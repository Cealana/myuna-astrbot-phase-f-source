from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def load_script(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {relative}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


prepare = load_script(
    "prepare_owner_profile_write_state_v1_tests",
    "scripts/prepare_owner_profile_write_state_v1.py",
)


class PrepareOwnerProfileWriteStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.legacy_root = root / "legacy-releases"
        self.write_root = root / "write-state"
        self.digest = "a" * 64
        self.source_release = self.legacy_root / f"r2-{self.digest}"
        self.source_release.mkdir(parents=True, mode=0o700)
        self.core_pythonpath = (
            Path("/opt/myuna/owner-profile-write-v1/releases")
            / ("b" * 64)
            / "src"
        )
        self.write_root.mkdir(mode=0o700)
        self.marker = self.write_root / "ledger"
        self.marker.mkdir(mode=0o700)
        self.marker_file = self.marker / "event.json"
        self.marker_file.write_bytes(b"synthetic")
        self.marker_file.chmod(0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _prepare(self, *, owner_results, bootstrap_runner=lambda *_: None):
        with (
            mock.patch.object(
                prepare, "LEGACY_PROFILE_RELEASE_ROOT", self.legacy_root
            ),
            mock.patch.object(prepare.os, "geteuid", return_value=0),
            mock.patch.object(
                prepare, "_tree_owner", side_effect=owner_results
            ) as owner,
            mock.patch.object(prepare, "_chown_tree") as chown,
        ):
            changed = prepare.prepare_write_state(
                source_release=self.source_release,
                source_sha256=self.digest,
                write_root=self.write_root,
                root_uid=0,
                root_gid=0,
                service_uid=1001,
                service_gid=1001,
                core_pythonpath=self.core_pythonpath,
                bootstrap_runner=bootstrap_runner,
            )
        return changed, owner, chown

    def test_root_owned_tree_transitions_and_bootstraps(self) -> None:
        bootstrap = mock.Mock()
        changed, _, chown = self._prepare(
            owner_results=[True, False, True],
            bootstrap_runner=bootstrap,
        )
        self.assertTrue(changed)
        chown.assert_called_once_with(self.write_root, uid=1001, gid=1001)
        bootstrap.assert_called_once_with(
            self.source_release,
            self.digest,
            self.write_root,
            False,
            self.core_pythonpath,
        )

    def test_already_service_owned_tree_is_idempotent(self) -> None:
        bootstrap = mock.Mock()
        changed, _, chown = self._prepare(
            owner_results=[False, True, True],
            bootstrap_runner=bootstrap,
        )
        self.assertFalse(changed)
        chown.assert_not_called()
        bootstrap.assert_called_once_with(
            self.source_release,
            self.digest,
            self.write_root,
            True,
            self.core_pythonpath,
        )

    def test_mixed_ownership_fails_closed(self) -> None:
        with (
            mock.patch.object(
                prepare, "LEGACY_PROFILE_RELEASE_ROOT", self.legacy_root
            ),
            mock.patch.object(prepare.os, "geteuid", return_value=0),
            mock.patch.object(
                prepare, "_tree_owner", side_effect=[False, False]
            ),
        ):
            with self.assertRaisesRegex(
                prepare.OwnerProfileWriteStatePrepareError,
                "profile_write_state_owner_drift",
            ):
                prepare.prepare_write_state(
                    source_release=self.source_release,
                    source_sha256=self.digest,
                    write_root=self.write_root,
                    service_uid=1001,
                    service_gid=1001,
                    core_pythonpath=self.core_pythonpath,
                )

    def test_bootstrap_failure_restores_root_ownership_without_deleting(self) -> None:
        def reject(*_):
            raise prepare.OwnerProfileWriteStatePrepareError(
                "profile_write_bootstrap_rejected"
            )

        with (
            mock.patch.object(
                prepare, "LEGACY_PROFILE_RELEASE_ROOT", self.legacy_root
            ),
            mock.patch.object(prepare.os, "geteuid", return_value=0),
            mock.patch.object(
                prepare, "_tree_owner", side_effect=[True, False]
            ),
            mock.patch.object(prepare, "_chown_tree") as chown,
        ):
            with self.assertRaisesRegex(
                prepare.OwnerProfileWriteStatePrepareError,
                "profile_write_bootstrap_rejected",
            ):
                prepare.prepare_write_state(
                    source_release=self.source_release,
                    source_sha256=self.digest,
                    write_root=self.write_root,
                    service_uid=1001,
                    service_gid=1001,
                    core_pythonpath=self.core_pythonpath,
                    bootstrap_runner=reject,
                )
        self.assertEqual(
            chown.call_args_list,
            [
                mock.call(self.write_root, uid=1001, gid=1001),
                mock.call(self.write_root, uid=0, gid=0),
            ],
        )
        self.assertEqual(self.marker_file.read_bytes(), b"synthetic")

    def test_partial_initial_chown_failure_still_attempts_root_rollback(self) -> None:
        failure = prepare.OwnerProfileWriteStatePrepareError(
            "profile_write_state_ownership_failed"
        )
        with (
            mock.patch.object(
                prepare, "LEGACY_PROFILE_RELEASE_ROOT", self.legacy_root
            ),
            mock.patch.object(prepare.os, "geteuid", return_value=0),
            mock.patch.object(
                prepare, "_tree_owner", side_effect=[True, False]
            ),
            mock.patch.object(
                prepare, "_chown_tree", side_effect=[failure, None]
            ) as chown,
        ):
            with self.assertRaisesRegex(
                prepare.OwnerProfileWriteStatePrepareError,
                "profile_write_state_ownership_failed",
            ):
                prepare.prepare_write_state(
                    source_release=self.source_release,
                    source_sha256=self.digest,
                    write_root=self.write_root,
                    service_uid=1001,
                    service_gid=1001,
                    core_pythonpath=self.core_pythonpath,
                )
        self.assertEqual(
            chown.call_args_list[-1],
            mock.call(self.write_root, uid=0, gid=0),
        )

    def test_type_and_permission_drift_are_rejected(self) -> None:
        self.marker_file.chmod(0o644)
        with self.assertRaisesRegex(
            prepare.OwnerProfileWriteStatePrepareError,
            "profile_write_state_permission_drift",
        ):
            prepare._tree_entries(self.write_root)
        self.marker_file.chmod(0o600)
        link = self.write_root / "link"
        link.symlink_to(self.marker_file)
        with self.assertRaisesRegex(
            prepare.OwnerProfileWriteStatePrepareError,
            "profile_write_state_type_drift",
        ):
            prepare._tree_entries(self.write_root)

    def test_restore_requires_uniform_service_ownership(self) -> None:
        with (
            mock.patch.object(prepare.os, "geteuid", return_value=0),
            mock.patch.object(
                prepare, "_tree_owner", side_effect=[False, True]
            ),
            mock.patch.object(prepare, "_chown_tree") as chown,
        ):
            changed = prepare.restore_write_state_root(
                write_root=self.write_root,
                service_uid=1001,
                service_gid=1001,
            )
        self.assertTrue(changed)
        chown.assert_called_once_with(self.write_root, uid=0, gid=0)


if __name__ == "__main__":
    unittest.main()
