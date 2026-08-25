from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from owner_profile_write_environment_v1 import (  # noqa: E402
    OwnerProfileWriteTarget,
    parse_environment,
    render_environment,
)
from switch_owner_profile_write_code_v1 import (  # noqa: E402
    OwnerProfileWriteCodeSwitchError,
    SwitchPaths,
    switch_writer_code,
)


class SwitchOwnerProfileWriteCodeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.paths = SwitchPaths(
            deploy_root=root / "deploy",
            environment=root / "etc" / "writer.env",
            backup_root=root / "control" / "backups" / "code-switch-v1",
            receipt_root=root / "control" / "receipts" / "code-switch-v1",
            journal=root / "control" / "PENDING-CODE-SWITCH-V1.json",
        )
        self.paths.environment.parent.mkdir(parents=True, mode=0o700)
        self.paths.backup_root.parent.mkdir(parents=True, mode=0o700)
        self.paths.receipt_root.parent.mkdir(parents=True, mode=0o700)
        os.chmod(self.paths.backup_root.parent, 0o700)
        os.chmod(self.paths.receipt_root.parent, 0o700)
        self.current_digest = "a" * 64
        self.target_digest = "b" * 64
        self.target = OwnerProfileWriteTarget(
            core_release_sha256="c" * 64,
            write_code_release_sha256=self.current_digest,
            owner_profile_uid=978,
            core_peer_uid=999,
        )
        self.paths.environment.write_bytes(render_environment(self.target))
        os.chmod(self.paths.environment, 0o600)
        self.restarts = 0
        self.units_active = True

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _validate(self, digest: str, *, gid: int) -> dict[str, object]:
        self.assertIn(digest, {self.current_digest, self.target_digest})
        self.assertEqual(gid, os.getegid())
        return {"source_commit": "d" * 40}

    def _active(self, unit: str) -> bool:
        self.assertIn(unit, {
            "myuna-owner-profile-write-v1.service",
            "myuna-owner-profile-write-v1.socket",
        })
        return self.units_active

    def _restart(self) -> None:
        self.restarts += 1

    def _switch(self) -> dict[str, object]:
        return switch_writer_code(
            expected_core_release_sha256=self.target.core_release_sha256,
            expected_current_release_sha256=self.current_digest,
            target_release_sha256=self.target_digest,
            service_gid=os.getegid(),
            paths=self.paths,
            root_uid=os.geteuid(),
            root_gid=os.getegid(),
            validate_release=self._validate,
            service_active=self._active,
            restart_writer=self._restart,
        )

    def test_switch_is_exact_content_free_and_keeps_rollback(self) -> None:
        original = self.paths.environment.read_bytes()
        receipt = self._switch()
        selected = parse_environment(self.paths.environment.read_bytes())
        self.assertEqual(selected.write_code_release_sha256, self.target_digest)
        self.assertEqual(selected.core_release_sha256, self.target.core_release_sha256)
        self.assertEqual(self.restarts, 1)
        self.assertFalse(self.paths.journal.exists())
        backup = self.paths.backup_root / str(receipt["backup"])
        self.assertEqual((backup / "writer.env").read_bytes(), original)
        self.assertFalse(receipt["profile_content_changed"])
        self.assertFalse(receipt["candidate_store_changed"])
        self.assertFalse(receipt["raw_content_recorded"])
        receipt_path = self.paths.receipt_root / f'{receipt["receipt_id"]}.json'
        self.assertEqual(json.loads(receipt_path.read_bytes()), receipt)

    def test_current_release_drift_stops_before_restart(self) -> None:
        with self.assertRaisesRegex(
            OwnerProfileWriteCodeSwitchError,
            "code_switch_current_release_drift",
        ):
            switch_writer_code(
                expected_core_release_sha256=self.target.core_release_sha256,
                expected_current_release_sha256="e" * 64,
                target_release_sha256=self.target_digest,
                service_gid=os.getegid(),
                paths=self.paths,
                root_uid=os.geteuid(),
                root_gid=os.getegid(),
                validate_release=self._validate,
                service_active=self._active,
                restart_writer=self._restart,
            )
        self.assertEqual(self.restarts, 0)

    def test_core_release_drift_stops_before_restart(self) -> None:
        with self.assertRaisesRegex(
            OwnerProfileWriteCodeSwitchError,
            "code_switch_core_release_drift",
        ):
            switch_writer_code(
                expected_core_release_sha256="e" * 64,
                expected_current_release_sha256=self.current_digest,
                target_release_sha256=self.target_digest,
                service_gid=os.getegid(),
                paths=self.paths,
                root_uid=os.geteuid(),
                root_gid=os.getegid(),
                validate_release=self._validate,
                service_active=self._active,
                restart_writer=self._restart,
            )
        self.assertEqual(self.restarts, 0)

    def test_failed_poststate_restores_exact_environment(self) -> None:
        original = self.paths.environment.read_bytes()
        checks = 0

        def active_then_fail_then_recover(unit: str) -> bool:
            nonlocal checks
            checks += 1
            if checks == 3:
                return False
            return True

        with self.assertRaisesRegex(
            OwnerProfileWriteCodeSwitchError,
            "code_switch_poststate_rejected",
        ):
            switch_writer_code(
                expected_core_release_sha256=self.target.core_release_sha256,
                expected_current_release_sha256=self.current_digest,
                target_release_sha256=self.target_digest,
                service_gid=os.getegid(),
                paths=self.paths,
                root_uid=os.geteuid(),
                root_gid=os.getegid(),
                validate_release=self._validate,
                service_active=active_then_fail_then_recover,
                restart_writer=self._restart,
            )
        self.assertEqual(self.paths.environment.read_bytes(), original)
        self.assertEqual(self.restarts, 2)
        self.assertFalse(self.paths.journal.exists())


if __name__ == "__main__":
    unittest.main()
