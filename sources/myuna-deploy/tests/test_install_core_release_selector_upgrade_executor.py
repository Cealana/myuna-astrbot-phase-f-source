from __future__ import annotations

import grp
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from core_release_selector_upgrade_release import (
    EXECUTOR_FILES,
    MANIFEST_NAME,
    build_manifest,
    canonical_bytes,
    validate_installed_release,
)
from install_core_release_selector_upgrade_executor import (
    SelectedUpgradeExecutorInstallError,
    install_inactive_executor,
)


APPROVAL = "a" * 64
ACTIVATION = "b" * 64
TRANSACTION = "c" * 64
INACTIVE_INSTALL = "d" * 64
DEPLOY_COMMIT = "e" * 40


class SelectedUpgradeExecutorInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="selected-upgrade-install-")
        self.root = Path(self.temporary.name)
        artifacts = {
            name: f"# synthetic {index}: {name}\n".encode()
            for index, name in enumerate(sorted(EXECUTOR_FILES), start=1)
        }
        self.manifest = build_manifest(
            artifacts,
            source_deploy_commit=DEPLOY_COMMIT,
            activation_plan_digest=ACTIVATION,
            transaction_tree_sha256=TRANSACTION,
            inactive_transaction_install_plan_digest=INACTIVE_INSTALL,
        )
        self.release = str(self.manifest["release_digest"])
        self.source = self.root / "source" / self.release
        self.source.mkdir(parents=True)
        for name, payload in artifacts.items():
            (self.source / name).write_bytes(payload)
        (self.source / MANIFEST_NAME).write_bytes(canonical_bytes(self.manifest))
        self.executor_root = self.root / "opt" / "selected-upgrade-executors"
        self.receipt_root = self.root / "opt" / "selected-upgrade-installations"
        self.executor_root.parent.mkdir(parents=True)
        self.state_root = self.root / "var" / "selected-upgrade-activations"
        self.state_root.parent.mkdir(parents=True)
        self.state_root.parent.chmod(0o700)
        self.gid = grp.getgrnam("myuna").gr_gid

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def install(self, **overrides: object) -> dict[str, object]:
        arguments = {
            "source_release": self.source,
            "approved_install_plan_digest": APPROVAL,
            "expected_executor_release_digest": self.release,
            "expected_source_deploy_commit": DEPLOY_COMMIT,
            "expected_activation_plan_digest": ACTIVATION,
            "expected_transaction_tree_sha256": TRANSACTION,
            "expected_inactive_transaction_install_plan_digest": INACTIVE_INSTALL,
            "executor_root": self.executor_root,
            "receipt_root": self.receipt_root,
            "state_root": self.state_root,
        }
        arguments.update(overrides)
        return install_inactive_executor(**arguments)

    def test_install_is_exact_inactive_and_idempotent(self) -> None:
        first = self.install()
        second = self.install()
        self.assertTrue(first["release_created"])
        self.assertTrue(first["receipt_created"])
        self.assertFalse(second["release_created"])
        self.assertFalse(second["receipt_created"])
        self.assertFalse(first["runtime_invoked"])
        self.assertFalse(first["systemd_changed"])
        self.assertFalse(first["service_lifecycle_performed"])
        self.assertFalse(first["journal_created"])
        self.assertEqual(list(self.state_root.iterdir()), [])

    def test_installed_release_and_receipt_are_cli_exact(self) -> None:
        self.install()
        destination = self.executor_root / self.release
        validate_installed_release(
            destination,
            expected_release_digest=self.release,
            expected_source_deploy_commit=DEPLOY_COMMIT,
            expected_activation_plan_digest=ACTIVATION,
            expected_transaction_tree_sha256=TRANSACTION,
            expected_inactive_install_plan_digest=INACTIVE_INSTALL,
        )
        receipt = json.loads((self.receipt_root / f"{APPROVAL}.json").read_text())
        self.assertEqual(receipt["executor_path"], destination.as_posix())
        self.assertEqual(receipt["status"], "installed_inactive_not_executed")
        self.assertEqual(set(receipt), {
            "schema", "status", "approved_install_plan_digest",
            "executor_release_digest", "executor_path", "source_deploy_commit",
            "activation_plan_digest", "transaction_tree_sha256",
            "inactive_transaction_install_plan_digest", "runtime_invoked",
            "systemd_changed", "service_lifecycle_performed",
        })

    def test_permissions_are_immutable_and_state_is_root_only(self) -> None:
        self.install()
        destination = self.executor_root / self.release
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o550)
        self.assertEqual(destination.stat().st_gid, self.gid)
        for entry in destination.iterdir():
            self.assertEqual(stat.S_IMODE(entry.stat().st_mode), 0o440)
        self.assertEqual(stat.S_IMODE(self.state_root.stat().st_mode), 0o700)
        self.assertEqual((self.state_root.stat().st_uid, self.state_root.stat().st_gid), (0, 0))

    def test_wrong_release_digest_fails_before_write(self) -> None:
        with self.assertRaises(SelectedUpgradeExecutorInstallError):
            self.install(expected_executor_release_digest="0" * 64)
        self.assertFalse(self.executor_root.exists())
        self.assertFalse(self.receipt_root.exists())

    def test_manifest_tamper_fails_before_write(self) -> None:
        manifest = self.source / MANIFEST_NAME
        manifest.write_bytes(manifest.read_bytes() + b"\n")
        with self.assertRaisesRegex(SelectedUpgradeExecutorInstallError, "source_release_rejected"):
            self.install()
        self.assertFalse(self.executor_root.exists())

    def test_symlinked_source_entry_is_rejected(self) -> None:
        target = self.source / sorted(EXECUTOR_FILES)[0]
        target.unlink()
        target.symlink_to(self.source / sorted(EXECUTOR_FILES)[1])
        with self.assertRaisesRegex(SelectedUpgradeExecutorInstallError, "source_release_rejected"):
            self.install()

    def test_prior_failed_journal_is_preserved_and_accepted(self) -> None:
        self.state_root.mkdir(mode=0o700)
        prior = self.state_root / ("f" * 64)
        prior.mkdir(mode=0o700)
        marker = prior / "journal.jsonl"
        marker.write_text("preserve")
        result = self.install()
        self.assertEqual(marker.read_text(), "preserve")
        self.assertTrue((self.executor_root / self.release).exists())
        self.assertEqual(result["preexisting_state_entry_count"], 2)
        self.assertTrue(result["preexisting_state_preserved"])

    def test_same_activation_journal_is_rejected_and_preserved(self) -> None:
        self.state_root.mkdir(mode=0o700)
        conflict = self.state_root / ACTIVATION
        conflict.mkdir(mode=0o700)
        marker = conflict / "journal.jsonl"
        marker.write_text("preserve")
        with self.assertRaisesRegex(
            SelectedUpgradeExecutorInstallError,
            "activation_journal_already_exists",
        ):
            self.install()
        self.assertEqual(marker.read_text(), "preserve")
        self.assertFalse((self.executor_root / self.release).exists())

    def test_wrong_state_metadata_is_rejected(self) -> None:
        self.state_root.mkdir(mode=0o755)
        with self.assertRaisesRegex(SelectedUpgradeExecutorInstallError, "install_parent_metadata_rejected"):
            self.install()

    def test_conflicting_receipt_preserved_and_new_release_rolled_back(self) -> None:
        self.receipt_root.mkdir(mode=0o750)
        os.chown(self.receipt_root, 0, self.gid)
        conflict = self.receipt_root / f"{APPROVAL}.json"
        conflict.write_bytes(b"{}")
        os.chown(conflict, 0, self.gid)
        conflict.chmod(0o440)
        with self.assertRaisesRegex(SelectedUpgradeExecutorInstallError, "install_receipt_rejected"):
            self.install()
        self.assertEqual(conflict.read_bytes(), b"{}")
        self.assertFalse((self.executor_root / self.release).exists())

    def test_tampered_existing_release_is_preserved_and_rejected(self) -> None:
        self.install()
        target = self.executor_root / self.release / sorted(EXECUTOR_FILES)[0]
        target.write_bytes(b"tampered")
        target.chmod(0o440)
        with self.assertRaisesRegex(SelectedUpgradeExecutorInstallError, "installed_release_rejected"):
            self.install()
        self.assertEqual(target.read_bytes(), b"tampered")


if __name__ == "__main__":
    unittest.main()
