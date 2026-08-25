from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import core_release_selector_r4c_release as release_contract
from core_release_selector_r4c_release import (
    ENTRYPOINT_NAME,
    MANIFEST_NAME,
    RUNTIME_FILES,
    STATE_ROOT_TEXT,
    ExecutorReleaseError,
    build_release_payloads,
    validate_installed_release,
    verify_install_receipt,
    verify_state_contract,
)
from install_core_release_selector_r4c_executor import (
    ExecutorInstallError,
    install_inactive_executor,
)
import install_core_release_selector_r4c_executor as installer
import run_core_release_selector_r4c as live_cli
from core_release_selector_r4c_executor import R4CExecutionError


ACTIVATION = "a" * 64
TRANSACTION = "b" * 64
INACTIVE_TRANSACTION_INSTALL = "c" * 64
EXECUTOR_INSTALL = "d" * 64
SOURCE_COMMIT = "e" * 40


class R4CInactiveExecutorInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="myuna-r4c-executor-install-"
        )
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        scripts = self.source / "scripts"
        scripts.mkdir(parents=True)
        for index, name in enumerate(RUNTIME_FILES, start=1):
            (scripts / name).write_bytes(
                f"# synthetic {index}: {name}\n".encode("utf-8")
            )

        self.selector_root = (
            self.root / "physical" / "opt" / "myuna"
            / "core-release-selector"
        )
        self.selector_root.mkdir(parents=True)
        os.chown(self.selector_root, 0, 0)
        self.selector_root.chmod(0o750)
        self.executor_root = self.selector_root / "executors"
        self.receipt_root = self.selector_root / "executor-installations"

        self.var_lib = self.root / "physical" / "var" / "lib"
        self.var_lib.mkdir(parents=True)
        self.state_root = (
            self.var_lib / "myuna-core-release-selector"
            / "r4c-activations"
        )
        self.evidence, self.payloads = build_release_payloads(
            self.source,
            source_deploy_commit=SOURCE_COMMIT,
            activation_plan_digest=ACTIVATION,
            transaction_tree_sha256=TRANSACTION,
            inactive_transaction_install_plan_digest=(
                INACTIVE_TRANSACTION_INSTALL
            ),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def install(self) -> dict[str, object]:
        return install_inactive_executor(
            EXECUTOR_INSTALL,
            source_root=self.source,
            source_deploy_commit=SOURCE_COMMIT,
            activation_plan_digest=ACTIVATION,
            transaction_tree_sha256=TRANSACTION,
            inactive_transaction_install_plan_digest=(
                INACTIVE_TRANSACTION_INSTALL
            ),
            expected_executor_release_digest=(
                self.evidence.executor_release_sha256
            ),
            executor_root=self.executor_root,
            receipt_root=self.receipt_root,
            state_root=self.state_root,
            uid=0,
            gid=0,
        )

    def test_release_is_deterministic_and_binding_sensitive(self) -> None:
        repeated, payloads = build_release_payloads(
            self.source,
            source_deploy_commit=SOURCE_COMMIT,
            activation_plan_digest=ACTIVATION,
            transaction_tree_sha256=TRANSACTION,
            inactive_transaction_install_plan_digest=(
                INACTIVE_TRANSACTION_INSTALL
            ),
        )
        self.assertEqual(repeated, self.evidence)
        self.assertEqual(payloads, self.payloads)
        changed, _ = build_release_payloads(
            self.source,
            source_deploy_commit=SOURCE_COMMIT,
            activation_plan_digest="f" * 64,
            transaction_tree_sha256=TRANSACTION,
            inactive_transaction_install_plan_digest=(
                INACTIVE_TRANSACTION_INSTALL
            ),
        )
        self.assertNotEqual(
            changed.executor_release_sha256,
            self.evidence.executor_release_sha256,
        )

    def test_runtime_payload_change_changes_release_digest(self) -> None:
        target = self.source / "scripts" / ENTRYPOINT_NAME
        target.write_bytes(target.read_bytes() + b"# changed\n")
        changed, _ = build_release_payloads(
            self.source,
            source_deploy_commit=SOURCE_COMMIT,
            activation_plan_digest=ACTIVATION,
            transaction_tree_sha256=TRANSACTION,
            inactive_transaction_install_plan_digest=(
                INACTIVE_TRANSACTION_INSTALL
            ),
        )
        self.assertNotEqual(
            changed.executor_release_sha256,
            self.evidence.executor_release_sha256,
        )

    def test_install_is_inactive_exact_and_idempotent(self) -> None:
        first = self.install()
        second = self.install()
        destination = (
            self.executor_root / self.evidence.executor_release_sha256
        )
        receipt = self.receipt_root / f"{EXECUTOR_INSTALL}.json"

        self.assertTrue(first["release_created"])
        self.assertTrue(first["receipt_created"])
        self.assertTrue(first["state_contract_created"])
        self.assertFalse(second["release_created"])
        self.assertFalse(second["receipt_created"])
        self.assertFalse(second["state_contract_created"])
        self.assertFalse(first["runtime_invoked"])
        self.assertFalse(first["systemd_changed"])
        self.assertFalse(first["service_lifecycle_performed"])
        self.assertFalse(first["selected_or_activated"])
        self.assertEqual(list(self.state_root.iterdir()), [])

        validated = validate_installed_release(
            destination,
            expected_release_digest=(
                self.evidence.executor_release_sha256
            ),
            expected_source_deploy_commit=SOURCE_COMMIT,
            expected_activation_plan_digest=ACTIVATION,
            expected_transaction_tree_sha256=TRANSACTION,
            expected_inactive_transaction_install_plan_digest=(
                INACTIVE_TRANSACTION_INSTALL
            ),
            uid=0,
            gid=0,
        )
        verify_install_receipt(
            receipt,
            validated,
            approved_executor_install_plan_digest=EXECUTOR_INSTALL,
            executor_path=destination,
            state_root=self.state_root,
            uid=0,
            gid=0,
        )
        verify_state_contract(self.state_root)

    def test_installed_permissions_are_exact(self) -> None:
        self.install()
        destination = (
            self.executor_root / self.evidence.executor_release_sha256
        )
        self.assertEqual(
            stat.S_IMODE(destination.stat().st_mode),
            0o550,
        )
        for entry in destination.iterdir():
            self.assertEqual(stat.S_IMODE(entry.stat().st_mode), 0o440)
        self.assertEqual(
            stat.S_IMODE(self.executor_root.stat().st_mode),
            0o750,
        )
        self.assertEqual(
            stat.S_IMODE(self.receipt_root.stat().st_mode),
            0o750,
        )
        self.assertEqual(
            stat.S_IMODE(self.state_root.parent.stat().st_mode),
            0o700,
        )
        self.assertEqual(
            stat.S_IMODE(self.state_root.stat().st_mode),
            0o700,
        )
        self.assertEqual(self.state_root.stat().st_uid, 0)
        self.assertEqual(self.state_root.stat().st_gid, 0)

    def test_digest_mismatch_fails_before_any_install_write(self) -> None:
        with self.assertRaisesRegex(
            ExecutorInstallError,
            "executor_release_digest_rejected",
        ):
            install_inactive_executor(
                EXECUTOR_INSTALL,
                source_root=self.source,
                source_deploy_commit=SOURCE_COMMIT,
                activation_plan_digest=ACTIVATION,
                transaction_tree_sha256=TRANSACTION,
                inactive_transaction_install_plan_digest=(
                    INACTIVE_TRANSACTION_INSTALL
                ),
                expected_executor_release_digest="0" * 64,
                executor_root=self.executor_root,
                receipt_root=self.receipt_root,
                state_root=self.state_root,
                uid=0,
                gid=0,
            )
        self.assertFalse(self.executor_root.exists())
        self.assertFalse(self.receipt_root.exists())
        self.assertFalse(self.state_root.parent.exists())

    def test_symlinked_source_file_is_rejected(self) -> None:
        target = self.source / "scripts" / ENTRYPOINT_NAME
        target.unlink()
        target.symlink_to(self.source / "scripts" / RUNTIME_FILES[0])
        with self.assertRaisesRegex(
            ExecutorInstallError,
            "executor_contract_rejected",
        ):
            self.install()
        self.assertFalse(self.executor_root.exists())
        self.assertFalse(self.state_root.parent.exists())

    def test_wrong_state_directory_metadata_is_rejected(self) -> None:
        self.state_root.parent.mkdir(mode=0o755)
        with self.assertRaisesRegex(
            ExecutorInstallError,
            "executor_state_directory_metadata_rejected",
        ):
            self.install()
        self.assertFalse(self.executor_root.exists())

    def test_state_directory_creation_failure_leaves_no_partial_path(self) -> None:
        with patch.object(
            installer.os,
            "chown",
            side_effect=PermissionError("injected"),
        ):
            with self.assertRaisesRegex(
                ExecutorInstallError,
                "inactive_executor_install_failed",
            ):
                self.install()
        self.assertFalse(self.state_root.parent.exists())
        self.assertFalse(self.executor_root.exists())

    def test_nonempty_state_contract_is_preserved_and_accepted(self) -> None:
        self.state_root.parent.mkdir(mode=0o700)
        os.chown(self.state_root.parent, 0, 0)
        self.state_root.parent.chmod(0o700)
        self.state_root.mkdir(mode=0o700)
        os.chown(self.state_root, 0, 0)
        self.state_root.chmod(0o700)
        marker = self.state_root / "unexpected"
        marker.write_text("preserve", encoding="utf-8")
        result = self.install()
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")
        self.assertTrue(
            (
                self.executor_root
                / self.evidence.executor_release_sha256
            ).is_dir()
        )
        self.assertFalse(result["state_contract_created"])
        self.assertEqual(result["preexisting_state_entry_count"], 1)
        self.assertTrue(result["preexisting_state_preserved"])

    def test_concurrent_state_change_rolls_back_only_new_install(self) -> None:
        self.state_root.parent.mkdir(mode=0o700)
        os.chown(self.state_root.parent, 0, 0)
        self.state_root.parent.chmod(0o700)
        self.state_root.mkdir(mode=0o700)
        os.chown(self.state_root, 0, 0)
        self.state_root.chmod(0o700)
        marker = self.state_root / "journal"
        marker.write_text("preserve", encoding="utf-8")
        with (
            patch.object(
                installer,
                "_snapshot_state_tree",
                side_effect=[
                    {"journal": ("file", 0, 0, 0o600, "a" * 64)},
                    {"journal": ("file", 0, 0, 0o600, "b" * 64)},
                ],
            ),
            self.assertRaisesRegex(
                ExecutorInstallError,
                "executor_state_changed_during_install",
            ),
        ):
            self.install()
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")
        self.assertFalse(
            (
                self.executor_root
                / self.evidence.executor_release_sha256
            ).exists()
        )

    def test_conflicting_receipt_rolls_back_new_release_and_state(self) -> None:
        self.receipt_root.mkdir()
        os.chown(self.receipt_root, 0, 0)
        self.receipt_root.chmod(0o750)
        conflict = self.receipt_root / f"{EXECUTOR_INSTALL}.json"
        conflict.write_bytes(b"{}")
        os.chown(conflict, 0, 0)
        conflict.chmod(0o440)
        with self.assertRaisesRegex(
            ExecutorInstallError,
            "inactive_executor_install_failed",
        ):
            self.install()
        self.assertFalse(
            (
                self.executor_root
                / self.evidence.executor_release_sha256
            ).exists()
        )
        self.assertFalse(self.state_root.parent.exists())
        self.assertEqual(conflict.read_bytes(), b"{}")

    def test_existing_tampered_release_is_preserved_and_rejected(self) -> None:
        self.install()
        destination = (
            self.executor_root / self.evidence.executor_release_sha256
        )
        target = destination / RUNTIME_FILES[0]
        target.write_bytes(b"tampered")
        target.chmod(0o440)
        with self.assertRaises(ExecutorInstallError):
            self.install()
        self.assertTrue(destination.exists())
        self.assertEqual(target.read_bytes(), b"tampered")

    def test_manifest_is_canonical_and_contains_no_secret_fields(self) -> None:
        manifest_payload = self.payloads[MANIFEST_NAME]
        manifest = json.loads(manifest_payload.decode("utf-8"))
        self.assertEqual(
            json.dumps(
                manifest,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8"),
            manifest_payload,
        )
        lowered = manifest_payload.lower()
        for forbidden in (
            b"api_key",
            b"password",
            b"cookie",
            b"authorization",
            b"token",
        ):
            self.assertNotIn(forbidden, lowered)

    def test_manifest_tamper_is_rejected(self) -> None:
        self.install()
        destination = (
            self.executor_root / self.evidence.executor_release_sha256
        )
        manifest = destination / MANIFEST_NAME
        manifest.write_bytes(manifest.read_bytes() + b"\n")
        manifest.chmod(0o440)
        with self.assertRaises(ExecutorReleaseError):
            validate_installed_release(
                destination,
                expected_release_digest=(
                    self.evidence.executor_release_sha256
                ),
                expected_source_deploy_commit=SOURCE_COMMIT,
                expected_activation_plan_digest=ACTIVATION,
                expected_transaction_tree_sha256=TRANSACTION,
                expected_inactive_transaction_install_plan_digest=(
                    INACTIVE_TRANSACTION_INSTALL
                ),
                uid=0,
                gid=0,
            )

    def test_cli_rejects_execution_outside_installed_release(self) -> None:
        with self.assertRaisesRegex(
            R4CExecutionError,
            "executor_entrypoint_rejected",
        ):
            live_cli._verify_executor_installation(
                approved_executor_install_plan_digest=EXECUTOR_INSTALL,
                expected_executor_release_digest=(
                    self.evidence.executor_release_sha256
                ),
                expected_source_deploy_commit=SOURCE_COMMIT,
                approved_activation_plan_digest=ACTIVATION,
                expected_transaction_tree=TRANSACTION,
                approved_inactive_transaction_install_plan_digest=(
                    INACTIVE_TRANSACTION_INSTALL
                ),
            )

    def test_cli_accepts_exact_inactive_install_contract(self) -> None:
        self.install()
        destination = (
            self.executor_root / self.evidence.executor_release_sha256
        )
        with (
            patch.object(live_cli, "EXECUTOR_ROOT", self.executor_root),
            patch.object(
                live_cli,
                "EXECUTOR_RECEIPT_ROOT",
                self.receipt_root,
            ),
            patch.object(live_cli, "STATE_ROOT", self.state_root),
            patch.object(
                live_cli,
                "__file__",
                (destination / ENTRYPOINT_NAME).as_posix(),
            ),
            patch.object(live_cli, "_myuna_gid", return_value=0),
            patch.object(
                release_contract,
                "_myuna_gid",
                return_value=0,
            ),
        ):
            live_cli._verify_executor_installation(
                approved_executor_install_plan_digest=EXECUTOR_INSTALL,
                expected_executor_release_digest=(
                    self.evidence.executor_release_sha256
                ),
                expected_source_deploy_commit=SOURCE_COMMIT,
                approved_activation_plan_digest=ACTIVATION,
                expected_transaction_tree=TRANSACTION,
                approved_inactive_transaction_install_plan_digest=(
                    INACTIVE_TRANSACTION_INSTALL
                ),
            )

    def test_cli_checks_confirmation_before_new_install_arguments(self) -> None:
        with patch.object(live_cli.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(
                R4CExecutionError,
                "live_confirmation_rejected",
            ):
                live_cli.main(
                    [
                        "activate-live",
                        "--approved-activation-plan-digest",
                        ACTIVATION,
                        "--approved-inactive-install-plan-digest",
                        INACTIVE_TRANSACTION_INSTALL,
                        "--expected-transaction-tree",
                        TRANSACTION,
                        "--live-confirmation",
                        "no",
                    ]
                )

    def test_cli_requires_install_contract_after_confirmation(self) -> None:
        with patch.object(live_cli.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(
                R4CExecutionError,
                "executor_installation_arguments_required",
            ):
                live_cli.main(
                    [
                        "activate-live",
                        "--approved-activation-plan-digest",
                        ACTIVATION,
                        "--approved-inactive-install-plan-digest",
                        INACTIVE_TRANSACTION_INSTALL,
                        "--expected-transaction-tree",
                        TRANSACTION,
                        "--live-confirmation",
                        live_cli.LIVE_CONFIRMATION,
                    ]
                )

    def test_state_root_is_independent_from_myuna_runtime_data(self) -> None:
        self.assertEqual(
            STATE_ROOT_TEXT,
            "/var/lib/myuna-core-release-selector/r4c-activations",
        )
        self.assertFalse(STATE_ROOT_TEXT.startswith("/var/lib/myuna/"))
        self.assertEqual(live_cli.STATE_ROOT.as_posix(), STATE_ROOT_TEXT)

    def test_installer_has_no_systemd_or_service_lifecycle_api(self) -> None:
        source = Path(installer.__file__).read_text(encoding="utf-8")
        self.assertNotIn("systemctl", source)
        self.assertNotIn("daemon-reload", source)
        self.assertNotIn("start_service", source)
        self.assertNotIn("restart_service", source)
        self.assertNotIn("stop_service", source)


if __name__ == "__main__":
    unittest.main()
