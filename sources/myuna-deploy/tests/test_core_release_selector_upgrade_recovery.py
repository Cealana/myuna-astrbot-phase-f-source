from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import sys
import unittest


CANDIDATE_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
FORMAL_SCRIPTS = Path("/srv/myuna/repos/deploy/scripts")
sys.path[:0] = [str(CANDIDATE_SCRIPTS), str(FORMAL_SCRIPTS)]

from core_release_selector_upgrade_executor import RuntimeSnapshot  # noqa: E402
from core_release_selector_upgrade_recovery import (  # noqa: E402
    SelectedUpgradeRecoveryExecutor,
    UpgradeRecoveryError,
    assess_recovery,
)


PLAN_DIGEST = "a" * 64
TARGET_TREE = "b" * 64


def bundle():
    return SimpleNamespace(
        plan_digest=PLAN_DIGEST,
        plan={"target": {"selected_release": {"tree_sha256": TARGET_TREE}}},
    )


def snapshot_payload() -> dict[str, object]:
    return RuntimeSnapshot.create(
        core_active=False,
        gateway_socket_active=True,
        gateway_service_active=False,
        binding_sha256="c" * 64,
    ).to_payload()


def record(phase: str, *, snapshot: bool = False) -> dict[str, object]:
    return {
        "phase": phase,
        "event": phase,
        "data": {"snapshot": snapshot_payload()} if snapshot else {},
    }


def success_receipt() -> dict[str, object]:
    return {
        "schema": "myuna.core-release-selector.selected-upgrade-receipt.v1",
        "status": "selected_release_upgraded",
        "plan_digest": PLAN_DIGEST,
        "target_tree_sha256": TARGET_TREE,
        "automatic_rollback_enabled": True,
        "secret_values_emitted": False,
    }


class FakeJournal:
    def __init__(self, records, receipt=None) -> None:
        self._records = list(records)
        self.receipt = receipt

    @property
    def records(self):
        return [dict(item) for item in self._records]

    def append(self, phase, event, data=None) -> None:
        self._records.append({"phase": phase, "event": event, "data": dict(data or {})})

    def verify_receipt(self):
        return None if self.receipt is None else dict(self.receipt)


class FakeBackend:
    def __init__(self, fail_at=None) -> None:
        self.fail_at = fail_at
        self.calls = []

    def _call(self, name):
        self.calls.append(name)
        if self.fail_at == name:
            raise RuntimeError(name)

    def verify_target(self, bundle, snapshot): self._call("verify_target")
    def restore_gateway(self, bundle, snapshot): self._call("restore_gateway")
    def quiesce_gateway(self, bundle): self._call("quiesce_gateway")
    def restore_files(self, bundle): self._call("restore_files")
    def daemon_reload(self, bundle): self._call("daemon_reload")
    def restore_prestate(self, bundle, snapshot): self._call("restore_prestate")


class RecoveryAssessmentTests(unittest.TestCase):
    def test_empty_journal_rejected(self) -> None:
        with self.assertRaisesRegex(UpgradeRecoveryError, "empty_journal"):
            assess_recovery(bundle=bundle(), journal=FakeJournal([]))

    def test_nonprefix_forward_sequence_rejected(self) -> None:
        journal = FakeJournal([record("prepared", snapshot=True), record("files_applied")])
        with self.assertRaisesRegex(UpgradeRecoveryError, "forward_journal_sequence"):
            assess_recovery(bundle=bundle(), journal=journal)

    def test_snapshot_digest_tamper_rejected(self) -> None:
        first = record("prepared", snapshot=True)
        first["data"]["snapshot"]["snapshot_sha256"] = "0" * 64
        with self.assertRaisesRegex(UpgradeRecoveryError, "snapshot_digest"):
            assess_recovery(bundle=bundle(), journal=FakeJournal([first]))


class RecoveryExecutorTests(unittest.TestCase):
    def execute(self, records, *, receipt=None, fail_at=None):
        journal = FakeJournal(records, receipt)
        backend = FakeBackend(fail_at)
        result = SelectedUpgradeRecoveryExecutor(
            bundle=bundle(), backend=backend, journal=journal
        ).recover()
        return result, backend, journal

    def test_pre_file_crash_rolls_back_without_file_restore(self) -> None:
        result, backend, journal = self.execute(
            [record("prepared", snapshot=True), record("gateway_quiesce_intent")]
        )
        self.assertEqual(result["status"], "recovered_rolled_back")
        self.assertEqual(
            backend.calls,
            ["quiesce_gateway", "restore_prestate"],
        )
        self.assertEqual(journal.records[-1]["phase"], "rolled_back")

    def test_post_file_intent_crash_restores_files_and_reloads(self) -> None:
        phases = ["prepared", "gateway_quiesce_intent", "gateway_quiesced", "file_apply_intent"]
        records = [record(phase, snapshot=(index == 0)) for index, phase in enumerate(phases)]
        result, backend, _ = self.execute(records)
        self.assertEqual(result["status"], "recovered_rolled_back")
        self.assertEqual(
            backend.calls,
            ["quiesce_gateway", "restore_files", "daemon_reload", "restore_prestate"],
        )

    def test_already_rolled_back_is_noop(self) -> None:
        result, backend, _ = self.execute(
            [record("prepared", snapshot=True), record("rollback_intent"), record("rolled_back")]
        )
        self.assertEqual(result["status"], "already_rolled_back")
        self.assertEqual(backend.calls, [])

    def test_rollback_failed_requires_new_owner_plan(self) -> None:
        journal = FakeJournal(
            [record("prepared", snapshot=True), record("rollback_intent"), record("rollback_failed")]
        )
        with self.assertRaisesRegex(UpgradeRecoveryError, "requires_owner_plan"):
            SelectedUpgradeRecoveryExecutor(
                bundle=bundle(), backend=FakeBackend(), journal=journal
            ).recover()

    def test_receipt_write_crash_reconciles_and_commits(self) -> None:
        phases = list(
            (
                "prepared",
                "gateway_quiesce_intent",
                "gateway_quiesced",
                "file_apply_intent",
                "files_applied",
                "daemon_reload_intent",
                "daemon_reloaded",
                "core_start_intent",
                "core_started",
                "target_verified",
                "gateway_restore_intent",
                "gateway_restored",
                "receipt_write_intent",
            )
        )
        records = [record(phase, snapshot=(index == 0)) for index, phase in enumerate(phases)]
        result, backend, journal = self.execute(records, receipt=success_receipt())
        self.assertEqual(result["status"], "recovered_committed")
        self.assertEqual(backend.calls, ["verify_target", "restore_gateway"])
        self.assertEqual(journal.records[-1]["phase"], "committed")

    def test_committed_with_receipt_is_noop(self) -> None:
        phases = [
            "prepared", "gateway_quiesce_intent", "gateway_quiesced",
            "file_apply_intent", "files_applied", "daemon_reload_intent",
            "daemon_reloaded", "core_start_intent", "core_started",
            "target_verified", "gateway_restore_intent", "gateway_restored",
            "receipt_write_intent", "committed",
        ]
        records = [record(phase, snapshot=(index == 0)) for index, phase in enumerate(phases)]
        result, backend, _ = self.execute(records, receipt=success_receipt())
        self.assertEqual(result["status"], "already_committed")
        self.assertEqual(backend.calls, [])

    def test_recovery_failure_is_terminal_and_audited(self) -> None:
        journal = FakeJournal([record("prepared", snapshot=True)])
        with self.assertRaisesRegex(UpgradeRecoveryError, "crash_recovery_rollback_failed"):
            SelectedUpgradeRecoveryExecutor(
                bundle=bundle(), backend=FakeBackend("restore_prestate"), journal=journal
            ).recover()
        self.assertEqual(journal.records[-1]["phase"], "rollback_failed")


if __name__ == "__main__":
    unittest.main()

