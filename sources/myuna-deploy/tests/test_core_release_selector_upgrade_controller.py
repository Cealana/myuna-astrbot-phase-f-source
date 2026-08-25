from __future__ import annotations

from pathlib import Path
import sys
import unittest


CANDIDATE_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
FORMAL_SCRIPTS = Path("/srv/myuna/repos/deploy/scripts")
FORMAL_TESTS = Path("/srv/myuna/repos/deploy/tests")
sys.path[:0] = [str(CANDIDATE_SCRIPTS), str(FORMAL_SCRIPTS), str(FORMAL_TESTS)]

from core_release_selector_upgrade_controller import (  # noqa: E402
    SelectedUpgradeController,
    UpgradeControllerError,
)
from core_release_selector_upgrade_executor import (  # noqa: E402
    FakeUpgradeBackend,
    MemoryJournal,
    RuntimeSnapshot,
    UpgradeBundle,
)
from test_core_release_selector_upgrade_executor import bundle_payloads  # noqa: E402


class RecoveryMemoryJournal(MemoryJournal):
    def verify_receipt(self):
        return None if self.receipt is None else dict(self.receipt)


class JournalStore:
    def __init__(self) -> None:
        self.journal = None
        self.created = 0
        self.opened = 0

    def exists(self) -> bool:
        return self.journal is not None

    def create(self):
        if self.journal is not None:
            raise AssertionError("duplicate journal")
        self.created += 1
        self.journal = RecoveryMemoryJournal()
        return self.journal

    def open(self):
        if self.journal is None:
            raise AssertionError("journal missing")
        self.opened += 1
        return self.journal


class ControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        payloads, plan_digest = bundle_payloads()
        self.bundle = UpgradeBundle.load(payloads, approved_plan_digest=plan_digest)
        self.backend = FakeUpgradeBackend()
        self.store = JournalStore()
        self.controller = SelectedUpgradeController(
            bundle=self.bundle,
            backend=self.backend,
            journal_exists=self.store.exists,
            create_journal=self.store.create,
            open_journal=self.store.open,
        )

    def test_preflight_is_read_only_and_does_not_create_journal(self) -> None:
        result = self.controller.preflight()
        self.assertEqual(result["status"], "ready_not_activated")
        self.assertFalse(result["journal_created"])
        self.assertFalse(result["runtime_changed"])
        self.assertEqual(self.backend.events, ["verify_exact_prestate"])
        self.assertEqual(self.store.created, 0)

    def test_preflight_rejects_existing_journal(self) -> None:
        self.store.create()
        with self.assertRaisesRegex(UpgradeControllerError, "requires_recovery"):
            self.controller.preflight()
        self.assertEqual(self.backend.events, [])

    def test_preflight_rejects_journal_race(self) -> None:
        calls = 0

        def appears() -> bool:
            nonlocal calls
            calls += 1
            return calls > 1

        controller = SelectedUpgradeController(
            bundle=self.bundle,
            backend=self.backend,
            journal_exists=appears,
            create_journal=self.store.create,
            open_journal=self.store.open,
        )
        with self.assertRaisesRegex(UpgradeControllerError, "appeared_during_preflight"):
            controller.preflight()

    def test_activate_creates_one_journal_and_executes(self) -> None:
        result = self.controller.activate()
        self.assertEqual(result["status"], "activated")
        self.assertEqual(self.store.created, 1)
        self.assertIsNotNone(self.store.journal.receipt)

    def test_activate_rejects_existing_journal(self) -> None:
        self.store.create()
        with self.assertRaisesRegex(UpgradeControllerError, "requires_recovery"):
            self.controller.activate()
        self.assertEqual(self.store.created, 1)

    def test_recover_rejects_missing_journal(self) -> None:
        with self.assertRaisesRegex(UpgradeControllerError, "recovery_journal_missing"):
            self.controller.recover()

    def test_recover_uses_existing_rolled_back_journal_without_create(self) -> None:
        snapshot = RuntimeSnapshot.create(
            core_active=False,
            gateway_socket_active=True,
            gateway_service_active=False,
            binding_sha256="a" * 64,
        )
        self.store.journal = RecoveryMemoryJournal()
        self.store.journal.append(
            "prepared", "exact_prestate_verified", {"snapshot": snapshot.to_payload()}
        )
        self.store.journal.append("rollback_intent", "rollback_started")
        self.store.journal.append("rolled_back", "rollback_completed")
        result = self.controller.recover()
        self.assertEqual(result["status"], "already_rolled_back")
        self.assertEqual(self.store.created, 0)
        self.assertEqual(self.store.opened, 1)


if __name__ == "__main__":
    unittest.main()
