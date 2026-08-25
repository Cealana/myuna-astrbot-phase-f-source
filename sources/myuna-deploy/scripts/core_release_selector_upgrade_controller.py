"""Pure composition controller for selected-to-selected Core upgrades.

R4B-A has no CLI, fixed filesystem paths, systemd calls, or live installation.
"""

from __future__ import annotations

from typing import Callable

from core_release_selector_upgrade_executor import (
    JournaledUpgradeExecutor,
    RuntimeSnapshot,
    UpgradeBackend,
    UpgradeBundle,
    UpgradeJournal,
)
from core_release_selector_upgrade_recovery import (
    RecoveryJournal,
    SelectedUpgradeRecoveryExecutor,
)


class UpgradeControllerError(RuntimeError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise UpgradeControllerError(code)


class SelectedUpgradeController:
    """Separates read-only preflight, first activation, and crash recovery."""

    def __init__(
        self,
        *,
        bundle: UpgradeBundle,
        backend: UpgradeBackend,
        journal_exists: Callable[[], bool],
        create_journal: Callable[[], UpgradeJournal],
        open_journal: Callable[[], RecoveryJournal],
    ) -> None:
        self.bundle = bundle
        self.backend = backend
        self.journal_exists = journal_exists
        self.create_journal = create_journal
        self.open_journal = open_journal

    def preflight(self) -> dict[str, object]:
        require(not self.journal_exists(), "existing_journal_requires_recovery")
        snapshot: RuntimeSnapshot = self.backend.verify_exact_prestate(self.bundle)
        require(not self.journal_exists(), "journal_appeared_during_preflight")
        return {
            "schema": "myuna.core-release-selector.selected-upgrade-preflight.v1",
            "status": "ready_not_activated",
            "plan_digest": self.bundle.plan_digest,
            "prestate_snapshot_sha256": snapshot.snapshot_sha256,
            "journal_created": False,
            "runtime_changed": False,
        }

    def activate(self) -> dict[str, object]:
        require(not self.journal_exists(), "existing_journal_requires_recovery")
        journal = self.create_journal()
        require(self.journal_exists(), "journal_creation_not_observable")
        return JournaledUpgradeExecutor(
            bundle=self.bundle,
            backend=self.backend,
            journal=journal,
        ).execute()

    def recover(self) -> dict[str, object]:
        require(self.journal_exists(), "recovery_journal_missing")
        journal = self.open_journal()
        return SelectedUpgradeRecoveryExecutor(
            bundle=self.bundle,
            backend=self.backend,
            journal=journal,
        ).recover()

