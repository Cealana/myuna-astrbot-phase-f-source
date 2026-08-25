"""Crash-recovery contract for selected-to-selected Core upgrades.

Repository-only R4A: this module has no CLI and creates no live backend.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol

from core_release_selector_upgrade_executor import (
    PHASES,
    ROLLBACK_PHASES,
    RuntimeSnapshot,
    UpgradeBackend,
    UpgradeBundle,
)


class UpgradeRecoveryError(RuntimeError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise UpgradeRecoveryError(code)


class RecoveryJournal(Protocol):
    @property
    def records(self) -> list[dict[str, object]]: ...

    def append(
        self,
        phase: str,
        event: str,
        data: Mapping[str, object] | None = None,
    ) -> None: ...

    def verify_receipt(self) -> dict[str, object] | None: ...


@dataclass(frozen=True, slots=True)
class RecoveryAssessment:
    last_phase: str
    files_may_have_changed: bool
    snapshot: RuntimeSnapshot
    receipt: Mapping[str, object] | None


FILE_CHANGE_PHASES = frozenset(
    {
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
        "committed",
        "rollback_file_restore_intent",
        "rollback_files_restored",
        "rollback_daemon_reload_intent",
        "rollback_daemon_reloaded",
    }
)


def _snapshot_from_record(record: Mapping[str, object]) -> RuntimeSnapshot:
    data = record.get("data")
    require(isinstance(data, Mapping), "prepared_data_rejected")
    payload = data.get("snapshot")
    require(isinstance(payload, Mapping), "prepared_snapshot_rejected")
    require(
        set(payload)
        == {
            "core_active",
            "gateway_socket_active",
            "gateway_service_active",
            "binding_sha256",
            "snapshot_sha256",
        },
        "prepared_snapshot_shape_rejected",
    )
    require(
        isinstance(payload["core_active"], bool)
        and isinstance(payload["gateway_socket_active"], bool)
        and isinstance(payload["gateway_service_active"], bool)
        and isinstance(payload["binding_sha256"], str),
        "prepared_snapshot_value_rejected",
    )
    snapshot = RuntimeSnapshot.create(
        core_active=payload["core_active"],
        gateway_socket_active=payload["gateway_socket_active"],
        gateway_service_active=payload["gateway_service_active"],
        binding_sha256=payload["binding_sha256"],
    )
    require(
        snapshot.snapshot_sha256 == payload["snapshot_sha256"],
        "prepared_snapshot_digest_rejected",
    )
    return snapshot


def _validate_records(records: list[dict[str, object]]) -> RuntimeSnapshot:
    require(bool(records), "empty_journal_has_nothing_to_recover")
    for record in records:
        require(
            isinstance(record, dict)
            and isinstance(record.get("phase"), str)
            and isinstance(record.get("event"), str)
            and isinstance(record.get("data"), Mapping),
            "journal_payload_shape_rejected",
        )
        require(
            record["phase"] in PHASES + ROLLBACK_PHASES,
            "journal_phase_rejected",
        )
    require(records[0]["phase"] == "prepared", "journal_missing_prepared_phase")

    rollback_index = next(
        (
            index
            for index, record in enumerate(records)
            if record["phase"] in ROLLBACK_PHASES
        ),
        len(records),
    )
    forward = [record["phase"] for record in records[:rollback_index]]
    require(
        forward == list(PHASES[: len(forward)]),
        "forward_journal_sequence_rejected",
    )
    rollback = [record["phase"] for record in records[rollback_index:]]
    if "rollback_failed" in rollback:
        require(rollback[-1] == "rollback_failed", "rollback_failed_not_terminal")
    if "rolled_back" in rollback:
        require(rollback[-1] == "rolled_back", "rolled_back_not_terminal")
    return _snapshot_from_record(records[0])


def _validate_receipt(
    receipt: Mapping[str, object],
    *,
    bundle: UpgradeBundle,
) -> None:
    require(
        receipt.get("schema")
        == "myuna.core-release-selector.selected-upgrade-receipt.v1"
        and receipt.get("status") == "selected_release_upgraded"
        and receipt.get("plan_digest") == bundle.plan_digest
        and receipt.get("target_tree_sha256")
        == bundle.plan["target"]["selected_release"]["tree_sha256"]
        and receipt.get("automatic_rollback_enabled") is True
        and receipt.get("secret_values_emitted") is False,
        "success_receipt_rejected",
    )


def assess_recovery(
    *,
    bundle: UpgradeBundle,
    journal: RecoveryJournal,
) -> RecoveryAssessment:
    records = journal.records
    snapshot = _validate_records(records)
    receipt = journal.verify_receipt()
    last_phase = str(records[-1]["phase"])
    if receipt is not None:
        _validate_receipt(receipt, bundle=bundle)
        require(
            last_phase in {"receipt_write_intent", "committed"},
            "success_receipt_phase_rejected",
        )
    return RecoveryAssessment(
        last_phase=last_phase,
        files_may_have_changed=any(
            record["phase"] in FILE_CHANGE_PHASES for record in records
        ),
        snapshot=snapshot,
        receipt=receipt,
    )


class SelectedUpgradeRecoveryExecutor:
    def __init__(
        self,
        *,
        bundle: UpgradeBundle,
        backend: UpgradeBackend,
        journal: RecoveryJournal,
    ) -> None:
        self.bundle = bundle
        self.backend = backend
        self.journal = journal

    def _append(
        self,
        phase: str,
        event: str,
        data: Mapping[str, object] | None = None,
    ) -> None:
        require(phase in ROLLBACK_PHASES + ("committed",), "recovery_phase_rejected")
        self.journal.append(phase, event, data)

    def recover(self) -> dict[str, object]:
        assessment = assess_recovery(bundle=self.bundle, journal=self.journal)
        if assessment.last_phase == "committed":
            require(assessment.receipt is not None, "committed_receipt_missing")
            return {
                "status": "already_committed",
                "plan_digest": self.bundle.plan_digest,
            }
        if assessment.last_phase == "rolled_back":
            require(assessment.receipt is None, "rolled_back_receipt_rejected")
            return {
                "status": "already_rolled_back",
                "plan_digest": self.bundle.plan_digest,
            }
        require(
            assessment.last_phase != "rollback_failed",
            "rollback_failed_requires_owner_plan",
        )

        if assessment.receipt is not None:
            try:
                self.backend.verify_target(self.bundle, assessment.snapshot)
                self.backend.restore_gateway(self.bundle, assessment.snapshot)
                self._append(
                    "committed",
                    "crash_recovery_completed_existing_success_receipt",
                )
                return {
                    "status": "recovered_committed",
                    "plan_digest": self.bundle.plan_digest,
                }
            except Exception as exc:
                self._append(
                    "rollback_failed",
                    "success_receipt_reconciliation_failed",
                    {"cause": type(exc).__name__},
                )
                raise UpgradeRecoveryError(
                    "success_receipt_reconciliation_failed"
                ) from exc

        self._append(
            "rollback_intent",
            "crash_recovery_rollback_started",
            {"from_phase": assessment.last_phase},
        )
        try:
            self.backend.quiesce_gateway(self.bundle)
            self._append(
                "rollback_gateway_quiesced",
                "crash_recovery_gateway_quiesced",
            )
            if assessment.files_may_have_changed:
                self._append(
                    "rollback_file_restore_intent",
                    "before_crash_recovery_file_restore",
                )
                self.backend.restore_files(self.bundle)
                self._append(
                    "rollback_files_restored",
                    "crash_recovery_files_restored",
                )
                self._append(
                    "rollback_daemon_reload_intent",
                    "before_crash_recovery_daemon_reload",
                )
                self.backend.daemon_reload(self.bundle)
                self._append(
                    "rollback_daemon_reloaded",
                    "crash_recovery_daemon_reloaded",
                )
            self._append(
                "rollback_prestate_restore_intent",
                "before_crash_recovery_prestate_restore",
            )
            self.backend.restore_prestate(self.bundle, assessment.snapshot)
            self._append(
                "rollback_prestate_restored",
                "crash_recovery_prestate_restored",
            )
            self._append("rolled_back", "crash_recovery_rollback_completed")
            return {
                "status": "recovered_rolled_back",
                "plan_digest": self.bundle.plan_digest,
            }
        except Exception as exc:
            self._append(
                "rollback_failed",
                "crash_recovery_rollback_failed",
                {"cause": type(exc).__name__},
            )
            raise UpgradeRecoveryError("crash_recovery_rollback_failed") from exc

