"""Journaled state machine for a selected-to-selected Core release upgrade.

R2A intentionally has no live backend and no filesystem journal.  All effects
are delegated through protocols so ordering and rollback can be verified with
the Fake backend before any privileged implementation is introduced.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Mapping, Protocol

from core_release_selector import canonical_json_bytes
from core_release_selector_upgrade import digest, validate_upgrade_bundle


PHASES = (
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
    "committed",
)
ROLLBACK_PHASES = (
    "rollback_intent",
    "rollback_gateway_quiesced",
    "rollback_file_restore_intent",
    "rollback_files_restored",
    "rollback_daemon_reload_intent",
    "rollback_daemon_reloaded",
    "rollback_prestate_restore_intent",
    "rollback_prestate_restored",
    "rolled_back",
    "rollback_failed",
)


class UpgradeExecutionError(RuntimeError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise UpgradeExecutionError(code)


@dataclass(frozen=True, slots=True)
class RuntimeSnapshot:
    core_active: bool
    gateway_socket_active: bool
    gateway_service_active: bool
    binding_sha256: str
    snapshot_sha256: str

    @classmethod
    def create(
        cls,
        *,
        core_active: bool,
        gateway_socket_active: bool,
        gateway_service_active: bool,
        binding_sha256: str,
    ) -> "RuntimeSnapshot":
        unsigned = {
            "core_active": core_active,
            "gateway_socket_active": gateway_socket_active,
            "gateway_service_active": gateway_service_active,
            "binding_sha256": binding_sha256,
        }
        return cls(
            **unsigned,
            snapshot_sha256=sha256(canonical_json_bytes(unsigned)).hexdigest(),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "core_active": self.core_active,
            "gateway_socket_active": self.gateway_socket_active,
            "gateway_service_active": self.gateway_service_active,
            "binding_sha256": self.binding_sha256,
            "snapshot_sha256": self.snapshot_sha256,
        }


@dataclass(frozen=True, slots=True)
class UpgradeBundle:
    payloads: Mapping[str, bytes]
    plan: Mapping[str, object]
    plan_digest: str
    manifest: Mapping[str, object]

    @classmethod
    def load(cls, payloads: Mapping[str, bytes], *, approved_plan_digest: str) -> "UpgradeBundle":
        manifest = validate_upgrade_bundle(payloads)
        plan_payload = payloads["activation/UPGRADE_PLAN.json"]
        actual = digest(plan_payload)
        require(actual == approved_plan_digest, "upgrade_plan_approval_rejected")
        from core_release_selector_upgrade import load_upgrade_plan

        plan = load_upgrade_plan(plan_payload)
        return cls(payloads=dict(payloads), plan=plan, plan_digest=actual, manifest=manifest)


class UpgradeBackend(Protocol):
    def verify_exact_prestate(self, bundle: UpgradeBundle) -> RuntimeSnapshot: ...

    def quiesce_gateway(self, bundle: UpgradeBundle) -> None: ...

    def apply_files(self, bundle: UpgradeBundle) -> None: ...

    def daemon_reload(self, bundle: UpgradeBundle) -> None: ...

    def start_core(self, bundle: UpgradeBundle) -> None: ...

    def verify_target(self, bundle: UpgradeBundle, snapshot: RuntimeSnapshot) -> None: ...

    def restore_gateway(self, bundle: UpgradeBundle, snapshot: RuntimeSnapshot) -> None: ...

    def restore_files(self, bundle: UpgradeBundle) -> None: ...

    def restore_prestate(self, bundle: UpgradeBundle, snapshot: RuntimeSnapshot) -> None: ...


class UpgradeJournal(Protocol):
    @property
    def records(self) -> list[dict[str, object]]: ...

    def append(self, phase: str, event: str, data: Mapping[str, object] | None = None) -> None: ...

    def write_receipt(self, document: Mapping[str, object]) -> None: ...


class MemoryJournal:
    def __init__(self) -> None:
        self._records: list[dict[str, object]] = []
        self.receipt: dict[str, object] | None = None

    @property
    def records(self) -> list[dict[str, object]]:
        return list(self._records)

    def append(self, phase: str, event: str, data: Mapping[str, object] | None = None) -> None:
        self._records.append({"phase": phase, "event": event, "data": dict(data or {})})

    def write_receipt(self, document: Mapping[str, object]) -> None:
        require(self.receipt is None, "receipt_already_written")
        self.receipt = dict(document)


class FakeUpgradeBackend:
    """Deterministic stateful Fake; it cannot touch the host."""

    def __init__(self, *, fail_at: str | None = None) -> None:
        self.fail_at = fail_at
        self.events: list[str] = []
        self.files = "prestate"
        self.core = "inactive"
        self.gateway = "prestate"
        self.reload_count = 0
        self.snapshot = RuntimeSnapshot.create(
            core_active=False,
            gateway_socket_active=True,
            gateway_service_active=False,
            binding_sha256="a" * 64,
        )

    def _event(self, name: str) -> None:
        self.events.append(name)
        if self.fail_at == name:
            raise UpgradeExecutionError(f"fake_failure:{name}")

    def verify_exact_prestate(self, bundle: UpgradeBundle) -> RuntimeSnapshot:
        self._event("verify_exact_prestate")
        require(self.files == "prestate" and self.gateway == "prestate", "fake_prestate_rejected")
        return self.snapshot

    def quiesce_gateway(self, bundle: UpgradeBundle) -> None:
        self._event("quiesce_gateway")
        self.gateway = "quiesced"

    def apply_files(self, bundle: UpgradeBundle) -> None:
        self._event("apply_files")
        require(self.gateway == "quiesced", "fake_gateway_not_quiesced")
        self.files = "target"

    def daemon_reload(self, bundle: UpgradeBundle) -> None:
        self._event("daemon_reload")
        self.reload_count += 1

    def start_core(self, bundle: UpgradeBundle) -> None:
        self._event("start_core")
        require(self.files == "target", "fake_target_files_missing")
        self.core = "active_target"

    def verify_target(self, bundle: UpgradeBundle, snapshot: RuntimeSnapshot) -> None:
        self._event("verify_target")
        require(self.core == "active_target" and self.files == "target", "fake_target_rejected")

    def restore_gateway(self, bundle: UpgradeBundle, snapshot: RuntimeSnapshot) -> None:
        self._event("restore_gateway")
        self.gateway = "prestate"

    def restore_files(self, bundle: UpgradeBundle) -> None:
        self._event("restore_files")
        self.files = "prestate"

    def restore_prestate(self, bundle: UpgradeBundle, snapshot: RuntimeSnapshot) -> None:
        self._event("restore_prestate")
        self.core = "inactive" if not snapshot.core_active else "active_prestate"
        self.gateway = "prestate"


class JournaledUpgradeExecutor:
    def __init__(self, *, bundle: UpgradeBundle, backend: UpgradeBackend, journal: UpgradeJournal) -> None:
        self.bundle = bundle
        self.backend = backend
        self.journal = journal

    def _append(self, phase: str, event: str, data: Mapping[str, object] | None = None) -> None:
        require(phase in PHASES + ROLLBACK_PHASES, "phase_rejected")
        self.journal.append(phase, event, data)

    def _rollback(self, snapshot: RuntimeSnapshot, cause: str, files_may_have_changed: bool) -> dict[str, object]:
        self._append("rollback_intent", "automatic_rollback_started", {"cause": cause})
        try:
            self.backend.quiesce_gateway(self.bundle)
            self._append("rollback_gateway_quiesced", "rollback_gateway_quiesced")
            if files_may_have_changed:
                self._append("rollback_file_restore_intent", "before_rollback_file_restore")
                self.backend.restore_files(self.bundle)
                self._append("rollback_files_restored", "rollback_files_restored")
                self._append("rollback_daemon_reload_intent", "before_rollback_daemon_reload")
                self.backend.daemon_reload(self.bundle)
                self._append("rollback_daemon_reloaded", "rollback_daemon_reloaded")
            self._append("rollback_prestate_restore_intent", "before_runtime_prestate_restore")
            self.backend.restore_prestate(self.bundle, snapshot)
            self._append("rollback_prestate_restored", "runtime_prestate_restored")
            self._append("rolled_back", "automatic_rollback_completed")
            return {"status": "rolled_back", "cause": cause, "plan_digest": self.bundle.plan_digest}
        except Exception as exc:
            self._append("rollback_failed", "automatic_rollback_failed", {"cause": type(exc).__name__})
            raise UpgradeExecutionError("automatic_rollback_failed") from exc

    def execute(self) -> dict[str, object]:
        require(not self.journal.records, "nonempty_journal_requires_later_recovery_contract")
        snapshot = self.backend.verify_exact_prestate(self.bundle)
        self._append("prepared", "exact_prestate_verified", {"snapshot": snapshot.to_payload()})
        files_may_have_changed = False
        try:
            self._append("gateway_quiesce_intent", "before_gateway_quiesce")
            self.backend.quiesce_gateway(self.bundle)
            self._append("gateway_quiesced", "gateway_quiesced")
            self._append("file_apply_intent", "before_file_apply")
            files_may_have_changed = True
            self.backend.apply_files(self.bundle)
            self._append("files_applied", "target_files_applied")
            self._append("daemon_reload_intent", "before_daemon_reload")
            self.backend.daemon_reload(self.bundle)
            self._append("daemon_reloaded", "daemon_reloaded")
            self._append("core_start_intent", "before_core_start")
            self.backend.start_core(self.bundle)
            self._append("core_started", "core_started")
            self.backend.verify_target(self.bundle, snapshot)
            self._append("target_verified", "target_verified")
            self._append("gateway_restore_intent", "before_gateway_restore")
            self.backend.restore_gateway(self.bundle, snapshot)
            self._append("gateway_restored", "gateway_restored")
            self._append("receipt_write_intent", "before_receipt_write")
            receipt = {
                "schema": "myuna.core-release-selector.selected-upgrade-receipt.v1",
                "status": "selected_release_upgraded",
                "plan_digest": self.bundle.plan_digest,
                "target_tree_sha256": self.bundle.plan["target"]["selected_release"]["tree_sha256"],
                "prestate_snapshot_sha256": snapshot.snapshot_sha256,
                "automatic_rollback_enabled": True,
                "secret_values_emitted": False,
            }
            self.journal.write_receipt(receipt)
            self._append("committed", "upgrade_committed")
            return {"status": "activated", "plan_digest": self.bundle.plan_digest}
        except Exception as exc:
            return self._rollback(snapshot, type(exc).__name__, files_may_have_changed)

