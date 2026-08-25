"""Journaled state machine for socket-aware Core Selector R4C activation.

This module contains no systemd command construction and no live path writes.
Those effects are delegated to an explicit backend.  The executor owns only
the deterministic ordering, durable intent journal, rollback policy, crash
recovery, and idempotent receipt semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
import grp
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
from typing import Mapping, Protocol

from core_release_selector import canonical_json_bytes, parse_json_document
import core_release_selector_transaction as transaction_v1
from core_release_selector_transaction_v2 import (
    digest,
    load_activation_plan,
    transaction_tree_digest,
    validate_transaction_payloads,
)
from core_release_selector_r4c_journal import (
    ACTIVATION_RECEIPT_SCHEMA,
    FileJournal,
    JournalError,
)


_HEX_64 = re.compile(r"^[a-f0-9]{64}$")
INACTIVE_INSTALL_RECEIPT_SCHEMA = (
    "myuna.core-release-selector.r4b-inactive-installation-receipt.v2"
)
PHASE_PREPARED = "prepared"
PHASE_SOCKET_STOP_INTENT = "socket_stop_intent"
PHASE_SOCKET_STOPPED = "socket_stopped"
PHASE_GATEWAY_STOP_INTENT = "gateway_stop_intent"
PHASE_GATEWAY_STOPPED = "gateway_stopped"
PHASE_CORE_APPLY_INTENT = "core_apply_intent"
PHASE_CORE_APPLIED = "core_applied"
PHASE_DAEMON_RELOAD_INTENT = "daemon_reload_intent"
PHASE_DAEMON_RELOADED = "daemon_reloaded"
PHASE_CORE_RESTART_INTENT = "core_restart_intent"
PHASE_CORE_RESTARTED = "core_restarted"
PHASE_CORE_VERIFIED = "core_verified"
PHASE_SOCKET_START_INTENT = "socket_start_intent"
PHASE_SOCKET_STARTED = "socket_started"
PHASE_SOCKET_VERIFIED = "socket_verified"
PHASE_GATEWAY_START_INTENT = "gateway_start_intent"
PHASE_GATEWAY_STARTED = "gateway_started"
PHASE_GATEWAY_VERIFIED = "gateway_verified"
PHASE_RECEIPT_WRITE_INTENT = "receipt_write_intent"
PHASE_COMMITTED = "committed"
PHASE_ROLLBACK_INTENT = "rollback_intent"
PHASE_ROLLBACK_SOCKET_STOPPED = "rollback_socket_stopped"
PHASE_ROLLBACK_GATEWAY_STOP_INTENT = "rollback_gateway_stop_intent"
PHASE_ROLLBACK_GATEWAY_STOPPED = "rollback_gateway_stopped"
PHASE_ROLLBACK_CORE_RESTORE_INTENT = "rollback_core_restore_intent"
PHASE_ROLLBACK_CORE_FILES_RESTORED = "rollback_core_files_restored"
PHASE_ROLLBACK_DAEMON_RELOAD_INTENT = "rollback_daemon_reload_intent"
PHASE_ROLLBACK_DAEMON_RELOADED = "rollback_daemon_reloaded"
PHASE_ROLLBACK_CORE_RESTART_INTENT = "rollback_core_restart_intent"
PHASE_ROLLBACK_CORE_RESTARTED = "rollback_core_restarted"
PHASE_ROLLBACK_CORE_RESTORED = "rollback_core_restored"
PHASE_ROLLBACK_SOCKET_RESTORE_INTENT = "rollback_socket_restore_intent"
PHASE_ROLLBACK_SOCKET_RESTORED = "rollback_socket_restored"
PHASE_ROLLBACK_GATEWAY_RESTORE_INTENT = "rollback_gateway_restore_intent"
PHASE_ROLLBACK_GATEWAY_RESTORED = "rollback_gateway_restored"
PHASE_ROLLED_BACK = "rolled_back"
PHASE_ROLLBACK_FAILED = "rollback_failed"

_FORWARD_ORDER = (
    PHASE_PREPARED,
    PHASE_SOCKET_STOP_INTENT,
    PHASE_SOCKET_STOPPED,
    PHASE_GATEWAY_STOP_INTENT,
    PHASE_GATEWAY_STOPPED,
    PHASE_CORE_APPLY_INTENT,
    PHASE_CORE_APPLIED,
    PHASE_DAEMON_RELOAD_INTENT,
    PHASE_DAEMON_RELOADED,
    PHASE_CORE_RESTART_INTENT,
    PHASE_CORE_RESTARTED,
    PHASE_CORE_VERIFIED,
    PHASE_SOCKET_START_INTENT,
    PHASE_SOCKET_STARTED,
    PHASE_SOCKET_VERIFIED,
    PHASE_GATEWAY_START_INTENT,
    PHASE_GATEWAY_STARTED,
    PHASE_GATEWAY_VERIFIED,
    PHASE_RECEIPT_WRITE_INTENT,
    PHASE_COMMITTED,
)
_FORWARD_INDEX = {phase: index for index, phase in enumerate(_FORWARD_ORDER)}
_TERMINAL_PHASES = {
    PHASE_COMMITTED,
    PHASE_ROLLED_BACK,
    PHASE_ROLLBACK_FAILED,
}
_ROLLBACK_PHASES = {
    PHASE_ROLLBACK_INTENT,
    PHASE_ROLLBACK_SOCKET_STOPPED,
    PHASE_ROLLBACK_GATEWAY_STOP_INTENT,
    PHASE_ROLLBACK_GATEWAY_STOPPED,
    PHASE_ROLLBACK_CORE_RESTORE_INTENT,
    PHASE_ROLLBACK_CORE_FILES_RESTORED,
    PHASE_ROLLBACK_DAEMON_RELOAD_INTENT,
    PHASE_ROLLBACK_DAEMON_RELOADED,
    PHASE_ROLLBACK_CORE_RESTART_INTENT,
    PHASE_ROLLBACK_CORE_RESTARTED,
    PHASE_ROLLBACK_CORE_RESTORED,
    PHASE_ROLLBACK_SOCKET_RESTORE_INTENT,
    PHASE_ROLLBACK_SOCKET_RESTORED,
    PHASE_ROLLBACK_GATEWAY_RESTORE_INTENT,
    PHASE_ROLLBACK_GATEWAY_RESTORED,
    PHASE_ROLLED_BACK,
    PHASE_ROLLBACK_FAILED,
}


class R4CExecutionError(RuntimeError):
    """A deterministic activation, recovery, or rollback rejection."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise R4CExecutionError(code)


def _hex_digest(value: str, code: str) -> str:
    _require(isinstance(value, str) and _HEX_64.fullmatch(value) is not None, code)
    return value


def _safe_transaction_payloads(root: Path) -> dict[str, bytes]:
    _require(
        isinstance(root, Path)
        and root.is_absolute()
        and root.is_dir()
        and not root.is_symlink(),
        "transaction_root_rejected",
    )
    payloads: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        _require(not path.is_symlink(), "transaction_symlink_rejected")
        if path.is_dir():
            continue
        _require(path.is_file(), "transaction_entry_rejected")
        relative = path.relative_to(root).as_posix()
        _require(relative not in payloads, "transaction_duplicate_path")
        payloads[relative] = path.read_bytes()
    _require(bool(payloads), "transaction_empty")
    return payloads


def _validate_installed_transaction_permissions(
    root: Path,
    *,
    expected_uid: int,
    expected_gid: int,
) -> None:
    for entry in (root, *root.rglob("*")):
        _require(not entry.is_symlink(), "transaction_permissions_rejected")
        metadata = entry.stat()
        expected_mode = 0o550 if entry.is_dir() else 0o440
        _require(
            metadata.st_uid == expected_uid
            and metadata.st_gid == expected_gid
            and stat.S_IMODE(metadata.st_mode) == expected_mode,
            "transaction_permissions_rejected",
        )


@dataclass(frozen=True)
class TransactionBundle:
    root: Path
    tree_sha256: str
    activation_plan_digest: str
    plan: dict[str, object]
    payloads: Mapping[str, bytes]

    @classmethod
    def load(
        cls,
        root: Path,
        *,
        expected_tree_sha256: str,
        approved_activation_plan_digest: str,
        validate_installed_permissions: bool = True,
        expected_uid: int = 0,
        expected_gid: int | None = None,
    ) -> "TransactionBundle":
        expected_tree = _hex_digest(
            expected_tree_sha256,
            "expected_transaction_digest_rejected",
        )
        approved = _hex_digest(
            approved_activation_plan_digest,
            "approved_activation_digest_rejected",
        )
        _require(root.name == expected_tree, "transaction_directory_name_rejected")
        if validate_installed_permissions:
            if expected_gid is None:
                try:
                    expected_gid = grp.getgrnam("myuna").gr_gid
                except KeyError as exc:
                    raise R4CExecutionError("myuna_group_missing") from exc
            _validate_installed_transaction_permissions(
                root,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
        payloads = _safe_transaction_payloads(root)
        try:
            evidence = validate_transaction_payloads(payloads)
            plan_payload = payloads[transaction_v1.ACTIVATION_PLAN_PATH]
            plan = load_activation_plan(plan_payload)
        except Exception as exc:
            raise R4CExecutionError("transaction_contract_rejected") from exc
        actual_tree = transaction_tree_digest(payloads)
        actual_plan = digest(plan_payload)
        _require(
            actual_tree == expected_tree
            and evidence.transaction_tree_sha256 == expected_tree
            and actual_plan == approved
            and evidence.activation_plan_digest == approved,
            "transaction_approval_binding_rejected",
        )
        binding_payload = payloads[transaction_v1.RUNTIME_BINDING_PATH]
        _require(
            sha256(binding_payload).hexdigest()
            == parse_json_document(
                payloads[transaction_v1.MIGRATION_EVIDENCE_PATH]
            )["runtime_binding_sha256"],
            "runtime_binding_evidence_rejected",
        )
        return cls(
            root=root,
            tree_sha256=actual_tree,
            activation_plan_digest=actual_plan,
            plan=plan,
            payloads=payloads,
        )

    def payload(self, relative_path: str) -> bytes:
        try:
            return self.payloads[relative_path]
        except KeyError as exc:
            raise R4CExecutionError("transaction_artifact_missing") from exc

    @property
    def runtime_binding(self) -> bytes:
        return self.payload(transaction_v1.RUNTIME_BINDING_PATH)

    @property
    def rollback_dropins(self) -> dict[str, bytes]:
        return {
            path[len(transaction_v1.ROLLBACK_PREFIX) :]: payload
            for path, payload in self.payloads.items()
            if path.startswith(transaction_v1.ROLLBACK_PREFIX)
        }

    @property
    def final_dropins(self) -> dict[str, bytes]:
        return {
            path[len(transaction_v1.FINAL_PREFIX) :]: payload
            for path, payload in self.payloads.items()
            if path.startswith(transaction_v1.FINAL_PREFIX)
        }


def verify_inactive_install_receipt(
    path: Path,
    bundle: TransactionBundle,
    *,
    approved_r4b_plan_digest: str,
    validate_installed_permissions: bool = True,
    expected_uid: int = 0,
    expected_gid: int | None = None,
) -> dict[str, object]:
    approval = _hex_digest(
        approved_r4b_plan_digest,
        "inactive_install_approval_digest_rejected",
    )
    _require(
        isinstance(path, Path)
        and path.is_absolute()
        and path.name == f"{approval}.json"
        and path.is_file()
        and not path.is_symlink(),
        "inactive_install_receipt_path_rejected",
    )
    if validate_installed_permissions:
        if expected_gid is None:
            try:
                expected_gid = grp.getgrnam("myuna").gr_gid
            except KeyError as exc:
                raise R4CExecutionError("myuna_group_missing") from exc
        metadata = path.stat()
        _require(
            metadata.st_uid == expected_uid
            and metadata.st_gid == expected_gid
            and stat.S_IMODE(metadata.st_mode) == 0o440,
            "inactive_install_receipt_permissions_rejected",
        )
    payload = path.read_bytes()
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise R4CExecutionError("inactive_install_receipt_json_rejected") from exc
    expected = {
        "schema": INACTIVE_INSTALL_RECEIPT_SCHEMA,
        "status": "inactive_socket_aware_transaction_installed",
        "approved_r4b_plan_digest": approval,
        "transaction_tree_sha256": bundle.tree_sha256,
        "transaction_path": bundle.root.as_posix(),
        "activation_plan_digest": bundle.activation_plan_digest,
        "runtime_binding_sha256": sha256(bundle.runtime_binding).hexdigest(),
        "artifact_count": len(bundle.payloads),
        "gateway_socket_in_contract": True,
        "runtime_paths_written": False,
        "systemd_changed": False,
        "daemon_reload_performed": False,
        "service_lifecycle_performed": False,
        "selected_or_activated": False,
    }
    _require(
        document == expected and canonical_json_bytes(document) == payload,
        "inactive_install_receipt_integrity_rejected",
    )
    return document


@dataclass(frozen=True)
class RuntimeSnapshot:
    core_restart_count: int
    core_active: bool
    gateway_socket_active: bool
    gateway_service_active: bool
    snapshot_sha256: str

    def to_payload(self) -> dict[str, object]:
        return {
            "core_restart_count": self.core_restart_count,
            "core_active": self.core_active,
            "gateway_socket_active": self.gateway_socket_active,
            "gateway_service_active": self.gateway_service_active,
            "snapshot_sha256": self.snapshot_sha256,
        }

    @classmethod
    def from_payload(cls, payload: object) -> "RuntimeSnapshot":
        _require(
            isinstance(payload, dict)
            and set(payload)
            == {
                "core_restart_count",
                "core_active",
                "gateway_socket_active",
                "gateway_service_active",
                "snapshot_sha256",
            }
            and type(payload["core_restart_count"]) is int
            and payload["core_restart_count"] >= 0
            and type(payload["core_active"]) is bool
            and type(payload["gateway_socket_active"]) is bool
            and type(payload["gateway_service_active"]) is bool,
            "journal_snapshot_rejected",
        )
        snapshot_hash = _hex_digest(
            payload["snapshot_sha256"],
            "journal_snapshot_rejected",
        )
        unsigned = dict(payload)
        unsigned.pop("snapshot_sha256")
        _require(
            sha256(canonical_json_bytes(unsigned)).hexdigest() == snapshot_hash,
            "journal_snapshot_integrity_rejected",
        )
        return cls(
            core_restart_count=payload["core_restart_count"],
            core_active=payload["core_active"],
            gateway_socket_active=payload["gateway_socket_active"],
            gateway_service_active=payload["gateway_service_active"],
            snapshot_sha256=snapshot_hash,
        )

    @classmethod
    def create(
        cls,
        *,
        core_restart_count: int,
        core_active: bool,
        gateway_socket_active: bool,
        gateway_service_active: bool,
    ) -> "RuntimeSnapshot":
        unsigned = {
            "core_restart_count": core_restart_count,
            "core_active": core_active,
            "gateway_socket_active": gateway_socket_active,
            "gateway_service_active": gateway_service_active,
        }
        return cls(
            **unsigned,
            snapshot_sha256=sha256(canonical_json_bytes(unsigned)).hexdigest(),
        )


class ActivationBackend(Protocol):
    def verify_exact_prestate(self, bundle: TransactionBundle) -> RuntimeSnapshot:
        ...

    def stop_gateway_socket(self, bundle: TransactionBundle) -> None:
        ...

    def verify_gateway_socket_inactive(self, bundle: TransactionBundle) -> None:
        ...

    def stop_gateway_service(self, bundle: TransactionBundle) -> None:
        ...

    def verify_gateway_service_inactive(self, bundle: TransactionBundle) -> None:
        ...

    def apply_core_files(self, bundle: TransactionBundle) -> None:
        ...

    def daemon_reload(self, bundle: TransactionBundle) -> None:
        ...

    def restart_core(self, bundle: TransactionBundle) -> None:
        ...

    def verify_target_core(
        self,
        bundle: TransactionBundle,
        snapshot: RuntimeSnapshot,
        *,
        enforce_restart_budget: bool = True,
    ) -> None:
        ...

    def start_gateway_socket(self, bundle: TransactionBundle) -> None:
        ...

    def verify_gateway_socket_active(self, bundle: TransactionBundle) -> None:
        ...

    def start_gateway_service(self, bundle: TransactionBundle) -> None:
        ...

    def verify_gateway_service_active(self, bundle: TransactionBundle) -> None:
        ...

    def restore_core_files(self, bundle: TransactionBundle) -> None:
        ...

    def verify_rollback_core(
        self,
        bundle: TransactionBundle,
        snapshot: RuntimeSnapshot,
    ) -> None:
        ...


def _last_phase(records: list[dict[str, object]]) -> str | None:
    return records[-1]["phase"] if records else None


def _snapshot_from_records(
    records: list[dict[str, object]],
) -> RuntimeSnapshot:
    prepared = [record for record in records if record["phase"] == PHASE_PREPARED]
    _require(len(prepared) == 1, "journal_prepared_record_rejected")
    return RuntimeSnapshot.from_payload(prepared[0]["data"]["snapshot"])


def _core_mutation_may_have_started(phase: str) -> bool:
    if phase in _ROLLBACK_PHASES:
        return True
    return phase in _FORWARD_INDEX and _FORWARD_INDEX[phase] >= _FORWARD_INDEX[
        PHASE_CORE_APPLY_INTENT
    ]


def _validate_journal_lifecycle(
    records: list[dict[str, object]],
) -> None:
    _require(bool(records), "journal_lifecycle_empty")
    phases = [record["phase"] for record in records]
    _require(
        phases[0] == PHASE_PREPARED
        and phases.count(PHASE_PREPARED) == 1,
        "journal_lifecycle_rejected",
    )
    rollback_transitions = {
        PHASE_ROLLBACK_INTENT: {PHASE_ROLLBACK_SOCKET_STOPPED},
        PHASE_ROLLBACK_SOCKET_STOPPED: {
            PHASE_ROLLBACK_GATEWAY_STOP_INTENT
        },
        PHASE_ROLLBACK_GATEWAY_STOP_INTENT: {
            PHASE_ROLLBACK_GATEWAY_STOPPED
        },
        PHASE_ROLLBACK_GATEWAY_STOPPED: {
            PHASE_ROLLBACK_CORE_RESTORE_INTENT,
            PHASE_ROLLBACK_SOCKET_RESTORE_INTENT,
        },
        PHASE_ROLLBACK_CORE_RESTORE_INTENT: {
            PHASE_ROLLBACK_CORE_FILES_RESTORED
        },
        PHASE_ROLLBACK_CORE_FILES_RESTORED: {
            PHASE_ROLLBACK_DAEMON_RELOAD_INTENT
        },
        PHASE_ROLLBACK_DAEMON_RELOAD_INTENT: {
            PHASE_ROLLBACK_DAEMON_RELOADED
        },
        PHASE_ROLLBACK_DAEMON_RELOADED: {
            PHASE_ROLLBACK_CORE_RESTART_INTENT
        },
        PHASE_ROLLBACK_CORE_RESTART_INTENT: {
            PHASE_ROLLBACK_CORE_RESTARTED
        },
        PHASE_ROLLBACK_CORE_RESTARTED: {PHASE_ROLLBACK_CORE_RESTORED},
        PHASE_ROLLBACK_CORE_RESTORED: {
            PHASE_ROLLBACK_SOCKET_RESTORE_INTENT
        },
        PHASE_ROLLBACK_SOCKET_RESTORE_INTENT: {
            PHASE_ROLLBACK_SOCKET_RESTORED
        },
        PHASE_ROLLBACK_SOCKET_RESTORED: {
            PHASE_ROLLBACK_GATEWAY_RESTORE_INTENT
        },
        PHASE_ROLLBACK_GATEWAY_RESTORE_INTENT: {
            PHASE_ROLLBACK_GATEWAY_RESTORED
        },
        PHASE_ROLLBACK_GATEWAY_RESTORED: {PHASE_ROLLED_BACK},
    }
    for current, following in zip(phases, phases[1:]):
        if current in _TERMINAL_PHASES:
            raise R4CExecutionError("journal_terminal_phase_followed")
        if current in _FORWARD_INDEX:
            next_index = _FORWARD_INDEX[current] + 1
            normal = (
                next_index < len(_FORWARD_ORDER)
                and _FORWARD_ORDER[next_index] == following
            )
            _require(
                normal or following == PHASE_ROLLBACK_INTENT,
                "journal_forward_transition_rejected",
            )
            continue
        allowed = rollback_transitions.get(current, set())
        _require(
            following in allowed or following == PHASE_ROLLBACK_FAILED,
            "journal_rollback_transition_rejected",
        )


class JournaledR4CExecutor:
    def __init__(
        self,
        *,
        bundle: TransactionBundle,
        journal: FileJournal,
        backend: ActivationBackend,
    ) -> None:
        _require(
            bundle.activation_plan_digest == journal.plan_digest
            and bundle.tree_sha256 == journal.transaction_tree_sha256,
            "executor_journal_binding_rejected",
        )
        self.bundle = bundle
        self.journal = journal
        self.backend = backend

    def _append(
        self,
        phase: str,
        event: str,
        data: Mapping[str, object] | None = None,
    ) -> None:
        self.journal.append(phase=phase, event=event, data=data)

    def _receipt_document(
        self,
        snapshot: RuntimeSnapshot,
    ) -> dict[str, object]:
        return {
            "schema": ACTIVATION_RECEIPT_SCHEMA,
            "status": "core_release_selector_active",
            "plan_digest": self.bundle.activation_plan_digest,
            "transaction_tree_sha256": self.bundle.tree_sha256,
            "selected_release_tree_sha256": self.bundle.plan["target"][
                "tree_sha256"
            ],
            "unit": self.bundle.plan["unit"],
            "gateway_socket_unit": self.bundle.plan["gateway"]["socket"]["unit"],
            "gateway_service_unit": self.bundle.plan["gateway"]["unit"],
            "prestate_snapshot_sha256": snapshot.snapshot_sha256,
            "core_restart_count_before": snapshot.core_restart_count,
            "maximum_activation_restart_count_increase": 1,
            "automatic_rollback_enabled": True,
            "secret_values_emitted": False,
        }

    def _commit(
        self,
        snapshot: RuntimeSnapshot,
        *,
        current_phase: str,
    ) -> dict[str, object]:
        _require(
            current_phase
            in {PHASE_GATEWAY_VERIFIED, PHASE_RECEIPT_WRITE_INTENT},
            "commit_phase_rejected",
        )
        if current_phase == PHASE_GATEWAY_VERIFIED:
            self._append(
                PHASE_RECEIPT_WRITE_INTENT,
                "before_activation_receipt_write",
            )
        document = self._receipt_document(snapshot)
        self.journal.write_receipt(document)
        self._append(
            PHASE_COMMITTED,
            "activation_committed",
            {
                "receipt_sha256": sha256(
                    canonical_json_bytes(document)
                ).hexdigest()
            },
        )
        return {
            "status": "activated",
            "plan_digest": self.bundle.activation_plan_digest,
            "transaction_tree_sha256": self.bundle.tree_sha256,
            "receipt_path": self.journal.receipt_path.as_posix(),
            "selected_or_activated": True,
        }

    def _verify_committed(
        self,
        snapshot: RuntimeSnapshot,
    ) -> dict[str, object]:
        self.backend.verify_target_core(
            self.bundle,
            snapshot,
            enforce_restart_budget=False,
        )
        self.backend.verify_gateway_socket_active(self.bundle)
        self.backend.verify_gateway_service_active(self.bundle)
        expected = self._receipt_document(snapshot)
        _require(
            self.journal.read_receipt() == expected,
            "committed_receipt_rejected",
        )
        return {
            "status": "already_activated_verified",
            "plan_digest": self.bundle.activation_plan_digest,
            "transaction_tree_sha256": self.bundle.tree_sha256,
            "selected_or_activated": True,
            "mutations_performed": False,
        }

    def _forward_from_prepared(
        self,
        snapshot: RuntimeSnapshot,
    ) -> dict[str, object]:
        self._append(PHASE_SOCKET_STOP_INTENT, "before_gateway_socket_stop")
        self.backend.stop_gateway_socket(self.bundle)
        self.backend.verify_gateway_socket_inactive(self.bundle)
        self._append(PHASE_SOCKET_STOPPED, "gateway_socket_stopped")

        self._append(PHASE_GATEWAY_STOP_INTENT, "before_gateway_service_stop")
        self.backend.stop_gateway_service(self.bundle)
        self.backend.verify_gateway_service_inactive(self.bundle)
        self._append(PHASE_GATEWAY_STOPPED, "gateway_service_stopped")

        self._append(PHASE_CORE_APPLY_INTENT, "before_core_file_mutation")
        self.backend.apply_core_files(self.bundle)
        self._append(PHASE_CORE_APPLIED, "core_files_applied")

        self._append(PHASE_DAEMON_RELOAD_INTENT, "before_daemon_reload")
        self.backend.daemon_reload(self.bundle)
        self._append(PHASE_DAEMON_RELOADED, "daemon_reloaded")

        self._append(PHASE_CORE_RESTART_INTENT, "before_core_restart")
        self.backend.restart_core(self.bundle)
        self._append(PHASE_CORE_RESTARTED, "core_restarted")
        self.backend.verify_target_core(self.bundle, snapshot)
        self._append(PHASE_CORE_VERIFIED, "target_core_verified")

        return self._resume_gateway_and_commit(
            snapshot,
            current_phase=PHASE_CORE_VERIFIED,
        )

    def _resume_gateway_and_commit(
        self,
        snapshot: RuntimeSnapshot,
        *,
        current_phase: str,
    ) -> dict[str, object]:
        _require(
            current_phase in _FORWARD_INDEX
            and _FORWARD_INDEX[PHASE_CORE_VERIFIED]
            <= _FORWARD_INDEX[current_phase]
            <= _FORWARD_INDEX[PHASE_RECEIPT_WRITE_INTENT],
            "gateway_resume_phase_rejected",
        )
        phase = current_phase
        if _FORWARD_INDEX[phase] < _FORWARD_INDEX[PHASE_SOCKET_START_INTENT]:
            self._append(PHASE_SOCKET_START_INTENT, "before_gateway_socket_start")
            phase = PHASE_SOCKET_START_INTENT
        if phase == PHASE_SOCKET_START_INTENT:
            self.backend.start_gateway_socket(self.bundle)
            self._append(PHASE_SOCKET_STARTED, "gateway_socket_started")
            phase = PHASE_SOCKET_STARTED
        if phase == PHASE_SOCKET_STARTED:
            self.backend.verify_gateway_socket_active(self.bundle)
            self._append(PHASE_SOCKET_VERIFIED, "gateway_socket_verified")
            phase = PHASE_SOCKET_VERIFIED
        if phase == PHASE_SOCKET_VERIFIED:
            self._append(
                PHASE_GATEWAY_START_INTENT,
                "before_gateway_service_start",
            )
            phase = PHASE_GATEWAY_START_INTENT
        if phase == PHASE_GATEWAY_START_INTENT:
            self.backend.start_gateway_service(self.bundle)
            self._append(PHASE_GATEWAY_STARTED, "gateway_service_started")
            phase = PHASE_GATEWAY_STARTED
        if phase == PHASE_GATEWAY_STARTED:
            self.backend.verify_gateway_service_active(self.bundle)
            self._append(PHASE_GATEWAY_VERIFIED, "gateway_service_verified")
            phase = PHASE_GATEWAY_VERIFIED
        return self._commit(snapshot, current_phase=phase)

    def _rollback(
        self,
        snapshot: RuntimeSnapshot,
        *,
        cause: str,
        core_mutation_may_have_started: bool,
    ) -> dict[str, object]:
        self._append(
            PHASE_ROLLBACK_INTENT,
            "automatic_rollback_started",
            {
                "cause": cause,
                "core_mutation_may_have_started": core_mutation_may_have_started,
            },
        )
        return self._continue_rollback(
            snapshot,
            cause=cause,
            core_mutation_may_have_started=core_mutation_may_have_started,
            current_phase=PHASE_ROLLBACK_INTENT,
        )

    def _continue_rollback(
        self,
        snapshot: RuntimeSnapshot,
        *,
        cause: str,
        core_mutation_may_have_started: bool,
        current_phase: str,
    ) -> dict[str, object]:
        _require(
            current_phase in _ROLLBACK_PHASES
            and current_phase
            not in {
                PHASE_ROLLED_BACK,
                PHASE_ROLLBACK_FAILED,
            },
            "rollback_resume_phase_rejected",
        )
        phase = current_phase
        try:
            if phase == PHASE_ROLLBACK_INTENT:
                self.backend.stop_gateway_socket(self.bundle)
                self.backend.verify_gateway_socket_inactive(self.bundle)
                self._append(
                    PHASE_ROLLBACK_SOCKET_STOPPED,
                    "rollback_gateway_socket_stopped",
                )
                phase = PHASE_ROLLBACK_SOCKET_STOPPED
            if phase == PHASE_ROLLBACK_SOCKET_STOPPED:
                self._append(
                    PHASE_ROLLBACK_GATEWAY_STOP_INTENT,
                    "before_rollback_gateway_service_stop",
                )
                phase = PHASE_ROLLBACK_GATEWAY_STOP_INTENT
            if phase == PHASE_ROLLBACK_GATEWAY_STOP_INTENT:
                self.backend.stop_gateway_service(self.bundle)
                self.backend.verify_gateway_service_inactive(self.bundle)
                self._append(
                    PHASE_ROLLBACK_GATEWAY_STOPPED,
                    "rollback_gateway_service_stopped",
                )
                phase = PHASE_ROLLBACK_GATEWAY_STOPPED
            if (
                core_mutation_may_have_started
                and phase == PHASE_ROLLBACK_GATEWAY_STOPPED
            ):
                self._append(
                    PHASE_ROLLBACK_CORE_RESTORE_INTENT,
                    "before_rollback_core_file_restore",
                )
                phase = PHASE_ROLLBACK_CORE_RESTORE_INTENT
            if phase == PHASE_ROLLBACK_CORE_RESTORE_INTENT:
                self.backend.restore_core_files(self.bundle)
                self._append(
                    PHASE_ROLLBACK_CORE_FILES_RESTORED,
                    "rollback_core_files_restored",
                )
                phase = PHASE_ROLLBACK_CORE_FILES_RESTORED
            if phase == PHASE_ROLLBACK_CORE_FILES_RESTORED:
                self._append(
                    PHASE_ROLLBACK_DAEMON_RELOAD_INTENT,
                    "before_rollback_daemon_reload",
                )
                phase = PHASE_ROLLBACK_DAEMON_RELOAD_INTENT
            if phase == PHASE_ROLLBACK_DAEMON_RELOAD_INTENT:
                self.backend.daemon_reload(self.bundle)
                self._append(
                    PHASE_ROLLBACK_DAEMON_RELOADED,
                    "rollback_daemon_reloaded",
                )
                phase = PHASE_ROLLBACK_DAEMON_RELOADED
            if phase == PHASE_ROLLBACK_DAEMON_RELOADED:
                self._append(
                    PHASE_ROLLBACK_CORE_RESTART_INTENT,
                    "before_rollback_core_restart",
                )
                phase = PHASE_ROLLBACK_CORE_RESTART_INTENT
            if phase == PHASE_ROLLBACK_CORE_RESTART_INTENT:
                self.backend.restart_core(self.bundle)
                self._append(
                    PHASE_ROLLBACK_CORE_RESTARTED,
                    "rollback_core_restarted",
                )
                phase = PHASE_ROLLBACK_CORE_RESTARTED
            if phase == PHASE_ROLLBACK_CORE_RESTARTED:
                self.backend.verify_rollback_core(self.bundle, snapshot)
                self._append(
                    PHASE_ROLLBACK_CORE_RESTORED,
                    "rollback_core_verified",
                )
                phase = PHASE_ROLLBACK_CORE_RESTORED
            if phase in {
                PHASE_ROLLBACK_GATEWAY_STOPPED,
                PHASE_ROLLBACK_CORE_RESTORED,
            }:
                self._append(
                    PHASE_ROLLBACK_SOCKET_RESTORE_INTENT,
                    "before_rollback_gateway_socket_restore",
                )
                phase = PHASE_ROLLBACK_SOCKET_RESTORE_INTENT
            if phase == PHASE_ROLLBACK_SOCKET_RESTORE_INTENT:
                if snapshot.gateway_socket_active:
                    self.backend.start_gateway_socket(self.bundle)
                    self.backend.verify_gateway_socket_active(self.bundle)
                else:
                    self.backend.stop_gateway_socket(self.bundle)
                    self.backend.verify_gateway_socket_inactive(self.bundle)
                self._append(
                    PHASE_ROLLBACK_SOCKET_RESTORED,
                    "rollback_gateway_socket_state_restored",
                )
                phase = PHASE_ROLLBACK_SOCKET_RESTORED
            if phase == PHASE_ROLLBACK_SOCKET_RESTORED:
                self._append(
                    PHASE_ROLLBACK_GATEWAY_RESTORE_INTENT,
                    "before_rollback_gateway_service_restore",
                )
                phase = PHASE_ROLLBACK_GATEWAY_RESTORE_INTENT
            if phase == PHASE_ROLLBACK_GATEWAY_RESTORE_INTENT:
                if snapshot.gateway_service_active:
                    _require(
                        snapshot.gateway_socket_active,
                        "gateway_prestate_trigger_relationship_rejected",
                    )
                    self.backend.start_gateway_service(self.bundle)
                    self.backend.verify_gateway_service_active(self.bundle)
                else:
                    self.backend.stop_gateway_service(self.bundle)
                    self.backend.verify_gateway_service_inactive(self.bundle)
                self._append(
                    PHASE_ROLLBACK_GATEWAY_RESTORED,
                    "rollback_gateway_service_state_restored",
                )
                phase = PHASE_ROLLBACK_GATEWAY_RESTORED
            _require(
                phase == PHASE_ROLLBACK_GATEWAY_RESTORED,
                "rollback_incomplete",
            )
            self._append(
                PHASE_ROLLED_BACK,
                "automatic_rollback_completed",
                {"cause": cause},
            )
        except Exception as rollback_exc:
            try:
                self._append(
                    PHASE_ROLLBACK_FAILED,
                    "automatic_rollback_failed",
                    {
                        "cause": cause,
                        "failure_type": type(rollback_exc).__name__,
                    },
                )
            except Exception as journal_exc:
                raise R4CExecutionError(
                    "rollback_journal_failed_owner_action_required"
                ) from journal_exc
            raise R4CExecutionError("rollback_failed_owner_action_required") from rollback_exc
        return {
            "status": "rolled_back",
            "plan_digest": self.bundle.activation_plan_digest,
            "transaction_tree_sha256": self.bundle.tree_sha256,
            "cause": cause,
            "selected_or_activated": False,
        }

    def _recover_locked(
        self,
        records: list[dict[str, object]],
    ) -> dict[str, object]:
        _validate_journal_lifecycle(records)
        phase = _last_phase(records)
        _require(phase is not None, "recovery_without_journal")
        snapshot = _snapshot_from_records(records)
        if phase == PHASE_COMMITTED:
            return self._verify_committed(snapshot)
        if phase == PHASE_ROLLED_BACK:
            return {
                "status": "already_rolled_back",
                "plan_digest": self.bundle.activation_plan_digest,
                "selected_or_activated": False,
                "mutations_performed": False,
            }
        if phase == PHASE_ROLLBACK_FAILED:
            raise R4CExecutionError("prior_rollback_failed_owner_action_required")
        if phase in _ROLLBACK_PHASES:
            rollback_intents = [
                record
                for record in records
                if record["phase"] == PHASE_ROLLBACK_INTENT
            ]
            _require(
                len(rollback_intents) == 1,
                "rollback_intent_record_rejected",
            )
            rollback_data = rollback_intents[0]["data"]
            _require(
                isinstance(rollback_data.get("cause"), str)
                and type(
                    rollback_data.get("core_mutation_may_have_started")
                )
                is bool,
                "rollback_intent_data_rejected",
            )
            return self._continue_rollback(
                snapshot,
                cause=rollback_data["cause"],
                core_mutation_may_have_started=rollback_data[
                    "core_mutation_may_have_started"
                ],
                current_phase=phase,
            )
        if phase in {
            PHASE_CORE_VERIFIED,
            PHASE_SOCKET_START_INTENT,
            PHASE_SOCKET_STARTED,
            PHASE_SOCKET_VERIFIED,
            PHASE_GATEWAY_START_INTENT,
            PHASE_GATEWAY_STARTED,
            PHASE_GATEWAY_VERIFIED,
            PHASE_RECEIPT_WRITE_INTENT,
        }:
            try:
                self.backend.verify_target_core(self.bundle, snapshot)
            except Exception:
                return self._rollback(
                    snapshot,
                    cause=f"crash_recovery_target_invalid_at_{phase}",
                    core_mutation_may_have_started=True,
                )
            if phase in {PHASE_GATEWAY_VERIFIED, PHASE_RECEIPT_WRITE_INTENT}:
                try:
                    self.backend.verify_gateway_socket_active(self.bundle)
                    self.backend.verify_gateway_service_active(self.bundle)
                    return self._commit(snapshot, current_phase=phase)
                except JournalError as exc:
                    raise R4CExecutionError(
                        "post_health_journal_failed_owner_action_required"
                    ) from exc
                except Exception:
                    return self._rollback(
                        snapshot,
                        cause=f"crash_recovery_gateway_invalid_at_{phase}",
                        core_mutation_may_have_started=True,
                    )
            try:
                return self._resume_gateway_and_commit(
                    snapshot,
                    current_phase=phase,
                )
            except JournalError as exc:
                raise R4CExecutionError(
                    "post_health_journal_failed_owner_action_required"
                ) from exc
            except Exception:
                return self._rollback(
                    snapshot,
                    cause=f"crash_recovery_gateway_failed_at_{phase}",
                    core_mutation_may_have_started=True,
                )
        return self._rollback(
            snapshot,
            cause=f"crash_recovery_from_{phase}",
            core_mutation_may_have_started=_core_mutation_may_have_started(phase),
        )

    def execute(self) -> dict[str, object]:
        with self.journal.acquire():
            records = self.journal.read_records()
            if records:
                _validate_journal_lifecycle(records)
                phase = _last_phase(records)
                if phase in _TERMINAL_PHASES:
                    return self._recover_locked(records)
                return self._recover_locked(records)
            snapshot = self.backend.verify_exact_prestate(self.bundle)
            _require(
                snapshot.core_active
                and snapshot.gateway_socket_active
                and snapshot.gateway_service_active,
                "required_prestate_not_active",
            )
            self._append(
                PHASE_PREPARED,
                "exact_prestate_verified",
                {"snapshot": snapshot.to_payload()},
            )
            try:
                return self._forward_from_prepared(snapshot)
            except Exception as exc:
                records = self.journal.read_records()
                _validate_journal_lifecycle(records)
                phase = _last_phase(records)
                _require(phase is not None, "failure_without_journal")
                if (
                    phase in _FORWARD_INDEX
                    and _FORWARD_INDEX[phase]
                    >= _FORWARD_INDEX[PHASE_CORE_VERIFIED]
                ):
                    try:
                        return self._recover_locked(records)
                    except JournalError as journal_exc:
                        raise R4CExecutionError(
                            "post_health_journal_failed_owner_action_required"
                        ) from journal_exc
                result = self._rollback(
                    snapshot,
                    cause=f"{type(exc).__name__}:{phase}",
                    core_mutation_may_have_started=_core_mutation_may_have_started(
                        phase
                    ),
                )
                raise R4CExecutionError(
                    f"activation_failed_{result['status']}"
                ) from exc

    def recover(self) -> dict[str, object]:
        with self.journal.acquire():
            records = self.journal.read_records()
            _require(bool(records), "recovery_without_journal")
            _validate_journal_lifecycle(records)
            return self._recover_locked(records)
