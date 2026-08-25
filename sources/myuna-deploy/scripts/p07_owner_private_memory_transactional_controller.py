#!/usr/bin/env python3
"""Source-only P07 owner-memory full-mutation transaction controller.

The module defines the future one-attempt controller contract without creating
its state, ledger, backup, staging, plan, or attempt namespace.  All filesystem
functions are parameterized and are exercised only with synthetic temporary
roots during T1 verification.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Callable, Mapping, Protocol, Sequence

import activate_p07_owner_private_memory_dual_state_recovery_v2 as dual_state
import activate_p07_owner_private_memory_v1 as memory
import p07_full_mutation_set_v1 as mutation
from myuna_core.episodic_memory.contracts import (
    OWNER_DAY_DIARY_STYLE_V2_DIGEST,
    OWNER_DAY_PREVIEW_EGRESS_V1_DIGEST,
    REFLECTIVE_DIARY_EGRESS_V1_DIGEST,
)
from myuna_core.episodic_memory.owner_day import (
    OWNER_DAY_DIARY_MODEL,
    OWNER_DAY_DIARY_MODEL_ROLE,
)


SOURCE_ID = "p07-owner-private-memory-transactional-mutation-controller"
SOURCE_SCHEMA = "myuna.p07-owner-private-memory-transactional-controller.v1"
PLAN_SCHEMA = "myuna.p07-owner-private-memory-transactional-plan.v1"
BACKUP_SCHEMA = "myuna.p07-owner-private-memory-transactional-backup.v1"
JOURNAL_SCHEMA = "myuna.p07-owner-private-memory-transactional-journal.v1"
NAMESPACE_SCHEMA = "myuna.p07-owner-private-memory-future-namespace.v1"
LINEAGE_SCHEMA = "myuna.p07-owner-private-memory-readonly-lineages.v1"
MAXIMUM_ACTIVATIONS = 1

LINEAGE_CORE_SOURCE_COMMIT = "279e545e612077a597257750ce858789d6c6b794"
LINEAGE_CORE_SOURCE_TREE = "8587222f1615288f15f44878609647144ce2472f"
CORE_SOURCE_COMMIT = "065ef4b647f63925ae20bb564007c127433c0b81"
CORE_SOURCE_TREE = "e1846c2b7f5aa7feed9c8e509c857306a0163993"
DEPLOY_PARENT_COMMIT = "274f73b6fe116fdd0cfa100d5a195777fc1e95c7"
DEPLOY_PARENT_TREE = "d0c7ed69f07509f1df65a24b45b51f5caf84e00c"
FULL_MUTATION_HANDOFF_SHA256 = (
    "7f0451a15a26731363828588cb622ec52d819ddc90c355e61197ecf4cfa86a09"
)
FULL_MUTATION_BUNDLE_ID = (
    "9dd8100ab627c08ddff091668d8e44d57970f09cd5ae852affb81cc353590e8d"
)
FULL_MUTATION_MANIFEST_SHA256 = (
    "203cb8377f717d0d8e4971b6f4f85d74cba7e371d84c54cbfbefc7592fb48774"
)
TERMINAL_V2_HANDOFF_SHA256 = (
    "11fce5addec0696b16dd1e27632fa0540193a454db61d1b2c998d83baf56cd3a"
)
ROOT_CAUSE_HANDOFF_SHA256 = (
    "38cfce40bd28638e345a7393914eccfc13e29acb4c3d02142c284fc32e526095"
)

PREDECESSOR_STRATEGY_ID = "p07-policy-overlay-v1"
PREDECESSOR_ATTEMPTS = 2
PREDECESSOR_MAXIMUM_ATTEMPTS = 2
V2_STRATEGY_ID = "p07-owner-private-memory-dual-state-recovery-v2"
V2_ATTEMPTS = 1
V2_MAXIMUM_ATTEMPTS = 1
V2_SOURCE_COMMIT = "9fbae1371af95028a34c175cc64cc9732e7e26d4"
V2_PLAN_SHA256 = "58cf41fded38cbe17b925778996aec3e625ec459824093981bfecce6c9c2973a"
V2_PRESTATE_SHA256 = (
    "dee2b8322bb43b3dc8179e4c3f9d611bf6ed49ab5f8dd30f97743e2422bf5d04"
)
V2_BACKUP_TREE_DIGEST = (
    "88d85d504e30fdace0cba106f8b044af6226ed437c60be5b1d726f798355e85e"
)
V2_LEDGER_SHA256 = "c935751d8b952070805ae5a80c8ab3e857d0c80643c5c6bf36420270051596d0"
V2_RECEIPT_SHA256 = (
    "4e58d1d51a59b228dd03f760e1d3411a376e70ba4674d013417532a164b33092"
)
V2_JOURNAL_SHA256 = V2_RECEIPT_SHA256
V2_STATE_TREE_DIGEST = (
    "1adee444aa7e46a14b35ec97149e7cbf3c8d571be3054d511052d187ef30fe18"
)
V2_STATE_ROOT = Path(
    "/var/lib/myuna-telegram-gateway/"
    "p07-owner-private-memory-dual-state-recovery-v2"
)
V2_BACKUP_ROOT = Path(
    "/var/backups/myuna/p07-owner-private-memory-dual-state-recovery-v2"
)

FUTURE_STATE_ROOT = Path(
    "/var/lib/myuna-telegram-gateway/"
    "p07-owner-private-memory-transactional-mutation-controller"
)
FUTURE_BACKUP_ROOT = Path(
    "/var/backups/myuna/"
    "p07-owner-private-memory-transactional-mutation-controller"
)

_SHA = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_TYPED = re.compile(r"^[a-z][a-z0-9_]{2,127}$")
_SOURCE_STATES = {
    "pre_attempt",
    "backup_verified",
    "staging_verified",
    "attempt_consumed",
    "services_stopped",
    "files_applying",
    "target_accepted",
    "rollback_started",
    "files_restored",
    "services_restored",
    "rolled_back",
    "rollback_failed",
}
_TRANSITIONS = {
    "pre_attempt": {"backup_verified"},
    "backup_verified": {"staging_verified"},
    "staging_verified": {"attempt_consumed"},
    "attempt_consumed": {"services_stopped", "rollback_started"},
    "services_stopped": {"files_applying", "rollback_started"},
    "files_applying": {"target_accepted", "rollback_started"},
    "target_accepted": set(),
    "rollback_started": {"files_restored", "rollback_failed"},
    "files_restored": {"services_restored", "rollback_failed"},
    "services_restored": {"rolled_back", "rollback_failed"},
    "rolled_back": set(),
    "rollback_failed": set(),
}
_REQUIRED_MUTATION_CATEGORIES = frozenset(
    {
        "archive_roots",
        "core_release",
        "diary_roots",
        "dropins",
        "index_roots",
        "plugin_release",
        "runtime_release",
        "selectors",
    }
)
_BOUNDARY_PROGRAMS = frozenset({"p01", "p08", "p09", "p10", "p15", "p16"})
_PUBLIC_PRESTATE_FIELDS = frozenset(
    {
        "archive_roots",
        "calendar_zone",
        "container",
        "credential",
        "dropins",
        "effective_v6",
        "epoch",
        "p08_status",
        "releases",
        "selectors",
        "services",
    }
)
_POLICY_FIELDS = frozenset(
    {
        "calendar_zone_selector_digest",
        "diary_mode",
        "diary_provider_capable",
        "diary_timer_capable",
        "diary_worker_capable",
        "historical_recall_egress_digest",
        "owner_day_closed_egress_purpose",
        "owner_day_closed_egress_policy_digest",
        "owner_day_diary_model",
        "owner_day_diary_model_role",
        "owner_day_diary_style_digest",
        "owner_day_open_preview_egress_purpose",
        "owner_day_open_preview_egress_policy_digest",
        "owner_day_policy_digest",
        "p15_prompt_owner_digest",
        "profile_confirmation_gate_digest",
        "selected_calendar_zone",
    }
)
_LEGACY_POLICY_FIELDS = frozenset(
    {
        "calendar_zone_selector_digest",
        "diary_egress_policy_digest",
        "historical_recall_egress_digest",
        "p15_prompt_owner_digest",
        "profile_confirmation_gate_digest",
        "selected_calendar_zone",
    }
)
_POLICY_DIGEST_FIELDS = frozenset(
    {
        "calendar_zone_selector_digest",
        "historical_recall_egress_digest",
        "owner_day_closed_egress_policy_digest",
        "owner_day_diary_style_digest",
        "owner_day_open_preview_egress_policy_digest",
        "owner_day_policy_digest",
        "p15_prompt_owner_digest",
        "profile_confirmation_gate_digest",
    }
)
POLICY_DIARY_MODE = "disabled-memory-only"
POLICY_OWNER_DAY_CLOSED_EGRESS_PURPOSE = "p07-owner-day-diary-egress-v2"
POLICY_OWNER_DAY_OPEN_PREVIEW_EGRESS_PURPOSE = (
    "p07-owner-day-as-of-preview-egress-v1"
)


class TransactionalControllerRejected(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        activation_failure_code: str | None = None,
        rollback_failure_code: str | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.activation_failure_code = activation_failure_code
        self.rollback_failure_code = rollback_failure_code


def require(condition: bool, code: str) -> None:
    if not condition:
        raise TransactionalControllerRejected(code)


def canonical(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"


def digest(domain: str, payload: object) -> str:
    require(_TYPED.fullmatch(domain) is not None, "transaction_domain_rejected")
    return sha256(domain.encode("ascii") + b"\0" + canonical(payload).rstrip()).hexdigest()


def digest_file(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _typed_error(exc: BaseException, fallback: str) -> str:
    candidate = (
        getattr(exc, "activation_failure_code", None)
        or getattr(exc, "cause_code", None)
        or getattr(exc, "code", None)
    )
    return candidate if isinstance(candidate, str) and _TYPED.fullmatch(candidate) else fallback


def _require_sha(value: object, code: str) -> str:
    require(isinstance(value, str) and _SHA.fullmatch(value) is not None, code)
    return value


def _require_commit(value: object, code: str) -> str:
    require(isinstance(value, str) and _COMMIT.fullmatch(value) is not None, code)
    return value


def _verify_file(path: Path, expected: str, code: str) -> None:
    try:
        metadata = path.lstat()
        observed = digest_file(path)
    except OSError as exc:
        raise TransactionalControllerRejected(code) from exc
    require(
        not stat.S_ISLNK(metadata.st_mode)
        and stat.S_ISREG(metadata.st_mode)
        and observed == expected,
        code,
    )


def _canonical_read(path: Path, code: str) -> dict[str, object]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise TransactionalControllerRejected(code) from exc
    require(isinstance(value, dict) and canonical(value) == raw, code)
    return value


def verify_v2_immutable_evidence(
    *,
    terminal_handoff: Path,
    state_root: Path = V2_STATE_ROOT,
    backup_root: Path = V2_BACKUP_ROOT,
) -> dict[str, object]:
    """Verify the exhausted v2 lineage without interpreting private content."""

    _verify_file(terminal_handoff, TERMINAL_V2_HANDOFF_SHA256, "v2_terminal_handoff_drifted")
    require(
        state_root == V2_STATE_ROOT and backup_root == V2_BACKUP_ROOT,
        "v2_evidence_root_rejected",
    )
    state_digest = dual_state._protected_tree_digest(
        state_root, code="v2_state_evidence_unavailable"
    )
    backup_digest = dual_state._protected_tree_digest(
        backup_root, code="v2_backup_evidence_unavailable"
    )
    require(
        state_digest == V2_STATE_TREE_DIGEST
        and backup_digest == V2_BACKUP_TREE_DIGEST,
        "v2_evidence_tree_drifted",
    )
    entries = sorted(path.name for path in state_root.iterdir())
    journals = [name for name in entries if name.startswith("JOURNAL-") and name.endswith(".json")]
    receipts = [name for name in entries if name.startswith("RECEIPT-") and name.endswith(".json")]
    require(
        entries == sorted(["ATTEMPT_LEDGER.json", *journals, *receipts])
        and len(journals) == 1
        and len(receipts) == 1,
        "v2_evidence_inventory_drifted",
    )
    ledger_path = state_root / "ATTEMPT_LEDGER.json"
    _verify_file(ledger_path, V2_LEDGER_SHA256, "v2_ledger_drifted")
    _verify_file(state_root / journals[0], V2_JOURNAL_SHA256, "v2_journal_drifted")
    _verify_file(state_root / receipts[0], V2_RECEIPT_SHA256, "v2_receipt_drifted")
    ledger = _canonical_read(ledger_path, "v2_ledger_rejected")
    require(
        ledger
        == {
            "attempts": V2_ATTEMPTS,
            "last_plan_sha256": V2_PLAN_SHA256,
            "schema": memory.DUAL_STATE_RECOVERY_V2_STRATEGY.attempt_schema,
        },
        "v2_ledger_rejected",
    )
    backup_names = sorted(path.name for path in backup_root.iterdir())
    require(backup_names == [V2_PLAN_SHA256], "v2_backup_inventory_drifted")
    return {
        "attempts": V2_ATTEMPTS,
        "backup_tree_digest": backup_digest,
        "journal_sha256": V2_JOURNAL_SHA256,
        "ledger_sha256": V2_LEDGER_SHA256,
        "maximum_attempts": V2_MAXIMUM_ATTEMPTS,
        "plan_sha256": V2_PLAN_SHA256,
        "prestate_sha256": V2_PRESTATE_SHA256,
        "receipt_sha256": V2_RECEIPT_SHA256,
        "schema": LINEAGE_SCHEMA,
        "source_commit": V2_SOURCE_COMMIT,
        "state_tree_digest": state_digest,
        "strategy_id": V2_STRATEGY_ID,
        "terminal_handoff_sha256": TERMINAL_V2_HANDOFF_SHA256,
    }


def verify_immutable_lineages(
    *,
    full_mutation_handoff: Path,
    root_cause_handoff: Path,
    terminal_handoff: Path,
    predecessor_arguments: Mapping[str, Path],
    v2_state_root: Path = V2_STATE_ROOT,
    v2_backup_root: Path = V2_BACKUP_ROOT,
) -> dict[str, object]:
    """Import both exhausted lineages and the accepted source evidence."""

    _verify_file(
        full_mutation_handoff,
        FULL_MUTATION_HANDOFF_SHA256,
        "full_mutation_handoff_drifted",
    )
    _verify_file(
        root_cause_handoff,
        ROOT_CAUSE_HANDOFF_SHA256,
        "root_cause_handoff_drifted",
    )
    expected_predecessor_keys = {
        "hard_stop_handoff",
        "diagnosis_handoff",
        "dual_state_t1_handoff",
        "formal_preflight_one",
        "formal_preflight_two",
        "state_root",
        "backup_root",
        "archive_root",
    }
    require(set(predecessor_arguments) == expected_predecessor_keys, "predecessor_evidence_arguments_rejected")
    predecessor = dual_state.verify_immutable_predecessor(**predecessor_arguments)
    require(
        predecessor.get("strategy_id") == PREDECESSOR_STRATEGY_ID
        and predecessor.get("attempts") == PREDECESSOR_ATTEMPTS
        and predecessor.get("maximum_attempts") == PREDECESSOR_MAXIMUM_ATTEMPTS,
        "predecessor_lineage_rejected",
    )
    v2 = verify_v2_immutable_evidence(
        terminal_handoff=terminal_handoff,
        state_root=v2_state_root,
        backup_root=v2_backup_root,
    )
    semantic = {
        "full_mutation_bundle_id": FULL_MUTATION_BUNDLE_ID,
        "full_mutation_handoff_sha256": FULL_MUTATION_HANDOFF_SHA256,
        "full_mutation_manifest_sha256": FULL_MUTATION_MANIFEST_SHA256,
        "predecessor": predecessor,
        "root_cause_handoff_sha256": ROOT_CAUSE_HANDOFF_SHA256,
        "schema": LINEAGE_SCHEMA,
        "source_boundary": {
            "core_commit": LINEAGE_CORE_SOURCE_COMMIT,
            "core_tree": LINEAGE_CORE_SOURCE_TREE,
            "deploy_parent_commit": DEPLOY_PARENT_COMMIT,
            "deploy_parent_tree": DEPLOY_PARENT_TREE,
        },
        "v2": v2,
    }
    return {**semantic, "evidence_digest": digest("p07_transactional_lineage_evidence", semantic)}


def validate_immutable_lineages(payload: Mapping[str, object]) -> dict[str, object]:
    lineages = dict(payload)
    required = {
        "evidence_digest",
        "full_mutation_bundle_id",
        "full_mutation_handoff_sha256",
        "full_mutation_manifest_sha256",
        "predecessor",
        "root_cause_handoff_sha256",
        "schema",
        "source_boundary",
        "v2",
    }
    require(
        set(lineages) == required
        and lineages.get("schema") == LINEAGE_SCHEMA
        and lineages.get("full_mutation_bundle_id") == FULL_MUTATION_BUNDLE_ID
        and lineages.get("full_mutation_handoff_sha256")
        == FULL_MUTATION_HANDOFF_SHA256
        and lineages.get("full_mutation_manifest_sha256")
        == FULL_MUTATION_MANIFEST_SHA256
        and lineages.get("root_cause_handoff_sha256")
        == ROOT_CAUSE_HANDOFF_SHA256,
        "transaction_lineage_evidence_rejected",
    )
    source_boundary = lineages.get("source_boundary")
    require(
        source_boundary
        == {
            "core_commit": LINEAGE_CORE_SOURCE_COMMIT,
            "core_tree": LINEAGE_CORE_SOURCE_TREE,
            "deploy_parent_commit": DEPLOY_PARENT_COMMIT,
            "deploy_parent_tree": DEPLOY_PARENT_TREE,
        },
        "transaction_lineage_source_boundary_rejected",
    )
    predecessor = lineages.get("predecessor")
    v2 = lineages.get("v2")
    require(
        isinstance(predecessor, Mapping)
        and predecessor.get("schema")
        == dual_state.IMMUTABLE_PREDECESSOR_SCHEMA
        and predecessor.get("strategy_id") == PREDECESSOR_STRATEGY_ID
        and predecessor.get("attempts") == PREDECESSOR_ATTEMPTS
        and predecessor.get("maximum_attempts") == PREDECESSOR_MAXIMUM_ATTEMPTS,
        "transaction_predecessor_lineage_rejected",
    )
    require(
        isinstance(v2, Mapping)
        and set(v2)
        == {
            "attempts",
            "backup_tree_digest",
            "journal_sha256",
            "ledger_sha256",
            "maximum_attempts",
            "plan_sha256",
            "prestate_sha256",
            "receipt_sha256",
            "schema",
            "source_commit",
            "state_tree_digest",
            "strategy_id",
            "terminal_handoff_sha256",
        }
        and v2.get("schema") == LINEAGE_SCHEMA
        and v2.get("strategy_id") == V2_STRATEGY_ID
        and v2.get("attempts") == V2_ATTEMPTS
        and v2.get("maximum_attempts") == V2_MAXIMUM_ATTEMPTS
        and v2.get("source_commit") == V2_SOURCE_COMMIT
        and v2.get("plan_sha256") == V2_PLAN_SHA256
        and v2.get("prestate_sha256") == V2_PRESTATE_SHA256
        and v2.get("backup_tree_digest") == V2_BACKUP_TREE_DIGEST
        and v2.get("ledger_sha256") == V2_LEDGER_SHA256
        and v2.get("receipt_sha256") == V2_RECEIPT_SHA256
        and v2.get("journal_sha256") == V2_JOURNAL_SHA256
        and v2.get("state_tree_digest") == V2_STATE_TREE_DIGEST
        and v2.get("terminal_handoff_sha256") == TERMINAL_V2_HANDOFF_SHA256,
        "transaction_v2_lineage_rejected",
    )
    semantic = {key: lineages[key] for key in required - {"evidence_digest"}}
    require(
        lineages.get("evidence_digest")
        == digest("p07_transactional_lineage_evidence", semantic),
        "transaction_lineage_evidence_digest_drifted",
    )
    return lineages


def namespace_observation(*, state_root: Path, backup_root: Path) -> dict[str, object]:
    require(state_root.is_absolute() and backup_root.is_absolute(), "future_namespace_path_rejected")
    return {
        "backup_root_exists": backup_root.exists() or backup_root.is_symlink(),
        "ledger_exists": (state_root / "ATTEMPT_LEDGER.json").exists()
        or (state_root / "ATTEMPT_LEDGER.json").is_symlink(),
        "schema": NAMESPACE_SCHEMA,
        "source_id": SOURCE_ID,
        "state_root_exists": state_root.exists() or state_root.is_symlink(),
    }


def verify_future_namespace_absent(observation: Mapping[str, object]) -> dict[str, object]:
    normalized = dict(observation)
    require(
        normalized
        == {
            "backup_root_exists": False,
            "ledger_exists": False,
            "schema": NAMESPACE_SCHEMA,
            "source_id": SOURCE_ID,
            "state_root_exists": False,
        },
        "future_namespace_preexisting",
    )
    return normalized


def _validate_boundaries(boundaries: Mapping[str, object]) -> dict[str, object]:
    normalized = dict(boundaries)
    require(set(normalized) == _BOUNDARY_PROGRAMS, "transaction_program_boundaries_rejected")
    for program, item in normalized.items():
        require(
            isinstance(item, Mapping)
            and set(item) == {"identity_digest", "mutation_allowed", "state"}
            and item.get("mutation_allowed") is False
            and isinstance(item.get("state"), str)
            and bool(item.get("state")),
            f"transaction_{program}_boundary_rejected",
        )
        _require_sha(item.get("identity_digest"), f"transaction_{program}_boundary_rejected")
    return normalized


def _validate_policy(policy: Mapping[str, object]) -> dict[str, object]:
    normalized = dict(policy)
    if set(normalized) == _LEGACY_POLICY_FIELDS:
        require(
            normalized["selected_calendar_zone"] == "Asia/Shanghai",
            "transaction_calendar_zone_rejected",
        )
        for field in _LEGACY_POLICY_FIELDS - {"selected_calendar_zone"}:
            _require_sha(normalized[field], "transaction_policy_identity_rejected")
        return normalized
    require(set(normalized) == _POLICY_FIELDS, "transaction_policy_identity_rejected")
    require(
        normalized["selected_calendar_zone"] == "Asia/Shanghai",
        "transaction_calendar_zone_rejected",
    )
    require(
        normalized["diary_mode"] == POLICY_DIARY_MODE
        and normalized["diary_provider_capable"] is False
        and normalized["diary_timer_capable"] is False
        and normalized["diary_worker_capable"] is False
        and normalized["owner_day_closed_egress_purpose"]
        == POLICY_OWNER_DAY_CLOSED_EGRESS_PURPOSE
        and normalized["owner_day_open_preview_egress_purpose"]
        == POLICY_OWNER_DAY_OPEN_PREVIEW_EGRESS_PURPOSE,
        "transaction_policy_identity_rejected",
    )
    require(
        normalized["owner_day_closed_egress_policy_digest"]
        == REFLECTIVE_DIARY_EGRESS_V1_DIGEST
        and normalized["owner_day_open_preview_egress_policy_digest"]
        == OWNER_DAY_PREVIEW_EGRESS_V1_DIGEST
        and normalized["owner_day_diary_style_digest"]
        == OWNER_DAY_DIARY_STYLE_V2_DIGEST
        and normalized["owner_day_diary_model"] == OWNER_DAY_DIARY_MODEL
        and normalized["owner_day_diary_model_role"] == OWNER_DAY_DIARY_MODEL_ROLE,
        "transaction_policy_identity_rejected",
    )
    for field in _POLICY_DIGEST_FIELDS:
        _require_sha(normalized[field], "transaction_policy_identity_rejected")
    return normalized


def _validate_public_prestate(prestate: Mapping[str, object]) -> dict[str, object]:
    normalized = dict(prestate)
    require(set(normalized) == _PUBLIC_PRESTATE_FIELDS, "transaction_public_prestate_rejected")
    for field, value in normalized.items():
        require(isinstance(value, Mapping) and bool(value), f"transaction_{field}_prestate_rejected")
    return normalized


def _validate_root_transitions(transitions: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    identities: set[str] = set()
    for item in transitions:
        value = dict(item)
        require(
            set(value)
            == {
                "after_exists",
                "after_gid",
                "after_mode",
                "after_type",
                "after_uid",
                "before_exists",
                "before_gid",
                "before_mode",
                "before_type",
                "before_uid",
                "kind",
                "path",
                "path_digest",
                "root_role",
            }
            and type(value["after_exists"]) is bool
            and type(value["before_exists"]) is bool
            and value["kind"] in {"add", "replace", "remove"}
            and _TYPED.fullmatch(str(value["root_role"])) is not None,
            "transaction_root_transition_rejected",
        )
        path = Path(str(value["path"]))
        require(
            path.is_absolute()
            and path.as_posix() == value["path"]
            and ".." not in PurePosixPath(path.as_posix()).parts
            and value["path_digest"]
            == digest("p07_protected_root_path", path.as_posix()),
            "transaction_root_transition_rejected",
        )
        for prefix in ("before", "after"):
            expected_type = "directory" if value[f"{prefix}_exists"] else "absent"
            require(value[f"{prefix}_type"] == expected_type, "transaction_root_transition_rejected")
            for field in ("uid", "gid", "mode"):
                selected = value[f"{prefix}_{field}"]
                require(type(selected) is int and selected >= 0, "transaction_root_transition_rejected")
        require(
            (value["kind"] == "add" and not value["before_exists"] and value["after_exists"])
            or (
                value["kind"] == "replace"
                and value["before_exists"]
                and value["after_exists"]
                and any(
                    value[f"before_{field}"] != value[f"after_{field}"]
                    for field in ("uid", "gid", "mode")
                )
            )
            or (value["kind"] == "remove" and value["before_exists"] and not value["after_exists"]),
            "transaction_root_transition_rejected",
        )
        identity = f"{value['root_role']}:{value['path_digest']}"
        require(identity not in identities, "transaction_root_transition_duplicate")
        identities.add(identity)
        result.append(value)
    result.sort(key=lambda value: (str(value["root_role"]), str(value["path_digest"])))
    require(bool(result), "transaction_root_transition_rejected")
    selected_paths = [PurePosixPath(str(value["path"])) for value in result]
    for index, left in enumerate(selected_paths):
        for right in selected_paths[index + 1 :]:
            require(
                left != right
                and left not in right.parents
                and right not in left.parents,
                "transaction_root_transition_overlap_rejected",
            )
    return result


def _inspect_protected_root(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {"exists": False, "gid": 0, "mode": 0, "type": "absent", "uid": 0}
    except OSError as exc:
        raise TransactionalControllerRejected("transaction_root_observation_failed") from exc
    require(
        not stat.S_ISLNK(metadata.st_mode) and stat.S_ISDIR(metadata.st_mode),
        "transaction_root_type_rejected",
    )
    return {
        "exists": True,
        "gid": metadata.st_gid,
        "mode": stat.S_IMODE(metadata.st_mode),
        "type": "directory",
        "uid": metadata.st_uid,
    }


def _root_side(item: Mapping[str, object], side: str) -> dict[str, object]:
    return {
        "exists": item[f"{side}_exists"],
        "gid": item[f"{side}_gid"],
        "mode": item[f"{side}_mode"],
        "type": item[f"{side}_type"],
        "uid": item[f"{side}_uid"],
    }


def verify_root_transitions(
    transitions: Sequence[Mapping[str, object]], *, side: str
) -> list[dict[str, object]]:
    require(side in {"before", "after"}, "transaction_root_side_rejected")
    normalized = _validate_root_transitions(transitions)
    events: list[dict[str, object]] = []
    for item in normalized:
        expected = _root_side(item, side)
        observed = _inspect_protected_root(Path(str(item["path"])))
        require(observed == expected, f"transaction_root_{side}_drifted")
        events.append(
            {
                "content_retained": False,
                "expected_state_digest": digest("p07_protected_root_state", expected),
                "observed_state_digest": digest("p07_protected_root_state", observed),
                "path_digest": item["path_digest"],
                "root_role": item["root_role"],
                "side": side,
            }
        )
    return events


def _apply_root_side(item: Mapping[str, object], *, side: str) -> None:
    path = Path(str(item["path"]))
    current = _inspect_protected_root(path)
    expected_current = _root_side(item, "before" if side == "after" else "after")
    target = _root_side(item, side)
    if current == target:
        return
    require(current == expected_current, "transaction_root_third_state_drifted")
    if target["exists"]:
        if current["exists"]:
            os.chown(path, int(target["uid"]), int(target["gid"]))
            os.chmod(path, int(target["mode"]))
        else:
            parent = path.parent.lstat()
            require(
                not stat.S_ISLNK(parent.st_mode) and stat.S_ISDIR(parent.st_mode),
                "transaction_root_parent_rejected",
            )
            path.mkdir(mode=int(target["mode"]))
            os.chown(path, int(target["uid"]), int(target["gid"]))
            os.chmod(path, int(target["mode"]))
    else:
        try:
            path.rmdir()
        except OSError as exc:
            raise TransactionalControllerRejected("transaction_root_remove_rejected") from exc
    require(_inspect_protected_root(path) == target, "transaction_root_readback_mismatch")


def apply_root_transitions(
    transitions: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    normalized = _validate_root_transitions(transitions)
    verify_root_transitions(normalized, side="before")
    completed: list[dict[str, object]] = []
    try:
        for item in normalized:
            _apply_root_side(item, side="after")
            completed.append(item)
        return verify_root_transitions(normalized, side="after")
    except Exception as exc:
        for item in reversed(completed):
            _apply_root_side(item, side="before")
        verify_root_transitions(normalized, side="before")
        raise TransactionalControllerRejected(
            "transaction_root_apply_failed_rolled_back",
            activation_failure_code=_typed_error(exc, "transaction_root_apply_failed"),
        ) from exc


def rollback_root_transitions(
    transitions: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    normalized = _validate_root_transitions(transitions)
    for item in reversed(normalized):
        _apply_root_side(item, side="before")
    return verify_root_transitions(normalized, side="before")


def _validate_coverage(
    coverage: Mapping[str, object],
    contract: Mapping[str, object],
    root_transitions: Sequence[Mapping[str, object]],
) -> dict[str, list[str]]:
    normalized_contract = mutation.validate_mutation_set(contract)
    normalized_transitions = _validate_root_transitions(root_transitions)
    normalized: dict[str, list[str]] = {}
    require(set(coverage) == _REQUIRED_MUTATION_CATEGORIES, "transaction_mutation_coverage_rejected")
    all_keys: list[str] = []
    for category in sorted(coverage):
        values = coverage[category]
        require(
            isinstance(values, list)
            and bool(values)
            and all(isinstance(value, str) for value in values),
            "transaction_mutation_coverage_rejected",
        )
        ordered = sorted(values)
        require(ordered == values and len(set(values)) == len(values), "transaction_mutation_coverage_rejected")
        normalized[category] = list(values)
        all_keys.extend(values)
    operation_keys = sorted(
        "file:"
        + mutation.path_key(str(item["root_id"]), str(item["logical_path"]))
        for item in normalized_contract["operations"]
    )
    transition_keys = sorted(
        f"root:{item['root_role']}:{item['path_digest']}"
        for item in normalized_transitions
    )
    require(
        sorted(all_keys) == sorted(operation_keys + transition_keys)
        and len(all_keys) == len(set(all_keys)),
        "transaction_mutation_coverage_rejected",
    )
    return normalized


def build_plan(
    *,
    core_commit: str,
    deploy_commit: str,
    deploy_tree: str,
    artifact_identities: Mapping[str, str],
    lineages: Mapping[str, object],
    public_prestate: Mapping[str, object],
    boundaries: Mapping[str, object],
    policy: Mapping[str, object],
    mutation_set: Mapping[str, object],
    mutation_coverage: Mapping[str, object],
    root_transitions: Sequence[Mapping[str, object]],
    namespace: Mapping[str, object],
    state_root: Path,
    backup_root: Path,
) -> dict[str, object]:
    """Build a pure future plan.  No path is created or mutated."""

    _require_commit(core_commit, "transaction_core_commit_rejected")
    _require_commit(deploy_commit, "transaction_deploy_commit_rejected")
    _require_commit(deploy_tree, "transaction_deploy_tree_rejected")
    require(core_commit == CORE_SOURCE_COMMIT, "transaction_core_commit_rejected")
    require(state_root.is_absolute() and backup_root.is_absolute(), "transaction_storage_root_rejected")
    require(PurePosixPath(state_root.as_posix()) != PurePosixPath(backup_root.as_posix()), "transaction_storage_root_rejected")
    verify_future_namespace_absent(namespace)
    normalized_contract = mutation.validate_mutation_set(mutation_set)
    normalized_artifacts = dict(artifact_identities)
    require(
        set(normalized_artifacts)
        == {
            "controller_bundle_id",
            "full_mutation_bundle_id",
            "full_mutation_manifest_sha256",
        },
        "transaction_artifact_identity_rejected",
    )
    for value in normalized_artifacts.values():
        _require_sha(value, "transaction_artifact_identity_rejected")
    require(
        normalized_artifacts["full_mutation_bundle_id"] == FULL_MUTATION_BUNDLE_ID
        and normalized_artifacts["full_mutation_manifest_sha256"]
        == FULL_MUTATION_MANIFEST_SHA256,
        "transaction_full_mutation_artifact_drifted",
    )
    normalized_lineages = validate_immutable_lineages(lineages)
    semantic = {
        "artifacts": normalized_artifacts,
        "attempts": {"consumed": 0, "maximum": MAXIMUM_ACTIVATIONS, "next": 1},
        "boundaries": _validate_boundaries(boundaries),
        "capabilities": {
            "channel_called": False,
            "credential_value_read": False,
            "health_called": False,
            "model_called": False,
            "old_history_migrated": False,
            "private_content_read": False,
            "provider_called": False,
        },
        "lineage_evidence_digest": normalized_lineages["evidence_digest"],
        "mutation_coverage": _validate_coverage(
            mutation_coverage,
            normalized_contract,
            root_transitions,
        ),
        "mutation_set_id": normalized_contract["mutation_set_id"],
        "policy": _validate_policy(policy),
        "public_prestate": _validate_public_prestate(public_prestate),
        "public_prestate_digest": digest("p07_transaction_public_prestate", public_prestate),
        "root_transitions": _validate_root_transitions(root_transitions),
        "schema": PLAN_SCHEMA,
        "source": {
            "controller_source_id": SOURCE_ID,
            "core_commit": core_commit,
            "deploy_commit": deploy_commit,
            "deploy_tree": deploy_tree,
            "full_mutation_source_id": mutation.SOURCE_ID,
        },
        "storage": {
            "backup_root": backup_root.as_posix(),
            "state_root": state_root.as_posix(),
        },
    }
    plan_id = digest("p07_transactional_mutation_plan", semantic)
    storage = {
        **semantic["storage"],
        "backup_path": (backup_root / plan_id).as_posix(),
        "filesystem_journal_path": (state_root / f"FILES-{plan_id}.json").as_posix(),
        "journal_path": (state_root / f"JOURNAL-{plan_id}.json").as_posix(),
        "staging_path": (state_root / f"STAGING-{plan_id}").as_posix(),
    }
    return {**semantic, "plan_id": plan_id, "storage": storage}


def validate_plan(
    payload: Mapping[str, object],
    *,
    mutation_set: Mapping[str, object],
    lineages: Mapping[str, object],
    namespace: Mapping[str, object],
) -> dict[str, object]:
    plan = dict(payload)
    required = {
        "artifacts",
        "attempts",
        "boundaries",
        "capabilities",
        "lineage_evidence_digest",
        "mutation_coverage",
        "mutation_set_id",
        "plan_id",
        "policy",
        "public_prestate",
        "public_prestate_digest",
        "root_transitions",
        "schema",
        "source",
        "storage",
    }
    require(set(plan) == required and plan.get("schema") == PLAN_SCHEMA, "transaction_plan_rejected")
    source = plan.get("source")
    storage = plan.get("storage")
    require(isinstance(source, Mapping) and isinstance(storage, Mapping), "transaction_plan_rejected")
    rebuilt = build_plan(
        core_commit=str(source.get("core_commit", "")),
        deploy_commit=str(source.get("deploy_commit", "")),
        deploy_tree=str(source.get("deploy_tree", "")),
        artifact_identities=plan["artifacts"],
        lineages=lineages,
        public_prestate=plan["public_prestate"],
        boundaries=plan["boundaries"],
        policy=plan["policy"],
        mutation_set=mutation_set,
        mutation_coverage=plan["mutation_coverage"],
        root_transitions=plan["root_transitions"],
        namespace=namespace,
        state_root=Path(str(storage.get("state_root", ""))),
        backup_root=Path(str(storage.get("backup_root", ""))),
    )
    require(plan == rebuilt, "transaction_plan_rejected")
    return rebuilt


def _atomic_write(path: Path, payload: bytes, *, mode: int) -> None:
    parent = path.parent
    metadata = parent.lstat()
    require(not stat.S_ISLNK(metadata.st_mode) and stat.S_ISDIR(metadata.st_mode), "transaction_write_parent_rejected")
    temporary = parent / f".{path.name}.{sha256(payload).hexdigest()[:16]}.tmp"
    require(not temporary.exists() and not temporary.is_symlink(), "transaction_stale_temp_rejected")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def create_plan_bound_backup(
    *,
    plan: Mapping[str, object],
    mutation_set: Mapping[str, object],
    backup_path: Path,
    before_payloads: Mapping[str, bytes],
    owner_uid: int,
    owner_gid: int,
) -> dict[str, object]:
    """Create a non-overwriting synthetic/future backup bound to one plan."""

    contract = mutation.validate_mutation_set(mutation_set)
    require(
        backup_path.is_absolute()
        and not backup_path.exists()
        and not backup_path.is_symlink()
        and backup_path.as_posix() == plan["storage"]["backup_path"],
        "transaction_backup_path_rejected",
    )
    expected = {
        mutation.path_key(str(item["root_id"]), str(item["logical_path"]))
        for item in contract["operations"]
        if item["before"]["exists"]
    }
    require(set(before_payloads) == expected, "transaction_backup_payload_set_rejected")
    backup_path.mkdir(parents=True, mode=0o700)
    os.chmod(backup_path, 0o700)
    os.chown(backup_path, owner_uid, owner_gid)
    fixed_files: list[dict[str, object]] = []
    for relative, payload in (
        ("PLAN.json", canonical(plan)),
        ("MUTATION_SET.json", mutation.canonical(contract)),
    ):
        target = backup_path / relative
        _atomic_write(target, payload, mode=0o600)
        os.chown(target, owner_uid, owner_gid)
        fixed_files.append(
            {
                "mode": 0o600,
                "path": relative,
                "sha256": sha256(payload).hexdigest(),
                "size": len(payload),
            }
        )
    files: list[dict[str, object]] = []
    for operation in contract["operations"]:
        if not operation["before"]["exists"]:
            continue
        key = mutation.path_key(str(operation["root_id"]), str(operation["logical_path"]))
        payload = before_payloads[key]
        require(
            sha256(payload).hexdigest() == operation["before"]["sha256"]
            and len(payload) == operation["before"]["size"],
            "transaction_backup_payload_rejected",
        )
        relative = f"before/{int(operation['order']):04d}-{digest('p07_backup_path', key)[:20]}.blob"
        target = backup_path / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(target.parent, 0o700)
        os.chown(target.parent, owner_uid, owner_gid)
        _atomic_write(target, payload, mode=0o600)
        os.chown(target, owner_uid, owner_gid)
        files.append(
            {
                "backup_mode": 0o600,
                "logical_path_digest": digest("p07_backup_path", key),
                "operation_order": operation["order"],
                "relative_path": relative,
                "sha256": operation["before"]["sha256"],
                "size": operation["before"]["size"],
                "target_gid": operation["before"]["gid"],
                "target_mode": operation["before"]["mode"],
                "target_uid": operation["before"]["uid"],
            }
        )
    semantic = {
        "content_retained_in_manifest": False,
        "files": files,
        "fixed_files": fixed_files,
        "mutation_set_id": contract["mutation_set_id"],
        "owner_gid": owner_gid,
        "owner_uid": owner_uid,
        "plan_id": plan["plan_id"],
        "protected_paths": {
            "filesystem_journal_path": plan["storage"]["filesystem_journal_path"],
            "journal_path": plan["storage"]["journal_path"],
            "staging_path": plan["storage"]["staging_path"],
        },
        "root_transitions_digest": digest("p07_root_transitions", plan["root_transitions"]),
        "schema": BACKUP_SCHEMA,
    }
    manifest = {**semantic, "backup_id": digest("p07_transaction_backup", semantic)}
    _atomic_write(backup_path / "manifest.json", canonical(manifest), mode=0o600)
    os.chown(backup_path / "manifest.json", owner_uid, owner_gid)
    verify_plan_bound_backup(
        plan=plan,
        mutation_set=contract,
        backup_path=backup_path,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    return manifest


def verify_plan_bound_backup(
    *,
    plan: Mapping[str, object],
    mutation_set: Mapping[str, object],
    backup_path: Path,
    owner_uid: int,
    owner_gid: int,
) -> dict[str, object]:
    contract = mutation.validate_mutation_set(mutation_set)
    try:
        root_metadata = backup_path.lstat()
        manifest = _canonical_read(backup_path / "manifest.json", "transaction_backup_manifest_rejected")
    except OSError as exc:
        raise TransactionalControllerRejected("transaction_backup_unavailable") from exc
    require(
        not stat.S_ISLNK(root_metadata.st_mode)
        and stat.S_ISDIR(root_metadata.st_mode)
        and stat.S_IMODE(root_metadata.st_mode) == 0o700
        and root_metadata.st_uid == owner_uid
        and root_metadata.st_gid == owner_gid,
        "transaction_backup_acl_rejected",
    )
    required = {
        "backup_id",
        "content_retained_in_manifest",
        "files",
        "fixed_files",
        "mutation_set_id",
        "owner_gid",
        "owner_uid",
        "plan_id",
        "protected_paths",
        "root_transitions_digest",
        "schema",
    }
    semantic = {key: manifest.get(key) for key in required - {"backup_id"}}
    require(
        set(manifest) == required
        and manifest.get("schema") == BACKUP_SCHEMA
        and manifest.get("plan_id") == plan["plan_id"]
        and manifest.get("mutation_set_id") == contract["mutation_set_id"]
        and manifest.get("content_retained_in_manifest") is False
        and manifest.get("owner_uid") == owner_uid
        and manifest.get("owner_gid") == owner_gid
        and manifest.get("backup_id") == digest("p07_transaction_backup", semantic),
        "transaction_backup_manifest_rejected",
    )
    expected_paths = {"manifest.json"}
    fixed_files = manifest.get("fixed_files")
    require(isinstance(fixed_files, list), "transaction_backup_manifest_rejected")
    for item in fixed_files:
        require(
            isinstance(item, dict)
            and set(item) == {"mode", "path", "sha256", "size"},
            "transaction_backup_manifest_rejected",
        )
        path = backup_path / str(item["path"])
        metadata = path.lstat()
        require(
            not stat.S_ISLNK(metadata.st_mode)
            and stat.S_ISREG(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == item["mode"]
            and metadata.st_uid == owner_uid
            and metadata.st_gid == owner_gid
            and metadata.st_size == item["size"]
            and digest_file(path) == item["sha256"],
            "transaction_backup_readback_rejected",
        )
        expected_paths.add(str(item["path"]))
    files = manifest.get("files")
    require(isinstance(files, list), "transaction_backup_manifest_rejected")
    if files:
        before_metadata = (backup_path / "before").lstat()
        require(
            not stat.S_ISLNK(before_metadata.st_mode)
            and stat.S_ISDIR(before_metadata.st_mode)
            and stat.S_IMODE(before_metadata.st_mode) == 0o700
            and before_metadata.st_uid == owner_uid
            and before_metadata.st_gid == owner_gid,
            "transaction_backup_acl_rejected",
        )
    for item in files:
        require(
            isinstance(item, dict)
            and set(item)
            == {
                "backup_mode",
                "logical_path_digest",
                "operation_order",
                "relative_path",
                "sha256",
                "size",
                "target_gid",
                "target_mode",
                "target_uid",
            },
            "transaction_backup_manifest_rejected",
        )
        path = backup_path / str(item["relative_path"])
        metadata = path.lstat()
        require(
            not stat.S_ISLNK(metadata.st_mode)
            and stat.S_ISREG(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == item["backup_mode"]
            and metadata.st_uid == owner_uid
            and metadata.st_gid == owner_gid
            and metadata.st_size == item["size"]
            and digest_file(path) == item["sha256"],
            "transaction_backup_readback_rejected",
        )
        expected_paths.add(str(item["relative_path"]))
    actual_paths = {
        path.relative_to(backup_path).as_posix()
        for path in backup_path.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    require(actual_paths == expected_paths, "transaction_backup_inventory_rejected")
    return manifest


def initial_journal(plan: Mapping[str, object]) -> dict[str, object]:
    return {
        "activation_failure_code": None,
        "attempts": 0,
        "content_retained": False,
        "events": [],
        "maximum_attempts": MAXIMUM_ACTIVATIONS,
        "plan_id": plan["plan_id"],
        "private_content_read": False,
        "rollback_failure_code": None,
        "rollback_invocations": 0,
        "schema": JOURNAL_SCHEMA,
        "source_id": SOURCE_ID,
        "stage": "pre_attempt",
    }


def validate_journal(payload: Mapping[str, object], plan: Mapping[str, object]) -> dict[str, object]:
    journal = dict(payload)
    required = {
        "activation_failure_code",
        "attempts",
        "content_retained",
        "events",
        "maximum_attempts",
        "plan_id",
        "private_content_read",
        "rollback_failure_code",
        "rollback_invocations",
        "schema",
        "source_id",
        "stage",
    }
    require(
        set(journal) == required
        and journal.get("schema") == JOURNAL_SCHEMA
        and journal.get("source_id") == SOURCE_ID
        and journal.get("plan_id") == plan["plan_id"]
        and journal.get("maximum_attempts") == MAXIMUM_ACTIVATIONS
        and journal.get("attempts") in {0, 1}
        and journal.get("rollback_invocations") in {0, 1}
        and journal.get("stage") in _SOURCE_STATES
        and journal.get("content_retained") is False
        and journal.get("private_content_read") is False
        and isinstance(journal.get("events"), list),
        "transaction_journal_rejected",
    )
    for field in ("activation_failure_code", "rollback_failure_code"):
        value = journal[field]
        require(value is None or (isinstance(value, str) and _TYPED.fullmatch(value)), "transaction_journal_rejected")
    return journal


def write_journal(path: Path, journal: Mapping[str, object], plan: Mapping[str, object]) -> None:
    validate_journal(journal, plan)
    require(path.is_absolute(), "transaction_journal_path_rejected")
    _atomic_write(path, canonical(journal), mode=0o600)


def load_journal(path: Path, plan: Mapping[str, object]) -> dict[str, object]:
    return validate_journal(_canonical_read(path, "transaction_journal_rejected"), plan)


def advance_journal(
    journal: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    stage: str,
    category: str,
    activation_failure_code: str | None = None,
    rollback_failure_code: str | None = None,
) -> dict[str, object]:
    current = validate_journal(journal, plan)
    require(stage in _TRANSITIONS[str(current["stage"])], "transaction_journal_transition_rejected")
    require(_TYPED.fullmatch(category) is not None, "transaction_journal_category_rejected")
    updated = dict(current)
    updated["stage"] = stage
    updated["events"] = [
        *current["events"],
        {
            "category": category,
            "event_digest": digest(
                "p07_transaction_journal_event",
                {
                    "category": category,
                    "index": len(current["events"]),
                    "plan_id": plan["plan_id"],
                    "stage": stage,
                },
            ),
            "stage": stage,
        },
    ]
    if stage == "attempt_consumed":
        require(current["attempts"] == 0, "transaction_attempt_replayed")
        updated["attempts"] = 1
    if stage == "rollback_started":
        require(current["rollback_invocations"] == 0, "transaction_rollback_replayed")
        updated["rollback_invocations"] = 1
    if activation_failure_code is not None:
        require(_TYPED.fullmatch(activation_failure_code) is not None, "transaction_activation_failure_code_rejected")
        updated["activation_failure_code"] = activation_failure_code
    if rollback_failure_code is not None:
        require(_TYPED.fullmatch(rollback_failure_code) is not None, "transaction_rollback_failure_code_rejected")
        updated["rollback_failure_code"] = rollback_failure_code
    return validate_journal(updated, plan)


class TransactionHooks(Protocol):
    def consume_attempt(self, *, maximum_attempts: int) -> int: ...

    def stop_target_services(self) -> None: ...

    def verify_target_services_stopped(self) -> None: ...

    def verify_target_semantics(self) -> None: ...

    def daemon_reload(self) -> None: ...

    def start_core(self) -> None: ...

    def verify_core(self) -> None: ...

    def start_telegram(self) -> None: ...

    def verify_target(self) -> None: ...

    def verify_prestate_files(self) -> None: ...

    def restore_core(self) -> None: ...

    def verify_core_prestate(self) -> None: ...

    def restore_telegram(self) -> None: ...

    def verify_prestate(self) -> None: ...


@dataclass(slots=True)
class TransactionStorage:
    backup_path: Path
    staging_path: Path
    filesystem_journal_path: Path
    controller_journal_path: Path


class FullMutationTransactionBackend:
    """Concrete filesystem adapter with injected, source-testable service hooks."""

    def __init__(
        self,
        *,
        plan: Mapping[str, object],
        mutation_set: Mapping[str, object],
        before_payloads: Mapping[str, bytes],
        after_payloads: Mapping[str, bytes],
        storage: TransactionStorage,
        hooks: TransactionHooks,
        owner_uid: int,
        owner_gid: int,
    ) -> None:
        self.plan = dict(plan)
        self.contract = mutation.validate_mutation_set(mutation_set)
        self.before_payloads = dict(before_payloads)
        self.after_payloads = dict(after_payloads)
        self.storage = storage
        self.hooks = hooks
        self.owner_uid = owner_uid
        self.owner_gid = owner_gid

    def create_backup(self) -> None:
        create_plan_bound_backup(
            plan=self.plan,
            mutation_set=self.contract,
            backup_path=self.storage.backup_path,
            before_payloads=self.before_payloads,
            owner_uid=self.owner_uid,
            owner_gid=self.owner_gid,
        )
        verify_plan_bound_backup(
            plan=self.plan,
            mutation_set=self.contract,
            backup_path=self.storage.backup_path,
            owner_uid=self.owner_uid,
            owner_gid=self.owner_gid,
        )

    def create_staging(self) -> None:
        mutation.stage_mutation_set(
            contract=self.contract,
            staging_root=self.storage.staging_path,
            before_payloads=self.before_payloads,
            after_payloads=self.after_payloads,
        )
        mutation.verify_staging(contract=self.contract, staging_root=self.storage.staging_path)

    def consume_attempt(self) -> None:
        require(self.hooks.consume_attempt(maximum_attempts=MAXIMUM_ACTIVATIONS) == 1, "transaction_attempt_count_rejected")

    def stop_services(self) -> None:
        self.hooks.stop_target_services()
        self.hooks.verify_target_services_stopped()

    def apply_and_accept_target(self) -> None:
        def after_files_verified() -> None:
            self.hooks.verify_target_semantics()
            self.hooks.daemon_reload()
            self.hooks.start_core()
            self.hooks.verify_core()
            self.hooks.start_telegram()
            self.hooks.verify_target()

        apply_root_transitions(self.plan["root_transitions"])
        mutation.execute_mutation_set(
            contract=self.contract,
            staging_root=self.storage.staging_path,
            journal_path=self.storage.filesystem_journal_path,
            after_verified=after_files_verified,
        )

    def restore_functional_prestate(self) -> None:
        verify_plan_bound_backup(
            plan=self.plan,
            mutation_set=self.contract,
            backup_path=self.storage.backup_path,
            owner_uid=self.owner_uid,
            owner_gid=self.owner_gid,
        )
        if self.storage.filesystem_journal_path.exists():
            projection = mutation.journal_projection(
                self.storage.filesystem_journal_path, self.contract
            )
            if projection["stage"] == "complete":
                mutation.rollback_mutation_set(
                    contract=self.contract,
                    staging_root=self.storage.staging_path,
                    journal_path=self.storage.filesystem_journal_path,
                )
            elif projection["stage"] != "rolled_back":
                mutation.recover_mutation_set(
                    contract=self.contract,
                    staging_root=self.storage.staging_path,
                    journal_path=self.storage.filesystem_journal_path,
                )
        rollback_root_transitions(self.plan["root_transitions"])
        verify_root_transitions(self.plan["root_transitions"], side="before")
        self.hooks.verify_prestate_files()
        self.hooks.daemon_reload()
        self.hooks.restore_core()
        self.hooks.verify_core_prestate()
        self.hooks.restore_telegram()
        self.hooks.verify_prestate()


def _persist(path: Path, journal: Mapping[str, object], plan: Mapping[str, object]) -> dict[str, object]:
    write_journal(path, journal, plan)
    return dict(journal)


def execute_transaction(
    *,
    backend: FullMutationTransactionBackend,
    plan: Mapping[str, object],
) -> dict[str, object]:
    """Execute one future transaction.  T1 invokes this only with temp roots."""

    journal_path = backend.storage.controller_journal_path
    require(not journal_path.exists() and not journal_path.is_symlink(), "transaction_journal_preexisting")
    journal = initial_journal(plan)
    _persist(journal_path, journal, plan)
    try:
        backend.create_backup()
        journal = advance_journal(journal, plan, stage="backup_verified", category="backup_verified")
        _persist(journal_path, journal, plan)
        backend.create_staging()
        journal = advance_journal(journal, plan, stage="staging_verified", category="staging_verified")
        _persist(journal_path, journal, plan)
        backend.consume_attempt()
        journal = advance_journal(journal, plan, stage="attempt_consumed", category="attempt_consumed")
        _persist(journal_path, journal, plan)
        backend.stop_services()
        journal = advance_journal(journal, plan, stage="services_stopped", category="services_stopped")
        _persist(journal_path, journal, plan)
        journal = advance_journal(journal, plan, stage="files_applying", category="files_applying")
        _persist(journal_path, journal, plan)
        backend.apply_and_accept_target()
        journal = advance_journal(journal, plan, stage="target_accepted", category="target_accepted")
        return _persist(journal_path, journal, plan)
    except Exception as activation_exc:
        activation_code = _typed_error(activation_exc, "transaction_activation_failed")
        if journal["attempts"] == 0:
            raise TransactionalControllerRejected(
                "transaction_pre_attempt_failed",
                activation_failure_code=activation_code,
            ) from activation_exc
        try:
            if journal["stage"] != "rollback_started":
                journal = advance_journal(
                    journal,
                    plan,
                    stage="rollback_started",
                    category="rollback_started",
                    activation_failure_code=activation_code,
                )
                _persist(journal_path, journal, plan)
            backend.stop_services()
            backend.restore_functional_prestate()
            journal = advance_journal(journal, plan, stage="files_restored", category="files_restored")
            _persist(journal_path, journal, plan)
            journal = advance_journal(journal, plan, stage="services_restored", category="services_restored")
            _persist(journal_path, journal, plan)
            journal = advance_journal(journal, plan, stage="rolled_back", category="rolled_back")
            _persist(journal_path, journal, plan)
        except Exception as rollback_exc:
            rollback_code = _typed_error(rollback_exc, "transaction_rollback_failed")
            if journal["stage"] == "rollback_started":
                journal = advance_journal(
                    journal,
                    plan,
                    stage="rollback_failed",
                    category="rollback_failed",
                    activation_failure_code=activation_code,
                    rollback_failure_code=rollback_code,
                )
                _persist(journal_path, journal, plan)
            raise TransactionalControllerRejected(
                "transaction_rollback_failed",
                activation_failure_code=activation_code,
                rollback_failure_code=rollback_code,
            ) from rollback_exc
        raise TransactionalControllerRejected(
            "transaction_activation_failed_rollback_verified",
            activation_failure_code=activation_code,
        ) from activation_exc


def recovery_class(journal: Mapping[str, object], plan: Mapping[str, object]) -> str:
    stage = validate_journal(journal, plan)["stage"]
    if stage in {"pre_attempt", "backup_verified", "staging_verified"}:
        return "pre_attempt"
    if stage in {"attempt_consumed", "services_stopped", "files_applying"}:
        return "in_attempt"
    if stage == "target_accepted":
        return "post_attempt"
    if stage in {"rollback_started", "files_restored", "services_restored"}:
        return "rollback"
    if stage == "rolled_back":
        return "rolled_back"
    if stage == "rollback_failed":
        return "rollback_failed"
    raise TransactionalControllerRejected("transaction_recovery_state_rejected")


def content_free_projection(journal: Mapping[str, object], plan: Mapping[str, object]) -> dict[str, object]:
    selected = validate_journal(journal, plan)
    return {
        "attempts": selected["attempts"],
        "content_retained": False,
        "event_count": len(selected["events"]),
        "maximum_attempts": selected["maximum_attempts"],
        "plan_id": selected["plan_id"],
        "private_content_read": False,
        "recovery_class": recovery_class(selected, plan),
        "rollback_invocations": selected["rollback_invocations"],
        "schema": JOURNAL_SCHEMA,
        "source_id": SOURCE_ID,
        "stage": selected["stage"],
    }
