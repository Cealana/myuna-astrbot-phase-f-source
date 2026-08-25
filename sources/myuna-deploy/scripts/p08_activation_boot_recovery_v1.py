#!/usr/bin/env python3
"""Boot-resumable recovery authority for ``myuna.p08-activation-engine.v1``.

The recovery gate is permanently installed before an activation is armed.  A
missing ARM is an exact no-op.  An unresolved valid ARM can only preserve an
already accepted target or converge the same PLAN to its predecessor; it can
never replay readiness, forward activation, continuity transition, or status
acceptance.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
import sys
import time
from typing import Callable, Mapping

import p08_activation_contract_v1 as contract_v1


MAX_JSON_BYTES = 1_048_576


class BootRecoveryError(RuntimeError):
    pass


def _exact_keys(value: object, expected: set[str], code: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise BootRecoveryError(code)
    return value


def _hex64(value: object, code: str) -> str:
    if not isinstance(value, str) or contract_v1.HEX64.fullmatch(value) is None:
        raise BootRecoveryError(code)
    return value


def _hex32(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 32
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise BootRecoveryError(code)
    return value


def _absolute(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or "//" in value
        or "/../" in value + "/"
        or "/./" in value + "/"
    ):
        raise BootRecoveryError(code)
    return value


def _canonical(value: object) -> bytes:
    try:
        return contract_v1.canonical_bytes(value)
    except contract_v1.ContractError:
        raise BootRecoveryError("canonical_value_rejected") from None


def _digest(value: object) -> str:
    try:
        return contract_v1.digest_value(value)
    except contract_v1.ContractError:
        raise BootRecoveryError("canonical_value_rejected") from None


def _public_backup_digest(plan: Mapping[str, object]) -> str:
    execution = plan.get("execution")
    if not isinstance(execution, Mapping):
        raise BootRecoveryError("boot_recovery_arm_rejected")
    public = execution.get("public_prestate")
    if not isinstance(public, Mapping):
        raise BootRecoveryError("boot_recovery_arm_rejected")
    try:
        rows = [
            {"role": role, **dict(public[role])}
            for role in contract_v1.PUBLIC_ROLES
        ]
    except (KeyError, TypeError, ValueError):
        raise BootRecoveryError("boot_recovery_arm_rejected") from None
    return _digest(rows)


def boot_recovery_contract(contract: Mapping[str, object]) -> dict[str, object]:
    try:
        validated = contract_v1.validate_contract(contract)
    except contract_v1.ContractError:
        raise BootRecoveryError("boot_recovery_contract_rejected") from None
    value = validated["production_adapter"]["boot_recovery"]
    if not isinstance(value, Mapping):
        raise BootRecoveryError("boot_recovery_contract_rejected")
    return json.loads(_canonical(value))


def systemd_transaction_oracle(
    contract: Mapping[str, object],
    *,
    result_class: str,
    start_number: int,
    authority_exact: bool = True,
) -> dict[str, object]:
    transaction = _exact_keys(
        boot_recovery_contract(contract).get("transaction_liveness"),
        {
            "schema",
            "systemd_version_identity",
            "restart_mode_added_version",
            "service_type",
            "restart",
            "restart_mode",
            "restart_prevent_exit_status",
            "start_limit_burst",
            "remain_after_exit",
            "dependent_relationship",
            "direct_reentry_preserves_dependent_job",
            "typed_blocked_fails_dependency",
            "second_unexpected_failure_fails_dependency",
        },
        "boot_recovery_transaction_rejected",
    )
    if (
        transaction["schema"] != contract_v1.BOOT_RECOVERY_TRANSACTION_SCHEMA
        or transaction["systemd_version_identity"]
        != contract["systemd_authority"]["version_identity"]
        or transaction["restart_mode_added_version"] != 254
        or transaction["service_type"] != "oneshot"
        or transaction["restart"] != "on-failure"
        or transaction["restart_mode"] != "direct"
        or transaction["restart_prevent_exit_status"] != [2]
        or transaction["start_limit_burst"] != 2
        or transaction["remain_after_exit"] is not True
        or transaction["dependent_relationship"] != ["Requires", "After"]
        or transaction["direct_reentry_preserves_dependent_job"] is not True
        or transaction["typed_blocked_fails_dependency"] is not True
        or transaction["second_unexpected_failure_fails_dependency"] is not True
        or result_class not in {"success", "typed_blocked", "unexpected_failure"}
        or not isinstance(start_number, int)
        or isinstance(start_number, bool)
        or start_number not in {1, 2}
        or not isinstance(authority_exact, bool)
    ):
        raise BootRecoveryError("boot_recovery_transaction_rejected")
    if not authority_exact:
        outcome = "blocked_invalid_authority"
        restart_scheduled = False
        dependent_job_preserved = False
        product_start_authorized = False
    elif result_class == "success":
        outcome = "recovery_succeeded"
        restart_scheduled = False
        dependent_job_preserved = True
        product_start_authorized = True
    elif result_class == "typed_blocked":
        outcome = "typed_blocked"
        restart_scheduled = False
        dependent_job_preserved = False
        product_start_authorized = False
    elif start_number == 1:
        outcome = "direct_reentry_pending"
        restart_scheduled = True
        dependent_job_preserved = True
        product_start_authorized = False
    else:
        outcome = "restart_budget_exhausted"
        restart_scheduled = False
        dependent_job_preserved = False
        product_start_authorized = False
    return {
        "schema": contract_v1.BOOT_RECOVERY_TRANSACTION_SCHEMA,
        "outcome": outcome,
        "start_number": start_number,
        "restart_scheduled": restart_scheduled,
        "dependent_job_preserved": dependent_job_preserved,
        "product_start_authorized": product_start_authorized,
    }


def validate_unit_state(
    contract: Mapping[str, object], value: object, *, armed: bool = False
) -> dict[str, object]:
    recovery = boot_recovery_contract(contract)
    expected = recovery["armed_unit_runtime" if armed else "unit_runtime"]
    if not isinstance(expected, Mapping):
        raise BootRecoveryError("boot_recovery_unit_state_rejected")
    row = _exact_keys(
        value,
        set(expected) | {"boot_identity_digest", "invocation_id"},
        "boot_recovery_unit_state_rejected",
    )
    _hex64(row["boot_identity_digest"], "boot_recovery_unit_state_rejected")
    _hex32(row["invocation_id"], "boot_recovery_unit_state_rejected")
    if any(row[key] != item for key, item in expected.items()):
        raise BootRecoveryError("boot_recovery_unit_state_rejected")
    return json.loads(_canonical(row))


def build_closure(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    runtime_inventory_digest: str,
    runtime_directories_digest: str,
    unit_state: Mapping[str, object],
) -> dict[str, object]:
    try:
        validated = contract_v1.validate_contract(contract)
        bound_plan = contract_v1.validate_plan(validated, plan)
    except contract_v1.ContractError:
        raise BootRecoveryError("boot_recovery_closure_rejected") from None
    _hex64(runtime_inventory_digest, "boot_recovery_closure_rejected")
    _hex64(runtime_directories_digest, "boot_recovery_closure_rejected")
    recovery = boot_recovery_contract(validated)
    artifacts = [
        artifact
        for artifact in recovery["artifacts"]
        if artifact["role"]
        not in {"service_recovery_dropin", "socket_recovery_dropin"}
    ]
    bound_unit_state = validate_unit_state(validated, unit_state)
    body = {
        "schema": contract_v1.BOOT_RECOVERY_CLOSURE_SCHEMA,
        "architecture": contract_v1.ARCHITECTURE,
        "contract_digest": validated["contract_digest"],
        "plan_digest": bound_plan["plan_digest"],
        "target_identity": bound_plan["target_identity"],
        "runtime_root": recovery["runtime_root"],
        "runtime_inventory_digest": runtime_inventory_digest,
        "runtime_directories_digest": runtime_directories_digest,
        "artifacts": artifacts,
        "artifacts_digest": _digest(artifacts),
        "install_order_digest": _digest(recovery["install_order"]),
        "unit_name": recovery["unit_name"],
        "unit_state": bound_unit_state,
        "unit_state_digest": _digest(bound_unit_state),
        "gate_units": recovery["gate_units"],
        "product_gate_exact": True,
        "raw_content_included": False,
    }
    return validate_closure(
        validated,
        bound_plan,
        {**body, "closure_digest": _digest(body)},
    )


def validate_closure(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    value: object,
) -> dict[str, object]:
    try:
        validated = contract_v1.validate_contract(contract)
        bound_plan = contract_v1.validate_plan(validated, plan)
    except contract_v1.ContractError:
        raise BootRecoveryError("boot_recovery_closure_rejected") from None
    row = _exact_keys(
        value,
        {
            "architecture",
            "artifacts",
            "artifacts_digest",
            "closure_digest",
            "contract_digest",
            "gate_units",
            "install_order_digest",
            "plan_digest",
            "product_gate_exact",
            "raw_content_included",
            "runtime_directories_digest",
            "runtime_inventory_digest",
            "runtime_root",
            "schema",
            "target_identity",
            "unit_name",
            "unit_state",
            "unit_state_digest",
        },
        "boot_recovery_closure_rejected",
    )
    for key in (
        "artifacts_digest",
        "closure_digest",
        "contract_digest",
        "install_order_digest",
        "plan_digest",
        "runtime_directories_digest",
        "runtime_inventory_digest",
        "target_identity",
        "unit_state_digest",
    ):
        _hex64(row[key], "boot_recovery_closure_rejected")
    recovery = boot_recovery_contract(validated)
    bound_unit_state = validate_unit_state(validated, row["unit_state"])
    unsigned = {key: item for key, item in row.items() if key != "closure_digest"}
    if (
        row["schema"] != contract_v1.BOOT_RECOVERY_CLOSURE_SCHEMA
        or row["architecture"] != contract_v1.ARCHITECTURE
        or row["contract_digest"] != validated["contract_digest"]
        or row["plan_digest"] != bound_plan["plan_digest"]
        or row["target_identity"] != bound_plan["target_identity"]
        or row["runtime_root"] != recovery["runtime_root"]
        or row["runtime_inventory_digest"]
        != bound_plan["execution"]["target_inventory_digest"]
        or row["runtime_directories_digest"]
        != bound_plan["execution"]["target_directories_digest"]
        or row["artifacts"]
        != [
            artifact
            for artifact in recovery["artifacts"]
            if artifact["role"]
            not in {"service_recovery_dropin", "socket_recovery_dropin"}
        ]
        or row["artifacts_digest"]
        != _digest(
            [
                artifact
                for artifact in recovery["artifacts"]
                if artifact["role"]
                not in {"service_recovery_dropin", "socket_recovery_dropin"}
            ]
        )
        or row["install_order_digest"] != _digest(recovery["install_order"])
        or row["unit_name"] != recovery["unit_name"]
        or row["unit_state"] != bound_unit_state
        or row["unit_state_digest"] != _digest(bound_unit_state)
        or row["gate_units"] != recovery["gate_units"]
        or row["product_gate_exact"] is not True
        or row["raw_content_included"] is not False
        or row["closure_digest"] != _digest(unsigned)
    ):
        raise BootRecoveryError("boot_recovery_closure_rejected")
    return json.loads(_canonical(row))


def build_arm(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    launch_claim: Mapping[str, object],
    backup_manifest: Mapping[str, object],
    closure: Mapping[str, object],
    journal_digest: str,
    boot_identity_digest: str,
) -> dict[str, object]:
    try:
        validated = contract_v1.validate_contract(contract)
        bound_plan = contract_v1.validate_plan(validated, plan)
        claim = contract_v1.validate_strategy_launch_claim(validated, launch_claim)
    except contract_v1.ContractError:
        raise BootRecoveryError("boot_recovery_arm_rejected") from None
    bound_closure = validate_closure(validated, bound_plan, closure)
    backup = _exact_keys(
        backup_manifest,
        {
            "backup_digest",
            "content_bytes_read",
            "content_parsed",
            "plan_digest",
            "rows",
            "schema",
        },
        "boot_recovery_arm_rejected",
    )
    _hex64(backup["backup_digest"], "boot_recovery_arm_rejected")
    _hex64(journal_digest, "boot_recovery_arm_rejected")
    _hex64(boot_identity_digest, "boot_recovery_arm_rejected")
    backup_unsigned = {
        key: item for key, item in backup.items() if key != "backup_digest"
    }
    if (
        claim["sequence_identity"] != bound_plan["sequence_identity"]
        or claim["target_source_path"] != bound_plan["execution"]["target_source_path"]
        or claim["target_inventory_digest"]
        != bound_plan["execution"]["target_inventory_digest"]
        or claim["target_directories_digest"]
        != bound_plan["execution"]["target_directories_digest"]
        or claim["prestate_identity"] != bound_plan["prestate_identity"]
        or backup["schema"] != contract_v1.OPAQUE_BACKUP_SCHEMA
        or backup["plan_digest"] != bound_plan["plan_digest"]
        or backup["content_bytes_read"] is not True
        or backup["content_parsed"] is not False
        or not isinstance(backup["rows"], list)
        or backup["backup_digest"] != _digest(backup_unsigned)
    ):
        raise BootRecoveryError("boot_recovery_arm_rejected")
    body = {
        "schema": contract_v1.BOOT_RECOVERY_ARM_SCHEMA,
        "architecture": contract_v1.ARCHITECTURE,
        "contract_digest": validated["contract_digest"],
        "plan_digest": bound_plan["plan_digest"],
        "sequence_identity": bound_plan["sequence_identity"],
        "launch_claim_digest": claim["launch_claim_digest"],
        "execution_digest": bound_plan["execution_digest"],
        "prestate_identity": bound_plan["prestate_identity"],
        "predecessor_identity": bound_plan["predecessor_identity"],
        "target_identity": bound_plan["target_identity"],
        "backup_digest": backup["backup_digest"],
        "public_backup_digest": _public_backup_digest(bound_plan),
        "closure_digest": bound_closure["closure_digest"],
        "journal_digest_at_arm": journal_digest,
        "arm_boot_identity_digest": boot_identity_digest,
        "armed_after_roles": [
            "claim",
            "backup",
            "stage",
            "recovery_install",
        ],
        "hazardous_mutation_started": False,
        "forward_action_replay_authorized": False,
        "acceptance_replay_authorized": False,
        "raw_content_included": False,
    }
    return validate_arm(
        validated,
        bound_plan,
        claim,
        backup,
        bound_closure,
        {**body, "arm_digest": _digest(body)},
    )


def validate_arm(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    launch_claim: Mapping[str, object],
    backup_manifest: Mapping[str, object],
    closure: Mapping[str, object],
    value: object,
) -> dict[str, object]:
    try:
        validated = contract_v1.validate_contract(contract)
        bound_plan = contract_v1.validate_plan(validated, plan)
        claim = contract_v1.validate_strategy_launch_claim(validated, launch_claim)
    except contract_v1.ContractError:
        raise BootRecoveryError("boot_recovery_arm_rejected") from None
    bound_closure = validate_closure(validated, bound_plan, closure)
    backup = _exact_keys(
        backup_manifest,
        {
            "backup_digest",
            "content_bytes_read",
            "content_parsed",
            "plan_digest",
            "rows",
            "schema",
        },
        "boot_recovery_arm_rejected",
    )
    backup_unsigned = {
        key: item for key, item in backup.items() if key != "backup_digest"
    }
    row = _exact_keys(
        value,
        {
            "acceptance_replay_authorized",
            "architecture",
            "arm_boot_identity_digest",
            "arm_digest",
            "armed_after_roles",
            "backup_digest",
            "closure_digest",
            "contract_digest",
            "execution_digest",
            "forward_action_replay_authorized",
            "hazardous_mutation_started",
            "journal_digest_at_arm",
            "launch_claim_digest",
            "plan_digest",
            "predecessor_identity",
            "prestate_identity",
            "public_backup_digest",
            "raw_content_included",
            "schema",
            "sequence_identity",
            "target_identity",
        },
        "boot_recovery_arm_rejected",
    )
    for key in (
        "arm_digest",
        "arm_boot_identity_digest",
        "backup_digest",
        "closure_digest",
        "contract_digest",
        "execution_digest",
        "journal_digest_at_arm",
        "launch_claim_digest",
        "plan_digest",
        "predecessor_identity",
        "prestate_identity",
        "public_backup_digest",
        "sequence_identity",
        "target_identity",
    ):
        _hex64(row[key], "boot_recovery_arm_rejected")
    unsigned = {key: item for key, item in row.items() if key != "arm_digest"}
    if (
        row["schema"] != contract_v1.BOOT_RECOVERY_ARM_SCHEMA
        or row["architecture"] != contract_v1.ARCHITECTURE
        or row["contract_digest"] != validated["contract_digest"]
        or row["plan_digest"] != bound_plan["plan_digest"]
        or row["sequence_identity"] != bound_plan["sequence_identity"]
        or row["launch_claim_digest"] != claim["launch_claim_digest"]
        or row["execution_digest"] != bound_plan["execution_digest"]
        or row["prestate_identity"] != bound_plan["prestate_identity"]
        or row["predecessor_identity"] != bound_plan["predecessor_identity"]
        or row["target_identity"] != bound_plan["target_identity"]
        or row["backup_digest"] != backup.get("backup_digest")
        or row["public_backup_digest"] != _public_backup_digest(bound_plan)
        or backup.get("schema") != contract_v1.OPAQUE_BACKUP_SCHEMA
        or backup.get("plan_digest") != bound_plan["plan_digest"]
        or backup.get("content_bytes_read") is not True
        or backup.get("content_parsed") is not False
        or not isinstance(backup.get("rows"), list)
        or backup.get("backup_digest") != _digest(backup_unsigned)
        or row["closure_digest"] != bound_closure["closure_digest"]
        or row["armed_after_roles"]
        != ["claim", "backup", "stage", "recovery_install"]
        or row["hazardous_mutation_started"] is not False
        or row["forward_action_replay_authorized"] is not False
        or row["acceptance_replay_authorized"] is not False
        or row["raw_content_included"] is not False
        or row["arm_digest"] != _digest(unsigned)
    ):
        raise BootRecoveryError("boot_recovery_arm_rejected")
    return json.loads(_canonical(row))


def build_owner(
    contract: Mapping[str, object],
    arm: Mapping[str, object],
    *,
    boot_identity_digest: str,
    monotonic_start_ns: int,
    initial_invocation_id: str,
) -> dict[str, object]:
    recovery = boot_recovery_contract(contract)
    bound_arm = _exact_keys(arm, set(arm), "boot_recovery_owner_rejected")
    _hex64(bound_arm.get("arm_digest"), "boot_recovery_owner_rejected")
    _hex64(boot_identity_digest, "boot_recovery_owner_rejected")
    _hex32(initial_invocation_id, "boot_recovery_owner_rejected")
    if not isinstance(monotonic_start_ns, int) or isinstance(monotonic_start_ns, bool) or monotonic_start_ns < 1:
        raise BootRecoveryError("boot_recovery_owner_rejected")
    deadline = monotonic_start_ns + int(recovery["fresh_boot_deadline_seconds"]) * 1_000_000_000
    body = {
        "schema": contract_v1.BOOT_RECOVERY_OWNER_SCHEMA,
        "architecture": contract_v1.ARCHITECTURE,
        "contract_digest": contract["contract_digest"],
        "arm_digest": bound_arm["arm_digest"],
        "plan_digest": bound_arm["plan_digest"],
        "boot_identity_digest": boot_identity_digest,
        "initial_invocation_id": initial_invocation_id,
        "monotonic_start_ns": monotonic_start_ns,
        "monotonic_deadline_ns": deadline,
        "recovery_count": 1,
        "manager_max_starts": 2,
        "forward_action_authorized": False,
        "raw_content_included": False,
    }
    return validate_owner(
        contract,
        arm,
        {**body, "owner_digest": _digest(body)},
    )


def validate_owner(
    contract: Mapping[str, object], arm: Mapping[str, object], value: object
) -> dict[str, object]:
    recovery = boot_recovery_contract(contract)
    row = _exact_keys(
        value,
        {
            "architecture",
            "arm_digest",
            "boot_identity_digest",
            "contract_digest",
            "forward_action_authorized",
            "initial_invocation_id",
            "manager_max_starts",
            "monotonic_deadline_ns",
            "monotonic_start_ns",
            "owner_digest",
            "plan_digest",
            "raw_content_included",
            "recovery_count",
            "schema",
        },
        "boot_recovery_owner_rejected",
    )
    for key in (
        "arm_digest",
        "boot_identity_digest",
        "contract_digest",
        "owner_digest",
        "plan_digest",
    ):
        _hex64(row[key], "boot_recovery_owner_rejected")
    _hex32(row["initial_invocation_id"], "boot_recovery_owner_rejected")
    unsigned = {key: item for key, item in row.items() if key != "owner_digest"}
    if (
        row["schema"] != contract_v1.BOOT_RECOVERY_OWNER_SCHEMA
        or row["architecture"] != contract_v1.ARCHITECTURE
        or row["contract_digest"] != contract["contract_digest"]
        or row["arm_digest"] != arm.get("arm_digest")
        or row["plan_digest"] != arm.get("plan_digest")
        or not isinstance(row["monotonic_start_ns"], int)
        or isinstance(row["monotonic_start_ns"], bool)
        or row["monotonic_start_ns"] < 1
        or row["monotonic_deadline_ns"]
        != row["monotonic_start_ns"]
        + int(recovery["fresh_boot_deadline_seconds"]) * 1_000_000_000
        or row["recovery_count"] != 1
        or row["manager_max_starts"] != recovery["per_boot_manager_max_starts"]
        or row["forward_action_authorized"] is not False
        or row["raw_content_included"] is not False
        or row["owner_digest"] != _digest(unsigned)
    ):
        raise BootRecoveryError("boot_recovery_owner_rejected")
    return json.loads(_canonical(row))


def build_reentry(
    contract: Mapping[str, object],
    arm: Mapping[str, object],
    owner: Mapping[str, object],
    *,
    invocation_id: str,
) -> dict[str, object]:
    bound_owner = validate_owner(contract, arm, owner)
    _hex32(invocation_id, "boot_recovery_reentry_rejected")
    if invocation_id == bound_owner["initial_invocation_id"]:
        raise BootRecoveryError("boot_recovery_reentry_rejected")
    body = {
        "schema": contract_v1.BOOT_RECOVERY_REENTRY_SCHEMA,
        "architecture": contract_v1.ARCHITECTURE,
        "contract_digest": contract["contract_digest"],
        "arm_digest": arm["arm_digest"],
        "plan_digest": arm["plan_digest"],
        "owner_digest": bound_owner["owner_digest"],
        "boot_identity_digest": bound_owner["boot_identity_digest"],
        "manager_generation": 2,
        "invocation_id": invocation_id,
        "forward_action_authorized": False,
        "raw_content_included": False,
    }
    return validate_reentry(
        contract,
        arm,
        owner,
        {**body, "reentry_digest": _digest(body)},
    )


def validate_reentry(
    contract: Mapping[str, object],
    arm: Mapping[str, object],
    owner: Mapping[str, object],
    value: object,
) -> dict[str, object]:
    bound_owner = validate_owner(contract, arm, owner)
    row = _exact_keys(
        value,
        {
            "architecture",
            "arm_digest",
            "boot_identity_digest",
            "contract_digest",
            "forward_action_authorized",
            "invocation_id",
            "manager_generation",
            "owner_digest",
            "plan_digest",
            "raw_content_included",
            "reentry_digest",
            "schema",
        },
        "boot_recovery_reentry_rejected",
    )
    for key in (
        "arm_digest",
        "boot_identity_digest",
        "contract_digest",
        "owner_digest",
        "plan_digest",
        "reentry_digest",
    ):
        _hex64(row[key], "boot_recovery_reentry_rejected")
    _hex32(row["invocation_id"], "boot_recovery_reentry_rejected")
    unsigned = {key: item for key, item in row.items() if key != "reentry_digest"}
    if (
        row["schema"] != contract_v1.BOOT_RECOVERY_REENTRY_SCHEMA
        or row["architecture"] != contract_v1.ARCHITECTURE
        or row["contract_digest"] != contract["contract_digest"]
        or row["arm_digest"] != arm.get("arm_digest")
        or row["plan_digest"] != arm.get("plan_digest")
        or row["owner_digest"] != bound_owner["owner_digest"]
        or row["boot_identity_digest"] != bound_owner["boot_identity_digest"]
        or row["manager_generation"] != 2
        or row["invocation_id"] == bound_owner["initial_invocation_id"]
        or row["forward_action_authorized"] is not False
        or row["raw_content_included"] is not False
        or row["reentry_digest"] != _digest(unsigned)
    ):
        raise BootRecoveryError("boot_recovery_reentry_rejected")
    return json.loads(_canonical(row))


@dataclass(frozen=True)
class RecoveryEvidence:
    arm: str
    disarm: str
    accepted: str
    predecessor: str
    backup: str
    convergence_terminal: str


def classify_recovery(evidence: RecoveryEvidence) -> str:
    allowed = {
        "arm": {"absent", "valid", "invalid"},
        "disarm": {"absent", "valid", "invalid"},
        "accepted": {"absent", "valid", "invalid"},
        "predecessor": {"exact", "not_exact", "indeterminate"},
        "backup": {"valid", "invalid", "not_required"},
        "convergence_terminal": {"absent", "converged", "failed", "invalid"},
    }
    for field, values in allowed.items():
        if getattr(evidence, field) not in values:
            raise BootRecoveryError("boot_recovery_evidence_rejected")
    if evidence.arm == "absent":
        if any(
            value != expected
            for value, expected in (
                (evidence.disarm, "absent"),
                (evidence.accepted, "absent"),
                (evidence.convergence_terminal, "absent"),
            )
        ):
            return "blocked_invalid_authority"
        return "no_arm_noop"
    if evidence.arm != "valid" or evidence.disarm == "invalid":
        return "blocked_invalid_authority"
    if evidence.disarm == "valid":
        return "disarmed_noop"
    if evidence.accepted == "invalid" or evidence.convergence_terminal == "invalid":
        return "blocked_invalid_authority"
    if evidence.accepted == "valid":
        return "accepted_preserved"
    if evidence.convergence_terminal == "converged":
        return "converged_predecessor"
    if evidence.convergence_terminal == "failed":
        return "blocked_convergence_failed"
    if evidence.predecessor == "exact":
        return "predecessor_already_exact"
    if evidence.backup != "valid":
        return "blocked_invalid_authority"
    return "convergence_required"


def build_terminal(
    contract: Mapping[str, object],
    arm: Mapping[str, object],
    owner: Mapping[str, object],
    *,
    state: str,
    convergence_count: int,
    forward_history_restored: bool,
) -> dict[str, object]:
    bound_owner = validate_owner(contract, arm, owner)
    allowed = set(
        boot_recovery_contract(contract)["state_machine"]["states"]
    )
    if (
        state not in allowed
        or state in {"no_arm_noop", "disarmed_noop"}
        or convergence_count not in {0, 1}
        or not isinstance(forward_history_restored, bool)
        or forward_history_restored
        or (state in {"converged_predecessor", "blocked_convergence_failed"})
        != (convergence_count == 1)
    ):
        raise BootRecoveryError("boot_recovery_terminal_rejected")
    body = {
        "schema": contract_v1.BOOT_RECOVERY_TERMINAL_SCHEMA,
        "architecture": contract_v1.ARCHITECTURE,
        "contract_digest": contract["contract_digest"],
        "arm_digest": arm["arm_digest"],
        "plan_digest": arm["plan_digest"],
        "owner_digest": bound_owner["owner_digest"],
        "boot_identity_digest": bound_owner["boot_identity_digest"],
        "state": state,
        "convergence_count": convergence_count,
        "forward_action_replayed": False,
        "acceptance_replayed": False,
        "forward_history_restored": False,
        "product_start_authorized": state
        in {"accepted_preserved", "predecessor_already_exact", "converged_predecessor"},
        "raw_content_included": False,
    }
    return validate_terminal(
        contract,
        arm,
        owner,
        {**body, "terminal_digest": _digest(body)},
    )


def validate_terminal(
    contract: Mapping[str, object],
    arm: Mapping[str, object],
    owner: Mapping[str, object],
    value: object,
) -> dict[str, object]:
    bound_owner = validate_owner(contract, arm, owner)
    row = _exact_keys(
        value,
        {
            "acceptance_replayed",
            "architecture",
            "arm_digest",
            "boot_identity_digest",
            "contract_digest",
            "convergence_count",
            "forward_action_replayed",
            "forward_history_restored",
            "owner_digest",
            "plan_digest",
            "product_start_authorized",
            "raw_content_included",
            "schema",
            "state",
            "terminal_digest",
        },
        "boot_recovery_terminal_rejected",
    )
    for key in (
        "arm_digest",
        "boot_identity_digest",
        "contract_digest",
        "owner_digest",
        "plan_digest",
        "terminal_digest",
    ):
        _hex64(row[key], "boot_recovery_terminal_rejected")
    success = {
        "accepted_preserved",
        "predecessor_already_exact",
        "converged_predecessor",
    }
    states = set(boot_recovery_contract(contract)["state_machine"]["states"])
    unsigned = {key: item for key, item in row.items() if key != "terminal_digest"}
    if (
        row["schema"] != contract_v1.BOOT_RECOVERY_TERMINAL_SCHEMA
        or row["architecture"] != contract_v1.ARCHITECTURE
        or row["contract_digest"] != contract["contract_digest"]
        or row["arm_digest"] != arm.get("arm_digest")
        or row["plan_digest"] != arm.get("plan_digest")
        or row["owner_digest"] != bound_owner["owner_digest"]
        or row["boot_identity_digest"] != bound_owner["boot_identity_digest"]
        or row["state"] not in states
        or row["state"] in {"no_arm_noop", "disarmed_noop"}
        or row["convergence_count"] not in {0, 1}
        or (row["state"] in {"converged_predecessor", "blocked_convergence_failed"})
        != (row["convergence_count"] == 1)
        or row["forward_action_replayed"] is not False
        or row["acceptance_replayed"] is not False
        or row["forward_history_restored"] is not False
        or row["product_start_authorized"] != (row["state"] in success)
        or row["raw_content_included"] is not False
        or row["terminal_digest"] != _digest(unsigned)
    ):
        raise BootRecoveryError("boot_recovery_terminal_rejected")
    return json.loads(_canonical(row))


def build_disarm(
    contract: Mapping[str, object],
    arm: Mapping[str, object],
    terminal: Mapping[str, object],
    owner: Mapping[str, object],
) -> dict[str, object]:
    row = validate_terminal(contract, arm, owner, terminal)
    if row["state"] not in {
        "accepted_preserved",
        "predecessor_already_exact",
        "converged_predecessor",
    }:
        raise BootRecoveryError("boot_recovery_disarm_rejected")
    body = {
        "schema": contract_v1.BOOT_RECOVERY_DISARM_SCHEMA,
        "architecture": contract_v1.ARCHITECTURE,
        "contract_digest": contract["contract_digest"],
        "arm_digest": arm["arm_digest"],
        "plan_digest": arm["plan_digest"],
        "terminal_digest": row["terminal_digest"],
        "owner_digest": row["owner_digest"],
        "boot_identity_digest": row["boot_identity_digest"],
        "final_state": row["state"],
        "product_start_authorized": True,
        "raw_content_included": False,
    }
    return validate_disarm(
        contract,
        arm,
        terminal,
        {**body, "disarm_digest": _digest(body)},
    )


def validate_disarm(
    contract: Mapping[str, object],
    arm: Mapping[str, object],
    terminal: Mapping[str, object],
    value: object,
) -> dict[str, object]:
    row = _exact_keys(
        value,
        {
            "architecture",
            "arm_digest",
            "boot_identity_digest",
            "contract_digest",
            "disarm_digest",
            "final_state",
            "owner_digest",
            "plan_digest",
            "product_start_authorized",
            "raw_content_included",
            "schema",
            "terminal_digest",
        },
        "boot_recovery_disarm_rejected",
    )
    for key in (
        "arm_digest",
        "boot_identity_digest",
        "contract_digest",
        "disarm_digest",
        "owner_digest",
        "plan_digest",
        "terminal_digest",
    ):
        _hex64(row[key], "boot_recovery_disarm_rejected")
    unsigned = {key: item for key, item in row.items() if key != "disarm_digest"}
    if (
        row["schema"] != contract_v1.BOOT_RECOVERY_DISARM_SCHEMA
        or row["architecture"] != contract_v1.ARCHITECTURE
        or row["contract_digest"] != contract["contract_digest"]
        or row["arm_digest"] != arm.get("arm_digest")
        or row["plan_digest"] != arm.get("plan_digest")
        or row["terminal_digest"] != terminal.get("terminal_digest")
        or row["owner_digest"] != terminal.get("owner_digest")
        or row["boot_identity_digest"] != terminal.get("boot_identity_digest")
        or row["final_state"] != terminal.get("state")
        or row["final_state"] not in {
            "accepted_preserved",
            "predecessor_already_exact",
            "converged_predecessor",
        }
        or row["product_start_authorized"] is not True
        or row["raw_content_included"] is not False
        or row["disarm_digest"] != _digest(unsigned)
    ):
        raise BootRecoveryError("boot_recovery_disarm_rejected")
    return json.loads(_canonical(row))


def _read_json(path: Path) -> dict[str, object]:
    try:
        details = path.lstat()
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
            or details.st_size < 2
            or details.st_size > MAX_JSON_BYTES
        ):
            raise BootRecoveryError("boot_recovery_evidence_rejected")
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise BootRecoveryError("boot_recovery_evidence_rejected") from None
    if not isinstance(value, dict) or raw != _canonical(value):
        raise BootRecoveryError("boot_recovery_evidence_rejected")
    return value


def _rooted(root: Path, absolute: object) -> Path:
    selected = _absolute(absolute, "boot_recovery_path_rejected")
    if not root.is_absolute():
        raise BootRecoveryError("boot_recovery_path_rejected")
    return root / selected.lstrip("/")


def _private_directory(path: Path, *, create: bool = False) -> None:
    if create:
        try:
            path.mkdir(mode=0o700)
            os.chmod(path, 0o700)
            os.chown(path, os.getuid(), os.getgid())
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError:
            raise BootRecoveryError("boot_recovery_evidence_write_rejected") from None
    try:
        details = path.lstat()
    except OSError:
        raise BootRecoveryError("boot_recovery_evidence_rejected") from None
    if (
        not stat.S_ISDIR(details.st_mode)
        or stat.S_ISLNK(details.st_mode)
        or stat.S_IMODE(details.st_mode) != 0o700
        or details.st_uid != os.getuid()
        or details.st_gid != os.getgid()
    ):
        raise BootRecoveryError("boot_recovery_evidence_rejected")


def _persist_json(path: Path, value: Mapping[str, object]) -> dict[str, object]:
    raw = _canonical(value)
    _private_directory(path.parent)
    temporary = path.parent / ("." + path.name + ".creating")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(temporary, flags, 0o600)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written < 1:
                raise OSError("short write")
            offset += written
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, os.getuid(), os.getgid())
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary, path, follow_symlinks=False)
        os.unlink(temporary)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except OSError:
        if "descriptor" in locals() and descriptor >= 0:
            os.close(descriptor)
        raise BootRecoveryError("boot_recovery_evidence_write_rejected") from None
    observed = _read_json(path)
    try:
        details = path.lstat()
    except OSError:
        raise BootRecoveryError("boot_recovery_evidence_write_rejected") from None
    if (
        observed != value
        or stat.S_IMODE(details.st_mode) != 0o600
        or details.st_uid != os.getuid()
        or details.st_gid != os.getgid()
        or details.st_nlink != 1
    ):
        raise BootRecoveryError("boot_recovery_evidence_write_rejected")
    return observed


def _load_contract(path: Path) -> dict[str, object]:
    value = _read_json(path)
    try:
        validated = contract_v1.validate_contract(value)
    except contract_v1.ContractError:
        raise BootRecoveryError("boot_recovery_contract_rejected") from None
    if _canonical(validated) != path.read_bytes():
        raise BootRecoveryError("boot_recovery_contract_rejected")
    return validated


def _load_plan_bundle(
    contract: Mapping[str, object], root: Path
) -> tuple[dict[str, object], dict[str, object], Path, Path]:
    fixed = contract["production_adapter"]["fixed_paths"]
    strategy = _rooted(root, fixed["strategy_root"])
    _private_directory(strategy)
    claim_path = strategy / "STRATEGY.LAUNCH.CLAIM.json"
    try:
        claim = contract_v1.validate_strategy_launch_claim(
            contract, _read_json(claim_path)
        )
    except contract_v1.ContractError:
        raise BootRecoveryError("boot_recovery_launch_claim_rejected") from None
    if _canonical(claim) != claim_path.read_bytes():
        raise BootRecoveryError("boot_recovery_launch_claim_rejected")
    sequence = strategy / "sequences" / str(claim["sequence_identity"])
    plan_path = sequence / "PLAN.json"
    try:
        plan = contract_v1.validate_plan(contract, _read_json(plan_path))
    except contract_v1.ContractError:
        raise BootRecoveryError("boot_recovery_plan_rejected") from None
    incident = strategy / "incidents" / str(plan["plan_digest"])
    if (
        Path(str(plan["execution"]["root"])) != root
        or claim["sequence_identity"] != plan["sequence_identity"]
        or claim["launch_claim_digest"]
        != _read_json(claim_path)["launch_claim_digest"]
        or claim["prestate_identity"] != plan["prestate_identity"]
        or claim["target_source_path"] != plan["execution"]["target_source_path"]
        or claim["target_inventory_digest"]
        != plan["execution"]["target_inventory_digest"]
        or claim["target_directories_digest"]
        != plan["execution"]["target_directories_digest"]
        or _read_json(incident / "PLAN.json") != plan
    ):
        raise BootRecoveryError("boot_recovery_plan_rejected")
    return claim, plan, strategy, incident


def _load_arm_bundle(
    contract: Mapping[str, object], root: Path
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
    Path,
    Path,
]:
    claim, plan, strategy, incident = _load_plan_bundle(contract, root)
    fixed = contract["production_adapter"]["fixed_paths"]
    arm_path = _rooted(root, fixed["boot_recovery_arm"])
    closure = _read_json(incident / "RECOVERY.CLOSURE.json")
    backup = _read_json(incident / "BACKUP" / "OPAQUE.json")
    arm = _read_json(arm_path)
    validate_closure(contract, plan, closure)
    validate_arm(contract, plan, claim, backup, closure, arm)
    return claim, plan, arm, closure, strategy, incident


def _guardian_accepted_exact(
    contract: Mapping[str, object],
    claim: Mapping[str, object],
    plan: Mapping[str, object],
    strategy: Path,
) -> bool:
    try:
        import p08_activation_guardian_manager_v1 as guardian_manager_v1

        guardian_root = strategy / "guardians" / str(claim["entry_nonce"])
        obligation = contract_v1.validate_guardian_obligation(
            contract, _read_json(guardian_root / "OBLIGATION.json")
        )
        if (
            obligation["launch_claim_digest"] != claim["launch_claim_digest"]
            or obligation["sequence_identity"] != plan["sequence_identity"]
            or obligation["entry_nonce"] != claim["entry_nonce"]
        ):
            return False
        terminal = guardian_manager_v1._load_exact_discharge(
            contract,
            obligation,
            guardian_root,
            materialize_strategy_terminal=True,
        )
        return terminal is not None and terminal["terminal_status"] == "accepted"
    except (BootRecoveryError, contract_v1.ContractError, OSError):
        return False


def _entry_result(
    contract: Mapping[str, object],
    *,
    plan_digest: str | None,
    boot_identity_digest: str,
    state: str,
    product_start_authorized: bool,
    convergence_count: int,
) -> dict[str, object]:
    if plan_digest is not None:
        _hex64(plan_digest, "boot_recovery_entry_rejected")
    _hex64(boot_identity_digest, "boot_recovery_entry_rejected")
    body = {
        "schema": contract_v1.BOOT_RECOVERY_ENTRY_SCHEMA,
        "architecture": contract_v1.ARCHITECTURE,
        "contract_digest": contract["contract_digest"],
        "plan_digest": plan_digest,
        "boot_identity_digest": boot_identity_digest,
        "state": state,
        "product_start_authorized": product_start_authorized,
        "convergence_count": convergence_count,
        "forward_action_replayed": False,
        "acceptance_replayed": False,
        "raw_content_included": False,
    }
    return {**body, "entry_digest": _digest(body)}


def execute_boot_recovery(
    contract: Mapping[str, object],
    *,
    activation_root: Path,
    boot_identity_digest: str,
    monotonic_start_ns: int,
    manager_invocation_id: str = "0" * 32,
    manager_restart_count: int = 0,
    monotonic_clock: Callable[[], int] | None = None,
) -> dict[str, object]:
    """Run the one-way boot gate without replaying the forward action."""
    _hex64(boot_identity_digest, "boot_recovery_boot_identity_rejected")
    _hex32(manager_invocation_id, "boot_recovery_manager_identity_rejected")
    if manager_restart_count not in {0, 1}:
        raise BootRecoveryError("boot_recovery_manager_identity_rejected")
    recovery = boot_recovery_contract(contract)
    clock = monotonic_clock or (lambda: monotonic_start_ns)

    def require_deadline(deadline_ns: int) -> None:
        observed = clock()
        if (
            not isinstance(observed, int)
            or isinstance(observed, bool)
            or observed < 1
            or observed > deadline_ns
        ):
            raise BootRecoveryError("boot_recovery_deadline_exceeded")

    fixed = contract["production_adapter"]["fixed_paths"]
    arm_path = _rooted(activation_root, fixed["boot_recovery_arm"])
    disarm_path = _rooted(activation_root, fixed["boot_recovery_disarm"])
    if not arm_path.exists() and not arm_path.is_symlink():
        if disarm_path.exists() or disarm_path.is_symlink():
            raise BootRecoveryError("boot_recovery_disarm_without_arm_rejected")
        _, plan, _, _ = _load_plan_bundle(contract, activation_root)
        import p08_activation_production_adapter_v1 as adapter_v1

        # Same-boot priming is an action-owned, bounded no-op: the isolated
        # recovery unit must start before ARM so its executable closure is
        # proven.  A boot-identity change (or any non-exact priming shape)
        # converts that durable obligation into same-PLAN convergence; the
        # forward action is never replayed.
        if adapter_v1._recovery_obligation_exists(contract, plan):
            if not adapter_v1._infrastructure_only_convergence_required(
                contract, plan
            ):
                raise BootRecoveryError(
                    "boot_recovery_infrastructure_authority_rejected"
                )
            obligation = adapter_v1._validate_recovery_obligation(
                contract,
                plan,
                adapter_v1._read_json(
                    adapter_v1._recovery_obligation_path(contract, plan)
                ),
            )
            if obligation["owner_boot_identity_digest"] == boot_identity_digest:
                adapter_v1._verify_boot_recovery_priming_closure(contract, plan)
                if not adapter_v1._boot_product_exact(
                    contract, plan, final_state="predecessor", allow_active=True
                ):
                    raise BootRecoveryError(
                        "boot_recovery_no_arm_prestate_rejected"
                    )
                return _entry_result(
                    contract,
                    plan_digest=plan["plan_digest"],
                    boot_identity_digest=boot_identity_digest,
                    state="no_arm_noop",
                    product_start_authorized=True,
                    convergence_count=0,
                )
            try:
                adapter_v1._converge_recovery_infrastructure(
                    contract,
                    plan,
                    current_unit_self_retirement=True,
                )
                adapter_v1._recover_recovery_infrastructure(contract, plan)
                adapter_v1._postflight_recovery_infrastructure(contract, plan)
            except Exception:
                return _entry_result(
                    contract,
                    plan_digest=plan["plan_digest"],
                    boot_identity_digest=boot_identity_digest,
                    state="blocked_convergence_failed",
                    product_start_authorized=False,
                    convergence_count=1,
                )
            return _entry_result(
                contract,
                plan_digest=plan["plan_digest"],
                boot_identity_digest=boot_identity_digest,
                state="converged_predecessor",
                product_start_authorized=True,
                convergence_count=1,
            )

        adapter_v1._verify_boot_recovery_priming_closure(contract, plan)
        if not adapter_v1._boot_product_exact(
            contract, plan, final_state="predecessor", allow_active=True
        ):
            raise BootRecoveryError("boot_recovery_no_arm_prestate_rejected")
        return _entry_result(
            contract,
            plan_digest=plan["plan_digest"],
            boot_identity_digest=boot_identity_digest,
            state="no_arm_noop",
            product_start_authorized=True,
            convergence_count=0,
        )
    claim, plan, arm, closure, strategy, _ = _load_arm_bundle(
        contract, activation_root
    )
    import p08_activation_production_adapter_v1 as adapter_v1

    adapter_v1._verify_boot_recovery_persistent_closure(
        contract, plan, closure=closure, current_boot=False
    )
    if disarm_path.exists() or disarm_path.is_symlink():
        disarm = _read_json(disarm_path)
        boot_root = _rooted(activation_root, fixed["boot_recovery_boots"])
        owner = _read_json(boot_root / str(disarm.get("boot_identity_digest")) / "OWNER.json")
        terminal = _read_json(boot_root / str(disarm.get("boot_identity_digest")) / "TERMINAL.json")
        validate_owner(contract, arm, owner)
        validate_terminal(contract, arm, owner, terminal)
        validate_disarm(contract, arm, terminal, disarm)
        final_state = "target" if terminal["state"] == "accepted_preserved" else "predecessor"
        if not adapter_v1._boot_product_exact(
            contract, plan, final_state=final_state, allow_active=False
        ):
            raise BootRecoveryError("boot_recovery_disarmed_product_rejected")
        return _entry_result(
            contract,
            plan_digest=plan["plan_digest"],
            boot_identity_digest=boot_identity_digest,
            state="disarmed_noop",
            product_start_authorized=True,
            convergence_count=int(terminal["convergence_count"]),
        )
    if boot_identity_digest == arm["arm_boot_identity_digest"]:
        raise BootRecoveryError("boot_recovery_same_boot_owner_active")
    boot_root = _rooted(activation_root, fixed["boot_recovery_boots"])
    if not boot_root.exists():
        boot_root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(boot_root.parent, 0o700)
        _private_directory(boot_root, create=True)
    else:
        _private_directory(boot_root)
    owner_root = boot_root / boot_identity_digest
    terminal: dict[str, object] | None = None
    if owner_root.exists() or owner_root.is_symlink():
        _private_directory(owner_root)
        owner = validate_owner(contract, arm, _read_json(owner_root / "OWNER.json"))
        terminal_path = owner_root / "TERMINAL.json"
        if terminal_path.exists() or terminal_path.is_symlink():
            terminal = validate_terminal(
                contract, arm, owner, _read_json(terminal_path)
            )
        else:
            if (
                manager_restart_count != 1
                or manager_invocation_id == owner["initial_invocation_id"]
            ):
                raise BootRecoveryError("boot_recovery_concurrent_owner_rejected")
            reentry_path = owner_root / "REENTRY.json"
            if reentry_path.exists() or reentry_path.is_symlink():
                raise BootRecoveryError("boot_recovery_generation_exhausted")
            reentry = build_reentry(
                contract,
                arm,
                owner,
                invocation_id=manager_invocation_id,
            )
            _persist_json(reentry_path, reentry)
    else:
        if manager_restart_count != 0:
            raise BootRecoveryError("boot_recovery_manager_identity_rejected")
        _private_directory(owner_root, create=True)
        owner = build_owner(
            contract,
            arm,
            boot_identity_digest=boot_identity_digest,
            monotonic_start_ns=monotonic_start_ns,
            initial_invocation_id=manager_invocation_id,
        )
        _persist_json(owner_root / "OWNER.json", owner)
    require_deadline(int(owner["monotonic_deadline_ns"]))
    if terminal is None:
        convergence_required = False
        try:
            accepted = _guardian_accepted_exact(contract, claim, plan, strategy)
            if accepted and adapter_v1._boot_product_exact(
                contract, plan, final_state="target", allow_active=False
            ):
                terminal = build_terminal(
                    contract,
                    arm,
                    owner,
                    state="accepted_preserved",
                    convergence_count=0,
                    forward_history_restored=False,
                )
            elif adapter_v1._boot_product_exact(
                contract, plan, final_state="predecessor", allow_active=False
            ):
                terminal = build_terminal(
                    contract,
                    arm,
                    owner,
                    state="predecessor_already_exact",
                    convergence_count=0,
                    forward_history_restored=False,
                )
            else:
                convergence_required = True
        except Exception:
            # Once exact ARM/backup/closure and per-boot ownership reopen, an
            # indeterminate product classification is never allowed to bypass
            # the same-PLAN convergence path.
            convergence_required = True
        if convergence_required:
            try:
                adapter_v1._boot_converge(
                    contract,
                    plan,
                    monotonic_deadline_ns=int(owner["monotonic_deadline_ns"]),
                    monotonic_clock=clock,
                )
                converged = adapter_v1._boot_product_exact(
                    contract, plan, final_state="predecessor", allow_active=False
                )
            except Exception:
                converged = False
            terminal = build_terminal(
                contract,
                arm,
                owner,
                state=(
                    "converged_predecessor"
                    if converged
                    else "blocked_convergence_failed"
                ),
                convergence_count=1,
                forward_history_restored=False,
            )
        require_deadline(int(owner["monotonic_deadline_ns"]))
        _persist_json(owner_root / "TERMINAL.json", terminal)
    assert terminal is not None
    if terminal["product_start_authorized"] is not True:
        return _entry_result(
            contract,
            plan_digest=plan["plan_digest"],
            boot_identity_digest=boot_identity_digest,
            state=str(terminal["state"]),
            product_start_authorized=False,
            convergence_count=int(terminal["convergence_count"]),
        )
    disarm = build_disarm(contract, arm, terminal, owner)
    if disarm_path.exists() or disarm_path.is_symlink():
        observed = _read_json(disarm_path)
        validate_disarm(contract, arm, terminal, observed)
        if observed != disarm:
            raise BootRecoveryError("boot_recovery_disarm_rejected")
    else:
        _persist_json(disarm_path, disarm)
    return _entry_result(
        contract,
        plan_digest=plan["plan_digest"],
        boot_identity_digest=boot_identity_digest,
        state=str(terminal["state"]),
        product_start_authorized=True,
        convergence_count=int(terminal["convergence_count"]),
    )


def _no_new_privileges() -> bool:
    try:
        raw = Path("/proc/self/status").read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError):
        return False
    values = [line.split(":", 1)[1].strip() for line in raw.splitlines() if line.startswith("NoNewPrivs:")]
    return values == ["1"]


def _self_cgroup() -> str | None:
    try:
        lines = Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    if len(lines) != 1 or not lines[0].startswith("0::/"):
        return None
    return lines[0][3:]


def _verify_runtime_entry(
    contract: Mapping[str, object], plan: Mapping[str, object], contract_path: Path
) -> None:
    import p08_activation_guardian_manager_v1 as guardian_manager_v1
    import p08_activation_launcher_v1 as launcher_v1
    import p08_activation_production_adapter_v1 as adapter_v1
    import p08_activation_supervisor_v1 as supervisor_v1

    recovery = boot_recovery_contract(contract)
    runtime = Path(str(recovery["runtime_root"]))
    expected_environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(runtime / "scripts") + ":" + str(runtime / "src"),
    }
    identity = recovery["runtime_identity"]
    expected_argv = [
        str(runtime / contract_v1.BOOT_RECOVERY_PATH),
        "--activation-contract",
        str(contract_path),
        "--activation-root",
        "/",
    ]
    if (
        contract_path != runtime / "contracts/P08_ACTIVATION_CONTRACT.json"
        or Path.cwd() != runtime
        or dict(os.environ) != expected_environment
        or os.getuid() != identity["uid"]
        or os.getgid() != identity["gid"]
        or sorted(os.getgroups()) != identity["groups"]
        or _no_new_privileges() is not identity["no_new_privileges"]
        or sys.argv != expected_argv
        or _self_cgroup() != recovery["unit_runtime"]["control_group"]
    ):
        raise BootRecoveryError("boot_recovery_entry_identity_rejected")
    modules = {
        contract_v1.BOOT_RECOVERY_PATH: sys.modules[__name__],
        "scripts/p08_activation_contract_v1.py": contract_v1,
        contract_v1.SUPERVISOR_GUARDIAN_MANAGER_PATH: guardian_manager_v1,
        "scripts/p08_activation_launcher_v1.py": launcher_v1,
        contract_v1.PRODUCTION_ADAPTER_PATH: adapter_v1,
        "scripts/p08_activation_supervisor_v1.py": supervisor_v1,
    }
    try:
        launcher_v1.verify_loaded_runtime_inventory(
            contract,
            runtime,
            list(plan["execution"]["target_inventory"]),
            list(plan["execution"]["target_directories"]),
            modules,
        )
        interpreter = contract["interpreter"]
        adapter_v1._verify_regular_authority(
            Path(str(interpreter["resolved_path"])), interpreter
        )
        if os.readlink("/proc/self/exe") != interpreter["resolved_path"]:
            raise BootRecoveryError("boot_recovery_interpreter_rejected")
    except (OSError, contract_v1.ContractError, launcher_v1.LauncherError, adapter_v1.AdapterError):
        raise BootRecoveryError("boot_recovery_entry_identity_rejected") from None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--activation-contract", required=True)
    parser.add_argument("--activation-root", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    contract: dict[str, object] | None = None
    try:
        arguments = _parser().parse_args(argv)
        root = Path(arguments.activation_root)
        contract_path = Path(arguments.activation_contract)
        contract = _load_contract(contract_path)
        _, plan, _, _ = _load_plan_bundle(contract, root)
        _verify_runtime_entry(contract, plan, contract_path)
        import p08_activation_launcher_v1 as launcher_v1
        import p08_activation_production_adapter_v1 as adapter_v1

        manager = adapter_v1._recovery_unit_entry_state(contract, plan)

        result = execute_boot_recovery(
            contract,
            activation_root=root,
            boot_identity_digest=launcher_v1.boot_identity_digest(),
            monotonic_start_ns=time.monotonic_ns(),
            manager_invocation_id=str(manager["invocation_id"]),
            manager_restart_count=int(manager["n_restarts"]),
            monotonic_clock=time.monotonic_ns,
        )
        sys.stdout.buffer.write(_canonical(result))
        return 0 if result["product_start_authorized"] is True else 2
    except (BaseException,):
        digest = (
            str(contract["contract_digest"])
            if isinstance(contract, Mapping)
            else "0" * 64
        )
        body = {
            "schema": contract_v1.BOOT_RECOVERY_ENTRY_SCHEMA,
            "architecture": contract_v1.ARCHITECTURE,
            "contract_digest": digest,
            "plan_digest": None,
            "boot_identity_digest": "0" * 64,
            "state": "blocked_invalid_authority",
            "product_start_authorized": False,
            "convergence_count": 0,
            "forward_action_replayed": False,
            "acceptance_replayed": False,
            "raw_content_included": False,
        }
        result = {**body, "entry_digest": _digest(body)}
        sys.stdout.buffer.write(_canonical(result))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
