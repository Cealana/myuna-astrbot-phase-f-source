#!/usr/bin/env python3
"""Synthetic-only subprocess child for source-owned launcher verification.

The child emits canonical synthetic results for every manifest role without
performing product mutations.  It is packaged to test the exact installed-
target import and invocation closure; it is not a production action backend.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import p08_activation_contract_v1 as contract_v1
import p08_activation_launcher_v1 as launcher_v1


def _read_json(path: Path, rejection: str) -> dict[str, object]:
    try:
        raw = path.read_bytes()
        if len(raw) < 2 or len(raw) > 1_048_576 or not raw.endswith(b"\n"):
            raise ValueError
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        raise RuntimeError(rejection) from None
    if not isinstance(value, dict):
        raise RuntimeError(rejection)
    return value


def _payload(role: str, plan: dict[str, object]) -> dict[str, object]:
    if role == "construct":
        return {"contract_verified": True}
    if role in {"prepare", "formal1", "formal2"}:
        return {
            "metadata_only": True,
            "opaque_content_read": False,
            "persistent_mutation": False,
        }
    if role == "exact_two":
        return {
            "formal_calls": 2,
            "byte_identical": True,
            "semantic_identical": True,
        }
    if role == "drift":
        return {"exact": True, "persistent_mutation": False}
    payloads = {
        "claim": {"incident_owned": True, "max_actions": 1},
        "backup": {"action_owned": True, "public_exact": True, "opaque_exact": True},
        "stage": {"inventory_exact": True, "non_overwriting": True},
        "recovery_install": {
            "runtime_exact": True,
            "unit_exact": True,
            "enablement_exact": True,
            "ordering_exact": True,
            "product_gate_exact": True,
        },
        "recovery_arm": {
            "arm_exact": True,
            "action_backup_bound": True,
            "hazardous_mutation_started": False,
        },
        "stop_socket": {
            "service_cascade_stopped": True,
            "socket_stopped": True,
        },
        "stop_service": {
            "dependency_state_exact": True,
            "service_stopped": True,
        },
        "install": {"installed_inventory_exact": True},
        "select": {
            "selector_exact": True,
            "environment_exact": True,
            "units_exact": True,
        },
        "start_service": {
            "service_started": True,
            "socket_dependency_started": True,
        },
        "start_socket": {
            "dependency_state_exact": True,
            "socket_started": True,
        },
        "continuity_assessment": {
            "continuity_state": "no_transition_required",
            "transition_required": False,
            "provider_state_effect": "none",
        },
        "continuity_transition": {
            "continuity_state": "transition_committed",
            "forward_state_possible": True,
            "provider_state_effect": "committed",
        },
        "continuity_reconcile": {
            "continuity_state": "reconciled_not_committed",
            "forward_state_possible": False,
            "provider_state_effect": "not_committed",
        },
        "accept_status": {
            "accepted": True,
            "nonce_echo_exact": True,
            "source_bound": True,
        },
        "converge": {
            "code_public_predecessor": True,
            "trusted_time_history_restored": False,
            "state_restore_scope": "p08_state_and_public",
        },
        "recover": {"converged": True, "orphan_count": 0},
        "postflight": {
            "selected_identity": plan["target_identity"],
            "stable": True,
            "state_preserved": True,
        },
    }
    try:
        return payloads[role]
    except KeyError:
        raise RuntimeError("fixture_role_rejected") from None


def build_fixture_result(
    contract: dict[str, object],
    plan: dict[str, object],
    *,
    role: str,
    call_index: int,
) -> dict[str, object]:
    return contract_v1.build_result(
        contract,
        plan,
        role=role,
        role_call=call_index,
        status="ready" if role in contract_v1.READINESS_ROLES else "success",
        result_class=contract["roles"][role]["success_result_class"],
        payload=_payload(role, plan),
        persistent_mutation=role
        in {
            "stop_socket",
            "stop_service",
            "install",
            "select",
            "start_service",
            "start_socket",
            "continuity_transition",
            "converge",
            "recover",
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--activation-contract", type=Path, required=True)
    parser.add_argument("--activation-plan", type=Path, required=True)
    parser.add_argument("--activation-role", required=True)
    parser.add_argument("--activation-call-index", type=int, required=True)
    values = parser.parse_args()
    contract = contract_v1.validate_contract(
        _read_json(values.activation_contract, "fixture_contract_rejected")
    )
    plan = contract_v1.validate_plan(
        contract, _read_json(values.activation_plan, "fixture_plan_rejected")
    )
    role = values.activation_role
    if role not in contract["roles"]:
        raise RuntimeError("fixture_role_rejected")
    progress_fd_raw = os.environ.get("MYUNA_P08_ACTIVATION_PROGRESS_FD", "")
    if not progress_fd_raw.isdigit():
        raise RuntimeError("fixture_progress_rejected")
    progress_fd = int(progress_fd_raw)
    for index, phase in enumerate(contract["roles"][role]["progress_phases"], 1):
        os.write(
            progress_fd,
            launcher_v1.progress_bytes(
                contract, plan, role=role, phase=phase, phase_index=index
            ),
        )
    result = build_fixture_result(
        contract,
        plan,
        role=role,
        call_index=values.activation_call_index,
    )
    os.write(1, contract_v1.canonical_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
