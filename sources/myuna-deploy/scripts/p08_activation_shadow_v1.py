#!/usr/bin/env python3
"""Production-equivalent, synthetic-only full-chain shadow for P08 activation."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

import p08_activation_contract_v1 as contract_v1
from p08_activation_engine_v1 import ActivationEngine, EngineError, TerminalStatus


@dataclass
class SyntheticWorld:
    predecessor_identity: str
    target_identity: str
    selected_identity: str
    state_bytes: bytes = b"SYNTHETIC_P08_OPAQUE_STATE_V1"
    state_backup: bytes | None = None
    public_backup_exact: bool = False
    incident_owned: bool = False
    staged: bool = False
    installed: bool = False
    service_running: bool = True
    socket_running: bool = True
    trusted_time_history: list[str] = field(default_factory=lambda: ["anchor-v1"])
    actions_consumed: int = 0
    orphan_count: int = 0


@dataclass(frozen=True)
class ShadowScenario:
    continuity: str = "no_transition_required"
    fault_role: str | None = None
    fault_kind: str = "rejected"
    convergence_fault: str | None = None
    public_modes_exact: bool = True
    inventory_exact: bool = True
    identity_exact: bool = True


def _result(
    engine: ActivationEngine,
    role: str,
    payload: Mapping[str, object],
    *,
    mutation_scope: str = "none",
) -> dict[str, object]:
    role_call = len(engine.results.get(role, [])) + 1
    status = "ready" if role in contract_v1.READINESS_ROLES else "success"
    return contract_v1.build_result(
        engine.contract,
        engine.plan,
        role=role,
        role_call=role_call,
        status=status,
        result_class=str(engine.contract["roles"][role]["success_result_class"]),
        payload=payload,
        persistent_mutation=mutation_scope != "none",
        mutation_scope=mutation_scope,
    )


def _payload(
    engine: ActivationEngine,
    world: SyntheticWorld,
    scenario: ShadowScenario,
    role: str,
) -> dict[str, object]:
    if role == "construct":
        return {"contract_verified": scenario.identity_exact}
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
        return {"exact": scenario.identity_exact, "persistent_mutation": False}
    if role == "claim":
        return {"incident_owned": True, "max_actions": 1}
    if role == "backup":
        return {
            "action_owned": world.incident_owned,
            "public_exact": scenario.public_modes_exact,
            "opaque_exact": world.state_backup == world.state_bytes,
        }
    if role == "stage":
        return {
            "inventory_exact": scenario.inventory_exact,
            "non_overwriting": not world.installed,
        }
    if role == "recovery_install":
        return {
            "runtime_exact": True,
            "unit_exact": True,
            "enablement_exact": True,
            "ordering_exact": True,
            "product_gate_exact": True,
        }
    if role == "recovery_arm":
        return {
            "arm_exact": True,
            "action_backup_bound": True,
            "hazardous_mutation_started": False,
        }
    if role == "stop_socket":
        return {
            "socket_stopped": not world.socket_running,
            "service_cascade_stopped": not world.service_running,
        }
    if role == "stop_service":
        return {
            "service_stopped": not world.service_running,
            "dependency_state_exact": not world.socket_running,
        }
    if role == "install":
        return {"installed_inventory_exact": world.installed and scenario.inventory_exact}
    if role == "select":
        return {
            "selector_exact": world.selected_identity == world.target_identity,
            "environment_exact": True,
            "units_exact": True,
        }
    if role == "start_service":
        return {
            "service_started": world.service_running,
            "socket_dependency_started": world.socket_running,
        }
    if role == "start_socket":
        return {
            "socket_started": world.socket_running,
            "dependency_state_exact": world.service_running,
        }
    if role == "continuity_assessment":
        transition_required = scenario.continuity != "no_transition_required"
        return {
            "continuity_state": (
                "transition_required" if transition_required else "no_transition_required"
            ),
            "transition_required": transition_required,
            "provider_state_effect": "none",
        }
    if role == "continuity_transition":
        ambiguous = scenario.continuity.startswith("ambiguous_")
        return {
            "continuity_state": (
                "transition_ambiguous" if ambiguous else "transition_committed"
            ),
            "forward_state_possible": True,
            "provider_state_effect": "ambiguous" if ambiguous else "committed",
        }
    if role == "continuity_reconcile":
        committed = scenario.continuity == "ambiguous_committed"
        return {
            "continuity_state": (
                "reconciled_committed" if committed else "reconciled_not_committed"
            ),
            "forward_state_possible": committed,
            "provider_state_effect": "committed" if committed else "not_committed",
        }
    if role == "accept_status":
        return {"accepted": True, "nonce_echo_exact": True, "source_bound": True}
    if role == "converge":
        return {
            "code_public_predecessor": world.selected_identity
            == world.predecessor_identity,
            "trusted_time_history_restored": False,
            "state_restore_scope": engine.convergence_scope
            or (
                "code_public_only"
                if engine.forward_state_possible
                else "p08_state_and_public"
            ),
        }
    if role == "recover":
        return {"converged": True, "orphan_count": world.orphan_count}
    if role == "postflight":
        expected = (
            world.predecessor_identity
            if engine.convergence_required
            else world.target_identity
        )
        return {
            "selected_identity": expected,
            "stable": world.service_running and world.socket_running,
            "state_preserved": (
                world.state_bytes == world.state_backup
                if engine.convergence_required and not engine.transition_committed
                else True
            ),
        }
    raise EngineError("shadow_role_rejected")


def _before_role(
    world: SyntheticWorld,
    engine: ActivationEngine,
    scenario: ShadowScenario,
    role: str,
) -> None:
    if role == "claim":
        if world.incident_owned or world.actions_consumed != 0:
            raise EngineError("shadow_claim_rejected")
        world.incident_owned = True
        world.actions_consumed = 1
    elif role == "backup":
        if not world.incident_owned:
            raise EngineError("shadow_backup_without_claim")
        world.state_backup = bytes(world.state_bytes)
        world.public_backup_exact = scenario.public_modes_exact
    elif role == "stage":
        world.staged = scenario.inventory_exact
    elif role == "stop_socket":
        world.socket_running = False
        world.service_running = False
    elif role == "stop_service":
        if world.socket_running:
            raise EngineError("shadow_stop_order_rejected")
        world.service_running = False
    elif role == "install":
        world.installed = scenario.inventory_exact and world.staged
    elif role == "select":
        world.selected_identity = world.target_identity
    elif role == "start_service":
        world.socket_running = True
        world.service_running = True
    elif role == "start_socket":
        if not world.service_running:
            raise EngineError("shadow_start_order_rejected")
        world.socket_running = True
    elif role == "continuity_transition":
        if scenario.continuity == "committed":
            world.trusted_time_history.append("forward-transition-v1")
        elif scenario.continuity == "ambiguous_committed":
            world.trusted_time_history.append("forward-transition-v1")
    elif role == "converge":
        if engine.convergence_scope == "recovery_infrastructure_only":
            return
        world.selected_identity = world.predecessor_identity
        world.service_running = True
        world.socket_running = True
        if not engine.forward_state_possible:
            if world.state_backup is None:
                raise EngineError("shadow_restore_authority_rejected")
            world.state_bytes = bytes(world.state_backup)
    elif role == "recover":
        world.orphan_count = 0


def run_shadow(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    scenario: ShadowScenario = ShadowScenario(),
) -> dict[str, object]:
    validated_plan = contract_v1.validate_plan(contract, plan)
    world = SyntheticWorld(
        predecessor_identity=str(validated_plan["predecessor_identity"]),
        target_identity=str(validated_plan["target_identity"]),
        selected_identity=str(validated_plan["predecessor_identity"]),
    )
    engine = ActivationEngine(contract, validated_plan)
    failure_applied = False
    convergence_failure_applied = False
    while engine.terminal_status is TerminalStatus.RUNNING:
        next_roles = engine.next_roles
        if len(next_roles) != 1:
            raise EngineError("shadow_phase_ambiguity")
        role = next(iter(next_roles))
        primary_failure = scenario.fault_role == role and not failure_applied
        convergence_failure = (
            scenario.convergence_fault == role and not convergence_failure_applied
        )
        if primary_failure or convergence_failure:
            if primary_failure:
                failure_applied = True
            if convergence_failure:
                convergence_failure_applied = True
            engine.fail(
                role,
                result_class=(
                    "indeterminate"
                    if scenario.fault_kind in {"crash", "timeout", "indeterminate"}
                    else "rejected"
                ),
            )
            continue
        _before_role(world, engine, scenario, role)
        payload = _payload(engine, world, scenario, role)
        product_mutation = role in {
            "stop_socket",
            "stop_service",
            "install",
            "select",
            "start_service",
            "start_socket",
            "continuity_transition",
            "converge",
            "recover",
        }
        if role in {"recovery_install", "recovery_arm"}:
            mutation_scope = "recovery_infrastructure"
        elif role in {"converge", "recover"} and (
            engine.convergence_scope == "recovery_infrastructure_only"
        ):
            mutation_scope = "recovery_infrastructure"
        elif product_mutation:
            mutation_scope = "product"
        else:
            mutation_scope = "none"
        engine.apply(
            _result(engine, role, payload, mutation_scope=mutation_scope)
        )
    receipt = engine.receipt()
    body = {
        "schema": contract_v1.SHADOW_SCHEMA,
        "contract_digest": contract["contract_digest"],
        "plan_digest": validated_plan["plan_digest"],
        "terminal_status": receipt.terminal_status,
        "last_role": receipt.last_role,
        "action_claimed": receipt.action_claimed,
        "infrastructure_mutated": receipt.infrastructure_mutated,
        "mutation_scope": receipt.mutation_scope,
        "actions_consumed": world.actions_consumed,
        "selected_identity": world.selected_identity,
        "service_running": world.service_running,
        "socket_running": world.socket_running,
        "state_preserved": (
            world.state_backup is None or world.state_bytes == world.state_backup
        ),
        "transition_state": receipt.transition_state,
        "transition_committed": receipt.transition_committed,
        "forward_state_possible": receipt.forward_state_possible,
        "trusted_time_history_length": len(world.trusted_time_history),
        "trusted_time_history_restored": receipt.trusted_time_history_restored,
        "state_restore_scope": receipt.state_restore_scope,
        "role_counts": receipt.role_counts,
        "fault_role": scenario.fault_role,
        "fault_kind": scenario.fault_kind if scenario.fault_role else None,
        "convergence_fault": scenario.convergence_fault,
        "raw_output_included": False,
        "production_mutation": False,
    }
    return {**body, "shadow_digest": contract_v1.digest_value(body)}
