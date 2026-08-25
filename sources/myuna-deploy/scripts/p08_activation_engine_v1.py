#!/usr/bin/env python3
"""Manifest-driven P08 activation state machine.

The engine contains no product-specific identity constants.  It consumes one
compiled activation contract and one canonical plan, and rejects any phase,
identity, continuity, mutation, or convergence decision that is not authorized
by those exact bytes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping

import p08_activation_contract_v1 as contract_v1


class EngineError(RuntimeError):
    pass


class TerminalStatus(str, Enum):
    RUNNING = "running"
    ACCEPTED = "accepted"
    CONVERGED_HARD_STOP = "converged_hard_stop"
    CONVERGENCE_FAILED_HARD_STOP = "convergence_failed_hard_stop"
    PREMUTATION_HARD_STOP = "premutation_hard_stop"


@dataclass(frozen=True)
class EngineReceipt:
    terminal_status: str
    last_role: str
    plan_digest: str
    action_claimed: bool
    product_mutated: bool
    infrastructure_mutated: bool
    mutation_scope: str
    transition_state: str | None
    transition_committed: bool
    forward_state_possible: bool
    state_restore_scope: str
    trusted_time_history_restored: bool
    role_counts: dict[str, int]


@dataclass
class ActivationEngine:
    contract: Mapping[str, object]
    plan: Mapping[str, object]
    current_role: str | None = None
    terminal_status: TerminalStatus = TerminalStatus.RUNNING
    action_claimed: bool = False
    product_mutated: bool = False
    infrastructure_mutated: bool = False
    convergence_scope: str | None = None
    transition_state: str | None = None
    transition_committed: bool = False
    forward_state_possible: bool = False
    convergence_required: bool = False
    results: dict[str, list[dict[str, object]]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.contract = contract_v1.validate_contract(self.contract)
        self.plan = contract_v1.validate_plan(self.contract, self.plan)

    @property
    def plan_digest(self) -> str:
        return str(self.plan["plan_digest"])

    @property
    def next_roles(self) -> frozenset[str]:
        if self.terminal_status is not TerminalStatus.RUNNING:
            return frozenset()
        if self.current_role is None:
            return frozenset({"construct"})
        if self.convergence_required:
            if self.current_role == "converge":
                return frozenset({"recover"})
            if self.current_role == "recover":
                return frozenset({"postflight"})
            return frozenset({"converge"})
        roles = contract_v1.allowed_successors(self.contract, self.current_role)
        if self.current_role == "continuity_assessment":
            if self.transition_state == "no_transition_required":
                return frozenset({"start_service"})
            if self.transition_state == "transition_required":
                return frozenset({"continuity_transition"})
        elif self.current_role == "continuity_transition":
            if self.transition_state == "transition_committed":
                return frozenset({"start_service"})
            if self.transition_state == "transition_ambiguous":
                return frozenset({"continuity_reconcile"})
        elif self.current_role == "continuity_reconcile":
            if self.transition_state == "reconciled_committed":
                return frozenset({"start_service"})
            if self.transition_state == "reconciled_not_committed":
                return frozenset({"converge"})
        return roles

    def _validate_common_success(self, role: str, result: Mapping[str, object]) -> None:
        if result["status"] not in {"ready", "success"}:
            raise EngineError("role_result_not_success")
        expected_class = self.contract["roles"][role]["success_result_class"]
        if result["result_class"] != expected_class:
            raise EngineError("role_result_class_rejected")
        if role in contract_v1.READINESS_ROLES and (
            result["persistent_mutation"] is not False
            or result["mutation_scope"] != "none"
        ):
            raise EngineError("readiness_mutation_rejected")

    def _validate_role_semantics(self, role: str, result: Mapping[str, object]) -> None:
        payload = result["payload"]
        self._validate_common_success(role, result)
        if role in {"prepare", "formal1", "formal2"}:
            if payload != {
                "metadata_only": True,
                "opaque_content_read": False,
                "persistent_mutation": False,
            }:
                raise EngineError("metadata_readiness_rejected")
        elif role == "exact_two":
            if payload != {
                "formal_calls": 2,
                "byte_identical": True,
                "semantic_identical": True,
            }:
                raise EngineError("exact_two_rejected")
            first = self.results.get("formal1", [])
            second = self.results.get("formal2", [])
            if len(first) != 1 or len(second) != 1:
                raise EngineError("exact_two_sequence_rejected")
            first_projection = {
                "status": first[0]["status"],
                "result_class": first[0]["result_class"],
                "persistent_mutation": first[0]["persistent_mutation"],
                "mutation_scope": first[0]["mutation_scope"],
                "payload": first[0]["payload"],
            }
            second_projection = {
                "status": second[0]["status"],
                "result_class": second[0]["result_class"],
                "persistent_mutation": second[0]["persistent_mutation"],
                "mutation_scope": second[0]["mutation_scope"],
                "payload": second[0]["payload"],
            }
            if contract_v1.canonical_bytes(first_projection) != contract_v1.canonical_bytes(
                second_projection
            ):
                raise EngineError("exact_two_projection_rejected")
        elif role == "drift":
            if payload != {"exact": True, "persistent_mutation": False}:
                raise EngineError("drift_rejected")
        elif role == "claim":
            if payload != {"incident_owned": True, "max_actions": 1}:
                raise EngineError("claim_rejected")
        elif role == "backup":
            if payload != {
                "action_owned": True,
                "public_exact": True,
                "opaque_exact": True,
            }:
                raise EngineError("backup_rejected")
        elif role == "stage":
            if payload != {"inventory_exact": True, "non_overwriting": True}:
                raise EngineError("stage_rejected")
        elif role == "recovery_install":
            if payload != {
                "runtime_exact": True,
                "unit_exact": True,
                "enablement_exact": True,
                "ordering_exact": True,
                "product_gate_exact": True,
            }:
                raise EngineError("boot_recovery_install_rejected")
        elif role == "recovery_arm":
            if payload != {
                "arm_exact": True,
                "action_backup_bound": True,
                "hazardous_mutation_started": False,
            }:
                raise EngineError("boot_recovery_arm_rejected")
        elif role == "stop_socket" and payload != {
            "service_cascade_stopped": True,
            "socket_stopped": True,
        }:
            raise EngineError("stop_order_rejected")
        elif role == "stop_service" and payload != {
            "dependency_state_exact": True,
            "service_stopped": True,
        }:
            raise EngineError("stop_order_rejected")
        elif role == "install" and payload != {"installed_inventory_exact": True}:
            raise EngineError("install_rejected")
        elif role == "select":
            if payload != {
                "selector_exact": True,
                "environment_exact": True,
                "units_exact": True,
            }:
                raise EngineError("selection_rejected")
        elif role == "start_service" and payload != {
            "service_started": True,
            "socket_dependency_started": True,
        }:
            raise EngineError("start_order_rejected")
        elif role == "start_socket" and payload != {
            "dependency_state_exact": True,
            "socket_started": True,
        }:
            raise EngineError("start_order_rejected")
        elif role == "continuity_assessment":
            if (
                payload["continuity_state"]
                not in {"no_transition_required", "transition_required"}
                or payload["provider_state_effect"] != "none"
                or payload["transition_required"]
                is not (payload["continuity_state"] == "transition_required")
            ):
                raise EngineError("continuity_assessment_rejected")
        elif role == "continuity_transition":
            if (
                payload["continuity_state"]
                not in {"transition_committed", "transition_ambiguous"}
                or payload["forward_state_possible"] is not True
                or payload["provider_state_effect"] not in {"committed", "ambiguous"}
                or (
                    payload["continuity_state"] == "transition_committed"
                    and payload["provider_state_effect"] != "committed"
                )
                or (
                    payload["continuity_state"] == "transition_ambiguous"
                    and payload["provider_state_effect"] != "ambiguous"
                )
            ):
                raise EngineError("continuity_transition_rejected")
        elif role == "continuity_reconcile":
            if (
                self.transition_state != "transition_ambiguous"
                or payload["continuity_state"]
                not in {"reconciled_committed", "reconciled_not_committed"}
                or payload["provider_state_effect"]
                not in {"committed", "not_committed"}
                or payload["forward_state_possible"]
                is not (payload["continuity_state"] == "reconciled_committed")
                or (
                    payload["continuity_state"] == "reconciled_committed"
                    and payload["provider_state_effect"] != "committed"
                )
                or (
                    payload["continuity_state"] == "reconciled_not_committed"
                    and payload["provider_state_effect"] != "not_committed"
                )
            ):
                raise EngineError("continuity_reconcile_rejected")
        elif role == "accept_status":
            if payload != {
                "accepted": True,
                "nonce_echo_exact": True,
                "source_bound": True,
            }:
                raise EngineError("acceptance_rejected")
        elif role == "converge":
            expected_scope = self.convergence_scope or (
                "code_public_only"
                if self.forward_state_possible
                else "p08_state_and_public"
            )
            if payload != {
                "code_public_predecessor": True,
                "trusted_time_history_restored": False,
                "state_restore_scope": expected_scope,
            }:
                raise EngineError("convergence_semantics_rejected")
        elif role == "recover":
            if payload != {"converged": True, "orphan_count": 0}:
                raise EngineError("recovery_rejected")
        elif role == "postflight":
            expected = (
                self.plan["predecessor_identity"]
                if self.convergence_required
                else self.plan["target_identity"]
            )
            if payload != {
                "selected_identity": expected,
                "stable": True,
                "state_preserved": True,
            }:
                raise EngineError("postflight_rejected")

    def apply(self, result: Mapping[str, object]) -> None:
        if self.terminal_status is not TerminalStatus.RUNNING:
            raise EngineError("engine_terminal")
        role = result.get("role") if isinstance(result, Mapping) else None
        if not isinstance(role, str) or role not in self.next_roles:
            raise EngineError("phase_order_rejected")
        role_call = len(self.results.get(role, [])) + 1
        try:
            validated = contract_v1.validate_result(
                self.contract,
                self.plan,
                result,
                expected_role=role,
                expected_call=role_call,
            )
        except contract_v1.ContractError as exc:
            raise EngineError("role_result_rejected") from exc

        if validated["status"] not in {"ready", "success"}:
            self.results.setdefault(role, []).append(validated)
            self.current_role = role
            if validated["persistent_mutation"]:
                if not self.action_claimed:
                    raise EngineError("mutation_without_claim_rejected")
                scope = str(validated["mutation_scope"])
                if scope in {"product", "recovery_infrastructure_and_product"}:
                    self.product_mutated = True
                if scope in {
                    "recovery_infrastructure",
                    "recovery_infrastructure_and_product",
                }:
                    self.infrastructure_mutated = True
            if role in {"continuity_transition", "continuity_reconcile"}:
                possible = validated["payload"].get("forward_state_possible")
                if not isinstance(possible, bool):
                    raise EngineError("continuity_failure_projection_rejected")
                self.forward_state_possible = possible
                if role == "continuity_transition" and possible:
                    self.transition_state = "transition_ambiguous"
                    # A transition with an indeterminate commit boundary must
                    # first pass through the same-action read-only reconcile.
                    # Convergence is chosen only after reconcile establishes a
                    # committed/not-committed result or itself fails closed.
                    return
            if self.convergence_required and role in {
                "converge",
                "recover",
                "postflight",
            }:
                self.terminal_status = TerminalStatus.CONVERGENCE_FAILED_HARD_STOP
                return
            if (self.product_mutated or self.infrastructure_mutated) and contract_v1.failure_can_converge(
                self.contract, role
            ):
                if self.infrastructure_mutated and not self.product_mutated:
                    self.convergence_scope = "recovery_infrastructure_only"
                self.convergence_required = True
                return
            self.terminal_status = TerminalStatus.PREMUTATION_HARD_STOP
            return

        self._validate_role_semantics(role, validated)
        self.results.setdefault(role, []).append(validated)
        self.current_role = role

        if role == "claim":
            self.action_claimed = True
        if validated["persistent_mutation"]:
            if not self.action_claimed:
                raise EngineError("mutation_without_claim_rejected")
            scope = str(validated["mutation_scope"])
            if scope in {"product", "recovery_infrastructure_and_product"}:
                self.product_mutated = True
            if scope in {
                "recovery_infrastructure",
                "recovery_infrastructure_and_product",
            }:
                self.infrastructure_mutated = True
        if role in {"stop_socket", "stop_service", "install", "select", "start_service", "start_socket"}:
            if not self.action_claimed:
                raise EngineError("mutation_without_claim_rejected")
            self.product_mutated = True
        if role.startswith("continuity_"):
            self.transition_state = str(validated["payload"]["continuity_state"])
            if self.transition_state in {"transition_committed", "reconciled_committed"}:
                self.transition_committed = True
                self.forward_state_possible = True
            elif self.transition_state == "reconciled_not_committed":
                self.forward_state_possible = False
                self.convergence_required = True
        if role == "converge":
            if self.convergence_scope != "recovery_infrastructure_only":
                self.product_mutated = True
        elif role == "recover":
            self.product_mutated = False
            if self.convergence_scope == "recovery_infrastructure_only":
                self.infrastructure_mutated = False
        elif role == "postflight":
            if self.convergence_required:
                self.terminal_status = TerminalStatus.CONVERGED_HARD_STOP
            else:
                self.terminal_status = TerminalStatus.ACCEPTED

    def fail(
        self,
        role: str,
        *,
        result_class: str = "rejected",
        mutation_scope: str | None = None,
    ) -> None:
        if role not in self.next_roles:
            raise EngineError("phase_order_rejected")
        payload = {key: False for key in self.contract["roles"][role]["payload_keys"]}
        if role in {"continuity_transition", "continuity_reconcile"}:
            payload.update(
                {
                    "continuity_state": "transition_ambiguous",
                    "forward_state_possible": True,
                    "provider_state_effect": "ambiguous",
                }
            )
        if mutation_scope is not None:
            if mutation_scope not in contract_v1.MUTATION_SCOPES:
                raise EngineError("failure_mutation_scope_rejected")
            inferred_scope = mutation_scope
            inferred_mutation = mutation_scope != "none"
        else:
            inferred_mutation = (
                result_class != "rejected"
                and self.action_claimed
                and contract_v1.failure_can_converge(self.contract, role)
            )
            inferred_scope = (
                "recovery_infrastructure"
                if inferred_mutation and role in {"recovery_install", "recovery_arm"}
                else "product"
                if inferred_mutation
                else "none"
            )
        result = contract_v1.build_result(
            self.contract,
            self.plan,
            role=role,
            role_call=len(self.results.get(role, [])) + 1,
            status="rejected" if result_class == "rejected" else "indeterminate",
            result_class=result_class,
            payload=payload,
            persistent_mutation=inferred_mutation,
            mutation_scope=inferred_scope,
        )
        self.apply(result)

    def abort_for_recovery(self) -> None:
        """Stop forward progress after a supervisor interruption.

        This does not consume a not-yet-created role call.  A claimed action
        with a mutated product converges; a pre-mutation interruption closes
        without ceremonial rollback.  An ambiguous transition must first use
        its one read-only reconcile role.
        """
        if self.terminal_status is not TerminalStatus.RUNNING:
            raise EngineError("engine_terminal")
        if self.transition_state == "transition_ambiguous":
            # A completed read-only reconcile call may itself fail closed.  In
            # that case the engine has already consumed the one reconcile and
            # must conservatively retain forward state while converging only
            # code/public selection; it must not demand or replay reconcile.
            if self.convergence_required:
                return
            if self.next_roles != frozenset({"continuity_reconcile"}):
                raise EngineError("recovery_reconcile_rejected")
            return
        # Once the product has been mutated, the installed recovery gate is
        # part of the safety substrate for the ordinary product convergence.
        # It must not be removed as though this were an infrastructure-only
        # pre-action failure.  Infrastructure-only convergence is reserved for
        # failures before the first product mutation.
        if self.action_claimed and self.product_mutated:
            self.convergence_scope = None
            self.convergence_required = True
            return
        if self.action_claimed and self.infrastructure_mutated:
            self.convergence_scope = "recovery_infrastructure_only"
            self.convergence_required = True
        else:
            self.terminal_status = TerminalStatus.PREMUTATION_HARD_STOP

    def require_guardian_convergence(self) -> None:
        """Convert an accepted-but-not-durably-discharged target into recovery.

        Acceptance is not guardian authority until the accepted terminal and
        discharge have both survived exact durable read-back.  The immutable
        accepted sequence receipt remains evidence; this state transition only
        authorizes the one bounded code/public convergence path.
        """
        if self.terminal_status is not TerminalStatus.ACCEPTED:
            raise EngineError("guardian_convergence_state_rejected")
        if not self.action_claimed or not self.product_mutated:
            raise EngineError("guardian_convergence_prestate_rejected")
        self.terminal_status = TerminalStatus.RUNNING
        self.convergence_scope = None
        self.convergence_required = True

    def bind_durable_infrastructure_obligation(self) -> None:
        """Import exact same-PLAN infrastructure mutation authority.

        A supervisor may be killed after the adapter durably creates the
        recovery obligation but before a role capture is persisted.  Recovery
        reconstructs role results from immutable evidence; the obligation is
        the independent source-owned truth that such an interrupted role is no
        longer pre-mutation.  This method never creates authority and is valid
        only after action ownership and before any product mutation.
        """
        if self.terminal_status is not TerminalStatus.RUNNING:
            raise EngineError("engine_terminal")
        if not self.action_claimed or self.product_mutated:
            raise EngineError("infrastructure_obligation_state_rejected")
        self.infrastructure_mutated = True
        self.convergence_scope = "recovery_infrastructure_only"

    def receipt(self) -> EngineReceipt:
        if self.current_role is None:
            raise EngineError("engine_not_started")
        if self.terminal_status is TerminalStatus.RUNNING:
            raise EngineError("engine_not_terminal")
        return EngineReceipt(
            terminal_status=self.terminal_status.value,
            last_role=self.current_role,
            plan_digest=self.plan_digest,
            action_claimed=self.action_claimed,
            product_mutated=self.product_mutated,
            infrastructure_mutated=self.infrastructure_mutated,
            mutation_scope=(
                "recovery_infrastructure_and_product"
                if self.infrastructure_mutated and self.product_mutated
                else "recovery_infrastructure"
                if self.infrastructure_mutated
                else "product"
                if self.product_mutated
                else "none"
            ),
            transition_state=self.transition_state,
            transition_committed=self.transition_committed,
            forward_state_possible=self.forward_state_possible,
            state_restore_scope=(
                self.convergence_scope
                or (
                    "code_public_only"
                    if self.forward_state_possible
                    else "p08_state_and_public"
                )
            ),
            trusted_time_history_restored=False,
            role_counts={role: len(rows) for role, rows in sorted(self.results.items())},
        )
