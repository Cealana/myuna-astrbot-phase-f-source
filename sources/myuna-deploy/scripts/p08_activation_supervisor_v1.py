#!/usr/bin/env python3
"""Source-owned plan construction and canonical role supervision.

This is the only production orchestration seam for the reset activation engine.
It creates a fresh plan from fixed public metadata, generates the sequence and
nonce internally, and drives every phase through the unified launcher.  It does
not grant live authority; callers still require a separately sequenced T2.
"""
from __future__ import annotations

import os
from pathlib import Path
import secrets
import signal
import stat
import sys
import time
from typing import Mapping, Sequence

import p08_activation_contract_v1 as contract_v1
from p08_activation_engine_v1 import ActivationEngine, EngineError, TerminalStatus
import p08_activation_launcher_v1 as launcher_v1
import p08_activation_production_adapter_v1 as adapter_v1


class SupervisorError(RuntimeError):
    pass


class SupervisorInterrupted(RuntimeError):
    pass


def _load_canonical(path: Path) -> dict[str, object]:
    try:
        value = adapter_v1._read_json(path)
    except adapter_v1.AdapterError:
        raise SupervisorError("supervisor_input_rejected") from None
    return value


def _load_private_evidence(path: Path) -> dict[str, object]:
    try:
        details = adapter_v1._regular(path, maximum=adapter_v1.MAX_JSON_BYTES)
    except adapter_v1.AdapterError:
        raise SupervisorError("private_evidence_rejected") from None
    if (
        stat.S_IMODE(details.st_mode) != 0o600
        or details.st_uid != os.getuid()
        or details.st_gid != os.getgid()
        or details.st_nlink != 1
    ):
        raise SupervisorError("private_evidence_rejected")
    return _load_canonical(path)


def _ensure_private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, exist_ok=False)
        os.chmod(path, 0o700)
        details = path.lstat()
    except OSError:
        raise SupervisorError("supervisor_namespace_rejected") from None
    if (
        not stat.S_ISDIR(details.st_mode)
        or stat.S_ISLNK(details.st_mode)
        or stat.S_IMODE(details.st_mode) != 0o700
        or details.st_uid != os.getuid()
        or details.st_gid != os.getgid()
    ):
        raise SupervisorError("supervisor_namespace_rejected")
    adapter_v1._fsync_directory(path.parent)


def prepare_plan(
    contract: Mapping[str, object],
    *,
    bootstrap_intent: Mapping[str, object],
    contract_path: Path,
    root: Path,
    backend: str,
    target_source_path: Path,
    acceptance_scope_digest: str,
) -> tuple[dict[str, object], Path]:
    validated = contract_v1.validate_contract(contract)
    try:
        validated_intent = launcher_v1.validate_supervisor_bootstrap_intent(
            validated, bootstrap_intent
        )
    except launcher_v1.LauncherError:
        raise SupervisorError("supervisor_bootstrap_rejected") from None
    if (
        validated_intent["contract_path"] != str(contract_path)
        or validated_intent["root"] != str(root)
        or validated_intent["backend"] != backend
        or validated_intent["target_source_path"] != str(target_source_path)
        or validated_intent["acceptance_scope_digest"] != acceptance_scope_digest
        or validated_intent["recover_plan"] is not None
    ):
        raise SupervisorError("supervisor_bootstrap_rejected")
    expected_contract_path = (
        target_source_path
        / str(contract_v1.release_manifest_binding(validated)["contract_path"])
    )
    if (
        not contract_path.is_absolute()
        or contract_path != expected_contract_path
        or adapter_v1._read_regular_bytes(contract_path)
        != contract_v1.canonical_bytes(validated)
    ):
        raise SupervisorError("contract_path_rejected")
    compatibility = validated["compatibility"].get("predecessor")
    if not isinstance(compatibility, Mapping):
        raise SupervisorError("predecessor_binding_rejected")
    predecessor = compatibility.get("release_identity")
    if not isinstance(predecessor, str) or contract_v1.HEX64.fullmatch(predecessor) is None:
        raise SupervisorError("predecessor_binding_rejected")
    sequence_identity = str(validated_intent["sequence_identity"])
    invocation_nonce = secrets.token_hex(32)
    try:
        plan = adapter_v1.construct_plan(
            validated,
            root=root,
            backend=backend,
            target_source_path=target_source_path,
            acceptance_scope_digest=acceptance_scope_digest,
            sequence_identity=sequence_identity,
            invocation_nonce=invocation_nonce,
            predecessor_identity=predecessor,
        )
        launcher_v1._verify_runtime_package(validated, plan)
        launcher_v1.verify_loaded_runtime_modules(
            validated,
            plan,
            {
                "scripts/p08_activation_contract_v1.py": contract_v1,
                "scripts/p08_activation_launcher_v1.py": launcher_v1,
                contract_v1.PRODUCTION_ADAPTER_PATH: adapter_v1,
                "scripts/p08_activation_supervisor_v1.py": sys.modules[__name__],
            },
        )
    except (
        adapter_v1.AdapterError,
        contract_v1.ContractError,
        launcher_v1.LauncherError,
    ):
        raise SupervisorError("plan_construction_rejected") from None
    sequence = adapter_v1.sequence_root(validated, plan)
    if sequence.exists() or sequence.is_symlink():
        raise SupervisorError("supervisor_namespace_rejected")
    strategy = adapter_v1._strategy_root(validated, plan["execution"])
    try:
        strategy.parent.mkdir(parents=True, exist_ok=True)
        parent_details = adapter_v1._directory(strategy.parent, owner=True)
        if stat.S_IMODE(parent_details.st_mode) & 0o022:
            raise adapter_v1.AdapterError("directory_identity_rejected")
    except (OSError, adapter_v1.AdapterError):
        raise SupervisorError("supervisor_namespace_rejected") from None
    if strategy.exists() or strategy.is_symlink():
        details = adapter_v1._directory(strategy, owner=True)
        if stat.S_IMODE(details.st_mode) != 0o700:
            raise SupervisorError("supervisor_namespace_rejected")
    else:
        _ensure_private_directory(strategy)
    sequences = strategy / "sequences"
    if sequences.exists() or sequences.is_symlink():
        details = adapter_v1._directory(sequences, owner=True)
        if stat.S_IMODE(details.st_mode) != 0o700:
            raise SupervisorError("supervisor_namespace_rejected")
    else:
        _ensure_private_directory(sequences)
    _ensure_private_directory(sequence)
    plan_path = sequence / "PLAN.json"
    try:
        adapter_v1._exclusive_write(
            plan_path,
            contract_v1.canonical_bytes(plan),
            mode=0o600,
        )
    except adapter_v1.AdapterError:
        raise SupervisorError("plan_persistence_rejected") from None
    return plan, plan_path


def _verify_bound_paths(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    contract_path: Path,
    plan_path: Path,
) -> None:
    expected_contract = (
        Path(str(plan["execution"]["target_source_path"]))
        / str(contract_v1.release_manifest_binding(contract)["contract_path"])
    )
    expected_plan = adapter_v1.sequence_root(contract, plan) / "PLAN.json"
    if (
        not contract_path.is_absolute()
        or not plan_path.is_absolute()
        or contract_path != expected_contract
        or plan_path != expected_plan
        or adapter_v1._read_regular_bytes(contract_path)
        != contract_v1.canonical_bytes(contract)
    ):
        raise SupervisorError("supervisor_path_binding_rejected")


def _terminal_receipt(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    engine: ActivationEngine,
    captures: Sequence[str],
    *,
    invocation_failures: int,
    capture_persistence_failures: int,
) -> dict[str, object]:
    receipt = engine.receipt()
    body = {
        "schema": contract_v1.SUPERVISOR_RECEIPT_SCHEMA,
        "architecture": contract_v1.ARCHITECTURE,
        "contract_digest": contract["contract_digest"],
        "plan_digest": plan["plan_digest"],
        "sequence_identity": plan["sequence_identity"],
        "terminal_status": receipt.terminal_status,
        "last_role": receipt.last_role,
        "action_claimed": receipt.action_claimed,
        "product_mutated": receipt.product_mutated,
        "infrastructure_mutated": receipt.infrastructure_mutated,
        "mutation_scope": receipt.mutation_scope,
        "transition_state": receipt.transition_state,
        "transition_committed": receipt.transition_committed,
        "forward_state_possible": receipt.forward_state_possible,
        "state_restore_scope": receipt.state_restore_scope,
        "trusted_time_history_restored": receipt.trusted_time_history_restored,
        "role_counts": receipt.role_counts,
        "capture_count": len(captures),
        "capture_chain_digest": contract_v1.digest_value(list(captures)),
        "invocation_failures": invocation_failures,
        "capture_persistence_failures": capture_persistence_failures,
        "raw_output_included": False,
    }
    return {**body, "receipt_digest": contract_v1.digest_value(body)}


def _intent_value(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    invocation: Mapping[str, object],
) -> dict[str, object]:
    body = {
        "schema": contract_v1.ROLE_INTENT_SCHEMA,
        "contract_digest": contract["contract_digest"],
        "plan_digest": plan["plan_digest"],
        "sequence_identity": plan["sequence_identity"],
        "invocation_digest": invocation["invocation_digest"],
        "invocation": dict(invocation),
        "role": invocation["role"],
        "call_index": invocation["call_index"],
        "child_creation_authorized": True,
        "raw_output_retained": False,
    }
    return {**body, "intent_digest": contract_v1.digest_value(body)}


def _validate_intent(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    value: Mapping[str, object],
    *,
    role: str,
    call_index: int,
) -> dict[str, object]:
    keys = {
        "call_index",
        "child_creation_authorized",
        "contract_digest",
        "intent_digest",
        "invocation_digest",
        "invocation",
        "plan_digest",
        "raw_output_retained",
        "role",
        "schema",
        "sequence_identity",
    }
    if not isinstance(value, Mapping) or set(value) != keys:
        raise SupervisorError("role_intent_rejected")
    body = {key: item for key, item in value.items() if key != "intent_digest"}
    if (
        value["schema"] != contract_v1.ROLE_INTENT_SCHEMA
        or value["contract_digest"] != contract["contract_digest"]
        or value["plan_digest"] != plan["plan_digest"]
        or value["sequence_identity"] != plan["sequence_identity"]
        or value["role"] != role
        or value["call_index"] != call_index
        or value["child_creation_authorized"] is not True
        or value["raw_output_retained"] is not False
        or not isinstance(value["invocation_digest"], str)
        or contract_v1.HEX64.fullmatch(str(value["invocation_digest"])) is None
        or not isinstance(value["invocation"], Mapping)
        or value["intent_digest"] != contract_v1.digest_value(body)
    ):
        raise SupervisorError("role_intent_rejected")
    try:
        invocation = launcher_v1.validate_invocation(contract, plan, value["invocation"])
    except launcher_v1.LauncherError:
        raise SupervisorError("role_intent_rejected") from None
    if invocation["invocation_digest"] != value["invocation_digest"]:
        raise SupervisorError("role_intent_rejected")
    return dict(value)


def _failure_value(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    role: str,
    call_index: int,
) -> dict[str, object]:
    body = {
        "schema": contract_v1.SUPERVISOR_FAILURE_SCHEMA,
        "contract_digest": contract["contract_digest"],
        "plan_digest": plan["plan_digest"],
        "sequence_identity": plan["sequence_identity"],
        "role": role,
        "call_index": call_index,
        "stage": "pre_child",
        "result_class": "indeterminate",
        "child_created": False,
        "raw_output_retained": False,
    }
    return {**body, "failure_digest": contract_v1.digest_value(body)}


def _validate_failure(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    value: Mapping[str, object],
    *,
    role: str,
    call_index: int,
) -> dict[str, object]:
    keys = {
        "call_index",
        "child_created",
        "contract_digest",
        "failure_digest",
        "plan_digest",
        "raw_output_retained",
        "result_class",
        "role",
        "schema",
        "sequence_identity",
        "stage",
    }
    if not isinstance(value, Mapping) or set(value) != keys:
        raise SupervisorError("supervisor_failure_rejected")
    body = {key: item for key, item in value.items() if key != "failure_digest"}
    if (
        value["schema"] != contract_v1.SUPERVISOR_FAILURE_SCHEMA
        or value["contract_digest"] != contract["contract_digest"]
        or value["plan_digest"] != plan["plan_digest"]
        or value["sequence_identity"] != plan["sequence_identity"]
        or value["role"] != role
        or value["call_index"] != call_index
        or value["stage"] != "pre_child"
        or value["result_class"] != "indeterminate"
        or value["child_created"] is not False
        or value["raw_output_retained"] is not False
        or value["failure_digest"] != contract_v1.digest_value(body)
    ):
        raise SupervisorError("supervisor_failure_rejected")
    return dict(value)


def _validate_terminal(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    value: Mapping[str, object],
) -> dict[str, object]:
    keys = {
        "action_claimed",
        "architecture",
        "capture_chain_digest",
        "capture_count",
        "capture_persistence_failures",
        "contract_digest",
        "forward_state_possible",
        "invocation_failures",
        "last_role",
        "plan_digest",
        "product_mutated",
        "infrastructure_mutated",
        "mutation_scope",
        "raw_output_included",
        "receipt_digest",
        "role_counts",
        "schema",
        "sequence_identity",
        "state_restore_scope",
        "terminal_status",
        "transition_committed",
        "transition_state",
        "trusted_time_history_restored",
    }
    if not isinstance(value, Mapping) or set(value) != keys:
        raise SupervisorError("terminal_receipt_rejected")
    body = {key: item for key, item in value.items() if key != "receipt_digest"}
    if (
        value["schema"] != contract_v1.SUPERVISOR_RECEIPT_SCHEMA
        or value["architecture"] != contract_v1.ARCHITECTURE
        or value["contract_digest"] != contract["contract_digest"]
        or value["plan_digest"] != plan["plan_digest"]
        or value["sequence_identity"] != plan["sequence_identity"]
        or value["raw_output_included"] is not False
        or value["trusted_time_history_restored"] is not False
        or value["mutation_scope"] not in contract_v1.MUTATION_SCOPES
        or value["product_mutated"] is not (
            value["mutation_scope"]
            in {"product", "recovery_infrastructure_and_product"}
        )
        or value["infrastructure_mutated"] is not (
            value["mutation_scope"]
            in {"recovery_infrastructure", "recovery_infrastructure_and_product"}
        )
        or value["receipt_digest"] != contract_v1.digest_value(body)
    ):
        raise SupervisorError("terminal_receipt_rejected")
    return dict(value)


def _role_paths(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    role: str,
    call_index: int,
) -> tuple[Path, Path]:
    root = adapter_v1.sequence_root(contract, plan)
    return (
        root / f"{role}-{call_index}.intent.json",
        root / f"{role}-{call_index}.json",
    )


def _failure_path(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    role: str,
    call_index: int,
) -> Path:
    return adapter_v1.sequence_root(contract, plan) / f"{role}-{call_index}.failure.json"


def _persist_prechild_failure(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    role: str,
    call_index: int,
) -> bool:
    value = _failure_value(
        contract,
        plan,
        role=role,
        call_index=call_index,
    )
    try:
        adapter_v1._exclusive_write(
            _failure_path(contract, plan, role, call_index),
            contract_v1.canonical_bytes(value),
            mode=0o600,
        )
    except adapter_v1.AdapterError:
        return False
    return True


def _synthetic_outer_supervisor_fault(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    role: str,
) -> None:
    """Terminate or corrupt the outer supervisor only after durable mutation evidence.

    The adapter child must finish and its capture must be persisted first.  This
    models loss of the supervisor process that the source-owned outer bootstrap
    is responsible for terminalizing; it is intentionally synthetic-only.
    """
    if plan["execution"]["backend"] != "synthetic" or role != "stop_socket":
        return
    control = adapter_v1._synthetic_control(contract, plan)
    if control["fault_role"] != role:
        return
    kind = control["fault_kind"]
    if kind in {
        "outer_kill_after_mutation",
        "outer_kill_after_mutation_recovery_rejected",
        "guardian_recovery_capture_persist_failed",
        "guardian_hardstop_terminal_persist_failed",
    }:
        os.kill(os.getpid(), 9)
    if kind == "outer_noncanonical_after_mutation":
        os.write(1, b'{"noncanonical":true}\n')
        os._exit(2)
    if kind == "outer_oversized_after_mutation":
        os.write(1, b"x" * (launcher_v1.MAX_STDOUT_BYTES + 1))
        os._exit(2)
    if kind in {
        "guardian_bootstrap_sigkill_after_mutation",
        "guardian_manager_sigkill_after_mutation",
    }:
        manager_pid = os.getppid()
        if kind == "guardian_manager_sigkill_after_mutation":
            target_pid = manager_pid
        else:
            try:
                raw = Path(f"/proc/{manager_pid}/stat").read_text(encoding="ascii")
                target_pid = int(raw[raw.rindex(")") + 2 :].split()[1])
            except (OSError, ValueError, IndexError):
                raise SupervisorError("synthetic_guardian_parent_rejected") from None
        if target_pid <= 1:
            raise SupervisorError("synthetic_guardian_parent_rejected")
        os.kill(target_pid, signal.SIGKILL)
        if kind == "guardian_bootstrap_sigkill_after_mutation":
            # Bootstrap identity is immutable provenance, not runtime liveness
            # authority.  The independent guardian continues the one action.
            return
        # The supervisor child must not continue product work after removing
        # its guardian manager.  It remains quiescent until the exact second
        # generation terminates it and owns same-plan convergence.
        while True:
            time.sleep(60.0)


def _fail_role_from_durable_evidence(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    engine: ActivationEngine,
    role: str,
    *,
    result_class: str,
) -> None:
    """Project a missing child result from exact same-PLAN mutation evidence.

    Recovery infrastructure has an independently durable obligation and an
    ordered journal.  Before the first ``stop_socket_started`` marker, those
    bytes prove that the product was not entered and that only infrastructure
    convergence is authorized.  This prevents a missing capture from
    conservatively inventing product mutation while still converging every
    persistent recovery write.  Once product entry is possible, the engine's
    ordinary conservative inference remains authoritative.
    """
    scope = None
    if (
        engine.action_claimed
        and not engine.product_mutated
        and adapter_v1._infrastructure_only_convergence_required(contract, plan)
    ):
        scope = "recovery_infrastructure"
    engine.fail(role, result_class=result_class, mutation_scope=scope)


def _run_one_role(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    engine: ActivationEngine,
    *,
    role: str,
    call_index: int,
    contract_path: Path,
    plan_path: Path,
    deploy_root: Path,
    captures: list[str],
    interrupt_after_intent_role: str | None = None,
    interrupt_after_role: str | None = None,
) -> tuple[int, int]:
    try:
        invocation = launcher_v1.build_invocation(
            contract,
            plan,
            role=role,
            call_index=call_index,
            contract_path=contract_path,
            plan_path=plan_path,
            deploy_root=deploy_root,
            entrypoint_relative=contract_v1.PRODUCTION_ADAPTER_PATH,
        )
    except (launcher_v1.LauncherError, OSError, RuntimeError):
        persisted = _persist_prechild_failure(
            contract,
            plan,
            role=role,
            call_index=call_index,
        )
        _fail_role_from_durable_evidence(
            contract, plan, engine, role, result_class="indeterminate"
        )
        return 1, 0 if persisted else 1
    intent_path, capture_path = _role_paths(contract, plan, role, call_index)
    intent = _intent_value(contract, plan, invocation)
    try:
        adapter_v1._exclusive_write(
            intent_path,
            contract_v1.canonical_bytes(intent),
            mode=0o600,
        )
    except adapter_v1.AdapterError:
        persisted = _persist_prechild_failure(
            contract,
            plan,
            role=role,
            call_index=call_index,
        )
        _fail_role_from_durable_evidence(
            contract, plan, engine, role, result_class="indeterminate"
        )
        return 1, 0 if persisted else 1
    if role == interrupt_after_intent_role:
        raise SupervisorInterrupted("after_intent")
    capture = launcher_v1.run_capture(contract, plan, invocation)
    try:
        launcher_v1.persist_capture_o_excl(capture_path, capture)
        captures.append(str(capture["capture_digest"]))
    except launcher_v1.LauncherError:
        _fail_role_from_durable_evidence(
            contract, plan, engine, role, result_class="indeterminate"
        )
        return 0, 1
    canonical = capture["canonical_result"]
    if canonical is None:
        _fail_role_from_durable_evidence(
            contract, plan, engine, role, result_class="indeterminate"
        )
    else:
        try:
            engine.apply(canonical)
            _synthetic_outer_supervisor_fault(
                contract,
                plan,
                role=role,
            )
        except EngineError:
            _fail_role_from_durable_evidence(
                contract, plan, engine, role, result_class="indeterminate"
            )
    if role == interrupt_after_role:
        raise SupervisorInterrupted("after_capture")
    return 0, 0


def run_sequence(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    contract_path: Path,
    plan_path: Path,
    deploy_root: Path,
    interrupt_after_intent_role: str | None = None,
    interrupt_after_role: str | None = None,
) -> dict[str, object]:
    validated_contract = contract_v1.validate_contract(contract)
    validated_plan = contract_v1.validate_plan(validated_contract, plan)
    _verify_bound_paths(
        validated_contract,
        validated_plan,
        contract_path=contract_path,
        plan_path=plan_path,
    )
    plan_details = adapter_v1._regular(plan_path, maximum=adapter_v1.MAX_JSON_BYTES)
    if (
        stat.S_IMODE(plan_details.st_mode) != 0o600
        or plan_details.st_uid != os.getuid()
        or plan_details.st_gid != os.getgid()
        or adapter_v1._read_regular_bytes(plan_path) != contract_v1.canonical_bytes(validated_plan)
    ):
        raise SupervisorError("plan_bytes_rejected")
    terminal_path = adapter_v1.sequence_root(
        validated_contract, validated_plan
    ) / "TERMINAL.json"
    if terminal_path.exists() or terminal_path.is_symlink():
        return _validate_terminal(
            validated_contract,
            validated_plan,
            _load_private_evidence(terminal_path),
        )
    engine = ActivationEngine(validated_contract, validated_plan)
    captures: list[str] = []
    invocation_failures = 0
    persistence_failures = 0
    while engine.terminal_status is TerminalStatus.RUNNING:
        if len(engine.next_roles) != 1:
            raise SupervisorError("supervisor_phase_ambiguity")
        role = next(iter(engine.next_roles))
        call_index = len(engine.results.get(role, [])) + 1
        invocation_delta, persistence_delta = _run_one_role(
            validated_contract,
            validated_plan,
            engine,
            role=role,
            call_index=call_index,
            contract_path=contract_path,
            plan_path=plan_path,
            deploy_root=deploy_root,
            captures=captures,
            interrupt_after_intent_role=interrupt_after_intent_role,
            interrupt_after_role=interrupt_after_role,
        )
        invocation_failures += invocation_delta
        persistence_failures += persistence_delta
    terminal = _terminal_receipt(
        validated_contract,
        validated_plan,
        engine,
        captures,
        invocation_failures=invocation_failures,
        capture_persistence_failures=persistence_failures,
    )
    terminal_path = adapter_v1.sequence_root(validated_contract, validated_plan) / "TERMINAL.json"
    try:
        adapter_v1._exclusive_write(
            terminal_path,
            contract_v1.canonical_bytes(terminal),
            mode=0o600,
        )
    except adapter_v1.AdapterError:
        raise SupervisorError("terminal_persistence_rejected") from None
    return terminal


def recover_sequence(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    contract_path: Path,
    plan_path: Path,
    deploy_root: Path,
    guardian_force_convergence: bool = False,
) -> dict[str, object]:
    validated_contract = contract_v1.validate_contract(contract)
    validated_plan = contract_v1.validate_plan(validated_contract, plan)
    _verify_bound_paths(
        validated_contract,
        validated_plan,
        contract_path=contract_path,
        plan_path=plan_path,
    )
    plan_details = adapter_v1._regular(plan_path, maximum=adapter_v1.MAX_JSON_BYTES)
    if (
        stat.S_IMODE(plan_details.st_mode) != 0o600
        or plan_details.st_uid != os.getuid()
        or plan_details.st_gid != os.getgid()
        or adapter_v1._read_regular_bytes(plan_path) != contract_v1.canonical_bytes(validated_plan)
    ):
        raise SupervisorError("plan_bytes_rejected")
    terminal_path = adapter_v1.sequence_root(
        validated_contract, validated_plan
    ) / "TERMINAL.json"
    guardian_terminal_path = adapter_v1.sequence_root(
        validated_contract, validated_plan
    ) / "GUARDIAN.RECOVERY.TERMINAL.json"
    if guardian_force_convergence and (
        guardian_terminal_path.exists() or guardian_terminal_path.is_symlink()
    ):
        return _validate_terminal(
            validated_contract,
            validated_plan,
            _load_private_evidence(guardian_terminal_path),
        )
    accepted_terminal: dict[str, object] | None = None
    if terminal_path.exists() or terminal_path.is_symlink():
        try:
            accepted_terminal = _validate_terminal(
                validated_contract,
                validated_plan,
                _load_private_evidence(terminal_path),
            )
        except SupervisorError:
            if not guardian_force_convergence:
                raise
            accepted_terminal = None
        if not guardian_force_convergence:
            assert accepted_terminal is not None
            return accepted_terminal
        if (
            accepted_terminal is not None
            and accepted_terminal["terminal_status"] != "accepted"
        ):
            return accepted_terminal
    engine = ActivationEngine(validated_contract, validated_plan)
    captures: list[str] = []
    invocation_failures = 0
    persistence_failures = 0
    while engine.terminal_status is TerminalStatus.RUNNING:
        if len(engine.next_roles) != 1:
            raise SupervisorError("supervisor_phase_ambiguity")
        role = next(iter(engine.next_roles))
        call_index = len(engine.results.get(role, [])) + 1
        intent_path, capture_path = _role_paths(
            validated_contract, validated_plan, role, call_index
        )
        failure_path = _failure_path(
            validated_contract, validated_plan, role, call_index
        )
        intent_exists = intent_path.exists() or intent_path.is_symlink()
        capture_exists = capture_path.exists() or capture_path.is_symlink()
        failure_exists = failure_path.exists() or failure_path.is_symlink()
        if failure_exists:
            if intent_exists or capture_exists:
                raise SupervisorError("mixed_role_evidence_rejected")
            _validate_failure(
                validated_contract,
                validated_plan,
                _load_private_evidence(failure_path),
                role=role,
                call_index=call_index,
            )
            invocation_failures += 1
            _fail_role_from_durable_evidence(
                validated_contract,
                validated_plan,
                engine,
                role,
                result_class="indeterminate",
            )
            continue
        if capture_exists and not intent_exists:
            raise SupervisorError("capture_without_intent_rejected")
        if intent_exists:
            intent = _validate_intent(
                validated_contract,
                validated_plan,
                _load_private_evidence(intent_path),
                role=role,
                call_index=call_index,
            )
            if not capture_exists:
                _fail_role_from_durable_evidence(
                    validated_contract,
                    validated_plan,
                    engine,
                    role,
                    result_class="indeterminate",
                )
                break
            capture = launcher_v1.validate_capture(
                validated_contract,
                validated_plan,
                _load_private_evidence(capture_path),
                expected_role=role,
                expected_call=call_index,
            )
            if capture["invocation_digest"] != intent["invocation_digest"]:
                raise SupervisorError("intent_capture_binding_rejected")
            captures.append(str(capture["capture_digest"]))
            canonical = capture["canonical_result"]
            if canonical is None:
                _fail_role_from_durable_evidence(
                    validated_contract,
                    validated_plan,
                    engine,
                    role,
                    result_class="indeterminate",
                )
            else:
                try:
                    engine.apply(canonical)
                except EngineError:
                    _fail_role_from_durable_evidence(
                        validated_contract,
                        validated_plan,
                        engine,
                        role,
                        result_class="indeterminate",
                    )
            continue
        break

    # The adapter persists a same-PLAN obligation before its first recovery
    # infrastructure write.  If the role child died before producing a
    # capture, replay alone cannot infer that durable mutation.  Import only
    # the exact validated obligation; never infer from ambient files.
    if (
        engine.terminal_status is TerminalStatus.RUNNING
        and not engine.product_mutated
        and adapter_v1._recovery_obligation_exists(
            validated_contract, validated_plan
        )
    ):
        engine.bind_durable_infrastructure_obligation()

    if guardian_force_convergence and engine.terminal_status is TerminalStatus.ACCEPTED:
        engine.require_guardian_convergence()
    if engine.terminal_status is TerminalStatus.RUNNING:
        engine.abort_for_recovery()
    while engine.terminal_status is TerminalStatus.RUNNING:
        if len(engine.next_roles) != 1:
            raise SupervisorError("recovery_phase_ambiguity")
        role = next(iter(engine.next_roles))
        if role not in {"continuity_reconcile", "converge", "recover", "postflight"}:
            engine.abort_for_recovery()
            continue
        call_index = len(engine.results.get(role, [])) + 1
        invocation_delta, persistence_delta = _run_one_role(
            validated_contract,
            validated_plan,
            engine,
            role=role,
            call_index=call_index,
            contract_path=contract_path,
            plan_path=plan_path,
            deploy_root=deploy_root,
            captures=captures,
        )
        invocation_failures += invocation_delta
        persistence_failures += persistence_delta
        if role == "continuity_reconcile" and engine.terminal_status is TerminalStatus.RUNNING:
            engine.abort_for_recovery()
    terminal = _terminal_receipt(
        validated_contract,
        validated_plan,
        engine,
        captures,
        invocation_failures=invocation_failures,
        capture_persistence_failures=persistence_failures,
    )
    output_terminal_path = (
        guardian_terminal_path if guardian_force_convergence else terminal_path
    )
    if output_terminal_path.exists() or output_terminal_path.is_symlink():
        observed = _load_private_evidence(output_terminal_path)
        if observed != terminal:
            raise SupervisorError("terminal_replay_rejected")
    else:
        try:
            adapter_v1._exclusive_write(
                output_terminal_path,
                contract_v1.canonical_bytes(terminal),
                mode=0o600,
            )
        except adapter_v1.AdapterError:
            raise SupervisorError("terminal_persistence_rejected") from None
    return terminal


def execute_or_recover(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    contract_path: Path,
    plan_path: Path,
    deploy_root: Path,
) -> dict[str, object]:
    """Run once and perform at most one same-plan bounded recovery.

    Ordinary in-child failures converge here.  If the OS terminates this child,
    the source-owned outer bootstrap binds the immutable capture to this exact
    plan and invokes the recovery entrypoint at most once in the same parent
    flow; no later manual caller receives recovery authority.
    """
    try:
        return run_sequence(
            contract,
            plan,
            contract_path=contract_path,
            plan_path=plan_path,
            deploy_root=deploy_root,
        )
    except SupervisorInterrupted:
        raise
    except Exception:
        return recover_sequence(
            contract,
            plan,
            contract_path=contract_path,
            plan_path=plan_path,
            deploy_root=deploy_root,
        )


def _validated_bootstrap_intent(
    contract: Mapping[str, object],
) -> dict[str, object]:
    raw_path = os.environ.get("MYUNA_P08_SUPERVISOR_BOOTSTRAP_INTENT")
    if raw_path is None:
        raise SupervisorError("supervisor_bootstrap_rejected")
    path = Path(raw_path)
    intent = _load_private_evidence(path)
    try:
        projected_argv = list(sys.orig_argv)
        return launcher_v1.verify_current_supervisor_entry(
            contract, intent, argv=projected_argv
        )
    except (KeyError, launcher_v1.LauncherError):
        raise SupervisorError("supervisor_bootstrap_rejected") from None


def _verify_loaded_entry_modules(
    contract: Mapping[str, object], intent: Mapping[str, object]
) -> None:
    target = Path(str(intent["target_source_path"]))
    try:
        inventory = adapter_v1.target_inventory(target)
        directories = adapter_v1.target_directory_inventory(
            target, file_inventory=inventory
        )
        adapter_v1._target_manifest(contract, target, inventory)
        if (
            contract_v1.digest_value(inventory)
            != intent["target_inventory_digest"]
            or contract_v1.digest_value(directories)
            != intent["target_directories_digest"]
        ):
            raise SupervisorError("supervisor_bootstrap_rejected")
        launcher_v1.verify_loaded_runtime_inventory(
            contract,
            target,
            inventory,
            directories,
            {
                "scripts/p08_activation_contract_v1.py": contract_v1,
                "scripts/p08_activation_launcher_v1.py": launcher_v1,
                contract_v1.PRODUCTION_ADAPTER_PATH: adapter_v1,
                "scripts/p08_activation_supervisor_v1.py": sys.modules[__name__],
            },
        )
    except (adapter_v1.AdapterError, launcher_v1.LauncherError):
        raise SupervisorError("supervisor_bootstrap_rejected") from None


def _verify_recovery_origin(
    contract: Mapping[str, object],
    bootstrap_intent: Mapping[str, object],
    plan: Mapping[str, object],
) -> bool:
    """Bind recovery to either legacy capture evidence or guardian ownership.

    The guardian path does not depend on CAPTURE persistence.  Its immutable
    obligation and pre-authorized child identity are durable before the child
    can create PLAN or mutate product state.
    """
    origin = bootstrap_intent.get("origin_entry_nonce")
    capture_digest = bootstrap_intent.get("origin_capture_digest")
    guardian_obligation_digest = bootstrap_intent.get(
        "guardian_obligation_digest"
    )
    guardian_child_digest = bootstrap_intent.get("guardian_child_digest")
    if (
        not isinstance(origin, str)
        or contract_v1.HEX64.fullmatch(origin) is None
        or origin != plan["sequence_identity"]
        or bootstrap_intent.get("sequence_identity") != origin
    ):
        raise SupervisorError("supervisor_recovery_origin_rejected")
    strategy = adapter_v1._rooted(
        Path(str(plan["execution"]["root"])),
        str(contract["production_adapter"]["fixed_paths"]["strategy_root"]),
    )
    guardian_authorized = (
        isinstance(guardian_obligation_digest, str)
        and contract_v1.HEX64.fullmatch(guardian_obligation_digest) is not None
        and isinstance(guardian_child_digest, str)
        and contract_v1.HEX64.fullmatch(guardian_child_digest) is not None
    )
    if guardian_authorized:
        guardian_root = strategy / "guardians" / origin
        try:
            obligation = contract_v1.validate_guardian_obligation(
                contract, _load_private_evidence(guardian_root / "OBLIGATION.json")
            )
            if (
                obligation["obligation_digest"] != guardian_obligation_digest
                or obligation["sequence_identity"] != origin
                or obligation["plan_path"]
                != str(
                    adapter_v1.sequence_root(contract, plan) / "PLAN.json"
                )
                or obligation["target_source_path"]
                != plan["execution"]["target_source_path"]
                or obligation["backend"] != plan["execution"]["backend"]
            ):
                raise SupervisorError("supervisor_recovery_origin_rejected")
            children = []
            for generation in (1, 2):
                path = guardian_root / f"CHILD.{generation}.json"
                if path.exists() or path.is_symlink():
                    child = contract_v1.validate_guardian_child(
                        contract, obligation, _load_private_evidence(path)
                    )
                    if child["child_digest"] == guardian_child_digest:
                        children.append(child)
            if len(children) != 1:
                raise SupervisorError("supervisor_recovery_origin_rejected")
            child = children[0]
            if capture_digest is not None:
                if (
                    not isinstance(capture_digest, str)
                    or contract_v1.HEX64.fullmatch(capture_digest) is None
                ):
                    raise SupervisorError("supervisor_recovery_origin_rejected")
                child_entry = strategy / "entries" / str(child["child_entry_nonce"])
                original_intent = launcher_v1.validate_supervisor_bootstrap_intent(
                    contract, _load_private_evidence(child_entry / "INTENT.json")
                )
                original_capture = launcher_v1.validate_supervisor_bootstrap_capture(
                    contract,
                    original_intent,
                    _load_private_evidence(child_entry / "CAPTURE.json"),
                )
                if original_capture["capture_digest"] != capture_digest:
                    raise SupervisorError("supervisor_recovery_origin_rejected")
        except (
            contract_v1.ContractError,
            launcher_v1.LauncherError,
            SupervisorError,
        ):
            raise SupervisorError("supervisor_recovery_origin_rejected") from None
        return True

    if (
        not isinstance(capture_digest, str)
        or contract_v1.HEX64.fullmatch(capture_digest) is None
        or origin == bootstrap_intent["entry_nonce"]
    ):
        raise SupervisorError("supervisor_recovery_origin_rejected")
    origin_entry = strategy / "entries" / origin
    try:
        original_intent = launcher_v1.validate_supervisor_bootstrap_intent(
            contract, _load_private_evidence(origin_entry / "INTENT.json")
        )
        original_capture = launcher_v1.validate_supervisor_bootstrap_capture(
            contract,
            original_intent,
            _load_private_evidence(origin_entry / "CAPTURE.json"),
        )
    except (launcher_v1.LauncherError, SupervisorError):
        raise SupervisorError("supervisor_recovery_origin_rejected") from None
    if (
        original_intent["entry_nonce"] != origin
        or original_intent["recover_plan"] is not None
        or original_intent["root"] != plan["execution"]["root"]
        or original_intent["backend"] != plan["execution"]["backend"]
        or original_intent["target_source_path"]
        != plan["execution"]["target_source_path"]
        or original_capture["capture_digest"] != capture_digest
        or original_capture["canonical_result"] is not None
        or original_capture["canonical_status"] != "indeterminate"
        or original_capture["orphan_count"] != 0
    ):
        raise SupervisorError("supervisor_recovery_origin_rejected")
    return False


def _synthetic_preplan_fault(
    contract: Mapping[str, object], *, root: Path, backend: str
) -> None:
    if backend != "synthetic":
        return
    fixed = contract["production_adapter"]["fixed_paths"]
    control = adapter_v1._synthetic_control_path(
        contract,
        adapter_v1._rooted(root, str(fixed["state_root"]))
        / "synthetic-control.json",
    )
    if control["fault_kind"] == "outer_kill_before_plan":
        os.kill(os.getpid(), 9)


def _synthetic_postplan_fault(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> None:
    if plan["execution"]["backend"] != "synthetic":
        return
    control = adapter_v1._synthetic_control(contract, plan)
    if control["fault_kind"] == "guardian_manager_sigkill_after_plan":
        manager_pid = os.getppid()
        if manager_pid <= 1:
            raise SupervisorError("synthetic_guardian_parent_rejected")
        os.kill(manager_pid, signal.SIGKILL)
        while True:
            time.sleep(60.0)


def main(argv: Sequence[str] | None = None) -> int:
    parser = adapter_v1.CanonicalArgumentParser(allow_abbrev=False)
    parser.add_argument("--activation-contract", type=Path, required=True)
    parser.add_argument("--activation-root", type=Path)
    parser.add_argument("--activation-backend", choices=("synthetic", "systemd"))
    parser.add_argument("--activation-target-source", type=Path)
    parser.add_argument("--acceptance-scope-digest")
    parser.add_argument("--recover-plan", type=Path)
    try:
        values = parser.parse_args(argv)
        contract = contract_v1.validate_contract(_load_canonical(values.activation_contract))
        bootstrap_intent = _validated_bootstrap_intent(contract)
        _verify_loaded_entry_modules(contract, bootstrap_intent)
        if values.recover_plan is not None:
            if any(
                value is not None
                for value in (
                    values.activation_root,
                    values.activation_backend,
                    values.activation_target_source,
                    values.acceptance_scope_digest,
                )
            ):
                raise SupervisorError("supervisor_arguments_rejected")
            plan = contract_v1.validate_plan(
                contract,
                _load_private_evidence(values.recover_plan),
            )
            if (
                bootstrap_intent["recover_plan"] != str(values.recover_plan)
                or bootstrap_intent["acceptance_scope_digest"] is not None
                or bootstrap_intent["root"] != plan["execution"]["root"]
                or bootstrap_intent["backend"] != plan["execution"]["backend"]
                or bootstrap_intent["target_source_path"]
                != plan["execution"]["target_source_path"]
            ):
                raise SupervisorError("supervisor_bootstrap_rejected")
            guardian_force_convergence = _verify_recovery_origin(
                contract, bootstrap_intent, plan
            )
            terminal = recover_sequence(
                contract,
                plan,
                contract_path=values.activation_contract,
                plan_path=values.recover_plan,
                deploy_root=Path(str(plan["execution"]["target_source_path"])),
                guardian_force_convergence=guardian_force_convergence,
            )
        else:
            if any(
                value is None
                for value in (
                    values.activation_root,
                    values.activation_backend,
                    values.activation_target_source,
                    values.acceptance_scope_digest,
                )
            ):
                raise SupervisorError("supervisor_arguments_rejected")
            _synthetic_preplan_fault(
                contract,
                root=values.activation_root,
                backend=values.activation_backend,
            )
            plan, plan_path = prepare_plan(
                contract,
                bootstrap_intent=bootstrap_intent,
                contract_path=values.activation_contract,
                root=values.activation_root,
                backend=values.activation_backend,
                target_source_path=values.activation_target_source,
                acceptance_scope_digest=values.acceptance_scope_digest,
            )
            _synthetic_postplan_fault(contract, plan)
            terminal = execute_or_recover(
                contract,
                plan,
                contract_path=values.activation_contract,
                plan_path=plan_path,
                deploy_root=Path(str(plan["execution"]["target_source_path"])),
            )
    except Exception:
        failure = {
            "schema": contract_v1.SUPERVISOR_ENTRY_SCHEMA,
            "status": "indeterminate",
            "stage": "source_owned_entry",
            "product_state": "unknown",
            "raw_output_included": False,
            "retry_authorized": False,
        }
        sys.stdout.buffer.write(contract_v1.canonical_bytes(failure))
        return 2
    sys.stdout.buffer.write(contract_v1.canonical_bytes(terminal))
    return 0 if terminal["terminal_status"] == "accepted" else 2


if __name__ == "__main__":
    raise SystemExit(main())
