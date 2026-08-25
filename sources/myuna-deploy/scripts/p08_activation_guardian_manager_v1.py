#!/usr/bin/env python3
"""Durable guardian manager for ``myuna.p08-activation-engine.v1``.

The caller submits an immutable obligation before this process starts.  This
manager is a separate process-group authority: it owns the supervisor child,
the canonical terminal read-back, and the accepted-target discharge.  A later
bootstrap integration may wait for these durable files, but it does not become
recovery authority merely by capturing this process.
"""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import secrets
import signal
import stat
import subprocess
import sys
import time
from typing import Callable, Mapping, Sequence

import p08_activation_contract_v1 as contract_v1
import p08_activation_launcher_v1 as launcher_v1
import p08_activation_production_adapter_v1 as adapter_v1
import p08_activation_supervisor_v1 as supervisor_v1


class GuardianError(RuntimeError):
    pass


def _verify_systemd_manager_cgroup(
    unit_name: str,
    *,
    pid: int,
    cgroup_raw: str,
    cgroup_procs_raw: str,
) -> None:
    expected = f"0::/system.slice/{unit_name}"
    try:
        procs = [int(value) for value in cgroup_procs_raw.splitlines()]
    except ValueError:
        raise GuardianError("guardian_manager_cgroup_rejected") from None
    if (
        cgroup_raw.splitlines() != [expected]
        or procs != [pid]
        or pid < 1
    ):
        raise GuardianError("guardian_manager_cgroup_rejected")


def _remaining_guardian_seconds(obligation: Mapping[str, object]) -> int:
    try:
        if launcher_v1.boot_identity_digest() != obligation["boot_identity_digest"]:
            raise GuardianError("guardian_deadline_rejected")
    except launcher_v1.LauncherError:
        raise GuardianError("guardian_deadline_rejected") from None
    now = time.monotonic_ns()
    start = int(obligation["monotonic_start_ns"])
    deadline = int(obligation["monotonic_deadline_ns"])
    if now < start or deadline <= start:
        raise GuardianError("guardian_deadline_rejected")
    remaining_ns = deadline - now
    if remaining_ns <= 0:
        return 0
    return (remaining_ns + 999_999_999) // 1_000_000_000


def _load_contract(path: Path) -> dict[str, object]:
    try:
        return contract_v1.validate_contract(adapter_v1._read_json(path))
    except (adapter_v1.AdapterError, contract_v1.ContractError):
        raise GuardianError("guardian_contract_rejected") from None


def _load_obligation(
    contract: Mapping[str, object], path: Path
) -> dict[str, object]:
    try:
        value = contract_v1.validate_guardian_obligation(
            contract, adapter_v1._read_json(path)
        )
        details = adapter_v1._regular(path, maximum=adapter_v1.MAX_JSON_BYTES)
    except (adapter_v1.AdapterError, contract_v1.ContractError):
        raise GuardianError("guardian_obligation_rejected") from None
    if (
        stat.S_IMODE(details.st_mode) != 0o600
        or details.st_uid != os.getuid()
        or details.st_gid != os.getgid()
        or adapter_v1._read_regular_bytes(path)
        != contract_v1.canonical_bytes(value)
    ):
        raise GuardianError("guardian_obligation_rejected")
    return value


def _persist_exact(
    path: Path,
    value: Mapping[str, object],
    validator: Callable[[object], Mapping[str, object]],
) -> dict[str, object]:
    try:
        launcher_v1.persist_capture_o_excl(path, value)
    except (
        launcher_v1.LauncherError,
        OSError,
    ):
        raise GuardianError("guardian_persistence_rejected") from None
    projected = _read_exact(path, validator)
    if projected != value:
        raise GuardianError("guardian_persistence_rejected")
    return dict(projected)


def _read_exact(
    path: Path,
    validator: Callable[[object], Mapping[str, object]],
) -> dict[str, object]:
    """Read one guardian record only after exact canonical validation."""
    try:
        observed = adapter_v1._read_json(path)
        projected = validator(observed)
        details = adapter_v1._regular(path, maximum=adapter_v1.MAX_JSON_BYTES)
        raw = adapter_v1._read_regular_bytes(path)
    except (
        adapter_v1.AdapterError,
        contract_v1.ContractError,
        GuardianError,
        launcher_v1.LauncherError,
        OSError,
        TypeError,
    ):
        raise GuardianError("guardian_persistence_rejected") from None
    if (
        stat.S_IMODE(details.st_mode) != 0o600
        or details.st_uid != os.getuid()
        or details.st_gid != os.getgid()
        or raw != contract_v1.canonical_bytes(projected)
    ):
        raise GuardianError("guardian_persistence_rejected")
    return dict(projected)


def _guardian_fault_kind(
    contract: Mapping[str, object], obligation: Mapping[str, object]
) -> str | None:
    if obligation["backend"] != "synthetic":
        return None
    fixed = contract["production_adapter"]["fixed_paths"]
    control = adapter_v1._synthetic_control_path(
        contract,
        adapter_v1._rooted(Path(str(obligation["root"])), str(fixed["state_root"]))
        / "synthetic-control.json",
    )
    return str(control["fault_kind"]) if control["fault_kind"] is not None else None


def _persist_fault_residue(
    path: Path,
    value: Mapping[str, object],
    *,
    stage: str,
) -> None:
    """Create deterministic temp-root persistence failures for shadow tests."""
    if stage == "create":
        raise GuardianError("guardian_persistence_rejected")
    if stage in {"write", "fsync"}:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            os.fchmod(descriptor, 0o600)
            raw = b"{" if stage == "write" else contract_v1.canonical_bytes(value)
            os.write(descriptor, raw)
            if stage == "write":
                os.fsync(descriptor)
        finally:
            os.close(descriptor)
        raise GuardianError("guardian_persistence_rejected")
    if stage == "validation":
        launcher_v1.persist_capture_o_excl(path, {"schema": "synthetic-invalid"})
        raise GuardianError("guardian_persistence_rejected")
    if stage == "readback":
        launcher_v1.persist_capture_o_excl(path, value)
        raise GuardianError("guardian_persistence_rejected")
    raise GuardianError("guardian_fault_stage_rejected")


def _persist_exact_guarded(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    path: Path,
    value: Mapping[str, object],
    validator: Callable[[object], Mapping[str, object]],
    *,
    generation: int,
    record_kind: str,
) -> dict[str, object]:
    fault = _guardian_fault_kind(contract, obligation)
    mapping = {
        "guardian_capture_create_failed_after_mutation": ("forward_capture", "create"),
        "guardian_capture_write_failed_after_mutation": ("forward_capture", "write"),
        "guardian_capture_fsync_failed_after_mutation": ("forward_capture", "fsync"),
        "guardian_capture_readback_failed_after_mutation": ("forward_capture", "readback"),
        "guardian_capture_validation_failed_after_mutation": ("forward_capture", "validation"),
        "guardian_recovery_capture_persist_failed": ("recovery_capture", "create"),
        "guardian_accepted_result_persist_failed": ("accepted_result", "create"),
        "guardian_accepted_terminal_persist_failed": ("accepted_terminal", "create"),
        "guardian_discharge_persist_failed": ("discharge", "create"),
        "guardian_hardstop_terminal_persist_failed": ("hardstop_terminal", "create"),
    }
    selected = mapping.get(fault)
    if generation == 1 and selected is not None and selected[0] == record_kind:
        _persist_fault_residue(path, value, stage=selected[1])
    projected = _persist_exact(path, value, validator)
    kill_after = {
        "guardian_manager_sigkill_after_accepted_result": "accepted_result",
        "guardian_manager_sigkill_after_accepted_terminal": "accepted_terminal",
        "guardian_manager_sigkill_after_discharge": "discharge",
    }
    if generation == 1 and kill_after.get(fault) == record_kind:
        os.kill(os.getpid(), signal.SIGKILL)
    return projected


def _target_closure(
    contract: Mapping[str, object], target: Path
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    try:
        inventory = adapter_v1.target_inventory(target)
        directories = adapter_v1.target_directory_inventory(
            target, file_inventory=inventory
        )
        adapter_v1._target_manifest(contract, target, inventory)
        launcher_v1.verify_runtime_inventory(
            contract, target, inventory, directories
        )
    except (adapter_v1.AdapterError, launcher_v1.LauncherError):
        raise GuardianError("guardian_target_rejected") from None
    return inventory, directories


def _verify_manager_process(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    manager_intent: Mapping[str, object],
    *,
    argv: Sequence[str] | None,
) -> None:
    try:
        validated = contract_v1.validate_guardian_manager_intent(
            contract, obligation, manager_intent
        )
        stdin_target = os.readlink("/proc/self/fd/0")
    except (contract_v1.ContractError, OSError):
        raise GuardianError("guardian_manager_process_rejected") from None
    if (
        argv is not None
        or list(sys.orig_argv) != validated["argv"]
        or Path.cwd() != Path(str(validated["cwd"]))
        or Path(sys.executable) != Path(str(validated["interpreter_path"]))
        or os.getuid() != validated["uid"]
        or os.getgid() != validated["gid"]
        or sorted(os.getgroups()) != validated["groups"]
        or dict(os.environ) != validated["environment"]
        or stdin_target != "/dev/null"
        or os.getpgrp() == obligation["bootstrap_process_group"]
        or (
            obligation["manager_backend"] == "synthetic_subprocess"
            and (os.getpgrp() != os.getpid() or os.getsid(0) != os.getpid())
        )
    ):
        raise GuardianError("guardian_manager_process_rejected")
    if obligation["manager_backend"] == "systemd_transient":
        try:
            transient = contract_v1.build_guardian_transient_launch(
                contract, obligation, validated
            )
            unit_name = str(transient["unit_name"])
            cgroup_path = Path("/sys/fs/cgroup/system.slice") / unit_name / "cgroup.procs"
            _verify_systemd_manager_cgroup(
                unit_name,
                pid=os.getpid(),
                cgroup_raw=Path("/proc/self/cgroup").read_text(
                    encoding="ascii"
                ),
                cgroup_procs_raw=cgroup_path.read_text(encoding="ascii"),
            )
        except (OSError, UnicodeError, contract_v1.ContractError):
            raise GuardianError("guardian_manager_cgroup_rejected") from None
    _load_strategy_launch_claim(contract, obligation)
    target = Path(str(obligation["target_source_path"]))
    inventory, directories = _target_closure(contract, target)
    if (
        contract_v1.digest_value(inventory)
        != obligation["target_inventory_digest"]
        or contract_v1.digest_value(directories)
        != obligation["target_directories_digest"]
    ):
        raise GuardianError("guardian_manager_source_rejected")
    try:
        launcher_v1._verify_interpreter(contract["interpreter"])
        launcher_v1.verify_loaded_runtime_inventory(
            contract,
            target,
            inventory,
            directories,
            {
                contract_v1.SUPERVISOR_GUARDIAN_MANAGER_PATH: sys.modules[__name__],
                "scripts/p08_activation_contract_v1.py": contract_v1,
                "scripts/p08_activation_launcher_v1.py": launcher_v1,
                contract_v1.PRODUCTION_ADAPTER_PATH: adapter_v1,
                "scripts/p08_activation_supervisor_v1.py": supervisor_v1,
            },
        )
    except launcher_v1.LauncherError:
        raise GuardianError("guardian_manager_source_rejected") from None


def _claim_generation(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    manager_intent: Mapping[str, object],
    guardian_root: Path,
) -> int:
    manager_process_group, manager_start_ticks = _read_start_ticks(os.getpid())
    if manager_process_group != os.getpgrp():
        raise GuardianError("guardian_generation_rejected")
    for generation in (1, 2):
        path = guardian_root / f"GENERATION.{generation}.json"
        if path.exists() or path.is_symlink():
            try:
                contract_v1.validate_guardian_generation(
                    contract,
                    obligation,
                    manager_intent,
                    adapter_v1._read_json(path),
                )
            except (contract_v1.ContractError, adapter_v1.AdapterError):
                raise GuardianError("guardian_generation_rejected") from None
            continue
        value = contract_v1.build_guardian_generation(
            contract,
            obligation,
            manager_intent,
            generation=generation,
            manager_pid=os.getpid(),
            manager_process_group=manager_process_group,
            manager_start_ticks=manager_start_ticks,
        )
        _persist_exact(
            path,
            value,
            lambda observed: contract_v1.validate_guardian_generation(
                contract, obligation, manager_intent, observed
            ),
        )
        return generation
    raise GuardianError("guardian_generation_exhausted")


def _ensure_private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(path, 0o700)
        details = path.lstat()
    except OSError:
        raise GuardianError("guardian_namespace_rejected") from None
    if (
        not stat.S_ISDIR(details.st_mode)
        or stat.S_ISLNK(details.st_mode)
        or stat.S_IMODE(details.st_mode) != 0o700
        or details.st_uid != os.getuid()
        or details.st_gid != os.getgid()
    ):
        raise GuardianError("guardian_namespace_rejected")


def _entry_root(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    *,
    generation: int,
    purpose: str,
) -> Path:
    if generation not in {1, 2} or purpose not in {"forward", "recovery"}:
        raise GuardianError("guardian_child_entry_rejected")
    child_entry_nonce = contract_v1.digest_value(
        {
            "schema": "myuna.p08-activation-guardian-child-entry.v1",
            "obligation_digest": obligation["obligation_digest"],
            "sequence_identity": obligation["sequence_identity"],
            "generation": generation,
            "purpose": purpose,
        }
    )
    root = Path(str(obligation["root"]))
    fixed = contract["production_adapter"]["fixed_paths"]
    return (
        adapter_v1._rooted(root, str(fixed["strategy_root"]))
        / "entries"
        / child_entry_nonce
    )


def _read_process_identity(pid: int) -> tuple[str, int, int]:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        tail = raw[raw.rindex(")") + 2 :].split()
        state = tail[0]
        process_group = int(tail[2])
        start_ticks = int(tail[19])
    except (OSError, ValueError, IndexError):
        raise GuardianError("guardian_child_identity_rejected") from None
    if len(state) != 1:
        raise GuardianError("guardian_child_identity_rejected")
    return state, process_group, start_ticks


def _read_start_ticks(pid: int) -> tuple[int, int]:
    _, process_group, start_ticks = _read_process_identity(pid)
    return process_group, start_ticks


def _canonical_sequence_terminal(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    result: Mapping[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    try:
        projected = contract_v1.validate_supervisor_bootstrap_output(result)
    except contract_v1.ContractError:
        raise GuardianError("guardian_child_terminal_rejected") from None
    if projected.get("sequence_identity") != obligation["sequence_identity"]:
        raise GuardianError("guardian_child_terminal_rejected")
    plan_path = Path(str(obligation["plan_path"]))
    try:
        plan = contract_v1.validate_plan(
            contract, supervisor_v1._load_private_evidence(plan_path)
        )
    except (contract_v1.ContractError, supervisor_v1.SupervisorError):
        raise GuardianError("guardian_child_terminal_rejected") from None
    candidates: list[dict[str, object]] = []
    for name in ("TERMINAL.json", "GUARDIAN.RECOVERY.TERMINAL.json"):
        path = plan_path.parent / name
        if not path.exists() and not path.is_symlink():
            continue
        try:
            candidates.append(
                supervisor_v1._validate_terminal(
                    contract,
                    plan,
                    supervisor_v1._load_private_evidence(path),
                )
            )
        except (contract_v1.ContractError, supervisor_v1.SupervisorError):
            continue
    matches = [terminal for terminal in candidates if terminal == projected]
    if len(matches) != 1:
        raise GuardianError("guardian_child_terminal_rejected")
    return plan, matches[0]


def _accepted_discharge(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    *,
    guardian_root: Path,
    generation: int,
    capture: Mapping[str, object],
    plan: Mapping[str, object],
    terminal: Mapping[str, object],
) -> dict[str, object]:
    if terminal["terminal_status"] != "accepted":
        raise GuardianError("guardian_accepted_terminal_rejected")
    result_path = guardian_root / "ACCEPTED.RESULT.json"
    result = _persist_exact_guarded(
        contract,
        obligation,
        result_path,
        terminal,
        lambda observed: supervisor_v1._validate_terminal(
            contract, plan, observed
        ),
        generation=generation,
        record_kind="accepted_result",
    )
    guardian_terminal = contract_v1.build_guardian_terminal(
        contract,
        obligation,
        terminal_status="accepted",
        product_state="target_accepted",
        plan_digest=str(plan["plan_digest"]),
        result_digest=contract_v1.digest_value(result),
        child_capture_digest=str(capture["capture_digest"]),
        child_terminal_digest=str(terminal["receipt_digest"]),
        acceptance_nonce=str(plan["invocation_nonce"]),
        recovery_count=0,
        manager_generation=generation,
        orphan_count=0,
    )
    guardian_terminal = _persist_exact_guarded(
        contract,
        obligation,
        guardian_root / "ACCEPTED.TERMINAL.json",
        guardian_terminal,
        lambda observed: contract_v1.validate_guardian_terminal(
            contract, obligation, observed
        ),
        generation=generation,
        record_kind="accepted_terminal",
    )
    discharge = contract_v1.build_guardian_discharge(
        contract, obligation, guardian_terminal
    )
    _persist_exact_guarded(
        contract,
        obligation,
        guardian_root / "DISCHARGE.json",
        discharge,
        lambda observed: contract_v1.validate_guardian_discharge(
            contract, obligation, guardian_terminal, observed
        ),
        generation=generation,
        record_kind="discharge",
    )
    # The fixed strategy terminal indexes only a fully durable lifecycle.
    # Local accepted evidence plus DISCHARGE is persisted and read back first;
    # a manager re-entry may safely materialize the missing global index.
    _persist_strategy_launch_terminal(
        contract,
        obligation,
        guardian_root=guardian_root,
        guardian_terminal=guardian_terminal,
    )
    return result


def _strategy_launch_paths(
    contract: Mapping[str, object], obligation: Mapping[str, object]
) -> tuple[Path, Path]:
    fixed = contract["production_adapter"]["fixed_paths"]
    strategy = adapter_v1._rooted(
        Path(str(obligation["root"])), str(fixed["strategy_root"])
    )
    return (
        strategy / "STRATEGY.LAUNCH.CLAIM.json",
        strategy / "STRATEGY.LAUNCH.TERMINAL.json",
    )


def _load_strategy_launch_claim(
    contract: Mapping[str, object], obligation: Mapping[str, object]
) -> dict[str, object]:
    claim_path, _ = _strategy_launch_paths(contract, obligation)
    claim = _read_exact(
        claim_path,
        lambda observed: contract_v1.validate_strategy_launch_claim(
            contract, observed
        ),
    )
    if (
        claim["launch_claim_digest"] != obligation["launch_claim_digest"]
        or claim["entry_nonce"] != obligation["entry_nonce"]
        or claim["prestate_identity"] != obligation["prestate_identity"]
        or claim["root"] != obligation["root"]
        or claim["backend"] != obligation["backend"]
        or claim["target_source_path"] != obligation["target_source_path"]
        or claim["target_inventory_digest"]
        != obligation["target_inventory_digest"]
        or claim["target_directories_digest"]
        != obligation["target_directories_digest"]
        or claim["acceptance_scope_digest"]
        != obligation["acceptance_scope_digest"]
    ):
        raise GuardianError("guardian_strategy_claim_rejected")
    return claim


def _persist_strategy_launch_terminal(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    *,
    guardian_root: Path,
    guardian_terminal: Mapping[str, object],
) -> dict[str, object]:
    claim = _load_strategy_launch_claim(contract, obligation)
    value = contract_v1.build_strategy_launch_terminal(
        contract, claim, obligation, guardian_terminal
    )
    _, path = _strategy_launch_paths(contract, obligation)
    if path.exists() or path.is_symlink():
        observed = _read_strategy_launch_terminal(
            contract, obligation, guardian_terminal
        )
        if observed != value:
            raise GuardianError("guardian_strategy_terminal_replay_rejected")
        return observed
    return _persist_exact(
        path,
        value,
        lambda item: contract_v1.validate_strategy_launch_terminal(
            contract, claim, obligation, guardian_terminal, item
        ),
    )


def _read_strategy_launch_terminal(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    guardian_terminal: Mapping[str, object],
) -> dict[str, object]:
    claim = _load_strategy_launch_claim(contract, obligation)
    _, path = _strategy_launch_paths(contract, obligation)
    return _read_exact(
        path,
        lambda item: contract_v1.validate_strategy_launch_terminal(
            contract, claim, obligation, guardian_terminal, item
        ),
    )


def _load_plan_optional(
    contract: Mapping[str, object], obligation: Mapping[str, object]
) -> dict[str, object] | None:
    path = Path(str(obligation["plan_path"]))
    if not path.exists() and not path.is_symlink():
        return None
    try:
        plan = contract_v1.validate_plan(
            contract, supervisor_v1._load_private_evidence(path)
        )
        details = adapter_v1._regular(path, maximum=adapter_v1.MAX_JSON_BYTES)
    except (contract_v1.ContractError, supervisor_v1.SupervisorError, adapter_v1.AdapterError):
        raise GuardianError("guardian_plan_rejected") from None
    if (
        plan["sequence_identity"] != obligation["sequence_identity"]
        or plan["prestate_identity"] != obligation["prestate_identity"]
        or plan["execution"]["root"] != obligation["root"]
        or plan["execution"]["backend"] != obligation["backend"]
        or plan["execution"]["target_source_path"]
        != obligation["target_source_path"]
        or stat.S_IMODE(details.st_mode) != 0o600
        or details.st_uid != os.getuid()
        or details.st_gid != os.getgid()
        or adapter_v1._read_regular_bytes(path) != contract_v1.canonical_bytes(plan)
    ):
        raise GuardianError("guardian_plan_rejected")
    return plan


def _persist_plan_only_premutation_terminal(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    plan: Mapping[str, object],
) -> dict[str, object] | None:
    """Close an exact PLAN-only sequence without inventing a rollback call.

    ``construct`` is the canonical first-role boundary.  A zero-count receipt
    with that boundary means the role was never entered; exact directory
    cardinality proves there is no role, claim, or action evidence to replay.
    """
    sequence = adapter_v1.sequence_root(contract, plan)
    try:
        names = sorted(path.name for path in sequence.iterdir())
    except OSError:
        raise GuardianError("guardian_plan_evidence_rejected") from None
    if names != ["PLAN.json"]:
        return None
    body = {
        "schema": contract_v1.SUPERVISOR_RECEIPT_SCHEMA,
        "architecture": contract_v1.ARCHITECTURE,
        "contract_digest": contract["contract_digest"],
        "plan_digest": plan["plan_digest"],
        "sequence_identity": plan["sequence_identity"],
        "terminal_status": "premutation_hard_stop",
        "last_role": "construct",
        "action_claimed": False,
        "product_mutated": False,
        "infrastructure_mutated": False,
        "mutation_scope": "none",
        "transition_state": None,
        "transition_committed": False,
        "forward_state_possible": False,
        "state_restore_scope": "p08_state_and_public",
        "trusted_time_history_restored": False,
        "role_counts": {},
        "capture_count": 0,
        "capture_chain_digest": contract_v1.digest_value([]),
        "invocation_failures": 0,
        "capture_persistence_failures": 0,
        "raw_output_included": False,
    }
    terminal = {**body, "receipt_digest": contract_v1.digest_value(body)}
    try:
        terminal = supervisor_v1._validate_terminal(contract, plan, terminal)
    except supervisor_v1.SupervisorError:
        raise GuardianError("guardian_plan_terminal_rejected") from None
    path = sequence / "GUARDIAN.RECOVERY.TERMINAL.json"
    return _persist_exact(
        path,
        terminal,
        lambda observed: supervisor_v1._validate_terminal(
            contract, plan, observed
        ),
    )


def _load_sequence_terminal_optional(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> dict[str, object] | None:
    sequence = Path(str(plan["execution"]["root"]))
    sequence = adapter_v1.sequence_root(contract, plan)
    for name in ("GUARDIAN.RECOVERY.TERMINAL.json", "TERMINAL.json"):
        path = sequence / name
        if not path.exists() and not path.is_symlink():
            continue
        try:
            return supervisor_v1._validate_terminal(
                contract, plan, supervisor_v1._load_private_evidence(path)
            )
        except (supervisor_v1.SupervisorError, contract_v1.ContractError):
            if name == "GUARDIAN.RECOVERY.TERMINAL.json":
                raise GuardianError("guardian_recovery_terminal_rejected") from None
            # A missing/invalid accepted terminal never authorizes preserving
            # the target.  Valid role evidence may still drive convergence.
            return None
    return None


def _load_exact_discharge(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    guardian_root: Path,
    *,
    materialize_strategy_terminal: bool = True,
) -> dict[str, object] | None:
    result_path = guardian_root / "ACCEPTED.RESULT.json"
    terminal_path = guardian_root / "ACCEPTED.TERMINAL.json"
    discharge_path = guardian_root / "DISCHARGE.json"
    if not (
        (result_path.exists() or result_path.is_symlink())
        and (terminal_path.exists() or terminal_path.is_symlink())
        and (discharge_path.exists() or discharge_path.is_symlink())
    ):
        return None
    try:
        guardian_terminal = _read_exact(
            terminal_path,
            lambda observed: contract_v1.validate_guardian_terminal(
                contract, obligation, observed
            ),
        )
        _read_exact(
            discharge_path,
            lambda observed: contract_v1.validate_guardian_discharge(
                contract,
                obligation,
                guardian_terminal,
                observed,
            ),
        )
        plan = _load_plan_optional(contract, obligation)
        if plan is None:
            raise GuardianError("guardian_discharge_plan_missing")
        terminal = _load_sequence_terminal_optional(contract, plan)
        if terminal is None:
            raise GuardianError("guardian_discharge_terminal_rejected")
        accepted_result = _read_exact(
            result_path,
            lambda observed: supervisor_v1._validate_terminal(
                contract, plan, observed
            ),
        )
        generation = int(guardian_terminal["manager_generation"])
        child = _read_exact(
            guardian_root / f"CHILD.{generation}.json",
            lambda observed: contract_v1.validate_guardian_child(
                contract, obligation, observed
            ),
        )
        entry = _entry_root(
            contract, obligation, generation=generation, purpose="forward"
        )
        intent = _read_exact(
            entry / "INTENT.json",
            lambda observed: launcher_v1.validate_supervisor_bootstrap_intent(
                contract, observed
            ),
        )
        capture = _read_exact(
            entry / "CAPTURE.json",
            lambda observed: launcher_v1.validate_supervisor_bootstrap_capture(
                contract, intent, observed
            ),
        )
        if (
            terminal["terminal_status"] != "accepted"
            or guardian_terminal["terminal_status"] != "accepted"
            or guardian_terminal["plan_digest"] != plan["plan_digest"]
            or accepted_result != terminal
            or guardian_terminal["child_terminal_digest"]
            != terminal["receipt_digest"]
            or guardian_terminal["result_digest"]
            != contract_v1.digest_value(accepted_result)
            or guardian_terminal["acceptance_nonce"]
            != plan["invocation_nonce"]
            or child["child_entry_nonce"] != entry.name
            or child["child_intent_digest"] != intent["intent_digest"]
            or intent["sequence_identity"] != obligation["sequence_identity"]
            or intent["recover_plan"] is not None
            or capture["capture_digest"]
            != guardian_terminal["child_capture_digest"]
            or capture["canonical_result"] != accepted_result
            or capture["canonical_status"] != "complete"
            or capture["stderr_size"] != 0
            or capture["orphan_count"] != 0
        ):
            raise GuardianError("guardian_discharge_terminal_rejected")
        if materialize_strategy_terminal:
            _persist_strategy_launch_terminal(
                contract,
                obligation,
                guardian_root=guardian_root,
                guardian_terminal=guardian_terminal,
            )
        else:
            _read_strategy_launch_terminal(
                contract, obligation, guardian_terminal
            )
        return terminal
    except (
        adapter_v1.AdapterError,
        contract_v1.ContractError,
        GuardianError,
        supervisor_v1.SupervisorError,
    ):
        return None


def _load_exact_lifecycle_terminal(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    guardian_root: Path,
    *,
    materialize_strategy_terminal: bool = True,
) -> dict[str, object] | None:
    """Authorize manager lifecycle success from durable validated evidence."""
    discharged = _load_exact_discharge(
        contract,
        obligation,
        guardian_root,
        materialize_strategy_terminal=materialize_strategy_terminal,
    )
    if discharged is not None:
        return discharged
    path = guardian_root / "HARDSTOP.TERMINAL.json"
    if not path.exists() and not path.is_symlink():
        return None
    hard_stop = _read_exact(
        path,
        lambda observed: contract_v1.validate_guardian_terminal(
            contract, obligation, observed
        ),
    )
    if hard_stop["terminal_status"] == "accepted":
        raise GuardianError("guardian_hard_stop_rejected")
    plan = _load_plan_optional(contract, obligation)
    if hard_stop["plan_digest"] is None:
        if (
            hard_stop["terminal_status"] != "premutation_hard_stop"
            or hard_stop["child_terminal_digest"] is not None
            or hard_stop["recovery_count"] != 0
            or plan is not None
        ):
            raise GuardianError("guardian_hard_stop_rejected")
        if materialize_strategy_terminal:
            _persist_strategy_launch_terminal(
                contract,
                obligation,
                guardian_root=guardian_root,
                guardian_terminal=hard_stop,
            )
        else:
            _read_strategy_launch_terminal(contract, obligation, hard_stop)
        return hard_stop
    if plan is None or hard_stop["plan_digest"] != plan["plan_digest"]:
        raise GuardianError("guardian_hard_stop_rejected")
    sequence_terminal = _load_sequence_terminal_optional(contract, plan)
    if (
        sequence_terminal is None
        or sequence_terminal["terminal_status"]
        != hard_stop["terminal_status"]
        or sequence_terminal["receipt_digest"]
        != hard_stop["child_terminal_digest"]
        or contract_v1.digest_value(sequence_terminal)
        != hard_stop["result_digest"]
    ):
        raise GuardianError("guardian_hard_stop_rejected")
    if materialize_strategy_terminal:
        _persist_strategy_launch_terminal(
            contract,
            obligation,
            guardian_root=guardian_root,
            guardian_terminal=hard_stop,
        )
    else:
        _read_strategy_launch_terminal(contract, obligation, hard_stop)
    return hard_stop


def _prior_child(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    guardian_root: Path,
) -> dict[str, object] | None:
    children = []
    for generation in (2, 1):
        path = guardian_root / f"CHILD.{generation}.json"
        if not path.exists() and not path.is_symlink():
            continue
        try:
            children.append(
                contract_v1.validate_guardian_child(
                    contract, obligation, adapter_v1._read_json(path)
                )
            )
        except (contract_v1.ContractError, adapter_v1.AdapterError):
            raise GuardianError("guardian_child_rejected") from None
    return children[0] if children else None


def _quiesce_prior_child(child: Mapping[str, object] | None) -> int:
    if child is None:
        return 0
    pid = int(child["pid"])
    try:
        state, process_group, start_ticks = _read_process_identity(pid)
    except GuardianError:
        return 0
    if (
        process_group != child["process_group"]
        or start_ticks != child["start_ticks"]
        or process_group != pid
    ):
        raise GuardianError("guardian_child_identity_rejected")
    # A zombie with the exact immutable PID/start/process-group identity has no
    # executable authority left.  Do not generalize this to kill(pid, 0): that
    # probe remains true for zombies and is not a quiescence oracle.
    if state == "Z":
        return 0
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        return 0
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        try:
            observed_state, observed_group, observed_ticks = _read_process_identity(pid)
        except GuardianError:
            return 0
        if (observed_group, observed_ticks) != (process_group, start_ticks):
            raise GuardianError("guardian_child_identity_rejected")
        if observed_state == "Z":
            return 0
        time.sleep(0.02)
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        return 0
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        try:
            observed_state, observed_group, observed_ticks = _read_process_identity(pid)
        except GuardianError:
            return 0
        if (observed_group, observed_ticks) != (process_group, start_ticks):
            raise GuardianError("guardian_child_identity_rejected")
        if observed_state == "Z":
            return 0
        time.sleep(0.02)
    return launcher_v1._process_group_orphan_count(process_group)


def _run_forward_child(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    manager_intent: Mapping[str, object],
    *,
    guardian_root: Path,
    generation: int,
    remaining_seconds: int,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    generation_record = _read_exact(
        guardian_root / f"GENERATION.{generation}.json",
        lambda observed: contract_v1.validate_guardian_generation(
            contract, obligation, manager_intent, observed
        ),
    )
    if (
        generation_record["manager_pid"] != os.getpid()
        or generation_record["manager_process_group"] != os.getpgrp()
    ):
        raise GuardianError("guardian_generation_rejected")
    entry = _entry_root(
        contract, obligation, generation=generation, purpose="forward"
    )
    _ensure_private_directory(entry.parent)
    if entry.exists() or entry.is_symlink():
        raise GuardianError("guardian_entry_replay_rejected")
    _ensure_private_directory(entry)
    intent_path = entry / "INTENT.json"
    capture_path = entry / "CAPTURE.json"
    parent_pipe_fds = os.pipe2(os.O_CLOEXEC)
    parent_nonce = secrets.token_bytes(32)
    target = Path(str(obligation["target_source_path"]))
    inventory, directories = _target_closure(contract, target)
    intent = launcher_v1.build_supervisor_bootstrap_intent(
        contract,
        entry_nonce=entry.name,
        sequence_identity=str(obligation["sequence_identity"]),
        intent_path=intent_path,
        contract_path=Path(str(obligation["contract_path"])),
        root=Path(str(obligation["root"])),
        backend=str(obligation["backend"]),
        target_source_path=target,
        target_inventory=inventory,
        target_directories=directories,
        acceptance_scope_digest=str(obligation["acceptance_scope_digest"]),
        recover_plan=None,
        origin_entry_nonce=None,
        origin_capture_digest=None,
        parent_pipe_fd=parent_pipe_fds[0],
        parent_nonce_sha256=sha256(parent_nonce).hexdigest(),
    )
    _persist_exact(
        intent_path,
        intent,
        lambda observed: launcher_v1.validate_supervisor_bootstrap_intent(
            contract, observed
        ),
    )

    def child_started(child: subprocess.Popen[bytes]) -> None:
        process_group, start_ticks = _read_start_ticks(child.pid)
        if process_group != child.pid:
            raise GuardianError("guardian_child_process_group_rejected")
        child_value = contract_v1.build_guardian_child(
            contract,
            obligation,
            generation=generation,
            pid=child.pid,
            process_group=process_group,
            start_ticks=start_ticks,
            child_entry_nonce=entry.name,
            child_intent_digest=str(intent["intent_digest"]),
            argv_digest=contract_v1.digest_value(intent["argv"]),
            parent_nonce_sha256=sha256(parent_nonce).hexdigest(),
        )
        _persist_exact(
            guardian_root / f"CHILD.{generation}.json",
            child_value,
            lambda observed: contract_v1.validate_guardian_child(
                contract, obligation, observed
            ),
        )

    capture = launcher_v1.run_supervisor_bootstrap_capture(
        contract,
        intent,
        parent_pipe_fds=parent_pipe_fds,
        parent_nonce=parent_nonce,
        child_started=child_started,
        guardian_parent_identity=(
            int(generation_record["manager_pid"]),
            int(generation_record["manager_start_ticks"]),
        ),
        hard_deadline_seconds_override=min(
            remaining_seconds, int(intent["hard_deadline_seconds"])
        ),
    )
    capture = _persist_exact_guarded(
        contract,
        obligation,
        capture_path,
        capture,
        lambda observed: launcher_v1.validate_supervisor_bootstrap_capture(
            contract, intent, observed
        ),
        generation=generation,
        record_kind="forward_capture",
    )
    result = capture["canonical_result"]
    if not isinstance(result, Mapping):
        raise GuardianError("guardian_child_indeterminate")
    plan, terminal = _canonical_sequence_terminal(contract, obligation, result)
    return capture, plan, terminal


def _run_recovery_child(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    *,
    guardian_root: Path,
    generation: int,
    plan: Mapping[str, object],
    child: Mapping[str, object],
) -> tuple[dict[str, object], dict[str, object] | None]:
    manager_intent = contract_v1.validate_guardian_manager_intent(
        contract,
        obligation,
        adapter_v1._read_json(guardian_root / "MANAGER.INTENT.json"),
    )
    generation_record = _read_exact(
        guardian_root / f"GENERATION.{generation}.json",
        lambda observed: contract_v1.validate_guardian_generation(
            contract, obligation, manager_intent, observed
        ),
    )
    if (
        generation_record["manager_pid"] != os.getpid()
        or generation_record["manager_process_group"] != os.getpgrp()
    ):
        raise GuardianError("guardian_generation_rejected")
    entry = _entry_root(
        contract, obligation, generation=generation, purpose="recovery"
    )
    _ensure_private_directory(entry.parent)
    if entry.exists() or entry.is_symlink():
        raise GuardianError("guardian_recovery_entry_replay_rejected")
    _ensure_private_directory(entry)
    intent_path = entry / "INTENT.json"
    capture_path = entry / "CAPTURE.json"
    target = Path(str(obligation["target_source_path"]))
    inventory, directories = _target_closure(contract, target)
    original_capture_digest: str | None = None
    original_capture_path = (
        _entry_root(
            contract,
            obligation,
            generation=int(child["generation"]),
            purpose="forward",
        )
        / "CAPTURE.json"
    )
    if original_capture_path.exists() or original_capture_path.is_symlink():
        try:
            original_intent = launcher_v1.validate_supervisor_bootstrap_intent(
                contract,
                adapter_v1._read_json(original_capture_path.parent / "INTENT.json"),
            )
            original_capture = launcher_v1.validate_supervisor_bootstrap_capture(
                contract,
                original_intent,
                adapter_v1._read_json(original_capture_path),
            )
            original_capture_digest = str(original_capture["capture_digest"])
        except (launcher_v1.LauncherError, adapter_v1.AdapterError):
            original_capture_digest = None
    parent_pipe_fds = os.pipe2(os.O_CLOEXEC)
    parent_nonce = secrets.token_bytes(32)
    intent = launcher_v1.build_supervisor_bootstrap_intent(
        contract,
        entry_nonce=entry.name,
        sequence_identity=str(obligation["sequence_identity"]),
        intent_path=intent_path,
        contract_path=Path(str(obligation["contract_path"])),
        root=Path(str(obligation["root"])),
        backend=str(obligation["backend"]),
        target_source_path=target,
        target_inventory=inventory,
        target_directories=directories,
        acceptance_scope_digest=None,
        recover_plan=Path(str(obligation["plan_path"])),
        origin_entry_nonce=str(obligation["sequence_identity"]),
        origin_capture_digest=original_capture_digest,
        guardian_obligation_digest=str(obligation["obligation_digest"]),
        guardian_child_digest=str(child["child_digest"]),
        parent_pipe_fd=parent_pipe_fds[0],
        parent_nonce_sha256=sha256(parent_nonce).hexdigest(),
    )
    _persist_exact(
        intent_path,
        intent,
        lambda observed: launcher_v1.validate_supervisor_bootstrap_intent(
            contract, observed
        ),
    )
    capture = launcher_v1.run_supervisor_bootstrap_capture(
        contract,
        intent,
        parent_pipe_fds=parent_pipe_fds,
        parent_nonce=parent_nonce,
        guardian_parent_identity=(
            int(generation_record["manager_pid"]),
            int(generation_record["manager_start_ticks"]),
        ),
        hard_deadline_seconds_override=int(
            contract["launcher"]["supervisor_bootstrap"]["guardian"][
                "convergence_grace_seconds"
            ]
        ),
    )
    try:
        capture = _persist_exact_guarded(
            contract,
            obligation,
            capture_path,
            capture,
            lambda observed: launcher_v1.validate_supervisor_bootstrap_capture(
                contract, intent, observed
            ),
            generation=generation,
            record_kind="recovery_capture",
        )
    except GuardianError:
        recovered = _load_sequence_terminal_optional(contract, plan)
        if recovered is not None and recovered["terminal_status"] != "accepted":
            return recovered, None
        raise
    result = capture["canonical_result"]
    if isinstance(result, Mapping):
        _, terminal = _canonical_sequence_terminal(contract, obligation, result)
    else:
        terminal = _load_sequence_terminal_optional(contract, plan)
        if terminal is None:
            raise GuardianError("guardian_recovery_indeterminate")
    if terminal["terminal_status"] not in {
        "converged_hard_stop",
        "convergence_failed_hard_stop",
        "premutation_hard_stop",
    }:
        raise GuardianError("guardian_recovery_terminal_rejected")
    return terminal, capture


def _persist_guardian_hard_stop(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    *,
    guardian_root: Path,
    generation: int,
    terminal: Mapping[str, object] | None,
    capture: Mapping[str, object] | None,
    recovery_count: int,
    orphan_count: int,
) -> dict[str, object]:
    if terminal is None:
        status = "premutation_hard_stop"
        product_state = "unmodified"
        plan_digest = None
        child_terminal_digest = None
        result_digest = contract_v1.digest_value(
            {
                "obligation_digest": obligation["obligation_digest"],
                "state": "plan_absent",
                "mutation": False,
            }
        )
    else:
        status = str(terminal["terminal_status"])
        product_state = {
            "premutation_hard_stop": "unmodified",
            "converged_hard_stop": "predecessor_converged",
            "convergence_failed_hard_stop": "unknown",
        }.get(status, "unknown")
        if status not in {
            "premutation_hard_stop",
            "converged_hard_stop",
            "convergence_failed_hard_stop",
        }:
            raise GuardianError("guardian_hard_stop_status_rejected")
        plan_digest = str(terminal["plan_digest"])
        child_terminal_digest = str(terminal["receipt_digest"])
        result_digest = contract_v1.digest_value(terminal)
    value = contract_v1.build_guardian_terminal(
        contract,
        obligation,
        terminal_status=status,
        product_state=product_state,
        plan_digest=plan_digest,
        result_digest=result_digest,
        child_capture_digest=(
            str(capture["capture_digest"]) if capture is not None else None
        ),
        child_terminal_digest=child_terminal_digest,
        acceptance_nonce=None,
        recovery_count=recovery_count,
        manager_generation=generation,
        orphan_count=orphan_count,
    )
    path = guardian_root / "HARDSTOP.TERMINAL.json"
    if path.exists() or path.is_symlink():
        try:
            observed = contract_v1.validate_guardian_terminal(
                contract, obligation, adapter_v1._read_json(path)
            )
        except (contract_v1.ContractError, adapter_v1.AdapterError):
            raise GuardianError("guardian_hard_stop_rejected") from None
        if observed != value:
            raise GuardianError("guardian_hard_stop_replay_rejected")
        projected = observed
    else:
        projected = _persist_exact_guarded(
            contract,
            obligation,
            path,
            value,
            lambda observed: contract_v1.validate_guardian_terminal(
                contract, obligation, observed
            ),
            generation=generation,
            record_kind="hardstop_terminal",
        )
    # A fixed strategy terminal is authority only after the local hard-stop is
    # re-opened and its PLAN/sequence semantics validate, not merely after the
    # guardian-terminal schema accepts its bytes.
    finalized = _load_exact_lifecycle_terminal(
        contract, obligation, guardian_root
    )
    if finalized != projected:
        raise GuardianError("guardian_hard_stop_rejected")
    return finalized


def _close_without_discharge(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    *,
    guardian_root: Path,
    generation: int,
    capture: Mapping[str, object] | None,
) -> dict[str, object]:
    child = _prior_child(contract, obligation, guardian_root)
    orphan_count = _quiesce_prior_child(child)
    plan = _load_plan_optional(contract, obligation)
    if plan is None:
        return _persist_guardian_hard_stop(
            contract,
            obligation,
            guardian_root=guardian_root,
            generation=generation,
            terminal=None,
            capture=capture,
            recovery_count=0,
            orphan_count=orphan_count,
        )
    terminal = _load_sequence_terminal_optional(contract, plan)
    recovery_count = 0
    if terminal is None or terminal["terminal_status"] == "accepted":
        if terminal is None:
            terminal = _persist_plan_only_premutation_terminal(
                contract, obligation, plan
            )
        if terminal is not None and terminal["terminal_status"] == "premutation_hard_stop":
            recovery_count = 0
        else:
            if child is None:
                raise GuardianError("guardian_recovery_child_missing")
            terminal, recovery_capture = _run_recovery_child(
                contract,
                obligation,
                guardian_root=guardian_root,
                generation=generation,
                plan=plan,
                child=child,
            )
            recovery_count = 1
            if recovery_capture is not None:
                capture = recovery_capture
    elif int(terminal.get("role_counts", {}).get("recover", 0)) == 1:
        recovery_count = 1
    _persist_guardian_hard_stop(
        contract,
        obligation,
        guardian_root=guardian_root,
        generation=generation,
        terminal=terminal,
        capture=capture,
        recovery_count=recovery_count,
        orphan_count=orphan_count,
    )
    return dict(terminal)


def run_manager(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    manager_intent: Mapping[str, object],
) -> dict[str, object]:
    guardian_root = Path(str(manager_intent["obligation_path"])).parent
    discharged = _load_exact_discharge(contract, obligation, guardian_root)
    if discharged is not None:
        return discharged
    generation = _claim_generation(
        contract, obligation, manager_intent, guardian_root
    )
    remaining_seconds = _remaining_guardian_seconds(obligation)
    if generation == 2 or remaining_seconds == 0:
        return _close_without_discharge(
            contract,
            obligation,
            guardian_root=guardian_root,
            generation=generation,
            capture=None,
        )
    capture: dict[str, object] | None = None
    try:
        capture, plan, terminal = _run_forward_child(
            contract,
            obligation,
            manager_intent,
            guardian_root=guardian_root,
            generation=generation,
            remaining_seconds=remaining_seconds,
        )
        if terminal["terminal_status"] != "accepted":
            return _close_without_discharge(
                contract,
                obligation,
                guardian_root=guardian_root,
                generation=generation,
                capture=capture,
            )
        return _accepted_discharge(
            contract,
            obligation,
            guardian_root=guardian_root,
            generation=generation,
            capture=capture,
            plan=plan,
            terminal=terminal,
        )
    except Exception:
        return _close_without_discharge(
            contract,
            obligation,
            guardian_root=guardian_root,
            generation=generation,
            capture=capture,
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = adapter_v1.CanonicalArgumentParser(allow_abbrev=False)
    parser.add_argument("--guardian-contract", type=Path, required=True)
    parser.add_argument("--guardian-obligation", type=Path, required=True)
    terminal: dict[str, object]
    durable_terminal = False
    contract: dict[str, object] | None = None
    obligation: dict[str, object] | None = None
    guardian_root: Path | None = None
    try:
        values = parser.parse_args(argv)
        contract = _load_contract(values.guardian_contract)
        obligation = _load_obligation(contract, values.guardian_obligation)
        guardian_root = values.guardian_obligation.parent
        manager_intent_path = values.guardian_obligation.parent / "MANAGER.INTENT.json"
        manager_intent = contract_v1.validate_guardian_manager_intent(
            contract,
            obligation,
            adapter_v1._read_json(manager_intent_path),
        )
        _verify_manager_process(
            contract, obligation, manager_intent, argv=argv
        )
        terminal = run_manager(contract, obligation, manager_intent)
        durable_terminal = (
            _load_exact_lifecycle_terminal(
                contract, obligation, guardian_root
            )
            is not None
        )
    except Exception:
        if (
            contract is not None
            and obligation is not None
            and guardian_root is not None
        ):
            try:
                durable_terminal = (
                    _load_exact_lifecycle_terminal(
                        contract, obligation, guardian_root
                    )
                    is not None
                )
            except GuardianError:
                durable_terminal = False
        terminal = {
            "schema": contract_v1.SUPERVISOR_ENTRY_SCHEMA,
            "status": "indeterminate",
            "stage": "source_owned_entry",
            "product_state": "unknown",
            "raw_output_included": False,
            "retry_authorized": False,
        }
    sys.stdout.buffer.write(contract_v1.canonical_bytes(terminal))
    # A durable final product terminal is lifecycle success even when the
    # product result is a hard stop.  Only a manager failure without durable
    # terminal evidence asks the transient manager for one bounded re-entry.
    return 0 if durable_terminal else 2


if __name__ == "__main__":
    raise SystemExit(main())
