#!/usr/bin/env python3
"""Source-owned, planless bootstrap and raw-free supervisor capture boundary."""
from __future__ import annotations

import os
from pathlib import Path
import json
import secrets
import stat
import subprocess
import sys
import time
from typing import Mapping, Sequence

import p08_activation_contract_v1 as contract_v1
import p08_activation_guardian_manager_v1 as guardian_manager_v1
import p08_activation_launcher_v1 as launcher_v1
import p08_activation_production_adapter_v1 as adapter_v1
import p08_activation_supervisor_v1 as supervisor_v1


class BootstrapError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        cause_source: str = "bootstrap",
        subcategory: str | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.cause_source = cause_source
        self.subcategory = subcategory if subcategory is not None else code


def _entry_failure() -> dict[str, object]:
    return {
        "schema": contract_v1.SUPERVISOR_ENTRY_SCHEMA,
        "status": "indeterminate",
        "stage": "source_owned_entry",
        "product_state": "unknown",
        "raw_output_included": False,
        "retry_authorized": False,
    }


class _PreclaimTracker:
    """Consume the contract-generated phase map without a local allowlist."""

    def __init__(
        self,
        contract: Mapping[str, object],
        top_level_intent: Mapping[str, object],
        *,
        root: Path,
        backend: str,
        completed_phases: Sequence[str],
    ) -> None:
        preclaim = contract["launcher"]["top_level_entry"]["preclaim"]
        self.contract = contract
        self.intent = top_level_intent
        self.root = root
        self.backend = backend
        self.rows = list(preclaim["ordered_phases"])
        self.completed = list(completed_phases)
        expected = [row["phase"] for row in self.rows[: len(self.completed)]]
        if self.completed != expected:
            raise BootstrapError("bootstrap_top_level_intent_rejected")
        self.current: str | None = None

    def _row(self, phase: str) -> Mapping[str, object]:
        matches = [row for row in self.rows if row["phase"] == phase]
        if len(matches) != 1:
            raise RuntimeError("preclaim phase authority mismatch")
        return matches[0]

    def enter(self, phase: str) -> None:
        if self.current is not None:
            self.completed.append(self.current)
        expected_index = len(self.completed)
        if (
            expected_index >= len(self.rows)
            or self.rows[expected_index]["phase"] != phase
        ):
            raise RuntimeError("preclaim phase sequence mismatch")
        self.current = phase
        if self.backend != "synthetic":
            return
        fixed = self.contract["production_adapter"]["fixed_paths"]
        try:
            control = adapter_v1._synthetic_control_path(
                self.contract,
                adapter_v1._rooted(self.root, str(fixed["state_root"]))
                / "synthetic-control.json",
            )
        except adapter_v1.AdapterError as error:
            raise BootstrapError(
                self.rejection_category(),
                cause_source="adapter",
                subcategory=error.code,
            ) from None
        row = self._row(phase)
        if (
            control["fault_role"] == "construct"
            and control["fault_kind"] == row["synthetic_fault_kind"]
        ):
            raise BootstrapError(str(row["rejection_categories"][0]))
        if control["fault_role"] == "construct":
            matches = [
                item
                for item in row["synthetic_adapter_fault_kinds"]
                if item["fault_kind"] == control["fault_kind"]
            ]
            if len(matches) == 1:
                raise BootstrapError(
                    str(row["rejection_categories"][0]),
                    cause_source="adapter",
                    subcategory=str(matches[0]["subcategory"]),
                )
        if (
            control["fault_role"] == "construct"
            and control["fault_kind"] == "preclaim_unexpected_exception"
            and phase == "execution_contract"
        ):
            raise RuntimeError("synthetic unexpected preclaim failure")

    def finish(self) -> None:
        if self.current is None:
            raise RuntimeError("preclaim phase sequence incomplete")
        self.completed.append(self.current)
        self.current = None
        if self.completed != [row["phase"] for row in self.rows]:
            raise RuntimeError("preclaim phase sequence incomplete")

    def rejection_category(self) -> str:
        if self.current is None:
            raise RuntimeError("preclaim phase unavailable")
        return str(self._row(self.current)["rejection_categories"][0])

    def result(
        self,
        error: BaseException,
        *,
        bootstrap_pid: int,
        bootstrap_start_ticks: int,
        bootstrap_process_group: int,
    ) -> dict[str, object]:
        if self.current is None:
            raise BootstrapError("bootstrap_top_level_intent_rejected")
        row = self._row(self.current)
        supplied = error.code if isinstance(error, BootstrapError) else None
        cause_source = (
            error.cause_source if isinstance(error, BootstrapError) else "unexpected"
        )
        subcategory = (
            error.subcategory
            if isinstance(error, BootstrapError)
            else contract_v1.PRECLAIM_UNEXPECTED_SUBCATEGORY
        )
        source_categories = row["subcategory_sources"]
        typed_cause = (
            isinstance(source_categories, Mapping)
            and cause_source in source_categories
            and subcategory in source_categories[cause_source]
        )
        if supplied in row["rejection_categories"] and typed_cause:
            classification = "typed_rejection"
            category = supplied
        else:
            classification = "unexpected_indeterminate"
            category = str(
                self.contract["launcher"]["top_level_entry"]["preclaim"][
                    "unexpected_category"
                ]
            )
            cause_source = "unexpected"
            subcategory = contract_v1.PRECLAIM_UNEXPECTED_SUBCATEGORY
        return contract_v1.build_supervisor_preclaim_result(
            self.contract,
            self.intent,
            phase=self.current,
            category=category,
            cause_source=cause_source,
            subcategory=subcategory,
            classification=classification,
            completed_phases=self.completed,
            bootstrap_pid=bootstrap_pid,
            bootstrap_start_ticks=bootstrap_start_ticks,
            bootstrap_process_group=bootstrap_process_group,
        )


def _persist_preclaim_result(
    contract: Mapping[str, object],
    top_level_intent: Mapping[str, object],
    result: Mapping[str, object],
) -> dict[str, object]:
    preclaim = contract["launcher"]["top_level_entry"]["preclaim"]
    path = (
        Path(str(top_level_intent["intent_path"])).parent
        / str(preclaim["result_filename"])
    )
    validated = contract_v1.validate_supervisor_preclaim_result(
        contract, top_level_intent, result
    )
    try:
        if not path.exists() and not path.is_symlink():
            launcher_v1.persist_capture_o_excl(path, validated)
        raw = launcher_v1._read_regular_bytes(path)
        parsed = json.loads(raw)
        observed = contract_v1.validate_supervisor_preclaim_result(
            contract, top_level_intent, parsed
        )
        if raw != contract_v1.canonical_bytes(observed) or observed != validated:
            raise BootstrapError("bootstrap_preclaim_result_persistence_rejected")
        return observed
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        contract_v1.ContractError,
        launcher_v1.LauncherError,
    ):
        raise BootstrapError("bootstrap_preclaim_result_persistence_rejected") from None


def _load_top_level_intent(
    contract: Mapping[str, object],
) -> dict[str, object] | None:
    path = os.environ.get("MYUNA_P08_TOP_LEVEL_ENTRY_INTENT")
    descriptor = os.environ.get("MYUNA_P08_TOP_LEVEL_PARENT_FD")
    if path is None and descriptor is None:
        return None
    if not path:
        raise BootstrapError("bootstrap_top_level_intent_rejected")
    try:
        intent = launcher_v1.validate_top_level_entry_intent(
            contract, adapter_v1._read_json(Path(path))
        )
    except (adapter_v1.AdapterError, launcher_v1.LauncherError):
        raise BootstrapError("bootstrap_top_level_intent_rejected") from None
    return intent


def _verify_top_level_intent_binding(
    intent: Mapping[str, object],
    *,
    contract_path: Path,
    root: Path,
    backend: str,
    target_source: Path,
    acceptance_scope_digest: str,
) -> None:
    descriptor = os.environ.get("MYUNA_P08_TOP_LEVEL_PARENT_FD")
    if (
        not descriptor
        or intent["contract_path"] != str(contract_path)
        or intent["root"] != str(root)
        or intent["backend"] != backend
        or intent["target_source_path"] != str(target_source)
        or intent["acceptance_scope_digest"] != acceptance_scope_digest
        or descriptor != str(intent["parent_pipe_fd"])
    ):
        raise BootstrapError("bootstrap_top_level_intent_rejected")


def _load_contract(path: Path) -> dict[str, object]:
    try:
        return contract_v1.validate_contract(adapter_v1._read_json(path))
    except (adapter_v1.AdapterError, contract_v1.ContractError):
        raise BootstrapError("bootstrap_contract_rejected") from None


def _ensure_private_directory(path: Path, *, create: bool) -> None:
    try:
        if create:
            path.mkdir(mode=0o700, exist_ok=False)
            os.chmod(path, 0o700)
        details = path.lstat()
    except OSError:
        raise BootstrapError("bootstrap_namespace_rejected") from None
    if (
        not stat.S_ISDIR(details.st_mode)
        or stat.S_ISLNK(details.st_mode)
        or stat.S_IMODE(details.st_mode) != 0o700
        or details.st_uid != os.getuid()
        or details.st_gid != os.getgid()
    ):
        raise BootstrapError("bootstrap_namespace_rejected")


def _guardian_directory(
    contract: Mapping[str, object], root: Path, entry_nonce: str
) -> Path:
    strategy = _strategy_directory(contract, root)
    try:
        guardians = strategy / "guardians"
        if guardians.exists() or guardians.is_symlink():
            _ensure_private_directory(guardians, create=False)
        else:
            _ensure_private_directory(guardians, create=True)
            adapter_v1._fsync_directory(strategy)
        selected = guardians / entry_nonce
        _ensure_private_directory(selected, create=True)
        adapter_v1._fsync_directory(guardians)
        return selected
    except (OSError, adapter_v1.AdapterError):
        raise BootstrapError("bootstrap_namespace_rejected") from None


def _strategy_directory(
    contract: Mapping[str, object], root: Path
) -> Path:
    fixed = contract["production_adapter"]["fixed_paths"]
    strategy = adapter_v1._rooted(root, str(fixed["strategy_root"]))
    try:
        strategy.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = adapter_v1._directory(strategy.parent, owner=True)
        if stat.S_IMODE(parent.st_mode) & 0o022:
            raise BootstrapError("bootstrap_namespace_rejected")
        if strategy.exists() or strategy.is_symlink():
            _ensure_private_directory(strategy, create=False)
        else:
            _ensure_private_directory(strategy, create=True)
            adapter_v1._fsync_directory(strategy.parent)
        return strategy
    except (OSError, adapter_v1.AdapterError):
        raise BootstrapError("bootstrap_namespace_rejected") from None


def _inspect_strategy_namespace(
    contract: Mapping[str, object], *, root: Path
) -> tuple[Path, list[str]]:
    fixed = contract["production_adapter"]["fixed_paths"]
    strategy = adapter_v1._rooted(root, str(fixed["strategy_root"]))
    try:
        parent = strategy.parent
        if parent.exists() or parent.is_symlink():
            details = adapter_v1._directory(parent, owner=True)
            if stat.S_IMODE(details.st_mode) & 0o022:
                raise BootstrapError("bootstrap_namespace_rejected")
        if not strategy.exists() and not strategy.is_symlink():
            return strategy, []
        _ensure_private_directory(strategy, create=False)
        inventory = sorted(item.name for item in strategy.iterdir())
    except (OSError, adapter_v1.AdapterError):
        raise BootstrapError("bootstrap_namespace_rejected") from None
    return strategy, inventory


def _build_strategy_launch_claim(
    contract: Mapping[str, object],
    *,
    root: Path,
    backend: str,
    target_source: Path,
    target_inventory: list[dict[str, object]],
    target_directories: list[dict[str, object]],
    acceptance_scope_digest: str,
    prestate_identity: str,
    entry_nonce: str,
) -> dict[str, object]:
    try:
        return contract_v1.build_strategy_launch_claim(
            contract,
            entry_nonce=entry_nonce,
            root=str(root),
            backend=backend,
            target_source_path=str(target_source),
            target_inventory_digest=contract_v1.digest_value(target_inventory),
            target_directories_digest=contract_v1.digest_value(target_directories),
            acceptance_scope_digest=acceptance_scope_digest,
            prestate_identity=prestate_identity,
        )
    except contract_v1.ContractError:
        raise BootstrapError("bootstrap_strategy_claim_rejected") from None


def _prepare_strategy_launch_claim(
    contract: Mapping[str, object],
    *,
    root: Path,
    backend: str,
    target_source: Path,
    target_inventory: list[dict[str, object]],
    target_directories: list[dict[str, object]],
    acceptance_scope_digest: str,
    prestate_identity: str,
    entry_nonce: str,
) -> dict[str, object]:
    strategy, preclaim_inventory = _inspect_strategy_namespace(contract, root=root)
    path = strategy / "STRATEGY.LAUNCH.CLAIM.json"
    if path.exists() or path.is_symlink():
        try:
            contract_v1.validate_strategy_launch_claim(
                contract, adapter_v1._read_json(path)
            )
        except (adapter_v1.AdapterError, contract_v1.ContractError):
            raise BootstrapError("bootstrap_strategy_claim_rejected") from None
        raise BootstrapError("bootstrap_strategy_already_claimed")
    if preclaim_inventory:
        raise BootstrapError("bootstrap_strategy_preclaim_residue_rejected")
    return _build_strategy_launch_claim(
        contract,
        root=root,
        backend=backend,
        target_source=target_source,
        target_inventory=target_inventory,
        target_directories=target_directories,
        acceptance_scope_digest=acceptance_scope_digest,
        prestate_identity=prestate_identity,
        entry_nonce=entry_nonce,
    )


def _persist_strategy_launch_claim(
    contract: Mapping[str, object],
    *,
    root: Path,
    claim: Mapping[str, object],
) -> dict[str, object]:
    strategy = _strategy_directory(contract, root)
    path = strategy / "STRATEGY.LAUNCH.CLAIM.json"
    try:
        if sorted(item.name for item in strategy.iterdir()):
            if path.exists() and not path.is_symlink():
                try:
                    contract_v1.validate_strategy_launch_claim(
                        contract, adapter_v1._read_json(path)
                    )
                except (adapter_v1.AdapterError, contract_v1.ContractError):
                    pass
                else:
                    raise BootstrapError("bootstrap_strategy_already_claimed")
            raise BootstrapError("bootstrap_strategy_claim_rejected")
        launcher_v1.persist_capture_o_excl(path, claim)
        observed = contract_v1.validate_strategy_launch_claim(
            contract, adapter_v1._read_json(path)
        )
    except (OSError, adapter_v1.AdapterError, contract_v1.ContractError, launcher_v1.LauncherError):
        # A concurrent creator may have won between absence and O_EXCL.  Its
        # exact claim remains the sole authority; this invocation creates no
        # guardian or PLAN and returns fail-closed.
        if path.exists() and not path.is_symlink():
            try:
                contract_v1.validate_strategy_launch_claim(
                    contract, adapter_v1._read_json(path)
                )
            except (adapter_v1.AdapterError, contract_v1.ContractError):
                pass
            else:
                raise BootstrapError("bootstrap_strategy_already_claimed") from None
        raise BootstrapError("bootstrap_strategy_claim_rejected") from None
    if observed != claim:
        raise BootstrapError("bootstrap_strategy_claim_rejected")
    try:
        if sorted(item.name for item in strategy.iterdir()) != [path.name]:
            raise BootstrapError("bootstrap_strategy_claim_inventory_rejected")
    except OSError:
        raise BootstrapError("bootstrap_strategy_claim_inventory_rejected") from None
    return observed


def _claim_strategy_launch(
    contract: Mapping[str, object],
    *,
    root: Path,
    backend: str,
    target_source: Path,
    target_inventory: list[dict[str, object]],
    target_directories: list[dict[str, object]],
    acceptance_scope_digest: str,
    prestate_identity: str,
    entry_nonce: str,
) -> dict[str, object]:
    """Compatibility wrapper; production main uses the explicit split seam."""
    claim = _prepare_strategy_launch_claim(
        contract,
        root=root,
        backend=backend,
        target_source=target_source,
        target_inventory=target_inventory,
        target_directories=target_directories,
        acceptance_scope_digest=acceptance_scope_digest,
        prestate_identity=prestate_identity,
        entry_nonce=entry_nonce,
    )
    return _persist_strategy_launch_claim(contract, root=root, claim=claim)


def _persist_strategy_launch_premutation_terminal(
    contract: Mapping[str, object],
    claim: Mapping[str, object],
    outer_terminal: Mapping[str, object],
) -> dict[str, object]:
    value = contract_v1.build_strategy_launch_premutation_terminal(
        contract, claim, outer_terminal
    )
    path = Path(str(claim["terminal_path"]))
    try:
        if path.exists() or path.is_symlink():
            observed = contract_v1.validate_strategy_launch_premutation_terminal(
                contract,
                claim,
                outer_terminal,
                adapter_v1._read_json(path),
            )
            if observed != value:
                raise BootstrapError("bootstrap_strategy_terminal_replay_rejected")
            return observed
        launcher_v1.persist_capture_o_excl(path, value)
        return contract_v1.validate_strategy_launch_premutation_terminal(
            contract,
            claim,
            outer_terminal,
            adapter_v1._read_json(path),
        )
    except (
        OSError,
        adapter_v1.AdapterError,
        contract_v1.ContractError,
        launcher_v1.LauncherError,
    ):
        raise BootstrapError("bootstrap_strategy_terminal_rejected") from None


def _process_start_ticks(pid: int) -> int:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        return int(raw[raw.rindex(")") + 2 :].split()[19])
    except (OSError, ValueError, IndexError):
        raise BootstrapError("bootstrap_process_rejected") from None


def _verify_parent_process(
    contract: Mapping[str, object],
    *,
    contract_path: Path,
    root: Path,
    backend: str,
    target_source: Path,
    target_inventory: list[dict[str, object]],
    target_directories: list[dict[str, object]],
    acceptance_scope_digest: str | None,
    argv: Sequence[str] | None,
    validated_top_level_intent: Mapping[str, object] | None = None,
) -> None:
    direct_environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": os.pathsep.join(
            (str(target_source / "scripts"), str(target_source / "src"))
        ),
    }
    runtime = contract["runtime_identity"]
    expected_argv = [
        str(contract["interpreter"]["invocation_path"]),
        "-B",
        "-P",
        "-S",
        "-m",
        Path(contract_v1.SUPERVISOR_BOOTSTRAP_PATH).stem,
        "--activation-contract",
        str(contract_path),
    ]
    expected_argv.extend(
        [
            "--activation-root",
            str(root),
            "--activation-backend",
            backend,
            "--activation-target-source",
            str(target_source),
            "--acceptance-scope-digest",
            str(acceptance_scope_digest),
        ]
    )
    top_intent = os.environ.get("MYUNA_P08_TOP_LEVEL_ENTRY_INTENT")
    top_parent_fd = os.environ.get("MYUNA_P08_TOP_LEVEL_PARENT_FD")
    if top_intent is not None or top_parent_fd is not None:
        if not top_intent or not top_parent_fd or argv is not None:
            raise BootstrapError("bootstrap_process_rejected")
        try:
            intent = (
                dict(validated_top_level_intent)
                if validated_top_level_intent is not None
                else launcher_v1.validate_top_level_entry_intent(
                    contract, adapter_v1._read_json(Path(top_intent))
                )
            )
            launcher_v1.verify_top_level_bootstrap_child(
                contract, intent, argv=expected_argv
            )
        except (
            OSError,
            ValueError,
            adapter_v1.AdapterError,
            launcher_v1.LauncherError,
        ):
            raise BootstrapError("bootstrap_process_rejected") from None
        if (
            intent["contract_path"] != str(contract_path)
            or intent["root"] != str(root)
            or intent["backend"] != backend
            or intent["target_source_path"] != str(target_source)
            or intent["acceptance_scope_digest"] != acceptance_scope_digest
            or intent["target_inventory_digest"]
            != contract_v1.digest_value(target_inventory)
            or intent["target_directories_digest"]
            != contract_v1.digest_value(target_directories)
            or top_parent_fd != str(intent["parent_pipe_fd"])
        ):
            raise BootstrapError("bootstrap_process_rejected")
    else:
        # Direct inner-bootstrap fixtures remain available only for the inert
        # synthetic backend.  Production systemd entry must be parent-nonce
        # bound to the source-owned Windows/guest top-level boundary.
        try:
            stdin_target = os.readlink("/proc/self/fd/0")
        except OSError:
            raise BootstrapError("bootstrap_process_rejected") from None
        if (
            backend != "synthetic"
            or argv is not None
            or list(sys.orig_argv) != expected_argv
            or Path.cwd() != target_source
            or Path(sys.executable)
            != Path(str(contract["interpreter"]["invocation_path"]))
            or os.getuid() != runtime["uid"]
            or os.getgid() != runtime["gid"]
            or sorted(os.getgroups()) != runtime["groups"]
            or dict(os.environ) != direct_environment
            or stdin_target != "/dev/null"
        ):
            raise BootstrapError("bootstrap_process_rejected")
    try:
        launcher_v1._verify_interpreter(contract["interpreter"])
        launcher_v1.verify_loaded_runtime_inventory(
            contract,
            target_source,
            target_inventory,
            target_directories,
            {
                contract_v1.SUPERVISOR_BOOTSTRAP_PATH: sys.modules[__name__],
                "scripts/p08_activation_contract_v1.py": contract_v1,
                "scripts/p08_activation_launcher_v1.py": launcher_v1,
                contract_v1.PRODUCTION_ADAPTER_PATH: adapter_v1,
                contract_v1.SUPERVISOR_GUARDIAN_MANAGER_PATH: guardian_manager_v1,
                "scripts/p08_activation_supervisor_v1.py": supervisor_v1,
            },
        )
    except launcher_v1.LauncherError:
        raise BootstrapError("bootstrap_source_identity_rejected") from None


def _target_closure(
    contract: Mapping[str, object], target_source: Path
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    try:
        inventory = adapter_v1.target_inventory(target_source)
        directories = adapter_v1.target_directory_inventory(
            target_source, file_inventory=inventory
        )
        adapter_v1._target_manifest(contract, target_source, inventory)
    except adapter_v1.AdapterError:
        raise BootstrapError("bootstrap_target_rejected") from None
    return inventory, directories


def _outer_terminal(
    contract: Mapping[str, object],
    *,
    status: str,
    product_state: str,
    entry_nonce: str,
    capture_digest: str,
    plan_digest: str | None,
    recovery_entry_nonce: str | None,
    recovery_capture_digest: str | None,
    recovery_count: int,
) -> dict[str, object]:
    body = {
        "schema": contract_v1.SUPERVISOR_OUTER_TERMINAL_SCHEMA,
        "architecture": contract_v1.ARCHITECTURE,
        "contract_digest": contract["contract_digest"],
        "terminal_status": status,
        "stage": "outer_capture_terminalization",
        "product_state": product_state,
        "entry_nonce": entry_nonce,
        "capture_digest": capture_digest,
        "plan_digest": plan_digest,
        "recovery_entry_nonce": recovery_entry_nonce,
        "recovery_capture_digest": recovery_capture_digest,
        "recovery_count": recovery_count,
        "orphan_count": 0,
        "raw_output_included": False,
        "retry_authorized": False,
    }
    return contract_v1.validate_supervisor_bootstrap_output(
        {**body, "terminal_digest": contract_v1.digest_value(body)}
    )


def _sequence_plan_path(
    contract: Mapping[str, object], root: Path, entry_nonce: str
) -> Path:
    return (
        adapter_v1._rooted(
            root, str(contract["production_adapter"]["fixed_paths"]["strategy_root"])
        )
        / "sequences"
        / entry_nonce
        / "PLAN.json"
    )


def _load_exact_sequence_plan(
    contract: Mapping[str, object], root: Path, entry_nonce: str
) -> tuple[dict[str, object] | None, Path]:
    plan_path = _sequence_plan_path(contract, root, entry_nonce)
    if not plan_path.exists() and not plan_path.is_symlink():
        return None, plan_path
    try:
        plan = contract_v1.validate_plan(
            contract, supervisor_v1._load_private_evidence(plan_path)
        )
        details = adapter_v1._regular(plan_path, maximum=adapter_v1.MAX_JSON_BYTES)
    except (contract_v1.ContractError, supervisor_v1.SupervisorError, adapter_v1.AdapterError):
        raise BootstrapError("bootstrap_plan_rejected") from None
    if (
        plan["sequence_identity"] != entry_nonce
        or Path(str(plan["execution"]["root"])) != root
        or stat.S_IMODE(details.st_mode) != 0o600
        or details.st_uid != os.getuid()
        or details.st_gid != os.getgid()
        or adapter_v1._read_regular_bytes(plan_path)
        != contract_v1.canonical_bytes(plan)
    ):
        raise BootstrapError("bootstrap_plan_rejected")
    return plan, plan_path


def _guardian_outcome(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    guardian_root: Path,
) -> dict[str, object] | None:
    accepted_path = guardian_root / "ACCEPTED.TERMINAL.json"
    discharge_path = guardian_root / "DISCHARGE.json"
    hard_stop_path = guardian_root / "HARDSTOP.TERMINAL.json"
    if (accepted_path.exists() or accepted_path.is_symlink()) and (
        discharge_path.exists() or discharge_path.is_symlink()
    ):
        try:
            accepted_result = guardian_manager_v1._load_exact_discharge(
                contract,
                obligation,
                guardian_root,
                materialize_strategy_terminal=False,
            )
            if accepted_result is None:
                raise BootstrapError("bootstrap_guardian_discharge_rejected")
            return accepted_result
        except (
            BootstrapError,
            guardian_manager_v1.GuardianError,
        ):
            # A malformed or incomplete discharge is never authority to retain
            # an accepted target.  The manager generation must converge it.
            return None
    if not hard_stop_path.exists() and not hard_stop_path.is_symlink():
        return None
    try:
        hard_stop = guardian_manager_v1._load_exact_lifecycle_terminal(
            contract,
            obligation,
            guardian_root,
            materialize_strategy_terminal=False,
        )
        if hard_stop is None:
            return None
    except guardian_manager_v1.GuardianError:
        return None
    if hard_stop["terminal_status"] == "accepted":
        return None
    if hard_stop["plan_digest"] is None:
        return _outer_terminal(
            contract,
            status=str(hard_stop["terminal_status"]),
            product_state=str(hard_stop["product_state"]),
            entry_nonce=str(obligation["entry_nonce"]),
            capture_digest=str(hard_stop["guardian_terminal_digest"]),
            plan_digest=None,
            recovery_entry_nonce=None,
            recovery_capture_digest=None,
            recovery_count=int(hard_stop["recovery_count"]),
        )
    try:
        plan, _ = _load_exact_sequence_plan(
            contract, Path(str(obligation["root"])), str(obligation["sequence_identity"])
        )
        if plan is None or plan["plan_digest"] != hard_stop["plan_digest"]:
            raise BootstrapError("bootstrap_guardian_plan_rejected")
        matches = []
        for name in ("GUARDIAN.RECOVERY.TERMINAL.json", "TERMINAL.json"):
            path = adapter_v1.sequence_root(contract, plan) / name
            if not path.exists() and not path.is_symlink():
                continue
            terminal = supervisor_v1._validate_terminal(
                contract, plan, supervisor_v1._load_private_evidence(path)
            )
            if (
                terminal["receipt_digest"] == hard_stop["child_terminal_digest"]
                and contract_v1.digest_value(terminal) == hard_stop["result_digest"]
            ):
                matches.append(terminal)
        if len(matches) != 1 or matches[0]["terminal_status"] == "accepted":
            raise BootstrapError("bootstrap_guardian_terminal_rejected")
        return matches[0]
    except (BootstrapError, supervisor_v1.SupervisorError):
        return None


def _run_guardian_manager_once(
    manager_intent: Mapping[str, object],
) -> tuple[int, int, str, int]:
    child = subprocess.Popen(
        list(manager_intent["argv"]),
        cwd=str(manager_intent["cwd"]),
        env=dict(manager_intent["environment"]),
        stdin=subprocess.DEVNULL,
        # Product disposition comes only from exact durable guardian records.
        # The bootstrap neither interprets nor retains manager stream bytes.
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        umask=int(manager_intent["umask"]),
    )
    try:
        child.wait(timeout=int(manager_intent["hard_deadline_seconds"]))
    except subprocess.TimeoutExpired:
        # The manager is the recovery owner.  The bootstrap must not destroy it
        # or race it with generation 2 merely because its own wait elapsed.
        # The process owns its independent session and remains responsible.
        return -1, 0, "manager_wait_timeout", 0
    return (
        int(child.returncode),
        0,
        "manager_exited",
        launcher_v1._process_group_orphan_count(child.pid),
    )


def _guardian_cgroup_members(
    control_group: str, *, cgroup_root: Path = Path("/sys/fs/cgroup")
) -> list[int] | None:
    """Return exact cgroup members, or None only when the cgroup was removed."""
    if (
        not isinstance(control_group, str)
        or not control_group.startswith("/system.slice/")
        or control_group.count("/") != 2
        or not control_group.endswith(".service")
        or any(part in {"", ".", ".."} for part in control_group.split("/")[1:])
    ):
        raise BootstrapError("bootstrap_guardian_cgroup_rejected")
    cgroup_path = cgroup_root / control_group.removeprefix("/")
    try:
        directory_before = cgroup_path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        raise BootstrapError("bootstrap_guardian_cgroup_rejected") from None
    if not stat.S_ISDIR(directory_before.st_mode) or stat.S_ISLNK(
        directory_before.st_mode
    ):
        raise BootstrapError("bootstrap_guardian_cgroup_rejected")
    procs_path = cgroup_path / "cgroup.procs"
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(procs_path, flags)
    except FileNotFoundError:
        try:
            cgroup_path.lstat()
        except FileNotFoundError:
            return None
        except OSError:
            pass
        raise BootstrapError("bootstrap_guardian_cgroup_rejected") from None
    except OSError:
        raise BootstrapError("bootstrap_guardian_cgroup_rejected") from None
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise BootstrapError("bootstrap_guardian_cgroup_rejected")
        raw = os.read(descriptor, 65537)
        if len(raw) > 65536:
            raise BootstrapError("bootstrap_guardian_cgroup_rejected")
    except OSError:
        raise BootstrapError("bootstrap_guardian_cgroup_rejected") from None
    finally:
        os.close(descriptor)
    try:
        directory_after = cgroup_path.lstat()
        text = raw.decode("ascii")
        members = [int(value) for value in text.splitlines()]
    except (OSError, UnicodeError, ValueError):
        raise BootstrapError("bootstrap_guardian_cgroup_rejected") from None
    if (
        directory_before.st_dev != directory_after.st_dev
        or directory_before.st_ino != directory_after.st_ino
        or any(value < 1 for value in members)
        or len(members) != len(set(members))
    ):
        raise BootstrapError("bootstrap_guardian_cgroup_rejected")
    return sorted(members)


def _guardian_transient_state(
    contract: Mapping[str, object], transient: Mapping[str, object]
) -> dict[str, object]:
    policy = contract["launcher"]["supervisor_bootstrap"]["guardian"][
        "production_transient"
    ]
    properties = list(policy["state_properties"])
    fields = adapter_v1._systemctl_show(
        {"execution_substrate": contract["systemd_authority"]},
        str(transient["unit_name"]),
        properties,
        allow_not_found=True,
    )
    try:
        main_pid = int(fields["MainPID"])
        restarts = int(fields["NRestarts"])
        exec_main_code = int(fields["ExecMainCode"])
        exec_main_status = int(fields["ExecMainStatus"])
    except ValueError:
        raise BootstrapError("bootstrap_guardian_unit_rejected") from None
    active_state = fields["ActiveState"]
    sub_state = fields["SubState"]
    load_state = fields["LoadState"]
    invocation_id = fields["InvocationID"]
    expected_cgroup = "/system.slice/" + str(transient["unit_name"])
    observed_cgroup = fields["ControlGroup"]
    if (
        active_state
        not in {"active", "activating", "deactivating", "inactive", "failed"}
        or not sub_state
        or load_state not in {"loaded", "not-found"}
        or fields["Result"] not in policy["result_classes"]
        or main_pid < 0
        or restarts not in {0, 1}
        or exec_main_code < 0
        or exec_main_status < 0
        or (
            invocation_id != ""
            and (
                len(invocation_id) != 32
                or any(
                    character not in "0123456789abcdef"
                    for character in invocation_id
                )
            )
        )
        or (
            load_state == "loaded" and observed_cgroup != expected_cgroup
        )
        or (
            load_state == "not-found"
            and (active_state != "inactive" or observed_cgroup != "")
        )
        or (load_state == "loaded" and invocation_id == "")
        or (load_state == "not-found" and invocation_id != "")
    ):
        raise BootstrapError("bootstrap_guardian_unit_rejected")
    members = _guardian_cgroup_members(expected_cgroup)
    if load_state == "not-found" and members is not None:
        raise BootstrapError("bootstrap_guardian_unit_rejected")
    if main_pid > 0 and (members is None or main_pid not in members):
        raise BootstrapError("bootstrap_guardian_unit_rejected")
    restart_scheduled = active_state == "activating" and sub_state == "auto-restart"
    terminal_quiescent = (
        active_state in {"inactive", "failed"}
        and sub_state != "auto-restart"
        and main_pid == 0
        and (members is None or members == [])
    )
    if (
        active_state == "active"
        and (main_pid < 1 or members is None or not members)
    ) or (
        active_state in {"activating", "deactivating"}
        and not restart_scheduled
        and members is None
    ) or (
        active_state in {"inactive", "failed"}
        and not terminal_quiescent
    ):
        raise BootstrapError("bootstrap_guardian_unit_rejected")
    lifecycle_state = (
        "scheduled_auto_restart"
        if restart_scheduled
        else "terminal_quiescent"
        if terminal_quiescent
        else "running_or_stopping"
    )
    return {
        "load_state": load_state,
        "active_state": active_state,
        "sub_state": sub_state,
        "main_pid": main_pid,
        "n_restarts": restarts,
        "control_group_exact": (
            observed_cgroup == expected_cgroup
            if load_state == "loaded"
            else observed_cgroup == ""
        ),
        "cgroup_present": members is not None,
        "cgroup_member_count": 0 if members is None else len(members),
        "result": fields["Result"],
        "exec_main_code": exec_main_code,
        "exec_main_status": exec_main_status,
        "invocation_id": invocation_id,
        "invocation_id_present": invocation_id != "",
        "restart_scheduled": restart_scheduled,
        "lifecycle_state": lifecycle_state,
        "terminal_quiescent": terminal_quiescent,
        "quiescent": terminal_quiescent,
        "raw_output_retained": False,
    }


def _drive_guardian_systemd_transient(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    manager_intent: Mapping[str, object],
    guardian_root: Path,
) -> dict[str, object]:
    transient = contract_v1.build_guardian_transient_launch(
        contract, obligation, manager_intent
    )
    transient_path = guardian_root / "MANAGER.TRANSIENT.json"
    launcher_v1.persist_capture_o_excl(transient_path, transient)
    transient = contract_v1.validate_guardian_transient_launch(
        contract,
        obligation,
        manager_intent,
        adapter_v1._read_json(transient_path),
    )
    if launcher_v1.boot_identity_digest() != obligation["boot_identity_digest"]:
        raise BootstrapError("bootstrap_guardian_deadline_rejected")
    completed = adapter_v1._run_bound_systemd_run(
        contract["systemd_authority"],
        list(transient["argv"])[1:],
        timeout=30,
    )
    submission = contract_v1.build_guardian_transient_submission(
        contract,
        obligation,
        manager_intent,
        transient,
        returncode=int(completed.returncode),
    )
    submission_path = guardian_root / "MANAGER.TRANSIENT.SUBMITTED.json"
    launcher_v1.persist_capture_o_excl(submission_path, submission)
    contract_v1.validate_guardian_transient_submission(
        contract,
        obligation,
        manager_intent,
        adapter_v1._read_json(submission_path),
    )
    deadline_ns = int(obligation["monotonic_deadline_ns"])
    poll_seconds = (
        int(
            contract["launcher"]["supervisor_bootstrap"]["guardian"][
                "poll_interval_ms"
            ]
        )
        / 1000.0
    )
    invocation_by_restart: dict[int, str] = {}
    while True:
        if launcher_v1.boot_identity_digest() != obligation["boot_identity_digest"]:
            raise BootstrapError("bootstrap_guardian_deadline_rejected")
        outcome = _guardian_outcome(contract, obligation, guardian_root)
        state = _guardian_transient_state(contract, transient)
        invocation_id = str(state["invocation_id"])
        restart_index = int(state["n_restarts"])
        if invocation_id:
            prior = invocation_by_restart.get(restart_index)
            if (
                (prior is not None and prior != invocation_id)
                or any(
                    index != restart_index and value == invocation_id
                    for index, value in invocation_by_restart.items()
                )
            ):
                raise BootstrapError("bootstrap_guardian_invocation_rejected")
            invocation_by_restart[restart_index] = invocation_id
        if outcome is not None and state["terminal_quiescent"] is True:
            return outcome
        if (
            outcome is None
            and state["terminal_quiescent"] is True
        ):
            raise BootstrapError("bootstrap_guardian_terminal_missing")
        if time.monotonic_ns() >= deadline_ns:
            # The exact transient unit remains the independent owner.  This
            # bootstrap neither starts another manager nor assumes recovery.
            raise BootstrapError("bootstrap_guardian_still_responsible")
        time.sleep(poll_seconds)


def _drive_guardian_manager(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    manager_intent: Mapping[str, object],
    guardian_root: Path,
) -> dict[str, object]:
    """Start at most one manager generation at a time and trust only disk."""
    if manager_intent["manager_backend"] == "systemd_transient":
        return _drive_guardian_systemd_transient(
            contract, obligation, manager_intent, guardian_root
        )
    for _ in range(int(manager_intent["manager_max_starts"])):
        manager_result = _run_guardian_manager_once(manager_intent)
        terminal = _guardian_outcome(contract, obligation, guardian_root)
        if terminal is not None:
            return terminal
        if manager_result[2] == "manager_wait_timeout":
            # The prior process is not known terminal, so generation 2 would
            # be a concurrent authority.  Leave the independent guardian in
            # charge and return no product disposition from this bootstrap.
            raise BootstrapError("bootstrap_guardian_still_responsible")
    raise BootstrapError("bootstrap_guardian_terminal_missing")


def main(argv: Sequence[str] | None = None) -> int:
    parser = adapter_v1.CanonicalArgumentParser(allow_abbrev=False)
    parser.add_argument("--activation-contract", type=Path, required=True)
    parser.add_argument("--activation-root", type=Path)
    parser.add_argument("--activation-backend", choices=("synthetic", "systemd"))
    parser.add_argument("--activation-target-source", type=Path)
    parser.add_argument("--acceptance-scope-digest")
    contract: dict[str, object] | None = None
    launch_claim: dict[str, object] | None = None
    entry_nonce: str | None = None
    manager_drive_entered = False
    top_level_intent: dict[str, object] | None = None
    preclaim_tracker: _PreclaimTracker | None = None
    preclaim_complete = False
    bootstrap_pid: int | None = None
    bootstrap_start_ticks: int | None = None
    bootstrap_process_group: int | None = None
    try:
        values = parser.parse_args(argv)
        contract = _load_contract(values.activation_contract)
        if any(
            value is None
            for value in (
                values.activation_root,
                values.activation_backend,
                values.activation_target_source,
                values.acceptance_scope_digest,
            )
        ):
            raise BootstrapError("bootstrap_arguments_rejected")
        root = values.activation_root
        backend = values.activation_backend
        target_source = values.activation_target_source
        acceptance_scope_digest = values.acceptance_scope_digest
        top_level_intent = _load_top_level_intent(contract)
        if top_level_intent is not None:
            bootstrap_pid = os.getpid()
            bootstrap_start_ticks = _process_start_ticks(bootstrap_pid)
            bootstrap_process_group = os.getpgrp()
            preclaim_tracker = _PreclaimTracker(
                contract,
                top_level_intent,
                root=root,
                backend=backend,
                completed_phases=(),
            )
            # The source-owned top-level entry has already bound the exact
            # argv, contract and intent before this child exists.  Replay
            # those completed observations through the same generated phase
            # observer so their synthetic fault seams and result projection
            # cannot drift from the later bootstrap gates.
            preclaim_tracker.enter("arguments")
            preclaim_tracker.enter("contract")
            preclaim_tracker.enter("top_level_intent")
            _verify_top_level_intent_binding(
                top_level_intent,
                contract_path=values.activation_contract,
                root=root,
                backend=backend,
                target_source=target_source,
                acceptance_scope_digest=acceptance_scope_digest,
            )
            preclaim_tracker.enter("target_closure")
        inventory, directories = _target_closure(contract, target_source)
        if preclaim_tracker is not None:
            preclaim_tracker.enter("parent_process")
        _verify_parent_process(
            contract,
            contract_path=values.activation_contract,
            root=root,
            backend=backend,
            target_source=target_source,
            target_inventory=inventory,
            target_directories=directories,
            acceptance_scope_digest=acceptance_scope_digest,
            argv=argv,
            validated_top_level_intent=top_level_intent,
        )
        # Freeze the exact metadata-only public/opaque/account/unit prestate
        # before any random guardian namespace can exist.  The fixed O_EXCL
        # claim above every sequence is the architecture-wide max1 authority.
        try:
            execution = adapter_v1.construct_execution(
                contract,
                root=root,
                backend=backend,
                target_source_path=target_source,
                acceptance_scope_digest=acceptance_scope_digest,
                preclaim_phase_observer=(
                    preclaim_tracker.enter
                    if preclaim_tracker is not None
                    else None
                ),
            )
        except BootstrapError:
            raise
        except adapter_v1.AdapterError as error:
            if preclaim_tracker is None:
                raise
            raise BootstrapError(
                preclaim_tracker.rejection_category(),
                cause_source="adapter",
                subcategory=error.code,
            ) from None
        except contract_v1.ContractError:
            if preclaim_tracker is None:
                raise
            raise BootstrapError(
                preclaim_tracker.rejection_category(),
                cause_source="contract",
                subcategory=contract_v1.PRECLAIM_CONTRACT_SUBCATEGORY,
            ) from None
        if preclaim_tracker is not None:
            preclaim_tracker.enter("prestate_identity")
        try:
            prestate_identity = adapter_v1.execution_prestate_identity(execution)
        except adapter_v1.AdapterError as error:
            if preclaim_tracker is None:
                raise
            raise BootstrapError(
                preclaim_tracker.rejection_category(),
                cause_source="adapter",
                subcategory=error.code,
            ) from None
        except contract_v1.ContractError:
            if preclaim_tracker is None:
                raise
            raise BootstrapError(
                preclaim_tracker.rejection_category(),
                cause_source="contract",
                subcategory=contract_v1.PRECLAIM_CONTRACT_SUBCATEGORY,
            ) from None
        if preclaim_tracker is not None:
            preclaim_tracker.enter("nonce")
        entry_nonce = secrets.token_hex(32)
        if preclaim_tracker is not None:
            preclaim_tracker.enter("strategy_namespace")
        strategy, namespace_inventory = _inspect_strategy_namespace(
            contract, root=root
        )
        claim_path = strategy / "STRATEGY.LAUNCH.CLAIM.json"
        if namespace_inventory:
            if claim_path.exists() and not claim_path.is_symlink():
                try:
                    contract_v1.validate_strategy_launch_claim(
                        contract, adapter_v1._read_json(claim_path)
                    )
                except (adapter_v1.AdapterError, contract_v1.ContractError):
                    raise BootstrapError(
                        "bootstrap_strategy_preclaim_residue_rejected"
                    ) from None
                raise BootstrapError("bootstrap_strategy_already_claimed")
            raise BootstrapError("bootstrap_strategy_preclaim_residue_rejected")
        if preclaim_tracker is not None:
            preclaim_tracker.enter("strategy_claim")
        prepared_claim = _build_strategy_launch_claim(
            contract,
            root=root,
            backend=backend,
            target_source=target_source,
            target_inventory=inventory,
            target_directories=directories,
            acceptance_scope_digest=acceptance_scope_digest,
            prestate_identity=prestate_identity,
            entry_nonce=entry_nonce,
        )
        if preclaim_tracker is not None:
            preclaim_tracker.finish()
        preclaim_complete = True
        launch_claim = _persist_strategy_launch_claim(
            contract, root=root, claim=prepared_claim
        )
        if backend == "synthetic":
            fixed = contract["production_adapter"]["fixed_paths"]
            control = adapter_v1._synthetic_control_path(
                contract,
                adapter_v1._rooted(root, str(fixed["state_root"]))
                / "synthetic-control.json",
            )
            if (
                control["fault_kind"]
                == "guardian_obligation_persist_failed_before_plan"
            ):
                capture_digest = contract_v1.digest_value(
                    {
                        "contract_digest": contract["contract_digest"],
                        "entry_nonce": entry_nonce,
                        "guardian_obligation_persisted": False,
                        "plan_persisted": False,
                        "product_mutation": False,
                    }
                )
                terminal = _outer_terminal(
                    contract,
                    status="premutation_hard_stop",
                    product_state="unmodified",
                    entry_nonce=entry_nonce,
                    capture_digest=capture_digest,
                    plan_digest=None,
                    recovery_entry_nonce=None,
                    recovery_capture_digest=None,
                    recovery_count=0,
                )
                _persist_strategy_launch_premutation_terminal(
                    contract, launch_claim, terminal
                )
                sys.stdout.buffer.write(contract_v1.canonical_bytes(terminal))
                return 2
        guardian_root = _guardian_directory(contract, root, entry_nonce)
        obligation_path = guardian_root / "OBLIGATION.json"
        manager_intent_path = guardian_root / "MANAGER.INTENT.json"
        obligation = contract_v1.build_guardian_obligation(
            contract,
            entry_nonce=entry_nonce,
            root=str(root),
            backend=backend,
            contract_path=str(values.activation_contract),
            target_source_path=str(target_source),
            target_inventory_digest=contract_v1.digest_value(inventory),
            target_directories_digest=contract_v1.digest_value(directories),
            acceptance_scope_digest=acceptance_scope_digest,
            launch_claim_digest=str(launch_claim["launch_claim_digest"]),
            prestate_identity=prestate_identity,
            bootstrap_pid=os.getpid(),
            bootstrap_process_group=os.getpgrp(),
            bootstrap_start_ticks=_process_start_ticks(os.getpid()),
            boot_identity_digest=launcher_v1.boot_identity_digest(),
            monotonic_start_ns=time.monotonic_ns(),
        )
        launcher_v1.persist_capture_o_excl(obligation_path, obligation)
        obligation = contract_v1.validate_guardian_obligation(
            contract, adapter_v1._read_json(obligation_path)
        )
        manager_intent = contract_v1.build_guardian_manager_intent(
            contract, obligation, obligation_path=str(obligation_path)
        )
        launcher_v1.persist_capture_o_excl(manager_intent_path, manager_intent)
        manager_intent = contract_v1.validate_guardian_manager_intent(
            contract, obligation, adapter_v1._read_json(manager_intent_path)
        )
        manager_drive_entered = True
        terminal = _drive_guardian_manager(
            contract, obligation, manager_intent, guardian_root
        )
    except Exception as error:
        if (
            contract is not None
            and top_level_intent is not None
            and preclaim_tracker is not None
            and not preclaim_complete
            and launch_claim is None
            and bootstrap_pid is not None
            and bootstrap_start_ticks is not None
            and bootstrap_process_group is not None
        ):
            try:
                candidate = preclaim_tracker.result(
                    error,
                    bootstrap_pid=bootstrap_pid,
                    bootstrap_start_ticks=bootstrap_start_ticks,
                    bootstrap_process_group=bootstrap_process_group,
                )
                try:
                    terminal = _persist_preclaim_result(
                        contract, top_level_intent, candidate
                    )
                except BootstrapError:
                    # The source-owned top-level capture is allowed by the
                    # generated contract to complete this exact O_EXCL write.
                    terminal = candidate
            except Exception:
                terminal = _entry_failure()
        elif (
            contract is not None
            and launch_claim is not None
            and entry_nonce is not None
            and not manager_drive_entered
        ):
            capture_digest = contract_v1.digest_value(
                {
                    "contract_digest": contract["contract_digest"],
                    "entry_nonce": entry_nonce,
                    "launch_claim_digest": launch_claim["launch_claim_digest"],
                    "manager_drive_entered": False,
                    "plan_persisted": False,
                    "product_mutation": False,
                }
            )
            candidate = _outer_terminal(
                contract,
                status="premutation_hard_stop",
                product_state="unmodified",
                entry_nonce=entry_nonce,
                capture_digest=capture_digest,
                plan_digest=None,
                recovery_entry_nonce=None,
                recovery_capture_digest=None,
                recovery_count=0,
            )
            try:
                _persist_strategy_launch_premutation_terminal(
                    contract, launch_claim, candidate
                )
                terminal = candidate
            except BootstrapError:
                terminal = _entry_failure()
        else:
            terminal = _entry_failure()
    sys.stdout.buffer.write(contract_v1.canonical_bytes(terminal))
    return 0 if terminal.get("terminal_status") == "accepted" else 2


if __name__ == "__main__":
    raise SystemExit(main())
