from __future__ import annotations

from hashlib import sha256
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import p08_activation_contract_v1 as contract_v1
import p08_activation_boot_recovery_v1 as boot_recovery
import p08_activation_guardian_manager_v1 as guardian_manager
import p08_activation_installed_shadow_v1 as installed_shadow
import p08_activation_launcher_v1 as launcher
import p08_activation_production_adapter_v1 as adapter
import p08_activation_supervisor_bootstrap_v1 as supervisor_bootstrap
import p08_activation_supervisor_v1 as supervisor


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _contract() -> dict[str, object]:
    interpreter = Path(sys.executable).resolve()
    core_source = Path("/srv/myuna/repos/core/src/myuna_core/trusted_time/__init__.py")
    source_inventory = []
    for relative in contract_v1.REQUIRED_ENGINE_SOURCE_PATHS:
        source = ROOT / relative
        source_inventory.append(
            {
                "path": relative,
                "size": source.stat().st_size,
                "mode": source.stat().st_mode & 0o777,
                "sha256": _digest(source),
            }
        )
    return contract_v1.compile_contract(
        core_root="/srv/myuna/repos/core",
        deploy_root=str(ROOT),
        core_commit="1" * 40,
        core_tree="2" * 40,
        deploy_commit="3" * 40,
        deploy_tree="4" * 40,
        source_inventory=source_inventory,
        core_inventory=[
            {
                "path": "src/myuna_core/trusted_time/__init__.py",
                "size": core_source.stat().st_size,
                "mode": core_source.stat().st_mode & 0o777,
                "sha256": _digest(core_source),
            }
        ],
        unit_semantics=contract_v1.build_unit_semantics(
            (ROOT / "systemd/myuna-active-temporal-context-v1.service").read_bytes(),
            (ROOT / "systemd/myuna-active-temporal-context-v1.socket").read_bytes(),
        ),
        compatibility={
            "legacy_release_contract_digest": "7" * 64,
            "p07": {"inventory_digest": "5" * 64},
            "p10b": {"inventory_digest": "6" * 64},
            "predecessor": installed_shadow.synthetic_predecessor_binding(
                ROOT,
                release_identity="b" * 64,
                core_commit="1" * 40,
                deploy_commit="2" * 40,
            ),
        },
        interpreter=dict(contract_v1.PRODUCTION_INTERPRETER),
        runtime_identity={
            "uid": os.getuid(),
            "gid": os.getgid(),
            "groups": sorted(set(os.getgroups())),
        },
    )


def _run(
    case: unittest.TestCase,
    scenario: installed_shadow.InstalledShadowScenario,
) -> tuple[dict[str, object], Path]:
    directory = tempfile.TemporaryDirectory()
    case.addCleanup(directory.cleanup)
    base = Path(directory.name)
    target = base / ("a" * 64)
    contract = _contract()
    installed_shadow.create_target_release(ROOT, target, contract)
    world = installed_shadow.create_world(
        contract,
        root=base / "world",
        target_source=target,
        predecessor_identity="b" * 64,
        scenario=scenario,
    )
    result = installed_shadow.run_installed_shadow(
        contract,
        world["plan"],
        contract_path=world["contract_path"],
        plan_path=world["plan_path"],
        deploy_root=ROOT,
    )
    return result, base / "world"


def _systemd_responses(
    contract: dict[str, object],
    *,
    service_updates: dict[str, str] | None = None,
    socket_updates: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[bytes], subprocess.CompletedProcess[bytes]]:
    # Independent systemd-255-shaped predecessor projection.  These rows are
    # intentionally not copied from the generated contract: this fixture is
    # the cross-authority oracle that caught the old contract-echo blind spot.
    service_dependencies = {
        "After": [
            "-.mount",
            "basic.target",
            "myuna-active-temporal-context-v1.socket",
            "sysinit.target",
            "system.slice",
            "systemd-journald.socket",
            "systemd-tmpfiles-setup.service",
            "tmp.mount",
        ],
        "Before": ["shutdown.target"],
        "BindsTo": [],
        "BoundBy": [],
        "ConflictedBy": [],
        "Conflicts": ["shutdown.target"],
        "ConsistsOf": [],
        "JoinsNamespaceOf": [],
        "OnFailure": [],
        "OnSuccess": [],
        "PartOf": [],
        "PropagatesReloadTo": [],
        "PropagatesStopTo": [],
        "ReloadPropagatedFrom": [],
        "RequiredBy": [],
        "Requires": [
            "myuna-active-temporal-context-v1.socket",
            "sysinit.target",
            "system.slice",
        ],
        "Requisite": [],
        "RequisiteOf": [],
        "StopPropagatedFrom": [],
        "TriggeredBy": ["myuna-active-temporal-context-v1.socket"],
        "Triggers": [],
        "UpheldBy": [],
        "Upholds": [],
        "WantedBy": [],
        "Wants": ["tmp.mount"],
    }
    socket_dependencies = {
        "After": ["-.mount", "sysinit.target", "system.slice"],
        "Before": [
            "myuna-active-temporal-context-v1.service",
            "shutdown.target",
            "sockets.target",
        ],
        "BindsTo": [],
        "BoundBy": [],
        "ConflictedBy": [],
        "Conflicts": ["shutdown.target"],
        "ConsistsOf": [],
        "JoinsNamespaceOf": [],
        "OnFailure": [],
        "OnSuccess": [],
        "PartOf": [],
        "PropagatesReloadTo": [],
        "PropagatesStopTo": [],
        "ReloadPropagatedFrom": [],
        "RequiredBy": ["myuna-active-temporal-context-v1.service"],
        "Requires": ["sysinit.target", "system.slice"],
        "Requisite": [],
        "RequisiteOf": [],
        "StopPropagatedFrom": [],
        "TriggeredBy": [],
        "Triggers": ["myuna-active-temporal-context-v1.service"],
        "UpheldBy": [],
        "Upholds": [],
        "WantedBy": ["sockets.target"],
        "Wants": [],
    }
    runtime = contract["compatibility"]["predecessor"]["unit_runtime"]
    service = {
        "ActiveEnterTimestampMonotonic": "42",
        "ActiveState": "active",
        "ControlGroup": runtime["service"]["control_group"],
        "DynamicUser": runtime["service"]["dynamic_user"],
        "DropInPaths": "",
        "EnvironmentFiles": runtime["service"]["environment_files"][0]
        + " (ignore_errors=no)",
        "ExecStart": (
            "{ path="
            + runtime["service"]["exec_start_argv"][0]
            + " ; argv[]="
            + " ".join(runtime["service"]["exec_start_argv"])
            + " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; "
            "pid=4242 ; code=(null) ; status=0/0 }"
        ),
        "FragmentPath": runtime["service"]["fragment_path"],
        "Group": runtime["service"]["group"],
        "LoadState": "loaded",
        "MainPID": "4242",
        "NRestarts": "0",
        "PAMName": runtime["service"]["pam_name"],
        "PrivateUsers": runtime["service"]["private_users"],
        "SetLoginEnvironment": "no",
        "Slice": runtime["service"]["slice"],
        "SubState": "running",
        "SupplementaryGroups": " ".join(
            runtime["service"]["supplementary_groups"]
        ),
        "UnitFileState": runtime["service"]["unit_file_state"],
        "User": runtime["service"]["user"],
    }
    socket = {
        "ActiveEnterTimestampMonotonic": "43",
        "ActiveState": "active",
        "ControlGroup": runtime["socket"]["control_group"],
        "DropInPaths": "",
        "FragmentPath": runtime["socket"]["fragment_path"],
        "Listen": runtime["socket"]["listen_stream"] + " (Stream)",
        "LoadState": "loaded",
        "NAccepted": "7",
        "NConnections": "0",
        "Slice": runtime["socket"]["slice"],
        "SocketGroup": runtime["socket"]["socket_group"],
        "SocketMode": runtime["socket"]["socket_mode"],
        "SocketUser": runtime["socket"]["socket_user"],
        "SubState": "running",
        "UnitFileState": runtime["socket"]["unit_file_state"],
    }
    for name in contract["systemd_authority"]["dependency_properties"]:
        service[name] = " ".join(service_dependencies[name])
        socket[name] = " ".join(socket_dependencies[name])
    service.update(
        {
            "Environment": "PYTHONDONTWRITEBYTECODE=1",
            "NoNewPrivileges": "yes",
            "PrivateDevices": "yes",
            "PrivateTmp": "yes",
            "ProtectControlGroups": "yes",
            "ProtectHome": "yes",
            "ProtectKernelModules": "yes",
            "ProtectKernelTunables": "yes",
            "ProtectSystem": "strict",
            "ReadWritePaths": "/var/lib/myuna-active-temporal-context-v1",
            "Restart": "on-failure",
            "RestartUSec": "2s",
            "RestrictAddressFamilies": "AF_UNIX",
            "Type": "simple",
            "UMask": "0077",
        }
    )
    service.update(service_updates or {})
    socket.update(socket_updates or {})
    service_raw = "".join(f"{key}={value}\n" for key, value in service.items()).encode(
        "ascii"
    )
    socket_raw = "".join(f"{key}={value}\n" for key, value in socket.items()).encode(
        "ascii"
    )
    return (
        subprocess.CompletedProcess([], 0, stdout=service_raw, stderr=b""),
        subprocess.CompletedProcess([], 0, stdout=socket_raw, stderr=b""),
    )


def _systemd_process_projection(contract: dict[str, object]) -> dict[str, object]:
    expected = contract["compatibility"]["predecessor"]["unit_runtime"]["service"][
        "process_identity"
    ]
    return {**dict(expected), "pid": 4242, "start_ticks": 123456}


def _source_owned_bootstrap_command(
    contract: dict[str, object], world: dict[str, object]
) -> list[str]:
    plan = world["plan"]
    target = Path(str(plan["execution"]["target_source_path"]))
    root = Path(str(plan["execution"]["root"]))
    return [
        str(contract["interpreter"]["invocation_path"]),
        "-B",
        "-P",
        "-S",
        "-m",
        "p08_activation_supervisor_bootstrap_v1",
        "--activation-contract",
        str(world["contract_path"]),
        "--activation-root",
        str(root),
        "--activation-backend",
        "synthetic",
        "--activation-target-source",
        str(target),
        "--acceptance-scope-digest",
        "7" * 64,
    ]


def _source_owned_bootstrap_environment(world: dict[str, object]) -> dict[str, str]:
    target = Path(str(world["plan"]["execution"]["target_source_path"]))
    return {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": os.pathsep.join((str(target / "scripts"), str(target / "src"))),
    }


def _source_owned_top_level_command(
    contract: dict[str, object], world: dict[str, object]
) -> list[str]:
    plan = world["plan"]
    target = Path(str(plan["execution"]["target_source_path"]))
    root = Path(str(plan["execution"]["root"]))
    return [
        str(contract["interpreter"]["invocation_path"]),
        "-B",
        "-P",
        "-S",
        "-m",
        "p08_activation_top_level_entry_v1",
        "--activation-contract",
        str(world["contract_path"]),
        "--activation-root",
        str(root),
        "--activation-backend",
        "synthetic",
        "--activation-target-source",
        str(target),
        "--acceptance-scope-digest",
        "7" * 64,
    ]


def _source_owned_top_level_environment(
    contract: dict[str, object], world: dict[str, object]
) -> dict[str, str]:
    plan = world["plan"]
    target = Path(str(plan["execution"]["target_source_path"]))
    root = Path(str(plan["execution"]["root"]))
    identity = launcher.windows_host_entry_identity(
        contract,
        acceptance_scope_digest="7" * 64,
        backend="synthetic",
        root=root,
        target_source=target,
    )
    return launcher._top_level_environment(target, identity)


def _run_source_owned_top_level(
    contract: dict[str, object],
    world: dict[str, object],
    *,
    stdin: int | None = subprocess.PIPE,
    environment: dict[str, str] | None = None,
    command: list[str] | None = None,
) -> tuple[subprocess.CompletedProcess[bytes], dict[str, object]]:
    target = Path(str(world["plan"]["execution"]["target_source_path"]))
    _remove_bootstrap_scaffold(contract, world)
    process = subprocess.Popen(
        _source_owned_top_level_command(contract, world)
        if command is None
        else command,
        cwd=target,
        env=(
            _source_owned_top_level_environment(contract, world)
            if environment is None
            else environment
        ),
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = process.communicate(timeout=360)
    completed = subprocess.CompletedProcess(
        process.args, process.returncode, stdout=stdout, stderr=stderr
    )
    if not stdout:
        raise AssertionError("source_owned_top_level_stdout_missing")
    parsed = json.loads(stdout)
    if parsed.get("schema") == contract_v1.TOP_LEVEL_ENTRY_RESULT_SCHEMA:
        parsed = launcher.validate_top_level_entry_result(contract, parsed)
    else:
        parsed = contract_v1.validate_supervisor_bootstrap_output(parsed)
    return completed, parsed


def _windows_drive_path(path: Path) -> str:
    resolved = path.resolve()
    parts = resolved.parts
    if len(parts) < 4 or parts[0] != "/" or parts[1] != "mnt":
        raise AssertionError("windows_drive_path_rejected")
    drive = parts[2]
    if len(drive) != 1 or not drive.isalpha():
        raise AssertionError("windows_drive_path_rejected")
    return drive.upper() + ":\\" + "\\".join(parts[3:])


def _remove_bootstrap_scaffold(
    contract: dict[str, object], world: dict[str, object]
) -> None:
    """Remove only create_world's exact temp-root direct-supervisor scaffold."""
    scaffold = adapter.sequence_root(contract, world["plan"])
    if not scaffold.exists():
        return
    expected_plan = contract_v1.canonical_bytes(world["plan"])
    if (
        sorted(item.name for item in scaffold.iterdir()) != ["PLAN.json"]
        or (scaffold / "PLAN.json").read_bytes() != expected_plan
    ):
        raise AssertionError("bootstrap_scaffold_rejected")
    (scaffold / "PLAN.json").unlink()
    scaffold.rmdir()
    sequences = scaffold.parent
    strategy = sequences.parent
    sequences.rmdir()
    # create_world's direct-supervisor scaffold also created the otherwise
    # empty strategy root.  Remove that exact empty directory so bootstrap
    # pre-claim tests model the production namespace-absent gate and can prove
    # that typed failures do not create it.
    if not any(strategy.iterdir()):
        strategy.rmdir()


def _run_source_owned_bootstrap(
    contract: dict[str, object],
    world: dict[str, object],
    *,
    cwd: Path | None = None,
    environment: dict[str, str] | None = None,
    command: list[str] | None = None,
) -> tuple[subprocess.CompletedProcess[bytes], dict[str, object]]:
    target = Path(str(world["plan"]["execution"]["target_source_path"]))
    # create_world persists one direct-supervisor PLAN for non-bootstrap tests.
    # The top-level bootstrap contract must begin before any PLAN namespace, so
    # remove only that exact temp-root scaffold (never arbitrary residue).
    _remove_bootstrap_scaffold(contract, world)
    completed = subprocess.run(
        _source_owned_bootstrap_command(contract, world) if command is None else command,
        cwd=target if cwd is None else cwd,
        env=(
            _source_owned_bootstrap_environment(world)
            if environment is None
            else environment
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=360,
        check=False,
    )
    if not completed.stdout:
        raise AssertionError("source_owned_bootstrap_stdout_missing")
    parsed = contract_v1.validate_supervisor_bootstrap_output(
        json.loads(completed.stdout)
    )
    return completed, parsed


def _guardian_submission(
    contract: dict[str, object],
    world: dict[str, object],
    *,
    entry_nonce: str,
    backend: str = "synthetic",
) -> tuple[Path, dict[str, object], dict[str, object]]:
    target = Path(str(world["plan"]["execution"]["target_source_path"]))
    root = Path(str(world["plan"]["execution"]["root"]))
    inventory = adapter.target_inventory(target)
    directories = adapter.target_directory_inventory(
        target, file_inventory=inventory
    )
    strategy = adapter._strategy_root(contract, world["plan"]["execution"])
    strategy.mkdir(parents=True, exist_ok=True, mode=0o700)
    strategy.chmod(0o700)
    prestate_identity = str(world["plan"]["prestate_identity"])
    launch_claim = contract_v1.build_strategy_launch_claim(
        contract,
        entry_nonce=entry_nonce,
        root=str(root),
        backend=backend,
        target_source_path=str(target),
        target_inventory_digest=contract_v1.digest_value(inventory),
        target_directories_digest=contract_v1.digest_value(directories),
        acceptance_scope_digest="7" * 64,
        prestate_identity=prestate_identity,
    )
    launcher.persist_capture_o_excl(
        strategy / "STRATEGY.LAUNCH.CLAIM.json", launch_claim
    )
    guardian_root = strategy / "guardians" / entry_nonce
    guardian_root.mkdir(parents=True, mode=0o700)
    strategy.chmod(0o700)
    guardian_root.parent.chmod(0o700)
    guardian_root.chmod(0o700)
    obligation_path = guardian_root / "OBLIGATION.json"
    raw_stat = Path(f"/proc/{os.getpid()}/stat").read_text(encoding="ascii")
    bootstrap_start_ticks = int(raw_stat[raw_stat.rindex(")") + 2 :].split()[19])
    obligation = contract_v1.build_guardian_obligation(
        contract,
        entry_nonce=entry_nonce,
        root=str(root),
        backend=backend,
        contract_path=str(world["contract_path"]),
        target_source_path=str(target),
        target_inventory_digest=contract_v1.digest_value(inventory),
        target_directories_digest=contract_v1.digest_value(directories),
        acceptance_scope_digest="7" * 64,
        launch_claim_digest=launch_claim["launch_claim_digest"],
        prestate_identity=prestate_identity,
        bootstrap_pid=os.getpid(),
        bootstrap_process_group=os.getpgrp(),
        bootstrap_start_ticks=bootstrap_start_ticks,
        boot_identity_digest=launcher.boot_identity_digest(),
        monotonic_start_ns=time.monotonic_ns(),
    )
    launcher.persist_capture_o_excl(obligation_path, obligation)
    manager_intent = contract_v1.build_guardian_manager_intent(
        contract, obligation, obligation_path=str(obligation_path)
    )
    launcher.persist_capture_o_excl(
        guardian_root / "MANAGER.INTENT.json", manager_intent
    )
    return obligation_path, obligation, manager_intent


def _direct_sequence_claim(
    contract: dict[str, object], world: dict[str, object]
) -> dict[str, object]:
    """Bind direct supervisor fixtures to the same fixed global max1 claim.

    Production creates this claim only through the source-owned bootstrap.
    Tests that intentionally exercise the inner supervisor directly must
    materialize the exact equivalent authority rather than bypassing it.
    """
    plan = world["plan"]
    execution = plan["execution"]
    strategy = adapter._strategy_root(contract, execution)
    path = strategy / "STRATEGY.LAUNCH.CLAIM.json"
    claim = contract_v1.build_strategy_launch_claim(
        contract,
        entry_nonce=str(plan["sequence_identity"]),
        root=str(execution["root"]),
        backend=str(execution["backend"]),
        target_source_path=str(execution["target_source_path"]),
        target_inventory_digest=str(execution["target_inventory_digest"]),
        target_directories_digest=str(execution["target_directories_digest"]),
        acceptance_scope_digest=str(execution["acceptance_scope_digest"]),
        prestate_identity=str(plan["prestate_identity"]),
    )
    if path.exists() or path.is_symlink():
        observed = contract_v1.validate_strategy_launch_claim(
            contract, adapter._read_json(path)
        )
        if observed != claim:
            raise AssertionError("direct strategy claim mismatch")
        return observed
    strategy.mkdir(parents=True, exist_ok=True, mode=0o700)
    strategy.chmod(0o700)
    launcher.persist_capture_o_excl(path, claim)
    return claim


class ProductionAdapterInstalledShadowTests(unittest.TestCase):
    def _world(
        self,
        scenario: installed_shadow.InstalledShadowScenario = installed_shadow.InstalledShadowScenario(),
    ) -> tuple[tempfile.TemporaryDirectory[str], dict[str, object], dict[str, object], Path]:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        base = Path(directory.name)
        target = base / ("a" * 64)
        contract = _contract()
        installed_shadow.create_target_release(ROOT, target, contract)
        world = installed_shadow.create_world(
            contract,
            root=base / "world",
            target_source=target,
            predecessor_identity="b" * 64,
            scenario=scenario,
        )
        return directory, contract, world, base / "world"

    def test_guardian_contract_exact_schema_and_discharge_binding(self) -> None:
        _, contract, world, _ = self._world()
        obligation_path, obligation, manager_intent = _guardian_submission(
            contract, world, entry_nonce="d" * 64
        )
        self.assertEqual(
            contract_v1.validate_guardian_obligation(contract, obligation),
            obligation,
        )
        self.assertEqual(
            contract_v1.validate_guardian_manager_intent(
                contract, obligation, manager_intent
            ),
            manager_intent,
        )
        generation = contract_v1.build_guardian_generation(
            contract,
            obligation,
            manager_intent,
            generation=1,
            manager_pid=1234,
            manager_process_group=1234,
            manager_start_ticks=88,
        )
        self.assertTrue(generation["separate_from_bootstrap_process_group"])
        child = contract_v1.build_guardian_child(
            contract,
            obligation,
            generation=1,
            pid=2345,
            process_group=2345,
            start_ticks=99,
            child_entry_nonce="a" * 64,
            child_intent_digest="b" * 64,
            argv_digest="1" * 64,
            parent_nonce_sha256="2" * 64,
        )
        self.assertEqual(
            contract_v1.validate_guardian_child(contract, obligation, child),
            child,
        )
        terminal = contract_v1.build_guardian_terminal(
            contract,
            obligation,
            terminal_status="accepted",
            product_state="target_accepted",
            plan_digest="3" * 64,
            result_digest="4" * 64,
            child_capture_digest="5" * 64,
            child_terminal_digest="6" * 64,
            acceptance_nonce="7" * 64,
            recovery_count=0,
            manager_generation=1,
            orphan_count=0,
        )
        discharge = contract_v1.build_guardian_discharge(
            contract, obligation, terminal
        )
        self.assertEqual(discharge["obligation_state"], "discharged_accepted_target")
        strategy = adapter._strategy_root(contract, world["plan"]["execution"])
        launch_claim = contract_v1.validate_strategy_launch_claim(
            contract, adapter._read_json(strategy / "STRATEGY.LAUNCH.CLAIM.json")
        )
        launch_terminal = contract_v1.build_strategy_launch_terminal(
            contract, launch_claim, obligation, terminal
        )
        self.assertEqual(launch_claim["strategy_launch_max_count"], 1)
        self.assertEqual(
            launch_terminal["guardian_terminal_digest"],
            terminal["guardian_terminal_digest"],
        )
        for mutation in (
            "obligation_contract",
            "manager_environment",
            "terminal_nonce",
            "discharge_terminal",
        ):
            with self.subTest(mutation=mutation):
                if mutation == "obligation_contract":
                    value = json.loads(json.dumps(obligation))
                    value["contract_digest"] = "0" * 64
                    with self.assertRaises(contract_v1.ContractError):
                        contract_v1.validate_guardian_obligation(contract, value)
                elif mutation == "manager_environment":
                    value = json.loads(json.dumps(manager_intent))
                    value["environment"]["UNEXPECTED"] = "1"
                    with self.assertRaises(contract_v1.ContractError):
                        contract_v1.validate_guardian_manager_intent(
                            contract, obligation, value
                        )
                elif mutation == "terminal_nonce":
                    value = json.loads(json.dumps(terminal))
                    value["acceptance_nonce"] = "8" * 64
                    with self.assertRaises(contract_v1.ContractError):
                        contract_v1.validate_guardian_terminal(
                            contract, obligation, value
                        )
                else:
                    value = json.loads(json.dumps(discharge))
                    value["guardian_terminal_digest"] = "9" * 64
                    with self.assertRaises(contract_v1.ContractError):
                        contract_v1.validate_guardian_discharge(
                            contract, obligation, terminal, value
                        )
        for mutation in ("claim_extra", "claim_prestate", "launch_terminal"):
            with self.subTest(mutation=mutation):
                if mutation.startswith("claim_"):
                    value = json.loads(json.dumps(launch_claim))
                    if mutation == "claim_extra":
                        value["unexpected"] = True
                    else:
                        value["prestate_identity"] = "0" * 64
                    with self.assertRaises(contract_v1.ContractError):
                        contract_v1.validate_strategy_launch_claim(contract, value)
                else:
                    value = json.loads(json.dumps(launch_terminal))
                    value["guardian_terminal_digest"] = "0" * 64
                    with self.assertRaises(contract_v1.ContractError):
                        contract_v1.validate_strategy_launch_terminal(
                            contract,
                            launch_claim,
                            obligation,
                            terminal,
                            value,
                        )
        self.assertTrue(obligation_path.is_file())

    def test_guardian_transient_launch_is_contract_bound_and_restart_safe(self) -> None:
        _, contract, world, _ = self._world()
        _, obligation, manager_intent = _guardian_submission(
            contract,
            world,
            entry_nonce="c" * 64,
            backend="systemd",
        )
        transient = contract_v1.build_guardian_transient_launch(
            contract, obligation, manager_intent
        )
        self.assertEqual(
            transient["unit_name"],
            "myuna-p08-activation-guardian-" + "c" * 64 + ".service",
        )
        self.assertEqual(transient["properties"]["Restart"], "on-failure")
        self.assertEqual(transient["properties"]["StartLimitBurst"], "2")
        self.assertEqual(transient["properties"]["KillMode"], "control-group")
        self.assertEqual(transient["properties"]["NoNewPrivileges"], "yes")
        # The exact f08 architecture runs the privileged guardian as root so
        # install/unit/convergence authority is preserved.  Do not reclassify
        # the excluded numeric-999 double-drop hypothesis as this contract.
        self.assertEqual(contract["runtime_identity"], {"uid": 0, "gid": 0, "groups": [0]})
        self.assertEqual(transient["properties"]["User"], "0")
        self.assertEqual(transient["properties"]["Group"], "0")
        self.assertIn("--reuid=0", transient["credential_argv"])
        self.assertIn("--regid=0", transient["credential_argv"])
        self.assertIn("--groups=0", transient["credential_argv"])
        self.assertNotIn("CapabilityBoundingSet", transient["properties"])
        self.assertNotIn("AmbientCapabilities", transient["properties"])
        self.assertIn("--system", transient["argv"])
        self.assertEqual(
            transient["systemd_run_sha256"],
            contract["systemd_authority"]["systemd_run"]["sha256"],
        )
        expected_environment = manager_intent["environment"]
        self.assertEqual(
            transient["credential_argv"][:2],
            [contract["systemd_authority"]["environment_scrubber"]["path"], "-i"],
        )
        self.assertEqual(
            transient["credential_argv"][2 : 2 + len(expected_environment)],
            [
                key + "=" + str(expected_environment[key])
                for key in sorted(expected_environment)
            ],
        )
        self.assertEqual(
            transient["credential_argv"][2 + len(expected_environment)],
            contract["systemd_authority"]["credential_drop"]["path"],
        )
        self.assertEqual(transient["manager_environment"], expected_environment)
        self.assertFalse(any(value.startswith("--setenv=") for value in transient["argv"]))
        self.assertIn("--no-new-privs", transient["credential_argv"])
        self.assertTrue(transient["cgroup_inactive_before_restart"])
        self.assertTrue(transient["cgroup_single_manager_before_generation"])
        self.assertTrue(transient["durable_terminal_exit_success"])
        guardian_contract = contract["launcher"]["supervisor_bootstrap"]["guardian"]
        self.assertFalse(guardian_contract["bootstrap_product_recovery_authorized"])
        self.assertTrue(guardian_contract["guardian_only_product_recovery"])
        bootstrap_source = (ROOT / contract_v1.SUPERVISOR_BOOTSTRAP_PATH).read_text(
            encoding="utf-8"
        )
        self.assertNotIn("_recover_indeterminate_capture", bootstrap_source)
        self.assertNotIn("--recover-plan", bootstrap_source)
        for mutation in (
            "restart",
            "unit",
            "systemd_run",
            "environment_scrubber",
            "deadline",
            "manager_argv",
        ):
            with self.subTest(mutation=mutation):
                value = json.loads(json.dumps(transient))
                if mutation == "restart":
                    value["properties"]["Restart"] = "always"
                elif mutation == "unit":
                    value["unit_name"] = "substituted.service"
                elif mutation == "systemd_run":
                    value["systemd_run_sha256"] = "0" * 64
                elif mutation == "environment_scrubber":
                    value["credential_argv"][0] = "/usr/bin/substituted-env"
                elif mutation == "deadline":
                    value["monotonic_deadline_ns"] += 1
                else:
                    value["credential_argv"][-1] = "substituted"
                with self.assertRaises(contract_v1.ContractError):
                    contract_v1.validate_guardian_transient_launch(
                        contract, obligation, manager_intent, value
                    )

    def test_guardian_environment_scrubber_removes_injected_systemd_variables(
        self,
    ) -> None:
        _, contract, world, _ = self._world()
        _, obligation, manager_intent = _guardian_submission(
            contract,
            world,
            entry_nonce="2" * 64,
            backend="systemd",
        )
        transient = contract_v1.build_guardian_transient_launch(
            contract, obligation, manager_intent
        )
        expected = manager_intent["environment"]
        command = [
            contract["systemd_authority"]["environment_scrubber"]["path"],
            "-i",
            *[key + "=" + str(expected[key]) for key in sorted(expected)],
            contract["interpreter"]["invocation_path"],
            "-B",
            "-P",
            "-S",
            "-c",
            "import os,sys;sys.stdout.write('\\n'.join(sorted(os.environ)))",
        ]
        completed = subprocess.run(
            command,
            env={"INJECTED_SYSTEMD_VALUE": "tainted", "PYTHONINSPECT": "1"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(
            completed.stdout.decode("ascii").splitlines(), sorted(expected)
        )
        substituted = json.loads(json.dumps(transient))
        substituted["credential_argv"].insert(2, "INJECTED_SYSTEMD_VALUE=tainted")
        with self.assertRaises(contract_v1.ContractError):
            contract_v1.validate_guardian_transient_launch(
                contract, obligation, manager_intent, substituted
            )

    def test_guardian_obligation_rejects_boot_or_monotonic_deadline_substitution(
        self,
    ) -> None:
        _, contract, world, _ = self._world()
        _, obligation, _ = _guardian_submission(
            contract, world, entry_nonce="4" * 64
        )
        for field, replacement in (
            ("boot_identity_digest", "0" * 64),
            ("monotonic_start_ns", int(obligation["monotonic_start_ns"]) + 1),
            (
                "monotonic_deadline_ns",
                int(obligation["monotonic_deadline_ns"]) + 1,
            ),
        ):
            with self.subTest(field=field):
                value = json.loads(json.dumps(obligation))
                value[field] = replacement
                with self.assertRaises(contract_v1.ContractError):
                    contract_v1.validate_guardian_obligation(contract, value)

    def test_guardian_systemd_cgroup_requires_only_exact_current_manager(self) -> None:
        unit = "myuna-p08-activation-guardian-" + "5" * 64 + ".service"
        guardian_manager._verify_systemd_manager_cgroup(
            unit,
            pid=4242,
            cgroup_raw=f"0::/system.slice/{unit}\n",
            cgroup_procs_raw="4242\n",
        )
        for cgroup, procs in (
            (f"0::/system.slice/{unit}\n", "4242\n4243\n"),
            ("0::/system.slice/substituted.service\n", "4242\n"),
            (f"0::/system.slice/{unit}\n", "4243\n"),
        ):
            with self.subTest(cgroup=cgroup, procs=procs):
                with self.assertRaises(guardian_manager.GuardianError):
                    guardian_manager._verify_systemd_manager_cgroup(
                        unit,
                        pid=4242,
                        cgroup_raw=cgroup,
                        cgroup_procs_raw=procs,
                    )

    def test_guardian_generation_uses_one_persistent_same_boot_deadline(self) -> None:
        _, contract, world, _ = self._world()
        _, obligation, _ = _guardian_submission(
            contract, world, entry_nonce="8" * 64
        )
        start = int(obligation["monotonic_start_ns"])
        with (
            patch.object(
                guardian_manager.launcher_v1,
                "boot_identity_digest",
                return_value=obligation["boot_identity_digest"],
            ),
            patch.object(
                guardian_manager.time,
                "monotonic_ns",
                return_value=start + 1_500_000_000,
            ),
        ):
            self.assertEqual(
                guardian_manager._remaining_guardian_seconds(obligation),
                int(obligation["hard_deadline_seconds"]) - 1,
            )
        with (
            patch.object(
                guardian_manager.launcher_v1,
                "boot_identity_digest",
                return_value=obligation["boot_identity_digest"],
            ),
            patch.object(
                guardian_manager.time,
                "monotonic_ns",
                return_value=int(obligation["monotonic_deadline_ns"]),
            ),
        ):
            self.assertEqual(guardian_manager._remaining_guardian_seconds(obligation), 0)
        with patch.object(
            guardian_manager.launcher_v1,
            "boot_identity_digest",
            return_value="0" * 64,
        ):
            with self.assertRaises(guardian_manager.GuardianError):
                guardian_manager._remaining_guardian_seconds(obligation)

    def test_guardian_synthetic_manager_runs_accepted_child_and_discharges(self) -> None:
        _, contract, world, _ = self._world()
        obligation_path, obligation, manager_intent = _guardian_submission(
            contract, world, entry_nonce="d" * 64
        )
        completed = subprocess.run(
            list(manager_intent["argv"]),
            cwd=str(manager_intent["cwd"]),
            env=dict(manager_intent["environment"]),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            timeout=360,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        terminal = supervisor._validate_terminal(
            contract,
            contract_v1.validate_plan(
                contract, adapter._read_json(Path(str(obligation["plan_path"])))
            ),
            json.loads(completed.stdout),
        )
        self.assertEqual(terminal["terminal_status"], "accepted")
        guardian_root = obligation_path.parent
        accepted = contract_v1.validate_guardian_terminal(
            contract,
            obligation,
            adapter._read_json(guardian_root / "ACCEPTED.TERMINAL.json"),
        )
        discharge = contract_v1.validate_guardian_discharge(
            contract,
            obligation,
            accepted,
            adapter._read_json(guardian_root / "DISCHARGE.json"),
        )
        self.assertEqual(discharge["acceptance_nonce"], accepted["acceptance_nonce"])
        self.assertTrue((guardian_root / "GENERATION.1.json").is_file())
        child = contract_v1.validate_guardian_child(
            contract,
            obligation,
            adapter._read_json(guardian_root / "CHILD.1.json"),
        )
        self.assertNotEqual(child["process_group"], obligation["bootstrap_process_group"])

    def test_guardian_discharge_requires_exact_result_and_forward_capture_intent(
        self,
    ) -> None:
        for mutation in (
            "result_missing",
            "result_malformed",
            "result_substituted",
            "forward_capture_missing",
            "forward_intent_missing",
        ):
            with self.subTest(mutation=mutation):
                _, contract, world, _ = self._world()
                obligation_path, obligation, manager_intent = _guardian_submission(
                    contract,
                    world,
                    entry_nonce=contract_v1.digest_value(
                        {"schema": "guardian-negative.v1", "mutation": mutation}
                    ),
                )
                completed = subprocess.run(
                    list(manager_intent["argv"]),
                    cwd=str(manager_intent["cwd"]),
                    env=dict(manager_intent["environment"]),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                    timeout=360,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0)
                self.assertEqual(completed.stderr, b"")
                guardian_root = obligation_path.parent
                accepted_result = guardian_root / "ACCEPTED.RESULT.json"
                child = contract_v1.validate_guardian_child(
                    contract,
                    obligation,
                    adapter._read_json(guardian_root / "CHILD.1.json"),
                )
                forward_entry = (
                    adapter._strategy_root(contract, world["plan"]["execution"])
                    / "entries"
                    / str(child["child_entry_nonce"])
                )
                if mutation == "result_missing":
                    accepted_result.unlink()
                elif mutation == "result_malformed":
                    accepted_result.write_bytes(b"{}\n")
                elif mutation == "result_substituted":
                    value = adapter._read_json(accepted_result)
                    value["capture_count"] = int(value["capture_count"]) + 1
                    unsigned = {
                        key: item
                        for key, item in value.items()
                        if key != "receipt_digest"
                    }
                    value["receipt_digest"] = contract_v1.digest_value(unsigned)
                    accepted_result.write_bytes(contract_v1.canonical_bytes(value))
                elif mutation == "forward_capture_missing":
                    (forward_entry / "CAPTURE.json").unlink()
                else:
                    (forward_entry / "INTENT.json").unlink()
                self.assertIsNone(
                    guardian_manager._load_exact_discharge(
                        contract, obligation, guardian_root
                    )
                )

    def test_guardian_manager_lifecycle_success_requires_exact_terminal_readback(
        self,
    ) -> None:
        for valid, expected_returncode in ((True, 0), (False, 2)):
            with self.subTest(valid=valid):
                _, contract, world, _ = self._world()
                obligation_path, obligation, _ = _guardian_submission(
                    contract,
                    world,
                    entry_nonce=("e" if valid else "f") * 64,
                )
                terminal_path = obligation_path.parent / "HARDSTOP.TERMINAL.json"
                if valid:
                    result_digest = contract_v1.digest_value(
                        {
                            "obligation_digest": obligation["obligation_digest"],
                            "state": "plan_absent",
                            "mutation": False,
                        }
                    )
                    terminal = contract_v1.build_guardian_terminal(
                        contract,
                        obligation,
                        terminal_status="premutation_hard_stop",
                        product_state="unmodified",
                        plan_digest=None,
                        result_digest=result_digest,
                        child_capture_digest=None,
                        child_terminal_digest=None,
                        acceptance_nonce=None,
                        recovery_count=0,
                        manager_generation=1,
                        orphan_count=0,
                    )
                    launcher.persist_capture_o_excl(terminal_path, terminal)
                else:
                    terminal_path.write_bytes(b"{}\n")
                    terminal_path.chmod(0o600)
                output = SimpleNamespace(buffer=io.BytesIO())
                with (
                    patch.object(guardian_manager, "_verify_manager_process"),
                    patch.object(
                        guardian_manager,
                        "run_manager",
                        side_effect=guardian_manager.GuardianError(
                            "synthetic_before_result_assignment"
                        ),
                    ),
                    patch.object(guardian_manager.sys, "stdout", output),
                ):
                    returncode = guardian_manager.main(
                        [
                            "--guardian-contract",
                            str(world["contract_path"]),
                            "--guardian-obligation",
                            str(obligation_path),
                        ]
                    )
                self.assertEqual(returncode, expected_returncode)
                projected = contract_v1.validate_supervisor_bootstrap_output(
                    json.loads(output.buffer.getvalue())
                )
                self.assertEqual(projected["status"], "indeterminate")

    def test_guardian_invalid_local_hardstop_never_materializes_global_terminal(
        self,
    ) -> None:
        _, contract, world, _ = self._world()
        obligation_path, obligation, _ = _guardian_submission(
            contract,
            world,
            entry_nonce=contract_v1.digest_value(
                {"schema": "invalid-local-hardstop.v1"}
            ),
        )
        guardian_root = obligation_path.parent
        # Schema-valid but semantically impossible without a PLAN: a converged
        # terminal cannot be promoted to fixed strategy authority merely
        # because its local bytes validate.
        hard_stop = contract_v1.build_guardian_terminal(
            contract,
            obligation,
            terminal_status="converged_hard_stop",
            product_state="predecessor_converged",
            plan_digest=None,
            result_digest=contract_v1.digest_value(
                {"schema": "invalid-local-hardstop-result.v1"}
            ),
            child_capture_digest=None,
            child_terminal_digest=None,
            acceptance_nonce=None,
            recovery_count=0,
            manager_generation=1,
            orphan_count=0,
        )
        launcher.persist_capture_o_excl(
            guardian_root / "HARDSTOP.TERMINAL.json", hard_stop
        )
        global_terminal = (
            adapter._strategy_root(contract, world["plan"]["execution"])
            / "STRATEGY.LAUNCH.TERMINAL.json"
        )
        self.assertFalse(global_terminal.exists())
        with self.assertRaisesRegex(
            guardian_manager.GuardianError, "guardian_hard_stop_rejected"
        ):
            guardian_manager._load_exact_lifecycle_terminal(
                contract, obligation, guardian_root
            )
        self.assertFalse(global_terminal.exists())

    def test_guardian_restart_policy_treats_all_exact_terminals_as_lifecycle_success(
        self,
    ) -> None:
        for status, expected_returncode in (
            ("accepted", 0),
            ("premutation_hard_stop", 0),
            ("converged_hard_stop", 0),
            ("convergence_failed_hard_stop", 0),
            (None, 2),
        ):
            with self.subTest(status=status):
                _, contract, world, _ = self._world()
                obligation_path, _, _ = _guardian_submission(
                    contract,
                    world,
                    entry_nonce=contract_v1.digest_value(
                        {"schema": "restart-matrix.v1", "status": status}
                    ),
                )
                output = SimpleNamespace(buffer=io.BytesIO())
                terminal = None if status is None else {"terminal_status": status}
                with (
                    patch.object(guardian_manager, "_verify_manager_process"),
                    patch.object(
                        guardian_manager,
                        "run_manager",
                        side_effect=guardian_manager.GuardianError(
                            "synthetic_manager_crash"
                        ),
                    ),
                    patch.object(
                        guardian_manager,
                        "_load_exact_lifecycle_terminal",
                        return_value=terminal,
                    ),
                    patch.object(guardian_manager.sys, "stdout", output),
                ):
                    returncode = guardian_manager.main(
                        [
                            "--guardian-contract",
                            str(world["contract_path"]),
                            "--guardian-obligation",
                            str(obligation_path),
                        ]
                    )
                self.assertEqual(returncode, expected_returncode)

    def test_guardian_bootstrap_timeout_never_starts_concurrent_generation(self) -> None:
        manager_intent = {
            "manager_backend": "synthetic_subprocess",
            "manager_max_starts": 2,
        }
        with (
            patch.object(
                supervisor_bootstrap,
                "_run_guardian_manager_once",
                return_value=(-1, 0, "manager_wait_timeout", 0),
            ) as run_manager,
            patch.object(
                supervisor_bootstrap, "_guardian_outcome", return_value=None
            ),
        ):
            with self.assertRaises(supervisor_bootstrap.BootstrapError):
                supervisor_bootstrap._drive_guardian_manager(
                    {}, {}, manager_intent, Path("/synthetic/guardian")
                )
        self.assertEqual(run_manager.call_count, 1)

    def test_guardian_bootstrap_reentry_requires_prior_manager_exit(self) -> None:
        durable = {"terminal_status": "premutation_hard_stop"}
        with (
            patch.object(
                supervisor_bootstrap,
                "_run_guardian_manager_once",
                side_effect=(
                    (2, 0, "manager_exited", 0),
                    (0, 0, "manager_exited", 0),
                ),
            ) as run_manager,
            patch.object(
                supervisor_bootstrap,
                "_guardian_outcome",
                side_effect=(None, durable),
            ),
        ):
            observed = supervisor_bootstrap._drive_guardian_manager(
                {},
                {},
                {
                    "manager_backend": "synthetic_subprocess",
                    "manager_max_starts": 2,
                },
                Path("/synthetic/guardian"),
            )
        self.assertIs(observed, durable)
        self.assertEqual(run_manager.call_count, 2)

    def test_guardian_systemd_transient_submits_once_and_trusts_durable_terminal(
        self,
    ) -> None:
        _, contract, world, _ = self._world()
        obligation_path, obligation, manager_intent = _guardian_submission(
            contract,
            world,
            entry_nonce="6" * 64,
            backend="systemd",
        )
        durable = {"terminal_status": "converged_hard_stop"}
        completed = subprocess.CompletedProcess([], 0, stdout=None, stderr=None)
        with (
            patch.object(
                adapter,
                "_run_bound_systemd_run",
                return_value=completed,
            ) as submitted,
            patch.object(
                supervisor_bootstrap,
                "_guardian_outcome",
                return_value=durable,
            ),
            patch.object(
                supervisor_bootstrap,
                "_guardian_transient_state",
                return_value={
                    "quiescent": True,
                    "terminal_quiescent": True,
                    "lifecycle_state": "terminal_quiescent",
                    "n_restarts": 0,
                    "invocation_id": "a" * 32,
                },
            ),
        ):
            observed = supervisor_bootstrap._drive_guardian_manager(
                contract,
                obligation,
                manager_intent,
                obligation_path.parent,
            )
        self.assertIs(observed, durable)
        self.assertEqual(submitted.call_count, 1)
        transient = contract_v1.validate_guardian_transient_launch(
            contract,
            obligation,
            manager_intent,
            adapter._read_json(obligation_path.parent / "MANAGER.TRANSIENT.json"),
        )
        self.assertEqual(
            submitted.call_args.args[1], list(transient["argv"])[1:]
        )
        submission = contract_v1.validate_guardian_transient_submission(
            contract,
            obligation,
            manager_intent,
            adapter._read_json(
                obligation_path.parent / "MANAGER.TRANSIENT.SUBMITTED.json"
            ),
        )
        self.assertEqual(submission["transient_digest"], transient["transient_digest"])

    def test_guardian_transient_unit_state_is_raw_free_and_restart_bounded(
        self,
    ) -> None:
        _, contract, world, _ = self._world()
        _, obligation, manager_intent = _guardian_submission(
            contract,
            world,
            entry_nonce="7" * 64,
            backend="systemd",
        )
        transient = contract_v1.build_guardian_transient_launch(
            contract, obligation, manager_intent
        )
        unit = str(transient["unit_name"])
        active = {
            "ActiveState": "active",
            "SubState": "running",
            "LoadState": "loaded",
            "MainPID": "4242",
            "NRestarts": "1",
            "ControlGroup": "/system.slice/" + unit,
            "Result": "success",
            "ExecMainCode": "0",
            "ExecMainStatus": "0",
            "InvocationID": "a" * 32,
        }
        with (
            patch.object(adapter, "_systemctl_show", return_value=active),
            patch.object(
                supervisor_bootstrap,
                "_guardian_cgroup_members",
                return_value=[4242],
            ),
        ):
            projected = supervisor_bootstrap._guardian_transient_state(
                contract, transient
            )
        self.assertFalse(projected["quiescent"])
        self.assertEqual(projected["lifecycle_state"], "running_or_stopping")
        self.assertEqual(projected["n_restarts"], 1)
        self.assertFalse(projected["raw_output_retained"])
        inactive = {
            **active,
            "ActiveState": "inactive",
            "SubState": "dead",
            "LoadState": "loaded",
            "MainPID": "0",
            "ControlGroup": "/system.slice/" + unit,
            "InvocationID": "a" * 32,
        }
        with (
            patch.object(adapter, "_systemctl_show", return_value=inactive),
            patch.object(
                supervisor_bootstrap,
                "_guardian_cgroup_members",
                return_value=[],
            ),
        ):
            projected = supervisor_bootstrap._guardian_transient_state(
                contract, transient
            )
        self.assertTrue(projected["quiescent"])
        self.assertEqual(projected["lifecycle_state"], "terminal_quiescent")
        scheduled = {
            **active,
            "ActiveState": "activating",
            "SubState": "auto-restart",
            "MainPID": "0",
        }
        with (
            patch.object(adapter, "_systemctl_show", return_value=scheduled),
            patch.object(
                supervisor_bootstrap,
                "_guardian_cgroup_members",
                return_value=[],
            ),
        ):
            projected = supervisor_bootstrap._guardian_transient_state(
                contract, transient
            )
        self.assertEqual(projected["lifecycle_state"], "scheduled_auto_restart")
        gc_state = {
            **inactive,
            "LoadState": "not-found",
            "ControlGroup": "",
            "Result": "exit-code",
            "InvocationID": "",
        }
        with (
            patch.object(adapter, "_systemctl_show", return_value=gc_state),
            patch.object(
                supervisor_bootstrap,
                "_guardian_cgroup_members",
                return_value=None,
            ),
        ):
            projected = supervisor_bootstrap._guardian_transient_state(
                contract, transient
            )
        self.assertTrue(projected["terminal_quiescent"])
        for result, exec_code, exec_status in (
            ("start-limit-hit", "0", "0"),
            ("exit-code", "1", "203"),
        ):
            with self.subTest(terminal_result=result):
                terminal = {
                    **inactive,
                    "ActiveState": "failed",
                    "SubState": "failed",
                    "Result": result,
                    "ExecMainCode": exec_code,
                    "ExecMainStatus": exec_status,
                }
                with (
                    patch.object(adapter, "_systemctl_show", return_value=terminal),
                    patch.object(
                        supervisor_bootstrap,
                        "_guardian_cgroup_members",
                        return_value=[],
                    ),
                ):
                    projected = supervisor_bootstrap._guardian_transient_state(
                        contract, transient
                    )
                self.assertEqual(
                    projected["lifecycle_state"], "terminal_quiescent"
                )
        for field, replacement in (
            ("NRestarts", "2"),
            ("ControlGroup", "/system.slice/substituted.service"),
            ("Result", "unknown-result"),
            ("InvocationID", "not-hex"),
        ):
            with self.subTest(field=field):
                invalid = dict(active)
                invalid[field] = replacement
                with (
                    patch.object(adapter, "_systemctl_show", return_value=invalid),
                    patch.object(
                        supervisor_bootstrap,
                        "_guardian_cgroup_members",
                        return_value=[4242],
                    ),
                ):
                    with self.assertRaises(supervisor_bootstrap.BootstrapError):
                        supervisor_bootstrap._guardian_transient_state(
                            contract, transient
                        )
        with (
            patch.object(adapter, "_systemctl_show", return_value=inactive),
            patch.object(
                supervisor_bootstrap,
                "_guardian_cgroup_members",
                return_value=[5151],
            ),
        ):
            with self.assertRaises(supervisor_bootstrap.BootstrapError):
                supervisor_bootstrap._guardian_transient_state(contract, transient)

    def test_guardian_systemctl_not_found_is_typed_without_raw_output(self) -> None:
        not_found = subprocess.CompletedProcess(
            [], 4, stdout=b"LoadState=not-found\n", stderr=None
        )
        with patch.object(
            adapter, "_run_bound_systemctl", return_value=not_found
        ):
            self.assertEqual(
                adapter._systemctl_show(
                    {}, "guardian.service", ["LoadState"], allow_not_found=True
                ),
                {"LoadState": "not-found"},
            )
            with self.assertRaises(adapter.AdapterError):
                adapter._systemctl_show({}, "guardian.service", ["LoadState"])
        substituted = subprocess.CompletedProcess(
            [], 4, stdout=b"LoadState=loaded\n", stderr=None
        )
        with patch.object(
            adapter, "_run_bound_systemctl", return_value=substituted
        ):
            with self.assertRaises(adapter.AdapterError):
                adapter._systemctl_show(
                    {}, "guardian.service", ["LoadState"], allow_not_found=True
                )

    def test_guardian_cgroup_oracle_requires_exact_regular_membership(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            group = root / "system.slice" / "guardian.service"
            group.mkdir(parents=True)
            (group / "cgroup.procs").write_text("4242\n4243\n", encoding="ascii")
            self.assertEqual(
                supervisor_bootstrap._guardian_cgroup_members(
                    "/system.slice/guardian.service", cgroup_root=root
                ),
                [4242, 4243],
            )
            (group / "cgroup.procs").write_bytes(b"")
            self.assertEqual(
                supervisor_bootstrap._guardian_cgroup_members(
                    "/system.slice/guardian.service", cgroup_root=root
                ),
                [],
            )
            (group / "cgroup.procs").unlink()
            group.rmdir()
            self.assertIsNone(
                supervisor_bootstrap._guardian_cgroup_members(
                    "/system.slice/guardian.service", cgroup_root=root
                )
            )

    def test_guardian_transient_no_outcome_terminal_state_fails_without_wait(
        self,
    ) -> None:
        _, contract, world, _ = self._world()
        obligation_path, obligation, manager_intent = _guardian_submission(
            contract,
            world,
            entry_nonce="9" * 64,
            backend="systemd",
        )
        completed = subprocess.CompletedProcess([], 0, stdout=None, stderr=None)
        terminal_state = {
            "terminal_quiescent": True,
            "lifecycle_state": "terminal_quiescent",
            "n_restarts": 0,
            "invocation_id": "a" * 32,
        }
        with (
            patch.object(adapter, "_run_bound_systemd_run", return_value=completed),
            patch.object(supervisor_bootstrap, "_guardian_outcome", return_value=None),
            patch.object(
                supervisor_bootstrap,
                "_guardian_transient_state",
                return_value=terminal_state,
            ),
            patch.object(supervisor_bootstrap.time, "sleep") as slept,
        ):
            with self.assertRaisesRegex(
                supervisor_bootstrap.BootstrapError,
                "bootstrap_guardian_terminal_missing",
            ):
                supervisor_bootstrap._drive_guardian_manager(
                    contract,
                    obligation,
                    manager_intent,
                    obligation_path.parent,
                )
        slept.assert_not_called()

    def test_guardian_transient_invocation_identity_is_stable_per_generation(
        self,
    ) -> None:
        for name, second in (
            (
                "same_restart_substitution",
                {"n_restarts": 0, "invocation_id": "b" * 32},
            ),
            (
                "restart_replay",
                {"n_restarts": 1, "invocation_id": "a" * 32},
            ),
        ):
            with self.subTest(name=name):
                _, contract, world, _ = self._world()
                obligation_path, obligation, manager_intent = _guardian_submission(
                    contract,
                    world,
                    entry_nonce=contract_v1.digest_value(
                        {"schema": "guardian-invocation-test.v1", "name": name}
                    ),
                    backend="systemd",
                )
                base = {
                    "terminal_quiescent": False,
                    "lifecycle_state": "scheduled_auto_restart",
                    "n_restarts": 0,
                    "invocation_id": "a" * 32,
                }
                completed = subprocess.CompletedProcess(
                    [], 0, stdout=None, stderr=None
                )
                with (
                    patch.object(
                        adapter, "_run_bound_systemd_run", return_value=completed
                    ),
                    patch.object(
                        supervisor_bootstrap, "_guardian_outcome", return_value=None
                    ),
                    patch.object(
                        supervisor_bootstrap,
                        "_guardian_transient_state",
                        side_effect=(base, {**base, **second}),
                    ),
                    patch.object(supervisor_bootstrap.time, "sleep"),
                ):
                    with self.assertRaisesRegex(
                        supervisor_bootstrap.BootstrapError,
                        "bootstrap_guardian_invocation_rejected",
                    ):
                        supervisor_bootstrap._drive_guardian_manager(
                            contract,
                            obligation,
                            manager_intent,
                            obligation_path.parent,
                        )

    def test_guardian_generation_o_excl_survives_unit_gc_and_exhaustion(self) -> None:
        _, contract, world, _ = self._world()
        obligation_path, obligation, manager_intent = _guardian_submission(
            contract,
            world,
            entry_nonce="1" * 64,
            backend="systemd",
        )
        manager_group = int(obligation["bootstrap_process_group"]) + 1000
        with (
            patch.object(guardian_manager.os, "getpgrp", return_value=manager_group),
            patch.object(
                guardian_manager,
                "_read_start_ticks",
                return_value=(manager_group, 123456),
            ),
        ):
            self.assertEqual(
                guardian_manager._claim_generation(
                    contract, obligation, manager_intent, obligation_path.parent
                ),
                1,
            )
            self.assertEqual(
                guardian_manager._claim_generation(
                    contract, obligation, manager_intent, obligation_path.parent
                ),
                2,
            )
            with self.assertRaisesRegex(
                guardian_manager.GuardianError, "guardian_generation_exhausted"
            ):
                guardian_manager._claim_generation(
                    contract, obligation, manager_intent, obligation_path.parent
                )
        self.assertEqual(
            sorted(path.name for path in obligation_path.parent.glob("GENERATION.*.json")),
            ["GENERATION.1.json", "GENERATION.2.json"],
        )

    def test_guardian_exact_identity_zombie_is_quiesced_without_pid_absence_inference(
        self,
    ) -> None:
        child = {
            "pid": 4242,
            "process_group": 4242,
            "start_ticks": 31337,
        }
        with (
            patch.object(
                guardian_manager,
                "_read_process_identity",
                return_value=("Z", 4242, 31337),
            ),
            patch.object(guardian_manager.os, "killpg") as kill_group,
        ):
            self.assertEqual(guardian_manager._quiesce_prior_child(child), 0)
        kill_group.assert_not_called()

    def test_full_chain_no_transition_is_accepted(self) -> None:
        result, root = _run(self, installed_shadow.InstalledShadowScenario())
        self.assertEqual(result["terminal_status"], "accepted")
        self.assertEqual(result["transition_state"], "no_transition_required")
        self.assertFalse(result["forward_state_possible"])
        self.assertEqual(result["role_counts"]["formal1"], 1)
        self.assertEqual(result["role_counts"]["formal2"], 1)
        self.assertEqual(result["role_counts"]["exact_two"], 1)
        self.assertEqual(result["role_counts"]["drift"], 1)
        self.assertFalse(result["production_mutation"])
        self.assertFalse(result["raw_output_included"])
        acceptance = json.loads(
            (
                root
                / "var/lib/myuna-activation-backups/p08-activation-engine-v1/incidents"
                / result["plan_digest"]
                / "ACCEPTANCE.ACCEPTED.json"
            ).read_bytes()
        )
        self.assertEqual(acceptance["acceptance_count"], 1)
        self.assertTrue(acceptance["socket_ingress_completed"])
        self.assertEqual(
            acceptance["unit_after"]["socket_n_accepted"],
            acceptance["unit_before"]["socket_n_accepted"] + 1,
        )
        self.assertEqual(acceptance["unit_after"]["socket_n_connections"], 0)
        self.assertGreater(acceptance["unit_after"]["service_main_pid"], 0)

    def test_source_owned_bootstrap_binds_target_and_runs_full_chain(self) -> None:
        _, contract, world, root = self._world()
        completed, terminal = _run_source_owned_bootstrap(contract, world)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(terminal["terminal_status"], "accepted")
        self.assertEqual(terminal["role_counts"]["formal1"], 1)
        self.assertEqual(terminal["role_counts"]["formal2"], 1)
        self.assertEqual(terminal["role_counts"]["drift"], 1)
        self.assertEqual(terminal["invocation_failures"], 0)
        self.assertEqual(terminal["capture_persistence_failures"], 0)
        strategy = adapter._strategy_root(contract, world["plan"]["execution"])
        launch_claim = contract_v1.validate_strategy_launch_claim(
            contract, adapter._read_json(strategy / "STRATEGY.LAUNCH.CLAIM.json")
        )
        plan_path = strategy / "sequences" / terminal["sequence_identity"] / "PLAN.json"
        self.assertEqual(plan_path.stat().st_mode & 0o777, 0o600)
        plan = contract_v1.validate_plan(contract, adapter._read_json(plan_path))
        guardians = sorted((strategy / "guardians").iterdir())
        self.assertEqual(len(guardians), 1)
        self.assertEqual(guardians[0].name, terminal["sequence_identity"])
        obligation = contract_v1.validate_guardian_obligation(
            contract, adapter._read_json(guardians[0] / "OBLIGATION.json")
        )
        manager_intent = contract_v1.validate_guardian_manager_intent(
            contract,
            obligation,
            adapter._read_json(guardians[0] / "MANAGER.INTENT.json"),
        )
        accepted = contract_v1.validate_guardian_terminal(
            contract,
            obligation,
            adapter._read_json(guardians[0] / "ACCEPTED.TERMINAL.json"),
        )
        discharge = contract_v1.validate_guardian_discharge(
            contract,
            obligation,
            accepted,
            adapter._read_json(guardians[0] / "DISCHARGE.json"),
        )
        launch_terminal = contract_v1.validate_strategy_launch_terminal(
            contract,
            launch_claim,
            obligation,
            accepted,
            adapter._read_json(strategy / "STRATEGY.LAUNCH.TERMINAL.json"),
        )
        self.assertEqual(discharge["acceptance_nonce"], plan["invocation_nonce"])
        self.assertEqual(
            launch_terminal["guardian_terminal_digest"],
            accepted["guardian_terminal_digest"],
        )
        self.assertEqual(
            launch_claim["prestate_identity"], plan["prestate_identity"]
        )
        self.assertEqual(manager_intent["obligation_digest"], obligation["obligation_digest"])
        child = contract_v1.validate_guardian_child(
            contract,
            obligation,
            adapter._read_json(guardians[0] / "CHILD.1.json"),
        )
        entries = sorted((strategy / "entries").iterdir())
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].name, child["child_entry_nonce"])
        self.assertNotEqual(entries[0].name, terminal["sequence_identity"])
        intent = launcher.validate_supervisor_bootstrap_intent(
            contract, adapter._read_json(entries[0] / "INTENT.json")
        )
        self.assertEqual(intent["sequence_identity"], terminal["sequence_identity"])
        self.assertEqual(intent["entry_nonce"], entries[0].name)
        self.assertEqual(
            {value.name for value in entries[0].iterdir()},
            {"CAPTURE.json", "INTENT.json"},
        )
        self.assertTrue(root.is_dir())

    def test_source_owned_top_level_closes_pipe_and_runs_reviewed_bootstrap(
        self,
    ) -> None:
        _, contract, world, root = self._world()
        completed, result = _run_source_owned_top_level(contract, world)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["child_terminal_status"], "accepted")
        identity = launcher.windows_host_entry_identity(
            contract,
            acceptance_scope_digest="7" * 64,
            backend="synthetic",
            root=Path(str(world["plan"]["execution"]["root"])),
            target_source=Path(
                str(world["plan"]["execution"]["target_source_path"])
            ),
        )
        evidence = (
            root
            / contract["launcher"]["top_level_entry"]["evidence_root"].lstrip("/")
            / identity
        )
        intent = launcher.validate_top_level_entry_intent(
            contract, adapter._read_json(evidence / "INTENT.json")
        )
        capture = launcher.validate_top_level_entry_capture(
            contract, intent, adapter._read_json(evidence / "CAPTURE.json")
        )
        reopened = launcher.validate_top_level_entry_result(
            contract, adapter._read_json(evidence / "RESULT.json")
        )
        self.assertEqual(intent["outer_descriptor_types"]["stdin"], "fifo")
        self.assertEqual(capture["child_stdin_target"], "/dev/null")
        self.assertEqual(capture["orphan_count"], 0)
        self.assertEqual(reopened, result)

    def test_generated_preclaim_phase_matrix_is_typed_and_zero_mutation(
        self,
    ) -> None:
        reference = _contract()
        rows = reference["launcher"]["top_level_entry"]["preclaim"][
            "ordered_phases"
        ]
        for row in rows:
            with self.subTest(phase=row["phase"]):
                scenario = installed_shadow.InstalledShadowScenario(
                    fault_role="construct",
                    fault_kind=row["synthetic_fault_kind"],
                )
                _, contract, world, root = self._world(scenario)
                unit_path = (
                    root / "var/lib/myuna-activation-engine-v1/unit-state.json"
                )
                before = contract_v1.digest_value(adapter._read_json(unit_path))
                completed, result = _run_source_owned_top_level(contract, world)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stderr, b"")
                self.assertEqual(result["status"], "rejected")
                self.assertEqual(result["child_preclaim_phase"], row["phase"])
                self.assertEqual(
                    result["child_preclaim_category"],
                    row["rejection_categories"][0],
                )
                self.assertEqual(result["child_preclaim_cause_source"], "bootstrap")
                self.assertEqual(
                    result["child_preclaim_subcategory"],
                    row["rejection_categories"][0],
                )
                self.assertEqual(
                    result["child_preclaim_mutation_state"], "unmodified"
                )
                self.assertEqual(
                    result["failure_category"], row["rejection_categories"][0]
                )
                self.assertEqual(
                    contract_v1.digest_value(adapter._read_json(unit_path)), before
                )
                strategy = adapter._strategy_root(
                    contract, world["plan"]["execution"]
                )
                self.assertFalse(strategy.exists())
                identity = launcher.windows_host_entry_identity(
                    contract,
                    acceptance_scope_digest="7" * 64,
                    backend="synthetic",
                    root=Path(str(world["plan"]["execution"]["root"])),
                    target_source=Path(
                        str(world["plan"]["execution"]["target_source_path"])
                    ),
                )
                evidence = (
                    root
                    / contract["launcher"]["top_level_entry"][
                        "evidence_root"
                    ].lstrip("/")
                    / identity
                )
                intent = launcher.validate_top_level_entry_intent(
                    contract, adapter._read_json(evidence / "INTENT.json")
                )
                preclaim = contract_v1.validate_supervisor_preclaim_result(
                    contract,
                    intent,
                    adapter._read_json(evidence / "PRECLAIM.RESULT.json"),
                )
                self.assertEqual(preclaim["phase"], row["phase"])
                self.assertEqual(preclaim["classification"], "typed_rejection")
                self.assertEqual(preclaim["cause_source"], "bootstrap")
                self.assertEqual(
                    preclaim["subcategory"], row["rejection_categories"][0]
                )
                self.assertFalse(preclaim["product_mutated"])

    def test_generated_adapter_subcategories_survive_actual_preclaim_subprocess(
        self,
    ) -> None:
        reference = _contract()
        rows = reference["launcher"]["top_level_entry"]["preclaim"][
            "ordered_phases"
        ]
        for row in rows:
            faults = row["synthetic_adapter_fault_kinds"]
            if not faults:
                continue
            selected_faults = (
                faults if row["phase"] == "execution_units" else faults[:1]
            )
            for fault in selected_faults:
                with self.subTest(
                    phase=row["phase"], subcategory=fault["subcategory"]
                ):
                    scenario = installed_shadow.InstalledShadowScenario(
                        fault_role="construct",
                        fault_kind=fault["fault_kind"],
                    )
                    _, contract, world, root = self._world(scenario)
                    completed, result = _run_source_owned_top_level(contract, world)
                    self.assertEqual(completed.returncode, 2)
                    self.assertEqual(completed.stderr, b"")
                    self.assertEqual(result["status"], "rejected")
                    self.assertEqual(result["child_preclaim_phase"], row["phase"])
                    self.assertEqual(
                        result["child_preclaim_category"],
                        row["rejection_categories"][0],
                    )
                    self.assertEqual(
                        result["child_preclaim_cause_source"], "adapter"
                    )
                    self.assertEqual(
                        result["child_preclaim_subcategory"], fault["subcategory"]
                    )
                    self.assertEqual(
                        result["child_preclaim_mutation_state"], "unmodified"
                    )
                    self.assertFalse(
                        adapter._strategy_root(
                            contract, world["plan"]["execution"]
                        ).exists()
                    )

    def test_preclaim_unexpected_and_evidence_substitution_fail_closed(
        self,
    ) -> None:
        scenario = installed_shadow.InstalledShadowScenario(
            fault_role="construct",
            fault_kind="preclaim_unexpected_exception",
        )
        _, contract, world, root = self._world(scenario)
        completed, result = _run_source_owned_top_level(contract, world)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(result["status"], "indeterminate")
        self.assertEqual(result["child_preclaim_phase"], "execution_contract")
        self.assertEqual(
            result["child_preclaim_category"],
            contract["launcher"]["top_level_entry"]["preclaim"][
                "unexpected_category"
            ],
        )
        self.assertEqual(result["child_preclaim_cause_source"], "unexpected")
        self.assertEqual(
            result["child_preclaim_subcategory"],
            contract_v1.PRECLAIM_UNEXPECTED_SUBCATEGORY,
        )
        self.assertEqual(result["child_preclaim_mutation_state"], "unmodified")
        strategy = adapter._strategy_root(contract, world["plan"]["execution"])
        self.assertFalse(strategy.exists())

        identity = launcher.windows_host_entry_identity(
            contract,
            acceptance_scope_digest="7" * 64,
            backend="synthetic",
            root=Path(str(world["plan"]["execution"]["root"])),
            target_source=Path(
                str(world["plan"]["execution"]["target_source_path"])
            ),
        )
        evidence = (
            root
            / contract["launcher"]["top_level_entry"]["evidence_root"].lstrip(
                "/"
            )
            / identity
        )
        stored = adapter._read_json(evidence / "PRECLAIM.RESULT.json")
        for mutation in (
            "missing",
            "extra",
            "stale",
            "mixed",
            "wrong_source",
            "wrong_subcategory",
            "raw_tainted",
        ):
            with self.subTest(mutation=mutation):
                candidate = json.loads(contract_v1.canonical_bytes(stored))
                if mutation == "missing":
                    candidate.pop("phase_map_digest")
                elif mutation == "extra":
                    candidate["unexpected"] = True
                elif mutation == "stale":
                    candidate["contract_digest"] = "0" * 64
                elif mutation == "mixed":
                    candidate["phase"] = "execution_accounts"
                elif mutation == "wrong_source":
                    candidate["cause_source"] = "adapter"
                elif mutation == "wrong_subcategory":
                    candidate["subcategory"] = "raw_exception_text"
                else:
                    candidate["raw_output_included"] = True
                unsigned = {
                    key: value
                    for key, value in candidate.items()
                    if key != "result_digest"
                }
                candidate["result_digest"] = contract_v1.digest_value(unsigned)
                with self.assertRaises(contract_v1.ContractError):
                    contract_v1.validate_supervisor_preclaim_result(
                        contract,
                        launcher.validate_top_level_entry_intent(
                            contract, adapter._read_json(evidence / "INTENT.json")
                        ),
                        candidate,
                    )

        projected = dict(result)
        projected["child_preclaim_phase"] = None
        projected["child_preclaim_category"] = None
        projected["child_preclaim_cause_source"] = None
        projected["child_preclaim_subcategory"] = None
        projected["child_preclaim_mutation_state"] = None
        unsigned = {
            key: value for key, value in projected.items() if key != "result_digest"
        }
        projected["result_digest"] = contract_v1.digest_value(unsigned)
        with self.assertRaises(launcher.LauncherError):
            launcher.validate_top_level_entry_result(contract, projected)

    def test_existing_mixed_preclaim_evidence_fails_before_claim(self) -> None:
        scenario = installed_shadow.InstalledShadowScenario(
            fault_role="construct",
            fault_kind="preclaim_execution_contract_rejected",
        )
        _, contract, world, root = self._world(scenario)
        target = Path(str(world["plan"]["execution"]["target_source_path"]))
        identity = launcher.windows_host_entry_identity(
            contract,
            acceptance_scope_digest="7" * 64,
            backend="synthetic",
            root=Path(str(world["plan"]["execution"]["root"])),
            target_source=target,
        )
        evidence = (
            root
            / contract["launcher"]["top_level_entry"]["evidence_root"].lstrip(
                "/"
            )
            / identity
        )
        evidence.mkdir(parents=True, mode=0o700)
        evidence.chmod(0o700)
        mixed = evidence / "PRECLAIM.RESULT.json"
        mixed.write_bytes(b"{}\n")
        mixed.chmod(0o600)
        completed, result = _run_source_owned_top_level(contract, world)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(result["status"], "indeterminate")
        self.assertEqual(
            result["failure_category"], "child_preclaim_evidence_rejected"
        )
        self.assertEqual(mixed.read_bytes(), b"{}\n")
        self.assertFalse(
            adapter._strategy_root(contract, world["plan"]["execution"]).exists()
        )

    def test_top_level_rejects_prior_descriptor_shapes_and_replay_without_mutation(
        self,
    ) -> None:
        for shape in ("direct_bootstrap_pipe", "top_level_devnull", "wrong_env"):
            with self.subTest(shape=shape):
                _, contract, world, root = self._world()
                unit_path = root / "var/lib/myuna-activation-engine-v1/unit-state.json"
                before = contract_v1.digest_value(adapter._read_json(unit_path))
                if shape == "direct_bootstrap_pipe":
                    _remove_bootstrap_scaffold(contract, world)
                    child = subprocess.run(
                        _source_owned_bootstrap_command(contract, world),
                        cwd=Path(
                            str(world["plan"]["execution"]["target_source_path"])
                        ),
                        env=_source_owned_bootstrap_environment(world),
                        input=b"",
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=60,
                        check=False,
                    )
                    projection = contract_v1.validate_supervisor_bootstrap_output(
                        json.loads(child.stdout)
                    )
                    self.assertEqual(child.returncode, 2)
                    self.assertEqual(projection["status"], "indeterminate")
                elif shape == "top_level_devnull":
                    child, projection = _run_source_owned_top_level(
                        contract, world, stdin=subprocess.DEVNULL
                    )
                    self.assertEqual(child.returncode, 2)
                    self.assertEqual(projection["status"], "rejected")
                else:
                    environment = _source_owned_top_level_environment(
                        contract, world
                    )
                    environment["MYUNA_P08_WINDOWS_HOST_ENTRY_IDENTITY"] = "0" * 64
                    child, projection = _run_source_owned_top_level(
                        contract, world, environment=environment
                    )
                    self.assertEqual(child.returncode, 2)
                    self.assertEqual(projection["status"], "rejected")
                self.assertEqual(child.stderr, b"")
                self.assertEqual(
                    contract_v1.digest_value(adapter._read_json(unit_path)), before
                )

        _, contract, world, root = self._world()
        accepted, accepted_result = _run_source_owned_top_level(contract, world)
        self.assertEqual(accepted.returncode, 0)
        unit_path = root / "var/lib/myuna-activation-engine-v1/unit-state.json"
        before_replay = contract_v1.digest_value(adapter._read_json(unit_path))
        target = Path(str(world["plan"]["execution"]["target_source_path"]))
        replay = subprocess.run(
            _source_owned_top_level_command(contract, world),
            cwd=target,
            env=_source_owned_top_level_environment(contract, world),
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )
        replay_result = launcher.validate_top_level_entry_result(
            contract, json.loads(replay.stdout)
        )
        self.assertEqual(replay.returncode, 2)
        self.assertEqual(replay.stderr, b"")
        self.assertEqual(replay_result["status"], "rejected")
        self.assertEqual(accepted_result["entry_identity"], replay_result["entry_identity"])
        self.assertEqual(
            contract_v1.digest_value(adapter._read_json(unit_path)), before_replay
        )

    def test_materialized_windows_launcher_executes_real_direct_wsl_chain(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".p08-win-entry-", dir=ROOT.parents[1]
        ) as raw:
            base = Path(raw)
            transport_target = base / ("a" * 64)
            contract = _contract()
            installed_shadow.create_target_release(ROOT, transport_target, contract)
            with tempfile.TemporaryDirectory(prefix="p08-win-target-") as target_raw:
                target = Path(target_raw) / ("a" * 64)
                installed_shadow.create_target_release(ROOT, target, contract)
                world = installed_shadow.create_world(
                    contract,
                    root=Path(target_raw) / "world",
                    target_source=target,
                    predecessor_identity="b" * 64,
                    scenario=installed_shadow.InstalledShadowScenario(),
                )
                _remove_bootstrap_scaffold(contract, world)
                root = Path(str(world["plan"]["execution"]["root"]))
                executable = transport_target / str(
                    contract["launcher"]["top_level_entry"]["host_launcher"][
                        "artifact_path"
                    ]
                )
                command = [
                    str(executable),
                    "--activation-contract",
                    _windows_drive_path(
                        transport_target / "contracts/P08_ACTIVATION_CONTRACT.json"
                    ),
                    "--activation-contract-linux",
                    str(world["contract_path"]),
                    "--activation-root",
                    str(root),
                    "--activation-backend",
                    "synthetic",
                    "--activation-target-source",
                    str(target),
                    "--acceptance-scope-digest",
                    "7" * 64,
                ]
                completed = subprocess.run(
                    command,
                    cwd=transport_target,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=360,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0)
                self.assertEqual(completed.stderr, b"")
                result = launcher.validate_top_level_entry_result(
                    contract, json.loads(completed.stdout)
                )
                self.assertEqual(result["status"], "accepted")
                capture_path = (
                    root
                    / contract["launcher"]["top_level_entry"]["evidence_root"].lstrip("/")
                    / result["entry_identity"]
                    / "HOST.CAPTURE.json"
                )
                host_capture = adapter._read_json(capture_path)
                self.assertEqual(
                    host_capture["schema"], contract_v1.WINDOWS_WSL_CAPTURE_SCHEMA
                )
                self.assertEqual(host_capture["canonical_status"], "complete")
                self.assertTrue(host_capture["stderr_classification_allowed"])
                self.assertFalse(host_capture["raw_output_retained"])
                self.assertEqual(host_capture["orphan_count"], 0)

                # The persisted host projection is an exact, raw-free authority
                # object.  Recompute its digest for semantic substitutions so the
                # rejection proves the field contract rather than only the digest.
                def recapture(**updates: object) -> dict[str, object]:
                    candidate = json.loads(json.dumps(host_capture))
                    candidate.update(updates)
                    unsigned = {
                        key: value
                        for key, value in candidate.items()
                        if key != "capture_digest"
                    }
                    candidate["capture_digest"] = contract_v1.digest_value(unsigned)
                    return candidate

                rejected_captures = {
                    "wrong_launcher": recapture(host_launcher_sha256="0" * 64),
                    "wrong_transport": recapture(wsl_sha256="1" * 64),
                    "raw_tainted": recapture(raw_output_retained=True),
                    "orphan": recapture(orphan_count=1),
                    "unknown_exit": recapture(exit_class="unknown"),
                    "oversize": recapture(
                        stdout_size=int(
                            contract["launcher"]["top_level_entry"][
                                "host_launcher"
                            ]["stdout_limit"]
                        )
                        + 1
                    ),
                }
                missing = json.loads(json.dumps(host_capture))
                missing.pop("wsl_sha256")
                rejected_captures["missing"] = missing
                extra = json.loads(json.dumps(host_capture))
                extra["raw_detail"] = False
                rejected_captures["extra"] = extra
                for name, candidate in rejected_captures.items():
                    with self.subTest(host_capture=name):
                        with self.assertRaises(launcher.LauncherError):
                            launcher.validate_windows_wsl_capture(contract, candidate)

                persist_result = adapter._read_json(
                    capture_path.with_name("HOST.PERSIST.RESULT.json")
                )
                launcher.validate_windows_capture_persist_result(
                    contract, persist_result
                )

                def repersist(**updates: object) -> dict[str, object]:
                    candidate = json.loads(json.dumps(persist_result))
                    candidate.update(updates)
                    unsigned = {
                        key: value
                        for key, value in candidate.items()
                        if key != "result_digest"
                    }
                    candidate["result_digest"] = contract_v1.digest_value(unsigned)
                    return candidate

                rejected_persist_results = {
                    "wrong_schema": repersist(schema="unknown"),
                    "wrong_contract": repersist(contract_digest="2" * 64),
                    "raw_tainted": repersist(raw_output_included=True),
                    "retry": repersist(retry_authorized=True),
                    "unknown_status": repersist(status="unknown"),
                }
                missing_result = json.loads(json.dumps(persist_result))
                missing_result.pop("capture_digest")
                rejected_persist_results["missing"] = missing_result
                extra_result = json.loads(json.dumps(persist_result))
                extra_result["raw_detail"] = False
                rejected_persist_results["extra"] = extra_result
                for name, candidate in rejected_persist_results.items():
                    with self.subTest(persist_result=name):
                        with self.assertRaises(launcher.LauncherError):
                            launcher.validate_windows_capture_persist_result(
                                contract, candidate
                            )

    def test_windows_launcher_uses_explicit_handle_allowlist_and_no_shell(
        self,
    ) -> None:
        contract = _contract()
        host = contract["launcher"]["top_level_entry"]["host_launcher"]
        self.assertTrue(host["direct_create_process"])
        self.assertTrue(host["explicit_handle_allowlist"])
        self.assertTrue(host["kill_on_close_job"])
        self.assertTrue(host["closed_parent_stdin"])
        self.assertFalse(host["host_shell_allowed"])
        source = (
            ROOT / str(host["source_path"])
        ).read_text(encoding="utf-8")
        for required in (
            "CreateProcessW(",
            "PROC_THREAD_ATTRIBUTE_HANDLE_LIST",
            "EXTENDED_STARTUPINFO_PRESENT",
            "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
            "TerminateProcess(process.hProcess",
            "TerminateJobObject(job",
        ):
            self.assertIn(required, source)
        for prohibited in (
            "Process.Start(",
            "cmd.exe",
            "powershell.exe",
            "bash -c",
            "sh -c",
        ):
            self.assertNotIn(prohibited, source)

    def test_exact_windows_wsl_transport_kill_leaves_no_guest_orphan(
        self,
    ) -> None:
        contract = _contract()
        transport = contract["launcher"]["top_level_entry"]["transport"]
        marker = "p08-wsl-orphan-" + sha256(
            str(time.time_ns()).encode("ascii")
        ).hexdigest()
        code = (
            "import os,time;print(os.getpid(),flush=True);time.sleep(120)"
        )
        child = subprocess.Popen(
            [
                str(transport["guest_visible_path"]),
                "--distribution",
                str(transport["distribution"]),
                "--user",
                "root",
                "--exec",
                str(contract["interpreter"]["invocation_path"]),
                "-c",
                code,
                marker,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert child.stdout is not None
        guest_pid = int(child.stdout.readline().strip())
        guest_stat = Path(f"/proc/{guest_pid}/stat")
        try:
            child.kill()
            child.wait(timeout=10)
            deadline = time.monotonic() + 5
            while guest_stat.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertFalse(guest_stat.exists())
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
            if child.stdout is not None:
                child.stdout.close()
            if child.stderr is not None:
                child.stderr.close()
            if guest_stat.exists():
                cmdline = Path(f"/proc/{guest_pid}/cmdline").read_bytes()
                if marker.encode("ascii") in cmdline:
                    os.kill(guest_pid, 9)

    def test_strategy_launch_claim_allows_only_empty_preclaim_root(self) -> None:
        _, contract, world, _ = self._world()
        _remove_bootstrap_scaffold(contract, world)
        strategy = adapter._strategy_root(contract, world["plan"]["execution"])
        strategy.mkdir(parents=True, mode=0o700, exist_ok=True)
        strategy.chmod(0o700)
        completed, terminal = _run_source_owned_bootstrap(contract, world)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(terminal["terminal_status"], "accepted")

        for residue_kind in ("guardian", "sequence", "temporary", "symlink"):
            with self.subTest(residue_kind=residue_kind):
                _, current_contract, current_world, root = self._world()
                _remove_bootstrap_scaffold(current_contract, current_world)
                current = adapter._strategy_root(
                    current_contract, current_world["plan"]["execution"]
                )
                current.mkdir(parents=True, mode=0o700, exist_ok=True)
                current.chmod(0o700)
                if residue_kind == "guardian":
                    (current / "guardians").mkdir(mode=0o700)
                elif residue_kind == "sequence":
                    (current / "sequences").mkdir(mode=0o700)
                elif residue_kind == "temporary":
                    (current / "CLAIM.tmp").write_bytes(b"")
                else:
                    (current / "claim-link").symlink_to(current / "missing")
                unit_path = (
                    root / "var/lib/myuna-activation-engine-v1/unit-state.json"
                )
                before = contract_v1.digest_value(adapter._read_json(unit_path))
                rejected, projection = _run_source_owned_bootstrap(
                    current_contract, current_world
                )
                self.assertEqual(rejected.returncode, 2)
                self.assertEqual(
                    projection["schema"], contract_v1.SUPERVISOR_ENTRY_SCHEMA
                )
                self.assertFalse(
                    (current / "STRATEGY.LAUNCH.CLAIM.json").exists()
                )
                self.assertFalse((current / "guardians" / ("0" * 64)).exists())
                self.assertEqual(
                    contract_v1.digest_value(adapter._read_json(unit_path)), before
                )

    def test_strategy_launch_claim_serializes_concurrent_top_level_bootstraps(
        self,
    ) -> None:
        _, contract, world, root = self._world()
        _remove_bootstrap_scaffold(contract, world)
        command = _source_owned_bootstrap_command(contract, world)
        environment = _source_owned_bootstrap_environment(world)
        target = Path(str(world["plan"]["execution"]["target_source_path"]))
        children = [
            subprocess.Popen(
                command,
                cwd=target,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for _ in range(2)
        ]
        completed = []
        for child in children:
            stdout, stderr = child.communicate(timeout=360)
            completed.append((child.returncode, stdout, stderr))
        self.assertEqual(sorted(item[0] for item in completed), [0, 2])
        self.assertTrue(all(item[2] == b"" for item in completed))
        projections = [
            contract_v1.validate_supervisor_bootstrap_output(json.loads(item[1]))
            for item in completed
        ]
        accepted = next(
            item for item in projections if item.get("terminal_status") == "accepted"
        )
        rejected = next(
            item for item in projections if item.get("schema") == contract_v1.SUPERVISOR_ENTRY_SCHEMA
        )
        self.assertEqual(rejected["status"], "indeterminate")
        self.assertEqual(accepted["role_counts"]["claim"], 1)
        strategy = adapter._strategy_root(contract, world["plan"]["execution"])
        claim = contract_v1.validate_strategy_launch_claim(
            contract, adapter._read_json(strategy / "STRATEGY.LAUNCH.CLAIM.json")
        )
        self.assertEqual(claim["entry_nonce"], accepted["sequence_identity"])
        self.assertEqual(len(list((strategy / "guardians").iterdir())), 1)
        self.assertEqual(len(list((strategy / "sequences").iterdir())), 1)
        before_replay = [
            (
                str(path.relative_to(strategy)),
                sha256(path.read_bytes()).hexdigest(),
            )
            for path in sorted(strategy.rglob("*"))
            if path.is_file() and not path.is_symlink()
        ]
        replay = subprocess.run(
            command,
            cwd=target,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )
        self.assertEqual(replay.returncode, 2)
        self.assertEqual(replay.stderr, b"")
        replay_projection = contract_v1.validate_supervisor_bootstrap_output(
            json.loads(replay.stdout)
        )
        self.assertEqual(
            replay_projection["schema"], contract_v1.SUPERVISOR_ENTRY_SCHEMA
        )
        after_replay = [
            (
                str(path.relative_to(strategy)),
                sha256(path.read_bytes()).hexdigest(),
            )
            for path in sorted(strategy.rglob("*"))
            if path.is_file() and not path.is_symlink()
        ]
        self.assertEqual(after_replay, before_replay)
        unit = adapter._read_json(
            root / "var/lib/myuna-activation-engine-v1/unit-state.json"
        )
        self.assertTrue(unit["service_active"])
        self.assertTrue(unit["socket_active"])

    def test_guardian_reboot_boundary_is_source_closed_but_live_unauthorized(self) -> None:
        contract = _contract()
        guardian = contract["launcher"]["supervisor_bootstrap"]["guardian"]
        self.assertFalse(guardian["same_boot_guardian_only"])
        self.assertTrue(guardian["boot_resumable_recovery_implemented"])
        self.assertEqual(
            guardian["reboot_after_mutation_classification"],
            "boot_resumable_same_plan_recovery_gate_implemented",
        )
        self.assertFalse(contract["production_live_authorized"])

    def test_exact_guardian_discharge_preserves_target_on_synthetic_reboot(self) -> None:
        _, contract, world, root = self._world()
        completed, terminal = _run_source_owned_bootstrap(contract, world)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(terminal["terminal_status"], "accepted")
        _, plan, arm, _, _, _ = boot_recovery._load_arm_bundle(contract, root)
        unit = adapter._unit_state(contract, plan)
        if unit["socket_active"]:
            adapter._remove_synthetic_socket(contract, plan["execution"])
        unit["service_active"] = False
        unit["socket_active"] = False
        unit["service_main_pid"] = 0
        unit["service_process"] = None
        unit["socket_inode"] = None
        for role in ("service", "socket"):
            unit["effective"][role]["active_state"] = "inactive"
            unit["effective"][role]["sub_state"] = "dead"
        unit["coupled_state"] = "stopped"
        adapter._write_unit_state(contract, plan, unit)
        boot_id = "e" * 64
        if boot_id == arm["arm_boot_identity_digest"]:
            boot_id = "d" * 64
        recovered = boot_recovery.execute_boot_recovery(
            contract,
            activation_root=root,
            boot_identity_digest=boot_id,
            monotonic_start_ns=100_000,
        )
        self.assertEqual(recovered["state"], "accepted_preserved")
        self.assertEqual(recovered["convergence_count"], 0)
        self.assertTrue(recovered["product_start_authorized"])
        self.assertTrue(
            adapter._boot_product_exact(
                contract, plan, final_state="target", allow_active=False
            )
        )

    def test_outer_indeterminate_before_plan_is_premutation_terminal(self) -> None:
        scenario = installed_shadow.InstalledShadowScenario(
            fault_role="construct",
            fault_kind="outer_kill_before_plan",
        )
        _, contract, world, _ = self._world(scenario)
        completed, terminal = _run_source_owned_bootstrap(contract, world)
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(
            terminal["schema"], contract_v1.SUPERVISOR_OUTER_TERMINAL_SCHEMA
        )
        self.assertEqual(terminal["terminal_status"], "premutation_hard_stop")
        self.assertEqual(terminal["product_state"], "unmodified")
        self.assertEqual(terminal["recovery_count"], 0)
        self.assertIsNone(terminal["plan_digest"])
        strategy = adapter._strategy_root(contract, world["plan"]["execution"])
        self.assertFalse(
            (
                strategy
                / "sequences"
                / terminal["entry_nonce"]
                / "PLAN.json"
            ).exists()
        )
        guardian = strategy / "guardians" / terminal["entry_nonce"]
        obligation = contract_v1.validate_guardian_obligation(
            contract, adapter._read_json(guardian / "OBLIGATION.json")
        )
        child = contract_v1.validate_guardian_child(
            contract, obligation, adapter._read_json(guardian / "CHILD.1.json")
        )
        entry = strategy / "entries" / child["child_entry_nonce"]
        self.assertEqual(
            {path.name for path in entry.iterdir()},
            {"INTENT.json", "CAPTURE.json"},
        )
        hard_stop = contract_v1.validate_guardian_terminal(
            contract,
            obligation,
            adapter._read_json(guardian / "HARDSTOP.TERMINAL.json"),
        )
        self.assertEqual(hard_stop["terminal_status"], "premutation_hard_stop")

    def test_outer_killed_after_first_unit_mutation_recovers_once(self) -> None:
        scenario = installed_shadow.InstalledShadowScenario(
            fault_role="stop_socket",
            fault_kind="outer_kill_after_mutation",
        )
        _, contract, world, root = self._world(scenario)
        completed, terminal = _run_source_owned_bootstrap(contract, world)
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(terminal["terminal_status"], "converged_hard_stop")
        self.assertTrue(terminal["action_claimed"])
        self.assertFalse(terminal["product_mutated"])
        self.assertEqual(terminal["role_counts"]["stop_socket"], 1)
        self.assertEqual(terminal["role_counts"]["converge"], 1)
        self.assertEqual(terminal["role_counts"]["recover"], 1)
        strategy = adapter._strategy_root(contract, world["plan"]["execution"])
        entries = sorted((strategy / "entries").iterdir())
        self.assertEqual(len(entries), 2)
        self.assertTrue(
            all(
                {path.name for path in entry.iterdir()}
                == {"CAPTURE.json", "INTENT.json"}
                for entry in entries
            )
        )
        guardian = strategy / "guardians" / terminal["sequence_identity"]
        obligation = contract_v1.validate_guardian_obligation(
            contract, adapter._read_json(guardian / "OBLIGATION.json")
        )
        child = contract_v1.validate_guardian_child(
            contract, obligation, adapter._read_json(guardian / "CHILD.1.json")
        )
        hard_stop = contract_v1.validate_guardian_terminal(
            contract,
            obligation,
            adapter._read_json(guardian / "HARDSTOP.TERMINAL.json"),
        )
        self.assertEqual(hard_stop["terminal_status"], "converged_hard_stop")
        self.assertEqual(hard_stop["recovery_count"], 1)
        original = strategy / "entries" / child["child_entry_nonce"]
        original_capture = adapter._read_json(original / "CAPTURE.json")
        recovery = next(entry for entry in entries if entry != original)
        recovery_intent = adapter._read_json(recovery / "INTENT.json")
        self.assertEqual(
            recovery_intent["origin_entry_nonce"], terminal["sequence_identity"]
        )
        self.assertEqual(
            recovery_intent["origin_capture_digest"],
            original_capture["capture_digest"],
        )
        self.assertEqual(recovery_intent["recover_plan"], str(
            strategy / "sequences" / terminal["sequence_identity"] / "PLAN.json"
        ))
        self.assertEqual(recovery_intent["sequence_identity"], terminal["sequence_identity"])
        self.assertEqual(
            adapter._read_json(
                strategy
                / "sequences"
                / terminal["sequence_identity"]
                / "GUARDIAN.RECOVERY.TERMINAL.json"
            ),
            terminal,
        )
        replay = subprocess.run(
            list(recovery_intent["argv"]),
            cwd=str(recovery_intent["cwd"]),
            env=dict(recovery_intent["environment"]),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        self.assertEqual(replay.returncode, 2)
        self.assertEqual(replay.stderr, b"")
        replay_result = contract_v1.validate_supervisor_bootstrap_output(
            json.loads(replay.stdout)
        )
        self.assertEqual(replay_result["status"], "indeterminate")
        self.assertEqual(len(list((strategy / "entries").iterdir())), 2)
        selector = adapter._read_json(
            root / "etc/myuna-active-temporal-context-v1/selector.json"
        )
        self.assertEqual(selector["release_digest"], "b" * 64)

    def test_outer_noncanonical_after_mutation_also_converges(self) -> None:
        for kind in (
            "outer_noncanonical_after_mutation",
            "outer_oversized_after_mutation",
        ):
            with self.subTest(kind=kind):
                scenario = installed_shadow.InstalledShadowScenario(
                    fault_role="stop_socket",
                    fault_kind=kind,
                )
                _, contract, world, _ = self._world(scenario)
                completed, terminal = _run_source_owned_bootstrap(contract, world)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stderr, b"")
                self.assertEqual(
                    terminal["terminal_status"], "converged_hard_stop"
                )
                self.assertEqual(terminal["role_counts"]["converge"], 1)
                strategy = adapter._strategy_root(
                    contract, world["plan"]["execution"]
                )
                self.assertEqual(len(list((strategy / "entries").iterdir())), 2)

    def test_outer_recovery_failure_is_nonretryable_terminal(self) -> None:
        scenario = installed_shadow.InstalledShadowScenario(
            fault_role="stop_socket",
            fault_kind="outer_kill_after_mutation_recovery_rejected",
        )
        _, contract, world, _ = self._world(scenario)
        completed, terminal = _run_source_owned_bootstrap(contract, world)
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(
            terminal["terminal_status"], "convergence_failed_hard_stop"
        )
        self.assertTrue(terminal["action_claimed"])
        self.assertEqual(terminal["role_counts"]["converge"], 1)
        strategy = adapter._strategy_root(contract, world["plan"]["execution"])
        self.assertEqual(len(list((strategy / "entries").iterdir())), 2)

    def test_guardian_post_child_persistence_failures_converge_once(self) -> None:
        kinds = (
            "guardian_capture_create_failed_after_mutation",
            "guardian_capture_write_failed_after_mutation",
            "guardian_capture_fsync_failed_after_mutation",
            "guardian_capture_readback_failed_after_mutation",
            "guardian_capture_validation_failed_after_mutation",
            "guardian_accepted_result_persist_failed",
            "guardian_accepted_terminal_persist_failed",
            "guardian_discharge_persist_failed",
        )
        for kind in kinds:
            with self.subTest(kind=kind):
                scenario = installed_shadow.InstalledShadowScenario(
                    fault_role="stop_socket", fault_kind=kind
                )
                _, contract, world, root = self._world(scenario)
                completed, terminal = _run_source_owned_bootstrap(contract, world)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stderr, b"")
                self.assertEqual(terminal["terminal_status"], "converged_hard_stop")
                self.assertEqual(terminal["role_counts"]["recover"], 1)
                self.assertEqual(terminal["role_counts"]["converge"], 1)
                self.assertFalse(terminal["product_mutated"])
                strategy = adapter._strategy_root(
                    contract, world["plan"]["execution"]
                )
                guardian = (
                    strategy / "guardians" / terminal["sequence_identity"]
                )
                obligation = contract_v1.validate_guardian_obligation(
                    contract, adapter._read_json(guardian / "OBLIGATION.json")
                )
                hard_stop = contract_v1.validate_guardian_terminal(
                    contract,
                    obligation,
                    adapter._read_json(guardian / "HARDSTOP.TERMINAL.json"),
                )
                self.assertEqual(hard_stop["recovery_count"], 1)
                self.assertFalse((guardian / "DISCHARGE.json").exists())
                unit = adapter._read_json(
                    root
                    / "var/lib/myuna-activation-engine-v1/unit-state.json"
                )
                self.assertTrue(unit["service_active"])
                self.assertTrue(unit["socket_active"])
                selector = adapter._read_json(
                    root / "etc/myuna-active-temporal-context-v1/selector.json"
                )
                self.assertEqual(selector["release_digest"], "b" * 64)

    def test_guardian_recovery_evidence_or_terminal_failure_still_converges(
        self,
    ) -> None:
        for kind in (
            "guardian_recovery_capture_persist_failed",
            "guardian_hardstop_terminal_persist_failed",
        ):
            with self.subTest(kind=kind):
                scenario = installed_shadow.InstalledShadowScenario(
                    fault_role="stop_socket", fault_kind=kind
                )
                _, contract, world, root = self._world(scenario)
                completed, terminal = _run_source_owned_bootstrap(contract, world)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stderr, b"")
                self.assertEqual(terminal["terminal_status"], "converged_hard_stop")
                self.assertEqual(terminal["role_counts"]["recover"], 1)
                self.assertEqual(terminal["role_counts"]["converge"], 1)
                strategy = adapter._strategy_root(
                    contract, world["plan"]["execution"]
                )
                guardian = (
                    strategy / "guardians" / terminal["sequence_identity"]
                )
                generations = sorted(guardian.glob("GENERATION.*.json"))
                expected_generations = (
                    2 if kind == "guardian_hardstop_terminal_persist_failed" else 1
                )
                self.assertEqual(len(generations), expected_generations)
                unit = adapter._read_json(
                    root
                    / "var/lib/myuna-activation-engine-v1/unit-state.json"
                )
                self.assertTrue(unit["service_active"])
                self.assertTrue(unit["socket_active"])

    def test_guardian_obligation_failure_is_premutation_and_has_no_recovery(
        self,
    ) -> None:
        scenario = installed_shadow.InstalledShadowScenario(
            fault_kind="guardian_obligation_persist_failed_before_plan"
        )
        _, contract, world, _ = self._world(scenario)
        strategy = adapter._strategy_root(contract, world["plan"]["execution"])
        completed, terminal = _run_source_owned_bootstrap(contract, world)
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(
            terminal["schema"], contract_v1.SUPERVISOR_OUTER_TERMINAL_SCHEMA
        )
        self.assertEqual(terminal["terminal_status"], "premutation_hard_stop")
        self.assertEqual(terminal["product_state"], "unmodified")
        self.assertEqual(terminal["recovery_count"], 0)
        claim = contract_v1.validate_strategy_launch_claim(
            contract, adapter._read_json(strategy / "STRATEGY.LAUNCH.CLAIM.json")
        )
        global_terminal = (
            contract_v1.validate_strategy_launch_premutation_terminal(
                contract,
                claim,
                terminal,
                adapter._read_json(strategy / "STRATEGY.LAUNCH.TERMINAL.json"),
            )
        )
        self.assertEqual(
            global_terminal["outer_terminal_digest"], terminal["terminal_digest"]
        )
        self.assertEqual(
            {path.name for path in strategy.iterdir()},
            {"STRATEGY.LAUNCH.CLAIM.json", "STRATEGY.LAUNCH.TERMINAL.json"},
        )
        self.assertFalse((strategy / "sequences").exists())
        self.assertFalse((strategy / "guardians").exists())

    def test_guardian_manager_sigkill_boundary_matrix_is_single_action(self) -> None:
        expectations = {
            "guardian_manager_sigkill_after_plan": "premutation_hard_stop",
            "guardian_manager_sigkill_after_mutation": "converged_hard_stop",
            "guardian_manager_sigkill_after_accepted_result": "converged_hard_stop",
            "guardian_manager_sigkill_after_accepted_terminal": "converged_hard_stop",
            "guardian_manager_sigkill_after_discharge": "accepted",
        }
        for kind, expected_status in expectations.items():
            with self.subTest(kind=kind):
                scenario = installed_shadow.InstalledShadowScenario(
                    fault_role="stop_socket", fault_kind=kind
                )
                _, contract, world, root = self._world(scenario)
                completed, terminal = _run_source_owned_bootstrap(contract, world)
                expected_returncode = 0 if expected_status == "accepted" else 2
                self.assertEqual(completed.returncode, expected_returncode)
                self.assertEqual(completed.stderr, b"")
                self.assertEqual(terminal["terminal_status"], expected_status)
                strategy = adapter._strategy_root(
                    contract, world["plan"]["execution"]
                )
                guardian = strategy / "guardians" / terminal["sequence_identity"]
                obligation = contract_v1.validate_guardian_obligation(
                    contract, adapter._read_json(guardian / "OBLIGATION.json")
                )
                guardian_terminal_path = (
                    guardian / "ACCEPTED.TERMINAL.json"
                    if expected_status == "accepted"
                    else guardian / "HARDSTOP.TERMINAL.json"
                )
                guardian_terminal = contract_v1.validate_guardian_terminal(
                    contract,
                    obligation,
                    adapter._read_json(guardian_terminal_path),
                )
                claim = contract_v1.validate_strategy_launch_claim(
                    contract,
                    adapter._read_json(
                        strategy / "STRATEGY.LAUNCH.CLAIM.json"
                    ),
                )
                strategy_terminal = contract_v1.validate_strategy_launch_terminal(
                    contract,
                    claim,
                    obligation,
                    guardian_terminal,
                    adapter._read_json(
                        strategy / "STRATEGY.LAUNCH.TERMINAL.json"
                    ),
                )
                self.assertEqual(
                    strategy_terminal["terminal_status"], expected_status
                )
                generations = sorted(guardian.glob("GENERATION.*.json"))
                self.assertEqual(
                    len(generations),
                    1 if kind == "guardian_manager_sigkill_after_discharge" else 2,
                )
                if expected_status == "accepted":
                    self.assertTrue((guardian / "DISCHARGE.json").is_file())
                    self.assertEqual(terminal["role_counts"].get("recover", 0), 0)
                else:
                    self.assertEqual(
                        terminal["role_counts"].get("recover", 0),
                        0 if kind == "guardian_manager_sigkill_after_plan" else 1,
                    )
                    self.assertLessEqual(
                        terminal["role_counts"].get("claim", 0), 1
                    )
                    unit = adapter._read_json(
                        root
                        / "var/lib/myuna-activation-engine-v1/unit-state.json"
                    )
                    self.assertTrue(unit["service_active"])
                    self.assertTrue(unit["socket_active"])

    def test_bootstrap_sigkill_after_mutation_does_not_abort_guardian_action(
        self,
    ) -> None:
        scenario = installed_shadow.InstalledShadowScenario(
            fault_role="stop_socket",
            fault_kind="guardian_bootstrap_sigkill_after_mutation",
        )
        _, contract, world, root = self._world(scenario)
        target = Path(str(world["plan"]["execution"]["target_source_path"]))
        _remove_bootstrap_scaffold(contract, world)
        completed = subprocess.run(
            _source_owned_bootstrap_command(contract, world),
            cwd=target,
            env=_source_owned_bootstrap_environment(world),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )
        self.assertEqual(completed.returncode, -9)
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"")
        strategy = adapter._strategy_root(contract, world["plan"]["execution"])
        terminal = None
        guardian = None
        for _ in range(200):
            guardians = (
                list((strategy / "guardians").iterdir())
                if (strategy / "guardians").is_dir()
                else []
            )
            if len(guardians) == 1:
                guardian = guardians[0]
                obligation = contract_v1.validate_guardian_obligation(
                    contract,
                    adapter._read_json(guardian / "OBLIGATION.json"),
                )
                terminal = supervisor_bootstrap._guardian_outcome(
                    contract, obligation, guardian
                )
                if terminal is not None:
                    break
            time.sleep(0.05)
        self.assertIsNotNone(guardian)
        self.assertIsNotNone(terminal)
        assert terminal is not None
        self.assertEqual(terminal["terminal_status"], "accepted")
        self.assertEqual(terminal["role_counts"].get("recover", 0), 0)
        self.assertEqual(terminal["role_counts"]["claim"], 1)
        self.assertEqual(terminal["role_counts"]["accept_status"], 1)
        assert guardian is not None
        self.assertEqual(len(list(guardian.glob("GENERATION.*.json"))), 1)
        self.assertTrue((guardian / "DISCHARGE.json").is_file())
        obligation = contract_v1.validate_guardian_obligation(
            contract, adapter._read_json(guardian / "OBLIGATION.json")
        )
        generation = contract_v1.validate_guardian_generation(
            contract,
            obligation,
            contract_v1.validate_guardian_manager_intent(
                contract,
                obligation,
                adapter._read_json(guardian / "MANAGER.INTENT.json"),
            ),
            adapter._read_json(guardian / "GENERATION.1.json"),
        )
        self.assertNotEqual(generation["manager_pid"], obligation["bootstrap_pid"])
        self.assertGreater(generation["manager_start_ticks"], 0)
        # Durable acceptance may become visible just before the independent
        # manager exits.  Wait only for this exact pid/start identity to be
        # absent or zombie so temp-root cleanup cannot race a final close;
        # never generalize kill(pid, 0) into a quiescence oracle.
        for _ in range(200):
            try:
                state, _, start_ticks = guardian_manager._read_process_identity(
                    int(generation["manager_pid"])
                )
            except guardian_manager.GuardianError:
                break
            if (
                start_ticks != int(generation["manager_start_ticks"])
                or state == "Z"
            ):
                break
            time.sleep(0.01)
        else:
            self.fail("guardian_manager_not_quiescent_after_terminal")
        unit = adapter._read_json(
            root / "var/lib/myuna-activation-engine-v1/unit-state.json"
        )
        self.assertTrue(unit["service_active"])
        self.assertTrue(unit["socket_active"])

    def test_manager_sigkill_while_bootstrap_lives_reenters_once_and_converges(
        self,
    ) -> None:
        scenario = installed_shadow.InstalledShadowScenario(
            fault_role="stop_socket",
            fault_kind="guardian_manager_sigkill_after_mutation",
        )
        _, contract, world, root = self._world(scenario)
        completed, terminal = _run_source_owned_bootstrap(contract, world)
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(terminal["terminal_status"], "converged_hard_stop")
        self.assertEqual(terminal["role_counts"]["claim"], 1)
        self.assertEqual(terminal["role_counts"]["recover"], 1)
        strategy = adapter._strategy_root(contract, world["plan"]["execution"])
        guardian = strategy / "guardians" / terminal["sequence_identity"]
        self.assertEqual(len(list(guardian.glob("GENERATION.*.json"))), 2)
        generations = [
            adapter._read_json(guardian / f"GENERATION.{index}.json")
            for index in (1, 2)
        ]
        self.assertNotEqual(generations[0]["manager_pid"], generations[1]["manager_pid"])
        self.assertTrue(
            all(int(value["manager_start_ticks"]) > 0 for value in generations)
        )
        unit = adapter._read_json(
            root / "var/lib/myuna-activation-engine-v1/unit-state.json"
        )
        self.assertTrue(unit["service_active"])
        self.assertTrue(unit["socket_active"])

    def test_supervisor_child_cannot_replay_bootstrap_intent_without_parent_pipe(
        self,
    ) -> None:
        _, contract, world, _ = self._world()
        completed, terminal = _run_source_owned_bootstrap(contract, world)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(terminal["terminal_status"], "accepted")
        strategy = adapter._strategy_root(contract, world["plan"]["execution"])
        entries = list((strategy / "entries").iterdir())
        self.assertEqual(len(entries), 1)
        intent = adapter._read_json(entries[0] / "INTENT.json")
        sequences_before = sorted(
            path.name for path in (strategy / "sequences").iterdir()
        )
        replay = subprocess.run(
            list(intent["argv"]),
            cwd=str(intent["cwd"]),
            env=dict(intent["environment"]),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        self.assertEqual(replay.returncode, 2)
        self.assertEqual(replay.stderr, b"")
        projected = contract_v1.validate_supervisor_bootstrap_output(
            json.loads(replay.stdout)
        )
        self.assertEqual(projected["schema"], contract_v1.SUPERVISOR_ENTRY_SCHEMA)
        self.assertEqual(projected["stage"], "source_owned_entry")
        self.assertEqual(
            sorted(path.name for path in (strategy / "sequences").iterdir()),
            sequences_before,
        )

    def test_source_owned_plan_rejects_writable_namespace_parent(self) -> None:
        _, contract, world, root = self._world()
        strategy = adapter._strategy_root(contract, world["plan"]["execution"])
        strategy.parent.chmod(0o770)
        completed, terminal = _run_source_owned_bootstrap(contract, world)
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(terminal["schema"], contract_v1.SUPERVISOR_ENTRY_SCHEMA)
        self.assertEqual(terminal["stage"], "source_owned_entry")
        self.assertFalse((strategy / "entries").exists())

    def test_source_owned_bootstrap_substitution_matrix_fails_before_plan(self) -> None:
        for mutation in (
            "wrong_root",
            "wrong_module_hash",
            "wrong_environment",
            "wrong_cwd",
            "wrong_argv",
            "wrong_interpreter",
            "bytecode",
            "sitecustomize",
            "mutable_worktree_import",
        ):
            with self.subTest(mutation=mutation):
                _, contract, world, root = self._world()
                target = Path(str(world["plan"]["execution"]["target_source_path"]))
                command = _source_owned_bootstrap_command(contract, world)
                environment = _source_owned_bootstrap_environment(world)
                cwd = target
                if mutation == "wrong_root":
                    index = command.index("--activation-target-source") + 1
                    command[index] = str(root / "absent-target")
                elif mutation == "wrong_module_hash":
                    module = target / "scripts/p08_activation_supervisor_v1.py"
                    module.write_bytes(module.read_bytes() + b"\n# substitution\n")
                elif mutation == "wrong_environment":
                    environment = dict(environment)
                    environment["UNEXPECTED"] = "1"
                elif mutation == "wrong_cwd":
                    cwd = root
                elif mutation == "wrong_argv":
                    command.append("--unexpected")
                elif mutation == "wrong_interpreter":
                    substitute = target.parent / "substituted-python"
                    os.link(Path(sys.executable).resolve(), substitute)
                    command[0] = str(substitute)
                elif mutation == "bytecode":
                    cache = target / "scripts/__pycache__"
                    cache.mkdir()
                    (cache / "p08_activation_supervisor_v1.cpython-312.pyc").write_bytes(
                        b"unchecked-bytecode"
                    )
                elif mutation == "sitecustomize":
                    (target / "scripts/sitecustomize.py").write_bytes(b"raise SystemExit\n")
                else:
                    environment = dict(environment)
                    environment["PYTHONPATH"] = os.pathsep.join(
                        (str(ROOT / "scripts"), str(target / "src"))
                    )
                completed, terminal = _run_source_owned_bootstrap(
                    contract,
                    world,
                    cwd=cwd,
                    environment=environment,
                    command=command,
                )
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stderr, b"")
                self.assertEqual(
                    terminal,
                    {
                        "schema": contract_v1.SUPERVISOR_ENTRY_SCHEMA,
                        "status": "indeterminate",
                        "stage": "source_owned_entry",
                        "product_state": "unknown",
                        "raw_output_included": False,
                        "retry_authorized": False,
                    },
                )
                strategy = adapter._strategy_root(
                    contract, world["plan"]["execution"]
                )
                entries = strategy / "entries"
                if entries.exists():
                    self.assertEqual(len(list(entries.iterdir())), 0)

    def test_crash_after_role_intent_consumes_call_and_converges(self) -> None:
        _, contract, world, root = self._world()
        _direct_sequence_claim(contract, world)
        with self.assertRaises(supervisor.SupervisorInterrupted):
            supervisor.run_sequence(
                contract,
                world["plan"],
                contract_path=world["contract_path"],
                plan_path=world["plan_path"],
                deploy_root=Path(str(world["plan"]["execution"]["target_source_path"])),
                interrupt_after_intent_role="stop_socket",
            )
        terminal = supervisor.recover_sequence(
            contract,
            world["plan"],
            contract_path=world["contract_path"],
            plan_path=world["plan_path"],
            deploy_root=Path(str(world["plan"]["execution"]["target_source_path"])),
        )
        self.assertEqual(terminal["terminal_status"], "converged_hard_stop")
        self.assertEqual(terminal["role_counts"]["stop_socket"], 1)
        self.assertEqual(terminal["role_counts"]["converge"], 1)
        self.assertEqual(terminal["role_counts"]["recover"], 1)
        unit = json.loads(
            (root / "var/lib/myuna-activation-engine-v1/unit-state.json").read_bytes()
        )
        self.assertTrue(unit["service_active"])
        self.assertTrue(unit["socket_active"])

    def test_supervisor_exception_before_mutation_hard_stops_without_convergence(self) -> None:
        _, contract, world, _ = self._world()
        original = supervisor._run_one_role
        raised = False

        def fail_after_drift(*args: object, **kwargs: object) -> tuple[int, int]:
            nonlocal raised
            result = original(*args, **kwargs)
            if kwargs["role"] == "drift" and not raised:
                raised = True
                raise supervisor.SupervisorError("synthetic_supervisor_failure")
            return result

        with patch.object(supervisor, "_run_one_role", side_effect=fail_after_drift):
            terminal = supervisor.execute_or_recover(
                contract,
                world["plan"],
                contract_path=world["contract_path"],
                plan_path=world["plan_path"],
                deploy_root=Path(str(world["plan"]["execution"]["target_source_path"])),
            )
        self.assertEqual(terminal["terminal_status"], "premutation_hard_stop")
        self.assertFalse(terminal["action_claimed"])
        self.assertFalse(terminal["product_mutated"])
        self.assertEqual(terminal["role_counts"]["drift"], 1)
        self.assertNotIn("converge", terminal["role_counts"])
        self.assertNotIn("recover", terminal["role_counts"])

    def test_public_drift_before_select_is_not_blindly_overwritten(self) -> None:
        _, contract, world, root = self._world()
        _direct_sequence_claim(contract, world)
        original = supervisor._run_one_role
        selector = adapter._rooted(
            root,
            str(contract["production_adapter"]["fixed_paths"]["selector"]),
        )
        drifted = False

        def drift_after_install(*args: object, **kwargs: object) -> tuple[int, int]:
            nonlocal drifted
            result = original(*args, **kwargs)
            if kwargs["role"] == "install" and not drifted:
                drifted = True
                selector.write_bytes(selector.read_bytes() + b" ")
            return result

        with patch.object(supervisor, "_run_one_role", side_effect=drift_after_install):
            terminal = supervisor.execute_or_recover(
                contract,
                world["plan"],
                contract_path=world["contract_path"],
                plan_path=world["plan_path"],
                deploy_root=Path(str(world["plan"]["execution"]["target_source_path"])),
            )
        self.assertEqual(terminal["terminal_status"], "converged_hard_stop")
        self.assertEqual(terminal["role_counts"]["select"], 1)
        self.assertEqual(terminal["role_counts"]["converge"], 1)
        self.assertEqual(terminal["role_counts"]["recover"], 1)
        self.assertEqual(
            json.loads(selector.read_bytes())["release_digest"],
            "b" * 64,
        )

    def test_supervisor_exception_after_first_unit_mutation_converges_once(self) -> None:
        _, contract, world, root = self._world()
        _direct_sequence_claim(contract, world)
        original = supervisor._run_one_role
        raised = False

        def fail_after_stop_socket(*args: object, **kwargs: object) -> tuple[int, int]:
            nonlocal raised
            result = original(*args, **kwargs)
            if kwargs["role"] == "stop_socket" and not raised:
                raised = True
                raise supervisor.SupervisorError("synthetic_supervisor_failure")
            return result

        with patch.object(supervisor, "_run_one_role", side_effect=fail_after_stop_socket):
            terminal = supervisor.execute_or_recover(
                contract,
                world["plan"],
                contract_path=world["contract_path"],
                plan_path=world["plan_path"],
                deploy_root=Path(str(world["plan"]["execution"]["target_source_path"])),
            )
        self.assertEqual(terminal["terminal_status"], "converged_hard_stop")
        self.assertEqual(terminal["role_counts"]["stop_socket"], 1)
        self.assertEqual(terminal["role_counts"]["converge"], 1)
        self.assertEqual(terminal["role_counts"]["recover"], 1)
        unit = json.loads(
            (root / "var/lib/myuna-activation-engine-v1/unit-state.json").read_bytes()
        )
        self.assertTrue(unit["service_active"])
        self.assertTrue(unit["socket_active"])
        selector_path = adapter._rooted(
            root,
            str(contract["production_adapter"]["fixed_paths"]["selector"]),
        )
        self.assertEqual(
            json.loads(selector_path.read_bytes())["release_digest"],
            "b" * 64,
        )
        stop_capture = adapter._read_json(
            adapter.sequence_root(contract, world["plan"]) / "stop_socket-1.json"
        )
        self.assertTrue(
            stop_capture["canonical_result"]["payload"]["service_cascade_stopped"]
        )

    def test_dependency_coupled_start_receipts_are_source_bound(self) -> None:
        _, contract, world, _ = self._world()
        _direct_sequence_claim(contract, world)
        terminal = supervisor.execute_or_recover(
            contract,
            world["plan"],
            contract_path=world["contract_path"],
            plan_path=world["plan_path"],
            deploy_root=Path(str(world["plan"]["execution"]["target_source_path"])),
        )
        self.assertEqual(terminal["terminal_status"], "accepted")
        sequence = adapter.sequence_root(contract, world["plan"])
        expected = {
            "stop_socket": {"service_cascade_stopped": True, "socket_stopped": True},
            "stop_service": {"dependency_state_exact": True, "service_stopped": True},
            "start_service": {"service_started": True, "socket_dependency_started": True},
            "start_socket": {"dependency_state_exact": True, "socket_started": True},
        }
        for role, payload in expected.items():
            with self.subTest(role=role):
                capture = adapter._read_json(sequence / f"{role}-1.json")
                self.assertEqual(capture["canonical_result"]["payload"], payload)

    def test_crash_after_ambiguous_transition_reconciles_before_convergence(self) -> None:
        scenario = installed_shadow.InstalledShadowScenario(
            continuity="transition_required",
            transition="ambiguous",
            reconcile="committed",
        )
        _, contract, world, root = self._world(scenario)
        _direct_sequence_claim(contract, world)
        with self.assertRaises(supervisor.SupervisorInterrupted):
            supervisor.run_sequence(
                contract,
                world["plan"],
                contract_path=world["contract_path"],
                plan_path=world["plan_path"],
                deploy_root=Path(str(world["plan"]["execution"]["target_source_path"])),
                interrupt_after_role="continuity_transition",
            )
        terminal = supervisor.recover_sequence(
            contract,
            world["plan"],
            contract_path=world["contract_path"],
            plan_path=world["plan_path"],
            deploy_root=Path(str(world["plan"]["execution"]["target_source_path"])),
        )
        self.assertEqual(terminal["terminal_status"], "converged_hard_stop")
        self.assertEqual(terminal["transition_state"], "reconciled_committed")
        self.assertEqual(terminal["role_counts"]["continuity_reconcile"], 1)
        self.assertEqual(terminal["state_restore_scope"], "code_public_only")
        history = root / "var/lib/myuna-active-temporal-context-v1/synthetic-forward-history"
        self.assertEqual(history.read_bytes(), b"committed\n")

    def test_recovery_reconcile_failure_converges_code_public_without_replay(self) -> None:
        scenario = installed_shadow.InstalledShadowScenario(
            continuity="transition_required",
            transition="ambiguous",
            reconcile="failed",
        )
        _, contract, world, root = self._world(scenario)
        _direct_sequence_claim(contract, world)
        with self.assertRaises(supervisor.SupervisorInterrupted):
            supervisor.run_sequence(
                contract,
                world["plan"],
                contract_path=world["contract_path"],
                plan_path=world["plan_path"],
                deploy_root=Path(str(world["plan"]["execution"]["target_source_path"])),
                interrupt_after_role="continuity_transition",
            )
        terminal = supervisor.recover_sequence(
            contract,
            world["plan"],
            contract_path=world["contract_path"],
            plan_path=world["plan_path"],
            deploy_root=Path(str(world["plan"]["execution"]["target_source_path"])),
        )
        self.assertEqual(terminal["terminal_status"], "converged_hard_stop")
        self.assertEqual(terminal["transition_state"], "transition_ambiguous")
        self.assertTrue(terminal["forward_state_possible"])
        self.assertEqual(terminal["state_restore_scope"], "code_public_only")
        self.assertEqual(terminal["role_counts"]["continuity_reconcile"], 1)
        self.assertEqual(terminal["role_counts"]["converge"], 1)
        self.assertNotIn("accept_status", terminal["role_counts"])
        selector_path = adapter._rooted(
            root,
            str(contract["production_adapter"]["fixed_paths"]["selector"]),
        )
        self.assertEqual(
            json.loads(selector_path.read_bytes())["release_digest"],
            "b" * 64,
        )

    def test_systemd_unit_projection_and_fragment_readback_are_exact(self) -> None:
        _, contract, world, _ = self._world()
        execution = json.loads(json.dumps(world["plan"]["execution"]))
        execution["backend"] = "systemd"
        execution["execution_substrate"] = dict(contract["systemd_authority"])
        service, socket = _systemd_responses(contract)
        with patch.object(
            adapter, "_run_bound_systemctl", side_effect=[service, socket]
        ) as invoked, patch.object(
            adapter, "_dependency_injection_paths", return_value=[]
        ), patch.object(
            adapter,
            "_service_process_projection",
            return_value=_systemd_process_projection(contract),
        ):
            projected = adapter._unit_state_for_execution(contract, execution)
        self.assertTrue(projected["service_active"])
        self.assertTrue(projected["socket_active"])
        self.assertTrue(projected["socket_enabled"])
        self.assertEqual(projected["service_main_pid"], 4242)
        self.assertEqual(projected["service_restarts"], 0)
        self.assertEqual(projected["socket_n_accepted"], 7)
        self.assertEqual(projected["socket_n_connections"], 0)
        self.assertEqual(invoked.call_count, 2)
        socket_show_argv = invoked.call_args_list[1].args[1]
        self.assertNotIn("--property=Service", socket_show_argv)
        self.assertIn("--property=Triggers", socket_show_argv)
        self.assertIn("--property=TriggeredBy", socket_show_argv)
        self.assertEqual(
            projected["effective"]["socket"]["service"],
            contract["compatibility"]["predecessor"]["unit_runtime"]["socket"][
                "service"
            ],
        )

        plan = json.loads(json.dumps(world["plan"]))
        plan["execution"] = execution
        fixed = contract["production_adapter"]["fixed_paths"]
        responses = [
            subprocess.CompletedProcess([], 0, stdout=b"", stderr=b""),
            *_systemd_responses(contract),
        ]
        with patch.object(
            adapter, "_run_bound_systemctl", side_effect=responses
        ) as invoked, patch.object(
            adapter, "_dependency_injection_paths", return_value=[]
        ), patch.object(
            adapter,
            "_service_process_projection",
            return_value=_systemd_process_projection(contract),
        ):
            adapter._daemon_reload(contract, plan)
        self.assertEqual(invoked.call_count, 3)
        self.assertEqual(invoked.call_args_list[0].args[1], ["daemon-reload"])
        self.assertIn("--property=FragmentPath", invoked.call_args_list[1].args[1])
        self.assertIn("--property=DropInPaths", invoked.call_args_list[1].args[1])
        self.assertIn("--property=ExecStart", invoked.call_args_list[1].args[1])

    def test_systemd_unhealthy_projection_is_never_operational_readiness(self) -> None:
        _, contract, world, _ = self._world()
        execution = json.loads(json.dumps(world["plan"]["execution"]))
        execution["backend"] = "systemd"
        execution["execution_substrate"] = dict(contract["systemd_authority"])
        for mutation in ("inactive", "disabled", "restart", "pid"):
            with self.subTest(mutation=mutation):
                service_updates: dict[str, str] = {}
                socket_updates: dict[str, str] = {}
                if mutation == "inactive":
                    service_updates.update(ActiveState="inactive", SubState="dead")
                elif mutation == "disabled":
                    socket_updates["UnitFileState"] = "disabled"
                elif mutation == "restart":
                    service_updates["NRestarts"] = "1"
                else:
                    service_updates["MainPID"] = "0"
                service, socket = _systemd_responses(
                    contract,
                    service_updates=service_updates,
                    socket_updates=socket_updates,
                )
                with patch.object(
                    adapter, "_run_bound_systemctl", side_effect=[service, socket]
                ), patch.object(
                    adapter, "_dependency_injection_paths", return_value=[]
                ), patch.object(
                    adapter,
                    "_service_process_projection",
                    return_value=_systemd_process_projection(contract),
                ):
                    if mutation == "restart":
                        projected = adapter._unit_state_for_execution(
                            contract, execution
                        )
                        with self.assertRaises(contract_v1.ContractError):
                            contract_v1._unit_state(projected)
                    else:
                        with self.assertRaises(adapter.AdapterError):
                            adapter._unit_state_for_execution(contract, execution)

    def test_systemd_effective_closure_substitution_fails_closed(self) -> None:
        _, contract, world, _ = self._world()
        execution = json.loads(json.dumps(world["plan"]["execution"]))
        execution["backend"] = "systemd"
        execution["execution_substrate"] = dict(contract["systemd_authority"])
        runtime = contract["compatibility"]["predecessor"]["unit_runtime"]
        service_dependencies = runtime["service"]["dependencies"]
        socket_dependencies = runtime["socket"]["dependencies"]
        cases = {
            "service_dropin": ({"DropInPaths": "/etc/systemd/system/x.conf"}, {}),
            "socket_dropin": ({}, {"DropInPaths": "/etc/systemd/system/y.conf"}),
            "stale_fragment": ({"FragmentPath": "/tmp/stale.service"}, {}),
            "wrong_load_state": ({"LoadState": "masked"}, {}),
            "wrong_user": ({"User": "root"}, {}),
            "wrong_group": ({"Group": "root"}, {}),
            "wrong_exec": (
                {
                    "ExecStart": "{ path=/bin/false ; argv[]=/bin/false ; "
                    "ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; "
                    "pid=4242 ; code=(null) ; status=0/0 }"
                },
                {},
            ),
            "wrong_environment": ({"EnvironmentFiles": "/tmp/other (ignore_errors=no)"}, {}),
            "environment_injection": ({"Environment": "PYTHONDONTWRITEBYTECODE=0"}, {}),
            "restart_policy": ({"Restart": "always"}, {}),
            "umask_policy": ({"UMask": "0022"}, {}),
            "protection_policy": ({"ProtectSystem": "no"}, {}),
            "external_requires": (
                {
                    "Requires": " ".join(
                        [*service_dependencies["Requires"], "example-out-of-scope.service"]
                    )
                },
                {},
            ),
            "external_wants": ({"Wants": "example-out-of-scope.service"}, {}),
            "install_runtime_conflation": ({"WantedBy": "multi-user.target"}, {}),
            "wrong_root_mount_unit": (
                {
                    "After": " ".join(
                        [
                            "-root.mount" if value == "-.mount" else value
                            for value in service_dependencies["After"]
                        ]
                    )
                },
                {},
            ),
            "external_after": (
                {
                    "After": " ".join(
                        [*service_dependencies["After"], "example-out-of-scope.service"]
                    )
                },
                {},
            ),
            "socket_external_requires": (
                {},
                {
                    "Requires": " ".join(
                        [*socket_dependencies["Requires"], "example-out-of-scope.service"]
                    )
                },
            ),
            "socket_external_wants": ({}, {"Wants": "example-out-of-scope.service"}),
            "socket_external_after": (
                {},
                {
                    "After": " ".join(
                        [*socket_dependencies["After"], "example-out-of-scope.service"]
                    )
                },
            ),
            "extra_supplementary_group": ({"SupplementaryGroups": "myuna-observer"}, {}),
            "dynamic_user": ({"DynamicUser": "yes"}, {}),
            "private_users": ({"PrivateUsers": "yes"}, {}),
            "login_environment": ({"SetLoginEnvironment": "yes"}, {}),
            "wrong_service_cgroup": ({"ControlGroup": "/system.slice/other.service"}, {}),
            "wrong_socket_cgroup": ({}, {"ControlGroup": "/system.slice/other.socket"}),
            "wrong_listen": ({}, {"Listen": "/run/other.sock (Stream)"}),
            "wrong_socket_user": ({}, {"SocketUser": "root"}),
            "wrong_socket_group": ({}, {"SocketGroup": "root"}),
            "wrong_socket_mode": ({}, {"SocketMode": "0600"}),
            "invented_socket_service_property": (
                {},
                {"Service": runtime["socket"]["service"]},
            ),
            "missing_socket_trigger": ({}, {"Triggers": ""}),
            "wrong_socket_trigger": ({}, {"Triggers": "other.service"}),
            "multiple_socket_triggers": (
                {},
                {
                    "Triggers": " ".join(
                        [
                            *socket_dependencies["Triggers"],
                            "other.service",
                        ]
                    )
                },
            ),
            "missing_service_triggered_by": ({"TriggeredBy": ""}, {}),
            "wrong_service_triggered_by": (
                {"TriggeredBy": "other.socket"},
                {},
            ),
            "multiple_service_triggered_by": (
                {
                    "TriggeredBy": " ".join(
                        [
                            *service_dependencies["TriggeredBy"],
                            "other.socket",
                        ]
                    )
                },
                {},
            ),
            "service_enabled": ({"UnitFileState": "enabled"}, {}),
        }
        for name, (service_updates, socket_updates) in cases.items():
            with self.subTest(name=name):
                service, socket = _systemd_responses(
                    contract,
                    service_updates=service_updates,
                    socket_updates=socket_updates,
                )
                with patch.object(
                    adapter, "_run_bound_systemctl", side_effect=[service, socket]
                ), patch.object(
                    adapter, "_dependency_injection_paths", return_value=[]
                ), patch.object(
                    adapter,
                    "_service_process_projection",
                    return_value=_systemd_process_projection(contract),
                ), self.assertRaises(adapter.AdapterError):
                    adapter._unit_state_for_execution(contract, execution)

    def test_fixed_account_projection_binds_pwd_group_and_supplementary_closure(self) -> None:
        contract = _contract()
        accounts = {
            "myuna_active_temporal": SimpleNamespace(
                pw_name="myuna_active_temporal", pw_uid=976, pw_gid=976
            ),
            "myuna-gateway-telegram": SimpleNamespace(
                pw_name="myuna-gateway-telegram", pw_uid=988, pw_gid=982
            ),
        }
        groups = [
            SimpleNamespace(gr_name="myuna_active_temporal", gr_gid=976, gr_mem=[]),
            SimpleNamespace(
                gr_name="myuna-gateway-telegram", gr_gid=982, gr_mem=[]
            ),
        ]
        with patch.object(
            adapter.pwd,
            "getpwnam",
            side_effect=lambda name: accounts[name],
        ), patch.object(
            adapter.grp,
            "getgrgid",
            side_effect=lambda gid: next(group for group in groups if group.gr_gid == gid),
        ), patch.object(
            adapter.os,
            "getgrouplist",
            side_effect=lambda name, primary: [primary],
        ):
            projection = adapter._system_account_projection(contract)
        self.assertEqual(projection["service"]["uid"], 976)
        self.assertEqual(projection["gateway"]["uid"], 988)
        self.assertEqual(
            projection["gateway"]["groups"],
            [{"gid": 982, "name": "myuna-gateway-telegram"}],
        )
        groups.append(
            SimpleNamespace(
                gr_name="myuna-observer",
                gr_gid=991,
                gr_mem=["myuna-gateway-telegram"],
            )
        )
        with patch.object(
            adapter.pwd,
            "getpwnam",
            side_effect=lambda name: accounts[name],
        ), patch.object(
            adapter.grp,
            "getgrgid",
            side_effect=lambda gid: next(group for group in groups if group.gr_gid == gid),
        ), patch.object(
            adapter.os,
            "getgrouplist",
            side_effect=lambda name, primary: [primary, 991]
            if name == "myuna-gateway-telegram"
            else [primary],
        ), self.assertRaises(
            adapter.AdapterError
        ):
            adapter._system_account_projection(contract)

        remapped_groups = [
            SimpleNamespace(gr_name="myuna_active_temporal", gr_gid=976, gr_mem=[]),
            SimpleNamespace(gr_name="substituted-gateway", gr_gid=982, gr_mem=[]),
        ]
        with patch.object(
            adapter.pwd,
            "getpwnam",
            side_effect=lambda name: accounts[name],
        ), patch.object(
            adapter.grp,
            "getgrgid",
            side_effect=lambda gid: next(
                group for group in remapped_groups if group.gr_gid == gid
            ),
        ), patch.object(
            adapter.os,
            "getgrouplist",
            side_effect=lambda name, primary: [primary],
        ), self.assertRaises(adapter.AdapterError):
            adapter._system_account_projection(contract)

    def test_account_drift_after_stage_rejects_before_unit_or_convergence_mutation(self) -> None:
        _, contract, world, root = self._world()
        plan = world["plan"]
        adapter._claim(contract, plan)
        adapter._backup(contract, plan)
        adapter._stage(contract, plan)
        account_path = root / "var/lib/myuna-activation-engine-v1/account-state.json"
        accounts = json.loads(account_path.read_bytes())
        accounts["gateway"]["groups"].append(
            {"gid": 991, "name": "nss-nonenumerable-extra"}
        )
        account_path.write_bytes(contract_v1.canonical_bytes(accounts))
        unit_path = root / "var/lib/myuna-activation-engine-v1/unit-state.json"
        before_units = unit_path.read_bytes()
        socket_path = root / "run/myuna-active-temporal-context-v1/temporal.sock"
        before_socket = socket_path.lstat()
        with self.assertRaisesRegex(
            adapter.AdapterError, "account_projection"
        ) as stopped:
            adapter._unit_action(
                contract, plan, unit_role="socket", start=False
            )
        self.assertFalse(stopped.exception.product_mutated)
        self.assertEqual(unit_path.read_bytes(), before_units)
        self.assertEqual(socket_path.lstat().st_ino, before_socket.st_ino)
        with self.assertRaisesRegex(
            adapter.AdapterError, "account_projection"
        ) as converged:
            adapter._converge(contract, plan)
        self.assertFalse(converged.exception.product_mutated)
        self.assertEqual(unit_path.read_bytes(), before_units)
        self.assertEqual(socket_path.lstat().st_ino, before_socket.st_ino)

    def test_post_start_account_drift_is_mutated_and_converges_once(self) -> None:
        _, contract, world, root = self._world()
        plan = world["plan"]
        _direct_sequence_claim(contract, world)
        adapter._claim(contract, plan)
        adapter._backup(contract, plan)
        adapter._stage(contract, plan)
        adapter._recovery_install(contract, plan)
        adapter._recovery_arm(contract, plan)
        adapter._unit_action(contract, plan, unit_role="socket", start=False)
        adapter._unit_action(contract, plan, unit_role="service", start=False)
        adapter._install(contract, plan)
        adapter._select(contract, plan)
        with patch.object(
            adapter,
            "_verify_account_authority",
            side_effect=[
                plan["execution"]["account_projection"],
                adapter.AdapterError("account_projection_drifted"),
            ],
        ), self.assertRaisesRegex(
            adapter.AdapterError, "account_projection"
        ) as started:
            adapter._unit_action(
                contract, plan, unit_role="service", start=True
            )
        self.assertTrue(started.exception.product_mutated)
        self.assertFalse(adapter._converge(contract, plan))
        units = adapter._unit_state(contract, plan)
        self.assertTrue(units["service_active"])
        self.assertTrue(units["socket_active"])
        selector = json.loads(
            (root / "etc/myuna-active-temporal-context-v1/selector.json").read_bytes()
        )
        self.assertEqual(selector["release_digest"], "b" * 64)

    def test_systemd_account_drift_is_checked_before_and_after_unit_action(self) -> None:
        _, contract, world, _ = self._world()
        plan = json.loads(json.dumps(world["plan"]))
        plan["execution"]["backend"] = "systemd"
        plan["execution"]["execution_substrate"] = dict(
            contract["systemd_authority"]
        )
        completed = subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")
        with patch.object(
            adapter,
            "_verify_account_authority",
            side_effect=adapter.AdapterError("account_projection_drifted"),
        ), patch.object(
            adapter, "_run_bound_systemctl", return_value=completed
        ) as invoked, self.assertRaisesRegex(
            adapter.AdapterError, "account_projection"
        ) as before:
            adapter._unit_action(
                contract, plan, unit_role="socket", start=False
            )
        self.assertFalse(before.exception.product_mutated)
        invoked.assert_not_called()
        with patch.object(
            adapter,
            "_verify_account_authority",
            side_effect=[
                plan["execution"]["account_projection"],
                adapter.AdapterError("account_projection_drifted"),
            ],
        ), patch.object(
            adapter, "_run_bound_systemctl", return_value=completed
        ) as invoked, self.assertRaisesRegex(
            adapter.AdapterError, "account_projection"
        ) as after:
            adapter._unit_action(
                contract, plan, unit_role="socket", start=False
            )
        self.assertTrue(after.exception.product_mutated)
        self.assertEqual(invoked.call_count, 1)

    def test_socket_inode_type_mode_owner_and_link_identity_fail_closed(self) -> None:
        for mutation in ("mode", "uid", "gid", "type", "symlink"):
            with self.subTest(mutation=mutation):
                _, contract, world, root = self._world()
                endpoint = root / "run/myuna-active-temporal-context-v1/temporal.sock"
                if mutation == "mode":
                    endpoint.chmod(0o600)
                elif mutation == "uid":
                    os.chown(endpoint, os.getuid() + 1, endpoint.stat().st_gid)
                elif mutation == "gid":
                    os.chown(endpoint, endpoint.stat().st_uid, os.getgid() + 1)
                elif mutation == "type":
                    endpoint.unlink()
                    endpoint.write_bytes(b"not-a-socket")
                else:
                    endpoint.unlink()
                    endpoint.symlink_to("substituted.sock")
                with self.assertRaisesRegex(
                    adapter.AdapterError, "socket_inode"
                ):
                    adapter._unit_state(contract, world["plan"])

    def test_privileged_systemd_substrate_is_source_bound_and_race_closed(self) -> None:
        contract = _contract()
        execution = {"execution_substrate": dict(contract["systemd_authority"])}
        completed = subprocess.CompletedProcess(
            [], 0, stdout=b"systemd 255\n", stderr=b""
        )
        with patch.object(adapter.subprocess, "run", return_value=completed) as invoked:
            observed = adapter._run_bound_systemctl(
                execution,
                ["--version"],
                capture_stdout=True,
                timeout=5,
            )
        self.assertIs(observed, completed)
        self.assertTrue(str(invoked.call_args.args[0][0]).startswith("/proc/self/fd/"))
        self.assertEqual(invoked.call_args.args[0][1:], ["--version"])
        self.assertEqual(len(invoked.call_args.kwargs["pass_fds"]), 1)

        for role in (
            "systemctl",
            "systemd_run",
            "environment_scrubber",
            "manager",
            "credential_drop",
        ):
            with self.subTest(role=role):
                substituted = json.loads(
                    json.dumps(contract["systemd_authority"])
                )
                substituted[role]["sha256"] = "0" * 64
                with self.assertRaises(adapter.AdapterError):
                    adapter._verify_systemd_substrate(substituted)

        with patch.object(adapter.subprocess, "run", return_value=completed), patch.object(
            adapter,
            "_stat_identity",
            side_effect=[(1,), (1,), (1,), (2,)],
        ), self.assertRaises(adapter.AdapterError):
            adapter._run_bound_systemctl(
                execution,
                ["show", "synthetic.service"],
                capture_stdout=True,
                timeout=5,
            )

    def test_dependency_directory_injection_and_symlink_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            load = Path(directory)
            execution = {
                "execution_substrate": {
                    "unit_load_paths": [str(load)],
                    "dependency_directory_suffixes": ["d", "requires", "upholds", "wants"],
                }
            }
            unit = "myuna-active-temporal-context-v1.service"
            self.assertEqual(adapter._dependency_injection_paths(execution, unit), [])
            injected = load / f"{unit}.requires"
            injected.mkdir()
            self.assertEqual(
                adapter._dependency_injection_paths(execution, unit),
                [str(injected)],
            )
            injected.rmdir()
            injected.symlink_to(load, target_is_directory=True)
            with self.assertRaises(adapter.AdapterError):
                adapter._dependency_injection_paths(execution, unit)

    def test_effective_dependency_directory_is_never_ignored(self) -> None:
        _, contract, world, _ = self._world()
        execution = json.loads(json.dumps(world["plan"]["execution"]))
        execution["backend"] = "systemd"
        execution["execution_substrate"] = dict(contract["systemd_authority"])
        service, socket = _systemd_responses(contract)
        with patch.object(
            adapter, "_run_bound_systemctl", side_effect=[service, socket]
        ), patch.object(
            adapter,
            "_dependency_injection_paths",
            side_effect=[["/etc/systemd/system/example.requires"], []],
        ), patch.object(
            adapter,
            "_service_process_projection",
            return_value=_systemd_process_projection(contract),
        ), self.assertRaises(adapter.AdapterError):
            adapter._unit_state_for_execution(contract, execution)

    def test_service_main_process_identity_projection_is_exact(self) -> None:
        contract = _contract()
        expected = contract["compatibility"]["predecessor"]["unit_runtime"][
            "service"
        ]["process_identity"]
        pid = 4242
        stat_line = (
            "4242 (python3) "
            + " ".join(["S", *("0" for _ in range(18)), "123456"])
            + "\n"
        ).encode("ascii")
        argv = b"\0".join(item.encode("ascii") for item in expected["argv"]) + b"\0"
        status = (
            f"Uid:\t{expected['uid']} {expected['uid']} {expected['uid']} {expected['uid']}\n"
            f"Gid:\t{expected['gid']} {expected['gid']} {expected['gid']} {expected['gid']}\n"
            f"Groups:\t{' '.join(str(value) for value in expected['groups'])}\n"
        ).encode("ascii")
        cgroup = f"0::{expected['cgroup']}\n".encode("ascii")

        with patch.object(
            adapter,
            "_read_proc_bytes",
            side_effect=[stat_line, argv, status, cgroup, stat_line],
        ), patch.object(
            adapter.os, "readlink", return_value=expected["executable"]["resolved_path"]
        ), patch.object(adapter, "_verify_regular_authority"):
            projected = adapter._service_process_projection(pid, expected)
        self.assertEqual(projected["pid"], pid)
        self.assertEqual(projected["start_ticks"], 123456)

        cases = {
            "wrong_argv": [stat_line, argv + b"extra\0", status, cgroup, stat_line],
            "wrong_uid": [
                stat_line,
                argv,
                status.replace(str(expected["uid"]).encode("ascii"), b"0"),
                cgroup,
                stat_line,
            ],
            "extra_group": [
                stat_line,
                argv,
                status.replace(
                    f"Groups:\t{' '.join(str(value) for value in expected['groups'])}\n".encode(
                        "ascii"
                    ),
                    f"Groups:\t{' '.join(str(value) for value in expected['groups'])} 991\n".encode(
                        "ascii"
                    ),
                ),
                cgroup,
                stat_line,
            ],
            "wrong_cgroup": [stat_line, argv, status, b"0::/system.slice/other.service\n", stat_line],
            "stale_generation": [stat_line, argv, status, cgroup, stat_line.replace(b"123456", b"123457")],
        }
        for name, values in cases.items():
            with self.subTest(name=name), patch.object(
                adapter, "_read_proc_bytes", side_effect=values
            ), patch.object(
                adapter.os,
                "readlink",
                return_value=expected["executable"]["resolved_path"],
            ), patch.object(adapter, "_verify_regular_authority"), self.assertRaises(
                adapter.AdapterError
            ):
                adapter._service_process_projection(pid, expected)
        with patch.object(
            adapter,
            "_read_proc_bytes",
            side_effect=[stat_line, argv, status, cgroup, stat_line],
        ), patch.object(
            adapter.os, "readlink", return_value="/usr/bin/substituted-python"
        ), patch.object(adapter, "_verify_regular_authority"), self.assertRaises(
            adapter.AdapterError
        ):
            adapter._service_process_projection(pid, expected)

    def test_target_process_projection_requires_numeric_empty_groups(self) -> None:
        contract = _contract()
        expected = contract["production_adapter"]["unit_runtime"]["service"][
            "process_identity"
        ]
        self.assertEqual(expected["uid"], 976)
        self.assertEqual(expected["gid"], 976)
        self.assertEqual(expected["groups"], [])
        self.assertEqual(expected["argv"][:4], [
            "/usr/bin/python3", "-B", "-P", "-S"
        ])
        stat_line = (
            "4242 (python3) "
            + " ".join(["S", *("0" for _ in range(18)), "123456"])
            + "\n"
        ).encode("ascii")
        argv = b"\0".join(item.encode("ascii") for item in expected["argv"]) + b"\0"
        status = (
            "Uid:\t976 976 976 976\n"
            "Gid:\t976 976 976 976\n"
            "Groups:\t\n"
        ).encode("ascii")
        cgroup = f"0::{expected['cgroup']}\n".encode("ascii")
        with patch.object(
            adapter,
            "_read_proc_bytes",
            side_effect=[stat_line, argv, status, cgroup, stat_line],
        ), patch.object(
            adapter.os, "readlink", return_value=expected["executable"]["resolved_path"]
        ), patch.object(adapter, "_verify_regular_authority"):
            projection = adapter._service_process_projection(4242, expected)
        self.assertEqual(projection["groups"], [])

        expanded = status.replace(b"Groups:\t\n", b"Groups:\t991\n")
        with patch.object(
            adapter,
            "_read_proc_bytes",
            side_effect=[stat_line, argv, expanded, cgroup, stat_line],
        ), patch.object(
            adapter.os, "readlink", return_value=expected["executable"]["resolved_path"]
        ), patch.object(adapter, "_verify_regular_authority"), self.assertRaises(
            adapter.AdapterError
        ):
            adapter._service_process_projection(4242, expected)

    @unittest.skipUnless(os.getuid() == 0, "numeric credential probe requires root")
    def test_numeric_credential_drop_precedes_any_target_module(self) -> None:
        contract = _contract()
        runtime = contract["production_adapter"]["unit_runtime"]["service"]
        launch = runtime["credential_launch"]
        self.assertIsNotNone(launch)
        self.assertEqual(runtime["user"], "")
        self.assertEqual(runtime["group"], "")
        self.assertEqual(runtime["supplementary_groups"], [])
        self.assertNotIn("myuna_active_temporal", runtime["exec_start_argv"])
        self.assertEqual(runtime["exec_start_argv"][:5], [
            contract["systemd_authority"]["credential_drop"]["path"],
            "--reuid=976",
            "--regid=976",
            "--clear-groups",
            "--no-new-privs",
        ])
        command = [
            contract["systemd_authority"]["credential_drop"]["path"],
            "--reuid=976",
            "--regid=976",
            "--clear-groups",
            "--no-new-privs",
            contract["interpreter"]["invocation_path"],
            "-B",
            "-P",
            "-S",
            "-m",
            "p08_activation_credential_probe_v1",
            "--expected-uid",
            "976",
            "--expected-gid",
            "976",
        ]
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env={
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": str(ROOT / "scripts"),
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        projection = json.loads(completed.stdout)
        self.assertEqual(completed.stdout, contract_v1.canonical_bytes(projection))
        self.assertEqual(projection["groups"], [])
        self.assertTrue(projection["no_new_privs"])
        self.assertFalse(projection["raw_output_included"])

    def test_account_missing_mismatch_and_drift_reject_before_claim(self) -> None:
        for mutation in (
            "missing_group",
            "wrong_user",
            "wrong_uid",
            "wrong_gid",
            "wrong_primary_group",
            "extra_group",
            "name_reuse",
        ):
            with self.subTest(mutation=mutation):
                _, contract, world, root = self._world()
                path = root / "var/lib/myuna-activation-engine-v1/account-state.json"
                value = json.loads(path.read_bytes())
                if mutation == "missing_group":
                    value["gateway"]["groups"] = []
                elif mutation == "wrong_user":
                    value["service"]["user"] = "substituted-service"
                elif mutation == "wrong_uid":
                    value["gateway"]["uid"] += 1
                elif mutation == "wrong_gid":
                    value["gateway"]["gid"] += 1
                elif mutation == "wrong_primary_group":
                    value["service"]["primary_group"] = "root"
                elif mutation == "extra_group":
                    value["gateway"]["groups"].append(
                        {"gid": 991, "name": "myuna-observer"}
                    )
                else:
                    value["service"]["uid"] = value["gateway"]["uid"]
                path.write_bytes(contract_v1.canonical_bytes(value))
                result = adapter.build_role_result(
                    contract, world["plan"], role="prepare", call_index=1
                )
                self.assertEqual(result["status"], "rejected")
                self.assertFalse(result["persistent_mutation"])
                self.assertFalse(adapter.incident_root(contract, world["plan"]).exists())

    def test_source_owned_subprocess_rejects_account_and_unit_prestate_defects(self) -> None:
        for mutation in (
            "account_uid",
            "selector_role_swap",
            "service_inactive",
            "service_enabled",
            "socket_disabled",
            "socket_listening_while_service_running",
            "socket_running_without_service",
            "restart",
            "pid",
        ):
            with self.subTest(mutation=mutation):
                _, contract, world, root = self._world()
                if mutation == "account_uid":
                    path = root / "var/lib/myuna-activation-engine-v1/account-state.json"
                    value = json.loads(path.read_bytes())
                    value["gateway"]["uid"] += 1
                elif mutation == "selector_role_swap":
                    path = root / "etc/myuna-active-temporal-context-v1/selector.json"
                    value = json.loads(path.read_bytes())
                    value["gateway_client_sha256"] = contract["compatibility"][
                        "predecessor"
                    ]["client_roles"]["roles"]["status_content_free_helper"][
                        "sha256"
                    ]
                else:
                    path = root / "var/lib/myuna-activation-engine-v1/unit-state.json"
                    value = json.loads(path.read_bytes())
                    if mutation == "service_inactive":
                        value["service_active"] = False
                    elif mutation == "service_enabled":
                        value["service_enabled"] = True
                    elif mutation == "socket_disabled":
                        value["socket_enabled"] = False
                    elif mutation == "socket_listening_while_service_running":
                        value["effective"]["socket"]["sub_state"] = "listening"
                    elif mutation == "socket_running_without_service":
                        value["service_active"] = False
                        value["service_main_pid"] = 0
                        value["service_process"] = None
                        value["effective"]["service"]["active_state"] = "inactive"
                        value["effective"]["service"]["sub_state"] = "dead"
                    elif mutation == "restart":
                        value["service_restarts"] = 1
                    else:
                        value["service_main_pid"] = 0
                path.write_bytes(contract_v1.canonical_bytes(value))
                result = installed_shadow.run_installed_shadow(
                    contract,
                    world["plan"],
                    contract_path=world["contract_path"],
                    plan_path=world["plan_path"],
                    deploy_root=ROOT,
                )
                self.assertEqual(result["terminal_status"], "premutation_hard_stop")
                self.assertEqual(result["role_counts"]["construct"], 1)
                self.assertFalse(result["action_claimed"])
                self.assertFalse(result["product_mutated"])

    def test_unhealthy_unit_projection_and_stale_generation_fail_closed(self) -> None:
        _, contract, world, _ = self._world()
        healthy = json.loads(json.dumps(world["plan"]["execution"]["unit_prestate"]))
        for field, value in (
            ("service_active", False),
            ("service_enabled", True),
            ("socket_active", False),
            ("socket_enabled", False),
            ("service_restarts", 9),
            ("service_main_pid", 0),
            ("socket_n_connections", 1),
        ):
            with self.subTest(field=field):
                candidate = dict(healthy)
                candidate[field] = value
                with self.assertRaises(contract_v1.ContractError):
                    contract_v1._unit_state(candidate)

        _direct_sequence_claim(contract, world)
        for role in ("claim", "backup", "stage", "recovery_install", "recovery_arm"):
            adapter._payload(contract, world["plan"], role)
        incident = adapter.incident_root(contract, world["plan"])
        with self.assertRaises(adapter.AdapterError) as rejected:
            adapter._unit_receipt(contract, world["plan"], label="predecessor", create=True)
        self.assertEqual(rejected.exception.code, "unit_generation_rejected")

        root = Path(str(world["plan"]["execution"]["root"]))
        unit_path = root / "var/lib/myuna-activation-engine-v1/unit-state.json"
        fresh = json.loads(unit_path.read_bytes())
        fresh["service_active_enter_monotonic_usec"] += 1
        fresh["socket_active_enter_monotonic_usec"] += 1
        fresh["service_main_pid"] += 1
        fresh["service_process"]["pid"] = fresh["service_main_pid"]
        fresh["service_process"]["start_ticks"] += 1
        unit_path.write_bytes(contract_v1.canonical_bytes(fresh))
        adapter._unit_receipt(contract, world["plan"], label="predecessor", create=True)
        receipt_path = incident / "UNITS.PREDECESSOR.json"
        receipt = json.loads(receipt_path.read_bytes())
        receipt["state"]["service_active_enter_monotonic_usec"] = 1
        body = {key: value for key, value in receipt.items() if key != "receipt_digest"}
        receipt["receipt_digest"] = contract_v1.digest_value(body)
        receipt_path.write_bytes(contract_v1.canonical_bytes(receipt))
        with self.assertRaises(adapter.AdapterError) as replayed:
            adapter._unit_receipt(contract, world["plan"], label="predecessor", create=False)
        self.assertEqual(replayed.exception.code, "unit_generation_rejected")

    def test_socket_ingress_projection_requires_exactly_one_completed_connection(self) -> None:
        _, _, world, _ = self._world()
        before = world["plan"]["execution"]["unit_prestate"]
        after = dict(before)
        after["socket_n_accepted"] += 1
        adapter._verify_completed_socket_ingress(before, after)
        for mutation in ("no_accept", "active_connection", "restart", "wrong_pid"):
            with self.subTest(mutation=mutation):
                invalid = dict(after)
                if mutation == "no_accept":
                    invalid["socket_n_accepted"] = before["socket_n_accepted"]
                elif mutation == "active_connection":
                    invalid["socket_n_connections"] = 1
                elif mutation == "restart":
                    invalid["service_restarts"] = 1
                else:
                    invalid["service_main_pid"] += 1
                with self.assertRaises(adapter.AdapterError):
                    adapter._verify_completed_socket_ingress(before, invalid)

    def test_committed_transition_is_accepted_and_history_is_forward(self) -> None:
        result, root = _run(
            self,
            installed_shadow.InstalledShadowScenario(
                continuity="transition_required",
                transition="committed",
            )
        )
        self.assertEqual(result["terminal_status"], "accepted")
        self.assertTrue(result["transition_committed"])
        self.assertEqual(result["state_restore_scope"], "code_public_only")
        history = root / "var/lib/myuna-active-temporal-context-v1/synthetic-forward-history"
        self.assertEqual(history.read_bytes(), b"committed\n")

    def test_ambiguous_transition_reconciles_both_outcomes(self) -> None:
        committed, _ = _run(
            self,
            installed_shadow.InstalledShadowScenario(
                continuity="transition_required",
                transition="ambiguous",
                reconcile="committed",
            )
        )
        self.assertEqual(committed["terminal_status"], "accepted")
        self.assertEqual(committed["transition_state"], "reconciled_committed")
        not_committed, _ = _run(
            self,
            installed_shadow.InstalledShadowScenario(
                continuity="transition_required",
                transition="ambiguous",
                reconcile="not_committed",
            )
        )
        self.assertEqual(not_committed["terminal_status"], "converged_hard_stop")
        self.assertEqual(not_committed["transition_state"], "reconciled_not_committed")
        self.assertEqual(not_committed["state_restore_scope"], "p08_state_and_public")

    def test_acceptance_failure_converges_once_and_preserves_forward_history(self) -> None:
        result, root = _run(
            self,
            installed_shadow.InstalledShadowScenario(
                continuity="transition_required",
                transition="committed",
                acceptance="reject",
            )
        )
        self.assertEqual(result["terminal_status"], "converged_hard_stop")
        self.assertEqual(result["role_counts"]["converge"], 1)
        self.assertEqual(result["role_counts"]["recover"], 1)
        self.assertEqual(result["state_restore_scope"], "code_public_only")
        history = root / "var/lib/myuna-active-temporal-context-v1/synthetic-forward-history"
        self.assertEqual(history.read_bytes(), b"committed\n")
        evidence = (
            root
            / "var/lib/myuna-activation-backups/p08-activation-engine-v1/incidents"
            / result["plan_digest"]
            / "ACCEPTANCE.REJECTION.json"
        )
        projection = json.loads(evidence.read_bytes())
        self.assertEqual(projection["status"], "rejected")
        self.assertEqual(projection["projection"]["stage"], "transport_connect")
        self.assertFalse(projection["raw_output_included"])
        units = json.loads(
            (root / "var/lib/myuna-activation-engine-v1/unit-state.json").read_bytes()
        )
        self.assertGreaterEqual(units["socket_n_accepted"], 1)
        self.assertGreater(units["service_active_enter_monotonic_usec"], 1)
        self.assertGreater(units["socket_active_enter_monotonic_usec"], 1)

    def test_convergence_failure_is_terminal_and_not_retried(self) -> None:
        result, _ = _run(
            self,
            installed_shadow.InstalledShadowScenario(
                acceptance="reject",
                fault_role="converge",
                fault_kind="rejected",
            )
        )
        self.assertEqual(result["terminal_status"], "convergence_failed_hard_stop")
        self.assertEqual(result["role_counts"]["converge"], 1)
        self.assertNotIn("recover", result["role_counts"])

    def test_each_owned_preselect_phase_fault_is_fail_closed(self) -> None:
        for role in (
            "backup",
            "stage",
            "recovery_install",
            "recovery_arm",
            "stop_socket",
            "stop_service",
            "install",
            "select",
        ):
            with self.subTest(role=role):
                result, _ = _run(
                    self,
                    installed_shadow.InstalledShadowScenario(
                        fault_role=role,
                        fault_kind="rejected",
                    )
                )
                self.assertIn(
                    result["terminal_status"],
                    {"premutation_hard_stop", "converged_hard_stop"},
                )
                self.assertEqual(result["role_counts"][role], 1)

    def test_every_recovery_install_prefix_fault_converges_infrastructure_once(
        self,
    ) -> None:
        prefixes = [
            "runtime_package",
            "recovery_unit",
            "recovery_enablement",
            "daemon_reload",
            "recovery_unit_start_no_arm",
            "closure_readback",
            "socket_recovery_dropin",
            "service_recovery_dropin",
            "arm",
            "product_gate_reload",
        ]
        install_prefixes = set(prefixes[:6])
        for prefix in prefixes:
            role = "recovery_install" if prefix in install_prefixes else "recovery_arm"
            for result_class in ("rejected", "indeterminate"):
                with self.subTest(prefix=prefix, result_class=result_class):
                    result, root = _run(
                        self,
                        installed_shadow.InstalledShadowScenario(
                            fault_role=role,
                            fault_kind=f"partial_{prefix}_{result_class}",
                        ),
                    )
                    self.assertEqual(result["terminal_status"], "converged_hard_stop")
                    self.assertEqual(result["role_counts"][role], 1)
                    self.assertEqual(result["role_counts"]["converge"], 1)
                    self.assertEqual(result["role_counts"]["recover"], 1)
                    self.assertEqual(result["role_counts"]["postflight"], 1)
                    self.assertNotIn("stop_socket", result["role_counts"])
                    self.assertFalse(result["product_mutated"])
                    self.assertFalse(result["infrastructure_mutated"])
                    self.assertEqual(result["mutation_scope"], "none")
                    self.assertEqual(
                        result["state_restore_scope"],
                        "recovery_infrastructure_only",
                    )
                    self.assertFalse(
                        (root / ("a" * 64)).exists(),
                        "target product must remain absent",
                    )
                    execution_root = root
                    self.assertFalse(
                        (
                            execution_root
                            / "usr/lib/myuna/p08-activation-engine-v1/recovery-runtime"
                        ).exists()
                    )
                    self.assertFalse(
                        (
                            execution_root
                            / "etc/systemd/system/myuna-p08-activation-recovery-v1.service"
                        ).exists()
                    )
                    self.assertFalse(
                        (
                            execution_root
                            / "etc/systemd/system/myuna-active-temporal-context-v1.service.d/90-p08-activation-recovery.conf"
                        ).exists()
                    )
                    self.assertFalse(
                        (
                            execution_root
                            / "etc/systemd/system/myuna-active-temporal-context-v1.socket.d/90-p08-activation-recovery.conf"
                        ).exists()
                    )

    def test_intraprefix_intent_stage_and_publish_boundaries_converge_once(
        self,
    ) -> None:
        cases = (
            ("runtime_package", "recovery_install", "post_intent", False),
            ("runtime_package", "recovery_install", "stage_open", True),
            ("runtime_package", "recovery_install", "stage_directory_open", True),
            ("runtime_package", "recovery_install", "stage_directory_chmod", True),
            ("runtime_package", "recovery_install", "stage_directory_chown", True),
            ("runtime_package", "recovery_install", "stage_file_open", True),
            ("runtime_package", "recovery_install", "stage_file_write", True),
            ("runtime_package", "recovery_install", "stage_file_chmod", True),
            ("runtime_package", "recovery_install", "stage_file_chown", True),
            ("runtime_package", "recovery_install", "stage_file_fsync", True),
            ("runtime_package", "recovery_install", "stage_file_pre_publish", True),
            ("runtime_package", "recovery_install", "stage_file_post_publish", True),
            ("runtime_package", "recovery_install", "stage_file_readback", True),
            ("runtime_package", "recovery_install", "stage_directory_fsync", True),
            ("runtime_package", "recovery_install", "stage_tree_readback", True),
            ("runtime_package", "recovery_install", "pre_publish", True),
            ("runtime_package", "recovery_install", "post_publish", True),
            ("recovery_unit", "recovery_install", "stage_write", True),
            ("recovery_enablement", "recovery_install", "stage_chown", True),
            ("closure_readback", "recovery_install", "post_publish", True),
            ("socket_recovery_dropin", "recovery_arm", "stage_write", True),
            ("service_recovery_dropin", "recovery_arm", "pre_publish", True),
            ("arm", "recovery_arm", "post_publish", True),
        )
        for prefix, role, boundary, durable_write in cases:
            with self.subTest(prefix=prefix, boundary=boundary):
                result, root = _run(
                    self,
                    installed_shadow.InstalledShadowScenario(
                        fault_role=role,
                        fault_kind=(
                            f"intraprefix_{prefix}_{boundary}_rejected"
                        ),
                    ),
                )
                self.assertEqual(result["terminal_status"], "converged_hard_stop")
                self.assertEqual(result["role_counts"][role], 1)
                self.assertEqual(result["role_counts"]["converge"], 1)
                self.assertEqual(result["role_counts"]["recover"], 1)
                self.assertFalse(result["product_mutated"])
                self.assertFalse(result["infrastructure_mutated"])
                self.assertEqual(
                    result["state_restore_scope"],
                    "recovery_infrastructure_only",
                )
                transaction = next(
                    root.glob(
                        "var/lib/myuna-activation-backups/"
                        "p08-activation-engine-v1/incidents/*/"
                        "RECOVERY.INFRASTRUCTURE"
                    )
                )
                self.assertTrue((transaction / "OBLIGATION.json").is_file())
                self.assertTrue(any((transaction / "intents").iterdir()))
                self.assertEqual(
                    list(root.rglob("*.p08-*.txn")),
                    [],
                    "owned hidden staging must be converged",
                )
                self.assertFalse((root / ("a" * 64)).exists())
                if durable_write:
                    self.assertIn(role, result["role_counts"])

    def test_intraprefix_manager_effect_and_event_boundaries_are_owned(self) -> None:
        for prefix, role, boundary in (
            ("daemon_reload", "recovery_install", "pre_effect"),
            ("daemon_reload", "recovery_install", "post_effect"),
            ("recovery_unit_start_no_arm", "recovery_install", "post_effect"),
            ("product_gate_reload", "recovery_arm", "post_effect"),
            ("runtime_package", "recovery_install", "pre_event"),
            ("runtime_package", "recovery_install", "post_event"),
        ):
            with self.subTest(prefix=prefix, boundary=boundary):
                result, root = _run(
                    self,
                    installed_shadow.InstalledShadowScenario(
                        fault_role=role,
                        fault_kind=f"intraprefix_{prefix}_{boundary}_indeterminate",
                    ),
                )
                self.assertEqual(result["terminal_status"], "converged_hard_stop")
                self.assertEqual(result["role_counts"]["converge"], 1)
                self.assertEqual(result["role_counts"]["recover"], 1)
                self.assertFalse(result["product_mutated"])
                self.assertEqual(list(root.rglob("*.p08-*.txn")), [])

    def test_intraprefix_typed_failure_reports_infrastructure_mutation(self) -> None:
        _, contract, world, _ = self._world()
        plan = world["plan"]
        _direct_sequence_claim(contract, world)
        adapter._claim(contract, plan)
        adapter._backup(contract, plan)
        adapter._stage(contract, plan)
        with patch.object(
            adapter,
            "_recovery_intraprefix_fault",
            side_effect=lambda _contract, _plan, _prefix, boundary: (
                (_ for _ in ()).throw(
                    adapter.AdapterError("typed_copy_failure")
                )
                if boundary == "stage_write"
                else None
            ),
        ):
            result = adapter.build_role_result(
                contract,
                plan,
                role="recovery_install",
                call_index=1,
            )
        self.assertEqual(result["status"], "rejected")
        self.assertTrue(
            result["persistent_mutation"],
            msg={
                "result": result,
                "obligation": adapter._recovery_obligation_path(
                    contract, plan
                ).exists(),
            },
        )
        self.assertEqual(result["mutation_scope"], "recovery_infrastructure")

    def test_intraprefix_substituted_staging_fails_closed_without_overcleanup(
        self,
    ) -> None:
        _, contract, world, root = self._world()
        plan = world["plan"]
        _direct_sequence_claim(contract, world)
        adapter._claim(contract, plan)
        adapter._backup(contract, plan)
        adapter._stage(contract, plan)
        adapter._ensure_recovery_obligation(contract, plan)
        intent = adapter._ensure_recovery_intent(contract, plan, "runtime_package")
        stage, _ = adapter._recovery_stage_paths(
            contract, plan, "runtime_package"
        )
        self.assertIsNotNone(stage)
        assert stage is not None
        stage.mkdir(parents=True)
        (stage / "substituted.bin").write_bytes(b"external")
        with self.assertRaises(adapter.AdapterError) as stopped:
            adapter._converge_recovery_infrastructure(contract, plan)
        self.assertTrue(stopped.exception.infrastructure_mutated)
        self.assertTrue(stage.is_dir())
        self.assertEqual((stage / "substituted.bin").read_bytes(), b"external")
        self.assertEqual(intent["mutation_scope"], "recovery_infrastructure")
        self.assertFalse((root / ("a" * 64)).exists())

    def test_intraprefix_same_bytes_wrong_metadata_is_not_overcleaned(self) -> None:
        for prefix in ("runtime_package", "recovery_unit"):
            with self.subTest(prefix=prefix):
                _, contract, world, root = self._world()
                plan = world["plan"]
                _direct_sequence_claim(contract, world)
                adapter._claim(contract, plan)
                adapter._backup(contract, plan)
                adapter._stage(contract, plan)
                adapter._ensure_recovery_obligation(contract, plan)
                intent = adapter._ensure_recovery_intent(contract, plan, prefix)
                stage, _ = adapter._recovery_stage_paths(contract, plan, prefix)
                self.assertIsNotNone(stage)
                assert stage is not None
                if prefix == "runtime_package":
                    adapter._ensure_parent_directory(
                        stage.parent, uid=os.getuid(), gid=os.getgid()
                    )
                    stage.mkdir(mode=0o700)
                    row = plan["execution"]["target_inventory"][0]
                    source = (
                        adapter.incident_root(contract, plan)
                        / "STAGE"
                        / str(plan["target_identity"])
                        / str(row["path"])
                    )
                    target = stage / str(row["path"])
                    target.parent.mkdir(parents=True, mode=0o700)
                    target.write_bytes(source.read_bytes())
                    os.chmod(target, 0o666)
                else:
                    artifact = next(
                        row
                        for row in adapter._recovery_contract(contract)["artifacts"]
                        if row["role"] == prefix
                    )
                    stage.parent.mkdir(parents=True, exist_ok=True)
                    stage.write_bytes(str(artifact["content"]).encode("ascii"))
                    os.chmod(stage, 0o666)
                with self.assertRaises(adapter.AdapterError) as stopped:
                    adapter._converge_recovery_infrastructure(contract, plan)
                self.assertTrue(stopped.exception.infrastructure_mutated)
                self.assertTrue(stage.exists())
                self.assertEqual(intent["mutation_scope"], "recovery_infrastructure")
                self.assertFalse((root / ("a" * 64)).exists())

    def test_existing_stage_or_destination_without_prior_intent_is_never_adopted(
        self,
    ) -> None:
        for kind in ("stage", "destination"):
            with self.subTest(kind=kind):
                _, contract, world, root = self._world()
                plan = world["plan"]
                _direct_sequence_claim(contract, world)
                adapter._claim(contract, plan)
                adapter._backup(contract, plan)
                adapter._stage(contract, plan)
                adapter._ensure_recovery_obligation(contract, plan)
                stage, _ = adapter._recovery_stage_paths(
                    contract, plan, "recovery_unit"
                )
                destination = adapter._recovery_prefix_destination(
                    contract, plan, "recovery_unit"
                )
                self.assertIsNotNone(stage)
                self.assertIsNotNone(destination)
                assert stage is not None and destination is not None
                selected = stage if kind == "stage" else destination
                adapter._ensure_parent_directory(
                    selected.parent, uid=os.getuid(), gid=os.getgid()
                )
                artifact = next(
                    row
                    for row in adapter._recovery_contract(contract)["artifacts"]
                    if row["role"] == "recovery_unit"
                )
                selected.write_bytes(str(artifact["content"]).encode("ascii"))
                os.chmod(selected, int(artifact["mode"]))
                with self.assertRaises(adapter.AdapterError) as stopped:
                    adapter._ensure_recovery_intent(
                        contract, plan, "recovery_unit"
                    )
                self.assertTrue(stopped.exception.infrastructure_mutated)
                self.assertTrue(selected.exists())
                self.assertFalse(
                    adapter._recovery_intent_path(
                        contract, plan, "recovery_unit"
                    ).exists()
                )
                self.assertFalse((root / ("a" * 64)).exists())

    def test_canonical_partial_stage_converges_from_intent_payload(self) -> None:
        _, contract, world, root = self._world()
        plan = world["plan"]
        _direct_sequence_claim(contract, world)
        adapter._claim(contract, plan)
        adapter._backup(contract, plan)
        adapter._stage(contract, plan)
        adapter._recovery_install(contract, plan)
        closure = adapter._verify_recovery_closure(contract, plan)
        backup = adapter._verify_backup(contract, plan, source_must_match=True)
        arm = adapter.boot_recovery_v1.build_arm(
            contract,
            plan,
            launch_claim=adapter._strategy_launch_claim(contract, plan),
            backup_manifest=backup,
            closure=closure,
            journal_digest=str(adapter._load_journal(contract, plan)["journal_digest"]),
            boot_identity_digest=adapter.launcher_v1.boot_identity_digest(),
        )
        raw = adapter.contract_v1.canonical_bytes(arm)
        intent = adapter._ensure_recovery_intent(
            contract,
            plan,
            "arm",
            payload={
                "kind": "canonical_file",
                "sha256": adapter._digest_bytes(raw),
                "size": len(raw),
                "mode": 0o600,
                "uid": os.getuid(),
                "gid": os.getgid(),
                "canonical_value": arm,
            },
        )
        stage, _ = adapter._recovery_stage_paths(contract, plan, "arm")
        self.assertIsNotNone(stage)
        assert stage is not None
        stage.write_bytes(raw[: max(1, len(raw) // 2)])
        os.chmod(stage, 0o600)
        adapter._converge_recovery_infrastructure(contract, plan)
        adapter._recover_recovery_infrastructure(contract, plan)
        self.assertFalse(stage.exists())
        self.assertEqual(intent["payload"]["canonical_value"], arm)
        self.assertFalse((root / ("a" * 64)).exists())

    def test_runtime_stage_create_kill_is_owned_and_converges(self) -> None:
        _, contract, world, root = self._world()
        plan = world["plan"]
        _direct_sequence_claim(contract, world)
        adapter._claim(contract, plan)
        adapter._backup(contract, plan)
        adapter._stage(contract, plan)
        with patch.object(
            adapter,
            "_recovery_intraprefix_fault",
            side_effect=lambda _contract, _plan, _prefix, boundary: (
                (_ for _ in ()).throw(RuntimeError("synthetic os kill"))
                if boundary == "stage_open"
                else None
            ),
        ):
            result = adapter.build_role_result(
                contract,
                plan,
                role="recovery_install",
                call_index=1,
            )
        self.assertEqual(result["status"], "indeterminate")
        self.assertTrue(result["persistent_mutation"])
        self.assertEqual(result["mutation_scope"], "recovery_infrastructure")
        stage, _ = adapter._recovery_stage_paths(contract, plan, "runtime_package")
        self.assertIsNotNone(stage)
        assert stage is not None
        self.assertTrue(stage.is_dir())
        adapter._converge_recovery_infrastructure(contract, plan)
        adapter._recover_recovery_infrastructure(contract, plan)
        self.assertFalse(stage.exists())
        self.assertFalse((root / ("a" * 64)).exists())

    def test_runtime_stage_real_sigkill_subprocess_is_recoverable(self) -> None:
        _, contract, world, root = self._world()
        plan = world["plan"]
        _direct_sequence_claim(contract, world)
        adapter._claim(contract, plan)
        adapter._backup(contract, plan)
        adapter._stage(contract, plan)
        contract_path = root / "sigkill-contract.json"
        plan_path = root / "sigkill-plan.json"
        contract_path.write_bytes(contract_v1.canonical_bytes(contract))
        plan_path.write_bytes(contract_v1.canonical_bytes(plan))
        script = (
            "import json,os,signal;"
            "from pathlib import Path;"
            "import p08_activation_contract_v1 as c;"
            "import p08_activation_production_adapter_v1 as a;"
            f"contract=json.loads(Path({str(contract_path)!r}).read_bytes());"
            f"plan=json.loads(Path({str(plan_path)!r}).read_bytes());"
            "original=a._recovery_intraprefix_fault;"
            "a._recovery_intraprefix_fault=lambda co,pl,pr,b: "
            "os.kill(os.getpid(),signal.SIGKILL) if b=='stage_open' else original(co,pl,pr,b);"
            "a._recovery_install(contract,plan)"
        )
        completed = subprocess.run(
            [sys.executable, "-B", "-P", "-S", "-c", script],
            cwd=ROOT,
            env={
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": f"{ROOT / 'scripts'}:/srv/myuna/repos/core/src",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        self.assertEqual(completed.returncode, -signal.SIGKILL)
        self.assertEqual(completed.stdout, b"")
        adapter._converge_recovery_infrastructure(contract, plan)
        adapter._recover_recovery_infrastructure(contract, plan)
        self.assertFalse((root / ("a" * 64)).exists())
        self.assertEqual(list(root.rglob("*.p08-*.txn")), [])

    def test_readiness_never_reads_opaque_state_bytes(self) -> None:
        _, contract, world, root = self._world()
        state_root = root / "var/lib/myuna-active-temporal-context-v1"
        original = adapter._read_regular_bytes

        def guarded(path: Path, *, maximum: int = adapter.MAX_TARGET_FILE_BYTES) -> bytes:
            try:
                Path(path).relative_to(state_root)
            except ValueError:
                return original(Path(path), maximum=maximum)
            raise AssertionError("opaque state bytes read during readiness")

        with patch.object(adapter, "_read_regular_bytes", side_effect=guarded):
            for role in ("construct", "prepare", "formal1", "formal2", "drift"):
                with self.subTest(role=role):
                    result = adapter.build_role_result(
                        contract,
                        world["plan"],
                        role=role,
                        call_index=1,
                    )
                    self.assertIn(result["status"], {"ready", "success"})
                    self.assertFalse(result["persistent_mutation"])

    def test_nested_opaque_state_requires_explicit_directory_authority(self) -> None:
        _, _, _, root = self._world()
        state_root = root / "var/lib/myuna-active-temporal-context-v1"
        nested = state_root / "nested"
        nested.mkdir(mode=0o700)
        (nested / "state.bin").write_bytes(b"opaque")
        with self.assertRaises(adapter.AdapterError):
            adapter.opaque_metadata(
                state_root,
                absolute_path="/var/lib/myuna-active-temporal-context-v1",
            )

    def test_unit_prestate_drift_rejects_before_claim(self) -> None:
        _, contract, world, root = self._world()
        unit_state = root / "var/lib/myuna-activation-engine-v1/unit-state.json"
        value = json.loads(unit_state.read_bytes())
        value["service_active_enter_monotonic_usec"] += 1
        unit_state.write_bytes(contract_v1.canonical_bytes(value))
        result = adapter.build_role_result(
            contract, world["plan"], role="prepare", call_index=1
        )
        self.assertEqual(result["status"], "rejected")
        self.assertFalse(result["persistent_mutation"])
        self.assertFalse(adapter.incident_root(contract, world["plan"]).exists())

    def test_target_directory_and_environment_drift_reject_before_claim(self) -> None:
        _, contract, world, root = self._world()
        target = Path(str(world["plan"]["execution"]["target_source_path"]))
        (target / "scripts").chmod(0o700)
        result = adapter.build_role_result(
            contract, world["plan"], role="prepare", call_index=1
        )
        self.assertEqual(result["status"], "rejected")
        self.assertFalse(result["persistent_mutation"])
        self.assertFalse(adapter.incident_root(contract, world["plan"]).exists())

        (target / "scripts").chmod(0o755)
        environment = root / "etc/myuna-active-temporal-context-v1/selector.env"
        environment.write_bytes(environment.read_bytes() + b"EXTRA=1\n")
        with self.assertRaises(adapter.AdapterError):
            adapter.construct_execution(
                contract,
                root=root,
                backend="synthetic",
                target_source_path=target,
                acceptance_scope_digest="7" * 64,
            )

    def test_target_manifest_contract_substitution_fails_closed(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        base = Path(directory.name)
        contract = _contract()
        target = base / ("a" * 64)
        installed_shadow.create_target_release(ROOT, target, contract)
        manifest_path = target / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["activation_engine_contract"]["production_live_authorized"] = True
        manifest_path.write_bytes(contract_v1.canonical_bytes(manifest))
        with self.assertRaises(adapter.AdapterError):
            installed_shadow.create_world(
                contract,
                root=base / "world",
                target_source=target,
                predecessor_identity="b" * 64,
                scenario=installed_shadow.InstalledShadowScenario(),
            )

    def test_supervisor_rejects_noncanonical_plan_path_before_child(self) -> None:
        _, contract, world, root = self._world()
        substituted = root / "SUBSTITUTED.PLAN.json"
        substituted.write_bytes(world["plan_path"].read_bytes())
        substituted.chmod(0o600)
        with self.assertRaises(supervisor.SupervisorError):
            supervisor.run_sequence(
                contract,
                world["plan"],
                contract_path=world["contract_path"],
                plan_path=substituted,
                deploy_root=Path(str(world["plan"]["execution"]["target_source_path"])),
            )
        self.assertFalse(adapter.incident_root(contract, world["plan"]).exists())

    def test_backup_mode_and_extra_inventory_fail_closed(self) -> None:
        result, root = _run(self, installed_shadow.InstalledShadowScenario())
        contract = _contract()
        incident = (
            root
            / "var/lib/myuna-activation-backups/p08-activation-engine-v1/incidents"
            / result["plan_digest"]
        )
        plan = adapter._read_json(incident / "PLAN.json")
        selector = incident / "BACKUP/public/selector"
        selector.chmod(0o644)
        with self.assertRaises(adapter.AdapterError):
            adapter._verify_backup(contract, plan, source_must_match=False)
        selector.chmod(0o600)
        (incident / "BACKUP/extra").mkdir()
        with self.assertRaises(adapter.AdapterError):
            adapter._verify_backup(contract, plan, source_must_match=False)

    def test_target_hardlink_and_symlink_substitution_fail_closed(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        target = Path(directory.name) / ("a" * 64)
        installed_shadow.create_target_release(ROOT, target, _contract())
        manifest = target / "manifest.json"
        os.link(manifest, target / "manifest-hardlink.json")
        with self.assertRaises(adapter.AdapterError):
            adapter.target_inventory(target)
        (target / "manifest-hardlink.json").unlink()
        original = target / "manifest.original"
        manifest.rename(original)
        manifest.symlink_to(original.name)
        with self.assertRaises(adapter.AdapterError):
            adapter.target_inventory(target)
        manifest.unlink()
        original.rename(manifest)
        extension = target / "scripts/p08_temporal_gateway_v1.so"
        extension.write_bytes(b"substitution")
        with self.assertRaises(adapter.AdapterError):
            adapter.target_inventory(target)
        extension.unlink()
        bytecode = target / "scripts/orphan.pyc"
        bytecode.write_bytes(b"bytecode")
        with self.assertRaises(adapter.AdapterError):
            adapter.target_inventory(target)

    def test_predecessor_release_manifest_inventory_and_metadata_drift_reject(self) -> None:
        mutations = (
            "manifest_byte",
            "extra",
            "missing",
            "symlink",
            "hardlink",
            "directory",
            "mode",
            "uid_gid",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                _, contract, world, root = self._world()
                execution = world["plan"]["execution"]
                predecessor = (
                    adapter._rooted(
                        root,
                        str(contract["production_adapter"]["fixed_paths"]["release_root"]),
                    )
                    / str(world["plan"]["predecessor_identity"])
                )
                selected = predecessor / "src/p08_temporal_service_v1.py"
                if mutation == "manifest_byte":
                    manifest = predecessor / "manifest.json"
                    manifest.write_bytes(manifest.read_bytes() + b" ")
                elif mutation == "extra":
                    (predecessor / "unexpected").write_bytes(b"x")
                elif mutation == "missing":
                    selected.unlink()
                elif mutation == "symlink":
                    selected.unlink()
                    selected.symlink_to("../manifest.json")
                elif mutation == "hardlink":
                    selected.unlink()
                    os.link(predecessor / "manifest.json", selected)
                elif mutation == "directory":
                    selected.unlink()
                    selected.mkdir()
                elif mutation == "mode":
                    selected.chmod(0o600)
                else:
                    if os.geteuid() != 0:
                        self.skipTest("uid/gid predecessor fixture requires root")
                    os.chown(selected, os.getuid() + 1, os.getgid() + 1)
                with self.assertRaises(adapter.AdapterError):
                    adapter.construct_execution(
                        contract,
                        root=root,
                        backend="synthetic",
                        target_source_path=Path(str(execution["target_source_path"])),
                        acceptance_scope_digest="7" * 64,
                    )

    def test_predecessor_public_lineage_and_unit_bytes_are_not_rollback_authority(self) -> None:
        for mutation in (
            "selector_source",
            "selector_role_swap",
            "environment_release",
            "unit_literal",
        ):
            with self.subTest(mutation=mutation):
                _, contract, world, root = self._world()
                execution = world["plan"]["execution"]
                if mutation == "selector_source":
                    selector = adapter._rooted(
                        root,
                        str(contract["production_adapter"]["fixed_paths"]["selector"]),
                    )
                    value = json.loads(selector.read_bytes())
                    value["deploy_commit"] = "f" * 40
                    selector.write_bytes(contract_v1.canonical_bytes(value))
                elif mutation == "selector_role_swap":
                    selector = adapter._rooted(
                        root,
                        str(contract["production_adapter"]["fixed_paths"]["selector"]),
                    )
                    value = json.loads(selector.read_bytes())
                    value["gateway_client_sha256"] = contract["compatibility"][
                        "predecessor"
                    ]["client_roles"]["roles"]["status_content_free_helper"][
                        "sha256"
                    ]
                    selector.write_bytes(contract_v1.canonical_bytes(value))
                elif mutation == "environment_release":
                    environment = adapter._rooted(
                        root,
                        str(contract["production_adapter"]["fixed_paths"]["environment"]),
                    )
                    environment.write_bytes(
                        environment.read_bytes().replace(b"b" * 64, b"c" * 64)
                    )
                else:
                    service = adapter._rooted(
                        root,
                        str(contract["production_adapter"]["fixed_paths"]["service_unit"]),
                    )
                    predecessor_argv = " ".join(
                        contract["compatibility"]["predecessor"]["unit_runtime"][
                            "service"
                        ]["exec_start_argv"]
                    ).encode("ascii")
                    service.write_bytes(
                        service.read_bytes().replace(
                            b"ExecStart=" + predecessor_argv,
                            b"ExecStart=/bin/false",
                        )
                    )
                with self.assertRaises(adapter.AdapterError):
                    adapter.construct_execution(
                        contract,
                        root=root,
                        backend="synthetic",
                        target_source_path=Path(str(execution["target_source_path"])),
                        acceptance_scope_digest="7" * 64,
                    )


if __name__ == "__main__":
    unittest.main()
