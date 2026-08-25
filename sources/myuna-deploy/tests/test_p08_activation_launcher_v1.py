from __future__ import annotations

from hashlib import sha256
import importlib.machinery
import json
import os
from pathlib import Path
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import p08_activation_contract_v1 as contract_v1
import p08_activation_installed_shadow_v1 as installed_shadow
from p08_activation_engine_v1 import ActivationEngine, TerminalStatus
import p08_activation_fixture_child_v1 as fixture_child_v1
import p08_activation_launcher_v1 as launcher_v1
import p08_activation_production_adapter_v1 as adapter_v1


_RUNTIME_ROOTS: list[tempfile.TemporaryDirectory[str]] = []


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _compile(root: Path, relative: str) -> dict[str, object]:
    interpreter = Path(sys.executable).resolve()
    if root != ROOT:
        for required in contract_v1.REQUIRED_ENGINE_SOURCE_PATHS:
            destination = root / required
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / required, destination)
            os.chmod(destination, (ROOT / required).stat().st_mode & 0o777)
    source = root / relative
    paths = set(contract_v1.REQUIRED_ENGINE_SOURCE_PATHS)
    paths.add(relative)
    inventory = []
    for inventory_relative in sorted(paths):
        inventory_source = root / inventory_relative
        inventory.append(
            {
                "path": inventory_relative,
                "size": inventory_source.stat().st_size,
                "mode": inventory_source.stat().st_mode & 0o777,
                "sha256": _digest(inventory_source),
            }
        )
    core_source = Path("/srv/myuna/repos/core/src/myuna_core/trusted_time/__init__.py")
    return contract_v1.compile_contract(
        core_root="/srv/myuna/repos/core",
        deploy_root=str(root),
        core_commit="1" * 40,
        core_tree="2" * 40,
        deploy_commit="3" * 40,
        deploy_tree="4" * 40,
        source_inventory=inventory,
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
            "legacy_release_contract_digest": "a" * 64,
            "p07": {"inventory_digest": "5" * 64},
            "p10b": {"inventory_digest": "6" * 64},
            "predecessor": installed_shadow.synthetic_predecessor_binding(
                ROOT,
                release_identity="7" * 64,
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


def _plan(contract: dict[str, object]) -> dict[str, object]:
    fixed = contract["production_adapter"]["fixed_paths"]
    public = {
        role: {
            "schema": contract_v1.PUBLIC_FILE_SCHEMA,
            "path": fixed[role],
            "type": "file",
            "mode": 0o600 if role in {"selector", "environment"} else 0o644,
            "uid": contract["production_adapter"]["accounts"]["service"]["uid"],
            "gid": contract["production_adapter"]["accounts"]["service"]["gid"],
            "nlink": 1,
            "size": 1,
            "sha256": str(index) * 64,
        }
        for index, role in enumerate(contract_v1.PUBLIC_ROLES, 1)
    }
    opaque = {
        "schema": contract_v1.OPAQUE_STATE_SCHEMA,
        "root": {
            "path": fixed["state_root"],
            "type": "directory",
            "mode": 0o700,
            "uid": contract["production_adapter"]["accounts"]["service"]["uid"],
            "gid": contract["production_adapter"]["accounts"]["service"]["gid"],
            "nlink": 2,
        },
        "entries": [
            {
                "path": "state.bin",
                "type": "file",
                "mode": 0o600,
                "uid": contract["production_adapter"]["accounts"]["service"]["uid"],
                "gid": contract["production_adapter"]["accounts"]["service"]["gid"],
                "nlink": 1,
                "size": 1,
            }
        ],
    }
    holder = tempfile.TemporaryDirectory(prefix="p08-launcher-runtime-")
    _RUNTIME_ROOTS.append(holder)
    runtime = Path(holder.name) / ("a" * 64)
    runtime.mkdir(mode=0o755)
    source = contract["engine_source"]
    for root_key, inventory_key in (
        ("deploy_root", "source_inventory"),
        ("core_root", "core_inventory"),
    ):
        source_root = Path(str(source[root_key]))
        for row in source[inventory_key]:
            selected = source_root / str(row["path"])
            destination = runtime / str(row["path"])
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            shutil.copyfile(selected, destination)
            os.chmod(destination, int(row["mode"]))
    manifest_path = runtime / "manifest.json"
    manifest_path.write_bytes(b"{}\n")
    os.chmod(manifest_path, 0o644)
    inventory = adapter_v1.target_inventory(runtime)
    directories = adapter_v1.target_directory_inventory(
        runtime, file_inventory=inventory
    )
    manifest_sha = _digest(manifest_path)
    execution = {
        "schema": contract_v1.EXECUTION_SCHEMA,
        "backend": "synthetic",
        "root": "/tmp/p08-launcher-test",
        "target_source_path": str(runtime),
        "target_manifest_sha256": manifest_sha,
        "target_inventory": inventory,
        "target_inventory_digest": contract_v1.digest_value(inventory),
        "target_directories": directories,
        "target_directories_digest": contract_v1.digest_value(directories),
        "public_prestate": public,
        "predecessor_release": contract["compatibility"]["predecessor"],
        "opaque_prestate": opaque,
        "acceptance_scope_digest": "c" * 64,
        "selected_release_identity": "7" * 64,
        "account_projection": {
            "schema": contract_v1.ACCOUNT_PROJECTION_SCHEMA,
            **json.loads(
                contract_v1.canonical_bytes(
                    contract["production_adapter"]["accounts"]
                )
            ),
        },
        "selector_compatibility": {
            "gateway_client_sha256": "d" * 64,
            "gateway_manifest_digest": "e" * 64,
            "plugin_digest": "f" * 64,
        },
        "execution_substrate": None,
        "runtime_package": {
            "schema": contract_v1.RUNTIME_PACKAGE_SCHEMA,
            "root": str(runtime),
            "inventory_digest": contract_v1.digest_value(inventory),
            "directories_digest": contract_v1.digest_value(directories),
            "manifest_sha256": manifest_sha,
            "contract_digest": contract["contract_digest"],
        },
        "unit_prestate": {
            "effective": {
                "schema": contract_v1.UNIT_RUNTIME_SCHEMA,
                "service": {
                    **dict(contract["compatibility"]["predecessor"]["unit_runtime"]["service"]),
                    "active_state": "active",
                    "sub_state": "running",
                },
                "socket": {
                    **dict(contract["compatibility"]["predecessor"]["unit_runtime"]["socket"]),
                    "active_state": "active",
                    "sub_state": "running",
                },
            },
            "coupled_state": "service_running",
            "schema": contract_v1.UNIT_STATE_SCHEMA,
            "service_active": True,
            "service_active_enter_monotonic_usec": 1,
            "service_enabled": False,
            "service_main_pid": 1001,
            "service_process": {
                **dict(
                    contract["compatibility"]["predecessor"]["unit_runtime"][
                        "service"
                    ]["process_identity"]
                ),
                "pid": 1001,
                "start_ticks": 1,
            },
            "service_restarts": 0,
            "socket_active": True,
            "socket_active_enter_monotonic_usec": 1,
            "socket_enabled": True,
            "socket_inode": {
                "schema": contract_v1.SOCKET_INODE_SCHEMA,
                "path": contract_v1.PRODUCTION_PATHS["socket_endpoint"],
                "type": "socket",
                "mode": 0o660,
                "uid": contract_v1.PRODUCTION_ACCOUNTS["service"]["uid"],
                "gid": contract_v1.PRODUCTION_ACCOUNTS["gateway"]["gid"],
                "nlink": 1,
            },
            "socket_n_accepted": 0,
            "socket_n_connections": 0,
        },
    }
    return contract_v1.build_plan(
        contract,
        sequence_identity="6" * 64,
        invocation_nonce="7" * 64,
        prestate_identity=contract_v1.digest_value(
            {
                "accounts": execution["account_projection"],
                "opaque": opaque,
                "predecessor_release": execution["predecessor_release"],
                "public": public,
                "units": execution["unit_prestate"],
            }
        ),
        predecessor_identity="7" * 64,
        target_identity="a" * 64,
        execution=execution,
    )


def _write_inputs(root: Path, contract: dict[str, object], plan: dict[str, object]) -> tuple[Path, Path]:
    contract_path = root / "CONTRACT.json"
    plan_path = root / "PLAN.json"
    contract_path.write_bytes(contract_v1.canonical_bytes(contract))
    plan_path.write_bytes(contract_v1.canonical_bytes(plan))
    return contract_path, plan_path


class ActivationLauncherTests(unittest.TestCase):
    def test_supervisor_bootstrap_timeout_kill_wait_drain_is_bounded(self) -> None:
        contract = _compile(ROOT, contract_v1.PRODUCTION_ADAPTER_PATH)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / ("a" * 64)
            installed_shadow.create_target_release(ROOT, target, contract)
            world = installed_shadow.create_world(
                contract,
                root=base / "world",
                target_source=target,
                predecessor_identity="7" * 64,
                scenario=installed_shadow.InstalledShadowScenario(),
            )
            strategy = adapter_v1._strategy_root(
                contract, world["plan"]["execution"]
            )
            intent_path = strategy / "entries" / ("e" * 64) / "INTENT.json"
            inventory = adapter_v1.target_inventory(target)
            directories = adapter_v1.target_directory_inventory(
                target, file_inventory=inventory
            )
            parent_pipe_fds = os.pipe2(os.O_CLOEXEC)
            parent_nonce = b"n" * 32
            intent = launcher_v1.build_supervisor_bootstrap_intent(
                contract,
                entry_nonce="e" * 64,
                intent_path=intent_path,
                contract_path=world["contract_path"],
                root=base / "world",
                backend="synthetic",
                target_source_path=target,
                target_inventory=inventory,
                target_directories=directories,
                acceptance_scope_digest="7" * 64,
                recover_plan=None,
                parent_pipe_fd=parent_pipe_fds[0],
                parent_nonce_sha256=sha256(parent_nonce).hexdigest(),
            )

            class TimedOutChild:
                pid = 4242
                returncode: int | None = None
                communicate_calls = 0

                def communicate(self, *, timeout: int) -> tuple[bytes, bytes]:
                    self.communicate_calls += 1
                    if self.communicate_calls < 2:
                        raise subprocess.TimeoutExpired([], timeout)
                    self.returncode = -signal.SIGKILL
                    return b"", b""

            child = TimedOutChild()
            with patch.object(
                launcher_v1.subprocess, "Popen", return_value=child
            ), patch.object(
                launcher_v1.os, "killpg"
            ) as killed, patch.object(
                launcher_v1, "_process_group_orphan_count", return_value=0
            ), patch.object(
                launcher_v1.time, "monotonic", side_effect=(0.0, 3601.0, 3602.0)
            ):
                capture = launcher_v1.run_supervisor_bootstrap_capture(
                    contract,
                    intent,
                    parent_pipe_fds=parent_pipe_fds,
                    parent_nonce=parent_nonce,
                )
            self.assertEqual(child.communicate_calls, 2)
            self.assertEqual(
                [call.args[1] for call in killed.call_args_list],
                [signal.SIGTERM, signal.SIGKILL],
            )
            self.assertEqual(capture["exit_class"], "hard_timeout")
            self.assertEqual(capture["returncode"], -signal.SIGKILL)
            self.assertEqual(capture["canonical_status"], "indeterminate")
            self.assertIsNone(capture["canonical_result"])
            launcher_v1.validate_supervisor_bootstrap_capture(
                contract, intent, capture
            )
            substituted = dict(capture)
            substituted["returncode"] = 0
            unsigned = {
                key: value
                for key, value in substituted.items()
                if key != "capture_digest"
            }
            substituted["capture_digest"] = contract_v1.digest_value(unsigned)
            with self.assertRaises(launcher_v1.LauncherError):
                launcher_v1.validate_supervisor_bootstrap_capture(
                    contract, intent, substituted
                )

    def test_launcher_drives_one_canonical_full_chain(self) -> None:
        relative = "scripts/p08_activation_fixture_child_v1.py"
        contract = _compile(ROOT, relative)
        plan = _plan(contract)
        engine = ActivationEngine(contract, plan)
        with tempfile.TemporaryDirectory() as directory:
            contract_path, plan_path = _write_inputs(Path(directory), contract, plan)
            while engine.terminal_status is TerminalStatus.RUNNING:
                self.assertEqual(len(engine.next_roles), 1)
                role = next(iter(engine.next_roles))
                call_index = len(engine.results.get(role, [])) + 1
                invocation = launcher_v1.build_invocation(
                    contract,
                    plan,
                    role=role,
                    call_index=call_index,
                    contract_path=contract_path,
                    plan_path=plan_path,
                    deploy_root=Path(str(plan["execution"]["target_source_path"])),
                    entrypoint_relative=relative,
                )
                self.assertEqual(invocation["argv"][1:4], ["-B", "-P", "-S"])
                self.assertNotIn("PYTHONPYCACHEPREFIX", invocation["environment"])
                capture = launcher_v1.run_capture(contract, plan, invocation)
                result = fixture_child_v1.build_fixture_result(
                    contract,
                    plan,
                    role=role,
                    call_index=call_index,
                )
                self.assertEqual(
                    capture["canonical_result_digest"], result["result_digest"]
                )
                engine.apply(result)
        self.assertEqual(engine.terminal_status, TerminalStatus.ACCEPTED)
        self.assertEqual(
            list(engine.results),
            [role for role in contract_v1.ROLE_ORDER if role not in {
                "continuity_transition",
                "continuity_reconcile",
                "converge",
                "recover",
            }],
        )

    def test_real_source_owned_all_role_subprocess_capture(self) -> None:
        relative = "scripts/p08_activation_fixture_child_v1.py"
        contract = _compile(ROOT, relative)
        plan = _plan(contract)
        with tempfile.TemporaryDirectory() as directory:
            contract_path, plan_path = _write_inputs(Path(directory), contract, plan)
            for role in contract_v1.ROLE_ORDER:
                call_index = 1
                invocation = launcher_v1.build_invocation(
                    contract,
                    plan,
                    role=role,
                    call_index=call_index,
                    contract_path=contract_path,
                    plan_path=plan_path,
                    deploy_root=Path(str(plan["execution"]["target_source_path"])),
                    entrypoint_relative=relative,
                )
                capture = launcher_v1.run_capture(contract, plan, invocation)
                with self.subTest(role=role):
                    self.assertEqual(capture["canonical_status"], "ready")
                    self.assertEqual(capture["returncode"], 0)
                    self.assertEqual(capture["stderr_size"], 0)
                    self.assertEqual(
                        capture["progress_count"],
                        len(contract["roles"][role]["progress_phases"]),
                    )
                    self.assertEqual(
                        capture["last_progress_phase"], "canonical_serialization"
                    )
                    self.assertFalse(capture["raw_output_retained"])
                    self.assertEqual(capture["orphan_count"], 0)

    def test_ready_result_with_partial_progress_is_indeterminate(self) -> None:
        relative = "scripts/p08_activation_fixture_child_v1.py"
        contract = _compile(ROOT, relative)
        plan = _plan(contract)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract_path, plan_path = _write_inputs(root, contract, plan)
            invocation = launcher_v1.build_invocation(
                contract,
                plan,
                role="prepare",
                call_index=1,
                contract_path=contract_path,
                plan_path=plan_path,
                deploy_root=Path(str(plan["execution"]["target_source_path"])),
                entrypoint_relative=relative,
            )
            result = fixture_child_v1.build_fixture_result(
                contract, plan, role="prepare", call_index=1
            )
            phases = contract["roles"]["prepare"]["progress_phases"]
            partial = b"".join(
                launcher_v1.progress_bytes(
                    contract,
                    plan,
                    role="prepare",
                    phase=phase,
                    phase_index=index,
                )
                for index, phase in enumerate(phases[:-1], 1)
            )
            capture = launcher_v1._capture_result(
                contract,
                plan,
                invocation,
                stdout=contract_v1.canonical_bytes(result),
                stderr=b"",
                progress=partial,
                returncode=0,
                exit_class="exit",
                elapsed_ms=1,
                orphan_count=0,
            )
            self.assertEqual(capture["canonical_status"], "indeterminate")
            self.assertIsNone(capture["canonical_result"])

    def test_exit_class_and_orphan_count_gate_canonical_result(self) -> None:
        relative = "scripts/p08_activation_fixture_child_v1.py"
        contract = _compile(ROOT, relative)
        plan = _plan(contract)
        with tempfile.TemporaryDirectory() as directory:
            contract_path, plan_path = _write_inputs(Path(directory), contract, plan)
            invocation = launcher_v1.build_invocation(
                contract,
                plan,
                role="prepare",
                call_index=1,
                contract_path=contract_path,
                plan_path=plan_path,
                deploy_root=Path(str(plan["execution"]["target_source_path"])),
                entrypoint_relative=relative,
            )
            result = fixture_child_v1.build_fixture_result(
                contract, plan, role="prepare", call_index=1
            )
            progress = b"".join(
                launcher_v1.progress_bytes(
                    contract,
                    plan,
                    role="prepare",
                    phase=phase,
                    phase_index=index,
                )
                for index, phase in enumerate(
                    contract["roles"]["prepare"]["progress_phases"], 1
                )
            )
            for exit_class, orphan_count in (("hard_timeout", 0), ("exit", 1)):
                with self.subTest(exit_class=exit_class, orphan_count=orphan_count):
                    capture = launcher_v1._capture_result(
                        contract,
                        plan,
                        invocation,
                        stdout=contract_v1.canonical_bytes(result),
                        stderr=b"",
                        progress=progress,
                        returncode=0,
                        exit_class=exit_class,
                        elapsed_ms=1,
                        orphan_count=orphan_count,
                    )
                    self.assertEqual(capture["canonical_status"], "indeterminate")
                    self.assertIsNone(capture["canonical_result"])

            ready = launcher_v1._capture_result(
                contract,
                plan,
                invocation,
                stdout=contract_v1.canonical_bytes(result),
                stderr=b"",
                progress=progress,
                returncode=0,
                exit_class="exit",
                elapsed_ms=1,
                orphan_count=0,
            )
            for key, value in (("exit_class", "unknown"), ("orphan_count", 1)):
                tampered = dict(ready)
                tampered[key] = value
                unsigned = {
                    name: item
                    for name, item in tampered.items()
                    if name != "capture_digest"
                }
                tampered["capture_digest"] = contract_v1.digest_value(unsigned)
                with self.subTest(key=key), self.assertRaises(launcher_v1.LauncherError):
                    launcher_v1.validate_capture(
                        contract,
                        plan,
                        tampered,
                        expected_role="prepare",
                        expected_call=1,
                    )

    def test_invocation_is_exactly_source_and_plan_bound(self) -> None:
        relative = "scripts/p08_activation_fixture_child_v1.py"
        contract = _compile(ROOT, relative)
        plan = _plan(contract)
        with tempfile.TemporaryDirectory() as directory:
            contract_path, plan_path = _write_inputs(Path(directory), contract, plan)
            invocation = launcher_v1.build_invocation(
                contract,
                plan,
                role="prepare",
                call_index=1,
                contract_path=contract_path,
                plan_path=plan_path,
                deploy_root=Path(str(plan["execution"]["target_source_path"])),
                entrypoint_relative=relative,
            )
            variants = []
            wrong_env = json.loads(json.dumps(invocation))
            wrong_env["environment"]["PYTHONPATH"] = "/substituted"
            wrong_env["invocation_digest"] = contract_v1.digest_value(
                {key: value for key, value in wrong_env.items() if key != "invocation_digest"}
            )
            variants.append(wrong_env)
            wrong_argv = json.loads(json.dumps(invocation))
            wrong_argv["argv"][-1] = "2"
            wrong_argv["invocation_digest"] = contract_v1.digest_value(
                {key: value for key, value in wrong_argv.items() if key != "invocation_digest"}
            )
            variants.append(wrong_argv)
            extra = json.loads(json.dumps(invocation))
            extra["extra"] = False
            variants.append(extra)
            for index, value in enumerate(variants):
                with self.subTest(index=index), self.assertRaises(launcher_v1.LauncherError):
                    launcher_v1.validate_invocation(contract, plan, value)

    def test_progress_wrong_nonce_order_replay_and_unknown_fail_closed(self) -> None:
        relative = "scripts/p08_activation_fixture_child_v1.py"
        contract = _compile(ROOT, relative)
        plan = _plan(contract)
        role = "prepare"
        valid = b"".join(
            launcher_v1.progress_bytes(
                contract, plan, role=role, phase=phase, phase_index=index
            )
            for index, phase in enumerate(contract["roles"][role]["progress_phases"], 1)
        )
        self.assertEqual(
            len(launcher_v1.validate_progress(contract, plan, role=role, raw=valid)),
            len(contract["roles"][role]["progress_phases"]),
        )
        values = [json.loads(line) for line in valid.splitlines()]
        variants = []
        wrong_nonce = json.loads(json.dumps(values))
        wrong_nonce[0]["invocation_nonce"] = "f" * 64
        variants.append(wrong_nonce)
        wrong_order = json.loads(json.dumps(values))
        wrong_order[0], wrong_order[1] = wrong_order[1], wrong_order[0]
        variants.append(wrong_order)
        replay = json.loads(json.dumps(values))
        replay.insert(1, replay[0])
        variants.append(replay)
        unknown = json.loads(json.dumps(values))
        unknown[0]["raw"] = "forbidden"
        variants.append(unknown)
        for index, rows in enumerate(variants):
            raw = b"".join(contract_v1.canonical_bytes(row) for row in rows)
            with self.subTest(index=index), self.assertRaises(launcher_v1.LauncherError):
                launcher_v1.validate_progress(contract, plan, role=role, raw=raw)

    def test_no_progress_timeout_kills_and_returns_content_free_capture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            child = scripts / "stall.py"
            child.write_text(
                "#!/usr/bin/env python3\nimport time\ntime.sleep(10)\n",
                "utf-8",
            )
            relative = "scripts/stall.py"
            contract = _compile(root, relative)
            contract["roles"]["prepare"]["hard_deadline_seconds"] = 2
            contract["roles"]["prepare"]["no_progress_seconds"] = 1
            unsigned = {
                key: value for key, value in contract.items() if key != "contract_digest"
            }
            contract["contract_digest"] = contract_v1.digest_value(unsigned)
            plan = _plan(contract)
            contract_path, plan_path = _write_inputs(root, contract, plan)
            invocation = launcher_v1.build_invocation(
                contract,
                plan,
                role="prepare",
                call_index=1,
                contract_path=contract_path,
                plan_path=plan_path,
                deploy_root=Path(str(plan["execution"]["target_source_path"])),
                entrypoint_relative=relative,
            )
            capture = launcher_v1.run_capture(contract, plan, invocation)
            self.assertEqual(capture["exit_class"], "no_progress_timeout")
            self.assertEqual(capture["canonical_status"], "indeterminate")
            self.assertLess(capture["elapsed_ms"], 4000)
            self.assertFalse(capture["raw_output_retained"])
            self.assertEqual(capture["orphan_count"], 0)

    def test_invalid_progress_cannot_extend_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            child = scripts / "invalid_progress.py"
            child.write_text(
                "#!/usr/bin/env python3\n"
                "import os, time\n"
                "fd=int(os.environ['MYUNA_P08_ACTIVATION_PROGRESS_FD'])\n"
                "os.write(fd,b'{\"schema\":\"wrong\"}\\n')\n"
                "time.sleep(10)\n",
                "utf-8",
            )
            relative = "scripts/invalid_progress.py"
            contract = _compile(root, relative)
            contract["roles"]["prepare"]["hard_deadline_seconds"] = 3
            contract["roles"]["prepare"]["no_progress_seconds"] = 2
            unsigned = {
                key: value for key, value in contract.items() if key != "contract_digest"
            }
            contract["contract_digest"] = contract_v1.digest_value(unsigned)
            plan = _plan(contract)
            contract_path, plan_path = _write_inputs(root, contract, plan)
            invocation = launcher_v1.build_invocation(
                contract,
                plan,
                role="prepare",
                call_index=1,
                contract_path=contract_path,
                plan_path=plan_path,
                deploy_root=Path(str(plan["execution"]["target_source_path"])),
                entrypoint_relative=relative,
            )
            capture = launcher_v1.run_capture(contract, plan, invocation)
            self.assertEqual(capture["exit_class"], "progress_invalid")
            self.assertEqual(capture["canonical_status"], "indeterminate")
            self.assertLess(capture["elapsed_ms"], 3000)

    def test_bound_source_inventory_drift_is_rejected_before_child(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            child = scripts / "child.py"
            child.write_text("#!/usr/bin/env python3\n", "utf-8")
            relative = "scripts/child.py"
            contract = _compile(root, relative)
            plan = _plan(contract)
            contract_path, plan_path = _write_inputs(root, contract, plan)
            bound = (
                Path(str(plan["execution"]["target_source_path"]))
                / "scripts/p08_activation_engine_v1.py"
            )
            bound.write_bytes(bound.read_bytes() + b"\n")
            with self.assertRaises(launcher_v1.LauncherError):
                launcher_v1.build_invocation(
                    contract,
                    plan,
                    role="prepare",
                    call_index=1,
                    contract_path=contract_path,
                    plan_path=plan_path,
                    deploy_root=Path(str(plan["execution"]["target_source_path"])),
                    entrypoint_relative=relative,
                )

    def test_bound_source_import_substitution_is_rejected_before_child(self) -> None:
        substitutions = (
            "same_stem_package",
            "extension",
            "stdlib_shadow",
            "sitecustomize",
            "unchecked_pycache",
            "core_shadow",
            "mixed_build",
        )
        for substitution in substitutions:
            with self.subTest(substitution=substitution), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                scripts = root / "scripts"
                scripts.mkdir()
                child = scripts / "child.py"
                child.write_text("#!/usr/bin/env python3\n", "utf-8")
                relative = "scripts/child.py"
                contract = _compile(root, relative)
                plan = _plan(contract)
                contract_path, plan_path = _write_inputs(root, contract, plan)
                runtime = Path(str(plan["execution"]["target_source_path"]))
                stem = runtime / "scripts/p08_activation_engine_v1"
                if substitution == "same_stem_package":
                    stem.mkdir()
                elif substitution == "extension":
                    Path(
                        str(stem) + importlib.machinery.EXTENSION_SUFFIXES[0]
                    ).write_bytes(b"")
                elif substitution == "stdlib_shadow":
                    (runtime / "scripts/json.py").write_bytes(b"raise RuntimeError\n")
                elif substitution == "sitecustomize":
                    (runtime / "scripts/sitecustomize.py").write_bytes(b"pass\n")
                elif substitution == "unchecked_pycache":
                    pycache = runtime / "scripts/__pycache__"
                    pycache.mkdir()
                    (pycache / "json.cpython-312.pyc").write_bytes(b"unchecked")
                elif substitution == "core_shadow":
                    package = runtime / "scripts/myuna_core"
                    package.mkdir()
                    (package / "__init__.py").write_bytes(b"pass\n")
                else:
                    selected = runtime / "scripts/p08_activation_launcher_v1.py"
                    selected.write_bytes(
                        (runtime / "scripts/p08_activation_contract_v1.py").read_bytes()
                    )
                with self.assertRaises(launcher_v1.LauncherError):
                    launcher_v1.build_invocation(
                        contract,
                        plan,
                        role="prepare",
                        call_index=1,
                        contract_path=contract_path,
                        plan_path=plan_path,
                        deploy_root=Path(str(plan["execution"]["target_source_path"])),
                        entrypoint_relative=relative,
                    )

    def test_production_adapter_subprocess_imports_only_materialized_runtime(self) -> None:
        relative = "scripts/p08_activation_production_adapter_v1.py"
        contract = _compile(ROOT, relative)
        plan = _plan(contract)
        with tempfile.TemporaryDirectory() as directory:
            contract_path, plan_path = _write_inputs(Path(directory), contract, plan)
            invocation = launcher_v1.build_invocation(
                contract,
                plan,
                role="construct",
                call_index=1,
                contract_path=contract_path,
                plan_path=plan_path,
                deploy_root=Path(str(plan["execution"]["target_source_path"])),
                entrypoint_relative=relative,
            )
            self.assertEqual(
                invocation["argv"][1:6],
                ["-B", "-P", "-S", "-m", "p08_activation_production_adapter_v1"],
            )
            capture = launcher_v1.run_capture(contract, plan, invocation)
        self.assertEqual(capture["returncode"], 2)
        self.assertEqual(capture["canonical_status"], "rejected")
        self.assertIsNotNone(capture["canonical_result"])
        self.assertFalse(capture["raw_output_retained"])

    def test_o_excl_capture_persistence_and_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence" / "CAPTURE.json"
            capture = {
                "schema": contract_v1.CAPTURE_SCHEMA,
                "capture_digest": "1" * 64,
                "raw_output_retained": False,
            }
            launcher_v1.persist_capture_o_excl(path, capture)
            details = path.lstat()
            self.assertTrue(stat.S_ISREG(details.st_mode))
            self.assertEqual(stat.S_IMODE(details.st_mode), 0o600)
            self.assertEqual(details.st_nlink, 1)
            with self.assertRaises(launcher_v1.LauncherError):
                launcher_v1.persist_capture_o_excl(path, capture)

    def test_o_excl_concurrent_capture_has_one_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence" / "CAPTURE.json"
            capture = {
                "schema": contract_v1.CAPTURE_SCHEMA,
                "capture_digest": "2" * 64,
                "raw_output_retained": False,
            }
            successes: list[int] = []
            failures: list[int] = []

            def write(index: int) -> None:
                try:
                    launcher_v1.persist_capture_o_excl(path, capture)
                except launcher_v1.LauncherError:
                    failures.append(index)
                else:
                    successes.append(index)

            threads = [threading.Thread(target=write, args=(index,)) for index in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
            self.assertEqual(len(successes), 1)
            self.assertEqual(len(failures), 7)
            self.assertFalse(any(thread.is_alive() for thread in threads))


if __name__ == "__main__":
    unittest.main()
