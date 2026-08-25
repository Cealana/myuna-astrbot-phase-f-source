from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import p08_activation_boot_recovery_v1 as boot_recovery
import p08_activation_contract_v1 as contract_v1
import p08_activation_installed_shadow_v1 as installed_shadow
import p08_activation_production_adapter_v1 as adapter


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _recovery_unit_state(contract: dict[str, object]) -> dict[str, object]:
    runtime = contract["production_adapter"]["boot_recovery"]["unit_runtime"]
    return {
        **dict(runtime),
        "boot_identity_digest": "f" * 64,
        "invocation_id": "e" * 32,
    }


def _contract() -> dict[str, object]:
    core_source = Path("/srv/myuna/repos/core/src/myuna_core/trusted_time/__init__.py")
    source_inventory = []
    for relative in contract_v1.REQUIRED_ENGINE_SOURCE_PATHS:
        path = ROOT / relative
        source_inventory.append(
            {
                "path": relative,
                "size": path.stat().st_size,
                "mode": path.stat().st_mode & 0o777,
                "sha256": _digest(path),
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


def _world(
    case: unittest.TestCase,
) -> tuple[dict[str, object], dict[str, object], Path]:
    temporary = tempfile.TemporaryDirectory()
    case.addCleanup(temporary.cleanup)
    base = Path(temporary.name)
    contract = _contract()
    target = base / ("a" * 64)
    installed_shadow.create_target_release(ROOT, target, contract)
    world = installed_shadow.create_world(
        contract,
        root=base / "world",
        target_source=target,
        predecessor_identity="b" * 64,
        scenario=installed_shadow.InstalledShadowScenario(),
    )
    return contract, world["plan"], base


def _world_details(
    case: unittest.TestCase,
    scenario: installed_shadow.InstalledShadowScenario | None = None,
) -> tuple[dict[str, object], dict[str, object], Path]:
    temporary = tempfile.TemporaryDirectory()
    case.addCleanup(temporary.cleanup)
    base = Path(temporary.name)
    contract = _contract()
    target = base / ("a" * 64)
    installed_shadow.create_target_release(ROOT, target, contract)
    world = installed_shadow.create_world(
        contract,
        root=base / "world",
        target_source=target,
        predecessor_identity="b" * 64,
        scenario=scenario or installed_shadow.InstalledShadowScenario(),
    )
    return contract, world, base


def _strategy_claim(
    contract: dict[str, object], plan: dict[str, object]
) -> dict[str, object]:
    execution = plan["execution"]
    claim = contract_v1.build_strategy_launch_claim(
        contract,
        entry_nonce=plan["sequence_identity"],
        root=execution["root"],
        backend=execution["backend"],
        target_source_path=execution["target_source_path"],
        target_inventory_digest=execution["target_inventory_digest"],
        target_directories_digest=execution["target_directories_digest"],
        acceptance_scope_digest=execution["acceptance_scope_digest"],
        prestate_identity=plan["prestate_identity"],
    )
    strategy = adapter._strategy_root(contract, execution)
    boot_recovery._persist_json(strategy / "STRATEGY.LAUNCH.CLAIM.json", claim)
    return claim


def _prime_recovery(
    contract: dict[str, object], world: dict[str, object]
) -> None:
    plan = world["plan"]
    _strategy_claim(contract, plan)
    for role in (
        "construct",
        "claim",
        "backup",
        "stage",
        "recovery_install",
    ):
        adapter._payload(contract, plan, role)


def _simulate_reboot(
    contract: dict[str, object], plan: dict[str, object]
) -> None:
    state = adapter._unit_state(contract, plan)
    if state["socket_active"]:
        adapter._remove_synthetic_socket(contract, plan["execution"])
    state["service_active"] = False
    state["socket_active"] = False
    state["service_main_pid"] = 0
    state["service_process"] = None
    state["socket_inode"] = None
    for role in ("service", "socket"):
        state["effective"][role]["active_state"] = "inactive"
        state["effective"][role]["sub_state"] = "dead"
    state["coupled_state"] = "stopped"
    adapter._write_unit_state(contract, plan, state)


class BootRecoveryContractTests(unittest.TestCase):
    def test_generated_gate_artifacts_and_order_are_exact(self) -> None:
        contract = _contract()
        recovery = boot_recovery.boot_recovery_contract(contract)
        self.assertEqual(recovery["schema"], contract_v1.BOOT_RECOVERY_CONTRACT_SCHEMA)
        self.assertFalse(recovery["production_live_authorized"])
        self.assertFalse(recovery["no_arm_is_exact_noop"])
        self.assertTrue(recovery["same_boot_owned_prime_is_exact_noop"])
        self.assertTrue(recovery["product_start_requires_recovery_success"])
        self.assertEqual(
            recovery["install_order"],
            [
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
            ],
        )
        self.assertLess(
            recovery["install_order"].index("socket_recovery_dropin"),
            recovery["install_order"].index("service_recovery_dropin"),
        )
        self.assertLess(
            recovery["install_order"].index("service_recovery_dropin"),
            recovery["install_order"].index("arm"),
        )
        self.assertLess(
            recovery["install_order"].index("arm"),
            recovery["install_order"].index("product_gate_reload"),
        )
        roles = {row["role"]: row for row in recovery["artifacts"]}
        self.assertEqual(
            set(roles),
            {
                "recovery_unit",
                "recovery_enablement",
                "service_recovery_dropin",
                "socket_recovery_dropin",
            },
        )
        unit = roles["recovery_unit"]
        self.assertEqual(
            sha256(unit["content"].encode("ascii")).hexdigest(), unit["sha256"]
        )
        self.assertIn("Before=myuna-active-temporal-context-v1.service", unit["content"])
        self.assertIn("p08_activation_boot_recovery_v1", unit["content"])
        self.assertIn("Restart=on-failure", unit["content"])
        self.assertIn("RestartMode=direct", unit["content"])
        self.assertIn("RestartPreventExitStatus=2", unit["content"])
        self.assertEqual(
            recovery["transaction_liveness"],
            contract_v1.parse_boot_recovery_transaction(
                unit["content"].encode("ascii"),
                roles["service_recovery_dropin"]["content"].encode("ascii"),
            ),
        )
        self.assertEqual(recovery["per_boot_manager_max_starts"], 2)
        self.assertEqual(recovery["fresh_boot_deadline_seconds"], 900)
        for role in ("service_recovery_dropin", "socket_recovery_dropin"):
            self.assertEqual(
                roles[role]["content"],
                "[Unit]\n"
                "Requires=myuna-p08-activation-recovery-v1.service\n"
                "After=myuna-p08-activation-recovery-v1.service\n",
            )
        self.assertEqual(
            roles["recovery_enablement"]["target"],
            "../myuna-p08-activation-recovery-v1.service",
        )

    def test_retained_failure21_residue_contract_is_verify_only_and_exact(self) -> None:
        contract = _contract()
        observed = contract_v1.validate_retained_residue_normalization_contract(
            contract
        )
        self.assertEqual(observed["mode"], "verify_only")
        self.assertEqual(
            observed["terminal_handoff_sha256"],
            "2cddf0f2768bdc9a876d14e94c02a36a1b2eb83299412a4281d07e72ae1a38ca",
        )
        self.assertEqual(
            observed["allowed_future_operation"],
            "infrastructure_convergence_only",
        )
        self.assertFalse(observed["normalization_execution_authorized"])
        self.assertFalse(observed["target_action_allowed"])
        self.assertEqual(
            observed["source_authority"]["source_inventory_digest"],
            contract["engine_source"]["source_inventory_digest"],
        )
        for mutation, replacement in (
            ("terminal_handoff_sha256", "0" * 64),
            ("plan_digest", "0" * 64),
            ("launch_claim_digest", "0" * 64),
            ("normalization_execution_authorized", True),
            ("target_action_allowed", True),
            ("old_role_replay_allowed", True),
        ):
            candidate = json.loads(contract_v1.canonical_bytes(observed))
            candidate[mutation] = replacement
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                contract_v1.ContractError,
                "recovery_residue_normalization_rejected",
            ):
                contract_v1.validate_retained_residue_normalization_contract(
                    contract, candidate
                )

    def test_systemd_transaction_liveness_is_direct_and_fail_closed(self) -> None:
        contract = _contract()
        recovery = boot_recovery.boot_recovery_contract(contract)
        roles = {row["role"]: row for row in recovery["artifacts"]}
        unit = roles["recovery_unit"]["content"].encode("ascii")
        gate = roles["service_recovery_dropin"]["content"].encode("ascii")
        parsed = contract_v1.parse_boot_recovery_transaction(unit, gate)
        self.assertEqual(parsed, recovery["transaction_liveness"])
        self.assertEqual(parsed["systemd_version_identity"], "systemd-255")
        self.assertEqual(parsed["restart_mode_added_version"], 254)
        self.assertEqual(parsed["restart_mode"], "direct")
        for candidate in (
            unit.replace(b"RestartMode=direct\n", b""),
            unit.replace(b"RestartMode=direct\n", b"RestartMode=normal\n"),
            unit.replace(b"RestartMode=direct\n", b"RestartMode=debug\n"),
            unit.replace(
                b"RestartMode=direct\n",
                b"RestartMode=direct\nRestartMode=normal\n",
            ),
            unit.replace(
                b"[Service]\nType=oneshot\n",
                b"[Service]\nType=oneshot\n[Unit]\nRestartMode=direct\n",
            ),
        ):
            with self.subTest(unit_sha256=sha256(candidate).hexdigest()):
                with self.assertRaisesRegex(
                    contract_v1.ContractError,
                    "boot_recovery_transaction_rejected",
                ):
                    contract_v1.parse_boot_recovery_transaction(candidate, gate)
        for candidate in (
            gate.replace(b"After=", b"Wants="),
            gate.replace(b"Requires=", b"Wants="),
            gate + b"Wants=external.service\n",
        ):
            with self.subTest(gate_sha256=sha256(candidate).hexdigest()):
                with self.assertRaisesRegex(
                    contract_v1.ContractError,
                    "boot_recovery_transaction_rejected",
                ):
                    contract_v1.parse_boot_recovery_transaction(unit, candidate)
        with patch.dict(
            contract_v1.PRODUCTION_SYSTEMD,
            {"version_identity": "systemd-253"},
        ):
            with self.assertRaisesRegex(
                contract_v1.ContractError,
                "boot_recovery_transaction_rejected",
            ):
                contract_v1.parse_boot_recovery_transaction(unit, gate)

        first = boot_recovery.systemd_transaction_oracle(
            contract,
            result_class="unexpected_failure",
            start_number=1,
        )
        self.assertEqual(first["outcome"], "direct_reentry_pending")
        self.assertTrue(first["restart_scheduled"])
        self.assertTrue(first["dependent_job_preserved"])
        self.assertFalse(first["product_start_authorized"])
        second = boot_recovery.systemd_transaction_oracle(
            contract,
            result_class="success",
            start_number=2,
        )
        self.assertEqual(second["outcome"], "recovery_succeeded")
        self.assertTrue(second["dependent_job_preserved"])
        self.assertTrue(second["product_start_authorized"])
        typed = boot_recovery.systemd_transaction_oracle(
            contract,
            result_class="typed_blocked",
            start_number=1,
        )
        self.assertEqual(typed["outcome"], "typed_blocked")
        self.assertFalse(typed["restart_scheduled"])
        self.assertFalse(typed["product_start_authorized"])
        exhausted = boot_recovery.systemd_transaction_oracle(
            contract,
            result_class="unexpected_failure",
            start_number=2,
        )
        self.assertEqual(exhausted["outcome"], "restart_budget_exhausted")
        self.assertFalse(exhausted["dependent_job_preserved"])
        invalid = boot_recovery.systemd_transaction_oracle(
            contract,
            result_class="success",
            start_number=1,
            authority_exact=False,
        )
        self.assertEqual(invalid["outcome"], "blocked_invalid_authority")
        self.assertFalse(invalid["product_start_authorized"])

    def test_independent_systemd255_recovery_dependency_model_is_exact(self) -> None:
        contract = _contract()
        recovery = boot_recovery.boot_recovery_contract(contract)
        model = recovery["effective_systemd_model"]
        independent_priming = {
            name: [] for name in contract["systemd_authority"]["dependency_properties"]
        }
        independent_priming.update(
            {
                "After": sorted(
                    [
                        "-.mount",
                        "local-fs.target",
                        "system.slice",
                        "systemd-journald.socket",
                        "systemd-tmpfiles-setup.service",
                        "tmp.mount",
                    ]
                ),
                "Before": sorted(
                    [
                        "myuna-active-temporal-context-v1.service",
                        "myuna-active-temporal-context-v1.socket",
                        "shutdown.target",
                    ]
                ),
                "Conflicts": ["shutdown.target"],
                "Requires": ["local-fs.target", "system.slice"],
                "WantedBy": ["multi-user.target"],
                "Wants": ["tmp.mount"],
            }
        )
        self.assertEqual(model["priming_effective_dependencies"], independent_priming)
        independent_armed = json.loads(contract_v1.canonical_bytes(independent_priming))
        independent_armed["RequiredBy"] = [
            "myuna-active-temporal-context-v1.service",
            "myuna-active-temporal-context-v1.socket",
        ]
        self.assertEqual(model["armed_effective_dependencies"], independent_armed)
        self.assertEqual(model["mount_authority"]["root_unit"], "-.mount")
        for field, token in (
            ("After", "external.service"),
            ("Requires", "substituted.target"),
            ("RequiredBy", "other-program.service"),
        ):
            with self.subTest(field=field):
                candidate = json.loads(
                    contract_v1.canonical_bytes(recovery["unit_runtime"])
                )
                candidate["dependencies"][field].append(token)
                candidate["dependencies"][field].sort()
                candidate.update(
                    {
                        "boot_identity_digest": "f" * 64,
                        "invocation_id": "e" * 32,
                    }
                )
                with self.assertRaises(boot_recovery.BootRecoveryError):
                    boot_recovery.validate_unit_state(contract, candidate)

    def test_systemd_255_offline_parser_accepts_generated_direct_reentry_unit(
        self,
    ) -> None:
        contract = _contract()
        roles = {
            row["role"]: row
            for row in contract["production_adapter"]["boot_recovery"]["artifacts"]
        }
        version = subprocess.run(
            ["/usr/bin/systemd-analyze", "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
        )
        self.assertEqual(version.returncode, 0)
        self.assertTrue(version.stdout.startswith("systemd 255 "))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recovery = root / "myuna-p08-activation-recovery-v1.service"
            service = root / "myuna-active-temporal-context-v1.service"
            socket = root / "myuna-active-temporal-context-v1.socket"
            recovery.write_text(roles["recovery_unit"]["content"], "ascii")
            service.write_text(
                roles["service_recovery_dropin"]["content"]
                + "\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\n",
                "ascii",
            )
            socket.write_text(
                roles["socket_recovery_dropin"]["content"]
                + "\n[Socket]\nListenStream="
                + str(root / "temporal.sock")
                + "\n",
                "ascii",
            )
            parsed = subprocess.run(
                [
                    "/usr/bin/systemd-analyze",
                    "verify",
                    str(recovery),
                    str(service),
                    str(socket),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
            )
        self.assertEqual(parsed.returncode, 0)

    def test_state_machine_is_fail_closed_and_never_replays_forward_action(self) -> None:
        cases = {
            boot_recovery.RecoveryEvidence(
                "absent", "absent", "absent", "exact", "not_required", "absent"
            ): "no_arm_noop",
            boot_recovery.RecoveryEvidence(
                "valid", "valid", "absent", "exact", "not_required", "absent"
            ): "disarmed_noop",
            boot_recovery.RecoveryEvidence(
                "valid", "absent", "valid", "not_exact", "not_required", "absent"
            ): "accepted_preserved",
            boot_recovery.RecoveryEvidence(
                "valid", "absent", "absent", "exact", "not_required", "absent"
            ): "predecessor_already_exact",
            boot_recovery.RecoveryEvidence(
                "valid", "absent", "absent", "not_exact", "valid", "absent"
            ): "convergence_required",
            boot_recovery.RecoveryEvidence(
                "valid", "absent", "absent", "not_exact", "valid", "converged"
            ): "converged_predecessor",
            boot_recovery.RecoveryEvidence(
                "valid", "absent", "invalid", "not_exact", "valid", "absent"
            ): "blocked_invalid_authority",
            boot_recovery.RecoveryEvidence(
                "valid", "absent", "absent", "not_exact", "invalid", "absent"
            ): "blocked_invalid_authority",
            boot_recovery.RecoveryEvidence(
                "valid", "absent", "absent", "not_exact", "valid", "failed"
            ): "blocked_convergence_failed",
        }
        for evidence, expected in cases.items():
            with self.subTest(expected=expected):
                self.assertEqual(boot_recovery.classify_recovery(evidence), expected)

    def test_closure_arm_owner_terminal_and_disarm_are_single_plan_bound(self) -> None:
        contract, plan, base = _world(self)
        execution = plan["execution"]
        closure = boot_recovery.build_closure(
            contract,
            plan,
            runtime_inventory_digest=execution["target_inventory_digest"],
            runtime_directories_digest=execution["target_directories_digest"],
            unit_state=_recovery_unit_state(contract),
        )
        claim = contract_v1.build_strategy_launch_claim(
            contract,
            entry_nonce=plan["sequence_identity"],
            root=str(execution["root"]),
            backend="synthetic",
            target_source_path=execution["target_source_path"],
            target_inventory_digest=execution["target_inventory_digest"],
            target_directories_digest=execution["target_directories_digest"],
            acceptance_scope_digest=execution["acceptance_scope_digest"],
            prestate_identity=plan["prestate_identity"],
        )
        backup_body = {
            "schema": contract_v1.OPAQUE_BACKUP_SCHEMA,
            "plan_digest": plan["plan_digest"],
            "content_bytes_read": True,
            "content_parsed": False,
            "rows": [],
        }
        backup = {
            **backup_body,
            "backup_digest": contract_v1.digest_value(backup_body),
        }
        arm = boot_recovery.build_arm(
            contract,
            plan,
            launch_claim=claim,
            backup_manifest=backup,
            closure=closure,
            journal_digest="c" * 64,
            boot_identity_digest="e" * 64,
        )
        owner = boot_recovery.build_owner(
            contract,
            arm,
            boot_identity_digest="d" * 64,
            monotonic_start_ns=1_000_000,
            initial_invocation_id="1" * 32,
        )
        terminal = boot_recovery.build_terminal(
            contract,
            arm,
            owner,
            state="accepted_preserved",
            convergence_count=0,
            forward_history_restored=False,
        )
        disarm = boot_recovery.build_disarm(contract, arm, terminal, owner)
        self.assertEqual(disarm["arm_digest"], arm["arm_digest"])
        self.assertEqual(disarm["terminal_digest"], terminal["terminal_digest"])
        self.assertTrue(disarm["product_start_authorized"])
        self.assertEqual(
            owner["monotonic_deadline_ns"] - owner["monotonic_start_ns"],
            900 * 1_000_000_000,
        )
        self.assertFalse(terminal["forward_action_replayed"])
        self.assertFalse(terminal["acceptance_replayed"])
        del base

    def test_mixed_stale_and_substituted_bindings_fail_closed(self) -> None:
        contract, plan, _ = _world(self)
        execution = plan["execution"]
        closure = boot_recovery.build_closure(
            contract,
            plan,
            runtime_inventory_digest=execution["target_inventory_digest"],
            runtime_directories_digest=execution["target_directories_digest"],
            unit_state=_recovery_unit_state(contract),
        )
        for mutation in (
            lambda value: value.update(runtime_inventory_digest="0" * 64),
            lambda value: value.update(plan_digest="0" * 64),
            lambda value: value.update(extra=True),
            lambda value: value["artifacts"].append({"raw": "tainted"}),
        ):
            candidate = json.loads(contract_v1.canonical_bytes(closure))
            mutation(candidate)
            with self.subTest(candidate=sorted(candidate)):
                with self.assertRaises(boot_recovery.BootRecoveryError):
                    boot_recovery.validate_closure(contract, plan, candidate)


class BootRecoveryExecutionTests(unittest.TestCase):
    def test_systemd_recovery_unit_projection_is_exact_and_source_bound(self) -> None:
        contract, plan, _ = _world(self)
        selected = json.loads(contract_v1.canonical_bytes(plan))
        selected["execution"]["backend"] = "systemd"
        expected = contract["production_adapter"]["boot_recovery"]["unit_runtime"]
        argv = expected["exec_start_argv"]
        fields = {
            "ActiveState": expected["active_state"],
            "After": " ".join(expected["dependencies"]["After"]),
            "Before": " ".join(expected["dependencies"]["Before"]),
            "Conflicts": " ".join(expected["dependencies"]["Conflicts"]),
            "ControlGroup": expected["control_group"],
            "DropInPaths": "",
            "ExecMainCode": str(expected["exec_main_code"]),
            "ExecMainStatus": str(expected["exec_main_status"]),
            "ExecStart": (
                "{ path="
                + argv[0]
                + " ; argv[]="
                + " ".join(argv)
                + " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; "
                "pid=0 ; code=exited ; status=0/0 }"
            ),
            "FragmentPath": expected["fragment_path"],
            "InvocationID": "a" * 32,
            "LoadState": expected["load_state"],
            "MainPID": str(expected["main_pid"]),
            "NRestarts": str(expected["n_restarts"]),
            "RestartMode": expected["restart_mode"],
            "Requires": " ".join(expected["dependencies"]["Requires"]),
            "Result": expected["result"],
            "SubState": expected["sub_state"],
            "UnitFileState": expected["unit_file_state"],
        }
        fields.update(
            {
                name: " ".join(expected["dependencies"][name])
                for name in contract["systemd_authority"]["dependency_properties"]
            }
        )
        with (
            patch.object(adapter, "_systemctl_show", return_value=fields),
            patch.object(adapter.launcher_v1, "boot_identity_digest", return_value="b" * 64),
        ):
            observed = adapter._recovery_unit_state(contract, selected)
        self.assertEqual(observed["invocation_id"], "a" * 32)
        self.assertEqual(observed["boot_identity_digest"], "b" * 64)
        self.assertEqual(
            {key: observed[key] for key in expected},
            expected,
        )
        for key, replacement in (
            ("UnitFileState", "disabled"),
            ("FragmentPath", "/tmp/substituted.service"),
            ("ControlGroup", "/system.slice/other.service"),
            ("After", "local-fs.target external.service"),
            ("RestartMode", "normal"),
            ("InvocationID", "z" * 32),
        ):
            candidate = dict(fields)
            candidate[key] = replacement
            with self.subTest(key=key), patch.object(
                adapter, "_systemctl_show", return_value=candidate
            ), patch.object(
                adapter.launcher_v1,
                "boot_identity_digest",
                return_value="b" * 64,
            ):
                with self.assertRaises(adapter.AdapterError):
                    adapter._recovery_unit_state(contract, selected)

    def test_running_recovery_manager_identity_and_restart_generation_are_exact(self) -> None:
        contract, plan, _ = _world(self)
        selected = json.loads(contract_v1.canonical_bytes(plan))
        selected["execution"]["backend"] = "systemd"
        recovery = contract["production_adapter"]["boot_recovery"]
        for artifact_role in ("recovery_unit", "recovery_enablement"):
            artifact = next(
                row for row in recovery["artifacts"] if row["role"] == artifact_role
            )
            adapter._materialize_recovery_artifact(selected["execution"], artifact)
        expected = recovery[
            "manager_entry_runtime"
        ]
        expected_dependencies = expected["base_dependencies"]
        argv = expected["exec_start_argv"]
        fields = {
            "ActiveState": expected["active_state"],
            "After": " ".join(expected_dependencies["After"]),
            "Before": " ".join(expected_dependencies["Before"]),
            "Conflicts": " ".join(expected_dependencies["Conflicts"]),
            "ControlGroup": expected["control_group"],
            "DropInPaths": "",
            "ExecMainCode": str(expected["exec_main_code"]),
            "ExecMainStatus": str(expected["exec_main_status"]),
            "ExecStart": (
                "{ path="
                + argv[0]
                + " ; argv[]="
                + " ".join(argv)
                + " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; "
                "pid=123 ; code=(null) ; status=0/0 }"
            ),
            "FragmentPath": expected["fragment_path"],
            "InvocationID": "a" * 32,
            "LoadState": expected["load_state"],
            "MainPID": "123",
            "NRestarts": "1",
            "RestartMode": expected["restart_mode"],
            "Requires": " ".join(expected_dependencies["Requires"]),
            "Result": expected["result"],
            "SubState": expected["sub_state"],
            "UnitFileState": expected["unit_file_state"],
        }
        fields.update(
            {
                name: " ".join(expected_dependencies[name])
                for name in contract["systemd_authority"]["dependency_properties"]
            }
        )
        with patch.object(adapter, "_systemctl_show", return_value=fields), patch.object(
            adapter.os, "getpid", return_value=123
        ):
            observed = adapter._recovery_unit_entry_state(contract, selected)
        self.assertEqual(observed, {"invocation_id": "a" * 32, "n_restarts": 1})
        for key, replacement in (
            ("ActiveState", "failed"),
            ("ControlGroup", "/system.slice/substituted.service"),
            ("InvocationID", "b" * 31),
            ("MainPID", "124"),
            ("NRestarts", "2"),
            ("Result", "exit-code"),
            ("ExecMainCode", "1"),
            ("After", "local-fs.target external.service"),
            ("RestartMode", "normal"),
        ):
            candidate = dict(fields)
            candidate[key] = replacement
            with self.subTest(key=key), patch.object(
                adapter, "_systemctl_show", return_value=candidate
            ), patch.object(adapter.os, "getpid", return_value=123):
                with self.assertRaises(adapter.AdapterError):
                    adapter._recovery_unit_entry_state(contract, selected)

        # The same manager entrypoint is valid at every exact installation
        # prefix.  Product reverse edges are derived from independently
        # verified drop-in files, never assumed from the target contract.
        for artifact_role, expected_unit in recovery["gate_artifact_units"].items():
            artifact = next(
                row for row in recovery["artifacts"] if row["role"] == artifact_role
            )
            adapter._materialize_recovery_artifact(selected["execution"], artifact)
            gate_fields = dict(fields)
            expected_required_by = sorted(
                str(unit)
                for role, unit in recovery["gate_artifact_units"].items()
                if adapter._recovery_artifact_path(
                    selected["execution"],
                    next(row for row in recovery["artifacts"] if row["role"] == role),
                ).exists()
            )
            gate_fields["RequiredBy"] = " ".join(expected_required_by)
            with patch.object(
                adapter, "_systemctl_show", return_value=gate_fields
            ), patch.object(adapter.os, "getpid", return_value=123):
                observed = adapter._recovery_unit_entry_state(contract, selected)
            self.assertEqual(observed["invocation_id"], "a" * 32)
            self.assertIn(expected_unit, expected_required_by)

    def test_no_arm_obligation_converges_isolated_infrastructure(self) -> None:
        contract, world, base = _world_details(self)
        _prime_recovery(contract, world)
        result = boot_recovery.execute_boot_recovery(
            contract,
            activation_root=base / "world",
            boot_identity_digest="9" * 64,
            monotonic_start_ns=10_000,
        )
        self.assertEqual(result["state"], "converged_predecessor")
        self.assertTrue(result["product_start_authorized"])
        self.assertEqual(result["convergence_count"], 1)
        self.assertFalse(
            adapter._fixed(
                contract, world["plan"]["execution"], "boot_recovery_arm"
            ).exists()
        )
        self.assertEqual(
            adapter._recovery_artifacts_state(
                contract, world["plan"]["execution"]
            ),
            "absent",
        )

    def test_new_boot_without_guardian_discharge_converges_once_and_disarms(
        self,
    ) -> None:
        contract, world, base = _world_details(self)
        result = installed_shadow.run_installed_shadow(
            contract,
            world["plan"],
            contract_path=world["contract_path"],
            plan_path=world["plan_path"],
            deploy_root=ROOT,
        )
        self.assertEqual(result["terminal_status"], "accepted")
        _simulate_reboot(contract, world["plan"])
        recovered = boot_recovery.execute_boot_recovery(
            contract,
            activation_root=base / "world",
            boot_identity_digest="9" * 64,
            monotonic_start_ns=20_000,
        )
        self.assertEqual(recovered["state"], "converged_predecessor")
        self.assertEqual(recovered["convergence_count"], 1)
        self.assertTrue(recovered["product_start_authorized"])
        self.assertTrue(
            adapter._boot_product_exact(
                contract,
                world["plan"],
                final_state="predecessor",
                allow_active=False,
            )
        )
        replay = boot_recovery.execute_boot_recovery(
            contract,
            activation_root=base / "world",
            boot_identity_digest="8" * 64,
            monotonic_start_ns=30_000,
        )
        self.assertEqual(replay["state"], "disarmed_noop")
        self.assertEqual(replay["convergence_count"], 1)

    def test_exact_accepted_authority_preserves_target_without_convergence(
        self,
    ) -> None:
        contract, world, base = _world_details(self)
        result = installed_shadow.run_installed_shadow(
            contract,
            world["plan"],
            contract_path=world["contract_path"],
            plan_path=world["plan_path"],
            deploy_root=ROOT,
        )
        self.assertEqual(result["terminal_status"], "accepted")
        _simulate_reboot(contract, world["plan"])
        with patch.object(boot_recovery, "_guardian_accepted_exact", return_value=True):
            recovered = boot_recovery.execute_boot_recovery(
                contract,
                activation_root=base / "world",
                boot_identity_digest="7" * 64,
                monotonic_start_ns=40_000,
            )
        self.assertEqual(recovered["state"], "accepted_preserved")
        self.assertEqual(recovered["convergence_count"], 0)
        self.assertTrue(
            adapter._boot_product_exact(
                contract,
                world["plan"],
                final_state="target",
                allow_active=False,
            )
        )

    def test_invalid_backup_keeps_boot_gate_blocked_without_disarm(self) -> None:
        contract, world, base = _world_details(self)
        installed_shadow.run_installed_shadow(
            contract,
            world["plan"],
            contract_path=world["contract_path"],
            plan_path=world["plan_path"],
            deploy_root=ROOT,
        )
        _simulate_reboot(contract, world["plan"])
        backup = (
            adapter.incident_root(contract, world["plan"])
            / "BACKUP"
            / "OPAQUE.json"
        )
        backup.write_bytes(b"{}")
        with self.assertRaises(boot_recovery.BootRecoveryError):
            boot_recovery.execute_boot_recovery(
                contract,
                activation_root=base / "world",
                boot_identity_digest="6" * 64,
                monotonic_start_ns=50_000,
            )
        self.assertFalse(
            adapter._fixed(
                contract, world["plan"]["execution"], "boot_recovery_disarm"
            ).exists()
        )
        state = adapter._unit_state(contract, world["plan"])
        self.assertFalse(state["service_active"])
        self.assertFalse(state["socket_active"])

    def test_partial_or_substituted_persistent_closure_keeps_units_blocked(self) -> None:
        for mutation in ("missing_closure", "substituted_dropin"):
            with self.subTest(mutation=mutation):
                contract, world, base = _world_details(self)
                installed_shadow.run_installed_shadow(
                    contract,
                    world["plan"],
                    contract_path=world["contract_path"],
                    plan_path=world["plan_path"],
                    deploy_root=ROOT,
                )
                _simulate_reboot(contract, world["plan"])
                if mutation == "missing_closure":
                    adapter._recovery_closure_path(contract, world["plan"]).unlink()
                else:
                    dropin = adapter._fixed(
                        contract,
                        world["plan"]["execution"],
                        "service_recovery_dropin",
                    )
                    dropin.write_bytes(b"[Unit]\nAfter=external.service\n")
                with self.assertRaises(
                    (boot_recovery.BootRecoveryError, adapter.AdapterError)
                ):
                    boot_recovery.execute_boot_recovery(
                        contract,
                        activation_root=base / "world",
                        boot_identity_digest="2" * 64,
                        monotonic_start_ns=60_000,
                    )
                state = adapter._read_json(
                    adapter._fixed(
                        contract,
                        world["plan"]["execution"],
                        "synthetic_unit_state",
                    )
                )
                self.assertFalse(state["service_active"])
                self.assertFalse(state["socket_active"])
                self.assertFalse(
                    adapter._fixed(
                        contract,
                        world["plan"]["execution"],
                        "boot_recovery_disarm",
                    ).exists()
                )

    def test_forward_state_is_never_restored_backward_during_boot_convergence(self) -> None:
        contract, world, base = _world_details(
            self,
            installed_shadow.InstalledShadowScenario(
                continuity="transition_required",
                transition="committed",
            ),
        )
        result = installed_shadow.run_installed_shadow(
            contract,
            world["plan"],
            contract_path=world["contract_path"],
            plan_path=world["plan_path"],
            deploy_root=ROOT,
        )
        self.assertEqual(result["terminal_status"], "accepted")
        history = (
            base
            / "world/var/lib/myuna-active-temporal-context-v1/synthetic-forward-history"
        )
        self.assertEqual(history.read_bytes(), b"committed\n")
        _simulate_reboot(contract, world["plan"])
        with patch.object(boot_recovery, "_guardian_accepted_exact", return_value=False):
            recovered = boot_recovery.execute_boot_recovery(
                contract,
                activation_root=base / "world",
                boot_identity_digest="1" * 64,
                monotonic_start_ns=70_000,
            )
        self.assertEqual(recovered["state"], "converged_predecessor")
        self.assertEqual(history.read_bytes(), b"committed\n")

    def test_disarm_persistence_failure_is_reboot_safe_and_never_starts_product(self) -> None:
        contract, world, base = _world_details(self)
        installed_shadow.run_installed_shadow(
            contract,
            world["plan"],
            contract_path=world["contract_path"],
            plan_path=world["plan_path"],
            deploy_root=ROOT,
        )
        _simulate_reboot(contract, world["plan"])
        disarm_path = adapter._fixed(
            contract, world["plan"]["execution"], "boot_recovery_disarm"
        )
        original = boot_recovery._persist_json

        def fail_disarm(path: Path, value: object) -> None:
            if path == disarm_path:
                raise boot_recovery.BootRecoveryError(
                    "boot_recovery_disarm_persist_rejected"
                )
            original(path, value)

        with patch.object(boot_recovery, "_persist_json", side_effect=fail_disarm):
            with self.assertRaisesRegex(
                boot_recovery.BootRecoveryError,
                "boot_recovery_disarm_persist_rejected",
            ):
                boot_recovery.execute_boot_recovery(
                    contract,
                    activation_root=base / "world",
                    boot_identity_digest="a" * 64,
                    monotonic_start_ns=80_000,
                )
        self.assertFalse(disarm_path.exists())
        state = adapter._unit_state(contract, world["plan"])
        self.assertFalse(state["service_active"])
        self.assertFalse(state["socket_active"])
        resumed = boot_recovery.execute_boot_recovery(
            contract,
            activation_root=base / "world",
            boot_identity_digest="0" * 64,
            monotonic_start_ns=90_000,
        )
        self.assertTrue(resumed["product_start_authorized"])
        self.assertTrue(disarm_path.is_file())

    def test_existing_owner_without_terminal_rejects_concurrent_recovery(self) -> None:
        contract, world, base = _world_details(self)
        installed_shadow.run_installed_shadow(
            contract,
            world["plan"],
            contract_path=world["contract_path"],
            plan_path=world["plan_path"],
            deploy_root=ROOT,
        )
        _simulate_reboot(contract, world["plan"])
        _, _, arm, _, _, _ = boot_recovery._load_arm_bundle(
            contract, base / "world"
        )
        boot_id = "5" * 64
        owner = boot_recovery.build_owner(
            contract,
            arm,
            boot_identity_digest=boot_id,
            monotonic_start_ns=1,
            initial_invocation_id="1" * 32,
        )
        root = adapter._fixed(
            contract, world["plan"]["execution"], "boot_recovery_boots"
        )
        root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(root.parent, 0o700)
        boot_recovery._private_directory(root, create=True)
        boot_recovery._private_directory(root / boot_id, create=True)
        boot_recovery._persist_json(root / boot_id / "OWNER.json", owner)
        with self.assertRaisesRegex(
            boot_recovery.BootRecoveryError,
            "boot_recovery_concurrent_owner_rejected",
        ):
            boot_recovery.execute_boot_recovery(
                contract,
                activation_root=base / "world",
                boot_identity_digest=boot_id,
                monotonic_start_ns=2,
            )
        self.assertFalse((root / boot_id / "TERMINAL.json").exists())

    def test_exact_second_generation_resumes_same_owner_and_exhausts_replay(self) -> None:
        contract, world, base = _world_details(self)
        installed_shadow.run_installed_shadow(
            contract,
            world["plan"],
            contract_path=world["contract_path"],
            plan_path=world["plan_path"],
            deploy_root=ROOT,
        )
        _simulate_reboot(contract, world["plan"])
        _, _, arm, _, _, _ = boot_recovery._load_arm_bundle(
            contract, base / "world"
        )
        boot_id = "4" * 64
        owner = boot_recovery.build_owner(
            contract,
            arm,
            boot_identity_digest=boot_id,
            monotonic_start_ns=1_000,
            initial_invocation_id="1" * 32,
        )
        root = adapter._fixed(
            contract, world["plan"]["execution"], "boot_recovery_boots"
        )
        root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(root.parent, 0o700)
        boot_recovery._private_directory(root, create=True)
        boot_recovery._private_directory(root / boot_id, create=True)
        boot_recovery._persist_json(root / boot_id / "OWNER.json", owner)
        result = boot_recovery.execute_boot_recovery(
            contract,
            activation_root=base / "world",
            boot_identity_digest=boot_id,
            monotonic_start_ns=2_000,
            manager_invocation_id="2" * 32,
            manager_restart_count=1,
        )
        self.assertIn(
            result["state"],
            {"accepted_preserved", "converged_predecessor"},
        )
        self.assertTrue((root / boot_id / "REENTRY.json").is_file())
        (adapter._fixed(
            contract, world["plan"]["execution"], "boot_recovery_disarm"
        )).unlink()
        with self.assertRaisesRegex(
            boot_recovery.BootRecoveryError,
            "boot_recovery_generation_exhausted",
        ):
            (root / boot_id / "TERMINAL.json").unlink()
            boot_recovery.execute_boot_recovery(
                contract,
                activation_root=base / "world",
                boot_identity_digest=boot_id,
                monotonic_start_ns=3_000,
                manager_invocation_id="3" * 32,
                manager_restart_count=1,
            )

    def test_same_boot_deadline_is_not_reset_by_second_generation(self) -> None:
        contract, world, base = _world_details(self)
        installed_shadow.run_installed_shadow(
            contract,
            world["plan"],
            contract_path=world["contract_path"],
            plan_path=world["plan_path"],
            deploy_root=ROOT,
        )
        _simulate_reboot(contract, world["plan"])
        _, _, arm, _, _, _ = boot_recovery._load_arm_bundle(
            contract, base / "world"
        )
        boot_id = "3" * 64
        owner = boot_recovery.build_owner(
            contract,
            arm,
            boot_identity_digest=boot_id,
            monotonic_start_ns=1_000,
            initial_invocation_id="1" * 32,
        )
        root = adapter._fixed(
            contract, world["plan"]["execution"], "boot_recovery_boots"
        )
        root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(root.parent, 0o700)
        boot_recovery._private_directory(root, create=True)
        boot_recovery._private_directory(root / boot_id, create=True)
        boot_recovery._persist_json(root / boot_id / "OWNER.json", owner)
        with self.assertRaisesRegex(
            boot_recovery.BootRecoveryError,
            "boot_recovery_deadline_exceeded",
        ):
            boot_recovery.execute_boot_recovery(
                contract,
                activation_root=base / "world",
                boot_identity_digest=boot_id,
                monotonic_start_ns=int(owner["monotonic_deadline_ns"]) + 1,
                manager_invocation_id="2" * 32,
                manager_restart_count=1,
            )
        self.assertFalse((root / boot_id / "TERMINAL.json").exists())


if __name__ == "__main__":
    unittest.main()
