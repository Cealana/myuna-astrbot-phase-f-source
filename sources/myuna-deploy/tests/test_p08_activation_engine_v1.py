from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import p08_activation_contract_v1 as contract_v1
import p08_activation_installed_shadow_v1 as installed_shadow
from p08_activation_engine_v1 import ActivationEngine, EngineError
from p08_activation_shadow_v1 import ShadowScenario, run_shadow


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
            "uid": __import__("os").getuid(),
            "gid": __import__("os").getgid(),
            "groups": sorted(set(__import__("os").getgroups())),
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
            "uid": __import__("os").getuid(),
            "gid": __import__("os").getgid(),
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
    inventory = [
        {
            "path": "manifest.json",
            "type": "file",
            "mode": 0o644,
            "uid": __import__("os").getuid(),
            "gid": __import__("os").getgid(),
            "size": 1,
            "sha256": "d" * 64,
        }
    ]
    directories = [
        {
            "path": ".",
            "type": "directory",
            "mode": 0o755,
            "uid": os.getuid(),
            "gid": os.getgid(),
            "nlink": 2,
        }
    ]
    execution = {
        "schema": contract_v1.EXECUTION_SCHEMA,
        "backend": "synthetic",
        "root": "/tmp/p08-activation-test",
        "target_source_path": "/tmp/p08-activation-test/target/" + "c" * 64,
        "target_manifest_sha256": "d" * 64,
        "target_inventory": inventory,
        "target_inventory_digest": contract_v1.digest_value(inventory),
        "target_directories": directories,
        "target_directories_digest": contract_v1.digest_value(directories),
        "public_prestate": public,
        "predecessor_release": contract["compatibility"]["predecessor"],
        "opaque_prestate": opaque,
        "acceptance_scope_digest": "e" * 64,
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
            "gateway_client_sha256": "f" * 64,
            "gateway_manifest_digest": "0" * 64,
            "plugin_digest": "1" * 64,
        },
        "execution_substrate": None,
        "runtime_package": {
            "schema": contract_v1.RUNTIME_PACKAGE_SCHEMA,
            "root": "/tmp/p08-activation-test/target/" + "c" * 64,
            "inventory_digest": contract_v1.digest_value(inventory),
            "directories_digest": contract_v1.digest_value(directories),
            "manifest_sha256": "d" * 64,
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
        sequence_identity="8" * 64,
        invocation_nonce="9" * 64,
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
        target_identity="c" * 64,
        execution=execution,
    )


class ActivationContractTests(unittest.TestCase):
    def test_unit_semantics_reject_wrong_section_duplicate_reset_and_unknown(self) -> None:
        service = (
            ROOT / "systemd/myuna-active-temporal-context-v1.service"
        ).read_bytes()
        socket = (
            ROOT / "systemd/myuna-active-temporal-context-v1.socket"
        ).read_bytes()
        contract_v1.build_unit_semantics(service, socket)
        mutations = {
            "wrong_section": service.replace(
                b"[Service]\nType=exec",
                b"[Service]\n[Unit]\nType=exec",
                1,
            ),
            "duplicate": service.replace(
                b"Type=exec\n",
                b"Type=exec\nType=simple\n",
                1,
            ),
            "reset": service.replace(
                b"Type=exec\n", b"Type=\n", 1
            ),
            "unknown": service.replace(
                b"ExecStart=/usr/bin/setpriv --reuid=976 --regid=976 --clear-groups --no-new-privs /usr/bin/python3 -B -P -S -m p08_temporal_service_v1\n",
                b"ExecStart=/usr/bin/setpriv --reuid=976 --regid=976 --clear-groups --no-new-privs /usr/bin/python3 -B -P -S -m p08_temporal_service_v1\n"
                b"ExecReload=/bin/false\n",
                1,
            ),
        }
        for name, raw in mutations.items():
            with self.subTest(name=name), self.assertRaisesRegex(
                contract_v1.ContractError, "unit_semantics_rejected"
            ):
                contract_v1.parse_unit_semantics(raw, role="service")

    def test_socket_service_semantics_are_single_exact_and_source_bound(self) -> None:
        service = (
            ROOT / "systemd/myuna-active-temporal-context-v1.service"
        ).read_bytes()
        socket = (
            ROOT / "systemd/myuna-active-temporal-context-v1.socket"
        ).read_bytes()
        exact = b"Service=myuna-active-temporal-context-v1.service\n"
        semantics = contract_v1.build_unit_semantics(service, socket)
        runtime = contract_v1.build_unit_runtime(semantics, profile="target")
        self.assertEqual(
            runtime["socket"]["service"],
            "myuna-active-temporal-context-v1.service",
        )
        self.assertEqual(
            runtime["socket"]["dependencies"]["Triggers"],
            [runtime["socket"]["service"]],
        )
        self.assertEqual(
            runtime["service"]["dependencies"]["TriggeredBy"],
            ["myuna-active-temporal-context-v1.socket"],
        )
        mutations = {
            "missing": socket.replace(exact, b"", 1),
            "duplicate": socket.replace(exact, exact + exact, 1),
            "reset": socket.replace(exact, b"Service=\n", 1),
            "malformed": socket.replace(exact, b"Service=../other.service\n", 1),
            "substituted": socket.replace(exact, b"Service=other.service\n", 1),
            "mixed": socket.replace(
                exact,
                b"Service=myuna-active-temporal-context-v1.socket\n",
                1,
            ),
        }
        for name, raw in mutations.items():
            with self.subTest(name=name), self.assertRaises(
                contract_v1.ContractError
            ):
                contract_v1.build_unit_runtime(
                    contract_v1.build_unit_semantics(service, raw),
                    profile="target",
                )

    def test_release_unit_mode_and_public_unit_mode_are_distinct_authorities(self) -> None:
        predecessor = installed_shadow.synthetic_predecessor_binding(
            ROOT,
            release_identity="7" * 64,
            core_commit="1" * 40,
            deploy_commit="2" * 40,
        )
        service = next(
            row
            for row in predecessor["inventory"]
            if row["path"] == "systemd/myuna-active-temporal-context-v1.service"
        )
        self.assertEqual(service["mode"], 0o644)
        self.assertEqual(
            predecessor["public_binding"]["file_identity"]["service_unit"]["mode"],
            0o644,
        )
        # The release inventory is itself source-bound and may be immutable
        # 0444 in a real accepted release; that must not weaken the distinct
        # 0644 public systemd-unit contract.
        immutable_inventory = json.loads(json.dumps(predecessor["inventory"]))
        for row in immutable_inventory:
            if row["path"].startswith("systemd/"):
                row["mode"] = 0o444
        client_roles = predecessor["client_roles"]
        runtime_client = client_roles["roles"]["legacy_runtime_client"]
        status_helper = client_roles["roles"]["status_content_free_helper"]
        status_row = next(
            row
            for row in immutable_inventory
            if row["path"] == status_helper["source_path"]
        )
        manifest = {
            "core_commit": predecessor["core_commit"],
            "deploy_commit": predecessor["deploy_commit"],
            "files": [
                {key: row[key] for key in ("path", "sha256", "size")}
                for row in immutable_inventory
                if row["path"] != "manifest.json"
            ],
            "gateway_client": {
                "runtime_path": status_helper["runtime_path"],
                "sha256": status_helper["sha256"],
                "source_path": status_helper["source_path"],
            },
            "upgrade_compatibility": {
                "active_gateway_client": {
                    "operations": runtime_client["operations"],
                    "schema": runtime_client["protocol_schema"],
                    "sha256": runtime_client["sha256"],
                    "source_path": runtime_client["source_path"],
                },
                "legacy_operation_subset": runtime_client["operations"],
                "predecessor_core_commit": predecessor["core_commit"],
                "predecessor_deploy_commit": predecessor["deploy_commit"],
                "predecessor_release_digest": "9" * 64,
                "schema": "myuna.p08-existing-state-compatibility.v1",
                "status_helper_client": {
                    "operations": status_helper["operations"],
                    "schema": status_helper["protocol_schema"],
                    "sha256": status_helper["sha256"],
                    "source_path": status_helper["source_path"],
                },
                "status_runtime": {
                    "entrypoint": status_helper["source_path"],
                    "files": [
                        {
                            key: status_row[key]
                            for key in ("path", "sha256", "size")
                        }
                    ],
                    "pythonpath": ["src", "scripts"],
                    "schema": "myuna.p08-content-free-status-runtime-closure.v1",
                },
            },
        }
        rebuilt = contract_v1.build_predecessor_binding(
            release_identity=predecessor["release_identity"],
            manifest_sha256=predecessor["manifest_sha256"],
            manifest_size=predecessor["manifest_size"],
            manifest=manifest,
            inventory=immutable_inventory,
            directories=predecessor["directories"],
            unit_semantics=predecessor["unit_semantics"],
        )
        rebuilt_service = next(
            row
            for row in rebuilt["inventory"]
            if row["path"] == "systemd/myuna-active-temporal-context-v1.service"
        )
        self.assertEqual(rebuilt_service["mode"], 0o444)
        self.assertEqual(
            rebuilt["public_binding"]["file_identity"]["service_unit"]["mode"],
            0o644,
        )

    def test_target_uses_numeric_credential_drop_and_predecessor_keeps_names(self) -> None:
        semantics = contract_v1.build_unit_semantics(
            (ROOT / "systemd/myuna-active-temporal-context-v1.service").read_bytes(),
            (ROOT / "systemd/myuna-active-temporal-context-v1.socket").read_bytes(),
        )
        target = contract_v1.build_unit_runtime(semantics, profile="target")
        predecessor = _contract()["compatibility"]["predecessor"]["unit_runtime"]
        self.assertEqual(target["service"]["user"], "")
        self.assertEqual(target["service"]["group"], "")
        self.assertEqual(target["service"]["supplementary_groups"], [])
        self.assertEqual(target["socket"]["socket_user"], "976")
        self.assertEqual(target["socket"]["socket_group"], "982")
        self.assertEqual(target["service"]["process_identity"]["groups"], [])
        self.assertEqual(
            target["service"]["credential_launch"]["executable"],
            contract_v1.PRODUCTION_SYSTEMD["credential_drop"],
        )
        self.assertIn("--clear-groups", target["service"]["exec_start_argv"])
        self.assertIn("--no-new-privs", target["service"]["exec_start_argv"])
        self.assertEqual(predecessor["service"]["user"], "myuna_active_temporal")
        self.assertEqual(
            predecessor["socket"]["socket_group"], "myuna-gateway-telegram"
        )

    def test_predecessor_client_roles_are_distinct_manifest_bound_and_fail_closed(self) -> None:
        predecessor = installed_shadow.synthetic_predecessor_binding(
            ROOT,
            release_identity="7" * 64,
        )
        roles = predecessor["client_roles"]["roles"]
        runtime = roles["legacy_runtime_client"]
        helper = roles["status_content_free_helper"]
        self.assertEqual(
            predecessor["public_binding"]["selector"]["gateway_client_sha256"],
            runtime["sha256"],
        )
        self.assertNotEqual(runtime["sha256"], helper["sha256"])
        self.assertEqual(
            runtime["operations"], list(contract_v1.PREDECESSOR_RUNTIME_OPERATIONS)
        )
        self.assertEqual(
            helper["operations"], list(contract_v1.PREDECESSOR_STATUS_OPERATIONS)
        )

        def resign(candidate: dict[str, object]) -> dict[str, object]:
            client_roles = candidate["client_roles"]
            client_roles["role_digest"] = contract_v1.digest_value(
                {
                    key: value
                    for key, value in client_roles.items()
                    if key != "role_digest"
                }
            )
            candidate["source_lineage_digest"] = contract_v1.digest_value(
                {
                    key: value
                    for key, value in candidate.items()
                    if key != "source_lineage_digest"
                }
            )
            return candidate

        cases: dict[str, dict[str, object]] = {}
        missing = json.loads(json.dumps(predecessor))
        del missing["client_roles"]["roles"]["status_content_free_helper"]
        cases["missing"] = missing
        swapped = json.loads(json.dumps(predecessor))
        swapped_roles = swapped["client_roles"]["roles"]
        swapped_roles["legacy_runtime_client"], swapped_roles[
            "status_content_free_helper"
        ] = (
            swapped_roles["status_content_free_helper"],
            swapped_roles["legacy_runtime_client"],
        )
        cases["swapped"] = swapped
        duplicate = json.loads(json.dumps(predecessor))
        duplicate["client_roles"]["roles"]["status_content_free_helper"][
            "sha256"
        ] = runtime["sha256"]
        cases["duplicate"] = duplicate
        stale = json.loads(json.dumps(predecessor))
        stale["client_roles"]["roles"]["status_content_free_helper"][
            "sha256"
        ] = "f" * 64
        cases["stale"] = stale
        mixed = json.loads(json.dumps(predecessor))
        mixed["client_roles"]["lineage"]["selected_manifest_sha256"] = "e" * 64
        cases["mixed"] = mixed
        replay = json.loads(json.dumps(predecessor))
        replay["client_roles"]["selector_role"] = "status_content_free_helper"
        cases["replay"] = replay
        extra = json.loads(json.dumps(predecessor))
        extra["client_roles"]["roles"]["legacy_runtime_client"]["raw"] = False
        cases["extra"] = extra
        wrong_path = json.loads(json.dumps(predecessor))
        wrong_path["client_roles"]["roles"]["legacy_runtime_client"][
            "source_path"
        ] = "../substituted.py"
        cases["wrong_path"] = wrong_path
        for name, candidate in cases.items():
            with self.subTest(name=name), self.assertRaises(
                contract_v1.ContractError
            ):
                contract_v1._predecessor_release(resign(candidate))

    def test_socket_only_enablement_and_accept_no_coupled_states_are_exact(self) -> None:
        contract = _contract()
        runtime = contract["compatibility"]["predecessor"]["unit_runtime"]
        self.assertEqual(
            runtime["enablement_policy"], contract_v1._unit_enablement_policy()
        )
        self.assertFalse(runtime["enablement_policy"]["service"]["enabled"])
        self.assertTrue(runtime["enablement_policy"]["socket"]["enabled"])
        self.assertFalse(runtime["coupled_state_machine"]["accept"])
        running = _plan(contract)["execution"]["unit_prestate"]
        self.assertEqual(
            contract_v1._unit_state(running, expected_runtime=runtime)[
                "coupled_state"
            ],
            "service_running",
        )
        waiting = json.loads(json.dumps(running))
        waiting["service_active"] = False
        waiting["service_main_pid"] = 0
        waiting["service_process"] = None
        waiting["effective"]["service"]["active_state"] = "inactive"
        waiting["effective"]["service"]["sub_state"] = "dead"
        waiting["effective"]["socket"]["sub_state"] = "listening"
        waiting["coupled_state"] = "socket_waiting"
        self.assertEqual(
            contract_v1._unit_snapshot(waiting, expected_runtime=runtime)[
                "coupled_state"
            ],
            "socket_waiting",
        )
        with self.assertRaises(contract_v1.ContractError):
            contract_v1._unit_state(waiting, expected_runtime=runtime)
        stopped = json.loads(json.dumps(waiting))
        stopped["socket_active"] = False
        stopped["socket_inode"] = None
        stopped["effective"]["socket"]["active_state"] = "inactive"
        stopped["effective"]["socket"]["sub_state"] = "dead"
        stopped["coupled_state"] = "stopped"
        contract_v1._unit_snapshot(stopped, expected_runtime=runtime)
        negatives = {}
        service_enabled = json.loads(json.dumps(running))
        service_enabled["service_enabled"] = True
        negatives["service_enabled"] = service_enabled
        socket_disabled = json.loads(json.dumps(running))
        socket_disabled["socket_enabled"] = False
        negatives["socket_disabled"] = socket_disabled
        listening_while_running = json.loads(json.dumps(running))
        listening_while_running["effective"]["socket"]["sub_state"] = "listening"
        negatives["listening_while_running"] = listening_while_running
        running_without_service = json.loads(json.dumps(waiting))
        running_without_service["effective"]["socket"]["sub_state"] = "running"
        negatives["running_without_service"] = running_without_service
        for name, candidate in negatives.items():
            with self.subTest(name=name), self.assertRaises(
                contract_v1.ContractError
            ):
                contract_v1._unit_snapshot(candidate, expected_runtime=runtime)

    def test_systemd255_unit_name_and_effective_model_are_independent(self) -> None:
        contract = _contract()
        authority = contract["systemd_authority"]["effective_unit_model"]
        predecessor = contract["compatibility"]["predecessor"]["unit_runtime"]
        self.assertTrue(contract_v1.is_safe_unit_name("-.mount"))
        for malformed in ("-foo.mount", "--.mount", "-", ".mount"):
            with self.subTest(malformed=malformed):
                self.assertFalse(contract_v1.is_safe_unit_name(malformed))
        self.assertEqual(authority["systemd_version_identity"], "systemd-255")
        self.assertEqual(authority["mount_authority"]["root_unit"], "-.mount")
        self.assertFalse(authority["source_install_is_runtime_reverse_dependency"])
        self.assertEqual(
            predecessor["source_install"]["service"],
            {"WantedBy": ["multi-user.target"]},
        )
        self.assertEqual(predecessor["service"]["dependencies"]["WantedBy"], [])
        self.assertEqual(predecessor["service"]["set_login_environment"], "no")
        self.assertIn("-.mount", predecessor["service"]["dependencies"]["After"])
        self.assertIn("-.mount", predecessor["socket"]["dependencies"]["After"])

    def test_compilation_and_plan_are_byte_deterministic(self) -> None:
        first = _contract()
        second = _contract()
        self.assertEqual(contract_v1.canonical_bytes(first), contract_v1.canonical_bytes(second))
        first_plan = _plan(first)
        second_plan = _plan(second)
        self.assertEqual(
            contract_v1.canonical_bytes(first_plan),
            contract_v1.canonical_bytes(second_plan),
        )
        self.assertEqual(
            first_plan["plan_digest"],
            second_plan["plan_digest"],
        )

    def test_contract_is_the_single_role_and_schema_authority(self) -> None:
        contract = _contract()
        self.assertEqual(set(contract["roles"]), set(contract_v1.ROLE_ORDER))
        reparsed = json.loads(contract_v1.canonical_bytes(contract))
        self.assertEqual(
            contract_v1.validate_contract(reparsed)["contract_digest"],
            contract["contract_digest"],
        )
        self.assertEqual(
            contract["schemas"],
            {
                "account_projection": contract_v1.ACCOUNT_PROJECTION_SCHEMA,
                "boot_recovery_arm": contract_v1.BOOT_RECOVERY_ARM_SCHEMA,
                "boot_recovery_closure": contract_v1.BOOT_RECOVERY_CLOSURE_SCHEMA,
                "boot_recovery_contract": contract_v1.BOOT_RECOVERY_CONTRACT_SCHEMA,
                "boot_recovery_disarm": contract_v1.BOOT_RECOVERY_DISARM_SCHEMA,
                "boot_recovery_entry": contract_v1.BOOT_RECOVERY_ENTRY_SCHEMA,
                "boot_recovery_owner": contract_v1.BOOT_RECOVERY_OWNER_SCHEMA,
                "boot_recovery_reentry": contract_v1.BOOT_RECOVERY_REENTRY_SCHEMA,
                "boot_recovery_state_machine": contract_v1.BOOT_RECOVERY_STATE_MACHINE_SCHEMA,
                "boot_recovery_terminal": contract_v1.BOOT_RECOVERY_TERMINAL_SCHEMA,
                "boot_recovery_transaction": contract_v1.BOOT_RECOVERY_TRANSACTION_SCHEMA,
                "boot_recovery_unit_state": contract_v1.BOOT_RECOVERY_UNIT_STATE_SCHEMA,
                "recovery_infrastructure_model": contract_v1.RECOVERY_INFRASTRUCTURE_MODEL_SCHEMA,
                "recovery_infrastructure_obligation": contract_v1.RECOVERY_INFRASTRUCTURE_OBLIGATION_SCHEMA,
                "recovery_infrastructure_intent": contract_v1.RECOVERY_INFRASTRUCTURE_INTENT_SCHEMA,
                "recovery_infrastructure_event": contract_v1.RECOVERY_INFRASTRUCTURE_EVENT_SCHEMA,
                "recovery_infrastructure_convergence": contract_v1.RECOVERY_INFRASTRUCTURE_CONVERGENCE_SCHEMA,
                "recovery_residue_normalization_plan": contract_v1.RECOVERY_RESIDUE_NORMALIZATION_PLAN_SCHEMA,
                "capture": contract_v1.CAPTURE_SCHEMA,
                "contract": contract_v1.CONTRACT_SCHEMA,
                "evidence": contract_v1.EVIDENCE_SCHEMA,
                "execution": contract_v1.EXECUTION_SCHEMA,
                "execution_substrate": contract_v1.EXECUTION_SUBSTRATE_SCHEMA,
                "systemd_effective_unit_model": contract_v1.SYSTEMD_EFFECTIVE_UNIT_MODEL_SCHEMA,
                "invocation": contract_v1.INVOCATION_SCHEMA,
                "journal": contract_v1.JOURNAL_SCHEMA,
                "ledger": contract_v1.LEDGER_SCHEMA,
                "opaque_backup": contract_v1.OPAQUE_BACKUP_SCHEMA,
                "predecessor_client_roles": contract_v1.PREDECESSOR_CLIENT_ROLES_SCHEMA,
                "predecessor_release": contract_v1.PREDECESSOR_RELEASE_SCHEMA,
                "process_identity": contract_v1.PROCESS_IDENTITY_SCHEMA,
                "numeric_credential_launch": contract_v1.NUMERIC_CREDENTIAL_LAUNCH_SCHEMA,
                "plan": contract_v1.PLAN_SCHEMA,
                "progress": contract_v1.PROGRESS_SCHEMA,
                "result": contract_v1.RESULT_SCHEMA,
                "runtime_package": contract_v1.RUNTIME_PACKAGE_SCHEMA,
                "continuity_binding": contract_v1.CONTINUITY_BINDING_SCHEMA,
                "unit_receipt": contract_v1.UNIT_RECEIPT_SCHEMA,
                "acceptance_receipt": contract_v1.ACCEPTANCE_RECEIPT_SCHEMA,
                "supervisor_receipt": contract_v1.SUPERVISOR_RECEIPT_SCHEMA,
                "role_intent": contract_v1.ROLE_INTENT_SCHEMA,
                "socket_inode": contract_v1.SOCKET_INODE_SCHEMA,
                "supervisor_bootstrap": contract_v1.SUPERVISOR_BOOTSTRAP_SCHEMA,
                "supervisor_bootstrap_capture": contract_v1.SUPERVISOR_BOOTSTRAP_CAPTURE_SCHEMA,
                "supervisor_bootstrap_intent": contract_v1.SUPERVISOR_BOOTSTRAP_INTENT_SCHEMA,
                "top_level_entry": contract_v1.TOP_LEVEL_ENTRY_SCHEMA,
                "top_level_entry_intent": contract_v1.TOP_LEVEL_ENTRY_INTENT_SCHEMA,
                "top_level_entry_capture": contract_v1.TOP_LEVEL_ENTRY_CAPTURE_SCHEMA,
                "top_level_entry_result": contract_v1.TOP_LEVEL_ENTRY_RESULT_SCHEMA,
                "windows_wsl_transport": contract_v1.WINDOWS_WSL_TRANSPORT_SCHEMA,
                "windows_wsl_capture": contract_v1.WINDOWS_WSL_CAPTURE_SCHEMA,
                "windows_wsl_capture_persist_result": contract_v1.WINDOWS_WSL_CAPTURE_PERSIST_RESULT_SCHEMA,
                "windows_host_launcher": contract_v1.WINDOWS_HOST_LAUNCHER_SCHEMA,
                "supervisor_outer_terminal": contract_v1.SUPERVISOR_OUTER_TERMINAL_SCHEMA,
                "supervisor_guardian_obligation": contract_v1.SUPERVISOR_GUARDIAN_OBLIGATION_SCHEMA,
                "supervisor_guardian_manager_intent": contract_v1.SUPERVISOR_GUARDIAN_MANAGER_INTENT_SCHEMA,
                "supervisor_guardian_transient": contract_v1.SUPERVISOR_GUARDIAN_TRANSIENT_SCHEMA,
                "supervisor_guardian_transient_submission": contract_v1.SUPERVISOR_GUARDIAN_TRANSIENT_SUBMISSION_SCHEMA,
                "supervisor_guardian_generation": contract_v1.SUPERVISOR_GUARDIAN_GENERATION_SCHEMA,
                "supervisor_guardian_child": contract_v1.SUPERVISOR_GUARDIAN_CHILD_SCHEMA,
                "supervisor_guardian_terminal": contract_v1.SUPERVISOR_GUARDIAN_TERMINAL_SCHEMA,
                "supervisor_guardian_discharge": contract_v1.SUPERVISOR_GUARDIAN_DISCHARGE_SCHEMA,
                "supervisor_strategy_launch_claim": contract_v1.SUPERVISOR_STRATEGY_LAUNCH_CLAIM_SCHEMA,
                "supervisor_strategy_launch_terminal": contract_v1.SUPERVISOR_STRATEGY_LAUNCH_TERMINAL_SCHEMA,
                "supervisor_strategy_launch_premutation_terminal": contract_v1.SUPERVISOR_STRATEGY_LAUNCH_PREMUTATION_TERMINAL_SCHEMA,
                "supervisor_failure": contract_v1.SUPERVISOR_FAILURE_SCHEMA,
                "supervisor_entry": contract_v1.SUPERVISOR_ENTRY_SCHEMA,
                "supervisor_preclaim_result": contract_v1.SUPERVISOR_PRECLAIM_RESULT_SCHEMA,
                "selector": contract_v1.SELECTOR_SCHEMA,
                "shadow": contract_v1.SHADOW_SCHEMA,
                "state_machine": contract_v1.STATE_MACHINE_SCHEMA,
                "unit_state": contract_v1.UNIT_STATE_SCHEMA,
                "unit_semantics": contract_v1.UNIT_SEMANTICS_SCHEMA,
                "unit_runtime": contract_v1.UNIT_RUNTIME_SCHEMA,
                "unit_enablement_policy": contract_v1.UNIT_ENABLEMENT_POLICY_SCHEMA,
                "unit_coupled_state": contract_v1.UNIT_COUPLED_STATE_SCHEMA,
            },
        )
        self.assertTrue(contract["continuity"]["no_transition_is_success"])
        self.assertTrue(
            contract["continuity"]["ambiguous_requires_same_action_reconcile"]
        )
        self.assertFalse(contract["continuity"]["postcommit_restores_old_history"])
        preclaim = contract["launcher"]["top_level_entry"]["preclaim"]
        self.assertEqual(
            [row["phase"] for row in preclaim["ordered_phases"]],
            [phase for phase, _categories in contract_v1.PRECLAIM_PHASE_DEFINITIONS],
        )
        self.assertEqual(
            preclaim["phase_map_digest"],
            contract_v1.digest_value(preclaim["ordered_phases"]),
        )
        self.assertEqual(preclaim["product_mutation_state"], "unmodified")
        tampered = json.loads(contract_v1.canonical_bytes(contract))
        tampered["launcher"]["top_level_entry"]["preclaim"]["ordered_phases"][
            0
        ]["phase"] = "substituted"
        unsigned = {
            key: value for key, value in tampered.items() if key != "contract_digest"
        }
        tampered["contract_digest"] = contract_v1.digest_value(unsigned)
        with self.assertRaisesRegex(
            contract_v1.ContractError, "contract_launcher_rejected"
        ):
            contract_v1.validate_contract(tampered)

    def test_legacy_failure_accounting_is_not_reset(self) -> None:
        lineage = _contract()["lineage"]
        self.assertEqual(lineage["architecture_reset_failure_counted"], 16)
        self.assertEqual(lineage["architecture_reset_failure_excluded"], 1)
        self.assertEqual(lineage["failure_counted"], 21)
        self.assertEqual(lineage["failure_excluded"], 1)
        self.assertEqual(
            len(lineage["post_reset_counted_terminal_handoff_sha256"]), 5
        )
        self.assertFalse(lineage["old_incidents_resettable"])
        self.assertFalse(lineage["old_sequences_replayable"])

    def test_unknown_contract_key_fails_closed(self) -> None:
        contract = _contract()
        contract["unexpected"] = False
        with self.assertRaises(contract_v1.ContractError):
            contract_v1.validate_contract(contract)

    def test_outer_terminal_projection_is_exact_and_nonretryable(self) -> None:
        contract = _contract()
        body = {
            "schema": contract_v1.SUPERVISOR_OUTER_TERMINAL_SCHEMA,
            "architecture": contract_v1.ARCHITECTURE,
            "contract_digest": contract["contract_digest"],
            "terminal_status": "convergence_failed_hard_stop",
            "stage": "outer_capture_terminalization",
            "product_state": "unknown",
            "entry_nonce": "1" * 64,
            "capture_digest": "2" * 64,
            "plan_digest": "3" * 64,
            "recovery_entry_nonce": "4" * 64,
            "recovery_capture_digest": "5" * 64,
            "recovery_count": 1,
            "orphan_count": 0,
            "raw_output_included": False,
            "retry_authorized": False,
        }
        value = {**body, "terminal_digest": contract_v1.digest_value(body)}
        self.assertEqual(
            contract_v1.validate_supervisor_bootstrap_output(value), value
        )
        variants = []
        extra = json.loads(json.dumps(value))
        extra["raw"] = "forbidden"
        variants.append(extra)
        replayable = json.loads(json.dumps(value))
        replayable["retry_authorized"] = True
        variants.append(replayable)
        mixed = json.loads(json.dumps(value))
        mixed["recovery_count"] = 0
        variants.append(mixed)
        substituted = json.loads(json.dumps(value))
        substituted["capture_digest"] = "6" * 64
        variants.append(substituted)
        for index, variant in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(
                contract_v1.ContractError
            ):
                contract_v1.validate_supervisor_bootstrap_output(variant)

    def test_contract_substitution_fails_closed(self) -> None:
        contract = _contract()
        contract["engine_source"]["deploy_commit"] = "d" * 40
        with self.assertRaises(contract_v1.ContractError):
            contract_v1.validate_contract(contract)

    def test_plan_digest_and_source_binding_fail_closed(self) -> None:
        contract = _contract()
        plan = _plan(contract)
        for key, replacement in (
            ("target_identity", "d" * 64),
            ("contract_digest", "e" * 64),
            ("legacy_lineage_digest", "f" * 64),
            ("plan_digest", "0" * 64),
        ):
            changed = json.loads(json.dumps(plan))
            changed[key] = replacement
            with self.subTest(key=key), self.assertRaises(contract_v1.ContractError):
                contract_v1.validate_plan(contract, changed)

    def test_execution_target_source_leaf_must_be_digest(self) -> None:
        contract = _contract()
        execution = json.loads(json.dumps(_plan(contract)["execution"]))
        execution["target_source_path"] = "/tmp/p08-activation-test/target/not-a-digest"
        with self.assertRaises(contract_v1.ContractError):
            contract_v1.validate_execution(contract, execution)

    def test_result_unknown_missing_and_raw_tainted_fail_closed(self) -> None:
        contract = _contract()
        plan = _plan(contract)
        result = contract_v1.build_result(
            contract,
            plan,
            role="prepare",
            role_call=1,
            status="ready",
            result_class="ready",
            payload={
                "metadata_only": True,
                "opaque_content_read": False,
                "persistent_mutation": False,
            },
            persistent_mutation=False,
        )
        variants = []
        extra = json.loads(json.dumps(result))
        extra["raw"] = "forbidden"
        variants.append(extra)
        missing = json.loads(json.dumps(result))
        del missing["payload"]["opaque_content_read"]
        variants.append(missing)
        raw_tainted = json.loads(json.dumps(result))
        raw_tainted["raw_output_included"] = True
        raw_tainted["result_digest"] = contract_v1.digest_value(
            {key: value for key, value in raw_tainted.items() if key != "result_digest"}
        )
        variants.append(raw_tainted)
        for index, value in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(contract_v1.ContractError):
                contract_v1.validate_result(
                    contract,
                    plan,
                    value,
                    expected_role="prepare",
                    expected_call=1,
                )


class ActivationEngineShadowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = _contract()
        self.plan = _plan(self.contract)

    def test_no_transition_required_is_normal_success(self) -> None:
        result = run_shadow(self.contract, self.plan)
        self.assertEqual(result["terminal_status"], "accepted")
        self.assertEqual(result["selected_identity"], self.plan["target_identity"])
        self.assertEqual(result["transition_state"], "no_transition_required")
        self.assertFalse(result["transition_committed"])
        self.assertEqual(result["trusted_time_history_length"], 1)
        self.assertEqual(result["actions_consumed"], 1)
        self.assertFalse(result["production_mutation"])

    def test_committed_transition_is_preserved_on_success(self) -> None:
        result = run_shadow(
            self.contract, self.plan, ShadowScenario(continuity="committed")
        )
        self.assertEqual(result["terminal_status"], "accepted")
        self.assertTrue(result["transition_committed"])
        self.assertEqual(result["trusted_time_history_length"], 2)
        self.assertFalse(result["trusted_time_history_restored"])

    def test_ambiguous_transition_reconciles_committed_in_same_action(self) -> None:
        result = run_shadow(
            self.contract,
            self.plan,
            ShadowScenario(continuity="ambiguous_committed"),
        )
        self.assertEqual(result["terminal_status"], "accepted")
        self.assertEqual(result["transition_state"], "reconciled_committed")
        self.assertEqual(result["role_counts"]["continuity_reconcile"], 1)
        self.assertEqual(result["actions_consumed"], 1)
        self.assertEqual(result["trusted_time_history_length"], 2)

    def test_ambiguous_not_committed_reconciles_without_replay(self) -> None:
        result = run_shadow(
            self.contract,
            self.plan,
            ShadowScenario(continuity="ambiguous_not_committed"),
        )
        self.assertEqual(result["terminal_status"], "converged_hard_stop")
        self.assertEqual(result["transition_state"], "reconciled_not_committed")
        self.assertNotIn("accept_status", result["role_counts"])
        self.assertEqual(result["selected_identity"], self.plan["predecessor_identity"])
        self.assertEqual(result["trusted_time_history_length"], 1)

    def test_precommit_failures_do_not_run_ceremonial_rollback(self) -> None:
        for role in (
            "construct",
            "prepare",
            "formal1",
            "formal2",
            "exact_two",
            "drift",
            "claim",
            "backup",
            "stage",
            "recovery_install",
        ):
            with self.subTest(role=role):
                result = run_shadow(
                    self.contract, self.plan, ShadowScenario(fault_role=role)
                )
                self.assertEqual(result["terminal_status"], "premutation_hard_stop")
                self.assertNotIn("converge", result["role_counts"])
                self.assertEqual(
                    result["selected_identity"], self.plan["predecessor_identity"]
                )

    def test_installed_recovery_infrastructure_is_converged_before_product(self) -> None:
        for role in ("recovery_arm", "stop_socket"):
            with self.subTest(role=role):
                result = run_shadow(
                    self.contract, self.plan, ShadowScenario(fault_role=role)
                )
                self.assertEqual(result["terminal_status"], "converged_hard_stop")
                self.assertEqual(result["role_counts"]["converge"], 1)
                self.assertEqual(result["role_counts"]["recover"], 1)
                self.assertEqual(
                    result["state_restore_scope"], "recovery_infrastructure_only"
                )
                self.assertFalse(result["infrastructure_mutated"])
                self.assertEqual(result["mutation_scope"], "none")
                self.assertEqual(
                    result["selected_identity"], self.plan["predecessor_identity"]
                )

    def test_every_postmutation_failure_converges_once(self) -> None:
        for role in (
            "stop_service",
            "install",
            "select",
            "start_service",
            "start_socket",
            "continuity_assessment",
            "accept_status",
        ):
            with self.subTest(role=role):
                result = run_shadow(
                    self.contract, self.plan, ShadowScenario(fault_role=role)
                )
                self.assertEqual(result["terminal_status"], "converged_hard_stop")
                self.assertEqual(result["role_counts"]["converge"], 1)
                self.assertEqual(result["role_counts"]["recover"], 1)
                self.assertEqual(
                    result["selected_identity"], self.plan["predecessor_identity"]
                )

    def test_acceptance_failure_after_commit_keeps_forward_history(self) -> None:
        result = run_shadow(
            self.contract,
            self.plan,
            ShadowScenario(continuity="committed", fault_role="accept_status"),
        )
        self.assertEqual(result["terminal_status"], "converged_hard_stop")
        self.assertEqual(result["state_restore_scope"], "code_public_only")
        self.assertEqual(result["trusted_time_history_length"], 2)
        self.assertFalse(result["trusted_time_history_restored"])

    def test_ambiguous_reconcile_failure_never_claims_acceptance(self) -> None:
        result = run_shadow(
            self.contract,
            self.plan,
            ShadowScenario(
                continuity="ambiguous_committed",
                fault_role="continuity_reconcile",
            ),
        )
        self.assertEqual(result["terminal_status"], "converged_hard_stop")
        self.assertNotIn("accept_status", result["role_counts"])
        self.assertEqual(result["role_counts"]["continuity_reconcile"], 1)
        self.assertEqual(result["role_counts"]["converge"], 1)
        self.assertEqual(result["trusted_time_history_length"], 2)
        self.assertFalse(result["trusted_time_history_restored"])

    def test_transition_failure_reconciles_not_committed_then_converges(self) -> None:
        result = run_shadow(
            self.contract,
            self.plan,
            ShadowScenario(continuity="committed", fault_role="continuity_transition"),
        )
        self.assertEqual(result["terminal_status"], "converged_hard_stop")
        self.assertEqual(result["transition_state"], "reconciled_not_committed")
        self.assertEqual(result["role_counts"]["continuity_reconcile"], 1)
        self.assertEqual(result["state_restore_scope"], "p08_state_and_public")
        self.assertEqual(result["trusted_time_history_length"], 1)

    def test_postflight_failure_converges_once(self) -> None:
        result = run_shadow(
            self.contract, self.plan, ShadowScenario(fault_role="postflight")
        )
        self.assertEqual(result["terminal_status"], "converged_hard_stop")
        self.assertEqual(result["role_counts"]["postflight"], 2)
        self.assertEqual(result["role_counts"]["converge"], 1)
        self.assertEqual(result["selected_identity"], self.plan["predecessor_identity"])

    def test_convergence_and_recovery_failure_do_not_retry(self) -> None:
        for role in ("converge", "recover"):
            with self.subTest(role=role):
                result = run_shadow(
                    self.contract,
                    self.plan,
                    ShadowScenario(
                        fault_role="accept_status",
                        fault_kind="crash",
                        convergence_fault=role,
                    ),
                )
                # The selected identity may already be restored for a recover
                # failure, but the bounded operation is never replayed.
                self.assertEqual(result["role_counts"][role], 1)
                self.assertEqual(
                    result["terminal_status"], "convergence_failed_hard_stop"
                )
                self.assertNotIn("postflight", result["role_counts"])

    def test_crash_and_timeout_are_indeterminate_and_never_retried(self) -> None:
        for kind in ("crash", "timeout"):
            with self.subTest(kind=kind):
                result = run_shadow(
                    self.contract,
                    self.plan,
                    ShadowScenario(fault_role="formal1", fault_kind=kind),
                )
                self.assertEqual(result["terminal_status"], "premutation_hard_stop")
                self.assertEqual(result["role_counts"]["formal1"], 1)
                self.assertNotIn("formal2", result["role_counts"])

    def test_indeterminate_first_stop_converges_once(self) -> None:
        result = run_shadow(
            self.contract,
            self.plan,
            ShadowScenario(fault_role="stop_socket", fault_kind="crash"),
        )
        self.assertEqual(result["terminal_status"], "converged_hard_stop")
        self.assertEqual(result["role_counts"]["stop_socket"], 1)
        self.assertEqual(result["role_counts"]["converge"], 1)
        self.assertEqual(result["role_counts"]["recover"], 1)

    def test_permission_inventory_and_identity_drift_fail_closed(self) -> None:
        for scenario in (
            ShadowScenario(public_modes_exact=False),
            ShadowScenario(inventory_exact=False),
            ShadowScenario(identity_exact=False),
        ):
            with self.assertRaises(EngineError):
                run_shadow(self.contract, self.plan, scenario)

    def test_phase_replay_and_out_of_order_are_rejected(self) -> None:
        engine = ActivationEngine(self.contract, self.plan)
        result = contract_v1.build_result(
            self.contract,
            self.plan,
            role="prepare",
            role_call=1,
            status="ready",
            result_class="ready",
            payload={
                "metadata_only": True,
                "opaque_content_read": False,
                "persistent_mutation": False,
            },
            persistent_mutation=False,
        )
        with self.assertRaises(EngineError):
            engine.apply(result)


if __name__ == "__main__":
    unittest.main()
