from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from myuna_core.external_context.contracts import EXTERNAL_PROJECTION_POLICY

import activate_p07_d_generation13_v1 as activation
from p07_d_activation_transaction import _S2_PROGRAM
from p07_d_generation11_release_set import selector_payload as generation11_selector
from p07_d_generation13_release_set import selector_payload as generation13_selector
import telegram_owner_runtime_gateway as runtime_gateway


class Generation13ActivationTests(unittest.TestCase):
    def test_controller_entry_reaches_only_atomic_owner_and_is_not_ready(self) -> None:
        environment = {
            activation.CONTROLLER_RELEASE_ENV: "a" * 64,
            activation.CONTROLLER_CONFIG_ENV: "b" * 64,
            activation.CONTROLLER_AUTHORITY_ENV: "c" * 64,
        }
        with patch.object(
            activation.AtomicReleaseSetTransaction,
            "enter_canonical_owner",
            side_effect=activation.ReleaseSetActivationRejected(
                "phase_f_t2_pair_required"
            ),
        ) as owner, patch.dict(activation.os.environ, environment, clear=False):
            self.assertEqual(activation.controller_entry(), 75)
        owner.assert_called_once_with(
            release_root=Path(activation.__file__).parent,
            selected_release_sha256="a" * 64,
            selected_config_sha256="b" * 64,
            selected_authority_sha256="c" * 64,
            t2_receipts=None,
        )

    def test_legacy_activation_modules_are_absent_from_owner_import_graph(self) -> None:
        source = Path(activation.__file__).read_text("utf-8")
        tree = ast.parse(source)
        imports = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        imports.update(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        )
        self.assertNotIn("activate_p07_hybrid_external_generation_v1", imports)
        self.assertNotIn("activate_p07_external_epoch_rollover_v1", imports)
        self.assertNotIn("p09_v7_phase1_packaging_contract", imports)

    def test_every_alternate_target_guard_dominates_legacy_mutation(self) -> None:
        scripts = Path(activation.__file__).resolve().parent
        cases = (
            ("activate_p07_d_generation7_v1.py", "def activate(", "BACKUP_ROOT.mkdir"),
            ("activate_p07_d_generation8_v1.py", "def activate(", "BACKUP_ROOT.mkdir"),
            ("activate_p07_d_generation9_v1.py", "def activate(", "BACKUP_ROOT.mkdir"),
            ("activate_p07_d_generation10_v1.py", "def activate(", "BACKUP_ROOT.mkdir"),
            ("activate_p07_d_generation11_v1.py", "def activate(", "BACKUP_ROOT.mkdir"),
            ("activate_p07_d_generation12_v1.py", "def activate(", "BACKUP_ROOT.mkdir"),
            ("activate_p08_p07_generation13_v1.py", "def activate_combined(\n", "BACKUP_ROOT.mkdir"),
            ("activate_p06_telegram_recovery_v1.py", "def activate(\n", "_verify_prestate()"),
            (
                "activate_p07_hybrid_external_generation_v1.py",
                "def activate(\n",
                "prestate = verify_prestate()",
            ),
            (
                "activate_p07_owner_private_memory_v1.py",
                "def activate(\n",
                "backend = LiveMemoryBackend",
            ),
            (
                "activate_p07c_telegram_diary_entry_v1.py",
                "def activate(\n",
                "backup, config_bytes, dropin_bytes = backup_prestate",
            ),
            (
                "activate_p07c_telegram_diary_consent_layer_v1.py",
                "def activate(\n",
                "backup, config_bytes = backup_prestate",
            ),
            ("activate_p01b_p16_successor_v1.py", "def activate(\n", "_create_backup(plan)"),
        )
        for relative, entry_marker, mutation_marker in cases:
            with self.subTest(relative=relative):
                source = (scripts / relative).read_text("utf-8")
                entry = source.index(entry_marker)
                guard = source.index("phase_f_canonical_owner_required", entry)
                selector = source.rindex("phase_f_selected_target", entry, guard)
                mutation = source.index(mutation_marker, entry)
                self.assertLess(selector, guard)
                self.assertLess(guard, mutation)
                self.assertNotIn(
                    '== "7ff8f35a3e141674d7111a45dd247069d09d445a"',
                    source[entry:guard],
                )

        unit = scripts.parent / "systemd" / "myuna-telegram-owner-r5-resume.service"
        self.assertIn(
            "ExecStart=/usr/bin/python3 @CONTROLLER_RELEASE_ROOT@/telegram_r5_boot_resume.py",
            unit.read_text("utf-8"),
        )
        for expected in (
            "Environment=MYUNA_PHASE_F_CONTROLLER_RELEASE_SHA256=@CONTROLLER_RELEASE_DIGEST@",
            "Environment=MYUNA_PHASE_F_CONTROLLER_CONFIG_SHA256=@CONTROLLER_CONFIG_SHA256@",
            "Environment=MYUNA_PHASE_F_CONTROLLER_AUTHORITY_SHA256=@CONTROLLER_AUTHORITY_SHA256@",
        ):
            self.assertIn(expected, unit.read_text("utf-8"))

    def test_stage_one_has_no_legacy_effect_or_ledger_surface(self) -> None:
        source = Path(activation.__file__).read_text("utf-8")
        for forbidden in (
            "ATTEMPT_LEDGER",
            "PLAN.json",
            "RECEIPT-",
            "def _consume_attempt",
            "def atomic_write",
            "def install_tree",
            "def systemctl",
            "_retired_activate_source_evidence",
            "_retired_prepare_activation_source_evidence",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

        tree = ast.parse(source)
        backend = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "Generation13LiveBackend"
        )
        methods = {
            node.name for node in backend.body if isinstance(node, ast.FunctionDef)
        }
        required = {"observe_operation", "apply_operation", "observe_compensation", "compensate_operation", "observe_full_old", "observe_forward_old", "apply_forward_old"}
        self.assertTrue(required.issubset(methods))
        self.assertNotIn("run", methods)
        self.assertNotIn("Protocol", source)

    def test_previous_metadata_uses_canonical_schema_v3_projection(self) -> None:
        release_set = type(
            "ReleaseSet",
            (),
            {
                "release_set_id": "a" * 64,
                "epoch": {"uid": 1000, "gid": 1001},
            },
        )()
        runtime_config = type(
            "RuntimeConfig",
            (),
            {
                "channel_kind": "astrbot_telegram",
                "principal_id": "owner",
                "namespace_id": "owner-private",
            },
        )()
        metadata = {
            "schema": "myuna.external-authorized-epoch.v3",
            "selected_revision": 2,
            "max_revision": 2,
            "turn_count": 2,
            "summary_count": 0,
            "pending_count": 0,
            "queued_summary_count": 0,
        }
        with patch.object(
            activation.ExternalEpochV3Store,
            "inspect_existing_metadata",
            return_value=metadata,
        ):
            observed = activation._expected_previous_metadata(
                previous_release_set=release_set,
                runtime_config=runtime_config,
                revision=2,
                turns=2,
                summaries=0,
                pending=0,
            )
            self.assertEqual(observed, metadata)

            wrong = dict(metadata)
            wrong["schema"] = "myuna.external-authorized-epoch.v2"
            with patch.object(
                activation.ExternalEpochV3Store,
                "inspect_existing_metadata",
                return_value=wrong,
            ), self.assertRaisesRegex(
                activation.Generation13ActivationRejected,
                "previous_epoch_metadata_rejected",
            ):
                activation._expected_previous_metadata(
                    previous_release_set=release_set,
                    runtime_config=runtime_config,
                    revision=2,
                    turns=2,
                    summaries=0,
                    pending=0,
                )

    def test_stage_one_has_no_component_state_or_attempt_owner(self) -> None:
        self.assertEqual(activation.GENERATION, 13)
        self.assertFalse(hasattr(activation, "STATE_ROOT"))
        self.assertFalse(hasattr(activation, "BACKUP_ROOT"))
        self.assertFalse(hasattr(activation, "ATTEMPT_LEDGER"))
        selector = generation13_selector("a" * 64)
        self.assertIn("external-d-reset-v7", selector["database_path"])
        self.assertNotEqual(selector["database_path"], activation.PREVIOUS_EPOCH_PATH)

    def test_previous_selector_is_strict_generation11_and_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "selector.json"
            payload = generation11_selector("a" * 64)
            path.write_bytes(activation.canonical(payload))
            path.chmod(0o640)
            with patch.object(activation, "SELECTOR_PATH", path), patch.object(
                activation.grp,
                "getgrnam",
                return_value=type("Group", (), {"gr_gid": path.stat().st_gid})(),
            ):
                raw, loaded = activation._load_previous_selector(
                    expected_uid=os.getuid(),
                    expected_gid=path.stat().st_gid,
                )
                self.assertEqual(raw, activation.canonical(payload))
                self.assertEqual(loaded["generation"], 11)
                wrong = dict(payload)
                wrong["generation"] = 12
                path.write_bytes(activation.canonical(wrong))
                with self.assertRaisesRegex(
                    activation.Generation13ActivationRejected,
                    "previous_selector_rejected",
                ):
                    activation._load_previous_selector(
                        expected_uid=os.getuid(),
                        expected_gid=path.stat().st_gid,
                    )

    def test_standalone_live_activation_requires_combined_coordinator(self) -> None:
        prepared = type(
            "Prepared",
            (),
            {
                "plan_digest": "a" * 64,
                "release_set": type("Release", (), {"release_set_id": "b" * 64})(),
            },
        )()
        with patch.object(activation, "_cross_identity_manifest_smoke"):
            ready = activation.activate(
                prepared,
                expected_plan_sha256=None,
                preflight_only=True,
            )
            self.assertEqual(ready["status"], "TARGET_ARTIFACT_VERIFIED_NOT_READY")
            with self.assertRaisesRegex(
                activation.Generation13ActivationRejected,
                "phase_f_stage2_bundle_required",
            ):
                activation.activate(
                    prepared,
                    expected_plan_sha256="a" * 64,
                    preflight_only=False,
                )

    def test_runtime_and_activator_admit_generation13_without_network_clients(self) -> None:
        source = Path(activation.__file__).read_text("utf-8")
        tree = ast.parse(source)
        self.assertNotIn("requests", source)
        self.assertNotIn("httpx", source)
        self.assertTrue(any(isinstance(node, ast.ClassDef) and node.name == "Generation13LiveBackend" for node in ast.walk(tree)))
        runtime_source = (Path(activation.__file__).with_name("telegram_owner_runtime_gateway.py")).read_text("utf-8")
        self.assertIn(
            "external_epoch_selection.generation in {7, 8, 9, 10, 11, 12, 13}",
            runtime_source,
        )
        selection = runtime_gateway.ExternalEpochSelection.from_payload(
            generation13_selector("a" * 64)
        )
        self.assertEqual(selection.generation, 13)
        self.assertEqual(
            runtime_gateway._EXTERNAL_EPOCH_GENERATIONS[13],
            (
                "telegram-owner-private-external-d-reset-v7",
                "telegram-owner-private-external-d-reset-v5",
            ),
        )
        self.assertNotIn(".generation==11", source)
        self.assertIn("prepared.release_set.release_set_id", source)

    def test_generation13_selector_reaches_fresh_epoch_and_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            epoch_id = "telegram-owner-private-external-d-reset-v7"
            epoch_parent = root / epoch_id
            epoch_parent.mkdir(mode=0o700)
            database_path = epoch_parent / "epoch.db"
            selector_path = root / "selector.json"
            runtime_config_path = root / "runtime-config.json"
            selector_digest = "b" * 64
            release_set_id = "c" * 64
            payload = generation13_selector("a" * 64)
            payload["database_path"] = database_path.as_posix()
            config = runtime_gateway.runtime_config_contract.RuntimeConfig(
                channel_kind="astrbot_telegram",
                binding_id="binding-1",
                principal_id="owner-1",
                namespace_id="owner-private-1",
                finalization_digest="d" * 64,
                evidence_sha256="e" * 64,
                channel_instance="owner-private",
                core_host="127.0.0.1",
                core_port=8080,
                max_requests_per_ten_minutes=10,
                max_history_messages=16,
                max_history_characters=4096,
            )
            config_snapshot = (
                runtime_gateway.runtime_config_contract.ProtectedRuntimeConfigSnapshot(
                    config=config,
                    content_sha256="f" * 64,
                    device=1,
                    inode=2,
                    uid=os.geteuid(),
                    gid=os.getegid(),
                    mode=0o640,
                    size=1,
                )
            )
            binding_digest = runtime_gateway.runtime_binding_digest(
                channel_kind=config.channel_kind,
                client_id=runtime_gateway.CORE_CLIENT_ID,
                principal_id=config.principal_id,
                namespace_id=config.namespace_id,
            )
            release_set = type(
                "SyntheticReleaseSet",
                (),
                {
                    "generation": 13,
                    "projection_policy_version": EXTERNAL_PROJECTION_POLICY,
                    "release_set_id": release_set_id,
                    "selector": {
                        "path": selector_path.as_posix(),
                        "digest": selector_digest,
                        "generation": 13,
                    },
                    "epoch": {
                        "epoch_id": epoch_id,
                        "database_path": database_path.as_posix(),
                        "uid": os.geteuid(),
                        "gid": os.getegid(),
                    },
                    "runtime_config": {
                        "path": runtime_config_path.as_posix(),
                        "digest": config_snapshot.content_sha256,
                        "binding_digest": binding_digest,
                        "channel_kind": config.channel_kind,
                        "principal_id": config.principal_id,
                        "namespace_id": config.namespace_id,
                        "uid": config_snapshot.uid,
                        "gid": config_snapshot.gid,
                        "mode": config_snapshot.mode,
                    },
                },
            )()
            release_snapshot = type(
                "SyntheticReleaseSnapshot",
                (),
                {"release_set": release_set},
            )()
            with patch.object(runtime_gateway, "EXTERNAL_EPOCH_ROOT", root), patch.object(
                runtime_gateway, "EXTERNAL_EPOCH_SELECTOR_PATH", selector_path
            ), patch.object(runtime_gateway, "CONFIG_PATH", runtime_config_path), patch.object(
                runtime_gateway,
                "_load_external_epoch_selection_snapshot",
                return_value=(
                    runtime_gateway.ExternalEpochSelection.from_payload(payload),
                    selector_digest,
                ),
            ), patch.object(
                runtime_gateway,
                "load_protected_release_set_snapshot",
                return_value=release_snapshot,
            ), patch.dict(os.environ, {"INVOCATION_ID": "1" * 32}):
                selection = runtime_gateway.ExternalEpochSelection.from_payload(payload)
                store, _worker = runtime_gateway._release_set_runtime(
                    config_snapshot=config_snapshot,
                    selection=selection,
                    core=object(),
                )
            metadata = store.public_metadata()
            self.assertEqual(metadata["selected_revision"], 0)
            self.assertEqual(metadata["turn_count"], 0)
            self.assertEqual(metadata["summary_count"], 0)
            self.assertEqual(metadata["pending_count"], 0)
            self.assertTrue(database_path.is_file())
            self.assertTrue((epoch_parent / "RUNTIME_READY.json").is_file())

    def test_stage_three_backend_has_no_generic_or_compose_mutation_surface(self) -> None:
        source = Path(activation.__file__).read_text("utf-8")
        tree = ast.parse(source)
        backend = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Generation13LiveBackend")
        backend_source = ast.get_source_segment(source, backend) or ""
        self.assertNotIn("ReleaseSetActivationBackend", backend_source)
        self.assertNotIn("compose up", backend_source)
        self.assertNotIn("compose stop", backend_source)
        self.assertNotIn("docker network create", backend_source)
        self.assertNotIn("docker network rm", backend_source)
        self.assertNotIn("getattr(", backend_source)
        self.assertNotIn("unit_forward = {", backend_source)
        self.assertNotIn("file_mapping = {", backend_source)

    def test_actual_backend_dispatch_owns_every_fixed_mutation_slot(self) -> None:
        backend = object.__new__(activation.Generation13LiveBackend)
        backend.prepared = SimpleNamespace(plan_digest="1" * 64)
        backend._runner = Mock()
        backend._writer = Mock()
        backend.expected_network = SimpleNamespace()
        backend.old_container = SimpleNamespace(container_id="old")
        backend.target_container = SimpleNamespace(archive_name="archive")
        backend._target_observation = SimpleNamespace(container_id="target")
        backend._file_contract = lambda operation: (SimpleNamespace(path=Path(f"/{operation}")), operation.encode("ascii"))
        backend.observe_operation = lambda _operation: "DESIRED"
        backend._apply_unit = Mock()
        archived = SimpleNamespace(container_id="old")
        target = SimpleNamespace(container_id="target")
        with patch.object(activation, "_phase_f_atomic_publish") as publish, patch.object(
            activation, "_run", return_value=""
        ) as systemd, patch.object(
            activation.r5_resume, "phase_f_stop_container_exact", return_value=archived
        ) as stop, patch.object(
            activation.r5_resume, "phase_f_rename_container_exact", return_value=archived
        ) as rename, patch.object(
            activation.r5_resume, "phase_f_container_projection", return_value=archived
        ), patch.object(
            activation.r5_resume, "phase_f_create_target_stopped", return_value=target
        ) as create, patch.object(
            activation.r5_resume, "phase_f_set_restart_policy_exact", return_value=target
        ) as policy, patch.object(
            activation.r5_resume, "phase_f_start_container_exact", return_value=target
        ) as start:
            for operation, _retry in _S2_PROGRAM:
                backend.apply_operation(operation)
        self.assertEqual(len(_S2_PROGRAM), 18)
        self.assertEqual(publish.call_count, 6)
        self.assertEqual(backend._apply_unit.call_count, 6)
        systemd.assert_called_once_with(["/usr/bin/systemctl", "daemon-reload"])
        stop.assert_called_once()
        rename.assert_called_once()
        create.assert_called_once()
        policy.assert_called_once()
        start.assert_called_once()
        source = Path(activation.__file__).read_text("utf-8")
        for operation, _retry in _S2_PROGRAM:
            with self.subTest(operation=operation):
                self.assertIn(operation, source)

    def test_forward_old_uses_real_startup_and_independent_terminal_observers(self) -> None:
        backend = object.__new__(activation.Generation13LiveBackend)
        backend._startup_recovery_result = None
        backend._old_location = Mock(return_value=(None, None))
        backend.observe_full_old = Mock(return_value="OLD")
        backend._observe_old_readiness = Mock(side_effect=("DESIRED", "DESIRED"))
        backend._observe_old_ingress = Mock(side_effect=("DESIRED", "DESIRED"))
        typed = activation.StartupRecoveryV3(
            abandoned_deliveries=1,
            discarded_unprepared_turns=2,
            requeued_summary_jobs=3,
            blocked_summary_jobs=4,
        )
        backend._ordinary_startup_recover = Mock(return_value=typed)

        self.assertEqual(backend.observe_forward_old("F16_ORDINARY_STARTUP_RECOVER"), "OLD")
        backend.apply_forward_old("F16_ORDINARY_STARTUP_RECOVER")
        self.assertEqual(backend.observe_forward_old("F16_ORDINARY_STARTUP_RECOVER"), "DESIRED")
        backend._ordinary_startup_recover.assert_called_once_with()
        self.assertIs(backend._startup_recovery_result, typed)

        backend.observe_full_old.reset_mock()
        self.assertEqual(backend.observe_forward_old("F17_READINESS_OBSERVATION_ONE"), "DESIRED")
        self.assertEqual(backend.observe_forward_old("F18_READINESS_OBSERVATION_TWO"), "DESIRED")
        self.assertEqual(backend._observe_old_readiness.call_count, 2)
        self.assertEqual(backend.observe_forward_old("F19_INGRESS_OBSERVATION_ONE"), "DESIRED")
        self.assertEqual(backend.observe_forward_old("F20_INGRESS_OBSERVATION_TWO"), "DESIRED")
        self.assertEqual(backend._observe_old_ingress.call_count, 2)
        self.assertEqual(backend.observe_forward_old("F21_FULL_OLD_OBSERVATION_ONE"), "DESIRED")
        self.assertEqual(backend.observe_forward_old("F22_FULL_OLD_OBSERVATION_TWO"), "DESIRED")
        self.assertEqual(backend.observe_full_old.call_count, 2)

    def test_ordinary_startup_recovery_calls_external_epoch_store_and_validates_type(self) -> None:
        backend = object.__new__(activation.Generation13LiveBackend)
        release_set = SimpleNamespace(
            epoch={
                "database_path": "/var/lib/myuna/old/epoch.db",
                "epoch_id": "p07-d-external-v3-g11",
                "uid": 1001,
                "gid": 1002,
            },
            runtime_config={
                "channel_kind": "astrbot_telegram",
                "principal_id": "owner",
                "namespace_id": "private",
            },
            release_set_id="a" * 64,
            projection_policy_version="external_projection_v1",
        )
        backend._old_release_set = Mock(return_value=release_set)
        typed = activation.StartupRecoveryV3(0, 0, 0, 0)
        store = Mock()
        store.startup_recover.return_value = typed
        with patch.object(activation, "ExternalEpochV3Store", return_value=store) as constructor:
            self.assertEqual(backend._ordinary_startup_recover(), typed)
        constructor.assert_called_once()
        store.startup_recover.assert_called_once_with()
        store.startup_recover.return_value = {"abandoned_deliveries": 0}
        with patch.object(activation, "ExternalEpochV3Store", return_value=store):
            with self.assertRaisesRegex(activation.Generation13ActivationRejected, "phase_f_startup_recovery_result_rejected"):
                backend._ordinary_startup_recover()



if __name__ == "__main__":
    unittest.main()
