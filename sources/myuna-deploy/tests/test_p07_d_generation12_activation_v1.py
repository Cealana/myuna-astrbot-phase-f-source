from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from myuna_core.external_context.contracts import EXTERNAL_PROJECTION_POLICY

import activate_p07_d_generation12_v1 as activation
from p07_d_generation11_release_set import selector_payload as generation11_selector
from p07_d_generation12_release_set import selector_payload as generation12_selector
import telegram_owner_runtime_gateway as runtime_gateway


class Generation12ActivationTests(unittest.TestCase):
    def test_rollback_restores_generation11_release_set_acl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release-set.json"
            backup = Path(directory) / "backup"
            backup.mkdir()
            with patch.object(activation, "atomic_write") as atomic_write, patch.object(
                activation, "apply_release_set_acl"
            ) as apply_acl:
                apply_acl.return_value = type("Acl", (), {"file_mode": 0o640})()
                activation._restore_release_set_prestate(
                    path,
                    b"{}",
                    backup_root=backup,
                    core_uid=1001,
                    telegram_uid=1002,
                )
            atomic_write.assert_called_once_with(path, b"{}", mode=0o600, gid=0)
            apply_acl.assert_called_once_with(
                path,
                core_uid=1001,
                telegram_uid=1002,
            )

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
                activation.Generation12ActivationRejected,
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

    def test_component_uses_new_isolated_state_and_never_reuses_generation11(self) -> None:
        self.assertEqual(activation.GENERATION, 12)
        self.assertIn("p08-p07-generation12-v1", activation.STATE_ROOT.as_posix())
        self.assertIn("p08-p07-generation12-v1", activation.BACKUP_ROOT.as_posix())
        self.assertEqual(activation.ATTEMPT_LEDGER.parent, activation.STATE_ROOT)
        selector = generation12_selector("a" * 64)
        self.assertIn("external-d-reset-v6", selector["database_path"])
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
                raw, loaded = activation._load_previous_selector()
                self.assertEqual(raw, activation.canonical(payload))
                self.assertEqual(loaded["generation"], 11)
                wrong = dict(payload)
                wrong["generation"] = 12
                path.write_bytes(activation.canonical(wrong))
                with self.assertRaisesRegex(
                    activation.Generation12ActivationRejected,
                    "previous_selector_rejected",
                ):
                    activation._load_previous_selector()

    def test_standalone_live_activation_requires_combined_coordinator(self) -> None:
        prepared = type(
            "Prepared",
            (),
            {
                "plan_digest": "a" * 64,
                "release_set": type("Release", (), {"release_set_id": "b" * 64})(),
            },
        )()
        with patch.object(activation, "_cross_identity_manifest_smoke"), patch.object(
            activation, "_attempt_count", return_value=0
        ), patch.object(
            activation, "phase_f_selected_target", return_value=True
        ), patch.object(activation, "atomic_write") as exact_effect:
            ready = activation.activate(
                prepared,
                expected_plan_sha256=None,
                preflight_only=True,
            )
            self.assertEqual(ready["status"], "ready")
            with self.assertRaisesRegex(
                activation.Generation12ActivationRejected,
                "phase_f_canonical_owner_required",
            ):
                activation.activate(
                    prepared,
                    expected_plan_sha256="a" * 64,
                    preflight_only=False,
                )
            exact_effect.assert_not_called()

    def test_generic_non_phase_f_generation12_keeps_historical_coordinated_path(self) -> None:
        prepared = type(
            "Prepared",
            (),
            {
                "plan_digest": "a" * 64,
                "plan_bytes": b"{}\n",
                "release_set": type("Release", (), {"release_set_id": "b" * 64})(),
            },
        )()
        result = type("Result", (), {"release_set_id": "b" * 64})()
        transaction = Mock()
        transaction.run.return_value = result
        with tempfile.TemporaryDirectory() as directory, patch.object(
            activation, "_cross_identity_manifest_smoke"
        ), patch.object(
            activation, "_attempt_count", return_value=0
        ), patch.object(
            activation, "phase_f_selected_target", return_value=False
        ), patch.object(
            activation, "BACKUP_ROOT", Path(directory) / "backup"
        ), patch.object(
            activation, "STATE_ROOT", Path(directory) / "state"
        ), patch.object(
            activation, "_consume_attempt", return_value=1
        ), patch.object(
            activation, "Generation12LiveBackend", return_value=object()
        ), patch.object(
            activation, "AtomicReleaseSetTransaction", return_value=transaction
        ), patch.object(activation, "atomic_write") as generic_effect:
            receipt = activation.activate(
                prepared,
                expected_plan_sha256="a" * 64,
                preflight_only=False,
                coordinated=True,
            )
        self.assertEqual(receipt["status"], "ACTIVE_WAITING_OWNER_ORGANIC_TELEGRAM_E2E")
        self.assertEqual(generic_effect.call_count, 4)
        transaction.run.assert_called_once_with()

    def test_runtime_and_activator_admit_generation12_without_network_clients(self) -> None:
        source = Path(activation.__file__).read_text("utf-8")
        tree = ast.parse(source)
        self.assertNotIn("requests", source)
        self.assertNotIn("httpx", source)
        self.assertTrue(any(isinstance(node, ast.ClassDef) and node.name == "Generation12LiveBackend" for node in ast.walk(tree)))
        runtime_source = (Path(activation.__file__).with_name("telegram_owner_runtime_gateway.py")).read_text("utf-8")
        self.assertIn(
            "external_epoch_selection.generation in {7, 8, 9, 10, 11, 12, 13}",
            runtime_source,
        )
        selection = runtime_gateway.ExternalEpochSelection.from_payload(
            generation12_selector("a" * 64)
        )
        self.assertEqual(selection.generation, 12)
        self.assertEqual(
            runtime_gateway._EXTERNAL_EPOCH_GENERATIONS[12],
            (
                "telegram-owner-private-external-d-reset-v6",
                "telegram-owner-private-external-d-reset-v5",
            ),
        )
        self.assertNotIn(".generation==11", source)
        self.assertIn("prepared.release_set.release_set_id", source)

    def test_generation12_selector_reaches_fresh_epoch_and_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            epoch_id = "telegram-owner-private-external-d-reset-v6"
            epoch_parent = root / epoch_id
            epoch_parent.mkdir(mode=0o700)
            database_path = epoch_parent / "epoch.db"
            selector_path = root / "selector.json"
            runtime_config_path = root / "runtime-config.json"
            selector_digest = "b" * 64
            release_set_id = "c" * 64
            payload = generation12_selector("a" * 64)
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
                    "generation": 12,
                    "projection_policy_version": EXTERNAL_PROJECTION_POLICY,
                    "release_set_id": release_set_id,
                    "selector": {
                        "path": selector_path.as_posix(),
                        "digest": selector_digest,
                        "generation": 12,
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

    def test_attempt_ledger_is_generation12_scoped_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = root / "ATTEMPT_LEDGER.json"
            with patch.object(activation, "STATE_ROOT", root), patch.object(
                activation, "ATTEMPT_LEDGER", ledger
            ):
                self.assertEqual(activation._consume_attempt("a" * 64), 1)
                self.assertEqual(activation._consume_attempt("b" * 64), 2)
                payload = json.loads(ledger.read_text("ascii"))
                self.assertEqual(
                    payload["schema"],
                    "myuna.p07-generation12-component-attempt-ledger.v1",
                )
                with self.assertRaisesRegex(
                    activation.Generation12ActivationRejected,
                    "live_attempt_budget_exhausted",
                ):
                    activation._consume_attempt("c" * 64)


if __name__ == "__main__":
    unittest.main()
