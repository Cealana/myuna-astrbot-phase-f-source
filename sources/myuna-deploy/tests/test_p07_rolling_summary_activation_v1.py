from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import activate_p07_external_epoch_rollover_v1 as b_activator
import activate_p07_rolling_summary_lifecycle_v1 as activator
from external_context_epoch import ExternalEpochBinding, ExternalEpochStore
import telegram_owner_runtime_gateway as runtime


class RollingSummaryActivationTests(unittest.TestCase):
    def test_selector_advances_exact_generation_and_epoch(self) -> None:
        payload = activator.selector_payload("a" * 64)
        self.assertEqual(6, payload["generation"])
        self.assertEqual(activator.NEW_EPOCH_ID, payload["epoch_id"])
        self.assertEqual(b_activator.NEW_EPOCH_ID, payload["previous_epoch_id"])
        self.assertEqual(activator.NEW_EPOCH_DATABASE.as_posix(), payload["database_path"])
        self.assertEqual(payload, activator.validate_selector_payload(payload))
        selection = runtime.ExternalEpochSelection.from_payload(payload)
        self.assertEqual(6, selection.generation)
        self.assertEqual(activator.NEW_EPOCH_ID, selection.epoch_id)

    def test_selector_rejects_generation_or_previous_epoch_drift(self) -> None:
        for key, value in (("generation", 4), ("previous_epoch_id", "wrong")):
            payload = activator.selector_payload("b" * 64)
            payload[key] = value
            with self.assertRaises(b_activator.RolloverRejected):
                activator.validate_selector_payload(payload)
        for key, value in (("generation", 7), ("epoch_id", "synthetic-other")):
            payload = activator.selector_payload("b" * 64)
            payload[key] = value
            with self.assertRaises(runtime.RuntimeRejected):
                runtime.ExternalEpochSelection.from_payload(payload)

    def test_previous_selector_requires_canonical_generation4_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            selector = Path(root) / "selector.json"
            payload = b_activator.selector_payload("c" * 64)
            selector.write_bytes(b_activator.canonical(payload))
            selector.chmod(0o640)
            group = types.SimpleNamespace(gr_gid=os.getgid())
            with mock.patch.object(activator, "SELECTOR_PATH", selector), \
                 mock.patch.object(activator.grp, "getgrnam", return_value=group):
                raw, loaded = activator.load_previous_selector()
                self.assertEqual(payload, loaded)
                self.assertEqual(b_activator.canonical(payload), raw)
                selector.unlink()
                selector.symlink_to(Path(root) / "missing")
                with self.assertRaises((OSError, b_activator.RolloverRejected)):
                    activator.load_previous_selector()

    def test_old_epoch_contract_rejects_pending_or_identity_drift(self) -> None:
        valid = {
            "schema_name": "myuna.external-authorized-epoch.v1",
            "schema_version": 1,
            "epoch_id": b_activator.NEW_EPOCH_ID,
            "selected_revision": 2,
            "max_revision": 2,
            "turn_count": 2,
            "summary_count": 0,
            "pending_count": 0,
        }
        activator.require_expected_old_epoch(valid, revision=2, turns=2,
                                             summaries=0, pending=0)
        for key, value in (("epoch_id", "wrong"), ("pending_count", 1)):
            drifted = dict(valid)
            drifted[key] = value
            with self.assertRaises(b_activator.RolloverRejected):
                activator.require_expected_old_epoch(
                    drifted, revision=2, turns=2, summaries=0,
                    pending=1 if key == "pending_count" else 0,
                )

    def test_epoch_root_requires_exact_existing_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "epochs"
            path.mkdir(mode=0o710)
            group = types.SimpleNamespace(gr_gid=os.getgid())
            with mock.patch.object(activator.grp, "getgrnam", return_value=group):
                activator.require_existing_epoch_root(path)
                path.chmod(0o700)
                with self.assertRaises(b_activator.RolloverRejected):
                    activator.require_existing_epoch_root(path)

    def test_schema_v2_empty_epoch_accepts_exact_d_identity_only(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            parent = Path(root) / "epoch"
            parent.mkdir(mode=0o700)
            database = parent / "epoch.db"
            binding = ExternalEpochBinding(
                channel_kind="astrbot_telegram",
                client_id="telegram-owner-private",
                principal_id="owner-synthetic",
                namespace_id="owner-synthetic-private",
            )
            store = ExternalEpochStore(
                database, epoch_id=activator.NEW_EPOCH_ID,
                startup_binding=binding,
            )
            self.assertEqual(0, store.public_metadata()["turn_count"])
            metadata = b_activator.inspect_empty_epoch(
                database, binding=binding, expected_uid=os.getuid(),
                expected_gid=os.getgid(), expected_epoch_id=activator.NEW_EPOCH_ID,
            )
            self.assertEqual(2, metadata["schema_version"])
            self.assertEqual(0, metadata["provenance_count"])
            self.assertEqual(0, metadata["pending_summary_count"])
            with self.assertRaises(b_activator.RolloverRejected):
                b_activator.inspect_empty_epoch(
                    database, binding=binding, expected_uid=os.getuid(),
                    expected_gid=os.getgid(), expected_epoch_id="wrong",
                )

    def test_plan_binds_present_selector_rollback_and_schema_v2(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            candidate = Path(root) / ("d" * 64)
            candidate.mkdir()
            prestate = {"previous_selector_sha256": "e" * 64}
            with mock.patch.object(activator, "digest_file", return_value="f" * 64):
                first = activator.build_plan(candidate, candidate,
                                             core_commit="1" * 40,
                                             deploy_commit="2" * 40,
                                             prestate=prestate)
                second = activator.build_plan(candidate, candidate,
                                              core_commit="1" * 40,
                                              deploy_commit="2" * 40,
                                              prestate=prestate)
            self.assertEqual(first, second)
            payload = json.loads(first)
            self.assertEqual("restore-exact-present-bytes",
                             payload["rollback"]["selector_prestate"])
            self.assertEqual(2, payload["target"]["sqlite_schema_version"])

    def test_backup_preserves_exact_present_selector(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            backup_root = Path(root) / "backup"
            dropin = Path(root) / "dropin"
            selector = Path(root) / "selector"
            core_binding = Path(root) / "core-binding"
            core_selector = Path(root) / "core-selector"
            core_gate = Path(root) / "core-gate"
            dropin.write_bytes(b"dropin-bytes")
            selector.write_bytes(b"selector-bytes")
            core_binding.write_bytes(b"core-binding-bytes")
            core_selector.write_bytes(b"core-selector-bytes")
            core_gate.write_bytes(b"core-gate-bytes")
            with mock.patch.object(activator, "BACKUP_ROOT", backup_root), \
                 mock.patch.object(activator, "TELEGRAM_DROPIN", dropin), \
                 mock.patch.object(activator, "SELECTOR_PATH", selector), \
                 mock.patch.object(activator, "CORE_BINDING", core_binding), \
                 mock.patch.object(activator, "CORE_SELECTOR", core_selector), \
                 mock.patch.object(activator, "CORE_GATE", core_gate):
                saved_root, payloads = activator.backup(
                    b"plan", {"status": "synthetic"}
                )
            self.assertEqual(b"dropin-bytes", payloads["TELEGRAM_DROPIN"])
            self.assertEqual(b"selector-bytes", payloads["SELECTOR"])
            self.assertEqual(b"selector-bytes", (saved_root / "SELECTOR").read_bytes())

    def test_restore_prestate_restores_exact_present_selector(self) -> None:
        selector = b"exact-generation4-selector"
        prestate = {
            "core_binding_sha256": "c" * 64,
            "core_gate_present": False,
            "core_gate_sha256": None,
            "core_selector_sha256": "d" * 64,
            "core_release": "e" * 64,
            "previous_selector_sha256": activator.digest_bytes(selector),
            "runtime_dropin_sha256": "a" * 64,
            "runtime_release": "b" * 64,
        }
        payloads = {
            "CORE_BINDING": b"binding",
            "CORE_SELECTOR": b"core-selector",
            "CORE_GATE": None,
            "TELEGRAM_DROPIN": b"dropin",
            "SELECTOR": selector,
        }
        payload = {"generation": 4}
        with mock.patch.object(activator, "stop_telegram"), \
             mock.patch.object(activator, "start_telegram"), \
             mock.patch.object(activator, "atomic_write"), \
             mock.patch.object(activator, "restore_optional") as restore, \
             mock.patch.object(activator, "restore_old_epoch_permissions"), \
             mock.patch.object(activator, "active", return_value=True), \
             mock.patch.object(activator, "digest_file", side_effect=(
                 "a" * 64, "c" * 64, "d" * 64
             )), \
             mock.patch.object(activator, "show", side_effect=(
                 f"/{'e' * 64}",
                 f"/{'b' * 64}/runtime/telegram_owner_runtime_gateway.py",
             )), \
             mock.patch.object(activator, "load_previous_selector", return_value=(selector, payload)), \
             mock.patch.object(activator.grp, "getgrnam", return_value=types.SimpleNamespace(gr_gid=123)), \
             mock.patch.object(activator, "systemctl"), \
             mock.patch.object(activator, "CORE_GATE",
                               types.SimpleNamespace(exists=lambda: False)):
            activator.restore_prestate(
                prestate, payloads, bundle_prestate={},
                current_bundle_digest="c" * 64,
                restore_bundle_permissions_needed=True,
            )
        restore.assert_any_call(activator.SELECTOR_PATH, selector,
                                mode=0o640, gid=123)

    def test_activate_preflight_binds_d_epoch_identity_without_mutation(self) -> None:
        candidate = Path("/synthetic") / ("a" * 64)
        core_candidate = Path("/synthetic-core") / ("c" * 64)
        prestate = {"status": "synthetic"}
        with mock.patch.object(activator.os, "geteuid", return_value=0), \
             mock.patch.object(activator, "core_evidence", return_value=(
                 types.SimpleNamespace(tree_sha256="c" * 64,
                                       source_commit="1" * 40), b"artifact", b"receipt"
             )) as evidence, \
             mock.patch.object(activator, "verify_core_response_contract"), \
             mock.patch.object(activator, "validate_runtime", return_value="a" * 64), \
             mock.patch.object(activator, "verify_runtime_startup_smoke"), \
             mock.patch.object(activator, "verify_new_epoch_startup_smoke") as smoke, \
             mock.patch.object(activator, "verify_live_prestate", return_value=prestate), \
             mock.patch.object(activator, "build_plan", return_value=b"plan"):
            result = activator.activate(
                core_candidate, candidate,
                core_commit="1" * 40, deploy_commit="2" * 40,
                expected_core_release="3" * 64,
                expected_runtime_release="4" * 64,
                expected_plugin_release="5" * 64,
                expected_old_sha256="6" * 64, expected_revision=0,
                expected_turns=0, expected_summaries=0, expected_pending=0,
                expected_plan_sha256=None, preflight_only=True,
            )
        self.assertEqual("ready", result["status"])
        evidence.assert_called_once_with(core_candidate)
        smoke.assert_called_once_with(candidate,
                                      expected_epoch_id=activator.NEW_EPOCH_ID)

    def test_plan_binds_target_core_release(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            runtime = Path(root) / ("a" * 64)
            core = Path(root) / ("b" * 64)
            runtime.mkdir()
            core.mkdir()
            with mock.patch.object(activator, "digest_file", return_value="c" * 64):
                payload = json.loads(activator.build_plan(
                    core, runtime, core_commit="1" * 40,
                    deploy_commit="2" * 40,
                    prestate={"previous_selector_sha256": "d" * 64},
                ))
        self.assertEqual("b" * 64, payload["target"]["core_release"])

    def test_stopped_bundle_prestate_is_durably_bound_for_later_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            backup = Path(root)
            stopped = {
                "bundle_digest": "e" * 64,
                "bundle_projection": {"files": []},
                "file_permissions": {},
                "parent_permission": {},
            }
            activator.persist_stopped_bundle_prestate(backup, stopped)
            payload = json.loads((backup / "STOPPED_BUNDLE_PRESTATE.json").read_text())
        self.assertEqual("e" * 64, payload["bundle_digest"])


if __name__ == "__main__":
    unittest.main()
