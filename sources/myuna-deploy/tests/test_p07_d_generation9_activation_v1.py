from __future__ import annotations

import ast
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import activate_p07_d_generation9_v1 as activation
from p07_d_activation_transaction import ReleaseSetActivationRejected
from p07_d_generation9_release_set import canonical
from p07_d_generation9_release_set import selector_payload
from tests.test_p07_d_release_set_transaction_v1 import release_set


class Generation9ActivationTests(unittest.TestCase):
    def test_incident_successor_uses_new_attempt_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            successor_root = root / "generation9-state"
            successor_root.mkdir()
            ledger = successor_root / "ATTEMPT_LEDGER.json"
            ledger.write_bytes(
                canonical(
                    {
                        "attempts": 1,
                        "last_plan_sha256": "a" * 64,
                        "schema": "myuna.p07-d-generation9-attempt-ledger.v1",
                    }
                )
            )
            ledger.chmod(0o600)
            with patch.object(activation, "STATE_ROOT", successor_root), patch.object(
                activation, "ATTEMPT_LEDGER", ledger
            ):
                self.assertEqual(activation._attempt_count(), 1)
                self.assertEqual(activation.STATE_ROOT, activation.ATTEMPT_LEDGER.parent)

    def test_attempt_ledger_is_goal_scoped_and_bounded_to_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(activation, "STATE_ROOT", root), patch.object(
                activation, "ATTEMPT_LEDGER", root / "ATTEMPT_LEDGER.json"
            ):
                self.assertEqual(activation._attempt_count(), 0)
                self.assertEqual(activation._consume_attempt("a" * 64), 1)
                self.assertEqual(activation._consume_attempt("b" * 64), 2)
                with self.assertRaisesRegex(
                    activation.Generation9ActivationRejected,
                    "live_attempt_budget_exhausted",
                ):
                    activation._consume_attempt("c" * 64)

    def test_target_service_set_binds_acl_and_exact_identities(self) -> None:
        services = activation._target_service_bindings(
            core_uid=999,
            core_gid=989,
            telegram_uid=988,
            telegram_gid=982,
            core_release="1" * 64,
            runtime_release="2" * 64,
            selector_digest="3" * 64,
            runtime_config_digest="4" * 64,
            acl_digest="5" * 64,
        )
        self.assertEqual({item["kind"] for item in services}, {"core", "telegram", "telegram_socket"})
        self.assertEqual({item["uid"] for item in services}, {999, 988})
        changed = activation._target_service_bindings(
            core_uid=999,
            core_gid=989,
            telegram_uid=988,
            telegram_gid=982,
            core_release="1" * 64,
            runtime_release="2" * 64,
            selector_digest="3" * 64,
            runtime_config_digest="4" * 64,
            acl_digest="6" * 64,
        )
        self.assertNotEqual(
            tuple(item["binding_digest"] for item in services),
            tuple(item["binding_digest"] for item in changed),
        )
        runtime_changed = activation._target_service_bindings(
            core_uid=999,
            core_gid=989,
            telegram_uid=988,
            telegram_gid=982,
            core_release="1" * 64,
            runtime_release="2" * 64,
            selector_digest="3" * 64,
            runtime_config_digest="7" * 64,
            acl_digest="5" * 64,
        )
        telegram = next(item for item in services if item["kind"] == "telegram")
        changed_telegram = next(
            item for item in runtime_changed if item["kind"] == "telegram"
        )
        self.assertNotEqual(
            telegram["binding_digest"],
            changed_telegram["binding_digest"],
        )

    def test_generation9_selector_does_not_reuse_failed_paths(self) -> None:
        payload = selector_payload("a" * 64)
        self.assertEqual(activation.GENERATION, 9)
        self.assertEqual(payload["generation"], 9)
        self.assertIn("external-d-reset-v3", payload["database_path"])
        self.assertNotIn("external-d-v1", payload["database_path"])
        self.assertNotIn("external-d-v2/", payload["database_path"])
        self.assertNotIn("external-d-reset-v1/", payload["database_path"])
        self.assertNotIn("external-d-reset-v2/", payload["database_path"])

    def test_socket_without_restart_property_projects_exact_zero(self) -> None:
        values = {
            "ActiveState": "active",
            "SubState": "running",
            "Result": "success",
            "NRestarts": "",
        }
        with patch.object(activation, "show", side_effect=lambda _unit, key: values[key]):
            observed = activation._service_observation("synthetic.socket")
        self.assertEqual(observed.nrestarts, 0)

    def test_activator_routes_effects_through_atomic_transaction(self) -> None:
        source = Path(activation.__file__).read_text("utf-8")
        tree = ast.parse(source)
        calls = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertIn("AtomicReleaseSetTransaction", calls)
        self.assertIn("wait_for_runtime_readiness", calls)
        self.assertNotIn("requests", source)
        self.assertNotIn("httpx", source)

    def test_runtime_readiness_never_writes_failed_generation_paths(self) -> None:
        runtime_source = (Path(activation.__file__).with_name("telegram_owner_runtime_gateway.py")).read_text("utf-8")
        self.assertIn("if release_set.generation >= 9:", runtime_source)
        self.assertIn("external_epoch_selection.generation in {7, 8, 9, 10, 11, 12, 13}", runtime_source)

    def test_failure_projection_preserves_typed_activation_and_rollback_gates(self) -> None:
        error = ReleaseSetActivationRejected(
            "functional_rollback_failed",
            activation_failure_code="target_core_inactive",
            rollback_failure_code="rollback_service_inactive",
        )
        self.assertEqual(
            activation._failure_projection(error),
            {
                "activation_failure_gate": "target_core_inactive",
                "failure_gate": "functional_rollback_failed",
                "rollback_failure_gate": "rollback_service_inactive",
            },
        )

    def test_failure_projection_never_copies_untyped_exception_text(self) -> None:
        projection = activation._failure_projection(
            RuntimeError("private or provider text must not escape")
        )
        self.assertEqual(
            projection,
            {"failure_gate": "generation9_activation_rejected"},
        )
        self.assertNotIn("private", repr(projection))

        unsafe_code = RuntimeError("opaque")
        unsafe_code.code = "invalid gate with private detail"
        self.assertEqual(
            activation._failure_projection(unsafe_code),
            {"failure_gate": "generation9_activation_rejected"},
        )

    @unittest.skipUnless(
        os.environ.get("P07_GENERATION9_CORE_CANDIDATE")
        and os.environ.get("P07_GENERATION9_RUNTIME_CANDIDATE"),
        "explicit immutable candidates required",
    )
    def test_exact_service_identities_can_read_shared_manifest(self) -> None:
        prepared = SimpleNamespace(
            core_candidate=Path(os.environ["P07_GENERATION9_CORE_CANDIDATE"]),
            runtime_candidate=Path(os.environ["P07_GENERATION9_RUNTIME_CANDIDATE"]),
            release_set_bytes=canonical(release_set().as_payload()),
        )
        activation._cross_identity_manifest_smoke(prepared)


if __name__ == "__main__":
    unittest.main()
