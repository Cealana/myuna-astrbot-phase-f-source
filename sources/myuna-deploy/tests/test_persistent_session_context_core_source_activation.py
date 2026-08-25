from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def load_module(filename: str, name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


activation = load_module(
    "activate_persistent_session_context_core_source_v1.py",
    "activate_persistent_session_context_core_source_v1",
)


class PersistentSessionContextCoreSourceActivationTests(unittest.TestCase):
    def test_target_binding_is_digest_bound_to_the_approved_plan(self) -> None:
        plan = activation._activation_plan_bytes(activation.GATEWAY_CANDIDATE_DIGEST)
        plan_digest = activation.digest_bytes(plan)
        binding_bytes, selector_bytes = activation._target_core_bytes(plan_digest)
        binding = activation.load_runtime_binding(
            activation.parse_json_document(binding_bytes)
        )

        self.assertEqual(binding.approval_plan_digest, plan_digest)
        self.assertEqual(
            binding.selected_release.tree_sha256,
            activation.CORE_CANDIDATE_DIGEST,
        )
        self.assertEqual(
            activation.digest_bytes(selector_bytes), binding.selector_dropin_sha256
        )

    def test_plan_fixes_call_budget_and_preserves_sqlite_on_rollback(self) -> None:
        plan = json.loads(
            activation._activation_plan_bytes(
                activation.GATEWAY_CANDIDATE_DIGEST
            )
        )
        self.assertEqual(plan["live_scope"]["provider_attempts_max"], 2)
        self.assertEqual(plan["live_scope"]["incremental_cost_cap_usd"], "0.08")
        self.assertTrue(plan["live_scope"]["health_endpoints_forbidden"])
        self.assertTrue(plan["rollback"]["preserve_sqlite"])
        self.assertEqual(plan["activation_attempt"]["ordinal"], 2)
        self.assertTrue(plan["activation_attempt"]["final_for_candidate"])
        self.assertEqual(len(plan["activation_attempt"]["executor_sha256"]), 64)

    def test_source_candidate_uses_selector_not_execstart_attempt_wrapper(self) -> None:
        source = (
            SCRIPTS / "activate_persistent_session_context_core_source_v1.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("CORE_EXEC_DROPIN", source)
        self.assertNotIn("/usr/bin/env MYUNA_DEEPSEEK_MAX_ATTEMPTS=1", source)
        self.assertIn("render_runtime_binding", source)

    def test_post_restart_verifier_uses_selected_release_cwd_and_pythonpath(self) -> None:
        target = (
            activation.CORE_RELEASE_ROOT / activation.CORE_CANDIDATE_DIGEST
        ).as_posix()
        completed = mock.Mock(returncode=0)
        running_environment = {
            "MYUNA_DEEPSEEK_MAX_ATTEMPTS": activation.gateway.CORE_BASE_MAX_ATTEMPTS
        }
        with (
            mock.patch.object(activation.gateway, "is_active", return_value=True),
            mock.patch.object(
                activation.gateway,
                "systemctl",
                return_value=target,
            ),
            mock.patch.object(
                activation.gateway,
                "_running_environment",
                return_value=running_environment,
            ),
            mock.patch.object(activation.subprocess, "run", return_value=completed) as run,
        ):
            activation._verify_active_core()

        verifier_call = run.call_args_list[0]
        self.assertEqual(verifier_call.kwargs["cwd"], target)
        self.assertEqual(
            verifier_call.kwargs["env"]["PYTHONPATH"], f"{target}/src"
        )


if __name__ == "__main__":
    unittest.main()
