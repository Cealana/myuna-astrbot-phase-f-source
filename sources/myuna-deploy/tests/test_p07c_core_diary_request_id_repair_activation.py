from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import activate_p07c_core_diary_request_id_repair_v1 as activation  # noqa: E402


class P07CCoreDiaryRequestIdRepairActivationTests(unittest.TestCase):
    def test_release_evidence_is_content_addressed_and_content_free(self) -> None:
        evidence = activation.target_evidence()
        self.assertEqual(evidence.tree_sha256, activation.TARGET_RELEASE)
        self.assertEqual(evidence.source_commit, activation.TARGET_COMMIT)
        self.assertEqual(evidence.file_count, 261)
        artifact = json.loads(activation.artifact_manifest_bytes())
        self.assertEqual(artifact["verification"]["core_tests"], 609)
        self.assertEqual(artifact["verification"]["focused_tests"], 124)
        self.assertTrue(
            artifact["verification"]["authenticated_request_id_preserved"]
        )
        self.assertFalse(
            artifact["verification"]["writer_request_id_equality_relaxed"]
        )
        self.assertFalse(artifact["verification"]["private_content_present"])

    def test_plan_is_narrow_and_preserves_writer_data(self) -> None:
        plan = json.loads(activation.plan_bytes())
        self.assertEqual(plan["prestate"]["profile_writer"], "installed-active")
        self.assertEqual(
            plan["target"]["writer_protocol_equality"], "strict-fail-closed-v1"
        )
        self.assertEqual(plan["target"]["profile_and_candidate_data"], "unchanged")
        self.assertEqual(plan["live_scope"]["core_restart_max"], 1)
        self.assertEqual(plan["live_scope"]["profile_writer_restart"], 0)
        self.assertTrue(plan["live_scope"]["model_calls_forbidden"])
        self.assertTrue(plan["live_scope"]["channel_messages_forbidden"])

    def test_selector_targets_only_the_repair_release(self) -> None:
        _binding, selector = activation.target_binding("a" * 64)
        rendered = selector.decode("utf-8")
        self.assertIn(activation.TARGET_RELEASE, rendered)
        self.assertNotIn(activation.CURRENT_RELEASE, rendered)

    def test_validator_requires_both_handoff_and_strict_writer_check(self) -> None:
        source = (SCRIPTS / "activate_p07c_core_diary_request_id_repair_v1.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("authenticated_context.request_id", source)
        self.assertIn("if context.request_id != request_id:", source)
        self.assertNotIn("profile.toml", source)
        self.assertNotIn("/chat/completions", source)

    def test_activation_status_is_specific_to_owner_e2e_retry(self) -> None:
        with mock.patch.object(
            activation.base,
            "activate",
            return_value={
                "core_release": activation.TARGET_RELEASE,
                "plan_sha256": "a" * 64,
                "status": "previous_gate",
            },
        ):
            result = activation.activate(Path("/synthetic"), preflight_only=False)
        self.assertEqual(result["status"], activation.ACTIVE_STATUS)


if __name__ == "__main__":
    unittest.main()
