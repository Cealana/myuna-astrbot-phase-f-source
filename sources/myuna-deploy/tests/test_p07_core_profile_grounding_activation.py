from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import activate_p07_core_profile_grounding_v1 as activation  # noqa: E402


class P07CoreProfileGroundingActivationTests(unittest.TestCase):
    def test_release_evidence_and_manifest_are_content_free(self) -> None:
        evidence = activation.target_evidence()
        self.assertEqual(evidence.tree_sha256, activation.TARGET_RELEASE)
        self.assertEqual(evidence.source_commit, activation.TARGET_COMMIT)
        self.assertEqual(evidence.file_count, 238)
        artifact = json.loads(activation.artifact_manifest_bytes())
        self.assertEqual(artifact["verification"]["core_tests"], 522)
        self.assertEqual(
            artifact["verification"]["owner_profile_factual_grounding"],
            "high-priority-runtime-control-v1",
        )
        self.assertEqual(
            artifact["verification"]["synthetic_model_probe"],
            "passed-ascii-order-and-no-generic-fill",
        )
        self.assertFalse(artifact["verification"]["private_content_present"])

    def test_plan_preserves_model_output_session_and_both_channels(self) -> None:
        plan = json.loads(activation.plan_bytes())
        self.assertEqual(plan["target"]["local_max_output_tokens"], 192)
        self.assertEqual(
            plan["target"]["session_store"],
            "unchanged-128-message-window",
        )
        self.assertEqual(plan["live_scope"]["local_provider_restart"], 0)
        self.assertEqual(
            plan["live_scope"]["gateway_quiesce_restore"],
            ["qq-owner-private", "telegram-owner-private"],
        )
        self.assertTrue(plan["live_scope"]["real_profile_probe_forbidden"])
        self.assertTrue(plan["rollback"]["preserve_profile_and_session_data"])

    def test_selector_targets_only_the_content_addressed_release(self) -> None:
        _binding, selector = activation.target_binding("a" * 64)
        text = selector.decode("utf-8")
        self.assertIn(activation.TARGET_RELEASE, text)
        self.assertNotIn(activation.CURRENT_RELEASE, text)
        self.assertNotIn("Authorization", text)

    def test_activation_has_no_health_real_profile_or_provider_probe(self) -> None:
        source = (
            SCRIPTS / "activate_p07_core_profile_grounding_v1.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "/healthz",
            "/readyz",
            "/chat/completions",
            "profile.toml",
            "urllib",
            "git push",
            "docker system prune",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("candidate_grounding_rejected", source)
        self.assertIn("raw_message_recorded", source)
        self.assertIn("restore_binding_and_selector_exact_bytes", source)

    def test_activation_reports_the_grounding_retry_gate(self) -> None:
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
