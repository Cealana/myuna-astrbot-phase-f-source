from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import activate_p07_core_local_output_cap_v1 as activation  # noqa: E402


class P07CoreLocalOutputCapActivationTests(unittest.TestCase):
    def test_release_evidence_is_exact_and_content_free(self) -> None:
        evidence = activation.target_evidence()
        self.assertEqual(evidence.tree_sha256, activation.TARGET_RELEASE)
        self.assertEqual(evidence.source_commit, activation.TARGET_COMMIT)
        self.assertEqual(evidence.file_count, 238)
        artifact = json.loads(activation.artifact_manifest_bytes())
        receipt = json.loads(activation.installation_receipt_bytes())
        self.assertEqual(artifact["verification"]["core_tests"], 522)
        self.assertEqual(artifact["verification"]["local_max_output_tokens"], 192)
        self.assertFalse(artifact["verification"]["private_content_present"])
        self.assertFalse(artifact["verification"]["deepseek_output_limits_changed"])
        self.assertEqual(receipt["tree_sha256"], activation.TARGET_RELEASE)

    def test_plan_preserves_boundaries_and_changes_only_local_output_limit(self) -> None:
        plan = json.loads(activation.plan_bytes())
        self.assertEqual(plan["target"]["local_input_limit_characters"], 14_000)
        self.assertEqual(plan["target"]["local_max_output_tokens"], 192)
        self.assertEqual(plan["target"]["local_thinking"], "disabled-fail-closed")
        self.assertEqual(
            plan["target"]["deepseek_output_limits"],
            "unchanged-768-4096",
        )
        self.assertEqual(
            plan["target"]["session_store"],
            "unchanged-128-message-window",
        )
        self.assertTrue(plan["rollback"]["preserve_profile_and_session_data"])

    def test_selector_targets_only_the_content_addressed_release(self) -> None:
        _binding, selector = activation.target_binding("a" * 64)
        text = selector.decode("utf-8")
        self.assertIn(activation.TARGET_RELEASE, text)
        self.assertNotIn(activation.CURRENT_RELEASE, text)
        self.assertNotIn("Authorization", text)

    def test_activation_has_no_health_provider_or_private_content_probe(self) -> None:
        source = (
            SCRIPTS / "activate_p07_core_local_output_cap_v1.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "/healthz",
            "/readyz",
            "/chat/completions",
            "urllib",
            "profile.toml",
            "git push",
            "docker system prune",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("local_max_output_tokens", source)
        self.assertIn("raw_message_recorded", source)
        self.assertIn("restore_binding_and_selector_exact_bytes", source)


if __name__ == "__main__":
    unittest.main()
