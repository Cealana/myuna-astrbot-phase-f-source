from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import activate_p07_core_local_definition_projection_v1 as activation  # noqa: E402


class P07CoreLocalDefinitionProjectionActivationTests(unittest.TestCase):
    def test_release_evidence_and_receipts_are_content_free(self) -> None:
        evidence = activation.target_evidence()
        self.assertEqual(evidence.tree_sha256, activation.TARGET_RELEASE)
        self.assertEqual(evidence.source_commit, activation.TARGET_COMMIT)
        self.assertEqual(evidence.file_count, 238)
        artifact = json.loads(activation.artifact_manifest_bytes())
        receipt = json.loads(activation.installation_receipt_bytes())
        self.assertEqual(artifact["verification"]["core_tests"], 519)
        self.assertEqual(
            artifact["verification"]["local_definition_projection"],
            "entrypoint-only-v1",
        )
        self.assertFalse(artifact["verification"]["private_content_present"])
        self.assertEqual(receipt["tree_sha256"], activation.TARGET_RELEASE)

    def test_plan_preserves_session_profile_and_both_owner_channels(self) -> None:
        plan = json.loads(activation.plan_bytes())
        self.assertEqual(plan["target"]["local_input_limit_characters"], 24_000)
        self.assertEqual(
            plan["target"]["definition_projection"],
            "approved-skill-entrypoint-only-v1",
        )
        self.assertFalse(plan["target"]["definition_source_mutated"])
        self.assertEqual(
            plan["target"]["non_local_definition_projection"],
            "full-unchanged",
        )
        self.assertEqual(
            plan["target"]["session_store"],
            "unchanged-128-message-window",
        )
        self.assertEqual(
            plan["live_scope"]["gateway_quiesce_restore"],
            ["qq-owner-private", "telegram-owner-private"],
        )
        self.assertTrue(plan["rollback"]["preserve_profile_and_session_data"])

    def test_selector_targets_only_the_content_addressed_core_release(self) -> None:
        _binding, selector = activation.target_binding("a" * 64)
        text = selector.decode("utf-8")
        self.assertIn(activation.TARGET_RELEASE, text)
        self.assertNotIn(activation.CURRENT_RELEASE, text)
        self.assertNotIn("Authorization", text)

    def test_activation_has_no_health_provider_or_private_content_probe(self) -> None:
        source = (
            SCRIPTS / "activate_p07_core_local_definition_projection_v1.py"
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
        self.assertIn("raw_message_recorded", source)
        self.assertIn("retain_installed_release", source)
        self.assertIn("PRE_BINDING.json", source)

    def test_active_uses_systemctl_exit_status(self) -> None:
        with mock.patch.object(activation.subprocess, "run") as run:
            run.return_value.returncode = 3
            self.assertFalse(activation.active("inactive.service"))
            run.return_value.returncode = 0
            self.assertTrue(activation.active("active.service"))


if __name__ == "__main__":
    unittest.main()
