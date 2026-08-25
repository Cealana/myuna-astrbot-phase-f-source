from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import activate_p07c_core_write_source_v1 as activation  # noqa: E402


class P07CCoreWriteSourceActivationTests(unittest.TestCase):
    def test_release_evidence_is_content_addressed_and_content_free(self) -> None:
        evidence = activation.target_evidence()
        self.assertEqual(evidence.tree_sha256, activation.TARGET_RELEASE)
        self.assertEqual(evidence.source_commit, activation.TARGET_COMMIT)
        self.assertEqual(evidence.file_count, 261)
        artifact = json.loads(activation.artifact_manifest_bytes())
        self.assertEqual(artifact["verification"]["core_tests"], 609)
        self.assertEqual(artifact["verification"]["candidate_max_changes"], 3)
        self.assertFalse(artifact["verification"]["private_content_present"])
        self.assertFalse(artifact["verification"]["candidate_source_retained"])

    def test_plan_installs_no_writer_and_preserves_other_memory_layers(self) -> None:
        plan = json.loads(activation.plan_bytes())
        self.assertEqual(
            plan["target"]["profile_writer_source"],
            "present-but-disabled-until-separate-activation",
        )
        self.assertEqual(
            plan["target"]["legacy_session_p08_p10_write"], "disabled"
        )
        self.assertFalse(plan["live_scope"]["profile_writer_install"])
        self.assertTrue(plan["live_scope"]["model_calls_forbidden"])
        self.assertTrue(plan["live_scope"]["channel_messages_forbidden"])
        self.assertEqual(plan["live_scope"]["local_provider_restart"], 0)

    def test_selector_targets_only_the_new_release(self) -> None:
        _binding, selector = activation.target_binding("a" * 64)
        rendered = selector.decode("utf-8")
        self.assertIn(activation.TARGET_RELEASE, rendered)
        self.assertNotIn(activation.CURRENT_RELEASE, rendered)

    def test_receipt_is_unique_and_content_free(self) -> None:
        source = (
            SCRIPTS / "activate_p07c_core_write_source_v1.py"
        ).read_text(encoding="utf-8")
        self.assertIn('f"{plan_sha256}.json"', source)
        self.assertIn("activation_receipt_conflict", source)
        self.assertNotIn("LAST_ACTIVATION.json", source)
        for forbidden in (
            "/chat/completions",
            "profile.toml",
            "raw_query",
            "git push",
            "docker system prune",
        ):
            self.assertNotIn(forbidden, source)

    def test_activation_reports_writer_still_disabled(self) -> None:
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
