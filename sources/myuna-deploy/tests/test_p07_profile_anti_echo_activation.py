from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import activate_p07_profile_anti_echo_v1 as activation  # noqa: E402


class P07ProfileAntiEchoActivationTests(unittest.TestCase):
    def test_release_evidence_and_manifest_are_content_free(self) -> None:
        evidence = activation.target_evidence()
        self.assertEqual(evidence.tree_sha256, activation.TARGET_RELEASE)
        self.assertEqual(evidence.source_commit, activation.TARGET_COMMIT)
        self.assertEqual(evidence.file_count, 273)
        artifact = json.loads(activation.artifact_manifest_bytes())
        verification = artifact["verification"]
        self.assertEqual(verification["core_tests"], 654)
        self.assertEqual(
            verification["recent_assistant_echo_guard"],
            "local-near-duplicate-repair-v1",
        )
        self.assertEqual(verification["similarity_threshold"], "0.90")
        self.assertTrue(verification["explicit_repeat_or_quote_exempt"])
        self.assertTrue(verification["short_reply_exempt"])
        self.assertTrue(verification["direct_profile_projection_exempt"])
        self.assertFalse(verification["private_content_present"])
        self.assertFalse(verification["profile_revision_mutated"])
        self.assertFalse(verification["session_store_mutated"])

    def test_plan_is_core_only_and_preserves_private_stores(self) -> None:
        plan = json.loads(activation.plan_bytes())
        self.assertEqual(
            plan["target"]["recent_assistant_echo_guard"],
            "local-near-duplicate-repair-v1",
        )
        self.assertEqual(
            plan["target"]["direct_profile_projection"],
            "strict-current-turn-v1-exempt",
        )
        self.assertEqual(
            plan["target"]["session_store"],
            "unchanged-128-message-window",
        )
        self.assertEqual(plan["target"]["profile_revisions"], "unchanged")
        self.assertEqual(plan["target"]["p08"], "no-write-no-double-write")
        self.assertEqual(plan["live_scope"]["core_restart_max"], 1)
        self.assertEqual(plan["live_scope"]["local_provider_restart"], 0)
        self.assertEqual(plan["live_scope"]["profile_service_restart"], 0)
        self.assertTrue(plan["live_scope"]["health_endpoints_forbidden"])
        self.assertTrue(plan["live_scope"]["channel_calls_forbidden"])
        self.assertTrue(plan["live_scope"]["provider_calls_forbidden"])

    def test_selector_targets_only_the_content_addressed_release(self) -> None:
        _binding, selector = activation.target_binding("a" * 64)
        text = selector.decode("utf-8")
        self.assertIn(activation.TARGET_RELEASE, text)
        self.assertNotIn(activation.CURRENT_RELEASE, text)

    def test_source_has_no_private_or_active_probe(self) -> None:
        source = (SCRIPTS / "activate_p07_profile_anti_echo_v1.py").read_text(
            encoding="utf-8"
        )
        for forbidden in (
            "/healthz",
            "/readyz",
            "/chat/completions",
            "profile.toml",
            "urllib",
            "sqlite3",
            "git push",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("candidate_anti_echo_probe_rejected", source)
        self.assertIn("restore_binding_and_selector_exact_bytes", source)
        self.assertIn("raw_message_recorded", source)

    def test_activation_reports_second_organic_owner_gate(self) -> None:
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
