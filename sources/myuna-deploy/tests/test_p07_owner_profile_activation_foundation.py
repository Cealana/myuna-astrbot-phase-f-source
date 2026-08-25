from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class P07OwnerProfileActivationFoundationTests(unittest.TestCase):
    def test_channel_profile_is_owner_private_read_only_and_channel_bounded(self) -> None:
        payload = json.loads(
            (
                ROOT
                / "config/capabilities/owner-private-profile-read-v1.json"
            ).read_text("utf-8")
        )
        self.assertEqual(payload["response_scope"], "owner_private_dev_profile_read_v1")
        self.assertEqual(payload["memory_protocol"], "profile-v1")
        self.assertEqual(
            set(payload["subject"]["channel_kinds"]),
            {"astrbot_qq", "astrbot_telegram"},
        )
        self.assertEqual(payload["subject"]["conversation_kinds"], ["private"])
        self.assertEqual(payload["subject"]["authority_levels"], ["owner"])
        capabilities = payload["capabilities"]
        self.assertTrue(capabilities["conversation"])
        self.assertTrue(capabilities["long_term_memory_read"])
        self.assertFalse(capabilities["long_term_memory_write"])
        self.assertFalse(capabilities["tools"])
        self.assertFalse(capabilities["external_actions"])

    def test_adr_keeps_deepseek_and_live_prompt_injection_blocked(self) -> None:
        text = (
            ROOT / "docs/ADR-053-owner-profile-activation-boundary-v1.md"
        ).read_text("utf-8")
        self.assertIn("structurally forbids `deepseek`", text)
        self.assertIn("authenticated context", text)
        self.assertIn("must not call the Profile service", text)
        self.assertIn("no fallback to legacy memory", text)
        self.assertIn("No encryption claim is made", text)
        self.assertIn("PROFILE_SERVICE_SOURCE_READY_PROVIDER_EGRESS_BLOCKED", text)

    def test_threat_model_covers_provider_and_context_forgery(self) -> None:
        text = (
            ROOT / "docs/p07a-owner-profile-privacy-threat-model-v1.md"
        ).read_text("utf-8")
        self.assertIn("Profile is sent to the selected DeepSeek route", text)
        self.assertIn("Gateway credential is mistaken", text)
        self.assertIn("Worker response forges provenance", text)


if __name__ == "__main__":
    unittest.main()
