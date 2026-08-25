from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "config" / "capabilities" / "owner-private-channel-neutral-v1.json"
ADR = ROOT / "docs" / "ADR-039-modularity-wave1-authenticated-context.md"


class ModularityWave1RepositoryContractTests(unittest.TestCase):
    def test_profile_is_channel_neutral_owner_private_and_read_only(self) -> None:
        document = json.loads(PROFILE.read_text(encoding="utf-8"))
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(
            set(document["subject"]["channel_kinds"]),
            {"astrbot_qq", "astrbot_telegram"},
        )
        self.assertEqual(document["subject"]["conversation_kinds"], ["private"])
        self.assertEqual(document["subject"]["authority_levels"], ["owner"])
        self.assertNotIn("qq", document["response_scope"].casefold())
        self.assertNotIn("qq_channel", document["capabilities"])
        self.assertTrue(document["capabilities"]["conversation"])
        self.assertTrue(document["capabilities"]["long_term_memory_read"])
        for name in (
            "long_term_memory_write",
            "vision",
            "tools",
            "external_data",
            "external_actions",
            "system_administration",
        ):
            self.assertFalse(document["capabilities"][name])

    def test_candidate_contains_no_secret_or_runtime_activation_material(self) -> None:
        profile_text = PROFILE.read_text(encoding="utf-8").casefold()
        for forbidden in (
            "api_key",
            "bot_token",
            "authorization",
            "password",
            "credential",
            "systemctl",
            "execstart",
        ):
            self.assertNotIn(forbidden, profile_text)

    def test_adr_declares_repository_only_and_future_bridge_boundaries(self) -> None:
        text = ADR.read_text(encoding="utf-8")
        self.assertIn("repository-only / inactive", text)
        self.assertIn("message body cannot assert or override", text)
        self.assertIn("Effective Runtime Profile v1", text)
        self.assertIn("Shared Gateway Runtime Kernel v1", text)


if __name__ == "__main__":
    unittest.main()
