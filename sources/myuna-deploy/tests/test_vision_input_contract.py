from __future__ import annotations

import json
from pathlib import Path
import unittest

from myuna_core.vision_input import VisionInputPolicy


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config" / "vision" / "vision-input-policy-v1.json"
ADR = ROOT / "docs" / "ADR-042-vision-input-contract-v1.md"


class VisionInputRepositoryContractTests(unittest.TestCase):
    def test_policy_loads_and_remains_inactive(self) -> None:
        policy = VisionInputPolicy.load(POLICY)
        self.assertEqual(policy.status, "inactive_candidate")
        self.assertFalse(policy.allow_remote_url_fetch)
        self.assertFalse(policy.allow_memory_write)
        self.assertFalse(policy.allow_tools)
        self.assertFalse(policy.allow_external_actions)

    def test_policy_contains_no_endpoint_secret_or_live_switch(self) -> None:
        document = json.loads(POLICY.read_text(encoding="utf-8"))
        flattened = json.dumps(document, sort_keys=True).casefold()
        for forbidden in (
            "api_key",
            "authorization",
            "base_url",
            "credential",
            "password",
            "secret",
            "token",
        ):
            self.assertNotIn(forbidden, flattened)
        self.assertNotIn("active", document)

    def test_adr_states_untrusted_evidence_and_non_effects(self) -> None:
        text = ADR.read_text(encoding="utf-8")
        for phrase in (
            "untrusted_media_content",
            "no memory write",
            "no tool or external action",
            "does not download media",
            "does not download media",
        ):
            self.assertIn(phrase, text)


if __name__ == "__main__":
    unittest.main()
