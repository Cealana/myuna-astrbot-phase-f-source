from __future__ import annotations

from pathlib import Path
import json
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PromptBudgetDeploymentPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = json.loads(
            (ROOT / "config/prompt-budget-profiles-v1.json").read_text(
                encoding="utf-8"
            )
        )

    def test_profiles_are_character_based_and_preserve_headroom(self) -> None:
        self.assertEqual(self.document["schema_version"], 1)
        self.assertEqual(self.document["unit"], "characters")
        headroom = self.document["minimum_model_input_headroom_characters"]
        for name, profile in self.document["profiles"].items():
            if name == "contract-ceiling":
                continue
            self.assertGreaterEqual(
                profile["model_input_max_characters"]
                - profile["definition_prompt_max_characters"],
                headroom,
            )

    def test_initial_profile_and_contract_ceiling_are_exact(self) -> None:
        self.assertEqual(
            self.document["profiles"]["v6-v7-initial"],
            {
                "definition_prompt_max_characters": 300000,
                "model_input_max_characters": 400000,
                "status": "offline-qa-only",
            },
        )
        self.assertEqual(
            self.document["profiles"]["contract-ceiling"],
            {
                "definition_prompt_max_characters": 524288,
                "model_input_max_characters": 700000,
                "status": "code-ceiling-not-an-activation-profile",
            },
        )

    def test_candidate_is_not_self_activating(self) -> None:
        activation = self.document["activation"]
        self.assertFalse(activation["automatic"])
        self.assertFalse(activation["changes_short_term_context_window"])
        self.assertTrue(activation["requires_immutable_core_release"])
        self.assertTrue(activation["requires_definition_route_measurement"])
        self.assertTrue(activation["requires_provider_context_verification"])


if __name__ == "__main__":
    unittest.main()
