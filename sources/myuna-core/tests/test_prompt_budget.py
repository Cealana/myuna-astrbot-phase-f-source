from __future__ import annotations

import unittest

from myuna_core.prompt_budget import (
    MAX_DEFINITION_PROMPT_MAX_CHARACTERS,
    MAX_MODEL_INPUT_MAX_CHARACTERS,
    PromptBudgetPolicy,
    PromptBudgetPolicyError,
)
from myuna_core.providers import ModelRequest


class PromptBudgetPolicyTests(unittest.TestCase):
    def test_default_profile_is_future_ready_but_bounded(self) -> None:
        policy = PromptBudgetPolicy.default()
        self.assertEqual(policy.definition_prompt_max_characters, 300000)
        self.assertEqual(policy.model_input_max_characters, 400000)
        self.assertEqual(
            policy.public_metadata(),
            {
                "policy": "prompt-budget-v1",
                "unit": "characters",
                "definition_prompt_max_characters": 300000,
                "model_input_max_characters": 400000,
                "minimum_model_input_headroom_characters": 65536,
            },
        )

    def test_contract_ceiling_profile_is_valid(self) -> None:
        policy = PromptBudgetPolicy(
            definition_prompt_max_characters=(
                MAX_DEFINITION_PROMPT_MAX_CHARACTERS
            ),
            model_input_max_characters=MAX_MODEL_INPUT_MAX_CHARACTERS,
        )
        self.assertEqual(policy.definition_prompt_max_characters, 524288)
        self.assertEqual(policy.model_input_max_characters, 700000)

    def test_definition_and_total_input_are_independently_enforced(self) -> None:
        policy = PromptBudgetPolicy(
            definition_prompt_max_characters=300000,
            model_input_max_characters=400000,
        )
        self.assertEqual(policy.validate_definition_prompt("x" * 300000), 300000)
        with self.assertRaisesRegex(
            PromptBudgetPolicyError,
            "Definition context exceeds configured 300000 character budget",
        ):
            policy.validate_definition_prompt("x" * 300001)

        messages = (
            {"role": "system", "content": "x" * 300000},
            {"role": "user", "content": "y" * 100000},
        )
        self.assertEqual(policy.validate_model_messages(messages), 400000)
        with self.assertRaisesRegex(
            PromptBudgetPolicyError,
            "combined model input exceeds configured 400000 character budget",
        ):
            policy.validate_model_messages(
                (*messages, {"role": "assistant", "content": "z"})
            )

    def test_policy_requires_reserved_non_definition_headroom(self) -> None:
        with self.assertRaisesRegex(PromptBudgetPolicyError, "at least 65536"):
            PromptBudgetPolicy(
                definition_prompt_max_characters=300000,
                model_input_max_characters=365535,
            )

    def test_model_request_uses_an_operational_limit_below_hard_ceiling(self) -> None:
        request = ModelRequest(
            request_id="prompt-budget-default",
            messages=({"role": "user", "content": "x" * 400000},),
            max_output_tokens=100,
        )
        self.assertEqual(request.max_input_characters, 400000)

        with self.assertRaisesRegex(ValueError, "configured 400000"):
            ModelRequest(
                request_id="prompt-budget-over-default",
                messages=({"role": "user", "content": "x" * 400001},),
                max_output_tokens=100,
            )

        expanded = ModelRequest(
            request_id="prompt-budget-expanded",
            messages=({"role": "user", "content": "x" * 500000},),
            max_output_tokens=100,
            max_input_characters=500000,
        )
        self.assertEqual(expanded.max_input_characters, 500000)


if __name__ == "__main__":
    unittest.main()
