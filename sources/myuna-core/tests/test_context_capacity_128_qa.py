from __future__ import annotations

import unittest

from myuna_core.config import load_settings
from myuna_core.context_window import ContextWindowPolicy
from myuna_core.conversation import ConversationInputError, parse_conversation_input
from myuna_core.providers.base import ModelRequest


PROFILE_MAX_MESSAGES = 128
PROFILE_MAX_CHARACTERS = 131_072
PROFILE_HTTP_MAX_BODY_BYTES = 1_048_576
PROFILE_MODEL_INPUT_MAX_CHARACTERS = 500_000
PROFILE_DEFINITION_MAX_CHARACTERS = 300_000
SATURATED_REQUEST_MESSAGES = PROFILE_MAX_MESSAGES - 1


def _messages(count: int, total_characters: int) -> list[dict[str, str]]:
    remaining = total_characters
    result: list[dict[str, str]] = []
    for index in range(count):
        remaining_slots = count - index - 1
        take = min(4_000, remaining - remaining_slots)
        if take < 1:
            raise AssertionError("invalid synthetic allocation")
        result.append(
            {
                "role": "user" if index % 2 == 0 else "assistant",
                "content": "界" * take,
            }
        )
        remaining -= take
    if remaining:
        raise AssertionError("synthetic allocation did not consume the budget")
    return result


class ContextCapacity128CoreQATests(unittest.TestCase):
    def test_saturated_profile_is_127_core_messages_not_128(self) -> None:
        policy = ContextWindowPolicy(
            max_messages=PROFILE_MAX_MESSAGES,
            max_characters=PROFILE_MAX_CHARACTERS,
        )
        messages = _messages(SATURATED_REQUEST_MESSAGES, PROFILE_MAX_CHARACTERS)
        parsed = parse_conversation_input(
            {"messages": messages},
            context_policy=policy,
        )
        self.assertEqual(len(parsed.messages), SATURATED_REQUEST_MESSAGES)
        self.assertEqual(
            sum(len(item["content"]) for item in parsed.messages),
            PROFILE_MAX_CHARACTERS,
        )

        with self.assertRaises(ConversationInputError):
            parse_conversation_input(
                {
                    "messages": _messages(
                        PROFILE_MAX_MESSAGES,
                        PROFILE_MAX_CHARACTERS,
                    )
                },
                context_policy=policy,
            )

    def test_candidate_complete_input_budget_fits_initial_and_repair(self) -> None:
        conversation = _messages(
            SATURATED_REQUEST_MESSAGES,
            PROFILE_MAX_CHARACTERS,
        )
        initial = ModelRequest(
            request_id="context128-initial",
            messages=(
                {
                    "role": "system",
                    "content": "S" * PROFILE_DEFINITION_MAX_CHARACTERS,
                },
                *conversation,
            ),
            max_output_tokens=4_096,
            max_input_characters=PROFILE_MODEL_INPUT_MAX_CHARACTERS,
        )
        self.assertEqual(len(initial.messages), PROFILE_MAX_MESSAGES)
        self.assertEqual(
            sum(len(item["content"]) for item in initial.messages),
            431_072,
        )

        repair = ModelRequest(
            request_id="context128-repair",
            messages=(
                *initial.messages,
                {"role": "assistant", "content": "R" * 32_000},
                {"role": "user", "content": "C" * 8_000},
            ),
            max_output_tokens=4_096,
            max_input_characters=PROFILE_MODEL_INPUT_MAX_CHARACTERS,
        )
        self.assertEqual(
            sum(len(item["content"]) for item in repair.messages),
            471_072,
        )

    def test_current_400000_complete_input_budget_blocks_full_profile(self) -> None:
        conversation = _messages(
            SATURATED_REQUEST_MESSAGES,
            PROFILE_MAX_CHARACTERS,
        )
        with self.assertRaises(ValueError):
            ModelRequest(
                request_id="context128-current-budget-block",
                messages=(
                    {
                        "role": "system",
                        "content": "S" * PROFILE_DEFINITION_MAX_CHARACTERS,
                    },
                    *conversation,
                ),
                max_output_tokens=768,
                max_input_characters=400_000,
            )

    def test_candidate_configuration_is_inside_existing_core_hard_bounds(self) -> None:
        settings = load_settings(
            {
                "MYUNA_CONTEXT_MAX_MESSAGES": str(PROFILE_MAX_MESSAGES),
                "MYUNA_CONTEXT_MAX_CHARACTERS": str(PROFILE_MAX_CHARACTERS),
                "MYUNA_HTTP_MAX_BODY_BYTES": str(PROFILE_HTTP_MAX_BODY_BYTES),
                "MYUNA_DEFINITION_PROMPT_MAX_CHARACTERS": str(
                    PROFILE_DEFINITION_MAX_CHARACTERS
                ),
                "MYUNA_MODEL_INPUT_MAX_CHARACTERS": str(
                    PROFILE_MODEL_INPUT_MAX_CHARACTERS
                ),
            }
        )
        self.assertEqual(settings.conversation_max_messages, PROFILE_MAX_MESSAGES)
        self.assertEqual(
            settings.conversation_max_characters,
            PROFILE_MAX_CHARACTERS,
        )
        self.assertEqual(settings.http_max_body_bytes, PROFILE_HTTP_MAX_BODY_BYTES)
        self.assertEqual(
            settings.definition_prompt_max_characters,
            PROFILE_DEFINITION_MAX_CHARACTERS,
        )
        self.assertEqual(
            settings.model_input_max_characters,
            PROFILE_MODEL_INPUT_MAX_CHARACTERS,
        )


if __name__ == "__main__":
    unittest.main()
