from __future__ import annotations

import unittest

from myuna_core.config import load_settings
from myuna_core.context_window import ContextWindowPolicy
from myuna_core.conversation import ConversationInputError, parse_conversation_input
from myuna_core.providers.base import ModelRequest


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


class ContextCapacity36CoreQATests(unittest.TestCase):
    def test_saturated_profile_is_35_core_messages_not_36(self) -> None:
        policy = ContextWindowPolicy(max_messages=36, max_characters=48_000)
        messages = _messages(35, 48_000)
        parsed = parse_conversation_input(
            {"messages": messages},
            context_policy=policy,
        )
        self.assertEqual(len(parsed.messages), 35)
        self.assertEqual(sum(len(item["content"]) for item in parsed.messages), 48_000)

        with self.assertRaises(ConversationInputError):
            parse_conversation_input(
                {"messages": _messages(36, 48_000)},
                context_policy=policy,
            )

    def test_system_persona_and_memory_share_the_complete_model_budget(self) -> None:
        conversation = _messages(35, 48_000)
        request = ModelRequest(
            request_id="context36-pass",
            messages=(
                {"role": "system", "content": "S" * 300_000},
                *conversation,
            ),
            max_output_tokens=128,
            max_input_characters=400_000,
        )
        self.assertEqual(len(request.messages), 36)
        self.assertEqual(sum(len(item["content"]) for item in request.messages), 348_000)

    def test_single_message_over_4000_characters_fails_closed(self) -> None:
        policy = ContextWindowPolicy(max_messages=36, max_characters=48_000)
        with self.assertRaises(ConversationInputError):
            parse_conversation_input(
                {"messages": [{"role": "user", "content": "超" * 4_001}]},
                context_policy=policy,
            )
        recovered = parse_conversation_input(
            {"messages": [{"role": "user", "content": "synthetic-recovery"}]},
            context_policy=policy,
        )
        self.assertEqual(recovered.messages[-1]["content"], "synthetic-recovery")

    def test_128_is_not_safe_from_numeric_support_alone(self) -> None:
        conversation = _messages(127, 131_072)
        with self.assertRaises(ValueError):
            ModelRequest(
                request_id="context128-blocked",
                messages=(
                    {"role": "system", "content": "S" * 300_000},
                    *conversation,
                ),
                max_output_tokens=128,
                max_input_characters=400_000,
            )

    def test_candidate_http_limit_is_within_existing_core_bounds(self) -> None:
        settings = load_settings(
            {
                "MYUNA_CONTEXT_MAX_MESSAGES": "36",
                "MYUNA_CONTEXT_MAX_CHARACTERS": "48000",
                "MYUNA_HTTP_MAX_BODY_BYTES": "327680",
            }
        )
        self.assertEqual(settings.conversation_max_messages, 36)
        self.assertEqual(settings.conversation_max_characters, 48_000)
        self.assertEqual(settings.http_max_body_bytes, 327_680)


if __name__ == "__main__":
    unittest.main()
