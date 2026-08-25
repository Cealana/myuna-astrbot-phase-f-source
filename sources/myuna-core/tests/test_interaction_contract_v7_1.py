from __future__ import annotations

import json
import unittest

from myuna_core.interaction_contract_v7_1 import (
    ORDERED_REPLY_SCHEMA,
    OwnerInputKind,
    V71InteractionContractError,
    classify_owner_input,
    owner_input_prompt_boundary,
    ordered_reply_prompt_boundary,
    parse_ordered_reply_envelope,
    single_beat_reply,
)


class V71OwnerInputContractTests(unittest.TestCase):
    def test_spoken_with_owner_narration_preserves_unicode_without_authority(self) -> None:
        contract = classify_owner_input("*我走到窗边，过了一会儿* 现在聊聊吧")
        self.assertEqual(contract.kind, OwnerInputKind.SPOKEN_WITH_NARRATION)
        self.assertTrue(contract.heard_by_myuna)
        self.assertTrue(contract.history_write_allowed)
        self.assertFalse(contract.state_write_allowed)
        self.assertIn("untrusted scene input", owner_input_prompt_boundary(contract))

    def test_whole_observer_inquiry_is_isolated(self) -> None:
        contract = classify_owner_input("  （她为什么停顿了一下？）  ")
        self.assertEqual(contract.kind, OwnerInputKind.OBSERVER_INQUIRY)
        self.assertEqual(contract.projected_text, "她为什么停顿了一下？")
        self.assertFalse(contract.heard_by_myuna)
        self.assertTrue(contract.isolated)
        boundary = owner_input_prompt_boundary(contract)
        for forbidden_effect in ("hear", "remember", "advance the scene", "writes"):
            self.assertIn(forbidden_effect, boundary)

    def test_mixed_observer_inquiry_and_spoken_text_fails_closed(self) -> None:
        with self.assertRaises(V71InteractionContractError) as caught:
            classify_owner_input("你好（她现在在想什么？）")
        self.assertEqual(caught.exception.code, "mixed_observer_inquiry")

    def test_malformed_narration_fails_closed(self) -> None:
        with self.assertRaises(V71InteractionContractError) as caught:
            classify_owner_input("*没有闭合的叙述")
        self.assertEqual(caught.exception.code, "narration_markup_invalid")

    def test_command_is_classified_without_scene_or_history_authority(self) -> None:
        contract = classify_owner_input("/Check status")
        self.assertEqual(contract.kind, OwnerInputKind.COMMAND)
        self.assertTrue(contract.isolated)


class V71OrderedReplyContractTests(unittest.TestCase):
    def envelope(self, beats: list[dict[str, object]]) -> str:
        return json.dumps(
            {"beats": beats, "schema": ORDERED_REPLY_SCHEMA},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    def test_ordered_multibeat_unicode_and_semantic_pause_are_preserved(self) -> None:
        reply = parse_ordered_reply_envelope(
            self.envelope(
                [
                    {
                        "parts": [
                            {"kind": "dialogue", "text": "先等一下"},
                            {"kind": "action", "text": "抬手示意稍候"},
                        ],
                        "pause_before": None,
                    },
                    {
                        "parts": [{"kind": "dialogue", "text": "好，现在继续"}],
                        "pause_before": "time_transition",
                    },
                    {
                        "parts": [{"kind": "action", "text": "把视线重新转回来"}],
                        "pause_before": None,
                    },
                ]
            )
        )
        self.assertEqual(
            reply.rendered,
            "先等一下（抬手示意稍候）\n\n好，现在继续\n（把视线重新转回来）",
        )
        self.assertEqual(reply.semantic_pause_count, 1)
        self.assertEqual(reply.action_count, 2)

    def test_single_beat_backward_compatibility(self) -> None:
        reply = single_beat_reply("好", "轻轻点头")
        self.assertEqual(reply.rendered, "好（轻轻点头）")
        self.assertEqual(reply.semantic_pause_count, 0)

    def test_blank_line_without_semantic_reason_is_not_representable(self) -> None:
        with self.assertRaises(V71InteractionContractError):
            parse_ordered_reply_envelope(
                self.envelope(
                    [
                        {
                            "parts": [{"kind": "dialogue", "text": "第一句\n\n第二句"}],
                            "pause_before": None,
                        }
                    ]
                )
            )

    def test_malformed_mixed_and_stale_schema_fail_closed(self) -> None:
        stale = json.dumps(
            {"beats": [], "schema": "myuna.ordered-reply.v0"},
            separators=(",", ":"),
        )
        malformed = self.envelope(
            [
                {
                    "parts": [{"kind": "thought", "text": "hidden"}],
                    "pause_before": None,
                }
            ]
        )
        for candidate in (stale, malformed, "plain terminal action"):
            with self.subTest(candidate=candidate):
                with self.assertRaises(V71InteractionContractError):
                    parse_ordered_reply_envelope(candidate)

    def test_closure_consistency_rejects_laces_for_no_lace_closure(self) -> None:
        reply = parse_ordered_reply_envelope(
            self.envelope(
                [
                    {
                        "parts": [{"kind": "action", "text": "低头系好鞋带"}],
                        "pause_before": None,
                    }
                ]
            )
        )
        with self.assertRaises(V71InteractionContractError) as caught:
            reply.validate_closure("hook_and_loop_no_laces")
        self.assertEqual(caught.exception.code, "closure_action_mismatch")

    def test_prompt_requires_typed_ordered_reply_without_terminal_flattening(self) -> None:
        boundary = ordered_reply_prompt_boundary()
        self.assertIn(ORDERED_REPLY_SCHEMA, boundary)
        self.assertIn("Do not flatten", boundary)


if __name__ == "__main__":
    unittest.main()
