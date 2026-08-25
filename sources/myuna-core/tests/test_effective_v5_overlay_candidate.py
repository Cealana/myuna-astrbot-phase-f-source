from __future__ import annotations

import os
from unittest import TestCase, mock

from myuna_core.conversation import (
    ConversationInput,
    _action_rendering_violations,
    _normalize_action_layout,
    _normalize_undefined_detail_reply,
    _selected_references,
    _undefined_detail_violations,
    parse_model_reply_envelope,
)


class EffectiveV5OverlayCandidateTests(TestCase):
    def request(self, text: str) -> ConversationInput:
        return ConversationInput(
            messages=({"role": "user", "content": text},),
            mode="myuna",
            task_class="ordinary_chat",
            risk_level="low",
            high_quality=False,
            synthetic_memory=False,
        )

    def test_natural_equipment_loads_structured_details(self) -> None:
        for prompt in ("CMOS挂件到底是什么？", "尾巴是什么颜色？", "喜欢什么气味？", "平时喝什么？"):
            selected = _selected_references(self.request(prompt))
            self.assertIn("references/03-appearance.md", selected)
            self.assertIn("references/16-lifestyle-equipment.md", selected)

    def test_natural_movement_loads_movement(self) -> None:
        selected = _selected_references(self.request("过来坐到我旁边"))
        self.assertIn("references/04-movement.md", selected)

    def test_overlay_policy_is_always_loaded(self) -> None:
        selected = _selected_references(self.request("今天怎么样？"))
        self.assertIn("references/17-effective-v5-overlay-policy.md", selected)

    def test_runtime_prompt_contains_light_action_contract(self) -> None:
        source = __import__("inspect").getsource(__import__("myuna_core.conversation", fromlist=["assemble_runtime_prompt"]))
        self.assertIn("full-width parenthesized action", source)

    def test_required_action_is_enforced(self) -> None:
        request = self.request("过来坐到我旁边")
        self.assertEqual(_action_rendering_violations("现在不过去，等一会吧", request), [])
        self.assertEqual(
            _action_rendering_violations("嗯，来了\n（她走过来坐到旁边）", request),
            [],
        )

    def test_action_must_follow_dialogue(self) -> None:
        request = self.request("把相机递给我")
        violations = _action_rendering_violations("（她把相机递来）\n给你", request)
        self.assertIn("action_dialogue_order_invalid", violations)
        same_line = _action_rendering_violations("给你（她把相机递来）", request)
        self.assertIn("action_dialogue_order_invalid", same_line)
        normalized = _normalize_action_layout("给你（她把相机递来）")
        self.assertEqual(normalized, "给你\n（她把相机递来）")
        self.assertEqual(_action_rendering_violations(normalized, request), [])

    def test_action_must_be_terminal(self) -> None:
        request = self.request("回头看看我")
        violations = _action_rendering_violations("嗯\n（她回过头）\n怎么了", request)
        self.assertIn("action_not_terminal", violations)
        normalized = _normalize_action_layout("好哦\n（她回过头）\n怎么了")
        self.assertEqual(normalized, "好哦\n怎么了\n（她回过头）")
        self.assertEqual(_action_rendering_violations(normalized, request), [])

    def test_camera_handoff_requires_action(self) -> None:
        request = self.request("把相机递给我看看？")
        self.assertEqual(_action_rendering_violations("现在不过去，等一会吧", request), [])

    def test_unrequested_action_is_rejected_in_light_mode(self) -> None:
        request = self.request("你的相机是什么型号？")
        violations = _action_rendering_violations("是 Nikon Zf\n（她摸了摸相机）", request)
        self.assertIn("action_unrequested_in_light_mode", violations)

    def test_undefined_origin_cannot_be_speculatively_filled(self) -> None:
        request = self.request("这个挂件是从哪里得到的？")
        self.assertEqual(_undefined_detail_violations("来源还没有设定", request), [])
        self.assertIn(
            "undefined_detail_speculated",
            _undefined_detail_violations("可能是某个时候自然就有了", request),
        )
        normalized = _normalize_undefined_detail_reply(
            "不是海边纪念品哦。可能是某个时候自然就有了吧", request
        )
        self.assertEqual(normalized, "不是海边纪念品哦。")
        self.assertEqual(_undefined_detail_violations(normalized, request), [])

    def test_guarded_plain_text_is_opt_in(self) -> None:
        with mock.patch.dict(os.environ, {"MYUNA_REPLY_PLAIN_FALLBACK_ENABLED": "true"}):
            parsed = parse_model_reply_envelope("嗯，知道了")
        self.assertEqual(parsed.reply, "嗯，知道了")
        self.assertEqual(parsed.normalization, "guarded_plain_text")

    def test_json_like_malformed_text_still_fails_closed(self) -> None:
        with mock.patch.dict(os.environ, {"MYUNA_REPLY_PLAIN_FALLBACK_ENABLED": "true"}):
            with self.assertRaises(Exception):
                parse_model_reply_envelope('{"reply": broken}')
