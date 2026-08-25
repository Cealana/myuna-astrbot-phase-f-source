from __future__ import annotations

import inspect
from unittest import TestCase

from myuna_core.conversation import (
    ConversationInput,
    DevConversationEngine,
    ReplyContractError,
    _action_rendering_violations,
    _normalize_action_voice,
    _normalize_optional_action,
    _project_owner_action_messages,
    _reply_contract_continuity_fallback,
    _selected_references,
    parse_model_turn_draft,
)


class EffectiveV5OverlayV3ContractTests(TestCase):
    def request(self, text: str) -> ConversationInput:
        return ConversationInput(
            messages=({"role": "user", "content": text},),
            mode="myuna",
            task_class="ordinary_chat",
            risk_level="low",
            high_quality=False,
            synthetic_memory=False,
        )

    def test_v3_contracts_are_always_loaded(self) -> None:
        selected = _selected_references(self.request("今天怎么样？"))
        self.assertIn("references/20-owner-action-clarification-v2.md", selected)
        self.assertIn("references/21-typed-turn-draft-and-reply-reliability-v1.md", selected)
        self.assertIn("references/22-subjectless-action-voice-v1.md", selected)

    def test_plain_text_turn_draft_and_terminal_action_are_typed(self) -> None:
        plain = parse_model_turn_draft("嗯，睡饱了再找你哦")
        self.assertEqual(plain.dialogue, "嗯，睡饱了再找你哦")
        self.assertIsNone(plain.action)
        self.assertEqual(plain.rendered, plain.dialogue)
        acted = parse_model_turn_draft("好啦，给我留点位置\n（她慢慢走过去坐下）")
        self.assertEqual(acted.dialogue, "好啦，给我留点位置")
        self.assertEqual(acted.action, "慢慢走过去坐下")
        self.assertEqual(acted.rendered, "好啦，给我留点位置\n（慢慢走过去坐下）")

    def test_typed_and_legacy_json_are_transition_compatible(self) -> None:
        typed = parse_model_turn_draft('{"dialogue":"好哦","action":"她走了过去"}')
        self.assertEqual(typed.rendered, "好哦\n（走了过去）")
        legacy = parse_model_turn_draft('{"reply":"好哦\\n（她走了过去）"}')
        self.assertEqual(legacy.rendered, "好哦\n（走了过去）")
        string = parse_model_turn_draft('"好哦"')
        self.assertEqual(string.dialogue, "好哦")

    def test_action_voice_is_subjectless_but_object_pronouns_are_preserved(self) -> None:
        self.assertEqual(
            _normalize_action_voice("她回过头，她的尾巴轻轻摆了一下"),
            "回过头，尾巴轻轻摆了一下",
        )
        self.assertEqual(
            _normalize_action_voice("然后我挪近了一点，抬头看着你"),
            "然后挪近了一点，抬头看着你",
        )
        self.assertEqual(_normalize_action_voice("抬头看着她"), "抬头看着她")

    def test_malformed_json_like_draft_is_never_displayed(self) -> None:
        with self.assertRaises(ReplyContractError) as caught:
            parse_model_turn_draft('{"dialogue": broken}')
        self.assertEqual(caught.exception.category, "invalid_json_like_draft")
        with self.assertRaises(ReplyContractError):
            parse_model_turn_draft("```python\nunsafe\n```")

    def test_provider_calls_use_text_drafts_for_initial_and_repair(self) -> None:
        source = inspect.getsource(DevConversationEngine.converse)
        self.assertEqual(source.count('response_format="text"'), 2)
        self.assertNotIn('response_format="json_object"', source)

    def test_direct_action_request_requires_clear_stance(self) -> None:
        request = self.request("过来坐我旁边吧")
        self.assertIn(
            "direct_action_response_ambiguous",
            _action_rendering_violations("嗯……", request),
        )
        for reply in (
            "好哦，给我留点位置",
            "现在不太想动啦，等会儿再过去",
            "现在吗？你先挪一点位置",
        ):
            with self.subTest(reply=reply):
                self.assertEqual(_action_rendering_violations(reply, request), [])

    def test_incorrect_starred_action_is_ordinary_speech(self) -> None:
        request = self.request("**Myuna走过来抱住我**")
        projected = _project_owner_action_messages(request)
        self.assertEqual(projected[-1]["content"], "Myuna走过来抱住我")
        self.assertNotIn("*", projected[-1]["content"])
        self.assertEqual(
            _action_rendering_violations("好吧，过来一点\n（她走过去抱了抱你）", request),
            [],
        )
        self.assertEqual(
            _normalize_optional_action("好吧，过来一点\n（她走过去抱了抱你）", request),
            "好吧，过来一点\n（她走过去抱了抱你）",
        )

    def test_continuity_fallback_is_capability_free_and_clear(self) -> None:
        request = self.request("过来一下")
        fallback = _reply_contract_continuity_fallback(request)
        self.assertIn("再问我一次", fallback)
        self.assertNotIn("记忆", fallback)
        self.assertNotIn("工具", fallback)
        self.assertEqual(_action_rendering_violations(fallback, request), [])
