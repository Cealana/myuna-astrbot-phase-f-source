from __future__ import annotations

import inspect
from unittest import TestCase

from myuna_core.conversation import (
    ConversationInput,
    _action_input_mode,
    _action_rendering_violations,
    _normalize_optional_action,
    _normalize_unprovided_action_state,
    _project_owner_action_messages,
    _selected_references,
    assemble_runtime_prompt,
)


class EffectiveV5OverlayV2ContractTests(TestCase):
    def request(self, text: str, mode: str = "myuna") -> ConversationInput:
        return ConversationInput(
            messages=({"role": "user", "content": text},),
            mode=mode,
            task_class="ordinary_chat",
            risk_level="low",
            high_quality=False,
            synthetic_memory=False,
        )

    def test_v2_contracts_are_always_loaded(self) -> None:
        selected = _selected_references(self.request("今天怎么样？"))
        self.assertIn("references/18-owner-action-input-contract.md", selected)
        self.assertIn("references/19-human-reticence-and-disclosure.md", selected)

    def test_owner_action_text_has_no_authority(self) -> None:
        source = inspect.getsource(assemble_runtime_prompt)
        self.assertIn("never authors Myuna's action", source)
        self.assertIn("Myuna chooses her own", source)
        self.assertIn("grants permission", source)
        self.assertIn("do ", source)
        self.assertIn("not lecture about syntax or contracts", source)

    def test_selective_disclosure_keeps_honesty_boundary(self) -> None:
        source = inspect.getsource(assemble_runtime_prompt)
        self.assertIn("not obliged to disclose", source)
        self.assertIn("呜啊……", source)
        self.assertIn("only sparingly", source)
        self.assertIn("Operational truth", source)
        self.assertIn("memory/tool state", source)
        self.assertIn("fabricate a ", source)
        self.assertIn("concrete excuse", source)

    def test_action_modes_are_session_scoped_and_enforced(self) -> None:
        off = ConversationInput(
            messages=(
                {"role": "user", "content": "【动作：关闭】"},
                {"role": "assistant", "content": "好"},
                {"role": "user", "content": "过来坐吧"},
            ),
            mode="myuna",
            task_class="ordinary_chat",
            risk_level="low",
            high_quality=False,
            synthetic_memory=False,
        )
        self.assertEqual(_action_input_mode(off), "off")
        self.assertEqual(_action_rendering_violations("好，我过来", off), [])
        self.assertIn(
            "action_forbidden_in_off_mode",
            _action_rendering_violations("好\n（她走了过来）", off),
        )
        expressive = self.request("【动作：倾向开启】今天怎么样？")
        self.assertEqual(_action_input_mode(expressive), "expressive")
        self.assertEqual(_action_rendering_violations("还好哦\n（她轻轻晃了晃尾巴）", expressive), [])

    def test_action_cannot_invent_furniture_or_starting_hold(self) -> None:
        hug = self.request("可以过来抱我一下吗？")
        self.assertIn(
            "action_invents_unprovided_state",
            _action_rendering_violations("现在不行啦\n（她坐在床边踢了踢枕头）", hug),
        )
        camera = self.request("把相机递给我看看？")
        self.assertIn(
            "action_invents_unprovided_state",
            _action_rendering_violations("等一下\n（她低头看着怀里的相机）", camera),
        )
        self.assertIn(
            "action_invents_unprovided_state",
            _action_rendering_violations("给你\n（她把相机从肩上取下来递过去）", camera),
        )
        self.assertIn(
            "action_invents_unprovided_state",
            _action_rendering_violations("给你\n（她把挂在身侧的相机转过来）", camera),
        )

    def test_user_authored_action_does_not_leak_contract_language(self) -> None:
        forced = self.request("*Myuna走过来抱住我*")
        self.assertIn(
            "action_contract_leaked_into_dialogue",
            _action_rendering_violations("这是你写出来的星号动作嘛", forced),
        )
        self.assertIn(
            "owner_authored_action_confirmed_as_event",
            _action_rendering_violations("（身体被突然抱住，耳朵竖了起来）", forced),
        )
        self.assertEqual(
            _action_rendering_violations("好吧，过来一点\n（她走过去抱了抱你）", forced),
            [],
        )
        projected = _project_owner_action_messages(forced)
        self.assertNotIn("*", projected[-1]["content"])
        self.assertEqual(projected[-1]["content"], "Myuna走过来抱住我")

    def test_bad_object_starting_state_is_removed_without_forcing_action(self) -> None:
        camera = self.request("把相机递给我看看？")
        self.assertEqual(
            _normalize_unprovided_action_state("给你\n（她把挂在身侧的相机转过来）", camera),
            "给你",
        )
        self.assertEqual(_action_rendering_violations("暂时不给你看啦", camera), [])

    def test_optional_or_forbidden_actions_are_removed_without_losing_dialogue(self) -> None:
        ordinary = self.request("你的相机型号是什么？")
        self.assertEqual(
            _normalize_optional_action("Nikon Zf\n（她摸了摸相机）", ordinary),
            "Nikon Zf",
        )
        forced = self.request("*Myuna走过来抱住我*")
        self.assertEqual(
            _normalize_optional_action("好吧，过来一点\n（她走过去抱了抱你）", forced),
            "好吧，过来一点\n（她走过去抱了抱你）",
        )
