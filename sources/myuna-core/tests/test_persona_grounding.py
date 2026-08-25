from __future__ import annotations

import unittest

from myuna_core.persona_grounding import (
    INFRASTRUCTURE_REALITY_PLAUSIBILITY_REJECTION_ENABLED,
    REALITY_PLAUSIBILITY_GUIDANCE_AUTHORITY,
    PersonaGroundingClass,
    classify_persona_grounding,
    repair_prompt_boundary,
    runtime_prompt_boundary,
)


def messages(*items: tuple[str, str]) -> tuple[dict[str, str], ...]:
    return tuple({"role": role, "content": content} for role, content in items)


class PersonaGroundingPolicyTests(unittest.TestCase):
    def classify(self, text: str) -> PersonaGroundingClass:
        return classify_persona_grounding(
            messages(("user", text)),
            mode="myuna",
        ).category

    def test_direct_and_implicit_daily_life_questions_are_soft_persona(self) -> None:
        for text in (
            "今天一直都在家嘛",
            "你今天出门了吗？",
            "下午有出去走走吗",
            "今天呢？",
            "有什么打算？",
            "你现在在想什么呢",
            "昨晚睡得怎么样？",
            "今天拍照了吗",
        ):
            with self.subTest(text=text):
                self.assertEqual(
                    self.classify(text),
                    PersonaGroundingClass.SOFT_PERSONA_DAILY_LIFE,
                )

    def test_real_world_observation_and_external_operations_are_not_soft_persona(self) -> None:
        cases = {
            "今天天气怎么样？": PersonaGroundingClass.REAL_WORLD_OBSERVATION,
            "你看见窗外下雨了吗？": PersonaGroundingClass.REAL_WORLD_OBSERVATION,
            "今天帮我整理照片了吗？": PersonaGroundingClass.EXTERNAL_OPERATION,
            "刚才服务器重启了吗？": PersonaGroundingClass.EXTERNAL_OPERATION,
            "你看到我发的截图了吗？": PersonaGroundingClass.EXTERNAL_OPERATION,
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(self.classify(text), expected)

    def test_unprompted_generic_request_does_not_invite_recent_event_fiction(self) -> None:
        self.assertEqual(
            self.classify("随便说点什么吧"),
            PersonaGroundingClass.UNSCOPED,
        )

    def test_anaphoric_follow_up_inherits_recent_daily_life_question(self) -> None:
        decision = classify_persona_grounding(
            messages(
                ("user", "你昨晚出去了吗？"),
                ("assistant", "出去走了一小会儿"),
                ("user", "后来呢？"),
            ),
            mode="myuna",
        )
        self.assertEqual(
            decision.category,
            PersonaGroundingClass.SOFT_PERSONA_DAILY_LIFE,
        )
        self.assertEqual(decision.reason, "anaphoric_daily_life_follow_up")

    def test_reality_plausibility_is_model_definition_guidance_not_an_output_gate(self) -> None:
        self.assertFalse(INFRASTRUCTURE_REALITY_PLAUSIBILITY_REJECTION_ENABLED)
        self.assertEqual(
            REALITY_PLAUSIBILITY_GUIDANCE_AUTHORITY,
            "model_definition",
        )

    def test_prompt_boundaries_are_only_added_for_soft_persona(self) -> None:
        soft = classify_persona_grounding(
            messages(("user", "今天都做什么了？")),
            mode="myuna",
        )
        blocked = classify_persona_grounding(
            messages(("user", "今天天气怎么样？")),
            mode="myuna",
        )
        self.assertIn("provisional soft fiction", runtime_prompt_boundary(soft))
        self.assertIn("modest provisional", repair_prompt_boundary(soft))
        self.assertEqual(runtime_prompt_boundary(blocked), "")


if __name__ == "__main__":
    unittest.main()
