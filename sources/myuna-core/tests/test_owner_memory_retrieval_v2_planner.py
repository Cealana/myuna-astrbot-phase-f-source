from __future__ import annotations

import unittest

from owner_memory_retrieval_v2 import detect_query_concepts, plan_query


class QueryPlannerTests(unittest.TestCase):
    def test_long_real_failure_is_deep_durable_recall(self) -> None:
        plan = plan_query(
            "还记得我们最开始讨论长期记忆时，我希望你怎样保留那些重要的事情吗？"
        )
        self.assertEqual(plan.primary_horizon, "deep")
        self.assertEqual(plan.intent, "historical_recall")
        self.assertIn("anchor_preference", plan.concepts)
        self.assertNotIn("还记得", plan.audit_metadata().values())

    def test_short_real_failure_is_deep_durable_policy(self) -> None:
        plan = plan_query("我希望长期记忆怎样保留重要的事情？")
        self.assertEqual(plan.primary_horizon, "deep")
        self.assertEqual(plan.intent, "durable_policy")
        self.assertFalse(plan.allow_deep_fallback)

    def test_ordinary_current_chat_stays_recent(self) -> None:
        plan = plan_query("今天有点困，刚刚喝了杯水")
        self.assertEqual(plan.primary_horizon, "recent")
        self.assertEqual(plan.intent, "current_context")
        self.assertFalse(plan.allow_deep_fallback)

    def test_owner_wish_without_durable_topic_stays_recent(self) -> None:
        plan = plan_query("我希望你今天晚一点回复")
        self.assertEqual(plan.primary_horizon, "recent")

    def test_exact_quote_has_highest_intent(self) -> None:
        plan = plan_query("我说过自己很喜欢回忆的原话是什么")
        self.assertEqual(plan.intent, "exact_quote_recall")
        self.assertEqual(plan.primary_horizon, "deep")

    def test_concepts_are_safe_labels_not_raw_phrases(self) -> None:
        concepts = detect_query_concepts("一对一私聊默认保存完整档案并在闲置时整理")
        self.assertIn("one_to_one", concepts)
        self.assertIn("full_archive", concepts)
        self.assertIn("local_organizer", concepts)
        self.assertNotIn("完整档案", concepts)

    def test_query_contract_is_bounded(self) -> None:
        with self.assertRaises(ValueError):
            plan_query("")
        with self.assertRaises(ValueError):
            plan_query("x" * 257)


if __name__ == "__main__":
    unittest.main()
