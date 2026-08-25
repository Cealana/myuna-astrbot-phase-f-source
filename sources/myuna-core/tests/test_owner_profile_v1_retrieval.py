from __future__ import annotations

import unittest

from myuna_core.owner_profile import OwnerProfileError
from myuna_core.owner_profile.loader import parse_profile_bytes
from myuna_core.owner_profile.retrieval import (
    OwnerProfileIndex,
    retrieve_from_loader,
)
from test_owner_profile_v1_loader import BASE_PROFILE


class OwnerProfileRetrievalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = parse_profile_bytes(BASE_PROFILE)
        self.index = OwnerProfileIndex(self.profile)

    def test_chinese_relevance_selects_the_matching_section_first(self) -> None:
        result = self.index.retrieve("软件设计方法是我的什么长期目标？")
        self.assertEqual(result.state, "selected")
        self.assertEqual(result.sections[0].category, "long_term_goal")
        self.assertIn("可验证的软件设计方法", result.sections[0].body)

    def test_unicode_category_cue_selects_self_introduction(self) -> None:
        result = self.index.retrieve("请根据自我介绍说明关于我有什么资料")
        self.assertEqual(result.sections[0].category, "self_introduction")
        self.assertIn("完全合成", result.context or "")

    def test_empty_result_does_not_inject_profile(self) -> None:
        result = self.index.retrieve("天气不错")
        self.assertEqual(result.state, "empty")
        self.assertEqual(result.sections, ())
        self.assertIsNone(result.context)

    def test_result_count_is_bounded_to_three(self) -> None:
        result = self.index.retrieve(
            "自我介绍 沟通偏好 长期目标 花园项目 持续项目"
        )
        self.assertEqual(len(result.sections), 3)

    def test_context_contains_exact_provenance_and_omits_unrelated_section(self) -> None:
        result = self.index.retrieve("月光花园项目")
        self.assertEqual(len(result.sections), 1)
        context = result.context or ""
        self.assertIn("owner-profile:synthetic-owner-profile:r1:garden-project", context)
        self.assertIn(self.profile.sha256, context)
        self.assertNotIn("先给结论", context)
        self.assertLessEqual(len(context), 6_000)

    def test_overlong_query_fails_closed(self) -> None:
        with self.assertRaises(OwnerProfileError) as captured:
            self.index.retrieve("问" * 257)
        self.assertEqual(captured.exception.code, "query_out_of_contract")

    def test_index_timeout_fails_closed(self) -> None:
        ticks = iter((0.0, 1.0))
        with self.assertRaises(OwnerProfileError) as captured:
            self.index.retrieve(
                "长期目标",
                timeout_seconds=0.05,
                monotonic=lambda: next(ticks),
            )
        self.assertEqual(captured.exception.code, "profile_timeout")
        self.assertTrue(captured.exception.retryable)

    def test_source_timeout_fails_closed(self) -> None:
        def timeout_loader():
            raise TimeoutError

        with self.assertRaises(OwnerProfileError) as captured:
            retrieve_from_loader(timeout_loader, "长期目标")
        self.assertEqual(captured.exception.code, "profile_timeout")
        self.assertTrue(captured.exception.retryable)

    def test_source_unavailable_fails_closed(self) -> None:
        def unavailable_loader():
            raise OSError("synthetic unavailable")

        with self.assertRaises(OwnerProfileError) as captured:
            retrieve_from_loader(unavailable_loader, "长期目标")
        self.assertEqual(captured.exception.code, "profile_unavailable")
        self.assertTrue(captured.exception.retryable)

    def test_invalid_query_is_rejected_before_source_access(self) -> None:
        called = False

        def loader():
            nonlocal called
            called = True
            raise OSError("must not be reached")

        with self.assertRaises(OwnerProfileError) as captured:
            retrieve_from_loader(loader, "问" * 257)
        self.assertEqual(captured.exception.code, "query_out_of_contract")
        self.assertFalse(called)


if __name__ == "__main__":
    unittest.main()
