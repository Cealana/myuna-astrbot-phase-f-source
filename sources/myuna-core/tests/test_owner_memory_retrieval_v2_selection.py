from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import unittest

from owner_memory_retrieval_v2 import retrieve_records


NOW = datetime(2026, 7, 21, 1, 0, tzinfo=timezone.utc)


def record(
    memory_id: str,
    text: str,
    *,
    subtype: str,
    tags: list[str],
    occurred_at: datetime | None = None,
    sensitivity: str = "normal",
    namespace: str = "ns-owner-cealana-private",
    confirmation: str = "user_confirmed",
    status: str = "confirmed",
    importance: float = 0.9,
    kind: str = "preference",
) -> dict[str, object]:
    return {
        "candidate_id": memory_id,
        "namespace_id": namespace,
        "memory_kind": kind,
        "subtype": subtype,
        "memory_status": status,
        "confirmation_level": confirmation,
        "importance": importance,
        "sensitivity": sensitivity,
        "assertion_text": text,
        "event_text": None,
        "exact_quote": text if kind == "exact_quote" else None,
        "occurred_at": (occurred_at or NOW).isoformat(),
        "time_precision": "minute",
        "time_phrase": "凌晨",
        "scope": ["global", "owner_private"],
        "tags": tags,
        "rationales": [],
        "anchors": [],
        "relations": [],
        "review_items": [],
    }


def base_records(*, old: bool = True) -> list[dict[str, object]]:
    occurred_at = NOW - timedelta(days=6) if old else NOW
    return [
        record(
            "M001",
            "Cealana 希望重要记忆保留完整背景，Myuna 成为可靠的记忆锚点。",
            subtype="memory_anchor_preference",
            tags=["memory", "recollection", "anchor_preference"],
            occurred_at=occurred_at,
            importance=0.95,
        ),
        record(
            "M003",
            "第一次与重要时刻应保留具体时间和详细经过。",
            subtype="detailed_memory_preference",
            tags=["firsts", "important_moment", "detail", "time"],
            occurred_at=occurred_at,
        ),
        record(
            "M013",
            "一对一私聊默认保存完整档案，并允许本地模型在闲置时整理。",
            subtype="complete_private_archive_preference",
            tags=["full_archive", "one_to_one", "local_organizer"],
            occurred_at=occurred_at,
        ),
    ]


class SelectionTests(unittest.TestCase):
    def test_both_real_failure_queries_select_m001_despite_age(self) -> None:
        for query in (
            "还记得我们最开始讨论长期记忆时，我希望你怎样保留那些重要的事情吗？",
            "我希望长期记忆怎样保留重要的事情？",
        ):
            with self.subTest(query=query):
                result = retrieve_records(base_records(), query=query, at=NOW)
                self.assertEqual(result.horizon_used, "deep")
                self.assertEqual(result.scores[0].memory_id, "M001")

    def test_long_question_is_not_diluted_by_conversational_scaffolding(self) -> None:
        short = retrieve_records(
            base_records(),
            query="长期记忆怎样保留重要的事情",
            at=NOW,
        )
        long = retrieve_records(
            base_records(),
            query="唔，我突然想起来了——还记得我们最开始讨论长期记忆时，我希望你怎样保留那些重要的事情吗？",
            at=NOW,
        )
        self.assertEqual(short.scores[0].memory_id, "M001")
        self.assertEqual(long.scores[0].memory_id, "M001")

    def test_ordinary_recent_query_does_not_scan_old_history(self) -> None:
        result = retrieve_records(base_records(), query="今天有点困", at=NOW)
        self.assertEqual(result.horizon_used, "recent")
        self.assertFalse(result.fallback_used)
        self.assertEqual(result.records, ())
        self.assertGreater(result.filtered.get("outside_recent_window", 0), 0)

    def test_recent_query_can_select_recent_record(self) -> None:
        records = base_records(old=False)
        records.append(
            record(
                "RECENT001",
                "今天正在进行检索候选测试。",
                subtype="current_test_state",
                tags=["deployment", "temporary_state"],
                occurred_at=NOW,
                status="provisional",
            )
        )
        result = retrieve_records(records, query="今天正在进行什么测试", at=NOW)
        self.assertEqual(result.horizon_used, "recent")
        self.assertEqual(result.scores[0].memory_id, "RECENT001")

    def test_restricted_and_wrong_namespace_are_never_selected(self) -> None:
        records = base_records()
        records.extend(
            [
                record(
                    "RESTRICTED",
                    "长期记忆的重要秘密。",
                    subtype="memory_anchor_preference",
                    tags=["memory", "anchor_preference"],
                    sensitivity="restricted",
                    importance=1.0,
                ),
                record(
                    "OTHER",
                    "长期记忆的重要秘密。",
                    subtype="memory_anchor_preference",
                    tags=["memory", "anchor_preference"],
                    namespace="ns-other",
                    importance=1.0,
                ),
            ]
        )
        result = retrieve_records(records, query="长期记忆怎样保留重要的事情", at=NOW)
        self.assertNotIn("RESTRICTED", [score.memory_id for score in result.scores])
        self.assertNotIn("OTHER", [score.memory_id for score in result.scores])
        self.assertEqual(result.filtered.get("sensitivity_not_normal"), 1)
        self.assertEqual(result.filtered.get("namespace_mismatch"), 1)

    def test_unconfirmed_and_inactive_records_are_never_selected(self) -> None:
        records = [
            record(
                "PROPOSED",
                "长期记忆应该保留重要事情。",
                subtype="memory_anchor_preference",
                tags=["memory", "anchor_preference"],
                confirmation="model_proposed",
            ),
            record(
                "REVOKED",
                "长期记忆应该保留重要事情。",
                subtype="memory_anchor_preference",
                tags=["memory", "anchor_preference"],
                status="revoked",
            ),
        ]
        result = retrieve_records(records, query="长期记忆怎样保留重要事情", at=NOW)
        self.assertEqual(result.records, ())

    def test_audit_metadata_contains_no_record_text_or_raw_query(self) -> None:
        secret = "这段正文不能进入审计"
        records = base_records()
        records[0]["assertion_text"] = secret
        result = retrieve_records(records, query="长期记忆怎样保留重要事情", at=NOW)
        encoded = json.dumps(result.audit_metadata(), ensure_ascii=False)
        self.assertNotIn(secret, encoded)
        self.assertNotIn("长期记忆怎样保留重要事情", encoded)
        self.assertFalse(result.audit_metadata()["model_called"])
        self.assertFalse(result.audit_metadata()["memory_write_performed"])
        self.assertFalse(result.audit_metadata()["restricted_included"])

    def test_complete_archive_is_distinct_from_memory_anchor(self) -> None:
        result = retrieve_records(
            base_records(),
            query="一对一私聊是不是默认保存完整档案并在闲置时整理",
            at=NOW,
        )
        self.assertEqual(result.scores[0].memory_id, "M013")

    def test_deep_runner_ups_need_specific_topic_overlap(self) -> None:
        records = base_records()
        records.append(
            record(
                "M004",
                "原始回忆不应为了节省空间压缩掉细节。",
                subtype="archive_detail_preference",
                tags=["archive", "detail", "lossless_source"],
            )
        )
        result = retrieve_records(
            records,
            query="原始回忆可以为了节省空间压缩掉细节吗",
            at=NOW,
        )
        self.assertEqual([score.memory_id for score in result.scores], ["M004"])

    def test_authoritative_tags_are_not_polluted_by_generic_record_words(self) -> None:
        records = base_records()
        records[1]["assertion_text"] = "保存长期记忆里所有重要事情的详细经过。"
        result = retrieve_records(
            records,
            query="我希望长期记忆怎样保留重要的事情？",
            at=NOW,
        )
        self.assertEqual(result.scores[0].memory_id, "M001")

    def test_single_type_concept_cannot_select_unrelated_memory(self) -> None:
        records = base_records()
        records.append(
            record(
                "M002",
                "我真的很喜欢回忆",
                subtype="exact_quote_anchor",
                tags=["exact_quote", "memory", "recollection"],
                kind="exact_quote",
            )
        )
        for query in (
            "还记得我的钥匙放在哪里吗？",
            "我说过明天要重启服务器吗？",
            "为什么我会喜欢蓝色？",
        ):
            with self.subTest(query=query):
                result = retrieve_records(records, query=query, at=NOW)
                self.assertEqual(result.records, ())


if __name__ == "__main__":
    unittest.main()
