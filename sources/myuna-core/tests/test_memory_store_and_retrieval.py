from __future__ import annotations

from datetime import datetime, timezone
import unittest

from myuna_core.memory.in_memory import InMemoryStore
from myuna_core.memory.models import (
    ConfirmationLevel,
    MemoryCandidate,
    MemoryKind,
    MemoryQuery,
    MemorySource,
    SourceKind,
    TimePrecision,
)
from myuna_core.memory.policy import DefaultMemoryPolicy
from myuna_core.memory.retrieval import ExplainableRetriever


NOW = datetime(2042, 5, 9, 12, 0, tzinfo=timezone.utc)


def build_record(
    memory_id: str,
    text: str,
    *,
    kind: MemoryKind = MemoryKind.PREFERENCE,
    confirmation: ConfirmationLevel = ConfirmationLevel.USER_CONFIRMED,
    scope: tuple[str, ...] = ("global",),
    directive: str = "",
    supersedes_id: str | None = None,
    namespace_id: str = "ns-synthetic-dev",
):
    source = MemorySource(
        f"source-{memory_id}",
        SourceKind.CONVERSATION,
        "synthetic://test",
        NOW,
        namespace_id=namespace_id,
    )
    candidate = MemoryCandidate(
        memory_id=memory_id,
        source=source,
        kind=kind,
        text=text,
        occurred_at=NOW,
        recorded_at=NOW,
        timezone="UTC",
        time_precision=TimePrecision.MINUTE,
        scope=scope,
        importance=0.8,
        confirmation=confirmation,
        directive_text=directive,
        supersedes_id=supersedes_id,
    )
    policy = DefaultMemoryPolicy()
    decision = policy.evaluate(candidate, NOW)
    record = policy.materialize(candidate, decision)
    if record is None:
        raise AssertionError("test candidate unexpectedly excluded")
    return record


class MemoryStoreAndRetrievalTests(unittest.TestCase):
    def test_store_rejects_duplicate_ids(self) -> None:
        store = InMemoryStore()
        record = build_record("duplicate", "合成内容")
        store.append(record)
        with self.assertRaises(ValueError):
            store.append(record)

    def test_scoped_current_state_can_override_confirmed_baseline(self) -> None:
        store = InMemoryStore()
        store.append(build_record("baseline", "平时喜欢茉莉花茶饮料"))
        store.append(
            build_record(
                "current",
                "今天暂时喜欢咖啡饮料",
                kind=MemoryKind.CURRENT_STATE,
                confirmation=ConfirmationLevel.OBSERVED,
                scope=("day:2042-05-09",),
            )
        )
        result = ExplainableRetriever(store).retrieve(
            MemoryQuery("喜欢饮料", scope=("day:2042-05-09",), at=NOW)
        )
        self.assertEqual(result.hits[0].record.memory_id, "current")
        self.assertIn("scoped_current_state_override", result.hits[0].reasons)

    def test_correction_hides_superseded_record(self) -> None:
        store = InMemoryStore()
        store.append(build_record("old", "旧书店在七号"))
        store.append(build_record("new", "更正旧书店在九号", supersedes_id="old"))
        result = ExplainableRetriever(store).retrieve(MemoryQuery("旧书店", at=NOW))
        self.assertEqual(result.hits[0].record.memory_id, "new")
        self.assertEqual(result.trace.filtered["superseded"], 1)

    def test_suppressed_record_is_on_demand_but_not_proactive(self) -> None:
        store = InMemoryStore()
        store.append(build_record("quiet", "雨天散步蓝桥", directive="忘了吧"))
        retriever = ExplainableRetriever(store)
        self.assertEqual(
            retriever.retrieve(MemoryQuery("雨天散步", at=NOW)).hits[0].record.memory_id,
            "quiet",
        )
        proactive = retriever.retrieve(MemoryQuery("雨天散步", at=NOW, proactive=True))
        self.assertFalse(proactive.hits)
        self.assertEqual(proactive.trace.filtered["proactive_suppression"], 1)

    def test_namespace_filter_blocks_cross_principal_memory(self) -> None:
        store = InMemoryStore()
        store.append(build_record("owner", "蓝色纸星", namespace_id="ns-owner"))
        store.append(build_record("friend", "蓝色纸星", namespace_id="ns-friend"))
        result = ExplainableRetriever(store).retrieve(
            MemoryQuery("蓝色纸星", namespace_id="ns-owner", principal_id="principal-owner")
        )
        self.assertEqual([hit.record.memory_id for hit in result.hits], ["owner"])
        self.assertEqual(result.trace.filtered["namespace_mismatch"], 1)


if __name__ == "__main__":
    unittest.main()
