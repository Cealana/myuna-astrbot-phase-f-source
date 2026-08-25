from __future__ import annotations

from datetime import datetime, timezone
import unittest

from myuna_core.memory.hybrid import (
    HybridCandidate,
    QueryIntent,
    StructuredHybridReranker,
    analyze_query_intents,
)
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


NOW = datetime(2042, 8, 1, 12, 0, tzinfo=timezone.utc)


def record(
    memory_id: str,
    text: str,
    *,
    kind: MemoryKind = MemoryKind.EPISODIC,
    time_precision: TimePrecision = TimePrecision.MINUTE,
    supersedes_id: str | None = None,
):
    source = MemorySource(
        source_id=f"source-{memory_id}",
        kind=SourceKind.CONVERSATION,
        reference=f"synthetic://hybrid/{memory_id}",
        captured_at=NOW,
        metadata={"synthetic": True},
    )
    candidate = MemoryCandidate(
        memory_id=memory_id,
        source=source,
        kind=kind,
        text=text,
        occurred_at=NOW,
        recorded_at=NOW,
        timezone="UTC",
        time_precision=time_precision,
        importance=0.8,
        confirmation=ConfirmationLevel.USER_CONFIRMED,
        supersedes_id=supersedes_id,
    )
    policy = DefaultMemoryPolicy()
    materialized = policy.materialize(candidate, policy.evaluate(candidate, NOW))
    if materialized is None:
        raise AssertionError("synthetic test record was excluded")
    return materialized


class HybridRerankerTests(unittest.TestCase):
    def test_intent_analysis_is_deterministic(self) -> None:
        intents = analyze_query_intents("第一次发生在几点？请给完整原话")
        self.assertEqual(
            intents,
            (QueryIntent.FIRST, QueryIntent.EXACT_QUOTE, QueryIntent.TIME),
        )

    def test_first_anchor_overrides_slightly_higher_vector_near_match(self) -> None:
        first = HybridCandidate(
            record("first", "第一次独自修好音乐盒", kind=MemoryKind.ANCHOR),
            vector_score=0.49,
            lexical_score=0.2,
            anchor_kind="first",
            source_channels=("vector",),
        )
        second = HybridCandidate(
            record("second", "第二次维修音乐盒"),
            vector_score=0.52,
            lexical_score=0.25,
            source_channels=("vector", "lexical"),
        )
        result = StructuredHybridReranker().rerank(
            MemoryQuery("头一回不靠别人修好发条玩具", at=NOW),
            (second, first),
        )
        self.assertEqual(result[0].record.memory_id, "first")
        self.assertIn("first_anchor_intent_match", result[0].reasons)

    def test_correction_and_exact_quote_have_structured_components(self) -> None:
        corrected = HybridCandidate(
            record("corrected", "实际位于九号", supersedes_id="old"),
            vector_score=0.5,
            lexical_score=0.3,
        )
        quote = HybridCandidate(
            record("quote", "纸船旁的一句话", kind=MemoryKind.ANCHOR),
            vector_score=0.5,
            lexical_score=0.3,
            anchor_kind="exact_quote",
        )
        reranker = StructuredHybridReranker()
        correction_hit = reranker.rerank(
            MemoryQuery("修正后的真实地址", at=NOW), (corrected,)
        )[0]
        quote_hit = reranker.rerank(
            MemoryQuery("写在纸船旁的完整原话", at=NOW), (quote,)
        )[0]
        self.assertIn("correction_intent", correction_hit.score_components)
        self.assertIn("exact_quote_intent", quote_hit.score_components)
        self.assertAlmostEqual(
            quote_hit.score,
            sum(quote_hit.score_components.values()),
            places=5,
        )

    def test_result_trace_records_strategy_and_model_identity(self) -> None:
        candidate = HybridCandidate(record("one", "合成记忆"), 0.7, 0.2)
        result = StructuredHybridReranker().build_result(
            MemoryQuery("合成记忆", at=NOW),
            (candidate,),
            examined=4,
            filtered={"expired": 2, "superseded": 1},
            candidate_sources={"vector": 1},
            embedding_identity={"model_id": "synthetic", "dimensions": 4},
        )
        self.assertEqual(result.trace.strategy_version, "structured-hybrid-v0.1")
        self.assertEqual(result.trace.filtered["expired"], 2)
        self.assertEqual(result.trace.embedding_identity["dimensions"], 4)

    def test_on_demand_suppressed_memory_has_no_score_penalty(self) -> None:
        source = MemorySource(
            "source-suppressed",
            SourceKind.CONVERSATION,
            "synthetic://hybrid/suppressed",
            NOW,
        )
        candidate = MemoryCandidate(
            memory_id="suppressed",
            source=source,
            kind=MemoryKind.EPISODIC,
            text="雨后把透明伞落在蓝桥",
            occurred_at=NOW,
            recorded_at=NOW,
            timezone="UTC",
            time_precision=TimePrecision.MINUTE,
            importance=0.5,
            directive_text="忘了吧",
        )
        policy = DefaultMemoryPolicy()
        materialized = policy.materialize(candidate, policy.evaluate(candidate, NOW))
        if materialized is None:
            raise AssertionError("suppressed test record was excluded")
        hit = StructuredHybridReranker().rerank(
            MemoryQuery("透明伞落在哪里", at=NOW),
            (HybridCandidate(materialized, 0.62, 0.1),),
        )[0]
        self.assertEqual(hit.score_components["confirmation"], 0.0)
        self.assertIn("suppressed_on_demand_no_penalty", hit.reasons)


if __name__ == "__main__":
    unittest.main()
