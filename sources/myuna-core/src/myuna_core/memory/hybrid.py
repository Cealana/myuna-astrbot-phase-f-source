from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import math
import unicodedata
from typing import Mapping, Sequence

from .models import (
    ConfirmationLevel,
    MemoryKind,
    MemoryQuery,
    MemoryRecord,
    MemoryStatus,
    RetrievalHit,
    RetrievalResult,
    RetrievalTrace,
    TimePrecision,
)
from .retrieval import _query_terms


HYBRID_STRATEGY_VERSION = "structured-hybrid-v0.1"


class QueryIntent(StrEnum):
    FIRST = "first"
    EXACT_QUOTE = "exact_quote"
    TIME = "time"
    CURRENT = "current"
    BASELINE = "baseline"
    CORRECTION = "correction"


INTENT_MARKERS: Mapping[QueryIntent, tuple[str, ...]] = {
    QueryIntent.FIRST: ("第一次", "首次", "头一回", "最初", "最早", "起初"),
    QueryIntent.EXACT_QUOTE: ("原话", "逐字", "那句话", "那句", "引用", "完整", "怎么说", "写下"),
    QueryIntent.TIME: (
        "什么时候", "几点", "几分", "哪天", "日期", "时间", "早上", "上午",
        "中午", "下午", "傍晚", "晚上", "半夜", "凌晨",
    ),
    QueryIntent.CURRENT: ("今天", "现在", "当下", "目前", "临时", "暂时", "这会儿"),
    QueryIntent.BASELINE: ("平时", "平常", "通常", "日常", "长期", "一直", "确认过"),
    QueryIntent.CORRECTION: ("更正", "修正", "实际", "真实", "不是", "改正", "正确"),
}


SCORE_WEIGHTS: Mapping[str, float] = {
    "vector_similarity": 0.65,
    "lexical_similarity": 0.15,
    "importance": 0.08,
    "confirmed": 0.07,
    "provisional": 0.02,
    "suppressed": 0.0,
    "anchor_prior": 0.01,
    "first_intent": 0.35,
    "exact_quote_intent": 0.30,
    "time_exact": 0.12,
    "time_part_of_day": 0.06,
    "scoped_current_state": 0.12,
    "current_intent": 0.20,
    "baseline_intent": 0.15,
    "correction_intent": 0.18,
}


@dataclass(frozen=True, slots=True)
class HybridCandidate:
    record: MemoryRecord
    vector_score: float | None
    lexical_score: float
    anchor_kind: str | None = None
    source_channels: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.vector_score is not None and not math.isfinite(self.vector_score):
            raise ValueError("vector_score must be finite")
        if not math.isfinite(self.lexical_score) or not 0.0 <= self.lexical_score <= 1.0:
            raise ValueError("lexical_score must be finite and between zero and one")
        if self.anchor_kind not in {None, "first", "exact_quote", "important_moment", "manual"}:
            raise ValueError("unsupported anchor_kind")


def analyze_query_intents(text: str) -> tuple[QueryIntent, ...]:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    return tuple(
        intent
        for intent, markers in INTENT_MARKERS.items()
        if any(marker in normalized for marker in markers)
    )


def _bounded_similarity(value: float | None) -> float:
    if value is None:
        return 0.0
    return max(0.0, min(1.0, value))


class StructuredHybridReranker:
    """Pure deterministic reranker; database and embedding providers remain adapters."""

    strategy_version = HYBRID_STRATEGY_VERSION
    score_weights = SCORE_WEIGHTS

    def rerank(
        self,
        query: MemoryQuery,
        candidates: Sequence[HybridCandidate],
    ) -> tuple[RetrievalHit, ...]:
        intents = set(analyze_query_intents(query.text))
        hits = [self._score(query, candidate, intents) for candidate in candidates]
        hits.sort(
            key=lambda hit: (
                -hit.score,
                -hit.record.occurred_at.timestamp(),
                hit.record.memory_id,
            )
        )
        return tuple(hits[: query.limit])

    def build_result(
        self,
        query: MemoryQuery,
        candidates: Sequence[HybridCandidate],
        *,
        examined: int,
        filtered: Mapping[str, int],
        candidate_sources: Mapping[str, int],
        embedding_identity: Mapping[str, str | int],
    ) -> RetrievalResult:
        intents = analyze_query_intents(query.text)
        return RetrievalResult(
            hits=self.rerank(query, candidates),
            trace=RetrievalTrace(
                strategy_version=self.strategy_version,
                examined=examined,
                eligible=len(candidates),
                filtered=dict(sorted(filtered.items())),
                query_terms=_query_terms(query.text),
                query_intents=tuple(intent.value for intent in intents),
                candidate_sources=dict(sorted(candidate_sources.items())),
                score_weights=dict(self.score_weights),
                embedding_identity=dict(embedding_identity),
            ),
        )

    def _score(
        self,
        query: MemoryQuery,
        candidate: HybridCandidate,
        intents: set[QueryIntent],
    ) -> RetrievalHit:
        record = candidate.record
        components: dict[str, float] = {}
        reasons: list[str] = []

        vector = _bounded_similarity(candidate.vector_score) * SCORE_WEIGHTS["vector_similarity"]
        if vector:
            components["vector_similarity"] = vector
            reasons.append("semantic_vector_candidate")
        lexical = candidate.lexical_score * SCORE_WEIGHTS["lexical_similarity"]
        if lexical:
            components["lexical_similarity"] = lexical
            reasons.append("lexical_candidate")

        components["importance"] = record.importance * SCORE_WEIGHTS["importance"]
        reasons.append("importance_weight")
        if record.status is MemoryStatus.CONFIRMED:
            components["confirmation"] = SCORE_WEIGHTS["confirmed"]
            reasons.append("confirmed_memory_boost")
        elif record.status is MemoryStatus.PROVISIONAL:
            components["confirmation"] = SCORE_WEIGHTS["provisional"]
            reasons.append("provisional_memory_boost")
        elif record.status is MemoryStatus.SUPPRESSED:
            components["confirmation"] = SCORE_WEIGHTS["suppressed"]
            reasons.append("suppressed_on_demand_no_penalty")

        if record.kind is MemoryKind.ANCHOR:
            components["anchor_prior"] = SCORE_WEIGHTS["anchor_prior"]
            reasons.append("anchor_prior")
        if QueryIntent.FIRST in intents and candidate.anchor_kind == "first":
            components["first_intent"] = SCORE_WEIGHTS["first_intent"]
            reasons.append("first_anchor_intent_match")
        if QueryIntent.EXACT_QUOTE in intents and (
            candidate.anchor_kind == "exact_quote" or record.exact_quote
        ):
            components["exact_quote_intent"] = SCORE_WEIGHTS["exact_quote_intent"]
            reasons.append("exact_quote_intent_match")
        if QueryIntent.TIME in intents:
            if record.time_precision in {TimePrecision.MINUTE, TimePrecision.EXACT}:
                components["time_precision"] = SCORE_WEIGHTS["time_exact"]
                reasons.append("precise_time_intent_match")
            elif record.time_precision is TimePrecision.PART_OF_DAY:
                components["time_precision"] = SCORE_WEIGHTS["time_part_of_day"]
                reasons.append("part_of_day_intent_match")
        if record.kind is MemoryKind.CURRENT_STATE and "global" not in record.scope:
            components["scoped_current_state"] = SCORE_WEIGHTS["scoped_current_state"]
            reasons.append("scoped_current_state_override")
        if QueryIntent.CURRENT in intents and record.kind is MemoryKind.CURRENT_STATE:
            components["current_intent"] = SCORE_WEIGHTS["current_intent"]
            reasons.append("current_state_intent_match")
        if (
            QueryIntent.BASELINE in intents
            and record.kind is MemoryKind.PREFERENCE
            and record.confirmation is ConfirmationLevel.USER_CONFIRMED
        ):
            components["baseline_intent"] = SCORE_WEIGHTS["baseline_intent"]
            reasons.append("confirmed_baseline_intent_match")
        if QueryIntent.CORRECTION in intents and record.supersedes_id is not None:
            components["correction_intent"] = SCORE_WEIGHTS["correction_intent"]
            reasons.append("correction_chain_intent_match")

        score = round(sum(components.values()), 6)
        rounded_components = {key: round(value, 6) for key, value in components.items()}
        return RetrievalHit(
            record=record,
            score=score,
            reasons=tuple(reasons),
            score_components=rounded_components,
        )
