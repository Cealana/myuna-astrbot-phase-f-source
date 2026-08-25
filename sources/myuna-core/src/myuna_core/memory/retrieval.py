from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import re
import unicodedata

from .interfaces import MemoryStore
from .models import (
    MemoryKind,
    MemoryQuery,
    MemoryRecord,
    MemoryStatus,
    RetrievalHit,
    RetrievalResult,
    RetrievalTrace,
    SourceKind,
)


STRATEGY_VERSION = "deterministic-zh-hybrid-v0.1"


def _normalize(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    return "".join(char for char in normalized if char.isalnum())


def _query_terms(text: str) -> tuple[str, ...]:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    ascii_terms = re.findall(r"[a-z0-9]+", normalized)
    compact = _normalize(normalized)
    cjk = "".join(char for char in compact if "\u3400" <= char <= "\u9fff")
    grams = [cjk[index : index + 2] for index in range(max(0, len(cjk) - 1))]
    return tuple(dict.fromkeys([*ascii_terms, *grams]))


def _bigrams(text: str) -> Counter[str]:
    compact = _normalize(text)
    if len(compact) < 2:
        return Counter({compact: 1}) if compact else Counter()
    return Counter(compact[index : index + 2] for index in range(len(compact) - 1))


def _lexical_score(query: str, text: str, exact_quote: str | None) -> tuple[float, list[str]]:
    query_compact = _normalize(query)
    combined = f"{text} {exact_quote or ''}"
    text_compact = _normalize(combined)
    reasons: list[str] = []
    if query_compact == text_compact:
        return 1.0, ["exact_text_match"]
    if query_compact and query_compact in text_compact:
        return 0.9, ["query_substring_match"]

    query_grams = _bigrams(query)
    text_grams = _bigrams(combined)
    overlap = sum((query_grams & text_grams).values())
    denominator = sum(query_grams.values()) + sum(text_grams.values())
    if not overlap or not denominator:
        return 0.0, reasons
    reasons.append("chinese_character_bigram_overlap")
    return (2.0 * overlap) / denominator, reasons


def _scope_matches(record: MemoryRecord, query: MemoryQuery) -> bool:
    if "global" in record.scope:
        return True
    return bool(set(record.scope) & set(query.scope))


class ExplainableRetriever:
    """Deterministic Stage 0 retrieval without embeddings or external services."""

    def __init__(self, store: MemoryStore) -> None:
        self._store = store

    def retrieve(self, query: MemoryQuery) -> RetrievalResult:
        records = self._store.all_records()
        filtered: Counter[str] = Counter()
        superseded_ids = {record.supersedes_id for record in records if record.supersedes_id}
        effective_at = query.at or datetime.now(timezone.utc)
        hits: list[RetrievalHit] = []

        for record in records:
            reason = self._ineligible_reason(record, query, superseded_ids, effective_at)
            if reason is not None:
                filtered[reason] += 1
                continue

            lexical, reasons = _lexical_score(query.text, record.text, record.exact_quote)
            if lexical <= 0.0:
                filtered["no_lexical_overlap"] += 1
                continue

            score = lexical
            if record.status is MemoryStatus.CONFIRMED:
                score += 0.18
                reasons.append("confirmed_memory_boost")
            elif record.status is MemoryStatus.PROVISIONAL:
                score += 0.08
                reasons.append("provisional_memory_boost")
            elif record.status is MemoryStatus.SUPPRESSED:
                score -= 0.15
                reasons.append("suppressed_memory_penalty")

            if record.kind is MemoryKind.CURRENT_STATE and "global" not in record.scope:
                score += 0.35
                reasons.append("scoped_current_state_override")
            if record.kind is MemoryKind.ANCHOR:
                score += 0.25
                reasons.append("anchor_boost")
            if record.exact_quote:
                score += 0.08
                reasons.append("exact_quote_preserved")

            score += record.importance * 0.20
            reasons.append("importance_weight")
            hits.append(RetrievalHit(record=record, score=round(score, 6), reasons=tuple(reasons)))

        hits.sort(
            key=lambda hit: (
                -hit.score,
                -hit.record.occurred_at.timestamp(),
                hit.record.memory_id,
            )
        )
        selected = tuple(hits[: query.limit])
        return RetrievalResult(
            hits=selected,
            trace=RetrievalTrace(
                strategy_version=STRATEGY_VERSION,
                examined=len(records),
                eligible=len(hits),
                filtered=dict(sorted(filtered.items())),
                query_terms=_query_terms(query.text),
            ),
        )

    @staticmethod
    def _ineligible_reason(
        record: MemoryRecord,
        query: MemoryQuery,
        superseded_ids: set[str | None],
        effective_at: datetime,
    ) -> str | None:
        if record.namespace_id != query.namespace_id:
            return "namespace_mismatch"
        if (
            record.source.kind is SourceKind.OPERATIONAL_RECORD
            and not query.include_external_records
        ):
            return "external_record"
        if record.status in {MemoryStatus.EXCLUDED, MemoryStatus.TOMBSTONED}:
            return "inactive_status"
        if record.memory_id in superseded_ids:
            return "superseded"
        if record.expires_at is not None and record.expires_at <= effective_at:
            return "expired"
        if query.proactive and record.do_not_surface_proactively:
            return "proactive_suppression"
        if query.kinds and record.kind not in query.kinds:
            return "kind_mismatch"
        if not _scope_matches(record, query):
            return "scope_mismatch"
        if query.time_start is not None and record.occurred_at < query.time_start:
            return "before_time_window"
        if query.time_end is not None and record.occurred_at > query.time_end:
            return "after_time_window"
        return None
