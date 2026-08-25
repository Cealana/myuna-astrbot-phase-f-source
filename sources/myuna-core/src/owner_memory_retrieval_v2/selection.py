from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Iterable

from .boundary import eligible_records, parse_datetime
from .contracts import CandidateScore, QueryPlan, SelectionResult
from .diversity import near_duplicate
from .planner import plan_query
from .scoring import score_record


GENERIC_QUERY_CONCEPTS = frozenset(
    {"memory", "recollection", "archive", "project", "time", "privacy", "identity"}
)


def _select_once(
    records: tuple[dict[str, Any], ...],
    *,
    query: str,
    plan: QueryPlan,
    horizon: str,
    at: datetime,
    maximum: int,
) -> tuple[list[dict[str, Any]], list[CandidateScore], Counter[str]]:
    filtered: Counter[str] = Counter()
    scored: list[tuple[CandidateScore, datetime, dict[str, Any]]] = []
    for record in eligible_records(records, horizon=horizon, at=at, filtered=filtered):
        score = score_record(query, plan, record)
        if score is None:
            filtered["insufficient_semantic_evidence"] += 1
            continue
        occurred_at = parse_datetime(record.get("occurred_at"))
        assert occurred_at is not None
        scored.append((score, occurred_at, record))

    scored.sort(
        key=lambda item: (
            -item[0].final_score,
            -item[1].timestamp(),
            item[0].memory_id,
        )
    )
    if not scored or scored[0][0].final_score < 0.30:
        filtered["below_injection_floor"] += len(scored)
        return [], [], filtered

    top_score = scored[0][0].final_score
    specific_query_concepts = set(plan.concepts) - GENERIC_QUERY_CONCEPTS
    selected_records: list[dict[str, Any]] = []
    selected_scores: list[CandidateScore] = []
    for score, _, record in scored:
        if selected_scores and (
            score.final_score < 0.26 or score.final_score < 0.66 * top_score
        ):
            filtered["relative_gap"] += 1
            continue
        if (
            selected_scores
            and specific_query_concepts
            and not specific_query_concepts.intersection(score.matched_concepts)
        ):
            filtered["secondary_without_specific_overlap"] += 1
            continue
        if any(near_duplicate(record, prior) for prior in selected_records):
            filtered["near_duplicate"] += 1
            continue
        selected_records.append(record)
        selected_scores.append(score)
        if len(selected_records) >= maximum:
            break
    return selected_records, selected_scores, filtered


def retrieve_records(
    records: Iterable[dict[str, Any]],
    *,
    query: str,
    at: datetime,
) -> SelectionResult:
    """Orchestrate one bounded retrieval plan without model or write access."""

    plan = plan_query(query)
    source = tuple(records)
    primary_records, primary_scores, primary_filtered = _select_once(
        source,
        query=query,
        plan=plan,
        horizon=plan.primary_horizon,
        at=at,
        maximum=plan.max_results,
    )
    if primary_records or not plan.allow_deep_fallback:
        return SelectionResult(
            plan=plan,
            horizon_used=plan.primary_horizon,
            fallback_used=False,
            records=tuple(primary_records),
            scores=tuple(primary_scores),
            filtered=dict(primary_filtered),
        )

    fallback_records, fallback_scores, fallback_filtered = _select_once(
        source,
        query=query,
        plan=plan,
        horizon="deep",
        at=at,
        maximum=3,
    )
    combined = Counter(primary_filtered)
    combined.update(
        {f"fallback_{key}": value for key, value in fallback_filtered.items()}
    )
    return SelectionResult(
        plan=plan,
        horizon_used="deep",
        fallback_used=True,
        records=tuple(fallback_records),
        scores=tuple(fallback_scores),
        filtered=dict(combined),
    )
