from __future__ import annotations

import math
from typing import Any

from .concepts import CONCEPT_PHRASES, character_terms, normalize
from .contracts import CandidateScore, QueryPlan


SUBTYPE_CONCEPTS: dict[str, tuple[str, ...]] = {
    "memory_anchor_preference": ("memory", "recollection", "anchor_preference"),
    "exact_quote_anchor": ("exact_quote", "memory", "recollection"),
    "detailed_memory_preference": ("firsts", "important_moment", "detail", "time"),
    "archive_detail_preference": ("archive", "detail", "lossless_source"),
    "deployment_phase_interaction_state": (
        "ask_when_uncertain",
        "deployment",
        "temporary_state",
    ),
    "rationale_capture_preference": ("rationale", "decision_context", "causality"),
    "change_timeline_preference": ("timeline", "correction", "change", "ask_when_uncertain"),
    "forget_phrase_preference": ("forget_semantics", "suppression", "deletion_boundary"),
    "project_extensibility_preference": ("project", "modularity", "extensibility"),
    "versioned_tuning_preference": ("project", "versioned_policy", "runtime_tuning"),
    "complete_private_archive_preference": ("full_archive", "one_to_one", "local_organizer"),
    "recent_retrieval_window_preference": ("retrieval", "recent_context", "deep_recall"),
}


def record_chunks(record: dict[str, Any], *, support: bool) -> list[str]:
    values: list[str] = []
    if support:
        for rationale in record.get("rationales") or []:
            if isinstance(rationale, dict):
                values.append(str(rationale.get("text") or ""))
        for anchor in record.get("anchors") or []:
            if isinstance(anchor, dict):
                values.extend(
                    [
                        str(anchor.get("title") or ""),
                        str(anchor.get("preservation_note") or ""),
                    ]
                )
        for review in record.get("review_items") or []:
            if isinstance(review, dict):
                values.append(str(review.get("question") or ""))
    else:
        values.extend(
            [
                str(record.get("assertion_text") or ""),
                str(record.get("event_text") or ""),
                str(record.get("exact_quote") or ""),
            ]
        )
    return [value for value in values if value]


def text_similarity(query: str, text: str) -> float:
    query_compact = normalize(query)
    text_compact = normalize(text)
    if not query_compact or not text_compact:
        return 0.0
    if query_compact == text_compact:
        return 1.0
    if query_compact in text_compact:
        return 0.96
    # v1 only rewarded query-in-record. v2 also recognizes a meaningful record
    # phrase inside a longer natural question, with a length guard against tiny
    # fragments dominating the result.
    if len(text_compact) >= 4 and text_compact in query_compact:
        return 0.88
    query_terms = character_terms(query)
    text_terms = character_terms(text)
    overlap = query_terms & text_terms
    if not overlap:
        return 0.0
    query_coverage = len(overlap) / max(1, len(query_terms))
    text_coverage = len(overlap) / max(1, len(text_terms))
    dice = 2 * len(overlap) / max(1, len(query_terms) + len(text_terms))
    return min(1.0, max(dice, (0.68 * query_coverage) + (0.32 * text_coverage)))


def best_text_similarity(query: str, chunks: list[str]) -> float:
    return max((text_similarity(query, chunk) for chunk in chunks), default=0.0)


def record_concepts(record: dict[str, Any]) -> set[str]:
    concepts = {
        str(tag)
        for tag in record.get("tags") or []
        if str(tag) in CONCEPT_PHRASES
    }
    concepts.update(SUBTYPE_CONCEPTS.get(str(record.get("subtype") or ""), ()))
    # Explicit tags/subtype are authoritative. Inferring additional broad labels
    # such as "memory" or "archive" from every stored sentence polluted v1-like
    # ranking: a detailed-event record could outrank the actual memory-policy
    # record merely because its prose used the word "保存". Text inference is a
    # compatibility fallback only for legacy records without recognized labels.
    if concepts:
        return concepts
    compact_text = normalize(
        " ".join(record_chunks(record, support=False) + record_chunks(record, support=True))
    )
    for concept, phrases in CONCEPT_PHRASES.items():
        if any(normalize(phrase) in compact_text for phrase in phrases):
            concepts.add(concept)
    return concepts


def concept_similarity(
    query_concepts: set[str],
    candidate_concepts: set[str],
) -> tuple[float, tuple[str, ...]]:
    overlap = query_concepts & candidate_concepts
    if not overlap:
        return 0.0, ()
    query_coverage = len(overlap) / max(1, len(query_concepts))
    record_coverage = len(overlap) / max(1, len(candidate_concepts))
    score = (0.78 * query_coverage) + (0.22 * record_coverage)
    return min(1.0, score), tuple(sorted(overlap))


def _safe_importance(value: object) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(number):
        return 0.0
    return min(1.0, max(0.0, number))


def score_record(query: str, plan: QueryPlan, record: dict[str, Any]) -> CandidateScore | None:
    query_concepts = set(plan.concepts)
    candidate_concepts = record_concepts(record)
    concept_score, matched = concept_similarity(query_concepts, candidate_concepts)
    primary_score = best_text_similarity(query, record_chunks(record, support=False))
    support_score = best_text_similarity(query, record_chunks(record, support=True))

    if query_concepts:
        semantic = (
            (0.64 * concept_score)
            + (0.30 * primary_score)
            + (0.06 * support_score)
        )
    else:
        # Ordinary recent-context messages often have no durable-policy concept.
        # In that lane, direct text evidence must stand on its own rather than
        # being multiplied by the concept-aware weight profile.
        semantic = (0.82 * primary_score) + (0.18 * support_score)
    # One broad type concept (for example only "exact_quote" or "rationale")
    # is not enough to identify a specific memory. Require either two concept
    # matches or independent text evidence. This blocks unrelated questions such
    # as "我说过要重启服务器吗" from selecting an arbitrary exact-quote record.
    evidence_present = (
        len(matched) >= 2
        or primary_score >= 0.18
        or support_score >= 0.24
    )
    if not evidence_present or semantic < 0.14:
        return None

    reasons = []
    if matched:
        reasons.append("concept_overlap")
    if primary_score >= 0.18:
        reasons.append("primary_text_overlap")
    if support_score >= 0.24:
        reasons.append("support_text_overlap")

    final = semantic
    if record.get("memory_status") == "confirmed":
        final += 0.04
        reasons.append("confirmed_prior")
    elif record.get("memory_status") == "provisional":
        final += 0.015
        reasons.append("provisional_prior")
    final += 0.06 * _safe_importance(record.get("importance"))
    if record.get("anchors"):
        final += 0.015
        reasons.append("anchor_prior")
    if plan.intent == "exact_quote_recall" and record.get("memory_kind") == "exact_quote":
        final += 0.10
        reasons.append("exact_quote_kind_match")

    return CandidateScore(
        memory_id=str(record.get("candidate_id") or ""),
        semantic_score=round(semantic, 6),
        final_score=round(final, 6),
        concept_score=round(concept_score, 6),
        primary_text_score=round(primary_score, 6),
        support_text_score=round(support_score, 6),
        matched_concepts=matched,
        reason_codes=tuple(reasons),
    )
