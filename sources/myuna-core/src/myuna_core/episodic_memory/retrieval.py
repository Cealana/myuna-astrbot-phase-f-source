from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Sequence

from .contracts import (
    EGRESS_POLICY_HISTORICAL_RAW_RECALL_V1,
    EGRESS_POLICY_RAW_HYDRATION,
    CompleteTurn,
    EpisodicCapsule,
    EpisodicMemoryError,
    RecallEgressPolicy,
    TurnTimeCorrection,
    require_digest,
    semantic_digest,
)
from .index import EpisodicIndexSnapshot, EpisodicSourceReference, verify_snapshot
from .owner_day import OwnerDayPolicy
from .temporal_bridge import TemporalIntervalIndexSnapshot


_EXACT_MARKERS = (
    "exact",
    "quote",
    "chronology",
    "commitment",
    "number",
    "negation",
    "准确",
    "原话",
    "按顺序",
    "承诺",
    "数字",
    "没有",
)


@dataclass(frozen=True, slots=True)
class EpisodicQuery:
    text: str
    start_utc: datetime | None = None
    end_utc: datetime | None = None
    require_exact: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.text, str) or not self.text.strip() or len(self.text) > 2_000:
            raise EpisodicMemoryError("episodic_query_invalid")
        if (self.start_utc is None) != (self.end_utc is None):
            raise EpisodicMemoryError("episodic_query_interval_incomplete")
        if self.start_utc is not None and self.start_utc >= self.end_utc:  # type: ignore[operator]
            raise EpisodicMemoryError("episodic_query_interval_invalid")

    @property
    def query_digest(self) -> str:
        return semantic_digest(
            "myuna-p07-episodic-query-v2",
            {
                "end_utc": (
                    None
                    if self.end_utc is None
                    else self.end_utc.isoformat(timespec="microseconds")
                ),
                "require_exact": self.require_exact,
                "start_utc": (
                    None
                    if self.start_utc is None
                    else self.start_utc.isoformat(timespec="microseconds")
                ),
                "text": self.text,
            },
        )


def _selection_digest_value(
    *,
    state: str,
    reason_category: str | None,
    source_references: Sequence[EpisodicSourceReference],
    capsules: Sequence[EpisodicCapsule],
    source_ranges: Sequence[tuple[int, int]],
    exact_raw_required: bool,
    coverage_limited: bool,
    query_digest: str,
    snapshot_digest: str,
    source_closure_digest: str,
) -> str:
    return semantic_digest(
        "myuna-p07-episodic-retrieval-selection-v2",
        {
            "capsule_digests": [item.capsule_digest for item in capsules],
            "coverage_limited": coverage_limited,
            "exact_raw_required": exact_raw_required,
            "query_digest": query_digest,
            "reason_category": reason_category,
            "snapshot_digest": snapshot_digest,
            "source_closure_digest": source_closure_digest,
            "source_ranges": [list(item) for item in source_ranges],
            "source_reference_digests": [
                item.source_reference_digest for item in source_references
            ],
            "state": state,
        },
    )


@dataclass(frozen=True, slots=True)
class RetrievalSelection:
    state: str
    reason_category: str | None
    source_references: tuple[EpisodicSourceReference, ...]
    hydrated_turns: tuple[CompleteTurn, ...]
    capsules: tuple[EpisodicCapsule, ...]
    source_ranges: tuple[tuple[int, int], ...]
    exact_raw_required: bool
    coverage_limited: bool
    query_digest: str
    snapshot_digest: str
    source_closure_digest: str
    selection_digest: str

    def __post_init__(self) -> None:
        if self.state not in {
            "available",
            "available_empty",
            "unavailable",
            "conflict",
        }:
            raise EpisodicMemoryError("retrieval_state_unknown")
        require_digest(self.source_closure_digest, "retrieval_source_closure")
        require_digest(self.query_digest, "retrieval_query")
        require_digest(self.snapshot_digest, "retrieval_snapshot")
        require_digest(self.selection_digest, "retrieval_selection")
        if self.state == "available_empty" and (
            self.source_references
            or self.hydrated_turns
            or self.capsules
            or self.source_ranges
        ):
            raise EpisodicMemoryError("retrieval_empty_state_invalid")
        if self.state in {"unavailable", "conflict"} and (
            self.source_references
            or self.hydrated_turns
            or self.capsules
            or self.source_ranges
        ):
            raise EpisodicMemoryError("retrieval_failure_contains_sources")
        if self.state == "available" and not self.source_references:
            raise EpisodicMemoryError("retrieval_available_sources_missing")
        if self.hydrated_turns and len(self.hydrated_turns) != len(self.source_references):
            raise EpisodicMemoryError("retrieval_hydration_count_mismatch")
        if self.source_references:
            sequences = tuple(item.sequence for item in self.source_references)
            if (
                sequences != tuple(sorted(set(sequences)))
                or _ranges(sequences) != self.source_ranges
            ):
                raise EpisodicMemoryError("retrieval_source_range_mismatch")
            if any(
                turn.draft.sequence != reference.sequence
                or turn.draft.turn_id != reference.turn_id
                or turn.turn_digest != reference.turn_digest
                for turn, reference in zip(
                    self.hydrated_turns,
                    self.source_references,
                    strict=False,
                )
            ):
                raise EpisodicMemoryError("retrieval_hydration_source_mismatch")
        if self.state in {"available", "available_empty"}:
            if self.reason_category is not None:
                raise EpisodicMemoryError("retrieval_success_reason_rejected")
        elif not self.reason_category:
            raise EpisodicMemoryError("retrieval_failure_reason_missing")
        expected = _selection_digest_value(
            state=self.state,
            reason_category=self.reason_category,
            source_references=self.source_references,
            capsules=self.capsules,
            source_ranges=self.source_ranges,
            exact_raw_required=self.exact_raw_required,
            coverage_limited=self.coverage_limited,
            query_digest=self.query_digest,
            snapshot_digest=self.snapshot_digest,
            source_closure_digest=self.source_closure_digest,
        )
        if expected != self.selection_digest:
            raise EpisodicMemoryError("retrieval_selection_digest_mismatch")

    def audit_projection(self) -> dict[str, object]:
        return {
            "capsule_count": len(self.capsules),
            "coverage_limited": self.coverage_limited,
            "exact_raw_required": self.exact_raw_required,
            "hydrated_turn_count": len(self.hydrated_turns),
            "query_digest": self.query_digest,
            "reason_category": self.reason_category,
            "selection_digest": self.selection_digest,
            "source_closure_digest": self.source_closure_digest,
            "source_reference_count": len(self.source_references),
            "source_ranges": [list(value) for value in self.source_ranges],
            "state": self.state,
            "snapshot_digest": self.snapshot_digest,
        }


def _terms(value: str) -> set[str]:
    result: set[str] = set()
    for item in re.findall(r"[\w\u4e00-\u9fff]{2,}", value):
        normalized = item.casefold()
        result.add(normalized)
        if any("\u4e00" <= character <= "\u9fff" for character in normalized):
            result.update(
                normalized[index : index + 2]
                for index in range(len(normalized) - 1)
            )
    return result


def _authorized(policy: RecallEgressPolicy) -> None:
    if policy.mode not in {
        EGRESS_POLICY_RAW_HYDRATION,
        EGRESS_POLICY_HISTORICAL_RAW_RECALL_V1,
    }:
        raise EpisodicMemoryError("historical_raw_egress_not_authorized")


def _ranges(sequences: Sequence[int]) -> tuple[tuple[int, int], ...]:
    result: list[tuple[int, int]] = []
    for sequence in sorted(sequences):
        if result and sequence == result[-1][1] + 1:
            result[-1] = (result[-1][0], sequence)
        else:
            result.append((sequence, sequence))
    return tuple(result)


def _failed_selection(
    *,
    state: str,
    category: str,
    index: EpisodicIndexSnapshot,
    query: EpisodicQuery,
) -> RetrievalSelection:
    receipt = _selection_digest_value(
        state=state,
        reason_category=category,
        source_references=(),
        capsules=(),
        source_ranges=(),
        exact_raw_required=True,
        coverage_limited=True,
        query_digest=query.query_digest,
        snapshot_digest=index.snapshot_digest,
        source_closure_digest=index.source_closure_digest,
    )
    return RetrievalSelection(
        state=state,
        reason_category=category,
        source_references=(),
        hydrated_turns=(),
        capsules=(),
        source_ranges=(),
        exact_raw_required=True,
        coverage_limited=True,
        query_digest=query.query_digest,
        snapshot_digest=index.snapshot_digest,
        source_closure_digest=index.source_closure_digest,
        selection_digest=receipt,
    )


def content_free_retrieval_failure(
    *,
    state: str,
    reason_category: str,
    index: EpisodicIndexSnapshot,
    query: EpisodicQuery,
) -> RetrievalSelection:
    """Return a source-bound failure receipt without exposing factual content."""

    if state not in {"unavailable", "conflict"}:
        raise EpisodicMemoryError("retrieval_failure_state_invalid")
    return _failed_selection(
        state=state,
        category=reason_category,
        index=index,
        query=query,
    )


def search_relevant_sources(
    *,
    query: EpisodicQuery,
    index: EpisodicIndexSnapshot,
    egress_policy: RecallEgressPolicy,
    maximum_turns: int = 12,
) -> RetrievalSelection:
    """Search only the derivative catalog and return content-free references."""

    _authorized(egress_policy)
    if isinstance(maximum_turns, bool) or not isinstance(maximum_turns, int) or maximum_turns < 1:
        raise EpisodicMemoryError("retrieval_limit_invalid")
    query_terms = _terms(query.text)
    exact_required = query.require_exact or any(
        marker in query.text.casefold() for marker in _EXACT_MARKERS
    )
    candidates: list[tuple[int, EpisodicCapsule]] = []
    reference_by_sequence = {item.sequence: item for item in index.source_references}
    for capsule in index.capsules:
        if any(
            not reference_by_sequence[sequence].model_history_eligible
            for sequence in range(capsule.source_start, capsule.source_end + 1)
        ):
            continue
        score = len(query_terms & _terms(capsule.label))
        if score:
            candidates.append((score, capsule))
    candidates.sort(key=lambda value: (-value[0], value[1].source_start, value[1].capsule_id))
    selected_capsules = tuple(item[1] for item in candidates[:maximum_turns])
    sequences: set[int] = set()
    coverage_limited = False
    for capsule in selected_capsules:
        if capsule.coverage_state != "complete":
            exact_required = True
            coverage_limited = True
        sequences.update(range(capsule.source_start, capsule.source_end + 1))
    if query.start_utc is not None:
        for reference in index.source_references:
            if not reference.model_history_eligible:
                continue
            if (
                reference.time_status != "exact"
                or reference.effective_delivered_at_utc is None
            ):
                return _failed_selection(
                    state="unavailable",
                    category="trusted_time_unavailable",
                    index=index,
                    query=query,
                )
            delivered = datetime.fromisoformat(reference.effective_delivered_at_utc)
            if (
                query.start_utc
                <= delivered  # type: ignore[operator]
                < query.end_utc
            ):
                sequences.add(reference.sequence)
    if not sequences:
        receipt = _selection_digest_value(
            state="available_empty",
            reason_category=None,
            source_references=(),
            capsules=(),
            source_ranges=(),
            exact_raw_required=exact_required,
            coverage_limited=False,
            query_digest=query.query_digest,
            snapshot_digest=index.snapshot_digest,
            source_closure_digest=index.source_closure_digest,
        )
        return RetrievalSelection(
            state="available_empty",
            reason_category=None,
            source_references=(),
            hydrated_turns=(),
            capsules=(),
            source_ranges=(),
            exact_raw_required=exact_required,
            coverage_limited=False,
            query_digest=query.query_digest,
            snapshot_digest=index.snapshot_digest,
            source_closure_digest=index.source_closure_digest,
            selection_digest=receipt,
        )
    if len(sequences) > maximum_turns:
        return _failed_selection(
            state="unavailable",
            category="raw_budget_limited",
            index=index,
            query=query,
        )
    references = tuple(reference_by_sequence[value] for value in sorted(sequences))
    ranges = _ranges(tuple(item.sequence for item in references))
    selection_digest = _selection_digest_value(
        state="available",
        reason_category=None,
        source_references=references,
        capsules=selected_capsules,
        source_ranges=ranges,
        exact_raw_required=exact_required,
        coverage_limited=coverage_limited,
        query_digest=query.query_digest,
        snapshot_digest=index.snapshot_digest,
        source_closure_digest=index.source_closure_digest,
    )
    return RetrievalSelection(
        state="available",
        reason_category=None,
        source_references=references,
        hydrated_turns=(),
        capsules=selected_capsules,
        source_ranges=ranges,
        exact_raw_required=exact_required,
        coverage_limited=coverage_limited,
        query_digest=query.query_digest,
        snapshot_digest=index.snapshot_digest,
        source_closure_digest=index.source_closure_digest,
        selection_digest=selection_digest,
    )


def _conflict_selection(
    selection: RetrievalSelection,
    index: EpisodicIndexSnapshot,
    category: str,
) -> RetrievalSelection:
    digest = _selection_digest_value(
        state="conflict",
        reason_category=category,
        source_references=(),
        capsules=(),
        source_ranges=(),
        exact_raw_required=True,
        coverage_limited=True,
        query_digest=selection.query_digest,
        snapshot_digest=index.snapshot_digest,
        source_closure_digest=index.source_closure_digest,
    )
    return RetrievalSelection(
        state="conflict",
        reason_category=category,
        source_references=(),
        hydrated_turns=(),
        capsules=(),
        source_ranges=(),
        exact_raw_required=True,
        coverage_limited=True,
        query_digest=selection.query_digest,
        snapshot_digest=index.snapshot_digest,
        source_closure_digest=index.source_closure_digest,
        selection_digest=digest,
    )


def fetch_relevant_raw(
    *,
    selection: RetrievalSelection,
    turns: Sequence[CompleteTurn],
    index: EpisodicIndexSnapshot,
    archive_id: str | None = None,
    corrections: Sequence[TurnTimeCorrection] = (),
    temporal_snapshot: TemporalIntervalIndexSnapshot | None = None,
    owner_day_policy: OwnerDayPolicy | None = None,
) -> RetrievalSelection:
    """Revalidate current raw/P08 closure before returning any factual text."""

    if (
        selection.snapshot_digest != index.snapshot_digest
        or selection.source_closure_digest != index.source_closure_digest
    ):
        return _conflict_selection(selection, index, "search_snapshot_conflict")
    if selection.state == "available_empty":
        try:
            verify_snapshot(
                index,
                turns,
                archive_id=index.archive_id if archive_id is None else archive_id,
                corrections=corrections,
                temporal_snapshot=temporal_snapshot,
                owner_day_policy=owner_day_policy,
            )
        except EpisodicMemoryError:
            return _conflict_selection(selection, index, "source_closure_conflict")
        return selection
    if selection.state != "available":
        return selection
    reference_by_sequence = {item.sequence: item for item in index.source_references}
    capsule_by_id = {item.capsule_id: item for item in index.capsules}
    if (
        tuple(
            reference_by_sequence.get(reference.sequence)
            for reference in selection.source_references
        )
        != selection.source_references
        or tuple(capsule_by_id.get(item.capsule_id) for item in selection.capsules)
        != selection.capsules
        or _ranges(tuple(item.sequence for item in selection.source_references))
        != selection.source_ranges
    ):
        return _conflict_selection(selection, index, "search_selection_conflict")
    try:
        verify_snapshot(
            index,
            turns,
            archive_id=index.archive_id if archive_id is None else archive_id,
            corrections=corrections,
            temporal_snapshot=temporal_snapshot,
            owner_day_policy=owner_day_policy,
        )
    except EpisodicMemoryError:
        return _conflict_selection(selection, index, "source_closure_conflict")
    by_sequence = {turn.draft.sequence: turn for turn in turns}
    hydrated: list[CompleteTurn] = []
    for reference in selection.source_references:
        turn = by_sequence.get(reference.sequence)
        if (
            turn is None
            or turn.draft.turn_id != reference.turn_id
            or turn.turn_digest != reference.turn_digest
            or not turn.model_history_eligible
        ):
            return _conflict_selection(selection, index, "raw_source_conflict")
        hydrated.append(turn)
    return RetrievalSelection(
        state="available",
        reason_category=None,
        source_references=selection.source_references,
        hydrated_turns=tuple(hydrated),
        capsules=selection.capsules,
        source_ranges=selection.source_ranges,
        exact_raw_required=selection.exact_raw_required,
        coverage_limited=selection.coverage_limited,
        query_digest=selection.query_digest,
        snapshot_digest=selection.snapshot_digest,
        source_closure_digest=selection.source_closure_digest,
        selection_digest=selection.selection_digest,
    )


def select_relevant_raw(
    *,
    query: EpisodicQuery,
    turns: Sequence[CompleteTurn],
    index: EpisodicIndexSnapshot,
    egress_policy: RecallEgressPolicy,
    archive_id: str | None = None,
    corrections: Sequence[TurnTimeCorrection] = (),
    temporal_snapshot: TemporalIntervalIndexSnapshot | None = None,
    owner_day_policy: OwnerDayPolicy | None = None,
    maximum_turns: int = 12,
) -> RetrievalSelection:
    searched = search_relevant_sources(
        query=query,
        index=index,
        egress_policy=egress_policy,
        maximum_turns=maximum_turns,
    )
    return fetch_relevant_raw(
        selection=searched,
        turns=turns,
        index=index,
        archive_id=archive_id,
        corrections=corrections,
        temporal_snapshot=temporal_snapshot,
        owner_day_policy=owner_day_policy,
    )
