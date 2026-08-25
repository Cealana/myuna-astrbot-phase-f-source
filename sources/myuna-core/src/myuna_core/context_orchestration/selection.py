from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import re
import unicodedata

from .contracts import (
    CandidateDecision,
    ContextCandidate,
    P15SelectionInput,
    P15SelectionResult,
)


MINIMUM_RELEVANCE = 1
MINIMUM_VISUAL_CONFIDENCE = 0.6

_LANE_CAPS = {
    "profile": (3, 6_000),
    "temporal": (6, 2_400),
    "external_summary": (1, 4_000),
    "external_recent_turn": (6, 12_000),
    "visual_observation": (1, 240),
    "affinity_state": (1, 512),
}
_REQUIRED_CAPS = {"definition": 20_000, "current_message": 4_000}
_PACKING_ORDER = {
    "visual_observation": 0,
    "temporal": 1,
    "profile": 2,
    "external_recent_turn": 3,
    "external_summary": 4,
    "affinity_state": 5,
}
_RENDER_ORDER = {
    "definition": 0,
    "profile": 1,
    "temporal": 2,
    "external_summary": 3,
    "external_recent_turn": 4,
    "visual_observation": 5,
    "affinity_state": 6,
    "current_message": 7,
}
_CONFLICT_AUTHORITY = {
    "policy": ("definition",),
    "current_intent": ("current_message",),
    "stable_fact": (
        "profile",
        "temporal",
        "external_recent_turn",
        "external_summary",
        "visual_observation",
    ),
    "current_time_bounded_fact": (
        "current_message",
        "temporal",
        "profile",
        "external_recent_turn",
        "external_summary",
        "visual_observation",
    ),
    "continuity": (
        "external_recent_turn",
        "external_summary",
        "profile",
        "temporal",
        "visual_observation",
    ),
    "visual_evidence": ("current_message", "visual_observation"),
    "style": ("definition", "affinity_state"),
}
_WHITESPACE = re.compile(r"\s+")


@dataclass(slots=True)
class _Evaluation:
    eligible: list[ContextCandidate]
    decisions: dict[str, CandidateDecision]
    clarification_required: bool = False

    def drop(self, candidate: ContextCandidate, reason: str) -> None:
        self.decisions[candidate.candidate_id] = CandidateDecision(
            candidate.candidate_id,
            candidate.source_kind,
            reason,
        )


def _normalized(candidate: ContextCandidate) -> str:
    value = "\u241f".join(candidate.content_fragments)
    return _WHITESPACE.sub(" ", unicodedata.normalize("NFKC", value).casefold()).strip()


def _abstain(
    request: P15SelectionInput,
    candidate: ContextCandidate | None,
    reason: str,
) -> P15SelectionResult:
    candidate_id = "request" if candidate is None else candidate.candidate_id
    source_kind = "request" if candidate is None else candidate.source_kind
    return P15SelectionResult(
        status="abstain",
        selected=(),
        decisions=(CandidateDecision(candidate_id, source_kind, reason),),
        clarification_required=False,
        normal_transition=request.external_context.continuity_reset,
        input_snapshot_digest=request.snapshot_digest(),
    )


def _required_preflight(request: P15SelectionInput) -> P15SelectionResult | None:
    required_characters = 0
    required_bytes = 0
    for lane, authenticated in (
        (request.definition, request.definition.verified_release),
        (request.current_message, request.current_message.authenticated),
    ):
        candidate = lane.candidate
        if (
            not authenticated
            or not candidate.provenance.known
            or not candidate.provenance.schema_known
        ):
            return _abstain(request, candidate, "abstain_required_provenance")
        characters, byte_count = candidate.content_size()
        if characters > _REQUIRED_CAPS[candidate.source_kind]:
            return _abstain(request, candidate, "abstain_required_oversize")
        required_characters += characters
        required_bytes += byte_count
    if (
        required_characters > request.budget.characters
        or required_bytes > request.budget.bytes
    ):
        return _abstain(
            request,
            request.current_message.candidate,
            "abstain_required_oversize",
        )
    if not request.replay_snapshot_match:
        return _abstain(request, None, "abstain_replay_snapshot_drift")
    summary = request.external_context.summary
    if summary is not None and not summary.integrity_known:
        return _abstain(request, summary.candidate, "abstain_summary_integrity")
    return None


def _initial_optional_filter(request: P15SelectionInput) -> _Evaluation:
    evaluation = _Evaluation([], {})
    if (
        request.current_message.requires_trusted_time
        and request.trusted_time.status != "available"
    ):
        evaluation.clarification_required = True
    summary = request.external_context.summary
    summary_gap = False
    if summary is not None and request.external_context.recent_turns:
        retained_sequences = sorted(
            item.sequence
            for item in request.external_context.recent_turns
            if item.delivery_state == "delivered"
            and item.replay_of is None
            and item.sequence > summary.coverage_end
        )
        if retained_sequences:
            expected = list(range(summary.coverage_end + 1, retained_sequences[-1] + 1))
            summary_gap = retained_sequences != expected

    for lane in request.profile:
        _filter_candidate(evaluation, lane.candidate)
    for lane in request.temporal:
        candidate = lane.candidate
        if request.trusted_time.status != "available":
            evaluation.drop(candidate, "drop_trusted_time_unavailable")
        elif lane.expires_at <= request.trusted_time.now:  # type: ignore[operator]
            evaluation.drop(candidate, "drop_expired")
        else:
            _filter_candidate(evaluation, candidate)
    if summary is not None:
        if summary_gap:
            evaluation.drop(summary.candidate, "drop_summary_gap")
            if request.current_message.continuity_required:
                evaluation.clarification_required = True
        else:
            _filter_candidate(evaluation, summary.candidate)
    for lane in request.external_context.recent_turns:
        candidate = lane.candidate
        if lane.delivery_state != "delivered":
            evaluation.drop(candidate, "drop_delivery_not_committed")
        elif lane.replay_of is not None:
            evaluation.drop(candidate, "drop_replay_duplicate")
        elif summary is not None and lane.sequence <= summary.coverage_end:
            evaluation.drop(candidate, "drop_duplicate")
        else:
            _filter_candidate(evaluation, candidate)
    if request.visual_observation is not None:
        lane = request.visual_observation
        if lane.confidence < MINIMUM_VISUAL_CONFIDENCE:
            evaluation.drop(lane.candidate, "drop_low_confidence")
            if lane.candidate.essential_for_current:
                evaluation.clarification_required = True
        else:
            _filter_candidate(evaluation, lane.candidate)
    if request.affinity_state is not None:
        lane = request.affinity_state
        if lane.capability_state != "ready":
            evaluation.drop(lane.candidate, "drop_capability_unavailable")
        else:
            _filter_candidate(evaluation, lane.candidate)
    return evaluation


def _filter_candidate(evaluation: _Evaluation, candidate: ContextCandidate) -> None:
    if not candidate.provenance.known:
        evaluation.drop(candidate, "drop_unknown_provenance")
    elif not candidate.provenance.schema_known:
        evaluation.drop(candidate, "drop_unknown_schema")
    elif candidate.state == "stale":
        evaluation.drop(candidate, "drop_stale")
    elif candidate.state == "expired":
        evaluation.drop(candidate, "drop_expired")
    elif candidate.state == "unavailable":
        evaluation.drop(candidate, "drop_capability_unavailable")
    elif candidate.relevance < MINIMUM_RELEVANCE:
        evaluation.drop(candidate, "drop_low_relevance")
    elif candidate.conflicts_with_current:
        evaluation.drop(candidate, "drop_conflict_shadowed")
        if candidate.material_conflict:
            evaluation.clarification_required = True
    else:
        evaluation.eligible.append(candidate)


def _resolve_conflicts(evaluation: _Evaluation) -> None:
    groups: dict[tuple[str, str], list[ContextCandidate]] = defaultdict(list)
    for candidate in evaluation.eligible:
        if candidate.conflict_key is not None:
            groups[(candidate.semantic_domain, candidate.conflict_key)].append(candidate)

    removed: set[str] = set()
    for (domain, _), candidates in groups.items():
        if len(candidates) < 2:
            continue
        authority = _CONFLICT_AUTHORITY[domain]
        ranked = sorted(candidates, key=lambda item: authority.index(item.source_kind))
        best_rank = authority.index(ranked[0].source_kind)
        winners = [item for item in ranked if authority.index(item.source_kind) == best_rank]
        if len(winners) > 1:
            for candidate in candidates:
                evaluation.drop(candidate, "drop_conflict_ambiguous")
                removed.add(candidate.candidate_id)
            evaluation.clarification_required = True
        else:
            winner = winners[0]
            for candidate in candidates:
                if candidate != winner:
                    evaluation.drop(candidate, "drop_conflict_shadowed")
                    removed.add(candidate.candidate_id)
    evaluation.eligible[:] = [
        candidate for candidate in evaluation.eligible if candidate.candidate_id not in removed
    ]


def _deduplicate(evaluation: _Evaluation) -> None:
    retained: list[ContextCandidate] = []
    seen: set[str] = set()
    for candidate in sorted(evaluation.eligible, key=_packing_key):
        normalized = _normalized(candidate)
        if normalized in seen:
            evaluation.drop(candidate, "drop_duplicate")
        else:
            seen.add(normalized)
            retained.append(candidate)
    evaluation.eligible[:] = retained


def _packing_key(candidate: ContextCandidate) -> tuple[object, ...]:
    return (
        not candidate.essential_for_current,
        -candidate.relevance,
        _PACKING_ORDER[candidate.source_kind],
        candidate.upstream_rank,
        candidate.candidate_id,
    )


def _pack(request: P15SelectionInput, evaluation: _Evaluation) -> list[ContextCandidate]:
    required = [request.definition.candidate, request.current_message.candidate]
    used_characters = sum(item.content_size()[0] for item in required)
    used_bytes = sum(item.content_size()[1] for item in required)
    lane_counts: dict[str, int] = defaultdict(int)
    lane_characters: dict[str, int] = defaultdict(int)
    retained: list[ContextCandidate] = []

    for candidate in sorted(evaluation.eligible, key=_packing_key):
        characters, byte_count = candidate.content_size()
        count_cap, character_cap = _LANE_CAPS[candidate.source_kind]
        if (
            lane_counts[candidate.source_kind] + 1 > count_cap
            or lane_characters[candidate.source_kind] + characters > character_cap
        ):
            evaluation.drop(candidate, "drop_lane_cap")
        elif (
            used_characters + characters > request.budget.characters
            or used_bytes + byte_count > request.budget.bytes
        ):
            evaluation.drop(candidate, "drop_budget")
        else:
            retained.append(candidate)
            lane_counts[candidate.source_kind] += 1
            lane_characters[candidate.source_kind] += characters
            used_characters += characters
            used_bytes += byte_count
            evaluation.drop(candidate, "included")
    return required + retained


def _render_key(candidate: ContextCandidate) -> tuple[object, ...]:
    return (_RENDER_ORDER[candidate.source_kind], candidate.upstream_rank, candidate.candidate_id)


def select_context(request: P15SelectionInput) -> P15SelectionResult:
    """Select existing typed bytes without inventing, truncating, or persisting facts."""

    stopped = _required_preflight(request)
    if stopped is not None:
        return stopped

    evaluation = _initial_optional_filter(request)
    _resolve_conflicts(evaluation)
    _deduplicate(evaluation)
    selected = _pack(request, evaluation)
    for candidate in (request.definition.candidate, request.current_message.candidate):
        evaluation.drop(candidate, "included")
    status = "clarify" if evaluation.clarification_required else "select"
    return P15SelectionResult(
        status=status,
        selected=tuple(sorted(selected, key=_render_key)),
        decisions=tuple(
            evaluation.decisions[candidate.candidate_id]
            for candidate in request.all_candidates()
            if candidate.candidate_id in evaluation.decisions
        ),
        clarification_required=evaluation.clarification_required,
        normal_transition=request.external_context.continuity_reset,
        input_snapshot_digest=request.snapshot_digest(),
    )
