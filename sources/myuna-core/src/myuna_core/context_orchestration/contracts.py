from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from typing import Mapping


P15_CONTRACT_SCHEMA = "myuna.p15-cross-source-orchestration-contract.v1"
P15_INPUT_SCHEMA = "myuna.p15-input.v1"
P15_RESULT_SCHEMA = "myuna.p15-selection-result.v1"

SOURCE_KINDS = (
    "definition",
    "current_message",
    "profile",
    "temporal",
    "external_summary",
    "external_recent_turn",
    "visual_observation",
    "affinity_state",
)
SEMANTIC_DOMAINS = (
    "policy",
    "current_intent",
    "stable_fact",
    "current_time_bounded_fact",
    "continuity",
    "visual_evidence",
    "style",
)
DOMAIN_SOURCE_KINDS = {
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
CANDIDATE_STATES = ("active", "stale", "expired", "unavailable")
DELIVERY_STATES = ("delivered", "failed", "pending", "abandoned", "crash_orphaned")
CAPABILITY_STATES = ("ready", "unavailable", "unknown")
SELECTION_STATUSES = ("select", "clarify", "abstain")

DECISION_REASONS = (
    "included",
    "drop_low_relevance",
    "drop_budget",
    "drop_lane_cap",
    "drop_duplicate",
    "drop_conflict_shadowed",
    "drop_conflict_ambiguous",
    "drop_stale",
    "drop_expired",
    "drop_unknown_provenance",
    "drop_unknown_schema",
    "drop_trusted_time_unavailable",
    "drop_summary_gap",
    "drop_low_confidence",
    "drop_delivery_not_committed",
    "drop_replay_duplicate",
    "drop_capability_unavailable",
    "abstain_required_provenance",
    "abstain_required_oversize",
    "abstain_replay_snapshot_drift",
    "abstain_summary_integrity",
)

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./:@+-]{0,255}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class P15ContractError(ValueError):
    """Content-free fail-closed contract error."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _digest(domain: bytes, payload: Mapping[str, object]) -> str:
    return sha256(domain + b"\0" + _canonical(payload)).hexdigest()


def _safe_id(value: object, code: str) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise P15ContractError(code)
    return value


def _safe_ref(value: object, code: str) -> str:
    if not isinstance(value, str) or _SAFE_REF.fullmatch(value) is None:
        raise P15ContractError(code)
    return value


def _positive_integer(value: object, code: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise P15ContractError(code)
    return value


def _utc(value: datetime, code: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise P15ContractError(code)
    return value.astimezone(timezone.utc)


def text_size(value: str) -> tuple[int, int]:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise P15ContractError("candidate_content_out_of_contract")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise P15ContractError("candidate_content_out_of_contract")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise P15ContractError("candidate_content_out_of_contract") from exc
    return len(value), len(encoded)


@dataclass(frozen=True, slots=True)
class SourceProvenance:
    known: bool
    schema_known: bool
    source_schema: str
    source_version: int
    source_revision: int
    source_ref: str

    def __post_init__(self) -> None:
        if not isinstance(self.known, bool) or not isinstance(self.schema_known, bool):
            raise P15ContractError("provenance_flags_out_of_contract")
        _safe_id(self.source_schema, "provenance_schema_out_of_contract")
        _positive_integer(self.source_version, "provenance_version_out_of_contract")
        _positive_integer(
            self.source_revision,
            "provenance_revision_out_of_contract",
            allow_zero=True,
        )
        _safe_ref(self.source_ref, "provenance_ref_out_of_contract")

    def as_payload(self) -> dict[str, object]:
        return {
            "known": self.known,
            "schema_known": self.schema_known,
            "source_ref": self.source_ref,
            "source_revision": self.source_revision,
            "source_schema": self.source_schema,
            "source_version": self.source_version,
        }


@dataclass(frozen=True, slots=True)
class ContextCandidate:
    candidate_id: str
    source_kind: str
    provenance: SourceProvenance
    content_fragments: tuple[str, ...]
    relevance: int
    upstream_rank: int
    essential_for_current: bool
    semantic_domain: str
    state: str = "active"
    conflict_key: str | None = None
    conflicts_with_current: bool = False
    material_conflict: bool = False

    def __post_init__(self) -> None:
        _safe_id(self.candidate_id, "candidate_id_out_of_contract")
        if self.source_kind not in SOURCE_KINDS:
            raise P15ContractError("candidate_source_kind_out_of_contract")
        if not self.content_fragments:
            raise P15ContractError("candidate_content_out_of_contract")
        for fragment in self.content_fragments:
            text_size(fragment)
        if (
            isinstance(self.relevance, bool)
            or not isinstance(self.relevance, int)
            or not 0 <= self.relevance <= 100
        ):
            raise P15ContractError("candidate_relevance_out_of_contract")
        _positive_integer(
            self.upstream_rank,
            "candidate_rank_out_of_contract",
            allow_zero=True,
        )
        if not isinstance(self.essential_for_current, bool):
            raise P15ContractError("candidate_essential_flag_out_of_contract")
        if self.semantic_domain not in SEMANTIC_DOMAINS:
            raise P15ContractError("candidate_domain_out_of_contract")
        if self.source_kind not in DOMAIN_SOURCE_KINDS[self.semantic_domain]:
            raise P15ContractError("candidate_domain_source_mismatch")
        if self.state not in CANDIDATE_STATES:
            raise P15ContractError("candidate_state_out_of_contract")
        if self.conflict_key is not None:
            _safe_id(self.conflict_key, "candidate_conflict_key_out_of_contract")
        if not isinstance(self.conflicts_with_current, bool) or not isinstance(
            self.material_conflict, bool
        ):
            raise P15ContractError("candidate_conflict_flags_out_of_contract")

    @property
    def content_digest(self) -> str:
        return _digest(
            b"myuna-p15-content-fragments-v1",
            {"fragments": list(self.content_fragments)},
        )

    def content_size(self) -> tuple[int, int]:
        sizes = tuple(text_size(fragment) for fragment in self.content_fragments)
        return sum(item[0] for item in sizes), sum(item[1] for item in sizes)

    def snapshot_payload(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "conflict_key": self.conflict_key,
            "conflicts_with_current": self.conflicts_with_current,
            "content_digest": self.content_digest,
            "essential_for_current": self.essential_for_current,
            "material_conflict": self.material_conflict,
            "provenance": self.provenance.as_payload(),
            "relevance": self.relevance,
            "semantic_domain": self.semantic_domain,
            "source_kind": self.source_kind,
            "state": self.state,
            "upstream_rank": self.upstream_rank,
        }


def _require_kind(candidate: ContextCandidate, expected: str) -> None:
    if candidate.source_kind != expected:
        raise P15ContractError(f"{expected}_lane_type_mismatch")


@dataclass(frozen=True, slots=True)
class DefinitionLane:
    candidate: ContextCandidate
    verified_release: bool

    def __post_init__(self) -> None:
        _require_kind(self.candidate, "definition")
        if not isinstance(self.verified_release, bool):
            raise P15ContractError("definition_release_flag_out_of_contract")


@dataclass(frozen=True, slots=True)
class CurrentMessageLane:
    candidate: ContextCandidate
    authenticated: bool
    requires_trusted_time: bool = False
    continuity_required: bool = False

    def __post_init__(self) -> None:
        _require_kind(self.candidate, "current_message")
        if not all(
            isinstance(value, bool)
            for value in (
                self.authenticated,
                self.requires_trusted_time,
                self.continuity_required,
            )
        ):
            raise P15ContractError("current_message_flags_out_of_contract")


@dataclass(frozen=True, slots=True)
class ProfileLane:
    candidate: ContextCandidate

    def __post_init__(self) -> None:
        _require_kind(self.candidate, "profile")


@dataclass(frozen=True, slots=True)
class TemporalLane:
    candidate: ContextCandidate
    expires_at: datetime

    def __post_init__(self) -> None:
        _require_kind(self.candidate, "temporal")
        object.__setattr__(self, "expires_at", _utc(self.expires_at, "temporal_expiry_invalid"))


@dataclass(frozen=True, slots=True)
class SummaryLane:
    candidate: ContextCandidate
    coverage_start: int
    coverage_end: int
    integrity_known: bool

    def __post_init__(self) -> None:
        _require_kind(self.candidate, "external_summary")
        start = _positive_integer(self.coverage_start, "summary_coverage_out_of_contract")
        end = _positive_integer(self.coverage_end, "summary_coverage_out_of_contract")
        if start > end or not isinstance(self.integrity_known, bool):
            raise P15ContractError("summary_coverage_out_of_contract")


@dataclass(frozen=True, slots=True)
class RecentTurnLane:
    candidate: ContextCandidate
    sequence: int
    delivery_state: str
    replay_of: str | None = None

    def __post_init__(self) -> None:
        _require_kind(self.candidate, "external_recent_turn")
        _positive_integer(self.sequence, "recent_turn_sequence_out_of_contract")
        if self.delivery_state not in DELIVERY_STATES:
            raise P15ContractError("recent_turn_delivery_state_out_of_contract")
        if self.replay_of is not None:
            _safe_id(self.replay_of, "recent_turn_replay_ref_out_of_contract")


@dataclass(frozen=True, slots=True)
class VisualObservationLane:
    candidate: ContextCandidate
    confidence: float

    def __post_init__(self) -> None:
        _require_kind(self.candidate, "visual_observation")
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
            raise P15ContractError("visual_confidence_out_of_contract")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise P15ContractError("visual_confidence_out_of_contract")


@dataclass(frozen=True, slots=True)
class AffinityStateLane:
    candidate: ContextCandidate
    capability_state: str
    capability_digest: str

    def __post_init__(self) -> None:
        _require_kind(self.candidate, "affinity_state")
        if self.candidate.semantic_domain != "style":
            raise P15ContractError("affinity_domain_out_of_contract")
        if self.capability_state not in CAPABILITY_STATES:
            raise P15ContractError("affinity_capability_state_out_of_contract")
        if not isinstance(self.capability_digest, str) or _SHA256.fullmatch(
            self.capability_digest
        ) is None:
            raise P15ContractError("affinity_capability_digest_out_of_contract")


@dataclass(frozen=True, slots=True)
class ExternalContextLanes:
    summary: SummaryLane | None
    recent_turns: tuple[RecentTurnLane, ...]
    continuity_reset: bool = False
    reset_reason: str = "none"

    def __post_init__(self) -> None:
        if not isinstance(self.continuity_reset, bool):
            raise P15ContractError("continuity_reset_flag_out_of_contract")
        expected = "authorized_generation_transition" if self.continuity_reset else "none"
        if self.reset_reason != expected:
            raise P15ContractError("continuity_reset_reason_out_of_contract")


@dataclass(frozen=True, slots=True)
class SelectionBudget:
    characters: int
    bytes: int

    def __post_init__(self) -> None:
        _positive_integer(self.characters, "selection_character_budget_out_of_contract")
        _positive_integer(self.bytes, "selection_byte_budget_out_of_contract")


@dataclass(frozen=True, slots=True)
class TrustedTimeState:
    status: str
    now: datetime | None
    source: str | None = None
    sequence: int = 0

    def __post_init__(self) -> None:
        if self.status not in ("available", "unavailable"):
            raise P15ContractError("trusted_time_status_out_of_contract")
        if self.status == "available":
            if self.now is None or self.source is None:
                raise P15ContractError("trusted_time_sample_missing")
            object.__setattr__(self, "now", _utc(self.now, "trusted_time_sample_invalid"))
            _safe_id(self.source, "trusted_time_source_out_of_contract")
            _positive_integer(self.sequence, "trusted_time_sequence_out_of_contract")
        elif self.now is not None or self.source is not None or self.sequence != 0:
            raise P15ContractError("trusted_time_unavailable_state_invalid")


@dataclass(frozen=True, slots=True)
class P15SelectionInput:
    event_id: str
    budget: SelectionBudget
    trusted_time: TrustedTimeState
    replay_snapshot_match: bool
    definition: DefinitionLane
    current_message: CurrentMessageLane
    profile: tuple[ProfileLane, ...]
    temporal: tuple[TemporalLane, ...]
    external_context: ExternalContextLanes
    visual_observation: VisualObservationLane | None = None
    affinity_state: AffinityStateLane | None = None
    schema: str = P15_INPUT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != P15_INPUT_SCHEMA:
            raise P15ContractError("p15_input_schema_unknown")
        _safe_id(self.event_id, "p15_event_id_out_of_contract")
        if not isinstance(self.replay_snapshot_match, bool):
            raise P15ContractError("p15_replay_snapshot_flag_out_of_contract")
        ids = [candidate.candidate_id for candidate in self.all_candidates()]
        if len(ids) != len(set(ids)):
            raise P15ContractError("p15_candidate_id_duplicate")

    def all_candidates(self) -> tuple[ContextCandidate, ...]:
        values = [self.definition.candidate, self.current_message.candidate]
        values.extend(item.candidate for item in self.profile)
        values.extend(item.candidate for item in self.temporal)
        if self.external_context.summary is not None:
            values.append(self.external_context.summary.candidate)
        values.extend(item.candidate for item in self.external_context.recent_turns)
        if self.visual_observation is not None:
            values.append(self.visual_observation.candidate)
        if self.affinity_state is not None:
            values.append(self.affinity_state.candidate)
        return tuple(values)

    def snapshot_digest(self) -> str:
        return _digest(
            b"myuna-p15-input-snapshot-v1",
            {
                "budget": {
                    "bytes": self.budget.bytes,
                    "characters": self.budget.characters,
                },
                "candidates": [item.snapshot_payload() for item in self.all_candidates()],
                "continuity_reset": self.external_context.continuity_reset,
                "event_id": self.event_id,
                "reset_reason": self.external_context.reset_reason,
                "schema": self.schema,
                "trusted_time": {
                    "now": self.trusted_time.now.isoformat(timespec="microseconds")
                    if self.trusted_time.now is not None
                    else None,
                    "sequence": self.trusted_time.sequence,
                    "source": self.trusted_time.source,
                    "status": self.trusted_time.status,
                },
            },
        )


@dataclass(frozen=True, slots=True)
class CandidateDecision:
    candidate_id: str
    source_kind: str
    reason: str

    def __post_init__(self) -> None:
        _safe_id(self.candidate_id, "decision_candidate_id_out_of_contract")
        if self.source_kind not in SOURCE_KINDS and self.source_kind != "request":
            raise P15ContractError("decision_source_kind_out_of_contract")
        if self.reason not in DECISION_REASONS:
            raise P15ContractError("decision_reason_out_of_contract")


@dataclass(frozen=True, slots=True)
class P15SelectionResult:
    status: str
    selected: tuple[ContextCandidate, ...]
    decisions: tuple[CandidateDecision, ...]
    clarification_required: bool
    normal_transition: bool
    input_snapshot_digest: str
    fault: bool = False
    schema: str = P15_RESULT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != P15_RESULT_SCHEMA or self.status not in SELECTION_STATUSES:
            raise P15ContractError("p15_result_out_of_contract")
        if not all(
            isinstance(value, bool)
            for value in (self.clarification_required, self.normal_transition, self.fault)
        ):
            raise P15ContractError("p15_result_flags_out_of_contract")
        if self.fault:
            raise P15ContractError("p15_normal_selection_cannot_be_fault")
        if _SHA256.fullmatch(self.input_snapshot_digest) is None:
            raise P15ContractError("p15_snapshot_digest_out_of_contract")
        if self.status == "abstain" and self.selected:
            raise P15ContractError("p15_abstention_contains_projection")

    def audit_payload(self) -> dict[str, object]:
        return {
            "clarification_required": self.clarification_required,
            "decisions": [
                {
                    "candidate_id": decision.candidate_id,
                    "reason": decision.reason,
                    "source_kind": decision.source_kind,
                }
                for decision in self.decisions
            ],
            "fault": self.fault,
            "input_snapshot_digest": self.input_snapshot_digest,
            "normal_transition": self.normal_transition,
            "schema": self.schema,
            "selected": [
                {
                    "candidate_id": candidate.candidate_id,
                    "content_digest": candidate.content_digest,
                    "source_kind": candidate.source_kind,
                }
                for candidate in self.selected
            ],
            "status": self.status,
        }
