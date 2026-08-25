from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date, datetime
import json
import os
from pathlib import Path
import re
import stat
from typing import Mapping, Sequence

from .contracts import (
    CompleteTurn,
    EpisodicCapsule,
    EpisodicMemoryError,
    TurnPrimitive,
    TurnTimeBinding,
    TurnTimeCorrection,
    SUPPORTED_CALENDAR_ZONES,
    canonical_bytes,
    require_digest,
    require_id,
    semantic_digest,
)
from .owner_day import OwnerDayPolicy, owner_day_label
from .temporal_bridge import TemporalIntervalIndexSnapshot


INDEX_SCHEMA = "myuna.p07-episodic-index.v2"
SOURCE_REFERENCE_SCHEMA = "myuna.p07-episodic-source-reference.v2"
SOURCE_MANIFEST_SCHEMA = "myuna.p07-derivative-source-manifest.v1"


_ACTOR = re.compile(r"(?<![A-Za-z0-9_])[A-Z][A-Za-z0-9_-]{1,31}(?![A-Za-z0-9_])")
_NUMBER = re.compile(r"\d+(?:[.:]\d+)?")
_TIME = re.compile(r"(?:\d{1,2}:\d{2}|今天|昨天|明天|上午|下午|晚上|today|yesterday)", re.I)
_NEGATION = ("不", "没", "未", "无", "not", "never")
_CONDITION = ("如果", "若", "除非", "if", "unless")
_ACTIONS = ("建议", "赞同", "接受", "拒绝", "去", "换", "开始", "停止", "完成", "承诺")
_LOCATIONS = ("江边", "海边", "公园", "学校", "上海", "洛杉矶", "Santa Monica")


def _present_markers(source: str, markers: Sequence[str]) -> tuple[str, ...]:
    folded = source.casefold()
    return tuple(marker for marker in markers if marker.casefold() in folded)


def _source_text(turn: CompleteTurn) -> str:
    return turn.draft.owner.text + "\n" + turn.draft.assistant.text


def coverage_findings(turn: CompleteTurn, primitive: TurnPrimitive) -> tuple[str, ...]:
    if (
        primitive.source_sequence != turn.draft.sequence
        or primitive.source_turn_id != turn.draft.turn_id
        or primitive.source_turn_digest != turn.turn_digest
    ):
        raise EpisodicMemoryError("primitive_source_pointer_drifted")
    source = _source_text(turn)
    structured = (
        primitive.actors
        + primitive.proposals_assertions
        + primitive.stances
        + primitive.decisions_commitments
        + primitive.actions_state_changes
        + primitive.entities
        + primitive.locations
        + primitive.times
        + primitive.numbers
        + primitive.negations_conditions
        + primitive.preferences
        + primitive.unresolved_items
    )
    findings: set[str] = set()
    for item in structured:
        if item not in source:
            findings.add("structured_item_not_source_grounded")
    actors = set(_ACTOR.findall(source))
    if actors - set(primitive.actors):
        findings.add("actor_coverage_incomplete")
    numbers = set(_NUMBER.findall(source))
    if numbers - set(primitive.numbers):
        findings.add("number_coverage_incomplete")
    times = set(_TIME.findall(source))
    if times and not all(any(value in item for item in primitive.times) for value in times):
        findings.add("time_coverage_incomplete")
    required_negations = {value for value in _NEGATION + _CONDITION if value in source.casefold()}
    if required_negations and not all(
        any(value in item.casefold() for item in primitive.negations_conditions)
        for value in required_negations
    ):
        findings.add("negation_condition_coverage_incomplete")
    required_actions = {value for value in _ACTIONS if value in source}
    action_fields = (
        primitive.actions_state_changes
        + primitive.proposals_assertions
        + primitive.stances
    )
    if required_actions and not all(
        any(value in item for item in action_fields) for value in required_actions
    ):
        findings.add("action_state_coverage_incomplete")
    required_locations = {value for value in _LOCATIONS if value in source}
    if required_locations - set(primitive.locations):
        findings.add("location_coverage_incomplete")
    return tuple(sorted(findings))


def certify_primitive(turn: CompleteTurn, candidate: TurnPrimitive) -> TurnPrimitive:
    findings = coverage_findings(turn, candidate)
    expected_state = "complete" if not findings and not candidate.ambiguity_codes else "ambiguous"
    if findings:
        expected_state = "coverage_incomplete"
    return replace(
        candidate,
        coverage_state=expected_state,
        ambiguity_codes=findings or candidate.ambiguity_codes,
    )


def derive_grounded_primitive(turn: CompleteTurn) -> TurnPrimitive:
    """Build a deterministic, source-grounded catalog primitive.

    The primitive is intentionally conservative.  It is a rebuildable candidate
    index, never a replacement for the authoritative raw turn.
    """

    source = _source_text(turn)
    actors = tuple(sorted(set(_ACTOR.findall(source))))
    numbers = tuple(sorted(set(_NUMBER.findall(source))))
    times = tuple(sorted(set(_TIME.findall(source))))
    actions = _present_markers(source, _ACTIONS)
    locations = _present_markers(source, _LOCATIONS)
    negations_conditions = _present_markers(source, _NEGATION + _CONDITION)
    proposals = tuple(marker for marker in actions if marker in {"建议", "承诺"})
    stances = tuple(marker for marker in actions if marker in {"赞同", "接受", "拒绝"})
    decisions = tuple(marker for marker in actions if marker in {"接受", "拒绝", "承诺"})
    candidate = TurnPrimitive(
        source_sequence=turn.draft.sequence,
        source_turn_id=turn.draft.turn_id,
        source_turn_digest=turn.turn_digest,
        actors=actors,
        proposals_assertions=proposals,
        stances=stances,
        decisions_commitments=decisions,
        actions_state_changes=actions,
        entities=actors,
        locations=locations,
        times=times,
        numbers=numbers,
        negations_conditions=negations_conditions,
    )
    return certify_primitive(turn, candidate)


@dataclass(frozen=True, slots=True)
class EpisodicSourceReference:
    """Content-free pointer back to exact raw and accepted temporal sources."""

    archive_id: str
    archive_turn_count: int
    archive_head_digest: str
    sequence: int
    turn_id: str
    turn_digest: str
    previous_turn_digest: str
    epoch_id: str
    release_set_id: str
    request_digest: str
    response_digest: str
    delivery_ack_digest: str
    model_history_eligible: bool
    original_time_binding_digest: str
    effective_time_binding_digest: str
    effective_delivered_at_utc: str | None
    time_status: str
    calendar_zone: str
    local_calendar_representation: str | None
    owner_day: str | None
    owner_day_policy_digest: str
    correction_digests: tuple[str, ...]
    temporal_interval_ids: tuple[str, ...]
    temporal_revision_numbers: tuple[int, ...]
    temporal_revision_digests: tuple[str, ...]
    temporal_episode_digests: tuple[str, ...]
    temporal_conflict_keys: tuple[str, ...]
    source_reference_digest: str
    schema: str = SOURCE_REFERENCE_SCHEMA

    def semantic_payload(self) -> dict[str, object]:
        return {
            "archive_head_digest": self.archive_head_digest,
            "archive_id": self.archive_id,
            "archive_turn_count": self.archive_turn_count,
            "calendar_zone": self.calendar_zone,
            "correction_digests": list(self.correction_digests),
            "delivery_ack_digest": self.delivery_ack_digest,
            "effective_delivered_at_utc": self.effective_delivered_at_utc,
            "effective_time_binding_digest": self.effective_time_binding_digest,
            "epoch_id": self.epoch_id,
            "local_calendar_representation": self.local_calendar_representation,
            "model_history_eligible": self.model_history_eligible,
            "original_time_binding_digest": self.original_time_binding_digest,
            "owner_day": self.owner_day,
            "owner_day_policy_digest": self.owner_day_policy_digest,
            "previous_turn_digest": self.previous_turn_digest,
            "release_set_id": self.release_set_id,
            "request_digest": self.request_digest,
            "response_digest": self.response_digest,
            "schema": self.schema,
            "sequence": self.sequence,
            "temporal_conflict_keys": list(self.temporal_conflict_keys),
            "temporal_episode_digests": list(self.temporal_episode_digests),
            "temporal_interval_ids": list(self.temporal_interval_ids),
            "temporal_revision_digests": list(self.temporal_revision_digests),
            "temporal_revision_numbers": list(self.temporal_revision_numbers),
            "time_status": self.time_status,
            "turn_digest": self.turn_digest,
            "turn_id": self.turn_id,
        }

    def payload(self) -> dict[str, object]:
        return self.semantic_payload() | {
            "source_reference_digest": self.source_reference_digest
        }

    def __post_init__(self) -> None:
        if self.schema != SOURCE_REFERENCE_SCHEMA:
            raise EpisodicMemoryError("index_source_reference_schema_unknown")
        require_id(self.archive_id, "index_source_archive")
        require_id(self.turn_id, "index_source_turn")
        require_id(self.epoch_id, "index_source_epoch")
        if (
            isinstance(self.archive_turn_count, bool)
            or not isinstance(self.archive_turn_count, int)
            or self.archive_turn_count < 0
            or isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 1
            or self.sequence > self.archive_turn_count
        ):
            raise EpisodicMemoryError("index_source_sequence_invalid")
        for value, label in (
            (self.archive_head_digest, "index_source_archive_head"),
            (self.turn_digest, "index_source_turn_digest"),
            (self.previous_turn_digest, "index_source_previous_turn"),
            (self.release_set_id, "index_source_release"),
            (self.request_digest, "index_source_request"),
            (self.response_digest, "index_source_response"),
            (self.delivery_ack_digest, "index_source_delivery_ack"),
            (self.original_time_binding_digest, "index_source_original_time"),
            (self.effective_time_binding_digest, "index_source_effective_time"),
            (self.owner_day_policy_digest, "index_source_owner_day_policy"),
        ):
            require_digest(value, label)
        if self.time_status not in {"exact", "unresolved"}:
            raise EpisodicMemoryError("index_source_time_status_unknown")
        if self.calendar_zone not in SUPPORTED_CALENDAR_ZONES:
            raise EpisodicMemoryError("index_source_calendar_zone_unknown")
        if (self.time_status == "exact") != (
            self.owner_day is not None and self.effective_delivered_at_utc is not None
        ):
            raise EpisodicMemoryError("index_source_owner_day_binding_invalid")
        if self.effective_delivered_at_utc is not None:
            try:
                delivered = datetime.fromisoformat(self.effective_delivered_at_utc)
            except (TypeError, ValueError):
                raise EpisodicMemoryError("index_source_time_binding_invalid") from None
            if delivered.tzinfo is None or delivered.utcoffset() is None:
                raise EpisodicMemoryError("index_source_time_binding_invalid")
            if self.local_calendar_representation is None:
                raise EpisodicMemoryError("index_source_local_time_missing")
        elif self.local_calendar_representation is not None:
            raise EpisodicMemoryError("index_source_unresolved_local_time_rejected")
        if not isinstance(self.model_history_eligible, bool):
            raise EpisodicMemoryError("index_source_history_eligibility_invalid")
        if tuple(sorted(set(self.correction_digests))) != self.correction_digests:
            raise EpisodicMemoryError("index_source_digest_set_invalid")
        for values in (
            self.correction_digests,
            self.temporal_revision_digests,
            self.temporal_episode_digests,
        ):
            for value in values:
                require_digest(value, "index_source_digest")
        if not (
            len(self.temporal_interval_ids)
            == len(self.temporal_revision_numbers)
            == len(self.temporal_revision_digests)
            == len(self.temporal_episode_digests)
            == len(self.temporal_conflict_keys)
        ):
            raise EpisodicMemoryError("index_source_temporal_binding_incomplete")
        if tuple(
            sorted(
                zip(
                    self.temporal_interval_ids,
                    self.temporal_revision_numbers,
                    self.temporal_revision_digests,
                    self.temporal_episode_digests,
                    self.temporal_conflict_keys,
                    strict=True,
                )
            )
        ) != tuple(
            zip(
                self.temporal_interval_ids,
                self.temporal_revision_numbers,
                self.temporal_revision_digests,
                self.temporal_episode_digests,
                self.temporal_conflict_keys,
                strict=True,
            )
        ):
            raise EpisodicMemoryError("index_source_temporal_order_invalid")
        for interval_id, revision, conflict_key in zip(
            self.temporal_interval_ids,
            self.temporal_revision_numbers,
            self.temporal_conflict_keys,
            strict=True,
        ):
            require_id(interval_id, "index_source_interval")
            require_id(conflict_key, "index_source_conflict_key")
            if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
                raise EpisodicMemoryError("index_source_temporal_revision_invalid")
        expected = semantic_digest(
            "myuna-p07-episodic-source-reference-v2",
            self.semantic_payload(),
        )
        if self.source_reference_digest != expected:
            raise EpisodicMemoryError("index_source_reference_digest_mismatch")


def _effective_sources(
    turns: Sequence[CompleteTurn],
    corrections: Sequence[TurnTimeCorrection],
) -> tuple[Mapping[int, TurnTimeBinding], tuple[str, ...], Mapping[str, str]]:
    from .diary_generation import effective_turn_time_bindings

    bindings, correction_digests = effective_turn_time_bindings(turns, corrections)
    selected_by_turn = {
        correction.turn_id: correction.correction_digest for correction in corrections
    }
    if tuple(sorted(set(correction_digests))) != correction_digests:
        raise EpisodicMemoryError("index_time_correction_order_invalid")
    return bindings, correction_digests, selected_by_turn


def _temporal_sources(
    temporal_snapshot: TemporalIntervalIndexSnapshot,
    turns: Sequence[CompleteTurn],
    archive_head_digest: str,
) -> Mapping[int, tuple[tuple[str, int, str, str, str], ...]]:
    if temporal_snapshot.archive_head_digest != archive_head_digest:
        raise EpisodicMemoryError("index_temporal_archive_conflict")
    by_sequence = {turn.draft.sequence: turn for turn in turns}
    selected: dict[int, list[tuple[str, int, str, str, str]]] = {}
    for episode in temporal_snapshot.episodes:
        for revision in episode.revisions:
            for sequence, turn_digest in zip(
                revision.source_turn_sequences,
                revision.source_turn_digests,
                strict=True,
            ):
                turn = by_sequence.get(sequence)
                if turn is None or turn.turn_digest != turn_digest:
                    raise EpisodicMemoryError("index_temporal_source_conflict")
                selected.setdefault(sequence, []).append(
                    (
                        revision.interval_id,
                        revision.p08_revision,
                        revision.revision_digest,
                        episode.episode_digest,
                        revision.conflict_key,
                    )
                )
    return {sequence: tuple(sorted(values)) for sequence, values in selected.items()}


def derive_snapshot(
    turns: Sequence[CompleteTurn],
    *,
    archive_id: str = "synthetic-episodic-archive",
    corrections: Sequence[TurnTimeCorrection] = (),
    temporal_snapshot: TemporalIntervalIndexSnapshot | None = None,
    owner_day_policy: OwnerDayPolicy | None = None,
) -> "EpisodicIndexSnapshot":
    """Rebuild immutable turn, local-date, and conservative event capsules.

    Every authoritative raw turn retains a turn capsule. Date and event
    capsules are derivative candidate-selection aids only, never cross an
    isolated control turn, and are omitted when trusted time is unresolved.
    """

    effective_bindings, _, _ = _effective_sources(turns, corrections)
    primitives = tuple(derive_grounded_primitive(turn) for turn in turns)

    def label(primitive: TurnPrimitive) -> str:
        values = (
            primitive.actors
            + primitive.proposals_assertions
            + primitive.stances
            + primitive.actions_state_changes
            + primitive.locations
            + primitive.times
            + primitive.numbers
            + primitive.negations_conditions
        )
        rendered = " ".join(dict.fromkeys(values))
        return rendered[:512] if rendered else f"turn:{primitive.source_sequence}"

    turn_capsules = tuple(
        EpisodicCapsule(
            capsule_id=f"turn-{turn.draft.sequence:012d}",
            capsule_kind="turn",
            source_start=turn.draft.sequence,
            source_end=turn.draft.sequence,
            source_terminal_digest=turn.turn_digest,
            primitive_digests=(primitive.primitive_digest,),
            label=label(primitive),
            coverage_state=primitive.coverage_state,
            ambiguity_codes=primitive.ambiguity_codes,
        )
        for turn, primitive in zip(turns, primitives, strict=True)
    )

    def local_day(turn: CompleteTurn) -> date | None:
        binding = effective_bindings[turn.draft.sequence]
        if (
            not turn.model_history_eligible
            or binding.status != "exact"
            or binding.delivered_at_utc is None
        ):
            return None
        from zoneinfo import ZoneInfo

        return binding.delivered_at_utc.astimezone(
            ZoneInfo(binding.calendar_zone)
        ).date()

    date_capsules: list[EpisodicCapsule] = []
    run_start: int | None = None
    run_day: date | None = None

    def flush_date(end: int) -> None:
        nonlocal run_start, run_day
        if run_start is None or run_day is None:
            return
        selected = primitives[run_start - 1 : end]
        date_capsules.append(
            _range_capsule(
                "date",
                run_start,
                end,
                turns,
                selected,
                run_day.isoformat(),
            )
        )

    for index, turn in enumerate(turns, start=1):
        day = local_day(turn)
        if day is None:
            flush_date(index - 1)
            run_start = None
            run_day = None
        elif run_day is None:
            run_start = index
            run_day = day
        elif day != run_day:
            flush_date(index - 1)
            run_start = index
            run_day = day
    flush_date(len(turns))

    event_capsules: list[EpisodicCapsule] = []
    event_start: int | None = None
    event_terms: set[str] = set()
    event_day: date | None = None

    def flush_event(end: int) -> None:
        nonlocal event_start, event_terms, event_day
        if event_start is None or end - event_start + 1 < 2:
            return
        selected = primitives[event_start - 1 : end]
        event_capsules.append(
            _range_capsule(
                "event",
                event_start,
                end,
                turns,
                selected,
                " ".join(sorted(event_terms))[:512],
            )
        )

    for index, (turn, primitive) in enumerate(
        zip(turns, primitives, strict=True), start=1
    ):
        day = local_day(turn)
        terms = _event_terms(primitive)
        if day is None or not terms:
            flush_event(index - 1)
            event_start = None
            event_terms = set()
            event_day = None
        elif event_start is None:
            event_start = index
            event_terms = set(terms)
            event_day = day
        elif day == event_day and event_terms & terms:
            event_terms.update(terms)
        else:
            flush_event(index - 1)
            event_start = index
            event_terms = set(terms)
            event_day = day
    flush_event(len(turns))

    return build_snapshot(
        turns,
        primitives,
        turn_capsules + tuple(date_capsules) + tuple(event_capsules),
        archive_id=archive_id,
        corrections=corrections,
        temporal_snapshot=temporal_snapshot,
        owner_day_policy=owner_day_policy,
    )


def _event_terms(primitive: TurnPrimitive) -> set[str]:
    return set(
        primitive.actors
        + primitive.actions_state_changes
        + primitive.decisions_commitments
        + primitive.entities
        + primitive.locations
    )


def _range_capsule(
    kind: str,
    start: int,
    end: int,
    turns: Sequence[CompleteTurn],
    primitives: Sequence[TurnPrimitive],
    label: str,
) -> EpisodicCapsule:
    ambiguity = tuple(
        sorted(
            {
                code
                for primitive in primitives
                for code in primitive.ambiguity_codes
            }
        )
    )
    coverage = "complete"
    if any(
        primitive.coverage_state == "coverage_incomplete"
        for primitive in primitives
    ):
        coverage = "coverage_incomplete"
    elif ambiguity or any(
        primitive.coverage_state == "ambiguous" for primitive in primitives
    ):
        coverage = "ambiguous"
    return EpisodicCapsule(
        capsule_id=f"{kind}-{start:012d}-{end:012d}",
        capsule_kind=kind,
        source_start=start,
        source_end=end,
        source_terminal_digest=turns[end - 1].turn_digest,
        primitive_digests=tuple(item.primitive_digest for item in primitives),
        label=label or f"{kind}:{start}-{end}",
        coverage_state=coverage,
        ambiguity_codes=ambiguity,
    )


@dataclass(frozen=True, slots=True)
class EpisodicIndexSnapshot:
    archive_id: str
    archive_turn_count: int
    archive_head_digest: str
    source_references: tuple[EpisodicSourceReference, ...]
    correction_digests: tuple[str, ...]
    temporal_snapshot_digest: str
    source_closure_digest: str
    primitives: tuple[TurnPrimitive, ...]
    capsules: tuple[EpisodicCapsule, ...]
    snapshot_digest: str
    schema: str = INDEX_SCHEMA

    def semantic_payload(self) -> dict[str, object]:
        return {
            "archive_head_digest": self.archive_head_digest,
            "archive_id": self.archive_id,
            "archive_turn_count": self.archive_turn_count,
            "capsules": [capsule.payload() for capsule in self.capsules],
            "correction_digests": list(self.correction_digests),
            "primitives": [primitive.payload() for primitive in self.primitives],
            "schema": self.schema,
            "source_closure_digest": self.source_closure_digest,
            "source_references": [item.payload() for item in self.source_references],
            "temporal_snapshot_digest": self.temporal_snapshot_digest,
        }

    def __post_init__(self) -> None:
        if self.schema != INDEX_SCHEMA:
            raise EpisodicMemoryError("index_schema_unknown")
        require_id(self.archive_id, "index_archive_id")
        require_digest(self.archive_head_digest, "index_archive_head")
        require_digest(self.temporal_snapshot_digest, "index_temporal_snapshot")
        require_digest(self.source_closure_digest, "index_source_closure")
        if (
            isinstance(self.archive_turn_count, bool)
            or not isinstance(self.archive_turn_count, int)
            or self.archive_turn_count < 0
            or len(self.source_references) != self.archive_turn_count
            or len(self.primitives) != self.archive_turn_count
        ):
            raise EpisodicMemoryError("index_archive_count_invalid")
        if tuple(item.sequence for item in self.source_references) != tuple(
            range(1, self.archive_turn_count + 1)
        ):
            raise EpisodicMemoryError("index_source_reference_order_invalid")
        if any(
            item.archive_id != self.archive_id
            or item.archive_turn_count != self.archive_turn_count
            or item.archive_head_digest != self.archive_head_digest
            for item in self.source_references
        ):
            raise EpisodicMemoryError("index_source_reference_archive_drifted")
        previous = "0" * 64
        for reference, primitive in zip(
            self.source_references,
            self.primitives,
            strict=True,
        ):
            if (
                reference.previous_turn_digest != previous
                or primitive.source_sequence != reference.sequence
                or primitive.source_turn_id != reference.turn_id
                or primitive.source_turn_digest != reference.turn_digest
            ):
                raise EpisodicMemoryError("index_source_chain_drifted")
            previous = reference.turn_digest
        if previous != self.archive_head_digest:
            raise EpisodicMemoryError("index_source_head_drifted")
        if tuple(sorted(set(self.correction_digests))) != self.correction_digests:
            raise EpisodicMemoryError("index_correction_digest_order_invalid")
        for digest in self.correction_digests:
            require_digest(digest, "index_correction_digest")
        if tuple(
            sorted(
                {
                    digest
                    for reference in self.source_references
                    for digest in reference.correction_digests
                }
            )
        ) != self.correction_digests:
            raise EpisodicMemoryError("index_correction_closure_drifted")
        primitive_by_sequence = {
            primitive.source_sequence: primitive for primitive in self.primitives
        }
        seen_capsules: set[str] = set()
        capsule_ranges: dict[tuple[str, int, int], str] = {}
        for capsule in self.capsules:
            if capsule.source_end > self.archive_turn_count:
                raise EpisodicMemoryError("capsule_source_pointer_drifted")
            if capsule.capsule_id in seen_capsules:
                raise EpisodicMemoryError("capsule_replay_detected")
            seen_capsules.add(capsule.capsule_id)
            range_key = (
                capsule.capsule_kind,
                capsule.source_start,
                capsule.source_end,
            )
            prior_digest = capsule_ranges.get(range_key)
            if prior_digest is not None and prior_digest != capsule.capsule_digest:
                raise EpisodicMemoryError("capsule_conflict")
            capsule_ranges[range_key] = capsule.capsule_digest
            selected = tuple(
                primitive_by_sequence.get(sequence)
                for sequence in range(capsule.source_start, capsule.source_end + 1)
            )
            if (
                any(item is None for item in selected)
                or tuple(
                    item.primitive_digest for item in selected if item is not None
                )
                != capsule.primitive_digests
                or self.source_references[capsule.source_end - 1].turn_digest
                != capsule.source_terminal_digest
            ):
                raise EpisodicMemoryError("capsule_source_pointer_drifted")
            if capsule.coverage_state == "complete" and any(
                item is not None and item.coverage_state != "complete"
                for item in selected
            ):
                raise EpisodicMemoryError("capsule_coverage_mismatch")
        closure = semantic_digest(
            "myuna-p07-episodic-source-closure-v2",
            {
                "archive_head_digest": self.archive_head_digest,
                "archive_id": self.archive_id,
                "archive_turn_count": self.archive_turn_count,
                "correction_digests": list(self.correction_digests),
                "source_reference_digests": [
                    item.source_reference_digest for item in self.source_references
                ],
                "temporal_snapshot_digest": self.temporal_snapshot_digest,
            },
        )
        if closure != self.source_closure_digest:
            raise EpisodicMemoryError("index_source_closure_digest_mismatch")
        expected = semantic_digest("myuna-p07-episodic-index-snapshot-v2", self.semantic_payload())
        if expected != self.snapshot_digest:
            raise EpisodicMemoryError("index_snapshot_digest_mismatch")

    def source_manifest(
        self,
        sequences: Sequence[int],
    ) -> tuple[dict[str, object], str]:
        selected_numbers = tuple(sorted(set(sequences)))
        if any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 1
            or value > self.archive_turn_count
            for value in selected_numbers
        ):
            raise EpisodicMemoryError("index_source_manifest_sequence_invalid")
        by_sequence = {item.sequence: item for item in self.source_references}
        selected = tuple(by_sequence[value] for value in selected_numbers)
        manifest: dict[str, object] = {
            "archive_head_digest": self.archive_head_digest,
            "archive_id": self.archive_id,
            "archive_turn_count": self.archive_turn_count,
            "correction_digests": list(self.correction_digests),
            "schema": SOURCE_MANIFEST_SCHEMA,
            "snapshot_digest": self.snapshot_digest,
            "source_closure_digest": self.source_closure_digest,
            "source_epoch_ids": [item.epoch_id for item in selected],
            "source_reference_digests": [
                item.source_reference_digest for item in selected
            ],
            "source_release_set_ids": [item.release_set_id for item in selected],
            "source_sequences": list(selected_numbers),
            "source_turn_digests": [item.turn_digest for item in selected],
            "source_turn_ids": [item.turn_id for item in selected],
            "temporal_snapshot_digest": self.temporal_snapshot_digest,
        }
        return manifest, semantic_digest(
            "myuna-p07-derivative-source-manifest-v1", manifest
        )

    def audit_projection(self) -> dict[str, object]:
        return {
            "archive_head_digest": self.archive_head_digest,
            "archive_id": self.archive_id,
            "archive_turn_count": self.archive_turn_count,
            "capsule_count": len(self.capsules),
            "coverage_incomplete_count": sum(
                primitive.coverage_state != "complete" for primitive in self.primitives
            ),
            "primitive_count": len(self.primitives),
            "schema": self.schema,
            "source_closure_digest": self.source_closure_digest,
            "snapshot_digest": self.snapshot_digest,
            "temporal_snapshot_digest": self.temporal_snapshot_digest,
        }


def build_snapshot(
    turns: Sequence[CompleteTurn],
    primitives: Sequence[TurnPrimitive],
    capsules: Sequence[EpisodicCapsule] = (),
    *,
    archive_id: str = "synthetic-episodic-archive",
    corrections: Sequence[TurnTimeCorrection] = (),
    temporal_snapshot: TemporalIntervalIndexSnapshot | None = None,
    owner_day_policy: OwnerDayPolicy | None = None,
) -> EpisodicIndexSnapshot:
    if len(turns) != len(primitives):
        raise EpisodicMemoryError("index_archive_coverage_incomplete")
    require_id(archive_id, "index_archive_id")
    previous = "0" * 64
    certified: list[TurnPrimitive] = []
    for sequence, (turn, primitive) in enumerate(zip(turns, primitives, strict=True), start=1):
        if turn.draft.sequence != sequence or turn.draft.previous_turn_digest != previous:
            raise EpisodicMemoryError("archive_turn_chain_drifted")
        selected = certify_primitive(turn, primitive)
        certified.append(selected)
        previous = turn.turn_digest
    archive_head_digest = previous
    selected_owner_day_policy = owner_day_policy or OwnerDayPolicy()
    selected_temporal_snapshot = temporal_snapshot or TemporalIntervalIndexSnapshot.empty(
        archive_head_digest
    )
    effective_bindings, correction_digests, corrections_by_turn = _effective_sources(
        turns, corrections
    )
    temporal_by_sequence = _temporal_sources(
        selected_temporal_snapshot, turns, archive_head_digest
    )
    source_references: list[EpisodicSourceReference] = []
    for turn in turns:
        binding = effective_bindings[turn.draft.sequence]
        temporal = temporal_by_sequence.get(turn.draft.sequence, ())
        owner_day = None
        if binding.status == "exact" and binding.delivered_at_utc is not None:
            owner_day = owner_day_label(
                binding.delivered_at_utc, selected_owner_day_policy
            ).isoformat()
        correction_digest = corrections_by_turn.get(turn.draft.turn_id)
        semantic = {
            "archive_head_digest": archive_head_digest,
            "archive_id": archive_id,
            "archive_turn_count": len(turns),
            "calendar_zone": binding.calendar_zone,
            "correction_digests": ([] if correction_digest is None else [correction_digest]),
            "delivery_ack_digest": turn.draft.delivery_ack_digest,
            "effective_delivered_at_utc": (
                None
                if binding.delivered_at_utc is None
                else binding.delivered_at_utc.isoformat(timespec="microseconds")
            ),
            "effective_time_binding_digest": binding.binding_digest,
            "epoch_id": turn.draft.epoch_id,
            "local_calendar_representation": binding.local_calendar_representation,
            "model_history_eligible": turn.model_history_eligible,
            "original_time_binding_digest": turn.draft.time_binding.binding_digest,
            "owner_day": owner_day,
            "owner_day_policy_digest": selected_owner_day_policy.policy_digest,
            "previous_turn_digest": turn.draft.previous_turn_digest,
            "release_set_id": turn.draft.release_set_id,
            "request_digest": turn.draft.request_digest,
            "response_digest": turn.draft.response_digest,
            "schema": SOURCE_REFERENCE_SCHEMA,
            "sequence": turn.draft.sequence,
            "temporal_conflict_keys": [item[4] for item in temporal],
            "temporal_episode_digests": [item[3] for item in temporal],
            "temporal_interval_ids": [item[0] for item in temporal],
            "temporal_revision_digests": [item[2] for item in temporal],
            "temporal_revision_numbers": [item[1] for item in temporal],
            "time_status": binding.status,
            "turn_digest": turn.turn_digest,
            "turn_id": turn.draft.turn_id,
        }
        source_references.append(
            EpisodicSourceReference(
                archive_id=archive_id,
                archive_turn_count=len(turns),
                archive_head_digest=archive_head_digest,
                sequence=turn.draft.sequence,
                turn_id=turn.draft.turn_id,
                turn_digest=turn.turn_digest,
                previous_turn_digest=turn.draft.previous_turn_digest,
                epoch_id=turn.draft.epoch_id,
                release_set_id=turn.draft.release_set_id,
                request_digest=turn.draft.request_digest,
                response_digest=turn.draft.response_digest,
                delivery_ack_digest=turn.draft.delivery_ack_digest,
                model_history_eligible=turn.model_history_eligible,
                original_time_binding_digest=turn.draft.time_binding.binding_digest,
                effective_time_binding_digest=binding.binding_digest,
                effective_delivered_at_utc=(
                    None
                    if binding.delivered_at_utc is None
                    else binding.delivered_at_utc.isoformat(timespec="microseconds")
                ),
                time_status=binding.status,
                calendar_zone=binding.calendar_zone,
                local_calendar_representation=binding.local_calendar_representation,
                owner_day=owner_day,
                owner_day_policy_digest=selected_owner_day_policy.policy_digest,
                correction_digests=(
                    () if correction_digest is None else (correction_digest,)
                ),
                temporal_interval_ids=tuple(item[0] for item in temporal),
                temporal_revision_numbers=tuple(item[1] for item in temporal),
                temporal_revision_digests=tuple(item[2] for item in temporal),
                temporal_episode_digests=tuple(item[3] for item in temporal),
                temporal_conflict_keys=tuple(item[4] for item in temporal),
                source_reference_digest=semantic_digest(
                    "myuna-p07-episodic-source-reference-v2", semantic
                ),
            )
        )
    primitive_by_sequence = {item.source_sequence: item for item in certified}
    seen_capsules: set[str] = set()
    capsule_ranges: dict[tuple[str, int, int], str] = {}
    for capsule in capsules:
        if capsule.capsule_id in seen_capsules:
            raise EpisodicMemoryError("capsule_replay_detected")
        seen_capsules.add(capsule.capsule_id)
        if capsule.capsule_kind in {"event", "date"} and any(
            effective_bindings[sequence].status != "exact"
            for sequence in range(capsule.source_start, capsule.source_end + 1)
        ):
            raise EpisodicMemoryError("capsule_time_unresolved")
        range_key = (capsule.capsule_kind, capsule.source_start, capsule.source_end)
        prior_digest = capsule_ranges.get(range_key)
        if prior_digest is not None and prior_digest != capsule.capsule_digest:
            raise EpisodicMemoryError("capsule_conflict")
        capsule_ranges[range_key] = capsule.capsule_digest
        selected = tuple(
            primitive_by_sequence.get(sequence)
            for sequence in range(capsule.source_start, capsule.source_end + 1)
        )
        if (
            any(item is None for item in selected)
            or tuple(item.primitive_digest for item in selected if item is not None)
            != capsule.primitive_digests
            or turns[capsule.source_end - 1].turn_digest != capsule.source_terminal_digest
        ):
            raise EpisodicMemoryError("capsule_source_pointer_drifted")
        incomplete = any(
            item is not None and item.coverage_state != "complete" for item in selected
        )
        if capsule.coverage_state == "complete" and incomplete:
            raise EpisodicMemoryError("capsule_coverage_mismatch")
    source_closure_digest = semantic_digest(
        "myuna-p07-episodic-source-closure-v2",
        {
            "archive_head_digest": archive_head_digest,
            "archive_id": archive_id,
            "archive_turn_count": len(turns),
            "correction_digests": list(correction_digests),
            "source_reference_digests": [
                item.source_reference_digest for item in source_references
            ],
            "temporal_snapshot_digest": selected_temporal_snapshot.snapshot_digest,
        },
    )
    semantic = {
        "archive_head_digest": archive_head_digest,
        "archive_id": archive_id,
        "archive_turn_count": len(turns),
        "capsules": [item.payload() for item in capsules],
        "correction_digests": list(correction_digests),
        "primitives": [item.payload() for item in certified],
        "schema": INDEX_SCHEMA,
        "source_closure_digest": source_closure_digest,
        "source_references": [item.payload() for item in source_references],
        "temporal_snapshot_digest": selected_temporal_snapshot.snapshot_digest,
    }
    return EpisodicIndexSnapshot(
        archive_id=archive_id,
        archive_turn_count=len(turns),
        archive_head_digest=archive_head_digest,
        source_references=tuple(source_references),
        correction_digests=correction_digests,
        temporal_snapshot_digest=selected_temporal_snapshot.snapshot_digest,
        source_closure_digest=source_closure_digest,
        primitives=tuple(certified),
        capsules=tuple(capsules),
        snapshot_digest=semantic_digest("myuna-p07-episodic-index-snapshot-v2", semantic),
    )


def verify_snapshot(
    snapshot: EpisodicIndexSnapshot,
    turns: Sequence[CompleteTurn],
    *,
    archive_id: str = "synthetic-episodic-archive",
    corrections: Sequence[TurnTimeCorrection] = (),
    temporal_snapshot: TemporalIntervalIndexSnapshot | None = None,
    owner_day_policy: OwnerDayPolicy | None = None,
) -> None:
    rebuilt = build_snapshot(
        turns,
        snapshot.primitives,
        snapshot.capsules,
        archive_id=archive_id,
        corrections=corrections,
        temporal_snapshot=temporal_snapshot,
        owner_day_policy=owner_day_policy,
    )
    if rebuilt.snapshot_digest != snapshot.snapshot_digest:
        raise EpisodicMemoryError("index_stale_or_replayed")


def _primitive_from_payload(payload: Mapping[str, object]) -> TurnPrimitive:
    tuple_fields = {
        "actions_state_changes",
        "actors",
        "ambiguity_codes",
        "decisions_commitments",
        "entities",
        "locations",
        "negations_conditions",
        "numbers",
        "preferences",
        "proposals_assertions",
        "stances",
        "times",
        "unresolved_items",
    }
    expected = tuple_fields | {
        "coverage_state",
        "source_sequence",
        "source_turn_digest",
        "source_turn_id",
    }
    if set(payload) != expected:
        raise EpisodicMemoryError("index_primitive_schema_rejected")
    if any(not isinstance(payload[name], list) for name in tuple_fields):
        raise EpisodicMemoryError("index_primitive_schema_rejected")
    values = {name: tuple(payload[name]) for name in tuple_fields}
    return TurnPrimitive(
        source_sequence=payload["source_sequence"],  # type: ignore[arg-type]
        source_turn_id=payload["source_turn_id"],  # type: ignore[arg-type]
        source_turn_digest=payload["source_turn_digest"],  # type: ignore[arg-type]
        coverage_state=payload["coverage_state"],  # type: ignore[arg-type]
        **values,
    )


def _capsule_from_payload(payload: Mapping[str, object]) -> EpisodicCapsule:
    if set(payload) != {
        "ambiguity_codes",
        "capsule_id",
        "capsule_kind",
        "coverage_state",
        "label",
        "primitive_digests",
        "source_end",
        "source_start",
        "source_terminal_digest",
    }:
        raise EpisodicMemoryError("index_capsule_schema_rejected")
    return EpisodicCapsule(
        capsule_id=payload["capsule_id"],  # type: ignore[arg-type]
        capsule_kind=payload["capsule_kind"],  # type: ignore[arg-type]
        source_start=payload["source_start"],  # type: ignore[arg-type]
        source_end=payload["source_end"],  # type: ignore[arg-type]
        source_terminal_digest=payload["source_terminal_digest"],  # type: ignore[arg-type]
        primitive_digests=tuple(payload["primitive_digests"]),  # type: ignore[arg-type]
        label=payload["label"],  # type: ignore[arg-type]
        coverage_state=payload["coverage_state"],  # type: ignore[arg-type]
        ambiguity_codes=tuple(payload["ambiguity_codes"]),  # type: ignore[arg-type]
    )


def _source_reference_from_payload(
    payload: Mapping[str, object],
) -> EpisodicSourceReference:
    tuple_fields = {
        "correction_digests",
        "temporal_conflict_keys",
        "temporal_episode_digests",
        "temporal_interval_ids",
        "temporal_revision_digests",
        "temporal_revision_numbers",
    }
    expected = tuple_fields | {
        "archive_head_digest",
        "archive_id",
        "archive_turn_count",
        "calendar_zone",
        "delivery_ack_digest",
        "effective_delivered_at_utc",
        "effective_time_binding_digest",
        "epoch_id",
        "local_calendar_representation",
        "model_history_eligible",
        "original_time_binding_digest",
        "owner_day",
        "owner_day_policy_digest",
        "previous_turn_digest",
        "release_set_id",
        "request_digest",
        "response_digest",
        "schema",
        "sequence",
        "source_reference_digest",
        "time_status",
        "turn_digest",
        "turn_id",
    }
    if set(payload) != expected or any(
        not isinstance(payload[name], list) for name in tuple_fields
    ):
        raise EpisodicMemoryError("index_source_reference_payload_rejected")
    return EpisodicSourceReference(
        archive_id=payload["archive_id"],  # type: ignore[arg-type]
        archive_turn_count=payload["archive_turn_count"],  # type: ignore[arg-type]
        archive_head_digest=payload["archive_head_digest"],  # type: ignore[arg-type]
        sequence=payload["sequence"],  # type: ignore[arg-type]
        turn_id=payload["turn_id"],  # type: ignore[arg-type]
        turn_digest=payload["turn_digest"],  # type: ignore[arg-type]
        previous_turn_digest=payload["previous_turn_digest"],  # type: ignore[arg-type]
        epoch_id=payload["epoch_id"],  # type: ignore[arg-type]
        release_set_id=payload["release_set_id"],  # type: ignore[arg-type]
        request_digest=payload["request_digest"],  # type: ignore[arg-type]
        response_digest=payload["response_digest"],  # type: ignore[arg-type]
        delivery_ack_digest=payload["delivery_ack_digest"],  # type: ignore[arg-type]
        model_history_eligible=payload["model_history_eligible"],  # type: ignore[arg-type]
        original_time_binding_digest=payload[  # type: ignore[arg-type]
            "original_time_binding_digest"
        ],
        effective_time_binding_digest=payload[  # type: ignore[arg-type]
            "effective_time_binding_digest"
        ],
        effective_delivered_at_utc=payload[  # type: ignore[arg-type]
            "effective_delivered_at_utc"
        ],
        time_status=payload["time_status"],  # type: ignore[arg-type]
        calendar_zone=payload["calendar_zone"],  # type: ignore[arg-type]
        local_calendar_representation=payload[  # type: ignore[arg-type]
            "local_calendar_representation"
        ],
        owner_day=payload["owner_day"],  # type: ignore[arg-type]
        owner_day_policy_digest=payload[  # type: ignore[arg-type]
            "owner_day_policy_digest"
        ],
        correction_digests=tuple(payload["correction_digests"]),  # type: ignore[arg-type]
        temporal_interval_ids=tuple(payload["temporal_interval_ids"]),  # type: ignore[arg-type]
        temporal_revision_numbers=tuple(  # type: ignore[arg-type]
            payload["temporal_revision_numbers"]
        ),
        temporal_revision_digests=tuple(  # type: ignore[arg-type]
            payload["temporal_revision_digests"]
        ),
        temporal_episode_digests=tuple(  # type: ignore[arg-type]
            payload["temporal_episode_digests"]
        ),
        temporal_conflict_keys=tuple(payload["temporal_conflict_keys"]),  # type: ignore[arg-type]
        source_reference_digest=payload["source_reference_digest"],  # type: ignore[arg-type]
        schema=payload["schema"],  # type: ignore[arg-type]
    )


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise EpisodicMemoryError("index_short_write", retryable=True)
        view = view[written:]


def _verify_existing_snapshot_target(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    status = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(status.st_mode)
        or status.st_nlink != 1
        or stat.S_IMODE(status.st_mode) != 0o600
    ):
        raise EpisodicMemoryError("index_type_rejected")


def _replace_verified_snapshot(
    temporary: Path,
    path: Path,
    expected: EpisodicIndexSnapshot,
) -> None:
    if read_snapshot(temporary) != expected:
        raise EpisodicMemoryError("index_write_readback_mismatch")
    _verify_existing_snapshot_target(path)
    os.replace(temporary, path)
    parent_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)
    if read_snapshot(path) != expected:
        raise EpisodicMemoryError("index_replace_readback_mismatch")


def write_snapshot(
    path: Path,
    snapshot: EpisodicIndexSnapshot,
    *,
    crash_before_replace: bool = False,
) -> None:
    payload = snapshot.semantic_payload() | {"snapshot_digest": snapshot.snapshot_digest}
    raw = canonical_bytes(payload) + b"\n"
    temporary = path.with_name(path.name + ".next")
    _verify_existing_snapshot_target(path)
    if temporary.exists() or temporary.is_symlink():
        raise EpisodicMemoryError("index_path_rejected")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            _write_all(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if crash_before_replace:
            raise EpisodicMemoryError("index_crash_before_replace", retryable=True)
        _replace_verified_snapshot(temporary, path, snapshot)
    except EpisodicMemoryError:
        raise
    except OSError as exc:
        raise EpisodicMemoryError("index_write_unavailable", retryable=True) from exc


def recover_or_write_snapshot(
    path: Path,
    turns: tuple[CompleteTurn, ...],
    *,
    archive_id: str = "synthetic-episodic-archive",
    corrections: tuple[TurnTimeCorrection, ...] = (),
    temporal_snapshot: TemporalIntervalIndexSnapshot | None = None,
    owner_day_policy: OwnerDayPolicy | None = None,
    explicit_rebuild: bool = False,
) -> bool:
    """Verify and promote one crash sidecar, or build a fresh derivative index.

    Raw turns are the authority. A sidecar is promoted only after its complete
    source pointers and archive terminal digest verify against those raw turns.
    """

    temporary = path.with_name(path.name + ".next")
    if temporary.exists() or temporary.is_symlink():
        candidate = read_snapshot(temporary)
        verify_snapshot(
            candidate,
            turns,
            archive_id=archive_id,
            corrections=corrections,
            temporal_snapshot=temporal_snapshot,
            owner_day_policy=owner_day_policy,
        )
        _replace_verified_snapshot(temporary, path, candidate)
        return True
    if path.exists() or path.is_symlink():
        _verify_existing_snapshot_target(path)
        try:
            current = read_snapshot(path)
        except EpisodicMemoryError:
            if not explicit_rebuild:
                raise
            write_snapshot(
                path,
                derive_snapshot(
                    turns,
                    archive_id=archive_id,
                    corrections=corrections,
                    temporal_snapshot=temporal_snapshot,
                    owner_day_policy=owner_day_policy,
                ),
            )
            return True
        if current.archive_turn_count > len(turns):
            raise EpisodicMemoryError("index_ahead_of_archive")
        if current.archive_turn_count == len(turns):
            try:
                verify_snapshot(
                    current,
                    turns,
                    archive_id=archive_id,
                    corrections=corrections,
                    temporal_snapshot=temporal_snapshot,
                    owner_day_policy=owner_day_policy,
                )
                return False
            except EpisodicMemoryError:
                if not explicit_rebuild:
                    raise
                write_snapshot(
                    path,
                    derive_snapshot(
                        turns,
                        archive_id=archive_id,
                        corrections=corrections,
                        temporal_snapshot=temporal_snapshot,
                        owner_day_policy=owner_day_policy,
                    ),
                )
                return True
        _verify_raw_source_references(
            current,
            turns[: current.archive_turn_count],
            archive_id=archive_id,
        )
        write_snapshot(
            path,
            derive_snapshot(
                turns,
                archive_id=archive_id,
                corrections=corrections,
                temporal_snapshot=temporal_snapshot,
                owner_day_policy=owner_day_policy,
            ),
        )
        return False
    write_snapshot(
        path,
        derive_snapshot(
            turns,
            archive_id=archive_id,
            corrections=corrections,
            temporal_snapshot=temporal_snapshot,
            owner_day_policy=owner_day_policy,
        ),
    )
    return False


def _verify_raw_source_references(
    snapshot: EpisodicIndexSnapshot,
    turns: Sequence[CompleteTurn],
    *,
    archive_id: str,
) -> None:
    if snapshot.archive_id != archive_id or len(turns) != snapshot.archive_turn_count:
        raise EpisodicMemoryError("index_raw_source_conflict")
    for reference, turn in zip(snapshot.source_references, turns, strict=True):
        if (
            reference.sequence != turn.draft.sequence
            or reference.turn_id != turn.draft.turn_id
            or reference.turn_digest != turn.turn_digest
            or reference.previous_turn_digest != turn.draft.previous_turn_digest
            or reference.release_set_id != turn.draft.release_set_id
            or reference.request_digest != turn.draft.request_digest
            or reference.response_digest != turn.draft.response_digest
            or reference.delivery_ack_digest != turn.draft.delivery_ack_digest
        ):
            raise EpisodicMemoryError("index_raw_source_conflict")


def read_snapshot(path: Path) -> EpisodicIndexSnapshot:
    try:
        status = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(status.st_mode)
            or status.st_nlink != 1
            or stat.S_IMODE(status.st_mode) != 0o600
        ):
            raise EpisodicMemoryError("index_type_rejected")
        payload = json.loads(path.read_text("utf-8"))
        if not isinstance(payload, Mapping) or set(payload) != {
            "archive_head_digest",
            "archive_id",
            "archive_turn_count",
            "capsules",
            "correction_digests",
            "primitives",
            "schema",
            "source_closure_digest",
            "source_references",
            "snapshot_digest",
            "temporal_snapshot_digest",
        }:
            raise EpisodicMemoryError("index_document_rejected")
        if (
            not isinstance(payload["correction_digests"], list)
            or not isinstance(payload["source_references"], list)
        ):
            raise EpisodicMemoryError("index_document_rejected")
        primitives = tuple(_primitive_from_payload(item) for item in payload["primitives"])
        capsules = tuple(_capsule_from_payload(item) for item in payload["capsules"])
        return EpisodicIndexSnapshot(
            archive_id=payload["archive_id"],  # type: ignore[arg-type]
            archive_turn_count=payload["archive_turn_count"],
            archive_head_digest=payload["archive_head_digest"],
            source_references=tuple(
                _source_reference_from_payload(item)
                for item in payload["source_references"]
            ),
            correction_digests=tuple(payload["correction_digests"]),  # type: ignore[arg-type]
            temporal_snapshot_digest=payload["temporal_snapshot_digest"],  # type: ignore[arg-type]
            source_closure_digest=payload["source_closure_digest"],  # type: ignore[arg-type]
            primitives=primitives,
            capsules=capsules,
            snapshot_digest=payload["snapshot_digest"],
            schema=payload["schema"],
        )
    except EpisodicMemoryError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise EpisodicMemoryError("index_document_rejected") from exc
