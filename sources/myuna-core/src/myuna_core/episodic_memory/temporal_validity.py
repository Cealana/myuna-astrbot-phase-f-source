from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from typing import Callable, Mapping, Sequence

from myuna_core.active_temporal_context.protocol import ActiveSnapshotReceipt

from .contracts import (
    EpisodicMemoryError,
    SUPPORTED_CALENDAR_ZONES,
    require_digest,
    require_id,
    require_text,
    require_utc,
    semantic_digest,
    TurnTimeBinding,
)


TEMPORAL_VALIDITY_SEAM_SCHEMA = "myuna.p07-p08-temporal-validity-seam.v1"
TEMPORAL_INTERVAL_EPISODE_SCHEMA = "myuna.temporal-interval-episode.v1"
TEMPORAL_STATES = frozenset(
    {"planned", "observed", "confirmed_started", "changed", "ended", "cancelled"}
)
TEMPORAL_RESIDENT_STATES = frozenset(
    {"available", "available_empty", "unavailable", "conflict"}
)
P08_EVENT_KINDS = frozenset(
    {
        "activate",
        "confirm",
        "create",
        "expire",
        "refresh",
        "restore",
        "revoke",
        "supersede",
    }
)
_RESIDENT_REVISION_STATES = frozenset(
    {"planned", "observed", "confirmed_started", "changed"}
)


@dataclass(frozen=True, slots=True)
class TemporalEndpoint:
    kind: str
    calendar_zone: str
    trusted_time_binding_digest: str
    uncertainty_microseconds: int
    instant_utc: datetime | None = None
    bounded_start_utc: datetime | None = None
    bounded_end_utc: datetime | None = None

    def __post_init__(self) -> None:
        if self.kind not in {"exact", "bounded", "unknown", "open"}:
            raise EpisodicMemoryError("temporal_endpoint_kind_unknown")
        if self.calendar_zone not in SUPPORTED_CALENDAR_ZONES:
            raise EpisodicMemoryError("temporal_calendar_zone_unsupported")
        require_digest(self.trusted_time_binding_digest, "temporal_time_binding_digest")
        if (
            isinstance(self.uncertainty_microseconds, bool)
            or not isinstance(self.uncertainty_microseconds, int)
            or self.uncertainty_microseconds < 0
        ):
            raise EpisodicMemoryError("temporal_uncertainty_invalid")
        if self.kind == "exact":
            if self.instant_utc is None or any(
                value is not None for value in (self.bounded_start_utc, self.bounded_end_utc)
            ):
                raise EpisodicMemoryError("temporal_exact_endpoint_invalid")
            object.__setattr__(
                self,
                "instant_utc",
                require_utc(self.instant_utc, "temporal_instant"),
            )
        elif self.kind == "bounded":
            if (
                self.instant_utc is not None
                or self.bounded_start_utc is None
                or self.bounded_end_utc is None
            ):
                raise EpisodicMemoryError("temporal_bounded_endpoint_invalid")
            start = require_utc(self.bounded_start_utc, "temporal_bound_start")
            end = require_utc(self.bounded_end_utc, "temporal_bound_end")
            if start >= end:
                raise EpisodicMemoryError("temporal_bounded_endpoint_invalid")
            object.__setattr__(self, "bounded_start_utc", start)
            object.__setattr__(self, "bounded_end_utc", end)
        elif any(
            value is not None
            for value in (self.instant_utc, self.bounded_start_utc, self.bounded_end_utc)
        ):
            raise EpisodicMemoryError("temporal_nonexact_endpoint_claimed_time")

    def payload(self) -> dict[str, object]:
        def timestamp(value: datetime | None) -> str | None:
            return None if value is None else value.isoformat(timespec="microseconds")

        return {
            "bounded_end_utc": timestamp(self.bounded_end_utc),
            "bounded_start_utc": timestamp(self.bounded_start_utc),
            "calendar_zone": self.calendar_zone,
            "instant_utc": timestamp(self.instant_utc),
            "kind": self.kind,
            "trusted_time_binding_digest": self.trusted_time_binding_digest,
            "uncertainty_microseconds": self.uncertainty_microseconds,
        }

    @classmethod
    def from_payload(cls, payload: object) -> TemporalEndpoint:
        expected = {
            "bounded_end_utc",
            "bounded_start_utc",
            "calendar_zone",
            "instant_utc",
            "kind",
            "trusted_time_binding_digest",
            "uncertainty_microseconds",
        }
        if not isinstance(payload, Mapping) or set(payload) != expected:
            raise EpisodicMemoryError("temporal_endpoint_payload_rejected")

        def parsed(value: object) -> datetime | None:
            if value is None:
                return None
            if not isinstance(value, str):
                raise EpisodicMemoryError("temporal_endpoint_payload_rejected")
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                raise EpisodicMemoryError(
                    "temporal_endpoint_payload_rejected"
                ) from None

        return cls(
            kind=payload["kind"],  # type: ignore[arg-type]
            calendar_zone=payload["calendar_zone"],  # type: ignore[arg-type]
            trusted_time_binding_digest=payload[
                "trusted_time_binding_digest"
            ],  # type: ignore[arg-type]
            uncertainty_microseconds=payload[
                "uncertainty_microseconds"
            ],  # type: ignore[arg-type]
            instant_utc=parsed(payload["instant_utc"]),
            bounded_start_utc=parsed(payload["bounded_start_utc"]),
            bounded_end_utc=parsed(payload["bounded_end_utc"]),
        )


@dataclass(frozen=True, slots=True)
class TemporalIntervalRevision:
    interval_id: str
    revision: int
    state: str
    statement: str
    conflict_key: str
    start: TemporalEndpoint
    end: TemporalEndpoint
    source_turn_sequences: tuple[int, ...]
    source_turn_digests: tuple[str, ...]
    p08_revision: int
    p08_event_sequence: int
    p08_event_kind: str
    previous_revision_digest: str

    def __post_init__(self) -> None:
        require_id(self.interval_id, "temporal_interval_id")
        if (
            isinstance(self.revision, bool)
            or not isinstance(self.revision, int)
            or self.revision < 1
        ):
            raise EpisodicMemoryError("temporal_revision_invalid")
        if self.state not in TEMPORAL_STATES:
            raise EpisodicMemoryError("temporal_state_unknown")
        require_text(self.statement, "temporal_statement", 4_000)
        if self.state == "planned" and any(
            marker in self.statement.casefold()
            for marker in (" was ", "正在", "已经", "已在", "confirmed started")
        ):
            raise EpisodicMemoryError("temporal_plan_claims_started")
        require_id(self.conflict_key, "temporal_conflict_key")
        if self.start.calendar_zone != self.end.calendar_zone:
            raise EpisodicMemoryError("temporal_interval_zone_mismatch")
        if (
            len(self.source_turn_sequences) != len(self.source_turn_digests)
            or not self.source_turn_sequences
        ):
            raise EpisodicMemoryError("temporal_source_pointer_incomplete")
        previous_sequence = 0
        for sequence, digest in zip(
            self.source_turn_sequences,
            self.source_turn_digests,
            strict=True,
        ):
            if (
                isinstance(sequence, bool)
                or not isinstance(sequence, int)
                or sequence <= previous_sequence
            ):
                raise EpisodicMemoryError("temporal_source_sequence_invalid")
            require_digest(digest, "temporal_source_turn_digest")
            previous_sequence = sequence
        if (
            isinstance(self.p08_revision, bool)
            or not isinstance(self.p08_revision, int)
            or self.p08_revision < 1
        ):
            raise EpisodicMemoryError("p08_revision_invalid")
        if (
            isinstance(self.p08_event_sequence, bool)
            or not isinstance(self.p08_event_sequence, int)
            or self.p08_event_sequence < 1
        ):
            raise EpisodicMemoryError("p08_event_sequence_invalid")
        if (
            type(self.p08_event_kind) is not str
            or self.p08_event_kind not in P08_EVENT_KINDS
        ):
            raise EpisodicMemoryError("p08_event_kind_invalid")
        if (
            self.state in {"ended", "cancelled"}
            and (self.state, self.p08_event_kind)
            not in {("ended", "expire"), ("cancelled", "revoke")}
        ):
            raise EpisodicMemoryError("p08_terminal_event_kind_mismatch")
        require_digest(self.previous_revision_digest, "temporal_previous_revision_digest")
        if self.revision == 1 and self.previous_revision_digest != "0" * 64:
            raise EpisodicMemoryError("temporal_revision_parent_invalid")
        if self.state in {"ended", "cancelled"} and self.end.kind == "open":
            raise EpisodicMemoryError("temporal_closed_state_has_open_end")

    def payload(self) -> dict[str, object]:
        return {
            "conflict_key": self.conflict_key,
            "end": self.end.payload(),
            "interval_id": self.interval_id,
            "p08_event_kind": self.p08_event_kind,
            "p08_event_sequence": self.p08_event_sequence,
            "p08_revision": self.p08_revision,
            "previous_revision_digest": self.previous_revision_digest,
            "revision": self.revision,
            "source_turn_digests": list(self.source_turn_digests),
            "source_turn_sequences": list(self.source_turn_sequences),
            "start": self.start.payload(),
            "state": self.state,
            "statement": self.statement,
        }

    @classmethod
    def from_payload(cls, payload: object) -> TemporalIntervalRevision:
        expected = {
            "conflict_key",
            "end",
            "interval_id",
            "p08_event_kind",
            "p08_event_sequence",
            "p08_revision",
            "previous_revision_digest",
            "revision",
            "source_turn_digests",
            "source_turn_sequences",
            "start",
            "state",
            "statement",
        }
        if (
            not isinstance(payload, Mapping)
            or set(payload) != expected
            or not isinstance(payload["source_turn_digests"], list)
            or not isinstance(payload["source_turn_sequences"], list)
        ):
            raise EpisodicMemoryError("temporal_revision_payload_rejected")
        return cls(
            interval_id=payload["interval_id"],  # type: ignore[arg-type]
            revision=payload["revision"],  # type: ignore[arg-type]
            state=payload["state"],  # type: ignore[arg-type]
            statement=payload["statement"],  # type: ignore[arg-type]
            conflict_key=payload["conflict_key"],  # type: ignore[arg-type]
            start=TemporalEndpoint.from_payload(payload["start"]),
            end=TemporalEndpoint.from_payload(payload["end"]),
            source_turn_sequences=tuple(payload["source_turn_sequences"]),  # type: ignore[arg-type]
            source_turn_digests=tuple(payload["source_turn_digests"]),  # type: ignore[arg-type]
            p08_revision=payload["p08_revision"],  # type: ignore[arg-type]
            p08_event_sequence=payload["p08_event_sequence"],  # type: ignore[arg-type]
            p08_event_kind=payload["p08_event_kind"],  # type: ignore[arg-type]
            previous_revision_digest=payload[
                "previous_revision_digest"
            ],  # type: ignore[arg-type]
        )

    @property
    def revision_digest(self) -> str:
        return semantic_digest("myuna-p07-temporal-interval-revision-v2", self.payload())


@dataclass(frozen=True, slots=True)
class TemporalIntervalEpisode:
    interval_id: str
    revisions: tuple[TemporalIntervalRevision, ...]
    terminal_state: str
    episode_digest: str
    schema: str = TEMPORAL_INTERVAL_EPISODE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != TEMPORAL_INTERVAL_EPISODE_SCHEMA or not self.revisions:
            raise EpisodicMemoryError("temporal_episode_schema_rejected")
        previous = "0" * 64
        for number, revision in enumerate(self.revisions, start=1):
            if (
                revision.interval_id != self.interval_id
                or revision.revision != number
                or revision.previous_revision_digest != previous
            ):
                raise EpisodicMemoryError("temporal_episode_revision_chain_drifted")
            previous = revision.revision_digest
        if self.terminal_state != self.revisions[-1].state:
            raise EpisodicMemoryError("temporal_episode_terminal_state_mismatch")
        semantic = {
            "interval_id": self.interval_id,
            "revision_digests": [item.revision_digest for item in self.revisions],
            "schema": self.schema,
            "terminal_state": self.terminal_state,
        }
        if self.episode_digest != semantic_digest(
            "myuna-p07-temporal-interval-episode-v1",
            semantic,
        ):
            raise EpisodicMemoryError("temporal_episode_digest_mismatch")

    @classmethod
    def create(cls, revisions: Sequence[TemporalIntervalRevision]) -> TemporalIntervalEpisode:
        selected = tuple(revisions)
        if not selected:
            raise EpisodicMemoryError("temporal_episode_empty")
        semantic = {
            "interval_id": selected[0].interval_id,
            "revision_digests": [item.revision_digest for item in selected],
            "schema": TEMPORAL_INTERVAL_EPISODE_SCHEMA,
            "terminal_state": selected[-1].state,
        }
        return cls(
            interval_id=selected[0].interval_id,
            revisions=selected,
            terminal_state=selected[-1].state,
            episode_digest=semantic_digest("myuna-p07-temporal-interval-episode-v1", semantic),
        )

    def payload(self) -> dict[str, object]:
        return {
            "episode_digest": self.episode_digest,
            "interval_id": self.interval_id,
            "revisions": [item.payload() for item in self.revisions],
            "schema": self.schema,
            "terminal_state": self.terminal_state,
        }

    @classmethod
    def from_payload(cls, payload: object) -> TemporalIntervalEpisode:
        expected = {
            "episode_digest",
            "interval_id",
            "revisions",
            "schema",
            "terminal_state",
        }
        if (
            not isinstance(payload, Mapping)
            or set(payload) != expected
            or not isinstance(payload["revisions"], list)
        ):
            raise EpisodicMemoryError("temporal_episode_payload_rejected")
        return cls(
            interval_id=payload["interval_id"],  # type: ignore[arg-type]
            revisions=tuple(
                TemporalIntervalRevision.from_payload(item)
                for item in payload["revisions"]
            ),
            terminal_state=payload["terminal_state"],  # type: ignore[arg-type]
            episode_digest=payload["episode_digest"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )

    @property
    def raw_hydration_required(self) -> bool:
        return True


@dataclass(frozen=True, slots=True)
class TemporalProjectionOccupancy:
    item_count: int
    character_count: int
    serialized_bytes: int
    token_count: int
    character_headroom: int
    byte_headroom: int
    token_headroom: int
    fit: bool
    limiting_oracle: str | None

    def audit_projection(self) -> dict[str, object]:
        return {
            "byte_headroom": self.byte_headroom,
            "character_count": self.character_count,
            "character_headroom": self.character_headroom,
            "fit": self.fit,
            "item_count": self.item_count,
            "limiting_oracle": self.limiting_oracle,
            "serialized_bytes": self.serialized_bytes,
            "token_count": self.token_count,
            "token_headroom": self.token_headroom,
        }


@dataclass(frozen=True, slots=True)
class TemporalValidityProjection:
    state: str
    reason_category: str | None
    fragments: tuple[str, ...]
    revision_digests: tuple[str, ...]
    source_closure_digest: str
    selection_digest: str
    occupancy: TemporalProjectionOccupancy
    projection_digest: str

    def __post_init__(self) -> None:
        if self.state not in TEMPORAL_RESIDENT_STATES:
            raise EpisodicMemoryError("temporal_resident_state_unknown")
        for value, label in (
            (self.source_closure_digest, "temporal_resident_source_closure"),
            (self.selection_digest, "temporal_resident_selection"),
            (self.projection_digest, "temporal_resident_projection"),
        ):
            require_digest(value, label)
        if self.state in {"available", "available_empty"}:
            if self.reason_category is not None or not self.occupancy.fit:
                raise EpisodicMemoryError("temporal_resident_available_invalid")
        else:
            if self.reason_category is None or self.fragments:
                raise EpisodicMemoryError("temporal_resident_failure_invalid")
            require_id(self.reason_category, "temporal_resident_reason")
        if self.state == "available":
            if not self.fragments or len(self.fragments) != len(self.revision_digests):
                raise EpisodicMemoryError("temporal_resident_available_empty")
        elif self.state == "available_empty" and (
            self.fragments or self.revision_digests or self.occupancy.item_count != 0
        ):
            raise EpisodicMemoryError("temporal_resident_empty_contains_items")

    def content_free_projection(self) -> dict[str, object]:
        return {
            "item_count": self.occupancy.item_count,
            "occupancy": self.occupancy.audit_projection(),
            "projection_digest": self.projection_digest,
            "reason_category": self.reason_category,
            "selection_digest": self.selection_digest,
            "source_closure_digest": self.source_closure_digest,
            "state": self.state,
        }


def _projection(
    *,
    state: str,
    reason_category: str | None,
    fragments: tuple[str, ...],
    revision_digests: tuple[str, ...],
    source_closure_digest: str,
    occupancy: TemporalProjectionOccupancy,
) -> TemporalValidityProjection:
    selection_digest = semantic_digest(
        "myuna-p08-resident-temporal-selection-v1",
        {"revision_digests": list(revision_digests)},
    )
    projection_digest = semantic_digest(
        "myuna-p08-resident-temporal-projection-v1",
        {
            "fragments": list(fragments),
            "occupancy": occupancy.audit_projection(),
            "reason_category": reason_category,
            "selection_digest": selection_digest,
            "source_closure_digest": source_closure_digest,
            "state": state,
        },
    )
    return TemporalValidityProjection(
        state=state,
        reason_category=reason_category,
        fragments=fragments,
        revision_digests=revision_digests,
        source_closure_digest=source_closure_digest,
        selection_digest=selection_digest,
        occupancy=occupancy,
        projection_digest=projection_digest,
    )


def _empty_occupancy(
    *,
    maximum_characters: int,
    maximum_serialized_bytes: int,
    maximum_tokens: int,
    limiting_oracle: str | None = None,
) -> TemporalProjectionOccupancy:
    return TemporalProjectionOccupancy(
        item_count=0,
        character_count=0,
        serialized_bytes=2,
        token_count=0,
        character_headroom=maximum_characters,
        byte_headroom=maximum_serialized_bytes - 2,
        token_headroom=maximum_tokens,
        fit=limiting_oracle is None,
        limiting_oracle=limiting_oracle,
    )


def content_free_temporal_projection(
    *,
    state: str,
    reason_category: str,
    source_snapshot_digest: str,
    trusted_time_binding_digest: str,
    maximum_characters: int,
    maximum_serialized_bytes: int,
    maximum_tokens: int,
) -> TemporalValidityProjection:
    if state not in {"unavailable", "conflict"}:
        raise EpisodicMemoryError("temporal_resident_failure_state_rejected")
    require_digest(source_snapshot_digest, "temporal_resident_source_snapshot")
    require_digest(trusted_time_binding_digest, "temporal_resident_time_binding")
    require_id(reason_category, "temporal_resident_reason")
    source_closure_digest = semantic_digest(
        "myuna-p08-resident-temporal-source-closure-v1",
        {
            "source_snapshot_digest": source_snapshot_digest,
            "trusted_time_binding_digest": trusted_time_binding_digest,
        },
    )
    return _projection(
        state=state,
        reason_category=reason_category,
        fragments=(),
        revision_digests=(),
        source_closure_digest=source_closure_digest,
        occupancy=_empty_occupancy(
            maximum_characters=maximum_characters,
            maximum_serialized_bytes=maximum_serialized_bytes,
            maximum_tokens=maximum_tokens,
        ),
    )


def project_all_active_temporal_items(
    items: Sequence[TemporalIntervalRevision],
    *,
    maximum_characters: int,
    maximum_serialized_bytes: int,
    maximum_tokens: int,
    token_counter: Callable[[tuple[str, ...]], int] | None,
) -> TemporalValidityProjection:
    active_states = {"planned", "observed", "confirmed_started", "changed"}
    selected = tuple(item for item in items if item.state in active_states)
    if len(selected) != len(items):
        raise EpisodicMemoryError("temporal_projection_nonactive_item")
    conflicts: dict[str, str] = {}
    for item in selected:
        prior = conflicts.get(item.conflict_key)
        if prior is not None and prior != item.revision_digest:
            raise EpisodicMemoryError("temporal_active_source_conflict")
        conflicts[item.conflict_key] = item.revision_digest
    ordered = tuple(sorted(selected, key=lambda item: (item.conflict_key, item.interval_id)))
    fragments = tuple(
        "[temporal_validity "
        f"state={item.state} interval={item.interval_id} revision={item.revision} "
        f"zone={item.start.calendar_zone}]\n{item.statement}"
        for item in ordered
    )
    characters = sum(len(item) for item in fragments)
    serialized = len(
        json.dumps(fragments, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )
    if token_counter is None:
        raise EpisodicMemoryError("temporal_token_oracle_unavailable")
    try:
        tokens = token_counter(fragments)
    except Exception:
        raise EpisodicMemoryError("temporal_token_oracle_unavailable") from None
    headrooms = {
        "characters": maximum_characters - characters,
        "serialized_bytes": maximum_serialized_bytes - serialized,
        "tokens": maximum_tokens - tokens,
    }
    fit = all(value >= 0 for value in headrooms.values())
    limiting = None if fit else min(headrooms, key=headrooms.__getitem__)
    occupancy = TemporalProjectionOccupancy(
        item_count=len(ordered),
        character_count=characters,
        serialized_bytes=serialized,
        token_count=tokens,
        character_headroom=headrooms["characters"],
        byte_headroom=headrooms["serialized_bytes"],
        token_headroom=headrooms["tokens"],
        fit=fit,
        limiting_oracle=limiting,
    )
    revision_digests = tuple(item.revision_digest for item in ordered)
    source_closure_digest = semantic_digest(
        "myuna-p07-p08-temporal-validity-source-v1",
        {
            "revision_digests": list(revision_digests),
            "schema": TEMPORAL_VALIDITY_SEAM_SCHEMA,
        },
    )
    return _projection(
        state=(
            "unavailable"
            if not fit
            else "available"
            if ordered
            else "available_empty"
        ),
        reason_category=None if fit else "capacity_exceeded",
        fragments=fragments if fit else (),
        revision_digests=revision_digests,
        source_closure_digest=source_closure_digest,
        occupancy=occupancy,
    )


def project_resident_temporal_items(
    episodes: Sequence[TemporalIntervalEpisode],
    *,
    source_snapshot_digest: str,
    source_complete: bool,
    trusted_time_binding: TurnTimeBinding,
    active_snapshot_receipt: ActiveSnapshotReceipt,
    maximum_characters: int,
    maximum_serialized_bytes: int,
    maximum_tokens: int,
    token_counter: Callable[[tuple[str, ...]], int] | None,
) -> TemporalValidityProjection:
    """Project only currently valid, source-verified P08 interval revisions.

    This function is pure.  It never repairs the derivative, samples a clock, or
    calls the P08 store.  The caller supplies one already-verified interval
    snapshot and the exact prompt-time binding derived from the same accepted
    P08 snapshot operation.
    """

    require_digest(source_snapshot_digest, "temporal_resident_source_snapshot")
    if not isinstance(source_complete, bool):
        raise EpisodicMemoryError("temporal_resident_source_state_invalid")
    if not isinstance(trusted_time_binding, TurnTimeBinding):
        raise EpisodicMemoryError("temporal_resident_time_binding_invalid")
    if not source_complete:
        return content_free_temporal_projection(
            state="unavailable",
            reason_category="source_incomplete",
            source_snapshot_digest=source_snapshot_digest,
            trusted_time_binding_digest=trusted_time_binding.binding_digest,
            maximum_characters=maximum_characters,
            maximum_serialized_bytes=maximum_serialized_bytes,
            maximum_tokens=maximum_tokens,
        )
    trusted_payload = (
        None
        if trusted_time_binding.status != "exact"
        or trusted_time_binding.sample_instant_utc is None
        else {
            "authority": trusted_time_binding.authority,
            "boot_id": trusted_time_binding.boot_id,
            "instant": trusted_time_binding.sample_instant_utc.isoformat(
                timespec="microseconds"
            ),
            "monotonic_ns": trusted_time_binding.sample_monotonic_ns,
            "sequence": trusted_time_binding.sequence,
            "source": trusted_time_binding.source,
            "source_class": trusted_time_binding.source_class,
            "synchronized": trusted_time_binding.synchronized,
            "uncertainty_microseconds": (
                trusted_time_binding.uncertainty_microseconds
            ),
        }
    )
    if not isinstance(active_snapshot_receipt, ActiveSnapshotReceipt) or not (
        active_snapshot_receipt.matches_trusted_time_payload(trusted_payload)
    ):
        return content_free_temporal_projection(
            state="conflict",
            reason_category="source_receipt_conflict",
            source_snapshot_digest=source_snapshot_digest,
            trusted_time_binding_digest=trusted_time_binding.binding_digest,
            maximum_characters=maximum_characters,
            maximum_serialized_bytes=maximum_serialized_bytes,
            maximum_tokens=maximum_tokens,
        )
    current = trusted_time_binding.sample_instant_utc
    if trusted_time_binding.status != "exact" or current is None:
        return content_free_temporal_projection(
            state="unavailable",
            reason_category="trusted_time_unavailable",
            source_snapshot_digest=source_snapshot_digest,
            trusted_time_binding_digest=trusted_time_binding.binding_digest,
            maximum_characters=maximum_characters,
            maximum_serialized_bytes=maximum_serialized_bytes,
            maximum_tokens=maximum_tokens,
        )
    selected: list[TemporalIntervalRevision] = []
    seen_intervals: set[str] = set()
    for episode in episodes:
        if not isinstance(episode, TemporalIntervalEpisode):
            return content_free_temporal_projection(
                state="conflict",
                reason_category="source_type_conflict",
                source_snapshot_digest=source_snapshot_digest,
                trusted_time_binding_digest=trusted_time_binding.binding_digest,
                maximum_characters=maximum_characters,
                maximum_serialized_bytes=maximum_serialized_bytes,
                maximum_tokens=maximum_tokens,
            )
        if episode.interval_id in seen_intervals:
            return content_free_temporal_projection(
                state="conflict",
                reason_category="source_identity_conflict",
                source_snapshot_digest=source_snapshot_digest,
                trusted_time_binding_digest=trusted_time_binding.binding_digest,
                maximum_characters=maximum_characters,
                maximum_serialized_bytes=maximum_serialized_bytes,
                maximum_tokens=maximum_tokens,
            )
        seen_intervals.add(episode.interval_id)
        revision = episode.revisions[-1]
        if revision.state in {"ended", "cancelled"}:
            continue
        if revision.state not in _RESIDENT_REVISION_STATES:
            return content_free_temporal_projection(
                state="conflict",
                reason_category="source_state_conflict",
                source_snapshot_digest=source_snapshot_digest,
                trusted_time_binding_digest=trusted_time_binding.binding_digest,
                maximum_characters=maximum_characters,
                maximum_serialized_bytes=maximum_serialized_bytes,
                maximum_tokens=maximum_tokens,
            )
        if (
            revision.start.kind != "exact"
            or revision.start.instant_utc is None
            or revision.end.kind != "exact"
            or revision.end.instant_utc is None
        ):
            return content_free_temporal_projection(
                state="unavailable",
                reason_category="endpoint_ambiguous",
                source_snapshot_digest=source_snapshot_digest,
                trusted_time_binding_digest=trusted_time_binding.binding_digest,
                maximum_characters=maximum_characters,
                maximum_serialized_bytes=maximum_serialized_bytes,
                maximum_tokens=maximum_tokens,
            )
        if revision.start.instant_utc <= current < revision.end.instant_utc:
            selected.append(revision)
    if token_counter is None:
        return content_free_temporal_projection(
            state="unavailable",
            reason_category="token_oracle_unavailable",
            source_snapshot_digest=source_snapshot_digest,
            trusted_time_binding_digest=trusted_time_binding.binding_digest,
            maximum_characters=maximum_characters,
            maximum_serialized_bytes=maximum_serialized_bytes,
            maximum_tokens=maximum_tokens,
        )
    try:
        projected = project_all_active_temporal_items(
            selected,
            maximum_characters=maximum_characters,
            maximum_serialized_bytes=maximum_serialized_bytes,
            maximum_tokens=maximum_tokens,
            token_counter=token_counter,
        )
    except EpisodicMemoryError as exc:
        state = "conflict" if str(exc) == "temporal_active_source_conflict" else "unavailable"
        reason = (
            "source_conflict"
            if state == "conflict"
            else "token_oracle_unavailable"
            if str(exc) == "temporal_token_oracle_unavailable"
            else "projection_unavailable"
        )
        return content_free_temporal_projection(
            state=state,
            reason_category=reason,
            source_snapshot_digest=source_snapshot_digest,
            trusted_time_binding_digest=trusted_time_binding.binding_digest,
            maximum_characters=maximum_characters,
            maximum_serialized_bytes=maximum_serialized_bytes,
            maximum_tokens=maximum_tokens,
        )
    source_closure_digest = semantic_digest(
        "myuna-p08-resident-temporal-source-closure-v1",
        {
            "active_snapshot_receipt_digest": (
                active_snapshot_receipt.receipt_digest
            ),
            "source_snapshot_digest": source_snapshot_digest,
            "trusted_time_binding_digest": trusted_time_binding.binding_digest,
        },
    )
    return _projection(
        state=projected.state,
        reason_category=projected.reason_category,
        fragments=projected.fragments,
        revision_digests=projected.revision_digests,
        source_closure_digest=source_closure_digest,
        occupancy=projected.occupancy,
    )


def recall_interval_episodes(
    query: str,
    episodes: Sequence[TemporalIntervalEpisode],
) -> tuple[TemporalIntervalEpisode, ...]:
    require_text(query, "temporal_episode_query", 2_000)
    terms = {item.casefold() for item in query.split() if item}
    selected = []
    for episode in episodes:
        searchable = " ".join(item.statement for item in episode.revisions).casefold()
        if any(term in searchable for term in terms):
            selected.append(episode)
    return tuple(sorted(selected, key=lambda item: item.interval_id))


TEMPORAL_VALIDITY_OWNERSHIP: Mapping[str, str] = {
    "active_interval_store_and_expiry": "P08",
    "lossless_raw_episodic_diary": "P07",
    "prompt_orchestration": "P15",
    "trusted_time_provider": "P10-B",
}


def require_exact_time_for_temporal_mutation(binding: TurnTimeBinding) -> None:
    if binding.status != "exact":
        raise EpisodicMemoryError("temporal_mutation_time_unresolved")
