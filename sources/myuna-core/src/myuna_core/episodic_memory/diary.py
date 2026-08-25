from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime
import json
import os
from pathlib import Path
import sqlite3
import stat
from typing import TYPE_CHECKING, Mapping, Sequence
from zoneinfo import ZoneInfo

from .contracts import (
    DEFAULT_CALENDAR_ZONE,
    SUPPORTED_CALENDAR_ZONES,
    CompleteTurn,
    EpisodicMemoryError,
    PrefixCapsule,
    PrefixCompactionPolicy,
    TurnTimeBinding,
    canonical_bytes,
    prefix_capsule_source_closure_digest,
    require_digest,
    require_id,
    require_text,
    require_utc,
    semantic_digest,
)
from .context import verify_prefix_capsule
from myuna_core.owner_profile.contracts import (
    OwnerProfileError,
    ProfileCurrentValue,
    ProfileModuleManifest,
    ProfileStateEvent,
    ProfileStateIntent,
    ProfileStateReceipt,
    profile_state_canonical_bytes,
    profile_v2_manifests,
)
from myuna_core.owner_profile.lifecycle import (
    evaluate_profile_state_transition,
    initial_profile_current,
    rebuild_profile_current,
)

if TYPE_CHECKING:
    from .index import EpisodicIndexSnapshot, EpisodicSourceReference
    from .owner_day_generation import OwnerDayDiaryRevision
    from .temporal_bridge import TemporalIntervalIndexSnapshot


DIARY_SCHEMA = "myuna.owner-private-reflective-diary.v6"
DERIVATIVE_SOURCE_MANIFEST_SCHEMA = "myuna.p07-derivative-source-manifest.v1"
DIARY_STATEMENT_KINDS = frozenset(
    {
        "factual_observation",
        "interpretation_reflection",
        "uncertainty",
        "intention",
    }
)


def _prefix_capsule_from_json(payload_json: object) -> PrefixCapsule:
    if type(payload_json) is not str:
        raise EpisodicMemoryError("prefix_capsule_payload_noncanonical")

    def reject_constant(_value: str) -> None:
        raise ValueError

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if type(key) is not str or key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        payload = json.loads(
            payload_json,
            parse_constant=reject_constant,
            object_pairs_hook=unique_object,
        )
        capsule = PrefixCapsule.from_payload(payload)
        if canonical_bytes(capsule.payload()).decode("utf-8") != payload_json:
            raise ValueError
    except (json.JSONDecodeError, TypeError, UnicodeError, ValueError):
        raise EpisodicMemoryError("prefix_capsule_payload_noncanonical") from None
    return capsule


def _profile_json_payload(payload_json: object) -> dict[str, object]:
    if type(payload_json) is not str:
        raise EpisodicMemoryError("profile_state_payload_noncanonical")

    def reject_constant(_value: str) -> None:
        raise ValueError

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if type(key) is not str or key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        payload = json.loads(
            payload_json,
            parse_constant=reject_constant,
            object_pairs_hook=unique_object,
        )
        if type(payload) is not dict:
            raise ValueError
        if profile_state_canonical_bytes(payload).decode("ascii") != payload_json:
            raise ValueError
    except (json.JSONDecodeError, TypeError, UnicodeError, ValueError):
        raise EpisodicMemoryError("profile_state_payload_noncanonical") from None
    return payload


def _profile_event_from_json(payload_json: object) -> ProfileStateEvent:
    payload = _profile_json_payload(payload_json)
    if set(payload) != {
        "action",
        "applied_delta",
        "current_state",
        "current_value",
        "delivered_source_reference_digest",
        "delivered_at_utc",
        "delivered_turn_id",
        "delivery_ack_digest",
        "episode_revision_id",
        "event_id",
        "field_id",
        "intent_digest",
        "manifest_digest",
        "module_id",
        "p08_source_digest",
        "p08_episode_id",
        "p08_interval_id",
        "p08_source_reference_digest",
        "p08_terminal_event_kind",
        "p08_terminal_event_sequence",
        "p08_terminal_revision",
        "p08_terminal_revision_digest",
        "proposal_change_digest",
        "proposal_expires_at_utc",
        "proposal_id",
        "proposal_manifest_head",
        "proposal_version",
        "proposal_value",
        "previous_event_digest",
        "prior_state",
        "prior_value",
        "raw_source_digest",
        "reason_category",
        "requested_delta",
        "rollback_target_event_digest",
        "rollback_target_event_id",
        "sequence",
        "trusted_time_digest",
    }:
        raise EpisodicMemoryError("profile_state_payload_noncanonical")
    try:
        return ProfileStateEvent(**payload)
    except (OwnerProfileError, TypeError, ValueError) as exc:
        raise EpisodicMemoryError("profile_state_payload_noncanonical") from exc


def _profile_current_from_json(payload_json: object) -> ProfileCurrentValue:
    payload = _profile_json_payload(payload_json)
    if set(payload) != {
        "field_id",
        "last_event_digest",
        "last_event_id",
        "last_sequence",
        "manifest_digest",
        "module_id",
        "projection_digest",
        "scaled_value",
        "state",
    }:
        raise EpisodicMemoryError("profile_state_payload_noncanonical")
    try:
        return ProfileCurrentValue(**payload)
    except (OwnerProfileError, TypeError, ValueError) as exc:
        raise EpisodicMemoryError("profile_state_payload_noncanonical") from exc


DIARY_GENERATION_KINDS = frozenset({"contemporaneous", "correction", "late_backfill"})
SQLITE_APPLICATION_ID = 0x4D594544
SCHEMA_VERSION = 6
MAX_DIARY_STATEMENT_CHARACTERS = 1_000_000
MAX_JOB_ATTEMPTS = 3

_SCHEMA_OBJECTS = {
    "metadata": """CREATE TABLE metadata (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
) STRICT""",
    "diary_entries": """CREATE TABLE diary_entries (
    day_key TEXT NOT NULL,
    calendar_zone TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    entry_digest TEXT NOT NULL UNIQUE,
    source_manifest_digest TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY(day_key, calendar_zone, revision)
) STRICT""",
    "owner_day_revisions": """CREATE TABLE owner_day_revisions (
    owner_day TEXT NOT NULL,
    calendar_zone TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    purpose TEXT NOT NULL,
    revision_digest TEXT NOT NULL UNIQUE,
    source_manifest_digest TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY(owner_day, calendar_zone, revision)
) STRICT""",
    "prefix_capsule_revisions": """CREATE TABLE prefix_capsule_revisions (
    capsule_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    capsule_digest TEXT NOT NULL UNIQUE,
    parent_capsule_digest TEXT NOT NULL,
    source_end INTEGER NOT NULL CHECK (source_end > 0),
    payload_json TEXT NOT NULL,
    PRIMARY KEY(capsule_id, revision)
) STRICT""",
    "profile_state_events": """CREATE TABLE profile_state_events (
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    event_id TEXT PRIMARY KEY NOT NULL,
    intent_digest TEXT NOT NULL UNIQUE,
    event_digest TEXT NOT NULL UNIQUE,
    module_id TEXT NOT NULL,
    field_id TEXT NOT NULL,
    payload_json TEXT NOT NULL
) STRICT""",
    "profile_current_projection": """CREATE TABLE profile_current_projection (
    module_id TEXT NOT NULL,
    field_id TEXT NOT NULL,
    state TEXT NOT NULL,
    scaled_value INTEGER,
    last_sequence INTEGER NOT NULL CHECK (last_sequence >= 0),
    last_event_id TEXT,
    last_event_digest TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    projection_digest TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY(module_id, field_id)
) STRICT""",
    "diary_entries_no_update": (
        "CREATE TRIGGER diary_entries_no_update BEFORE UPDATE ON diary_entries\n"
        "BEGIN SELECT RAISE(ABORT, 'diary_entry_immutable'); END"
    ),
    "diary_entries_no_delete": (
        "CREATE TRIGGER diary_entries_no_delete BEFORE DELETE ON diary_entries\n"
        "BEGIN SELECT RAISE(ABORT, 'diary_entry_immutable'); END"
    ),
    "owner_day_revisions_no_update": (
        "CREATE TRIGGER owner_day_revisions_no_update "
        "BEFORE UPDATE ON owner_day_revisions\n"
        "BEGIN SELECT RAISE(ABORT, 'owner_day_revision_immutable'); END"
    ),
    "owner_day_revisions_no_delete": (
        "CREATE TRIGGER owner_day_revisions_no_delete "
        "BEFORE DELETE ON owner_day_revisions\n"
        "BEGIN SELECT RAISE(ABORT, 'owner_day_revision_immutable'); END"
    ),
    "prefix_capsule_revisions_no_update": (
        "CREATE TRIGGER prefix_capsule_revisions_no_update "
        "BEFORE UPDATE ON prefix_capsule_revisions\n"
        "BEGIN SELECT RAISE(ABORT, 'prefix_capsule_revision_immutable'); END"
    ),
    "prefix_capsule_revisions_no_delete": (
        "CREATE TRIGGER prefix_capsule_revisions_no_delete "
        "BEFORE DELETE ON prefix_capsule_revisions\n"
        "BEGIN SELECT RAISE(ABORT, 'prefix_capsule_revision_immutable'); END"
    ),
    "profile_state_events_no_update": (
        "CREATE TRIGGER profile_state_events_no_update "
        "BEFORE UPDATE ON profile_state_events\n"
        "BEGIN SELECT RAISE(ABORT, 'profile_state_event_immutable'); END"
    ),
    "profile_state_events_no_delete": (
        "CREATE TRIGGER profile_state_events_no_delete "
        "BEFORE DELETE ON profile_state_events\n"
        "BEGIN SELECT RAISE(ABORT, 'profile_state_event_immutable'); END"
    ),
}
_SCHEMA = ";\n".join(_SCHEMA_OBJECTS.values()) + ";\n"


def _normalized_sql(value: str) -> str:
    return " ".join(value.split()).rstrip(";")


@dataclass(frozen=True, slots=True)
class DiaryStatement:
    statement_id: str
    kind: str
    text: str
    source_sequences: tuple[int, ...] = ()
    source_turn_digests: tuple[str, ...] = ()
    source_episode_digests: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        require_id(self.statement_id, "diary_statement_id")
        if self.kind not in DIARY_STATEMENT_KINDS:
            raise EpisodicMemoryError("diary_statement_kind_rejected")
        require_text(self.text, "diary_statement", MAX_DIARY_STATEMENT_CHARACTERS)
        if len(self.source_sequences) != len(self.source_turn_digests):
            raise EpisodicMemoryError("diary_source_pointer_incomplete")
        previous = 0
        for sequence, digest in zip(
            self.source_sequences,
            self.source_turn_digests,
            strict=True,
        ):
            if (
                isinstance(sequence, bool)
                or not isinstance(sequence, int)
                or sequence <= previous
            ):
                raise EpisodicMemoryError("diary_source_sequence_invalid")
            require_digest(digest, "diary_source_turn_digest")
            previous = sequence
        if self.kind == "factual_observation" and not self.source_sequences:
            raise EpisodicMemoryError("diary_fact_source_required")
        for value in self.source_episode_digests:
            require_digest(value, "diary_source_episode_digest")

    def payload(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "source_sequences": list(self.source_sequences),
            "source_turn_digests": list(self.source_turn_digests),
            "source_episode_digests": list(self.source_episode_digests),
            "statement_id": self.statement_id,
            "text": self.text,
        }

    @classmethod
    def from_payload(cls, payload: object) -> DiaryStatement:
        required = {
            "kind",
            "source_episode_digests",
            "source_sequences",
            "source_turn_digests",
            "statement_id",
            "text",
        }
        if (
            not isinstance(payload, Mapping)
            or set(payload) != required
            or not isinstance(payload["source_sequences"], list)
            or not isinstance(payload["source_turn_digests"], list)
            or not isinstance(payload["source_episode_digests"], list)
        ):
            raise EpisodicMemoryError("diary_statement_fields_rejected")
        return cls(
            statement_id=payload["statement_id"],  # type: ignore[arg-type]
            kind=payload["kind"],  # type: ignore[arg-type]
            text=payload["text"],  # type: ignore[arg-type]
            source_sequences=tuple(payload["source_sequences"]),  # type: ignore[arg-type]
            source_turn_digests=tuple(payload["source_turn_digests"]),  # type: ignore[arg-type]
            source_episode_digests=tuple(payload["source_episode_digests"]),  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class ReflectiveDiaryEntry:
    day: date
    calendar_zone: str
    revision: int
    created_at_utc: datetime
    model_role: str
    model_version: str
    persona_digest: str
    release_set_id: str
    generation_kind: str
    reason_code: str
    statements: tuple[DiaryStatement, ...]
    source_selection_digest: str
    egress_policy_digest: str
    style_contract_digest: str
    closure_binding_digest: str
    source_sequences: tuple[int, ...]
    source_turn_digests: tuple[str, ...]
    supersedes_revision: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.day, date) or isinstance(self.day, datetime):
            raise EpisodicMemoryError("diary_day_invalid")
        if self.calendar_zone not in SUPPORTED_CALENDAR_ZONES:
            raise EpisodicMemoryError("diary_calendar_zone_unsupported")
        if (
            isinstance(self.revision, bool)
            or not isinstance(self.revision, int)
            or self.revision < 1
        ):
            raise EpisodicMemoryError("diary_revision_invalid")
        object.__setattr__(
            self,
            "created_at_utc",
            require_utc(self.created_at_utc, "diary_created_at"),
        )
        require_id(self.model_role, "diary_model_role")
        require_id(self.model_version, "diary_model_version")
        require_digest(self.persona_digest, "diary_persona_digest")
        require_digest(self.release_set_id, "diary_release_set_id")
        if self.generation_kind not in DIARY_GENERATION_KINDS:
            raise EpisodicMemoryError("diary_generation_kind_rejected")
        require_id(self.reason_code, "diary_reason_code")
        if not self.statements or len({item.statement_id for item in self.statements}) != len(
            self.statements
        ):
            raise EpisodicMemoryError("diary_statements_invalid")
        for value, label in (
            (self.source_selection_digest, "diary_source_selection"),
            (self.egress_policy_digest, "diary_egress_policy"),
            (self.style_contract_digest, "diary_style_contract"),
            (self.closure_binding_digest, "diary_closure_binding"),
        ):
            require_digest(value, label)
        if (
            not self.source_sequences
            or len(self.source_sequences) != len(self.source_turn_digests)
        ):
            raise EpisodicMemoryError("diary_complete_source_set_required")
        previous = 0
        for sequence, digest in zip(
            self.source_sequences,
            self.source_turn_digests,
            strict=True,
        ):
            if (
                isinstance(sequence, bool)
                or not isinstance(sequence, int)
                or sequence <= previous
            ):
                raise EpisodicMemoryError("diary_complete_source_sequence_invalid")
            require_digest(digest, "diary_complete_source_digest")
            previous = sequence
        if self.generation_kind == "contemporaneous":
            if self.supersedes_revision is not None:
                raise EpisodicMemoryError("diary_contemporaneous_supersede_prohibited")
        elif self.generation_kind == "late_backfill" and self.revision == 1:
            if self.supersedes_revision is not None:
                raise EpisodicMemoryError("diary_supersedes_revision_invalid")
        elif (
            isinstance(self.supersedes_revision, bool)
            or not isinstance(self.supersedes_revision, int)
            or self.supersedes_revision < 1
            or self.supersedes_revision >= self.revision
        ):
            raise EpisodicMemoryError("diary_supersedes_revision_invalid")

    def payload(self) -> dict[str, object]:
        return {
            "calendar_zone": self.calendar_zone,
            "created_at_utc": self.created_at_utc.isoformat(timespec="microseconds"),
            "day": self.day.isoformat(),
            "generation_kind": self.generation_kind,
            "model_role": self.model_role,
            "model_version": self.model_version,
            "persona_digest": self.persona_digest,
            "reason_code": self.reason_code,
            "release_set_id": self.release_set_id,
            "revision": self.revision,
            "source_selection_digest": self.source_selection_digest,
            "egress_policy_digest": self.egress_policy_digest,
            "style_contract_digest": self.style_contract_digest,
            "closure_binding_digest": self.closure_binding_digest,
            "source_sequences": list(self.source_sequences),
            "source_turn_digests": list(self.source_turn_digests),
            "statements": [item.payload() for item in self.statements],
            "supersedes_revision": self.supersedes_revision,
        }

    @classmethod
    def from_payload(cls, payload: object) -> ReflectiveDiaryEntry:
        required = {
            "calendar_zone",
            "closure_binding_digest",
            "created_at_utc",
            "day",
            "egress_policy_digest",
            "generation_kind",
            "model_role",
            "model_version",
            "persona_digest",
            "reason_code",
            "release_set_id",
            "revision",
            "source_selection_digest",
            "source_sequences",
            "source_turn_digests",
            "statements",
            "style_contract_digest",
            "supersedes_revision",
        }
        if (
            not isinstance(payload, Mapping)
            or set(payload) != required
            or not isinstance(payload["statements"], list)
            or not isinstance(payload["source_sequences"], list)
            or not isinstance(payload["source_turn_digests"], list)
        ):
            raise EpisodicMemoryError("diary_entry_fields_rejected")
        try:
            parsed_day = date.fromisoformat(payload["day"])  # type: ignore[arg-type]
            created = datetime.fromisoformat(payload["created_at_utc"])  # type: ignore[arg-type]
        except (TypeError, ValueError):
            raise EpisodicMemoryError("diary_entry_fields_rejected") from None
        return cls(
            day=parsed_day,
            calendar_zone=payload["calendar_zone"],  # type: ignore[arg-type]
            revision=payload["revision"],  # type: ignore[arg-type]
            created_at_utc=created,
            model_role=payload["model_role"],  # type: ignore[arg-type]
            model_version=payload["model_version"],  # type: ignore[arg-type]
            persona_digest=payload["persona_digest"],  # type: ignore[arg-type]
            release_set_id=payload["release_set_id"],  # type: ignore[arg-type]
            generation_kind=payload["generation_kind"],  # type: ignore[arg-type]
            reason_code=payload["reason_code"],  # type: ignore[arg-type]
            statements=tuple(DiaryStatement.from_payload(item) for item in payload["statements"]),
            source_selection_digest=payload["source_selection_digest"],  # type: ignore[arg-type]
            egress_policy_digest=payload["egress_policy_digest"],  # type: ignore[arg-type]
            style_contract_digest=payload["style_contract_digest"],  # type: ignore[arg-type]
            closure_binding_digest=payload["closure_binding_digest"],  # type: ignore[arg-type]
            source_sequences=tuple(payload["source_sequences"]),  # type: ignore[arg-type]
            source_turn_digests=tuple(payload["source_turn_digests"]),  # type: ignore[arg-type]
            supersedes_revision=payload["supersedes_revision"],  # type: ignore[arg-type]
        )

    @property
    def entry_digest(self) -> str:
        return semantic_digest("myuna-p07-reflective-diary-entry-v1", self.payload())


@dataclass(frozen=True, slots=True)
class DiaryJobEvent:
    job_id: str
    day: date
    calendar_zone: str
    target_revision: int
    event_kind: str
    attempt: int
    reason_code: str
    occurred_at_utc: datetime
    generation_kind: str = "contemporaneous"
    supersedes_revision: int | None = None
    archive_head_digest: str | None = None
    job_digest: str | None = None
    source_selection_digest: str | None = None
    closure_binding_digest: str | None = None
    source_sequences: tuple[int, ...] = ()
    source_turn_digests: tuple[str, ...] = ()
    capacity_receipt_digest: str | None = None
    provider_call_state: str = "not_called"
    entry_digest: str | None = None

    def __post_init__(self) -> None:
        require_id(self.job_id, "diary_job_id")
        if self.calendar_zone not in SUPPORTED_CALENDAR_ZONES:
            raise EpisodicMemoryError("diary_calendar_zone_unsupported")
        if (
            isinstance(self.target_revision, bool)
            or not isinstance(self.target_revision, int)
            or self.target_revision < 1
        ):
            raise EpisodicMemoryError("diary_target_revision_invalid")
        if self.event_kind not in {
            "pending",
            "ready",
            "dispatch_started",
            "attempted",
            "retryable_gap",
            "coverage_incomplete",
            "missing",
            "completed",
        }:
            raise EpisodicMemoryError("diary_job_event_unknown")
        if self.generation_kind not in DIARY_GENERATION_KINDS:
            raise EpisodicMemoryError("diary_generation_kind_rejected")
        if self.generation_kind == "contemporaneous":
            if self.supersedes_revision is not None:
                raise EpisodicMemoryError("diary_contemporaneous_supersede_prohibited")
        elif self.generation_kind == "late_backfill" and self.target_revision == 1:
            if self.supersedes_revision is not None:
                raise EpisodicMemoryError("diary_supersedes_revision_invalid")
        elif (
            isinstance(self.supersedes_revision, bool)
            or not isinstance(self.supersedes_revision, int)
            or self.supersedes_revision < 1
            or self.supersedes_revision >= self.target_revision
        ):
            raise EpisodicMemoryError("diary_supersedes_revision_invalid")
        if isinstance(self.attempt, bool) or not 0 <= self.attempt <= MAX_JOB_ATTEMPTS:
            raise EpisodicMemoryError("diary_job_attempt_invalid")
        require_id(self.reason_code, "diary_job_reason")
        object.__setattr__(
            self,
            "occurred_at_utc",
            require_utc(self.occurred_at_utc, "diary_job_time"),
        )
        for value, label in (
            (self.job_digest, "diary_job_digest"),
            (self.source_selection_digest, "diary_job_source_selection"),
            (self.closure_binding_digest, "diary_job_closure_binding"),
            (self.capacity_receipt_digest, "diary_job_capacity_receipt"),
            (self.archive_head_digest, "diary_job_archive_head"),
        ):
            if value is not None:
                require_digest(value, label)
        if len(self.source_sequences) != len(self.source_turn_digests):
            raise EpisodicMemoryError("diary_job_source_pointer_incomplete")
        previous = 0
        for sequence, digest in zip(
            self.source_sequences,
            self.source_turn_digests,
            strict=True,
        ):
            if (
                isinstance(sequence, bool)
                or not isinstance(sequence, int)
                or sequence <= previous
            ):
                raise EpisodicMemoryError("diary_job_source_sequence_invalid")
            require_digest(digest, "diary_job_source_turn")
            previous = sequence
        if self.event_kind in {
            "ready",
            "dispatch_started",
            "attempted",
            "retryable_gap",
            "completed",
        }:
            if (
                self.archive_head_digest is None
                or self.job_digest is None
                or self.source_selection_digest is None
                or self.closure_binding_digest is None
                or not self.source_sequences
            ):
                raise EpisodicMemoryError("diary_job_binding_incomplete")
        if self.provider_call_state not in {"not_called", "called", "unknown"}:
            raise EpisodicMemoryError("diary_provider_call_state_rejected")
        if self.event_kind in {"pending", "ready", "coverage_incomplete"}:
            if self.provider_call_state != "not_called":
                raise EpisodicMemoryError("diary_gap_provider_call_prohibited")
        elif self.event_kind in {"attempted", "completed"}:
            if self.provider_call_state != "called":
                raise EpisodicMemoryError("diary_attempt_provider_call_required")
        elif self.event_kind in {"dispatch_started", "retryable_gap"}:
            if self.provider_call_state != "unknown":
                raise EpisodicMemoryError("diary_provider_call_state_required")
        if self.event_kind == "completed":
            if self.entry_digest is None:
                raise EpisodicMemoryError("diary_completed_digest_required")
            require_digest(self.entry_digest, "diary_entry_digest")
        elif self.entry_digest is not None:
            raise EpisodicMemoryError("diary_gap_entry_digest_prohibited")

    def payload(self) -> dict[str, object]:
        return {
            "attempt": self.attempt,
            "archive_head_digest": self.archive_head_digest,
            "calendar_zone": self.calendar_zone,
            "capacity_receipt_digest": self.capacity_receipt_digest,
            "closure_binding_digest": self.closure_binding_digest,
            "day": self.day.isoformat(),
            "entry_digest": self.entry_digest,
            "event_kind": self.event_kind,
            "generation_kind": self.generation_kind,
            "job_digest": self.job_digest,
            "job_id": self.job_id,
            "occurred_at_utc": self.occurred_at_utc.isoformat(timespec="microseconds"),
            "provider_call_state": self.provider_call_state,
            "reason_code": self.reason_code,
            "source_selection_digest": self.source_selection_digest,
            "source_sequences": list(self.source_sequences),
            "source_turn_digests": list(self.source_turn_digests),
            "supersedes_revision": self.supersedes_revision,
            "target_revision": self.target_revision,
        }

    @property
    def event_digest(self) -> str:
        return semantic_digest("myuna-p07-reflective-diary-job-event-v3", self.payload())

    @classmethod
    def from_payload(cls, payload: object) -> DiaryJobEvent:
        required = {
            "attempt",
            "archive_head_digest",
            "calendar_zone",
            "capacity_receipt_digest",
            "closure_binding_digest",
            "day",
            "entry_digest",
            "event_kind",
            "generation_kind",
            "job_digest",
            "job_id",
            "occurred_at_utc",
            "provider_call_state",
            "reason_code",
            "source_selection_digest",
            "source_sequences",
            "source_turn_digests",
            "supersedes_revision",
            "target_revision",
        }
        if (
            not isinstance(payload, Mapping)
            or set(payload) != required
            or not isinstance(payload["source_sequences"], list)
            or not isinstance(payload["source_turn_digests"], list)
        ):
            raise EpisodicMemoryError("diary_job_event_fields_rejected")
        try:
            parsed_day = date.fromisoformat(payload["day"])  # type: ignore[arg-type]
            occurred = datetime.fromisoformat(payload["occurred_at_utc"])  # type: ignore[arg-type]
        except (TypeError, ValueError):
            raise EpisodicMemoryError("diary_job_event_fields_rejected") from None
        return cls(
            job_id=payload["job_id"],  # type: ignore[arg-type]
            day=parsed_day,
            calendar_zone=payload["calendar_zone"],  # type: ignore[arg-type]
            target_revision=payload["target_revision"],  # type: ignore[arg-type]
            event_kind=payload["event_kind"],  # type: ignore[arg-type]
            attempt=payload["attempt"],  # type: ignore[arg-type]
            reason_code=payload["reason_code"],  # type: ignore[arg-type]
            occurred_at_utc=occurred,
            generation_kind=payload["generation_kind"],  # type: ignore[arg-type]
            supersedes_revision=payload["supersedes_revision"],  # type: ignore[arg-type]
            archive_head_digest=payload["archive_head_digest"],  # type: ignore[arg-type]
            job_digest=payload["job_digest"],  # type: ignore[arg-type]
            source_selection_digest=payload["source_selection_digest"],  # type: ignore[arg-type]
            closure_binding_digest=payload["closure_binding_digest"],  # type: ignore[arg-type]
            source_sequences=tuple(payload["source_sequences"]),  # type: ignore[arg-type]
            source_turn_digests=tuple(payload["source_turn_digests"]),  # type: ignore[arg-type]
            capacity_receipt_digest=payload["capacity_receipt_digest"],  # type: ignore[arg-type]
            provider_call_state=payload["provider_call_state"],  # type: ignore[arg-type]
            entry_digest=payload["entry_digest"],  # type: ignore[arg-type]
        )


def verify_diary_sources(
    entry: ReflectiveDiaryEntry,
    turns: Sequence[CompleteTurn],
    *,
    effective_time_bindings: Mapping[int, TurnTimeBinding] | None = None,
) -> None:
    by_sequence = {turn.draft.sequence: turn for turn in turns}
    if tuple(by_sequence) != entry.source_sequences:
        raise EpisodicMemoryError("diary_complete_source_set_mismatch")
    for statement in entry.statements:
        for sequence, expected_digest in zip(
            statement.source_sequences,
            statement.source_turn_digests,
            strict=True,
        ):
            selected = by_sequence.get(sequence)
            if selected is None or selected.turn_digest != expected_digest:
                raise EpisodicMemoryError("diary_source_pointer_drifted")
            binding = (
                selected.draft.time_binding
                if effective_time_bindings is None
                else effective_time_bindings.get(sequence)
            )
            if binding is None:
                raise EpisodicMemoryError("diary_source_time_binding_missing")
            if binding.status != "exact" or binding.delivered_at_utc is None:
                raise EpisodicMemoryError("diary_source_time_unresolved")
            if binding.calendar_zone != entry.calendar_zone:
                raise EpisodicMemoryError("diary_source_calendar_zone_mismatch")
            if (
                binding.delivered_at_utc.astimezone(ZoneInfo(entry.calendar_zone)).date()
                != entry.day
            ):
                raise EpisodicMemoryError("diary_source_day_mismatch")
    if tuple(turn.turn_digest for turn in turns) != entry.source_turn_digests:
        raise EpisodicMemoryError("diary_complete_source_digest_mismatch")


def _verify_source_manifest(
    manifest: Mapping[str, object],
    manifest_digest: str,
    *,
    source_sequences: Sequence[int],
    source_turn_digests: Sequence[str],
    source_snapshot: EpisodicIndexSnapshot | None = None,
) -> None:
    expected = {
        "archive_head_digest",
        "archive_id",
        "archive_turn_count",
        "correction_digests",
        "schema",
        "snapshot_digest",
        "source_closure_digest",
        "source_epoch_ids",
        "source_reference_digests",
        "source_release_set_ids",
        "source_sequences",
        "source_turn_digests",
        "source_turn_ids",
        "temporal_snapshot_digest",
    }
    list_fields = {
        "correction_digests",
        "source_epoch_ids",
        "source_reference_digests",
        "source_release_set_ids",
        "source_sequences",
        "source_turn_digests",
        "source_turn_ids",
    }
    if set(manifest) != expected or any(
        not isinstance(manifest[name], list) for name in list_fields
    ):
        raise EpisodicMemoryError("diary_source_manifest_rejected")
    if manifest["schema"] != DERIVATIVE_SOURCE_MANIFEST_SCHEMA:
        raise EpisodicMemoryError("diary_source_manifest_schema_unknown")
    for name in (
        "archive_head_digest",
        "snapshot_digest",
        "source_closure_digest",
        "temporal_snapshot_digest",
    ):
        require_digest(manifest[name], "diary_source_manifest_digest")  # type: ignore[arg-type]
    require_id(manifest["archive_id"], "diary_source_manifest_archive")  # type: ignore[arg-type]
    turn_count = manifest["archive_turn_count"]
    if (
        isinstance(turn_count, bool)
        or not isinstance(turn_count, int)
        or turn_count < 0
    ):
        raise EpisodicMemoryError("diary_source_manifest_count_invalid")
    sequences = tuple(manifest["source_sequences"])
    if (
        sequences != tuple(sorted(set(sequences)))
        or any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 1
            or value > turn_count
            for value in sequences
        )
    ):
        raise EpisodicMemoryError("diary_source_manifest_sequence_invalid")
    selected_count = len(sequences)
    for name in (
        "source_epoch_ids",
        "source_reference_digests",
        "source_release_set_ids",
        "source_turn_digests",
        "source_turn_ids",
    ):
        if len(manifest[name]) != selected_count:  # type: ignore[arg-type]
            raise EpisodicMemoryError("diary_source_manifest_binding_mismatch")
    for value in manifest["source_epoch_ids"]:  # type: ignore[union-attr]
        require_id(value, "diary_source_epoch")
    for value in manifest["source_turn_ids"]:  # type: ignore[union-attr]
        require_id(value, "diary_source_turn")
    for name in (
        "correction_digests",
        "source_reference_digests",
        "source_release_set_ids",
        "source_turn_digests",
    ):
        for value in manifest[name]:  # type: ignore[union-attr]
            require_digest(value, "diary_source_digest")
    if tuple(sorted(set(manifest["correction_digests"]))) != tuple(  # type: ignore[arg-type]
        manifest["correction_digests"]  # type: ignore[arg-type]
    ):
        raise EpisodicMemoryError("diary_source_manifest_corrections_invalid")
    require_digest(manifest_digest, "diary_source_manifest")
    if manifest_digest != semantic_digest(
        "myuna-p07-derivative-source-manifest-v1", manifest
    ):
        raise EpisodicMemoryError("diary_source_manifest_digest_mismatch")
    if (
        tuple(manifest["source_sequences"]) != tuple(source_sequences)
        or tuple(manifest["source_turn_digests"]) != tuple(source_turn_digests)
    ):
        raise EpisodicMemoryError("diary_source_manifest_binding_mismatch")
    if sequences and sequences[-1] == turn_count:
        source_head = manifest["source_turn_digests"][-1]  # type: ignore[index]
        if source_head != manifest["archive_head_digest"]:
            raise EpisodicMemoryError("diary_source_manifest_head_mismatch")
    if source_snapshot is not None:
        expected_manifest, expected_digest = source_snapshot.source_manifest(
            source_sequences
        )
        if dict(manifest) != expected_manifest or manifest_digest != expected_digest:
            raise EpisodicMemoryError("diary_source_manifest_snapshot_mismatch")


def _verify_snapshot_turns(
    snapshot: EpisodicIndexSnapshot,
    turns: Sequence[CompleteTurn],
) -> dict[int, EpisodicSourceReference]:
    from .index import EpisodicIndexSnapshot

    if not isinstance(snapshot, EpisodicIndexSnapshot):
        raise EpisodicMemoryError("diary_source_snapshot_rejected")
    if len(snapshot.source_references) != snapshot.archive_turn_count:
        raise EpisodicMemoryError("diary_source_snapshot_mismatch")
    references = {item.sequence: item for item in snapshot.source_references}
    for turn in turns:
        reference = references.get(turn.draft.sequence)
        if (
            reference is None
            or reference.sequence != turn.draft.sequence
            or reference.turn_id != turn.draft.turn_id
            or reference.turn_digest != turn.turn_digest
            or reference.previous_turn_digest != turn.draft.previous_turn_digest
            or reference.epoch_id != turn.draft.epoch_id
            or reference.release_set_id != turn.draft.release_set_id
            or reference.request_digest != turn.draft.request_digest
            or reference.response_digest != turn.draft.response_digest
            or reference.delivery_ack_digest != turn.draft.delivery_ack_digest
            or reference.model_history_eligible != turn.model_history_eligible
            or reference.original_time_binding_digest
            != turn.draft.time_binding.binding_digest
        ):
            raise EpisodicMemoryError("diary_source_snapshot_mismatch")
    return references


class ReflectiveDiaryStore:
    """Append-only authored perspective; raw turns remain the factual authority."""

    def __init__(
        self,
        path: Path,
        *,
        current_source_snapshot_loader: Callable[
            [],
            tuple[
                EpisodicIndexSnapshot,
                tuple[CompleteTurn, ...],
                TemporalIntervalIndexSnapshot,
            ],
        ],
        timeout: float = 1.0,
    ) -> None:
        self.path = path
        self._current_source_snapshot_loader = current_source_snapshot_loader
        self.timeout = timeout

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=self.timeout, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA trusted_schema = OFF")
        return connection

    def _load_current_source_authority(
        self,
    ) -> tuple[
        EpisodicIndexSnapshot,
        tuple[CompleteTurn, ...],
        TemporalIntervalIndexSnapshot,
    ]:
        from .index import EpisodicIndexSnapshot
        from .temporal_bridge import TemporalIntervalIndexSnapshot

        try:
            authority = self._current_source_snapshot_loader()
        except (EpisodicMemoryError, OSError, TypeError, ValueError) as exc:
            raise EpisodicMemoryError(
                "diary_current_source_authority_unavailable"
            ) from exc
        if (
            not isinstance(authority, tuple)
            or len(authority) != 3
            or not isinstance(authority[0], EpisodicIndexSnapshot)
            or not isinstance(authority[1], tuple)
            or any(not isinstance(turn, CompleteTurn) for turn in authority[1])
            or not isinstance(authority[2], TemporalIntervalIndexSnapshot)
        ):
            raise EpisodicMemoryError("diary_current_source_authority_ambiguous")
        snapshot, turns, temporal_snapshot = authority
        if (
            len(turns) != snapshot.archive_turn_count
            or tuple(turn.draft.sequence for turn in turns)
            != tuple(range(1, snapshot.archive_turn_count + 1))
            or temporal_snapshot.archive_head_digest != snapshot.archive_head_digest
            or temporal_snapshot.snapshot_digest != snapshot.temporal_snapshot_digest
        ):
            raise EpisodicMemoryError("diary_current_source_authority_ambiguous")
        _verify_snapshot_turns(snapshot, turns)
        return snapshot, turns, temporal_snapshot

    def _load_current_source_snapshot(self) -> EpisodicIndexSnapshot:
        return self._load_current_source_authority()[0]

    def _verify_current_source_binding(
        self,
        *,
        submitted_snapshot: EpisodicIndexSnapshot,
        turns: Sequence[CompleteTurn],
        source_manifest: Mapping[str, object],
        source_manifest_digest: str,
        source_sequences: Sequence[int],
        source_turn_digests: Sequence[str],
    ) -> None:
        current_snapshot, _, _ = self._load_current_source_authority()
        if current_snapshot != submitted_snapshot:
            raise EpisodicMemoryError("diary_current_source_snapshot_mismatch")
        _verify_snapshot_turns(current_snapshot, turns)
        _verify_source_manifest(
            source_manifest,
            source_manifest_digest,
            source_sequences=source_sequences,
            source_turn_digests=source_turn_digests,
            source_snapshot=current_snapshot,
        )

    def initialize(self) -> None:
        if self.path.exists() or self.path.is_symlink():
            status = self.path.lstat()
            if (
                self.path.is_symlink()
                or not stat.S_ISREG(status.st_mode)
                or status.st_nlink != 1
                or stat.S_IMODE(status.st_mode) != 0o600
            ):
                raise EpisodicMemoryError("diary_type_rejected")
            self._verify()
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = self._connect()
        try:
            connection.executescript("BEGIN IMMEDIATE;\n" + _SCHEMA)
            connection.execute(f"PRAGMA application_id = {SQLITE_APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            connection.executemany(
                "INSERT INTO metadata(key, value) VALUES (?, ?)",
                (("diary_schema", DIARY_SCHEMA), ("default_calendar_zone", DEFAULT_CALENDAR_ZONE)),
            )
            for manifest in profile_v2_manifests():
                current = initial_profile_current(manifest)
                connection.execute(
                    "INSERT INTO profile_current_projection VALUES "
                    "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        current.module_id,
                        current.field_id,
                        current.state,
                        current.scaled_value,
                        current.last_sequence,
                        current.last_event_id,
                        current.last_event_digest,
                        current.manifest_digest,
                        current.projection_digest,
                        profile_state_canonical_bytes(current.payload()).decode("ascii"),
                    ),
                )
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        os.chmod(self.path, 0o600)
        self._verify()

    def _verify(self) -> None:
        connection = self._connect()
        try:
            self._verify_connection_schema(connection)
        except sqlite3.Error as exc:
            raise EpisodicMemoryError("diary_unavailable") from exc
        finally:
            connection.close()

    @staticmethod
    def _verify_connection_schema(connection: sqlite3.Connection) -> None:
        application = connection.execute("PRAGMA application_id").fetchone()[0]
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        metadata = dict(connection.execute("SELECT key, value FROM metadata"))
        objects = {
            row[0]: _normalized_sql(row[1])
            for row in connection.execute(
                "SELECT name, sql FROM sqlite_schema "
                "WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL"
            )
        }
        expected_objects = {
            name: _normalized_sql(sql) for name, sql in _SCHEMA_OBJECTS.items()
        }
        if (
            application != SQLITE_APPLICATION_ID
            or version != SCHEMA_VERSION
            or metadata
            != {
                "default_calendar_zone": DEFAULT_CALENDAR_ZONE,
                "diary_schema": DIARY_SCHEMA,
            }
            or objects != expected_objects
        ):
            raise EpisodicMemoryError("diary_schema_rejected")

    def append_job_event(self, event: DiaryJobEvent) -> None:
        del event
        raise EpisodicMemoryError("diary_job_queue_retired")

    def _reflective_records(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[tuple[ReflectiveDiaryEntry, dict[str, object], str], ...]:
        rows = connection.execute(
            "SELECT day_key, calendar_zone, revision, entry_digest, "
            "source_manifest_digest, payload_json FROM diary_entries "
            "ORDER BY day_key, calendar_zone, revision"
        ).fetchall()
        result: list[tuple[ReflectiveDiaryEntry, dict[str, object], str]] = []
        expected_by_day: dict[tuple[str, str], int] = {}
        for row in rows:
            payload = json.loads(row["payload_json"])
            if not isinstance(payload, Mapping) or set(payload) != {
                "entry",
                "source_manifest",
            }:
                raise EpisodicMemoryError("diary_revision_payload_rejected")
            entry = ReflectiveDiaryEntry.from_payload(payload["entry"])
            manifest = payload["source_manifest"]
            if not isinstance(manifest, Mapping):
                raise EpisodicMemoryError("diary_source_manifest_rejected")
            manifest_copy = dict(manifest)
            _verify_source_manifest(
                manifest_copy,
                row["source_manifest_digest"],
                source_sequences=entry.source_sequences,
                source_turn_digests=entry.source_turn_digests,
            )
            key = (entry.day.isoformat(), entry.calendar_zone)
            expected = expected_by_day.get(key, 0) + 1
            if (
                row["day_key"] != key[0]
                or row["calendar_zone"] != key[1]
                or row["revision"] != entry.revision
                or entry.revision != expected
                or entry.supersedes_revision
                != (None if expected == 1 else expected - 1)
                or row["entry_digest"] != entry.entry_digest
            ):
                raise EpisodicMemoryError("diary_revision_chain_drifted")
            expected_by_day[key] = expected
            result.append(
                (entry, manifest_copy, row["source_manifest_digest"])
            )
        return tuple(result)

    def _owner_day_records(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[tuple[OwnerDayDiaryRevision, dict[str, object], str], ...]:
        from .owner_day_generation import OwnerDayDiaryRevision

        rows = connection.execute(
            "SELECT owner_day, calendar_zone, revision, purpose, revision_digest, "
            "source_manifest_digest, payload_json FROM owner_day_revisions "
            "ORDER BY owner_day, calendar_zone, revision"
        ).fetchall()
        result: list[tuple[OwnerDayDiaryRevision, dict[str, object], str]] = []
        expected_by_day: dict[tuple[str, str], int] = {}
        for row in rows:
            payload = json.loads(row["payload_json"])
            if not isinstance(payload, Mapping) or set(payload) != {
                "revision",
                "source_manifest",
            }:
                raise EpisodicMemoryError("owner_day_revision_payload_rejected")
            revision = OwnerDayDiaryRevision.from_payload(payload["revision"])
            manifest = payload["source_manifest"]
            if not isinstance(manifest, Mapping):
                raise EpisodicMemoryError("diary_source_manifest_rejected")
            manifest_copy = dict(manifest)
            _verify_source_manifest(
                manifest_copy,
                row["source_manifest_digest"],
                source_sequences=revision.source_sequences,
                source_turn_digests=revision.source_turn_digests,
            )
            key = (revision.owner_day, revision.calendar_zone)
            expected = expected_by_day.get(key, 0) + 1
            if (
                row["owner_day"] != key[0]
                or row["calendar_zone"] != key[1]
                or row["revision"] != revision.revision
                or row["purpose"] != revision.purpose
                or revision.revision != expected
                or revision.supersedes_revision
                != (None if expected == 1 else expected - 1)
                or row["revision_digest"] != revision.revision_digest
            ):
                raise EpisodicMemoryError("owner_day_revision_chain_drifted")
            expected_by_day[key] = expected
            result.append(
                (revision, manifest_copy, row["source_manifest_digest"])
            )
        return tuple(result)

    def _prefix_capsule_records(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[PrefixCapsule, ...]:
        rows = connection.execute(
            "SELECT capsule_id, revision, capsule_digest, "
            "parent_capsule_digest, source_end, payload_json, "
            "typeof(capsule_id) AS capsule_id_type, "
            "typeof(revision) AS revision_type, "
            "typeof(capsule_digest) AS capsule_digest_type, "
            "typeof(parent_capsule_digest) AS parent_capsule_digest_type, "
            "typeof(source_end) AS source_end_type, "
            "typeof(payload_json) AS payload_json_type "
            "FROM prefix_capsule_revisions ORDER BY capsule_id, revision"
        ).fetchall()
        result: list[PrefixCapsule] = []
        latest_by_id: dict[str, tuple[int, str]] = {}
        for row in rows:
            if (
                type(row["capsule_id"]) is not str
                or type(row["revision"]) is not int
                or type(row["capsule_digest"]) is not str
                or type(row["parent_capsule_digest"]) is not str
                or type(row["source_end"]) is not int
                or type(row["payload_json"]) is not str
                or row["capsule_id_type"] != "text"
                or row["revision_type"] != "integer"
                or row["capsule_digest_type"] != "text"
                or row["parent_capsule_digest_type"] != "text"
                or row["source_end_type"] != "integer"
                or row["payload_json_type"] != "text"
            ):
                raise EpisodicMemoryError("prefix_capsule_chain_drifted")
            capsule = _prefix_capsule_from_json(row["payload_json"])
            prior = latest_by_id.get(capsule.capsule_id)
            expected_revision = 1 if prior is None else prior[0] + 1
            expected_parent = "0" * 64 if prior is None else prior[1]
            if (
                row["capsule_id"] != capsule.capsule_id
                or row["revision"] != capsule.revision
                or row["capsule_digest"] != capsule.capsule_digest
                or row["parent_capsule_digest"]
                != capsule.parent_capsule_digest
                or row["source_end"] != capsule.source_end
                or capsule.revision != expected_revision
                or capsule.parent_capsule_digest != expected_parent
            ):
                raise EpisodicMemoryError("prefix_capsule_chain_drifted")
            latest_by_id[capsule.capsule_id] = (
                capsule.revision,
                capsule.capsule_digest,
            )
            result.append(capsule)
        return tuple(result)

    def _profile_event_records(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[ProfileStateEvent, ...]:
        event_rows = connection.execute(
            "SELECT sequence, event_id, intent_digest, event_digest, module_id, "
            "field_id, payload_json, typeof(sequence) AS sequence_type, "
            "typeof(event_id) AS event_id_type, "
            "typeof(intent_digest) AS intent_digest_type, "
            "typeof(event_digest) AS event_digest_type, "
            "typeof(module_id) AS module_id_type, "
            "typeof(field_id) AS field_id_type, "
            "typeof(payload_json) AS payload_json_type "
            "FROM profile_state_events ORDER BY module_id, field_id, sequence"
        ).fetchall()
        events: list[ProfileStateEvent] = []
        expected_by_field: dict[str, int] = {}
        for row in event_rows:
            if (
                row["sequence_type"] != "integer"
                or row["event_id_type"] != "text"
                or row["intent_digest_type"] != "text"
                or row["event_digest_type"] != "text"
                or row["module_id_type"] != "text"
                or row["field_id_type"] != "text"
                or row["payload_json_type"] != "text"
            ):
                raise EpisodicMemoryError("profile_state_chain_drifted")
            event = _profile_event_from_json(row["payload_json"])
            expected_sequence = expected_by_field.get(event.field_id, 0) + 1
            if (
                row["sequence"] != expected_sequence
                or event.sequence != expected_sequence
                or row["event_id"] != event.event_id
                or row["intent_digest"] != event.intent_digest
                or row["event_digest"] != event.event_digest
                or row["module_id"] != event.module_id
                or row["field_id"] != event.field_id
            ):
                raise EpisodicMemoryError("profile_state_chain_drifted")
            expected_by_field[event.field_id] = expected_sequence
            events.append(event)
        return tuple(events)

    def _profile_state_records(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[tuple[ProfileStateEvent, ...], tuple[ProfileCurrentValue, ...]]:
        events = self._profile_event_records(connection)
        current_rows = connection.execute(
            "SELECT module_id, field_id, state, scaled_value, last_sequence, "
            "last_event_id, last_event_digest, manifest_digest, projection_digest, "
            "payload_json, typeof(module_id) AS module_id_type, "
            "typeof(field_id) AS field_id_type, typeof(state) AS state_type, "
            "typeof(last_sequence) AS last_sequence_type, "
            "typeof(last_event_digest) AS last_event_digest_type, "
            "typeof(manifest_digest) AS manifest_digest_type, "
            "typeof(projection_digest) AS projection_digest_type, "
            "typeof(payload_json) AS payload_json_type "
            "FROM profile_current_projection ORDER BY module_id, field_id"
        ).fetchall()
        manifests = {item.field_id: item for item in profile_v2_manifests()}
        currents: list[ProfileCurrentValue] = []
        if len(current_rows) != len(manifests):
            raise EpisodicMemoryError("profile_state_projection_drifted")
        for row in current_rows:
            if (
                row["module_id_type"] != "text"
                or row["field_id_type"] != "text"
                or row["state_type"] != "text"
                or row["last_sequence_type"] != "integer"
                or row["last_event_digest_type"] != "text"
                or row["manifest_digest_type"] != "text"
                or row["projection_digest_type"] != "text"
                or row["payload_json_type"] != "text"
            ):
                raise EpisodicMemoryError("profile_state_projection_drifted")
            current = _profile_current_from_json(row["payload_json"])
            manifest = manifests.get(current.field_id)
            if manifest is None:
                raise EpisodicMemoryError("profile_state_projection_drifted")
            rebuilt = rebuild_profile_current(
                manifest,
                tuple(item for item in events if item.field_id == current.field_id),
            )
            columns = (
                row["module_id"],
                row["field_id"],
                row["state"],
                row["scaled_value"],
                row["last_sequence"],
                row["last_event_id"],
                row["last_event_digest"],
                row["manifest_digest"],
                row["projection_digest"],
            )
            expected = (
                current.module_id,
                current.field_id,
                current.state,
                current.scaled_value,
                current.last_sequence,
                current.last_event_id,
                current.last_event_digest,
                current.manifest_digest,
                current.projection_digest,
            )
            if columns != expected or current != rebuilt:
                raise EpisodicMemoryError("profile_state_projection_drifted")
            currents.append(current)
        current_by_field = {item.field_id: item for item in currents}
        ordered_currents = tuple(
            current_by_field[item.field_id] for item in profile_v2_manifests()
        )
        return events, ordered_currents

    def _verify_all_records(self, connection: sqlite3.Connection) -> None:
        try:
            self._verify_connection_schema(connection)
            self._reflective_records(connection)
            self._owner_day_records(connection)
            self._prefix_capsule_records(connection)
            self._profile_state_records(connection)
        except EpisodicMemoryError:
            raise
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise EpisodicMemoryError("diary_metadata_unavailable") from exc

    def _verify_profile_source(self, intent: ProfileStateIntent) -> None:
        snapshot, turns, temporal_snapshot = self._load_current_source_authority()
        if intent.raw_source_digest != snapshot.source_closure_digest:
            raise EpisodicMemoryError("profile_state_raw_source_mismatch")
        if intent.p08_source_digest != snapshot.temporal_snapshot_digest:
            raise EpisodicMemoryError("profile_state_temporal_source_mismatch")
        delivered = tuple(
            turn for turn in turns if turn.draft.turn_id == intent.delivered_turn_id
        )
        if len(delivered) != 1:
            raise EpisodicMemoryError("profile_state_delivered_turn_mismatch")
        delivered_reference = next(
            (
                item
                for item in snapshot.source_references
                if item.turn_id == intent.delivered_turn_id
            ),
            None,
        )
        if (
            delivered_reference is None
            or delivered[0].draft.delivery_ack_digest is None
            or intent.delivery_ack_digest
            != delivered[0].draft.delivery_ack_digest
            or intent.delivery_ack_digest != delivered_reference.delivery_ack_digest
            or intent.delivered_source_reference_digest
            != delivered_reference.source_reference_digest
        ):
            raise EpisodicMemoryError("profile_state_delivery_binding_mismatch")
        binding = delivered[0].draft.time_binding
        if (
            binding.status != "exact"
            or binding.delivered_at_utc is None
            or intent.trusted_time_digest != binding.binding_digest
            or intent.delivered_at_utc
            != binding.delivered_at_utc.isoformat(timespec="microseconds").replace(
                "+00:00", "Z"
            )
        ):
            raise EpisodicMemoryError("profile_state_trusted_time_mismatch")
        if intent.reason_category != "episode_end":
            return
        episode = next(
            (
                item
                for item in temporal_snapshot.episodes
                if item.interval_id == intent.p08_interval_id
            ),
            None,
        )
        if episode is None or not episode.revisions:
            raise EpisodicMemoryError("profile_state_terminal_source_mismatch")
        terminal = episode.revisions[-1]
        expected_revision_id = "p08-terminal-" + terminal.revision_digest[:48]
        source_sequence = terminal.source_turn_sequences[-1]
        source_reference = next(
            (
                item
                for item in snapshot.source_references
                if item.sequence == source_sequence
            ),
            None,
        )
        temporal_binding_present = False
        if source_reference is not None:
            temporal_binding_present = any(
                interval_id == episode.interval_id
                and revision_number == terminal.p08_revision
                and revision_digest == terminal.revision_digest
                and episode_digest == episode.episode_digest
                for interval_id, revision_number, revision_digest, episode_digest in zip(
                    source_reference.temporal_interval_ids,
                    source_reference.temporal_revision_numbers,
                    source_reference.temporal_revision_digests,
                    source_reference.temporal_episode_digests,
                    strict=True,
                )
            )
        if (
            (episode.terminal_state, terminal.p08_event_kind)
            not in {("ended", "expire"), ("cancelled", "revoke")}
            or intent.episode_revision_id != expected_revision_id
            or intent.p08_episode_id != episode.episode_digest
            or intent.p08_interval_id != episode.interval_id
            or intent.p08_terminal_revision != terminal.revision
            or intent.p08_terminal_revision_digest != terminal.revision_digest
            or intent.p08_terminal_event_sequence != terminal.p08_event_sequence
            or intent.p08_terminal_event_kind != terminal.p08_event_kind
            or source_reference is None
            or intent.p08_source_reference_digest
            != source_reference.source_reference_digest
            or source_sequence > delivered_reference.sequence
            or not temporal_binding_present
        ):
            raise EpisodicMemoryError("profile_state_terminal_source_mismatch")

    @staticmethod
    def _profile_manifest(field_id: str) -> ProfileModuleManifest:
        for manifest in profile_v2_manifests():
            if manifest.field_id == field_id:
                return manifest
        raise EpisodicMemoryError("profile_state_manifest_unknown")

    def current_profile_values(self) -> tuple[ProfileCurrentValue, ...]:
        connection = self._connect()
        try:
            self._verify_connection_schema(connection)
            return self._profile_state_records(connection)[1]
        except (OwnerProfileError, EpisodicMemoryError):
            raise
        except (sqlite3.Error, TypeError, ValueError) as exc:
            raise EpisodicMemoryError("profile_state_unavailable") from exc
        finally:
            connection.close()

    def current_profile_proposal(
        self,
        proposal_id: str,
        proposal_version: int,
    ) -> ProfileStateEvent:
        connection = self._connect()
        try:
            self._verify_connection_schema(connection)
            events, _currents = self._profile_state_records(connection)
            proposals = tuple(
                item
                for item in events
                if item.action == "propose_manifest"
                and item.proposal_id == proposal_id
                and item.proposal_version == proposal_version
            )
            terminals = tuple(
                item
                for item in events
                if item.action in {"confirm_manifest", "cancel_manifest"}
                and item.proposal_id == proposal_id
                and item.proposal_version == proposal_version
            )
            if len(proposals) != 1 or terminals:
                raise EpisodicMemoryError("profile_state_proposal_unavailable")
            return proposals[0]
        except (OwnerProfileError, EpisodicMemoryError):
            raise
        except sqlite3.Error as exc:
            raise EpisodicMemoryError("profile_state_unavailable") from exc
        finally:
            connection.close()

    def profile_rollback_target(
        self,
        field_id: str,
        requested_value: int,
    ) -> ProfileStateEvent:
        connection = self._connect()
        try:
            self._verify_connection_schema(connection)
            events, currents = self._profile_state_records(connection)
            current = next(
                (item for item in currents if item.field_id == field_id),
                None,
            )
            candidates = tuple(
                item
                for item in events
                if item.field_id == field_id
                and current is not None
                and item.sequence < current.last_sequence
                and item.current_value == requested_value
            )
            if not candidates:
                raise EpisodicMemoryError("profile_state_rollback_target_unavailable")
            return candidates[-1]
        except (OwnerProfileError, EpisodicMemoryError):
            raise
        except sqlite3.Error as exc:
            raise EpisodicMemoryError("profile_state_unavailable") from exc
        finally:
            connection.close()

    def append_profile_state_intent(
        self,
        intent: ProfileStateIntent,
    ) -> ProfileStateReceipt:
        manifest = self._profile_manifest(intent.field_id)
        if intent.module_id != manifest.module_id:
            raise EpisodicMemoryError("profile_state_manifest_mismatch")
        try:
            manifest.require_action_policy(
                actor=intent.actor,
                action=intent.action,
                reason_category=intent.reason_category,
            )
        except OwnerProfileError as exc:
            raise EpisodicMemoryError(exc.code) from exc
        if (
            intent.action == "delta"
            and intent.actor == "myuna"
            and manifest.ordinary_delta_limit is not None
            and abs(intent.requested_delta or 0) > manifest.ordinary_delta_limit
        ):
            raise EpisodicMemoryError("profile_state_delta_limit_rejected")
        self._verify_profile_source(intent)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._verify_profile_source(intent)
            self._verify_all_records(connection)
            events, currents = self._profile_state_records(connection)
            existing = next(
                (item for item in events if item.intent_digest == intent.intent_digest),
                None,
            )
            if existing is not None:
                relevant = tuple(
                    item
                    for item in events
                    if item.field_id == existing.field_id
                    and item.sequence <= existing.sequence
                )
                original = rebuild_profile_current(manifest, relevant)
                connection.execute("COMMIT")
                return ProfileStateReceipt(
                    outcome="committed",
                    replayed=True,
                    mutated=False,
                    event_id=existing.event_id,
                    event_digest=existing.event_digest,
                    projection_digest=original.projection_digest,
                    reason_category=intent.reason_category,
                )
            if any(item.event_id == intent.intent_id for item in events):
                raise EpisodicMemoryError("profile_state_intent_conflict")
            if intent.episode_revision_id is not None and any(
                item.episode_revision_id == intent.episode_revision_id
                for item in events
            ):
                raise EpisodicMemoryError("profile_state_episode_replay_conflict")
            current = next(
                (item for item in currents if item.field_id == intent.field_id),
                None,
            )
            if current is None:
                raise EpisodicMemoryError("profile_state_projection_missing")
            prior_event = next(
                (
                    item
                    for item in reversed(events)
                    if item.field_id == intent.field_id
                    and item.sequence == current.last_sequence
                ),
                None,
            )
            rollback_target = None
            if intent.action == "rollback":
                matches = tuple(
                    item
                    for item in events
                    if item.event_id == intent.rollback_target_event_id
                    and item.event_digest == intent.rollback_target_event_digest
                    and item.field_id == intent.field_id
                    and item.sequence < current.last_sequence
                    and item.current_value == intent.requested_value
                )
                if len(matches) != 1:
                    raise EpisodicMemoryError("profile_state_rollback_target_mismatch")
                rollback_target = matches[0]
            event, updated, receipt = evaluate_profile_state_transition(
                manifest,
                current,
                intent,
                prior_event=prior_event,
                rollback_target=rollback_target,
            )
            if event is None:
                connection.execute("COMMIT")
                return receipt
            event_json = profile_state_canonical_bytes(event.payload()).decode("ascii")
            current_json = profile_state_canonical_bytes(updated.payload()).decode(
                "ascii"
            )
            connection.execute(
                "INSERT INTO profile_state_events VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    event.sequence,
                    event.event_id,
                    event.intent_digest,
                    event.event_digest,
                    event.module_id,
                    event.field_id,
                    event_json,
                ),
            )
            connection.execute(
                "UPDATE profile_current_projection SET state = ?, scaled_value = ?, "
                "last_sequence = ?, last_event_id = ?, last_event_digest = ?, "
                "manifest_digest = ?, projection_digest = ?, payload_json = ? "
                "WHERE module_id = ? AND field_id = ?",
                (
                    updated.state,
                    updated.scaled_value,
                    updated.last_sequence,
                    updated.last_event_id,
                    updated.last_event_digest,
                    updated.manifest_digest,
                    updated.projection_digest,
                    current_json,
                    updated.module_id,
                    updated.field_id,
                ),
            )
            if connection.execute("SELECT changes()").fetchone()[0] != 1:
                raise EpisodicMemoryError("profile_state_projection_missing")
            persisted_events, persisted_currents = self._profile_state_records(connection)
            if (
                event not in persisted_events
                or updated not in persisted_currents
            ):
                raise EpisodicMemoryError("profile_state_write_unconfirmed")
            connection.execute("COMMIT")
            return receipt
        except (OwnerProfileError, EpisodicMemoryError):
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.IntegrityError as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise EpisodicMemoryError("profile_state_conflict") from exc
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise EpisodicMemoryError(
                "profile_state_write_failed", retryable=True
            ) from exc
        finally:
            connection.close()

    def rebuild_profile_current_values(self) -> tuple[ProfileCurrentValue, ...]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._verify_connection_schema(connection)
            events = self._profile_event_records(connection)
            manifests = profile_v2_manifests()
            rebuilt = tuple(
                rebuild_profile_current(
                    manifest,
                    tuple(item for item in events if item.field_id == manifest.field_id),
                )
                for manifest in manifests
            )
            try:
                currents = self._profile_state_records(connection)[1]
            except EpisodicMemoryError as exc:
                if exc.code != "profile_state_projection_drifted":
                    raise
                currents = ()
            if rebuilt == currents:
                connection.execute("COMMIT")
                return rebuilt
            connection.execute("DELETE FROM profile_current_projection")
            for current in rebuilt:
                connection.execute(
                    "INSERT INTO profile_current_projection VALUES "
                    "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        current.module_id,
                        current.field_id,
                        current.state,
                        current.scaled_value,
                        current.last_sequence,
                        current.last_event_id,
                        current.last_event_digest,
                        current.manifest_digest,
                        current.projection_digest,
                        profile_state_canonical_bytes(current.payload()).decode("ascii"),
                    ),
                )
            if self._profile_state_records(connection)[1] != rebuilt:
                raise EpisodicMemoryError("profile_state_rebuild_unconfirmed")
            connection.execute("COMMIT")
            return rebuilt
        except (OwnerProfileError, EpisodicMemoryError):
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise EpisodicMemoryError("profile_state_rebuild_failed") from exc
        finally:
            connection.close()

    def append_reflective_revision(
        self,
        *,
        entry: ReflectiveDiaryEntry,
        turns: Sequence[CompleteTurn],
        source_snapshot: EpisodicIndexSnapshot,
        source_manifest: Mapping[str, object],
        source_manifest_digest: str,
        effective_time_bindings: Mapping[int, TurnTimeBinding] | None = None,
    ) -> str:
        verify_diary_sources(
            entry,
            turns,
            effective_time_bindings=effective_time_bindings,
        )
        _verify_snapshot_turns(source_snapshot, turns)
        _verify_source_manifest(
            source_manifest,
            source_manifest_digest,
            source_sequences=entry.source_sequences,
            source_turn_digests=entry.source_turn_digests,
            source_snapshot=source_snapshot,
        )
        self._verify_current_source_binding(
            submitted_snapshot=source_snapshot,
            turns=turns,
            source_manifest=source_manifest,
            source_manifest_digest=source_manifest_digest,
            source_sequences=entry.source_sequences,
            source_turn_digests=entry.source_turn_digests,
        )
        by_sequence = {turn.draft.sequence: turn for turn in turns}
        if tuple(source_manifest["source_release_set_ids"]) != tuple(
            by_sequence[sequence].draft.release_set_id
            for sequence in entry.source_sequences
        ) or any(
            by_sequence[sequence].draft.release_set_id != entry.release_set_id
            for sequence in entry.source_sequences
        ):
            raise EpisodicMemoryError("diary_source_release_mismatch")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._verify_all_records(connection)
            existing = connection.execute(
                "SELECT entry_digest, source_manifest_digest FROM diary_entries "
                "WHERE day_key = ? AND calendar_zone = ? AND revision = ?",
                (entry.day.isoformat(), entry.calendar_zone, entry.revision),
            ).fetchone()
            if existing is not None:
                if (
                    existing["entry_digest"] == entry.entry_digest
                    and existing["source_manifest_digest"] == source_manifest_digest
                ):
                    connection.execute("COMMIT")
                    return entry.entry_digest
                raise EpisodicMemoryError("diary_revision_conflict")
            latest = connection.execute(
                "SELECT MAX(revision) FROM diary_entries WHERE day_key = ? AND calendar_zone = ?",
                (entry.day.isoformat(), entry.calendar_zone),
            ).fetchone()[0]
            expected_revision = (0 if latest is None else latest) + 1
            if (
                entry.revision != expected_revision
                or entry.supersedes_revision
                != (None if expected_revision == 1 else expected_revision - 1)
            ):
                raise EpisodicMemoryError("diary_revision_gap")
            connection.execute(
                "INSERT INTO diary_entries VALUES (?, ?, ?, ?, ?, ?)",
                (
                    entry.day.isoformat(),
                    entry.calendar_zone,
                    entry.revision,
                    entry.entry_digest,
                    source_manifest_digest,
                    canonical_bytes(
                        {
                            "entry": entry.payload(),
                            "source_manifest": dict(source_manifest),
                        }
                    ).decode("utf-8"),
                ),
            )
            connection.execute("COMMIT")
            return entry.entry_digest
        except EpisodicMemoryError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.IntegrityError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise EpisodicMemoryError("diary_duplicate_or_replay") from None
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise EpisodicMemoryError("diary_write_failed", retryable=True) from exc
        finally:
            connection.close()

    def job_events(self) -> tuple[DiaryJobEvent, ...]:
        raise EpisodicMemoryError("diary_job_queue_retired")

    def append_owner_day_revision(
        self,
        *,
        revision: object,
        turns: Sequence[CompleteTurn],
        source_snapshot: EpisodicIndexSnapshot,
        source_manifest: Mapping[str, object],
        source_manifest_digest: str,
    ) -> str:
        from .owner_day_generation import OwnerDayDiaryRevision

        if not isinstance(revision, OwnerDayDiaryRevision):
            raise EpisodicMemoryError("owner_day_revision_type_rejected")
        if (
            tuple(turn.draft.sequence for turn in turns)
            != revision.source_sequences
            or tuple(turn.turn_digest for turn in turns)
            != revision.source_turn_digests
        ):
            raise EpisodicMemoryError("owner_day_source_snapshot_mismatch")
        references = _verify_snapshot_turns(source_snapshot, turns)
        _verify_source_manifest(
            source_manifest,
            source_manifest_digest,
            source_sequences=revision.source_sequences,
            source_turn_digests=revision.source_turn_digests,
            source_snapshot=source_snapshot,
        )
        self._verify_current_source_binding(
            submitted_snapshot=source_snapshot,
            turns=turns,
            source_manifest=source_manifest,
            source_manifest_digest=source_manifest_digest,
            source_sequences=revision.source_sequences,
            source_turn_digests=revision.source_turn_digests,
        )
        selected = tuple(references[sequence] for sequence in revision.source_sequences)
        if any(
            reference.owner_day != revision.owner_day
            or reference.calendar_zone != revision.calendar_zone
            or reference.owner_day_policy_digest != revision.policy_digest
            or reference.release_set_id != revision.memory_release_set_id
            for reference in selected
        ):
            raise EpisodicMemoryError("owner_day_source_snapshot_mismatch")
        if any(
            value != revision.memory_release_set_id
            for value in source_manifest["source_release_set_ids"]
        ):
            raise EpisodicMemoryError("owner_day_source_release_mismatch")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._verify_all_records(connection)
            existing = connection.execute(
                "SELECT revision_digest, source_manifest_digest "
                "FROM owner_day_revisions "
                "WHERE owner_day = ? AND calendar_zone = ? AND revision = ?",
                (revision.owner_day, revision.calendar_zone, revision.revision),
            ).fetchone()
            if existing is not None:
                if (
                    existing["revision_digest"] == revision.revision_digest
                    and existing["source_manifest_digest"] == source_manifest_digest
                ):
                    connection.execute("COMMIT")
                    return revision.revision_digest
                raise EpisodicMemoryError("owner_day_revision_conflict")
            latest = connection.execute(
                "SELECT MAX(revision) FROM owner_day_revisions "
                "WHERE owner_day = ? AND calendar_zone = ?",
                (revision.owner_day, revision.calendar_zone),
            ).fetchone()[0]
            expected_revision = (0 if latest is None else latest) + 1
            expected_parent = None if expected_revision == 1 else expected_revision - 1
            if (
                revision.revision != expected_revision
                or revision.supersedes_revision != expected_parent
            ):
                raise EpisodicMemoryError("owner_day_revision_chain_gap")
            connection.execute(
                "INSERT INTO owner_day_revisions VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    revision.owner_day,
                    revision.calendar_zone,
                    revision.revision,
                    revision.purpose,
                    revision.revision_digest,
                    source_manifest_digest,
                    canonical_bytes(
                        {
                            "revision": revision.as_payload(),
                            "source_manifest": dict(source_manifest),
                        }
                    ).decode("utf-8"),
                ),
            )
            connection.execute("COMMIT")
            return revision.revision_digest
        except EpisodicMemoryError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.IntegrityError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise EpisodicMemoryError("owner_day_revision_duplicate") from None
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise EpisodicMemoryError("diary_write_failed", retryable=True) from exc
        finally:
            connection.close()

    def reflective_revisions(self) -> tuple[ReflectiveDiaryEntry, ...]:
        connection = self._connect()
        try:
            self._verify_connection_schema(connection)
            return tuple(item[0] for item in self._reflective_records(connection))
        except EpisodicMemoryError:
            raise
        except (sqlite3.Error, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise EpisodicMemoryError("diary_metadata_unavailable") from exc
        finally:
            connection.close()

    def owner_day_revisions(self) -> tuple[OwnerDayDiaryRevision, ...]:
        connection = self._connect()
        try:
            self._verify_connection_schema(connection)
            return tuple(item[0] for item in self._owner_day_records(connection))
        except EpisodicMemoryError:
            raise
        except (sqlite3.Error, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise EpisodicMemoryError("diary_metadata_unavailable") from exc
        finally:
            connection.close()

    def append_prefix_capsule(
        self,
        capsule: PrefixCapsule,
        *,
        source_snapshot: EpisodicIndexSnapshot,
        verification_receipt: tuple[PrefixCapsule, str],
        token_counter: Callable[[tuple[Mapping[str, str], ...]], int] | None,
    ) -> str:
        policy = PrefixCompactionPolicy.balanced_default()
        try:
            submitted_payload = capsule.payload()
            capsule = PrefixCapsule.from_payload(submitted_payload)
            if canonical_bytes(submitted_payload) != canonical_bytes(capsule.payload()):
                raise EpisodicMemoryError(
                    "prefix_capsule_primitive_type_invalid"
                )
        except EpisodicMemoryError:
            raise
        except (AttributeError, TypeError, UnicodeError, ValueError):
            raise EpisodicMemoryError(
                "prefix_capsule_primitive_type_invalid"
            ) from None
        if (
            capsule.policy_version != policy.policy_version
            or capsule.policy_digest != policy.policy_digest
            or capsule.token_oracle_id != policy.token_oracle_id
            or capsule.risk_class not in policy.permitted_risk_classes
            or not capsule.projection_eligible
            or capsule.source_end > policy.maximum_source_turns
            or capsule.capsule_characters > policy.maximum_capsule_characters
            or capsule.capsule_bytes > policy.maximum_capsule_bytes
            or capsule.capsule_tokens > policy.maximum_capsule_tokens
            or capsule.character_ratio_milli > policy.hard_character_ratio * 1_000
            or capsule.byte_ratio_milli > policy.hard_byte_ratio * 1_000
            or capsule.token_ratio_milli > policy.hard_token_ratio * 1_000
        ):
            raise EpisodicMemoryError("prefix_capsule_policy_binding_mismatch")
        if (
            type(verification_receipt) is not tuple
            or len(verification_receipt) != 2
            or type(verification_receipt[0]) is not PrefixCapsule
            or type(verification_receipt[1]) is not str
        ):
            raise EpisodicMemoryError("prefix_verification_receipt_invalid")
        verified_capsule, verified_source_closure = verification_receipt
        require_digest(verified_source_closure, "prefix_verified_source_closure")
        current_snapshot, current_turns, current_temporal_snapshot = (
            self._load_current_source_authority()
        )
        if current_snapshot != source_snapshot:
            raise EpisodicMemoryError("prefix_capsule_source_snapshot_mismatch")
        authoritative_receipt = verify_prefix_capsule(
            capsule,
            turns=current_turns,
            archive_id=current_snapshot.archive_id,
            archive_head_digest=current_snapshot.archive_head_digest,
            policy=policy,
            token_counter=token_counter,
            expected_generator_version=capsule.generator_version,
            expected_model_provider_class=capsule.model_provider_class,
            expected_created_at_utc=capsule.created_at_utc,
        )
        canonical_capsule, authoritative_source_closure = authoritative_receipt
        reverified_receipt = verify_prefix_capsule(
            verified_capsule,
            turns=current_turns,
            archive_id=current_snapshot.archive_id,
            archive_head_digest=current_snapshot.archive_head_digest,
            policy=policy,
            token_counter=token_counter,
            expected_generator_version=canonical_capsule.generator_version,
            expected_model_provider_class=canonical_capsule.model_provider_class,
            expected_created_at_utc=canonical_capsule.created_at_utc,
        )
        if (
            reverified_receipt != authoritative_receipt
            or verified_source_closure != authoritative_source_closure
        ):
            raise EpisodicMemoryError("prefix_verification_capsule_mismatch")
        capsule = canonical_capsule
        references = current_snapshot.source_references[
            capsule.source_start - 1 : capsule.source_end
        ]
        if (
            current_snapshot.archive_id != capsule.archive_id
            or current_snapshot.archive_turn_count
            != capsule.source_snapshot_turn_count
            or current_snapshot.archive_head_digest
            != capsule.source_snapshot_head_digest
            or tuple(item.sequence for item in references)
            != tuple(range(capsule.source_start, capsule.source_end + 1))
            or tuple(item.turn_id for item in references)
            != capsule.source_turn_ids
            or tuple(item.turn_digest for item in references)
            != capsule.source_turn_digests
            or tuple(item.calendar_zone for item in references)
            != capsule.source_original_zones
            or any(item.epoch_id != capsule.epoch_id for item in references)
            or not references
            or references[0].effective_delivered_at_utc
            != capsule.source_time_start_utc.isoformat(timespec="microseconds")
            or references[-1].effective_delivered_at_utc
            != capsule.source_time_end_utc.isoformat(timespec="microseconds")
        ):
            raise EpisodicMemoryError("prefix_capsule_source_binding_mismatch")
        expected_source_closure = prefix_capsule_source_closure_digest(
            archive_id=current_snapshot.archive_id,
            archive_head_digest=current_snapshot.archive_head_digest,
            archive_turn_count=current_snapshot.archive_turn_count,
            source_end=capsule.source_end,
            source_turn_ids=tuple(item.turn_id for item in references),
            source_turn_digests=tuple(item.turn_digest for item in references),
            eligible_source_turn_ids=tuple(
                item.turn_id for item in references if item.model_history_eligible
            ),
        )
        if authoritative_source_closure != expected_source_closure:
            raise EpisodicMemoryError("prefix_verification_source_mismatch")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            transaction_snapshot, transaction_turns, transaction_temporal_snapshot = (
                self._load_current_source_authority()
            )
            if (
                transaction_snapshot != current_snapshot
                or transaction_turns != current_turns
                or transaction_temporal_snapshot != current_temporal_snapshot
            ):
                raise EpisodicMemoryError(
                    "prefix_capsule_source_snapshot_mismatch"
                )
            transaction_receipt = verify_prefix_capsule(
                capsule,
                turns=transaction_turns,
                archive_id=transaction_snapshot.archive_id,
                archive_head_digest=transaction_snapshot.archive_head_digest,
                policy=policy,
                token_counter=token_counter,
                expected_generator_version=capsule.generator_version,
                expected_model_provider_class=capsule.model_provider_class,
                expected_created_at_utc=capsule.created_at_utc,
            )
            if transaction_receipt != authoritative_receipt:
                raise EpisodicMemoryError("prefix_verification_source_mismatch")
            transaction_capsule = transaction_receipt[0]
            payload_json = canonical_bytes(transaction_capsule.payload()).decode(
                "utf-8"
            )
            reconstructed_capsule = _prefix_capsule_from_json(payload_json)
            if (
                reconstructed_capsule != transaction_capsule
                or reconstructed_capsule.capsule_digest
                != transaction_capsule.capsule_digest
            ):
                raise EpisodicMemoryError("prefix_capsule_payload_noncanonical")
            capsule = transaction_capsule
            self._verify_all_records(connection)
            existing = connection.execute(
                "SELECT capsule_digest FROM prefix_capsule_revisions "
                "WHERE capsule_id = ? AND revision = ?",
                (capsule.capsule_id, capsule.revision),
            ).fetchone()
            if existing is not None:
                if existing["capsule_digest"] == capsule.capsule_digest:
                    connection.execute("COMMIT")
                    return capsule.capsule_digest
                raise EpisodicMemoryError("prefix_capsule_revision_conflict")
            latest = connection.execute(
                "SELECT revision, capsule_digest, payload_json "
                "FROM prefix_capsule_revisions "
                "WHERE capsule_id = ? ORDER BY revision DESC LIMIT 1",
                (capsule.capsule_id,),
            ).fetchone()
            expected_revision = 1 if latest is None else latest["revision"] + 1
            expected_parent = "0" * 64 if latest is None else latest["capsule_digest"]
            if (
                capsule.revision != expected_revision
                or capsule.parent_capsule_digest != expected_parent
            ):
                raise EpisodicMemoryError("prefix_capsule_revision_gap")
            if latest is not None:
                prior = _prefix_capsule_from_json(latest["payload_json"])
                if (
                    capsule.source_snapshot_head_digest
                    == prior.source_snapshot_head_digest
                    and capsule.policy_digest == prior.policy_digest
                    and capsule.generator_version == prior.generator_version
                    and capsule.model_provider_class == prior.model_provider_class
                    and capsule.token_oracle_id == prior.token_oracle_id
                ):
                    raise EpisodicMemoryError(
                        "prefix_capsule_regeneration_conflict"
                    )
            connection.execute(
                "INSERT INTO prefix_capsule_revisions VALUES (?, ?, ?, ?, ?, ?)",
                (
                    capsule.capsule_id,
                    capsule.revision,
                    capsule.capsule_digest,
                    capsule.parent_capsule_digest,
                    capsule.source_end,
                    payload_json,
                ),
            )
            persisted_capsules = self._prefix_capsule_records(connection)
            if not any(
                item.capsule_id == capsule.capsule_id
                and item.revision == capsule.revision
                and item.capsule_digest == capsule.capsule_digest
                for item in persisted_capsules
            ):
                raise EpisodicMemoryError("prefix_capsule_write_unconfirmed")
            connection.execute("COMMIT")
            return capsule.capsule_digest
        except EpisodicMemoryError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.IntegrityError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise EpisodicMemoryError("prefix_capsule_duplicate") from None
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise EpisodicMemoryError(
                "prefix_capsule_write_failed", retryable=True
            ) from exc
        finally:
            connection.close()

    def prefix_capsules(self) -> tuple[PrefixCapsule, ...]:
        connection = self._connect()
        try:
            self._verify_connection_schema(connection)
            return self._prefix_capsule_records(connection)
        except EpisodicMemoryError:
            raise
        except (sqlite3.Error, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise EpisodicMemoryError("diary_metadata_unavailable") from exc
        finally:
            connection.close()

    def current_reflective_revisions(self) -> tuple[ReflectiveDiaryEntry, ...]:
        selected: dict[tuple[date, str], ReflectiveDiaryEntry] = {}
        for entry in self.reflective_revisions():
            selected[(entry.day, entry.calendar_zone)] = entry
        return tuple(selected[key] for key in sorted(selected))

    def current_owner_day_revisions(self) -> tuple[OwnerDayDiaryRevision, ...]:
        from .owner_day_generation import OwnerDayDiaryRevision

        selected: dict[tuple[str, str], OwnerDayDiaryRevision] = {}
        for revision in self.owner_day_revisions():
            selected[(revision.owner_day, revision.calendar_zone)] = revision
        return tuple(selected[key] for key in sorted(selected))

    def verify_source_closure(self, snapshot: object) -> dict[str, object]:
        from .index import EpisodicIndexSnapshot

        if not isinstance(snapshot, EpisodicIndexSnapshot):
            raise EpisodicMemoryError("diary_source_snapshot_rejected")
        connection = self._connect()
        try:
            self._verify_connection_schema(connection)
            reflective = self._reflective_records(connection)
            owner_day = self._owner_day_records(connection)
            for revision, manifest, manifest_digest in reflective + owner_day:
                expected, expected_digest = snapshot.source_manifest(
                    revision.source_sequences
                )
                if manifest != expected or manifest_digest != expected_digest:
                    raise EpisodicMemoryError("diary_source_closure_conflict")
            return {
                "owner_day_revision_count": len(owner_day),
                "owner_day_state": (
                    "available" if owner_day else "unavailable"
                ),
                "reflective_revision_count": len(reflective),
                "reflective_state": (
                    "available" if reflective else "unavailable"
                ),
                "snapshot_digest": snapshot.snapshot_digest,
                "source_closure_digest": snapshot.source_closure_digest,
            }
        except EpisodicMemoryError:
            raise
        except (sqlite3.Error, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise EpisodicMemoryError("diary_metadata_unavailable") from exc
        finally:
            connection.close()

    def latest_revision(self, day: date, calendar_zone: str) -> int:
        if calendar_zone not in SUPPORTED_CALENDAR_ZONES:
            raise EpisodicMemoryError("diary_calendar_zone_unsupported")
        connection = self._connect()
        try:
            self._verify_connection_schema(connection)
            value = connection.execute(
                "SELECT MAX(revision) FROM diary_entries WHERE day_key = ? AND calendar_zone = ?",
                (day.isoformat(), calendar_zone),
            ).fetchone()[0]
            return 0 if value is None else int(value)
        except (sqlite3.Error, TypeError, ValueError) as exc:
            raise EpisodicMemoryError("diary_metadata_unavailable") from exc
        finally:
            connection.close()

    def audit_projection(self) -> dict[str, object]:
        connection = self._connect()
        try:
            self._verify_connection_schema(connection)
            reflective_records = self._reflective_records(connection)
            owner_day_records = self._owner_day_records(connection)
            prefix_capsules = self._prefix_capsule_records(connection)
            chain_digest = semantic_digest(
                "myuna-p07-derivative-diary-chain-v5",
                {
                    "owner_day_revisions": [
                        [item.revision_digest, manifest_digest]
                        for item, _manifest, manifest_digest in owner_day_records
                    ],
                    "reflective_revisions": [
                        [item.entry_digest, manifest_digest]
                        for item, _manifest, manifest_digest in reflective_records
                    ],
                    "prefix_capsules": [
                        item.capsule_digest for item in prefix_capsules
                    ],
                },
            )
            return {
                "chain_digest": chain_digest,
                "job_queue_active": False,
                "owner_day_revision_count": len(owner_day_records),
                "owner_day_state": (
                    "available" if owner_day_records else "unavailable"
                ),
                "provider_capable": False,
                "prefix_capsule_count": len(prefix_capsules),
                "reflective_revision_count": len(reflective_records),
                "reflective_state": (
                    "available" if reflective_records else "unavailable"
                ),
                "schema": DIARY_SCHEMA,
            }
        except sqlite3.Error as exc:
            raise EpisodicMemoryError("diary_metadata_unavailable") from exc
        finally:
            connection.close()


@dataclass(frozen=True, slots=True)
class DiaryRecallPlan:
    entry_digests: tuple[str, ...]
    source_sequences: tuple[int, ...]
    perspective_available: bool
    raw_hydration_required: bool
    state: str
    reason_category: str | None

    def __post_init__(self) -> None:
        if self.state not in {"available", "unavailable"}:
            raise EpisodicMemoryError("diary_recall_state_unknown")
        if (self.state == "available") != self.perspective_available:
            raise EpisodicMemoryError("diary_recall_state_conflict")
        if self.state == "available" and self.reason_category is not None:
            raise EpisodicMemoryError("diary_recall_reason_rejected")
        if self.state == "unavailable" and self.reason_category != "authored_revision_absent":
            raise EpisodicMemoryError("diary_recall_reason_unknown")

    def audit_projection(self) -> dict[str, object]:
        return {
            "entry_count": len(self.entry_digests),
            "entry_digests": list(self.entry_digests),
            "perspective_available": self.perspective_available,
            "raw_hydration_required": self.raw_hydration_required,
            "reason_category": self.reason_category,
            "source_sequences": list(self.source_sequences),
            "state": self.state,
        }


def plan_diary_recall(
    entries: Sequence[ReflectiveDiaryEntry],
    *,
    exact_factual_detail_requested: bool,
) -> DiaryRecallPlan:
    selected = tuple(entries)
    source_sequences = tuple(
        sorted(
            {
                sequence
                for entry in selected
                for statement in entry.statements
                for sequence in statement.source_sequences
            }
        )
    )
    return DiaryRecallPlan(
        entry_digests=tuple(entry.entry_digest for entry in selected),
        source_sequences=source_sequences,
        perspective_available=bool(selected),
        raw_hydration_required=bool(selected) or exact_factual_detail_requested,
        state="available" if selected else "unavailable",
        reason_category=None if selected else "authored_revision_absent",
    )
