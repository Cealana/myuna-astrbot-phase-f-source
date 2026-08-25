"""Versioned Owner-day and reflective-diary v2 source contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from typing import Mapping, Sequence
from zoneinfo import ZoneInfo

from myuna_core.active_temporal_context.contracts import TemporalContextError
from myuna_core.active_temporal_context.time import TrustedTimeSample

from .contracts import (
    OWNER_DAY_DIARY_STYLE_V2_DIGEST,
    OWNER_DAY_PREVIEW_EGRESS_V1_DIGEST,
    REFLECTIVE_DIARY_EGRESS_V1_DIGEST,
    SUPPORTED_CALENDAR_ZONES,
    CompleteTurn,
    EpisodicMemoryError,
    TurnTimeBinding,
    require_digest,
    require_id,
    semantic_digest,
)


OWNER_DAY_POLICY_SCHEMA = "myuna.p07-owner-day-policy.v2"
OWNER_DAY_DIARY_JOB_SCHEMA = "myuna.p07-owner-day-diary-job.v2"
OWNER_DAY_PREVIEW_PURPOSE = "owner_day_as_of_preview"
OWNER_DAY_FINAL_PURPOSE = "owner_day_final"
OWNER_DAY_SOFT_CLOSE_PURPOSE = "owner_day_soft_close"
OWNER_DAY_ADDENDUM_PURPOSE = "owner_day_addendum"
OWNER_DAY_PURPOSES = frozenset(
    {
        OWNER_DAY_PREVIEW_PURPOSE,
        OWNER_DAY_FINAL_PURPOSE,
        OWNER_DAY_SOFT_CLOSE_PURPOSE,
        OWNER_DAY_ADDENDUM_PURPOSE,
    }
)
OWNER_DAY_DIARY_MODEL = "deepseek-v4-flash"
OWNER_DAY_DIARY_MODEL_ROLE = "p07_external_owner_day_reflective_diary_v2"
DEFAULT_OWNER_DAY_ZONE = "Asia/Shanghai"
DEFAULT_OWNER_DAY_BOUNDARY = "06:00"
DEFAULT_SOFT_CLOSE_GRACE_SECONDS = 120 * 60


def _parse_boundary(value: str) -> time:
    if not isinstance(value, str) or len(value) != 5 or value[2] != ":":
        raise EpisodicMemoryError("owner_day_boundary_rejected")
    try:
        hour, minute = int(value[:2]), int(value[3:])
    except ValueError:
        raise EpisodicMemoryError("owner_day_boundary_rejected") from None
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise EpisodicMemoryError("owner_day_boundary_rejected")
    return time(hour, minute)


@dataclass(frozen=True, slots=True)
class OwnerDayPolicy:
    calendar_zone: str = DEFAULT_OWNER_DAY_ZONE
    boundary_local_time: str = DEFAULT_OWNER_DAY_BOUNDARY
    soft_close_grace_seconds: int = DEFAULT_SOFT_CLOSE_GRACE_SECONDS
    schema: str = OWNER_DAY_POLICY_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != OWNER_DAY_POLICY_SCHEMA:
            raise EpisodicMemoryError("owner_day_policy_schema_rejected")
        if self.calendar_zone not in SUPPORTED_CALENDAR_ZONES:
            raise EpisodicMemoryError("owner_day_zone_rejected")
        _parse_boundary(self.boundary_local_time)
        if (
            isinstance(self.soft_close_grace_seconds, bool)
            or not isinstance(self.soft_close_grace_seconds, int)
            or not 60 <= self.soft_close_grace_seconds <= 24 * 60 * 60
        ):
            raise EpisodicMemoryError("owner_day_grace_rejected")

    def payload(self) -> dict[str, object]:
        return {
            "boundary_local_time": self.boundary_local_time,
            "calendar_zone": self.calendar_zone,
            "schema": self.schema,
            "soft_close_grace_seconds": self.soft_close_grace_seconds,
        }

    @property
    def policy_digest(self) -> str:
        return semantic_digest("myuna-p07-owner-day-policy-v2", self.payload())

    def as_payload(self) -> dict[str, object]:
        return self.payload() | {"policy_digest": self.policy_digest}

    @classmethod
    def from_payload(cls, payload: object) -> "OwnerDayPolicy":
        required = {
            "boundary_local_time",
            "calendar_zone",
            "policy_digest",
            "schema",
            "soft_close_grace_seconds",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise EpisodicMemoryError("owner_day_policy_fields_rejected")
        result = cls(
            calendar_zone=payload["calendar_zone"],  # type: ignore[arg-type]
            boundary_local_time=payload["boundary_local_time"],  # type: ignore[arg-type]
            soft_close_grace_seconds=payload["soft_close_grace_seconds"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )
        if payload["policy_digest"] != result.policy_digest:
            raise EpisodicMemoryError("owner_day_policy_digest_mismatch")
        return result


@dataclass(frozen=True, slots=True)
class OwnerDayInterval:
    owner_day: date
    calendar_zone: str
    boundary_local_time: str
    start_utc: datetime
    end_utc: datetime
    policy_digest: str

    def __post_init__(self) -> None:
        if (
            self.start_utc.tzinfo is None
            or self.end_utc.tzinfo is None
            or self.start_utc.utcoffset() != timedelta(0)
            or self.end_utc.utcoffset() != timedelta(0)
            or self.end_utc <= self.start_utc
        ):
            raise EpisodicMemoryError("owner_day_interval_rejected")
        require_digest(self.policy_digest, "owner_day_policy")


def _exact_local_boundary(day: date, policy: OwnerDayPolicy) -> datetime:
    zone = ZoneInfo(policy.calendar_zone)
    naive = datetime.combine(day, _parse_boundary(policy.boundary_local_time))
    candidates: list[datetime] = []
    for fold in (0, 1):
        candidate = naive.replace(tzinfo=zone, fold=fold)
        roundtrip = candidate.astimezone(timezone.utc).astimezone(zone)
        if roundtrip.replace(tzinfo=None) == naive and roundtrip.fold == fold:
            candidates.append(candidate)
    distinct_offsets = {candidate.utcoffset() for candidate in candidates}
    if not candidates:
        raise EpisodicMemoryError("owner_day_boundary_nonexistent")
    if len(distinct_offsets) != 1:
        raise EpisodicMemoryError("owner_day_boundary_ambiguous")
    return candidates[0]


def owner_day_interval(day: date, policy: OwnerDayPolicy) -> OwnerDayInterval:
    if not isinstance(day, date):
        raise EpisodicMemoryError("owner_day_label_rejected")
    start = _exact_local_boundary(day, policy).astimezone(timezone.utc)
    end = _exact_local_boundary(day + timedelta(days=1), policy).astimezone(timezone.utc)
    return OwnerDayInterval(
        owner_day=day,
        calendar_zone=policy.calendar_zone,
        boundary_local_time=policy.boundary_local_time,
        start_utc=start,
        end_utc=end,
        policy_digest=policy.policy_digest,
    )


def owner_day_label(instant_utc: datetime, policy: OwnerDayPolicy) -> date:
    if instant_utc.tzinfo is None or instant_utc.utcoffset() != timedelta(0):
        raise EpisodicMemoryError("owner_day_instant_rejected")
    local = instant_utc.astimezone(ZoneInfo(policy.calendar_zone))
    boundary = _parse_boundary(policy.boundary_local_time)
    selected = (
        local.date()
        if local.timetz().replace(tzinfo=None) >= boundary
        else local.date() - timedelta(days=1)
    )
    owner_day_interval(selected, policy)
    return selected


@dataclass(frozen=True, slots=True)
class OwnerDayDiaryJob:
    purpose: str
    owner_day: date
    policy: OwnerDayPolicy
    source_turns: tuple[CompleteTurn, ...]
    source_time_bindings: tuple[TurnTimeBinding, ...]
    archive_head_digest: str
    source_watermark: int
    source_selection_digest: str
    target_revision: int
    supersedes_revision: int | None
    generation_time_sample: TrustedTimeSample
    memory_release_set_id: str
    parent_release_set_id: str
    policy_overlay_id: str
    archive_id: str
    persona_digest: str
    egress_policy_digest: str = REFLECTIVE_DIARY_EGRESS_V1_DIGEST
    style_contract_digest: str = OWNER_DAY_DIARY_STYLE_V2_DIGEST
    model: str = OWNER_DAY_DIARY_MODEL
    model_role: str = OWNER_DAY_DIARY_MODEL_ROLE
    schema: str = OWNER_DAY_DIARY_JOB_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != OWNER_DAY_DIARY_JOB_SCHEMA:
            raise EpisodicMemoryError("owner_day_diary_job_schema_rejected")
        if self.purpose not in OWNER_DAY_PURPOSES:
            raise EpisodicMemoryError("owner_day_diary_purpose_rejected")
        if not self.source_turns or len(self.source_turns) != len(self.source_time_bindings):
            raise EpisodicMemoryError("owner_day_diary_sources_empty")
        if (
            not self.generation_time_sample.evidence_complete
            or self.generation_time_sample.synchronized is not True
            or self.generation_time_sample.source_class
            not in {"trusted_local", "trusted_remote"}
            or self.generation_time_sample.uncertainty_microseconds is None
            or self.generation_time_sample.uncertainty_microseconds > 1_000_000
        ):
            raise EpisodicMemoryError("owner_day_generation_time_rejected")
        if (
            isinstance(self.source_watermark, bool)
            or not isinstance(self.source_watermark, int)
            or self.source_watermark < 1
            or isinstance(self.target_revision, bool)
            or not isinstance(self.target_revision, int)
            or self.target_revision < 1
        ):
            raise EpisodicMemoryError("owner_day_diary_revision_rejected")
        if self.purpose == OWNER_DAY_PREVIEW_PURPOSE:
            if self.supersedes_revision is not None:
                raise EpisodicMemoryError("owner_day_diary_supersede_rejected")
        elif self.target_revision == 1:
            if self.supersedes_revision is not None:
                raise EpisodicMemoryError("owner_day_diary_supersede_rejected")
        elif (
            isinstance(self.supersedes_revision, bool)
            or not isinstance(self.supersedes_revision, int)
            or self.supersedes_revision != self.target_revision - 1
        ):
            raise EpisodicMemoryError("owner_day_diary_supersede_rejected")
        require_digest(self.archive_head_digest, "owner_day_archive_head")
        require_digest(self.source_selection_digest, "owner_day_source_selection")
        for value, label in (
            (self.memory_release_set_id, "owner_day_memory_release"),
            (self.parent_release_set_id, "owner_day_parent_release"),
            (self.policy_overlay_id, "owner_day_policy_overlay"),
            (self.persona_digest, "owner_day_persona"),
            (self.egress_policy_digest, "owner_day_egress_policy"),
            (self.style_contract_digest, "owner_day_style_contract"),
        ):
            require_digest(value, label)
        expected_egress = (
            OWNER_DAY_PREVIEW_EGRESS_V1_DIGEST
            if self.purpose == OWNER_DAY_PREVIEW_PURPOSE
            else REFLECTIVE_DIARY_EGRESS_V1_DIGEST
        )
        if (
            self.egress_policy_digest != expected_egress
            or self.style_contract_digest != OWNER_DAY_DIARY_STYLE_V2_DIGEST
            or self.model != OWNER_DAY_DIARY_MODEL
            or self.model_role != OWNER_DAY_DIARY_MODEL_ROLE
        ):
            raise EpisodicMemoryError("owner_day_diary_contract_drifted")
        for value, label in (
            (self.archive_id, "owner_day_archive"),
            (self.model, "owner_day_model"),
            (self.model_role, "owner_day_model_role"),
        ):
            require_id(value, label)
        interval = owner_day_interval(self.owner_day, self.policy)
        previous = 0
        for turn, binding in zip(self.source_turns, self.source_time_bindings, strict=True):
            if (
                turn.draft.sequence <= previous
                or turn.draft.sequence > self.source_watermark
                or not turn.model_history_eligible
                or binding.status != "exact"
                or binding.delivered_at_utc is None
                or not interval.start_utc <= binding.delivered_at_utc < interval.end_utc
            ):
                raise EpisodicMemoryError("owner_day_diary_source_rejected")
            previous = turn.draft.sequence
        if self.source_watermark != self.source_turns[-1].draft.sequence:
            raise EpisodicMemoryError("owner_day_diary_watermark_incomplete")
        if self.source_selection_digest != semantic_digest(
            "myuna-p07-owner-day-source-selection-v2", self.source_selection_payload()
        ):
            raise EpisodicMemoryError("owner_day_source_selection_digest_mismatch")

    def source_selection_payload(self) -> dict[str, object]:
        return {
            "archive_head_digest": self.archive_head_digest,
            "owner_day": self.owner_day.isoformat(),
            "policy_digest": self.policy.policy_digest,
            "purpose": self.purpose,
            "source_sequences": [turn.draft.sequence for turn in self.source_turns],
            "source_time_binding_digests": [binding.binding_digest for binding in self.source_time_bindings],
            "source_turn_digests": [turn.turn_digest for turn in self.source_turns],
            "source_watermark": self.source_watermark,
        }

    @property
    def as_of_utc(self) -> datetime:
        return self.generation_time_sample.instant

    @property
    def generation_time_sample_digest(self) -> str:
        return semantic_digest(
            "myuna-p07-owner-day-generation-time-sample-v2",
            self.generation_time_sample.as_payload(),
        )

    @property
    def job_digest(self) -> str:
        return semantic_digest(
            "myuna-p07-owner-day-diary-job-v2",
            self.source_selection_payload()
            | {
                "generation_time_sample_digest": self.generation_time_sample_digest,
                "schema": self.schema,
                "archive_id": self.archive_id,
                "egress_policy_digest": self.egress_policy_digest,
                "memory_release_set_id": self.memory_release_set_id,
                "model": self.model,
                "model_role": self.model_role,
                "parent_release_set_id": self.parent_release_set_id,
                "persona_digest": self.persona_digest,
                "policy_overlay_id": self.policy_overlay_id,
                "style_contract_digest": self.style_contract_digest,
                "supersedes_revision": self.supersedes_revision,
                "target_revision": self.target_revision,
            },
        )

    def audit_projection(self) -> dict[str, object]:
        return {
            "job_digest": self.job_digest,
            "owner_day": self.owner_day.isoformat(),
            "policy_digest": self.policy.policy_digest,
            "purpose": self.purpose,
            "egress_binding_digest": self.egress_binding_digest,
            "source_selection_digest": self.source_selection_digest,
            "source_turn_count": len(self.source_turns),
            "source_watermark": self.source_watermark,
            "target_revision": self.target_revision,
            "generation_time_sample_digest": self.generation_time_sample_digest,
        }

    def as_payload(self) -> dict[str, object]:
        return {
            "archive_head_digest": self.archive_head_digest,
            "archive_id": self.archive_id,
            "egress_policy_digest": self.egress_policy_digest,
            "generation_time_sample": self.generation_time_sample.as_payload(),
            "memory_release_set_id": self.memory_release_set_id,
            "model": self.model,
            "model_role": self.model_role,
            "owner_day": self.owner_day.isoformat(),
            "parent_release_set_id": self.parent_release_set_id,
            "persona_digest": self.persona_digest,
            "policy": self.policy.as_payload(),
            "policy_overlay_id": self.policy_overlay_id,
            "purpose": self.purpose,
            "schema": self.schema,
            "source_selection_digest": self.source_selection_digest,
            "source_time_bindings": [item.payload() for item in self.source_time_bindings],
            "source_turns": [item.payload() for item in self.source_turns],
            "source_watermark": self.source_watermark,
            "style_contract_digest": self.style_contract_digest,
            "supersedes_revision": self.supersedes_revision,
            "target_revision": self.target_revision,
        }

    @classmethod
    def from_payload(cls, payload: object) -> "OwnerDayDiaryJob":
        required = {
            "archive_head_digest",
            "archive_id",
            "egress_policy_digest",
            "generation_time_sample",
            "memory_release_set_id",
            "model",
            "model_role",
            "owner_day",
            "parent_release_set_id",
            "persona_digest",
            "policy",
            "policy_overlay_id",
            "purpose",
            "schema",
            "source_selection_digest",
            "source_time_bindings",
            "source_turns",
            "source_watermark",
            "style_contract_digest",
            "supersedes_revision",
            "target_revision",
        }
        if (
            not isinstance(payload, Mapping)
            or set(payload) != required
            or not isinstance(payload["source_turns"], list)
            or not isinstance(payload["source_time_bindings"], list)
        ):
            raise EpisodicMemoryError("owner_day_diary_job_fields_rejected")
        try:
            parsed_day = date.fromisoformat(payload["owner_day"])  # type: ignore[arg-type]
            if not isinstance(payload["generation_time_sample"], Mapping):
                raise TypeError
            generation_time_sample = TrustedTimeSample.from_payload(
                payload["generation_time_sample"]
            )
            turns = tuple(
                CompleteTurn.from_payload(item)
                for item in payload["source_turns"]
                if isinstance(item, Mapping)
            )
            bindings = tuple(
                TurnTimeBinding.from_payload(item)
                for item in payload["source_time_bindings"]
                if isinstance(item, Mapping)
            )
        except (TypeError, ValueError, EpisodicMemoryError, TemporalContextError):
            raise EpisodicMemoryError("owner_day_diary_job_fields_rejected") from None
        if len(turns) != len(payload["source_turns"]) or len(bindings) != len(
            payload["source_time_bindings"]
        ):
            raise EpisodicMemoryError("owner_day_diary_job_fields_rejected")
        return cls(
            purpose=payload["purpose"],  # type: ignore[arg-type]
            owner_day=parsed_day,
            policy=OwnerDayPolicy.from_payload(payload["policy"]),
            source_turns=turns,
            source_time_bindings=bindings,
            archive_head_digest=payload["archive_head_digest"],  # type: ignore[arg-type]
            source_watermark=payload["source_watermark"],  # type: ignore[arg-type]
            source_selection_digest=payload["source_selection_digest"],  # type: ignore[arg-type]
            target_revision=payload["target_revision"],  # type: ignore[arg-type]
            supersedes_revision=payload["supersedes_revision"],  # type: ignore[arg-type]
            generation_time_sample=generation_time_sample,
            memory_release_set_id=payload["memory_release_set_id"],  # type: ignore[arg-type]
            parent_release_set_id=payload["parent_release_set_id"],  # type: ignore[arg-type]
            policy_overlay_id=payload["policy_overlay_id"],  # type: ignore[arg-type]
            archive_id=payload["archive_id"],  # type: ignore[arg-type]
            persona_digest=payload["persona_digest"],  # type: ignore[arg-type]
            egress_policy_digest=payload["egress_policy_digest"],  # type: ignore[arg-type]
            style_contract_digest=payload["style_contract_digest"],  # type: ignore[arg-type]
            model=payload["model"],  # type: ignore[arg-type]
            model_role=payload["model_role"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )

    @property
    def egress_binding_digest(self) -> str:
        return semantic_digest(
            "myuna-p07-owner-day-diary-egress-binding-v2",
            {
                "archive_id": self.archive_id,
                "egress_policy_digest": self.egress_policy_digest,
                "memory_release_set_id": self.memory_release_set_id,
                "model": self.model,
                "model_role": self.model_role,
                "parent_release_set_id": self.parent_release_set_id,
                "persona_digest": self.persona_digest,
                "policy_digest": self.policy.policy_digest,
                "policy_overlay_id": self.policy_overlay_id,
                "style_contract_digest": self.style_contract_digest,
            },
        )


def build_owner_day_diary_job(
    *,
    turns: Sequence[CompleteTurn],
    effective_bindings: Mapping[int, TurnTimeBinding],
    owner_day: date,
    policy: OwnerDayPolicy,
    purpose: str,
    generation_time_sample: TrustedTimeSample,
    target_revision: int,
    supersedes_revision: int | None,
    memory_release_set_id: str,
    parent_release_set_id: str,
    policy_overlay_id: str,
    archive_id: str,
    persona_digest: str,
) -> OwnerDayDiaryJob:
    previous_digest = "0" * 64
    for expected_sequence, turn in enumerate(turns, start=1):
        if (
            turn.draft.sequence != expected_sequence
            or turn.draft.previous_turn_digest != previous_digest
        ):
            raise EpisodicMemoryError("owner_day_archive_chain_drifted")
        previous_digest = turn.turn_digest
    interval = owner_day_interval(owner_day, policy)
    as_of_utc = generation_time_sample.instant
    if purpose == OWNER_DAY_FINAL_PURPOSE and as_of_utc < interval.end_utc:
        raise EpisodicMemoryError("owner_day_not_closed")
    selected: list[CompleteTurn] = []
    bindings: list[TurnTimeBinding] = []
    for turn in turns:
        binding = effective_bindings.get(turn.draft.sequence)
        if binding is None:
            raise EpisodicMemoryError("owner_day_time_binding_missing")
        if binding.status != "exact" or binding.delivered_at_utc is None:
            start = binding.unresolved_interval_start_utc
            end = binding.unresolved_interval_end_utc
            if start is None or end is None or (start < interval.end_utc and end > interval.start_utc):
                raise EpisodicMemoryError("owner_day_source_time_incomplete")
            continue
        if interval.start_utc <= binding.delivered_at_utc < interval.end_utc:
            if binding.delivered_at_utc > as_of_utc:
                raise EpisodicMemoryError("owner_day_source_after_as_of")
            selected.append(turn)
            bindings.append(binding)
    if not selected:
        raise EpisodicMemoryError("owner_day_has_no_eligible_turns")
    archive_head = turns[-1].turn_digest
    watermark = selected[-1].draft.sequence
    selection = {
        "archive_head_digest": archive_head,
        "owner_day": owner_day.isoformat(),
        "policy_digest": policy.policy_digest,
        "purpose": purpose,
        "source_sequences": [turn.draft.sequence for turn in selected],
        "source_time_binding_digests": [binding.binding_digest for binding in bindings],
        "source_turn_digests": [turn.turn_digest for turn in selected],
        "source_watermark": watermark,
    }
    return OwnerDayDiaryJob(
        purpose=purpose,
        owner_day=owner_day,
        policy=policy,
        source_turns=tuple(selected),
        source_time_bindings=tuple(bindings),
        archive_head_digest=archive_head,
        source_watermark=watermark,
        source_selection_digest=semantic_digest(
            "myuna-p07-owner-day-source-selection-v2", selection
        ),
        target_revision=target_revision,
        supersedes_revision=supersedes_revision,
        generation_time_sample=generation_time_sample,
        memory_release_set_id=memory_release_set_id,
        parent_release_set_id=parent_release_set_id,
        policy_overlay_id=policy_overlay_id,
        archive_id=archive_id,
        persona_digest=persona_digest,
        egress_policy_digest=(
            OWNER_DAY_PREVIEW_EGRESS_V1_DIGEST
            if purpose == OWNER_DAY_PREVIEW_PURPOSE
            else REFLECTIVE_DIARY_EGRESS_V1_DIGEST
        ),
    )
