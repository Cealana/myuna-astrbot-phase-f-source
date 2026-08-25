"""Bounded provider contract for append-only Owner-day diary revisions.

The caller owns scheduling and persistence. This module only validates one
source-bound job, computes capacity before egress, and validates one candidate.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
import json
from typing import Callable, Mapping, Protocol

from .context import ContextLimits
from .contracts import EpisodicMemoryError, require_digest, semantic_digest
from .diary import DiaryStatement
from .diary_generation import (
    DIARY_PROVIDER_TIMEOUT_SECONDS,
    DiaryCapacityReceipt,
    evaluate_diary_capacity,
)
from .owner_day import (
    OWNER_DAY_FINAL_PURPOSE,
    OWNER_DAY_PURPOSES,
    OWNER_DAY_PREVIEW_PURPOSE,
    OWNER_DAY_DIARY_MODEL,
    OWNER_DAY_DIARY_MODEL_ROLE,
    OwnerDayDiaryJob,
    OwnerDayPolicy,
)


OWNER_DAY_DIARY_CANDIDATE_SCHEMA = "myuna.p07-owner-day-diary-candidate.v2"
OWNER_DAY_DIARY_REVISION_SCHEMA = "myuna.p07-owner-day-diary-revision.v2"


def owner_day_diary_provider_messages(
    job: OwnerDayDiaryJob,
    *,
    persona_context: str,
) -> tuple[Mapping[str, str], ...]:
    if not persona_context or "\x00" in persona_context:
        raise EpisodicMemoryError("owner_day_persona_context_rejected")
    if semantic_digest(
        "myuna-p07-owner-day-diary-persona-context-v2",
        {"persona_context": persona_context},
    ) != job.persona_digest:
        raise EpisodicMemoryError("owner_day_persona_context_drifted")
    source = {
        "job_digest": job.job_digest,
        "owner_day": job.owner_day.isoformat(),
        "owner_day_policy": job.policy.as_payload(),
        "purpose": job.purpose,
        "schema": OWNER_DAY_DIARY_CANDIDATE_SCHEMA,
        "source_selection_digest": job.source_selection_digest,
        "source_watermark": job.source_watermark,
        "turns": [
            {
                "assistant": turn.draft.assistant.text,
                "assistant_kind": turn.draft.assistant.kind,
                "owner": turn.draft.owner.text,
                "owner_kind": turn.draft.owner.kind,
                "sequence": turn.draft.sequence,
                "turn_digest": turn.turn_digest,
            }
            for turn in job.source_turns
        ],
    }
    instruction = (
        persona_context
        + "\n\nWrite one source-bound Owner-day reflective diary revision in Myuna's "
        "current voice. Return one strict JSON object containing exactly job_digest, "
        "schema, and statements; echo the supplied job_digest and schema exactly. "
        "Separate factual_observation, interpretation_reflection, uncertainty, and "
        "intention. Raw turns remain factual authority. Every selected turn must be "
        "covered by at least one source pointer. Do not mutate Profile or temporal state."
    )
    return (
        {"role": "system", "content": instruction},
        {
            "role": "user",
            "content": json.dumps(
                source,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ),
        },
    )


@dataclass(frozen=True, slots=True)
class OwnerDayDiaryRevision:
    job_digest: str
    purpose: str
    owner_day: str
    policy_digest: str
    calendar_zone: str
    boundary_local_time: str
    soft_close_grace_seconds: int
    revision: int
    created_at_utc: datetime
    model: str
    model_role: str
    persona_digest: str
    memory_release_set_id: str
    source_selection_digest: str
    source_sequences: tuple[int, ...]
    source_turn_digests: tuple[str, ...]
    statements: tuple[DiaryStatement, ...]
    supersedes_revision: int | None
    schema: str = OWNER_DAY_DIARY_REVISION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != OWNER_DAY_DIARY_REVISION_SCHEMA:
            raise EpisodicMemoryError("owner_day_revision_schema_rejected")
        for value, label in (
            (self.job_digest, "owner_day_revision_job"),
            (self.policy_digest, "owner_day_revision_policy"),
            (self.persona_digest, "owner_day_revision_persona"),
            (self.memory_release_set_id, "owner_day_revision_release"),
            (self.source_selection_digest, "owner_day_revision_source"),
        ):
            require_digest(value, label)
        if (
            self.created_at_utc.tzinfo is None
            or self.created_at_utc.utcoffset() != timedelta(0)
            or self.revision < 1
            or not self.source_sequences
            or len(self.source_sequences) != len(self.source_turn_digests)
            or not self.statements
            or self.purpose not in OWNER_DAY_PURPOSES
            or self.model != OWNER_DAY_DIARY_MODEL
            or self.model_role != OWNER_DAY_DIARY_MODEL_ROLE
        ):
            raise EpisodicMemoryError("owner_day_revision_identity_rejected")
        try:
            parsed_day = date.fromisoformat(self.owner_day)
            policy = OwnerDayPolicy(
                calendar_zone=self.calendar_zone,
                boundary_local_time=self.boundary_local_time,
                soft_close_grace_seconds=self.soft_close_grace_seconds,
            )
        except (TypeError, ValueError, EpisodicMemoryError):
            raise EpisodicMemoryError("owner_day_revision_identity_rejected") from None
        if parsed_day.isoformat() != self.owner_day or policy.policy_digest != self.policy_digest:
            raise EpisodicMemoryError("owner_day_revision_policy_drifted")
        expected = set(self.source_sequences)
        covered = {
            sequence
            for statement in self.statements
            for sequence in statement.source_sequences
        }
        if covered != expected:
            raise EpisodicMemoryError("owner_day_revision_coverage_incomplete")
        by_sequence = dict(zip(self.source_sequences, self.source_turn_digests, strict=True))
        for statement in self.statements:
            for sequence, source_digest in zip(
                statement.source_sequences,
                statement.source_turn_digests,
                strict=True,
            ):
                if by_sequence.get(sequence) != source_digest:
                    raise EpisodicMemoryError("owner_day_revision_source_drifted")

    @property
    def revision_digest(self) -> str:
        return semantic_digest(
            "myuna-p07-owner-day-diary-revision-v2",
            {
                "boundary_local_time": self.boundary_local_time,
                "calendar_zone": self.calendar_zone,
                "created_at_utc": self.created_at_utc.isoformat(timespec="microseconds"),
                "job_digest": self.job_digest,
                "memory_release_set_id": self.memory_release_set_id,
                "model": self.model,
                "model_role": self.model_role,
                "owner_day": self.owner_day,
                "persona_digest": self.persona_digest,
                "policy_digest": self.policy_digest,
                "purpose": self.purpose,
                "revision": self.revision,
                "schema": self.schema,
                "source_selection_digest": self.source_selection_digest,
                "statements": [item.payload() for item in self.statements],
                "supersedes_revision": self.supersedes_revision,
            },
        )

    def as_payload(self) -> dict[str, object]:
        return {
            "boundary_local_time": self.boundary_local_time,
            "calendar_zone": self.calendar_zone,
            "created_at_utc": self.created_at_utc.isoformat(timespec="microseconds"),
            "job_digest": self.job_digest,
            "memory_release_set_id": self.memory_release_set_id,
            "model": self.model,
            "model_role": self.model_role,
            "owner_day": self.owner_day,
            "persona_digest": self.persona_digest,
            "policy_digest": self.policy_digest,
            "soft_close_grace_seconds": self.soft_close_grace_seconds,
            "purpose": self.purpose,
            "revision": self.revision,
            "schema": self.schema,
            "source_selection_digest": self.source_selection_digest,
            "source_sequences": list(self.source_sequences),
            "source_turn_digests": list(self.source_turn_digests),
            "statements": [item.payload() for item in self.statements],
            "supersedes_revision": self.supersedes_revision,
        }

    @classmethod
    def from_payload(cls, payload: object) -> "OwnerDayDiaryRevision":
        required = {
            "boundary_local_time",
            "calendar_zone",
            "created_at_utc",
            "job_digest",
            "memory_release_set_id",
            "model",
            "model_role",
            "owner_day",
            "persona_digest",
            "policy_digest",
            "purpose",
            "revision",
            "schema",
            "source_selection_digest",
            "source_sequences",
            "source_turn_digests",
            "statements",
            "supersedes_revision",
            "soft_close_grace_seconds",
        }
        if (
            not isinstance(payload, Mapping)
            or set(payload) != required
            or not isinstance(payload["source_sequences"], list)
            or not isinstance(payload["source_turn_digests"], list)
            or not isinstance(payload["statements"], list)
        ):
            raise EpisodicMemoryError("owner_day_revision_fields_rejected")
        try:
            created_at = datetime.fromisoformat(payload["created_at_utc"])  # type: ignore[arg-type]
        except (TypeError, ValueError):
            raise EpisodicMemoryError("owner_day_revision_fields_rejected") from None
        return cls(
            job_digest=payload["job_digest"],  # type: ignore[arg-type]
            purpose=payload["purpose"],  # type: ignore[arg-type]
            owner_day=payload["owner_day"],  # type: ignore[arg-type]
            policy_digest=payload["policy_digest"],  # type: ignore[arg-type]
            calendar_zone=payload["calendar_zone"],  # type: ignore[arg-type]
            boundary_local_time=payload["boundary_local_time"],  # type: ignore[arg-type]
            soft_close_grace_seconds=payload["soft_close_grace_seconds"],  # type: ignore[arg-type]
            revision=payload["revision"],  # type: ignore[arg-type]
            created_at_utc=created_at,
            model=payload["model"],  # type: ignore[arg-type]
            model_role=payload["model_role"],  # type: ignore[arg-type]
            persona_digest=payload["persona_digest"],  # type: ignore[arg-type]
            memory_release_set_id=payload["memory_release_set_id"],  # type: ignore[arg-type]
            source_selection_digest=payload["source_selection_digest"],  # type: ignore[arg-type]
            source_sequences=tuple(payload["source_sequences"]),  # type: ignore[arg-type]
            source_turn_digests=tuple(payload["source_turn_digests"]),  # type: ignore[arg-type]
            statements=tuple(DiaryStatement.from_payload(item) for item in payload["statements"]),
            supersedes_revision=payload["supersedes_revision"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )

    def audit_projection(self) -> dict[str, object]:
        return {
            "final": self.purpose == OWNER_DAY_FINAL_PURPOSE,
            "job_digest": self.job_digest,
            "owner_day": self.owner_day,
            "policy_digest": self.policy_digest,
            "preview": self.purpose == OWNER_DAY_PREVIEW_PURPOSE,
            "revision": self.revision,
            "revision_digest": self.revision_digest,
            "source_selection_digest": self.source_selection_digest,
            "source_turn_count": len(self.source_sequences),
        }


@dataclass(frozen=True, slots=True)
class OwnerDayDiaryCandidate:
    job_digest: str
    revision: OwnerDayDiaryRevision
    candidate_digest: str
    schema: str = OWNER_DAY_DIARY_CANDIDATE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != OWNER_DAY_DIARY_CANDIDATE_SCHEMA:
            raise EpisodicMemoryError("owner_day_candidate_schema_rejected")
        require_digest(self.job_digest, "owner_day_candidate_job")
        require_digest(self.candidate_digest, "owner_day_candidate")
        if self.revision.job_digest != self.job_digest or self.candidate_digest != semantic_digest(
            "myuna-p07-owner-day-diary-candidate-v2",
            {
                "job_digest": self.job_digest,
                "revision_digest": self.revision.revision_digest,
                "schema": self.schema,
            },
        ):
            raise EpisodicMemoryError("owner_day_candidate_digest_mismatch")

    def as_payload(self) -> dict[str, object]:
        return {
            "candidate_digest": self.candidate_digest,
            "job_digest": self.job_digest,
            "revision": self.revision.as_payload(),
            "schema": self.schema,
        }

    @classmethod
    def from_payload(cls, payload: object) -> "OwnerDayDiaryCandidate":
        if not isinstance(payload, Mapping) or set(payload) != {
            "candidate_digest",
            "job_digest",
            "revision",
            "schema",
        }:
            raise EpisodicMemoryError("owner_day_candidate_fields_rejected")
        return cls(
            job_digest=payload["job_digest"],  # type: ignore[arg-type]
            revision=OwnerDayDiaryRevision.from_payload(payload["revision"]),
            candidate_digest=payload["candidate_digest"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )

    @classmethod
    def from_provider_text(
        cls,
        text: str,
        *,
        job: OwnerDayDiaryJob,
        created_at_utc: datetime,
    ) -> "OwnerDayDiaryCandidate":
        try:
            payload = json.loads(text)
        except (TypeError, json.JSONDecodeError):
            raise EpisodicMemoryError("owner_day_provider_output_rejected") from None
        if not isinstance(payload, Mapping) or set(payload) != {
            "job_digest",
            "schema",
            "statements",
        }:
            raise EpisodicMemoryError("owner_day_provider_output_rejected")
        if (
            payload["job_digest"] != job.job_digest
            or payload["schema"] != OWNER_DAY_DIARY_CANDIDATE_SCHEMA
        ):
            raise EpisodicMemoryError("owner_day_provider_output_binding_rejected")
        raw_statements = payload["statements"]
        if not isinstance(raw_statements, list):
            raise EpisodicMemoryError("owner_day_provider_output_rejected")
        statements = tuple(DiaryStatement.from_payload(item) for item in raw_statements)
        revision = OwnerDayDiaryRevision(
            job_digest=job.job_digest,
            purpose=job.purpose,
            owner_day=job.owner_day.isoformat(),
            policy_digest=job.policy.policy_digest,
            calendar_zone=job.policy.calendar_zone,
            boundary_local_time=job.policy.boundary_local_time,
            soft_close_grace_seconds=job.policy.soft_close_grace_seconds,
            revision=job.target_revision,
            created_at_utc=created_at_utc,
            model=job.model,
            model_role=job.model_role,
            persona_digest=job.persona_digest,
            memory_release_set_id=job.memory_release_set_id,
            source_selection_digest=job.source_selection_digest,
            source_sequences=tuple(turn.draft.sequence for turn in job.source_turns),
            source_turn_digests=tuple(turn.turn_digest for turn in job.source_turns),
            statements=statements,
            supersedes_revision=job.supersedes_revision,
        )
        candidate_digest = semantic_digest(
            "myuna-p07-owner-day-diary-candidate-v2",
            {
                "job_digest": job.job_digest,
                "revision_digest": revision.revision_digest,
                "schema": OWNER_DAY_DIARY_CANDIDATE_SCHEMA,
            },
        )
        return cls(job.job_digest, revision, candidate_digest)


class OwnerDayDiaryProviderPort(Protocol):
    def generate_owner_day_diary(
        self,
        messages: tuple[Mapping[str, str], ...],
        *,
        timeout_seconds: float,
    ) -> str: ...


@dataclass(frozen=True, slots=True)
class OwnerDayDiaryGenerationResult:
    status: str
    job_digest: str
    capacity: DiaryCapacityReceipt
    provider_called: bool
    candidate: OwnerDayDiaryCandidate | None = None

    def audit_projection(self) -> dict[str, object]:
        return {
            "candidate_digest": (
                None if self.candidate is None else self.candidate.candidate_digest
            ),
            "capacity": self.capacity.audit_projection(),
            "job_digest": self.job_digest,
            "provider_called": self.provider_called,
            "status": self.status,
        }


class OwnerDayDiaryGenerationCoordinator:
    def __init__(
        self,
        *,
        limits: ContextLimits,
        token_counter: Callable[[tuple[Mapping[str, str], ...]], int] | None,
    ) -> None:
        self.limits = limits
        self.token_counter = token_counter

    def generate(
        self,
        job: OwnerDayDiaryJob,
        *,
        persona_context: str,
        provider: OwnerDayDiaryProviderPort,
        created_at_utc: datetime,
        timeout_seconds: float = DIARY_PROVIDER_TIMEOUT_SECONDS,
    ) -> OwnerDayDiaryGenerationResult:
        if created_at_utc != job.as_of_utc:
            raise EpisodicMemoryError("owner_day_generation_time_drifted")
        messages = owner_day_diary_provider_messages(job, persona_context=persona_context)
        capacity = evaluate_diary_capacity(
            messages,
            limits=self.limits,
            token_counter=self.token_counter,
        )
        if not capacity.fit:
            return OwnerDayDiaryGenerationResult(
                "coverage_incomplete", job.job_digest, capacity, False
            )
        try:
            generated = provider.generate_owner_day_diary(
                messages,
                timeout_seconds=timeout_seconds,
            )
        except (OSError, RuntimeError, TimeoutError):
            raise EpisodicMemoryError(
                "owner_day_diary_provider_unavailable", retryable=True
            ) from None
        candidate = OwnerDayDiaryCandidate.from_provider_text(
            generated,
            job=job,
            created_at_utc=created_at_utc,
        )
        return OwnerDayDiaryGenerationResult(
            "completed", job.job_digest, capacity, True, candidate
        )
