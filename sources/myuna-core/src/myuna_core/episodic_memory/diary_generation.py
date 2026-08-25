from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import json
from typing import Callable, Mapping, Protocol, Sequence
from zoneinfo import ZoneInfo

from .calendar import local_date_interval
from .context import ContextLimits
from .contracts import (
    EGRESS_POLICY_REFLECTIVE_DIARY_V1,
    REFLECTIVE_DIARY_EGRESS_V1_DIGEST,
    REFLECTIVE_DIARY_STYLE_V1_DIGEST,
    CompleteTurn,
    EpisodicMemoryError,
    TurnTimeBinding,
    TurnTimeCorrection,
    require_digest,
    require_id,
    reflective_diary_egress_binding_digest,
    semantic_digest,
)
from .diary import DiaryStatement, ReflectiveDiaryEntry, verify_diary_sources


DIARY_GENERATION_JOB_SCHEMA = "myuna.p07-reflective-diary-generation-job.v1"
DIARY_GENERATION_CANDIDATE_SCHEMA = "myuna.p07-reflective-diary-candidate.v1"
DIARY_MODEL = "deepseek-v4-flash"
DIARY_MODEL_ROLE = "p07_external_daily_reflective_diary"
DIARY_MAX_OUTPUT_TOKENS = 4_000
DIARY_PROVIDER_TIMEOUT_SECONDS = 75.0


def _verify_archive_chain(turns: Sequence[CompleteTurn]) -> None:
    previous = "0" * 64
    for expected_sequence, turn in enumerate(turns, start=1):
        if (
            turn.draft.sequence != expected_sequence
            or turn.draft.previous_turn_digest != previous
        ):
            raise EpisodicMemoryError("diary_archive_chain_drifted")
        previous = turn.turn_digest


def _effective_bindings(
    turns: Sequence[CompleteTurn],
    corrections: Sequence[TurnTimeCorrection],
) -> tuple[dict[int, TurnTimeBinding], tuple[str, ...]]:
    by_id = {turn.draft.turn_id: turn for turn in turns}
    selected: dict[str, TurnTimeCorrection] = {}
    for correction in corrections:
        turn = by_id.get(correction.turn_id)
        if (
            turn is None
            or turn.turn_digest != correction.turn_digest
            or turn.draft.time_binding.binding_digest != correction.original_binding_digest
        ):
            raise EpisodicMemoryError("diary_time_correction_source_drifted")
        prior = selected.get(correction.turn_id)
        if (
            prior is not None
            and prior.corrected_binding.binding_digest
            != correction.corrected_binding.binding_digest
        ):
            raise EpisodicMemoryError("diary_time_correction_conflicted")
        selected[correction.turn_id] = correction
    bindings = {
        turn.draft.sequence: (
            selected[turn.draft.turn_id].corrected_binding
            if turn.draft.turn_id in selected
            else turn.draft.time_binding
        )
        for turn in turns
    }
    return bindings, tuple(
        sorted(correction.correction_digest for correction in selected.values())
    )


def effective_turn_time_bindings(
    turns: Sequence[CompleteTurn],
    corrections: Sequence[TurnTimeCorrection],
) -> tuple[Mapping[int, TurnTimeBinding], tuple[str, ...]]:
    """Return the verified append-only time view without rewriting raw turns."""

    return _effective_bindings(turns, corrections)


@dataclass(frozen=True, slots=True)
class DiaryGenerationJob:
    job_id: str
    day: date
    calendar_zone: str
    target_revision: int
    generation_kind: str
    supersedes_revision: int | None
    memory_release_set_id: str
    parent_release_set_id: str
    policy_overlay_id: str
    archive_id: str
    archive_head_digest: str
    persona_digest: str
    closure_binding_digest: str
    source_turns: tuple[CompleteTurn, ...]
    source_time_bindings: tuple[TurnTimeBinding, ...]
    source_selection_digest: str
    egress_policy_digest: str = REFLECTIVE_DIARY_EGRESS_V1_DIGEST
    style_contract_digest: str = REFLECTIVE_DIARY_STYLE_V1_DIGEST
    model: str = DIARY_MODEL
    model_role: str = DIARY_MODEL_ROLE
    schema: str = DIARY_GENERATION_JOB_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != DIARY_GENERATION_JOB_SCHEMA:
            raise EpisodicMemoryError("diary_generation_job_schema_rejected")
        require_id(self.job_id, "diary_generation_job_id")
        if not isinstance(self.day, date):
            raise EpisodicMemoryError("diary_generation_day_invalid")
        try:
            ZoneInfo(self.calendar_zone)
        except Exception:
            raise EpisodicMemoryError("diary_generation_zone_rejected") from None
        if (
            isinstance(self.target_revision, bool)
            or not isinstance(self.target_revision, int)
            or self.target_revision < 1
        ):
            raise EpisodicMemoryError("diary_generation_revision_invalid")
        if self.generation_kind not in {"contemporaneous", "correction", "late_backfill"}:
            raise EpisodicMemoryError("diary_generation_kind_rejected")
        if self.generation_kind == "contemporaneous":
            if self.supersedes_revision is not None:
                raise EpisodicMemoryError("diary_generation_supersede_rejected")
        elif self.generation_kind == "late_backfill" and self.target_revision == 1:
            if self.supersedes_revision is not None:
                raise EpisodicMemoryError("diary_generation_supersede_rejected")
        elif (
            isinstance(self.supersedes_revision, bool)
            or not isinstance(self.supersedes_revision, int)
            or self.supersedes_revision < 1
            or self.supersedes_revision >= self.target_revision
        ):
            raise EpisodicMemoryError("diary_generation_supersede_rejected")
        for value, label in (
            (self.memory_release_set_id, "diary_memory_release_set"),
            (self.parent_release_set_id, "diary_parent_release_set"),
            (self.policy_overlay_id, "diary_policy_overlay"),
            (self.archive_head_digest, "diary_archive_head"),
            (self.persona_digest, "diary_persona"),
            (self.closure_binding_digest, "diary_closure_binding"),
            (self.source_selection_digest, "diary_source_selection"),
            (self.egress_policy_digest, "diary_egress_policy"),
            (self.style_contract_digest, "diary_style_contract"),
        ):
            require_digest(value, label)
        require_id(self.archive_id, "diary_archive_id")
        require_id(self.model, "diary_model")
        require_id(self.model_role, "diary_model_role")
        if (
            self.egress_policy_digest != REFLECTIVE_DIARY_EGRESS_V1_DIGEST
            or self.style_contract_digest != REFLECTIVE_DIARY_STYLE_V1_DIGEST
            or self.model != DIARY_MODEL
            or self.model_role != DIARY_MODEL_ROLE
        ):
            raise EpisodicMemoryError("diary_generation_contract_drifted")
        if not self.source_turns or len(self.source_turns) != len(self.source_time_bindings):
            raise EpisodicMemoryError("diary_generation_sources_empty")
        previous_sequence = 0
        for turn, binding in zip(
            self.source_turns,
            self.source_time_bindings,
            strict=True,
        ):
            if (
                turn.draft.sequence <= previous_sequence
                or not turn.model_history_eligible
                or binding.status != "exact"
                or binding.delivered_at_utc is None
                or binding.calendar_zone != self.calendar_zone
                or binding.delivered_at_utc.astimezone(
                    ZoneInfo(self.calendar_zone)
                ).date()
                != self.day
            ):
                raise EpisodicMemoryError("diary_generation_source_rejected")
            previous_sequence = turn.draft.sequence
        if self.source_selection_digest != semantic_digest(
            "myuna-p07-reflective-diary-source-selection-v1",
            self.source_selection_payload(),
        ):
            raise EpisodicMemoryError("diary_source_selection_digest_mismatch")

    def source_selection_payload(self) -> dict[str, object]:
        return {
            "archive_head_digest": self.archive_head_digest,
            "calendar_zone": self.calendar_zone,
            "closure_binding_digest": self.closure_binding_digest,
            "day": self.day.isoformat(),
            "source_sequences": [turn.draft.sequence for turn in self.source_turns],
            "source_time_binding_digests": [
                binding.binding_digest for binding in self.source_time_bindings
            ],
            "source_turn_digests": [turn.turn_digest for turn in self.source_turns],
        }

    def digest_payload(self) -> dict[str, object]:
        return {
            "archive_id": self.archive_id,
            "egress_policy_digest": self.egress_policy_digest,
            "generation_kind": self.generation_kind,
            "job_id": self.job_id,
            "memory_release_set_id": self.memory_release_set_id,
            "model": self.model,
            "model_role": self.model_role,
            "parent_release_set_id": self.parent_release_set_id,
            "persona_digest": self.persona_digest,
            "policy_overlay_id": self.policy_overlay_id,
            "schema": self.schema,
            "source_selection_digest": self.source_selection_digest,
            "style_contract_digest": self.style_contract_digest,
            "supersedes_revision": self.supersedes_revision,
            "target_revision": self.target_revision,
        }

    @property
    def job_digest(self) -> str:
        return semantic_digest("myuna-p07-reflective-diary-generation-job-v1", self.digest_payload())

    @property
    def egress_binding_digest(self) -> str:
        return reflective_diary_egress_binding_digest(
            memory_release_set_id=self.memory_release_set_id,
            parent_release_set_id=self.parent_release_set_id,
            policy_overlay_id=self.policy_overlay_id,
            archive_id=self.archive_id,
            egress_policy_digest=self.egress_policy_digest,
            style_contract_digest=self.style_contract_digest,
            persona_digest=self.persona_digest,
            model=self.model,
            model_role=self.model_role,
        )

    def as_payload(self) -> dict[str, object]:
        return self.digest_payload() | {
            "day": self.day.isoformat(),
            "calendar_zone": self.calendar_zone,
            "archive_head_digest": self.archive_head_digest,
            "closure_binding_digest": self.closure_binding_digest,
            "job_digest": self.job_digest,
            "source_turns": [turn.payload() for turn in self.source_turns],
            "source_time_bindings": [
                binding.payload() for binding in self.source_time_bindings
            ],
        }

    @classmethod
    def from_payload(cls, payload: object) -> DiaryGenerationJob:
        required = {
            "archive_head_digest",
            "archive_id",
            "calendar_zone",
            "closure_binding_digest",
            "day",
            "egress_policy_digest",
            "generation_kind",
            "job_digest",
            "job_id",
            "memory_release_set_id",
            "model",
            "model_role",
            "parent_release_set_id",
            "persona_digest",
            "policy_overlay_id",
            "schema",
            "source_selection_digest",
            "source_time_bindings",
            "source_turns",
            "style_contract_digest",
            "supersedes_revision",
            "target_revision",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise EpisodicMemoryError("diary_generation_job_fields_rejected")
        if not isinstance(payload["source_turns"], list) or not isinstance(
            payload["source_time_bindings"], list
        ):
            raise EpisodicMemoryError("diary_generation_job_fields_rejected")
        try:
            parsed_day = date.fromisoformat(payload["day"])  # type: ignore[arg-type]
            turns = tuple(CompleteTurn.from_payload(item) for item in payload["source_turns"])
            bindings = tuple(
                TurnTimeBinding.from_payload(item)
                for item in payload["source_time_bindings"]
            )
        except (TypeError, ValueError):
            raise EpisodicMemoryError("diary_generation_job_fields_rejected") from None
        result = cls(
            job_id=payload["job_id"],  # type: ignore[arg-type]
            day=parsed_day,
            calendar_zone=payload["calendar_zone"],  # type: ignore[arg-type]
            target_revision=payload["target_revision"],  # type: ignore[arg-type]
            generation_kind=payload["generation_kind"],  # type: ignore[arg-type]
            supersedes_revision=payload["supersedes_revision"],  # type: ignore[arg-type]
            memory_release_set_id=payload["memory_release_set_id"],  # type: ignore[arg-type]
            parent_release_set_id=payload["parent_release_set_id"],  # type: ignore[arg-type]
            policy_overlay_id=payload["policy_overlay_id"],  # type: ignore[arg-type]
            archive_id=payload["archive_id"],  # type: ignore[arg-type]
            archive_head_digest=payload["archive_head_digest"],  # type: ignore[arg-type]
            persona_digest=payload["persona_digest"],  # type: ignore[arg-type]
            closure_binding_digest=payload["closure_binding_digest"],  # type: ignore[arg-type]
            source_turns=turns,
            source_time_bindings=bindings,
            source_selection_digest=payload["source_selection_digest"],  # type: ignore[arg-type]
            egress_policy_digest=payload["egress_policy_digest"],  # type: ignore[arg-type]
            style_contract_digest=payload["style_contract_digest"],  # type: ignore[arg-type]
            model=payload["model"],  # type: ignore[arg-type]
            model_role=payload["model_role"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )
        if payload["job_digest"] != result.job_digest:
            raise EpisodicMemoryError("diary_generation_job_digest_mismatch")
        return result

    def audit_projection(self) -> dict[str, object]:
        return {
            "calendar_zone": self.calendar_zone,
            "day": self.day.isoformat(),
            "egress_binding_digest": self.egress_binding_digest,
            "egress_policy_digest": self.egress_policy_digest,
            "job_digest": self.job_digest,
            "model": self.model,
            "model_role": self.model_role,
            "source_selection_digest": self.source_selection_digest,
            "source_turn_count": len(self.source_turns),
            "style_contract_digest": self.style_contract_digest,
            "target_revision": self.target_revision,
        }


def build_closed_day_job(
    *,
    turns: Sequence[CompleteTurn],
    corrections: Sequence[TurnTimeCorrection],
    day: date,
    calendar_zone: str,
    closure_binding: TurnTimeBinding,
    target_revision: int,
    generation_kind: str,
    supersedes_revision: int | None,
    memory_release_set_id: str,
    parent_release_set_id: str,
    policy_overlay_id: str,
    archive_id: str,
    persona_digest: str,
) -> DiaryGenerationJob:
    _verify_archive_chain(turns)
    if closure_binding.status != "exact" or closure_binding.delivered_at_utc is None:
        raise EpisodicMemoryError("diary_day_closure_time_unresolved")
    interval = local_date_interval(day, calendar_zone)
    if closure_binding.delivered_at_utc < interval.end:
        raise EpisodicMemoryError("diary_day_not_closed")
    effective, correction_digests = _effective_bindings(turns, corrections)
    selected: list[CompleteTurn] = []
    effective_digests: list[str] = []
    for turn in turns:
        if not turn.model_history_eligible:
            continue
        binding = effective[turn.draft.sequence]
        if binding.status != "exact" or binding.delivered_at_utc is None:
            if binding.calendar_zone != calendar_zone:
                continue
            start = binding.unresolved_interval_start_utc
            end = binding.unresolved_interval_end_utc
            if start is None or end is None or (start < interval.end and end > interval.start):
                raise EpisodicMemoryError("diary_day_source_time_incomplete")
            continue
        if binding.calendar_zone != calendar_zone:
            continue
        if binding.delivered_at_utc.astimezone(ZoneInfo(calendar_zone)).date() != day:
            continue
        selected.append(turn)
        effective_digests.append(binding.binding_digest)
    if not selected:
        raise EpisodicMemoryError("diary_day_has_no_eligible_turns")
    archive_head = turns[-1].turn_digest if turns else "0" * 64
    selection_payload = {
        "archive_head_digest": archive_head,
        "calendar_zone": calendar_zone,
        "closure_binding_digest": closure_binding.binding_digest,
        "day": day.isoformat(),
        "source_sequences": [turn.draft.sequence for turn in selected],
        "source_time_binding_digests": effective_digests,
        "source_turn_digests": [turn.turn_digest for turn in selected],
    }
    selection_digest = semantic_digest(
        "myuna-p07-reflective-diary-source-selection-v1", selection_payload
    )
    job_id = "diary-" + semantic_digest(
        "myuna-p07-reflective-diary-job-id-v1",
        {
            "archive_id": archive_id,
            "calendar_zone": calendar_zone,
            "correction_digests": list(correction_digests),
            "day": day.isoformat(),
            "generation_kind": generation_kind,
            "source_selection_digest": selection_digest,
            "target_revision": target_revision,
        },
    )
    return DiaryGenerationJob(
        job_id=job_id,
        day=day,
        calendar_zone=calendar_zone,
        target_revision=target_revision,
        generation_kind=generation_kind,
        supersedes_revision=supersedes_revision,
        memory_release_set_id=memory_release_set_id,
        parent_release_set_id=parent_release_set_id,
        policy_overlay_id=policy_overlay_id,
        archive_id=archive_id,
        archive_head_digest=archive_head,
        persona_digest=persona_digest,
        closure_binding_digest=closure_binding.binding_digest,
        source_turns=tuple(selected),
        source_time_bindings=tuple(effective[turn.draft.sequence] for turn in selected),
        source_selection_digest=selection_digest,
    )


@dataclass(frozen=True, slots=True)
class DiaryCapacityReceipt:
    request_characters: int
    projection_characters: int
    serialized_bytes: int
    input_tokens: int
    request_headroom: int
    projection_headroom: int
    serialized_headroom: int
    token_headroom: int
    limiting_oracle: str | None
    fit: bool

    def audit_projection(self) -> dict[str, object]:
        return {
            "fit": self.fit,
            "input_tokens": self.input_tokens,
            "limiting_oracle": self.limiting_oracle,
            "projection_characters": self.projection_characters,
            "projection_headroom": self.projection_headroom,
            "request_characters": self.request_characters,
            "request_headroom": self.request_headroom,
            "serialized_bytes": self.serialized_bytes,
            "serialized_headroom": self.serialized_headroom,
            "token_headroom": self.token_headroom,
        }

    @classmethod
    def from_payload(cls, payload: object) -> DiaryCapacityReceipt:
        required = {
            "fit",
            "input_tokens",
            "limiting_oracle",
            "projection_characters",
            "projection_headroom",
            "request_characters",
            "request_headroom",
            "serialized_bytes",
            "serialized_headroom",
            "token_headroom",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise EpisodicMemoryError("diary_capacity_receipt_fields_rejected")
        result = cls(
            request_characters=payload["request_characters"],  # type: ignore[arg-type]
            projection_characters=payload["projection_characters"],  # type: ignore[arg-type]
            serialized_bytes=payload["serialized_bytes"],  # type: ignore[arg-type]
            input_tokens=payload["input_tokens"],  # type: ignore[arg-type]
            request_headroom=payload["request_headroom"],  # type: ignore[arg-type]
            projection_headroom=payload["projection_headroom"],  # type: ignore[arg-type]
            serialized_headroom=payload["serialized_headroom"],  # type: ignore[arg-type]
            token_headroom=payload["token_headroom"],  # type: ignore[arg-type]
            limiting_oracle=payload["limiting_oracle"],  # type: ignore[arg-type]
            fit=payload["fit"],  # type: ignore[arg-type]
        )
        integer_fields = (
            result.request_characters,
            result.projection_characters,
            result.serialized_bytes,
            result.input_tokens,
            result.request_headroom,
            result.projection_headroom,
            result.serialized_headroom,
            result.token_headroom,
        )
        if (
            any(isinstance(value, bool) or not isinstance(value, int) for value in integer_fields)
            or not isinstance(result.fit, bool)
            or result.limiting_oracle
            not in {None, "request_characters", "projection_characters", "serialized_bytes", "input_tokens"}
        ):
            raise EpisodicMemoryError("diary_capacity_receipt_fields_rejected")
        return result

    @property
    def receipt_digest(self) -> str:
        return semantic_digest(
            "myuna-p07-reflective-diary-capacity-receipt-v1",
            self.audit_projection(),
        )


def diary_provider_messages(
    job: DiaryGenerationJob,
    *,
    persona_context: str,
) -> tuple[Mapping[str, str], ...]:
    if not persona_context or "\x00" in persona_context:
        raise EpisodicMemoryError("diary_persona_context_rejected")
    if semantic_digest(
        "myuna-p07-reflective-diary-persona-context-v1",
        {"persona_context": persona_context},
    ) != job.persona_digest:
        raise EpisodicMemoryError("diary_persona_context_drifted")
    source_payload = {
        "calendar_zone": job.calendar_zone,
        "day": job.day.isoformat(),
        "job_digest": job.job_digest,
        "source_selection_digest": job.source_selection_digest,
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
        + "\n\nWrite one reflective diary for the bound closed day in Myuna's current voice. "
        "Return one strict JSON object only. Separate factual_observation, "
        "interpretation_reflection, uncertainty, and intention statements. Raw turns are "
        "the sole factual authority. Do not create Profile or temporal facts. Every selected "
        "turn sequence and digest must appear in at least one statement source pointer. "
        "Do not omit an event while claiming complete coverage."
    )
    return (
        {"role": "system", "content": instruction},
        {
            "role": "user",
            "content": json.dumps(
                source_payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ),
        },
    )


def evaluate_diary_capacity(
    messages: tuple[Mapping[str, str], ...],
    *,
    limits: ContextLimits,
    token_counter: Callable[[tuple[Mapping[str, str], ...]], int] | None,
) -> DiaryCapacityReceipt:
    projection_characters = sum(len(item["content"]) for item in messages)
    request_characters = projection_characters + limits.output_reserve_characters
    serialized_bytes = len(
        json.dumps(
            [dict(item) for item in messages],
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ) + limits.output_reserve_bytes
    if token_counter is None:
        raise EpisodicMemoryError("diary_token_capacity_oracle_unavailable")
    try:
        input_tokens = token_counter(messages) + limits.output_reserve_tokens
    except Exception:
        raise EpisodicMemoryError("diary_token_capacity_oracle_unavailable") from None
    if isinstance(input_tokens, bool) or not isinstance(input_tokens, int) or input_tokens < 1:
        raise EpisodicMemoryError("diary_token_capacity_oracle_unavailable")
    headrooms = {
        "request_characters": limits.request_characters - request_characters,
        "projection_characters": limits.projection_characters - projection_characters,
        "serialized_bytes": limits.serialized_bytes - serialized_bytes,
        "input_tokens": limits.input_tokens - input_tokens,
    }
    limiting = min(headrooms, key=headrooms.__getitem__)
    fit = all(value >= 0 for value in headrooms.values())
    return DiaryCapacityReceipt(
        request_characters=request_characters,
        projection_characters=projection_characters,
        serialized_bytes=serialized_bytes,
        input_tokens=input_tokens,
        request_headroom=headrooms["request_characters"],
        projection_headroom=headrooms["projection_characters"],
        serialized_headroom=headrooms["serialized_bytes"],
        token_headroom=headrooms["input_tokens"],
        limiting_oracle=None if fit else limiting,
        fit=fit,
    )


@dataclass(frozen=True, slots=True)
class DiaryGenerationCandidate:
    job_digest: str
    entry: ReflectiveDiaryEntry
    candidate_digest: str
    schema: str = DIARY_GENERATION_CANDIDATE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != DIARY_GENERATION_CANDIDATE_SCHEMA:
            raise EpisodicMemoryError("diary_candidate_schema_rejected")
        require_digest(self.job_digest, "diary_candidate_job")
        require_digest(self.candidate_digest, "diary_candidate")
        expected = semantic_digest(
            "myuna-p07-reflective-diary-candidate-v1",
            {
                "entry": self.entry.payload(),
                "job_digest": self.job_digest,
                "schema": self.schema,
            },
        )
        if self.candidate_digest != expected:
            raise EpisodicMemoryError("diary_candidate_digest_mismatch")

    def as_payload(self) -> dict[str, object]:
        return {
            "candidate_digest": self.candidate_digest,
            "entry": self.entry.payload(),
            "job_digest": self.job_digest,
            "schema": self.schema,
        }

    @classmethod
    def from_payload(cls, payload: object) -> DiaryGenerationCandidate:
        if not isinstance(payload, Mapping) or set(payload) != {
            "candidate_digest",
            "entry",
            "job_digest",
            "schema",
        }:
            raise EpisodicMemoryError("diary_candidate_fields_rejected")
        return cls(
            job_digest=payload["job_digest"],  # type: ignore[arg-type]
            entry=ReflectiveDiaryEntry.from_payload(payload["entry"]),
            candidate_digest=payload["candidate_digest"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )

    @classmethod
    def from_provider_text(
        cls,
        text: str,
        *,
        job: DiaryGenerationJob,
        created_at_utc,
    ) -> DiaryGenerationCandidate:
        try:
            payload = json.loads(text)
        except (TypeError, json.JSONDecodeError):
            raise EpisodicMemoryError("diary_provider_output_malformed") from None
        if not isinstance(payload, Mapping) or set(payload) != {
            "job_digest",
            "schema",
            "statements",
        }:
            raise EpisodicMemoryError("diary_provider_output_fields_rejected")
        if (
            payload["schema"] != DIARY_GENERATION_CANDIDATE_SCHEMA
            or payload["job_digest"] != job.job_digest
            or not isinstance(payload["statements"], list)
        ):
            raise EpisodicMemoryError("diary_provider_output_binding_rejected")
        statements = tuple(DiaryStatement.from_payload(item) for item in payload["statements"])
        entry = ReflectiveDiaryEntry(
            day=job.day,
            calendar_zone=job.calendar_zone,
            revision=job.target_revision,
            created_at_utc=created_at_utc,
            model_role=job.model_role,
            model_version=job.model,
            persona_digest=job.persona_digest,
            release_set_id=job.memory_release_set_id,
            generation_kind=job.generation_kind,
            reason_code="automatic_closed_day_reflection",
            statements=statements,
            source_selection_digest=job.source_selection_digest,
            egress_policy_digest=job.egress_policy_digest,
            style_contract_digest=job.style_contract_digest,
            closure_binding_digest=job.closure_binding_digest,
            source_sequences=tuple(turn.draft.sequence for turn in job.source_turns),
            source_turn_digests=tuple(turn.turn_digest for turn in job.source_turns),
            supersedes_revision=job.supersedes_revision,
        )
        verify_diary_sources(
            entry,
            job.source_turns,
            effective_time_bindings={
                turn.draft.sequence: binding
                for turn, binding in zip(
                    job.source_turns,
                    job.source_time_bindings,
                    strict=True,
                )
            },
        )
        covered = {
            sequence for statement in statements for sequence in statement.source_sequences
        }
        expected = {turn.draft.sequence for turn in job.source_turns}
        if covered != expected:
            raise EpisodicMemoryError("diary_provider_output_coverage_incomplete")
        digest = semantic_digest(
            "myuna-p07-reflective-diary-candidate-v1",
            {
                "entry": entry.payload(),
                "job_digest": job.job_digest,
                "schema": DIARY_GENERATION_CANDIDATE_SCHEMA,
            },
        )
        return cls(job.job_digest, entry, digest)


class DiaryProviderPort(Protocol):
    def generate_diary(
        self,
        messages: tuple[Mapping[str, str], ...],
        *,
        timeout_seconds: float,
    ) -> str: ...


@dataclass(frozen=True, slots=True)
class DiaryGenerationResult:
    status: str
    job_digest: str
    capacity: DiaryCapacityReceipt
    provider_called: bool
    candidate: DiaryGenerationCandidate | None = None

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


class ReflectiveDiaryGenerationCoordinator:
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
        job: DiaryGenerationJob,
        *,
        persona_context: str,
        provider: DiaryProviderPort,
        created_at_utc,
        timeout_seconds: float = DIARY_PROVIDER_TIMEOUT_SECONDS,
    ) -> DiaryGenerationResult:
        messages = diary_provider_messages(job, persona_context=persona_context)
        capacity = evaluate_diary_capacity(
            messages,
            limits=self.limits,
            token_counter=self.token_counter,
        )
        if not capacity.fit:
            return DiaryGenerationResult(
                "coverage_incomplete",
                job.job_digest,
                capacity,
                False,
            )
        try:
            generated = provider.generate_diary(
                messages,
                timeout_seconds=timeout_seconds,
            )
        except (OSError, RuntimeError, TimeoutError):
            raise EpisodicMemoryError(
                "diary_provider_unavailable",
                retryable=True,
            ) from None
        candidate = DiaryGenerationCandidate.from_provider_text(
            generated,
            job=job,
            created_at_utc=created_at_utc,
        )
        return DiaryGenerationResult(
            "completed",
            job.job_digest,
            capacity,
            True,
            candidate,
        )
