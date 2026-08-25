from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import json
from typing import Callable, Mapping, Sequence

from .contracts import (
    CONTEXT_POLICY_DYNAMIC_PREFIX,
    CONTEXT_POLICY_NO_SUMMARY,
    CONTEXT_POLICY_RAW_FIRST,
    CompleteTurn,
    EpisodicMemoryError,
    PrefixCapsule,
    PrefixCompactionPolicy,
    TurnTimeBinding,
    canonical_bytes,
    prefix_capsule_source_closure_digest,
)
from .trusted_time import render_trusted_current_time
from .temporal_validity import TemporalValidityProjection


def _verify_complete_turn_chain(turns: Sequence[CompleteTurn]) -> None:
    previous = "0" * 64
    for expected_sequence, turn in enumerate(turns, start=1):
        if (
            turn.draft.sequence != expected_sequence
            or turn.draft.previous_turn_digest != previous
        ):
            raise EpisodicMemoryError("archive_turn_chain_drifted")
        previous = turn.turn_digest


def _verify_archive_eligible_chain(
    archive_turns: Sequence[CompleteTurn],
    eligible_turns: Sequence[CompleteTurn],
) -> None:
    _verify_complete_turn_chain(archive_turns)
    expected = tuple(turn for turn in archive_turns if turn.model_history_eligible)
    if tuple(eligible_turns) != expected:
        raise EpisodicMemoryError("archive_eligible_turn_chain_drifted")


@dataclass(frozen=True, slots=True)
class ContextLimits:
    request_characters: int = 200_000
    projection_characters: int = 199_000
    serialized_bytes: int = 1_198_096
    input_tokens: int = 999_232
    output_reserve_characters: int = 4_000
    output_reserve_bytes: int = 16_000
    output_reserve_tokens: int = 4_000

    def __post_init__(self) -> None:
        for value in (
            self.request_characters,
            self.projection_characters,
            self.serialized_bytes,
            self.input_tokens,
            self.output_reserve_characters,
            self.output_reserve_bytes,
            self.output_reserve_tokens,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise EpisodicMemoryError("context_limit_invalid")


@dataclass(frozen=True, slots=True)
class ContextOccupancy:
    policy_version: str
    total_complete_turns: int
    projected_complete_turns: int
    raw_history_characters: int
    fixed_context_characters: int
    current_turn_characters: int
    projection_characters: int
    request_characters: int
    serialized_bytes: int
    input_tokens: int
    request_headroom: int
    projection_headroom: int
    serialized_headroom: int
    token_headroom: int
    limiting_oracle: str | None
    fit: bool
    summary_used: bool = False
    capsule_used_count: int = 0

    def audit_projection(self) -> dict[str, object]:
        return {
            "capsule_used_count": self.capsule_used_count,
            "current_turn_characters": self.current_turn_characters,
            "fit": self.fit,
            "fixed_context_characters": self.fixed_context_characters,
            "input_tokens": self.input_tokens,
            "limiting_oracle": self.limiting_oracle,
            "policy_version": self.policy_version,
            "projected_complete_turns": self.projected_complete_turns,
            "projection_characters": self.projection_characters,
            "projection_headroom": self.projection_headroom,
            "raw_history_characters": self.raw_history_characters,
            "request_characters": self.request_characters,
            "request_headroom": self.request_headroom,
            "serialized_bytes": self.serialized_bytes,
            "serialized_headroom": self.serialized_headroom,
            "summary_used": self.summary_used,
            "token_headroom": self.token_headroom,
            "total_complete_turns": self.total_complete_turns,
        }


@dataclass(frozen=True, slots=True)
class ContextProjection:
    messages: tuple[Mapping[str, str], ...]
    selected_sequences: tuple[int, ...]
    occupancy: ContextOccupancy
    projection_digest: str


@dataclass(frozen=True, slots=True)
class PrefixCompactionPlan:
    action: str
    policy_version: str
    capsule: PrefixCapsule | None
    raw_turns: tuple[CompleteTurn, ...]
    prefix_end: int
    recent_tail_start: int
    overflow_action: str | None
    reason_code: str
    occupancy: ContextOccupancy

    def __post_init__(self) -> None:
        if self.action not in {
            "all_raw",
            "generate_prefix_capsule",
            "prefix_capsule",
            "overflow",
        }:
            raise EpisodicMemoryError("prefix_plan_action_invalid")
        if self.policy_version != CONTEXT_POLICY_DYNAMIC_PREFIX:
            raise EpisodicMemoryError("prefix_plan_policy_invalid")
        if self.action == "prefix_capsule":
            if self.capsule is None or self.prefix_end != self.capsule.source_end:
                raise EpisodicMemoryError("prefix_plan_capsule_missing")
            if self.overflow_action is not None:
                raise EpisodicMemoryError("prefix_plan_overflow_conflict")
        elif self.action == "generate_prefix_capsule":
            if self.capsule is not None or self.prefix_end < 1:
                raise EpisodicMemoryError("prefix_plan_generation_invalid")
            if self.overflow_action is not None:
                raise EpisodicMemoryError("prefix_plan_overflow_conflict")
        elif self.capsule is not None:
            raise EpisodicMemoryError("prefix_plan_unexpected_capsule")
        if self.action == "overflow" and self.overflow_action is None:
            raise EpisodicMemoryError("prefix_plan_overflow_missing")
        if self.action != "overflow" and not self.occupancy.fit:
            raise EpisodicMemoryError("prefix_plan_capacity_invalid")

    def audit_projection(self) -> dict[str, object]:
        return {
            "action": self.action,
            "capsule_digest": (
                None if self.capsule is None else self.capsule.capsule_digest
            ),
            "overflow_action": self.overflow_action,
            "policy_version": self.policy_version,
            "prefix_end": self.prefix_end,
            "raw_turn_count": len(self.raw_turns),
            "reason_code": self.reason_code,
            "recent_tail_start": self.recent_tail_start,
        }


def _target_headroom_met(
    occupancy: ContextOccupancy,
    policy: PrefixCompactionPolicy,
) -> bool:
    return (
        occupancy.fit
        and occupancy.projection_headroom >= policy.target_character_headroom
        and occupancy.serialized_headroom >= policy.target_byte_headroom
        and occupancy.token_headroom >= policy.target_token_headroom
    )


def _raw_messages(turns: Sequence[CompleteTurn]) -> tuple[Mapping[str, str], ...]:
    result: list[Mapping[str, str]] = []
    for turn in turns:
        result.extend(
            (
                {"role": "user", "content": turn.draft.owner.text},
                {"role": "assistant", "content": turn.draft.assistant.text},
            )
        )
    return tuple(result)


def count_offline_token_units(
    token_counter: Callable[[tuple[Mapping[str, str], ...]], int] | None,
    messages: tuple[Mapping[str, str], ...],
) -> int:
    if token_counter is None:
        raise EpisodicMemoryError("token_capacity_oracle_unavailable")
    try:
        result = token_counter(messages)
    except Exception:
        raise EpisodicMemoryError("token_capacity_oracle_unavailable") from None
    if isinstance(result, bool) or not isinstance(result, int) or result < 0:
        raise EpisodicMemoryError("token_capacity_oracle_unavailable")
    return result


def next_prefix_overflow_action(
    policy: PrefixCompactionPolicy,
    completed_actions: Sequence[str],
) -> str:
    completed = tuple(completed_actions)
    if (
        len(completed) >= len(policy.overflow_actions)
        or completed != policy.overflow_actions[: len(completed)]
    ):
        raise EpisodicMemoryError("prefix_overflow_progress_rejected")
    return policy.overflow_actions[len(completed)]


def verify_prefix_capsule(
    capsule: PrefixCapsule,
    *,
    turns: Sequence[CompleteTurn],
    archive_id: str,
    archive_head_digest: str,
    policy: PrefixCompactionPolicy,
    token_counter: Callable[[tuple[Mapping[str, str], ...]], int] | None,
    expected_generator_version: str,
    expected_model_provider_class: str,
    expected_created_at_utc: datetime,
) -> tuple[PrefixCapsule, str]:
    try:
        submitted_payload = capsule.payload()
        canonical_capsule = PrefixCapsule.from_payload(submitted_payload)
        if canonical_bytes(submitted_payload) != canonical_bytes(
            canonical_capsule.payload()
        ):
            raise EpisodicMemoryError("prefix_capsule_primitive_type_invalid")
    except EpisodicMemoryError:
        raise
    except (AttributeError, TypeError, UnicodeError, ValueError):
        raise EpisodicMemoryError("prefix_capsule_primitive_type_invalid") from None
    capsule = canonical_capsule
    _verify_complete_turn_chain(turns)
    if (
        not turns
        or turns[-1].turn_digest != archive_head_digest
        or capsule.archive_id != archive_id
        or capsule.source_snapshot_turn_count > len(turns)
        or turns[capsule.source_snapshot_turn_count - 1].turn_digest
        != capsule.source_snapshot_head_digest
        or capsule.policy_version != policy.policy_version
        or capsule.policy_digest != policy.policy_digest
        or capsule.token_oracle_id != policy.token_oracle_id
        or capsule.generator_version != expected_generator_version
        or capsule.model_provider_class != expected_model_provider_class
        or capsule.created_at_utc != expected_created_at_utc
        or capsule.risk_class not in policy.permitted_risk_classes
        or not capsule.projection_eligible
        or capsule.source_start != 1
        or capsule.source_end > len(turns)
        or capsule.source_end > policy.maximum_source_turns
    ):
        raise EpisodicMemoryError("prefix_capsule_source_binding_mismatch")
    source = tuple(turns[: capsule.source_end])
    if (
        not source
        or any(turn.draft.epoch_id != capsule.epoch_id for turn in source)
        or capsule.source_turn_ids != tuple(turn.draft.turn_id for turn in source)
        or capsule.source_turn_digests != tuple(turn.turn_digest for turn in source)
        or capsule.source_original_zones
        != tuple(turn.draft.time_binding.calendar_zone for turn in source)
        or capsule.source_time_start_utc
        != source[0].draft.time_binding.delivered_at_utc
        or capsule.source_time_end_utc
        != source[-1].draft.time_binding.delivered_at_utc
    ):
        raise EpisodicMemoryError("prefix_capsule_source_binding_mismatch")
    eligible_source = tuple(turn for turn in source if turn.model_history_eligible)
    if not eligible_source:
        raise EpisodicMemoryError("prefix_capsule_eligible_source_empty")
    source_characters = sum(
        len(turn.draft.owner.text) + len(turn.draft.assistant.text)
        for turn in eligible_source
    )
    source_bytes = sum(
        len(turn.draft.owner.text.encode("utf-8"))
        + len(turn.draft.assistant.text.encode("utf-8"))
        for turn in eligible_source
    )
    source_tokens = count_offline_token_units(
        token_counter,
        _raw_messages(eligible_source),
    )
    capsule_tokens = count_offline_token_units(
        token_counter,
        ({"role": "assistant", "content": capsule.capsule_text},),
    )
    capsule_characters = len(capsule.capsule_text)
    try:
        capsule_bytes = len(capsule.capsule_text.encode("utf-8"))
    except UnicodeEncodeError:
        raise EpisodicMemoryError("prefix_capsule_capacity_binding_mismatch") from None
    if capsule_characters < 1 or capsule_bytes < 1 or capsule_tokens < 1:
        raise EpisodicMemoryError("prefix_capsule_capacity_binding_mismatch")
    expected_ratios = (
        source_characters * 1_000 // capsule_characters,
        source_bytes * 1_000 // capsule_bytes,
        source_tokens * 1_000 // capsule_tokens,
    )
    if (
        capsule.source_characters != source_characters
        or capsule.source_bytes != source_bytes
        or capsule.source_tokens != source_tokens
        or capsule.capsule_characters != capsule_characters
        or capsule.capsule_bytes != capsule_bytes
        or capsule.capsule_tokens != capsule_tokens
        or (
            capsule.character_ratio_milli,
            capsule.byte_ratio_milli,
            capsule.token_ratio_milli,
        )
        != expected_ratios
        or capsule_characters > policy.maximum_capsule_characters
        or capsule_bytes > policy.maximum_capsule_bytes
        or capsule_tokens > policy.maximum_capsule_tokens
        or expected_ratios[0] > policy.hard_character_ratio * 1000
        or expected_ratios[1] > policy.hard_byte_ratio * 1000
        or expected_ratios[2] > policy.hard_token_ratio * 1000
    ):
        raise EpisodicMemoryError("prefix_capsule_capacity_binding_mismatch")
    return (
        capsule,
        prefix_capsule_source_closure_digest(
            archive_id=archive_id,
            archive_head_digest=archive_head_digest,
            archive_turn_count=len(turns),
            source_end=capsule.source_end,
            source_turn_ids=tuple(turn.draft.turn_id for turn in source),
            source_turn_digests=tuple(turn.turn_digest for turn in source),
            eligible_source_turn_ids=tuple(
                turn.draft.turn_id for turn in eligible_source
            ),
        ),
    )


def plan_dynamic_prefix(
    *,
    archive_turns: Sequence[CompleteTurn],
    turns: Sequence[CompleteTurn],
    required_sequences: Sequence[int],
    capsules: Sequence[PrefixCapsule],
    archive_id: str,
    archive_head_digest: str,
    risk_class: str,
    source_sensitive_claim: bool,
    completed_overflow_actions: Sequence[str] = (),
    policy: PrefixCompactionPolicy,
    token_counter: Callable[[tuple[Mapping[str, str], ...]], int] | None,
    evaluate: Callable[[PrefixCapsule | None, tuple[CompleteTurn, ...]], ContextOccupancy],
    evaluate_envelope: Callable[[int, tuple[CompleteTurn, ...]], ContextOccupancy],
    expected_generator_version: str,
    expected_model_provider_class: str,
    expected_created_at_utc: datetime,
) -> PrefixCompactionPlan:
    """Select one boundary from a deterministic envelope before reuse/generation."""

    _verify_archive_eligible_chain(archive_turns, turns)
    if not archive_turns:
        occupancy = evaluate(None, ())
        return PrefixCompactionPlan(
            "all_raw",
            policy.policy_version,
            None,
            (),
            0,
            1,
            None,
            "complete_raw_empty",
            occupancy,
        )
    if archive_turns[-1].turn_digest != archive_head_digest:
        raise EpisodicMemoryError("archive_turn_chain_drifted")
    eligible_sequences = {turn.draft.sequence for turn in turns}
    required = tuple(sorted(set(required_sequences)))
    if required != tuple(required_sequences) or any(
        isinstance(value, bool) or value not in eligible_sequences
        for value in required
    ):
        raise EpisodicMemoryError("prefix_required_sequence_invalid")
    all_raw = tuple(turns)
    occupancy = evaluate(None, all_raw)
    if _target_headroom_met(occupancy, policy):
        return PrefixCompactionPlan(
            "all_raw",
            policy.policy_version,
            None,
            all_raw,
            0,
            1,
            None,
            "complete_raw_fit",
            occupancy,
        )
    if source_sensitive_claim and not required:
        return PrefixCompactionPlan(
            "overflow",
            policy.policy_version,
            None,
            (),
            0,
            len(turns) + 1,
            next_prefix_overflow_action(policy, completed_overflow_actions),
            "mandatory_raw_search_fetch_required",
            occupancy,
        )
    if risk_class not in policy.permitted_risk_classes:
        return PrefixCompactionPlan(
            "overflow",
            policy.policy_version,
            None,
            (),
            0,
            len(turns) + 1,
            next_prefix_overflow_action(policy, completed_overflow_actions),
            "capsule_risk_class_prohibited",
            occupancy,
        )
    by_sequence = {turn.draft.sequence: turn for turn in turns}
    total_raw_characters = sum(
        len(turn.draft.owner.text) + len(turn.draft.assistant.text)
        for turn in turns
    )
    total_raw_tokens = count_offline_token_units(
        token_counter,
        _raw_messages(turns),
    )
    max_end = min(
        policy.maximum_source_turns,
        archive_turns[-1].draft.sequence,
    )
    selected_end = 0
    selected_raw: tuple[CompleteTurn, ...] = ()
    selected_occupancy: ContextOccupancy | None = None
    for prefix_end in range(1, max_end + 1):
        source = tuple(
            turn for turn in turns if turn.draft.sequence <= prefix_end
        )
        if not source:
            continue
        tail = tuple(
            turn for turn in turns if turn.draft.sequence > prefix_end
        )
        tail_characters = sum(
            len(turn.draft.owner.text) + len(turn.draft.assistant.text)
            for turn in tail
        )
        tail_tokens = count_offline_token_units(
            token_counter,
            _raw_messages(tail),
        )
        if (
            len(tail) < min(policy.minimum_recent_raw_turns, len(turns))
            or tail_characters
            < min(policy.minimum_recent_raw_characters, total_raw_characters)
            or tail_tokens < min(policy.minimum_recent_raw_tokens, total_raw_tokens)
        ):
            continue
        raw_numbers = set(required) | {
            turn.draft.sequence for turn in tail
        }
        raw = tuple(by_sequence[number] for number in sorted(raw_numbers))
        candidate_occupancy = evaluate_envelope(prefix_end, raw)
        if (
            not isinstance(candidate_occupancy, ContextOccupancy)
            or candidate_occupancy.policy_version != policy.policy_version
            or candidate_occupancy.summary_used
            or candidate_occupancy.capsule_used_count != 1
        ):
            raise EpisodicMemoryError("prefix_capsule_envelope_invalid")
        if _target_headroom_met(candidate_occupancy, policy):
            selected_end = prefix_end
            selected_raw = raw
            selected_occupancy = candidate_occupancy
            break
    if selected_occupancy is None:
        return PrefixCompactionPlan(
            "overflow",
            policy.policy_version,
            None,
            (),
            0,
            archive_turns[-1].draft.sequence + 1,
            next_prefix_overflow_action(policy, completed_overflow_actions),
            "no_declared_prefix_envelope_fit",
            occupancy,
        )
    matching = tuple(
        capsule for capsule in capsules if capsule.source_end == selected_end
    )
    if len(matching) > 1:
        raise EpisodicMemoryError("prefix_capsule_range_conflict")
    if not matching:
        return PrefixCompactionPlan(
            "generate_prefix_capsule",
            policy.policy_version,
            None,
            selected_raw,
            selected_end,
            selected_end + 1,
            None,
            "minimum_prefix_generation_required",
            selected_occupancy,
        )
    capsule = matching[0]
    capsule, _ = verify_prefix_capsule(
        capsule,
        turns=archive_turns,
        archive_id=archive_id,
        archive_head_digest=archive_head_digest,
        policy=policy,
        token_counter=token_counter,
        expected_generator_version=expected_generator_version,
        expected_model_provider_class=expected_model_provider_class,
        expected_created_at_utc=expected_created_at_utc,
    )
    actual_occupancy = evaluate(capsule, selected_raw)
    if not _target_headroom_met(actual_occupancy, policy):
        return PrefixCompactionPlan(
            "generate_prefix_capsule",
            policy.policy_version,
            None,
            selected_raw,
            selected_end,
            selected_end + 1,
            None,
            "selected_prefix_repair_required",
            selected_occupancy,
        )
    return PrefixCompactionPlan(
        "prefix_capsule",
        policy.policy_version,
        capsule,
        selected_raw,
        selected_end,
        selected_end + 1,
        None,
        "minimum_prefix_fit",
        actual_occupancy,
    )


class DynamicContextOracle:
    def __init__(
        self,
        limits: ContextLimits,
        *,
        token_counter: Callable[[tuple[Mapping[str, str], ...]], int] | None,
    ) -> None:
        self.limits = limits
        self.token_counter = token_counter

    def _evaluate(
        self,
        *,
        policy_version: str,
        fixed_messages: Sequence[Mapping[str, str]],
        turns: Sequence[CompleteTurn],
        current_message: str,
        total_turn_count: int,
        trusted_time_binding: TurnTimeBinding,
        temporal_projection: TemporalValidityProjection,
    ) -> ContextProjection:
        if policy_version not in {CONTEXT_POLICY_NO_SUMMARY, CONTEXT_POLICY_RAW_FIRST}:
            raise EpisodicMemoryError("context_policy_unknown")
        if not current_message or "\x00" in current_message:
            raise EpisodicMemoryError("current_message_invalid")
        if not temporal_projection.occupancy.fit:
            raise EpisodicMemoryError("temporal_active_layer_overflow")
        messages: list[Mapping[str, str]] = [
            {"role": "system", "content": render_trusted_current_time(trusted_time_binding)},
            *(
                {"role": "system", "content": fragment}
                for fragment in temporal_projection.fragments
            ),
            *(dict(item) for item in fixed_messages),
        ]
        fixed_chars = sum(len(item.get("content", "")) for item in messages)
        raw_chars = 0
        sequences: list[int] = []
        for turn in turns:
            messages.append({"role": "user", "content": turn.draft.owner.text})
            messages.append({"role": "assistant", "content": turn.draft.assistant.text})
            raw_chars += len(turn.draft.owner.text) + len(turn.draft.assistant.text)
            sequences.append(turn.draft.sequence)
        messages.append({"role": "user", "content": current_message})
        frozen = tuple(messages)
        projection_chars = fixed_chars + raw_chars + len(current_message)
        request_chars = projection_chars + self.limits.output_reserve_characters
        serialized = len(
            json.dumps(
                [dict(item) for item in frozen],
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ) + self.limits.output_reserve_bytes
        tokens = (
            count_offline_token_units(self.token_counter, frozen)
            + self.limits.output_reserve_tokens
        )
        headrooms = {
            "request_characters": self.limits.request_characters - request_chars,
            "projection_characters": self.limits.projection_characters - projection_chars,
            "serialized_bytes": self.limits.serialized_bytes - serialized,
            "input_tokens": self.limits.input_tokens - tokens,
        }
        limiting = min(headrooms, key=headrooms.__getitem__)
        fit = all(value >= 0 for value in headrooms.values())
        occupancy = ContextOccupancy(
            policy_version=policy_version,
            total_complete_turns=total_turn_count,
            projected_complete_turns=len(turns),
            raw_history_characters=raw_chars,
            fixed_context_characters=fixed_chars,
            current_turn_characters=len(current_message),
            projection_characters=projection_chars,
            request_characters=request_chars,
            serialized_bytes=serialized,
            input_tokens=tokens,
            request_headroom=headrooms["request_characters"],
            projection_headroom=headrooms["projection_characters"],
            serialized_headroom=headrooms["serialized_bytes"],
            token_headroom=headrooms["input_tokens"],
            limiting_oracle=None if fit else limiting,
            fit=fit,
        )
        digest = sha256(
            json.dumps(
                [dict(item) for item in frozen],
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        return ContextProjection(frozen, tuple(sequences), occupancy, digest)

    def project_all_or_fail(
        self,
        *,
        fixed_messages: Sequence[Mapping[str, str]],
        turns: Sequence[CompleteTurn],
        current_message: str,
        trusted_time_binding: TurnTimeBinding,
        temporal_projection: TemporalValidityProjection,
    ) -> ContextProjection:
        _verify_complete_turn_chain(turns)
        selected = self._evaluate(
            policy_version=CONTEXT_POLICY_NO_SUMMARY,
            fixed_messages=fixed_messages,
            turns=turns,
            current_message=current_message,
            total_turn_count=len(turns),
            trusted_time_binding=trusted_time_binding,
            temporal_projection=temporal_projection,
        )
        if not selected.occupancy.fit:
            raise EpisodicMemoryError(
                f"context_{selected.occupancy.limiting_oracle}_exceeded"
            )
        return selected

    def project_raw_first(
        self,
        *,
        fixed_messages: Sequence[Mapping[str, str]],
        turns: Sequence[CompleteTurn],
        current_message: str,
        trusted_time_binding: TurnTimeBinding,
        temporal_projection: TemporalValidityProjection,
        relevant_sequences: Sequence[int] = (),
    ) -> ContextProjection:
        _verify_complete_turn_chain(turns)
        all_turns = self._evaluate(
            policy_version=CONTEXT_POLICY_RAW_FIRST,
            fixed_messages=fixed_messages,
            turns=turns,
            current_message=current_message,
            total_turn_count=len(turns),
            trusted_time_binding=trusted_time_binding,
            temporal_projection=temporal_projection,
        )
        if all_turns.occupancy.fit:
            return all_turns
        by_sequence = {turn.draft.sequence: turn for turn in turns}
        required = set(relevant_sequences)
        if not required <= set(by_sequence):
            raise EpisodicMemoryError("context_retrieval_source_missing")
        selected_sequences = set(required)
        required_turns = tuple(by_sequence[value] for value in sorted(required))
        best = self._evaluate(
            policy_version=CONTEXT_POLICY_RAW_FIRST,
            fixed_messages=fixed_messages,
            turns=required_turns,
            current_message=current_message,
            total_turn_count=len(turns),
            trusted_time_binding=trusted_time_binding,
            temporal_projection=temporal_projection,
        )
        if not best.occupancy.fit:
            raise EpisodicMemoryError("context_relevant_raw_budget_limited")
        for turn in reversed(turns):
            if turn.draft.sequence in selected_sequences:
                continue
            selected_sequences.add(turn.draft.sequence)
            candidate_turns = tuple(by_sequence[value] for value in sorted(selected_sequences))
            candidate = self._evaluate(
                policy_version=CONTEXT_POLICY_RAW_FIRST,
                fixed_messages=fixed_messages,
                turns=candidate_turns,
                current_message=current_message,
                total_turn_count=len(turns),
                trusted_time_binding=trusted_time_binding,
                temporal_projection=temporal_projection,
            )
            if candidate.occupancy.fit:
                best = candidate
            else:
                selected_sequences.remove(turn.draft.sequence)
                break
        return best
