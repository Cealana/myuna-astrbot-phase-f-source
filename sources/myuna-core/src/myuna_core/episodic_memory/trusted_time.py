from __future__ import annotations

from datetime import datetime, timedelta
from hashlib import sha256
from typing import Protocol
from zoneinfo import ZoneInfo

from myuna_core.active_temporal_context.time import TrustedTimePort, TrustedTimeSample
from myuna_core.trusted_time.contracts import TrustedTimeWatermark, UtcObservation
from myuna_core.trusted_time.errors import TrustedTimeError
from myuna_core.trusted_time.source import SystemUtcObservationSource

from .contracts import (
    DEFAULT_CALENDAR_ZONE,
    EpisodicMemoryError,
    TurnTimeBinding,
    require_id,
    require_utc,
)


TRUSTED_TIME_CONTEXT_SCHEMA = "myuna.p07-trusted-current-time-context.v1"


class TrustedTimeEvidencePort(Protocol):
    """Read-only evidence paired with the one P10-B sample; it never polls."""

    def evidence_for_sample(
        self, sample: TrustedTimeSample
    ) -> tuple[UtcObservation, TrustedTimeWatermark]: ...


def read_current_boot_identity() -> str | None:
    """Read the local kernel boot identity through the existing trusted source seam."""

    try:
        return require_id(
            SystemUtcObservationSource._linux_boot_id(),
            "delivery_callback_boot_id",
        )
    except (TrustedTimeError, EpisodicMemoryError):
        return None


def _estimate(sample: UtcObservation, monotonic_ns: int) -> datetime:
    delta = monotonic_ns - sample.monotonic_ns
    return sample.instant + timedelta(microseconds=delta / 1_000)


def bind_prompt_time_sample(
    sample: TrustedTimeSample,
    *,
    received_monotonic_ns: int,
    calendar_zone: str = DEFAULT_CALENDAR_ZONE,
) -> TurnTimeBinding:
    """Bind the one pre-provider sample used for both prompt and final archive time."""

    if not sample.evidence_complete or sample.synchronized is not True:
        raise EpisodicMemoryError("trusted_time_evidence_unavailable")
    assert sample.monotonic_ns is not None
    assert sample.uncertainty_microseconds is not None
    assert sample.authority is not None
    assert sample.boot_id is not None
    if received_monotonic_ns > sample.monotonic_ns:
        raise EpisodicMemoryError("trusted_time_sample_precedes_received")
    received = sample.instant + timedelta(
        microseconds=(received_monotonic_ns - sample.monotonic_ns) / 1_000
    )
    local = sample.instant.astimezone(ZoneInfo(calendar_zone))
    offset = local.utcoffset()
    if offset is None:
        raise EpisodicMemoryError("timezone_database_unavailable")
    return TurnTimeBinding(
        status="exact",
        calendar_zone=calendar_zone,
        received_monotonic_ns=received_monotonic_ns,
        committed_monotonic_ns=sample.monotonic_ns,
        delivered_monotonic_ns=sample.monotonic_ns,
        sample_instant_utc=sample.instant,
        received_at_utc=received,
        committed_at_utc=sample.instant,
        delivered_at_utc=sample.instant,
        local_calendar_representation=local.isoformat(timespec="microseconds"),
        event_offset_minutes=int(offset.total_seconds() // 60),
        uncertainty_microseconds=sample.uncertainty_microseconds,
        synchronized=True,
        source=sample.source,
        source_class=sample.source_class,
        authority=sample.authority,
        boot_id=sample.boot_id,
        sequence=sample.sequence,
        sample_monotonic_ns=sample.monotonic_ns,
        quality_codes=("trusted_exact", "single_pre_provider_sample"),
    )


def finalize_prompt_time_binding(
    prompt_binding: TurnTimeBinding,
    *,
    committed_monotonic_ns: int,
    delivered_monotonic_ns: int,
    maximum_turn_duration: timedelta = timedelta(minutes=3),
) -> TurnTimeBinding:
    if not (
        prompt_binding.received_monotonic_ns
        <= committed_monotonic_ns
        <= delivered_monotonic_ns
    ):
        raise EpisodicMemoryError("turn_lifecycle_order_invalid")
    if (
        delivered_monotonic_ns - prompt_binding.received_monotonic_ns
        > int(maximum_turn_duration.total_seconds() * 1_000_000_000)
    ):
        raise EpisodicMemoryError("turn_duration_out_of_contract")
    if prompt_binding.status == "unresolved":
        return TurnTimeBinding(
            status="unresolved",
            calendar_zone=prompt_binding.calendar_zone,
            received_monotonic_ns=prompt_binding.received_monotonic_ns,
            committed_monotonic_ns=committed_monotonic_ns,
            delivered_monotonic_ns=delivered_monotonic_ns,
            unresolved_interval_start_utc=prompt_binding.unresolved_interval_start_utc,
            unresolved_interval_end_utc=prompt_binding.unresolved_interval_end_utc,
            quality_codes=prompt_binding.quality_codes,
        )
    assert prompt_binding.sample_instant_utc is not None
    assert prompt_binding.sample_monotonic_ns is not None
    assert prompt_binding.uncertainty_microseconds is not None
    assert prompt_binding.source is not None
    assert prompt_binding.source_class is not None
    assert prompt_binding.authority is not None
    assert prompt_binding.boot_id is not None
    assert prompt_binding.sequence is not None
    def estimate(monotonic_ns: int) -> datetime:
        return prompt_binding.sample_instant_utc + timedelta(
            microseconds=(monotonic_ns - prompt_binding.sample_monotonic_ns) / 1_000
        )

    received = estimate(prompt_binding.received_monotonic_ns)
    committed = estimate(committed_monotonic_ns)
    delivered = estimate(delivered_monotonic_ns)
    local = delivered.astimezone(ZoneInfo(prompt_binding.calendar_zone))
    offset = local.utcoffset()
    if offset is None:
        raise EpisodicMemoryError("timezone_database_unavailable")
    return TurnTimeBinding(
        status="exact",
        calendar_zone=prompt_binding.calendar_zone,
        received_monotonic_ns=prompt_binding.received_monotonic_ns,
        committed_monotonic_ns=committed_monotonic_ns,
        delivered_monotonic_ns=delivered_monotonic_ns,
        sample_instant_utc=prompt_binding.sample_instant_utc,
        received_at_utc=received,
        committed_at_utc=committed,
        delivered_at_utc=delivered,
        local_calendar_representation=local.isoformat(timespec="microseconds"),
        event_offset_minutes=int(offset.total_seconds() // 60),
        uncertainty_microseconds=prompt_binding.uncertainty_microseconds,
        synchronized=True,
        source=prompt_binding.source,
        source_class=prompt_binding.source_class,
        authority=prompt_binding.authority,
        boot_id=prompt_binding.boot_id,
        sequence=prompt_binding.sequence,
        sample_monotonic_ns=prompt_binding.sample_monotonic_ns,
        quality_codes=prompt_binding.quality_codes,
    )


def finalize_delivery_time_binding(
    prompt_binding: TurnTimeBinding,
    *,
    committed_monotonic_ns: int,
    delivered_monotonic_ns: int | None,
    delivered_boot_id: str | None,
    maximum_turn_duration: timedelta = timedelta(minutes=3),
) -> TurnTimeBinding:
    """Finalize explicit close evidence without sampling an implicit clock."""

    continuity_reason: str | None = None
    if delivered_boot_id is None:
        continuity_reason = "delivery_boot_continuity_unproven"
    else:
        try:
            require_id(delivered_boot_id, "delivery_callback_boot_id")
        except EpisodicMemoryError:
            continuity_reason = "delivery_callback_boot_identity_malformed"
        else:
            if prompt_binding.boot_id is None:
                continuity_reason = "delivery_boot_continuity_unproven"
            elif delivered_boot_id != prompt_binding.boot_id:
                continuity_reason = "delivery_callback_boot_identity_mismatched"
    if delivered_monotonic_ns is None or continuity_reason is not None:
        reasons = (
            (() if delivered_monotonic_ns is not None else ("delivery_close_evidence_missing",))
            + (() if continuity_reason is None else (continuity_reason,))
        )
        return TurnTimeBinding(
            status="unresolved",
            calendar_zone=prompt_binding.calendar_zone,
            received_monotonic_ns=prompt_binding.received_monotonic_ns,
            committed_monotonic_ns=committed_monotonic_ns,
            delivered_monotonic_ns=committed_monotonic_ns,
            quality_codes=tuple(
                dict.fromkeys(
                    prompt_binding.quality_codes + reasons
                )
            ),
        )
    try:
        selected = finalize_prompt_time_binding(
            prompt_binding,
            committed_monotonic_ns=committed_monotonic_ns,
            delivered_monotonic_ns=delivered_monotonic_ns,
            maximum_turn_duration=maximum_turn_duration,
        )
    except EpisodicMemoryError as exc:
        reason_by_code = {
            "turn_lifecycle_order_invalid": "delivery_close_monotonic_regression",
            "turn_duration_out_of_contract": "delivery_close_duration_out_of_contract",
            "timezone_database_unavailable": "delivery_calendar_resolution_unavailable",
        }
        reason = reason_by_code.get(exc.code)
        if reason is None:
            raise
        return TurnTimeBinding(
            status="unresolved",
            calendar_zone=prompt_binding.calendar_zone,
            received_monotonic_ns=prompt_binding.received_monotonic_ns,
            committed_monotonic_ns=committed_monotonic_ns,
            delivered_monotonic_ns=committed_monotonic_ns,
            quality_codes=tuple(
                dict.fromkeys(prompt_binding.quality_codes + (reason,))
            ),
        )
    if selected.status == "exact":
        return selected
    return TurnTimeBinding(
        status="unresolved",
        calendar_zone=selected.calendar_zone,
        received_monotonic_ns=selected.received_monotonic_ns,
        committed_monotonic_ns=selected.committed_monotonic_ns,
        delivered_monotonic_ns=selected.delivered_monotonic_ns,
        unresolved_interval_start_utc=selected.unresolved_interval_start_utc,
        unresolved_interval_end_utc=selected.unresolved_interval_end_utc,
        quality_codes=tuple(
            dict.fromkeys(selected.quality_codes + ("delivery_close_observed",))
        ),
    )


def bind_exact_turn_time(
    *,
    sample: TrustedTimeSample,
    observation: UtcObservation,
    watermark: TrustedTimeWatermark,
    received_monotonic_ns: int,
    committed_monotonic_ns: int,
    delivered_monotonic_ns: int,
    captured_at_utc: datetime,
    calendar_zone: str = DEFAULT_CALENDAR_ZONE,
    maximum_age: timedelta = timedelta(seconds=2),
    maximum_uncertainty: timedelta = timedelta(seconds=1),
    maximum_turn_duration: timedelta = timedelta(minutes=3),
    previous: TurnTimeBinding | None = None,
) -> TurnTimeBinding:
    captured = require_utc(captured_at_utc, "trusted_time_captured_at")
    if (
        not observation.evidence.synchronized
        or observation.evidence.uncertainty > maximum_uncertainty
        or sample.instant != observation.instant
        or watermark.instant != sample.instant
        or watermark.source != sample.source
        or watermark.sequence != sample.sequence
        or sample.sequence < 1
    ):
        raise EpisodicMemoryError("trusted_time_binding_mismatch")
    age = captured - sample.instant
    if age < timedelta(0) or age > maximum_age:
        raise EpisodicMemoryError("trusted_time_stale")
    if not 0 <= received_monotonic_ns <= committed_monotonic_ns <= delivered_monotonic_ns:
        raise EpisodicMemoryError("turn_lifecycle_order_invalid")
    if (
        abs(delivered_monotonic_ns - observation.monotonic_ns)
        > int(maximum_turn_duration.total_seconds() * 1_000_000_000)
    ):
        raise EpisodicMemoryError("turn_duration_out_of_contract")
    if previous is not None and previous.status == "exact":
        assert previous.sequence is not None
        assert previous.sample_instant_utc is not None
        assert previous.source is not None
        if sample.source != previous.source:
            raise EpisodicMemoryError("trusted_time_source_drift")
        if sample.sequence <= previous.sequence:
            raise EpisodicMemoryError("trusted_time_sequence_regression")
        if sample.instant < previous.sample_instant_utc:
            raise EpisodicMemoryError("trusted_time_regression")
        if previous.boot_id == observation.boot_id:
            assert previous.sample_monotonic_ns is not None
            if observation.monotonic_ns <= previous.sample_monotonic_ns:
                raise EpisodicMemoryError("trusted_time_monotonic_regression")
    received = _estimate(observation, received_monotonic_ns)
    committed = _estimate(observation, committed_monotonic_ns)
    delivered = _estimate(observation, delivered_monotonic_ns)
    local = delivered.astimezone(ZoneInfo(calendar_zone))
    offset = local.utcoffset()
    if offset is None:
        raise EpisodicMemoryError("timezone_database_unavailable")
    return TurnTimeBinding(
        status="exact",
        calendar_zone=calendar_zone,
        received_monotonic_ns=received_monotonic_ns,
        committed_monotonic_ns=committed_monotonic_ns,
        delivered_monotonic_ns=delivered_monotonic_ns,
        sample_instant_utc=sample.instant,
        received_at_utc=received,
        committed_at_utc=committed,
        delivered_at_utc=delivered,
        local_calendar_representation=local.isoformat(timespec="microseconds"),
        event_offset_minutes=int(offset.total_seconds() // 60),
        uncertainty_microseconds=int(
            observation.evidence.uncertainty.total_seconds() * 1_000_000
        ),
        synchronized=True,
        source=sample.source,
        source_class=sample.source_class,
        authority=observation.evidence.authority,
        boot_id=observation.boot_id,
        sequence=sample.sequence,
        sample_monotonic_ns=observation.monotonic_ns,
        quality_codes=("trusted_exact",),
    )


def sample_once_and_bind(
    *,
    port: TrustedTimePort,
    evidence_port: TrustedTimeEvidencePort,
    received_monotonic_ns: int,
    committed_monotonic_ns: int,
    delivered_monotonic_ns: int,
    captured_at_utc: datetime,
    calendar_zone: str = DEFAULT_CALENDAR_ZONE,
    previous: TurnTimeBinding | None = None,
) -> TurnTimeBinding:
    sample = port.sample()
    observation, watermark = evidence_port.evidence_for_sample(sample)
    return bind_exact_turn_time(
        sample=sample,
        observation=observation,
        watermark=watermark,
        received_monotonic_ns=received_monotonic_ns,
        committed_monotonic_ns=committed_monotonic_ns,
        delivered_monotonic_ns=delivered_monotonic_ns,
        captured_at_utc=captured_at_utc,
        calendar_zone=calendar_zone,
        previous=previous,
    )


def unresolved_turn_time(
    *,
    reason_code: str,
    received_monotonic_ns: int,
    committed_monotonic_ns: int,
    delivered_monotonic_ns: int,
    calendar_zone: str = DEFAULT_CALENDAR_ZONE,
    interval_start_utc: datetime | None = None,
    interval_end_utc: datetime | None = None,
) -> TurnTimeBinding:
    return TurnTimeBinding(
        status="unresolved",
        calendar_zone=calendar_zone,
        received_monotonic_ns=received_monotonic_ns,
        committed_monotonic_ns=committed_monotonic_ns,
        delivered_monotonic_ns=delivered_monotonic_ns,
        unresolved_interval_start_utc=interval_start_utc,
        unresolved_interval_end_utc=interval_end_utc,
        quality_codes=(reason_code,),
    )


def render_trusted_current_time(binding: TurnTimeBinding) -> str:
    if binding.status == "unresolved":
        return (
            f"[trusted_current_time schema={TRUSTED_TIME_CONTEXT_SCHEMA} "
            f"status=unresolved zone={binding.calendar_zone} "
            "exact_calendar_claim_allowed=false]"
        )
    return (
        f"[trusted_current_time schema={TRUSTED_TIME_CONTEXT_SCHEMA} status=exact "
        f"utc={binding.delivered_at_utc.isoformat(timespec='seconds')} "  # type: ignore[union-attr]
        f"local={binding.local_calendar_representation} zone={binding.calendar_zone} "
        f"uncertainty_us={binding.uncertainty_microseconds} source={binding.source} "
        f"sequence={binding.sequence} exact_calendar_claim_allowed=true]"
    )


def trusted_time_audit(binding: TurnTimeBinding) -> dict[str, object]:
    return {
        "binding_digest": binding.binding_digest,
        "boot_identity_digest": (
            None
            if binding.boot_id is None
            else sha256(binding.boot_id.encode("utf-8")).hexdigest()
        ),
        "calendar_zone": binding.calendar_zone,
        "exact_calendar_claim_allowed": binding.status == "exact",
        "quality_codes": list(binding.quality_codes),
        "sequence": binding.sequence,
        "source_class": binding.source_class,
        "status": binding.status,
        "uncertainty_microseconds": binding.uncertainty_microseconds,
    }
