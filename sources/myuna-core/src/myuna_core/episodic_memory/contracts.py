from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from typing import Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


ARCHIVE_SCHEMA = "myuna.owner-private-lossless-archive.v1"
INDEX_SCHEMA = "myuna.owner-private-episodic-index.v1"
RETRIEVAL_SCHEMA = "myuna.owner-private-episodic-retrieval.v1"
CONTEXT_POLICY_NO_SUMMARY = "p07-no-summary-diagnostic-v1"
CONTEXT_POLICY_RAW_FIRST = "p07-raw-first-episodic-v1"
CONTEXT_POLICY_DYNAMIC_PREFIX = "myuna.p07.dynamic-raw-first-prefix-compaction.v1"
EGRESS_POLICY_DENY = "p07-episodic-egress-deny-v1"
EGRESS_POLICY_RAW_HYDRATION = "p07-episodic-egress-raw-hydration-v1"
EGRESS_POLICY_HISTORICAL_RAW_RECALL_V1 = "p07-historical-raw-recall-egress-v1"
EGRESS_POLICY_REFLECTIVE_DIARY_V1 = "p07-reflective-diary-egress-v1"
EGRESS_POLICY_OWNER_DAY_PREVIEW_V1 = "p07-owner-day-preview-egress-v1"
CONTROL_ISOLATED_CATEGORY = "control_isolated"
DEFAULT_CALENDAR_ZONE = "Asia/Shanghai"
SUPPORTED_CALENDAR_ZONES = frozenset({DEFAULT_CALENDAR_ZONE, "America/Los_Angeles"})
CALENDAR_ZONE_SELECTION_SCHEMA = "myuna.p07-calendar-zone-selection.v1"
ZERO_DIGEST = "0" * 64

MAX_TURN_TEXT_CHARACTERS = 64_000
MAX_ID_CHARACTERS = 160
MAX_STRUCTURED_ITEMS = 64
MAX_STRUCTURED_ITEM_CHARACTERS = 256

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,159}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class EpisodicMemoryError(RuntimeError):
    """Stable content-free failure for the P07 episodic-memory boundary."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def canonical_bytes(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def semantic_digest(domain: str, payload: Mapping[str, object]) -> str:
    return sha256(domain.encode("ascii") + b"\0" + canonical_bytes(payload)).hexdigest()


def calendar_zone_selection_payload(zone_name: str) -> Mapping[str, object]:
    if zone_name not in SUPPORTED_CALENDAR_ZONES:
        raise EpisodicMemoryError("calendar_zone_selection_unsupported")
    try:
        ZoneInfo(zone_name)
    except ZoneInfoNotFoundError:
        raise EpisodicMemoryError("timezone_database_unavailable") from None
    return {
        "default_zone": DEFAULT_CALENDAR_ZONE,
        "historical_turn_rewrite": False,
        "resample_on_zone_switch": False,
        "schema": CALENDAR_ZONE_SELECTION_SCHEMA,
        "selected_zone": zone_name,
        "supported_zones": sorted(SUPPORTED_CALENDAR_ZONES),
        "trusted_time_port": "myuna.p10b-trusted-time-single-sample.v1",
    }


def calendar_zone_selection_digest(zone_name: str) -> str:
    return semantic_digest(
        "myuna-p07-calendar-zone-selection-v1",
        calendar_zone_selection_payload(zone_name),
    )


HISTORICAL_RAW_RECALL_EGRESS_V1_PAYLOAD: Mapping[str, object] = {
    "audit": "content-free",
    "channel": "telegram",
    "conversation_kind": "private",
    "identity": "authenticated-owner",
    "image_bytes": False,
    "minimum_source_bound_complete_turns": True,
    "over_limit": "coverage_incomplete",
    "provider_route": "existing-deepseek",
    "rollback": "local-only",
    "schema": "myuna.p07-historical-raw-recall-egress-policy.v1",
}
HISTORICAL_RAW_RECALL_EGRESS_V1_DIGEST = semantic_digest(
    "myuna-p07-historical-raw-recall-egress-policy-v1",
    HISTORICAL_RAW_RECALL_EGRESS_V1_PAYLOAD,
)

REFLECTIVE_DIARY_EGRESS_V1_PAYLOAD: Mapping[str, object] = {
    "audit": "content-free",
    "calendar_scope": "one-closed-original-iana-day",
    "channel": "telegram",
    "complete_day_required": True,
    "conversation_kind": "private",
    "identity": "authenticated-owner",
    "image_bytes": False,
    "maximum_provider_calls_per_job_attempt": 1,
    "over_limit_or_incomplete": "pending-coverage-incomplete-no-provider-call",
    "provider_route": "existing-deepseek",
    "raw_authority": "local-lossless-archive",
    "rollback": "local-only-disabled",
    "schema": "myuna.p07-reflective-diary-egress-policy.v1",
    "whole_history_corpus": False,
}
REFLECTIVE_DIARY_EGRESS_V1_DIGEST = semantic_digest(
    "myuna-p07-reflective-diary-egress-policy-v1",
    REFLECTIVE_DIARY_EGRESS_V1_PAYLOAD,
)

OWNER_DAY_PREVIEW_EGRESS_V1_PAYLOAD: Mapping[str, object] = {
    "audit": "content-free",
    "calendar_scope": "one-open-owner-day-as-of-complete-turn-watermark",
    "channel": "telegram",
    "close_or_finalize_day": False,
    "conversation_kind": "private",
    "identity": "authenticated-owner",
    "image_bytes": False,
    "maximum_provider_calls_per_request": 1,
    "out_of_band_message": False,
    "over_limit_or_incomplete": "pending-coverage-incomplete-no-provider-call",
    "provider_route": "existing-deepseek",
    "raw_authority": "local-lossless-archive",
    "rollback": "local-only-disabled",
    "schema": "myuna.p07-owner-day-preview-egress-policy.v1",
    "source_scope": "current-owner-day-through-exact-watermark",
    "whole_history_corpus": False,
}
OWNER_DAY_PREVIEW_EGRESS_V1_DIGEST = semantic_digest(
    "myuna-p07-owner-day-preview-egress-policy-v1",
    OWNER_DAY_PREVIEW_EGRESS_V1_PAYLOAD,
)

REFLECTIVE_DIARY_STYLE_V1_PAYLOAD: Mapping[str, object] = {
    "authority": "derivative-myuna-perspective",
    "candidate_schema": "myuna.p07-reflective-diary-candidate.v1",
    "factual_authority": "source-raw-turns-only",
    "model": "deepseek-v4-flash",
    "model_role": "p07_external_daily_reflective_diary",
    "no_profile_or_p08_mutation": True,
    "source_pointer_coverage": "every-selected-complete-turn",
    "statement_kinds": [
        "factual_observation",
        "interpretation_reflection",
        "uncertainty",
        "intention",
    ],
    "style": "myuna-current-persona",
}
REFLECTIVE_DIARY_STYLE_V1_DIGEST = semantic_digest(
    "myuna-p07-reflective-diary-style-v1",
    REFLECTIVE_DIARY_STYLE_V1_PAYLOAD,
)

OWNER_DAY_DIARY_STYLE_V2_PAYLOAD: Mapping[str, object] = {
    "authority": "derivative-myuna-perspective",
    "candidate_schema": "myuna.p07-owner-day-diary-candidate.v2",
    "factual_authority": "source-raw-turns-only",
    "model": "deepseek-v4-flash",
    "model_role": "p07_external_owner_day_reflective_diary_v2",
    "no_profile_or_p08_mutation": True,
    "preview_is_not_final": True,
    "source_pointer_coverage": "every-selected-complete-turn",
    "statement_kinds": [
        "factual_observation",
        "interpretation_reflection",
        "uncertainty",
        "intention",
    ],
    "style": "myuna-current-persona",
}
OWNER_DAY_DIARY_STYLE_V2_DIGEST = semantic_digest(
    "myuna-p07-owner-day-diary-style-v2",
    OWNER_DAY_DIARY_STYLE_V2_PAYLOAD,
)


def reflective_diary_egress_binding_digest(
    *,
    memory_release_set_id: str,
    parent_release_set_id: str,
    policy_overlay_id: str,
    archive_id: str,
    egress_policy_digest: str,
    style_contract_digest: str,
    persona_digest: str,
    model: str,
    model_role: str,
) -> str:
    """Bind the independently disableable diary route to one exact runtime set."""

    for value, label in (
        (memory_release_set_id, "diary_binding_memory_release_set"),
        (parent_release_set_id, "diary_binding_parent_release_set"),
        (policy_overlay_id, "diary_binding_policy_overlay"),
        (egress_policy_digest, "diary_binding_egress_policy"),
        (style_contract_digest, "diary_binding_style_contract"),
        (persona_digest, "diary_binding_persona"),
    ):
        require_digest(value, label)
    require_id(archive_id, "diary_binding_archive")
    require_id(model, "diary_binding_model")
    require_id(model_role, "diary_binding_model_role")
    return semantic_digest(
        "myuna-p07-reflective-diary-core-egress-binding-v1",
        {
            "archive_id": archive_id,
            "egress_policy_digest": egress_policy_digest,
            "memory_release_set_id": memory_release_set_id,
            "model": model,
            "model_role": model_role,
            "parent_release_set_id": parent_release_set_id,
            "persona_digest": persona_digest,
            "policy_overlay_id": policy_overlay_id,
            "style_contract_digest": style_contract_digest,
        },
    )


def require_id(value: str, label: str) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise EpisodicMemoryError(f"{label}_invalid")
    return value


def require_digest(value: str, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise EpisodicMemoryError(f"{label}_invalid")
    return value


def require_text(value: str, label: str, maximum: int = MAX_TURN_TEXT_CHARACTERS) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
        or len(value) > maximum
    ):
        raise EpisodicMemoryError(f"{label}_invalid")
    return value


def require_utc(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise EpisodicMemoryError(f"{label}_timezone_missing")
    normalized = value.astimezone(timezone.utc)
    return normalized


def require_zone_offset(instant: datetime, zone_name: str, offset_minutes: int) -> None:
    if zone_name not in SUPPORTED_CALENDAR_ZONES:
        raise EpisodicMemoryError("event_timezone_unsupported")
    if isinstance(offset_minutes, bool) or not isinstance(offset_minutes, int):
        raise EpisodicMemoryError("event_offset_invalid")
    try:
        expected = instant.astimezone(ZoneInfo(zone_name)).utcoffset()
    except ZoneInfoNotFoundError:
        raise EpisodicMemoryError("timezone_database_unavailable") from None
    if expected is None or int(expected.total_seconds() // 60) != offset_minutes:
        raise EpisodicMemoryError("event_offset_mismatch")


@dataclass(frozen=True, slots=True)
class TurnTimeBinding:
    status: str
    calendar_zone: str
    received_monotonic_ns: int
    committed_monotonic_ns: int
    delivered_monotonic_ns: int
    sample_instant_utc: datetime | None = None
    received_at_utc: datetime | None = None
    committed_at_utc: datetime | None = None
    delivered_at_utc: datetime | None = None
    local_calendar_representation: str | None = None
    event_offset_minutes: int | None = None
    uncertainty_microseconds: int | None = None
    synchronized: bool = False
    source: str | None = None
    source_class: str | None = None
    authority: str | None = None
    boot_id: str | None = None
    sequence: int | None = None
    sample_monotonic_ns: int | None = None
    unresolved_interval_start_utc: datetime | None = None
    unresolved_interval_end_utc: datetime | None = None
    quality_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in {"exact", "unresolved"}:
            raise EpisodicMemoryError("turn_time_status_unknown")
        if self.calendar_zone not in SUPPORTED_CALENDAR_ZONES:
            raise EpisodicMemoryError("event_timezone_unsupported")
        markers = (
            self.received_monotonic_ns,
            self.committed_monotonic_ns,
            self.delivered_monotonic_ns,
        )
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in markers
        ):
            raise EpisodicMemoryError("turn_lifecycle_order_invalid")
        if not markers[0] <= markers[1] <= markers[2]:
            raise EpisodicMemoryError("turn_lifecycle_order_invalid")
        if len(set(self.quality_codes)) != len(self.quality_codes):
            raise EpisodicMemoryError("turn_time_quality_invalid")
        for code in self.quality_codes:
            require_id(code, "turn_time_quality")
        if self.status == "exact":
            required = (
                self.sample_instant_utc,
                self.received_at_utc,
                self.committed_at_utc,
                self.delivered_at_utc,
                self.local_calendar_representation,
                self.event_offset_minutes,
                self.uncertainty_microseconds,
                self.source,
                self.source_class,
                self.authority,
                self.boot_id,
                self.sequence,
                self.sample_monotonic_ns,
            )
            if any(value is None for value in required) or not self.synchronized:
                raise EpisodicMemoryError("exact_turn_time_incomplete")
            sample = require_utc(
                self.sample_instant_utc,  # type: ignore[arg-type]
                "sample_instant",
            )
            received = require_utc(self.received_at_utc, "received_at")  # type: ignore[arg-type]
            committed = require_utc(self.committed_at_utc, "committed_at")  # type: ignore[arg-type]
            delivered = require_utc(self.delivered_at_utc, "delivered_at")  # type: ignore[arg-type]
            if not received <= committed <= delivered:
                raise EpisodicMemoryError("turn_utc_order_invalid")
            if (
                isinstance(self.uncertainty_microseconds, bool)
                or not isinstance(self.uncertainty_microseconds, int)
                or self.uncertainty_microseconds < 0
                or isinstance(self.sequence, bool)
                or not isinstance(self.sequence, int)
                or self.sequence < 1
                or isinstance(self.sample_monotonic_ns, bool)
                or not isinstance(self.sample_monotonic_ns, int)
            ):
                raise EpisodicMemoryError("exact_turn_time_invalid")
            require_id(self.source, "turn_time_source")  # type: ignore[arg-type]
            require_id(self.source_class, "turn_time_source_class")  # type: ignore[arg-type]
            require_id(self.authority, "turn_time_authority")  # type: ignore[arg-type]
            require_id(self.boot_id, "turn_time_boot_id")  # type: ignore[arg-type]
            require_zone_offset(
                delivered,
                self.calendar_zone,
                self.event_offset_minutes,  # type: ignore[arg-type]
            )
            expected_local = delivered.astimezone(ZoneInfo(self.calendar_zone)).isoformat(
                timespec="microseconds"
            )
            if self.local_calendar_representation != expected_local:
                raise EpisodicMemoryError("local_calendar_representation_mismatch")
            object.__setattr__(self, "sample_instant_utc", sample)
            object.__setattr__(self, "received_at_utc", received)
            object.__setattr__(self, "committed_at_utc", committed)
            object.__setattr__(self, "delivered_at_utc", delivered)
            if (
                self.unresolved_interval_start_utc is not None
                or self.unresolved_interval_end_utc is not None
            ):
                raise EpisodicMemoryError("exact_turn_time_unresolved_interval_prohibited")
        else:
            prohibited = (
                self.sample_instant_utc,
                self.received_at_utc,
                self.committed_at_utc,
                self.delivered_at_utc,
                self.local_calendar_representation,
                self.event_offset_minutes,
                self.uncertainty_microseconds,
                self.source,
                self.source_class,
                self.authority,
                self.boot_id,
                self.sequence,
                self.sample_monotonic_ns,
            )
            if any(value is not None for value in prohibited) or self.synchronized:
                raise EpisodicMemoryError("unresolved_turn_time_claims_exact")
            if not self.quality_codes:
                raise EpisodicMemoryError("unresolved_turn_time_reason_required")
            if (self.unresolved_interval_start_utc is None) != (
                self.unresolved_interval_end_utc is None
            ):
                raise EpisodicMemoryError("unresolved_interval_incomplete")
            if self.unresolved_interval_start_utc is not None:
                start = require_utc(self.unresolved_interval_start_utc, "unresolved_start")
                end = require_utc(
                    self.unresolved_interval_end_utc,  # type: ignore[arg-type]
                    "unresolved_end",
                )
                if start >= end:
                    raise EpisodicMemoryError("unresolved_interval_invalid")
                object.__setattr__(self, "unresolved_interval_start_utc", start)
                object.__setattr__(self, "unresolved_interval_end_utc", end)

    def payload(self) -> dict[str, object]:
        def timestamp(value: datetime | None) -> str | None:
            return None if value is None else value.isoformat(timespec="microseconds")

        return {
            "authority": self.authority,
            "boot_id": self.boot_id,
            "calendar_zone": self.calendar_zone,
            "committed_at_utc": timestamp(self.committed_at_utc),
            "committed_monotonic_ns": self.committed_monotonic_ns,
            "delivered_at_utc": timestamp(self.delivered_at_utc),
            "delivered_monotonic_ns": self.delivered_monotonic_ns,
            "event_offset_minutes": self.event_offset_minutes,
            "local_calendar_representation": self.local_calendar_representation,
            "quality_codes": list(self.quality_codes),
            "received_at_utc": timestamp(self.received_at_utc),
            "received_monotonic_ns": self.received_monotonic_ns,
            "sample_instant_utc": timestamp(self.sample_instant_utc),
            "sample_monotonic_ns": self.sample_monotonic_ns,
            "sequence": self.sequence,
            "source": self.source,
            "source_class": self.source_class,
            "status": self.status,
            "synchronized": self.synchronized,
            "uncertainty_microseconds": self.uncertainty_microseconds,
            "unresolved_interval_end_utc": timestamp(self.unresolved_interval_end_utc),
            "unresolved_interval_start_utc": timestamp(self.unresolved_interval_start_utc),
        }

    @property
    def binding_digest(self) -> str:
        return semantic_digest("myuna-p07-turn-time-binding-v1", self.payload())

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> TurnTimeBinding:
        expected = {
            "authority",
            "boot_id",
            "calendar_zone",
            "committed_at_utc",
            "committed_monotonic_ns",
            "delivered_at_utc",
            "delivered_monotonic_ns",
            "event_offset_minutes",
            "local_calendar_representation",
            "quality_codes",
            "received_at_utc",
            "received_monotonic_ns",
            "sample_instant_utc",
            "sample_monotonic_ns",
            "sequence",
            "source",
            "source_class",
            "status",
            "synchronized",
            "uncertainty_microseconds",
            "unresolved_interval_end_utc",
            "unresolved_interval_start_utc",
        }
        if set(payload) != expected or not isinstance(payload["quality_codes"], list):
            raise EpisodicMemoryError("turn_time_binding_schema_rejected")

        def parse(value: object) -> datetime | None:
            if value is None:
                return None
            if not isinstance(value, str):
                raise EpisodicMemoryError("turn_time_binding_schema_rejected")
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                raise EpisodicMemoryError("turn_time_binding_schema_rejected") from None

        return cls(
            status=payload["status"],  # type: ignore[arg-type]
            calendar_zone=payload["calendar_zone"],  # type: ignore[arg-type]
            received_monotonic_ns=payload["received_monotonic_ns"],  # type: ignore[arg-type]
            committed_monotonic_ns=payload["committed_monotonic_ns"],  # type: ignore[arg-type]
            delivered_monotonic_ns=payload["delivered_monotonic_ns"],  # type: ignore[arg-type]
            sample_instant_utc=parse(payload["sample_instant_utc"]),
            received_at_utc=parse(payload["received_at_utc"]),
            committed_at_utc=parse(payload["committed_at_utc"]),
            delivered_at_utc=parse(payload["delivered_at_utc"]),
            local_calendar_representation=payload[
                "local_calendar_representation"
            ],  # type: ignore[arg-type]
            event_offset_minutes=payload["event_offset_minutes"],  # type: ignore[arg-type]
            uncertainty_microseconds=payload["uncertainty_microseconds"],  # type: ignore[arg-type]
            synchronized=payload["synchronized"],  # type: ignore[arg-type]
            source=payload["source"],  # type: ignore[arg-type]
            source_class=payload["source_class"],  # type: ignore[arg-type]
            authority=payload["authority"],  # type: ignore[arg-type]
            boot_id=payload["boot_id"],  # type: ignore[arg-type]
            sequence=payload["sequence"],  # type: ignore[arg-type]
            sample_monotonic_ns=payload["sample_monotonic_ns"],  # type: ignore[arg-type]
            unresolved_interval_start_utc=parse(payload["unresolved_interval_start_utc"]),
            unresolved_interval_end_utc=parse(payload["unresolved_interval_end_utc"]),
            quality_codes=tuple(payload["quality_codes"]),  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class TurnTimeCorrection:
    correction_id: str
    turn_id: str
    turn_digest: str
    original_binding_digest: str
    corrected_binding: TurnTimeBinding
    reason_code: str
    created_at_utc: datetime
    provenance_digest: str

    def __post_init__(self) -> None:
        require_id(self.correction_id, "time_correction_id")
        require_id(self.turn_id, "turn_id")
        require_digest(self.turn_digest, "turn_digest")
        require_digest(self.original_binding_digest, "original_binding_digest")
        if self.corrected_binding.status != "exact":
            raise EpisodicMemoryError("time_correction_not_exact")
        require_id(self.reason_code, "time_correction_reason")
        object.__setattr__(
            self,
            "created_at_utc",
            require_utc(self.created_at_utc, "time_correction_created_at"),
        )
        require_digest(self.provenance_digest, "time_correction_provenance")

    def payload(self) -> dict[str, object]:
        return {
            "corrected_binding": self.corrected_binding.payload(),
            "correction_id": self.correction_id,
            "created_at_utc": self.created_at_utc.isoformat(timespec="microseconds"),
            "original_binding_digest": self.original_binding_digest,
            "provenance_digest": self.provenance_digest,
            "reason_code": self.reason_code,
            "turn_digest": self.turn_digest,
            "turn_id": self.turn_id,
        }

    @property
    def correction_digest(self) -> str:
        return semantic_digest("myuna-p07-turn-time-correction-v1", self.payload())

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> TurnTimeCorrection:
        required = {
            "corrected_binding",
            "correction_id",
            "created_at_utc",
            "original_binding_digest",
            "provenance_digest",
            "reason_code",
            "turn_digest",
            "turn_id",
        }
        if set(payload) != required or not isinstance(payload["corrected_binding"], Mapping):
            raise EpisodicMemoryError("time_correction_schema_rejected")
        try:
            created = datetime.fromisoformat(payload["created_at_utc"])  # type: ignore[arg-type]
        except (TypeError, ValueError):
            raise EpisodicMemoryError("time_correction_schema_rejected") from None
        return cls(
            correction_id=payload["correction_id"],  # type: ignore[arg-type]
            turn_id=payload["turn_id"],  # type: ignore[arg-type]
            turn_digest=payload["turn_digest"],  # type: ignore[arg-type]
            original_binding_digest=payload["original_binding_digest"],  # type: ignore[arg-type]
            corrected_binding=TurnTimeBinding.from_payload(payload["corrected_binding"]),
            reason_code=payload["reason_code"],  # type: ignore[arg-type]
            created_at_utc=created,
            provenance_digest=payload["provenance_digest"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class ArchivedContent:
    kind: str
    text: str
    media_identity_digest: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in {"text", "image_description"}:
            raise EpisodicMemoryError("content_kind_rejected")
        require_text(self.text, "content_text")
        if self.kind == "text" and self.media_identity_digest is not None:
            raise EpisodicMemoryError("text_media_identity_prohibited")
        if self.kind == "image_description":
            if self.media_identity_digest is None:
                raise EpisodicMemoryError("image_identity_required")
            require_digest(self.media_identity_digest, "image_identity_digest")

    @property
    def text_digest(self) -> str:
        return semantic_digest(
            "myuna-p07-archived-content-v1",
            {
                "kind": self.kind,
                "media_identity_digest": self.media_identity_digest,
                "text": self.text,
            },
        )


@dataclass(frozen=True, slots=True)
class CompleteTurnDraft:
    turn_id: str
    sequence: int
    owner: ArchivedContent
    assistant: ArchivedContent
    time_binding: TurnTimeBinding
    epoch_id: str
    release_set_id: str
    request_digest: str
    response_digest: str
    delivery_ack_digest: str
    previous_turn_digest: str
    provenance_categories: tuple[str, ...]

    def __post_init__(self) -> None:
        require_id(self.turn_id, "turn_id")
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 1
        ):
            raise EpisodicMemoryError("turn_sequence_invalid")
        if not isinstance(self.time_binding, TurnTimeBinding):
            raise EpisodicMemoryError("turn_time_binding_required")
        require_id(self.epoch_id, "epoch_id")
        require_digest(self.release_set_id, "release_set_id")
        require_digest(self.request_digest, "request_digest")
        require_digest(self.response_digest, "response_digest")
        require_digest(self.delivery_ack_digest, "delivery_ack_digest")
        require_digest(self.previous_turn_digest, "previous_turn_digest")
        if (
            not isinstance(self.provenance_categories, tuple)
            or not self.provenance_categories
            or len(set(self.provenance_categories)) != len(self.provenance_categories)
        ):
            raise EpisodicMemoryError("provenance_categories_invalid")
        for category in self.provenance_categories:
            require_id(category, "provenance_category")

    def payload(self) -> dict[str, object]:
        return {
            "assistant_kind": self.assistant.kind,
            "assistant_media_identity_digest": self.assistant.media_identity_digest,
            "assistant_text": self.assistant.text,
            "delivery_ack_digest": self.delivery_ack_digest,
            "epoch_id": self.epoch_id,
            "owner_kind": self.owner.kind,
            "owner_media_identity_digest": self.owner.media_identity_digest,
            "owner_text": self.owner.text,
            "previous_turn_digest": self.previous_turn_digest,
            "provenance_categories": list(self.provenance_categories),
            "release_set_id": self.release_set_id,
            "request_digest": self.request_digest,
            "response_digest": self.response_digest,
            "sequence": self.sequence,
            "time_binding": self.time_binding.payload(),
            "turn_id": self.turn_id,
        }


@dataclass(frozen=True, slots=True)
class CompleteTurn:
    draft: CompleteTurnDraft
    turn_digest: str

    def __post_init__(self) -> None:
        expected = semantic_digest("myuna-p07-complete-turn-v1", self.draft.payload())
        if self.turn_digest != expected:
            raise EpisodicMemoryError("turn_digest_mismatch")

    @classmethod
    def create(cls, draft: CompleteTurnDraft) -> CompleteTurn:
        return cls(
            draft=draft,
            turn_digest=semantic_digest("myuna-p07-complete-turn-v1", draft.payload()),
        )

    def payload(self) -> dict[str, object]:
        return self.draft.payload() | {"turn_digest": self.turn_digest}

    @property
    def model_history_eligible(self) -> bool:
        """Whether this raw turn may enter ordinary model history.

        Control commands and replies remain in the authoritative archive while
        their explicit isolation marker keeps them out of normal conversation
        projection and historical-recall candidate selection.
        """

        return CONTROL_ISOLATED_CATEGORY not in self.draft.provenance_categories

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> CompleteTurn:
        expected = {
            "assistant_kind",
            "assistant_media_identity_digest",
            "assistant_text",
            "delivery_ack_digest",
            "epoch_id",
            "owner_kind",
            "owner_media_identity_digest",
            "owner_text",
            "previous_turn_digest",
            "provenance_categories",
            "release_set_id",
            "request_digest",
            "response_digest",
            "sequence",
            "time_binding",
            "turn_digest",
            "turn_id",
        }
        if (
            set(payload) != expected
            or not isinstance(payload["time_binding"], Mapping)
            or not isinstance(payload["provenance_categories"], list)
        ):
            raise EpisodicMemoryError("complete_turn_schema_rejected")
        draft = CompleteTurnDraft(
            turn_id=payload["turn_id"],  # type: ignore[arg-type]
            sequence=payload["sequence"],  # type: ignore[arg-type]
            owner=ArchivedContent(
                payload["owner_kind"],  # type: ignore[arg-type]
                payload["owner_text"],  # type: ignore[arg-type]
                payload["owner_media_identity_digest"],  # type: ignore[arg-type]
            ),
            assistant=ArchivedContent(
                payload["assistant_kind"],  # type: ignore[arg-type]
                payload["assistant_text"],  # type: ignore[arg-type]
                payload["assistant_media_identity_digest"],  # type: ignore[arg-type]
            ),
            time_binding=TurnTimeBinding.from_payload(payload["time_binding"]),
            epoch_id=payload["epoch_id"],  # type: ignore[arg-type]
            release_set_id=payload["release_set_id"],  # type: ignore[arg-type]
            request_digest=payload["request_digest"],  # type: ignore[arg-type]
            response_digest=payload["response_digest"],  # type: ignore[arg-type]
            delivery_ack_digest=payload["delivery_ack_digest"],  # type: ignore[arg-type]
            previous_turn_digest=payload["previous_turn_digest"],  # type: ignore[arg-type]
            provenance_categories=tuple(payload["provenance_categories"]),  # type: ignore[arg-type]
        )
        return cls(draft=draft, turn_digest=payload["turn_digest"])  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class LifecycleRecord:
    lifecycle_id: str
    event_kind: str
    request_digest: str
    occurred_at_utc: datetime
    reason_code: str
    delivery_acknowledged: bool
    complete_turn_written: bool

    def __post_init__(self) -> None:
        require_id(self.lifecycle_id, "lifecycle_id")
        if self.event_kind not in {
            "prepared",
            "delivery_failed",
            "delivery_rejected",
            "crash_pending",
            "abandoned",
        }:
            raise EpisodicMemoryError("lifecycle_kind_rejected")
        require_digest(self.request_digest, "request_digest")
        object.__setattr__(
            self,
            "occurred_at_utc",
            require_utc(self.occurred_at_utc, "occurred_at"),
        )
        require_id(self.reason_code, "reason_code")
        if self.delivery_acknowledged or self.complete_turn_written:
            raise EpisodicMemoryError("incomplete_lifecycle_claimed_complete")


def _structured(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if not isinstance(values, tuple) or len(values) > MAX_STRUCTURED_ITEMS:
        raise EpisodicMemoryError(f"{label}_invalid")
    for value in values:
        require_text(value, label, MAX_STRUCTURED_ITEM_CHARACTERS)
    if len(set(values)) != len(values):
        raise EpisodicMemoryError(f"{label}_duplicate")
    return values


@dataclass(frozen=True, slots=True)
class TurnPrimitive:
    source_sequence: int
    source_turn_id: str
    source_turn_digest: str
    actors: tuple[str, ...] = ()
    proposals_assertions: tuple[str, ...] = ()
    stances: tuple[str, ...] = ()
    decisions_commitments: tuple[str, ...] = ()
    actions_state_changes: tuple[str, ...] = ()
    entities: tuple[str, ...] = ()
    locations: tuple[str, ...] = ()
    times: tuple[str, ...] = ()
    numbers: tuple[str, ...] = ()
    negations_conditions: tuple[str, ...] = ()
    preferences: tuple[str, ...] = ()
    unresolved_items: tuple[str, ...] = ()
    coverage_state: str = "coverage_incomplete"
    ambiguity_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            isinstance(self.source_sequence, bool)
            or not isinstance(self.source_sequence, int)
            or self.source_sequence < 1
        ):
            raise EpisodicMemoryError("primitive_sequence_invalid")
        require_id(self.source_turn_id, "source_turn_id")
        require_digest(self.source_turn_digest, "source_turn_digest")
        for name in (
            "actors",
            "proposals_assertions",
            "stances",
            "decisions_commitments",
            "actions_state_changes",
            "entities",
            "locations",
            "times",
            "numbers",
            "negations_conditions",
            "preferences",
            "unresolved_items",
            "ambiguity_codes",
        ):
            _structured(getattr(self, name), name)
        if self.coverage_state not in {"complete", "coverage_incomplete", "ambiguous"}:
            raise EpisodicMemoryError("coverage_state_invalid")

    def payload(self) -> dict[str, object]:
        return {
            name: list(getattr(self, name))
            for name in (
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
            )
        } | {
            "coverage_state": self.coverage_state,
            "source_sequence": self.source_sequence,
            "source_turn_digest": self.source_turn_digest,
            "source_turn_id": self.source_turn_id,
        }

    @property
    def primitive_digest(self) -> str:
        return semantic_digest("myuna-p07-turn-primitive-v1", self.payload())


@dataclass(frozen=True, slots=True)
class EpisodicCapsule:
    capsule_id: str
    capsule_kind: str
    source_start: int
    source_end: int
    source_terminal_digest: str
    primitive_digests: tuple[str, ...]
    label: str
    coverage_state: str
    ambiguity_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        require_id(self.capsule_id, "capsule_id")
        if self.capsule_kind not in {"turn", "event", "date"}:
            raise EpisodicMemoryError("capsule_kind_rejected")
        if (
            isinstance(self.source_start, bool)
            or not isinstance(self.source_start, int)
            or not isinstance(self.source_end, int)
            or self.source_start < 1
            or self.source_end < self.source_start
        ):
            raise EpisodicMemoryError("capsule_range_invalid")
        require_digest(self.source_terminal_digest, "source_terminal_digest")
        if len(self.primitive_digests) != self.source_end - self.source_start + 1:
            raise EpisodicMemoryError("capsule_range_noncontiguous")
        for value in self.primitive_digests:
            require_digest(value, "primitive_digest")
        require_text(self.label, "capsule_label", 512)
        if self.coverage_state not in {"complete", "coverage_incomplete", "ambiguous"}:
            raise EpisodicMemoryError("coverage_state_invalid")
        _structured(self.ambiguity_codes, "ambiguity_codes")

    def payload(self) -> dict[str, object]:
        return {
            "ambiguity_codes": list(self.ambiguity_codes),
            "capsule_id": self.capsule_id,
            "capsule_kind": self.capsule_kind,
            "coverage_state": self.coverage_state,
            "label": self.label,
            "primitive_digests": list(self.primitive_digests),
            "source_end": self.source_end,
            "source_start": self.source_start,
            "source_terminal_digest": self.source_terminal_digest,
        }

    @property
    def capsule_digest(self) -> str:
        return semantic_digest("myuna-p07-episodic-capsule-v1", self.payload())


PREFIX_CAPSULE_SCHEMA = "myuna.p07-prefix-capsule.v1"
PREFIX_CAPSULE_RISK_CLASSES = frozenset(
    {"continuity_orientation", "retrieval_hint"}
)
PREFIX_OVERFLOW_ACTIONS = (
    "retrieve",
    "narrow",
    "clarify",
    "abstain",
    "safe_failure",
)


@dataclass(frozen=True, slots=True)
class PrefixCompactionPolicy:
    policy_version: str
    preferred_character_ratio: int
    preferred_byte_ratio: int
    preferred_token_ratio: int
    hard_character_ratio: int
    hard_byte_ratio: int
    hard_token_ratio: int
    minimum_recent_raw_turns: int
    minimum_recent_raw_characters: int
    minimum_recent_raw_tokens: int
    target_character_headroom: int
    target_byte_headroom: int
    target_token_headroom: int
    repair_reserve_characters: int
    repair_reserve_bytes: int
    repair_reserve_tokens: int
    maximum_source_turns: int
    maximum_capsule_characters: int
    maximum_capsule_bytes: int
    maximum_capsule_tokens: int
    token_oracle_id: str
    permitted_risk_classes: tuple[str, ...]
    overflow_actions: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.policy_version != CONTEXT_POLICY_DYNAMIC_PREFIX:
            raise EpisodicMemoryError("prefix_policy_version_unknown")
        for preferred, hard in (
            (self.preferred_character_ratio, self.hard_character_ratio),
            (self.preferred_byte_ratio, self.hard_byte_ratio),
            (self.preferred_token_ratio, self.hard_token_ratio),
        ):
            if (
                isinstance(preferred, bool)
                or not isinstance(preferred, int)
                or isinstance(hard, bool)
                or not isinstance(hard, int)
                or preferred < 1
                or hard < preferred
            ):
                raise EpisodicMemoryError("prefix_policy_ratio_invalid")
        for value in (
            self.minimum_recent_raw_turns,
            self.minimum_recent_raw_characters,
            self.minimum_recent_raw_tokens,
            self.target_character_headroom,
            self.target_byte_headroom,
            self.target_token_headroom,
            self.repair_reserve_characters,
            self.repair_reserve_bytes,
            self.repair_reserve_tokens,
            self.maximum_source_turns,
            self.maximum_capsule_characters,
            self.maximum_capsule_bytes,
            self.maximum_capsule_tokens,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise EpisodicMemoryError("prefix_policy_limit_invalid")
        require_id(self.token_oracle_id, "prefix_token_oracle")
        if (
            tuple(sorted(set(self.permitted_risk_classes)))
            != self.permitted_risk_classes
            or not set(self.permitted_risk_classes) <= PREFIX_CAPSULE_RISK_CLASSES
        ):
            raise EpisodicMemoryError("prefix_policy_risk_class_invalid")
        if self.overflow_actions != PREFIX_OVERFLOW_ACTIONS:
            raise EpisodicMemoryError("prefix_policy_overflow_actions_invalid")

    @classmethod
    def balanced_default(cls) -> PrefixCompactionPolicy:
        return cls(
            policy_version=CONTEXT_POLICY_DYNAMIC_PREFIX,
            preferred_character_ratio=4,
            preferred_byte_ratio=4,
            preferred_token_ratio=4,
            hard_character_ratio=8,
            hard_byte_ratio=8,
            hard_token_ratio=8,
            minimum_recent_raw_turns=16,
            minimum_recent_raw_characters=16_000,
            minimum_recent_raw_tokens=12_000,
            target_character_headroom=5_000,
            target_byte_headroom=15_000,
            target_token_headroom=15_000,
            repair_reserve_characters=1_000,
            repair_reserve_bytes=4_096,
            repair_reserve_tokens=4_096,
            maximum_source_turns=128,
            maximum_capsule_characters=9_000,
            maximum_capsule_bytes=27_000,
            maximum_capsule_tokens=27_000,
            token_oracle_id="deepseek-v4-flash-utf8-byte-upper-bound-v1",
            permitted_risk_classes=(
                "continuity_orientation",
                "retrieval_hint",
            ),
            overflow_actions=PREFIX_OVERFLOW_ACTIONS,
        )

    def payload(self) -> dict[str, object]:
        return {
            "hard_byte_ratio": self.hard_byte_ratio,
            "hard_character_ratio": self.hard_character_ratio,
            "hard_token_ratio": self.hard_token_ratio,
            "maximum_capsule_bytes": self.maximum_capsule_bytes,
            "maximum_capsule_characters": self.maximum_capsule_characters,
            "maximum_capsule_tokens": self.maximum_capsule_tokens,
            "maximum_source_turns": self.maximum_source_turns,
            "minimum_recent_raw_characters": self.minimum_recent_raw_characters,
            "minimum_recent_raw_tokens": self.minimum_recent_raw_tokens,
            "minimum_recent_raw_turns": self.minimum_recent_raw_turns,
            "overflow_actions": list(self.overflow_actions),
            "permitted_risk_classes": list(self.permitted_risk_classes),
            "policy_version": self.policy_version,
            "preferred_byte_ratio": self.preferred_byte_ratio,
            "preferred_character_ratio": self.preferred_character_ratio,
            "preferred_token_ratio": self.preferred_token_ratio,
            "repair_reserve_bytes": self.repair_reserve_bytes,
            "repair_reserve_characters": self.repair_reserve_characters,
            "repair_reserve_tokens": self.repair_reserve_tokens,
            "target_byte_headroom": self.target_byte_headroom,
            "target_character_headroom": self.target_character_headroom,
            "target_token_headroom": self.target_token_headroom,
            "token_oracle_id": self.token_oracle_id,
        }

    @property
    def policy_digest(self) -> str:
        return semantic_digest("myuna-p07-prefix-compaction-policy-v1", self.payload())

    @classmethod
    def from_payload(cls, payload: object) -> PrefixCompactionPolicy:
        if not isinstance(payload, Mapping):
            raise EpisodicMemoryError("prefix_policy_fields_rejected")
        expected = set(cls.__dataclass_fields__)
        if (
            set(payload) != expected
            or not isinstance(payload["permitted_risk_classes"], list)
            or not isinstance(payload["overflow_actions"], list)
        ):
            raise EpisodicMemoryError("prefix_policy_fields_rejected")
        values = dict(payload)
        values["permitted_risk_classes"] = tuple(
            payload["permitted_risk_classes"]
        )
        values["overflow_actions"] = tuple(payload["overflow_actions"])
        return cls(**values)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class PrefixCapsule:
    capsule_id: str
    revision: int
    parent_capsule_digest: str
    archive_id: str
    epoch_id: str
    source_snapshot_head_digest: str
    source_snapshot_turn_count: int
    source_start: int
    source_end: int
    source_turn_ids: tuple[str, ...]
    source_turn_digests: tuple[str, ...]
    source_original_zones: tuple[str, ...]
    source_characters: int
    source_bytes: int
    source_tokens: int
    capsule_text: str
    capsule_characters: int
    capsule_bytes: int
    capsule_tokens: int
    character_ratio_milli: int
    byte_ratio_milli: int
    token_ratio_milli: int
    policy_version: str
    policy_digest: str
    generator_version: str
    model_provider_class: str
    token_oracle_id: str
    created_at_utc: datetime
    source_time_start_utc: datetime
    source_time_end_utc: datetime
    omission_counts: tuple[tuple[str, int], ...]
    risk_class: str
    projection_eligible: bool
    schema: str = PREFIX_CAPSULE_SCHEMA

    def _validate_primitive_types(self) -> None:
        string_fields = (
            "capsule_id",
            "parent_capsule_digest",
            "archive_id",
            "epoch_id",
            "source_snapshot_head_digest",
            "capsule_text",
            "policy_version",
            "policy_digest",
            "generator_version",
            "model_provider_class",
            "token_oracle_id",
            "risk_class",
            "schema",
        )
        integer_fields = (
            "revision",
            "source_snapshot_turn_count",
            "source_start",
            "source_end",
            "source_characters",
            "source_bytes",
            "source_tokens",
            "capsule_characters",
            "capsule_bytes",
            "capsule_tokens",
            "character_ratio_milli",
            "byte_ratio_milli",
            "token_ratio_milli",
        )
        if any(type(getattr(self, name)) is not str for name in string_fields):
            raise EpisodicMemoryError("prefix_capsule_primitive_type_invalid")
        if any(type(getattr(self, name)) is not int for name in integer_fields):
            raise EpisodicMemoryError("prefix_capsule_primitive_type_invalid")
        if type(self.projection_eligible) is not bool:
            raise EpisodicMemoryError("prefix_capsule_primitive_type_invalid")
        for values in (
            self.source_turn_ids,
            self.source_turn_digests,
            self.source_original_zones,
        ):
            if type(values) is not tuple or any(
                type(value) is not str for value in values
            ):
                raise EpisodicMemoryError("prefix_capsule_primitive_type_invalid")
        if type(self.omission_counts) is not tuple or any(
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not int
            for item in self.omission_counts
        ):
            raise EpisodicMemoryError("prefix_capsule_primitive_type_invalid")
        if any(
            type(value) is not datetime
            for value in (
                self.created_at_utc,
                self.source_time_start_utc,
                self.source_time_end_utc,
            )
        ):
            raise EpisodicMemoryError("prefix_capsule_primitive_type_invalid")

    def __post_init__(self) -> None:
        self._validate_primitive_types()
        if self.schema != PREFIX_CAPSULE_SCHEMA:
            raise EpisodicMemoryError("prefix_capsule_schema_unknown")
        for value, label in (
            (self.capsule_id, "prefix_capsule_id"),
            (self.archive_id, "prefix_archive_id"),
            (self.epoch_id, "prefix_epoch_id"),
            (self.generator_version, "prefix_generator_version"),
            (self.model_provider_class, "prefix_model_provider_class"),
            (self.token_oracle_id, "prefix_token_oracle"),
        ):
            require_id(value, label)
        for value, label in (
            (self.parent_capsule_digest, "prefix_parent_capsule"),
            (self.source_snapshot_head_digest, "prefix_source_head"),
            (self.policy_digest, "prefix_policy_digest"),
        ):
            require_digest(value, label)
        if self.policy_version != CONTEXT_POLICY_DYNAMIC_PREFIX:
            raise EpisodicMemoryError("prefix_policy_version_unknown")
        if self.risk_class not in PREFIX_CAPSULE_RISK_CLASSES:
            raise EpisodicMemoryError("prefix_capsule_risk_class_rejected")
        if (
            self.revision < 1
            or self.source_start != 1
            or self.source_end < self.source_start
            or self.source_snapshot_turn_count < self.source_end
        ):
            raise EpisodicMemoryError("prefix_capsule_range_invalid")
        count = self.source_end - self.source_start + 1
        if (
            len(self.source_turn_ids) != count
            or len(self.source_turn_digests) != count
            or len(self.source_original_zones) != count
        ):
            raise EpisodicMemoryError("prefix_capsule_source_binding_incomplete")
        for value in self.source_turn_ids:
            require_id(value, "prefix_source_turn_id")
        for value in self.source_turn_digests:
            require_digest(value, "prefix_source_turn_digest")
        if any(zone not in SUPPORTED_CALENDAR_ZONES for zone in self.source_original_zones):
            raise EpisodicMemoryError("prefix_source_zone_rejected")
        require_text(self.capsule_text, "prefix_capsule_text", 9_000)
        actual_characters = len(self.capsule_text)
        try:
            actual_bytes = len(self.capsule_text.encode("utf-8"))
        except UnicodeEncodeError:
            raise EpisodicMemoryError("prefix_capsule_text_invalid") from None
        if (
            self.capsule_characters != actual_characters
            or self.capsule_bytes != actual_bytes
        ):
            raise EpisodicMemoryError("prefix_capsule_size_mismatch")
        for value in (
            self.source_characters,
            self.source_bytes,
            self.source_tokens,
            self.capsule_characters,
            self.capsule_bytes,
            self.capsule_tokens,
            self.character_ratio_milli,
            self.byte_ratio_milli,
            self.token_ratio_milli,
        ):
            if value < 1:
                raise EpisodicMemoryError("prefix_capsule_count_invalid")
        expected_ratios = (
            self.source_characters * 1000 // self.capsule_characters,
            self.source_bytes * 1000 // self.capsule_bytes,
            self.source_tokens * 1000 // self.capsule_tokens,
        )
        if expected_ratios != (
            self.character_ratio_milli,
            self.byte_ratio_milli,
            self.token_ratio_milli,
        ):
            raise EpisodicMemoryError("prefix_capsule_ratio_mismatch")
        object.__setattr__(
            self,
            "created_at_utc",
            require_utc(self.created_at_utc, "prefix_created_at"),
        )
        object.__setattr__(
            self,
            "source_time_start_utc",
            require_utc(self.source_time_start_utc, "prefix_source_time_start"),
        )
        object.__setattr__(
            self,
            "source_time_end_utc",
            require_utc(self.source_time_end_utc, "prefix_source_time_end"),
        )
        if self.source_time_end_utc < self.source_time_start_utc:
            raise EpisodicMemoryError("prefix_capsule_time_range_invalid")
        names = tuple(item[0] for item in self.omission_counts)
        if names != tuple(sorted(set(names))):
            raise EpisodicMemoryError("prefix_capsule_omission_projection_invalid")
        for name, value in self.omission_counts:
            require_id(name, "prefix_omission_category")
            if value < 0:
                raise EpisodicMemoryError("prefix_omission_count_invalid")

    def payload(self) -> dict[str, object]:
        self._validate_primitive_types()
        return {
            "archive_id": self.archive_id,
            "byte_ratio_milli": self.byte_ratio_milli,
            "capsule_bytes": self.capsule_bytes,
            "capsule_characters": self.capsule_characters,
            "capsule_id": self.capsule_id,
            "capsule_text": self.capsule_text,
            "capsule_tokens": self.capsule_tokens,
            "character_ratio_milli": self.character_ratio_milli,
            "created_at_utc": self.created_at_utc.isoformat(timespec="microseconds"),
            "epoch_id": self.epoch_id,
            "generator_version": self.generator_version,
            "model_provider_class": self.model_provider_class,
            "omission_counts": [list(item) for item in self.omission_counts],
            "parent_capsule_digest": self.parent_capsule_digest,
            "policy_digest": self.policy_digest,
            "policy_version": self.policy_version,
            "projection_eligible": self.projection_eligible,
            "revision": self.revision,
            "risk_class": self.risk_class,
            "schema": self.schema,
            "source_bytes": self.source_bytes,
            "source_characters": self.source_characters,
            "source_end": self.source_end,
            "source_snapshot_head_digest": self.source_snapshot_head_digest,
            "source_snapshot_turn_count": self.source_snapshot_turn_count,
            "source_start": self.source_start,
            "source_time_end_utc": self.source_time_end_utc.isoformat(
                timespec="microseconds"
            ),
            "source_time_start_utc": self.source_time_start_utc.isoformat(
                timespec="microseconds"
            ),
            "source_tokens": self.source_tokens,
            "source_original_zones": list(self.source_original_zones),
            "source_turn_digests": list(self.source_turn_digests),
            "source_turn_ids": list(self.source_turn_ids),
            "token_oracle_id": self.token_oracle_id,
            "token_ratio_milli": self.token_ratio_milli,
        }

    @property
    def capsule_digest(self) -> str:
        return semantic_digest("myuna-p07-prefix-capsule-v1", self.payload())

    def audit_projection(self) -> dict[str, object]:
        return {
            "capsule_digest": self.capsule_digest,
            "capsule_id": self.capsule_id,
            "capsule_revision": self.revision,
            "omission_category_count": len(self.omission_counts),
            "projection_eligible": self.projection_eligible,
            "risk_class": self.risk_class,
            "source_end": self.source_end,
            "source_start": self.source_start,
        }

    @classmethod
    def from_payload(cls, payload: object) -> PrefixCapsule:
        if type(payload) is not dict or any(type(key) is not str for key in payload):
            raise EpisodicMemoryError("prefix_capsule_fields_rejected")
        expected = set(cls.__dataclass_fields__)
        if set(payload) != expected:
            raise EpisodicMemoryError("prefix_capsule_fields_rejected")
        string_fields = expected - {
            "revision",
            "source_snapshot_turn_count",
            "source_start",
            "source_end",
            "source_characters",
            "source_bytes",
            "source_tokens",
            "capsule_characters",
            "capsule_bytes",
            "capsule_tokens",
            "character_ratio_milli",
            "byte_ratio_milli",
            "token_ratio_milli",
            "created_at_utc",
            "source_time_start_utc",
            "source_time_end_utc",
            "source_turn_ids",
            "source_turn_digests",
            "source_original_zones",
            "omission_counts",
            "projection_eligible",
        }
        integer_fields = (
            "revision",
            "source_snapshot_turn_count",
            "source_start",
            "source_end",
            "source_characters",
            "source_bytes",
            "source_tokens",
            "capsule_characters",
            "capsule_bytes",
            "capsule_tokens",
            "character_ratio_milli",
            "byte_ratio_milli",
            "token_ratio_milli",
        )
        sequence_fields = (
            "source_turn_ids",
            "source_turn_digests",
            "source_original_zones",
        )
        timestamp_fields = (
            "created_at_utc",
            "source_time_start_utc",
            "source_time_end_utc",
        )
        if any(type(payload[name]) is not str for name in string_fields):
            raise EpisodicMemoryError("prefix_capsule_fields_rejected")
        if any(type(payload[name]) is not int for name in integer_fields):
            raise EpisodicMemoryError("prefix_capsule_fields_rejected")
        if type(payload["projection_eligible"]) is not bool:
            raise EpisodicMemoryError("prefix_capsule_fields_rejected")
        if any(
            type(payload[name]) is not list
            or any(type(value) is not str for value in payload[name])
            for name in sequence_fields
        ):
            raise EpisodicMemoryError("prefix_capsule_fields_rejected")
        if (
            type(payload["omission_counts"]) is not list
            or any(
                type(item) is not list
                or len(item) != 2
                or type(item[0]) is not str
                or type(item[1]) is not int
                for item in payload["omission_counts"]
            )
            or any(type(payload[name]) is not str for name in timestamp_fields)
        ):
            raise EpisodicMemoryError("prefix_capsule_fields_rejected")
        try:
            parsed_times = tuple(
                require_utc(datetime.fromisoformat(payload[name]), name)
                for name in timestamp_fields
            )
            if any(
                payload[name] != value.isoformat(timespec="microseconds")
                for name, value in zip(timestamp_fields, parsed_times, strict=True)
            ):
                raise ValueError
            omissions = tuple(
                (item[0], item[1])
                for item in payload["omission_counts"]
            )
        except (IndexError, TypeError, ValueError):
            raise EpisodicMemoryError("prefix_capsule_fields_rejected") from None
        values = dict(payload)
        for name, value in zip(timestamp_fields, parsed_times, strict=True):
            values[name] = value
        values["source_turn_ids"] = tuple(payload["source_turn_ids"])
        values["source_turn_digests"] = tuple(payload["source_turn_digests"])
        values["source_original_zones"] = tuple(payload["source_original_zones"])
        values["omission_counts"] = omissions
        return cls(**values)  # type: ignore[arg-type]


def prefix_capsule_source_closure_digest(
    *,
    archive_id: str,
    archive_head_digest: str,
    archive_turn_count: int,
    source_end: int,
    source_turn_ids: tuple[str, ...],
    source_turn_digests: tuple[str, ...],
    eligible_source_turn_ids: tuple[str, ...],
) -> str:
    return semantic_digest(
        "myuna-p07-prefix-capsule-source-closure-v1",
        {
            "archive_head_digest": archive_head_digest,
            "archive_id": archive_id,
            "archive_turn_count": archive_turn_count,
            "eligible_source_turn_ids": list(eligible_source_turn_ids),
            "source_end": source_end,
            "source_turn_digests": list(source_turn_digests),
            "source_turn_ids": list(source_turn_ids),
        },
    )


@dataclass(frozen=True, slots=True)
class RecallEgressPolicy:
    mode: str = EGRESS_POLICY_DENY
    policy_digest: str = ZERO_DIGEST

    def __post_init__(self) -> None:
        if self.mode not in {
            EGRESS_POLICY_DENY,
            EGRESS_POLICY_RAW_HYDRATION,
            EGRESS_POLICY_HISTORICAL_RAW_RECALL_V1,
        }:
            raise EpisodicMemoryError("egress_policy_mode_unknown")
        require_digest(self.policy_digest, "egress_policy_digest")
        if self.mode == EGRESS_POLICY_DENY and self.policy_digest != ZERO_DIGEST:
            raise EpisodicMemoryError("denied_egress_policy_drifted")
        if self.mode != EGRESS_POLICY_DENY and self.policy_digest == ZERO_DIGEST:
            raise EpisodicMemoryError("egress_policy_unbound")


SEMANTIC_WRITE_BOUNDARY: Mapping[str, str] = {
    "daily_reflective_diary": "automatic_subjective_derivative_no_semantic_promotion",
    "episodic_index": "automatic_derivative",
    "identity_claim": "proposal_confirmation_required",
    "inferred_preference": "proposal_confirmation_required",
    "owner_private_raw_archive": "automatic_lossless",
    "relationship_claim": "proposal_confirmation_required",
    "stable_profile_fact": "proposal_confirmation_required",
    "subjective_owner_state": "proposal_confirmation_required",
    "temporal_validity_active_fact": "p08_always_on_separate_contract",
}
