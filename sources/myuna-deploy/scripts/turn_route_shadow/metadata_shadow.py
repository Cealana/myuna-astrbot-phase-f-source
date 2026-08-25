from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import json
import re
from typing import Mapping, Protocol
from uuid import UUID


SCHEMA_VERSION = "myuna.hybrid-shadow.metadata.v1"
CLASSIFIER_VERSION = "hybrid-turn-route-v1"


class ShadowGroup(str, Enum):
    TURN = "turn"
    ROUTE = "route"


TURN_MEANINGS = {
    "A": "would_close_silently",
    "B": "would_reply",
    "C": "would_wait_more",
}
ROUTE_MEANINGS = {
    "A": "local_low_risk",
    "B": "deepseek_default",
    "C": "deepseek_pro",
    "D": "openai_or_independent_review",
}
ALLOWED_SOURCES = frozenset({"rule", "model", "fallback"})
ALLOWED_ACTUAL_ROUTES = frozenset(
    {
        "local_low_risk",
        "deepseek_default",
        "deepseek_pro",
        "openai_or_independent_review",
        "fallback",
        "unknown",
    }
)


def _size_bucket(value: int) -> str:
    if value <= 16:
        return "1-16"
    if value <= 64:
        return "17-64"
    if value <= 256:
        return "65-256"
    if value <= 1024:
        return "257-1024"
    return "1025-4096"


def _event_count_bucket(value: int) -> str:
    if value == 1:
        return "1"
    if value <= 4:
        return "2-4"
    if value <= 8:
        return "5-8"
    if value <= 16:
        return "9-16"
    return "17-32"


def _latency_bucket(value: float) -> str:
    if value < 10:
        return "lt10ms"
    if value < 50:
        return "10-49ms"
    if value < 150:
        return "50-149ms"
    if value < 500:
        return "150-499ms"
    return "gte500ms"


@dataclass(frozen=True, slots=True)
class ShadowObservation:
    request_id: str
    group: ShadowGroup
    label: str
    source: str
    reason_code: str
    observed_at: datetime
    latency_ms: float
    input_char_count: int
    event_count: int = 1
    model_valid: bool = True
    actual_route: str | None = None
    classifier_version: str = CLASSIFIER_VERSION

    def __post_init__(self) -> None:
        UUID(self.request_id)
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        if self.source not in ALLOWED_SOURCES:
            raise ValueError("invalid decision source")
        if not re.fullmatch(r"[a-z][a-z0-9_]{2,63}", self.reason_code):
            raise ValueError("invalid reason code")
        if not re.fullmatch(
            r"[a-z0-9][a-z0-9._-]{2,63}", self.classifier_version
        ):
            raise ValueError("invalid classifier version")
        if not 0 <= self.latency_ms <= 60_000:
            raise ValueError("invalid latency")
        if not 1 <= self.input_char_count <= 4096:
            raise ValueError("invalid input size")
        if not 1 <= self.event_count <= 32:
            raise ValueError("invalid event count")
        if self.group is ShadowGroup.TURN:
            if self.label not in TURN_MEANINGS or self.actual_route is not None:
                raise ValueError("invalid Turn observation")
        elif self.group is ShadowGroup.ROUTE:
            if self.label not in ROUTE_MEANINGS:
                raise ValueError("invalid Route observation")
            if self.actual_route not in ALLOWED_ACTUAL_ROUTES:
                raise ValueError("invalid actual route")
        else:
            raise ValueError("invalid Shadow group")

    def as_metadata(self) -> dict[str, object]:
        base: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "request_id": self.request_id,
            "observed_at": self.observed_at.astimezone(timezone.utc).isoformat(),
            "group": self.group.value,
            "classifier_version": self.classifier_version,
            "decision_label": self.label,
            "decision_source": self.source,
            "reason_code": self.reason_code,
            "model_valid": self.model_valid,
            "latency_bucket": _latency_bucket(self.latency_ms),
            "input_size_bucket": _size_bucket(self.input_char_count),
            "event_count_bucket": _event_count_bucket(self.event_count),
            "shadow_only": True,
            "production_effect": "none",
        }
        if self.group is ShadowGroup.TURN:
            base.update(
                {
                    "suggested_turn_action": TURN_MEANINGS[self.label],
                    "actual_reply_path": "unchanged_pass_through",
                    "reply_suppressed": False,
                    "reply_delayed": False,
                }
            )
        else:
            suggested = ROUTE_MEANINGS[self.label]
            base.update(
                {
                    "suggested_route": suggested,
                    "actual_route": self.actual_route,
                    "would_differ": suggested != self.actual_route,
                    "provider_switched": False,
                }
            )
        assert_metadata_only(base)
        return base


@dataclass(frozen=True, slots=True)
class ShadowOutcome:
    trace_written: bool
    safe_error_class: str | None
    production_effect: str = "none"


class MetadataSink(Protocol):
    def append(self, trace: Mapping[str, object]) -> None: ...


class MetadataOnlyShadowRecorder:
    def __init__(self, sink: MetadataSink) -> None:
        self.sink = sink

    def observe(self, observation: object) -> ShadowOutcome:
        try:
            if not isinstance(observation, ShadowObservation):
                raise ValueError("invalid observation object")
            trace = observation.as_metadata()
        except Exception:
            return ShadowOutcome(False, "invalid_observation")
        try:
            self.sink.append(trace)
        except Exception:
            return ShadowOutcome(False, "metadata_sink_unavailable")
        return ShadowOutcome(True, None)


def assert_metadata_only(trace: Mapping[str, object]) -> None:
    forbidden_fragments = (
        "text",
        "message",
        "prompt",
        "reply_content",
        "qq",
        "account",
        "principal",
        "namespace",
        "credential",
        "secret",
        "token",
        "cookie",
        "qr",
        "memory",
        "input_sha",
        "provider_name",
        "model_name",
        "route_reason",
    )
    for key in trace:
        lowered = str(key).lower()
        if any(fragment in lowered for fragment in forbidden_fragments):
            raise ValueError(f"forbidden metadata key: {key}")
    encoded = json.dumps(dict(trace), ensure_ascii=True, sort_keys=True)
    if len(encoded) > 4096:
        raise ValueError("trace exceeds metadata limit")
    if trace.get("shadow_only") is not True:
        raise ValueError("trace is not Shadow-only")
    if trace.get("production_effect") != "none":
        raise ValueError("trace has a production effect")
