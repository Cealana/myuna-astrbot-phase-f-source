#!/usr/bin/env python3
"""Socket-activated, content-free Natural Degradation R2C Shadow worker."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import argparse
import json
import os
from pathlib import Path
import re
import socket
import time
from typing import Mapping, Protocol
from uuid import UUID


EVENT_SCHEMA = "myuna.degradation-shadow.event.v1"
TRACE_SCHEMA = "myuna.degradation-shadow.metadata.v1"
MAX_DATAGRAM_BYTES = 4096
LEGACY_RESPONSE_CODE = "owner-runtime-unavailable"
ALLOWED_SOURCES = frozenset({"core", "gateway"})
ALLOWED_CATEGORIES = frozenset(
    {
        "memory_no_evidence",
        "reply_contract_rejected",
        "provider_transient_failure",
        "provider_budget_or_auth_failure",
        "core_or_gateway_failure",
        "memory_service_failure",
        "onebot_or_napcat_offline",
        "host_or_network_unreachable",
        "scheduled_notification_unavailable",
        "memory_write_unavailable",
        "external_data_unavailable",
        "vision_unavailable",
        "external_action_unavailable",
    }
)
ALLOWED_RECOVERY_STATES = frozenset({"active", "recovering", "recovered"})
EVENT_FIELDS = frozenset(
    {
        "schema",
        "boundary",
        "observation_uuid",
        "legacy_response_code",
        "projection_source",
        "category",
        "retryable",
        "owner_action_required",
        "safe_detail_code",
        "recovery_state",
        "fingerprint",
        "enqueue_monotonic_ns",
    }
)
TRACE_FIELDS = frozenset(
    {
        "schema",
        "observation_uuid",
        "observed_at",
        "legacy_response_code",
        "projection_source",
        "category",
        "retryable",
        "owner_action_required",
        "safe_detail_code",
        "recovery_state",
        "fingerprint",
        "delivery_latency_bucket",
        "comparison_result",
        "legacy_visible_path",
        "shadow_only",
        "production_effect",
    }
)
_SAFE_DETAIL = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
_SAFE_FINGERPRINT = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,383}$")


@dataclass(frozen=True, slots=True)
class ShadowEvent:
    observation_uuid: str
    legacy_response_code: str
    projection_source: str
    category: str
    retryable: bool
    owner_action_required: bool
    safe_detail_code: str
    recovery_state: str
    fingerprint: str
    enqueue_monotonic_ns: int


@dataclass(frozen=True, slots=True)
class EventOutcome:
    trace_written: bool
    safe_error_class: str | None
    production_effect: str = "none"


class TraceSink(Protocol):
    def append(self, trace: Mapping[str, object]) -> None: ...


class JsonlTraceSink:
    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, trace: Mapping[str, object]) -> None:
        assert_metadata_only(trace)
        encoded = json.dumps(
            dict(trace),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        with self.path.open("a", encoding="ascii", newline="\n") as handle:
            handle.write(encoded + "\n")


def parse_event(datagram: bytes) -> ShadowEvent:
    if not datagram or len(datagram) > MAX_DATAGRAM_BYTES:
        raise ValueError("invalid_event")
    try:
        payload = json.loads(datagram.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError("invalid_event") from None
    if not isinstance(payload, Mapping) or set(payload) != EVENT_FIELDS:
        raise ValueError("invalid_event")
    if payload.get("schema") != EVENT_SCHEMA:
        raise ValueError("invalid_event")
    if payload.get("boundary") != "verified_owner_private_failure_post_response":
        raise ValueError("invalid_event")
    try:
        UUID(str(payload.get("observation_uuid") or ""))
    except ValueError:
        raise ValueError("invalid_event") from None
    if payload.get("legacy_response_code") != LEGACY_RESPONSE_CODE:
        raise ValueError("invalid_event")
    if payload.get("projection_source") not in ALLOWED_SOURCES:
        raise ValueError("invalid_event")
    if payload.get("category") not in ALLOWED_CATEGORIES:
        raise ValueError("invalid_event")
    if type(payload.get("retryable")) is not bool:
        raise ValueError("invalid_event")
    if type(payload.get("owner_action_required")) is not bool:
        raise ValueError("invalid_event")
    detail = payload.get("safe_detail_code")
    fingerprint = payload.get("fingerprint")
    if not isinstance(detail, str) or _SAFE_DETAIL.fullmatch(detail) is None:
        raise ValueError("invalid_event")
    if (
        not isinstance(fingerprint, str)
        or _SAFE_FINGERPRINT.fullmatch(fingerprint) is None
    ):
        raise ValueError("invalid_event")
    if payload.get("recovery_state") not in ALLOWED_RECOVERY_STATES:
        raise ValueError("invalid_event")
    enqueue_ns = payload.get("enqueue_monotonic_ns")
    if type(enqueue_ns) is not int or enqueue_ns <= 0:
        raise ValueError("invalid_event")
    return ShadowEvent(
        observation_uuid=str(payload["observation_uuid"]),
        legacy_response_code=LEGACY_RESPONSE_CODE,
        projection_source=str(payload["projection_source"]),
        category=str(payload["category"]),
        retryable=payload["retryable"],
        owner_action_required=payload["owner_action_required"],
        safe_detail_code=detail,
        recovery_state=str(payload["recovery_state"]),
        fingerprint=fingerprint,
        enqueue_monotonic_ns=enqueue_ns,
    )


def _latency_bucket(milliseconds: float) -> str:
    if milliseconds < 10:
        return "lt10ms"
    if milliseconds < 50:
        return "10-49ms"
    if milliseconds < 150:
        return "50-149ms"
    if milliseconds < 500:
        return "150-499ms"
    return "gte500ms"


def trace_for_event(
    event: ShadowEvent,
    *,
    observed_at: datetime,
    monotonic_ns: int,
) -> dict[str, object]:
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise ValueError("observed_at must be timezone-aware")
    latency_ms = max(0, monotonic_ns - event.enqueue_monotonic_ns) / 1_000_000
    trace: dict[str, object] = {
        "schema": TRACE_SCHEMA,
        "observation_uuid": event.observation_uuid,
        "observed_at": observed_at.astimezone(timezone.utc).isoformat(),
        "legacy_response_code": event.legacy_response_code,
        "projection_source": event.projection_source,
        "category": event.category,
        "retryable": event.retryable,
        "owner_action_required": event.owner_action_required,
        "safe_detail_code": event.safe_detail_code,
        "recovery_state": event.recovery_state,
        "fingerprint": event.fingerprint,
        "delivery_latency_bucket": _latency_bucket(latency_ms),
        "comparison_result": "typed_projection_available",
        "legacy_visible_path": "unchanged",
        "shadow_only": True,
        "production_effect": "none",
    }
    assert_metadata_only(trace)
    return trace


def assert_metadata_only(trace: Mapping[str, object]) -> None:
    if set(trace) != TRACE_FIELDS:
        raise ValueError("invalid_trace")
    forbidden_fragments = (
        "message",
        "prompt",
        "reply",
        "text",
        "account",
        "qq",
        "principal",
        "namespace",
        "credential",
        "secret",
        "token",
        "cookie",
        "memory",
        "provider_output",
        "model",
        "raw",
        "exception",
        "log",
    )
    for key in trace:
        lowered = str(key).lower()
        if any(fragment in lowered for fragment in forbidden_fragments):
            raise ValueError("invalid_trace")
    if trace.get("shadow_only") is not True:
        raise ValueError("invalid_trace")
    if trace.get("production_effect") != "none":
        raise ValueError("invalid_trace")
    encoded = json.dumps(dict(trace), ensure_ascii=True, sort_keys=True)
    if len(encoded) > MAX_DATAGRAM_BYTES:
        raise ValueError("invalid_trace")


def handle_event(
    datagram: bytes,
    *,
    sink: TraceSink,
    observed_at: datetime | None = None,
    monotonic_ns: int | None = None,
) -> EventOutcome:
    try:
        event = parse_event(datagram)
        trace = trace_for_event(
            event,
            observed_at=observed_at or datetime.now(timezone.utc),
            monotonic_ns=monotonic_ns or time.monotonic_ns(),
        )
    except (TypeError, ValueError):
        return EventOutcome(False, "invalid_event")
    try:
        sink.append(trace)
    except Exception:
        return EventOutcome(False, "metadata_sink_unavailable")
    return EventOutcome(True, None)


def serve_systemd_socket(trace_path: Path) -> None:
    if int(os.environ.get("LISTEN_FDS", "0")) != 1:
        raise RuntimeError("systemd_socket_required")
    listen_pid = int(os.environ.get("LISTEN_PID", "0"))
    if listen_pid not in (0, os.getpid()):
        raise RuntimeError("systemd_socket_pid_mismatch")
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    sink = JsonlTraceSink(trace_path)
    print("natural degradation Shadow stage=ready", flush=True)
    with socket.fromfd(3, socket.AF_UNIX, socket.SOCK_DGRAM) as server:
        while True:
            datagram = server.recv(MAX_DATAGRAM_BYTES + 1)
            try:
                outcome = handle_event(datagram, sink=sink)
                if not outcome.trace_written:
                    print("natural degradation Shadow stage=safe_drop", flush=True)
            except Exception:
                print("natural degradation Shadow stage=safe_drop", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace", required=True)
    arguments = parser.parse_args()
    serve_systemd_socket(Path(arguments.trace))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
