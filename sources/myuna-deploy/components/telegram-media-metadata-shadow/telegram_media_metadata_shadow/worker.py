#!/usr/bin/env python3
"""Identity- and content-free Telegram media metadata Shadow worker."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import argparse
import json
import os
from pathlib import Path
import socket
import time
from typing import Mapping
from uuid import UUID


EVENT_SCHEMA = "myuna.telegram-media-metadata-shadow.event.v1"
TRACE_SCHEMA = "myuna.telegram-media-metadata-shadow.trace.v1"
MAX_DATAGRAM_BYTES = 2048
EVENT_FIELDS = frozenset(
    {
        "attachment_count_bucket",
        "attachment_kind",
        "boundary",
        "caption_present",
        "enqueue_monotonic_ns",
        "observation_uuid",
        "schema",
    }
)
TRACE_FIELDS = frozenset(
    {
        "attachment_count_bucket",
        "attachment_kind",
        "auth_boundary",
        "caption_present",
        "delivery_latency_bucket",
        "observed_at",
        "observation_uuid",
        "production_effect",
        "schema",
        "shadow_only",
        "visible_behavior",
    }
)


@dataclass(frozen=True, slots=True)
class ShadowEvent:
    observation_uuid: str
    attachment_count_bucket: str
    caption_present: bool
    enqueue_monotonic_ns: int


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
    if payload.get("boundary") != "verified_owner_private_media_pre_download":
        raise ValueError("invalid_event")
    if payload.get("attachment_kind") != "image_component":
        raise ValueError("invalid_event")
    try:
        UUID(str(payload.get("observation_uuid") or ""))
    except ValueError:
        raise ValueError("invalid_event") from None
    if payload.get("attachment_count_bucket") not in {"1", "2-4"}:
        raise ValueError("invalid_event")
    if type(payload.get("caption_present")) is not bool:
        raise ValueError("invalid_event")
    enqueue_ns = payload.get("enqueue_monotonic_ns")
    if type(enqueue_ns) is not int or enqueue_ns <= 0:
        raise ValueError("invalid_event")
    return ShadowEvent(
        observation_uuid=str(payload["observation_uuid"]),
        attachment_count_bucket=str(payload["attachment_count_bucket"]),
        caption_present=payload["caption_present"],
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


def trace_for_event(event: ShadowEvent, *, observed_at: datetime, monotonic_ns: int) -> dict[str, object]:
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise ValueError("observed_at must be timezone-aware")
    latency_ms = max(0, monotonic_ns - event.enqueue_monotonic_ns) / 1_000_000
    trace: dict[str, object] = {
        "attachment_count_bucket": event.attachment_count_bucket,
        "attachment_kind": "image_component",
        "auth_boundary": "verified_owner_private",
        "caption_present": event.caption_present,
        "delivery_latency_bucket": _latency_bucket(latency_ms),
        "observed_at": observed_at.astimezone(timezone.utc).isoformat(),
        "observation_uuid": event.observation_uuid,
        "production_effect": "none",
        "schema": TRACE_SCHEMA,
        "shadow_only": True,
        "visible_behavior": "unchanged_silent_nontext_boundary",
    }
    assert_metadata_only(trace)
    return trace


def assert_metadata_only(trace: Mapping[str, object]) -> None:
    if set(trace) != TRACE_FIELDS:
        raise ValueError("invalid_trace")
    forbidden = (
        "account", "actor", "binding", "byte", "caption_text", "content",
        "credential", "file", "hash", "message", "mime", "namespace",
        "path", "principal", "prompt", "ref", "secret", "token", "url",
    )
    for key in trace:
        if any(fragment in str(key).casefold() for fragment in forbidden):
            raise ValueError("invalid_trace")
    if trace.get("shadow_only") is not True or trace.get("production_effect") != "none":
        raise ValueError("invalid_trace")
    encoded = json.dumps(dict(trace), ensure_ascii=True, sort_keys=True)
    if len(encoded) > MAX_DATAGRAM_BYTES:
        raise ValueError("invalid_trace")


def handle_event(datagram: bytes, *, observed_at: datetime | None = None, monotonic_ns: int | None = None) -> dict[str, object] | None:
    try:
        return trace_for_event(
            parse_event(datagram),
            observed_at=observed_at or datetime.now(timezone.utc),
            monotonic_ns=monotonic_ns or time.monotonic_ns(),
        )
    except (TypeError, ValueError):
        return None


def serve(trace_path: Path) -> None:
    if int(os.environ.get("LISTEN_FDS", "0")) != 1:
        raise RuntimeError("systemd_socket_required")
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    print("telegram media metadata Shadow stage=ready", flush=True)
    with socket.fromfd(3, socket.AF_UNIX, socket.SOCK_DGRAM) as server:
        while True:
            trace = handle_event(server.recv(MAX_DATAGRAM_BYTES + 1))
            if trace is None:
                print("telegram media metadata Shadow stage=safe_drop", flush=True)
                continue
            with trace_path.open("a", encoding="ascii", newline="\n") as handle:
                handle.write(json.dumps(trace, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace", type=Path, required=True)
    args = parser.parse_args()
    serve(args.trace)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
