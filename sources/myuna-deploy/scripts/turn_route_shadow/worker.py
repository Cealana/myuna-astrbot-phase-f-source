#!/usr/bin/env python3
"""Socket-activated Turn/Route metadata-only Shadow candidate worker."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import argparse
import json
import os
from pathlib import Path
import socket
import stat
import time
from typing import Callable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import ProxyHandler, Request, build_opener
from uuid import UUID

from .hybrid_classifier import Decision, classify
from .metadata_shadow import (
    ALLOWED_ACTUAL_ROUTES,
    MetadataOnlyShadowRecorder,
    ShadowGroup,
    ShadowObservation,
    assert_metadata_only,
)


MAX_DATAGRAM_BYTES = 16_384
MAX_QUERY_CHARACTERS = 4096
ALLOWED_EVENT_KEYS = frozenset(
    {
        "schema_version",
        "boundary",
        "request_uuid",
        "query",
        "input_character_count",
        "event_count",
        "actual_route",
        "enqueue_monotonic_ns",
    }
)
ALLOWED_CONFIG_KEYS = frozenset(
    {
        "schema_version",
        "model_enabled",
        "model_endpoint",
        "model_timeout_ms",
        "model_id",
        "expected_model_sha256",
        "trace_retention_days",
    }
)
MODEL_INSTRUCTIONS = {
    "turn": (
        "Classify the final owner text. Return exactly A, B, or C. "
        "A=natural close, B=reply now, C=wait for continuation."
    ),
    "route": (
        "Classify the task tier. Return exactly A, B, C, or D. "
        "A=local low risk, B=default cloud, C=strong cloud, D=independent review."
    ),
}


class ModelUnavailable(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class WorkerConfig:
    model_enabled: bool
    model_endpoint: str
    model_timeout_ms: int
    model_id: str
    expected_model_sha256: str
    trace_retention_days: int

    @classmethod
    def from_payload(cls, payload: object) -> "WorkerConfig":
        if not isinstance(payload, Mapping) or set(payload) != ALLOWED_CONFIG_KEYS:
            raise ValueError("invalid_config")
        schema_version = payload.get("schema_version")
        if (
            not isinstance(schema_version, int)
            or isinstance(schema_version, bool)
            or schema_version != 1
        ):
            raise ValueError("invalid_config")
        enabled = payload.get("model_enabled")
        timeout_ms = payload.get("model_timeout_ms")
        retention = payload.get("trace_retention_days")
        endpoint = payload.get("model_endpoint")
        model_id = payload.get("model_id")
        digest = payload.get("expected_model_sha256")
        if not isinstance(enabled, bool):
            raise ValueError("invalid_config")
        if not isinstance(timeout_ms, int) or not 100 <= timeout_ms <= 5000:
            raise ValueError("invalid_config")
        if retention != 7:
            raise ValueError("invalid_config")
        if endpoint != "http://127.0.0.1:18093":
            raise ValueError("invalid_config")
        parsed = urlparse(str(endpoint))
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
            raise ValueError("invalid_config")
        if parsed.port != 18093 or parsed.path not in {"", "/"}:
            raise ValueError("invalid_config")
        if model_id != "Qwen3.5-4B-Q4_K_M":
            raise ValueError("invalid_config")
        if not isinstance(digest, str) or len(digest) != 64:
            raise ValueError("invalid_config")
        try:
            int(digest, 16)
        except ValueError:
            raise ValueError("invalid_config") from None
        return cls(
            model_enabled=enabled,
            model_endpoint=str(endpoint),
            model_timeout_ms=timeout_ms,
            model_id=str(model_id),
            expected_model_sha256=digest,
            trace_retention_days=retention,
        )


@dataclass(frozen=True, slots=True)
class ShadowEvent:
    request_uuid: str
    query: str
    input_character_count: int
    event_count: int
    actual_route: str
    enqueue_monotonic_ns: int


@dataclass(frozen=True, slots=True)
class EventOutcome:
    traces: tuple[dict[str, object], ...]
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
            sort_keys=True,
            separators=(",", ":"),
        )
        with self.path.open("a", encoding="ascii", newline="\n") as handle:
            handle.write(encoded + "\n")


class LoopbackModelClient:
    def __init__(self, config: WorkerConfig) -> None:
        self.config = config
        self.opener = build_opener(ProxyHandler({}))

    def __call__(self, group: str, text: str) -> str:
        if not self.config.model_enabled:
            raise ModelUnavailable("model_disabled")
        instruction = MODEL_INSTRUCTIONS.get(group)
        if instruction is None:
            raise ModelUnavailable("unsupported_group")
        body = json.dumps(
            {
                "model": "local-router-4b-hybrid-v1",
                "messages": [
                    {"role": "system", "content": instruction},
                    {"role": "user", "content": text},
                ],
                "temperature": 0,
                "max_tokens": 1,
                "stream": False,
                "chat_template_kwargs": {"enable_thinking": False},
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        request = Request(
            self.config.model_endpoint.rstrip("/") + "/v1/chat/completions",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with self.opener.open(
                request,
                timeout=self.config.model_timeout_ms / 1000,
            ) as response:
                raw = response.read(4097)
                if response.status != 200 or len(raw) > 4096:
                    raise ModelUnavailable("model_unavailable")
            payload = json.loads(raw.decode("utf-8"))
            choices = payload.get("choices") if isinstance(payload, dict) else None
            if not isinstance(choices, list) or len(choices) != 1:
                raise ModelUnavailable("model_unavailable")
            message = choices[0].get("message")
            content = message.get("content") if isinstance(message, dict) else None
            if not isinstance(content, str):
                raise ModelUnavailable("model_unavailable")
            return content.strip()
        except (
            HTTPError,
            URLError,
            TimeoutError,
            OSError,
            UnicodeError,
            json.JSONDecodeError,
        ):
            raise ModelUnavailable("model_unavailable") from None


def parse_event(datagram: bytes) -> ShadowEvent:
    if not datagram or len(datagram) > MAX_DATAGRAM_BYTES:
        raise ValueError("invalid_event")
    try:
        payload = json.loads(datagram.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError("invalid_event") from None
    if not isinstance(payload, dict) or set(payload) != ALLOWED_EVENT_KEYS:
        raise ValueError("invalid_event")
    schema_version = payload.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != 1
    ):
        raise ValueError("invalid_event")
    if payload.get("boundary") != "verified_owner_private_text_post_reply":
        raise ValueError("invalid_event")
    try:
        UUID(str(payload.get("request_uuid") or ""))
    except ValueError:
        raise ValueError("invalid_event") from None
    query = payload.get("query")
    if not isinstance(query, str) or not query.strip():
        raise ValueError("invalid_event")
    if len(query) > MAX_QUERY_CHARACTERS:
        raise ValueError("invalid_event")
    character_count = payload.get("input_character_count")
    if (
        not isinstance(character_count, int)
        or isinstance(character_count, bool)
        or character_count != len(query)
    ):
        raise ValueError("invalid_event")
    event_count = payload.get("event_count")
    if (
        not isinstance(event_count, int)
        or isinstance(event_count, bool)
        or event_count != 1
    ):
        raise ValueError("invalid_event")
    actual_route = payload.get("actual_route")
    if actual_route not in ALLOWED_ACTUAL_ROUTES:
        raise ValueError("invalid_event")
    enqueue_ns = payload.get("enqueue_monotonic_ns")
    if not isinstance(enqueue_ns, int) or isinstance(enqueue_ns, bool) or enqueue_ns <= 0:
        raise ValueError("invalid_event")
    return ShadowEvent(
        request_uuid=str(payload["request_uuid"]),
        query=query,
        input_character_count=len(query),
        event_count=1,
        actual_route=str(actual_route),
        enqueue_monotonic_ns=enqueue_ns,
    )


def _observation(
    event: ShadowEvent,
    group: ShadowGroup,
    decision: Decision,
    latency_ms: float,
    observed_at: datetime,
) -> ShadowObservation:
    return ShadowObservation(
        request_id=event.request_uuid,
        group=group,
        label=decision.label,
        source=decision.source,
        reason_code=decision.reason,
        observed_at=observed_at,
        latency_ms=latency_ms,
        input_char_count=event.input_character_count,
        event_count=event.event_count,
        model_valid=decision.model_valid,
        actual_route=event.actual_route if group is ShadowGroup.ROUTE else None,
    )


def handle_event(
    datagram: bytes,
    *,
    model_call: Callable[[str, str], str],
    sink: TraceSink,
    observed_at: datetime | None = None,
) -> EventOutcome:
    try:
        event = parse_event(datagram)
    except ValueError:
        return EventOutcome((), "invalid_event")

    now = observed_at or datetime.now(timezone.utc)
    traces: list[dict[str, object]] = []
    recorder = MetadataOnlyShadowRecorder(sink)
    for group in (ShadowGroup.TURN, ShadowGroup.ROUTE):
        started = time.monotonic_ns()
        decision = classify(group.value, event.query, model_call)
        latency_ms = (time.monotonic_ns() - started) / 1_000_000
        observation = _observation(event, group, decision, latency_ms, now)
        trace = observation.as_metadata()
        outcome = recorder.observe(observation)
        if not outcome.trace_written:
            return EventOutcome(tuple(traces), outcome.safe_error_class)
        traces.append(trace)
    return EventOutcome(tuple(traces), None)


def load_config(path: Path) -> WorkerConfig:
    metadata = path.stat()
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid != 0 or mode & 0o022:
        raise ValueError("invalid_config")
    payload = json.loads(path.read_text(encoding="utf-8"))
    return WorkerConfig.from_payload(payload)


def serve_systemd_socket(
    *,
    config: WorkerConfig,
    trace_path: Path,
) -> None:
    if int(os.environ.get("LISTEN_FDS", "0")) != 1:
        raise RuntimeError("systemd_socket_required")
    listen_pid = int(os.environ.get("LISTEN_PID", "0"))
    if listen_pid not in (0, os.getpid()):
        raise RuntimeError("systemd_socket_pid_mismatch")
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    model = LoopbackModelClient(config)
    sink = JsonlTraceSink(trace_path)
    print("turn route Shadow stage=ready", flush=True)
    with socket.fromfd(3, socket.AF_UNIX, socket.SOCK_DGRAM) as server:
        while True:
            datagram = server.recv(MAX_DATAGRAM_BYTES + 1)
            try:
                outcome = handle_event(datagram, model_call=model, sink=sink)
                if outcome.safe_error_class is not None:
                    print("turn route Shadow stage=safe_drop", flush=True)
            except Exception:
                print("turn route Shadow stage=safe_drop", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--trace", required=True)
    args = parser.parse_args()
    config = load_config(Path(args.config))
    serve_systemd_socket(config=config, trace_path=Path(args.trace))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
