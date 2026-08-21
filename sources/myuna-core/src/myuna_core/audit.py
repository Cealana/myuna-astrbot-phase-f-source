from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
import json
import re


SENSITIVE_KEY_FRAGMENTS = (
    "account_fingerprint",
    "account_id",
    "actor_id",
    "api_key",
    "authorization",
    "cookie",
    "credential",
    "nonce",
    "password",
    "qq_id",
    "secret",
    "session",
    "signature",
    "token",
)
SAFE_TOKEN_METRIC_KEYS = frozenset(
    {
        "cache_hit_tokens",
        "cache_miss_tokens",
        "input_tokens",
        "max_output_tokens",
        "output_tokens",
        "reasoning_tokens",
        "total_tokens",
    }
)
_TRACE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_TRACE_STAGES = frozenset(
    {
        "core_request_started",
        "provider_attempt_started",
        "provider_response_received",
        "core_response_returned",
    }
)
_TRACE_STATUSES = frozenset({"started", "succeeded", "failed", "rejected"})


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).lower()
            if normalized not in SAFE_TOKEN_METRIC_KEYS and any(
                fragment in normalized for fragment in SENSITIVE_KEY_FRAGMENTS
            ):
                result[str(key)] = "[REDACTED]"
            else:
                result[str(key)] = redact(item)
        return result
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    return value


class AuditLogger:
    def __init__(self, log_dir: Path, environment: str) -> None:
        self.log_dir = log_dir
        self.environment = environment
        self.path = log_dir / "audit.jsonl"

    def emit(
        self,
        event: str,
        *,
        outcome: str = "ok",
        request_id: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.path.touch(mode=0o600, exist_ok=True)
        self.path.chmod(0o600)
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "environment": self.environment,
            "event": event,
            "outcome": outcome,
            "request_id": request_id,
            "details": redact(details or {}),
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    def emit_trace_marker(
        self,
        *,
        trace_id: str,
        stage: str,
        status: str,
        attempt_ordinal: int = 1,
        round_ordinal: int = 0,
    ) -> None:
        if (
            type(trace_id) is not str
            or _TRACE_ID.fullmatch(trace_id) is None
            or type(stage) is not str
            or stage not in _TRACE_STAGES
            or type(status) is not str
            or status not in _TRACE_STATUSES
            or type(attempt_ordinal) is not int
            or type(round_ordinal) is not int
            or attempt_ordinal < 0
            or round_ordinal < 0
        ):
            raise ValueError("content-free trace marker rejected")
        marker = {
                "attempt_ordinal": attempt_ordinal,
                "round_ordinal": round_ordinal,
                "stage": stage,
                "status": status,
                "trace_id": trace_id,
                "version": 1,
        }
        record = {
            "marker": marker,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        encoded = json.dumps(
            record,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        if "\n" in encoded or "\r" in encoded:
            raise ValueError("content-free trace marker rejected")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.path.touch(mode=0o600, exist_ok=True)
        self.path.chmod(0o600)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded + "\n")
