from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import json
import math
from pathlib import Path
import re
import socket
import time
from typing import Any, Mapping, Protocol


OWNER_NAMESPACE = "ns-owner-cealana-private"
OWNER_BOUNDARY = "verified_owner_private_text"
OWNER_MEMORY_CAPABILITY_SCOPE = (
    "verified owner private QQ text; owner namespace; non-restricted; "
    "read-only prompt context"
)
OWNER_MEMORY_SOCKET_V1 = Path("/run/myuna-owner-memory-read-v1/worker.sock")
OWNER_MEMORY_POLICY_V1 = "owner-qq-readonly-injection-deterministic-zh-v1"

MAX_QUERY_CHARACTERS = 256
MAX_REQUEST_BYTES = 4096
MAX_RESPONSE_BYTES = 65_536
MAX_RECENT_RECORDS = 1
MAX_DEEP_RECORDS = 3
MAX_CONTEXT_CHARACTERS = 12_000

_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_MEMORY_KINDS = frozenset(
    {
        "episodic",
        "exact_quote",
        "anchor",
        "fact",
        "preference",
        "current_state",
        "rationale",
        "relationship",
        "project",
    }
)
_DEEP_TERMS = (
    "记得",
    "回忆",
    "以前",
    "第一回",
    "第一次",
    "首次",
    "原话",
    "逐字",
    "当时为什么",
    "什么时候",
    "哪一天",
    "几点",
    "经过",
    "详细说说",
)


class OwnerMemoryReadError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class AuditSink(Protocol):
    def emit(
        self,
        event: str,
        *,
        outcome: str = "ok",
        request_id: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None: ...


class OwnerMemoryClient(Protocol):
    def retrieve(
        self,
        query: str,
        *,
        mode: str,
        request_id: str,
        timeout_seconds: float,
    ) -> "OwnerMemoryResult": ...


@dataclass(frozen=True, slots=True)
class OwnerMemoryRationale:
    status: str
    text: str


@dataclass(frozen=True, slots=True)
class OwnerMemoryAnchor:
    title: str
    preservation_note: str | None


@dataclass(frozen=True, slots=True)
class OwnerMemoryRecord:
    memory_id: str
    memory_kind: str
    memory_status: str
    confirmation_level: str
    importance: float
    sensitivity: str
    assertion_text: str
    exact_quote: str | None
    occurred_at: str
    time_precision: str
    time_phrase: str | None
    scope: tuple[str, ...]
    tags: tuple[str, ...]
    rationales: tuple[OwnerMemoryRationale, ...]
    anchors: tuple[OwnerMemoryAnchor, ...]


@dataclass(frozen=True, slots=True)
class OwnerMemoryResult:
    request_id: str
    mode_used: str
    policy_version: str
    duration_ms: float
    records: tuple[OwnerMemoryRecord, ...]


@dataclass(frozen=True, slots=True)
class OwnerMemorySelection:
    state: str
    context: str | None
    hit_ids: tuple[str, ...]
    mode_used: str
    policy_version: str


def query_fingerprint(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def classify_owner_memory_mode(query: str) -> str:
    normalized = query.casefold()
    return "deep" if any(term in normalized for term in _DEEP_TERMS) else "recent"


def _require_safe_label(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _SAFE_LABEL.fullmatch(value) is None:
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    return value


def _require_text(
    value: object,
    field_name: str,
    *,
    maximum: int,
    optional: bool = False,
) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    if "\x00" in value:
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    return value.strip()


def _require_finite(value: object, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    result = float(value)
    if not math.isfinite(result):
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    return result


def _require_timestamp(value: object) -> str:
    text = _require_text(value, "occurred_at", maximum=64)
    assert text is not None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    return parsed.isoformat()


def _parse_string_list(value: object, *, maximum: int) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum:
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    result: list[str] = []
    for item in value:
        text = _require_text(item, "list_item", maximum=128)
        assert text is not None
        result.append(text)
    return tuple(result)


def _parse_rationales(value: object) -> tuple[OwnerMemoryRationale, ...]:
    if not isinstance(value, list) or len(value) > 4:
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    result: list[OwnerMemoryRationale] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"status", "text"}:
            raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
        status = _require_safe_label(item["status"], "rationale.status")
        text = _require_text(item["text"], "rationale.text", maximum=2000)
        assert text is not None
        result.append(OwnerMemoryRationale(status=status, text=text))
    return tuple(result)


def _parse_anchors(value: object) -> tuple[OwnerMemoryAnchor, ...]:
    if not isinstance(value, list) or len(value) > 3:
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    result: list[OwnerMemoryAnchor] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"title", "preservation_note"}:
            raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
        title = _require_text(item["title"], "anchor.title", maximum=512)
        note = _require_text(
            item["preservation_note"],
            "anchor.preservation_note",
            maximum=1200,
            optional=True,
        )
        assert title is not None
        result.append(OwnerMemoryAnchor(title=title, preservation_note=note))
    return tuple(result)


_RECORD_KEYS = {
    "memory_id",
    "memory_kind",
    "memory_status",
    "confirmation_level",
    "importance",
    "sensitivity",
    "assertion_text",
    "exact_quote",
    "occurred_at",
    "time_precision",
    "time_phrase",
    "scope",
    "tags",
    "rationales",
    "anchors",
}


def parse_owner_memory_record(payload: object) -> OwnerMemoryRecord:
    if not isinstance(payload, dict) or set(payload) != _RECORD_KEYS:
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    memory_id = _require_safe_label(payload["memory_id"], "memory_id")
    memory_kind = _require_safe_label(payload["memory_kind"], "memory_kind")
    if memory_kind not in _MEMORY_KINDS:
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    memory_status = _require_safe_label(payload["memory_status"], "memory_status")
    if memory_status not in {"confirmed", "provisional"}:
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    confirmation = _require_safe_label(
        payload["confirmation_level"], "confirmation_level"
    )
    if confirmation != "user_confirmed":
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    sensitivity = _require_safe_label(payload["sensitivity"], "sensitivity")
    if sensitivity != "normal":
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    importance = _require_finite(payload["importance"], "importance")
    if not 0.0 <= importance <= 1.0:
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    assertion = _require_text(
        payload["assertion_text"], "assertion_text", maximum=4000
    )
    exact_quote = _require_text(
        payload["exact_quote"], "exact_quote", maximum=2000, optional=True
    )
    time_precision = _require_safe_label(payload["time_precision"], "time_precision")
    time_phrase = _require_text(
        payload["time_phrase"], "time_phrase", maximum=128, optional=True
    )
    assert assertion is not None
    record = OwnerMemoryRecord(
        memory_id=memory_id,
        memory_kind=memory_kind,
        memory_status=memory_status,
        confirmation_level=confirmation,
        importance=importance,
        sensitivity=sensitivity,
        assertion_text=assertion,
        exact_quote=exact_quote,
        occurred_at=_require_timestamp(payload["occurred_at"]),
        time_precision=time_precision,
        time_phrase=time_phrase,
        scope=_parse_string_list(payload["scope"], maximum=12),
        tags=_parse_string_list(payload["tags"], maximum=16),
        rationales=_parse_rationales(payload["rationales"]),
        anchors=_parse_anchors(payload["anchors"]),
    )
    visible_characters = len(record.assertion_text) + len(record.exact_quote or "")
    visible_characters += sum(len(item.text) for item in record.rationales)
    visible_characters += sum(
        len(item.title) + len(item.preservation_note or "") for item in record.anchors
    )
    if visible_characters > 6000:
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    return record


_SUCCESS_KEYS = {
    "schema_version",
    "operation",
    "ok",
    "request_id",
    "boundary",
    "namespace_id",
    "mode_used",
    "policy_version",
    "model_called",
    "memory_write_performed",
    "restricted_included",
    "duration_ms",
    "records",
}
_ERROR_KEYS = {
    "schema_version",
    "operation",
    "ok",
    "request_id",
    "error",
}


def parse_owner_memory_response(
    payload: object,
    *,
    expected_request_id: str,
    expected_mode: str,
) -> OwnerMemoryResult:
    if not isinstance(payload, dict):
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    if payload.get("ok") is False:
        if set(payload) != _ERROR_KEYS:
            raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
        error = payload.get("error")
        if not isinstance(error, dict) or set(error) != {"code", "retryable"}:
            raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
        code = _require_safe_label(error.get("code"), "error.code")
        retryable = error.get("retryable")
        if not isinstance(retryable, bool):
            raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
        raise OwnerMemoryReadError(code, retryable=retryable)
    if set(payload) != _SUCCESS_KEYS:
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    if (
        payload.get("schema_version") != 1
        or payload.get("operation") != "owner_memory.retrieve"
        or payload.get("ok") is not True
        or payload.get("request_id") != expected_request_id
        or payload.get("boundary") != OWNER_BOUNDARY
        or payload.get("namespace_id") != OWNER_NAMESPACE
        or payload.get("mode_used") != expected_mode
        or payload.get("policy_version") != OWNER_MEMORY_POLICY_V1
        or payload.get("model_called") is not False
        or payload.get("memory_write_performed") is not False
        or payload.get("restricted_included") is not False
    ):
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    records_payload = payload.get("records")
    maximum = MAX_DEEP_RECORDS if expected_mode == "deep" else MAX_RECENT_RECORDS
    if not isinstance(records_payload, list) or len(records_payload) > maximum:
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    records = tuple(parse_owner_memory_record(item) for item in records_payload)
    identifiers = [item.memory_id for item in records]
    if len(identifiers) != len(set(identifiers)):
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    duration_ms = _require_finite(payload.get("duration_ms"), "duration_ms")
    if not 0 <= duration_ms <= 10_000:
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    return OwnerMemoryResult(
        request_id=expected_request_id,
        mode_used=expected_mode,
        policy_version=OWNER_MEMORY_POLICY_V1,
        duration_ms=duration_ms,
        records=records,
    )


class UnixSocketOwnerMemoryClient:
    def __init__(self, socket_path: Path = OWNER_MEMORY_SOCKET_V1) -> None:
        if not socket_path.is_absolute() or socket_path != OWNER_MEMORY_SOCKET_V1:
            raise ValueError("Owner Memory v1 requires its fixed Unix socket")
        self.socket_path = socket_path

    def retrieve(
        self,
        query: str,
        *,
        mode: str,
        request_id: str,
        timeout_seconds: float,
    ) -> OwnerMemoryResult:
        if (
            not isinstance(query, str)
            or not query.strip()
            or len(query) > MAX_QUERY_CHARACTERS
            or "\x00" in query
        ):
            raise OwnerMemoryReadError("query_out_of_contract", retryable=False)
        if mode not in {"recent", "deep"}:
            raise OwnerMemoryReadError("invalid_mode", retryable=False)
        _require_safe_label(request_id, "request_id")
        if not 0.1 <= timeout_seconds <= 3.0:
            raise OwnerMemoryReadError("invalid_timeout", retryable=False)
        request = json.dumps(
            {
                "schema_version": 1,
                "operation": "owner_memory.retrieve",
                "request_id": request_id,
                "boundary": OWNER_BOUNDARY,
                "query": query.strip(),
                "mode": mode,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        if len(request) > MAX_REQUEST_BYTES:
            raise OwnerMemoryReadError("query_out_of_contract", retryable=False)
        response = bytearray()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(timeout_seconds)
                client.connect(str(self.socket_path))
                client.sendall(request)
                client.shutdown(socket.SHUT_WR)
                while True:
                    chunk = client.recv(8192)
                    if not chunk:
                        break
                    response.extend(chunk)
                    if len(response) > MAX_RESPONSE_BYTES:
                        raise OwnerMemoryReadError(
                            "worker_response_too_large", retryable=False
                        )
        except OwnerMemoryReadError:
            raise
        except (OSError, TimeoutError) as exc:
            raise OwnerMemoryReadError("worker_unavailable", retryable=True) from exc
        try:
            payload = json.loads(response.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise OwnerMemoryReadError("invalid_worker_response", retryable=False) from exc
        return parse_owner_memory_response(
            payload,
            expected_request_id=request_id,
            expected_mode=mode,
        )


class AuditedOwnerMemoryReadAdapter:
    def __init__(
        self,
        client: OwnerMemoryClient,
        audit: AuditSink,
        *,
        caller: str = "myuna-core-qq-owner-readonly",
    ) -> None:
        _require_safe_label(caller, "caller")
        self.client = client
        self.audit = audit
        self.caller = caller

    def retrieve(
        self,
        query: str,
        *,
        mode: str,
        request_id: str,
        timeout_seconds: float,
    ) -> OwnerMemoryResult:
        started = time.perf_counter()
        common = {
            "caller": self.caller,
            "namespace_policy": "fixed_owner_namespace_v1",
            "restricted_allowed": False,
            "memory_write_allowed": False,
            "query_fingerprint": query_fingerprint(query),
            "query_characters": len(query),
            "mode_requested": mode,
        }
        try:
            result = self.client.retrieve(
                query,
                mode=mode,
                request_id=request_id,
                timeout_seconds=timeout_seconds,
            )
        except OwnerMemoryReadError as exc:
            self.audit.emit(
                "owner_memory_read",
                outcome="degraded" if exc.retryable else "rejected",
                request_id=request_id,
                details={
                    **common,
                    "error_code": exc.code,
                    "retryable": exc.retryable,
                    "bridge_duration_ms": round(
                        (time.perf_counter() - started) * 1000, 3
                    ),
                },
            )
            raise
        self.audit.emit(
            "owner_memory_read",
            outcome="ok" if result.records else "empty",
            request_id=request_id,
            details={
                **common,
                "mode_used": result.mode_used,
                "policy_version": result.policy_version,
                "hit_count": len(result.records),
                "hit_ids": [item.memory_id for item in result.records],
                "worker_duration_ms": result.duration_ms,
                "bridge_duration_ms": round(
                    (time.perf_counter() - started) * 1000, 3
                ),
            },
        )
        return result


def render_owner_memory_context(records: tuple[OwnerMemoryRecord, ...]) -> str:
    rendered: list[dict[str, object]] = []
    for index, record in enumerate(records, start=1):
        rendered.append(
            {
                "record": index,
                "kind": record.memory_kind,
                "status": record.memory_status,
                "confirmation": record.confirmation_level,
                "importance": record.importance,
                "occurred_at": record.occurred_at,
                "time_precision": record.time_precision,
                "time_phrase": record.time_phrase,
                "assertion": record.assertion_text,
                "exact_quote": record.exact_quote,
                "rationales": [
                    {"status": item.status, "text": item.text}
                    for item in record.rationales
                ],
                "anchors": [
                    {
                        "title": item.title,
                        "preservation_note": item.preservation_note,
                    }
                    for item in record.anchors
                ],
            }
        )
    context = json.dumps(rendered, ensure_ascii=False, sort_keys=True)
    if len(context) > MAX_CONTEXT_CHARACTERS:
        raise OwnerMemoryReadError("context_budget_exceeded", retryable=False)
    return context


class OwnerMemoryReadRuntime:
    def __init__(
        self,
        adapter: AuditedOwnerMemoryReadAdapter,
        *,
        timeout_seconds: float = 1.2,
    ) -> None:
        if not 0.1 <= timeout_seconds <= 3.0:
            raise ValueError("Owner Memory timeout must be between 0.1 and 3 seconds")
        self.adapter = adapter
        self.timeout_seconds = timeout_seconds

    def retrieve(self, text: str, *, request_id: str) -> OwnerMemorySelection:
        query = text.strip()
        if not query or len(query) > MAX_QUERY_CHARACTERS:
            raise OwnerMemoryReadError("query_out_of_contract", retryable=False)
        mode = classify_owner_memory_mode(query)
        result = self.adapter.retrieve(
            query,
            mode=mode,
            request_id=request_id,
            timeout_seconds=self.timeout_seconds,
        )
        if not result.records:
            return OwnerMemorySelection(
                state="empty",
                context=None,
                hit_ids=(),
                mode_used=result.mode_used,
                policy_version=result.policy_version,
            )
        return OwnerMemorySelection(
            state="selected",
            context=render_owner_memory_context(result.records),
            hit_ids=tuple(item.memory_id for item in result.records),
            mode_used=result.mode_used,
            policy_version=result.policy_version,
        )
