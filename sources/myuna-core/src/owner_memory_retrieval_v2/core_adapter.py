from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any

from .planner import POLICY_VERSION
from .protocol import BOUNDARY, NAMESPACE, OPERATION


_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CoreAdapterError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


@dataclass(frozen=True, slots=True)
class CoreMemoryRecord:
    memory_id: str
    memory_kind: str
    memory_status: str
    importance: float
    assertion_text: str
    exact_quote: str | None
    occurred_at: str
    time_precision: str
    time_phrase: str | None
    scope: tuple[str, ...]
    tags: tuple[str, ...]
    rationales: tuple[dict[str, object], ...]
    anchors: tuple[dict[str, object], ...]


@dataclass(frozen=True, slots=True)
class CoreSelection:
    state: str
    intent: str
    horizon_used: str
    fallback_used: bool
    hit_ids: tuple[str, ...]
    records: tuple[CoreMemoryRecord, ...]
    query_fingerprint: str
    duration_ms: float


def _safe_text(value: object, field: str, *, maximum: int, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise CoreAdapterError("invalid_worker_response")
    return value.strip()


def _safe_labels(value: object, *, maximum: int) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum:
        raise CoreAdapterError("invalid_worker_response")
    labels = []
    for item in value:
        if not isinstance(item, str) or _SAFE_LABEL.fullmatch(item) is None:
            raise CoreAdapterError("invalid_worker_response")
        labels.append(item)
    return tuple(labels)


def _parse_record(payload: object) -> CoreMemoryRecord:
    if not isinstance(payload, dict):
        raise CoreAdapterError("invalid_worker_response")
    memory_id = payload.get("memory_id")
    if not isinstance(memory_id, str) or _SAFE_LABEL.fullmatch(memory_id) is None:
        raise CoreAdapterError("invalid_worker_response")
    if payload.get("sensitivity") != "normal" or payload.get("confirmation_level") != "user_confirmed":
        raise CoreAdapterError("invalid_worker_response")
    status = payload.get("memory_status")
    if status not in {"confirmed", "provisional"}:
        raise CoreAdapterError("invalid_worker_response")
    importance = payload.get("importance")
    if not isinstance(importance, (int, float)) or isinstance(importance, bool) or not 0 <= float(importance) <= 1:
        raise CoreAdapterError("invalid_worker_response")
    rationales = payload.get("rationales")
    anchors = payload.get("anchors")
    if not isinstance(rationales, list) or len(rationales) > 4:
        raise CoreAdapterError("invalid_worker_response")
    if not isinstance(anchors, list) or len(anchors) > 3:
        raise CoreAdapterError("invalid_worker_response")
    return CoreMemoryRecord(
        memory_id=memory_id,
        memory_kind=str(_safe_text(payload.get("memory_kind"), "memory_kind", maximum=64)),
        memory_status=str(status),
        importance=float(importance),
        assertion_text=str(_safe_text(payload.get("assertion_text"), "assertion_text", maximum=6000)),
        exact_quote=_safe_text(payload.get("exact_quote"), "exact_quote", maximum=4000, optional=True),
        occurred_at=str(_safe_text(payload.get("occurred_at"), "occurred_at", maximum=64)),
        time_precision=str(_safe_text(payload.get("time_precision"), "time_precision", maximum=32)),
        time_phrase=_safe_text(payload.get("time_phrase"), "time_phrase", maximum=64, optional=True),
        scope=_safe_labels(payload.get("scope"), maximum=12),
        tags=_safe_labels(payload.get("tags"), maximum=16),
        rationales=tuple(item for item in rationales if isinstance(item, dict)),
        anchors=tuple(item for item in anchors if isinstance(item, dict)),
    )


def parse_response(payload: object, *, expected_request_id: str) -> CoreSelection:
    if not isinstance(payload, dict):
        raise CoreAdapterError("invalid_worker_response")
    if payload.get("ok") is False:
        error = payload.get("error")
        if not isinstance(error, dict) or not isinstance(error.get("code"), str):
            raise CoreAdapterError("invalid_worker_response")
        raise CoreAdapterError(
            error["code"],
            retryable=error.get("retryable") is True,
        )
    if (
        payload.get("schema_version") != 2
        or payload.get("operation") != OPERATION
        or payload.get("request_id") != expected_request_id
        or payload.get("boundary") != BOUNDARY
        or payload.get("namespace_id") != NAMESPACE
        or payload.get("policy_version") != POLICY_VERSION
        or payload.get("model_called") is not False
        or payload.get("memory_write_performed") is not False
        or payload.get("restricted_included") is not False
    ):
        raise CoreAdapterError("invalid_worker_response")
    plan = payload.get("plan")
    if not isinstance(plan, dict):
        raise CoreAdapterError("invalid_worker_response")
    intent = plan.get("intent")
    horizon = plan.get("horizon_used")
    fallback = plan.get("fallback_used")
    fingerprint = plan.get("query_fingerprint")
    if (
        not isinstance(intent, str)
        or _SAFE_LABEL.fullmatch(intent) is None
        or horizon not in {"recent", "deep"}
        or not isinstance(fallback, bool)
        or not isinstance(fingerprint, str)
        or _SHA256.fullmatch(fingerprint) is None
    ):
        raise CoreAdapterError("invalid_worker_response")
    raw_records = payload.get("records")
    hit_ids = payload.get("hit_ids")
    maximum = 3 if horizon == "deep" else 1
    if not isinstance(raw_records, list) or len(raw_records) > maximum:
        raise CoreAdapterError("invalid_worker_response")
    if not isinstance(hit_ids, list) or len(hit_ids) != len(raw_records):
        raise CoreAdapterError("invalid_worker_response")
    records = tuple(_parse_record(item) for item in raw_records)
    record_ids = tuple(record.memory_id for record in records)
    if tuple(hit_ids) != record_ids or len(set(record_ids)) != len(record_ids):
        raise CoreAdapterError("invalid_worker_response")
    duration = payload.get("duration_ms")
    if not isinstance(duration, (int, float)) or isinstance(duration, bool) or not 0 <= float(duration) <= 10_000:
        raise CoreAdapterError("invalid_worker_response")
    return CoreSelection(
        state="selected" if records else "empty",
        intent=intent,
        horizon_used=horizon,
        fallback_used=fallback,
        hit_ids=record_ids,
        records=records,
        query_fingerprint=fingerprint,
        duration_ms=float(duration),
    )


def render_context(selection: CoreSelection) -> str | None:
    if not selection.records:
        return None
    rendered = []
    for record in selection.records:
        rendered.append(
            {
                "status": record.memory_status,
                "importance": record.importance,
                "assertion": record.assertion_text,
                "exact_quote": record.exact_quote,
                "occurred_at": record.occurred_at,
                "time_precision": record.time_precision,
                "time_phrase": record.time_phrase,
                "scope": list(record.scope),
                "tags": list(record.tags),
                "rationales": list(record.rationales),
                "anchors": list(record.anchors),
            }
        )
    return (
        "Owner Memory read-only context. Use only when relevant; preserve time, "
        "quotes, reasons, and uncertainty. Do not claim a write or expose internal IDs.\n"
        + json.dumps(rendered, ensure_ascii=False, sort_keys=True)
    )
