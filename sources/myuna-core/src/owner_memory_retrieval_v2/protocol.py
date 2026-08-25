from __future__ import annotations

from datetime import datetime
import json
import re
import time
from typing import Any, Iterable

from .planner import POLICY_VERSION
from .selection import retrieve_records


BOUNDARY = "verified_owner_private_text"
NAMESPACE = "ns-owner-cealana-private"
OPERATION = "owner_memory.retrieve_v2"
MAX_REQUEST_BYTES = 4096
MAX_RESPONSE_BYTES = 65_536
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_REQUEST_KEYS = {
    "schema_version",
    "operation",
    "request_id",
    "boundary",
    "query",
}


class ProtocolError(ValueError):
    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def parse_request(payload: object) -> dict[str, str]:
    if not isinstance(payload, dict) or set(payload) != _REQUEST_KEYS:
        raise ProtocolError("invalid_request")
    request_id = payload.get("request_id")
    query = payload.get("query")
    if (
        payload.get("schema_version") != 2
        or payload.get("operation") != OPERATION
        or payload.get("boundary") != BOUNDARY
        or not isinstance(request_id, str)
        or _SAFE_LABEL.fullmatch(request_id) is None
        or not isinstance(query, str)
        or not query.strip()
        or len(query) > 256
        or "\x00" in query
    ):
        raise ProtocolError("invalid_request")
    return {"request_id": request_id, "query": query.strip()}


def parse_request_bytes(payload: bytes) -> dict[str, str]:
    if not payload or len(payload) > MAX_REQUEST_BYTES:
        raise ProtocolError("invalid_request")
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid_request") from exc
    return parse_request(decoded)


def _project_rationales(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    projected = []
    for item in value[:4]:
        if isinstance(item, dict):
            projected.append({"status": item.get("status"), "text": item.get("text")})
    return projected


def _project_anchors(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    projected = []
    for item in value[:3]:
        if isinstance(item, dict):
            projected.append(
                {
                    "title": item.get("title"),
                    "preservation_note": item.get("preservation_note"),
                }
            )
    return projected


def project_record(record: dict[str, Any]) -> dict[str, object]:
    return {
        "memory_id": record.get("candidate_id"),
        "memory_kind": record.get("memory_kind"),
        "memory_status": record.get("memory_status"),
        "confirmation_level": record.get("confirmation_level"),
        "importance": record.get("importance"),
        "sensitivity": record.get("sensitivity"),
        "assertion_text": record.get("assertion_text"),
        "exact_quote": record.get("exact_quote"),
        "occurred_at": record.get("occurred_at"),
        "time_precision": record.get("time_precision"),
        "time_phrase": record.get("time_phrase"),
        "scope": list(record.get("scope") or [])[:12],
        "tags": list(record.get("tags") or [])[:16],
        "rationales": _project_rationales(record.get("rationales")),
        "anchors": _project_anchors(record.get("anchors")),
    }


def build_response(
    request: dict[str, str],
    records: Iterable[dict[str, Any]],
    *,
    at: datetime,
) -> dict[str, object]:
    started = time.perf_counter()
    result = retrieve_records(records, query=request["query"], at=at)
    return {
        "schema_version": 2,
        "operation": OPERATION,
        "ok": True,
        "request_id": request["request_id"],
        "boundary": BOUNDARY,
        "namespace_id": NAMESPACE,
        "policy_version": POLICY_VERSION,
        "plan": {
            "intent": result.plan.intent,
            "primary_horizon": result.plan.primary_horizon,
            "horizon_used": result.horizon_used,
            "fallback_used": result.fallback_used,
            "reason_codes": list(result.plan.reason_codes),
            "query_fingerprint": result.plan.query_fingerprint,
            "query_characters": result.plan.query_characters,
        },
        "hit_ids": [score.memory_id for score in result.scores],
        "model_called": False,
        "memory_write_performed": False,
        "restricted_included": False,
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        "records": [project_record(record) for record in result.records],
    }


def error_response(request_id: str | None, error: ProtocolError) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": 2,
        "operation": OPERATION,
        "ok": False,
        "error": {"code": error.code, "retryable": error.retryable},
    }
    if isinstance(request_id, str) and _SAFE_LABEL.fullmatch(request_id):
        payload["request_id"] = request_id
    return payload


def handle_request_bytes(
    payload: bytes,
    *,
    records: Iterable[dict[str, Any]],
    at: datetime,
) -> bytes:
    request_id = None
    try:
        request = parse_request_bytes(payload)
        request_id = request["request_id"]
        response = build_response(request, records, at=at)
    except ProtocolError as exc:
        response = error_response(request_id, exc)
    encoded = json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_RESPONSE_BYTES:
        encoded = json.dumps(
            error_response(request_id, ProtocolError("response_too_large")),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    return encoded
