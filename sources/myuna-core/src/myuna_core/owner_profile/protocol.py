from __future__ import annotations

import json
import re
from typing import Mapping

from .contracts import (
    MAX_QUERY_CHARACTERS,
    MAX_RESULTS,
    PROFILE_CATEGORIES,
    OwnerProfileError,
    RetrievalResult,
    RetrievedProfileSection,
)
from .retrieval import OwnerProfileIndex, render_profile_context


SCHEMA_VERSION = 1
OPERATION = "owner_profile.retrieve_v1"
BOUNDARY = "authenticated_owner_private_profile_read"
MAX_REQUEST_BYTES = 4096
MAX_RESPONSE_BYTES = 16_384
MIN_TIMEOUT_MS = 50
MAX_TIMEOUT_MS = 3000
ALLOWED_CHANNEL_KINDS = frozenset({"astrbot_qq", "astrbot_telegram"})
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REQUEST_KEYS = {
    "schema_version",
    "operation",
    "request_id",
    "boundary",
    "channel_kind",
    "query",
    "timeout_ms",
}
_SUCCESS_KEYS = {
    "schema_version",
    "operation",
    "ok",
    "request_id",
    "boundary",
    "channel_kind",
    "state",
    "profile_revision",
    "profile_sha256",
    "query_characters",
    "sections",
    "model_called",
    "memory_write_performed",
    "legacy_namespace_written",
}
_ERROR_KEYS = {
    "schema_version",
    "operation",
    "ok",
    "request_id",
    "error",
}


class ProfileProtocolError(ValueError):
    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def _query(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > MAX_QUERY_CHARACTERS
        or "\x00" in value
    ):
        raise ProfileProtocolError("invalid_request")
    return value.strip()


def parse_request(payload: object) -> dict[str, object]:
    if not isinstance(payload, Mapping) or set(payload) != _REQUEST_KEYS:
        raise ProfileProtocolError("invalid_request")
    request_id = payload.get("request_id")
    channel_kind = payload.get("channel_kind")
    timeout_ms = payload.get("timeout_ms")
    if (
        payload.get("schema_version") != SCHEMA_VERSION
        or payload.get("operation") != OPERATION
        or payload.get("boundary") != BOUNDARY
        or not isinstance(request_id, str)
        or _SAFE_LABEL.fullmatch(request_id) is None
        or channel_kind not in ALLOWED_CHANNEL_KINDS
        or isinstance(timeout_ms, bool)
        or not isinstance(timeout_ms, int)
        or not MIN_TIMEOUT_MS <= timeout_ms <= MAX_TIMEOUT_MS
    ):
        raise ProfileProtocolError("invalid_request")
    return {
        "request_id": request_id,
        "channel_kind": channel_kind,
        "query": _query(payload.get("query")),
        "timeout_ms": timeout_ms,
    }


def parse_request_bytes(payload: bytes) -> dict[str, object]:
    if not payload or len(payload) > MAX_REQUEST_BYTES:
        raise ProfileProtocolError("invalid_request")
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileProtocolError("invalid_request") from exc
    return parse_request(decoded)


def build_response(
    request: Mapping[str, object],
    index: OwnerProfileIndex,
) -> dict[str, object]:
    result = index.retrieve(
        str(request["query"]),
        timeout_seconds=int(request["timeout_ms"]) / 1000,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "operation": OPERATION,
        "ok": True,
        "request_id": request["request_id"],
        "boundary": BOUNDARY,
        "channel_kind": request["channel_kind"],
        "state": result.state,
        "profile_revision": result.profile_revision,
        "profile_sha256": result.profile_sha256,
        "query_characters": result.query_characters,
        "sections": [
            {
                "rank": section.rank,
                "category": section.category,
                "title": section.title,
                "body": section.body,
                "source_ref": section.source_ref,
            }
            for section in result.sections
        ],
        "model_called": False,
        "memory_write_performed": False,
        "legacy_namespace_written": False,
    }


def error_response(
    request_id: str | None,
    error: ProfileProtocolError | OwnerProfileError,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "operation": OPERATION,
        "ok": False,
        "error": {"code": error.code, "retryable": error.retryable},
    }
    if isinstance(request_id, str) and _SAFE_LABEL.fullmatch(request_id):
        payload["request_id"] = request_id
    return payload


def _text(value: object, *, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ProfileProtocolError("invalid_worker_response")
    return value.strip()


def parse_response(
    payload: object,
    *,
    expected_request_id: str,
    expected_channel_kind: str,
    expected_query_characters: int,
) -> RetrievalResult:
    if not isinstance(payload, Mapping):
        raise ProfileProtocolError("invalid_worker_response")
    if payload.get("ok") is False:
        error = payload.get("error")
        if (
            set(payload) != _ERROR_KEYS
            or payload.get("schema_version") != SCHEMA_VERSION
            or payload.get("operation") != OPERATION
            or payload.get("request_id") != expected_request_id
            or not isinstance(error, Mapping)
            or set(error) != {"code", "retryable"}
            or not isinstance(error.get("code"), str)
            or _SAFE_LABEL.fullmatch(str(error.get("code"))) is None
            or not isinstance(error.get("retryable"), bool)
        ):
            raise ProfileProtocolError("invalid_worker_response")
        raise OwnerProfileError(
            str(error["code"]),
            retryable=bool(error["retryable"]),
        )
    if set(payload) != _SUCCESS_KEYS:
        raise ProfileProtocolError("invalid_worker_response")
    digest = payload.get("profile_sha256")
    revision = payload.get("profile_revision")
    query_characters = payload.get("query_characters")
    if (
        payload.get("schema_version") != SCHEMA_VERSION
        or payload.get("operation") != OPERATION
        or payload.get("ok") is not True
        or payload.get("request_id") != expected_request_id
        or payload.get("boundary") != BOUNDARY
        or payload.get("channel_kind") != expected_channel_kind
        or payload.get("state") not in {"empty", "selected"}
        or not isinstance(digest, str)
        or _SHA256.fullmatch(digest) is None
        or isinstance(revision, bool)
        or not isinstance(revision, int)
        or revision < 1
        or isinstance(query_characters, bool)
        or not isinstance(query_characters, int)
        or not 1 <= query_characters <= MAX_QUERY_CHARACTERS
        or query_characters != expected_query_characters
        or payload.get("model_called") is not False
        or payload.get("memory_write_performed") is not False
        or payload.get("legacy_namespace_written") is not False
    ):
        raise ProfileProtocolError("invalid_worker_response")
    raw_sections = payload.get("sections")
    if not isinstance(raw_sections, list) or len(raw_sections) > MAX_RESULTS:
        raise ProfileProtocolError("invalid_worker_response")
    sections: list[RetrievedProfileSection] = []
    for expected_rank, raw in enumerate(raw_sections, start=1):
        if not isinstance(raw, Mapping) or set(raw) != {
            "rank",
            "category",
            "title",
            "body",
            "source_ref",
        }:
            raise ProfileProtocolError("invalid_worker_response")
        category = raw.get("category")
        source_ref = raw.get("source_ref")
        if (
            raw.get("rank") != expected_rank
            or category not in PROFILE_CATEGORIES
            or not isinstance(source_ref, str)
            or re.fullmatch(
                rf"owner-profile:{_SAFE_LABEL.pattern[1:-1]}:r{revision}:"
                rf"{_SAFE_LABEL.pattern[1:-1]}@sha256:{digest}",
                source_ref,
            )
            is None
        ):
            raise ProfileProtocolError("invalid_worker_response")
        sections.append(
            RetrievedProfileSection(
                rank=expected_rank,
                category=str(category),
                title=_text(raw.get("title"), maximum=120),
                body=_text(raw.get("body"), maximum=4000),
                source_ref=source_ref,
            )
        )
    state = str(payload["state"])
    if (state == "selected") != bool(sections):
        raise ProfileProtocolError("invalid_worker_response")
    context = render_profile_context(sections) if sections else None
    return RetrievalResult(
        state=state,
        profile_revision=revision,
        profile_sha256=digest,
        query_characters=query_characters,
        sections=tuple(sections),
        context=context,
    )
