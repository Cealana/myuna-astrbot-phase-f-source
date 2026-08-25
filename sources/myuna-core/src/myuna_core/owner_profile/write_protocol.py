from __future__ import annotations

import json
import re
from typing import Mapping

from myuna_core.authenticated_conversation import (
    AuthenticatedConversationContext,
    AuthenticatedConversationContextError,
)

from .contracts import OwnerProfileError
from .write_candidate import MAX_PREVIEW_CHARACTERS, MAX_SOURCE_CHARACTERS
from .write_runtime import OwnerProfileWriteResult


SCHEMA_VERSION = 1
OPERATION = "owner_profile.write_v1"
BOUNDARY = "authenticated_owner_private_local_profile_write"
MAX_REQUEST_BYTES = 24_000
MAX_RESPONSE_BYTES = 8_192
MAX_TEXT_CHARACTERS = MAX_SOURCE_CHARACTERS + 32
MIN_TIMEOUT_MS = 1_000
MAX_TIMEOUT_MS = 180_000
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_ACTIONS = frozenset(
    {
        "prepared",
        "published",
        "cancelled",
        "no_change",
        "needs_owner_resolution",
        "temporal_only",
    }
)
_MODEL_ACTIONS = frozenset(
    {"prepared", "no_change", "needs_owner_resolution", "temporal_only"}
)
_REQUEST_KEYS = {
    "authenticated_context",
    "boundary",
    "operation",
    "request_id",
    "schema_version",
    "text",
    "timeout_ms",
}
_SUCCESS_KEYS = {
    "action",
    "boundary",
    "legacy_namespace_written",
    "memory_write_performed",
    "model_called",
    "ok",
    "operation",
    "reply",
    "request_id",
    "schema_version",
    "target_revision",
}
_ERROR_KEYS = {
    "error",
    "ok",
    "operation",
    "request_id",
    "schema_version",
}


class ProfileWriteProtocolError(ValueError):
    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def parse_write_request_bytes(
    payload: bytes,
    *,
    authenticated_client_id: str,
    authenticated_channel_kind: str,
) -> dict[str, object]:
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_REQUEST_BYTES:
        raise ProfileWriteProtocolError("invalid_write_request")
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileWriteProtocolError("invalid_write_request") from exc
    if not isinstance(decoded, Mapping) or set(decoded) != _REQUEST_KEYS:
        raise ProfileWriteProtocolError("invalid_write_request")
    request_id = decoded.get("request_id")
    text = decoded.get("text")
    timeout_ms = decoded.get("timeout_ms")
    if (
        decoded.get("schema_version") != SCHEMA_VERSION
        or decoded.get("operation") != OPERATION
        or decoded.get("boundary") != BOUNDARY
        or not isinstance(request_id, str)
        or _SAFE_LABEL.fullmatch(request_id) is None
        or not isinstance(text, str)
        or not text
        or text != text.strip()
        or len(text) > MAX_TEXT_CHARACTERS
        or "\x00" in text
        or isinstance(timeout_ms, bool)
        or not isinstance(timeout_ms, int)
        or not MIN_TIMEOUT_MS <= timeout_ms <= MAX_TIMEOUT_MS
    ):
        raise ProfileWriteProtocolError("invalid_write_request")
    try:
        context = AuthenticatedConversationContext.from_payload(
            decoded.get("authenticated_context"),
            authenticated_client_id=authenticated_client_id,
            authenticated_channel_kind=authenticated_channel_kind,
        )
    except AuthenticatedConversationContextError as exc:
        raise ProfileWriteProtocolError("write_context_rejected") from exc
    if context.request_id != request_id:
        raise ProfileWriteProtocolError("write_context_rejected")
    return {
        "authenticated_context": context,
        "request_id": request_id,
        "text": text,
        "timeout_ms": timeout_ms,
    }


def build_write_success_response(
    *,
    request_id: str,
    result: OwnerProfileWriteResult,
) -> dict[str, object]:
    model_called = result.action in _MODEL_ACTIONS
    return {
        "action": result.action,
        "boundary": BOUNDARY,
        "legacy_namespace_written": False,
        "memory_write_performed": result.memory_write_performed,
        "model_called": model_called,
        "ok": True,
        "operation": OPERATION,
        "reply": result.reply,
        "request_id": request_id,
        "schema_version": SCHEMA_VERSION,
        "target_revision": result.target_revision,
    }


def build_write_error_response(
    request_id: str | None,
    error: ProfileWriteProtocolError | OwnerProfileError,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "error": {"code": error.code, "retryable": error.retryable},
        "ok": False,
        "operation": OPERATION,
        "schema_version": SCHEMA_VERSION,
    }
    if isinstance(request_id, str) and _SAFE_LABEL.fullmatch(request_id):
        payload["request_id"] = request_id
    return payload


def parse_write_response(
    payload: object,
    *,
    expected_request_id: str,
) -> OwnerProfileWriteResult:
    if not isinstance(payload, Mapping):
        raise ProfileWriteProtocolError("invalid_write_worker_response")
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
            raise ProfileWriteProtocolError("invalid_write_worker_response")
        raise OwnerProfileError(
            str(error["code"]), retryable=bool(error["retryable"])
        )
    if set(payload) != _SUCCESS_KEYS:
        raise ProfileWriteProtocolError("invalid_write_worker_response")
    action = payload.get("action")
    reply = payload.get("reply")
    revision = payload.get("target_revision")
    memory_write = payload.get("memory_write_performed")
    if (
        payload.get("schema_version") != SCHEMA_VERSION
        or payload.get("operation") != OPERATION
        or payload.get("boundary") != BOUNDARY
        or payload.get("ok") is not True
        or payload.get("request_id") != expected_request_id
        or action not in _ACTIONS
        or not isinstance(reply, str)
        or not reply
        or len(reply) > MAX_PREVIEW_CHARACTERS
        or isinstance(revision, bool)
        or not isinstance(revision, int)
        or revision < 0
        or not isinstance(memory_write, bool)
        or payload.get("model_called") is not (action in _MODEL_ACTIONS)
        or payload.get("legacy_namespace_written") is not False
        or memory_write is not (action == "published")
        or (revision > 0) is not (action in {"prepared", "published"})
    ):
        raise ProfileWriteProtocolError("invalid_write_worker_response")
    return OwnerProfileWriteResult(
        action=str(action),
        reply=reply,
        memory_write_performed=memory_write,
        target_revision=revision,
    )
