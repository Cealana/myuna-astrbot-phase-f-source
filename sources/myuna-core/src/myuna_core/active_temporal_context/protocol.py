from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
import json
import re
from typing import Mapping

from myuna_core.authenticated_conversation import (
    AuthenticatedConversationContext,
    AuthenticatedConversationContextError,
)

from .contracts import TemporalContextError, TemporalFactDraft
from .runtime import ActiveTemporalContextRuntime
from .store import MAX_EVENTS, MAX_FACTS, MAX_PENDING_PROPOSALS


SCHEMA = "myuna.active-temporal-context-protocol.v1"
BOUNDARY = "authenticated_telegram_owner_private_temporal_context"
MAX_REQUEST_BYTES = 16_384
MAX_RESPONSE_BYTES = 16_384
_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
CONTENT_FREE_STATUS_SCHEMA = "myuna.active-temporal-content-free-status.v1"
ACTIVE_SNAPSHOT_RECEIPT_SCHEMA = "myuna.active-temporal-snapshot-receipt.v1"
_CONTENT_FREE_STATUS_CONTRACT = {
    "coverage_fields": [
        "active_set_complete",
        "lifecycle_complete",
        "trusted_time_evidence_complete",
    ],
    "count_fields": [
        "active_fact_count",
        "lifecycle_event_count",
        "pending_proposal_count",
        "total_fact_count",
    ],
    "digest_fields": [
        "active_set_digest",
        "lifecycle_digest",
        "scope_binding_digest",
        "trusted_time_binding_digest",
    ],
    "lifecycle_watermark": True,
    "limits": {
        "events": MAX_EVENTS,
        "facts": MAX_FACTS,
        "pending_proposals": MAX_PENDING_PROPOSALS,
    },
    "private_content_returned": False,
    "schema": CONTENT_FREE_STATUS_SCHEMA,
}
CONTENT_FREE_STATUS_SOURCE_IDENTITY = sha256(
    b"myuna-p08-content-free-status-source-v1\0"
    + json.dumps(
        _CONTENT_FREE_STATUS_CONTRACT,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
).hexdigest()
_OPERATIONS = frozenset(
    {"retrieve", "snapshot_active", "status_content_free", "propose", "confirm"}
)


class TemporalProtocolError(ValueError):
    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def _canonical_digest(domain: str, payload: Mapping[str, object]) -> str:
    return sha256(
        domain.encode("ascii")
        + b"\0"
        + json.dumps(
            dict(payload),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


def _lifecycle_page_digest(
    transitions: object,
) -> str:
    if not isinstance(transitions, (list, tuple)) or any(
        not isinstance(item, Mapping) for item in transitions
    ):
        raise TemporalProtocolError("active_snapshot_receipt_invalid")
    return _canonical_digest(
        "myuna-p08-active-snapshot-lifecycle-page-v1",
        {"transitions": [dict(item) for item in transitions]},
    )


def _trusted_time_payload_digest(payload: object) -> str:
    if not isinstance(payload, Mapping):
        raise TemporalProtocolError("active_snapshot_receipt_invalid")
    return _canonical_digest(
        "myuna-p08-active-snapshot-trusted-time-v1",
        dict(payload),
    )


def _active_snapshot_response_identity(
    *,
    request_id: str,
    after_event_sequence: int,
    fact_count: int,
    lifecycle_page_digest: str,
    lifecycle_watermark: int,
    lifecycle_has_more: bool,
    trusted_time_digest: str,
) -> str:
    return _canonical_digest(
        "myuna-p08-active-snapshot-non-rendered-response-v1",
        {
            "after_event_sequence": after_event_sequence,
            "fact_count": fact_count,
            "lifecycle_has_more": lifecycle_has_more,
            "lifecycle_page_digest": lifecycle_page_digest,
            "lifecycle_watermark": lifecycle_watermark,
            "request_id": request_id,
            "trusted_time_digest": trusted_time_digest,
        },
    )


@dataclass(frozen=True, slots=True)
class ActiveSnapshotReceipt:
    request_id: str
    after_event_sequence: int
    fact_count: int
    lifecycle_page_digest: str
    lifecycle_watermark: int
    lifecycle_has_more: bool
    trusted_time_digest: str
    response_identity: str
    receipt_digest: str
    schema: str = ACTIVE_SNAPSHOT_RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if (
            self.schema != ACTIVE_SNAPSHOT_RECEIPT_SCHEMA
            or not isinstance(self.request_id, str)
            or _SAFE.fullmatch(self.request_id) is None
            or isinstance(self.after_event_sequence, bool)
            or not isinstance(self.after_event_sequence, int)
            or self.after_event_sequence < 0
            or isinstance(self.fact_count, bool)
            or not isinstance(self.fact_count, int)
            or self.fact_count < 0
            or isinstance(self.lifecycle_watermark, bool)
            or not isinstance(self.lifecycle_watermark, int)
            or self.lifecycle_watermark < self.after_event_sequence
            or not isinstance(self.lifecycle_has_more, bool)
            or any(
                not isinstance(value, str) or _SHA256.fullmatch(value) is None
                for value in (
                    self.lifecycle_page_digest,
                    self.trusted_time_digest,
                    self.response_identity,
                    self.receipt_digest,
                )
            )
        ):
            raise TemporalProtocolError("active_snapshot_receipt_invalid")
        if self.receipt_digest != _canonical_digest(
            "myuna-p08-active-snapshot-receipt-v1",
            self.semantic_payload(),
        ):
            raise TemporalProtocolError("active_snapshot_receipt_invalid")

    def semantic_payload(self) -> dict[str, object]:
        return {
            "after_event_sequence": self.after_event_sequence,
            "fact_count": self.fact_count,
            "lifecycle_has_more": self.lifecycle_has_more,
            "lifecycle_page_digest": self.lifecycle_page_digest,
            "lifecycle_watermark": self.lifecycle_watermark,
            "request_id": self.request_id,
            "response_identity": self.response_identity,
            "schema": self.schema,
            "trusted_time_digest": self.trusted_time_digest,
        }

    def as_payload(self) -> dict[str, object]:
        return self.semantic_payload() | {"receipt_digest": self.receipt_digest}

    @classmethod
    def from_payload(cls, payload: object) -> "ActiveSnapshotReceipt":
        expected = {
            "after_event_sequence",
            "fact_count",
            "lifecycle_has_more",
            "lifecycle_page_digest",
            "lifecycle_watermark",
            "receipt_digest",
            "request_id",
            "response_identity",
            "schema",
            "trusted_time_digest",
        }
        if not isinstance(payload, Mapping) or set(payload) != expected:
            raise TemporalProtocolError("active_snapshot_receipt_invalid")
        return cls(
            request_id=payload["request_id"],  # type: ignore[arg-type]
            after_event_sequence=payload["after_event_sequence"],  # type: ignore[arg-type]
            fact_count=payload["fact_count"],  # type: ignore[arg-type]
            lifecycle_page_digest=payload["lifecycle_page_digest"],  # type: ignore[arg-type]
            lifecycle_watermark=payload["lifecycle_watermark"],  # type: ignore[arg-type]
            lifecycle_has_more=payload["lifecycle_has_more"],  # type: ignore[arg-type]
            trusted_time_digest=payload["trusted_time_digest"],  # type: ignore[arg-type]
            response_identity=payload["response_identity"],  # type: ignore[arg-type]
            receipt_digest=payload["receipt_digest"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )

    def matches_lifecycle_page(
        self,
        *,
        after_event_sequence: int,
        transitions: object,
        lifecycle_watermark: int,
        lifecycle_has_more: bool,
    ) -> bool:
        try:
            page_digest = _lifecycle_page_digest(transitions)
        except TemporalProtocolError:
            return False
        return (
            self.after_event_sequence == after_event_sequence
            and self.lifecycle_page_digest == page_digest
            and self.lifecycle_watermark == lifecycle_watermark
            and self.lifecycle_has_more is lifecycle_has_more
        )

    def matches_trusted_time_payload(self, payload: object) -> bool:
        try:
            digest = _trusted_time_payload_digest(payload)
        except TemporalProtocolError:
            return False
        return self.trusted_time_digest == digest

    def matches_source_tuple(
        self,
        *,
        request_id: str,
        after_event_sequence: int,
        fact_count: int,
        transitions: object,
        lifecycle_watermark: int,
        lifecycle_has_more: bool,
        trusted_time: object,
    ) -> bool:
        try:
            page_digest = _lifecycle_page_digest(transitions)
            trusted_digest = _trusted_time_payload_digest(trusted_time)
            response_identity = _active_snapshot_response_identity(
                request_id=request_id,
                after_event_sequence=after_event_sequence,
                fact_count=fact_count,
                lifecycle_page_digest=page_digest,
                lifecycle_watermark=lifecycle_watermark,
                lifecycle_has_more=lifecycle_has_more,
                trusted_time_digest=trusted_digest,
            )
        except (TemporalProtocolError, TypeError):
            return False
        return (
            self.request_id == request_id
            and self.after_event_sequence == after_event_sequence
            and self.fact_count == fact_count
            and self.lifecycle_page_digest == page_digest
            and self.lifecycle_watermark == lifecycle_watermark
            and self.lifecycle_has_more is lifecycle_has_more
            and self.trusted_time_digest == trusted_digest
            and self.response_identity == response_identity
        )


def build_active_snapshot_receipt(
    *,
    request_id: str,
    after_event_sequence: int,
    fact_count: int,
    lifecycle_transitions: object,
    lifecycle_watermark: int,
    lifecycle_has_more: bool,
    trusted_time: object,
) -> ActiveSnapshotReceipt:
    _safe(request_id)
    if (
        isinstance(after_event_sequence, bool)
        or not isinstance(after_event_sequence, int)
        or after_event_sequence < 0
        or isinstance(fact_count, bool)
        or not isinstance(fact_count, int)
        or fact_count < 0
        or isinstance(lifecycle_watermark, bool)
        or not isinstance(lifecycle_watermark, int)
        or lifecycle_watermark < after_event_sequence
        or not isinstance(lifecycle_has_more, bool)
    ):
        raise TemporalProtocolError("active_snapshot_receipt_invalid")
    page_digest = _lifecycle_page_digest(lifecycle_transitions)
    trusted_digest = _trusted_time_payload_digest(trusted_time)
    response_identity = _active_snapshot_response_identity(
        request_id=request_id,
        after_event_sequence=after_event_sequence,
        fact_count=fact_count,
        lifecycle_page_digest=page_digest,
        lifecycle_watermark=lifecycle_watermark,
        lifecycle_has_more=lifecycle_has_more,
        trusted_time_digest=trusted_digest,
    )
    semantic = {
        "after_event_sequence": after_event_sequence,
        "fact_count": fact_count,
        "lifecycle_has_more": lifecycle_has_more,
        "lifecycle_page_digest": page_digest,
        "lifecycle_watermark": lifecycle_watermark,
        "request_id": request_id,
        "response_identity": response_identity,
        "schema": ACTIVE_SNAPSHOT_RECEIPT_SCHEMA,
        "trusted_time_digest": trusted_digest,
    }
    return ActiveSnapshotReceipt(
        request_id=request_id,
        after_event_sequence=after_event_sequence,
        fact_count=fact_count,
        lifecycle_page_digest=page_digest,
        lifecycle_watermark=lifecycle_watermark,
        lifecycle_has_more=lifecycle_has_more,
        trusted_time_digest=trusted_digest,
        response_identity=response_identity,
        receipt_digest=_canonical_digest(
            "myuna-p08-active-snapshot-receipt-v1",
            semantic,
        ),
    )


def _safe(value: object) -> str:
    if not isinstance(value, str) or _SAFE.fullmatch(value) is None:
        raise TemporalProtocolError("invalid_request")
    return value


def _sha256(value: object) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise TemporalProtocolError("invalid_request")
    return value


def _content_free_status_digest(payload: Mapping[str, object]) -> str:
    return sha256(
        b"myuna-p08-content-free-status-v1\0"
        + json.dumps(
            dict(payload),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


def parse_request_bytes(
    raw: bytes,
    *,
    authenticated_client_id: str,
    authenticated_channel_kind: str,
) -> tuple[str, str, AuthenticatedConversationContext, Mapping[str, object]]:
    if not raw or len(raw) > MAX_REQUEST_BYTES:
        raise TemporalProtocolError("invalid_request")
    try:
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, Mapping) or set(payload) != {
            "schema",
            "boundary",
            "operation",
            "request_id",
            "authenticated_context",
            "input",
        }:
            raise ValueError
        operation = payload["operation"]
        request_id = _safe(payload["request_id"])
        if (
            payload["schema"] != SCHEMA
            or payload["boundary"] != BOUNDARY
            or operation not in _OPERATIONS
            or not isinstance(payload["input"], Mapping)
        ):
            raise ValueError
        context = AuthenticatedConversationContext.from_payload(
            payload["authenticated_context"],
            authenticated_client_id=authenticated_client_id,
            authenticated_channel_kind=authenticated_channel_kind,
        )
        if context.request_id != request_id:
            raise ValueError
        return request_id, str(operation), context, payload["input"]
    except (AuthenticatedConversationContextError, UnicodeError, ValueError, json.JSONDecodeError):
        raise TemporalProtocolError("invalid_request") from None


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 16 or any(
        not isinstance(item, str) for item in value
    ):
        raise TemporalProtocolError("invalid_request")
    return tuple(value)


def execute_request(
    runtime: ActiveTemporalContextRuntime,
    *,
    operation: str,
    request_id: str,
    context: AuthenticatedConversationContext,
    payload: Mapping[str, object],
) -> dict[str, object]:
    if operation == "retrieve":
        if set(payload) != {"query", "categories", "slot_keys"} or not isinstance(
            payload["query"], str
        ):
            raise TemporalProtocolError("invalid_request")
        result, trusted_time = runtime.retrieve_with_sample(
            context,
            query=payload["query"],
            categories=_string_tuple(payload["categories"]),
            slot_keys=_string_tuple(payload["slot_keys"]),
        )
        output: dict[str, object] = {
            "state": result.state,
            "query_characters": result.query_characters,
            "context": result.context,
            "fact_count": len(result.facts),
        }
    elif operation == "snapshot_active":
        if set(payload) - {"after_event_sequence"}:
            raise TemporalProtocolError("invalid_request")
        after_event_sequence = payload.get("after_event_sequence", 0)
        if (
            isinstance(after_event_sequence, bool)
            or not isinstance(after_event_sequence, int)
            or after_event_sequence < 0
        ):
            raise TemporalProtocolError("invalid_request")
        result = runtime.snapshot_active(
            context,
            after_event_sequence=after_event_sequence,
        )
        trusted_time = result.sample
        output = {
            "context": result.context,
            "fact_count": result.fact_count,
            "lifecycle_has_more": result.lifecycle_has_more,
            "lifecycle_transitions": [
                item.as_payload() for item in result.lifecycle_transitions
            ],
            "lifecycle_watermark": result.lifecycle_watermark,
            "projection_digest": result.projection_digest,
            "trusted_time": result.sample.as_payload(),
        }
        output["active_snapshot_receipt"] = build_active_snapshot_receipt(
            request_id=request_id,
            after_event_sequence=after_event_sequence,
            fact_count=result.fact_count,
            lifecycle_transitions=output["lifecycle_transitions"],
            lifecycle_watermark=result.lifecycle_watermark,
            lifecycle_has_more=result.lifecycle_has_more,
            trusted_time=output["trusted_time"],
        ).as_payload()
    elif operation == "status_content_free":
        if set(payload) != {
            "expected_scope_digest",
            "expected_source_identity",
            "minimum_lifecycle_watermark",
            "request_nonce",
            "response_schema",
        }:
            raise TemporalProtocolError("invalid_request")
        request_nonce = _sha256(payload["request_nonce"])
        expected_scope_digest = _sha256(payload["expected_scope_digest"])
        minimum_watermark = payload["minimum_lifecycle_watermark"]
        if (
            payload["response_schema"] != CONTENT_FREE_STATUS_SCHEMA
            or payload["expected_source_identity"]
            != CONTENT_FREE_STATUS_SOURCE_IDENTITY
            or isinstance(minimum_watermark, bool)
            or not isinstance(minimum_watermark, int)
            or minimum_watermark < 0
        ):
            raise TemporalProtocolError("invalid_request")
        result = runtime.content_free_status(context)
        trusted_time = result.sample
        projection = result.audit_projection()
        if projection["scope_binding_digest"] != expected_scope_digest:
            raise TemporalProtocolError("status_scope_mismatch")
        if result.lifecycle_watermark < minimum_watermark:
            raise TemporalProtocolError("status_lifecycle_stale", retryable=True)
        stable_status = {
            "active_fact_count": result.active_fact_count,
            "active_set_complete": result.active_set_complete,
            "active_set_digest": result.active_set_digest,
            "lifecycle_complete": result.lifecycle_complete,
            "lifecycle_digest": result.lifecycle_digest,
            "lifecycle_event_count": result.lifecycle_event_count,
            "lifecycle_watermark": result.lifecycle_watermark,
            "pending_proposal_count": result.pending_proposal_count,
            "scope_binding_digest": result.scope_binding_digest,
            "source_identity": CONTENT_FREE_STATUS_SOURCE_IDENTITY,
            "status_schema": CONTENT_FREE_STATUS_SCHEMA,
            "total_fact_count": result.total_fact_count,
            "trusted_time_binding_digest": result.trusted_time_binding_digest,
            "trusted_time_evidence_complete": True,
        }
        status_digest = _content_free_status_digest(stable_status)
        response_digest = _content_free_status_digest(
            {
                "request_nonce": request_nonce,
                "source_identity": CONTENT_FREE_STATUS_SOURCE_IDENTITY,
                "status_digest": status_digest,
            }
        )
        output = {
            **stable_status,
            "request_nonce": request_nonce,
            "response_digest": response_digest,
            "status_digest": status_digest,
        }
    elif operation == "propose":
        if set(payload) != {
            "explicit_intent",
            "action",
            "draft",
            "target_fact_id",
            "ttl_seconds",
        }:
            raise TemporalProtocolError("invalid_request")
        ttl = payload["ttl_seconds"]
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not 60 <= ttl <= 1800:
            raise TemporalProtocolError("invalid_request")
        draft = (
            None
            if payload["draft"] is None
            else TemporalFactDraft.from_payload(payload["draft"])
        )
        target = payload["target_fact_id"]
        if target is not None:
            target = _safe(target)
        if not isinstance(payload["explicit_intent"], bool) or not isinstance(
            payload["action"], str
        ):
            raise TemporalProtocolError("invalid_request")
        result, trusted_time = runtime.propose_with_sample(
            context,
            explicit_intent=payload["explicit_intent"],
            request_id=request_id,
            action=payload["action"],
            draft=draft,
            target_fact_id=target,
            ttl=timedelta(seconds=ttl),
        )
        output = {
            "proposal_id": result.proposal_id,
            "confirmation_code": result.confirmation_code,
            "expires_at": result.expires_at.isoformat(timespec="microseconds"),
        }
    elif operation == "confirm":
        if set(payload) != {"explicit_intent", "proposal_id", "confirmation_code"}:
            raise TemporalProtocolError("invalid_request")
        if not isinstance(payload["explicit_intent"], bool):
            raise TemporalProtocolError("invalid_request")
        result, trusted_time = runtime.confirm_with_sample(
            context,
            explicit_intent=payload["explicit_intent"],
            request_id=request_id,
            proposal_id=_safe(payload["proposal_id"]),
            confirmation_code=_safe(payload["confirmation_code"]),
        )
        output = {
            "outcome": result.outcome,
            "fact_id": None if result.fact is None else result.fact.fact_id,
            "event_written": result.event_written,
        }
    else:  # pragma: no cover - parse_request_bytes owns the operation allowlist
        raise TemporalProtocolError("invalid_request")
    if operation != "status_content_free":
        output["trusted_time"] = trusted_time.as_payload()
    response = {
        "schema": SCHEMA,
        "operation": operation,
        "ok": True,
        "request_id": request_id,
        "output": output,
        "model_called": False,
        "profile_written": False,
        "session_written": False,
        "legacy_namespace_written": False,
    }
    if operation == "status_content_free":
        response.update(
            {
                "channel_called": False,
                "health_called": False,
                "private_content_returned": False,
                "provider_called": False,
            }
        )
    return response


def error_response(request_id: str | None, error: object) -> dict[str, object]:
    code = getattr(error, "code", "temporal_unavailable")
    retryable = getattr(error, "retryable", False)
    response: dict[str, object] = {
        "schema": SCHEMA,
        "ok": False,
        "error": {"code": str(code), "retryable": bool(retryable)},
    }
    if isinstance(request_id, str) and _SAFE.fullmatch(request_id):
        response["request_id"] = request_id
    return response


def process_request(
    raw: bytes,
    runtime: ActiveTemporalContextRuntime,
    *,
    authenticated_client_id: str,
    authenticated_channel_kind: str,
) -> bytes:
    request_id: str | None = None
    try:
        request_id, operation, context, payload = parse_request_bytes(
            raw,
            authenticated_client_id=authenticated_client_id,
            authenticated_channel_kind=authenticated_channel_kind,
        )
        response = execute_request(
            runtime,
            operation=operation,
            request_id=request_id,
            context=context,
            payload=payload,
        )
    except (TemporalProtocolError, TemporalContextError) as error:
        response = error_response(request_id, error)
    except Exception:
        response = error_response(request_id, TemporalContextError("temporal_unavailable", retryable=True))
    encoded = json.dumps(
        response,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > MAX_RESPONSE_BYTES:
        encoded = json.dumps(
            error_response(request_id, TemporalProtocolError("response_too_large")),
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    return encoded
