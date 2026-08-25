from __future__ import annotations

import json
from pathlib import Path
import re
import socket
import time

from owner_memory_retrieval_v2.core_adapter import (
    CoreAdapterError,
    CoreSelection,
    parse_response,
    render_context,
)
from owner_memory_retrieval_v2.planner import POLICY_VERSION
from owner_memory_retrieval_v2.protocol import BOUNDARY, OPERATION

from .owner_readonly import (
    AuditSink,
    MAX_CONTEXT_CHARACTERS,
    MAX_QUERY_CHARACTERS,
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    OWNER_MEMORY_SOCKET_V1,
    OwnerMemoryReadError,
    OwnerMemorySelection,
    query_fingerprint,
)


OWNER_MEMORY_SOCKET_V2 = Path("/run/myuna-owner-memory-read-v2/worker.sock")
OWNER_MEMORY_POLICY_V2 = POLICY_VERSION
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def _require_safe_label(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _SAFE_LABEL.fullmatch(value) is None:
        raise OwnerMemoryReadError("invalid_worker_response", retryable=False)
    return value


class UnixSocketOwnerMemoryV2Client:
    """Strict transport for the independently versioned v2 retrieval protocol."""

    def __init__(self, socket_path: Path = OWNER_MEMORY_SOCKET_V2) -> None:
        if not socket_path.is_absolute() or socket_path != OWNER_MEMORY_SOCKET_V2:
            raise ValueError("Owner Memory v2 requires its fixed Unix socket")
        if socket_path == OWNER_MEMORY_SOCKET_V1:
            raise ValueError("Owner Memory v2 must not share the v1 Unix socket")
        self.socket_path = socket_path

    def retrieve(
        self,
        query: str,
        *,
        request_id: str,
        timeout_seconds: float,
    ) -> CoreSelection:
        if (
            not isinstance(query, str)
            or not query.strip()
            or len(query) > MAX_QUERY_CHARACTERS
            or "\x00" in query
        ):
            raise OwnerMemoryReadError("query_out_of_contract", retryable=False)
        _require_safe_label(request_id, "request_id")
        if not 0.1 <= timeout_seconds <= 3.0:
            raise OwnerMemoryReadError("invalid_timeout", retryable=False)
        request = json.dumps(
            {
                "schema_version": 2,
                "operation": OPERATION,
                "request_id": request_id,
                "boundary": BOUNDARY,
                "query": query.strip(),
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
                            "worker_response_too_large",
                            retryable=False,
                        )
        except OwnerMemoryReadError:
            raise
        except (OSError, TimeoutError) as exc:
            raise OwnerMemoryReadError("worker_unavailable", retryable=True) from exc
        try:
            payload = json.loads(response.decode("utf-8"))
            if not isinstance(payload, dict) or (
                payload.get("ok") is not True and payload.get("ok") is not False
            ):
                raise OwnerMemoryReadError(
                    "invalid_worker_response",
                    retryable=False,
                )
            return parse_response(payload, expected_request_id=request_id)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise OwnerMemoryReadError(
                "invalid_worker_response",
                retryable=False,
            ) from exc
        except CoreAdapterError as exc:
            raise OwnerMemoryReadError(exc.code, retryable=exc.retryable) from exc


class AuditedOwnerMemoryReadV2Adapter:
    def __init__(
        self,
        client: UnixSocketOwnerMemoryV2Client,
        audit: AuditSink,
        *,
        caller: str = "myuna-core-qq-owner-readonly-v2",
    ) -> None:
        _require_safe_label(caller, "caller")
        self.client = client
        self.audit = audit
        self.caller = caller

    def retrieve(
        self,
        query: str,
        *,
        request_id: str,
        timeout_seconds: float,
    ) -> CoreSelection:
        started = time.perf_counter()
        common = {
            "caller": self.caller,
            "protocol": "v2",
            "namespace_policy": "fixed_owner_namespace_v2",
            "restricted_allowed": False,
            "memory_write_allowed": False,
            "query_fingerprint": query_fingerprint(query),
            "query_characters": len(query),
        }
        try:
            result = self.client.retrieve(
                query,
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
                        (time.perf_counter() - started) * 1000,
                        3,
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
                "intent": result.intent,
                "horizon_used": result.horizon_used,
                "fallback_used": result.fallback_used,
                "policy_version": OWNER_MEMORY_POLICY_V2,
                "hit_count": len(result.records),
                "hit_ids": list(result.hit_ids),
                "worker_duration_ms": result.duration_ms,
                "bridge_duration_ms": round(
                    (time.perf_counter() - started) * 1000,
                    3,
                ),
            },
        )
        return result


class OwnerMemoryReadV2Runtime:
    def __init__(
        self,
        adapter: AuditedOwnerMemoryReadV2Adapter,
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
        result = self.adapter.retrieve(
            query,
            request_id=request_id,
            timeout_seconds=self.timeout_seconds,
        )
        context = render_context(result)
        if context is not None and len(context) > MAX_CONTEXT_CHARACTERS:
            raise OwnerMemoryReadError("context_budget_exceeded", retryable=False)
        return OwnerMemorySelection(
            state=result.state,
            context=context,
            hit_ids=result.hit_ids,
            mode_used=result.horizon_used,
            policy_version=OWNER_MEMORY_POLICY_V2,
        )
