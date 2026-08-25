from __future__ import annotations

import json
from pathlib import Path
import socket
import time
from typing import Callable

from myuna_core.audit import AuditLogger

from .contracts import AUDIT_NAMESPACE, OwnerProfileError, RetrievalResult
from .projection import error_audit_projection, success_audit_projection
from .protocol import (
    BOUNDARY,
    MAX_RESPONSE_BYTES,
    OPERATION,
    SCHEMA_VERSION,
    ProfileProtocolError,
    parse_response,
)


class UnixSocketOwnerProfileClient:
    def __init__(self, socket_path: Path) -> None:
        if not socket_path.is_absolute():
            raise ValueError("Profile socket path must be absolute")
        self.socket_path = socket_path

    def retrieve(
        self,
        query: str,
        *,
        request_id: str,
        channel_kind: str,
        timeout_seconds: float,
    ) -> RetrievalResult:
        request = json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "operation": OPERATION,
                "request_id": request_id,
                "boundary": BOUNDARY,
                "channel_kind": channel_kind,
                "query": query,
                "timeout_ms": round(timeout_seconds * 1000),
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(timeout_seconds)
                connection.connect(str(self.socket_path))
                connection.sendall(request + b"\n")
                connection.shutdown(socket.SHUT_WR)
                response = bytearray()
                while len(response) <= MAX_RESPONSE_BYTES:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    response.extend(chunk)
        except TimeoutError as exc:
            raise OwnerProfileError("profile_timeout", retryable=True) from exc
        except OSError as exc:
            raise OwnerProfileError("profile_unavailable", retryable=True) from exc
        if not response or len(response) > MAX_RESPONSE_BYTES:
            raise OwnerProfileError("profile_unavailable", retryable=True)
        try:
            payload = json.loads(bytes(response).decode("utf-8"))
            return parse_response(
                payload,
                expected_request_id=request_id,
                expected_channel_kind=channel_kind,
                expected_query_characters=len(query.strip()),
            )
        except (UnicodeError, json.JSONDecodeError, ProfileProtocolError) as exc:
            raise OwnerProfileError("malformed_worker_response") from exc


class AuditedOwnerProfileReadRuntime:
    def __init__(
        self,
        client: UnixSocketOwnerProfileClient,
        audit: AuditLogger,
        *,
        timeout_seconds: float = 0.5,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not 0.05 <= timeout_seconds <= 3.0:
            raise ValueError("Profile timeout is outside the supported range")
        self.client = client
        self.audit = audit
        self.timeout_seconds = timeout_seconds
        self.monotonic = monotonic

    def retrieve(
        self,
        query: str,
        *,
        request_id: str,
        channel_kind: str,
    ) -> RetrievalResult:
        started = self.monotonic()
        try:
            result = self.client.retrieve(
                query,
                request_id=request_id,
                channel_kind=channel_kind,
                timeout_seconds=self.timeout_seconds,
            )
        except OwnerProfileError as error:
            projection = error_audit_projection(
                error,
                query_characters=len(query) if isinstance(query, str) else 0,
                duration_ms=(self.monotonic() - started) * 1000,
            )
            self._emit(projection, request_id=request_id)
            raise
        projection = success_audit_projection(
            result,
            duration_ms=(self.monotonic() - started) * 1000,
        )
        self._emit(projection, request_id=request_id)
        return result

    def _emit(self, projection: dict[str, object], *, request_id: str) -> None:
        details = dict(projection)
        event = str(details.pop("event_namespace"))
        outcome = str(details.pop("outcome"))
        if event != AUDIT_NAMESPACE:
            raise RuntimeError("Profile audit namespace drifted")
        self.audit.emit(event, outcome=outcome, request_id=request_id, details=details)
