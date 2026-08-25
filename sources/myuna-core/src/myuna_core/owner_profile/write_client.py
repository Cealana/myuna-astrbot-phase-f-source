from __future__ import annotations

import json
from pathlib import Path
import socket

from myuna_core.authenticated_conversation import AuthenticatedConversationContext

from .contracts import OwnerProfileError
from .write_protocol import (
    BOUNDARY,
    MAX_RESPONSE_BYTES,
    OPERATION,
    SCHEMA_VERSION,
    ProfileWriteProtocolError,
    parse_write_response,
)
from .write_runtime import OwnerProfileWriteResult


class UnixSocketOwnerProfileWriteClient:
    def __init__(self, socket_path: Path, *, timeout_seconds: float = 150.0) -> None:
        if not isinstance(socket_path, Path) or not socket_path.is_absolute():
            raise ValueError("Profile write socket path must be absolute")
        if not 1.0 <= timeout_seconds <= 180.0:
            raise ValueError("Profile write timeout is outside the supported range")
        self.socket_path = socket_path
        self.timeout_seconds = timeout_seconds

    def handle(
        self,
        text: str,
        *,
        request_id: str,
        authenticated_context: AuthenticatedConversationContext | None,
    ) -> OwnerProfileWriteResult:
        if authenticated_context is None:
            raise OwnerProfileError("authenticated_context_required")
        request = json.dumps(
            {
                "authenticated_context": authenticated_context.as_payload(),
                "boundary": BOUNDARY,
                "operation": OPERATION,
                "request_id": request_id,
                "schema_version": SCHEMA_VERSION,
                "text": text,
                "timeout_ms": round(self.timeout_seconds * 1000),
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout_seconds)
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
            raise OwnerProfileError("profile_write_timeout", retryable=True) from exc
        except OSError as exc:
            raise OwnerProfileError("profile_write_unavailable", retryable=True) from exc
        if not response or len(response) > MAX_RESPONSE_BYTES:
            raise OwnerProfileError("profile_write_unavailable", retryable=True)
        try:
            payload = json.loads(bytes(response).decode("utf-8"))
            return parse_write_response(
                payload,
                expected_request_id=request_id,
            )
        except (UnicodeError, json.JSONDecodeError, ProfileWriteProtocolError) as exc:
            raise OwnerProfileError("malformed_write_worker_response") from exc
