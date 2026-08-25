from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import re
import socket
from typing import Callable, Iterable

from .postgres_source import RecordSourceError, load_safe_records, verify_runtime_identity
from .protocol import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    ProtocolError,
    build_response,
    error_response,
    parse_request_bytes,
)


_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def _safe_request_id(payload: bytes) -> str | None:
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(decoded, dict):
        return None
    value = decoded.get("request_id")
    return value if isinstance(value, str) and _SAFE_LABEL.fullmatch(value) else None


def _encode(response: dict[str, object], *, request_id: str | None) -> bytes:
    encoded = json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    if len(encoded) <= MAX_RESPONSE_BYTES:
        return encoded
    return json.dumps(
        error_response(request_id, ProtocolError("response_too_large")),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def process_request(
    payload: bytes,
    *,
    records: Iterable[dict[str, object]] | None = None,
    at: datetime | None = None,
    loader: Callable[[], list[dict[str, object]]] = load_safe_records,
) -> bytes:
    request_id = _safe_request_id(payload)
    try:
        request = parse_request_bytes(payload)
        request_id = request["request_id"]
        safe_records = list(records) if records is not None else loader()
        response = build_response(
            request,
            safe_records,
            at=at or datetime.now(timezone.utc),
        )
    except ProtocolError as exc:
        response = error_response(request_id, exc)
    except RecordSourceError as exc:
        response = error_response(
            request_id,
            ProtocolError(exc.code, retryable=exc.retryable),
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        response = error_response(
            request_id,
            ProtocolError("retrieval_unavailable", retryable=True),
        )
    return _encode(response, request_id=request_id)


def read_one_request(connection: socket.socket) -> bytes:
    payload = bytearray()
    while True:
        chunk = connection.recv(1024)
        if not chunk:
            break
        payload.extend(chunk)
        if len(payload) > MAX_REQUEST_BYTES or b"\n" in chunk:
            break
    return bytes(payload).rstrip(b"\r\n")


def inherited_systemd_socket() -> socket.socket:
    if int(os.environ.get("LISTEN_FDS", "0")) != 1:
        raise RuntimeError("systemd_socket_required")
    listen_pid = int(os.environ.get("LISTEN_PID", "0"))
    if listen_pid not in (0, os.getpid()):
        raise RuntimeError("systemd_socket_pid_mismatch")
    return socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)


def serve_systemd_socket() -> None:
    verify_runtime_identity()
    with inherited_systemd_socket() as server:
        while True:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(1.5)
                connection.sendall(process_request(read_one_request(connection)))


def main() -> int:
    serve_systemd_socket()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
