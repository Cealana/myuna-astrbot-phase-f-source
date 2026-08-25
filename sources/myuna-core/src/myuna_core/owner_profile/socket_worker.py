from __future__ import annotations

import json
import os
from pathlib import Path
import re
import socket
from typing import Callable, Mapping

from .active_selector import load_active_profile
from .contracts import OwnerProfileError
from .loader import load_approved_profile
from .protocol import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    ProfileProtocolError,
    build_response,
    error_response,
    parse_request_bytes,
)
from .retrieval import OwnerProfileIndex


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
    encoded = json.dumps(
        response,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) <= MAX_RESPONSE_BYTES:
        return encoded
    fallback = error_response(
        request_id,
        ProfileProtocolError("response_too_large"),
    )
    return json.dumps(fallback, separators=(",", ":"), sort_keys=True).encode("utf-8")


def process_request(
    payload: bytes,
    *,
    index: OwnerProfileIndex | None = None,
    index_loader: Callable[[], OwnerProfileIndex] | None = None,
) -> bytes:
    request_id = _safe_request_id(payload)
    try:
        request = parse_request_bytes(payload)
        request_id = str(request["request_id"])
        if (index is None) == (index_loader is None):
            raise RuntimeError("exactly one Profile index source is required")
        if index_loader is not None:
            index = index_loader()
        assert index is not None
        response = build_response(request, index)
    except (ProfileProtocolError, OwnerProfileError) as exc:
        response = error_response(request_id, exc)
    except (OSError, RuntimeError, TypeError, ValueError):
        response = error_response(
            request_id,
            OwnerProfileError("profile_unavailable", retryable=True),
        )
    return _encode(response, request_id=request_id)


def build_index_from_environment(
    environ: Mapping[str, str] | None = None,
) -> OwnerProfileIndex:
    source = os.environ if environ is None else environ
    raw_uid = source.get("MYUNA_OWNER_PROFILE_OWNER_UID", "")
    try:
        owner_uid = int(raw_uid)
    except ValueError as exc:
        raise RuntimeError("invalid Profile owner uid") from exc
    profile_root_value = source.get("MYUNA_OWNER_PROFILE_ROOT", "")
    if profile_root_value:
        if source.get("MYUNA_OWNER_PROFILE_RELEASE_DIR", "") or source.get(
            "MYUNA_OWNER_PROFILE_SHA256", ""
        ):
            raise RuntimeError("dynamic and pinned Profile selectors cannot coexist")
        profile = load_active_profile(
            Path(profile_root_value),
            expected_uid=owner_uid,
        )
    else:
        profile = load_approved_profile(
            Path(source.get("MYUNA_OWNER_PROFILE_RELEASE_DIR", "")),
            expected_sha256=source.get("MYUNA_OWNER_PROFILE_SHA256", ""),
            expected_owner_uid=owner_uid,
        )
    return OwnerProfileIndex(profile)


def read_one_request(connection: socket.socket) -> bytes:
    payload = bytearray()
    while True:
        chunk = connection.recv(1024)
        if not chunk:
            break
        payload.extend(chunk)
        if len(payload) > MAX_REQUEST_BYTES or b"\n" in chunk:
            break
    return bytes(payload).split(b"\n", 1)[0].rstrip(b"\r")


def inherited_systemd_socket() -> socket.socket:
    if int(os.environ.get("LISTEN_FDS", "0")) != 1:
        raise RuntimeError("systemd_socket_required")
    listen_pid = int(os.environ.get("LISTEN_PID", "0"))
    if listen_pid not in (0, os.getpid()):
        raise RuntimeError("systemd_socket_pid_mismatch")
    return socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)


def serve_connection(
    connection: socket.socket,
    *,
    index: OwnerProfileIndex | None = None,
    index_loader: Callable[[], OwnerProfileIndex] | None = None,
) -> None:
    connection.settimeout(3.0)
    try:
        payload = read_one_request(connection)
    except TimeoutError:
        response = _encode(
            error_response(
                None,
                OwnerProfileError("profile_timeout", retryable=True),
            ),
            request_id=None,
        )
    except OSError:
        return
    else:
        response = process_request(
            payload,
            index=index,
            index_loader=index_loader,
        )
    try:
        connection.sendall(response)
    except OSError:
        return


def serve_systemd_socket() -> None:
    if os.geteuid() == 0:
        raise RuntimeError("refusing_to_run_as_root")
    with inherited_systemd_socket() as server:
        while True:
            connection, _ = server.accept()
            with connection:
                serve_connection(
                    connection,
                    index_loader=build_index_from_environment,
                )


def main() -> int:
    serve_systemd_socket()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
