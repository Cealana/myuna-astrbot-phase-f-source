from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
import struct
from typing import Callable, Mapping

from myuna_core.audit import AuditLogger
from myuna_core.channel_capability import ChannelNeutralCapabilityProfile
from myuna_core.providers.local import LocalOpenAIProvider

from .active_selector import load_active_profile
from .client import AuditedOwnerProfileReadRuntime, UnixSocketOwnerProfileClient
from .contracts import OwnerProfileError
from .write_protocol import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    ProfileWriteProtocolError,
    build_write_error_response,
    build_write_success_response,
    parse_write_request_bytes,
)
from .write_publish import publish_stored_profile_candidate
from .write_runtime import (
    FilesystemOwnerProfileCandidateBackend,
    OwnerProfileWriteAccessError,
    OwnerProfileWriteAccessPolicy,
    OwnerProfileWriteRuntime,
)


_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DEFAULT_CLIENT_ID = "telegram-owner-private"
_DEFAULT_CHANNEL_KIND = "astrbot_telegram"


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
    fallback = build_write_error_response(
        request_id,
        OwnerProfileError("profile_write_response_too_large"),
    )
    return json.dumps(fallback, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )


def _audit_failure(
    audit: AuditLogger | None,
    *,
    request_id: str | None,
    error: OwnerProfileError | ProfileWriteProtocolError,
) -> None:
    if audit is None or request_id is None:
        return
    audit.emit(
        "owner_profile_candidate_write_v1",
        outcome="failed" if error.retryable else "rejected",
        request_id=request_id,
        details={
            "operation_category": "worker",
            "error_category": error.code,
            "raw_input_recorded": False,
            "candidate_content_recorded": False,
            "profile_content_recorded": False,
            "identity_recorded": False,
            "confirmation_code_recorded": False,
            "legacy_namespace_written": False,
            "memory_write_performed": False,
        },
    )


def process_write_request(
    payload: bytes,
    *,
    runtime: OwnerProfileWriteRuntime,
    authenticated_client_id: str = _DEFAULT_CLIENT_ID,
    authenticated_channel_kind: str = _DEFAULT_CHANNEL_KIND,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> bytes:
    request_id = _safe_request_id(payload)
    try:
        request = parse_write_request_bytes(
            payload,
            authenticated_client_id=authenticated_client_id,
            authenticated_channel_kind=authenticated_channel_kind,
        )
        request_id = str(request["request_id"])
        result = runtime.handle(
            str(request["text"]),
            request_id=request_id,
            authenticated_context=request["authenticated_context"],
            now=now(),
        )
        response = build_write_success_response(
            request_id=request_id,
            result=result,
        )
    except OwnerProfileWriteAccessError as exc:
        error = OwnerProfileError(exc.code)
        _audit_failure(runtime.audit, request_id=request_id, error=error)
        response = build_write_error_response(request_id, error)
    except (ProfileWriteProtocolError, OwnerProfileError) as exc:
        _audit_failure(runtime.audit, request_id=request_id, error=exc)
        response = build_write_error_response(request_id, exc)
    except (OSError, RuntimeError, TypeError, ValueError):
        error = OwnerProfileError("profile_write_unavailable", retryable=True)
        _audit_failure(runtime.audit, request_id=request_id, error=error)
        response = build_write_error_response(request_id, error)
    return _encode(response, request_id=request_id)


def read_one_request(connection: socket.socket) -> bytes:
    payload = bytearray()
    while True:
        chunk = connection.recv(4096)
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


def unix_peer_uid(connection: socket.socket) -> int:
    payload = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    _pid, uid, _gid = struct.unpack("3i", payload)
    return uid


def serve_write_connection(
    connection: socket.socket,
    *,
    runtime: OwnerProfileWriteRuntime,
    expected_peer_uid: int,
    peer_uid: Callable[[socket.socket], int] = unix_peer_uid,
) -> None:
    connection.settimeout(180.0)
    try:
        if peer_uid(connection) != expected_peer_uid:
            response = _encode(
                build_write_error_response(
                    None,
                    OwnerProfileError("profile_write_peer_rejected"),
                ),
                request_id=None,
            )
        else:
            payload = read_one_request(connection)
            response = process_write_request(payload, runtime=runtime)
    except TimeoutError:
        response = _encode(
            build_write_error_response(
                None,
                OwnerProfileError("profile_write_timeout", retryable=True),
            ),
            request_id=None,
        )
    except OSError:
        return
    try:
        connection.sendall(response)
    except OSError:
        return


def _required_absolute(source: Mapping[str, str], key: str) -> Path:
    path = Path(source.get(key, ""))
    if not path.is_absolute():
        raise RuntimeError(f"{key} must be absolute")
    return path


def _required_uid(source: Mapping[str, str], key: str) -> int:
    try:
        value = int(source.get(key, ""))
    except ValueError as exc:
        raise RuntimeError(f"{key} must be an integer") from exc
    if value < 1:
        raise RuntimeError(f"{key} must be positive")
    return value


def build_runtime_from_environment(
    environ: Mapping[str, str] | None = None,
) -> tuple[OwnerProfileWriteRuntime, int]:
    source = os.environ if environ is None else environ
    owner_uid = _required_uid(source, "MYUNA_OWNER_PROFILE_OWNER_UID")
    core_peer_uid = _required_uid(source, "MYUNA_OWNER_PROFILE_CORE_PEER_UID")
    if owner_uid != os.geteuid():
        raise RuntimeError("Profile writer uid does not match process identity")
    profile_root = _required_absolute(source, "MYUNA_OWNER_PROFILE_ROOT")
    candidate_root = _required_absolute(source, "MYUNA_OWNER_PROFILE_CANDIDATE_ROOT")
    lifecycle_ledger = _required_absolute(source, "MYUNA_OWNER_PROFILE_LIFECYCLE_LEDGER")
    capability_path = _required_absolute(
        source, "MYUNA_OWNER_PROFILE_WRITE_CAPABILITY_PROFILE"
    )
    read_socket = _required_absolute(source, "MYUNA_OWNER_PROFILE_READ_SOCKET")
    audit_dir = _required_absolute(source, "MYUNA_OWNER_PROFILE_WRITE_AUDIT_DIR")
    local_base_url = source.get("MYUNA_LOCAL_PROVIDER_BASE_URL", "")
    local_model = source.get("MYUNA_LOCAL_PROVIDER_MODEL", "")
    try:
        local_timeout = float(
            source.get("MYUNA_LOCAL_PROVIDER_TIMEOUT_SECONDS", "120")
        )
    except ValueError as exc:
        raise RuntimeError("local provider timeout is invalid") from exc
    audit = AuditLogger(audit_dir, "dev")
    read_runtime = AuditedOwnerProfileReadRuntime(
        UnixSocketOwnerProfileClient(read_socket),
        audit,
        timeout_seconds=0.5,
    )
    provider = LocalOpenAIProvider(
        default_model=local_model,
        base_url=local_base_url,
        timeout_seconds=local_timeout,
    )

    def publish(record):
        active = load_active_profile(profile_root, expected_uid=owner_uid)
        return publish_stored_profile_candidate(
            profile_root=profile_root,
            lifecycle_ledger=lifecycle_ledger,
            active_profile=active,
            record=record,
            expected_uid=owner_uid,
        )

    backend = FilesystemOwnerProfileCandidateBackend(
        store_root=candidate_root,
        active_profile_loader=lambda: load_active_profile(
            profile_root, expected_uid=owner_uid
        ),
        publisher=publish,
        expected_uid=owner_uid,
    )
    runtime = OwnerProfileWriteRuntime(
        access_policy=OwnerProfileWriteAccessPolicy(
            ChannelNeutralCapabilityProfile.load(capability_path)
        ),
        read_runtime=read_runtime,
        provider=provider,
        backend=backend,
        audit=audit,
    )
    return runtime, core_peer_uid


def serve_systemd_socket() -> None:
    if os.geteuid() == 0:
        raise RuntimeError("refusing_to_run_as_root")
    runtime, core_peer_uid = build_runtime_from_environment()
    with inherited_systemd_socket() as server:
        while True:
            connection, _ = server.accept()
            with connection:
                serve_write_connection(
                    connection,
                    runtime=runtime,
                    expected_peer_uid=core_peer_uid,
                )


def main() -> int:
    serve_systemd_socket()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
