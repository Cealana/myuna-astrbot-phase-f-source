from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import struct
from typing import Mapping

from myuna_core.trusted_time import (
    DurableTrustedTimeProvider,
    LinuxAdjtimexSynchronizationProbe,
    SystemUtcObservationSource,
    TrustedTimeWatermark,
)

from .contracts import TemporalContextError
from .protocol import MAX_REQUEST_BYTES, error_response, process_request
from .runtime import ActiveTemporalContextRuntime
from .store import TemporalContextStore


STATE_DIRECTORY_NAME = "myuna-active-temporal-context-v1"
TEMPORAL_DATABASE_NAME = "temporal-context.sqlite3"
TRUSTED_TIME_DATABASE_NAME = "trusted-time.sqlite3"
CLIENT_ID = "telegram-owner-runtime-v1"
CHANNEL_KIND = "astrbot_telegram"
MAX_CONNECTION_SECONDS = 3.0


def _positive_int(source: Mapping[str, str], key: str) -> int:
    try:
        value = int(source.get(key, ""))
    except ValueError:
        raise RuntimeError("service_environment_invalid") from None
    if value < 1:
        raise RuntimeError("service_environment_invalid")
    return value


def _state_root(source: Mapping[str, str], *, expected_uid: int) -> Path:
    path = Path(source.get("MYUNA_P08_STATE_ROOT", ""))
    if not path.is_absolute() or path.name != STATE_DIRECTORY_NAME:
        raise RuntimeError("service_environment_invalid")
    try:
        metadata = path.lstat()
    except OSError:
        raise RuntimeError("service_state_unavailable") from None
    if path.is_symlink() or metadata.st_uid != expected_uid or (metadata.st_mode & 0o777) != 0o700:
        raise RuntimeError("service_state_permission_drift")
    return path


def build_runtime_from_environment(
    environ: Mapping[str, str] | None = None,
) -> ActiveTemporalContextRuntime:
    source = os.environ if environ is None else environ
    expected_uid = _positive_int(source, "MYUNA_P08_SERVICE_UID")
    if os.geteuid() != expected_uid:
        raise RuntimeError("service_identity_rejected")
    root = _state_root(source, expected_uid=expected_uid)
    store = TemporalContextStore(
        root / TEMPORAL_DATABASE_NAME,
        expected_uid=expected_uid,
    )
    watermark = store.trusted_time_watermark()
    provider_watermark = (
        None
        if watermark is None
        else TrustedTimeWatermark(
            source=watermark[0],
            sequence=watermark[1],
            instant=watermark[2],
        )
    )
    observation = SystemUtcObservationSource(LinuxAdjtimexSynchronizationProbe())
    provider = DurableTrustedTimeProvider(
        root / TRUSTED_TIME_DATABASE_NAME,
        observation,
        consumer_watermark=provider_watermark,
        expected_uid=expected_uid,
    )
    provider.validate_state()
    return ActiveTemporalContextRuntime(store, provider)


def initialize_state(
    root: Path,
    *,
    expected_uid: int,
) -> None:
    """Initialize two empty private databases; never repair or replace state."""

    if os.geteuid() != expected_uid:
        raise RuntimeError("service_identity_rejected")
    validated = _state_root(
        {"MYUNA_P08_STATE_ROOT": str(root)},
        expected_uid=expected_uid,
    )
    temporal_path = validated / TEMPORAL_DATABASE_NAME
    trusted_path = validated / TRUSTED_TIME_DATABASE_NAME
    if temporal_path.exists() or trusted_path.exists() or temporal_path.is_symlink() or trusted_path.is_symlink():
        raise RuntimeError("service_state_already_exists")
    TemporalContextStore.create(temporal_path, expected_uid=expected_uid)
    try:
        DurableTrustedTimeProvider.create(
            trusted_path,
            SystemUtcObservationSource(LinuxAdjtimexSynchronizationProbe()),
            expected_uid=expected_uid,
        )
    except BaseException:
        # Initialization is allowed to remove only the brand-new empty P08 file
        # created by this call. Existing paths were rejected above.
        temporal_path.unlink(missing_ok=True)
        raise


def _peer_uid(connection: socket.socket) -> int:
    try:
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        _pid, uid, _gid = struct.unpack("3i", raw)
    except (AttributeError, OSError, struct.error):
        raise RuntimeError("peer_credentials_unavailable") from None
    if uid < 1:
        raise RuntimeError("peer_identity_rejected")
    return uid


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


def serve_connection(
    connection: socket.socket,
    runtime: ActiveTemporalContextRuntime,
    *,
    expected_peer_uid: int,
) -> None:
    connection.settimeout(MAX_CONNECTION_SECONDS)
    try:
        if _peer_uid(connection) != expected_peer_uid:
            raise RuntimeError("peer_identity_rejected")
        raw = read_one_request(connection)
        response = process_request(
            raw,
            runtime,
            authenticated_client_id=CLIENT_ID,
            authenticated_channel_kind=CHANNEL_KIND,
        )
    except (OSError, RuntimeError, TimeoutError):
        response = json.dumps(
            error_response(None, TemporalContextError("temporal_unavailable", retryable=True)),
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    try:
        connection.sendall(response)
    except OSError:
        return


def inherited_systemd_socket() -> socket.socket:
    if int(os.environ.get("LISTEN_FDS", "0")) != 1:
        raise RuntimeError("systemd_socket_required")
    listen_pid = int(os.environ.get("LISTEN_PID", "0"))
    if listen_pid not in (0, os.getpid()):
        raise RuntimeError("systemd_socket_pid_mismatch")
    return socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)


def serve_systemd_socket() -> None:
    if os.geteuid() == 0:
        raise RuntimeError("refusing_to_run_as_root")
    peer_uid = _positive_int(os.environ, "MYUNA_P08_TELEGRAM_UID")
    runtime = build_runtime_from_environment()
    with inherited_systemd_socket() as server:
        while True:
            connection, _ = server.accept()
            with connection:
                serve_connection(connection, runtime, expected_peer_uid=peer_uid)


def main() -> int:
    serve_systemd_socket()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
