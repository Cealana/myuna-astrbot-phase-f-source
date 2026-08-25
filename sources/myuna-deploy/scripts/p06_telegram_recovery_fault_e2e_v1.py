#!/usr/bin/env python3
"""Bounded Telegram Owner-only fault/recovery controller for P06 E2E."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import grp
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import tempfile
import time
from typing import Mapping


CONFIG = Path("/etc/myuna-telegram-gateway/owner-runtime-v1.json")
BACKUP_ROOT = Path(
    "/var/backups/myuna/p06-telegram-recovery-v1/fault-e2e"
)
STATE = Path(
    "/var/lib/myuna-telegram-gateway/p06-recovery/FAULT_E2E_STATE.json"
)
SERVICE = "myuna-telegram-owner-runtime-dev.service"
SERVICE_GROUP = "myuna-gateway-telegram"
SCHEMA = "myuna.p06-telegram-recovery-fault-e2e.v1"
FAULT_PORTS = range(65431, 65440)


class FaultRejected(RuntimeError):
    """A bounded fault-control invariant was rejected."""


@dataclass(frozen=True, slots=True)
class ProtectedMetadata:
    uid: int
    gid: int
    mode: int


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _service_gid() -> int:
    try:
        return grp.getgrnam(SERVICE_GROUP).gr_gid
    except KeyError as exc:
        raise FaultRejected("service group rejected") from exc


def _metadata(path: Path) -> ProtectedMetadata:
    if path.is_symlink() or not path.is_file():
        raise FaultRejected("protected file rejected")
    metadata = path.stat()
    return ProtectedMetadata(
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        mode=stat.S_IMODE(metadata.st_mode),
    )


def _validate_config(path: Path = CONFIG) -> tuple[bytes, dict[str, object], ProtectedMetadata]:
    metadata = _metadata(path)
    if metadata != ProtectedMetadata(uid=0, gid=_service_gid(), mode=0o640):
        raise FaultRejected("runtime config metadata rejected")
    try:
        raw = path.read_bytes()
        payload = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise FaultRejected("runtime config rejected") from exc
    if not isinstance(payload, dict):
        raise FaultRejected("runtime config rejected")
    core_port = payload.get("core_port")
    if not isinstance(core_port, int) or not 1024 <= core_port <= 65535:
        raise FaultRejected("runtime core port rejected")
    return raw, payload, metadata


def render_fault_config(
    payload: Mapping[str, object],
    fault_port: int,
) -> bytes:
    if not 1024 <= fault_port <= 65535:
        raise FaultRejected("fault port rejected")
    rendered = dict(payload)
    if not isinstance(rendered.get("core_port"), int):
        raise FaultRejected("runtime core port rejected")
    rendered["core_port"] = fault_port
    return (
        json.dumps(rendered, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _atomic_write(
    path: Path,
    payload: bytes,
    metadata: ProtectedMetadata,
) -> None:
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    try:
        os.fchmod(file_descriptor, metadata.mode)
        os.fchown(file_descriptor, metadata.uid, metadata.gid)
        with os.fdopen(file_descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def _write_state(payload: Mapping[str, object]) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(
        STATE,
        (
            json.dumps(payload, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8"),
        ProtectedMetadata(uid=0, gid=0, mode=0o600),
    )


def _read_state(*, require_active: bool) -> dict[str, object] | None:
    if not STATE.exists():
        if require_active:
            raise FaultRejected("fault state missing")
        return None
    metadata = _metadata(STATE)
    if metadata != ProtectedMetadata(uid=0, gid=0, mode=0o600):
        raise FaultRejected("fault state metadata rejected")
    try:
        payload = json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FaultRejected("fault state rejected") from exc
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        raise FaultRejected("fault state rejected")
    if require_active and payload.get("status") != "active":
        raise FaultRejected("no active fault")
    return payload


def _choose_fault_port() -> int:
    for candidate in FAULT_PORTS:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", candidate))
        except OSError:
            probe.close()
            continue
        probe.close()
        return candidate
    raise FaultRejected("no bounded fault port available")


def _systemctl(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["systemctl", *arguments],
        check=check,
        capture_output=True,
        text=True,
    )


def _restart_and_verify_stable() -> None:
    _systemctl("restart", SERVICE)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        active = _systemctl("is-active", SERVICE, check=False)
        if active.stdout.strip() == "active":
            break
        time.sleep(0.25)
    else:
        raise FaultRejected("runtime restart rejected")
    before = _systemctl(
        "show",
        SERVICE,
        "-p",
        "NRestarts",
        "--value",
    ).stdout.strip()
    time.sleep(3)
    active = _systemctl("is-active", SERVICE, check=False)
    after = _systemctl(
        "show",
        SERVICE,
        "-p",
        "NRestarts",
        "--value",
    ).stdout.strip()
    if active.stdout.strip() != "active" or before != after:
        raise FaultRejected("runtime stability rejected")


def _restore_from_state(state: Mapping[str, object]) -> None:
    backup_value = state.get("backup")
    original_sha256 = state.get("original_sha256")
    original_uid = state.get("original_uid")
    original_gid = state.get("original_gid")
    original_mode = state.get("original_mode")
    if (
        not isinstance(backup_value, str)
        or not isinstance(original_sha256, str)
        or not isinstance(original_uid, int)
        or not isinstance(original_gid, int)
        or not isinstance(original_mode, int)
    ):
        raise FaultRejected("restore state rejected")
    backup = Path(backup_value)
    backup_metadata = _metadata(backup)
    if backup_metadata != ProtectedMetadata(uid=0, gid=0, mode=0o600):
        raise FaultRejected("backup metadata rejected")
    original = backup.read_bytes()
    if _digest(original) != original_sha256:
        raise FaultRejected("backup digest rejected")
    expected = ProtectedMetadata(
        uid=original_uid,
        gid=original_gid,
        mode=original_mode,
    )
    if expected != ProtectedMetadata(uid=0, gid=_service_gid(), mode=0o640):
        raise FaultRejected("restore metadata rejected")
    _atomic_write(CONFIG, original, expected)
    _restart_and_verify_stable()


def inject() -> dict[str, object]:
    if os.geteuid() != 0:
        raise FaultRejected("root required")
    previous_state = _read_state(require_active=False)
    if previous_state is not None and previous_state.get("status") == "active":
        raise FaultRejected("fault already active")
    original, payload, metadata = _validate_config()
    fault_port = _choose_fault_port()
    stamp = _utc_stamp()
    backup_dir = BACKUP_ROOT / stamp
    backup_dir.mkdir(parents=True, mode=0o700)
    os.chown(backup_dir, 0, 0)
    os.chmod(backup_dir, 0o700)
    backup = backup_dir / CONFIG.name
    _atomic_write(
        backup,
        original,
        ProtectedMetadata(uid=0, gid=0, mode=0o600),
    )
    if previous_state is not None:
        previous_receipt = backup_dir / "FAULT_E2E_STATE.previous.json"
        _atomic_write(
            previous_receipt,
            STATE.read_bytes(),
            ProtectedMetadata(uid=0, gid=0, mode=0o600),
        )
    state: dict[str, object] = {
        "schema": SCHEMA,
        "status": "active",
        "backup": str(backup),
        "original_sha256": _digest(original),
        "original_uid": metadata.uid,
        "original_gid": metadata.gid,
        "original_mode": metadata.mode,
        "original_port": payload["core_port"],
        "fault_port": fault_port,
        "started_at": stamp,
    }
    _atomic_write(CONFIG, render_fault_config(payload, fault_port), metadata)
    _write_state(state)
    try:
        _restart_and_verify_stable()
    except BaseException:
        _restore_from_state(state)
        state["status"] = "rolled_back"
        state["ended_at"] = _utc_stamp()
        _write_state(state)
        raise
    return {
        "status": "FAULT_ACTIVE",
        "scope": "telegram-owner-runtime-only",
        "backup": stamp,
        "runtime_service": "active_stable",
    }


def restore() -> dict[str, object]:
    if os.geteuid() != 0:
        raise FaultRejected("root required")
    state = _read_state(require_active=True)
    assert state is not None
    _restore_from_state(state)
    state["status"] = "restored"
    state["ended_at"] = _utc_stamp()
    _write_state(state)
    return {
        "status": "RESTORED",
        "runtime_service": "active_stable",
        "backup_preserved": True,
    }


def status() -> dict[str, object]:
    state = _read_state(require_active=False)
    return {
        "status": "ABSENT" if state is None else state.get("status"),
        "scope": "telegram-owner-runtime-only",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("inject", "restore", "status"))
    arguments = parser.parse_args()
    try:
        if arguments.action == "inject":
            result = inject()
        elif arguments.action == "restore":
            result = restore()
        else:
            result = status()
    except (FaultRejected, OSError, subprocess.SubprocessError, ValueError):
        print(json.dumps({"status": "rejected"}, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
