#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import grp
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from activate_p06_telegram_recovery_v1 import (
    ActivationRejected as RuntimeCandidateRejected,
    validate_runtime_candidate,
)


RUNTIME_RELEASE_ROOT = Path("/opt/myuna/context24-gateway/telegram/releases")
PREVIOUS_RUNTIME_RELEASE = (
    "ff8cc051fed592a4752b7a184ad613bb4ccde3012a004a1367385fcaa66a0227"
)
RUNTIME_SERVICE = "myuna-telegram-owner-runtime-dev.service"
RUNTIME_SOCKET = "myuna-telegram-owner-runtime-dev.socket"
CORE_SERVICE = "myuna-core@qq.service"
DROPIN = Path(
    "/etc/systemd/system/myuna-telegram-owner-runtime-dev.service.d/"
    "zzzzzzzz-p07-owner-profile-read-v1.conf"
)
BACKUP_ROOT = Path("/var/backups/myuna/p07-owner-profile-telegram-v1")
RECEIPT_ROOT = Path("/var/lib/myuna-telegram-gateway/p07-owner-profile")
RECEIPT = RECEIPT_ROOT / "LAST_ACTIVATION.json"
SCHEMA = "myuna.p07-owner-profile-telegram-activation.v1"


class ActivationRejected(RuntimeError):
    """The bounded Telegram Profile-read activation was rejected."""


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(arguments: list[str], *, check: bool = True, timeout: int = 300) -> str:
    result = subprocess.run(
        arguments,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        raise ActivationRejected(
            f"fixed command failed: {Path(arguments[0]).name}:{result.returncode}"
        )
    return result.stdout.strip()


def systemctl(*arguments: str, check: bool = True) -> str:
    return run(["/usr/bin/systemctl", *arguments], check=check)


def is_active(unit: str) -> bool:
    result = subprocess.run(
        ["/usr/bin/systemctl", "is-active", "--quiet", unit],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def render_dropin(runtime_digest: str) -> bytes:
    runtime = RUNTIME_RELEASE_ROOT / runtime_digest / "runtime"
    return (
        "[Service]\n"
        "ExecStart=\n"
        f"ExecStart=/usr/bin/python3 {runtime}/telegram_owner_runtime_gateway.py\n"
        f"Environment=PYTHONPATH={runtime}\n"
        "Environment=MYUNA_SESSION_CONTEXT_STORE=sqlite-v1\n"
    ).encode("utf-8")


def _atomic_write(path: Path, content: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, 0, 0)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _file_inventory(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): digest_file(path)
        for path in root.rglob("*")
        if path.is_file()
    }


def _install_runtime(candidate: Path, runtime_digest: str) -> Path:
    destination = RUNTIME_RELEASE_ROOT / runtime_digest
    if destination.exists():
        if destination.is_symlink() or _file_inventory(candidate) != _file_inventory(
            destination
        ):
            raise ActivationRejected("installed runtime release drifted")
    else:
        shutil.copytree(candidate, destination)
    group_id = grp.getgrnam("myuna-gateway-telegram").gr_gid
    for path in (destination, *destination.rglob("*")):
        os.chown(path, 0, group_id)
        os.chmod(path, 0o550 if path.is_dir() else 0o440)
    return destination


def _validate_authenticated_context(candidate: Path) -> None:
    source = candidate / "runtime/telegram_owner_runtime_gateway.py"
    try:
        text = source.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ActivationRejected("Telegram runtime source rejected") from exc
    required = (
        'AUTHENTICATED_CONTEXT_SCHEMA_VERSION = '
        '"myuna.authenticated-conversation-context.v1"',
        "def build_authenticated_context(",
        '"authenticated_context": authenticated_context',
        "core.chat(messages, decision=decision)",
        'CORE_CLIENT_ID = "telegram-owner-private"',
        'CHANNEL_KIND = "astrbot_telegram"',
    )
    if any(value not in text for value in required):
        raise ActivationRejected("authenticated Telegram context boundary missing")


def _effective_exec_start() -> str:
    return systemctl("show", RUNTIME_SERVICE, "-p", "ExecStart", "--value")


def _verify_prestate(runtime_digest: str) -> str:
    if not all(is_active(unit) for unit in (CORE_SERVICE, RUNTIME_SOCKET, RUNTIME_SERVICE)):
        raise ActivationRejected("required live services are not active")
    current = _effective_exec_start()
    expected_candidate = f"/{runtime_digest}/runtime/telegram_owner_runtime_gateway.py"
    if DROPIN.exists():
        if DROPIN.is_symlink() or DROPIN.read_bytes() != render_dropin(runtime_digest):
            raise ActivationRejected("P07 Telegram drop-in drifted")
        if expected_candidate not in current:
            raise ActivationRejected("P07 Telegram effective runtime drifted")
        return "already-active"
    if f"/{PREVIOUS_RUNTIME_RELEASE}/runtime/telegram_owner_runtime_gateway.py" not in current:
        raise ActivationRejected("Telegram runtime prestate drifted")
    return "ready"


def _backup(runtime_digest: str, previous_exec_start: str) -> Path:
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(BACKUP_ROOT, 0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = BACKUP_ROOT / stamp
    backup.mkdir(mode=0o700)
    receipt = {
        "candidate_runtime_release": runtime_digest,
        "candidate_dropin_preexisting": False,
        "previous_runtime_release": PREVIOUS_RUNTIME_RELEASE,
        "previous_exec_start_sha256": hashlib.sha256(
            previous_exec_start.encode("utf-8")
        ).hexdigest(),
        "schema": SCHEMA,
    }
    _atomic_write(backup / "PRESTATE.json", canonical_bytes(receipt) + b"\n", mode=0o600)
    return backup


def _write_receipt(runtime_digest: str, backup: Path, *, status: str) -> None:
    RECEIPT_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(RECEIPT_ROOT, 0o700)
    payload = {
        "backup": backup.name,
        "core_service": "active",
        "profile_content_recorded": False,
        "raw_identity_recorded": False,
        "raw_message_recorded": False,
        "runtime_release": runtime_digest,
        "runtime_service": "active",
        "runtime_socket": "active",
        "schema": SCHEMA,
        "secret_recorded": False,
        "status": status,
    }
    _atomic_write(RECEIPT, canonical_bytes(payload) + b"\n", mode=0o600)


def _verify_active(runtime_digest: str) -> None:
    expected = f"/{runtime_digest}/runtime/telegram_owner_runtime_gateway.py"
    if not all(is_active(unit) for unit in (CORE_SERVICE, RUNTIME_SOCKET, RUNTIME_SERVICE)):
        raise ActivationRejected("post-activation service state rejected")
    if expected not in _effective_exec_start():
        raise ActivationRejected("post-activation runtime selection rejected")


def _rollback() -> None:
    try:
        if DROPIN.exists() and not DROPIN.is_symlink():
            DROPIN.unlink()
        systemctl("daemon-reload")
        systemctl("restart", RUNTIME_SERVICE)
        if not is_active(RUNTIME_SERVICE):
            raise ActivationRejected("rollback runtime is inactive")
        expected = f"/{PREVIOUS_RUNTIME_RELEASE}/runtime/telegram_owner_runtime_gateway.py"
        if expected not in _effective_exec_start():
            raise ActivationRejected("rollback runtime selection rejected")
    except (OSError, subprocess.SubprocessError) as exc:
        raise ActivationRejected("bounded rollback failed") from exc


def activate(candidate: Path, *, preflight_only: bool) -> dict[str, object]:
    runtime_digest, _manifest = validate_runtime_candidate(candidate)
    _validate_authenticated_context(candidate)
    state = _verify_prestate(runtime_digest)
    if state == "already-active":
        return {"runtime_release": runtime_digest, "status": "already-active"}
    if preflight_only:
        return {"runtime_release": runtime_digest, "status": "ready"}
    previous_exec_start = _effective_exec_start()
    backup = _backup(runtime_digest, previous_exec_start)
    mutated = False
    try:
        _install_runtime(candidate, runtime_digest)
        _atomic_write(DROPIN, render_dropin(runtime_digest), mode=0o644)
        mutated = True
        systemctl("daemon-reload")
        systemctl("restart", RUNTIME_SERVICE)
        _verify_active(runtime_digest)
        _write_receipt(
            runtime_digest,
            backup,
            status="ACTIVE_WAITING_OWNER_TELEGRAM_E2E",
        )
    except Exception:
        if mutated:
            _rollback()
        raise
    return {
        "backup": backup.name,
        "runtime_release": runtime_digest,
        "status": "ACTIVE_WAITING_OWNER_TELEGRAM_E2E",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-candidate", required=True, type=Path)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    try:
        result = activate(
            args.runtime_candidate.resolve(),
            preflight_only=args.preflight_only,
        )
    except (
        ActivationRejected,
        RuntimeCandidateRejected,
        OSError,
        ValueError,
        subprocess.SubprocessError,
    ):
        print(json.dumps({"status": "rejected"}, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
