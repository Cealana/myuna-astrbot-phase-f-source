#!/usr/bin/env python3
"""Safely restart only NapCat when its QQ login state is stuck or offline."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
from typing import Any, Callable, Iterator
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


NAPCAT_CONTAINER = "myuna-napcat-dev"
ASTRBOT_CONTAINER = "myuna-astrbot-dev"
CORE_UNIT = "myuna-core@qq.service"
SECRET = Path("/etc/myuna-gateway/secrets/napcat-webui-token-v1")
STATE = Path("/var/lib/myuna-gateway/napcat-recovery/state.json")
EVENTS = Path("/var/log/myuna/napcat-recovery/events.jsonl")
LOCK = Path("/run/lock/myuna-napcat-login-recovery.lock")
BASE = "http://127.0.0.1:6099/api"
REQUIRED_MOUNTS = {"/app/.config/QQ", "/app/napcat/config"}


class RecoveryError(RuntimeError):
    """Fail-closed recovery error safe to display."""


class Runner:
    def run(self, *args: str, timeout: int = 60) -> str:
        result = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
        if result.returncode != 0:
            raise RecoveryError("recovery_dependency_failed")
        return result.stdout.decode("utf-8", "replace").strip()


def classify_login_error(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    rules = (
        ("already_logged_in_state_conflict", r"qq\s+is\s+logined|already\s+log(?:ged)?\s*in|已登录"),
        ("security_or_risk", r"security|risk|unsafe|安全|风险|验证"),
        ("session_or_credential", r"session|ticket|credential|token|会话|凭据|失效|过期"),
        ("offline_or_kicked", r"offline|logout|kicked|下线|掉线|被踢|离线"),
    )
    for name, pattern in rules:
        if re.search(pattern, value, re.I):
            return name
    return "other_nonempty_error"


def request_json(path: str, *, payload: dict[str, Any], bearer: str | None = None) -> tuple[int, Any]:
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    request = Request(
        BASE + path,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8", "replace"))
    except HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode("utf-8", "replace"))
        except Exception:
            return exc.code, None
    except URLError:
        return 0, None


def extract_bearer(document: Any) -> str | None:
    data = document.get("data") if isinstance(document, dict) else None
    if isinstance(data, str) and data:
        return data
    if isinstance(data, dict):
        for key in ("Credential", "token", "accessToken", "access_token"):
            value = data.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def probe_login_state() -> dict[str, Any]:
    metadata = SECRET.stat()
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise RecoveryError("webui_secret_permissions_unsafe")
    raw = SECRET.read_text(encoding="utf-8").strip()
    digest = sha256((raw + ".napcat").encode("utf-8")).hexdigest()
    auth_http, auth = request_json("/auth/login", payload={"hash": digest, "totpCode": ""})
    bearer = extract_bearer(auth)
    if auth_http != 200 or not bearer:
        return {"state": "unknown", "webui_reachable": auth_http != 0}

    check_http, check = request_json("/QQLogin/CheckLoginStatus", payload={}, bearer=bearer)
    info_http, info = request_json("/QQLogin/GetQQLoginInfo", payload={}, bearer=bearer)
    check_data = check.get("data") if isinstance(check, dict) else None
    info_data = info.get("data") if isinstance(info, dict) else None
    is_login = check_data.get("isLogin") if isinstance(check_data, dict) else None
    is_offline = check_data.get("isOffline") if isinstance(check_data, dict) else None
    online = info_data.get("online") if isinstance(info_data, dict) else None
    qrcode_available = bool(check_data.get("qrcodeurl")) if isinstance(check_data, dict) else False
    error_class = classify_login_error(check_data.get("loginError")) if isinstance(check_data, dict) else None

    if is_login is True and online is True:
        state = "online"
    elif is_offline is True or online is False:
        state = "offline"
    elif qrcode_available or error_class:
        state = "authentication_required"
    else:
        state = "unknown"
    return {
        "state": state,
        "webui_reachable": check_http == 200 and info_http == 200,
        "qrcode_available": qrcode_available,
        "login_error_class": error_class,
    }


def inspect_container(runner: Runner, name: str) -> dict[str, Any]:
    document = json.loads(runner.run("docker", "inspect", name))[0]
    if not isinstance(document, dict):
        raise RecoveryError("container_inspect_invalid")
    return document


def validate_napcat(document: dict[str, Any]) -> None:
    state = document.get("State") or {}
    health = state.get("Health") or {}
    if state.get("Status") != "running" or health.get("Status") != "healthy":
        raise RecoveryError("napcat_container_not_healthy")
    if state.get("OOMKilled") is not False:
        raise RecoveryError("napcat_container_oom_state_unsafe")
    mounts = {
        str(item.get("Destination"))
        for item in document.get("Mounts") or []
        if isinstance(item, dict) and item.get("Type") == "bind"
    }
    if not REQUIRED_MOUNTS.issubset(mounts):
        raise RecoveryError("napcat_persistent_mounts_missing")


def safe_container_id(document: dict[str, Any]) -> str:
    value = str(document.get("Id") or "")
    if len(value) < 12:
        raise RecoveryError("container_identity_missing")
    return sha256(value.encode("ascii", "ignore")).hexdigest()


def core_pid(runner: Runner) -> str:
    value = runner.run("systemctl", "show", CORE_UNIT, "--property=MainPID", "--value")
    if not value.isdigit() or value == "0":
        raise RecoveryError("core_not_running")
    return value


def atomic_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, 0, 0)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def append_event(document: dict[str, Any]) -> None:
    EVENTS.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    descriptor = os.open(EVENTS, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(descriptor, (json.dumps(document, sort_keys=True) + "\n").encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chown(EVENTS, 0, 0)
    os.chmod(EVENTS, 0o600)


def last_attempt() -> datetime | None:
    if not STATE.exists():
        return None
    try:
        document = json.loads(STATE.read_text(encoding="utf-8"))
        return datetime.fromisoformat(str(document["last_attempt_at"]))
    except Exception:
        raise RecoveryError("recovery_state_invalid") from None


@contextmanager
def exclusive_lock() -> Iterator[None]:
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RecoveryError("recovery_already_running") from None
        yield
    finally:
        os.close(descriptor)


def wait_healthy(runner: Runner, timeout_seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        document = inspect_container(runner, NAPCAT_CONTAINER)
        state = document.get("State") or {}
        health = state.get("Health") or {}
        if state.get("Status") == "running" and health.get("Status") == "healthy":
            validate_napcat(document)
            return document
        time.sleep(1)
    raise RecoveryError("napcat_did_not_become_healthy")


def wait_login(probe: Callable[[], dict[str, Any]], timeout_seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    latest = {"state": "unknown", "webui_reachable": False}
    while time.monotonic() < deadline:
        latest = probe()
        if latest.get("state") in {"online", "authentication_required", "offline"}:
            return latest
        time.sleep(1)
    return latest


def recovery_decision(login: dict[str, Any], execute: bool) -> str:
    if login.get("state") == "online":
        return "already_online"
    return "restart" if execute else "would_restart"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--ignore-cooldown", action="store_true")
    parser.add_argument("--cooldown-minutes", type=int, default=30)
    parser.add_argument("--wait-seconds", type=int, default=60)
    args = parser.parse_args()

    if os.geteuid() != 0:
        raise RecoveryError("root_required")
    if args.cooldown_minutes < 1 or args.wait_seconds < 10:
        raise RecoveryError("invalid_recovery_limits")

    runner = Runner()
    with exclusive_lock():
        napcat_before = inspect_container(runner, NAPCAT_CONTAINER)
        validate_napcat(napcat_before)
        astrbot_before = safe_container_id(inspect_container(runner, ASTRBOT_CONTAINER))
        core_before = core_pid(runner)
        login_before = probe_login_state()
        decision = recovery_decision(login_before, args.execute)
        if decision != "restart":
            print(json.dumps({
                "result": decision,
                "login_state": login_before.get("state"),
                "napcat_restarted": False,
                "persistent_data_changed": False,
                "raw_identifiers_printed": False,
                "secrets_printed": False,
            }, sort_keys=True))
            return 0

        now = datetime.now(timezone.utc)
        previous = last_attempt()
        cooldown = timedelta(minutes=args.cooldown_minutes)
        if previous and now - previous < cooldown and not args.ignore_cooldown:
            raise RecoveryError("recovery_cooldown_active")

        atomic_json(STATE, {
            "schema_version": 1,
            "last_attempt_at": now.isoformat(),
            "cooldown_minutes": args.cooldown_minutes,
        })
        runner.run("docker", "restart", "--timeout", "20", NAPCAT_CONTAINER, timeout=45)
        napcat_after = wait_healthy(runner, args.wait_seconds)
        login_after = wait_login(probe_login_state, min(args.wait_seconds, 30))

        if safe_container_id(napcat_before) != safe_container_id(napcat_after):
            raise RecoveryError("napcat_container_was_recreated")
        if safe_container_id(inspect_container(runner, ASTRBOT_CONTAINER)) != astrbot_before:
            raise RecoveryError("astrbot_container_changed")
        if core_pid(runner) != core_before:
            raise RecoveryError("core_process_changed")

        result = "recovered_online" if login_after.get("state") == "online" else "human_verification_required"
        receipt = {
            "schema_version": 1,
            "operation": "napcat-stuck-login-recovery-v1",
            "attempted_at": now.isoformat(),
            "result": result,
            "before_login_state": login_before.get("state"),
            "after_login_state": login_after.get("state"),
            "qrcode_available": bool(login_after.get("qrcode_available")),
            "login_error_class": login_after.get("login_error_class"),
            "napcat_restarted": True,
            "napcat_recreated": False,
            "persistent_data_changed": False,
            "astrbot_unchanged": True,
            "core_unchanged": True,
            "raw_identifiers_printed": False,
            "secrets_printed": False,
        }
        append_event(receipt)
        print(json.dumps(receipt, sort_keys=True))
        return 0 if result == "recovered_online" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RecoveryError as exc:
        print(json.dumps({
            "result": "failed_closed",
            "reason": str(exc),
            "napcat_restarted": False,
            "persistent_data_changed": False,
            "raw_identifiers_printed": False,
            "secrets_printed": False,
        }, sort_keys=True))
        raise SystemExit(1)
