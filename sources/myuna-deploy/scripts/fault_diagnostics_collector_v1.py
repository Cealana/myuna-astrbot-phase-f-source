"""Allowlisted local metadata collector for the P16 Owner entry."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from typing import Callable, Mapping

from fault_diagnostics_v1 import SNAPSHOT_SCHEMA
from fault_incident_v1 import validate_incident_ref


BASELINE_SCHEMA = "myuna.diagnostics.baseline.v1"
RECEIPT_SCHEMA = "myuna.fault-incident-receipt.v1"
BASELINE_PATH = Path("/etc/myuna-diagnostics/baseline.json")
MAX_SAFE_FILE_BYTES = 128 * 1024
MAX_RECEIPT_AGE = timedelta(minutes=30)
_CHANNELS = frozenset({"all", "qq", "telegram"})
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_RELEASE_PATH = re.compile(r"^/(?:srv|opt)/[A-Za-z0-9_./@-]{1,511}$")
_SYSTEMCTL_FIELDS = frozenset(
    {"ActiveState", "ExecStart", "NRestarts", "SubState", "WorkingDirectory"}
)
_BASELINE_FIELDS = frozenset(
    {
        "schema",
        "core_working_directory",
        "qq_exec_path",
        "telegram_exec_path",
        "session_capacity_messages",
        "session_capacity_characters",
        "safe_unit_digests",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "schema",
        "observed_at",
        "channel",
        "incident_ref",
        "projection_source",
        "category",
        "retryable",
        "owner_action_required",
        "safe_detail_code",
        "recovery_state",
        "fingerprint",
        "private_content_written",
        "raw_payload_written",
    }
)

_UNITS = {
    "core": ("myuna-core@qq.service", None),
    "local_provider": ("myuna-local-provider-v1.service", None),
    "profile_reader": (
        "myuna-owner-profile-read-v1.service",
        "myuna-owner-profile-read-v1.socket",
    ),
    "profile_writer": (
        "myuna-owner-profile-write-v1.service",
        "myuna-owner-profile-write-v1.socket",
    ),
    "qq_gateway": (
        "myuna-qq-owner-runtime-dev.service",
        "myuna-qq-owner-runtime-dev.socket",
    ),
    "telegram_gateway": (
        "myuna-telegram-owner-runtime-dev.service",
        "myuna-telegram-owner-runtime-dev.socket",
    ),
    "temporal_context": (
        "myuna-active-temporal-context-v1.service",
        "myuna-active-temporal-context-v1.socket",
    ),
}
_SESSION_FILES = {
    "qq_session": Path("/var/lib/myuna-gateway/session-context/context.db"),
    "telegram_session": Path(
        "/var/lib/myuna-telegram-gateway/session-context/context.db"
    ),
}
_RECEIPT_FILES = {
    "qq": Path("/run/myuna-fault-diagnostics/qq/last.json"),
    "telegram": Path("/run/myuna-fault-diagnostics/telegram/last.json"),
}
_SAFE_UNIT_FILES = {
    "core_selector": Path(
        "/etc/systemd/system/myuna-core@qq.service.d/10-core-release-selector-v1.conf"
    ),
    "qq_unit": Path("/etc/systemd/system/myuna-qq-owner-runtime-dev.service"),
    "qq_selector": Path(
        "/etc/systemd/system/myuna-qq-owner-runtime-dev.service.d/"
        "zzzzzzzzzz-p16-diagnostics-v1.conf"
    ),
    "telegram_selector": Path(
        "/etc/systemd/system/myuna-telegram-owner-runtime-dev.service.d/"
        "zzzzzzzzzz-p16-diagnostics-v1.conf"
    ),
}
_DETAIL_TO_FAULT = {
    "provider-transport-failure": ("provider", "provider_unavailable"),
    "provider-rate-limited": ("provider", "provider_unavailable"),
    "provider-upstream-failure": ("provider", "provider_unavailable"),
    "provider-invalid-response": ("provider", "provider_unavailable"),
    "provider-request-rejected": ("provider", "provider_unavailable"),
    "provider-authentication-failed": ("provider", "provider_auth_failed"),
    "provider-insufficient-balance": ("provider", "provider_auth_failed"),
    "provider-daily-budget-exceeded": ("deepseek_budget", "budget_exceeded"),
    "provider-budget-accounting-failed": (
        "deepseek_budget",
        "budget_accounting_failed",
    ),
    "local-provider-timeout": ("local_provider", "local_provider_timeout"),
    "local-provider-busy": ("local_provider", "local_provider_busy"),
    "local-model-not-ready": ("local_provider", "local_model_not_ready"),
    "local-provider-unavailable": (
        "local_provider",
        "local_provider_unavailable",
    ),
    "local-provider-http-rejected": (
        "local_provider",
        "local_provider_http_rejected",
    ),
    "local-provider-endpoint-rejected": (
        "local_provider",
        "local_provider_endpoint_rejected",
    ),
    "owner-memory-read-failed": ("profile_reader", "profile_read_unavailable"),
    "reply-runtime-guard-rejected": ("core", "core_runtime_fail_closed"),
    "core-runtime-not-ready": ("core", "core_runtime_not_ready"),
    "core-runtime-fail-closed": ("core", "core_runtime_fail_closed"),
    "gateway-temporal-unavailable": (
        "temporal_context",
        "temporal_context_unavailable",
    ),
}

SystemctlReader = Callable[[str, float], Mapping[str, str] | None]


def _rooted(root: Path, absolute: Path) -> Path:
    if root == Path("/"):
        return absolute
    return root / str(absolute).lstrip("/")


def _read_bounded_regular(path: Path) -> bytes:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or path.is_symlink():
        raise ValueError("safe metadata path is invalid")
    if before.st_size <= 0 or before.st_size > MAX_SAFE_FILE_BYTES:
        raise ValueError("safe metadata size is invalid")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError("safe metadata path is invalid")
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("safe metadata path changed")
        payload = handle.read(MAX_SAFE_FILE_BYTES + 1)
    if len(payload) > MAX_SAFE_FILE_BYTES:
        raise ValueError("safe metadata size is invalid")
    return payload


def _systemctl_show(unit: str, timeout_seconds: float) -> Mapping[str, str] | None:
    if unit not in {item for pair in _UNITS.values() for item in pair if item}:
        raise ValueError("systemd unit is not allowlisted")
    try:
        properties = ["ActiveState", "SubState"]
        if not unit.endswith(".socket"):
            properties.extend(["NRestarts", "ExecStart", "WorkingDirectory"])
        command = ["/usr/bin/systemctl", "show", unit]
        command.extend(f"--property={field}" for field in properties)
        command.append("--no-pager")
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=max(0.05, timeout_seconds),
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or len(result.stdout) > 32 * 1024:
        return None
    try:
        lines = result.stdout.decode("ascii").splitlines()
    except UnicodeError:
        return None
    fields: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator or key not in _SYSTEMCTL_FIELDS or key in fields:
            return None
        fields[key] = value
    expected = {"ActiveState", "SubState"}
    if not unit.endswith(".socket"):
        expected = set(_SYSTEMCTL_FIELDS)
    return fields if set(fields) == expected else None


def _load_baseline(path: Path) -> dict[str, object]:
    payload = json.loads(_read_bounded_regular(path).decode("utf-8"))
    if not isinstance(payload, dict) or set(payload) != _BASELINE_FIELDS:
        raise ValueError("diagnostic baseline is invalid")
    if payload.get("schema") != BASELINE_SCHEMA:
        raise ValueError("diagnostic baseline is invalid")
    for key in ("core_working_directory", "qq_exec_path", "telegram_exec_path"):
        value = payload.get(key)
        if not isinstance(value, str) or _RELEASE_PATH.fullmatch(value) is None:
            raise ValueError("diagnostic baseline is invalid")
    if payload.get("session_capacity_messages") != 128:
        raise ValueError("diagnostic baseline is invalid")
    if payload.get("session_capacity_characters") != 131_072:
        raise ValueError("diagnostic baseline is invalid")
    digests = payload.get("safe_unit_digests")
    if not isinstance(digests, dict) or set(digests) != set(_SAFE_UNIT_FILES):
        raise ValueError("diagnostic baseline is invalid")
    if any(
        not isinstance(value, str) or _HEX64.fullmatch(value) is None
        for value in digests.values()
    ):
        raise ValueError("diagnostic baseline is invalid")
    return payload


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("fault receipt timestamp is invalid")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("fault receipt timestamp is invalid")
    return parsed.astimezone(timezone.utc)


def _load_receipt(path: Path, *, expected_channel: str) -> dict[str, object]:
    payload = json.loads(_read_bounded_regular(path).decode("ascii"))
    if not isinstance(payload, dict) or set(payload) != _RECEIPT_FIELDS:
        raise ValueError("fault receipt is invalid")
    if payload.get("schema") != RECEIPT_SCHEMA or payload.get("channel") != expected_channel:
        raise ValueError("fault receipt is invalid")
    validate_incident_ref(payload.get("incident_ref"))
    if payload.get("private_content_written") is not False:
        raise ValueError("fault receipt is invalid")
    if payload.get("raw_payload_written") is not False:
        raise ValueError("fault receipt is invalid")
    if type(payload.get("retryable")) is not bool:
        raise ValueError("fault receipt is invalid")
    if type(payload.get("owner_action_required")) is not bool:
        raise ValueError("fault receipt is invalid")
    detail = payload.get("safe_detail_code")
    if not isinstance(detail, str) or not 1 <= len(detail) <= 128:
        raise ValueError("fault receipt is invalid")
    _parse_time(payload.get("observed_at"))
    return payload


def _has_local_listener(root: Path) -> bool:
    path = _rooted(root, Path("/proc/net/tcp"))
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or path.is_symlink():
            return False
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            text = handle.read(MAX_SAFE_FILE_BYTES + 1).decode("ascii")
        if len(text) > MAX_SAFE_FILE_BYTES:
            return False
    except (OSError, UnicodeError, ValueError):
        return False
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 4 and fields[1] == "0100007F:036F" and fields[3] == "0A":
            return True
    return False


def _digest(path: Path) -> str:
    return sha256(_read_bounded_regular(path)).hexdigest()


def collect_diagnostic_snapshot(
    channel: str,
    *,
    timeout_seconds: float = 2.0,
    now: datetime | None = None,
    root: Path = Path("/"),
    systemctl_reader: SystemctlReader = _systemctl_show,
) -> dict[str, object]:
    if channel not in _CHANNELS:
        raise ValueError("diagnostic channel is invalid")
    if not isinstance(timeout_seconds, (int, float)) or not 0.5 <= timeout_seconds <= 2.0:
        raise ValueError("diagnostic timeout is invalid")
    observed = now or datetime.now(timezone.utc)
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise ValueError("diagnostic time is invalid")
    observed = observed.astimezone(timezone.utc)
    deadline = time.monotonic() + float(timeout_seconds)
    observations: dict[tuple[str, str], dict[str, str]] = {}
    unit_state: dict[str, Mapping[str, str] | None] = {}

    def add(target: str, code: str, evidence: str = "verified_live") -> None:
        observations[(target, code)] = {
            "target": target,
            "code": code,
            "evidence_class": evidence,
        }

    selected_targets = {"core", "local_provider", "profile_reader", "profile_writer"}
    if channel in {"all", "qq"}:
        selected_targets.add("qq_gateway")
    if channel in {"all", "telegram"}:
        selected_targets.add("telegram_gateway")
        selected_targets.add("temporal_context")
    for target in sorted(selected_targets):
        service, socket_unit = _UNITS[target]
        for unit in (service, socket_unit):
            if unit is None:
                continue
            remaining = deadline - time.monotonic()
            state = (
                systemctl_reader(unit, min(0.15, remaining))
                if remaining > 0
                else None
            )
            unit_state[unit] = state
            if state is None:
                add(target, "unknown_insufficient_safe_evidence", "unknown")
            elif unit == service:
                if target == "temporal_context":
                    active_code = (
                        "active"
                        if state.get("ActiveState") == "active"
                        else "temporal_service_inactive"
                    )
                else:
                    active_code = (
                        "active"
                        if state.get("ActiveState") == "active"
                        else "service_inactive"
                    )
                add(target, active_code)
            else:
                listening = state.get("ActiveState") == "active"
                listening = listening and state.get("SubState") in {
                    "listening",
                    "running",
                }
                if target == "temporal_context":
                    add(
                        target,
                        "listening" if listening else "temporal_socket_inactive",
                    )
                else:
                    add(target, "listening" if listening else "socket_inactive")

    if _has_local_listener(root):
        add("local_provider", "listening")
        add("local_provider", "local_model_readiness_unverified", "unknown")
    else:
        add("local_provider", "unknown_insufficient_safe_evidence", "unknown")

    baseline: dict[str, object] | None = None
    try:
        baseline = _load_baseline(_rooted(root, BASELINE_PATH))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        add("release", "unknown_insufficient_safe_evidence", "unknown")

    selected_sessions: list[str] = []
    if channel in {"all", "qq"}:
        selected_sessions.append("qq_session")
    if channel in {"all", "telegram"}:
        selected_sessions.append("telegram_session")
    for target in selected_sessions:
        path = _rooted(root, _SESSION_FILES[target])
        try:
            metadata = path.lstat()
            secure = stat.S_ISREG(metadata.st_mode) and not path.is_symlink()
            secure = secure and stat.S_IMODE(metadata.st_mode) == 0o600
        except OSError:
            secure = False
        add(target, "secure" if secure else "session_unavailable")
        if baseline is not None:
            add(target, "session_capacity_128", "source_only")
        else:
            add(target, "unknown_insufficient_safe_evidence", "unknown")

    if baseline is not None:
        drift = False
        core_state = unit_state.get(_UNITS["core"][0])
        qq_state = unit_state.get(_UNITS["qq_gateway"][0])
        telegram_state = unit_state.get(_UNITS["telegram_gateway"][0])
        if core_state is not None:
            drift |= core_state.get("WorkingDirectory") != baseline["core_working_directory"]
        if qq_state is not None:
            drift |= str(baseline["qq_exec_path"]) not in qq_state.get("ExecStart", "")
        if telegram_state is not None:
            drift |= str(baseline["telegram_exec_path"]) not in telegram_state.get("ExecStart", "")
        for key, fixed_path in _SAFE_UNIT_FILES.items():
            try:
                drift |= _digest(_rooted(root, fixed_path)) != baseline["safe_unit_digests"][key]
            except (OSError, ValueError):
                drift = True
        add("release", "release_drift" if drift else "match")

    latest: tuple[datetime, dict[str, object]] | None = None
    selected_channels = ("qq", "telegram") if channel == "all" else (channel,)
    for receipt_channel in selected_channels:
        try:
            receipt = _load_receipt(
                _rooted(root, _RECEIPT_FILES[receipt_channel]),
                expected_channel=receipt_channel,
            )
            receipt_time = _parse_time(receipt["observed_at"])
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            continue
        age = observed - receipt_time
        if timedelta(0) <= age <= MAX_RECEIPT_AGE:
            if latest is None or receipt_time > latest[0]:
                latest = (receipt_time, receipt)

    incident_ref: str | None = None
    if latest is not None:
        receipt = latest[1]
        incident_ref = str(receipt["incident_ref"])
        detail = str(receipt["safe_detail_code"])
        receipt_channel = str(receipt["channel"])
        target_code = _DETAIL_TO_FAULT.get(detail)
        if detail == "gateway-core-unreachable":
            target_code = (f"{receipt_channel}_gateway", "core_unreachable")
        elif detail == "gateway-core-invalid-response":
            target_code = (f"{receipt_channel}_gateway", "core_invalid_response")
        elif detail == "gateway-owner-duplicate-suppressed":
            target_code = (f"{receipt_channel}_gateway", "duplicate_suppressed")
        elif detail == "gateway-owner-rate-limited":
            target_code = (f"{receipt_channel}_gateway", "rate_limited")
        if target_code is None:
            target_code = (
                f"{receipt_channel}_gateway",
                "unknown_insufficient_safe_evidence",
            )
        add(target_code[0], target_code[1])

    return {
        "schema": SNAPSHOT_SCHEMA,
        "observed_at": observed.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "channel": channel,
        "incident_ref": incident_ref,
        "observations": [observations[key] for key in sorted(observations)],
    }
