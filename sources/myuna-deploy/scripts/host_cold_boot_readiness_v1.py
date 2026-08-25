#!/usr/bin/env python3
"""No-audit readiness gate for the Myuna host cold-boot chain."""

from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import time


SCHEMA = "myuna.host-cold-boot-readiness.v1"
READY = "HOST_COLD_BOOT_READY_NO_AUDIT"
NOT_READY = "HOST_COLD_BOOT_NOT_READY_NO_AUDIT"
TIMEOUT_SECONDS = 360
POLL_SECONDS = 5
R5_RECEIPT = Path("/var/lib/myuna-telegram-gateway/r5-resume/LAST_SUCCESS.json")
ARCHIVE_PREFIX = "myuna-astrbot-telegram-dev.pre-"
ALLOWED_FAILED_UNITS = ("user-runtime-dir@999.service",)

REQUIRED_UNITS = (
    "docker.service",
    "postgresql.service",
    "minecraft.service",
    "minecraft-backup.timer",
    "sakurafrp-minecraft.service",
    "myuna-core@qq.service",
    "myuna-telegram-owner-r5-resume.service",
    "myuna-telegram-owner-runtime-dev.service",
    "myuna-telegram-owner-runtime-dev.socket",
    "myuna-telegram-media-auth-shadow-v1.socket",
)

ISOLATED_UNITS = (
    "myuna-telegram-owner-challenge-dev.service",
    "myuna-telegram-owner-challenge-dev.socket",
    "myuna-telegram-vision-auth-v1.socket",
)

EXPECTED_CONTAINERS = {
    "myuna-astrbot-dev": (
        "running|healthy|myuna-astrbot-qq-dev|astrbot|unless-stopped|0"
    ),
    "myuna-napcat-dev": (
        "running|healthy|myuna-astrbot-qq-dev|napcat|unless-stopped|0"
    ),
    "myuna-astrbot-telegram-dev": (
        "running|healthy|myuna-telegram-r5-v1|astrbot-telegram|on-failure|3"
    ),
    "sakurafrp-minecraft": "running|none|||no|0",
}


def canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ) + "\n"


def run(args: list[str], *, timeout: int = 15) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
        check=False,
        shell=False,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )


def unit_state(unit: str) -> str:
    result = run(["/usr/bin/systemctl", "is-active", unit])
    value = result.stdout.strip()
    return value if value in {"active", "activating", "inactive", "failed"} else "unknown"


def system_state() -> str:
    result = run(["/usr/bin/systemctl", "is-system-running"])
    state = result.stdout.strip()
    if state == "running":
        return "running"
    if state != "degraded":
        return "not-ready"
    failed = run(
        [
            "/usr/bin/systemctl",
            "--failed",
            "--no-legend",
            "--plain",
        ]
    )
    if failed.returncode not in {0, 1}:
        return "not-ready"
    names = {
        line.split()[0]
        for line in failed.stdout.splitlines()
        if line.split()
    }
    return (
        "degraded-allowlisted"
        if names and names.issubset(ALLOWED_FAILED_UNITS)
        else "not-ready"
    )


def container_state(name: str) -> str:
    result = run(
        [
            "/usr/bin/docker",
            "inspect",
            "-f",
            (
                "{{.State.Status}}|"
                "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|"
                "{{with .Config.Labels}}"
                "{{index . \"com.docker.compose.project\"}}{{end}}|"
                "{{with .Config.Labels}}"
                "{{index . \"com.docker.compose.service\"}}{{end}}|"
                "{{.HostConfig.RestartPolicy.Name}}|"
                "{{.HostConfig.RestartPolicy.MaximumRetryCount}}"
            ),
            name,
        ]
    )
    return result.stdout.strip() if result.returncode == 0 else "absent"


def archives_ready() -> tuple[bool, int]:
    result = run(
        [
            "/usr/bin/docker",
            "ps",
            "-a",
            "--filter",
            f"name=^/{ARCHIVE_PREFIX}",
            "--format",
            "{{.Names}}",
        ]
    )
    if result.returncode != 0:
        return False, 0
    names = tuple(line for line in result.stdout.splitlines() if line)
    for name in names:
        if not name.startswith(ARCHIVE_PREFIX):
            return False, len(names)
        state = run(
            [
                "/usr/bin/docker",
                "inspect",
                "-f",
                "{{.State.Status}}|{{.HostConfig.RestartPolicy.Name}}",
                name,
            ]
        )
        if state.returncode != 0 or state.stdout.strip() != "exited|no":
            return False, len(names)
    return True, len(names)


def network_ready() -> dict[str, bool]:
    route = run(["/usr/sbin/ip", "route", "show", "default"], timeout=5)
    dns = run(["/usr/bin/getent", "ahostsv4", "www.microsoft.com"], timeout=5)
    return {
        "default_route": route.returncode == 0 and bool(route.stdout.strip()),
        "dns": dns.returncode == 0 and bool(dns.stdout.strip()),
    }


def receipt_ready(path: Path = R5_RECEIPT) -> bool:
    try:
        service = pwd.getpwnam("myuna-gateway-telegram")
        if path.is_symlink() or not path.is_file():
            return False
        metadata = path.stat()
        if (
            stat.S_IMODE(metadata.st_mode) != 0o440
            or metadata.st_uid != service.pw_uid
            or metadata.st_gid != service.pw_gid
        ):
            return False
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (KeyError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return (
        payload.get("schema") == "myuna.telegram.r5-boot-resume-receipt.v2"
        and payload.get("status") == "TELEGRAM_R5_RESUME_READY_NO_AUDIT"
        and payload.get("compose_project") == "myuna-telegram-r5-v1"
        and payload.get("core_http_health_called") is False
        and payload.get("message_model_memory_tool_calls") is False
    )


def collect() -> dict[str, object]:
    current_system_state = system_state()
    units = {unit: unit_state(unit) for unit in REQUIRED_UNITS}
    isolated = {unit: unit_state(unit) for unit in ISOLATED_UNITS}
    containers = {
        name: container_state(name) for name in EXPECTED_CONTAINERS
    }
    archive_ok, archive_count = archives_ready()
    network = network_ready()
    ready = (
        current_system_state in {"running", "degraded-allowlisted"}
        and all(value == "active" for value in units.values())
        and all(value == "inactive" for value in isolated.values())
        and all(
            containers[name] == expected
            for name, expected in EXPECTED_CONTAINERS.items()
        )
        and archive_ok
        and archive_count >= 1
        and all(network.values())
        and receipt_ready()
    )
    return {
        "archive_count": archive_count,
        "archives": archive_ok,
        "containers": containers,
        "isolated_units": isolated,
        "network": network,
        "ready": ready,
        "systemd": current_system_state,
        "units": units,
    }


def main() -> int:
    started = time.monotonic()
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    last: dict[str, object] = {"ready": False}
    deadline = started + TIMEOUT_SECONDS
    try:
        while True:
            last = collect()
            if last["ready"] or time.monotonic() >= deadline:
                break
            time.sleep(POLL_SECONDS)
    except Exception:
        last = {"inspection": "error", "ready": False}
    payload = {
        **last,
        "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "core_http_health_called": False,
        "elapsed_seconds": int(time.monotonic() - started),
        "message_model_memory_tool_calls": False,
        "real_e2e": False,
        "schema": SCHEMA,
        "started_at": started_at,
        "status": READY if last.get("ready") else NOT_READY,
    }
    print(canonical(payload), end="")
    return 0 if last.get("ready") else 1


if __name__ == "__main__":
    raise SystemExit(main())
