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


BASE_RELEASE_DIGEST = (
    "cf3f941a13c94bdac2fd94c4159618354fb82899cad36117b92d0c88981dbde5"
)
BACKUP_ROOT = Path("/var/backups/myuna/persistent-session-context-v1")
CORE_SERVICE = "myuna-core@qq.service"
CORE_ENV_PATH = Path("/etc/myuna/qq.env")
CORE_ENV_BASE_SHA256 = (
    "8cba42f5df84853c2e0ad9592b9898fa70fe35d5584f6003a2878e985a921507"
)
CORE_ENV_GROUP = "myuna"
CORE_ENV_KEY = b"MYUNA_DEEPSEEK_MAX_ATTEMPTS="
CORE_EXEC_DROPIN = Path(
    "/etc/systemd/system/myuna-core@qq.service.d/"
    "zzzzzz-session-context-attempt-cap.conf"
)
CORE_BASE_MAX_ATTEMPTS = "2"
CORE_CANDIDATE_MAX_ATTEMPTS = "1"
CHANNELS = {
    "qq": {
        "group": "myuna-gateway",
        "release_root": Path("/opt/myuna/context24-gateway/qq/releases"),
        "runtime": "qq_owner_runtime_gateway.py",
        "service": "myuna-qq-owner-runtime-dev.service",
        "socket": "myuna-qq-owner-runtime-dev.socket",
        "dropin": Path(
            "/etc/systemd/system/myuna-qq-owner-runtime-dev.service.d/"
            "zzzzzz-session-context-v1.conf"
        ),
    },
    "telegram": {
        "group": "myuna-gateway-telegram",
        "release_root": Path(
            "/opt/myuna/context24-gateway/telegram/releases"
        ),
        "runtime": "telegram_owner_runtime_gateway.py",
        "service": "myuna-telegram-owner-runtime-dev.service",
        "socket": "myuna-telegram-owner-runtime-dev.socket",
        "dropin": Path(
            "/etc/systemd/system/myuna-telegram-owner-runtime-dev.service.d/"
            "zzzzzz-session-context-v1.conf"
        ),
    },
}


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_file(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def systemctl(*arguments: str, capture: bool = False) -> str:
    completed = subprocess.run(
        ["systemctl", *arguments],
        check=True,
        capture_output=capture,
        text=True,
    )
    return completed.stdout.strip() if capture else ""


def is_active(unit: str) -> bool:
    completed = subprocess.run(
        ["systemctl", "is-active", "--quiet", unit],
        check=False,
    )
    return completed.returncode == 0


def validate_candidate(candidate: Path) -> tuple[str, dict[str, object]]:
    candidate = candidate.resolve()
    manifest = json.loads(
        (candidate / "MANIFEST.json").read_text(encoding="utf-8")
    )
    if manifest.get("schema") != "myuna-persistent-session-context-release-v1":
        raise RuntimeError("candidate schema mismatch")
    if manifest.get("base_release_digest") != BASE_RELEASE_DIGEST:
        raise RuntimeError("candidate base release mismatch")
    release_digest = manifest.get("release_digest")
    if not isinstance(release_digest, str) or len(release_digest) != 64:
        raise RuntimeError("candidate release digest is invalid")
    if candidate.name != release_digest:
        raise RuntimeError("candidate directory does not match release digest")
    identity = {
        key: value
        for key, value in manifest.items()
        if key not in {"release_digest", "destinations"}
    }
    if digest_bytes(canonical_bytes(identity)) != release_digest:
        raise RuntimeError("candidate release identity mismatch")
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise RuntimeError("candidate file manifest is invalid")
    actual = {
        str(path.relative_to(candidate)).replace("\\", "/"): digest_file(path)
        for path in sorted((candidate / "runtime").rglob("*.py"))
    }
    if actual != files:
        raise RuntimeError("candidate files do not match manifest")
    return release_digest, manifest


def render_dropin(channel: str, release_digest: str) -> bytes:
    spec = CHANNELS[channel]
    release = spec["release_root"] / release_digest
    return (
        "[Service]\n"
        "ExecStart=\n"
        f"ExecStart=/usr/bin/python3 {release}/runtime/{spec['runtime']}\n"
        f"Environment=PYTHONPATH={release}/runtime\n"
        "Environment=MYUNA_SESSION_CONTEXT_STORE=sqlite-v1\n"
    ).encode("utf-8")


def render_core_exec_dropin() -> bytes:
    return (
        "[Service]\n"
        "ExecStart=\n"
        "ExecStart=/usr/bin/env MYUNA_DEEPSEEK_MAX_ATTEMPTS=1 "
        "/usr/bin/python3 -m myuna_core\n"
    ).encode("utf-8")


def _validated_core_environment_baseline() -> bytes:
    metadata = CORE_ENV_PATH.stat()
    if (
        metadata.st_uid != 0
        or metadata.st_gid != grp.getgrnam(CORE_ENV_GROUP).gr_gid
        or metadata.st_mode & 0o777 != 0o640
    ):
        raise RuntimeError("Core environment permissions drifted")
    current = CORE_ENV_PATH.read_bytes()
    if digest_bytes(current) != CORE_ENV_BASE_SHA256:
        raise RuntimeError("Core environment bytes drifted")
    expected = CORE_ENV_KEY + CORE_BASE_MAX_ATTEMPTS.encode("ascii")
    if current.count(CORE_ENV_KEY) != 1 or current.count(expected) != 1:
        raise RuntimeError("Core environment attempt baseline is invalid")
    return current


def _running_environment(unit: str) -> dict[str, str]:
    raw_pid = systemctl("show", "-p", "MainPID", "--value", unit, capture=True)
    if not raw_pid.isdigit() or int(raw_pid) <= 0:
        raise RuntimeError("target service has no running process")
    raw = Path(f"/proc/{raw_pid}/environ").read_bytes()
    result: dict[str, str] = {}
    for entry in raw.split(b"\0"):
        if b"=" not in entry:
            continue
        key, value = entry.split(b"=", 1)
        result[key.decode("utf-8")] = value.decode("utf-8")
    return result


def _effective_core_attempts() -> str:
    return _running_environment(CORE_SERVICE).get(
        "MYUNA_DEEPSEEK_MAX_ATTEMPTS",
        CORE_BASE_MAX_ATTEMPTS,
    )


def _verify_current_baseline() -> None:
    _validated_core_environment_baseline()
    if CORE_EXEC_DROPIN.exists():
        raise RuntimeError("candidate Core ExecStart drop-in already exists")
    if not is_active(CORE_SERVICE):
        raise RuntimeError("target Core service is not active")
    if _effective_core_attempts() != CORE_BASE_MAX_ATTEMPTS:
        raise RuntimeError("Core provider attempts no longer match approved baseline")
    for spec in CHANNELS.values():
        if not is_active(str(spec["socket"])):
            raise RuntimeError("target socket is not active")
        dropin = spec["dropin"]
        if dropin.exists():
            raise RuntimeError("candidate drop-in already exists")
        exec_start = systemctl(
            "show", "-p", "ExecStart", "--value", str(spec["service"]),
            capture=True,
        )
        if BASE_RELEASE_DIGEST not in exec_start:
            raise RuntimeError("live ExecStart no longer matches approved baseline")


def _backup_current_units(release_digest: str) -> Path:
    core_environment = _validated_core_environment_baseline()
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(BACKUP_ROOT, 0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = BACKUP_ROOT / stamp
    backup.mkdir(mode=0o700)
    unit_backup = backup / "systemd"
    unit_backup.mkdir(mode=0o700)
    receipt: dict[str, object] = {
        "schema": "myuna-persistent-session-context-backup-v1",
        "release_digest": release_digest,
        "base_release_digest": BASE_RELEASE_DIGEST,
        "candidate_dropins_preexisting": False,
        "sqlite_preservation_required": True,
        "channels": {},
        "core": {
            "service_active": is_active(CORE_SERVICE),
            "effective_max_attempts": _effective_core_attempts(),
            "environment_sha256": digest_bytes(core_environment),
            "exec_dropin_preexisting": False,
        },
    }
    channels = receipt["channels"]
    assert isinstance(channels, dict)
    for channel, spec in CHANNELS.items():
        service = str(spec["service"])
        dropin_dir = spec["dropin"].parent
        target = unit_backup / channel
        if dropin_dir.is_dir():
            shutil.copytree(dropin_dir, target)
        channels[channel] = {
            "service_active": is_active(service),
            "socket_active": is_active(str(spec["socket"])),
            "exec_start_sha256": digest_bytes(systemctl(
                "show", "-p", "ExecStart", "--value", service,
                capture=True,
            ).encode("utf-8")),
        }
    (backup / "qq.env").write_bytes(core_environment)
    os.chmod(backup / "qq.env", 0o600)
    if CORE_EXEC_DROPIN.parent.is_dir():
        shutil.copytree(CORE_EXEC_DROPIN.parent, unit_backup / "core")
    (backup / "RECEIPT.json").write_bytes(canonical_bytes(receipt) + b"\n")
    os.chmod(backup / "RECEIPT.json", 0o600)
    return backup


def _install_release(candidate: Path, destination: Path, group: str) -> None:
    group_id = grp.getgrnam(group).gr_gid
    if destination.exists():
        candidate_files = {
            str(path.relative_to(candidate)): digest_file(path)
            for path in candidate.rglob("*")
            if path.is_file()
        }
        installed_files = {
            str(path.relative_to(destination)): digest_file(path)
            for path in destination.rglob("*")
            if path.is_file()
        }
        if candidate_files != installed_files:
            raise RuntimeError("installed candidate release has drifted")
        for path in [destination, *destination.rglob("*")]:
            metadata = path.stat()
            expected_mode = 0o550 if path.is_dir() else 0o440
            if (
                metadata.st_uid != 0
                or metadata.st_gid != group_id
                or metadata.st_mode & 0o777 != expected_mode
            ):
                raise RuntimeError("installed candidate release permissions drifted")
        return
    shutil.copytree(candidate, destination)
    for path in [destination, *destination.rglob("*")]:
        os.chown(path, 0, group_id)
        os.chmod(path, 0o550 if path.is_dir() else 0o440)


def _atomic_write(
    path: Path,
    content: bytes,
    *,
    mode: int = 0o644,
    uid: int = 0,
    gid: int = 0,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".session-context-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, uid, gid)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _remove_candidate_dropins(release_digest: str) -> None:
    for channel, spec in CHANNELS.items():
        dropin = spec["dropin"]
        expected = render_dropin(channel, release_digest)
        if dropin.exists():
            if dropin.read_bytes() != expected:
                raise RuntimeError("candidate drop-in drift prevents rollback")
            dropin.unlink()
    if CORE_EXEC_DROPIN.exists():
        if CORE_EXEC_DROPIN.read_bytes() != render_core_exec_dropin():
            raise RuntimeError("candidate Core ExecStart drift prevents rollback")
        CORE_EXEC_DROPIN.unlink()


def _rollback_live(release_digest: str, backup: Path) -> None:
    receipt = json.loads((backup / "RECEIPT.json").read_text(encoding="utf-8"))
    core = receipt.get("core")
    if not isinstance(core, dict):
        raise RuntimeError("rollback receipt Core metadata is invalid")
    if digest_file(CORE_ENV_PATH) != core.get("environment_sha256"):
        raise RuntimeError("Core environment drift prevents rollback")
    _remove_candidate_dropins(release_digest)
    systemctl("daemon-reload")
    systemctl("restart", CORE_SERVICE)
    if not is_active(CORE_SERVICE):
        raise RuntimeError("Core did not recover during rollback")
    if _effective_core_attempts() != CORE_BASE_MAX_ATTEMPTS:
        raise RuntimeError("Core attempt setting did not roll back")
    for spec in CHANNELS.values():
        systemctl("stop", str(spec["service"]))
        if not is_active(str(spec["socket"])):
            raise RuntimeError("socket became inactive during rollback")


def apply(candidate: Path) -> tuple[str, Path]:
    if os.geteuid() != 0:
        raise RuntimeError("activation requires root")
    release_digest, _ = validate_candidate(candidate)
    _verify_current_baseline()
    backup = _backup_current_units(release_digest)
    mutated = False
    try:
        for spec in CHANNELS.values():
            destination = spec["release_root"] / release_digest
            _install_release(candidate, destination, str(spec["group"]))
        for channel, spec in CHANNELS.items():
            _atomic_write(spec["dropin"], render_dropin(channel, release_digest))
            mutated = True
        _atomic_write(CORE_EXEC_DROPIN, render_core_exec_dropin())
        systemctl("daemon-reload")
        systemctl("restart", CORE_SERVICE)
        if not is_active(CORE_SERVICE):
            raise RuntimeError("target Core service is not active after activation")
        if _effective_core_attempts() != CORE_CANDIDATE_MAX_ATTEMPTS:
            raise RuntimeError("target Core attempt cap was not activated")
        for spec in CHANNELS.values():
            systemctl("stop", str(spec["service"]))
        for channel, spec in CHANNELS.items():
            if not is_active(str(spec["socket"])):
                raise RuntimeError("target socket is not active after activation")
            if is_active(str(spec["service"])):
                raise RuntimeError("target service did not enter socket-only state")
            exec_start = systemctl(
                "show", "-p", "ExecStart", "--value", str(spec["service"]),
                capture=True,
            )
            if release_digest not in exec_start:
                raise RuntimeError("activated ExecStart mismatch")
            if spec["dropin"].read_bytes() != render_dropin(channel, release_digest):
                raise RuntimeError("activated drop-in mismatch")
        return release_digest, backup
    except Exception:
        if mutated:
            _rollback_live(release_digest, backup)
        raise


def rollback(candidate: Path, backup: Path) -> str:
    if os.geteuid() != 0:
        raise RuntimeError("rollback requires root")
    release_digest, _ = validate_candidate(candidate)
    receipt = json.loads((backup / "RECEIPT.json").read_text(encoding="utf-8"))
    if receipt.get("release_digest") != release_digest:
        raise RuntimeError("rollback backup does not match candidate")
    _rollback_live(release_digest, backup)
    return release_digest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preflight", "apply", "rollback"))
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--backup", type=Path)
    args = parser.parse_args()
    raise RuntimeError(
        "superseded ExecStart-wrapper executor; use "
        "activate_persistent_session_context_core_source_v1.py"
    )
    release_digest, _ = validate_candidate(args.candidate)
    if args.action == "preflight":
        _verify_current_baseline()
        result = {"status": "ready", "release_digest": release_digest}
    elif args.action == "apply":
        release_digest, backup = apply(args.candidate)
        result = {
            "status": "activated-socket-only",
            "release_digest": release_digest,
            "backup": str(backup),
        }
    else:
        if args.backup is None:
            parser.error("rollback requires --backup")
        release_digest = rollback(args.candidate, args.backup)
        result = {
            "status": "rolled-back-socket-only",
            "release_digest": release_digest,
            "sqlite": "preserved",
        }
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
