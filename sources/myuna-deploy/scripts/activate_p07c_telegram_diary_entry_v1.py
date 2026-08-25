#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import grp
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time

from p07_d_generation13_release_set import phase_f_selected_target

PREVIOUS_RUNTIME_RELEASE = (
    "ea55dd9dd75c9e644c45449290e99959333b1a9a3f8b4b4479b8da21f27d7044"
)
PREVIOUS_PLUGIN_RELEASE = (
    "6abc41ed3fdf9d27433278c03aac2eb15192f06bacb978eae7c2a7935e57374f"
)
RUNTIME_ROOT = Path("/opt/myuna/context24-gateway/telegram/releases")
PLUGIN_ROOT = Path("/opt/myuna/telegram-gateway/releases")
CONFIG = Path("/etc/myuna-telegram-gateway/r5-resume-v1.json")
DROPIN = Path(
    "/etc/systemd/system/myuna-telegram-owner-runtime-dev.service.d/"
    "zzzzzzzzz-p07c-diary-entry-v1.conf"
)
RUNTIME_SERVICE = "myuna-telegram-owner-runtime-dev.service"
RUNTIME_SOCKET = "myuna-telegram-owner-runtime-dev.socket"
RESUME_CONTROLLER = Path(
    "/opt/myuna/telegram-r5/releases/"
    "06d06baf23e6f97cbfa37e8e6bde12a2fa1d495e7bc0b736239655c05ac57b53/"
    "telegram_r5_boot_resume.py"
)
CONTAINER = "myuna-astrbot-telegram-dev"
BACKUP_ROOT = Path("/var/backups/myuna/p07c-telegram-diary-entry-v1")
STATE_ROOT = Path("/var/lib/myuna-telegram-gateway/p07c-diary-entry-v1")
SCHEMA = "myuna.p07c-telegram-diary-entry-activation.v1"
RUNTIME_SCHEMA = "myuna.p07c-telegram-diary-runtime-repair.v1"
PLUGIN_SCHEMA = "myuna.telegram-gateway-release.v1"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


class ActivationRejected(RuntimeError):
    """The bounded P07-C Telegram entry activation was rejected."""


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"


def digest_file(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def run(arguments: list[str], *, check: bool = True, timeout: int = 420) -> str:
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


def systemctl(*arguments: str) -> str:
    return run(["/usr/bin/systemctl", *arguments])


def active(unit: str) -> bool:
    return subprocess.run(
        ["/usr/bin/systemctl", "is-active", "--quiet", unit],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def atomic_write(path: Path, payload: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
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


def validate_runtime_candidate(candidate: Path, source_commit: str) -> str:
    try:
        manifest = json.loads((candidate / "MANIFEST.json").read_text("ascii"))
        digest = manifest.get("release_digest")
        if (
            manifest.get("schema") != RUNTIME_SCHEMA
            or digest != candidate.name
            or manifest.get("source_deploy_commit") != source_commit
            or _DIGEST.fullmatch(str(digest)) is None
        ):
            raise ActivationRejected("runtime manifest rejected")
        files = manifest.get("files")
        if not isinstance(files, dict) or not files:
            raise ActivationRejected("runtime inventory rejected")
        for relative, expected in files.items():
            path = candidate / relative
            if (
                not isinstance(relative, str)
                or not isinstance(expected, str)
                or path.is_symlink()
                or not path.is_file()
                or digest_file(path) != expected
            ):
                raise ActivationRejected("runtime bytes rejected")
        return str(digest)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ActivationRejected("runtime candidate rejected") from exc


def validate_plugin_candidate(candidate: Path) -> str:
    manifest_path = candidate.parent / f"{candidate.name}.manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text("ascii"))
        digest = manifest.get("release_digest")
        if (
            manifest.get("schema") != PLUGIN_SCHEMA
            or digest != candidate.name
            or _DIGEST.fullmatch(str(digest)) is None
        ):
            raise ActivationRejected("plugin manifest rejected")
        entries = manifest.get("files")
        if not isinstance(entries, list) or not entries:
            raise ActivationRejected("plugin inventory rejected")
        expected_paths = set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise ActivationRejected("plugin inventory rejected")
            relative = entry.get("destination")
            path = candidate / str(relative)
            if (
                not isinstance(relative, str)
                or path.is_symlink()
                or not path.is_file()
                or path.stat().st_size != entry.get("size")
                or digest_file(path) != entry.get("sha256")
            ):
                raise ActivationRejected("plugin bytes rejected")
            expected_paths.add(relative)
        actual_paths = {
            path.relative_to(candidate).as_posix()
            for path in candidate.rglob("*")
            if path.is_file()
        }
        if actual_paths != expected_paths:
            raise ActivationRejected("plugin file set rejected")
        return str(digest)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ActivationRejected("plugin candidate rejected") from exc


def render_config(plugin_digest: str) -> bytes:
    release = PLUGIN_ROOT / plugin_digest
    payload = {
        "channel_root": "/srv/myuna/channels/astrbot-telegram/dev",
        "compose_file": (
            release / "channels/astrbot-telegram/compose.dev.yml"
        ).as_posix(),
        "gateway_release": plugin_digest,
        "plugin_root": (
            release
            / "channels/astrbot-telegram/plugin/myuna_telegram_gateway"
        ).as_posix(),
        "schema": "myuna.telegram.r5-boot-resume-config.v1",
    }
    return canonical_bytes(payload)


def render_dropin(runtime_digest: str) -> bytes:
    runtime = RUNTIME_ROOT / runtime_digest / "runtime"
    return (
        "[Service]\n"
        "ExecStart=\n"
        f"ExecStart=/usr/bin/python3 {runtime}/telegram_owner_runtime_gateway.py\n"
        f"Environment=PYTHONPATH={runtime}\n"
        "Environment=MYUNA_SESSION_CONTEXT_STORE=sqlite-v1\n"
    ).encode("ascii")


def install_runtime(candidate: Path, digest: str) -> None:
    destination = RUNTIME_ROOT / digest
    if destination.exists():
        if destination.is_symlink():
            raise ActivationRejected("installed runtime path rejected")
    else:
        shutil.copytree(candidate, destination)
    group = grp.getgrnam("myuna-gateway-telegram").gr_gid
    for path in (destination, *destination.rglob("*")):
        os.chown(path, 0, group)
        os.chmod(path, 0o550 if path.is_dir() else 0o440)
    validate_runtime_candidate(destination, json.loads((candidate / "MANIFEST.json").read_text("ascii"))["source_deploy_commit"])


def install_plugin(candidate: Path, digest: str) -> None:
    destination = PLUGIN_ROOT / digest
    if destination.exists():
        if destination.is_symlink():
            raise ActivationRejected("installed plugin path rejected")
    else:
        shutil.copytree(candidate, destination)
    candidate_files = {
        path.relative_to(candidate).as_posix(): digest_file(path)
        for path in candidate.rglob("*")
        if path.is_file()
    }
    installed_files = {
        path.relative_to(destination).as_posix(): digest_file(path)
        for path in destination.rglob("*")
        if path.is_file()
    }
    if installed_files != candidate_files:
        raise ActivationRejected("installed plugin release drifted")
    for path in (destination, *destination.rglob("*")):
        os.chown(path, 0, 0)
        os.chmod(path, 0o555 if path.is_dir() else 0o444)


def effective_runtime() -> str:
    return systemctl("show", RUNTIME_SERVICE, "-p", "ExecStart", "--value")


def container_mounts() -> str:
    return run(
        [
            "/usr/bin/docker",
            "inspect",
            CONTAINER,
            "--format",
            "{{range .Mounts}}{{println .Source .Destination}}{{end}}",
        ]
    )


def container_healthy() -> bool:
    return run(
        [
            "/usr/bin/docker",
            "inspect",
            CONTAINER,
            "--format",
            "{{.State.Status}} {{.State.Health.Status}} {{.RestartCount}}",
        ],
        check=False,
    ) == "running healthy 0"


def verify_live(runtime_digest: str, plugin_digest: str) -> None:
    if not all(active(unit) for unit in (RUNTIME_SOCKET, RUNTIME_SERVICE)):
        raise ActivationRejected("Telegram runtime units rejected")
    if f"/{runtime_digest}/runtime/telegram_owner_runtime_gateway.py" not in effective_runtime():
        raise ActivationRejected("effective runtime selection rejected")
    if CONFIG.read_bytes() != render_config(plugin_digest):
        raise ActivationRejected("resume config selection rejected")
    if (
        CONFIG.is_symlink()
        or stat.S_IMODE(CONFIG.stat().st_mode) != 0o600
        or DROPIN.is_symlink()
        or DROPIN.read_bytes() != render_dropin(runtime_digest)
        or stat.S_IMODE(DROPIN.stat().st_mode) != 0o644
    ):
        raise ActivationRejected("selection metadata rejected")
    expected_plugin = (
        PLUGIN_ROOT
        / plugin_digest
        / "channels/astrbot-telegram/plugin/myuna_telegram_gateway"
    ).as_posix()
    if expected_plugin not in container_mounts() or not container_healthy():
        raise ActivationRejected("Telegram plugin container rejected")


def verify_rollback() -> None:
    if DROPIN.exists() or DROPIN.is_symlink():
        raise ActivationRejected("rollback drop-in rejected")
    if not all(active(unit) for unit in (RUNTIME_SOCKET, RUNTIME_SERVICE)):
        raise ActivationRejected("rollback runtime units rejected")
    if (
        f"/{PREVIOUS_RUNTIME_RELEASE}/runtime/telegram_owner_runtime_gateway.py"
        not in effective_runtime()
        or CONFIG.read_bytes() != render_config(PREVIOUS_PLUGIN_RELEASE)
    ):
        raise ActivationRejected("rollback selection rejected")
    expected_plugin = (
        PLUGIN_ROOT
        / PREVIOUS_PLUGIN_RELEASE
        / "channels/astrbot-telegram/plugin/myuna_telegram_gateway"
    ).as_posix()
    if expected_plugin not in container_mounts() or not container_healthy():
        raise ActivationRejected("rollback container rejected")


def run_resume_controller() -> None:
    run(["/usr/bin/python3", str(RESUME_CONTROLLER)], timeout=420)


def backup_prestate(activation_id: str) -> tuple[Path, bytes, bytes | None]:
    backup = BACKUP_ROOT / activation_id
    backup.mkdir(parents=True, mode=0o700)
    os.chmod(BACKUP_ROOT, 0o700)
    config_bytes = CONFIG.read_bytes()
    dropin_bytes = DROPIN.read_bytes() if DROPIN.is_file() else None
    atomic_write(backup / "r5-resume-v1.json", config_bytes, mode=0o600)
    if dropin_bytes is not None:
        atomic_write(backup / "runtime-dropin.conf", dropin_bytes, mode=0o600)
    atomic_write(
        backup / "PRESTATE.json",
        canonical_bytes(
            {
                "config_sha256": sha256(config_bytes).hexdigest(),
                "dropin_preexisting": dropin_bytes is not None,
                "plugin_release": PREVIOUS_PLUGIN_RELEASE,
                "runtime_release": PREVIOUS_RUNTIME_RELEASE,
                "schema": SCHEMA,
            }
        ),
        mode=0o600,
    )
    return backup, config_bytes, dropin_bytes


def restore_prestate(config_bytes: bytes, dropin_bytes: bytes | None) -> None:
    atomic_write(CONFIG, config_bytes, mode=0o600)
    if dropin_bytes is None:
        if DROPIN.exists() and not DROPIN.is_symlink():
            DROPIN.unlink()
    else:
        atomic_write(DROPIN, dropin_bytes, mode=0o644)
    systemctl("daemon-reload")
    systemctl("restart", RUNTIME_SERVICE)
    run_resume_controller()
    verify_rollback()


def activate(
    runtime_candidate: Path,
    plugin_candidate: Path,
    *,
    source_commit: str,
    preflight_only: bool,
) -> dict[str, object]:
    if os.geteuid() != 0:
        raise ActivationRejected("root identity required")
    if _COMMIT.fullmatch(source_commit) is None:
        raise ActivationRejected("source commit rejected")
    runtime_digest = validate_runtime_candidate(runtime_candidate, source_commit)
    plugin_digest = validate_plugin_candidate(plugin_candidate)
    if not all(active(unit) for unit in (RUNTIME_SOCKET, RUNTIME_SERVICE)):
        raise ActivationRejected("Telegram runtime prestate rejected")
    if not container_healthy():
        raise ActivationRejected("Telegram container prestate rejected")
    if DROPIN.exists() or DROPIN.is_symlink():
        raise ActivationRejected("candidate drop-in preexists")
    if CONFIG.read_bytes() != render_config(PREVIOUS_PLUGIN_RELEASE):
        raise ActivationRejected("Telegram plugin prestate drifted")
    if (
        f"/{PREVIOUS_RUNTIME_RELEASE}/runtime/telegram_owner_runtime_gateway.py"
        not in effective_runtime()
    ):
        raise ActivationRejected("Telegram runtime prestate drifted")
    previous_plugin_path = (
        PLUGIN_ROOT
        / PREVIOUS_PLUGIN_RELEASE
        / "channels/astrbot-telegram/plugin/myuna_telegram_gateway"
    ).as_posix()
    if previous_plugin_path not in container_mounts():
        raise ActivationRejected("Telegram container prestate drifted")
    if preflight_only:
        return {
            "plugin_release": plugin_digest,
            "runtime_release": runtime_digest,
            "status": "ready",
        }
    if phase_f_selected_target(Path(__file__).resolve().parent):
        raise ActivationRejected("phase_f_canonical_owner_required")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    activation_id = f"{stamp}-{runtime_digest[:12]}-{plugin_digest[:12]}"
    backup, config_bytes, dropin_bytes = backup_prestate(activation_id)
    STATE_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STATE_ROOT, 0o700)
    journal = STATE_ROOT / f"JOURNAL-{activation_id}.json"
    receipt = STATE_ROOT / f"RECEIPT-{activation_id}.json"
    atomic_write(
        journal,
        canonical_bytes(
            {
                "activation_id": activation_id,
                "profile_content_recorded": False,
                "raw_identity_recorded": False,
                "raw_message_recorded": False,
                "schema": SCHEMA,
                "status": "activating",
            }
        ),
        mode=0o600,
    )
    try:
        install_runtime(runtime_candidate, runtime_digest)
        install_plugin(plugin_candidate, plugin_digest)
        atomic_write(CONFIG, render_config(plugin_digest), mode=0o600)
        atomic_write(DROPIN, render_dropin(runtime_digest), mode=0o644)
        systemctl("daemon-reload")
        systemctl("restart", RUNTIME_SERVICE)
        run_resume_controller()
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                verify_live(runtime_digest, plugin_digest)
                break
            except ActivationRejected:
                time.sleep(2)
        else:
            raise ActivationRejected("post-activation health timeout")
        payload = {
            "activation_id": activation_id,
            "backup": backup.name,
            "model_called": False,
            "plugin_release": plugin_digest,
            "profile_content_recorded": False,
            "raw_identity_recorded": False,
            "raw_message_recorded": False,
            "runtime_release": runtime_digest,
            "schema": SCHEMA,
            "source_commit": source_commit,
            "status": "ACTIVE_WAITING_OWNER_DIARY_E2E",
        }
        atomic_write(receipt, canonical_bytes(payload), mode=0o600)
        atomic_write(journal, canonical_bytes(payload), mode=0o600)
        return payload
    except Exception:
        restore_prestate(config_bytes, dropin_bytes)
        atomic_write(
            journal,
            canonical_bytes(
                {
                    "activation_id": activation_id,
                    "model_called": False,
                    "rollback": "verified",
                    "schema": SCHEMA,
                    "status": "rolled_back",
                }
            ),
            mode=0o600,
        )
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-candidate", required=True, type=Path)
    parser.add_argument("--plugin-candidate", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    try:
        result = activate(
            args.runtime_candidate.resolve(),
            args.plugin_candidate.resolve(),
            source_commit=args.source_commit,
            preflight_only=args.preflight_only,
        )
    except ActivationRejected as exc:
        print(
            json.dumps(
                {"error": str(exc), "status": "rejected"},
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
