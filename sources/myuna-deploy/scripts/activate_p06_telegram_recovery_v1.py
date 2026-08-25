#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from build_p06_telegram_recovery_release_v1 import (
    BASE_RELEASE_DIGEST,
    SCHEMA as RUNTIME_SCHEMA,
    canonical_bytes,
)
from build_telegram_gateway_release_v1 import verify_release as verify_plugin_release
from p07_d_generation13_release_set import phase_f_selected_target


RUNTIME_RELEASE_ROOT = Path(
    "/opt/myuna/context24-gateway/telegram/releases"
)
PLUGIN_RELEASE_ROOT = Path("/opt/myuna/telegram-gateway/releases")
R5_CONFIG = Path("/etc/myuna-telegram-gateway/r5-resume-v1.json")
R5_SERVICE = "myuna-telegram-owner-r5-resume.service"
RUNTIME_SERVICE = "myuna-telegram-owner-runtime-dev.service"
RUNTIME_SOCKET = "myuna-telegram-owner-runtime-dev.socket"
CONTAINER = "myuna-astrbot-telegram-dev"
DROPIN = Path(
    "/etc/systemd/system/myuna-telegram-owner-runtime-dev.service.d/"
    "zzzzzzz-p06-recovery-v1.conf"
)
BACKUP_ROOT = Path("/var/backups/myuna/p06-telegram-recovery-v1")
RECEIPT_ROOT = Path("/var/lib/myuna-telegram-gateway/p06-recovery")
RECEIPT = RECEIPT_ROOT / "LAST_ACTIVATION.json"
RECOVERY_DATABASE = Path(
    "/var/lib/myuna-telegram-gateway/session-context/recovery-episode.db"
)
DIGEST = re.compile(r"^[0-9a-f]{64}$")
R5_SCHEMA = "myuna.telegram.r5-boot-resume-config.v1"


class ActivationRejected(RuntimeError):
    """A bounded P06 activation or rollback invariant was rejected."""


def digest_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def digest_file(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def run(
    arguments: list[str],
    *,
    check: bool = True,
    timeout: int = 300,
) -> str:
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


def _runtime_identity(manifest: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in manifest.items()
        if key not in {"release_digest", "destination"}
    }


def validate_runtime_candidate(candidate: Path) -> tuple[str, dict[str, object]]:
    if candidate.is_symlink():
        raise ActivationRejected("runtime candidate path rejected")
    candidate = candidate.resolve()
    if any(path.is_symlink() for path in candidate.rglob("*")):
        raise ActivationRejected("runtime candidate symlink rejected")
    try:
        manifest = json.loads(
            (candidate / "MANIFEST.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ActivationRejected("runtime candidate rejected") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != RUNTIME_SCHEMA
        or manifest.get("base_release_digest") != BASE_RELEASE_DIGEST
    ):
        raise ActivationRejected("runtime candidate identity rejected")
    digest = manifest.get("release_digest")
    if (
        not isinstance(digest, str)
        or DIGEST.fullmatch(digest) is None
        or candidate.name != digest
        or digest_bytes(canonical_bytes(_runtime_identity(manifest))) != digest
    ):
        raise ActivationRejected("runtime candidate digest rejected")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ActivationRejected("runtime candidate files rejected")
    actual = {
        path.relative_to(candidate).as_posix(): digest_file(path)
        for path in sorted((candidate / "runtime").rglob("*.py"))
    }
    if actual != files:
        raise ActivationRejected("runtime candidate bytes rejected")
    if "runtime/gateway_recovery_episode.py" not in files:
        raise ActivationRejected("runtime recovery module missing")
    return digest, manifest


def validate_plugin_candidate(
    output_root: Path,
    digest: str,
) -> tuple[Path, dict[str, object]]:
    if DIGEST.fullmatch(digest) is None:
        raise ActivationRejected("plugin digest rejected")
    candidate = output_root.resolve() / digest
    manifest_path = output_root.resolve() / f"{digest}.manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ActivationRejected("plugin manifest rejected") from exc
    if (
        manifest.get("release_digest") != digest
        or not verify_plugin_release(output_root.resolve(), manifest)
    ):
        raise ActivationRejected("plugin candidate rejected")
    return candidate, manifest


def render_dropin(runtime_digest: str) -> bytes:
    release = RUNTIME_RELEASE_ROOT / runtime_digest / "runtime"
    return (
        "[Service]\n"
        "ExecStart=\n"
        f"ExecStart=/usr/bin/python3 {release}/telegram_owner_runtime_gateway.py\n"
        f"Environment=PYTHONPATH={release}\n"
        "Environment=MYUNA_SESSION_CONTEXT_STORE=sqlite-v1\n"
    ).encode("utf-8")


def render_r5_config(plugin_digest: str) -> bytes:
    release = PLUGIN_RELEASE_ROOT / plugin_digest
    return canonical_bytes(
        {
            "channel_root": "/srv/myuna/channels/astrbot-telegram/dev",
            "compose_file": (
                release / "channels/astrbot-telegram/compose.dev.yml"
            ).as_posix(),
            "gateway_release": plugin_digest,
            "plugin_root": (
                release
                / "channels/astrbot-telegram/plugin/myuna_telegram_gateway"
            ).as_posix(),
            "schema": R5_SCHEMA,
        }
    ) + b"\n"


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


def _install_tree(
    source: Path,
    destination: Path,
    *,
    group: str,
    directory_mode: int,
    file_mode: int,
) -> None:
    group_id = grp.getgrnam(group).gr_gid
    if destination.exists():
        if _file_inventory(source) != _file_inventory(destination):
            raise ActivationRejected("installed release bytes drifted")
    else:
        shutil.copytree(source, destination)
    for path in (destination, *destination.rglob("*")):
        expected = directory_mode if path.is_dir() else file_mode
        os.chown(path, 0, group_id)
        os.chmod(path, expected)


def _current_plugin_release() -> str:
    try:
        payload = json.loads(R5_CONFIG.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ActivationRejected("current R5 config rejected") from exc
    release = payload.get("gateway_release")
    if (
        not isinstance(release, str)
        or DIGEST.fullmatch(release) is None
        or render_r5_config(release) != R5_CONFIG.read_bytes()
    ):
        raise ActivationRejected("current R5 config drifted")
    return release


def _container_fact(format_value: str) -> str:
    return run(
        [
            "/usr/bin/docker",
            "inspect",
            CONTAINER,
            "--format",
            format_value,
        ]
    )


def _verify_prestate() -> tuple[str, bytes]:
    if DROPIN.exists() or DROPIN.is_symlink():
        raise ActivationRejected("candidate drop-in already exists")
    if not is_active(RUNTIME_SOCKET) or not is_active(RUNTIME_SERVICE):
        raise ActivationRejected("Telegram runtime is not active")
    if not is_active(R5_SERVICE):
        raise ActivationRejected("R5 controller is not ready")
    status = _container_fact("{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}")
    if status != "running|healthy":
        raise ActivationRejected("Telegram container is not healthy")
    exec_start = systemctl(
        "show",
        RUNTIME_SERVICE,
        "-p",
        "ExecStart",
        "--value",
    )
    if BASE_RELEASE_DIGEST not in exec_start:
        raise ActivationRejected("runtime base release drifted")
    current_plugin = _current_plugin_release()
    current_config = R5_CONFIG.read_bytes()
    return current_plugin, current_config


def _backup(
    runtime_digest: str,
    plugin_digest: str,
    current_plugin: str,
    current_config: bytes,
) -> Path:
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(BACKUP_ROOT, 0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = BACKUP_ROOT / stamp
    backup.mkdir(mode=0o700)
    (backup / "r5-resume-v1.json").write_bytes(current_config)
    os.chmod(backup / "r5-resume-v1.json", 0o600)
    receipt = {
        "schema": "myuna.p06-telegram-recovery-backup.v1",
        "runtime_base_release": BASE_RELEASE_DIGEST,
        "previous_plugin_release": current_plugin,
        "candidate_runtime_release": runtime_digest,
        "candidate_plugin_release": plugin_digest,
        "candidate_dropin_preexisting": False,
        "recovery_database_preserved": True,
    }
    (backup / "RECEIPT.json").write_bytes(canonical_bytes(receipt) + b"\n")
    os.chmod(backup / "RECEIPT.json", 0o600)
    return backup


def _verify_poststate(runtime_digest: str, plugin_digest: str) -> None:
    if not is_active(RUNTIME_SOCKET) or not is_active(RUNTIME_SERVICE):
        raise ActivationRejected("runtime poststate rejected")
    if not is_active(R5_SERVICE):
        raise ActivationRejected("R5 poststate rejected")
    deadline = time.monotonic() + 240
    expected_mount = (
        PLUGIN_RELEASE_ROOT
        / plugin_digest
        / "channels/astrbot-telegram/plugin/myuna_telegram_gateway"
    ).as_posix()
    while time.monotonic() < deadline:
        status = _container_fact(
            "{{.State.Status}}|"
            "{{if .State.Health}}{{.State.Health.Status}}{{end}}"
        )
        mounts = _container_fact(
            "{{range .Mounts}}{{if eq .Destination "
            "\"/AstrBot/data/plugins/astrbot_plugin_myuna_telegram_gateway\"}}"
            "{{.Source}}{{end}}{{end}}"
        )
        exec_start = systemctl(
            "show",
            RUNTIME_SERVICE,
            "-p",
            "ExecStart",
            "--value",
        )
        if (
            status == "running|healthy"
            and mounts == expected_mount
            and runtime_digest in exec_start
            and _current_plugin_release() == plugin_digest
        ):
            break
        time.sleep(3)
    else:
        raise ActivationRejected("bounded readiness rejected")
    if not RECOVERY_DATABASE.is_file() or RECOVERY_DATABASE.is_symlink():
        raise ActivationRejected("recovery database missing")
    metadata = RECOVERY_DATABASE.stat()
    service_uid = int(
        run(["/usr/bin/id", "-u", "myuna-gateway-telegram"])
    )
    if metadata.st_uid != service_uid or metadata.st_mode & 0o777 != 0o600:
        raise ActivationRejected("recovery database metadata rejected")


def _rollback(
    *,
    runtime_digest: str,
    current_config: bytes,
) -> None:
    expected = render_dropin(runtime_digest)
    if DROPIN.exists():
        if DROPIN.read_bytes() != expected:
            raise ActivationRejected("drop-in drift prevents rollback")
        DROPIN.unlink()
    _atomic_write(R5_CONFIG, current_config, mode=0o600)
    systemctl("daemon-reload")
    systemctl("restart", RUNTIME_SERVICE)
    systemctl("restart", R5_SERVICE)
    if (
        not is_active(RUNTIME_SERVICE)
        or not is_active(R5_SERVICE)
        or _container_fact("{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}") != "running|healthy"
    ):
        raise ActivationRejected("rollback readiness rejected")


def activate(
    runtime_candidate: Path,
    plugin_output_root: Path,
    plugin_digest: str,
) -> dict[str, object]:
    if os.geteuid() != 0:
        raise ActivationRejected("activation requires root")
    runtime_candidate = runtime_candidate.resolve()
    plugin_output_root = plugin_output_root.resolve()
    runtime_digest, _ = validate_runtime_candidate(runtime_candidate)
    plugin_candidate, _ = validate_plugin_candidate(
        plugin_output_root,
        plugin_digest,
    )
    if phase_f_selected_target(Path(__file__).resolve().parent):
        raise ActivationRejected("phase_f_canonical_owner_required")
    current_plugin, current_config = _verify_prestate()
    backup = _backup(
        runtime_digest,
        plugin_digest,
        current_plugin,
        current_config,
    )
    mutated = False
    try:
        _install_tree(
            runtime_candidate.resolve(),
            RUNTIME_RELEASE_ROOT / runtime_digest,
            group="myuna-gateway-telegram",
            directory_mode=0o550,
            file_mode=0o440,
        )
        _install_tree(
            plugin_candidate,
            PLUGIN_RELEASE_ROOT / plugin_digest,
            group="root",
            directory_mode=0o555,
            file_mode=0o444,
        )
        plugin_manifest_target = (
            PLUGIN_RELEASE_ROOT / f"{plugin_digest}.manifest.json"
        )
        if plugin_manifest_target.exists():
            if plugin_manifest_target.read_bytes() != (
                plugin_output_root / f"{plugin_digest}.manifest.json"
            ).read_bytes():
                raise ActivationRejected("installed plugin manifest drifted")
            metadata = plugin_manifest_target.stat()
            if metadata.st_uid != 0 or metadata.st_mode & 0o777 != 0o444:
                raise ActivationRejected("installed plugin manifest metadata drifted")
        else:
            shutil.copyfile(
                plugin_output_root / f"{plugin_digest}.manifest.json",
                plugin_manifest_target,
            )
            os.chown(plugin_manifest_target, 0, 0)
            os.chmod(plugin_manifest_target, 0o444)
        mutated = True
        _atomic_write(DROPIN, render_dropin(runtime_digest), mode=0o644)
        _atomic_write(R5_CONFIG, render_r5_config(plugin_digest), mode=0o600)
        systemctl("daemon-reload")
        systemctl("restart", RUNTIME_SERVICE)
        systemctl("restart", R5_SERVICE)
        _verify_poststate(runtime_digest, plugin_digest)
        receipt = {
            "schema": "myuna.p06-telegram-recovery-activation.v1",
            "status": "READY_NO_AUDIT",
            "runtime_release": runtime_digest,
            "plugin_release": plugin_digest,
            "previous_plugin_release": current_plugin,
            "backup": backup.name,
            "runtime_service": "active",
            "runtime_socket": "active",
            "container": "running_healthy",
            "recovery_database": "private_ready",
            "real_owner_e2e": False,
        }
        RECEIPT_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
        _atomic_write(RECEIPT, canonical_bytes(receipt) + b"\n", mode=0o600)
    except Exception:
        if mutated:
            _rollback(
                runtime_digest=runtime_digest,
                current_config=current_config,
            )
        raise
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=("verify-candidates", "activate"),
    )
    parser.add_argument("--runtime-candidate", type=Path, required=True)
    parser.add_argument("--plugin-output-root", type=Path, required=True)
    parser.add_argument("--plugin-digest", required=True)
    args = parser.parse_args()
    try:
        runtime_digest, _ = validate_runtime_candidate(args.runtime_candidate)
        validate_plugin_candidate(args.plugin_output_root, args.plugin_digest)
        if args.command == "activate":
            receipt = activate(
                args.runtime_candidate,
                args.plugin_output_root,
                args.plugin_digest,
            )
            result = receipt
        else:
            result = {
                "schema": "myuna.p06-telegram-recovery-candidate-check.v1",
                "status": "VERIFIED",
                "runtime_release": runtime_digest,
                "plugin_release": args.plugin_digest,
            }
    except (ActivationRejected, OSError, subprocess.SubprocessError, ValueError):
        print(json.dumps({"status": "rejected"}, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
