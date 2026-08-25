#!/usr/bin/env python3
"""Activate the exact P07 Qwen3 1.7B local-provider model release."""

from __future__ import annotations

import argparse
import grp
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

from core_release_selector import canonical_json_bytes


LOCAL_SERVICE = "myuna-local-provider-v1.service"
CORE_SERVICE = "myuna-core@qq.service"
QQ_SOCKET = "myuna-qq-owner-runtime-dev.socket"
QQ_SERVICE = "myuna-qq-owner-runtime-dev.service"
TELEGRAM_SOCKET = "myuna-telegram-owner-runtime-dev.socket"
TELEGRAM_SERVICE = "myuna-telegram-owner-runtime-dev.service"
GATEWAY_UNITS = (QQ_SOCKET, QQ_SERVICE, TELEGRAM_SOCKET, TELEGRAM_SERVICE)
LIVE_UNIT = Path("/etc/systemd/system/myuna-local-provider-v1.service")
CURRENT_UNIT_SHA256 = "21c4034fdba31f99eb74d904800e9ea582fab6c407dc2dd81886f6b454b421e3"
CURRENT_MODEL_SHA256 = "7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5"
CURRENT_MODEL_BYTES = 2_497_280_256
CURRENT_MODEL_PATH = Path(
    "/var/lib/myuna-local-provider-v1/models/"
    "qwen3-4b-q4-k-m-7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5/"
    "model.gguf"
)
TARGET_MODEL_REPOSITORY = "ggml-org/Qwen3-1.7B-GGUF"
TARGET_MODEL_REVISION = "daeb8e2d528a760970442092f6bf1e55c3b659eb"
TARGET_MODEL_FILENAME = "Qwen3-1.7B-Q4_K_M.gguf"
TARGET_MODEL_SHA256 = "d2387ca2dbfee2ffabce7120d3770dadca0b293052bc2f0e138fdc940d9bc7b5"
TARGET_MODEL_BYTES = 1_282_439_264
TARGET_MODEL_ROOT = Path(
    "/var/lib/myuna-local-provider-v1/models/"
    "qwen3-1-7b-q4-k-m-d2387ca2dbfee2ffabce7120d3770dadca0b293052bc2f0e138fdc940d9bc7b5"
)
TARGET_MODEL_PATH = TARGET_MODEL_ROOT / "model.gguf"
ROOT = Path(__file__).resolve().parents[1]
TARGET_UNIT_SOURCE = ROOT / "systemd/myuna-local-provider-qwen3-1_7b-v1.service"
BACKUP_ROOT = Path("/var/backups/myuna/p07-local-provider-1-7b-v1")
RECEIPT_ROOT = Path("/var/lib/myuna/local-provider-selector/p07-1-7b-v1")
RECEIPT = RECEIPT_ROOT / "LAST_ACTIVATION.json"
SCHEMA = "myuna.p07-local-provider-1-7b-activation.v1"


class ActivationRejected(RuntimeError):
    """Content-free bounded activation rejection."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ActivationRejected(code)


def digest_bytes(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def digest_file(path: Path) -> str:
    try:
        digest = sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as exc:
        raise ActivationRejected("file_unavailable") from exc


def systemctl(*arguments: str, check: bool = True) -> str:
    try:
        result = subprocess.run(
            ["/usr/bin/systemctl", *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ActivationRejected("systemd_unavailable") from exc
    if check and result.returncode != 0:
        raise ActivationRejected("systemd_command_failed")
    return result.stdout.strip()


def active(unit: str) -> bool:
    try:
        result = subprocess.run(
            ["/usr/bin/systemctl", "is-active", "--quiet", unit],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ActivationRejected("systemd_unavailable") from exc
    return result.returncode == 0


def show(unit: str, property_name: str) -> str:
    return systemctl("show", "-p", property_name, "--value", unit)


def target_unit_bytes() -> bytes:
    try:
        payload = TARGET_UNIT_SOURCE.read_bytes()
    except OSError as exc:
        raise ActivationRejected("unit_source_unavailable") from exc
    require(payload.count(TARGET_MODEL_PATH.as_posix().encode()) == 1, "unit_model_rejected")
    require(CURRENT_MODEL_PATH.as_posix().encode() not in payload, "unit_prestate_leaked")
    require(b"--host 127.0.0.1 --port 879" in payload, "unit_listener_rejected")
    require(b"--offline" in payload and b"--log-disable" in payload, "unit_boundary_rejected")
    return payload


def verify_model_file(path: Path, *, expected_size: int, expected_sha256: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ActivationRejected("model_unavailable") from exc
    require(not path.is_symlink() and path.is_file(), "model_type_rejected")
    require(metadata.st_size == expected_size, "model_size_rejected")
    require(digest_file(path) == expected_sha256, "model_digest_rejected")


def plan_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "schema": SCHEMA,
            "status": "standing_authority",
            "executor_sha256": digest_file(Path(__file__).resolve()),
            "prestate": {
                "unit_sha256": CURRENT_UNIT_SHA256,
                "model_sha256": CURRENT_MODEL_SHA256,
                "model_bytes": CURRENT_MODEL_BYTES,
                "local_service": "active",
            },
            "target": {
                "repository": TARGET_MODEL_REPOSITORY,
                "revision": TARGET_MODEL_REVISION,
                "filename": TARGET_MODEL_FILENAME,
                "model_sha256": TARGET_MODEL_SHA256,
                "model_bytes": TARGET_MODEL_BYTES,
                "unit_sha256": digest_bytes(target_unit_bytes()),
                "alias": "myuna-local-owner-v1",
                "loopback_port": 879,
                "runtime_unchanged": "llama.cpp-b10217-cpu",
            },
            "live_scope": {
                "local_service_restart_max": 1,
                "core_restart": 0,
                "gateway_quiesce_restore": ["qq-owner-private", "telegram-owner-private"],
                "model_or_provider_probe_forbidden": True,
                "health_endpoints_forbidden": True,
            },
            "rollback": {
                "restore_unit_exact_bytes": True,
                "restore_model": CURRENT_MODEL_SHA256,
                "retain_installed_model": True,
                "profile_and_session_data_unchanged": True,
            },
        }
    )


def _atomic_write(path: Path, payload: bytes, *, mode: int, gid: int = 0) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, 0, gid)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def verify_prestate(candidate: Path) -> None:
    require(os.geteuid() == 0, "root_required")
    verify_model_file(
        candidate,
        expected_size=TARGET_MODEL_BYTES,
        expected_sha256=TARGET_MODEL_SHA256,
    )
    require(all(active(unit) for unit in (LOCAL_SERVICE, CORE_SERVICE, *GATEWAY_UNITS)), "live_prestate_rejected")
    require(digest_file(LIVE_UNIT) == CURRENT_UNIT_SHA256, "unit_drifted")
    verify_model_file(
        CURRENT_MODEL_PATH,
        expected_size=CURRENT_MODEL_BYTES,
        expected_sha256=CURRENT_MODEL_SHA256,
    )
    require(TARGET_MODEL_PATH.as_posix().encode() in target_unit_bytes(), "target_unit_rejected")


def backup(plan: bytes) -> Path:
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(BACKUP_ROOT, 0o700)
    root = BACKUP_ROOT / digest_bytes(plan)
    require(not root.exists(), "backup_conflict")
    root.mkdir(mode=0o700)
    _atomic_write(root / "PLAN.json", plan, mode=0o600)
    _atomic_write(root / "PRE_UNIT.service", LIVE_UNIT.read_bytes(), mode=0o600)
    return root


def install_model(candidate: Path) -> None:
    if TARGET_MODEL_ROOT.exists():
        verify_model_file(
            TARGET_MODEL_PATH,
            expected_size=TARGET_MODEL_BYTES,
            expected_sha256=TARGET_MODEL_SHA256,
        )
        return
    group_id = grp.getgrnam("myuna_local_provider").gr_gid
    temporary = Path(tempfile.mkdtemp(prefix=f".{TARGET_MODEL_SHA256[:12]}-", dir=TARGET_MODEL_ROOT.parent))
    try:
        destination = temporary / "model.gguf"
        shutil.copyfile(candidate, destination)
        verify_model_file(
            destination,
            expected_size=TARGET_MODEL_BYTES,
            expected_sha256=TARGET_MODEL_SHA256,
        )
        os.chown(destination, 0, group_id)
        os.chmod(destination, 0o440)
        os.chown(temporary, 0, group_id)
        os.chmod(temporary, 0o550)
        os.replace(temporary, TARGET_MODEL_ROOT)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def quiesce_gateways() -> None:
    systemctl("stop", QQ_SOCKET, TELEGRAM_SOCKET, QQ_SERVICE, TELEGRAM_SERVICE)


def restore_gateways() -> None:
    systemctl("start", QQ_SOCKET, TELEGRAM_SOCKET)
    systemctl("start", QQ_SERVICE, TELEGRAM_SERVICE)
    require(all(active(unit) for unit in GATEWAY_UNITS), "gateway_restore_rejected")


def _port_ready() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 879), timeout=0.25):
            return True
    except OSError:
        return False


def _process_uses_model(expected: Path) -> bool:
    try:
        pid = int(show(LOCAL_SERVICE, "MainPID"))
        require(pid > 0, "local_pid_rejected")
        command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except (OSError, ValueError) as exc:
        raise ActivationRejected("local_process_unavailable") from exc
    return expected.as_posix().encode() in command


def wait_local(expected_model: Path) -> None:
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        if active(LOCAL_SERVICE) and _process_uses_model(expected_model) and _port_ready():
            require(show(LOCAL_SERVICE, "NRestarts") == "0", "local_restart_loop")
            return
        time.sleep(1)
    raise ActivationRejected("local_readiness_timeout")


def rollback(root: Path) -> None:
    _atomic_write(LIVE_UNIT, (root / "PRE_UNIT.service").read_bytes(), mode=0o644)
    systemctl("daemon-reload")
    systemctl("restart", LOCAL_SERVICE)
    wait_local(CURRENT_MODEL_PATH)
    restore_gateways()


def write_receipt(root: Path, plan: bytes) -> None:
    RECEIPT_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(RECEIPT_ROOT, 0o700)
    payload = canonical_json_bytes(
        {
            "schema": SCHEMA,
            "status": "ACTIVE_WAITING_CORE_OUTPUT_CAP_SELECTION",
            "plan_sha256": digest_bytes(plan),
            "backup": root.name,
            "model_sha256": TARGET_MODEL_SHA256,
            "model_bytes": TARGET_MODEL_BYTES,
            "model_revision": TARGET_MODEL_REVISION,
            "local_service_restart_count": 1,
            "core_restarted": False,
            "model_probe_performed": False,
            "health_endpoint_called": False,
            "profile_content_recorded": False,
            "raw_message_recorded": False,
            "secret_recorded": False,
        }
    )
    _atomic_write(RECEIPT, payload, mode=0o600)
    _atomic_write(root / "RECEIPT.json", payload, mode=0o600)


def activate(candidate: Path, *, preflight_only: bool) -> dict[str, object]:
    verify_prestate(candidate)
    plan = plan_bytes()
    if preflight_only:
        return {"plan_sha256": digest_bytes(plan), "status": "ready"}
    root = backup(plan)
    install_model(candidate)
    gateways_stopped = False
    unit_mutated = False
    try:
        quiesce_gateways()
        gateways_stopped = True
        _atomic_write(LIVE_UNIT, target_unit_bytes(), mode=0o644)
        unit_mutated = True
        systemctl("daemon-reload")
        systemctl("restart", LOCAL_SERVICE)
        wait_local(TARGET_MODEL_PATH)
        restore_gateways()
        gateways_stopped = False
        write_receipt(root, plan)
    except Exception:
        if unit_mutated:
            rollback(root)
        elif gateways_stopped:
            restore_gateways()
        raise
    return {
        "model_sha256": TARGET_MODEL_SHA256,
        "plan_sha256": digest_bytes(plan),
        "status": "ACTIVE_WAITING_CORE_OUTPUT_CAP_SELECTION",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-candidate", required=True, type=Path)
    parser.add_argument("--preflight-only", action="store_true")
    arguments = parser.parse_args()
    try:
        result = activate(arguments.model_candidate, preflight_only=arguments.preflight_only)
    except (ActivationRejected, OSError, ValueError, subprocess.SubprocessError):
        print(json.dumps({"status": "rejected"}, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
