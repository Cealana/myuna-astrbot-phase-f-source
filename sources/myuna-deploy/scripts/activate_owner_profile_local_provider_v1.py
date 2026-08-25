#!/usr/bin/env python3
"""Activate the exact P07 local provider and Owner Profile read-only route."""

from __future__ import annotations

import argparse
import grp
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from typing import Sequence
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from core_release_selector import (
    ReleaseEvidence,
    SelectionCandidate,
    build_binding_intent,
    canonical_json_bytes,
    load_runtime_binding,
    parse_json_document,
    render_runtime_binding,
    render_selector_dropin,
    validate_immutable_release_tree,
)


CORE_SERVICE = "myuna-core@qq.service"
GATEWAY_SOCKET = "myuna-qq-owner-runtime-dev.socket"
GATEWAY_SERVICE = "myuna-qq-owner-runtime-dev.service"
PROFILE_SOCKET = "myuna-owner-profile-read-v1.socket"
PROFILE_SERVICE = "myuna-owner-profile-read-v1.service"
LOCAL_SERVICE = "myuna-local-provider-v1.service"
CORE_BASE_RELEASE = "16255b4b61b0a3ac9ce8c1489a6f51faec363a99ff6859f01ce8b1ec6339d9a3"
CORE_TARGET_RELEASE = "d540f76ee83710153937769dfa433d651767e9a9443c3678539314020a3175fc"
CORE_TARGET_COMMIT = "9a711bc265bcb121197877ea40882dfc8ee3e0b8"
CORE_TARGET_FILE_COUNT = 238
CORE_RELEASE_ROOT = Path("/srv/myuna/releases/core")
CORE_BINDING = Path("/etc/myuna/core-release-selector/qq.binding.json")
CORE_SELECTOR = Path(
    "/etc/systemd/system/myuna-core@qq.service.d/10-core-release-selector-v1.conf"
)
CORE_DROPIN = Path(
    "/etc/systemd/system/myuna-core@qq.service.d/zzzzzzz-p07-local-profile-v1.conf"
)
CORE_DROPIN_BYTES = (
    b"[Unit]\n"
    b"Wants=myuna-local-provider-v1.service myuna-owner-profile-read-v1.socket\n"
    b"After=myuna-local-provider-v1.service myuna-owner-profile-read-v1.socket\n\n"
    b"[Service]\n"
    b"LoadCredential=\n"
    b"LoadCredential=deepseek_api_key:/etc/myuna/secrets/deepseek-api-key\n"
    b"LoadCredential=telegram_owner_core_token:/etc/myuna-telegram-gateway/secrets/core-token-v1\n"
    b"LoadCredential=qq_owner_core_token:/etc/myuna-gateway/secrets/qq-owner-core-token\n"
    b"EnvironmentFile=/etc/myuna/p07-local-profile-v1.env\n"
)
DEPLOY_ROOT = Path("/srv/myuna/repos/deploy")
CORE_ENV_SOURCE = DEPLOY_ROOT / "config/qq-owner-p07-local-profile-v1.env"
CORE_ENV = Path("/etc/myuna/p07-local-profile-v1.env")
MANIFEST_SOURCE = (
    DEPLOY_ROOT / "config/capabilities/qq-owner-v6-p07-local-profile-v1.json"
)
MANIFEST = Path("/etc/myuna/capabilities/qq-owner-v6-p07-local-profile-v1.json")
CHANNEL_PROFILE_SOURCE = (
    DEPLOY_ROOT / "config/capabilities/owner-private-profile-read-v1.json"
)
CHANNEL_PROFILE = Path("/etc/myuna/capabilities/owner-private-profile-read-v1.json")
LOCAL_UNIT_SOURCE = DEPLOY_ROOT / "systemd/myuna-local-provider-v1.service"
LOCAL_UNIT = Path("/etc/systemd/system/myuna-local-provider-v1.service")
MODEL_PATH = Path(
    "/var/lib/myuna-local-provider-v1/models/"
    "qwen3-4b-q4-k-m-7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5/"
    "model.gguf"
)
MODEL_SHA256 = "7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5"
MODEL_BYTES = 2_497_280_256
RUNTIME_PATH = Path(
    "/opt/myuna/local-provider-v1/releases/"
    "b10217-b79145bfa48f4fef83e76e1cef7ef4fbdf966e497a2fd774f1107fc2a24500af"
)
VERIFIER_SHA256 = "3fab13b7b533c3e93bf5759256ff5153d7bb17aea0fc8307f560e82985a7fcaf"
VERIFIER_PATH = (
    Path("/opt/myuna/core-release-selector/releases")
    / VERIFIER_SHA256
    / "core_release_selector.py"
)
BACKUP_ROOT = Path("/var/backups/myuna/p07-owner-profile-local-provider-v1")
CONFIRMATION = "I_UNDERSTAND_P07_WILL_RESTART_MYUNA_CORE_AND_QQ_GATEWAY"
LOCAL_HEALTH_MAX_BYTES = 4096


class P07ActivationError(RuntimeError):
    """Content-free P07 activation rejection."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def _reject(code: str) -> P07ActivationError:
    return P07ActivationError(code)


def _digest(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def _digest_file(path: Path) -> str:
    value = sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                value.update(chunk)
    except OSError as exc:
        raise _reject("activation_file_unavailable") from exc
    return value.hexdigest()


def _systemctl(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            ["/usr/bin/systemctl", *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=200,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _reject("systemd_unavailable") from exc
    if check and result.returncode != 0:
        raise _reject("systemd_command_failed")
    return result


def _active(unit: str) -> bool:
    return _systemctl("is-active", "--quiet", unit, check=False).returncode == 0


def _show(unit: str, property_name: str) -> str:
    result = _systemctl("show", "-p", property_name, "--value", unit)
    return result.stdout.strip()


def _source_bytes(path: Path) -> bytes:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as exc:
        raise _reject("activation_source_unavailable") from exc
    if path.is_symlink() or not path.is_file() or metadata.st_nlink != 1 or not payload:
        raise _reject("activation_source_rejected")
    return payload


def _artifact_manifest_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "schema": "myuna.core-source-artifact.p07-owner-profile-local-v1",
            "status": "offline_tested_installed_inactive",
            "tree_digest_algorithm": "myuna-path-content-tree-sha256-v1",
            "tree_sha256": CORE_TARGET_RELEASE,
            "source_commit": CORE_TARGET_COMMIT,
            "file_count": CORE_TARGET_FILE_COUNT,
            "verification": {
                "core_tests": 515,
                "deploy_p07_tests": 56,
                "private_content_present": False,
                "provider_calls": 0,
            },
        }
    )


def _installation_receipt_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "schema": "myuna.core-release.inactive-installation.v1",
            "status": "installed_inactive_not_selected",
            "tree_sha256": CORE_TARGET_RELEASE,
            "source_commit": CORE_TARGET_COMMIT,
            "file_count": CORE_TARGET_FILE_COUNT,
            "release_path": (CORE_RELEASE_ROOT / CORE_TARGET_RELEASE).as_posix(),
            "artifact_manifest_sha256": _digest(_artifact_manifest_bytes()),
            "ownership": "root:myuna",
            "directory_mode": "0550",
            "file_mode": "0440",
        }
    )


def _target_evidence() -> ReleaseEvidence:
    return ReleaseEvidence(
        tree_sha256=CORE_TARGET_RELEASE,
        source_commit=CORE_TARGET_COMMIT,
        file_count=CORE_TARGET_FILE_COUNT,
        artifact_manifest_sha256=_digest(_artifact_manifest_bytes()),
        installation_receipt_sha256=_digest(_installation_receipt_bytes()),
    )


def _target_binding(plan_digest: str) -> tuple[bytes, bytes]:
    candidate = SelectionCandidate(selected_release=_target_evidence())
    intent = build_binding_intent(
        candidate,
        verifier_script_path=VERIFIER_PATH.as_posix(),
        verifier_script_sha256=VERIFIER_SHA256,
    )
    binding = render_runtime_binding(intent, approval_plan_digest=plan_digest)
    binding_bytes = canonical_json_bytes(binding.to_payload())
    selector_bytes = render_selector_dropin(candidate).encode("utf-8")
    load_runtime_binding(parse_json_document(binding_bytes))
    if _digest(selector_bytes) != binding.selector_dropin_sha256:
        raise _reject("target_binding_rejected")
    return binding_bytes, selector_bytes


def _plan_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "schema": "myuna.p07-owner-profile-local-provider-live-plan.v1",
            "status": "owner_route_selected",
            "prestate": {
                "core_release": CORE_BASE_RELEASE,
                "core_binding_sha256": _digest_file(CORE_BINDING),
                "core_selector_sha256": _digest_file(CORE_SELECTOR),
                "gateway_socket_active": _active(GATEWAY_SOCKET),
                "gateway_service_active": _active(GATEWAY_SERVICE),
            },
            "target": {
                "core_release": CORE_TARGET_RELEASE,
                "core_source_commit": CORE_TARGET_COMMIT,
                "local_provider_alias": "myuna-local-owner-v1",
                "local_provider_endpoint": "http://127.0.0.1:879/v1",
                "model_sha256": MODEL_SHA256,
                "owner_profile_protocol": "profile-v1",
                "legacy_owner_memory_read_enabled": False,
            },
            "source_files": {
                "core_env_sha256": _digest(_source_bytes(CORE_ENV_SOURCE)),
                "manifest_sha256": _digest(_source_bytes(MANIFEST_SOURCE)),
                "channel_profile_sha256": _digest(_source_bytes(CHANNEL_PROFILE_SOURCE)),
                "local_unit_sha256": _digest(_source_bytes(LOCAL_UNIT_SOURCE)),
                "core_dropin_sha256": _digest(CORE_DROPIN_BYTES),
            },
            "activation": {
                "provider_synthetic_probe": 1,
                "core_restart_max": 1,
                "gateway_ingress_paused": True,
                "health_endpoint_called": False,
                "external_profile_egress": False,
            },
            "rollback": {
                "restore_exact_binding_and_selector": True,
                "restore_core_release": CORE_BASE_RELEASE,
                "stop_local_provider": True,
                "retain_runtime_model_release_and_receipts": True,
            },
        }
    )


def _atomic_write(path: Path, payload: bytes, *, mode: int, gid: int = 0) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, 0, gid)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise _reject("activation_write_failed") from exc
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _verify_model_and_runtime() -> None:
    try:
        metadata = MODEL_PATH.lstat()
    except OSError as exc:
        raise _reject("model_release_unavailable") from exc
    if (
        MODEL_PATH.is_symlink()
        or not MODEL_PATH.is_file()
        or metadata.st_size != MODEL_BYTES
        or _digest_file(MODEL_PATH) != MODEL_SHA256
        or not (RUNTIME_PATH / "llama-server").is_file()
    ):
        raise _reject("model_runtime_release_rejected")


def preflight() -> bytes:
    if os.geteuid() != 0:
        raise _reject("must_run_as_root")
    if not all(_active(unit) for unit in (CORE_SERVICE, GATEWAY_SOCKET, GATEWAY_SERVICE)):
        raise _reject("live_prestate_rejected")
    if _show(CORE_SERVICE, "WorkingDirectory") != (CORE_RELEASE_ROOT / CORE_BASE_RELEASE).as_posix():
        raise _reject("core_prestate_rejected")
    if not _active(PROFILE_SOCKET) or not _active(PROFILE_SERVICE):
        raise _reject("profile_read_service_unavailable")
    if _active(LOCAL_SERVICE):
        raise _reject("local_provider_already_active")
    validate_immutable_release_tree(CORE_RELEASE_ROOT / CORE_TARGET_RELEASE, _target_evidence())
    _verify_model_and_runtime()
    if _digest_file(VERIFIER_PATH) != VERIFIER_SHA256:
        raise _reject("core_verifier_rejected")
    for destination, source in (
        (CORE_ENV, CORE_ENV_SOURCE),
        (MANIFEST, MANIFEST_SOURCE),
        (CHANNEL_PROFILE, CHANNEL_PROFILE_SOURCE),
        (LOCAL_UNIT, LOCAL_UNIT_SOURCE),
    ):
        if destination.exists() and destination.read_bytes() != _source_bytes(source):
            raise _reject("activation_destination_conflict")
    if CORE_DROPIN.exists() and CORE_DROPIN.read_bytes() != CORE_DROPIN_BYTES:
        raise _reject("activation_destination_conflict")
    return _plan_bytes()


def _backup(plan: bytes) -> Path:
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(BACKUP_ROOT, 0o700)
    root = BACKUP_ROOT / _digest(plan)
    if root.exists():
        try:
            if (
                (root / "PLAN.json").read_bytes() != plan
                or (root / "RECEIPT.json").exists()
                or not (root / "PRE_BINDING.json").is_file()
                or not (root / "PRE_SELECTOR.conf").is_file()
            ):
                raise _reject("activation_backup_conflict")
        except OSError as exc:
            raise _reject("activation_backup_conflict") from exc
        return root
    root.mkdir(parents=True, mode=0o700, exist_ok=False)
    os.chmod(root, 0o700)
    for name, payload in (
        ("PRE_BINDING.json", CORE_BINDING.read_bytes()),
        ("PRE_SELECTOR.conf", CORE_SELECTOR.read_bytes()),
        ("PLAN.json", plan),
        ("CORE_ARTIFACT_MANIFEST.json", _artifact_manifest_bytes()),
        ("CORE_INSTALLATION_RECEIPT.json", _installation_receipt_bytes()),
    ):
        _atomic_write(root / name, payload, mode=0o600)
    return root


def _local_health_ready(status_code: int, body: bytes) -> bool:
    if status_code != 200 or len(body) > LOCAL_HEALTH_MAX_BYTES:
        return False
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return False
    return document == {"status": "ok"}


def _wait_local_service() -> None:
    request = Request(
        "http://127.0.0.1:879/health",
        headers={"Accept": "application/json"},
        method="GET",
    )
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        if _active(LOCAL_SERVICE):
            try:
                with opener.open(request, timeout=2) as response:
                    body = response.read(LOCAL_HEALTH_MAX_BYTES + 1)
                    if _local_health_ready(int(response.status), body):
                        return
            except (HTTPError, URLError, TimeoutError, OSError):
                pass
        time.sleep(1)
    raise _reject("local_provider_start_timeout")


def _synthetic_probe() -> None:
    payload = canonical_json_bytes(
        {
            "model": "myuna-local-owner-v1",
            "messages": [
                {"role": "user", "content": "Synthetic protocol probe. Reply briefly."}
            ],
            "max_tokens": 32,
            "stream": False,
        }
    )
    request = Request(
        "http://127.0.0.1:879/v1/chat/completions",
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=120) as response:
            body = response.read(1024 * 1024 + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise _reject("synthetic_provider_probe_failed") from exc
    if len(body) > 1024 * 1024:
        raise _reject("synthetic_provider_probe_failed")
    try:
        document = json.loads(body.decode("utf-8"))
        choices = document["choices"]
        content = choices[0]["message"]["content"]
        model = document["model"]
    except (KeyError, IndexError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
        raise _reject("synthetic_provider_probe_failed") from exc
    if (
        model != "myuna-local-owner-v1"
        or not isinstance(choices, list)
        or len(choices) != 1
        or not isinstance(content, str)
        or not content.strip()
        or len(content) > 2048
    ):
        raise _reject("synthetic_provider_probe_failed")


def _install_live_files(plan: bytes) -> None:
    myuna_gid = grp.getgrnam("myuna").gr_gid
    binding, selector = _target_binding(_digest(plan))
    for destination, source in (
        (CORE_ENV, CORE_ENV_SOURCE),
        (MANIFEST, MANIFEST_SOURCE),
        (CHANNEL_PROFILE, CHANNEL_PROFILE_SOURCE),
        (LOCAL_UNIT, LOCAL_UNIT_SOURCE),
    ):
        _atomic_write(destination, _source_bytes(source), mode=0o644)
    _atomic_write(CORE_DROPIN, CORE_DROPIN_BYTES, mode=0o644)
    _atomic_write(CORE_BINDING, binding, mode=0o640, gid=myuna_gid)
    _atomic_write(CORE_SELECTOR, selector, mode=0o644)


def _verify_target() -> None:
    if not _active(CORE_SERVICE):
        raise _reject("core_target_unavailable")
    if _show(CORE_SERVICE, "WorkingDirectory") != (CORE_RELEASE_ROOT / CORE_TARGET_RELEASE).as_posix():
        raise _reject("core_target_release_rejected")
    result = subprocess.run(
        ["/usr/bin/python3", VERIFIER_PATH.as_posix(), "verify-active"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        cwd=CORE_RELEASE_ROOT / CORE_TARGET_RELEASE,
        env={
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": f"{CORE_RELEASE_ROOT / CORE_TARGET_RELEASE}/src",
        },
    )
    if result.returncode != 0:
        raise _reject("core_target_verifier_rejected")


def _rollback(backup: Path) -> None:
    _systemctl("stop", GATEWAY_SOCKET, check=False)
    _systemctl("stop", GATEWAY_SERVICE, check=False)
    myuna_gid = grp.getgrnam("myuna").gr_gid
    _atomic_write(CORE_BINDING, (backup / "PRE_BINDING.json").read_bytes(), mode=0o640, gid=myuna_gid)
    _atomic_write(CORE_SELECTOR, (backup / "PRE_SELECTOR.conf").read_bytes(), mode=0o644)
    CORE_DROPIN.unlink(missing_ok=True)
    _systemctl("disable", "--now", LOCAL_SERVICE, check=False)
    _systemctl("daemon-reload")
    _systemctl("restart", CORE_SERVICE)
    _systemctl("start", GATEWAY_SOCKET)
    _systemctl("start", GATEWAY_SERVICE)
    if not _active(CORE_SERVICE) or _show(CORE_SERVICE, "WorkingDirectory") != (CORE_RELEASE_ROOT / CORE_BASE_RELEASE).as_posix():
        raise _reject("rollback_failed")


def activate() -> dict[str, object]:
    plan = preflight()
    backup = _backup(plan)
    mutated = False
    try:
        _install_live_files(plan)
        mutated = True
        _systemctl("daemon-reload")
        _systemctl("start", LOCAL_SERVICE)
        _wait_local_service()
        _synthetic_probe()
        _systemctl("stop", GATEWAY_SOCKET)
        _systemctl("stop", GATEWAY_SERVICE)
        _systemctl("restart", CORE_SERVICE)
        _verify_target()
        _systemctl("start", GATEWAY_SOCKET)
        _systemctl("start", GATEWAY_SERVICE)
        if not _active(GATEWAY_SOCKET) or not _active(GATEWAY_SERVICE):
            raise _reject("gateway_restore_failed")
        _systemctl("enable", LOCAL_SERVICE)
        receipt = {
            "schema": "myuna.p07-owner-profile-local-provider-activation.v1",
            "status": "activated",
            "plan_sha256": _digest(plan),
            "core_release": CORE_TARGET_RELEASE,
            "core_source_commit": CORE_TARGET_COMMIT,
            "model_sha256": MODEL_SHA256,
            "provider": "local",
            "profile_protocol": "profile-v1",
            "legacy_memory_read_enabled": False,
            "synthetic_provider_probe": "passed",
            "private_content_present": False,
        }
        _atomic_write(backup / "RECEIPT.json", canonical_json_bytes(receipt), mode=0o600)
        return receipt
    except Exception:
        if mutated:
            _rollback(backup)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("preflight")
    live = subparsers.add_parser("activate-live")
    live.add_argument("--live-confirmation", required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "preflight":
            plan = preflight()
            result = {
                "status": "preflight_passed",
                "plan_sha256": _digest(plan),
                "private_content_present": False,
            }
        else:
            if arguments.live_confirmation != CONFIRMATION:
                raise _reject("live_confirmation_rejected")
            result = activate()
    except (P07ActivationError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "rejected", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
