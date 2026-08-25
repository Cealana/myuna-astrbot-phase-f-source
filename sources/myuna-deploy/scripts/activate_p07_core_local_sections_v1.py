#!/usr/bin/env python3
"""Select the exact P07 Core release with bounded local Definition sections."""

from __future__ import annotations

import argparse
import grp
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from core_release_selector import (
    ReleaseEvidence,
    SelectionCandidate,
    build_binding_intent,
    canonical_json_bytes,
    compute_tree_digest,
    load_runtime_binding,
    parse_json_document,
    render_runtime_binding,
    render_selector_dropin,
    validate_immutable_release_tree,
)


CORE_SERVICE = "myuna-core@qq.service"
QQ_SOCKET = "myuna-qq-owner-runtime-dev.socket"
QQ_SERVICE = "myuna-qq-owner-runtime-dev.service"
TELEGRAM_SOCKET = "myuna-telegram-owner-runtime-dev.socket"
TELEGRAM_SERVICE = "myuna-telegram-owner-runtime-dev.service"
PROFILE_SERVICE = "myuna-owner-profile-read-v1.service"
LOCAL_SERVICE = "myuna-local-provider-v1.service"
CURRENT_RELEASE = "8d0497be37db5aa797843d0367cd24f71b1ad20f7006abc61f1eff205c22cc9c"
CURRENT_BINDING_SHA256 = (
    "109955e67c8180aae368c2d6af927451529f17a4a4e00d711d66b969d13f4055"
)
CURRENT_SELECTOR_SHA256 = (
    "f66271c4c3ea0c1ed62b0f1995d8312110c5d41439f0a29325d539c517da3a6a"
)
TARGET_RELEASE = "75cfa2dbe9f476a110f52ee0d26a994bbb6548ab06122c4f0c4fe1343aaab5cf"
TARGET_COMMIT = "3c3bcb6ef47a51b3752d7897065c90bbdb559a15"
TARGET_FILE_COUNT = 238
CORE_RELEASE_ROOT = Path("/srv/myuna/releases/core")
CORE_BINDING = Path("/etc/myuna/core-release-selector/qq.binding.json")
CORE_SELECTOR = Path(
    "/etc/systemd/system/myuna-core@qq.service.d/10-core-release-selector-v1.conf"
)
VERIFIER_SHA256 = "3fab13b7b533c3e93bf5759256ff5153d7bb17aea0fc8307f560e82985a7fcaf"
VERIFIER_PATH = (
    Path("/opt/myuna/core-release-selector/releases")
    / VERIFIER_SHA256
    / "core_release_selector.py"
)
BACKUP_ROOT = Path("/var/backups/myuna/p07-core-local-sections-v1")
RECEIPT_ROOT = Path(
    "/var/lib/myuna/core-release-selector/p07-local-sections"
)
RECEIPT = RECEIPT_ROOT / "LAST_ACTIVATION.json"
SCHEMA = "myuna.p07-core-local-sections-activation.v1"


class ActivationRejected(RuntimeError):
    """Content-free bounded activation rejection."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ActivationRejected(code)


def digest_bytes(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def digest_file(path: Path) -> str:
    try:
        return sha256(path.read_bytes()).hexdigest()
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


def artifact_manifest_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "schema": "myuna.core-source-artifact.p07-local-sections-v1",
            "status": "offline_tested_not_installed",
            "tree_digest_algorithm": "myuna-path-content-tree-sha256-v1",
            "tree_sha256": TARGET_RELEASE,
            "source_commit": TARGET_COMMIT,
            "file_count": TARGET_FILE_COUNT,
            "verification": {
                "core_tests": 521,
                "private_content_present": False,
                "provider_calls": 0,
                "local_input_projection": "recent-complete-turns-v1",
                "local_definition_projection": "exact-core-sections-v1",
            },
        }
    )


def installation_receipt_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "schema": "myuna.core-release.inactive-installation.v1",
            "status": "installed_inactive_not_selected",
            "tree_sha256": TARGET_RELEASE,
            "source_commit": TARGET_COMMIT,
            "file_count": TARGET_FILE_COUNT,
            "release_path": (CORE_RELEASE_ROOT / TARGET_RELEASE).as_posix(),
            "artifact_manifest_sha256": digest_bytes(artifact_manifest_bytes()),
            "ownership": "root:myuna",
            "directory_mode": "0550",
            "file_mode": "0440",
        }
    )


def target_evidence() -> ReleaseEvidence:
    return ReleaseEvidence(
        tree_sha256=TARGET_RELEASE,
        source_commit=TARGET_COMMIT,
        file_count=TARGET_FILE_COUNT,
        artifact_manifest_sha256=digest_bytes(artifact_manifest_bytes()),
        installation_receipt_sha256=digest_bytes(installation_receipt_bytes()),
    )


def target_binding(plan_digest: str) -> tuple[bytes, bytes]:
    candidate = SelectionCandidate(selected_release=target_evidence())
    intent = build_binding_intent(
        candidate,
        verifier_script_path=VERIFIER_PATH.as_posix(),
        verifier_script_sha256=VERIFIER_SHA256,
    )
    binding = render_runtime_binding(intent, approval_plan_digest=plan_digest)
    binding_bytes = canonical_json_bytes(binding.to_payload())
    selector_bytes = render_selector_dropin(candidate).encode("utf-8")
    load_runtime_binding(parse_json_document(binding_bytes))
    require(
        digest_bytes(selector_bytes) == binding.selector_dropin_sha256,
        "target_binding_rejected",
    )
    return binding_bytes, selector_bytes


def plan_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "schema": SCHEMA,
            "status": "standing_authority",
            "executor_sha256": digest_file(Path(__file__).resolve()),
            "prestate": {
                "core_release": CURRENT_RELEASE,
                "binding_sha256": CURRENT_BINDING_SHA256,
                "selector_sha256": CURRENT_SELECTOR_SHA256,
                "profile_service": "active",
                "local_provider": "active",
            },
            "target": {
                "core_release": TARGET_RELEASE,
                "core_source_commit": TARGET_COMMIT,
                "local_input_limit_characters": 14_000,
                "projection": "newest-complete-turns-preserve-system-and-final-user",
                "definition_projection": "exact-approved-skill-sections-v1",
                "definition_source_mutated": False,
                "non_local_definition_projection": "full-unchanged",
                "session_store": "unchanged-128-message-window",
            },
            "live_scope": {
                "core_restart_max": 1,
                "gateway_restarts": 0,
                "gateway_quiesce_restore": ["qq-owner-private", "telegram-owner-private"],
                "health_endpoints_forbidden": True,
                "provider_probe_forbidden": True,
            },
            "rollback": {
                "restore_binding_and_selector_exact_bytes": True,
                "restore_core_release": CURRENT_RELEASE,
                "retain_installed_release": True,
                "preserve_profile_and_session_data": True,
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


def validate_candidate(candidate: Path) -> None:
    resolved = candidate.resolve()
    require(
        not candidate.is_symlink() and resolved.name == TARGET_RELEASE,
        "candidate_path_rejected",
    )
    require(
        compute_tree_digest(resolved) == (TARGET_RELEASE, TARGET_FILE_COUNT),
        "candidate_tree_rejected",
    )
    probe = (
        "from myuna_core.providers import ModelRequest;"
        "from myuna_core.providers.local import LOCAL_MAX_INPUT_CHARACTERS,project_local_request;"
        "m=[{'role':'system','content':'s'*13500}];"
        "m.extend(x for i in range(52) for x in "
        "({'role':'user','content':'u'*51},{'role':'assistant','content':'a'*51}));"
        "m.append({'role':'user','content':'final'});"
        "p=project_local_request(ModelRequest(request_id='probe',messages=tuple(m),"
        "max_output_tokens=32,model='myuna-local-owner-v1',"
        "definition_projection='local_core_sections'));"
        "assert p.applied and p.request.messages[0]['role']=='system';"
        "assert p.request.definition_projection=='local_core_sections';"
        "assert p.request.messages[-1]['content']=='final';"
        "assert sum(len(x['content']) for x in p.request.messages)<=LOCAL_MAX_INPUT_CHARACTERS"
    )
    completed = subprocess.run(
        ["/usr/bin/python3", "-B", "-c", probe],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": f"{resolved}/src",
        },
    )
    require(completed.returncode == 0, "candidate_projection_probe_rejected")


def verify_prestate() -> None:
    required_units = (
        CORE_SERVICE,
        QQ_SOCKET,
        QQ_SERVICE,
        TELEGRAM_SOCKET,
        TELEGRAM_SERVICE,
        PROFILE_SERVICE,
        LOCAL_SERVICE,
    )
    require(all(active(unit) for unit in required_units), "live_prestate_rejected")
    require(
        show(CORE_SERVICE, "WorkingDirectory")
        == (CORE_RELEASE_ROOT / CURRENT_RELEASE).as_posix(),
        "core_release_prestate_rejected",
    )
    require(digest_file(CORE_BINDING) == CURRENT_BINDING_SHA256, "binding_drifted")
    require(digest_file(CORE_SELECTOR) == CURRENT_SELECTOR_SHA256, "selector_drifted")
    require(digest_file(VERIFIER_PATH) == VERIFIER_SHA256, "verifier_drifted")


def backup(plan: bytes) -> Path:
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(BACKUP_ROOT, 0o700)
    root = BACKUP_ROOT / digest_bytes(plan)
    require(not root.exists(), "backup_conflict")
    root.mkdir(mode=0o700)
    for name, payload in (
        ("PLAN.json", plan),
        ("PRE_BINDING.json", CORE_BINDING.read_bytes()),
        ("PRE_SELECTOR.conf", CORE_SELECTOR.read_bytes()),
        ("CORE_ARTIFACT_MANIFEST.json", artifact_manifest_bytes()),
        ("CORE_INSTALLATION_RECEIPT.json", installation_receipt_bytes()),
    ):
        _atomic_write(root / name, payload, mode=0o600)
    return root


def install_candidate(candidate: Path) -> Path:
    destination = CORE_RELEASE_ROOT / TARGET_RELEASE
    if destination.exists():
        validate_immutable_release_tree(destination, target_evidence())
        return destination
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{TARGET_RELEASE[:12]}-", dir=CORE_RELEASE_ROOT)
    )
    try:
        shutil.copytree(candidate.resolve(), temporary, dirs_exist_ok=True)
        myuna_gid = grp.getgrnam("myuna").gr_gid
        for entry in (temporary, *temporary.rglob("*")):
            os.chown(entry, 0, myuna_gid)
            os.chmod(entry, 0o550 if entry.is_dir() else 0o440)
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    validate_immutable_release_tree(destination, target_evidence())
    return destination


def quiesce_gateways() -> None:
    systemctl("stop", QQ_SOCKET, TELEGRAM_SOCKET, QQ_SERVICE, TELEGRAM_SERVICE)


def restore_gateways() -> None:
    systemctl("start", QQ_SOCKET, TELEGRAM_SOCKET)
    systemctl("start", QQ_SERVICE, TELEGRAM_SERVICE)
    require(
        all(active(unit) for unit in (QQ_SOCKET, QQ_SERVICE, TELEGRAM_SOCKET, TELEGRAM_SERVICE)),
        "gateway_restore_rejected",
    )


def verify_target() -> None:
    require(active(CORE_SERVICE), "core_target_inactive")
    target = CORE_RELEASE_ROOT / TARGET_RELEASE
    require(show(CORE_SERVICE, "WorkingDirectory") == target.as_posix(), "core_target_rejected")
    completed = subprocess.run(
        ["/usr/bin/python3", VERIFIER_PATH.as_posix(), "verify-active"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        cwd=target,
        env={"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": f"{target}/src"},
    )
    require(completed.returncode == 0, "core_verifier_rejected")


def rollback(root: Path) -> None:
    myuna_gid = grp.getgrnam("myuna").gr_gid
    _atomic_write(CORE_BINDING, (root / "PRE_BINDING.json").read_bytes(), mode=0o640, gid=myuna_gid)
    _atomic_write(CORE_SELECTOR, (root / "PRE_SELECTOR.conf").read_bytes(), mode=0o644)
    systemctl("daemon-reload")
    systemctl("restart", CORE_SERVICE)
    restore_gateways()
    require(
        show(CORE_SERVICE, "WorkingDirectory")
        == (CORE_RELEASE_ROOT / CURRENT_RELEASE).as_posix(),
        "rollback_rejected",
    )


def write_receipt(root: Path, plan: bytes) -> None:
    RECEIPT_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(RECEIPT_ROOT, 0o700)
    payload = canonical_json_bytes(
        {
            "schema": SCHEMA,
            "status": "ACTIVE_WAITING_OWNER_TELEGRAM_E2E_RETRY",
            "plan_sha256": digest_bytes(plan),
            "backup": root.name,
            "core_release": TARGET_RELEASE,
            "core_source_commit": TARGET_COMMIT,
            "core_tests": 521,
            "local_input_projection": "recent-complete-turns-v1",
            "local_definition_projection": "exact-core-sections-v1",
            "definition_source_mutated": False,
            "session_store_changed": False,
            "profile_content_recorded": False,
            "raw_identity_recorded": False,
            "raw_message_recorded": False,
            "secret_recorded": False,
        }
    )
    _atomic_write(RECEIPT, payload, mode=0o600)
    _atomic_write(root / "RECEIPT.json", payload, mode=0o600)


def activate(candidate: Path, *, preflight_only: bool) -> dict[str, object]:
    validate_candidate(candidate)
    verify_prestate()
    plan = plan_bytes()
    if preflight_only:
        return {"plan_sha256": digest_bytes(plan), "status": "ready"}
    root = backup(plan)
    install_candidate(candidate)
    gateways_stopped = False
    selector_mutated = False
    try:
        quiesce_gateways()
        gateways_stopped = True
        binding, selector = target_binding(digest_bytes(plan))
        myuna_gid = grp.getgrnam("myuna").gr_gid
        _atomic_write(CORE_BINDING, binding, mode=0o640, gid=myuna_gid)
        _atomic_write(CORE_SELECTOR, selector, mode=0o644)
        selector_mutated = True
        systemctl("daemon-reload")
        systemctl("restart", CORE_SERVICE)
        verify_target()
        restore_gateways()
        gateways_stopped = False
        write_receipt(root, plan)
    except Exception:
        if selector_mutated:
            rollback(root)
        elif gateways_stopped:
            restore_gateways()
        raise
    return {
        "core_release": TARGET_RELEASE,
        "plan_sha256": digest_bytes(plan),
        "status": "ACTIVE_WAITING_OWNER_TELEGRAM_E2E_RETRY",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--preflight-only", action="store_true")
    arguments = parser.parse_args()
    try:
        result = activate(
            arguments.candidate,
            preflight_only=arguments.preflight_only,
        )
    except (ActivationRejected, OSError, ValueError, subprocess.SubprocessError):
        print(json.dumps({"status": "rejected"}, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
