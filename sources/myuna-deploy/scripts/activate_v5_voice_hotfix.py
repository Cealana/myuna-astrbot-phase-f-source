#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import grp
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any
from urllib.request import urlopen


OPERATION = "v5-voice-hotfix-dev-qq-activation-v1"
EXPECTED_DEPLOY_COMMIT = "a173eff2ae5fd4f1471a79dd081f0a3c2a59b760"
EXPECTED_CORE_COMMIT = "970405a987b12e00ef857e4a115c0ac1938fef84"
TARGET_CORE_COMMIT = "f0930a26077f5e9fb8f5f9840af7a2cbde0ac262"
EXPECTED_DEFINITION_COMMIT = "8b337f837b2cd5870164a3edb850c56cc7b34be9"
TARGET_DEFINITION_COMMIT = "8b337f837b2cd5870164a3edb850c56cc7b34be9"

BUILD_ID = "v5vh1-2755db85ca7e-h3977d01a-g5e782ef9-t85c51fd3-a5a5a558b"
RELEASE_ID = f"v5-{BUILD_ID}"
BASE_RELEASE_ID = "v5-2755db85ca7e-b1-dbc4b229-g9f993b18-a95b4a017-te2e33bb3"
SOURCE_SHA256 = "2755DB85CA7ED8182BF43A88787728D386EBB74279468734FDF9B17EE99C636B"
CASES_SHA256 = "F8F056BE6410AB47B301E496AE3F5D638E326B549A3FC291479FF48257F60F82"
GOLDEN_APPROVAL_SHA256 = "5A5A558BB70E4B5D0E08D06623F57930A6E2416E5BDB9982D0BAD9B1D5435A71"
CANDIDATE_SUMMARY_SHA256 = "E20C3FCCFF548B82223B48CB9A570310C6AF979E3604D8C6F84AC61CE49C5B51"
CANDIDATE_MANIFEST_SHA256 = "4B5BAD7AC7788358C84ABE5DD4DC203E9513AFD220A0392409704DD4AB5C88A8"
EVALUATION_SHA256 = "EEDCC468485CE892EF7EF9E5B0BC3AB987ED6E4DF9CA43AE6A2E09CA212A8514"

STAGED_DEPLOY_REPO = Path(__file__).resolve().parents[1]
LIVE_DEPLOY_REPO = Path("/srv/myuna/repos/deploy")
LIVE_CORE_REPO = Path("/srv/myuna/repos/core")
LIVE_DEFINITION_REPO = Path("/srv/myuna/repos/definition")
EXTERNAL_CANDIDATE = Path(
    "/srv/myuna/staging/definition-v5-voice-hotfix-approved/v5"
) / BUILD_ID
EVALUATION_SUMMARY = Path(
    "/var/lib/myuna/qq/voice-hotfix-tests/20260716T083623Z/summary.json"
)
CORE_RELEASE = Path("/srv/myuna/releases/core") / TARGET_CORE_COMMIT
DEFINITION_STAGING = LIVE_DEFINITION_REPO / "staging/v5" / BUILD_ID
DEFINITION_RELEASE = LIVE_DEFINITION_REPO / "releases/v5" / BUILD_ID
DEFINITION_CURRENT = Path("/srv/myuna/environments/dev/definition/current")
DEFINITION_PREVIOUS = Path("/srv/myuna/environments/dev/definition/previous")
DEFINITION_ACTIVATION = Path("/srv/myuna/environments/dev/definition/activation.json")
EXPECTED_CURRENT_RELEASE = LIVE_DEFINITION_REPO / (
    "releases/v5/2755db85ca7e-b1-dbc4b229-g9f993b18-a95b4a017-te2e33bb3"
)

QQ_ENV = Path("/etc/myuna/qq.env")
CAPABILITY_MANIFEST = Path("/etc/myuna/capabilities/qq-owner-v5.json")
CORE_DROPIN = Path(
    "/etc/systemd/system/myuna-core@qq.service.d/90-voice-hotfix.conf"
)
TARGET_ENV = STAGED_DEPLOY_REPO / "config/qq-owner-v5-voice-hotfix-1.env"
TARGET_CAPABILITY = (
    STAGED_DEPLOY_REPO / "config/capabilities/dev-v5-voice-hotfix-1.json"
)
TARGET_DROPIN = STAGED_DEPLOY_REPO / "systemd/myuna-core-qq-voice-hotfix-1.conf"

BACKUP_ROOT = Path("/var/backups/myuna/v5-voice-hotfix-activation-v1")
WINDOWS_BACKUP_ROOT = Path(
    "/mnt/c/Server-Critical-Backup/Myuna/Voice-Hotfix-Activation"
)
STATE_ROOT = Path("/var/lib/myuna/voice-hotfix-activation-v1")
RECEIPT_PATH = STATE_ROOT / "receipt.json"


class VoiceHotfixActivationError(RuntimeError):
    pass


def canonical_json(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _run(
    command: list[str],
    *,
    check: bool = True,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=check,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _git(repo: Path, *args: str, mutate: bool = False) -> subprocess.CompletedProcess[str]:
    command = [
        "git",
        "-c",
        f"safe.directory={repo}",
        "-C",
        str(repo),
        *args,
    ]
    if mutate:
        command = ["runuser", "-u", "myuna", "--", *command]
    return _run(command)


def _git_value(repo: Path, *args: str) -> str:
    return _git(repo, *args).stdout.strip()


def _write_atomic(path: Path, payload: bytes, *, mode: int, uid: int, gid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(payload)
        os.chmod(temporary, mode)
        os.chown(temporary, uid, gid)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VoiceHotfixActivationError(f"{label} is unavailable or invalid") from exc
    if not isinstance(value, dict):
        raise VoiceHotfixActivationError(f"{label} must be an object")
    return value


def _container_state(name: str) -> dict[str, object]:
    result = _run(
        [
            "docker",
            "inspect",
            "--format={{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.RestartCount}}",
            name,
        ],
        check=False,
    )
    if result.returncode != 0:
        return {"present": False, "healthy": False, "restart_count": None}
    parts = result.stdout.strip().split("|")
    return {
        "present": True,
        "healthy": parts[:2] == ["running", "healthy"],
        "restart_count": int(parts[2]),
    }


def _unit_active(unit: str) -> bool:
    return _run(["systemctl", "is-active", "--quiet", unit], check=False).returncode == 0


def _verify_manifest(root: Path, manifest: Path) -> int:
    verified = 0
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        try:
            expected, relative = line.split("  ", 1)
        except ValueError as exc:
            raise VoiceHotfixActivationError("invalid candidate manifest") from exc
        pure = PurePosixPath(relative)
        if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
            raise VoiceHotfixActivationError("unsafe candidate manifest path")
        candidate = root.joinpath(*pure.parts)
        if not candidate.is_file() or sha256_file(candidate) != expected.upper():
            raise VoiceHotfixActivationError(f"candidate manifest mismatch: {relative}")
        verified += 1
    if verified == 0:
        raise VoiceHotfixActivationError("candidate manifest is empty")
    return verified


def _target_deploy_commit() -> str:
    return _git_value(STAGED_DEPLOY_REPO, "rev-parse", "HEAD")


def _target_deploy_parent() -> str:
    return _git_value(STAGED_DEPLOY_REPO, "rev-parse", "HEAD^")


def build_activation_plan() -> dict[str, object]:
    candidate = _load_json(
        EXTERNAL_CANDIDATE / "evidence/build-summary.json",
        "inactive Definition candidate",
    )
    evaluation = _load_json(EVALUATION_SUMMARY, "voice hotfix evaluation")
    napcat = _container_state("myuna-napcat-dev")
    astrbot = _container_state("myuna-astrbot-dev")
    return {
        "operation": OPERATION,
        "scope": {
            "environment": "dev",
            "channel": "verified owner private QQ text only",
            "ordinary_myuna_chat_only": True,
        },
        "source": {
            "prior_deploy_commit": EXPECTED_DEPLOY_COMMIT,
            "target_deploy_commit": _target_deploy_commit(),
            "target_deploy_parent": _target_deploy_parent(),
            "prior_core_commit": EXPECTED_CORE_COMMIT,
            "target_core_commit": TARGET_CORE_COMMIT,
            "prior_definition_commit": EXPECTED_DEFINITION_COMMIT,
            "target_definition_commit": TARGET_DEFINITION_COMMIT,
            "candidate_build_id": candidate.get("build_id"),
            "candidate_summary_sha256": sha256_file(
                EXTERNAL_CANDIDATE / "evidence/build-summary.json"
            ),
            "candidate_manifest_sha256": sha256_file(
                EXTERNAL_CANDIDATE / "evidence/files.sha256"
            ),
            "combined_golden_cases_sha256": candidate.get("golden_cases_sha256"),
            "golden_approval_sha256": candidate.get("golden_approval_sha256"),
            "evaluation_summary_sha256": sha256_file(EVALUATION_SUMMARY),
        },
        "current": {
            "definition_release_id": BASE_RELEASE_ID,
            "definition_target": str(DEFINITION_CURRENT.resolve(strict=True)),
            "qq_env_sha256": sha256_file(QQ_ENV),
            "capability_manifest_sha256": sha256_file(CAPABILITY_MANIFEST),
            "credentials_dropin_sha256": sha256_file(
                Path("/etc/systemd/system/myuna-core@qq.service.d/credentials.conf")
            ),
            "napcat": napcat,
            "astrbot": astrbot,
            "core_active": _unit_active("myuna-core@qq.service"),
            "minecraft_active": _unit_active("minecraft.service"),
        },
        "target": {
            "definition_release_id": RELEASE_ID,
            "definition_build_id": BUILD_ID,
            "core_release_path": str(CORE_RELEASE),
            "qq_env_sha256": sha256_file(TARGET_ENV),
            "capability_manifest_sha256": sha256_file(TARGET_CAPABILITY),
            "core_dropin_sha256": sha256_file(TARGET_DROPIN),
        },
        "evidence": {
            "definition_tests_passed": 19,
            "core_tests_passed": 100,
            "deploy_tests_passed": 58,
            "voice_cases": evaluation.get("case_count"),
            "raw_auto_passed": evaluation.get("raw_auto_passed"),
            "normalized_auto_passed": evaluation.get("normalized_auto_passed"),
            "capability_violation_count": evaluation.get(
                "capability_violation_count"
            ),
            "actual_cost_usd": evaluation.get("actual_cost_usd"),
            "known_nonblocking_observation": (
                "the English synthetic prompt received a natural Chinese reply; "
                "the terminal punctuation contract passed and language policy is unchanged"
            ),
            "manual_voice_review": (
                "three cases directly satisfied their semantic review notes; the English "
                "case is accepted only for punctuation evidence, not as an English-language pass"
            ),
        },
        "changes": {
            "definition_new_immutable_release": True,
            "core_new_immutable_release": True,
            "definition_pointer_atomic_switch": True,
            "qq_core_restart": True,
            "napcat_restart": False,
            "astrbot_restart": False,
            "minecraft_restart": False,
            "database_writes": False,
            "identity_writes": False,
            "memory_read": False,
            "memory_write": False,
            "tools": False,
            "vision": False,
            "groups": False,
            "discord": False,
            "network_listener_change": False,
            "provider_or_budget_change": False,
        },
        "backup": {
            "wsl_root_only": True,
            "c_drive_verified_copy": True,
            "items": [
                "Definition registry and activation record",
                "QQ environment",
                "capability manifest",
                "systemd drop-in state",
                "prior Definition pointer",
            ],
        },
        "rollback": {
            "automatic_on_apply_failure": True,
            "definition_target": str(EXPECTED_CURRENT_RELEASE),
            "restore_registry": True,
            "restore_environment_and_capabilities": True,
            "remove_new_core_dropin": True,
            "restart_original_qq_core": True,
            "source_commits_may_remain_inactive_for_audit": True,
        },
    }


def activation_digest(plan: dict[str, object]) -> str:
    return sha256(canonical_json(plan)).hexdigest()


def ensure_preconditions(plan: dict[str, object]) -> None:
    if os.geteuid() != 0:
        raise VoiceHotfixActivationError("run as root from the local server console")
    allowed_heads = (
        (LIVE_DEPLOY_REPO, {EXPECTED_DEPLOY_COMMIT, _target_deploy_commit()}),
        (LIVE_CORE_REPO, {EXPECTED_CORE_COMMIT}),
        (LIVE_DEFINITION_REPO, {EXPECTED_DEFINITION_COMMIT, TARGET_DEFINITION_COMMIT}),
    )
    for repo, allowed in allowed_heads:
        if _git_value(repo, "rev-parse", "HEAD") not in allowed:
            raise VoiceHotfixActivationError(f"live repository changed: {repo.name}")
        if _git_value(repo, "status", "--porcelain"):
            raise VoiceHotfixActivationError(f"live repository is not clean: {repo.name}")
    if _git(
        STAGED_DEPLOY_REPO,
        "merge-base",
        "--is-ancestor",
        EXPECTED_DEPLOY_COMMIT,
        _target_deploy_commit(),
    ).returncode != 0:
        raise VoiceHotfixActivationError("staged deploy branch is not a fast-forward")
    if _git(LIVE_CORE_REPO, "merge-base", "--is-ancestor", EXPECTED_CORE_COMMIT, TARGET_CORE_COMMIT).returncode != 0:
        raise VoiceHotfixActivationError("Core hotfix is not descended from the live commit")
    if _git(LIVE_DEFINITION_REPO, "merge-base", "--is-ancestor", EXPECTED_DEFINITION_COMMIT, TARGET_DEFINITION_COMMIT).returncode != 0:
        raise VoiceHotfixActivationError("Definition hotfix is not descended from the live commit")
    if DEFINITION_CURRENT.resolve(strict=True) != EXPECTED_CURRENT_RELEASE.resolve(strict=True):
        raise VoiceHotfixActivationError("current Definition pointer changed")
    if DEFINITION_PREVIOUS.exists() or DEFINITION_PREVIOUS.is_symlink():
        raise VoiceHotfixActivationError("unexpected previous Definition pointer exists")
    if CORE_DROPIN.exists() or DEFINITION_RELEASE.exists():
        raise VoiceHotfixActivationError("voice hotfix runtime target already exists")
    if sha256_file(EXTERNAL_CANDIDATE / "evidence/build-summary.json") != CANDIDATE_SUMMARY_SHA256:
        raise VoiceHotfixActivationError("candidate summary hash changed")
    if sha256_file(EXTERNAL_CANDIDATE / "evidence/files.sha256") != CANDIDATE_MANIFEST_SHA256:
        raise VoiceHotfixActivationError("candidate manifest hash changed")
    _verify_manifest(EXTERNAL_CANDIDATE, EXTERNAL_CANDIDATE / "evidence/files.sha256")
    candidate = _load_json(
        EXTERNAL_CANDIDATE / "evidence/build-summary.json", "candidate summary"
    )
    if (
        candidate.get("status") != "hotfix-staging-candidate"
        or candidate.get("build_id") != BUILD_ID
        or candidate.get("source_sha256") != SOURCE_SHA256
        or candidate.get("golden_cases_sha256") != CASES_SHA256
        or candidate.get("golden_approval_sha256") != GOLDEN_APPROVAL_SHA256
        or candidate.get("approved") is not False
        or candidate.get("active") is not False
        or candidate.get("activation_allowed") is not False
        or candidate.get("golden", {}).get("effective", {}).get("release_gate_ready")
        is not True
    ):
        raise VoiceHotfixActivationError("inactive candidate gate failed")
    evaluation = _load_json(EVALUATION_SUMMARY, "voice evaluation")
    if sha256_file(EVALUATION_SUMMARY) != EVALUATION_SHA256 or any(
        (
            evaluation.get("candidate_build_id") != BUILD_ID,
            evaluation.get("status") != "automatic_pass",
            evaluation.get("case_count") != 4,
            evaluation.get("raw_auto_passed") != 4,
            evaluation.get("normalized_auto_passed") != 4,
            evaluation.get("capability_violation_count") != 0,
            evaluation.get("memory_read") is not False,
            evaluation.get("memory_write") is not False,
            evaluation.get("tools") is not False,
            evaluation.get("qq_delivery") is not False,
        )
    ):
        raise VoiceHotfixActivationError("voice evaluation gate failed")
    current = plan["current"]
    if not isinstance(current, dict) or any(
        (
            current.get("core_active") is not True,
            current.get("minecraft_active") is not True,
            current.get("napcat", {}).get("healthy") is not True,
            current.get("astrbot", {}).get("healthy") is not True,
            current.get("napcat", {}).get("restart_count") != 0,
            current.get("astrbot", {}).get("restart_count") != 0,
        )
    ):
        raise VoiceHotfixActivationError("live service health precondition failed")


def _backup_file(source: Path, destination: Path) -> dict[str, str]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    os.chmod(destination, 0o600)
    return {
        "name": source.name,
        "sha256": sha256_file(source),
        "backup_sha256": sha256_file(destination),
    }


def create_backups(stamp: str, plan: dict[str, object]) -> tuple[Path, list[dict[str, str]]]:
    root = BACKUP_ROOT / stamp
    windows = WINDOWS_BACKUP_ROOT / stamp
    root.mkdir(parents=True, mode=0o700)
    windows.mkdir(parents=True, mode=0o700)
    entries: list[dict[str, str]] = []
    files = {
        "qq.env": QQ_ENV,
        "qq-owner-v5.json": CAPABILITY_MANIFEST,
        "credentials.conf": Path(
            "/etc/systemd/system/myuna-core@qq.service.d/credentials.conf"
        ),
        "registry.json": LIVE_DEFINITION_REPO / "registry.json",
        "activation.json": DEFINITION_ACTIVATION,
    }
    for name, source in files.items():
        entry = _backup_file(source, root / name)
        windows_entry = _backup_file(source, windows / name)
        if entry["sha256"] != windows_entry["backup_sha256"]:
            raise VoiceHotfixActivationError("C-drive backup verification failed")
        entries.append(entry)
    pointer = {
        "current": str(DEFINITION_CURRENT.resolve(strict=True)),
        "previous_existed": DEFINITION_PREVIOUS.exists() or DEFINITION_PREVIOUS.is_symlink(),
        "plan_digest": activation_digest(plan),
    }
    payload = json.dumps(pointer, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    for destination in (root / "pointers.json", windows / "pointers.json"):
        _write_atomic(destination, payload, mode=0o600, uid=0, gid=0)
    if sha256_file(root / "pointers.json") != sha256_file(windows / "pointers.json"):
        raise VoiceHotfixActivationError("pointer backup verification failed")
    return root, entries


def _make_read_only(root: Path) -> None:
    shutil.chown(root, user="root", group="myuna")
    for path in root.rglob("*"):
        shutil.chown(path, user="root", group="myuna")
    for path in sorted(root.rglob("*"), reverse=True):
        path.chmod(0o550 if path.is_dir() else 0o440)
    root.chmod(0o550)


def _verify_core_release(root: Path) -> None:
    if (root / "SOURCE_COMMIT").read_text(encoding="utf-8").strip() != TARGET_CORE_COMMIT:
        raise VoiceHotfixActivationError("Core release commit mismatch")
    _verify_manifest(root, root / "RELEASE_FILES.sha256")
    for path in (root, *root.rglob("*")):
        if stat.S_IMODE(path.stat().st_mode) & 0o222:
            raise VoiceHotfixActivationError("Core release is writable")


def build_core_release() -> None:
    if CORE_RELEASE.exists():
        _verify_core_release(CORE_RELEASE)
        return
    CORE_RELEASE.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{TARGET_CORE_COMMIT[:12]}-", dir=CORE_RELEASE.parent)
    )
    archive = temporary.parent / f".{temporary.name}.tar"
    try:
        with archive.open("wb") as handle:
            result = subprocess.run(
                [
                    "git",
                    "-c",
                    f"safe.directory={LIVE_CORE_REPO}",
                    "-C",
                    str(LIVE_CORE_REPO),
                    "archive",
                    "--format=tar",
                    TARGET_CORE_COMMIT,
                ],
                check=False,
                stdout=handle,
                stderr=subprocess.PIPE,
            )
        if result.returncode != 0:
            raise VoiceHotfixActivationError("could not archive Core hotfix commit")
        with tarfile.open(archive, "r:") as bundle:
            bundle.extractall(temporary, filter="data")
        (temporary / "SOURCE_COMMIT").write_text(TARGET_CORE_COMMIT + "\n", encoding="utf-8")
        manifest = temporary / "RELEASE_FILES.sha256"
        lines = []
        for path in sorted(item for item in temporary.rglob("*") if item.is_file()):
            if path == manifest:
                continue
            lines.append(f"{sha256_file(path)}  {path.relative_to(temporary).as_posix()}\n")
        manifest.write_text("".join(lines), encoding="utf-8")
        os.replace(temporary, CORE_RELEASE)
        _make_read_only(CORE_RELEASE)
        _verify_core_release(CORE_RELEASE)
    finally:
        archive.unlink(missing_ok=True)
        if temporary.exists():
            shutil.rmtree(temporary)


def _fast_forward(repo: Path, target: str) -> None:
    _git(repo, "merge", "--ff-only", target, mutate=True)


def ensure_definition_candidate() -> None:
    if DEFINITION_STAGING.exists():
        summary = _load_json(
            DEFINITION_STAGING / "evidence/build-summary.json",
            "repository staging candidate",
        )
        if summary.get("build_id") != BUILD_ID:
            raise VoiceHotfixActivationError("repository staging candidate mismatch")
        return
    parent = DEFINITION_STAGING.parent
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{BUILD_ID}-", dir=parent))
    try:
        shutil.copytree(EXTERNAL_CANDIDATE, temporary, dirs_exist_ok=True)
        copied_summary = temporary / "evidence/build-summary.json"
        copied_manifest = temporary / "evidence/files.sha256"
        if (
            sha256_file(copied_summary) != CANDIDATE_SUMMARY_SHA256
            or sha256_file(copied_manifest) != CANDIDATE_MANIFEST_SHA256
        ):
            raise VoiceHotfixActivationError("copied candidate evidence mismatch")
        _verify_manifest(temporary, copied_manifest)
        shutil.chown(temporary, user="myuna", group="myuna")
        for path in temporary.rglob("*"):
            shutil.chown(path, user="myuna", group="myuna")
        for path in sorted(temporary.rglob("*"), reverse=True):
            path.chmod(0o550 if path.is_dir() else 0o440)
        temporary.chmod(0o550)
        os.replace(temporary, DEFINITION_STAGING)
    finally:
        if temporary.exists():
            for path in (temporary, *temporary.rglob("*")):
                try:
                    path.chmod(0o700 if path.is_dir() else 0o600)
                except OSError:
                    pass
            shutil.rmtree(temporary, ignore_errors=True)


def create_release_approval(digest: str, stamp: str) -> Path:
    evaluation = _load_json(EVALUATION_SUMMARY, "voice evaluation")
    approval = {
        "schema_version": 1,
        "scope": "definition-v5-dev-qq-voice-hotfix-only",
        "version": "v5",
        "build_id": BUILD_ID,
        "source_sha256": SOURCE_SHA256,
        "approved": True,
        "approved_by": "server-owner",
        "approved_at": datetime.now(timezone.utc).astimezone().isoformat(),
        "allowed_environments": ["dev"],
        "activation_plan_digest": digest,
        "authorizations": {
            "create_release": True,
            "activate_dev": True,
            "qq_owner_private_text": True,
            "restart_qq_core": True,
            "restart_channel_containers": False,
            "real_memory": False,
            "tools": False,
            "external_listener": False,
        },
        "golden_evaluation": {
            "run_id": EVALUATION_SUMMARY.parent.name,
            "summary_sha256": sha256_file(EVALUATION_SUMMARY),
            "case_count": evaluation["case_count"],
            "raw_auto_passed": evaluation["raw_auto_passed"],
            "normalized_auto_passed": evaluation["normalized_auto_passed"],
            "capability_guard_passed": evaluation["capability_violation_count"] == 0,
        },
    }
    path = STATE_ROOT / stamp / "release-approval.json"
    _write_atomic(
        path,
        json.dumps(approval, ensure_ascii=False, indent=2, sort_keys=True).encode(
            "utf-8"
        )
        + b"\n",
        mode=0o640,
        uid=0,
        gid=grp.getgrnam("myuna").gr_gid,
    )
    return path


def promote_and_activate_definition(approval: Path, digest: str) -> None:
    _run(
        [
            "runuser",
            "-u",
            "myuna",
            "--",
            "python3",
            str(LIVE_DEFINITION_REPO / "tools/promote_release.py"),
            "--repo",
            str(LIVE_DEFINITION_REPO),
            "--version",
            "v5",
            "--build-id",
            BUILD_ID,
            "--approval",
            str(approval),
            "--evaluation-summary",
            str(EVALUATION_SUMMARY),
            "--approved-plan-digest",
            digest,
        ]
    )
    _run(
        [
            "runuser",
            "-u",
            "myuna",
            "--",
            "python3",
            str(LIVE_DEPLOY_REPO / "scripts/activate_definition_release.py"),
            "--environment",
            "dev",
            "--release-root",
            str(DEFINITION_RELEASE),
            "--registry",
            str(LIVE_DEFINITION_REPO / "registry.json"),
            "--approval",
            str(approval),
            "--environments-root",
            "/srv/myuna/environments",
        ]
    )


def _install_runtime_configuration() -> None:
    _run(["install", "-o", "root", "-g", "myuna", "-m", "0640", str(LIVE_DEPLOY_REPO / TARGET_ENV.relative_to(STAGED_DEPLOY_REPO)), str(QQ_ENV)])
    _run(["install", "-o", "root", "-g", "root", "-m", "0644", str(LIVE_DEPLOY_REPO / TARGET_CAPABILITY.relative_to(STAGED_DEPLOY_REPO)), str(CAPABILITY_MANIFEST)])
    _run(["install", "-o", "root", "-g", "root", "-m", "0644", str(LIVE_DEPLOY_REPO / TARGET_DROPIN.relative_to(STAGED_DEPLOY_REPO)), str(CORE_DROPIN)])
    _run(["systemctl", "daemon-reload"])


def _wait_core_ready(timeout_seconds: int = 45) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _unit_active("myuna-core@qq.service"):
            try:
                with urlopen("http://127.0.0.1:18081/readyz", timeout=2) as response:
                    if response.status == 200:
                        return
            except OSError:
                pass
        time.sleep(1)
    raise VoiceHotfixActivationError("QQ Core did not become ready")


def postconditions(plan: dict[str, object]) -> None:
    if DEFINITION_CURRENT.resolve(strict=True) != DEFINITION_RELEASE.resolve(strict=True):
        raise VoiceHotfixActivationError("Definition pointer did not switch")
    if sha256_file(QQ_ENV) != plan["target"]["qq_env_sha256"]:  # type: ignore[index]
        raise VoiceHotfixActivationError("QQ environment target hash mismatch")
    if sha256_file(CAPABILITY_MANIFEST) != plan["target"]["capability_manifest_sha256"]:  # type: ignore[index]
        raise VoiceHotfixActivationError("capability target hash mismatch")
    if sha256_file(CORE_DROPIN) != plan["target"]["core_dropin_sha256"]:  # type: ignore[index]
        raise VoiceHotfixActivationError("Core drop-in target hash mismatch")
    _verify_core_release(CORE_RELEASE)
    _wait_core_ready()
    pid = _run(["systemctl", "show", "myuna-core@qq.service", "-p", "MainPID", "--value"]).stdout.strip()
    if not pid.isdigit() or Path(f"/proc/{pid}/cwd").resolve(strict=True) != CORE_RELEASE:
        raise VoiceHotfixActivationError("running Core did not use the immutable hotfix release")
    for name in ("myuna-napcat-dev", "myuna-astrbot-dev"):
        state = _container_state(name)
        if state.get("healthy") is not True or state.get("restart_count") != 0:
            raise VoiceHotfixActivationError(f"channel container health changed: {name}")
    if not _unit_active("minecraft.service"):
        raise VoiceHotfixActivationError("Minecraft stopped during activation")


def _atomic_symlink(path: Path, target: Path) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.symlink_to(target, target_is_directory=True)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def rollback(backup: Path) -> None:
    _run(["systemctl", "stop", "myuna-core@qq.service"], check=False)
    _run(["install", "-o", "root", "-g", "myuna", "-m", "0640", str(backup / "qq.env"), str(QQ_ENV)], check=False)
    _run(["install", "-o", "root", "-g", "root", "-m", "0644", str(backup / "qq-owner-v5.json"), str(CAPABILITY_MANIFEST)], check=False)
    CORE_DROPIN.unlink(missing_ok=True)
    _run(["install", "-o", "myuna", "-g", "myuna", "-m", "0640", str(backup / "registry.json"), str(LIVE_DEFINITION_REPO / "registry.json")], check=False)
    _run(["install", "-o", "myuna", "-g", "myuna", "-m", "0640", str(backup / "activation.json"), str(DEFINITION_ACTIVATION)], check=False)
    try:
        _atomic_symlink(DEFINITION_CURRENT, EXPECTED_CURRENT_RELEASE)
        DEFINITION_PREVIOUS.unlink(missing_ok=True)
    except OSError:
        pass
    if DEFINITION_RELEASE.exists() and DEFINITION_RELEASE.parent.resolve() == (LIVE_DEFINITION_REPO / "releases/v5").resolve():
        for path in (DEFINITION_RELEASE, *DEFINITION_RELEASE.rglob("*")):
            try:
                path.chmod(0o700 if path.is_dir() else 0o600)
            except OSError:
                pass
        shutil.rmtree(DEFINITION_RELEASE, ignore_errors=True)
    _run(["systemctl", "daemon-reload"], check=False)
    _run(["systemctl", "restart", "myuna-core@qq.service"], check=False)


def _commit_definition_release() -> str:
    _git(
        LIVE_DEFINITION_REPO,
        "add",
        "registry.json",
        f"releases/v5/{BUILD_ID}",
        mutate=True,
    )
    _git(
        LIVE_DEFINITION_REPO,
        "commit",
        "-m",
        "release(definition): activate v5 voice hotfix",
        mutate=True,
    )
    return _git_value(LIVE_DEFINITION_REPO, "rev-parse", "HEAD")


def public_receipt(
    digest: str,
    plan: dict[str, object],
    backups: list[dict[str, str]],
    definition_commit: str,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "operation": OPERATION,
        "plan_digest": digest,
        "result": "v5-voice-hotfix-active-on-qq-core",
        "definition_release_id": RELEASE_ID,
        "definition_build_id": BUILD_ID,
        "core_release_commit": TARGET_CORE_COMMIT,
        "definition_repository_commit": definition_commit,
        "verified_backups": backups,
        "core": "ready",
        "napcat": "healthy-unchanged",
        "astrbot": "healthy-unchanged",
        "minecraft": "active-unchanged",
        "memory_read": False,
        "memory_write": False,
        "tools": False,
        "channel_containers_restarted": False,
        "database_changed": False,
        "known_nonblocking_observation": plan["evidence"]["known_nonblocking_observation"],  # type: ignore[index]
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--approved-plan-digest")
    parser.add_argument("--check-preconditions", action="store_true")
    args = parser.parse_args()
    plan = build_activation_plan()
    digest = activation_digest(plan)
    if not args.apply:
        if args.check_preconditions:
            ensure_preconditions(plan)
        print(
            json.dumps(
                {
                    "apply_requested": False,
                    "plan": plan,
                    "plan_digest": digest,
                    "preconditions_checked": args.check_preconditions,
                    "preconditions_passed": args.check_preconditions,
                    "result": "preview-only-no-writes",
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if not args.approved_plan_digest or not hmac.compare_digest(
        args.approved_plan_digest,
        digest,
    ):
        raise VoiceHotfixActivationError("voice hotfix activation digest does not match approval")
    ensure_preconditions(plan)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup, backups = create_backups(stamp, plan)
    succeeded = False
    try:
        build_core_release()
        _fast_forward(LIVE_DEPLOY_REPO, plan["source"]["target_deploy_commit"])  # type: ignore[index]
        _fast_forward(LIVE_DEFINITION_REPO, TARGET_DEFINITION_COMMIT)
        ensure_definition_candidate()
        approval = create_release_approval(digest, stamp)
        _run(["systemctl", "stop", "myuna-core@qq.service"])
        promote_and_activate_definition(approval, digest)
        _install_runtime_configuration()
        _run(["systemctl", "start", "myuna-core@qq.service"])
        postconditions(plan)
        definition_commit = _commit_definition_release()
        receipt = public_receipt(digest, plan, backups, definition_commit)
        payload = json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        _write_atomic(RECEIPT_PATH, payload, mode=0o600, uid=0, gid=0)
        windows_receipt = WINDOWS_BACKUP_ROOT / stamp / "receipt.json"
        _write_atomic(windows_receipt, payload, mode=0o600, uid=0, gid=0)
        if sha256_file(RECEIPT_PATH) != sha256_file(windows_receipt):
            raise VoiceHotfixActivationError("receipt C-drive copy verification failed")
        print(json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True))
        succeeded = True
    finally:
        if not succeeded:
            rollback(backup)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.SubprocessError, VoiceHotfixActivationError) as exc:
        print(f"v5 voice hotfix activation rejected: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
