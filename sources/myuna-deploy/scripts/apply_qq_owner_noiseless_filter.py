#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

try:
    from scripts.apply_owner_binding_pending import (
        _run,
        _sha256_file,
        _write_atomic,
        ensure_channel_healthy,
    )
except ModuleNotFoundError:
    from apply_owner_binding_pending import (  # type: ignore[no-redef]
        _run,
        _sha256_file,
        _write_atomic,
        ensure_channel_healthy,
    )


OPERATION = "qq-owner-noiseless-event-filter-v1"
PRIOR_PLAN_DIGEST = "6f344516a030a6f61f04a07d012ed12fb01cd584b16a1b32235db97c5b000386"
EXPECTED_LIVE_COMMIT = "d5b5aaf288c0467fa139874107ff9f5acb7038f7"

STAGED_REPO = Path(__file__).resolve().parents[1]
LIVE_REPO = Path("/srv/myuna/repos/deploy")
PLUGIN_RELATIVE = Path("channels/astrbot-qq/plugin/myuna_gateway")
CURRENT_PLUGIN_ROOT = Path(
    "/srv/myuna/channel-adapters/astrbot_plugin_myuna_gateway/v1"
)
CHANNEL_ENV_PATH = Path("/etc/myuna-gateway/astrbot-napcat-dev.env")
PRIOR_RECEIPT_PATH = Path(
    "/var/lib/myuna-gateway/qq-owner-runtime-activation-v1-receipt.json"
)
FINAL_RECEIPT_PATH = Path(
    "/var/lib/myuna-gateway/qq-owner-noiseless-filter-v1-receipt.json"
)
BACKUP_ROOT = Path("/var/backups/myuna/qq-owner-runtime/noiseless-filter-v1")
WINDOWS_BACKUP_ROOT = Path(
    "/mnt/c/Server-Critical-Backup/Myuna/QQ-Runtime-Hotfix"
)
PLUGIN_FILES = ("main.py", "protocol.py")


class NoiselessFilterError(RuntimeError):
    pass


def canonical_json(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return _run(
        [
            "/usr/sbin/runuser",
            "-u",
            "myuna",
            "--",
            "git",
            "-C",
            str(repo),
            *args,
        ],
        check=check,
    )


def _git_value(repo: Path, *args: str) -> str:
    return _git(repo, *args).stdout.strip()


def _target_commit() -> str:
    return _git_value(STAGED_REPO, "rev-parse", "HEAD")


def _target_parent() -> str:
    return _git_value(STAGED_REPO, "rev-parse", "HEAD^")


def _target_plugin_root(target_commit: str) -> Path:
    return Path(
        "/srv/myuna/channel-adapters/astrbot_plugin_myuna_gateway"
    ) / f"v1.1-noiseless-{target_commit[:12]}"


def _plugin_hashes(root: Path) -> dict[str, str]:
    return {name: _sha256_file(root / name) for name in PLUGIN_FILES}


def build_update_plan() -> dict[str, object]:
    target_commit = _target_commit()
    hashes = _plugin_hashes(STAGED_REPO / PLUGIN_RELATIVE)
    plugin_bundle_sha256 = sha256(canonical_json(hashes)).hexdigest()
    return {
        "backup": {
            "c_drive_verified_copy": True,
            "database_backup": False,
            "previous_plugin_files": True,
        },
        "behavior": {
            "group_events": "silent-drop",
            "invalid_account_events": "silent-drop",
            "non_plain_private_events": "silent-drop",
            "self_echo_events": "silent-drop-before-signing",
            "verified_owner_private_plain_text": "unchanged",
        },
        "capabilities_unchanged": {
            "deepseek_daily_budget_usd": "2.00",
            "group_chat": False,
            "memory_read": False,
            "memory_write": False,
            "tools": False,
            "vision": False,
        },
        "database": {
            "backup_required": False,
            "migration": None,
            "writes": False,
        },
        "deployment": {
            "astrbot_recreated": True,
            "auto_start_changed": False,
            "core_restarted": False,
            "live_repo_fast_forward": True,
            "napcat_recreated": False,
            "target_plugin_root": str(_target_plugin_root(target_commit)),
        },
        "model": {
            "api_call_by_update": False,
            "provider_or_routing_changed": False,
        },
        "operation": OPERATION,
        "prior_runtime_plan_digest": PRIOR_PLAN_DIGEST,
        "rollback": {
            "git_compensating_revert": True,
            "plugin_pointer_restore": str(CURRENT_PLUGIN_ROOT),
            "recreate_astrbot_after_restore": True,
        },
        "source": {
            "plugin_bundle_sha256": plugin_bundle_sha256,
            "plugin_files": hashes,
            "prior_deploy_commit": EXPECTED_LIVE_COMMIT,
            "target_deploy_commit": target_commit,
            "target_parent_commit": _target_parent(),
        },
    }


def update_digest(plan: dict[str, object]) -> str:
    return sha256(canonical_json(plan)).hexdigest()


def _unit_active(unit: str) -> bool:
    return _run(
        ["systemctl", "is-active", "--quiet", unit],
        check=False,
    ).returncode == 0


def _read_prior_receipt() -> dict[str, object]:
    try:
        payload = json.loads(PRIOR_RECEIPT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NoiselessFilterError("approved QQ runtime receipt is unavailable") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("plan_digest") != PRIOR_PLAN_DIGEST
        or payload.get("result") != "qq-owner-private-runtime-ready-for-first-live-test"
    ):
        raise NoiselessFilterError("approved QQ runtime receipt does not match")
    return payload


def _plugin_root_line() -> str:
    lines = CHANNEL_ENV_PATH.read_text(encoding="utf-8").splitlines()
    matches = [line for line in lines if line.startswith("CHANNEL_PLUGIN_ROOT=")]
    if len(matches) != 1:
        raise NoiselessFilterError("channel plugin root is ambiguous")
    return matches[0]


def _set_plugin_root(expected: Path, replacement: Path) -> None:
    stat = CHANNEL_ENV_PATH.stat()
    old_line = f"CHANNEL_PLUGIN_ROOT={expected}"
    new_line = f"CHANNEL_PLUGIN_ROOT={replacement}"
    text = CHANNEL_ENV_PATH.read_text(encoding="utf-8")
    if text.count(old_line) != 1 or new_line in text:
        raise NoiselessFilterError("channel plugin pointer precondition failed")
    updated = text.replace(old_line, new_line, 1)
    _write_atomic(
        CHANNEL_ENV_PATH,
        updated.encode("utf-8"),
        mode=stat.st_mode & 0o777,
        uid=stat.st_uid,
        gid=stat.st_gid,
    )


def _container_healthy(name: str) -> bool:
    result = _run(
        [
            "docker",
            "inspect",
            "--format={{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}",
            name,
        ],
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() == "running|healthy"


def _wait_container_healthy(name: str, timeout_seconds: int = 120) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _container_healthy(name):
            return
        time.sleep(2)
    raise NoiselessFilterError(f"container did not become healthy: {name}")


def _recreate_astrbot() -> None:
    _run(
        [
            "docker",
            "compose",
            "--env-file",
            str(CHANNEL_ENV_PATH),
            "-f",
            str(LIVE_REPO / "channels/astrbot-qq/compose.dev.yml"),
            "up",
            "-d",
            "--no-deps",
            "--force-recreate",
            "astrbot",
        ],
        timeout=180,
    )
    _wait_container_healthy("myuna-astrbot-dev")


def ensure_preconditions() -> None:
    if os.geteuid() != 0:
        raise NoiselessFilterError("run as root from the local server console")
    if _git_value(STAGED_REPO, "status", "--porcelain"):
        raise NoiselessFilterError("staged update repository must be clean")
    if _target_parent() != EXPECTED_LIVE_COMMIT:
        raise NoiselessFilterError("target update is not a single fast-forward commit")
    if _git_value(LIVE_REPO, "rev-parse", "HEAD") != EXPECTED_LIVE_COMMIT:
        raise NoiselessFilterError("live deploy commit changed")
    if _git_value(LIVE_REPO, "status", "--porcelain"):
        raise NoiselessFilterError("live deploy repository must be clean")
    if _git(
        LIVE_REPO,
        "merge-base",
        "--is-ancestor",
        EXPECTED_LIVE_COMMIT,
        _target_commit(),
        check=False,
    ).returncode != 0:
        raise NoiselessFilterError("target commit is not available to the live repository")
    _read_prior_receipt()
    if _plugin_root_line() != f"CHANNEL_PLUGIN_ROOT={CURRENT_PLUGIN_ROOT}":
        raise NoiselessFilterError("current channel plugin pointer changed")
    if _plugin_hashes(CURRENT_PLUGIN_ROOT) != _plugin_hashes(LIVE_REPO / PLUGIN_RELATIVE):
        raise NoiselessFilterError("current plugin files do not match the live commit")
    target_text = (STAGED_REPO / PLUGIN_RELATIVE / "main.py").read_text(
        encoding="utf-8"
    )
    if (
        "event.get_self_id()" not in target_text
        or "should_forward_private_plain_text" not in target_text
        or "当前安全入口只接收纯文字私聊" in target_text
    ):
        raise NoiselessFilterError("target plugin does not implement the approved filter")
    for unit in (
        "myuna-core@qq.service",
        "myuna-qq-owner-runtime-dev.socket",
        "myuna-astrbot-qq-dev.service",
    ):
        if not _unit_active(unit):
            raise NoiselessFilterError(f"required service is inactive: {unit}")
    for unit in (
        "myuna-core@dev.service",
        "myuna-retrieval-worker-dev.service",
        "myuna-channel-gateway-dev.service",
    ):
        if _unit_active(unit):
            raise NoiselessFilterError(f"excluded service became active: {unit}")
    ensure_channel_healthy()
    target_root = _target_plugin_root(_target_commit())
    if target_root.exists() or FINAL_RECEIPT_PATH.exists():
        raise NoiselessFilterError("noiseless filter activation gate is not clean")


def _copy_verified(source: Path, destination: Path) -> dict[str, str]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    source_hash = _sha256_file(source)
    if _sha256_file(destination) != source_hash:
        raise NoiselessFilterError("backup copy hash mismatch")
    return {
        "filename": destination.name,
        "sha256": source_hash,
    }


def _backup_current_plugin(run_stamp: str) -> list[dict[str, str]]:
    linux_root = BACKUP_ROOT / run_stamp
    windows_root = WINDOWS_BACKUP_ROOT / f"Owner-QQ-Noiseless-v1-{run_stamp}"
    records: list[dict[str, str]] = []
    for name in PLUGIN_FILES:
        source = CURRENT_PLUGIN_ROOT / name
        linux_record = _copy_verified(source, linux_root / f"pre-{name}")
        windows_record = _copy_verified(source, windows_root / f"pre-{name}")
        if linux_record["sha256"] != windows_record["sha256"]:
            raise NoiselessFilterError("Windows backup hash mismatch")
        records.append(linux_record)
    return records


def _install_target_plugin(target_root: Path) -> None:
    source_root = STAGED_REPO / PLUGIN_RELATIVE
    for name in PLUGIN_FILES:
        destination = target_root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        _run(
            [
                "install",
                "-o",
                "root",
                "-g",
                "root",
                "-m",
                "0644",
                str(source_root / name),
                str(destination),
            ]
        )
    if _plugin_hashes(target_root) != _plugin_hashes(source_root):
        raise NoiselessFilterError("installed plugin hash mismatch")


def _postconditions(target_commit: str, target_root: Path) -> None:
    if _git_value(LIVE_REPO, "rev-parse", "HEAD") != target_commit:
        raise NoiselessFilterError("live deploy repository did not fast-forward")
    if _git_value(LIVE_REPO, "status", "--porcelain"):
        raise NoiselessFilterError("live deploy repository is not clean")
    if _plugin_root_line() != f"CHANNEL_PLUGIN_ROOT={target_root}":
        raise NoiselessFilterError("new plugin pointer was not installed")
    if _plugin_hashes(target_root) != _plugin_hashes(LIVE_REPO / PLUGIN_RELATIVE):
        raise NoiselessFilterError("new plugin files do not match the live commit")
    if not _container_healthy("myuna-astrbot-dev"):
        raise NoiselessFilterError("AstrBot is not healthy")
    if not _container_healthy("myuna-napcat-dev"):
        raise NoiselessFilterError("NapCat is not healthy")
    for unit in ("myuna-core@qq.service", "myuna-qq-owner-runtime-dev.socket"):
        if not _unit_active(unit):
            raise NoiselessFilterError(f"required service stopped: {unit}")


def _rollback(target_commit: str, target_root: Path, *, pointer_changed: bool, repo_changed: bool) -> None:
    if pointer_changed:
        try:
            _set_plugin_root(target_root, CURRENT_PLUGIN_ROOT)
        except (OSError, NoiselessFilterError):
            pass
    if repo_changed:
        _git(LIVE_REPO, "revert", "--no-edit", target_commit, check=False)
    resolved = target_root.resolve()
    allowed = Path(
        "/srv/myuna/channel-adapters/astrbot_plugin_myuna_gateway"
    ).resolve()
    if resolved.parent == allowed and target_root.name.startswith("v1.1-noiseless-"):
        shutil.rmtree(target_root, ignore_errors=True)
    if pointer_changed:
        try:
            _recreate_astrbot()
        except (OSError, subprocess.SubprocessError, NoiselessFilterError):
            pass


def public_receipt(
    *,
    digest: str,
    plan: dict[str, object],
    backups: list[dict[str, str]],
) -> dict[str, object]:
    return {
        "astrbot": "healthy",
        "capabilities_changed": False,
        "database_changed": False,
        "model_called_by_update": False,
        "napcat": "healthy",
        "operation": OPERATION,
        "plan_digest": digest,
        "prior_runtime_plan_digest": PRIOR_PLAN_DIGEST,
        "result": "qq-owner-noiseless-filter-active",
        "target_deploy_commit": plan["source"]["target_deploy_commit"],  # type: ignore[index]
        "verified_backups": backups,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--approved-plan-digest")
    parser.add_argument("--check-preconditions", action="store_true")
    args = parser.parse_args()

    if os.geteuid() != 0:
        raise NoiselessFilterError("run as root from the local server console")
    plan = build_update_plan()
    digest = update_digest(plan)
    if not args.apply:
        if args.check_preconditions:
            ensure_preconditions()
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
        raise NoiselessFilterError("noiseless filter plan digest does not match approval")

    ensure_preconditions()
    target_commit = _target_commit()
    target_root = _target_plugin_root(target_commit)
    run_stamp = datetime.now().astimezone().strftime("%Y%m%dT%H%M%S%z")
    pointer_changed = False
    repo_changed = False
    succeeded = False
    try:
        backups = _backup_current_plugin(run_stamp)
        _install_target_plugin(target_root)
        _git(LIVE_REPO, "merge", "--ff-only", target_commit)
        repo_changed = True
        _set_plugin_root(CURRENT_PLUGIN_ROOT, target_root)
        pointer_changed = True
        _recreate_astrbot()
        _postconditions(target_commit, target_root)
        receipt = public_receipt(digest=digest, plan=plan, backups=backups)
        _write_atomic(
            FINAL_RECEIPT_PATH,
            (
                json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True)
                + "\n"
            ).encode("utf-8"),
            mode=0o600,
            uid=0,
            gid=0,
        )
        print(json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True))
        succeeded = True
    finally:
        if not succeeded:
            _rollback(
                target_commit,
                target_root,
                pointer_changed=pointer_changed,
                repo_changed=repo_changed,
            )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, NoiselessFilterError, subprocess.SubprocessError) as exc:
        print(f"QQ noiseless filter update rejected: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
