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


OPERATION = "qq-owner-boundary-metadata-failclosed-v1"
PRIOR_PLAN_DIGEST = "86bfc37bfd558b558fa94e040c9170c629863de4ff2f8825a577496906a71f85"
EXPECTED_LIVE_COMMIT = "6f1ae26009c5cdbafc7ea258525080e48b79372a"

STAGED_REPO = Path(__file__).resolve().parents[1]
LIVE_REPO = Path("/srv/myuna/repos/deploy")
PLUGIN_RELATIVE = Path("channels/astrbot-qq/plugin/myuna_gateway")
CURRENT_PLUGIN_ROOT = Path(
    "/srv/myuna/channel-adapters/astrbot_plugin_myuna_gateway/"
    "v1.1-noiseless-6f1ae26009c5"
)
PLUGIN_PARENT = Path("/srv/myuna/channel-adapters/astrbot_plugin_myuna_gateway")
CHANNEL_ENV_PATH = Path("/etc/myuna-gateway/astrbot-napcat-dev.env")
ASTRBOT_CONFIG_PATH = Path(
    "/srv/myuna/channels/astrbot-qq/dev/astrbot-data/cmd_config.json"
)
PRIOR_RECEIPT_PATH = Path(
    "/var/lib/myuna-gateway/qq-owner-noiseless-filter-v1-receipt.json"
)
FINAL_RECEIPT_PATH = Path(
    "/var/lib/myuna-gateway/qq-owner-boundary-metadata-failclosed-v1-receipt.json"
)
BACKUP_ROOT = Path(
    "/var/backups/myuna/qq-owner-runtime/boundary-metadata-failclosed-v1"
)
WINDOWS_BACKUP_ROOT = Path(
    "/mnt/c/Server-Critical-Backup/Myuna/QQ-Boundary-Metadata-Fix"
)
CURRENT_PLUGIN_FILES = ("main.py", "protocol.py")
TARGET_PLUGIN_FILES = ("main.py", "protocol.py", "metadata.yaml")


class BoundaryMetadataFixError(RuntimeError):
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
        ["/usr/sbin/runuser", "-u", "myuna", "--", "git", "-C", str(repo), *args],
        check=check,
    )


def _git_value(repo: Path, *args: str) -> str:
    return _git(repo, *args).stdout.strip()


def _target_commit() -> str:
    return _git_value(STAGED_REPO, "rev-parse", "HEAD")


def _target_parent() -> str:
    return _git_value(STAGED_REPO, "rev-parse", "HEAD^")


def _target_plugin_root(target_commit: str) -> Path:
    return PLUGIN_PARENT / f"v1.2-boundary-{target_commit[:12]}"


def _plugin_hashes(root: Path, names: tuple[str, ...]) -> dict[str, str]:
    return {name: _sha256_file(root / name) for name in names}


def build_update_plan() -> dict[str, object]:
    target_commit = _target_commit()
    hashes = _plugin_hashes(STAGED_REPO / PLUGIN_RELATIVE, TARGET_PLUGIN_FILES)
    return {
        "backup": {
            "astrbot_config": "WSL-and-C-drive-hash-verified",
            "database_backup": False,
            "previous_plugin_files": "WSL-and-C-drive-hash-verified",
        },
        "behavior": {
            "astrbot_builtin_llm": "disabled-fail-closed",
            "plugin_metadata": "required-and-hash-verified",
            "rejected_events": "silent-drop",
            "verified_owner_private_plain_text": "Myuna-gateway-only",
        },
        "capabilities_unchanged": {
            "deepseek_daily_budget_usd": "2.00",
            "group_chat": False,
            "memory_read": False,
            "memory_write": False,
            "tools": False,
            "vision": False,
        },
        "database": {"backup_required": False, "migration": None, "writes": False},
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
            "astrbot_provider_count": 0,
            "astrbot_provider_gate_changed": True,
            "myuna_provider_or_routing_changed": False,
        },
        "operation": OPERATION,
        "prior_runtime_plan_digest": PRIOR_PLAN_DIGEST,
        "rollback": {
            "astrbot_config_restore": True,
            "git_compensating_revert": True,
            "plugin_pointer_restore": str(CURRENT_PLUGIN_ROOT),
            "recreate_astrbot_after_restore": True,
        },
        "source": {
            "plugin_bundle_sha256": sha256(canonical_json(hashes)).hexdigest(),
            "plugin_files": hashes,
            "prior_deploy_commit": EXPECTED_LIVE_COMMIT,
            "target_deploy_commit": target_commit,
            "target_parent_commit": _target_parent(),
        },
    }


def update_digest(plan: dict[str, object]) -> str:
    return sha256(canonical_json(plan)).hexdigest()


def _unit_active(unit: str) -> bool:
    return _run(["systemctl", "is-active", "--quiet", unit], check=False).returncode == 0


def _read_prior_receipt() -> dict[str, object]:
    try:
        payload = json.loads(PRIOR_RECEIPT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BoundaryMetadataFixError("approved noiseless-filter receipt is unavailable") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("plan_digest") != PRIOR_PLAN_DIGEST
        or payload.get("result") != "qq-owner-noiseless-filter-active"
    ):
        raise BoundaryMetadataFixError("approved noiseless-filter receipt does not match")
    return payload


def _plugin_root_line() -> str:
    matches = [
        line
        for line in CHANNEL_ENV_PATH.read_text(encoding="utf-8").splitlines()
        if line.startswith("CHANNEL_PLUGIN_ROOT=")
    ]
    if len(matches) != 1:
        raise BoundaryMetadataFixError("channel plugin root is ambiguous")
    return matches[0]


def _set_plugin_root(expected: Path, replacement: Path) -> None:
    stat = CHANNEL_ENV_PATH.stat()
    old_line = f"CHANNEL_PLUGIN_ROOT={expected}"
    new_line = f"CHANNEL_PLUGIN_ROOT={replacement}"
    text = CHANNEL_ENV_PATH.read_text(encoding="utf-8")
    if text.count(old_line) != 1 or new_line in text:
        raise BoundaryMetadataFixError("channel plugin pointer precondition failed")
    _write_atomic(
        CHANNEL_ENV_PATH,
        text.replace(old_line, new_line, 1).encode("utf-8"),
        mode=stat.st_mode & 0o777,
        uid=stat.st_uid,
        gid=stat.st_gid,
    )


def _read_astrbot_config() -> dict[str, object]:
    try:
        payload = json.loads(ASTRBOT_CONFIG_PATH.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BoundaryMetadataFixError("AstrBot configuration is unavailable") from exc
    if not isinstance(payload, dict):
        raise BoundaryMetadataFixError("AstrBot configuration root is invalid")
    return payload


def _astrbot_provider_state() -> tuple[bool, int]:
    payload = _read_astrbot_config()
    provider_settings = payload.get("provider_settings")
    providers = payload.get("provider")
    if not isinstance(provider_settings, dict) or not isinstance(providers, list):
        raise BoundaryMetadataFixError("AstrBot provider configuration is invalid")
    return bool(provider_settings.get("enable", True)), len(providers)


def _disable_astrbot_default_llm() -> None:
    payload = _read_astrbot_config()
    provider_settings = payload.get("provider_settings")
    if not isinstance(provider_settings, dict):
        raise BoundaryMetadataFixError("AstrBot provider settings are invalid")
    provider_settings["enable"] = False
    stat = ASTRBOT_CONFIG_PATH.stat()
    serialized = (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    _write_atomic(
        ASTRBOT_CONFIG_PATH,
        serialized,
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
    raise BoundaryMetadataFixError(f"container did not become healthy: {name}")


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
        raise BoundaryMetadataFixError("run as root from the local server console")
    if _git_value(STAGED_REPO, "status", "--porcelain"):
        raise BoundaryMetadataFixError("staged update repository must be clean")
    if _target_parent() != EXPECTED_LIVE_COMMIT:
        raise BoundaryMetadataFixError("target update is not a single fast-forward commit")
    if _git_value(LIVE_REPO, "rev-parse", "HEAD") != EXPECTED_LIVE_COMMIT:
        raise BoundaryMetadataFixError("live deploy commit changed")
    if _git_value(LIVE_REPO, "status", "--porcelain"):
        raise BoundaryMetadataFixError("live deploy repository must be clean")
    if _git(
        LIVE_REPO,
        "merge-base",
        "--is-ancestor",
        EXPECTED_LIVE_COMMIT,
        _target_commit(),
        check=False,
    ).returncode != 0:
        raise BoundaryMetadataFixError("target commit is not staged in the live repository")
    _read_prior_receipt()
    if _plugin_root_line() != f"CHANNEL_PLUGIN_ROOT={CURRENT_PLUGIN_ROOT}":
        raise BoundaryMetadataFixError("current channel plugin pointer changed")
    if _plugin_hashes(CURRENT_PLUGIN_ROOT, CURRENT_PLUGIN_FILES) != _plugin_hashes(
        LIVE_REPO / PLUGIN_RELATIVE,
        CURRENT_PLUGIN_FILES,
    ):
        raise BoundaryMetadataFixError("current plugin files do not match the live commit")
    if (CURRENT_PLUGIN_ROOT / "metadata.yaml").exists():
        raise BoundaryMetadataFixError("current plugin metadata state changed")
    metadata = (STAGED_REPO / PLUGIN_RELATIVE / "metadata.yaml").read_text(
        encoding="utf-8"
    )
    if (
        "name: astrbot_plugin_myuna_gateway" not in metadata
        or "version: 0.2.0" not in metadata
        or "support_platforms:" not in metadata
        or "  - aiocqhttp" not in metadata
    ):
        raise BoundaryMetadataFixError("target plugin metadata is incomplete")
    if _astrbot_provider_state() != (True, 0):
        raise BoundaryMetadataFixError("AstrBot provider precondition changed")
    for unit in (
        "myuna-core@qq.service",
        "myuna-qq-owner-runtime-dev.socket",
        "myuna-astrbot-qq-dev.service",
    ):
        if not _unit_active(unit):
            raise BoundaryMetadataFixError(f"required service is inactive: {unit}")
    for unit in (
        "myuna-core@dev.service",
        "myuna-retrieval-worker-dev.service",
        "myuna-channel-gateway-dev.service",
    ):
        if _unit_active(unit):
            raise BoundaryMetadataFixError(f"excluded service became active: {unit}")
    ensure_channel_healthy()
    target_root = _target_plugin_root(_target_commit())
    if target_root.exists() or FINAL_RECEIPT_PATH.exists():
        raise BoundaryMetadataFixError("boundary metadata fix activation gate is not clean")


def _copy_verified(source: Path, destination: Path, *, mode: int | None = None) -> dict[str, str]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    if mode is not None and destination.as_posix().startswith("/var/backups/"):
        destination.chmod(mode)
    source_hash = _sha256_file(source)
    if _sha256_file(destination) != source_hash:
        raise BoundaryMetadataFixError("backup copy hash mismatch")
    return {"filename": destination.name, "sha256": source_hash}


def _backup_state(run_stamp: str) -> tuple[list[dict[str, str]], Path]:
    linux_root = BACKUP_ROOT / run_stamp
    windows_root = WINDOWS_BACKUP_ROOT / f"Owner-QQ-Boundary-v1-{run_stamp}"
    linux_root.mkdir(parents=True, mode=0o700, exist_ok=False)
    windows_root.mkdir(parents=True, exist_ok=False)
    records: list[dict[str, str]] = []
    for name in CURRENT_PLUGIN_FILES:
        source = CURRENT_PLUGIN_ROOT / name
        linux_record = _copy_verified(source, linux_root / f"pre-{name}")
        windows_record = _copy_verified(source, windows_root / f"pre-{name}")
        if linux_record["sha256"] != windows_record["sha256"]:
            raise BoundaryMetadataFixError("plugin backup hash mismatch")
        records.append({"kind": "plugin", **linux_record})
    linux_config = linux_root / "pre-cmd_config.json"
    linux_record = _copy_verified(ASTRBOT_CONFIG_PATH, linux_config, mode=0o600)
    windows_record = _copy_verified(
        ASTRBOT_CONFIG_PATH,
        windows_root / "pre-cmd_config.json",
    )
    if linux_record["sha256"] != windows_record["sha256"]:
        raise BoundaryMetadataFixError("AstrBot config backup hash mismatch")
    records.append({"kind": "astrbot-config", **linux_record})
    return records, linux_config


def _install_target_plugin(target_root: Path) -> None:
    source_root = STAGED_REPO / PLUGIN_RELATIVE
    for name in TARGET_PLUGIN_FILES:
        _run(
            [
                "install",
                "-D",
                "-o",
                "root",
                "-g",
                "root",
                "-m",
                "0644",
                str(source_root / name),
                str(target_root / name),
            ]
        )
    if _plugin_hashes(target_root, TARGET_PLUGIN_FILES) != _plugin_hashes(
        source_root,
        TARGET_PLUGIN_FILES,
    ):
        raise BoundaryMetadataFixError("installed plugin hash mismatch")


def _runtime_metadata_log_present() -> bool:
    result = _run(
        ["docker", "logs", "--since", "3m", "myuna-astrbot-dev"],
        check=False,
    )
    combined = result.stdout + result.stderr
    return (
        "Plugin astrbot_plugin_myuna_gateway (0.2.0) by Myuna Server" in combined
        and "Myuna QQ fail-closed boundary initialized" in combined
    )


def _postconditions(target_commit: str, target_root: Path) -> None:
    if _git_value(LIVE_REPO, "rev-parse", "HEAD") != target_commit:
        raise BoundaryMetadataFixError("live deploy repository did not fast-forward")
    if _git_value(LIVE_REPO, "status", "--porcelain"):
        raise BoundaryMetadataFixError("live deploy repository is not clean")
    if _plugin_root_line() != f"CHANNEL_PLUGIN_ROOT={target_root}":
        raise BoundaryMetadataFixError("new plugin pointer was not installed")
    if _plugin_hashes(target_root, TARGET_PLUGIN_FILES) != _plugin_hashes(
        LIVE_REPO / PLUGIN_RELATIVE,
        TARGET_PLUGIN_FILES,
    ):
        raise BoundaryMetadataFixError("new plugin files do not match the live commit")
    if _astrbot_provider_state() != (False, 0):
        raise BoundaryMetadataFixError("AstrBot default LLM did not fail closed")
    if not _container_healthy("myuna-astrbot-dev") or not _runtime_metadata_log_present():
        raise BoundaryMetadataFixError("AstrBot did not load the named Myuna boundary")
    if not _container_healthy("myuna-napcat-dev"):
        raise BoundaryMetadataFixError("NapCat is not healthy")
    for unit in ("myuna-core@qq.service", "myuna-qq-owner-runtime-dev.socket"):
        if not _unit_active(unit):
            raise BoundaryMetadataFixError(f"required service stopped: {unit}")


def _restore_config(config_backup: Path) -> None:
    stat = ASTRBOT_CONFIG_PATH.stat()
    _write_atomic(
        ASTRBOT_CONFIG_PATH,
        config_backup.read_bytes(),
        mode=stat.st_mode & 0o777,
        uid=stat.st_uid,
        gid=stat.st_gid,
    )


def _rollback(
    target_commit: str,
    target_root: Path,
    *,
    config_backup: Path | None,
    config_changed: bool,
    pointer_changed: bool,
    repo_changed: bool,
) -> None:
    if config_changed and config_backup:
        try:
            _restore_config(config_backup)
        except OSError:
            pass
    if pointer_changed:
        try:
            _set_plugin_root(target_root, CURRENT_PLUGIN_ROOT)
        except (OSError, BoundaryMetadataFixError):
            pass
    if repo_changed:
        _git(LIVE_REPO, "revert", "--no-edit", target_commit, check=False)
    try:
        resolved = target_root.resolve()
        if resolved.parent == PLUGIN_PARENT.resolve() and target_root.name.startswith(
            "v1.2-boundary-"
        ):
            shutil.rmtree(target_root, ignore_errors=True)
    except OSError:
        pass
    if config_changed or pointer_changed:
        try:
            _recreate_astrbot()
        except (OSError, subprocess.SubprocessError, BoundaryMetadataFixError):
            pass


def public_receipt(
    *,
    digest: str,
    plan: dict[str, object],
    backups: list[dict[str, str]],
) -> dict[str, object]:
    return {
        "astrbot": "healthy",
        "astrbot_builtin_llm_enabled": False,
        "database_changed": False,
        "model_called_by_update": False,
        "myuna_capabilities_expanded": False,
        "napcat": "healthy",
        "operation": OPERATION,
        "plan_digest": digest,
        "plugin_metadata_verified": True,
        "prior_runtime_plan_digest": PRIOR_PLAN_DIGEST,
        "result": "qq-owner-boundary-metadata-failclosed-active",
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
        raise BoundaryMetadataFixError("run as root from the local server console")
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
        raise BoundaryMetadataFixError("boundary metadata fix plan digest does not match")

    ensure_preconditions()
    target_commit = _target_commit()
    target_root = _target_plugin_root(target_commit)
    run_stamp = datetime.now().astimezone().strftime("%Y%m%dT%H%M%S%z")
    config_backup: Path | None = None
    config_changed = False
    pointer_changed = False
    repo_changed = False
    succeeded = False
    try:
        backups, config_backup = _backup_state(run_stamp)
        _install_target_plugin(target_root)
        _git(LIVE_REPO, "merge", "--ff-only", target_commit)
        repo_changed = True
        _set_plugin_root(CURRENT_PLUGIN_ROOT, target_root)
        pointer_changed = True
        _disable_astrbot_default_llm()
        config_changed = True
        _recreate_astrbot()
        _postconditions(target_commit, target_root)
        receipt = public_receipt(digest=digest, plan=plan, backups=backups)
        _write_atomic(
            FINAL_RECEIPT_PATH,
            (json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            ),
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
                config_backup=config_backup,
                config_changed=config_changed,
                pointer_changed=pointer_changed,
                repo_changed=repo_changed,
            )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, BoundaryMetadataFixError, subprocess.SubprocessError) as exc:
        print(f"QQ boundary metadata fix rejected: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
