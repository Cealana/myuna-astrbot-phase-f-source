#!/usr/bin/env python3
"""Atomically switch only the immutable Owner Profile writer code release."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import grp
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
from typing import Callable, Sequence

from install_owner_profile_write_code_v1 import (
    OwnerProfileCodeInstallError,
    validate_installed_code_release,
)
from owner_profile_write_environment_v1 import (
    OwnerProfileWriteTarget,
    parse_environment,
    render_environment,
)


DEPLOY_ROOT = Path("/srv/myuna/repos/deploy")
ENVIRONMENT_PATH = Path("/etc/myuna-owner-profile-write-v1/writer.env")
CONTROL_ROOT = Path("/var/lib/myuna-owner-profile-write-control-v1")
BACKUP_ROOT = CONTROL_ROOT / "backups" / "code-switch-v1"
RECEIPT_ROOT = CONTROL_ROOT / "receipts" / "code-switch-v1"
JOURNAL_PATH = CONTROL_ROOT / "PENDING-CODE-SWITCH-V1.json"
WRITER_SERVICE = "myuna-owner-profile-write-v1.service"
WRITER_SOCKET = "myuna-owner-profile-write-v1.socket"
SERVICE_GROUP = "myuna_owner_profile"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SOURCE_FILES = (
    "scripts/switch_owner_profile_write_code_v1.py",
    "scripts/install_owner_profile_write_code_v1.py",
    "scripts/owner_profile_write_environment_v1.py",
)


class OwnerProfileWriteCodeSwitchError(RuntimeError):
    """A deterministic content-free code-switch rejection."""


def _reject(code: str) -> OwnerProfileWriteCodeSwitchError:
    return OwnerProfileWriteCodeSwitchError(code)


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


@dataclass(frozen=True, slots=True)
class SwitchPaths:
    deploy_root: Path = DEPLOY_ROOT
    environment: Path = ENVIRONMENT_PATH
    backup_root: Path = BACKUP_ROOT
    receipt_root: Path = RECEIPT_ROOT
    journal: Path = JOURNAL_PATH


def _run(arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            arguments,
            check=check,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise _reject("code_switch_command_failed") from exc


def _service_active(unit: str) -> bool:
    return _run(
        ["/usr/bin/systemctl", "is-active", "--quiet", unit],
        check=False,
    ).returncode == 0


def _restart_writer() -> None:
    _run(["/usr/bin/systemctl", "restart", WRITER_SERVICE])


def _validate_private_directory(path: Path, *, uid: int, gid: int) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise _reject("code_switch_control_unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != uid
        or metadata.st_gid != gid
    ):
        raise _reject("code_switch_control_rejected")


def _read_environment(path: Path, *, uid: int, gid: int) -> bytes:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as exc:
        raise _reject("code_switch_environment_unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or metadata.st_nlink != 1
        or not payload
        or len(payload) != metadata.st_size
    ):
        raise _reject("code_switch_environment_rejected")
    return payload


def _atomic_write(path: Path, payload: bytes, *, uid: int, gid: int) -> None:
    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, raw_path = tempfile.mkstemp(prefix=".code-switch-", dir=path.parent)
        temporary = Path(raw_path)
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise _reject("code_switch_write_failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _write_new(path: Path, payload: bytes, *, uid: int, gid: int) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise _reject("code_switch_write_failed") from exc


def _make_private_directory(path: Path, *, uid: int, gid: int) -> None:
    try:
        path.mkdir(mode=0o700)
        os.chown(path, uid, gid)
    except OSError as exc:
        raise _reject("code_switch_write_failed") from exc


def verify_deploy_source(root: Path, *, expected_commit: str) -> None:
    if (
        not root.is_absolute()
        or root.is_symlink()
        or not root.is_dir()
        or _COMMIT.fullmatch(expected_commit) is None
    ):
        raise _reject("code_switch_source_rejected")
    head = _run(
        ["git", "-c", f"safe.directory={root}", "-C", str(root), "rev-parse", "HEAD"]
    ).stdout.strip()
    status = _run(
        [
            "git",
            "-c",
            f"safe.directory={root}",
            "-C",
            str(root),
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            *_SOURCE_FILES,
        ]
    ).stdout
    if head != expected_commit or status:
        raise _reject("code_switch_source_rejected")


ReleaseValidator = Callable[..., dict[str, object]]
ServiceCheck = Callable[[str], bool]
Restart = Callable[[], None]


def switch_writer_code(
    *,
    expected_core_release_sha256: str,
    expected_current_release_sha256: str,
    target_release_sha256: str,
    service_gid: int,
    paths: SwitchPaths = SwitchPaths(),
    root_uid: int = 0,
    root_gid: int = 0,
    validate_release: ReleaseValidator = validate_installed_code_release,
    service_active: ServiceCheck = _service_active,
    restart_writer: Restart = _restart_writer,
) -> dict[str, object]:
    if (
        os.geteuid() != root_uid
        or _DIGEST.fullmatch(expected_core_release_sha256) is None
        or _DIGEST.fullmatch(expected_current_release_sha256) is None
        or _DIGEST.fullmatch(target_release_sha256) is None
        or expected_current_release_sha256 == target_release_sha256
        or paths.journal.exists()
        or paths.journal.is_symlink()
    ):
        raise _reject("code_switch_preflight_rejected")
    _validate_private_directory(paths.backup_root.parent, uid=root_uid, gid=root_gid)
    _validate_private_directory(paths.receipt_root.parent, uid=root_uid, gid=root_gid)
    for directory in (paths.backup_root, paths.receipt_root):
        if not directory.exists():
            _make_private_directory(directory, uid=root_uid, gid=root_gid)
        _validate_private_directory(directory, uid=root_uid, gid=root_gid)
    current_payload = _read_environment(paths.environment, uid=root_uid, gid=root_gid)
    try:
        current = parse_environment(current_payload)
    except ValueError as exc:
        raise _reject("code_switch_environment_rejected") from exc
    if current.core_release_sha256 != expected_core_release_sha256:
        raise _reject("code_switch_core_release_drift")
    if current.write_code_release_sha256 != expected_current_release_sha256:
        raise _reject("code_switch_current_release_drift")
    try:
        current_manifest = validate_release(
            expected_current_release_sha256,
            gid=service_gid,
        )
        target_manifest = validate_release(target_release_sha256, gid=service_gid)
    except OwnerProfileCodeInstallError as exc:
        raise _reject("code_switch_release_rejected") from exc
    if (
        not isinstance(current_manifest, dict)
        or not isinstance(target_manifest, dict)
    ):
        raise _reject("code_switch_release_rejected")
    source_commit = str(target_manifest.get("source_commit", ""))
    if (
        _COMMIT.fullmatch(source_commit) is None
        or not service_active(WRITER_SERVICE)
        or not service_active(WRITER_SOCKET)
    ):
        raise _reject("code_switch_runtime_preflight_rejected")
    target = OwnerProfileWriteTarget(
        core_release_sha256=current.core_release_sha256,
        write_code_release_sha256=target_release_sha256,
        owner_profile_uid=current.owner_profile_uid,
        core_peer_uid=current.core_peer_uid,
    )
    target_payload = render_environment(target)
    switch_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{time.time_ns()}"
    backup = paths.backup_root / switch_id
    _make_private_directory(backup, uid=root_uid, gid=root_gid)
    _write_new(backup / "writer.env", current_payload, uid=root_uid, gid=root_gid)
    _write_new(
        backup / "MANIFEST.json",
        _canonical(
            {
                "schema": "myuna.owner-profile-write-code-switch-backup.v1",
                "from_release_sha256": expected_current_release_sha256,
                "to_release_sha256": target_release_sha256,
                "raw_content_recorded": False,
                "profile_content_recorded": False,
            }
        ),
        uid=root_uid,
        gid=root_gid,
    )
    _write_new(
        paths.journal,
        _canonical(
            {
                "schema": "myuna.owner-profile-write-code-switch-journal.v1",
                "status": "pending",
                "backup": switch_id,
                "raw_content_recorded": False,
                "profile_content_recorded": False,
            }
        ),
        uid=root_uid,
        gid=root_gid,
    )
    mutated = False
    commit_started = False
    try:
        _atomic_write(paths.environment, target_payload, uid=root_uid, gid=root_gid)
        mutated = True
        restart_writer()
        if (
            _read_environment(paths.environment, uid=root_uid, gid=root_gid)
            != target_payload
            or not service_active(WRITER_SERVICE)
            or not service_active(WRITER_SOCKET)
        ):
            raise _reject("code_switch_poststate_rejected")
        receipt = {
            "schema": "myuna.owner-profile-write-code-switch-receipt.v1",
            "status": "WRITER_CODE_SWITCHED_AWAITING_OWNER_E2E",
            "receipt_id": switch_id,
            "backup": switch_id,
            "from_release_sha256": expected_current_release_sha256,
            "to_release_sha256": target_release_sha256,
            "source_commit": source_commit,
            "core_release_sha256": expected_core_release_sha256,
            "writer_service_restarted": True,
            "core_service_changed": False,
            "profile_content_changed": False,
            "candidate_store_changed": False,
            "raw_content_recorded": False,
        }
        _write_new(
            paths.receipt_root / f"{switch_id}.json",
            _canonical(receipt),
            uid=root_uid,
            gid=root_gid,
        )
        commit_started = True
        paths.journal.unlink()
        return receipt
    except Exception as exc:
        if commit_started:
            raise _reject("code_switch_commit_recovery_required") from exc
        try:
            if mutated:
                _atomic_write(
                    paths.environment,
                    current_payload,
                    uid=root_uid,
                    gid=root_gid,
                )
                restart_writer()
                if (
                    _read_environment(paths.environment, uid=root_uid, gid=root_gid)
                    != current_payload
                    or not service_active(WRITER_SERVICE)
                    or not service_active(WRITER_SOCKET)
                ):
                    raise _reject("code_switch_rollback_failed")
            if paths.journal.exists() and not paths.journal.is_symlink():
                paths.journal.unlink()
        except Exception as rollback_exc:
            raise _reject("code_switch_rollback_failed") from rollback_exc
        raise exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-core-release-sha256", required=True)
    parser.add_argument("--expected-current-release-sha256", required=True)
    parser.add_argument("--target-release-sha256", required=True)
    parser.add_argument("--expected-deploy-commit", required=True)
    arguments = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise _reject("must_run_as_root")
        verify_deploy_source(
            DEPLOY_ROOT,
            expected_commit=arguments.expected_deploy_commit,
        )
        service_gid = grp.getgrnam(SERVICE_GROUP).gr_gid
        receipt = switch_writer_code(
            expected_core_release_sha256=(
                arguments.expected_core_release_sha256
            ),
            expected_current_release_sha256=(
                arguments.expected_current_release_sha256
            ),
            target_release_sha256=arguments.target_release_sha256,
            service_gid=service_gid,
        )
        print(json.dumps(receipt, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
        return 0
    except (KeyError, OwnerProfileWriteCodeSwitchError) as exc:
        print(
            json.dumps(
                {
                    "status": "REJECTED",
                    "error_category": str(exc),
                    "raw_content_recorded": False,
                    "profile_content_changed": False,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
