#!/usr/bin/env python3
"""Prepare the existing private lifecycle root for the bounded writer identity."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Callable, Sequence

from install_owner_profile_service_identity_v1 import (
    SERVICE_ACCOUNT,
    validate_service_identity,
)


LEGACY_PROFILE_RELEASE_ROOT = Path("/var/lib/myuna-owner-profile-v1/releases")
WRITE_ROOT = Path("/var/lib/myuna-owner-profile-write-v1")
WRITE_CODE_RELEASE_ROOT = Path("/opt/myuna/owner-profile-write-v1/releases")
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_RELEASE_NAME = re.compile(r"^r[1-9][0-9]*-([0-9a-f]{64})$")
_CORE_PYTHONPATH = re.compile(
    r"^/opt/myuna/owner-profile-write-v1/releases/([0-9a-f]{64})/src$"
)


class OwnerProfileWriteStatePrepareError(RuntimeError):
    pass


def _reject(code: str) -> OwnerProfileWriteStatePrepareError:
    return OwnerProfileWriteStatePrepareError(code)


def _tree_entries(root: Path) -> tuple[Path, ...]:
    try:
        entries = (root, *root.rglob("*"))
        for path in entries:
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                if stat.S_IMODE(metadata.st_mode) != PRIVATE_DIRECTORY_MODE:
                    raise _reject("profile_write_state_permission_drift")
            elif stat.S_ISREG(metadata.st_mode):
                if (
                    stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE_MODE
                    or metadata.st_nlink != 1
                ):
                    raise _reject("profile_write_state_permission_drift")
            else:
                raise _reject("profile_write_state_type_drift")
        return entries
    except OwnerProfileWriteStatePrepareError:
        raise
    except OSError as exc:
        raise _reject("profile_write_state_unavailable") from exc


def _tree_owner(entries: tuple[Path, ...], *, uid: int, gid: int) -> bool:
    return all(
        path.lstat().st_uid == uid and path.lstat().st_gid == gid
        for path in entries
    )


def _chown_tree(root: Path, *, uid: int, gid: int) -> None:
    entries = _tree_entries(root)
    try:
        for path in reversed(entries):
            os.chown(path, uid, gid, follow_symlinks=False)
    except OSError as exc:
        raise _reject("profile_write_state_ownership_failed") from exc
    if not _tree_owner(_tree_entries(root), uid=uid, gid=gid):
        raise _reject("profile_write_state_ownership_failed")


BootstrapRunner = Callable[[Path, str, Path, bool, Path], None]


def _run_bootstrap(
    source_release: Path,
    source_sha256: str,
    write_root: Path,
    validate_only: bool,
    core_pythonpath: Path,
) -> None:
    command = [
        "/usr/sbin/runuser",
        "-u",
        SERVICE_ACCOUNT,
        "--",
        "/usr/bin/env",
        "PYTHONDONTWRITEBYTECODE=1",
        f"PYTHONPATH={core_pythonpath}",
        "/usr/bin/python3",
        "-m",
        "myuna_core.owner_profile.write_bootstrap",
        "--source-release",
        str(source_release),
        "--source-sha256",
        source_sha256,
        "--write-root",
        str(write_root),
    ]
    if validate_only:
        command.append("--validate-only")
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _reject("profile_write_bootstrap_unavailable") from exc
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise _reject("profile_write_bootstrap_rejected") from exc
    if (
        completed.returncode != 0
        or not isinstance(result, dict)
        or result.get("status") != "PROFILE_WRITE_STORE_READY"
        or result.get("raw_content_recorded") is not False
        or result.get("profile_digest_recorded") is not False
    ):
        raise _reject("profile_write_bootstrap_rejected")


def prepare_write_state(
    *,
    source_release: Path,
    source_sha256: str,
    write_root: Path = WRITE_ROOT,
    root_uid: int = 0,
    root_gid: int = 0,
    service_uid: int,
    service_gid: int,
    core_pythonpath: Path,
    bootstrap_runner: BootstrapRunner = _run_bootstrap,
) -> bool:
    release_match = _RELEASE_NAME.fullmatch(source_release.name)
    if (
        os.geteuid() != root_uid
        or not source_release.is_absolute()
        or not write_root.is_absolute()
        or _DIGEST.fullmatch(source_sha256) is None
        or source_release.parent != LEGACY_PROFILE_RELEASE_ROOT
        or release_match is None
        or release_match.group(1) != source_sha256
        or _CORE_PYTHONPATH.fullmatch(core_pythonpath.as_posix()) is None
    ):
        raise _reject("profile_write_state_request_rejected")
    entries = _tree_entries(write_root)
    root_owned = _tree_owner(entries, uid=root_uid, gid=root_gid)
    service_owned = _tree_owner(entries, uid=service_uid, gid=service_gid)
    if not root_owned and not service_owned:
        raise _reject("profile_write_state_owner_drift")
    ownership_changed = False
    try:
        if root_owned:
            ownership_changed = True
            _chown_tree(write_root, uid=service_uid, gid=service_gid)
        bootstrap_runner(
            source_release,
            source_sha256,
            write_root,
            service_owned,
            core_pythonpath,
        )
        if not _tree_owner(
            _tree_entries(write_root), uid=service_uid, gid=service_gid
        ):
            raise _reject("profile_write_state_owner_drift")
        return ownership_changed
    except Exception:
        if ownership_changed:
            _chown_tree(write_root, uid=root_uid, gid=root_gid)
        raise


def restore_write_state_root(
    *,
    write_root: Path = WRITE_ROOT,
    root_uid: int = 0,
    root_gid: int = 0,
    service_uid: int,
    service_gid: int,
) -> bool:
    """Restore only a fully service-owned tree to its inert root-owned state."""

    if os.geteuid() != root_uid or not write_root.is_absolute():
        raise _reject("profile_write_state_request_rejected")
    entries = _tree_entries(write_root)
    if _tree_owner(entries, uid=root_uid, gid=root_gid):
        return False
    if not _tree_owner(entries, uid=service_uid, gid=service_gid):
        raise _reject("profile_write_state_owner_drift")
    _chown_tree(write_root, uid=root_uid, gid=root_gid)
    return True


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile-revision", type=int, required=True)
    parser.add_argument("--profile-sha256", required=True)
    parser.add_argument("--write-code-release-sha256", required=True)
    arguments = parser.parse_args(argv)
    try:
        service_uid, service_gid = validate_service_identity()
        release = LEGACY_PROFILE_RELEASE_ROOT / (
            f"r{arguments.profile_revision}-{arguments.profile_sha256}"
        )
        if _DIGEST.fullmatch(arguments.write_code_release_sha256) is None:
            raise _reject("profile_write_state_request_rejected")
        core_pythonpath = WRITE_CODE_RELEASE_ROOT / (
            arguments.write_code_release_sha256
        ) / "src"
        changed = prepare_write_state(
            source_release=release,
            source_sha256=arguments.profile_sha256,
            service_uid=service_uid,
            service_gid=service_gid,
            core_pythonpath=core_pythonpath,
        )
        print(
            json.dumps(
                {
                    "status": "PROFILE_WRITE_STATE_READY",
                    "ownership_changed": changed,
                    "raw_content_recorded": False,
                    "profile_digest_recorded": False,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 0
    except (OSError, ValueError, OwnerProfileWriteStatePrepareError) as exc:
        print(
            json.dumps(
                {
                    "status": "REJECTED",
                    "error_category": str(exc),
                    "raw_content_recorded": False,
                    "profile_digest_recorded": False,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
