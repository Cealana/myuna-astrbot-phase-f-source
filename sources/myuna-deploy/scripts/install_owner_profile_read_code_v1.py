#!/usr/bin/env python3
"""Build and install the minimal immutable Owner Profile read-worker code release."""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
import errno
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import grp
import re
import stat
import subprocess
from typing import Sequence


DESTINATION_ROOT = Path("/opt/myuna/owner-profile-read-v1")
SERVICE_ACCOUNT = "myuna_owner_profile"
MANIFEST_FILENAME = "MANIFEST.json"
MANIFEST_SCHEMA = "myuna.owner-profile-read-code-release.v1"
ROOT_MODE = 0o750
RELEASE_MODE = 0o550
FILE_MODE = 0o440
MAX_SOURCE_FILE_BYTES = 256_000
SOURCE_FILES = (
    "src/myuna_core/__init__.py",
    "src/myuna_core/owner_profile/__init__.py",
    "src/myuna_core/owner_profile/active_selector.py",
    "src/myuna_core/owner_profile/approval.py",
    "src/myuna_core/owner_profile/contracts.py",
    "src/myuna_core/owner_profile/loader.py",
    "src/myuna_core/owner_profile/projection.py",
    "src/myuna_core/owner_profile/protocol.py",
    "src/myuna_core/owner_profile/retrieval.py",
    "src/myuna_core/owner_profile/socket_worker.py",
    "deploy/myuna-owner-profile-read-v1.service",
    "deploy/myuna-owner-profile-read-v1.socket",
    "deploy/myuna-owner-profile-read-v1.tmpfiles.conf",
    "deploy/myuna-owner-profile-read-v1.sysusers.conf",
)
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_RENAME_NOREPLACE = 1


class OwnerProfileCodeInstallError(RuntimeError):
    """A deterministic code-release rejection."""


@dataclass(frozen=True, slots=True)
class CodeReleaseBundle:
    source_commit: str
    release_sha256: str
    manifest_bytes: bytes
    payloads: tuple[tuple[str, bytes], ...]


def _reject(code: str) -> OwnerProfileCodeInstallError:
    return OwnerProfileCodeInstallError(code)


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


def _source_file(source_root: Path, relative: str) -> bytes:
    path = source_root / relative
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise _reject("code_source_unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size < 1
        or metadata.st_size > MAX_SOURCE_FILE_BYTES
    ):
        raise _reject("code_source_rejected")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise _reject("code_source_unavailable") from exc
    if len(payload) != metadata.st_size:
        raise _reject("code_source_rejected")
    return payload


def build_code_bundle(source_root: Path, *, source_commit: str) -> CodeReleaseBundle:
    if (
        not isinstance(source_root, Path)
        or not source_root.is_absolute()
        or source_root.is_symlink()
        or not source_root.is_dir()
        or not isinstance(source_commit, str)
        or _COMMIT.fullmatch(source_commit) is None
    ):
        raise _reject("code_source_rejected")
    payloads = tuple(
        (relative, _source_file(source_root, relative))
        for relative in SOURCE_FILES
    )
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "component": "owner_profile_read_v1",
        "source_commit": source_commit,
        "files": [
            {
                "path": relative,
                "bytes": len(payload),
                "sha256": sha256(payload).hexdigest(),
                "mode": "0440",
            }
            for relative, payload in payloads
        ],
    }
    manifest_bytes = _canonical(manifest)
    return CodeReleaseBundle(
        source_commit=source_commit,
        release_sha256=sha256(manifest_bytes).hexdigest(),
        manifest_bytes=manifest_bytes,
        payloads=payloads,
    )


def verify_git_source(
    source_root: Path,
    *,
    expected_commit: str,
) -> None:
    if _COMMIT.fullmatch(expected_commit) is None:
        raise _reject("code_source_commit_rejected")
    commands = (
        ["git", "-C", str(source_root), "rev-parse", "HEAD"],
        [
            "git",
            "-C",
            str(source_root),
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            *SOURCE_FILES,
        ],
    )
    outputs: list[str] = []
    for command in commands:
        command = ["git", "-c", f"safe.directory={source_root}", *command[1:]]

        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise _reject("code_source_git_unavailable") from exc
        if completed.returncode != 0:
            raise _reject("code_source_git_rejected")
        outputs.append(completed.stdout.strip())
    if outputs[0] != expected_commit or outputs[1]:
        raise _reject("code_source_git_rejected")


def _ensure_root(path: Path, *, uid: int, gid: int) -> None:
    try:
        os.mkdir(path, ROOT_MODE)
        created = True
    except FileExistsError:
        created = False
    except OSError as exc:
        raise _reject("code_install_unavailable") from exc
    if created:
        try:
            os.chown(path, uid, gid)
            os.chmod(path, ROOT_MODE)
        except OSError as exc:
            raise _reject("code_install_unavailable") from exc
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise _reject("code_install_unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != ROOT_MODE
        or metadata.st_uid != uid
        or metadata.st_gid != gid
    ):
        raise _reject("code_install_root_rejected")


def _expected_directories() -> frozenset[str]:
    directories: set[str] = set()
    for relative in SOURCE_FILES:
        parent = Path(relative).parent
        while parent != Path("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    return frozenset(directories)


def _verify_release(
    directory: Path,
    bundle: CodeReleaseBundle,
    *,
    uid: int,
    gid: int,
    expected_name: str,
) -> None:
    if directory.name != expected_name:
        raise _reject("code_release_identity_rejected")
    expected_files = {MANIFEST_FILENAME, *SOURCE_FILES}
    expected_directories = _expected_directories()
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    try:
        entries = (directory, *directory.rglob("*"))
        for entry in entries:
            metadata = entry.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise _reject("code_release_metadata_rejected")
            if metadata.st_uid != uid or metadata.st_gid != gid:
                raise _reject("code_release_metadata_rejected")
            relative = entry.relative_to(directory).as_posix()
            if stat.S_ISDIR(metadata.st_mode):
                if stat.S_IMODE(metadata.st_mode) != RELEASE_MODE:
                    raise _reject("code_release_metadata_rejected")
                if entry != directory:
                    actual_directories.add(relative)
            elif stat.S_ISREG(metadata.st_mode):
                if stat.S_IMODE(metadata.st_mode) != FILE_MODE or metadata.st_nlink != 1:
                    raise _reject("code_release_metadata_rejected")
                actual_files.add(relative)
            else:
                raise _reject("code_release_metadata_rejected")
    except OwnerProfileCodeInstallError:
        raise
    except OSError as exc:
        raise _reject("code_install_unavailable") from exc
    if actual_files != expected_files or actual_directories != expected_directories:
        raise _reject("code_release_file_set_rejected")
    expected_payloads = dict(bundle.payloads)
    expected_payloads[MANIFEST_FILENAME] = bundle.manifest_bytes
    for relative, expected in expected_payloads.items():
        try:
            actual = (directory / relative).read_bytes()
        except OSError as exc:
            raise _reject("code_install_unavailable") from exc
        if actual != expected:
            raise _reject("code_release_content_rejected")
    try:
        manifest_digest = sha256(
            (directory / MANIFEST_FILENAME).read_bytes()
        ).hexdigest()
    except OSError as exc:
        raise _reject("code_install_unavailable") from exc
    if manifest_digest != bundle.release_sha256:
        raise _reject("code_release_identity_rejected")


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise _reject("code_install_unavailable") from exc


def _write_release(
    directory: Path,
    bundle: CodeReleaseBundle,
    *,
    uid: int,
    gid: int,
) -> None:
    try:
        directory.mkdir(mode=0o700)
        for relative in sorted(_expected_directories(), key=lambda item: (item.count("/"), item)):
            (directory / relative).mkdir(mode=0o700)
        payloads = dict(bundle.payloads)
        payloads[MANIFEST_FILENAME] = bundle.manifest_bytes
        for relative, payload in payloads.items():
            target = directory / relative
            descriptor = os.open(
                target,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                FILE_MODE,
            )
            try:
                os.fchown(descriptor, uid, gid)
                os.fchmod(descriptor, FILE_MODE)
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written < 1:
                        raise _reject("code_install_unavailable")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        for item in sorted(directory.rglob("*"), reverse=True):
            if item.is_dir():
                os.chown(item, uid, gid)
                os.chmod(item, RELEASE_MODE)
        os.chown(directory, uid, gid)
        os.chmod(directory, RELEASE_MODE)
        for item in sorted(directory.rglob("*"), reverse=True):
            if item.is_dir():
                _fsync_directory(item)
        _fsync_directory(directory)
    except OwnerProfileCodeInstallError:
        raise
    except OSError as exc:
        raise _reject("code_install_unavailable") from exc


def _rename_noreplace(directory_descriptor: int, source: str, target: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise _reject("code_install_noreplace_unavailable")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if renameat2(
        directory_descriptor,
        os.fsencode(source),
        directory_descriptor,
        os.fsencode(target),
        _RENAME_NOREPLACE,
    ) == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise _reject("code_release_conflict")
    if error in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP}:
        raise _reject("code_install_noreplace_unavailable")
    raise _reject("code_install_unavailable")


def install_code_release(
    bundle: CodeReleaseBundle,
    *,
    destination_root: Path = DESTINATION_ROOT,
    uid: int = 0,
    gid: int,
) -> tuple[Path, bool]:
    if (
        isinstance(uid, bool)
        or not isinstance(uid, int)
        or uid < 0
        or isinstance(gid, bool)
        or not isinstance(gid, int)
        or gid < 0
        or not destination_root.is_absolute()
        or destination_root.is_symlink()
    ):
        raise _reject("code_install_root_rejected")
    try:
        parent_metadata = destination_root.parent.lstat()
    except OSError as exc:
        raise _reject("code_install_root_rejected") from exc
    if (
        stat.S_ISLNK(parent_metadata.st_mode)
        or not stat.S_ISDIR(parent_metadata.st_mode)
    ):
        raise _reject("code_install_root_rejected")
    _ensure_root(destination_root, uid=uid, gid=gid)
    releases = destination_root / "releases"
    _ensure_root(releases, uid=uid, gid=gid)
    destination = releases / bundle.release_sha256
    pending = releases / f".pending-{bundle.release_sha256}"
    try:
        descriptor = os.open(
            releases,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise _reject("code_install_unavailable") from exc
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        if destination.exists() or destination.is_symlink():
            if pending.exists() or pending.is_symlink():
                raise _reject("code_install_recovery_required")
            _verify_release(
                destination,
                bundle,
                uid=uid,
                gid=gid,
                expected_name=destination.name,
            )
            return destination, False
        if pending.exists() or pending.is_symlink():
            _verify_release(
                pending,
                bundle,
                uid=uid,
                gid=gid,
                expected_name=pending.name,
            )
        else:
            _write_release(pending, bundle, uid=uid, gid=gid)
            _verify_release(
                pending,
                bundle,
                uid=uid,
                gid=gid,
                expected_name=pending.name,
            )
        _rename_noreplace(descriptor, pending.name, destination.name)
        os.fsync(descriptor)
        _verify_release(
            destination,
            bundle,
            uid=uid,
            gid=gid,
            expected_name=destination.name,
        )
        return destination, True
    except OwnerProfileCodeInstallError:
        raise
    except OSError as exc:
        raise _reject("code_install_unavailable") from exc
    finally:
        os.close(descriptor)


def _service_gid() -> int:
    try:
        account = pwd.getpwnam(SERVICE_ACCOUNT)
        group = grp.getgrnam(SERVICE_ACCOUNT)
    except KeyError as exc:
        raise _reject("profile_service_identity_missing") from exc
    if account.pw_gid != group.gr_gid:
        raise _reject("profile_service_identity_rejected")
    return group.gr_gid


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    arguments = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise _reject("must_run_as_root")
        verify_git_source(
            arguments.source_root,
            expected_commit=arguments.source_commit,
        )
        bundle = build_code_bundle(
            arguments.source_root,
            source_commit=arguments.source_commit,
        )
        _, created = install_code_release(bundle, gid=_service_gid())
        print(
            json.dumps(
                {
                    "status": "CODE_RELEASE_INSTALLED_INACTIVE",
                    "created": created,
                    "code_release_sha256": bundle.release_sha256,
                    "source_commit": bundle.source_commit,
                    "profile_content_present": False,
                    "service_changed": False,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 0
    except OwnerProfileCodeInstallError as exc:
        print(
            json.dumps(
                {
                    "status": "REJECTED",
                    "error_category": str(exc),
                    "profile_content_present": False,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
