#!/usr/bin/env python3
"""Verify and install one Owner-approved immutable Profile release."""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
import errno
import fcntl
import grp
import json
import os
from pathlib import Path
import pwd
import stat
from typing import Mapping, Sequence

from myuna_core.owner_profile.approval import (
    APPROVAL_FILENAME,
    MAX_APPROVAL_BYTES,
    ProfileReleaseApproval,
    verify_profile_approval,
)
from myuna_core.owner_profile.contracts import (
    MAX_PROFILE_BYTES,
    MAX_RECEIPT_BYTES,
    PROFILE_FILENAME,
    RECEIPT_FILENAME,
    SCHEMA_VERSION,
    OwnerProfile,
    OwnerProfileError,
    ProfileReceipt,
)
from myuna_core.owner_profile.loader import (
    parse_profile_bytes,
    parse_receipt_bytes,
)


DESTINATION_ROOT = Path("/var/lib/myuna-owner-profile-v1")
DEFAULT_INTAKE_ROOT = Path(
    "/home/serveradmin/.local/share/myuna-owner-profile/drafts"
)
SERVICE_ACCOUNT = "myuna_owner_profile"
ROOT_MODE = 0o710
RELEASE_MODE = 0o700
FILE_MODE = 0o600
_INTAKE_FILES = frozenset({PROFILE_FILENAME, RECEIPT_FILENAME, APPROVAL_FILENAME})
_RELEASE_FILES = frozenset({PROFILE_FILENAME, RECEIPT_FILENAME})
_RENAME_NOREPLACE = 1


class OwnerProfileInstallError(RuntimeError):
    """A deterministic content-free install rejection."""


@dataclass(frozen=True, slots=True)
class IntakeBundle:
    profile: OwnerProfile
    approval: ProfileReleaseApproval
    approval_bytes: bytes
    profile_bytes: bytes
    receipt_bytes: bytes

    @property
    def release_name(self) -> str:
        return f"r{self.profile.profile_revision}-{self.profile.sha256}"


def _reject(code: str) -> OwnerProfileInstallError:
    return OwnerProfileInstallError(code)


def _validate_uid(value: int, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _reject(code)
    return value


def _validate_gid(value: int, code: str) -> int:
    return _validate_uid(value, code)


def _inside(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def _validate_directory_metadata(
    metadata: os.stat_result,
    *,
    mode: int,
    uid: int,
    gid: int | None,
    code: str,
) -> None:
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_uid != uid
        or (gid is not None and metadata.st_gid != gid)
    ):
        raise _reject(code)


def _validate_file_metadata(
    metadata: os.stat_result,
    *,
    uid: int,
    gid: int | None,
    code: str,
) -> None:
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != FILE_MODE
        or metadata.st_nlink != 1
        or metadata.st_uid != uid
        or (gid is not None and metadata.st_gid != gid)
    ):
        raise _reject(code)


def _open_directory(
    path: Path,
    *,
    mode: int,
    uid: int,
    gid: int | None,
    code: str,
) -> int:
    try:
        before = path.lstat()
        _validate_directory_metadata(before, mode=mode, uid=uid, gid=gid, code=code)
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OwnerProfileInstallError:
        raise
    except OSError as exc:
        raise _reject("profile_install_unavailable") from exc
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise _reject(code)
        _validate_directory_metadata(opened, mode=mode, uid=uid, gid=gid, code=code)
    except OwnerProfileInstallError:
        os.close(descriptor)
        raise
    except OSError as exc:
        os.close(descriptor)
        raise _reject("profile_install_unavailable") from exc
    return descriptor


def _read_file(
    directory_descriptor: int,
    name: str,
    *,
    maximum: int,
    uid: int,
    gid: int | None,
    code: str,
) -> bytes:
    try:
        before = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        _validate_file_metadata(before, uid=uid, gid=gid, code=code)
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
    except OwnerProfileInstallError:
        raise
    except OSError as exc:
        raise _reject("profile_install_unavailable") from exc
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise _reject(code)
        _validate_file_metadata(opened, uid=uid, gid=gid, code=code)
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(4096, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        payload = b"".join(chunks)
    except OwnerProfileInstallError:
        raise
    except OSError as exc:
        raise _reject("profile_install_unavailable") from exc
    finally:
        os.close(descriptor)
    if not payload or len(payload) > maximum:
        raise _reject(code)
    return payload


def _read_exact_file_set(
    directory: Path,
    *,
    names: frozenset[str],
    maxima: Mapping[str, int],
    mode: int,
    uid: int,
    gid: int | None,
    code: str,
) -> dict[str, bytes]:
    descriptor = _open_directory(
        directory,
        mode=mode,
        uid=uid,
        gid=gid,
        code=code,
    )
    try:
        try:
            actual = frozenset(os.listdir(descriptor))
        except OSError as exc:
            raise _reject("profile_install_unavailable") from exc
        if actual != names:
            raise _reject(code)
        return {
            name: _read_file(
                descriptor,
                name,
                maximum=maxima[name],
                uid=uid,
                gid=gid,
                code=code,
            )
            for name in sorted(names)
        }
    finally:
        os.close(descriptor)


def _expected_receipt(profile: OwnerProfile) -> ProfileReceipt:
    return ProfileReceipt(
        profile_sha256=profile.sha256,
        profile_bytes=profile.byte_count,
        profile_schema_version=SCHEMA_VERSION,
        profile_id=profile.profile_id,
        profile_revision=profile.profile_revision,
        section_count=len(profile.sections),
        category_counts=profile.category_counts,
    )


def load_intake_bundle(
    intake: Path,
    *,
    intake_uid: int,
    allowed_roots: tuple[Path, ...] = (DEFAULT_INTAKE_ROOT,),
) -> IntakeBundle:
    _validate_uid(intake_uid, "profile_intake_owner_rejected")
    if not isinstance(intake, Path) or not intake.is_absolute() or not allowed_roots:
        raise _reject("profile_intake_path_rejected")
    resolved_roots: list[Path] = []
    for root in allowed_roots:
        if not isinstance(root, Path) or not root.is_absolute():
            raise _reject("profile_intake_path_rejected")
        try:
            resolved_root = root.resolve(strict=True)
            root_metadata = root.lstat()
        except OSError as exc:
            raise _reject("profile_intake_unavailable") from exc
        if resolved_root != root:
            raise _reject("profile_intake_path_rejected")
        _validate_directory_metadata(
            root_metadata,
            mode=RELEASE_MODE,
            uid=intake_uid,
            gid=None,
            code="profile_intake_root_rejected",
        )
        resolved_roots.append(resolved_root)
    try:
        resolved = intake.resolve(strict=True)
    except OSError as exc:
        raise _reject("profile_intake_unavailable") from exc
    if resolved != intake or not _inside(resolved, tuple(resolved_roots)):
        raise _reject("profile_intake_path_rejected")
    payloads = _read_exact_file_set(
        resolved,
        names=_INTAKE_FILES,
        maxima={
            PROFILE_FILENAME: MAX_PROFILE_BYTES,
            RECEIPT_FILENAME: MAX_RECEIPT_BYTES,
            APPROVAL_FILENAME: MAX_APPROVAL_BYTES,
        },
        mode=RELEASE_MODE,
        uid=intake_uid,
        gid=None,
        code="profile_intake_metadata_rejected",
    )
    try:
        profile = parse_profile_bytes(payloads[PROFILE_FILENAME])
        receipt = parse_receipt_bytes(payloads[RECEIPT_FILENAME])
        approval = verify_profile_approval(profile, payloads[APPROVAL_FILENAME])
    except OwnerProfileError as exc:
        raise _reject(exc.code) from exc
    if receipt != _expected_receipt(profile):
        raise _reject("receipt_mismatch")
    if resolved.name != f"r{profile.profile_revision}-{profile.sha256}":
        raise _reject("profile_intake_identity_rejected")
    return IntakeBundle(
        profile=profile,
        approval=approval,
        approval_bytes=payloads[APPROVAL_FILENAME],
        profile_bytes=payloads[PROFILE_FILENAME],
        receipt_bytes=payloads[RECEIPT_FILENAME],
    )


def _ensure_root(path: Path, *, uid: int, gid: int) -> None:
    try:
        os.mkdir(path, ROOT_MODE)
        created = True
    except FileExistsError:
        created = False
    except OSError as exc:
        raise _reject("profile_install_unavailable") from exc
    if created:
        try:
            os.chown(path, uid, gid)
            os.chmod(path, ROOT_MODE)
        except OSError as exc:
            raise _reject("profile_install_unavailable") from exc
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise _reject("profile_install_unavailable") from exc
    _validate_directory_metadata(
        metadata,
        mode=ROOT_MODE,
        uid=uid,
        gid=gid,
        code="profile_install_root_rejected",
    )


def _write_staged_release(
    pending: Path,
    bundle: IntakeBundle,
    *,
    service_uid: int,
    service_gid: int,
) -> None:
    try:
        os.mkdir(pending, RELEASE_MODE)
        os.chown(pending, service_uid, service_gid)
        os.chmod(pending, RELEASE_MODE)
        directory_descriptor = _open_directory(
            pending,
            mode=RELEASE_MODE,
            uid=service_uid,
            gid=service_gid,
            code="profile_install_pending_rejected",
        )
    except FileExistsError as exc:
        raise _reject("profile_install_recovery_required") from exc
    except OSError as exc:
        raise _reject("profile_install_unavailable") from exc
    payloads = {
        PROFILE_FILENAME: bundle.profile_bytes,
        RECEIPT_FILENAME: bundle.receipt_bytes,
    }
    try:
        for name, payload in payloads.items():
            try:
                descriptor = os.open(
                    name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    FILE_MODE,
                    dir_fd=directory_descriptor,
                )
            except OSError as exc:
                raise _reject("profile_install_unavailable") from exc
            try:
                os.fchown(descriptor, service_uid, service_gid)
                os.fchmod(descriptor, FILE_MODE)
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written < 1:
                        raise _reject("profile_install_unavailable")
                    view = view[written:]
                os.fsync(descriptor)
            except OSError as exc:
                raise _reject("profile_install_unavailable") from exc
            finally:
                os.close(descriptor)
        try:
            os.fsync(directory_descriptor)
        except OSError as exc:
            raise _reject("profile_install_unavailable") from exc
    finally:
        os.close(directory_descriptor)


def _verify_installed_release(
    directory: Path,
    bundle: IntakeBundle,
    *,
    service_uid: int,
    service_gid: int,
    expected_name: str,
) -> None:
    payloads = _read_exact_file_set(
        directory,
        names=_RELEASE_FILES,
        maxima={
            PROFILE_FILENAME: MAX_PROFILE_BYTES,
            RECEIPT_FILENAME: MAX_RECEIPT_BYTES,
        },
        mode=RELEASE_MODE,
        uid=service_uid,
        gid=service_gid,
        code="profile_installed_release_rejected",
    )
    if (
        payloads[PROFILE_FILENAME] != bundle.profile_bytes
        or payloads[RECEIPT_FILENAME] != bundle.receipt_bytes
    ):
        raise _reject("profile_installed_release_conflict")
    try:
        profile = parse_profile_bytes(payloads[PROFILE_FILENAME])
        receipt = parse_receipt_bytes(payloads[RECEIPT_FILENAME])
    except OwnerProfileError as exc:
        raise _reject(exc.code) from exc
    if (
        profile != bundle.profile
        or receipt != _expected_receipt(profile)
        or directory.name != expected_name
    ):
        raise _reject("profile_installed_release_rejected")


def _rename_noreplace(
    directory_descriptor: int,
    source_name: str,
    destination_name: str,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise _reject("profile_install_noreplace_unavailable")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        directory_descriptor,
        os.fsencode(source_name),
        directory_descriptor,
        os.fsencode(destination_name),
        _RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise _reject("profile_installed_release_conflict")
    if error in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP}:
        raise _reject("profile_install_noreplace_unavailable")
    raise _reject("profile_install_unavailable")


def install_profile_release(
    bundle: IntakeBundle,
    *,
    destination_root: Path = DESTINATION_ROOT,
    root_uid: int = 0,
    service_uid: int,
    service_gid: int,
) -> tuple[Path, bool]:
    _validate_uid(root_uid, "profile_install_owner_rejected")
    _validate_uid(service_uid, "profile_install_owner_rejected")
    _validate_gid(service_gid, "profile_install_group_rejected")
    if not destination_root.is_absolute() or destination_root.is_symlink():
        raise _reject("profile_install_root_rejected")
    try:
        parent_metadata = destination_root.parent.lstat()
    except OSError as exc:
        raise _reject("profile_install_root_rejected") from exc
    if (
        stat.S_ISLNK(parent_metadata.st_mode)
        or not stat.S_ISDIR(parent_metadata.st_mode)
    ):
        raise _reject("profile_install_root_rejected")
    _ensure_root(destination_root, uid=root_uid, gid=service_gid)
    releases = destination_root / "releases"
    _ensure_root(releases, uid=root_uid, gid=service_gid)
    releases_descriptor = _open_directory(
        releases,
        mode=ROOT_MODE,
        uid=root_uid,
        gid=service_gid,
        code="profile_install_root_rejected",
    )
    destination = releases / bundle.release_name
    pending = releases / f".pending-{bundle.release_name}"
    try:
        try:
            fcntl.flock(releases_descriptor, fcntl.LOCK_EX)
        except OSError as exc:
            raise _reject("profile_install_unavailable") from exc
        if destination.exists() or destination.is_symlink():
            if pending.exists() or pending.is_symlink():
                raise _reject("profile_install_recovery_required")
            _verify_installed_release(
                destination,
                bundle,
                service_uid=service_uid,
                service_gid=service_gid,
                expected_name=destination.name,
            )
            return destination, False
        if pending.exists() or pending.is_symlink():
            _verify_installed_release(
                pending,
                bundle,
                service_uid=service_uid,
                service_gid=service_gid,
                expected_name=pending.name,
            )
        else:
            _write_staged_release(
                pending,
                bundle,
                service_uid=service_uid,
                service_gid=service_gid,
            )
            _verify_installed_release(
                pending,
                bundle,
                service_uid=service_uid,
                service_gid=service_gid,
                expected_name=pending.name,
            )
        _rename_noreplace(
            releases_descriptor,
            pending.name,
            destination.name,
        )
        try:
            os.fsync(releases_descriptor)
        except OSError as exc:
            raise _reject("profile_install_unavailable") from exc
        _verify_installed_release(
            destination,
            bundle,
            service_uid=service_uid,
            service_gid=service_gid,
            expected_name=destination.name,
        )
        return destination, True
    finally:
        os.close(releases_descriptor)


def _service_identity() -> tuple[int, int]:
    try:
        account = pwd.getpwnam(SERVICE_ACCOUNT)
        group = grp.getgrnam(SERVICE_ACCOUNT)
    except KeyError as exc:
        raise _reject("profile_service_identity_missing") from exc
    if account.pw_gid != group.gr_gid:
        raise _reject("profile_service_identity_rejected")
    return account.pw_uid, group.gr_gid


def _status(*, status: str, revision: int, created: bool | None = None) -> str:
    payload: dict[str, object] = {
        "status": status,
        "profile_revision": revision,
        "raw_content_recorded": False,
        "profile_digest_recorded": False,
        "profile_identity_recorded": False,
    }
    if created is not None:
        payload["created"] = created
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--intake-owner-uid", required=True, type=int)
    parser.add_argument("intake", type=Path)
    arguments = parser.parse_args(argv)
    try:
        bundle = load_intake_bundle(
            arguments.intake,
            intake_uid=arguments.intake_owner_uid,
        )
        if arguments.verify_only:
            print(
                _status(
                    status="INTAKE_VERIFIED_NO_MUTATION",
                    revision=bundle.profile.profile_revision,
                )
            )
            return 0
        if os.geteuid() != 0:
            raise _reject("must_run_as_root")
        service_uid, service_gid = _service_identity()
        _, created = install_profile_release(
            bundle,
            service_uid=service_uid,
            service_gid=service_gid,
        )
        print(
            _status(
                status="INSTALLED_INACTIVE",
                revision=bundle.profile.profile_revision,
                created=created,
            )
        )
        return 0
    except OwnerProfileInstallError as exc:
        print(
            json.dumps(
                {
                    "status": "REJECTED",
                    "error_category": str(exc),
                    "raw_content_recorded": False,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
