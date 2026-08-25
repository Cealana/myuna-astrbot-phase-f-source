#!/usr/bin/env python3
"""Prepare one private exact Owner-approved Profile release intake."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import re
import stat
from typing import Sequence

from install_owner_profile_data_v1 import (
    APPROVAL_FILENAME,
    PROFILE_FILENAME,
    RECEIPT_FILENAME,
    OwnerProfileInstallError,
    load_intake_bundle,
)
from myuna_core.owner_profile.approval import (
    APPROVAL_DECISION,
    APPROVAL_SCOPE,
    APPROVAL_TYPE,
)
from myuna_core.owner_profile.contracts import (
    MAX_PROFILE_BYTES,
    MAX_RECEIPT_BYTES,
    SCHEMA_VERSION,
    OwnerProfileError,
)
from myuna_core.owner_profile.loader import (
    parse_profile_bytes,
    parse_receipt_bytes,
)


DEFAULT_INTAKE_ROOT = Path(
    "/home/serveradmin/.local/share/myuna-owner-profile/drafts"
)
DIRECTORY_MODE = 0o700
FILE_MODE = 0o600
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class OwnerProfileIntakePrepareError(RuntimeError):
    """A deterministic content-free intake preparation rejection."""


def _reject(code: str) -> OwnerProfileIntakePrepareError:
    return OwnerProfileIntakePrepareError(code)


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


def _validate_directory(path: Path, *, uid: int) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise _reject("intake_root_unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != DIRECTORY_MODE
        or metadata.st_uid != uid
    ):
        raise _reject("intake_root_rejected")


def _read_source(path: Path, *, uid: int, maximum: int) -> bytes:
    if not isinstance(path, Path) or not path.is_absolute():
        raise _reject("intake_source_rejected")
    try:
        before = path.lstat()
    except OSError as exc:
        raise _reject("intake_source_unavailable") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) != FILE_MODE
        or before.st_uid != uid
        or before.st_nlink != 1
        or before.st_size < 1
        or before.st_size > maximum
    ):
        raise _reject("intake_source_rejected")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise _reject("intake_source_unavailable") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != FILE_MODE
            or opened.st_uid != uid
            or opened.st_nlink != 1
        ):
            raise _reject("intake_source_rejected")
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(4096, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OwnerProfileIntakePrepareError:
        raise
    except OSError as exc:
        raise _reject("intake_source_unavailable") from exc
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    if not payload or len(payload) > maximum or len(payload) != before.st_size:
        raise _reject("intake_source_rejected")
    return payload


def _approval_bytes(profile_id: str, revision: int, digest: str) -> bytes:
    return _canonical(
        {
            "schema_version": 1,
            "approval_type": APPROVAL_TYPE,
            "approval_scope": APPROVAL_SCOPE,
            "decision": APPROVAL_DECISION,
            "profile_schema_version": SCHEMA_VERSION,
            "profile_id": profile_id,
            "profile_revision": revision,
            "profile_sha256": digest,
        }
    )


def _write_file(
    directory_descriptor: int,
    name: str,
    payload: bytes,
    *,
    uid: int,
    gid: int,
) -> None:
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
        raise _reject("intake_write_unavailable") from exc
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written < 1:
                raise _reject("intake_write_unavailable")
            view = view[written:]
        os.fsync(descriptor)
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, FILE_MODE)
    except OwnerProfileIntakePrepareError:
        raise
    except OSError as exc:
        raise _reject("intake_write_unavailable") from exc
    finally:
        os.close(descriptor)


def prepare_intake(
    profile_source: Path,
    receipt_source: Path,
    *,
    expected_sha256: str,
    expected_revision: int,
    intake_root: Path = DEFAULT_INTAKE_ROOT,
    owner_uid: int | None = None,
    owner_gid: int | None = None,
) -> tuple[Path, bool]:
    uid = os.geteuid() if owner_uid is None else owner_uid
    gid = os.getegid() if owner_gid is None else owner_gid
    if (
        isinstance(uid, bool)
        or not isinstance(uid, int)
        or uid < 1
        or isinstance(gid, bool)
        or not isinstance(gid, int)
        or gid < 1
        or (os.geteuid() != 0 and uid != os.geteuid())
        or not isinstance(expected_sha256, str)
        or _DIGEST.fullmatch(expected_sha256) is None
        or isinstance(expected_revision, bool)
        or not isinstance(expected_revision, int)
        or expected_revision < 1
        or not intake_root.is_absolute()
        or profile_source.parent != intake_root
        or receipt_source.parent != intake_root
    ):
        raise _reject("intake_request_rejected")
    _validate_directory(intake_root, uid=uid)
    profile_bytes = _read_source(
        profile_source,
        uid=uid,
        maximum=MAX_PROFILE_BYTES,
    )
    receipt_bytes = _read_source(
        receipt_source,
        uid=uid,
        maximum=MAX_RECEIPT_BYTES,
    )
    try:
        profile = parse_profile_bytes(profile_bytes)
        receipt = parse_receipt_bytes(receipt_bytes)
    except OwnerProfileError as exc:
        raise _reject(exc.code) from exc
    if (
        profile.sha256 != expected_sha256
        or sha256(profile_bytes).hexdigest() != expected_sha256
        or profile.profile_revision != expected_revision
        or receipt.profile_sha256 != expected_sha256
        or receipt.profile_revision != expected_revision
        or receipt.profile_id != profile.profile_id
        or receipt.profile_bytes != len(profile_bytes)
        or receipt.section_count != len(profile.sections)
        or receipt.category_counts != profile.category_counts
    ):
        raise _reject("intake_binding_rejected")
    destination = intake_root / f"r{expected_revision}-{expected_sha256}"
    if destination.exists() or destination.is_symlink():
        try:
            bundle = load_intake_bundle(
                destination,
                intake_uid=uid,
                allowed_roots=(intake_root,),
            )
        except OwnerProfileInstallError as exc:
            raise _reject(str(exc)) from exc
        if (
            bundle.profile_bytes != profile_bytes
            or bundle.receipt_bytes != receipt_bytes
        ):
            raise _reject("intake_existing_conflict")
        return destination, False
    try:
        destination.mkdir(mode=DIRECTORY_MODE)
        os.chown(destination, uid, gid)
        os.chmod(destination, DIRECTORY_MODE)
        directory_descriptor = os.open(
            destination,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise _reject("intake_write_unavailable") from exc
    try:
        _write_file(
            directory_descriptor,
            PROFILE_FILENAME,
            profile_bytes,
            uid=uid,
            gid=gid,
        )
        _write_file(
            directory_descriptor,
            RECEIPT_FILENAME,
            receipt_bytes,
            uid=uid,
            gid=gid,
        )
        _write_file(
            directory_descriptor,
            APPROVAL_FILENAME,
            _approval_bytes(
                profile.profile_id,
                profile.profile_revision,
                profile.sha256,
            ),
            uid=uid,
            gid=gid,
        )
        os.fsync(directory_descriptor)
    except OSError as exc:
        raise _reject("intake_write_unavailable") from exc
    finally:
        os.close(directory_descriptor)
    try:
        bundle = load_intake_bundle(
            destination,
            intake_uid=uid,
            allowed_roots=(intake_root,),
        )
    except OwnerProfileInstallError as exc:
        raise _reject(str(exc)) from exc
    if bundle.profile_bytes != profile_bytes or bundle.receipt_bytes != receipt_bytes:
        raise _reject("intake_postwrite_rejected")
    try:
        root_descriptor = os.open(
            intake_root,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(root_descriptor)
        finally:
            os.close(root_descriptor)
    except OSError as exc:
        raise _reject("intake_write_unavailable") from exc
    return destination, True


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--expected-revision", required=True, type=int)
    parser.add_argument("--owner-account", default="serveradmin")
    arguments = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise _reject("intake_requires_root")
        try:
            owner = pwd.getpwnam(arguments.owner_account)
        except KeyError as exc:
            raise _reject("intake_owner_missing") from exc
        _, created = prepare_intake(
            arguments.profile,
            arguments.receipt,
            expected_sha256=arguments.expected_sha256,
            expected_revision=arguments.expected_revision,
            owner_uid=owner.pw_uid,
            owner_gid=owner.pw_gid,
        )
        print(
            json.dumps(
                {
                    "status": "OWNER_APPROVED_INTAKE_READY",
                    "profile_revision": arguments.expected_revision,
                    "created": created,
                    "raw_content_recorded": False,
                    "profile_digest_recorded": False,
                    "profile_identity_recorded": False,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 0
    except OwnerProfileIntakePrepareError as exc:
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
