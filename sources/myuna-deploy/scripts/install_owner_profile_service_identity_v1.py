#!/usr/bin/env python3
"""Install and verify the inert Owner Profile read-worker system identity."""

from __future__ import annotations

import argparse
import fcntl
import grp
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import tempfile
from typing import Callable, Sequence


SERVICE_ACCOUNT = "myuna_owner_profile"
SERVICE_HOME = "/nonexistent"
SERVICE_SHELL = "/usr/sbin/nologin"
SYSUSERS_PATH = Path(
    "/usr/lib/sysusers.d/myuna-owner-profile-read-v1.conf"
)
SYSUSERS_BYTES = (
    b'u myuna_owner_profile - "Myuna Owner Profile read-only service" '
    b'/nonexistent /usr/sbin/nologin\n'
)
FILE_MODE = 0o644


class OwnerProfileIdentityInstallError(RuntimeError):
    """A deterministic content-free identity install rejection."""


def _reject(code: str) -> OwnerProfileIdentityInstallError:
    return OwnerProfileIdentityInstallError(code)


def _validate_parent(path: Path, *, uid: int, gid: int) -> int:
    parent = path.parent
    try:
        before = parent.lstat()
        descriptor = os.open(
            parent,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise _reject("identity_install_unavailable") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISDIR(before.st_mode)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_uid != uid
            or opened.st_gid != gid
            or stat.S_IMODE(opened.st_mode) != 0o755
        ):
            raise _reject("identity_install_parent_rejected")
    except OwnerProfileIdentityInstallError:
        os.close(descriptor)
        raise
    except OSError as exc:
        os.close(descriptor)
        raise _reject("identity_install_unavailable") from exc
    return descriptor


def _verify_config(path: Path, *, uid: int, gid: int) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise _reject("identity_install_unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != FILE_MODE
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or metadata.st_nlink != 1
    ):
        raise _reject("identity_config_rejected")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise _reject("identity_install_unavailable") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            (metadata.st_dev, metadata.st_ino)
            != (opened.st_dev, opened.st_ino)
            or not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != FILE_MODE
            or opened.st_uid != uid
            or opened.st_gid != gid
            or opened.st_nlink != 1
        ):
            raise _reject("identity_config_rejected")
        payload = os.read(descriptor, len(SYSUSERS_BYTES) + 1)
    except OwnerProfileIdentityInstallError:
        raise
    except OSError as exc:
        raise _reject("identity_install_unavailable") from exc
    finally:
        os.close(descriptor)
    if payload != SYSUSERS_BYTES:
        raise _reject("identity_config_rejected")


def install_identity_config(
    destination: Path = SYSUSERS_PATH,
    *,
    uid: int = 0,
    gid: int = 0,
) -> bool:
    if (
        not isinstance(destination, Path)
        or not destination.is_absolute()
        or destination.name != SYSUSERS_PATH.name
        or isinstance(uid, bool)
        or not isinstance(uid, int)
        or uid < 0
        or isinstance(gid, bool)
        or not isinstance(gid, int)
        or gid < 0
    ):
        raise _reject("identity_install_path_rejected")
    parent_descriptor = _validate_parent(destination, uid=uid, gid=gid)
    temporary: str | None = None
    created = False
    try:
        fcntl.flock(parent_descriptor, fcntl.LOCK_EX)
        if destination.exists() or destination.is_symlink():
            _verify_config(destination, uid=uid, gid=gid)
            return False
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            dir=destination.parent,
        )
        try:
            view = memoryview(SYSUSERS_BYTES)
            while view:
                written = os.write(descriptor, view)
                if written < 1:
                    raise _reject("identity_install_unavailable")
                view = view[written:]
            os.fsync(descriptor)
            os.fchown(descriptor, uid, gid)
            os.fchmod(descriptor, FILE_MODE)
        finally:
            os.close(descriptor)
        try:
            os.link(temporary, destination, follow_symlinks=False)
        except FileExistsError:
            _verify_config(destination, uid=uid, gid=gid)
            return False
        created = True
        os.unlink(temporary)
        temporary = None
        os.fsync(parent_descriptor)
        _verify_config(destination, uid=uid, gid=gid)
        return True
    except OwnerProfileIdentityInstallError:
        raise
    except OSError as exc:
        raise _reject("identity_install_unavailable") from exc
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
        os.close(parent_descriptor)


def validate_service_identity(
    *,
    account_lookup: Callable[[str], object] = pwd.getpwnam,
    group_lookup: Callable[[str], object] = grp.getgrnam,
) -> tuple[int, int]:
    try:
        account = account_lookup(SERVICE_ACCOUNT)
        group = group_lookup(SERVICE_ACCOUNT)
        uid = int(getattr(account, "pw_uid"))
        primary_gid = int(getattr(account, "pw_gid"))
        home = str(getattr(account, "pw_dir"))
        shell = str(getattr(account, "pw_shell"))
        gid = int(getattr(group, "gr_gid"))
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise _reject("profile_service_identity_missing") from exc
    if (
        uid < 1
        or gid < 1
        or primary_gid != gid
        or home != SERVICE_HOME
        or shell != SERVICE_SHELL
    ):
        raise _reject("profile_service_identity_rejected")
    return uid, gid


def _run_sysusers(path: Path) -> None:
    try:
        completed = subprocess.run(
            ["/usr/bin/systemd-sysusers", str(path)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _reject("identity_install_unavailable") from exc
    if completed.returncode != 0:
        raise _reject("identity_install_rejected")


def prepare_service_identity(
    destination: Path = SYSUSERS_PATH,
    *,
    uid: int = 0,
    gid: int = 0,
    runner: Callable[[Path], None] = _run_sysusers,
) -> bool:
    created = install_identity_config(destination, uid=uid, gid=gid)
    runner(destination)
    validate_service_identity()
    return created


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise _reject("must_run_as_root")
        created = prepare_service_identity()
        print(
            json.dumps(
                {
                    "status": "SERVICE_IDENTITY_READY_INERT",
                    "created": created,
                    "service_started": False,
                    "profile_content_present": False,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 0
    except OwnerProfileIdentityInstallError as exc:
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
