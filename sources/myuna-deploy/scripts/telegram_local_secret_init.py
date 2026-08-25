#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
from typing import Callable


SECRET_ROOT = Path("/etc/myuna-telegram-gateway/secrets")
SECRET_NAMES = (
    "channel-signing-v1",
    "core-token-v1",
    "identity-pepper-v1",
)
_SECRET_VALUE = re.compile(rb"^[A-Za-z0-9_-]{43,128}$")


class LocalSecretInitRejected(RuntimeError):
    """Content-free rejection; secret-derived material must never escape."""


def _new_secret() -> bytes:
    return secrets.token_urlsafe(48).encode("ascii")


def initialize_local_secrets(
    root: Path,
    *,
    secret_factory: Callable[[], bytes] = _new_secret,
    uid: int = 0,
    gid: int = 0,
) -> tuple[str, ...]:
    if root.is_symlink():
        raise LocalSecretInitRejected("Telegram local secret init rejected")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(root, uid, gid)
    os.chmod(root, 0o700)
    root_metadata = root.stat()
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != uid
        or root_metadata.st_gid != gid
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise LocalSecretInitRejected("Telegram local secret init rejected")

    targets = tuple(root / name for name in SECRET_NAMES)
    if any(target.exists() or target.is_symlink() for target in targets):
        raise LocalSecretInitRejected("Telegram local secret init rejected")

    buffers: list[bytearray] = []
    temporary_paths: list[Path] = []
    installed_paths: list[Path] = []
    try:
        seen: set[bytes] = set()
        for name, target in zip(SECRET_NAMES, targets, strict=True):
            buffer = bytearray(secret_factory())
            buffers.append(buffer)
            value = bytes(buffer)
            if _SECRET_VALUE.fullmatch(value) is None or value in seen:
                raise LocalSecretInitRejected("Telegram local secret init rejected")
            seen.add(value)

            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{name}.",
                dir=root,
            )
            temporary = Path(temporary_name)
            temporary_paths.append(temporary)
            try:
                os.fchmod(descriptor, 0o600)
                os.fchown(descriptor, uid, gid)
                with os.fdopen(descriptor, "wb") as handle:
                    descriptor = -1
                    handle.write(value + b"\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            finally:
                if descriptor >= 0:
                    os.close(descriptor)

            os.link(temporary, target, follow_symlinks=False)
            installed_paths.append(target)
            temporary.unlink()
            temporary_paths.remove(temporary)

        for target in targets:
            metadata = target.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != uid
                or metadata.st_gid != gid
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise LocalSecretInitRejected(
                    "Telegram local secret init rejected"
                )
        directory_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        return SECRET_NAMES
    except (LocalSecretInitRejected, OSError, ValueError):
        for target in reversed(installed_paths):
            target.unlink(missing_ok=True)
        raise LocalSecretInitRejected("Telegram local secret init rejected") from None
    finally:
        for temporary in temporary_paths:
            temporary.unlink(missing_ok=True)
        for buffer in buffers:
            for index in range(len(buffer)):
                buffer[index] = 0


def main() -> int:
    if os.geteuid() != 0:
        raise LocalSecretInitRejected("local root authority is required")
    created = initialize_local_secrets(SECRET_ROOT)
    print(
        json.dumps(
            {
                "created_secret_names": list(created),
                "result": "telegram-local-secrets-created",
                "secret_values_echoed": False,
                "secret_values_hashed": False,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (LocalSecretInitRejected, OSError):
        print("Telegram local secret init rejected", file=sys.stderr)
        raise SystemExit(1) from None
