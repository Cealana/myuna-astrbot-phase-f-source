#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


TOKEN_PATH = Path("/etc/myuna-telegram-gateway/secrets/bot-token-v1")
_TOKEN = re.compile(rb"^[1-9][0-9]{7,11}:[A-Za-z0-9_-]{30,80}$")
_MAX_STDIN_BYTES = 128


class TokenIntakeRejected(RuntimeError):
    """Content-free rejection; never include token-derived material."""


def validate_token(raw: bytes) -> bytes:
    token = raw.rstrip(b"\r\n")
    if not token or len(token) > _MAX_STDIN_BYTES or _TOKEN.fullmatch(token) is None:
        raise TokenIntakeRejected("Telegram token intake rejected")
    return token


def read_token_from_stdin(stream) -> bytes:
    raw = stream.read(_MAX_STDIN_BYTES + 2)
    if len(raw) > _MAX_STDIN_BYTES + 1:
        raise TokenIntakeRejected("Telegram token intake rejected")
    return validate_token(raw)


def write_secret_atomic(
    target: Path,
    token: bytes,
    *,
    replace: bool,
    uid: int = 0,
    gid: int = 0,
) -> None:
    token = validate_token(token)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(target.parent, uid, gid)
    os.chmod(target.parent, 0o700)
    if target.is_symlink():
        raise TokenIntakeRejected("Telegram token intake rejected")
    if target.exists() and not replace:
        raise TokenIntakeRejected("Telegram token intake rejected")

    descriptor: int | None = None
    temporary_name: str | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".bot-token-",
            dir=target.parent,
        )
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(token + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, target)
        temporary_name = None
        metadata = target.stat()
        if (
            metadata.st_uid != uid
            or metadata.st_gid != gid
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise TokenIntakeRejected("Telegram token intake rejected")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise TokenIntakeRejected("local root authority is required")

    token = bytearray(read_token_from_stdin(sys.stdin.buffer))
    try:
        write_secret_atomic(
            TOKEN_PATH,
            bytes(token),
            replace=args.replace,
        )
    finally:
        for index in range(len(token)):
            token[index] = 0

    print(
        json.dumps(
            {
                "result": "telegram-bot-token-stored",
                "secret_path": str(TOKEN_PATH),
                "token_echoed": False,
                "token_hashed_in_receipt": False,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, TokenIntakeRejected):
        print("Telegram token intake rejected", file=sys.stderr)
        raise SystemExit(1) from None
