#!/usr/bin/env python3
"""Reproduce a P16 T2 artifact/checkpoint preflight without live access."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from p16_phase1_t2_contract_v1 import build_preflight, canonical


def _read_canonical(path: Path, *, maximum: int = 1_000_000) -> object:
    metadata = path.lstat()
    if path.is_symlink() or not path.is_file() or metadata.st_size < 2 or metadata.st_size > maximum:
        raise ValueError("preflight input is invalid")
    raw = path.read_bytes()
    if not raw.endswith(b"\n"):
        raise ValueError("preflight input framing is invalid")
    value = json.loads(raw.decode("ascii"))
    if raw != canonical(value) + b"\n":
        raise ValueError("preflight input is not canonical")
    return value


def _write_exclusive(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o440,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical(payload) + b"\n")
            handle.flush()
            os.fchmod(handle.fileno(), 0o440)
            os.fsync(handle.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = build_preflight(
        _read_canonical(args.bundle),
        _read_canonical(args.checkpoint),
    )
    _write_exclusive(args.output, result)
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
