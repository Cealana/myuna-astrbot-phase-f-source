#!/usr/bin/env python3
"""Synthetic-only proof of the contract-bound numeric credential launch."""
from __future__ import annotations

import argparse
from hashlib import sha256
import os
from pathlib import Path
import sys

import p08_activation_contract_v1 as contract_v1


SCHEMA = "myuna.p08-numeric-credential-probe.v1"


def _no_new_privileges() -> bool:
    try:
        raw = Path("/proc/self/status").read_bytes()
    except OSError:
        raise RuntimeError("credential_probe_rejected") from None
    rows = [line for line in raw.splitlines() if line.startswith(b"NoNewPrivs:")]
    if len(rows) != 1 or rows[0].split() != [b"NoNewPrivs:", b"1"]:
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--expected-uid", type=int, required=True)
    parser.add_argument("--expected-gid", type=int, required=True)
    values = parser.parse_args()
    source = Path(__file__)
    body = {
        "schema": SCHEMA,
        "uid": os.getuid(),
        "gid": os.getgid(),
        "groups": sorted(os.getgroups()),
        "no_new_privs": _no_new_privileges(),
        "source_sha256": sha256(source.read_bytes()).hexdigest(),
        "raw_output_included": False,
    }
    if (
        values.expected_uid < 0
        or values.expected_gid < 0
        or body["uid"] != values.expected_uid
        or body["gid"] != values.expected_gid
        or body["groups"] != []
        or body["no_new_privs"] is not True
    ):
        return 2
    sys.stdout.buffer.write(contract_v1.canonical_bytes(body))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
