#!/usr/bin/env python3
"""Render one strict content-free P16 snapshot or explicit incident lookup."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys

from fault_diagnostics_v1 import OUTPUT_SCHEMA, build_diagnostic_report


_MAX_SNAPSHOT_BYTES = 128 * 1024


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="myuna-diagnose")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--snapshot",
        help="Path to a sanitized myuna.diagnostics.snapshot.v1 file, or - for stdin.",
    )
    source.add_argument(
        "--channel",
        choices=("all", "qq", "telegram"),
        help="Collect only allowlisted local metadata for the selected channel.",
    )
    source.add_argument(
        "--incident-index",
        help=(
            "Path to a sanitized myuna.user-visible-fault-index-set.v1 file, "
            "or - for stdin. This source-only entry is never selected by default."
        ),
    )
    parser.add_argument(
        "--incident-ref",
        help="Opaque inc1 reference required with --incident-index.",
    )
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--pretty", action="store_true")
    return parser


def _load_snapshot(source: str) -> object:
    if source == "-":
        encoded = sys.stdin.buffer.read(_MAX_SNAPSHOT_BYTES + 1)
    else:
        path = Path(source)
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("snapshot path is invalid")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise ValueError("snapshot path is invalid")
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError("snapshot path changed while opening")
            if opened.st_size <= 0 or opened.st_size > _MAX_SNAPSHOT_BYTES:
                raise ValueError("snapshot size is invalid")
            encoded = stream.read(_MAX_SNAPSHOT_BYTES + 1)
    if not encoded or len(encoded) > _MAX_SNAPSHOT_BYTES:
        raise ValueError("snapshot size is invalid")
    return json.loads(encoded.decode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.incident_index is not None:
        try:
            if args.incident_ref is None:
                raise ValueError("incident_ref is required")
            from user_visible_fault_v1 import ContentFreeIncidentIndex

            index = ContentFreeIncidentIndex.from_payload(
                _load_snapshot(args.incident_index)
            )
            report = index.lookup(args.incident_ref)
        except (KeyError, OSError, UnicodeError, ValueError, json.JSONDecodeError):
            report = {
                "schema": "myuna.user-visible-fault-index.v1",
                "status": "unavailable",
                "error": "incident_lookup_unavailable",
                "private_content_read": False,
                "raw_log_read": False,
                "model_called": False,
                "channel_called": False,
                "provider_called": False,
                "state_changed": False,
            }
            print(json.dumps(report, ensure_ascii=True, separators=(",", ":")))
            return 3
        if args.pretty:
            print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))
        else:
            print(
                json.dumps(
                    report, ensure_ascii=True, separators=(",", ":"), sort_keys=True
                )
            )
        return 0
    if args.incident_ref is not None:
        report = {
            "schema": OUTPUT_SCHEMA,
            "overall": "failed",
            "error": "incident_ref_without_index",
            "private_content_read": False,
            "raw_log_read": False,
            "model_called": False,
            "channel_called": False,
            "provider_called": False,
            "state_changed": False,
        }
        print(json.dumps(report, ensure_ascii=True, separators=(",", ":")))
        return 3
    try:
        if args.snapshot is not None:
            snapshot = _load_snapshot(args.snapshot)
        else:
            from fault_diagnostics_collector_v1 import collect_diagnostic_snapshot

            snapshot = collect_diagnostic_snapshot(
                args.channel,
                timeout_seconds=args.timeout,
            )
        report = build_diagnostic_report(snapshot)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        report = {
            "schema": OUTPUT_SCHEMA,
            "overall": "failed",
            "error": "invalid_snapshot",
            "private_content_read": False,
            "raw_log_read": False,
            "model_called": False,
            "channel_called": False,
            "provider_called": False,
            "state_changed": False,
        }
        print(json.dumps(report, ensure_ascii=True, separators=(",", ":")))
        return 3
    if args.pretty:
        print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))
    else:
        print(json.dumps(report, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0 if report["overall"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
