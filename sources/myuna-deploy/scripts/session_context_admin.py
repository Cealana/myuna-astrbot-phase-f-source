#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Final

from context_window_policy import SQLITE_CONTEXT_SCHEMA, SqliteContextStore


CHANNELS: Final[dict[str, tuple[Path, str]]] = {
    "qq": (
        Path("/var/lib/myuna-gateway/session-context/context.db"),
        "qq-owner-private-v1",
    ),
    "telegram": (
        Path("/var/lib/myuna-telegram-gateway/session-context/context.db"),
        "telegram-owner-private-v1",
    ),
}


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _missing_metadata(channel: str, namespace: str) -> dict[str, object]:
    return {
        "channel": channel,
        "schema": SQLITE_CONTEXT_SCHEMA,
        "namespace": namespace,
        "present": False,
        "message_count": 0,
        "character_count": 0,
    }


def inspect_channel(channel: str, *, show_content: bool) -> dict[str, object]:
    path, namespace = CHANNELS[channel]
    if not path.exists():
        return _missing_metadata(channel, namespace)
    store = SqliteContextStore(path, namespace=namespace)
    result: dict[str, object] = {
        "channel": channel,
        **store.public_metadata(),
    }
    if show_content:
        result["messages"] = store.export_messages()
    return result


def clear_channel(channel: str) -> bool:
    path, namespace = CHANNELS[channel]
    if not path.exists():
        return False
    return SqliteContextStore(path, namespace=namespace).clear()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect or explicitly clear Myuna owner-private session context."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("--channel", choices=sorted(CHANNELS), required=True)
    inspect_parser.add_argument(
        "--show-content",
        action="store_true",
        help="Explicitly print private message content; requires root.",
    )

    clear_parser = subparsers.add_parser("clear")
    clear_parser.add_argument(
        "--channel",
        choices=[*sorted(CHANNELS), "all"],
        required=True,
    )
    clear_parser.add_argument(
        "--confirm",
        required=True,
        help="Must exactly match CLEAR-QQ, CLEAR-TELEGRAM, or CLEAR-ALL.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "inspect":
        if args.show_content and not _is_root():
            raise SystemExit("--show-content requires root")
        print(
            json.dumps(
                inspect_channel(args.channel, show_content=args.show_content),
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 0

    expected = f"CLEAR-{args.channel.upper()}"
    if args.confirm != expected:
        raise SystemExit(f"confirmation must exactly match {expected}")
    if not _is_root():
        raise SystemExit("clearing session context requires root")
    channels = sorted(CHANNELS) if args.channel == "all" else [args.channel]
    result = {channel: clear_channel(channel) for channel in channels}
    print(json.dumps({"cleared": result}, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
