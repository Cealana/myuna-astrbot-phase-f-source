#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys


LEGACY_LINE = "MYUNA_DEV_TOKEN_CREDENTIAL=qq_owner_core_token"
SCOPED_LINE = (
    "MYUNA_HTTP_CLIENT_CREDENTIALS="
    "qq-owner-private:astrbot_qq:qq_owner_core_token,"
    "telegram-owner-private:astrbot_telegram:telegram_owner_core_token"
)


class CoreHttpClientEnvRejected(ValueError):
    """Raised when the source environment cannot be migrated exactly."""


def render_scoped_http_clients(source: str) -> str:
    lines = source.splitlines(keepends=True)
    legacy_indexes = [
        index
        for index, line in enumerate(lines)
        if line.rstrip("\r\n") == LEGACY_LINE
    ]
    if len(legacy_indexes) != 1:
        raise CoreHttpClientEnvRejected(
            "legacy Core credential declaration must occur exactly once"
        )
    if any(
        line.rstrip("\r\n").startswith("MYUNA_HTTP_CLIENT_CREDENTIALS=")
        for line in lines
    ):
        raise CoreHttpClientEnvRejected(
            "scoped Core credential declaration already exists"
        )

    index = legacy_indexes[0]
    ending = lines[index][len(lines[index].rstrip("\r\n")) :]
    lines[index] = SCOPED_LINE + ending
    rendered = "".join(lines)
    if rendered.count(SCOPED_LINE) != 1 or LEGACY_LINE in rendered:
        raise CoreHttpClientEnvRejected("Core credential migration was ambiguous")
    return rendered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render a work-only channel-scoped Core environment candidate."
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args(argv)
    try:
        source = arguments.source.read_text(encoding="utf-8")
        rendered = render_scoped_http_clients(source)
        if arguments.destination.exists():
            raise CoreHttpClientEnvRejected("destination already exists")
        arguments.destination.write_text(rendered, encoding="utf-8", newline="")
    except (CoreHttpClientEnvRejected, OSError, UnicodeError):
        print("Core HTTP client environment render rejected", file=sys.stderr)
        return 1
    print("Core HTTP client environment candidate rendered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
