#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys

from telegram_owner_binding import (
    DiscoveryEvidence,
    TelegramBindingRejected,
    public_pending_preview,
)
from telegram_owner_discovery import EVIDENCE_PATH


def load_discovery_evidence(path: Path) -> DiscoveryEvidence:
    if path.is_symlink() or not path.is_file():
        raise TelegramBindingRejected("Telegram binding evidence rejected")
    metadata = path.stat()
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise TelegramBindingRejected("Telegram binding evidence rejected")
    raw = path.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise TelegramBindingRejected("Telegram binding evidence rejected") from None
    return DiscoveryEvidence.from_payload(
        payload,
        evidence_sha256=sha256(raw).hexdigest(),
        now=datetime.now(timezone.utc),
    )


def main() -> int:
    if os.geteuid() != 0:
        raise TelegramBindingRejected("local root authority is required")
    evidence = load_discovery_evidence(EVIDENCE_PATH)
    print(
        json.dumps(
            public_pending_preview(evidence),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, TelegramBindingRejected):
        print("Telegram Owner binding preview rejected", file=sys.stderr)
        raise SystemExit(1) from None
