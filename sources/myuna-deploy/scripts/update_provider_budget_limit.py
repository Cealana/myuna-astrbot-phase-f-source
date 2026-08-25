#!/usr/bin/env python3
from __future__ import annotations

from argparse import ArgumentParser
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import fcntl
import json
import os
from pathlib import Path
import shutil


def parse_limit(raw: str) -> Decimal:
    try:
        value = Decimal(raw)
    except InvalidOperation as exc:
        raise ValueError("new limit must be a decimal") from exc
    if not value.is_finite() or not Decimal("0.01") <= value <= Decimal("100"):
        raise ValueError("new limit must be between 0.01 and 100")
    return value


def migrate(path: Path, new_limit: Decimal) -> dict[str, str]:
    lock_path = path.with_suffix(path.suffix + ".lock")
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        state = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(state, dict) or state.get("schema_version") != 1:
            raise ValueError("unsupported budget ledger")
        if state.get("reservations") != {}:
            raise ValueError("budget limit cannot change while reservations exist")
        old_limit = Decimal(str(state["daily_limit_usd"]))
        spent = Decimal(str(state["spent_usd"]))
        if not old_limit.is_finite() or not spent.is_finite() or spent < 0:
            raise ValueError("budget ledger contains invalid decimal values")
        if new_limit < spent:
            raise ValueError("new limit cannot be lower than already-accounted spend")

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = path.with_name(f"{path.name}.pre-limit-{timestamp}")
        if backup.exists():
            raise ValueError("budget migration backup already exists")
        shutil.copyfile(path, backup)
        backup.chmod(0o600)

        state["daily_limit_usd"] = str(new_limit)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        payload = json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        output = os.open(temporary, flags, 0o600)
        try:
            with os.fdopen(output, "w", encoding="utf-8") as handle:
                handle.write(payload + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            path.chmod(0o600)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        return {
            "status": "updated",
            "old_limit_usd": str(old_limit),
            "new_limit_usd": str(new_limit),
            "spent_usd_preserved": str(spent),
            "backup": str(backup),
        }
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def main() -> int:
    parser = ArgumentParser(description="Atomically change a quiescent provider budget ledger")
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--new-limit", required=True)
    args = parser.parse_args()
    try:
        result = migrate(args.ledger, parse_limit(args.new_limit))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
