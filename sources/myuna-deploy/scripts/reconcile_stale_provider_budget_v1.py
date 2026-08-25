#!/usr/bin/env python3
"""Archive a stale provider budget ledger and open the current UTC day."""

from __future__ import annotations

import argparse
import collections
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import tempfile
from typing import Mapping


LEDGER = Path("/var/lib/myuna/qq/provider-budget/deepseek.json")
ARCHIVE_ROOT = LEDGER.parent / "archive"
RECEIPT_ROOT = LEDGER.parent / "rollover-receipts"
SERVICE_USER = "myuna"
SCHEMA = "myuna.provider-budget-rollover.v1"


class ReconciliationRejected(RuntimeError):
    """A stale-ledger reconciliation invariant was rejected."""


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _identity() -> tuple[int, int]:
    try:
        record = pwd.getpwnam(SERVICE_USER)
    except KeyError as exc:
        raise ReconciliationRejected("service identity rejected") from exc
    return record.pw_uid, record.pw_gid


def _metadata(path: Path) -> tuple[int, int, int]:
    if path.is_symlink() or not path.is_file():
        raise ReconciliationRejected("protected file rejected")
    metadata = path.stat()
    return (
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
    )


def validate_ledger(
    payload: object,
    *,
    today: str,
) -> tuple[str, str, collections.Counter[str]]:
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ReconciliationRejected("ledger schema rejected")
    recorded = payload.get("date_utc")
    limit = payload.get("daily_limit_usd")
    spent = payload.get("spent_usd")
    reservations = payload.get("reservations")
    if (
        not isinstance(recorded, str)
        or not isinstance(limit, str)
        or not isinstance(spent, str)
        or not isinstance(reservations, dict)
    ):
        raise ReconciliationRejected("ledger payload rejected")
    try:
        recorded_date = datetime.strptime(recorded, "%Y-%m-%d").date()
        today_date = datetime.strptime(today, "%Y-%m-%d").date()
        limit_value = Decimal(limit)
        spent_value = Decimal(spent)
    except (ValueError, InvalidOperation) as exc:
        raise ReconciliationRejected("ledger values rejected") from exc
    if (
        recorded_date > today_date
        or not limit_value.is_finite()
        or limit_value <= 0
        or not spent_value.is_finite()
        or spent_value < 0
    ):
        raise ReconciliationRejected("ledger values rejected")
    counts: collections.Counter[str] = collections.Counter()
    for reservation_id, item in reservations.items():
        if (
            not isinstance(reservation_id, str)
            or not isinstance(item, dict)
            or item.get("state") not in {"active", "uncertain"}
            or not isinstance(item.get("reserved_usd"), str)
        ):
            raise ReconciliationRejected("ledger reservation rejected")
        try:
            amount = Decimal(item["reserved_usd"])
        except InvalidOperation as exc:
            raise ReconciliationRejected(
                "ledger reservation rejected"
            ) from exc
        if not amount.is_finite() or amount <= 0:
            raise ReconciliationRejected("ledger reservation rejected")
        counts[str(item["state"])] += 1
    return recorded, limit, counts


def render_current_ledger(*, today: str, daily_limit_usd: str) -> bytes:
    payload = {
        "schema_version": 1,
        "date_utc": today,
        "daily_limit_usd": daily_limit_usd,
        "spent_usd": "0",
        "reservations": {},
    }
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _atomic_write(
    path: Path,
    payload: bytes,
    *,
    uid: int,
    gid: int,
    mode: int,
) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def _private_directory(path: Path, *, uid: int, gid: int) -> None:
    path.mkdir(parents=True, exist_ok=True)
    metadata = path.stat()
    if path.is_symlink() or not path.is_dir():
        raise ReconciliationRejected("private directory rejected")
    if metadata.st_uid != uid or metadata.st_gid != gid:
        os.chown(path, uid, gid)
    os.chmod(path, 0o700)


def _read() -> tuple[bytes, dict[str, object], int, int]:
    uid, gid = _identity()
    if _metadata(LEDGER) != (uid, gid, 0o600):
        raise ReconciliationRejected("ledger metadata rejected")
    raw = LEDGER.read_bytes()
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReconciliationRejected("ledger JSON rejected") from exc
    if not isinstance(payload, dict):
        raise ReconciliationRejected("ledger JSON rejected")
    return raw, payload, uid, gid


def _lock(uid: int, gid: int) -> int:
    lock_path = LEDGER.with_suffix(LEDGER.suffix + ".lock")
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    os.fchmod(descriptor, 0o600)
    os.fchown(descriptor, uid, gid)
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    return descriptor


def inspect() -> dict[str, object]:
    _, payload, _, _ = _read()
    today = datetime.now(timezone.utc).date().isoformat()
    recorded, _, counts = validate_ledger(payload, today=today)
    return {
        "status": "STALE" if recorded != today else "CURRENT",
        "recorded_date_matches_today": recorded == today,
        "reservation_active": counts["active"],
        "reservation_uncertain": counts["uncertain"],
    }


def reconcile() -> dict[str, object]:
    uid, gid = _identity()
    if os.geteuid() not in {0, uid}:
        raise ReconciliationRejected("service identity required")
    descriptor = _lock(uid, gid)
    try:
        original, payload, _, _ = _read()
        now = datetime.now(timezone.utc)
        today = now.date().isoformat()
        recorded, limit, counts = validate_ledger(payload, today=today)
        if recorded == today:
            return {
                "status": "ALREADY_CURRENT",
                "recorded_date_matches_today": True,
                "reservation_active": counts["active"],
                "reservation_uncertain": counts["uncertain"],
            }
        digest = _digest(original)
        _private_directory(ARCHIVE_ROOT, uid=uid, gid=gid)
        _private_directory(RECEIPT_ROOT, uid=uid, gid=gid)
        archive = ARCHIVE_ROOT / f"deepseek-{recorded}-{digest}.json"
        if archive.exists():
            if (
                _metadata(archive) != (uid, gid, 0o600)
                or archive.read_bytes() != original
            ):
                raise ReconciliationRejected("archive drifted")
        else:
            _atomic_write(
                archive,
                original,
                uid=uid,
                gid=gid,
                mode=0o600,
            )
        current = render_current_ledger(
            today=today,
            daily_limit_usd=limit,
        )
        replaced = False
        try:
            _atomic_write(
                LEDGER,
                current,
                uid=uid,
                gid=gid,
                mode=0o600,
            )
            replaced = True
            receipt = {
                "schema": SCHEMA,
                "status": "RECONCILED",
                "previous_date": recorded,
                "current_date": today,
                "archive_file": archive.name,
                "archive_sha256": digest,
                "reservation_active": counts["active"],
                "reservation_uncertain": counts["uncertain"],
                "raw_ids_recorded": False,
                "amounts_recorded": False,
                "recorded_at": now.isoformat(),
            }
            receipt_path = RECEIPT_ROOT / (
                f"rollover-{now.strftime('%Y%m%dT%H%M%SZ')}-"
                f"{digest[:12]}.json"
            )
            _atomic_write(
                receipt_path,
                (
                    json.dumps(
                        receipt,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8"),
                uid=uid,
                gid=gid,
                mode=0o600,
            )
        except BaseException:
            if replaced:
                _atomic_write(
                    LEDGER,
                    original,
                    uid=uid,
                    gid=gid,
                    mode=0o600,
                )
            raise
        return {
            "status": "RECONCILED",
            "recorded_date_matches_today": True,
            "reservation_active_archived": counts["active"],
            "reservation_uncertain_archived": counts["uncertain"],
            "archive_sha256": digest,
            "rollback_bytes_preserved": True,
        }
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("inspect", "reconcile"))
    arguments = parser.parse_args()
    try:
        result = inspect() if arguments.action == "inspect" else reconcile()
    except (
        ReconciliationRejected,
        OSError,
        ValueError,
        json.JSONDecodeError,
    ):
        print(json.dumps({"status": "rejected"}, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
