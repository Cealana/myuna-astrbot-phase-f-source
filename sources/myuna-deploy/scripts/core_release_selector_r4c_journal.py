"""Append-only, hash-chained journal for Core Selector R4C.

The journal is deliberately separate from the activation state machine and
the systemd/filesystem backend.  Every mutation intent is fsync'd before the
backend is called.  A process restart can therefore recover from the last
durable intent without guessing whether a mutation completed.
"""

from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
import fcntl
import json
import os
from pathlib import Path
import re
import time
from typing import Callable, Iterator, Mapping


JOURNAL_RECORD_SCHEMA = "myuna.core-release-selector.r4c-journal-record.v1"
ACTIVATION_RECEIPT_SCHEMA = (
    "myuna.core-release-selector.r4c-activation-receipt.v1"
)
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")


class JournalError(RuntimeError):
    """A deterministic journal integrity or lifecycle rejection."""


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise JournalError(code)


def _digest(value: str, code: str) -> str:
    _require(isinstance(value, str) and _HEX_64.fullmatch(value) is not None, code)
    return value


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class FileJournal:
    """One approval-digest-scoped journal with a non-blocking process lock."""

    def __init__(
        self,
        root: Path,
        plan_digest: str,
        transaction_tree_sha256: str,
        *,
        clock_ns: Callable[[], int] = time.time_ns,
    ) -> None:
        if not isinstance(root, Path) or not root.is_absolute():
            raise JournalError("journal_root_rejected")
        self.plan_digest = _digest(plan_digest, "journal_plan_digest_rejected")
        self.transaction_tree_sha256 = _digest(
            transaction_tree_sha256,
            "journal_transaction_digest_rejected",
        )
        self.root = root
        self.operation_root = root / self.plan_digest
        self.journal_path = self.operation_root / "journal.jsonl"
        self.lock_path = self.operation_root / "operation.lock"
        self.receipt_path = self.operation_root / "activation-receipt.json"
        self._clock_ns = clock_ns
        self._lock_descriptor: int | None = None

    def _ensure_directories(self) -> None:
        self.root.mkdir(mode=0o750, parents=True, exist_ok=True)
        self.operation_root.mkdir(mode=0o750, exist_ok=True)
        for path in (self.root, self.operation_root):
            _require(
                path.is_dir() and not path.is_symlink(),
                "journal_directory_rejected",
            )

    @contextmanager
    def acquire(self) -> Iterator["FileJournal"]:
        self._ensure_directories()
        _require(self._lock_descriptor is None, "journal_lock_reentrant")
        flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.lock_path, flags, 0o640)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise JournalError("journal_lock_busy") from exc
            self._lock_descriptor = descriptor
            yield self
        finally:
            self._lock_descriptor = None
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _require_locked(self) -> None:
        _require(self._lock_descriptor is not None, "journal_lock_required")

    def read_records(self) -> list[dict[str, object]]:
        self._require_locked()
        if not self.journal_path.exists():
            return []
        _require(
            self.journal_path.is_file() and not self.journal_path.is_symlink(),
            "journal_file_rejected",
        )
        payload = self.journal_path.read_bytes()
        _require(payload.endswith(b"\n"), "journal_truncated")
        records: list[dict[str, object]] = []
        previous = "0" * 64
        for sequence, line in enumerate(payload.splitlines(), start=1):
            _require(line != b"", "journal_blank_record")
            try:
                record = json.loads(line.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise JournalError("journal_record_json_rejected") from exc
            _require(
                isinstance(record, dict)
                and set(record)
                == {
                    "schema",
                    "sequence",
                    "recorded_at_ns",
                    "plan_digest",
                    "transaction_tree_sha256",
                    "phase",
                    "event",
                    "data",
                    "previous_record_sha256",
                    "record_sha256",
                },
                "journal_record_shape_rejected",
            )
            record_hash = record["record_sha256"]
            _digest(record_hash, "journal_record_digest_rejected")
            unsigned = dict(record)
            unsigned.pop("record_sha256")
            expected_hash = sha256(canonical_json_bytes(unsigned)).hexdigest()
            _require(
                record["schema"] == JOURNAL_RECORD_SCHEMA
                and record["sequence"] == sequence
                and type(record["recorded_at_ns"]) is int
                and record["recorded_at_ns"] > 0
                and record["plan_digest"] == self.plan_digest
                and record["transaction_tree_sha256"]
                == self.transaction_tree_sha256
                and isinstance(record["phase"], str)
                and record["phase"] != ""
                and isinstance(record["event"], str)
                and record["event"] != ""
                and isinstance(record["data"], dict)
                and record["previous_record_sha256"] == previous
                and record_hash == expected_hash,
                "journal_record_integrity_rejected",
            )
            _require(
                canonical_json_bytes(record) == line,
                "journal_record_not_canonical",
            )
            records.append(record)
            previous = record_hash
        return records

    def append(
        self,
        *,
        phase: str,
        event: str,
        data: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        self._require_locked()
        _require(
            isinstance(phase, str)
            and phase != ""
            and isinstance(event, str)
            and event != "",
            "journal_event_rejected",
        )
        records = self.read_records()
        previous = records[-1]["record_sha256"] if records else "0" * 64
        unsigned: dict[str, object] = {
            "schema": JOURNAL_RECORD_SCHEMA,
            "sequence": len(records) + 1,
            "recorded_at_ns": int(self._clock_ns()),
            "plan_digest": self.plan_digest,
            "transaction_tree_sha256": self.transaction_tree_sha256,
            "phase": phase,
            "event": event,
            "data": dict(data or {}),
            "previous_record_sha256": previous,
        }
        record = dict(unsigned)
        record["record_sha256"] = sha256(canonical_json_bytes(unsigned)).hexdigest()
        line = canonical_json_bytes(record) + b"\n"
        flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.journal_path, flags, 0o640)
        try:
            view = memoryview(line)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise JournalError("journal_append_failed")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_directory(self.operation_root)
        verified = self.read_records()
        _require(verified[-1] == record, "journal_append_verification_failed")
        return record

    def write_receipt(self, document: Mapping[str, object]) -> Path:
        self._require_locked()
        payload = dict(document)
        _require(
            payload.get("schema") == ACTIVATION_RECEIPT_SCHEMA
            and payload.get("plan_digest") == self.plan_digest
            and payload.get("transaction_tree_sha256")
            == self.transaction_tree_sha256,
            "activation_receipt_rejected",
        )
        rendered = canonical_json_bytes(payload)
        if self.receipt_path.exists():
            _require(
                self.receipt_path.is_file()
                and not self.receipt_path.is_symlink()
                and self.receipt_path.read_bytes() == rendered,
                "activation_receipt_conflict",
            )
            return self.receipt_path
        temporary = self.operation_root / (
            f".activation-receipt.{os.getpid()}.{self._clock_ns()}.tmp"
        )
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o640)
        try:
            view = memoryview(rendered)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise JournalError("activation_receipt_write_failed")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, self.receipt_path)
        _fsync_directory(self.operation_root)
        _require(
            self.receipt_path.read_bytes() == rendered,
            "activation_receipt_verification_failed",
        )
        return self.receipt_path

    def read_receipt(self) -> dict[str, object] | None:
        self._require_locked()
        if not self.receipt_path.exists():
            return None
        _require(
            self.receipt_path.is_file() and not self.receipt_path.is_symlink(),
            "activation_receipt_file_rejected",
        )
        raw = self.receipt_path.read_bytes()
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise JournalError("activation_receipt_json_rejected") from exc
        _require(
            isinstance(document, dict)
            and document.get("schema") == ACTIVATION_RECEIPT_SCHEMA
            and document.get("plan_digest") == self.plan_digest
            and document.get("transaction_tree_sha256")
            == self.transaction_tree_sha256
            and canonical_json_bytes(document) == raw,
            "activation_receipt_integrity_rejected",
        )
        return document
