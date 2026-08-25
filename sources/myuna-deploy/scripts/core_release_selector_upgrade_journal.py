"""Durable hash-chain journal contract for selected Core upgrades.

R2B operates only on a caller-provided directory. It has no systemd, network,
database, secret, channel, or live release backend.
"""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import stat
from typing import Mapping


ZERO_HASH = "0" * 64


class DurableJournalError(RuntimeError):
    pass


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def require(condition: bool, code: str) -> None:
    if not condition:
        raise DurableJournalError(code)


def _atomic_write_new(path: Path, payload: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            require(written > 0, "journal_write_failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class HashChainJournal:
    """Append-only JSONL journal plus an exclusive canonical receipt."""

    def __init__(self, root: Path, transaction_id: str, *, create: bool) -> None:
        require(root.is_absolute(), "journal_root_must_be_absolute")
        require(
            len(transaction_id) == 64
            and all(character in "0123456789abcdef" for character in transaction_id),
            "transaction_id_rejected",
        )
        self.root = root
        self.transaction_id = transaction_id
        self.transaction_root = root / transaction_id
        self.journal_path = self.transaction_root / "journal.jsonl"
        self.receipt_path = self.transaction_root / "SUCCESS_RECEIPT.json"
        if create:
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            require(
                stat.S_IMODE(root.stat().st_mode) == 0o700,
                "journal_root_mode_rejected",
            )
            self.transaction_root.mkdir(mode=0o700)
            _atomic_write_new(self.journal_path, b"", 0o600)
        self._verify_metadata()
        self._records = self._read_and_verify_records()

    def _verify_metadata(self) -> None:
        for path, expected in ((self.root, 0o700), (self.transaction_root, 0o700)):
            require(
                path.exists() and path.is_dir() and not path.is_symlink(),
                "journal_directory_rejected",
            )
            require(
                stat.S_IMODE(path.stat().st_mode) == expected,
                "journal_directory_mode_rejected",
            )
        require(
            self.journal_path.is_file() and not self.journal_path.is_symlink(),
            "journal_file_rejected",
        )
        require(
            stat.S_IMODE(self.journal_path.stat().st_mode) == 0o600,
            "journal_file_mode_rejected",
        )
        if self.receipt_path.exists():
            require(
                self.receipt_path.is_file() and not self.receipt_path.is_symlink(),
                "receipt_file_rejected",
            )
            require(
                stat.S_IMODE(self.receipt_path.stat().st_mode) == 0o400,
                "receipt_file_mode_rejected",
            )

    def _read_and_verify_records(self) -> list[dict[str, object]]:
        records: list[dict[str, object]] = []
        previous = ZERO_HASH
        for index, line in enumerate(self.journal_path.read_bytes().splitlines(), start=1):
            require(line, "empty_journal_record")
            try:
                record = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise DurableJournalError("journal_json_rejected") from None
            require(isinstance(record, dict), "journal_record_rejected")
            require(
                set(record)
                == {
                    "sequence",
                    "previous_hash",
                    "payload",
                    "payload_hash",
                    "record_hash",
                },
                "journal_record_shape_rejected",
            )
            payload = record["payload"]
            require(isinstance(payload, dict), "journal_payload_rejected")
            require(record["sequence"] == index, "journal_sequence_rejected")
            require(record["previous_hash"] == previous, "journal_previous_hash_rejected")
            payload_hash = sha256(canonical_bytes(payload)).hexdigest()
            require(record["payload_hash"] == payload_hash, "journal_payload_hash_rejected")
            unsigned = {
                "sequence": index,
                "previous_hash": previous,
                "payload": payload,
                "payload_hash": payload_hash,
            }
            record_hash = sha256(canonical_bytes(unsigned)).hexdigest()
            require(record["record_hash"] == record_hash, "journal_record_hash_rejected")
            previous = record_hash
            records.append(record)
        return records

    @property
    def records(self) -> list[dict[str, object]]:
        return [dict(record["payload"]) for record in self._records]

    @property
    def head_hash(self) -> str:
        return str(self._records[-1]["record_hash"]) if self._records else ZERO_HASH

    def append(
        self,
        phase: str,
        event: str,
        data: Mapping[str, object] | None = None,
    ) -> None:
        require(isinstance(phase, str) and phase, "journal_phase_rejected")
        require(isinstance(event, str) and event, "journal_event_rejected")
        payload = {"phase": phase, "event": event, "data": dict(data or {})}
        sequence = len(self._records) + 1
        payload_hash = sha256(canonical_bytes(payload)).hexdigest()
        unsigned = {
            "sequence": sequence,
            "previous_hash": self.head_hash,
            "payload": payload,
            "payload_hash": payload_hash,
        }
        record = {
            **unsigned,
            "record_hash": sha256(canonical_bytes(unsigned)).hexdigest(),
        }
        descriptor = os.open(self.journal_path, os.O_WRONLY | os.O_APPEND)
        try:
            view = memoryview(canonical_bytes(record))
            while view:
                written = os.write(descriptor, view)
                require(written > 0, "journal_append_failed")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._records.append(record)

    def write_receipt(self, document: Mapping[str, object]) -> None:
        require(not self.receipt_path.exists(), "receipt_already_exists")
        receipt = dict(document)
        receipt["journal_head_before_receipt"] = self.head_hash
        receipt["journal_record_count_before_receipt"] = len(self._records)
        _atomic_write_new(self.receipt_path, canonical_bytes(receipt), 0o400)

    def verify_receipt(self) -> dict[str, object] | None:
        if not self.receipt_path.exists():
            return None
        self._verify_metadata()
        try:
            payload = json.loads(self.receipt_path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise DurableJournalError("receipt_json_rejected") from None
        require(isinstance(payload, dict), "receipt_payload_rejected")
        head = payload.get("journal_head_before_receipt")
        count = payload.get("journal_record_count_before_receipt")
        require(
            isinstance(count, int) and 0 <= count <= len(self._records),
            "receipt_record_count_rejected",
        )
        expected_head = ZERO_HASH if count == 0 else self._records[count - 1]["record_hash"]
        require(head == expected_head, "receipt_journal_head_rejected")
        return payload
