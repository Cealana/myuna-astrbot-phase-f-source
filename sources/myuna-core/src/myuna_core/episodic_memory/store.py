from __future__ import annotations

import ctypes
import errno
import json
import os
from pathlib import Path
import sqlite3
import stat
import threading

from .contracts import (
    ARCHIVE_SCHEMA,
    ZERO_DIGEST,
    ArchivedContent,
    CompleteTurn,
    CompleteTurnDraft,
    EpisodicMemoryError,
    LifecycleRecord,
    TurnTimeBinding,
    TurnTimeCorrection,
    canonical_bytes,
    require_digest,
    semantic_digest,
)
from .delivery import (
    DELIVERY_JOURNAL_SCHEMA,
    DeliveryPreparation,
    DeliveryPreparationResolution,
    DeliveryResolution,
    FactualDeliveryEpisodeV1,
)
from .owner_day import OwnerDayPolicy
from .trusted_time import finalize_delivery_time_binding


SCHEMA_VERSION = 2
SQLITE_APPLICATION_ID = 0x4D594541
MAX_BUSY_TIMEOUT_SECONDS = 5.0
JOURNAL_MODE = "persist"
SYNCHRONOUS_LEVEL = 2

_CONNECTION_DESCRIPTOR_LOCK = threading.RLock()

_SCHEMA = """
CREATE TABLE metadata (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
) STRICT;
CREATE TABLE complete_turns (
    sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
    turn_id TEXT NOT NULL UNIQUE,
    owner_kind TEXT NOT NULL,
    owner_text TEXT NOT NULL,
    owner_media_identity_digest TEXT,
    assistant_kind TEXT NOT NULL,
    assistant_text TEXT NOT NULL,
    assistant_media_identity_digest TEXT,
    time_binding_json TEXT NOT NULL,
    time_binding_digest TEXT NOT NULL,
    epoch_id TEXT NOT NULL,
    release_set_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    response_digest TEXT NOT NULL,
    delivery_ack_digest TEXT NOT NULL,
    previous_turn_digest TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    turn_digest TEXT NOT NULL UNIQUE
) STRICT;
CREATE TABLE lifecycle_records (
    lifecycle_id TEXT PRIMARY KEY NOT NULL,
    event_kind TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    occurred_at_utc TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    delivery_acknowledged INTEGER NOT NULL CHECK (delivery_acknowledged = 0),
    complete_turn_written INTEGER NOT NULL CHECK (complete_turn_written = 0)
) STRICT;
CREATE TABLE append_receipts (
    turn_id TEXT PRIMARY KEY NOT NULL,
    request_digest TEXT NOT NULL,
    turn_digest TEXT NOT NULL,
    sequence INTEGER NOT NULL
) STRICT;
CREATE TABLE time_corrections (
    correction_id TEXT PRIMARY KEY NOT NULL,
    turn_id TEXT NOT NULL,
    turn_digest TEXT NOT NULL,
    original_binding_digest TEXT NOT NULL,
    correction_digest TEXT NOT NULL UNIQUE,
    payload_json TEXT NOT NULL
) STRICT;
CREATE TABLE delivery_preparations (
    delivery_token TEXT PRIMARY KEY NOT NULL,
    turn_id TEXT NOT NULL UNIQUE,
    preparation_digest TEXT NOT NULL UNIQUE,
    payload_json TEXT NOT NULL
) STRICT;
CREATE TABLE delivery_events (
    delivery_token TEXT NOT NULL,
    event_kind TEXT NOT NULL CHECK(event_kind IN ('delivered', 'cancelled')),
    event_digest TEXT NOT NULL UNIQUE,
    payload_json TEXT NOT NULL,
    PRIMARY KEY(delivery_token, event_kind),
    FOREIGN KEY(delivery_token) REFERENCES delivery_preparations(delivery_token)
) STRICT;
CREATE TRIGGER complete_turns_no_update BEFORE UPDATE ON complete_turns
BEGIN SELECT RAISE(ABORT, 'complete_turn_immutable'); END;
CREATE TRIGGER complete_turns_no_delete BEFORE DELETE ON complete_turns
BEGIN SELECT RAISE(ABORT, 'complete_turn_immutable'); END;
CREATE TRIGGER lifecycle_no_update BEFORE UPDATE ON lifecycle_records
BEGIN SELECT RAISE(ABORT, 'lifecycle_immutable'); END;
CREATE TRIGGER lifecycle_no_delete BEFORE DELETE ON lifecycle_records
BEGIN SELECT RAISE(ABORT, 'lifecycle_immutable'); END;
CREATE TRIGGER receipts_no_update BEFORE UPDATE ON append_receipts
BEGIN SELECT RAISE(ABORT, 'receipt_immutable'); END;
CREATE TRIGGER receipts_no_delete BEFORE DELETE ON append_receipts
BEGIN SELECT RAISE(ABORT, 'receipt_immutable'); END;
CREATE TRIGGER corrections_no_update BEFORE UPDATE ON time_corrections
BEGIN SELECT RAISE(ABORT, 'time_correction_immutable'); END;
CREATE TRIGGER corrections_no_delete BEFORE DELETE ON time_corrections
BEGIN SELECT RAISE(ABORT, 'time_correction_immutable'); END;
CREATE TRIGGER delivery_preparations_no_update BEFORE UPDATE ON delivery_preparations
BEGIN SELECT RAISE(ABORT, 'delivery_preparation_immutable'); END;
CREATE TRIGGER delivery_preparations_no_delete BEFORE DELETE ON delivery_preparations
BEGIN SELECT RAISE(ABORT, 'delivery_preparation_immutable'); END;
CREATE TRIGGER delivery_events_no_update BEFORE UPDATE ON delivery_events
BEGIN SELECT RAISE(ABORT, 'delivery_event_immutable'); END;
CREATE TRIGGER delivery_events_no_delete BEFORE DELETE ON delivery_events
BEGIN SELECT RAISE(ABORT, 'delivery_event_immutable'); END;
"""


def _regular_identity(path: Path) -> tuple[int, int, int, int, int]:
    try:
        status = path.lstat()
    except OSError as exc:
        raise EpisodicMemoryError("archive_identity_unavailable", retryable=True) from exc
    if path.is_symlink() or not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
        raise EpisodicMemoryError("archive_type_rejected")
    return (
        status.st_dev,
        status.st_ino,
        status.st_uid,
        status.st_gid,
        stat.S_IMODE(status.st_mode),
    )


def _fd_inventory() -> dict[int, tuple[int, int, int, int, int]]:
    proc = Path("/proc/self/fd")
    if not proc.is_dir():
        raise EpisodicMemoryError("archive_fd_attestation_unavailable")
    inventory: dict[int, tuple[int, int, int, int, int]] = {}
    try:
        with os.scandir(proc) as entries:
            for entry in entries:
                try:
                    descriptor = int(entry.name)
                    status = entry.stat(follow_symlinks=True)
                except (OSError, ValueError):
                    continue
                inventory[descriptor] = (
                    status.st_dev,
                    status.st_ino,
                    status.st_uid,
                    status.st_gid,
                    stat.S_IMODE(status.st_mode),
                )
    except OSError as exc:
        raise EpisodicMemoryError("archive_fd_attestation_unavailable") from exc
    return inventory


def _descriptor_identity(descriptor: int) -> tuple[int, int, int, int, int]:
    try:
        status = os.stat(f"/proc/self/fd/{descriptor}")
    except OSError as exc:
        raise EpisodicMemoryError("archive_connection_identity_unbound") from exc
    return (
        status.st_dev,
        status.st_ino,
        status.st_uid,
        status.st_gid,
        stat.S_IMODE(status.st_mode),
    )


def _delivery_boot_identity(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise EpisodicMemoryError("delivery_boot_identity_invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise EpisodicMemoryError("delivery_boot_identity_invalid") from exc
    if not encoded or len(encoded) > 128:
        raise EpisodicMemoryError("delivery_boot_identity_invalid")
    return value


def _new_connection_descriptor(
    before: dict[int, tuple[int, int, int, int, int]],
    after: dict[int, tuple[int, int, int, int, int]],
    identity: tuple[int, int, int, int, int],
) -> int:
    candidates = tuple(
        descriptor
        for descriptor, observed in after.items()
        if observed[:2] == identity[:2] and before.get(descriptor) != observed
    )
    if len(candidates) != 1:
        raise EpisodicMemoryError("archive_connection_identity_ambiguous")
    return candidates[0]


def _same_open_file_description(left: int, right: int) -> bool:
    if os.uname().machine != "x86_64":
        raise EpisodicMemoryError("archive_connection_close_oracle_unavailable")
    libc = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    result = libc.syscall(312, os.getpid(), os.getpid(), 0, left, right)
    if result == 0:
        return True
    if result > 0:
        return False
    if ctypes.get_errno() == errno.EBADF:
        return False
    raise EpisodicMemoryError("archive_connection_close_oracle_unavailable")


def _open_file_description_members(proof_descriptor: int) -> tuple[int, ...]:
    try:
        descriptor_names = os.listdir("/proc/self/fd")
    except OSError as exc:
        raise EpisodicMemoryError("archive_connection_close_oracle_unavailable") from exc
    members: list[int] = []
    for name in descriptor_names:
        try:
            candidate = int(name)
        except ValueError:
            continue
        if candidate == proof_descriptor:
            continue
        if _same_open_file_description(candidate, proof_descriptor):
            members.append(candidate)
    return tuple(sorted(members))


def _close_connection(
    connection: sqlite3.Connection,
    descriptor: int,
    proof_descriptor: int | None = None,
) -> None:
    close_error: BaseException | None = None
    owned_proof = proof_descriptor
    if owned_proof is None:
        _CONNECTION_DESCRIPTOR_LOCK.acquire()
    try:
        if owned_proof is None:
            owned_proof = os.dup(descriptor)
        if _open_file_description_members(owned_proof) != (descriptor,):
            raise EpisodicMemoryError("archive_connection_identity_unbound")
        try:
            connection.close()
        except BaseException as exc:
            close_error = exc
        if close_error is None and not _open_file_description_members(owned_proof):
            return
    except (OSError, EpisodicMemoryError) as exc:
        close_error = close_error or exc
    finally:
        if owned_proof is not None:
            os.close(owned_proof)
        _CONNECTION_DESCRIPTOR_LOCK.release()
    raise EpisodicMemoryError("archive_connection_close_unconfirmed") from close_error


def _connection(
    path: Path,
    timeout: float,
    *,
    create: bool = False,
) -> tuple[sqlite3.Connection, tuple[int, int, int, int, int], int, int]:
    if not create:
        _regular_identity(path)
    _CONNECTION_DESCRIPTOR_LOCK.acquire()
    connection: sqlite3.Connection | None = None
    proof_descriptor: int | None = None
    try:
        before = _fd_inventory()
        connection = sqlite3.connect(path, timeout=timeout, isolation_level=None)
        after = _fd_inventory()
        identity = _regular_identity(path)
        descriptor = _new_connection_descriptor(before, after, identity)
        proof_descriptor = os.dup(descriptor)
        if _open_file_description_members(proof_descriptor) != (descriptor,):
            raise EpisodicMemoryError("archive_connection_identity_unbound")
    except BaseException:
        if connection is not None:
            connection.close()
        if proof_descriptor is not None:
            os.close(proof_descriptor)
        _CONNECTION_DESCRIPTOR_LOCK.release()
        raise
    assert connection is not None
    assert proof_descriptor is not None
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute(f"PRAGMA busy_timeout = {int(timeout * 1_000)}")
        mode = str(
            connection.execute("PRAGMA journal_mode = PERSIST").fetchone()[0]
        ).lower()
        connection.execute("PRAGMA synchronous = FULL")
        synchronous = int(connection.execute("PRAGMA synchronous").fetchone()[0])
        database_rows = connection.execute("PRAGMA database_list").fetchall()
        if (
            mode != JOURNAL_MODE
            or synchronous != SYNCHRONOUS_LEVEL
            or len(database_rows) != 1
            or database_rows[0][1] != "main"
            or Path(str(database_rows[0][2])).resolve() != path.resolve()
        ):
            raise EpisodicMemoryError("archive_connection_contract_rejected")
        identity = _regular_identity(path)
        if _descriptor_identity(descriptor) != identity:
            raise EpisodicMemoryError("archive_connection_identity_unbound")
    except BaseException:
        _close_connection(connection, descriptor, proof_descriptor)
        raise
    return connection, identity, descriptor, proof_descriptor


class LosslessArchiveStore:
    """Append-only Owner-private raw authority; no migration or deletion API."""

    def __init__(
        self,
        path: Path,
        *,
        timeout: float = 1.0,
        expected_uid: int | None = None,
        expected_gid: int | None = None,
    ) -> None:
        if not path.is_absolute():
            raise EpisodicMemoryError("archive_path_invalid")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
            raise EpisodicMemoryError("archive_timeout_invalid")
        if not 0 <= float(timeout) <= MAX_BUSY_TIMEOUT_SECONDS:
            raise EpisodicMemoryError("archive_timeout_invalid")
        self.path = path
        self.timeout = float(timeout)
        self.expected_uid = os.geteuid() if expected_uid is None else expected_uid
        self.expected_gid = os.getegid() if expected_gid is None else expected_gid

    def _verify_parent(self) -> None:
        try:
            status = self.path.parent.lstat()
        except OSError as exc:
            raise EpisodicMemoryError("archive_root_absent") from exc
        if (
            self.path.parent.is_symlink()
            or not stat.S_ISDIR(status.st_mode)
            or status.st_uid != self.expected_uid
            or status.st_gid != self.expected_gid
            or stat.S_IMODE(status.st_mode) != 0o700
        ):
            raise EpisodicMemoryError("archive_root_identity_rejected")
        current = Path(self.path.anchor)
        for component in self.path.parent.parts[1:]:
            current /= component
            component_status = current.lstat()
            if current.is_symlink() or not stat.S_ISDIR(component_status.st_mode):
                raise EpisodicMemoryError("archive_root_ancestry_rejected")

    def _verify_identity(self, identity: tuple[int, int, int, int, int]) -> None:
        if identity[2:] != (self.expected_uid, self.expected_gid, 0o600):
            raise EpisodicMemoryError("archive_file_identity_rejected")

    def _verify_terminal(
        self,
        connection: sqlite3.Connection,
        identity: tuple[int, int, int, int, int],
        descriptor: int,
    ) -> None:
        current = _regular_identity(self.path)
        self._verify_identity(current)
        if current != identity or _descriptor_identity(descriptor) != identity:
            raise EpisodicMemoryError("archive_connection_identity_drifted")
        if (
            str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
            != JOURNAL_MODE
            or int(connection.execute("PRAGMA synchronous").fetchone()[0])
            != SYNCHRONOUS_LEVEL
            or connection.execute("PRAGMA quick_check").fetchone()[0] != "ok"
        ):
            raise EpisodicMemoryError("archive_terminal_verification_rejected")

    def _normalize_sidecar(self) -> None:
        sidecar = self.path.with_name(self.path.name + "-journal")
        if not sidecar.exists() and not sidecar.is_symlink():
            return
        if sidecar.is_symlink():
            raise EpisodicMemoryError("archive_journal_type_rejected")
        identity = _regular_identity(sidecar)
        if identity[2:4] != (self.expected_uid, self.expected_gid):
            raise EpisodicMemoryError("archive_journal_identity_rejected")
        if identity[4] != 0o600:
            os.chmod(sidecar, 0o600)
            identity = _regular_identity(sidecar)
        if identity[2:] != (self.expected_uid, self.expected_gid, 0o600):
            raise EpisodicMemoryError("archive_journal_identity_rejected")

    def _open(
        self, *, create: bool = False
    ) -> tuple[sqlite3.Connection, tuple[int, int, int, int, int], int, int]:
        preopen_identity = None
        if not create:
            preopen_identity = _regular_identity(self.path)
            self._verify_identity(preopen_identity)
            self._normalize_sidecar()
        connection, identity, descriptor, proof_descriptor = _connection(
            self.path, self.timeout, create=create
        )
        try:
            if preopen_identity is not None and identity != preopen_identity:
                raise EpisodicMemoryError("archive_connection_identity_drifted")
            if create:
                current = _regular_identity(self.path)
                if (
                    current[:4] != identity[:4]
                    or current[2:4] != (self.expected_uid, self.expected_gid)
                ):
                    raise EpisodicMemoryError("archive_file_identity_rejected")
                os.chmod(self.path, 0o600)
                identity = _regular_identity(self.path)
            self._verify_identity(identity)
            self._normalize_sidecar()
        except BaseException:
            _close_connection(connection, descriptor, proof_descriptor)
            raise
        return connection, identity, descriptor, proof_descriptor

    def _remove_uncommitted_initialization(
        self, identity: tuple[int, int, int, int, int]
    ) -> None:
        if _regular_identity(self.path) != identity:
            raise EpisodicMemoryError("archive_initialization_preserved_ambiguous")
        allowed = {self.path.name, self.path.name + "-journal"}
        observed = {
            item.name for item in self.path.parent.iterdir() if item.name in allowed
        }
        if self.path.name not in observed:
            raise EpisodicMemoryError("archive_initialization_preserved_ambiguous")
        sidecar = self.path.with_name(self.path.name + "-journal")
        if sidecar.exists() or sidecar.is_symlink():
            _regular_identity(sidecar)
            sidecar.unlink()
        self.path.unlink()
        descriptor = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if self.path.exists() or self.path.is_symlink():
            raise EpisodicMemoryError("archive_initialization_preserved_ambiguous")

    def initialize(self, *, fault_stage: str | None = None) -> None:
        if fault_stage not in {
            None,
            "before_commit",
            "after_commit_before_verification",
            "after_verification_before_return",
        }:
            raise EpisodicMemoryError("archive_fault_stage_rejected")
        self._verify_parent()
        if self.path.exists() or self.path.is_symlink():
            self._verify()
            return
        connection, identity, descriptor, proof_descriptor = self._open(create=True)
        committed = False
        failure: BaseException | None = None
        try:
            connection.executescript("BEGIN IMMEDIATE;\n" + _SCHEMA)
            connection.execute(f"PRAGMA application_id = {SQLITE_APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            connection.executemany(
                "INSERT INTO metadata(key, value) VALUES (?, ?)",
                (
                    ("archive_schema", ARCHIVE_SCHEMA),
                    ("delivery_schema", DELIVERY_JOURNAL_SCHEMA),
                    ("head_digest", ZERO_DIGEST),
                    ("turn_count", "0"),
                ),
            )
            if fault_stage == "before_commit":
                raise EpisodicMemoryError("archive_initialization_before_commit", retryable=True)
            connection.execute("COMMIT")
            committed = True
            if fault_stage == "after_commit_before_verification":
                raise EpisodicMemoryError(
                    "archive_initialization_lost_return", retryable=True
                )
            self._verify_connection(connection)
            self._verify_terminal(connection, identity, descriptor)
            if fault_stage == "after_verification_before_return":
                raise EpisodicMemoryError(
                    "archive_initialization_lost_return", retryable=True
                )
        except BaseException as exc:
            failure = exc
            if connection.in_transaction:
                connection.execute("ROLLBACK")
        finally:
            _close_connection(connection, descriptor, proof_descriptor)
        self._normalize_sidecar()
        if failure is not None:
            if not committed:
                self._remove_uncommitted_initialization(identity)
            raise failure.with_traceback(None)

    def _verify(self) -> None:
        self._verify_parent()
        connection, identity, descriptor, proof_descriptor = self._open()
        try:
            self._verify_connection(connection)
            self._verify_terminal(connection, identity, descriptor)
        except sqlite3.Error as exc:
            raise EpisodicMemoryError("archive_unavailable", retryable=True) from exc
        finally:
            _close_connection(connection, descriptor, proof_descriptor)

    def _verify_connection(self, connection: sqlite3.Connection) -> None:
        application_id = connection.execute("PRAGMA application_id").fetchone()[0]
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        triggers = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type='trigger'"
            )
        }
        if "metadata" not in tables:
            raise EpisodicMemoryError("archive_schema_rejected")
        metadata = dict(connection.execute("SELECT key, value FROM metadata"))
        if (
            application_id != SQLITE_APPLICATION_ID
            or version != SCHEMA_VERSION
            or tables
            != {
                "metadata",
                "complete_turns",
                "lifecycle_records",
                "append_receipts",
                "time_corrections",
                "delivery_preparations",
                "delivery_events",
            }
            or triggers
            != {
                "complete_turns_no_update",
                "complete_turns_no_delete",
                "lifecycle_no_update",
                "lifecycle_no_delete",
                "receipts_no_update",
                "receipts_no_delete",
                "corrections_no_update",
                "corrections_no_delete",
                "delivery_preparations_no_update",
                "delivery_preparations_no_delete",
                "delivery_events_no_update",
                "delivery_events_no_delete",
            }
            or metadata.get("archive_schema") != ARCHIVE_SCHEMA
            or metadata.get("delivery_schema") != DELIVERY_JOURNAL_SCHEMA
            or set(metadata)
            != {"archive_schema", "delivery_schema", "head_digest", "turn_count"}
        ):
            raise EpisodicMemoryError("archive_schema_rejected")
        count = connection.execute("SELECT COUNT(*) FROM complete_turns").fetchone()[0]
        if int(metadata["turn_count"]) != count:
            raise EpisodicMemoryError("archive_count_drifted")
        head = ZERO_DIGEST
        if count:
            last = connection.execute(
                "SELECT sequence, turn_digest FROM complete_turns ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if last["sequence"] != count:
                raise EpisodicMemoryError("archive_sequence_drifted")
            head = last["turn_digest"]
        if metadata["head_digest"] != head:
            raise EpisodicMemoryError("archive_head_drifted")

    @staticmethod
    def _turn_from_row(row: sqlite3.Row) -> CompleteTurn:
        draft = CompleteTurnDraft(
            turn_id=row["turn_id"],
            sequence=row["sequence"],
            owner=ArchivedContent(
                row["owner_kind"], row["owner_text"], row["owner_media_identity_digest"]
            ),
            assistant=ArchivedContent(
                row["assistant_kind"],
                row["assistant_text"],
                row["assistant_media_identity_digest"],
            ),
            time_binding=TurnTimeBinding.from_payload(json.loads(row["time_binding_json"])),
            epoch_id=row["epoch_id"],
            release_set_id=row["release_set_id"],
            request_digest=row["request_digest"],
            response_digest=row["response_digest"],
            delivery_ack_digest=row["delivery_ack_digest"],
            previous_turn_digest=row["previous_turn_digest"],
            provenance_categories=tuple(json.loads(row["provenance_json"])),
        )
        selected = CompleteTurn(draft=draft, turn_digest=row["turn_digest"])
        if CompleteTurn.create(draft) != selected:
            raise EpisodicMemoryError("archive_turn_digest_drifted")
        return selected

    def _turns_from_connection(
        self, connection: sqlite3.Connection
    ) -> tuple[CompleteTurn, ...]:
        rows = connection.execute("SELECT * FROM complete_turns ORDER BY sequence").fetchall()
        turns = tuple(self._turn_from_row(row) for row in rows)
        parent = ZERO_DIGEST
        for expected_sequence, turn in enumerate(turns, start=1):
            if (
                turn.draft.sequence != expected_sequence
                or turn.draft.previous_turn_digest != parent
            ):
                raise EpisodicMemoryError("archive_chain_drifted")
            receipt = connection.execute(
                "SELECT request_digest, turn_digest, sequence FROM append_receipts "
                "WHERE turn_id=?",
                (turn.draft.turn_id,),
            ).fetchone()
            if receipt is None or tuple(receipt) != (
                turn.draft.request_digest,
                turn.turn_digest,
                turn.draft.sequence,
            ):
                raise EpisodicMemoryError("archive_receipt_drifted")
            parent = turn.turn_digest
        return turns

    def _corrections_from_connection(
        self, connection: sqlite3.Connection
    ) -> tuple[TurnTimeCorrection, ...]:
        rows = connection.execute(
            "SELECT correction_digest, payload_json FROM time_corrections ORDER BY rowid"
        ).fetchall()
        corrections = tuple(
            TurnTimeCorrection.from_payload(json.loads(row["payload_json"]))
            for row in rows
        )
        if any(
            row["correction_digest"] != correction.correction_digest
            for row, correction in zip(rows, corrections, strict=True)
        ):
            raise EpisodicMemoryError("time_correction_digest_drifted")
        return corrections

    @staticmethod
    def _write_complete_turn(
        connection: sqlite3.Connection, complete: CompleteTurn
    ) -> None:
        draft = complete.draft
        connection.execute(
            """INSERT INTO complete_turns(
                sequence, turn_id, owner_kind, owner_text,
                owner_media_identity_digest, assistant_kind, assistant_text,
                assistant_media_identity_digest, time_binding_json,
                time_binding_digest, epoch_id, release_set_id, request_digest,
                response_digest, delivery_ack_digest, previous_turn_digest,
                provenance_json, turn_digest
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                draft.sequence,
                draft.turn_id,
                draft.owner.kind,
                draft.owner.text,
                draft.owner.media_identity_digest,
                draft.assistant.kind,
                draft.assistant.text,
                draft.assistant.media_identity_digest,
                json.dumps(
                    draft.time_binding.payload(),
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                draft.time_binding.binding_digest,
                draft.epoch_id,
                draft.release_set_id,
                draft.request_digest,
                draft.response_digest,
                draft.delivery_ack_digest,
                draft.previous_turn_digest,
                json.dumps(draft.provenance_categories, separators=(",", ":")),
                complete.turn_digest,
            ),
        )
        connection.execute(
            "INSERT INTO append_receipts VALUES (?, ?, ?, ?)",
            (draft.turn_id, draft.request_digest, complete.turn_digest, draft.sequence),
        )
        connection.execute(
            "UPDATE metadata SET value=? WHERE key='head_digest'",
            (complete.turn_digest,),
        )
        connection.execute(
            "UPDATE metadata SET value=? WHERE key='turn_count'",
            (str(draft.sequence),),
        )

    @staticmethod
    def _preparation_from_row(row: sqlite3.Row) -> DeliveryPreparation:
        try:
            payload = json.loads(row["payload_json"])
            preparation = DeliveryPreparation.from_payload(payload)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise EpisodicMemoryError("delivery_preparation_corrupt") from exc
        if (
            preparation.delivery_token != row["delivery_token"]
            or preparation.turn_id != row["turn_id"]
            or preparation.preparation_digest != row["preparation_digest"]
        ):
            raise EpisodicMemoryError("delivery_preparation_digest_drifted")
        return preparation

    @staticmethod
    def _event_payload(
        row: sqlite3.Row, *, expected_kind: str
    ) -> dict[str, object]:
        try:
            payload = json.loads(row["payload_json"])
        except (json.JSONDecodeError, TypeError) as exc:
            raise EpisodicMemoryError("delivery_event_corrupt") from exc
        if not isinstance(payload, dict) or payload.get("outcome") != expected_kind:
            raise EpisodicMemoryError("delivery_event_schema_rejected")
        expected_digest = semantic_digest("myuna-p07-delivery-event-v2", payload)
        if row["event_digest"] != expected_digest:
            raise EpisodicMemoryError("delivery_event_digest_drifted")
        return payload

    def prepare_delivery(
        self,
        preparation: DeliveryPreparation,
        *,
        owner_day_policy: OwnerDayPolicy | None = None,
        crash_stage: str | None = None,
        _return_episode: bool = False,
    ) -> bool | DeliveryPreparationResolution:
        if crash_stage not in {None, "before_commit", "after_commit_before_return"}:
            raise EpisodicMemoryError("archive_fault_stage_rejected")
        connection, identity, descriptor, proof_descriptor = self._open()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._verify_connection(connection)
            existing = connection.execute(
                "SELECT * FROM delivery_preparations WHERE delivery_token=?",
                (preparation.delivery_token,),
            ).fetchone()
            if existing is not None:
                selected = self._preparation_from_row(existing)
                candidate = preparation.bind_archive_head(
                    turn_count=selected.expected_archive_turn_count,  # type: ignore[arg-type]
                    head_digest=selected.expected_archive_head_digest,  # type: ignore[arg-type]
                )
                if selected.preparation_digest != candidate.preparation_digest:
                    raise EpisodicMemoryError("delivery_preparation_replay_conflict")
                connection.execute("COMMIT")
                self._verify_terminal(connection, identity, descriptor)
                result = DeliveryPreparationResolution(
                    preparation=selected,
                    replayed=True,
                    episode=FactualDeliveryEpisodeV1.derive(
                        selected, owner_day_policy=owner_day_policy
                    ),
                )
                return result if _return_episode else result.replayed
            duplicate_turn = connection.execute(
                "SELECT preparation_digest FROM delivery_preparations WHERE turn_id=?",
                (preparation.turn_id,),
            ).fetchone()
            if duplicate_turn is not None:
                raise EpisodicMemoryError("delivery_preparation_replay_conflict")
            metadata = dict(connection.execute("SELECT key, value FROM metadata"))
            preparation = preparation.bind_archive_head(
                turn_count=int(metadata["turn_count"]),
                head_digest=str(metadata["head_digest"]),
            )
            connection.execute(
                "INSERT INTO delivery_preparations VALUES (?, ?, ?, ?)",
                (
                    preparation.delivery_token,
                    preparation.turn_id,
                    preparation.preparation_digest,
                    canonical_bytes(preparation.payload()).decode("utf-8"),
                ),
            )
            if crash_stage == "before_commit":
                raise EpisodicMemoryError("delivery_prepare_crash_before_commit", retryable=True)
            connection.execute("COMMIT")
            if crash_stage == "after_commit_before_return":
                raise EpisodicMemoryError(
                    "delivery_prepare_crash_after_commit", retryable=True
                )
            self._verify_terminal(connection, identity, descriptor)
            result = DeliveryPreparationResolution(
                preparation=preparation,
                replayed=False,
                episode=FactualDeliveryEpisodeV1.derive(
                    preparation, owner_day_policy=owner_day_policy
                ),
            )
            return result if _return_episode else result.replayed
        except EpisodicMemoryError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise EpisodicMemoryError("archive_write_failed", retryable=True) from exc
        finally:
            _close_connection(connection, descriptor, proof_descriptor)
            self._normalize_sidecar()

    def prepare_delivery_episode(
        self,
        preparation: DeliveryPreparation,
        *,
        owner_day_policy: OwnerDayPolicy | None = None,
        crash_stage: str | None = None,
    ) -> DeliveryPreparationResolution:
        result = self.prepare_delivery(
            preparation,
            owner_day_policy=owner_day_policy,
            crash_stage=crash_stage,
            _return_episode=True,
        )
        if not isinstance(result, DeliveryPreparationResolution):
            raise EpisodicMemoryError("delivery_preparation_result_rejected")
        return result

    def _resolution_from_event(
        self,
        connection: sqlite3.Connection,
        preparation: DeliveryPreparation,
        row: sqlite3.Row,
        *,
        replayed: bool,
        owner_day_policy: OwnerDayPolicy | None = None,
    ) -> DeliveryResolution:
        outcome = str(row["event_kind"])
        payload = self._event_payload(row, expected_kind=outcome)
        if (
            payload.get("delivery_token") != preparation.delivery_token
            or payload.get("preparation_digest") != preparation.preparation_digest
        ):
            raise EpisodicMemoryError("delivery_event_binding_drifted")
        complete = None
        if outcome == "delivered":
            expected = {
                "delivery_ack_digest",
                "delivered_boot_id",
                "delivery_token",
                "delivered_monotonic_ns",
                "outcome",
                "preparation_digest",
                "previous_turn_digest",
                "sequence",
                "turn_digest",
            }
            if set(payload) != expected:
                raise EpisodicMemoryError("delivery_event_schema_rejected")
            delivered_boot_id = _delivery_boot_identity(
                payload.get("delivered_boot_id")
            )
            turn_row = connection.execute(
                "SELECT * FROM complete_turns WHERE turn_digest=?",
                (payload["turn_digest"],),
            ).fetchone()
            if turn_row is None:
                raise EpisodicMemoryError("delivery_turn_receipt_missing")
            complete = self._turn_from_row(turn_row)
            if (
                complete.draft.turn_id != preparation.turn_id
                or complete.draft.sequence != payload["sequence"]
                or complete.draft.previous_turn_digest != payload["previous_turn_digest"]
                or complete.draft.delivery_ack_digest != payload["delivery_ack_digest"]
            ):
                raise EpisodicMemoryError("delivery_turn_receipt_drifted")
        else:
            if set(payload) != {"delivery_token", "outcome", "preparation_digest"}:
                raise EpisodicMemoryError("delivery_event_schema_rejected")
            delivered_boot_id = None
        archive_turns = self._turns_from_connection(connection)
        time_corrections = self._corrections_from_connection(connection)
        episode = FactualDeliveryEpisodeV1.derive(
            preparation,
            outcome=outcome,
            delivery_event_digest=row["event_digest"],
            delivered_monotonic_ns=payload.get("delivered_monotonic_ns"),  # type: ignore[arg-type]
            delivery_ack_digest=payload.get("delivery_ack_digest"),  # type: ignore[arg-type]
            complete_turn=complete,
            time_corrections=time_corrections,
            owner_day_policy=owner_day_policy,
        )
        return DeliveryResolution(
            preparation=preparation,
            outcome=outcome,
            delivered_monotonic_ns=payload.get("delivered_monotonic_ns"),  # type: ignore[arg-type]
            delivered_boot_id=delivered_boot_id,
            delivery_ack_digest=payload.get("delivery_ack_digest"),  # type: ignore[arg-type]
            archived=complete is not None,
            replayed=replayed,
            episode=episode,
            complete_turn=complete,
            archive_turns=archive_turns,
            time_corrections=time_corrections,
        )

    def resolve_delivery(
        self,
        *,
        delivery_token: str,
        outcome: str,
        delivered_monotonic_ns: int | None,
        delivered_boot_id: str | None = None,
        owner_day_policy: OwnerDayPolicy | None = None,
        crash_stage: str | None = None,
    ) -> DeliveryResolution:
        require_digest(delivery_token, "delivery_token")
        if outcome not in {"delivered", "cancelled"}:
            raise EpisodicMemoryError("delivery_outcome_rejected")
        if outcome == "delivered":
            if delivered_monotonic_ns is not None and (
                isinstance(delivered_monotonic_ns, bool)
                or not isinstance(delivered_monotonic_ns, int)
                or delivered_monotonic_ns < 0
            ):
                raise EpisodicMemoryError("delivery_monotonic_invalid")
            delivered_boot_id = _delivery_boot_identity(delivered_boot_id)
        elif delivered_monotonic_ns is not None or delivered_boot_id is not None:
            raise EpisodicMemoryError("cancelled_delivery_time_prohibited")
        if crash_stage not in {
            None,
            "before_commit",
            "at_commit_boundary",
            "after_commit_before_return",
        }:
            raise EpisodicMemoryError("archive_fault_stage_rejected")
        connection, identity, descriptor, proof_descriptor = self._open()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._verify_connection(connection)
            preparation_row = connection.execute(
                "SELECT * FROM delivery_preparations WHERE delivery_token=?",
                (delivery_token,),
            ).fetchone()
            if preparation_row is None:
                raise EpisodicMemoryError("delivery_token_unknown")
            preparation = self._preparation_from_row(preparation_row)
            delivered = connection.execute(
                "SELECT * FROM delivery_events WHERE delivery_token=? AND event_kind='delivered'",
                (delivery_token,),
            ).fetchone()
            cancelled = connection.execute(
                "SELECT * FROM delivery_events WHERE delivery_token=? AND event_kind='cancelled'",
                (delivery_token,),
            ).fetchone()
            if delivered is not None:
                if outcome == "cancelled":
                    raise EpisodicMemoryError("delivery_outcome_downgrade_rejected")
                delivered_payload = self._event_payload(
                    delivered, expected_kind="delivered"
                )
                if delivered_monotonic_ns is not None and (
                    delivered_payload.get("delivered_monotonic_ns")
                    != delivered_monotonic_ns
                ):
                    raise EpisodicMemoryError("delivery_resolution_replay_conflict")
                if delivered_boot_id is not None and (
                    delivered_payload.get("delivered_boot_id") != delivered_boot_id
                ):
                    raise EpisodicMemoryError("delivery_resolution_replay_conflict")
                result = self._resolution_from_event(
                    connection,
                    preparation,
                    delivered,
                    replayed=True,
                    owner_day_policy=owner_day_policy,
                )
                connection.execute("COMMIT")
                self._verify_terminal(connection, identity, descriptor)
                return result
            if outcome == "cancelled" and cancelled is not None:
                result = self._resolution_from_event(
                    connection,
                    preparation,
                    cancelled,
                    replayed=True,
                    owner_day_policy=owner_day_policy,
                )
                connection.execute("COMMIT")
                self._verify_terminal(connection, identity, descriptor)
                return result
            if outcome == "cancelled":
                payload: dict[str, object] = {
                    "delivery_token": delivery_token,
                    "outcome": "cancelled",
                    "preparation_digest": preparation.preparation_digest,
                }
                event_digest = semantic_digest("myuna-p07-delivery-event-v2", payload)
                connection.execute(
                    "INSERT INTO delivery_events VALUES (?, 'cancelled', ?, ?)",
                    (
                        delivery_token,
                        event_digest,
                        canonical_bytes(payload).decode("utf-8"),
                    ),
                )
                connection.execute(
                    "INSERT INTO lifecycle_records VALUES (?, ?, ?, ?, ?, 0, 0)",
                    (
                        f"{preparation.turn_id}:delivery-cancelled",
                        "delivery_failed",
                        preparation.request_digest,
                        preparation.source_occurred_at_utc.isoformat(
                            timespec="microseconds"
                        ),
                        "channel_delivery_cancelled",
                    ),
                )
            else:
                metadata = dict(connection.execute("SELECT key, value FROM metadata"))
                sequence = int(metadata["turn_count"]) + 1
                parent = str(metadata["head_digest"])
                delivery_ack_digest = semantic_digest(
                    "myuna-p07-owner-private-delivery-ack-v2",
                    {
                        "delivery_token": delivery_token,
                        "outcome": "delivered",
                        "preparation_digest": preparation.preparation_digest,
                    },
                )
                final_time = finalize_delivery_time_binding(
                    preparation.prompt_time_binding,
                    committed_monotonic_ns=preparation.committed_monotonic_ns,
                    delivered_monotonic_ns=delivered_monotonic_ns,
                    delivered_boot_id=delivered_boot_id,
                )
                complete = CompleteTurn.create(
                    preparation.complete_turn_draft(
                        sequence=sequence,
                        previous_turn_digest=parent,
                        final_time_binding=final_time,
                        delivery_ack_digest=delivery_ack_digest,
                    )
                )
                self._write_complete_turn(connection, complete)
                payload = {
                    "delivery_ack_digest": delivery_ack_digest,
                    "delivered_boot_id": delivered_boot_id,
                    "delivery_token": delivery_token,
                    "delivered_monotonic_ns": delivered_monotonic_ns,
                    "outcome": "delivered",
                    "preparation_digest": preparation.preparation_digest,
                    "previous_turn_digest": parent,
                    "sequence": sequence,
                    "turn_digest": complete.turn_digest,
                }
                event_digest = semantic_digest("myuna-p07-delivery-event-v2", payload)
                connection.execute(
                    "INSERT INTO delivery_events VALUES (?, 'delivered', ?, ?)",
                    (
                        delivery_token,
                        event_digest,
                        canonical_bytes(payload).decode("utf-8"),
                    ),
                )
            if crash_stage in {"before_commit", "at_commit_boundary"}:
                raise EpisodicMemoryError(
                    "delivery_resolution_crash_before_commit", retryable=True
                )
            selected_event = connection.execute(
                "SELECT * FROM delivery_events WHERE delivery_token=? AND event_kind=?",
                (delivery_token, outcome),
            ).fetchone()
            result = self._resolution_from_event(
                connection,
                preparation,
                selected_event,
                replayed=False,
                owner_day_policy=owner_day_policy,
            )
            connection.execute("COMMIT")
            if crash_stage == "after_commit_before_return":
                raise EpisodicMemoryError(
                    "delivery_resolution_crash_after_commit", retryable=True
                )
            self._verify_terminal(connection, identity, descriptor)
            return result
        except EpisodicMemoryError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except (sqlite3.Error, json.JSONDecodeError, TypeError, ValueError) as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise EpisodicMemoryError("archive_write_failed", retryable=True) from exc
        finally:
            _close_connection(connection, descriptor, proof_descriptor)
            self._normalize_sidecar()

    def delivery_close_evidence_required(self, delivery_token: str) -> bool:
        """Whether a validated preparation still lacks a delivered receipt."""

        require_digest(delivery_token, "delivery_token")
        connection, identity, descriptor, proof_descriptor = self._open()
        try:
            self._verify_connection(connection)
            preparation_row = connection.execute(
                "SELECT * FROM delivery_preparations WHERE delivery_token=?",
                (delivery_token,),
            ).fetchone()
            if preparation_row is None:
                raise EpisodicMemoryError("delivery_token_unknown")
            preparation = self._preparation_from_row(preparation_row)
            delivered = connection.execute(
                "SELECT * FROM delivery_events WHERE delivery_token=? AND event_kind='delivered'",
                (delivery_token,),
            ).fetchone()
            if delivered is not None:
                self._resolution_from_event(
                    connection, preparation, delivered, replayed=True
                )
                self._verify_terminal(connection, identity, descriptor)
                return False
            cancelled = connection.execute(
                "SELECT * FROM delivery_events WHERE delivery_token=? AND event_kind='cancelled'",
                (delivery_token,),
            ).fetchone()
            if cancelled is not None:
                self._resolution_from_event(
                    connection, preparation, cancelled, replayed=True
                )
            self._verify_terminal(connection, identity, descriptor)
            return True
        except EpisodicMemoryError:
            raise
        except (sqlite3.Error, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise EpisodicMemoryError("archive_read_failed") from exc
        finally:
            _close_connection(connection, descriptor, proof_descriptor)

    def unresolved_preparations(self) -> tuple[DeliveryPreparation, ...]:
        connection, identity, descriptor, proof_descriptor = self._open()
        try:
            self._verify_connection(connection)
            rows = connection.execute(
                "SELECT p.* FROM delivery_preparations p "
                "WHERE NOT EXISTS (SELECT 1 FROM delivery_events e "
                "WHERE e.delivery_token=p.delivery_token) ORDER BY p.rowid"
            ).fetchall()
            result = tuple(self._preparation_from_row(row) for row in rows)
            self._verify_terminal(connection, identity, descriptor)
            return result
        except (sqlite3.Error, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise EpisodicMemoryError("archive_read_failed") from exc
        finally:
            _close_connection(connection, descriptor, proof_descriptor)

    def delivery_metadata(self) -> dict[str, object]:
        connection, identity, descriptor, proof_descriptor = self._open()
        try:
            self._verify_connection(connection)
            prepared = connection.execute(
                "SELECT COUNT(*) FROM delivery_preparations"
            ).fetchone()[0]
            delivered = connection.execute(
                "SELECT COUNT(*) FROM delivery_events WHERE event_kind='delivered'"
            ).fetchone()[0]
            cancelled = connection.execute(
                "SELECT COUNT(*) FROM delivery_events WHERE event_kind='cancelled'"
            ).fetchone()[0]
            pending = connection.execute(
                "SELECT COUNT(*) FROM delivery_preparations p WHERE NOT EXISTS "
                "(SELECT 1 FROM delivery_events e WHERE e.delivery_token=p.delivery_token)"
            ).fetchone()[0]
            late = connection.execute(
                "SELECT COUNT(*) FROM delivery_preparations p "
                "WHERE EXISTS (SELECT 1 FROM delivery_events c WHERE "
                "c.delivery_token=p.delivery_token AND c.event_kind='cancelled') "
                "AND EXISTS (SELECT 1 FROM delivery_events d WHERE "
                "d.delivery_token=p.delivery_token AND d.event_kind='delivered')"
            ).fetchone()[0]
            result = {
                "archived_count": delivered,
                "cancelled_count": cancelled,
                "delivered_count": delivered,
                "late_delivered_after_cancelled_count": late,
                "pending_count": pending,
                "prepared_count": prepared,
                "schema": DELIVERY_JOURNAL_SCHEMA,
            }
            self._verify_terminal(connection, identity, descriptor)
            return result
        except sqlite3.Error as exc:
            raise EpisodicMemoryError("archive_metadata_unavailable") from exc
        finally:
            _close_connection(connection, descriptor, proof_descriptor)

    def storage_projection(self) -> dict[str, object]:
        connection, identity, descriptor, proof_descriptor = self._open()
        try:
            self._verify_connection(connection)
            result = {
                "device": identity[0],
                "gid": identity[3],
                "inode": identity[1],
                "journal_mode": str(
                    connection.execute("PRAGMA journal_mode").fetchone()[0]
                ).lower(),
                "mode": identity[4],
                "synchronous": int(
                    connection.execute("PRAGMA synchronous").fetchone()[0]
                ),
                "uid": identity[2],
            }
            self._verify_terminal(connection, identity, descriptor)
            return result
        finally:
            _close_connection(connection, descriptor, proof_descriptor)

    def append_complete_turn(
        self,
        draft: CompleteTurnDraft,
        *,
        crash_stage: str | None = None,
    ) -> CompleteTurn:
        complete = CompleteTurn.create(draft)
        connection, identity, descriptor, proof_descriptor = self._open()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._verify_connection(connection)
            existing = connection.execute(
                "SELECT request_digest, turn_digest, sequence "
                "FROM append_receipts WHERE turn_id = ?",
                (draft.turn_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["request_digest"] == draft.request_digest
                    and existing["turn_digest"] == complete.turn_digest
                    and existing["sequence"] == draft.sequence
                ):
                    connection.execute("COMMIT")
                    self._verify_terminal(connection, identity, descriptor)
                    return complete
                raise EpisodicMemoryError("archive_replay_conflict")
            metadata = dict(connection.execute("SELECT key, value FROM metadata"))
            if int(metadata["turn_count"]) + 1 != draft.sequence:
                raise EpisodicMemoryError("archive_sequence_gap")
            if metadata["head_digest"] != draft.previous_turn_digest:
                raise EpisodicMemoryError("archive_parent_digest_mismatch")
            self._write_complete_turn(connection, complete)
            if crash_stage == "before_commit":
                raise EpisodicMemoryError("archive_crash_before_commit", retryable=True)
            connection.execute("COMMIT")
            if crash_stage == "after_commit":
                raise EpisodicMemoryError("archive_crash_after_commit", retryable=True)
            self._verify_terminal(connection, identity, descriptor)
            return complete
        except EpisodicMemoryError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise EpisodicMemoryError("archive_write_failed", retryable=True) from exc
        finally:
            _close_connection(connection, descriptor, proof_descriptor)
            self._normalize_sidecar()

    def append_lifecycle(self, record: LifecycleRecord) -> None:
        connection, identity, descriptor, proof_descriptor = self._open()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._verify_connection(connection)
            existing = connection.execute(
                "SELECT event_kind, request_digest, reason_code "
                "FROM lifecycle_records WHERE lifecycle_id = ?",
                (record.lifecycle_id,),
            ).fetchone()
            if existing is not None:
                if tuple(existing) != (
                    record.event_kind,
                    record.request_digest,
                    record.reason_code,
                ):
                    raise EpisodicMemoryError("lifecycle_replay_conflict")
                connection.execute("COMMIT")
                self._verify_terminal(connection, identity, descriptor)
                return
            connection.execute(
                "INSERT INTO lifecycle_records VALUES (?, ?, ?, ?, ?, 0, 0)",
                (
                    record.lifecycle_id,
                    record.event_kind,
                    record.request_digest,
                    record.occurred_at_utc.isoformat(timespec="microseconds"),
                    record.reason_code,
                ),
            )
            connection.execute("COMMIT")
            self._verify_terminal(connection, identity, descriptor)
        except EpisodicMemoryError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise EpisodicMemoryError("archive_write_failed", retryable=True) from exc
        finally:
            _close_connection(connection, descriptor, proof_descriptor)
            self._normalize_sidecar()

    def append_time_correction(self, correction: TurnTimeCorrection) -> str:
        connection, identity, descriptor, proof_descriptor = self._open()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._verify_connection(connection)
            selected = connection.execute(
                "SELECT turn_digest, time_binding_digest FROM complete_turns WHERE turn_id = ?",
                (correction.turn_id,),
            ).fetchone()
            if (
                selected is None
                or selected["turn_digest"] != correction.turn_digest
                or selected["time_binding_digest"] != correction.original_binding_digest
            ):
                raise EpisodicMemoryError("time_correction_source_drifted")
            existing = connection.execute(
                "SELECT correction_digest FROM time_corrections WHERE correction_id = ?",
                (correction.correction_id,),
            ).fetchone()
            if existing is not None:
                if existing[0] == correction.correction_digest:
                    connection.execute("COMMIT")
                    self._verify_terminal(connection, identity, descriptor)
                    return correction.correction_digest
                raise EpisodicMemoryError("time_correction_replay_conflict")
            connection.execute(
                "INSERT INTO time_corrections VALUES (?, ?, ?, ?, ?, ?)",
                (
                    correction.correction_id,
                    correction.turn_id,
                    correction.turn_digest,
                    correction.original_binding_digest,
                    correction.correction_digest,
                    json.dumps(
                        correction.payload(),
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                ),
            )
            connection.execute("COMMIT")
            self._verify_terminal(connection, identity, descriptor)
            return correction.correction_digest
        except EpisodicMemoryError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise EpisodicMemoryError("archive_write_failed", retryable=True) from exc
        finally:
            _close_connection(connection, descriptor, proof_descriptor)
            self._normalize_sidecar()

    def turns(self) -> tuple[CompleteTurn, ...]:
        """Internal authority read used by bounded retrieval, never by audit projection."""
        connection, identity, descriptor, proof_descriptor = self._open()
        try:
            self._verify_connection(connection)
            result = self._turns_from_connection(connection)
            self._verify_terminal(connection, identity, descriptor)
            return result
        except (sqlite3.Error, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise EpisodicMemoryError("archive_read_failed") from exc
        finally:
            _close_connection(connection, descriptor, proof_descriptor)

    def time_corrections(self) -> tuple[TurnTimeCorrection, ...]:
        """Internal append-only correction read; audit surfaces only its count."""

        connection, identity, descriptor, proof_descriptor = self._open()
        try:
            self._verify_connection(connection)
            result = self._corrections_from_connection(connection)
            self._verify_terminal(connection, identity, descriptor)
            return result
        except (sqlite3.Error, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise EpisodicMemoryError("archive_read_failed") from exc
        finally:
            _close_connection(connection, descriptor, proof_descriptor)

    def metadata(self) -> dict[str, object]:
        connection, identity, descriptor, proof_descriptor = self._open()
        try:
            self._verify_connection(connection)
            values = dict(connection.execute("SELECT key, value FROM metadata"))
            lifecycle_count = connection.execute(
                "SELECT COUNT(*) FROM lifecycle_records"
            ).fetchone()[0]
            correction_count = connection.execute(
                "SELECT COUNT(*) FROM time_corrections"
            ).fetchone()[0]
            result = {
                "archive_schema": values["archive_schema"],
                "head_digest": values["head_digest"],
                "lifecycle_count": lifecycle_count,
                "time_correction_count": correction_count,
                "turn_count": int(values["turn_count"]),
            }
            self._verify_terminal(connection, identity, descriptor)
            return result
        except (sqlite3.Error, KeyError, ValueError) as exc:
            raise EpisodicMemoryError("archive_metadata_unavailable") from exc
        finally:
            _close_connection(connection, descriptor, proof_descriptor)
