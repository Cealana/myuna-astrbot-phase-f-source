from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Mapping

from myuna_core.authenticated_conversation import AuthenticatedConversationContext
from myuna_core.external_context.contracts import (
    EXTERNAL_CONTEXT_SCHEMA,
    EXTERNAL_PROJECTION_POLICY,
    EXTERNAL_VISUAL_CONTEXT_SCHEMA,
    EXTERNAL_VISUAL_PROJECTION_POLICY,
    MAX_RECENT_CHARACTERS,
    MAX_RECENT_TURNS,
    ZERO_DIGEST,
    EgressSafetySignals,
    ExternalContextEnvelope,
    ExternalSummaryCandidate,
    ExternalSummaryJob,
    ExternalSummary,
    ExternalTurn,
    ExternalTurnProvenance,
    VisualEvidence,
    current_message_digest,
)


SQLITE_SCHEMA = "myuna.external-authorized-epoch.v2"
SQLITE_SCHEMA_VERSION = 2
ROLLING_SUMMARY_TRIGGER_TURNS = 5
ROLLING_SUMMARY_TRIGGER_CHARACTERS = 9_000
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")

_TABLE_DEFINITIONS = (
    """
    CREATE TABLE epoch_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        schema_name TEXT NOT NULL,
        schema_version INTEGER NOT NULL,
        epoch_id TEXT NOT NULL,
        channel_kind TEXT NOT NULL,
        principal_id TEXT NOT NULL,
        namespace_id TEXT NOT NULL,
        selected_revision INTEGER NOT NULL,
        max_revision INTEGER NOT NULL,
        latest_sequence INTEGER NOT NULL,
        latest_digest TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE epoch_revisions (
        revision INTEGER PRIMARY KEY,
        selected_sequence INTEGER NOT NULL,
        selected_digest TEXT NOT NULL,
        summary_version INTEGER,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE committed_turns (
        sequence INTEGER PRIMARY KEY,
        parent_digest TEXT NOT NULL,
        turn_digest TEXT NOT NULL UNIQUE,
        user_message TEXT NOT NULL,
        assistant_reply TEXT NOT NULL,
        delivered_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE committed_turn_provenance (
        sequence INTEGER PRIMARY KEY,
        provenance_json TEXT NOT NULL,
        provenance_digest TEXT NOT NULL UNIQUE,
        FOREIGN KEY(sequence) REFERENCES committed_turns(sequence)
    )
    """,
    """
    CREATE TABLE committed_summaries (
        summary_version INTEGER PRIMARY KEY,
        covered_start INTEGER NOT NULL,
        covered_end INTEGER NOT NULL,
        covered_terminal_digest TEXT NOT NULL,
        profile_revisions_json TEXT NOT NULL,
        content TEXT NOT NULL,
        summary_digest TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE pending_turns (
        event_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL,
        base_revision INTEGER NOT NULL,
        sequence INTEGER NOT NULL,
        parent_digest TEXT NOT NULL,
        current_message TEXT NOT NULL,
        current_message_digest TEXT NOT NULL,
        safety_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE summary_jobs (
        job_digest TEXT PRIMARY KEY,
        base_revision INTEGER NOT NULL UNIQUE,
        summary_version INTEGER NOT NULL,
        covered_end INTEGER NOT NULL,
        covered_terminal_digest TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending', 'committed')),
        committed_revision INTEGER,
        candidate_digest TEXT,
        created_at TEXT NOT NULL,
        committed_at TEXT
    )
    """,
)

EXPECTED_EPOCH_COLUMNS = {
    "committed_turn_provenance": (
        ("sequence", "INTEGER", 0, 1),
        ("provenance_json", "TEXT", 1, 0),
        ("provenance_digest", "TEXT", 1, 0),
    ),
    "committed_summaries": (
        ("summary_version", "INTEGER", 0, 1),
        ("covered_start", "INTEGER", 1, 0),
        ("covered_end", "INTEGER", 1, 0),
        ("covered_terminal_digest", "TEXT", 1, 0),
        ("profile_revisions_json", "TEXT", 1, 0),
        ("content", "TEXT", 1, 0),
        ("summary_digest", "TEXT", 1, 0),
        ("created_at", "TEXT", 1, 0),
    ),
    "committed_turns": (
        ("sequence", "INTEGER", 0, 1),
        ("parent_digest", "TEXT", 1, 0),
        ("turn_digest", "TEXT", 1, 0),
        ("user_message", "TEXT", 1, 0),
        ("assistant_reply", "TEXT", 1, 0),
        ("delivered_at", "TEXT", 1, 0),
    ),
    "epoch_revisions": (
        ("revision", "INTEGER", 0, 1),
        ("selected_sequence", "INTEGER", 1, 0),
        ("selected_digest", "TEXT", 1, 0),
        ("summary_version", "INTEGER", 0, 0),
        ("created_at", "TEXT", 1, 0),
    ),
    "epoch_state": (
        ("singleton", "INTEGER", 0, 1),
        ("schema_name", "TEXT", 1, 0),
        ("schema_version", "INTEGER", 1, 0),
        ("epoch_id", "TEXT", 1, 0),
        ("channel_kind", "TEXT", 1, 0),
        ("principal_id", "TEXT", 1, 0),
        ("namespace_id", "TEXT", 1, 0),
        ("selected_revision", "INTEGER", 1, 0),
        ("max_revision", "INTEGER", 1, 0),
        ("latest_sequence", "INTEGER", 1, 0),
        ("latest_digest", "TEXT", 1, 0),
        ("updated_at", "TEXT", 1, 0),
    ),
    "pending_turns": (
        ("event_id", "TEXT", 0, 1),
        ("request_id", "TEXT", 1, 0),
        ("base_revision", "INTEGER", 1, 0),
        ("sequence", "INTEGER", 1, 0),
        ("parent_digest", "TEXT", 1, 0),
        ("current_message", "TEXT", 1, 0),
        ("current_message_digest", "TEXT", 1, 0),
        ("safety_json", "TEXT", 1, 0),
        ("created_at", "TEXT", 1, 0),
    ),
    "summary_jobs": (
        ("job_digest", "TEXT", 0, 1),
        ("base_revision", "INTEGER", 1, 0),
        ("summary_version", "INTEGER", 1, 0),
        ("covered_end", "INTEGER", 1, 0),
        ("covered_terminal_digest", "TEXT", 1, 0),
        ("status", "TEXT", 1, 0),
        ("committed_revision", "INTEGER", 0, 0),
        ("candidate_digest", "TEXT", 0, 0),
        ("created_at", "TEXT", 1, 0),
        ("committed_at", "TEXT", 0, 0),
    ),
}
EXPECTED_EPOCH_INDEXES = {
    "committed_turn_provenance": {("u", 1, ("provenance_digest",))},
    "committed_summaries": {("u", 1, ("summary_digest",))},
    "committed_turns": {("u", 1, ("turn_digest",))},
    "epoch_revisions": set(),
    "epoch_state": set(),
    "pending_turns": {("pk", 1, ("event_id",))},
    "summary_jobs": {
        ("pk", 1, ("job_digest",)),
        ("u", 1, ("base_revision",)),
    },
}


class ExternalEpochRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ExternalEpochBinding:
    channel_kind: str
    client_id: str
    principal_id: str
    namespace_id: str

    def __post_init__(self) -> None:
        if self.channel_kind != "astrbot_telegram":
            raise ExternalEpochRejected("epoch_binding_scope_rejected")
        if self.client_id != "telegram-owner-private":
            raise ExternalEpochRejected("epoch_binding_scope_rejected")
        for value in (self.principal_id, self.namespace_id):
            if _SAFE_ID.fullmatch(value) is None:
                raise ExternalEpochRejected("epoch_binding_identity_rejected")


def verify_epoch_schema(connection: sqlite3.Connection) -> None:
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    if tables != set(EXPECTED_EPOCH_COLUMNS):
        raise ExternalEpochRejected("epoch_database_schema_rejected")
    if connection.execute("PRAGMA user_version").fetchone()[0] != SQLITE_SCHEMA_VERSION:
        raise ExternalEpochRejected("epoch_database_schema_version_rejected")
    for table, expected in EXPECTED_EPOCH_COLUMNS.items():
        actual = tuple(
            (row[1], row[2], row[3], row[5])
            for row in connection.execute(f"PRAGMA table_info({table})")
        )
        if actual != expected:
            raise ExternalEpochRejected("epoch_database_columns_rejected")
        indexes = set()
        for index in connection.execute(f"PRAGMA index_list({table})"):
            columns = tuple(
                row[2]
                for row in connection.execute(f"PRAGMA index_info({index[1]})")
            )
            indexes.add((index[3], index[2], columns))
        if indexes != EXPECTED_EPOCH_INDEXES[table]:
            raise ExternalEpochRejected("epoch_database_indexes_rejected")


@dataclass(frozen=True, slots=True)
class PendingExternalTurn:
    epoch_id: str
    event_id: str
    request_id: str
    base_revision: int
    sequence: int
    current_message_digest: str

    def audit_projection(self) -> dict[str, object]:
        return {
            "base_revision": self.base_revision,
            "pending": True,
            "sequence": self.sequence,
        }


@dataclass(frozen=True, slots=True)
class DeliveryCommitResult:
    turn: ExternalTurn
    summary_job: ExternalSummaryJob | None


def _canonical_json(payload: Mapping[str, object]) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _provenance_digest(provenance: ExternalTurnProvenance) -> str:
    return sha256(
        b"myuna-external-turn-provenance-v1\0"
        + _canonical_json(provenance.as_payload()).encode("utf-8")
    ).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class ExternalEpochStore:
    """Independent private sidecar; it never reads or migrates legacy session data."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        epoch_id: str,
        startup_binding: ExternalEpochBinding | None = None,
        expected_uid: int | None = None,
        expected_gid: int | None = None,
    ) -> None:
        self.database_path = Path(database_path)
        if not self.database_path.is_absolute():
            raise ExternalEpochRejected("epoch_database_path_not_absolute")
        if _SAFE_ID.fullmatch(epoch_id) is None:
            raise ExternalEpochRejected("epoch_id_out_of_contract")
        self.epoch_id = epoch_id
        self.startup_binding = startup_binding
        self.expected_uid = os.geteuid() if expected_uid is None else expected_uid
        self.expected_gid = os.getegid() if expected_gid is None else expected_gid
        if self.expected_uid < 0 or self.expected_gid < 0:
            raise ExternalEpochRejected("epoch_database_owner_rejected")
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        self._verify_existing_paths()
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _verify_existing_paths(self) -> None:
        parent = self.database_path.parent
        if parent.is_symlink():
            raise ExternalEpochRejected("epoch_database_parent_type_rejected")
        if parent.exists():
            if not parent.is_dir():
                raise ExternalEpochRejected("epoch_database_parent_type_rejected")
            metadata = parent.stat()
            if (
                stat.S_IMODE(metadata.st_mode) != 0o700
                or metadata.st_uid != self.expected_uid
                or metadata.st_gid != self.expected_gid
            ):
                raise ExternalEpochRejected("epoch_database_permission_drift")
        for path in (
            self.database_path,
            Path(f"{self.database_path}-wal"),
            Path(f"{self.database_path}-shm"),
        ):
            if path.is_symlink():
                raise ExternalEpochRejected("epoch_database_type_rejected")
            if not path.exists():
                continue
            if not path.is_file():
                raise ExternalEpochRejected("epoch_database_type_rejected")
            metadata = path.stat()
            if (
                stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != self.expected_uid
                or metadata.st_gid != self.expected_gid
            ):
                raise ExternalEpochRejected("epoch_database_permission_drift")

    def _secure_paths(self) -> None:
        if self.database_path.parent.is_symlink() or not self.database_path.parent.is_dir():
            raise ExternalEpochRejected("epoch_database_parent_type_rejected")
        os.chmod(self.database_path.parent, 0o700)
        for path in (
            self.database_path,
            Path(f"{self.database_path}-wal"),
            Path(f"{self.database_path}-shm"),
        ):
            if path.exists():
                if path.is_symlink() or not path.is_file():
                    raise ExternalEpochRejected("epoch_database_type_rejected")
                os.chmod(path, 0o600)

    def _initialize(self) -> None:
        parent = self.database_path.parent
        if parent.exists() and (parent.is_symlink() or not parent.is_dir()):
            raise ExternalEpochRejected("epoch_database_parent_type_rejected")
        if self.database_path.exists() and (
            self.database_path.is_symlink() or not self.database_path.is_file()
        ):
            raise ExternalEpochRejected("epoch_database_type_rejected")
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            self._verify_existing_schema_before_mutation()
            self._verify_existing_paths()
            try:
                descriptor = os.open(
                    self.database_path,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
            self._verify_existing_paths()
            connection = sqlite3.connect(self.database_path, timeout=5.0)
            connection.row_factory = sqlite3.Row
            try:
                connection.execute("PRAGMA busy_timeout = 5000")
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute("BEGIN IMMEDIATE")
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                    )
                }
                if tables:
                    verify_epoch_schema(connection)
                    if self.startup_binding is not None:
                        self._verify_startup_state(connection, self.startup_binding)
                else:
                    for definition in _TABLE_DEFINITIONS:
                        connection.execute(definition)
                    connection.execute(f"PRAGMA user_version = {SQLITE_SCHEMA_VERSION}")
                    if self.startup_binding is not None:
                        self._insert_startup_state(connection, self.startup_binding)
                    verify_epoch_schema(connection)
                connection.commit()
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute("PRAGMA synchronous = FULL")
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
            self._secure_paths()
        except ExternalEpochRejected:
            raise
        except (OSError, sqlite3.Error):
            raise ExternalEpochRejected("epoch_database_initialization_failed") from None

    def _insert_startup_state(
        self,
        connection: sqlite3.Connection,
        binding: ExternalEpochBinding,
    ) -> None:
        now = _utc_now()
        connection.execute(
            """
            INSERT INTO epoch_state (
                singleton, schema_name, schema_version, epoch_id,
                channel_kind, principal_id, namespace_id,
                selected_revision, max_revision, latest_sequence,
                latest_digest, updated_at
            ) VALUES (1, ?, ?, ?, ?, ?, ?, 0, 0, 0, ?, ?)
            """,
            (
                SQLITE_SCHEMA,
                SQLITE_SCHEMA_VERSION,
                self.epoch_id,
                binding.channel_kind,
                binding.principal_id,
                binding.namespace_id,
                ZERO_DIGEST,
                now,
            ),
        )
        connection.execute(
            """
            INSERT INTO epoch_revisions (
                revision, selected_sequence, selected_digest,
                summary_version, created_at
            ) VALUES (0, 0, ?, NULL, ?)
            """,
            (ZERO_DIGEST, now),
        )

    def _verify_startup_state(
        self,
        connection: sqlite3.Connection,
        binding: ExternalEpochBinding,
    ) -> None:
        rows = connection.execute("SELECT * FROM epoch_state LIMIT 2").fetchall()
        if len(rows) != 1:
            raise ExternalEpochRejected("epoch_state_cardinality_rejected")
        state = rows[0]
        if (
            state["schema_name"] != SQLITE_SCHEMA
            or state["schema_version"] != SQLITE_SCHEMA_VERSION
            or state["epoch_id"] != self.epoch_id
        ):
            raise ExternalEpochRejected("epoch_state_schema_drift")
        if (
            state["channel_kind"] != binding.channel_kind
            or state["principal_id"] != binding.principal_id
            or state["namespace_id"] != binding.namespace_id
        ):
            raise ExternalEpochRejected("epoch_state_binding_mismatch")

    def _verify_existing_schema_before_mutation(self) -> None:
        if not self.database_path.exists() or self.database_path.stat().st_size == 0:
            return
        uri = f"file:{self.database_path}?mode=ro"
        try:
            with sqlite3.connect(uri, uri=True, timeout=5.0) as connection:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA query_only = ON")
                verify_epoch_schema(connection)
                rows = connection.execute(
                    "SELECT * FROM epoch_state WHERE singleton = 1 LIMIT 2"
                ).fetchall()
                if len(rows) != 1:
                    raise ExternalEpochRejected("epoch_state_cardinality_rejected")
                state = rows[0]
                if (
                    state["schema_name"] != SQLITE_SCHEMA
                    or state["schema_version"] != SQLITE_SCHEMA_VERSION
                    or state["epoch_id"] != self.epoch_id
                ):
                    raise ExternalEpochRejected("epoch_state_schema_drift")
                if self.startup_binding is not None:
                    self._verify_startup_state(connection, self.startup_binding)
        except ExternalEpochRejected:
            raise
        except sqlite3.Error:
            raise ExternalEpochRejected("epoch_state_schema_drift") from None

    @staticmethod
    def _verify_context(context: AuthenticatedConversationContext) -> None:
        if (
            context.channel_kind != "astrbot_telegram"
            or context.client_id != "telegram-owner-private"
            or context.authority_level != "owner"
            or context.conversation_kind != "private"
        ):
            raise ExternalEpochRejected("external_epoch_owner_scope_rejected")

    def _state(self, connection: sqlite3.Connection) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM epoch_state WHERE singleton = 1"
        ).fetchone()

    def _ensure_state(
        self,
        connection: sqlite3.Connection,
        context: AuthenticatedConversationContext,
    ) -> sqlite3.Row:
        state = self._state(connection)
        if state is None and self.startup_binding is not None:
            raise ExternalEpochRejected("epoch_state_unavailable")
        if state is None:
            now = _utc_now()
            connection.execute(
                """
                INSERT INTO epoch_state (
                    singleton, schema_name, schema_version, epoch_id,
                    channel_kind, principal_id, namespace_id,
                    selected_revision, max_revision, latest_sequence,
                    latest_digest, updated_at
                ) VALUES (1, ?, ?, ?, ?, ?, ?, 0, 0, 0, ?, ?)
                """,
                (
                    SQLITE_SCHEMA,
                    SQLITE_SCHEMA_VERSION,
                    self.epoch_id,
                    context.channel_kind,
                    context.principal_id,
                    context.namespace_id,
                    ZERO_DIGEST,
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO epoch_revisions (
                    revision, selected_sequence, selected_digest,
                    summary_version, created_at
                ) VALUES (0, 0, ?, NULL, ?)
                """,
                (ZERO_DIGEST, now),
            )
            state = self._state(connection)
        if state is None:
            raise ExternalEpochRejected("epoch_state_unavailable")
        if (
            state["schema_name"] != SQLITE_SCHEMA
            or state["schema_version"] != SQLITE_SCHEMA_VERSION
            or state["epoch_id"] != self.epoch_id
        ):
            raise ExternalEpochRejected("epoch_state_schema_drift")
        if (
            state["channel_kind"] != context.channel_kind
            or state["principal_id"] != context.principal_id
            or state["namespace_id"] != context.namespace_id
        ):
            raise ExternalEpochRejected("epoch_state_binding_mismatch")
        return state

    def begin_turn(
        self,
        context: AuthenticatedConversationContext,
        current_message: str,
        safety: EgressSafetySignals,
    ) -> PendingExternalTurn:
        self._verify_context(context)
        digest = current_message_digest(context, current_message)
        safety_json = json.dumps(
            safety.as_payload(),
            separators=(",", ":"),
            sort_keys=True,
        )
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = self._ensure_state(connection, context)
                if state["selected_revision"] != state["max_revision"]:
                    raise ExternalEpochRejected("rollback_requires_new_epoch")
                if connection.execute(
                    "SELECT 1 FROM summary_jobs WHERE status = 'pending' LIMIT 1"
                ).fetchone():
                    raise ExternalEpochRejected("external_summary_pending")
                if connection.execute("SELECT 1 FROM pending_turns LIMIT 1").fetchone():
                    raise ExternalEpochRejected("external_turn_already_pending")
                sequence = state["latest_sequence"] + 1
                connection.execute(
                    """
                    INSERT INTO pending_turns (
                        event_id, request_id, base_revision, sequence,
                        parent_digest, current_message, current_message_digest,
                        safety_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        context.event_id,
                        context.request_id,
                        state["selected_revision"],
                        sequence,
                        state["latest_digest"],
                        current_message,
                        digest,
                        safety_json,
                        _utc_now(),
                    ),
                )
            self._secure_paths()
        except ExternalEpochRejected:
            raise
        except sqlite3.IntegrityError:
            raise ExternalEpochRejected("external_turn_duplicate") from None
        except (OSError, sqlite3.Error):
            raise ExternalEpochRejected("external_turn_begin_failed") from None
        return PendingExternalTurn(
            epoch_id=self.epoch_id,
            event_id=context.event_id,
            request_id=context.request_id,
            base_revision=state["selected_revision"],
            sequence=sequence,
            current_message_digest=digest,
        )

    def _pending(
        self,
        connection: sqlite3.Connection,
        token: PendingExternalTurn,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM pending_turns WHERE event_id = ?",
            (token.event_id,),
        ).fetchone()
        if (
            row is None
            or row["request_id"] != token.request_id
            or row["base_revision"] != token.base_revision
            or row["sequence"] != token.sequence
            or row["current_message_digest"] != token.current_message_digest
        ):
            raise ExternalEpochRejected("pending_turn_token_rejected")
        return row

    def context_payload(
        self,
        context: AuthenticatedConversationContext,
        token: PendingExternalTurn,
        *,
        visual_event: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        self._verify_context(context)
        try:
            with self._connect() as connection:
                state = self._ensure_state(connection, context)
                pending = self._pending(connection, token)
                revision = connection.execute(
                    "SELECT * FROM epoch_revisions WHERE revision = ?",
                    (state["selected_revision"],),
                ).fetchone()
                if revision is None:
                    raise ExternalEpochRejected("epoch_revision_unavailable")
                summary = None
                first_sequence = 1
                if revision["summary_version"] is not None:
                    row = connection.execute(
                        "SELECT * FROM committed_summaries WHERE summary_version = ?",
                        (revision["summary_version"],),
                    ).fetchone()
                    if row is None:
                        raise ExternalEpochRejected("epoch_summary_unavailable")
                    summary = ExternalSummary(
                        summary_version=row["summary_version"],
                        covered_start=row["covered_start"],
                        covered_end=row["covered_end"],
                        covered_terminal_digest=row["covered_terminal_digest"],
                        profile_revisions=tuple(
                            json.loads(row["profile_revisions_json"])
                        ),
                        content=row["content"],
                        digest=row["summary_digest"],
                    )
                    first_sequence = summary.covered_end + 1
                rows = connection.execute(
                    """
                    SELECT * FROM committed_turns
                    WHERE sequence BETWEEN ? AND ? ORDER BY sequence
                    """,
                    (first_sequence, revision["selected_sequence"]),
                ).fetchall()
                turns = tuple(
                    ExternalTurn(
                        sequence=row["sequence"],
                        parent_digest=row["parent_digest"],
                        digest=row["turn_digest"],
                        user_message=row["user_message"],
                        assistant_reply=row["assistant_reply"],
                    )
                    for row in rows
                )
                if len(turns) > MAX_RECENT_TURNS or sum(
                    len(item.user_message) + len(item.assistant_reply) for item in turns
                ) > MAX_RECENT_CHARACTERS:
                    raise ExternalEpochRejected("external_summary_capacity_drift")
                visual_evidence = None
                if visual_event is not None:
                    if (
                        set(visual_event)
                        != {"caption_present", "observation", "schema", "source"}
                        or visual_event["schema"] != "myuna.telegram-visual-evidence.v1"
                        or visual_event["source"] != "gemini_visual_extraction"
                    ):
                        raise ExternalEpochRejected("visual_event_out_of_contract")
                    visual_evidence = VisualEvidence.create(
                        context=context,
                        current_message=pending["current_message"],
                        observation=visual_event["observation"],
                        caption_present=visual_event["caption_present"],
                    )
                envelope = ExternalContextEnvelope(
                    epoch_id=self.epoch_id,
                    epoch_revision=state["selected_revision"],
                    turn_sequence=revision["selected_sequence"],
                    parent_digest=revision["selected_digest"],
                    channel_kind=context.channel_kind,
                    principal_id=context.principal_id,
                    namespace_id=context.namespace_id,
                    current_message=pending["current_message"],
                    current_message_digest=pending["current_message_digest"],
                    summary=summary,
                    recent_turns=turns,
                    safety=EgressSafetySignals.from_payload(
                        json.loads(pending["safety_json"])
                    ),
                    visual_evidence=visual_evidence,
                    projection_policy_version=(
                        EXTERNAL_VISUAL_PROJECTION_POLICY
                        if visual_evidence is not None
                        else EXTERNAL_PROJECTION_POLICY
                    ),
                    schema=(
                        EXTERNAL_VISUAL_CONTEXT_SCHEMA
                        if visual_evidence is not None
                        else EXTERNAL_CONTEXT_SCHEMA
                    ),
                )
            self._secure_paths()
            return envelope.as_payload()
        except ExternalEpochRejected:
            raise
        except Exception:
            raise ExternalEpochRejected("external_context_load_failed") from None

    def _summary_for_revision(
        self,
        connection: sqlite3.Connection,
        revision: int,
    ) -> ExternalSummary | None:
        selected = connection.execute(
            "SELECT summary_version FROM epoch_revisions WHERE revision = ?",
            (revision,),
        ).fetchone()
        if selected is None:
            raise ExternalEpochRejected("epoch_revision_unavailable")
        if selected["summary_version"] is None:
            return None
        row = connection.execute(
            "SELECT * FROM committed_summaries WHERE summary_version = ?",
            (selected["summary_version"],),
        ).fetchone()
        if row is None:
            raise ExternalEpochRejected("epoch_summary_unavailable")
        return ExternalSummary(
            summary_version=row["summary_version"],
            covered_start=row["covered_start"],
            covered_end=row["covered_end"],
            covered_terminal_digest=row["covered_terminal_digest"],
            profile_revisions=tuple(json.loads(row["profile_revisions_json"])),
            content=row["content"],
            digest=row["summary_digest"],
        )

    def _reconstruct_summary_job(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> ExternalSummaryJob:
        prior = self._summary_for_revision(connection, row["base_revision"])
        first_sequence = 1 if prior is None else prior.covered_end + 1
        turn_rows = connection.execute(
            "SELECT * FROM committed_turns WHERE sequence BETWEEN ? AND ? ORDER BY sequence",
            (first_sequence, row["covered_end"]),
        ).fetchall()
        turns = tuple(
            ExternalTurn(
                sequence=item["sequence"],
                parent_digest=item["parent_digest"],
                digest=item["turn_digest"],
                user_message=item["user_message"],
                assistant_reply=item["assistant_reply"],
            )
            for item in turn_rows
        )
        revisions = set(() if prior is None else prior.profile_revisions)
        provenance_rows = connection.execute(
            "SELECT provenance_json FROM committed_turn_provenance WHERE sequence BETWEEN ? AND ? ORDER BY sequence",
            (first_sequence, row["covered_end"]),
        ).fetchall()
        if len(provenance_rows) != len(turns):
            raise ExternalEpochRejected("summary_job_provenance_unavailable")
        for item in provenance_rows:
            provenance = ExternalTurnProvenance.from_payload(
                json.loads(item["provenance_json"])
            )
            if "unknown" in provenance.sources:
                raise ExternalEpochRejected("summary_job_unknown_provenance")
            revisions.update(provenance.profile_revisions)
        job = ExternalSummaryJob.create(
            epoch_id=self.epoch_id,
            base_revision=row["base_revision"],
            summary_version=row["summary_version"],
            covered_end=row["covered_end"],
            covered_terminal_digest=row["covered_terminal_digest"],
            profile_revisions=tuple(sorted(revisions)),
            prior_summary=prior,
            turns=turns,
        )
        if row["job_digest"] and job.digest != row["job_digest"]:
            raise ExternalEpochRejected("summary_job_digest_drift")
        return job

    def _maybe_enqueue_summary_job(
        self,
        connection: sqlite3.Connection,
        *,
        base_revision: int,
        latest_turn: ExternalTurn,
    ) -> ExternalSummaryJob | None:
        if connection.execute(
            "SELECT 1 FROM summary_jobs WHERE status = 'pending' LIMIT 1"
        ).fetchone():
            raise ExternalEpochRejected("summary_job_cardinality_drift")
        prior = self._summary_for_revision(connection, base_revision)
        first_sequence = 1 if prior is None else prior.covered_end + 1
        rows = connection.execute(
            "SELECT user_message, assistant_reply FROM committed_turns WHERE sequence BETWEEN ? AND ? ORDER BY sequence",
            (first_sequence, latest_turn.sequence),
        ).fetchall()
        characters = sum(len(row["user_message"]) + len(row["assistant_reply"]) for row in rows)
        if len(rows) < ROLLING_SUMMARY_TRIGGER_TURNS and characters < ROLLING_SUMMARY_TRIGGER_CHARACTERS:
            return None
        placeholder = {
            "job_digest": "",
            "base_revision": base_revision,
            "summary_version": 1 if prior is None else prior.summary_version + 1,
            "covered_end": latest_turn.sequence,
            "covered_terminal_digest": latest_turn.digest,
        }
        # Reconstruct once with a temporary row-like mapping to derive the exact digest.
        job = self._reconstruct_summary_job(connection, placeholder)  # type: ignore[arg-type]
        now = _utc_now()
        connection.execute(
            """
            INSERT INTO summary_jobs (
                job_digest, base_revision, summary_version, covered_end,
                covered_terminal_digest, status, created_at
            ) VALUES (?, ?, ?, ?, ?, 'pending', ?)
            """,
            (
                job.digest,
                job.base_revision,
                job.summary_version,
                job.covered_end,
                job.covered_terminal_digest,
                now,
            ),
        )
        return job

    def commit_delivery(
        self,
        context: AuthenticatedConversationContext,
        token: PendingExternalTurn,
        assistant_reply: str,
        provenance: ExternalTurnProvenance,
    ) -> DeliveryCommitResult:
        self._verify_context(context)
        if (
            provenance.epoch_id != self.epoch_id
            or provenance.epoch_revision != token.base_revision
            or "unknown" in provenance.sources
        ):
            raise ExternalEpochRejected("delivery_provenance_binding_rejected")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = self._ensure_state(connection, context)
                pending = self._pending(connection, token)
                if (
                    state["selected_revision"] != token.base_revision
                    or state["max_revision"] != token.base_revision
                    or state["latest_sequence"] + 1 != token.sequence
                    or state["latest_digest"] != pending["parent_digest"]
                ):
                    raise ExternalEpochRejected("delivery_commit_prestate_drift")
                turn = ExternalTurn.create(
                    sequence=token.sequence,
                    parent_digest=pending["parent_digest"],
                    user_message=pending["current_message"],
                    assistant_reply=assistant_reply,
                )
                now = _utc_now()
                connection.execute(
                    "INSERT INTO committed_turns (sequence, parent_digest, turn_digest, user_message, assistant_reply, delivered_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (turn.sequence, turn.parent_digest, turn.digest, turn.user_message, turn.assistant_reply, now),
                )
                provenance_json = _canonical_json(provenance.as_payload())
                connection.execute(
                    "INSERT INTO committed_turn_provenance (sequence, provenance_json, provenance_digest) VALUES (?, ?, ?)",
                    (turn.sequence, provenance_json, _provenance_digest(provenance)),
                )
                previous_revision = connection.execute(
                    "SELECT summary_version FROM epoch_revisions WHERE revision = ?",
                    (token.base_revision,),
                ).fetchone()
                if previous_revision is None:
                    raise ExternalEpochRejected("epoch_revision_unavailable")
                new_revision = token.base_revision + 1
                connection.execute(
                    "INSERT INTO epoch_revisions (revision, selected_sequence, selected_digest, summary_version, created_at) VALUES (?, ?, ?, ?, ?)",
                    (new_revision, turn.sequence, turn.digest, previous_revision["summary_version"], now),
                )
                connection.execute(
                    "UPDATE epoch_state SET selected_revision = ?, max_revision = ?, latest_sequence = ?, latest_digest = ?, updated_at = ? WHERE singleton = 1",
                    (new_revision, new_revision, turn.sequence, turn.digest, now),
                )
                connection.execute("DELETE FROM pending_turns WHERE event_id = ?", (token.event_id,))
                summary_job = self._maybe_enqueue_summary_job(
                    connection,
                    base_revision=new_revision,
                    latest_turn=turn,
                )
            self._secure_paths()
            return DeliveryCommitResult(turn=turn, summary_job=summary_job)
        except ExternalEpochRejected:
            raise
        except (OSError, sqlite3.Error, ValueError):
            raise ExternalEpochRejected("delivery_commit_failed") from None

    def pending_summary_job(
        self,
        context: AuthenticatedConversationContext,
    ) -> ExternalSummaryJob | None:
        self._verify_context(context)
        try:
            with self._connect() as connection:
                state = self._ensure_state(connection, context)
                rows = connection.execute(
                    "SELECT * FROM summary_jobs WHERE status = 'pending' LIMIT 2"
                ).fetchall()
                if len(rows) > 1:
                    raise ExternalEpochRejected("summary_job_cardinality_drift")
                if not rows:
                    return None
                if (
                    state["selected_revision"] != state["max_revision"]
                    or state["selected_revision"] != rows[0]["base_revision"]
                ):
                    raise ExternalEpochRejected("summary_job_epoch_drift")
                return self._reconstruct_summary_job(connection, rows[0])
        except ExternalEpochRejected:
            raise
        except (OSError, sqlite3.Error, ValueError):
            raise ExternalEpochRejected("summary_job_load_failed") from None

    def commit_summary_candidate(
        self,
        context: AuthenticatedConversationContext,
        job: ExternalSummaryJob,
        candidate: ExternalSummaryCandidate,
    ) -> int:
        self._verify_context(context)
        summary = candidate.summary
        if (
            candidate.job_digest != job.digest
            or summary.summary_version != job.summary_version
            or summary.covered_start != job.covered_start
            or summary.covered_end != job.covered_end
            or summary.covered_terminal_digest != job.covered_terminal_digest
            or summary.profile_revisions != job.profile_revisions
        ):
            raise ExternalEpochRejected("summary_candidate_binding_rejected")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = self._ensure_state(connection, context)
                row = connection.execute(
                    "SELECT * FROM summary_jobs WHERE job_digest = ?",
                    (job.digest,),
                ).fetchone()
                if row is None:
                    raise ExternalEpochRejected("summary_job_unknown")
                if row["status"] == "committed":
                    if row["candidate_digest"] != summary.digest:
                        raise ExternalEpochRejected("summary_job_replay_mismatch")
                    return row["committed_revision"]
                reconstructed = self._reconstruct_summary_job(connection, row)
                if reconstructed != job:
                    raise ExternalEpochRejected("summary_job_digest_drift")
                if (
                    state["selected_revision"] != job.base_revision
                    or state["max_revision"] != job.base_revision
                    or connection.execute("SELECT 1 FROM pending_turns LIMIT 1").fetchone()
                ):
                    raise ExternalEpochRejected("summary_commit_prestate_drift")
                now = _utc_now()
                connection.execute(
                    "INSERT INTO committed_summaries (summary_version, covered_start, covered_end, covered_terminal_digest, profile_revisions_json, content, summary_digest, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (summary.summary_version, summary.covered_start, summary.covered_end,
                     summary.covered_terminal_digest, json.dumps(list(summary.profile_revisions), separators=(",", ":")),
                     summary.content, summary.digest, now),
                )
                new_revision = job.base_revision + 1
                connection.execute(
                    "INSERT INTO epoch_revisions (revision, selected_sequence, selected_digest, summary_version, created_at) VALUES (?, ?, ?, ?, ?)",
                    (new_revision, state["latest_sequence"], state["latest_digest"], summary.summary_version, now),
                )
                connection.execute(
                    "UPDATE epoch_state SET selected_revision = ?, max_revision = ?, updated_at = ? WHERE singleton = 1",
                    (new_revision, new_revision, now),
                )
                connection.execute(
                    "UPDATE summary_jobs SET status = 'committed', committed_revision = ?, candidate_digest = ?, committed_at = ? WHERE job_digest = ? AND status = 'pending'",
                    (new_revision, summary.digest, now, job.digest),
                )
            self._secure_paths()
            return new_revision
        except ExternalEpochRejected:
            raise
        except (OSError, sqlite3.Error, ValueError):
            raise ExternalEpochRejected("summary_commit_failed") from None

    def cancel_pending(
        self,
        context: AuthenticatedConversationContext,
        token: PendingExternalTurn,
    ) -> None:
        self._verify_context(context)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._ensure_state(connection, context)
                self._pending(connection, token)
                connection.execute(
                    "DELETE FROM pending_turns WHERE event_id = ?",
                    (token.event_id,),
                )
            self._secure_paths()
        except ExternalEpochRejected:
            raise
        except (OSError, sqlite3.Error):
            raise ExternalEpochRejected("pending_turn_cancel_failed") from None

    def discard_uncommitted_after_restart(
        self,
        context: AuthenticatedConversationContext,
    ) -> bool:
        """Explicitly discard one crash-left pending turn without projecting content."""

        self._verify_context(context)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._ensure_state(connection, context)
                row = connection.execute(
                    "SELECT event_id FROM pending_turns LIMIT 2"
                ).fetchall()
                if len(row) > 1:
                    raise ExternalEpochRejected("pending_turn_cardinality_drift")
                discarded = bool(row)
                if row:
                    connection.execute(
                        "DELETE FROM pending_turns WHERE event_id = ?",
                        (row[0]["event_id"],),
                    )
            self._secure_paths()
            return discarded
        except ExternalEpochRejected:
            raise
        except (OSError, sqlite3.Error):
            raise ExternalEpochRejected("pending_turn_recovery_failed") from None

    def discard_all_uncommitted_after_restart(self) -> bool:
        """Discard the single crash-left pending turn before accepting events."""

        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                rows = connection.execute(
                    "SELECT event_id FROM pending_turns LIMIT 2"
                ).fetchall()
                if len(rows) > 1:
                    raise ExternalEpochRejected("pending_turn_cardinality_drift")
                discarded = bool(rows)
                if rows:
                    connection.execute(
                        "DELETE FROM pending_turns WHERE event_id = ?",
                        (rows[0]["event_id"],),
                    )
            self._secure_paths()
            return discarded
        except ExternalEpochRejected:
            raise
        except (OSError, sqlite3.Error):
            raise ExternalEpochRejected("pending_turn_recovery_failed") from None

    def commit_summary(
        self,
        context: AuthenticatedConversationContext,
        summary: ExternalSummary,
    ) -> int:
        self._verify_context(context)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = self._ensure_state(connection, context)
                if state["selected_revision"] != state["max_revision"]:
                    raise ExternalEpochRejected("rollback_requires_new_epoch")
                if connection.execute("SELECT 1 FROM pending_turns LIMIT 1").fetchone():
                    raise ExternalEpochRejected("summary_commit_while_turn_pending")
                terminal = connection.execute(
                    "SELECT turn_digest FROM committed_turns WHERE sequence = ?",
                    (summary.covered_end,),
                ).fetchone()
                if (
                    terminal is None
                    or terminal["turn_digest"] != summary.covered_terminal_digest
                    or summary.covered_end > state["latest_sequence"]
                ):
                    raise ExternalEpochRejected("summary_range_digest_mismatch")
                latest_summary = connection.execute(
                    "SELECT MAX(summary_version) AS version FROM committed_summaries"
                ).fetchone()["version"]
                expected_version = 1 if latest_summary is None else latest_summary + 1
                if summary.summary_version != expected_version:
                    raise ExternalEpochRejected("summary_version_not_monotonic")
                now = _utc_now()
                connection.execute(
                    """
                    INSERT INTO committed_summaries (
                        summary_version, covered_start, covered_end,
                        covered_terminal_digest, profile_revisions_json,
                        content, summary_digest, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        summary.summary_version,
                        summary.covered_start,
                        summary.covered_end,
                        summary.covered_terminal_digest,
                        json.dumps(list(summary.profile_revisions), separators=(",", ":")),
                        summary.content,
                        summary.digest,
                        now,
                    ),
                )
                new_revision = state["max_revision"] + 1
                connection.execute(
                    """
                    INSERT INTO epoch_revisions (
                        revision, selected_sequence, selected_digest,
                        summary_version, created_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        new_revision,
                        state["latest_sequence"],
                        state["latest_digest"],
                        summary.summary_version,
                        now,
                    ),
                )
                connection.execute(
                    """
                    UPDATE epoch_state SET selected_revision = ?, max_revision = ?,
                        updated_at = ? WHERE singleton = 1
                    """,
                    (new_revision, new_revision, now),
                )
            self._secure_paths()
            return new_revision
        except ExternalEpochRejected:
            raise
        except (OSError, sqlite3.Error):
            raise ExternalEpochRejected("summary_commit_failed") from None

    def select_revision(
        self,
        context: AuthenticatedConversationContext,
        revision: int,
    ) -> None:
        self._verify_context(context)
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
            raise ExternalEpochRejected("rollback_revision_out_of_contract")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._ensure_state(connection, context)
                if connection.execute("SELECT 1 FROM pending_turns LIMIT 1").fetchone():
                    raise ExternalEpochRejected("rollback_while_turn_pending")
                if connection.execute(
                    "SELECT 1 FROM summary_jobs WHERE status = 'pending' LIMIT 1"
                ).fetchone():
                    raise ExternalEpochRejected("rollback_while_summary_pending")
                if connection.execute(
                    "SELECT 1 FROM epoch_revisions WHERE revision = ?", (revision,)
                ).fetchone() is None:
                    raise ExternalEpochRejected("rollback_revision_unknown")
                connection.execute(
                    """
                    UPDATE epoch_state SET selected_revision = ?, updated_at = ?
                    WHERE singleton = 1
                    """,
                    (revision, _utc_now()),
                )
            self._secure_paths()
        except ExternalEpochRejected:
            raise
        except (OSError, sqlite3.Error):
            raise ExternalEpochRejected("rollback_selector_update_failed") from None

    def public_metadata(self) -> dict[str, object]:
        try:
            with self._connect() as connection:
                state = self._state(connection)
                pending_count = connection.execute(
                    "SELECT COUNT(*) AS count FROM pending_turns"
                ).fetchone()["count"]
                turn_count = connection.execute(
                    "SELECT COUNT(*) AS count FROM committed_turns"
                ).fetchone()["count"]
                summary_count = connection.execute(
                    "SELECT COUNT(*) AS count FROM committed_summaries"
                ).fetchone()["count"]
                provenance_count = connection.execute(
                    "SELECT COUNT(*) AS count FROM committed_turn_provenance"
                ).fetchone()["count"]
                pending_summary_count = connection.execute(
                    "SELECT COUNT(*) AS count FROM summary_jobs WHERE status = 'pending'"
                ).fetchone()["count"]
            if state is None:
                metadata = {
                    "initialized": False,
                    "pending_count": pending_count,
                    "pending_summary_count": pending_summary_count,
                    "provenance_count": provenance_count,
                    "schema": SQLITE_SCHEMA,
                    "summary_count": summary_count,
                    "turn_count": turn_count,
                }
            else:
                metadata = {
                    "initialized": True,
                    "max_revision": state["max_revision"],
                    "pending_count": pending_count,
                    "pending_summary_count": pending_summary_count,
                    "provenance_count": provenance_count,
                    "schema": SQLITE_SCHEMA,
                    "selected_revision": state["selected_revision"],
                    "summary_count": summary_count,
                    "turn_count": turn_count,
                }
            self._secure_paths()
            return metadata
        except (OSError, sqlite3.Error):
            raise ExternalEpochRejected("epoch_metadata_unavailable") from None
