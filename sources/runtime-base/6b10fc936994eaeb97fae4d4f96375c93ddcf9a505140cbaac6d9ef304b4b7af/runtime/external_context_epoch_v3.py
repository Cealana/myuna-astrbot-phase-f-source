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
    ExternalSummary,
    ExternalTurn,
    ExternalTurnProvenance,
    VisualEvidence,
    current_message_digest,
)
from myuna_core.external_context.lifecycle_v3 import (
    ReleaseBoundExternalContext,
    ReleaseBoundSummaryCandidate,
    ReleaseBoundSummaryJob,
    ReleaseBoundTurnProvenance,
)


SQLITE_SCHEMA = "myuna.external-authorized-epoch.v3"
SQLITE_SCHEMA_VERSION = 3
SOFT_SUMMARY_TRIGGER_TURNS = 4
SOFT_SUMMARY_TRIGGER_CHARACTERS = 7_500
SUMMARY_JOB_TURN_LIMIT = 4
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_TOKEN = re.compile(r"^[0-9a-f]{64}$")


class ExternalEpochV3Rejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ExternalEpochV3Rejected(code)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _canonical(payload: Mapping[str, object]) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _digest(domain: bytes, payload: Mapping[str, object]) -> str:
    return sha256(domain + b"\0" + _canonical(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ExternalEpochV3Binding:
    channel_kind: str
    client_id: str
    principal_id: str
    namespace_id: str

    def __post_init__(self) -> None:
        _require(self.channel_kind == "astrbot_telegram", "epoch_v3_binding_rejected")
        _require(self.client_id == "telegram-owner-private", "epoch_v3_binding_rejected")
        for value in (self.principal_id, self.namespace_id):
            _require(_SAFE_ID.fullmatch(value) is not None, "epoch_v3_binding_rejected")


@dataclass(frozen=True, slots=True)
class PendingTurnV3:
    event_id: str
    request_id: str
    base_revision: int
    sequence: int
    current_message_digest: str


@dataclass(frozen=True, slots=True)
class DeliveryResolutionV3:
    status: str
    committed_revision: int | None
    summary_job_queued: bool
    replayed: bool


@dataclass(frozen=True, slots=True)
class StartupRecoveryV3:
    abandoned_deliveries: int
    discarded_unprepared_turns: int
    requeued_summary_jobs: int
    blocked_summary_jobs: int


MAX_SUMMARY_ATTEMPTS = 3


_TABLES = (
    """CREATE TABLE epoch_state (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        schema_name TEXT NOT NULL,
        schema_version INTEGER NOT NULL,
        epoch_id TEXT NOT NULL,
        release_set_id TEXT NOT NULL,
        channel_kind TEXT NOT NULL,
        principal_id TEXT NOT NULL,
        namespace_id TEXT NOT NULL,
        selected_revision INTEGER NOT NULL,
        max_revision INTEGER NOT NULL,
        latest_sequence INTEGER NOT NULL,
        latest_digest TEXT NOT NULL,
        active_summary_version INTEGER,
        updated_at TEXT NOT NULL
    )""",
    """CREATE TABLE epoch_revisions (
        revision INTEGER PRIMARY KEY,
        selected_sequence INTEGER NOT NULL,
        selected_digest TEXT NOT NULL,
        summary_version INTEGER,
        created_at TEXT NOT NULL
    )""",
    """CREATE TABLE committed_turns (
        sequence INTEGER PRIMARY KEY,
        parent_digest TEXT NOT NULL,
        turn_digest TEXT NOT NULL UNIQUE,
        user_message TEXT NOT NULL,
        assistant_reply TEXT NOT NULL,
        delivered_at TEXT NOT NULL
    )""",
    """CREATE TABLE committed_turn_provenance (
        sequence INTEGER PRIMARY KEY,
        provenance_json TEXT NOT NULL,
        provenance_digest TEXT NOT NULL UNIQUE,
        FOREIGN KEY(sequence) REFERENCES committed_turns(sequence)
    )""",
    """CREATE TABLE committed_summaries (
        summary_version INTEGER PRIMARY KEY,
        covered_start INTEGER NOT NULL,
        covered_end INTEGER NOT NULL,
        covered_terminal_digest TEXT NOT NULL,
        profile_revisions_json TEXT NOT NULL,
        content TEXT NOT NULL,
        summary_digest TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL
    )""",
    """CREATE TABLE pending_turns (
        event_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE,
        base_revision INTEGER NOT NULL,
        sequence INTEGER NOT NULL,
        parent_digest TEXT NOT NULL,
        current_message TEXT NOT NULL,
        current_message_digest TEXT NOT NULL,
        safety_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""",
    """CREATE TABLE delivery_intents (
        delivery_token TEXT PRIMARY KEY,
        event_id TEXT NOT NULL UNIQUE,
        request_id TEXT NOT NULL UNIQUE,
        base_revision INTEGER NOT NULL,
        sequence INTEGER NOT NULL,
        assistant_reply TEXT NOT NULL,
        reply_digest TEXT NOT NULL,
        provenance_json TEXT NOT NULL,
        provenance_digest TEXT NOT NULL,
        prepared_at TEXT NOT NULL
    )""",
    """CREATE TABLE delivery_receipts (
        delivery_token TEXT PRIMARY KEY,
        event_id TEXT NOT NULL UNIQUE,
        outcome TEXT NOT NULL CHECK(outcome IN ('delivered','cancelled','abandoned')),
        committed_revision INTEGER,
        reply_digest TEXT NOT NULL,
        provenance_digest TEXT NOT NULL,
        resolved_at TEXT NOT NULL
    )""",
    """CREATE TABLE summary_jobs (
        job_digest TEXT PRIMARY KEY,
        release_set_id TEXT NOT NULL,
        base_revision INTEGER NOT NULL,
        summary_version INTEGER NOT NULL UNIQUE,
        covered_start INTEGER NOT NULL,
        covered_end INTEGER NOT NULL,
        covered_terminal_digest TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('queued','leased','committed','blocked')),
        lease_owner TEXT,
        attempt_count INTEGER NOT NULL CHECK(attempt_count >= 0),
        candidate_digest TEXT,
        committed_revision INTEGER,
        created_at TEXT NOT NULL,
        committed_at TEXT,
        CHECK((status = 'leased' AND lease_owner IS NOT NULL) OR (status != 'leased' AND lease_owner IS NULL))
    )""",
)

_EXPECTED_TABLES = {
    "epoch_state",
    "epoch_revisions",
    "committed_turns",
    "committed_turn_provenance",
    "committed_summaries",
    "pending_turns",
    "delivery_intents",
    "delivery_receipts",
    "summary_jobs",
}

_EXPECTED_COLUMNS = {
    "epoch_state": (
        "singleton", "schema_name", "schema_version", "epoch_id",
        "release_set_id", "channel_kind", "principal_id", "namespace_id",
        "selected_revision", "max_revision", "latest_sequence",
        "latest_digest", "active_summary_version", "updated_at",
    ),
    "epoch_revisions": (
        "revision", "selected_sequence", "selected_digest", "summary_version",
        "created_at",
    ),
    "committed_turns": (
        "sequence", "parent_digest", "turn_digest", "user_message",
        "assistant_reply", "delivered_at",
    ),
    "committed_turn_provenance": (
        "sequence", "provenance_json", "provenance_digest",
    ),
    "committed_summaries": (
        "summary_version", "covered_start", "covered_end",
        "covered_terminal_digest", "profile_revisions_json", "content",
        "summary_digest", "created_at",
    ),
    "pending_turns": (
        "event_id", "request_id", "base_revision", "sequence", "parent_digest",
        "current_message", "current_message_digest", "safety_json", "created_at",
    ),
    "delivery_intents": (
        "delivery_token", "event_id", "request_id", "base_revision", "sequence",
        "assistant_reply", "reply_digest", "provenance_json", "provenance_digest",
        "prepared_at",
    ),
    "delivery_receipts": (
        "delivery_token", "event_id", "outcome", "committed_revision",
        "reply_digest", "provenance_digest", "resolved_at",
    ),
    "summary_jobs": (
        "job_digest", "release_set_id", "base_revision", "summary_version",
        "covered_start", "covered_end", "covered_terminal_digest", "status",
        "lease_owner", "attempt_count", "candidate_digest", "committed_revision",
        "created_at", "committed_at",
    ),
}


def verify_epoch_v3_schema(connection: sqlite3.Connection) -> None:
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    _require(tables == _EXPECTED_TABLES, "epoch_v3_schema_rejected")
    _require(connection.execute("PRAGMA user_version").fetchone()[0] == SQLITE_SCHEMA_VERSION, "epoch_v3_schema_version_rejected")
    for table, expected in _EXPECTED_COLUMNS.items():
        actual = tuple(row[1] for row in connection.execute(f"PRAGMA table_info({table})"))
        _require(actual == expected, "epoch_v3_columns_rejected")


class ExternalEpochV3Store:
    def __init__(
        self,
        database_path: str | Path,
        *,
        epoch_id: str,
        release_set_id: str,
        binding: ExternalEpochV3Binding,
        expected_uid: int | None = None,
        expected_gid: int | None = None,
    ) -> None:
        self.database_path = Path(database_path)
        _require(self.database_path.is_absolute(), "epoch_v3_path_rejected")
        _require(_SAFE_ID.fullmatch(epoch_id) is not None, "epoch_v3_id_rejected")
        _require(_TOKEN.fullmatch(release_set_id) is not None, "epoch_v3_release_set_rejected")
        self.epoch_id = epoch_id
        self.release_set_id = release_set_id
        self.binding = binding
        self.expected_uid = os.geteuid() if expected_uid is None else expected_uid
        self.expected_gid = os.getegid() if expected_gid is None else expected_gid
        self._initialize()

    @classmethod
    def inspect_existing_metadata(
        cls,
        database_path: str | Path,
        *,
        epoch_id: str,
        release_set_id: str,
        binding: ExternalEpochV3Binding,
        expected_uid: int,
        expected_gid: int,
    ) -> dict[str, object]:
        """Inspect an existing epoch through the strict query-only path."""
        store = object.__new__(cls)
        store.database_path = Path(database_path)
        _require(store.database_path.is_absolute(), "epoch_v3_path_rejected")
        _require(_SAFE_ID.fullmatch(epoch_id) is not None, "epoch_v3_id_rejected")
        _require(_TOKEN.fullmatch(release_set_id) is not None, "epoch_v3_release_set_rejected")
        store.epoch_id = epoch_id
        store.release_set_id = release_set_id
        store.binding = binding
        store.expected_uid = expected_uid
        store.expected_gid = expected_gid
        return store.public_metadata()

    def _verify_paths(self) -> None:
        parent = self.database_path.parent
        _require(not parent.is_symlink() and parent.is_dir(), "epoch_v3_parent_type_rejected")
        metadata = parent.stat()
        _require(
            metadata.st_uid == self.expected_uid
            and metadata.st_gid == self.expected_gid
            and stat.S_IMODE(metadata.st_mode) == 0o700,
            "epoch_v3_permission_drift",
        )
        for path in (self.database_path, Path(f"{self.database_path}-wal"), Path(f"{self.database_path}-shm")):
            if not path.exists() and not path.is_symlink():
                continue
            _require(not path.is_symlink() and path.is_file(), "epoch_v3_file_type_rejected")
            item = path.stat()
            _require(
                item.st_uid == self.expected_uid
                and item.st_gid == self.expected_gid
                and stat.S_IMODE(item.st_mode) == 0o600,
                "epoch_v3_permission_drift",
            )

    def _secure_paths(self) -> None:
        os.chmod(self.database_path.parent, 0o700)
        for path in (self.database_path, Path(f"{self.database_path}-wal"), Path(f"{self.database_path}-shm")):
            if path.exists():
                _require(not path.is_symlink() and path.is_file(), "epoch_v3_file_type_rejected")
                os.chmod(path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        self._verify_paths()
        connection = sqlite3.connect(self.database_path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _connect_query_only(self) -> sqlite3.Connection:
        self._verify_paths()
        connection = sqlite3.connect(
            self.database_path.as_uri() + "?mode=ro",
            uri=True,
            timeout=5.0,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        parent = self.database_path.parent
        _require(not parent.is_symlink(), "epoch_v3_parent_type_rejected")
        if parent.exists():
            _require(parent.is_dir(), "epoch_v3_parent_type_rejected")
        else:
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = parent.stat()
        _require(
            metadata.st_uid == self.expected_uid
            and metadata.st_gid == self.expected_gid
            and stat.S_IMODE(metadata.st_mode) == 0o700,
            "epoch_v3_permission_drift",
        )
        if self.database_path.exists() and self.database_path.stat().st_size > 0:
            self._verify_existing_read_only()
        try:
            fd = os.open(self.database_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        self._secure_paths()
        try:
            connection = sqlite3.connect(self.database_path, timeout=5.0, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("BEGIN IMMEDIATE")
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            if not tables:
                for definition in _TABLES:
                    connection.execute(definition)
                connection.execute(f"PRAGMA user_version = {SQLITE_SCHEMA_VERSION}")
                now = _utc_now()
                connection.execute(
                    "INSERT INTO epoch_state VALUES (1,?,?,?,?,?,?,?,0,0,0,?,NULL,?)",
                    (
                        SQLITE_SCHEMA,
                        SQLITE_SCHEMA_VERSION,
                        self.epoch_id,
                        self.release_set_id,
                        self.binding.channel_kind,
                        self.binding.principal_id,
                        self.binding.namespace_id,
                        ZERO_DIGEST,
                        now,
                    ),
                )
                connection.execute(
                    "INSERT INTO epoch_revisions VALUES (0,0,?,NULL,?)",
                    (ZERO_DIGEST, now),
                )
            verify_epoch_v3_schema(connection)
            self._verify_state(connection)
            connection.execute("COMMIT")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.close()
            self._secure_paths()
            self._verify_paths()
        except ExternalEpochV3Rejected:
            raise
        except (OSError, sqlite3.Error):
            raise ExternalEpochV3Rejected("epoch_v3_initialization_failed") from None

    def _verify_existing_read_only(self) -> None:
        self._verify_paths()
        uri = self.database_path.as_uri() + "?mode=ro"
        try:
            with sqlite3.connect(uri, uri=True, timeout=5.0) as connection:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA query_only = ON")
                verify_epoch_v3_schema(connection)
                self._verify_state(connection)
        except ExternalEpochV3Rejected:
            raise
        except sqlite3.Error:
            raise ExternalEpochV3Rejected("epoch_v3_existing_database_rejected") from None

    def _verify_state(self, connection: sqlite3.Connection) -> sqlite3.Row:
        rows = connection.execute("SELECT * FROM epoch_state LIMIT 2").fetchall()
        _require(len(rows) == 1, "epoch_v3_state_cardinality_rejected")
        state = rows[0]
        _require(
            state["schema_name"] == SQLITE_SCHEMA
            and state["schema_version"] == SQLITE_SCHEMA_VERSION
            and state["epoch_id"] == self.epoch_id
            and state["release_set_id"] == self.release_set_id,
            "epoch_v3_state_identity_rejected",
        )
        _require(
            state["channel_kind"] == self.binding.channel_kind
            and state["principal_id"] == self.binding.principal_id
            and state["namespace_id"] == self.binding.namespace_id,
            "epoch_v3_state_binding_rejected",
        )
        return state

    @staticmethod
    def _verify_context(context: AuthenticatedConversationContext) -> None:
        _require(
            context.channel_kind == "astrbot_telegram"
            and context.client_id == "telegram-owner-private"
            and context.authority_level == "owner"
            and context.conversation_kind == "private",
            "epoch_v3_owner_scope_rejected",
        )

    def _state(self, connection: sqlite3.Connection) -> sqlite3.Row:
        return self._verify_state(connection)

    def _pending(self, connection: sqlite3.Connection, token: PendingTurnV3) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM pending_turns WHERE event_id = ?", (token.event_id,)).fetchone()
        _require(
            row is not None
            and row["request_id"] == token.request_id
            and row["base_revision"] == token.base_revision
            and row["sequence"] == token.sequence
            and row["current_message_digest"] == token.current_message_digest,
            "epoch_v3_pending_token_rejected",
        )
        return row

    def _active_summary(self, connection: sqlite3.Connection, state: sqlite3.Row) -> ExternalSummary | None:
        version = state["active_summary_version"]
        if version is None:
            return None
        row = connection.execute("SELECT * FROM committed_summaries WHERE summary_version = ?", (version,)).fetchone()
        _require(row is not None, "epoch_v3_summary_unavailable")
        return ExternalSummary(
            summary_version=row["summary_version"],
            covered_start=row["covered_start"],
            covered_end=row["covered_end"],
            covered_terminal_digest=row["covered_terminal_digest"],
            profile_revisions=tuple(json.loads(row["profile_revisions_json"])),
            content=row["content"],
            digest=row["summary_digest"],
        )

    def begin_turn(
        self,
        context: AuthenticatedConversationContext,
        current_message: str,
        safety: EgressSafetySignals,
    ) -> PendingTurnV3:
        self._verify_context(context)
        digest = current_message_digest(context, current_message)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = self._state(connection)
                _require(state["selected_revision"] == state["max_revision"], "epoch_v3_revision_drift")
                _require(connection.execute("SELECT COUNT(*) FROM pending_turns").fetchone()[0] == 0, "epoch_v3_turn_pending")
                _require(connection.execute("SELECT COUNT(*) FROM delivery_intents").fetchone()[0] == 0, "epoch_v3_delivery_pending")
                sequence = state["latest_sequence"] + 1
                connection.execute(
                    "INSERT INTO pending_turns VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        context.event_id,
                        context.request_id,
                        state["selected_revision"],
                        sequence,
                        state["latest_digest"],
                        current_message,
                        digest,
                        _canonical(safety.as_payload()),
                        _utc_now(),
                    ),
                )
                connection.execute("COMMIT")
            self._secure_paths()
            return PendingTurnV3(context.event_id, context.request_id, state["selected_revision"], sequence, digest)
        except ExternalEpochV3Rejected:
            raise
        except (sqlite3.Error, OSError):
            raise ExternalEpochV3Rejected("epoch_v3_begin_turn_failed") from None

    def context_payload(
        self,
        context: AuthenticatedConversationContext,
        token: PendingTurnV3,
        *,
        visual_event: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        self._verify_context(context)
        try:
            with self._connect() as connection:
                state = self._state(connection)
                pending = self._pending(connection, token)
                summary = self._active_summary(connection, state)
                first = 1 if summary is None else summary.covered_end + 1
                rows = connection.execute(
                    "SELECT * FROM committed_turns WHERE sequence BETWEEN ? AND ? ORDER BY sequence",
                    (first, state["latest_sequence"]),
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
                _require(
                    len(turns) <= MAX_RECENT_TURNS
                    and sum(len(item.user_message) + len(item.assistant_reply) for item in turns) <= MAX_RECENT_CHARACTERS,
                    "external_summary_backpressure",
                )
                visual_evidence = None
                if visual_event is not None:
                    _require(
                        set(visual_event)
                        == {"caption_present", "observation", "schema", "source"}
                        and visual_event["schema"] == "myuna.telegram-visual-evidence.v1"
                        and visual_event["source"] == "gemini_visual_extraction",
                        "epoch_v3_visual_event_rejected",
                    )
                    visual_evidence = VisualEvidence.create(
                        context=context,
                        current_message=pending["current_message"],
                        observation=visual_event["observation"],
                        caption_present=visual_event["caption_present"],
                    )
                envelope = ExternalContextEnvelope(
                    epoch_id=self.epoch_id,
                    epoch_revision=state["selected_revision"],
                    turn_sequence=state["latest_sequence"],
                    parent_digest=state["latest_digest"],
                    channel_kind=context.channel_kind,
                    principal_id=context.principal_id,
                    namespace_id=context.namespace_id,
                    current_message=pending["current_message"],
                    current_message_digest=pending["current_message_digest"],
                    summary=summary,
                    recent_turns=turns,
                    safety=EgressSafetySignals.from_payload(json.loads(pending["safety_json"])),
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
            return ReleaseBoundExternalContext(self.release_set_id, envelope).as_payload()
        except ExternalEpochV3Rejected:
            raise
        except (sqlite3.Error, OSError, ValueError, TypeError):
            raise ExternalEpochV3Rejected("epoch_v3_context_load_failed") from None

    def cancel_pending(
        self,
        context: AuthenticatedConversationContext,
        token: PendingTurnV3,
    ) -> None:
        self._verify_context(context)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._state(connection)
                self._pending(connection, token)
                prepared = connection.execute(
                    "SELECT 1 FROM delivery_intents WHERE event_id=? LIMIT 1",
                    (token.event_id,),
                ).fetchone()
                _require(prepared is None, "epoch_v3_delivery_already_prepared")
                connection.execute(
                    "DELETE FROM pending_turns WHERE event_id=?",
                    (token.event_id,),
                )
                connection.execute("COMMIT")
            self._secure_paths()
        except ExternalEpochV3Rejected:
            raise
        except (sqlite3.Error, OSError):
            raise ExternalEpochV3Rejected("epoch_v3_pending_cancel_failed") from None

    def prepare_delivery(
        self,
        context: AuthenticatedConversationContext,
        token: PendingTurnV3,
        *,
        delivery_token: str,
        assistant_reply: str,
        provenance: ReleaseBoundTurnProvenance,
    ) -> None:
        self._verify_context(context)
        _require(_TOKEN.fullmatch(delivery_token) is not None, "epoch_v3_delivery_token_rejected")
        _require(provenance.release_set_id == self.release_set_id, "epoch_v3_provenance_release_set_rejected")
        _require(
            provenance.provenance.epoch_id == self.epoch_id
            and provenance.provenance.epoch_revision == token.base_revision
            and "unknown" not in provenance.provenance.sources,
            "epoch_v3_provenance_binding_rejected",
        )
        provenance_json = _canonical(provenance.as_payload())
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._state(connection)
                self._pending(connection, token)
                existing = connection.execute("SELECT * FROM delivery_intents WHERE delivery_token = ?", (delivery_token,)).fetchone()
                if existing is not None:
                    _require(
                        existing["event_id"] == token.event_id
                        and existing["assistant_reply"] == assistant_reply
                        and existing["provenance_json"] == provenance_json,
                        "epoch_v3_delivery_prepare_replay_mismatch",
                    )
                    connection.execute("COMMIT")
                    return
                connection.execute(
                    "INSERT INTO delivery_intents VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        delivery_token,
                        token.event_id,
                        token.request_id,
                        token.base_revision,
                        token.sequence,
                        assistant_reply,
                        sha256(assistant_reply.encode("utf-8")).hexdigest(),
                        provenance_json,
                        _digest(b"myuna-p07-d-provenance-v2", provenance.as_payload()),
                        _utc_now(),
                    ),
                )
                connection.execute("COMMIT")
            self._secure_paths()
        except ExternalEpochV3Rejected:
            raise
        except (sqlite3.Error, OSError):
            raise ExternalEpochV3Rejected("epoch_v3_delivery_prepare_failed") from None

    def _provenance_profile_revisions(self, connection: sqlite3.Connection, start: int, end: int) -> tuple[int, ...]:
        revisions: set[int] = set()
        rows = connection.execute(
            "SELECT provenance_json FROM committed_turn_provenance WHERE sequence BETWEEN ? AND ? ORDER BY sequence",
            (start, end),
        ).fetchall()
        _require(len(rows) == end - start + 1, "epoch_v3_summary_provenance_unavailable")
        for row in rows:
            provenance = ReleaseBoundTurnProvenance.from_payload(json.loads(row["provenance_json"]))
            _require(provenance.release_set_id == self.release_set_id, "epoch_v3_summary_release_set_drift")
            _require("unknown" not in provenance.provenance.sources, "epoch_v3_summary_unknown_provenance")
            revisions.update(provenance.provenance.profile_revisions)
        return tuple(sorted(revisions))

    def _build_job(self, connection: sqlite3.Connection, row: sqlite3.Row | Mapping[str, object]) -> ReleaseBoundSummaryJob:
        state = self._state(connection)
        prior = self._active_summary(connection, state)
        first = 1 if prior is None else prior.covered_end + 1
        turns = tuple(
            ExternalTurn(
                sequence=item["sequence"],
                parent_digest=item["parent_digest"],
                digest=item["turn_digest"],
                user_message=item["user_message"],
                assistant_reply=item["assistant_reply"],
            )
            for item in connection.execute(
                "SELECT * FROM committed_turns WHERE sequence BETWEEN ? AND ? ORDER BY sequence",
                (first, row["covered_end"]),
            ).fetchall()
        )
        revisions = set(() if prior is None else prior.profile_revisions)
        revisions.update(self._provenance_profile_revisions(connection, first, row["covered_end"]))
        job = ReleaseBoundSummaryJob.create(
            release_set_id=self.release_set_id,
            epoch_id=self.epoch_id,
            base_revision=row["base_revision"],
            summary_version=row["summary_version"],
            covered_end=row["covered_end"],
            covered_terminal_digest=row["covered_terminal_digest"],
            profile_revisions=tuple(sorted(revisions)),
            prior_summary=prior,
            turns=turns,
        )
        if row.get("job_digest") if isinstance(row, dict) else row["job_digest"]:
            _require(job.digest == row["job_digest"], "epoch_v3_summary_job_digest_drift")
        return job

    def _maybe_queue_summary(self, connection: sqlite3.Connection, *, base_revision: int) -> bool:
        if connection.execute("SELECT 1 FROM summary_jobs WHERE status IN ('queued','leased','blocked') LIMIT 1").fetchone():
            return False
        state = self._state(connection)
        summary = self._active_summary(connection, state)
        first = 1 if summary is None else summary.covered_end + 1
        rows = connection.execute(
            "SELECT * FROM committed_turns WHERE sequence BETWEEN ? AND ? ORDER BY sequence",
            (first, state["latest_sequence"]),
        ).fetchall()
        characters = sum(len(row["user_message"]) + len(row["assistant_reply"]) for row in rows)
        if len(rows) < SOFT_SUMMARY_TRIGGER_TURNS and characters < SOFT_SUMMARY_TRIGGER_CHARACTERS:
            return False
        selected = rows[:SUMMARY_JOB_TURN_LIMIT]
        _require(bool(selected), "epoch_v3_summary_job_empty")
        covered_end = selected[-1]["sequence"]
        placeholder: dict[str, object] = {
            "job_digest": "",
            "base_revision": base_revision,
            "summary_version": 1 if summary is None else summary.summary_version + 1,
            "covered_end": covered_end,
            "covered_terminal_digest": selected[-1]["turn_digest"],
        }
        job = self._build_job(connection, placeholder)
        connection.execute(
            "INSERT INTO summary_jobs VALUES (?,?,?,?,?,?,?,'queued',NULL,0,NULL,NULL,?,NULL)",
            (
                job.digest,
                self.release_set_id,
                job.job.base_revision,
                job.job.summary_version,
                job.job.covered_start,
                job.job.covered_end,
                job.job.covered_terminal_digest,
                _utc_now(),
            ),
        )
        return True

    def resolve_delivery(self, *, delivery_token: str, outcome: str) -> DeliveryResolutionV3:
        _require(_TOKEN.fullmatch(delivery_token) is not None, "epoch_v3_delivery_token_rejected")
        _require(outcome in {"delivered", "cancelled"}, "epoch_v3_delivery_outcome_rejected")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = self._state(connection)
                receipt = connection.execute(
                    "SELECT * FROM delivery_receipts WHERE delivery_token = ?",
                    (delivery_token,),
                ).fetchone()
                if receipt is not None:
                    if receipt["outcome"] == outcome:
                        connection.execute("COMMIT")
                        return DeliveryResolutionV3(
                            outcome,
                            receipt["committed_revision"],
                            False,
                            True,
                        )
                    raise ExternalEpochV3Rejected("epoch_v3_delivery_outcome_conflict")
                intent = connection.execute("SELECT * FROM delivery_intents WHERE delivery_token = ?", (delivery_token,)).fetchone()
                _require(intent is not None, "epoch_v3_delivery_unknown")
                pending = connection.execute("SELECT * FROM pending_turns WHERE event_id = ?", (intent["event_id"],)).fetchone()
                _require(pending is not None, "epoch_v3_delivery_pending_unavailable")
                queued = False
                committed_revision = None
                if outcome == "delivered":
                    _require(
                        state["selected_revision"] == state["max_revision"] == intent["base_revision"]
                        and state["latest_sequence"] + 1 == intent["sequence"]
                        and state["latest_digest"] == pending["parent_digest"],
                        "epoch_v3_delivery_prestate_drift",
                    )
                    provenance = ReleaseBoundTurnProvenance.from_payload(json.loads(intent["provenance_json"]))
                    _require(provenance.release_set_id == self.release_set_id, "epoch_v3_provenance_release_set_rejected")
                    turn = ExternalTurn.create(
                        sequence=intent["sequence"],
                        parent_digest=pending["parent_digest"],
                        user_message=pending["current_message"],
                        assistant_reply=intent["assistant_reply"],
                    )
                    now = _utc_now()
                    connection.execute(
                        "INSERT INTO committed_turns VALUES (?,?,?,?,?,?)",
                        (turn.sequence, turn.parent_digest, turn.digest, turn.user_message, turn.assistant_reply, now),
                    )
                    connection.execute(
                        "INSERT INTO committed_turn_provenance VALUES (?,?,?)",
                        (turn.sequence, intent["provenance_json"], intent["provenance_digest"]),
                    )
                    committed_revision = state["max_revision"] + 1
                    connection.execute(
                        "INSERT INTO epoch_revisions VALUES (?,?,?,?,?)",
                        (committed_revision, turn.sequence, turn.digest, state["active_summary_version"], now),
                    )
                    connection.execute(
                        "UPDATE epoch_state SET selected_revision=?,max_revision=?,latest_sequence=?,latest_digest=?,updated_at=? WHERE singleton=1",
                        (committed_revision, committed_revision, turn.sequence, turn.digest, now),
                    )
                    queued = self._maybe_queue_summary(connection, base_revision=committed_revision)
                now = _utc_now()
                connection.execute(
                    "INSERT INTO delivery_receipts VALUES (?,?,?,?,?,?,?)",
                    (
                        delivery_token,
                        intent["event_id"],
                        outcome,
                        committed_revision,
                        intent["reply_digest"],
                        intent["provenance_digest"],
                        now,
                    ),
                )
                connection.execute("DELETE FROM pending_turns WHERE event_id=?", (intent["event_id"],))
                connection.execute("DELETE FROM delivery_intents WHERE delivery_token=?", (delivery_token,))
                connection.execute("COMMIT")
            self._secure_paths()
            return DeliveryResolutionV3(outcome, committed_revision, queued, False)
        except ExternalEpochV3Rejected:
            raise
        except (sqlite3.Error, OSError, ValueError, TypeError):
            raise ExternalEpochV3Rejected("epoch_v3_delivery_resolution_failed") from None

    def startup_recover(self) -> StartupRecoveryV3:
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._state(connection)
                awaiting = connection.execute(
                    "SELECT delivery_token,event_id,reply_digest,provenance_digest FROM delivery_intents"
                ).fetchall()
                for row in awaiting:
                    connection.execute(
                        "INSERT INTO delivery_receipts VALUES (?,?,\'abandoned\',NULL,?,?,?)",
                        (
                            row["delivery_token"],
                            row["event_id"],
                            row["reply_digest"],
                            row["provenance_digest"],
                            _utc_now(),
                        ),
                    )
                    connection.execute("DELETE FROM pending_turns WHERE event_id=?", (row["event_id"],))
                    connection.execute("DELETE FROM delivery_intents WHERE event_id=?", (row["event_id"],))
                bare = connection.execute(
                    "SELECT event_id FROM pending_turns WHERE event_id NOT IN (SELECT event_id FROM delivery_intents)"
                ).fetchall()
                for row in bare:
                    connection.execute("DELETE FROM pending_turns WHERE event_id=?", (row["event_id"],))
                leased_rows = connection.execute(
                    "SELECT attempt_count FROM summary_jobs WHERE status='leased'"
                ).fetchall()
                requeued = sum(row["attempt_count"] < MAX_SUMMARY_ATTEMPTS for row in leased_rows)
                blocked = len(leased_rows) - requeued
                connection.execute(
                    "UPDATE summary_jobs SET status=CASE WHEN attempt_count >= ? THEN 'blocked' ELSE 'queued' END,"
                    "lease_owner=NULL WHERE status='leased'",
                    (MAX_SUMMARY_ATTEMPTS,),
                )
                connection.execute("COMMIT")
            self._secure_paths()
            return StartupRecoveryV3(len(awaiting), len(bare), requeued, blocked)
        except (sqlite3.Error, OSError):
            raise ExternalEpochV3Rejected("epoch_v3_startup_recovery_failed") from None

    def acquire_summary_job(self, *, worker_id: str) -> ReleaseBoundSummaryJob | None:
        _require(_SAFE_ID.fullmatch(worker_id) is not None, "epoch_v3_worker_id_rejected")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._state(connection)
                existing = connection.execute("SELECT * FROM summary_jobs WHERE status='leased' LIMIT 2").fetchall()
                _require(len(existing) <= 1, "epoch_v3_summary_lease_cardinality")
                if existing:
                    _require(existing[0]["lease_owner"] == worker_id, "epoch_v3_summary_lease_busy")
                    job = self._build_job(connection, existing[0])
                    connection.execute("COMMIT")
                    return job
                row = connection.execute("SELECT * FROM summary_jobs WHERE status='queued' ORDER BY summary_version LIMIT 1").fetchone()
                if row is None:
                    connection.execute("COMMIT")
                    return None
                connection.execute(
                    "UPDATE summary_jobs SET status='leased',lease_owner=?,attempt_count=attempt_count+1 WHERE job_digest=? AND status='queued'",
                    (worker_id, row["job_digest"]),
                )
                leased = connection.execute("SELECT * FROM summary_jobs WHERE job_digest=?", (row["job_digest"],)).fetchone()
                job = self._build_job(connection, leased)
                connection.execute("COMMIT")
                return job
        except ExternalEpochV3Rejected:
            raise
        except (sqlite3.Error, OSError, ValueError, TypeError):
            raise ExternalEpochV3Rejected("epoch_v3_summary_acquire_failed") from None

    def record_summary_failure(self, *, worker_id: str, job_digest: str) -> bool:
        _require(_SAFE_ID.fullmatch(worker_id) is not None, "epoch_v3_worker_id_rejected")
        _require(_TOKEN.fullmatch(job_digest) is not None, "epoch_v3_summary_job_digest_rejected")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT attempt_count FROM summary_jobs WHERE job_digest=? AND status='leased' AND lease_owner=?",
                    (job_digest, worker_id),
                ).fetchone()
                _require(row is not None, "epoch_v3_summary_lease_mismatch")
                retryable = row["attempt_count"] < MAX_SUMMARY_ATTEMPTS
                connection.execute(
                    "UPDATE summary_jobs SET status=?,lease_owner=NULL WHERE job_digest=? AND status='leased' AND lease_owner=?",
                    ("queued" if retryable else "blocked", job_digest, worker_id),
                )
                connection.execute("COMMIT")
                return retryable
        except ExternalEpochV3Rejected:
            raise
        except sqlite3.Error:
            raise ExternalEpochV3Rejected("epoch_v3_summary_failure_record_failed") from None

    def commit_summary_candidate(
        self,
        *,
        worker_id: str,
        job: ReleaseBoundSummaryJob,
        candidate: ReleaseBoundSummaryCandidate,
    ) -> int:
        _require(_SAFE_ID.fullmatch(worker_id) is not None, "epoch_v3_worker_id_rejected")
        _require(job.release_set_id == self.release_set_id, "epoch_v3_summary_release_set_drift")
        candidate.validate_for(job)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = self._state(connection)
                row = connection.execute("SELECT * FROM summary_jobs WHERE job_digest=?", (job.digest,)).fetchone()
                _require(row is not None, "epoch_v3_summary_job_unknown")
                if row["status"] == "committed":
                    _require(row["candidate_digest"] == candidate.summary.digest, "epoch_v3_summary_replay_mismatch")
                    connection.execute("COMMIT")
                    return row["committed_revision"]
                _require(row["status"] == "leased" and row["lease_owner"] == worker_id, "epoch_v3_summary_lease_mismatch")
                reconstructed = self._build_job(connection, row)
                _require(reconstructed == job, "epoch_v3_summary_job_digest_drift")
                _require(state["selected_revision"] == state["max_revision"], "epoch_v3_summary_revision_drift")
                terminal = connection.execute("SELECT turn_digest FROM committed_turns WHERE sequence=?", (job.job.covered_end,)).fetchone()
                _require(terminal is not None and terminal["turn_digest"] == job.job.covered_terminal_digest, "epoch_v3_summary_terminal_drift")
                now = _utc_now()
                summary = candidate.summary
                connection.execute(
                    "INSERT INTO committed_summaries VALUES (?,?,?,?,?,?,?,?)",
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
                revision = state["max_revision"] + 1
                connection.execute(
                    "INSERT INTO epoch_revisions VALUES (?,?,?,?,?)",
                    (revision, state["latest_sequence"], state["latest_digest"], summary.summary_version, now),
                )
                connection.execute(
                    "UPDATE epoch_state SET selected_revision=?,max_revision=?,active_summary_version=?,updated_at=? WHERE singleton=1",
                    (revision, revision, summary.summary_version, now),
                )
                connection.execute(
                    "UPDATE summary_jobs SET status='committed',lease_owner=NULL,candidate_digest=?,committed_revision=?,committed_at=? WHERE job_digest=?",
                    (summary.digest, revision, now, job.digest),
                )
                connection.execute("COMMIT")
            self._secure_paths()
            return revision
        except ExternalEpochV3Rejected:
            raise
        except (sqlite3.Error, OSError, ValueError, TypeError):
            raise ExternalEpochV3Rejected("epoch_v3_summary_commit_failed") from None

    def public_metadata(self) -> dict[str, object]:
        try:
            with self._connect_query_only() as connection:
                verify_epoch_v3_schema(connection)
                state = self._state(connection)
                count = lambda table, where="": connection.execute(f"SELECT COUNT(*) FROM {table} {where}").fetchone()[0]
                return {
                    "abandoned_delivery_count": count("delivery_receipts", "WHERE outcome='abandoned'"),
                    "delivered_intent_count": count("delivery_receipts", "WHERE outcome='delivered'"),
                    "epoch_id": self.epoch_id,
                    "max_revision": state["max_revision"],
                    "pending_count": count("pending_turns"),
                    "queued_summary_count": count("summary_jobs", "WHERE status IN ('queued','leased')"),
                    "blocked_summary_count": count("summary_jobs", "WHERE status='blocked'"),
                    "release_set_id": self.release_set_id,
                    "schema": SQLITE_SCHEMA,
                    "selected_revision": state["selected_revision"],
                    "summary_count": count("committed_summaries"),
                    "turn_count": count("committed_turns"),
                }
        except (sqlite3.Error, OSError):
            raise ExternalEpochV3Rejected("epoch_v3_metadata_unavailable") from None
