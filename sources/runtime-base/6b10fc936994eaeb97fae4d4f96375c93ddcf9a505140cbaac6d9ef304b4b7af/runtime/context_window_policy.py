from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
from threading import Lock
from typing import Protocol


MIN_HISTORY_MESSAGES = 2
MAX_HISTORY_MESSAGES = 256
MIN_HISTORY_CHARACTERS = 4_000
MAX_HISTORY_CHARACTERS = 262_144
SQLITE_CONTEXT_SCHEMA = "myuna.gateway.session-context.v1"
_SQLITE_SCHEMA_VERSION = 1
_NAMESPACE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ContextWindowRejected(ValueError):
    """Raised when a gateway short-term context boundary is invalid."""


@dataclass(frozen=True, slots=True)
class ContextWindowPolicy:
    max_messages: int
    max_characters: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.max_messages, int)
            or isinstance(self.max_messages, bool)
            or not MIN_HISTORY_MESSAGES <= self.max_messages <= MAX_HISTORY_MESSAGES
            or self.max_messages % 2
        ):
            raise ContextWindowRejected(
                "max history messages must be an even integer between 2 and 256"
            )
        if (
            not isinstance(self.max_characters, int)
            or isinstance(self.max_characters, bool)
            or not MIN_HISTORY_CHARACTERS
            <= self.max_characters
            <= MAX_HISTORY_CHARACTERS
        ):
            raise ContextWindowRejected(
                "max history characters must be between 4000 and 262144"
            )


class ContextStore(Protocol):
    """Replaceable storage boundary for volatile short-term context only."""

    def load(self, conversation_id: str) -> list[dict[str, str]]:
        ...

    def save(self, conversation_id: str, messages: list[dict[str, str]]) -> None:
        ...


class InMemoryContextStore:
    """Current runtime behavior: isolated per-process and cleared on restart."""

    def __init__(self) -> None:
        self._sessions: dict[str, list[dict[str, str]]] = {}

    def load(self, conversation_id: str) -> list[dict[str, str]]:
        return [dict(item) for item in self._sessions.get(conversation_id, [])]

    def save(self, conversation_id: str, messages: list[dict[str, str]]) -> None:
        self._sessions[conversation_id] = [dict(item) for item in messages]

    def session_count(self) -> int:
        return len(self._sessions)


class RecentRequestGuard:
    """Suppress identical owner-private redelivery without storing content.

    This is deliberately process-local.  It addresses transport redelivery
    while a socket-activated Gateway remains alive, and resets cleanly on a
    service restart.  Only salted SHA-256 fingerprints and expiry timestamps
    are retained.
    """

    def __init__(
        self,
        *,
        namespace: str,
        cooldown_seconds: int = 300,
        max_entries: int = 128,
    ) -> None:
        if _NAMESPACE.fullmatch(namespace) is None:
            raise ContextWindowRejected("request guard namespace is invalid")
        if not isinstance(cooldown_seconds, int) or not 30 <= cooldown_seconds <= 900:
            raise ContextWindowRejected("request guard cooldown is invalid")
        if not isinstance(max_entries, int) or not 8 <= max_entries <= 1024:
            raise ContextWindowRejected("request guard capacity is invalid")
        self.namespace = namespace
        self.cooldown_seconds = cooldown_seconds
        self.max_entries = max_entries
        self._expires: dict[str, datetime] = {}
        self._lock = Lock()

    def _fingerprint(self, conversation_id: str, message_text: str) -> str:
        if not isinstance(conversation_id, str) or not conversation_id:
            raise ContextWindowRejected("request guard conversation is invalid")
        if not isinstance(message_text, str) or not message_text:
            raise ContextWindowRejected("request guard message is invalid")
        return sha256(
            b"myuna-owner-request-guard-v1\0"
            + self.namespace.encode("ascii")
            + b"\0"
            + conversation_id.encode("utf-8")
            + b"\0"
            + message_text.encode("utf-8")
        ).hexdigest()

    def claim(
        self,
        conversation_id: str,
        message_text: str,
        now: datetime,
    ) -> bool:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ContextWindowRejected("request guard clock is invalid")
        current = now.astimezone(timezone.utc)
        fingerprint = self._fingerprint(conversation_id, message_text)
        expires_at = current.timestamp() + self.cooldown_seconds
        with self._lock:
            self._expires = {
                key: expiry
                for key, expiry in self._expires.items()
                if expiry > current
            }
            if self._expires.get(fingerprint, current) > current:
                return False
            if len(self._expires) >= self.max_entries:
                oldest = min(self._expires, key=self._expires.__getitem__)
                del self._expires[oldest]
            self._expires[fingerprint] = datetime.fromtimestamp(
                expires_at,
                tz=timezone.utc,
            )
        return True


def _validated_messages(messages: object) -> list[dict[str, str]]:
    if not isinstance(messages, list) or len(messages) % 2:
        raise ContextWindowRejected("context snapshot is not complete turns")
    validated: list[dict[str, str]] = []
    for index, item in enumerate(messages):
        expected_role = "user" if index % 2 == 0 else "assistant"
        if (
            not isinstance(item, dict)
            or set(item) != {"role", "content"}
            or item.get("role") != expected_role
            or not isinstance(item.get("content"), str)
        ):
            raise ContextWindowRejected("context snapshot has an invalid message")
        validated.append({"role": expected_role, "content": item["content"]})
    return validated


class SqliteContextStore:
    """A single-session, channel-scoped durable context snapshot.

    The database intentionally stores one rolling snapshot rather than an
    append-only transcript.  A conversation change starts empty and replaces
    the previous snapshot only after a successful reply is committed.
    """

    def __init__(self, database_path: str | Path, *, namespace: str) -> None:
        self.database_path = Path(database_path)
        if not self.database_path.is_absolute():
            raise ContextWindowRejected("context database path must be absolute")
        if _NAMESPACE.fullmatch(namespace) is None:
            raise ContextWindowRejected("context namespace is invalid")
        self.namespace = namespace
        self._initialize()

    @staticmethod
    def _conversation_fingerprint(namespace: str, conversation_id: str) -> str:
        if not isinstance(conversation_id, str) or not conversation_id:
            raise ContextWindowRejected("conversation id is invalid")
        return sha256(
            b"myuna-session-context-conversation-v1\0"
            + namespace.encode("ascii")
            + b"\0"
            + conversation_id.encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _canonical_messages(messages: list[dict[str, str]]) -> str:
        return json.dumps(
            messages,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    @staticmethod
    def _content_sha256(
        namespace: str,
        conversation_fingerprint: str,
        messages_json: str,
    ) -> str:
        return sha256(
            b"myuna-session-context-snapshot-v1\0"
            + namespace.encode("ascii")
            + b"\0"
            + conversation_fingerprint.encode("ascii")
            + b"\0"
            + messages_json.encode("utf-8")
        ).hexdigest()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _secure_paths(self) -> None:
        os.chmod(self.database_path.parent, 0o700)
        for path in (
            self.database_path,
            Path(f"{self.database_path}-wal"),
            Path(f"{self.database_path}-shm"),
        ):
            if path.exists():
                os.chmod(path, 0o600)

    def _initialize(self) -> None:
        parent = self.database_path.parent
        if self.database_path.exists() and self.database_path.is_symlink():
            raise ContextWindowRejected("context database must not be a symlink")
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if parent.is_symlink():
            raise ContextWindowRejected("context database parent must not be a symlink")
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS context_snapshot (
                        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                        schema_name TEXT NOT NULL,
                        schema_version INTEGER NOT NULL,
                        namespace TEXT NOT NULL,
                        conversation_fingerprint TEXT NOT NULL,
                        messages_json TEXT NOT NULL,
                        message_count INTEGER NOT NULL,
                        character_count INTEGER NOT NULL,
                        content_sha256 TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
            self._secure_paths()
        except (OSError, sqlite3.Error):
            raise ContextWindowRejected("context database initialization failed") from None

    def _read_row(self) -> sqlite3.Row | None:
        try:
            with self._connect() as connection:
                row = connection.execute(
                    """
                    SELECT schema_name, schema_version, namespace,
                           conversation_fingerprint, messages_json,
                           message_count, character_count, content_sha256,
                           updated_at
                    FROM context_snapshot
                    WHERE singleton = 1
                    """
                ).fetchone()
            self._secure_paths()
            return row
        except (OSError, sqlite3.Error):
            raise ContextWindowRejected("context database read failed") from None

    def _decode_row(self, row: sqlite3.Row) -> list[dict[str, str]]:
        try:
            if (
                row["schema_name"] != SQLITE_CONTEXT_SCHEMA
                or row["schema_version"] != _SQLITE_SCHEMA_VERSION
                or row["namespace"] != self.namespace
                or _SHA256.fullmatch(row["conversation_fingerprint"]) is None
                or _SHA256.fullmatch(row["content_sha256"]) is None
                or not isinstance(row["message_count"], int)
                or not isinstance(row["character_count"], int)
                or not isinstance(row["updated_at"], str)
            ):
                raise ContextWindowRejected("context snapshot metadata is invalid")
            datetime.fromisoformat(row["updated_at"].replace("Z", "+00:00"))
            messages = _validated_messages(json.loads(row["messages_json"]))
            if (
                row["message_count"] != len(messages)
                or row["character_count"]
                != sum(len(item["content"]) for item in messages)
                or row["content_sha256"]
                != self._content_sha256(
                    self.namespace,
                    row["conversation_fingerprint"],
                    row["messages_json"],
                )
            ):
                raise ContextWindowRejected("context snapshot integrity check failed")
            return messages
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise ContextWindowRejected("context snapshot is invalid") from None

    def load(self, conversation_id: str) -> list[dict[str, str]]:
        row = self._read_row()
        if row is None:
            return []
        messages = self._decode_row(row)
        expected = self._conversation_fingerprint(self.namespace, conversation_id)
        if row["conversation_fingerprint"] != expected:
            return []
        return [dict(item) for item in messages]

    def save(self, conversation_id: str, messages: list[dict[str, str]]) -> None:
        validated = _validated_messages(messages)
        fingerprint = self._conversation_fingerprint(self.namespace, conversation_id)
        messages_json = self._canonical_messages(validated)
        content_sha256 = self._content_sha256(
            self.namespace,
            fingerprint,
            messages_json,
        )
        updated_at = (
            datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT INTO context_snapshot (
                        singleton, schema_name, schema_version, namespace,
                        conversation_fingerprint, messages_json, message_count,
                        character_count, content_sha256, updated_at
                    ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(singleton) DO UPDATE SET
                        schema_name = excluded.schema_name,
                        schema_version = excluded.schema_version,
                        namespace = excluded.namespace,
                        conversation_fingerprint = excluded.conversation_fingerprint,
                        messages_json = excluded.messages_json,
                        message_count = excluded.message_count,
                        character_count = excluded.character_count,
                        content_sha256 = excluded.content_sha256,
                        updated_at = excluded.updated_at
                    """,
                    (
                        SQLITE_CONTEXT_SCHEMA,
                        _SQLITE_SCHEMA_VERSION,
                        self.namespace,
                        fingerprint,
                        messages_json,
                        len(validated),
                        sum(len(item["content"]) for item in validated),
                        content_sha256,
                        updated_at,
                    ),
                )
            self._secure_paths()
        except (OSError, sqlite3.Error):
            raise ContextWindowRejected("context database write failed") from None

    def public_metadata(self) -> dict[str, int | str | bool]:
        row = self._read_row()
        if row is None:
            return {
                "schema": SQLITE_CONTEXT_SCHEMA,
                "namespace": self.namespace,
                "present": False,
                "message_count": 0,
                "character_count": 0,
            }
        self._decode_row(row)
        return {
            "schema": row["schema_name"],
            "namespace": self.namespace,
            "present": True,
            "message_count": row["message_count"],
            "character_count": row["character_count"],
            "updated_at": row["updated_at"],
        }

    def export_messages(self) -> list[dict[str, str]]:
        row = self._read_row()
        if row is None:
            return []
        return [dict(item) for item in self._decode_row(row)]

    def clear(self) -> bool:
        try:
            with self._connect() as connection:
                connection.execute("PRAGMA secure_delete = ON")
                cursor = connection.execute(
                    "DELETE FROM context_snapshot WHERE singleton = 1"
                )
                removed = cursor.rowcount > 0
                connection.commit()
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                connection.execute("VACUUM")
            self._secure_paths()
            return removed
        except (OSError, sqlite3.Error):
            raise ContextWindowRejected("context database clear failed") from None


class ConversationHistory:
    """Bounded alternating context with a replaceable storage backend.

    The gateway is still responsible only for recent conversational continuity.
    Medium-term temporal state and long-term memory remain separate sources.
    """

    def __init__(
        self,
        max_messages: int,
        max_characters: int,
        *,
        store: ContextStore | None = None,
    ) -> None:
        self.policy = ContextWindowPolicy(max_messages, max_characters)
        self.max_messages = self.policy.max_messages
        self.max_characters = self.policy.max_characters
        self.store = store or InMemoryContextStore()

    def _trim(
        self,
        messages: list[dict[str, str]],
        *,
        final_role: str,
    ) -> list[dict[str, str]]:
        bounded = [dict(item) for item in messages]
        while len(bounded) > 1 and (
            len(bounded) > self.max_messages
            or sum(len(item["content"]) for item in bounded) > self.max_characters
        ):
            del bounded[:2]
        if not bounded or bounded[-1]["role"] != final_role:
            raise ContextWindowRejected("context history has an invalid final role")
        return bounded

    def request_messages(
        self,
        conversation_id: str,
        user_text: str,
    ) -> list[dict[str, str]]:
        existing = self.store.load(conversation_id)
        request = [*existing, {"role": "user", "content": user_text}]
        return self._trim(request, final_role="user")

    def commit_reply(
        self,
        conversation_id: str,
        request_messages: list[dict[str, str]],
        reply: str,
    ) -> None:
        committed = [
            *(dict(item) for item in request_messages),
            {"role": "assistant", "content": reply},
        ]
        self.store.save(
            conversation_id,
            self._trim(committed, final_role="assistant"),
        )

    def public_metadata(self) -> dict[str, int | str]:
        return {
            "policy": "gateway-short-term-context-v1",
            "max_messages": self.max_messages,
            "max_characters": self.max_characters,
            "store": type(self.store).__name__,
        }
