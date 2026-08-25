"""Durable, content-free recovery episodes for one authorized channel scope."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import sqlite3
import stat
from uuid import uuid4


RECOVERY_NOTICE_TEXT = (
    "\u521a\u624d\u7684\u670d\u52a1\u5f02\u5e38\u5df2\u7ecf\u6062\u590d\uff0c\u53ef\u4ee5\u7ee7\u7eed\u4f7f\u7528\u4e86\u3002"
)
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,383}$")
_PROJECTION_FIELDS = frozenset(
    {
        "schema",
        "status",
        "category",
        "fingerprint",
        "recovery_state",
        "retryable",
        "owner_action_required",
    }
)


class RecoveryEpisodeRejected(RuntimeError):
    """The bounded recovery state operation failed closed."""


@dataclass(frozen=True, slots=True)
class RecoverySnapshot:
    episode_id: str
    state: str
    category: str
    fingerprint: str
    first_seen_at: str
    last_seen_at: str
    occurrence_count: int
    recovered_at: str | None
    notice_claimed: bool


def _safe_identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _SAFE_IDENTIFIER.fullmatch(value) is None:
        raise RecoveryEpisodeRejected(f"{label} rejected")
    return value


def _canonical_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise RecoveryEpisodeRejected("timestamp rejected")
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _validated_projection(projection: object) -> tuple[str, str]:
    if not isinstance(projection, Mapping) or set(projection) != _PROJECTION_FIELDS:
        raise RecoveryEpisodeRejected("projection rejected")
    if (
        projection["schema"] != "myuna.safe-degradation.v1"
        or projection["status"] != "degraded"
        or projection["recovery_state"] != "active"
        or type(projection["retryable"]) is not bool
        or type(projection["owner_action_required"]) is not bool
    ):
        raise RecoveryEpisodeRejected("projection rejected")
    category = _safe_identifier(projection["category"], "category")
    fingerprint = _safe_identifier(projection["fingerprint"], "fingerprint")
    return category, fingerprint


class RecoveryEpisodeStore:
    """One-row-per-scope SQLite state with atomic at-most-once notice claims."""

    def __init__(self, database_path: Path, scope_key: str) -> None:
        self.database_path = Path(database_path)
        self.scope_key = _safe_identifier(scope_key, "scope")
        self._prepare_path()
        self._initialize()

    def _prepare_path(self) -> None:
        try:
            self.database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            parent_metadata = self.database_path.parent.lstat()
            if (
                stat.S_ISLNK(parent_metadata.st_mode)
                or not stat.S_ISDIR(parent_metadata.st_mode)
                or parent_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(parent_metadata.st_mode) != 0o700
            ):
                raise RecoveryEpisodeRejected("database directory rejected")
            if self.database_path.exists() or self.database_path.is_symlink():
                metadata = self.database_path.lstat()
                if (
                    stat.S_ISLNK(metadata.st_mode)
                    or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                ):
                    raise RecoveryEpisodeRejected("database path rejected")
        except OSError as exc:
            raise RecoveryEpisodeRejected("database path rejected") from exc

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                self.database_path,
                timeout=5,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA foreign_keys = ON")
            return connection
        except sqlite3.Error as exc:
            raise RecoveryEpisodeRejected("recovery database unavailable") from exc

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS recovery_episode (
                    scope_key TEXT PRIMARY KEY,
                    episode_id TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('active', 'recovered')),
                    category TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    occurrence_count INTEGER NOT NULL
                        CHECK (occurrence_count >= 1),
                    recovered_at TEXT,
                    notice_claimed INTEGER NOT NULL
                        CHECK (notice_claimed IN (0, 1)),
                    CHECK (
                        (state = 'active'
                         AND recovered_at IS NULL
                         AND notice_claimed = 0)
                        OR
                        (state = 'recovered'
                         AND recovered_at IS NOT NULL
                         AND notice_claimed = 1)
                    )
                )
                """
            )
        except sqlite3.Error as exc:
            raise RecoveryEpisodeRejected("recovery database unavailable") from exc
        finally:
            connection.close()
        try:
            os.chmod(self.database_path, 0o600)
            metadata = self.database_path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise RecoveryEpisodeRejected("database metadata rejected")
        except OSError as exc:
            raise RecoveryEpisodeRejected("database metadata rejected") from exc

    def mark_active(self, projection: object, *, now: datetime) -> None:
        category, fingerprint = _validated_projection(projection)
        timestamp = _canonical_timestamp(now)
        episode_id = f"episode-{uuid4().hex}"
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                """
                SELECT state
                FROM recovery_episode
                WHERE scope_key = ?
                """,
                (self.scope_key,),
            ).fetchone()
            if current is not None and current["state"] == "active":
                connection.execute(
                    """
                    UPDATE recovery_episode
                    SET category = ?,
                        fingerprint = ?,
                        last_seen_at = ?,
                        occurrence_count = occurrence_count + 1
                    WHERE scope_key = ? AND state = 'active'
                    """,
                    (category, fingerprint, timestamp, self.scope_key),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO recovery_episode (
                        scope_key,
                        episode_id,
                        state,
                        category,
                        fingerprint,
                        first_seen_at,
                        last_seen_at,
                        occurrence_count,
                        recovered_at,
                        notice_claimed
                    )
                    VALUES (?, ?, 'active', ?, ?, ?, ?, 1, NULL, 0)
                    ON CONFLICT(scope_key) DO UPDATE SET
                        episode_id = excluded.episode_id,
                        state = 'active',
                        category = excluded.category,
                        fingerprint = excluded.fingerprint,
                        first_seen_at = excluded.first_seen_at,
                        last_seen_at = excluded.last_seen_at,
                        occurrence_count = 1,
                        recovered_at = NULL,
                        notice_claimed = 0
                    """,
                    (
                        self.scope_key,
                        episode_id,
                        category,
                        fingerprint,
                        timestamp,
                        timestamp,
                    ),
                )
            connection.execute("COMMIT")
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise RecoveryEpisodeRejected("active transition rejected") from exc
        finally:
            connection.close()

    def claim_recovery_notice(self, *, now: datetime) -> bool:
        timestamp = _canonical_timestamp(now)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE recovery_episode
                SET state = 'recovered',
                    recovered_at = ?,
                    notice_claimed = 1
                WHERE scope_key = ?
                  AND state = 'active'
                  AND notice_claimed = 0
                """,
                (timestamp, self.scope_key),
            )
            claimed = cursor.rowcount == 1
            connection.execute("COMMIT")
            return claimed
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise RecoveryEpisodeRejected("recovery transition rejected") from exc
        finally:
            connection.close()

    def snapshot(self) -> RecoverySnapshot | None:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT
                    episode_id,
                    state,
                    category,
                    fingerprint,
                    first_seen_at,
                    last_seen_at,
                    occurrence_count,
                    recovered_at,
                    notice_claimed
                FROM recovery_episode
                WHERE scope_key = ?
                """,
                (self.scope_key,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise RecoveryEpisodeRejected("snapshot rejected") from exc
        finally:
            connection.close()
        if row is None:
            return None
        return RecoverySnapshot(
            episode_id=str(row["episode_id"]),
            state=str(row["state"]),
            category=str(row["category"]),
            fingerprint=str(row["fingerprint"]),
            first_seen_at=str(row["first_seen_at"]),
            last_seen_at=str(row["last_seen_at"]),
            occurrence_count=int(row["occurrence_count"]),
            recovered_at=(
                None if row["recovered_at"] is None else str(row["recovered_at"])
            ),
            notice_claimed=bool(row["notice_claimed"]),
        )
