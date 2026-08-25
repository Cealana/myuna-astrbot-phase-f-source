from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import secrets
import sqlite3
import stat

from .access import AuthorizedTemporalScope
from .contracts import (
    MAX_PROPOSAL_BYTES,
    MAX_PROPOSAL_TTL,
    MIN_PROPOSAL_TTL,
    MUTATION_ACTIONS,
    SCHEMA_LABEL,
    SCHEMA_VERSION,
    SQLITE_APPLICATION_ID,
    PreparedTemporalProposal,
    TemporalContextError,
    TemporalFact,
    TemporalFactDraft,
    TemporalLifecycleRecord,
    TemporalMutationResult,
    TemporalRetrievalResult,
    normalized_text,
    safe_label,
    utc,
)
from .retrieval import select_temporal_facts
from .time import TrustedTimeGuard, TrustedTimeSample


MAX_DATABASE_BYTES = 16 * 1024 * 1024
MAX_FACTS = 4_096
MAX_EVENTS = 16_384
MAX_PENDING_PROPOSALS = 256
MAX_PENDING_PER_SCOPE = 32
MAX_BUSY_TIMEOUT_SECONDS = 5.0

_SCHEMA = """
CREATE TABLE metadata (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
) STRICT;
CREATE TABLE clock_watermark (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    source TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    instant TEXT NOT NULL
) STRICT;
CREATE TABLE facts (
    fact_id TEXT PRIMARY KEY NOT NULL,
    revision INTEGER NOT NULL UNIQUE CHECK (revision > 0),
    category TEXT NOT NULL,
    slot_key TEXT NOT NULL,
    summary TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    source_channel TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to TEXT,
    expires_at TEXT NOT NULL,
    state TEXT NOT NULL,
    supersedes_fact_id TEXT REFERENCES facts(fact_id),
    semantic_sha256 TEXT NOT NULL,
    created_request_id TEXT NOT NULL
) STRICT;
CREATE UNIQUE INDEX one_active_fact_per_slot
    ON facts(slot_key) WHERE state = 'active';
CREATE TABLE proposals (
    proposal_id TEXT PRIMARY KEY NOT NULL,
    scope_sha256 TEXT NOT NULL,
    request_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_fact_id TEXT,
    candidate_json TEXT,
    candidate_sha256 TEXT NOT NULL,
    confirmation_sha256 TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'consumed', 'cancelled')),
    UNIQUE(scope_sha256, request_id)
) STRICT;
CREATE TABLE lifecycle_events (
    event_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_kind TEXT NOT NULL,
    fact_id TEXT,
    previous_fact_id TEXT,
    category TEXT,
    transition TEXT NOT NULL,
    reason TEXT NOT NULL,
    trusted_time_source_class TEXT NOT NULL,
    occurred_at TEXT NOT NULL
) STRICT;
CREATE TABLE idempotency (
    scope_sha256 TEXT NOT NULL,
    request_id TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    result_json TEXT NOT NULL,
    PRIMARY KEY(scope_sha256, request_id)
) STRICT;
"""


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="microseconds")


def _parse_time(value: str, label: str) -> datetime:
    try:
        return utc(datetime.fromisoformat(value), label)
    except (TypeError, ValueError) as exc:
        raise TemporalContextError("database_corrupt") from exc


def _digest(value: bytes) -> str:
    return sha256(value).hexdigest()


def _validated_timeout(value: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 <= float(value) <= MAX_BUSY_TIMEOUT_SECONDS
    ):
        raise TemporalContextError("database_timeout_invalid")
    return float(value)


def _semantic_digest(draft: TemporalFactDraft) -> str:
    payload = {
        "category": draft.category,
        "expires_at": _iso(draft.expires_at),
        "slot_key": draft.slot_key,
        "summary": normalized_text(draft.summary),
        "valid_from": _iso(draft.valid_from),
        "valid_to": _iso(draft.valid_to) if draft.valid_to else None,
    }
    return _digest(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )


def _fact_payload(fact: TemporalFact | None) -> object:
    if fact is None:
        return None
    return {
        "category": fact.category,
        "expires_at": _iso(fact.expires_at),
        "fact_id": fact.fact_id,
        "observed_at": _iso(fact.observed_at),
        "revision": fact.revision,
        "slot_key": fact.slot_key,
        "source_channel": fact.source_channel,
        "source_kind": fact.source_kind,
        "source_ref": fact.source_ref,
        "state": fact.state,
        "summary": fact.summary,
        "supersedes_fact_id": fact.supersedes_fact_id,
        "valid_from": _iso(fact.valid_from),
        "valid_to": _iso(fact.valid_to) if fact.valid_to else None,
    }


def _result_payload(result: TemporalMutationResult) -> str:
    return json.dumps(
        {
            "event_written": result.event_written,
            "fact": _fact_payload(result.fact),
            "outcome": result.outcome,
            "previous_state": result.previous_state,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _result_from_payload(raw: str) -> TemporalMutationResult:
    try:
        payload = json.loads(raw)
        if not isinstance(payload, dict) or set(payload) != {
            "event_written",
            "fact",
            "outcome",
            "previous_state",
        }:
            raise ValueError
        fact_payload = payload["fact"]
        fact = _fact_from_mapping(fact_payload) if fact_payload is not None else None
        if not isinstance(payload["event_written"], bool):
            raise ValueError
        if not isinstance(payload["outcome"], str):
            raise ValueError
        previous = payload["previous_state"]
        if previous is not None and not isinstance(previous, str):
            raise ValueError
        expected = {
            "active": ("active", "proposed", True),
            "no_change": ("active", "active", False),
            "conflict": ("conflicted", "proposed", True),
            "supersede": ("active", "active", True),
            "refresh": ("active", "active", True),
            "revoked": ("revoked", "active", True),
            "restored": ("active", "revoked", True),
        }.get(payload["outcome"])
        if (
            expected is None
            or fact is None
            or (fact.state, previous, payload["event_written"]) != expected
        ):
            raise ValueError
        return TemporalMutationResult(
            outcome=payload["outcome"],
            fact=fact,
            previous_state=previous,
            event_written=payload["event_written"],
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise TemporalContextError("database_corrupt") from exc


def _fact_from_mapping(row: object) -> TemporalFact:
    try:
        values = dict(row)  # type: ignore[arg-type]
        return TemporalFact(
            fact_id=values["fact_id"],
            revision=values["revision"],
            category=values["category"],
            slot_key=values["slot_key"],
            summary=values["summary"],
            source_kind=values["source_kind"],
            source_channel=values["source_channel"],
            source_ref=values["source_ref"],
            observed_at=_parse_time(values["observed_at"], "observed_at"),
            valid_from=_parse_time(values["valid_from"], "valid_from"),
            valid_to=(
                _parse_time(values["valid_to"], "valid_to")
                if values["valid_to"] is not None
                else None
            ),
            expires_at=_parse_time(values["expires_at"], "expires_at"),
            state=values["state"],
            supersedes_fact_id=values["supersedes_fact_id"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise TemporalContextError("database_corrupt") from exc


class TemporalContextStore:
    """Strict private SQLite store with no session/Profile/P10 fallback."""

    def __init__(
        self,
        path: str | Path,
        *,
        expected_uid: int | None = None,
        timeout_seconds: float = 1.0,
        failure_injector: Callable[[str], None] | None = None,
    ) -> None:
        self.path = Path(path)
        if not self.path.is_absolute():
            raise TemporalContextError("database_path_invalid")
        self.expected_uid = os.getuid() if expected_uid is None else expected_uid
        self.timeout_seconds = _validated_timeout(timeout_seconds)
        self.failure_injector = failure_injector
        self._validate_path()
        watermark = self._load_and_validate_watermark()
        self._time_guard = TrustedTimeGuard(
            source=watermark[0] if watermark else None,
            sequence=watermark[1] if watermark else None,
            instant=watermark[2] if watermark else None,
        )

    @classmethod
    def create(
        cls,
        path: str | Path,
        *,
        expected_uid: int | None = None,
        timeout_seconds: float = 1.0,
        failure_injector: Callable[[str], None] | None = None,
    ) -> TemporalContextStore:
        target = Path(path)
        uid = os.getuid() if expected_uid is None else expected_uid
        timeout_seconds = _validated_timeout(timeout_seconds)
        cls._validate_parent(target.parent, uid)
        if target.exists() or target.is_symlink():
            raise TemporalContextError("database_already_exists")
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(target, flags, 0o600)
        os.close(descriptor)
        try:
            connection = sqlite3.connect(target, timeout=timeout_seconds)
            try:
                connection.execute("PRAGMA journal_mode=DELETE")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute("PRAGMA trusted_schema=OFF")
                connection.execute(f"PRAGMA application_id={SQLITE_APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                connection.executescript(_SCHEMA)
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES('schema_label', ?)",
                    (SCHEMA_LABEL,),
                )
                connection.commit()
            finally:
                connection.close()
        except BaseException:
            target.unlink(missing_ok=True)
            raise
        return cls(
            target,
            expected_uid=uid,
            timeout_seconds=timeout_seconds,
            failure_injector=failure_injector,
        )

    @staticmethod
    def _validate_parent(parent: Path, expected_uid: int) -> None:
        try:
            metadata = parent.lstat()
        except OSError as exc:
            raise TemporalContextError("database_unavailable", retryable=True) from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or parent.is_symlink()
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise TemporalContextError("database_permission_drift")

    def _validate_path(self) -> None:
        self._validate_parent(self.path.parent, self.expected_uid)
        try:
            metadata = self.path.lstat()
        except OSError as exc:
            raise TemporalContextError("database_unavailable", retryable=True) from exc
        if self.path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise TemporalContextError("database_type_drift")
        if metadata.st_uid != self.expected_uid or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise TemporalContextError("database_permission_drift")
        if metadata.st_size > MAX_DATABASE_BYTES:
            raise TemporalContextError("database_oversize")

    def _connect(self) -> sqlite3.Connection:
        self._validate_path()
        try:
            connection = sqlite3.connect(
                f"file:{self.path}?mode=rw",
                uri=True,
                timeout=self.timeout_seconds,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute(f"PRAGMA busy_timeout={int(self.timeout_seconds * 1000)}")
            return connection
        except sqlite3.Error as exc:
            raise TemporalContextError("database_unavailable", retryable=True) from exc

    def _validate_database(self, connection: sqlite3.Connection) -> None:
        try:
            application_id = connection.execute("PRAGMA application_id").fetchone()[0]
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if application_id != SQLITE_APPLICATION_ID or version != SCHEMA_VERSION:
                raise TemporalContextError("schema_unknown")
            label = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_label'"
            ).fetchone()
            if label is None or label[0] != SCHEMA_LABEL:
                raise TemporalContextError("schema_unknown")
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise TemporalContextError("database_corrupt")
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise TemporalContextError("database_corrupt")
            counts = {
                "facts": connection.execute("SELECT COUNT(*) FROM facts").fetchone()[0],
                "events": connection.execute(
                    "SELECT COUNT(*) FROM lifecycle_events"
                ).fetchone()[0],
                "pending": connection.execute(
                    "SELECT COUNT(*) FROM proposals WHERE state='pending'"
                ).fetchone()[0],
            }
            if (
                counts["facts"] > MAX_FACTS
                or counts["events"] > MAX_EVENTS
                or counts["pending"] > MAX_PENDING_PROPOSALS
            ):
                raise TemporalContextError("database_oversize")
            missing_event = connection.execute(
                "SELECT 1 FROM facts f WHERE NOT EXISTS "
                "(SELECT 1 FROM lifecycle_events e WHERE e.fact_id=f.fact_id) LIMIT 1"
            ).fetchone()
            if missing_event is not None:
                raise TemporalContextError("database_corrupt")
            invalid_chain = connection.execute(
                "SELECT 1 FROM facts current JOIN facts prior "
                "ON current.supersedes_fact_id=prior.fact_id "
                "WHERE current.slot_key != prior.slot_key "
                "OR current.revision <= prior.revision LIMIT 1"
            ).fetchone()
            if invalid_chain is not None:
                raise TemporalContextError("database_corrupt")
            for fact_row in connection.execute(
                "SELECT fact_id, state FROM facts"
            ).fetchall():
                fact_id, state = fact_row["fact_id"], fact_row["state"]
                own_event = connection.execute(
                    "SELECT transition FROM lifecycle_events WHERE fact_id=? "
                    "ORDER BY event_sequence DESC LIMIT 1",
                    (fact_id,),
                ).fetchone()
                if own_event is None:
                    raise TemporalContextError("database_corrupt")
                transition = own_event["transition"]
                valid = {
                    "active": transition in {
                        "proposed->active",
                        "active->superseded+active",
                        "revoked->active(new_revision)",
                    },
                    "conflicted": transition == "proposed->conflicted",
                    "revoked": transition == "active->revoked",
                    "expired": transition == "active->expired",
                    "superseded": connection.execute(
                        "SELECT 1 FROM lifecycle_events WHERE previous_fact_id=? "
                        "AND transition='active->superseded+active' LIMIT 1",
                        (fact_id,),
                    ).fetchone()
                    is not None,
                }.get(state, False)
                if not valid:
                    raise TemporalContextError("database_corrupt")
        except TemporalContextError:
            raise
        except sqlite3.DatabaseError as exc:
            raise TemporalContextError("database_corrupt") from exc

    @staticmethod
    def _assert_write_limits(connection: sqlite3.Connection) -> None:
        facts = connection.execute("SELECT COUNT(*) FROM facts").fetchone()[0]
        events = connection.execute(
            "SELECT COUNT(*) FROM lifecycle_events"
        ).fetchone()[0]
        pending = connection.execute(
            "SELECT COUNT(*) FROM proposals WHERE state='pending'"
        ).fetchone()[0]
        page_count = connection.execute("PRAGMA page_count").fetchone()[0]
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
        if (
            facts > MAX_FACTS
            or events > MAX_EVENTS
            or pending > MAX_PENDING_PROPOSALS
            or page_count * page_size > MAX_DATABASE_BYTES
        ):
            raise TemporalContextError("database_oversize")

    def _load_and_validate_watermark(self) -> tuple[str, int, datetime] | None:
        connection = self._connect()
        try:
            self._validate_database(connection)
            row = connection.execute(
                "SELECT source, sequence, instant FROM clock_watermark WHERE singleton=1"
            ).fetchone()
            if row is None:
                return None
            return row["source"], int(row["sequence"]), _parse_time(
                row["instant"], "trusted_time_watermark"
            )
        finally:
            connection.close()

    def _accept_time(
        self,
        connection: sqlite3.Connection,
        sample: TrustedTimeSample,
        *,
        persist: bool,
    ) -> None:
        self._time_guard.accept(sample)
        if persist:
            connection.execute(
                "INSERT INTO clock_watermark(singleton, source, sequence, instant) "
                "VALUES(1, ?, ?, ?) ON CONFLICT(singleton) DO UPDATE SET "
                "source=excluded.source, sequence=excluded.sequence, instant=excluded.instant",
                (sample.source, sample.sequence, _iso(sample.instant)),
            )

    @staticmethod
    def _proposal_payload(
        *,
        action: str,
        target_fact_id: str | None,
        draft: TemporalFactDraft | None,
        observed_at: datetime,
    ) -> str:
        payload = {
            "action": action,
            "candidate": draft.as_payload() if draft is not None else None,
            "observed_at": _iso(observed_at),
            "target_fact_id": target_fact_id,
        }
        raw = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        )
        if len(raw.encode("utf-8")) > MAX_PROPOSAL_BYTES:
            raise TemporalContextError("proposal_oversize")
        return raw

    def propose_mutation(
        self,
        scope: AuthorizedTemporalScope,
        *,
        request_id: str,
        action: str,
        sample: TrustedTimeSample,
        draft: TemporalFactDraft | None = None,
        target_fact_id: str | None = None,
        ttl: timedelta = timedelta(minutes=10),
        confirmation_code: str | None = None,
    ) -> PreparedTemporalProposal:
        safe_label(request_id, "request_id")
        safe_label(scope.scope_sha256, "scope_sha256")
        if scope.channel_kind != "telegram" or action not in MUTATION_ACTIONS:
            raise TemporalContextError("write_scope_rejected")
        requires_draft = action in {"create", "supersede", "refresh", "restore"}
        requires_target = action in {"supersede", "refresh", "revoke", "restore"}
        if requires_draft != (draft is not None) or requires_target != (
            target_fact_id is not None
        ):
            raise TemporalContextError("mutation_shape_invalid")
        if target_fact_id is not None:
            safe_label(target_fact_id, "target_fact_id")
        if not MIN_PROPOSAL_TTL <= ttl <= MAX_PROPOSAL_TTL:
            raise TemporalContextError("proposal_expiry_invalid")
        if draft is not None:
            draft.validate_observed_at(sample.instant)
        expires_at = sample.instant + ttl
        if draft is not None and expires_at >= draft.expires_at:
            raise TemporalContextError("proposal_expiry_invalid")
        code = confirmation_code or secrets.token_hex(6).upper()
        safe_label(code, "confirmation_code")
        candidate_json = self._proposal_payload(
            action=action,
            target_fact_id=target_fact_id,
            draft=draft,
            observed_at=sample.instant,
        )
        candidate_sha = _digest(candidate_json.encode("utf-8"))
        proposal_id = "tp_" + _digest(
            b"myuna-temporal-proposal-v1\0"
            + scope.scope_sha256.encode("ascii")
            + b"\0"
            + request_id.encode("ascii")
            + b"\0"
            + candidate_sha.encode("ascii")
        )[:32]
        connection = self._connect()
        try:
            self._validate_database(connection)
            connection.execute("BEGIN IMMEDIATE")
            self._accept_time(connection, sample, persist=True)
            connection.execute(
                "UPDATE proposals SET state='cancelled' "
                "WHERE state='pending' AND expires_at <= ?",
                (_iso(sample.instant),),
            )
            if connection.execute(
                "SELECT 1 FROM proposals WHERE scope_sha256=? AND request_id=?",
                (scope.scope_sha256, request_id),
            ).fetchone():
                raise TemporalContextError("proposal_request_replayed")
            pending_scope = connection.execute(
                "SELECT COUNT(*) FROM proposals WHERE scope_sha256=? AND state='pending'",
                (scope.scope_sha256,),
            ).fetchone()[0]
            if pending_scope >= MAX_PENDING_PER_SCOPE:
                raise TemporalContextError("proposal_capacity_exceeded")
            connection.execute(
                "INSERT INTO proposals VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
                (
                    proposal_id,
                    scope.scope_sha256,
                    request_id,
                    action,
                    target_fact_id,
                    candidate_json,
                    candidate_sha,
                    _digest(code.encode("ascii")),
                    _iso(sample.instant),
                    _iso(expires_at),
                ),
            )
            self._assert_write_limits(connection)
            if self.failure_injector:
                self.failure_injector("before_commit")
            connection.commit()
        except TemporalContextError:
            connection.rollback()
            raise
        except sqlite3.OperationalError as exc:
            connection.rollback()
            raise TemporalContextError("database_busy", retryable=True) from exc
        except BaseException as exc:
            connection.rollback()
            raise TemporalContextError("transaction_aborted", retryable=True) from exc
        finally:
            connection.close()
        return PreparedTemporalProposal(proposal_id, code, expires_at)

    @staticmethod
    def _parse_candidate(
        raw: str,
    ) -> tuple[str, str | None, TemporalFactDraft | None, datetime]:
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict) or set(payload) != {
                "action",
                "candidate",
                "observed_at",
                "target_fact_id",
            }:
                raise ValueError
            action = payload["action"]
            target = payload["target_fact_id"]
            if action not in MUTATION_ACTIONS or (
                target is not None and not isinstance(target, str)
            ):
                raise ValueError
            observed = _parse_time(payload["observed_at"], "observed_at")
            candidate = payload["candidate"]
            requires_draft = action in {"create", "supersede", "refresh", "restore"}
            requires_target = action in {"supersede", "refresh", "revoke", "restore"}
            if requires_draft != (candidate is not None) or requires_target != (
                target is not None
            ):
                raise ValueError
            if target is not None:
                safe_label(target, "target_fact_id")
            draft = (
                TemporalFactDraft.from_payload(candidate)
                if candidate is not None
                else None
            )
            if draft is not None:
                draft.validate_observed_at(observed)
            return action, target, draft, observed
        except TemporalContextError as exc:
            raise TemporalContextError("database_corrupt") from exc
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise TemporalContextError("database_corrupt") from exc

    @staticmethod
    def _load_fact(
        connection: sqlite3.Connection, fact_id: str
    ) -> TemporalFact | None:
        row = connection.execute(
            "SELECT * FROM facts WHERE fact_id=?", (fact_id,)
        ).fetchone()
        return _fact_from_mapping(row) if row is not None else None

    @staticmethod
    def _active_for_slot(
        connection: sqlite3.Connection, slot_key: str
    ) -> TemporalFact | None:
        row = connection.execute(
            "SELECT * FROM facts WHERE slot_key=? AND state='active'", (slot_key,)
        ).fetchone()
        return _fact_from_mapping(row) if row is not None else None

    @staticmethod
    def _next_revision(connection: sqlite3.Connection) -> int:
        row = connection.execute(
            "SELECT COALESCE(MAX(revision), 0)+1 FROM facts"
        ).fetchone()
        return int(row[0])

    @staticmethod
    def _new_fact(
        connection: sqlite3.Connection,
        *,
        draft: TemporalFactDraft,
        observed_at: datetime,
        sample: TrustedTimeSample,
        proposal_id: str,
        state: str,
        supersedes_fact_id: str | None,
    ) -> TemporalFact:
        revision = TemporalContextStore._next_revision(connection)
        fact_id = "tf_" + _digest(
            b"myuna-temporal-fact-v1\0"
            + proposal_id.encode("ascii")
            + b"\0"
            + str(revision).encode("ascii")
        )[:32]
        fact = TemporalFact(
            fact_id=fact_id,
            revision=revision,
            category=draft.category,
            slot_key=draft.slot_key,
            summary=draft.summary,
            source_kind=draft.source_kind,
            source_channel=draft.source_channel,
            source_ref=draft.source_ref,
            observed_at=observed_at,
            valid_from=draft.valid_from,
            valid_to=draft.valid_to,
            expires_at=draft.expires_at,
            state=state,
            supersedes_fact_id=supersedes_fact_id,
        )
        connection.execute(
            "INSERT INTO facts VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                fact.fact_id,
                fact.revision,
                fact.category,
                fact.slot_key,
                fact.summary,
                fact.source_kind,
                fact.source_channel,
                fact.source_ref,
                _iso(fact.observed_at),
                _iso(fact.valid_from),
                _iso(fact.valid_to) if fact.valid_to else None,
                _iso(fact.expires_at),
                fact.state,
                fact.supersedes_fact_id,
                _semantic_digest(draft),
                proposal_id,
            ),
        )
        return fact

    @staticmethod
    def _event(
        connection: sqlite3.Connection,
        *,
        kind: str,
        fact: TemporalFact,
        previous_fact: TemporalFact | None,
        transition: str,
        reason: str,
        sample: TrustedTimeSample,
    ) -> None:
        connection.execute(
            "INSERT INTO lifecycle_events(event_kind, fact_id, previous_fact_id, "
            "category, transition, reason, trusted_time_source_class, occurred_at) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            (
                kind,
                fact.fact_id,
                previous_fact.fact_id if previous_fact else None,
                fact.category,
                transition,
                reason,
                sample.source_class,
                _iso(sample.instant),
            ),
        )

    def _apply_candidate(
        self,
        connection: sqlite3.Connection,
        *,
        proposal_id: str,
        action: str,
        target_fact_id: str | None,
        draft: TemporalFactDraft | None,
        observed_at: datetime,
        sample: TrustedTimeSample,
    ) -> TemporalMutationResult:
        target = self._load_fact(connection, target_fact_id) if target_fact_id else None
        if action == "create":
            assert draft is not None
            active = self._active_for_slot(connection, draft.slot_key)
            if active is not None:
                active_draft = TemporalFactDraft(
                    active.category,
                    active.slot_key,
                    active.summary,
                    active.source_kind,
                    active.source_channel,
                    active.source_ref,
                    active.valid_from,
                    active.valid_to,
                    active.expires_at,
                )
                if _semantic_digest(active_draft) == _semantic_digest(draft):
                    return TemporalMutationResult("no_change", active, "active", False)
                fact = self._new_fact(
                    connection,
                    draft=draft,
                    observed_at=observed_at,
                    sample=sample,
                    proposal_id=proposal_id,
                    state="conflicted",
                    supersedes_fact_id=None,
                )
                self._event(
                    connection,
                    kind="conflict",
                    fact=fact,
                    previous_fact=active,
                    transition="proposed->conflicted",
                    reason="slot_conflict",
                    sample=sample,
                )
                return TemporalMutationResult("conflict", fact, "proposed", True)
            fact = self._new_fact(
                connection,
                draft=draft,
                observed_at=observed_at,
                sample=sample,
                proposal_id=proposal_id,
                state="active",
                supersedes_fact_id=None,
            )
            self._event(
                connection,
                kind="activate",
                fact=fact,
                previous_fact=None,
                transition="proposed->active",
                reason="owner_confirmed",
                sample=sample,
            )
            return TemporalMutationResult("active", fact, "proposed", True)
        if target is None:
            raise TemporalContextError("target_fact_not_found")
        if action == "revoke":
            if target.state != "active":
                raise TemporalContextError("target_state_invalid")
            connection.execute(
                "UPDATE facts SET state='revoked' WHERE fact_id=? AND state='active'",
                (target.fact_id,),
            )
            revoked = self._load_fact(connection, target.fact_id)
            assert revoked is not None
            self._event(
                connection,
                kind="revoke",
                fact=revoked,
                previous_fact=target,
                transition="active->revoked",
                reason="owner_confirmed",
                sample=sample,
            )
            return TemporalMutationResult("revoked", revoked, "active", True)
        assert draft is not None
        if draft.slot_key != target.slot_key:
            raise TemporalContextError("target_slot_mismatch")
        if action in {"supersede", "refresh"}:
            if target.state != "active":
                raise TemporalContextError("target_state_invalid")
            if action == "refresh" and (
                target.category != draft.category
                or normalized_text(target.summary) != normalized_text(draft.summary)
            ):
                raise TemporalContextError("refresh_content_mismatch")
            connection.execute(
                "UPDATE facts SET state='superseded' WHERE fact_id=? AND state='active'",
                (target.fact_id,),
            )
            fact = self._new_fact(
                connection,
                draft=draft,
                observed_at=observed_at,
                sample=sample,
                proposal_id=proposal_id,
                state="active",
                supersedes_fact_id=target.fact_id,
            )
            self._event(
                connection,
                kind=action,
                fact=fact,
                previous_fact=target,
                transition="active->superseded+active",
                reason="owner_confirmed",
                sample=sample,
            )
            return TemporalMutationResult(action, fact, "active", True)
        if action == "restore":
            if target.state != "revoked":
                raise TemporalContextError("target_state_invalid")
            if (
                target.category != draft.category
                or normalized_text(target.summary) != normalized_text(draft.summary)
                or self._active_for_slot(connection, target.slot_key) is not None
            ):
                raise TemporalContextError("restore_ineligible")
            fact = self._new_fact(
                connection,
                draft=draft,
                observed_at=observed_at,
                sample=sample,
                proposal_id=proposal_id,
                state="active",
                supersedes_fact_id=None,
            )
            self._event(
                connection,
                kind="restore",
                fact=fact,
                previous_fact=target,
                transition="revoked->active(new_revision)",
                reason="owner_confirmed",
                sample=sample,
            )
            return TemporalMutationResult("restored", fact, "revoked", True)
        raise TemporalContextError("mutation_shape_invalid")

    def confirm_mutation(
        self,
        scope: AuthorizedTemporalScope,
        *,
        request_id: str,
        proposal_id: str,
        confirmation_code: str,
        sample: TrustedTimeSample,
    ) -> TemporalMutationResult:
        safe_label(request_id, "request_id")
        safe_label(proposal_id, "proposal_id")
        safe_label(confirmation_code, "confirmation_code")
        safe_label(scope.scope_sha256, "scope_sha256")
        if scope.channel_kind != "telegram":
            raise TemporalContextError("write_scope_rejected")
        request_sha = _digest(
            b"myuna-temporal-confirm-v1\0"
            + proposal_id.encode("ascii")
            + b"\0"
            + _digest(confirmation_code.encode("ascii")).encode("ascii")
        )
        connection = self._connect()
        committed = False
        try:
            self._validate_database(connection)
            replay = connection.execute(
                "SELECT request_sha256, result_json FROM idempotency "
                "WHERE scope_sha256=? AND request_id=?",
                (scope.scope_sha256, request_id),
            ).fetchone()
            if replay is not None:
                if replay["request_sha256"] != request_sha:
                    raise TemporalContextError("idempotency_conflict")
                return _result_from_payload(replay["result_json"])
            connection.execute("BEGIN IMMEDIATE")
            self._accept_time(connection, sample, persist=True)
            proposal = connection.execute(
                "SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,)
            ).fetchone()
            if proposal is None:
                raise TemporalContextError("proposal_not_found")
            if proposal["scope_sha256"] != scope.scope_sha256:
                raise TemporalContextError("proposal_scope_rejected")
            if proposal["state"] != "pending":
                raise TemporalContextError("proposal_already_consumed")
            if sample.instant >= _parse_time(proposal["expires_at"], "proposal_expiry"):
                raise TemporalContextError("confirmation_expired")
            if proposal["confirmation_sha256"] != _digest(
                confirmation_code.encode("ascii")
            ):
                raise TemporalContextError("confirmation_rejected")
            if proposal["candidate_sha256"] != _digest(
                proposal["candidate_json"].encode("utf-8")
            ):
                raise TemporalContextError("database_corrupt")
            action, target_fact_id, draft, observed_at = self._parse_candidate(
                proposal["candidate_json"]
            )
            proposal_expiry = _parse_time(proposal["expires_at"], "proposal_expiry")
            stored_observed = _parse_time(proposal["observed_at"], "observed_at")
            if (
                proposal["action"] != action
                or proposal["target_fact_id"] != target_fact_id
                or stored_observed != observed_at
                or not MIN_PROPOSAL_TTL
                <= proposal_expiry - observed_at
                <= MAX_PROPOSAL_TTL
                or (draft is not None and proposal_expiry >= draft.expires_at)
            ):
                raise TemporalContextError("database_corrupt")
            result = self._apply_candidate(
                connection,
                proposal_id=proposal_id,
                action=action,
                target_fact_id=target_fact_id,
                draft=draft,
                observed_at=observed_at,
                sample=sample,
            )
            connection.execute(
                "UPDATE proposals SET state='consumed' WHERE proposal_id=?",
                (proposal_id,),
            )
            connection.execute(
                "INSERT INTO idempotency VALUES(?, ?, ?, ?)",
                (scope.scope_sha256, request_id, request_sha, _result_payload(result)),
            )
            self._assert_write_limits(connection)
            if self.failure_injector:
                self.failure_injector("before_commit")
            connection.commit()
            committed = True
            if self.failure_injector:
                self.failure_injector("after_commit")
            return result
        except TemporalContextError:
            if not committed:
                connection.rollback()
            raise
        except sqlite3.OperationalError as exc:
            if not committed:
                connection.rollback()
            raise TemporalContextError("database_busy", retryable=True) from exc
        except BaseException as exc:
            if committed:
                raise TemporalContextError("commit_outcome_unknown", retryable=True) from exc
            connection.rollback()
            raise TemporalContextError("transaction_aborted", retryable=True) from exc
        finally:
            connection.close()

    def active_facts(
        self,
        scope: AuthorizedTemporalScope,
        sample: TrustedTimeSample,
    ) -> tuple[TemporalFact, ...]:
        if scope.channel_kind != "telegram":
            raise TemporalContextError("read_scope_rejected")
        connection = self._connect()
        try:
            self._validate_database(connection)
            self._accept_time(connection, sample, persist=False)
            rows = connection.execute(
                "SELECT * FROM facts WHERE state='active' ORDER BY revision"
            ).fetchall()
            return tuple(
                fact
                for fact in (_fact_from_mapping(row) for row in rows)
                if fact.valid_from <= sample.instant < fact.effective_end
            )
        finally:
            connection.close()

    def active_facts_with_lifecycle(
        self,
        scope: AuthorizedTemporalScope,
        sample: TrustedTimeSample,
        *,
        after_event_sequence: int,
        maximum_events: int,
    ) -> tuple[
        tuple[TemporalFact, ...],
        tuple[TemporalLifecycleRecord, ...],
        int,
        bool,
    ]:
        """Read one consistent active snapshot plus a bounded lifecycle page."""

        if scope.channel_kind != "telegram":
            raise TemporalContextError("read_scope_rejected")
        if (
            isinstance(after_event_sequence, bool)
            or not isinstance(after_event_sequence, int)
            or after_event_sequence < 0
            or isinstance(maximum_events, bool)
            or not isinstance(maximum_events, int)
            or not 1 <= maximum_events <= 64
        ):
            raise TemporalContextError("lifecycle_cursor_invalid")
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._validate_database(connection)
            self._accept_time(connection, sample, persist=False)
            watermark = int(
                connection.execute(
                    "SELECT COALESCE(MAX(event_sequence), 0) FROM lifecycle_events"
                ).fetchone()[0]
            )
            if after_event_sequence > watermark:
                raise TemporalContextError("lifecycle_cursor_drifted")
            fact_rows = connection.execute(
                "SELECT * FROM facts WHERE state='active' ORDER BY revision"
            ).fetchall()
            facts = tuple(
                fact
                for fact in (_fact_from_mapping(row) for row in fact_rows)
                if fact.valid_from <= sample.instant < fact.effective_end
            )
            event_rows = connection.execute(
                "SELECT * FROM lifecycle_events WHERE event_sequence>? "
                "ORDER BY event_sequence LIMIT ?",
                (after_event_sequence, maximum_events + 1),
            ).fetchall()
            has_more = len(event_rows) > maximum_events
            selected_rows = event_rows[:maximum_events]
            records: list[TemporalLifecycleRecord] = []
            for event in selected_rows:
                fact_row = connection.execute(
                    "SELECT * FROM facts WHERE fact_id=?",
                    (event["fact_id"],),
                ).fetchone()
                if fact_row is None:
                    raise TemporalContextError("database_corrupt")
                fact = _fact_from_mapping(fact_row)
                records.append(
                    TemporalLifecycleRecord(
                        event_sequence=event["event_sequence"],
                        event_kind=event["event_kind"],
                        transition=event["transition"],
                        reason=event["reason"],
                        trusted_time_source_class=event[
                            "trusted_time_source_class"
                        ],
                        occurred_at=_parse_time(event["occurred_at"], "occurred_at"),
                        fact_id=fact.fact_id,
                        revision=fact.revision,
                        category=fact.category,
                        slot_key=fact.slot_key,
                        source_kind=fact.source_kind,
                        source_ref=fact.source_ref,
                        valid_from=fact.valid_from,
                        valid_to=fact.valid_to,
                        expires_at=fact.expires_at,
                        state=fact.state,
                        supersedes_fact_id=fact.supersedes_fact_id,
                    )
                )
            connection.commit()
            return facts, tuple(records), watermark, has_more
        except TemporalContextError:
            connection.rollback()
            raise
        except sqlite3.DatabaseError as exc:
            connection.rollback()
            raise TemporalContextError("database_corrupt") from exc
        finally:
            connection.close()

    def content_free_lifecycle_status(
        self,
        scope: AuthorizedTemporalScope,
        sample: TrustedTimeSample,
    ) -> dict[str, object]:
        """Return one complete fixed-field status without temporal text or raw IDs."""

        if scope.channel_kind != "telegram":
            raise TemporalContextError("read_scope_rejected")
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._validate_database(connection)
            self._accept_time(connection, sample, persist=False)
            active_rows = connection.execute(
                "SELECT fact_id, revision, category, slot_key, source_kind, "
                "source_channel, source_ref, observed_at, valid_from, valid_to, "
                "expires_at, state, supersedes_fact_id, semantic_sha256, "
                "created_request_id FROM facts WHERE state='active' ORDER BY revision"
            ).fetchall()
            active_rows = tuple(
                row
                for row in active_rows
                if _parse_time(row["valid_from"], "valid_from")
                <= sample.instant
                < _parse_time(
                    row["valid_to"] or row["expires_at"],
                    "effective_end",
                )
            )
            lifecycle_rows = connection.execute(
                "SELECT event_sequence, event_kind, fact_id, previous_fact_id, "
                "category, transition, reason, trusted_time_source_class, occurred_at "
                "FROM lifecycle_events ORDER BY event_sequence"
            ).fetchall()
            total_fact_count = int(
                connection.execute("SELECT COUNT(*) FROM facts").fetchone()[0]
            )
            pending_proposal_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM proposals WHERE state='pending'"
                ).fetchone()[0]
            )
            lifecycle_event_count = len(lifecycle_rows)
            lifecycle_watermark = (
                0
                if not lifecycle_rows
                else int(lifecycle_rows[-1]["event_sequence"])
            )
            if lifecycle_event_count != lifecycle_watermark:
                raise TemporalContextError("database_corrupt")

            def row_digest(domain: str, row: sqlite3.Row) -> str:
                fixed = [row[key] for key in row.keys()]
                return sha256(
                    domain.encode("ascii")
                    + b"\0"
                    + json.dumps(
                        fixed,
                        ensure_ascii=True,
                        separators=(",", ":"),
                    ).encode("ascii")
                ).hexdigest()

            active_set_digest = sha256(
                b"myuna-p08-content-free-active-set-v1\0"
                + "".join(
                    row_digest("myuna-p08-active-row-v1", row)
                    for row in active_rows
                ).encode("ascii")
            ).hexdigest()
            lifecycle_digest = sha256(
                b"myuna-p08-content-free-lifecycle-v1\0"
                + "".join(
                    row_digest("myuna-p08-lifecycle-row-v1", row)
                    for row in lifecycle_rows
                ).encode("ascii")
            ).hexdigest()
            connection.commit()
            return {
                "active_fact_count": len(active_rows),
                "active_set_complete": True,
                "active_set_digest": active_set_digest,
                "lifecycle_complete": True,
                "lifecycle_digest": lifecycle_digest,
                "lifecycle_event_count": lifecycle_event_count,
                "lifecycle_watermark": lifecycle_watermark,
                "pending_proposal_count": pending_proposal_count,
                "total_fact_count": total_fact_count,
            }
        except TemporalContextError:
            connection.rollback()
            raise
        except sqlite3.DatabaseError as exc:
            connection.rollback()
            raise TemporalContextError("database_corrupt") from exc
        finally:
            connection.close()

    def retrieve(
        self,
        scope: AuthorizedTemporalScope,
        sample: TrustedTimeSample,
        *,
        query: str,
        categories: tuple[str, ...] = (),
        slot_keys: tuple[str, ...] = (),
    ) -> TemporalRetrievalResult:
        facts = self.active_facts(scope, sample)
        return select_temporal_facts(
            facts,
            query=query,
            current=sample.instant,
            categories=categories,
            slot_keys=slot_keys,
        )

    def expire_due(self, sample: TrustedTimeSample) -> int:
        connection = self._connect()
        try:
            self._validate_database(connection)
            connection.execute("BEGIN IMMEDIATE")
            self._accept_time(connection, sample, persist=True)
            rows = connection.execute(
                "SELECT * FROM facts WHERE state='active' ORDER BY revision"
            ).fetchall()
            expired = 0
            for row in rows:
                fact = _fact_from_mapping(row)
                if sample.instant < fact.effective_end:
                    continue
                connection.execute(
                    "UPDATE facts SET state='expired' WHERE fact_id=? AND state='active'",
                    (fact.fact_id,),
                )
                updated = self._load_fact(connection, fact.fact_id)
                assert updated is not None
                self._event(
                    connection,
                    kind="expire",
                    fact=updated,
                    previous_fact=fact,
                    transition="active->expired",
                    reason="trusted_time_expiry",
                    sample=sample,
                )
                expired += 1
            self._assert_write_limits(connection)
            if self.failure_injector:
                self.failure_injector("before_commit")
            connection.commit()
            return expired
        except TemporalContextError:
            connection.rollback()
            raise
        except sqlite3.OperationalError as exc:
            connection.rollback()
            raise TemporalContextError("database_busy", retryable=True) from exc
        except BaseException as exc:
            connection.rollback()
            raise TemporalContextError("transaction_aborted", retryable=True) from exc
        finally:
            connection.close()

    def content_free_counts(self) -> dict[str, int]:
        connection = self._connect()
        try:
            self._validate_database(connection)
            return {
                "facts": connection.execute("SELECT COUNT(*) FROM facts").fetchone()[0],
                "events": connection.execute(
                    "SELECT COUNT(*) FROM lifecycle_events"
                ).fetchone()[0],
                "pending_proposals": connection.execute(
                    "SELECT COUNT(*) FROM proposals WHERE state='pending'"
                ).fetchone()[0],
            }
        finally:
            connection.close()

    def trusted_time_watermark(self) -> tuple[str, int, datetime] | None:
        """Return the content-free P10-B restart floor after full store validation."""

        connection = self._connect()
        try:
            self._validate_database(connection)
        finally:
            connection.close()
        return self._time_guard.watermark
