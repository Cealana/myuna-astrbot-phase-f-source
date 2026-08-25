from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
import os
from pathlib import Path
import sqlite3
import stat
import time

from myuna_core.active_temporal_context.time import TrustedTimeSample

from .audit import TrustedTimeAuditEvent, TrustedTimeAuditSink
from .contracts import (
    TrustedTimePolicy,
    TrustedTimeWatermark,
    UtcObservation,
    UtcObservationPort,
    safe_label,
    utc,
)
from .continuity import (
    ContinuityAnchor,
    ContinuityAssessment,
    ContinuityLedger,
    ForwardContinuityAuthorization,
    ForwardContinuityReconciliation,
    ForwardContinuityTransitionReceipt,
    drift_bucket,
    evidence_digest,
    policy_digest,
    source_binding_digest,
    timedelta_microseconds,
    uncertainty_bucket,
    validate_assessment_integrity,
    validate_authorization_integrity,
    watermark_digest,
)
from .errors import (
    TrustedTimeAuditUnavailableError,
    TrustedTimeDriftError,
    TrustedTimeError,
    TrustedTimePersistenceAmbiguousError,
    TrustedTimeRegressionError,
    TrustedTimeSequenceExhaustedError,
    TrustedTimeSourceDriftError,
    TrustedTimeStateCorruptError,
    TrustedTimeStatePermissionError,
    TrustedTimeTimeoutError,
    TrustedTimeContinuityIneligibleError,
    TrustedTimeTransitionAmbiguousError,
    TrustedTimeTransitionExpiredError,
    TrustedTimeTransitionRejectedError,
    TrustedTimeTransitionReplayError,
    TrustedTimeUnavailableError,
    TrustedTimeUncertainError,
    TrustedTimeUnsynchronizedError,
)


SQLITE_APPLICATION_ID = 0x4D595454  # MYTT
SCHEMA_VERSION = 1
SCHEMA_LABEL = "myuna.trusted-time-provider.v1"
MAX_STATE_BYTES = 1024 * 1024
MAX_SEQUENCE = (1 << 63) - 2

_SCHEMA = """
CREATE TABLE metadata (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
) STRICT;
CREATE TABLE clock_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    source TEXT NOT NULL,
    source_class TEXT NOT NULL,
    authority TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    instant TEXT NOT NULL,
    monotonic_ns INTEGER NOT NULL CHECK (monotonic_ns >= 0),
    boot_id TEXT NOT NULL
) STRICT;
"""


@dataclass(frozen=True, slots=True)
class _State:
    source: str
    source_class: str
    authority: str
    sequence: int
    instant: datetime
    monotonic_ns: int
    boot_id: str


class DurableTrustedTimeProvider:
    """Durably allocate P08-compatible trusted UTC samples.

    Gaps are allowed after an ambiguous commit; reuse or regression is not.
    The provider never reads message, filesystem timestamp, database timestamp,
    model output, Owner content, Profile, session or relevance state.
    """

    def __init__(
        self,
        path: str | Path,
        source: UtcObservationPort,
        *,
        policy: TrustedTimePolicy = TrustedTimePolicy(),
        consumer_watermark: TrustedTimeWatermark | None = None,
        expected_uid: int | None = None,
        audit_sink: TrustedTimeAuditSink | None = None,
        failure_injector: Callable[[str], None] | None = None,
        transition_monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        self.path = Path(path)
        if not self.path.is_absolute():
            raise TrustedTimeStatePermissionError()
        if not isinstance(source, UtcObservationPort):
            raise TrustedTimeUnavailableError()
        self.source = source
        self.policy = policy
        self.expected_uid = os.getuid() if expected_uid is None else expected_uid
        self.consumer_watermark = consumer_watermark
        if consumer_watermark is not None and consumer_watermark.source != policy.source:
            raise TrustedTimeSourceDriftError()
        self.audit_sink = audit_sink
        self.failure_injector = failure_injector
        if not callable(transition_monotonic_ns):
            raise TrustedTimeUnavailableError()
        self.transition_monotonic_ns = transition_monotonic_ns
        self.validate_state()

    @classmethod
    def create(
        cls,
        path: str | Path,
        source: UtcObservationPort,
        **kwargs: object,
    ) -> DurableTrustedTimeProvider:
        if not isinstance(source, UtcObservationPort):
            raise TrustedTimeUnavailableError()
        target = Path(path)
        if not target.is_absolute():
            raise TrustedTimeStatePermissionError()
        policy_value = kwargs.get("policy", TrustedTimePolicy())
        if not isinstance(policy_value, TrustedTimePolicy):
            raise TrustedTimeStateCorruptError()
        watermark_value = kwargs.get("consumer_watermark")
        if watermark_value is not None:
            if not isinstance(watermark_value, TrustedTimeWatermark):
                raise TrustedTimeStateCorruptError()
            if watermark_value.source != policy_value.source:
                raise TrustedTimeSourceDriftError()
        uid_value = kwargs.get("expected_uid")
        uid = os.getuid() if uid_value is None else int(uid_value)
        cls._validate_parent(target.parent, uid)
        if target.exists() or target.is_symlink():
            raise TrustedTimeStatePermissionError()
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(target, flags, 0o600)
        os.close(descriptor)
        try:
            connection = sqlite3.connect(target)
            try:
                connection.execute("PRAGMA journal_mode=DELETE")
                connection.execute("PRAGMA synchronous=FULL")
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
        return cls(target, source, **kwargs)

    @staticmethod
    def _validate_parent(parent: Path, expected_uid: int) -> None:
        try:
            metadata = parent.lstat()
        except OSError:
            raise TrustedTimeUnavailableError() from None
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or parent.is_symlink()
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise TrustedTimeStatePermissionError()

    def _validate_path(self) -> None:
        self._validate_parent(self.path.parent, self.expected_uid)
        try:
            metadata = self.path.lstat()
        except OSError:
            raise TrustedTimeUnavailableError() from None
        if (
            self.path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != self.expected_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise TrustedTimeStatePermissionError()
        if metadata.st_size > MAX_STATE_BYTES:
            raise TrustedTimeStateCorruptError()

    def _connect(self, *, read_only: bool = False) -> sqlite3.Connection:
        self._validate_path()
        try:
            connection = sqlite3.connect(
                f"file:{self.path}?mode={'ro' if read_only else 'rw'}",
                uri=True,
                timeout=float(self.policy.timeout_seconds),
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute(
                f"PRAGMA busy_timeout={int(self.policy.timeout_seconds * 1000)}"
            )
            return connection
        except sqlite3.Error:
            raise TrustedTimeUnavailableError() from None

    @staticmethod
    def _iso(value: datetime) -> str:
        return value.isoformat(timespec="microseconds")

    def _validate_database(self, connection: sqlite3.Connection) -> None:
        try:
            if (
                connection.execute("PRAGMA application_id").fetchone()[0]
                != SQLITE_APPLICATION_ID
                or connection.execute("PRAGMA user_version").fetchone()[0]
                != SCHEMA_VERSION
            ):
                raise TrustedTimeStateCorruptError()
            label = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_label'"
            ).fetchone()
            if label is None or label[0] != SCHEMA_LABEL:
                raise TrustedTimeStateCorruptError()
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise TrustedTimeStateCorruptError()
            if connection.execute("SELECT COUNT(*) FROM clock_state").fetchone()[0] > 1:
                raise TrustedTimeStateCorruptError()
        except TrustedTimeError:
            raise
        except sqlite3.DatabaseError:
            raise TrustedTimeStateCorruptError() from None

    @staticmethod
    def _anchor(state: _State | None) -> ContinuityAnchor | None:
        if state is None:
            return None
        return ContinuityAnchor(
            source=state.source,
            source_class=state.source_class,
            authority=state.authority,
            sequence=state.sequence,
            instant=state.instant,
            monotonic_ns=state.monotonic_ns,
            boot_id=state.boot_id,
        )

    def _validated_state(self, connection: sqlite3.Connection) -> _State | None:
        self._validate_database(connection)
        state = self._read_state(connection)
        ContinuityLedger.validate(connection, self._anchor(state))
        return state

    def validate_state(self) -> None:
        connection = self._connect(read_only=True)
        try:
            self._validated_state(connection)
        finally:
            connection.close()

    def _transition_clock(self) -> int:
        try:
            value = self.transition_monotonic_ns()
        except Exception:
            raise TrustedTimeUnavailableError() from None
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise TrustedTimeUnavailableError()
        return value

    def _floors(
        self,
        state: _State | None,
    ) -> tuple[int, datetime | None]:
        floor_sequence = 0 if state is None else state.sequence
        floor_instant = None if state is None else state.instant
        if self.consumer_watermark is not None:
            floor_sequence = max(floor_sequence, self.consumer_watermark.sequence)
            floor_instant = max(
                value
                for value in (floor_instant, self.consumer_watermark.instant)
                if value is not None
            )
        return floor_sequence, floor_instant

    def assess_continuity(self) -> ContinuityAssessment:
        """Return a source-bound assessment without changing provider state."""

        connection = self._connect(read_only=True)
        try:
            state = self._validated_state(connection)
            observation = self._observe()
            floor_sequence, floor_instant = self._floors(state)
            if floor_instant is not None and observation.instant < floor_instant:
                raise TrustedTimeRegressionError()
            if floor_sequence >= MAX_SEQUENCE:
                raise TrustedTimeSequenceExhaustedError()

            prior_anchor = self._anchor(state)
            signed_residual_microseconds: int | None = None
            if state is None:
                continuity = (
                    "consumer_reconciled"
                    if self.consumer_watermark is not None
                    else "initial"
                )
                status = "within_policy"
                eligibility = "ordinary_sample"
                direction = "within_tolerance"
            elif observation.evidence.authority != state.authority:
                raise TrustedTimeSourceDriftError()
            elif observation.boot_id != state.boot_id:
                continuity = "boot_transition"
                status = "within_policy"
                eligibility = "ordinary_sample"
                direction = "boot_transition"
            else:
                continuity = "same_boot"
                elapsed_ns = observation.monotonic_ns - state.monotonic_ns
                if elapsed_ns < 0:
                    raise TrustedTimeRegressionError()
                expected = state.instant + timedelta(microseconds=elapsed_ns / 1000)
                signed_residual_microseconds = timedelta_microseconds(
                    observation.instant - expected
                )
                maximum = timedelta_microseconds(self.policy.max_drift)
                if signed_residual_microseconds < -maximum:
                    raise TrustedTimeContinuityIneligibleError()
                if signed_residual_microseconds > maximum:
                    status = "forward_transition_required"
                    eligibility = "explicit_forward_transition"
                    direction = "forward"
                else:
                    status = "within_policy"
                    eligibility = "ordinary_sample"
                    direction = "within_tolerance"

            candidate = ContinuityAnchor(
                source=self.policy.source,
                source_class=self.policy.source_class,
                authority=observation.evidence.authority,
                sequence=floor_sequence + 1,
                instant=observation.instant,
                monotonic_ns=observation.monotonic_ns,
                boot_id=observation.boot_id,
            )
            return ContinuityAssessment.create(
                status=status,
                continuity=continuity,
                eligibility=eligibility,
                direction=direction,
                drift_bucket_value=drift_bucket(
                    signed_residual_microseconds,
                    continuity,
                ),
                uncertainty_bucket_value=uncertainty_bucket(
                    observation.evidence.uncertainty
                ),
                source_binding_digest_value=source_binding_digest(
                    self.policy,
                    observation,
                ),
                prior_anchor=prior_anchor,
                candidate=candidate,
                consumer_watermark_digest_value=watermark_digest(
                    self.consumer_watermark
                ),
                evidence_digest_value=evidence_digest(observation, candidate),
                policy_digest_value=policy_digest(self.policy),
                signed_residual_microseconds=signed_residual_microseconds,
                observation=observation,
                assessed_monotonic_ns=self._transition_clock(),
            )
        finally:
            connection.close()

    def _validate_transition_inputs(
        self,
        assessment: ContinuityAssessment,
        authorization: ForwardContinuityAuthorization,
        *,
        enforce_age: bool,
    ) -> tuple[ContinuityAnchor, UtcObservation, int]:
        validate_assessment_integrity(
            assessment,
            policy=self.policy,
            consumer_watermark=self.consumer_watermark,
        )
        validate_authorization_integrity(authorization, assessment)
        if (
            assessment.status != "forward_transition_required"
            or assessment.continuity != "same_boot"
            or assessment.eligibility != "explicit_forward_transition"
            or assessment.direction != "forward"
            or assessment._prior_anchor is None
            or assessment._candidate is None
            or assessment._observation is None
            or assessment._signed_residual_microseconds is None
            or assessment._signed_residual_microseconds
            <= timedelta_microseconds(self.policy.max_drift)
            or not (
                authorization._residual_lower_microseconds
                <= assessment._signed_residual_microseconds
                <= authorization._residual_upper_microseconds
            )
        ):
            raise TrustedTimeTransitionRejectedError()
        if enforce_age:
            age = self._transition_clock() - assessment._assessed_monotonic_ns
            if age < 0:
                raise TrustedTimeTransitionRejectedError()
            if age > authorization.max_age_seconds * 1_000_000_000:
                raise TrustedTimeTransitionExpiredError()
        return (
            assessment._prior_anchor,
            assessment._observation,
            assessment._signed_residual_microseconds,
        )

    def transition_forward(
        self,
        assessment: ContinuityAssessment,
        authorization: ForwardContinuityAuthorization,
    ) -> ForwardContinuityTransitionReceipt:
        """Consume one explicit authorization and move one anchor only forward."""

        prior_anchor, observation, _residual = self._validate_transition_inputs(
            assessment,
            authorization,
            enforce_age=True,
        )
        candidate = assessment._candidate
        assert candidate is not None
        connection = self._connect()
        committed = False
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as error:
                if error.sqlite_errorcode in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
                    raise TrustedTimeTimeoutError() from None
                raise TrustedTimeUnavailableError() from None
            state = self._validated_state(connection)
            current_anchor = self._anchor(state)
            ledger = ContinuityLedger.validate(connection, current_anchor)
            if ContinuityLedger.transition_for_id(ledger, authorization.transition_id):
                raise TrustedTimeTransitionReplayError()
            if current_anchor is None or current_anchor.anchor_digest != prior_anchor.anchor_digest:
                raise TrustedTimeTransitionRejectedError()
            floor_sequence, floor_instant = self._floors(state)
            if (
                candidate.source != self.policy.source
                or candidate.source_class != self.policy.source_class
                or candidate.authority != current_anchor.authority
                or candidate.boot_id != current_anchor.boot_id
                or candidate.sequence != floor_sequence + 1
                or candidate.sequence <= current_anchor.sequence
                or candidate.instant < current_anchor.instant
                or (floor_instant is not None and candidate.instant < floor_instant)
                or candidate.instant != observation.instant
                or candidate.monotonic_ns != observation.monotonic_ns
            ):
                raise TrustedTimeTransitionRejectedError()
            history_record_digest, transition_digest = ContinuityLedger.append(
                connection,
                current_anchor=current_anchor,
                candidate=candidate,
                assessment=assessment,
                authorization=authorization,
            )
            if self.failure_injector is not None:
                self.failure_injector("transition_after_history")
            connection.execute(
                "UPDATE clock_state SET source=?, source_class=?, authority=?, "
                "sequence=?, instant=?, monotonic_ns=?, boot_id=? WHERE singleton=1",
                (
                    candidate.source,
                    candidate.source_class,
                    candidate.authority,
                    candidate.sequence,
                    self._iso(candidate.instant),
                    candidate.monotonic_ns,
                    candidate.boot_id,
                ),
            )
            if connection.execute("SELECT changes()").fetchone()[0] != 1:
                raise TrustedTimeStateCorruptError()
            if self.failure_injector is not None:
                self.failure_injector("transition_before_commit")
            try:
                connection.commit()
                committed = True
            except sqlite3.Error:
                raise TrustedTimeTransitionAmbiguousError() from None
            try:
                if self.failure_injector is not None:
                    self.failure_injector("transition_after_commit")
                self._emit(
                    operation="forward_transition",
                    outcome="accepted",
                    error=None,
                    continuity="same_boot",
                    uncertainty=observation.evidence.uncertainty,
                    drift=timedelta(microseconds=abs(_residual)),
                )
            except Exception:
                raise TrustedTimeTransitionAmbiguousError() from None
            return ForwardContinuityTransitionReceipt(
                transition_id=authorization.transition_id,
                prior_anchor_digest=current_anchor.anchor_digest,
                candidate_digest=candidate.anchor_digest,
                history_record_digest=history_record_digest,
                transition_digest=transition_digest,
                authorization_digest=authorization.authorization_digest,
            )
        except TrustedTimeError:
            if connection.in_transaction:
                connection.rollback()
            raise
        except (sqlite3.Error, OSError, RuntimeError):
            if connection.in_transaction:
                connection.rollback()
            if committed:
                raise TrustedTimeTransitionAmbiguousError() from None
            raise TrustedTimeUnavailableError() from None
        finally:
            connection.close()

    def reconcile_forward_transition(
        self,
        assessment: ContinuityAssessment,
        authorization: ForwardContinuityAuthorization,
    ) -> ForwardContinuityReconciliation:
        """Read back one uncertain transition without consuming it again."""

        prior_anchor, _observation, _residual = self._validate_transition_inputs(
            assessment,
            authorization,
            enforce_age=False,
        )
        connection = self._connect(read_only=True)
        try:
            state = self._validated_state(connection)
            current_anchor = self._anchor(state)
            ledger = ContinuityLedger.validate(connection, current_anchor)
            transition = ContinuityLedger.transition_for_id(
                ledger,
                authorization.transition_id,
            )
            candidate = assessment._candidate
            if candidate is None:
                raise TrustedTimeTransitionAmbiguousError()
            if transition is None:
                if (
                    current_anchor is not None
                    and current_anchor.anchor_digest == prior_anchor.anchor_digest
                ):
                    return ForwardContinuityReconciliation(
                        transition_id=authorization.transition_id,
                        status="not_committed",
                        authorization_digest=authorization.authorization_digest,
                        transition_digest=None,
                    )
                raise TrustedTimeTransitionAmbiguousError()
            if (
                transition["assessment_digest"] != assessment.assessment_digest
                or transition["authorization_digest"]
                != authorization.authorization_digest
                or transition["prior_anchor_digest"] != prior_anchor.anchor_digest
                or transition["candidate_digest"] != assessment.candidate_digest
                or current_anchor is None
                or current_anchor.sequence < candidate.sequence
                or current_anchor.instant < candidate.instant
            ):
                raise TrustedTimeTransitionAmbiguousError()
            return ForwardContinuityReconciliation(
                transition_id=authorization.transition_id,
                status="committed",
                authorization_digest=authorization.authorization_digest,
                transition_digest=transition["transition_digest"],  # type: ignore[arg-type]
            )
        finally:
            connection.close()

    def _read_state(self, connection: sqlite3.Connection) -> _State | None:
        try:
            row = connection.execute(
                "SELECT source, source_class, authority, sequence, instant, "
                "monotonic_ns, boot_id FROM clock_state WHERE singleton=1"
            ).fetchone()
            if row is None:
                return None
            state = _State(
                source=safe_label(row["source"]),
                source_class=safe_label(row["source_class"]),
                authority=safe_label(row["authority"]),
                sequence=int(row["sequence"]),
                instant=utc(datetime.fromisoformat(row["instant"])),
                monotonic_ns=int(row["monotonic_ns"]),
                boot_id=safe_label(row["boot_id"]),
            )
            if (
                state.source != self.policy.source
                or state.source_class != self.policy.source_class
                or state.sequence < 1
                or state.sequence > MAX_SEQUENCE
                or state.monotonic_ns < 0
            ):
                raise TrustedTimeStateCorruptError()
            return state
        except TrustedTimeError:
            raise
        except (KeyError, TypeError, ValueError, sqlite3.DatabaseError):
            raise TrustedTimeStateCorruptError() from None

    @staticmethod
    def _uncertainty_bucket(value: timedelta) -> str:
        milliseconds = value.total_seconds() * 1000
        if milliseconds <= 10:
            return "le_10ms"
        if milliseconds <= 100:
            return "le_100ms"
        if milliseconds <= 1000:
            return "le_1s"
        return "over_limit"

    @staticmethod
    def _drift_bucket(value: timedelta | None, continuity: str) -> str:
        if continuity != "same_boot" or value is None:
            return continuity
        milliseconds = value.total_seconds() * 1000
        if milliseconds <= 10:
            return "le_10ms"
        if milliseconds <= 100:
            return "le_100ms"
        if milliseconds <= 1000:
            return "le_1s"
        if milliseconds <= 2000:
            return "le_2s"
        return "over_limit"

    def _emit(
        self,
        *,
        operation: str = "sample",
        outcome: str,
        error: TrustedTimeError | None,
        continuity: str,
        uncertainty: timedelta = timedelta(0),
        drift: timedelta | None = None,
    ) -> None:
        if self.audit_sink is None:
            return
        event = TrustedTimeAuditEvent(
            operation=operation,
            outcome=outcome,
            error_category=None if error is None else error.code,
            continuity=continuity,
            source_class=self.policy.source_class,
            uncertainty_bucket=self._uncertainty_bucket(uncertainty),
            drift_bucket=self._drift_bucket(drift, continuity),
            retryable=False if error is None else error.retryable,
        )
        try:
            self.audit_sink.emit(event)
        except Exception:
            raise TrustedTimeAuditUnavailableError() from None

    def _fail(
        self,
        error: TrustedTimeError,
        *,
        continuity: str,
        observation: UtcObservation | None = None,
        drift: timedelta | None = None,
    ) -> None:
        self._emit(
            outcome="rejected",
            error=error,
            continuity=continuity,
            uncertainty=(
                timedelta(0) if observation is None else observation.evidence.uncertainty
            ),
            drift=drift,
        )
        raise error

    def _observe(self) -> UtcObservation:
        try:
            observation = self.source.observe(float(self.policy.timeout_seconds))
        except TrustedTimeError:
            raise
        except Exception:
            raise TrustedTimeUnavailableError() from None
        if not isinstance(observation, UtcObservation):
            raise TrustedTimeUnavailableError()
        if not observation.evidence.synchronized:
            raise TrustedTimeUnsynchronizedError()
        if observation.evidence.uncertainty > self.policy.max_uncertainty:
            raise TrustedTimeUncertainError()
        return observation

    def sample(self) -> TrustedTimeSample:
        connection = self._connect()
        continuity = "unknown"
        observation: UtcObservation | None = None
        drift: timedelta | None = None
        committed = False
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as error:
                if error.sqlite_errorcode in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
                    raise TrustedTimeTimeoutError() from None
                raise TrustedTimeUnavailableError() from None
            state = self._validated_state(connection)
            observation = self._observe()
            floor_sequence = 0 if state is None else state.sequence
            floor_instant = None if state is None else state.instant
            if self.consumer_watermark is not None:
                floor_sequence = max(floor_sequence, self.consumer_watermark.sequence)
                floor_instant = max(
                    value
                    for value in (floor_instant, self.consumer_watermark.instant)
                    if value is not None
                )
            if state is None:
                continuity = (
                    "consumer_reconciled"
                    if self.consumer_watermark is not None
                    else "initial"
                )
            elif observation.evidence.authority != state.authority:
                raise TrustedTimeSourceDriftError()
            elif observation.boot_id == state.boot_id:
                continuity = "same_boot"
                elapsed_ns = observation.monotonic_ns - state.monotonic_ns
                if elapsed_ns < 0:
                    raise TrustedTimeRegressionError()
                expected = state.instant + timedelta(microseconds=elapsed_ns / 1000)
                drift = abs(observation.instant - expected)
                if drift > self.policy.max_drift:
                    raise TrustedTimeDriftError()
            else:
                continuity = "restart"
            if floor_instant is not None and observation.instant < floor_instant:
                raise TrustedTimeRegressionError()
            if floor_sequence >= MAX_SEQUENCE:
                raise TrustedTimeSequenceExhaustedError()
            sequence = floor_sequence + 1
            connection.execute(
                "INSERT INTO clock_state(singleton, source, source_class, authority, "
                "sequence, instant, monotonic_ns, boot_id) VALUES(1, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(singleton) DO UPDATE SET source=excluded.source, "
                "source_class=excluded.source_class, authority=excluded.authority, "
                "sequence=excluded.sequence, instant=excluded.instant, "
                "monotonic_ns=excluded.monotonic_ns, boot_id=excluded.boot_id",
                (
                    self.policy.source,
                    self.policy.source_class,
                    observation.evidence.authority,
                    sequence,
                    self._iso(observation.instant),
                    observation.monotonic_ns,
                    observation.boot_id,
                ),
            )
            if self.failure_injector is not None:
                self.failure_injector("before_commit")
            try:
                connection.commit()
                committed = True
            except sqlite3.Error:
                raise TrustedTimePersistenceAmbiguousError() from None
            if self.failure_injector is not None:
                try:
                    self.failure_injector("after_commit")
                except Exception:
                    raise TrustedTimePersistenceAmbiguousError() from None
            sample = TrustedTimeSample(
                instant=observation.instant,
                source=self.policy.source,
                source_class=self.policy.source_class,
                sequence=sequence,
                authority=observation.evidence.authority,
                uncertainty_microseconds=int(
                    observation.evidence.uncertainty.total_seconds() * 1_000_000
                ),
                synchronized=observation.evidence.synchronized,
                boot_id=observation.boot_id,
                monotonic_ns=observation.monotonic_ns,
            )
            self._emit(
                outcome="accepted",
                error=None,
                continuity=continuity,
                uncertainty=observation.evidence.uncertainty,
                drift=drift,
            )
            return sample
        except TrustedTimeError as error:
            if connection.in_transaction:
                connection.rollback()
            if isinstance(error, TrustedTimeAuditUnavailableError):
                raise
            if isinstance(error, TrustedTimePersistenceAmbiguousError) or committed:
                self._emit(
                    outcome="ambiguous",
                    error=error,
                    continuity=continuity,
                    uncertainty=(
                        timedelta(0)
                        if observation is None
                        else observation.evidence.uncertainty
                    ),
                    drift=drift,
                )
                raise
            self._fail(
                error,
                continuity=continuity,
                observation=observation,
                drift=drift,
            )
        except (sqlite3.Error, OSError, RuntimeError):
            if connection.in_transaction:
                connection.rollback()
            self._fail(
                TrustedTimeUnavailableError(),
                continuity=continuity,
                observation=observation,
                drift=drift,
            )
        finally:
            connection.close()
