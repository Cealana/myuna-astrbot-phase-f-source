from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from hashlib import sha256
import json
import re
import sqlite3
from typing import Mapping

from .contracts import (
    TrustedTimePolicy,
    TrustedTimeWatermark,
    UtcObservation,
    safe_label,
    utc,
)
from .errors import (
    TrustedTimeContinuityIneligibleError,
    TrustedTimeStateCorruptError,
    TrustedTimeTransitionRejectedError,
    TrustedTimeTransitionReplayError,
)


ASSESSMENT_SCHEMA = "myuna.trusted-time-continuity-assessment.v1"
AUTHORIZATION_SCHEMA = "myuna.trusted-time-forward-transition-authorization.v1"
RECEIPT_SCHEMA = "myuna.trusted-time-forward-transition-receipt.v1"
RECONCILIATION_SCHEMA = "myuna.trusted-time-forward-transition-reconciliation.v1"
CONTINUITY_EXTENSION_SCHEMA = "myuna.trusted-time-continuity-ledger.v1"
HISTORY_RECORD_SCHEMA = "myuna.trusted-time-anchor-history-record.v1"
TRANSITION_RECORD_SCHEMA = "myuna.trusted-time-forward-transition-record.v1"
ZERO_DIGEST = "0" * 64

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ASSESSMENT_STATUSES = frozenset({"within_policy", "forward_transition_required"})
_CONTINUITIES = frozenset({"initial", "consumer_reconciled", "same_boot", "boot_transition"})
_ELIGIBILITIES = frozenset({"ordinary_sample", "explicit_forward_transition"})
_DIRECTIONS = frozenset({"within_tolerance", "forward", "boot_transition"})
_DRIFT_BUCKETS = frozenset(
    {
        "initial",
        "consumer_reconciled",
        "boot_transition",
        "le_10ms",
        "le_100ms",
        "le_1s",
        "le_2s",
        "gt_2s_le_5s",
        "gt_5s_le_30s",
        "gt_30s",
    }
)
_UNCERTAINTY_BUCKETS = frozenset({"le_10ms", "le_100ms", "le_1s", "over_limit"})

_CONTINUITY_SCHEMA_SQL = """
CREATE TABLE continuity_anchor_history (
    history_id INTEGER PRIMARY KEY CHECK (history_id > 0),
    transition_id TEXT NOT NULL UNIQUE,
    prior_anchor_digest TEXT NOT NULL UNIQUE,
    prior_history_head TEXT NOT NULL,
    record_digest TEXT NOT NULL UNIQUE,
    payload TEXT NOT NULL
) STRICT;
CREATE TABLE continuity_transitions (
    transition_id TEXT PRIMARY KEY NOT NULL,
    history_id INTEGER NOT NULL UNIQUE,
    assessment_digest TEXT NOT NULL UNIQUE,
    authorization_digest TEXT NOT NULL UNIQUE,
    prior_anchor_digest TEXT NOT NULL UNIQUE,
    candidate_digest TEXT NOT NULL UNIQUE,
    history_record_digest TEXT NOT NULL UNIQUE,
    prior_history_head TEXT NOT NULL,
    transition_digest TEXT NOT NULL UNIQUE,
    payload TEXT NOT NULL
) STRICT;
"""

_METADATA_KEYS = {
    "continuity_transition_schema",
    "continuity_transition_count",
    "continuity_transition_head",
}
_TABLE_NAMES = {"continuity_anchor_history", "continuity_transitions"}


def canonical(payload: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(
            dict(payload),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        raise TrustedTimeStateCorruptError() from None


def digest(domain: str, payload: Mapping[str, object]) -> str:
    return sha256(domain.encode("ascii") + b"\0" + canonical(payload)).hexdigest()


def require_digest(value: object) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise TrustedTimeStateCorruptError()
    return value


def timedelta_microseconds(value: timedelta) -> int:
    if not isinstance(value, timedelta):
        raise TrustedTimeStateCorruptError()
    return ((value.days * 86_400) + value.seconds) * 1_000_000 + value.microseconds


def instant_text(value: datetime) -> str:
    return utc(value).isoformat(timespec="microseconds")


@dataclass(frozen=True, slots=True)
class ContinuityAnchor:
    source: str
    source_class: str
    authority: str
    sequence: int
    instant: datetime
    monotonic_ns: int
    boot_id: str

    def __post_init__(self) -> None:
        safe_label(self.source)
        safe_label(self.source_class)
        safe_label(self.authority)
        safe_label(self.boot_id)
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 1
            or isinstance(self.monotonic_ns, bool)
            or not isinstance(self.monotonic_ns, int)
            or self.monotonic_ns < 0
        ):
            raise TrustedTimeStateCorruptError()
        object.__setattr__(self, "instant", utc(self.instant))

    def payload(self) -> dict[str, object]:
        return {
            "authority": self.authority,
            "boot_id": self.boot_id,
            "instant": instant_text(self.instant),
            "monotonic_ns": self.monotonic_ns,
            "sequence": self.sequence,
            "source": self.source,
            "source_class": self.source_class,
        }

    @property
    def anchor_digest(self) -> str:
        return digest("myuna-trusted-time-anchor-v1", self.payload())

    @classmethod
    def from_payload(cls, payload: object) -> ContinuityAnchor:
        expected = {
            "authority",
            "boot_id",
            "instant",
            "monotonic_ns",
            "sequence",
            "source",
            "source_class",
        }
        if not isinstance(payload, Mapping) or set(payload) != expected:
            raise TrustedTimeStateCorruptError()
        try:
            instant = datetime.fromisoformat(payload["instant"])  # type: ignore[arg-type]
        except (TypeError, ValueError):
            raise TrustedTimeStateCorruptError() from None
        return cls(
            source=payload["source"],  # type: ignore[arg-type]
            source_class=payload["source_class"],  # type: ignore[arg-type]
            authority=payload["authority"],  # type: ignore[arg-type]
            sequence=payload["sequence"],  # type: ignore[arg-type]
            instant=instant,
            monotonic_ns=payload["monotonic_ns"],  # type: ignore[arg-type]
            boot_id=payload["boot_id"],  # type: ignore[arg-type]
        )


def policy_digest(policy: TrustedTimePolicy) -> str:
    if not isinstance(policy, TrustedTimePolicy):
        raise TrustedTimeStateCorruptError()
    return digest(
        "myuna-trusted-time-policy-v1",
        {
            "consumer_id": policy.consumer_id,
            "max_drift_microseconds": timedelta_microseconds(policy.max_drift),
            "max_uncertainty_microseconds": timedelta_microseconds(policy.max_uncertainty),
            "source": policy.source,
            "source_class": policy.source_class,
            "timeout_microseconds": int(float(policy.timeout_seconds) * 1_000_000),
        },
    )


def watermark_digest(watermark: TrustedTimeWatermark | None) -> str:
    if watermark is None:
        return digest("myuna-trusted-time-consumer-watermark-v1", {"state": "absent"})
    return digest(
        "myuna-trusted-time-consumer-watermark-v1",
        {
            "instant": instant_text(watermark.instant),
            "sequence": watermark.sequence,
            "source": watermark.source,
            "state": "present",
        },
    )


def source_binding_digest(
    policy: TrustedTimePolicy,
    observation: UtcObservation,
) -> str:
    return digest(
        "myuna-trusted-time-source-binding-v1",
        {
            "authority": observation.evidence.authority,
            "boot_id": observation.boot_id,
            "source": policy.source,
            "source_class": policy.source_class,
        },
    )


def evidence_digest(observation: UtcObservation, candidate: ContinuityAnchor) -> str:
    return digest(
        "myuna-trusted-time-observation-evidence-v1",
        {
            "authority": observation.evidence.authority,
            "candidate_digest": candidate.anchor_digest,
            "synchronized": observation.evidence.synchronized,
            "uncertainty_microseconds": timedelta_microseconds(
                observation.evidence.uncertainty
            ),
        },
    )


def uncertainty_bucket(value: timedelta) -> str:
    microseconds = timedelta_microseconds(value)
    if microseconds <= 10_000:
        return "le_10ms"
    if microseconds <= 100_000:
        return "le_100ms"
    if microseconds <= 1_000_000:
        return "le_1s"
    return "over_limit"


def drift_bucket(residual_microseconds: int | None, continuity: str) -> str:
    if continuity != "same_boot" or residual_microseconds is None:
        return continuity
    absolute = abs(residual_microseconds)
    if absolute <= 10_000:
        return "le_10ms"
    if absolute <= 100_000:
        return "le_100ms"
    if absolute <= 1_000_000:
        return "le_1s"
    if absolute <= 2_000_000:
        return "le_2s"
    if absolute <= 5_000_000:
        return "gt_2s_le_5s"
    if absolute <= 30_000_000:
        return "gt_5s_le_30s"
    return "gt_30s"


@dataclass(frozen=True, slots=True)
class ContinuityAssessment:
    schema: str
    status: str
    continuity: str
    eligibility: str
    direction: str
    drift_bucket: str
    uncertainty_bucket: str
    source_binding_digest: str
    prior_anchor_digest: str
    candidate_digest: str
    consumer_watermark_digest: str
    evidence_digest: str
    policy_digest: str
    assessment_clock_digest: str
    assessment_digest: str
    persistent_mutation: bool = False
    _prior_anchor: ContinuityAnchor | None = field(repr=False, compare=False, default=None)
    _candidate: ContinuityAnchor | None = field(repr=False, compare=False, default=None)
    _observation: UtcObservation | None = field(repr=False, compare=False, default=None)
    _signed_residual_microseconds: int | None = field(
        repr=False,
        compare=False,
        default=None,
    )
    _assessed_monotonic_ns: int = field(repr=False, compare=False, default=0)

    def __post_init__(self) -> None:
        if (
            self.schema != ASSESSMENT_SCHEMA
            or self.status not in _ASSESSMENT_STATUSES
            or self.continuity not in _CONTINUITIES
            or self.eligibility not in _ELIGIBILITIES
            or self.direction not in _DIRECTIONS
            or self.drift_bucket not in _DRIFT_BUCKETS
            or self.uncertainty_bucket not in _UNCERTAINTY_BUCKETS
            or not isinstance(self.persistent_mutation, bool)
            or self.persistent_mutation
            or isinstance(self._assessed_monotonic_ns, bool)
            or not isinstance(self._assessed_monotonic_ns, int)
            or self._assessed_monotonic_ns < 0
        ):
            raise TrustedTimeStateCorruptError()
        for value in (
            self.source_binding_digest,
            self.prior_anchor_digest,
            self.candidate_digest,
            self.consumer_watermark_digest,
            self.evidence_digest,
            self.policy_digest,
            self.assessment_clock_digest,
            self.assessment_digest,
        ):
            require_digest(value)

    def _stable_payload(self) -> dict[str, object]:
        return {
            "assessment_clock_digest": self.assessment_clock_digest,
            "candidate_digest": self.candidate_digest,
            "consumer_watermark_digest": self.consumer_watermark_digest,
            "continuity": self.continuity,
            "direction": self.direction,
            "drift_bucket": self.drift_bucket,
            "eligibility": self.eligibility,
            "evidence_digest": self.evidence_digest,
            "persistent_mutation": self.persistent_mutation,
            "policy_digest": self.policy_digest,
            "prior_anchor_digest": self.prior_anchor_digest,
            "schema": self.schema,
            "source_binding_digest": self.source_binding_digest,
            "status": self.status,
            "uncertainty_bucket": self.uncertainty_bucket,
        }

    def public_payload(self) -> dict[str, object]:
        return {**self._stable_payload(), "assessment_digest": self.assessment_digest}

    def expected_digest(self) -> str:
        return digest("myuna-trusted-time-continuity-assessment-v1", self._stable_payload())

    @classmethod
    def create(
        cls,
        *,
        status: str,
        continuity: str,
        eligibility: str,
        direction: str,
        drift_bucket_value: str,
        uncertainty_bucket_value: str,
        source_binding_digest_value: str,
        prior_anchor: ContinuityAnchor | None,
        candidate: ContinuityAnchor,
        consumer_watermark_digest_value: str,
        evidence_digest_value: str,
        policy_digest_value: str,
        signed_residual_microseconds: int | None,
        observation: UtcObservation,
        assessed_monotonic_ns: int,
    ) -> ContinuityAssessment:
        values: dict[str, object] = {
            "assessment_clock_digest": digest(
                "myuna-trusted-time-assessment-clock-v1",
                {"monotonic_ns": assessed_monotonic_ns},
            ),
            "candidate_digest": candidate.anchor_digest,
            "consumer_watermark_digest": consumer_watermark_digest_value,
            "continuity": continuity,
            "direction": direction,
            "drift_bucket": drift_bucket_value,
            "eligibility": eligibility,
            "evidence_digest": evidence_digest_value,
            "persistent_mutation": False,
            "policy_digest": policy_digest_value,
            "prior_anchor_digest": (
                ZERO_DIGEST if prior_anchor is None else prior_anchor.anchor_digest
            ),
            "schema": ASSESSMENT_SCHEMA,
            "source_binding_digest": source_binding_digest_value,
            "status": status,
            "uncertainty_bucket": uncertainty_bucket_value,
        }
        return cls(
            **values,  # type: ignore[arg-type]
            assessment_digest=digest(
                "myuna-trusted-time-continuity-assessment-v1",
                values,
            ),
            _prior_anchor=prior_anchor,
            _candidate=candidate,
            _observation=observation,
            _signed_residual_microseconds=signed_residual_microseconds,
            _assessed_monotonic_ns=assessed_monotonic_ns,
        )


@dataclass(frozen=True, slots=True)
class ForwardContinuityAuthorization:
    schema: str
    transition_id: str
    direction: str
    max_attempts: int
    max_age_seconds: int
    assessment_digest: str
    prior_anchor_digest: str
    candidate_digest: str
    consumer_watermark_digest: str
    policy_digest: str
    source_binding_digest: str
    assessment_evidence_digest: str
    source_contract_digest: str
    source_evidence_digest: str
    lineage_digest: str
    authorization_identity_digest: str
    residual_window_digest: str
    authorization_digest: str
    _residual_lower_microseconds: int = field(repr=False, compare=False)
    _residual_upper_microseconds: int = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        safe_label(self.transition_id)
        if (
            self.schema != AUTHORIZATION_SCHEMA
            or self.direction != "forward"
            or self.max_attempts != 1
            or isinstance(self.max_age_seconds, bool)
            or not isinstance(self.max_age_seconds, int)
            or not 1 <= self.max_age_seconds <= 300
            or isinstance(self._residual_lower_microseconds, bool)
            or isinstance(self._residual_upper_microseconds, bool)
            or self._residual_lower_microseconds <= 0
            or self._residual_upper_microseconds < self._residual_lower_microseconds
        ):
            raise TrustedTimeStateCorruptError()
        for value in (
            self.assessment_digest,
            self.prior_anchor_digest,
            self.candidate_digest,
            self.consumer_watermark_digest,
            self.policy_digest,
            self.source_binding_digest,
            self.assessment_evidence_digest,
            self.source_contract_digest,
            self.source_evidence_digest,
            self.lineage_digest,
            self.authorization_identity_digest,
            self.residual_window_digest,
            self.authorization_digest,
        ):
            require_digest(value)

    def _stable_payload(self) -> dict[str, object]:
        return {
            "assessment_digest": self.assessment_digest,
            "assessment_evidence_digest": self.assessment_evidence_digest,
            "authorization_identity_digest": self.authorization_identity_digest,
            "candidate_digest": self.candidate_digest,
            "consumer_watermark_digest": self.consumer_watermark_digest,
            "direction": self.direction,
            "lineage_digest": self.lineage_digest,
            "max_age_seconds": self.max_age_seconds,
            "max_attempts": self.max_attempts,
            "policy_digest": self.policy_digest,
            "prior_anchor_digest": self.prior_anchor_digest,
            "residual_window_digest": self.residual_window_digest,
            "schema": self.schema,
            "source_binding_digest": self.source_binding_digest,
            "source_contract_digest": self.source_contract_digest,
            "source_evidence_digest": self.source_evidence_digest,
            "transition_id": self.transition_id,
        }

    def public_payload(self) -> dict[str, object]:
        return {**self._stable_payload(), "authorization_digest": self.authorization_digest}

    def expected_digest(self) -> str:
        return digest("myuna-trusted-time-forward-authorization-v1", self._stable_payload())

    def expected_window_digest(self) -> str:
        return digest(
            "myuna-trusted-time-forward-residual-window-v1",
            {
                "lower_microseconds": self._residual_lower_microseconds,
                "upper_microseconds": self._residual_upper_microseconds,
            },
        )

    @classmethod
    def bind(
        cls,
        assessment: ContinuityAssessment,
        *,
        transition_id: str,
        source_contract_digest: str,
        source_evidence_digest: str,
        lineage_digest: str,
        authorization_identity_digest: str,
        residual_tolerance_microseconds: int,
        max_age_seconds: int,
    ) -> ForwardContinuityAuthorization:
        if (
            not isinstance(assessment, ContinuityAssessment)
            or assessment.status != "forward_transition_required"
            or assessment.eligibility != "explicit_forward_transition"
            or assessment.direction != "forward"
            or assessment._signed_residual_microseconds is None
            or assessment._signed_residual_microseconds <= 0
        ):
            raise TrustedTimeContinuityIneligibleError()
        if (
            isinstance(residual_tolerance_microseconds, bool)
            or not isinstance(residual_tolerance_microseconds, int)
            or not 0 <= residual_tolerance_microseconds <= 1_000_000
        ):
            raise TrustedTimeTransitionRejectedError()
        lower = max(1, assessment._signed_residual_microseconds - residual_tolerance_microseconds)
        upper = assessment._signed_residual_microseconds + residual_tolerance_microseconds
        window = digest(
            "myuna-trusted-time-forward-residual-window-v1",
            {"lower_microseconds": lower, "upper_microseconds": upper},
        )
        values: dict[str, object] = {
            "assessment_digest": assessment.assessment_digest,
            "assessment_evidence_digest": assessment.evidence_digest,
            "authorization_identity_digest": require_digest(authorization_identity_digest),
            "candidate_digest": assessment.candidate_digest,
            "consumer_watermark_digest": assessment.consumer_watermark_digest,
            "direction": "forward",
            "lineage_digest": require_digest(lineage_digest),
            "max_age_seconds": max_age_seconds,
            "max_attempts": 1,
            "policy_digest": assessment.policy_digest,
            "prior_anchor_digest": assessment.prior_anchor_digest,
            "residual_window_digest": window,
            "schema": AUTHORIZATION_SCHEMA,
            "source_binding_digest": assessment.source_binding_digest,
            "source_contract_digest": require_digest(source_contract_digest),
            "source_evidence_digest": require_digest(source_evidence_digest),
            "transition_id": transition_id,
        }
        return cls(
            **values,  # type: ignore[arg-type]
            authorization_digest=digest(
                "myuna-trusted-time-forward-authorization-v1",
                values,
            ),
            _residual_lower_microseconds=lower,
            _residual_upper_microseconds=upper,
        )


@dataclass(frozen=True, slots=True)
class ForwardContinuityTransitionReceipt:
    transition_id: str
    prior_anchor_digest: str
    candidate_digest: str
    history_record_digest: str
    transition_digest: str
    authorization_digest: str
    status: str = "committed"
    sequence_relation: str = "strictly_advanced"
    persistent_mutation: bool = True
    schema: str = RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        safe_label(self.transition_id)
        if (
            self.schema != RECEIPT_SCHEMA
            or self.status != "committed"
            or self.sequence_relation != "strictly_advanced"
            or self.persistent_mutation is not True
        ):
            raise TrustedTimeStateCorruptError()
        for value in (
            self.prior_anchor_digest,
            self.candidate_digest,
            self.history_record_digest,
            self.transition_digest,
            self.authorization_digest,
        ):
            require_digest(value)

    def public_payload(self) -> dict[str, object]:
        return {
            "authorization_digest": self.authorization_digest,
            "candidate_digest": self.candidate_digest,
            "history_record_digest": self.history_record_digest,
            "persistent_mutation": self.persistent_mutation,
            "prior_anchor_digest": self.prior_anchor_digest,
            "schema": self.schema,
            "sequence_relation": self.sequence_relation,
            "status": self.status,
            "transition_digest": self.transition_digest,
            "transition_id": self.transition_id,
        }


@dataclass(frozen=True, slots=True)
class ForwardContinuityReconciliation:
    transition_id: str
    status: str
    authorization_digest: str
    transition_digest: str | None
    persistent_mutation: bool = False
    schema: str = RECONCILIATION_SCHEMA

    def __post_init__(self) -> None:
        safe_label(self.transition_id)
        if (
            self.schema != RECONCILIATION_SCHEMA
            or self.status not in {"committed", "not_committed"}
            or self.persistent_mutation is not False
            or (self.status == "committed") != (self.transition_digest is not None)
        ):
            raise TrustedTimeStateCorruptError()
        require_digest(self.authorization_digest)
        if self.transition_digest is not None:
            require_digest(self.transition_digest)

    def public_payload(self) -> dict[str, object]:
        return {
            "authorization_digest": self.authorization_digest,
            "persistent_mutation": self.persistent_mutation,
            "schema": self.schema,
            "status": self.status,
            "transition_digest": self.transition_digest,
            "transition_id": self.transition_id,
        }


@dataclass(frozen=True, slots=True)
class ContinuityLedgerState:
    present: bool
    count: int
    head: str
    transitions: tuple[dict[str, object], ...] = ()


class ContinuityLedger:
    @staticmethod
    def _metadata(connection: sqlite3.Connection) -> dict[str, str]:
        rows = connection.execute(
            "SELECT key, value FROM metadata WHERE key IN "
            "('continuity_transition_schema','continuity_transition_count',"
            "'continuity_transition_head')"
        ).fetchall()
        return {str(row[0]): str(row[1]) for row in rows}

    @staticmethod
    def _tables(connection: sqlite3.Connection) -> set[str]:
        rows = connection.execute(
            "SELECT name FROM sqlite_schema WHERE type='table' AND name IN "
            "('continuity_anchor_history','continuity_transitions')"
        ).fetchall()
        return {str(row[0]) for row in rows}

    @staticmethod
    def _parse_payload(raw: object, expected: set[str]) -> dict[str, object]:
        if not isinstance(raw, str):
            raise TrustedTimeStateCorruptError()
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, UnicodeError):
            raise TrustedTimeStateCorruptError() from None
        if not isinstance(payload, dict) or set(payload) != expected:
            raise TrustedTimeStateCorruptError()
        if canonical(payload).decode("ascii") != raw:
            raise TrustedTimeStateCorruptError()
        return payload

    @classmethod
    def validate(
        cls,
        connection: sqlite3.Connection,
        current_anchor: ContinuityAnchor | None,
    ) -> ContinuityLedgerState:
        try:
            metadata = cls._metadata(connection)
            tables = cls._tables(connection)
            if not metadata and not tables:
                return ContinuityLedgerState(False, 0, ZERO_DIGEST)
            if set(metadata) != _METADATA_KEYS or tables != _TABLE_NAMES:
                raise TrustedTimeStateCorruptError()
            if metadata["continuity_transition_schema"] != CONTINUITY_EXTENSION_SCHEMA:
                raise TrustedTimeStateCorruptError()
            try:
                count = int(metadata["continuity_transition_count"])
            except ValueError:
                raise TrustedTimeStateCorruptError() from None
            head = require_digest(metadata["continuity_transition_head"])
            if count < 1 or head == ZERO_DIGEST:
                raise TrustedTimeStateCorruptError()
            history_rows = connection.execute(
                "SELECT history_id, transition_id, prior_anchor_digest, "
                "prior_history_head, record_digest, payload "
                "FROM continuity_anchor_history ORDER BY history_id"
            ).fetchall()
            transition_rows = connection.execute(
                "SELECT transition_id, history_id, assessment_digest, "
                "authorization_digest, prior_anchor_digest, candidate_digest, "
                "history_record_digest, prior_history_head, transition_digest, payload "
                "FROM continuity_transitions ORDER BY history_id"
            ).fetchall()
            if len(history_rows) != count or len(transition_rows) != count:
                raise TrustedTimeStateCorruptError()
            expected_head = ZERO_DIGEST
            transitions: list[dict[str, object]] = []
            latest_candidate: ContinuityAnchor | None = None
            for expected_id, (history, transition) in enumerate(
                zip(history_rows, transition_rows, strict=True),
                start=1,
            ):
                history_expected = {
                    "anchor",
                    "anchor_digest",
                    "assessment_digest",
                    "history_id",
                    "prior_history_head",
                    "schema",
                    "transition_id",
                }
                history_payload = cls._parse_payload(history[5], history_expected)
                prior_anchor = ContinuityAnchor.from_payload(history_payload["anchor"])
                history_record_digest = digest(
                    "myuna-trusted-time-anchor-history-record-v1",
                    history_payload,
                )
                if (
                    history[0] != expected_id
                    or history[1] != history_payload["transition_id"]
                    or history[2] != prior_anchor.anchor_digest
                    or history[2] != history_payload["anchor_digest"]
                    or history[3] != expected_head
                    or history[3] != history_payload["prior_history_head"]
                    or history[4] != history_record_digest
                    or history_payload["history_id"] != expected_id
                    or history_payload["schema"] != HISTORY_RECORD_SCHEMA
                ):
                    raise TrustedTimeStateCorruptError()
                transition_expected = {
                    "assessment_digest",
                    "assessment_evidence_digest",
                    "authorization_digest",
                    "authorization_identity_digest",
                    "authorization_schema",
                    "candidate",
                    "candidate_digest",
                    "consumer_watermark_digest",
                    "direction",
                    "history_id",
                    "history_record_digest",
                    "lineage_digest",
                    "max_age_seconds",
                    "max_attempts",
                    "policy_digest",
                    "prior_anchor_digest",
                    "prior_history_head",
                    "residual_lower_microseconds",
                    "residual_upper_microseconds",
                    "residual_window_digest",
                    "schema",
                    "source_binding_digest",
                    "source_contract_digest",
                    "source_evidence_digest",
                    "state_effect",
                    "transition_id",
                }
                transition_payload = cls._parse_payload(transition[9], transition_expected)
                candidate = ContinuityAnchor.from_payload(transition_payload["candidate"])
                try:
                    residual_window_digest = digest(
                        "myuna-trusted-time-forward-residual-window-v1",
                        {
                            "lower_microseconds": transition_payload[
                                "residual_lower_microseconds"
                            ],
                            "upper_microseconds": transition_payload[
                                "residual_upper_microseconds"
                            ],
                        },
                    )
                    authorization_payload = {
                        "assessment_digest": transition_payload["assessment_digest"],
                        "assessment_evidence_digest": transition_payload[
                            "assessment_evidence_digest"
                        ],
                        "authorization_identity_digest": transition_payload[
                            "authorization_identity_digest"
                        ],
                        "candidate_digest": transition_payload["candidate_digest"],
                        "consumer_watermark_digest": transition_payload[
                            "consumer_watermark_digest"
                        ],
                        "direction": transition_payload["direction"],
                        "lineage_digest": transition_payload["lineage_digest"],
                        "max_age_seconds": transition_payload["max_age_seconds"],
                        "max_attempts": transition_payload["max_attempts"],
                        "policy_digest": transition_payload["policy_digest"],
                        "prior_anchor_digest": transition_payload["prior_anchor_digest"],
                        "residual_window_digest": transition_payload[
                            "residual_window_digest"
                        ],
                        "schema": transition_payload["authorization_schema"],
                        "source_binding_digest": transition_payload[
                            "source_binding_digest"
                        ],
                        "source_contract_digest": transition_payload[
                            "source_contract_digest"
                        ],
                        "source_evidence_digest": transition_payload[
                            "source_evidence_digest"
                        ],
                        "transition_id": transition_payload["transition_id"],
                    }
                    authorization_digest = digest(
                        "myuna-trusted-time-forward-authorization-v1",
                        authorization_payload,
                    )
                except (KeyError, TypeError, ValueError):
                    raise TrustedTimeStateCorruptError() from None
                transition_record_digest = digest(
                    "myuna-trusted-time-forward-transition-record-v1",
                    transition_payload,
                )
                for value in (
                    transition_payload["assessment_digest"],
                    transition_payload["assessment_evidence_digest"],
                    transition_payload["authorization_digest"],
                    transition_payload["authorization_identity_digest"],
                    transition_payload["candidate_digest"],
                    transition_payload["consumer_watermark_digest"],
                    transition_payload["history_record_digest"],
                    transition_payload["lineage_digest"],
                    transition_payload["policy_digest"],
                    transition_payload["prior_anchor_digest"],
                    transition_payload["prior_history_head"],
                    transition_payload["residual_window_digest"],
                    transition_payload["source_binding_digest"],
                    transition_payload["source_contract_digest"],
                    transition_payload["source_evidence_digest"],
                ):
                    require_digest(value)
                if (
                    transition[0] != history[1]
                    or transition[0] != transition_payload["transition_id"]
                    or transition[1] != expected_id
                    or transition[1] != transition_payload["history_id"]
                    or transition[2] != transition_payload["assessment_digest"]
                    or transition[3] != transition_payload["authorization_digest"]
                    or transition[4] != prior_anchor.anchor_digest
                    or transition[4] != transition_payload["prior_anchor_digest"]
                    or transition[5] != candidate.anchor_digest
                    or transition[5] != transition_payload["candidate_digest"]
                    or transition[6] != history_record_digest
                    or transition[6] != transition_payload["history_record_digest"]
                    or transition[7] != expected_head
                    or transition[7] != transition_payload["prior_history_head"]
                    or transition[8] != transition_record_digest
                    or transition_payload["schema"] != TRANSITION_RECORD_SCHEMA
                    or transition_payload["authorization_schema"]
                    != AUTHORIZATION_SCHEMA
                    or transition_payload["direction"] != "forward"
                    or transition_payload["max_attempts"] != 1
                    or isinstance(transition_payload["max_age_seconds"], bool)
                    or not isinstance(transition_payload["max_age_seconds"], int)
                    or not 1 <= transition_payload["max_age_seconds"] <= 300
                    or transition_payload["residual_window_digest"]
                    != residual_window_digest
                    or transition_payload["authorization_digest"]
                    != authorization_digest
                    or transition_payload["state_effect"] != "committed"
                    or transition_payload["assessment_digest"]
                    != history_payload["assessment_digest"]
                    or candidate.source != prior_anchor.source
                    or candidate.source_class != prior_anchor.source_class
                    or candidate.authority != prior_anchor.authority
                    or candidate.boot_id != prior_anchor.boot_id
                    or candidate.sequence != prior_anchor.sequence + 1
                    or candidate.instant < prior_anchor.instant
                    or candidate.monotonic_ns < prior_anchor.monotonic_ns
                ):
                    raise TrustedTimeStateCorruptError()
                expected_head = transition_record_digest
                latest_candidate = candidate
                transitions.append(
                    {**transition_payload, "transition_digest": transition_record_digest}
                )
            if expected_head != head or latest_candidate is None or current_anchor is None:
                raise TrustedTimeStateCorruptError()
            if (
                current_anchor.source != latest_candidate.source
                or current_anchor.source_class != latest_candidate.source_class
                or current_anchor.authority != latest_candidate.authority
                or current_anchor.sequence < latest_candidate.sequence
                or current_anchor.instant < latest_candidate.instant
            ):
                raise TrustedTimeStateCorruptError()
            return ContinuityLedgerState(True, count, head, tuple(transitions))
        except TrustedTimeStateCorruptError:
            raise
        except (KeyError, TypeError, ValueError, sqlite3.DatabaseError):
            raise TrustedTimeStateCorruptError() from None

    @classmethod
    def append(
        cls,
        connection: sqlite3.Connection,
        *,
        current_anchor: ContinuityAnchor,
        candidate: ContinuityAnchor,
        assessment: ContinuityAssessment,
        authorization: ForwardContinuityAuthorization,
    ) -> tuple[str, str]:
        state = cls.validate(connection, current_anchor)
        if state.present:
            for transition in state.transitions:
                if (
                    transition["transition_id"] == authorization.transition_id
                    or transition["prior_anchor_digest"] == current_anchor.anchor_digest
                ):
                    raise TrustedTimeTransitionReplayError()
        else:
            for statement in _CONTINUITY_SCHEMA_SQL.split(";"):
                if statement.strip():
                    connection.execute(statement)
            connection.executemany(
                "INSERT INTO metadata(key, value) VALUES(?, ?)",
                (
                    ("continuity_transition_schema", CONTINUITY_EXTENSION_SCHEMA),
                    ("continuity_transition_count", "0"),
                    ("continuity_transition_head", ZERO_DIGEST),
                ),
            )
        history_id = state.count + 1
        history_payload: dict[str, object] = {
            "anchor": current_anchor.payload(),
            "anchor_digest": current_anchor.anchor_digest,
            "assessment_digest": assessment.assessment_digest,
            "history_id": history_id,
            "prior_history_head": state.head,
            "schema": HISTORY_RECORD_SCHEMA,
            "transition_id": authorization.transition_id,
        }
        history_record_digest = digest(
            "myuna-trusted-time-anchor-history-record-v1",
            history_payload,
        )
        transition_payload: dict[str, object] = {
            "assessment_digest": assessment.assessment_digest,
            "assessment_evidence_digest": assessment.evidence_digest,
            "authorization_digest": authorization.authorization_digest,
            "authorization_identity_digest": authorization.authorization_identity_digest,
            "authorization_schema": authorization.schema,
            "candidate": candidate.payload(),
            "candidate_digest": candidate.anchor_digest,
            "consumer_watermark_digest": assessment.consumer_watermark_digest,
            "direction": authorization.direction,
            "history_id": history_id,
            "history_record_digest": history_record_digest,
            "lineage_digest": authorization.lineage_digest,
            "max_age_seconds": authorization.max_age_seconds,
            "max_attempts": authorization.max_attempts,
            "policy_digest": assessment.policy_digest,
            "prior_anchor_digest": current_anchor.anchor_digest,
            "prior_history_head": state.head,
            "residual_lower_microseconds": authorization._residual_lower_microseconds,
            "residual_upper_microseconds": authorization._residual_upper_microseconds,
            "residual_window_digest": authorization.residual_window_digest,
            "schema": TRANSITION_RECORD_SCHEMA,
            "source_binding_digest": assessment.source_binding_digest,
            "source_contract_digest": authorization.source_contract_digest,
            "source_evidence_digest": authorization.source_evidence_digest,
            "state_effect": "committed",
            "transition_id": authorization.transition_id,
        }
        transition_digest = digest(
            "myuna-trusted-time-forward-transition-record-v1",
            transition_payload,
        )
        connection.execute(
            "INSERT INTO continuity_anchor_history(history_id, transition_id, "
            "prior_anchor_digest, prior_history_head, record_digest, payload) "
            "VALUES(?, ?, ?, ?, ?, ?)",
            (
                history_id,
                authorization.transition_id,
                current_anchor.anchor_digest,
                state.head,
                history_record_digest,
                canonical(history_payload).decode("ascii"),
            ),
        )
        connection.execute(
            "INSERT INTO continuity_transitions(transition_id, history_id, "
            "assessment_digest, authorization_digest, prior_anchor_digest, "
            "candidate_digest, history_record_digest, prior_history_head, "
            "transition_digest, payload) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                authorization.transition_id,
                history_id,
                assessment.assessment_digest,
                authorization.authorization_digest,
                current_anchor.anchor_digest,
                candidate.anchor_digest,
                history_record_digest,
                state.head,
                transition_digest,
                canonical(transition_payload).decode("ascii"),
            ),
        )
        connection.execute(
            "UPDATE metadata SET value=? WHERE key='continuity_transition_count'",
            (str(history_id),),
        )
        connection.execute(
            "UPDATE metadata SET value=? WHERE key='continuity_transition_head'",
            (transition_digest,),
        )
        return history_record_digest, transition_digest

    @staticmethod
    def transition_for_id(
        state: ContinuityLedgerState,
        transition_id: str,
    ) -> dict[str, object] | None:
        for transition in state.transitions:
            if transition["transition_id"] == transition_id:
                return transition
        return None


def validate_assessment_integrity(
    assessment: ContinuityAssessment,
    *,
    policy: TrustedTimePolicy,
    consumer_watermark: TrustedTimeWatermark | None,
) -> None:
    try:
        if not isinstance(assessment, ContinuityAssessment):
            raise TrustedTimeTransitionRejectedError()
        candidate = assessment._candidate
        observation = assessment._observation
        prior_anchor = assessment._prior_anchor
        if candidate is None or observation is None:
            raise TrustedTimeTransitionRejectedError()
        floor_sequence = 0 if prior_anchor is None else prior_anchor.sequence
        floor_instant = None if prior_anchor is None else prior_anchor.instant
        if consumer_watermark is not None:
            floor_sequence = max(floor_sequence, consumer_watermark.sequence)
            floor_instant = max(
                value
                for value in (floor_instant, consumer_watermark.instant)
                if value is not None
            )
        if (
            not observation.evidence.synchronized
            or observation.evidence.uncertainty > policy.max_uncertainty
            or (floor_instant is not None and observation.instant < floor_instant)
            or candidate.source != policy.source
            or candidate.source_class != policy.source_class
            or candidate.authority != observation.evidence.authority
            or candidate.sequence != floor_sequence + 1
            or candidate.instant != observation.instant
            or candidate.monotonic_ns != observation.monotonic_ns
            or candidate.boot_id != observation.boot_id
        ):
            raise TrustedTimeTransitionRejectedError()

        signed_residual_microseconds: int | None = None
        if prior_anchor is None:
            continuity = (
                "consumer_reconciled" if consumer_watermark is not None else "initial"
            )
            status = "within_policy"
            eligibility = "ordinary_sample"
            direction = "within_tolerance"
        elif observation.evidence.authority != prior_anchor.authority:
            raise TrustedTimeTransitionRejectedError()
        elif observation.boot_id != prior_anchor.boot_id:
            continuity = "boot_transition"
            status = "within_policy"
            eligibility = "ordinary_sample"
            direction = "boot_transition"
        else:
            continuity = "same_boot"
            elapsed_ns = observation.monotonic_ns - prior_anchor.monotonic_ns
            if elapsed_ns < 0:
                raise TrustedTimeTransitionRejectedError()
            expected = prior_anchor.instant + timedelta(microseconds=elapsed_ns / 1000)
            signed_residual_microseconds = timedelta_microseconds(
                observation.instant - expected
            )
            maximum = timedelta_microseconds(policy.max_drift)
            if signed_residual_microseconds < -maximum:
                raise TrustedTimeTransitionRejectedError()
            if signed_residual_microseconds > maximum:
                status = "forward_transition_required"
                eligibility = "explicit_forward_transition"
                direction = "forward"
            else:
                status = "within_policy"
                eligibility = "ordinary_sample"
                direction = "within_tolerance"

        expected_clock_digest = digest(
            "myuna-trusted-time-assessment-clock-v1",
            {"monotonic_ns": assessment._assessed_monotonic_ns},
        )
        if (
            assessment.expected_digest() != assessment.assessment_digest
            or assessment.assessment_clock_digest != expected_clock_digest
            or assessment.policy_digest != policy_digest(policy)
            or assessment.consumer_watermark_digest != watermark_digest(consumer_watermark)
            or assessment.candidate_digest != candidate.anchor_digest
            or assessment.prior_anchor_digest
            != (
                ZERO_DIGEST
                if prior_anchor is None
                else prior_anchor.anchor_digest
            )
            or assessment.source_binding_digest
            != source_binding_digest(policy, observation)
            or assessment.evidence_digest
            != evidence_digest(observation, candidate)
            or assessment.status != status
            or assessment.continuity != continuity
            or assessment.eligibility != eligibility
            or assessment.direction != direction
            or assessment.drift_bucket
            != drift_bucket(signed_residual_microseconds, continuity)
            or assessment.uncertainty_bucket
            != uncertainty_bucket(observation.evidence.uncertainty)
            or assessment._signed_residual_microseconds
            != signed_residual_microseconds
        ):
            raise TrustedTimeTransitionRejectedError()
    except TrustedTimeTransitionRejectedError:
        raise
    except Exception:
        raise TrustedTimeTransitionRejectedError() from None


def validate_authorization_integrity(
    authorization: ForwardContinuityAuthorization,
    assessment: ContinuityAssessment,
) -> None:
    try:
        if (
            not isinstance(authorization, ForwardContinuityAuthorization)
            or authorization.expected_digest() != authorization.authorization_digest
            or authorization.expected_window_digest() != authorization.residual_window_digest
            or authorization.assessment_digest != assessment.assessment_digest
            or authorization.prior_anchor_digest != assessment.prior_anchor_digest
            or authorization.candidate_digest != assessment.candidate_digest
            or authorization.consumer_watermark_digest
            != assessment.consumer_watermark_digest
            or authorization.policy_digest != assessment.policy_digest
            or authorization.source_binding_digest != assessment.source_binding_digest
            or authorization.assessment_evidence_digest != assessment.evidence_digest
        ):
            raise TrustedTimeTransitionRejectedError()
    except TrustedTimeTransitionRejectedError:
        raise
    except Exception:
        raise TrustedTimeTransitionRejectedError() from None
