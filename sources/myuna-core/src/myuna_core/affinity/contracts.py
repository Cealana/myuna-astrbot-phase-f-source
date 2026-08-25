from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from typing import Mapping


SCHEMA_VERSION = 1
SCHEMA_LABEL = "myuna.structured-affinity.v1"
CAPABILITY_ID = "p09-v7-structured-affinity-v1"
AUDIT_NAMESPACE = "structured_affinity_v1"
FIXTURE_SCHEMA = "myuna.structured-affinity.synthetic-fixtures.v1"

LONG_TERM_DIMENSIONS = (
    "affection",
    "daily_trust",
    "operational_trust",
    "security",
    "agency",
)
SHORT_TERM_DIMENSIONS = (
    "mood",
    "energy",
    "stress",
    "shyness",
    "playfulness",
)
AFFINITY_DIMENSIONS = LONG_TERM_DIMENSIONS + SHORT_TERM_DIMENSIONS
CONFIDENCE_BANDS = ("none", "low", "medium", "high")
DIMENSION_STATES = ("provisional", "confirmed", "conflicted", "revoked")
UPDATE_ACTIONS = (
    "propose",
    "confirm",
    "update",
    "conflict",
    "repair",
    "revoke",
    "abstain",
)
ABSTENTION_REASONS = (
    "insufficient_evidence",
    "conflicting_evidence",
    "dependency_unavailable",
    "scope_not_authorized",
    "schema_unavailable",
)
SOURCE_KINDS = ("synthetic_fixture",)

MAX_EVIDENCE_REFS = 8
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AffinityError(RuntimeError):
    """Typed, content-free structured-affinity failure."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def safe_label(value: object, label: str) -> str:
    if not isinstance(value, str) or _SAFE_LABEL.fullmatch(value) is None:
        raise AffinityError(f"{label}_invalid")
    return value


def utc(value: object, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise AffinityError(f"{label}_timezone_missing")
    try:
        if value.utcoffset() is None:
            raise AffinityError(f"{label}_timezone_missing")
        return value.astimezone(timezone.utc)
    except AffinityError:
        raise
    except Exception:
        raise AffinityError(f"{label}_invalid") from None


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise AffinityError(f"{label}_invalid")
    return value


def _value(value: object) -> int:
    result = _integer(value, "affinity_value")
    if result > 100:
        raise AffinityError("affinity_value_invalid")
    return result


def _evidence_refs(values: object) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise AffinityError("evidence_refs_invalid")
    for item in values:
        safe_label(item, "evidence_ref")
    if (
        len(values) > MAX_EVIDENCE_REFS
        or len(set(values)) != len(values)
        or tuple(sorted(values)) != values
    ):
        raise AffinityError("evidence_refs_invalid")
    return values


def canonical_bytes(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class AffinityTimeSample:
    instant: datetime
    sequence: int
    source: str
    source_class: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "instant", utc(self.instant, "trusted_time"))
        _integer(self.sequence, "trusted_time_sequence", minimum=1)
        safe_label(self.source, "trusted_time_source")
        if self.source_class not in {"synthetic", "trusted_local", "trusted_remote"}:
            raise AffinityError("trusted_time_source_class_invalid")


@dataclass(frozen=True, slots=True)
class AffinityDimensionState:
    dimension: str
    state: str
    value: int | None
    confidence: str
    evidence_refs: tuple[str, ...]
    revision: int
    updated_at: datetime

    def __post_init__(self) -> None:
        if self.dimension not in AFFINITY_DIMENSIONS:
            raise AffinityError("affinity_dimension_invalid")
        if self.state not in DIMENSION_STATES:
            raise AffinityError("affinity_dimension_state_invalid")
        if self.confidence not in CONFIDENCE_BANDS:
            raise AffinityError("affinity_confidence_invalid")
        _integer(self.revision, "affinity_revision", minimum=1)
        object.__setattr__(self, "updated_at", utc(self.updated_at, "updated_at"))
        _evidence_refs(self.evidence_refs)
        if self.state in {"provisional", "confirmed"}:
            _value(self.value)
            if self.confidence == "none" or not self.evidence_refs:
                raise AffinityError("affinity_assertion_incomplete")
        elif self.value is not None or self.confidence != "none":
            raise AffinityError("affinity_nonasserting_state_leaks_value")

    @property
    def scope(self) -> str:
        return "long_term" if self.dimension in LONG_TERM_DIMENSIONS else "short_term"

    def as_payload(self) -> dict[str, object]:
        return {
            "confidence": self.confidence,
            "dimension": self.dimension,
            "evidence_refs": list(self.evidence_refs),
            "revision": self.revision,
            "scope": self.scope,
            "state": self.state,
            "updated_at": self.updated_at.isoformat(timespec="microseconds"),
            "value": self.value,
        }


@dataclass(frozen=True, slots=True)
class AffinitySnapshot:
    namespace_id: str
    revision: int
    dimensions: tuple[AffinityDimensionState, ...]
    observed_at: datetime | None = None
    time_sequence: int = 0
    time_source: str | None = None
    schema: str = SCHEMA_LABEL

    def __post_init__(self) -> None:
        if self.schema != SCHEMA_LABEL:
            raise AffinityError("affinity_schema_unknown")
        safe_label(self.namespace_id, "affinity_namespace")
        _integer(self.revision, "affinity_revision")
        _integer(self.time_sequence, "trusted_time_sequence")
        names = tuple(item.dimension for item in self.dimensions)
        if tuple(sorted(names)) != names or len(set(names)) != len(names):
            raise AffinityError("affinity_dimensions_not_canonical")
        if self.revision == 0:
            if self.dimensions or self.observed_at is not None or self.time_sequence != 0:
                raise AffinityError("affinity_empty_snapshot_invalid")
            if self.time_source is not None:
                raise AffinityError("affinity_empty_snapshot_invalid")
        else:
            if self.observed_at is None or self.time_source is None or self.time_sequence < 1:
                raise AffinityError("affinity_snapshot_time_missing")
            object.__setattr__(self, "observed_at", utc(self.observed_at, "observed_at"))
            safe_label(self.time_source, "trusted_time_source")
            if any(item.revision > self.revision for item in self.dimensions):
                raise AffinityError("affinity_dimension_revision_ahead")

    @classmethod
    def empty(cls, namespace_id: str) -> "AffinitySnapshot":
        return cls(namespace_id=namespace_id, revision=0, dimensions=())

    def as_payload(self) -> dict[str, object]:
        return {
            "dimensions": [item.as_payload() for item in self.dimensions],
            "namespace_id": self.namespace_id,
            "observed_at": (
                self.observed_at.isoformat(timespec="microseconds")
                if self.observed_at is not None
                else None
            ),
            "revision": self.revision,
            "schema": self.schema,
            "time_sequence": self.time_sequence,
            "time_source": self.time_source,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.as_payload())

    @property
    def digest(self) -> str:
        return sha256(b"myuna-structured-affinity-v1\0" + self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class AffinityUpdate:
    namespace_id: str
    event_id: str
    sequence: int
    action: str
    dimension: str | None
    value: int | None
    confidence: str
    evidence_refs: tuple[str, ...]
    source_kind: str
    abstention_reason: str | None = None
    schema: str = SCHEMA_LABEL

    def __post_init__(self) -> None:
        if self.schema != SCHEMA_LABEL:
            raise AffinityError("affinity_schema_unknown")
        safe_label(self.namespace_id, "affinity_namespace")
        safe_label(self.event_id, "affinity_event_id")
        _integer(self.sequence, "affinity_sequence", minimum=1)
        if self.action not in UPDATE_ACTIONS:
            raise AffinityError("affinity_action_invalid")
        if self.source_kind not in SOURCE_KINDS:
            raise AffinityError("affinity_source_kind_inactive")
        if self.confidence not in CONFIDENCE_BANDS:
            raise AffinityError("affinity_confidence_invalid")
        _evidence_refs(self.evidence_refs)
        if self.dimension is not None and self.dimension not in AFFINITY_DIMENSIONS:
            raise AffinityError("affinity_dimension_invalid")

        if self.action == "abstain":
            if (
                self.value is not None
                or self.confidence != "none"
                or self.abstention_reason not in ABSTENTION_REASONS
            ):
                raise AffinityError("affinity_abstention_invalid")
            return

        if self.dimension is None or self.abstention_reason is not None:
            raise AffinityError("affinity_update_out_of_contract")
        if self.action == "revoke":
            if self.value is not None or self.confidence != "none" or not self.evidence_refs:
                raise AffinityError("affinity_revoke_invalid")
            return
        _value(self.value)
        if self.confidence == "none" or not self.evidence_refs:
            raise AffinityError("affinity_assertion_incomplete")

    @classmethod
    def from_payload(cls, payload: object) -> "AffinityUpdate":
        required = {
            "abstention_reason",
            "action",
            "confidence",
            "dimension",
            "event_id",
            "evidence_refs",
            "namespace_id",
            "schema",
            "sequence",
            "source_kind",
            "value",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise AffinityError("affinity_update_fields_invalid")
        evidence = payload["evidence_refs"]
        if not isinstance(evidence, list) or any(not isinstance(item, str) for item in evidence):
            raise AffinityError("evidence_refs_invalid")
        return cls(
            namespace_id=payload["namespace_id"],  # type: ignore[arg-type]
            event_id=payload["event_id"],  # type: ignore[arg-type]
            sequence=payload["sequence"],  # type: ignore[arg-type]
            action=payload["action"],  # type: ignore[arg-type]
            dimension=payload["dimension"],  # type: ignore[arg-type]
            value=payload["value"],  # type: ignore[arg-type]
            confidence=payload["confidence"],  # type: ignore[arg-type]
            evidence_refs=tuple(evidence),
            source_kind=payload["source_kind"],  # type: ignore[arg-type]
            abstention_reason=payload["abstention_reason"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )

    def as_payload(self) -> dict[str, object]:
        return {
            "abstention_reason": self.abstention_reason,
            "action": self.action,
            "confidence": self.confidence,
            "dimension": self.dimension,
            "event_id": self.event_id,
            "evidence_refs": list(self.evidence_refs),
            "namespace_id": self.namespace_id,
            "schema": self.schema,
            "sequence": self.sequence,
            "source_kind": self.source_kind,
            "value": self.value,
        }


@dataclass(frozen=True, slots=True)
class AffinityDependencyContract:
    dependency: str
    interface_schema: str
    status: str
    reads_content: bool = False
    writes_state: bool = False

    def __post_init__(self) -> None:
        safe_label(self.dependency, "affinity_dependency")
        safe_label(self.interface_schema, "affinity_dependency_schema")
        if self.status not in {"interface_only", "dependency_checkpoint"}:
            raise AffinityError("affinity_dependency_status_invalid")
        if type(self.reads_content) is not bool or type(self.writes_state) is not bool:
            raise AffinityError("affinity_dependency_flags_invalid")

    def as_payload(self) -> dict[str, object]:
        return {
            "dependency": self.dependency,
            "interface_schema": self.interface_schema,
            "reads_content": self.reads_content,
            "status": self.status,
            "writes_state": self.writes_state,
        }


@dataclass(frozen=True, slots=True)
class AffinityCapabilityContract:
    dependencies: tuple[AffinityDependencyContract, ...]
    capability_id: str = CAPABILITY_ID
    schema: str = SCHEMA_LABEL
    active: bool = False
    bootstrap_active: bool = False
    persistence_active: bool = False
    writer_active: bool = False
    retrieval_active: bool = False
    prompt_projection_active: bool = False
    legacy_trust_migration_active: bool = False
    synthetic_machine_only: bool = True

    def __post_init__(self) -> None:
        if self.capability_id != CAPABILITY_ID or self.schema != SCHEMA_LABEL:
            raise AffinityError("affinity_capability_identity_invalid")
        flags = (
            self.active,
            self.bootstrap_active,
            self.persistence_active,
            self.writer_active,
            self.retrieval_active,
            self.prompt_projection_active,
            self.legacy_trust_migration_active,
        )
        if any(flag is not False for flag in flags) or self.synthetic_machine_only is not True:
            raise AffinityError("affinity_phase_b_foundation_must_remain_inactive")
        names = tuple(item.dependency for item in self.dependencies)
        if len(set(names)) != len(names) or tuple(sorted(names)) != names:
            raise AffinityError("affinity_dependencies_not_canonical")

    @classmethod
    def phase_b_foundation(cls) -> "AffinityCapabilityContract":
        return cls(
            dependencies=tuple(
                sorted(
                    (
                        AffinityDependencyContract(
                            "p07_external_context",
                            "myuna.external-context-envelope.v2",
                            "interface_only",
                        ),
                        AffinityDependencyContract(
                            "p07_owner_profile",
                            "owner_profile_baseline.v1",
                            "interface_only",
                        ),
                        AffinityDependencyContract(
                            "p08_temporal_context",
                            "myuna.active-temporal-context.v1",
                            "interface_only",
                        ),
                        AffinityDependencyContract(
                            "p10_trusted_time",
                            "myuna.trusted-time.consumer.unassigned",
                            "dependency_checkpoint",
                        ),
                        AffinityDependencyContract(
                            "p15_relevance",
                            "myuna.affinity-relevance-port.v1",
                            "dependency_checkpoint",
                        ),
                        AffinityDependencyContract(
                            "p16_diagnostics",
                            "myuna.user-visible-fault.v1",
                            "interface_only",
                        ),
                    ),
                    key=lambda item: item.dependency,
                )
            )
        )

    def as_payload(self) -> dict[str, object]:
        return {
            "active": self.active,
            "bootstrap_active": self.bootstrap_active,
            "capability_id": self.capability_id,
            "dependencies": [item.as_payload() for item in self.dependencies],
            "legacy_trust_migration_active": self.legacy_trust_migration_active,
            "persistence_active": self.persistence_active,
            "prompt_projection_active": self.prompt_projection_active,
            "retrieval_active": self.retrieval_active,
            "schema": self.schema,
            "synthetic_machine_only": self.synthetic_machine_only,
            "writer_active": self.writer_active,
        }

    @property
    def digest(self) -> str:
        return sha256(canonical_bytes(self.as_payload())).hexdigest()


def validate_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise AffinityError(f"{label}_invalid")
    return value
