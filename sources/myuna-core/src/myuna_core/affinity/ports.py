from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from .contracts import (
    AFFINITY_DIMENSIONS,
    AUDIT_NAMESPACE,
    AffinityError,
    AffinityTimeSample,
    safe_label,
    utc,
)


EVIDENCE_SOURCES = (
    "p07_owner_profile",
    "p07_external_context",
    "p08_temporal_context",
)
RELEVANCE_BANDS = ("excluded", "low", "medium", "high")
DIAGNOSTIC_CODES = (
    "affinity_abstained",
    "affinity_dependency_unavailable",
    "affinity_persistence_inactive",
    "affinity_transition_rejected",
    "affinity_update_applied",
)


@dataclass(frozen=True, slots=True)
class AffinityEvidenceQuery:
    namespace_id: str
    dimension: str
    query_ref: str
    maximum_results: int = 6

    def __post_init__(self) -> None:
        safe_label(self.namespace_id, "affinity_namespace")
        if self.dimension not in AFFINITY_DIMENSIONS:
            raise AffinityError("affinity_dimension_invalid")
        safe_label(self.query_ref, "affinity_query_ref")
        if (
            isinstance(self.maximum_results, bool)
            or not isinstance(self.maximum_results, int)
            or not 1 <= self.maximum_results <= 6
        ):
            raise AffinityError("affinity_query_limit_invalid")


@dataclass(frozen=True, slots=True)
class AffinityEvidenceReference:
    source: str
    source_ref: str
    revision: int
    observed_at: datetime

    def __post_init__(self) -> None:
        if self.source not in EVIDENCE_SOURCES:
            raise AffinityError("affinity_evidence_source_invalid")
        safe_label(self.source_ref, "affinity_evidence_ref")
        if (
            isinstance(self.revision, bool)
            or not isinstance(self.revision, int)
            or self.revision < 1
        ):
            raise AffinityError("affinity_evidence_revision_invalid")
        object.__setattr__(self, "observed_at", utc(self.observed_at, "evidence_observed_at"))


@dataclass(frozen=True, slots=True)
class AffinityRelevanceResult:
    evidence_ref: str
    band: str
    reason_code: str

    def __post_init__(self) -> None:
        safe_label(self.evidence_ref, "affinity_evidence_ref")
        if self.band not in RELEVANCE_BANDS:
            raise AffinityError("affinity_relevance_band_invalid")
        safe_label(self.reason_code, "affinity_relevance_reason")


@dataclass(frozen=True, slots=True)
class AffinityDiagnosticEvent:
    code: str
    outcome: str
    retryable: bool
    revision: int
    dimension: str | None = None
    event_namespace: str = AUDIT_NAMESPACE

    def __post_init__(self) -> None:
        if self.event_namespace != AUDIT_NAMESPACE:
            raise AffinityError("affinity_diagnostic_namespace_invalid")
        if self.code not in DIAGNOSTIC_CODES:
            raise AffinityError("affinity_diagnostic_code_invalid")
        safe_label(self.outcome, "affinity_diagnostic_outcome")
        if type(self.retryable) is not bool:
            raise AffinityError("affinity_diagnostic_retryable_invalid")
        if (
            isinstance(self.revision, bool)
            or not isinstance(self.revision, int)
            or self.revision < 0
        ):
            raise AffinityError("affinity_diagnostic_revision_invalid")
        if self.dimension is not None and self.dimension not in AFFINITY_DIMENSIONS:
            raise AffinityError("affinity_dimension_invalid")

    def as_payload(self) -> dict[str, object]:
        return {
            "code": self.code,
            "dimension": self.dimension,
            "event_namespace": self.event_namespace,
            "outcome": self.outcome,
            "retryable": self.retryable,
            "revision": self.revision,
        }


@runtime_checkable
class P07OwnerProfileAffinityPort(Protocol):
    def evidence_refs(
        self, query: AffinityEvidenceQuery
    ) -> tuple[AffinityEvidenceReference, ...]: ...


@runtime_checkable
class P07ExternalContextAffinityPort(Protocol):
    def evidence_refs(
        self, query: AffinityEvidenceQuery
    ) -> tuple[AffinityEvidenceReference, ...]: ...


@runtime_checkable
class P08TemporalAffinityPort(Protocol):
    def evidence_refs(
        self, query: AffinityEvidenceQuery
    ) -> tuple[AffinityEvidenceReference, ...]: ...


@runtime_checkable
class P10TrustedTimeAffinityPort(Protocol):
    def observe(self, timeout_seconds: float) -> AffinityTimeSample: ...


@runtime_checkable
class P15AffinityRelevancePort(Protocol):
    def rank(
        self,
        query: AffinityEvidenceQuery,
        evidence: tuple[AffinityEvidenceReference, ...],
    ) -> tuple[AffinityRelevanceResult, ...]: ...


@runtime_checkable
class P16AffinityDiagnosticsPort(Protocol):
    def emit(self, event: AffinityDiagnosticEvent) -> None: ...
