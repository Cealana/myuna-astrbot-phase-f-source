from __future__ import annotations

from collections import Counter
import math

from .contracts import (
    AUDIT_NAMESPACE,
    SCHEMA_VERSION,
    TemporalContextError,
    TemporalMutationResult,
    TemporalRetrievalResult,
)
from .time import TIME_SOURCE_CLASSES, TrustedTimeSample


_PUBLIC_ERRORS = frozenset(
    {
        "candidate_schema_invalid",
        "category_filter_invalid",
        "category_prohibited",
        "commit_outcome_unknown",
        "confirmation_expired",
        "confirmation_rejected",
        "database_busy",
        "database_corrupt",
        "database_oversize",
        "database_permission_drift",
        "database_type_drift",
        "fact_conflict",
        "proposal_not_found",
        "proposal_scope_rejected",
        "query_out_of_contract",
        "read_scope_rejected",
        "retrieval_budget_exceeded",
        "active_projection_overflow",
        "schema_unknown",
        "source_channel_rejected",
        "source_kind_rejected",
        "summary_policy_rejected",
        "trusted_time_regression",
        "trusted_time_sequence_regression",
        "trusted_time_source_drift",
        "trusted_time_evidence_unavailable",
        "write_scope_rejected",
    }
)
_AUDIT_OPERATIONS = frozenset(
    {
        "propose",
        "confirm",
        "create",
        "supersede",
        "refresh",
        "revoke",
        "restore",
        "expire",
        "retrieve",
    }
)
_MUTATION_OUTCOMES = frozenset(
    {"active", "no_change", "conflict", "supersede", "refresh", "revoked", "restored"}
)
_MUTATION_TRANSITIONS = {
    "active": "proposed->active",
    "no_change": "none",
    "conflict": "proposed->conflicted",
    "supersede": "active->superseded+active",
    "refresh": "active->superseded+active",
    "revoked": "active->revoked",
    "restored": "revoked->active(new_revision)",
}
_RETRIEVAL_STATES = frozenset({"selected", "empty"})


def _audit_operation(value: str) -> str:
    if value not in _AUDIT_OPERATIONS:
        raise ValueError("audit operation is invalid")
    return value


def _source_class(value: str) -> str:
    if value not in TIME_SOURCE_CLASSES:
        raise ValueError("trusted time source class is invalid")
    return value


def _duration_bucket(value: float) -> str:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or value < 0
    ):
        raise ValueError("duration is invalid")
    if value < 10:
        return "lt10ms"
    if value < 50:
        return "10-49ms"
    if value < 250:
        return "50-249ms"
    if value < 1000:
        return "250-999ms"
    return "gte1000ms"


def _query_bucket(value: int) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("query length is invalid")
    if value == 0:
        return "0"
    if value <= 64:
        return "1-64"
    if value <= 256:
        return "65-256"
    if value <= 512:
        return "257-512"
    return "513+"


def mutation_audit_projection(
    result: TemporalMutationResult,
    *,
    operation: str,
    sample: TrustedTimeSample,
    duration_ms: float,
) -> dict[str, object]:
    _audit_operation(operation)
    if result.outcome not in _MUTATION_OUTCOMES:
        raise ValueError("mutation outcome is invalid")
    _source_class(sample.source_class)
    categories = Counter(
        [result.fact.category] if result.fact is not None else []
    )
    return {
        "event_namespace": AUDIT_NAMESPACE,
        "schema_version": SCHEMA_VERSION,
        "operation": operation,
        "outcome": result.outcome,
        "category_counts": dict(sorted(categories.items())),
        "selected_count": 0,
        "lifecycle_transition": _MUTATION_TRANSITIONS[result.outcome],
        "duration_bucket": _duration_bucket(duration_ms),
        "retryable": False,
        "trusted_time_source_class": sample.source_class,
        "p07_written": False,
        "session_written": False,
        "legacy_memory_written": False,
        "p10_written": False,
    }


def retrieval_audit_projection(
    result: TemporalRetrievalResult,
    *,
    sample: TrustedTimeSample,
    duration_ms: float,
) -> dict[str, object]:
    if result.state not in _RETRIEVAL_STATES:
        raise ValueError("retrieval state is invalid")
    _source_class(sample.source_class)
    return {
        "event_namespace": AUDIT_NAMESPACE,
        "schema_version": SCHEMA_VERSION,
        "operation": "retrieve",
        "outcome": result.state,
        "category_counts": dict(sorted(Counter(x.category for x in result.facts).items())),
        "selected_count": len(result.facts),
        "lifecycle_transition": "none",
        "query_length_bucket": _query_bucket(result.query_characters),
        "duration_bucket": _duration_bucket(duration_ms),
        "retryable": False,
        "trusted_time_source_class": sample.source_class,
        "p07_written": False,
        "session_written": False,
        "legacy_memory_written": False,
        "p10_written": False,
    }


def error_audit_projection(
    error: TemporalContextError,
    *,
    operation: str,
    query_characters: int,
    duration_ms: float,
    source_class: str,
) -> dict[str, object]:
    _audit_operation(operation)
    _source_class(source_class)
    return {
        "event_namespace": AUDIT_NAMESPACE,
        "schema_version": SCHEMA_VERSION,
        "operation": operation,
        "outcome": "degraded" if error.retryable else "rejected",
        "category_counts": {},
        "selected_count": 0,
        "lifecycle_transition": "none",
        "query_length_bucket": _query_bucket(query_characters),
        "duration_bucket": _duration_bucket(duration_ms),
        "retryable": error.retryable,
        "trusted_time_source_class": source_class,
        "error_category": error.code if error.code in _PUBLIC_ERRORS else "internal_error",
        "p07_written": False,
        "session_written": False,
        "legacy_memory_written": False,
        "p10_written": False,
    }
