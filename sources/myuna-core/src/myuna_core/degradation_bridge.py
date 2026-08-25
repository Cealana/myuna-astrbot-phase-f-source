from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import re

from .degradation_protocol import SafeDegradationProjection
from .natural_degradation import DegradationCategory, FailureEnvelope, RecoveryState


class CoreFailureCode(str, Enum):
    CORE_REQUEST_REJECTED = "core_request_rejected"
    REPLY_CONTRACT_REJECTED = "reply_contract_rejected"
    REPLY_RUNTIME_GUARD_REJECTED = "reply_runtime_guard_rejected"
    PROVIDER_TRANSPORT_FAILURE = "provider_transport_failure"
    PROVIDER_RATE_LIMITED = "provider_rate_limited"
    PROVIDER_UPSTREAM_FAILURE = "provider_upstream_failure"
    PROVIDER_INVALID_RESPONSE = "provider_invalid_response"
    PROVIDER_REQUEST_REJECTED = "provider_request_rejected"
    PROVIDER_AUTHENTICATION_FAILED = "provider_authentication_failed"
    PROVIDER_INSUFFICIENT_BALANCE = "provider_insufficient_balance"
    PROVIDER_DAILY_BUDGET_EXCEEDED = "provider_daily_budget_exceeded"
    PROVIDER_BUDGET_ACCOUNTING_FAILED = "provider_budget_accounting_failed"
    LOCAL_PROVIDER_TIMEOUT = "local_provider_timeout"
    LOCAL_PROVIDER_BUSY = "local_provider_busy"
    LOCAL_MODEL_NOT_READY = "local_model_not_ready"
    LOCAL_PROVIDER_UNAVAILABLE = "local_provider_unavailable"
    LOCAL_PROVIDER_HTTP_REJECTED = "local_provider_http_rejected"
    LOCAL_PROVIDER_ENDPOINT_REJECTED = "local_provider_endpoint_rejected"
    OWNER_MEMORY_READ_FAILED = "owner_memory_read_failed"
    CORE_RUNTIME_NOT_READY = "core_runtime_not_ready"
    CORE_RUNTIME_FAIL_CLOSED = "core_runtime_fail_closed"


@dataclass(frozen=True, slots=True)
class CoreFailureProfile:
    category: DegradationCategory
    component: str
    safe_detail_code: str
    retryable: bool
    owner_action_required: bool
    confirmed_facts: tuple[str, ...]
    unknown_facts: tuple[str, ...]


_PROFILES = {
    CoreFailureCode.CORE_REQUEST_REJECTED: CoreFailureProfile(
        DegradationCategory.CORE_OR_GATEWAY_FAILURE,
        "myuna-core",
        "core-request-rejected",
        False,
        True,
        ("request-contract-rejected",),
        (),
    ),
    CoreFailureCode.REPLY_CONTRACT_REJECTED: CoreFailureProfile(
        DegradationCategory.REPLY_CONTRACT_REJECTED,
        "myuna-core",
        "reply-contract-rejected",
        True,
        False,
        ("provider-output-discarded",),
        ("discarded-content",),
    ),
    CoreFailureCode.REPLY_RUNTIME_GUARD_REJECTED: CoreFailureProfile(
        DegradationCategory.REPLY_CONTRACT_REJECTED,
        "myuna-core",
        "reply-runtime-guard-rejected",
        True,
        False,
        ("provider-output-discarded", "runtime-guard-rejected"),
        ("discarded-content",),
    ),
    CoreFailureCode.PROVIDER_TRANSPORT_FAILURE: CoreFailureProfile(
        DegradationCategory.PROVIDER_TRANSIENT_FAILURE,
        "model-provider",
        "provider-transport-failure",
        True,
        False,
        ("provider-request-failed",),
        ("upstream-state",),
    ),
    CoreFailureCode.PROVIDER_RATE_LIMITED: CoreFailureProfile(
        DegradationCategory.PROVIDER_TRANSIENT_FAILURE,
        "model-provider",
        "provider-rate-limited",
        True,
        False,
        ("provider-rate-limited",),
        ("retry-after",),
    ),
    CoreFailureCode.PROVIDER_UPSTREAM_FAILURE: CoreFailureProfile(
        DegradationCategory.PROVIDER_TRANSIENT_FAILURE,
        "model-provider",
        "provider-upstream-failure",
        True,
        False,
        ("provider-request-failed",),
        ("upstream-state",),
    ),
    CoreFailureCode.PROVIDER_INVALID_RESPONSE: CoreFailureProfile(
        DegradationCategory.PROVIDER_TRANSIENT_FAILURE,
        "model-provider",
        "provider-invalid-response",
        True,
        False,
        ("provider-response-discarded",),
        ("discarded-content",),
    ),
    CoreFailureCode.PROVIDER_REQUEST_REJECTED: CoreFailureProfile(
        DegradationCategory.CORE_OR_GATEWAY_FAILURE,
        "myuna-core",
        "provider-request-rejected",
        False,
        True,
        ("provider-request-rejected",),
        ("configuration-state",),
    ),
    CoreFailureCode.PROVIDER_AUTHENTICATION_FAILED: CoreFailureProfile(
        DegradationCategory.PROVIDER_BUDGET_OR_AUTH_FAILURE,
        "model-provider",
        "provider-authentication-failed",
        False,
        True,
        ("provider-authentication-failed",),
        (),
    ),
    CoreFailureCode.PROVIDER_INSUFFICIENT_BALANCE: CoreFailureProfile(
        DegradationCategory.PROVIDER_BUDGET_OR_AUTH_FAILURE,
        "model-provider",
        "provider-insufficient-balance",
        False,
        True,
        ("provider-balance-unavailable",),
        (),
    ),
    CoreFailureCode.PROVIDER_DAILY_BUDGET_EXCEEDED: CoreFailureProfile(
        DegradationCategory.PROVIDER_BUDGET_OR_AUTH_FAILURE,
        "myuna-core",
        "provider-daily-budget-exceeded",
        False,
        True,
        ("local-budget-blocked-request",),
        (),
    ),
    CoreFailureCode.PROVIDER_BUDGET_ACCOUNTING_FAILED: CoreFailureProfile(
        DegradationCategory.CORE_OR_GATEWAY_FAILURE,
        "myuna-core",
        "provider-budget-accounting-failed",
        False,
        True,
        ("provider-request-failed-closed",),
        ("accounting-state",),
    ),
    CoreFailureCode.LOCAL_PROVIDER_TIMEOUT: CoreFailureProfile(
        DegradationCategory.PROVIDER_TRANSIENT_FAILURE,
        "local-model-provider",
        "local-provider-timeout",
        True,
        False,
        ("local-provider-request-timed-out",),
        ("model-readiness",),
    ),
    CoreFailureCode.LOCAL_PROVIDER_BUSY: CoreFailureProfile(
        DegradationCategory.PROVIDER_TRANSIENT_FAILURE,
        "local-model-provider",
        "local-provider-busy",
        True,
        False,
        ("local-provider-busy",),
        ("retry-after",),
    ),
    CoreFailureCode.LOCAL_MODEL_NOT_READY: CoreFailureProfile(
        DegradationCategory.CORE_OR_GATEWAY_FAILURE,
        "local-model-provider",
        "local-model-not-ready",
        False,
        True,
        ("local-model-unavailable",),
        ("model-readiness", "configuration-state"),
    ),
    CoreFailureCode.LOCAL_PROVIDER_UNAVAILABLE: CoreFailureProfile(
        DegradationCategory.PROVIDER_TRANSIENT_FAILURE,
        "local-model-provider",
        "local-provider-unavailable",
        True,
        False,
        ("local-provider-request-failed",),
        ("model-readiness",),
    ),
    CoreFailureCode.LOCAL_PROVIDER_HTTP_REJECTED: CoreFailureProfile(
        DegradationCategory.CORE_OR_GATEWAY_FAILURE,
        "myuna-core",
        "local-provider-http-rejected",
        False,
        True,
        ("local-provider-request-rejected",),
        ("configuration-state",),
    ),
    CoreFailureCode.LOCAL_PROVIDER_ENDPOINT_REJECTED: CoreFailureProfile(
        DegradationCategory.CORE_OR_GATEWAY_FAILURE,
        "myuna-core",
        "local-provider-endpoint-rejected",
        False,
        True,
        ("local-provider-endpoint-rejected",),
        ("configuration-state",),
    ),
    CoreFailureCode.OWNER_MEMORY_READ_FAILED: CoreFailureProfile(
        DegradationCategory.MEMORY_SERVICE_FAILURE,
        "owner-memory-v2",
        "owner-memory-read-failed",
        True,
        False,
        ("memory-context-omitted",),
        ("memory-read-result",),
    ),
    CoreFailureCode.CORE_RUNTIME_NOT_READY: CoreFailureProfile(
        DegradationCategory.CORE_OR_GATEWAY_FAILURE,
        "myuna-core",
        "core-runtime-not-ready",
        False,
        True,
        ("core-not-ready",),
        ("runtime-cause",),
    ),
    CoreFailureCode.CORE_RUNTIME_FAIL_CLOSED: CoreFailureProfile(
        DegradationCategory.CORE_OR_GATEWAY_FAILURE,
        "myuna-core",
        "core-runtime-fail-closed",
        True,
        False,
        ("request-failed-closed",),
        ("runtime-cause",),
    ),
}

_PROVIDER_CODE_MAP = {
    "transport_failure": CoreFailureCode.PROVIDER_TRANSPORT_FAILURE,
    "rate_limited": CoreFailureCode.PROVIDER_RATE_LIMITED,
    "upstream_server_error": CoreFailureCode.PROVIDER_UPSTREAM_FAILURE,
    "upstream_overloaded": CoreFailureCode.PROVIDER_UPSTREAM_FAILURE,
    "upstream_http_error": CoreFailureCode.PROVIDER_UPSTREAM_FAILURE,
    "invalid_response": CoreFailureCode.PROVIDER_INVALID_RESPONSE,
    "invalid_request": CoreFailureCode.PROVIDER_REQUEST_REJECTED,
    "invalid_parameters": CoreFailureCode.PROVIDER_REQUEST_REJECTED,
    "authentication_failed": CoreFailureCode.PROVIDER_AUTHENTICATION_FAILED,
    "insufficient_balance": CoreFailureCode.PROVIDER_INSUFFICIENT_BALANCE,
    "local_timeout": CoreFailureCode.LOCAL_PROVIDER_TIMEOUT,
    "local_busy": CoreFailureCode.LOCAL_PROVIDER_BUSY,
    "model_unavailable": CoreFailureCode.LOCAL_MODEL_NOT_READY,
    "local_unavailable": CoreFailureCode.LOCAL_PROVIDER_UNAVAILABLE,
    "local_server_error": CoreFailureCode.LOCAL_PROVIDER_UNAVAILABLE,
    "local_http_error": CoreFailureCode.LOCAL_PROVIDER_HTTP_REJECTED,
    "endpoint_redirect_forbidden": (
        CoreFailureCode.LOCAL_PROVIDER_ENDPOINT_REJECTED
    ),
}

_HTTP_ERROR_MAP = {
    "invalid_conversation_request": CoreFailureCode.CORE_REQUEST_REJECTED,
    "profile_unavailable": CoreFailureCode.OWNER_MEMORY_READ_FAILED,
    "runtime_not_activated": CoreFailureCode.CORE_RUNTIME_NOT_READY,
    "provider_daily_budget_exceeded": CoreFailureCode.PROVIDER_DAILY_BUDGET_EXCEEDED,
    "provider_budget_accounting_unavailable": (
        CoreFailureCode.PROVIDER_BUDGET_ACCOUNTING_FAILED
    ),
    "provider_unavailable": CoreFailureCode.PROVIDER_UPSTREAM_FAILURE,
    "reply_failed_runtime_guard": CoreFailureCode.REPLY_RUNTIME_GUARD_REJECTED,
    "runtime_fail_closed": CoreFailureCode.CORE_RUNTIME_FAIL_CLOSED,
    "internal_error": CoreFailureCode.CORE_RUNTIME_FAIL_CLOSED,
}

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


@dataclass(frozen=True, slots=True)
class CoreFailureObservation:
    event_id: str
    correlation_id: str
    code: CoreFailureCode
    first_seen_at: datetime
    last_seen_at: datetime
    occurrence_count: int = 1
    recovery_state: RecoveryState = RecoveryState.ACTIVE

    def __post_init__(self) -> None:
        for label, value in (
            ("event_id", self.event_id),
            ("correlation_id", self.correlation_id),
        ):
            if _SAFE_IDENTIFIER.fullmatch(value) is None:
                raise ValueError(f"{label} must be a safe identifier")
        if not isinstance(self.code, CoreFailureCode):
            raise TypeError("code must be a CoreFailureCode")
        for label, value in (
            ("first_seen_at", self.first_seen_at),
            ("last_seen_at", self.last_seen_at),
        ):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"{label} must be timezone-aware")
        if self.last_seen_at < self.first_seen_at:
            raise ValueError("last_seen_at cannot precede first_seen_at")
        if self.occurrence_count < 1:
            raise ValueError("occurrence_count must be positive")
        if not isinstance(self.recovery_state, RecoveryState):
            raise TypeError("recovery_state must be a RecoveryState")


def core_failure_code_for_provider(provider_code: str) -> CoreFailureCode:
    try:
        return _PROVIDER_CODE_MAP[provider_code]
    except KeyError:
        raise ValueError("provider error code is not mapped to a safe profile") from None


def core_failure_code_for_http_error(error_code: str) -> CoreFailureCode:
    try:
        return _HTTP_ERROR_MAP[error_code]
    except KeyError:
        raise ValueError("HTTP error code is not mapped to a safe profile") from None


def failure_envelope_from_core(
    observation: CoreFailureObservation,
) -> FailureEnvelope:
    profile = _PROFILES[observation.code]
    return FailureEnvelope(
        event_id=observation.event_id,
        correlation_id=observation.correlation_id,
        category=profile.category,
        component=profile.component,
        retryable=profile.retryable,
        owner_action_required=profile.owner_action_required,
        confirmed_facts=profile.confirmed_facts,
        unknown_facts=profile.unknown_facts,
        safe_detail_code=profile.safe_detail_code,
        first_seen_at=observation.first_seen_at,
        last_seen_at=observation.last_seen_at,
        occurrence_count=observation.occurrence_count,
        recovery_state=observation.recovery_state,
    )


def project_core_failure(
    observation: CoreFailureObservation,
) -> SafeDegradationProjection:
    return SafeDegradationProjection.from_envelope(
        failure_envelope_from_core(observation)
    )
