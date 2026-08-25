from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping

from .degradation_bridge import (
    CoreFailureCode,
    CoreFailureObservation,
    core_failure_code_for_provider,
    project_core_failure,
)


CORE_FAILURE_RESPONSE_SCHEMA_V1 = "myuna.core-failure-response.v1"
CORE_FAILURE_RESPONSE_SCHEMA = "myuna.core-failure-response.v2"
CORE_FAILURE_PROVENANCE_SCHEMA_V1 = "myuna.core-failure-provenance.v1"
CORE_FAILURE_PROVENANCE_SCHEMA = "myuna.core-failure-provenance.v2"
_HTTP_FAILURE_CODES = frozenset(
    {
        "internal_error",
        "invalid_conversation_request",
        "profile_unavailable",
        "provider_budget_accounting_unavailable",
        "provider_daily_budget_exceeded",
        "provider_unavailable",
        "reply_failed_runtime_guard",
        "runtime_fail_closed",
        "runtime_not_activated",
    }
)
_STAGES = frozenset(
    {
        "core_pre_provider",
        "core_readiness",
        "core_runtime",
        "output_repair",
        "profile_projection",
        "provider_readiness",
        "provider_request",
        "provider_response",
        "request_parser",
        "unknown",
    }
)
_PROVIDER_OUTCOMES = frozenset(
    {
        "authentication_failed",
        "budget_failure",
        "invalid_response",
        "not_called",
        "rate_limited",
        "request_rejected",
        "timeout",
        "transport_failure",
        "unknown",
        "upstream_failure",
    }
)
_PERSONA_CLASSES = frozenset(
    {
        "external_operation",
        "not_evaluated",
        "real_world_observation",
        "soft_persona_daily_life",
        "unknown",
        "unscoped",
    }
)
_PROVIDER_STAGE = {
    "authentication_failed": ("provider_request", "authentication_failed"),
    "endpoint_redirect_forbidden": ("provider_request", "request_rejected"),
    "insufficient_balance": ("provider_request", "budget_failure"),
    "invalid_parameters": ("provider_request", "request_rejected"),
    "invalid_request": ("provider_request", "request_rejected"),
    "invalid_response": ("provider_response", "invalid_response"),
    "local_busy": ("provider_request", "upstream_failure"),
    "local_http_error": ("provider_response", "invalid_response"),
    "local_server_error": ("provider_request", "upstream_failure"),
    "local_timeout": ("provider_request", "timeout"),
    "local_unavailable": ("provider_request", "transport_failure"),
    "model_unavailable": ("provider_readiness", "upstream_failure"),
    "rate_limited": ("provider_request", "rate_limited"),
    "transport_failure": ("provider_request", "transport_failure"),
    "upstream_http_error": ("provider_request", "upstream_failure"),
    "upstream_overloaded": ("provider_request", "upstream_failure"),
    "upstream_server_error": ("provider_request", "upstream_failure"),
}
_PRE_PROVIDER_FAILURE_GATES = frozenset(
    {
        "core_pre_provider_unknown",
        "credential_material_excluded",
        "definition_digest_mismatch",
        "definition_out_of_contract",
        "egress_safety_unavailable",
        "external_profile_egress_rejected",
        "forwarded_private_content_excluded",
        "generation_timeout_out_of_contract",
        "profile_context_characters_exceeded",
        "profile_section_count_exceeded",
        "profile_state_out_of_contract",
        "projection_byte_budget_exceeded",
        "projection_character_budget_exceeded",
        "projection_token_budget_exceeded",
        "recent_turn_characters_exceeded",
        "third_party_private_content_excluded",
        "token_capacity_oracle_unavailable",
    }
)
_FAILURE_GATES = _PRE_PROVIDER_FAILURE_GATES | frozenset(_PROVIDER_STAGE) | frozenset(
    {
        "core_request_rejected",
        "core_runtime_not_ready",
        "owner_memory_read_failed",
        "provider_budget_accounting_failed",
        "provider_daily_budget_exceeded",
        "reply_runtime_guard_rejected",
        "unknown",
    }
)
_DEFAULT_PRE_PROVIDER_GATE = {
    "core_readiness": "core_runtime_not_ready",
    "profile_projection": "owner_memory_read_failed",
    "request_parser": "core_request_rejected",
}


def safe_pre_provider_failure_gate(value: object) -> str:
    """Project one source-owned error code onto the frozen content-free gate set."""

    if isinstance(value, str) and value in _PRE_PROVIDER_FAILURE_GATES:
        return value
    return "core_pre_provider_unknown"


def _optional_bool(value: object, label: str) -> bool | None:
    if value is None or type(value) is bool:
        return value
    raise TypeError(f"{label} must be boolean or null")


@dataclass(frozen=True, slots=True)
class CoreFailureProvenance:
    stage: str
    provider_outcome_class: str
    attempt_count: int | None
    provider_called: bool | None
    model_called: bool | None
    profile_called: bool | None
    memory_called: bool | None
    tool_called: bool | None
    persona_grounding_class: str
    output_guard_applied: bool | None
    failure_gate: str = "unknown"

    def __post_init__(self) -> None:
        if self.stage not in _STAGES:
            raise ValueError("failure provenance stage is invalid")
        if self.provider_outcome_class not in _PROVIDER_OUTCOMES:
            raise ValueError("failure provenance provider outcome is invalid")
        if self.attempt_count is not None and (
            type(self.attempt_count) is not int
            or not 0 <= self.attempt_count <= 16
        ):
            raise ValueError("failure provenance attempt count is invalid")
        for field in (
            "provider_called",
            "model_called",
            "profile_called",
            "memory_called",
            "tool_called",
            "output_guard_applied",
        ):
            _optional_bool(getattr(self, field), field)
        if self.persona_grounding_class not in _PERSONA_CLASSES:
            raise ValueError("failure provenance persona class is invalid")
        if self.failure_gate not in _FAILURE_GATES:
            raise ValueError("failure provenance gate is invalid")
        if self.provider_called is False and self.provider_outcome_class != "not_called":
            raise ValueError("failure provenance provider outcome contradicts call evidence")
        if self.provider_called is True and self.provider_outcome_class in {
            "not_called",
            "unknown",
        }:
            raise ValueError("failure provenance provider outcome contradicts call evidence")
        if self.model_called is True and self.provider_called is not True:
            raise ValueError("failure provenance model call lacks provider call")
        if self.attempt_count == 0 and self.provider_called is not False:
            raise ValueError("zero attempts require provider_called=false")
        if self.provider_called is True and (
            self.attempt_count is not None and self.attempt_count < 1
        ):
            raise ValueError("provider calls require a positive attempt count")
        if self.output_guard_applied is True and self.model_called is not True:
            raise ValueError("output guard evidence requires a model call")

    def as_payload(self) -> dict[str, object]:
        return {
            "schema": CORE_FAILURE_PROVENANCE_SCHEMA,
            "failure_gate": self.failure_gate,
            "stage": self.stage,
            "provider_outcome_class": self.provider_outcome_class,
            "attempt_count": self.attempt_count,
            "provider_called": self.provider_called,
            "model_called": self.model_called,
            "profile_called": self.profile_called,
            "memory_called": self.memory_called,
            "tool_called": self.tool_called,
            "persona_grounding_class": self.persona_grounding_class,
            "output_guard_applied": self.output_guard_applied,
        }


def unknown_core_failure_provenance(
    *,
    stage: str = "core_runtime",
    persona_grounding_class: str = "unknown",
) -> CoreFailureProvenance:
    return CoreFailureProvenance(
        stage=stage,
        provider_outcome_class="unknown",
        attempt_count=None,
        provider_called=None,
        model_called=None,
        profile_called=None,
        memory_called=None,
        tool_called=None,
        persona_grounding_class=persona_grounding_class,
        output_guard_applied=None,
        failure_gate="unknown",
    )


def pre_provider_failure_provenance(
    stage: str,
    *,
    profile_called: bool | None = False,
    persona_grounding_class: str = "unknown",
    failure_gate: str | None = None,
) -> CoreFailureProvenance:
    resolved_gate = failure_gate or _DEFAULT_PRE_PROVIDER_GATE.get(
        stage, "core_pre_provider_unknown"
    )
    return CoreFailureProvenance(
        stage=stage,
        provider_outcome_class="not_called",
        attempt_count=0,
        provider_called=False,
        model_called=False,
        profile_called=profile_called,
        memory_called=False,
        tool_called=False,
        persona_grounding_class=persona_grounding_class,
        output_guard_applied=False,
        failure_gate=resolved_gate,
    )


def output_repair_failure_provenance(
    *,
    attempt_count: int | None,
    profile_called: bool | None = None,
    persona_grounding_class: str = "unknown",
) -> CoreFailureProvenance:
    return CoreFailureProvenance(
        stage="output_repair",
        provider_outcome_class="invalid_response",
        attempt_count=attempt_count,
        provider_called=True,
        model_called=True,
        profile_called=profile_called,
        memory_called=None,
        tool_called=False,
        persona_grounding_class=persona_grounding_class,
        output_guard_applied=True,
        failure_gate="reply_runtime_guard_rejected",
    )


def provider_failure_provenance(
    provider_code: str,
    *,
    attempt_count: int | None,
    profile_called: bool | None = None,
    persona_grounding_class: str = "unknown",
) -> CoreFailureProvenance:
    stage, outcome = _PROVIDER_STAGE.get(
        provider_code,
        ("provider_request", "request_rejected"),
    )
    return CoreFailureProvenance(
        stage=stage,
        provider_outcome_class=outcome,
        attempt_count=(
            attempt_count
            if type(attempt_count) is int and 1 <= attempt_count <= 16
            else None
        ),
        provider_called=True,
        model_called=True,
        profile_called=profile_called,
        memory_called=None,
        tool_called=False,
        persona_grounding_class=persona_grounding_class,
        output_guard_applied=False,
        failure_gate=provider_code,
    )


def _default_core_failure_provenance(
    code: CoreFailureCode,
) -> CoreFailureProvenance:
    if code is CoreFailureCode.CORE_REQUEST_REJECTED:
        return pre_provider_failure_provenance(
            "request_parser", failure_gate="core_request_rejected"
        )
    if code is CoreFailureCode.OWNER_MEMORY_READ_FAILED:
        return pre_provider_failure_provenance(
            "profile_projection",
            profile_called=True,
            failure_gate="owner_memory_read_failed",
        )
    if code is CoreFailureCode.CORE_RUNTIME_NOT_READY:
        return pre_provider_failure_provenance(
            "core_readiness", failure_gate="core_runtime_not_ready"
        )
    if code is CoreFailureCode.PROVIDER_DAILY_BUDGET_EXCEEDED:
        return pre_provider_failure_provenance(
            "core_pre_provider",
            profile_called=None,
            failure_gate="provider_daily_budget_exceeded",
        )
    if code is CoreFailureCode.PROVIDER_BUDGET_ACCOUNTING_FAILED:
        return pre_provider_failure_provenance(
            "core_pre_provider",
            profile_called=None,
            failure_gate="provider_budget_accounting_failed",
        )
    if code in {
        CoreFailureCode.REPLY_CONTRACT_REJECTED,
        CoreFailureCode.REPLY_RUNTIME_GUARD_REJECTED,
    }:
        return output_repair_failure_provenance(attempt_count=None)
    return unknown_core_failure_provenance()


def _projection(
    request_id: str,
    code: CoreFailureCode,
    *,
    observed_at: datetime | None = None,
) -> dict[str, object]:
    now = observed_at or datetime.now(timezone.utc)
    observation = CoreFailureObservation(
        event_id=f"failure-{request_id}",
        correlation_id=request_id,
        code=code,
        first_seen_at=now,
        last_seen_at=now,
    )
    return project_core_failure(observation).as_payload()


def attach_core_failure_metadata(
    payload: Mapping[str, object],
    *,
    request_id: str,
    code: CoreFailureCode,
    observed_at: datetime | None = None,
    provenance: CoreFailureProvenance | None = None,
) -> dict[str, object]:
    """Attach one canonical, content-free degradation projection.

    The original HTTP error and compatibility fields remain unchanged.  The
    projection is private loopback metadata and never contains the request,
    provider output, prompt, log, account, credential or memory identifiers.
    """

    error = payload.get("error")
    if not isinstance(error, str) or error not in _HTTP_FAILURE_CODES:
        raise ValueError("unsupported Core HTTP failure payload")
    result = dict(payload)
    result["failure_schema"] = CORE_FAILURE_RESPONSE_SCHEMA
    result["failure_provenance"] = (
        provenance or _default_core_failure_provenance(code)
    ).as_payload()
    result["safe_degradation"] = _projection(
        request_id,
        code,
        observed_at=observed_at,
    )
    return result


def attach_provider_failure_metadata(
    payload: Mapping[str, object],
    *,
    request_id: str,
    provider_code: str,
    observed_at: datetime | None = None,
    attempt_count: int | None = 1,
    profile_called: bool | None = None,
    persona_grounding_class: str = "unknown",
) -> dict[str, object]:
    """Map one safe provider code without exposing its message or response."""

    try:
        code = core_failure_code_for_provider(provider_code)
    except (TypeError, ValueError):
        code = CoreFailureCode.CORE_RUNTIME_FAIL_CLOSED
        provenance = unknown_core_failure_provenance(
            persona_grounding_class=persona_grounding_class
        )
    else:
        provenance = provider_failure_provenance(
            provider_code,
            attempt_count=attempt_count,
            profile_called=profile_called,
            persona_grounding_class=persona_grounding_class,
        )
    return attach_core_failure_metadata(
        payload,
        request_id=request_id,
        code=code,
        observed_at=observed_at,
        provenance=provenance,
    )
