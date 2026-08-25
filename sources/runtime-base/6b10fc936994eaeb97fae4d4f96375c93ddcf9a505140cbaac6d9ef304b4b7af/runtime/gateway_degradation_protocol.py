"""Strict, content-free Gateway responses for Natural Degradation R2B.

This module is deliberately not imported by the live owner runtime in R2B.
R2C may use it for metadata-only observation; a later R2D approval is required
before it can replace any user-visible fallback.
"""

from __future__ import annotations

import json
import re
from typing import Mapping


GATEWAY_RESPONSE_SCHEMA = "myuna.gateway-response.v2"
SAFE_DEGRADATION_SCHEMA = "myuna.safe-degradation.v1"
CORE_FAILURE_RESPONSE_SCHEMA_V1 = "myuna.core-failure-response.v1"
CORE_FAILURE_RESPONSE_SCHEMA = "myuna.core-failure-response.v2"
CORE_FAILURE_PROVENANCE_SCHEMA_V1 = "myuna.core-failure-provenance.v1"
CORE_FAILURE_PROVENANCE_SCHEMA = "myuna.core-failure-provenance.v2"
MAX_GATEWAY_RESPONSE_BYTES = 4096
_SAFE_DETAIL = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
_SAFE_FINGERPRINT = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,383}$")
_SAFE_GATE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_RECOVERY_STATES = frozenset({"active", "recovering", "recovered"})
_SAFE_DEGRADATION_FIELDS = frozenset(
    {
        "schema",
        "status",
        "category",
        "retryable",
        "owner_action_required",
        "safe_detail_code",
        "recovery_state",
        "fingerprint",
        "reply",
    }
)
CANONICAL_DEGRADATION_REPLIES = {
    "memory_no_evidence": "我现在没有找到能确认这件事的记录，所以不能装作记得",
    "reply_contract_rejected": (
        "刚才那句话没有通过回复检查，我没有把不可靠的内容继续发出来。"
        "你可以换个说法再问我一次"
    ),
    "provider_transient_failure": "我刚才没能正常完成这次回复。稍后再试一次就好",
    "provider_budget_or_auth_failure": (
        "我现在没能使用对话模型，这不是你说错了什么，需要先检查服务额度或配置"
    ),
    "core_or_gateway_failure": (
        "我这边的对话服务现在不太正常，这次没能继续处理，需要先恢复服务"
    ),
    "memory_service_failure": (
        "我刚才没能读取记忆服务，所以不能把这次情况说成‘没有相关记忆’。"
        "我只能先根据眼前的对话回答"
    ),
    "onebot_or_napcat_offline": (
        "QQ 连接现在不在线，没法从同一个 QQ 会话继续发送，需要先恢复登录"
    ),
    "host_or_network_unreachable": (
        "服务器或网络现在不可达，同一台机器里的服务没法自行恢复通信"
    ),
    "scheduled_notification_unavailable": (
        "我现在还不能设置定时任务，也不能在你不发消息时主动从 QQ 提醒你。"
        "你可以先设一个手机闹钟，到时再来找我就好"
    ),
    "memory_write_unavailable": (
        "我现在只能读取已经接入的记忆，还不能把新内容写进去。"
        "你可以先记在备忘录里，下次把记录发给我，我可以帮你整理"
    ),
    "external_data_unavailable": "我现在不能查询实时外部数据，所以不能替你确认最新结果",
    "vision_unavailable": "我现在还不能读取图片里的内容",
    "external_action_unavailable": (
        "我现在没有外部操作权限，不能直接替你执行这件事。你完成后再告诉我就好"
    ),
}

_CORE_ERROR_STATUS = {
    "invalid_conversation_request": frozenset({400}),
    "profile_unavailable": frozenset({503}),
    "runtime_not_activated": frozenset({503}),
    "provider_budget_accounting_unavailable": frozenset({503}),
    "provider_daily_budget_exceeded": frozenset({429}),
    "provider_unavailable": frozenset({502, 503}),
    "reply_failed_runtime_guard": frozenset({502}),
    "runtime_fail_closed": frozenset({503}),
    "internal_error": frozenset({500}),
}
_CORE_ERROR_FIELDS = {
    "invalid_conversation_request": frozenset(
        {"error", "failure_schema", "safe_degradation"}
    ),
    "profile_unavailable": frozenset(
        {"error", "failure_schema", "safe_degradation"}
    ),
    "runtime_not_activated": frozenset(
        {"error", "failure_schema", "reasons", "safe_degradation"}
    ),
    "provider_unavailable": frozenset(
        {"error", "failure_schema", "retryable", "safe_degradation"}
    ),
    "provider_daily_budget_exceeded": frozenset(
        {"error", "failure_schema", "safe_degradation"}
    ),
    "provider_budget_accounting_unavailable": frozenset(
        {"error", "failure_schema", "safe_degradation"}
    ),
    "reply_failed_runtime_guard": frozenset(
        {"error", "failure_schema", "safe_degradation"}
    ),
    "runtime_fail_closed": frozenset(
        {"error", "failure_schema", "safe_degradation"}
    ),
    "internal_error": frozenset(
        {"error", "failure_schema", "safe_degradation"}
    ),
}
_CORE_DETAIL_CONTRACT = {
    "core-request-rejected": (
        frozenset({"invalid_conversation_request"}),
        "core_or_gateway_failure",
        False,
        True,
    ),
    "owner-memory-read-failed": (
        frozenset({"profile_unavailable"}),
        "memory_service_failure",
        True,
        False,
    ),
    "core-runtime-not-ready": (
        frozenset({"runtime_not_activated"}),
        "core_or_gateway_failure",
        False,
        True,
    ),
    "provider-daily-budget-exceeded": (
        frozenset({"provider_daily_budget_exceeded"}),
        "provider_budget_or_auth_failure",
        False,
        True,
    ),
    "provider-budget-accounting-failed": (
        frozenset({"provider_budget_accounting_unavailable"}),
        "core_or_gateway_failure",
        False,
        True,
    ),
    "provider-transport-failure": (
        frozenset({"provider_unavailable"}),
        "provider_transient_failure",
        True,
        False,
    ),
    "provider-rate-limited": (
        frozenset({"provider_unavailable"}),
        "provider_transient_failure",
        True,
        False,
    ),
    "provider-upstream-failure": (
        frozenset({"provider_unavailable"}),
        "provider_transient_failure",
        True,
        False,
    ),
    "provider-invalid-response": (
        frozenset({"provider_unavailable"}),
        "provider_transient_failure",
        True,
        False,
    ),
    "provider-request-rejected": (
        frozenset({"provider_unavailable"}),
        "core_or_gateway_failure",
        False,
        True,
    ),
    "provider-authentication-failed": (
        frozenset({"provider_unavailable"}),
        "provider_budget_or_auth_failure",
        False,
        True,
    ),
    "provider-insufficient-balance": (
        frozenset({"provider_unavailable"}),
        "provider_budget_or_auth_failure",
        False,
        True,
    ),
    "local-provider-timeout": (
        frozenset({"provider_unavailable"}),
        "provider_transient_failure",
        True,
        False,
    ),
    "local-provider-busy": (
        frozenset({"provider_unavailable"}),
        "provider_transient_failure",
        True,
        False,
    ),
    "local-model-not-ready": (
        frozenset({"provider_unavailable"}),
        "core_or_gateway_failure",
        False,
        True,
    ),
    "local-provider-unavailable": (
        frozenset({"provider_unavailable"}),
        "provider_transient_failure",
        True,
        False,
    ),
    "local-provider-http-rejected": (
        frozenset({"provider_unavailable"}),
        "core_or_gateway_failure",
        False,
        True,
    ),
    "local-provider-endpoint-rejected": (
        frozenset({"provider_unavailable"}),
        "core_or_gateway_failure",
        False,
        True,
    ),
    "reply-runtime-guard-rejected": (
        frozenset({"reply_failed_runtime_guard"}),
        "reply_contract_rejected",
        True,
        False,
    ),
    "core-runtime-fail-closed": (
        frozenset({"provider_unavailable", "runtime_fail_closed", "internal_error"}),
        "core_or_gateway_failure",
        True,
        False,
    ),
}
_GATEWAY_LOCAL_DETAILS = {
    "gateway-core-unreachable": ("core_or_gateway_failure", True, False),
    "gateway-core-invalid-response": ("core_or_gateway_failure", True, False),
    "gateway-owner-duplicate-suppressed": ("core_or_gateway_failure", True, False),
    "gateway-owner-rate-limited": ("core_or_gateway_failure", True, False),
    "gateway-temporal-unavailable": ("core_or_gateway_failure", True, False),
}
_PROVENANCE_FIELDS_V1 = frozenset(
    {
        "schema",
        "stage",
        "provider_outcome_class",
        "attempt_count",
        "provider_called",
        "model_called",
        "profile_called",
        "memory_called",
        "tool_called",
        "persona_grounding_class",
        "output_guard_applied",
    }
)
_PROVENANCE_FIELDS = _PROVENANCE_FIELDS_V1 | frozenset({"failure_gate"})
_PROVENANCE_STAGES = frozenset(
    {
        "core_pre_provider",
        "core_readiness",
        "core_runtime",
        "core_response",
        "core_transport",
        "entry_guard",
        "output_repair",
        "profile_projection",
        "provider_readiness",
        "provider_request",
        "provider_response",
        "request_parser",
        "temporal_context",
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
_CORE_PRE_PROVIDER_FAILURE_GATES = frozenset(
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
_GATEWAY_PROVENANCE = {
    "gateway-core-invalid-response": (
        "core_response",
        "unknown",
        None,
        "core_invalid_response",
    ),
    "gateway-core-unreachable": (
        "core_transport",
        "unknown",
        None,
        "core_unavailable",
    ),
    "gateway-owner-duplicate-suppressed": (
        "entry_guard",
        "not_called",
        False,
        "duplicate_suppressed",
    ),
    "gateway-owner-rate-limited": (
        "entry_guard",
        "not_called",
        False,
        "rate_limited",
    ),
    "gateway-temporal-unavailable": (
        "temporal_context",
        "not_called",
        False,
        "temporal_unavailable",
    ),
}
_CORE_DETAIL_PROVENANCE = {
    "core-request-rejected": (frozenset({"request_parser"}), False, False),
    "owner-memory-read-failed": (frozenset({"profile_projection"}), False, False),
    "core-runtime-not-ready": (frozenset({"core_readiness"}), False, False),
    "provider-daily-budget-exceeded": (frozenset({"core_pre_provider"}), False, False),
    "provider-budget-accounting-failed": (frozenset({"core_pre_provider"}), False, False),
    "provider-transport-failure": (frozenset({"provider_request"}), True, False),
    "provider-rate-limited": (frozenset({"provider_request"}), True, False),
    "provider-upstream-failure": (frozenset({"provider_request"}), True, False),
    "provider-invalid-response": (frozenset({"provider_response"}), True, False),
    "provider-request-rejected": (frozenset({"provider_request"}), True, False),
    "provider-authentication-failed": (frozenset({"provider_request"}), True, False),
    "provider-insufficient-balance": (frozenset({"provider_request"}), True, False),
    "local-provider-timeout": (frozenset({"provider_request"}), True, False),
    "local-provider-busy": (frozenset({"provider_request"}), True, False),
    "local-model-not-ready": (frozenset({"provider_readiness"}), True, False),
    "local-provider-unavailable": (frozenset({"provider_request"}), True, False),
    "local-provider-http-rejected": (frozenset({"provider_response"}), True, False),
    "local-provider-endpoint-rejected": (frozenset({"provider_request"}), True, False),
    "reply-runtime-guard-rejected": (frozenset({"output_repair"}), True, True),
    "core-runtime-fail-closed": (
        frozenset({"core_pre_provider", "core_runtime"}),
        None,
        None,
    ),
}


class GatewayDegradationProtocolError(ValueError):
    """A content-free protocol rejection safe to count without raw payloads."""


def validate_core_failure_provenance(payload: object) -> dict[str, object]:
    if not isinstance(payload, Mapping):
        raise GatewayDegradationProtocolError("Core failure provenance rejected")
    schema = payload.get("schema")
    fields = (
        _PROVENANCE_FIELDS_V1
        if schema == CORE_FAILURE_PROVENANCE_SCHEMA_V1
        else _PROVENANCE_FIELDS
        if schema == CORE_FAILURE_PROVENANCE_SCHEMA
        else None
    )
    if fields is None or set(payload) != fields:
        raise GatewayDegradationProtocolError("Core failure provenance rejected")
    if payload.get("stage") not in _PROVENANCE_STAGES:
        raise GatewayDegradationProtocolError("Core failure provenance rejected")
    if payload.get("provider_outcome_class") not in _PROVIDER_OUTCOMES:
        raise GatewayDegradationProtocolError("Core failure provenance rejected")
    attempts = payload.get("attempt_count")
    if attempts is not None and (
        type(attempts) is not int or not 0 <= attempts <= 16
    ):
        raise GatewayDegradationProtocolError("Core failure provenance rejected")
    for field in (
        "provider_called",
        "model_called",
        "profile_called",
        "memory_called",
        "tool_called",
        "output_guard_applied",
    ):
        if payload.get(field) is not None and type(payload[field]) is not bool:
            raise GatewayDegradationProtocolError("Core failure provenance rejected")
    if payload.get("persona_grounding_class") not in _PERSONA_CLASSES:
        raise GatewayDegradationProtocolError("Core failure provenance rejected")
    if schema == CORE_FAILURE_PROVENANCE_SCHEMA:
        failure_gate = payload.get("failure_gate")
        if (
            not isinstance(failure_gate, str)
            or _SAFE_GATE.fullmatch(failure_gate) is None
        ):
            raise GatewayDegradationProtocolError("Core failure provenance rejected")
        if (
            payload.get("stage") == "core_pre_provider"
            and failure_gate not in _CORE_PRE_PROVIDER_FAILURE_GATES
            and failure_gate not in {
                "provider_budget_accounting_failed",
                "provider_daily_budget_exceeded",
            }
        ):
            raise GatewayDegradationProtocolError("Core failure provenance rejected")
    provider_called = payload.get("provider_called")
    provider_outcome = payload.get("provider_outcome_class")
    if provider_called is False and provider_outcome != "not_called":
        raise GatewayDegradationProtocolError("Core failure provenance rejected")
    if provider_called is True and provider_outcome in {"not_called", "unknown"}:
        raise GatewayDegradationProtocolError("Core failure provenance rejected")
    if payload.get("model_called") is True and provider_called is not True:
        raise GatewayDegradationProtocolError("Core failure provenance rejected")
    if attempts == 0 and provider_called is not False:
        raise GatewayDegradationProtocolError("Core failure provenance rejected")
    if provider_called is True and attempts is not None and attempts < 1:
        raise GatewayDegradationProtocolError("Core failure provenance rejected")
    if payload.get("output_guard_applied") is True and payload.get("model_called") is not True:
        raise GatewayDegradationProtocolError("Core failure provenance rejected")
    return dict(payload)


def unknown_core_failure_provenance(*, stage: str = "unknown") -> dict[str, object]:
    return validate_core_failure_provenance(
        {
            "schema": CORE_FAILURE_PROVENANCE_SCHEMA,
            "failure_gate": "unknown",
            "stage": stage,
            "provider_outcome_class": "unknown",
            "attempt_count": None,
            "provider_called": None,
            "model_called": None,
            "profile_called": None,
            "memory_called": None,
            "tool_called": None,
            "persona_grounding_class": "unknown",
            "output_guard_applied": None,
        }
    )


def deterministic_gateway_failure_provenance(detail: str) -> dict[str, object]:
    try:
        stage, outcome, called, failure_gate = _GATEWAY_PROVENANCE[detail]
    except KeyError:
        raise GatewayDegradationProtocolError(
            "Gateway failure detail rejected"
        ) from None
    return validate_core_failure_provenance(
        {
            "schema": CORE_FAILURE_PROVENANCE_SCHEMA,
            "failure_gate": failure_gate,
            "stage": stage,
            "provider_outcome_class": outcome,
            "attempt_count": 0 if called is False else None,
            "provider_called": called,
            "model_called": False if called is False else None,
            "profile_called": False if called is False else None,
            "memory_called": False if called is False else None,
            "tool_called": False if called is False else None,
            "persona_grounding_class": "not_evaluated",
            "output_guard_applied": False if called is False else None,
        }
    )


def _require_core_detail_provenance(
    detail: str,
    provenance: Mapping[str, object],
) -> None:
    try:
        stages, provider_called, output_guard = _CORE_DETAIL_PROVENANCE[detail]
    except KeyError:
        raise GatewayDegradationProtocolError(
            "Core failure provenance contract rejected"
        ) from None
    if provenance["stage"] not in stages:
        raise GatewayDegradationProtocolError(
            "Core failure provenance contract rejected"
        )
    if provider_called is not None and provenance["provider_called"] is not provider_called:
        raise GatewayDegradationProtocolError(
            "Core failure provenance contract rejected"
        )
    if output_guard is not None and provenance["output_guard_applied"] is not output_guard:
        raise GatewayDegradationProtocolError(
            "Core failure provenance contract rejected"
        )
    if detail == "core-runtime-fail-closed":
        if provenance["stage"] == "core_pre_provider" and provenance["provider_called"] is not False:
            raise GatewayDegradationProtocolError(
                "Core failure provenance contract rejected"
            )
        if provenance["stage"] == "core_runtime" and provenance["provider_called"] is False:
            raise GatewayDegradationProtocolError(
                "Core failure provenance contract rejected"
            )


def validate_safe_degradation(payload: object) -> dict[str, object]:
    if not isinstance(payload, Mapping) or set(payload) != _SAFE_DEGRADATION_FIELDS:
        raise GatewayDegradationProtocolError("safe degradation rejected")
    string_fields = (
        "schema",
        "status",
        "category",
        "safe_detail_code",
        "recovery_state",
        "fingerprint",
        "reply",
    )
    if any(not isinstance(payload[field], str) for field in string_fields):
        raise GatewayDegradationProtocolError("safe degradation rejected")
    if payload["schema"] != SAFE_DEGRADATION_SCHEMA or payload["status"] != "degraded":
        raise GatewayDegradationProtocolError("safe degradation rejected")
    category = payload["category"]
    if category not in CANONICAL_DEGRADATION_REPLIES:
        raise GatewayDegradationProtocolError("safe degradation rejected")
    if payload["recovery_state"] not in _RECOVERY_STATES:
        raise GatewayDegradationProtocolError("safe degradation rejected")
    if type(payload["retryable"]) is not bool:
        raise GatewayDegradationProtocolError("safe degradation rejected")
    if type(payload["owner_action_required"]) is not bool:
        raise GatewayDegradationProtocolError("safe degradation rejected")
    if _SAFE_DETAIL.fullmatch(payload["safe_detail_code"]) is None:
        raise GatewayDegradationProtocolError("safe degradation rejected")
    if _SAFE_FINGERPRINT.fullmatch(payload["fingerprint"]) is None:
        raise GatewayDegradationProtocolError("safe degradation rejected")
    reply = payload["reply"]
    if reply != CANONICAL_DEGRADATION_REPLIES[category] or not 1 <= len(reply) <= 512:
        raise GatewayDegradationProtocolError("safe degradation rejected")
    return dict(payload)


def validate_core_failure_response(
    http_status: int,
    payload: object,
) -> dict[str, object]:
    """Validate the private Core error envelope without retaining its extras."""

    projection, _provenance = validate_core_failure_response_with_provenance(
        http_status,
        payload,
    )
    return projection


def validate_core_failure_response_with_provenance(
    http_status: int,
    payload: object,
) -> tuple[dict[str, object], dict[str, object]]:
    """Validate safe degradation and a versioned fixed-field provenance seam."""

    if not isinstance(payload, Mapping):
        raise GatewayDegradationProtocolError("Core failure response rejected")
    error = payload.get("error")
    if not isinstance(error, str) or error not in _CORE_ERROR_STATUS:
        raise GatewayDegradationProtocolError("Core failure response rejected")
    if type(http_status) is not int or http_status not in _CORE_ERROR_STATUS[error]:
        raise GatewayDegradationProtocolError("Core failure response rejected")
    failure_schema = payload.get("failure_schema")
    expected_fields = _CORE_ERROR_FIELDS[error]
    if failure_schema == CORE_FAILURE_RESPONSE_SCHEMA_V1:
        if set(payload) != expected_fields:
            raise GatewayDegradationProtocolError("Core failure response rejected")
        provenance = unknown_core_failure_provenance()
    elif failure_schema == CORE_FAILURE_RESPONSE_SCHEMA:
        if set(payload) != expected_fields | {"failure_provenance"}:
            raise GatewayDegradationProtocolError("Core failure response rejected")
        provenance = validate_core_failure_provenance(
            payload.get("failure_provenance")
        )
    else:
        raise GatewayDegradationProtocolError("Core failure response rejected")
    if error == "provider_unavailable" and type(payload.get("retryable")) is not bool:
        raise GatewayDegradationProtocolError("Core failure response rejected")
    if error == "runtime_not_activated":
        reasons = payload.get("reasons")
        if (
            not isinstance(reasons, list)
            or len(reasons) > 16
            or any(
                not isinstance(reason, str) or _SAFE_DETAIL.fullmatch(reason) is None
                for reason in reasons
            )
        ):
            raise GatewayDegradationProtocolError("Core failure response rejected")
    projection = validate_safe_degradation(payload.get("safe_degradation"))
    contract = _CORE_DETAIL_CONTRACT.get(str(projection["safe_detail_code"]))
    if contract is None:
        raise GatewayDegradationProtocolError("Core failure response rejected")
    allowed_errors, category, retryable, owner_action_required = contract
    if (
        error not in allowed_errors
        or projection["category"] != category
        or projection["retryable"] is not retryable
        or projection["owner_action_required"] is not owner_action_required
    ):
        raise GatewayDegradationProtocolError("Core failure response rejected")
    if failure_schema == CORE_FAILURE_RESPONSE_SCHEMA:
        _require_core_detail_provenance(
            str(projection["safe_detail_code"]), provenance
        )
    return projection, provenance


def accepted_reply_payload(reply: str) -> dict[str, object]:
    if not isinstance(reply, str) or not reply.strip() or len(reply) > 4000:
        raise GatewayDegradationProtocolError("accepted reply rejected")
    return {
        "kind": "accepted_reply",
        "reply": reply.strip(),
        "schema": GATEWAY_RESPONSE_SCHEMA,
    }


def safe_degraded_reply_payload(projection: object) -> dict[str, object]:
    return {
        "degradation": validate_safe_degradation(projection),
        "kind": "safe_degraded_reply",
        "schema": GATEWAY_RESPONSE_SCHEMA,
    }


def deterministic_gateway_projection(detail: str) -> dict[str, object]:
    try:
        category, retryable, owner_action_required = _GATEWAY_LOCAL_DETAILS[detail]
    except KeyError:
        raise GatewayDegradationProtocolError("Gateway failure detail rejected") from None
    return {
        "schema": SAFE_DEGRADATION_SCHEMA,
        "status": "degraded",
        "category": category,
        "retryable": retryable,
        "owner_action_required": owner_action_required,
        "safe_detail_code": detail,
        "recovery_state": "active",
        "fingerprint": f"{category}:gateway:{detail}",
        "reply": CANONICAL_DEGRADATION_REPLIES[category],
    }


def deterministic_core_unreachable_projection() -> dict[str, object]:
    return deterministic_gateway_projection("gateway-core-unreachable")


def encode_gateway_response(payload: object) -> bytes:
    if not isinstance(payload, Mapping):
        raise GatewayDegradationProtocolError("gateway response rejected")
    kind = payload.get("kind")
    if kind == "accepted_reply" and set(payload) == {"kind", "reply", "schema"}:
        if payload.get("schema") != GATEWAY_RESPONSE_SCHEMA:
            raise GatewayDegradationProtocolError("gateway response rejected")
        canonical = accepted_reply_payload(payload["reply"])
    elif kind == "safe_degraded_reply" and set(payload) == {
        "degradation",
        "kind",
        "schema",
    }:
        if payload.get("schema") != GATEWAY_RESPONSE_SCHEMA:
            raise GatewayDegradationProtocolError("gateway response rejected")
        canonical = safe_degraded_reply_payload(payload["degradation"])
    else:
        raise GatewayDegradationProtocolError("gateway response rejected")
    encoded = json.dumps(
        canonical,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    if len(encoded) > MAX_GATEWAY_RESPONSE_BYTES:
        raise GatewayDegradationProtocolError("gateway response rejected")
    return encoded
