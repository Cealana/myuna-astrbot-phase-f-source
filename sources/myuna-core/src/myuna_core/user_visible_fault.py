"""Versioned, content-free public fault taxonomy for future opt-in projection.

This module is intentionally not imported by the legacy HTTP or degradation paths.
It freezes a v1 public codebook and allowlisted typed mappings for a later gate.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

from .degradation_bridge import CoreFailureCode


PUBLIC_FAULT_SCHEMA = "myuna.user-visible-fault.v1"
CODEBOOK_VERSION = 1
_CODE = re.compile(r"^MYU-[A-Z]+-[0-9]{2}$")
_DOMAIN = re.compile(r"^[a-z]+$")
_RECOVERY_CLASSES = frozenset(
    {"diagnostic_only", "no_action", "owner_check", "owner_review", "retry_later", "retry_rephrase"}
)
_RECOVERY_GATES = frozenset({"T0", "T2", "T3"})


@dataclass(frozen=True, slots=True)
class PublicFaultDescriptor:
    code: str
    domain: str
    category_zh: str
    retryable: bool
    recovery_class: str
    recovery_gate: str

    def __post_init__(self) -> None:
        if _CODE.fullmatch(self.code) is None:
            raise ValueError("public fault code is invalid")
        if _DOMAIN.fullmatch(self.domain) is None:
            raise ValueError("public fault domain is invalid")
        if self.code.split("-")[1].lower() != self.domain:
            raise ValueError("public fault code and domain do not match")
        if (
            not isinstance(self.category_zh, str)
            or self.category_zh != self.category_zh.strip()
            or not 2 <= len(self.category_zh) <= 16
            or any(ord(char) < 32 for char in self.category_zh)
        ):
            raise ValueError("public fault category is invalid")
        if type(self.retryable) is not bool:
            raise TypeError("retryable must be boolean")
        if self.recovery_class not in _RECOVERY_CLASSES:
            raise ValueError("recovery class is invalid")
        if self.recovery_gate not in _RECOVERY_GATES:
            raise ValueError("recovery gate is invalid")

    def as_codebook_row(self) -> dict[str, object]:
        return {
            "code": self.code,
            "domain": self.domain,
            "category_zh": self.category_zh,
            "retryable": self.retryable,
            "recovery_class": self.recovery_class,
            "recovery_gate": self.recovery_gate,
        }

    def as_payload(self) -> dict[str, object]:
        return {
            "schema": PUBLIC_FAULT_SCHEMA,
            "codebook_version": CODEBOOK_VERSION,
            **self.as_codebook_row(),
        }


def _descriptor(
    code: str,
    domain: str,
    category_zh: str,
    retryable: bool,
    recovery_class: str,
    recovery_gate: str,
) -> PublicFaultDescriptor:
    return PublicFaultDescriptor(
        code, domain, category_zh, retryable, recovery_class, recovery_gate
    )


PUBLIC_FAULTS = {
    item.code: item
    for item in (
        _descriptor("MYU-CHANNEL-01", "channel", "通道暂不可用", True, "retry_later", "T2"),
        _descriptor("MYU-CHANNEL-02", "channel", "入口验证失败", False, "owner_check", "T2"),
        _descriptor("MYU-CHANNEL-03", "channel", "请求过于频繁", True, "retry_later", "T0"),
        _descriptor("MYU-IDENTITY-01", "identity", "身份验证失败", False, "owner_check", "T2"),
        _descriptor("MYU-CORE-01", "core", "核心服务未就绪", False, "owner_check", "T2"),
        _descriptor("MYU-CORE-02", "core", "核心处理失败", True, "retry_later", "T2"),
        _descriptor("MYU-CORE-03", "core", "回复安全检查未通过", True, "retry_rephrase", "T0"),
        _descriptor("MYU-PROVIDER-01", "provider", "模型服务超时", True, "retry_later", "T0"),
        _descriptor("MYU-PROVIDER-02", "provider", "模型服务不可用", True, "retry_later", "T0"),
        _descriptor("MYU-PROVIDER-03", "provider", "模型服务配置异常", False, "owner_check", "T2"),
        _descriptor("MYU-LOCAL-01", "local", "本地模型超时", True, "retry_later", "T0"),
        _descriptor("MYU-LOCAL-02", "local", "本地模型不可用", True, "owner_check", "T2"),
        _descriptor("MYU-LOCAL-03", "local", "本地模型未就绪", False, "owner_check", "T2"),
        _descriptor("MYU-LOCAL-04", "local", "本地模型请求被拒", False, "owner_check", "T2"),
        _descriptor("MYU-BUDGET-01", "budget", "模型额度受限", False, "owner_check", "T2"),
        _descriptor("MYU-BUDGET-02", "budget", "额度轮转待处理", False, "owner_check", "T2"),
        _descriptor("MYU-BUDGET-03", "budget", "额度记账异常", False, "owner_check", "T3"),
        _descriptor("MYU-SESSION-01", "session", "会话暂不可用", False, "owner_check", "T3"),
        _descriptor("MYU-SESSION-02", "session", "会话状态异常", False, "owner_check", "T2"),
        _descriptor("MYU-SESSION-03", "session", "会话写入失败", False, "owner_check", "T3"),
        _descriptor("MYU-SESSION-04", "session", "会话容量处理失败", False, "owner_check", "T2"),
        _descriptor("MYU-PROFILE-01", "profile", "资料读取失败", True, "owner_check", "T2"),
        _descriptor("MYU-PROFILE-02", "profile", "资料写入失败", True, "owner_check", "T2"),
        _descriptor("MYU-PROFILE-03", "profile", "资料候选重复", False, "no_action", "T0"),
        _descriptor("MYU-PROFILE-04", "profile", "资料候选冲突", False, "owner_review", "T0"),
        _descriptor("MYU-PROFILE-05", "profile", "资料边界拒绝", False, "owner_review", "T0"),
        _descriptor("MYU-DRIFT-01", "drift", "服务配置漂移", False, "owner_check", "T2"),
        _descriptor("MYU-TIME-01", "time", "可信时间不可用", True, "owner_check", "T2"),
        _descriptor("MYU-TIME-02", "time", "可信时间状态异常", False, "owner_check", "T3"),
        _descriptor("MYU-TEMPORAL-01", "temporal", "时间上下文不可用", True, "owner_check", "T3"),
        _descriptor("MYU-UNKNOWN-01", "unknown", "暂时无法分类", False, "diagnostic_only", "T0"),
    )
}

_UNKNOWN = PUBLIC_FAULTS["MYU-UNKNOWN-01"]

_CORE_TO_PUBLIC = {
    CoreFailureCode.CORE_REQUEST_REJECTED: "MYU-CORE-02",
    CoreFailureCode.REPLY_CONTRACT_REJECTED: "MYU-CORE-03",
    CoreFailureCode.REPLY_RUNTIME_GUARD_REJECTED: "MYU-CORE-03",
    CoreFailureCode.PROVIDER_TRANSPORT_FAILURE: "MYU-PROVIDER-02",
    CoreFailureCode.PROVIDER_RATE_LIMITED: "MYU-PROVIDER-02",
    CoreFailureCode.PROVIDER_UPSTREAM_FAILURE: "MYU-PROVIDER-02",
    CoreFailureCode.PROVIDER_INVALID_RESPONSE: "MYU-PROVIDER-02",
    CoreFailureCode.PROVIDER_REQUEST_REJECTED: "MYU-PROVIDER-03",
    CoreFailureCode.PROVIDER_AUTHENTICATION_FAILED: "MYU-PROVIDER-03",
    CoreFailureCode.PROVIDER_INSUFFICIENT_BALANCE: "MYU-BUDGET-01",
    CoreFailureCode.PROVIDER_DAILY_BUDGET_EXCEEDED: "MYU-BUDGET-01",
    CoreFailureCode.PROVIDER_BUDGET_ACCOUNTING_FAILED: "MYU-BUDGET-03",
    CoreFailureCode.LOCAL_PROVIDER_TIMEOUT: "MYU-LOCAL-01",
    CoreFailureCode.LOCAL_PROVIDER_BUSY: "MYU-LOCAL-02",
    CoreFailureCode.LOCAL_MODEL_NOT_READY: "MYU-LOCAL-03",
    CoreFailureCode.LOCAL_PROVIDER_UNAVAILABLE: "MYU-LOCAL-02",
    CoreFailureCode.LOCAL_PROVIDER_HTTP_REJECTED: "MYU-LOCAL-04",
    CoreFailureCode.LOCAL_PROVIDER_ENDPOINT_REJECTED: "MYU-LOCAL-04",
    CoreFailureCode.OWNER_MEMORY_READ_FAILED: "MYU-PROFILE-01",
    CoreFailureCode.CORE_RUNTIME_NOT_READY: "MYU-CORE-01",
    CoreFailureCode.CORE_RUNTIME_FAIL_CLOSED: "MYU-CORE-02",
}

_SAFE_DETAIL_TO_PUBLIC = {
    "core-request-rejected": "MYU-CORE-02",
    "reply-contract-rejected": "MYU-CORE-03",
    "reply-runtime-guard-rejected": "MYU-CORE-03",
    "provider-transport-failure": "MYU-PROVIDER-02",
    "provider-rate-limited": "MYU-PROVIDER-02",
    "provider-upstream-failure": "MYU-PROVIDER-02",
    "provider-invalid-response": "MYU-PROVIDER-02",
    "provider-request-rejected": "MYU-PROVIDER-03",
    "provider-authentication-failed": "MYU-PROVIDER-03",
    "provider-insufficient-balance": "MYU-BUDGET-01",
    "provider-daily-budget-exceeded": "MYU-BUDGET-01",
    "provider-budget-accounting-failed": "MYU-BUDGET-03",
    "local-provider-timeout": "MYU-LOCAL-01",
    "local-provider-busy": "MYU-LOCAL-02",
    "local-model-not-ready": "MYU-LOCAL-03",
    "local-provider-unavailable": "MYU-LOCAL-02",
    "local-provider-http-rejected": "MYU-LOCAL-04",
    "local-provider-endpoint-rejected": "MYU-LOCAL-04",
    "owner-memory-read-failed": "MYU-PROFILE-01",
    "core-runtime-not-ready": "MYU-CORE-01",
    "core-runtime-fail-closed": "MYU-CORE-02",
}

_TRUSTED_TIME_RETRYABLE = frozenset(
    {
        "trusted_time_unavailable",
        "trusted_time_timeout",
        "trusted_time_unsynchronized",
        "trusted_time_uncertainty_exceeded",
        "trusted_time_drift_exceeded",
        "trusted_time_audit_unavailable",
    }
)
_TRUSTED_TIME_STATE = frozenset(
    {
        "trusted_time_error",
        "trusted_time_permission_denied",
        "trusted_time_regression",
        "trusted_time_source_drift",
        "trusted_time_state_corrupt",
        "trusted_time_state_permission_drift",
        "trusted_time_persistence_ambiguous",
        "trusted_time_sequence_exhausted",
    }
)
_TEMPORAL_FAILURES = frozenset(
    {
        "database_unavailable",
        "database_busy",
        "database_corrupt",
        "database_permission_drift",
        "database_type_drift",
        "database_oversize",
        "schema_unknown",
        "transaction_aborted",
        "retrieval_budget_exceeded",
        "proposal_capacity_exceeded",
    }
)


def public_fault_for_core_failure(code: CoreFailureCode) -> PublicFaultDescriptor:
    if not isinstance(code, CoreFailureCode):
        raise TypeError("code must be a CoreFailureCode")
    return PUBLIC_FAULTS[_CORE_TO_PUBLIC[code]]


def public_fault_for_safe_detail(value: object) -> PublicFaultDescriptor:
    if not isinstance(value, str):
        return _UNKNOWN
    return PUBLIC_FAULTS.get(_SAFE_DETAIL_TO_PUBLIC.get(value, ""), _UNKNOWN)


def public_fault_for_typed_input(
    namespace: object, code: object
) -> PublicFaultDescriptor:
    if namespace == "trusted_time" and code in _TRUSTED_TIME_RETRYABLE:
        return PUBLIC_FAULTS["MYU-TIME-01"]
    if namespace == "trusted_time" and code in _TRUSTED_TIME_STATE:
        return PUBLIC_FAULTS["MYU-TIME-02"]
    if namespace == "active_temporal_context" and code in _TEMPORAL_FAILURES:
        return PUBLIC_FAULTS["MYU-TEMPORAL-01"]
    return _UNKNOWN
