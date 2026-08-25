"""Inactive-by-default public fault renderer, correlation and bounded index v1."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
import re
import secrets
from typing import Mapping


PUBLIC_FAULT_SCHEMA = "myuna.user-visible-fault.v1"
INCIDENT_INDEX_SCHEMA = "myuna.user-visible-fault-index.v1"
INCIDENT_INDEX_SET_SCHEMA = "myuna.user-visible-fault-index-set.v1"
CODEBOOK_VERSION = 1
_CODE = re.compile(r"^MYU-[A-Z]+-[0-9]{2}$")
_INCIDENT_REF = re.compile(r"^inc1-[0-9a-f]{32}$")
_DOMAIN = re.compile(r"^[a-z]+$")
_CHANNELS = frozenset({"qq", "telegram"})
_REF_STATES = frozenset({"available", "unavailable"})
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

_DIAGNOSTIC_TO_PUBLIC: dict[str, str | None] = {
    "active": None,
    "listening": None,
    "secure": None,
    "match": None,
    "current": None,
    "session_capacity_128": None,
    "duplicate_suppressed": None,
    "recovery_episode_active": None,
    "service_inactive": "MYU-CHANNEL-01",
    "socket_inactive": "MYU-CHANNEL-01",
    "ingress_rejected": "MYU-CHANNEL-02",
    "identity_rejected": "MYU-IDENTITY-01",
    "rate_limited": "MYU-CHANNEL-03",
    "session_unavailable": "MYU-SESSION-01",
    "session_capacity_mismatch": "MYU-SESSION-04",
    "session_corrupt": "MYU-SESSION-02",
    "session_write_failed": "MYU-SESSION-03",
    "core_unreachable": "MYU-CORE-01",
    "core_invalid_response": "MYU-CORE-02",
    "core_runtime_not_ready": "MYU-CORE-01",
    "core_runtime_fail_closed": "MYU-CORE-02",
    "provider_timeout": "MYU-PROVIDER-01",
    "provider_unavailable": "MYU-PROVIDER-02",
    "provider_auth_failed": "MYU-PROVIDER-03",
    "budget_exceeded": "MYU-BUDGET-01",
    "budget_rollover_required": "MYU-BUDGET-02",
    "budget_accounting_failed": "MYU-BUDGET-03",
    "local_model_not_ready": "MYU-LOCAL-03",
    "local_model_readiness_unverified": "MYU-UNKNOWN-01",
    "local_provider_timeout": "MYU-LOCAL-01",
    "local_provider_busy": "MYU-LOCAL-02",
    "local_provider_unavailable": "MYU-LOCAL-02",
    "local_provider_http_rejected": "MYU-LOCAL-04",
    "local_provider_endpoint_rejected": "MYU-LOCAL-04",
    "profile_read_unavailable": "MYU-PROFILE-01",
    "profile_write_unavailable": "MYU-PROFILE-02",
    "candidate_duplicate": "MYU-PROFILE-03",
    "candidate_conflict": "MYU-PROFILE-04",
    "boundary_rejected": "MYU-PROFILE-05",
    "recovery_state_unavailable": "MYU-CORE-02",
    "config_drift": "MYU-DRIFT-01",
    "release_drift": "MYU-DRIFT-01",
    "permission_drift": "MYU-DRIFT-01",
    "temporal_context_unavailable": "MYU-TEMPORAL-01",
    "temporal_service_inactive": "MYU-TEMPORAL-01",
    "temporal_socket_inactive": "MYU-TEMPORAL-01",
    "unknown_insufficient_safe_evidence": "MYU-UNKNOWN-01",
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


def public_fault_for_diagnostic(code: object) -> PublicFaultDescriptor | None:
    if not isinstance(code, str):
        return _UNKNOWN
    mapped = _DIAGNOSTIC_TO_PUBLIC.get(code, "MYU-UNKNOWN-01")
    return None if mapped is None else PUBLIC_FAULTS[mapped]


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


def _incident_ref_from_entropy(random_bytes: bytes) -> str:
    if not isinstance(random_bytes, bytes) or len(random_bytes) != 16:
        raise ValueError("incident entropy is invalid")
    return "inc1-" + random_bytes.hex()


def new_incident_ref() -> str:
    return _incident_ref_from_entropy(secrets.token_bytes(16))


def validate_incident_ref_v1(value: object) -> str:
    if not isinstance(value, str) or _INCIDENT_REF.fullmatch(value) is None:
        raise ValueError("incident_ref is invalid")
    return value


_PROJECTION_FIELDS = frozenset(
    {
        "schema",
        "codebook_version",
        "code",
        "domain",
        "category_zh",
        "channel",
        "incident_ref",
        "incident_ref_status",
        "retryable",
        "recovery_class",
        "recovery_gate",
    }
)


@dataclass(frozen=True, slots=True)
class PublicFaultProjection:
    schema: str
    codebook_version: int
    code: str
    domain: str
    category_zh: str
    channel: str
    incident_ref: str | None
    incident_ref_status: str
    retryable: bool
    recovery_class: str
    recovery_gate: str

    def __post_init__(self) -> None:
        if (
            self.schema != PUBLIC_FAULT_SCHEMA
            or type(self.codebook_version) is not int
            or self.codebook_version != CODEBOOK_VERSION
        ):
            raise ValueError("public fault schema is invalid")
        descriptor = PUBLIC_FAULTS.get(self.code)
        if descriptor is None or (
            self.domain,
            self.category_zh,
            self.retryable,
            self.recovery_class,
            self.recovery_gate,
        ) != (
            descriptor.domain,
            descriptor.category_zh,
            descriptor.retryable,
            descriptor.recovery_class,
            descriptor.recovery_gate,
        ):
            raise ValueError("public fault descriptor is invalid")
        if self.channel not in _CHANNELS:
            raise ValueError("public fault channel is invalid")
        if type(self.retryable) is not bool:
            raise TypeError("retryable must be boolean")
        if self.incident_ref_status not in _REF_STATES:
            raise ValueError("incident_ref status is invalid")
        if self.incident_ref_status == "available":
            validate_incident_ref_v1(self.incident_ref)
        elif self.incident_ref is not None:
            raise ValueError("unavailable incident_ref must be null")

    @classmethod
    def from_descriptor(
        cls,
        descriptor: PublicFaultDescriptor,
        *,
        channel: str,
        incident_ref: str | None,
    ) -> "PublicFaultProjection":
        if not isinstance(descriptor, PublicFaultDescriptor):
            raise TypeError("descriptor is invalid")
        status = "available" if incident_ref is not None else "unavailable"
        return cls(
            schema=PUBLIC_FAULT_SCHEMA,
            codebook_version=CODEBOOK_VERSION,
            code=descriptor.code,
            domain=descriptor.domain,
            category_zh=descriptor.category_zh,
            channel=channel,
            incident_ref=incident_ref,
            incident_ref_status=status,
            retryable=descriptor.retryable,
            recovery_class=descriptor.recovery_class,
            recovery_gate=descriptor.recovery_gate,
        )

    @classmethod
    def from_payload(cls, payload: object) -> "PublicFaultProjection":
        if not isinstance(payload, Mapping) or set(payload) != _PROJECTION_FIELDS:
            raise ValueError("public fault payload is invalid")
        values = dict(payload)
        if any(
            not isinstance(values[field], str)
            for field in (
                "schema",
                "code",
                "domain",
                "category_zh",
                "channel",
                "incident_ref_status",
                "recovery_class",
                "recovery_gate",
            )
        ):
            raise ValueError("public fault payload is invalid")
        return cls(**values)

    def as_payload(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "codebook_version": self.codebook_version,
            "code": self.code,
            "domain": self.domain,
            "category_zh": self.category_zh,
            "channel": self.channel,
            "incident_ref": self.incident_ref,
            "incident_ref_status": self.incident_ref_status,
            "retryable": self.retryable,
            "recovery_class": self.recovery_class,
            "recovery_gate": self.recovery_gate,
        }


def render_public_fault(projection: PublicFaultProjection) -> str:
    if not isinstance(projection, PublicFaultProjection):
        raise TypeError("projection is invalid")
    event = (
        str(projection.incident_ref)
        if projection.incident_ref_status == "available"
        else "事件号不可用"
    )
    label = "事件 " + event if projection.incident_ref_status == "available" else event
    rendered = f"{projection.category_zh}（{projection.code}，{label}）"
    if len(rendered.encode("utf-8")) > 256:
        raise ValueError("public fault rendering is oversized")
    return rendered


@dataclass(frozen=True, slots=True)
class IncidentIndexRecord:
    schema: str
    incident_ref: str
    code: str
    domain: str
    category_zh: str
    channel: str
    observed_at: str
    retryable: bool
    recovery_class: str
    recovery_gate: str

    def __post_init__(self) -> None:
        if self.schema != INCIDENT_INDEX_SCHEMA:
            raise ValueError("incident index schema is invalid")
        validate_incident_ref_v1(self.incident_ref)
        descriptor = PUBLIC_FAULTS.get(self.code)
        if descriptor is None or (
            self.domain,
            self.category_zh,
            self.retryable,
            self.recovery_class,
            self.recovery_gate,
        ) != (
            descriptor.domain,
            descriptor.category_zh,
            descriptor.retryable,
            descriptor.recovery_class,
            descriptor.recovery_gate,
        ):
            raise ValueError("incident index descriptor is invalid")
        if self.channel not in _CHANNELS:
            raise ValueError("incident index channel is invalid")
        if type(self.retryable) is not bool:
            raise TypeError("retryable must be boolean")
        _parse_utc(self.observed_at)

    @classmethod
    def from_projection(
        cls, projection: PublicFaultProjection, *, observed_at: datetime
    ) -> "IncidentIndexRecord":
        if projection.incident_ref_status != "available":
            raise ValueError("incident index requires an available incident_ref")
        return cls(
            schema=INCIDENT_INDEX_SCHEMA,
            incident_ref=validate_incident_ref_v1(projection.incident_ref),
            code=projection.code,
            domain=projection.domain,
            category_zh=projection.category_zh,
            channel=projection.channel,
            observed_at=_normalize_datetime(observed_at),
            retryable=projection.retryable,
            recovery_class=projection.recovery_class,
            recovery_gate=projection.recovery_gate,
        )

    @classmethod
    def from_payload(cls, payload: object) -> "IncidentIndexRecord":
        fields = {
            "schema",
            "incident_ref",
            "code",
            "domain",
            "category_zh",
            "channel",
            "observed_at",
            "retryable",
            "recovery_class",
            "recovery_gate",
        }
        if not isinstance(payload, Mapping) or set(payload) != fields:
            raise ValueError("incident index record is invalid")
        return cls(**dict(payload))

    def as_payload(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "incident_ref": self.incident_ref,
            "code": self.code,
            "domain": self.domain,
            "category_zh": self.category_zh,
            "channel": self.channel,
            "observed_at": self.observed_at,
            "retryable": self.retryable,
            "recovery_class": self.recovery_class,
            "recovery_gate": self.recovery_gate,
        }


def _normalize_datetime(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("observed_at is invalid")
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("observed_at is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("observed_at is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("observed_at is invalid")
    if _normalize_datetime(parsed) != value:
        raise ValueError("observed_at must be canonical UTC")
    return parsed


class ContentFreeIncidentIndex:
    def __init__(self, *, max_records: int = 256) -> None:
        if type(max_records) is not int or not 1 <= max_records <= 4096:
            raise ValueError("incident index capacity is invalid")
        self._max_records = max_records
        self._records: OrderedDict[str, IncidentIndexRecord] = OrderedDict()

    def add(self, record: IncidentIndexRecord) -> str:
        if not isinstance(record, IncidentIndexRecord):
            raise TypeError("incident index record is invalid")
        existing = self._records.get(record.incident_ref)
        if existing is not None:
            if existing != record:
                raise ValueError("incident_ref collision")
            return "idempotent"
        self._records[record.incident_ref] = record
        while len(self._records) > self._max_records:
            self._records.popitem(last=False)
        return "added"

    def allocate(
        self,
        descriptor: PublicFaultDescriptor,
        *,
        channel: str,
        observed_at: datetime,
    ) -> PublicFaultProjection:
        if not isinstance(descriptor, PublicFaultDescriptor):
            raise TypeError("descriptor is invalid")
        for _ in range(8):
            ref = new_incident_ref()
            if ref in self._records:
                continue
            projection = PublicFaultProjection.from_descriptor(
                descriptor, channel=channel, incident_ref=ref
            )
            self.add(
                IncidentIndexRecord.from_projection(
                    projection, observed_at=observed_at
                )
            )
            return projection
        raise RuntimeError("incident_ref allocation exhausted")

    def lookup(self, incident_ref: object) -> dict[str, object]:
        ref = validate_incident_ref_v1(incident_ref)
        try:
            record = self._records[ref]
        except KeyError:
            raise KeyError("incident_ref not found") from None
        return {
            "schema": INCIDENT_INDEX_SCHEMA,
            "incident_ref": record.incident_ref,
            "code": record.code,
            "domain": record.domain,
            "diagnostic_conclusion": record.category_zh,
            "channel": record.channel,
            "observed_at": record.observed_at,
            "retryable": record.retryable,
            "recovery_class": record.recovery_class,
            "recovery_gate": record.recovery_gate,
        }

    def as_payload(self) -> dict[str, object]:
        return {
            "schema": INCIDENT_INDEX_SET_SCHEMA,
            "max_records": self._max_records,
            "records": [record.as_payload() for record in self._records.values()],
        }

    @classmethod
    def from_payload(cls, payload: object) -> "ContentFreeIncidentIndex":
        if not isinstance(payload, Mapping) or set(payload) != {
            "schema",
            "max_records",
            "records",
        }:
            raise ValueError("incident index set is invalid")
        if payload.get("schema") != INCIDENT_INDEX_SET_SCHEMA:
            raise ValueError("incident index set is invalid")
        records = payload.get("records")
        if not isinstance(records, list):
            raise ValueError("incident index set is invalid")
        index = cls(max_records=payload.get("max_records"))
        if len(records) > index._max_records:
            raise ValueError("incident index set is oversized")
        for item in records:
            if index.add(IncidentIndexRecord.from_payload(item)) != "added":
                raise ValueError("incident index set contains a duplicate")
        return index
