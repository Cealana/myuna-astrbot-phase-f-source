from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from hashlib import sha256
from math import isfinite
from types import MappingProxyType
from typing import Any, Mapping
import json
import re


SCHEMA_VERSION = "myuna.operation.v1"
MAX_ARGUMENT_DEPTH = 8
MAX_ARGUMENT_ITEMS = 128
MAX_ARGUMENT_STRING = 4096
MAX_REASON_CHARACTERS = 1024
MAX_RESULT_EXCERPT_CHARACTERS = 4096

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_OPERATION_NAME = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,5}$")
_TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_ARGUMENT_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SENSITIVE_KEY_FRAGMENTS = (
    "api_key",
    "authorization",
    "cookie",
    "credential",
    "nonce",
    "password",
    "private_key",
    "secret",
    "signature",
    "token",
)
_SENSITIVE_TEXT_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(
        r"(?i)\b(api[_-]?key|authorization|password|secret|token)"
        r"(\s*[:=]\s*)([^\s,;]+)"
    ),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?i)([?&](?:api_key|key|secret|token)=)[^&#\s]+"),
)


class OperationOrigin(StrEnum):
    MYUNA = "myuna"
    CEALANA_REMOTE = "cealana_remote"
    RECOVERY = "recovery"


class RiskLevel(StrEnum):
    LEVEL_0 = "level_0"
    LEVEL_1 = "level_1"
    LEVEL_2 = "level_2"
    LEVEL_3 = "level_3"
    FORBIDDEN = "forbidden"

    @property
    def rank(self) -> int:
        return {
            RiskLevel.LEVEL_0: 0,
            RiskLevel.LEVEL_1: 1,
            RiskLevel.LEVEL_2: 2,
            RiskLevel.LEVEL_3: 3,
            RiskLevel.FORBIDDEN: 100,
        }[self]


class OperationStatus(StrEnum):
    PENDING = "pending"
    AWAITING_APPROVAL = "awaiting_approval"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PARTIAL = "partial"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class ApprovalStatus(StrEnum):
    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CONSUMED = "consumed"


class TaskStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


def require_safe_id(value: str, label: str) -> None:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise ValueError(f"{label} must be a safe opaque identifier")


def require_aware(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _is_sensitive_key(key: str) -> bool:
    normalized = key.casefold()
    return any(fragment in normalized for fragment in _SENSITIVE_KEY_FRAGMENTS)


def redact_sensitive_text(value: str) -> str:
    result = value
    result = _SENSITIVE_TEXT_PATTERNS[0].sub("Bearer [REDACTED]", result)
    result = _SENSITIVE_TEXT_PATTERNS[1].sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]",
        result,
    )
    result = _SENSITIVE_TEXT_PATTERNS[2].sub("[REDACTED]", result)
    result = _SENSITIVE_TEXT_PATTERNS[3].sub(
        lambda match: f"{match.group(1)}[REDACTED]",
        result,
    )
    return result


def _freeze_json(
    value: Any,
    *,
    depth: int = 0,
    path: str = "arguments",
    reject_sensitive_keys: bool = True,
) -> Any:
    if depth > MAX_ARGUMENT_DEPTH:
        raise ValueError(f"{path} exceeds the maximum nesting depth")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise ValueError(f"{path} contains a non-finite number")
        return value
    if isinstance(value, str):
        if len(value) > MAX_ARGUMENT_STRING:
            raise ValueError(f"{path} contains an oversized string")
        sanitized = redact_sensitive_text(value)
        if reject_sensitive_keys and sanitized != value:
            raise ValueError(f"{path} may not contain secret-shaped values")
        return value if reject_sensitive_keys else sanitized
    if isinstance(value, Mapping):
        if len(value) > MAX_ARGUMENT_ITEMS:
            raise ValueError(f"{path} contains too many fields")
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or _ARGUMENT_KEY.fullmatch(key) is None:
                raise ValueError(f"{path} contains an invalid field name")
            if _is_sensitive_key(key):
                if reject_sensitive_keys:
                    raise ValueError(f"{path} may not contain secret-bearing fields")
                frozen[key] = "[REDACTED]"
                continue
            frozen[key] = _freeze_json(
                item,
                depth=depth + 1,
                path=f"{path}.{key}",
                reject_sensitive_keys=reject_sensitive_keys,
            )
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_ARGUMENT_ITEMS:
            raise ValueError(f"{path} contains too many items")
        return tuple(
            _freeze_json(
                item,
                depth=depth + 1,
                path=f"{path}[]",
                reject_sensitive_keys=reject_sensitive_keys,
            )
            for item in value
        )
    raise ValueError(f"{path} must contain JSON-compatible values")


def thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw_json(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class OperationRequest:
    request_id: str
    correlation_id: str
    idempotency_key: str
    origin: OperationOrigin
    actor: str
    operation: str
    target: str
    arguments: Mapping[str, Any]
    risk_level: RiskLevel
    timeout_seconds: int
    requires_approval: bool
    reason: str
    created_at: datetime
    parent_request_id: str | None = None
    hop_count: int = 0
    route_trace: tuple[str, ...] = ()
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported operation request schema")
        for value, label in (
            (self.request_id, "request_id"),
            (self.correlation_id, "correlation_id"),
            (self.idempotency_key, "idempotency_key"),
            (self.actor, "actor"),
        ):
            require_safe_id(value, label)
        if self.parent_request_id is not None:
            require_safe_id(self.parent_request_id, "parent_request_id")
        if not isinstance(self.origin, OperationOrigin):
            raise ValueError("origin must be an OperationOrigin")
        if not isinstance(self.risk_level, RiskLevel):
            raise ValueError("risk_level must be a RiskLevel")
        if _OPERATION_NAME.fullmatch(self.operation) is None:
            raise ValueError("operation must be a namespaced operation identifier")
        if _TARGET.fullmatch(self.target) is None:
            raise ValueError("target must be a bounded target identifier")
        if not 1 <= self.timeout_seconds <= 3600:
            raise ValueError("timeout_seconds must be between 1 and 3600")
        if not isinstance(self.requires_approval, bool):
            raise ValueError("requires_approval must be boolean")
        if not self.reason.strip() or len(self.reason) > MAX_REASON_CHARACTERS:
            raise ValueError("reason must contain 1-1024 characters")
        if redact_sensitive_text(self.reason) != self.reason:
            raise ValueError("reason may not contain secret-shaped values")
        if not 0 <= self.hop_count <= 16:
            raise ValueError("hop_count must be between 0 and 16")
        if len(self.route_trace) != self.hop_count:
            raise ValueError("route_trace length must match hop_count")
        if len(set(self.route_trace)) != len(self.route_trace):
            raise ValueError("route_trace must not already contain a loop")
        for component in self.route_trace:
            require_safe_id(component, "route_trace component")
        object.__setattr__(self, "created_at", require_aware(self.created_at, "created_at"))
        object.__setattr__(self, "arguments", _freeze_json(self.arguments))

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "actor": self.actor,
            "arguments": thaw_json(self.arguments),
            "correlation_id": self.correlation_id,
            "created_at": self.created_at.isoformat(timespec="microseconds"),
            "hop_count": self.hop_count,
            "idempotency_key": self.idempotency_key,
            "operation": self.operation,
            "origin": self.origin.value,
            "parent_request_id": self.parent_request_id,
            "reason": self.reason,
            "request_id": self.request_id,
            "requires_approval": self.requires_approval,
            "risk_level": self.risk_level.value,
            "route_trace": list(self.route_trace),
            "schema_version": self.schema_version,
            "target": self.target,
            "timeout_seconds": self.timeout_seconds,
        }

    @property
    def request_digest(self) -> str:
        canonical = json.dumps(
            self.canonical_payload(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return sha256(b"myuna-operation-request-v1\0" + canonical).hexdigest()


@dataclass(frozen=True, slots=True)
class OperationErrorDetail:
    code: str
    message: str
    retryable: bool = False

    def __post_init__(self) -> None:
        require_safe_id(self.code, "error code")
        sanitized = redact_sensitive_text(self.message)
        if not sanitized.strip() or len(sanitized) > 512:
            raise ValueError("error message must contain 1-512 characters")
        object.__setattr__(self, "message", sanitized)


@dataclass(frozen=True, slots=True)
class OperationResult:
    request_id: str
    operation_id: str
    status: OperationStatus
    success: bool
    started_at: datetime
    finished_at: datetime | None
    exit_code: int | None
    summary: str
    structured_data: Mapping[str, Any] = field(default_factory=dict)
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    truncated: bool = False
    approval_status: ApprovalStatus = ApprovalStatus.NOT_REQUIRED
    audit_reference: str | None = None
    error: OperationErrorDetail | None = None

    def __post_init__(self) -> None:
        require_safe_id(self.request_id, "request_id")
        require_safe_id(self.operation_id, "operation_id")
        if not isinstance(self.status, OperationStatus):
            raise ValueError("status must be an OperationStatus")
        if not isinstance(self.approval_status, ApprovalStatus):
            raise ValueError("approval_status must be an ApprovalStatus")
        started = require_aware(self.started_at, "started_at")
        object.__setattr__(self, "started_at", started)
        if self.finished_at is not None:
            finished = require_aware(self.finished_at, "finished_at")
            if finished < started:
                raise ValueError("finished_at must not precede started_at")
            object.__setattr__(self, "finished_at", finished)
        terminal = {
            OperationStatus.SUCCEEDED,
            OperationStatus.FAILED,
            OperationStatus.PARTIAL,
            OperationStatus.CANCELLED,
            OperationStatus.TIMED_OUT,
        }
        if (self.status in terminal) != (self.finished_at is not None):
            raise ValueError("terminal status and finished_at must agree")
        if self.success != (self.status is OperationStatus.SUCCEEDED):
            raise ValueError("success is true only for succeeded operations")
        if self.success and self.error is not None:
            raise ValueError("successful operations may not contain an error")
        error_required = {
            OperationStatus.FAILED,
            OperationStatus.PARTIAL,
            OperationStatus.TIMED_OUT,
        }
        if self.status in error_required:
            if self.error is None:
                raise ValueError("failed, partial, and timed-out results require an error")
        sanitized_summary = redact_sensitive_text(self.summary)
        if not sanitized_summary.strip() or len(sanitized_summary) > 1024:
            raise ValueError("summary must contain 1-1024 characters")
        object.__setattr__(self, "summary", sanitized_summary)
        object.__setattr__(self, "stdout_excerpt", redact_sensitive_text(self.stdout_excerpt))
        object.__setattr__(self, "stderr_excerpt", redact_sensitive_text(self.stderr_excerpt))
        for excerpt in (self.stdout_excerpt, self.stderr_excerpt):
            if len(excerpt) > MAX_RESULT_EXCERPT_CHARACTERS:
                raise ValueError("result excerpt exceeds the contract limit")
        if self.audit_reference is not None:
            require_safe_id(self.audit_reference, "audit_reference")
        object.__setattr__(
            self,
            "structured_data",
            _freeze_json(
                self.structured_data,
                path="structured_data",
                reject_sensitive_keys=False,
            ),
        )

    def public_payload(self) -> dict[str, Any]:
        return {
            "approval_status": self.approval_status.value,
            "audit_reference": self.audit_reference,
            "error": None
            if self.error is None
            else {
                "code": self.error.code,
                "message": self.error.message,
                "retryable": self.error.retryable,
            },
            "exit_code": self.exit_code,
            "finished_at": None
            if self.finished_at is None
            else self.finished_at.isoformat(timespec="microseconds"),
            "operation_id": self.operation_id,
            "request_id": self.request_id,
            "started_at": self.started_at.isoformat(timespec="microseconds"),
            "status": self.status.value,
            "stderr_excerpt": self.stderr_excerpt,
            "stdout_excerpt": self.stdout_excerpt,
            "structured_data": thaw_json(self.structured_data),
            "success": self.success,
            "summary": self.summary,
            "truncated": self.truncated,
        }


@dataclass(frozen=True, slots=True)
class NotificationRequest:
    notification_id: str
    correlation_id: str
    recipient_principal_id: str
    template_id: str
    variables: Mapping[str, Any]
    created_at: datetime

    def __post_init__(self) -> None:
        for value, label in (
            (self.notification_id, "notification_id"),
            (self.correlation_id, "correlation_id"),
            (self.recipient_principal_id, "recipient_principal_id"),
            (self.template_id, "template_id"),
        ):
            require_safe_id(value, label)
        object.__setattr__(self, "created_at", require_aware(self.created_at, "created_at"))
        object.__setattr__(self, "variables", _freeze_json(self.variables, path="variables"))


@dataclass(frozen=True, slots=True)
class NotificationReceipt:
    notification_id: str
    status: str
    audit_reference: str

    def __post_init__(self) -> None:
        require_safe_id(self.notification_id, "notification_id")
        require_safe_id(self.status, "notification status")
        require_safe_id(self.audit_reference, "audit_reference")
