from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from hashlib import sha256
import hmac
from threading import Lock
from typing import Protocol, runtime_checkable

from .errors import (
    ApprovalAlreadyConsumedError,
    ApprovalDeniedError,
    ApprovalExpiredError,
    ApprovalRequiredError,
)
from .models import (
    ApprovalStatus,
    OperationRequest,
    RiskLevel,
    redact_sensitive_text,
    require_aware,
    require_safe_id,
)


def _nonce_digest(nonce: str) -> str:
    if not isinstance(nonce, str) or not 32 <= len(nonce) <= 128:
        raise ValueError("approval nonce must contain 32-128 characters")
    return sha256(b"myuna-approval-nonce-v1\0" + nonce.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    approval_id: str
    operation_id: str
    request_digest: str
    request_id: str
    requested_by: str
    approver_principal_id: str
    operation: str
    target: str
    risk_level: RiskLevel
    reason: str
    impact_summary: str
    rollback_summary: str
    created_at: datetime
    expires_at: datetime
    nonce_sha256: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_at: datetime | None = None
    consumed_at: datetime | None = None

    def __post_init__(self) -> None:
        for value, label in (
            (self.approval_id, "approval_id"),
            (self.operation_id, "operation_id"),
            (self.request_id, "request_id"),
            (self.requested_by, "requested_by"),
            (self.approver_principal_id, "approver_principal_id"),
        ):
            require_safe_id(value, label)
        if len(self.request_digest) != 64 or any(
            character not in "0123456789abcdef" for character in self.request_digest
        ):
            raise ValueError("request_digest must be lowercase SHA-256 hex")
        if len(self.nonce_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.nonce_sha256
        ):
            raise ValueError("nonce_sha256 must be lowercase SHA-256 hex")
        if not isinstance(self.risk_level, RiskLevel):
            raise ValueError("risk_level must be a RiskLevel")
        created = require_aware(self.created_at, "created_at")
        expires = require_aware(self.expires_at, "expires_at")
        if expires <= created:
            raise ValueError("approval expiry must follow creation")
        object.__setattr__(self, "created_at", created)
        object.__setattr__(self, "expires_at", expires)
        for field_name in ("reason", "impact_summary", "rollback_summary"):
            value = getattr(self, field_name)
            sanitized = redact_sensitive_text(value)
            if not sanitized.strip() or len(sanitized) > 1024:
                raise ValueError(f"{field_name} must contain 1-1024 characters")
            object.__setattr__(self, field_name, sanitized)
        decided = None
        if self.decided_at is not None:
            decided = require_aware(self.decided_at, "decided_at")
            if decided < created:
                raise ValueError("approval decision must not precede creation")
            object.__setattr__(self, "decided_at", decided)
        consumed = None
        if self.consumed_at is not None:
            consumed = require_aware(self.consumed_at, "consumed_at")
            if consumed < (decided or created):
                raise ValueError("approval consumption must follow its decision")
            object.__setattr__(self, "consumed_at", consumed)
        if self.status is ApprovalStatus.PENDING and (decided is not None or consumed is not None):
            raise ValueError("pending approval must not contain decision timestamps")
        if self.status in {
            ApprovalStatus.APPROVED,
            ApprovalStatus.DENIED,
            ApprovalStatus.EXPIRED,
        } and (decided is None or consumed is not None):
            raise ValueError("decided approval requires one decision timestamp")
        if self.status is ApprovalStatus.CONSUMED and (decided is None or consumed is None):
            raise ValueError("consumed approval requires decision and consumption timestamps")


@runtime_checkable
class ApprovalLedger(Protocol):
    def create(
        self,
        request: OperationRequest,
        *,
        approval_id: str,
        operation_id: str,
        approver_principal_id: str,
        nonce: str,
        expires_at: datetime,
        effective_risk: RiskLevel,
        impact_summary: str,
        rollback_summary: str,
    ) -> ApprovalRecord: ...

    def approve(
        self,
        approval_id: str,
        *,
        approver_principal_id: str,
        nonce: str,
        decided_at: datetime,
    ) -> ApprovalRecord: ...

    def deny(
        self,
        approval_id: str,
        *,
        approver_principal_id: str,
        nonce: str,
        decided_at: datetime,
    ) -> ApprovalRecord: ...

    def consume(
        self,
        approval_id: str,
        *,
        operation_id: str,
        request_digest: str,
        now: datetime,
    ) -> ApprovalRecord: ...


class InMemoryApprovalLedger:
    """Thread-safe fake ledger. Production must replace it with transactional storage."""

    def __init__(self) -> None:
        self._records: dict[str, ApprovalRecord] = {}
        self._lock = Lock()

    def create(
        self,
        request: OperationRequest,
        *,
        approval_id: str,
        operation_id: str,
        approver_principal_id: str,
        nonce: str,
        expires_at: datetime,
        effective_risk: RiskLevel,
        impact_summary: str,
        rollback_summary: str,
    ) -> ApprovalRecord:
        created_at = request.created_at.astimezone(timezone.utc)
        record = ApprovalRecord(
            approval_id=approval_id,
            operation_id=operation_id,
            request_digest=request.request_digest,
            request_id=request.request_id,
            requested_by=request.actor,
            approver_principal_id=approver_principal_id,
            operation=request.operation,
            target=request.target,
            risk_level=effective_risk,
            reason=request.reason,
            impact_summary=impact_summary,
            rollback_summary=rollback_summary,
            created_at=created_at,
            expires_at=expires_at,
            nonce_sha256=_nonce_digest(nonce),
        )
        with self._lock:
            if approval_id in self._records:
                raise ValueError("approval_id already exists")
            self._records[approval_id] = record
        return record

    def get(self, approval_id: str) -> ApprovalRecord | None:
        with self._lock:
            return self._records.get(approval_id)

    def _decide(
        self,
        approval_id: str,
        *,
        approver_principal_id: str,
        nonce: str,
        decided_at: datetime,
        status: ApprovalStatus,
    ) -> ApprovalRecord:
        decided_at = require_aware(decided_at, "decided_at")
        with self._lock:
            record = self._records.get(approval_id)
            if record is None:
                raise ApprovalRequiredError("approval record was not found")
            if record.status is not ApprovalStatus.PENDING:
                raise ApprovalAlreadyConsumedError("approval is no longer pending")
            if decided_at < record.created_at:
                raise ApprovalDeniedError("approval decision precedes the request")
            if decided_at >= record.expires_at:
                expired = replace(record, status=ApprovalStatus.EXPIRED, decided_at=decided_at)
                self._records[approval_id] = expired
                raise ApprovalExpiredError("approval has expired")
            if record.approver_principal_id != approver_principal_id:
                raise ApprovalDeniedError("approval principal does not match")
            if not hmac.compare_digest(record.nonce_sha256, _nonce_digest(nonce)):
                raise ApprovalDeniedError("approval challenge does not match")
            decided = replace(record, status=status, decided_at=decided_at)
            self._records[approval_id] = decided
            return decided

    def approve(
        self,
        approval_id: str,
        *,
        approver_principal_id: str,
        nonce: str,
        decided_at: datetime,
    ) -> ApprovalRecord:
        return self._decide(
            approval_id,
            approver_principal_id=approver_principal_id,
            nonce=nonce,
            decided_at=decided_at,
            status=ApprovalStatus.APPROVED,
        )

    def deny(
        self,
        approval_id: str,
        *,
        approver_principal_id: str,
        nonce: str,
        decided_at: datetime,
    ) -> ApprovalRecord:
        return self._decide(
            approval_id,
            approver_principal_id=approver_principal_id,
            nonce=nonce,
            decided_at=decided_at,
            status=ApprovalStatus.DENIED,
        )

    def consume(
        self,
        approval_id: str,
        *,
        operation_id: str,
        request_digest: str,
        now: datetime,
    ) -> ApprovalRecord:
        now = require_aware(now, "now")
        with self._lock:
            record = self._records.get(approval_id)
            if record is None:
                raise ApprovalRequiredError("approval record was not found")
            if now < record.created_at or (
                record.decided_at is not None and now < record.decided_at
            ):
                raise ApprovalDeniedError("approval consumption precedes the decision")
            if now >= record.expires_at:
                expired = replace(
                    record,
                    status=ApprovalStatus.EXPIRED,
                    decided_at=record.decided_at or now,
                )
                self._records[approval_id] = expired
                raise ApprovalExpiredError("approval has expired")
            if record.status is ApprovalStatus.DENIED:
                raise ApprovalDeniedError("approval was denied")
            if record.status is ApprovalStatus.CONSUMED:
                raise ApprovalAlreadyConsumedError("approval was already consumed")
            if record.status is not ApprovalStatus.APPROVED:
                raise ApprovalRequiredError("approval has not been granted")
            if record.operation_id != operation_id or not hmac.compare_digest(
                record.request_digest, request_digest
            ):
                raise ApprovalDeniedError("approval does not match the exact operation request")
            consumed = replace(record, status=ApprovalStatus.CONSUMED, consumed_at=now)
            self._records[approval_id] = consumed
            return consumed

    def all_records(self) -> tuple[ApprovalRecord, ...]:
        with self._lock:
            return tuple(self._records[key] for key in sorted(self._records))
