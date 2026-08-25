from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from threading import RLock
from typing import Any, Callable, Mapping
import json

from myuna_core.operations.approval import (
    ApprovalRecord,
    InMemoryApprovalLedger,
)
from myuna_core.operations.audit import OperationAuditLogger
from myuna_core.operations.catalog import (
    DEFAULT_OPERATION_CATALOG,
    OperationCatalog,
    OperationDefinition,
)
from myuna_core.operations.errors import (
    ApprovalRequiredError,
    InvalidOperationArgumentsError,
    OperationCancelledError,
    OperationNotFoundError,
)
from myuna_core.operations.guard import OperationLoopGuard
from myuna_core.operations.idempotency import InMemoryIdempotencyLedger
from myuna_core.operations.models import (
    ApprovalStatus,
    NotificationReceipt,
    NotificationRequest,
    OperationErrorDetail,
    OperationRequest,
    OperationResult,
    OperationStatus,
    redact_sensitive_text,
    require_aware,
    require_safe_id,
)
from myuna_core.operations.policy import (
    OperationExecutionContext,
    OperationPolicy,
    OperationPolicyDecision,
)


@dataclass(frozen=True, slots=True)
class FakeOperationOutcome:
    """A deterministic fixture; it never executes a command or opens a connection."""

    status: OperationStatus = OperationStatus.SUCCEEDED
    summary: str = "fake operation completed"
    structured_data: Mapping[str, Any] = field(default_factory=dict)
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    exit_code: int | None = 0
    duration_seconds: float = 0.0
    error: OperationErrorDetail | None = None

    def __post_init__(self) -> None:
        if self.duration_seconds < 0 or self.duration_seconds > 86400:
            raise ValueError("fake duration is outside the supported range")
        if self.status in {
            OperationStatus.FAILED,
            OperationStatus.PARTIAL,
            OperationStatus.TIMED_OUT,
        } and self.error is None:
            raise ValueError("fake failed outcomes require an error")
        if self.status is OperationStatus.SUCCEEDED and self.error is not None:
            raise ValueError("fake successful outcomes may not contain an error")


class FakeOpenClawAdapter:
    """Repository-only test double with policy, approval, audit and replay semantics."""

    adapter_id = "fake-openclaw-stage7.1"

    def __init__(
        self,
        *,
        catalog: OperationCatalog = DEFAULT_OPERATION_CATALOG,
        approvals: InMemoryApprovalLedger | None = None,
        idempotency: InMemoryIdempotencyLedger | None = None,
        audit: OperationAuditLogger | None = None,
        outcomes: Mapping[str, FakeOperationOutcome] | None = None,
        now: Callable[[], datetime] | None = None,
        max_hops: int = 4,
    ) -> None:
        self.catalog = catalog
        self.policy = OperationPolicy(catalog)
        self.approvals = approvals or InMemoryApprovalLedger()
        self.idempotency = idempotency or InMemoryIdempotencyLedger()
        self.audit = audit
        self.outcomes = dict(outcomes or {})
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.loop_guard = OperationLoopGuard(max_hops=max_hops)
        self._results: dict[str, OperationResult] = {}
        self._requests: dict[str, OperationRequest] = {}
        self._notifications: dict[str, NotificationReceipt] = {}
        self._execution_counts: dict[str, int] = {}
        self._lock = RLock()

    @staticmethod
    def operation_id_for(request: OperationRequest) -> str:
        digest = sha256(
            b"myuna-fake-operation-v1\0" + request.request_digest.encode("ascii")
        ).hexdigest()
        return f"operation-{digest[:24]}"

    def _clock(self) -> datetime:
        return require_aware(self.now(), "adapter clock")

    @staticmethod
    def _expect(request: OperationRequest, allowed: frozenset[str]) -> None:
        if request.operation not in allowed:
            raise InvalidOperationArgumentsError("adapter method received the wrong operation")

    @staticmethod
    def _bounded_outputs(
        stdout: str,
        stderr: str,
        maximum: int,
    ) -> tuple[str, str, bool]:
        stdout = redact_sensitive_text(stdout)
        stderr = redact_sensitive_text(stderr)
        remaining = maximum
        bounded_stdout = stdout[:remaining]
        remaining -= len(bounded_stdout)
        bounded_stderr = stderr[:remaining]
        truncated = len(bounded_stdout) < len(stdout) or len(bounded_stderr) < len(stderr)
        return bounded_stdout, bounded_stderr, truncated

    def _result_from_outcome(
        self,
        request: OperationRequest,
        operation_id: str,
        definition: OperationDefinition,
        decision: OperationPolicyDecision,
        outcome: FakeOperationOutcome,
        *,
        started_at: datetime,
        approval_status: ApprovalStatus,
        audit_reference: str | None,
    ) -> OperationResult:
        status = outcome.status
        error = outcome.error
        duration = outcome.duration_seconds
        if duration > request.timeout_seconds:
            status = OperationStatus.TIMED_OUT
            error = OperationErrorDetail(
                code="operation_timeout",
                message="fake operation exceeded the requested timeout",
                retryable=True,
            )
            duration = float(request.timeout_seconds)

        stdout, stderr, output_truncated = self._bounded_outputs(
            outcome.stdout_excerpt,
            outcome.stderr_excerpt,
            definition.max_output_characters,
        )
        summary = redact_sensitive_text(outcome.summary)
        summary_truncated = len(summary) > 1024
        summary = summary[:1024]
        terminal = status not in {
            OperationStatus.PENDING,
            OperationStatus.AWAITING_APPROVAL,
            OperationStatus.RUNNING,
        }
        finished_at = started_at + timedelta(seconds=duration) if terminal else None
        exit_code = outcome.exit_code
        if status is OperationStatus.TIMED_OUT:
            exit_code = None
        structured_data = {
            **dict(outcome.structured_data),
            "effective_risk": decision.effective_risk.value,
            "fake_adapter": True,
            "handler_id": definition.handler_id,
        }
        if (
            len(json.dumps(structured_data, ensure_ascii=False, default=str))
            > definition.max_output_characters
        ):
            structured_data = {
                "fake_adapter": True,
                "handler_id": definition.handler_id,
                "structured_data_truncated": True,
            }
            output_truncated = True
        return OperationResult(
            request_id=request.request_id,
            operation_id=operation_id,
            status=status,
            success=status is OperationStatus.SUCCEEDED,
            started_at=started_at,
            finished_at=finished_at,
            exit_code=exit_code,
            summary=summary,
            structured_data=structured_data,
            stdout_excerpt=stdout,
            stderr_excerpt=stderr,
            truncated=output_truncated or summary_truncated,
            approval_status=approval_status,
            audit_reference=audit_reference,
            error=error,
        )

    def _cancel_target(
        self,
        request: OperationRequest,
        *,
        now: datetime,
    ) -> Mapping[str, Any]:
        target_operation_id = str(request.arguments["operation_id"])
        target = self._results.get(target_operation_id)
        target_request = self._requests.get(target_operation_id)
        if target is None or target_request is None:
            raise OperationNotFoundError("operation to cancel was not found")
        if target.status is not OperationStatus.RUNNING:
            raise OperationCancelledError("only a running operation can be cancelled")
        target_definition = self.catalog.resolve(target_request.operation)
        if not target_definition.supports_cancellation:
            raise OperationCancelledError("operation does not support cancellation")
        cancelled = OperationResult(
            request_id=target.request_id,
            operation_id=target.operation_id,
            status=OperationStatus.CANCELLED,
            success=False,
            started_at=target.started_at,
            finished_at=now,
            exit_code=None,
            summary="fake operation cancelled",
            structured_data={"cancelled": True},
            truncated=False,
            approval_status=target.approval_status,
            audit_reference=target.audit_reference,
        )
        self._results[target_operation_id] = cancelled
        self.idempotency.replace_completed(
            target_request.idempotency_key,
            target_request.request_digest,
            cancelled,
        )
        return {"cancelled_operation_id": target_operation_id}

    def run_operation(
        self,
        request: OperationRequest,
        *,
        context: OperationExecutionContext = OperationExecutionContext(),
    ) -> OperationResult:
        self.loop_guard.advance(request, "openclaw")
        definition, decision = self.policy.evaluate(request, context)
        operation_id = self.operation_id_for(request)

        with self._lock:
            existing = self.idempotency.lookup(
                request.idempotency_key,
                request.request_digest,
            )
            if existing is not None:
                return existing

            approval_status = ApprovalStatus.NOT_REQUIRED
            if decision.approval_required:
                if context.approval_id is None:
                    raise ApprovalRequiredError("operation requires an exact bound approval")
                self.approvals.consume(
                    context.approval_id,
                    operation_id=operation_id,
                    request_digest=request.request_digest,
                    now=self._clock(),
                )
                approval_status = ApprovalStatus.CONSUMED

            self.idempotency.claim(
                request.idempotency_key,
                request.request_digest,
                operation_id,
            )
            started_at = self._clock()
            audit_reference = None
            if self.audit is not None:
                audit_reference = self.audit.emit_request(request, decision, context)

            self._execution_counts[request.operation] = (
                self._execution_counts.get(request.operation, 0) + 1
            )
            outcome = self.outcomes.get(request.operation, FakeOperationOutcome())
            try:
                if request.operation == "operation.cancel":
                    cancelled_data = self._cancel_target(request, now=started_at)
                    outcome = FakeOperationOutcome(
                        summary="fake cancellation completed",
                        structured_data=cancelled_data,
                    )
                result = self._result_from_outcome(
                    request,
                    operation_id,
                    definition,
                    decision,
                    outcome,
                    started_at=started_at,
                    approval_status=approval_status,
                    audit_reference=audit_reference,
                )
            except Exception:
                self.idempotency.abandon(
                    request.idempotency_key,
                    request.request_digest,
                )
                raise
            self.idempotency.complete(
                request.idempotency_key,
                request.request_digest,
                result,
            )
            self._results[operation_id] = result
            self._requests[operation_id] = request
            if self.audit is not None:
                self.audit.emit_result(request, result)
            return result

    def health_check(
        self,
        request: OperationRequest,
        *,
        context: OperationExecutionContext = OperationExecutionContext(),
    ) -> OperationResult:
        self._expect(request, frozenset({"myuna.health"}))
        return self.run_operation(request, context=context)

    def get_host_status(
        self,
        request: OperationRequest,
        *,
        context: OperationExecutionContext = OperationExecutionContext(),
    ) -> OperationResult:
        self._expect(request, frozenset({"host.metrics", "disk.usage", "port.inspect"}))
        return self.run_operation(request, context=context)

    def get_service_status(
        self,
        request: OperationRequest,
        *,
        context: OperationExecutionContext = OperationExecutionContext(),
    ) -> OperationResult:
        self._expect(
            request,
            frozenset({"myuna.status", "service.status", "worker.list", "worker.status"}),
        )
        return self.run_operation(request, context=context)

    def read_service_logs(
        self,
        request: OperationRequest,
        *,
        context: OperationExecutionContext = OperationExecutionContext(),
    ) -> OperationResult:
        self._expect(request, frozenset({"myuna.recent_logs"}))
        return self.run_operation(request, context=context)

    def run_playbook(
        self,
        request: OperationRequest,
        *,
        context: OperationExecutionContext,
    ) -> OperationResult:
        if not request.operation.startswith("recovery."):
            raise InvalidOperationArgumentsError("run_playbook accepts recovery operations only")
        return self.run_operation(request, context=context)

    def get_operation_status(self, operation_id: str) -> OperationResult:
        require_safe_id(operation_id, "operation_id")
        with self._lock:
            result = self._results.get(operation_id)
            if result is None:
                raise OperationNotFoundError("operation was not found")
            return result

    def cancel_operation(
        self,
        request: OperationRequest,
        *,
        context: OperationExecutionContext,
    ) -> OperationResult:
        self._expect(request, frozenset({"operation.cancel"}))
        return self.run_operation(request, context=context)

    def send_notification(self, request: NotificationRequest) -> NotificationReceipt:
        with self._lock:
            if request.notification_id in self._notifications:
                return self._notifications[request.notification_id]
            digest = sha256(
                b"myuna-fake-notification-v1\0"
                + request.notification_id.encode("utf-8")
            ).hexdigest()
            receipt = NotificationReceipt(
                notification_id=request.notification_id,
                status="fake_recorded",
                audit_reference=f"audit-{digest[:24]}",
            )
            self._notifications[request.notification_id] = receipt
            return receipt

    def request_approval(
        self,
        request: OperationRequest,
        *,
        context: OperationExecutionContext = OperationExecutionContext(),
        approval_id: str,
        approver_principal_id: str,
        nonce: str,
        expires_at: datetime,
        impact_summary: str,
        rollback_summary: str,
    ) -> ApprovalRecord:
        _, decision = self.policy.evaluate(request, context)
        if not decision.approval_required:
            raise InvalidOperationArgumentsError("operation policy does not require approval")
        now = self._clock()
        if require_aware(expires_at, "expires_at") <= now:
            raise ValueError("approval expiry must be in the future")
        return self.approvals.create(
            request,
            approval_id=approval_id,
            operation_id=self.operation_id_for(request),
            approver_principal_id=approver_principal_id,
            nonce=nonce,
            expires_at=expires_at,
            effective_risk=decision.effective_risk,
            impact_summary=impact_summary,
            rollback_summary=rollback_summary,
        )

    def execution_count(self, operation: str) -> int:
        with self._lock:
            return self._execution_counts.get(operation, 0)
