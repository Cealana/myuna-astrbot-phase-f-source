from __future__ import annotations

from hashlib import sha256

from myuna_core.audit import AuditLogger

from .models import OperationRequest, OperationResult
from .policy import OperationExecutionContext, OperationPolicyDecision


class OperationAuditLogger:
    """Emit metadata-only operation events through the existing redacted audit sink."""

    def __init__(self, audit: AuditLogger) -> None:
        self.audit = audit

    @staticmethod
    def reference_for(request: OperationRequest) -> str:
        digest = sha256(
            b"myuna-operation-audit-v1\0" + request.request_digest.encode("ascii")
        ).hexdigest()
        return f"audit-{digest[:24]}"

    def emit_request(
        self,
        request: OperationRequest,
        decision: OperationPolicyDecision,
        context: OperationExecutionContext,
    ) -> str:
        reference = self.reference_for(request)
        self.audit.emit(
            "openclaw.operation.requested",
            request_id=request.request_id,
            details={
                "actor": request.actor,
                "approval_required": decision.approval_required,
                "audit_reference": reference,
                "correlation_id": request.correlation_id,
                "effective_risk": decision.effective_risk.value,
                "idempotency_fingerprint": sha256(
                    request.idempotency_key.encode("utf-8")
                ).hexdigest(),
                "operation": request.operation,
                "origin": request.origin.value,
                "policy_reasons": decision.reason_codes,
                "recovery_mode": context.recovery_mode,
                "request_digest": request.request_digest,
                "supplied_argument_names": tuple(sorted(request.arguments)),
                "target": request.target,
            },
        )
        return reference

    def emit_result(self, request: OperationRequest, result: OperationResult) -> None:
        self.audit.emit(
            "openclaw.operation.finished",
            request_id=request.request_id,
            outcome=result.status.value,
            details={
                "approval_status": result.approval_status.value,
                "audit_reference": result.audit_reference,
                "correlation_id": request.correlation_id,
                "error_code": None if result.error is None else result.error.code,
                "exit_code": result.exit_code,
                "operation": request.operation,
                "operation_id": result.operation_id,
                "origin": request.origin.value,
                "stderr_characters": len(result.stderr_excerpt),
                "stdout_characters": len(result.stdout_excerpt),
                "success": result.success,
                "target": request.target,
                "truncated": result.truncated,
            },
        )

