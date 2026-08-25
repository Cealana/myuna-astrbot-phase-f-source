from __future__ import annotations

from hashlib import sha256

from myuna_core.audit import AuditLogger
from myuna_core.operations.models import OperationRequest, OperationResult, require_safe_id
from myuna_core.operations.policy import OperationExecutionContext, OperationPolicyDecision


class CapabilityRuntimeAuditProjector:
    """Project bounded neutral capability events into the existing audit sink."""

    def __init__(self, audit: AuditLogger) -> None:
        self.audit = audit

    @staticmethod
    def reference_for(runtime_id: str, request: OperationRequest) -> str:
        require_safe_id(runtime_id, "runtime_id")
        digest = sha256(
            b"myuna-capability-runtime-audit-v1\0"
            + runtime_id.encode("utf-8")
            + b"\0"
            + request.request_digest.encode("ascii")
        ).hexdigest()
        return f"audit-{digest[:24]}"

    def emit_request(
        self,
        runtime_id: str,
        request: OperationRequest,
        decision: OperationPolicyDecision,
        context: OperationExecutionContext,
    ) -> str:
        reference = self.reference_for(runtime_id, request)
        self.audit.emit(
            "capability_runtime.operation.requested",
            request_id=request.request_id,
            details={
                "approval_required": decision.approval_required,
                "audit_reference": reference,
                "correlation_id": request.correlation_id,
                "effective_risk": decision.effective_risk.value,
                "operation": request.operation,
                "origin": request.origin.value,
                "policy_reasons": decision.reason_codes,
                "recovery_mode": context.recovery_mode,
                "request_digest": request.request_digest,
                "runtime_id": runtime_id,
                "supplied_argument_names": tuple(sorted(request.arguments)),
                "target": request.target,
            },
        )
        return reference

    def emit_result(
        self,
        runtime_id: str,
        request: OperationRequest,
        result: OperationResult,
    ) -> None:
        require_safe_id(runtime_id, "runtime_id")
        audit_reference = result.audit_reference or self.reference_for(runtime_id, request)
        self.audit.emit(
            "capability_runtime.operation.finished",
            request_id=request.request_id,
            outcome=result.status.value,
            details={
                "approval_status": result.approval_status.value,
                "audit_reference": audit_reference,
                "correlation_id": request.correlation_id,
                "error_code": None if result.error is None else result.error.code,
                "operation": request.operation,
                "operation_id": result.operation_id,
                "origin": request.origin.value,
                "runtime_id": runtime_id,
                "success": result.success,
                "target": request.target,
                "truncated": result.truncated,
            },
        )
