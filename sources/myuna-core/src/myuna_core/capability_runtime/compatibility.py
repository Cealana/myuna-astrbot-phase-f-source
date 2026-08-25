from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from myuna_core.integrations.openclaw.base import OpenClawAdapter
from myuna_core.operations.approval import ApprovalRecord
from myuna_core.operations.models import (
    NotificationReceipt,
    NotificationRequest,
    OperationRequest,
    OperationResult,
    require_safe_id,
)
from myuna_core.operations.policy import OperationExecutionContext


@dataclass(frozen=True, slots=True)
class LegacyOpenClawCapabilityShim:
    """Expose a legacy OpenClaw adapter through the neutral capability port."""

    adapter: OpenClawAdapter

    def __post_init__(self) -> None:
        require_safe_id(self.adapter.adapter_id, "legacy adapter_id")

    @property
    def runtime_id(self) -> str:
        return self.adapter.adapter_id

    def execute(
        self,
        request: OperationRequest,
        *,
        context: OperationExecutionContext = OperationExecutionContext(),
    ) -> OperationResult:
        return self.adapter.run_operation(request, context=context)

    def get_execution_status(self, operation_id: str) -> OperationResult:
        return self.adapter.get_operation_status(operation_id)

    def cancel(
        self,
        request: OperationRequest,
        *,
        context: OperationExecutionContext,
    ) -> OperationResult:
        return self.adapter.cancel_operation(request, context=context)

    def notify(self, request: NotificationRequest) -> NotificationReceipt:
        return self.adapter.send_notification(request)

    def submit_approval_request(
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
        return self.adapter.request_approval(
            request,
            context=context,
            approval_id=approval_id,
            approver_principal_id=approver_principal_id,
            nonce=nonce,
            expires_at=expires_at,
            impact_summary=impact_summary,
            rollback_summary=rollback_summary,
        )
