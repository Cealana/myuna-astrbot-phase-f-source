from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from myuna_core.operations.approval import ApprovalRecord
from myuna_core.operations.models import (
    NotificationReceipt,
    NotificationRequest,
    OperationRequest,
    OperationResult,
)
from myuna_core.operations.policy import OperationExecutionContext


@runtime_checkable
class OpenClawAdapter(Protocol):
    adapter_id: str

    def health_check(
        self,
        request: OperationRequest,
        *,
        context: OperationExecutionContext = OperationExecutionContext(),
    ) -> OperationResult: ...

    def get_host_status(
        self,
        request: OperationRequest,
        *,
        context: OperationExecutionContext = OperationExecutionContext(),
    ) -> OperationResult: ...

    def get_service_status(
        self,
        request: OperationRequest,
        *,
        context: OperationExecutionContext = OperationExecutionContext(),
    ) -> OperationResult: ...

    def read_service_logs(
        self,
        request: OperationRequest,
        *,
        context: OperationExecutionContext = OperationExecutionContext(),
    ) -> OperationResult: ...

    def run_operation(
        self,
        request: OperationRequest,
        *,
        context: OperationExecutionContext = OperationExecutionContext(),
    ) -> OperationResult: ...

    def run_playbook(
        self,
        request: OperationRequest,
        *,
        context: OperationExecutionContext,
    ) -> OperationResult: ...

    def get_operation_status(self, operation_id: str) -> OperationResult: ...

    def cancel_operation(
        self,
        request: OperationRequest,
        *,
        context: OperationExecutionContext,
    ) -> OperationResult: ...

    def send_notification(self, request: NotificationRequest) -> NotificationReceipt: ...

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
    ) -> ApprovalRecord: ...
