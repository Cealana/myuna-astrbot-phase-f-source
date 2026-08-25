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

from .lifecycle import CapabilityLifecycleSnapshot


@runtime_checkable
class CapabilityRuntimePort(Protocol):
    """Transport-neutral structured operation boundary."""

    runtime_id: str

    def execute(
        self,
        request: OperationRequest,
        *,
        context: OperationExecutionContext = OperationExecutionContext(),
    ) -> OperationResult: ...

    def get_execution_status(self, operation_id: str) -> OperationResult: ...

    def cancel(
        self,
        request: OperationRequest,
        *,
        context: OperationExecutionContext,
    ) -> OperationResult: ...

    def notify(self, request: NotificationRequest) -> NotificationReceipt: ...

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
    ) -> ApprovalRecord: ...


@runtime_checkable
class CapabilityLifecyclePort(Protocol):
    """Lifecycle boundary for a capability runtime implementation."""

    runtime_id: str

    def lifecycle_snapshot(self) -> CapabilityLifecycleSnapshot: ...

    def startup(self) -> CapabilityLifecycleSnapshot: ...

    def shutdown(self) -> CapabilityLifecycleSnapshot: ...

    def recover(self) -> CapabilityLifecycleSnapshot: ...
