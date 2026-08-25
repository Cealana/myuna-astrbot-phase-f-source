from __future__ import annotations

from typing import Any, Mapping


class OpenClawError(RuntimeError):
    """A typed, content-free failure safe to expose at an adapter boundary."""

    code = "openclaw_error"
    retryable = False

    def __init__(
        self,
        message: str | None = None,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message or self.code)
        self.details = dict(details or {})


class OpenClawUnavailableError(OpenClawError):
    code = "openclaw_unavailable"
    retryable = True


class OperationNotAllowedError(OpenClawError):
    code = "operation_not_allowed"


class UnknownOperationError(OperationNotAllowedError):
    code = "unknown_operation"


class InvalidOperationArgumentsError(OpenClawError, ValueError):
    code = "invalid_operation_arguments"


class ApprovalRequiredError(OpenClawError):
    code = "approval_required"


class ApprovalDeniedError(OpenClawError):
    code = "approval_denied"


class ApprovalExpiredError(OpenClawError):
    code = "approval_expired"


class ApprovalAlreadyConsumedError(OpenClawError):
    code = "approval_already_consumed"


class IdempotencyConflictError(OpenClawError):
    code = "idempotency_conflict"


class IdempotencyInProgressError(OpenClawError):
    code = "idempotency_in_progress"
    retryable = True


class OperationTimeoutError(OpenClawError):
    code = "operation_timeout"
    retryable = True


class OperationCancelledError(OpenClawError):
    code = "operation_cancelled"


class OperationNotFoundError(OpenClawError):
    code = "operation_not_found"


class OutputLimitExceededError(OpenClawError):
    code = "output_limit_exceeded"


class HopLimitExceededError(OpenClawError):
    code = "hop_limit_exceeded"


class OperationLoopDetectedError(OpenClawError):
    code = "operation_loop_detected"


class RecoveryModeViolationError(OpenClawError):
    code = "recovery_mode_violation"


class RemoteNodeUnavailableError(OpenClawError):
    code = "remote_node_unavailable"
    retryable = True


class PartialOperationError(OpenClawError):
    code = "partial_operation"

