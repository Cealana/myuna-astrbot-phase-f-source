from __future__ import annotations

from types import MappingProxyType
from typing import Any, Mapping

from myuna_core.operations.models import require_safe_id


class CapabilityRuntimeError(RuntimeError):
    """A structured, content-free capability-runtime boundary error."""

    code = "capability_runtime_error"
    retryable = False
    public_message = "capability runtime error"

    def __init__(
        self,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        bounded_details: dict[str, Any] = {}
        for key, value in dict(details or {}).items():
            require_safe_id(key, "capability error detail key")
            if isinstance(value, str):
                require_safe_id(value, f"capability error detail {key}")
            elif value is not None and not isinstance(value, (bool, int)):
                raise ValueError("capability error details must be scalar and content-free")
            bounded_details[key] = value
        super().__init__(self.public_message)
        self.details = MappingProxyType(bounded_details)

    def public_payload(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "details": dict(self.details),
            "message": str(self),
            "retryable": self.retryable,
        }


class CapabilityRuntimeUnavailableError(CapabilityRuntimeError):
    code = "capability_runtime_unavailable"
    retryable = True
    public_message = "capability runtime is unavailable"


class InvalidLifecycleTransitionError(CapabilityRuntimeError):
    code = "invalid_lifecycle_transition"
    public_message = "capability lifecycle transition is not allowed"

    def __init__(self, current: str, requested: str) -> None:
        require_safe_id(current, "current lifecycle state")
        require_safe_id(requested, "requested lifecycle state")
        super().__init__(details={"current": current, "requested": requested})


class LifecycleActionFailedError(CapabilityRuntimeError):
    code = "lifecycle_action_failed"
    retryable = True
    public_message = "capability lifecycle action failed"

    def __init__(self, phase: str) -> None:
        require_safe_id(phase, "lifecycle phase")
        super().__init__(details={"phase": phase})
