from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock

from myuna_core.operations.models import require_safe_id

from .errors import InvalidLifecycleTransitionError, LifecycleActionFailedError


class CapabilityLifecycleState(StrEnum):
    STOPPED = "stopped"
    STARTING = "starting"
    READY = "ready"
    DEGRADED = "degraded"
    RECOVERING = "recovering"
    FAILED = "failed"
    STOPPING = "stopping"


@dataclass(frozen=True, slots=True)
class CapabilityLifecycleSnapshot:
    runtime_id: str
    state: CapabilityLifecycleState
    revision: int
    reason_code: str | None = None

    def __post_init__(self) -> None:
        require_safe_id(self.runtime_id, "runtime_id")
        if not isinstance(self.state, CapabilityLifecycleState):
            raise ValueError("state must be a CapabilityLifecycleState")
        if self.revision < 0:
            raise ValueError("revision must be non-negative")
        if self.reason_code is not None:
            require_safe_id(self.reason_code, "reason_code")

    @property
    def accepting_requests(self) -> bool:
        return self.state is CapabilityLifecycleState.READY

    def public_payload(self) -> dict[str, object]:
        return {
            "accepting_requests": self.accepting_requests,
            "reason_code": self.reason_code,
            "revision": self.revision,
            "runtime_id": self.runtime_id,
            "state": self.state.value,
        }


class CapabilityLifecycleController:
    """Deterministic, repository-only lifecycle state controller."""

    def __init__(self, runtime_id: str) -> None:
        require_safe_id(runtime_id, "runtime_id")
        self.runtime_id = runtime_id
        self._state = CapabilityLifecycleState.STOPPED
        self._revision = 0
        self._reason_code: str | None = None
        self._lock = RLock()

    def lifecycle_snapshot(self) -> CapabilityLifecycleSnapshot:
        with self._lock:
            return CapabilityLifecycleSnapshot(
                runtime_id=self.runtime_id,
                state=self._state,
                revision=self._revision,
                reason_code=self._reason_code,
            )

    def _transition(
        self,
        state: CapabilityLifecycleState,
        reason_code: str,
    ) -> CapabilityLifecycleSnapshot:
        require_safe_id(reason_code, "reason_code")
        self._state = state
        self._revision += 1
        self._reason_code = reason_code
        return self.lifecycle_snapshot()

    @staticmethod
    def _invoke(action: Callable[[], None] | None) -> None:
        if action is not None:
            action()

    def startup(
        self,
        action: Callable[[], None] | None = None,
    ) -> CapabilityLifecycleSnapshot:
        with self._lock:
            if self._state is CapabilityLifecycleState.READY:
                return self.lifecycle_snapshot()
            if self._state is not CapabilityLifecycleState.STOPPED:
                raise InvalidLifecycleTransitionError(self._state.value, "startup")
            self._transition(CapabilityLifecycleState.STARTING, "startup_started")
            try:
                self._invoke(action)
            except Exception:
                self._transition(CapabilityLifecycleState.FAILED, "startup_failed")
                raise LifecycleActionFailedError("startup") from None
            return self._transition(CapabilityLifecycleState.READY, "startup_succeeded")

    def degrade(self, reason_code: str = "runtime_degraded") -> CapabilityLifecycleSnapshot:
        with self._lock:
            require_safe_id(reason_code, "reason_code")
            if (
                self._state is CapabilityLifecycleState.DEGRADED
                and self._reason_code == reason_code
            ):
                return self.lifecycle_snapshot()
            if self._state not in {
                CapabilityLifecycleState.READY,
                CapabilityLifecycleState.DEGRADED,
            }:
                raise InvalidLifecycleTransitionError(self._state.value, "degrade")
            return self._transition(CapabilityLifecycleState.DEGRADED, reason_code)

    def fail(self, reason_code: str = "runtime_failed") -> CapabilityLifecycleSnapshot:
        with self._lock:
            require_safe_id(reason_code, "reason_code")
            if self._state not in {
                CapabilityLifecycleState.READY,
                CapabilityLifecycleState.DEGRADED,
                CapabilityLifecycleState.FAILED,
            }:
                raise InvalidLifecycleTransitionError(self._state.value, "fail")
            if (
                self._state is CapabilityLifecycleState.FAILED
                and self._reason_code == reason_code
            ):
                return self.lifecycle_snapshot()
            return self._transition(CapabilityLifecycleState.FAILED, reason_code)

    def recover(
        self,
        action: Callable[[], None] | None = None,
    ) -> CapabilityLifecycleSnapshot:
        with self._lock:
            if self._state not in {
                CapabilityLifecycleState.DEGRADED,
                CapabilityLifecycleState.FAILED,
            }:
                raise InvalidLifecycleTransitionError(self._state.value, "recover")
            self._transition(CapabilityLifecycleState.RECOVERING, "recovery_started")
            try:
                self._invoke(action)
            except Exception:
                self._transition(CapabilityLifecycleState.FAILED, "recovery_failed")
                raise LifecycleActionFailedError("recovery") from None
            return self._transition(CapabilityLifecycleState.READY, "recovery_succeeded")

    def shutdown(
        self,
        action: Callable[[], None] | None = None,
    ) -> CapabilityLifecycleSnapshot:
        with self._lock:
            if self._state is CapabilityLifecycleState.STOPPED:
                return self.lifecycle_snapshot()
            if self._state not in {
                CapabilityLifecycleState.READY,
                CapabilityLifecycleState.DEGRADED,
                CapabilityLifecycleState.FAILED,
            }:
                raise InvalidLifecycleTransitionError(self._state.value, "shutdown")
            self._transition(CapabilityLifecycleState.STOPPING, "shutdown_started")
            try:
                self._invoke(action)
            except Exception:
                self._transition(CapabilityLifecycleState.FAILED, "shutdown_failed")
                raise LifecycleActionFailedError("shutdown") from None
            return self._transition(CapabilityLifecycleState.STOPPED, "shutdown_succeeded")
