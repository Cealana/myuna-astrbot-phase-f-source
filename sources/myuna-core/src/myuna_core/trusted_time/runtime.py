from __future__ import annotations

from myuna_core.active_temporal_context.time import TrustedTimeSample
from myuna_core.capability_runtime import (
    CapabilityLifecycleController,
    CapabilityLifecycleSnapshot,
)

from .errors import TrustedTimeError, TrustedTimeUnavailableError
from .provider import DurableTrustedTimeProvider


class TrustedTimeCapability:
    """P10-A lifecycle plus the narrow P08 TrustedTimePort."""

    runtime_id = "trusted-time-capability-v1"

    def __init__(self, provider: DurableTrustedTimeProvider) -> None:
        self.provider = provider
        self._lifecycle = CapabilityLifecycleController(self.runtime_id)

    def lifecycle_snapshot(self) -> CapabilityLifecycleSnapshot:
        return self._lifecycle.lifecycle_snapshot()

    def startup(self) -> CapabilityLifecycleSnapshot:
        return self._lifecycle.startup(self.provider.validate_state)

    def shutdown(self) -> CapabilityLifecycleSnapshot:
        return self._lifecycle.shutdown()

    def recover(self) -> CapabilityLifecycleSnapshot:
        return self._lifecycle.recover(self.provider.validate_state)

    def sample(self) -> TrustedTimeSample:
        if not self.lifecycle_snapshot().accepting_requests:
            raise TrustedTimeUnavailableError()
        try:
            return self.provider.sample()
        except TrustedTimeError as error:
            if error.retryable:
                self._lifecycle.degrade(error.code)
            else:
                self._lifecycle.fail(error.code)
            raise
