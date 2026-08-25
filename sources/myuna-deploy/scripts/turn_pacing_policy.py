from __future__ import annotations

from dataclasses import dataclass
import math


class TurnPacingRejected(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PacingPlan:
    delay_seconds: float
    cancellable: bool
    bypass_reason: str | None


class BoundedTurnPacingPolicy:
    """Pure policy only; provider execution and error delivery never sleep here."""

    def __init__(self, *, maximum_delay_seconds: float) -> None:
        if (
            not isinstance(maximum_delay_seconds, (int, float))
            or isinstance(maximum_delay_seconds, bool)
            or not math.isfinite(maximum_delay_seconds)
            or not 0.0 <= maximum_delay_seconds <= 15.0
        ):
            raise TurnPacingRejected("pacing maximum must be between 0 and 15 seconds")
        self.maximum_delay_seconds = float(maximum_delay_seconds)

    def plan(
        self,
        *,
        requested_delay_seconds: float,
        is_error: bool = False,
        is_recovery_notice: bool = False,
        cancelled: bool = False,
    ) -> PacingPlan:
        if (
            not isinstance(requested_delay_seconds, (int, float))
            or isinstance(requested_delay_seconds, bool)
            or not math.isfinite(requested_delay_seconds)
            or requested_delay_seconds < 0
        ):
            raise TurnPacingRejected("pacing delay must be finite and non-negative")
        if cancelled:
            return PacingPlan(0.0, True, "cancelled")
        if is_error:
            return PacingPlan(0.0, True, "error")
        if is_recovery_notice:
            return PacingPlan(0.0, True, "recovery_notice")
        return PacingPlan(
            min(requested_delay_seconds, self.maximum_delay_seconds),
            True,
            None,
        )
