from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Protocol
import re

from .testflight_state import FileTestFlightStateStore, TestFlightStateRecord


_SAFE_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/ -]{0,127}$")
_OVERALL_STATES = frozenset({"healthy", "degraded", "failed"})


class TestFlightCoordinatorError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TestFlightHealthSnapshot:
    observed_at: datetime
    overall: str
    available_modules: tuple[str, ...] = ()
    unavailable_modules: tuple[str, ...] = ()
    faults: tuple[str, ...] = ()
    pending_sync: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise TestFlightCoordinatorError("health snapshot time must include a timezone")
        if self.overall not in _OVERALL_STATES:
            raise TestFlightCoordinatorError("health snapshot state is invalid")
        for collection in (
            self.available_modules,
            self.unavailable_modules,
            self.faults,
            self.pending_sync,
        ):
            if len(collection) > 64 or len(set(collection)) != len(collection):
                raise TestFlightCoordinatorError("health snapshot collection is invalid")
            if any(not isinstance(value, str) or _SAFE_VALUE.fullmatch(value) is None for value in collection):
                raise TestFlightCoordinatorError("health snapshot value is invalid")

    def prompt_context(self) -> str:
        def render(values: tuple[str, ...]) -> str:
            return ", ".join(values) if values else "none"

        return "\n".join(
            (
                "Authoritative TestFlight health snapshot:",
                f"observed_at: {self.observed_at.isoformat()}",
                f"overall: {self.overall}",
                f"available_modules: {render(self.available_modules)}",
                f"unavailable_modules: {render(self.unavailable_modules)}",
                f"faults: {render(self.faults)}",
                f"pending_sync: {render(self.pending_sync)}",
                "Do not improve, guess, or contradict this snapshot.",
            )
        )


class TestFlightHealthSource(Protocol):
    def snapshot(self) -> TestFlightHealthSnapshot: ...


@dataclass(frozen=True, slots=True)
class TestFlightPlan:
    version: str
    activation_id: str
    first_activation: bool
    health: TestFlightHealthSnapshot


class TestFlightCoordinator:
    """Two-phase TestFlight coordinator with no service-management authority."""

    def __init__(
        self,
        state_store: FileTestFlightStateStore,
        health_source: TestFlightHealthSource,
        *,
        clock: Callable[[], datetime],
    ) -> None:
        self.state_store = state_store
        self.health_source = health_source
        self.clock = clock

    def prepare(self, *, version: str, activation_id: str) -> TestFlightPlan:
        current = self.state_store.read(version)
        health = self.health_source.snapshot()
        if health.overall == "failed":
            raise TestFlightCoordinatorError("TestFlight health check failed")
        return TestFlightPlan(
            version=version,
            activation_id=activation_id,
            first_activation=current is None,
            health=health,
        )

    def commit(self, plan: TestFlightPlan) -> tuple[TestFlightStateRecord | None, bool]:
        if not plan.first_activation:
            return self.state_store.read(plan.version), False
        committed_at = self.clock()
        if committed_at.tzinfo is None or committed_at.utcoffset() is None:
            raise TestFlightCoordinatorError("TestFlight commit time must include a timezone")
        return self.state_store.activate_once(
            plan.version,
            activated_at=committed_at,
            activation_id=plan.activation_id,
        )
