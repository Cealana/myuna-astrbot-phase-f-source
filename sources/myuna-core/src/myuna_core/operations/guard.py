from __future__ import annotations

from dataclasses import dataclass

from .errors import HopLimitExceededError, OperationLoopDetectedError
from .models import OperationRequest


@dataclass(frozen=True, slots=True)
class RouteAdvance:
    hop_count: int
    route_trace: tuple[str, ...]


class OperationLoopGuard:
    def __init__(self, *, max_hops: int = 4) -> None:
        if not 1 <= max_hops <= 16:
            raise ValueError("max_hops must be between 1 and 16")
        self.max_hops = max_hops

    def advance(self, request: OperationRequest, destination: str) -> RouteAdvance:
        if request.hop_count >= self.max_hops:
            raise HopLimitExceededError("operation hop limit exceeded")
        if destination in request.route_trace:
            raise OperationLoopDetectedError("operation route loop detected")
        return RouteAdvance(
            hop_count=request.hop_count + 1,
            route_trace=request.route_trace + (destination,),
        )
