from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re


class PersonaRoute(str, Enum):
    MYUNA = "myuna"
    CHRYNA = "chryna"
    DUAL = "dual"


class WakeDecision(str, Enum):
    SLEEP = "sleep"
    CHRYNA = "chryna"
    DUAL = "dual"


_DIRECT_CHRYNA = re.compile(r"^\s*Chryna(?:\s*|[，,:：]\s*.*)$", re.I | re.S)
_DIRECT_MYUNA = re.compile(r"^\s*Myuna(?:\s*|[，,:：]\s*.*)$", re.I | re.S)
_PLURAL = re.compile(
    r"(?:Myuna.{0,24}Chryna|Chryna.{0,24}Myuna|你们(?:两个|俩)?|你们都|你们怎么看)",
    re.I | re.S,
)


class PersonaRouteParser:
    def parse(self, text: str, *, requested_mode: str = "auto") -> PersonaRoute:
        normalized_mode = requested_mode.strip().casefold()
        if normalized_mode in {"myuna", "chryna", "dual"}:
            return PersonaRoute(normalized_mode)
        if normalized_mode != "auto":
            raise ValueError("unsupported persona route mode")
        if _PLURAL.search(text):
            return PersonaRoute.DUAL
        if _DIRECT_CHRYNA.fullmatch(text):
            return PersonaRoute.CHRYNA
        if _DIRECT_MYUNA.fullmatch(text):
            return PersonaRoute.MYUNA
        return PersonaRoute.MYUNA


@dataclass(frozen=True, slots=True)
class ChrynaWakeInput:
    explicit_route: PersonaRoute
    internal_precision_request: bool = False
    risk_score: int = 0
    first_testflight: bool = False
    later_testflight: bool = False
    factual_correction: bool = False
    major_closure: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.risk_score, int)
            or isinstance(self.risk_score, bool)
            or not 0 <= self.risk_score <= 100
        ):
            raise ValueError("risk score must be an integer from 0 through 100")
        if self.first_testflight and self.later_testflight:
            raise ValueError("TestFlight state is contradictory")


@dataclass(frozen=True, slots=True)
class ChrynaWakeResult:
    decision: WakeDecision
    reason: str


class ChrynaWakeController:
    def __init__(self, takeover_threshold: int = 90) -> None:
        if (
            not isinstance(takeover_threshold, int)
            or isinstance(takeover_threshold, bool)
            or not 0 <= takeover_threshold <= 100
        ):
            raise ValueError("takeover threshold must be from 0 through 100")
        self.takeover_threshold = takeover_threshold

    def decide(self, value: ChrynaWakeInput) -> ChrynaWakeResult:
        if value.explicit_route is PersonaRoute.CHRYNA:
            return ChrynaWakeResult(WakeDecision.CHRYNA, "explicit_chryna_route")
        if value.explicit_route is PersonaRoute.DUAL:
            return ChrynaWakeResult(WakeDecision.DUAL, "explicit_plural_route")
        if value.first_testflight:
            return ChrynaWakeResult(WakeDecision.DUAL, "first_testflight")
        if value.later_testflight:
            return ChrynaWakeResult(WakeDecision.CHRYNA, "later_testflight")
        if value.risk_score >= self.takeover_threshold:
            return ChrynaWakeResult(WakeDecision.CHRYNA, "takeover_threshold")
        if value.internal_precision_request:
            return ChrynaWakeResult(WakeDecision.DUAL, "typed_precision_request")
        if value.factual_correction:
            return ChrynaWakeResult(WakeDecision.DUAL, "factual_correction")
        if value.major_closure:
            return ChrynaWakeResult(WakeDecision.DUAL, "major_closure")
        return ChrynaWakeResult(WakeDecision.SLEEP, "ordinary_myuna_turn")
