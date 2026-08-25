from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import math
import re
from typing import Protocol, runtime_checkable

from .errors import (
    TrustedTimeError,
    TrustedTimePermissionError,
    TrustedTimeStateCorruptError,
)


P08_CONSUMER_ID = "p08-active-temporal-context-v1"
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def safe_label(value: object) -> str:
    if not isinstance(value, str) or not _SAFE_LABEL.fullmatch(value):
        raise TrustedTimeStateCorruptError()
    return value


def utc(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise TrustedTimeStateCorruptError()
    try:
        if value.utcoffset() is None:
            raise TrustedTimeStateCorruptError()
        return value.astimezone(timezone.utc)
    except TrustedTimeError:
        raise
    except Exception:
        raise TrustedTimeStateCorruptError() from None


@dataclass(frozen=True, slots=True)
class SynchronizationEvidence:
    synchronized: bool
    uncertainty: timedelta
    authority: str

    def __post_init__(self) -> None:
        if not isinstance(self.synchronized, bool):
            raise TrustedTimeStateCorruptError()
        if (
            not isinstance(self.uncertainty, timedelta)
            or self.uncertainty < timedelta(0)
        ):
            raise TrustedTimeStateCorruptError()
        safe_label(self.authority)


@dataclass(frozen=True, slots=True)
class UtcObservation:
    instant: datetime
    monotonic_ns: int
    boot_id: str
    evidence: SynchronizationEvidence

    def __post_init__(self) -> None:
        object.__setattr__(self, "instant", utc(self.instant))
        if (
            isinstance(self.monotonic_ns, bool)
            or not isinstance(self.monotonic_ns, int)
            or self.monotonic_ns < 0
        ):
            raise TrustedTimeStateCorruptError()
        safe_label(self.boot_id)
        if not isinstance(self.evidence, SynchronizationEvidence):
            raise TrustedTimeStateCorruptError()


@runtime_checkable
class UtcObservationPort(Protocol):
    def observe(self, timeout_seconds: float) -> UtcObservation: ...


@dataclass(frozen=True, slots=True)
class TrustedTimeWatermark:
    source: str
    sequence: int
    instant: datetime

    def __post_init__(self) -> None:
        safe_label(self.source)
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 1
        ):
            raise TrustedTimeStateCorruptError()
        object.__setattr__(self, "instant", utc(self.instant))


@dataclass(frozen=True, slots=True)
class TrustedTimePolicy:
    source: str = "myuna-trusted-local-v1"
    source_class: str = "trusted_local"
    consumer_id: str = P08_CONSUMER_ID
    max_uncertainty: timedelta = timedelta(seconds=1)
    max_drift: timedelta = timedelta(seconds=2)
    timeout_seconds: float = 1.0

    def __post_init__(self) -> None:
        safe_label(self.source)
        if self.source_class not in {"trusted_local", "trusted_remote"}:
            raise TrustedTimeStateCorruptError()
        if self.consumer_id != P08_CONSUMER_ID:
            raise TrustedTimePermissionError()
        if (
            not isinstance(self.max_uncertainty, timedelta)
            or self.max_uncertainty <= timedelta(0)
            or self.max_uncertainty > timedelta(seconds=1)
            or not isinstance(self.max_drift, timedelta)
            or self.max_drift <= timedelta(0)
            or self.max_drift > timedelta(seconds=2)
            or isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(float(self.timeout_seconds))
            or not 0 < float(self.timeout_seconds) <= 5
        ):
            raise TrustedTimeStateCorruptError()
