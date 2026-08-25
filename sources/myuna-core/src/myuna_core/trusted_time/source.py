from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
import time

from .contracts import SynchronizationEvidence, UtcObservation
from .errors import (
    TrustedTimeError,
    TrustedTimeTimeoutError,
    TrustedTimeUnavailableError,
)


class SystemUtcObservationSource:
    """Read UTC only when an explicit synchronization probe attests it.

    The system clock is an observation, never a fallback.  The required probe
    owns its timeout and returns bounded uncertainty plus a stable authority
    class (not a server address or other private detail).
    """

    def __init__(
        self,
        synchronization_probe: Callable[[float], SynchronizationEvidence],
        *,
        now: Callable[[], datetime] | None = None,
        monotonic_ns: Callable[[], int] | None = None,
        boot_id_reader: Callable[[], str] | None = None,
        elapsed: Callable[[], float] | None = None,
    ) -> None:
        if not callable(synchronization_probe):
            raise TrustedTimeUnavailableError()
        self._probe = synchronization_probe
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._monotonic_ns = monotonic_ns or time.monotonic_ns
        self._boot_id_reader = boot_id_reader or self._linux_boot_id
        self._elapsed = elapsed or time.monotonic

    @staticmethod
    def _linux_boot_id() -> str:
        try:
            return Path("/proc/sys/kernel/random/boot_id").read_text(
                encoding="ascii"
            ).strip()
        except OSError:
            raise TrustedTimeUnavailableError() from None

    def observe(self, timeout_seconds: float) -> UtcObservation:
        started = self._elapsed()
        try:
            evidence = self._probe(timeout_seconds)
            instant = self._now()
            monotonic_value = self._monotonic_ns()
            boot_id = self._boot_id_reader()
        except TrustedTimeError:
            raise
        except Exception:
            raise TrustedTimeUnavailableError() from None
        if self._elapsed() - started > timeout_seconds:
            raise TrustedTimeTimeoutError()
        try:
            return UtcObservation(
                instant=instant,
                monotonic_ns=monotonic_value,
                boot_id=boot_id,
                evidence=evidence,
            )
        except TrustedTimeError:
            raise
        except Exception:
            raise TrustedTimeUnavailableError() from None
