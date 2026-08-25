from __future__ import annotations

import ctypes
from dataclasses import dataclass
from datetime import timedelta
import os
import sys
import time
from typing import Callable

from .contracts import SynchronizationEvidence
from .errors import TrustedTimeTimeoutError, TrustedTimeUnavailableError


STA_UNSYNC = 0x0040
TIME_ERROR = 5
AUTHORITY = "linux-kernel-adjtimex-v1"


class _Timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _Timex(ctypes.Structure):
    # Linux UAPI struct timex for the native ABI.  Only status/maxerror/esterror
    # are consumed, but the complete tail prevents an undersized syscall buffer.
    _fields_ = [
        ("modes", ctypes.c_uint),
        ("offset", ctypes.c_long),
        ("freq", ctypes.c_long),
        ("maxerror", ctypes.c_long),
        ("esterror", ctypes.c_long),
        ("status", ctypes.c_int),
        ("constant", ctypes.c_long),
        ("precision", ctypes.c_long),
        ("tolerance", ctypes.c_long),
        ("time", _Timeval),
        ("tick", ctypes.c_long),
        ("ppsfreq", ctypes.c_long),
        ("jitter", ctypes.c_long),
        ("shift", ctypes.c_int),
        ("stabil", ctypes.c_long),
        ("jitcnt", ctypes.c_long),
        ("calcnt", ctypes.c_long),
        ("errcnt", ctypes.c_long),
        ("stbcnt", ctypes.c_long),
        ("tai", ctypes.c_int),
        ("_padding", ctypes.c_int * 11),
    ]


@dataclass(frozen=True, slots=True)
class LinuxClockStatus:
    state: int
    status: int
    maxerror_microseconds: int
    esterror_microseconds: int


def _native_adjtimex() -> LinuxClockStatus:
    if sys.platform != "linux" or os.name != "posix":
        raise TrustedTimeUnavailableError()
    value = _Timex()
    try:
        function = ctypes.CDLL(None, use_errno=True).adjtimex
        function.argtypes = [ctypes.POINTER(_Timex)]
        function.restype = ctypes.c_int
        state = int(function(ctypes.byref(value)))
    except (AttributeError, OSError, TypeError, ValueError):
        raise TrustedTimeUnavailableError() from None
    if state < 0:
        raise TrustedTimeUnavailableError()
    return LinuxClockStatus(
        state=state,
        status=int(value.status),
        maxerror_microseconds=int(value.maxerror),
        esterror_microseconds=int(value.esterror),
    )


class LinuxAdjtimexSynchronizationProbe:
    """Attest UTC synchronization from the Linux kernel time discipline.

    The probe performs no network or subprocess call, reads no timestamp and does
    not treat filesystem state as authority.  The provider still applies its own
    one-second uncertainty ceiling and continuity checks.
    """

    def __init__(
        self,
        *,
        reader: Callable[[], LinuxClockStatus] = _native_adjtimex,
        elapsed: Callable[[], float] = time.monotonic,
    ) -> None:
        if not callable(reader) or not callable(elapsed):
            raise TrustedTimeUnavailableError()
        self._reader = reader
        self._elapsed = elapsed

    def __call__(self, timeout_seconds: float) -> SynchronizationEvidence:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0 < float(timeout_seconds) <= 5
        ):
            raise TrustedTimeUnavailableError()
        started = self._elapsed()
        try:
            status = self._reader()
        except (TrustedTimeUnavailableError, TrustedTimeTimeoutError):
            raise
        except Exception:
            raise TrustedTimeUnavailableError() from None
        if self._elapsed() - started > float(timeout_seconds):
            raise TrustedTimeTimeoutError()
        if not isinstance(status, LinuxClockStatus):
            raise TrustedTimeUnavailableError()
        errors = (status.maxerror_microseconds, status.esterror_microseconds)
        if any(isinstance(value, bool) or value < 0 for value in errors):
            raise TrustedTimeUnavailableError()
        synchronized = status.state != TIME_ERROR and not (status.status & STA_UNSYNC)
        return SynchronizationEvidence(
            synchronized=synchronized,
            uncertainty=timedelta(microseconds=max(errors)),
            authority=AUTHORITY,
        )
