from datetime import timedelta
import unittest

from myuna_core.trusted_time import LinuxAdjtimexSynchronizationProbe
from myuna_core.trusted_time.errors import (
    TrustedTimeTimeoutError,
    TrustedTimeUnavailableError,
)
from myuna_core.trusted_time.linux import (
    AUTHORITY,
    STA_UNSYNC,
    TIME_ERROR,
    LinuxClockStatus,
)


class LinuxAdjtimexProbeTests(unittest.TestCase):
    def test_synchronized_status_returns_bounded_kernel_evidence(self) -> None:
        probe = LinuxAdjtimexSynchronizationProbe(
            reader=lambda: LinuxClockStatus(0, 0x2000, 80_000, 20_000),
            elapsed=lambda: 1.0,
        )
        evidence = probe(1.0)
        self.assertTrue(evidence.synchronized)
        self.assertEqual(evidence.uncertainty, timedelta(milliseconds=80))
        self.assertEqual(evidence.authority, AUTHORITY)

    def test_unsync_flag_and_time_error_never_become_authority(self) -> None:
        for value in (
            LinuxClockStatus(0, STA_UNSYNC, 1, 1),
            LinuxClockStatus(TIME_ERROR, 0, 1, 1),
        ):
            with self.subTest(value=value):
                evidence = LinuxAdjtimexSynchronizationProbe(
                    reader=lambda value=value: value,
                    elapsed=lambda: 1.0,
                )(1.0)
                self.assertFalse(evidence.synchronized)

    def test_negative_or_malformed_kernel_result_fails_closed(self) -> None:
        with self.assertRaises(TrustedTimeUnavailableError):
            LinuxAdjtimexSynchronizationProbe(
                reader=lambda: LinuxClockStatus(0, 0, -1, 1),
                elapsed=lambda: 1.0,
            )(1.0)
        with self.assertRaises(TrustedTimeUnavailableError):
            LinuxAdjtimexSynchronizationProbe(
                reader=lambda: object(),
                elapsed=lambda: 1.0,
            )(1.0)

    def test_probe_timeout_is_typed_and_no_fallback_occurs(self) -> None:
        elapsed = iter((0.0, 2.0))
        probe = LinuxAdjtimexSynchronizationProbe(
            reader=lambda: LinuxClockStatus(0, 0, 1, 1),
            elapsed=lambda: next(elapsed),
        )
        with self.assertRaises(TrustedTimeTimeoutError):
            probe(1.0)


if __name__ == "__main__":
    unittest.main()
