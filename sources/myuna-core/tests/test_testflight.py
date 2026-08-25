from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from myuna_core.testflight import (
    TestFlightCoordinator,
    TestFlightCoordinatorError,
    TestFlightHealthSnapshot,
)
from myuna_core.testflight_state import FileTestFlightStateStore


class FakeHealthSource:
    def __init__(self, snapshot: TestFlightHealthSnapshot) -> None:
        self.value = snapshot
        self.calls = 0

    def snapshot(self) -> TestFlightHealthSnapshot:
        self.calls += 1
        return self.value


class TestFlightCoordinatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 7, 26, 18, 0, tzinfo=timezone.utc)
        self.health = TestFlightHealthSnapshot(
            observed_at=self.now,
            overall="degraded",
            available_modules=("conversation", "memory-read"),
            unavailable_modules=("memory-write", "diary"),
            pending_sync=("effective-v6",),
        )

    def test_first_plan_is_read_only_until_commit_then_later_is_chryna_only(self) -> None:
        with TemporaryDirectory() as temporary:
            state_root = Path(temporary) / "state"
            source = FakeHealthSource(self.health)
            coordinator = TestFlightCoordinator(
                FileTestFlightStateStore(state_root),
                source,
                clock=lambda: self.now,
            )
            first = coordinator.prepare(version="v6", activation_id="request-first")
            self.assertTrue(first.first_activation)
            self.assertFalse(state_root.exists())
            record, created = coordinator.commit(first)
            self.assertTrue(created)
            self.assertIsNotNone(record)
            later = coordinator.prepare(version="v6", activation_id="request-later")
            self.assertFalse(later.first_activation)
            _, created_again = coordinator.commit(later)
            self.assertFalse(created_again)
            self.assertEqual(source.calls, 2)

    def test_failed_health_never_creates_state(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            coordinator = TestFlightCoordinator(
                FileTestFlightStateStore(root),
                FakeHealthSource(
                    TestFlightHealthSnapshot(
                        observed_at=self.now,
                        overall="failed",
                        faults=("core-unready",),
                    )
                ),
                clock=lambda: self.now,
            )
            with self.assertRaises(TestFlightCoordinatorError):
                coordinator.prepare(version="v6", activation_id="failed")
            self.assertFalse(root.exists())

    def test_snapshot_rejects_unbounded_or_unsafe_values(self) -> None:
        with self.assertRaises(TestFlightCoordinatorError):
            TestFlightHealthSnapshot(
                observed_at=self.now,
                overall="healthy",
                faults=("secret=abc\nnext",),
            )


if __name__ == "__main__":
    unittest.main()
