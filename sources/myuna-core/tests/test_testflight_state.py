from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from myuna_core.testflight_state import (
    FileTestFlightStateStore,
    TestFlightStateError,
)


class TestFlightStateStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 7, 26, 15, 30, tzinfo=timezone.utc)

    def test_first_activation_is_version_scoped_persistent_and_idempotent(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            first_store = FileTestFlightStateStore(root)
            first, created = first_store.activate_once(
                "v6",
                activated_at=self.now,
                activation_id="testflight-v6-first",
            )
            restarted_store = FileTestFlightStateStore(root)
            second, created_again = restarted_store.activate_once(
                "v6",
                activated_at=self.now,
                activation_id="different-request-id",
            )
            self.assertTrue(created)
            self.assertFalse(created_again)
            self.assertEqual(first, second)
            self.assertTrue(second.first_activation_completed)
            self.assertIsNone(restarted_store.read("v5"))
            self.assertEqual((root / "v6.json").stat().st_mode & 0o777, 0o600)

    def test_invalid_or_tampered_state_fails_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            root.mkdir()
            (root / "v6.json").write_text(json.dumps({"version": "v6"}), encoding="utf-8")
            with self.assertRaises(TestFlightStateError):
                FileTestFlightStateStore(root).read("v6")

    def test_version_and_time_are_strict(self) -> None:
        with TemporaryDirectory() as temporary:
            store = FileTestFlightStateStore(Path(temporary) / "state")
            with self.assertRaises(TestFlightStateError):
                store.read("../v6")
            with self.assertRaises(TestFlightStateError):
                store.activate_once(
                    "v6",
                    activated_at=datetime(2026, 7, 26, 15, 30),
                    activation_id="test",
                )

    def test_symlink_state_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            root.mkdir(mode=0o700)
            target = Path(temporary) / "target.json"
            target.write_text("{}", encoding="utf-8")
            (root / "v6.json").symlink_to(target)
            with self.assertRaises(TestFlightStateError):
                FileTestFlightStateStore(root).read("v6")


if __name__ == "__main__":
    unittest.main()
