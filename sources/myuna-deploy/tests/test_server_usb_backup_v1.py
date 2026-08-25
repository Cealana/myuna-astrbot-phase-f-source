import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "server_usb_backup_v1.py"
SPEC = importlib.util.spec_from_file_location("server_usb_backup_v1", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class BackupContractTests(unittest.TestCase):
    def test_retention_keeps_daily_weekly_monthly_union(self):
        names = [f"202607{day:02d}T053000Z" for day in range(1, 27)]
        keep = MODULE.retention_keep(names, daily=14, weekly=8, monthly=6)
        self.assertTrue(set(names[-14:]).issubset(keep))
        self.assertGreaterEqual(len(keep), 14)

    def test_marker_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            usb = root / "usb"
            usb.mkdir()
            (usb / "DEVICE_ID.json").write_text(json.dumps({"schema": MODULE.MARKER_SCHEMA, "label": "wrong"}))
            config = MODULE.Config(usb, root / "stage", root / "secret", root / "state", "Server BU", "exFAT", "serial", 1, 1, 1, 1, 1)
            with self.assertRaisesRegex(MODULE.BackupError, "USB_MARKER_MISMATCH"):
                MODULE.validate_marker(config)

    def test_missing_marker_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            usb = root / "usb"
            usb.mkdir()
            config = MODULE.Config(usb, root / "stage", root / "secret", root / "state", "Server BU", "exFAT", "serial", 1, 1, 1, 1, 1)
            with self.assertRaisesRegex(MODULE.BackupError, "USB_MARKER_UNAVAILABLE"):
                MODULE.validate_marker(config)

    def test_safe_remove_rejects_non_snapshot_name(self):
        with tempfile.TemporaryDirectory() as root:
            parent = Path(root)
            target = parent / "not-a-snapshot"
            target.mkdir()
            with self.assertRaisesRegex(MODULE.BackupError, "UNSAFE_RETENTION_TARGET"):
                MODULE.safe_remove_tree(target, parent)

    def test_canonical_json_is_stable(self):
        self.assertEqual(MODULE.canonical_json({"b": 2, "a": 1}), '{"a":1,"b":2}\n')


if __name__ == "__main__":
    unittest.main()
