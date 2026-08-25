from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import reconcile_stale_provider_budget_v1 as reconcile  # noqa: E402


class ReconcileStaleProviderBudgetTests(unittest.TestCase):
    def test_stale_reservations_are_counted_without_exposing_ids(self) -> None:
        payload = {
            "schema_version": 1,
            "date_utc": "2026-07-30",
            "daily_limit_usd": "1.00",
            "spent_usd": "0.25",
            "reservations": {
                "private-request-a": {
                    "reserved_usd": "0.10",
                    "state": "active",
                },
                "private-request-b": {
                    "reserved_usd": "0.20",
                    "state": "uncertain",
                },
            },
        }
        recorded, limit, counts = reconcile.validate_ledger(
            payload,
            today="2026-07-31",
        )
        self.assertEqual(recorded, "2026-07-30")
        self.assertEqual(limit, "1.00")
        self.assertEqual(counts["active"], 1)
        self.assertEqual(counts["uncertain"], 1)

    def test_future_or_invalid_ledger_is_rejected(self) -> None:
        base = {
            "schema_version": 1,
            "date_utc": "2026-08-01",
            "daily_limit_usd": "1.00",
            "spent_usd": "0",
            "reservations": {},
        }
        with self.assertRaises(reconcile.ReconciliationRejected):
            reconcile.validate_ledger(base, today="2026-07-31")
        invalid = dict(base)
        invalid["date_utc"] = "2026-07-30"
        invalid["reservations"] = {
            "request": {"reserved_usd": "-1", "state": "active"}
        }
        with self.assertRaises(reconcile.ReconciliationRejected):
            reconcile.validate_ledger(invalid, today="2026-07-31")

    def test_current_ledger_resets_only_daily_state(self) -> None:
        rendered = json.loads(
            reconcile.render_current_ledger(
                today="2026-07-31",
                daily_limit_usd="1.00",
            )
        )
        self.assertEqual(
            rendered,
            {
                "schema_version": 1,
                "date_utc": "2026-07-31",
                "daily_limit_usd": "1.00",
                "spent_usd": "0",
                "reservations": {},
            },
        )

    def test_reconcile_archives_exact_bytes_and_is_idempotent(self) -> None:
        original_paths = (
            reconcile.LEDGER,
            reconcile.ARCHIVE_ROOT,
            reconcile.RECEIPT_ROOT,
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            reconcile.LEDGER = root / "deepseek.json"
            reconcile.ARCHIVE_ROOT = root / "archive"
            reconcile.RECEIPT_ROOT = root / "rollover-receipts"
            try:
                yesterday = (
                    datetime.now(timezone.utc).date() - timedelta(days=1)
                ).isoformat()
                stale = {
                    "schema_version": 1,
                    "date_utc": yesterday,
                    "daily_limit_usd": "1.00",
                    "spent_usd": "0.25",
                    "reservations": {
                        "private-request-a": {
                            "reserved_usd": "0.10",
                            "state": "active",
                        },
                        "private-request-b": {
                            "reserved_usd": "0.20",
                            "state": "uncertain",
                        },
                    },
                }
                original = (
                    json.dumps(stale, sort_keys=True, separators=(",", ":"))
                    + "\n"
                ).encode("utf-8")
                reconcile.LEDGER.write_bytes(original)
                reconcile.LEDGER.chmod(0o600)

                result = reconcile.reconcile()
                self.assertEqual(result["status"], "RECONCILED")
                self.assertTrue(result["rollback_bytes_preserved"])
                current = json.loads(reconcile.LEDGER.read_text())
                self.assertEqual(
                    current["date_utc"],
                    datetime.now(timezone.utc).date().isoformat(),
                )
                self.assertEqual(current["reservations"], {})
                archives = list(reconcile.ARCHIVE_ROOT.glob("*.json"))
                receipts = list(reconcile.RECEIPT_ROOT.glob("*.json"))
                self.assertEqual(len(archives), 1)
                self.assertEqual(len(receipts), 1)
                self.assertEqual(archives[0].read_bytes(), original)
                receipt = json.loads(receipts[0].read_text())
                self.assertFalse(receipt["raw_ids_recorded"])
                self.assertFalse(receipt["amounts_recorded"])

                again = reconcile.reconcile()
                self.assertEqual(again["status"], "ALREADY_CURRENT")
                self.assertEqual(len(list(reconcile.ARCHIVE_ROOT.glob("*.json"))), 1)
                self.assertEqual(
                    len(list(reconcile.RECEIPT_ROOT.glob("*.json"))),
                    1,
                )
            finally:
                (
                    reconcile.LEDGER,
                    reconcile.ARCHIVE_ROOT,
                    reconcile.RECEIPT_ROOT,
                ) = original_paths

    def test_receipt_is_content_free_and_archive_is_retained(self) -> None:
        source = (
            ROOT / "scripts/reconcile_stale_provider_budget_v1.py"
        ).read_text(encoding="utf-8")
        self.assertIn('"raw_ids_recorded": False', source)
        self.assertIn('"amounts_recorded": False', source)
        self.assertIn("archive.read_bytes() != original", source)
        self.assertIn("rollback_bytes_preserved", source)
        self.assertNotIn("reservation_id", source.split("receipt = {", 1)[1])

    def test_scope_excludes_restart_network_and_audit_health(self) -> None:
        source = (
            ROOT / "scripts/reconcile_stale_provider_budget_v1.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "systemctl",
            "docker",
            "/healthz",
            "/readyz",
            "subprocess",
            "shutil.rmtree",
            "archive.unlink",
            "LEDGER.unlink",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("fcntl.flock", source)
        self.assertIn("os.replace", source)
        self.assertIn('SERVICE_USER = "myuna"', source)


if __name__ == "__main__":
    unittest.main()
