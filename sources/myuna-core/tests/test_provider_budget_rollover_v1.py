from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest

from myuna_core.providers import BudgetAccountingError, DailyBudgetLedger


UTC = timezone.utc
DAY_ONE = datetime(2026, 7, 30, 23, 59, 59, tzinfo=UTC)
DAY_TWO = datetime(2026, 7, 31, 0, 0, 0, tzinfo=UTC)
DAY_THREE = datetime(2026, 8, 1, 0, 0, 0, tzinfo=UTC)


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class SimulatedCrash(RuntimeError):
    pass


class ProviderBudgetRolloverTests(unittest.TestCase):
    def ledger(
        self,
        path: Path,
        clock: MutableClock,
        *,
        failpoint=None,
    ) -> DailyBudgetLedger:
        return DailyBudgetLedger(
            path,
            daily_limit_usd=Decimal("2.00"),
            clock=clock,
            failpoint=failpoint,
        )

    def seed_unresolved(self, ledger: DailyBudgetLedger) -> None:
        ledger.reserve("synthetic:active", Decimal("0.20"))
        ledger.reserve("synthetic:uncertain", Decimal("0.30"))
        ledger.mark_uncertain(
            "synthetic:uncertain",
            reason="transport_failure",
        )
        ledger.reserve("synthetic:completed", Decimal("0.40"))
        ledger.settle("synthetic:completed", Decimal("0.10"))

    def test_exact_utc_boundary_archives_unresolved_and_opens_new_day(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "deepseek.json"
            clock = MutableClock(DAY_ONE)
            ledger = self.ledger(path, clock)
            self.seed_unresolved(ledger)
            original = path.read_bytes()

            clock.value = DAY_TWO
            ledger.reserve("synthetic:new-day", Decimal("0.05"))
            current = ledger.snapshot()

            self.assertEqual(current["date_utc"], "2026-07-31")
            self.assertEqual(current["daily_limit_usd"], "2.00")
            self.assertEqual(current["spent_usd"], "0")
            self.assertEqual(set(current["reservations"]), {"synthetic:new-day"})
            rollover = current["rollover"]
            self.assertEqual(rollover["reservation_active"], 1)
            self.assertEqual(rollover["reservation_uncertain"], 1)
            self.assertEqual(
                rollover["archive_sha256"],
                hashlib.sha256(original).hexdigest(),
            )

            archives = list(ledger.archive_root.glob("*.json"))
            receipts = list(ledger.receipt_root.glob("*.json"))
            self.assertEqual(len(archives), 1)
            self.assertEqual(len(receipts), 1)
            self.assertEqual(archives[0].read_bytes(), original)
            receipt = receipts[0].read_text(encoding="utf-8")
            rollover_text = json.dumps(rollover, sort_keys=True)
            for forbidden in (
                "synthetic:active",
                "synthetic:uncertain",
                "synthetic:completed",
                "0.20",
                "0.30",
                "0.40",
                "0.10",
            ):
                self.assertNotIn(forbidden, receipt)
                self.assertNotIn(forbidden, rollover_text)

    def test_transaction_captures_the_authoritative_clock_once(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "deepseek.json"
            initial_clock = MutableClock(DAY_ONE)
            self.ledger(path, initial_clock).reserve(
                "synthetic:stale",
                Decimal("0.10"),
            )
            calls = 0

            def advancing_clock() -> datetime:
                nonlocal calls
                calls += 1
                return DAY_TWO if calls == 1 else DAY_THREE

            ledger = DailyBudgetLedger(
                path,
                daily_limit_usd=Decimal("2.00"),
                clock=advancing_clock,
            )
            current = ledger.snapshot()

            self.assertEqual(calls, 1)
            self.assertEqual(current["date_utc"], "2026-07-31")
            self.assertEqual(current["rollover"]["current_date_utc"], "2026-07-31")

    def test_late_settlement_preserves_immutable_unresolved_archive(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "deepseek.json"
            clock = MutableClock(DAY_ONE)
            ledger = self.ledger(path, clock)
            ledger.reserve("synthetic:late", Decimal("0.25"))
            original = path.read_bytes()
            clock.value = DAY_TWO
            ledger.snapshot()
            archive = next(ledger.archive_root.glob("*.json"))
            archived = archive.read_bytes()

            with self.assertRaises(BudgetAccountingError):
                ledger.settle("synthetic:late", Decimal("0.10"))

            self.assertEqual(archived, original)
            self.assertEqual(archive.read_bytes(), archived)
            self.assertNotIn("synthetic:late", ledger.snapshot()["reservations"])

    def test_current_ledger_is_idempotent_without_rollover_artifacts(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "deepseek.json"
            ledger = self.ledger(path, MutableClock(DAY_TWO))

            first = ledger.snapshot()
            first_bytes = path.read_bytes()
            second = ledger.snapshot()

            self.assertEqual(first, second)
            self.assertEqual(path.read_bytes(), first_bytes)
            self.assertNotIn("rollover", first)
            self.assertFalse(ledger.archive_root.exists())
            self.assertFalse(ledger.receipt_root.exists())

    def test_multi_day_rollover_retains_auditable_chain(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "deepseek.json"
            clock = MutableClock(DAY_ONE)
            ledger = self.ledger(path, clock)
            ledger.reserve("synthetic:day-one", Decimal("0.20"))

            clock.value = DAY_TWO
            ledger.reserve("synthetic:day-two", Decimal("0.20"))
            ledger.settle("synthetic:day-two", Decimal("0.10"))
            day_two_bytes = path.read_bytes()

            clock.value = DAY_THREE
            day_three = ledger.snapshot()

            self.assertEqual(day_three["date_utc"], "2026-08-01")
            self.assertEqual(day_three["spent_usd"], "0")
            self.assertEqual(day_three["reservations"], {})
            self.assertEqual(len(list(ledger.archive_root.glob("*.json"))), 2)
            self.assertEqual(len(list(ledger.receipt_root.glob("*.json"))), 2)
            day_two_archive = (
                ledger.archive_root / day_three["rollover"]["archive_file"]
            )
            self.assertEqual(day_two_archive.read_bytes(), day_two_bytes)

    def test_corrupt_partial_unknown_cap_and_clock_regression_fail_closed(self) -> None:
        cases = {
            "corrupt": b"{",
            "partial": self.payload_bytes(
                {
                    "schema_version": 1,
                    "date_utc": "2026-07-31",
                    "daily_limit_usd": "2.00",
                    "spent_usd": "0",
                }
            ),
            "unknown": self.payload_bytes(
                {
                    **self.valid_payload("2026-07-31"),
                    "unknown": "field",
                }
            ),
            "schema": self.payload_bytes(
                {
                    **self.valid_payload("2026-07-31"),
                    "schema_version": 2,
                }
            ),
            "cap": self.payload_bytes(
                {
                    **self.valid_payload("2026-07-31"),
                    "daily_limit_usd": "1.99",
                }
            ),
            "clock-regression": self.payload_bytes(
                self.valid_payload("2026-08-01")
            ),
        }
        for label, payload in cases.items():
            with self.subTest(label=label), TemporaryDirectory() as temp:
                path = Path(temp) / "deepseek.json"
                path.write_bytes(payload)
                path.chmod(0o600)
                ledger = self.ledger(path, MutableClock(DAY_TWO))

                with self.assertRaises(BudgetAccountingError):
                    ledger.snapshot()

                self.assertEqual(path.read_bytes(), payload)
                self.assertFalse(ledger.archive_root.exists())
                self.assertFalse(ledger.receipt_root.exists())

    def test_naive_clock_fails_before_ledger_creation(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "deepseek.json"
            ledger = DailyBudgetLedger(
                path,
                daily_limit_usd=Decimal("2.00"),
                clock=lambda: datetime(2026, 7, 31, 0, 0, 0),
            )

            with self.assertRaises(BudgetAccountingError):
                ledger.snapshot()

            self.assertFalse(path.exists())
            self.assertFalse(ledger.archive_root.exists())

    def test_symlinked_lock_is_reported_as_budget_accounting_error(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "deepseek.json"
            target = Path(temp) / "synthetic-target"
            target.write_text("synthetic\n", encoding="utf-8")
            path.with_suffix(".json.lock").symlink_to(target)
            ledger = self.ledger(path, MutableClock(DAY_TWO))

            with self.assertRaises(BudgetAccountingError):
                ledger.snapshot()

            self.assertFalse(path.exists())
            self.assertEqual(target.read_text(encoding="utf-8"), "synthetic\n")

    def test_concurrent_first_requests_publish_one_archive_and_receipt(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "deepseek.json"
            clock = MutableClock(DAY_ONE)
            initial = self.ledger(path, clock)
            initial.reserve("synthetic:stale", Decimal("0.10"))
            original = path.read_bytes()
            clock.value = DAY_TWO
            barrier = threading.Barrier(8)
            errors: list[BaseException] = []

            def reserve(index: int) -> None:
                try:
                    candidate = self.ledger(path, clock)
                    barrier.wait(timeout=5)
                    candidate.reserve(
                        f"synthetic:concurrent:{index}",
                        Decimal("0.10"),
                    )
                except BaseException as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=reserve, args=(index,)) for index in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(errors, [])

            current = self.ledger(path, clock).snapshot()
            self.assertEqual(len(current["reservations"]), 8)
            archives = list(initial.archive_root.glob("*.json"))
            receipts = list(initial.receipt_root.glob("*.json"))
            self.assertEqual(len(archives), 1)
            self.assertEqual(len(receipts), 1)
            self.assertEqual(archives[0].read_bytes(), original)

    def test_concurrent_first_use_creates_private_parent_without_race(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "new-parent" / "deepseek.json"
            clock = MutableClock(DAY_TWO)
            barrier = threading.Barrier(8)
            errors: list[BaseException] = []

            def snapshot() -> None:
                try:
                    candidate = self.ledger(path, clock)
                    barrier.wait(timeout=5)
                    candidate.snapshot()
                except BaseException as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=snapshot) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)

            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(errors, [])
            self.assertEqual(
                self.ledger(path, clock).snapshot()["date_utc"],
                "2026-07-31",
            )

    def test_crash_after_archive_reuses_exact_archive_on_retry(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "deepseek.json"
            clock = MutableClock(DAY_ONE)
            initial = self.ledger(path, clock)
            initial.reserve("synthetic:stale", Decimal("0.20"))
            original = path.read_bytes()
            clock.value = DAY_TWO
            crashing = self.ledger(
                path,
                clock,
                failpoint=self.crash_at("rollover.after_archive"),
            )

            with self.assertRaises(SimulatedCrash):
                crashing.snapshot()

            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(len(list(initial.archive_root.glob("*.json"))), 1)
            self.assertFalse(initial.receipt_root.exists())
            recovered = self.ledger(path, clock).snapshot()
            self.assertEqual(recovered["date_utc"], "2026-07-31")
            self.assertEqual(len(list(initial.archive_root.glob("*.json"))), 1)
            self.assertEqual(len(list(initial.receipt_root.glob("*.json"))), 1)

    def test_crash_after_ledger_replace_recovers_missing_receipt(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "deepseek.json"
            clock = MutableClock(DAY_ONE)
            initial = self.ledger(path, clock)
            initial.reserve("synthetic:stale", Decimal("0.20"))
            clock.value = DAY_TWO
            crashing = self.ledger(
                path,
                clock,
                failpoint=self.crash_at("rollover.after_ledger_replace"),
            )

            with self.assertRaises(SimulatedCrash):
                crashing.snapshot()

            replaced = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(replaced["date_utc"], "2026-07-31")
            self.assertFalse(initial.receipt_root.exists())
            recovered = self.ledger(path, clock).snapshot()
            self.assertEqual(recovered, replaced)
            self.assertEqual(len(list(initial.archive_root.glob("*.json"))), 1)
            self.assertEqual(len(list(initial.receipt_root.glob("*.json"))), 1)

    def test_drifted_recovery_receipt_is_rejected(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "deepseek.json"
            clock = MutableClock(DAY_ONE)
            initial = self.ledger(path, clock)
            initial.reserve("synthetic:stale", Decimal("0.20"))
            clock.value = DAY_TWO
            crashing = self.ledger(
                path,
                clock,
                failpoint=self.crash_at("rollover.after_ledger_replace"),
            )
            with self.assertRaises(SimulatedCrash):
                crashing.snapshot()
            replaced = path.read_bytes()
            rollover = json.loads(replaced)["rollover"]
            initial.receipt_root.mkdir(mode=0o700)
            receipt = initial.receipt_root / rollover["receipt_file"]
            receipt.write_bytes(b"drifted\n")
            receipt.chmod(0o600)

            with self.assertRaises(BudgetAccountingError):
                self.ledger(path, clock).snapshot()

            self.assertEqual(path.read_bytes(), replaced)
            self.assertEqual(receipt.read_bytes(), b"drifted\n")

    def test_crash_after_receipt_is_already_idempotently_complete(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "deepseek.json"
            clock = MutableClock(DAY_ONE)
            initial = self.ledger(path, clock)
            initial.reserve("synthetic:stale", Decimal("0.20"))
            clock.value = DAY_TWO
            crashing = self.ledger(
                path,
                clock,
                failpoint=self.crash_at("rollover.after_receipt"),
            )

            with self.assertRaises(SimulatedCrash):
                crashing.snapshot()

            before = path.read_bytes()
            recovered = self.ledger(path, clock).snapshot()
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(recovered["date_utc"], "2026-07-31")
            self.assertEqual(len(list(initial.archive_root.glob("*.json"))), 1)
            self.assertEqual(len(list(initial.receipt_root.glob("*.json"))), 1)

    def test_drifted_archive_is_rejected_without_replacing_stale_ledger(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "deepseek.json"
            clock = MutableClock(DAY_ONE)
            initial = self.ledger(path, clock)
            initial.reserve("synthetic:stale", Decimal("0.20"))
            original = path.read_bytes()
            clock.value = DAY_TWO
            crashing = self.ledger(
                path,
                clock,
                failpoint=self.crash_at("rollover.after_archive"),
            )
            with self.assertRaises(SimulatedCrash):
                crashing.snapshot()
            archive = next(initial.archive_root.glob("*.json"))
            archive.write_bytes(b"drifted\n")
            archive.chmod(0o600)

            with self.assertRaises(BudgetAccountingError):
                self.ledger(path, clock).snapshot()

            self.assertEqual(path.read_bytes(), original)

    @staticmethod
    def crash_at(expected: str):
        def failpoint(name: str) -> None:
            if name == expected:
                raise SimulatedCrash(name)

        return failpoint

    @staticmethod
    def valid_payload(date_utc: str) -> dict[str, object]:
        return {
            "schema_version": 1,
            "date_utc": date_utc,
            "daily_limit_usd": "2.00",
            "spent_usd": "0",
            "reservations": {},
        }

    @staticmethod
    def payload_bytes(payload: dict[str, object]) -> bytes:
        return (
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
