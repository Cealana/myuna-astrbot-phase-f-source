from __future__ import annotations

from decimal import Decimal
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
import json
import stat
import unittest

from myuna_core.audit import AuditLogger
from myuna_core.providers import (
    AuditedBudgetedProvider,
    BudgetAccountingError,
    BudgetExceededError,
    DailyBudgetLedger,
    DeepSeekProvider,
    ModelRequest,
    ProviderError,
)
from myuna_core.providers.registry import get_model_spec
from myuna_core.providers.transport import TransportFailure, TransportResponse

from test_provider_deepseek import FakeTransport, successful_response


class ProviderBudgetAndAuditTests(unittest.TestCase):
    def request(self, request_id: str = "budget-1") -> ModelRequest:
        return ModelRequest(
            request_id=request_id,
            messages=({"role": "user", "content": "private prompt text"},),
            max_output_tokens=100,
            route_reason="normal_chat",
        )

    def test_budget_reservation_settlement_and_permissions(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "private" / "budget.json"
            ledger = DailyBudgetLedger(path, daily_limit_usd=Decimal("1.00"))
            ledger.reserve("request:one", Decimal("0.40"))
            ledger.settle("request:one", Decimal("0.25"))
            snapshot = ledger.snapshot()
            self.assertEqual(snapshot["spent_usd"], "0.25")
            self.assertEqual(snapshot["reservations"], {})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    def test_budget_rejects_a_reservation_above_remaining_limit(self) -> None:
        with TemporaryDirectory() as temp:
            ledger = DailyBudgetLedger(
                Path(temp) / "budget.json",
                daily_limit_usd=Decimal("0.50"),
            )
            ledger.reserve("request:one", Decimal("0.40"))
            with self.assertRaises(BudgetExceededError):
                ledger.reserve("request:two", Decimal("0.11"))

    def test_prior_day_uncertain_reservation_rolls_over_with_exact_archive(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "budget.json"
            ledger = DailyBudgetLedger(path, daily_limit_usd=Decimal("1.00"))
            ledger.reserve("request:uncertain", Decimal("0.40"))
            ledger.mark_uncertain("request:uncertain", reason="transport_failure")
            state = json.loads(path.read_text(encoding="utf-8"))
            state["date_utc"] = (
                datetime.now(timezone.utc).date() - timedelta(days=1)
            ).isoformat()
            path.write_text(json.dumps(state), encoding="utf-8")
            path.chmod(0o600)
            original = path.read_bytes()
            snapshot = ledger.snapshot()
            self.assertEqual(snapshot["reservations"], {})
            self.assertEqual(snapshot["rollover"]["reservation_uncertain"], 1)
            archives = list((path.parent / "archive").glob("*.json"))
            self.assertEqual(len(archives), 1)
            self.assertEqual(archives[0].read_bytes(), original)

    def test_success_audit_contains_metrics_but_no_content_or_secret(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            transport = FakeTransport([successful_response()])
            raw = DeepSeekProvider(
                api_key="mock-secret-key",
                default_model="deepseek-v4-flash",
                transport=transport,
                max_attempts=2,
                sleep=lambda _: None,
            )
            ledger = DailyBudgetLedger(
                root / "data" / "budget.json",
                daily_limit_usd=Decimal("1.00"),
            )
            audit = AuditLogger(root / "logs", "dev")
            provider = AuditedBudgetedProvider(raw, budget=ledger, audit=audit)
            response = provider.generate(self.request())

            self.assertGreater(response.cost_usd or Decimal(0), Decimal(0))
            records = [json.loads(line) for line in audit.path.read_text().splitlines()]
            self.assertEqual([record["event"] for record in records], [
                "provider.request",
                "provider.response",
            ])
            serialized = audit.path.read_text(encoding="utf-8")
            for forbidden in (
                "private prompt text",
                "mock answer",
                "must never be retained",
                "mock-secret-key",
            ):
                self.assertNotIn(forbidden, serialized)
            details = records[-1]["details"]
            self.assertEqual(details["input_tokens"], 100)
            self.assertEqual(details["route_reason"], "normal_chat")
            self.assertIn("actual_cost_usd", details)
            self.assertEqual(ledger.snapshot()["reservations"], {})

    def test_uncertain_transport_failure_keeps_fail_closed_reservation(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            raw = DeepSeekProvider(
                api_key="mock-secret-key",
                default_model="deepseek-v4-flash",
                transport=FakeTransport([TransportFailure("details")]),
                max_attempts=1,
            )
            ledger = DailyBudgetLedger(
                root / "budget.json",
                daily_limit_usd=Decimal("1.00"),
            )
            provider = AuditedBudgetedProvider(
                raw,
                budget=ledger,
                audit=AuditLogger(root / "logs", "dev"),
            )
            with self.assertRaises(ProviderError):
                provider.generate(self.request("uncertain-1"))
            reservation = ledger.snapshot()["reservations"]["provider:uncertain-1"]
            self.assertEqual(reservation["state"], "uncertain")
            self.assertEqual(reservation["reason"], "transport_failure")

    def test_accounting_failure_audit_is_fixed_and_content_free(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "budget.json"
            path.write_text("{", encoding="utf-8")
            path.chmod(0o600)
            raw = DeepSeekProvider(
                api_key="mock-secret-key",
                default_model="deepseek-v4-flash",
                transport=FakeTransport([successful_response()]),
                max_attempts=1,
            )
            audit = AuditLogger(root / "logs", "dev")
            provider = AuditedBudgetedProvider(
                raw,
                budget=DailyBudgetLedger(
                    path,
                    daily_limit_usd=Decimal("1.00"),
                ),
                audit=audit,
            )
            with self.assertRaises(BudgetAccountingError):
                provider.generate(self.request("accounting-failure"))
            records = [
                json.loads(line)
                for line in audit.path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["event"], "provider.budget_accounting")
            self.assertEqual(
                records[0]["details"],
                {
                    "classification": "provider_budget_accounting_failed",
                    "stage": "reserve",
                },
            )
            serialized = audit.path.read_text(encoding="utf-8")
            self.assertNotIn(str(path), serialized)
            self.assertNotIn("mock-secret-key", serialized)

    def test_registry_has_only_current_reviewed_models_and_pricing(self) -> None:
        flash = get_model_spec("deepseek-v4-flash")
        pro = get_model_spec("deepseek-v4-pro")
        self.assertEqual(flash.pricing.cache_miss_input_per_million_usd, Decimal("0.14"))
        self.assertEqual(pro.pricing.output_per_million_usd, Decimal("0.87"))
        with self.assertRaises(ValueError):
            get_model_spec("deepseek-chat")


if __name__ == "__main__":
    unittest.main()
