from __future__ import annotations

import json
import unittest
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from myuna_core.audit import AuditLogger
from myuna_core.providers import ModelRequest, ProviderError
from myuna_core.providers.budget import worst_case_cost_usd
from myuna_core.providers.registry import get_model_spec
from myuna_core.providers.runtime import (
    build_deepseek_runtime_provider,
    load_deepseek_runtime_settings,
)
from myuna_core.providers.transport import TransportFailure

from test_provider_deepseek import FakeTransport


class ProviderRuntimeTests(unittest.TestCase):
    def test_safe_defaults_use_current_flash_model_and_one_dollar_gate(self) -> None:
        settings = load_deepseek_runtime_settings({})
        self.assertEqual(settings.model, "deepseek-v4-flash")
        self.assertEqual(settings.daily_budget_usd, Decimal("1.00"))
        self.assertEqual(settings.max_attempts, 1)
        self.assertFalse(settings.live_calls_enabled)

    def test_reviewed_legacy_attempt_values_are_clamped_to_one(self) -> None:
        for configured_attempts in (1, 2, 3):
            with self.subTest(configured_attempts=configured_attempts):
                settings = load_deepseek_runtime_settings(
                    {"MYUNA_DEEPSEEK_MAX_ATTEMPTS": str(configured_attempts)}
                )
                self.assertEqual(settings.max_attempts, 1)

    def test_runtime_settings_reject_old_alias_and_unbounded_values(self) -> None:
        with self.assertRaises(ValueError):
            load_deepseek_runtime_settings({"MYUNA_DEEPSEEK_MODEL": "deepseek-chat"})
        with self.assertRaises(ValueError):
            load_deepseek_runtime_settings({"MYUNA_DEEPSEEK_DAILY_BUDGET_USD": "1000"})
        with self.assertRaises(ValueError):
            load_deepseek_runtime_settings({"MYUNA_DEEPSEEK_MAX_ATTEMPTS": "9"})
        with self.assertRaises(ValueError):
            load_deepseek_runtime_settings({"MYUNA_PROVIDER_LIVE_CALLS_ENABLED": "yes"})

    def test_runtime_factory_stops_before_credential_lookup_when_live_calls_are_off(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaisesRegex(RuntimeError, "live provider calls are disabled"):
                build_deepseek_runtime_provider(
                    data_dir=root / "data",
                    audit=AuditLogger(root / "logs", "dev"),
                    environ={},
                )

    def test_runtime_provider_never_retries_and_reserves_one_attempt(self) -> None:
        request = ModelRequest(
            request_id="runtime-single-attempt",
            messages=({"role": "user", "content": "synthetic prompt"},),
            max_output_tokens=100,
            route_reason="normal_chat",
        )
        transport = FakeTransport(
            [TransportFailure("synthetic failure"), AssertionError("second call attempted")]
        )
        environ = {
            "MYUNA_PROVIDER_LIVE_CALLS_ENABLED": "true",
            "MYUNA_DEEPSEEK_MAX_ATTEMPTS": "3",
        }

        with TemporaryDirectory() as temp:
            root = Path(temp)
            audit = AuditLogger(root / "logs", "dev")
            with (
                patch(
                    "myuna_core.providers.runtime.load_systemd_credential",
                    return_value="mock-secret-key",
                ),
                patch(
                    "myuna_core.providers.deepseek.UrllibJsonTransport",
                    return_value=transport,
                ),
            ):
                provider = build_deepseek_runtime_provider(
                    data_dir=root / "data",
                    audit=audit,
                    environ=environ,
                )
                self.assertEqual(provider.max_attempts, 1)
                with self.assertRaises(ProviderError) as caught:
                    provider.generate(request)

            self.assertEqual(caught.exception.attempts, 1)
            self.assertEqual(len(transport.calls), 1)
            records = [json.loads(line) for line in audit.path.read_text().splitlines()]
            expected_reservation = worst_case_cost_usd(
                get_model_spec("deepseek-v4-flash"), request
            )
            self.assertEqual(
                records[0]["details"]["reserved_usd"], str(expected_reservation)
            )


if __name__ == "__main__":
    unittest.main()
