from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest

from myuna_core.degradation_bridge import (
    CoreFailureCode,
    CoreFailureObservation,
    core_failure_code_for_http_error,
    core_failure_code_for_provider,
    failure_envelope_from_core,
    project_core_failure,
)
from myuna_core.degradation_protocol import (
    SAFE_DEGRADATION_SCHEMA,
    SafeDegradationProjection,
)
from myuna_core.natural_degradation import RecoveryState, natural_degradation_text


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 7, 22, 12, 0, tzinfo=timezone(timedelta(hours=8)))


def observation(code: CoreFailureCode) -> CoreFailureObservation:
    return CoreFailureObservation(
        event_id="event-001",
        correlation_id="correlation-001",
        code=code,
        first_seen_at=NOW,
        last_seen_at=NOW,
    )


class DegradationBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.golden = json.loads(
            (ROOT / "fixtures/natural_degradation_r2a_core_bridge_golden.json").read_text(
                encoding="utf-8"
            )
        )

    def test_all_core_failure_profiles_match_golden(self) -> None:
        seen: set[CoreFailureCode] = set()
        for case in self.golden["cases"]:
            code = CoreFailureCode(case["code"])
            with self.subTest(code=code.value):
                envelope = failure_envelope_from_core(observation(code))
                self.assertEqual(envelope.category.value, case["category"])
                self.assertEqual(envelope.safe_detail_code, case["detail"])
                self.assertEqual(envelope.retryable, case["retryable"])
                self.assertEqual(
                    envelope.owner_action_required,
                    case["owner_action_required"],
                )
                seen.add(code)
        self.assertEqual(seen, set(CoreFailureCode))

    def test_known_provider_codes_map_without_importing_provider_exceptions(self) -> None:
        expected = {
            "transport_failure": CoreFailureCode.PROVIDER_TRANSPORT_FAILURE,
            "rate_limited": CoreFailureCode.PROVIDER_RATE_LIMITED,
            "upstream_server_error": CoreFailureCode.PROVIDER_UPSTREAM_FAILURE,
            "upstream_overloaded": CoreFailureCode.PROVIDER_UPSTREAM_FAILURE,
            "upstream_http_error": CoreFailureCode.PROVIDER_UPSTREAM_FAILURE,
            "invalid_response": CoreFailureCode.PROVIDER_INVALID_RESPONSE,
            "invalid_request": CoreFailureCode.PROVIDER_REQUEST_REJECTED,
            "invalid_parameters": CoreFailureCode.PROVIDER_REQUEST_REJECTED,
            "authentication_failed": CoreFailureCode.PROVIDER_AUTHENTICATION_FAILED,
            "insufficient_balance": CoreFailureCode.PROVIDER_INSUFFICIENT_BALANCE,
            "local_timeout": CoreFailureCode.LOCAL_PROVIDER_TIMEOUT,
            "local_busy": CoreFailureCode.LOCAL_PROVIDER_BUSY,
            "model_unavailable": CoreFailureCode.LOCAL_MODEL_NOT_READY,
            "local_unavailable": CoreFailureCode.LOCAL_PROVIDER_UNAVAILABLE,
            "local_server_error": CoreFailureCode.LOCAL_PROVIDER_UNAVAILABLE,
            "local_http_error": CoreFailureCode.LOCAL_PROVIDER_HTTP_REJECTED,
            "endpoint_redirect_forbidden": (
                CoreFailureCode.LOCAL_PROVIDER_ENDPOINT_REJECTED
            ),
        }
        for provider_code, core_code in expected.items():
            with self.subTest(provider_code=provider_code):
                self.assertEqual(core_failure_code_for_provider(provider_code), core_code)

    def test_unknown_provider_code_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            core_failure_code_for_provider("free-form-upstream-message")

    def test_current_http_error_codes_have_explicit_profiles(self) -> None:
        expected = {
            "runtime_not_activated": CoreFailureCode.CORE_RUNTIME_NOT_READY,
            "provider_daily_budget_exceeded": CoreFailureCode.PROVIDER_DAILY_BUDGET_EXCEEDED,
            "provider_budget_accounting_unavailable": (
                CoreFailureCode.PROVIDER_BUDGET_ACCOUNTING_FAILED
            ),
            "provider_unavailable": CoreFailureCode.PROVIDER_UPSTREAM_FAILURE,
            "reply_failed_runtime_guard": CoreFailureCode.REPLY_RUNTIME_GUARD_REJECTED,
            "runtime_fail_closed": CoreFailureCode.CORE_RUNTIME_FAIL_CLOSED,
            "internal_error": CoreFailureCode.CORE_RUNTIME_FAIL_CLOSED,
        }
        for error_code, core_code in expected.items():
            with self.subTest(error_code=error_code):
                self.assertEqual(core_failure_code_for_http_error(error_code), core_code)

    def test_projection_round_trip_has_exact_bounded_schema(self) -> None:
        projection = project_core_failure(
            observation(CoreFailureCode.PROVIDER_TRANSPORT_FAILURE)
        )
        payload = projection.as_payload()
        self.assertEqual(payload["schema"], SAFE_DEGRADATION_SCHEMA)
        self.assertEqual(payload["status"], "degraded")
        self.assertEqual(
            payload["reply"],
            natural_degradation_text(projection.category),
        )
        self.assertEqual(SafeDegradationProjection.from_payload(payload), projection)

    def test_projection_does_not_expose_event_or_correlation_identifiers(self) -> None:
        payload = project_core_failure(
            observation(CoreFailureCode.REPLY_CONTRACT_REJECTED)
        ).as_payload()
        self.assertNotIn("event_id", payload)
        self.assertNotIn("correlation_id", payload)
        self.assertNotIn("confirmed_facts", payload)
        self.assertNotIn("unknown_facts", payload)
        self.assertNotIn("component", payload)

    def test_projection_rejects_tampered_or_free_form_reply(self) -> None:
        payload = project_core_failure(
            observation(CoreFailureCode.PROVIDER_RATE_LIMITED)
        ).as_payload()
        payload["reply"] = "upstream raw message or model-generated explanation"
        with self.assertRaises(ValueError):
            SafeDegradationProjection.from_payload(payload)

    def test_projection_rejects_extra_fields_and_integer_booleans(self) -> None:
        payload = project_core_failure(
            observation(CoreFailureCode.CORE_RUNTIME_FAIL_CLOSED)
        ).as_payload()
        with_extra = {**payload, "raw_log": "forbidden"}
        with self.assertRaises(ValueError):
            SafeDegradationProjection.from_payload(with_extra)
        payload["retryable"] = 1
        with self.assertRaises(TypeError):
            SafeDegradationProjection.from_payload(payload)

    def test_observation_requires_aware_ordered_times_and_safe_ids(self) -> None:
        with self.assertRaises(ValueError):
            CoreFailureObservation(
                event_id="unsafe event id",
                correlation_id="correlation-001",
                code=CoreFailureCode.CORE_RUNTIME_FAIL_CLOSED,
                first_seen_at=NOW,
                last_seen_at=NOW,
            )
        with self.assertRaises(ValueError):
            CoreFailureObservation(
                event_id="event-001",
                correlation_id="correlation-001",
                code=CoreFailureCode.CORE_RUNTIME_FAIL_CLOSED,
                first_seen_at=NOW,
                last_seen_at=NOW - timedelta(seconds=1),
            )

    def test_fingerprint_is_stable_across_event_instances(self) -> None:
        first = project_core_failure(observation(CoreFailureCode.PROVIDER_RATE_LIMITED))
        second = project_core_failure(
            CoreFailureObservation(
                event_id="event-002",
                correlation_id="correlation-002",
                code=CoreFailureCode.PROVIDER_RATE_LIMITED,
                first_seen_at=NOW + timedelta(minutes=1),
                last_seen_at=NOW + timedelta(minutes=1),
                occurrence_count=2,
                recovery_state=RecoveryState.ACTIVE,
            )
        )
        self.assertEqual(first.fingerprint, second.fingerprint)


if __name__ == "__main__":
    unittest.main()
