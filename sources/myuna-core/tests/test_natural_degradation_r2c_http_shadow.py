from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
from threading import Thread
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from myuna_core.audit import AuditLogger
from myuna_core.config import load_settings
from myuna_core.conversation import (
    ConversationGuardError,
    ConversationInputError,
    ConversationPreProviderError,
    ConversationProfileError,
)
from myuna_core.degradation_bridge import CoreFailureCode
from myuna_core.degradation_http import (
    CORE_FAILURE_RESPONSE_SCHEMA,
    attach_core_failure_metadata,
    attach_provider_failure_metadata,
)
from myuna_core.http_api import build_server
from myuna_core.providers import BudgetAccountingError, ProviderError


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 7, 22, 7, 0, tzinfo=timezone.utc)
REQUEST_ID = "11111111-2222-4333-8444-555555555555"


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


def _settings(temp: str):
    return load_settings(
        {
            "MYUNA_ENV": "dev",
            "MYUNA_BIND_HOST": "127.0.0.1",
            "MYUNA_PORT": str(_free_loopback_port()),
            "MYUNA_DATA_DIR": temp,
            "MYUNA_LOG_DIR": temp,
            "MYUNA_DEFINITION_RELEASE": "v5-r2c-test",
            "MYUNA_DEFINITION_PATH": "/unused/release",
            "MYUNA_CAPABILITY_MANIFEST": "/unused/capabilities.json",
            "MYUNA_PROVIDERS_ENABLED": "deepseek",
            "MYUNA_DEV_TOKEN_CREDENTIAL": "myuna_dev_token",
        }
    )


class NaturalDegradationR2CCoreHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.golden = json.loads(
            (
                ROOT / "fixtures/natural_degradation_r2c_core_http_golden.json"
            ).read_text(encoding="utf-8")
        )

    def test_golden_http_failures_have_one_canonical_projection(self) -> None:
        for case in self.golden["cases"]:
            with self.subTest(case=case):
                base: dict[str, object] = {"error": case["error"]}
                if case["error"] == "provider_unavailable":
                    base["retryable"] = case.get(
                        "legacy_retryable",
                        case["retryable"],
                    )
                    payload = attach_provider_failure_metadata(
                        base,
                        request_id=REQUEST_ID,
                        provider_code=case["provider_code"],
                        observed_at=NOW,
                    )
                else:
                    payload = attach_core_failure_metadata(
                        base,
                        request_id=REQUEST_ID,
                        code=CoreFailureCode(case["core_code"]),
                        observed_at=NOW,
                    )
                projection = payload["safe_degradation"]
                self.assertEqual(payload["error"], case["error"])
                self.assertEqual(
                    payload["failure_schema"],
                    CORE_FAILURE_RESPONSE_SCHEMA,
                )
                self.assertEqual(projection["category"], case["category"])
                self.assertEqual(projection["safe_detail_code"], case["detail"])
                self.assertIs(projection["retryable"], case["retryable"])
                self.assertIs(
                    projection["owner_action_required"],
                    case["owner_action_required"],
                )

    def test_unknown_provider_code_fails_closed_without_echoing_it(self) -> None:
        unsafe_code = "secret-upstream-error-and-user-content"
        payload = attach_provider_failure_metadata(
            {"error": "provider_unavailable", "retryable": False},
            request_id=REQUEST_ID,
            provider_code=unsafe_code,
            observed_at=NOW,
        )
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        self.assertEqual(
            payload["safe_degradation"]["safe_detail_code"],
            "core-runtime-fail-closed",
        )
        self.assertNotIn(unsafe_code, encoded)

    def test_projection_omits_request_provider_and_private_content(self) -> None:
        payload = attach_provider_failure_metadata(
            {"error": "provider_unavailable", "retryable": True},
            request_id=REQUEST_ID,
            provider_code="transport_failure",
            observed_at=NOW,
        )
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        for forbidden in (
            REQUEST_ID,
            "message_text",
            "provider_output",
            "prompt",
            "authorization",
            "memory_id",
        ):
            self.assertNotIn(forbidden, encoded)

    def test_provider_http_failure_adds_metadata_but_keeps_legacy_error(self) -> None:
        class Engine:
            def converse(self, payload, *, request_id):
                raise ProviderError(
                    "authentication_failed",
                    "synthetic provider detail that must not escape",
                    retryable=False,
                    status_code=401,
                )

        with TemporaryDirectory() as temp:
            settings = _settings(temp)
            server = build_server(
                settings,
                AuditLogger(Path(temp), "dev"),
                engine=Engine(),
                dev_token="test-token",
            )
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                request = Request(
                    f"http://127.0.0.1:{server.server_address[1]}/v1/chat",
                    data=json.dumps(
                        {"messages": [{"role": "user", "content": "private"}]}
                    ).encode("utf-8"),
                    headers={
                        "Authorization": "Bearer test-token",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                with self.assertRaises(HTTPError) as caught:
                    urlopen(request, timeout=3)
                self.assertEqual(caught.exception.code, 502)
                payload = json.loads(caught.exception.read().decode("utf-8"))
                self.assertEqual(payload["error"], "provider_unavailable")
                self.assertIs(payload["retryable"], False)
                self.assertEqual(
                    payload["safe_degradation"]["safe_detail_code"],
                    "provider-authentication-failed",
                )
                self.assertEqual(payload["failure_provenance"]["stage"], "provider_request")
                self.assertEqual(payload["failure_provenance"]["attempt_count"], 1)
                encoded = json.dumps(payload, ensure_ascii=False)
                self.assertNotIn("synthetic provider detail", encoded)
                self.assertNotIn("private", encoded)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

    def test_hybrid_transport_failure_keeps_provider_typed_provenance(self) -> None:
        class Engine:
            def converse(self, payload, *, request_id):
                raise ProviderError(
                    "transport_failure",
                    "synthetic transport detail that must not escape",
                    retryable=True,
                )

        with TemporaryDirectory() as temp:
            settings = _settings(temp)
            server = build_server(
                settings,
                AuditLogger(Path(temp), "dev"),
                engine=Engine(),
                dev_token="test-token",
            )
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                request = Request(
                    f"http://127.0.0.1:{server.server_address[1]}/v1/chat",
                    data=json.dumps(
                        {"messages": [{"role": "user", "content": "synthetic"}]}
                    ).encode("utf-8"),
                    headers={
                        "Authorization": "Bearer test-token",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                with self.assertRaises(HTTPError) as caught:
                    urlopen(request, timeout=3)
                self.assertEqual(caught.exception.code, 503)
                payload = json.loads(caught.exception.read().decode("utf-8"))
                projection = payload["safe_degradation"]
                self.assertEqual(
                    projection["safe_detail_code"],
                    "provider-transport-failure",
                )
                self.assertEqual(
                    projection["category"],
                    "provider_transient_failure",
                )
                self.assertIs(projection["retryable"], True)
                self.assertEqual(payload["failure_provenance"]["stage"], "provider_request")
                self.assertEqual(
                    payload["failure_provenance"]["provider_outcome_class"],
                    "transport_failure",
                )
                self.assertNotIn("synthetic transport detail", json.dumps(payload))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

    def test_budget_accounting_failure_has_fixed_safe_projection(self) -> None:
        unsafe_detail = (
            "synthetic amount 9.99 reservation private-id "
            "/private/ledger.json fingerprint-secret"
        )

        class Engine:
            def converse(self, payload, *, request_id):
                raise BudgetAccountingError(unsafe_detail)

        with TemporaryDirectory() as temp:
            settings = _settings(temp)
            server = build_server(
                settings,
                AuditLogger(Path(temp), "dev"),
                engine=Engine(),
                dev_token="test-token",
            )
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                request = Request(
                    f"http://127.0.0.1:{server.server_address[1]}/v1/chat",
                    data=json.dumps(
                        {"messages": [{"role": "user", "content": "private"}]}
                    ).encode("utf-8"),
                    headers={
                        "Authorization": "Bearer test-token",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                with self.assertRaises(HTTPError) as caught:
                    urlopen(request, timeout=3)
                self.assertEqual(caught.exception.code, 503)
                payload = json.loads(caught.exception.read().decode("utf-8"))
                self.assertEqual(
                    payload["error"],
                    "provider_budget_accounting_unavailable",
                )
                projection = payload["safe_degradation"]
                self.assertEqual(
                    projection["safe_detail_code"],
                    "provider-budget-accounting-failed",
                )
                self.assertIs(projection["retryable"], False)
                self.assertIs(projection["owner_action_required"], True)
                self.assertEqual(
                    payload["failure_provenance"]["stage"],
                    "core_pre_provider",
                )
                self.assertIs(payload["failure_provenance"]["provider_called"], False)
                channel_reply = projection["reply"]
                for forbidden in (
                    unsafe_detail,
                    "9.99",
                    "private-id",
                    "/private/ledger.json",
                    "fingerprint-secret",
                ):
                    self.assertNotIn(forbidden, channel_reply)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

    def test_request_profile_and_output_failures_have_distinct_http_provenance(self) -> None:
        class RejectingEngine:
            failure: Exception | None = None

            def converse(self, payload, *, request_id):
                if self.failure is None:
                    raise AssertionError("invalid input must not reach engine")
                raise self.failure

        cases = (
            (
                ConversationInputError("synthetic_invalid_request"),
                {"messages": [{"role": "user", "content": "synthetic"}]},
                400,
                "invalid_conversation_request",
                "request_parser",
                "core_request_rejected",
                False,
                False,
            ),
            (
                ConversationProfileError("profile_timeout", retryable=True),
                {"messages": [{"role": "user", "content": "synthetic"}]},
                503,
                "profile_unavailable",
                "profile_projection",
                "owner_memory_read_failed",
                False,
                True,
            ),
            (
                ConversationPreProviderError("projection_character_budget_exceeded"),
                {"messages": [{"role": "user", "content": "synthetic"}]},
                503,
                "runtime_fail_closed",
                "core_pre_provider",
                "projection_character_budget_exceeded",
                False,
                False,
            ),
            (
                ConversationGuardError("synthetic_output_repair_exhausted"),
                {"messages": [{"role": "user", "content": "synthetic"}]},
                502,
                "reply_failed_runtime_guard",
                "output_repair",
                "reply_runtime_guard_rejected",
                True,
                False,
            ),
        )
        for (
            failure,
            request_payload,
            status,
            error,
            stage,
            failure_gate,
            provider_called,
            profile_called,
        ) in cases:
            with self.subTest(stage=stage), TemporaryDirectory() as temp:
                engine = RejectingEngine()
                engine.failure = failure
                settings = _settings(temp)
                server = build_server(
                    settings,
                    AuditLogger(Path(temp), "dev"),
                    engine=engine,
                    dev_token="test-token",
                )
                thread = Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    request = Request(
                        f"http://127.0.0.1:{server.server_address[1]}/v1/chat",
                        data=json.dumps(request_payload).encode("utf-8"),
                        headers={
                            "Authorization": "Bearer test-token",
                            "Content-Type": "application/json",
                        },
                        method="POST",
                    )
                    with self.assertRaises(HTTPError) as caught:
                        urlopen(request, timeout=3)
                    self.assertEqual(caught.exception.code, status)
                    response = json.loads(caught.exception.read().decode("utf-8"))
                    self.assertEqual(response["error"], error)
                    provenance = response["failure_provenance"]
                    self.assertEqual(provenance["stage"], stage)
                    self.assertEqual(provenance["failure_gate"], failure_gate)
                    self.assertIs(provenance["provider_called"], provider_called)
                    self.assertIs(provenance["profile_called"], profile_called)
                    encoded = json.dumps(response)
                    self.assertNotIn("synthetic_output_repair_exhausted", encoded)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=3)

    def test_client_rejections_do_not_receive_operational_metadata(self) -> None:
        class Engine:
            def converse(self, payload, *, request_id):
                raise AssertionError("unauthorized request must not reach engine")

        with TemporaryDirectory() as temp:
            settings = _settings(temp)
            server = build_server(
                settings,
                AuditLogger(Path(temp), "dev"),
                engine=Engine(),
                dev_token="test-token",
            )
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                request = Request(
                    f"http://127.0.0.1:{server.server_address[1]}/v1/chat",
                    data=b"{}",
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(HTTPError) as caught:
                    urlopen(request, timeout=3)
                payload = json.loads(caught.exception.read().decode("utf-8"))
                self.assertEqual(payload, {"error": "unauthorized"})
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
