from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import json
import socket
import unittest

from myuna_core.audit import AuditLogger
from myuna_core.authenticated_conversation import (
    SCHEMA_VERSION as AUTH_SCHEMA,
    AuthenticatedConversationContext,
)
from myuna_core.config import load_settings
from myuna_core.external_context.contracts import (
    EgressSafetySignals,
    ExternalContextEnvelope,
    ZERO_DIGEST,
    current_message_digest,
)
from myuna_core.external_context.lifecycle_v3 import ReleaseBoundExternalContext
from myuna_core.http_api import build_server
from myuna_core.http_client_auth import LoadedHttpClientCredential


RELEASE_SET_ID = "a" * 64
POLICY_OVERLAY_ID = "f" * 64
MESSAGE = "synthetic generation10 request"


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


def authenticated_context() -> AuthenticatedConversationContext:
    return AuthenticatedConversationContext(
        schema_version=AUTH_SCHEMA,
        request_id="request-generation10-http",
        correlation_id="correlation-generation10-http",
        client_id="telegram-owner-private",
        channel_kind="astrbot_telegram",
        binding_id="binding-generation10-http",
        principal_id="principal-generation10-http",
        namespace_id="namespace-generation10-http",
        authority_level="owner",
        channel_instance="telegram-primary",
        conversation_id="conversation-generation10-http",
        conversation_kind="private",
        event_id="event-generation10-http",
        trace_id="trace-generation10-http",
        occurred_at=datetime(2026, 8, 5, tzinfo=timezone.utc),
        delivery_capabilities=("text",),
    )


def release_bound_payload(
    *,
    release_set_id: str = RELEASE_SET_ID,
    policy_overlay_id: str | None = None,
) -> dict[str, object]:
    context = authenticated_context()
    envelope = ExternalContextEnvelope(
        epoch_id="telegram-owner-private-external-d-reset-v4",
        epoch_revision=0,
        turn_sequence=0,
        parent_digest=ZERO_DIGEST,
        channel_kind=context.channel_kind,
        principal_id=context.principal_id,
        namespace_id=context.namespace_id,
        current_message=MESSAGE,
        current_message_digest=current_message_digest(context, MESSAGE),
        summary=None,
        recent_turns=(),
        safety=EgressSafetySignals(classifier_available=True),
    )
    return ReleaseBoundExternalContext(
        release_set_id,
        envelope,
        policy_overlay_id=policy_overlay_id,
    ).as_payload()


class Result:
    def public_payload(self) -> dict[str, object]:
        return {"request_id": "synthetic", "reply": "synthetic reply"}


class DiaryResult:
    def public_payload(self) -> dict[str, object]:
        return {
            "candidate": None,
            "job_digest": "d" * 64,
            "provider_called": False,
            "status": "coverage_incomplete",
        }


class LegacyEngine:
    pass


class CapturingHybridEngine:
    release_set_id = RELEASE_SET_ID
    policy_overlay_id: str | None = None

    def __init__(self) -> None:
        self.calls: list[tuple[object, object, object]] = []
        self.diary_calls: list[object] = []
        self.owner_day_diary_calls: list[object] = []

    def converse_external(
        self,
        conversation_payload: object,
        external_context_payload: object,
        *,
        request_id: str,
        authenticated_context: AuthenticatedConversationContext,
    ) -> Result:
        self.calls.append(
            (conversation_payload, external_context_payload, authenticated_context)
        )
        return Result()

    def summarize_external(self, summary_job_payload: object, *, request_id: str) -> Result:
        raise AssertionError("summary endpoint must not be called")

    def generate_reflective_diary(
        self,
        diary_job_payload: object,
        *,
        request_id: str,
    ) -> DiaryResult:
        self.diary_calls.append(diary_job_payload)
        return DiaryResult()

    def generate_owner_day_diary(
        self,
        diary_job_payload: object,
        *,
        request_id: str,
    ) -> DiaryResult:
        self.owner_day_diary_calls.append(diary_job_payload)
        return DiaryResult()


class Generation10ReleaseBoundHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        settings = load_settings(
            {
                "MYUNA_ENV": "dev",
                "MYUNA_BIND_HOST": "127.0.0.1",
                "MYUNA_PORT": str(free_loopback_port()),
                "MYUNA_DATA_DIR": self.temp.name,
                "MYUNA_LOG_DIR": self.temp.name,
                "MYUNA_DEFINITION_RELEASE": "v6-synthetic-release",
                "MYUNA_DEFINITION_PATH": "/unused/release",
                "MYUNA_CAPABILITY_MANIFEST": "/unused/capabilities.json",
                "MYUNA_PROVIDERS_ENABLED": "deepseek",
                "MYUNA_HTTP_CLIENT_CREDENTIALS": (
                    "telegram-owner-private:astrbot_telegram:telegram_owner_core_token"
                ),
            }
        )
        self.audit = AuditLogger(Path(self.temp.name), "dev")
        self.hybrid = CapturingHybridEngine()
        client = LoadedHttpClientCredential(
            client_id="telegram-owner-private",
            channel_kind="astrbot_telegram",
            token="synthetic-telegram-token",
        )
        self.server = build_server(
            settings,
            self.audit,
            engine=LegacyEngine(),  # type: ignore[arg-type]
            hybrid_engine=self.hybrid,
            http_clients=(client,),
        )
        self.port = self.server.server_address[1]
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.temp.cleanup()

    def send(self, external_context: object) -> tuple[int, dict[str, object]]:
        body = json.dumps(
            {
                "authenticated_context": authenticated_context().as_payload(),
                "conversation": {
                    "messages": [{"role": "user", "content": MESSAGE}],
                    "synthetic_memory": False,
                },
                "external_context": external_context,
            }
        ).encode("utf-8")
        request = Request(
            f"http://127.0.0.1:{self.port}/v1/chat",
            data=body,
            headers={
                "Authorization": "Bearer synthetic-telegram-token",
                "Content-Type": "application/json",
                "X-Myuna-Channel-Kind": "astrbot_telegram",
                "X-Myuna-Client-Id": "telegram-owner-private",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=3) as response:
                return response.status, json.load(response)
        except HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_valid_release_bound_message_reaches_hybrid_engine(self) -> None:
        wrapped = release_bound_payload()
        status, response = self.send(wrapped)
        self.assertEqual(status, 200)
        self.assertEqual(response["reply"], "synthetic reply")
        self.assertEqual(len(self.hybrid.calls), 1)
        self.assertEqual(self.hybrid.calls[0][1], wrapped)

    def test_reflective_diary_endpoint_is_telegram_scoped_and_exactly_shaped(self) -> None:
        body = json.dumps({"diary_job": {"schema": "synthetic-diary-job"}}).encode(
            "utf-8"
        )
        request = Request(
            f"http://127.0.0.1:{self.port}/v1/reflective-diary",
            data=body,
            headers={
                "Authorization": "Bearer synthetic-telegram-token",
                "Content-Type": "application/json",
                "X-Myuna-Channel-Kind": "astrbot_telegram",
                "X-Myuna-Client-Id": "telegram-owner-private",
            },
            method="POST",
        )
        with urlopen(request, timeout=3) as response:
            payload = json.load(response)
        self.assertEqual(payload["status"], "coverage_incomplete")
        self.assertEqual(self.hybrid.diary_calls, [{"schema": "synthetic-diary-job"}])

        malformed = Request(
            f"http://127.0.0.1:{self.port}/v1/reflective-diary",
            data=json.dumps({"diary_job": {}, "extra": True}).encode("utf-8"),
            headers={
                "Authorization": "Bearer synthetic-telegram-token",
                "Content-Type": "application/json",
                "X-Myuna-Channel-Kind": "astrbot_telegram",
                "X-Myuna-Client-Id": "telegram-owner-private",
            },
            method="POST",
        )
        with self.assertRaises(HTTPError) as caught:
            urlopen(malformed, timeout=3)
        self.assertEqual(caught.exception.code, 400)

    def test_owner_day_diary_endpoint_is_distinct_and_exactly_shaped(self) -> None:
        body = json.dumps(
            {"owner_day_diary_job": {"schema": "synthetic-owner-day-job"}}
        ).encode("utf-8")
        request = Request(
            f"http://127.0.0.1:{self.port}/v1/owner-day-diary",
            data=body,
            headers={
                "Authorization": "Bearer synthetic-telegram-token",
                "Content-Type": "application/json",
                "X-Myuna-Channel-Kind": "astrbot_telegram",
                "X-Myuna-Client-Id": "telegram-owner-private",
            },
            method="POST",
        )
        with urlopen(request, timeout=3) as response:
            payload = json.load(response)
        self.assertEqual(payload["status"], "coverage_incomplete")
        self.assertEqual(
            self.hybrid.owner_day_diary_calls,
            [{"schema": "synthetic-owner-day-job"}],
        )

        malformed = Request(
            f"http://127.0.0.1:{self.port}/v1/owner-day-diary",
            data=json.dumps(
                {"owner_day_diary_job": {}, "extra": True}
            ).encode("utf-8"),
            headers={
                "Authorization": "Bearer synthetic-telegram-token",
                "Content-Type": "application/json",
                "X-Myuna-Channel-Kind": "astrbot_telegram",
                "X-Myuna-Client-Id": "telegram-owner-private",
            },
            method="POST",
        )
        with self.assertRaises(HTTPError) as caught:
            urlopen(malformed, timeout=3)
        self.assertEqual(caught.exception.code, 400)

    def test_invalid_release_bound_shapes_fail_before_hybrid_engine(self) -> None:
        valid = release_bound_payload()
        candidates = (
            {"schema": valid["schema"], "release_set_id": RELEASE_SET_ID},
            {
                "schema": valid["schema"],
                "release_set_id": RELEASE_SET_ID,
                "external_context": valid,
            },
            {
                "schema": "myuna.external-context-release-bound.unknown",
                "release_set_id": RELEASE_SET_ID,
                "external_context": valid["external_context"],
            },
            release_bound_payload(release_set_id="b" * 64),
        )
        for candidate in candidates:
            with self.subTest(candidate_schema=candidate["schema"]):
                status, response = self.send(candidate)
                self.assertEqual(status, 400)
                self.assertEqual(response["error"], "invalid_conversation_request")
        self.assertEqual(self.hybrid.calls, [])

    def test_overlay_bound_message_requires_exact_overlay_identity(self) -> None:
        self.hybrid.policy_overlay_id = POLICY_OVERLAY_ID
        wrapped = release_bound_payload(policy_overlay_id=POLICY_OVERLAY_ID)
        status, response = self.send(wrapped)
        self.assertEqual(status, 200)
        self.assertEqual(response["reply"], "synthetic reply")
        self.assertEqual(len(self.hybrid.calls), 1)

        self.hybrid.calls.clear()
        for candidate in (
            release_bound_payload(),
            release_bound_payload(policy_overlay_id="9" * 64),
        ):
            with self.subTest(schema=candidate["schema"]):
                status, response = self.send(candidate)
                self.assertEqual(status, 400)
                self.assertEqual(
                    response["error"], "invalid_conversation_request"
                )
        self.assertEqual(self.hybrid.calls, [])


if __name__ == "__main__":
    unittest.main()
