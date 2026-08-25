from __future__ import annotations

from datetime import datetime, timezone
import json
import unittest

from myuna_core.authenticated_conversation import (
    SCHEMA_VERSION as CONTEXT_SCHEMA_VERSION,
    AuthenticatedConversationContext,
)
from myuna_core.owner_profile.contracts import OwnerProfileError
from myuna_core.owner_profile.write_protocol import BOUNDARY, OPERATION
from myuna_core.owner_profile.write_runtime import OwnerProfileWriteResult
from myuna_core.owner_profile.write_socket_worker import (
    process_write_request,
    serve_write_connection,
)


class FakeAudit:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def emit(self, _event: str, **kwargs: object) -> None:
        self.events.append(dict(kwargs))


class FakeRuntime:
    def __init__(self, *, error: OwnerProfileError | None = None) -> None:
        self.audit = FakeAudit()
        self.error = error
        self.calls: list[str] = []

    def handle(self, text: str, **_kwargs: object) -> OwnerProfileWriteResult:
        self.calls.append(text)
        if self.error is not None:
            raise self.error
        return OwnerProfileWriteResult(
            action="prepared",
            reply="长期记忆候选（尚未写入）\n确认写入：/Benchmark confirm AABBCCDDEEFF",
            memory_write_performed=False,
            target_revision=3,
        )


def context() -> AuthenticatedConversationContext:
    return AuthenticatedConversationContext(
        schema_version=CONTEXT_SCHEMA_VERSION,
        request_id="request-synthetic",
        correlation_id="correlation-synthetic",
        client_id="telegram-owner-private",
        channel_kind="astrbot_telegram",
        binding_id="binding-synthetic",
        principal_id="principal-synthetic",
        namespace_id="namespace-synthetic",
        authority_level="owner",
        channel_instance="telegram-dev",
        conversation_id="conversation-synthetic",
        conversation_kind="private",
        event_id="event-synthetic",
        trace_id="trace-synthetic",
        occurred_at=datetime(2035, 1, 2, tzinfo=timezone.utc),
        delivery_capabilities=("text",),
        consent_memory_candidate=True,
    )


def request_payload() -> bytes:
    return json.dumps(
        {
            "authenticated_context": context().as_payload(),
            "boundary": BOUNDARY,
            "operation": OPERATION,
            "request_id": "request-synthetic",
            "schema_version": 1,
            "text": "/Benchmark 我长期偏好直接沟通。",
            "timeout_ms": 150_000,
        },
        ensure_ascii=False,
    ).encode("utf-8")


class OwnerProfileWriteSocketWorkerTests(unittest.TestCase):
    def test_process_returns_exact_candidate_preview(self) -> None:
        runtime = FakeRuntime()
        response = json.loads(
            process_write_request(
                request_payload(),
                runtime=runtime,  # type: ignore[arg-type]
                now=lambda: datetime(2035, 1, 2, tzinfo=timezone.utc),
            )
        )
        self.assertTrue(response["ok"])
        self.assertEqual(response["action"], "prepared")
        self.assertIn("AABBCCDDEEFF", response["reply"])
        self.assertFalse(response["memory_write_performed"])
        self.assertEqual(runtime.calls, ["/Benchmark 我长期偏好直接沟通。"])

    def test_runtime_error_response_and_audit_are_content_free(self) -> None:
        runtime = FakeRuntime(
            error=OwnerProfileError("candidate_provider_unavailable", retryable=True)
        )
        response = json.loads(
            process_write_request(
                request_payload(), runtime=runtime  # type: ignore[arg-type]
            )
        )
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "candidate_provider_unavailable")
        serialized = json.dumps(runtime.audit.events, ensure_ascii=False)
        self.assertNotIn("我长期偏好", serialized)
        self.assertNotIn("principal-synthetic", serialized)

    def test_malformed_request_never_echoes_raw_text(self) -> None:
        runtime = FakeRuntime()
        response = process_write_request(
            b'{"request_id":"request-synthetic","private":"do not echo"}',
            runtime=runtime,  # type: ignore[arg-type]
        )
        self.assertNotIn(b"do not echo", response)
        self.assertFalse(json.loads(response)["ok"])

    def test_peer_uid_rejection_does_not_read_request(self) -> None:
        class FakeConnection:
            def __init__(self) -> None:
                self.recv_called = False
                self.response = b""

            def settimeout(self, _value: float) -> None:
                pass

            def recv(self, _size: int) -> bytes:
                self.recv_called = True
                return request_payload()

            def sendall(self, payload: bytes) -> None:
                self.response = payload

        connection = FakeConnection()
        serve_write_connection(
            connection,  # type: ignore[arg-type]
            runtime=FakeRuntime(),  # type: ignore[arg-type]
            expected_peer_uid=1001,
            peer_uid=lambda _connection: 1002,
        )
        self.assertFalse(connection.recv_called)
        response = json.loads(connection.response)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "profile_write_peer_rejected")


if __name__ == "__main__":
    unittest.main()
