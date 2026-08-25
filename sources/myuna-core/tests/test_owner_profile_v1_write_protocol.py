from __future__ import annotations

from datetime import datetime, timezone
import json
import unittest

from myuna_core.authenticated_conversation import (
    SCHEMA_VERSION as CONTEXT_SCHEMA_VERSION,
    AuthenticatedConversationContext,
)
from myuna_core.owner_profile.contracts import OwnerProfileError
from myuna_core.owner_profile.write_protocol import (
    BOUNDARY,
    OPERATION,
    ProfileWriteProtocolError,
    build_write_error_response,
    build_write_success_response,
    parse_write_request_bytes,
    parse_write_response,
)
from myuna_core.owner_profile.write_runtime import OwnerProfileWriteResult


def context(request_id: str = "request-synthetic") -> AuthenticatedConversationContext:
    return AuthenticatedConversationContext(
        schema_version=CONTEXT_SCHEMA_VERSION,
        request_id=request_id,
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


def request_payload(**overrides: object) -> bytes:
    document: dict[str, object] = {
        "authenticated_context": context().as_payload(),
        "boundary": BOUNDARY,
        "operation": OPERATION,
        "request_id": "request-synthetic",
        "schema_version": 1,
        "text": "/Benchmark 我长期偏好直接沟通。",
        "timeout_ms": 150_000,
    }
    document.update(overrides)
    return json.dumps(document, ensure_ascii=False).encode("utf-8")


class OwnerProfileWriteProtocolTests(unittest.TestCase):
    def test_request_round_trip_preserves_unicode_and_authenticated_context(self) -> None:
        parsed = parse_write_request_bytes(
            request_payload(),
            authenticated_client_id="telegram-owner-private",
            authenticated_channel_kind="astrbot_telegram",
        )
        self.assertEqual(parsed["text"], "/Benchmark 我长期偏好直接沟通。")
        self.assertTrue(parsed["authenticated_context"].consent_memory_candidate)

    def test_request_rejects_unknown_fields_and_context_mismatch(self) -> None:
        with self.assertRaisesRegex(
            ProfileWriteProtocolError, "invalid_write_request"
        ):
            parse_write_request_bytes(
                request_payload(extra=True),
                authenticated_client_id="telegram-owner-private",
                authenticated_channel_kind="astrbot_telegram",
            )
        with self.assertRaisesRegex(
            ProfileWriteProtocolError, "write_context_rejected"
        ):
            parse_write_request_bytes(
                request_payload(request_id="different-request"),
                authenticated_client_id="telegram-owner-private",
                authenticated_channel_kind="astrbot_telegram",
            )

    def test_prepared_success_round_trip_has_no_write_claim(self) -> None:
        response = build_write_success_response(
            request_id="request-synthetic",
            result=OwnerProfileWriteResult(
                action="prepared",
                reply="长期记忆候选（尚未写入）\n确认写入：/Benchmark confirm AABBCCDDEEFF",
                memory_write_performed=False,
                target_revision=3,
            ),
        )
        parsed = parse_write_response(
            response, expected_request_id="request-synthetic"
        )
        self.assertEqual(parsed.action, "prepared")
        self.assertFalse(parsed.memory_write_performed)
        self.assertTrue(response["model_called"])

    def test_published_response_requires_write_and_revision(self) -> None:
        response = build_write_success_response(
            request_id="request-synthetic",
            result=OwnerProfileWriteResult(
                action="published",
                reply="长期记忆已写入 revision 3。",
                memory_write_performed=True,
                target_revision=3,
            ),
        )
        response["memory_write_performed"] = False
        with self.assertRaisesRegex(
            ProfileWriteProtocolError, "invalid_write_worker_response"
        ):
            parse_write_response(response, expected_request_id="request-synthetic")

    def test_typed_error_round_trip_and_malformed_error_reject(self) -> None:
        response = build_write_error_response(
            "request-synthetic",
            OwnerProfileError("candidate_provider_unavailable", retryable=True),
        )
        with self.assertRaises(OwnerProfileError) as caught:
            parse_write_response(response, expected_request_id="request-synthetic")
        self.assertEqual(caught.exception.code, "candidate_provider_unavailable")
        self.assertTrue(caught.exception.retryable)
        response["error"]["raw_text"] = "private"
        with self.assertRaisesRegex(
            ProfileWriteProtocolError, "invalid_write_worker_response"
        ):
            parse_write_response(response, expected_request_id="request-synthetic")


if __name__ == "__main__":
    unittest.main()
