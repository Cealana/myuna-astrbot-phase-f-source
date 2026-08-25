from __future__ import annotations

import unittest

from myuna_core.conversation import ConversationInputError
from myuna_core.http_api import _parse_chat_envelope, _parse_hybrid_chat_envelope
from myuna_core.http_client_auth import LoadedHttpClientCredential


def context_payload(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "authority_level": "owner",
        "binding_id": "binding-owner",
        "channel_instance": "telegram-primary",
        "channel_kind": "astrbot_telegram",
        "client_id": "telegram-owner-private",
        "consent": {
            "media_processing": False,
            "memory_candidate": False,
            "tools": False,
        },
        "conversation_id": "conversation-private",
        "conversation_kind": "private",
        "correlation_id": "correlation-1",
        "delivery_capabilities": ["text"],
        "event_id": "event-1",
        "namespace_id": "namespace-owner",
        "occurred_at": "2026-08-01T00:00:00+00:00",
        "principal_id": "principal-owner",
        "request_id": "gateway-request-1",
        "schema_version": "myuna.authenticated-conversation-context.v1",
        "trace_id": "trace-1",
    }
    values.update(overrides)
    return values


class OwnerProfileHttpContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = LoadedHttpClientCredential(
            client_id="telegram-owner-private",
            channel_kind="astrbot_telegram",
            token="synthetic-test-token",
        )
        self.conversation = {
            "messages": [{"role": "user", "content": "synthetic query"}],
            "synthetic_memory": False,
        }

    def test_nested_context_is_bound_to_authenticated_http_client(self) -> None:
        conversation, context = _parse_chat_envelope(
            {
                "authenticated_context": context_payload(),
                "conversation": self.conversation,
            },
            self.client,
        )
        self.assertEqual(conversation, self.conversation)
        self.assertIsNotNone(context)
        assert context is not None
        self.assertEqual(context.client_id, "telegram-owner-private")
        self.assertEqual(context.channel_kind, "astrbot_telegram")
        self.assertEqual(context.authority_level, "owner")
        self.assertFalse(context.consent_memory_candidate)

    def test_client_or_channel_mismatch_fails_closed(self) -> None:
        mismatches = (
            {"client_id": "qq-owner-private"},
            {"channel_kind": "astrbot_qq"},
        )
        for overrides in mismatches:
            with self.subTest(overrides=overrides), self.assertRaises(
                ConversationInputError
            ):
                _parse_chat_envelope(
                    {
                        "authenticated_context": context_payload(**overrides),
                        "conversation": self.conversation,
                    },
                    self.client,
                )

    def test_partial_or_extra_envelope_is_rejected(self) -> None:
        candidates = (
            {"authenticated_context": context_payload()},
            {
                "authenticated_context": context_payload(),
                "conversation": self.conversation,
                "extra": True,
            },
        )
        for payload in candidates:
            with self.subTest(payload_fields=sorted(payload)), self.assertRaises(
                ConversationInputError
            ):
                _parse_chat_envelope(payload, self.client)

    def test_hybrid_envelope_accepts_only_one_bound_current_message(self) -> None:
        external_context = {"current_message": "synthetic query", "schema": "synthetic"}
        conversation, context, parsed_external = _parse_hybrid_chat_envelope(
            {
                "authenticated_context": context_payload(),
                "conversation": self.conversation,
                "external_context": external_context,
            },
            self.client,
        )
        self.assertEqual(conversation, self.conversation)
        self.assertIsNotNone(context)
        self.assertEqual(parsed_external, external_context)

    def test_hybrid_envelope_rejects_legacy_history_and_message_drift(self) -> None:
        candidates = (
            {
                "messages": [
                    {"role": "user", "content": "legacy"},
                    {"role": "assistant", "content": "legacy reply"},
                    {"role": "user", "content": "synthetic query"},
                ],
                "synthetic_memory": False,
            },
            self.conversation,
        )
        external_messages = ("synthetic query", "different query")
        for conversation, external_message in zip(candidates, external_messages):
            with self.subTest(conversation=conversation), self.assertRaises(
                ConversationInputError
            ):
                _parse_hybrid_chat_envelope(
                    {
                        "authenticated_context": context_payload(),
                        "conversation": conversation,
                        "external_context": {
                            "current_message": external_message,
                            "schema": "synthetic",
                        },
                    },
                    self.client,
                )
