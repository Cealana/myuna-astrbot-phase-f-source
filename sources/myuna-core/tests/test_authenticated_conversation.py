from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import unittest

from myuna_core.authenticated_conversation import (
    AuthenticatedConversationContext,
    AuthenticatedConversationContextError,
)
from myuna_core.channel_gateway import (
    ASTRBOT_QQ_CHANNEL,
    ASTRBOT_TELEGRAM_CHANNEL,
    SCHEMA_VERSION,
    ChannelEvent,
    ConsentContext,
    GatewayVerifier,
    build_signed_envelope,
)
from myuna_core.identity import AccountBinding, IdentityRegistry, account_fingerprint


IDENTITY_PEPPER = b"synthetic-identity-pepper-32-bytes-minimum"
GATEWAY_SECRET = b"synthetic-gateway-secret-32-bytes-minimum"
OWNER_ACCOUNT = "synthetic-owner-account"
NOW = datetime(2026, 7, 27, 0, 0, tzinfo=timezone.utc)


def verified_message(channel: str):
    registry = IdentityRegistry(
        (
            AccountBinding(
                binding_id=f"binding-{channel}-owner",
                principal_id="principal-owner-test",
                namespace_id="namespace-owner-private",
                channel_kind=channel,
                account_fingerprint=account_fingerprint(
                    channel,
                    OWNER_ACCOUNT,
                    IDENTITY_PEPPER,
                ),
                authority_level="owner",
            ),
        )
    )
    event = ChannelEvent(
        schema_version=SCHEMA_VERSION,
        event_id=f"event-{channel}-0001",
        channel=channel,
        channel_instance=f"instance-{channel}",
        actor_account_id=OWNER_ACCOUNT,
        conversation_id=f"conversation-{channel}-private",
        conversation_kind="private",
        occurred_at=NOW,
        message_text="这段正文不应进入身份上下文",
        reply_to=None,
        delivery_capabilities=("text",),
        consent_context=ConsentContext(),
        trace_id=f"trace-{channel}-0001",
        nonce=f"nonce_{channel}_000000000000000000000000",
    )
    verifier = GatewayVerifier(
        registry,
        identity_pepper=IDENTITY_PEPPER,
        gateway_secret=GATEWAY_SECRET,
        now=lambda: NOW,
    )
    return verifier.verify(build_signed_envelope(event, GATEWAY_SECRET).as_payload())


class AuthenticatedConversationContextTests(unittest.TestCase):
    def context(self, channel: str = ASTRBOT_QQ_CHANNEL):
        return AuthenticatedConversationContext.from_verified_channel_message(
            verified_message(channel),
            authenticated_client_id=f"client-{channel}",
            authenticated_channel_kind=channel,
            request_id="request-context-0001",
            correlation_id="correlation-context-0001",
        )

    def test_qq_and_telegram_produce_the_same_identity_contract(self) -> None:
        qq = self.context(ASTRBOT_QQ_CHANNEL)
        telegram = self.context(ASTRBOT_TELEGRAM_CHANNEL)
        self.assertEqual(qq.principal_id, telegram.principal_id)
        self.assertEqual(qq.namespace_id, telegram.namespace_id)
        self.assertNotEqual(qq.channel_kind, telegram.channel_kind)
        self.assertEqual(set(qq.as_payload()), set(telegram.as_payload()))

    def test_context_contains_no_message_account_fingerprint_or_secret(self) -> None:
        context = self.context()
        flattened = repr(context.as_payload())
        self.assertNotIn("这段正文", flattened)
        self.assertNotIn(OWNER_ACCOUNT, flattened)
        self.assertNotIn("fingerprint", flattened)
        self.assertNotIn("secret", flattened)
        self.assertNotIn("token", flattened)

    def test_internal_round_trip_requires_the_authenticated_client_binding(self) -> None:
        context = self.context(ASTRBOT_TELEGRAM_CHANNEL)
        restored = AuthenticatedConversationContext.from_payload(
            context.as_payload(),
            authenticated_client_id=context.client_id,
            authenticated_channel_kind=ASTRBOT_TELEGRAM_CHANNEL,
        )
        self.assertEqual(restored, context)

        for client_id, channel in (
            ("different-client", ASTRBOT_TELEGRAM_CHANNEL),
            (context.client_id, ASTRBOT_QQ_CHANNEL),
        ):
            with self.subTest(client_id=client_id, channel=channel):
                with self.assertRaisesRegex(
                    AuthenticatedConversationContextError,
                    "^authenticated conversation context rejected$",
                ):
                    AuthenticatedConversationContext.from_payload(
                        context.as_payload(),
                        authenticated_client_id=client_id,
                        authenticated_channel_kind=channel,
                    )

    def test_strict_schema_rejects_extra_fields_and_identity_tampering(self) -> None:
        context = self.context()
        extra = deepcopy(context.as_payload())
        extra["message_text"] = "spoofed"
        tampered = deepcopy(context.as_payload())
        tampered["channel_kind"] = ASTRBOT_TELEGRAM_CHANNEL
        for payload in (extra, tampered):
            with self.assertRaises(AuthenticatedConversationContextError):
                AuthenticatedConversationContext.from_payload(
                    payload,
                    authenticated_client_id=context.client_id,
                    authenticated_channel_kind=context.channel_kind,
                )

    def test_verified_event_channel_must_match_authenticated_http_channel(self) -> None:
        with self.assertRaises(AuthenticatedConversationContextError):
            AuthenticatedConversationContext.from_verified_channel_message(
                verified_message(ASTRBOT_QQ_CHANNEL),
                authenticated_client_id="client-telegram",
                authenticated_channel_kind=ASTRBOT_TELEGRAM_CHANNEL,
                request_id="request-channel-mismatch",
            )


if __name__ == "__main__":
    unittest.main()
