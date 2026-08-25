from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import unittest

from myuna_core.channel_gateway import (
    ASTRBOT_QQ_CHANNEL,
    ASTRBOT_TELEGRAM_CHANNEL,
    SCHEMA_VERSION,
    ChannelEvent,
    ConsentContext,
    GatewayEnvelopeError,
    GatewayVerifier,
    build_signed_envelope,
)
from myuna_core.identity import AccountBinding, IdentityRegistry, account_fingerprint


IDENTITY_PEPPER = b"synthetic-identity-pepper-32-bytes-minimum"
TELEGRAM_GATEWAY_SECRET = b"synthetic-telegram-gateway-secret-32-bytes"
QQ_GATEWAY_SECRET = b"synthetic-qq-gateway-secret-separate-32-bytes"
OWNER_ACCOUNT = "123456789"
NOW = datetime(2026, 7, 25, 0, 0, tzinfo=timezone.utc)


def event(*, channel: str = ASTRBOT_TELEGRAM_CHANNEL) -> ChannelEvent:
    return ChannelEvent(
        schema_version=SCHEMA_VERSION,
        event_id="event-telegram-test-0001",
        channel=channel,
        channel_instance="telegram-owner-dev",
        actor_account_id=OWNER_ACCOUNT,
        conversation_id="conversation-telegram-private",
        conversation_kind="private",
        occurred_at=NOW,
        message_text="你好，Myuna",
        reply_to=None,
        delivery_capabilities=("text",),
        consent_context=ConsentContext(),
        trace_id="trace-telegram-test-0001",
        nonce="telegram_nonce_00000000000000000000000001",
    )


class TelegramChannelBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        binding = AccountBinding(
            binding_id="binding-telegram-owner-test",
            principal_id="principal-test-owner",
            namespace_id="ns-test-owner-private",
            channel_kind=ASTRBOT_TELEGRAM_CHANNEL,
            account_fingerprint=account_fingerprint(
                ASTRBOT_TELEGRAM_CHANNEL,
                OWNER_ACCOUNT,
                IDENTITY_PEPPER,
            ),
            authority_level="owner",
        )
        self.registry = IdentityRegistry((binding,))

    def verifier(self, secret: bytes = TELEGRAM_GATEWAY_SECRET) -> GatewayVerifier:
        return GatewayVerifier(
            self.registry,
            identity_pepper=IDENTITY_PEPPER,
            gateway_secret=secret,
            now=lambda: NOW,
        )

    def test_verified_telegram_private_text_uses_existing_owner_namespace(self) -> None:
        verified = self.verifier().verify(
            build_signed_envelope(event(), TELEGRAM_GATEWAY_SECRET).as_payload()
        )
        self.assertEqual(verified.context.principal_id, "principal-test-owner")
        self.assertEqual(verified.context.namespace_id, "ns-test-owner-private")
        self.assertEqual(verified.context.channel_kind, ASTRBOT_TELEGRAM_CHANNEL)
        self.assertEqual(verified.message_text, "你好，Myuna")
        self.assertNotIn(OWNER_ACCOUNT, repr(verified))

    def test_same_account_is_domain_separated_between_qq_and_telegram(self) -> None:
        telegram = account_fingerprint(
            ASTRBOT_TELEGRAM_CHANNEL,
            OWNER_ACCOUNT,
            IDENTITY_PEPPER,
        )
        qq = account_fingerprint(
            ASTRBOT_QQ_CHANNEL,
            OWNER_ACCOUNT,
            IDENTITY_PEPPER,
        )
        self.assertNotEqual(telegram, qq)

    def test_qq_secret_cannot_authenticate_telegram_envelope(self) -> None:
        payload = build_signed_envelope(event(), QQ_GATEWAY_SECRET).as_payload()
        with self.assertRaisesRegex(GatewayEnvelopeError, "^gateway envelope rejected$"):
            self.verifier().verify(payload)

    def test_channel_tampering_is_rejected(self) -> None:
        payload = build_signed_envelope(event(), TELEGRAM_GATEWAY_SECRET).as_payload()
        tampered = deepcopy(payload)
        tampered["event"]["channel"] = ASTRBOT_QQ_CHANNEL
        with self.assertRaisesRegex(GatewayEnvelopeError, "^gateway envelope rejected$"):
            self.verifier().verify(tampered)

    def test_unknown_channel_remains_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "^unsupported channel$"):
            event(channel="telegram")


if __name__ == "__main__":
    unittest.main()
