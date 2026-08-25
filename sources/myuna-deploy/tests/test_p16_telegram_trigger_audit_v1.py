from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = (
    ROOT
    / "channels"
    / "astrbot-telegram"
    / "plugin"
    / "myuna_telegram_gateway"
)


def _load_protocol():
    name = "p16_telegram_trigger_protocol_test"
    spec = importlib.util.spec_from_file_location(name, PLUGIN / "protocol.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load Telegram protocol")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


protocol = _load_protocol()


class P16TelegramTriggerAuditTests(unittest.TestCase):
    def forward(self, message: str) -> bool:
        return protocol.should_forward_private_plain_text(
            sender_id="123456789",
            is_private_chat=True,
            has_plain_text_only=True,
            sender_is_bot=False,
            message_text=message,
        )

    def test_relational_shared_context_minimal_pairs_are_ordinary_text(self) -> None:
        pairs = (
            ("我和你的纸船", "我和她的纸船"),
            ("我和她一起画星图", "我和她计划一起画星图"),
            ("我和你昨天一起折纸船", "我和你明天一起折纸船"),
        )
        for pair in pairs:
            for message in pair:
                with self.subTest(category=pair.index(message)):
                    self.assertTrue(self.forward(message))

    def test_command_prefix_length_and_unicode_boundaries_are_exact(self) -> None:
        self.assertFalse(self.forward("/unknown"))
        self.assertTrue(self.forward("／unknown"))
        self.assertTrue(self.forward("\u200b/unknown"))
        self.assertTrue(self.forward("/diary synthetic-entry"))
        self.assertTrue(self.forward("/temporal"))
        self.assertTrue(self.forward("界" * 4000))
        self.assertFalse(self.forward("界" * 4001))
        self.assertFalse(self.forward(" \t\r\n"))
        self.assertTrue(self.forward("合成\x00文本"))

    def test_relational_text_survives_signed_envelope_without_reclassification(self) -> None:
        message = "我和她一起画星图"
        envelope = protocol.build_signed_envelope(
            sender_id="123456789",
            message_text=message,
            message_id="synthetic-1",
            raw_timestamp=datetime(2026, 8, 6, tzinfo=timezone.utc).timestamp(),
            signing_secret=b"synthetic-signing-secret-at-least-32-bytes",
            channel_instance="telegram-synthetic",
            now=datetime(2026, 8, 6, tzinfo=timezone.utc),
            nonce_factory=lambda: "n" * 32,
        )
        self.assertEqual(envelope["event"]["message_parts"], [{"text": message, "type": "text"}])

    def test_gateway_response_validation_is_structural_not_semantic(self) -> None:
        reality_like = {
            "kind": "accepted_reply",
            "reply": "昨天我出门看到一只合成纸鹤",
            "schema": protocol.GATEWAY_RESPONSE_SCHEMA,
        }
        decoded = protocol.decode_gateway_response(
            json.dumps(reality_like, ensure_ascii=False).encode("utf-8")
        )
        self.assertEqual(decoded["reply"], reality_like["reply"])

        malformed = {**reality_like, "unexpected": True}
        with self.assertRaises(protocol.GatewayTransportError):
            protocol.decode_gateway_response(
                json.dumps(malformed, ensure_ascii=False).encode("utf-8")
            )


if __name__ == "__main__":
    unittest.main()
