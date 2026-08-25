from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys
import unittest

from myuna_core.channel_gateway import ChannelEvent, sign_channel_event


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = ROOT / "channels" / "astrbot-qq" / "plugin" / "myuna_gateway"
RUNNER_PATH = ROOT / "scripts" / "qq_owner_runtime_gateway.py"
SERVICE = ROOT / "systemd" / "myuna-qq-owner-runtime-dev.service"
SOCKET = ROOT / "systemd" / "myuna-qq-owner-runtime-dev.socket"
MIGRATION = ROOT / "database" / "migrations" / "0005_qq_owner_runtime_resolution.sql"
MANIFEST = ROOT / "config" / "capabilities" / "dev-v5.json"
PLUGIN_MAIN = PLUGIN_ROOT / "main.py"
COMPOSE = ROOT / "channels" / "astrbot-qq" / "compose.dev.yml"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


protocol = _load_module("myuna_gateway_runtime_protocol_test", PLUGIN_ROOT / "protocol.py")
runner = _load_module("qq_owner_runtime_gateway_test", RUNNER_PATH)


class QQOwnerRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 7, 16, 4, 30, tzinfo=timezone.utc)
        self.signing_secret = b"synthetic-channel-signing-key-32-bytes-minimum"
        self.identity_pepper = b"synthetic-identity-pepper-32-bytes-minimum"
        self.config = runner.RuntimeConfig(
            binding_id="binding-astrbot-qq-owner-cealana",
            principal_id="principal-owner-cealana",
            namespace_id="ns-owner-cealana-private",
            finalization_digest="a" * 64,
            evidence_sha256="b" * 64,
            channel_instance="napcat-dev",
            core_host="127.0.0.1",
            core_port=18081,
            max_requests_per_ten_minutes=12,
            max_history_messages=12,
            max_history_characters=12000,
        )

    def envelope(self, text: str = "在吗？"):
        return protocol.build_signed_envelope(
            sender_id="12345678",
            message_text=text,
            message_id="synthetic-runtime-message-1",
            raw_timestamp=self.now.timestamp(),
            signing_secret=self.signing_secret,
            channel_instance="napcat-dev",
            now=self.now,
            nonce_factory=lambda: "r" * 32,
        )

    def test_signed_private_text_envelope_is_accepted_without_consent(self) -> None:
        decision = runner.evaluate_runtime_envelope(
            self.envelope(),
            config=self.config,
            signing_secret=self.signing_secret,
            identity_pepper=self.identity_pepper,
            now=self.now,
        )
        self.assertEqual(decision.channel_kind, "astrbot_qq")
        self.assertEqual(decision.channel_instance, "napcat-dev")
        self.assertEqual(decision.message_text, "在吗？")
        self.assertNotIn("12345678", repr(decision))

    def test_group_consent_stale_wrong_channel_and_instance_fail_closed(self) -> None:
        for mutation in ("group", "tools", "stale", "channel", "instance"):
            payload = self.envelope()
            if mutation == "group":
                payload["event"]["conversation_kind"] = "group"
            elif mutation == "tools":
                payload["event"]["consent_context"]["tools"] = True
            elif mutation == "stale":
                payload["event"]["timestamp"] = (
                    self.now - timedelta(minutes=6)
                ).isoformat()
            elif mutation == "channel":
                payload["event"]["channel"] = "astrbot_telegram"
            else:
                payload["event"]["channel_instance"] = "other-instance"
            event = ChannelEvent.from_payload(payload["event"])
            payload["signature"] = sign_channel_event(event, self.signing_secret)
            with self.assertRaises(runner.RuntimeRejected):
                runner.evaluate_runtime_envelope(
                    payload,
                    config=self.config,
                    signing_secret=self.signing_secret,
                    identity_pepper=self.identity_pepper,
                    now=self.now,
                )

    def test_history_is_bounded_in_memory_and_alternating(self) -> None:
        history = runner.ConversationHistory(4, 4000)
        first = history.request_messages("conv-test", "u1")
        history.commit_reply("conv-test", first, "a1")
        second = history.request_messages("conv-test", "u2")
        history.commit_reply("conv-test", second, "a2")
        third = history.request_messages("conv-test", "u3")
        self.assertEqual(
            [item["role"] for item in third],
            ["user", "assistant", "user"],
        )
        self.assertEqual(third[-1]["content"], "u3")

    def test_runtime_config_accepts_staged_and_long_context_contracts(self) -> None:
        base = {
            "binding_id": "binding-astrbot-qq-owner-cealana",
            "channel_instance": "napcat-dev",
            "core_host": "127.0.0.1",
            "core_port": 18081,
            "evidence_sha256": "a" * 64,
            "finalization_digest": "b" * 64,
            "max_history_characters": 262144,
            "max_history_messages": 12,
            "max_requests_per_ten_minutes": 12,
            "namespace_id": "ns-owner-cealana-private",
            "principal_id": "principal-owner-cealana",
        }
        for max_messages in (24, 36, 128, 256):
            with self.subTest(max_messages=max_messages):
                payload = {**base, "max_history_messages": max_messages}
                self.assertEqual(
                    runner.RuntimeConfig.from_payload(payload).max_history_messages,
                    max_messages,
                )

    def test_protocol_accepts_only_bounded_runtime_reply_shape(self) -> None:
        decoded = protocol.decode_gateway_response(
            b'{"code":"owner-runtime-reply","reply":"  ok  ","status":"accepted"}'
        )
        self.assertEqual(decoded["reply"], "ok")
        with self.assertRaises(protocol.GatewayTransportError):
            protocol.decode_gateway_response(
                b'{"code":"owner-runtime-reply","reply":"","status":"accepted"}'
            )
        with self.assertRaises(protocol.GatewayTransportError):
            protocol.decode_gateway_response(
                b'{"code":"owner-runtime-reply","reply":"ok","status":"rejected"}'
            )

    def test_event_admission_silently_rejects_self_and_non_text_events(self) -> None:
        accepted = protocol.should_forward_private_plain_text(
            sender_id="12345678",
            self_id="87654321",
            is_private_chat=True,
            has_plain_text_only=True,
        )
        self.assertTrue(accepted)

        rejected_cases = (
            {
                "sender_id": "87654321",
                "self_id": "87654321",
                "is_private_chat": True,
                "has_plain_text_only": True,
            },
            {
                "sender_id": "12345678",
                "self_id": "87654321",
                "is_private_chat": False,
                "has_plain_text_only": True,
            },
            {
                "sender_id": "12345678",
                "self_id": "87654321",
                "is_private_chat": True,
                "has_plain_text_only": False,
            },
            {
                "sender_id": "invalid",
                "self_id": "87654321",
                "is_private_chat": True,
                "has_plain_text_only": True,
            },
            {
                "sender_id": "12345678",
                "self_id": "",
                "is_private_chat": True,
                "has_plain_text_only": True,
            },
        )
        for case in rejected_cases:
            with self.subTest(case=case):
                self.assertFalse(protocol.should_forward_private_plain_text(**case))

    def test_systemd_and_plugin_keep_the_boundary_narrow(self) -> None:
        service = SERVICE.read_text(encoding="utf-8")
        socket_unit = SOCKET.read_text(encoding="utf-8")
        plugin = PLUGIN_MAIN.read_text(encoding="utf-8")
        compose = COMPOSE.read_text(encoding="utf-8")
        self.assertIn("User=myuna-gateway", service)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET", service)
        self.assertIn("IPAddressDeny=any", service)
        self.assertIn("IPAddressAllow=127.0.0.1/32", service)
        self.assertIn("Requires=postgresql.service myuna-core@qq.service", service)
        self.assertIn("LoadCredential=core-token:", service)
        self.assertIn("SocketMode=0660", socket_unit)
        self.assertIn("event.should_call_llm(False)", plugin)
        self.assertIn("event.stop_event()", plugin)
        self.assertIn("event.get_self_id()", plugin)
        self.assertIn("should_forward_private_plain_text", plugin)
        self.assertNotIn("当前安全入口只接收纯文字私聊", plugin)
        self.assertIn("/run/myuna-gateway/qq-owner.sock", compose)
        self.assertNotIn("/var/run/postgresql", compose)

    def test_migration_exposes_only_exact_verified_binding_resolution(self) -> None:
        sql = MIGRATION.read_text(encoding="utf-8")
        self.assertIn("SECURITY DEFINER", sql)
        self.assertIn("resolve_verified_binding", sql)
        self.assertIn("binding.binding_status = 'verified'", sql)
        self.assertIn("principal.principal_status = 'active'", sql)
        self.assertIn("namespace.namespace_status = 'active'", sql)
        self.assertIn("TO myuna_gateway_app", sql)
        self.assertNotIn("message_text", sql)
        self.assertNotIn("actor_account_id", sql)

    def test_manifest_is_explicitly_qq_only_without_memory_or_tools(self) -> None:
        text = MANIFEST.read_text(encoding="utf-8")
        self.assertIn('"response_scope": "qq_owner_private_dev_no_memory"', text)
        self.assertIn('"scope": "verified owner private text only"', text)
        self.assertIn('"real_memory": false', text)
        self.assertIn('"tools": false', text)
        self.assertIn('"external_network_listener": false', text)


if __name__ == "__main__":
    unittest.main()
