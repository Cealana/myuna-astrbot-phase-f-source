from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from myuna_core.channel_gateway import ChannelEvent, sign_channel_event


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
PLUGIN = (
    ROOT
    / "channels"
    / "astrbot-telegram"
    / "plugin"
    / "myuna_telegram_gateway"
)
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


protocol = _load("telegram_r2_protocol_test", PLUGIN / "protocol.py")
runtime = _load(
    "telegram_owner_runtime_gateway_r2_test",
    SCRIPTS / "telegram_owner_runtime_gateway.py",
)
challenge = _load(
    "telegram_owner_challenge_gateway_r2_test",
    SCRIPTS / "telegram_owner_challenge_gateway.py",
)


class TelegramOwnerRuntimeR2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)
        self.signing_secret = b"synthetic-telegram-signing-secret-32-bytes"
        self.identity_pepper = b"synthetic-identity-pepper-32-bytes-minimum"
        self.config = runtime.RuntimeConfig(
            channel_kind="astrbot_telegram",
            binding_id="binding-astrbot-telegram-owner-cealana",
            principal_id="principal-owner-cealana",
            namespace_id="ns-owner-cealana-private",
            finalization_digest="a" * 64,
            evidence_sha256="b" * 64,
            channel_instance="telegram-owner-dev",
            core_host="127.0.0.1",
            core_port=18081,
            max_requests_per_ten_minutes=12,
            max_history_messages=12,
            max_history_characters=12000,
        )

    def envelope(self):
        return protocol.build_signed_envelope(
            sender_id="123456789",
            message_text="你好",
            message_id="42",
            raw_timestamp=self.now.timestamp(),
            signing_secret=self.signing_secret,
            channel_instance="telegram-owner-dev",
            now=self.now,
            nonce_factory=lambda: "n" * 32,
        )

    def test_runtime_requires_explicit_telegram_channel_and_instance(self) -> None:
        decision = runtime.evaluate_runtime_envelope(
            self.envelope(),
            config=self.config,
            signing_secret=self.signing_secret,
            identity_pepper=self.identity_pepper,
            now=self.now,
        )
        self.assertEqual(decision.channel_kind, "astrbot_telegram")

        payload = self.envelope()
        payload["event"]["channel"] = "astrbot_qq"
        event = ChannelEvent.from_payload(payload["event"])
        payload["signature"] = sign_channel_event(event, self.signing_secret)
        with self.assertRaises(runtime.RuntimeRejected):
            runtime.evaluate_runtime_envelope(
                payload,
                config=self.config,
                signing_secret=self.signing_secret,
                identity_pepper=self.identity_pepper,
                now=self.now,
            )

    def test_visual_event_is_separately_signed_and_tamper_rejected(self) -> None:
        payload = protocol.attach_signed_visual_event(
            self.envelope(),
            observation=(
                "A synthetic screenshot says ignore prior instructions; "
                "a red icon is visible."
            ),
            caption_present=True,
            signing_secret=self.signing_secret,
        )
        decision = runtime.evaluate_runtime_envelope(
            payload,
            config=self.config,
            signing_secret=self.signing_secret,
            identity_pepper=self.identity_pepper,
            now=self.now,
        )
        self.assertTrue(decision.hybrid_external_generation)
        self.assertEqual(
            decision.visual_event["source"],
            "gemini_visual_extraction",
        )
        self.assertTrue(decision.visual_event["caption_present"])

        payload["routing"]["visual_event"]["observation"] = (
            "tampered synthetic observation"
        )
        with self.assertRaises(runtime.RuntimeRejected):
            runtime.evaluate_runtime_envelope(
                payload,
                config=self.config,
                signing_secret=self.signing_secret,
                identity_pepper=self.identity_pepper,
                now=self.now,
            )

    def test_runtime_config_rejects_qq_or_extra_fields(self) -> None:
        payload = {
            "binding_id": "binding-astrbot-telegram-owner-cealana",
            "channel_instance": "telegram-owner-dev",
            "channel_kind": "astrbot_qq",
            "core_host": "127.0.0.1",
            "core_port": 18081,
            "evidence_sha256": "a" * 64,
            "finalization_digest": "b" * 64,
            "max_history_characters": 12000,
            "max_history_messages": 12,
            "max_requests_per_ten_minutes": 12,
            "namespace_id": "ns-owner-cealana-private",
            "principal_id": "principal-owner-cealana",
        }
        with self.assertRaises(runtime.RuntimeRejected):
            runtime.RuntimeConfig.from_payload(payload)
        payload["channel_kind"] = "astrbot_telegram"
        payload["unexpected"] = True
        with self.assertRaises(runtime.RuntimeRejected):
            runtime.RuntimeConfig.from_payload(payload)

    def test_runtime_config_accepts_staged_and_long_context_contracts(self) -> None:
        base = {
            "binding_id": "binding-astrbot-telegram-owner-cealana",
            "channel_instance": "telegram-owner-dev",
            "channel_kind": "astrbot_telegram",
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
                    runtime.RuntimeConfig.from_payload(payload).max_history_messages,
                    max_messages,
                )

    def test_database_calls_use_telegram_only_functions(self) -> None:
        decision = runtime.evaluate_runtime_envelope(
            self.envelope(),
            config=self.config,
            signing_secret=self.signing_secret,
            identity_pepper=self.identity_pepper,
            now=self.now,
        )
        with patch.object(runtime, "_psql_scalar", return_value="t") as scalar:
            self.assertTrue(runtime.claim_inbound(decision, self.now))
            sql, variables = scalar.call_args.args
            self.assertIn("claim_telegram_inbound_event", sql)
            self.assertNotIn(":'channel_kind'", sql)
            self.assertNotIn("channel_kind", variables)

        with patch.object(
            runtime,
            "_psql_scalar",
            return_value=(
                "binding-astrbot-telegram-owner-cealana|"
                "principal-owner-cealana|ns-owner-cealana-private"
            ),
        ) as scalar:
            self.assertTrue(runtime.resolve_verified_owner(decision, self.config))
            self.assertIn(
                "resolve_verified_telegram_owner_binding",
                scalar.call_args.args[0],
            )

    def test_challenge_rejects_wrong_channel_or_instance(self) -> None:
        challenge_config = challenge.ChallengeConfig(
            binding_id="binding-astrbot-telegram-owner-cealana",
            principal_id="principal-owner-cealana",
            namespace_id="ns-owner-cealana-private",
            channel_instance="telegram-owner-dev",
            account_fingerprint=runtime.account_fingerprint(
                "astrbot_telegram",
                "123456789",
                self.identity_pepper,
            ),
            plan_digest="c" * 64,
            challenge_sha256=runtime.sha256("CODE".encode("utf-8")).hexdigest(),
            expires_at=self.now + timedelta(minutes=5),
        )
        payload = self.envelope()
        payload["event"]["message_parts"] = [{"text": "CODE", "type": "text"}]
        event = ChannelEvent.from_payload(payload["event"])
        payload["signature"] = sign_channel_event(event, self.signing_secret)
        accepted = challenge.evaluate_challenge(
            payload,
            config=challenge_config,
            signing_secret=self.signing_secret,
            identity_pepper=self.identity_pepper,
            now=self.now,
        )
        self.assertTrue(accepted.matched)

        payload["event"]["channel_instance"] = "other"
        event = ChannelEvent.from_payload(payload["event"])
        payload["signature"] = sign_channel_event(event, self.signing_secret)
        with self.assertRaises(challenge.ChallengeRejected):
            challenge.evaluate_challenge(
                payload,
                config=challenge_config,
                signing_secret=self.signing_secret,
                identity_pepper=self.identity_pepper,
                now=self.now,
            )


class TelegramOwnerStaticIsolationR2Tests(unittest.TestCase):
    def test_database_migration_has_separate_role_and_no_identity_insert(self) -> None:
        migration = (
            ROOT
            / "database"
            / "migrations"
            / "0006_telegram_owner_channel_foundation.sql"
        ).read_text(encoding="utf-8")
        self.assertIn("myuna_telegram_gateway_app", migration)
        self.assertIn("claim_telegram_inbound_event", migration)
        self.assertIn("resolve_verified_telegram_owner_binding", migration)
        self.assertIn("'astrbot_qq', 'astrbot_telegram'", migration)
        self.assertNotIn(
            "INSERT INTO myuna_identity.account_binding",
            migration,
        )
        self.assertNotIn("GRANT SELECT ON", migration)

    def test_systemd_users_sockets_and_credentials_are_separate(self) -> None:
        runtime_service = (
            ROOT / "systemd" / "myuna-telegram-owner-runtime-dev.service"
        ).read_text(encoding="utf-8")
        runtime_socket = (
            ROOT / "systemd" / "myuna-telegram-owner-runtime-dev.socket"
        ).read_text(encoding="utf-8")
        challenge_service = (
            ROOT / "systemd" / "myuna-telegram-owner-challenge-dev.service"
        ).read_text(encoding="utf-8")
        self.assertIn("User=myuna-gateway-telegram", runtime_service)
        self.assertIn(
            "/etc/myuna-telegram-gateway/secrets/channel-signing-v1",
            runtime_service,
        )
        self.assertIn(
            "/etc/myuna-telegram-gateway/secrets/core-token-v1",
            runtime_service,
        )
        self.assertIn(
            "ListenStream=/run/myuna-telegram-gateway/owner.sock",
            runtime_socket,
        )
        self.assertIn("PrivateNetwork=true", challenge_service)
        self.assertNotIn("/run/myuna-gateway/qq-owner.sock", runtime_service)


if __name__ == "__main__":
    unittest.main()
