from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import importlib.util
from pathlib import Path
import sys
import unittest

from myuna_core.channel_gateway import ChannelEvent, SignedChannelEnvelope, sign_channel_event
from myuna_core.identity import account_fingerprint


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = ROOT / "channels" / "astrbot-qq" / "plugin" / "myuna_gateway"
PLUGIN_MAIN = PLUGIN_ROOT / "main.py"
RUNNER_PATH = ROOT / "scripts" / "owner_challenge_gateway.py"
REHEARSAL = ROOT / "scripts" / "rehearse_owner_challenge_adapter.py"
SERVICE = ROOT / "systemd" / "myuna-channel-gateway-dev.service"
SOCKET = ROOT / "systemd" / "myuna-channel-gateway-dev.socket"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


protocol = _load_module("myuna_gateway_protocol_test", PLUGIN_ROOT / "protocol.py")
runner = _load_module("owner_challenge_gateway_test", RUNNER_PATH)


class OwnerChallengeAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 7, 16, 3, 0, tzinfo=timezone.utc)
        self.signing_secret = b"synthetic-channel-signing-key-32-bytes-minimum"
        self.identity_pepper = b"synthetic-identity-pepper-32-bytes-minimum"
        self.sender = "12345678"
        self.challenge = "synthetic-owner-challenge-code"
        self.config = runner.ChallengeConfig(
            binding_id="binding-astrbot-qq-owner-cealana",
            principal_id="principal-owner-cealana",
            namespace_id="ns-owner-cealana-private",
            account_fingerprint=account_fingerprint(
                "astrbot_qq",
                self.sender,
                self.identity_pepper,
            ),
            plan_digest="a" * 64,
            challenge_sha256=sha256(self.challenge.encode("utf-8")).hexdigest(),
            expires_at=self.now + timedelta(hours=1),
        )

    def envelope(self, sender: str | None = None, text: str | None = None):
        return protocol.build_signed_envelope(
            sender_id=sender or self.sender,
            message_text=text or self.challenge,
            message_id="synthetic-message-1",
            raw_timestamp=self.now.timestamp(),
            signing_secret=self.signing_secret,
            channel_instance="napcat-dev",
            now=self.now,
            nonce_factory=lambda: "n" * 32,
        )

    def test_plugin_signature_matches_core_contract(self) -> None:
        payload = self.envelope()
        envelope = SignedChannelEnvelope.from_payload(payload)
        self.assertEqual(
            envelope.signature,
            sign_channel_event(envelope.event, self.signing_secret),
        )
        self.assertNotIn(self.sender, envelope.event.event_id)
        self.assertNotIn(self.sender, envelope.event.conversation_id)
        self.assertFalse(envelope.event.consent_context.memory_candidate)
        self.assertFalse(envelope.event.consent_context.tools)
        self.assertFalse(envelope.event.consent_context.media_processing)

    def test_matching_owner_and_code_are_accepted_by_pure_evaluator(self) -> None:
        decision = runner.evaluate_challenge(
            self.envelope(),
            config=self.config,
            signing_secret=self.signing_secret,
            identity_pepper=self.identity_pepper,
            now=self.now,
        )
        self.assertTrue(decision.matched)

    def test_wrong_actor_and_wrong_code_share_negative_decision(self) -> None:
        wrong_actor = runner.evaluate_challenge(
            self.envelope(sender="12345679"),
            config=self.config,
            signing_secret=self.signing_secret,
            identity_pepper=self.identity_pepper,
            now=self.now,
        )
        wrong_code = runner.evaluate_challenge(
            self.envelope(text="different-synthetic-code"),
            config=self.config,
            signing_secret=self.signing_secret,
            identity_pepper=self.identity_pepper,
            now=self.now,
        )
        self.assertFalse(wrong_actor.matched)
        self.assertFalse(wrong_code.matched)

    def test_stale_event_is_rejected(self) -> None:
        payload = protocol.build_signed_envelope(
            sender_id=self.sender,
            message_text=self.challenge,
            message_id="synthetic-stale-message",
            raw_timestamp=(self.now - timedelta(minutes=6)).timestamp(),
            signing_secret=self.signing_secret,
            channel_instance="napcat-dev",
            now=self.now,
            nonce_factory=lambda: "s" * 32,
        )
        with self.assertRaises(runner.ChallengeRejected):
            runner.evaluate_challenge(
                payload,
                config=self.config,
                signing_secret=self.signing_secret,
                identity_pepper=self.identity_pepper,
                now=self.now,
            )

    def test_group_and_consent_escalation_are_rejected(self) -> None:
        for mutation in ("group", "tools"):
            payload = self.envelope()
            if mutation == "group":
                payload["event"]["conversation_kind"] = "group"
            else:
                payload["event"]["consent_context"]["tools"] = True
            event = ChannelEvent.from_payload(payload["event"])
            payload["signature"] = sign_channel_event(event, self.signing_secret)
            with self.assertRaises(runner.ChallengeRejected):
                runner.evaluate_challenge(
                    payload,
                    config=self.config,
                    signing_secret=self.signing_secret,
                    identity_pepper=self.identity_pepper,
                    now=self.now,
                )

    def test_plugin_stops_llm_and_does_not_log_event_fields(self) -> None:
        source = PLUGIN_MAIN.read_text(encoding="utf-8")
        self.assertIn("event.should_call_llm(False)", source)
        self.assertIn("event.stop_event()", source)
        self.assertIn("PlatformAdapterType.AIOCQHTTP", source)
        for unsafe_log_expression in (
            "logger.info(event",
            "logger.warning(event",
            "logger.error(event",
            "logger.info(message_text",
            "logger.warning(message_text",
            "logger.info(event.get_sender_id",
        ):
            self.assertNotIn(unsafe_log_expression, source)

    def test_systemd_socket_and_credentials_are_gated(self) -> None:
        service = SERVICE.read_text(encoding="utf-8")
        socket_unit = SOCKET.read_text(encoding="utf-8")
        self.assertIn("User=myuna-gateway", service)
        self.assertIn("PrivateNetwork=true", service)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", service)
        self.assertIn("LoadCredential=channel-signing:", service)
        self.assertIn("LoadCredential=identity-pepper:", service)
        self.assertIn("ConditionPathExists=/etc/myuna-gateway/activation-approved", service)
        self.assertIn("SocketMode=0660", socket_unit)
        self.assertIn("SocketUser=root", socket_unit)
        self.assertIn("SocketGroup=myuna-gateway", socket_unit)

    def test_rehearsal_is_synthetic_and_cleans_activation_files(self) -> None:
        source = REHEARSAL.read_text(encoding="utf-8")
        self.assertIn('synthetic_sender = "9876543210"', source)
        self.assertIn('if _identity_counts() != "0|0|0"', source)
        self.assertIn(
            "for path in (EVIDENCE_PATH, ACTIVATION_PATH, CONFIG_PATH):",
            source,
        )
        self.assertIn("path.unlink(missing_ok=True)", source)
        self.assertIn("_delete_synthetic_event(event_id)", source)


if __name__ == "__main__":
    unittest.main()
