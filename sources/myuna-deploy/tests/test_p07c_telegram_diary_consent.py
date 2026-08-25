from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

from myuna_core.authenticated_conversation import AuthenticatedConversationContext


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load_runtime():
    path = SCRIPTS / "telegram_owner_runtime_gateway.py"
    spec = importlib.util.spec_from_file_location("p07c_telegram_runtime_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load Telegram runtime")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


runtime = _load_runtime()


def _load_plugin_protocol():
    path = (
        ROOT
        / "channels/astrbot-telegram/plugin/myuna_telegram_gateway/protocol.py"
    )
    spec = importlib.util.spec_from_file_location(
        "p07c_diary_cross_layer_protocol_test",
        path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load Telegram plugin protocol")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


plugin_protocol = _load_plugin_protocol()


def config():
    return runtime.RuntimeConfig(
        binding_id="binding-telegram-owner-synthetic",
        principal_id="principal-owner-synthetic",
        namespace_id="namespace-owner-synthetic",
        finalization_digest="a" * 64,
        evidence_sha256="b" * 64,
        channel_kind="astrbot_telegram",
        channel_instance="telegram-dev",
        core_host="127.0.0.1",
        core_port=18081,
        max_requests_per_ten_minutes=12,
        max_history_messages=12,
        max_history_characters=12000,
    )


def decision(message_text: str):
    return runtime.RuntimeDecision(
        event_id="event-synthetic-1",
        channel_kind="astrbot_telegram",
        channel_instance="telegram-dev",
        conversation_id="conversation-synthetic-1",
        occurred_at=datetime(2035, 1, 2, tzinfo=timezone.utc),
        nonce_fingerprint="c" * 64,
        payload_sha256="d" * 64,
        trace_id="trace-synthetic-1",
        account_fingerprint="e" * 64,
        message_text=message_text,
    )


class TelegramBenchmarkProfileBoundaryTests(unittest.TestCase):
    def _context(self, text: str) -> AuthenticatedConversationContext:
        payload = runtime.build_authenticated_context(decision(text), config())
        return AuthenticatedConversationContext.from_payload(
            payload,
            authenticated_client_id="telegram-owner-private",
            authenticated_channel_kind="astrbot_telegram",
        )

    def test_exact_benchmark_proposal_grants_candidate_consent(self) -> None:
        parsed = self._context("/Benchmark I prefer synthetic examples.")
        self.assertTrue(parsed.consent_memory_candidate)

    def test_diary_never_grants_profile_candidate_consent(self) -> None:
        for text in ("/Diary", "/Diary archive", "/Diary confirm ABCDEF123456"):
            with self.subTest(text=text):
                self.assertFalse(self._context(text).consent_memory_candidate)

    def test_cross_layer_envelope_is_capability_free_then_gateway_derives_consent(self) -> None:
        now = datetime(2035, 1, 2, tzinfo=timezone.utc)
        signing_secret = b"s" * 32
        envelope = plugin_protocol.build_signed_envelope(
            sender_id="123456789",
            message_text="/Benchmark synthetic stable preference",
            message_id="synthetic-message",
            raw_timestamp=now.timestamp(),
            signing_secret=signing_secret,
            channel_instance="telegram-dev",
            now=now,
            nonce_factory=lambda: "n" * 32,
        )
        self.assertEqual(
            envelope["event"]["consent_context"],
            {"media_processing": False, "memory_candidate": False, "tools": False},
        )
        verified = runtime.evaluate_runtime_envelope(
            envelope,
            config=config(),
            signing_secret=signing_secret,
            identity_pepper=b"p" * 32,
            now=now,
        )
        context = AuthenticatedConversationContext.from_payload(
            runtime.build_authenticated_context(verified, config()),
            authenticated_client_id="telegram-owner-private",
            authenticated_channel_kind="astrbot_telegram",
        )
        self.assertTrue(context.consent_memory_candidate)

    def test_exact_confirm_and_cancel_grant_candidate_consent(self) -> None:
        self.assertTrue(
            self._context("/Benchmark confirm ABCDEF123456").consent_memory_candidate
        )
        self.assertTrue(
            self._context("/Benchmark cancel ABCDEF123456").consent_memory_candidate
        )

    def test_ordinary_or_malformed_benchmark_text_does_not_grant(self) -> None:
        for text in ("ordinary chat", "/Benchmark", "/Benchmark confirm bad"):
            with self.subTest(text=text):
                self.assertFalse(self._context(text).consent_memory_candidate)

    def test_source_capability_and_current_docs_name_benchmark_as_profile_gate(self) -> None:
        capability = json.loads(
            (
                ROOT
                / "config/capabilities/telegram-owner-v6-p07c-local-profile-write-v1.json"
            ).read_text(encoding="utf-8")
        )
        reason = capability["capabilities"]["long_term_memory_write"]["reason"]
        self.assertIn("Benchmark", reason)
        self.assertNotIn("Diary intent", reason)
        for relative in (
            "docs/ADR-057-owner-profile-intelligent-candidate-write-v1.md",
            "docs/p07c-owner-profile-write-current-state-matrix-v1.md",
        ):
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("/Benchmark confirm <code>", source)
            self.assertNotIn("/Diary confirm <code>", source)

    def test_diary_control_bypasses_short_term_session_context(self) -> None:
        source = (SCRIPTS / "telegram_owner_runtime_gateway.py").read_text(
            encoding="utf-8"
        )
        process = source[
            source.index("def process_connection(") : source.index("def main()")
        ]
        self.assertIn(
            "diary_control = diary_command_is_explicit",
            process,
        )
        self.assertIn(
            "benchmark_control = benchmark_intent_grants_profile_consent",
            process,
        )
        self.assertIn(
            '[{"role": "user", "content": decision.message_text}]',
            process,
        )
        self.assertIn("if diary_control:", process)
        self.assertIn('_audit_stage("diary_context_isolated")', process)
        self.assertEqual(runtime.CORE_REQUEST_TIMEOUT_SECONDS, 165)

    def test_diary_process_uses_single_turn_and_does_not_commit_history(self) -> None:
        diary_text = "/Diary I prefer synthetic rollback checks."
        inbound = decision(diary_text)
        history = runtime.ConversationHistory(8, 8_000)
        baseline = history.request_messages(
            inbound.conversation_id,
            "synthetic baseline",
        )
        history.commit_reply(
            inbound.conversation_id,
            baseline,
            "synthetic baseline reply",
        )

        class Connection:
            def __init__(self) -> None:
                self.responses = []

            def sendall(self, payload: bytes) -> None:
                self.responses.append(json.loads(payload))

        class Core:
            def __init__(self) -> None:
                self.calls = []

            def chat(self, messages, *, decision, external_context=None):
                self.assert_external_context = external_context
                self.calls.append((messages, decision.message_text))
                return runtime.CoreReply(
                    reply="synthetic candidate prepared",
                    actual_route="deterministic",
                )

        class Limiter:
            def allow(self, _principal_id, _now) -> bool:
                return True

        connection = Connection()
        core = Core()
        with (
            mock.patch.object(runtime, "_read_request", return_value={}),
            mock.patch.object(
                runtime,
                "evaluate_runtime_envelope",
                return_value=inbound,
            ),
            mock.patch.object(runtime, "claim_inbound", return_value=True),
            mock.patch.object(runtime, "resolve_verified_owner", return_value=True),
            mock.patch.object(runtime, "record_outcome", return_value=True),
        ):
            runtime.process_connection(
                connection,
                config=SimpleNamespace(principal_id="principal-owner-synthetic"),
                signing_secret=b"s" * 32,
                identity_pepper=b"p" * 32,
                core=core,
                limiter=Limiter(),
                history=history,
                recovery_store=None,
            )

        self.assertEqual(
            core.calls,
            [([{"role": "user", "content": diary_text}], diary_text)],
        )
        self.assertIsNone(core.assert_external_context)
        after = history.request_messages(inbound.conversation_id, "synthetic after")
        self.assertEqual(
            after,
            [
                {"role": "user", "content": "synthetic baseline"},
                {"role": "assistant", "content": "synthetic baseline reply"},
                {"role": "user", "content": "synthetic after"},
            ],
        )
        self.assertEqual(
            connection.responses[0],
            {
                "code": "owner-runtime-reply",
                "reply": "synthetic candidate prepared",
                "status": "accepted",
            },
        )


if __name__ == "__main__":
    unittest.main()
