from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
import inspect
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

from myuna_core.command_routing import CommandName, CommandParser
from myuna_core.runtime_state import (
    CheckHandler,
    RuntimeStateRegistry,
    RuntimeStateStatus,
    RuntimeStateValue,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


runtime = _load_module(
    "p10_check_command_runtime_test",
    SCRIPTS / "telegram_owner_runtime_gateway.py",
)
plugin_protocol = _load_module(
    "p10_check_command_plugin_protocol_test",
    ROOT / "channels/astrbot-telegram/plugin/myuna_telegram_gateway/protocol.py",
)


def _decision(message_text: str) -> object:
    return runtime.RuntimeDecision(
        event_id="event-p10-check-synthetic",
        channel_kind="astrbot_telegram",
        channel_instance="telegram-dev",
        conversation_id="conversation-p10-check-synthetic",
        occurred_at=datetime(2035, 1, 2, tzinfo=timezone.utc),
        nonce_fingerprint="c" * 64,
        payload_sha256="d" * 64,
        trace_id="trace-p10-check-synthetic",
        account_fingerprint="e" * 64,
        message_text=message_text,
        hybrid_external_generation=True,
    )


class _Connection:
    def __init__(self) -> None:
        self.responses: list[dict[str, object]] = []

    def sendall(self, payload: bytes) -> None:
        self.responses.append(json.loads(payload))


class _Limiter:
    def allow(self, _principal_id: str, _now: datetime) -> bool:
        return True


class CheckCommandIngressTests(unittest.TestCase):
    def test_plugin_and_core_share_the_exact_check_route(self) -> None:
        parser = CommandParser()
        for message_text in ("/Check", "/check overview", "  /CHECK synthetic  "):
            with self.subTest(message_text=message_text):
                self.assertTrue(plugin_protocol.check_command_is_explicit(message_text))
                parsed = parser.parse(message_text)
                self.assertIsNotNone(parsed)
                self.assertIs(parsed.name, CommandName.CHECK)

        for message_text in ("/Checklist", "/Checker", "/Check\nsynthetic"):
            with self.subTest(message_text=message_text):
                self.assertFalse(plugin_protocol.check_command_is_explicit(message_text))

    def test_empty_and_populated_runtime_state_are_explicit(self) -> None:
        empty = CheckHandler(RuntimeStateRegistry()).render(
            subject="MYUNA",
            category="overview",
        )
        self.assertIs(empty.status, RuntimeStateStatus.UNKNOWN)
        self.assertIn("unavailable", empty.text)
        self.assertIn("0.00", empty.text)

        observed = datetime(2035, 1, 2, 3, 4, tzinfo=timezone.utc)
        populated = CheckHandler(
            RuntimeStateRegistry(
                (
                    RuntimeStateValue(
                        subject="MYUNA",
                        category="overview",
                        key="synthetic-health",
                        value="ready",
                        status=RuntimeStateStatus.CURRENT,
                        source="synthetic-source",
                        observed_at=observed,
                        confidence=0.75,
                    ),
                )
            )
        ).render(subject="MYUNA", category="overview")
        self.assertIs(populated.status, RuntimeStateStatus.CURRENT)
        for expected in (
            "synthetic-health",
            "ready",
            "synthetic-source",
            observed.isoformat(),
            "0.75",
        ):
            self.assertIn(expected, populated.text)

    def test_check_bypasses_epoch_and_history_without_private_audit_data(self) -> None:
        marker = "private-marker-must-not-project"
        inbound = _decision(f"/Check {marker}")
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

        class Core:
            def __init__(self) -> None:
                self.calls = []

            def chat(self, messages, *, decision, external_context=None):
                self.calls.append((messages, decision.message_text, external_context))
                return runtime.CoreReply(
                    reply="synthetic check result",
                    actual_route="deterministic",
                )

        core = Core()
        connection = _Connection()
        stages: list[str] = []
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
            mock.patch.object(runtime, "_audit_stage", side_effect=stages.append),
        ):
            runtime.process_connection(
                connection,
                config=SimpleNamespace(principal_id="principal-owner-synthetic"),
                signing_secret=b"s" * 32,
                identity_pepper=b"p" * 32,
                core=core,
                limiter=_Limiter(),
                history=history,
                recovery_store=None,
                hybrid_enabled=True,
            )

        self.assertEqual(
            core.calls,
            [
                (
                    [{"role": "user", "content": inbound.message_text}],
                    inbound.message_text,
                    None,
                )
            ],
        )
        self.assertIn("check_context_isolated", stages)
        self.assertIn("reply_accepted", stages)
        self.assertNotIn(marker, json.dumps(stages))
        self.assertEqual(
            connection.responses[0],
            {
                "code": "owner-runtime-reply",
                "reply": "synthetic check result",
                "status": "accepted",
            },
        )
        after = history.request_messages(inbound.conversation_id, "synthetic after")
        self.assertEqual(
            after,
            [
                {"role": "user", "content": "synthetic baseline"},
                {"role": "assistant", "content": "synthetic baseline reply"},
                {"role": "user", "content": "synthetic after"},
            ],
        )

    def test_timeout_contract_is_bounded_and_ordered(self) -> None:
        plugin_timeout = inspect.signature(plugin_protocol.send_envelope).parameters[
            "timeout"
        ].default
        self.assertEqual(plugin_timeout, 175.0)
        self.assertEqual(runtime.CORE_REQUEST_TIMEOUT_SECONDS, 165)
        self.assertGreater(plugin_timeout, runtime.CORE_REQUEST_TIMEOUT_SECONDS)


if __name__ == "__main__":
    unittest.main()
