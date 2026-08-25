from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from context_window_policy import (  # noqa: E402
    ContextWindowRejected,
    RecentRequestGuard,
)


class RecentRequestGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 7, 31, 3, 0, tzinfo=timezone.utc)
        self.guard = RecentRequestGuard(
            namespace="qq-owner-private-v1",
            cooldown_seconds=300,
            max_entries=8,
        )

    def test_identical_redelivery_is_suppressed_during_cooldown(self) -> None:
        self.assertTrue(self.guard.claim("conv-a", "同一条消息", self.now))
        self.assertFalse(
            self.guard.claim(
                "conv-a",
                "同一条消息",
                self.now + timedelta(seconds=299),
            )
        )
        self.assertTrue(
            self.guard.claim(
                "conv-a",
                "同一条消息",
                self.now + timedelta(seconds=300),
            )
        )

    def test_channel_conversation_and_content_are_isolated(self) -> None:
        self.assertTrue(self.guard.claim("conv-a", "消息一", self.now))
        self.assertTrue(self.guard.claim("conv-a", "消息二", self.now))
        self.assertTrue(self.guard.claim("conv-b", "消息一", self.now))
        other = RecentRequestGuard(namespace="telegram-owner-private-v1")
        self.assertTrue(other.claim("conv-a", "消息一", self.now))

    def test_only_fingerprints_are_retained_and_capacity_is_bounded(self) -> None:
        for index in range(9):
            self.assertTrue(self.guard.claim("conv", f"private-{index}", self.now))
        self.assertEqual(len(self.guard._expires), 8)
        self.assertNotIn("private-8", repr(self.guard._expires))

    def test_invalid_clock_fails_closed(self) -> None:
        with self.assertRaises(ContextWindowRejected):
            self.guard.claim("conv", "message", datetime(2026, 7, 31))


def _load_runtime(filename: str, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class _Connection:
    def __init__(self) -> None:
        self.responses: list[bytes] = []

    def sendall(self, payload: bytes) -> None:
        self.responses.append(payload)


class _Core:
    def __init__(self, runtime) -> None:
        self.runtime = runtime
        self.calls = 0

    def chat(self, messages, *, decision, external_context=None):
        self.calls += 1
        return self.runtime.CoreReply(reply="synthetic-reply", actual_route="deepseek_default")


class GatewayDuplicateSuppressionTests(unittest.TestCase):
    def test_qq_content_duplicate_guard_remains_bounded(self) -> None:
        for filename, namespace, channel in (
            ("qq_owner_runtime_gateway.py", "qq-owner-private-v1", "astrbot_qq"),
        ):
            with self.subTest(filename=filename):
                runtime = _load_runtime(filename, "guard_test_" + filename[:-3])
                now = datetime.now(timezone.utc)
                decision = runtime.RuntimeDecision(
                    event_id="evt-synthetic",
                    channel_kind=channel,
                    channel_instance="synthetic-owner",
                    conversation_id="conv-synthetic",
                    occurred_at=now,
                    nonce_fingerprint="a" * 64,
                    payload_sha256="b" * 64,
                    trace_id="trace-synthetic",
                    account_fingerprint="c" * 64,
                    message_text="identical synthetic request",
                )
                core = _Core(runtime)
                guard = RecentRequestGuard(namespace=namespace)
                history = runtime.ConversationHistory(4, 4000)
                limiter = runtime.SlidingRateLimiter(12)
                config = SimpleNamespace(principal_id="principal-synthetic")
                patches = (
                    mock.patch.object(runtime, "_read_request", return_value={}),
                    mock.patch.object(
                        runtime,
                        "evaluate_runtime_envelope",
                        return_value=decision,
                    ),
                    mock.patch.object(runtime, "claim_inbound", return_value=True),
                    mock.patch.object(
                        runtime,
                        "resolve_verified_owner",
                        return_value=True,
                    ),
                    mock.patch.object(runtime, "record_outcome", return_value=True),
                )
                with patches[0], patches[1], patches[2], patches[3], patches[4]:
                    first = _Connection()
                    runtime.process_connection(
                        first,
                        config=config,
                        signing_secret=b"x" * 32,
                        identity_pepper=b"y" * 32,
                        core=core,
                        limiter=limiter,
                        history=history,
                        request_guard=guard,
                    )
                    second = _Connection()
                    runtime.process_connection(
                        second,
                        config=config,
                        signing_secret=b"x" * 32,
                        identity_pepper=b"y" * 32,
                        core=core,
                        limiter=limiter,
                        history=history,
                        request_guard=guard,
                    )
                self.assertEqual(core.calls, 1)
                self.assertIn(b'"status":"accepted"', first.responses[0])
                self.assertIn(b'"code":"owner-runtime-unavailable"', second.responses[0])

    def test_telegram_exact_event_replay_is_silent_and_pre_core(self) -> None:
        runtime = _load_runtime(
            "telegram_owner_runtime_gateway.py",
            "telegram_exact_replay_test",
        )
        now = datetime.now(timezone.utc)
        decision = runtime.RuntimeDecision(
            event_id="evt-synthetic",
            channel_kind="astrbot_telegram",
            channel_instance="synthetic-owner",
            conversation_id="conv-synthetic",
            occurred_at=now,
            nonce_fingerprint="a" * 64,
            payload_sha256="b" * 64,
            trace_id="trace-synthetic",
            account_fingerprint="c" * 64,
            message_text="identical synthetic request",
        )
        core = _Core(runtime)
        history = runtime.ConversationHistory(4, 4000)
        limiter = runtime.SlidingRateLimiter(12)
        config = SimpleNamespace(principal_id="principal-synthetic")
        with (
            mock.patch.object(runtime, "_read_request", return_value={}),
            mock.patch.object(
                runtime,
                "evaluate_runtime_envelope",
                return_value=decision,
            ),
            mock.patch.object(
                runtime,
                "claim_inbound",
                side_effect=(True, False),
            ),
            mock.patch.object(
                runtime,
                "resolve_verified_owner",
                return_value=True,
            ),
            mock.patch.object(runtime, "record_outcome", return_value=True),
        ):
            first = _Connection()
            runtime.process_connection(
                first,
                config=config,
                signing_secret=b"x" * 32,
                identity_pepper=b"y" * 32,
                core=core,
                limiter=limiter,
                history=history,
            )
            replay = _Connection()
            runtime.process_connection(
                replay,
                config=config,
                signing_secret=b"x" * 32,
                identity_pepper=b"y" * 32,
                core=core,
                limiter=limiter,
                history=history,
            )
        self.assertEqual(core.calls, 1)
        self.assertIn(b'"status":"accepted"', first.responses[0])
        self.assertEqual(
            replay.responses,
            [
                b'{"kind":"duplicate_suppressed",'
                b'"schema":"myuna.gateway-response.v3"}\n'
            ],
        )

    def test_telegram_same_text_in_distinct_events_is_processed_twice(self) -> None:
        runtime = _load_runtime(
            "telegram_owner_runtime_gateway.py",
            "telegram_distinct_event_test",
        )
        now = datetime.now(timezone.utc)
        first_decision = runtime.RuntimeDecision(
            event_id="evt-synthetic-1",
            channel_kind="astrbot_telegram",
            channel_instance="synthetic-owner",
            conversation_id="conv-synthetic",
            occurred_at=now,
            nonce_fingerprint="a" * 64,
            payload_sha256="b" * 64,
            trace_id="trace-synthetic-1",
            account_fingerprint="c" * 64,
            message_text="intentional repeated request",
        )
        second_decision = replace(
            first_decision,
            event_id="evt-synthetic-2",
            nonce_fingerprint="d" * 64,
            payload_sha256="e" * 64,
            trace_id="trace-synthetic-2",
        )
        core = _Core(runtime)
        history = runtime.ConversationHistory(4, 4000)
        limiter = runtime.SlidingRateLimiter(12)
        config = SimpleNamespace(principal_id="principal-synthetic")
        with (
            mock.patch.object(runtime, "_read_request", return_value={}),
            mock.patch.object(
                runtime,
                "evaluate_runtime_envelope",
                side_effect=(first_decision, second_decision),
            ),
            mock.patch.object(runtime, "claim_inbound", return_value=True),
            mock.patch.object(
                runtime,
                "resolve_verified_owner",
                return_value=True,
            ),
            mock.patch.object(runtime, "record_outcome", return_value=True),
        ):
            for _ in range(2):
                runtime.process_connection(
                    _Connection(),
                    config=config,
                    signing_secret=b"x" * 32,
                    identity_pepper=b"y" * 32,
                    core=core,
                    limiter=limiter,
                    history=history,
                )
        self.assertEqual(core.calls, 2)


if __name__ == "__main__":
    unittest.main()
