from __future__ import annotations

from datetime import datetime, timezone
import json
import sys
from pathlib import Path
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import qq_owner_runtime_gateway as qq_runtime  # noqa: E402
import telegram_owner_runtime_gateway as telegram_runtime  # noqa: E402
from context_capacity_128_qa import (  # noqa: E402
    PROFILE_HTTP_MAX_BODY_BYTES,
    PROFILE_MAX_CHARACTERS,
    PROFILE_MAX_MESSAGES,
    SATURATED_REQUEST_MESSAGES,
    build_saturated_request,
    core_payload_bytes,
    maximal_valid_messages,
    run_offline_gate,
)
from context_window_policy import ConversationHistory  # noqa: E402


class _FakeResponse:
    status = 200

    def read(self, _limit: int) -> bytes:
        return b'{"reply":"synthetic-ok","synthetic_memory":{"used":false}}'


class _CaptureConnection:
    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []

    def request(self, method, path, *, body, headers) -> None:  # noqa: ANN001
        self.requests.append(
            {"method": method, "path": path, "body": body, "headers": headers}
        )

    def getresponse(self) -> _FakeResponse:
        return _FakeResponse()

    def close(self) -> None:
        return None


def _runtime_config(module, channel: str):  # noqa: ANN001
    payload = {
        "binding_id": f"binding-synthetic-{channel}",
        "channel_instance": f"instance-synthetic-{channel}",
        "core_host": "127.0.0.1",
        "core_port": 18081,
        "evidence_sha256": "a" * 64,
        "finalization_digest": "b" * 64,
        "max_history_characters": PROFILE_MAX_CHARACTERS,
        "max_history_messages": PROFILE_MAX_MESSAGES,
        "max_requests_per_ten_minutes": 60,
        "namespace_id": "namespace-synthetic-owner",
        "principal_id": "principal-synthetic-owner",
    }
    if channel == "telegram":
        payload["channel_kind"] = "astrbot_telegram"
    return module.RuntimeConfig.from_payload(payload)


def _decision(module, channel: str):  # noqa: ANN001
    return module.RuntimeDecision(
        event_id="event-synthetic-capacity",
        channel_kind=module.CHANNEL_KIND,
        channel_instance=f"instance-synthetic-{channel}",
        conversation_id="conversation-synthetic-capacity",
        occurred_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
        nonce_fingerprint="c" * 64,
        payload_sha256="d" * 64,
        trace_id="trace-synthetic-capacity",
        account_fingerprint="e" * 64,
        message_text="synthetic capacity query",
    )


class ContextCapacity128QATests(unittest.TestCase):
    def test_exact_storage_request_order_and_recall_positions(self) -> None:
        _, stored, request = build_saturated_request()
        self.assertEqual(len(stored), PROFILE_MAX_MESSAGES)
        self.assertEqual(len(request), SATURATED_REQUEST_MESSAGES)
        self.assertEqual(request[0]["role"], "user")
        self.assertEqual(request[-1]["role"], "user")
        self.assertFalse(any("EVICTED=" in item["content"] for item in request))
        self.assertIn("FIRST=雾蓝纸鸢", request[0]["content"])
        self.assertTrue(
            any("MIDDLE=珊瑚时钟" in item["content"] for item in request)
        )
        self.assertTrue(any("TAIL=月桂玻璃" in item["content"] for item in request))
        self.assertEqual(
            [item["content"] for item in request],
            list(dict.fromkeys(item["content"] for item in request)),
        )

    def test_character_budget_trims_oldest_complete_pairs(self) -> None:
        history = ConversationHistory(PROFILE_MAX_MESSAGES, PROFILE_MAX_CHARACTERS)
        for turn in range(17):
            request = history.request_messages(
                "synthetic-long",
                f"u{turn}-" + "你" * 3_997,
            )
            history.commit_reply(
                "synthetic-long",
                request,
                f"a{turn}-" + "界" * 3_997,
            )
        stored = history.store.load("synthetic-long")
        self.assertEqual(len(stored), 32)
        self.assertLessEqual(
            sum(len(item["content"]) for item in stored),
            PROFILE_MAX_CHARACTERS,
        )
        self.assertEqual([item["role"] for item in stored], ["user", "assistant"] * 16)
        self.assertTrue(stored[0]["content"].startswith("u1-"))

    def test_session_and_channel_stores_are_isolated(self) -> None:
        telegram = ConversationHistory(PROFILE_MAX_MESSAGES, PROFILE_MAX_CHARACTERS)
        qq = ConversationHistory(PROFILE_MAX_MESSAGES, PROFILE_MAX_CHARACTERS)
        request = telegram.request_messages("session-a", "tg-only")
        telegram.commit_reply("session-a", request, "tg-reply")
        request = telegram.request_messages("session-b", "tg-session-b")
        telegram.commit_reply("session-b", request, "tg-session-b-reply")
        request = qq.request_messages("session-a", "qq-only")
        qq.commit_reply("session-a", request, "qq-reply")

        self.assertEqual(telegram.store.load("session-a")[0]["content"], "tg-only")
        self.assertEqual(telegram.store.load("session-b")[0]["content"], "tg-session-b")
        self.assertEqual(qq.store.load("session-a")[0]["content"], "qq-only")

    def test_failed_request_is_not_committed_or_replayed(self) -> None:
        history = ConversationHistory(PROFILE_MAX_MESSAGES, PROFILE_MAX_CHARACTERS)
        baseline = history.request_messages("failure", "baseline")
        history.commit_reply("failure", baseline, "baseline-reply")
        failed = history.request_messages("failure", "must-not-stick")
        self.assertEqual(failed[-1]["content"], "must-not-stick")

        next_request = history.request_messages("failure", "after-failure")
        self.assertFalse(
            any(item["content"] == "must-not-stick" for item in next_request)
        )
        self.assertEqual(next_request[-1]["content"], "after-failure")

    def test_unicode_transport_envelope_fits_candidate_limit(self) -> None:
        cjk = core_payload_bytes(maximal_valid_messages("你"))
        escaped = core_payload_bytes(maximal_valid_messages("\x00"))
        self.assertGreater(len(cjk), 327_680)
        self.assertGreater(len(escaped), len(cjk))
        self.assertLessEqual(len(escaped), PROFILE_HTTP_MAX_BODY_BYTES)

    def test_qq_and_telegram_build_the_same_synthetic_core_payload(self) -> None:
        _, _, messages = build_saturated_request()
        channel_headers: list[str] = []
        for module, channel in (
            (qq_runtime, "qq"),
            (telegram_runtime, "telegram"),
        ):
            with self.subTest(channel=channel):
                capture = _CaptureConnection()
                with patch.object(module, "HTTPConnection", return_value=capture):
                    config = _runtime_config(module, channel)
                    client = module.LoopbackCoreClient(
                        config,
                        b"synthetic-token",
                    )
                    client.chat(messages, decision=_decision(module, channel))
                self.assertEqual(len(capture.requests), 1)
                recorded = capture.requests[0]
                self.assertEqual(recorded["method"], "POST")
                self.assertEqual(recorded["path"], "/v1/chat")
                channel_headers.append(recorded["headers"]["X-Myuna-Channel-Kind"])
                self.assertEqual(
                    recorded["headers"]["X-Myuna-Channel-Kind"],
                    module.CHANNEL_KIND,
                )
                decoded = json.loads(recorded["body"].decode("utf-8"))
                self.assertEqual(
                    set(decoded), {"authenticated_context", "conversation"}
                )
                self.assertEqual(decoded["conversation"]["messages"], messages)
                self.assertEqual(
                    len(decoded["conversation"]["messages"]),
                    SATURATED_REQUEST_MESSAGES,
                )
                context = decoded["authenticated_context"]
                self.assertEqual(context["channel_kind"], module.CHANNEL_KIND)
                self.assertEqual(context["principal_id"], config.principal_id)
                serialized = recorded["body"].decode("utf-8")
                for forbidden in (
                    "account_fingerprint", "nonce_fingerprint", "payload_sha256"
                ):
                    self.assertNotIn(forbidden, serialized)
                self.assertLessEqual(len(recorded["body"]), PROFILE_HTTP_MAX_BODY_BYTES)
        self.assertEqual(set(channel_headers), {"astrbot_qq", "astrbot_telegram"})

    def test_sanitized_offline_gate_passes(self) -> None:
        report = run_offline_gate()
        self.assertEqual(report["result"], "passed")
        self.assertTrue(all(report["checks"].values()))


if __name__ == "__main__":
    unittest.main()
