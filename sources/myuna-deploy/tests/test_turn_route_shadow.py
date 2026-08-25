from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from turn_route_enqueue import (  # noqa: E402
    build_turn_route_event,
    enqueue_turn_route_after_reply,
)
from turn_route_shadow.hybrid_classifier import classify  # noqa: E402
from turn_route_shadow.metadata_shadow import assert_metadata_only  # noqa: E402
from turn_route_shadow.worker import (  # noqa: E402
    JsonlTraceSink,
    LoopbackModelClient,
    ModelUnavailable,
    WorkerConfig,
    handle_event,
    parse_event,
)


NOW = datetime(2026, 7, 20, 6, 0, tzinfo=timezone.utc)
MODEL_SHA256 = "13c16f426047e2de38cd075bdade4a7bcbc8c774384876f677740cda65f8a983"


class ListSink:
    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    def append(self, trace) -> None:
        self.rows.append(json.loads(json.dumps(dict(trace))))


class RaisingSink:
    def append(self, _trace) -> None:
        raise OSError("synthetic sink failure")


def event(text: str, actual_route: str = "deepseek_default") -> bytes:
    return build_turn_route_event(
        str(uuid4()),
        text,
        actual_route,
        monotonic_ns=123456789,
    )


def config(**overrides) -> WorkerConfig:
    payload = {
        "schema_version": 1,
        "model_enabled": False,
        "model_endpoint": "http://127.0.0.1:18093",
        "model_timeout_ms": 2000,
        "model_id": "Qwen3.5-4B-Q4_K_M",
        "expected_model_sha256": MODEL_SHA256,
        "trace_retention_days": 7,
    }
    payload.update(overrides)
    return WorkerConfig.from_payload(payload)


class TurnRouteShadowTests(unittest.TestCase):
    def test_event_schema_is_exact_and_content_is_transient(self) -> None:
        raw = event("synthetic private text")
        parsed = parse_event(raw)
        self.assertEqual(parsed.query, "synthetic private text")
        self.assertEqual(parsed.event_count, 1)
        payload = json.loads(raw)
        payload["message_text"] = "forbidden extra field"
        with self.assertRaisesRegex(ValueError, "invalid_event"):
            parse_event(json.dumps(payload).encode())

    def test_count_route_and_uuid_mismatches_fail_closed(self) -> None:
        base = json.loads(event("synthetic"))
        mutations = (
            {"input_character_count": 999},
            {"event_count": 2},
            {"actual_route": "deepseek-secret-model"},
            {"request_uuid": "not-a-uuid"},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                payload = dict(base)
                payload.update(mutation)
                with self.assertRaisesRegex(ValueError, "invalid_event"):
                    parse_event(json.dumps(payload).encode())

        for boolean_field in ("schema_version", "input_character_count", "event_count"):
            with self.subTest(boolean_field=boolean_field):
                payload = dict(base)
                payload[boolean_field] = True
                with self.assertRaisesRegex(ValueError, "invalid_event"):
                    parse_event(json.dumps(payload).encode())

    def test_missing_or_full_socket_is_one_safe_nonblocking_drop(self) -> None:
        request_uuid = str(uuid4())
        missing = enqueue_turn_route_after_reply(
            "/run/does-not-exist/turn-route-shadow.sock",
            request_uuid,
            "synthetic",
            "unknown",
        )
        self.assertEqual(missing, "unavailable")

        class FullSocket:
            def __init__(self) -> None:
                self.nonblocking = False
                self.send_calls = 0

            def setblocking(self, enabled: bool) -> None:
                self.nonblocking = not enabled

            def connect(self, _path: str) -> None:
                return None

            def send(self, _payload: bytes) -> None:
                self.send_calls += 1
                raise BlockingIOError("synthetic full queue")

            def close(self) -> None:
                return None

        full = FullSocket()
        with patch("turn_route_enqueue.socket.socket", return_value=full):
            result = enqueue_turn_route_after_reply(
                "/run/synthetic.sock",
                request_uuid,
                "synthetic",
                "unknown",
            )
        self.assertEqual(result, "unavailable")
        self.assertTrue(full.nonblocking)
        self.assertEqual(full.send_calls, 1)

    def test_frozen_rules_bypass_model_for_clear_high_risk_request(self) -> None:
        calls: list[str] = []

        def model_call(group, text):
            calls.append(group)
            return "A"

        sink = ListSink()
        outcome = handle_event(
            event("请帮我修改防火墙并开放公网管理端口"),
            model_call=model_call,
            sink=sink,
            observed_at=NOW,
        )
        self.assertIsNone(outcome.safe_error_class)
        self.assertEqual(calls, [])
        self.assertEqual([row["decision_label"] for row in sink.rows], ["B", "D"])
        self.assertEqual([row["decision_source"] for row in sink.rows], ["rule", "rule"])

    def test_ambiguous_model_advice_creates_metadata_only_traces(self) -> None:
        labels = {"turn": "C", "route": "B"}
        sink = ListSink()
        outcome = handle_event(
            event("我们也许可以再想想这个"),
            model_call=lambda group, _text: labels[group],
            sink=sink,
            observed_at=NOW,
        )
        self.assertIsNone(outcome.safe_error_class)
        self.assertEqual(len(outcome.traces), 2)
        self.assertEqual(len(sink.rows), 2)
        for trace in sink.rows:
            assert_metadata_only(trace)
            encoded = json.dumps(trace, ensure_ascii=False).casefold()
            self.assertNotIn("我们也许可以再想想这个", encoded)
            self.assertNotIn("input_sha", encoded)
            self.assertNotIn("message_text", encoded)
            self.assertNotIn("account", encoded)
            self.assertEqual(trace["production_effect"], "none")
        self.assertFalse(sink.rows[0]["reply_suppressed"])
        self.assertFalse(sink.rows[0]["reply_delayed"])
        self.assertFalse(sink.rows[1]["provider_switched"])

    def test_model_unavailable_falls_back_without_escaping(self) -> None:
        def unavailable(_group, _text):
            raise ModelUnavailable("synthetic unavailable")

        sink = ListSink()
        outcome = handle_event(
            event("我们也许可以再想想这个", "unknown"),
            model_call=unavailable,
            sink=sink,
            observed_at=NOW,
        )
        self.assertIsNone(outcome.safe_error_class)
        self.assertEqual([row["decision_label"] for row in sink.rows], ["B", "D"])
        self.assertEqual(
            [row["reason_code"] for row in sink.rows],
            ["model_unavailable", "model_unavailable"],
        )
        self.assertTrue(all(row["model_valid"] is False for row in sink.rows))

    def test_invalid_model_labels_use_the_same_conservative_fallback(self) -> None:
        for group, expected in (("turn", "B"), ("route", "D")):
            with self.subTest(group=group):
                decision = classify(group, "模糊的合成输入", lambda *_: "INVALID")
                self.assertEqual(decision.label, expected)
                self.assertEqual(decision.source, "fallback")
                self.assertEqual(decision.reason, "invalid_model_label")
                self.assertFalse(decision.model_valid)

    def test_invalid_event_and_sink_failure_are_safe_drops(self) -> None:
        invalid = handle_event(
            b"not-json",
            model_call=lambda *_: "B",
            sink=ListSink(),
            observed_at=NOW,
        )
        self.assertEqual(invalid.safe_error_class, "invalid_event")
        self.assertEqual(invalid.traces, ())
        failed = handle_event(
            event("模糊的合成输入"),
            model_call=lambda group, _text: "B" if group == "turn" else "C",
            sink=RaisingSink(),
            observed_at=NOW,
        )
        self.assertEqual(failed.safe_error_class, "metadata_sink_unavailable")
        self.assertEqual(failed.production_effect, "none")

    def test_jsonl_sink_writes_ascii_metadata_only(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            sink = JsonlTraceSink(path)
            handle_event(
                event("synthetic only"),
                model_call=lambda group, _text: "B" if group == "turn" else "C",
                sink=sink,
                observed_at=NOW,
            )
            raw = path.read_bytes()
            raw.decode("ascii")
            rows = [json.loads(line) for line in raw.splitlines()]
            self.assertEqual(len(rows), 2)
            for row in rows:
                assert_metadata_only(row)

    def test_config_is_pinned_disabled_and_loopback_only(self) -> None:
        current = config()
        self.assertFalse(current.model_enabled)
        self.assertEqual(current.trace_retention_days, 7)
        self.assertEqual(current.model_endpoint, "http://127.0.0.1:18093")
        with self.assertRaisesRegex(ValueError, "invalid_config"):
            config(model_endpoint="http://0.0.0.0:18093")
        with self.assertRaisesRegex(ValueError, "invalid_config"):
            config(trace_retention_days=30)
        with self.assertRaises(ModelUnavailable):
            LoopbackModelClient(current)("turn", "synthetic")


if __name__ == "__main__":
    unittest.main()
