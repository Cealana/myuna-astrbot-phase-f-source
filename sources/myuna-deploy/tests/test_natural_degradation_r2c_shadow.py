from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
CORE_SRC = ROOT.parent / "core" / "src"
if not CORE_SRC.is_dir():
    CORE_SRC = ROOT.parent / "core-tree" / "src"
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(CORE_SRC))

from degradation_shadow.worker import (  # noqa: E402
    TRACE_FIELDS,
    handle_event,
)
from degradation_shadow_enqueue import (  # noqa: E402
    DegradationShadowJob,
    build_degradation_shadow_event,
    build_fault_incident_receipt,
    write_fault_incident_receipt_after_response,
)
import gateway_degradation_protocol as protocol  # noqa: E402
import gateway_post_reply as post_reply  # noqa: E402
import qq_owner_runtime_gateway as runtime  # noqa: E402
from myuna_core.degradation_bridge import CoreFailureCode  # noqa: E402
from myuna_core.degradation_http import (  # noqa: E402
    attach_core_failure_metadata,
    attach_provider_failure_metadata,
)


NOW = datetime(2026, 7, 22, 7, 30, tzinfo=timezone.utc)
REQUEST_ID = "11111111-2222-4333-8444-555555555555"


class FakeConnection:
    def __init__(self) -> None:
        self.entered = False
        self.closed = False

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.closed = True


class ListSink:
    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    def append(self, trace) -> None:
        self.rows.append(dict(trace))


def _config() -> runtime.RuntimeConfig:
    return runtime.RuntimeConfig(
        binding_id="binding-test",
        principal_id="principal-test",
        namespace_id="namespace-test",
        finalization_digest="a" * 64,
        evidence_sha256="b" * 64,
        channel_instance="napcat-dev",
        core_host="127.0.0.1",
        core_port=18081,
        max_requests_per_ten_minutes=12,
        max_history_messages=12,
        max_history_characters=12000,
    )


def _decision() -> runtime.RuntimeDecision:
    return runtime.RuntimeDecision(
        event_id="event-synthetic-degradation",
        channel_kind="astrbot_qq",
        channel_instance="napcat-dev",
        conversation_id="conversation-synthetic-degradation",
        occurred_at=NOW,
        nonce_fingerprint="c" * 64,
        payload_sha256="d" * 64,
        trace_id="trace-synthetic-degradation",
        account_fingerprint="e" * 64,
        message_text="private",
    )


def _core_payload(case: dict[str, object]) -> dict[str, object]:
    base: dict[str, object] = {"error": case["error"]}
    if case["error"] == "provider_unavailable":
        base["retryable"] = case.get("legacy_retryable", case["retryable"])
        return attach_provider_failure_metadata(
            base,
            request_id=REQUEST_ID,
            provider_code=str(case["provider_code"]),
            observed_at=NOW,
        )
    return attach_core_failure_metadata(
        base,
        request_id=REQUEST_ID,
        code=CoreFailureCode(str(case["core_code"])),
        observed_at=NOW,
    )


class NaturalDegradationR2CShadowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.golden = json.loads(
            (
                ROOT
                / "tests/fixtures/natural_degradation_r2c_shadow_golden.json"
            ).read_text(encoding="utf-8")
        )

    def test_core_and_gateway_projections_match_golden(self) -> None:
        for case in self.golden["cases"]:
            with self.subTest(case=case):
                if case["source"] == "core":
                    projection = protocol.validate_core_failure_response(
                        case["http_status"],
                        _core_payload(case),
                    )
                else:
                    projection = protocol.deterministic_gateway_projection(
                        case["detail"]
                    )
                self.assertEqual(projection["category"], case["category"])
                self.assertEqual(
                    projection["safe_detail_code"],
                    case["detail"],
                )
                self.assertIs(projection["retryable"], case["retryable"])
                self.assertIs(
                    projection["owner_action_required"],
                    case["owner_action_required"],
                )

    def test_core_response_validation_is_closed_and_cross_checked(self) -> None:
        case = self.golden["cases"][0]
        payload = _core_payload(case)
        with self.assertRaises(protocol.GatewayDegradationProtocolError):
            protocol.validate_core_failure_response(
                case["http_status"],
                {**payload, "raw_error": "forbidden"},
            )
        with self.assertRaises(protocol.GatewayDegradationProtocolError):
            protocol.validate_core_failure_response(418, payload)
        tampered = json.loads(json.dumps(payload))
        tampered["safe_degradation"]["owner_action_required"] = True
        with self.assertRaises(protocol.GatewayDegradationProtocolError):
            protocol.validate_core_failure_response(case["http_status"], tampered)

    def test_shadow_event_and_trace_contain_no_conversation_content(self) -> None:
        phrase = "这一段绝对不能出现在 Shadow 里"
        projection = protocol.deterministic_core_unreachable_projection()
        job = DegradationShadowJob.from_projection(
            projection,
            projection_source="gateway",
            channel="qq",
            request_id=REQUEST_ID,
            observation_uuid=str(uuid4()),
        )
        datagram = build_degradation_shadow_event(job, monotonic_ns=1_000_000)
        self.assertNotIn(phrase.encode("utf-8"), datagram)
        self.assertNotIn(str(projection["reply"]).encode("utf-8"), datagram)
        sink = ListSink()
        outcome = handle_event(
            datagram,
            sink=sink,
            observed_at=NOW,
            monotonic_ns=2_000_000,
        )
        self.assertTrue(outcome.trace_written)
        self.assertIsNone(outcome.safe_error_class)
        self.assertEqual(len(sink.rows), 1)
        trace = sink.rows[0]
        self.assertEqual(set(trace), TRACE_FIELDS)
        self.assertIs(trace["shadow_only"], True)
        self.assertEqual(trace["production_effect"], "none")
        self.assertEqual(trace["legacy_visible_path"], "unchanged")
        encoded = json.dumps(trace, ensure_ascii=False)
        self.assertNotIn(phrase, encoded)
        self.assertNotIn(str(projection["reply"]), encoded)

    def test_invalid_shadow_event_is_dropped_without_trace(self) -> None:
        sink = ListSink()
        outcome = handle_event(b'{"message_text":"forbidden"}', sink=sink)
        self.assertFalse(outcome.trace_written)
        self.assertEqual(outcome.safe_error_class, "invalid_event")
        self.assertEqual(sink.rows, [])

    def test_degradation_fanout_runs_only_after_legacy_connection_closes(self) -> None:
        connection = FakeConnection()
        projection = protocol.deterministic_core_unreachable_projection()
        degradation = DegradationShadowJob.from_projection(
            projection,
            projection_source="gateway",
            channel="qq",
            request_id=REQUEST_ID,
        )
        calls: list[str] = []

        def enqueue(socket_path, job):
            self.assertTrue(connection.closed)
            self.assertEqual(socket_path, post_reply.DEGRADATION_SHADOW_SOCKET)
            self.assertEqual(job, degradation)
            calls.append("degradation")
            return "enqueued"

        def write_receipt(job):
            self.assertTrue(connection.closed)
            self.assertEqual(job, degradation)
            calls.append("receipt")
            return "written"

        post_reply.serve_accepted_connection(
            connection,
            lambda _: post_reply.PostConnectionFanout(degradation=degradation),
            marker_check=lambda path: "natural-degradation" in path,
            enqueue=lambda *_: calls.append("memory") or "enqueued",
            turn_route_enqueue=lambda *_: calls.append("turn_route") or "enqueued",
            degradation_enqueue=enqueue,
            fault_receipt_write=write_receipt,
        )
        self.assertEqual(calls, ["receipt", "degradation"])

    def test_shadow_failure_cannot_change_or_repeat_the_legacy_path(self) -> None:
        projection = protocol.deterministic_gateway_projection(
            "gateway-owner-rate-limited"
        )
        degradation = DegradationShadowJob.from_projection(
            projection,
            projection_source="gateway",
            channel="telegram",
            request_id=REQUEST_ID,
        )
        calls: list[str] = []

        def broken(*_args):
            calls.append("degradation")
            raise OSError("synthetic Shadow failure")

        post_reply.serve_accepted_connection(
            FakeConnection(),
            lambda _: post_reply.PostConnectionFanout(degradation=degradation),
            marker_check=lambda _: True,
            degradation_enqueue=broken,
            fault_receipt_write=lambda _: "written",
        )
        self.assertEqual(calls, ["degradation"])

    def test_fault_receipt_is_content_free_atomic_and_channel_scoped(self) -> None:
        projection = protocol.deterministic_core_unreachable_projection()
        job = DegradationShadowJob.from_projection(
            projection,
            projection_source="gateway",
            channel="telegram",
            request_id=REQUEST_ID,
        )
        encoded = build_fault_incident_receipt(job, observed_at=NOW)
        self.assertNotIn(str(projection["reply"]).encode("utf-8"), encoded)
        receipt = json.loads(encoded)
        self.assertEqual(receipt["channel"], "telegram")
        self.assertRegex(receipt["incident_ref"], r"^inc-[0-9a-f]{12}$")
        self.assertIs(receipt["private_content_written"], False)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "telegram").mkdir()
            result = write_fault_incident_receipt_after_response(
                job,
                receipt_root=root,
            )
            self.assertEqual(result, "written")
            persisted = json.loads((root / "telegram/last.json").read_text())
            self.assertEqual(
                {key: value for key, value in persisted.items() if key != "observed_at"},
                {key: value for key, value in receipt.items() if key != "observed_at"},
            )

    def test_success_path_keeps_existing_observers_and_skips_degradation(self) -> None:
        calls: list[str] = []
        accepted = post_reply.PostReplyObservationJob(
            request_uuid=str(uuid4()),
            query="synthetic",
            actual_route="deepseek_default",
        )
        post_reply.serve_accepted_connection(
            FakeConnection(),
            lambda _: post_reply.PostConnectionFanout(accepted=accepted),
            marker_check=lambda _: True,
            enqueue=lambda *_: calls.append("memory") or "enqueued",
            turn_route_enqueue=lambda *_: calls.append("turn_route") or "enqueued",
            degradation_enqueue=lambda *_: calls.append("degradation") or "enqueued",
        )
        self.assertEqual(calls, ["memory", "turn_route"])

    def test_loopback_client_accepts_only_valid_core_failure_metadata(self) -> None:
        case = self.golden["cases"][1]
        raw = json.dumps(_core_payload(case), ensure_ascii=False).encode("utf-8")

        class Response:
            status = case["http_status"]

            def read(self, _limit):
                return raw

        class Connection:
            def __init__(self, *_args, **_kwargs):
                pass

            def request(self, *_args, **_kwargs):
                pass

            def getresponse(self):
                return Response()

            def close(self):
                pass

        with patch.object(runtime, "HTTPConnection", Connection):
            client = runtime.LoopbackCoreClient(_config(), b"test-token")
            with self.assertRaises(runtime.CoreUnavailable) as caught:
                client.chat(
                    [{"role": "user", "content": "private"}],
                    decision=_decision(),
                )
        self.assertEqual(caught.exception.projection_source, "core")
        self.assertEqual(
            caught.exception.projection["safe_detail_code"],
            case["detail"],
        )

    def test_invalid_core_failure_becomes_fixed_gateway_projection(self) -> None:
        class Response:
            status = 503

            def read(self, _limit):
                return b'{"error":"provider_unavailable","secret":"forbidden"}'

        class Connection:
            def __init__(self, *_args, **_kwargs):
                pass

            def request(self, *_args, **_kwargs):
                pass

            def getresponse(self):
                return Response()

            def close(self):
                pass

        with patch.object(runtime, "HTTPConnection", Connection):
            client = runtime.LoopbackCoreClient(_config(), b"test-token")
            with self.assertRaises(runtime.CoreUnavailable) as caught:
                client.chat(
                    [{"role": "user", "content": "private"}],
                    decision=_decision(),
                )
        self.assertEqual(caught.exception.projection_source, "gateway")
        self.assertEqual(
            caught.exception.projection["safe_detail_code"],
            "gateway-core-invalid-response",
        )
        self.assertNotIn("secret", json.dumps(caught.exception.projection))

    def test_legacy_unavailable_bytes_are_unchanged(self) -> None:
        class SendConnection:
            def __init__(self) -> None:
                self.data = b""

            def sendall(self, data: bytes) -> None:
                self.data += data

        connection = SendConnection()
        runtime._respond(connection, "unavailable")
        self.assertEqual(
            connection.data,
            b'{"code":"owner-runtime-unavailable","status":"rejected"}\n',
        )


if __name__ == "__main__":
    unittest.main()
