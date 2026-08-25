from __future__ import annotations

from pathlib import Path
import sys
import unittest
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT.parent / "core" / "src"))

import gateway_post_reply as post_reply  # noqa: E402
import qq_owner_runtime_gateway as runtime  # noqa: E402


class FakeConnection:
    def __init__(self) -> None:
        self.entered = False
        self.closed = False

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.closed = True


def job() -> post_reply.PostReplyObservationJob:
    return post_reply.PostReplyObservationJob(
        request_uuid=str(uuid4()),
        query="synthetic owner message",
        actual_route="deepseek_default",
    )


class GatewayPostReplyFanoutTests(unittest.TestCase):
    def test_core_metadata_maps_only_to_bounded_route_enums(self) -> None:
        cases = (
            ({"provider": "deepseek", "model": "deepseek-v4-flash"}, "deepseek_default"),
            ({"provider": "deepseek", "model": "deepseek-v4-pro"}, "deepseek_pro"),
            ({"provider": "future", "model": "secret-internal-name"}, "unknown"),
            ({}, "unknown"),
        )
        for payload, expected in cases:
            with self.subTest(payload=payload):
                self.assertEqual(runtime.bounded_actual_route(payload), expected)

    def test_both_sinks_run_only_after_reply_connection_closes(self) -> None:
        connection = FakeConnection()
        calls: list[str] = []

        def process(active_connection):
            self.assertTrue(active_connection.entered)
            self.assertFalse(active_connection.closed)
            return job()

        def memory_enqueue(socket_path, request_uuid, query):
            self.assertTrue(connection.closed)
            self.assertEqual(socket_path, post_reply.MEMORY_SHADOW_SOCKET)
            calls.append("memory")
            return "enqueued"

        def turn_route_enqueue(socket_path, request_uuid, query, actual_route):
            self.assertTrue(connection.closed)
            self.assertEqual(socket_path, post_reply.TURN_ROUTE_SHADOW_SOCKET)
            self.assertEqual(actual_route, "deepseek_default")
            calls.append("turn_route")
            return "enqueued"

        post_reply.serve_accepted_connection(
            connection,
            process,
            marker_check=lambda _: True,
            enqueue=memory_enqueue,
            turn_route_enqueue=turn_route_enqueue,
        )
        self.assertEqual(calls, ["memory", "turn_route"])

    def test_memory_failure_cannot_block_turn_route(self) -> None:
        calls: list[str] = []

        def broken_memory(*_args):
            calls.append("memory")
            raise OSError("synthetic failure")

        def turn_route(*_args):
            calls.append("turn_route")
            return "enqueued"

        post_reply.serve_accepted_connection(
            FakeConnection(),
            lambda _: job(),
            marker_check=lambda _: True,
            enqueue=broken_memory,
            turn_route_enqueue=turn_route,
        )
        self.assertEqual(calls, ["memory", "turn_route"])

    def test_turn_route_failure_cannot_escape_or_repeat_memory(self) -> None:
        calls: list[str] = []

        def memory(*_args):
            calls.append("memory")
            return "enqueued"

        def broken_turn_route(*_args):
            calls.append("turn_route")
            raise TimeoutError("synthetic failure")

        post_reply.serve_accepted_connection(
            FakeConnection(),
            lambda _: job(),
            marker_check=lambda _: True,
            enqueue=memory,
            turn_route_enqueue=broken_turn_route,
        )
        self.assertEqual(calls, ["memory", "turn_route"])

    def test_marker_errors_disable_only_the_matching_sink(self) -> None:
        calls: list[str] = []

        def marker_check(path: str) -> bool:
            if "memory" in path:
                raise OSError("synthetic marker failure")
            return True

        post_reply.serve_accepted_connection(
            FakeConnection(),
            lambda _: job(),
            marker_check=marker_check,
            enqueue=lambda *_: calls.append("memory") or "enqueued",
            turn_route_enqueue=lambda *_: calls.append("turn_route") or "enqueued",
        )
        self.assertEqual(calls, ["turn_route"])

    def test_disabled_markers_and_missing_job_have_no_fanout(self) -> None:
        calls: list[str] = []
        for process in (lambda _: job(), lambda _: None):
            post_reply.serve_accepted_connection(
                FakeConnection(),
                process,
                marker_check=lambda _: False,
                enqueue=lambda *_: calls.append("memory") or "enqueued",
                turn_route_enqueue=lambda *_: calls.append("turn_route") or "enqueued",
            )
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
