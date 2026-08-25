from __future__ import annotations

import json
import unittest

from myuna_core.owner_profile.loader import parse_profile_bytes
from myuna_core.owner_profile.protocol import BOUNDARY, OPERATION
from myuna_core.owner_profile.retrieval import OwnerProfileIndex
from myuna_core.owner_profile.socket_worker import (
    process_request,
    serve_connection,
)
from test_owner_profile_v1_loader import BASE_PROFILE


class OwnerProfileSocketWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.index = OwnerProfileIndex(parse_profile_bytes(BASE_PROFILE))

    def request(self, **overrides: object) -> bytes:
        payload: dict[str, object] = {
            "schema_version": 1,
            "operation": OPERATION,
            "request_id": "worker-req-1",
            "boundary": BOUNDARY,
            "channel_kind": "astrbot_telegram",
            "query": "fictional camera preference",
            "timeout_ms": 500,
        }
        payload.update(overrides)
        return json.dumps(payload).encode("utf-8")

    def test_process_request_returns_strict_read_only_response(self) -> None:
        response = json.loads(process_request(self.request(), index=self.index))
        self.assertTrue(response["ok"])
        self.assertEqual(response["request_id"], "worker-req-1")
        self.assertFalse(response["model_called"])
        self.assertFalse(response["memory_write_performed"])
        self.assertFalse(response["legacy_namespace_written"])

    def test_malformed_content_and_unknown_channel_are_content_free_errors(self) -> None:
        for payload in (
            b"not-json",
            self.request(channel_kind="unknown"),
        ):
            with self.subTest(payload=payload[:16]):
                response = json.loads(process_request(payload, index=self.index))
                self.assertFalse(response["ok"])
                self.assertEqual(response["error"]["code"], "invalid_request")
                encoded = json.dumps(response, sort_keys=True)
                self.assertNotIn("fictional camera preference", encoded)

    def test_timeout_is_typed_and_returns_no_sections(self) -> None:
        response = json.loads(
            process_request(self.request(timeout_ms=50), index=self.index)
        )
        self.assertTrue(response["ok"])
        self.assertLessEqual(len(response["sections"]), 3)

    def test_dynamic_index_is_loaded_for_every_request(self) -> None:
        calls = 0

        def load_index() -> OwnerProfileIndex:
            nonlocal calls
            calls += 1
            return self.index

        for _ in range(2):
            response = json.loads(
                process_request(self.request(), index_loader=load_index)
            )
            self.assertTrue(response["ok"])
        self.assertEqual(calls, 2)

    def test_dynamic_index_failure_is_content_free(self) -> None:
        def unavailable() -> OwnerProfileIndex:
            raise RuntimeError("synthetic selector failure")

        response = json.loads(
            process_request(self.request(), index_loader=unavailable)
        )
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "profile_unavailable")
        self.assertNotIn("synthetic selector failure", json.dumps(response))

    def test_connection_timeout_is_content_free_and_does_not_escape(self) -> None:
        class TimedOutConnection:
            def __init__(self) -> None:
                self.timeout = None
                self.response = b""

            def settimeout(self, value: float) -> None:
                self.timeout = value

            def recv(self, _size: int) -> bytes:
                raise TimeoutError

            def sendall(self, payload: bytes) -> None:
                self.response += payload

        connection = TimedOutConnection()
        serve_connection(connection, index=self.index)  # type: ignore[arg-type]
        response = json.loads(connection.response)
        self.assertEqual(connection.timeout, 3.0)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "profile_timeout")
        self.assertNotIn("fictional camera preference", connection.response.decode())


if __name__ == "__main__":
    unittest.main()
