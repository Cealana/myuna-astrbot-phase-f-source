from __future__ import annotations

import unittest

from myuna_core.owner_profile import OwnerProfileError
from myuna_core.owner_profile.loader import parse_profile_bytes
from myuna_core.owner_profile.protocol import (
    BOUNDARY,
    OPERATION,
    ProfileProtocolError,
    build_response,
    parse_request,
    parse_response,
)
from myuna_core.owner_profile.retrieval import OwnerProfileIndex
from test_owner_profile_v1_loader import BASE_PROFILE


def request_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": 1,
        "operation": OPERATION,
        "request_id": "req-1",
        "boundary": BOUNDARY,
        "channel_kind": "astrbot_telegram",
        "query": "fictional camera preference",
        "timeout_ms": 500,
    }
    payload.update(overrides)
    return payload


class OwnerProfileProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.index = OwnerProfileIndex(parse_profile_bytes(BASE_PROFILE))

    def test_round_trip_is_bounded_read_only_and_cited(self) -> None:
        request = parse_request(request_payload())
        response = build_response(request, self.index)
        result = parse_response(
            response,
            expected_request_id="req-1",
            expected_channel_kind="astrbot_telegram",
            expected_query_characters=len(str(request["query"])),
        )
        self.assertEqual(result.state, "selected")
        self.assertLessEqual(len(result.sections), 3)
        self.assertIsNotNone(result.context)
        self.assertLessEqual(len(result.context or ""), 6000)
        self.assertIn("@sha256:", result.sections[0].source_ref)
        self.assertFalse(response["model_called"])
        self.assertFalse(response["memory_write_performed"])
        self.assertFalse(response["legacy_namespace_written"])

    def test_empty_result_has_no_context(self) -> None:
        request = parse_request(request_payload(query="unrelated nebulous topic"))
        result = parse_response(
            build_response(request, self.index),
            expected_request_id="req-1",
            expected_channel_kind="astrbot_telegram",
            expected_query_characters=len(str(request["query"])),
        )
        self.assertEqual(result.state, "empty")
        self.assertIsNone(result.context)

    def test_unknown_channel_and_unsafe_timeout_fail_closed(self) -> None:
        for overrides in (
            {"channel_kind": "loopback_dev"},
            {"timeout_ms": 49},
            {"timeout_ms": 3001},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(ProfileProtocolError):
                    parse_request(request_payload(**overrides))

    def test_response_tampering_is_rejected(self) -> None:
        request = parse_request(request_payload())
        response = build_response(request, self.index)
        response["model_called"] = True
        with self.assertRaises(ProfileProtocolError):
            parse_response(
                response,
                expected_request_id="req-1",
                expected_channel_kind="astrbot_telegram",
                expected_query_characters=len(str(request["query"])),
            )

    def test_worker_error_preserves_typed_fail_closed_result(self) -> None:
        with self.assertRaises(OwnerProfileError) as caught:
            parse_response(
                {
                    "schema_version": 1,
                    "operation": OPERATION,
                    "ok": False,
                    "request_id": "req-1",
                    "error": {"code": "profile_unavailable", "retryable": True},
                },
                expected_request_id="req-1",
                expected_channel_kind="astrbot_telegram",
                expected_query_characters=10,
            )
        self.assertEqual(caught.exception.code, "profile_unavailable")
        self.assertTrue(caught.exception.retryable)


if __name__ == "__main__":
    unittest.main()
