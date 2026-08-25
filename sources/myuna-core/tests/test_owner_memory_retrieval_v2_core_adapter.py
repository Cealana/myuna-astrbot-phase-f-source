from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import unittest

from owner_memory_retrieval_v2.core_adapter import (
    CoreAdapterError,
    parse_response,
    render_context,
)
from owner_memory_retrieval_v2.protocol import BOUNDARY, OPERATION, build_response


NOW = datetime(2026, 7, 21, 1, tzinfo=timezone.utc)


def record() -> dict[str, object]:
    return {
        "candidate_id": "M001",
        "namespace_id": "ns-owner-cealana-private",
        "memory_kind": "preference",
        "subtype": "memory_anchor_preference",
        "memory_status": "confirmed",
        "confirmation_level": "user_confirmed",
        "importance": 0.95,
        "sensitivity": "normal",
        "assertion_text": "重要记忆应保留完整背景。",
        "event_text": None,
        "exact_quote": None,
        "occurred_at": (NOW - timedelta(days=6)).isoformat(),
        "time_precision": "day",
        "time_phrase": "凌晨",
        "scope": ["global", "owner_private"],
        "tags": ["memory", "recollection", "anchor_preference"],
        "rationales": [],
        "anchors": [],
        "relations": [],
        "review_items": [],
    }


def response() -> dict[str, object]:
    return build_response(
        {
            "request_id": "request-v2-1",
            "query": "我希望长期记忆怎样保留重要的事情？",
        },
        [record()],
        at=NOW,
    )


class CoreAdapterTests(unittest.TestCase):
    def test_valid_response_is_rendered_without_internal_id(self) -> None:
        parsed = parse_response(response(), expected_request_id="request-v2-1")
        self.assertEqual(parsed.hit_ids, ("M001",))
        context = render_context(parsed)
        assert context is not None
        self.assertIn("重要记忆应保留完整背景", context)
        self.assertNotIn("M001", context)

    def test_hit_id_mismatch_is_rejected(self) -> None:
        payload = response()
        payload["hit_ids"] = ["M999"]
        with self.assertRaises(CoreAdapterError):
            parse_response(payload, expected_request_id="request-v2-1")

    def test_restricted_response_is_rejected_even_if_worker_claims_safe(self) -> None:
        payload = response()
        payload["records"][0]["sensitivity"] = "restricted"
        with self.assertRaises(CoreAdapterError):
            parse_response(payload, expected_request_id="request-v2-1")

    def test_error_response_is_typed_and_content_free(self) -> None:
        payload = {
            "schema_version": 2,
            "operation": OPERATION,
            "ok": False,
            "request_id": "request-v2-1",
            "error": {"code": "worker_unavailable", "retryable": True},
        }
        with self.assertRaises(CoreAdapterError) as captured:
            parse_response(payload, expected_request_id="request-v2-1")
        self.assertTrue(captured.exception.retryable)
        self.assertEqual(captured.exception.code, "worker_unavailable")
        self.assertNotIn("query", json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
