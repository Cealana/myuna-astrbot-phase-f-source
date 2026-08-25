from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import unittest

from owner_memory_retrieval_v2.postgres_source import RecordSourceError
from owner_memory_retrieval_v2.socket_worker import process_request


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


def request() -> bytes:
    return json.dumps(
        {
            "schema_version": 2,
            "operation": "owner_memory.retrieve_v2",
            "request_id": "r2-worker-test",
            "boundary": "verified_owner_private_text",
            "query": "我希望长期记忆怎样保留重要的事情？",
        },
        ensure_ascii=False,
    ).encode("utf-8")


class SocketWorkerTests(unittest.TestCase):
    def test_valid_request_uses_v2_without_model_or_write(self) -> None:
        response = json.loads(process_request(request(), records=[record()], at=NOW))
        self.assertTrue(response["ok"])
        self.assertEqual(response["hit_ids"], ["M001"])
        self.assertFalse(response["model_called"])
        self.assertFalse(response["memory_write_performed"])
        self.assertFalse(response["restricted_included"])

    def test_invalid_request_never_calls_loader(self) -> None:
        called = False

        def loader() -> list[dict[str, object]]:
            nonlocal called
            called = True
            return []

        response = json.loads(process_request(b"{}", loader=loader, at=NOW))
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")
        self.assertFalse(called)

    def test_source_error_is_typed_and_content_free(self) -> None:
        def loader() -> list[dict[str, object]]:
            raise RecordSourceError("safe_view_unavailable", retryable=True)

        encoded = process_request(request(), loader=loader, at=NOW)
        response = json.loads(encoded)
        self.assertEqual(response["request_id"], "r2-worker-test")
        self.assertEqual(response["error"]["code"], "safe_view_unavailable")
        self.assertTrue(response["error"]["retryable"])
        self.assertNotIn("长期记忆", encoded.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
