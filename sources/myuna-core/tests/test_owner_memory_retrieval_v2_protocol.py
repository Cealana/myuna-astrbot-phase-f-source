from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import unittest

from owner_memory_retrieval_v2.protocol import (
    BOUNDARY,
    OPERATION,
    handle_request_bytes,
    parse_request,
)


NOW = datetime(2026, 7, 21, 1, tzinfo=timezone.utc)


def request(query: str, **extra: object) -> bytes:
    payload = {
        "schema_version": 2,
        "operation": OPERATION,
        "request_id": "request-v2-1",
        "boundary": BOUNDARY,
        "query": query,
    }
    payload.update(extra)
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def record(
    *,
    sensitivity: str = "normal",
    namespace: str = "ns-owner-cealana-private",
) -> dict[str, object]:
    return {
        "candidate_id": "M001",
        "namespace_id": namespace,
        "memory_kind": "preference",
        "subtype": "memory_anchor_preference",
        "memory_status": "confirmed",
        "confirmation_level": "user_confirmed",
        "importance": 0.95,
        "sensitivity": sensitivity,
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


class ProtocolTests(unittest.TestCase):
    def test_v2_request_does_not_accept_core_selected_mode(self) -> None:
        payload = json.loads(request("长期记忆怎样保留重要事情"))
        payload["mode"] = "deep"
        with self.assertRaises(ValueError):
            parse_request(payload)

    def test_protocol_returns_plan_and_one_matching_record(self) -> None:
        response = json.loads(
            handle_request_bytes(
                request("我希望长期记忆怎样保留重要的事情？"),
                records=[record()],
                at=NOW,
            )
        )
        self.assertTrue(response["ok"])
        self.assertEqual(response["hit_ids"], ["M001"])
        self.assertEqual(response["plan"]["horizon_used"], "deep")
        self.assertFalse(response["model_called"])
        self.assertFalse(response["memory_write_performed"])
        self.assertFalse(response["restricted_included"])

    def test_restricted_record_is_absent_from_protocol_response(self) -> None:
        response = json.loads(
            handle_request_bytes(
                request("我希望长期记忆怎样保留重要的事情？"),
                records=[record(sensitivity="restricted")],
                at=NOW,
            )
        )
        self.assertEqual(response["records"], [])
        self.assertEqual(response["hit_ids"], [])

    def test_error_response_never_echoes_query(self) -> None:
        secret = "不应该出现在错误响应中的正文"
        response = handle_request_bytes(
            json.dumps({"query": secret}, ensure_ascii=False).encode("utf-8"),
            records=[],
            at=NOW,
        ).decode("utf-8")
        self.assertNotIn(secret, response)
        self.assertIn("invalid_request", response)


if __name__ == "__main__":
    unittest.main()
