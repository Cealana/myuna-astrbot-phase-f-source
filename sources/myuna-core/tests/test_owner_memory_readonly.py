from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from myuna_core.audit import AuditLogger
from myuna_core.memory.owner_readonly import (
    OWNER_BOUNDARY,
    OWNER_MEMORY_POLICY_V1,
    OWNER_NAMESPACE,
    AuditedOwnerMemoryReadAdapter,
    OwnerMemoryReadError,
    OwnerMemoryReadRuntime,
    OwnerMemoryResult,
    classify_owner_memory_mode,
    parse_owner_memory_record,
    parse_owner_memory_response,
)


def record_payload(memory_id: str = "M001") -> dict[str, object]:
    return {
        "memory_id": memory_id,
        "memory_kind": "preference",
        "memory_status": "confirmed",
        "confirmation_level": "user_confirmed",
        "importance": 0.85,
        "sensitivity": "normal",
        "assertion_text": "Cealana 希望重要记忆保留时间与具体经过。",
        "exact_quote": "我真的很喜欢回忆",
        "occurred_at": "2026-07-16T22:30:00+08:00",
        "time_precision": "part_of_day",
        "time_phrase": "晚上",
        "scope": ["memory", "owner"],
        "tags": ["memory", "detail"],
        "rationales": [
            {
                "status": "confirmed",
                "text": "细节和时间能够作为长期记忆锚点。",
            }
        ],
        "anchors": [
            {
                "title": "Owner Memory 初始设计",
                "preservation_note": "保留原话和时间线。",
            }
        ],
    }


def response_payload(
    *,
    request_id: str = "request-1-owner-memory",
    mode: str = "recent",
    records: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "operation": "owner_memory.retrieve",
        "ok": True,
        "request_id": request_id,
        "boundary": OWNER_BOUNDARY,
        "namespace_id": OWNER_NAMESPACE,
        "mode_used": mode,
        "policy_version": OWNER_MEMORY_POLICY_V1,
        "model_called": False,
        "memory_write_performed": False,
        "restricted_included": False,
        "duration_ms": 4.2,
        "records": records if records is not None else [record_payload()],
    }


class StubClient:
    def __init__(self, result: OwnerMemoryResult | None = None) -> None:
        self.result = result
        self.error: OwnerMemoryReadError | None = None

    def retrieve(self, query, *, mode, request_id, timeout_seconds):
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result


class OwnerMemoryReadonlyTests(unittest.TestCase):
    def test_record_contract_accepts_only_normal_user_confirmed_data(self) -> None:
        record = parse_owner_memory_record(record_payload())
        self.assertEqual(record.memory_id, "M001")
        self.assertEqual(record.memory_status, "confirmed")

        restricted = record_payload()
        restricted["sensitivity"] = "restricted"
        with self.assertRaises(OwnerMemoryReadError):
            parse_owner_memory_record(restricted)

        unconfirmed = record_payload()
        unconfirmed["confirmation_level"] = "model_proposed"
        with self.assertRaises(OwnerMemoryReadError):
            parse_owner_memory_record(unconfirmed)

    def test_response_binds_namespace_boundary_policy_and_top_k(self) -> None:
        parsed = parse_owner_memory_response(
            response_payload(),
            expected_request_id="request-1-owner-memory",
            expected_mode="recent",
        )
        self.assertEqual(parsed.records[0].memory_id, "M001")

        wrong_namespace = response_payload()
        wrong_namespace["namespace_id"] = "ns-friend"
        with self.assertRaises(OwnerMemoryReadError):
            parse_owner_memory_response(
                wrong_namespace,
                expected_request_id="request-1-owner-memory",
                expected_mode="recent",
            )

        too_many = response_payload(
            records=[record_payload("M001"), record_payload("M002")]
        )
        with self.assertRaises(OwnerMemoryReadError):
            parse_owner_memory_response(
                too_many,
                expected_request_id="request-1-owner-memory",
                expected_mode="recent",
            )

    def test_runtime_renders_details_without_internal_ids(self) -> None:
        parsed = parse_owner_memory_response(
            response_payload(),
            expected_request_id="request-1-owner-memory",
            expected_mode="recent",
        )
        with TemporaryDirectory() as temporary:
            audit = AuditLogger(Path(temporary), "dev")
            runtime = OwnerMemoryReadRuntime(
                AuditedOwnerMemoryReadAdapter(StubClient(parsed), audit)
            )
            selection = runtime.retrieve(
                "记忆要保留什么细节",
                request_id="request-1-owner-memory",
            )
            self.assertEqual(selection.state, "selected")
            self.assertEqual(selection.hit_ids, ("M001",))
            assert selection.context is not None
            self.assertIn("我真的很喜欢回忆", selection.context)
            self.assertIn("长期记忆锚点", selection.context)
            self.assertNotIn("M001", selection.context)

            raw_audit = audit.path.read_text(encoding="utf-8")
            self.assertIn("M001", raw_audit)
            self.assertNotIn("我真的很喜欢回忆", raw_audit)
            self.assertNotIn("长期记忆锚点", raw_audit)

    def test_empty_and_failure_are_typed_without_content_leakage(self) -> None:
        empty = parse_owner_memory_response(
            response_payload(records=[]),
            expected_request_id="request-1-owner-memory",
            expected_mode="recent",
        )
        with TemporaryDirectory() as temporary:
            audit = AuditLogger(Path(temporary), "dev")
            runtime = OwnerMemoryReadRuntime(
                AuditedOwnerMemoryReadAdapter(StubClient(empty), audit)
            )
            selection = runtime.retrieve("普通聊天", request_id="request-1-owner-memory")
            self.assertEqual(selection.state, "empty")
            self.assertIsNone(selection.context)

            failing_client = StubClient()
            failing_client.error = OwnerMemoryReadError(
                "worker_unavailable", retryable=True
            )
            failing = OwnerMemoryReadRuntime(
                AuditedOwnerMemoryReadAdapter(failing_client, audit)
            )
            secret_query = "这段查询正文不得进入审计"
            with self.assertRaises(OwnerMemoryReadError):
                failing.retrieve(secret_query, request_id="request-2-owner-memory")
            raw_audit = audit.path.read_text(encoding="utf-8")
            self.assertNotIn(secret_query, raw_audit)
            self.assertIn("worker_unavailable", raw_audit)

    def test_mode_classifier_is_deterministic(self) -> None:
        self.assertEqual(classify_owner_memory_mode("今天随便聊聊"), "recent")
        self.assertEqual(classify_owner_memory_mode("还记得第一次部署吗"), "deep")

    def test_error_response_is_content_free_and_typed(self) -> None:
        payload = {
            "schema_version": 1,
            "operation": "owner_memory.retrieve",
            "ok": False,
            "request_id": "request-1-owner-memory",
            "error": {"code": "retrieval_unavailable", "retryable": True},
        }
        with self.assertRaises(OwnerMemoryReadError) as captured:
            parse_owner_memory_response(
                payload,
                expected_request_id="request-1-owner-memory",
                expected_mode="recent",
            )
        self.assertTrue(captured.exception.retryable)
        self.assertEqual(str(captured.exception), "retrieval_unavailable")
        self.assertNotIn(json.dumps(record_payload(), ensure_ascii=False), str(captured.exception))


if __name__ == "__main__":
    unittest.main()
