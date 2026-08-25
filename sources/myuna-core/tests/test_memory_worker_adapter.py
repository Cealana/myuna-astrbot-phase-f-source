from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest

from myuna_core.audit import AuditLogger
from myuna_core.memory.models import MemoryQuery
from myuna_core.memory.worker_adapter import (
    AuditedSyntheticRetrievalAdapter,
    RetrievalWorkerError,
    UnixSocketSyntheticRetrievalClient,
    WorkerRetrievalHit,
    WorkerRetrievalResult,
    query_fingerprint,
)


NOW = datetime(2042, 8, 1, 12, tzinfo=timezone.utc)


class StubClient:
    def __init__(self, result: WorkerRetrievalResult | None = None) -> None:
        self.result = result
        self.error: RetrievalWorkerError | None = None

    def retrieve(
        self,
        query: MemoryQuery,
        *,
        mode: str = "auto",
        timeout_seconds: float = 20.0,
        request_id: str | None = None,
    ) -> WorkerRetrievalResult:
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result


def result(*, degraded_reason: str | None = None) -> WorkerRetrievalResult:
    return WorkerRetrievalResult(
        request_id="request-1",
        mode_requested="auto",
        mode_used="lexical" if degraded_reason else "hybrid",
        degraded_reason=degraded_reason,
        duration_ms=12.5,
        hits=(WorkerRetrievalHit("synthetic-memory-1", 0.8, ("candidate",), {}),),
        trace={
            "embedding_identity": {
                "provider_id": "local-cpu",
                "model_id": "synthetic-model",
                "model_revision": "revision-1",
                "dimensions": 1024,
                "mode": "hybrid",
            },
            "query_terms": ["must-not-be-audited"],
        },
        model={"loaded": True, "pid": 123},
    )


class WorkerResponseValidationTests(unittest.TestCase):
    def test_valid_response_is_parsed(self) -> None:
        payload = {
            "ok": True,
            "request_id": "request-1",
            "synthetic_only": True,
            "mode_requested": "auto",
            "mode_used": "hybrid",
            "degraded_reason": None,
            "duration_ms": 5.0,
            "hits": [
                {
                    "memory_id": "synthetic-1",
                    "score": 0.7,
                    "reasons": ["vector"],
                    "score_components": {"vector": 0.7},
                }
            ],
            "trace": {},
            "model": {},
        }
        parsed = UnixSocketSyntheticRetrievalClient._parse_retrieval_response(
            payload, "request-1", "auto"
        )
        self.assertEqual(parsed.hits[0].memory_id, "synthetic-1")

    def test_synthetic_boundary_and_request_id_are_mandatory(self) -> None:
        base = {
            "ok": True,
            "request_id": "request-1",
            "synthetic_only": True,
            "mode_requested": "lexical",
            "mode_used": "lexical",
            "degraded_reason": None,
            "duration_ms": 1,
            "hits": [],
            "trace": {},
            "model": {},
        }
        with self.assertRaises(RetrievalWorkerError):
            UnixSocketSyntheticRetrievalClient._parse_retrieval_response(
                {**base, "synthetic_only": False}, "request-1", "lexical"
            )
        with self.assertRaises(RetrievalWorkerError):
            UnixSocketSyntheticRetrievalClient._parse_retrieval_response(
                base, "different-request", "lexical"
            )

    def test_unexplained_auto_degradation_is_rejected(self) -> None:
        payload = {
            "ok": True,
            "request_id": "request-1",
            "synthetic_only": True,
            "mode_requested": "auto",
            "mode_used": "lexical",
            "degraded_reason": None,
            "duration_ms": 1,
            "hits": [],
            "trace": {},
            "model": {},
        }
        with self.assertRaises(RetrievalWorkerError):
            UnixSocketSyntheticRetrievalClient._parse_retrieval_response(
                payload, "request-1", "auto"
            )


class AuditedAdapterTests(unittest.TestCase):
    def test_audit_contains_fingerprint_but_not_query_or_trace_terms(self) -> None:
        query_text = "这段合成问题正文绝不能进入审计日志"
        with TemporaryDirectory() as temp:
            logger = AuditLogger(Path(temp), "dev")
            adapter = AuditedSyntheticRetrievalAdapter(StubClient(result()), logger)
            response = adapter.retrieve(
                MemoryQuery(query_text, at=NOW, limit=1),
                request_id="request-1",
            )
            self.assertEqual(response.hits[0].memory_id, "synthetic-memory-1")
            raw = logger.path.read_text(encoding="utf-8")
            record = json.loads(raw)
            self.assertNotIn(query_text, raw)
            self.assertNotIn("must-not-be-audited", raw)
            self.assertEqual(record["details"]["query_fingerprint"], query_fingerprint(query_text))
            self.assertEqual(record["details"]["hit_ids"], ["synthetic-memory-1"])

    def test_degraded_and_error_outcomes_are_explicit(self) -> None:
        with TemporaryDirectory() as temp:
            logger = AuditLogger(Path(temp), "dev")
            degraded = AuditedSyntheticRetrievalAdapter(
                StubClient(result(degraded_reason="model_timeout")),  # type: ignore[arg-type]
                logger,
            )
            degraded.retrieve(MemoryQuery("合成降级测试", at=NOW), request_id="request-1")

            failing_client = StubClient()
            failing_client.error = RetrievalWorkerError(
                "worker_unavailable", "unavailable", retryable=True
            )
            failing = AuditedSyntheticRetrievalAdapter(failing_client, logger)
            with self.assertRaises(RetrievalWorkerError):
                failing.retrieve(MemoryQuery("合成失败测试", at=NOW), request_id="request-2")

            records = [
                json.loads(line)
                for line in logger.path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(records[0]["outcome"], "degraded")
            self.assertEqual(records[0]["details"]["degraded_reason"], "model_timeout")
            self.assertEqual(records[1]["outcome"], "error")
            self.assertEqual(records[1]["details"]["error_code"], "worker_unavailable")

    def test_audit_labels_cannot_carry_user_text(self) -> None:
        with TemporaryDirectory() as temp:
            logger = AuditLogger(Path(temp), "dev")
            with self.assertRaises(ValueError):
                AuditedSyntheticRetrievalAdapter(
                    StubClient(result()), logger, caller="user supplied sentence"
                )
            adapter = AuditedSyntheticRetrievalAdapter(StubClient(result()), logger)
            with self.assertRaises(ValueError):
                adapter.retrieve(
                    MemoryQuery("合成问题", at=NOW),
                    route_reason="user supplied sentence",
                )


if __name__ == "__main__":
    unittest.main()
