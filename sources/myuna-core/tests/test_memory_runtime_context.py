from __future__ import annotations

from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from myuna_core.memory.models import MemoryQuery
from myuna_core.memory.runtime_context import (
    SyntheticFixtureCatalog,
    SyntheticMemoryContextError,
    SyntheticMemoryRuntime,
)
from myuna_core.memory.worker_adapter import WorkerRetrievalHit, WorkerRetrievalResult


class StubAdapter:
    def __init__(self, result: WorkerRetrievalResult) -> None:
        self.result = result
        self.query: MemoryQuery | None = None

    def retrieve(self, query, **kwargs):
        self.query = query
        return self.result


def result(memory_id: str) -> WorkerRetrievalResult:
    return WorkerRetrievalResult(
        request_id="memory-request",
        mode_requested="hybrid",
        mode_used="hybrid",
        degraded_reason=None,
        duration_ms=1.0,
        hits=(WorkerRetrievalHit(memory_id, 0.9, ("vector",), {}),),
        trace={},
        model={},
    )


class SyntheticMemoryRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.path = Path(self.temporary.name) / "fixture.jsonl"
        documents = [
            {
                "type": "document",
                "id": "synthetic-bookshop",
                "synthetic": True,
                "text": "虚构旧书店位于银杏路九号。",
                "kind": "semantic",
                "status": "confirmed",
                "confirmation": "user_confirmed",
                "occurred_at": "2042-04-15T14:08:00+08:00",
                "time_precision": "minute",
                "time_phrase": "下午两点零八分",
                "scope": ["global"],
            },
            {
                "type": "document",
                "id": "synthetic-tombstone",
                "synthetic": True,
                "text": "不可见旧记录。",
                "kind": "semantic",
                "status": "tombstoned",
                "confirmation": "observed",
                "occurred_at": "2042-01-01T00:00:00+08:00",
                "time_precision": "date",
                "time_phrase": "元旦",
                "scope": ["global"],
            },
        ]
        self.path.write_text(
            "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in documents),
            encoding="utf-8",
        )
        self.digest = sha256(self.path.read_bytes()).hexdigest().upper()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_catalog_is_checksum_bound_and_renders_only_selected_record(self) -> None:
        catalog = SyntheticFixtureCatalog.load(self.path, expected_sha256=self.digest)
        adapter = StubAdapter(result("synthetic-bookshop"))
        runtime = SyntheticMemoryRuntime(
            adapter,
            catalog,
            fixed_at=datetime.fromisoformat("2042-08-01T12:00:00+08:00"),
        )
        selection = runtime.retrieve("旧书店在哪", request_id="memory-request")
        self.assertEqual(selection.hit_ids, ("synthetic-bookshop",))
        self.assertIn("虚构旧书店位于银杏路九号", selection.context)
        self.assertNotIn("不可见旧记录", selection.context)
        self.assertEqual(adapter.query.limit, 1)  # type: ignore[union-attr]
        self.assertIn("Never invent, infer, or embellish", selection.context)

    def test_checksum_and_unknown_hit_fail_closed(self) -> None:
        with self.assertRaises(SyntheticMemoryContextError):
            SyntheticFixtureCatalog.load(self.path, expected_sha256="0" * 64)
        catalog = SyntheticFixtureCatalog.load(self.path, expected_sha256=self.digest)
        runtime = SyntheticMemoryRuntime(
            StubAdapter(result("missing-record")),
            catalog,
            fixed_at=datetime.fromisoformat("2042-08-01T12:00:00+08:00"),
        )
        with self.assertRaises(SyntheticMemoryContextError):
            runtime.retrieve("未知记录", request_id="memory-request")


if __name__ == "__main__":
    unittest.main()
