from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from myuna_core.audit import AuditLogger
from myuna_core.memory.owner_readonly_v2 import (
    OWNER_MEMORY_POLICY_V2,
    AuditedOwnerMemoryReadV2Adapter,
    OwnerMemoryReadV2Runtime,
    UnixSocketOwnerMemoryV2Client,
)
from owner_memory_retrieval_v2.core_adapter import CoreMemoryRecord, CoreSelection


class FakeV2Client:
    def retrieve(self, query: str, *, request_id: str, timeout_seconds: float) -> CoreSelection:
        return CoreSelection(
            state="selected",
            intent="durable_policy",
            horizon_used="deep",
            fallback_used=False,
            hit_ids=("M001",),
            records=(
                CoreMemoryRecord(
                    memory_id="M001",
                    memory_kind="preference",
                    memory_status="confirmed",
                    importance=0.95,
                    assertion_text="重要记忆应保留完整背景。",
                    exact_quote=None,
                    occurred_at="2026-07-17T01:00:00+08:00",
                    time_precision="day",
                    time_phrase="凌晨",
                    scope=("global", "owner_private"),
                    tags=("memory",),
                    rationales=(),
                    anchors=(),
                ),
            ),
            query_fingerprint="a" * 64,
            duration_ms=1.0,
        )


class OwnerMemoryV2QQBridgeTests(unittest.TestCase):
    def test_v1_socket_is_rejected_by_v2_client(self) -> None:
        with self.assertRaises(ValueError):
            UnixSocketOwnerMemoryV2Client(
                Path("/run/myuna-owner-memory-read-v1/worker.sock")
            )

    def test_v2_selection_maps_to_existing_conversation_shape_without_id_leak(self) -> None:
        with TemporaryDirectory() as temporary:
            audit = AuditLogger(Path(temporary), "dev")
            adapter = AuditedOwnerMemoryReadV2Adapter(FakeV2Client(), audit)  # type: ignore[arg-type]
            runtime = OwnerMemoryReadV2Runtime(adapter)
            selection = runtime.retrieve(
                "我希望长期记忆怎样保留重要的事情？",
                request_id="request-v2-bridge",
            )
            self.assertEqual(selection.state, "selected")
            self.assertEqual(selection.mode_used, "deep")
            self.assertEqual(selection.policy_version, OWNER_MEMORY_POLICY_V2)
            assert selection.context is not None
            self.assertIn("重要记忆应保留完整背景", selection.context)
            self.assertNotIn("M001", selection.context)
            audit_text = (Path(temporary) / "audit.jsonl").read_text(encoding="utf-8")
            self.assertNotIn("重要记忆应保留完整背景", audit_text)
            event = json.loads(audit_text.splitlines()[-1])
            self.assertEqual(event["details"]["protocol"], "v2")
            self.assertEqual(event["details"]["horizon_used"], "deep")


if __name__ == "__main__":
    unittest.main()
