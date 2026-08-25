from __future__ import annotations

from pathlib import Path
import unittest

from myuna_core.memory.evaluation import SyntheticEvaluationHarness
from myuna_core.memory.migrations import record_from_payload, record_to_payload


class MemoryMigrationsAndEvaluationTests(unittest.TestCase):
    def test_v0_payload_migrates_to_v2_and_round_trips(self) -> None:
        payload = {
            "memory_id": "legacy-1",
            "source": {
                "source_id": "legacy-source",
                "kind": "conversation",
                "reference": "synthetic://legacy",
                "captured_at": "2042-05-09T12:00:00+00:00",
            },
            "kind": "episodic",
            "text": "纯合成旧格式内容",
            "occurred_at": "2042-05-09T12:00:00+00:00",
            "recorded_at": "2042-05-09T12:00:01+00:00",
            "timezone": "UTC",
        }
        record = record_from_payload(payload)
        self.assertEqual(record.schema_version, 2)
        self.assertEqual(record.policy_reasons, ("migrated_from_v0",))
        self.assertEqual(record.namespace_id, "ns-synthetic-dev")
        self.assertEqual(record.source.principal_id, "principal-synthetic")
        self.assertEqual(record_from_payload(record_to_payload(record)), record)

    def test_synthetic_chinese_evaluation_has_no_failures(self) -> None:
        fixture = Path(__file__).parents[1] / "fixtures" / "memory" / "synthetic_zh_v1.jsonl"
        result = SyntheticEvaluationHarness(fixture).run()
        self.assertTrue(result["synthetic_only"])
        self.assertGreaterEqual(result["policy_cases"], 10)
        self.assertGreaterEqual(result["retrieval_cases"], 8)
        self.assertEqual(result["failed"], 0, result)


if __name__ == "__main__":
    unittest.main()
