from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from myuna_core.memory.models import (
    ConfirmationLevel,
    MemoryCandidate,
    MemoryKind,
    MemorySource,
    PolicyAction,
    SourceKind,
    TimePrecision,
)
from myuna_core.memory.policy import DefaultMemoryPolicy


NOW = datetime(2042, 5, 9, 12, 0, tzinfo=timezone.utc)


def candidate(**overrides: object) -> MemoryCandidate:
    source = overrides.pop(
        "source",
        MemorySource("source-1", SourceKind.CONVERSATION, "synthetic://1", NOW),
    )
    values: dict[str, object] = {
        "memory_id": "memory-1",
        "source": source,
        "kind": MemoryKind.EPISODIC,
        "text": "一条纯合成记忆。",
        "occurred_at": NOW,
        "recorded_at": NOW,
        "timezone": "UTC",
        "time_precision": TimePrecision.MINUTE,
    }
    values.update(overrides)
    return MemoryCandidate(**values)


class MemoryModelsAndPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = DefaultMemoryPolicy()

    def test_naive_datetime_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            candidate(occurred_at=datetime(2042, 5, 9, 12, 0))

    def test_explicit_no_recall_routes_to_sealed_archive(self) -> None:
        decision = self.policy.evaluate(candidate(directive_text="不要添加到记忆里"), NOW)
        self.assertEqual(decision.action, PolicyAction.SEALED_ARCHIVE)
        self.assertTrue(decision.archive_receipt_required)
        self.assertIsNone(self.policy.materialize(candidate(), decision))

    def test_explicit_no_storage_discards_everywhere(self) -> None:
        decision = self.policy.evaluate(candidate(directive_text="完全不要保存"), NOW)
        self.assertEqual(decision.action, PolicyAction.DISCARD)
        self.assertFalse(decision.archive_receipt_required)
        self.assertIsNone(self.policy.materialize(candidate(), decision))

    def test_colloquial_forget_suppresses_but_retains(self) -> None:
        item = candidate(directive_text="这件事忘了吧")
        decision = self.policy.evaluate(item, NOW)
        record = self.policy.materialize(item, decision)
        self.assertEqual(decision.action, PolicyAction.RETAIN_SUPPRESSED)
        self.assertIsNotNone(record)
        self.assertTrue(record.do_not_surface_proactively)

    def test_operational_record_is_external(self) -> None:
        source = MemorySource("ops-1", SourceKind.OPERATIONAL_RECORD, "ops://1", NOW)
        decision = self.policy.evaluate(candidate(source=source), NOW)
        self.assertEqual(decision.action, PolicyAction.STORE_AS_EXTERNAL_RECORD)

    def test_model_inference_cannot_self_confirm(self) -> None:
        item = candidate(
            confirmation=ConfirmationLevel.MODEL_INFERRED,
            source=MemorySource("model-1", SourceKind.MODEL_INFERENCE, "model://1", NOW),
        )
        decision = self.policy.evaluate(item, NOW)
        self.assertEqual(decision.action, PolicyAction.RETAIN_PROVISIONAL)

    def test_current_state_gets_scoped_ttl(self) -> None:
        item = candidate(kind=MemoryKind.CURRENT_STATE, scope=("day:2042-05-09",))
        decision = self.policy.evaluate(item, NOW)
        self.assertEqual(decision.review_after, NOW + timedelta(days=3))
        self.assertEqual(decision.consolidate_after, NOW + timedelta(days=7))
        self.assertEqual(decision.low_activity_after, NOW + timedelta(days=30))
        self.assertEqual(decision.expires_at, NOW + timedelta(days=30))

    def test_provisional_memory_gets_ordered_3_7_30_lifecycle(self) -> None:
        decision = self.policy.evaluate(candidate(), NOW)
        record = self.policy.materialize(candidate(), decision)
        self.assertIsNotNone(record)
        self.assertEqual(record.review_after, NOW + timedelta(days=3))
        self.assertEqual(record.consolidate_after, NOW + timedelta(days=7))
        self.assertEqual(record.low_activity_after, NOW + timedelta(days=30))

    def test_user_confirmation_becomes_confirmed(self) -> None:
        item = replace(candidate(), confirmation=ConfirmationLevel.USER_CONFIRMED)
        decision = self.policy.evaluate(item, NOW)
        self.assertEqual(decision.action, PolicyAction.RETAIN_CONFIRMED)

    def test_contract_memory_kinds_materialize_without_lossy_downcast(self) -> None:
        for kind in (
            MemoryKind.EXACT_QUOTE,
            MemoryKind.FACT,
            MemoryKind.RELATIONSHIP,
            MemoryKind.PROJECT,
        ):
            with self.subTest(kind=kind):
                item = candidate(
                    kind=kind,
                    confirmation=ConfirmationLevel.USER_CONFIRMED,
                )
                decision = self.policy.evaluate(item, NOW)
                record = self.policy.materialize(item, decision)
                self.assertIsNotNone(record)
                self.assertEqual(record.kind, kind)


if __name__ == "__main__":
    unittest.main()
