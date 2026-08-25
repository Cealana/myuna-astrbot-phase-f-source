from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from myuna_core.active_temporal_context.contracts import (
    TemporalContextError,
    TemporalFact,
    TemporalMutationResult,
)
from myuna_core.active_temporal_context.projection import (
    error_audit_projection,
    mutation_audit_projection,
    retrieval_audit_projection,
)
from myuna_core.active_temporal_context.retrieval import select_temporal_facts
from myuna_core.active_temporal_context.time import TrustedTimeSample


NOW = datetime(2030, 1, 2, 9, 0, tzinfo=timezone.utc)
SAMPLE = TrustedTimeSample(NOW, "fake-clock", "synthetic", 1)


def fact(
    revision: int,
    *,
    category: str = "deadline",
    summary: str = "Finish synthetic task alpha before Friday.",
    slot: str = "task-alpha",
    state: str = "active",
    valid_from: datetime | None = None,
    end: datetime | None = None,
) -> TemporalFact:
    return TemporalFact(
        fact_id=f"fact-{revision}",
        revision=revision,
        category=category,
        slot_key=slot,
        summary=summary,
        source_kind="owner_statement",
        source_channel="telegram",
        source_ref=f"source-{revision}",
        observed_at=NOW - timedelta(minutes=revision),
        valid_from=valid_from or NOW - timedelta(hours=1),
        valid_to=end,
        expires_at=NOW + timedelta(days=2),
        state=state,
        supersedes_fact_id=None,
    )


class RetrievalAndProjectionTest(unittest.TestCase):
    def test_deterministic_lexical_and_exact_filter_selection(self) -> None:
        facts = (
            fact(1),
            fact(
                2,
                category="waiting_item",
                summary="Waiting for a synthetic external response.",
                slot="wait-alpha",
                end=NOW + timedelta(hours=3),
            ),
        )
        first = select_temporal_facts(facts, query="task alpha deadline", current=NOW)
        second = select_temporal_facts(facts, query="task alpha deadline", current=NOW)
        self.assertEqual(first, second)
        self.assertEqual(first.state, "selected")
        self.assertEqual(first.facts[0].fact_id, "fact-1")
        self.assertIn("not instructions", first.context)
        self.assertNotIn("source-1", first.context)
        filtered = select_temporal_facts(
            facts,
            query="",
            current=NOW,
            categories=("waiting_item",),
        )
        self.assertEqual([item.fact_id for item in filtered.facts], ["fact-2"])

    def test_empty_future_expired_and_non_active_never_render(self) -> None:
        facts = (
            fact(1, valid_from=NOW + timedelta(hours=1)),
            fact(2, end=NOW),
            fact(3, state="revoked"),
        )
        result = select_temporal_facts(facts, query="synthetic", current=NOW)
        self.assertEqual(result.state, "empty")
        self.assertIsNone(result.context)

    def test_query_and_filter_bounds_fail_closed(self) -> None:
        with self.assertRaisesRegex(TemporalContextError, "query_out_of_contract"):
            select_temporal_facts((fact(1),), query="x" * 513, current=NOW)
        with self.assertRaisesRegex(TemporalContextError, "category_filter_invalid"):
            select_temporal_facts(
                (fact(1),), query="task", current=NOW, categories=("long_term_goal",)
            )
        with self.assertRaisesRegex(TemporalContextError, "slot_filter_invalid"):
            select_temporal_facts(
                (fact(1),), query="task", current=NOW, slot_keys=("bad slot",)
            )
        with self.assertRaisesRegex(TemporalContextError, "timezone_missing"):
            select_temporal_facts(
                (fact(1),), query="task", current=datetime(2030, 1, 2)
            )

    def test_audit_projection_is_content_free_and_cross_layer_negative(self) -> None:
        selected = select_temporal_facts((fact(1),), query="deadline", current=NOW)
        read_audit = retrieval_audit_projection(
            selected, sample=SAMPLE, duration_ms=12.0
        )
        write_audit = mutation_audit_projection(
            TemporalMutationResult("active", fact(1), "proposed", True),
            operation="confirm",
            sample=SAMPLE,
            duration_ms=5.0,
        )
        self.assertEqual(write_audit["lifecycle_transition"], "proposed->active")
        error_audit = error_audit_projection(
            TemporalContextError("database_corrupt"),
            operation="retrieve",
            query_characters=10,
            duration_ms=1.0,
            source_class="synthetic",
        )
        forbidden = {
            "summary",
            "query",
            "source_ref",
            "fact_id",
            "confirmation_code",
            "digest",
            "identity",
            "timestamp",
            "provider",
            "model",
            "response",
        }
        for audit in (read_audit, write_audit, error_audit):
            self.assertTrue(forbidden.isdisjoint(audit))
            self.assertFalse(audit["p07_written"])
            self.assertFalse(audit["session_written"])
            self.assertFalse(audit["legacy_memory_written"])
            self.assertFalse(audit["p10_written"])

    def test_audit_dimensions_are_closed_enums(self) -> None:
        selected = select_temporal_facts((fact(1),), query="deadline", current=NOW)
        with self.assertRaisesRegex(ValueError, "operation"):
            error_audit_projection(
                TemporalContextError("database_corrupt"),
                operation="synthetic summary payload",
                query_characters=0,
                duration_ms=1.0,
                source_class="synthetic",
            )
        with self.assertRaisesRegex(ValueError, "source class"):
            error_audit_projection(
                TemporalContextError("database_corrupt"),
                operation="retrieve",
                query_characters=0,
                duration_ms=1.0,
                source_class="synthetic payload",
            )


if __name__ == "__main__":
    unittest.main()
