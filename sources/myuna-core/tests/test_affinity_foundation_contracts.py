from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import unittest

from myuna_core.affinity import (
    AFFINITY_DIMENSIONS,
    LONG_TERM_DIMENSIONS,
    SHORT_TERM_DIMENSIONS,
    AffinityCapabilityContract,
    AffinityDiagnosticEvent,
    AffinityError,
    AffinityEvidenceQuery,
    AffinityEvidenceReference,
    AffinitySnapshot,
    AffinityTimeSample,
    AffinityUpdate,
)


NOW = datetime(2040, 1, 2, 3, 4, tzinfo=timezone.utc)


class AffinityFoundationContractTests(unittest.TestCase):
    def test_exact_multidimensional_namespace_has_no_initial_values(self) -> None:
        self.assertEqual(len(LONG_TERM_DIMENSIONS), 5)
        self.assertEqual(len(SHORT_TERM_DIMENSIONS), 5)
        self.assertEqual(len(AFFINITY_DIMENSIONS), 10)
        empty = AffinitySnapshot.empty("synthetic.owner-alpha")
        self.assertEqual(empty.dimensions, ())
        self.assertEqual(empty.revision, 0)

    def test_phase_b_capability_is_explicitly_inactive_and_checkpointed(self) -> None:
        contract = AffinityCapabilityContract.phase_b_foundation()
        payload = contract.as_payload()
        for key in (
            "active",
            "bootstrap_active",
            "legacy_trust_migration_active",
            "persistence_active",
            "prompt_projection_active",
            "retrieval_active",
            "writer_active",
        ):
            self.assertIs(payload[key], False)
        self.assertIs(payload["synthetic_machine_only"], True)
        dependencies = {item.dependency: item for item in contract.dependencies}
        self.assertEqual(dependencies["p10_trusted_time"].status, "dependency_checkpoint")
        self.assertEqual(dependencies["p15_relevance"].status, "dependency_checkpoint")
        self.assertTrue(all(not item.writes_state for item in contract.dependencies))
        self.assertEqual(contract.digest, AffinityCapabilityContract.phase_b_foundation().digest)
        with self.assertRaisesRegex(
            AffinityError, "affinity_phase_b_foundation_must_remain_inactive"
        ):
            replace(contract, active=True)

    def test_abstention_has_no_value_or_confidence_claim(self) -> None:
        update = AffinityUpdate(
            namespace_id="synthetic.owner-alpha",
            event_id="event-1",
            sequence=1,
            action="abstain",
            dimension="daily_trust",
            value=None,
            confidence="none",
            evidence_refs=(),
            source_kind="synthetic_fixture",
            abstention_reason="insufficient_evidence",
        )
        self.assertIsNone(update.value)
        with self.assertRaisesRegex(AffinityError, "affinity_abstention_invalid"):
            replace(update, value=50)

    def test_updates_reject_unknown_dimensions_and_non_synthetic_sources(self) -> None:
        base = dict(
            namespace_id="synthetic.owner-alpha",
            event_id="event-2",
            sequence=1,
            action="propose",
            value=10,
            confidence="low",
            evidence_refs=("synthetic.profile.1",),
            source_kind="synthetic_fixture",
        )
        with self.assertRaisesRegex(AffinityError, "affinity_dimension_invalid"):
            AffinityUpdate(dimension="legacy_trust", **base)
        with self.assertRaisesRegex(AffinityError, "affinity_source_kind_inactive"):
            AffinityUpdate(dimension="affection", **(base | {"source_kind": "live"}))

    def test_update_payload_rejects_unknown_fields(self) -> None:
        payload = AffinityUpdate(
            namespace_id="synthetic.owner-alpha",
            event_id="event-3",
            sequence=1,
            action="propose",
            dimension="agency",
            value=10,
            confidence="low",
            evidence_refs=("synthetic.profile.1",),
            source_kind="synthetic_fixture",
        ).as_payload()
        payload["unknown"] = True
        with self.assertRaisesRegex(AffinityError, "affinity_update_fields_invalid"):
            AffinityUpdate.from_payload(payload)

    def test_typed_dependency_seams_carry_references_not_content(self) -> None:
        query = AffinityEvidenceQuery(
            namespace_id="synthetic.owner-alpha",
            dimension="security",
            query_ref="synthetic.query.1",
        )
        evidence = AffinityEvidenceReference(
            source="p07_owner_profile",
            source_ref="synthetic.profile.1",
            revision=1,
            observed_at=NOW,
        )
        event = AffinityDiagnosticEvent(
            code="affinity_abstained",
            outcome="insufficient_evidence",
            retryable=False,
            revision=0,
            dimension=query.dimension,
        )
        self.assertFalse(hasattr(evidence, "content"))
        self.assertNotIn("value", event.as_payload())
        self.assertNotIn("evidence_refs", event.as_payload())

    def test_trusted_time_sample_requires_typed_source_class(self) -> None:
        AffinityTimeSample(NOW, 1, "synthetic-clock", "synthetic")
        with self.assertRaisesRegex(AffinityError, "trusted_time_source_class_invalid"):
            AffinityTimeSample(NOW, 1, "synthetic-clock", "wall_clock")


if __name__ == "__main__":
    unittest.main()
