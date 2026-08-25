from __future__ import annotations

from pathlib import Path
import unittest

import p07_episodic_memory_contract_v1 as contract


ROOT = Path(__file__).resolve().parents[1]
ADR = ROOT / "docs" / "ADR-066-p07-lossless-episodic-memory-v1.md"


class EpisodicMemoryContractTests(unittest.TestCase):
    def test_contract_keeps_raw_as_authority_and_derivatives_non_destructive(self) -> None:
        selected = contract.contract_payload()
        contract.require_exact_contract(selected)
        self.assertTrue(selected["archive"]["raw_is_sole_factual_authority"])
        self.assertFalse(selected["archive"]["rewrite_or_compaction"])
        self.assertFalse(selected["episodic"]["index_authority"])
        self.assertFalse(selected["episodic"]["cumulative_summary"])
        self.assertTrue(selected["episodic"]["raw_preferred"])

    def test_diary_is_subjective_append_only_and_never_semantic_promotion(self) -> None:
        selected = contract.contract_payload()
        self.assertEqual(
            selected["diary"]["entry_authority"],
            "myuna_subjective_perspective_not_fact_authority",
        )
        self.assertTrue(selected["diary"]["revisions_append_only"])
        self.assertFalse(selected["diary"]["profile_benchmark_p08_mutation"])
        self.assertTrue(selected["semantic_boundary"]["benchmark_profile_proposal_first"])

    def test_temporal_validity_ownership_and_whole_layer_overflow_are_explicit(self) -> None:
        selected = contract.contract_payload()
        self.assertEqual(selected["ownership"]["active_temporal_validity_and_expiry"], "P08")
        self.assertEqual(selected["ownership"]["trusted_time_provider"], "P10-B")
        self.assertEqual(selected["ownership"]["prompt_orchestration"], "P15")
        self.assertTrue(
            selected["temporal_validity"][
                "active_layer_all_nonconflicting_or_typed_overflow"
            ]
        )
        self.assertFalse(selected["temporal_validity"]["expiry_deletes_or_migrates_raw"])

    def test_trusted_time_and_capacity_contracts_are_distinct_and_inactive(self) -> None:
        selected = contract.contract_payload()
        self.assertTrue(selected["trusted_time"]["one_sample_per_turn"])
        self.assertTrue(selected["trusted_time"]["archive_survives_unavailable_time"])
        self.assertFalse(selected["trusted_time"]["background_polling"])
        self.assertEqual(selected["context"]["request_max_characters"], 200_000)
        self.assertEqual(selected["context"]["projection_max_characters"], 199_000)
        self.assertEqual(selected["context"]["serialized_max_bytes"], 1_198_096)
        self.assertEqual(selected["context"]["token_max_input"], 999_232)
        self.assertIsNone(selected["context"]["fixed_turn_ceiling"])
        self.assertTrue(all(value is False for value in selected["t1_inactive"].values()))

    def test_egress_default_is_deny_and_live_selection_is_separate(self) -> None:
        selected = contract.contract_payload()
        self.assertEqual(selected["egress"]["default_policy"], contract.DEFAULT_EGRESS_POLICY)
        self.assertFalse(selected["egress"]["historical_private_raw_selected_live"])

    def test_adr_uses_correct_layering_priority_and_terminology(self) -> None:
        content = ADR.read_text(encoding="utf-8")
        for required in (
            "Raw archive — original record",
            "Episodic index and capsules — catalog and map",
            "Daily reflective diary — Myuna's authored perspective",
            "P08 temporal-validity memory",
            "P10-B",
            "P15",
            "Asia/Shanghai",
            "America/Los_Angeles",
            "Historical private raw egress is a separate digest-bound policy decision",
        ):
            self.assertIn(required, content)
        self.assertNotIn("effective memory", content.casefold())
        self.assertNotIn("实效性记忆", content)


if __name__ == "__main__":
    unittest.main()
