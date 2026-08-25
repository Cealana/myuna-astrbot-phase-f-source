from __future__ import annotations

import ast
from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from p08_p07_combined_release_set_v1 import (  # noqa: E402
    GENERATION,
    ROLLBACK_ORDER as RELEASE_SET_ROLLBACK_ORDER,
    SCHEMA as RELEASE_SET_SCHEMA,
)
from p08_p07_combined_transaction_v1 import APPLY_ORDER, ROLLBACK_ORDER  # noqa: E402
import p15_context_orchestration_contract_v1 as p15_deploy  # noqa: E402
from user_visible_fault_v1 import (  # noqa: E402
    PUBLIC_FAULT_SCHEMA,
    PUBLIC_FAULTS,
    public_fault_for_typed_input,
)


def literal_assignments(path: Path, names: set[str]) -> dict[str, object]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    values: dict[str, object] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id in names:
            values[target.id] = ast.literal_eval(node.value)
    return values


class P16Generation12V7BDiagnosticsV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = json.loads(
            (ROOT / "tests/fixtures/p16_generation12_v7b_diagnostics_v2.json")
            .read_text(encoding="utf-8")
        )

    def test_current_main_identity_and_dependency_status_are_exact(self) -> None:
        self.assertEqual(
            self.payload["schema"], "myuna.p16-generation12-v7b-diagnostics.v2"
        )
        self.assertEqual(self.payload["public_taxonomy_schema"], PUBLIC_FAULT_SCHEMA)
        dependencies = {item["id"]: item for item in self.payload["dependencies"]}
        generation12 = dependencies["generation12_combined_interface"]
        self.assertEqual(
            generation12["status"], "EXACT_COMMITTED_ANCESTOR_ON_CURRENT_MAINS"
        )
        self.assertEqual(
            generation12["current_core_head"],
            "527fc1aed963fd3627791e6fafeb8e14bc5bc882",
        )
        self.assertEqual(
            generation12["current_deploy_head"],
            "2ca38e1c8607a5cc5bd7e474a4ffb6ebac574eac",
        )
        affinity = dependencies["v7_phase_b_affinity_interface"]
        self.assertEqual(affinity["status"], "EXACT_COMMITTED_MAINLINE")
        self.assertEqual(
            affinity["source_main_commit"],
            "31250bbd015c07ddefaca889d8c56ddf28971a12",
        )
        p15 = dependencies["p15_relevance_retention_interface"]
        self.assertEqual(p15["status"], "EXACT_COMMITTED_MAINLINE")
        self.assertEqual(p15["core_head"], generation12["current_core_head"])
        self.assertEqual(p15["deploy_head"], generation12["current_deploy_head"])

    def test_v1_semantic_projection_is_byte_canonically_invariant(self) -> None:
        projection = {
            key: self.payload[key]
            for key in ("policies", "generation12", "v7_phase_b")
        }
        canonical = json.dumps(
            projection, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        self.assertEqual(
            sha256(canonical).hexdigest(),
            self.payload["semantic_projection_sha256"],
        )
        self.assertEqual(
            self.payload["semantic_projection_sha256"],
            "18c42a102993bde1a07263946689cfab7ec21678e9e34b6e24e55c0b2a6d888a",
        )

    def test_generation12_source_schemas_orders_and_gates_remain_exact(self) -> None:
        generation12 = self.payload["generation12"]
        constants = literal_assignments(
            ROOT / "scripts/activate_p08_p07_generation12_v1.py",
            {"PLAN_SCHEMA", "JOURNAL_SCHEMA", "RECEIPT_SCHEMA"},
        )
        self.assertEqual(GENERATION, 12)
        self.assertEqual(RELEASE_SET_SCHEMA, generation12["schemas"]["release_set"])
        self.assertEqual(constants["PLAN_SCHEMA"], generation12["schemas"]["activation_plan"])
        self.assertEqual(constants["JOURNAL_SCHEMA"], generation12["schemas"]["journal"])
        self.assertEqual(constants["RECEIPT_SCHEMA"], generation12["schemas"]["receipt"])
        self.assertEqual(list(APPLY_ORDER), generation12["apply_order"])
        self.assertEqual(list(ROLLBACK_ORDER), generation12["rollback_order"])
        self.assertEqual(ROLLBACK_ORDER, RELEASE_SET_ROLLBACK_ORDER)
        rows = {item["id"]: item for item in generation12["failure_cases"]}
        self.assertEqual(
            rows["g12_combined_accept_rejected"]["fallback_gate"],
            "p08_activation_rejected",
        )
        for component in ("p07", "telegram_plugin", "p08"):
            self.assertEqual(
                rows[f"g12_{component}_apply_rejected"]["complete_rollback_gate"],
                "combined_activation_rolled_back",
            )
            self.assertEqual(
                rows[f"g12_{component}_rollback_rejected"]["hard_stop_gate"],
                "combined_functional_rollback_failed",
            )

    def test_non_fault_and_hard_stop_semantics_create_no_incident(self) -> None:
        invariants = {
            item["id"]: item for item in self.payload["generation12"]["invariants"]
        }
        reset = invariants["g12_fresh_external_context_continuity_reset"]
        complete = invariants["g12_reverse_order_rollback_complete"]
        partial = invariants["g12_partial_rollback_hard_stop"]
        self.assertFalse(reset["fault"])
        self.assertFalse(complete["fault"])
        self.assertEqual(complete["order"], list(ROLLBACK_ORDER))
        self.assertTrue(partial["fault"])
        self.assertTrue(partial["hard_stop"])
        self.assertEqual(partial["typed_gate"], "combined_functional_rollback_failed")
        for item in (reset, complete, partial):
            self.assertIsNone(item["public_code"])
            self.assertIsNone(item["incident_ref"])

    def test_affinity_absent_abstained_and_unavailable_semantics_are_preserved(self) -> None:
        rows = {
            item["id"]: item for item in self.payload["v7_phase_b"]["cases"]
        }
        self.assertFalse(rows["v7b_affinity_capability_absent"]["fault"])
        self.assertIsNone(rows["v7b_affinity_capability_absent"]["typed_code"])
        self.assertFalse(rows["v7b_affinity_capability_abstained"]["fault"])
        self.assertEqual(
            rows["v7b_affinity_capability_abstained"]["typed_code"],
            "affinity_abstained",
        )
        unavailable = rows["v7b_affinity_capability_unavailable"]
        self.assertIsNone(unavailable["fault"])
        self.assertEqual(unavailable["typed_code"], "affinity_dependency_unavailable")
        self.assertIsNone(unavailable["public_code"])
        self.assertIsNone(unavailable["incident_ref"])

    def test_existing_time_codes_remain_conditional_without_synthetic_projection(self) -> None:
        rows = {
            item["id"]: item for item in self.payload["v7_phase_b"]["cases"]
        }
        for key in (
            "v7b_trusted_time_dependency_unavailable",
            "v7b_temporal_dependency_unavailable",
        ):
            row = rows[key]
            descriptor = public_fault_for_typed_input(
                row["typed_namespace"], row["typed_code"]
            )
            self.assertIn(row["conditional_public_code"], PUBLIC_FAULTS)
            self.assertEqual(descriptor.code, row["conditional_public_code"])
            self.assertIsNone(row["public_code"])
            self.assertIsNone(row["incident_ref"])

    def test_p15_deploy_identity_contract_matches_fixture(self) -> None:
        dependency = next(
            item
            for item in self.payload["dependencies"]
            if item["id"] == "p15_relevance_retention_interface"
        )
        self.assertEqual(p15_deploy.SCHEMA, dependency["deploy_contract_schema"])
        self.assertEqual(
            p15_deploy.CORE_MODULE_SCHEMA, dependency["core_contract_schema"]
        )
        self.assertEqual(
            p15_deploy.P09_P15_INTERFACE_SCHEMA,
            dependency["affinity_interface_schema"],
        )
        self.assertEqual(p15_deploy.contract_digest(), dependency["deploy_contract_digest"])
        self.assertFalse(p15_deploy.contract_payload()["activation_authorized"])

    def test_current_core_p09_and_p15_contracts_match_fixture(self) -> None:
        core_src = os.environ.get("MYUNA_CORE_SRC")
        if not core_src:
            self.skipTest("MYUNA_CORE_SRC is required for the cross-repo gate")
        sys.path.insert(0, core_src)
        try:
            affinity_contracts = importlib.import_module("myuna_core.affinity.contracts")
            affinity_ports = importlib.import_module("myuna_core.affinity.ports")
            p15_contracts = importlib.import_module(
                "myuna_core.context_orchestration.contracts"
            )
            affinity = affinity_contracts.AffinityCapabilityContract.phase_b_foundation()
            affinity_dependency = next(
                item
                for item in self.payload["dependencies"]
                if item["id"] == "v7_phase_b_affinity_interface"
            )
            self.assertEqual(affinity.schema, affinity_dependency["schema"])
            self.assertEqual(affinity.digest, affinity_dependency["capability_digest"])
            self.assertEqual(
                set(affinity_ports.DIAGNOSTIC_CODES),
                set(self.payload["v7_phase_b"]["diagnostic_codes"]),
            )
            p15_dependency = next(
                item
                for item in self.payload["dependencies"]
                if item["id"] == "p15_relevance_retention_interface"
            )
            self.assertEqual(
                p15_contracts.P15_CONTRACT_SCHEMA,
                p15_dependency["core_contract_schema"],
            )
            self.assertEqual(p15_contracts.P15_INPUT_SCHEMA, p15_dependency["input_schema"])
            self.assertEqual(p15_contracts.P15_RESULT_SCHEMA, p15_dependency["result_schema"])
            self.assertEqual(
                set(p15_contracts.SELECTION_STATUSES),
                set(self.payload["p15_relevance_retention"]["selection_statuses"]),
            )
            result = p15_contracts.P15SelectionResult(
                status="abstain",
                selected=(),
                decisions=(),
                clarification_required=False,
                normal_transition=True,
                input_snapshot_digest="0" * 64,
            )
            self.assertFalse(result.fault)
            self.assertTrue(result.normal_transition)
        finally:
            sys.path.remove(core_src)

    def test_p15_relevance_retention_rows_are_non_fault_and_unprojected(self) -> None:
        rows = self.payload["p15_relevance_retention"]["cases"]
        reasons = {
            row.get("decision_reason") for row in rows if "decision_reason" in row
        }
        self.assertEqual(
            reasons,
            {
                "drop_capability_unavailable",
                "abstain_required_provenance",
                "drop_budget",
                "drop_duplicate",
            },
        )
        reset = next(row for row in rows if row["id"] == "p15_authorized_continuity_reset")
        self.assertTrue(reset["normal_transition"])
        for row in rows:
            self.assertFalse(row["fault"])
            self.assertIsNone(row["public_code"])
            self.assertIsNone(row["incident_ref"])

    def test_fixture_is_content_free_deterministic_and_has_no_incident_evidence(self) -> None:
        forbidden_keys = {
            "raw_exception", "path", "secret", "amount", "ledger", "reservation",
            "provider_payload", "model_response", "private_message", "profile",
            "db_row", "fingerprint",
        }

        def walk(value: object) -> None:
            if isinstance(value, dict):
                self.assertTrue(forbidden_keys.isdisjoint(value))
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(self.payload)
        serialized = json.dumps(
            self.payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        )
        self.assertNotIn("inc1-", serialized)
        self.assertNotIn("inc-000000000000", serialized)
        self.assertTrue(self.payload["policies"]["fail_closed"])
        self.assertEqual(self.payload["policies"]["new_public_codes"], "forbidden")


if __name__ == "__main__":
    unittest.main()
