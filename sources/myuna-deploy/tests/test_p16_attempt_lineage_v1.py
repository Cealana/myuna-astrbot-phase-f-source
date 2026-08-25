from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import p16_phase1_t2_contract_v1 as contract  # noqa: E402


class P16TerminalAttemptLineageCompatibilityTests(unittest.TestCase):
    def _identity(self) -> dict[str, object]:
        return {
            "schema": contract.BUNDLE_SCHEMA,
            "status": "built_inactive",
            "core_source_commit": "1" * 40,
            "deploy_source_commit": "2" * 40,
            "controller_source_sha256": "3" * 64,
            "generation13_base": {
                "core_release_digest": "4" * 64,
                "runtime_release_digest": "5" * 64,
                "plugin_release_digest": "6" * 64,
                "p08_release_digest": "7" * 64,
            },
            "artifacts": {
                name: {
                    "release_digest": character * 64,
                    "inventory_digest": character * 64,
                    "file_count": 1,
                }
                for name, character in zip(
                    ("core", "telegram_runtime", "telegram_plugin", "p16_adapter"),
                    "89ab",
                )
            },
            "compatibility": {
                "combined_release_set_id": "c" * 64,
                "p07_release_set_id": "d" * 64,
                "p08_plan_digest": "e" * 64,
                "effective_definition_id": "effective-v6-safe-id",
                "generation": 13,
                "epoch_schema": "myuna.external-authorized-epoch.v3",
            },
            "content_free": True,
        }

    def test_terminal_series_is_linked_but_never_inherited_or_reopened(self) -> None:
        lineage = contract.build_attempt_lineage(self._identity())
        terminal = lineage["terminal_predecessor"]
        self.assertEqual(
            terminal["snapshot_schema"],
            "myuna.p16-active-successor-predecessor-snapshot.v1",
        )
        self.assertEqual(terminal["attempts"], 1)
        self.assertEqual(terminal["maximum_attempts"], 2)
        self.assertEqual(lineage["attempts_inherited"], 0)
        self.assertEqual(lineage["maximum_attempts"], 2)
        self.assertEqual(lineage["predecessor_remaining_attempts_retired"], 1)
        self.assertEqual(
            lineage["strategy_relation"],
            "supersedes_failed_strategy_without_retry_or_reset",
        )
        self.assertNotIn("predecessor", lineage)
        self.assertNotIn("ledger_action", lineage)

    def test_terminal_evidence_binds_ledger_transition_receipt_backup_and_active_files(self) -> None:
        terminal = contract.build_attempt_lineage(self._identity())["terminal_predecessor"]
        expected = {
            "snapshot_digest",
            "bundle_manifest_sha256",
            "lineage_digest",
            "attempt_digest",
            "attempt_file_sha256",
            "activation_receipt_digest",
            "activation_receipt_file_sha256",
            "activation_backup_digest",
            "activation_backup_manifest_sha256",
            "marker_sha256",
            "selector_sha256",
            "dropin_sha256",
        }
        self.assertTrue(expected.issubset(terminal))
        self.assertTrue(all(len(str(terminal[field])) == 64 for field in expected))

    def test_terminal_or_successor_substitution_fails_closed(self) -> None:
        identity = self._identity()
        lineage = contract.build_attempt_lineage(identity)
        contract.validate_attempt_lineage(lineage, identity)
        terminal_drift = copy.deepcopy(lineage)
        terminal_drift["terminal_predecessor"]["snapshot_digest"] = "0" * 64
        with self.assertRaises(ValueError):
            contract.validate_attempt_lineage(terminal_drift, identity)
        successor_drift = copy.deepcopy(identity)
        successor_drift["deploy_source_commit"] = "f" * 40
        with self.assertRaises(ValueError):
            contract.validate_attempt_lineage(lineage, successor_drift)

    def test_lineage_is_content_free_and_has_no_attempt_three_vocabulary(self) -> None:
        serialized = contract.canonical(contract.build_attempt_lineage(self._identity())).decode(
            "ascii"
        )
        for forbidden in (
            "message",
            "prompt",
            "response",
            "profile",
            "db_row",
            "raw_log",
            "secret",
            "credential",
            "provider_payload",
            "model_response",
            "attempt3",
            "attempt-0003",
        ):
            self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main()
