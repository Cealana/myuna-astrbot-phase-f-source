from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import activate_p16_phase1_t2_v1 as activation  # noqa: E402
import p16_phase1_t2_contract_v1 as contract  # noqa: E402


class P16SuccessorAttemptSeriesContractV1Tests(unittest.TestCase):
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

    def test_successor_lineage_is_new_bounded_and_terminally_linked(self) -> None:
        identity = self._identity()
        lineage = contract.build_attempt_lineage(identity)
        self.assertEqual(contract.BUNDLE_SCHEMA, "myuna.p16-phase1-t2-bundle.v3")
        self.assertEqual(
            lineage["schema"], "myuna.p16-successor-attempt-series-lineage.v2"
        )
        self.assertEqual(lineage["maximum_attempts"], 2)
        self.assertEqual(lineage["attempts_inherited"], 0)
        self.assertEqual(
            lineage["state_action"],
            "new_append_only_series_after_explicit_strategy_retirement",
        )
        self.assertEqual(lineage["predecessor_remaining_attempts_retired"], 1)
        self.assertEqual(
            lineage["strategy_relation"],
            "supersedes_failed_strategy_without_retry_or_reset",
        )
        terminal = lineage["terminal_predecessor"]
        self.assertEqual(terminal["attempts"], 1)
        self.assertEqual(terminal["maximum_attempts"], 2)
        self.assertEqual(
            terminal["bundle_digest"],
            "839e08f7cbbedacc950ed9606e8ddad62c82df6613eeb99b1a4b22f56688b6b6",
        )
        self.assertEqual(
            terminal["snapshot_digest"],
            "939cbcbef2d07a9295e0077d69d3f1ec34f9b74708a84f1c26c8e4cc0b458934",
        )
        self.assertEqual(
            terminal["activation_receipt_digest"],
            "2e2ca358a31058656e0d9d3ccc84443625e9f9b08d117fedf26128e095ccb45c",
        )
        contract.validate_attempt_lineage(lineage, identity)

    def test_lineage_rejects_bundle_substitution_branch_and_unknown_fields(self) -> None:
        identity = self._identity()
        lineage = contract.build_attempt_lineage(identity)
        substituted = copy.deepcopy(identity)
        substituted["controller_source_sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            contract.validate_attempt_lineage(lineage, substituted)
        changed = copy.deepcopy(lineage)
        changed["terminal_predecessor"]["transition_digest"] = "0" * 64
        with self.assertRaises(ValueError):
            contract.validate_attempt_lineage(changed, identity)
        with self.assertRaises(ValueError):
            contract.validate_attempt_lineage({**lineage, "unknown": True}, identity)

    def test_same_core_strategy_and_legacy_lineage_are_handled_explicitly(self) -> None:
        identity = self._identity()
        unchanged = copy.deepcopy(identity)
        unchanged["core_source_commit"] = contract._ACTIVE_ATTEMPT_PREDECESSOR[
            "active_core_source_commit"
        ]
        with self.assertRaisesRegex(ValueError, "no Core behavior change"):
            contract.build_attempt_lineage(unchanged)
        legacy = contract._build_legacy_attempt_lineage(identity)
        self.assertEqual(legacy["schema"], contract.ATTEMPT_LINEAGE_SCHEMA_V1)
        self.assertEqual(
            legacy["state_namespace"], "p16-successor-attempt-series-v1"
        )
        self.assertEqual(
            legacy["terminal_predecessor"]["bundle_digest"],
            "8083194816861adb07a2ba107a5c04d591bb477c7517b05554fe92af5608401e",
        )
        contract.validate_attempt_lineage(legacy, identity)


class P16SuccessorAttemptSeriesRuntimeV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("exact owner/mode attempt-series tests require root")

    def _bundle(self) -> dict[str, object]:
        identity = P16SuccessorAttemptSeriesContractV1Tests()._identity()
        return {
            **identity,
            "attempt_lineage": contract.build_attempt_lineage(identity),
            "bundle_digest": "f" * 64,
        }

    @contextmanager
    def _patched(self, root: Path):
        lock = root / "terminal-series.lock"
        lock.write_bytes(b"")
        os.chmod(lock, 0o600)
        with ExitStack() as stack:
            predecessor_root = root / "predecessor-series-v1"
            successor_root = root / "projection-budget-series-v1"
            stack.enter_context(
                mock.patch.multiple(
                    activation,
                    SUCCESSOR_STATE_ROOT=predecessor_root,
                    PROJECTION_BUDGET_SUCCESSOR_STATE_ROOT=successor_root,
                    ATTEMPT_LOCK=lock,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    activation, "_validate_terminal_predecessor", return_value=None
                )
            )
            stack.enter_context(
                mock.patch.object(
                    activation,
                    "validate_attempt_lineage",
                    side_effect=lambda value, _identity: value,
                )
            )
            yield

    def test_read_only_projection_starts_new_series_at_zero_without_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = self._bundle()
            with self._patched(root):
                projection = activation._attempt_projection(bundle)
            self.assertEqual(projection["attempts"], 0)
            self.assertEqual(projection["maximum_attempts"], 2)
            self.assertEqual(projection["series_state"], "absent")
            self.assertFalse((root / "projection-budget-series-v1").exists())

    def test_attempts_one_and_two_append_and_third_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = self._bundle()
            with self._patched(root):
                self.assertEqual(activation._consume_attempt(bundle, "1" * 64), 1)
                first_path = root / "projection-budget-series-v1" / "attempt-0001.json"
                first = first_path.read_bytes()
                first_value = activation._read_canonical(first_path, maximum=4096)
                self.assertEqual(first_value["predecessor_remaining_attempts_retired"], 1)
                self.assertEqual(activation._consume_attempt(bundle, "2" * 64), 2)
                self.assertEqual(
                    activation._attempt_projection(bundle)["attempts"], 2
                )
                with self.assertRaisesRegex(
                    activation.P16Phase1T2Rejected, "live_attempt_budget_exhausted"
                ):
                    activation._consume_attempt(bundle, "3" * 64)
            self.assertEqual(
                first,
                first_path.read_bytes(),
            )
            self.assertFalse((root / "predecessor-series-v1").exists())

    def test_bundle_branch_replay_partial_and_permission_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = self._bundle()
            with self._patched(root):
                activation._consume_attempt(bundle, "1" * 64)
                branch = copy.deepcopy(bundle)
                branch["bundle_digest"] = "e" * 64
                with self.assertRaises(activation.P16Phase1T2Rejected):
                    activation._attempt_projection(branch)
                series = root / "projection-budget-series-v1"
                (series / ".attempt-0002.crash").write_bytes(b"partial")
                with self.assertRaisesRegex(
                    activation.P16Phase1T2Rejected,
                    "successor_attempt_series_partial",
                ):
                    activation._attempt_projection(bundle)
                (series / ".attempt-0002.crash").unlink()
                os.chmod(series / "attempt-0001.json", 0o644)
                with self.assertRaises(activation.P16Phase1T2Rejected):
                    activation._attempt_projection(bundle)

    def test_two_concurrent_consumers_append_one_attempt_each(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = self._bundle()

            def consume() -> int | str:
                try:
                    return activation._consume_attempt(bundle, "1" * 64)
                except activation.P16Phase1T2Rejected as exc:
                    return exc.code

            with self._patched(root), ThreadPoolExecutor(max_workers=2) as pool:
                results = sorted(pool.map(lambda _unused: consume(), range(2)), key=str)
            self.assertEqual(results, [1, 2])
            self.assertTrue(
                (root / "projection-budget-series-v1" / "attempt-0001.json").is_file()
            )
            self.assertTrue(
                (root / "projection-budget-series-v1" / "attempt-0002.json").is_file()
            )
            self.assertFalse((root / "predecessor-series-v1").exists())


if __name__ == "__main__":
    unittest.main()
