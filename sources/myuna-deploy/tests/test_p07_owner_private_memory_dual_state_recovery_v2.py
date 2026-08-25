from __future__ import annotations

import json
import os
from contextlib import ExitStack
import inspect
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import activate_p07_owner_private_memory_dual_state_recovery_v2 as recovery
import activate_p07_owner_private_memory_v1 as memory


def _write(path: Path, payload: bytes, mode: int = 0o600) -> str:
    path.write_bytes(payload)
    os.chmod(path, mode)
    return memory.digest_file(path)


def _predecessor_projection() -> dict[str, object]:
    return {
        "archive_evidence_digest": "1" * 64,
        "archive_gid": 982,
        "archive_id": "p07-owner-private-memory-v1-" + "2" * 16,
        "archive_uid": 988,
        "attempt1_receipt_sha256": "3" * 64,
        "attempt2_receipt_sha256": "4" * 64,
        "attempts": 2,
        "backup_evidence_digest": "5" * 64,
        "backup_root": memory.lineage.BACKUP_ROOT.as_posix(),
        "diagnosis_handoff_sha256": "6" * 64,
        "dual_state_t1_handoff_sha256": "7" * 64,
        "hard_stop_handoff_sha256": "8" * 64,
        "last_plan_sha256": "9" * 64,
        "ledger_sha256": "a" * 64,
        "maximum_attempts": 2,
        "preflight_sha256": "b" * 64,
        "schema": recovery.IMMUTABLE_PREDECESSOR_SCHEMA,
        "state_evidence_digest": "c" * 64,
        "state_root": memory.lineage.STATE_ROOT.as_posix(),
        "strategy_id": "p07-policy-overlay-v1",
    }


class DualStateRecoveryV2Tests(unittest.TestCase):
    def test_v2_identity_is_distinct_and_exactly_one_attempt(self) -> None:
        selected = memory.DUAL_STATE_RECOVERY_V2_STRATEGY
        self.assertEqual(selected.maximum_attempts, 1)
        self.assertNotEqual(selected.strategy_id, memory.LEGACY_ATTEMPT_STRATEGY.strategy_id)
        self.assertNotEqual(selected.state_root, memory.LEGACY_ATTEMPT_STRATEGY.state_root)
        self.assertNotEqual(selected.backup_root, memory.LEGACY_ATTEMPT_STRATEGY.backup_root)
        self.assertNotEqual(selected.attempt_schema, memory.LEGACY_ATTEMPT_STRATEGY.attempt_schema)
        preparation_source = inspect.getsource(memory.prepare_activation)
        self.assertIn('"immutable_predecessor_digest"', preparation_source)
        self.assertIn('"attempt_strategy"', preparation_source)

    def test_v2_lineage_keeps_exhausted_predecessor_and_reports_zero_to_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            p16_attempt = Path(directory) / "attempt-0001.json"
            p16_attempt.write_text("{}", encoding="ascii")
            predecessor = _predecessor_projection()
            with (
                patch.object(memory, "_verify_evidence"),
                patch.object(memory, "P16_ATTEMPT", p16_attempt),
                patch.object(memory, "_absent", return_value=True),
            ):
                result = memory._verify_attempt_lineages(
                    rejected_call=Path("rejected"),
                    p16_handoff=Path("p16"),
                    p01_handoff=Path("p01"),
                    attempt_strategy=memory.DUAL_STATE_RECOVERY_V2_STRATEGY,
                    immutable_predecessor=predecessor,
                )
            self.assertEqual(result["p07"]["consumed"], 0)
            self.assertEqual(result["p07"]["next"], 1)
            self.assertEqual(result["p07"]["maximum"], 1)
            self.assertEqual(result["p07"]["immutable_predecessor"]["attempts"], 2)
            self.assertEqual(
                result["p07"]["immutable_predecessor"]["maximum_attempts"], 2
            )

    def test_v2_lineage_rejects_predecessor_reset_and_boolean_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            p16_attempt = Path(directory) / "attempt-0001.json"
            p16_attempt.write_text("{}", encoding="ascii")
            for field, value in (("attempts", 0), ("maximum_attempts", 3), ("archive_uid", True)):
                predecessor = _predecessor_projection()
                predecessor[field] = value
                with (
                    patch.object(memory, "_verify_evidence"),
                    patch.object(memory, "P16_ATTEMPT", p16_attempt),
                    patch.object(memory, "_absent", return_value=True),
                    self.assertRaisesRegex(
                        memory.MemoryActivationRejected,
                        "p07_v2_immutable_predecessor_rejected",
                    ),
                ):
                    memory._verify_attempt_lineages(
                        rejected_call=Path("rejected"),
                        p16_handoff=Path("p16"),
                        p01_handoff=Path("p01"),
                        attempt_strategy=memory.DUAL_STATE_RECOVERY_V2_STRATEGY,
                        immutable_predecessor=predecessor,
                    )

    def test_v2_preflight_is_deterministic_zero_to_one_max_one(self) -> None:
        prepared = SimpleNamespace(
            attempt_strategy=memory.DUAL_STATE_RECOVERY_V2_STRATEGY,
            backup_ready=True,
            expected_attempts=0,
            memory_release_set_id="1" * 64,
            parent=SimpleNamespace(release_set_id="2" * 64),
            plan_digest="3" * 64,
        )
        first = memory.preflight_projection(prepared)
        second = memory.preflight_projection(prepared)
        self.assertEqual(memory.canonical(first), memory.canonical(second))
        self.assertEqual(first["attempts"], 0)
        self.assertEqual(first["next_attempt"], 1)
        self.assertEqual(first["maximum_attempts"], 1)
        self.assertEqual(first["schema"], memory.DUAL_STATE_RECOVERY_V2_STRATEGY.preflight_schema)

    def test_v2_consumes_only_one_attempt_in_distinct_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            strategy = memory.MemoryAttemptStrategy(
                strategy_id=memory.DUAL_STATE_RECOVERY_V2_STRATEGY.strategy_id,
                activation_schema=memory.DUAL_STATE_RECOVERY_V2_STRATEGY.activation_schema,
                preflight_schema=memory.DUAL_STATE_RECOVERY_V2_STRATEGY.preflight_schema,
                backup_schema=memory.DUAL_STATE_RECOVERY_V2_STRATEGY.backup_schema,
                attempt_schema=memory.DUAL_STATE_RECOVERY_V2_STRATEGY.attempt_schema,
                state_root=root / "v2-state",
                backup_root=root / "v2-backup",
                maximum_attempts=1,
            )
            prepared = SimpleNamespace(
                attempt_strategy=strategy,
                expected_attempts=0,
                plan_digest="4" * 64,
            )
            with patch.object(memory, "DUAL_STATE_RECOVERY_V2_STRATEGY", strategy):
                backend = memory.LiveMemoryBackend(prepared)
                self.assertEqual(backend.consume_attempt(), 1)
                ledger = json.loads(strategy.attempt_ledger.read_text("ascii"))
                self.assertEqual(
                    ledger,
                    {
                        "attempts": 1,
                        "last_plan_sha256": prepared.plan_digest,
                        "schema": strategy.attempt_schema,
                    },
                )
                with self.assertRaisesRegex(
                    memory.MemoryActivationRejected, "p07_attempt_state_preexisting"
                ):
                    backend.consume_attempt()
                prepared.expected_attempts = 1
                with self.assertRaisesRegex(
                    memory.MemoryActivationRejected, "p07_attempt_lineage_drifted"
                ):
                    memory.LiveMemoryBackend(prepared).consume_attempt()

    def test_v2_backup_is_non_overwriting_and_precedes_attempt_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            strategy = memory.MemoryAttemptStrategy(
                strategy_id=memory.DUAL_STATE_RECOVERY_V2_STRATEGY.strategy_id,
                activation_schema=memory.DUAL_STATE_RECOVERY_V2_STRATEGY.activation_schema,
                preflight_schema=memory.DUAL_STATE_RECOVERY_V2_STRATEGY.preflight_schema,
                backup_schema=memory.DUAL_STATE_RECOVERY_V2_STRATEGY.backup_schema,
                attempt_schema=memory.DUAL_STATE_RECOVERY_V2_STRATEGY.attempt_schema,
                state_root=root / "v2-state",
                backup_root=root / "v2-backup",
                maximum_attempts=1,
            )
            prepared = SimpleNamespace(
                attempt_strategy=strategy,
                backup_ready=False,
                expected_attempts=0,
                plan_digest="d" * 64,
                plan_bytes=b'{"schema":"v2"}\n',
                prestate={"archive_prestate": {"runtime_root_absent": False}},
                prestate_payloads={"CORE_BINDING": b"binding\n"},
                prior_plan_digest=None,
                prior_backup_sha256=None,
                prior_backup_evidence_digest=None,
            )
            with patch.object(memory, "DUAL_STATE_RECOVERY_V2_STRATEGY", strategy):
                result = memory.prepare_plan_bound_backup(prepared)
                self.assertEqual(result["status"], "backup_ready")
                self.assertFalse(strategy.state_root.exists())
                self.assertTrue(
                    memory._plan_backup_matches(
                        plan_digest=prepared.plan_digest,
                        plan_bytes=prepared.plan_bytes,
                        prestate=prepared.prestate,
                        prestate_payloads=prepared.prestate_payloads,
                        backup_root=strategy.backup_root,
                    )
                )
                with self.assertRaisesRegex(
                    memory.MemoryActivationRejected, "memory_plan_backup_preexisting"
                ):
                    memory.prepare_plan_bound_backup(prepared)

    def test_v2_controller_has_no_reset_delete_or_private_egress_primitive(self) -> None:
        source = inspect.getsource(recovery)
        for forbidden in (
            "reset --hard",
            "git reset",
            "shutil.rmtree",
            "os.remove",
            "unlink(",
            "sqlite3",
            "requests.",
            "httpx.",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("_legacy_continuation_arguments_absent", source)
        self.assertIn("maximum_attempts=1", inspect.getsource(memory))

    def test_v2_attempt_zero_preserves_existing_predecessor_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime_root = root / "runtime"
            runtime_root.mkdir(mode=0o700)
            archive_id = "p07-owner-private-memory-v1-" + "5" * 16
            (runtime_root / archive_id).mkdir(mode=0o700)
            uid = os.getuid()
            gid = os.getgid()
            with patch.object(memory, "MEMORY_RUNTIME_ROOT", runtime_root):
                evidence = memory._memory_runtime_root_evidence(
                    archive_ids={archive_id},
                    expected_uid=uid,
                    expected_gid=gid,
                    empty_archive_ids={archive_id},
                    code="synthetic_archive_rejected",
                )
                prepared = SimpleNamespace(
                    attempt_strategy=memory.LEGACY_ATTEMPT_STRATEGY,
                    expected_attempts=0,
                    plan_digest="6" * 64,
                    prestate={
                        "archive_prestate": {"runtime_root_absent": False},
                        "lineages": {
                            "p07": {
                                "prior_evidence": {
                                    "archive_evidence_digest": evidence,
                                    "archive_gid": gid,
                                    "archive_id": archive_id,
                                    "archive_uid": uid,
                                }
                            }
                        },
                    },
                )
                memory.LiveMemoryBackend(prepared)._verify_memory_runtime_prestate()
                (runtime_root / ("p07-owner-private-memory-v1-" + "7" * 16)).mkdir(
                    mode=0o700
                )
                with self.assertRaisesRegex(
                    memory.MemoryActivationRejected, "memory_runtime_prestate_drifted"
                ):
                    memory.LiveMemoryBackend(prepared)._verify_memory_runtime_prestate()

    def test_immutable_predecessor_verifier_binds_all_three_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            backup = root / "backup"
            archive = root / "archive"
            for path in (state, backup, archive):
                path.mkdir(mode=0o700)
                os.chmod(path, 0o700)
            plan = "8" * 64
            ledger_payload = memory.canonical(
                {
                    "attempts": 2,
                    "last_plan_sha256": plan,
                    "schema": memory.lineage.ATTEMPT_SCHEMA,
                }
            )
            state_files = {
                "ATTEMPT_LEDGER.json": _write(state / "ATTEMPT_LEDGER.json", ledger_payload),
                "JOURNAL-one.json": _write(state / "JOURNAL-one.json", b"one\n"),
                "JOURNAL-two.json": _write(state / "JOURNAL-two.json", b"two\n"),
                "RECEIPT-one.json": _write(state / "RECEIPT-one.json", b"one\n"),
                "RECEIPT-two.json": _write(state / "RECEIPT-two.json", b"two\n"),
            }
            backup_plans = {"9" * 64, plan}
            for name in backup_plans:
                (backup / name).mkdir(mode=0o700)
            archive_id = "p07-owner-private-memory-v1-" + "a" * 16
            (archive / archive_id).mkdir(mode=0o700)
            handoffs = [root / f"handoff-{index}.md" for index in range(3)]
            for index, path in enumerate(handoffs):
                _write(path, f"handoff-{index}\n".encode("ascii"))
            preflights = [root / f"preflight-{index}.json" for index in range(2)]
            for path in preflights:
                _write(path, b'{"status":"ready"}\n')
            state_digest = recovery._protected_tree_digest(state, code="synthetic")
            backup_digest = recovery._protected_tree_digest(backup, code="synthetic")
            archive_tree_digest = recovery._protected_tree_digest(archive, code="synthetic")
            with patch.object(memory, "MEMORY_RUNTIME_ROOT", archive):
                archive_evidence = memory._memory_runtime_root_evidence(
                    archive_ids={archive_id},
                    expected_uid=os.getuid(),
                    expected_gid=os.getgid(),
                    empty_archive_ids={archive_id},
                    code="synthetic",
                )
            patches = (
                patch.object(recovery, "LEGACY_STATE_ROOT", state),
                patch.object(recovery, "LEGACY_BACKUP_ROOT", backup),
                patch.object(recovery, "LEGACY_ARCHIVE_ROOT", archive),
                patch.object(recovery, "LEGACY_ARCHIVE_ID", archive_id),
                patch.object(recovery, "LEGACY_ARCHIVE_UID", os.getuid()),
                patch.object(recovery, "LEGACY_ARCHIVE_GID", os.getgid()),
                patch.object(recovery, "LEGACY_ARCHIVE_EVIDENCE_DIGEST", archive_evidence),
                patch.object(recovery, "LEGACY_STATE_TREE_DIGEST", state_digest),
                patch.object(recovery, "LEGACY_BACKUP_TREE_DIGEST", backup_digest),
                patch.object(recovery, "LEGACY_ARCHIVE_TREE_DIGEST", archive_tree_digest),
                patch.object(
                    recovery,
                    "LEGACY_LEDGER_SHA256",
                    state_files["ATTEMPT_LEDGER.json"],
                ),
                patch.object(
                    recovery,
                    "LEGACY_ATTEMPT1_RECEIPT_SHA256",
                    state_files["RECEIPT-one.json"],
                ),
                patch.object(
                    recovery,
                    "LEGACY_ATTEMPT2_RECEIPT_SHA256",
                    state_files["RECEIPT-two.json"],
                ),
                patch.object(recovery, "LEGACY_LAST_PLAN_SHA256", plan),
                patch.object(
                    recovery,
                    "LEGACY_FORMAL_PREFLIGHT_SHA256",
                    memory.digest_file(preflights[0]),
                ),
                patch.object(
                    recovery,
                    "HARD_STOP_HANDOFF_SHA256",
                    memory.digest_file(handoffs[0]),
                ),
                patch.object(
                    recovery,
                    "DIAGNOSIS_HANDOFF_SHA256",
                    memory.digest_file(handoffs[1]),
                ),
                patch.object(
                    recovery,
                    "DUAL_STATE_T1_HANDOFF_SHA256",
                    memory.digest_file(handoffs[2]),
                ),
                patch.object(recovery, "_STATE_FILES", state_files),
                patch.object(recovery, "_BACKUP_PLANS", backup_plans),
            )
            with ExitStack() as stack:
                for selected in patches:
                    stack.enter_context(selected)
                stack.enter_context(
                    patch.object(memory, "MEMORY_RUNTIME_ROOT", archive)
                )
                projection = recovery.verify_immutable_predecessor(
                    hard_stop_handoff=handoffs[0],
                    diagnosis_handoff=handoffs[1],
                    dual_state_t1_handoff=handoffs[2],
                    formal_preflight_one=preflights[0],
                    formal_preflight_two=preflights[1],
                    state_root=state,
                    backup_root=backup,
                    archive_root=archive,
                )
                self.assertEqual(projection["attempts"], 2)
                self.assertEqual(projection["maximum_attempts"], 2)
                self.assertEqual(projection["state_evidence_digest"], state_digest)
                _write(state / "RECEIPT-two.json", b"tampered\n")
                with self.assertRaisesRegex(
                    memory.MemoryActivationRejected,
                    "p07_v2_immutable_predecessor_drifted",
                ):
                    recovery.verify_immutable_predecessor(
                        hard_stop_handoff=handoffs[0],
                        diagnosis_handoff=handoffs[1],
                        dual_state_t1_handoff=handoffs[2],
                        formal_preflight_one=preflights[0],
                        formal_preflight_two=preflights[1],
                        state_root=state,
                        backup_root=backup,
                        archive_root=archive,
                    )


if __name__ == "__main__":
    unittest.main()
