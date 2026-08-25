from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from myuna_core.external_context.release_set import (
    P07DReleaseSet,
    RELEASE_SET_EPOCH_ID,
    RELEASE_SET_EPOCH_PATH,
    RELEASE_SET_GENERATION,
)

from p07_d_activation_transaction import (
    _S2_ATTEMPT,
    _S2_GEN0,
    _S2_PROGRAM,
    _S2_REVERSE,
    _S2_SCHEMA,
    _S3_FORWARD_OLD,
    _S2_SOURCE,
    _s2_bytes,
    _s2_initialize,
    _s2_parse,
    _s2_plan_id,
    _s2_program_body,
    _s2_record,
    _s2_recover_once,
    _s2_recovery_side,
    ActivationPrestate,
    AtomicReleaseSetTransaction,
    FunctionalObservation,
    ReleaseSetActivationRejected,
    ServiceObservation,
    TargetPreflightObservation,
    verify_stable_functional_rollback,
)
from p07_d_release_set import (
    ProtectedReleaseSetRejected,
    ProtectedReleaseSetSnapshot,
    load_protected_release_set_snapshot,
    require_effective_credential_projection,
    require_runtime_binding_projection,
)


def release_set() -> P07DReleaseSet:
    return P07DReleaseSet.create(
        core={
            "entrypoint": "/release/core/main.py",
            "file_count": 3,
            "inventory_digest": "1" * 64,
            "release_digest": "2" * 64,
            "tree_digest": "3" * 64,
        },
        telegram_runtime={
            "entrypoint": "/release/runtime/gateway.py",
            "file_count": 4,
            "inventory_digest": "4" * 64,
            "release_digest": "5" * 64,
        },
        selector={
            "digest": "6" * 64,
            "generation": RELEASE_SET_GENERATION,
            "path": "/etc/myuna/selector.json",
            "schema": "myuna.external-epoch-selector.v2",
        },
        runtime_config={
            "binding_digest": "7" * 64,
            "channel_kind": "astrbot_telegram",
            "digest": "8" * 64,
            "gid": os.getgid(),
            "mode": 0o640,
            "namespace_id": "namespace-synthetic",
            "path": "/etc/myuna/runtime.json",
            "principal_id": "principal-synthetic",
            "uid": os.getuid(),
        },
        credential={
            "dropin_set_digest": "9" * 64,
            "effective_count": 1,
            "effective_source": "/etc/myuna/secret",
            "name": "deepseek_api_key",
            "projection_digest": "a" * 64,
            "source_category": "systemd_load_credential",
        },
        epoch={
            "database_path": RELEASE_SET_EPOCH_PATH,
            "directory_mode": 0o700,
            "epoch_id": RELEASE_SET_EPOCH_ID,
            "file_mode": 0o600,
            "gid": os.getgid(),
            "schema": "myuna.external-authorized-epoch.v3",
            "schema_version": 3,
            "uid": os.getuid(),
        },
        services=[
            {"binding_digest": "5" * 64, "desired_state": "active", "gid": os.getgid(), "kind": "core", "stable_observation_seconds": 5, "uid": os.getuid(), "unit": "core.service"},
            {"binding_digest": "6" * 64, "desired_state": "active", "gid": os.getgid(), "kind": "telegram", "stable_observation_seconds": 5, "uid": os.getuid(), "unit": "telegram.service"},
            {"binding_digest": "7" * 64, "desired_state": "active", "gid": os.getgid(), "kind": "telegram_socket", "stable_observation_seconds": 5, "uid": os.getuid(), "unit": "telegram.socket"},
        ],
        rollback={
            "core_release_digest": "b" * 64,
            "desired_service_states_digest": "c" * 64,
            "epoch_bundle_digest": "d" * 64,
            "manifest_digest": "e" * 64,
            "runtime_release_digest": "f" * 64,
            "selector_digest": "0" * 64,
        },
    )


def target_observation(selected: P07DReleaseSet) -> FunctionalObservation:
    return FunctionalObservation(
        services=(
            ServiceObservation("core.service", "active", "running", "success", 2),
            ServiceObservation("telegram.service", "active", "running", "success", 0),
            ServiceObservation("telegram.socket", "active", "listening", "success", 0),
        ),
        service_binding_digests=tuple(
            sorted((item["unit"], item["binding_digest"]) for item in selected.services)
        ),
        selected_release_set_id=selected.release_set_id,
        core_release_digest=selected.core["release_digest"],
        runtime_release_digest=selected.telegram_runtime["release_digest"],
        selector_digest=selected.selector["digest"],
        runtime_config_digest=selected.runtime_config["digest"],
        credential_projection_digest=selected.credential["projection_digest"],
        epoch_identity_digest=selected.epoch_identity_digest,
        selected_failed_epoch=False,
    )


def rollback_observation() -> FunctionalObservation:
    return FunctionalObservation(
        services=(
            ServiceObservation("core.service", "active", "running", "success", 54),
            ServiceObservation("telegram.service", "active", "running", "success", 0),
            ServiceObservation("telegram.socket", "active", "listening", "success", 0),
        ),
        service_binding_digests=(("core.service", "5" * 64), ("telegram.service", "6" * 64), ("telegram.socket", "7" * 64)),
        selected_release_set_id=None,
        core_release_digest="b" * 64,
        runtime_release_digest="f" * 64,
        selector_digest="0" * 64,
        runtime_config_digest="2" * 64,
        credential_projection_digest="3" * 64,
        epoch_identity_digest="4" * 64,
        selected_failed_epoch=False,
    )


def preflight_observation(selected: P07DReleaseSet) -> TargetPreflightObservation:
    return TargetPreflightObservation(
        core_file_count=selected.core["file_count"],
        core_inventory_digest=selected.core["inventory_digest"],
        core_release_digest=selected.core["release_digest"],
        core_tree_digest=selected.core["tree_digest"],
        runtime_file_count=selected.telegram_runtime["file_count"],
        runtime_inventory_digest=selected.telegram_runtime["inventory_digest"],
        runtime_release_digest=selected.telegram_runtime["release_digest"],
        selector_digest=selected.selector["digest"],
        selector_generation=selected.selector["generation"],
        selector_schema=selected.selector["schema"],
        runtime_config_path=selected.runtime_config["path"],
        runtime_config_digest=selected.runtime_config["digest"],
        runtime_binding_digest=selected.runtime_config["binding_digest"],
        credential_name=selected.credential["name"],
        credential_effective_count=selected.credential["effective_count"],
        credential_effective_source=selected.credential["effective_source"],
        credential_dropin_set_digest=selected.credential["dropin_set_digest"],
        credential_projection_digest=selected.credential["projection_digest"],
        credential_source_category=selected.credential["source_category"],
        target_epoch_path=selected.epoch["database_path"],
        target_epoch_exists=False,
        failed_epoch_selected=False,
        service_binding_digests=tuple(
            sorted((item["unit"], item["binding_digest"]) for item in selected.services)
        ),
    )


class ReleaseSetTransactionTests(unittest.TestCase):
    def test_stage_one_owner_admission_is_effect_free(self) -> None:
        with self.assertRaisesRegex(
            ReleaseSetActivationRejected,
            "phase_f_target_artifact_required",
        ):
            AtomicReleaseSetTransaction.enter_canonical_owner()
        artifact = {"owner_chain": [
            "telegram_r5_boot_resume.main",
            "activate_p07_d_generation13_v1.controller_entry",
            "p07_d_activation_transaction.AtomicReleaseSetTransaction.enter_canonical_owner",
            "activate_p07_d_generation13_v1.Generation13LiveBackend",
        ]}
        with self.assertRaisesRegex(
            ReleaseSetActivationRejected,
            "phase_f_target_artifact_not_verified",
        ):
            AtomicReleaseSetTransaction.enter_canonical_owner(
                release_root=Path("/nonexistent/controller-release"),
                selected_release_sha256="a" * 64,
                selected_config_sha256="b" * 64,
                selected_authority_sha256="c" * 64,
                t2_receipts=None,
            )
        with patch(
            "p07_d_activation_transaction.verify_controller_release_authority",
            return_value=artifact,
        ), self.assertRaisesRegex(
            ReleaseSetActivationRejected, "phase_f_t2_pair_required"
        ):
            AtomicReleaseSetTransaction.enter_canonical_owner(
                release_root=Path("sealed-release"),
                selected_release_sha256="a" * 64,
                selected_config_sha256="b" * 64,
                selected_authority_sha256="c" * 64,
                t2_receipts=None,
            )
        with patch(
            "p07_d_activation_transaction.verify_controller_release_authority",
            return_value=artifact,
        ), self.assertRaisesRegex(
            ReleaseSetActivationRejected, "phase_f_t2_observation_stage_required"
        ):
            AtomicReleaseSetTransaction.enter_canonical_owner(
                release_root=Path("sealed-release"),
                selected_release_sha256="a" * 64,
                selected_config_sha256="b" * 64,
                selected_authority_sha256="c" * 64,
                t2_receipts=({"collector": "one"}, {"collector": "two"}),
            )
        with self.assertRaisesRegex(
            ReleaseSetActivationRejected,
            "phase_f_t2_terminal_not_implemented",
        ):
            _s2_parse(
                _s2_bytes(
                    _s2_record(
                        "TERMINAL_TARGET",
                        1,
                        "e" * 64,
                    )
                )
            )

    def test_protected_snapshot_and_binding_projections(self) -> None:
        selected = release_set()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release-set.json"
            path.write_text(json.dumps(selected.as_payload(), sort_keys=True), encoding="utf-8")
            path.chmod(0o640)
            snapshot = load_protected_release_set_snapshot(
                path,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
            )
            self.assertEqual(snapshot.release_set, selected)
            require_runtime_binding_projection(
                snapshot,
                runtime_config_path=Path("/etc/myuna/runtime.json"),
                runtime_config_digest="8" * 64,
                binding_digest="7" * 64,
                channel_kind="astrbot_telegram",
                principal_id="principal-synthetic",
                namespace_id="namespace-synthetic",
            )
            require_effective_credential_projection(
                snapshot,
                name="deepseek_api_key",
                source=Path("/etc/myuna/secret"),
                dropin_set_digest="9" * 64,
                projection_digest="a" * 64,
                effective_count=1,
            )

    def test_symlink_mode_and_document_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text("{}", encoding="utf-8")
            target.chmod(0o640)
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaisesRegex(ProtectedReleaseSetRejected, "type_rejected"):
                load_protected_release_set_snapshot(link, expected_uid=os.getuid(), expected_gid=os.getgid())
            target.chmod(0o644)
            with self.assertRaisesRegex(ProtectedReleaseSetRejected, "mode_rejected"):
                load_protected_release_set_snapshot(target, expected_uid=os.getuid(), expected_gid=os.getgid())

    def test_rollback_accepts_restart_counter_reset_after_functional_restore(self) -> None:
        expected = rollback_observation()
        restored = replace(
            expected,
            services=(
                replace(expected.services[0], nrestarts=0),
                *expected.services[1:],
            ),
        )
        verify_stable_functional_rollback(expected, restored, restored)

    def test_rollback_rejects_restart_counter_above_prestate(self) -> None:
        expected = replace(
            rollback_observation(),
            services=(
                replace(rollback_observation().services[0], nrestarts=0),
                *rollback_observation().services[1:],
            ),
        )
        restarted = replace(
            expected,
            services=(replace(expected.services[0], nrestarts=1), *expected.services[1:]),
        )
        with self.assertRaisesRegex(
            ReleaseSetActivationRejected,
            "rollback_restart_counter_increased_from_prestate",
        ):
            verify_stable_functional_rollback(expected, restarted, restarted)

    def test_rollback_rejects_restart_counter_increase_during_observation(self) -> None:
        expected = rollback_observation()
        first = replace(
            expected,
            services=(replace(expected.services[0], nrestarts=0), *expected.services[1:]),
        )
        second = replace(
            expected,
            services=(replace(expected.services[0], nrestarts=1), *expected.services[1:]),
        )
        with self.assertRaisesRegex(
            ReleaseSetActivationRejected,
            "rollback_restart_counter_increased_during_observation",
        ):
            verify_stable_functional_rollback(expected, first, second)

    def test_rollback_accepts_non_increasing_restart_counter_during_observation(self) -> None:
        expected = rollback_observation()
        first = replace(
            expected,
            services=(replace(expected.services[0], nrestarts=1), *expected.services[1:]),
        )
        second = replace(
            expected,
            services=(replace(expected.services[0], nrestarts=0), *expected.services[1:]),
        )
        verify_stable_functional_rollback(expected, first, second)


class DurableJournalTests(unittest.TestCase):
    def journal_parent(self, root: str) -> Path:
        path = Path(root) / "journal"
        path.mkdir(mode=0o700)
        path.chmod(0o700)
        return path

    @staticmethod
    def independent_bytes(value: object) -> bytes:
        return json.dumps(value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"

    def test_plan_and_gen0_bytes_are_independently_recomputed(self) -> None:
        body = {"attempt": 3, "program": _s2_program_body(), "source_commit": _S2_SOURCE}
        expected_plan = hashlib.sha256(b"myuna.phase-f.stage2.plan.v1\0" + self.independent_bytes(body)).hexdigest()
        self.assertEqual(_s2_plan_id(), expected_plan)
        with tempfile.TemporaryDirectory() as root:
            parent = self.journal_parent(root)
            self.assertTrue(_s2_initialize(parent))
            persisted = parent / _S2_ATTEMPT / _S2_GEN0
            raw = persisted.read_bytes()
            expected = {
                "attempt": 3,
                "kind": "GEN0",
                "operation_id": None,
                "plan_id": expected_plan,
                "predecessor_sha256": None,
                "program": body["program"],
                "schema": _S2_SCHEMA,
                "sequence": 0,
                "source_commit": _S2_SOURCE,
                "stage_observation": None,
            }
            self.assertEqual(raw, self.independent_bytes(expected))
            self.assertEqual((parent / _S2_ATTEMPT).stat().st_mode & 0o777, 0o700)
            self.assertEqual(persisted.stat().st_mode & 0o777, 0o600)

    def test_parser_rejects_duplicates_unknown_bool_and_noncanonical(self) -> None:
        good = {
            "attempt": 3, "kind": "GEN0", "operation_id": None,
            "plan_id": _s2_plan_id(), "predecessor_sha256": None,
            "program": _s2_program_body(), "schema": _S2_SCHEMA,
            "sequence": 0, "source_commit": _S2_SOURCE, "stage_observation": None,
        }
        raw = self.independent_bytes(good)
        self.assertEqual(_s2_parse(raw), good)
        with self.assertRaises(ReleaseSetActivationRejected):
            _s2_parse(raw.replace(b'"attempt":3', b'"attempt":3,"attempt":3'))
        for mutation in (
            {**good, "extra": None},
            {key: value for key, value in good.items() if key != "program"},
            {**good, "attempt": True},
            {**good, "sequence": False},
        ):
            with self.assertRaises(ReleaseSetActivationRejected):
                _s2_parse(self.independent_bytes(mutation))
        with self.assertRaisesRegex(ReleaseSetActivationRejected, "journal_noncanonical"):
            _s2_parse(json.dumps(good, indent=2, sort_keys=True).encode() + b"\n")
        with self.assertRaises(ReleaseSetActivationRejected):
            _s2_parse(raw[:-1])

    def test_concurrent_gen0_has_one_creator_and_one_exact_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            parent = self.journal_parent(root)
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _index: _s2_initialize(parent), range(2)))
            self.assertEqual(sorted(results), [False, True])
            self.assertEqual(list((parent / _S2_ATTEMPT).iterdir()), [parent / _S2_ATTEMPT / _S2_GEN0])

    def test_intent_dispatched_already_desired_and_fresh_process(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            parent = self.journal_parent(root)
            _s2_initialize(parent)
            calls: list[str] = []
            self.assertEqual(_s2_recover_once(parent, observe=lambda _op: "DESIRED", apply=calls.append, invoke_writer=lambda: calls.append("writer")), "INTENT_DURABLE")
            self.assertEqual(calls, [])
            self.assertEqual(_s2_recover_once(parent, observe=lambda _op: "DESIRED", apply=calls.append, invoke_writer=lambda: calls.append("writer")), "DISPATCHED_DURABLE_NO_CALL")
            self.assertEqual(calls, [])
            code = (
                "from pathlib import Path; from p07_d_activation_transaction import _s2_recover_once; "
                f"print(_s2_recover_once(Path({str(parent)!r}), observe=lambda _:'DESIRED', apply=lambda _:None, invoke_writer=lambda:None))"
            )
            environment = dict(os.environ)
            environment["PYTHONPATH"] = os.pathsep.join((str(Path(__file__).parents[1] / "scripts"), str(Path(__file__).parents[1]), environment.get("PYTHONPATH", "")))
            completed = subprocess.run([sys.executable, "-c", code], check=True, capture_output=True, text=True, env=environment)
            self.assertEqual(completed.stdout.strip(), "DESIRED_DURABLE")
            self.assertEqual(calls, [])

    def test_exact_old_dispatch_lost_return_and_reobservation(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            parent = self.journal_parent(root); _s2_initialize(parent)
            _s2_recover_once(parent, observe=lambda _op: "OLD", apply=lambda _op: None, invoke_writer=lambda: None)
            _s2_recover_once(parent, observe=lambda _op: "OLD", apply=lambda _op: None, invoke_writer=lambda: None)
            calls: list[str] = []
            def lost(operation: str) -> None:
                calls.append(operation)
                raise RuntimeError("lost return")
            self.assertEqual(_s2_recover_once(parent, observe=lambda _op: "OLD", apply=lost, invoke_writer=lambda: None), "LOST_RETURN_REOBSERVE_REQUIRED")
            self.assertEqual(calls, [_S2_PROGRAM[0][0]])
            self.assertEqual(_s2_recover_once(parent, observe=lambda _op: "DESIRED", apply=calls.append, invoke_writer=lambda: None), "DESIRED_DURABLE")
            self.assertEqual(calls, [_S2_PROGRAM[0][0]])

    def test_all_non_prestate_observations_close_admission_without_apply(self) -> None:
        for observation in ("ALTERNATE", "UNKNOWN", "IN_FLIGHT", "ABA", "THIRD_STATE"):
            with self.subTest(observation=observation), tempfile.TemporaryDirectory() as root:
                parent = self.journal_parent(root); _s2_initialize(parent)
                # Converge O01, then reach dispatched O02.
                for _ in range(3):
                    _s2_recover_once(parent, observe=lambda _op: "DESIRED", apply=lambda _op: None, invoke_writer=lambda: None)
                _s2_recover_once(parent, observe=lambda _op: "DESIRED", apply=lambda _op: None, invoke_writer=lambda: None)
                _s2_recover_once(parent, observe=lambda _op: "DESIRED", apply=lambda _op: None, invoke_writer=lambda: None)
                applied: list[str] = []
                result = _s2_recover_once(parent, observe=lambda _op, value=observation: value, apply=applied.append, invoke_writer=lambda: None)
                self.assertEqual(result, "AMBIGUOUS_ADMISSION_CLOSED")
                self.assertEqual(applied, [])
                self.assertEqual(_s2_recovery_side(parent), "PRE_WRITER_ROLLBACK_ALLOWED")

    def advance_to_writer_intent(self, parent: Path) -> None:
        no_apply = lambda _operation: self.fail("already-desired stage applied")
        for _operation in _S2_PROGRAM:
            self.assertEqual(_s2_recover_once(parent, observe=lambda _op: "DESIRED", apply=no_apply, invoke_writer=lambda: None), "INTENT_DURABLE")
            self.assertEqual(_s2_recover_once(parent, observe=lambda _op: "DESIRED", apply=no_apply, invoke_writer=lambda: None), "DISPATCHED_DURABLE_NO_CALL")
            self.assertEqual(_s2_recover_once(parent, observe=lambda _op: "DESIRED", apply=no_apply, invoke_writer=lambda: None), "DESIRED_DURABLE")
        self.assertEqual(_s2_recover_once(parent, observe=lambda _op: "DESIRED", apply=no_apply, invoke_writer=lambda: None), "WRITER_INTENT_DURABLE")

    def test_writer_dispatched_is_irreversible_on_lost_return(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            parent = self.journal_parent(root); _s2_initialize(parent); self.advance_to_writer_intent(parent)
            calls: list[str] = []
            def lost_writer() -> None:
                calls.append("writer")
                raise RuntimeError("lost return")
            self.assertEqual(_s2_recover_once(parent, observe=lambda _op: "OLD", apply=lambda _op: self.fail(), invoke_writer=lost_writer), "WRITER_LOST_RETURN_POST_BOUNDARY")
            self.assertEqual(_s2_recovery_side(parent), "POST_WRITER_FORWARD_ONLY")
            self.assertEqual(_s2_recover_once(parent, observe=lambda _op: "OLD", apply=lambda _op: self.fail(), invoke_writer=lost_writer), "POST_WRITER_RECOVERY_REQUIRED")
            self.assertEqual(calls, ["writer"])
            names = [path.name for path in sorted((parent / _S2_ATTEMPT).iterdir())]
            self.assertTrue(names[-1].endswith("WRITER_DISPATCHED.json"))
            self.assertNotIn("DB", "".join(names).upper())

    def test_writer_return_is_durable_and_still_forward_only(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            parent = self.journal_parent(root); _s2_initialize(parent); self.advance_to_writer_intent(parent)
            calls: list[str] = []
            self.assertEqual(_s2_recover_once(parent, observe=lambda _op: "DESIRED", apply=lambda _op: self.fail(), invoke_writer=lambda: calls.append("writer")), "WRITER_RETURNED_POST_BOUNDARY")
            self.assertEqual(calls, ["writer"])
            self.assertEqual(_s2_recovery_side(parent), "POST_WRITER_FORWARD_ONLY")

    def test_gap_predecessor_symlink_mode_and_source_substitution_reject(self) -> None:
        mutations = ("gap", "duplicate", "sequence", "kind", "predecessor", "plan", "source", "mode", "symlink")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as root:
                parent = self.journal_parent(root); _s2_initialize(parent)
                attempt = parent / _S2_ATTEMPT
                gen0 = attempt / _S2_GEN0
                if mutation == "gap":
                    rogue = attempt / "J000002-OP_INTENT.json"; rogue.write_bytes(gen0.read_bytes()); rogue.chmod(0o600)
                elif mutation in {"duplicate", "sequence", "kind", "predecessor", "plan", "source"}:
                    value = json.loads(gen0.read_text())
                    value["sequence"] = 1; value["kind"] = "OP_INTENT"; value.pop("program")
                    value["operation_id"] = _S2_PROGRAM[0][0]
                    value["predecessor_sha256"] = hashlib.sha256(gen0.read_bytes()).hexdigest()
                    if mutation == "sequence": value["sequence"] = 2
                    if mutation == "kind": value["kind"] = "OP_DISPATCHED"
                    if mutation == "predecessor": value["predecessor_sha256"] = "0" * 64
                    if mutation == "plan": value["plan_id"] = "0" * 64
                    if mutation == "source": value["source_commit"] = "0" * 40
                    rogue = attempt / "J000001-OP_INTENT.json"; rogue.write_bytes(self.independent_bytes(value)); rogue.chmod(0o600)
                    if mutation == "duplicate":
                        duplicate = attempt / "J000001-OP_DISPATCHED.json"
                        duplicate_value = dict(value); duplicate_value["kind"] = "OP_DISPATCHED"
                        duplicate.write_bytes(self.independent_bytes(duplicate_value)); duplicate.chmod(0o600)
                elif mutation == "mode": gen0.chmod(0o644)
                else:
                    target = attempt / "target"; target.write_bytes(gen0.read_bytes()); target.chmod(0o600); gen0.unlink(); gen0.symlink_to(target.name)
                with self.assertRaises(ReleaseSetActivationRejected):
                    _s2_recovery_side(parent)

    def test_every_completed_pre_writer_prefix_has_exact_reverse_convergence(self) -> None:
        class Backend:
            def __init__(self) -> None:
                self.compensated: list[str] = []
                self.full_old_count = 0

            def observe_compensation(self, operation: str) -> str:
                return "OLD" if operation in self.compensated else "DESIRED"

            def compensate_operation(self, operation: str) -> None:
                self.compensated.append(operation)

            def observe_full_old(self) -> str:
                self.full_old_count += 1
                return "OLD"

        for completed_count in range(1, len(_S2_PROGRAM) + 1):
            with self.subTest(completed_count=completed_count), tempfile.TemporaryDirectory() as root:
                parent = self.journal_parent(root)
                _s2_initialize(parent)
                for _operation in _S2_PROGRAM[:completed_count]:
                    for expected in ("INTENT_DURABLE", "DISPATCHED_DURABLE_NO_CALL", "DESIRED_DURABLE"):
                        self.assertEqual(
                            _s2_recover_once(parent, observe=lambda _op: "DESIRED", apply=lambda _op: self.fail("desired stage applied"), invoke_writer=lambda: self.fail("writer invoked")),
                            expected,
                        )
                self.assertEqual(
                    _s2_recover_once(parent, observe=lambda _op: "DESIRED", apply=lambda _op: None, invoke_writer=lambda: None),
                    "WRITER_INTENT_DURABLE" if completed_count == len(_S2_PROGRAM) else "INTENT_DURABLE",
                )
                backend = Backend()
                transaction = AtomicReleaseSetTransaction(backend)
                result = ""
                for _ in range(4 * len(_S2_PROGRAM) + 8):
                    result = transaction.rollback_once(parent)
                    if result == "TERMINAL_OLD":
                        break
                self.assertEqual(result, "TERMINAL_OLD")
                selected = {row[0] for row in _S2_PROGRAM[:completed_count]}
                expected_reverse = tuple(item for item in _S2_REVERSE if item in selected)
                self.assertEqual(tuple(backend.compensated), expected_reverse)
                self.assertEqual(backend.full_old_count, 2)

    def test_writer_lost_return_runs_exact_forward_old_program_only(self) -> None:
        class Backend:
            def __init__(self) -> None:
                self.completed: list[str] = []

            def observe_forward_old(self, operation: str) -> str:
                return "DESIRED" if operation in self.completed else "OLD"

            def apply_forward_old(self, operation: str) -> None:
                self.completed.append(operation)

        with tempfile.TemporaryDirectory() as root:
            parent = self.journal_parent(root)
            _s2_initialize(parent)
            self.advance_to_writer_intent(parent)
            def lost_writer() -> None:
                raise RuntimeError("lost")
            self.assertEqual(
                _s2_recover_once(parent, observe=lambda _op: "DESIRED", apply=lambda _op: None, invoke_writer=lost_writer),
                "WRITER_LOST_RETURN_POST_BOUNDARY",
            )
            backend = Backend()
            transaction = AtomicReleaseSetTransaction(backend)
            result = ""
            for _ in range(4 * len(_S3_FORWARD_OLD) + 8):
                result = transaction.forward_old_once(parent)
                if result == "TERMINAL_OLD":
                    break
            self.assertEqual(result, "TERMINAL_OLD")
            self.assertEqual(tuple(backend.completed), _S3_FORWARD_OLD)
            forbidden = ("DB", "WAL", "SHM", "RESTORE_READINESS_BYTES")
            self.assertFalse(any(token in operation for operation in _S3_FORWARD_OLD for token in forbidden))


if __name__ == "__main__":
    unittest.main()
