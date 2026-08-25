from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import p07_full_mutation_set_v1 as mutation


class SyntheticCrash(BaseException):
    pass


def file_inventory(root_contract: dict[str, object]) -> list[dict[str, object]]:
    return mutation.scan_root(root_contract)


class Fixture:
    def __init__(self, directory: str) -> None:
        self.base = Path(directory)
        self.target = self.base / "target"
        self.target.mkdir(mode=0o700)
        self.uid = os.getuid()
        self.gid = os.getgid()
        self.before_replace = b"selector-before\n"
        self.after_replace = b"selector-after\n"
        self.after_add = b"memory-dropin\n"
        self.before_remove = b"obsolete-dropin\n"
        self.replace_path = self.target / "10-selector.conf"
        self.add_path = self.target / "90-memory.conf"
        self.remove_path = self.target / "80-obsolete.conf"
        for path, payload in (
            (self.replace_path, self.before_replace),
            (self.remove_path, self.before_remove),
        ):
            path.write_bytes(payload)
            path.chmod(0o644)
        self.root = mutation.build_root(
            root_id="core_service_dropins",
            path=self.target,
            allowed_logical_paths=(
                self.replace_path.name,
                self.add_path.name,
                self.remove_path.name,
            ),
            allowed_owners=((self.uid, self.gid),),
        )
        self.prestate = file_inventory(self.root)
        source_sha = "1" * 64
        replace_after = mutation.regular_state(
            self.after_replace, uid=self.uid, gid=self.gid, mode=0o644
        )
        add_after = mutation.regular_state(
            self.after_add, uid=self.uid, gid=self.gid, mode=0o644
        )
        remove_after = mutation.absent_state()
        before_map = {
            item["logical_path"]: item["state"] for item in self.prestate
        }
        self.operations = [
            mutation.build_operation(
                root=self.root,
                order=0,
                kind="replace",
                logical_path=self.replace_path.name,
                before=before_map[self.replace_path.name],
                after=replace_after,
                generator=mutation.build_generator(
                    generator_id="selector-render-v1",
                    source_sha256=source_sha,
                    input_digest="2" * 64,
                    output_state=replace_after,
                ),
            ),
            mutation.build_operation(
                root=self.root,
                order=1,
                kind="add",
                logical_path=self.add_path.name,
                before=mutation.absent_state(),
                after=add_after,
                generator=mutation.build_generator(
                    generator_id="memory-dropin-render-v1",
                    source_sha256=source_sha,
                    input_digest="3" * 64,
                    output_state=add_after,
                ),
            ),
            mutation.build_operation(
                root=self.root,
                order=2,
                kind="remove",
                logical_path=self.remove_path.name,
                before=before_map[self.remove_path.name],
                after=remove_after,
                generator=mutation.build_generator(
                    generator_id="obsolete-removal-v1",
                    source_sha256=source_sha,
                    input_digest="4" * 64,
                    output_state=remove_after,
                ),
            ),
        ]
        self.contract = mutation.build_mutation_set(
            transaction_id="synthetic-full-mutation-v1",
            roots=[self.root],
            prestate_inventory=self.prestate,
            operations=self.operations,
        )
        self.before_payloads = {
            mutation.path_key("core_service_dropins", self.replace_path.name): self.before_replace,
            mutation.path_key("core_service_dropins", self.remove_path.name): self.before_remove,
        }
        self.after_payloads = {
            mutation.path_key("core_service_dropins", self.replace_path.name): self.after_replace,
            mutation.path_key("core_service_dropins", self.add_path.name): self.after_add,
        }

    def stage(self, name: str = "stage") -> Path:
        path = self.base / name
        mutation.stage_mutation_set(
            contract=self.contract,
            staging_root=path,
            before_payloads=self.before_payloads,
            after_payloads=self.after_payloads,
        )
        return path


class FullMutationSetContractTests(unittest.TestCase):
    def test_contract_models_add_replace_remove_and_complete_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            contract = mutation.validate_mutation_set(fixture.contract)
            self.assertEqual(
                [item["kind"] for item in contract["operations"]],
                ["replace", "add", "remove"],
            )
            target = {
                item["logical_path"]: item["state"]
                for item in contract["target_inventory"]
            }
            self.assertEqual(
                target[fixture.replace_path.name]["sha256"],
                sha256(fixture.after_replace).hexdigest(),
            )
            self.assertEqual(
                target[fixture.add_path.name]["sha256"],
                sha256(fixture.after_add).hexdigest(),
            )
            self.assertNotIn(fixture.remove_path.name, target)

    def test_contract_rejects_duplicate_overlap_escape_owner_and_impossible_kinds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            duplicate = [fixture.operations[0], {**fixture.operations[1], "order": 1, "logical_path": fixture.operations[0]["logical_path"]}]
            with self.assertRaisesRegex(mutation.MutationSetRejected, "mutation_set_duplicate_path_rejected"):
                mutation.build_mutation_set(
                    transaction_id="duplicate-v1",
                    roots=[fixture.root],
                    prestate_inventory=fixture.prestate,
                    operations=duplicate,
                )
            recursive_root = mutation.build_root(
                root_id="recursive_root",
                path=fixture.target,
                allowed_logical_paths=("a.conf", "a.conf/child.conf"),
                allowed_owners=((fixture.uid, fixture.gid),),
                recursive=True,
            )
            state = mutation.regular_state(b"x", uid=fixture.uid, gid=fixture.gid, mode=0o644)
            operations = []
            for order, logical in enumerate(("a.conf", "a.conf/child.conf")):
                operations.append(
                    mutation.build_operation(
                        root=recursive_root,
                        order=order,
                        kind="add",
                        logical_path=logical,
                        before=mutation.absent_state(),
                        after=state,
                        generator=mutation.build_generator(
                            generator_id=f"generator-{order}",
                            source_sha256="1" * 64,
                            input_digest=f"{order + 2}" * 64,
                            output_state=state,
                        ),
                    )
                )
            with self.assertRaisesRegex(mutation.MutationSetRejected, "mutation_set_overlapping_path_rejected"):
                mutation.build_mutation_set(
                    transaction_id="overlap-v1",
                    roots=[recursive_root],
                    prestate_inventory=[],
                    operations=operations,
                )
            with self.assertRaisesRegex(mutation.MutationSetRejected, "mutation_set_logical_path_rejected"):
                mutation.build_operation(
                    root=fixture.root,
                    order=0,
                    kind="add",
                    logical_path="../escape.conf",
                    before=mutation.absent_state(),
                    after=state,
                    generator=mutation.build_generator(
                        generator_id="escape-generator",
                        source_sha256="1" * 64,
                        input_digest="2" * 64,
                        output_state=state,
                    ),
                )
            foreign = mutation.regular_state(b"x", uid=fixture.uid + 1, gid=fixture.gid, mode=0o644)
            with self.assertRaisesRegex(mutation.MutationSetRejected, "mutation_set_operation_owner_rejected"):
                mutation.build_operation(
                    root=fixture.root,
                    order=0,
                    kind="add",
                    logical_path=fixture.add_path.name,
                    before=mutation.absent_state(),
                    after=foreign,
                    generator=mutation.build_generator(
                        generator_id="foreign-owner",
                        source_sha256="1" * 64,
                        input_digest="2" * 64,
                        output_state=foreign,
                    ),
                )
            with self.assertRaisesRegex(mutation.MutationSetRejected, "mutation_set_replace_precondition_rejected"):
                mutation.build_operation(
                    root=fixture.root,
                    order=0,
                    kind="replace",
                    logical_path=fixture.add_path.name,
                    before=mutation.absent_state(),
                    after=state,
                    generator=mutation.build_generator(
                        generator_id="impossible-replace",
                        source_sha256="1" * 64,
                        input_digest="2" * 64,
                        output_state=state,
                    ),
                )

    def test_absolute_inventory_roundtrip_and_escape_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            absolute = mutation.inventory_to_absolute(
                root=fixture.root, inventory=fixture.prestate
            )
            self.assertEqual(
                mutation.inventory_from_absolute(root=fixture.root, inventory=absolute),
                fixture.prestate,
            )
            absolute[0] = {**absolute[0], "path": "/outside.conf"}
            with self.assertRaisesRegex(mutation.MutationSetRejected, "mutation_set_inventory_escape_rejected"):
                mutation.inventory_from_absolute(root=fixture.root, inventory=absolute)

    def test_inventory_symlink_type_metadata_stale_and_replay_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            link = fixture.target / "70-link.conf"
            link.symlink_to(fixture.replace_path)
            with self.assertRaisesRegex(mutation.MutationSetRejected, "mutation_set_symlink_rejected"):
                mutation.scan_root(fixture.root)
            link.unlink()
            fixture.replace_path.chmod(0o600)
            with self.assertRaisesRegex(mutation.MutationSetRejected, "mutation_set_prestate_drifted"):
                mutation.require_prestate(fixture.contract)
            fixture.replace_path.chmod(0o644)
            fixture.replace_path.write_bytes(fixture.after_replace)
            fixture.add_path.write_bytes(fixture.after_add)
            fixture.add_path.chmod(0o644)
            fixture.remove_path.unlink()
            with self.assertRaisesRegex(mutation.MutationSetRejected, "mutation_set_replayed"):
                mutation.require_prestate(fixture.contract)


class FullMutationSetStagingTests(unittest.TestCase):
    def test_staging_is_deterministic_byte_and_mode_identical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            first = fixture.stage("stage-a")
            second = fixture.stage("stage-b")
            first_files = {
                path.relative_to(first).as_posix(): (
                    path.read_bytes(),
                    stat.S_IMODE(path.stat().st_mode),
                )
                for path in first.rglob("*")
                if path.is_file()
            }
            second_files = {
                path.relative_to(second).as_posix(): (
                    path.read_bytes(),
                    stat.S_IMODE(path.stat().st_mode),
                )
                for path in second.rglob("*")
                if path.is_file()
            }
            self.assertEqual(first_files, second_files)
            self.assertFalse(any("__pycache__" in key for key in first_files))

    def test_staging_rejects_missing_extra_tampered_stale_and_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            missing = dict(fixture.after_payloads)
            missing.pop(next(iter(missing)))
            with self.assertRaisesRegex(mutation.MutationSetRejected, "mutation_set_staging_payload_set_rejected"):
                mutation.stage_mutation_set(
                    contract=fixture.contract,
                    staging_root=fixture.base / "missing",
                    before_payloads=fixture.before_payloads,
                    after_payloads=missing,
                )
            stage = fixture.stage("stage")
            manifest = json.loads((stage / "manifest.json").read_text("ascii"))
            blob = stage / manifest["files"][0]["staged_path"]
            blob.write_bytes(b"tampered")
            with self.assertRaisesRegex(mutation.MutationSetRejected, "mutation_set_staging_readback_rejected"):
                mutation.verify_staging(contract=fixture.contract, staging_root=stage)
            with self.assertRaisesRegex(mutation.MutationSetRejected, "mutation_set_staging_root_rejected"):
                mutation.stage_mutation_set(
                    contract=fixture.contract,
                    staging_root=stage,
                    before_payloads=fixture.before_payloads,
                    after_payloads=fixture.after_payloads,
                )
            with self.assertRaisesRegex(mutation.MutationSetRejected, "mutation_set_staging_overlaps_target"):
                mutation.stage_mutation_set(
                    contract=fixture.contract,
                    staging_root=fixture.target / "stage",
                    before_payloads=fixture.before_payloads,
                    after_payloads=fixture.after_payloads,
                )


class FullMutationSetTransactionTests(unittest.TestCase):
    def test_recursive_release_tree_scans_files_and_prunes_created_parents_on_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "release"
            target.mkdir(mode=0o550)
            uid, gid = os.getuid(), os.getgid()
            payloads = {
                "pkg/__init__.py": b"# package\n",
                "pkg/runtime/main.py": b"VALUE = 1\n",
            }
            root = mutation.build_root(
                root_id="recursive_release",
                path=target,
                allowed_logical_paths=tuple(payloads),
                allowed_owners=((uid, gid),),
                inventory_pattern="*",
                recursive=True,
            )
            operations = []
            after_payloads = {}
            for order, (logical_path, payload) in enumerate(sorted(payloads.items())):
                after = mutation.regular_state(
                    payload, uid=uid, gid=gid, mode=0o440
                )
                operations.append(
                    mutation.build_operation(
                        root=root,
                        order=order,
                        kind="add",
                        logical_path=logical_path,
                        before=mutation.absent_state(),
                        after=after,
                        generator=mutation.build_generator(
                            generator_id=f"recursive-release-{order}",
                            source_sha256="1" * 64,
                            input_digest=f"{order + 2}" * 64,
                            output_state=after,
                        ),
                    )
                )
                after_payloads[mutation.path_key("recursive_release", logical_path)] = payload
            contract = mutation.build_mutation_set(
                transaction_id="recursive_release_transaction",
                roots=[root],
                prestate_inventory=[],
                operations=operations,
            )
            staging = base / "staging"
            mutation.stage_mutation_set(
                contract=contract,
                staging_root=staging,
                before_payloads={},
                after_payloads=after_payloads,
            )
            journal = base / "journal.json"
            mutation.execute_mutation_set(
                contract=contract,
                staging_root=staging,
                journal_path=journal,
            )
            self.assertEqual(
                mutation.scan_contract_roots(contract), contract["target_inventory"]
            )
            mutation.rollback_mutation_set(
                contract=contract,
                staging_root=staging,
                journal_path=journal,
            )
            self.assertEqual(mutation.scan_contract_roots(contract), [])
            self.assertFalse((target / "pkg").exists())

    def test_execute_verifies_all_paths_and_inventory_before_callback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            stage = fixture.stage()
            journal = fixture.base / "journal.json"
            called: list[bool] = []
            result = mutation.execute_mutation_set(
                contract=fixture.contract,
                staging_root=stage,
                journal_path=journal,
                after_verified=lambda: called.append(True),
            )
            self.assertEqual(result["stage"], "complete")
            self.assertEqual(called, [True])
            self.assertEqual(
                mutation.scan_contract_roots(fixture.contract),
                fixture.contract["target_inventory"],
            )
            projection = mutation.journal_projection(journal, fixture.contract)
            self.assertEqual(projection["stage"], "complete")
            self.assertFalse(projection["content_retained"])
            self.assertFalse(projection["credential_value_read"])

    def test_crash_at_every_forward_checkpoint_recovers_by_one_exact_rollback(self) -> None:
        checkpoints = [
            ("prepared", None),
            ("before_forward_operation", 0),
            ("after_forward_operation", 0),
            ("before_forward_operation", 1),
            ("after_forward_operation", 1),
            ("before_forward_operation", 2),
            ("after_forward_operation", 2),
            ("target_verified", None),
        ]
        for expected_stage, expected_order in checkpoints:
            with self.subTest(stage=expected_stage, order=expected_order):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = Fixture(directory)
                    stage = fixture.stage()
                    journal = fixture.base / "journal.json"

                    def crash(stage_name: str, order: int | None) -> None:
                        if (stage_name, order) == (expected_stage, expected_order):
                            raise SyntheticCrash()

                    with self.assertRaises(SyntheticCrash):
                        mutation.execute_mutation_set(
                            contract=fixture.contract,
                            staging_root=stage,
                            journal_path=journal,
                            checkpoint=crash,
                        )
                    self.assertEqual(
                        mutation.recover_mutation_set(
                            contract=fixture.contract,
                            staging_root=stage,
                            journal_path=journal,
                        ),
                        "rolled_back",
                    )
                    self.assertEqual(
                        mutation.scan_contract_roots(fixture.contract),
                        fixture.contract["prestate_inventory"],
                    )

    def test_crash_at_every_rollback_checkpoint_resumes_same_rollback(self) -> None:
        checkpoints = [
            ("rollback_started", None),
            ("before_rollback_operation", 2),
            ("after_rollback_operation", 2),
            ("before_rollback_operation", 1),
            ("after_rollback_operation", 1),
            ("before_rollback_operation", 0),
            ("after_rollback_operation", 0),
            ("rolled_back", None),
        ]
        for expected_stage, expected_order in checkpoints:
            with self.subTest(stage=expected_stage, order=expected_order):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = Fixture(directory)
                    stage = fixture.stage()
                    journal = fixture.base / "journal.json"

                    def forward_crash(stage_name: str, order: int | None) -> None:
                        if (stage_name, order) == ("target_verified", None):
                            raise SyntheticCrash()

                    with self.assertRaises(SyntheticCrash):
                        mutation.execute_mutation_set(
                            contract=fixture.contract,
                            staging_root=stage,
                            journal_path=journal,
                            checkpoint=forward_crash,
                        )

                    def rollback_crash(stage_name: str, order: int | None) -> None:
                        if (stage_name, order) == (expected_stage, expected_order):
                            raise SyntheticCrash()

                    with self.assertRaises(SyntheticCrash):
                        mutation.recover_mutation_set(
                            contract=fixture.contract,
                            staging_root=stage,
                            journal_path=journal,
                            checkpoint=rollback_crash,
                        )
                    self.assertEqual(
                        mutation.recover_mutation_set(
                            contract=fixture.contract,
                            staging_root=stage,
                            journal_path=journal,
                        ),
                        "rolled_back",
                    )

    def test_unexpected_extra_and_full_inventory_mismatch_fail_closed_before_callback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            stage = fixture.stage()
            journal = fixture.base / "journal.json"
            called: list[bool] = []

            def add_extra(stage_name: str, order: int | None) -> None:
                if (stage_name, order) == ("after_forward_operation", 2):
                    extra = fixture.target / "99-unmodelled.conf"
                    extra.write_bytes(b"unexpected\n")
                    extra.chmod(0o644)

            with self.assertRaisesRegex(mutation.MutationSetRejected, "mutation_set_rollback_failed"):
                mutation.execute_mutation_set(
                    contract=fixture.contract,
                    staging_root=stage,
                    journal_path=journal,
                    after_verified=lambda: called.append(True),
                    checkpoint=add_extra,
                )
            self.assertEqual(called, [])
            self.assertTrue(mutation.journal_projection(journal, fixture.contract)["rollback_failed"])

    def test_readback_mismatch_fails_closed_and_callback_is_not_called(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            stage = fixture.stage()
            journal = fixture.base / "journal.json"
            called: list[bool] = []
            real_atomic = mutation._atomic_write
            corrupted = False

            def corrupt_first(path: Path, payload: bytes, *, mode: int, uid: int, gid: int) -> None:
                nonlocal corrupted
                real_atomic(path, payload, mode=mode, uid=uid, gid=gid)
                if not corrupted and path == fixture.replace_path:
                    corrupted = True
                    path.write_bytes(b"wrong\n")
                    path.chmod(mode)

            with (
                patch.object(mutation, "_atomic_write", side_effect=corrupt_first),
                self.assertRaisesRegex(mutation.MutationSetRejected, "mutation_set_rollback_failed"),
            ):
                mutation.execute_mutation_set(
                    contract=fixture.contract,
                    staging_root=stage,
                    journal_path=journal,
                    after_verified=lambda: called.append(True),
                )
            self.assertEqual(called, [])
            self.assertTrue(
                mutation.journal_projection(journal, fixture.contract)[
                    "rollback_failed"
                ]
            )

    def test_verified_callback_failure_performs_exact_reverse_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            stage = fixture.stage()
            journal = fixture.base / "journal.json"

            def fail_callback() -> None:
                raise RuntimeError("synthetic")

            with self.assertRaisesRegex(
                mutation.MutationSetRejected,
                "mutation_set_apply_failed_rolled_back",
            ):
                mutation.execute_mutation_set(
                    contract=fixture.contract,
                    staging_root=stage,
                    journal_path=journal,
                    after_verified=fail_callback,
                )
            self.assertEqual(
                mutation.scan_contract_roots(fixture.contract),
                fixture.contract["prestate_inventory"],
            )
            self.assertEqual(
                mutation.journal_projection(journal, fixture.contract)["stage"],
                "rolled_back",
            )

    def test_rollback_failure_is_persisted_and_replay_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            stage = fixture.stage()
            journal = fixture.base / "journal.json"

            def fail_callback() -> None:
                raise RuntimeError("synthetic")

            with (
                patch.object(
                    mutation,
                    "_restore_operation",
                    side_effect=mutation.MutationSetRejected("synthetic_rollback_failure"),
                ),
                self.assertRaisesRegex(mutation.MutationSetRejected, "mutation_set_rollback_failed"),
            ):
                mutation.execute_mutation_set(
                    contract=fixture.contract,
                    staging_root=stage,
                    journal_path=journal,
                    after_verified=fail_callback,
                )
            projection = mutation.journal_projection(journal, fixture.contract)
            self.assertTrue(projection["rollback_failed"])
            with self.assertRaisesRegex(mutation.MutationSetRejected, "mutation_set_rollback_previous_failed"):
                mutation.recover_mutation_set(
                    contract=fixture.contract,
                    staging_root=stage,
                    journal_path=journal,
                )

    def test_path_specific_evidence_is_content_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            observed = list(fixture.contract["target_inventory"])
            observed[0] = {
                **observed[0],
                "state": {
                    **observed[0]["state"],
                    "sha256": "f" * 64,
                },
            }
            evidence = mutation.comparison_evidence(
                expected=fixture.contract["target_inventory"],
                observed=observed,
                contract=fixture.contract,
                phase="synthetic_postflight",
            )
            self.assertEqual(evidence["status"], "mismatch")
            self.assertEqual(evidence["mismatches"][0]["mismatch_fields"], ["sha256"])
            self.assertRegex(evidence["mismatches"][0]["path_digest"], r"^[0-9a-f]{64}$")
            serialized = mutation.canonical(evidence)
            for forbidden in (
                fixture.before_replace,
                fixture.after_replace,
                fixture.after_add,
                fixture.before_remove,
            ):
                self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main()
