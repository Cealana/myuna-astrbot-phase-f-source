from __future__ import annotations

from contextlib import ExitStack
import inspect
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import activate_p07_owner_private_memory_dual_state_recovery_v2 as dual_state
import activate_p07_owner_private_memory_v1 as memory
import p07_full_mutation_set_v1 as mutation
import p07_owner_private_memory_transactional_controller as controller


CATEGORIES = (
    "archive_roots",
    "core_release",
    "diary_roots",
    "dropins",
    "index_roots",
    "plugin_release",
    "runtime_release",
    "selectors",
)


def _lineages() -> dict[str, object]:
    semantic = {
        "full_mutation_bundle_id": controller.FULL_MUTATION_BUNDLE_ID,
        "full_mutation_handoff_sha256": controller.FULL_MUTATION_HANDOFF_SHA256,
        "full_mutation_manifest_sha256": controller.FULL_MUTATION_MANIFEST_SHA256,
        "predecessor": {
            "attempts": 2,
            "maximum_attempts": 2,
            "schema": dual_state.IMMUTABLE_PREDECESSOR_SCHEMA,
            "strategy_id": controller.PREDECESSOR_STRATEGY_ID,
        },
        "root_cause_handoff_sha256": controller.ROOT_CAUSE_HANDOFF_SHA256,
        "schema": controller.LINEAGE_SCHEMA,
        "source_boundary": {
            "core_commit": controller.LINEAGE_CORE_SOURCE_COMMIT,
            "core_tree": controller.LINEAGE_CORE_SOURCE_TREE,
            "deploy_parent_commit": controller.DEPLOY_PARENT_COMMIT,
            "deploy_parent_tree": controller.DEPLOY_PARENT_TREE,
        },
        "v2": {
            "attempts": 1,
            "backup_tree_digest": controller.V2_BACKUP_TREE_DIGEST,
            "journal_sha256": controller.V2_JOURNAL_SHA256,
            "ledger_sha256": controller.V2_LEDGER_SHA256,
            "maximum_attempts": 1,
            "plan_sha256": controller.V2_PLAN_SHA256,
            "prestate_sha256": controller.V2_PRESTATE_SHA256,
            "receipt_sha256": controller.V2_RECEIPT_SHA256,
            "schema": controller.LINEAGE_SCHEMA,
            "source_commit": controller.V2_SOURCE_COMMIT,
            "state_tree_digest": controller.V2_STATE_TREE_DIGEST,
            "strategy_id": controller.V2_STRATEGY_ID,
            "terminal_handoff_sha256": controller.TERMINAL_V2_HANDOFF_SHA256,
        },
    }
    return {
        **semantic,
        "evidence_digest": controller.digest(
            "p07_transactional_lineage_evidence", semantic
        ),
    }


def _boundaries() -> dict[str, object]:
    return {
        name: {
            "identity_digest": (index + 1).__format__("x") * 64,
            "mutation_allowed": False,
            "state": "immutable",
        }
        for index, name in enumerate(sorted(controller._BOUNDARY_PROGRAMS))
    }


def _policy() -> dict[str, object]:
    return {
        "calendar_zone_selector_digest": "1" * 64,
        "diary_egress_policy_digest": "2" * 64,
        "historical_recall_egress_digest": "3" * 64,
        "p15_prompt_owner_digest": "4" * 64,
        "profile_confirmation_gate_digest": "5" * 64,
        "selected_calendar_zone": "Asia/Shanghai",
    }


def _public_prestate() -> dict[str, object]:
    return {
        name: {"digest": f"{index + 1:064x}"}
        for index, name in enumerate(sorted(controller._PUBLIC_PRESTATE_FIELDS))
    }


def _namespace() -> dict[str, object]:
    return {
        "backup_root_exists": False,
        "ledger_exists": False,
        "schema": controller.NAMESPACE_SCHEMA,
        "source_id": controller.SOURCE_ID,
        "state_root_exists": False,
    }


def _root_transitions(root: Path) -> list[dict[str, object]]:
    path = (root / "protected-archive").as_posix()
    return [
        {
            "after_exists": True,
            "after_gid": os.getgid(),
            "after_mode": 0o700,
            "after_type": "directory",
            "after_uid": os.getuid(),
            "before_exists": False,
            "before_gid": 0,
            "before_mode": 0,
            "before_type": "absent",
            "before_uid": 0,
            "kind": "add",
            "path": path,
            "path_digest": controller.digest("p07_protected_root_path", path),
            "root_role": "archive_root",
        }
    ]


def _synthetic_contract(root: Path) -> tuple[dict[str, object], dict[str, bytes], dict[str, bytes]]:
    paths = [f"{index:02d}-{category}.conf" for index, category in enumerate(CATEGORIES)]
    root_contract = mutation.build_root(
        root_id="transaction_root",
        path=root,
        allowed_logical_paths=paths,
        allowed_owners=((os.getuid(), os.getgid()),),
        inventory_pattern="*.conf",
        recursive=False,
    )
    before_payloads: dict[str, bytes] = {}
    after_payloads: dict[str, bytes] = {}
    prestate: list[dict[str, object]] = []
    operations: list[dict[str, object]] = []
    for order, path in enumerate(paths):
        before_payload = f"before-{path}\n".encode("ascii")
        after_payload = f"after-{path}\n".encode("ascii")
        if order == 0:
            kind = "add"
            before = mutation.absent_state()
        else:
            kind = "remove" if order == 1 else "replace"
            (root / path).write_bytes(before_payload)
            os.chmod(root / path, 0o640)
            before = mutation.regular_state(
                before_payload,
                uid=os.getuid(),
                gid=os.getgid(),
                mode=0o640,
            )
            prestate.append(
                mutation.inventory_entry(
                    root_id="transaction_root",
                    logical_path=path,
                    state=before,
                )
            )
        after = (
            mutation.absent_state()
            if kind == "remove"
            else mutation.regular_state(
                after_payload,
                uid=os.getuid(),
                gid=os.getgid(),
                mode=0o640,
            )
        )
        generator = mutation.build_generator(
            generator_id=f"generator_{order}",
            source_sha256=f"{order + 1:064x}",
            input_digest=f"{order + 11:064x}",
            output_state=after,
        )
        operations.append(
            mutation.build_operation(
                root=root_contract,
                order=order,
                kind=kind,
                logical_path=path,
                before=before,
                after=after,
                generator=generator,
            )
        )
        key = mutation.path_key("transaction_root", path)
        if before["exists"]:
            before_payloads[key] = before_payload
        if after["exists"]:
            after_payloads[key] = after_payload
    contract = mutation.build_mutation_set(
        transaction_id="synthetic_transaction",
        roots=[root_contract],
        prestate_inventory=prestate,
        operations=operations,
    )
    return contract, before_payloads, after_payloads


def _coverage(contract: dict[str, object], root: Path) -> dict[str, object]:
    operation_keys = [
        "file:"
        + mutation.path_key(str(item["root_id"]), str(item["logical_path"]))
        for item in contract["operations"]
    ]
    archive_path = (root / "protected-archive").as_posix()
    return {
        "archive_roots": [
            "root:archive_root:"
            + controller.digest("p07_protected_root_path", archive_path)
        ],
        "core_release": [operation_keys[0]],
        "diary_roots": [operation_keys[1]],
        "dropins": [operation_keys[2], operation_keys[3]],
        "index_roots": [operation_keys[4]],
        "plugin_release": [operation_keys[5]],
        "runtime_release": [operation_keys[6]],
        "selectors": [operation_keys[7]],
    }


def _plan(root: Path, contract: dict[str, object]) -> dict[str, object]:
    return controller.build_plan(
        core_commit=controller.CORE_SOURCE_COMMIT,
        deploy_commit="c" * 40,
        deploy_tree="d" * 40,
        artifact_identities={
            "controller_bundle_id": "f" * 64,
            "full_mutation_bundle_id": controller.FULL_MUTATION_BUNDLE_ID,
            "full_mutation_manifest_sha256": controller.FULL_MUTATION_MANIFEST_SHA256,
        },
        lineages=_lineages(),
        public_prestate=_public_prestate(),
        boundaries=_boundaries(),
        policy=_policy(),
        mutation_set=contract,
        mutation_coverage=_coverage(contract, root),
        root_transitions=_root_transitions(root),
        namespace=_namespace(),
        state_root=root / "state",
        backup_root=root / "backup",
    )


class SyntheticRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Hooks:
    def __init__(self, *, fail_at: str | None = None, root: Path, contract: dict[str, object]) -> None:
        self.fail_at = fail_at
        self.root = root
        self.contract = contract
        self.calls: list[str] = []
        self.attempts = 0

    def _call(self, name: str) -> None:
        self.calls.append(name)
        if self.fail_at == name:
            self.fail_at = None
            raise SyntheticRejected(f"synthetic_{name}_failed")

    def consume_attempt(self, *, maximum_attempts: int) -> int:
        self._call("consume_attempt")
        if self.attempts >= maximum_attempts:
            raise SyntheticRejected("synthetic_attempt_exhausted")
        self.attempts += 1
        return self.attempts

    def stop_target_services(self) -> None:
        self._call("stop_target_services")

    def verify_target_services_stopped(self) -> None:
        self._call("verify_target_services_stopped")

    def verify_target_semantics(self) -> None:
        self._call("verify_target_semantics")
        self.assert_inventory("target_inventory")

    def daemon_reload(self) -> None:
        self._call("daemon_reload")

    def start_core(self) -> None:
        self._call("start_core")

    def verify_core(self) -> None:
        self._call("verify_core")

    def start_telegram(self) -> None:
        self._call("start_telegram")

    def verify_target(self) -> None:
        self._call("verify_target")
        self.assert_inventory("target_inventory")

    def verify_prestate_files(self) -> None:
        self._call("verify_prestate_files")
        self.assert_inventory("prestate_inventory")

    def restore_core(self) -> None:
        self._call("restore_core")

    def verify_core_prestate(self) -> None:
        self._call("verify_core_prestate")

    def restore_telegram(self) -> None:
        self._call("restore_telegram")

    def verify_prestate(self) -> None:
        self._call("verify_prestate")
        self.assert_inventory("prestate_inventory")

    def assert_inventory(self, field: str) -> None:
        observed = mutation.scan_contract_roots(self.contract)
        if observed != self.contract[field]:
            raise SyntheticRejected(f"synthetic_{field}_drifted")


def _backend(
    root: Path,
    contract: dict[str, object],
    before: dict[str, bytes],
    after: dict[str, bytes],
    plan: dict[str, object],
    hooks: Hooks,
) -> controller.FullMutationTransactionBackend:
    storage = controller.TransactionStorage(
        backup_path=Path(str(plan["storage"]["backup_path"])),
        staging_path=Path(str(plan["storage"]["staging_path"])),
        filesystem_journal_path=Path(str(plan["storage"]["filesystem_journal_path"])),
        controller_journal_path=Path(str(plan["storage"]["journal_path"])),
    )
    storage.controller_journal_path.parent.mkdir(parents=True, mode=0o700)
    return controller.FullMutationTransactionBackend(
        plan=plan,
        mutation_set=contract,
        before_payloads=before,
        after_payloads=after,
        storage=storage,
        hooks=hooks,
        owner_uid=os.getuid(),
        owner_gid=os.getgid(),
    )


class TransactionalControllerTests(unittest.TestCase):
    def test_identity_is_independent_and_has_one_future_attempt(self) -> None:
        self.assertEqual(controller.MAXIMUM_ACTIVATIONS, 1)
        self.assertNotEqual(
            controller.CORE_SOURCE_COMMIT,
            controller.LINEAGE_CORE_SOURCE_COMMIT,
        )
        self.assertEqual(
            controller.LINEAGE_CORE_SOURCE_COMMIT,
            "279e545e612077a597257750ce858789d6c6b794",
        )
        self.assertNotIn("v2", controller.SOURCE_ID)
        self.assertNotEqual(controller.SOURCE_ID, controller.PREDECESSOR_STRATEGY_ID)
        self.assertNotEqual(controller.SOURCE_ID, controller.V2_STRATEGY_ID)
        source = inspect.getsource(controller)
        for forbidden in (
            "reset --hard",
            "git reset",
            "shutil.rmtree",
            "requests.",
            "httpx.",
            "sqlite3",
        ):
            self.assertNotIn(forbidden, source)

    def test_plan_is_deterministic_complete_and_rejects_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            contract, _, _ = _synthetic_contract(target)
            first = _plan(root, contract)
            second = _plan(root, contract)
            self.assertEqual(first, second)
            self.assertEqual(first["attempts"], {"consumed": 0, "maximum": 1, "next": 1})
            self.assertEqual(set(first["mutation_coverage"]), set(CATEGORIES))
            self.assertTrue(all(value is False for value in first["capabilities"].values()))
            controller.validate_plan(
                first,
                mutation_set=contract,
                lineages=_lineages(),
                namespace=_namespace(),
            )
            for mutation_case in ("source", "artifact", "lineage", "prestate", "coverage"):
                changed = json.loads(json.dumps(first))
                if mutation_case == "source":
                    changed["source"]["deploy_commit"] = "0" * 40
                elif mutation_case == "artifact":
                    changed["artifacts"]["controller_bundle_id"] = "0" * 64
                elif mutation_case == "lineage":
                    changed["lineage_evidence_digest"] = "0" * 64
                elif mutation_case == "prestate":
                    changed["public_prestate"]["epoch"]["digest"] = "0" * 64
                else:
                    changed["mutation_coverage"]["selectors"] = changed["mutation_coverage"]["dropins"]
                with self.assertRaises(controller.TransactionalControllerRejected):
                    controller.validate_plan(
                        changed,
                        mutation_set=contract,
                        lineages=_lineages(),
                        namespace=_namespace(),
                    )

    def test_preexisting_or_partial_future_namespace_rejected(self) -> None:
        for field in ("backup_root_exists", "ledger_exists", "state_root_exists"):
            value = _namespace()
            value[field] = True
            with self.assertRaisesRegex(
                controller.TransactionalControllerRejected,
                "future_namespace_preexisting",
            ):
                controller.verify_future_namespace_absent(value)

    def test_lineage_digest_and_both_exhausted_identities_are_closed(self) -> None:
        lineages = _lineages()
        self.assertEqual(controller.validate_immutable_lineages(lineages), lineages)
        for field in ("evidence_digest", "full_mutation_bundle_id"):
            changed = json.loads(json.dumps(lineages))
            changed[field] = "0" * 64
            with self.assertRaises(controller.TransactionalControllerRejected):
                controller.validate_immutable_lineages(changed)
        changed = json.loads(json.dumps(lineages))
        changed["predecessor"]["attempts"] = 0
        with self.assertRaisesRegex(
            controller.TransactionalControllerRejected,
            "transaction_predecessor_lineage_rejected",
        ):
            controller.validate_immutable_lineages(changed)
        changed = json.loads(json.dumps(lineages))
        changed["v2"]["maximum_attempts"] = 2
        with self.assertRaisesRegex(
            controller.TransactionalControllerRejected,
            "transaction_v2_lineage_rejected",
        ):
            controller.validate_immutable_lineages(changed)

    def test_root_add_replace_remove_reverse_and_third_state_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            added = root / "added"
            replaced = root / "replaced"
            removed = root / "removed"
            replaced.mkdir(mode=0o750)
            removed.mkdir(mode=0o700)

            def item(
                *,
                path: Path,
                role: str,
                kind: str,
                before_exists: bool,
                before_mode: int,
                after_exists: bool,
                after_mode: int,
            ) -> dict[str, object]:
                selected = path.as_posix()
                return {
                    "after_exists": after_exists,
                    "after_gid": os.getgid() if after_exists else 0,
                    "after_mode": after_mode,
                    "after_type": "directory" if after_exists else "absent",
                    "after_uid": os.getuid() if after_exists else 0,
                    "before_exists": before_exists,
                    "before_gid": os.getgid() if before_exists else 0,
                    "before_mode": before_mode,
                    "before_type": "directory" if before_exists else "absent",
                    "before_uid": os.getuid() if before_exists else 0,
                    "kind": kind,
                    "path": selected,
                    "path_digest": controller.digest(
                        "p07_protected_root_path", selected
                    ),
                    "root_role": role,
                }

            transitions = [
                item(
                    path=added,
                    role="archive_root",
                    kind="add",
                    before_exists=False,
                    before_mode=0,
                    after_exists=True,
                    after_mode=0o700,
                ),
                item(
                    path=replaced,
                    role="diary_root",
                    kind="replace",
                    before_exists=True,
                    before_mode=0o750,
                    after_exists=True,
                    after_mode=0o700,
                ),
                item(
                    path=removed,
                    role="index_root",
                    kind="remove",
                    before_exists=True,
                    before_mode=0o700,
                    after_exists=False,
                    after_mode=0,
                ),
            ]
            controller.apply_root_transitions(transitions)
            controller.verify_root_transitions(transitions, side="after")
            controller.rollback_root_transitions(transitions)
            controller.verify_root_transitions(transitions, side="before")
            added.mkdir(mode=0o700)
            (added / "unexpected").write_bytes(b"third state")
            with self.assertRaisesRegex(
                controller.TransactionalControllerRejected,
                "transaction_root_before_drifted",
            ):
                controller.apply_root_transitions(transitions)

    def test_backup_non_overwriting_acl_inventory_and_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            contract, before, _ = _synthetic_contract(target)
            plan = _plan(root, contract)
            backup = Path(str(plan["storage"]["backup_path"]))
            controller.create_plan_bound_backup(
                plan=plan,
                mutation_set=contract,
                backup_path=backup,
                before_payloads=before,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )
            with self.assertRaisesRegex(
                controller.TransactionalControllerRejected,
                "transaction_backup_path_rejected",
            ):
                controller.create_plan_bound_backup(
                    plan=plan,
                    mutation_set=contract,
                    backup_path=backup,
                    before_payloads=before,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
            first_blob = next((backup / "before").iterdir())
            first_blob.write_bytes(b"tampered")
            with self.assertRaisesRegex(
                controller.TransactionalControllerRejected,
                "transaction_backup_readback_rejected",
            ):
                controller.verify_plan_bound_backup(
                    plan=plan,
                    mutation_set=contract,
                    backup_path=backup,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )

    def test_exact_transaction_order_and_target_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            contract, before, after = _synthetic_contract(target)
            plan = _plan(root, contract)
            hooks = Hooks(root=target, contract=contract)
            backend = _backend(root, contract, before, after, plan, hooks)
            journal = controller.execute_transaction(backend=backend, plan=plan)
            self.assertEqual(journal["stage"], "target_accepted")
            self.assertEqual(journal["attempts"], 1)
            self.assertEqual(journal["rollback_invocations"], 0)
            self.assertEqual(
                hooks.calls,
                [
                    "consume_attempt",
                    "stop_target_services",
                    "verify_target_services_stopped",
                    "verify_target_semantics",
                    "daemon_reload",
                    "start_core",
                    "verify_core",
                    "start_telegram",
                    "verify_target",
                ],
            )
            self.assertEqual(mutation.scan_contract_roots(contract), contract["target_inventory"])

    def test_each_service_failure_rolls_back_once_and_preserves_typed_cause(self) -> None:
        failure_stages = (
            "verify_target_semantics",
            "daemon_reload",
            "start_core",
            "verify_core",
            "start_telegram",
            "verify_target",
        )
        for fail_at in failure_stages:
            with self.subTest(fail_at=fail_at), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root / "target"
                target.mkdir()
                contract, before, after = _synthetic_contract(target)
                plan = _plan(root, contract)
                hooks = Hooks(fail_at=fail_at, root=target, contract=contract)
                backend = _backend(root, contract, before, after, plan, hooks)
                with self.assertRaisesRegex(
                    controller.TransactionalControllerRejected,
                    "transaction_activation_failed_rollback_verified",
                ) as caught:
                    controller.execute_transaction(backend=backend, plan=plan)
                self.assertEqual(caught.exception.activation_failure_code, f"synthetic_{fail_at}_failed")
                journal = controller.load_journal(
                    backend.storage.controller_journal_path, plan
                )
                self.assertEqual(journal["stage"], "rolled_back")
                self.assertEqual(journal["rollback_invocations"], 1)
                self.assertEqual(hooks.attempts, 1)
                self.assertEqual(mutation.scan_contract_roots(contract), contract["prestate_inventory"])

    def test_rollback_failure_is_terminal_and_not_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            contract, before, after = _synthetic_contract(target)
            plan = _plan(root, contract)
            hooks = Hooks(fail_at="start_core", root=target, contract=contract)

            original_restore = hooks.restore_core

            def fail_restore() -> None:
                original_restore()
                raise SyntheticRejected("synthetic_restore_core_failed")

            hooks.restore_core = fail_restore  # type: ignore[method-assign]
            backend = _backend(root, contract, before, after, plan, hooks)
            with self.assertRaisesRegex(
                controller.TransactionalControllerRejected,
                "transaction_rollback_failed",
            ) as caught:
                controller.execute_transaction(backend=backend, plan=plan)
            self.assertEqual(caught.exception.rollback_failure_code, "synthetic_restore_core_failed")
            journal = controller.load_journal(backend.storage.controller_journal_path, plan)
            self.assertEqual(journal["stage"], "rollback_failed")
            with self.assertRaisesRegex(
                controller.TransactionalControllerRejected,
                "transaction_journal_transition_rejected",
            ):
                controller.advance_journal(
                    journal,
                    plan,
                    stage="rollback_started",
                    category="rollback_started",
                )

    def test_recovery_classes_cover_pre_in_post_and_rollback_states(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            contract, _, _ = _synthetic_contract(target)
            plan = _plan(root, contract)
            journal = controller.initial_journal(plan)
            expected = {
                "pre_attempt": "pre_attempt",
                "backup_verified": "pre_attempt",
                "staging_verified": "pre_attempt",
                "attempt_consumed": "in_attempt",
                "services_stopped": "in_attempt",
                "files_applying": "in_attempt",
                "target_accepted": "post_attempt",
                "rollback_started": "rollback",
                "files_restored": "rollback",
                "services_restored": "rollback",
                "rolled_back": "rolled_back",
                "rollback_failed": "rollback_failed",
            }
            for stage, recovery in expected.items():
                value = dict(journal)
                value["stage"] = stage
                if stage not in {"pre_attempt", "backup_verified", "staging_verified"}:
                    value["attempts"] = 1
                if stage in {"rollback_started", "files_restored", "services_restored", "rolled_back", "rollback_failed"}:
                    value["rollback_invocations"] = 1
                self.assertEqual(controller.recovery_class(value, plan), recovery)

    def test_generic_completed_target_can_exactly_reverse_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            contract, before, after = _synthetic_contract(target)
            staging = root / "staging"
            journal = root / "files.json"
            mutation.stage_mutation_set(
                contract=contract,
                staging_root=staging,
                before_payloads=before,
                after_payloads=after,
            )
            mutation.execute_mutation_set(
                contract=contract,
                staging_root=staging,
                journal_path=journal,
            )
            mutation.rollback_mutation_set(
                contract=contract,
                staging_root=staging,
                journal_path=journal,
            )
            self.assertEqual(mutation.scan_contract_roots(contract), contract["prestate_inventory"])
            with self.assertRaisesRegex(
                mutation.MutationSetRejected,
                "mutation_set_rollback_state_rejected",
            ):
                mutation.rollback_mutation_set(
                    contract=contract,
                    staging_root=staging,
                    journal_path=journal,
                )

    def test_v2_evidence_verifier_rejects_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            backup = root / "backup"
            state.mkdir(mode=0o700)
            backup.mkdir(mode=0o700)
            plan = "8" * 64
            terminal = root / "terminal.md"
            terminal.write_bytes(b"terminal\n")
            ledger = memory.canonical(
                {
                    "attempts": 1,
                    "last_plan_sha256": plan,
                    "schema": memory.DUAL_STATE_RECOVERY_V2_STRATEGY.attempt_schema,
                }
            )
            (state / "ATTEMPT_LEDGER.json").write_bytes(ledger)
            (state / "JOURNAL-one.json").write_bytes(b"receipt\n")
            (state / "RECEIPT-one.json").write_bytes(b"receipt\n")
            (backup / plan).mkdir(mode=0o700)
            state_digest = dual_state._protected_tree_digest(state, code="synthetic")
            backup_digest = dual_state._protected_tree_digest(backup, code="synthetic")
            patches = (
                patch.object(controller, "V2_STATE_ROOT", state),
                patch.object(controller, "V2_BACKUP_ROOT", backup),
                patch.object(controller, "V2_PLAN_SHA256", plan),
                patch.object(controller, "V2_LEDGER_SHA256", controller.digest_file(state / "ATTEMPT_LEDGER.json")),
                patch.object(controller, "V2_JOURNAL_SHA256", controller.digest_file(state / "JOURNAL-one.json")),
                patch.object(controller, "V2_RECEIPT_SHA256", controller.digest_file(state / "RECEIPT-one.json")),
                patch.object(controller, "V2_STATE_TREE_DIGEST", state_digest),
                patch.object(controller, "V2_BACKUP_TREE_DIGEST", backup_digest),
                patch.object(controller, "TERMINAL_V2_HANDOFF_SHA256", controller.digest_file(terminal)),
            )
            with ExitStack() as stack:
                for selected in patches:
                    stack.enter_context(selected)
                projection = controller.verify_v2_immutable_evidence(
                    terminal_handoff=terminal,
                    state_root=state,
                    backup_root=backup,
                )
                self.assertEqual(projection["attempts"], 1)
                (state / "RECEIPT-one.json").write_bytes(b"substituted\n")
                with self.assertRaisesRegex(
                    controller.TransactionalControllerRejected,
                    "v2_evidence_tree_drifted",
                ):
                    controller.verify_v2_immutable_evidence(
                        terminal_handoff=terminal,
                        state_root=state,
                        backup_root=backup,
                    )


if __name__ == "__main__":
    unittest.main()
