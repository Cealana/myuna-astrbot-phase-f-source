from __future__ import annotations

import ast
from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
FORMAL_SCRIPTS = Path("/srv/myuna/repos/deploy/scripts")
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(1, str(FORMAL_SCRIPTS))

from core_release_selector import (  # noqa: E402
    canonical_json_bytes as selector_canonical_json_bytes,
    load_binding_intent,
    parse_json_document,
    render_guard_dropin,
    render_runtime_binding,
    render_selector_dropin,
    SelectionCandidate,
)
import core_release_selector_transaction as transaction_v1  # noqa: E402
from core_release_selector_transaction_v2 import (  # noqa: E402
    build_activation_plan,
    build_transaction_payloads,
    digest,
    transaction_tree_digest,
)
from core_release_selector_r4c_executor import (  # noqa: E402
    JournaledR4CExecutor,
    PHASE_COMMITTED,
    PHASE_CORE_APPLY_INTENT,
    PHASE_CORE_VERIFIED,
    PHASE_RECEIPT_WRITE_INTENT,
    PHASE_GATEWAY_START_INTENT,
    PHASE_GATEWAY_VERIFIED,
    PHASE_PREPARED,
    PHASE_ROLLED_BACK,
    PHASE_SOCKET_START_INTENT,
    PHASE_SOCKET_STOP_INTENT,
    R4CExecutionError,
    RuntimeSnapshot,
    TransactionBundle,
    verify_inactive_install_receipt,
)
from core_release_selector_r4c_journal import (  # noqa: E402
    FileJournal,
    canonical_json_bytes,
)
import run_core_release_selector_r4c as r4c_cli  # noqa: E402


FORMAL_ROOT = (
    ROOT
    if (ROOT / "config" / "core-release-selector-v1-binding-intent.json").is_file()
    else Path("/srv/myuna/repos/deploy")
)


def build_fixture_transaction(parent: Path) -> tuple[Path, str, str]:
    intent = load_binding_intent(
        parse_json_document(
            (
                FORMAL_ROOT
                / "config"
                / "core-release-selector-v1-binding-intent.json"
            ).read_bytes()
        )
    )
    candidate = SelectionCandidate(selected_release=intent.selected_release)
    selector = render_selector_dropin(candidate).encode("utf-8")
    guard = render_guard_dropin(intent.verifier_script_path).encode("utf-8")
    base = (
        b"[Service]\n"
        b"WorkingDirectory=/srv/myuna/repos/core\n"
        b"Environment=PYTHONPATH=/srv/myuna/repos/core/src\n"
    )
    legacy = (
        b"[Service]\n"
        b"WorkingDirectory=/srv/myuna/releases/core/legacy\n"
        b"Environment=PYTHONPATH=/srv/myuna/releases/core/legacy/src\n"
    )
    feature = b"[Service]\nEnvironment=MYUNA_FEATURE=1\n"
    rollback = {"90-legacy.conf": legacy, "feature.conf": feature}
    final = {
        transaction_v1.GUARD_NAME: guard,
        transaction_v1.SELECTOR_NAME: selector,
        "feature.conf": feature,
    }
    writes = {
        transaction_v1.GUARD_NAME: guard,
        transaction_v1.SELECTOR_NAME: selector,
    }
    plan = build_activation_plan(
        deploy_commit="a" * 40,
        core_commit="b" * 40,
        migration_contract_sha256="c" * 64,
        r3b_plan_digest="d" * 64,
        binding_intent_sha256="e" * 64,
        verifier_sha256=intent.verifier_script_sha256,
        base_template_sha256=digest(base),
        prestate_dropin_sha256={
            name: digest(payload) for name, payload in rollback.items()
        },
        prestate_effective_owner="90-legacy.conf",
        prestate_working_directory="/srv/myuna/releases/core/legacy",
        target_release_path=intent.selected_release.release_path.as_posix(),
        target_tree_sha256=intent.selected_release.tree_sha256,
        target_file_count=intent.selected_release.file_count,
        final_dropin_sha256={
            name: digest(payload) for name, payload in final.items()
        },
        write_dropin_sha256={
            name: digest(payload) for name, payload in writes.items()
        },
        deletes=("90-legacy.conf",),
        gateway_fragment_sha256="1" * 64,
        gateway_dropin_sha256={"gateway.conf": "2" * 64},
        gateway_socket_fragment_sha256="3" * 64,
        gateway_socket_dropin_sha256={},
        gateway_socket_listen_stream="/run/myuna-gateway/qq-owner.sock",
        gateway_socket_unit_file_state="enabled",
        gateway_socket_substate="running",
    )
    plan_digest = digest(plan)
    binding = selector_canonical_json_bytes(
        render_runtime_binding(
            intent,
            approval_plan_digest=plan_digest,
        ).to_payload()
    )
    payloads = build_transaction_payloads(
        activation_plan=plan,
        runtime_binding=binding,
        base_template=base,
        rollback_dropins=rollback,
        final_dropins=final,
        write_dropins=writes,
        deletes=("90-legacy.conf",),
    )
    tree_digest = transaction_tree_digest(payloads)
    root = parent / tree_digest
    for relative, payload in payloads.items():
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    return root, tree_digest, plan_digest


class InjectedFailure(RuntimeError):
    pass


class InjectedCrash(BaseException):
    pass


class CrashBeforeCommittedJournal(FileJournal):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.crashed = False

    def append(self, *, phase: str, event: str, data=None):
        if phase == PHASE_COMMITTED and not self.crashed:
            self.crashed = True
            raise InjectedCrash("before_committed_record")
        return super().append(phase=phase, event=event, data=data)


class FakeBackend:
    def __init__(self) -> None:
        self.core_mode = "legacy"
        self.binding_present = False
        self.core_active = True
        self.socket_active = True
        self.service_active = True
        self.restart_count = 0
        self.daemon_reload_count = 0
        self.mutations: list[str] = []
        self.fail_before: str | None = None
        self.fail_after: str | None = None
        self.crash_after: str | None = None
        self.target_valid = True
        self.rollback_valid = True
        self.rollback_failure = False

    def _mutate(self, name: str, function) -> None:
        self.mutations.append(name)
        if self.fail_before == name:
            self.fail_before = None
            raise InjectedFailure(f"before:{name}")
        function()
        if self.crash_after == name:
            self.crash_after = None
            raise InjectedCrash(f"after:{name}")
        if self.fail_after == name:
            self.fail_after = None
            raise InjectedFailure(f"after:{name}")

    def verify_exact_prestate(self, bundle: TransactionBundle) -> RuntimeSnapshot:
        if not (
            self.core_mode == "legacy"
            and not self.binding_present
            and self.core_active
            and self.socket_active
            and self.service_active
        ):
            raise InjectedFailure("prestate")
        return RuntimeSnapshot.create(
            core_restart_count=self.restart_count,
            core_active=self.core_active,
            gateway_socket_active=self.socket_active,
            gateway_service_active=self.service_active,
        )

    def stop_gateway_socket(self, bundle: TransactionBundle) -> None:
        self._mutate("stop_socket", lambda: setattr(self, "socket_active", False))

    def verify_gateway_socket_inactive(self, bundle: TransactionBundle) -> None:
        if self.socket_active:
            raise InjectedFailure("socket_still_active")

    def stop_gateway_service(self, bundle: TransactionBundle) -> None:
        self._mutate("stop_service", lambda: setattr(self, "service_active", False))

    def verify_gateway_service_inactive(self, bundle: TransactionBundle) -> None:
        if self.service_active:
            raise InjectedFailure("service_still_active")

    def apply_core_files(self, bundle: TransactionBundle) -> None:
        def apply() -> None:
            self.core_mode = "target"
            self.binding_present = True

        self._mutate("apply_core", apply)

    def daemon_reload(self, bundle: TransactionBundle) -> None:
        def reload() -> None:
            self.daemon_reload_count += 1

        self._mutate("daemon_reload", reload)

    def restart_core(self, bundle: TransactionBundle) -> None:
        def restart() -> None:
            self.restart_count += 1
            self.core_active = True

        self._mutate("restart_core", restart)

    def verify_target_core(
        self,
        bundle: TransactionBundle,
        snapshot: RuntimeSnapshot,
        *,
        enforce_restart_budget: bool = True,
    ) -> None:
        if not (
            self.target_valid
            and self.core_mode == "target"
            and self.binding_present
            and self.core_active
            and (
                not enforce_restart_budget
                or self.restart_count <= snapshot.core_restart_count + 1
            )
        ):
            raise InjectedFailure("target_invalid")

    def start_gateway_socket(self, bundle: TransactionBundle) -> None:
        self._mutate("start_socket", lambda: setattr(self, "socket_active", True))

    def verify_gateway_socket_active(self, bundle: TransactionBundle) -> None:
        if not self.socket_active:
            raise InjectedFailure("socket_inactive")

    def start_gateway_service(self, bundle: TransactionBundle) -> None:
        def start() -> None:
            if not self.socket_active:
                raise InjectedFailure("service_before_socket")
            self.service_active = True

        self._mutate("start_service", start)

    def verify_gateway_service_active(self, bundle: TransactionBundle) -> None:
        if not (self.socket_active and self.service_active):
            raise InjectedFailure("gateway_invalid")

    def restore_core_files(self, bundle: TransactionBundle) -> None:
        def restore() -> None:
            if self.rollback_failure:
                raise InjectedFailure("restore_failed")
            self.core_mode = "legacy"
            self.binding_present = False

        self._mutate("restore_core", restore)

    def verify_rollback_core(
        self,
        bundle: TransactionBundle,
        snapshot: RuntimeSnapshot,
    ) -> None:
        if not (
            self.rollback_valid
            and self.core_mode == "legacy"
            and not self.binding_present
            and self.core_active
        ):
            raise InjectedFailure("rollback_invalid")


class ExecutorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture_temporary = tempfile.TemporaryDirectory()
        (
            cls.transaction,
            cls.tree_digest,
            cls.plan_digest,
        ) = build_fixture_transaction(
            Path(cls.fixture_temporary.name).resolve()
        )
        cls.bundle = TransactionBundle.load(
            cls.transaction,
            expected_tree_sha256=cls.tree_digest,
            approved_activation_plan_digest=cls.plan_digest,
            validate_installed_permissions=False,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_temporary.cleanup()

    def make_executor(
        self,
        root: Path,
        backend: FakeBackend,
    ) -> tuple[JournaledR4CExecutor, FileJournal]:
        counter = iter(range(1, 1000))
        journal = FileJournal(
            root,
            self.plan_digest,
            self.tree_digest,
            clock_ns=lambda: next(counter),
        )
        return (
            JournaledR4CExecutor(
                bundle=self.bundle,
                journal=journal,
                backend=backend,
            ),
            journal,
        )

    def phases(self, journal: FileJournal) -> list[str]:
        with journal.acquire():
            return [record["phase"] for record in journal.read_records()]

    def test_happy_path_is_ordered_journaled_and_committed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            executor, journal = self.make_executor(
                Path(temporary).resolve(),
                backend,
            )
            result = executor.execute()
            self.assertEqual(result["status"], "activated")
            self.assertEqual(
                backend.mutations,
                [
                    "stop_socket",
                    "stop_service",
                    "apply_core",
                    "daemon_reload",
                    "restart_core",
                    "start_socket",
                    "start_service",
                ],
            )
            phases = self.phases(journal)
            self.assertEqual(phases[0], PHASE_PREPARED)
            self.assertLess(
                phases.index(PHASE_SOCKET_STOP_INTENT),
                phases.index(PHASE_CORE_APPLY_INTENT),
            )
            self.assertLess(
                phases.index(PHASE_CORE_VERIFIED),
                phases.index(PHASE_SOCKET_START_INTENT),
            )
            self.assertLess(
                phases.index(PHASE_SOCKET_START_INTENT),
                phases.index(PHASE_GATEWAY_START_INTENT),
            )
            self.assertEqual(phases[-1], PHASE_COMMITTED)
            self.assertEqual(backend.restart_count, 1)
            self.assertEqual(backend.daemon_reload_count, 1)
            self.assertTrue(journal.receipt_path.is_file())

    def test_committed_reexecution_is_read_only_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            executor, _ = self.make_executor(Path(temporary).resolve(), backend)
            executor.execute()
            mutation_count = len(backend.mutations)
            result = executor.execute()
            self.assertEqual(result["status"], "already_activated_verified")
            self.assertEqual(len(backend.mutations), mutation_count)

    def test_committed_verification_allows_later_unrelated_core_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            executor, _ = self.make_executor(Path(temporary).resolve(), backend)
            executor.execute()
            backend.restart_count += 3
            mutation_count = len(backend.mutations)
            result = executor.execute()
            self.assertEqual(result["status"], "already_activated_verified")
            self.assertEqual(len(backend.mutations), mutation_count)

    def test_failure_before_core_mutation_restores_gateway_without_core_restart(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            backend.fail_after = "stop_socket"
            executor, journal = self.make_executor(
                Path(temporary).resolve(),
                backend,
            )
            with self.assertRaisesRegex(
                R4CExecutionError,
                "activation_failed_rolled_back",
            ):
                executor.execute()
            self.assertEqual(backend.core_mode, "legacy")
            self.assertTrue(backend.socket_active)
            self.assertTrue(backend.service_active)
            self.assertEqual(backend.restart_count, 0)
            self.assertEqual(self.phases(journal)[-1], PHASE_ROLLED_BACK)

    def test_failure_after_core_apply_restores_exact_legacy_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            backend.fail_after = "daemon_reload"
            executor, journal = self.make_executor(
                Path(temporary).resolve(),
                backend,
            )
            with self.assertRaises(R4CExecutionError):
                executor.execute()
            self.assertEqual(backend.core_mode, "legacy")
            self.assertFalse(backend.binding_present)
            self.assertTrue(backend.socket_active)
            self.assertTrue(backend.service_active)
            self.assertEqual(backend.restart_count, 1)
            self.assertEqual(self.phases(journal)[-1], PHASE_ROLLED_BACK)

    def test_failed_target_health_rolls_back_after_two_controlled_restarts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            backend.target_valid = False
            executor, _ = self.make_executor(Path(temporary).resolve(), backend)
            with self.assertRaises(R4CExecutionError):
                executor.execute()
            self.assertEqual(backend.core_mode, "legacy")
            self.assertEqual(backend.restart_count, 2)
            self.assertEqual(backend.daemon_reload_count, 2)

    def test_crash_after_socket_stop_recovers_without_core_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            backend = FakeBackend()
            backend.crash_after = "stop_socket"
            executor, journal = self.make_executor(root, backend)
            with self.assertRaises(InjectedCrash):
                executor.execute()
            backend.crash_after = None
            recovered = executor.recover()
            self.assertEqual(recovered["status"], "rolled_back")
            self.assertEqual(backend.restart_count, 0)
            self.assertTrue(backend.socket_active)
            self.assertTrue(backend.service_active)
            self.assertEqual(self.phases(journal)[-1], PHASE_ROLLED_BACK)

    def test_crash_during_core_apply_recovers_by_full_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            backend.crash_after = "apply_core"
            executor, journal = self.make_executor(
                Path(temporary).resolve(),
                backend,
            )
            with self.assertRaises(InjectedCrash):
                executor.execute()
            self.assertEqual(backend.core_mode, "target")
            backend.crash_after = None
            result = executor.recover()
            self.assertEqual(result["status"], "rolled_back")
            self.assertEqual(backend.core_mode, "legacy")
            self.assertFalse(backend.binding_present)
            self.assertEqual(self.phases(journal)[-1], PHASE_ROLLED_BACK)

    def test_crash_after_verified_core_resumes_forward_when_target_is_valid(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            backend.crash_after = "start_socket"
            executor, journal = self.make_executor(
                Path(temporary).resolve(),
                backend,
            )
            with self.assertRaises(InjectedCrash):
                executor.execute()
            self.assertIn(PHASE_SOCKET_START_INTENT, self.phases(journal))
            backend.crash_after = None
            result = executor.recover()
            self.assertEqual(result["status"], "activated")
            self.assertEqual(backend.core_mode, "target")
            self.assertEqual(backend.restart_count, 1)
            self.assertEqual(self.phases(journal)[-1], PHASE_COMMITTED)

    def test_crash_after_verified_core_rolls_back_if_target_drifts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            backend.crash_after = "start_socket"
            executor, _ = self.make_executor(Path(temporary).resolve(), backend)
            with self.assertRaises(InjectedCrash):
                executor.execute()
            backend.crash_after = None
            backend.target_valid = False
            result = executor.recover()
            self.assertEqual(result["status"], "rolled_back")
            self.assertEqual(backend.core_mode, "legacy")

    def test_crash_after_receipt_write_recovers_to_single_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            backend = FakeBackend()
            counter = iter(range(1, 1000))
            journal = CrashBeforeCommittedJournal(
                root,
                self.plan_digest,
                self.tree_digest,
                clock_ns=lambda: next(counter),
            )
            executor = JournaledR4CExecutor(
                bundle=self.bundle,
                journal=journal,
                backend=backend,
            )
            with self.assertRaises(InjectedCrash):
                executor.execute()
            self.assertTrue(journal.receipt_path.is_file())
            self.assertEqual(self.phases(journal)[-1], PHASE_RECEIPT_WRITE_INTENT)
            result = executor.recover()
            self.assertEqual(result["status"], "activated")
            phases = self.phases(journal)
            self.assertEqual(phases.count(PHASE_RECEIPT_WRITE_INTENT), 1)
            self.assertEqual(phases[-1], PHASE_COMMITTED)

    def test_crash_during_rollback_resumes_from_durable_rollback_intent(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            backend.fail_after = "daemon_reload"
            backend.crash_after = "restore_core"
            executor, journal = self.make_executor(
                Path(temporary).resolve(),
                backend,
            )
            with self.assertRaises(InjectedCrash):
                executor.execute()
            self.assertEqual(
                self.phases(journal)[-1],
                "rollback_core_restore_intent",
            )
            result = executor.recover()
            self.assertEqual(result["status"], "rolled_back")
            self.assertEqual(backend.core_mode, "legacy")
            self.assertTrue(backend.socket_active)
            self.assertTrue(backend.service_active)
            self.assertEqual(self.phases(journal)[-1], PHASE_ROLLED_BACK)

    def test_transient_gateway_start_failure_resumes_after_core_health(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            backend.fail_after = "start_socket"
            executor, journal = self.make_executor(
                Path(temporary).resolve(),
                backend,
            )
            result = executor.execute()
            self.assertEqual(result["status"], "activated")
            self.assertEqual(backend.core_mode, "target")
            self.assertEqual(backend.restart_count, 1)
            self.assertEqual(self.phases(journal)[-1], PHASE_COMMITTED)

    def test_rolled_back_operation_is_terminal_and_not_retried(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            backend.fail_after = "stop_socket"
            executor, _ = self.make_executor(Path(temporary).resolve(), backend)
            with self.assertRaises(R4CExecutionError):
                executor.execute()
            backend.fail_after = None
            mutations = len(backend.mutations)
            result = executor.execute()
            self.assertEqual(result["status"], "already_rolled_back")
            self.assertEqual(len(backend.mutations), mutations)

    def test_rollback_failure_is_terminal_owner_action_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            backend.fail_after = "daemon_reload"
            backend.rollback_failure = True
            executor, journal = self.make_executor(
                Path(temporary).resolve(),
                backend,
            )
            with self.assertRaisesRegex(
                R4CExecutionError,
                "rollback_failed_owner_action_required",
            ):
                executor.execute()
            self.assertEqual(self.phases(journal)[-1], "rollback_failed")
            with self.assertRaisesRegex(
                R4CExecutionError,
                "prior_rollback_failed_owner_action_required",
            ):
                executor.recover()

    def test_wrong_activation_digest_is_rejected_before_executor_exists(self) -> None:
        with self.assertRaisesRegex(
            R4CExecutionError,
            "transaction_approval_binding_rejected",
        ):
            TransactionBundle.load(
                self.transaction,
                expected_tree_sha256=self.tree_digest,
                approved_activation_plan_digest="0" * 64,
                validate_installed_permissions=False,
            )

    def test_inactive_install_receipt_is_plan_and_transaction_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            approval = "9" * 64
            receipt = Path(temporary).resolve() / f"{approval}.json"
            document = {
                "schema": (
                    "myuna.core-release-selector."
                    "r4b-inactive-installation-receipt.v2"
                ),
                "status": "inactive_socket_aware_transaction_installed",
                "approved_r4b_plan_digest": approval,
                "transaction_tree_sha256": self.tree_digest,
                "transaction_path": self.transaction.as_posix(),
                "activation_plan_digest": self.plan_digest,
                "runtime_binding_sha256": sha256(
                    self.bundle.runtime_binding
                ).hexdigest(),
                "artifact_count": len(self.bundle.payloads),
                "gateway_socket_in_contract": True,
                "runtime_paths_written": False,
                "systemd_changed": False,
                "daemon_reload_performed": False,
                "service_lifecycle_performed": False,
                "selected_or_activated": False,
            }
            receipt.write_bytes(selector_canonical_json_bytes(document))
            verified = verify_inactive_install_receipt(
                receipt,
                self.bundle,
                approved_r4b_plan_digest=approval,
                validate_installed_permissions=False,
            )
            self.assertEqual(verified, document)
            changed = dict(document)
            changed["selected_or_activated"] = True
            receipt.write_bytes(selector_canonical_json_bytes(changed))
            with self.assertRaisesRegex(
                R4CExecutionError,
                "inactive_install_receipt_integrity_rejected",
            ):
                verify_inactive_install_receipt(
                    receipt,
                    self.bundle,
                    approved_r4b_plan_digest=approval,
                    validate_installed_permissions=False,
                )

    def test_tampered_transaction_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture_parent = Path(temporary).resolve()
            root, tree_digest, plan_digest = build_fixture_transaction(
                fixture_parent
            )
            target = root / "evidence" / "DELETE_LIST.json"
            target.write_bytes(target.read_bytes() + b"\n")
            with self.assertRaisesRegex(
                R4CExecutionError,
                "transaction_contract_rejected",
            ):
                TransactionBundle.load(
                    root,
                    expected_tree_sha256=tree_digest,
                    approved_activation_plan_digest=plan_digest,
                    validate_installed_permissions=False,
                )

    def test_valid_hash_chain_with_illegal_phase_jump_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            backend.crash_after = "stop_socket"
            executor, journal = self.make_executor(
                Path(temporary).resolve(),
                backend,
            )
            with self.assertRaises(InjectedCrash):
                executor.execute()
            documents = [
                json.loads(line)
                for line in journal.journal_path.read_text().splitlines()
            ]
            documents[1]["phase"] = PHASE_CORE_VERIFIED
            unsigned = dict(documents[1])
            unsigned.pop("record_sha256")
            documents[1]["record_sha256"] = sha256(
                canonical_json_bytes(unsigned)
            ).hexdigest()
            journal.journal_path.write_bytes(
                b"".join(canonical_json_bytes(item) + b"\n" for item in documents)
            )
            with self.assertRaisesRegex(
                R4CExecutionError,
                "journal_forward_transition_rejected",
            ):
                executor.recover()

    def test_cli_rejects_live_execution_without_exact_confirmation(self) -> None:
        with mock.patch.object(r4c_cli.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(
                R4CExecutionError,
                "live_confirmation_rejected",
            ):
                r4c_cli.main(
                    [
                        "activate-live",
                        "--approved-activation-plan-digest",
                        self.plan_digest,
                        "--approved-inactive-install-plan-digest",
                        "9" * 64,
                        "--expected-transaction-tree",
                        self.tree_digest,
                        "--live-confirmation",
                        "no",
                    ]
                )

    def test_executor_sources_do_not_use_shell_eval_or_dynamic_exec(self) -> None:
        for name in (
            "core_release_selector_r4c_executor.py",
            "core_release_selector_r4c_live_backend.py",
            "run_core_release_selector_r4c.py",
        ):
            source = (SCRIPTS / name).read_text(encoding="utf-8")
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, {"eval", "exec"})
                if isinstance(node, ast.Call):
                    for keyword in node.keywords:
                        if keyword.arg == "shell":
                            self.assertIsInstance(keyword.value, ast.Constant)
                            self.assertIs(keyword.value.value, False)
            self.assertNotIn("os.system(", source)


if __name__ == "__main__":
    unittest.main()
