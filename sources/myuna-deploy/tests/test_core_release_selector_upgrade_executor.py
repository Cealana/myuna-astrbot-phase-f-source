from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import sys
import unittest


FORMAL_SCRIPTS = Path("/srv/myuna/repos/deploy/scripts")
R1_SCRIPTS = Path(
    "/mnt/c/Users/26856/Documents/Codex/2026-07-15/"
    "codex-chatgpt-conversation-6a566367-92e0-83ee-4/work/"
    "astrbot-telegram-gateway-20260725/"
    "core-release-selected-upgrade-v1-r1-work-only/deploy-changes/scripts"
)
R2_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path[:0] = [str(R2_SCRIPTS), str(R1_SCRIPTS), str(FORMAL_SCRIPTS)]

from core_release_selector import (  # noqa: E402
    ReleaseEvidence,
    SelectionCandidate,
    build_binding_intent,
    canonical_json_bytes,
    render_runtime_binding,
    render_selector_dropin,
)
import core_release_selector_upgrade as contract  # noqa: E402
from core_release_selector_upgrade_executor import (  # noqa: E402
    FakeUpgradeBackend,
    JournaledUpgradeExecutor,
    MemoryJournal,
    UpgradeBundle,
    UpgradeExecutionError,
)


def h(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def bundle_payloads() -> tuple[dict[str, bytes], str]:
    current = ReleaseEvidence("1" * 64, "2" * 40, 149, "3" * 64, "4" * 64)
    target = ReleaseEvidence("5" * 64, "6" * 40, 153, "7" * 64, "8" * 64)
    verifier = "/opt/myuna/core-release-selector/releases/" + "9" * 64 + "/core_release_selector.py"
    current_intent = build_binding_intent(
        SelectionCandidate(current), verifier_script_path=verifier, verifier_script_sha256="9" * 64
    )
    current_binding = render_runtime_binding(current_intent, approval_plan_digest="a" * 64)
    old_binding = canonical_json_bytes(current_binding.to_payload())
    old_selector = render_selector_dropin(SelectionCandidate(current)).encode()
    new_selector = render_selector_dropin(SelectionCandidate(target)).encode()
    old_env = b"MYUNA_DEV_TOKEN_CREDENTIAL=qq_owner_core_token\n"
    new_env = b"MYUNA_HTTP_CLIENT_CREDENTIALS=qq-owner-private:astrbot_qq:qq_owner_core_token,telegram-owner-private:astrbot_telegram:telegram_owner_core_token\n"
    credential = b"[Service]\nLoadCredential=telegram_owner_core_token:/etc/myuna-telegram-gateway/secrets/core-token-v1\n"
    old_dropins = {"05-core-release-selector-guard-v1.conf": "b" * 64, contract.SELECTOR_DROPIN: h(old_selector)}
    new_dropins = dict(old_dropins)
    new_dropins[contract.SELECTOR_DROPIN] = h(new_selector)
    new_dropins[contract.TELEGRAM_CREDENTIAL_DROPIN] = h(credential)
    plan = contract.build_upgrade_plan(
        deploy_commit="d" * 40,
        core_commit="e" * 40,
        current_binding=current_binding,
        target_release=target,
        verifier_sha256="9" * 64,
        base_unit_sha256="f" * 64,
        prestate_dropin_sha256=old_dropins,
        target_dropin_sha256=new_dropins,
        prestate_qq_env_sha256=h(old_env),
        target_qq_env_sha256=h(new_env),
        target_selector_sha256=h(new_selector),
        target_credential_dropin_sha256=h(credential),
        service_states={
            contract.UNIT: {"active_state": "inactive", "sub_state": "dead"},
            "myuna-qq-owner-runtime-dev.socket": {"active_state": "active", "sub_state": "listening"},
            "myuna-qq-owner-runtime-dev.service": {"active_state": "inactive", "sub_state": "dead"},
        },
    )
    target_intent = build_binding_intent(
        SelectionCandidate(target), verifier_script_path=verifier, verifier_script_sha256="9" * 64
    )
    target_binding = render_runtime_binding(target_intent, approval_plan_digest=h(plan))
    payloads = contract.build_upgrade_bundle(
        plan=plan,
        target_binding=canonical_json_bytes(target_binding.to_payload()),
        target_selector=new_selector,
        target_qq_env=new_env,
        target_credential_dropin=credential,
        rollback_binding=old_binding,
        rollback_selector=old_selector,
        rollback_qq_env=old_env,
    )
    return payloads, h(plan)


class ExecutorTests(unittest.TestCase):
    def load(self) -> UpgradeBundle:
        payloads, plan_digest = bundle_payloads()
        return UpgradeBundle.load(payloads, approved_plan_digest=plan_digest)

    def test_success_order_and_receipt(self) -> None:
        backend = FakeUpgradeBackend()
        journal = MemoryJournal()
        result = JournaledUpgradeExecutor(bundle=self.load(), backend=backend, journal=journal).execute()
        self.assertEqual(result["status"], "activated")
        self.assertEqual(
            backend.events,
            ["verify_exact_prestate", "quiesce_gateway", "apply_files", "daemon_reload", "start_core", "verify_target", "restore_gateway"],
        )
        self.assertEqual(journal.records[-1]["phase"], "committed")
        self.assertEqual(journal.receipt["status"], "selected_release_upgraded")

    def test_failure_before_file_apply_rolls_back_without_file_restore(self) -> None:
        backend = FakeUpgradeBackend(fail_at="quiesce_gateway")
        journal = MemoryJournal()
        with self.assertRaises(UpgradeExecutionError):
            JournaledUpgradeExecutor(bundle=self.load(), backend=backend, journal=journal).execute()
        self.assertEqual(journal.records[-1]["phase"], "rollback_failed")

    def test_apply_failure_attempts_file_restore(self) -> None:
        backend = FakeUpgradeBackend(fail_at="apply_files")
        journal = MemoryJournal()
        result = JournaledUpgradeExecutor(bundle=self.load(), backend=backend, journal=journal).execute()
        self.assertEqual(result["status"], "rolled_back")
        self.assertIn("restore_files", backend.events)
        self.assertEqual(backend.files, "prestate")

    def test_reload_failure_rolls_back_and_reloads_again(self) -> None:
        backend = FakeUpgradeBackend(fail_at="daemon_reload")
        journal = MemoryJournal()
        with self.assertRaises(UpgradeExecutionError):
            JournaledUpgradeExecutor(bundle=self.load(), backend=backend, journal=journal).execute()
        self.assertEqual(journal.records[-1]["phase"], "rollback_failed")

    def test_core_start_failure_rolls_back(self) -> None:
        backend = FakeUpgradeBackend(fail_at="start_core")
        backend.fail_at = "start_core"
        journal = MemoryJournal()
        result = JournaledUpgradeExecutor(bundle=self.load(), backend=backend, journal=journal).execute()
        self.assertEqual(result["status"], "rolled_back")
        self.assertEqual(backend.files, "prestate")

    def test_target_verification_failure_rolls_back(self) -> None:
        backend = FakeUpgradeBackend(fail_at="verify_target")
        journal = MemoryJournal()
        result = JournaledUpgradeExecutor(bundle=self.load(), backend=backend, journal=journal).execute()
        self.assertEqual(result["status"], "rolled_back")
        self.assertEqual(backend.core, "inactive")

    def test_gateway_restore_failure_rolls_back(self) -> None:
        backend = FakeUpgradeBackend(fail_at="restore_gateway")
        journal = MemoryJournal()
        result = JournaledUpgradeExecutor(bundle=self.load(), backend=backend, journal=journal).execute()
        self.assertEqual(result["status"], "rolled_back")
        self.assertEqual(backend.gateway, "prestate")

    def test_nonempty_journal_fails_closed(self) -> None:
        backend = FakeUpgradeBackend()
        journal = MemoryJournal()
        journal.append("prepared", "old")
        with self.assertRaises(UpgradeExecutionError):
            JournaledUpgradeExecutor(bundle=self.load(), backend=backend, journal=journal).execute()
        self.assertEqual(backend.events, [])

    def test_wrong_approval_digest_fails_closed(self) -> None:
        payloads, _ = bundle_payloads()
        with self.assertRaises(UpgradeExecutionError):
            UpgradeBundle.load(payloads, approved_plan_digest="0" * 64)


if __name__ == "__main__":
    unittest.main()

