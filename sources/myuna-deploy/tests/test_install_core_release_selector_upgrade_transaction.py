from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest


CANDIDATE_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [
    str(CANDIDATE_ROOT / "scripts"),
    "/srv/myuna/repos/deploy/scripts",
]

from core_release_selector import (  # noqa: E402
    ReleaseEvidence,
    SelectionCandidate,
    build_binding_intent,
    canonical_json_bytes,
    render_runtime_binding,
    render_selector_dropin,
)
from core_release_selector_transaction_v2 import transaction_tree_digest  # noqa: E402
import core_release_selector_upgrade as upgrade  # noqa: E402
from install_core_release_selector_upgrade_transaction import (  # noqa: E402
    SelectedUpgradeTransactionInstallError,
    install_inactive_transaction,
)

class InactiveInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.current = ReleaseEvidence(
            tree_sha256="1" * 64,
            source_commit="2" * 40,
            file_count=149,
            artifact_manifest_sha256="3" * 64,
            installation_receipt_sha256="4" * 64,
        )
        self.target = ReleaseEvidence(
            tree_sha256="5" * 64,
            source_commit="6" * 40,
            file_count=153,
            artifact_manifest_sha256="7" * 64,
            installation_receipt_sha256="8" * 64,
        )
        self.verifier = (
            "/opt/myuna/core-release-selector/releases/"
            + "9" * 64
            + "/core_release_selector.py"
        )
        current_intent = build_binding_intent(
            SelectionCandidate(self.current),
            verifier_script_path=self.verifier,
            verifier_script_sha256="9" * 64,
        )
        self.current_binding = render_runtime_binding(
            current_intent,
            approval_plan_digest="a" * 64,
        )
        self.current_binding_payload = canonical_json_bytes(
            self.current_binding.to_payload()
        )
        self.rollback_selector = render_selector_dropin(
            SelectionCandidate(self.current)
        ).encode()
        self.target_selector = render_selector_dropin(
            SelectionCandidate(self.target)
        ).encode()
        self.old_env = (
            b"MYUNA_ENV=dev\nMYUNA_DEV_TOKEN_CREDENTIAL=qq_owner_core_token\n"
        )
        self.new_env = (
            b"MYUNA_ENV=dev\nMYUNA_HTTP_CLIENT_CREDENTIALS="
            b"qq-owner-private:astrbot_qq:qq_owner_core_token,"
            b"telegram-owner-private:astrbot_telegram:telegram_owner_core_token\n"
        )
        self.credential = (
            b"[Service]\nLoadCredential=telegram_owner_core_token:"
            b"/etc/myuna-telegram-gateway/secrets/core-token-v1\n"
        )
        self.prestate_dropins = {
            "05-core-release-selector-guard-v1.conf": "b" * 64,
            upgrade.SELECTOR_DROPIN: self.digest(self.rollback_selector),
            "credentials.conf": "c" * 64,
        }
        self.target_dropins = dict(self.prestate_dropins)
        self.target_dropins[upgrade.SELECTOR_DROPIN] = self.digest(
            self.target_selector
        )
        self.target_dropins[upgrade.TELEGRAM_CREDENTIAL_DROPIN] = self.digest(
            self.credential
        )
        self.states = {
            upgrade.UNIT: {"active_state": "inactive", "sub_state": "dead"},
            "myuna-qq-owner-runtime-dev.socket": {
                "active_state": "active",
                "sub_state": "listening",
            },
            "myuna-qq-owner-runtime-dev.service": {
                "active_state": "inactive",
                "sub_state": "dead",
            },
        }

    def plan(self) -> bytes:
        return upgrade.build_upgrade_plan(
            deploy_commit="d" * 40,
            core_commit="e" * 40,
            current_binding=self.current_binding,
            target_release=self.target,
            verifier_sha256="9" * 64,
            base_unit_sha256="f" * 64,
            prestate_dropin_sha256=self.prestate_dropins,
            target_dropin_sha256=self.target_dropins,
            prestate_qq_env_sha256=self.digest(self.old_env),
            target_qq_env_sha256=self.digest(self.new_env),
            target_selector_sha256=self.digest(self.target_selector),
            target_credential_dropin_sha256=self.digest(self.credential),
            service_states=self.states,
        )

    def bundle(self) -> dict[str, bytes]:
        plan = self.plan()
        target_intent = build_binding_intent(
            SelectionCandidate(self.target),
            verifier_script_path=self.verifier,
            verifier_script_sha256="9" * 64,
        )
        target_binding = render_runtime_binding(
            target_intent,
            approval_plan_digest=self.digest(plan),
        )
        return upgrade.build_upgrade_bundle(
            plan=plan,
            target_binding=canonical_json_bytes(target_binding.to_payload()),
            target_selector=self.target_selector,
            target_qq_env=self.new_env,
            target_credential_dropin=self.credential,
            rollback_binding=self.current_binding_payload,
            rollback_selector=self.rollback_selector,
            rollback_qq_env=self.old_env,
        )

    def _source(self, root: Path) -> tuple[Path, str, str]:
        plan = self.plan()
        bundle = self.bundle()
        tree = transaction_tree_digest(bundle)
        source = root / "source" / tree
        for relative, payload in bundle.items():
            destination = source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)
        return source, tree, self.digest(plan)

    def digest(self, payload: bytes) -> str:
        from hashlib import sha256

        return sha256(payload).hexdigest()

    def test_installs_exact_tree_and_receipt_without_runtime_effect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, tree, activation = self._source(root)
            transaction_root = root / "transactions"
            receipt_root = root / "receipts"
            transaction_root.mkdir(mode=0o750)
            receipt_root.mkdir(mode=0o750)
            result = install_inactive_transaction(
                source=source,
                approved_install_plan_digest="a" * 64,
                expected_tree_sha256=tree,
                approved_activation_plan_digest=activation,
                transaction_root=transaction_root,
                receipt_root=receipt_root,
                uid=0,
                gid=0,
            )
            self.assertEqual(result["status"], "installed_inactive_not_activated")
            self.assertFalse(result["runtime_invoked"])
            self.assertTrue((transaction_root / tree).is_dir())
            self.assertEqual(
                (receipt_root / f"{'a' * 64}.json").read_bytes(),
                canonical_json_bytes(result),
            )

    def test_rejects_wrong_tree_without_installing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, _tree, activation = self._source(root)
            transaction_root = root / "transactions"
            receipt_root = root / "receipts"
            transaction_root.mkdir(mode=0o750)
            receipt_root.mkdir(mode=0o750)
            with self.assertRaises(SelectedUpgradeTransactionInstallError):
                install_inactive_transaction(
                    source=source,
                    approved_install_plan_digest="a" * 64,
                    expected_tree_sha256="b" * 64,
                    approved_activation_plan_digest=activation,
                    transaction_root=transaction_root,
                    receipt_root=receipt_root,
                    uid=0,
                    gid=0,
                )
            self.assertEqual(list(transaction_root.iterdir()), [])
            self.assertEqual(list(receipt_root.iterdir()), [])

    def test_idempotent_only_for_exact_existing_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, tree, activation = self._source(root)
            transaction_root = root / "transactions"
            receipt_root = root / "receipts"
            transaction_root.mkdir(mode=0o750)
            receipt_root.mkdir(mode=0o750)
            keywords = dict(
                source=source,
                approved_install_plan_digest="a" * 64,
                expected_tree_sha256=tree,
                approved_activation_plan_digest=activation,
                transaction_root=transaction_root,
                receipt_root=receipt_root,
                uid=0,
                gid=0,
            )
            first = install_inactive_transaction(**keywords)
            second = install_inactive_transaction(**keywords)
            self.assertEqual(first, second)
            target = transaction_root / tree / "target/qq.env"
            target.chmod(0o640)
            target.write_bytes(b"drift")
            target.chmod(0o440)
            with self.assertRaises(SelectedUpgradeTransactionInstallError):
                install_inactive_transaction(**keywords)


if __name__ == "__main__":
    unittest.main()
