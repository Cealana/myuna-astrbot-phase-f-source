from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


CANDIDATE_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
FORMAL_SCRIPTS = Path("/srv/myuna/repos/deploy/scripts")
sys.path[:0] = [str(CANDIDATE_SCRIPTS), str(FORMAL_SCRIPTS)]

import run_core_release_selector_upgrade as cli  # noqa: E402


class CliBoundaryTests(unittest.TestCase):
    def test_repository_copy_cannot_pass_installed_entrypoint_gate(self) -> None:
        with self.assertRaisesRegex(cli.UpgradeCliError, "entrypoint_rejected"):
            cli.verify_executor_installation(
                expected_executor_release_digest="a" * 64,
                expected_source_deploy_commit="b" * 40,
                approved_activation_plan_digest="c" * 64,
                expected_transaction_tree="d" * 64,
                approved_inactive_install_plan_digest="e" * 64,
                approved_executor_install_plan_digest="f" * 64,
            )

    def test_live_confirmation_is_required_before_any_verifier(self) -> None:
        with mock.patch.object(cli, "verify_executor_installation") as verify:
            with self.assertRaisesRegex(cli.UpgradeCliError, "live_confirmation_rejected"):
                cli.main(
                    [
                        "activate-live",
                        "--expected-executor-release-digest", "a" * 64,
                        "--expected-source-deploy-commit", "b" * 40,
                        "--approved-executor-install-plan-digest", "c" * 64,
                        "--approved-activation-plan-digest", "d" * 64,
                        "--expected-transaction-tree", "e" * 64,
                        "--approved-inactive-install-plan-digest", "f" * 64,
                        "--live-confirmation", "wrong",
                    ]
                )
        verify.assert_not_called()

    def test_preflight_has_no_live_confirmation_argument(self) -> None:
        parser_error = None
        with self.assertRaises(SystemExit) as raised:
            cli.main(
                [
                    "preflight",
                    "--expected-executor-release-digest", "a" * 64,
                    "--expected-source-deploy-commit", "b" * 40,
                    "--approved-executor-install-plan-digest", "c" * 64,
                    "--approved-activation-plan-digest", "d" * 64,
                    "--expected-transaction-tree", "e" * 64,
                    "--approved-inactive-install-plan-digest", "f" * 64,
                    "--live-confirmation", cli.LIVE_CONFIRMATION,
                ]
            )
        parser_error = raised.exception.code
        self.assertEqual(parser_error, 2)

    def test_transaction_receipt_rejects_changed_safety_flag(self) -> None:
        transaction = Path("/opt/example")
        receipt = {
            "schema": "myuna.core-release-selector.selected-upgrade-transaction-installation.v1",
            "status": "installed_inactive_not_activated",
            "approved_install_plan_digest": "b" * 64,
            "activation_plan_digest": "c" * 64,
            "transaction_tree_sha256": "a" * 64,
            "transaction_path": transaction.as_posix(),
            "transaction_file_count": 9,
            "runtime_invoked": True,
            "systemd_changed": False,
            "service_lifecycle_performed": False,
            "selected_or_activated": False,
            "secret_values_read": False,
        }
        with self.assertRaisesRegex(cli.UpgradeCliError, "receipt_rejected"):
            cli.verify_transaction_install_receipt(
                receipt,
                transaction_root=transaction,
                transaction_tree="a" * 64,
                activation_plan_digest="c" * 64,
                inactive_install_plan_digest="b" * 64,
            )


if __name__ == "__main__":
    unittest.main()
