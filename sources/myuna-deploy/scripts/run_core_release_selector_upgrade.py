#!/usr/bin/env python3
"""Fixed CLI gate for selected-to-selected Core preflight/activation/recovery."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import Sequence

sys.dont_write_bytecode = True

from core_release_selector_upgrade_controller import SelectedUpgradeController
from core_release_selector_upgrade_executor import UpgradeBundle
from core_release_selector_upgrade_journal import HashChainJournal
from core_release_selector_upgrade_live_backend import FixedSystemdSelectedUpgradeBackend
from core_release_selector_upgrade_release import (
    ENTRYPOINT_NAME,
    UpgradeReleaseError,
    validate_installed_release,
)


TRANSACTION_ROOT = Path("/opt/myuna/core-release-selector/selected-upgrade-transactions")
TRANSACTION_RECEIPT_ROOT = Path(
    "/opt/myuna/core-release-selector/selected-upgrade-transaction-installations"
)
EXECUTOR_ROOT = Path("/opt/myuna/core-release-selector/selected-upgrade-executors")
EXECUTOR_RECEIPT_ROOT = Path(
    "/opt/myuna/core-release-selector/selected-upgrade-executor-installations"
)
STATE_ROOT = Path("/var/lib/myuna-core-release-selector/selected-upgrade-activations")
LIVE_CONFIRMATION = "I_UNDERSTAND_THIS_WILL_RESTART_MYUNA_CORE"
EXPECTED_TRANSACTION_PATHS = frozenset(
    {
        "activation/UPGRADE_PLAN.json",
        "target/qq.binding.json",
        "target/10-core-release-selector-v1.conf",
        "target/qq.env",
        "target/15-telegram-http-client-credential-v1.conf",
        "rollback/qq.binding.json",
        "rollback/10-core-release-selector-v1.conf",
        "rollback/qq.env",
        "TRANSACTION_MANIFEST.json",
    }
)


class UpgradeCliError(RuntimeError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise UpgradeCliError(code)


def _load_json(path: Path, code: str) -> dict[str, object]:
    require(path.is_file() and not path.is_symlink(), code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise UpgradeCliError(code) from None
    require(isinstance(payload, dict), code)
    return payload


def verify_executor_installation(
    *,
    expected_executor_release_digest: str,
    expected_source_deploy_commit: str,
    approved_activation_plan_digest: str,
    expected_transaction_tree: str,
    approved_inactive_install_plan_digest: str,
    approved_executor_install_plan_digest: str,
) -> None:
    release_root = EXECUTOR_ROOT / expected_executor_release_digest
    require(
        Path(__file__).absolute() == release_root / ENTRYPOINT_NAME
        and not Path(__file__).is_symlink(),
        "executor_entrypoint_rejected",
    )
    try:
        validate_installed_release(
            release_root,
            expected_release_digest=expected_executor_release_digest,
            expected_source_deploy_commit=expected_source_deploy_commit,
            expected_activation_plan_digest=approved_activation_plan_digest,
            expected_transaction_tree_sha256=expected_transaction_tree,
            expected_inactive_install_plan_digest=approved_inactive_install_plan_digest,
        )
    except UpgradeReleaseError as exc:
        raise UpgradeCliError("executor_release_rejected") from exc
    receipt = _load_json(
        EXECUTOR_RECEIPT_ROOT / f"{approved_executor_install_plan_digest}.json",
        "executor_install_receipt_rejected",
    )
    require(
        receipt
        == {
            "schema": "myuna.core-release-selector.selected-upgrade-executor-installation.v1",
            "status": "installed_inactive_not_executed",
            "approved_install_plan_digest": approved_executor_install_plan_digest,
            "executor_release_digest": expected_executor_release_digest,
            "executor_path": release_root.as_posix(),
            "source_deploy_commit": expected_source_deploy_commit,
            "activation_plan_digest": approved_activation_plan_digest,
            "transaction_tree_sha256": expected_transaction_tree,
            "inactive_transaction_install_plan_digest": approved_inactive_install_plan_digest,
            "runtime_invoked": False,
            "systemd_changed": False,
            "service_lifecycle_performed": False,
        },
        "executor_install_receipt_rejected",
    )


def load_transaction_bundle(
    *,
    transaction_tree: str,
    activation_plan_digest: str,
    inactive_install_plan_digest: str,
) -> UpgradeBundle:
    root = TRANSACTION_ROOT / transaction_tree
    require(root.is_dir() and not root.is_symlink(), "transaction_root_rejected")
    payloads: dict[str, bytes] = {}
    for entry in sorted(root.rglob("*")):
        require(not entry.is_symlink(), "transaction_entry_rejected")
        if entry.is_file():
            payloads[entry.relative_to(root).as_posix()] = entry.read_bytes()
    require(set(payloads) == EXPECTED_TRANSACTION_PATHS, "transaction_paths_rejected")
    bundle = UpgradeBundle.load(payloads, approved_plan_digest=activation_plan_digest)
    receipt = _load_json(
        TRANSACTION_RECEIPT_ROOT / f"{inactive_install_plan_digest}.json",
        "transaction_install_receipt_rejected",
    )
    verify_transaction_install_receipt(
        receipt,
        transaction_root=root,
        transaction_tree=transaction_tree,
        activation_plan_digest=activation_plan_digest,
        inactive_install_plan_digest=inactive_install_plan_digest,
    )
    return bundle


def verify_transaction_install_receipt(
    receipt: dict[str, object],
    *,
    transaction_root: Path,
    transaction_tree: str,
    activation_plan_digest: str,
    inactive_install_plan_digest: str,
) -> None:
    require(
        receipt.get("schema")
        == "myuna.core-release-selector.selected-upgrade-transaction-installation.v1"
        and receipt.get("status") == "installed_inactive_not_activated"
        and receipt.get("approved_install_plan_digest") == inactive_install_plan_digest
        and receipt.get("activation_plan_digest") == activation_plan_digest
        and receipt.get("transaction_tree_sha256") == transaction_tree
        and receipt.get("transaction_path") == transaction_root.as_posix()
        and receipt.get("transaction_file_count") == 9
        and receipt.get("runtime_invoked") is False
        and receipt.get("systemd_changed") is False
        and receipt.get("service_lifecycle_performed") is False
        and receipt.get("selected_or_activated") is False
        and receipt.get("secret_values_read") is False,
        "transaction_install_receipt_rejected",
    )


def build_controller(bundle: UpgradeBundle) -> SelectedUpgradeController:
    transaction_id = bundle.plan_digest

    def journal_exists() -> bool:
        return (STATE_ROOT / transaction_id).exists()

    def create_journal():
        return HashChainJournal(STATE_ROOT, transaction_id, create=True)

    def open_journal():
        return HashChainJournal(STATE_ROOT, transaction_id, create=False)

    return SelectedUpgradeController(
        bundle=bundle,
        backend=FixedSystemdSelectedUpgradeBackend(),
        journal_exists=journal_exists,
        create_journal=create_journal,
        open_journal=open_journal,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("preflight", "activate-live", "recover-live"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--expected-executor-release-digest", required=True)
        subparser.add_argument("--expected-source-deploy-commit", required=True)
        subparser.add_argument("--approved-executor-install-plan-digest", required=True)
        subparser.add_argument("--approved-activation-plan-digest", required=True)
        subparser.add_argument("--expected-transaction-tree", required=True)
        subparser.add_argument("--approved-inactive-install-plan-digest", required=True)
        if command != "preflight":
            subparser.add_argument("--live-confirmation", required=True)
    arguments = parser.parse_args(argv)
    require(os.geteuid() == 0, "must_run_as_root")
    if arguments.command != "preflight":
        require(arguments.live_confirmation == LIVE_CONFIRMATION, "live_confirmation_rejected")
    verify_executor_installation(
        expected_executor_release_digest=arguments.expected_executor_release_digest,
        expected_source_deploy_commit=arguments.expected_source_deploy_commit,
        approved_activation_plan_digest=arguments.approved_activation_plan_digest,
        expected_transaction_tree=arguments.expected_transaction_tree,
        approved_inactive_install_plan_digest=arguments.approved_inactive_install_plan_digest,
        approved_executor_install_plan_digest=arguments.approved_executor_install_plan_digest,
    )
    bundle = load_transaction_bundle(
        transaction_tree=arguments.expected_transaction_tree,
        activation_plan_digest=arguments.approved_activation_plan_digest,
        inactive_install_plan_digest=arguments.approved_inactive_install_plan_digest,
    )
    controller = build_controller(bundle)
    if arguments.command == "preflight":
        result = controller.preflight()
    elif arguments.command == "activate-live":
        result = controller.activate()
    else:
        result = controller.recover()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
