#!/usr/bin/env python3
"""Explicit CLI gate for live R4C activation or crash recovery."""

from __future__ import annotations

import argparse
import grp
import json
import os
from pathlib import Path
import stat
from typing import Sequence

from core_release_selector_r4c_executor import (
    JournaledR4CExecutor,
    R4CExecutionError,
    TransactionBundle,
    verify_inactive_install_receipt,
)
from core_release_selector_r4c_journal import FileJournal
from core_release_selector_r4c_live_backend import SystemdFilesystemBackend
from core_release_selector_r4c_release import (
    ENTRYPOINT_NAME,
    ExecutorReleaseError,
    validate_installed_release,
    verify_install_receipt,
    verify_state_contract,
)


TRANSACTION_ROOT = Path("/opt/myuna/core-release-selector/transactions")
INACTIVE_TRANSACTION_RECEIPT_ROOT = Path(
    "/opt/myuna/core-release-selector/transaction-installations"
)
EXECUTOR_ROOT = Path("/opt/myuna/core-release-selector/executors")
EXECUTOR_RECEIPT_ROOT = Path(
    "/opt/myuna/core-release-selector/executor-installations"
)
STATE_ROOT = Path(
    "/var/lib/myuna-core-release-selector/r4c-activations"
)
LIVE_CONFIRMATION = "I_UNDERSTAND_THIS_WILL_RESTART_MYUNA_CORE"


def _myuna_gid() -> int:
    try:
        return grp.getgrnam("myuna").gr_gid
    except KeyError as exc:
        raise R4CExecutionError("myuna_group_missing") from exc


def _verify_storage_parent(path: Path) -> None:
    metadata = path.stat()
    if (
        path.is_symlink()
        or not path.is_dir()
        or metadata.st_uid != 0
        or metadata.st_gid != _myuna_gid()
        or stat.S_IMODE(metadata.st_mode) != 0o750
    ):
        raise R4CExecutionError("executor_storage_parent_rejected")


def _verify_executor_installation(
    *,
    approved_executor_install_plan_digest: str,
    expected_executor_release_digest: str,
    expected_source_deploy_commit: str,
    approved_activation_plan_digest: str,
    expected_transaction_tree: str,
    approved_inactive_transaction_install_plan_digest: str,
) -> None:
    release_root = EXECUTOR_ROOT / expected_executor_release_digest
    entrypoint = release_root / ENTRYPOINT_NAME
    current_file = Path(__file__).absolute()
    if current_file != entrypoint or current_file.is_symlink():
        raise R4CExecutionError("executor_entrypoint_rejected")
    try:
        _verify_storage_parent(EXECUTOR_ROOT)
        _verify_storage_parent(EXECUTOR_RECEIPT_ROOT)
        evidence = validate_installed_release(
            release_root,
            expected_release_digest=expected_executor_release_digest,
            expected_source_deploy_commit=expected_source_deploy_commit,
            expected_activation_plan_digest=(
                approved_activation_plan_digest
            ),
            expected_transaction_tree_sha256=expected_transaction_tree,
            expected_inactive_transaction_install_plan_digest=(
                approved_inactive_transaction_install_plan_digest
            ),
        )
        verify_install_receipt(
            EXECUTOR_RECEIPT_ROOT
            / f"{approved_executor_install_plan_digest}.json",
            evidence,
            approved_executor_install_plan_digest=(
                approved_executor_install_plan_digest
            ),
            executor_path=release_root,
            state_root=STATE_ROOT,
        )
        verify_state_contract(STATE_ROOT)
    except (ExecutorReleaseError, OSError) as exc:
        raise R4CExecutionError(
            "executor_installation_contract_rejected"
        ) from exc


def _executor(
    *,
    approved_executor_install_plan_digest: str,
    expected_executor_release_digest: str,
    expected_source_deploy_commit: str,
    approved_plan_digest: str,
    expected_transaction_tree: str,
    approved_inactive_install_plan_digest: str,
) -> JournaledR4CExecutor:
    _verify_executor_installation(
        approved_executor_install_plan_digest=(
            approved_executor_install_plan_digest
        ),
        expected_executor_release_digest=(
            expected_executor_release_digest
        ),
        expected_source_deploy_commit=expected_source_deploy_commit,
        approved_activation_plan_digest=approved_plan_digest,
        expected_transaction_tree=expected_transaction_tree,
        approved_inactive_transaction_install_plan_digest=(
            approved_inactive_install_plan_digest
        ),
    )
    transaction_root = TRANSACTION_ROOT / expected_transaction_tree
    bundle = TransactionBundle.load(
        transaction_root,
        expected_tree_sha256=expected_transaction_tree,
        approved_activation_plan_digest=approved_plan_digest,
    )
    verify_inactive_install_receipt(
        INACTIVE_TRANSACTION_RECEIPT_ROOT
        / f"{approved_inactive_install_plan_digest}.json",
        bundle,
        approved_r4b_plan_digest=approved_inactive_install_plan_digest,
    )
    journal = FileJournal(
        STATE_ROOT,
        approved_plan_digest,
        expected_transaction_tree,
    )
    return JournaledR4CExecutor(
        bundle=bundle,
        journal=journal,
        backend=SystemdFilesystemBackend(),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Journaled Core Release Selector R4C executor"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("activate-live", "recover-live"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument(
            "--approved-executor-install-plan-digest",
        )
        subparser.add_argument(
            "--expected-executor-release-digest",
        )
        subparser.add_argument(
            "--expected-source-deploy-commit",
        )
        subparser.add_argument(
            "--approved-activation-plan-digest",
            required=True,
        )
        subparser.add_argument(
            "--approved-inactive-transaction-install-plan-digest",
            "--approved-inactive-install-plan-digest",
            dest="approved_inactive_transaction_install_plan_digest",
        )
        subparser.add_argument(
            "--expected-transaction-tree",
            required=True,
        )
        subparser.add_argument("--live-confirmation", required=True)
    arguments = parser.parse_args(argv)
    if os.geteuid() != 0:
        raise R4CExecutionError("must_run_as_root")
    if arguments.live_confirmation != LIVE_CONFIRMATION:
        raise R4CExecutionError("live_confirmation_rejected")
    if not all(
        isinstance(value, str) and value != ""
        for value in (
            arguments.approved_executor_install_plan_digest,
            arguments.expected_executor_release_digest,
            arguments.expected_source_deploy_commit,
            arguments.approved_inactive_transaction_install_plan_digest,
        )
    ):
        raise R4CExecutionError(
            "executor_installation_arguments_required"
        )
    executor = _executor(
        approved_executor_install_plan_digest=(
            arguments.approved_executor_install_plan_digest
        ),
        expected_executor_release_digest=(
            arguments.expected_executor_release_digest
        ),
        expected_source_deploy_commit=(
            arguments.expected_source_deploy_commit
        ),
        approved_plan_digest=arguments.approved_activation_plan_digest,
        expected_transaction_tree=arguments.expected_transaction_tree,
        approved_inactive_install_plan_digest=(
            arguments.approved_inactive_transaction_install_plan_digest
        ),
    )
    if arguments.command == "activate-live":
        result = executor.execute()
    else:
        result = executor.recover()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
