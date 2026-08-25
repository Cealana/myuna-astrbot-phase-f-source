"""Install one verified socket-aware transaction into inactive storage.

The v2 installer intentionally reuses the reviewed atomic file primitives from
the v1 inactive installer.  Its only behavioral difference is validating the
socket-aware v2 transaction schema and emitting a v2 inactive receipt.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import pwd
from typing import Sequence

from core_release_selector import canonical_json_bytes
from core_release_selector_transaction_v2 import (
    TransactionContractError,
    validate_transaction_payloads,
)
import install_core_release_selector_transaction as v1_installer


TRANSACTION_ROOT = Path("/opt/myuna/core-release-selector/transactions")
RECEIPT_ROOT = Path(
    "/opt/myuna/core-release-selector/transaction-installations"
)
RECEIPT_SCHEMA = (
    "myuna.core-release-selector.r4b-inactive-installation-receipt.v2"
)
RECEIPT_STATUS = "inactive_socket_aware_transaction_installed"


class TransactionInstallError(RuntimeError):
    """A deterministic v2 inactive installation rejection."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise TransactionInstallError(code)


def install_inactive_transaction(
    approved_r4b_plan_digest: str,
    *,
    source_root: Path,
    expected_transaction_digest: str,
    transaction_root: Path = TRANSACTION_ROOT,
    receipt_root: Path = RECEIPT_ROOT,
    uid: int = 0,
    gid: int | None = None,
) -> dict[str, object]:
    try:
        approval = v1_installer._digest(
            approved_r4b_plan_digest, "approved_r4b_plan_digest_rejected"
        )
        expected = v1_installer._digest(
            expected_transaction_digest,
            "expected_transaction_digest_rejected",
        )
        if gid is None:
            gid = v1_installer._group_gid()
        payloads = v1_installer._safe_source_payloads(source_root)
        evidence = validate_transaction_payloads(payloads)
    except (
        v1_installer.TransactionInstallError,
        TransactionContractError,
    ) as exc:
        raise TransactionInstallError("transaction_contract_rejected") from exc
    require(
        evidence.transaction_tree_sha256 == expected,
        "transaction_tree_digest_rejected",
    )
    require(
        transaction_root.is_absolute()
        and receipt_root.is_absolute()
        and transaction_root != receipt_root,
        "transaction_install_roots_rejected",
    )
    try:
        v1_installer._ensure_parent(
            transaction_root.parent, uid=uid, gid=gid
        )
        v1_installer._ensure_parent(transaction_root, uid=uid, gid=gid)
        v1_installer._ensure_parent(receipt_root, uid=uid, gid=gid)
    except v1_installer.TransactionInstallError as exc:
        raise TransactionInstallError("transaction_parent_rejected") from exc
    destination = transaction_root / expected
    receipt_path = receipt_root / f"{approval}.json"
    receipt_payload = canonical_json_bytes(
        {
            "schema": RECEIPT_SCHEMA,
            "status": RECEIPT_STATUS,
            "approved_r4b_plan_digest": approval,
            "transaction_tree_sha256": expected,
            "transaction_path": destination.as_posix(),
            "activation_plan_digest": evidence.activation_plan_digest,
            "runtime_binding_sha256": evidence.runtime_binding_sha256,
            "artifact_count": evidence.artifact_count,
            "gateway_socket_in_contract": True,
            "runtime_paths_written": False,
            "systemd_changed": False,
            "daemon_reload_performed": False,
            "service_lifecycle_performed": False,
            "selected_or_activated": False,
        }
    )
    tree_created = False
    receipt_created = False
    try:
        tree_created = v1_installer._install_tree(
            destination, payloads, uid=uid, gid=gid
        )
        receipt_created = v1_installer._install_receipt(
            receipt_path, receipt_payload, uid=uid, gid=gid
        )
    except Exception as exc:
        if (
            receipt_created
            and receipt_path.is_file()
            and not receipt_path.is_symlink()
        ):
            receipt_path.unlink()
        if (
            tree_created
            and destination.is_dir()
            and not destination.is_symlink()
        ):
            import shutil

            shutil.rmtree(destination)
        raise TransactionInstallError("inactive_install_failed") from exc
    return {
        "status": RECEIPT_STATUS,
        "approved_r4b_plan_digest": approval,
        "transaction_tree_sha256": expected,
        "transaction_destination": destination.as_posix(),
        "receipt_path": receipt_path.as_posix(),
        "activation_plan_digest": evidence.activation_plan_digest,
        "artifact_count": evidence.artifact_count,
        "transaction_created": tree_created,
        "receipt_created": receipt_created,
        "gateway_socket_in_contract": True,
        "runtime_changed": False,
        "systemd_changed": False,
        "daemon_reload_performed": False,
        "service_lifecycle_performed": False,
        "selected_or_activated": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Install an inactive socket-aware Core Selector transaction"
    )
    parser.add_argument("--approved-r4b-plan-digest", required=True)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--expected-transaction-digest", required=True)
    arguments = parser.parse_args(argv)
    if pwd.getpwuid(os.geteuid()).pw_name != "root":
        raise TransactionInstallError("must_run_as_root")
    result = install_inactive_transaction(
        arguments.approved_r4b_plan_digest,
        source_root=arguments.source_root,
        expected_transaction_digest=arguments.expected_transaction_digest,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
