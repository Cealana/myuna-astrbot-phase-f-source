"""Install one verified Core Selector transaction into inactive storage.

The production CLI writes only a content-addressed transaction directory and a
non-sensitive installation receipt below ``/opt/myuna/core-release-selector``.
It has no process, network, service-manager, runtime binding, or active drop-in
API.
"""

from __future__ import annotations

import argparse
import grp
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
from typing import Mapping, Sequence

from core_release_selector import canonical_json_bytes
from core_release_selector_transaction import (
    TransactionContractError,
    validate_transaction_payloads,
)


TRANSACTION_ROOT = Path("/opt/myuna/core-release-selector/transactions")
RECEIPT_ROOT = Path(
    "/opt/myuna/core-release-selector/transaction-installations"
)
RECEIPT_SCHEMA = (
    "myuna.core-release-selector.r4b-inactive-installation-receipt.v1"
)
RECEIPT_STATUS = "inactive_transaction_installed"
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")


class TransactionInstallError(RuntimeError):
    """A deterministic inactive transaction installation rejection."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise TransactionInstallError(code)


def _digest(value: str, code: str) -> str:
    require(
        isinstance(value, str) and _HEX_64.fullmatch(value) is not None,
        code,
    )
    return value


def _group_gid() -> int:
    try:
        return grp.getgrnam("myuna").gr_gid
    except KeyError as exc:
        raise TransactionInstallError("myuna_group_missing") from exc


def _safe_source_payloads(source_root: Path) -> dict[str, bytes]:
    require(
        isinstance(source_root, Path)
        and source_root.is_absolute()
        and not source_root.is_symlink()
        and source_root.is_dir(),
        "transaction_source_rejected",
    )
    payloads: dict[str, bytes] = {}
    for entry in sorted(
        source_root.rglob("*"),
        key=lambda item: item.relative_to(source_root).as_posix(),
    ):
        require(not entry.is_symlink(), "transaction_source_symlink_rejected")
        if entry.is_dir():
            continue
        require(entry.is_file(), "transaction_source_entry_rejected")
        relative = entry.relative_to(source_root).as_posix()
        payloads[relative] = entry.read_bytes()
    require(payloads, "transaction_source_empty")
    return payloads


def _ensure_parent(path: Path, *, uid: int, gid: int) -> None:
    if path.exists():
        require(
            not path.is_symlink() and path.is_dir(),
            "transaction_parent_rejected",
        )
    else:
        require(
            path.parent.is_dir() and not path.parent.is_symlink(),
            "transaction_parent_missing",
        )
        path.mkdir(mode=0o750)
        os.chown(path, uid, gid)
    metadata = path.stat()
    require(
        metadata.st_uid == uid
        and metadata.st_gid == gid
        and stat.S_IMODE(metadata.st_mode) == 0o750,
        "transaction_parent_metadata_rejected",
    )


def _verify_tree(
    destination: Path,
    payloads: Mapping[str, bytes],
    *,
    uid: int,
    gid: int,
) -> None:
    require(
        not destination.is_symlink() and destination.is_dir(),
        "transaction_destination_rejected",
    )
    root_metadata = destination.stat()
    require(
        root_metadata.st_uid == uid
        and root_metadata.st_gid == gid
        and stat.S_IMODE(root_metadata.st_mode) == 0o550,
        "transaction_destination_metadata_rejected",
    )
    observed_files: dict[str, bytes] = {}
    for entry in sorted(
        destination.rglob("*"),
        key=lambda item: item.relative_to(destination).as_posix(),
    ):
        require(not entry.is_symlink(), "transaction_installed_symlink_rejected")
        metadata = entry.stat()
        require(
            metadata.st_uid == uid and metadata.st_gid == gid,
            "transaction_installed_owner_rejected",
        )
        if entry.is_dir():
            require(
                stat.S_IMODE(metadata.st_mode) == 0o550,
                "transaction_installed_directory_mode_rejected",
            )
            continue
        require(
            entry.is_file() and stat.S_IMODE(metadata.st_mode) == 0o440,
            "transaction_installed_file_rejected",
        )
        observed_files[entry.relative_to(destination).as_posix()] = (
            entry.read_bytes()
        )
    require(
        observed_files == dict(payloads),
        "transaction_installed_content_rejected",
    )


def _install_tree(
    destination: Path,
    payloads: Mapping[str, bytes],
    *,
    uid: int,
    gid: int,
) -> bool:
    if destination.exists():
        _verify_tree(destination, payloads, uid=uid, gid=gid)
        return False
    require(
        not destination.is_symlink(),
        "transaction_destination_symlink_rejected",
    )
    temporary = destination.parent / f".{destination.name}.{os.getpid()}.tmp"
    require(
        not temporary.exists() and not temporary.is_symlink(),
        "transaction_temporary_exists",
    )
    try:
        temporary.mkdir(mode=0o700)
        for relative, payload in sorted(payloads.items()):
            target = temporary / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            os.chown(target, uid, gid)
            target.chmod(0o440)
        directories = sorted(
            (entry for entry in temporary.rglob("*") if entry.is_dir()),
            key=lambda item: len(item.parts),
            reverse=True,
        )
        for directory in directories:
            os.chown(directory, uid, gid)
            directory.chmod(0o550)
        os.chown(temporary, uid, gid)
        temporary.chmod(0o550)
        os.replace(temporary, destination)
    except Exception:
        if temporary.exists() and not temporary.is_symlink():
            shutil.rmtree(temporary)
        raise
    _verify_tree(destination, payloads, uid=uid, gid=gid)
    return True


def _verify_receipt(
    path: Path, payload: bytes, *, uid: int, gid: int
) -> None:
    require(
        not path.is_symlink() and path.is_file(),
        "transaction_receipt_rejected",
    )
    metadata = path.stat()
    require(
        metadata.st_uid == uid
        and metadata.st_gid == gid
        and stat.S_IMODE(metadata.st_mode) == 0o440
        and path.read_bytes() == payload,
        "transaction_receipt_metadata_rejected",
    )


def _install_receipt(
    path: Path, payload: bytes, *, uid: int, gid: int
) -> bool:
    if path.exists():
        _verify_receipt(path, payload, uid=uid, gid=gid)
        return False
    require(not path.is_symlink(), "transaction_receipt_symlink_rejected")
    temporary = path.parent / f".{path.name}.{os.getpid()}.tmp"
    require(
        not temporary.exists() and not temporary.is_symlink(),
        "transaction_receipt_temporary_exists",
    )
    try:
        temporary.write_bytes(payload)
        os.chown(temporary, uid, gid)
        temporary.chmod(0o440)
        os.replace(temporary, path)
    except Exception:
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()
        raise
    _verify_receipt(path, payload, uid=uid, gid=gid)
    return True


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
    approval = _digest(
        approved_r4b_plan_digest, "approved_r4b_plan_digest_rejected"
    )
    expected = _digest(
        expected_transaction_digest, "expected_transaction_digest_rejected"
    )
    if gid is None:
        gid = _group_gid()
    payloads = _safe_source_payloads(source_root)
    try:
        evidence = validate_transaction_payloads(payloads)
    except TransactionContractError as exc:
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
    _ensure_parent(transaction_root.parent, uid=uid, gid=gid)
    _ensure_parent(transaction_root, uid=uid, gid=gid)
    _ensure_parent(receipt_root, uid=uid, gid=gid)
    destination = transaction_root / expected
    receipt_path = receipt_root / f"{approval}.json"
    receipt_document = {
        "schema": RECEIPT_SCHEMA,
        "status": RECEIPT_STATUS,
        "approved_r4b_plan_digest": approval,
        "transaction_tree_sha256": expected,
        "transaction_path": destination.as_posix(),
        "activation_plan_digest": evidence.activation_plan_digest,
        "runtime_binding_sha256": evidence.runtime_binding_sha256,
        "artifact_count": evidence.artifact_count,
        "runtime_paths_written": False,
        "systemd_changed": False,
        "daemon_reload_performed": False,
        "service_lifecycle_performed": False,
        "selected_or_activated": False,
    }
    receipt_payload = canonical_json_bytes(receipt_document)
    tree_created = False
    receipt_created = False
    try:
        tree_created = _install_tree(
            destination, payloads, uid=uid, gid=gid
        )
        receipt_created = _install_receipt(
            receipt_path, receipt_payload, uid=uid, gid=gid
        )
    except Exception:
        if receipt_created and receipt_path.is_file() and not receipt_path.is_symlink():
            receipt_path.unlink()
        if tree_created and destination.is_dir() and not destination.is_symlink():
            shutil.rmtree(destination)
        raise
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
        "runtime_changed": False,
        "systemd_changed": False,
        "daemon_reload_performed": False,
        "service_lifecycle_performed": False,
        "selected_or_activated": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Install an inactive Core Selector R4 transaction"
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
