#!/usr/bin/env python3
"""Inactive installer for a selected-to-selected Core upgrade transaction."""

from __future__ import annotations

import argparse
import grp
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import stat
from typing import Mapping, Sequence

from core_release_selector import canonical_json_bytes
from core_release_selector_transaction_v2 import transaction_tree_digest
from core_release_selector_upgrade import digest, validate_upgrade_bundle


TRANSACTION_ROOT = Path(
    "/opt/myuna/core-release-selector/selected-upgrade-transactions"
)
RECEIPT_ROOT = Path(
    "/opt/myuna/core-release-selector/selected-upgrade-transaction-installations"
)
EXPECTED_PATHS = frozenset(
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


class SelectedUpgradeTransactionInstallError(RuntimeError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise SelectedUpgradeTransactionInstallError(code)


def _hex_digest(value: str, code: str) -> str:
    require(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value),
        code,
    )
    return value


def _group_gid() -> int:
    try:
        return grp.getgrnam("myuna").gr_gid
    except KeyError as exc:
        raise SelectedUpgradeTransactionInstallError("myuna_group_missing") from exc


def _load_payloads(source: Path) -> dict[str, bytes]:
    require(
        source.is_absolute()
        and source.is_dir()
        and not source.is_symlink(),
        "transaction_source_rejected",
    )
    payloads: dict[str, bytes] = {}
    for entry in sorted(source.rglob("*")):
        require(not entry.is_symlink(), "transaction_source_entry_rejected")
        if entry.is_dir():
            continue
        require(entry.is_file(), "transaction_source_entry_rejected")
        relative = entry.relative_to(source).as_posix()
        payloads[relative] = entry.read_bytes()
    require(set(payloads) == EXPECTED_PATHS, "transaction_source_paths_rejected")
    validate_upgrade_bundle(payloads)
    return payloads


def _ensure_parent(path: Path, *, uid: int, gid: int) -> bool:
    if path.exists():
        require(path.is_dir() and not path.is_symlink(), "install_parent_rejected")
        metadata = path.stat()
        require(
            metadata.st_uid == uid
            and metadata.st_gid == gid
            and stat.S_IMODE(metadata.st_mode) == 0o750,
            "install_parent_metadata_rejected",
        )
        return False
    require(path.is_absolute() and path.parent.is_dir(), "install_parent_rejected")
    path.mkdir(mode=0o750)
    os.chown(path, uid, gid)
    path.chmod(0o750)
    return True


def _write_new(path: Path, payload: bytes, *, mode: int, uid: int, gid: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        mode,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            require(written > 0, "install_write_failed")
            view = view[written:]
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _verify_installed(
    root: Path,
    *,
    expected_tree: str,
    expected_activation_plan: str,
    uid: int,
    gid: int,
    require_content_addressed_name: bool = True,
) -> dict[str, bytes]:
    require(
        (not require_content_addressed_name or root.name == expected_tree)
        and root.is_dir()
        and not root.is_symlink(),
        "installed_transaction_root_rejected",
    )
    metadata = root.stat()
    require(
        metadata.st_uid == uid
        and metadata.st_gid == gid
        and stat.S_IMODE(metadata.st_mode) == 0o550,
        "installed_transaction_root_metadata_rejected",
    )
    payloads: dict[str, bytes] = {}
    for entry in sorted(root.rglob("*")):
        require(not entry.is_symlink(), "installed_transaction_entry_rejected")
        entry_metadata = entry.stat()
        if entry.is_dir():
            require(
                entry_metadata.st_uid == uid
                and entry_metadata.st_gid == gid
                and stat.S_IMODE(entry_metadata.st_mode) == 0o550,
                "installed_transaction_directory_metadata_rejected",
            )
            continue
        require(
            entry.is_file()
            and entry_metadata.st_uid == uid
            and entry_metadata.st_gid == gid
            and stat.S_IMODE(entry_metadata.st_mode) == 0o440,
            "installed_transaction_file_metadata_rejected",
        )
        payloads[entry.relative_to(root).as_posix()] = entry.read_bytes()
    validate_upgrade_bundle(payloads)
    require(
        transaction_tree_digest(payloads) == expected_tree
        and digest(payloads["activation/UPGRADE_PLAN.json"])
        == expected_activation_plan,
        "installed_transaction_digest_rejected",
    )
    return payloads


def install_inactive_transaction(
    *,
    source: Path,
    approved_install_plan_digest: str,
    expected_tree_sha256: str,
    approved_activation_plan_digest: str,
    transaction_root: Path = TRANSACTION_ROOT,
    receipt_root: Path = RECEIPT_ROOT,
    uid: int = 0,
    gid: int | None = None,
) -> dict[str, object]:
    approval = _hex_digest(
        approved_install_plan_digest,
        "approved_install_plan_digest_rejected",
    )
    expected_tree = _hex_digest(
        expected_tree_sha256,
        "expected_transaction_tree_rejected",
    )
    activation = _hex_digest(
        approved_activation_plan_digest,
        "approved_activation_plan_digest_rejected",
    )
    if gid is None:
        gid = _group_gid()
    require(
        transaction_root.is_absolute()
        and receipt_root.is_absolute()
        and transaction_root != receipt_root,
        "install_roots_rejected",
    )
    payloads = _load_payloads(source)
    require(
        transaction_tree_digest(payloads) == expected_tree
        and digest(payloads["activation/UPGRADE_PLAN.json"]) == activation,
        "source_transaction_digest_rejected",
    )

    destination = transaction_root / expected_tree
    receipt_path = receipt_root / f"{approval}.json"
    receipt = {
        "schema": "myuna.core-release-selector.selected-upgrade-transaction-installation.v1",
        "status": "installed_inactive_not_activated",
        "approved_install_plan_digest": approval,
        "activation_plan_digest": activation,
        "transaction_tree_sha256": expected_tree,
        "transaction_path": destination.as_posix(),
        "transaction_file_count": len(payloads),
        "runtime_invoked": False,
        "systemd_changed": False,
        "service_lifecycle_performed": False,
        "selected_or_activated": False,
        "secret_values_read": False,
    }
    receipt_payload = canonical_json_bytes(receipt)
    transaction_parent_created = False
    receipt_parent_created = False
    staging: Path | None = None
    destination_created = False
    receipt_created = False
    try:
        transaction_parent_created = _ensure_parent(transaction_root, uid=uid, gid=gid)
        receipt_parent_created = _ensure_parent(receipt_root, uid=uid, gid=gid)
        if destination.exists():
            _verify_installed(
                destination,
                expected_tree=expected_tree,
                expected_activation_plan=activation,
                uid=uid,
                gid=gid,
            )
        else:
            staging = transaction_root / f".{expected_tree}.{os.getpid()}.tmp"
            require(not staging.exists(), "transaction_staging_exists")
            staging.mkdir(mode=0o550)
            os.chown(staging, uid, gid)
            for relative, payload in sorted(payloads.items()):
                target = staging / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                for parent in [target.parent, *target.parents]:
                    if parent == staging.parent:
                        break
                    if parent.exists() and parent != staging:
                        os.chown(parent, uid, gid)
                        parent.chmod(0o550)
                _write_new(target, payload, mode=0o440, uid=uid, gid=gid)
            staging.chmod(0o550)
            _verify_installed(
                staging,
                expected_tree=expected_tree,
                expected_activation_plan=activation,
                uid=uid,
                gid=gid,
                require_content_addressed_name=False,
            )
            os.rename(staging, destination)
            staging = None
            destination_created = True
            _fsync(transaction_root)
        if receipt_path.exists():
            require(
                receipt_path.is_file()
                and not receipt_path.is_symlink()
                and receipt_path.read_bytes() == receipt_payload,
                "install_receipt_conflict",
            )
        else:
            _write_new(receipt_path, receipt_payload, mode=0o440, uid=uid, gid=gid)
            receipt_created = True
            _fsync(receipt_root)
        _verify_installed(
            destination,
            expected_tree=expected_tree,
            expected_activation_plan=activation,
            uid=uid,
            gid=gid,
        )
    except Exception as exc:
        if staging is not None and staging.exists():
            shutil.rmtree(staging)
        if receipt_created and receipt_path.exists():
            receipt_path.unlink()
        if destination_created and destination.exists():
            shutil.rmtree(destination)
        for path, created in (
            (receipt_root, receipt_parent_created),
            (transaction_root, transaction_parent_created),
        ):
            if created and path.exists() and not any(path.iterdir()):
                path.rmdir()
        if isinstance(exc, SelectedUpgradeTransactionInstallError):
            raise
        raise SelectedUpgradeTransactionInstallError(
            "inactive_transaction_install_failed"
        ) from exc
    return receipt


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Install one selected Core upgrade transaction inactive")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--approved-install-plan-digest", required=True)
    parser.add_argument("--expected-transaction-tree", required=True)
    parser.add_argument("--approved-activation-plan-digest", required=True)
    arguments = parser.parse_args(argv)
    require(os.geteuid() == 0, "must_run_as_root")
    result = install_inactive_transaction(
        source=arguments.source,
        approved_install_plan_digest=arguments.approved_install_plan_digest,
        expected_tree_sha256=arguments.expected_transaction_tree,
        approved_activation_plan_digest=arguments.approved_activation_plan_digest,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
