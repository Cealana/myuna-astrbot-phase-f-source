#!/usr/bin/env python3
"""Install a selected-upgrade Executor release without executing it."""

from __future__ import annotations

import argparse
import grp
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import stat
from typing import Sequence

from core_release_selector_upgrade_release import (
    MANIFEST_NAME,
    UpgradeReleaseError,
    canonical_bytes,
    validate_installed_release,
)


EXECUTOR_ROOT = Path("/opt/myuna/core-release-selector/selected-upgrade-executors")
RECEIPT_ROOT = Path(
    "/opt/myuna/core-release-selector/selected-upgrade-executor-installations"
)
STATE_ROOT = Path(
    "/var/lib/myuna-core-release-selector/selected-upgrade-activations"
)


class SelectedUpgradeExecutorInstallError(RuntimeError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise SelectedUpgradeExecutorInstallError(code)


def hex_digest(value: str, code: str) -> str:
    require(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value),
        code,
    )
    return value


def myuna_gid() -> int:
    try:
        return grp.getgrnam("myuna").gr_gid
    except KeyError as exc:
        raise SelectedUpgradeExecutorInstallError("myuna_group_missing") from exc


def ensure_parent(path: Path, *, uid: int, gid: int, mode: int) -> bool:
    if path.exists():
        require(path.is_dir() and not path.is_symlink(), "install_parent_rejected")
        metadata = path.stat()
        require(
            metadata.st_uid == uid
            and metadata.st_gid == gid
            and stat.S_IMODE(metadata.st_mode) == mode,
            "install_parent_metadata_rejected",
        )
        return False
    require(path.is_absolute() and path.parent.is_dir(), "install_parent_rejected")
    path.mkdir(mode=mode)
    os.chown(path, uid, gid)
    path.chmod(mode)
    return True


def remove_empty(path: Path) -> None:
    if (
        path.exists()
        and path.is_dir()
        and not path.is_symlink()
        and not any(path.iterdir())
    ):
        path.rmdir()


def state_snapshot(root: Path) -> dict[str, tuple[object, ...]]:
    snapshot: dict[str, tuple[object, ...]] = {}
    for entry in sorted(root.rglob("*")):
        require(not entry.is_symlink(), "activation_state_symlink_rejected")
        metadata = entry.stat()
        relative = entry.relative_to(root).as_posix()
        if entry.is_dir():
            snapshot[relative] = (
                "directory", metadata.st_uid, metadata.st_gid,
                stat.S_IMODE(metadata.st_mode), None,
            )
        elif entry.is_file():
            snapshot[relative] = (
                "file", metadata.st_uid, metadata.st_gid,
                stat.S_IMODE(metadata.st_mode),
                sha256(entry.read_bytes()).hexdigest(),
            )
        else:
            raise SelectedUpgradeExecutorInstallError(
                "activation_state_entry_rejected"
            )
    return snapshot


def write_new(path: Path, payload: bytes, *, mode: int, uid: int, gid: int) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, mode
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


def load_source(
    source: Path,
    *,
    expected_release_digest: str,
    expected_source_deploy_commit: str,
    expected_activation_plan_digest: str,
    expected_transaction_tree_sha256: str,
    expected_inactive_install_plan_digest: str,
) -> dict[str, bytes]:
    try:
        evidence = validate_installed_release(
            source,
            expected_release_digest=expected_release_digest,
            expected_source_deploy_commit=expected_source_deploy_commit,
            expected_activation_plan_digest=expected_activation_plan_digest,
            expected_transaction_tree_sha256=expected_transaction_tree_sha256,
            expected_inactive_install_plan_digest=(
                expected_inactive_install_plan_digest
            ),
            require_installed_metadata=False,
        )
        if (source / MANIFEST_NAME).read_bytes() != canonical_bytes(evidence):
            raise UpgradeReleaseError("source_manifest_not_canonical")
    except (OSError, UpgradeReleaseError) as exc:
        raise SelectedUpgradeExecutorInstallError("source_release_rejected") from exc
    return {entry.name: entry.read_bytes() for entry in sorted(source.iterdir())}


def verify_destination(
    destination: Path,
    *,
    expected_release_digest: str,
    expected_source_deploy_commit: str,
    expected_activation_plan_digest: str,
    expected_transaction_tree_sha256: str,
    expected_inactive_install_plan_digest: str,
) -> None:
    try:
        validate_installed_release(
            destination,
            expected_release_digest=expected_release_digest,
            expected_source_deploy_commit=expected_source_deploy_commit,
            expected_activation_plan_digest=expected_activation_plan_digest,
            expected_transaction_tree_sha256=expected_transaction_tree_sha256,
            expected_inactive_install_plan_digest=(
                expected_inactive_install_plan_digest
            ),
            require_installed_metadata=True,
        )
    except UpgradeReleaseError as exc:
        raise SelectedUpgradeExecutorInstallError("installed_release_rejected") from exc


def install_inactive_executor(
    *,
    source_release: Path,
    approved_install_plan_digest: str,
    expected_executor_release_digest: str,
    expected_source_deploy_commit: str,
    expected_activation_plan_digest: str,
    expected_transaction_tree_sha256: str,
    expected_inactive_transaction_install_plan_digest: str,
    executor_root: Path = EXECUTOR_ROOT,
    receipt_root: Path = RECEIPT_ROOT,
    state_root: Path = STATE_ROOT,
) -> dict[str, object]:
    approval = hex_digest(approved_install_plan_digest, "install_plan_digest_rejected")
    release_digest = hex_digest(
        expected_executor_release_digest, "executor_release_digest_rejected"
    )
    activation = hex_digest(
        expected_activation_plan_digest, "activation_plan_digest_rejected"
    )
    transaction = hex_digest(
        expected_transaction_tree_sha256, "transaction_tree_digest_rejected"
    )
    inactive_install = hex_digest(
        expected_inactive_transaction_install_plan_digest,
        "inactive_transaction_install_digest_rejected",
    )
    require(
        len(expected_source_deploy_commit) == 40
        and all(character in "0123456789abcdef" for character in expected_source_deploy_commit),
        "source_deploy_commit_rejected",
    )
    require(
        executor_root.is_absolute()
        and receipt_root.is_absolute()
        and state_root.is_absolute()
        and len({executor_root, receipt_root, state_root}) == 3,
        "install_roots_rejected",
    )
    payloads = load_source(
        source_release,
        expected_release_digest=release_digest,
        expected_source_deploy_commit=expected_source_deploy_commit,
        expected_activation_plan_digest=activation,
        expected_transaction_tree_sha256=transaction,
        expected_inactive_install_plan_digest=inactive_install,
    )
    gid = myuna_gid()
    destination = executor_root / release_digest
    receipt_path = receipt_root / f"{approval}.json"
    receipt = {
        "schema": "myuna.core-release-selector.selected-upgrade-executor-installation.v1",
        "status": "installed_inactive_not_executed",
        "approved_install_plan_digest": approval,
        "executor_release_digest": release_digest,
        "executor_path": destination.as_posix(),
        "source_deploy_commit": expected_source_deploy_commit,
        "activation_plan_digest": activation,
        "transaction_tree_sha256": transaction,
        "inactive_transaction_install_plan_digest": inactive_install,
        "runtime_invoked": False,
        "systemd_changed": False,
        "service_lifecycle_performed": False,
    }
    receipt_payload = canonical_bytes(receipt)

    executor_parent_created = False
    receipt_parent_created = False
    state_parent_created = False
    state_root_created = False
    destination_created = False
    receipt_created = False
    staging: Path | None = None
    try:
        executor_parent_created = ensure_parent(
            executor_root, uid=0, gid=gid, mode=0o750
        )
        receipt_parent_created = ensure_parent(
            receipt_root, uid=0, gid=gid, mode=0o750
        )
        state_parent_created = ensure_parent(
            state_root.parent, uid=0, gid=0, mode=0o700
        )
        state_root_created = ensure_parent(
            state_root, uid=0, gid=0, mode=0o700
        )
        existing_state = state_snapshot(state_root)
        require(
            not (state_root / activation).exists(),
            "activation_journal_already_exists",
        )

        if destination.exists():
            verify_destination(
                destination,
                expected_release_digest=release_digest,
                expected_source_deploy_commit=expected_source_deploy_commit,
                expected_activation_plan_digest=activation,
                expected_transaction_tree_sha256=transaction,
                expected_inactive_install_plan_digest=inactive_install,
            )
        else:
            staging = executor_root / f".{release_digest}.{os.getpid()}.tmp"
            require(not staging.exists(), "executor_staging_exists")
            staging.mkdir(mode=0o550)
            os.chown(staging, 0, gid)
            for name, payload in sorted(payloads.items()):
                write_new(staging / name, payload, mode=0o440, uid=0, gid=gid)
            staging.chmod(0o550)
            os.rename(staging, destination)
            destination_created = True
            verify_destination(
                destination,
                expected_release_digest=release_digest,
                expected_source_deploy_commit=expected_source_deploy_commit,
                expected_activation_plan_digest=activation,
                expected_transaction_tree_sha256=transaction,
                expected_inactive_install_plan_digest=inactive_install,
            )

        if receipt_path.exists():
            metadata = receipt_path.stat()
            require(
                receipt_path.is_file()
                and not receipt_path.is_symlink()
                and metadata.st_uid == 0
                and metadata.st_gid == gid
                and stat.S_IMODE(metadata.st_mode) == 0o440
                and receipt_path.read_bytes() == receipt_payload,
                "install_receipt_rejected",
            )
        else:
            write_new(receipt_path, receipt_payload, mode=0o440, uid=0, gid=gid)
            receipt_created = True
        require(
            state_snapshot(state_root) == existing_state,
            "activation_state_changed_during_install",
        )
    except Exception as exc:
        if receipt_created and receipt_path.exists():
            receipt_path.unlink()
        if destination_created and destination.exists():
            shutil.rmtree(destination)
        if staging is not None and staging.exists():
            shutil.rmtree(staging)
        if state_root_created:
            remove_empty(state_root)
        if state_parent_created:
            remove_empty(state_root.parent)
        if receipt_parent_created:
            remove_empty(receipt_root)
        if executor_parent_created:
            remove_empty(executor_root)
        if isinstance(exc, SelectedUpgradeExecutorInstallError):
            raise
        raise SelectedUpgradeExecutorInstallError("inactive_install_failed") from exc

    return {
        **receipt,
        "release_created": destination_created,
        "receipt_created": receipt_created,
        "state_contract_created": state_parent_created or state_root_created,
        "preexisting_state_entry_count": len(existing_state),
        "preexisting_state_preserved": True,
        "journal_created": False,
        "selected_or_activated": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-release", type=Path, required=True)
    parser.add_argument("--approved-install-plan-digest", required=True)
    parser.add_argument("--expected-executor-release-digest", required=True)
    parser.add_argument("--expected-source-deploy-commit", required=True)
    parser.add_argument("--expected-activation-plan-digest", required=True)
    parser.add_argument("--expected-transaction-tree", required=True)
    parser.add_argument("--expected-inactive-transaction-install-plan-digest", required=True)
    arguments = parser.parse_args(argv)
    require(os.geteuid() == 0, "must_run_as_root")
    result = install_inactive_executor(
        source_release=arguments.source_release,
        approved_install_plan_digest=arguments.approved_install_plan_digest,
        expected_executor_release_digest=arguments.expected_executor_release_digest,
        expected_source_deploy_commit=arguments.expected_source_deploy_commit,
        expected_activation_plan_digest=arguments.expected_activation_plan_digest,
        expected_transaction_tree_sha256=arguments.expected_transaction_tree,
        expected_inactive_transaction_install_plan_digest=(
            arguments.expected_inactive_transaction_install_plan_digest
        ),
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
