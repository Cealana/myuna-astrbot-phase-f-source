"""Install the journaled R4C executor into inactive, immutable storage.

The production CLI has fixed roots.  It installs code, a non-sensitive
receipt, and an empty root-owned state-directory contract only.  It has no
systemd, process, network, Core-selection, or activation API.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
from typing import Sequence

from core_release_selector import canonical_json_bytes
from core_release_selector_r4c_release import (
    ExecutorReleaseError,
    build_install_receipt,
    build_release_payloads,
    validate_installed_release,
    verify_install_receipt,
    verify_state_contract,
)
import install_core_release_selector_transaction as transaction_installer


FORMAL_DEPLOY = Path("/srv/myuna/repos/deploy")
EXECUTOR_ROOT = Path("/opt/myuna/core-release-selector/executors")
RECEIPT_ROOT = Path(
    "/opt/myuna/core-release-selector/executor-installations"
)
STATE_ROOT = Path(
    "/var/lib/myuna-core-release-selector/r4c-activations"
)


class ExecutorInstallError(RuntimeError):
    """A deterministic inactive executor installation rejection."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ExecutorInstallError(code)


def _ensure_root_only_directory(path: Path) -> bool:
    if path.exists():
        require(
            path.is_dir() and not path.is_symlink(),
            "executor_state_directory_rejected",
        )
        metadata = path.stat()
        require(
            metadata.st_uid == 0
            and metadata.st_gid == 0
            and stat.S_IMODE(metadata.st_mode) == 0o700,
            "executor_state_directory_metadata_rejected",
        )
        return False
    require(
        path.is_absolute()
        and path.parent.is_dir()
        and not path.parent.is_symlink()
        and not path.is_symlink(),
        "executor_state_parent_rejected",
    )
    created = False
    try:
        path.mkdir(mode=0o700)
        created = True
        os.chown(path, 0, 0)
        path.chmod(0o700)
        verify_state_contract(path)
    except Exception:
        if (
            created
            and path.exists()
            and path.is_dir()
            and not path.is_symlink()
            and not any(path.iterdir())
        ):
            path.rmdir()
        raise
    return True


def _remove_empty(path: Path) -> None:
    if (
        path.exists()
        and not path.is_symlink()
        and path.is_dir()
        and not any(path.iterdir())
    ):
        path.rmdir()


def _snapshot_state_tree(
    state_root: Path,
) -> dict[str, tuple[str, int, int, int, str | None]]:
    """Capture a content-only state fingerprint without exposing contents."""
    snapshot: dict[
        str,
        tuple[str, int, int, int, str | None],
    ] = {}
    for path in sorted(
        state_root.rglob("*"),
        key=lambda entry: entry.relative_to(state_root).as_posix(),
    ):
        require(
            not path.is_symlink(),
            "executor_state_entry_rejected",
        )
        metadata = path.stat()
        relative = path.relative_to(state_root).as_posix()
        if path.is_dir():
            kind = "directory"
            content_sha256 = None
        elif path.is_file():
            kind = "file"
            content_sha256 = sha256(path.read_bytes()).hexdigest()
        else:
            raise ExecutorInstallError(
                "executor_state_entry_rejected"
            )
        snapshot[relative] = (
            kind,
            metadata.st_uid,
            metadata.st_gid,
            stat.S_IMODE(metadata.st_mode),
            content_sha256,
        )
    return snapshot


def _verify_formal_deploy(expected_commit: str) -> None:
    commands = (
        ("rev-parse", "HEAD"),
        ("status", "--porcelain"),
    )
    outputs: list[str] = []
    for arguments in commands:
        result = subprocess.run(
            [
                "/usr/sbin/runuser",
                "-u",
                "myuna",
                "--",
                "/usr/bin/git",
                "-C",
                FORMAL_DEPLOY.as_posix(),
                *arguments,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
            shell=False,
        )
        require(
            result.returncode == 0,
            "formal_deploy_verification_failed",
        )
        outputs.append(result.stdout.strip())
    require(
        outputs[0] == expected_commit and outputs[1] == "",
        "formal_deploy_prestate_rejected",
    )


def install_inactive_executor(
    approved_executor_install_plan_digest: str,
    *,
    source_root: Path,
    source_deploy_commit: str,
    activation_plan_digest: str,
    transaction_tree_sha256: str,
    inactive_transaction_install_plan_digest: str,
    expected_executor_release_digest: str,
    executor_root: Path = EXECUTOR_ROOT,
    receipt_root: Path = RECEIPT_ROOT,
    state_root: Path = STATE_ROOT,
    uid: int = 0,
    gid: int | None = None,
) -> dict[str, object]:
    try:
        approval = transaction_installer._digest(
            approved_executor_install_plan_digest,
            "approved_executor_install_plan_digest_rejected",
        )
        expected_release = transaction_installer._digest(
            expected_executor_release_digest,
            "expected_executor_release_digest_rejected",
        )
        if gid is None:
            gid = transaction_installer._group_gid()
        evidence, payloads = build_release_payloads(
            source_root,
            source_deploy_commit=source_deploy_commit,
            activation_plan_digest=activation_plan_digest,
            transaction_tree_sha256=transaction_tree_sha256,
            inactive_transaction_install_plan_digest=(
                inactive_transaction_install_plan_digest
            ),
        )
    except (
        transaction_installer.TransactionInstallError,
        ExecutorReleaseError,
    ) as exc:
        raise ExecutorInstallError("executor_contract_rejected") from exc
    require(
        evidence.executor_release_sha256 == expected_release,
        "executor_release_digest_rejected",
    )
    require(
        executor_root.is_absolute()
        and receipt_root.is_absolute()
        and state_root.is_absolute()
        and len({executor_root, receipt_root, state_root}) == 3
        and state_root.name == "r4c-activations",
        "executor_install_roots_rejected",
    )

    destination = executor_root / expected_release
    receipt_path = receipt_root / f"{approval}.json"
    receipt_document = build_install_receipt(
        evidence,
        approved_executor_install_plan_digest=approval,
        executor_path=destination,
        state_root=state_root,
    )
    receipt_payload = canonical_json_bytes(receipt_document)

    state_parent_created = False
    state_root_created = False
    executor_root_created = False
    receipt_root_created = False
    destination_existed = destination.exists()
    receipt_existed = receipt_path.exists()
    try:
        state_parent_created = _ensure_root_only_directory(
            state_root.parent
        )
        state_root_created = _ensure_root_only_directory(state_root)
        verify_state_contract(state_root)
        state_snapshot_before = _snapshot_state_tree(state_root)

        transaction_installer._ensure_parent(
            executor_root.parent,
            uid=uid,
            gid=gid,
        )
        executor_root_created = not executor_root.exists()
        transaction_installer._ensure_parent(
            executor_root,
            uid=uid,
            gid=gid,
        )
        receipt_root_created = not receipt_root.exists()
        transaction_installer._ensure_parent(
            receipt_root,
            uid=uid,
            gid=gid,
        )

        release_created = transaction_installer._install_tree(
            destination,
            payloads,
            uid=uid,
            gid=gid,
        )
        receipt_created = transaction_installer._install_receipt(
            receipt_path,
            receipt_payload,
            uid=uid,
            gid=gid,
        )
        validated = validate_installed_release(
            destination,
            expected_release_digest=expected_release,
            expected_source_deploy_commit=source_deploy_commit,
            expected_activation_plan_digest=activation_plan_digest,
            expected_transaction_tree_sha256=transaction_tree_sha256,
            expected_inactive_transaction_install_plan_digest=(
                inactive_transaction_install_plan_digest
            ),
            uid=uid,
            gid=gid,
        )
        verify_install_receipt(
            receipt_path,
            validated,
            approved_executor_install_plan_digest=approval,
            executor_path=destination,
            state_root=state_root,
            uid=uid,
            gid=gid,
        )
        verify_state_contract(state_root)
        require(
            _snapshot_state_tree(state_root) == state_snapshot_before,
            "executor_state_changed_during_install",
        )
    except Exception as exc:
        if (
            not receipt_existed
            and receipt_path.exists()
            and receipt_path.is_file()
            and not receipt_path.is_symlink()
        ):
            receipt_path.unlink()
        if (
            not destination_existed
            and destination.exists()
            and destination.is_dir()
            and not destination.is_symlink()
        ):
            shutil.rmtree(destination)
        if receipt_root_created:
            _remove_empty(receipt_root)
        if executor_root_created:
            _remove_empty(executor_root)
        if state_root_created:
            _remove_empty(state_root)
        if state_parent_created:
            _remove_empty(state_root.parent)
        if isinstance(exc, ExecutorInstallError):
            raise
        raise ExecutorInstallError("inactive_executor_install_failed") from exc

    return {
        "status": receipt_document["status"],
        "approved_executor_install_plan_digest": approval,
        "executor_release_sha256": expected_release,
        "executor_destination": destination.as_posix(),
        "receipt_path": receipt_path.as_posix(),
        "state_root": state_root.as_posix(),
        "source_deploy_commit": source_deploy_commit,
        "activation_plan_digest": activation_plan_digest,
        "transaction_tree_sha256": transaction_tree_sha256,
        "inactive_transaction_install_plan_digest": (
            inactive_transaction_install_plan_digest
        ),
        "release_created": release_created,
        "receipt_created": receipt_created,
        "state_contract_created": (
            state_parent_created or state_root_created
        ),
        "preexisting_state_entry_count": len(state_snapshot_before),
        "preexisting_state_preserved": True,
        "runtime_invoked": False,
        "systemd_changed": False,
        "daemon_reload_performed": False,
        "service_lifecycle_performed": False,
        "selected_or_activated": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Install the journaled R4C executor inactive"
    )
    parser.add_argument(
        "--approved-executor-install-plan-digest",
        required=True,
    )
    parser.add_argument(
        "--expected-executor-release-digest",
        required=True,
    )
    parser.add_argument(
        "--expected-source-deploy-commit",
        required=True,
    )
    parser.add_argument(
        "--approved-activation-plan-digest",
        required=True,
    )
    parser.add_argument(
        "--expected-transaction-tree",
        required=True,
    )
    parser.add_argument(
        "--approved-inactive-transaction-install-plan-digest",
        required=True,
    )
    arguments = parser.parse_args(argv)
    if pwd.getpwuid(os.geteuid()).pw_name != "root":
        raise ExecutorInstallError("must_run_as_root")
    _verify_formal_deploy(arguments.expected_source_deploy_commit)
    result = install_inactive_executor(
        arguments.approved_executor_install_plan_digest,
        source_root=FORMAL_DEPLOY,
        source_deploy_commit=arguments.expected_source_deploy_commit,
        activation_plan_digest=arguments.approved_activation_plan_digest,
        transaction_tree_sha256=arguments.expected_transaction_tree,
        inactive_transaction_install_plan_digest=(
            arguments.approved_inactive_transaction_install_plan_digest
        ),
        expected_executor_release_digest=(
            arguments.expected_executor_release_digest
        ),
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
