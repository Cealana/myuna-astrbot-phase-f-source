"""Content-addressed release and inactive-install contracts for R4C.

This module contains no systemd, process, network, or mutation API.  It builds
and validates one flat, immutable Python release and its non-sensitive
inactive-install receipt.
"""

from __future__ import annotations

from dataclasses import dataclass
import grp
from hashlib import sha256
from pathlib import Path
import re
import stat
from typing import Mapping

from core_release_selector import canonical_json_bytes, parse_json_document


RELEASE_MANIFEST_SCHEMA = (
    "myuna.core-release-selector.r4c-executor-release-manifest.v1"
)
INSTALL_RECEIPT_SCHEMA = (
    "myuna.core-release-selector.r4c-executor-inactive-installation-receipt.v1"
)
RELEASE_STATUS = "inactive_journaled_executor_release"
INSTALL_STATUS = "inactive_journaled_executor_installed"
MANIFEST_NAME = "EXECUTOR_MANIFEST.json"
ENTRYPOINT_NAME = "run_core_release_selector_r4c.py"
STATE_ROOT_TEXT = (
    "/var/lib/myuna-core-release-selector/r4c-activations"
)
RUNTIME_FILES = (
    "core_release_selector.py",
    "core_release_selector_r4c_executor.py",
    "core_release_selector_r4c_journal.py",
    "core_release_selector_r4c_live_backend.py",
    "core_release_selector_r4c_release.py",
    "core_release_selector_transaction.py",
    "core_release_selector_transaction_v2.py",
    ENTRYPOINT_NAME,
)

_HEX_40 = re.compile(r"^[a-f0-9]{40}$")
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")


class ExecutorReleaseError(RuntimeError):
    """A deterministic executor release or receipt rejection."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ExecutorReleaseError(code)


def _digest(value: str, code: str) -> str:
    require(
        isinstance(value, str) and _HEX_64.fullmatch(value) is not None,
        code,
    )
    return value


def _commit(value: str) -> str:
    require(
        isinstance(value, str) and _HEX_40.fullmatch(value) is not None,
        "source_deploy_commit_rejected",
    )
    return value


def _myuna_gid() -> int:
    try:
        return grp.getgrnam("myuna").gr_gid
    except KeyError as exc:
        raise ExecutorReleaseError("myuna_group_missing") from exc


def _canonical_document(payload: bytes, code: str) -> dict[str, object]:
    try:
        document = parse_json_document(payload)
    except Exception as exc:
        raise ExecutorReleaseError(code) from exc
    require(
        isinstance(document, dict)
        and canonical_json_bytes(document) == payload,
        code,
    )
    return document


@dataclass(frozen=True)
class ExecutorReleaseEvidence:
    executor_release_sha256: str
    source_deploy_commit: str
    activation_plan_digest: str
    transaction_tree_sha256: str
    inactive_transaction_install_plan_digest: str
    state_root: str
    entrypoint: str
    file_hashes: Mapping[str, str]


def _source_payloads(source_root: Path) -> dict[str, bytes]:
    require(
        isinstance(source_root, Path)
        and source_root.is_absolute()
        and source_root.is_dir()
        and not source_root.is_symlink(),
        "executor_source_root_rejected",
    )
    scripts = source_root / "scripts"
    require(
        scripts.is_dir() and not scripts.is_symlink(),
        "executor_source_scripts_rejected",
    )
    payloads: dict[str, bytes] = {}
    for name in RUNTIME_FILES:
        path = scripts / name
        require(
            path.is_file() and not path.is_symlink(),
            "executor_source_file_rejected",
        )
        payloads[name] = path.read_bytes()
    return payloads


def build_release_payloads(
    source_root: Path,
    *,
    source_deploy_commit: str,
    activation_plan_digest: str,
    transaction_tree_sha256: str,
    inactive_transaction_install_plan_digest: str,
) -> tuple[ExecutorReleaseEvidence, dict[str, bytes]]:
    commit = _commit(source_deploy_commit)
    activation = _digest(
        activation_plan_digest,
        "activation_plan_digest_rejected",
    )
    transaction = _digest(
        transaction_tree_sha256,
        "transaction_tree_sha256_rejected",
    )
    inactive_install = _digest(
        inactive_transaction_install_plan_digest,
        "inactive_transaction_install_plan_digest_rejected",
    )
    runtime_payloads = _source_payloads(source_root)
    file_hashes = {
        name: sha256(payload).hexdigest()
        for name, payload in sorted(runtime_payloads.items())
    }
    unsigned_manifest: dict[str, object] = {
        "schema": RELEASE_MANIFEST_SCHEMA,
        "status": RELEASE_STATUS,
        "source_deploy_commit": commit,
        "activation_plan_digest": activation,
        "transaction_tree_sha256": transaction,
        "inactive_transaction_install_plan_digest": inactive_install,
        "state_root": STATE_ROOT_TEXT,
        "entrypoint": ENTRYPOINT_NAME,
        "runtime_file_count": len(file_hashes),
        "runtime_files": file_hashes,
        "runtime_invoked": False,
        "systemd_changed": False,
        "service_lifecycle_performed": False,
        "selected_or_activated": False,
    }
    release_digest = sha256(
        canonical_json_bytes(unsigned_manifest)
    ).hexdigest()
    manifest = dict(unsigned_manifest)
    manifest["executor_release_sha256"] = release_digest
    payloads = dict(runtime_payloads)
    payloads[MANIFEST_NAME] = canonical_json_bytes(manifest)
    evidence = ExecutorReleaseEvidence(
        executor_release_sha256=release_digest,
        source_deploy_commit=commit,
        activation_plan_digest=activation,
        transaction_tree_sha256=transaction,
        inactive_transaction_install_plan_digest=inactive_install,
        state_root=STATE_ROOT_TEXT,
        entrypoint=ENTRYPOINT_NAME,
        file_hashes=file_hashes,
    )
    return evidence, payloads


def _manifest_evidence(
    manifest_payload: bytes,
    *,
    expected_release_digest: str,
    expected_source_deploy_commit: str,
    expected_activation_plan_digest: str,
    expected_transaction_tree_sha256: str,
    expected_inactive_transaction_install_plan_digest: str,
) -> ExecutorReleaseEvidence:
    expected_release = _digest(
        expected_release_digest,
        "expected_executor_release_digest_rejected",
    )
    commit = _commit(expected_source_deploy_commit)
    activation = _digest(
        expected_activation_plan_digest,
        "expected_activation_plan_digest_rejected",
    )
    transaction = _digest(
        expected_transaction_tree_sha256,
        "expected_transaction_tree_sha256_rejected",
    )
    inactive_install = _digest(
        expected_inactive_transaction_install_plan_digest,
        "expected_inactive_transaction_install_plan_digest_rejected",
    )
    manifest = _canonical_document(
        manifest_payload,
        "executor_manifest_rejected",
    )
    required = {
        "schema",
        "status",
        "source_deploy_commit",
        "activation_plan_digest",
        "transaction_tree_sha256",
        "inactive_transaction_install_plan_digest",
        "state_root",
        "entrypoint",
        "runtime_file_count",
        "runtime_files",
        "runtime_invoked",
        "systemd_changed",
        "service_lifecycle_performed",
        "selected_or_activated",
        "executor_release_sha256",
    }
    require(
        set(manifest) == required
        and manifest["schema"] == RELEASE_MANIFEST_SCHEMA
        and manifest["status"] == RELEASE_STATUS
        and manifest["source_deploy_commit"] == commit
        and manifest["activation_plan_digest"] == activation
        and manifest["transaction_tree_sha256"] == transaction
        and manifest["inactive_transaction_install_plan_digest"]
        == inactive_install
        and manifest["state_root"] == STATE_ROOT_TEXT
        and manifest["entrypoint"] == ENTRYPOINT_NAME
        and manifest["runtime_file_count"] == len(RUNTIME_FILES)
        and manifest["runtime_invoked"] is False
        and manifest["systemd_changed"] is False
        and manifest["service_lifecycle_performed"] is False
        and manifest["selected_or_activated"] is False
        and manifest["executor_release_sha256"] == expected_release,
        "executor_manifest_contract_rejected",
    )
    file_hashes = manifest["runtime_files"]
    require(
        isinstance(file_hashes, dict)
        and set(file_hashes) == set(RUNTIME_FILES)
        and all(
            isinstance(name, str)
            and isinstance(value, str)
            and _HEX_64.fullmatch(value) is not None
            for name, value in file_hashes.items()
        ),
        "executor_manifest_files_rejected",
    )
    unsigned = dict(manifest)
    unsigned.pop("executor_release_sha256")
    require(
        sha256(canonical_json_bytes(unsigned)).hexdigest()
        == expected_release,
        "executor_manifest_digest_rejected",
    )
    return ExecutorReleaseEvidence(
        executor_release_sha256=expected_release,
        source_deploy_commit=commit,
        activation_plan_digest=activation,
        transaction_tree_sha256=transaction,
        inactive_transaction_install_plan_digest=inactive_install,
        state_root=STATE_ROOT_TEXT,
        entrypoint=ENTRYPOINT_NAME,
        file_hashes=dict(file_hashes),
    )


def validate_installed_release(
    release_root: Path,
    *,
    expected_release_digest: str,
    expected_source_deploy_commit: str,
    expected_activation_plan_digest: str,
    expected_transaction_tree_sha256: str,
    expected_inactive_transaction_install_plan_digest: str,
    uid: int = 0,
    gid: int | None = None,
) -> ExecutorReleaseEvidence:
    if gid is None:
        gid = _myuna_gid()
    expected_release = _digest(
        expected_release_digest,
        "expected_executor_release_digest_rejected",
    )
    require(
        isinstance(release_root, Path)
        and release_root.is_absolute()
        and release_root.name == expected_release
        and release_root.is_dir()
        and not release_root.is_symlink(),
        "executor_release_root_rejected",
    )
    root_metadata = release_root.stat()
    require(
        root_metadata.st_uid == uid
        and root_metadata.st_gid == gid
        and stat.S_IMODE(root_metadata.st_mode) == 0o550,
        "executor_release_root_metadata_rejected",
    )
    entries = sorted(release_root.iterdir(), key=lambda item: item.name)
    require(
        [entry.name for entry in entries]
        == sorted((*RUNTIME_FILES, MANIFEST_NAME)),
        "executor_release_file_set_rejected",
    )
    observed: dict[str, bytes] = {}
    for entry in entries:
        require(
            entry.is_file() and not entry.is_symlink(),
            "executor_release_entry_rejected",
        )
        metadata = entry.stat()
        require(
            metadata.st_uid == uid
            and metadata.st_gid == gid
            and stat.S_IMODE(metadata.st_mode) == 0o440,
            "executor_release_entry_metadata_rejected",
        )
        observed[entry.name] = entry.read_bytes()
    evidence = _manifest_evidence(
        observed[MANIFEST_NAME],
        expected_release_digest=expected_release,
        expected_source_deploy_commit=expected_source_deploy_commit,
        expected_activation_plan_digest=expected_activation_plan_digest,
        expected_transaction_tree_sha256=expected_transaction_tree_sha256,
        expected_inactive_transaction_install_plan_digest=(
            expected_inactive_transaction_install_plan_digest
        ),
    )
    require(
        {
            name: sha256(observed[name]).hexdigest()
            for name in RUNTIME_FILES
        }
        == dict(evidence.file_hashes),
        "executor_release_content_rejected",
    )
    return evidence


def verify_state_contract(
    state_root: Path,
    *,
    uid: int = 0,
    gid: int = 0,
) -> None:
    require(
        isinstance(state_root, Path)
        and state_root.is_absolute()
        and state_root.is_dir()
        and not state_root.is_symlink(),
        "executor_state_root_rejected",
    )
    metadata = state_root.stat()
    require(
        metadata.st_uid == uid
        and metadata.st_gid == gid
        and stat.S_IMODE(metadata.st_mode) == 0o700,
        "executor_state_root_metadata_rejected",
    )


def build_install_receipt(
    evidence: ExecutorReleaseEvidence,
    *,
    approved_executor_install_plan_digest: str,
    executor_path: Path,
    state_root: Path,
) -> dict[str, object]:
    approval = _digest(
        approved_executor_install_plan_digest,
        "approved_executor_install_plan_digest_rejected",
    )
    require(
        isinstance(executor_path, Path)
        and executor_path.is_absolute()
        and isinstance(state_root, Path)
        and state_root.is_absolute(),
        "executor_install_paths_rejected",
    )
    return {
        "schema": INSTALL_RECEIPT_SCHEMA,
        "status": INSTALL_STATUS,
        "approved_executor_install_plan_digest": approval,
        "executor_release_sha256": evidence.executor_release_sha256,
        "executor_path": executor_path.as_posix(),
        "source_deploy_commit": evidence.source_deploy_commit,
        "activation_plan_digest": evidence.activation_plan_digest,
        "transaction_tree_sha256": evidence.transaction_tree_sha256,
        "inactive_transaction_install_plan_digest": (
            evidence.inactive_transaction_install_plan_digest
        ),
        "state_contract": {
            "path": state_root.as_posix(),
            "uid": 0,
            "gid": 0,
            "mode": "0700",
            "empty_at_install": True,
        },
        "runtime_invoked": False,
        "systemd_changed": False,
        "daemon_reload_performed": False,
        "service_lifecycle_performed": False,
        "selected_or_activated": False,
    }


def verify_install_receipt(
    receipt_path: Path,
    evidence: ExecutorReleaseEvidence,
    *,
    approved_executor_install_plan_digest: str,
    executor_path: Path,
    state_root: Path,
    uid: int = 0,
    gid: int | None = None,
) -> None:
    if gid is None:
        gid = _myuna_gid()
    require(
        receipt_path.is_file() and not receipt_path.is_symlink(),
        "executor_install_receipt_rejected",
    )
    metadata = receipt_path.stat()
    expected = build_install_receipt(
        evidence,
        approved_executor_install_plan_digest=(
            approved_executor_install_plan_digest
        ),
        executor_path=executor_path,
        state_root=state_root,
    )
    payload = receipt_path.read_bytes()
    require(
        metadata.st_uid == uid
        and metadata.st_gid == gid
        and stat.S_IMODE(metadata.st_mode) == 0o440
        and payload == canonical_json_bytes(expected),
        "executor_install_receipt_metadata_rejected",
    )
