"""Content-addressed Executor release contract for selected Core upgrades."""

from __future__ import annotations

import grp
from hashlib import sha256
import json
from pathlib import Path
import stat
from typing import Mapping


MANIFEST_NAME = "EXECUTOR_MANIFEST.json"
ENTRYPOINT_NAME = "run_core_release_selector_upgrade.py"
EXECUTOR_FILES = frozenset(
    {
        ENTRYPOINT_NAME,
        "core_release_selector.py",
        "core_release_selector_upgrade.py",
        "core_release_selector_upgrade_executor.py",
        "core_release_selector_upgrade_journal.py",
        "core_release_selector_upgrade_live_backend.py",
        "core_release_selector_upgrade_recovery.py",
        "core_release_selector_upgrade_controller.py",
        "core_release_selector_upgrade_release.py",
    }
)


class UpgradeReleaseError(RuntimeError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise UpgradeReleaseError(code)


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _hex(value: str, code: str) -> str:
    require(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value),
        code,
    )
    return value


def build_manifest(
    artifacts: Mapping[str, bytes],
    *,
    source_deploy_commit: str,
    activation_plan_digest: str,
    transaction_tree_sha256: str,
    inactive_transaction_install_plan_digest: str,
) -> dict[str, object]:
    require(set(artifacts) == EXECUTOR_FILES, "executor_artifact_paths_rejected")
    require(
        isinstance(source_deploy_commit, str)
        and len(source_deploy_commit) == 40
        and all(character in "0123456789abcdef" for character in source_deploy_commit),
        "source_deploy_commit_rejected",
    )
    artifact_hashes = {
        path: sha256(payload).hexdigest() for path, payload in sorted(artifacts.items())
    }
    unsigned = {
        "schema": "myuna.core-release-selector.selected-upgrade-executor-release.v1",
        "source_deploy_commit": source_deploy_commit,
        "activation_plan_digest": _hex(activation_plan_digest, "activation_digest_rejected"),
        "transaction_tree_sha256": _hex(transaction_tree_sha256, "transaction_tree_rejected"),
        "inactive_transaction_install_plan_digest": _hex(
            inactive_transaction_install_plan_digest,
            "inactive_install_digest_rejected",
        ),
        "entrypoint": ENTRYPOINT_NAME,
        "artifacts": artifact_hashes,
        "artifact_count": len(artifact_hashes),
    }
    return {
        **unsigned,
        "release_digest": sha256(canonical_bytes(unsigned)).hexdigest(),
    }


def validate_manifest(
    manifest: Mapping[str, object],
    artifacts: Mapping[str, bytes],
    *,
    expected_release_digest: str,
    expected_source_deploy_commit: str,
    expected_activation_plan_digest: str,
    expected_transaction_tree_sha256: str,
    expected_inactive_install_plan_digest: str,
) -> dict[str, object]:
    rebuilt = build_manifest(
        artifacts,
        source_deploy_commit=expected_source_deploy_commit,
        activation_plan_digest=expected_activation_plan_digest,
        transaction_tree_sha256=expected_transaction_tree_sha256,
        inactive_transaction_install_plan_digest=expected_inactive_install_plan_digest,
    )
    require(dict(manifest) == rebuilt, "executor_manifest_rejected")
    require(
        rebuilt["release_digest"] == _hex(expected_release_digest, "release_digest_rejected"),
        "executor_release_digest_rejected",
    )
    return rebuilt


def validate_installed_release(
    root: Path,
    *,
    expected_release_digest: str,
    expected_source_deploy_commit: str,
    expected_activation_plan_digest: str,
    expected_transaction_tree_sha256: str,
    expected_inactive_install_plan_digest: str,
    require_installed_metadata: bool = True,
) -> dict[str, object]:
    require(
        root.is_absolute()
        and root.name == expected_release_digest
        and root.is_dir()
        and not root.is_symlink(),
        "executor_release_root_rejected",
    )
    try:
        manifest = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise UpgradeReleaseError("executor_manifest_read_rejected") from None
    require(isinstance(manifest, dict), "executor_manifest_shape_rejected")
    artifacts: dict[str, bytes] = {}
    observed: set[str] = set()
    for entry in sorted(root.iterdir()):
        require(entry.is_file() and not entry.is_symlink(), "executor_release_entry_rejected")
        observed.add(entry.name)
        if entry.name != MANIFEST_NAME:
            artifacts[entry.name] = entry.read_bytes()
    require(observed == EXECUTOR_FILES | {MANIFEST_NAME}, "executor_release_paths_rejected")
    evidence = validate_manifest(
        manifest,
        artifacts,
        expected_release_digest=expected_release_digest,
        expected_source_deploy_commit=expected_source_deploy_commit,
        expected_activation_plan_digest=expected_activation_plan_digest,
        expected_transaction_tree_sha256=expected_transaction_tree_sha256,
        expected_inactive_install_plan_digest=expected_inactive_install_plan_digest,
    )
    if require_installed_metadata:
        try:
            gid = grp.getgrnam("myuna").gr_gid
        except KeyError as exc:
            raise UpgradeReleaseError("myuna_group_missing") from exc
        root_info = root.stat()
        require(
            root_info.st_uid == 0
            and root_info.st_gid == gid
            and stat.S_IMODE(root_info.st_mode) == 0o550,
            "executor_release_root_metadata_rejected",
        )
        for entry in root.iterdir():
            info = entry.stat()
            require(
                info.st_uid == 0
                and info.st_gid == gid
                and stat.S_IMODE(info.st_mode) == 0o440,
                "executor_release_file_metadata_rejected",
            )
    return evidence

