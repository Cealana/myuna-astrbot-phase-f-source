#!/usr/bin/env python3
"""Build the deterministic inactive P07 source-bound package runtime bundle."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

import p07_full_mutation_set_v1 as mutation
import p07_owner_private_memory_production_plan as production
import p07_owner_private_memory_runtime_artifact_v1 as runtime_artifact
import p07_owner_private_memory_transactional_controller as parent
import p07_owner_private_memory_transactional_runtime as runtime
import p07_transactional_plugin_artifact_v1 as plugin_artifact


SOURCE_FILES = (
    "docs/ADR-072-p07-owner-private-memory-production-plan-builder.md",
    "docs/ADR-074-p07-transactional-plugin-artifact-source-binding.md",
    "docs/ADR-075-p07-runtime-artifact-source-binding.md",
    "docs/ADR-076-p07-source-owned-transactional-request-constructor.md",
    "docs/ADR-078-p07-immutable-failed-request-continuation.md",
    "docs/ADR-079-p07-p08-content-free-status-stage-projection.md",
    "docs/ADR-080-p07-immutable-continuation-fresh-strategy.md",
    "docs/ADR-081-p07-historical-request-evidence-ownership.md",
    "docs/ADR-082-p07-source-owned-artifact-root-binding.md",
    "docs/ADR-083-p07-context-bound-rejection-envelope.md",
    "docs/ADR-084-p07-p08-server-rejection-integration.md",
    "docs/ADR-085-p07-p08-current-selected-reconciliation.md",
    "docs/ADR-087-p07-p08-single-nonce-stage-integration.md",
    "scripts/build_p07_hybrid_live_releases_v1.py",
    "scripts/build_p07_owner_private_memory_transactional_runtime.py",
    "scripts/build_telegram_gateway_release_v1.py",
    "scripts/p07_full_mutation_set_v1.py",
    "scripts/p07_owner_private_memory_production_plan.py",
    "scripts/p07_owner_private_memory_runtime_artifact_v1.py",
    "scripts/p07_owner_private_memory_transactional_controller.py",
    "scripts/p07_owner_private_memory_transactional_runtime.py",
    "scripts/p07_transactional_plugin_artifact_v1.py",
    "scripts/p08_temporal_gateway_v1.py",
    "scripts/p08_temporal_service_v1.py",
    "systemd/myuna-active-temporal-context-v1.service",
    "systemd/myuna-active-temporal-context-v1.socket",
    "tests/test_build_p07_owner_private_memory_transactional_runtime.py",
    "tests/test_p07_full_mutation_set_v1.py",
    "tests/test_p07_owner_private_memory_build_profile_v1.py",
    "tests/test_p07_owner_private_memory_production_plan.py",
    "tests/test_p07_owner_private_memory_runtime_artifact_v1.py",
    "tests/test_p07_owner_private_memory_transactional_controller.py",
    "tests/test_p07_owner_private_memory_transactional_runtime.py",
    "tests/test_p07_transactional_plugin_artifact_v1.py",
    "tests/test_p08_telegram_gateway_v1.py",
    "tests/test_p08_temporal_service_v1.py",
)
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


class TransactionalRuntimeBuildRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def require(condition: bool, code: str) -> None:
    if not condition:
        raise TransactionalRuntimeBuildRejected(code)


def git(source: Path, *arguments: str) -> str:
    completed = subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            f"safe.directory={source.resolve()}",
            "-C",
            str(source.resolve()),
            *arguments,
        ],
        capture_output=True,
        check=False,
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/usr/sbin",
        },
        text=True,
        timeout=120,
    )
    require(completed.returncode == 0, "transactional_runtime_build_git_rejected")
    return completed.stdout.strip()


def validate_source(source: Path, expected_commit: str) -> tuple[str, str]:
    require(
        _COMMIT.fullmatch(expected_commit) is not None,
        "transactional_runtime_build_commit_rejected",
    )
    require(
        git(source, "rev-parse", "HEAD") == expected_commit,
        "transactional_runtime_build_head_drifted",
    )
    require(not git(source, "status", "--porcelain"), "transactional_runtime_build_source_dirty")
    deploy_tree = git(source, "rev-parse", "HEAD^{tree}")
    require(
        _COMMIT.fullmatch(deploy_tree) is not None,
        "transactional_runtime_build_tree_rejected",
    )
    require(
        git(source, "rev-parse", f"{runtime.DEPLOY_PARENT_COMMIT}^{{tree}}")
        == runtime.DEPLOY_PARENT_TREE,
        "transactional_runtime_build_parent_tree_drifted",
    )
    require(
        git(source, "merge-base", "--is-ancestor", runtime.DEPLOY_PARENT_COMMIT, expected_commit)
        == "",
        "transactional_runtime_build_parent_ancestry_rejected",
    )
    return expected_commit, deploy_tree


def git_mode(source: Path, relative: str) -> int:
    fields = git(source, "ls-files", "-s", "--", relative).split()
    require(
        len(fields) >= 4
        and fields[3] == relative
        and fields[0] in {"100644", "100755"},
        "transactional_runtime_build_source_mode_rejected",
    )
    return 0o755 if fields[0] == "100755" else 0o644


def copy_source(source: Path, relative: str, destination: Path) -> dict[str, object]:
    path = source / relative
    require(
        path.is_file() and not path.is_symlink(),
        "transactional_runtime_build_source_file_rejected",
    )
    mode = git_mode(source, relative)
    target = destination / relative
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    shutil.copyfile(path, target)
    os.chmod(target, mode)
    return {
        "mode": mode,
        "path": relative,
        "sha256": sha256(target.read_bytes()).hexdigest(),
        "size": target.stat().st_size,
    }


def build_bundle(
    *,
    deploy_source: Path,
    output_root: Path,
    core_commit: str,
    deploy_commit: str,
    runtime_candidate: Path,
) -> dict[str, object]:
    require(
        core_commit == runtime.CORE_SOURCE_COMMIT,
        "transactional_runtime_build_core_commit_rejected",
    )
    deploy_commit, deploy_tree = validate_source(deploy_source, deploy_commit)
    require(
        not output_root.exists() and not output_root.is_symlink(),
        "transactional_runtime_build_output_exists",
    )
    output_root.mkdir(parents=True, mode=0o750)
    os.chmod(output_root, 0o750)
    files = [copy_source(deploy_source, relative, output_root) for relative in SOURCE_FILES]
    plugin_binding = plugin_artifact.derive_binding(
        deploy_source,
        expected_commit=deploy_commit,
        expected_tree=deploy_tree,
    )
    plugin_artifact.materialize_source_bound_release(
        source=deploy_source,
        output_root=output_root / "telegram-plugin",
        binding=plugin_binding,
    )
    runtime_release, runtime_projection = production.verify_runtime_artifact_candidate(
        runtime_candidate,
        core_commit=runtime.CORE_SOURCE_COMMIT,
        core_tree=runtime.CORE_SOURCE_TREE,
        deploy_commit=deploy_commit,
        deploy_tree=deploy_tree,
        plugin_binding=plugin_binding,
    )
    require(
        runtime_release == runtime_projection["release_digest"],
        "transactional_runtime_build_runtime_artifact_rejected",
    )
    semantic = {
        "capabilities": {
            "after_payload_package_source_present": True,
            "attempt_consumed": False,
            "backup_created": False,
            "context_bound_rejection_envelope_source_present": True,
            "failed_request_continuation_materialized": False,
            "failed_request_continuation_source_present": True,
            "installed": False,
            "immutable_continuation_reference_source_present": True,
            "ledger_created": False,
            "live_mutated": False,
            "p08_status_stage_projection_source_present": True,
            "p08_server_rejection_subprojection_source_present": True,
            "plan_created": False,
            "preflight_executed": False,
            "production_adapter_source_present": True,
            "provider_called": False,
            "selected": False,
            "source_derived_fresh_max1_strategy_present": True,
            "source_owned_artifact_root_contract_present": True,
            "source_owned_request_collection_closed": True,
            "source_owned_request_collection_present": True,
            "source_owned_request_constructor_present": True,
            "status_invocation_evidence_source_present": True,
            "state_created": False,
        },
        "failed_request_continuation_storage": (
            runtime.failed_request_continuation_storage_identity()
        ),
        "files": files,
        "parent": {
            "controller_bundle_id": runtime.PARENT_CONTROLLER_BUNDLE_ID,
            "controller_manifest_sha256": runtime.PARENT_CONTROLLER_MANIFEST_SHA256,
            "controller_source_id": parent.SOURCE_ID,
            "full_mutation_bundle_id": parent.FULL_MUTATION_BUNDLE_ID,
            "full_mutation_manifest_sha256": parent.FULL_MUTATION_MANIFEST_SHA256,
            "full_mutation_source_id": mutation.SOURCE_ID,
            "predecessor_runtime_bundle_id": runtime.PREDECESSOR_RUNTIME_BUNDLE_ID,
            "predecessor_runtime_manifest_sha256": (
                runtime.PREDECESSOR_RUNTIME_MANIFEST_SHA256
            ),
            "production_plan_source_id": runtime.production.SOURCE_ID,
        },
        "plugin": plugin_binding,
        "runtime_artifact": runtime_projection,
        "schema": runtime.BUNDLE_SCHEMA,
        "source_owned_artifact_roots": runtime.source_owned_artifact_root_contract(),
        "source": {
            "core_commit": runtime.CORE_SOURCE_COMMIT,
            "core_tree": runtime.CORE_SOURCE_TREE,
            "deploy_commit": deploy_commit,
            "deploy_parent_commit": runtime.DEPLOY_PARENT_COMMIT,
            "deploy_parent_tree": runtime.DEPLOY_PARENT_TREE,
            "deploy_tree": deploy_tree,
            "runtime_source_id": runtime.SOURCE_ID,
        },
    }
    manifest = {
        **semantic,
        "bundle_id": runtime.digest(
            runtime.BUNDLE_ID_DOMAIN, semantic
        ),
    }
    (output_root / "manifest.json").write_bytes(runtime.canonical(manifest))
    os.chmod(output_root / "manifest.json", 0o644)
    verify_bundle(output_root)
    return manifest


def verify_bundle(root: Path) -> dict[str, object]:
    require(
        root.is_dir() and not root.is_symlink(),
        "transactional_runtime_bundle_root_rejected",
    )
    try:
        raw = (root / "manifest.json").read_bytes()
        manifest = json.loads(raw.decode("ascii"), object_pairs_hook=runtime._strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TransactionalRuntimeBuildRejected(
            "transactional_runtime_bundle_manifest_rejected"
        ) from exc
    require(
        isinstance(manifest, dict) and runtime.canonical(manifest) == raw,
        "transactional_runtime_bundle_manifest_rejected",
    )
    manifest_sha = sha256(raw).hexdigest()
    runtime.validate_runtime_artifact_manifest(
        manifest,
        manifest_sha256=manifest_sha,
        expected_bundle_id=str(manifest.get("bundle_id", "")),
        expected_manifest_sha256=manifest_sha,
    )
    binding = plugin_artifact.validate_binding(manifest["plugin"])
    runtime_projection = runtime_artifact.validate_projection(
        manifest["runtime_artifact"]
    )
    plugin_release = str(binding["target"]["release_digest"])
    plugin_root = root / "telegram-plugin"
    plugin_artifact.verify_candidate(plugin_root / plugin_release, binding)
    require(
        runtime_projection["plugin"] == plugin_artifact.binding_projection(binding),
        "transactional_runtime_build_runtime_artifact_rejected",
    )
    expected_paths = {
        "manifest.json",
        *SOURCE_FILES,
    }
    expected_paths.add(
        f"telegram-plugin/{plugin_release}{plugin_artifact.MANIFEST_SUFFIX}"
    )
    expected_paths.update(
        {
            f"telegram-plugin/{plugin_release}/{row['destination']}"
            for row in binding["source"]["files"]
        }
    )
    actual_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    actual_files: list[dict[str, object]] = []
    for relative in SOURCE_FILES:
        path = root / relative
        metadata = path.lstat()
        require(
            stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
            "transactional_runtime_bundle_inventory_rejected",
        )
        actual_files.append(
            {
                "mode": stat.S_IMODE(metadata.st_mode),
                "path": relative,
                "sha256": sha256(path.read_bytes()).hexdigest(),
                "size": metadata.st_size,
            }
        )
    require(
        actual_paths == expected_paths
        and actual_files == manifest["files"]
        and not any(
            "__pycache__" in path or path.endswith((".pyc", ".pyo"))
            for path in actual_paths
        ),
        "transactional_runtime_bundle_inventory_rejected",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deploy-source", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--core-commit", required=True)
    parser.add_argument("--deploy-commit", required=True)
    parser.add_argument("--runtime-candidate", type=Path, required=True)
    values = parser.parse_args()
    manifest = build_bundle(
        deploy_source=values.deploy_source,
        output_root=values.output_root,
        core_commit=values.core_commit,
        deploy_commit=values.deploy_commit,
        runtime_candidate=values.runtime_candidate,
    )
    print(json.dumps(manifest, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
