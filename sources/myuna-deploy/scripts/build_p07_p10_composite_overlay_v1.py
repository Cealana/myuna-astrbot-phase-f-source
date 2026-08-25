#!/usr/bin/env python3
"""Build a deterministic inactive P07/P10 composite policy-overlay bundle."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
from typing import Mapping

from activate_p07_hybrid_external_generation_v1 import (
    core_evidence,
    validate_plugin,
    validate_runtime,
)
from build_p07_policy_overlay_v1 import (
    load_parent_manifest,
    validate_source,
    verify_bundle as verify_overlay_bundle,
)
from p07_p10_composite_overlay_contract_v1 import (
    BUNDLE_SCHEMA,
    COMPRESSED_RUNTIME_PROFILE,
    CompositeContractRejected,
    P10_SOURCE_IDENTITIES,
    canonical,
    contract_digest,
    contract_payload,
    digest,
    require,
    require_exact_contract,
    require_source_identity,
)


P09_COMPATIBILITY_PATHS = (
    "scripts/activate_p07_hybrid_external_generation_v1.py",
    "scripts/build_p07_hybrid_live_releases_v1.py",
    "scripts/p09_v7_phase1_packaging_contract.py",
    "tests/test_p09_v7_phase1_packaging.py",
)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        require(key not in result, "composite_bundle_duplicate_field")
        result[key] = value
    return result


def _load(path: Path) -> dict[str, object]:
    try:
        selected = json.loads(
            path.read_text("ascii"), object_pairs_hook=_strict_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise CompositeContractRejected("composite_bundle_document_rejected") from None
    require(isinstance(selected, dict), "composite_bundle_document_rejected")
    return selected


def _git_blob(source: Path, relative: str) -> str:
    from build_p07_policy_overlay_v1 import git

    return git(source, "rev-parse", f"HEAD:{relative}")


def _source_projection(
    source: Path,
    paths: tuple[str, ...] | Mapping[str, tuple[str, str]],
) -> dict[str, dict[str, str]]:
    selected: dict[str, dict[str, str]] = {}
    for relative in paths:
        content = (source / relative).read_bytes()
        selected[relative] = {
            "git_blob": _git_blob(source, relative),
            "sha256": sha256(content).hexdigest(),
        }
    return selected


def _runtime_manifest(runtime_candidate: Path) -> dict[str, object]:
    manifest = _load(runtime_candidate / "P16_MANIFEST.json")
    require(
        "runtime_profile" not in manifest
        and "v7_phase1_contract" not in manifest,
        "composite_runtime_profile_rejected",
    )
    return manifest


def _overlay_inventory(overlay_bundle: Path) -> dict[str, str]:
    return {
        path.name: sha256(path.read_bytes()).hexdigest()
        for path in sorted(overlay_bundle.iterdir(), key=lambda item: item.name)
        if path.is_file() and not path.is_symlink()
    }


def build_bundle(
    *,
    output_root: Path,
    core_source: Path,
    deploy_source: Path,
    parent_manifest: Path,
    core_candidate: Path,
    runtime_candidate: Path,
    plugin_candidate: Path,
    overlay_bundle: Path,
    core_commit: str,
    deploy_commit: str,
) -> dict[str, object]:
    validate_source(core_source, core_commit)
    validate_source(deploy_source, deploy_commit)
    parent, parent_file_digest = load_parent_manifest(parent_manifest)
    overlay = verify_overlay_bundle(overlay_bundle, parent_release_set=parent)
    core, _artifact, _receipt = core_evidence(core_candidate)
    runtime_release = validate_runtime(runtime_candidate, core_commit, deploy_commit)
    plugin_release = validate_plugin(plugin_candidate)
    require(
        core.source_commit == core_commit
        and core.tree_sha256 == core_candidate.name,
        "composite_core_candidate_rejected",
    )
    require(
        overlay["components"] == {
            "core_release_digest": core.tree_sha256,
            "plugin_config_digest": overlay["components"]["plugin_config_digest"],
            "plugin_release_digest": plugin_release,
            "runtime_release_digest": runtime_release,
        },
        "composite_overlay_component_rejected",
    )
    require(
        overlay["parent_release_set_id"] == parent.release_set_id
        and overlay["source"]
        == {"core_commit": core_commit, "deploy_commit": deploy_commit},
        "composite_overlay_source_rejected",
    )
    runtime_manifest = _runtime_manifest(runtime_candidate)
    p10_files = _source_projection(deploy_source, P10_SOURCE_IDENTITIES)
    require_source_identity(
        core_commit=core_commit,
        deploy_commit=deploy_commit,
        p10_files=p10_files,
    )
    p09_files = _source_projection(deploy_source, P09_COMPATIBILITY_PATHS)
    overlay_files = _overlay_inventory(overlay_bundle)
    semantic: dict[str, object] = {
        "artifacts": {
            "core_release": core.tree_sha256,
            "plugin_release": plugin_release,
            "runtime_release": runtime_release,
        },
        "contract": contract_payload(),
        "contract_digest": contract_digest(),
        "overlay_bundle": {
            "bundle_id": overlay["bundle_id"],
            "files": overlay_files,
        },
        "p09_source_compatibility": {
            "affinity_active": False,
            "files": p09_files,
            "runtime_manifest_profile_field_absent": True,
            "selected_runtime_profile": COMPRESSED_RUNTIME_PROFILE,
            "v7_selected": False,
        },
        "p10_ingress": {
            "external_message": False,
            "files": p10_files,
            "hybrid_epoch_access": False,
            "short_term_history_access": False,
        },
        "parent_manifest_file_sha256": parent_file_digest,
        "schema": BUNDLE_SCHEMA,
        "source": {"core_commit": core_commit, "deploy_commit": deploy_commit},
    }
    composite_id = digest("myuna-p07-p10-composite-overlay-bundle-v1", semantic)
    manifest = {**semantic, "composite_id": composite_id}
    target = output_root / composite_id
    require(not target.exists(), "composite_bundle_target_exists")
    target.mkdir(parents=True, mode=0o750)
    overlay_parent = target / "policy-overlay"
    overlay_parent.mkdir(mode=0o750)
    overlay_target = overlay_parent / str(overlay["bundle_id"])
    overlay_target.mkdir(mode=0o750)
    for path in sorted(overlay_bundle.iterdir(), key=lambda item: item.name):
        require(path.is_file() and not path.is_symlink(), "composite_overlay_inventory_rejected")
        (overlay_target / path.name).write_bytes(path.read_bytes())
    (target / "composite-manifest.json").write_bytes(canonical(manifest))
    verify_bundle(
        target,
        core_source=core_source,
        deploy_source=deploy_source,
        parent_manifest=parent_manifest,
        core_candidate=core_candidate,
        runtime_candidate=runtime_candidate,
        plugin_candidate=plugin_candidate,
        core_commit=core_commit,
        deploy_commit=deploy_commit,
    )
    return manifest


def verify_bundle(
    target: Path,
    *,
    core_source: Path,
    deploy_source: Path,
    parent_manifest: Path,
    core_candidate: Path,
    runtime_candidate: Path,
    plugin_candidate: Path,
    core_commit: str,
    deploy_commit: str,
) -> dict[str, object]:
    validate_source(core_source, core_commit)
    validate_source(deploy_source, deploy_commit)
    require(target.is_dir() and not target.is_symlink(), "composite_bundle_type_rejected")
    require(
        {path.name for path in target.iterdir()}
        == {"composite-manifest.json", "policy-overlay"},
        "composite_bundle_inventory_rejected",
    )
    manifest = _load(target / "composite-manifest.json")
    required = {
        "artifacts",
        "composite_id",
        "contract",
        "contract_digest",
        "overlay_bundle",
        "p09_source_compatibility",
        "p10_ingress",
        "parent_manifest_file_sha256",
        "schema",
        "source",
    }
    require(
        set(manifest) == required and manifest["schema"] == BUNDLE_SCHEMA,
        "composite_bundle_manifest_rejected",
    )
    require_exact_contract(manifest["contract"])  # type: ignore[arg-type]
    require(manifest["contract_digest"] == contract_digest(), "composite_contract_digest_drifted")
    parent, parent_file_digest = load_parent_manifest(parent_manifest)
    overlay_root = (
        target / "policy-overlay" / str(manifest["overlay_bundle"]["bundle_id"])
    )
    overlay = verify_overlay_bundle(overlay_root, parent_release_set=parent)
    core, _artifact, _receipt = core_evidence(core_candidate)
    runtime_release = validate_runtime(runtime_candidate, core_commit, deploy_commit)
    plugin_release = validate_plugin(plugin_candidate)
    _runtime_manifest(runtime_candidate)
    require(
        manifest["parent_manifest_file_sha256"] == parent_file_digest
        and manifest["source"]
        == {"core_commit": core_commit, "deploy_commit": deploy_commit}
        and manifest["artifacts"]
        == {
            "core_release": core.tree_sha256,
            "plugin_release": plugin_release,
            "runtime_release": runtime_release,
        },
        "composite_bundle_identity_drifted",
    )
    require(
        manifest["overlay_bundle"]
        == {"bundle_id": overlay["bundle_id"], "files": _overlay_inventory(overlay_root)},
        "composite_overlay_inventory_rejected",
    )
    p10 = manifest["p10_ingress"]
    require(isinstance(p10, Mapping), "p10_source_inventory_rejected")
    require_source_identity(
        core_commit=core_commit,
        deploy_commit=deploy_commit,
        p10_files=p10["files"],  # type: ignore[arg-type]
    )
    require(
        p10["files"] == _source_projection(deploy_source, P10_SOURCE_IDENTITIES),
        "p10_source_identity_drifted",
    )
    p09 = manifest["p09_source_compatibility"]
    require(
        isinstance(p09, Mapping)
        and p09.get("selected_runtime_profile") == COMPRESSED_RUNTIME_PROFILE
        and p09.get("runtime_manifest_profile_field_absent") is True
        and p09.get("v7_selected") is False
        and p09.get("affinity_active") is False,
        "composite_p09_compatibility_rejected",
    )
    require(
        p09.get("files") == _source_projection(deploy_source, P09_COMPATIBILITY_PATHS),
        "composite_p09_source_drifted",
    )
    semantic = {key: manifest[key] for key in sorted(required - {"composite_id"})}
    require(
        manifest["composite_id"]
        == digest("myuna-p07-p10-composite-overlay-bundle-v1", semantic)
        and target.name == manifest["composite_id"],
        "composite_bundle_digest_mismatch",
    )
    return manifest


def parser() -> argparse.ArgumentParser:
    selected = argparse.ArgumentParser()
    selected.add_argument("--output-root", type=Path, required=True)
    selected.add_argument("--core-source", type=Path, required=True)
    selected.add_argument("--deploy-source", type=Path, required=True)
    selected.add_argument("--parent-manifest", type=Path, required=True)
    selected.add_argument("--core-candidate", type=Path, required=True)
    selected.add_argument("--runtime-candidate", type=Path, required=True)
    selected.add_argument("--plugin-candidate", type=Path, required=True)
    selected.add_argument("--overlay-bundle", type=Path, required=True)
    selected.add_argument("--core-commit", required=True)
    selected.add_argument("--deploy-commit", required=True)
    return selected


def main() -> int:
    arguments = parser().parse_args()
    try:
        manifest = build_bundle(
            output_root=arguments.output_root.resolve(),
            core_source=arguments.core_source.resolve(),
            deploy_source=arguments.deploy_source.resolve(),
            parent_manifest=arguments.parent_manifest.resolve(),
            core_candidate=arguments.core_candidate.resolve(),
            runtime_candidate=arguments.runtime_candidate.resolve(),
            plugin_candidate=arguments.plugin_candidate.resolve(),
            overlay_bundle=arguments.overlay_bundle.resolve(),
            core_commit=arguments.core_commit,
            deploy_commit=arguments.deploy_commit,
        )
    except Exception as exc:
        code = getattr(exc, "code", "composite_bundle_build_rejected")
        print(json.dumps({"failure_gate": code, "schema": BUNDLE_SCHEMA, "status": "rejected"}, separators=(",", ":"), sort_keys=True))
        return 1
    print(json.dumps(manifest, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
