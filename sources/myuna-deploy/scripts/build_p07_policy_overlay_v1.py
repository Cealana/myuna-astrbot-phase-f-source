#!/usr/bin/env python3
"""Build and verify a deterministic inactive P07 policy-overlay bundle."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
from typing import Mapping

from myuna_core.external_context.policy_overlay import (
    PolicyOverlay,
    PolicyOverlayMarker,
    PolicyOverlayRejected,
    PolicyOverlaySelector,
    PolicyOverlayState,
    ZERO_DIGEST,
    canonical_document,
    require_overlay_component_set,
    require_policy_overlay_transition,
)
from myuna_core.external_context.release_set import P07DReleaseSet


BUNDLE_SCHEMA = "myuna.p07-policy-overlay-bundle.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_BUNDLE_FILES = (
    "overlay-manifest.json",
    "overlay-marker.json",
    "overlay-selector.json",
    "overlay-state.json",
)


class PolicyOverlayBuildRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def require(condition: bool, code: str) -> None:
    if not condition:
        raise PolicyOverlayBuildRejected(code)


def canonical(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"


def digest(domain: str, payload: Mapping[str, object]) -> str:
    return sha256(
        domain.encode("ascii") + b"\0" + canonical(payload).rstrip(b"\n")
    ).hexdigest()


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        require(key not in result, "overlay_build_duplicate_field")
        result[key] = value
    return result


def load_parent_manifest(path: Path) -> tuple[P07DReleaseSet, str]:
    try:
        raw = path.read_bytes()
        payload = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_strict_object
        )
        selected = P07DReleaseSet.from_payload(payload)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        PolicyOverlayRejected,
        TypeError,
        ValueError,
    ):
        raise PolicyOverlayBuildRejected(
            "overlay_build_parent_manifest_rejected"
        ) from None
    return selected, sha256(raw).hexdigest()


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
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    require(completed.returncode == 0, "overlay_build_git_rejected")
    return completed.stdout.strip()


def validate_source(source: Path, expected_commit: str) -> None:
    require(
        _COMMIT.fullmatch(expected_commit) is not None,
        "overlay_build_source_commit_rejected",
    )
    require(git(source, "rev-parse", "HEAD") == expected_commit, "overlay_build_source_head_drifted")
    require(not git(source, "status", "--porcelain"), "overlay_build_source_dirty")


def bundle_documents(
    *,
    parent_release_set: P07DReleaseSet,
    parent_manifest_file_digest: str,
    core_release_digest: str,
    runtime_release_digest: str,
    plugin_release_digest: str,
    plugin_config_digest: str,
    core_commit: str,
    deploy_commit: str,
) -> dict[str, bytes]:
    selected = PolicyOverlay.create(
        parent_release_set=parent_release_set,
        parent_manifest_file_digest=parent_manifest_file_digest,
        core_release_digest=core_release_digest,
        runtime_release_digest=runtime_release_digest,
        plugin_release_digest=plugin_release_digest,
        plugin_config_digest=plugin_config_digest,
        core_commit=core_commit,
        deploy_commit=deploy_commit,
    )
    require_overlay_component_set(
        selected,
        core_release_digest=core_release_digest,
        runtime_release_digest=runtime_release_digest,
        plugin_release_digest=plugin_release_digest,
        plugin_config_digest=plugin_config_digest,
    )
    state = PolicyOverlayState.create(
        sequence=1,
        status="active",
        overlay_id=selected.overlay_id,
        previous_state_digest=ZERO_DIGEST,
    )
    require_policy_overlay_transition(None, state)
    selector = PolicyOverlaySelector.create(selected, state)
    marker = PolicyOverlayMarker.create(selector, state)
    return {
        "overlay-manifest.json": canonical_document(selected.as_payload()),
        "overlay-marker.json": canonical_document(marker.as_payload()),
        "overlay-selector.json": canonical_document(selector.as_payload()),
        "overlay-state.json": canonical_document(state.as_payload()),
    }


def build_bundle(
    *,
    output_root: Path,
    parent_release_set: P07DReleaseSet,
    parent_manifest_file_digest: str,
    core_release_digest: str,
    runtime_release_digest: str,
    plugin_release_digest: str,
    plugin_config_digest: str,
    core_commit: str,
    deploy_commit: str,
) -> dict[str, object]:
    documents = bundle_documents(
        parent_release_set=parent_release_set,
        parent_manifest_file_digest=parent_manifest_file_digest,
        core_release_digest=core_release_digest,
        runtime_release_digest=runtime_release_digest,
        plugin_release_digest=plugin_release_digest,
        plugin_config_digest=plugin_config_digest,
        core_commit=core_commit,
        deploy_commit=deploy_commit,
    )
    inventory = {
        name: sha256(content).hexdigest()
        for name, content in sorted(documents.items())
    }
    semantic = {
        "components": {
            "core_release_digest": core_release_digest,
            "plugin_config_digest": plugin_config_digest,
            "plugin_release_digest": plugin_release_digest,
            "runtime_release_digest": runtime_release_digest,
        },
        "files": inventory,
        "overlay_id": json.loads(
            documents["overlay-manifest.json"].decode("ascii")
        )["overlay_id"],
        "parent_release_set_id": parent_release_set.release_set_id,
        "schema": BUNDLE_SCHEMA,
        "source": {
            "core_commit": core_commit,
            "deploy_commit": deploy_commit,
        },
    }
    bundle_id = digest("myuna-p07-policy-overlay-bundle-v1", semantic)
    manifest = {**semantic, "bundle_id": bundle_id}
    target = output_root / bundle_id
    require(not target.exists(), "overlay_build_target_exists")
    target.mkdir(parents=True, mode=0o750)
    for name, content in documents.items():
        (target / name).write_bytes(content)
    (target / "bundle-manifest.json").write_bytes(canonical(manifest))
    verify_bundle(target, parent_release_set=parent_release_set)
    return manifest


def verify_bundle(
    target: Path,
    *,
    parent_release_set: P07DReleaseSet,
) -> dict[str, object]:
    require(target.is_dir() and not target.is_symlink(), "overlay_bundle_type_rejected")
    expected_names = {*_BUNDLE_FILES, "bundle-manifest.json"}
    require(
        {path.name for path in target.iterdir()} == expected_names,
        "overlay_bundle_inventory_rejected",
    )
    try:
        manifest = json.loads(
            (target / "bundle-manifest.json").read_text("ascii"),
            object_pairs_hook=_strict_object,
        )
        selected = PolicyOverlay.from_payload(
            json.loads(
                (target / "overlay-manifest.json").read_text("ascii"),
                object_pairs_hook=_strict_object,
            )
        )
        selector = PolicyOverlaySelector.from_payload(
            json.loads(
                (target / "overlay-selector.json").read_text("ascii"),
                object_pairs_hook=_strict_object,
            )
        )
        marker = PolicyOverlayMarker.from_payload(
            json.loads(
                (target / "overlay-marker.json").read_text("ascii"),
                object_pairs_hook=_strict_object,
            )
        )
        state = PolicyOverlayState.from_payload(
            json.loads(
                (target / "overlay-state.json").read_text("ascii"),
                object_pairs_hook=_strict_object,
            )
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        PolicyOverlayRejected,
        TypeError,
        ValueError,
    ):
        raise PolicyOverlayBuildRejected("overlay_bundle_document_rejected") from None
    required = {
        "bundle_id",
        "components",
        "files",
        "overlay_id",
        "parent_release_set_id",
        "schema",
        "source",
    }
    require(
        isinstance(manifest, Mapping)
        and set(manifest) == required
        and manifest["schema"] == BUNDLE_SCHEMA,
        "overlay_bundle_manifest_rejected",
    )
    inventory = {
        name: sha256((target / name).read_bytes()).hexdigest()
        for name in _BUNDLE_FILES
    }
    semantic = {key: manifest[key] for key in sorted(required - {"bundle_id"})}
    require(
        manifest["files"] == inventory
        and manifest["overlay_id"] == selected.overlay_id
        and manifest["parent_release_set_id"] == parent_release_set.release_set_id
        and manifest["bundle_id"]
        == digest("myuna-p07-policy-overlay-bundle-v1", semantic)
        and target.name == manifest["bundle_id"],
        "overlay_bundle_digest_mismatch",
    )
    require(
        selected.parent["release_set_id"] == parent_release_set.release_set_id
        and selector.overlay_id == selected.overlay_id
        and marker.overlay_id == selected.overlay_id
        and state.overlay_id == selected.overlay_id
        and state.status == "active"
        and selector.state_digest == state.state_digest
        and marker.selector_id == selector.selector_id,
        "overlay_bundle_binding_mismatch",
    )
    components = manifest["components"]
    require(isinstance(components, Mapping), "overlay_bundle_components_rejected")
    require_overlay_component_set(
        selected,
        core_release_digest=components["core_release_digest"],  # type: ignore[arg-type]
        runtime_release_digest=components["runtime_release_digest"],  # type: ignore[arg-type]
        plugin_release_digest=components["plugin_release_digest"],  # type: ignore[arg-type]
        plugin_config_digest=components["plugin_config_digest"],  # type: ignore[arg-type]
    )
    return dict(manifest)


def parser() -> argparse.ArgumentParser:
    selected = argparse.ArgumentParser()
    selected.add_argument("--core-source", type=Path, required=True)
    selected.add_argument("--deploy-source", type=Path, required=True)
    selected.add_argument("--parent-manifest", type=Path, required=True)
    selected.add_argument("--core-commit", required=True)
    selected.add_argument("--deploy-commit", required=True)
    selected.add_argument("--core-release-digest", required=True)
    selected.add_argument("--runtime-release-digest", required=True)
    selected.add_argument("--plugin-release-digest", required=True)
    selected.add_argument("--plugin-config-digest", required=True)
    selected.add_argument("--output-root", type=Path, required=True)
    return selected


def main() -> int:
    arguments = parser().parse_args()
    validate_source(arguments.core_source, arguments.core_commit)
    validate_source(arguments.deploy_source, arguments.deploy_commit)
    parent, parent_digest = load_parent_manifest(arguments.parent_manifest)
    manifest = build_bundle(
        output_root=arguments.output_root,
        parent_release_set=parent,
        parent_manifest_file_digest=parent_digest,
        core_release_digest=arguments.core_release_digest,
        runtime_release_digest=arguments.runtime_release_digest,
        plugin_release_digest=arguments.plugin_release_digest,
        plugin_config_digest=arguments.plugin_config_digest,
        core_commit=arguments.core_commit,
        deploy_commit=arguments.deploy_commit,
    )
    print(json.dumps(manifest, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
