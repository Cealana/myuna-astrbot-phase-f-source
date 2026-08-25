#!/usr/bin/env python3
"""Build deterministic, inactive P16 Phase 1 T2 artifacts and inventories."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

import build_p16_releases_v1 as p16_builder
from p16_phase1_t2_contract_v1 import (
    BUNDLE_SCHEMA,
    build_attempt_lineage,
    canonical,
    digest,
    validate_bundle,
)


EXPECTED_CORE_SOURCE = "7e7bd8c3a0f44494fe520da8df105609e7e4534a"
GENERATION13_CORE = "128a9e1ad8fbd3b4d2b6ee64adabf63c88ea5263527f7ced5357495a31e22bcb"
GENERATION13_RUNTIME = "7baf48da3715ee2e1446ebf04a40ba8183c990fcf7f9505d9df465dc04e3d421"
GENERATION13_PLUGIN = "0aa958c2575814e3e2abbfe219a6d651f0bb156c45812f9cd39e51d4da512012"
GENERATION13_P08 = "9a767797c9e4ee9ac3e417e2e00fdcabb68b6fcafeddcec090b05eb3ef9b103f"
COMBINED_RELEASE_SET = "ae655eee017174b5ca78789e41aa597c6c68c59fd111a1b930ffaabef850f383"
P07_RELEASE_SET = "8d6f9df8f33cb573ba8ef1f4761acaef6c6b1acd831eed529ff6666e5afe8b32"
P08_PLAN = "246f1f862225e2c176a192495c04cdf3095f42c5694312299efa11e1e6072f28"
EFFECTIVE_V6 = "v6-v6ev2-1c344e35df28-o63656be5-cfcf597f6-g311561ea-qa12-qqtg1-r3"

_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
CONTROLLER_SOURCE = "scripts/activate_p16_phase1_t2_v1.py"

TELEGRAM_OVERLAYS = {
    **p16_builder._GATEWAY_SHARED,
    "runtime/p07_d_runtime_readiness.py": "scripts/p07_d_runtime_readiness.py",
    "runtime/telegram_owner_runtime_gateway.py": "scripts/telegram_owner_runtime_gateway.py",
}

ADAPTER_OVERLAYS = {
    **p16_builder._GATEWAY_SHARED,
    "contract/p16_phase1_t2_contract_v1.py": "scripts/p16_phase1_t2_contract_v1.py",
    "contract/preflight_p16_phase1_t2_v1.py": "scripts/preflight_p16_phase1_t2_v1.py",
    "systemd/myuna-telegram-owner-runtime-dev.service.d/40-p16-incident-history-v1.conf": (
        "systemd/myuna-telegram-owner-runtime-dev.service.d/40-p16-incident-history-v1.conf"
    ),
    "docs/P16_PHASE1_T2_DESIGN_V1.md": "docs/P16_PHASE1_T2_DESIGN_V1.md",
    "docs/P16_INCIDENT_HISTORY_V1.md": "docs/P16_INCIDENT_HISTORY_V1.md",
}


def _freeze(root: Path) -> None:
    for path in [root, *root.rglob("*")]:
        if path.is_symlink():
            raise ValueError("artifact contains a symlink")
        if path.is_dir():
            path.chmod(0o550)
        elif path.is_file():
            path.chmod(0o440)
        else:
            raise ValueError("artifact contains a non-regular entry")


def _inventory(root: Path) -> tuple[dict[str, object], str]:
    files: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            raise ValueError("artifact inventory contains a symlink")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("artifact inventory contains a non-regular entry")
        payload = path.read_bytes()
        files.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": sha256(payload).hexdigest(),
                "size": len(payload),
                "mode": f"{path.stat().st_mode & 0o777:04o}",
            }
        )
    if not files:
        raise ValueError("artifact inventory is empty")
    payload = {"schema": "myuna.p16-artifact-inventory.v1", "files": files}
    return payload, digest("myuna-p16-artifact-inventory-v1", payload)


def _copy_plugin(base: Path, output_root: Path) -> Path:
    resolved = p16_builder._validate_base(base)
    if resolved.name != GENERATION13_PLUGIN:
        raise ValueError("generation13 plugin identity is invalid")
    component = output_root / "telegram_plugin"
    destination = component / resolved.name
    component.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        existing, _ = _inventory(destination)
        source, _ = _inventory(resolved)
        existing_bytes = [
            {key: item[key] for key in ("path", "sha256", "size")}
            for item in existing["files"]
        ]
        source_bytes = [
            {key: item[key] for key in ("path", "sha256", "size")}
            for item in source["files"]
        ]
        if existing_bytes != source_bytes:
            raise ValueError("existing generation13 plugin artifact drifted")
        return destination
    temporary = Path(tempfile.mkdtemp(prefix=".p16-plugin-", dir=component))
    try:
        p16_builder._remove_temporary_tree(temporary)
        shutil.copytree(resolved, temporary, symlinks=True)
        _freeze(temporary)
        os.replace(temporary, destination)
    except BaseException:
        try:
            p16_builder._remove_temporary_tree(temporary)
        except OSError:
            pass
        raise
    return destination


def _artifact_record(root: Path) -> tuple[dict[str, object], dict[str, object]]:
    _freeze(root)
    inventory, inventory_digest = _inventory(root)
    record = {
        "release_digest": root.name,
        "inventory_digest": inventory_digest,
        "file_count": len(inventory["files"]),
    }
    return record, inventory


def build_phase1_t2_bundle(
    *,
    core_base: Path,
    telegram_base: Path,
    plugin_base: Path,
    core_source_root: Path,
    deploy_source_root: Path,
    core_source_commit: str,
    deploy_source_commit: str,
    output_root: Path,
) -> dict[str, object]:
    if core_source_commit != EXPECTED_CORE_SOURCE:
        raise ValueError("Core source is not the approved Phase 1 head")
    if _HEX40.fullmatch(deploy_source_commit) is None:
        raise ValueError("Deploy source commit is invalid")
    controller_source = deploy_source_root / CONTROLLER_SOURCE
    if controller_source.is_symlink() or not controller_source.is_file():
        raise ValueError("P16 live controller source is unavailable")
    controller_source_sha256 = sha256(controller_source.read_bytes()).hexdigest()
    core_base = p16_builder._validate_base(core_base)
    telegram_base = p16_builder._validate_base(telegram_base)
    plugin_base = p16_builder._validate_base(plugin_base)
    if core_base.name != GENERATION13_CORE or telegram_base.name != GENERATION13_RUNTIME:
        raise ValueError("generation13 base identity is invalid")
    if plugin_base.name != GENERATION13_PLUGIN:
        raise ValueError("generation13 plugin identity is invalid")
    output_root.mkdir(parents=True, exist_ok=True)
    built = {
        "core": Path(
            p16_builder._materialize(
                "core",
                base=core_base,
                overlays=p16_builder._CORE_OVERLAYS,
                source_root=core_source_root,
                source_commit=core_source_commit,
                output_root=output_root,
            )["release"]
        ),
        "telegram_runtime": Path(
            p16_builder._materialize(
                "telegram_runtime",
                base=telegram_base,
                overlays=TELEGRAM_OVERLAYS,
                source_root=deploy_source_root,
                source_commit=deploy_source_commit,
                output_root=output_root,
            )["release"]
        ),
        "telegram_plugin": _copy_plugin(plugin_base, output_root),
        "p16_adapter": Path(
            p16_builder._materialize(
                "p16_adapter",
                base=None,
                overlays=ADAPTER_OVERLAYS,
                source_root=deploy_source_root,
                source_commit=deploy_source_commit,
                output_root=output_root,
            )["release"]
        ),
    }
    artifact_records: dict[str, object] = {}
    inventories = output_root / "inventories"
    inventories.mkdir(exist_ok=True)
    for name, root in built.items():
        record, inventory = _artifact_record(root)
        artifact_records[name] = record
        inventory_path = inventories / f"{name}.json"
        expected = canonical(inventory) + b"\n"
        if inventory_path.exists():
            if inventory_path.is_symlink() or inventory_path.read_bytes() != expected:
                raise ValueError("existing artifact inventory drifted")
        else:
            inventory_path.write_bytes(expected)
            inventory_path.chmod(0o440)
    successor_identity = {
        "schema": BUNDLE_SCHEMA,
        "status": "built_inactive",
        "core_source_commit": core_source_commit,
        "deploy_source_commit": deploy_source_commit,
        "controller_source_sha256": controller_source_sha256,
        "generation13_base": {
            "core_release_digest": GENERATION13_CORE,
            "runtime_release_digest": GENERATION13_RUNTIME,
            "plugin_release_digest": GENERATION13_PLUGIN,
            "p08_release_digest": GENERATION13_P08,
        },
        "artifacts": artifact_records,
        "compatibility": {
            "combined_release_set_id": COMBINED_RELEASE_SET,
            "p07_release_set_id": P07_RELEASE_SET,
            "p08_plan_digest": P08_PLAN,
            "effective_definition_id": EFFECTIVE_V6,
            "generation": 13,
            "epoch_schema": "myuna.external-authorized-epoch.v3",
        },
        "content_free": True,
    }
    unsigned = {
        **successor_identity,
        "attempt_lineage": build_attempt_lineage(successor_identity),
    }
    bundle = {
        **unsigned,
        "bundle_digest": digest("myuna-p16-phase1-t2-bundle-v3", unsigned),
    }
    validate_bundle(bundle)
    manifest = output_root / "P16_PHASE1_T2_BUNDLE.json"
    expected_manifest = canonical(bundle) + b"\n"
    if manifest.exists():
        if manifest.is_symlink() or manifest.read_bytes() != expected_manifest:
            raise ValueError("existing Phase 1 T2 bundle drifted")
    else:
        manifest.write_bytes(expected_manifest)
        manifest.chmod(0o440)
    return bundle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core-base", type=Path, required=True)
    parser.add_argument("--telegram-base", type=Path, required=True)
    parser.add_argument("--plugin-base", type=Path, required=True)
    parser.add_argument("--core-source-root", type=Path, required=True)
    parser.add_argument("--deploy-source-root", type=Path, required=True)
    parser.add_argument("--core-source-commit", required=True)
    parser.add_argument("--deploy-source-commit", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    result = build_phase1_t2_bundle(**vars(args))
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
