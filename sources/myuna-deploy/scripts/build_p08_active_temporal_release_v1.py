#!/usr/bin/env python3
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil


SCHEMA = "myuna.p08-active-temporal-code-release.v1"
SAFE_COMMIT = re.compile(r"^[0-9a-f]{40}$")
CORE_FILES = (
    "src/myuna_core/authenticated_conversation.py",
    "src/myuna_core/channel_gateway.py",
    "src/myuna_core/identity.py",
)
CORE_DIRECTORIES = (
    "src/myuna_core/active_temporal_context",
    "src/myuna_core/trusted_time",
)
DEPLOY_FILES = (
    "systemd/myuna-active-temporal-context-v1.service",
    "systemd/myuna-active-temporal-context-v1.socket",
    "systemd/myuna-active-temporal-context-v1.sysusers.conf",
    "systemd/myuna-active-temporal-context-v1.tmpfiles.conf",
)


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _inventory(root: Path) -> list[dict[str, object]]:
    result = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            raise RuntimeError("bytecode_cache_rejected")
        result.append(
            {"path": relative, "size": path.stat().st_size, "sha256": _digest(path)}
        )
    return result


def build_release(
    *,
    core_root: Path,
    deploy_root: Path,
    output_root: Path,
    core_commit: str,
    deploy_commit: str,
) -> dict[str, object]:
    if not SAFE_COMMIT.fullmatch(core_commit) or not SAFE_COMMIT.fullmatch(deploy_commit):
        raise RuntimeError("source_commit_rejected")
    if output_root.exists() or output_root.is_symlink():
        raise RuntimeError("output_exists")
    output_root.mkdir(parents=True, mode=0o755)
    try:
        for relative in CORE_FILES:
            source = core_root / relative
            if not source.is_file() or source.is_symlink():
                raise RuntimeError("core_inventory_rejected")
            destination = output_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        for relative in CORE_DIRECTORIES:
            source_root = core_root / relative
            if not source_root.is_dir() or source_root.is_symlink():
                raise RuntimeError("core_inventory_rejected")
            for source in sorted(source_root.rglob("*.py")):
                if "__pycache__" in source.parts or source.is_symlink():
                    continue
                destination = output_root / source.relative_to(core_root)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
        for relative in DEPLOY_FILES:
            source = deploy_root / relative
            if not source.is_file() or source.is_symlink():
                raise RuntimeError("deploy_inventory_rejected")
            destination = output_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        inventory = _inventory(output_root)
        manifest = {
            "schema": SCHEMA,
            "core_commit": core_commit,
            "deploy_commit": deploy_commit,
            "entrypoint": "myuna_core.active_temporal_context.service",
            "runtime_profile": "p08-active-temporal-private-v1",
            "state_schema": "myuna.active-temporal-context.v1",
            "trusted_time_schema": "myuna.trusted-time-provider.v1",
            "protocol_schema": "myuna.active-temporal-context-protocol.v1",
            "files": inventory,
        }
        raw = json.dumps(
            manifest,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8") + b"\n"
        (output_root / "manifest.json").write_bytes(raw)
        return manifest
    except BaseException:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core-root", type=Path, required=True)
    parser.add_argument("--deploy-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--core-commit", required=True)
    parser.add_argument("--deploy-commit", required=True)
    values = parser.parse_args()
    build_release(
        core_root=values.core_root.resolve(),
        deploy_root=values.deploy_root.resolve(),
        output_root=values.output_root.resolve(),
        core_commit=values.core_commit,
        deploy_commit=values.deploy_commit,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
