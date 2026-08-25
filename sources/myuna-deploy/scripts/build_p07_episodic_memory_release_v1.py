#!/usr/bin/env python3
"""Build a deterministic, bytecode-free, inactive P07 episodic-memory release."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import subprocess

from p07_episodic_memory_contract_v1 import (
    RELEASE_SCHEMA,
    canonical,
    contract_digest,
    contract_payload,
)


_COMMIT = re.compile(r"^[0-9a-f]{40}$")
CORE_DIRECTORY = "src/myuna_core/episodic_memory"
DEPLOY_FILES = (
    "docs/ADR-066-p07-lossless-episodic-memory-v1.md",
    "scripts/build_p07_episodic_memory_release_v1.py",
    "scripts/p07_episodic_memory_contract_v1.py",
)


class EpisodicBuildRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def require(condition: bool, code: str) -> None:
    if not condition:
        raise EpisodicBuildRejected(code)


def file_digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def copy_file(source: Path, destination: Path) -> None:
    require(source.is_file() and not source.is_symlink(), "episodic_build_source_rejected")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def inventory(root: Path) -> list[dict[str, object]]:
    result = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        require(
            "__pycache__" not in path.parts and path.suffix not in {".pyc", ".pyo"},
            "episodic_build_bytecode_rejected",
        )
        result.append(
            {"path": relative, "sha256": file_digest(path), "size": path.stat().st_size}
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
    require(_COMMIT.fullmatch(core_commit) is not None, "episodic_core_commit_rejected")
    require(_COMMIT.fullmatch(deploy_commit) is not None, "episodic_deploy_commit_rejected")
    require(not output_root.exists() and not output_root.is_symlink(), "episodic_output_exists")
    source_root = core_root / CORE_DIRECTORY
    require(
        source_root.is_dir() and not source_root.is_symlink(),
        "episodic_core_inventory_rejected",
    )
    output_root.mkdir(parents=True, mode=0o750)
    try:
        for source in sorted(source_root.glob("*.py")):
            copy_file(source, output_root / source.relative_to(core_root))
        for relative in DEPLOY_FILES:
            copy_file(deploy_root / relative, output_root / relative)
        files = inventory(output_root)
        manifest = {
            "capabilities": {
                "archive_population": False,
                "diary_schedule": False,
                "historical_raw_egress": False,
                "live_selector": False,
                "migration": False,
                "provider_call": False,
            },
            "contract": contract_payload(),
            "contract_digest": contract_digest(),
            "files": files,
            "rollback_runtime": "compressed-generation13",
            "schema": RELEASE_SCHEMA,
            "source": {"core_commit": core_commit, "deploy_commit": deploy_commit},
        }
        manifest["release_id"] = sha256(
            b"myuna-p07-episodic-memory-inactive-release-v1\0" + canonical(manifest).rstrip()
        ).hexdigest()
        (output_root / "manifest.json").write_bytes(canonical(manifest))
        verify_release(output_root)
        return manifest
    except BaseException:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def verify_release(root: Path) -> dict[str, object]:
    require(root.is_dir() and not root.is_symlink(), "episodic_release_type_rejected")
    try:
        manifest = json.loads((root / "manifest.json").read_text("ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise EpisodicBuildRejected("episodic_manifest_rejected") from None
    required = {
        "capabilities",
        "contract",
        "contract_digest",
        "files",
        "release_id",
        "rollback_runtime",
        "schema",
        "source",
    }
    require(isinstance(manifest, dict) and set(manifest) == required, "episodic_manifest_rejected")
    selected_files = [
        path
        for path in sorted(item for item in root.rglob("*") if item.is_file())
        if path.name != "manifest.json"
    ]
    actual = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": file_digest(path),
            "size": path.stat().st_size,
        }
        for path in selected_files
    ]
    semantic = {key: manifest[key] for key in sorted(required - {"release_id"})}
    expected_id = sha256(
        b"myuna-p07-episodic-memory-inactive-release-v1\0" + canonical(semantic).rstrip()
    ).hexdigest()
    require(
        manifest["schema"] == RELEASE_SCHEMA
        and manifest["contract"] == contract_payload()
        and manifest["contract_digest"] == contract_digest()
        and manifest["files"] == actual
        and manifest["release_id"] == expected_id,
        "episodic_release_digest_mismatch",
    )
    return manifest


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
        text=True,
        timeout=120,
    )
    require(completed.returncode == 0, "episodic_git_rejected")
    return completed.stdout.strip()


def validate_source(source: Path, expected_commit: str) -> None:
    require(git(source, "rev-parse", "HEAD") == expected_commit, "episodic_source_head_drifted")
    require(not git(source, "status", "--porcelain"), "episodic_source_dirty")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core-root", type=Path, required=True)
    parser.add_argument("--deploy-root", type=Path, required=True)
    parser.add_argument("--core-commit", required=True)
    parser.add_argument("--deploy-commit", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    values = parser.parse_args()
    validate_source(values.core_root, values.core_commit)
    validate_source(values.deploy_root, values.deploy_commit)
    manifest = build_release(
        core_root=values.core_root,
        deploy_root=values.deploy_root,
        output_root=values.output_root,
        core_commit=values.core_commit,
        deploy_commit=values.deploy_commit,
    )
    print(json.dumps(manifest, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
