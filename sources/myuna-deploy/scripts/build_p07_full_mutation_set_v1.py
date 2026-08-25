#!/usr/bin/env python3
"""Build a deterministic inactive P07 full-mutation-set source bundle."""

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
from typing import Mapping


SCHEMA = "myuna.p07-full-mutation-set-inactive-bundle.v1"
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
SOURCE_FILES = (
    "docs/ADR-067-p07-full-filesystem-mutation-set-v1.md",
    "scripts/activate_p07_owner_private_memory_v1.py",
    "scripts/build_p07_full_mutation_set_v1.py",
    "scripts/p07_full_mutation_set_v1.py",
    "scripts/p07_policy_overlay_transaction.py",
    "tests/test_build_p07_full_mutation_set_v1.py",
    "tests/test_p07_full_mutation_set_v1.py",
    "tests/test_p07_owner_private_memory_activation_v1.py",
)


class FullMutationBuildRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def require(condition: bool, code: str) -> None:
    if not condition:
        raise FullMutationBuildRejected(code)


def canonical(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"


def file_digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


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
    require(completed.returncode == 0, "full_mutation_build_git_rejected")
    return completed.stdout.strip()


def validate_source(source: Path, expected_commit: str) -> None:
    require(
        _COMMIT.fullmatch(expected_commit) is not None,
        "full_mutation_build_source_commit_rejected",
    )
    require(
        git(source, "rev-parse", "HEAD") == expected_commit,
        "full_mutation_build_source_head_drifted",
    )
    require(
        not git(source, "status", "--porcelain"),
        "full_mutation_build_source_dirty",
    )


def git_mode(source: Path, relative: str) -> int:
    line = git(source, "ls-files", "-s", "--", relative)
    fields = line.split()
    require(
        len(fields) >= 4 and fields[3] == relative and fields[0] in {"100644", "100755"},
        "full_mutation_build_source_mode_rejected",
    )
    return 0o755 if fields[0] == "100755" else 0o644


def copy_source(source: Path, relative: str, destination: Path) -> dict[str, object]:
    path = source / relative
    require(
        path.is_file() and not path.is_symlink(),
        "full_mutation_build_source_file_rejected",
    )
    mode = git_mode(source, relative)
    target = destination / relative
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    shutil.copyfile(path, target)
    os.chmod(target, mode)
    return {
        "mode": mode,
        "path": relative,
        "sha256": file_digest(target),
        "size": target.stat().st_size,
    }


def build_bundle(
    *,
    deploy_source: Path,
    output_root: Path,
    core_commit: str,
    deploy_commit: str,
) -> dict[str, object]:
    require(
        _COMMIT.fullmatch(core_commit) is not None
        and _COMMIT.fullmatch(deploy_commit) is not None,
        "full_mutation_build_source_commit_rejected",
    )
    require(
        not output_root.exists() and not output_root.is_symlink(),
        "full_mutation_build_output_exists",
    )
    output_root.mkdir(parents=True, mode=0o750)
    os.chmod(output_root, 0o750)
    files = [
        copy_source(deploy_source, relative, output_root)
        for relative in SOURCE_FILES
    ]
    semantic = {
        "capabilities": {
            "attempt_namespace": False,
            "backup": False,
            "live_activation": False,
            "live_preflight": False,
            "private_content": False,
            "provider_or_channel_call": False,
            "service_restart": False,
        },
        "files": files,
        "mutation_contract": "myuna.p07-full-filesystem-mutation-set.v1",
        "rollback_lineages": {
            "dual_state_v2": "immutable-exhausted-1-of-1",
            "predecessor": "immutable-exhausted-2-of-2",
        },
        "schema": SCHEMA,
        "source": {
            "core_commit": core_commit,
            "deploy_commit": deploy_commit,
        },
    }
    manifest = {
        **semantic,
        "bundle_id": sha256(
            b"myuna-p07-full-mutation-set-inactive-bundle-v1\0"
            + canonical(semantic).rstrip(b"\n")
        ).hexdigest(),
    }
    (output_root / "manifest.json").write_bytes(canonical(manifest))
    os.chmod(output_root / "manifest.json", 0o644)
    verify_bundle(output_root)
    return manifest


def verify_bundle(root: Path) -> dict[str, object]:
    require(
        root.is_dir() and not root.is_symlink(),
        "full_mutation_bundle_root_rejected",
    )
    try:
        raw = (root / "manifest.json").read_bytes()
        manifest = json.loads(raw.decode("ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FullMutationBuildRejected("full_mutation_bundle_manifest_rejected") from exc
    required = {
        "bundle_id",
        "capabilities",
        "files",
        "mutation_contract",
        "rollback_lineages",
        "schema",
        "source",
    }
    require(
        isinstance(manifest, dict)
        and set(manifest) == required
        and manifest.get("schema") == SCHEMA
        and canonical(manifest) == raw,
        "full_mutation_bundle_manifest_rejected",
    )
    actual_files = []
    expected_paths = {"manifest.json"}
    for item in manifest["files"]:
        require(
            isinstance(item, dict)
            and set(item) == {"mode", "path", "sha256", "size"},
            "full_mutation_bundle_inventory_rejected",
        )
        path = root / item["path"]
        metadata = path.lstat()
        require(
            not stat.S_ISLNK(metadata.st_mode)
            and stat.S_ISREG(metadata.st_mode),
            "full_mutation_bundle_file_type_rejected",
        )
        actual_files.append(
            {
                "mode": stat.S_IMODE(metadata.st_mode),
                "path": item["path"],
                "sha256": file_digest(path),
                "size": metadata.st_size,
            }
        )
        expected_paths.add(item["path"])
    actual_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    semantic = {key: manifest[key] for key in required - {"bundle_id"}}
    expected_id = sha256(
        b"myuna-p07-full-mutation-set-inactive-bundle-v1\0"
        + canonical(semantic).rstrip(b"\n")
    ).hexdigest()
    require(
        actual_files == manifest["files"]
        and actual_paths == expected_paths
        and manifest["bundle_id"] == expected_id
        and not any(
            "__pycache__" in path or path.endswith((".pyc", ".pyo"))
            for path in actual_paths
        ),
        "full_mutation_bundle_inventory_rejected",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deploy-source", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--core-commit", required=True)
    parser.add_argument("--deploy-commit", required=True)
    values = parser.parse_args()
    validate_source(values.deploy_source, values.deploy_commit)
    manifest = build_bundle(
        deploy_source=values.deploy_source,
        output_root=values.output_root,
        core_commit=values.core_commit,
        deploy_commit=values.deploy_commit,
    )
    print(json.dumps(manifest, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
