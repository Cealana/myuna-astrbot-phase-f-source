#!/usr/bin/env python3
"""Build a deterministic inactive P07 transactional-controller bundle."""

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

import p07_owner_private_memory_transactional_controller as controller


SCHEMA = "myuna.p07-owner-private-memory-transactional-controller-bundle.v1"
SOURCE_FILES = (
    "docs/ADR-070-p07-owner-private-memory-transactional-controller.md",
    "scripts/build_p07_owner_private_memory_transactional_controller.py",
    "scripts/p07_full_mutation_set_v1.py",
    "scripts/p07_owner_private_memory_transactional_controller.py",
    "tests/test_build_p07_owner_private_memory_transactional_controller.py",
    "tests/test_p07_full_mutation_set_v1.py",
    "tests/test_p07_owner_private_memory_transactional_controller.py",
)
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


class TransactionalControllerBuildRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def require(condition: bool, code: str) -> None:
    if not condition:
        raise TransactionalControllerBuildRejected(code)


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
    require(completed.returncode == 0, "transactional_build_git_rejected")
    return completed.stdout.strip()


def validate_source(source: Path, expected_commit: str) -> None:
    require(_COMMIT.fullmatch(expected_commit) is not None, "transactional_build_commit_rejected")
    require(git(source, "rev-parse", "HEAD") == expected_commit, "transactional_build_head_drifted")
    require(not git(source, "status", "--porcelain"), "transactional_build_source_dirty")


def git_mode(source: Path, relative: str) -> int:
    fields = git(source, "ls-files", "-s", "--", relative).split()
    require(
        len(fields) >= 4
        and fields[3] == relative
        and fields[0] in {"100644", "100755"},
        "transactional_build_source_mode_rejected",
    )
    return 0o755 if fields[0] == "100755" else 0o644


def copy_source(source: Path, relative: str, destination: Path) -> dict[str, object]:
    path = source / relative
    require(path.is_file() and not path.is_symlink(), "transactional_build_source_file_rejected")
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
        "transactional_build_commit_rejected",
    )
    require(not output_root.exists() and not output_root.is_symlink(), "transactional_build_output_exists")
    output_root.mkdir(parents=True, mode=0o750)
    os.chmod(output_root, 0o750)
    files = [copy_source(deploy_source, relative, output_root) for relative in SOURCE_FILES]
    semantic = {
        "capabilities": {
            "attempt_consumed": False,
            "backup_created": False,
            "ledger_created": False,
            "live_controller_source_present": True,
            "live_mutated": False,
            "plan_created": False,
            "preflight_executed": False,
            "provider_called": False,
            "selected": False,
            "installed": False,
        },
        "controller_contract": controller.SOURCE_SCHEMA,
        "files": files,
        "full_mutation_contract": mutation_identity(),
        "immutable_evidence": {
            "full_mutation_bundle_id": controller.FULL_MUTATION_BUNDLE_ID,
            "full_mutation_handoff_sha256": controller.FULL_MUTATION_HANDOFF_SHA256,
            "full_mutation_manifest_sha256": controller.FULL_MUTATION_MANIFEST_SHA256,
            "predecessor": "immutable-exhausted-2-of-2",
            "root_cause_handoff_sha256": controller.ROOT_CAUSE_HANDOFF_SHA256,
            "terminal_v2_handoff_sha256": controller.TERMINAL_V2_HANDOFF_SHA256,
            "v2": "immutable-exhausted-1-of-1",
        },
        "maximum_future_activations": controller.MAXIMUM_ACTIVATIONS,
        "schema": SCHEMA,
        "source": {
            "controller_source_id": controller.SOURCE_ID,
            "core_commit": core_commit,
            "deploy_commit": deploy_commit,
        },
    }
    manifest = {
        **semantic,
        "bundle_id": sha256(
            b"myuna-p07-transactional-controller-inactive-bundle-v1\0"
            + canonical(semantic).rstrip()
        ).hexdigest(),
    }
    (output_root / "manifest.json").write_bytes(canonical(manifest))
    os.chmod(output_root / "manifest.json", 0o644)
    verify_bundle(output_root)
    return manifest


def mutation_identity() -> dict[str, object]:
    return {
        "bundle_id": controller.FULL_MUTATION_BUNDLE_ID,
        "manifest_sha256": controller.FULL_MUTATION_MANIFEST_SHA256,
        "schema": controller.mutation.SCHEMA,
        "source_id": controller.mutation.SOURCE_ID,
    }


def verify_bundle(root: Path) -> dict[str, object]:
    require(root.is_dir() and not root.is_symlink(), "transactional_bundle_root_rejected")
    try:
        raw = (root / "manifest.json").read_bytes()
        manifest = json.loads(raw.decode("ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TransactionalControllerBuildRejected("transactional_bundle_manifest_rejected") from exc
    required = {
        "bundle_id",
        "capabilities",
        "controller_contract",
        "files",
        "full_mutation_contract",
        "immutable_evidence",
        "maximum_future_activations",
        "schema",
        "source",
    }
    require(
        isinstance(manifest, dict)
        and set(manifest) == required
        and manifest.get("schema") == SCHEMA
        and canonical(manifest) == raw,
        "transactional_bundle_manifest_rejected",
    )
    actual_files: list[dict[str, object]] = []
    expected_paths = {"manifest.json"}
    for item in manifest["files"]:
        require(
            isinstance(item, dict)
            and set(item) == {"mode", "path", "sha256", "size"},
            "transactional_bundle_inventory_rejected",
        )
        path = root / item["path"]
        metadata = path.lstat()
        require(
            not stat.S_ISLNK(metadata.st_mode) and stat.S_ISREG(metadata.st_mode),
            "transactional_bundle_inventory_rejected",
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
        b"myuna-p07-transactional-controller-inactive-bundle-v1\0"
        + canonical(semantic).rstrip()
    ).hexdigest()
    capabilities = manifest["capabilities"]
    require(
        actual_files == manifest["files"]
        and actual_paths == expected_paths
        and manifest["bundle_id"] == expected_id
        and manifest["maximum_future_activations"] == 1
        and capabilities["live_controller_source_present"] is True
        and all(
            value is False
            for key, value in capabilities.items()
            if key != "live_controller_source_present"
        )
        and not any(
            "__pycache__" in path or path.endswith((".pyc", ".pyo"))
            for path in actual_paths
        ),
        "transactional_bundle_inventory_rejected",
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
