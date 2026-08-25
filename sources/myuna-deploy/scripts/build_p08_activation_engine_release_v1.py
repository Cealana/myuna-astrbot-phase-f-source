#!/usr/bin/env python3
"""Deterministic inactive release builder for the reset P08 engine."""
from __future__ import annotations

import argparse
import base64
import binascii
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

import build_p08_active_temporal_release_v2 as legacy_builder
import p08_activation_contract_v1 as activation_contract
import p08_activation_production_adapter_v1 as production_adapter


SCHEMA = activation_contract.RELEASE_SCHEMA
SAFE_COMMIT = re.compile(r"^[0-9a-f]{40}$")
ENGINE_FILES = (
    "scripts/p08_activation_boot_recovery_v1.py",
    "scripts/p08_activation_contract_v1.py",
    "scripts/p08_activation_credential_probe_v1.py",
    "scripts/p08_activation_engine_v1.py",
    "scripts/p08_activation_guardian_manager_v1.py",
    "scripts/p08_activation_launcher_v1.py",
    "scripts/p08_activation_production_adapter_v1.py",
    "scripts/p08_activation_supervisor_bootstrap_v1.py",
    "scripts/p08_activation_top_level_entry_v1.py",
    "scripts/p08_activation_windows_capture_persist_v1.py",
    "scripts/p08_activation_windows_entry_v1.cs",
    "scripts/p08_activation_windows_entry_v1.exe.b64",
    "scripts/p08_activation_supervisor_v1.py",
    "scripts/p08_forward_continuity_orchestration_v1.py",
    "scripts/p08_temporal_gateway_v1.py",
    "scripts/p08_activation_shadow_v1.py",
    "scripts/p08_activation_installed_shadow_v1.py",
    "scripts/p08_activation_synthetic_acceptance_v1.py",
    "scripts/p08_activation_fixture_child_v1.py",
    "scripts/build_p08_activation_engine_release_v1.py",
)


def _materialize_windows_entry(deploy_root: Path, release_root: Path) -> None:
    identity = activation_contract.PRODUCTION_WINDOWS_HOST_LAUNCHER
    source = deploy_root / str(identity["source_path"])
    encoded = deploy_root / str(identity["base64_path"])
    if _digest(source) != identity["source_sha256"]:
        raise RuntimeError("windows_entry_source_rejected")
    try:
        raw = base64.b64decode(
            b"".join(encoded.read_bytes().split()), validate=True
        )
    except (OSError, binascii.Error):
        raise RuntimeError("windows_entry_artifact_rejected") from None
    if (
        len(raw) != identity["size"]
        or sha256(raw).hexdigest() != identity["sha256"]
        or not raw.startswith(b"MZ")
    ):
        raise RuntimeError("windows_entry_artifact_rejected")
    destination = release_root / str(identity["artifact_path"])
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(destination, flags, 0o555)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written < 1:
                raise RuntimeError("windows_entry_artifact_rejected")
            offset += written
        os.fchmod(descriptor, 0o555)
        os.fsync(descriptor)
        observed = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = destination.lstat()
    if (
        not stat.S_ISREG(observed.st_mode)
        or not stat.S_ISREG(current.st_mode)
        or observed.st_nlink != 1
        or current.st_nlink != 1
        or stat.S_IMODE(observed.st_mode) != 0o555
        or stat.S_IMODE(current.st_mode) != 0o555
        or destination.read_bytes() != raw
    ):
        raise RuntimeError("windows_entry_artifact_rejected")


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii") + b"\n"


def _git(root: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "--no-optional-locks", "-C", str(root), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("engine_source_identity_rejected") from None
    if len(completed.stdout) > 1_048_576:
        raise RuntimeError("engine_source_identity_rejected")
    return completed.stdout.strip()


def _copy_file(source: Path, destination: Path) -> None:
    details = source.lstat()
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        raise RuntimeError("engine_source_inventory_rejected")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    os.chmod(destination, stat.S_IMODE(details.st_mode))


def _normalize_directory_modes(root: Path) -> None:
    for path in (root, *sorted(item for item in root.rglob("*") if item.is_dir())):
        details = path.lstat()
        if not stat.S_ISDIR(details.st_mode) or path.is_symlink():
            raise RuntimeError("engine_directory_inventory_rejected")
        os.chmod(path, 0o755)


def _source_inventory(deploy_root: Path, deploy_commit: str) -> list[dict[str, object]]:
    if _git(deploy_root, "rev-parse", "HEAD") != deploy_commit:
        raise RuntimeError("engine_source_identity_rejected")
    status = _git(
        deploy_root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--",
        *ENGINE_FILES,
    )
    if status:
        raise RuntimeError("engine_source_identity_rejected")
    tracked = set(
        _git(
            deploy_root,
            "ls-tree",
            "-r",
            "--name-only",
            deploy_commit,
            "--",
            *ENGINE_FILES,
        ).splitlines()
    )
    if tracked != set(ENGINE_FILES):
        raise RuntimeError("engine_source_identity_rejected")
    rows = []
    for relative in sorted(ENGINE_FILES):
        path = deploy_root / relative
        details = path.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise RuntimeError("engine_source_inventory_rejected")
        rows.append(
            {
                "path": relative,
                "size": details.st_size,
                "mode": stat.S_IMODE(details.st_mode),
                "sha256": _digest(path),
            }
        )
    return rows


def _core_source_inventory(core_root: Path, core_commit: str) -> list[dict[str, object]]:
    pathspecs = (*legacy_builder.CORE_FILES, *legacy_builder.CORE_DIRECTORIES)
    if _git(core_root, "rev-parse", "HEAD") != core_commit:
        raise RuntimeError("core_source_identity_rejected")
    status = _git(
        core_root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--",
        *pathspecs,
    )
    if status:
        raise RuntimeError("core_source_identity_rejected")
    tracked = set(
        _git(
            core_root,
            "ls-tree",
            "-r",
            "--name-only",
            core_commit,
            "--",
            *pathspecs,
        ).splitlines()
    )
    selected = set(legacy_builder.CORE_FILES)
    for directory in legacy_builder.CORE_DIRECTORIES:
        prefix = directory + "/"
        matches = {
            relative
            for relative in tracked
            if relative.startswith(prefix) and relative.endswith(".py")
        }
        if not matches:
            raise RuntimeError("core_source_identity_rejected")
        selected.update(matches)
    if not set(legacy_builder.CORE_FILES).issubset(tracked):
        raise RuntimeError("core_source_identity_rejected")
    rows = []
    for relative in sorted(selected):
        path = core_root / relative
        details = path.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise RuntimeError("core_source_inventory_rejected")
        rows.append(
            {
                "path": relative,
                "size": details.st_size,
                "mode": stat.S_IMODE(details.st_mode),
                "sha256": _digest(path),
            }
        )
    return rows


def _p07_binding(deploy_root: Path) -> dict[str, object]:
    rows = []
    for relative in sorted(legacy_builder.P07_INTEGRATION_FILES):
        path = deploy_root / relative
        details = path.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise RuntimeError("p07_integration_source_identity_rejected")
        rows.append(
            {
                "path": relative,
                "mode": stat.S_IMODE(details.st_mode),
                "size": details.st_size,
                "sha256": _digest(path),
            }
        )
    return {
        "schema": "myuna.p07-p08-activation-compatibility.v1",
        "file_count": len(rows),
        "inventory_digest": activation_contract.digest_value(rows),
    }


def _core_continuity_binding(output_root: Path, core_commit: str, core_tree: str) -> dict[str, object]:
    rows = []
    root = output_root / "src/myuna_core/trusted_time"
    for path in sorted(root.rglob("*.py")):
        details = path.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise RuntimeError("core_continuity_inventory_rejected")
        rows.append(
            {
                "path": path.relative_to(output_root).as_posix(),
                "size": details.st_size,
                "mode": stat.S_IMODE(details.st_mode),
                "sha256": _digest(path),
            }
        )
    if not rows:
        raise RuntimeError("core_continuity_inventory_rejected")
    return {
        "schema": "myuna.p10b-forward-continuity-compatibility.v1",
        "core_commit": core_commit,
        "core_tree": core_tree,
        "inventory_digest": activation_contract.digest_value(rows),
        "file_count": len(rows),
    }


def _interpreter_identity() -> dict[str, object]:
    expected = dict(activation_contract.PRODUCTION_INTERPRETER)
    invocation = Path(str(expected["invocation_path"]))
    resolved = Path(str(expected["resolved_path"]))
    try:
        link = invocation.lstat()
        details = resolved.lstat()
    except OSError:
        raise RuntimeError("interpreter_identity_rejected") from None
    if (
        not stat.S_ISLNK(link.st_mode)
        or os.readlink(invocation) != expected["link_target"]
        or invocation.resolve() != resolved
        or not stat.S_ISREG(details.st_mode)
        or stat.S_IMODE(details.st_mode) != expected["mode"]
        or details.st_uid != expected["uid"]
        or details.st_gid != expected["gid"]
        or details.st_nlink != expected["nlink"]
        or details.st_size != expected["size"]
        or _digest(resolved) != expected["sha256"]
    ):
        raise RuntimeError("interpreter_identity_rejected")
    return expected


def _predecessor_binding(predecessor_release: Path) -> dict[str, object]:
    if (
        not predecessor_release.is_dir()
        or predecessor_release.is_symlink()
        or not activation_contract.HEX64.fullmatch(predecessor_release.name)
    ):
        raise RuntimeError("predecessor_release_rejected")
    manifest_path = predecessor_release / "manifest.json"
    details = manifest_path.lstat()
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        raise RuntimeError("predecessor_release_rejected")
    try:
        manifest = json.loads(manifest_path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("predecessor_release_rejected") from None
    if (
        not isinstance(manifest, dict)
        or manifest_path.read_bytes() != _canonical(manifest)
    ):
        raise RuntimeError("predecessor_release_rejected")
    try:
        inventory = production_adapter.target_inventory(predecessor_release)
        directories = production_adapter.target_directory_inventory(
            predecessor_release,
            file_inventory=inventory,
        )
        semantics = activation_contract.build_unit_semantics(
            (predecessor_release / "systemd/myuna-active-temporal-context-v1.service").read_bytes(),
            (predecessor_release / "systemd/myuna-active-temporal-context-v1.socket").read_bytes(),
        )
        return activation_contract.build_predecessor_binding(
            release_identity=predecessor_release.name,
            manifest_sha256=_digest(manifest_path),
            manifest_size=details.st_size,
            manifest=manifest,
            inventory=inventory,
            directories=directories,
            unit_semantics=semantics,
        )
    except (activation_contract.ContractError, production_adapter.AdapterError, OSError):
        raise RuntimeError("predecessor_release_rejected") from None


def build_release(
    *,
    core_root: Path,
    deploy_root: Path,
    output_root: Path,
    predecessor_release: Path,
    core_commit: str,
    deploy_commit: str,
) -> dict[str, object]:
    if not SAFE_COMMIT.fullmatch(core_commit) or not SAFE_COMMIT.fullmatch(deploy_commit):
        raise RuntimeError("source_commit_rejected")
    if output_root.exists() or output_root.is_symlink():
        raise RuntimeError("output_exists")
    core_tree = _git(core_root, "rev-parse", f"{core_commit}^{{tree}}")
    deploy_tree = _git(deploy_root, "rev-parse", f"{deploy_commit}^{{tree}}")
    source_inventory = _source_inventory(deploy_root, deploy_commit)
    core_inventory = _core_source_inventory(core_root, core_commit)
    output_root.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="p08-engine-build-", dir=output_root.parent) as temp:
        legacy_output = Path(temp) / "legacy"
        legacy_predecessor = (
            predecessor_release.parent
            / legacy_builder.existing_state_upgrade.PREDECESSOR_RELEASE_DIGEST
        )
        legacy_manifest = legacy_builder.build_release(
            core_root=core_root,
            deploy_root=deploy_root,
            output_root=legacy_output,
            predecessor_release=legacy_predecessor,
            core_commit=core_commit,
            deploy_commit=deploy_commit,
        )
        legacy_manifest_path = legacy_output / "manifest.json"
        if legacy_manifest_path.read_bytes() != _canonical(legacy_manifest):
            raise RuntimeError("legacy_manifest_rejected")
        legacy_manifest_path.unlink()
        for relative in ENGINE_FILES:
            _copy_file(deploy_root / relative, legacy_output / relative)
        _materialize_windows_entry(deploy_root, legacy_output)
        compatibility = {
            "predecessor": _predecessor_binding(predecessor_release),
            "p07": _p07_binding(deploy_root),
            "p10b": _core_continuity_binding(legacy_output, core_commit, core_tree),
            "legacy_release_contract_digest": activation_contract.digest_value(
                {
                    key: legacy_manifest[key]
                    for key in sorted(legacy_manifest)
                    if key != "files"
                }
            ),
        }
        contract = activation_contract.compile_contract(
            core_root=str(core_root),
            deploy_root=str(deploy_root),
            core_commit=core_commit,
            core_tree=core_tree,
            deploy_commit=deploy_commit,
            deploy_tree=deploy_tree,
            source_inventory=source_inventory,
            core_inventory=core_inventory,
            unit_semantics=activation_contract.build_unit_semantics(
                (deploy_root / "systemd/myuna-active-temporal-context-v1.service").read_bytes(),
                (deploy_root / "systemd/myuna-active-temporal-context-v1.socket").read_bytes(),
            ),
            compatibility=compatibility,
            interpreter=_interpreter_identity(),
            runtime_identity={
                "uid": os.getuid(),
                "gid": os.getgid(),
                "groups": sorted(set(os.getgroups())),
            },
        )
        contract_root = legacy_output / "contracts"
        contract_root.mkdir(mode=0o755)
        contract_path = contract_root / "P08_ACTIVATION_CONTRACT.json"
        lineage_path = contract_root / "P08_LEGACY_LINEAGE_INDEX.json"
        contract_path.write_bytes(activation_contract.canonical_bytes(contract))
        lineage_path.write_bytes(
            activation_contract.canonical_bytes(contract["lineage"])
        )
        os.chmod(contract_path, 0o644)
        os.chmod(lineage_path, 0o644)
        _normalize_directory_modes(legacy_output)
        files = legacy_builder._inventory(legacy_output)
        manifest = {
            **legacy_manifest,
            "schema": SCHEMA,
            "activation_engine_contract": activation_contract.release_manifest_binding(
                contract
            ),
            "legacy_activation_architecture_authoritative": False,
            "files": files,
        }
        manifest_path = legacy_output / "manifest.json"
        manifest_raw = _canonical(manifest)
        manifest_path.write_bytes(manifest_raw)
        os.chmod(manifest_path, 0o644)
        manifest_details = manifest_path.lstat()
        if (
            not stat.S_ISREG(manifest_details.st_mode)
            or manifest_details.st_nlink != 1
            or stat.S_IMODE(manifest_details.st_mode) != 0o644
            or manifest_details.st_size != len(manifest_raw)
            or manifest_path.read_bytes() != manifest_raw
        ):
            raise RuntimeError("release_manifest_write_rejected")
        os.replace(legacy_output, output_root)
        return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core-root", type=Path, required=True)
    parser.add_argument("--deploy-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--predecessor-release", type=Path, required=True)
    parser.add_argument("--core-commit", required=True)
    parser.add_argument("--deploy-commit", required=True)
    values = parser.parse_args()
    build_release(
        core_root=values.core_root.resolve(),
        deploy_root=values.deploy_root.resolve(),
        output_root=values.output_root.resolve(),
        predecessor_release=values.predecessor_release.resolve(),
        core_commit=values.core_commit,
        deploy_commit=values.deploy_commit,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
