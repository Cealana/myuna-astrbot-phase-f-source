#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

import p08_existing_state_upgrade_v1 as existing_state_upgrade
import p08_current_selected_upgrade_v1 as current_selected_upgrade
import p08_forward_continuity_orchestration_v1 as forward_continuity
import p08_formal_preflight_launcher_v1 as formal_preflight_launcher
import p08_post_target_action_v1 as post_target_action


SCHEMA = "myuna.p08-active-temporal-code-release.v2"
SAFE_COMMIT = re.compile(r"^[0-9a-f]{40}$")
CORE_FILES = (
    "src/myuna_core/__init__.py",
    "src/myuna_core/audit.py",
    "src/myuna_core/authenticated_conversation.py",
    "src/myuna_core/channel_gateway.py",
    "src/myuna_core/identity.py",
    "src/myuna_core/integrations/__init__.py",
)
CORE_DIRECTORIES = (
    "src/myuna_core/active_temporal_context",
    "src/myuna_core/capability_runtime",
    "src/myuna_core/integrations/openclaw",
    "src/myuna_core/operations",
    "src/myuna_core/trusted_time",
)
DEPLOY_FILES = (
    "systemd/myuna-active-temporal-context-v1.service",
    "systemd/myuna-active-temporal-context-v1.socket",
    "systemd/myuna-active-temporal-context-v1.sysusers.conf",
    "systemd/myuna-active-temporal-context-v1.tmpfiles.conf",
    "scripts/p08_temporal_gateway_v1.py",
    "scripts/p08_temporal_service_v1.py",
    "scripts/p08_existing_state_upgrade_v1.py",
    "scripts/p08_post_target_action_v1.py",
    "scripts/p08_current_selected_upgrade_v1.py",
    "scripts/p08_forward_continuity_orchestration_v1.py",
    "scripts/p08_formal_preflight_launcher_v1.py",
    "scripts/build_p08_active_temporal_release_v2.py",
)
P07_INTEGRATION_FILES = (
    "docs/ADR-087-p07-p08-single-nonce-stage-integration.md",
    "scripts/build_p07_owner_private_memory_transactional_runtime.py",
    "scripts/p07_owner_private_memory_production_plan.py",
    "scripts/p07_owner_private_memory_transactional_runtime.py",
    "tests/test_build_p07_owner_private_memory_transactional_runtime.py",
    "tests/test_p07_owner_private_memory_production_plan.py",
    "tests/test_p07_owner_private_memory_transactional_runtime.py",
)
PROTOCOL_PATH = "src/myuna_core/active_temporal_context/protocol.py"
SERVICE_PATH = "src/myuna_core/active_temporal_context/service.py"
SERVICE_SOURCE_PATH = "scripts/p08_temporal_service_v1.py"
SERVICE_ENTRYPOINT_PATH = "src/p08_temporal_service_v1.py"
EXPECTED_PROTOCOL_SCHEMA = "myuna.active-temporal-context-protocol.v1"
EXPECTED_CONTENT_FREE_STATUS_SCHEMA = "myuna.active-temporal-content-free-status.v1"
MAX_PROTOCOL_BYTES = 262_144


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _copy_file(source: Path, destination: Path) -> None:
    if not source.is_file() or source.is_symlink():
        raise RuntimeError("release_inventory_rejected")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    os.chmod(destination, stat.S_IMODE(source.stat().st_mode))


def _git(
    root: Path,
    arguments: list[str],
    *,
    rejection: str,
) -> str:
    try:
        completed = subprocess.run(
            ["git", "--no-optional-locks", "-C", str(root), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError(rejection) from None
    if len(completed.stdout) > 1_048_576:
        raise RuntimeError(rejection)
    return completed.stdout


def _validate_source_identity(
    *,
    root: Path,
    commit: str,
    pathspecs: tuple[str, ...],
    rejection: str,
) -> set[str]:
    if not root.is_dir() or root.is_symlink():
        raise RuntimeError(rejection)
    top_level = _git(
        root,
        ["rev-parse", "--show-toplevel"],
        rejection=rejection,
    ).strip()
    head = _git(root, ["rev-parse", "HEAD"], rejection=rejection).strip()
    if not top_level or Path(top_level).resolve() != root.resolve() or head != commit:
        raise RuntimeError(rejection)
    status = _git(
        root,
        ["status", "--porcelain=v1", "--untracked-files=all", "--", *pathspecs],
        rejection=rejection,
    )
    if status:
        raise RuntimeError(rejection)
    tracked = {
        line
        for line in _git(
            root,
            ["ls-tree", "-r", "--name-only", commit, "--", *pathspecs],
            rejection=rejection,
        ).splitlines()
        if line
    }
    if not tracked:
        raise RuntimeError(rejection)
    return tracked


def _validate_p07_integration_source_identity(
    *, root: Path, deploy_commit: str, tracked: set[str]
) -> None:
    if any(relative not in tracked for relative in P07_INTEGRATION_FILES):
        raise RuntimeError("p07_integration_source_identity_rejected")
    _git(
        root,
        [
            "merge-base",
            "--is-ancestor",
            current_selected_upgrade.P07_INTEGRATION_DEPLOY_COMMIT,
            deploy_commit,
        ],
        rejection="p07_integration_source_identity_rejected",
    )
    changed = _git(
        root,
        [
            "diff",
            "--name-only",
            current_selected_upgrade.P07_INTEGRATION_DEPLOY_COMMIT,
            deploy_commit,
            "--",
            *P07_INTEGRATION_FILES,
        ],
        rejection="p07_integration_source_identity_rejected",
    )
    if changed:
        raise RuntimeError("p07_integration_source_identity_rejected")


def _literal_string(module: ast.Module, name: str) -> str:
    matches = []
    for node in module.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == name:
            matches.append(node.value)
    if len(matches) != 1:
        raise RuntimeError("protocol_contract_rejected")
    try:
        value = ast.literal_eval(matches[0])
    except (ValueError, SyntaxError):
        raise RuntimeError("protocol_contract_rejected") from None
    if not isinstance(value, str):
        raise RuntimeError("protocol_contract_rejected")
    return value


def _protocol_contract(path: Path) -> dict[str, object]:
    if (
        not path.is_file()
        or path.is_symlink()
        or path.stat().st_size < 1
        or path.stat().st_size > MAX_PROTOCOL_BYTES
    ):
        raise RuntimeError("protocol_contract_rejected")
    try:
        module = ast.parse(path.read_text("utf-8"), filename=PROTOCOL_PATH)
    except (OSError, UnicodeError, SyntaxError):
        raise RuntimeError("protocol_contract_rejected") from None
    operation_nodes = []
    for node in module.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == "_OPERATIONS":
            operation_nodes.append(node.value)
    if len(operation_nodes) != 1:
        raise RuntimeError("protocol_contract_rejected")
    value = operation_nodes[0]
    if (
        not isinstance(value, ast.Call)
        or not isinstance(value.func, ast.Name)
        or value.func.id != "frozenset"
        or len(value.args) != 1
        or value.keywords
    ):
        raise RuntimeError("protocol_contract_rejected")
    try:
        operations = ast.literal_eval(value.args[0])
    except (ValueError, SyntaxError):
        raise RuntimeError("protocol_contract_rejected") from None
    if (
        not isinstance(operations, set)
        or not operations
        or len(operations) > 32
        or any(not isinstance(item, str) for item in operations)
        or "status_content_free" not in operations
    ):
        raise RuntimeError("protocol_contract_rejected")
    protocol_schema = _literal_string(module, "SCHEMA")
    status_schema = _literal_string(module, "CONTENT_FREE_STATUS_SCHEMA")
    if (
        protocol_schema != EXPECTED_PROTOCOL_SCHEMA
        or status_schema != EXPECTED_CONTENT_FREE_STATUS_SCHEMA
    ):
        raise RuntimeError("protocol_contract_rejected")
    return {
        "content_free_status_schema": status_schema,
        "operations": sorted(operations),
        "schema": protocol_schema,
        "sha256": _digest(path),
        "source_path": PROTOCOL_PATH,
    }


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
    predecessor_release: Path,
    core_commit: str,
    deploy_commit: str,
) -> dict[str, object]:
    if not SAFE_COMMIT.fullmatch(core_commit) or not SAFE_COMMIT.fullmatch(deploy_commit):
        raise RuntimeError("source_commit_rejected")
    if core_commit != forward_continuity.CORE_COMMIT:
        raise RuntimeError("core_source_identity_rejected")
    if set(formal_preflight_launcher.CORE_PATHS) != set((*CORE_FILES, *CORE_DIRECTORIES)):
        raise RuntimeError("formal_launcher_source_binding_rejected")
    if set(formal_preflight_launcher.DEPLOY_PATHS) != set(
        (*DEPLOY_FILES, *P07_INTEGRATION_FILES)
    ):
        raise RuntimeError("formal_launcher_source_binding_rejected")
    if output_root.exists() or output_root.is_symlink():
        raise RuntimeError("output_exists")
    core_pathspecs = (*CORE_FILES, *CORE_DIRECTORIES)
    core_tracked = _validate_source_identity(
        root=core_root,
        commit=core_commit,
        pathspecs=core_pathspecs,
        rejection="core_source_identity_rejected",
    )
    deploy_tracked = _validate_source_identity(
        root=deploy_root,
        commit=deploy_commit,
        pathspecs=(*DEPLOY_FILES, *P07_INTEGRATION_FILES),
        rejection="deploy_source_identity_rejected",
    )
    if any(relative not in core_tracked for relative in CORE_FILES):
        raise RuntimeError("core_source_identity_rejected")
    if any(relative not in deploy_tracked for relative in DEPLOY_FILES):
        raise RuntimeError("deploy_source_identity_rejected")
    _validate_p07_integration_source_identity(
        root=deploy_root,
        deploy_commit=deploy_commit,
        tracked=deploy_tracked,
    )
    target_service_unit_sha256 = _digest(
        deploy_root / "systemd/myuna-active-temporal-context-v1.service"
    )
    target_socket_unit_sha256 = _digest(
        deploy_root / "systemd/myuna-active-temporal-context-v1.socket"
    )
    output_root.mkdir(parents=True, mode=0o755)
    try:
        for relative in CORE_FILES:
            _copy_file(core_root / relative, output_root / relative)
        for relative in CORE_DIRECTORIES:
            source_root = core_root / relative
            if not source_root.is_dir() or source_root.is_symlink():
                raise RuntimeError("core_inventory_rejected")
            prefix = relative + "/"
            sources = sorted(
                path
                for path in core_tracked
                if path.startswith(prefix) and path.endswith(".py")
            )
            if not sources:
                raise RuntimeError("core_inventory_rejected")
            for tracked_path in sources:
                _copy_file(
                    core_root / tracked_path,
                    output_root / tracked_path,
                )
        for relative in DEPLOY_FILES:
            _copy_file(deploy_root / relative, output_root / relative)
        _copy_file(
            deploy_root / SERVICE_SOURCE_PATH,
            output_root / SERVICE_ENTRYPOINT_PATH,
        )
        inventory = _inventory(output_root)
        client_path = output_root / "scripts/p08_temporal_gateway_v1.py"
        protocol_path = output_root / PROTOCOL_PATH
        manifest = {
            "schema": SCHEMA,
            "core_commit": core_commit,
            "deploy_commit": deploy_commit,
            "entrypoint": "p08_temporal_service_v1",
            "runtime_profile": "p08-active-temporal-private-v2",
            "state_schema": "myuna.active-temporal-context.v1",
            "trusted_time_schema": "myuna.trusted-time-provider.v1",
            "trusted_time_capability_contract": (
                existing_state_upgrade.trusted_time_capability_contract(
                    output_root
                )
            ),
            "forward_continuity_contract": forward_continuity.contract(),
            "protocol_schema": EXPECTED_PROTOCOL_SCHEMA,
            "protocol_contract": _protocol_contract(protocol_path),
            "service_contract": existing_state_upgrade.server_rejection_contract(
                output_root
            ),
            "gateway_client": {
                "source_path": "scripts/p08_temporal_gateway_v1.py",
                "runtime_path": "runtime/p08_temporal_gateway_v1.py",
                "sha256": _digest(client_path),
            },
            "gateway_status_runtime": existing_state_upgrade.status_runtime_contract(
                output_root
            ),
            "post_target_action_contract": {
                "action_state_binding_schema": "myuna.p08-post-target-action-state-binding.v1",
                "incident_max_actions": 1,
                "live_execute_implemented": True,
                "max_attempts_per_action_plan": 1,
                "readiness_schema": "myuna.p08-post-target-action-readiness.v1",
                "repair_plan_schema": "myuna.p08-post-target-repair-plan.v3",
                "rollback_plan_schema": "myuna.p08-post-target-rollback-plan.v3",
                "sha256": _digest(
                    output_root / "scripts/p08_post_target_action_v1.py"
                ),
                "source_path": "scripts/p08_post_target_action_v1.py",
                "protocol_acceptance": post_target_action.protocol_acceptance_contract(
                    output_root
                ),
            },
            "formal_preflight_launcher_contract": (
                formal_preflight_launcher.build_manifest_contract(
                    release_root=output_root,
                    core_root=core_root,
                    deploy_root=deploy_root,
                    core_commit=core_commit,
                    deploy_commit=deploy_commit,
                )
            ),
            "p07_single_nonce_integration": (
                current_selected_upgrade.p07_single_nonce_integration_contract()
            ),
            "current_selected_upgrade_contract": current_selected_upgrade.release_contract(
                output_root
            ),
            "upgrade_compatibility": existing_state_upgrade.derive_compatibility_closure(
                predecessor_release=predecessor_release,
                target_root=output_root,
                target_service_unit_sha256=target_service_unit_sha256,
                target_socket_unit_sha256=target_socket_unit_sha256,
            ),
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
