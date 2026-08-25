#!/usr/bin/env python3
"""Build deterministic, inactive P07 Core and Telegram runtime releases."""

from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile

from core_release_selector import compute_tree_digest
from p09_v7_phase1_packaging_contract import (
    SUPPORTED_RUNTIME_PROFILES as V7_RUNTIME_PROFILES,
    V7PackagingContractRejected,
    contract_payload as v7_contract_payload,
    core_files_for as v7_core_files_for,
    core_root_modules_for as v7_core_root_modules_for,
    projection_files_for as v7_projection_files_for,
    validate_core_source as validate_v7_core_source,
)
import p07_owner_private_memory_production_plan as production_plan
import p07_owner_private_memory_runtime_artifact_v1 as runtime_artifact
import p07_transactional_plugin_artifact_v1 as plugin_artifact


SCHEMA = "myuna.p07-hybrid-live-build.v1"
RUNTIME_SCHEMA = "myuna.p07-hybrid-telegram-runtime.v2"
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_RUNTIME_OVERLAYS = (
    "degradation_shadow_enqueue.py",
    "external_context_epoch.py",
    "external_context_epoch_v3.py",
    "fault_incident_v1.py",
    "gateway_degradation_protocol.py",
    "gateway_enqueue.py",
    "gateway_post_reply.py",
    "incident_history_runtime_adapter_v1.py",
    "incident_history_v1.py",
    "p08_temporal_gateway_v1.py",
    "p07_d_release_set.py",
    "p07_d_runtime_readiness.py",
    "p07_d_summary_worker.py",
    "telegram_owner_runtime_gateway.py",
    "telegram_runtime_config.py",
    "turn_pacing_policy.py",
    "user_visible_fault_v1.py",
)
_RUNTIME_CORE_ROOT_MODULES = (
    "myuna_core",
    "myuna_core.authenticated_conversation",
    "myuna_core.channel_gateway",
    "myuna_core.identity",
    "myuna_core.external_context.contracts",
    "myuna_core.external_context.lifecycle_v3",
    "myuna_core.external_context.policy_overlay",
    "myuna_core.external_context.release_set",
    "myuna_core.external_context.safety",
)
_IMPORT_CLOSURE_ALGORITHM = "python-ast-local-import-closure-v1"
_BASELINE_RUNTIME_PROFILE = "p07-hybrid-v2"
_OWNER_PRIVATE_MEMORY_RUNTIME_PROFILE = "p07-owner-private-memory-v1"
_OWNER_PRIVATE_MEMORY_OVERLAYS = _RUNTIME_OVERLAYS + (
    "p07_owner_day_diary_v2.py",
    "p07_owner_private_memory_runtime_v1.py",
    "p07_reflective_diary_worker_v1.py",
)
_OWNER_PRIVATE_MEMORY_CONTRACT = runtime_artifact.MEMORY_CONTRACT
_VERIFIED_CORE_TEST_COUNT = 908
_FORBIDDEN_RUNTIME_CORE_PREFIXES = (
    "myuna_core.active_temporal_context",
    "myuna_core.capability_runtime",
    "myuna_core.owner_memory",
    "myuna_core.providers",
    "myuna_core.session_context",
    "myuna_core.trusted_time",
)


class BuildRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii") + b"\n"


def digest(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def git(source: Path, *arguments: str, binary: bool = False) -> bytes | str:
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
        timeout=120,
    )
    if completed.returncode != 0:
        raise BuildRejected("git_source_rejected")
    return completed.stdout if binary else completed.stdout.decode("ascii").strip()


def validate_commit(source: Path, expected: str) -> None:
    if _COMMIT.fullmatch(expected) is None:
        raise BuildRejected("source_commit_rejected")
    if git(source, "rev-parse", "HEAD") != expected:
        raise BuildRejected("source_head_drifted")
    if git(source, "status", "--porcelain"):
        raise BuildRejected("source_tree_dirty")


def _module_source(core_source: Path, module: str) -> Path | None:
    if module != "myuna_core" and not module.startswith("myuna_core."):
        return None
    relative = Path(*module.split("."))
    package = core_source / "src" / relative / "__init__.py"
    source = core_source / "src" / relative.with_suffix(".py")
    matches = [path for path in (package, source) if path.is_file()]
    if len(matches) > 1:
        raise BuildRejected("runtime_import_module_ambiguous")
    return matches[0] if matches else None


def _module_name(core_source: Path, source: Path) -> tuple[str, bool]:
    try:
        relative = source.relative_to(core_source / "src")
    except ValueError as exc:
        raise BuildRejected("runtime_import_source_rejected") from exc
    if source.name == "__init__.py":
        parts = relative.parent.parts
        is_package = True
    else:
        parts = (*relative.parent.parts, source.stem)
        is_package = False
    if not parts or parts[0] != "myuna_core":
        raise BuildRejected("runtime_import_source_rejected")
    return ".".join(parts), is_package


def _package_modules(module: str) -> tuple[str, ...]:
    parts = module.split(".")
    return tuple(".".join(parts[:index]) for index in range(1, len(parts)))


def _import_from_base(
    current_module: str,
    *,
    is_package: bool,
    imported_module: str | None,
    level: int,
) -> str:
    if level == 0:
        return imported_module or ""
    package = current_module if is_package else current_module.rpartition(".")[0]
    parts = package.split(".") if package else []
    ascend = level - 1
    if ascend >= len(parts):
        raise BuildRejected("runtime_relative_import_rejected")
    prefix = parts[: len(parts) - ascend]
    if imported_module:
        prefix.extend(imported_module.split("."))
    return ".".join(prefix)


def _local_imports(core_source: Path, source: Path) -> set[str]:
    try:
        tree = ast.parse(source.read_text("utf-8"), filename=source.as_posix())
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise BuildRejected("runtime_import_parse_rejected") from exc
    current_module, is_package = _module_name(core_source, source)
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(
                alias.name
                for alias in node.names
                if alias.name == "myuna_core" or alias.name.startswith("myuna_core.")
            )
        elif isinstance(node, ast.ImportFrom):
            base = _import_from_base(
                current_module,
                is_package=is_package,
                imported_module=node.module,
                level=node.level,
            )
            if base == "myuna_core" or base.startswith("myuna_core."):
                imports.add(base)
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    candidate = f"{base}.{alias.name}"
                    if _module_source(core_source, candidate) is not None:
                        imports.add(candidate)
        elif isinstance(node, ast.Call) and node.args:
            function = node.func
            dynamic_import = (
                isinstance(function, ast.Name) and function.id == "__import__"
            ) or (
                isinstance(function, ast.Attribute)
                and function.attr == "import_module"
            )
            argument = node.args[0]
            if (
                dynamic_import
                and isinstance(argument, ast.Constant)
                and isinstance(argument.value, str)
                and (
                    argument.value == "myuna_core"
                    or argument.value.startswith("myuna_core.")
                )
            ):
                imports.add(argument.value)
    return imports


def runtime_overlay_core_root_modules(
    source: Path,
    core_source: Path,
    overlays: tuple[str, ...],
) -> tuple[str, ...]:
    """Derive Core roots from the exact selected Deploy runtime overlays."""

    roots: set[str] = set()
    for name in overlays:
        overlay = source / "scripts" / name
        if overlay.is_symlink() or not overlay.is_file():
            raise BuildRejected("runtime_overlay_source_rejected")
        try:
            tree = ast.parse(overlay.read_text("utf-8"), filename=overlay.as_posix())
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise BuildRejected("runtime_import_parse_rejected") from exc
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(
                    alias.name
                    for alias in node.names
                    if alias.name == "myuna_core"
                    or alias.name.startswith("myuna_core.")
                )
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if base == "myuna_core" or base.startswith("myuna_core."):
                    roots.add(base)
                    for alias in node.names:
                        if alias.name == "*":
                            continue
                        candidate = f"{base}.{alias.name}"
                        if _module_source(core_source, candidate) is not None:
                            roots.add(candidate)
            elif isinstance(node, ast.Call) and node.args:
                function = node.func
                dynamic_import = (
                    isinstance(function, ast.Name) and function.id == "__import__"
                ) or (
                    isinstance(function, ast.Attribute)
                    and function.attr == "import_module"
                )
                argument = node.args[0]
                if (
                    dynamic_import
                    and isinstance(argument, ast.Constant)
                    and isinstance(argument.value, str)
                    and (
                        argument.value == "myuna_core"
                        or argument.value.startswith("myuna_core.")
                    )
                ):
                    roots.add(argument.value)
    if not roots:
        raise BuildRejected("runtime_import_closure_rejected")
    return tuple(sorted(roots))


def runtime_core_import_closure(
    core_source: Path,
    *,
    root_modules: tuple[str, ...] = _RUNTIME_CORE_ROOT_MODULES,
    forbidden_prefixes: tuple[str, ...] = _FORBIDDEN_RUNTIME_CORE_PREFIXES,
) -> tuple[str, ...]:
    pending = list(root_modules)
    modules: set[str] = set()
    while pending:
        module = pending.pop()
        if any(
            module == prefix or module.startswith(f"{prefix}.")
            for prefix in forbidden_prefixes
        ):
            raise BuildRejected("runtime_import_scope_rejected")
        candidates = (*_package_modules(module), module)
        for candidate in candidates:
            if candidate in modules:
                continue
            source = _module_source(core_source, candidate)
            if source is None:
                raise BuildRejected("runtime_import_closure_rejected")
            modules.add(candidate)
            pending.extend(sorted(_local_imports(core_source, source), reverse=True))
    files = {
        _module_source(core_source, module).relative_to(core_source / "src").as_posix()
        for module in modules
    }
    return tuple(sorted(files))


def validate_declared_runtime_core_files(
    core_source: Path,
    declared: tuple[str, ...],
) -> tuple[str, ...]:
    closure = runtime_core_import_closure(core_source)
    if set(declared) != set(closure):
        raise BuildRejected("runtime_import_closure_rejected")
    return closure


def _tree_file_inventory(root: Path) -> dict[str, dict[str, object]]:
    inventory: dict[str, dict[str, object]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise BuildRejected("release_type_rejected")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            if relative == "P07_HYBRID_MANIFEST.json":
                continue
            payload = path.read_bytes()
            inventory[relative] = {"sha256": digest(payload), "size": len(payload)}
    return inventory


def _strip_python_bytecode_from_staging(root: Path) -> None:
    """Remove non-source Python cache artifacts from a private build staging tree."""

    paths = sorted(root.rglob("*"), key=lambda path: len(path.parts), reverse=True)
    for path in paths:
        if path.is_symlink():
            continue
        if path.is_file() and path.suffix in {".pyc", ".pyo"}:
            path.unlink()
        elif path.is_dir() and path.name == "__pycache__":
            shutil.rmtree(path)


def _tree_file_inventory_with_mode(root: Path) -> dict[str, dict[str, object]]:
    inventory = _tree_file_inventory(root)
    return {
        relative: {
            **row,
            "mode": f"{os.stat(root / relative, follow_symlinks=False).st_mode & 0o7777:04o}",
        }
        for relative, row in inventory.items()
    }


def _safe_archive_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = archive.getmembers()
    if not members:
        raise BuildRejected("core_archive_empty")
    for member in members:
        relative = PurePosixPath(member.name)
        if relative.is_absolute() or ".." in relative.parts:
            raise BuildRejected("core_archive_path_rejected")
        if not (member.isdir() or member.isfile()):
            raise BuildRejected("core_archive_type_rejected")
    return members


def _secure_tree(root: Path, *, directory_mode: int, file_mode: int) -> None:
    for path in (root, *root.rglob("*")):
        if path.is_symlink():
            raise BuildRejected("release_symlink_rejected")
        if not (path.is_dir() or path.is_file()):
            raise BuildRejected("release_type_rejected")
        path.chmod(directory_mode if path.is_dir() else file_mode)


def build_core(source: Path, source_commit: str, output: Path) -> dict[str, object]:
    validate_commit(source, source_commit)
    archive_bytes = git(source, "archive", "--format=tar", source_commit, binary=True)
    output.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".p07-core-", dir=output))
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
            archive.extractall(temporary, members=_safe_archive_members(archive))
        tree_sha256, file_count = compute_tree_digest(temporary)
        destination = output / tree_sha256
        artifact = canonical(
            {
                "schema": "myuna.core-source-artifact.p07-hybrid-v1",
                "source_commit": source_commit,
                "tree_digest_algorithm": "myuna-path-content-tree-sha256-v1",
                "tree_sha256": tree_sha256,
                "file_count": file_count,
                "verification": {
                    "core_tests": _VERIFIED_CORE_TEST_COUNT,
                    "model_calls": 0,
                    "private_content_read": False,
                    "profile_content_recorded": False,
                },
            }
        )
        receipt = canonical(
            {
                "schema": "myuna.core-release.inactive-installation.v1",
                "status": "built_inactive_not_selected",
                "source_commit": source_commit,
                "tree_sha256": tree_sha256,
                "file_count": file_count,
                "artifact_manifest_sha256": digest(artifact),
                "ownership": "root:myuna",
                "directory_mode": "0550",
                "file_mode": "0440",
            }
        )
        evidence = canonical(
            {
                "schema": SCHEMA,
                "kind": "core",
                "source_commit": source_commit,
                "tree_sha256": tree_sha256,
                "file_count": file_count,
                "artifact_manifest_sha256": digest(artifact),
                "installation_receipt_sha256": digest(receipt),
            }
        )
        if destination.exists():
            if compute_tree_digest(destination) != (tree_sha256, file_count):
                raise BuildRejected("existing_core_candidate_drifted")
            shutil.rmtree(temporary)
        else:
            _secure_tree(temporary, directory_mode=0o550, file_mode=0o440)
            os.replace(temporary, destination)
        (output / f"{tree_sha256}.artifact.json").write_bytes(artifact)
        (output / f"{tree_sha256}.receipt.json").write_bytes(receipt)
        (output / f"{tree_sha256}.evidence.json").write_bytes(evidence)
        return json.loads(evidence)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def build_runtime(
    source: Path,
    source_commit: str,
    core_source: Path,
    core_commit: str,
    base: Path,
    output: Path,
    runtime_profile: str = _BASELINE_RUNTIME_PROFILE,
) -> dict[str, object]:
    validate_commit(source, source_commit)
    validate_commit(core_source, core_commit)
    if (
        base.is_symlink()
        or not base.is_dir()
        or _DIGEST.fullmatch(base.name) is None
    ):
        raise BuildRejected("runtime_base_rejected")
    if runtime_profile == _BASELINE_RUNTIME_PROFILE:
        core_roots = _RUNTIME_CORE_ROOT_MODULES
        projection_files: tuple[str, ...] = ()
        runtime_overlays = _RUNTIME_OVERLAYS
        forbidden_prefixes = _FORBIDDEN_RUNTIME_CORE_PREFIXES
    elif runtime_profile == _OWNER_PRIVATE_MEMORY_RUNTIME_PROFILE:
        projection_files = ()
        runtime_overlays = _OWNER_PRIVATE_MEMORY_OVERLAYS
        core_roots = runtime_overlay_core_root_modules(
            source,
            core_source,
            runtime_overlays,
        )
        forbidden_prefixes = tuple(
            prefix
            for prefix in _FORBIDDEN_RUNTIME_CORE_PREFIXES
            if prefix
            not in {
                "myuna_core.active_temporal_context",
                "myuna_core.capability_runtime",
                "myuna_core.trusted_time",
            }
        )
    elif runtime_profile in V7_RUNTIME_PROFILES:
        try:
            validate_v7_core_source(
                core_source,
                core_commit,
                runtime_profile=runtime_profile,
            )
        except V7PackagingContractRejected as exc:
            raise BuildRejected(exc.code) from exc
        core_roots = v7_core_root_modules_for(runtime_profile)
        projection_files = v7_projection_files_for(runtime_profile)
        runtime_overlays = _RUNTIME_OVERLAYS
        forbidden_prefixes = _FORBIDDEN_RUNTIME_CORE_PREFIXES
    else:
        raise BuildRejected("runtime_profile_rejected")
    core_files = runtime_core_import_closure(
        core_source,
        root_modules=core_roots,
        forbidden_prefixes=forbidden_prefixes,
    )
    if (
        runtime_profile in V7_RUNTIME_PROFILES
        and core_files != v7_core_files_for(runtime_profile)
    ):
        raise BuildRejected("v7_runtime_core_inventory_rejected")
    output.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".p07-runtime-", dir=output))
    try:
        shutil.rmtree(temporary)
        shutil.copytree(base, temporary)
        _strip_python_bytecode_from_staging(temporary)
        bundled_core = temporary / "runtime/myuna_core"
        if bundled_core.exists():
            if bundled_core.is_symlink() or not bundled_core.is_dir():
                raise BuildRejected("runtime_core_overlay_rejected")
            shutil.rmtree(bundled_core)
        for name in runtime_overlays:
            target = temporary / "runtime" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((source / "scripts" / name).read_bytes())
        for relative in projection_files:
            target = temporary / "runtime" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((source / "scripts" / relative).read_bytes())
        for relative in core_files:
            target = temporary / "runtime" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((core_source / "src" / relative).read_bytes())
        old_manifest = temporary / "P07_HYBRID_MANIFEST.json"
        if old_manifest.exists() or old_manifest.is_symlink():
            if old_manifest.is_symlink() or not old_manifest.is_file():
                raise BuildRejected("runtime_manifest_type_rejected")
            old_manifest.unlink()
        inventory = _tree_file_inventory(temporary)
        if runtime_profile == _OWNER_PRIVATE_MEMORY_RUNTIME_PROFILE:
            inventory = {
                relative: {**row, "mode": runtime_artifact.FILE_MODE}
                for relative, row in inventory.items()
            }
        unsigned = {
            "schema": RUNTIME_SCHEMA,
            "base_release_digest": base.name,
            "source_core_commit": core_commit,
            "source_deploy_commit": source_commit,
            "files": inventory,
            "core_import_closure": {
                "algorithm": _IMPORT_CLOSURE_ALGORITHM,
                "roots": list(core_roots),
                "files": list(core_files),
            },
        }
        if runtime_profile in V7_RUNTIME_PROFILES:
            unsigned["runtime_profile"] = runtime_profile
            unsigned["v7_phase1_contract"] = v7_contract_payload(runtime_profile)
        elif runtime_profile == _OWNER_PRIVATE_MEMORY_RUNTIME_PROFILE:
            source_core_tree = str(git(core_source, "rev-parse", "HEAD^{tree}"))
            source_deploy_tree = str(git(source, "rev-parse", "HEAD^{tree}"))
            binding = plugin_artifact.derive_binding(
                source,
                expected_commit=source_commit,
                expected_tree=source_deploy_tree,
            )
            unsigned["runtime_profile"] = runtime_profile
            unsigned["owner_private_memory_contract"] = dict(
                _OWNER_PRIVATE_MEMORY_CONTRACT
            )
            unsigned["source_core_tree"] = source_core_tree
            unsigned["source_deploy_tree"] = source_deploy_tree
            unsigned["owner_private_memory_runtime_binding"] = (
                runtime_artifact.build_binding(
                    source_core_commit=core_commit,
                    source_core_tree=source_core_tree,
                    source_deploy_commit=source_commit,
                    source_deploy_tree=source_deploy_tree,
                    base_release_digest=base.name,
                    file_inventory=inventory,
                    plugin_binding=binding,
                    memory_contract=_OWNER_PRIVATE_MEMORY_CONTRACT,
                    source_policy=production_plan.source_policy(),
                    program_boundaries=production_plan.source_boundaries(),
                )
            )
        release_digest = digest(canonical(unsigned))
        manifest = canonical({**unsigned, "release_digest": release_digest})
        destination = output / release_digest
        (temporary / "P07_HYBRID_MANIFEST.json").write_bytes(manifest)
        _secure_tree(temporary, directory_mode=0o550, file_mode=0o440)
        if destination.exists():
            installed = destination / "P07_HYBRID_MANIFEST.json"
            installed_inventory = (
                _tree_file_inventory_with_mode(destination)
                if runtime_profile == _OWNER_PRIVATE_MEMORY_RUNTIME_PROFILE
                else _tree_file_inventory(destination)
            )
            if (
                not installed.is_file()
                or installed.is_symlink()
                or installed.read_bytes() != manifest
                or installed_inventory != inventory
            ):
                raise BuildRejected("existing_runtime_candidate_drifted")
            shutil.rmtree(temporary)
        else:
            os.replace(temporary, destination)
        return json.loads(manifest)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core-source", required=True, type=Path)
    parser.add_argument("--core-commit", required=True)
    parser.add_argument("--core-output", required=True, type=Path)
    parser.add_argument("--deploy-source", required=True, type=Path)
    parser.add_argument("--deploy-commit", required=True)
    parser.add_argument("--runtime-base", required=True, type=Path)
    parser.add_argument("--runtime-output", required=True, type=Path)
    parser.add_argument(
        "--runtime-profile",
        choices=(
            _BASELINE_RUNTIME_PROFILE,
            _OWNER_PRIVATE_MEMORY_RUNTIME_PROFILE,
            *V7_RUNTIME_PROFILES,
        ),
        default=_BASELINE_RUNTIME_PROFILE,
    )
    arguments = parser.parse_args()
    try:
        core = build_core(arguments.core_source, arguments.core_commit, arguments.core_output)
        runtime = build_runtime(
            arguments.deploy_source,
            arguments.deploy_commit,
            arguments.core_source,
            arguments.core_commit,
            arguments.runtime_base,
            arguments.runtime_output,
            arguments.runtime_profile,
        )
    except (BuildRejected, OSError, ValueError, tarfile.TarError):
        print(json.dumps({"status": "rejected"}, separators=(",", ":")))
        return 1
    print(
        json.dumps(
            {
                "core_release": core["tree_sha256"],
                "runtime_release": runtime["release_digest"],
                "status": "built_inactive",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
