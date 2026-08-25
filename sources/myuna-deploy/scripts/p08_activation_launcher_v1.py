#!/usr/bin/env python3
"""Unified raw-free launcher/capture boundary for every activation role."""
from __future__ import annotations

from hashlib import sha256
import importlib.machinery
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time
from typing import Callable, Mapping

import p08_activation_contract_v1 as contract_v1


MAX_STDOUT_BYTES = 1_048_576
MAX_STDERR_BYTES = 65_536
MAX_PROGRESS_BYTES = 65_536
EXIT_CLASSES = frozenset(
    {
        "exit",
        "signal",
        "hard_timeout",
        "no_progress_timeout",
        "progress_invalid",
        "stdout_oversize",
        "stderr_oversize",
        "progress_oversize",
    }
)


class LauncherError(RuntimeError):
    pass


def boot_identity_digest() -> str:
    try:
        raw = Path("/proc/sys/kernel/random/boot_id").read_bytes()
        value = raw.decode("ascii", "strict").strip()
    except (OSError, UnicodeError):
        raise LauncherError("boot_identity_rejected") from None
    compact = value.replace("-", "")
    if (
        len(value) != 36
        or [value[index] for index in (8, 13, 18, 23)] != ["-"] * 4
        or len(compact) != 32
        or any(character not in "0123456789abcdef" for character in compact)
    ):
        raise LauncherError("boot_identity_rejected")
    return sha256(value.encode("ascii")).hexdigest()


def _digest(path: Path) -> str:
    return sha256(_read_regular_bytes(path)).hexdigest()


def _read_regular_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise LauncherError("invocation_path_rejected") from None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise LauncherError("invocation_path_rejected")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1_048_576))
            if not chunk:
                raise LauncherError("invocation_path_rejected")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise LauncherError("invocation_path_rejected")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        final = path.lstat()
    except OSError:
        raise LauncherError("invocation_path_rejected") from None
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_uid,
        value.st_gid,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if identity(before) != identity(after) or identity(after) != identity(final):
        raise LauncherError("invocation_path_rejected")
    return b"".join(chunks)


def _regular_file(path: Path, *, expected_sha256: str | None = None) -> None:
    try:
        details = path.lstat()
    except OSError:
        raise LauncherError("invocation_path_rejected") from None
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        raise LauncherError("invocation_path_rejected")
    payload = _read_regular_bytes(path)
    if len(payload) != details.st_size:
        raise LauncherError("invocation_path_rejected")
    if expected_sha256 is not None and sha256(payload).hexdigest() != expected_sha256:
        raise LauncherError("invocation_path_rejected")


def _verify_python_import_collision(path: Path) -> None:
    if path.suffix != ".py" or path.name == "__init__.py":
        return
    stem = path.stem
    forbidden_names = {stem + ".pyc", stem + ".pyo"}
    forbidden_names.update(
        stem + suffix for suffix in importlib.machinery.EXTENSION_SUFFIXES
    )
    try:
        for sibling in path.parent.iterdir():
            if sibling.name in forbidden_names or sibling.name == stem:
                raise LauncherError("source_import_substitution_rejected")
    except OSError:
        raise LauncherError("source_inventory_rejected") from None


def _verify_interpreter(value: Mapping[str, object]) -> None:
    invocation = Path(str(value["invocation_path"]))
    try:
        link = invocation.lstat()
    except OSError:
        raise LauncherError("interpreter_identity_rejected") from None
    if (
        not stat.S_ISLNK(link.st_mode)
        or os.readlink(invocation) != value["link_target"]
    ):
        raise LauncherError("interpreter_identity_rejected")
    resolved = Path(str(value["resolved_path"]))
    try:
        details = resolved.lstat()
    except OSError:
        raise LauncherError("interpreter_identity_rejected") from None
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_nlink != value["nlink"]
        or stat.S_IMODE(details.st_mode) != value["mode"]
        or details.st_uid != value["uid"]
        or details.st_gid != value["gid"]
        or details.st_size != value["size"]
        or invocation.resolve() != resolved
        or _digest(resolved) != value["sha256"]
    ):
        raise LauncherError("interpreter_identity_rejected")


def verify_runtime_inventory(
    contract: Mapping[str, object],
    runtime: Path,
    inventory: list[dict[str, object]],
    directories: list[dict[str, object]],
) -> Path:
    """Verify one exact, bytecode-free materialized runtime without a plan."""
    validated_contract = contract_v1.validate_contract(contract)
    if not runtime.is_absolute() or contract_v1.HEX64.fullmatch(runtime.name) is None:
        raise LauncherError("runtime_package_rejected")
    try:
        root_details = runtime.lstat()
    except OSError:
        raise LauncherError("runtime_package_rejected") from None
    if not stat.S_ISDIR(root_details.st_mode) or stat.S_ISLNK(root_details.st_mode):
        raise LauncherError("runtime_package_rejected")
    expected_files = {str(row["path"]): row for row in inventory}
    expected_directories = {
        str(row["path"]): row for row in directories
    }
    if (
        len(expected_files) != len(inventory)
        or len(expected_directories) != len(directories)
    ):
        raise LauncherError("runtime_package_rejected")
    observed_files: set[str] = set()
    observed_directories = {"."}
    forbidden_names = {"sitecustomize.py", "usercustomize.py"}
    forbidden_suffixes = {".pyc", ".pyo", *importlib.machinery.EXTENSION_SUFFIXES}
    try:
        paths = sorted(runtime.rglob("*"))
    except OSError:
        raise LauncherError("runtime_package_rejected") from None
    for path in paths:
        relative = path.relative_to(runtime).as_posix()
        try:
            details = path.lstat()
        except OSError:
            raise LauncherError("runtime_package_rejected") from None
        if stat.S_ISDIR(details.st_mode) and not stat.S_ISLNK(details.st_mode):
            if path.name == "__pycache__":
                raise LauncherError("runtime_import_substitution_rejected")
            observed_directories.add(relative)
            continue
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise LauncherError("runtime_package_rejected")
        if (
            path.name in forbidden_names
            or path.suffix in forbidden_suffixes
            or "__pycache__" in path.parts
        ):
            raise LauncherError("runtime_import_substitution_rejected")
        row = expected_files.get(relative)
        if row is None:
            raise LauncherError("runtime_package_rejected")
        payload = _read_regular_bytes(path)
        if (
            details.st_size != row["size"]
            or stat.S_IMODE(details.st_mode) != row["mode"]
            or details.st_uid != row["uid"]
            or details.st_gid != row["gid"]
            or sha256(payload).hexdigest() != row["sha256"]
        ):
            raise LauncherError("runtime_package_rejected")
        observed_files.add(relative)
        _verify_python_import_collision(path)
    if observed_files != set(expected_files) or observed_directories != set(
        expected_directories
    ):
        raise LauncherError("runtime_package_rejected")
    for relative, row in expected_directories.items():
        path = runtime if relative == "." else runtime / relative
        details = path.lstat()
        if (
            not stat.S_ISDIR(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or stat.S_IMODE(details.st_mode) != row["mode"]
            or details.st_uid != row["uid"]
            or details.st_gid != row["gid"]
            or details.st_nlink != row["nlink"]
        ):
            raise LauncherError("runtime_package_rejected")
    source_rows = {
        str(row["path"]): row
        for row in validated_contract["engine_source"]["source_inventory"]
    }
    for relative in contract_v1.REQUIRED_ENGINE_SOURCE_PATHS:
        row = expected_files.get(relative)
        source_row = source_rows.get(relative)
        if (
            row is None
            or source_row is None
            or any(row[key] != source_row[key] for key in ("mode", "sha256", "size"))
        ):
            raise LauncherError("runtime_package_rejected")
    return runtime


def _verify_runtime_package(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> Path:
    execution = plan["execution"]
    runtime = Path(str(execution["runtime_package"]["root"]))
    if runtime != Path(str(execution["target_source_path"])):
        raise LauncherError("runtime_package_rejected")
    verified = verify_runtime_inventory(
        contract,
        runtime,
        list(execution["target_inventory"]),
        list(execution["target_directories"]),
    )
    if (
        contract_v1.digest_value(execution["target_inventory"])
        != execution["runtime_package"]["inventory_digest"]
        or contract_v1.digest_value(execution["target_directories"])
        != execution["runtime_package"]["directories_digest"]
    ):
        raise LauncherError("runtime_package_rejected")
    return verified


def _inventory_sha(inventory: list[dict[str, object]], relative: str) -> str:
    matches = [row["sha256"] for row in inventory if row["path"] == relative]
    if len(matches) != 1:
        raise LauncherError("source_entrypoint_rejected")
    return str(matches[0])


def _source_sha(plan: Mapping[str, object], relative: str) -> str:
    return _inventory_sha(list(plan["execution"]["target_inventory"]), relative)


def verify_loaded_runtime_inventory(
    contract: Mapping[str, object],
    runtime: Path,
    inventory: list[dict[str, object]],
    directories: list[dict[str, object]],
    modules: Mapping[str, object],
) -> None:
    """Prove privileged imports against a planless materialized runtime."""
    verify_runtime_inventory(contract, runtime, inventory, directories)
    expected_pythonpath = [str(runtime / "scripts"), str(runtime / "src")]
    if (
        os.environ.get("PYTHONPATH", "").split(os.pathsep) != expected_pythonpath
        or sys.path[:2] != expected_pythonpath
    ):
        raise LauncherError("runtime_import_path_rejected")
    for relative, module in modules.items():
        expected = runtime / relative
        module_file = getattr(module, "__file__", None)
        spec = getattr(module, "__spec__", None)
        loader = getattr(spec, "loader", None)
        if (
            not isinstance(module_file, str)
            or Path(module_file) != expected
            or getattr(spec, "origin", None) != str(expected)
            or not isinstance(loader, importlib.machinery.SourceFileLoader)
            or _digest(expected) != _inventory_sha(inventory, relative)
        ):
            raise LauncherError("runtime_import_identity_rejected")
        cached = getattr(module, "__cached__", None)
        if isinstance(cached, str) and Path(cached).exists():
            raise LauncherError("runtime_import_bytecode_rejected")


def verify_loaded_runtime_modules(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    modules: Mapping[str, object],
) -> None:
    """Prove that privileged imports came from the bound materialized runtime."""
    validated_contract = contract_v1.validate_contract(contract)
    validated_plan = contract_v1.validate_plan(validated_contract, plan)
    runtime = _verify_runtime_package(validated_contract, validated_plan)
    verify_loaded_runtime_inventory(
        validated_contract,
        runtime,
        list(validated_plan["execution"]["target_inventory"]),
        list(validated_plan["execution"]["target_directories"]),
        modules,
    )


def _descriptor_type(descriptor: int) -> str:
    try:
        details = os.fstat(descriptor)
    except OSError:
        return "missing"
    if stat.S_ISFIFO(details.st_mode):
        return "fifo"
    if stat.S_ISCHR(details.st_mode):
        return "character"
    if stat.S_ISREG(details.st_mode):
        return "regular"
    if stat.S_ISSOCK(details.st_mode):
        return "socket"
    return "other"


def _verify_windows_wsl_transport(contract: Mapping[str, object]) -> dict[str, object]:
    validated = contract_v1.validate_contract(contract)
    transport = dict(validated["launcher"]["top_level_entry"]["transport"])
    if transport != contract_v1.PRODUCTION_WINDOWS_WSL_TRANSPORT:
        raise LauncherError("windows_wsl_transport_rejected")
    path = Path(str(transport["guest_visible_path"]))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise LauncherError("windows_wsl_transport_rejected") from None
    digest = sha256()
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != transport["guest_mode"]
            or before.st_uid != transport["guest_uid"]
            or before.st_gid != transport["guest_gid"]
            or before.st_nlink != transport["guest_nlink"]
            or before.st_size != transport["size"]
        ):
            raise LauncherError("windows_wsl_transport_rejected")
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1_048_576))
            if not chunk:
                raise LauncherError("windows_wsl_transport_rejected")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise LauncherError("windows_wsl_transport_rejected")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    final = path.lstat()
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if (
        identity(before) != identity(after)
        or identity(after) != identity(final)
        or digest.hexdigest() != transport["sha256"]
        or os.uname().release != transport["kernel_release"]
    ):
        raise LauncherError("windows_wsl_transport_rejected")
    return transport


def windows_host_entry_identity(
    contract: Mapping[str, object],
    *,
    acceptance_scope_digest: str,
    backend: str,
    root: Path,
    target_source: Path,
) -> str:
    validated = contract_v1.validate_contract(contract)
    top = validated["launcher"]["top_level_entry"]
    body = "\n".join(
        (
            "myuna.p08-windows-wsl-entry-scope.v1",
            str(validated["contract_digest"]),
            acceptance_scope_digest,
            backend,
            str(root),
            str(target_source),
            str(top["host_launcher"]["sha256"]),
            str(top["transport"]["sha256"]),
            "",
        )
    )
    return sha256(body.encode("utf-8")).hexdigest()


def _top_level_environment(
    target_source: Path, host_entry_identity: str
) -> dict[str, str]:
    return {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "MYUNA_P08_WINDOWS_HOST_ENTRY_IDENTITY": host_entry_identity,
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": os.pathsep.join(
            (str(target_source / "scripts"), str(target_source / "src"))
        ),
    }


def _top_level_argv(
    contract: Mapping[str, object],
    *,
    contract_path: Path,
    root: Path,
    backend: str,
    target_source: Path,
    acceptance_scope_digest: str,
) -> list[str]:
    return [
        str(contract["interpreter"]["invocation_path"]),
        "-B",
        "-P",
        "-S",
        "-m",
        Path(contract_v1.TOP_LEVEL_ENTRY_PATH).stem,
        "--activation-contract",
        str(contract_path),
        "--activation-root",
        str(root),
        "--activation-backend",
        backend,
        "--activation-target-source",
        str(target_source),
        "--acceptance-scope-digest",
        acceptance_scope_digest,
    ]


def _top_level_child_argv(
    contract: Mapping[str, object],
    *,
    contract_path: Path,
    root: Path,
    backend: str,
    target_source: Path,
    acceptance_scope_digest: str,
) -> list[str]:
    return [
        str(contract["interpreter"]["invocation_path"]),
        "-B",
        "-P",
        "-S",
        "-m",
        Path(contract_v1.SUPERVISOR_BOOTSTRAP_PATH).stem,
        "--activation-contract",
        str(contract_path),
        "--activation-root",
        str(root),
        "--activation-backend",
        backend,
        "--activation-target-source",
        str(target_source),
        "--acceptance-scope-digest",
        acceptance_scope_digest,
    ]


def build_windows_wsl_transport_argv(
    contract: Mapping[str, object],
    *,
    contract_path: Path,
    root: Path,
    backend: str,
    target_source: Path,
    acceptance_scope_digest: str,
) -> list[str]:
    validated = contract_v1.validate_contract(contract)
    transport = dict(validated["launcher"]["top_level_entry"]["transport"])
    host_entry_identity = windows_host_entry_identity(
        validated,
        acceptance_scope_digest=acceptance_scope_digest,
        backend=backend,
        root=root,
        target_source=target_source,
    )
    environment = _top_level_environment(target_source, host_entry_identity)
    guest = [
        "/usr/bin/env",
        "-i",
        *(f"{key}={environment[key]}" for key in sorted(environment)),
        *_top_level_argv(
            validated,
            contract_path=contract_path,
            root=root,
            backend=backend,
            target_source=target_source,
            acceptance_scope_digest=acceptance_scope_digest,
        ),
    ]
    return [
        str(transport["windows_path"]),
        "--distribution",
        str(transport["distribution"]),
        "--user",
        "root",
        "--cd",
        str(target_source),
        "--exec",
        *guest,
    ]


def build_top_level_entry_intent(
    contract: Mapping[str, object],
    *,
    contract_path: Path,
    root: Path,
    backend: str,
    target_source: Path,
    target_inventory: list[dict[str, object]],
    target_directories: list[dict[str, object]],
    acceptance_scope_digest: str,
    parent_pipe_fd: int,
    parent_nonce_sha256: str,
) -> dict[str, object]:
    validated = contract_v1.validate_contract(contract)
    top = validated["launcher"]["top_level_entry"]
    verify_runtime_inventory(validated, target_source, target_inventory, target_directories)
    if (
        not root.is_absolute()
        or backend not in {"synthetic", "systemd"}
        or contract_v1.HEX64.fullmatch(acceptance_scope_digest) is None
        or isinstance(parent_pipe_fd, bool)
        or not isinstance(parent_pipe_fd, int)
        or parent_pipe_fd < 3
        or contract_v1.HEX64.fullmatch(parent_nonce_sha256) is None
    ):
        raise LauncherError("top_level_entry_arguments_rejected")
    expected_contract = target_source / str(
        contract_v1.release_manifest_binding(validated)["contract_path"]
    )
    if contract_path != expected_contract:
        raise LauncherError("top_level_entry_arguments_rejected")
    _verify_interpreter(validated["interpreter"])
    _regular_file(
        contract_path,
        expected_sha256=sha256(contract_v1.canonical_bytes(validated)).hexdigest(),
    )
    entry_relative = str(top["entrypoint"])
    child_relative = str(top["child_entrypoint"])
    entry_path = target_source / entry_relative
    child_path = target_source / child_relative
    entry_sha = _inventory_sha(target_inventory, entry_relative)
    child_sha = _inventory_sha(target_inventory, child_relative)
    _regular_file(entry_path, expected_sha256=entry_sha)
    _regular_file(child_path, expected_sha256=child_sha)
    transport = _verify_windows_wsl_transport(validated)
    host_launcher = dict(top["host_launcher"])
    entry_identity = windows_host_entry_identity(
        validated,
        acceptance_scope_digest=acceptance_scope_digest,
        backend=backend,
        root=root,
        target_source=target_source,
    )
    environment = _top_level_environment(target_source, entry_identity)
    launcher_argv = _top_level_argv(
        validated,
        contract_path=contract_path,
        root=root,
        backend=backend,
        target_source=target_source,
        acceptance_scope_digest=acceptance_scope_digest,
    )
    child_argv = _top_level_child_argv(
        validated,
        contract_path=contract_path,
        root=root,
        backend=backend,
        target_source=target_source,
        acceptance_scope_digest=acceptance_scope_digest,
    )
    transport_argv = build_windows_wsl_transport_argv(
        validated,
        contract_path=contract_path,
        root=root,
        backend=backend,
        target_source=target_source,
        acceptance_scope_digest=acceptance_scope_digest,
    )
    evidence_root = root / str(top["evidence_root"]).lstrip("/") / entry_identity
    intent_path = evidence_root / "INTENT.json"
    capture_path = evidence_root / "CAPTURE.json"
    result_path = evidence_root / "RESULT.json"
    child_environment = {
        **environment,
        "MYUNA_P08_TOP_LEVEL_ENTRY_INTENT": str(intent_path),
        "MYUNA_P08_TOP_LEVEL_PARENT_FD": str(parent_pipe_fd),
    }
    body = {
        "schema": contract_v1.TOP_LEVEL_ENTRY_INTENT_SCHEMA,
        "architecture": contract_v1.ARCHITECTURE,
        "contract_digest": validated["contract_digest"],
        "acceptance_scope_digest": acceptance_scope_digest,
        "entry_identity": entry_identity,
        "root": str(root),
        "backend": backend,
        "target_source_path": str(target_source),
        "target_inventory_digest": contract_v1.digest_value(target_inventory),
        "target_directories_digest": contract_v1.digest_value(target_directories),
        "evidence_root": str(evidence_root),
        "intent_path": str(intent_path),
        "capture_path": str(capture_path),
        "result_path": str(result_path),
        "interpreter_path": str(validated["interpreter"]["invocation_path"]),
        "interpreter_sha256": str(validated["interpreter"]["sha256"]),
        "entrypoint_path": str(entry_path),
        "entrypoint_sha256": entry_sha,
        "child_entrypoint_path": str(child_path),
        "child_entrypoint_sha256": child_sha,
        "contract_path": str(contract_path),
        "contract_sha256": sha256(contract_v1.canonical_bytes(validated)).hexdigest(),
        "cwd": str(target_source),
        "uid": validated["runtime_identity"]["uid"],
        "gid": validated["runtime_identity"]["gid"],
        "groups": validated["runtime_identity"]["groups"],
        "umask": validated["launcher"]["umask"],
        "environment": environment,
        "argv": launcher_argv,
        "child_environment": child_environment,
        "child_argv": child_argv,
        "parent_pipe_fd": parent_pipe_fd,
        "parent_nonce_sha256": parent_nonce_sha256,
        "outer_descriptor_types": dict(transport["outer_descriptor_types"]),
        "child_stdin_target": str(transport["child_stdin_target"]),
        "transport_identity_digest": contract_v1.digest_value(transport),
        "host_launcher_identity_digest": contract_v1.digest_value(host_launcher),
        "host_launcher_sha256": str(host_launcher["sha256"]),
        "transport_argv": transport_argv,
        "transport_argv_digest": contract_v1.digest_value(transport_argv),
        "hard_deadline_seconds": top["hard_deadline_seconds"],
        "kill_grace_seconds": top["kill_grace_seconds"],
        "stdout_limit": top["stdout_limit"],
        "stderr_limit": top["stderr_limit"],
        "raw_output_retained": False,
    }
    return {**body, "intent_digest": contract_v1.digest_value(body)}


def validate_top_level_entry_intent(
    contract: Mapping[str, object], intent: Mapping[str, object]
) -> dict[str, object]:
    validated = contract_v1.validate_contract(contract)
    keys = {
        "acceptance_scope_digest",
        "architecture",
        "argv",
        "backend",
        "capture_path",
        "child_argv",
        "child_entrypoint_path",
        "child_entrypoint_sha256",
        "child_environment",
        "child_stdin_target",
        "contract_digest",
        "contract_path",
        "contract_sha256",
        "cwd",
        "entry_identity",
        "entrypoint_path",
        "entrypoint_sha256",
        "environment",
        "evidence_root",
        "gid",
        "groups",
        "hard_deadline_seconds",
        "host_launcher_identity_digest",
        "host_launcher_sha256",
        "intent_digest",
        "intent_path",
        "interpreter_path",
        "interpreter_sha256",
        "kill_grace_seconds",
        "outer_descriptor_types",
        "parent_nonce_sha256",
        "parent_pipe_fd",
        "raw_output_retained",
        "result_path",
        "root",
        "schema",
        "stderr_limit",
        "stdout_limit",
        "target_directories_digest",
        "target_inventory_digest",
        "target_source_path",
        "transport_argv",
        "transport_argv_digest",
        "transport_identity_digest",
        "uid",
        "umask",
    }
    if not isinstance(intent, Mapping) or set(intent) != keys:
        raise LauncherError("top_level_entry_intent_rejected")
    top = validated["launcher"]["top_level_entry"]
    transport = dict(top["transport"])
    for key in (
        "acceptance_scope_digest",
        "child_entrypoint_sha256",
        "contract_digest",
        "contract_sha256",
        "entry_identity",
        "entrypoint_sha256",
        "intent_digest",
        "interpreter_sha256",
        "parent_nonce_sha256",
        "target_directories_digest",
        "target_inventory_digest",
        "transport_argv_digest",
        "transport_identity_digest",
        "host_launcher_identity_digest",
        "host_launcher_sha256",
    ):
        if not isinstance(intent[key], str) or contract_v1.HEX64.fullmatch(
            intent[key]
        ) is None:
            raise LauncherError("top_level_entry_intent_rejected")
    target_source = Path(str(intent["target_source_path"]))
    root = Path(str(intent["root"]))
    contract_path = Path(str(intent["contract_path"]))
    expected_contract = target_source / str(
        contract_v1.release_manifest_binding(validated)["contract_path"]
    )
    entry_path = target_source / str(top["entrypoint"])
    child_path = target_source / str(top["child_entrypoint"])
    evidence_root = root / str(top["evidence_root"]).lstrip("/") / str(
        intent["entry_identity"]
    )
    expected_entry_identity = windows_host_entry_identity(
        validated,
        acceptance_scope_digest=str(intent["acceptance_scope_digest"]),
        backend=str(intent["backend"]),
        root=root,
        target_source=target_source,
    )
    expected_environment = _top_level_environment(
        target_source, expected_entry_identity
    )
    expected_argv = _top_level_argv(
        validated,
        contract_path=contract_path,
        root=root,
        backend=str(intent["backend"]),
        target_source=target_source,
        acceptance_scope_digest=str(intent["acceptance_scope_digest"]),
    )
    expected_child_argv = _top_level_child_argv(
        validated,
        contract_path=contract_path,
        root=root,
        backend=str(intent["backend"]),
        target_source=target_source,
        acceptance_scope_digest=str(intent["acceptance_scope_digest"]),
    )
    expected_transport_argv = build_windows_wsl_transport_argv(
        validated,
        contract_path=contract_path,
        root=root,
        backend=str(intent["backend"]),
        target_source=target_source,
        acceptance_scope_digest=str(intent["acceptance_scope_digest"]),
    )
    expected_child_environment = {
        **expected_environment,
        "MYUNA_P08_TOP_LEVEL_ENTRY_INTENT": str(evidence_root / "INTENT.json"),
        "MYUNA_P08_TOP_LEVEL_PARENT_FD": str(intent["parent_pipe_fd"]),
    }
    if (
        intent["schema"] != contract_v1.TOP_LEVEL_ENTRY_INTENT_SCHEMA
        or intent["architecture"] != contract_v1.ARCHITECTURE
        or intent["contract_digest"] != validated["contract_digest"]
        or intent["entry_identity"] != expected_entry_identity
        or not root.is_absolute()
        or not target_source.is_absolute()
        or contract_v1.HEX64.fullmatch(target_source.name) is None
        or intent["backend"] not in {"synthetic", "systemd"}
        or contract_path != expected_contract
        or Path(str(intent["entrypoint_path"])) != entry_path
        or Path(str(intent["child_entrypoint_path"])) != child_path
        or Path(str(intent["evidence_root"])) != evidence_root
        or Path(str(intent["intent_path"])) != evidence_root / "INTENT.json"
        or Path(str(intent["capture_path"])) != evidence_root / "CAPTURE.json"
        or Path(str(intent["result_path"])) != evidence_root / "RESULT.json"
        or intent["interpreter_path"] != validated["interpreter"]["invocation_path"]
        or intent["interpreter_sha256"] != validated["interpreter"]["sha256"]
        or intent["contract_sha256"]
        != sha256(contract_v1.canonical_bytes(validated)).hexdigest()
        or intent["cwd"] != str(target_source)
        or intent["uid"] != validated["runtime_identity"]["uid"]
        or intent["gid"] != validated["runtime_identity"]["gid"]
        or intent["groups"] != validated["runtime_identity"]["groups"]
        or intent["umask"] != validated["launcher"]["umask"]
        or intent["environment"] != expected_environment
        or intent["argv"] != expected_argv
        or intent["child_environment"] != expected_child_environment
        or intent["child_argv"] != expected_child_argv
        or not isinstance(intent["parent_pipe_fd"], int)
        or isinstance(intent["parent_pipe_fd"], bool)
        or intent["parent_pipe_fd"] < 3
        or intent["outer_descriptor_types"] != transport["outer_descriptor_types"]
        or intent["child_stdin_target"] != transport["child_stdin_target"]
        or intent["transport_identity_digest"]
        != contract_v1.digest_value(transport)
        or intent["host_launcher_identity_digest"]
        != contract_v1.digest_value(top["host_launcher"])
        or intent["host_launcher_sha256"] != top["host_launcher"]["sha256"]
        or intent["transport_argv"] != expected_transport_argv
        or intent["transport_argv_digest"]
        != contract_v1.digest_value(expected_transport_argv)
        or intent["hard_deadline_seconds"] != top["hard_deadline_seconds"]
        or intent["kill_grace_seconds"] != top["kill_grace_seconds"]
        or intent["stdout_limit"] != top["stdout_limit"]
        or intent["stderr_limit"] != top["stderr_limit"]
        or intent["raw_output_retained"] is not False
    ):
        raise LauncherError("top_level_entry_intent_rejected")
    unsigned = {key: value for key, value in intent.items() if key != "intent_digest"}
    if contract_v1.digest_value(unsigned) != intent["intent_digest"]:
        raise LauncherError("top_level_entry_intent_rejected")
    _verify_interpreter(validated["interpreter"])
    _regular_file(
        contract_path,
        expected_sha256=str(intent["contract_sha256"]),
    )
    _regular_file(entry_path, expected_sha256=str(intent["entrypoint_sha256"]))
    _regular_file(
        child_path, expected_sha256=str(intent["child_entrypoint_sha256"])
    )
    _verify_windows_wsl_transport(validated)
    return dict(intent)


def verify_current_top_level_entry(
    contract: Mapping[str, object],
    intent: Mapping[str, object],
) -> dict[str, object]:
    validated = validate_top_level_entry_intent(contract, intent)
    descriptor_types = {str(fd): _descriptor_type(fd) for fd in (0, 1, 2)}
    expected_types = validated["outer_descriptor_types"]
    if (
        Path.cwd() != Path(str(validated["cwd"]))
        or Path(sys.executable) != Path(str(validated["interpreter_path"]))
        or list(sys.orig_argv) != validated["argv"]
        or dict(os.environ) != validated["environment"]
        or os.getuid() != validated["uid"]
        or os.getgid() != validated["gid"]
        or sorted(os.getgroups()) != validated["groups"]
        or descriptor_types
        != {
            "0": expected_types["stdin"],
            "1": expected_types["stdout"],
            "2": expected_types["stderr"],
        }
    ):
        raise LauncherError("top_level_entry_process_rejected")
    return validated


def verify_top_level_bootstrap_child(
    contract: Mapping[str, object],
    intent: Mapping[str, object],
    *,
    argv: list[str],
) -> dict[str, object]:
    validated = validate_top_level_entry_intent(contract, intent)
    if (
        argv != validated["child_argv"]
        or list(sys.orig_argv) != validated["child_argv"]
        or Path.cwd() != Path(str(validated["cwd"]))
        or Path(sys.executable) != Path(str(validated["interpreter_path"]))
        or dict(os.environ) != validated["child_environment"]
        or os.getuid() != validated["uid"]
        or os.getgid() != validated["gid"]
        or sorted(os.getgroups()) != validated["groups"]
    ):
        raise LauncherError("top_level_bootstrap_child_rejected")
    try:
        stdin_target = os.readlink("/proc/self/fd/0")
        descriptor = int(str(validated["parent_pipe_fd"]))
        nonce = bytearray()
        while len(nonce) <= 32:
            chunk = os.read(descriptor, 33 - len(nonce))
            if not chunk:
                break
            nonce.extend(chunk)
    except (OSError, ValueError):
        raise LauncherError("top_level_bootstrap_child_rejected") from None
    finally:
        if "descriptor" in locals():
            try:
                os.close(descriptor)
            except OSError:
                pass
    if (
        stdin_target != validated["child_stdin_target"]
        or len(nonce) != 32
        or sha256(bytes(nonce)).hexdigest() != validated["parent_nonce_sha256"]
    ):
        raise LauncherError("top_level_bootstrap_child_rejected")
    return validated


def _open_verified_devnull() -> int:
    path = Path("/dev/null")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        details = os.fstat(descriptor)
        current = path.lstat()
    except OSError:
        if "descriptor" in locals():
            os.close(descriptor)
        raise LauncherError("devnull_identity_rejected") from None
    if (
        not stat.S_ISCHR(details.st_mode)
        or not stat.S_ISCHR(current.st_mode)
        or stat.S_IMODE(details.st_mode) != 0o666
        or stat.S_IMODE(current.st_mode) != 0o666
        or details.st_uid != 0
        or details.st_gid != 0
        or current.st_uid != 0
        or current.st_gid != 0
        or details.st_rdev != current.st_rdev
    ):
        os.close(descriptor)
        raise LauncherError("devnull_identity_rejected")
    return descriptor


def _read_process_identity(pid: int) -> dict[str, object]:
    try:
        status_rows: dict[str, str] = {}
        for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                status_rows[key] = value.strip()
        uid_values = [int(value) for value in status_rows["Uid"].split()]
        gid_values = [int(value) for value in status_rows["Gid"].split()]
        groups = sorted(int(value) for value in status_rows.get("Groups", "").split())
        argv = [
            item.decode("utf-8", "strict")
            for item in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\x00")
            if item
        ]
        environment = {}
        for item in Path(f"/proc/{pid}/environ").read_bytes().split(b"\x00"):
            if not item:
                continue
            key, value = item.decode("utf-8", "strict").split("=", 1)
            environment[key] = value
        return {
            "exe": os.readlink(f"/proc/{pid}/exe"),
            "cwd": os.readlink(f"/proc/{pid}/cwd"),
            "stdin": os.readlink(f"/proc/{pid}/fd/0"),
            "argv": argv,
            "environment": environment,
            "uids": uid_values,
            "gids": gid_values,
            "groups": groups,
            "process_group": os.getpgid(pid),
        }
    except (OSError, UnicodeError, ValueError, KeyError):
        raise LauncherError("top_level_bootstrap_child_identity_rejected") from None


def _verify_top_level_child_process(
    contract: Mapping[str, object], intent: Mapping[str, object], child: subprocess.Popen[bytes]
) -> None:
    validated = validate_top_level_entry_intent(contract, intent)
    observed = _read_process_identity(child.pid)
    expected_executable = str(contract["interpreter"]["resolved_path"])
    if (
        observed["exe"] != expected_executable
        or observed["cwd"] != validated["cwd"]
        or observed["stdin"] != validated["child_stdin_target"]
        or observed["argv"] != validated["child_argv"]
        or observed["environment"] != validated["child_environment"]
        or observed["uids"] != [validated["uid"]] * 4
        or observed["gids"] != [validated["gid"]] * 4
        or observed["groups"] != validated["groups"]
        or observed["process_group"] != child.pid
    ):
        raise LauncherError("top_level_bootstrap_child_identity_rejected")


def _preclaim_result_path(
    contract: Mapping[str, object], intent: Mapping[str, object]
) -> Path:
    preclaim = contract["launcher"]["top_level_entry"]["preclaim"]
    return Path(str(intent["intent_path"])).parent / str(
        preclaim["result_filename"]
    )


def _ensure_preclaim_result_evidence(
    contract: Mapping[str, object],
    intent: Mapping[str, object],
    result: Mapping[str, object],
) -> dict[str, object]:
    validated = contract_v1.validate_supervisor_preclaim_result(
        contract, intent, result
    )
    path = _preclaim_result_path(contract, intent)
    try:
        if not path.exists() and not path.is_symlink():
            # The child normally owns this write.  The generated contract
            # explicitly permits the source-owned parent to complete the same
            # exact O_EXCL evidence when child-side persistence failed.
            persist_capture_o_excl(path, validated)
        raw = _read_regular_bytes(path)
        parsed = json.loads(raw)
        observed = contract_v1.validate_supervisor_preclaim_result(
            contract, intent, parsed
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        contract_v1.ContractError,
        LauncherError,
    ):
        raise LauncherError("top_level_preclaim_evidence_rejected") from None
    if raw != contract_v1.canonical_bytes(observed) or observed != validated:
        raise LauncherError("top_level_preclaim_evidence_rejected")
    return observed


def run_top_level_entry_capture(
    contract: Mapping[str, object],
    intent: Mapping[str, object],
    *,
    parent_pipe_fds: tuple[int, int],
    parent_nonce: bytes,
    hard_deadline_seconds_override: int | None = None,
    child_started: Callable[[subprocess.Popen[bytes]], None] | None = None,
) -> dict[str, object]:
    validated = validate_top_level_entry_intent(contract, intent)
    read_fd, write_fd = parent_pipe_fds
    if (
        read_fd != validated["parent_pipe_fd"]
        or len(parent_nonce) != 32
        or sha256(parent_nonce).hexdigest() != validated["parent_nonce_sha256"]
    ):
        raise LauncherError("top_level_entry_parent_rejected")
    hard_deadline = int(validated["hard_deadline_seconds"])
    if hard_deadline_seconds_override is not None:
        if (
            not isinstance(hard_deadline_seconds_override, int)
            or isinstance(hard_deadline_seconds_override, bool)
            or hard_deadline_seconds_override < 1
            or hard_deadline_seconds_override > hard_deadline
        ):
            raise LauncherError("top_level_entry_deadline_rejected")
        hard_deadline = hard_deadline_seconds_override
    devnull_fd = _open_verified_devnull()
    started = time.monotonic()
    try:
        child = subprocess.Popen(
            list(validated["child_argv"]),
            cwd=str(validated["cwd"]),
            env=dict(validated["child_environment"]),
            stdin=devnull_fd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(read_fd,),
            close_fds=True,
            start_new_session=True,
            umask=int(validated["umask"]),
        )
    except OSError:
        os.close(devnull_fd)
        raise LauncherError("top_level_entry_child_create_rejected") from None
    finally:
        if "child" in locals():
            os.close(devnull_fd)
    try:
        _verify_top_level_child_process(contract, validated, child)
        if child_started is not None:
            child_started(child)
        offset = 0
        while offset < len(parent_nonce):
            written = os.write(write_fd, parent_nonce[offset:])
            if written < 1:
                raise OSError("short top-level parent nonce write")
            offset += written
    except Exception:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.communicate(timeout=int(validated["kill_grace_seconds"]))
        raise LauncherError("top_level_entry_child_identity_rejected") from None
    finally:
        for descriptor in (write_fd, read_fd):
            try:
                os.close(descriptor)
            except OSError:
                pass
    assert child.stdout is not None and child.stderr is not None
    selector = selectors.DefaultSelector()
    for stream, label in ((child.stdout, "stdout"), (child.stderr, "stderr")):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, label)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    exit_class = "exit"
    deadline = started + hard_deadline
    terminated = False
    while selector.get_map():
        now = time.monotonic()
        if now >= deadline:
            exit_class = "hard_timeout"
            terminated = True
        if terminated:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            break
        events = selector.select(timeout=min(0.1, max(0.0, deadline - now)))
        for key, _ in events:
            label = str(key.data)
            stream = key.fileobj
            try:
                chunk = os.read(stream.fileno(), 65536)
            except BlockingIOError:
                continue
            if not chunk:
                selector.unregister(stream)
                stream.close()
                continue
            buffers[label].extend(chunk)
            limit = int(validated[f"{label}_limit"])
            if len(buffers[label]) > limit:
                exit_class = f"{label}_oversize"
                terminated = True
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                break
    if child.poll() is None:
        try:
            child.wait(timeout=int(validated["kill_grace_seconds"]))
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=int(validated["kill_grace_seconds"]))
    # Drain only already-open finite pipes after the child is terminal.
    for key in list(selector.get_map().values()):
        stream = key.fileobj
        while True:
            try:
                chunk = os.read(stream.fileno(), 65536)
            except BlockingIOError:
                break
            if not chunk:
                break
            if len(buffers[str(key.data)]) <= int(validated[f"{key.data}_limit"]):
                buffers[str(key.data)].extend(chunk)
        selector.unregister(stream)
        stream.close()
    selector.close()
    stdout = bytes(buffers["stdout"])
    stderr = bytes(buffers["stderr"])
    canonical_result = None
    canonical_status = "indeterminate"
    if (
        exit_class == "exit"
        and child.returncode in {0, 2}
        and not stderr
        and 0 < len(stdout) <= int(validated["stdout_limit"])
    ):
        try:
            parsed = json.loads(stdout)
            if stdout != contract_v1.canonical_bytes(parsed):
                raise contract_v1.ContractError("top_level_entry_child_rejected")
            candidate = contract_v1.validate_supervisor_bootstrap_output(
                parsed,
                contract=contract,
                top_level_intent=validated,
            )
            if candidate.get("schema") == contract_v1.SUPERVISOR_PRECLAIM_RESULT_SCHEMA:
                try:
                    canonical_result = _ensure_preclaim_result_evidence(
                        contract, validated, candidate
                    )
                except LauncherError:
                    canonical_result = None
                    canonical_status = "preclaim_evidence_rejected"
                else:
                    canonical_status = "complete"
            else:
                canonical_result = candidate
                canonical_status = "complete"
        except (UnicodeDecodeError, json.JSONDecodeError, contract_v1.ContractError):
            canonical_result = None
            canonical_status = "indeterminate"
    process_identity = contract_v1.preclaim_process_identity(validated)
    body = {
        "schema": contract_v1.TOP_LEVEL_ENTRY_CAPTURE_SCHEMA,
        "architecture": contract_v1.ARCHITECTURE,
        "contract_digest": contract["contract_digest"],
        "acceptance_scope_digest": validated["acceptance_scope_digest"],
        "entry_identity": validated["entry_identity"],
        "intent_digest": validated["intent_digest"],
        "transport_argv_digest": validated["transport_argv_digest"],
        "child_pid": child.pid,
        "child_process_identity_digest": contract_v1.digest_value(process_identity),
        "child_stdin_target": validated["child_stdin_target"],
        "hard_deadline_seconds": hard_deadline,
        "exit_class": exit_class,
        "returncode": child.returncode,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "stdout_size": len(stdout),
        "stdout_sha256": sha256(stdout).hexdigest(),
        "stderr_size": len(stderr),
        "stderr_sha256": sha256(stderr).hexdigest(),
        "canonical_status": canonical_status,
        "canonical_result": canonical_result,
        "canonical_result_digest": (
            contract_v1.digest_value(canonical_result)
            if canonical_result is not None
            else None
        ),
        "raw_output_retained": False,
        "orphan_count": _process_group_orphan_count(child.pid),
    }
    return {**body, "capture_digest": contract_v1.digest_value(body)}


def validate_top_level_entry_capture(
    contract: Mapping[str, object],
    intent: Mapping[str, object],
    capture: Mapping[str, object],
) -> dict[str, object]:
    validated_intent = validate_top_level_entry_intent(contract, intent)
    keys = {
        "acceptance_scope_digest",
        "architecture",
        "canonical_result",
        "canonical_result_digest",
        "canonical_status",
        "capture_digest",
        "child_pid",
        "child_process_identity_digest",
        "child_stdin_target",
        "contract_digest",
        "elapsed_ms",
        "entry_identity",
        "exit_class",
        "hard_deadline_seconds",
        "intent_digest",
        "orphan_count",
        "raw_output_retained",
        "returncode",
        "schema",
        "stderr_sha256",
        "stderr_size",
        "stdout_sha256",
        "stdout_size",
        "transport_argv_digest",
    }
    if not isinstance(capture, Mapping) or set(capture) != keys:
        raise LauncherError("top_level_entry_capture_rejected")
    if (
        capture["schema"] != contract_v1.TOP_LEVEL_ENTRY_CAPTURE_SCHEMA
        or capture["architecture"] != contract_v1.ARCHITECTURE
        or capture["contract_digest"] != contract["contract_digest"]
        or capture["acceptance_scope_digest"]
        != validated_intent["acceptance_scope_digest"]
        or capture["entry_identity"] != validated_intent["entry_identity"]
        or capture["intent_digest"] != validated_intent["intent_digest"]
        or capture["transport_argv_digest"]
        != validated_intent["transport_argv_digest"]
        or capture["child_stdin_target"] != "/dev/null"
        or capture["raw_output_retained"] is not False
        or capture["exit_class"]
        not in {"exit", "hard_timeout", "stdout_oversize", "stderr_oversize"}
        or capture["canonical_status"]
        not in {"complete", "indeterminate", "preclaim_evidence_rejected"}
        or capture["orphan_count"] != 0
        or not isinstance(capture["returncode"], int)
        or isinstance(capture["returncode"], bool)
        or not isinstance(capture["child_pid"], int)
        or isinstance(capture["child_pid"], bool)
        or capture["child_pid"] < 1
        or not isinstance(capture["hard_deadline_seconds"], int)
        or isinstance(capture["hard_deadline_seconds"], bool)
        or capture["hard_deadline_seconds"] < 1
        or capture["hard_deadline_seconds"]
        > validated_intent["hard_deadline_seconds"]
    ):
        raise LauncherError("top_level_entry_capture_rejected")
    for key in ("elapsed_ms", "orphan_count", "stderr_size", "stdout_size"):
        if (
            not isinstance(capture[key], int)
            or isinstance(capture[key], bool)
            or capture[key] < 0
        ):
            raise LauncherError("top_level_entry_capture_rejected")
    for key in (
        "capture_digest",
        "child_process_identity_digest",
        "stderr_sha256",
        "stdout_sha256",
    ):
        if not isinstance(capture[key], str) or contract_v1.HEX64.fullmatch(
            capture[key]
        ) is None:
            raise LauncherError("top_level_entry_capture_rejected")
    empty = sha256(b"").hexdigest()
    if (
        (capture["stdout_size"] == 0) != (capture["stdout_sha256"] == empty)
        or (capture["stderr_size"] == 0) != (capture["stderr_sha256"] == empty)
    ):
        raise LauncherError("top_level_entry_capture_rejected")
    if capture["canonical_result"] is None:
        if (
            capture["canonical_result_digest"] is not None
            or capture["canonical_status"]
            not in {"indeterminate", "preclaim_evidence_rejected"}
        ):
            raise LauncherError("top_level_entry_capture_rejected")
    else:
        result = contract_v1.validate_supervisor_bootstrap_output(
            capture["canonical_result"],
            contract=contract,
            top_level_intent=validated_intent,
        )
        expected_returncode = 0 if result.get("terminal_status") == "accepted" else 2
        if (
            capture["canonical_status"] != "complete"
            or capture["exit_class"] != "exit"
            or capture["returncode"] != expected_returncode
            or capture["stderr_size"] != 0
            or capture["stdout_size"] < 1
            or capture["stdout_size"] > validated_intent["stdout_limit"]
            or capture["canonical_result_digest"] != contract_v1.digest_value(result)
            or (
                result.get("schema")
                == contract_v1.SUPERVISOR_PRECLAIM_RESULT_SCHEMA
                and (
                    result["bootstrap_pid"] != capture["child_pid"]
                    or result["process_identity_digest"]
                    != capture["child_process_identity_digest"]
                )
            )
        ):
            raise LauncherError("top_level_entry_capture_rejected")
    if capture["exit_class"] != "exit" and capture["canonical_result"] is not None:
        raise LauncherError("top_level_entry_capture_rejected")
    unsigned = {key: value for key, value in capture.items() if key != "capture_digest"}
    if contract_v1.digest_value(unsigned) != capture["capture_digest"]:
        raise LauncherError("top_level_entry_capture_rejected")
    return dict(capture)


def build_top_level_entry_result(
    contract: Mapping[str, object],
    intent: Mapping[str, object],
    capture: Mapping[str, object] | None,
    *,
    prelaunch_status: str | None = None,
    failure_category: str | None = None,
) -> dict[str, object]:
    validated_contract = contract_v1.validate_contract(contract)
    allowed_failures = set(
        validated_contract["launcher"]["top_level_entry"][
            "result_failure_categories"
        ]
    )
    if capture is None:
        if prelaunch_status not in {"rejected", "indeterminate"}:
            raise LauncherError("top_level_entry_result_rejected")
        entry_identity = str(intent.get("entry_identity"))
        acceptance_scope = str(intent.get("acceptance_scope_digest"))
        intent_digest = intent.get("intent_digest")
        status = prelaunch_status
        product_state = "unmodified" if status == "rejected" else "unknown"
        child_terminal_status = None
        child_plan_digest = None
        child_result_digest = None
        capture_digest = None
        child_preclaim_phase = None
        child_preclaim_category = None
        child_preclaim_cause_source = None
        child_preclaim_subcategory = None
        child_preclaim_mutation_state = None
        if failure_category not in allowed_failures:
            raise LauncherError("top_level_entry_result_rejected")
    else:
        if failure_category is not None:
            raise LauncherError("top_level_entry_result_rejected")
        validated_capture = validate_top_level_entry_capture(
            validated_contract, intent, capture
        )
        child = validated_capture["canonical_result"]
        entry_identity = str(validated_capture["entry_identity"])
        acceptance_scope = str(validated_capture["acceptance_scope_digest"])
        intent_digest = validated_capture["intent_digest"]
        capture_digest = validated_capture["capture_digest"]
        child_result_digest = validated_capture["canonical_result_digest"]
        child_preclaim_phase = None
        child_preclaim_category = None
        child_preclaim_cause_source = None
        child_preclaim_subcategory = None
        child_preclaim_mutation_state = None
        if child is None:
            status = "indeterminate"
            product_state = "unknown"
            child_terminal_status = None
            child_plan_digest = None
            failure_category = (
                "child_preclaim_evidence_rejected"
                if validated_capture["canonical_status"]
                == "preclaim_evidence_rejected"
                else "child_capture_indeterminate"
            )
        else:
            child_terminal_status = child.get("terminal_status")
            child_plan_digest = child.get("plan_digest")
            product_state = str(child.get("product_state", "unknown"))
            status = "accepted" if child_terminal_status == "accepted" else "hard_stop"
            if (
                child.get("schema")
                == contract_v1.SUPERVISOR_PRECLAIM_RESULT_SCHEMA
            ):
                status = str(child["status"])
                product_state = "unmodified"
                failure_category = str(child["category"])
                child_preclaim_phase = str(child["phase"])
                child_preclaim_category = str(child["category"])
                child_preclaim_cause_source = str(child["cause_source"])
                child_preclaim_subcategory = str(child["subcategory"])
                child_preclaim_mutation_state = str(
                    child["product_mutation_state"]
                )
            elif child.get("schema") == contract_v1.SUPERVISOR_ENTRY_SCHEMA:
                status = "indeterminate"
                failure_category = "child_result_indeterminate"
    body = {
        "schema": contract_v1.TOP_LEVEL_ENTRY_RESULT_SCHEMA,
        "architecture": contract_v1.ARCHITECTURE,
        "contract_digest": validated_contract["contract_digest"],
        "acceptance_scope_digest": acceptance_scope,
        "entry_identity": entry_identity,
        "intent_digest": intent_digest,
        "capture_digest": capture_digest,
        "canonical_child_result_digest": child_result_digest,
        "child_terminal_status": child_terminal_status,
        "child_product_state": product_state,
        "child_plan_digest": child_plan_digest,
        "child_preclaim_phase": child_preclaim_phase,
        "child_preclaim_category": child_preclaim_category,
        "child_preclaim_cause_source": child_preclaim_cause_source,
        "child_preclaim_subcategory": child_preclaim_subcategory,
        "child_preclaim_mutation_state": child_preclaim_mutation_state,
        "failure_category": failure_category,
        "status": status,
        "stage": "source_owned_top_level_capture",
        "raw_output_included": False,
        "retry_authorized": False,
    }
    return {**body, "result_digest": contract_v1.digest_value(body)}


def validate_top_level_entry_result(
    contract: Mapping[str, object], result: Mapping[str, object]
) -> dict[str, object]:
    validated = contract_v1.validate_contract(contract)
    keys = {
        "acceptance_scope_digest",
        "architecture",
        "canonical_child_result_digest",
        "capture_digest",
        "child_plan_digest",
        "child_preclaim_category",
        "child_preclaim_cause_source",
        "child_preclaim_mutation_state",
        "child_preclaim_phase",
        "child_preclaim_subcategory",
        "child_product_state",
        "child_terminal_status",
        "contract_digest",
        "entry_identity",
        "failure_category",
        "intent_digest",
        "raw_output_included",
        "result_digest",
        "retry_authorized",
        "schema",
        "stage",
        "status",
    }
    if not isinstance(result, Mapping) or set(result) != keys:
        raise LauncherError("top_level_entry_result_rejected")
    for key in ("acceptance_scope_digest", "entry_identity", "result_digest"):
        if not isinstance(result[key], str) or contract_v1.HEX64.fullmatch(
            result[key]
        ) is None:
            raise LauncherError("top_level_entry_result_rejected")
    for key in (
        "canonical_child_result_digest",
        "capture_digest",
        "child_plan_digest",
        "intent_digest",
    ):
        if result[key] is not None and (
            not isinstance(result[key], str)
            or contract_v1.HEX64.fullmatch(result[key]) is None
        ):
            raise LauncherError("top_level_entry_result_rejected")
    top_level = validated["launcher"]["top_level_entry"]
    allowed_failures = set(top_level["result_failure_categories"])
    preclaim = top_level["preclaim"]
    preclaim_rows = {
        str(row["phase"]): set(row["rejection_categories"])
        | {str(preclaim["unexpected_category"])}
        for row in preclaim["ordered_phases"]
    }
    preclaim_categories = set().union(*preclaim_rows.values())
    preclaim_fields = (
        result["child_preclaim_phase"],
        result["child_preclaim_category"],
        result["child_preclaim_cause_source"],
        result["child_preclaim_subcategory"],
        result["child_preclaim_mutation_state"],
    )
    has_preclaim = any(value is not None for value in preclaim_fields)
    valid_preclaim = (
        has_preclaim
        and all(isinstance(value, str) for value in preclaim_fields)
        and result["child_preclaim_phase"] in preclaim_rows
        and result["child_preclaim_category"]
        in preclaim_rows.get(result["child_preclaim_phase"], set())
        and result["child_preclaim_cause_source"]
        in next(
            row["subcategory_sources"]
            for row in preclaim["ordered_phases"]
            if row["phase"] == result["child_preclaim_phase"]
        )
        and result["child_preclaim_subcategory"]
        in next(
            row["subcategory_sources"][result["child_preclaim_cause_source"]]
            for row in preclaim["ordered_phases"]
            if row["phase"] == result["child_preclaim_phase"]
        )
        and result["child_preclaim_mutation_state"]
        == preclaim["product_mutation_state"]
        and result["failure_category"] == result["child_preclaim_category"]
        and result["status"]
        == (
            preclaim["unexpected_status"]
            if result["child_preclaim_category"]
            == preclaim["unexpected_category"]
            else preclaim["typed_status"]
        )
        and result["child_product_state"] == "unmodified"
        and result["child_terminal_status"] is None
        and result["child_plan_digest"] is None
        and result["intent_digest"] is not None
        and result["canonical_child_result_digest"] is not None
        and result["capture_digest"] is not None
    )
    if (
        result["schema"] != contract_v1.TOP_LEVEL_ENTRY_RESULT_SCHEMA
        or result["architecture"] != contract_v1.ARCHITECTURE
        or result["contract_digest"] != validated["contract_digest"]
        or result["stage"] != "source_owned_top_level_capture"
        or result["status"]
        not in {"accepted", "hard_stop", "indeterminate", "rejected"}
        or result["child_product_state"]
        not in {"accepted", "predecessor_restored", "unmodified", "unknown"}
        or result["raw_output_included"] is not False
        or result["retry_authorized"] is not False
        or (
            result["failure_category"] is not None
            and result["failure_category"] not in allowed_failures
        )
        or (
            result["status"] in {"accepted", "hard_stop"}
            and result["failure_category"] is not None
        )
        or (
            result["status"] in {"rejected", "indeterminate"}
            and result["failure_category"] is None
        )
        or (
            result["status"] in {"accepted", "hard_stop"}
            and (
                result["intent_digest"] is None
                or result["capture_digest"] is None
                or result["canonical_child_result_digest"] is None
                or result["child_terminal_status"] is None
            )
        )
        or (
            result["status"] in {"rejected", "indeterminate"}
            and result["capture_digest"] is None
            and result["canonical_child_result_digest"] is not None
        )
        or (has_preclaim and not valid_preclaim)
        or (
            not has_preclaim and result["failure_category"] in preclaim_categories
        )
    ):
        raise LauncherError("top_level_entry_result_rejected")
    unsigned = {key: value for key, value in result.items() if key != "result_digest"}
    if contract_v1.digest_value(unsigned) != result["result_digest"]:
        raise LauncherError("top_level_entry_result_rejected")
    return dict(result)


def validate_windows_wsl_capture(
    contract: Mapping[str, object], capture: Mapping[str, object]
) -> dict[str, object]:
    validated = contract_v1.validate_contract(contract)
    keys = {
        "acceptance_scope_digest",
        "architecture",
        "canonical_result_digest",
        "canonical_status",
        "capture_digest",
        "child_pid",
        "contract_digest",
        "elapsed_ms",
        "entry_identity",
        "exit_class",
        "host_launcher_sha256",
        "orphan_count",
        "raw_output_retained",
        "returncode",
        "schema",
        "stderr_classification_allowed",
        "stderr_sha256",
        "stderr_size",
        "stdout_sha256",
        "stdout_size",
        "wsl_sha256",
    }
    if not isinstance(capture, Mapping) or set(capture) != keys:
        raise LauncherError("windows_wsl_capture_rejected")
    for key in (
        "acceptance_scope_digest",
        "capture_digest",
        "contract_digest",
        "entry_identity",
        "host_launcher_sha256",
        "stderr_sha256",
        "stdout_sha256",
        "wsl_sha256",
    ):
        if not isinstance(capture[key], str) or contract_v1.HEX64.fullmatch(
            capture[key]
        ) is None:
            raise LauncherError("windows_wsl_capture_rejected")
    if capture["canonical_result_digest"] is not None and (
        not isinstance(capture["canonical_result_digest"], str)
        or contract_v1.HEX64.fullmatch(capture["canonical_result_digest"]) is None
    ):
        raise LauncherError("windows_wsl_capture_rejected")
    for key in (
        "child_pid",
        "elapsed_ms",
        "orphan_count",
        "returncode",
        "stderr_size",
        "stdout_size",
    ):
        if not isinstance(capture[key], int) or isinstance(capture[key], bool):
            raise LauncherError("windows_wsl_capture_rejected")
    top = validated["launcher"]["top_level_entry"]
    if (
        capture["schema"] != contract_v1.WINDOWS_WSL_CAPTURE_SCHEMA
        or capture["architecture"] != contract_v1.ARCHITECTURE
        or capture["contract_digest"] != validated["contract_digest"]
        or capture["host_launcher_sha256"] != top["host_launcher"]["sha256"]
        or capture["wsl_sha256"] != top["transport"]["sha256"]
        or capture["exit_class"]
        not in {
            "exit",
            "wait_failed",
            "hard_timeout",
            "stdout_oversize",
            "stderr_oversize",
        }
        or capture["canonical_status"] not in {"complete", "indeterminate"}
        or not isinstance(capture["stderr_classification_allowed"], bool)
        or capture["raw_output_retained"] is not False
        or capture["orphan_count"] != 0
        or capture["child_pid"] < 1
        or capture["elapsed_ms"] < 0
        or capture["stdout_size"] < 0
        or capture["stdout_size"] > int(top["host_launcher"]["stdout_limit"])
        or capture["stderr_size"] < 0
        or capture["stderr_size"] > int(top["host_launcher"]["stderr_limit"])
        or (
            capture["canonical_status"] == "complete"
            and capture["canonical_result_digest"] is None
        )
        or (
            capture["canonical_status"] == "indeterminate"
            and capture["canonical_result_digest"] is not None
        )
    ):
        raise LauncherError("windows_wsl_capture_rejected")
    unsigned = {key: value for key, value in capture.items() if key != "capture_digest"}
    if contract_v1.digest_value(unsigned) != capture["capture_digest"]:
        raise LauncherError("windows_wsl_capture_rejected")
    return dict(capture)


def build_windows_capture_persist_argv(
    contract: Mapping[str, object],
    *,
    contract_path: Path,
    root: Path,
    backend: str,
    target_source: Path,
    acceptance_scope_digest: str,
    entry_identity: str,
) -> list[str]:
    validated = contract_v1.validate_contract(contract)
    if (
        backend not in {"synthetic", "systemd"}
        or contract_v1.HEX64.fullmatch(acceptance_scope_digest) is None
        or contract_v1.HEX64.fullmatch(entry_identity) is None
    ):
        raise LauncherError("windows_capture_persist_arguments_rejected")
    entrypoint = Path(
        str(validated["launcher"]["top_level_entry"]["capture_persist_entrypoint"])
    )
    return [
        str(validated["interpreter"]["invocation_path"]),
        "-B",
        "-P",
        "-S",
        "-m",
        entrypoint.stem,
        "--activation-contract",
        str(contract_path),
        "--activation-root",
        str(root),
        "--activation-backend",
        backend,
        "--activation-target-source",
        str(target_source),
        "--acceptance-scope-digest",
        acceptance_scope_digest,
        "--entry-identity",
        entry_identity,
    ]


def verify_current_windows_capture_persister(
    contract: Mapping[str, object],
    *,
    contract_path: Path,
    root: Path,
    backend: str,
    target_source: Path,
    acceptance_scope_digest: str,
    entry_identity: str,
) -> None:
    validated = contract_v1.validate_contract(contract)
    expected_argv = build_windows_capture_persist_argv(
        validated,
        contract_path=contract_path,
        root=root,
        backend=backend,
        target_source=target_source,
        acceptance_scope_digest=acceptance_scope_digest,
        entry_identity=entry_identity,
    )
    expected_environment = _top_level_environment(target_source, entry_identity)
    descriptor_types = {str(fd): _descriptor_type(fd) for fd in (0, 1, 2)}
    if (
        Path.cwd() != target_source
        or Path(sys.executable) != Path(str(validated["interpreter"]["invocation_path"]))
        or list(sys.orig_argv) != expected_argv
        or dict(os.environ) != expected_environment
        or os.getuid() != 0
        or os.getgid() != 0
        or sorted(os.getgroups()) != [0]
        or descriptor_types != {"0": "fifo", "1": "fifo", "2": "fifo"}
    ):
        raise LauncherError("windows_capture_persist_process_rejected")


def build_windows_capture_persist_result(
    contract: Mapping[str, object], capture: Mapping[str, object]
) -> dict[str, object]:
    validated = contract_v1.validate_contract(contract)
    checked = validate_windows_wsl_capture(validated, capture)
    body = {
        "schema": contract_v1.WINDOWS_WSL_CAPTURE_PERSIST_RESULT_SCHEMA,
        "architecture": contract_v1.ARCHITECTURE,
        "contract_digest": validated["contract_digest"],
        "acceptance_scope_digest": checked["acceptance_scope_digest"],
        "entry_identity": checked["entry_identity"],
        "capture_digest": checked["capture_digest"],
        "canonical_status": checked["canonical_status"],
        "status": "persisted",
        "raw_output_included": False,
        "retry_authorized": False,
    }
    return {**body, "result_digest": contract_v1.digest_value(body)}


def validate_windows_capture_persist_result(
    contract: Mapping[str, object], result: Mapping[str, object]
) -> dict[str, object]:
    validated = contract_v1.validate_contract(contract)
    keys = {
        "acceptance_scope_digest",
        "architecture",
        "canonical_status",
        "capture_digest",
        "contract_digest",
        "entry_identity",
        "raw_output_included",
        "result_digest",
        "retry_authorized",
        "schema",
        "status",
    }
    if not isinstance(result, Mapping) or set(result) != keys:
        raise LauncherError("windows_capture_persist_result_rejected")
    for key in (
        "acceptance_scope_digest",
        "capture_digest",
        "contract_digest",
        "entry_identity",
        "result_digest",
    ):
        if not isinstance(result[key], str) or contract_v1.HEX64.fullmatch(
            result[key]
        ) is None:
            raise LauncherError("windows_capture_persist_result_rejected")
    if (
        result["schema"] != contract_v1.WINDOWS_WSL_CAPTURE_PERSIST_RESULT_SCHEMA
        or result["architecture"] != contract_v1.ARCHITECTURE
        or result["contract_digest"] != validated["contract_digest"]
        or result["canonical_status"] not in {"complete", "indeterminate"}
        or result["status"] != "persisted"
        or result["raw_output_included"] is not False
        or result["retry_authorized"] is not False
    ):
        raise LauncherError("windows_capture_persist_result_rejected")
    unsigned = {key: value for key, value in result.items() if key != "result_digest"}
    if contract_v1.digest_value(unsigned) != result["result_digest"]:
        raise LauncherError("windows_capture_persist_result_rejected")
    return dict(result)


def build_invocation(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    role: str,
    call_index: int,
    contract_path: Path,
    plan_path: Path,
    deploy_root: Path,
    entrypoint_relative: str,
) -> dict[str, object]:
    validated_contract = contract_v1.validate_contract(contract)
    validated_plan = contract_v1.validate_plan(validated_contract, plan)
    runtime_root = _verify_runtime_package(validated_contract, validated_plan)
    if role not in validated_contract["roles"]:
        raise LauncherError("invocation_role_rejected")
    role_contract = validated_contract["roles"][role]
    if (
        not isinstance(call_index, int)
        or isinstance(call_index, bool)
        or call_index < 1
        or call_index > role_contract["call_budget"]
    ):
        raise LauncherError("invocation_call_rejected")
    if (
        not deploy_root.is_absolute()
        or deploy_root != runtime_root
    ):
        raise LauncherError("invocation_cwd_rejected")
    entrypoint = deploy_root / entrypoint_relative
    entrypoint_path = Path(entrypoint_relative)
    if (
        entrypoint_path.parent.as_posix() != "scripts"
        or entrypoint_path.suffix != ".py"
        or not entrypoint_path.stem.isidentifier()
    ):
        raise LauncherError("source_entrypoint_rejected")
    entrypoint_module = entrypoint_path.stem
    interpreter = Path(str(validated_contract["interpreter"]["invocation_path"]))
    _verify_interpreter(validated_contract["interpreter"])
    _regular_file(entrypoint, expected_sha256=_source_sha(validated_plan, entrypoint_relative))
    _regular_file(contract_path)
    _regular_file(plan_path)
    if _read_regular_bytes(contract_path) != contract_v1.canonical_bytes(validated_contract):
        raise LauncherError("invocation_contract_bytes_rejected")
    if _read_regular_bytes(plan_path) != contract_v1.canonical_bytes(validated_plan):
        raise LauncherError("invocation_plan_bytes_rejected")
    groups = sorted(os.getgroups())
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": os.pathsep.join(
            (
                str(deploy_root / "scripts"),
                str(deploy_root / "src"),
            )
        ),
    }
    body = {
        "schema": contract_v1.INVOCATION_SCHEMA,
        "contract_digest": validated_contract["contract_digest"],
        "plan_digest": validated_plan["plan_digest"],
        "sequence_identity": validated_plan["sequence_identity"],
        "invocation_nonce": validated_plan["invocation_nonce"],
        "role": role,
        "call_index": call_index,
        "interpreter_path": str(interpreter),
        "interpreter_sha256": validated_contract["interpreter"]["sha256"],
        "entrypoint_path": str(entrypoint),
        "entrypoint_sha256": _source_sha(validated_plan, entrypoint_relative),
        "contract_path": str(contract_path),
        "contract_sha256": _digest(contract_path),
        "plan_path": str(plan_path),
        "plan_sha256": _digest(plan_path),
        "cwd": str(deploy_root),
        "uid": os.getuid(),
        "gid": os.getgid(),
        "groups": groups,
        "umask": int(validated_contract["launcher"]["umask"]),
        "closed_stdin": True,
        "environment": environment,
        "hard_deadline_seconds": role_contract["hard_deadline_seconds"],
        "no_progress_seconds": role_contract["no_progress_seconds"],
        "progress_phases": role_contract["progress_phases"],
        "argv": [
            str(interpreter),
            "-B",
            "-P",
            "-S",
            "-m",
            entrypoint_module,
            "--activation-contract",
            str(contract_path),
            "--activation-plan",
            str(plan_path),
            "--activation-role",
            role,
            "--activation-call-index",
            str(call_index),
        ],
    }
    return {**body, "invocation_digest": contract_v1.digest_value(body)}


def validate_invocation(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    invocation: Mapping[str, object],
) -> dict[str, object]:
    validated_contract = contract_v1.validate_contract(contract)
    validated_plan = contract_v1.validate_plan(validated_contract, plan)
    runtime_root = _verify_runtime_package(validated_contract, validated_plan)
    keys = {
        "argv",
        "call_index",
        "closed_stdin",
        "contract_digest",
        "contract_path",
        "contract_sha256",
        "cwd",
        "entrypoint_path",
        "entrypoint_sha256",
        "environment",
        "gid",
        "groups",
        "hard_deadline_seconds",
        "interpreter_path",
        "interpreter_sha256",
        "invocation_digest",
        "invocation_nonce",
        "no_progress_seconds",
        "plan_digest",
        "plan_path",
        "plan_sha256",
        "progress_phases",
        "role",
        "schema",
        "sequence_identity",
        "uid",
        "umask",
    }
    if not isinstance(invocation, Mapping) or set(invocation) != keys:
        raise LauncherError("invocation_keys_rejected")
    if (
        invocation["schema"] != contract_v1.INVOCATION_SCHEMA
        or invocation["contract_digest"] != validated_contract["contract_digest"]
        or invocation["plan_digest"] != validated_plan["plan_digest"]
        or invocation["sequence_identity"] != validated_plan["sequence_identity"]
        or invocation["invocation_nonce"] != validated_plan["invocation_nonce"]
        or invocation["closed_stdin"] is not True
    ):
        raise LauncherError("invocation_binding_rejected")
    role = invocation["role"]
    if role not in validated_contract["roles"]:
        raise LauncherError("invocation_role_rejected")
    role_contract = validated_contract["roles"][role]
    if (
        not isinstance(invocation["call_index"], int)
        or isinstance(invocation["call_index"], bool)
        or invocation["call_index"] < 1
        or invocation["call_index"] > role_contract["call_budget"]
        or invocation["hard_deadline_seconds"] != role_contract["hard_deadline_seconds"]
        or invocation["no_progress_seconds"] != role_contract["no_progress_seconds"]
        or invocation["progress_phases"] != role_contract["progress_phases"]
    ):
        raise LauncherError("invocation_budget_rejected")
    expected_environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": os.pathsep.join(
            (
                str(Path(str(invocation["cwd"])) / "scripts"),
                str(Path(str(invocation["cwd"])) / "src"),
            )
        ),
    }
    runtime_identity = validated_contract["runtime_identity"]
    try:
        entrypoint_relative = (
            Path(str(invocation["entrypoint_path"])).resolve()
            .relative_to(Path(str(invocation["cwd"])).resolve())
            .as_posix()
        )
        bound_entrypoint_sha = _source_sha(validated_plan, entrypoint_relative)
        entrypoint_path = Path(entrypoint_relative)
        if (
            entrypoint_path.parent.as_posix() != "scripts"
            or entrypoint_path.suffix != ".py"
            or not entrypoint_path.stem.isidentifier()
        ):
            raise LauncherError("invocation_identity_rejected")
        entrypoint_module = entrypoint_path.stem
    except (ValueError, LauncherError):
        raise LauncherError("invocation_identity_rejected") from None
    if (
        invocation["interpreter_path"]
        != validated_contract["interpreter"]["invocation_path"]
        or invocation["interpreter_sha256"]
        != validated_contract["interpreter"]["sha256"]
        or Path(str(invocation["cwd"])) != runtime_root
        or invocation["uid"] != runtime_identity["uid"]
        or invocation["gid"] != runtime_identity["gid"]
        or invocation["groups"] != runtime_identity["groups"]
        or invocation["umask"] != validated_contract["launcher"]["umask"]
        or invocation["environment"] != expected_environment
        or invocation["entrypoint_sha256"] != bound_entrypoint_sha
        or invocation["argv"]
        != [
            invocation["interpreter_path"],
            "-B",
            "-P",
            "-S",
            "-m",
            entrypoint_module,
            "--activation-contract",
            invocation["contract_path"],
            "--activation-plan",
            invocation["plan_path"],
            "--activation-role",
            role,
            "--activation-call-index",
            str(invocation["call_index"]),
        ]
    ):
        raise LauncherError("invocation_identity_rejected")
    try:
        _verify_interpreter(validated_contract["interpreter"])
        _regular_file(
            Path(str(invocation["entrypoint_path"])),
            expected_sha256=str(invocation["entrypoint_sha256"]),
        )
        _regular_file(
            Path(str(invocation["contract_path"])),
            expected_sha256=str(invocation["contract_sha256"]),
        )
        _regular_file(
            Path(str(invocation["plan_path"])),
            expected_sha256=str(invocation["plan_sha256"]),
        )
    except LauncherError:
        raise LauncherError("invocation_identity_rejected") from None
    unsigned = {key: value for key, value in invocation.items() if key != "invocation_digest"}
    if contract_v1.digest_value(unsigned) != invocation["invocation_digest"]:
        raise LauncherError("invocation_digest_rejected")
    return dict(invocation)


def build_supervisor_bootstrap_intent(
    contract: Mapping[str, object],
    *,
    entry_nonce: str,
    intent_path: Path,
    contract_path: Path,
    root: Path,
    backend: str,
    target_source_path: Path,
    target_inventory: list[dict[str, object]],
    target_directories: list[dict[str, object]],
    acceptance_scope_digest: str | None,
    recover_plan: Path | None,
    sequence_identity: str | None = None,
    origin_entry_nonce: str | None = None,
    origin_capture_digest: str | None = None,
    guardian_obligation_digest: str | None = None,
    guardian_child_digest: str | None = None,
    parent_pipe_fd: int,
    parent_nonce_sha256: str,
) -> dict[str, object]:
    validated = contract_v1.validate_contract(contract)
    bootstrap = validated["launcher"]["supervisor_bootstrap"]
    verify_runtime_inventory(
        validated, target_source_path, target_inventory, target_directories
    )
    sequence_identity = entry_nonce if sequence_identity is None else sequence_identity
    if (
        contract_v1.HEX64.fullmatch(entry_nonce) is None
        or contract_v1.HEX64.fullmatch(sequence_identity) is None
        or contract_v1.HEX64.fullmatch(parent_nonce_sha256) is None
        or isinstance(parent_pipe_fd, bool)
        or not isinstance(parent_pipe_fd, int)
        or parent_pipe_fd < 3
    ):
        raise LauncherError("supervisor_bootstrap_nonce_rejected")
    if not root.is_absolute() or not intent_path.is_absolute():
        raise LauncherError("supervisor_bootstrap_path_rejected")
    expected_contract_path = target_source_path / str(
        contract_v1.release_manifest_binding(validated)["contract_path"]
    )
    if contract_path != expected_contract_path:
        raise LauncherError("supervisor_bootstrap_path_rejected")
    _regular_file(
        contract_path,
        expected_sha256=sha256(contract_v1.canonical_bytes(validated)).hexdigest(),
    )
    if backend not in {"synthetic", "systemd"}:
        raise LauncherError("supervisor_bootstrap_arguments_rejected")
    if (recover_plan is None) == (acceptance_scope_digest is None):
        raise LauncherError("supervisor_bootstrap_arguments_rejected")
    guardian_recovery = (
        guardian_obligation_digest is not None or guardian_child_digest is not None
    )
    if guardian_recovery and (
        not isinstance(guardian_obligation_digest, str)
        or contract_v1.HEX64.fullmatch(guardian_obligation_digest) is None
        or not isinstance(guardian_child_digest, str)
        or contract_v1.HEX64.fullmatch(guardian_child_digest) is None
    ):
        raise LauncherError("supervisor_bootstrap_arguments_rejected")
    if recover_plan is None:
        if (
            origin_entry_nonce is not None
            or origin_capture_digest is not None
            or guardian_recovery
        ):
            raise LauncherError("supervisor_bootstrap_arguments_rejected")
    elif (
        origin_entry_nonce is None
        or contract_v1.HEX64.fullmatch(origin_entry_nonce) is None
        or (
            origin_capture_digest is not None
            and contract_v1.HEX64.fullmatch(origin_capture_digest) is None
        )
        or (origin_capture_digest is None and not guardian_recovery)
    ):
        raise LauncherError("supervisor_bootstrap_arguments_rejected")
    if acceptance_scope_digest is not None and contract_v1.HEX64.fullmatch(
        acceptance_scope_digest
    ) is None:
        raise LauncherError("supervisor_bootstrap_arguments_rejected")
    interpreter = Path(str(validated["interpreter"]["invocation_path"]))
    _verify_interpreter(validated["interpreter"])
    child_relative = str(bootstrap["child_entrypoint"])
    child_path = target_source_path / child_relative
    child_sha256 = _inventory_sha(target_inventory, child_relative)
    _regular_file(child_path, expected_sha256=child_sha256)
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": os.pathsep.join(
            (str(target_source_path / "scripts"), str(target_source_path / "src"))
        ),
        "MYUNA_P08_SUPERVISOR_BOOTSTRAP_INTENT": str(intent_path),
        "MYUNA_P08_SUPERVISOR_PARENT_FD": str(parent_pipe_fd),
    }
    arguments = [
        str(interpreter),
        "-B",
        "-P",
        "-S",
        "-m",
        Path(child_relative).stem,
        "--activation-contract",
        str(contract_path),
    ]
    if recover_plan is None:
        arguments.extend(
            [
                "--activation-root",
                str(root),
                "--activation-backend",
                backend,
                "--activation-target-source",
                str(target_source_path),
                "--acceptance-scope-digest",
                str(acceptance_scope_digest),
            ]
        )
    else:
        arguments.extend(["--recover-plan", str(recover_plan)])
    body = {
        "schema": contract_v1.SUPERVISOR_BOOTSTRAP_INTENT_SCHEMA,
        "contract_digest": validated["contract_digest"],
        "entry_nonce": entry_nonce,
        "sequence_identity": sequence_identity,
        "parent_nonce_sha256": parent_nonce_sha256,
        "intent_path": str(intent_path),
        "root": str(root),
        "backend": backend,
        "target_source_path": str(target_source_path),
        "target_inventory_digest": contract_v1.digest_value(target_inventory),
        "target_directories_digest": contract_v1.digest_value(target_directories),
        "acceptance_scope_digest": acceptance_scope_digest,
        "recover_plan": str(recover_plan) if recover_plan is not None else None,
        "origin_entry_nonce": origin_entry_nonce,
        "origin_capture_digest": origin_capture_digest,
        "guardian_obligation_digest": guardian_obligation_digest,
        "guardian_child_digest": guardian_child_digest,
        "interpreter_path": str(interpreter),
        "interpreter_sha256": validated["interpreter"]["sha256"],
        "entrypoint_path": str(child_path),
        "entrypoint_sha256": child_sha256,
        "contract_path": str(contract_path),
        "contract_sha256": sha256(contract_v1.canonical_bytes(validated)).hexdigest(),
        "cwd": str(target_source_path),
        "uid": validated["runtime_identity"]["uid"],
        "gid": validated["runtime_identity"]["gid"],
        "groups": validated["runtime_identity"]["groups"],
        "umask": validated["launcher"]["umask"],
        "closed_stdin": True,
        "environment": environment,
        "hard_deadline_seconds": bootstrap["hard_deadline_seconds"],
        "kill_grace_seconds": bootstrap["kill_grace_seconds"],
        "argv": arguments,
    }
    return {**body, "intent_digest": contract_v1.digest_value(body)}


def validate_supervisor_bootstrap_intent(
    contract: Mapping[str, object], intent: Mapping[str, object]
) -> dict[str, object]:
    validated = contract_v1.validate_contract(contract)
    keys = {
        "acceptance_scope_digest",
        "argv",
        "backend",
        "closed_stdin",
        "contract_digest",
        "contract_path",
        "contract_sha256",
        "cwd",
        "entry_nonce",
        "sequence_identity",
        "entrypoint_path",
        "entrypoint_sha256",
        "environment",
        "gid",
        "groups",
        "hard_deadline_seconds",
        "intent_digest",
        "intent_path",
        "interpreter_path",
        "interpreter_sha256",
        "kill_grace_seconds",
        "parent_nonce_sha256",
        "origin_capture_digest",
        "origin_entry_nonce",
        "guardian_obligation_digest",
        "guardian_child_digest",
        "recover_plan",
        "root",
        "schema",
        "target_directories_digest",
        "target_inventory_digest",
        "target_source_path",
        "uid",
        "umask",
    }
    if not isinstance(intent, Mapping) or set(intent) != keys:
        raise LauncherError("supervisor_bootstrap_intent_rejected")
    bootstrap = validated["launcher"]["supervisor_bootstrap"]
    if (
        intent["schema"] != contract_v1.SUPERVISOR_BOOTSTRAP_INTENT_SCHEMA
        or intent["contract_digest"] != validated["contract_digest"]
        or intent["closed_stdin"] is not True
        or intent["interpreter_path"] != validated["interpreter"]["invocation_path"]
        or intent["interpreter_sha256"] != validated["interpreter"]["sha256"]
        or intent["uid"] != validated["runtime_identity"]["uid"]
        or intent["gid"] != validated["runtime_identity"]["gid"]
        or intent["groups"] != validated["runtime_identity"]["groups"]
        or intent["umask"] != validated["launcher"]["umask"]
        or intent["hard_deadline_seconds"] != bootstrap["hard_deadline_seconds"]
        or intent["kill_grace_seconds"] != bootstrap["kill_grace_seconds"]
    ):
        raise LauncherError("supervisor_bootstrap_intent_rejected")
    for key in (
        "contract_sha256",
        "entry_nonce",
        "sequence_identity",
        "entrypoint_sha256",
        "intent_digest",
        "parent_nonce_sha256",
        "target_directories_digest",
        "target_inventory_digest",
    ):
        if not isinstance(intent[key], str) or contract_v1.HEX64.fullmatch(
            intent[key]
        ) is None:
            raise LauncherError("supervisor_bootstrap_intent_rejected")
    target_source = Path(str(intent["target_source_path"]))
    root = Path(str(intent["root"]))
    intent_path = Path(str(intent["intent_path"]))
    contract_path = Path(str(intent["contract_path"]))
    child_relative = str(bootstrap["child_entrypoint"])
    child_path = target_source / child_relative
    expected_contract_path = target_source / str(
        contract_v1.release_manifest_binding(validated)["contract_path"]
    )
    raw_environment = intent["environment"]
    if not isinstance(raw_environment, Mapping):
        raise LauncherError("supervisor_bootstrap_intent_rejected")
    raw_parent_fd = raw_environment.get("MYUNA_P08_SUPERVISOR_PARENT_FD")
    if (
        not isinstance(raw_parent_fd, str)
        or not raw_parent_fd.isdigit()
        or int(raw_parent_fd) < 3
    ):
        raise LauncherError("supervisor_bootstrap_intent_rejected")
    expected_environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": os.pathsep.join(
            (str(target_source / "scripts"), str(target_source / "src"))
        ),
        "MYUNA_P08_SUPERVISOR_BOOTSTRAP_INTENT": str(intent_path),
        "MYUNA_P08_SUPERVISOR_PARENT_FD": raw_parent_fd,
    }
    expected_arguments = [
        str(validated["interpreter"]["invocation_path"]),
        "-B",
        "-P",
        "-S",
        "-m",
        Path(child_relative).stem,
        "--activation-contract",
        str(expected_contract_path),
    ]
    recover_plan = intent["recover_plan"]
    origin_entry_nonce = intent["origin_entry_nonce"]
    origin_capture_digest = intent["origin_capture_digest"]
    guardian_obligation_digest = intent["guardian_obligation_digest"]
    guardian_child_digest = intent["guardian_child_digest"]
    guardian_recovery = (
        guardian_obligation_digest is not None or guardian_child_digest is not None
    )
    if recover_plan is None:
        expected_arguments.extend(
            [
                "--activation-root",
                str(root),
                "--activation-backend",
                str(intent["backend"]),
                "--activation-target-source",
                str(target_source),
                "--acceptance-scope-digest",
                str(intent["acceptance_scope_digest"]),
            ]
        )
    else:
        expected_arguments.extend(["--recover-plan", str(recover_plan)])
    expected_intent_path = (
        root
        / str(validated["production_adapter"]["fixed_paths"]["strategy_root"]).lstrip("/")
        / "entries"
        / str(intent["entry_nonce"])
        / "INTENT.json"
    )
    if (
        not target_source.is_absolute()
        or contract_v1.HEX64.fullmatch(target_source.name) is None
        or not root.is_absolute()
        or intent_path != expected_intent_path
        or contract_path != expected_contract_path
        or Path(str(intent["entrypoint_path"])) != child_path
        or intent["entrypoint_sha256"]
        != _inventory_sha(validated["engine_source"]["source_inventory"], child_relative)
        or intent["contract_sha256"]
        != sha256(contract_v1.canonical_bytes(validated)).hexdigest()
        or intent["cwd"] != str(target_source)
        or intent["environment"] != expected_environment
        or intent["argv"] != expected_arguments
        or intent["backend"] not in {"synthetic", "systemd"}
        or (recover_plan is None) == (intent["acceptance_scope_digest"] is None)
        or (
            recover_plan is None
            and (
                origin_entry_nonce is not None
                or origin_capture_digest is not None
                or guardian_recovery
            )
        )
        or (
            recover_plan is not None
            and (
                not isinstance(origin_entry_nonce, str)
                or contract_v1.HEX64.fullmatch(origin_entry_nonce) is None
                or (
                    origin_capture_digest is not None
                    and (
                        not isinstance(origin_capture_digest, str)
                        or contract_v1.HEX64.fullmatch(origin_capture_digest) is None
                    )
                )
                or (origin_capture_digest is None and not guardian_recovery)
            )
        )
        or (
            guardian_recovery
            and (
                not isinstance(guardian_obligation_digest, str)
                or contract_v1.HEX64.fullmatch(guardian_obligation_digest) is None
                or not isinstance(guardian_child_digest, str)
                or contract_v1.HEX64.fullmatch(guardian_child_digest) is None
            )
        )
        or (
            intent["acceptance_scope_digest"] is not None
            and contract_v1.HEX64.fullmatch(str(intent["acceptance_scope_digest"]))
            is None
        )
    ):
        raise LauncherError("supervisor_bootstrap_intent_rejected")
    unsigned = {key: value for key, value in intent.items() if key != "intent_digest"}
    if contract_v1.digest_value(unsigned) != intent["intent_digest"]:
        raise LauncherError("supervisor_bootstrap_intent_rejected")
    _verify_interpreter(validated["interpreter"])
    _regular_file(
        Path(str(intent["entrypoint_path"])),
        expected_sha256=str(intent["entrypoint_sha256"]),
    )
    _regular_file(
        Path(str(intent["contract_path"])),
        expected_sha256=str(intent["contract_sha256"]),
    )
    return dict(intent)


def verify_current_supervisor_entry(
    contract: Mapping[str, object],
    intent: Mapping[str, object],
    *,
    argv: list[str],
) -> dict[str, object]:
    validated = validate_supervisor_bootstrap_intent(contract, intent)
    expected_environment = dict(validated["environment"])
    try:
        stdin_target = os.readlink("/proc/self/fd/0")
    except OSError:
        raise LauncherError("supervisor_bootstrap_process_rejected") from None
    if (
        Path.cwd() != Path(str(validated["cwd"]))
        or Path(sys.executable) != Path(str(validated["interpreter_path"]))
        or os.getuid() != validated["uid"]
        or os.getgid() != validated["gid"]
        or sorted(os.getgroups()) != validated["groups"]
        or dict(os.environ) != expected_environment
        or argv != validated["argv"]
        or stdin_target != "/dev/null"
    ):
        raise LauncherError("supervisor_bootstrap_process_rejected")
    raw_fd = expected_environment.get("MYUNA_P08_SUPERVISOR_PARENT_FD")
    try:
        descriptor = int(str(raw_fd))
        nonce = bytearray()
        while len(nonce) <= 32:
            chunk = os.read(descriptor, 33 - len(nonce))
            if not chunk:
                break
            nonce.extend(chunk)
    except (OSError, ValueError):
        raise LauncherError("supervisor_bootstrap_parent_rejected") from None
    finally:
        if "descriptor" in locals():
            try:
                os.close(descriptor)
            except OSError:
                pass
    if len(nonce) != 32 or sha256(bytes(nonce)).hexdigest() != validated[
        "parent_nonce_sha256"
    ]:
        raise LauncherError("supervisor_bootstrap_parent_rejected")
    return validated


def run_supervisor_bootstrap_capture(
    contract: Mapping[str, object],
    intent: Mapping[str, object],
    *,
    parent_pipe_fds: tuple[int, int],
    parent_nonce: bytes,
    child_started: Callable[[subprocess.Popen[bytes]], None] | None = None,
    guardian_parent_identity: tuple[int, int] | None = None,
    hard_deadline_seconds_override: int | None = None,
) -> dict[str, object]:
    validated = validate_supervisor_bootstrap_intent(contract, intent)
    read_fd, write_fd = parent_pipe_fds
    expected_fd = int(
        str(validated["environment"]["MYUNA_P08_SUPERVISOR_PARENT_FD"])
    )
    if (
        read_fd != expected_fd
        or len(parent_nonce) != 32
        or sha256(parent_nonce).hexdigest() != validated["parent_nonce_sha256"]
    ):
        raise LauncherError("supervisor_bootstrap_parent_rejected")
    hard_deadline_seconds = int(validated["hard_deadline_seconds"])
    if hard_deadline_seconds_override is not None:
        if (
            not isinstance(hard_deadline_seconds_override, int)
            or isinstance(hard_deadline_seconds_override, bool)
            or hard_deadline_seconds_override < 1
            or hard_deadline_seconds_override > hard_deadline_seconds
        ):
            raise LauncherError("supervisor_bootstrap_deadline_rejected")
        hard_deadline_seconds = hard_deadline_seconds_override
    started = time.monotonic()
    exit_class = "exit"
    try:
        child = subprocess.Popen(
            list(validated["argv"]),
            cwd=str(validated["cwd"]),
            env=dict(validated["environment"]),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            umask=int(validated["umask"]),
            pass_fds=(read_fd,),
        )
        if child_started is not None:
            try:
                child_started(child)
            except Exception:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.communicate(timeout=int(validated["kill_grace_seconds"]))
                raise LauncherError("supervisor_bootstrap_child_identity_rejected") from None
        # The child blocks on this one-time nonce.  Durable child identity is
        # therefore established before the child can create PLAN or mutate
        # product state; a failed identity write kills the still-unauthorized
        # child and remains pre-mutation.
        offset = 0
        while offset < len(parent_nonce):
            written = os.write(write_fd, parent_nonce[offset:])
            if written < 1:
                raise OSError("short bootstrap nonce write")
            offset += written
        os.close(write_fd)
        write_fd = -1
    except OSError:
        raise LauncherError("supervisor_bootstrap_child_rejected") from None
    finally:
        if write_fd >= 0:
            try:
                os.close(write_fd)
            except OSError:
                pass
    try:
        os.close(read_fd)
    except OSError:
        pass
    deadline = started + hard_deadline_seconds
    while True:
        remaining = deadline - time.monotonic()
        parent_lost = False
        if guardian_parent_identity is not None:
            parent_pid, parent_start_ticks = guardian_parent_identity
            try:
                raw = Path(f"/proc/{parent_pid}/stat").read_text(encoding="ascii")
                observed_ticks = int(raw[raw.rindex(")") + 2 :].split()[19])
                parent_lost = observed_ticks != parent_start_ticks
            except (OSError, ValueError, IndexError):
                parent_lost = True
        if parent_lost or remaining <= 0:
            exit_class = "guardian_parent_lost" if parent_lost else "hard_timeout"
            break
        try:
            stdout, stderr = child.communicate(
                timeout=min(0.1, remaining)
            )
            break
        except subprocess.TimeoutExpired:
            continue
    if exit_class in {"hard_timeout", "guardian_parent_lost"}:
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = child.communicate(
                timeout=int(validated["kill_grace_seconds"])
            )
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = child.communicate(
                timeout=int(validated["kill_grace_seconds"])
            )
    canonical_result = None
    canonical_status = "indeterminate"
    if (
        exit_class == "exit"
        and child.returncode in {0, 2}
        and not stderr
        and 0 < len(stdout) <= MAX_STDOUT_BYTES
        and stdout.endswith(b"\n")
    ):
        try:
            parsed = json.loads(stdout)
            if stdout != contract_v1.canonical_bytes(parsed):
                raise contract_v1.ContractError("supervisor_bootstrap_output_rejected")
            canonical_result = contract_v1.validate_supervisor_bootstrap_output(parsed)
            canonical_status = "complete"
        except (UnicodeDecodeError, json.JSONDecodeError, contract_v1.ContractError):
            canonical_result = None
            canonical_status = "indeterminate"
    body = {
        "schema": contract_v1.SUPERVISOR_BOOTSTRAP_CAPTURE_SCHEMA,
        "contract_digest": contract["contract_digest"],
        "intent_digest": validated["intent_digest"],
        "entry_nonce": validated["entry_nonce"],
        "hard_deadline_seconds": hard_deadline_seconds,
        "exit_class": exit_class,
        "returncode": child.returncode,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "stdout_size": len(stdout),
        "stdout_sha256": sha256(stdout).hexdigest(),
        "stderr_size": len(stderr),
        "stderr_sha256": sha256(stderr).hexdigest(),
        "canonical_status": canonical_status,
        "canonical_result": canonical_result,
        "canonical_result_digest": (
            contract_v1.digest_value(canonical_result)
            if canonical_result is not None
            else None
        ),
        "raw_output_retained": False,
        "orphan_count": _process_group_orphan_count(child.pid),
    }
    return {**body, "capture_digest": contract_v1.digest_value(body)}


def validate_supervisor_bootstrap_capture(
    contract: Mapping[str, object],
    intent: Mapping[str, object],
    capture: Mapping[str, object],
) -> dict[str, object]:
    validated_intent = validate_supervisor_bootstrap_intent(contract, intent)
    keys = {
        "canonical_result",
        "canonical_result_digest",
        "canonical_status",
        "capture_digest",
        "contract_digest",
        "elapsed_ms",
        "entry_nonce",
        "exit_class",
        "intent_digest",
        "hard_deadline_seconds",
        "orphan_count",
        "raw_output_retained",
        "returncode",
        "schema",
        "stderr_sha256",
        "stderr_size",
        "stdout_sha256",
        "stdout_size",
    }
    if not isinstance(capture, Mapping) or set(capture) != keys:
        raise LauncherError("supervisor_bootstrap_capture_rejected")
    if (
        capture["schema"] != contract_v1.SUPERVISOR_BOOTSTRAP_CAPTURE_SCHEMA
        or capture["contract_digest"] != contract["contract_digest"]
        or capture["intent_digest"] != validated_intent["intent_digest"]
        or capture["entry_nonce"] != validated_intent["entry_nonce"]
        or capture["raw_output_retained"] is not False
        or capture["exit_class"] not in {
            "exit",
            "hard_timeout",
            "guardian_parent_lost",
        }
        or capture["canonical_status"] not in {"complete", "indeterminate"}
        or capture["orphan_count"] != 0
        or not isinstance(capture["hard_deadline_seconds"], int)
        or isinstance(capture["hard_deadline_seconds"], bool)
        or capture["hard_deadline_seconds"] < 1
        or capture["hard_deadline_seconds"]
        > validated_intent["hard_deadline_seconds"]
    ):
        raise LauncherError("supervisor_bootstrap_capture_rejected")
    for key in ("elapsed_ms", "orphan_count", "stderr_size", "stdout_size"):
        if (
            not isinstance(capture[key], int)
            or isinstance(capture[key], bool)
            or capture[key] < 0
        ):
            raise LauncherError("supervisor_bootstrap_capture_rejected")
    if not isinstance(capture["returncode"], int) or isinstance(
        capture["returncode"], bool
    ):
        raise LauncherError("supervisor_bootstrap_capture_rejected")
    for key in ("capture_digest", "stderr_sha256", "stdout_sha256"):
        if not isinstance(capture[key], str) or contract_v1.HEX64.fullmatch(
            capture[key]
        ) is None:
            raise LauncherError("supervisor_bootstrap_capture_rejected")
    empty_sha256 = sha256(b"").hexdigest()
    if (
        (capture["stderr_size"] == 0)
        != (capture["stderr_sha256"] == empty_sha256)
        or (capture["stdout_size"] == 0)
        != (capture["stdout_sha256"] == empty_sha256)
    ):
        raise LauncherError("supervisor_bootstrap_capture_rejected")
    if capture["canonical_result"] is None:
        if (
            capture["canonical_result_digest"] is not None
            or capture["canonical_status"] != "indeterminate"
        ):
            raise LauncherError("supervisor_bootstrap_capture_rejected")
    else:
        validated_result = contract_v1.validate_supervisor_bootstrap_output(
            capture["canonical_result"]
        )
        expected_returncode = (
            0 if validated_result.get("terminal_status") == "accepted" else 2
        )
        if (
            capture["canonical_status"] != "complete"
            or capture["exit_class"] != "exit"
            or capture["returncode"] != expected_returncode
            or capture["stderr_size"] != 0
            or capture["stdout_size"] < 1
            or capture["stdout_size"] > MAX_STDOUT_BYTES
            or capture["canonical_result_digest"]
            != contract_v1.digest_value(validated_result)
        ):
            raise LauncherError("supervisor_bootstrap_capture_rejected")
    if capture["exit_class"] in {"hard_timeout", "guardian_parent_lost"} and (
        capture["canonical_result"] is not None
        or capture["canonical_status"] != "indeterminate"
        or capture["returncode"] >= 0
    ):
        raise LauncherError("supervisor_bootstrap_capture_rejected")
    unsigned = {key: value for key, value in capture.items() if key != "capture_digest"}
    if contract_v1.digest_value(unsigned) != capture["capture_digest"]:
        raise LauncherError("supervisor_bootstrap_capture_rejected")
    return dict(capture)


def progress_bytes(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    role: str,
    phase: str,
    phase_index: int,
) -> bytes:
    validated_contract = contract_v1.validate_contract(contract)
    validated_plan = contract_v1.validate_plan(validated_contract, plan)
    phases = validated_contract["roles"][role]["progress_phases"]
    if phase_index < 1 or phase_index > len(phases) or phases[phase_index - 1] != phase:
        raise LauncherError("progress_phase_rejected")
    payload = {
        "schema": contract_v1.PROGRESS_SCHEMA,
        "contract_digest": validated_contract["contract_digest"],
        "plan_digest": validated_plan["plan_digest"],
        "sequence_identity": validated_plan["sequence_identity"],
        "invocation_nonce": validated_plan["invocation_nonce"],
        "role": role,
        "phase": phase,
        "phase_index": phase_index,
    }
    return contract_v1.canonical_bytes(payload)


def validate_progress(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    role: str,
    raw: bytes,
) -> list[dict[str, object]]:
    validated_contract = contract_v1.validate_contract(contract)
    validated_plan = contract_v1.validate_plan(validated_contract, plan)
    if not raw or len(raw) > MAX_PROGRESS_BYTES or not raw.endswith(b"\n"):
        raise LauncherError("progress_stream_rejected")
    phases = validated_contract["roles"][role]["progress_phases"]
    records = []
    for expected_index, line in enumerate(raw.splitlines(), 1):
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise LauncherError("progress_stream_rejected") from None
        keys = {
            "contract_digest",
            "invocation_nonce",
            "phase",
            "phase_index",
            "plan_digest",
            "role",
            "schema",
            "sequence_identity",
        }
        if not isinstance(value, dict) or set(value) != keys:
            raise LauncherError("progress_stream_rejected")
        if line + b"\n" != contract_v1.canonical_bytes(value):
            raise LauncherError("progress_stream_rejected")
        if (
            expected_index > len(phases)
            or value["schema"] != contract_v1.PROGRESS_SCHEMA
            or value["contract_digest"] != validated_contract["contract_digest"]
            or value["plan_digest"] != validated_plan["plan_digest"]
            or value["sequence_identity"] != validated_plan["sequence_identity"]
            or value["invocation_nonce"] != validated_plan["invocation_nonce"]
            or value["role"] != role
            or value["phase_index"] != expected_index
            or value["phase"] != phases[expected_index - 1]
        ):
            raise LauncherError("progress_stream_rejected")
        records.append(value)
    return records


def _capture_result(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    invocation: Mapping[str, object],
    *,
    stdout: bytes,
    stderr: bytes,
    progress: bytes,
    returncode: int,
    exit_class: str,
    elapsed_ms: int,
    orphan_count: int,
) -> dict[str, object]:
    if (
        exit_class not in EXIT_CLASSES
        or not isinstance(returncode, int)
        or isinstance(returncode, bool)
        or not isinstance(elapsed_ms, int)
        or isinstance(elapsed_ms, bool)
        or elapsed_ms < 0
        or not isinstance(orphan_count, int)
        or isinstance(orphan_count, bool)
        or orphan_count < 0
    ):
        raise LauncherError("capture_process_projection_rejected")
    canonical_result = None
    canonical_status = "indeterminate"
    progress_records: list[dict[str, object]] = []
    try:
        progress_records = validate_progress(
            contract, plan, role=str(invocation["role"]), raw=progress
        )
        if (
            exit_class != "exit"
            or orphan_count != 0
            or len(stdout) < 1
            or len(stdout) > MAX_STDOUT_BYTES
            or len(stderr) > MAX_STDERR_BYTES
            or stderr
            or not stdout.endswith(b"\n")
        ):
            raise LauncherError("capture_stream_rejected")
        value = json.loads(stdout)
        if stdout != contract_v1.canonical_bytes(value):
            raise LauncherError("capture_stream_rejected")
        canonical_result = contract_v1.validate_result(
            contract,
            plan,
            value,
            expected_role=str(invocation["role"]),
            expected_call=int(invocation["call_index"]),
        )
        if canonical_result["status"] in {"ready", "success"} and len(
            progress_records
        ) != len(contract["roles"][str(invocation["role"])]["progress_phases"]):
            raise LauncherError("progress_incomplete")
        if returncode == 0 and canonical_result["status"] in {"ready", "success"}:
            canonical_status = "ready"
        elif returncode == 2 and canonical_result["status"] == "rejected":
            canonical_status = "rejected"
        else:
            canonical_result = None
    except (LauncherError, contract_v1.ContractError, UnicodeDecodeError, json.JSONDecodeError):
        canonical_result = None
        canonical_status = "indeterminate"
    body = {
        "schema": contract_v1.CAPTURE_SCHEMA,
        "contract_digest": contract["contract_digest"],
        "plan_digest": plan["plan_digest"],
        "invocation_digest": invocation["invocation_digest"],
        "role": invocation["role"],
        "call_index": invocation["call_index"],
        "exit_class": exit_class,
        "returncode": returncode,
        "elapsed_ms": elapsed_ms,
        "stdout_size": len(stdout),
        "stdout_sha256": sha256(stdout).hexdigest(),
        "stderr_size": len(stderr),
        "stderr_sha256": sha256(stderr).hexdigest(),
        "progress_size": len(progress),
        "progress_sha256": sha256(progress).hexdigest(),
        "progress_count": len(progress_records),
        "last_progress_phase": progress_records[-1]["phase"] if progress_records else None,
        "canonical_status": canonical_status,
        "canonical_result_digest": (
            canonical_result["result_digest"] if canonical_result else None
        ),
        "canonical_result": canonical_result,
        "raw_output_retained": False,
        "orphan_count": orphan_count,
    }
    return {**body, "capture_digest": contract_v1.digest_value(body)}


def validate_capture(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    capture: Mapping[str, object],
    *,
    expected_role: str,
    expected_call: int,
) -> dict[str, object]:
    validated_contract = contract_v1.validate_contract(contract)
    validated_plan = contract_v1.validate_plan(validated_contract, plan)
    keys = {
        "call_index",
        "canonical_result",
        "canonical_result_digest",
        "canonical_status",
        "capture_digest",
        "contract_digest",
        "elapsed_ms",
        "exit_class",
        "invocation_digest",
        "last_progress_phase",
        "orphan_count",
        "plan_digest",
        "progress_count",
        "progress_sha256",
        "progress_size",
        "raw_output_retained",
        "returncode",
        "role",
        "schema",
        "stderr_sha256",
        "stderr_size",
        "stdout_sha256",
        "stdout_size",
    }
    if not isinstance(capture, Mapping) or set(capture) != keys:
        raise LauncherError("capture_keys_rejected")
    if (
        capture["schema"] != contract_v1.CAPTURE_SCHEMA
        or capture["contract_digest"] != validated_contract["contract_digest"]
        or capture["plan_digest"] != validated_plan["plan_digest"]
        or capture["role"] != expected_role
        or capture["call_index"] != expected_call
        or capture["raw_output_retained"] is not False
        or capture["exit_class"] not in EXIT_CLASSES
        or not isinstance(capture["returncode"], int)
        or isinstance(capture["returncode"], bool)
        or not isinstance(capture["elapsed_ms"], int)
        or isinstance(capture["elapsed_ms"], bool)
        or capture["elapsed_ms"] < 0
        or not isinstance(capture["orphan_count"], int)
        or isinstance(capture["orphan_count"], bool)
        or capture["orphan_count"] < 0
    ):
        raise LauncherError("capture_binding_rejected")
    for key in ("invocation_digest", "progress_sha256", "stderr_sha256", "stdout_sha256"):
        if not isinstance(capture[key], str) or contract_v1.HEX64.fullmatch(capture[key]) is None:
            raise LauncherError("capture_identity_rejected")
    for key in ("progress_count", "progress_size", "stderr_size", "stdout_size"):
        if not isinstance(capture[key], int) or isinstance(capture[key], bool) or capture[key] < 0:
            raise LauncherError("capture_size_rejected")
    canonical_result = capture["canonical_result"]
    if canonical_result is None:
        if capture["canonical_result_digest"] is not None or capture["canonical_status"] != "indeterminate":
            raise LauncherError("capture_result_rejected")
    else:
        try:
            validated_result = contract_v1.validate_result(
                validated_contract,
                validated_plan,
                canonical_result,
                expected_role=expected_role,
                expected_call=expected_call,
            )
        except contract_v1.ContractError:
            raise LauncherError("capture_result_rejected") from None
        if (
            capture["canonical_result_digest"] != validated_result["result_digest"]
            or capture["canonical_status"] not in {"ready", "rejected"}
            or capture["exit_class"] != "exit"
            or capture["orphan_count"] != 0
            or (
                capture["canonical_status"] == "ready"
                and validated_result["status"] not in {"ready", "success"}
            )
            or (
                capture["canonical_status"] == "rejected"
                and validated_result["status"] != "rejected"
            )
        ):
            raise LauncherError("capture_result_rejected")
    unsigned = {key: value for key, value in capture.items() if key != "capture_digest"}
    if contract_v1.digest_value(unsigned) != capture["capture_digest"]:
        raise LauncherError("capture_digest_rejected")
    return dict(capture)


def _process_group_orphan_count(process_group: int) -> int:
    """Return a content-free lower bound for surviving process-group members."""
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return 0
    except (PermissionError, OSError):
        return 1
    return 1


def run_capture(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    invocation: Mapping[str, object],
) -> dict[str, object]:
    invocation = validate_invocation(contract, plan, invocation)
    read_fd, write_fd = os.pipe()
    os.set_inheritable(write_fd, True)
    environment = dict(invocation["environment"])
    environment["MYUNA_P08_ACTIVATION_PROGRESS_FD"] = str(write_fd)
    started = time.monotonic()
    try:
        child = subprocess.Popen(
            list(invocation["argv"]),
            cwd=str(invocation["cwd"]),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(write_fd,),
            start_new_session=True,
            umask=int(invocation["umask"]),
        )
    except OSError:
        os.close(read_fd)
        os.close(write_fd)
        raise LauncherError("child_create_rejected") from None
    os.close(write_fd)
    assert child.stdout is not None and child.stderr is not None
    selector = selectors.DefaultSelector()
    for stream, label in (
        (child.stdout, "stdout"),
        (child.stderr, "stderr"),
    ):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, label)
    os.set_blocking(read_fd, False)
    selector.register(read_fd, selectors.EVENT_READ, "progress")
    buffers = {"stdout": bytearray(), "stderr": bytearray(), "progress": bytearray()}
    last_progress = started
    exit_class = "exit"
    timed_out = False
    hard_deadline = started + int(invocation["hard_deadline_seconds"])
    no_progress_deadline = started + int(invocation["no_progress_seconds"])
    validated_progress_count = 0
    while selector.get_map():
        now = time.monotonic()
        if now >= hard_deadline or now >= no_progress_deadline:
            timed_out = True
            exit_class = "hard_timeout" if now >= hard_deadline else "no_progress_timeout"
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            break
        events = selector.select(timeout=min(0.1, hard_deadline - now, no_progress_deadline - now))
        for key, _ in events:
            label = key.data
            fd = key.fileobj if isinstance(key.fileobj, int) else key.fileobj.fileno()
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                continue
            if not chunk:
                selector.unregister(key.fileobj)
                if isinstance(key.fileobj, int):
                    os.close(key.fileobj)
                else:
                    key.fileobj.close()
                continue
            buffers[label].extend(chunk)
            if label == "progress":
                if buffers[label].endswith(b"\n"):
                    try:
                        records = validate_progress(
                            contract,
                            plan,
                            role=str(invocation["role"]),
                            raw=bytes(buffers[label]),
                        )
                    except LauncherError:
                        timed_out = True
                        exit_class = "progress_invalid"
                        try:
                            os.killpg(child.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        break
                    if len(records) > validated_progress_count:
                        validated_progress_count = len(records)
                        last_progress = time.monotonic()
                        no_progress_deadline = last_progress + int(
                            invocation["no_progress_seconds"]
                        )
            limit = {
                "stdout": MAX_STDOUT_BYTES,
                "stderr": MAX_STDERR_BYTES,
                "progress": MAX_PROGRESS_BYTES,
            }[label]
            if len(buffers[label]) > limit:
                timed_out = True
                exit_class = f"{label}_oversize"
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                break
        if timed_out:
            break
        if child.poll() is not None and not selector.get_map():
            break
    if child.poll() is None:
        try:
            child.wait(timeout=1)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=1)
    # A killed child may leave bytes in already-open pipes; drain without blocking.
    for key in list(selector.get_map().values()):
        fd = key.fileobj if isinstance(key.fileobj, int) else key.fileobj.fileno()
        while True:
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                break
            if not chunk:
                break
            buffers[key.data].extend(chunk)
        selector.unregister(key.fileobj)
        if isinstance(key.fileobj, int):
            os.close(key.fileobj)
        else:
            key.fileobj.close()
    selector.close()
    elapsed_ms = int((time.monotonic() - started) * 1000)
    returncode = child.returncode if child.returncode is not None else -signal.SIGKILL
    if returncode < 0 and not timed_out:
        exit_class = "signal"
    orphan_count = _process_group_orphan_count(child.pid)
    return _capture_result(
        contract,
        plan,
        invocation,
        stdout=bytes(buffers["stdout"]),
        stderr=bytes(buffers["stderr"]),
        progress=bytes(buffers["progress"]),
        returncode=returncode,
        exit_class=exit_class,
        elapsed_ms=elapsed_ms,
        orphan_count=orphan_count,
    )


def persist_capture_o_excl(path: Path, capture: Mapping[str, object]) -> None:
    raw = contract_v1.canonical_bytes(capture)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_details = path.parent.lstat()
    if (
        not stat.S_ISDIR(parent_details.st_mode)
        or path.parent.is_symlink()
        or stat.S_IMODE(parent_details.st_mode) != 0o700
        or parent_details.st_uid != os.getuid()
        or parent_details.st_gid != os.getgid()
        or path.name in {"", ".", ".."}
    ):
        raise LauncherError("capture_parent_rejected")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    try:
        directory_fd = os.open(path.parent, directory_flags)
    except OSError:
        raise LauncherError("capture_parent_rejected") from None
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path.name, flags, 0o600, dir_fd=directory_fd)
    except OSError:
        os.close(directory_fd)
        raise LauncherError("capture_persistence_rejected") from None
    try:
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            if written < 1:
                raise LauncherError("capture_persistence_rejected")
            offset += written
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        raise
    os.close(fd)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    details = path.lstat()
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_nlink != 1
        or stat.S_IMODE(details.st_mode) != 0o600
        or path.read_bytes() != raw
    ):
        raise LauncherError("capture_persistence_rejected")
