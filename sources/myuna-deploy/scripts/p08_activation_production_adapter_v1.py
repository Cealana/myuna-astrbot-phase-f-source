#!/usr/bin/env python3
"""Production role adapter for ``myuna.p08-activation-engine.v1``.

The adapter owns concrete filesystem, unit, continuity and acceptance seams,
but owns no independent phase or identity allowlist.  Every input is derived
from the canonical contract and its single plan digest.  The same entrypoint is
used by the protected installed-target shadow and by a future separately
authorized live action.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import grp
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import socket
import stat
import subprocess
import sys
import signal
from typing import Callable, Mapping, Sequence

import p08_activation_contract_v1 as contract_v1
import p08_activation_boot_recovery_v1 as boot_recovery_v1
import p08_activation_launcher_v1 as launcher_v1


MAX_JSON_BYTES = 1_048_576
MAX_TARGET_FILES = 512
MAX_TARGET_FILE_BYTES = 16 * 1024 * 1024
MAX_STATE_FILE_BYTES = 2 * 1024 * 1024 * 1024
JOURNAL_SCHEMA = contract_v1.JOURNAL_SCHEMA
LEDGER_SCHEMA = contract_v1.LEDGER_SCHEMA
OPAQUE_BACKUP_SCHEMA = contract_v1.OPAQUE_BACKUP_SCHEMA
CONTINUITY_BINDING_SCHEMA = contract_v1.CONTINUITY_BINDING_SCHEMA
UNIT_RECEIPT_SCHEMA = contract_v1.UNIT_RECEIPT_SCHEMA
ACCEPTANCE_RECEIPT_SCHEMA = contract_v1.ACCEPTANCE_RECEIPT_SCHEMA


class AdapterError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        product_mutated: bool = False,
        infrastructure_mutated: bool = False,
        forward_state_possible: bool = False,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.product_mutated = product_mutated
        self.infrastructure_mutated = infrastructure_mutated
        self.forward_state_possible = forward_state_possible


class CanonicalArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise AdapterError("adapter_argument_rejected")


def _digest_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def _digest(path: Path, *, maximum: int = MAX_TARGET_FILE_BYTES) -> str:
    return _digest_bytes(_read_regular_bytes(path, maximum=maximum))


def _verify_regular_authority(
    path: Path, authority: Mapping[str, object]
) -> os.stat_result:
    try:
        details = _regular(path, maximum=max(MAX_TARGET_FILE_BYTES, int(authority["size"])))
    except (AdapterError, KeyError, TypeError, ValueError):
        raise AdapterError("execution_substrate_rejected") from None
    expected_path = authority.get("path", authority.get("resolved_path"))
    if (
        str(path) != expected_path
        or stat.S_IMODE(details.st_mode) != authority["mode"]
        or details.st_uid != authority["uid"]
        or details.st_gid != authority["gid"]
        or details.st_nlink != authority["nlink"]
        or details.st_size != authority["size"]
        or _digest(path, maximum=int(authority["size"])) != authority["sha256"]
    ):
        raise AdapterError("execution_substrate_rejected")
    return details


def _verify_systemd_substrate(authority: Mapping[str, object]) -> None:
    try:
        contract_v1._systemd_authority(authority)
        _verify_regular_authority(Path(str(authority["systemctl"]["path"])), authority["systemctl"])
        _verify_regular_authority(
            Path(str(authority["systemd_run"]["path"])),
            authority["systemd_run"],
        )
        _verify_regular_authority(
            Path(str(authority["environment_scrubber"]["path"])),
            authority["environment_scrubber"],
        )
        _verify_regular_authority(Path(str(authority["manager"]["path"])), authority["manager"])
        _verify_regular_authority(
            Path(str(authority["credential_drop"]["path"])),
            authority["credential_drop"],
        )
        manager_link = Path(str(authority["manager_proc_exe"]))
        link_details = manager_link.lstat()
        manager_target = os.readlink(manager_link)
    except (AdapterError, OSError, KeyError, TypeError, ValueError, contract_v1.ContractError):
        raise AdapterError("execution_substrate_rejected") from None
    if (
        not stat.S_ISLNK(link_details.st_mode)
        or manager_target != authority["manager"]["path"]
    ):
        raise AdapterError("execution_substrate_rejected")


def _run_bound_systemctl(
    execution: Mapping[str, object],
    arguments: Sequence[str],
    *,
    capture_stdout: bool,
    timeout: int,
) -> subprocess.CompletedProcess[bytes]:
    authority = execution.get("execution_substrate")
    if not isinstance(authority, Mapping):
        raise AdapterError("execution_substrate_rejected")
    _verify_systemd_substrate(authority)
    path = Path(str(authority["systemctl"]["path"]))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
    except OSError:
        raise AdapterError("execution_substrate_rejected") from None
    try:
        if _stat_identity(opened) != _stat_identity(
            _verify_regular_authority(path, authority["systemctl"])
        ):
            raise AdapterError("execution_substrate_rejected")
        completed = subprocess.run(
            [f"/proc/self/fd/{descriptor}", *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture_stdout else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            timeout=timeout,
            check=False,
            pass_fds=(descriptor,),
        )
        after = os.fstat(descriptor)
        if _stat_identity(opened) != _stat_identity(after):
            raise AdapterError("execution_substrate_rejected")
        _verify_systemd_substrate(authority)
    except (OSError, subprocess.SubprocessError):
        raise AdapterError("execution_substrate_rejected") from None
    finally:
        os.close(descriptor)
    return completed


def _run_bound_systemd_run(
    authority: Mapping[str, object],
    arguments: Sequence[str],
    *,
    timeout: int,
) -> subprocess.CompletedProcess[bytes]:
    _verify_systemd_substrate(authority)
    path = Path(str(authority["systemd_run"]["path"]))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
    except OSError:
        raise AdapterError("execution_substrate_rejected") from None
    try:
        if _stat_identity(opened) != _stat_identity(
            _verify_regular_authority(path, authority["systemd_run"])
        ):
            raise AdapterError("execution_substrate_rejected")
        completed = subprocess.run(
            [f"/proc/self/fd/{descriptor}", *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            timeout=timeout,
            check=False,
            pass_fds=(descriptor,),
        )
        if _stat_identity(opened) != _stat_identity(os.fstat(descriptor)):
            raise AdapterError("execution_substrate_rejected")
        _verify_systemd_substrate(authority)
    except (OSError, subprocess.SubprocessError):
        raise AdapterError("execution_substrate_rejected") from None
    finally:
        os.close(descriptor)
    return completed


def _stat_identity(details: os.stat_result) -> tuple[int, ...]:
    return (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_uid,
        details.st_gid,
        details.st_nlink,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
    )


def _verify_parent_directories(path: Path) -> None:
    if not path.is_absolute():
        raise AdapterError("path_identity_rejected")
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current /= part
        try:
            details = current.lstat()
        except OSError:
            raise AdapterError("path_identity_rejected") from None
        if not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode):
            raise AdapterError("path_identity_rejected")


def _read_regular_bytes(path: Path, *, maximum: int = MAX_TARGET_FILE_BYTES) -> bytes:
    before = _regular(path, maximum=maximum)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise AdapterError("file_read_rejected") from None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _stat_identity(opened) != _stat_identity(before)
        ):
            raise AdapterError("file_read_rejected")
        chunks = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise AdapterError("file_read_rejected")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise AdapterError("file_read_rejected")
    finally:
        os.close(descriptor)
    after = _regular(path, maximum=maximum)
    if _stat_identity(after) != _stat_identity(before):
        raise AdapterError("file_read_rejected")
    return b"".join(chunks)


def _regular(path: Path, *, maximum: int = MAX_TARGET_FILE_BYTES) -> os.stat_result:
    _verify_parent_directories(path)
    try:
        details = path.lstat()
    except OSError:
        raise AdapterError("file_identity_rejected") from None
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_nlink != 1
        or details.st_size < 0
        or details.st_size > maximum
    ):
        raise AdapterError("file_identity_rejected")
    return details


def _directory(path: Path, *, owner: bool = False) -> os.stat_result:
    if path != Path(path.anchor):
        _verify_parent_directories(path)
    try:
        details = path.lstat()
    except OSError:
        raise AdapterError("directory_identity_rejected") from None
    if (
        not stat.S_ISDIR(details.st_mode)
        or path.is_symlink()
        or (owner and (details.st_uid != os.getuid() or details.st_gid != os.getgid()))
    ):
        raise AdapterError("directory_identity_rejected")
    return details


def _rooted(root: Path, absolute: str) -> Path:
    if not root.is_absolute() or not absolute.startswith("/"):
        raise AdapterError("rooted_path_rejected")
    if root == Path("/"):
        selected = Path(absolute)
    else:
        selected = root / absolute.lstrip("/")
    try:
        selected.relative_to(root)
    except ValueError:
        raise AdapterError("rooted_path_rejected") from None
    return selected


def _expected_directories(files: Sequence[str]) -> set[str]:
    expected: set[str] = set()
    for relative in files:
        parent = Path(relative).parent
        while parent != Path("."):
            expected.add(parent.as_posix())
            parent = parent.parent
    return expected


def _tree_shape_exact(root: Path, expected_files: Sequence[str]) -> None:
    _directory(root)
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        details = path.lstat()
        if stat.S_ISDIR(details.st_mode) and not stat.S_ISLNK(details.st_mode):
            observed_directories.add(relative)
        elif stat.S_ISREG(details.st_mode) and details.st_nlink == 1:
            observed_files.add(relative)
        else:
            raise AdapterError("tree_shape_rejected")
    expected_file_set = set(expected_files)
    if (
        len(expected_file_set) != len(expected_files)
        or observed_files != expected_file_set
        or observed_directories != _expected_directories(expected_files)
    ):
        raise AdapterError("tree_shape_rejected")


def _fixed(contract: Mapping[str, object], execution: Mapping[str, object], role: str) -> Path:
    return _rooted(
        Path(str(execution["root"])),
        str(contract["production_adapter"]["fixed_paths"][role]),
    )


def _recovery_contract(contract: Mapping[str, object]) -> dict[str, object]:
    try:
        return boot_recovery_v1.boot_recovery_contract(contract)
    except boot_recovery_v1.BootRecoveryError:
        raise AdapterError("boot_recovery_contract_rejected") from None


def _recovery_artifact_path(
    execution: Mapping[str, object], artifact: Mapping[str, object]
) -> Path:
    return _rooted(Path(str(execution["root"])), str(artifact["path"]))


def _verify_recovery_artifact(
    execution: Mapping[str, object], artifact: Mapping[str, object]
) -> None:
    path = _recovery_artifact_path(execution, artifact)
    expected_uid = int(artifact["uid"]) if execution["backend"] == "systemd" else os.getuid()
    expected_gid = int(artifact["gid"]) if execution["backend"] == "systemd" else os.getgid()
    try:
        details = path.lstat()
    except OSError:
        raise AdapterError("boot_recovery_artifact_rejected") from None
    if artifact["type"] == "file":
        raw = str(artifact["content"]).encode("ascii")
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or details.st_nlink != 1
            or stat.S_IMODE(details.st_mode) != artifact["mode"]
            or details.st_uid != expected_uid
            or details.st_gid != expected_gid
            or details.st_size != artifact["size"]
            or _digest(path, maximum=max(len(raw), 1)) != artifact["sha256"]
            or _read_regular_bytes(path, maximum=max(len(raw), 1)) != raw
        ):
            raise AdapterError("boot_recovery_artifact_rejected")
        return
    if artifact["type"] != "symlink":
        raise AdapterError("boot_recovery_artifact_rejected")
    try:
        target = os.readlink(path)
    except OSError:
        raise AdapterError("boot_recovery_artifact_rejected") from None
    raw_target = target.encode("ascii", "strict")
    if (
        not stat.S_ISLNK(details.st_mode)
        or details.st_uid != expected_uid
        or details.st_gid != expected_gid
        or target != artifact["target"]
        or len(raw_target) != artifact["size"]
        or _digest_bytes(raw_target) != artifact["sha256"]
    ):
        raise AdapterError("boot_recovery_artifact_rejected")


def _recovery_artifacts_state(
    contract: Mapping[str, object], execution: Mapping[str, object]
) -> str:
    recovery = _recovery_contract(contract)
    runtime_root = _fixed(contract, execution, "recovery_runtime_root")
    paths = [
        runtime_root,
        *(
            _recovery_artifact_path(execution, artifact)
            for artifact in recovery["artifacts"]
        ),
    ]
    present = [path.exists() or path.is_symlink() for path in paths]
    if not any(present):
        return "absent"
    if not all(present):
        return "invalid"
    try:
        for artifact in recovery["artifacts"]:
            _verify_recovery_artifact(execution, artifact)
        for role in ("service_recovery_dropin", "socket_recovery_dropin"):
            directory = _fixed(contract, execution, role).parent
            _directory(directory)
            if sorted(path.name for path in directory.iterdir()) != [
                _fixed(contract, execution, role).name
            ]:
                raise AdapterError("boot_recovery_artifact_rejected")
    except (AdapterError, OSError):
        return "invalid"
    return "exact"


def _runtime_with_recovery_gate(
    contract: Mapping[str, object], runtime: Mapping[str, object]
) -> dict[str, object]:
    projected = json.loads(contract_v1.canonical_bytes(runtime))
    recovery_name = str(
        contract["production_adapter"]["fixed_paths"]["recovery_unit_name"]
    )
    for role in ("service", "socket"):
        dropin = str(
            contract["production_adapter"]["fixed_paths"][
                f"{role}_recovery_dropin"
            ]
        )
        projected[role]["drop_in_paths"] = [dropin]
        projected[role]["dependency_injection_paths"] = [
            dropin.rsplit("/", 1)[0]
        ]
        for name in ("After", "Requires"):
            projected[role]["dependencies"][name] = sorted(
                set(projected[role]["dependencies"][name]) | {recovery_name}
            )
    body = {key: value for key, value in projected.items() if key != "runtime_digest"}
    projected["runtime_digest"] = contract_v1.digest_value(body)
    try:
        return contract_v1._unit_runtime(projected)
    except contract_v1.ContractError:
        raise AdapterError("boot_recovery_unit_overlay_rejected") from None


def _gate_runtime(
    contract: Mapping[str, object],
    execution: Mapping[str, object],
    runtime: Mapping[str, object],
) -> dict[str, object]:
    state = _recovery_artifacts_state(contract, execution)
    if state == "absent":
        return dict(runtime)
    if state != "exact":
        states = _recovery_artifact_states(contract, {"execution": execution})
        # Exact transaction prefixes before the product gate files do not
        # change product-unit runtime.  Runtime/package/unit/enablement may be
        # partially present under the durable transaction obligation, but both
        # drop-ins must still be absent.  A one-sided gate is never normalized
        # into an expected runtime: convergence removes both exact files first,
        # then reloads this base projection.
        gate_roles = ("service_recovery_dropin", "socket_recovery_dropin")
        base_roles = ("recovery_unit", "recovery_enablement")
        if (
            all(states.get(role) in {"absent", "exact"} for role in base_roles)
            and all(states.get(role) == "absent" for role in gate_roles)
        ):
            return dict(runtime)
        raise AdapterError("boot_recovery_closure_rejected")
    return _runtime_with_recovery_gate(contract, runtime)


def _read_json(path: Path, *, maximum: int = MAX_JSON_BYTES) -> dict[str, object]:
    details = _regular(path, maximum=maximum)
    raw = _read_regular_bytes(path, maximum=maximum)
    if len(raw) != details.st_size or not raw.endswith(b"\n"):
        raise AdapterError("canonical_json_rejected")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AdapterError("canonical_json_rejected") from None
    if not isinstance(value, dict) or raw != contract_v1.canonical_bytes(value):
        raise AdapterError("canonical_json_rejected")
    return value


def _canonical_mapping(raw: bytes) -> dict[str, object]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AdapterError("canonical_json_rejected") from None
    if not isinstance(value, dict) or raw != contract_v1.canonical_bytes(value):
        raise AdapterError("canonical_json_rejected")
    return value


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise AdapterError("directory_sync_rejected") from None
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _exclusive_write(
    path: Path,
    raw: bytes,
    *,
    mode: int,
    uid: int | None = None,
    gid: int | None = None,
    on_boundary: Callable[[str], None] | None = None,
) -> None:
    def boundary(name: str) -> None:
        if on_boundary is not None:
            on_boundary(name)

    _directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        # Every interrupted create has one deterministic initial mode.  The
        # requested final mode is applied through the descriptor immediately
        # afterwards and is verified before the file can be published.
        descriptor = os.open(path, flags, 0o600)
    except OSError:
        raise AdapterError("exclusive_write_rejected") from None
    boundary("stage_open")
    try:
        os.fchmod(descriptor, mode)
        boundary("stage_chmod")
        if uid is not None and gid is not None:
            os.fchown(descriptor, uid, gid)
            boundary("stage_chown")
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written < 1:
                raise AdapterError("exclusive_write_rejected")
            offset += written
            boundary("stage_write")
        os.fsync(descriptor)
        boundary("stage_fsync")
    except BaseException:
        os.close(descriptor)
        raise
    os.close(descriptor)
    _fsync_directory(path.parent)
    details = _regular(path, maximum=max(len(raw), 1))
    if (
        stat.S_IMODE(details.st_mode) != mode
        or (uid is not None and details.st_uid != uid)
        or (gid is not None and details.st_gid != gid)
        or _read_regular_bytes(path, maximum=max(len(raw), 1)) != raw
    ):
        raise AdapterError("exclusive_write_rejected")
    boundary("stage_readback")


def _atomic_write(
    path: Path,
    raw: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
    token: str,
) -> None:
    _directory(path.parent)
    temporary = path.parent / f".{path.name}.{token}.new"
    _exclusive_write(temporary, raw, mode=mode, uid=uid, gid=gid)
    try:
        os.replace(temporary, path)
    except OSError:
        raise AdapterError("public_apply_rejected", product_mutated=True) from None
    _fsync_directory(path.parent)
    details = _regular(path, maximum=max(len(raw), 1))
    if (
        stat.S_IMODE(details.st_mode) != mode
        or details.st_uid != uid
        or details.st_gid != gid
        or _read_regular_bytes(path, maximum=max(len(raw), 1)) != raw
    ):
        raise AdapterError("public_apply_rejected", product_mutated=True)


def _public_projection(path: Path, *, absolute_path: str) -> dict[str, object]:
    details = _regular(path)
    return {
        "schema": contract_v1.PUBLIC_FILE_SCHEMA,
        "path": absolute_path,
        "type": "file",
        "mode": stat.S_IMODE(details.st_mode),
        "uid": details.st_uid,
        "gid": details.st_gid,
        "nlink": details.st_nlink,
        "size": details.st_size,
        "sha256": _digest(path),
    }


def opaque_metadata(root: Path, *, absolute_path: str) -> dict[str, object]:
    root_details = _directory(root)
    rows: list[dict[str, object]] = []
    directories: set[str] = set()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        details = path.lstat()
        if stat.S_ISDIR(details.st_mode) and not stat.S_ISLNK(details.st_mode):
            directories.add(relative)
            continue
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise AdapterError("opaque_state_metadata_rejected")
        if details.st_size < 0 or details.st_size > MAX_STATE_FILE_BYTES:
            raise AdapterError("opaque_state_metadata_rejected")
        rows.append(
            {
                "path": relative,
                "type": "file",
                "mode": stat.S_IMODE(details.st_mode),
                "uid": details.st_uid,
                "gid": details.st_gid,
                "nlink": details.st_nlink,
                "size": details.st_size,
            }
        )
    if not rows:
        raise AdapterError("opaque_state_metadata_rejected")
    # The current P08 protected state contract is deliberately flat.  Nested
    # directories would require independently bound mode/UID/GID/link metadata;
    # accepting them as implicit containers would weaken rollback authority.
    if directories:
        raise AdapterError("opaque_state_metadata_rejected")
    return {
        "schema": contract_v1.OPAQUE_STATE_SCHEMA,
        "root": {
            "path": absolute_path,
            "type": "directory",
            "mode": stat.S_IMODE(root_details.st_mode),
            "uid": root_details.st_uid,
            "gid": root_details.st_gid,
            "nlink": root_details.st_nlink,
        },
        "entries": rows,
    }


def target_inventory(root: Path) -> list[dict[str, object]]:
    _directory(root)
    rows: list[dict[str, object]] = []
    directories: set[str] = set()
    for path in sorted(root.rglob("*")):
        details = path.lstat()
        if stat.S_ISDIR(details.st_mode) and not path.is_symlink():
            directories.add(path.relative_to(root).as_posix())
            continue
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise AdapterError("target_inventory_rejected")
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            raise AdapterError("target_bytecode_rejected")
        if details.st_size < 1 or details.st_size > MAX_TARGET_FILE_BYTES:
            raise AdapterError("target_inventory_rejected")
        rows.append(
            {
                "path": path.relative_to(root).as_posix(),
                "type": "file",
                "mode": stat.S_IMODE(details.st_mode),
                "uid": details.st_uid,
                "gid": details.st_gid,
                "size": details.st_size,
                "sha256": _digest(path),
            }
        )
        try:
            launcher_v1._verify_python_import_collision(path)
        except launcher_v1.LauncherError:
            raise AdapterError("target_import_substitution_rejected") from None
    if not 1 <= len(rows) <= MAX_TARGET_FILES:
        raise AdapterError("target_inventory_rejected")
    if directories != _expected_directories([str(row["path"]) for row in rows]):
        raise AdapterError("target_inventory_rejected")
    return contract_v1._target_inventory(rows)


def target_directory_inventory(
    root: Path,
    *,
    file_inventory: list[dict[str, object]],
) -> list[dict[str, object]]:
    root_details = _directory(root)
    rows = [
        {
            "path": ".",
            "type": "directory",
            "mode": stat.S_IMODE(root_details.st_mode),
            "uid": root_details.st_uid,
            "gid": root_details.st_gid,
            "nlink": root_details.st_nlink,
        }
    ]
    for path in sorted(root.rglob("*")):
        details = path.lstat()
        if stat.S_ISDIR(details.st_mode) and not stat.S_ISLNK(details.st_mode):
            rows.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "type": "directory",
                    "mode": stat.S_IMODE(details.st_mode),
                    "uid": details.st_uid,
                    "gid": details.st_gid,
                    "nlink": details.st_nlink,
                }
            )
    rows.sort(key=lambda row: str(row["path"]))
    return contract_v1._target_directories(rows, file_inventory=file_inventory)


def _target_manifest(
    contract: Mapping[str, object],
    root: Path,
    inventory: list[dict[str, object]],
) -> dict[str, object]:
    manifest = _read_json(root / "manifest.json")
    files = manifest.get("files")
    expected_files = [
        {
            "path": row["path"],
            "size": row["size"],
            "sha256": row["sha256"],
        }
        for row in inventory
        if row["path"] != "manifest.json"
    ]
    if (
        set(manifest) != set(contract_v1.RELEASE_MANIFEST_KEYS)
        or manifest.get("schema") != contract_v1.RELEASE_SCHEMA
        or manifest.get("core_commit") != contract["engine_source"]["core_commit"]
        or manifest.get("deploy_commit")
        != contract["engine_source"]["deploy_commit"]
        or manifest.get("activation_engine_contract")
        != contract_v1.release_manifest_binding(contract)
        or manifest.get("legacy_activation_architecture_authoritative") is not False
        or files != expected_files
    ):
        raise AdapterError("target_manifest_binding_rejected")
    return manifest


def _unit_semantics_from_paths(
    service_path: Path, socket_path: Path
) -> dict[str, object]:
    try:
        return contract_v1.build_unit_semantics(
            _read_regular_bytes(service_path),
            _read_regular_bytes(socket_path),
        )
    except contract_v1.ContractError:
        raise AdapterError("unit_semantics_rejected") from None


def _predecessor_release_for_execution(
    contract: Mapping[str, object], *, root: Path, release_identity: str
) -> dict[str, object]:
    fixed = contract["production_adapter"]["fixed_paths"]
    source = _rooted(root, str(fixed["release_root"])) / release_identity
    if source.name != release_identity:
        raise AdapterError("predecessor_release_rejected")
    try:
        manifest_path = source / "manifest.json"
        manifest_details = _regular(manifest_path)
        manifest = _read_json(manifest_path)
        inventory = target_inventory(source)
        directories = target_directory_inventory(
            source,
            file_inventory=inventory,
        )
        semantics = _unit_semantics_from_paths(
            source / "systemd" / str(fixed["service_name"]),
            source / "systemd" / str(fixed["socket_name"]),
        )
        observed = contract_v1.build_predecessor_binding(
            release_identity=release_identity,
            manifest_sha256=_digest(manifest_path),
            manifest_size=manifest_details.st_size,
            manifest=manifest,
            inventory=inventory,
            directories=directories,
            unit_semantics=semantics,
        )
    except (contract_v1.ContractError, AdapterError, OSError):
        raise AdapterError("predecessor_release_rejected") from None
    expected = contract["compatibility"]["predecessor"]
    if observed != expected:
        raise AdapterError("predecessor_release_rejected")
    return observed


def _environment_rows(path: Path) -> dict[str, str]:
    try:
        raw = _read_regular_bytes(path).decode("ascii", "strict")
    except UnicodeDecodeError:
        raise AdapterError("environment_projection_rejected") from None
    rows: dict[str, str] = {}
    for line in raw.splitlines():
        if "=" not in line:
            raise AdapterError("environment_projection_rejected")
        key, value = line.split("=", 1)
        if not key or key in rows or not value:
            raise AdapterError("environment_projection_rejected")
        rows[key] = value
    return rows


def _verify_predecessor_public_binding(
    contract: Mapping[str, object],
    *,
    root: Path,
    backend: str,
    public: Mapping[str, object],
    selector: Mapping[str, object],
    environment_rows: Mapping[str, str],
) -> None:
    fixed = contract["production_adapter"]["fixed_paths"]
    predecessor = contract["compatibility"]["predecessor"]
    binding = predecessor["public_binding"]
    expected_owner = 0 if backend == "systemd" else os.getuid()
    expected_group = 0 if backend == "systemd" else os.getgid()
    for role in contract_v1.PUBLIC_ROLES:
        row = public[role]
        identity = binding["file_identity"][role]
        expected = dict(identity)
        expected["uid"] = expected_owner
        expected["gid"] = expected_group
        for key, expected_value in expected.items():
            if row[key] != expected_value:
                raise AdapterError("predecessor_public_identity_rejected")
    selector_binding = binding["selector"]
    for key, expected_value in selector_binding.items():
        if selector.get(key) != expected_value:
            raise AdapterError("selector_lineage_rejected")
    for key in ("gateway_manifest_digest", "plan_digest", "plugin_digest"):
        if contract_v1.HEX64.fullmatch(str(selector.get(key))) is None:
            raise AdapterError("selector_lineage_rejected")
    expected_environment_keys = {
        "MYUNA_P08_SERVICE_UID",
        "MYUNA_P08_STATE_ROOT",
        "MYUNA_P08_TELEGRAM_UID",
        "PYTHONPATH",
    }
    if (
        set(environment_rows) != expected_environment_keys
        or environment_rows["PYTHONPATH"] != binding["environment"]["pythonpath"]
        or environment_rows["MYUNA_P08_STATE_ROOT"]
        != binding["environment"]["state_root"]
    ):
        raise AdapterError("environment_lineage_rejected")
    semantics = _unit_semantics_from_paths(
        _rooted(root, str(fixed["service_unit"])),
        _rooted(root, str(fixed["socket_unit"])),
    )
    if semantics != predecessor["unit_semantics"]:
        raise AdapterError("unit_semantics_rejected")


def _validate_account_projection(
    contract: Mapping[str, object], value: object
) -> dict[str, object]:
    try:
        return contract_v1._account_projection(
            value,
            account_contract=contract["production_adapter"]["accounts"],
        )
    except contract_v1.ContractError:
        raise AdapterError("account_projection_rejected") from None


def _system_account_projection(contract: Mapping[str, object]) -> dict[str, object]:
    projected: dict[str, object] = {
        "schema": contract_v1.ACCOUNT_PROJECTION_SCHEMA,
    }
    for role in ("gateway", "service"):
        expected = contract["production_adapter"]["accounts"][role]
        try:
            account = pwd.getpwnam(str(expected["user"]))
            primary = grp.getgrgid(account.pw_gid)
            group_ids = sorted(set(os.getgrouplist(account.pw_name, account.pw_gid)))
            resolved_groups = [grp.getgrgid(group_id) for group_id in group_ids]
        except (KeyError, OSError):
            raise AdapterError("account_projection_rejected") from None
        groups = sorted(
            (
                {"gid": group.gr_gid, "name": group.gr_name}
                for group in resolved_groups
            ),
            key=lambda row: (str(row["name"]), int(row["gid"])),
        )
        if len({int(group["gid"]) for group in groups}) != len(groups):
            raise AdapterError("account_projection_rejected")
        projected[role] = {
            "user": account.pw_name,
            "uid": account.pw_uid,
            "primary_group": primary.gr_name,
            "gid": account.pw_gid,
            "groups": groups,
        }
    return _validate_account_projection(contract, projected)


def _account_projection_for_execution(
    contract: Mapping[str, object], *, root: Path, backend: str
) -> dict[str, object]:
    if backend == "synthetic":
        fixed = contract["production_adapter"]["fixed_paths"]
        return _validate_account_projection(
            contract,
            _read_json(_rooted(root, str(fixed["synthetic_account_state"]))),
        )
    return _system_account_projection(contract)


def _verify_account_authority(
    contract: Mapping[str, object], execution: Mapping[str, object]
) -> dict[str, object]:
    observed = _account_projection_for_execution(
        contract,
        root=Path(str(execution["root"])),
        backend=str(execution["backend"]),
    )
    if observed != execution["account_projection"]:
        raise AdapterError("account_projection_drifted")
    return observed


def _verify_unit_account_bindings(
    contract: Mapping[str, object], *, root: Path, target_source_path: Path
) -> None:
    fixed = contract["production_adapter"]["fixed_paths"]
    accounts = contract["production_adapter"]["accounts"]
    predecessor_expected = {
        "service_unit": (
            f"User={accounts['service']['user']}",
            f"Group={accounts['service']['primary_group']}",
        ),
        "socket_unit": (
            f"SocketUser={accounts['service']['user']}",
            f"SocketGroup={accounts['gateway']['primary_group']}",
        ),
    }
    target_runtime = contract["production_adapter"]["unit_runtime"]
    target_expected = {
        "service_unit": (
            "ExecStart=" + " ".join(target_runtime["service"]["exec_start_argv"]),
        ),
        "socket_unit": (
            f"SocketUser={target_runtime['socket']['socket_user']}",
            f"SocketGroup={target_runtime['socket']['socket_group']}",
        ),
    }
    target_paths = {
        "service_unit": target_source_path
        / "systemd/myuna-active-temporal-context-v1.service",
        "socket_unit": target_source_path
        / "systemd/myuna-active-temporal-context-v1.socket",
    }
    for role in ("service_unit", "socket_unit"):
        for path, required_lines in (
            (_rooted(root, str(fixed[role])), predecessor_expected[role]),
            (target_paths[role], target_expected[role]),
        ):
            try:
                lines = _read_regular_bytes(path).decode("ascii", "strict").splitlines()
            except UnicodeDecodeError:
                raise AdapterError("unit_account_binding_rejected") from None
            if any(lines.count(line) != 1 for line in required_lines):
                raise AdapterError("unit_account_binding_rejected")
            if path == target_paths.get("service_unit") and any(
                line.startswith(("User=", "Group=", "SupplementaryGroups="))
                for line in lines
            ):
                raise AdapterError("unit_account_binding_rejected")
    current_semantics = _unit_semantics_from_paths(
        _rooted(root, str(fixed["service_unit"])),
        _rooted(root, str(fixed["socket_unit"])),
    )
    target_semantics = _unit_semantics_from_paths(
        target_paths["service_unit"],
        target_paths["socket_unit"],
    )
    if (
        current_semantics != contract["compatibility"]["predecessor"]["unit_semantics"]
        or target_semantics != contract["production_adapter"]["unit_semantics"]
    ):
        raise AdapterError("unit_semantics_rejected")


def construct_execution(
    contract: Mapping[str, object],
    *,
    root: Path,
    backend: str,
    target_source_path: Path,
    acceptance_scope_digest: str,
    preclaim_phase_observer: Callable[[str], None] | None = None,
) -> dict[str, object]:
    def enter(phase: str) -> None:
        if preclaim_phase_observer is not None:
            preclaim_phase_observer(phase)

    enter("execution_contract")
    validated = contract_v1.validate_contract(contract)
    enter("execution_arguments")
    if backend not in validated["production_adapter"]["backends"]:
        raise AdapterError("execution_backend_rejected")
    if not root.is_absolute() or (backend == "synthetic") is (root == Path("/")):
        raise AdapterError("execution_root_rejected")
    if (
        not target_source_path.is_absolute()
        or contract_v1.HEX64.fullmatch(target_source_path.name) is None
    ):
        raise AdapterError("target_source_identity_rejected")
    fixed = validated["production_adapter"]["fixed_paths"]
    enter("execution_public")
    public = {
        role: _public_projection(
            _rooted(root, str(fixed[role])), absolute_path=str(fixed[role])
        )
        for role in contract_v1.PUBLIC_ROLES
    }
    enter("execution_selector")
    selector = _read_json(_rooted(root, str(fixed["selector"])))
    selector_keys = {
        "core_commit",
        "deploy_commit",
        "gateway_client_sha256",
        "gateway_manifest_digest",
        "plan_digest",
        "plugin_digest",
        "release_digest",
        "release_path",
        "schema",
    }
    if set(selector) != selector_keys:
        raise AdapterError("selector_identity_rejected")
    if (
        selector["schema"] != contract_v1.SELECTOR_SCHEMA
        or contract_v1.COMMIT40.fullmatch(str(selector["core_commit"])) is None
        or contract_v1.COMMIT40.fullmatch(str(selector["deploy_commit"])) is None
        or contract_v1.HEX64.fullmatch(str(selector["release_digest"])) is None
        or selector["release_path"]
        != str(Path(str(fixed["release_root"])) / str(selector["release_digest"]))
    ):
        raise AdapterError("selector_identity_rejected")
    compatibility_keys = {
        "gateway_client_sha256",
        "gateway_manifest_digest",
        "plugin_digest",
    }
    if not compatibility_keys.issubset(selector):
        raise AdapterError("selector_compatibility_rejected")
    enter("execution_predecessor")
    predecessor_release = _predecessor_release_for_execution(
        validated,
        root=root,
        release_identity=str(selector["release_digest"]),
    )
    enter("execution_opaque_metadata")
    opaque = opaque_metadata(
        _rooted(root, str(fixed["state_root"])),
        absolute_path=str(fixed["state_root"]),
    )
    enter("execution_accounts")
    account_projection = _account_projection_for_execution(
        validated,
        root=root,
        backend=backend,
    )
    enter("execution_unit_accounts")
    _verify_unit_account_bindings(
        validated,
        root=root,
        target_source_path=target_source_path,
    )
    enter("execution_environment")
    environment_rows = _environment_rows(
        _rooted(root, str(fixed["environment"]))
    )
    expected_environment_keys = {
        "MYUNA_P08_SERVICE_UID",
        "MYUNA_P08_STATE_ROOT",
        "MYUNA_P08_TELEGRAM_UID",
        "PYTHONPATH",
    }
    try:
        gateway_uid = int(environment_rows["MYUNA_P08_TELEGRAM_UID"])
        service_uid = int(environment_rows["MYUNA_P08_SERVICE_UID"])
    except (KeyError, ValueError):
        raise AdapterError("gateway_identity_rejected") from None
    if (
        set(environment_rows) != expected_environment_keys
        or environment_rows["PYTHONPATH"]
        != f"{fixed['release_root']}/{selector['release_digest']}/src"
        or environment_rows["MYUNA_P08_STATE_ROOT"] != fixed["state_root"]
        or service_uid != opaque["root"]["uid"]
        or service_uid != account_projection["service"]["uid"]
        or opaque["root"]["gid"] != account_projection["service"]["gid"]
        or gateway_uid != account_projection["gateway"]["uid"]
    ):
        raise AdapterError("environment_projection_rejected")
    enter("execution_predecessor_public")
    _verify_predecessor_public_binding(
        validated,
        root=root,
        backend=backend,
        public=public,
        selector=selector,
        environment_rows=environment_rows,
    )
    enter("execution_target")
    manifest_path = target_source_path / "manifest.json"
    inventory = target_inventory(target_source_path)
    directories = target_directory_inventory(
        target_source_path,
        file_inventory=inventory,
    )
    _target_manifest(validated, target_source_path, inventory)
    enter("execution_systemd")
    execution_substrate = (
        dict(validated["systemd_authority"]) if backend == "systemd" else None
    )
    if execution_substrate is not None:
        _verify_systemd_substrate(execution_substrate)
    target_inventory_digest = contract_v1.digest_value(inventory)
    target_directories_digest = contract_v1.digest_value(directories)
    target_manifest_sha256 = _digest(manifest_path)
    execution = {
        "schema": contract_v1.EXECUTION_SCHEMA,
        "backend": backend,
        "root": str(root),
        "target_source_path": str(target_source_path),
        "target_manifest_sha256": target_manifest_sha256,
        "target_inventory": inventory,
        "target_inventory_digest": target_inventory_digest,
        "target_directories": directories,
        "target_directories_digest": target_directories_digest,
        "public_prestate": public,
        "predecessor_release": predecessor_release,
        "opaque_prestate": opaque,
        "acceptance_scope_digest": acceptance_scope_digest,
        "selected_release_identity": selector["release_digest"],
        "account_projection": account_projection,
        "selector_compatibility": {
            key: selector[key] for key in sorted(compatibility_keys)
        },
        "execution_substrate": execution_substrate,
        "runtime_package": {
            "schema": contract_v1.RUNTIME_PACKAGE_SCHEMA,
            "root": str(target_source_path),
            "inventory_digest": target_inventory_digest,
            "directories_digest": target_directories_digest,
            "manifest_sha256": target_manifest_sha256,
            "contract_digest": validated["contract_digest"],
        },
    }
    enter("execution_units")
    execution["unit_prestate"] = _unit_state_for_execution(validated, execution)
    enter("execution_validation")
    return contract_v1.validate_execution(validated, execution)


def construct_plan(
    contract: Mapping[str, object],
    *,
    root: Path,
    backend: str,
    target_source_path: Path,
    acceptance_scope_digest: str,
    sequence_identity: str,
    invocation_nonce: str,
    predecessor_identity: str,
) -> dict[str, object]:
    execution = construct_execution(
        contract,
        root=root,
        backend=backend,
        target_source_path=target_source_path,
        acceptance_scope_digest=acceptance_scope_digest,
    )
    prestate_identity = execution_prestate_identity(execution)
    return contract_v1.build_plan(
        contract,
        sequence_identity=sequence_identity,
        invocation_nonce=invocation_nonce,
        prestate_identity=prestate_identity,
        predecessor_identity=predecessor_identity,
        target_identity=target_source_path.name,
        execution=execution,
    )


def execution_prestate_identity(execution: Mapping[str, object]) -> str:
    """Canonical content-free prestate binding shared by claim and PLAN."""
    return contract_v1.digest_value(
        {
            "accounts": execution["account_projection"],
            "opaque": execution["opaque_prestate"],
            "predecessor_release": execution["predecessor_release"],
            "public": execution["public_prestate"],
            "units": execution["unit_prestate"],
        }
    )


def _strategy_root(contract: Mapping[str, object], execution: Mapping[str, object]) -> Path:
    return _fixed(contract, execution, "strategy_root")


def sequence_root(contract: Mapping[str, object], plan: Mapping[str, object]) -> Path:
    return _strategy_root(contract, plan["execution"]) / "sequences" / str(
        plan["sequence_identity"]
    )


def incident_root(contract: Mapping[str, object], plan: Mapping[str, object]) -> Path:
    return _strategy_root(contract, plan["execution"]) / "incidents" / str(
        plan["plan_digest"]
    )


def _journal_payload(plan: Mapping[str, object], events: Sequence[str], continuity_state: str | None) -> dict[str, object]:
    body = {
        "schema": JOURNAL_SCHEMA,
        "plan_digest": plan["plan_digest"],
        "events": list(events),
        "continuity_state": continuity_state,
        "raw_content_included": False,
    }
    return {**body, "journal_digest": contract_v1.digest_value(body)}


def _load_journal(contract: Mapping[str, object], plan: Mapping[str, object]) -> dict[str, object]:
    value = _read_json(incident_root(contract, plan) / "JOURNAL.json")
    expected = {"continuity_state", "events", "journal_digest", "plan_digest", "raw_content_included", "schema"}
    if (
        set(value) != expected
        or value["schema"] != JOURNAL_SCHEMA
        or value["plan_digest"] != plan["plan_digest"]
        or value["raw_content_included"] is not False
        or not isinstance(value["events"], list)
        or any(not isinstance(item, str) for item in value["events"])
        or value != _journal_payload(plan, value["events"], value["continuity_state"])
    ):
        raise AdapterError("journal_rejected")
    return value


def _replace_journal(contract: Mapping[str, object], plan: Mapping[str, object], events: Sequence[str], continuity_state: str | None) -> None:
    path = incident_root(contract, plan) / "JOURNAL.json"
    temporary = path.with_name("JOURNAL.NEXT.json")
    _exclusive_write(
        temporary,
        contract_v1.canonical_bytes(_journal_payload(plan, events, continuity_state)),
        mode=0o600,
        uid=os.getuid(),
        gid=os.getgid(),
    )
    try:
        os.replace(temporary, path)
    except OSError:
        raise AdapterError("journal_write_rejected") from None
    _fsync_directory(path.parent)


def _advance(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    event: str,
    *,
    continuity_state: str | None = None,
    product_mutated: bool = False,
    forward_state_possible: bool = False,
) -> None:
    try:
        journal = _load_journal(contract, plan)
        events = list(journal["events"])
        if event in events:
            raise AdapterError("phase_replay_rejected")
        events.append(event)
        _replace_journal(
            contract,
            plan,
            events,
            continuity_state if continuity_state is not None else journal["continuity_state"],
        )
    except AdapterError as error:
        if product_mutated or forward_state_possible:
            raise AdapterError(
                error.code,
                product_mutated=product_mutated,
                forward_state_possible=forward_state_possible,
            ) from None
        raise


def _verify_target_source(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> None:
    execution = plan["execution"]
    source = Path(str(execution["target_source_path"]))
    if source.name != plan["target_identity"]:
        raise AdapterError("target_source_identity_rejected")
    if _digest(source / "manifest.json") != execution["target_manifest_sha256"]:
        raise AdapterError("target_manifest_rejected")
    observed = target_inventory(source)
    if observed != execution["target_inventory"]:
        raise AdapterError("target_inventory_rejected")
    directories = target_directory_inventory(source, file_inventory=observed)
    if directories != execution["target_directories"]:
        raise AdapterError("target_directory_inventory_rejected")
    _target_manifest(contract, source, observed)
    semantics = _unit_semantics_from_paths(
        source / "systemd" / str(contract["production_adapter"]["fixed_paths"]["service_name"]),
        source / "systemd" / str(contract["production_adapter"]["fixed_paths"]["socket_name"]),
    )
    if semantics != contract["production_adapter"]["unit_semantics"]:
        raise AdapterError("target_unit_semantics_rejected")


def _verify_public(contract: Mapping[str, object], plan: Mapping[str, object], *, predecessor: bool) -> None:
    execution = plan["execution"]
    if predecessor:
        for role in contract_v1.PUBLIC_ROLES:
            expected = execution["public_prestate"][role]
            observed = _public_projection(
                _fixed(contract, execution, role),
                absolute_path=str(contract["production_adapter"]["fixed_paths"][role]),
            )
            if observed != expected:
                raise AdapterError("public_prestate_drifted")
        selected = _read_json(_fixed(contract, execution, "selector"))
        environment = _environment_rows(_fixed(contract, execution, "environment"))
        _verify_predecessor_public_binding(
            contract,
            root=Path(str(execution["root"])),
            backend=str(execution["backend"]),
            public=execution["public_prestate"],
            selector=selected,
            environment_rows=environment,
        )
        observed_predecessor = _predecessor_release_for_execution(
            contract,
            root=Path(str(execution["root"])),
            release_identity=str(plan["predecessor_identity"]),
        )
        if observed_predecessor != execution["predecessor_release"]:
            raise AdapterError("predecessor_release_drifted")
    else:
        expected = _target_public_bytes(contract, plan)
        for role, raw in expected.items():
            path = _fixed(contract, execution, role)
            details = _regular(path, maximum=max(len(raw), 1))
            mode = 0o600 if role in {"selector", "environment"} else 0o644
            expected_uid = 0 if execution["backend"] == "systemd" else os.getuid()
            expected_gid = 0 if execution["backend"] == "systemd" else os.getgid()
            if (
                stat.S_IMODE(details.st_mode) != mode
                or details.st_uid != expected_uid
                or details.st_gid != expected_gid
                or details.st_nlink != 1
                or _read_regular_bytes(path, maximum=max(len(raw), 1)) != raw
            ):
                raise AdapterError("target_public_rejected")
        semantics = _unit_semantics_from_paths(
            _fixed(contract, execution, "service_unit"),
            _fixed(contract, execution, "socket_unit"),
        )
        if semantics != contract["production_adapter"]["unit_semantics"]:
            raise AdapterError("target_unit_semantics_rejected")


def _verify_opaque_metadata(contract: Mapping[str, object], plan: Mapping[str, object], *, exact_size: bool) -> None:
    execution = plan["execution"]
    expected = execution["opaque_prestate"]
    observed = opaque_metadata(
        _fixed(contract, execution, "state_root"),
        absolute_path=str(contract["production_adapter"]["fixed_paths"]["state_root"]),
    )
    if exact_size:
        if observed != expected:
            raise AdapterError("opaque_state_metadata_drifted")
        return
    expected_security = {
        "root": {key: expected["root"][key] for key in ("path", "type", "mode", "uid", "gid")},
        "entries": [
            {key: row[key] for key in ("path", "type", "mode", "uid", "gid", "nlink")}
            for row in expected["entries"]
        ],
    }
    observed_security = {
        "root": {key: observed["root"][key] for key in ("path", "type", "mode", "uid", "gid")},
        "entries": [
            {key: row[key] for key in ("path", "type", "mode", "uid", "gid", "nlink")}
            for row in observed["entries"]
        ],
    }
    if observed_security != expected_security:
        raise AdapterError("opaque_state_security_drifted")


def _expected_unit_runtime(
    contract: Mapping[str, object], execution: Mapping[str, object]
) -> dict[str, object]:
    selector = _read_json(_fixed(contract, execution, "selector"))
    selected = selector.get("release_digest")
    predecessor = contract["compatibility"]["predecessor"]
    target_identity = Path(str(execution["target_source_path"])).name
    if selected == predecessor["release_identity"]:
        expected_semantics = predecessor["unit_semantics"]
        expected_runtime = predecessor["unit_runtime"]
    elif selected == target_identity:
        expected_semantics = contract["production_adapter"]["unit_semantics"]
        expected_runtime = contract["production_adapter"]["unit_runtime"]
    else:
        raise AdapterError("unit_release_binding_rejected")
    observed_semantics = _unit_semantics_from_paths(
        _fixed(contract, execution, "service_unit"),
        _fixed(contract, execution, "socket_unit"),
    )
    if observed_semantics != expected_semantics:
        raise AdapterError("unit_semantics_rejected")
    return _gate_runtime(contract, execution, expected_runtime)


def _known_unit_runtimes(
    contract: Mapping[str, object], execution: Mapping[str, object]
) -> list[dict[str, object]]:
    """Return only source-bound runtimes matching the installed unit bytes.

    This is used solely while bounded convergence is stopping an unaccepted
    target.  A malformed selector must not prevent the stop, but it also must
    not become authority: the loaded/unit-file closure still has to match the
    exact predecessor or exact target contract.
    """
    observed_semantics = _unit_semantics_from_paths(
        _fixed(contract, execution, "service_unit"),
        _fixed(contract, execution, "socket_unit"),
    )
    pairs = (
        (
            contract["compatibility"]["predecessor"]["unit_semantics"],
            contract["compatibility"]["predecessor"]["unit_runtime"],
        ),
        (
            contract["production_adapter"]["unit_semantics"],
            contract["production_adapter"]["unit_runtime"],
        ),
    )
    result: list[dict[str, object]] = []
    digests: set[str] = set()
    for semantics, runtime in pairs:
        if observed_semantics != semantics:
            continue
        selected = _gate_runtime(contract, execution, runtime)
        digest = contract_v1.digest_value(selected)
        if digest not in digests:
            result.append(selected)
            digests.add(digest)
    if not result:
        raise AdapterError("unit_semantics_rejected")
    return result


def _systemctl_show(
    execution: Mapping[str, object],
    unit: str,
    properties: Sequence[str],
    *,
    allow_not_found: bool = False,
) -> dict[str, str]:
    completed = _run_bound_systemctl(
        execution,
        [
            "show",
            unit,
            *(f"--property={value}" for value in properties),
            "--no-pager",
        ],
        capture_stdout=True,
        timeout=10,
    )
    if (
        completed.returncode not in ({0, 4} if allow_not_found else {0})
        or len(completed.stdout) > 16 * 1024
    ):
        raise AdapterError("unit_state_rejected")
    fields: dict[str, str] = {}
    try:
        lines = completed.stdout.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError:
        raise AdapterError("unit_state_rejected") from None
    for line in lines:
        if "=" not in line:
            raise AdapterError("unit_state_rejected")
        key, value = line.split("=", 1)
        if key in fields:
            raise AdapterError("unit_state_rejected")
        fields[key] = value
    if set(fields) != set(properties):
        raise AdapterError("unit_state_rejected")
    if completed.returncode == 4 and fields.get("LoadState") != "not-found":
        raise AdapterError("unit_state_rejected")
    return fields


def _exec_start_projection(value: str) -> list[str]:
    if not value.startswith("{ ") or not value.endswith(" }"):
        raise AdapterError("unit_effective_exec_rejected")
    fields: dict[str, str] = {}
    for item in value[2:-2].split(" ; "):
        if "=" not in item:
            raise AdapterError("unit_effective_exec_rejected")
        key, selected = item.split("=", 1)
        if key in fields:
            raise AdapterError("unit_effective_exec_rejected")
        fields[key] = selected
    if set(fields) != {
        "argv[]",
        "code",
        "ignore_errors",
        "path",
        "pid",
        "start_time",
        "status",
        "stop_time",
    } or fields["ignore_errors"] != "no":
        raise AdapterError("unit_effective_exec_rejected")
    argv = fields["argv[]"].split(" ")
    if (
        not argv
        or any(not item for item in argv)
        or argv[0] != fields["path"]
        or not fields["pid"].isdigit()
    ):
        raise AdapterError("unit_effective_exec_rejected")
    return argv


def _dependency_projection(raw: str) -> list[str]:
    tokens = raw.split(" ") if raw else []
    if (
        any(
            not token or not contract_v1.is_safe_unit_name(token)
            for token in tokens
        )
        or len(tokens) != len(set(tokens))
    ):
        raise AdapterError("unit_effective_dependency_rejected")
    return sorted(tokens)


def _path_projection(raw: str) -> list[str]:
    values = raw.split(" ") if raw else []
    if (
        any(
            not value
            or not value.startswith("/")
            or "//" in value
            or "/../" in value + "/"
            or "/./" in value + "/"
            for value in values
        )
        or len(values) != len(set(values))
    ):
        raise AdapterError("unit_effective_dropin_rejected")
    return sorted(values)


def _dependency_injection_paths(
    execution: Mapping[str, object], unit: str
) -> list[str]:
    authority = execution.get("execution_substrate")
    if not isinstance(authority, Mapping):
        raise AdapterError("execution_substrate_rejected")
    observed: list[str] = []
    for root in authority["unit_load_paths"]:
        for suffix in authority["dependency_directory_suffixes"]:
            path = Path(str(root)) / f"{unit}.{suffix}"
            try:
                details = path.lstat()
            except FileNotFoundError:
                continue
            except OSError:
                raise AdapterError("unit_dependency_injection_rejected") from None
            if not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode):
                raise AdapterError("unit_dependency_injection_rejected")
            observed.append(str(path))
    return sorted(observed)


def _read_proc_bytes(path: Path, *, maximum: int = 65536) -> bytes:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError:
        raise AdapterError("service_process_identity_rejected") from None
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise AdapterError("service_process_identity_rejected")
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def _service_process_projection(
    pid: int, expected: Mapping[str, object]
) -> dict[str, object]:
    if pid < 1:
        raise AdapterError("service_process_identity_rejected")
    root = Path("/proc") / str(pid)
    try:
        stat_before = _read_proc_bytes(root / "stat").decode("ascii", "strict")
        executable = os.readlink(root / "exe")
        argv_raw = _read_proc_bytes(root / "cmdline")
        status_raw = _read_proc_bytes(root / "status").decode("ascii", "strict")
        cgroup_raw = _read_proc_bytes(root / "cgroup").decode("ascii", "strict")
        stat_after = _read_proc_bytes(root / "stat").decode("ascii", "strict")
    except (OSError, UnicodeDecodeError):
        raise AdapterError("service_process_identity_rejected") from None
    if stat_before != stat_after or ") " not in stat_before:
        raise AdapterError("service_process_identity_rejected")
    suffix = stat_before.rsplit(") ", 1)[1].split()
    if len(suffix) < 20:
        raise AdapterError("service_process_identity_rejected")
    try:
        start_ticks = int(suffix[19])
        argv = argv_raw.rstrip(b"\0").decode("ascii", "strict").split("\0")
    except (ValueError, UnicodeDecodeError):
        raise AdapterError("service_process_identity_rejected") from None
    status: dict[str, list[str]] = {}
    for line in status_raw.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key in {"Uid", "Gid", "Groups"}:
            if key in status:
                raise AdapterError("service_process_identity_rejected")
            status[key] = value.split()
    try:
        uid_values = [int(value) for value in status["Uid"]]
        gid_values = [int(value) for value in status["Gid"]]
        group_values = sorted(int(value) for value in status["Groups"])
    except (KeyError, ValueError):
        raise AdapterError("service_process_identity_rejected") from None
    expected_executable = expected["executable"]
    if (
        executable != expected_executable["resolved_path"]
        or argv != expected["argv"]
        or len(uid_values) != 4
        or set(uid_values) != {expected["uid"]}
        or len(gid_values) != 4
        or set(gid_values) != {expected["gid"]}
        or group_values != expected["groups"]
        or cgroup_raw.splitlines() != [f"0::{expected['cgroup']}"]
        or start_ticks < 1
    ):
        raise AdapterError("service_process_identity_rejected")
    _verify_regular_authority(
        Path(str(expected_executable["resolved_path"])), expected_executable
    )
    return {
        "schema": contract_v1.PROCESS_IDENTITY_SCHEMA,
        "pid": pid,
        "start_ticks": start_ticks,
        "argv": list(expected["argv"]),
        "cgroup": expected["cgroup"],
        "executable": dict(expected_executable),
        "uid": expected["uid"],
        "gid": expected["gid"],
        "groups": list(expected["groups"]),
    }


def _socket_inode_projection(
    contract: Mapping[str, object],
    execution: Mapping[str, object],
    *,
    active: bool,
) -> dict[str, object] | None:
    path = _fixed(contract, execution, "socket_endpoint")
    if not active:
        if path.exists() or path.is_symlink():
            raise AdapterError("socket_inode_rejected")
        return None
    if not hasattr(os, "O_PATH"):
        raise AdapterError("socket_inode_rejected")
    flags = os.O_PATH | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        before = path.lstat()
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        after = path.lstat()
    except OSError:
        raise AdapterError("socket_inode_rejected") from None
    finally:
        if "descriptor" in locals():
            os.close(descriptor)
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_ctime_ns,
    )
    runtime = _expected_unit_runtime(contract, execution)
    accounts = contract["production_adapter"]["accounts"]
    if (
        identity(before) != identity(opened)
        or identity(opened) != identity(after)
        or not stat.S_ISSOCK(after.st_mode)
        or after.st_nlink != 1
        or stat.S_IMODE(after.st_mode) != int(str(runtime["socket"]["socket_mode"]), 8)
        or after.st_uid != accounts["service"]["uid"]
        or after.st_gid != accounts["gateway"]["gid"]
    ):
        raise AdapterError("socket_inode_rejected")
    return {
        "schema": contract_v1.SOCKET_INODE_SCHEMA,
        "path": str(contract["production_adapter"]["fixed_paths"]["socket_endpoint"]),
        "type": "socket",
        "mode": stat.S_IMODE(after.st_mode),
        "uid": after.st_uid,
        "gid": after.st_gid,
        "nlink": after.st_nlink,
    }


def _create_synthetic_socket(
    contract: Mapping[str, object], execution: Mapping[str, object]
) -> dict[str, object]:
    path = _fixed(contract, execution, "socket_endpoint")
    if path.exists() or path.is_symlink():
        raise AdapterError("socket_inode_rejected", product_mutated=True)
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            endpoint.bind(str(path))
        finally:
            endpoint.close()
        runtime = _expected_unit_runtime(contract, execution)
        accounts = contract["production_adapter"]["accounts"]
        os.chmod(path, int(str(runtime["socket"]["socket_mode"]), 8))
        os.chown(path, int(accounts["service"]["uid"]), int(accounts["gateway"]["gid"]))
    except OSError:
        raise AdapterError("socket_inode_rejected", product_mutated=True) from None
    projected = _socket_inode_projection(contract, execution, active=True)
    assert projected is not None
    return projected


def _remove_synthetic_socket(
    contract: Mapping[str, object], execution: Mapping[str, object]
) -> None:
    path = _fixed(contract, execution, "socket_endpoint")
    _socket_inode_projection(contract, execution, active=True)
    try:
        path.unlink()
    except OSError:
        raise AdapterError("socket_inode_rejected", product_mutated=True) from None
    _socket_inode_projection(contract, execution, active=False)


def _unit_state_for_execution(
    contract: Mapping[str, object],
    execution: Mapping[str, object],
    *,
    allow_known_selection_drift: bool = False,
) -> dict[str, object]:
    expected_runtimes = (
        _known_unit_runtimes(contract, execution)
        if allow_known_selection_drift
        else [_expected_unit_runtime(contract, execution)]
    )
    if execution["backend"] == "synthetic":
        value = _read_json(_fixed(contract, execution, "synthetic_unit_state"))
        matches: list[dict[str, object]] = []
        for expected_runtime in expected_runtimes:
            try:
                matches.append(
                    contract_v1._unit_snapshot(
                        value, expected_runtime=expected_runtime
                    )
                )
            except contract_v1.ContractError:
                continue
        if len(matches) != 1:
            raise AdapterError("unit_state_rejected")
        observed_socket = _socket_inode_projection(
            contract, execution, active=bool(matches[0]["socket_active"])
        )
        if observed_socket != matches[0]["socket_inode"]:
            raise AdapterError("socket_inode_rejected")
        return matches[0]
    fixed = contract["production_adapter"]["fixed_paths"]
    # systemd 255 does not expose a Socket.Service D-Bus property.  Reopen the
    # exact source-owned unit semantics and use the independently observed
    # Triggers/TriggeredBy relation below as the effective association.
    source_unit_semantics = _unit_semantics_from_paths(
        _fixed(contract, execution, "service_unit"),
        _fixed(contract, execution, "socket_unit"),
    )
    source_socket_service = source_unit_semantics["socket"]["sections"][
        "Socket"
    ].get("Service")
    if (
        not isinstance(source_socket_service, str)
        or source_socket_service != fixed["service_name"]
    ):
        raise AdapterError("unit_trigger_relation_rejected")
    dependency_properties = tuple(
        str(value) for value in contract["systemd_authority"]["dependency_properties"]
    )
    policy_properties = tuple(
        str(value)
        for value in expected_runtimes[0]["service"]["execution_policy"]
    )
    if any(
        tuple(runtime["service"]["execution_policy"]) != policy_properties
        for runtime in expected_runtimes
    ):
        raise AdapterError("unit_effective_policy_rejected")
    service_properties = tuple(dict.fromkeys((
        "ActiveEnterTimestampMonotonic",
        "ActiveState",
        "ControlGroup",
        "DynamicUser",
        "DropInPaths",
        "EnvironmentFiles",
        "ExecStart",
        "FragmentPath",
        "Group",
        "LoadState",
        "MainPID",
        "NRestarts",
        "PAMName",
        "PrivateUsers",
        "SetLoginEnvironment",
        "Slice",
        "SubState",
        "SupplementaryGroups",
        "UnitFileState",
        "User",
        *dependency_properties,
        *policy_properties,
    )))
    socket_properties = tuple(dict.fromkeys((
        "ActiveEnterTimestampMonotonic",
        "ActiveState",
        "ControlGroup",
        "DropInPaths",
        "FragmentPath",
        "Listen",
        "LoadState",
        "NAccepted",
        "NConnections",
        "Slice",
        "SocketGroup",
        "SocketMode",
        "SocketUser",
        "SubState",
        "UnitFileState",
        *dependency_properties,
    )))
    service_fields = _systemctl_show(
        execution, str(fixed["service_name"]), service_properties
    )
    socket_fields = _systemctl_show(
        execution, str(fixed["socket_name"]), socket_properties
    )
    service_injections = _dependency_injection_paths(
        execution, str(fixed["service_name"])
    )
    socket_injections = _dependency_injection_paths(
        execution, str(fixed["socket_name"])
    )
    service_dropins = _path_projection(service_fields["DropInPaths"])
    socket_dropins = _path_projection(socket_fields["DropInPaths"])
    exec_start = _exec_start_projection(service_fields["ExecStart"])
    service_dependencies = {
        name: _dependency_projection(service_fields[name])
        for name in dependency_properties
    }
    socket_dependencies = {
        name: _dependency_projection(socket_fields[name])
        for name in dependency_properties
    }
    matched: list[tuple[dict[str, object], dict[str, object]]] = []
    for expected_runtime in expected_runtimes:
        expected_semantics = (
            contract["compatibility"]["predecessor"]["unit_semantics"]
            if expected_runtime["profile"] == "predecessor"
            else contract["production_adapter"]["unit_semantics"]
        )
        expected_environment = (
            f"{expected_runtime['service']['environment_files'][0]} (ignore_errors=no)"
        )
        expected_listen = f"{expected_runtime['socket']['listen_stream']} (Stream)"
        reciprocal_trigger_closed = (
            source_unit_semantics == expected_semantics
            and source_socket_service == expected_runtime["socket"]["service"]
            and socket_dependencies["Triggers"] == [source_socket_service]
            and service_dependencies["TriggeredBy"] == [fixed["socket_name"]]
            and fixed["socket_name"] in service_dependencies["Requires"]
            and fixed["socket_name"] in service_dependencies["After"]
            and source_socket_service in socket_dependencies["Before"]
        )
        observed_service_static = {
            "control_group": service_fields["ControlGroup"],
            "credential_launch": expected_runtime["service"]["credential_launch"],
            "dependencies": service_dependencies,
            "dependency_injection_paths": service_injections,
            "drop_in_paths": service_dropins,
            "dynamic_user": service_fields["DynamicUser"],
            "environment_files": expected_runtime["service"]["environment_files"]
            if service_fields["EnvironmentFiles"] == expected_environment
            else [],
            "execution_policy": {
                name: service_fields[name] for name in policy_properties
            },
            "exec_start_argv": exec_start,
            "fragment_path": service_fields["FragmentPath"],
            "group": service_fields["Group"],
            "load_state": service_fields["LoadState"],
            "pam_name": service_fields["PAMName"],
            "private_users": service_fields["PrivateUsers"],
            "process_identity": expected_runtime["service"]["process_identity"],
            "ready_active_state": expected_runtime["service"]["ready_active_state"],
            "ready_sub_state": expected_runtime["service"]["ready_sub_state"],
            "set_login_environment": service_fields["SetLoginEnvironment"],
            "slice": service_fields["Slice"],
            "supplementary_groups": _dependency_projection(
                service_fields["SupplementaryGroups"]
            ),
            "unit_file_state": service_fields["UnitFileState"],
            "user": service_fields["User"],
        }
        observed_socket_static = {
            "control_group": socket_fields["ControlGroup"],
            "dependencies": socket_dependencies,
            "dependency_injection_paths": socket_injections,
            "drop_in_paths": socket_dropins,
            "fragment_path": socket_fields["FragmentPath"],
            "listen_stream": expected_runtime["socket"]["listen_stream"]
            if socket_fields["Listen"] == expected_listen
            else "",
            "load_state": socket_fields["LoadState"],
            "ready_active_state": expected_runtime["socket"]["ready_active_state"],
            "ready_sub_state": expected_runtime["socket"]["ready_sub_state"],
            "service": (
                socket_dependencies["Triggers"][0]
                if reciprocal_trigger_closed
                else ""
            ),
            "slice": socket_fields["Slice"],
            "socket_group": socket_fields["SocketGroup"],
            "socket_mode": socket_fields["SocketMode"],
            "socket_user": socket_fields["SocketUser"],
            "unit_file_state": socket_fields["UnitFileState"],
        }
        if (
            observed_service_static == expected_runtime["service"]
            and observed_socket_static == expected_runtime["socket"]
        ):
            effective = {
                "schema": contract_v1.UNIT_RUNTIME_SCHEMA,
                "service": {
                    **dict(expected_runtime["service"]),
                    "active_state": service_fields["ActiveState"],
                    "sub_state": service_fields["SubState"],
                },
                "socket": {
                    **dict(expected_runtime["socket"]),
                    "active_state": socket_fields["ActiveState"],
                    "sub_state": socket_fields["SubState"],
                },
            }
            matched.append((expected_runtime, effective))
    if len(matched) != 1:
        raise AdapterError("unit_effective_closure_rejected")
    expected_runtime, effective = matched[0]
    result: dict[str, object] = {
        "schema": contract_v1.UNIT_STATE_SCHEMA,
        "effective": effective,
        "service_active": service_fields["ActiveState"] == "active",
        "service_enabled": service_fields["UnitFileState"] == "enabled",
        "socket_active": socket_fields["ActiveState"] == "active",
        "socket_enabled": socket_fields["UnitFileState"] == "enabled",
    }
    try:
        result["service_active_enter_monotonic_usec"] = int(
            service_fields["ActiveEnterTimestampMonotonic"]
        )
        result["service_main_pid"] = int(service_fields["MainPID"])
        result["service_restarts"] = int(service_fields["NRestarts"])
        result["socket_active_enter_monotonic_usec"] = int(
            socket_fields["ActiveEnterTimestampMonotonic"]
        )
        result["socket_n_accepted"] = int(socket_fields["NAccepted"])
        result["socket_n_connections"] = int(socket_fields["NConnections"])
    except ValueError:
        raise AdapterError("unit_state_rejected") from None
    if result["service_active"]:
        result["service_process"] = _service_process_projection(
            int(result["service_main_pid"]), expected_runtime["service"]["process_identity"]
        )
    else:
        result["service_process"] = None
    result["socket_inode"] = _socket_inode_projection(
        contract, execution, active=bool(result["socket_active"])
    )
    try:
        result["coupled_state"] = contract_v1._coupled_unit_state_name(
            result, effective
        )
        return contract_v1._unit_snapshot(
            result, expected_runtime=expected_runtime
        )
    except contract_v1.ContractError:
        raise AdapterError("unit_state_rejected") from None


def _unit_state(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    allow_known_selection_drift: bool = False,
) -> dict[str, object]:
    return _unit_state_for_execution(
        contract,
        plan["execution"],
        allow_known_selection_drift=allow_known_selection_drift,
    )


def _write_unit_state(contract: Mapping[str, object], plan: Mapping[str, object], value: Mapping[str, object]) -> None:
    path = _fixed(contract, plan["execution"], "synthetic_unit_state")
    raw = contract_v1.canonical_bytes(value)
    _atomic_write(path, raw, mode=0o600, uid=os.getuid(), gid=os.getgid(), token=plan["plan_digest"][:16])


def _unit_action(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    unit_role: str,
    start: bool,
    allow_known_selection_drift: bool = False,
) -> None:
    execution = plan["execution"]
    fixed = contract["production_adapter"]["fixed_paths"]
    _verify_account_authority(contract, execution)
    if execution["backend"] == "synthetic":
        value = _unit_state(
            contract,
            plan,
            allow_known_selection_drift=allow_known_selection_drift,
        )
        if unit_role == "socket" and not start:
            # Requires= and After= make the first socket stop a coupled stop of
            # the dependent service.  The later service stop is intentionally
            # idempotent and remains a separately journaled role.
            if value["socket_active"] is True:
                _remove_synthetic_socket(contract, execution)
            else:
                _socket_inode_projection(contract, execution, active=False)
            value["socket_active"] = False
            value["service_active"] = False
            value["service_main_pid"] = 0
            value["service_process"] = None
            value["effective"]["socket"]["active_state"] = "inactive"
            value["effective"]["socket"]["sub_state"] = "dead"
            value["effective"]["service"]["active_state"] = "inactive"
            value["effective"]["service"]["sub_state"] = "dead"
            value["socket_inode"] = None
        elif unit_role == "service" and not start:
            value["service_active"] = False
            value["service_main_pid"] = 0
            value["service_process"] = None
            value["effective"]["service"]["active_state"] = "inactive"
            value["effective"]["service"]["sub_state"] = "dead"
            if value["socket_active"] is True:
                value["effective"]["socket"]["sub_state"] = "listening"
        elif unit_role == "service" and start:
            if value["socket_active"] is not True:
                value["socket_active"] = True
                value["socket_active_enter_monotonic_usec"] = (
                    int(value["socket_active_enter_monotonic_usec"]) + 1
                )
            value["effective"]["socket"]["active_state"] = "active"
            value["effective"]["socket"]["sub_state"] = "running"
            value["socket_inode"] = _create_synthetic_socket(contract, execution)
            value["service_active"] = True
            value["service_active_enter_monotonic_usec"] = (
                int(value["service_active_enter_monotonic_usec"]) + 1
            )
            value["service_main_pid"] = (
                1000 + int(value["service_active_enter_monotonic_usec"])
            )
            process = value["effective"]["service"]["process_identity"]
            value["service_process"] = {
                **dict(process),
                "pid": value["service_main_pid"],
                "start_ticks": int(value["service_active_enter_monotonic_usec"]),
            }
            value["effective"]["service"]["active_state"] = "active"
            value["effective"]["service"]["sub_state"] = "running"
        elif unit_role == "socket" and start:
            if value["service_active"] is not True:
                raise AdapterError("unit_dependency_rejected", product_mutated=True)
            if value["socket_active"] is not True:
                value["socket_active"] = True
                value["socket_active_enter_monotonic_usec"] = (
                    int(value["socket_active_enter_monotonic_usec"]) + 1
                )
            value["effective"]["socket"]["active_state"] = "active"
            value["effective"]["socket"]["sub_state"] = "running"
        value["coupled_state"] = contract_v1._coupled_unit_state_name(
            value, value["effective"]
        )
        _write_unit_state(contract, plan, value)
        try:
            _verify_account_authority(contract, execution)
        except AdapterError as error:
            raise AdapterError(error.code, product_mutated=True) from None
        return
    unit = fixed[f"{unit_role}_name"]
    try:
        completed = _run_bound_systemctl(
            execution,
            ["start" if start else "stop", str(unit)],
            capture_stdout=False,
            timeout=30,
        )
    except AdapterError as error:
        raise AdapterError(error.code, product_mutated=True) from None
    if completed.returncode != 0:
        raise AdapterError("unit_action_rejected", product_mutated=True)
    try:
        _verify_account_authority(contract, execution)
    except AdapterError as error:
        raise AdapterError(error.code, product_mutated=True) from None
    observed = _unit_state(
        contract,
        plan,
        allow_known_selection_drift=allow_known_selection_drift,
    )
    if (
        (not start and (observed["service_active"] or observed["socket_active"]))
        or (start and (not observed["service_active"] or not observed["socket_active"]))
    ):
        raise AdapterError("unit_dependency_rejected", product_mutated=True)


def _daemon_reload(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    mutation_scope: str = "product",
) -> None:
    if mutation_scope not in {"product", "recovery_infrastructure"}:
        raise AdapterError("unit_reload_scope_rejected")
    product_mutated = mutation_scope == "product"
    infrastructure_mutated = mutation_scope == "recovery_infrastructure"
    execution = plan["execution"]
    _verify_account_authority(contract, execution)
    if execution["backend"] == "synthetic":
        path = _fixed(contract, execution, "synthetic_unit_state")
        value = _read_json(path)
        try:
            value = contract_v1._unit_snapshot(value)
        except contract_v1.ContractError:
            raise AdapterError(
                "unit_reload_rejected",
                product_mutated=product_mutated,
                infrastructure_mutated=infrastructure_mutated,
            ) from None
        runtime = _expected_unit_runtime(contract, execution)
        for role in ("service", "socket"):
            active_state = value["effective"][role]["active_state"]
            sub_state = value["effective"][role]["sub_state"]
            value["effective"][role] = {
                **dict(runtime[role]),
                "active_state": active_state,
                "sub_state": sub_state,
            }
        _write_unit_state(contract, plan, value)
        try:
            _verify_account_authority(contract, execution)
        except AdapterError as error:
            raise AdapterError(
                error.code,
                product_mutated=product_mutated,
                infrastructure_mutated=infrastructure_mutated,
            ) from None
        _unit_state(contract, plan)
        return
    try:
        completed = _run_bound_systemctl(
            execution,
            ["daemon-reload"],
            capture_stdout=False,
            timeout=30,
        )
    except AdapterError as error:
        raise AdapterError(
            error.code,
            product_mutated=product_mutated,
            infrastructure_mutated=infrastructure_mutated,
        ) from None
    if completed.returncode != 0:
        raise AdapterError(
            "unit_reload_rejected",
            product_mutated=product_mutated,
            infrastructure_mutated=infrastructure_mutated,
        )
    try:
        _verify_account_authority(contract, execution)
    except AdapterError as error:
        raise AdapterError(
            error.code,
            product_mutated=product_mutated,
            infrastructure_mutated=infrastructure_mutated,
        ) from None
    # Reload authority is not established by FragmentPath alone.  Reopen the
    # entire loaded closure, including empty DropInPaths, effective accounts,
    # entrypoint, environment, socket endpoint, dependency, enablement and
    # state/counter projection.
    try:
        _unit_state(contract, plan)
    except AdapterError as error:
        raise AdapterError(
            error.code,
            product_mutated=product_mutated,
            infrastructure_mutated=infrastructure_mutated,
            forward_state_possible=error.forward_state_possible,
        ) from None


def _verify_fresh_unit_generation(
    plan: Mapping[str, object],
    state: Mapping[str, object],
    *,
    product_mutated: bool,
) -> None:
    baseline = plan["execution"]["unit_prestate"]
    if (
        state["service_active_enter_monotonic_usec"]
        <= baseline["service_active_enter_monotonic_usec"]
        or state["socket_active_enter_monotonic_usec"]
        <= baseline["socket_active_enter_monotonic_usec"]
        or state["socket_n_accepted"] < baseline["socket_n_accepted"]
    ):
        raise AdapterError(
            "unit_generation_rejected",
            product_mutated=product_mutated,
        )


def _unit_receipt(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    label: str,
    create: bool,
) -> dict[str, object]:
    if label not in {"predecessor", "target"}:
        raise AdapterError("unit_receipt_rejected")
    expected_identity = (
        plan["predecessor_identity"] if label == "predecessor" else plan["target_identity"]
    )
    selector = _read_json(_fixed(contract, plan["execution"], "selector"))
    if selector.get("release_digest") != expected_identity:
        raise AdapterError("unit_receipt_rejected")
    base_runtime = (
        contract["compatibility"]["predecessor"]["unit_runtime"]
        if label == "predecessor"
        else contract["production_adapter"]["unit_runtime"]
    )
    # Recovery installation is deliberately persistent across both the target
    # and predecessor selections.  Receipts therefore bind the same generated
    # effective gate overlay that _unit_state() reopens; accepting the ungated
    # source-unit projection here would split post-start and convergence
    # authority after ARM.
    expected_runtime = _runtime_with_recovery_gate(contract, base_runtime)
    socket_name = contract["production_adapter"]["fixed_paths"]["socket_name"]
    service_name = contract["production_adapter"]["fixed_paths"]["service_name"]
    service_requires_socket = socket_name in expected_runtime["service"][
        "dependencies"
    ]["Requires"]
    dependency = {
        "service_requires_socket": service_requires_socket,
        "start_service_activates_socket": service_requires_socket,
        "stop_socket_cascades_service": service_name
        in expected_runtime["socket"]["dependencies"]["RequiredBy"],
    }
    if set(dependency.values()) != {True}:
        raise AdapterError("unit_dependency_rejected", product_mutated=create)
    path = incident_root(contract, plan) / f"UNITS.{label.upper()}.json"
    if create:
        state = _unit_state(contract, plan)
        try:
            contract_v1._unit_state(state, expected_runtime=expected_runtime)
        except contract_v1.ContractError:
            raise AdapterError("unit_receipt_rejected", product_mutated=True)
        _verify_fresh_unit_generation(plan, state, product_mutated=True)
        body = {
            "schema": UNIT_RECEIPT_SCHEMA,
            "plan_digest": plan["plan_digest"],
            "label": label,
            "counter_policy": "monotonic_not_restored",
            "dependency_coupled": dependency,
            "state": state,
        }
        value = {**body, "receipt_digest": contract_v1.digest_value(body)}
        _exclusive_write(path, contract_v1.canonical_bytes(value), mode=0o600)
    value = _read_json(path)
    body = {key: item for key, item in value.items() if key != "receipt_digest"}
    try:
        state = contract_v1._unit_state(
            value.get("state"), expected_runtime=expected_runtime
        )
    except contract_v1.ContractError:
        raise AdapterError("unit_receipt_rejected") from None
    _verify_fresh_unit_generation(plan, state, product_mutated=False)
    if (
        set(value)
        != {
            "counter_policy",
            "dependency_coupled",
            "label",
            "plan_digest",
            "receipt_digest",
            "schema",
            "state",
        }
        or value["schema"] != UNIT_RECEIPT_SCHEMA
        or value["plan_digest"] != plan["plan_digest"]
        or value["label"] != label
        or value["counter_policy"] != "monotonic_not_restored"
        or value["dependency_coupled"] != dependency
        or value["state"] != state
        or value["receipt_digest"] != contract_v1.digest_value(body)
    ):
        raise AdapterError("unit_receipt_rejected")
    return value


def _target_public_bytes(contract: Mapping[str, object], plan: Mapping[str, object]) -> dict[str, bytes]:
    execution = plan["execution"]
    fixed = contract["production_adapter"]["fixed_paths"]
    source = Path(str(execution["target_source_path"]))
    compatibility = execution["selector_compatibility"]
    selector = {
        "core_commit": contract["engine_source"]["core_commit"],
        "deploy_commit": contract["engine_source"]["deploy_commit"],
        "gateway_client_sha256": compatibility["gateway_client_sha256"],
        "gateway_manifest_digest": compatibility["gateway_manifest_digest"],
        "plan_digest": plan["plan_digest"],
        "plugin_digest": compatibility["plugin_digest"],
        "release_digest": plan["target_identity"],
        "release_path": str(Path(str(fixed["release_root"])) / str(plan["target_identity"])),
        "schema": contract_v1.SELECTOR_SCHEMA,
    }
    environment = (
        f"PYTHONPATH={fixed['release_root']}/{plan['target_identity']}/src\n"
        f"MYUNA_P08_STATE_ROOT={fixed['state_root']}\n"
        f"MYUNA_P08_SERVICE_UID={execution['account_projection']['service']['uid']}\n"
        f"MYUNA_P08_TELEGRAM_UID={execution['account_projection']['gateway']['uid']}\n"
    ).encode("ascii")
    return {
        "selector": contract_v1.canonical_bytes(selector),
        "environment": environment,
        "service_unit": _read_regular_bytes(source / "systemd" / str(fixed["service_name"])),
        "socket_unit": _read_regular_bytes(source / "systemd" / str(fixed["socket_name"])),
    }


class _ProgressEmitter:
    def __init__(
        self,
        contract: Mapping[str, object],
        plan: Mapping[str, object],
        role: str,
    ) -> None:
        raw_fd = os.environ.get("MYUNA_P08_ACTIVATION_PROGRESS_FD")
        if raw_fd is None:
            raise AdapterError("progress_fd_rejected")
        try:
            self._descriptor = int(raw_fd)
        except ValueError:
            raise AdapterError("progress_fd_rejected") from None
        self._contract = contract
        self._plan = plan
        self._role = role
        self._phases = list(contract["roles"][role]["progress_phases"])
        self._index = 0

    def emit(self, phase: str) -> None:
        if self._index >= len(self._phases) or self._phases[self._index] != phase:
            raise AdapterError("progress_phase_rejected")
        raw = launcher_v1.progress_bytes(
            self._contract,
            self._plan,
            role=self._role,
            phase=phase,
            phase_index=self._index + 1,
        )
        offset = 0
        while offset < len(raw):
            written = os.write(self._descriptor, raw[offset:])
            if written < 1:
                raise AdapterError("progress_write_rejected")
            offset += written
        self._index += 1

    @property
    def complete(self) -> bool:
        return self._index == len(self._phases)


def _readiness(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    role: str | None = None,
    progress: _ProgressEmitter | None = None,
) -> None:
    execution = plan["execution"]
    formal = role in {"formal1", "formal2"}
    if formal and progress is not None:
        progress.emit("target_validation_pass1")
    _verify_target_source(contract, plan)
    if progress is not None and role in {"prepare", "formal1", "formal2"}:
        progress.emit("current_public_snapshot")
    _verify_public(contract, plan, predecessor=True)
    _verify_account_authority(contract, execution)
    _verify_opaque_metadata(contract, plan, exact_size=True)
    units = _unit_state(contract, plan)
    try:
        contract_v1._unit_state(units)
    except contract_v1.ContractError:
        raise AdapterError("unit_prestate_rejected") from None
    if units != execution["unit_prestate"]:
        raise AdapterError("unit_prestate_rejected")
    if progress is not None and role in {"prepare", "formal1", "formal2"}:
        progress.emit("plan_verify")
        contract_v1.validate_plan(contract, plan)
    if formal and progress is not None:
        progress.emit("target_validation_pass2")
        _verify_target_source(contract, plan)
    target_install = _fixed(contract, execution, "release_root") / str(plan["target_identity"])
    if target_install.exists() or target_install.is_symlink():
        raise AdapterError("target_install_preexists")
    incident = incident_root(contract, plan)
    if incident.exists() or incident.is_symlink():
        raise AdapterError("incident_preexists")
    if _recovery_artifacts_state(contract, execution) != "absent":
        raise AdapterError("boot_recovery_preexists")
    for role in (
        "boot_recovery_arm",
        "boot_recovery_disarm",
        "boot_recovery_boots",
        "synthetic_recovery_state",
    ):
        path = _fixed(contract, execution, role)
        if path.exists() or path.is_symlink():
            raise AdapterError("boot_recovery_preexists")


def _claim(contract: Mapping[str, object], plan: Mapping[str, object]) -> None:
    _readiness(contract, plan)
    incident = incident_root(contract, plan)
    incident.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(incident.parent, 0o700)
    _directory(incident.parent, owner=True)
    try:
        incident.mkdir(mode=0o700)
    except OSError:
        raise AdapterError("incident_claim_rejected") from None
    _fsync_directory(incident.parent)
    ledger_body = {
        "schema": LEDGER_SCHEMA,
        "plan_digest": plan["plan_digest"],
        "max_actions": 1,
        "actions_consumed": 1,
        "namespace_reset_allowed": False,
    }
    ledger = {**ledger_body, "ledger_digest": contract_v1.digest_value(ledger_body)}
    _exclusive_write(incident / "PLAN.json", contract_v1.canonical_bytes(plan), mode=0o600)
    _exclusive_write(incident / "LEDGER.json", contract_v1.canonical_bytes(ledger), mode=0o600)
    _exclusive_write(
        incident / "JOURNAL.json",
        contract_v1.canonical_bytes(_journal_payload(plan, ["claim"], None)),
        mode=0o600,
    )


def _verify_claim(contract: Mapping[str, object], plan: Mapping[str, object]) -> None:
    incident = incident_root(contract, plan)
    details = _directory(incident, owner=True)
    if stat.S_IMODE(details.st_mode) != 0o700:
        raise AdapterError("incident_identity_rejected")
    if _read_regular_bytes(incident / "PLAN.json", maximum=MAX_JSON_BYTES) != contract_v1.canonical_bytes(plan):
        raise AdapterError("incident_plan_rejected")
    ledger = _read_json(incident / "LEDGER.json")
    body = {key: value for key, value in ledger.items() if key != "ledger_digest"}
    if (
        set(ledger) != {"actions_consumed", "ledger_digest", "max_actions", "namespace_reset_allowed", "plan_digest", "schema"}
        or ledger["schema"] != LEDGER_SCHEMA
        or ledger["plan_digest"] != plan["plan_digest"]
        or ledger["max_actions"] != 1
        or ledger["actions_consumed"] != 1
        or ledger["namespace_reset_allowed"] is not False
        or ledger["ledger_digest"] != contract_v1.digest_value(body)
    ):
        raise AdapterError("incident_ledger_rejected")
    _load_journal(contract, plan)


def _copy_exact(
    source: Path,
    destination: Path,
    *,
    mode: int,
    uid: int,
    gid: int,
    maximum: int,
    on_boundary: Callable[[str], None] | None = None,
) -> dict[str, object]:
    def boundary(name: str) -> None:
        if on_boundary is not None:
            on_boundary(name)

    before = _regular(source, maximum=maximum)
    source_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
    try:
        source_descriptor = os.open(source, source_flags)
    except OSError:
        raise AdapterError("backup_copy_rejected") from None
    try:
        opened = os.fstat(source_descriptor)
    except OSError:
        os.close(source_descriptor)
        raise AdapterError("backup_copy_rejected") from None
    if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or _stat_identity(opened) != _stat_identity(before):
        os.close(source_descriptor)
        raise AdapterError("backup_copy_rejected")
    try:
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(destination.parent, 0o700)
        _directory(destination.parent)
    except BaseException:
        os.close(source_descriptor)
        raise
    temporary = destination.parent / f".{destination.name}.copying"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(temporary, flags, 0o600)
    except OSError:
        os.close(source_descriptor)
        raise AdapterError("backup_copy_rejected") from None
    boundary("stage_open")
    digest = sha256()
    try:
        remaining = opened.st_size
        while remaining:
            chunk = os.read(source_descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise AdapterError("backup_copy_rejected")
            digest.update(chunk)
            offset = 0
            while offset < len(chunk):
                written = os.write(descriptor, chunk[offset:])
                if written < 1:
                    raise AdapterError("backup_copy_rejected")
                offset += written
                boundary("stage_write")
            remaining -= len(chunk)
        if os.read(source_descriptor, 1):
            raise AdapterError("backup_copy_rejected")
        os.fchmod(descriptor, mode)
        boundary("stage_chmod")
        os.fchown(descriptor, uid, gid)
        boundary("stage_chown")
        os.fsync(descriptor)
        boundary("stage_fsync")
    except BaseException:
        os.close(descriptor)
        os.close(source_descriptor)
        raise
    os.close(descriptor)
    os.close(source_descriptor)
    boundary("pre_publish")
    _rename_noreplace(
        temporary,
        destination,
        error_category="backup_finalize_rejected",
        infrastructure_mutated=False,
    )
    boundary("post_publish")
    _fsync_directory(destination.parent)
    after = _regular(source, maximum=maximum)
    copied = _regular(destination, maximum=maximum)
    source_digest = digest.hexdigest()
    if (
        _stat_identity(before) != _stat_identity(after)
        or copied.st_size != before.st_size
        or stat.S_IMODE(copied.st_mode) != mode
        or copied.st_uid != uid
        or copied.st_gid != gid
        or _digest(destination, maximum=maximum) != source_digest
    ):
        raise AdapterError("backup_copy_rejected")
    boundary("stage_readback")
    return {"path": destination.name, "size": copied.st_size, "sha256": source_digest, "mode": mode, "uid": uid, "gid": gid}


def _backup(contract: Mapping[str, object], plan: Mapping[str, object]) -> None:
    _verify_claim(contract, plan)
    _verify_public(contract, plan, predecessor=True)
    _verify_opaque_metadata(contract, plan, exact_size=True)
    incident = incident_root(contract, plan)
    backup = incident / "BACKUP"
    backup.mkdir(mode=0o700)
    public_root = backup / "public"
    state_root = backup / "opaque-state"
    public_root.mkdir(mode=0o700)
    state_root.mkdir(mode=0o700)
    execution = plan["execution"]
    for role in contract_v1.PUBLIC_ROLES:
        row = execution["public_prestate"][role]
        _copy_exact(
            _fixed(contract, execution, role),
            public_root / role,
            mode=int(row["mode"]),
            uid=int(row["uid"]),
            gid=int(row["gid"]),
            maximum=MAX_TARGET_FILE_BYTES,
        )
    opaque_rows = []
    source_root = _fixed(contract, execution, "state_root")
    for row in execution["opaque_prestate"]["entries"]:
        source = source_root / str(row["path"])
        destination = state_root / str(row["path"])
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        opaque_rows.append(
            {
                "source_path": row["path"],
                **_copy_exact(
                    source,
                    destination,
                    mode=int(row["mode"]),
                    uid=int(row["uid"]),
                    gid=int(row["gid"]),
                    maximum=MAX_STATE_FILE_BYTES,
                ),
            }
        )
    body = {
        "schema": OPAQUE_BACKUP_SCHEMA,
        "plan_digest": plan["plan_digest"],
        "content_bytes_read": True,
        "content_parsed": False,
        "rows": opaque_rows,
    }
    manifest = {**body, "backup_digest": contract_v1.digest_value(body)}
    _exclusive_write(backup / "OPAQUE.json", contract_v1.canonical_bytes(manifest), mode=0o600)
    _advance(contract, plan, "backup")


def _verify_backup(contract: Mapping[str, object], plan: Mapping[str, object], *, source_must_match: bool) -> dict[str, object]:
    _verify_claim(contract, plan)
    incident = incident_root(contract, plan)
    backup = incident / "BACKUP"
    execution = plan["execution"]
    if source_must_match:
        _verify_public(contract, plan, predecessor=True)
        _verify_opaque_metadata(contract, plan, exact_size=True)
    expected_backup_files = [
        "OPAQUE.json",
        *(f"public/{role}" for role in contract_v1.PUBLIC_ROLES),
        *(
            "opaque-state/" + str(row["path"])
            for row in execution["opaque_prestate"]["entries"]
        ),
    ]
    _tree_shape_exact(backup, expected_backup_files)
    for role in contract_v1.PUBLIC_ROLES:
        expected = execution["public_prestate"][role]
        path = backup / "public" / role
        details = _regular(path)
        if (
            details.st_nlink != 1
            or stat.S_IMODE(details.st_mode) != int(expected["mode"])
            or details.st_uid != int(expected["uid"])
            or details.st_gid != int(expected["gid"])
            or details.st_size != int(expected["size"])
            or _digest(path) != expected["sha256"]
        ):
            raise AdapterError("public_backup_rejected")
    manifest = _read_json(backup / "OPAQUE.json")
    body = {key: value for key, value in manifest.items() if key != "backup_digest"}
    if (
        manifest.get("schema") != OPAQUE_BACKUP_SCHEMA
        or manifest.get("plan_digest") != plan["plan_digest"]
        or manifest.get("content_bytes_read") is not True
        or manifest.get("content_parsed") is not False
        or manifest.get("backup_digest") != contract_v1.digest_value(body)
    ):
        raise AdapterError("opaque_backup_rejected")
    source_root = _fixed(contract, execution, "state_root")
    rows = manifest.get("rows")
    if not isinstance(rows, list) or len(rows) != len(execution["opaque_prestate"]["entries"]):
        raise AdapterError("opaque_backup_rejected")
    for expected, row in zip(execution["opaque_prestate"]["entries"], rows, strict=True):
        if (
            not isinstance(row, dict)
            or set(row) != {"gid", "mode", "path", "sha256", "size", "source_path", "uid"}
            or row.get("source_path") != expected["path"]
            or row.get("path") != Path(str(expected["path"])).name
            or row.get("mode") != expected["mode"]
            or row.get("uid") != expected["uid"]
            or row.get("gid") != expected["gid"]
            or row.get("size") != expected["size"]
        ):
            raise AdapterError("opaque_backup_rejected")
        backup_path = backup / "opaque-state" / str(expected["path"])
        details = _regular(backup_path, maximum=MAX_STATE_FILE_BYTES)
        if (
            stat.S_IMODE(details.st_mode) != int(expected["mode"])
            or details.st_uid != int(expected["uid"])
            or details.st_gid != int(expected["gid"])
            or details.st_size != int(expected["size"])
            or _digest(backup_path, maximum=MAX_STATE_FILE_BYTES) != row.get("sha256")
        ):
            raise AdapterError("opaque_backup_rejected")
        if source_must_match:
            source_path = source_root / str(expected["path"])
            source_details = _regular(source_path, maximum=MAX_STATE_FILE_BYTES)
            if (
                stat.S_IMODE(source_details.st_mode) != int(expected["mode"])
                or source_details.st_uid != int(expected["uid"])
                or source_details.st_gid != int(expected["gid"])
                or source_details.st_size != int(expected["size"])
                or _digest(source_path, maximum=MAX_STATE_FILE_BYTES)
                != row.get("sha256")
            ):
                raise AdapterError("action_owned_state_drifted")
    return manifest


def _copy_tree_exact(
    source: Path,
    destination: Path,
    inventory: Sequence[Mapping[str, object]],
    directories: Sequence[Mapping[str, object]],
    *,
    on_boundary: Callable[[str], None] | None = None,
    root_precreated: bool = False,
) -> None:
    def boundary(name: str) -> None:
        if on_boundary is not None:
            on_boundary(name)

    for row in sorted(
        directories,
        key=lambda value: (str(value["path"]).count("/"), str(value["path"])),
    ):
        path = destination if row["path"] == "." else destination / str(row["path"])
        try:
            if row["path"] == "." and root_precreated:
                _directory(path, owner=True)
            else:
                # Use one deterministic interrupted-create mode.  The exact
                # source-owned directory mode follows through chmod below.
                path.mkdir(mode=0o700)
                boundary("stage_directory_open")
            os.chmod(path, int(row["mode"]))
            boundary("stage_directory_chmod")
            os.chown(path, os.getuid(), os.getgid(), follow_symlinks=False)
            boundary("stage_directory_chown")
        except OSError:
            raise AdapterError("target_copy_rejected") from None
        _directory(path, owner=True)
    for row in inventory:
        source_path = source / str(row["path"])
        destination_path = destination / str(row["path"])
        _directory(destination_path.parent, owner=True)
        _copy_exact(
            source_path,
            destination_path,
            mode=int(row["mode"]),
            uid=os.getuid(),
            gid=os.getgid(),
            maximum=MAX_TARGET_FILE_BYTES,
            on_boundary=(
                lambda name: boundary(
                    "stage_file_"
                    + (
                        name[len("stage_") :]
                        if name.startswith("stage_")
                        else name
                    )
                )
            ),
        )
    # The secure file copier intentionally forces its immediate parent to
    # 0700 for backup use.  Release directories have their own source-bound
    # modes, so restore those exact modes only after every file is durable.
    for row in directories:
        path = destination if row["path"] == "." else destination / str(row["path"])
        try:
            os.chmod(path, int(row["mode"]))
            boundary("stage_directory_chmod")
            os.chown(path, os.getuid(), os.getgid(), follow_symlinks=False)
            boundary("stage_directory_chown")
        except OSError:
            raise AdapterError("target_copy_rejected") from None
    observed = target_inventory(destination)
    expected = [
        {**dict(row), "uid": os.getuid(), "gid": os.getgid()} for row in inventory
    ]
    if observed != expected:
        raise AdapterError("target_copy_rejected")
    observed_directories = target_directory_inventory(
        destination,
        file_inventory=observed,
    )
    expected_directories = [
        {**dict(row), "uid": os.getuid(), "gid": os.getgid()}
        for row in directories
    ]
    if observed_directories != expected_directories:
        raise AdapterError("target_copy_rejected")
    for row in sorted(
        directories,
        key=lambda value: (str(value["path"]).count("/"), str(value["path"])),
        reverse=True,
    ):
        path = destination if row["path"] == "." else destination / str(row["path"])
        _fsync_directory(path)
        boundary("stage_directory_fsync")
    _fsync_directory(destination.parent)
    boundary("stage_tree_readback")


def _stage(contract: Mapping[str, object], plan: Mapping[str, object]) -> None:
    _verify_backup(contract, plan, source_must_match=True)
    incident = incident_root(contract, plan)
    stage = incident / "STAGE" / str(plan["target_identity"])
    stage.parent.mkdir(mode=0o700)
    _copy_tree_exact(
        Path(str(plan["execution"]["target_source_path"])),
        stage,
        plan["execution"]["target_inventory"],
        plan["execution"]["target_directories"],
    )
    _advance(contract, plan, "stage")


def _ensure_parent_directory(path: Path, *, uid: int, gid: int) -> None:
    missing: list[Path] = []
    current = path
    while not current.exists():
        if current.is_symlink():
            raise AdapterError("boot_recovery_path_rejected")
        missing.append(current)
        if current == current.parent:
            raise AdapterError("boot_recovery_path_rejected")
        current = current.parent
    try:
        details = current.lstat()
    except OSError:
        raise AdapterError("boot_recovery_path_rejected") from None
    if not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode):
        raise AdapterError("boot_recovery_path_rejected")
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o755)
            os.chmod(directory, 0o755)
            os.chown(directory, uid, gid)
            _fsync_directory(directory.parent)
        except OSError:
            raise AdapterError("boot_recovery_path_rejected") from None
    _verify_parent_directories(path / "placeholder")


def _recovery_intraprefix_fault(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    prefix: str,
    boundary: str,
) -> None:
    if plan["execution"]["backend"] != "synthetic":
        return
    control = _synthetic_control(contract, plan)
    recovery = _recovery_contract(contract)
    install_end = recovery["install_order"].index("closure_readback")
    prefix_index = recovery["install_order"].index(prefix)
    expected_role = "recovery_install" if prefix_index <= install_end else "recovery_arm"
    if control["fault_role"] != expected_role:
        return
    for outcome in ("rejected", "indeterminate", "kill"):
        if control["fault_kind"] != f"intraprefix_{prefix}_{boundary}_{outcome}":
            continue
        mutated = boundary not in {"pre_intent", "post_intent"}
        if outcome == "rejected":
            raise AdapterError(
                "synthetic_recovery_intraprefix_fault",
                infrastructure_mutated=mutated,
            )
        if outcome == "indeterminate":
            raise RuntimeError("synthetic recovery intraprefix fault")
        os.kill(os.getpid(), signal.SIGKILL)
    return


def _ensure_prefix_intent_and_fault(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    prefix: str,
    *,
    payload: Mapping[str, object] | None = None,
) -> dict[str, object]:
    _recovery_intraprefix_fault(contract, plan, prefix, "pre_intent")
    intent = _ensure_recovery_intent(contract, plan, prefix, payload=payload)
    _recovery_intraprefix_fault(contract, plan, prefix, "post_intent")
    return intent


def _verify_exact_stage_owner(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    prefix: str,
    intent: Mapping[str, object],
) -> None:
    _ensure_recovery_stage_owner(contract, plan, prefix, intent)


def _transactional_publish_file(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    prefix: str,
    raw: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
) -> None:
    operation = _recovery_prefix_operation(contract, prefix)
    payload: Mapping[str, object] | None = None
    if operation["kind"] == "canonical_file":
        payload = {
            "kind": "canonical_file",
            "sha256": _digest_bytes(raw),
            "size": len(raw),
            "mode": mode,
            "uid": uid,
            "gid": gid,
            "canonical_value": _canonical_mapping(raw),
        }
    intent = _ensure_prefix_intent_and_fault(
        contract, plan, prefix, payload=payload
    )
    bound = intent["payload"]
    if (
        bound["sha256"] != _digest_bytes(raw)
        or bound["size"] != len(raw)
        or bound["mode"] != mode
        or bound["uid"] != uid
        or bound["gid"] != gid
    ):
        raise AdapterError("boot_recovery_intent_rejected", infrastructure_mutated=True)
    destination = _recovery_prefix_destination(contract, plan, prefix)
    stage, _ = _recovery_stage_paths(contract, plan, prefix)
    if destination is None or stage is None:
        raise AdapterError("boot_recovery_stage_rejected", infrastructure_mutated=True)
    _ensure_parent_directory(destination.parent, uid=uid, gid=gid)
    _recovery_intraprefix_fault(contract, plan, prefix, "parent_ready")
    owner = _ensure_recovery_stage_owner(contract, plan, prefix, intent)
    del owner
    if destination.exists() or destination.is_symlink():
        details = _regular(destination, maximum=max(len(raw), 1))
        if (
            details.st_nlink != 1
            or stat.S_IMODE(details.st_mode) != mode
            or details.st_uid != uid
            or details.st_gid != gid
            or _read_regular_bytes(destination, maximum=max(len(raw), 1)) != raw
        ):
            raise AdapterError("boot_recovery_publish_rejected", infrastructure_mutated=True)
    else:
        if stage.exists() or stage.is_symlink():
            raise AdapterError("boot_recovery_stage_rejected", infrastructure_mutated=True)
        _exclusive_write(
            stage,
            raw,
            mode=mode,
            uid=uid,
            gid=gid,
            on_boundary=lambda name: _recovery_intraprefix_fault(
                contract, plan, prefix, name
            ),
        )
        _recovery_intraprefix_fault(contract, plan, prefix, "pre_publish")
        _rename_noreplace(stage, destination)
        _recovery_intraprefix_fault(contract, plan, prefix, "post_publish")
    details = _regular(destination, maximum=max(len(raw), 1))
    if (
        details.st_nlink != 1
        or stat.S_IMODE(details.st_mode) != mode
        or details.st_uid != uid
        or details.st_gid != gid
        or _read_regular_bytes(destination, maximum=max(len(raw), 1)) != raw
    ):
        raise AdapterError("boot_recovery_publish_rejected", infrastructure_mutated=True)
    _verify_exact_stage_owner(contract, plan, prefix, intent)


def _transactional_publish_symlink(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    prefix: str,
    target: str,
    *,
    uid: int,
    gid: int,
) -> None:
    intent = _ensure_prefix_intent_and_fault(contract, plan, prefix)
    destination = _recovery_prefix_destination(contract, plan, prefix)
    stage, _ = _recovery_stage_paths(contract, plan, prefix)
    if destination is None or stage is None:
        raise AdapterError("boot_recovery_stage_rejected", infrastructure_mutated=True)
    _ensure_parent_directory(destination.parent, uid=uid, gid=gid)
    _recovery_intraprefix_fault(contract, plan, prefix, "parent_ready")
    _ensure_recovery_stage_owner(contract, plan, prefix, intent)
    if destination.exists() or destination.is_symlink():
        try:
            if not destination.is_symlink() or os.readlink(destination) != target:
                raise AdapterError("boot_recovery_publish_rejected", infrastructure_mutated=True)
        except OSError:
            raise AdapterError("boot_recovery_publish_rejected", infrastructure_mutated=True) from None
    else:
        if stage.exists() or stage.is_symlink():
            raise AdapterError("boot_recovery_stage_rejected", infrastructure_mutated=True)
        try:
            os.symlink(target, stage)
            _recovery_intraprefix_fault(contract, plan, prefix, "stage_open")
            os.lchown(stage, uid, gid)
            _recovery_intraprefix_fault(contract, plan, prefix, "stage_chown")
            _fsync_directory(stage.parent)
            _recovery_intraprefix_fault(contract, plan, prefix, "stage_fsync")
            if os.readlink(stage) != target:
                raise AdapterError("boot_recovery_stage_rejected", infrastructure_mutated=True)
            _recovery_intraprefix_fault(contract, plan, prefix, "stage_readback")
        except OSError:
            raise AdapterError("boot_recovery_stage_rejected", infrastructure_mutated=True) from None
        _recovery_intraprefix_fault(contract, plan, prefix, "pre_publish")
        _rename_noreplace(stage, destination)
        _recovery_intraprefix_fault(contract, plan, prefix, "post_publish")
    _verify_exact_stage_owner(contract, plan, prefix, intent)


def _transactional_materialize_recovery_artifact(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    artifact: Mapping[str, object],
) -> None:
    execution = plan["execution"]
    prefix = str(artifact["role"])
    uid = int(artifact["uid"]) if execution["backend"] == "systemd" else os.getuid()
    gid = int(artifact["gid"]) if execution["backend"] == "systemd" else os.getgid()
    if artifact["type"] == "file":
        _transactional_publish_file(
            contract,
            plan,
            prefix,
            str(artifact["content"]).encode("ascii"),
            mode=int(artifact["mode"]),
            uid=uid,
            gid=gid,
        )
    elif artifact["type"] == "symlink":
        _transactional_publish_symlink(
            contract,
            plan,
            prefix,
            str(artifact["target"]),
            uid=uid,
            gid=gid,
        )
    else:
        raise AdapterError("boot_recovery_artifact_rejected", infrastructure_mutated=True)
    _verify_recovery_artifact(execution, artifact)


def _transactional_publish_runtime(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    source: Path,
) -> None:
    prefix = "runtime_package"
    intent = _ensure_prefix_intent_and_fault(contract, plan, prefix)
    execution = plan["execution"]
    destination = _fixed(contract, execution, "recovery_runtime_root")
    stage, _ = _recovery_stage_paths(contract, plan, prefix)
    if stage is None:
        raise AdapterError("boot_recovery_stage_rejected", infrastructure_mutated=True)
    _ensure_parent_directory(destination.parent, uid=os.getuid(), gid=os.getgid())
    _recovery_intraprefix_fault(contract, plan, prefix, "parent_ready")
    _ensure_recovery_stage_owner(contract, plan, prefix, intent)
    if destination.exists() or destination.is_symlink():
        _verify_recovery_runtime(contract, plan)
    else:
        if stage.exists() or stage.is_symlink():
            try:
                stage_details = stage.lstat()
            except OSError:
                raise AdapterError(
                    "boot_recovery_stage_rejected", infrastructure_mutated=True
                ) from None
            if (
                not stat.S_ISDIR(stage_details.st_mode)
                or stat.S_ISLNK(stage_details.st_mode)
                or any(stage.iterdir())
            ):
                raise AdapterError(
                    "boot_recovery_stage_rejected", infrastructure_mutated=True
                )
        else:
            try:
                stage.mkdir(mode=0o700)
                os.chmod(stage, 0o700)
                os.chown(stage, os.getuid(), os.getgid(), follow_symlinks=False)
                _fsync_directory(stage.parent)
            except OSError:
                raise AdapterError(
                    "boot_recovery_stage_rejected", infrastructure_mutated=True
                ) from None
            _recovery_intraprefix_fault(contract, plan, prefix, "stage_open")
        _copy_tree_exact(
            source,
            stage,
            execution["target_inventory"],
            execution["target_directories"],
            on_boundary=lambda name: _recovery_intraprefix_fault(
                contract, plan, prefix, name
            ),
            root_precreated=True,
        )
        _recovery_intraprefix_fault(contract, plan, prefix, "pre_publish")
        _rename_noreplace(stage, destination)
        _recovery_intraprefix_fault(contract, plan, prefix, "post_publish")
        _verify_recovery_runtime(contract, plan)
    _verify_exact_stage_owner(contract, plan, prefix, intent)


def _begin_manager_effect(
    contract: Mapping[str, object], plan: Mapping[str, object], prefix: str
) -> None:
    _ensure_prefix_intent_and_fault(contract, plan, prefix)
    _recovery_intraprefix_fault(contract, plan, prefix, "pre_effect")


def _finish_manager_effect(
    contract: Mapping[str, object], plan: Mapping[str, object], prefix: str
) -> None:
    _recovery_intraprefix_fault(contract, plan, prefix, "post_effect")


def _apply_synthetic_recovery_overlay(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> None:
    value = _read_json(_fixed(contract, plan["execution"], "synthetic_unit_state"))
    try:
        current = contract_v1._unit_snapshot(value)
    except contract_v1.ContractError:
        raise AdapterError("boot_recovery_unit_overlay_rejected") from None
    expected = _runtime_with_recovery_gate(
        contract,
        contract["compatibility"]["predecessor"]["unit_runtime"],
    )
    for role in ("service", "socket"):
        current["effective"][role] = {
            **dict(expected[role]),
            "active_state": current["effective"][role]["active_state"],
            "sub_state": current["effective"][role]["sub_state"],
        }
    _write_unit_state(contract, plan, current)


def _set_synthetic_recovery_unit_state(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    armed: bool,
) -> None:
    """Atomically project the generated recovery-unit shape for a reload.

    The initial reload exposes only the isolated recovery unit and its
    enablement relation.  The product reverse edges become effective only on
    the explicit post-ARM reload.
    """

    execution = plan["execution"]
    path = _fixed(contract, execution, "synthetic_recovery_state")
    expected = _recovery_contract(contract)[
        "armed_unit_runtime" if armed else "unit_runtime"
    ]
    value = {
        **dict(expected),
        "boot_identity_digest": launcher_v1.boot_identity_digest(),
        "invocation_id": str(plan["sequence_identity"])[:32],
    }
    _ensure_parent_directory(path.parent, uid=os.getuid(), gid=os.getgid())
    if not path.exists() and not path.is_symlink():
        _exclusive_write(
            path,
            contract_v1.canonical_bytes(value),
            mode=0o600,
            uid=os.getuid(),
            gid=os.getgid(),
        )
        return
    current = _read_json(path)
    if current == value:
        return
    temporary = path.with_name(path.name + ".NEXT")
    _exclusive_write(
        temporary,
        contract_v1.canonical_bytes(value),
        mode=0o600,
        uid=os.getuid(),
        gid=os.getgid(),
    )
    try:
        os.replace(temporary, path)
    except OSError:
        raise AdapterError(
            "boot_recovery_unit_state_rejected", infrastructure_mutated=True
        ) from None
    _fsync_directory(path.parent)


def _verify_recovery_runtime(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> None:
    execution = plan["execution"]
    runtime = _fixed(contract, execution, "recovery_runtime_root")
    observed = target_inventory(runtime)
    expected = [
        {**dict(row), "uid": os.getuid(), "gid": os.getgid()}
        for row in execution["target_inventory"]
    ]
    if observed != expected:
        raise AdapterError("boot_recovery_runtime_rejected")
    directories = target_directory_inventory(runtime, file_inventory=observed)
    expected_directories = [
        {**dict(row), "uid": os.getuid(), "gid": os.getgid()}
        for row in execution["target_directories"]
    ]
    if directories != expected_directories:
        raise AdapterError("boot_recovery_runtime_rejected")


def _recovery_closure_path(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> Path:
    return incident_root(contract, plan) / "RECOVERY.CLOSURE.json"


def _recovery_transaction_root(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> Path:
    return incident_root(contract, plan) / "RECOVERY.INFRASTRUCTURE"


def _recovery_obligation_path(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> Path:
    return _recovery_transaction_root(contract, plan) / "OBLIGATION.json"


def _recovery_event_path(
    contract: Mapping[str, object], plan: Mapping[str, object], prefix: str
) -> Path:
    transaction = _recovery_contract(contract)["infrastructure_transaction"]
    prefixes = list(transaction["prefixes"])
    if prefix not in prefixes:
        raise AdapterError("boot_recovery_transaction_rejected")
    return (
        _recovery_transaction_root(contract, plan)
        / "events"
        / f"{prefixes.index(prefix) + 1:02d}-{prefix}.json"
    )


def _recovery_intent_path(
    contract: Mapping[str, object], plan: Mapping[str, object], prefix: str
) -> Path:
    transaction = _recovery_contract(contract)["infrastructure_transaction"]
    prefixes = list(transaction["prefixes"])
    if prefix not in prefixes:
        raise AdapterError("boot_recovery_transaction_rejected")
    return (
        _recovery_transaction_root(contract, plan)
        / "intents"
        / f"{prefixes.index(prefix) + 1:02d}-{prefix}.json"
    )


def _recovery_prefix_operation(
    contract: Mapping[str, object], prefix: str
) -> dict[str, object]:
    transaction = _recovery_contract(contract)["infrastructure_transaction"]
    rows = [
        dict(row)
        for row in transaction["prefix_operations"]
        if isinstance(row, Mapping) and row.get("prefix") == prefix
    ]
    if len(rows) != 1:
        raise AdapterError("boot_recovery_transaction_rejected")
    return rows[0]


def _recovery_prefix_destination(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    prefix: str,
) -> Path | None:
    operation = _recovery_prefix_operation(contract, prefix)
    authority = str(operation["destination_authority"])
    execution = plan["execution"]
    if operation["kind"] == "runtime_tree":
        return _fixed(contract, execution, authority)
    if operation["kind"] == "artifact":
        matches = [
            row
            for row in _recovery_contract(contract)["artifacts"]
            if row["role"] == authority
        ]
        if len(matches) != 1:
            raise AdapterError("boot_recovery_transaction_rejected")
        return _recovery_artifact_path(execution, matches[0])
    if authority == "incident_recovery_closure":
        return _recovery_closure_path(contract, plan)
    if authority == "boot_recovery_arm":
        return _fixed(contract, execution, authority)
    return None


def _recovery_stage_paths(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    prefix: str,
) -> tuple[Path | None, Path | None]:
    destination = _recovery_prefix_destination(contract, plan, prefix)
    if destination is None:
        return None, None
    token = str(plan["plan_digest"])[:20]
    stage = destination.parent / f".{destination.name}.p08-{token}-{prefix}.txn"
    owner = _recovery_intent_path(contract, plan, prefix)
    return stage, owner


def _recovery_intent_payload(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    prefix: str,
    supplied: Mapping[str, object] | None = None,
) -> dict[str, object]:
    operation = _recovery_prefix_operation(contract, prefix)
    execution = plan["execution"]
    kind = str(operation["kind"])
    if kind == "runtime_tree":
        expected = {
            "kind": kind,
            "inventory_digest": execution["target_inventory_digest"],
            "directories_digest": execution["target_directories_digest"],
            "uid": os.getuid(),
            "gid": os.getgid(),
        }
    elif kind == "artifact":
        matches = [
            row
            for row in _recovery_contract(contract)["artifacts"]
            if row["role"] == prefix
        ]
        if len(matches) != 1:
            raise AdapterError("boot_recovery_intent_rejected", infrastructure_mutated=True)
        artifact = matches[0]
        expected = {
            "kind": str(artifact["type"]),
            "sha256": str(artifact["sha256"]),
            "size": int(artifact["size"]),
            "mode": artifact["mode"],
            "uid": (
                int(artifact["uid"])
                if execution["backend"] == "systemd"
                else os.getuid()
            ),
            "gid": (
                int(artifact["gid"])
                if execution["backend"] == "systemd"
                else os.getgid()
            ),
            "target": artifact.get("target"),
        }
    elif kind == "manager_effect":
        expected = {
            "kind": kind,
            "operation_digest": contract_v1.digest_value(operation),
        }
    elif kind == "canonical_file":
        if not isinstance(supplied, Mapping):
            raise AdapterError(
                "boot_recovery_intent_rejected", infrastructure_mutated=True
            )
        value = supplied.get("canonical_value")
        if not isinstance(value, Mapping):
            raise AdapterError(
                "boot_recovery_intent_rejected", infrastructure_mutated=True
            )
        canonical_value = dict(value)
        try:
            if prefix == "closure_readback":
                canonical_value = boot_recovery_v1.validate_closure(
                    contract, plan, canonical_value
                )
            elif prefix == "arm":
                closure = boot_recovery_v1.validate_closure(
                    contract,
                    plan,
                    _read_json(_recovery_closure_path(contract, plan)),
                )
                canonical_value = boot_recovery_v1.validate_arm(
                    contract,
                    plan,
                    _strategy_launch_claim(contract, plan),
                    _verify_backup(contract, plan, source_must_match=False),
                    closure,
                    canonical_value,
                )
            else:
                raise AdapterError("boot_recovery_intent_rejected")
        except boot_recovery_v1.BootRecoveryError:
            raise AdapterError(
                "boot_recovery_intent_rejected", infrastructure_mutated=True
            ) from None
        raw = contract_v1.canonical_bytes(canonical_value)
        expected = {
            "kind": kind,
            "sha256": _digest_bytes(raw),
            "size": len(raw),
            "mode": 0o600,
            "uid": os.getuid(),
            "gid": os.getgid(),
            "canonical_value": canonical_value,
        }
    else:
        raise AdapterError("boot_recovery_intent_rejected", infrastructure_mutated=True)
    if supplied is not None and dict(supplied) != expected:
        raise AdapterError("boot_recovery_intent_rejected", infrastructure_mutated=True)
    return expected


def _recovery_intent_value(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    prefix: str,
    payload: Mapping[str, object] | None = None,
) -> dict[str, object]:
    obligation = _validate_recovery_obligation(
        contract, plan, _read_json(_recovery_obligation_path(contract, plan))
    )
    operation = _recovery_prefix_operation(contract, prefix)
    bound_payload = _recovery_intent_payload(
        contract, plan, prefix, supplied=payload
    )
    destination = _recovery_prefix_destination(contract, plan, prefix)
    stage, owner = _recovery_stage_paths(contract, plan, prefix)
    body = {
        "schema": contract_v1.RECOVERY_INFRASTRUCTURE_INTENT_SCHEMA,
        "contract_digest": contract["contract_digest"],
        "plan_digest": plan["plan_digest"],
        "sequence_identity": plan["sequence_identity"],
        "obligation_digest": obligation["obligation_digest"],
        "prefix": prefix,
        "ordinal": list(obligation["prefixes"]).index(prefix) + 1,
        "operation": operation,
        "operation_digest": contract_v1.digest_value(operation),
        "payload": bound_payload,
        "payload_digest": contract_v1.digest_value(bound_payload),
        "destination_path_digest": (
            _digest_bytes(str(destination).encode("utf-8"))
            if destination is not None
            else None
        ),
        "stage_path_digest": (
            _digest_bytes(str(stage).encode("utf-8")) if stage is not None else None
        ),
        "owner_path_digest": (
            _digest_bytes(str(owner).encode("utf-8")) if owner is not None else None
        ),
        "destination_prestate": "absent",
        "persistent_effect_may_follow": True,
        "product_mutation_allowed": False,
        "mutation_scope": "recovery_infrastructure",
        "raw_content_included": False,
    }
    return {**body, "intent_digest": contract_v1.digest_value(body)}


def _validate_recovery_intent(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    prefix: str,
    value: Mapping[str, object],
) -> dict[str, object]:
    if not isinstance(value, Mapping) or not isinstance(value.get("payload"), Mapping):
        raise AdapterError("boot_recovery_intent_rejected", infrastructure_mutated=True)
    expected = _recovery_intent_value(
        contract, plan, prefix, payload=value["payload"]
    )
    path = _recovery_intent_path(contract, plan, prefix)
    try:
        details = _regular(path, maximum=MAX_JSON_BYTES)
    except AdapterError:
        raise AdapterError(
            "boot_recovery_intent_rejected", infrastructure_mutated=True
        ) from None
    if (
        not isinstance(value, Mapping)
        or dict(value) != expected
        or details.st_nlink != 1
        or stat.S_IMODE(details.st_mode) != 0o600
        or details.st_uid != os.getuid()
        or details.st_gid != os.getgid()
    ):
        raise AdapterError(
            "boot_recovery_intent_rejected", infrastructure_mutated=True
        )
    return dict(value)


def _ensure_recovery_intent(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    prefix: str,
    payload: Mapping[str, object] | None = None,
) -> dict[str, object]:
    path = _recovery_intent_path(contract, plan, prefix)
    expected = _recovery_intent_value(contract, plan, prefix, payload=payload)
    if path.exists() or path.is_symlink():
        observed = _validate_recovery_intent(
            contract, plan, prefix, _read_json(path)
        )
        if observed != expected:
            raise AdapterError(
                "boot_recovery_intent_rejected", infrastructure_mutated=True
            )
        return observed
    destination = _recovery_prefix_destination(contract, plan, prefix)
    stage, _ = _recovery_stage_paths(contract, plan, prefix)
    if (
        (destination is not None and (destination.exists() or destination.is_symlink()))
        or (stage is not None and (stage.exists() or stage.is_symlink()))
    ):
        raise AdapterError("boot_recovery_intent_rejected", infrastructure_mutated=True)
    _exclusive_write(
        path,
        contract_v1.canonical_bytes(expected),
        mode=0o600,
        uid=os.getuid(),
        gid=os.getgid(),
    )
    return _validate_recovery_intent(contract, plan, prefix, _read_json(path))


def _ensure_recovery_stage_owner(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    prefix: str,
    intent: Mapping[str, object],
) -> dict[str, object]:
    _, owner_path = _recovery_stage_paths(contract, plan, prefix)
    if owner_path is None:
        raise AdapterError("boot_recovery_stage_rejected", infrastructure_mutated=True)
    observed = _validate_recovery_intent(
        contract, plan, prefix, _read_json(owner_path)
    )
    if observed != dict(intent):
        raise AdapterError("boot_recovery_stage_rejected", infrastructure_mutated=True)
    stage, _ = _recovery_stage_paths(contract, plan, prefix)
    if stage is None:
        raise AdapterError("boot_recovery_stage_rejected", infrastructure_mutated=True)
    parent = stage.parent
    incident = incident_root(contract, plan)
    try:
        parent.relative_to(incident)
        incident_owned = True
    except ValueError:
        incident_owned = False
    if incident_owned:
        details = _directory(parent, owner=True)
        if stat.S_IMODE(details.st_mode) != 0o700:
            raise AdapterError(
                "boot_recovery_stage_rejected", infrastructure_mutated=True
            )
    else:
        obligation = _validate_recovery_obligation(
            contract, plan, _read_json(_recovery_obligation_path(contract, plan))
        )
        root = Path(str(plan["execution"]["root"]))
        relative = "/" + parent.relative_to(root).as_posix()
        rows = [row for row in obligation["parent_prestate"] if row["path"] == relative]
        if len(rows) != 1:
            raise AdapterError(
                "boot_recovery_stage_rejected", infrastructure_mutated=True
            )
        details = _directory(parent)
        row = rows[0]
        expected = (
            (0o755, os.getuid(), os.getgid())
            if row["state"] == "absent"
            else (int(row["mode"]), int(row["uid"]), int(row["gid"]))
        )
        if (stat.S_IMODE(details.st_mode), details.st_uid, details.st_gid) != expected:
            raise AdapterError(
                "boot_recovery_stage_rejected", infrastructure_mutated=True
            )
    return observed


def _rename_noreplace(
    source: Path,
    destination: Path,
    *,
    error_category: str = "boot_recovery_publish_rejected",
    infrastructure_mutated: bool = True,
) -> None:
    def stable_parent_identity(details: os.stat_result) -> tuple[int, ...]:
        return (
            details.st_dev,
            details.st_ino,
            stat.S_IFMT(details.st_mode),
            stat.S_IMODE(details.st_mode),
            details.st_uid,
            details.st_gid,
        )

    if (
        source.parent != destination.parent
        or source.name in {"", ".", ".."}
        or destination.name in {"", ".", ".."}
    ):
        raise AdapterError(
            error_category, infrastructure_mutated=infrastructure_mutated
        )
    parent = source.parent
    before = _directory(parent)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        parent_descriptor = os.open(parent, flags)
        opened = os.fstat(parent_descriptor)
    except OSError:
        raise AdapterError(
            error_category, infrastructure_mutated=infrastructure_mutated
        ) from None
    if stable_parent_identity(opened) != stable_parent_identity(before):
        os.close(parent_descriptor)
        raise AdapterError(
            error_category, infrastructure_mutated=infrastructure_mutated
        )
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        os.close(parent_descriptor)
        raise AdapterError(
            error_category, infrastructure_mutated=infrastructure_mutated
        )
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent_descriptor,
        os.fsencode(source.name),
        parent_descriptor,
        os.fsencode(destination.name),
        1,
    )
    if result != 0:
        code = ctypes.get_errno()
        os.close(parent_descriptor)
        if code in {errno.EEXIST, errno.ENOTEMPTY}:
            raise AdapterError(
                "boot_recovery_publish_preexists"
                if infrastructure_mutated
                else error_category,
                infrastructure_mutated=infrastructure_mutated,
            )
        raise AdapterError(
            error_category, infrastructure_mutated=infrastructure_mutated
        )
    try:
        after = os.fstat(parent_descriptor)
        os.fsync(parent_descriptor)
    except OSError:
        os.close(parent_descriptor)
        raise AdapterError(
            error_category, infrastructure_mutated=infrastructure_mutated
        ) from None
    os.close(parent_descriptor)
    if stable_parent_identity(after) != stable_parent_identity(before):
        raise AdapterError(
            error_category, infrastructure_mutated=infrastructure_mutated
        )


def _recovery_convergence_path(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> Path:
    return _recovery_transaction_root(contract, plan) / "CONVERGENCE.json"


def _recovery_obligation_value(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> dict[str, object]:
    recovery = _recovery_contract(contract)
    transaction = recovery["infrastructure_transaction"]
    backup = _verify_backup(contract, plan, source_must_match=True)
    claim = _strategy_launch_claim(contract, plan)
    root = Path(str(plan["execution"]["root"]))
    mutation_paths = [
        _fixed(contract, plan["execution"], "recovery_runtime_root"),
        _fixed(contract, plan["execution"], "boot_recovery_arm"),
        *(
            _recovery_artifact_path(plan["execution"], artifact)
            for artifact in recovery["artifacts"]
        ),
    ]
    parent_paths: set[Path] = set()
    for mutation_path in mutation_paths:
        current = mutation_path.parent
        while current != root:
            try:
                current.relative_to(root)
            except ValueError:
                raise AdapterError("boot_recovery_path_rejected") from None
            parent_paths.add(current)
            current = current.parent
    parent_prestate: list[dict[str, object]] = []
    for path in sorted(parent_paths, key=lambda value: value.as_posix()):
        relative = "/" + path.relative_to(root).as_posix()
        if not path.exists() and not path.is_symlink():
            parent_prestate.append({"path": relative, "state": "absent"})
            continue
        try:
            details = path.lstat()
        except OSError:
            raise AdapterError("boot_recovery_path_rejected") from None
        if not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode):
            raise AdapterError("boot_recovery_path_rejected")
        parent_prestate.append(
            {
                "path": relative,
                "state": "directory",
                "mode": stat.S_IMODE(details.st_mode),
                "uid": details.st_uid,
                "gid": details.st_gid,
            }
        )
    body = {
        "schema": contract_v1.RECOVERY_INFRASTRUCTURE_OBLIGATION_SCHEMA,
        "architecture": contract_v1.ARCHITECTURE,
        "contract_digest": contract["contract_digest"],
        "plan_digest": plan["plan_digest"],
        "sequence_identity": plan["sequence_identity"],
        "launch_claim_digest": claim["launch_claim_digest"],
        "prestate_identity": plan["prestate_identity"],
        "predecessor_identity": plan["predecessor_identity"],
        "target_identity": plan["target_identity"],
        "backup_digest": backup["backup_digest"],
        "owner_boot_identity_digest": launcher_v1.boot_identity_digest(),
        "prestate": "absent",
        "parent_prestate": parent_prestate,
        "runtime_inventory_digest": plan["execution"]["target_inventory_digest"],
        "runtime_directories_digest": plan["execution"][
            "target_directories_digest"
        ],
        "artifacts_digest": transaction["artifacts_digest"],
        "prefix_operations_digest": transaction["prefix_operations_digest"],
        "prefixes": transaction["prefixes"],
        "reverse_order": transaction["reverse_order"],
        "max_convergence_count": 1,
        "target_product_mutation_allowed": False,
        "raw_content_included": False,
    }
    return {**body, "obligation_digest": contract_v1.digest_value(body)}


def _validate_recovery_obligation(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    value: Mapping[str, object],
) -> dict[str, object]:
    expected_keys = {
        "architecture",
        "artifacts_digest",
        "backup_digest",
        "contract_digest",
        "launch_claim_digest",
        "max_convergence_count",
        "obligation_digest",
        "owner_boot_identity_digest",
        "parent_prestate",
        "plan_digest",
        "predecessor_identity",
        "prefix_operations_digest",
        "prefixes",
        "prestate",
        "prestate_identity",
        "raw_content_included",
        "reverse_order",
        "runtime_directories_digest",
        "runtime_inventory_digest",
        "schema",
        "sequence_identity",
        "target_identity",
        "target_product_mutation_allowed",
    }
    if not isinstance(value, Mapping) or set(value) != expected_keys:
        raise AdapterError("boot_recovery_obligation_rejected")
    backup = _verify_backup(contract, plan, source_must_match=False)
    claim = _strategy_launch_claim(contract, plan)
    transaction = _recovery_contract(contract)["infrastructure_transaction"]
    parents = value["parent_prestate"]
    if not isinstance(parents, list) or not parents:
        raise AdapterError("boot_recovery_obligation_rejected")
    parent_paths: list[str] = []
    for row in parents:
        if (
            not isinstance(row, Mapping)
            or row.get("state") not in {"absent", "directory"}
            or not isinstance(row.get("path"), str)
            or not str(row["path"]).startswith("/")
            or "//" in str(row["path"])
            or "/../" in str(row["path"]) + "/"
            or (
                row["state"] == "absent"
                and set(row) != {"path", "state"}
            )
            or (
                row["state"] == "directory"
                and (
                    set(row) != {"gid", "mode", "path", "state", "uid"}
                    or any(
                        not isinstance(row[key], int)
                        or isinstance(row[key], bool)
                        or row[key] < 0
                        for key in ("gid", "mode", "uid")
                    )
                )
            )
        ):
            raise AdapterError("boot_recovery_obligation_rejected")
        parent_paths.append(str(row["path"]))
    unsigned = {
        key: item for key, item in value.items() if key != "obligation_digest"
    }
    if (
        parent_paths != sorted(set(parent_paths))
        or value["schema"]
        != contract_v1.RECOVERY_INFRASTRUCTURE_OBLIGATION_SCHEMA
        or value["architecture"] != contract_v1.ARCHITECTURE
        or value["contract_digest"] != contract["contract_digest"]
        or value["plan_digest"] != plan["plan_digest"]
        or value["sequence_identity"] != plan["sequence_identity"]
        or value["launch_claim_digest"] != claim["launch_claim_digest"]
        or value["prestate_identity"] != plan["prestate_identity"]
        or value["predecessor_identity"] != plan["predecessor_identity"]
        or value["target_identity"] != plan["target_identity"]
        or value["backup_digest"] != backup["backup_digest"]
        or contract_v1.HEX64.fullmatch(str(value["owner_boot_identity_digest"]))
        is None
        or value["prestate"] != "absent"
        or value["runtime_inventory_digest"]
        != plan["execution"]["target_inventory_digest"]
        or value["runtime_directories_digest"]
        != plan["execution"]["target_directories_digest"]
        or value["artifacts_digest"] != transaction["artifacts_digest"]
        or value["prefix_operations_digest"]
        != transaction["prefix_operations_digest"]
        or value["prefixes"] != transaction["prefixes"]
        or value["reverse_order"] != transaction["reverse_order"]
        or value["max_convergence_count"] != 1
        or value["target_product_mutation_allowed"] is not False
        or value["raw_content_included"] is not False
        or value["obligation_digest"] != contract_v1.digest_value(unsigned)
    ):
        raise AdapterError("boot_recovery_obligation_rejected")
    return dict(value)


def _ensure_recovery_obligation(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> dict[str, object]:
    path = _recovery_obligation_path(contract, plan)
    expected = _recovery_obligation_value(contract, plan)
    if path.exists() or path.is_symlink():
        return _validate_recovery_obligation(contract, plan, _read_json(path))
    transaction_root = _recovery_transaction_root(contract, plan)
    events_root = transaction_root / "events"
    intents_root = transaction_root / "intents"
    try:
        transaction_root.mkdir(mode=0o700)
        os.chmod(transaction_root, 0o700)
        _fsync_directory(transaction_root.parent)
        events_root.mkdir(mode=0o700)
        os.chmod(events_root, 0o700)
        intents_root.mkdir(mode=0o700)
        os.chmod(intents_root, 0o700)
        _fsync_directory(transaction_root)
    except OSError:
        raise AdapterError("boot_recovery_obligation_rejected") from None
    for directory in (transaction_root, events_root, intents_root):
        details = _directory(directory, owner=True)
        if stat.S_IMODE(details.st_mode) != 0o700:
            raise AdapterError("boot_recovery_obligation_rejected")
    _exclusive_write(
        path,
        contract_v1.canonical_bytes(expected),
        mode=0o600,
        uid=os.getuid(),
        gid=os.getgid(),
    )
    return _validate_recovery_obligation(contract, plan, _read_json(path))


def _record_recovery_prefix(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    prefix: str,
    state_digest: str,
) -> dict[str, object]:
    obligation = _validate_recovery_obligation(
        contract, plan, _read_json(_recovery_obligation_path(contract, plan))
    )
    intent = _validate_recovery_intent(
        contract,
        plan,
        prefix,
        _read_json(_recovery_intent_path(contract, plan, prefix)),
    )
    if contract_v1.HEX64.fullmatch(state_digest) is None:
        raise AdapterError("boot_recovery_event_rejected")
    body = {
        "schema": contract_v1.RECOVERY_INFRASTRUCTURE_EVENT_SCHEMA,
        "contract_digest": contract["contract_digest"],
        "plan_digest": plan["plan_digest"],
        "obligation_digest": obligation["obligation_digest"],
        "intent_digest": intent["intent_digest"],
        "prefix": prefix,
        "ordinal": list(obligation["prefixes"]).index(prefix) + 1,
        "state_digest": state_digest,
        "persistent_mutation": True,
        "mutation_scope": "recovery_infrastructure",
        "raw_content_included": False,
    }
    value = {**body, "event_digest": contract_v1.digest_value(body)}
    path = _recovery_event_path(contract, plan, prefix)
    if path.exists() or path.is_symlink():
        if _read_json(path) != value:
            raise AdapterError(
                "boot_recovery_event_rejected", infrastructure_mutated=True
            )
        return value
    _exclusive_write(
        path,
        contract_v1.canonical_bytes(value),
        mode=0o600,
        uid=os.getuid(),
        gid=os.getgid(),
    )
    if _read_json(path) != value:
        raise AdapterError(
            "boot_recovery_event_rejected", infrastructure_mutated=True
        )
    return value


def _recovery_prefixes(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> list[str]:
    path = _recovery_obligation_path(contract, plan)
    if not path.exists() and not path.is_symlink():
        return []
    obligation = _validate_recovery_obligation(contract, plan, _read_json(path))
    observed: list[str] = []
    for prefix in obligation["prefixes"]:
        event_path = _recovery_event_path(contract, plan, str(prefix))
        if not event_path.exists() and not event_path.is_symlink():
            break
        event = _read_json(event_path)
        if (
            event.get("schema")
            != contract_v1.RECOVERY_INFRASTRUCTURE_EVENT_SCHEMA
            or event.get("contract_digest") != contract["contract_digest"]
            or event.get("plan_digest") != plan["plan_digest"]
            or event.get("obligation_digest") != obligation["obligation_digest"]
            or event.get("intent_digest")
            != _validate_recovery_intent(
                contract,
                plan,
                str(prefix),
                _read_json(_recovery_intent_path(contract, plan, str(prefix))),
            )["intent_digest"]
            or event.get("prefix") != prefix
            or event.get("ordinal") != len(observed) + 1
            or event.get("persistent_mutation") is not True
            or event.get("mutation_scope") != "recovery_infrastructure"
            or event.get("raw_content_included") is not False
            or not isinstance(event.get("state_digest"), str)
            or contract_v1.HEX64.fullmatch(str(event["state_digest"])) is None
            or event.get("event_digest")
            != contract_v1.digest_value(
                {key: item for key, item in event.items() if key != "event_digest"}
            )
        ):
            raise AdapterError(
                "boot_recovery_event_rejected", infrastructure_mutated=True
            )
        observed.append(str(prefix))
    events = _recovery_transaction_root(contract, plan) / "events"
    if events.exists() or events.is_symlink():
        expected_names = {
            _recovery_event_path(contract, plan, prefix).name for prefix in observed
        }
        if set(path.name for path in events.iterdir()) != expected_names:
            raise AdapterError(
                "boot_recovery_event_rejected", infrastructure_mutated=True
            )
    intents = _recovery_transaction_root(contract, plan) / "intents"
    if intents.exists() or intents.is_symlink():
        allowed_names = {
            _recovery_intent_path(contract, plan, str(prefix)).name
            for prefix in obligation["prefixes"]
        }
        names = {item.name for item in intents.iterdir()}
        if not names.issubset(allowed_names):
            raise AdapterError(
                "boot_recovery_intent_rejected", infrastructure_mutated=True
            )
        seen_gap = False
        for prefix in obligation["prefixes"]:
            intent_path = _recovery_intent_path(contract, plan, str(prefix))
            present = intent_path.exists() or intent_path.is_symlink()
            if not present:
                seen_gap = True
                continue
            if seen_gap:
                raise AdapterError(
                    "boot_recovery_intent_rejected", infrastructure_mutated=True
                )
            _validate_recovery_intent(
                contract, plan, str(prefix), _read_json(intent_path)
            )
    return observed


def _recovery_obligation_exists(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> bool:
    path = _recovery_obligation_path(contract, plan)
    if not path.exists() and not path.is_symlink():
        return False
    _validate_recovery_obligation(contract, plan, _read_json(path))
    return True


def _infrastructure_only_convergence_required(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> bool:
    if not _recovery_obligation_exists(contract, plan):
        return False
    events = _load_journal(contract, plan)["events"]
    allowed = [
        "claim",
        "backup",
        "stage",
        "recovery_install",
        "recovery_arm",
    ]
    return events == allowed[: len(events)]


def _recovery_runtime_state(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> str:
    runtime = _fixed(contract, plan["execution"], "recovery_runtime_root")
    if not runtime.exists() and not runtime.is_symlink():
        return "absent"
    try:
        _verify_recovery_runtime(contract, plan)
    except AdapterError:
        return "invalid"
    return "exact"


def _recovery_artifact_states(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> dict[str, str]:
    execution = plan["execution"]
    result: dict[str, str] = {}
    for artifact in _recovery_contract(contract)["artifacts"]:
        role = str(artifact["role"])
        path = _recovery_artifact_path(execution, artifact)
        if not path.exists() and not path.is_symlink():
            result[role] = "absent"
            continue
        try:
            _verify_recovery_artifact(execution, artifact)
        except AdapterError:
            result[role] = "invalid"
        else:
            result[role] = "exact"
    return result


def _recovery_presence_projection(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> dict[str, object]:
    execution = plan["execution"]
    artifacts = _recovery_artifact_states(contract, plan)
    closure_path = _recovery_closure_path(contract, plan)
    arm_path = _fixed(contract, execution, "boot_recovery_arm")
    disarm_path = _fixed(contract, execution, "boot_recovery_disarm")
    boots_path = _fixed(contract, execution, "boot_recovery_boots")
    synthetic_state = _fixed(contract, execution, "synthetic_recovery_state")

    def presence(path: Path) -> str:
        if not path.exists() and not path.is_symlink():
            return "absent"
        try:
            details = path.lstat()
        except OSError:
            return "invalid"
        if stat.S_ISREG(details.st_mode) and not stat.S_ISLNK(details.st_mode):
            return "present"
        if stat.S_ISDIR(details.st_mode) and not stat.S_ISLNK(details.st_mode):
            return "present"
        return "invalid"

    return {
        "runtime": _recovery_runtime_state(contract, plan),
        "artifacts": artifacts,
        "staging": {
            str(prefix): (
                "present"
                if (lambda paths: paths[0] is not None and (paths[0].exists() or paths[0].is_symlink()))(
                    _recovery_stage_paths(contract, plan, str(prefix))
                )
                else "absent"
            )
            for prefix in _recovery_contract(contract)["infrastructure_transaction"]["prefixes"]
        },
        "closure": presence(closure_path),
        "arm": presence(arm_path),
        "disarm": presence(disarm_path),
        "boots": presence(boots_path),
        "synthetic_unit_state": (
            presence(synthetic_state)
            if execution["backend"] == "synthetic"
            else "not_applicable"
        ),
    }


def _recovery_state_digest(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> str:
    return contract_v1.digest_value(_recovery_presence_projection(contract, plan))


def _recovery_prefix_fault(
    contract: Mapping[str, object], plan: Mapping[str, object], prefix: str
) -> None:
    if plan["execution"]["backend"] != "synthetic":
        return
    control = _synthetic_control(contract, plan)
    recovery = _recovery_contract(contract)
    arm_index = recovery["install_order"].index("arm")
    install_end = recovery["install_order"].index("closure_readback")
    prefix_index = recovery["install_order"].index(prefix)
    if prefix_index > arm_index:
        expected_role = "recovery_arm"
    else:
        expected_role = (
            "recovery_install" if prefix_index <= install_end else "recovery_arm"
        )
    if control["fault_role"] != expected_role:
        return
    if control["fault_kind"] == f"partial_{prefix}_rejected":
        raise AdapterError(
            "synthetic_recovery_prefix_fault", infrastructure_mutated=True
        )
    if control["fault_kind"] == f"partial_{prefix}_indeterminate":
        raise RuntimeError("synthetic recovery prefix fault")


def _record_and_fault_recovery_prefix(
    contract: Mapping[str, object], plan: Mapping[str, object], prefix: str
) -> None:
    _recovery_intraprefix_fault(contract, plan, prefix, "pre_event")
    _record_recovery_prefix(
        contract,
        plan,
        prefix=prefix,
        state_digest=_recovery_state_digest(contract, plan),
    )
    _recovery_intraprefix_fault(contract, plan, prefix, "post_event")
    _recovery_prefix_fault(contract, plan, prefix)


def _recovery_unit_state(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    armed: bool = False,
) -> dict[str, object]:
    execution = plan["execution"]
    recovery = _recovery_contract(contract)
    if execution["backend"] == "synthetic":
        value = _read_json(_fixed(contract, execution, "synthetic_recovery_state"))
        try:
            return boot_recovery_v1.validate_unit_state(
                contract, value, armed=armed
            )
        except boot_recovery_v1.BootRecoveryError:
            raise AdapterError("boot_recovery_unit_state_rejected") from None
    properties = (
        "ActiveState",
        "After",
        "Before",
        "BindsTo",
        "BoundBy",
        "ConflictedBy",
        "Conflicts",
        "ConsistsOf",
        "ControlGroup",
        "DropInPaths",
        "ExecMainCode",
        "ExecMainStatus",
        "ExecStart",
        "FragmentPath",
        "InvocationID",
        "LoadState",
        "MainPID",
        "NRestarts",
        "OnFailure",
        "OnSuccess",
        "PartOf",
        "PropagatesReloadTo",
        "PropagatesStopTo",
        "ReloadPropagatedFrom",
        "RequiredBy",
        "RestartMode",
        "Requires",
        "Requisite",
        "RequisiteOf",
        "Result",
        "StopPropagatedFrom",
        "SubState",
        "TriggeredBy",
        "Triggers",
        "UnitFileState",
        "UpheldBy",
        "Upholds",
        "WantedBy",
        "Wants",
    )
    fields = _systemctl_show(
        execution, str(recovery["unit_name"]), properties
    )
    try:
        observed = {
            "schema": contract_v1.BOOT_RECOVERY_UNIT_STATE_SCHEMA,
            "load_state": fields["LoadState"],
            "active_state": fields["ActiveState"],
            "sub_state": fields["SubState"],
            "unit_file_state": fields["UnitFileState"],
            "result": fields["Result"],
            "exec_main_code": int(fields["ExecMainCode"]),
            "exec_main_status": int(fields["ExecMainStatus"]),
            "main_pid": int(fields["MainPID"]),
            "n_restarts": int(fields["NRestarts"]),
            "restart_mode": fields["RestartMode"],
            "control_group": fields["ControlGroup"],
            "fragment_path": fields["FragmentPath"],
            "drop_in_paths": _path_projection(fields["DropInPaths"]),
            "exec_start_argv": _exec_start_projection(fields["ExecStart"]),
            "dependencies": {
                name: _dependency_projection(fields[name])
                for name in contract["systemd_authority"]["dependency_properties"]
            },
            "boot_identity_digest": launcher_v1.boot_identity_digest(),
            "invocation_id": fields["InvocationID"],
        }
    except ValueError:
        raise AdapterError("boot_recovery_unit_state_rejected") from None
    try:
        return boot_recovery_v1.validate_unit_state(
            contract, observed, armed=armed
        )
    except boot_recovery_v1.BootRecoveryError:
        raise AdapterError("boot_recovery_unit_state_rejected") from None


def _recovery_unit_entry_state(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> dict[str, object]:
    execution = plan["execution"]
    if execution["backend"] != "systemd":
        return {
            "invocation_id": str(plan["sequence_identity"])[:32],
            "n_restarts": 0,
        }
    recovery = _recovery_contract(contract)
    expected = recovery["manager_entry_runtime"]
    properties = (
        "ActiveState",
        "After",
        "Before",
        "BindsTo",
        "BoundBy",
        "ConflictedBy",
        "Conflicts",
        "ConsistsOf",
        "ControlGroup",
        "DropInPaths",
        "ExecMainCode",
        "ExecMainStatus",
        "ExecStart",
        "FragmentPath",
        "InvocationID",
        "LoadState",
        "MainPID",
        "NRestarts",
        "OnFailure",
        "OnSuccess",
        "PartOf",
        "PropagatesReloadTo",
        "PropagatesStopTo",
        "ReloadPropagatedFrom",
        "RequiredBy",
        "RestartMode",
        "Requires",
        "Requisite",
        "RequisiteOf",
        "Result",
        "StopPropagatedFrom",
        "SubState",
        "TriggeredBy",
        "Triggers",
        "UnitFileState",
        "UpheldBy",
        "Upholds",
        "WantedBy",
        "Wants",
    )
    fields = _systemctl_show(execution, str(recovery["unit_name"]), properties)
    try:
        pid = int(fields["MainPID"])
        restarts = int(fields["NRestarts"])
        exec_main_code = int(fields["ExecMainCode"])
        exec_main_status = int(fields["ExecMainStatus"])
    except ValueError:
        raise AdapterError("boot_recovery_entry_unit_rejected") from None
    invocation_id = fields["InvocationID"]
    dependencies = {
        name: _dependency_projection(fields[name])
        for name in contract["systemd_authority"]["dependency_properties"]
    }
    artifact_states = _recovery_artifact_states(contract, plan)
    gate_artifact_units = recovery["gate_artifact_units"]
    if (
        set(gate_artifact_units)
        != {"service_recovery_dropin", "socket_recovery_dropin"}
        or artifact_states.get("recovery_unit") != "exact"
        or artifact_states.get("recovery_enablement") != "exact"
        or any(
            artifact_states.get(role) not in {"absent", "exact"}
            for role in gate_artifact_units
        )
    ):
        raise AdapterError("boot_recovery_entry_unit_rejected")
    expected_dependencies = {
        name: list(values)
        for name, values in expected["base_dependencies"].items()
    }
    expected_dependencies["RequiredBy"] = sorted(
        str(gate_artifact_units[role])
        for role in sorted(gate_artifact_units)
        if artifact_states[role] == "exact"
    )
    if (
        fields["LoadState"] != expected["load_state"]
        or fields["ActiveState"] != expected["active_state"]
        or fields["SubState"] != expected["sub_state"]
        or fields["UnitFileState"] != expected["unit_file_state"]
        or fields["Result"] != expected["result"]
        or exec_main_code != expected["exec_main_code"]
        or exec_main_status != expected["exec_main_status"]
        or fields["ControlGroup"] != expected["control_group"]
        or fields["FragmentPath"] != expected["fragment_path"]
        or _path_projection(fields["DropInPaths"]) != expected["drop_in_paths"]
        or _exec_start_projection(fields["ExecStart"])
        != expected["exec_start_argv"]
        or dependencies != expected_dependencies
        or pid != os.getpid()
        or restarts not in expected["n_restarts_allowed"]
        or fields["RestartMode"] != expected["restart_mode"]
        or len(invocation_id) != 32
        or any(character not in "0123456789abcdef" for character in invocation_id)
    ):
        raise AdapterError("boot_recovery_entry_unit_rejected")
    return {"invocation_id": invocation_id, "n_restarts": restarts}


def _start_recovery_unit_no_arm(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> dict[str, object]:
    execution = plan["execution"]
    for role in ("boot_recovery_arm", "boot_recovery_disarm"):
        path = _fixed(contract, execution, role)
        if path.exists() or path.is_symlink():
            raise AdapterError("boot_recovery_prime_rejected")
    if execution["backend"] == "synthetic":
        state = {
            **dict(_recovery_contract(contract)["unit_runtime"]),
            "boot_identity_digest": launcher_v1.boot_identity_digest(),
            "invocation_id": str(plan["sequence_identity"])[:32],
        }
        path = _fixed(contract, execution, "synthetic_recovery_state")
        _ensure_parent_directory(path.parent, uid=os.getuid(), gid=os.getgid())
        _exclusive_write(
            path,
            contract_v1.canonical_bytes(state),
            mode=0o600,
            uid=os.getuid(),
            gid=os.getgid(),
        )
    else:
        completed = _run_bound_systemctl(
            execution,
            ["start", str(_recovery_contract(contract)["unit_name"])],
            capture_stdout=False,
            timeout=30,
        )
        if completed.returncode != 0:
            raise AdapterError("boot_recovery_prime_rejected")
    return _recovery_unit_state(contract, plan)


def _stop_recovery_unit_for_infrastructure_convergence(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> None:
    execution = plan["execution"]
    if execution["backend"] == "synthetic":
        state_path = _fixed(contract, execution, "synthetic_recovery_state")
        if state_path.exists() or state_path.is_symlink():
            _read_json(state_path)
            state_path.unlink()
            _fsync_directory(state_path.parent)
        return
    completed = _run_bound_systemctl(
        execution,
        ["stop", str(_recovery_contract(contract)["unit_name"])],
        capture_stdout=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise AdapterError(
            "boot_recovery_infrastructure_convergence_rejected",
            infrastructure_mutated=True,
        )


def _unlink_exact_recovery_artifact(
    execution: Mapping[str, object], artifact: Mapping[str, object]
) -> None:
    _verify_recovery_artifact(execution, artifact)
    path = _recovery_artifact_path(execution, artifact)
    try:
        path.unlink()
    except OSError:
        raise AdapterError(
            "boot_recovery_infrastructure_convergence_rejected",
            infrastructure_mutated=True,
        ) from None
    _fsync_directory(path.parent)


def _remove_exact_recovery_runtime(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> None:
    _verify_recovery_runtime(contract, plan)
    runtime = _fixed(contract, plan["execution"], "recovery_runtime_root")
    files = target_inventory(runtime)
    directories = target_directory_inventory(runtime, file_inventory=files)
    for row in files:
        path = runtime / str(row["path"])
        try:
            path.unlink()
        except OSError:
            raise AdapterError(
                "boot_recovery_infrastructure_convergence_rejected",
                infrastructure_mutated=True,
            ) from None
    for row in sorted(
        directories,
        key=lambda value: (str(value["path"]).count("/"), str(value["path"])),
        reverse=True,
    ):
        path = runtime if row["path"] == "." else runtime / str(row["path"])
        try:
            path.rmdir()
        except OSError:
            raise AdapterError(
                "boot_recovery_infrastructure_convergence_rejected",
                infrastructure_mutated=True,
            ) from None
    _fsync_directory(runtime.parent)


def _remove_owned_stage_file(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    prefix: str,
    intent: Mapping[str, object],
    *,
    expected_raw: bytes | None,
    expected_symlink: str | None,
) -> None:
    stage, _ = _recovery_stage_paths(contract, plan, prefix)
    if stage is None or (not stage.exists() and not stage.is_symlink()):
        return
    _ensure_recovery_stage_owner(contract, plan, prefix, intent)
    try:
        details = stage.lstat()
    except OSError:
        raise AdapterError(
            "boot_recovery_infrastructure_convergence_rejected",
            infrastructure_mutated=True,
        ) from None
    payload = intent["payload"]
    expected_uid = int(payload["uid"])
    expected_gid = int(payload["gid"])
    if expected_symlink is not None:
        try:
            exact = (
                stat.S_ISLNK(details.st_mode)
                and os.readlink(stage) == expected_symlink
                and (details.st_uid, details.st_gid)
                in {
                    (os.getuid(), os.getgid()),
                    (expected_uid, expected_gid),
                }
            )
        except OSError:
            exact = False
        if not exact:
            raise AdapterError(
                "boot_recovery_infrastructure_convergence_rejected",
                infrastructure_mutated=True,
            )
    else:
        if (
            expected_raw is None
            or not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
        ):
            raise AdapterError(
                "boot_recovery_infrastructure_convergence_rejected",
                infrastructure_mutated=True,
            )
        observed = _read_regular_bytes(stage, maximum=max(len(expected_raw), 1))
        final_mode = int(payload["mode"])
        lifecycle_metadata = {
            (0o600, os.getuid(), os.getgid()),
            (final_mode, os.getuid(), os.getgid()),
            (final_mode, expected_uid, expected_gid),
        }
        if (
            (stat.S_IMODE(details.st_mode), details.st_uid, details.st_gid)
            not in lifecycle_metadata
            or len(observed) > len(expected_raw)
            or not expected_raw.startswith(observed)
        ):
            raise AdapterError(
                "boot_recovery_infrastructure_convergence_rejected",
                infrastructure_mutated=True,
            )
    try:
        stage.unlink()
    except OSError:
        raise AdapterError(
            "boot_recovery_infrastructure_convergence_rejected",
            infrastructure_mutated=True,
        ) from None
    _fsync_directory(stage.parent)


def _validate_owned_runtime_stage_prefix(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    stage: Path,
) -> tuple[list[Path], list[Path]]:
    execution = plan["execution"]
    source = incident_root(contract, plan) / "STAGE" / str(plan["target_identity"])
    observed_source = target_inventory(source)
    expected_source = [
        {**dict(row), "uid": os.getuid(), "gid": os.getgid()}
        for row in execution["target_inventory"]
    ]
    if observed_source != expected_source:
        raise AdapterError(
            "boot_recovery_infrastructure_convergence_rejected",
            infrastructure_mutated=True,
        )
    observed_source_directories = target_directory_inventory(
        source, file_inventory=observed_source
    )
    expected_source_directories = [
        {**dict(row), "uid": os.getuid(), "gid": os.getgid()}
        for row in execution["target_directories"]
    ]
    if observed_source_directories != expected_source_directories:
        raise AdapterError(
            "boot_recovery_infrastructure_convergence_rejected",
            infrastructure_mutated=True,
        )
    expected_files = {
        str(row["path"]): row for row in execution["target_inventory"]
    }
    expected_directories = {
        str(row["path"]): row for row in execution["target_directories"]
    }
    files: list[Path] = []
    directories: list[Path] = []
    copying_files = 0
    try:
        entries = [stage, *sorted(stage.rglob("*"))]
    except OSError:
        raise AdapterError(
            "boot_recovery_infrastructure_convergence_rejected",
            infrastructure_mutated=True,
        ) from None
    directory_details: dict[Path, os.stat_result] = {}
    stage_parent_device = stage.parent.lstat().st_dev
    for path in entries:
        try:
            details = path.lstat()
        except OSError:
            raise AdapterError(
                "boot_recovery_infrastructure_convergence_rejected",
                infrastructure_mutated=True,
            ) from None
        relative = "." if path == stage else path.relative_to(stage).as_posix()
        if stat.S_ISDIR(details.st_mode) and not stat.S_ISLNK(details.st_mode):
            row = expected_directories.get(relative)
            if row is None or (
                stat.S_IMODE(details.st_mode)
                not in {0o700, int(row["mode"])}
                or details.st_uid != os.getuid()
                or details.st_gid != os.getgid()
                or details.st_dev != stage_parent_device
            ):
                raise AdapterError(
                    "boot_recovery_infrastructure_convergence_rejected",
                    infrastructure_mutated=True,
                )
            directories.append(path)
            directory_details[path] = details
            continue
        if not stat.S_ISREG(details.st_mode) or stat.S_ISLNK(details.st_mode) or details.st_nlink != 1:
            raise AdapterError(
                "boot_recovery_infrastructure_convergence_rejected",
                infrastructure_mutated=True,
            )
        expected_relative = relative
        row = expected_files.get(expected_relative)
        if row is None:
            candidate = Path(relative)
            if candidate.name.startswith(".") and candidate.name.endswith(".copying"):
                expected_relative = (
                    candidate.parent
                    / candidate.name[1 : -len(".copying")]
                ).as_posix()
                row = expected_files.get(expected_relative)
                copying_files += 1
                if (
                    row is None
                    or copying_files > 1
                    or (stage / expected_relative).exists()
                    or (stage / expected_relative).is_symlink()
                ):
                    row = None
        if row is None:
            raise AdapterError(
                "boot_recovery_infrastructure_convergence_rejected",
                infrastructure_mutated=True,
            )
        expected = _read_regular_bytes(
            source / expected_relative, maximum=MAX_TARGET_FILE_BYTES
        )
        observed = _read_regular_bytes(path, maximum=MAX_TARGET_FILE_BYTES)
        if (
            stat.S_IMODE(details.st_mode) not in {0o600, int(row["mode"])}
            or details.st_uid != os.getuid()
            or details.st_gid != os.getgid()
            or len(observed) > len(expected)
            or not expected.startswith(observed)
        ):
            raise AdapterError(
                "boot_recovery_infrastructure_convergence_rejected",
                infrastructure_mutated=True,
            )
        files.append(path)
    for path, details in directory_details.items():
        child_directories = sum(
            1 for candidate in directories if candidate.parent == path
        )
        if details.st_nlink != 2 + child_directories:
            raise AdapterError(
                "boot_recovery_infrastructure_convergence_rejected",
                infrastructure_mutated=True,
            )
    return files, directories


def _remove_owned_recovery_staging(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> None:
    obligation = _validate_recovery_obligation(
        contract, plan, _read_json(_recovery_obligation_path(contract, plan))
    )
    artifacts = {
        str(row["role"]): row for row in _recovery_contract(contract)["artifacts"]
    }
    for prefix in reversed(list(obligation["prefixes"])):
        intent_path = _recovery_intent_path(contract, plan, str(prefix))
        if not intent_path.exists() and not intent_path.is_symlink():
            continue
        intent = _validate_recovery_intent(
            contract, plan, str(prefix), _read_json(intent_path)
        )
        stage, _ = _recovery_stage_paths(contract, plan, str(prefix))
        if stage is None or (not stage.exists() and not stage.is_symlink()):
            continue
        operation = _recovery_prefix_operation(contract, str(prefix))
        if operation["kind"] == "runtime_tree":
            _ensure_recovery_stage_owner(contract, plan, str(prefix), intent)
            files, directories = _validate_owned_runtime_stage_prefix(
                contract, plan, stage
            )
            for path in files:
                path.unlink()
            for path in sorted(
                directories,
                key=lambda item: len(item.relative_to(stage).parts),
                reverse=True,
            ):
                path.rmdir()
            _fsync_directory(stage.parent)
            continue
        if operation["kind"] == "artifact":
            artifact = artifacts[str(prefix)]
            if artifact["type"] == "file":
                _remove_owned_stage_file(
                    contract,
                    plan,
                    str(prefix),
                    intent,
                    expected_raw=str(artifact["content"]).encode("ascii"),
                    expected_symlink=None,
                )
            else:
                _remove_owned_stage_file(
                    contract,
                    plan,
                    str(prefix),
                    intent,
                    expected_raw=None,
                    expected_symlink=str(artifact["target"]),
                )
            continue
        if str(prefix) == "closure_readback":
            expected = dict(intent["payload"])["canonical_value"]
            if not isinstance(expected, Mapping):
                raise AdapterError(
                    "boot_recovery_infrastructure_convergence_rejected",
                    infrastructure_mutated=True,
                )
            _remove_owned_stage_file(
                contract,
                plan,
                str(prefix),
                intent,
                expected_raw=contract_v1.canonical_bytes(expected),
                expected_symlink=None,
            )
            continue
        if str(prefix) == "arm":
            expected = dict(intent["payload"])["canonical_value"]
            if not isinstance(expected, Mapping):
                raise AdapterError(
                    "boot_recovery_infrastructure_convergence_rejected",
                    infrastructure_mutated=True,
                )
            _remove_owned_stage_file(
                contract,
                plan,
                str(prefix),
                intent,
                expected_raw=contract_v1.canonical_bytes(expected),
                expected_symlink=None,
            )


def _owned_staging_is_absent(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> bool:
    obligation_path = _recovery_obligation_path(contract, plan)
    if not obligation_path.exists() and not obligation_path.is_symlink():
        return True
    obligation = _validate_recovery_obligation(
        contract, plan, _read_json(obligation_path)
    )
    for prefix in obligation["prefixes"]:
        stage, _ = _recovery_stage_paths(contract, plan, str(prefix))
        if stage is not None and (stage.exists() or stage.is_symlink()):
            return False
    return True


def _restore_recovery_parent_prestate(
    obligation: Mapping[str, object], execution: Mapping[str, object]
) -> None:
    root = Path(str(execution["root"]))
    rows = list(obligation["parent_prestate"])
    for row in sorted(
        rows,
        key=lambda value: str(value["path"]).count("/"),
        reverse=True,
    ):
        path = _rooted(root, str(row["path"]))
        if row["state"] == "absent":
            if not path.exists() and not path.is_symlink():
                continue
            _directory(path)
            try:
                path.rmdir()
            except OSError:
                raise AdapterError(
                    "boot_recovery_infrastructure_convergence_rejected",
                    infrastructure_mutated=True,
                ) from None
            _fsync_directory(path.parent)
            continue
        details = _directory(path)
        if (
            stat.S_IMODE(details.st_mode) != row["mode"]
            or details.st_uid != row["uid"]
            or details.st_gid != row["gid"]
        ):
            raise AdapterError(
                "boot_recovery_infrastructure_convergence_rejected",
                infrastructure_mutated=True,
            )


def _infrastructure_convergence_value(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    obligation: Mapping[str, object],
    *,
    steps: Sequence[str],
    current_unit_self_retirement: bool,
) -> dict[str, object]:
    body = {
        "schema": contract_v1.RECOVERY_INFRASTRUCTURE_CONVERGENCE_SCHEMA,
        "contract_digest": contract["contract_digest"],
        "plan_digest": plan["plan_digest"],
        "obligation_digest": obligation["obligation_digest"],
        "convergence_count": 1,
        "owner_mode": (
            "boot_recovery_self_retirement"
            if current_unit_self_retirement
            else "external_guardian"
        ),
        "steps": list(steps),
        "final_prestate": "absent",
        "product_mutation": False,
        "trusted_time_history_restored": False,
        "raw_content_included": False,
    }
    return {**body, "convergence_digest": contract_v1.digest_value(body)}


def _validate_infrastructure_convergence(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    value: Mapping[str, object],
) -> dict[str, object]:
    obligation = _validate_recovery_obligation(
        contract, plan, _read_json(_recovery_obligation_path(contract, plan))
    )
    allowed_steps = [
        "remove_owned_staging",
        "remove_arm",
        "remove_socket_dropin",
        "remove_service_dropin",
        "detach_product_gates",
        "stop_recovery_unit",
        "remove_closure",
        "remove_enablement",
        "remove_recovery_unit",
        "remove_runtime_package",
        "final_daemon_reload",
        "verify_prestate",
    ]
    if (
        not isinstance(value, Mapping)
        or set(value)
        != {
            "contract_digest",
            "convergence_count",
            "convergence_digest",
            "final_prestate",
            "obligation_digest",
            "owner_mode",
            "plan_digest",
            "product_mutation",
            "raw_content_included",
            "schema",
            "steps",
            "trusted_time_history_restored",
        }
        or not isinstance(value["steps"], list)
        or value["steps"] != allowed_steps[: len(value["steps"])]
        or value.get("owner_mode")
        not in {"external_guardian", "boot_recovery_self_retirement"}
        or value != _infrastructure_convergence_value(
            contract,
            plan,
            obligation,
            steps=value["steps"],
            current_unit_self_retirement=(
                value["owner_mode"] == "boot_recovery_self_retirement"
            ),
        )
    ):
        raise AdapterError(
            "boot_recovery_infrastructure_convergence_rejected",
            infrastructure_mutated=True,
        )
    return dict(value)


def _replace_infrastructure_convergence(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    value: Mapping[str, object],
) -> dict[str, object]:
    path = _recovery_convergence_path(contract, plan)
    temporary = path.with_name("CONVERGENCE.NEXT.json")
    _exclusive_write(
        temporary,
        contract_v1.canonical_bytes(value),
        mode=0o600,
        uid=os.getuid(),
        gid=os.getgid(),
    )
    try:
        os.replace(temporary, path)
    except OSError:
        raise AdapterError(
            "boot_recovery_infrastructure_convergence_rejected",
            infrastructure_mutated=True,
        ) from None
    _fsync_directory(path.parent)
    return _validate_infrastructure_convergence(contract, plan, _read_json(path))


def _converge_recovery_infrastructure(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    current_unit_self_retirement: bool = False,
) -> None:
    obligation = _validate_recovery_obligation(
        contract, plan, _read_json(_recovery_obligation_path(contract, plan))
    )
    _verify_backup(contract, plan, source_must_match=True)
    _verify_public(contract, plan, predecessor=True)
    _verify_opaque_metadata(contract, plan, exact_size=True)
    arm_path = _fixed(contract, plan["execution"], "boot_recovery_arm")
    if arm_path.exists() or arm_path.is_symlink():
        closure_path = _recovery_closure_path(contract, plan)
        if not closure_path.exists() or closure_path.is_symlink():
            raise AdapterError(
                "boot_recovery_infrastructure_convergence_rejected",
                infrastructure_mutated=True,
            )
        closure = _read_json(closure_path)
        try:
            validated_closure = boot_recovery_v1.validate_closure(
                contract, plan, closure
            )
            boot_recovery_v1.validate_arm(
                contract,
                plan,
                _strategy_launch_claim(contract, plan),
                _verify_backup(contract, plan, source_must_match=False),
                validated_closure,
                _read_json(arm_path),
            )
        except boot_recovery_v1.BootRecoveryError:
            raise AdapterError(
                "boot_recovery_infrastructure_convergence_rejected",
                infrastructure_mutated=True,
            ) from None
    path = _recovery_convergence_path(contract, plan)
    if path.exists() or path.is_symlink():
        value = _validate_infrastructure_convergence(contract, plan, _read_json(path))
        expected_owner_mode = (
            "boot_recovery_self_retirement"
            if current_unit_self_retirement
            else "external_guardian"
        )
        if value["owner_mode"] != expected_owner_mode:
            raise AdapterError(
                "boot_recovery_infrastructure_convergence_rejected",
                infrastructure_mutated=True,
            )
    else:
        value = _infrastructure_convergence_value(
            contract,
            plan,
            obligation,
            steps=[],
            current_unit_self_retirement=current_unit_self_retirement,
        )
        _exclusive_write(
            path,
            contract_v1.canonical_bytes(value),
            mode=0o600,
            uid=os.getuid(),
            gid=os.getgid(),
        )
        value = _validate_infrastructure_convergence(contract, plan, _read_json(path))

    def complete(step: str) -> None:
        nonlocal value
        if step in value["steps"]:
            return
        replacement = _infrastructure_convergence_value(
            contract,
            plan,
            obligation,
            steps=[*value["steps"], step],
            current_unit_self_retirement=current_unit_self_retirement,
        )
        value = _replace_infrastructure_convergence(
            contract, plan, replacement
        )

    if "remove_owned_staging" not in value["steps"]:
        _remove_owned_recovery_staging(contract, plan)
        complete("remove_owned_staging")
    presence = _recovery_presence_projection(contract, plan)
    artifact_by_role = {
        str(row["role"]): row for row in _recovery_contract(contract)["artifacts"]
    }
    if "remove_arm" not in value["steps"]:
        if arm_path.exists() or arm_path.is_symlink():
            try:
                arm_path.unlink()
            except OSError:
                raise AdapterError(
                    "boot_recovery_infrastructure_convergence_rejected",
                    infrastructure_mutated=True,
                ) from None
            _fsync_directory(arm_path.parent)
        complete("remove_arm")
    for step, role in (
        ("remove_socket_dropin", "socket_recovery_dropin"),
        ("remove_service_dropin", "service_recovery_dropin"),
    ):
        if step in value["steps"]:
            continue
        artifact = artifact_by_role[role]
        artifact_path = _recovery_artifact_path(plan["execution"], artifact)
        if artifact_path.exists() or artifact_path.is_symlink():
            _unlink_exact_recovery_artifact(plan["execution"], artifact)
        complete(step)
    if "detach_product_gates" not in value["steps"]:
        if plan["execution"]["backend"] == "synthetic":
            state = _read_json(
                _fixed(contract, plan["execution"], "synthetic_unit_state")
            )
            expected = contract["compatibility"]["predecessor"]["unit_runtime"]
            for role in ("service", "socket"):
                state["effective"][role] = {
                    **dict(expected[role]),
                    "active_state": state["effective"][role]["active_state"],
                    "sub_state": state["effective"][role]["sub_state"],
                }
            _write_unit_state(contract, plan, state)
        _daemon_reload(
            contract, plan, mutation_scope="recovery_infrastructure"
        )
        complete("detach_product_gates")
    if "stop_recovery_unit" not in value["steps"]:
        if presence["runtime"] != "absent" or any(
            state != "absent" for state in presence["artifacts"].values()
        ):
            if current_unit_self_retirement:
                # A boot recovery process is the currently executing recovery
                # unit.  Stopping that unit here could terminate the only
                # convergence owner before durable prestate verification.  It
                # instead proves its exact manager identity, removes all
                # persistent authority below, reloads the detached product
                # topology, and exits.  The manager may retain the now-unbound
                # unit object for this boot only; no persistent file or product
                # dependency survives.
                _recovery_unit_entry_state(contract, plan)
                if plan["execution"]["backend"] == "synthetic":
                    state_path = _fixed(
                        contract,
                        plan["execution"],
                        "synthetic_recovery_state",
                    )
                    if state_path.exists() or state_path.is_symlink():
                        _read_json(state_path)
                        state_path.unlink()
                        _fsync_directory(state_path.parent)
            else:
                _stop_recovery_unit_for_infrastructure_convergence(contract, plan)
        complete("stop_recovery_unit")
    if "remove_closure" not in value["steps"]:
        closure_path = _recovery_closure_path(contract, plan)
        if closure_path.exists() or closure_path.is_symlink():
            boot_recovery_v1.validate_closure(
                contract, plan, _read_json(closure_path)
            )
            closure_path.unlink()
            _fsync_directory(closure_path.parent)
        complete("remove_closure")
    for step, role in (
        ("remove_enablement", "recovery_enablement"),
        ("remove_recovery_unit", "recovery_unit"),
    ):
        if step in value["steps"]:
            continue
        artifact = artifact_by_role[role]
        artifact_path = _recovery_artifact_path(plan["execution"], artifact)
        if artifact_path.exists() or artifact_path.is_symlink():
            _unlink_exact_recovery_artifact(plan["execution"], artifact)
        complete(step)
    if "remove_runtime_package" not in value["steps"]:
        runtime = _fixed(contract, plan["execution"], "recovery_runtime_root")
        if runtime.exists() or runtime.is_symlink():
            _remove_exact_recovery_runtime(contract, plan)
        complete("remove_runtime_package")
    if "final_daemon_reload" not in value["steps"]:
        _daemon_reload(
            contract, plan, mutation_scope="recovery_infrastructure"
        )
        complete("final_daemon_reload")
    if "verify_prestate" not in value["steps"]:
        if _recovery_artifacts_state(contract, plan["execution"]) != "absent":
            raise AdapterError(
                "boot_recovery_infrastructure_convergence_rejected",
                infrastructure_mutated=True,
            )
        if not _owned_staging_is_absent(contract, plan):
            raise AdapterError(
                "boot_recovery_infrastructure_convergence_rejected",
                infrastructure_mutated=True,
            )
        _restore_recovery_parent_prestate(obligation, plan["execution"])
        _verify_public(contract, plan, predecessor=True)
        _verify_opaque_metadata(contract, plan, exact_size=True)
        if _unit_state(contract, plan) != plan["execution"]["unit_prestate"]:
            raise AdapterError(
                "boot_recovery_infrastructure_convergence_rejected",
                infrastructure_mutated=True,
            )
        complete("verify_prestate")


def _recover_recovery_infrastructure(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> None:
    convergence = _validate_infrastructure_convergence(
        contract, plan, _read_json(_recovery_convergence_path(contract, plan))
    )
    if convergence["steps"][-1:] != ["verify_prestate"]:
        raise AdapterError(
            "boot_recovery_infrastructure_convergence_rejected",
            infrastructure_mutated=True,
        )
    _verify_public(contract, plan, predecessor=True)
    _verify_opaque_metadata(contract, plan, exact_size=True)
    if (
        _recovery_artifacts_state(contract, plan["execution"]) != "absent"
        or not _owned_staging_is_absent(contract, plan)
        or _unit_state(contract, plan) != plan["execution"]["unit_prestate"]
    ):
        raise AdapterError(
            "boot_recovery_infrastructure_convergence_rejected",
            infrastructure_mutated=True,
        )


def _postflight_recovery_infrastructure(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> None:
    _recover_recovery_infrastructure(contract, plan)
    target = _fixed(contract, plan["execution"], "release_root") / str(
        plan["target_identity"]
    )
    if target.exists() or target.is_symlink():
        raise AdapterError(
            "boot_recovery_infrastructure_convergence_rejected",
            infrastructure_mutated=True,
        )


def _verify_recovery_closure(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    allow_known_selection_drift: bool = False,
) -> dict[str, object]:
    if _recovery_artifacts_state(contract, plan["execution"]) != "exact":
        # Before ARM the service/socket gate drop-ins are intentionally absent;
        # the isolated recovery unit/runtime/enablement closure is still exact.
        states = _recovery_artifact_states(contract, plan)
        if not (
            states.get("recovery_unit") == "exact"
            and states.get("recovery_enablement") == "exact"
            and states.get("service_recovery_dropin") == "absent"
            and states.get("socket_recovery_dropin") == "absent"
        ):
            raise AdapterError("boot_recovery_closure_rejected")
    _verify_recovery_runtime(contract, plan)
    arm_path = _fixed(contract, plan["execution"], "boot_recovery_arm")
    armed = arm_path.exists() or arm_path.is_symlink()
    unit_state = _recovery_unit_state(contract, plan, armed=armed)
    closure_unit_state = (
        _read_json(_recovery_closure_path(contract, plan)).get("unit_state")
        if armed
        else unit_state
    )
    expected = boot_recovery_v1.build_closure(
        contract,
        plan,
        runtime_inventory_digest=str(plan["execution"]["target_inventory_digest"]),
        runtime_directories_digest=str(
            plan["execution"]["target_directories_digest"]
        ),
        unit_state=closure_unit_state,
    )
    observed = _read_json(_recovery_closure_path(contract, plan))
    try:
        validated = boot_recovery_v1.validate_closure(
            contract, plan, observed
        )
    except boot_recovery_v1.BootRecoveryError:
        raise AdapterError("boot_recovery_closure_rejected") from None
    if validated != expected:
        raise AdapterError("boot_recovery_closure_rejected")
    _unit_state(
        contract,
        plan,
        allow_known_selection_drift=allow_known_selection_drift,
    )
    return validated


def _recovery_install(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> None:
    _verify_backup(contract, plan, source_must_match=True)
    execution = plan["execution"]
    staged = incident_root(contract, plan) / "STAGE" / str(plan["target_identity"])
    observed_stage = target_inventory(staged)
    expected_stage = [
        {**dict(row), "uid": os.getuid(), "gid": os.getgid()}
        for row in execution["target_inventory"]
    ]
    if observed_stage != expected_stage:
        raise AdapterError("boot_recovery_runtime_rejected")
    _ensure_recovery_obligation(contract, plan)
    observed_prefixes = _recovery_prefixes(contract, plan)
    allowed_prefixes = list(
        _recovery_contract(contract)["infrastructure_transaction"]["prefixes"]
    )
    if observed_prefixes != allowed_prefixes[: len(observed_prefixes)]:
        raise AdapterError(
            "boot_recovery_transaction_rejected", infrastructure_mutated=True
        )
    runtime = _fixed(contract, execution, "recovery_runtime_root")
    if "runtime_package" not in observed_prefixes:
        if runtime.exists() or runtime.is_symlink():
            raise AdapterError(
                "boot_recovery_runtime_rejected", infrastructure_mutated=True
            )
        _transactional_publish_runtime(contract, plan, staged)
        _verify_recovery_runtime(contract, plan)
        _record_and_fault_recovery_prefix(contract, plan, "runtime_package")
        observed_prefixes.append("runtime_package")
    else:
        _verify_recovery_runtime(contract, plan)
    recovery_contract = _recovery_contract(contract)
    artifacts = {row["role"]: row for row in recovery_contract["artifacts"]}
    for role in ("recovery_unit", "recovery_enablement"):
        if role in artifacts:
            if role not in observed_prefixes:
                _transactional_materialize_recovery_artifact(
                    contract, plan, artifacts[role]
                )
                _record_and_fault_recovery_prefix(contract, plan, role)
                observed_prefixes.append(role)
            else:
                _verify_recovery_artifact(execution, artifacts[role])
    if "daemon_reload" not in observed_prefixes:
        _begin_manager_effect(contract, plan, "daemon_reload")
        _daemon_reload(
            contract, plan, mutation_scope="recovery_infrastructure"
        )
        _finish_manager_effect(contract, plan, "daemon_reload")
        _record_and_fault_recovery_prefix(contract, plan, "daemon_reload")
        observed_prefixes.append("daemon_reload")
    else:
        _unit_state(contract, plan)
    if "recovery_unit_start_no_arm" not in observed_prefixes:
        _begin_manager_effect(contract, plan, "recovery_unit_start_no_arm")
        unit_state = _start_recovery_unit_no_arm(contract, plan)
        _finish_manager_effect(contract, plan, "recovery_unit_start_no_arm")
        _record_and_fault_recovery_prefix(
            contract, plan, "recovery_unit_start_no_arm"
        )
        observed_prefixes.append("recovery_unit_start_no_arm")
    else:
        unit_state = _recovery_unit_state(contract, plan)
    closure = boot_recovery_v1.build_closure(
        contract,
        plan,
        runtime_inventory_digest=str(execution["target_inventory_digest"]),
        runtime_directories_digest=str(execution["target_directories_digest"]),
        unit_state=unit_state,
    )
    closure_path = _recovery_closure_path(contract, plan)
    if "closure_readback" not in observed_prefixes:
        if closure_path.exists() or closure_path.is_symlink():
            raise AdapterError(
                "boot_recovery_closure_rejected", infrastructure_mutated=True
            )
        _transactional_publish_file(
            contract,
            plan,
            "closure_readback",
            contract_v1.canonical_bytes(closure),
            mode=0o600,
            uid=os.getuid(),
            gid=os.getgid(),
        )
        _record_and_fault_recovery_prefix(contract, plan, "closure_readback")
    elif _read_json(closure_path) != closure:
        raise AdapterError(
            "boot_recovery_closure_rejected", infrastructure_mutated=True
        )
    _verify_recovery_closure(contract, plan)
    _advance(contract, plan, "recovery_install")


def _strategy_launch_claim(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> dict[str, object]:
    value = _read_json(
        _strategy_root(contract, plan["execution"])
        / "STRATEGY.LAUNCH.CLAIM.json"
    )
    try:
        return contract_v1.validate_strategy_launch_claim(contract, value)
    except contract_v1.ContractError:
        raise AdapterError("strategy_launch_claim_rejected") from None


def _recovery_arm(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> None:
    closure = _verify_recovery_closure(contract, plan)
    backup = _verify_backup(contract, plan, source_must_match=True)
    claim = _strategy_launch_claim(contract, plan)
    journal = _load_journal(contract, plan)
    if journal["events"] != ["claim", "backup", "stage", "recovery_install"]:
        raise AdapterError("boot_recovery_arm_order_rejected")
    execution = plan["execution"]
    for role in ("boot_recovery_disarm", "boot_recovery_boots"):
        path = _fixed(contract, execution, role)
        if path.exists() or path.is_symlink():
            raise AdapterError("boot_recovery_arm_preexists")
    try:
        arm = boot_recovery_v1.build_arm(
            contract,
            plan,
            launch_claim=claim,
            backup_manifest=backup,
            closure=closure,
            journal_digest=str(journal["journal_digest"]),
            boot_identity_digest=launcher_v1.boot_identity_digest(),
        )
    except boot_recovery_v1.BootRecoveryError:
        raise AdapterError("boot_recovery_arm_rejected") from None
    arm_path = _fixed(contract, execution, "boot_recovery_arm")
    observed_prefixes = _recovery_prefixes(contract, plan)
    artifacts = {
        str(row["role"]): row for row in _recovery_contract(contract)["artifacts"]
    }
    for role in ("socket_recovery_dropin", "service_recovery_dropin"):
        if role not in observed_prefixes:
            _transactional_materialize_recovery_artifact(
                contract, plan, artifacts[role]
            )
            _record_and_fault_recovery_prefix(contract, plan, role)
            observed_prefixes.append(role)
        else:
            _verify_recovery_artifact(plan["execution"], artifacts[role])
    if "arm" not in observed_prefixes:
        if arm_path.exists() or arm_path.is_symlink():
            if _read_json(arm_path) != arm:
                raise AdapterError(
                    "boot_recovery_arm_rejected", infrastructure_mutated=True
                )
        else:
            _transactional_publish_file(
                contract,
                plan,
                "arm",
                contract_v1.canonical_bytes(arm),
                mode=0o600,
                uid=os.getuid(),
                gid=os.getgid(),
            )
            if _read_json(arm_path) != arm:
                raise AdapterError(
                    "boot_recovery_arm_rejected", infrastructure_mutated=True
                )
        _record_and_fault_recovery_prefix(contract, plan, "arm")
        observed_prefixes.append("arm")
    elif _read_json(arm_path) != arm:
        raise AdapterError(
            "boot_recovery_arm_rejected", infrastructure_mutated=True
        )
    if "product_gate_reload" not in observed_prefixes:
        _begin_manager_effect(contract, plan, "product_gate_reload")
        if plan["execution"]["backend"] == "synthetic":
            _set_synthetic_recovery_unit_state(contract, plan, armed=True)
            _apply_synthetic_recovery_overlay(contract, plan)
        _daemon_reload(
            contract, plan, mutation_scope="recovery_infrastructure"
        )
        _finish_manager_effect(contract, plan, "product_gate_reload")
        _record_and_fault_recovery_prefix(contract, plan, "product_gate_reload")
    _verify_boot_recovery_persistent_closure(
        contract, plan, closure=closure, current_boot=True
    )
    _advance(contract, plan, "recovery_arm")


def _verify_recovery_arm(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    boot_reentry: bool = False,
    allow_known_selection_drift: bool = False,
) -> dict[str, object]:
    closure = (
        _verify_boot_recovery_persistent_closure(
            contract, plan, current_boot=True
        )
        if boot_reentry
        else _verify_recovery_closure(
            contract,
            plan,
            allow_known_selection_drift=allow_known_selection_drift,
        )
    )
    backup = _verify_backup(contract, plan, source_must_match=False)
    claim = _strategy_launch_claim(contract, plan)
    arm = _read_json(_fixed(contract, plan["execution"], "boot_recovery_arm"))
    try:
        return boot_recovery_v1.validate_arm(
            contract, plan, claim, backup, closure, arm
        )
    except boot_recovery_v1.BootRecoveryError:
        raise AdapterError("boot_recovery_arm_rejected") from None


def _verify_boot_recovery_persistent_closure(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    closure: Mapping[str, object] | None = None,
    current_boot: bool,
) -> dict[str, object]:
    states = _recovery_artifact_states(contract, plan)
    if not (
        states.get("recovery_unit") == "exact"
        and states.get("recovery_enablement") == "exact"
        and states.get("service_recovery_dropin") == "exact"
        and states.get("socket_recovery_dropin") == "exact"
    ):
        raise AdapterError("boot_recovery_closure_rejected")
    _verify_recovery_runtime(contract, plan)
    stored = _read_json(_recovery_closure_path(contract, plan))
    try:
        validated = boot_recovery_v1.validate_closure(contract, plan, stored)
    except boot_recovery_v1.BootRecoveryError:
        raise AdapterError("boot_recovery_closure_rejected") from None
    if closure is not None and validated != closure:
        raise AdapterError("boot_recovery_closure_rejected")
    if current_boot:
        # InvocationID and boot identity are intentionally fresh after reboot;
        # every other generated unit field remains exact.
        _recovery_unit_state(contract, plan, armed=True)
    _unit_state(contract, plan, allow_known_selection_drift=True)
    return validated


def _verify_boot_recovery_priming_closure(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> None:
    """Verify the installed gate immediately before its no-ARM first start."""
    states = _recovery_artifact_states(contract, plan)
    if not (
        states.get("recovery_unit") == "exact"
        and states.get("recovery_enablement") == "exact"
        and states.get("service_recovery_dropin") == "absent"
        and states.get("socket_recovery_dropin") == "absent"
    ):
        raise AdapterError("boot_recovery_closure_rejected")
    _verify_recovery_runtime(contract, plan)
    _unit_state(contract, plan, allow_known_selection_drift=True)


def _boot_product_exact(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    final_state: str,
    allow_active: bool,
) -> bool:
    if final_state not in {"predecessor", "target"}:
        raise AdapterError("boot_recovery_final_state_rejected")
    try:
        _verify_claim(contract, plan)
        _verify_account_authority(contract, plan["execution"])
        _verify_public(contract, plan, predecessor=final_state == "predecessor")
        forward = _forward_state_possible(contract, plan)
        _verify_opaque_metadata(
            contract,
            plan,
            exact_size=final_state == "predecessor" and not forward,
        )
        if final_state == "target":
            destination = _fixed(
                contract, plan["execution"], "release_root"
            ) / str(plan["target_identity"])
            observed = target_inventory(destination)
            expected = [
                {**dict(row), "uid": os.getuid(), "gid": os.getgid()}
                for row in plan["execution"]["target_inventory"]
            ]
            if observed != expected or target_directory_inventory(
                destination, file_inventory=observed
            ) != [
                {**dict(row), "uid": os.getuid(), "gid": os.getgid()}
                for row in plan["execution"]["target_directories"]
            ]:
                return False
        units = _unit_state(contract, plan)
        if allow_active:
            return bool(
                units["service_active"]
                and units["socket_active"]
                and units["service_main_pid"] > 0
                and units["socket_inode"] is not None
            )
        return bool(
            units["service_active"] is False
            and units["socket_active"] is False
            and units["service_main_pid"] == 0
            and units["service_process"] is None
            and units["socket_inode"] is None
        )
    except AdapterError:
        return False


def _boot_converge(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    monotonic_deadline_ns: int | None = None,
    monotonic_clock: Callable[[], int] | None = None,
) -> bool:
    """Converge public/state authority while keeping boot-gated units stopped."""
    _verify_recovery_arm(contract, plan, boot_reentry=True)
    _verify_backup(contract, plan, source_must_match=False)
    convergence_path = incident_root(contract, plan) / "BOOT.RECOVERY.CONVERGENCE.json"
    forward = _forward_state_possible(contract, plan)

    def require_deadline() -> None:
        if monotonic_deadline_ns is None:
            return
        observed = monotonic_clock() if monotonic_clock is not None else 0
        if (
            not isinstance(monotonic_deadline_ns, int)
            or isinstance(monotonic_deadline_ns, bool)
            or monotonic_deadline_ns < 1
            or not isinstance(observed, int)
            or isinstance(observed, bool)
            or observed < 1
            or observed > monotonic_deadline_ns
        ):
            raise AdapterError(
                "boot_recovery_deadline_exceeded", product_mutated=True
            )

    require_deadline()
    body = {
        "schema": "myuna.p08-boot-recovery-convergence.v1",
        "contract_digest": contract["contract_digest"],
        "plan_digest": plan["plan_digest"],
        "convergence_count": 1,
        "forward_state_retained": forward,
        "steps": [],
        "raw_content_included": False,
    }
    value = {**body, "convergence_digest": contract_v1.digest_value(body)}
    if convergence_path.exists() or convergence_path.is_symlink():
        value = _read_json(convergence_path)
        unsigned = {
            key: item for key, item in value.items() if key != "convergence_digest"
        }
        if (
            set(value)
            != {
                "contract_digest",
                "convergence_count",
                "convergence_digest",
                "forward_state_retained",
                "plan_digest",
                "raw_content_included",
                "schema",
                "steps",
            }
            or value["schema"] != "myuna.p08-boot-recovery-convergence.v1"
            or value["contract_digest"] != contract["contract_digest"]
            or value["plan_digest"] != plan["plan_digest"]
            or value["convergence_count"] != 1
            or value["forward_state_retained"] is not forward
            or value["raw_content_included"] is not False
            or not isinstance(value["steps"], list)
            or value["steps"]
            != [
                item
                for item in (
                    "stop_socket",
                    "stop_service",
                    "restore_public",
                    "retain_forward_state" if forward else "restore_opaque",
                    "verify_predecessor",
                )
                if item in value["steps"]
            ]
            or value["convergence_digest"] != contract_v1.digest_value(unsigned)
        ):
            raise AdapterError("boot_recovery_convergence_rejected", product_mutated=True)
    else:
        _exclusive_write(
            convergence_path,
            contract_v1.canonical_bytes(value),
            mode=0o600,
            uid=os.getuid(),
            gid=os.getgid(),
        )

    def complete(step: str) -> None:
        nonlocal value
        if step in value["steps"]:
            return
        steps = [*value["steps"], step]
        unsigned = {
            key: item
            for key, item in {**value, "steps": steps}.items()
            if key != "convergence_digest"
        }
        replacement = {
            **unsigned,
            "convergence_digest": contract_v1.digest_value(unsigned),
        }
        temporary = convergence_path.with_name("BOOT.RECOVERY.CONVERGENCE.NEXT.json")
        _exclusive_write(
            temporary,
            contract_v1.canonical_bytes(replacement),
            mode=0o600,
            uid=os.getuid(),
            gid=os.getgid(),
        )
        try:
            os.replace(temporary, convergence_path)
        except OSError:
            raise AdapterError(
                "boot_recovery_convergence_rejected", product_mutated=True
            ) from None
        _fsync_directory(convergence_path.parent)
        value = replacement

    if "stop_socket" not in value["steps"]:
        require_deadline()
        _unit_action(
            contract,
            plan,
            unit_role="socket",
            start=False,
            allow_known_selection_drift=True,
        )
        complete("stop_socket")
    if "stop_service" not in value["steps"]:
        require_deadline()
        _unit_action(
            contract,
            plan,
            unit_role="service",
            start=False,
            allow_known_selection_drift=True,
        )
        complete("stop_service")
    if "restore_public" not in value["steps"]:
        require_deadline()
        _restore_public(contract, plan)
        complete("restore_public")
    state_step = "retain_forward_state" if forward else "restore_opaque"
    if state_step not in value["steps"]:
        require_deadline()
        if not forward:
            _restore_opaque(contract, plan)
        complete(state_step)
    if "verify_predecessor" not in value["steps"]:
        require_deadline()
        if not _boot_product_exact(
            contract, plan, final_state="predecessor", allow_active=False
        ):
            raise AdapterError(
                "boot_recovery_convergence_rejected", product_mutated=True
            )
        complete("verify_predecessor")
    return forward


def _install(contract: Mapping[str, object], plan: Mapping[str, object]) -> None:
    execution = plan["execution"]
    staged = incident_root(contract, plan) / "STAGE" / str(plan["target_identity"])
    destination = _fixed(contract, execution, "release_root") / str(plan["target_identity"])
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    _copy_tree_exact(
        staged,
        destination,
        execution["target_inventory"],
        execution["target_directories"],
    )
    _advance(contract, plan, "install", product_mutated=True)


def _select(contract: Mapping[str, object], plan: Mapping[str, object]) -> None:
    execution = plan["execution"]
    # Installation does not modify the predecessor's public selection.  Refuse
    # to overwrite a concurrent public writer between the final pre-stop gate
    # and selection.
    _verify_public(contract, plan, predecessor=True)
    target_public = _target_public_bytes(contract, plan)
    uid = 0 if execution["backend"] == "systemd" else os.getuid()
    gid = 0 if execution["backend"] == "systemd" else os.getgid()
    for role in ("selector", "environment", "service_unit", "socket_unit"):
        _atomic_write(
            _fixed(contract, execution, role),
            target_public[role],
            mode=0o600 if role in {"selector", "environment"} else 0o644,
            uid=uid,
            gid=gid,
            token=str(plan["plan_digest"])[:16],
        )
    _daemon_reload(contract, plan)
    _verify_public(contract, plan, predecessor=False)
    _advance(contract, plan, "select", product_mutated=True)


def _synthetic_continuity(contract: Mapping[str, object], plan: Mapping[str, object]) -> dict[str, object]:
    path = _fixed(contract, plan["execution"], "state_root") / "synthetic-continuity.json"
    value = _read_json(path)
    expected = {"assessment", "reconcile", "schema", "transition"}
    if (
        set(value) != expected
        or value["schema"] != "myuna.p08-activation-synthetic-continuity.v1"
        or value["assessment"] not in {"no_transition_required", "transition_required"}
        or value["transition"] not in {"committed", "ambiguous", "precommit_rejected"}
        or value["reconcile"] not in {"committed", "not_committed", "failed"}
    ):
        raise AdapterError("synthetic_continuity_rejected")
    return value


def _synthetic_control(contract: Mapping[str, object], plan: Mapping[str, object]) -> dict[str, object]:
    path = _fixed(contract, plan["execution"], "state_root") / "synthetic-control.json"
    return _synthetic_control_path(contract, path)


def _synthetic_control_path(
    contract: Mapping[str, object], path: Path
) -> dict[str, object]:
    value = _read_json(path)
    if (
        set(value) != {"acceptance", "fault_kind", "fault_role", "schema"}
        or value["schema"] != "myuna.p08-activation-synthetic-control.v1"
        or value["acceptance"] not in {"accept", "reject"}
        or value["fault_kind"] not in contract_v1.SYNTHETIC_FAULT_KINDS
        or not (value["fault_role"] is None or value["fault_role"] in contract_v1.ROLE_ORDER)
    ):
        raise AdapterError("synthetic_control_rejected")
    return value


def _provider() -> object:
    from p08_forward_continuity_orchestration_v1 import provider_for_state

    return provider_for_state


def _continuity_assessment(contract: Mapping[str, object], plan: Mapping[str, object]) -> str:
    execution = plan["execution"]
    if execution["backend"] == "synthetic":
        state = str(_synthetic_continuity(contract, plan)["assessment"])
    else:
        provider = _provider()(
            _fixed(contract, execution, "state_root"),
            expected_uid=int(execution["opaque_prestate"]["root"]["uid"]),
        )
        assessment = provider.assess_continuity()
        status = getattr(assessment, "status", None)
        if status == "within_policy":
            state = "no_transition_required"
        elif status == "forward_transition_required":
            state = "transition_required"
        else:
            raise AdapterError("continuity_assessment_rejected")
    _advance(contract, plan, "continuity_assessment", continuity_state=state)
    return state


def _continuity_transition(contract: Mapping[str, object], plan: Mapping[str, object]) -> str:
    execution = plan["execution"]
    _advance(contract, plan, "continuity_transition_started", continuity_state="transition_ambiguous")
    if execution["backend"] == "synthetic":
        synthetic = _synthetic_continuity(contract, plan)
        outcome = str(synthetic["transition"])
        if outcome == "precommit_rejected":
            _advance(
                contract,
                plan,
                "continuity_transition_precommit_rejected",
                continuity_state="transition_required",
                product_mutated=False,
                forward_state_possible=False,
            )
            raise AdapterError("continuity_transition_precommit_rejected")
        state = "transition_committed" if outcome == "committed" else "transition_ambiguous"
        if outcome == "committed" or (
            outcome == "ambiguous" and synthetic["reconcile"] == "committed"
        ):
            path = _fixed(contract, execution, "state_root") / "synthetic-forward-history"
            service_account = execution["account_projection"]["service"]
            _atomic_write(
                path,
                b"committed\n",
                mode=0o600,
                uid=int(service_account["uid"]),
                gid=int(service_account["gid"]),
                token=str(plan["plan_digest"])[:16] + "-forward",
            )
        _advance(
            contract,
            plan,
            "continuity_transition",
            continuity_state=state,
            product_mutated=True,
            forward_state_possible=True,
        )
        return state

    # The current Core provider is the source authority.  The protected binding
    # codec remains local-only and is persisted before the first transition write.
    import p08_forward_continuity_orchestration_v1 as continuity
    from myuna_core.trusted_time import ForwardContinuityAuthorization
    from myuna_core.trusted_time.errors import (
        TrustedTimeError,
        TrustedTimeTransitionAmbiguousError,
    )

    provider = continuity.provider_for_state(
        _fixed(contract, execution, "state_root"),
        expected_uid=int(execution["opaque_prestate"]["root"]["uid"]),
    )
    assessment = provider.assess_continuity()
    if getattr(assessment, "status", None) != "forward_transition_required":
        raise AdapterError("continuity_transition_precommit_rejected")
    authorization = ForwardContinuityAuthorization.bind(
        assessment,
        transition_id=str(plan["plan_digest"]),
        source_contract_digest=str(contract["contract_digest"]),
        source_evidence_digest=str(plan["plan_digest"]),
        lineage_digest=str(plan["legacy_lineage_digest"]),
        authorization_identity_digest=contract_v1.digest_value(
            {"contract_digest": contract["contract_digest"], "plan_digest": plan["plan_digest"]}
        ),
        residual_tolerance_microseconds=0,
        max_age_seconds=60,
    )
    protected = continuity._protected_binding(
        assessment,
        authorization,
        plan_digest=str(plan["plan_digest"]),
        strategy_digest=str(contract["contract_digest"]),
    )
    _exclusive_write(
        incident_root(contract, plan) / "CONTINUITY.PRIVATE.json",
        contract_v1.canonical_bytes(protected),
        mode=0o600,
    )
    try:
        receipt = provider.transition_forward(assessment, authorization)
    except TrustedTimeTransitionAmbiguousError:
        _advance(
            contract,
            plan,
            "continuity_transition",
            continuity_state="transition_ambiguous",
            product_mutated=True,
            forward_state_possible=True,
        )
        return "transition_ambiguous"
    except TrustedTimeError:
        _advance(
            contract,
            plan,
            "continuity_transition_precommit_rejected",
            continuity_state="transition_required",
            product_mutated=False,
            forward_state_possible=False,
        )
        raise AdapterError("continuity_transition_precommit_rejected") from None
    except Exception:
        raise AdapterError("continuity_transition_indeterminate", forward_state_possible=True) from None
    if getattr(receipt, "status", None) != "committed":
        raise AdapterError("continuity_transition_indeterminate", forward_state_possible=True)
    _advance(
        contract,
        plan,
        "continuity_transition",
        continuity_state="transition_committed",
        product_mutated=True,
        forward_state_possible=True,
    )
    return "transition_committed"


def _continuity_reconcile(contract: Mapping[str, object], plan: Mapping[str, object]) -> str:
    execution = plan["execution"]
    if execution["backend"] == "synthetic":
        outcome = str(_synthetic_continuity(contract, plan)["reconcile"])
        if outcome == "failed":
            raise AdapterError("continuity_reconcile_rejected", forward_state_possible=True)
        state = "reconciled_committed" if outcome == "committed" else "reconciled_not_committed"
        _advance(
            contract,
            plan,
            "continuity_reconcile",
            continuity_state=state,
            product_mutated=True,
            forward_state_possible=True,
        )
        return state
    import p08_forward_continuity_orchestration_v1 as continuity

    protected = _read_json(incident_root(contract, plan) / "CONTINUITY.PRIVATE.json")
    assessment, authorization = continuity.restore_protected_binding(
        protected,
        plan_digest=str(plan["plan_digest"]),
        strategy_digest=str(contract["contract_digest"]),
    )
    provider = continuity.provider_for_state(
        _fixed(contract, execution, "state_root"),
        expected_uid=int(execution["opaque_prestate"]["root"]["uid"]),
    )
    try:
        reconciled = provider.reconcile_forward_transition(assessment, authorization)
    except Exception:
        raise AdapterError("continuity_reconcile_rejected", forward_state_possible=True) from None
    if getattr(reconciled, "status", None) == "committed":
        state = "reconciled_committed"
    elif getattr(reconciled, "status", None) == "not_committed":
        state = "reconciled_not_committed"
    else:
        raise AdapterError("continuity_reconcile_rejected", forward_state_possible=True)
    _advance(
        contract,
        plan,
        "continuity_reconcile",
        continuity_state=state,
        product_mutated=True,
        forward_state_possible=True,
    )
    return state


def _synthetic_socket_ingress(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    opened: bool,
) -> None:
    state = _unit_state(contract, plan)
    if opened:
        state["socket_n_accepted"] = int(state["socket_n_accepted"]) + 1
        state["socket_n_connections"] = int(state["socket_n_connections"]) + 1
    else:
        if state["socket_n_connections"] < 1:
            raise AdapterError("socket_ingress_projection_rejected", product_mutated=True)
        state["socket_n_connections"] = int(state["socket_n_connections"]) - 1
    _write_unit_state(contract, plan, state)


def _verify_completed_socket_ingress(
    before: Mapping[str, object], after: Mapping[str, object]
) -> None:
    try:
        contract_v1._unit_state(after)
    except contract_v1.ContractError:
        raise AdapterError("socket_ingress_projection_rejected", product_mutated=True) from None
    stable_keys = {
        "coupled_state",
        "effective",
        "schema",
        "service_active",
        "service_active_enter_monotonic_usec",
        "service_enabled",
        "service_main_pid",
        "service_process",
        "service_restarts",
        "socket_active",
        "socket_active_enter_monotonic_usec",
        "socket_enabled",
    }
    if (
        any(before[key] != after[key] for key in stable_keys)
        or before["socket_n_connections"] != 0
        or after["socket_n_connections"] != 0
        or after["socket_n_accepted"] != before["socket_n_accepted"] + 1
    ):
        raise AdapterError("socket_ingress_projection_rejected", product_mutated=True)


def _accepted_receipt(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> dict[str, object]:
    value = _read_json(incident_root(contract, plan) / "ACCEPTANCE.ACCEPTED.json")
    expected_keys = {
        "acceptance_count",
        "plan_digest",
        "projection",
        "raw_output_included",
        "receipt_digest",
        "schema",
        "socket_ingress_completed",
        "status",
        "unit_after",
        "unit_before",
    }
    body = {key: item for key, item in value.items() if key != "receipt_digest"}
    try:
        before = contract_v1._unit_state(value.get("unit_before"))
        after = contract_v1._unit_state(value.get("unit_after"))
    except contract_v1.ContractError:
        raise AdapterError("acceptance_receipt_rejected") from None
    from p08_temporal_gateway_v1 import parse_content_free_status_projection

    try:
        status = parse_content_free_status_projection(
            value.get("projection"),
            expected_scope_digest=str(plan["execution"]["acceptance_scope_digest"]),
        )
    except Exception:
        raise AdapterError("acceptance_receipt_rejected") from None
    _verify_completed_socket_ingress(before, after)
    if (
        set(value) != expected_keys
        or value["schema"] != ACCEPTANCE_RECEIPT_SCHEMA
        or value["plan_digest"] != plan["plan_digest"]
        or value["status"] != "accepted"
        or value["acceptance_count"] != 1
        or value["socket_ingress_completed"] is not True
        or value["raw_output_included"] is not False
        or status.request_nonce != plan["invocation_nonce"]
        or value["unit_before"] != before
        or value["unit_after"] != after
        or value["receipt_digest"] != contract_v1.digest_value(body)
    ):
        raise AdapterError("acceptance_receipt_rejected")
    return value


def _accept(contract: Mapping[str, object], plan: Mapping[str, object]) -> None:
    execution = plan["execution"]
    fixed = contract["production_adapter"]
    entrypoint = fixed["acceptance_entrypoints"][execution["backend"]]
    installed = _fixed(contract, execution, "release_root") / str(plan["target_identity"])
    helper = installed / str(entrypoint)
    helper_relative = Path(str(entrypoint))
    if (
        helper_relative.parent.as_posix() != "scripts"
        or helper_relative.suffix != ".py"
        or not helper_relative.stem.isidentifier()
    ):
        raise AdapterError("acceptance_helper_rejected", product_mutated=True)
    expected = [row for row in execution["target_inventory"] if row["path"] == entrypoint]
    helper_details = _regular(helper)
    interpreter = Path(str(contract["interpreter"]["invocation_path"]))
    if (
        len(expected) != 1
        or _digest(helper) != expected[0]["sha256"]
        or stat.S_IMODE(helper_details.st_mode) != expected[0]["mode"]
        or helper_details.st_uid != os.getuid()
        or helper_details.st_gid != os.getgid()
    ):
        raise AdapterError("acceptance_helper_rejected", product_mutated=True)
    try:
        launcher_v1._verify_interpreter(contract["interpreter"])
        launcher_v1._verify_runtime_package(contract, plan)
    except launcher_v1.LauncherError:
        raise AdapterError("acceptance_helper_rejected", product_mutated=True) from None
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": os.pathsep.join(
            (
                str(installed / "scripts"),
                str(installed / "src"),
            )
        ),
        "MYUNA_P08_STATUS_INVOCATION_NONCE": str(plan["invocation_nonce"]),
    }
    if execution["backend"] == "synthetic":
        environment["MYUNA_P08_SYNTHETIC_SCOPE_DIGEST"] = str(execution["acceptance_scope_digest"])
        environment["MYUNA_P08_SYNTHETIC_ROOT"] = str(execution["root"])
    unit_before = _unit_state(contract, plan)
    target_units = _unit_receipt(contract, plan, label="target", create=False)[
        "state"
    ]
    if unit_before != target_units:
        raise AdapterError("acceptance_unit_prestate_rejected", product_mutated=True)
    synthetic_ingress = execution["backend"] == "synthetic"
    if synthetic_ingress:
        _synthetic_socket_ingress(contract, plan, opened=True)
    try:
        completed = subprocess.run(
            [
                str(interpreter),
                "-B",
                "-P",
                "-S",
                "-m",
                helper_relative.stem,
                "--content-free-status",
            ],
            cwd=str(installed),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
    finally:
        if synthetic_ingress:
            _synthetic_socket_ingress(contract, plan, opened=False)
    unit_after = _unit_state(contract, plan)
    _verify_completed_socket_ingress(unit_before, unit_after)
    if (
        completed.stderr
        or not completed.stdout.endswith(b"\n")
        or len(completed.stdout) > MAX_JSON_BYTES
    ):
        raise AdapterError("protocol_acceptance_rejected", product_mutated=True)
    if completed.returncode != 0:
        from p08_temporal_gateway_v1 import (
            parse_content_free_status_rejection_bytes,
        )

        try:
            rejection = parse_content_free_status_rejection_bytes(
                completed.stdout,
                expected_invocation_nonce=str(plan["invocation_nonce"]),
            )
        except ValueError:
            raise AdapterError(
                "protocol_acceptance_rejected", product_mutated=True
            ) from None
        body = {
            "schema": ACCEPTANCE_RECEIPT_SCHEMA,
            "plan_digest": plan["plan_digest"],
            "status": "rejected",
            "projection": rejection.projection(),
            "raw_output_included": False,
        }
        receipt = {**body, "receipt_digest": contract_v1.digest_value(body)}
        _exclusive_write(
            incident_root(contract, plan) / "ACCEPTANCE.REJECTION.json",
            contract_v1.canonical_bytes(receipt),
            mode=0o600,
        )
        raise AdapterError("protocol_acceptance_rejected", product_mutated=True)
    try:
        projection = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AdapterError("protocol_acceptance_rejected", product_mutated=True) from None
    if completed.stdout != contract_v1.canonical_bytes(projection):
        raise AdapterError("protocol_acceptance_rejected", product_mutated=True)
    from p08_temporal_gateway_v1 import parse_content_free_status_projection

    try:
        status = parse_content_free_status_projection(
            projection,
            expected_scope_digest=str(execution["acceptance_scope_digest"]),
        )
    except Exception:
        raise AdapterError("protocol_acceptance_rejected", product_mutated=True) from None
    if status.request_nonce != plan["invocation_nonce"]:
        raise AdapterError("protocol_acceptance_nonce_rejected", product_mutated=True)
    body = {
        "schema": ACCEPTANCE_RECEIPT_SCHEMA,
        "plan_digest": plan["plan_digest"],
        "status": "accepted",
        "projection": projection,
        "acceptance_count": 1,
        "socket_ingress_completed": True,
        "unit_before": unit_before,
        "unit_after": unit_after,
        "raw_output_included": False,
    }
    receipt = {**body, "receipt_digest": contract_v1.digest_value(body)}
    _exclusive_write(
        incident_root(contract, plan) / "ACCEPTANCE.ACCEPTED.json",
        contract_v1.canonical_bytes(receipt),
        mode=0o600,
    )
    _accepted_receipt(contract, plan)
    _advance(contract, plan, "accept_status", product_mutated=True)


def _restore_public(contract: Mapping[str, object], plan: Mapping[str, object]) -> None:
    execution = plan["execution"]
    backup = incident_root(contract, plan) / "BACKUP" / "public"
    for role in contract_v1.PUBLIC_ROLES:
        row = execution["public_prestate"][role]
        raw = _read_regular_bytes(backup / role)
        if _digest_bytes(raw) != row["sha256"]:
            raise AdapterError("public_backup_rejected", product_mutated=True)
        _atomic_write(
            _fixed(contract, execution, role),
            raw,
            mode=int(row["mode"]),
            uid=int(row["uid"]),
            gid=int(row["gid"]),
            token=str(plan["plan_digest"])[:16] + "-restore",
        )
    _daemon_reload(contract, plan)


def _restore_opaque(contract: Mapping[str, object], plan: Mapping[str, object]) -> None:
    execution = plan["execution"]
    manifest = _verify_backup(contract, plan, source_must_match=False)
    state_root = _fixed(contract, execution, "state_root")
    backup_root = incident_root(contract, plan) / "BACKUP" / "opaque-state"
    rows = manifest["rows"]
    for expected, row in zip(execution["opaque_prestate"]["entries"], rows, strict=True):
        source = backup_root / str(expected["path"])
        destination = state_root / str(expected["path"])
        raw = _read_regular_bytes(source, maximum=MAX_STATE_FILE_BYTES)
        if _digest_bytes(raw) != row["sha256"]:
            raise AdapterError("opaque_backup_rejected", product_mutated=True)
        _atomic_write(
            destination,
            raw,
            mode=int(expected["mode"]),
            uid=int(expected["uid"]),
            gid=int(expected["gid"]),
            token=str(plan["plan_digest"])[:16] + "-state",
        )


def _forward_state_possible(contract: Mapping[str, object], plan: Mapping[str, object]) -> bool:
    state = _load_journal(contract, plan)["continuity_state"]
    return state in {"transition_ambiguous", "transition_committed", "reconciled_committed"}


def _converge(contract: Mapping[str, object], plan: Mapping[str, object]) -> bool:
    _unit_action(
        contract,
        plan,
        unit_role="socket",
        start=False,
        allow_known_selection_drift=True,
    )
    _unit_action(
        contract,
        plan,
        unit_role="service",
        start=False,
        allow_known_selection_drift=True,
    )
    forward = _forward_state_possible(contract, plan)
    _restore_public(contract, plan)
    if not forward:
        _restore_opaque(contract, plan)
    _unit_action(contract, plan, unit_role="service", start=True)
    _unit_action(contract, plan, unit_role="socket", start=True)
    _unit_receipt(contract, plan, label="predecessor", create=True)
    _advance(
        contract,
        plan,
        "converge",
        product_mutated=True,
        forward_state_possible=forward,
    )
    return forward


def _recover(contract: Mapping[str, object], plan: Mapping[str, object]) -> None:
    _verify_public(contract, plan, predecessor=True)
    _verify_opaque_metadata(contract, plan, exact_size=not _forward_state_possible(contract, plan))
    units = _unit_state(contract, plan)
    expected_units = _unit_receipt(
        contract, plan, label="predecessor", create=False
    )["state"]
    if units != expected_units:
        raise AdapterError("recover_units_rejected", product_mutated=True, forward_state_possible=_forward_state_possible(contract, plan))
    _advance(
        contract,
        plan,
        "recover",
        product_mutated=True,
        forward_state_possible=_forward_state_possible(contract, plan),
    )


def _postflight(contract: Mapping[str, object], plan: Mapping[str, object]) -> bool:
    journal = _load_journal(contract, plan)
    converged = "converge" in journal["events"]
    _verify_public(contract, plan, predecessor=converged)
    _verify_opaque_metadata(contract, plan, exact_size=converged and not _forward_state_possible(contract, plan))
    units = _unit_state(contract, plan)
    if converged:
        expected_units = _unit_receipt(
            contract, plan, label="predecessor", create=False
        )["state"]
        if units != expected_units:
            raise AdapterError(
                "postflight_units_rejected",
                product_mutated=True,
                forward_state_possible=_forward_state_possible(contract, plan),
            )
    else:
        target_units = _unit_receipt(contract, plan, label="target", create=False)[
            "state"
        ]
        acceptance = _accepted_receipt(contract, plan)
        if (
            acceptance["unit_before"] != target_units
            or units != acceptance["unit_after"]
        ):
            raise AdapterError(
                "postflight_units_rejected",
                product_mutated=True,
                forward_state_possible=_forward_state_possible(contract, plan),
            )
        destination = _fixed(contract, plan["execution"], "release_root") / str(plan["target_identity"])
        observed = target_inventory(destination)
        expected = [{**dict(row), "uid": os.getuid(), "gid": os.getgid()} for row in plan["execution"]["target_inventory"]]
        if observed != expected:
            raise AdapterError("postflight_install_rejected", product_mutated=True, forward_state_possible=_forward_state_possible(contract, plan))
        observed_directories = target_directory_inventory(
            destination,
            file_inventory=observed,
        )
        expected_directories = [
            {**dict(row), "uid": os.getuid(), "gid": os.getgid()}
            for row in plan["execution"]["target_directories"]
        ]
        if observed_directories != expected_directories:
            raise AdapterError("postflight_install_rejected", product_mutated=True, forward_state_possible=_forward_state_possible(contract, plan))
    _advance(
        contract,
        plan,
        "convergence_postflight" if converged else "postflight",
        product_mutated=not converged,
        forward_state_possible=_forward_state_possible(contract, plan),
    )
    return converged


def _exact_two(contract: Mapping[str, object], plan: Mapping[str, object]) -> None:
    captures = []
    for role in ("formal1", "formal2"):
        path = sequence_root(contract, plan) / f"{role}-1.json"
        capture = launcher_v1.validate_capture(
            contract,
            plan,
            _read_json(path),
            expected_role=role,
            expected_call=1,
        )
        if capture["canonical_status"] != "ready" or capture["canonical_result"] is None:
            raise AdapterError("formal_capture_rejected")
        captures.append(capture)
    projections = [
        {
            "status": value["canonical_result"]["status"],
            "result_class": value["canonical_result"]["result_class"],
            "persistent_mutation": value["canonical_result"]["persistent_mutation"],
            "payload": value["canonical_result"]["payload"],
        }
        for value in captures
    ]
    if contract_v1.canonical_bytes(projections[0]) != contract_v1.canonical_bytes(projections[1]):
        raise AdapterError("formal_projection_mismatch")


def _payload(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    role: str,
    *,
    progress: _ProgressEmitter | None = None,
) -> tuple[dict[str, object], bool]:
    infrastructure_convergence = (
        role in {"converge", "recover", "postflight"}
        and _infrastructure_only_convergence_required(contract, plan)
    )
    if (
        role in _recovery_contract(contract)["hazardous_roles_after_arm"]
        and not infrastructure_convergence
    ):
        _verify_recovery_arm(
            contract,
            plan,
            # A selector/environment/unit drift discovered after mutation is
            # exactly why the bounded convergence role exists.  The ARM,
            # backup, claim and persistent recovery artifacts remain exact;
            # only this pre-restore live projection may be non-authoritative.
            allow_known_selection_drift=role == "converge",
        )
    if (
        plan["execution"]["backend"] == "synthetic"
        and role not in contract_v1.READINESS_ROLES
        and role != "claim"
    ):
        control = _synthetic_control(contract, plan)
        if (
            control["fault_role"] == role
            and control["fault_kind"] in {"rejected", "indeterminate"}
        ):
            forward = role in {"continuity_transition", "continuity_reconcile"}
            mutated = role in {
                "stop_service",
                "install",
                "select",
                "start_service",
                "start_socket",
                "accept_status",
                "converge",
                "recover",
                "postflight",
            }
            raise AdapterError(
                "synthetic_phase_fault",
                infrastructure_mutated=(
                    role == "stop_socket"
                    and _infrastructure_only_convergence_required(contract, plan)
                ),
                product_mutated=mutated,
                forward_state_possible=forward,
            )
        if (
            role == "converge"
            and control["fault_kind"]
            == "outer_kill_after_mutation_recovery_rejected"
        ):
            raise AdapterError(
                "synthetic_recovery_fault",
                product_mutated=True,
            )
    if role == "construct":
        _readiness(contract, plan)
        return {"contract_verified": True}, False
    if role in {"prepare", "formal1", "formal2"}:
        _readiness(contract, plan, role=role, progress=progress)
        return {"metadata_only": True, "opaque_content_read": False, "persistent_mutation": False}, False
    if role == "exact_two":
        _exact_two(contract, plan)
        return {"formal_calls": 2, "byte_identical": True, "semantic_identical": True}, False
    if role == "drift":
        _readiness(contract, plan)
        return {"exact": True, "persistent_mutation": False}, False
    if role == "claim":
        _claim(contract, plan)
        return {"incident_owned": True, "max_actions": 1}, False
    if role == "backup":
        _backup(contract, plan)
        return {"action_owned": True, "public_exact": True, "opaque_exact": True}, False
    if role == "stage":
        _stage(contract, plan)
        return {"inventory_exact": True, "non_overwriting": True}, False
    if role == "recovery_install":
        _recovery_install(contract, plan)
        return {
            "runtime_exact": True,
            "unit_exact": True,
            "enablement_exact": True,
            "ordering_exact": True,
            "product_gate_exact": True,
        }, True
    if role == "recovery_arm":
        _recovery_arm(contract, plan)
        return {
            "arm_exact": True,
            "action_backup_bound": True,
            "hazardous_mutation_started": False,
        }, True
    if role == "stop_socket":
        _verify_backup(contract, plan, source_must_match=True)
        _advance(contract, plan, "stop_socket_started")
        _unit_action(contract, plan, unit_role="socket", start=False)
        coupled = _unit_state(contract, plan)
        if coupled["socket_active"] or coupled["service_active"]:
            raise AdapterError("unit_dependency_rejected", product_mutated=True)
        _advance(contract, plan, "stop_socket", product_mutated=True)
        return {"socket_stopped": True, "service_cascade_stopped": True}, True
    if role == "stop_service":
        if _unit_state(contract, plan)["socket_active"] is not False:
            raise AdapterError("stop_order_rejected", product_mutated=True)
        _unit_action(contract, plan, unit_role="service", start=False)
        _advance(contract, plan, "stop_service", product_mutated=True)
        return {"service_stopped": True, "dependency_state_exact": True}, True
    if role == "install":
        _install(contract, plan)
        return {"installed_inventory_exact": True}, True
    if role == "select":
        _select(contract, plan)
        return {"selector_exact": True, "environment_exact": True, "units_exact": True}, True
    if role == "continuity_assessment":
        state = _continuity_assessment(contract, plan)
        return {"continuity_state": state, "transition_required": state == "transition_required", "provider_state_effect": "none"}, False
    if role == "continuity_transition":
        state = _continuity_transition(contract, plan)
        return {"continuity_state": state, "forward_state_possible": True, "provider_state_effect": "committed" if state == "transition_committed" else "ambiguous"}, state == "transition_committed"
    if role == "continuity_reconcile":
        state = _continuity_reconcile(contract, plan)
        committed = state == "reconciled_committed"
        return {"continuity_state": state, "forward_state_possible": committed, "provider_state_effect": "committed" if committed else "not_committed"}, False
    if role == "start_service":
        _unit_action(contract, plan, unit_role="service", start=True)
        coupled = _unit_state(contract, plan)
        if not coupled["service_active"] or not coupled["socket_active"]:
            raise AdapterError("unit_dependency_rejected", product_mutated=True)
        _advance(
            contract,
            plan,
            "start_service",
            product_mutated=True,
            forward_state_possible=_forward_state_possible(contract, plan),
        )
        return {"service_started": True, "socket_dependency_started": True}, True
    if role == "start_socket":
        if _unit_state(contract, plan)["service_active"] is not True:
            raise AdapterError("start_order_rejected", product_mutated=True, forward_state_possible=_forward_state_possible(contract, plan))
        _unit_action(contract, plan, unit_role="socket", start=True)
        _unit_receipt(contract, plan, label="target", create=True)
        _advance(
            contract,
            plan,
            "start_socket",
            product_mutated=True,
            forward_state_possible=_forward_state_possible(contract, plan),
        )
        return {"socket_started": True, "dependency_state_exact": True}, True
    if role == "accept_status":
        _accept(contract, plan)
        return {"accepted": True, "nonce_echo_exact": True, "source_bound": True}, False
    if role == "converge":
        if infrastructure_convergence:
            _converge_recovery_infrastructure(contract, plan)
            return {
                "code_public_predecessor": True,
                "trusted_time_history_restored": False,
                "state_restore_scope": "recovery_infrastructure_only",
            }, True
        forward = _converge(contract, plan)
        return {"code_public_predecessor": True, "trusted_time_history_restored": False, "state_restore_scope": "code_public_only" if forward else "p08_state_and_public"}, True
    if role == "recover":
        if infrastructure_convergence:
            _recover_recovery_infrastructure(contract, plan)
            return {"converged": True, "orphan_count": 0}, True
        _recover(contract, plan)
        return {"converged": True, "orphan_count": 0}, True
    if role == "postflight":
        if infrastructure_convergence:
            _postflight_recovery_infrastructure(contract, plan)
            return {
                "selected_identity": plan["predecessor_identity"],
                "stable": True,
                "state_preserved": True,
            }, False
        converged = _postflight(contract, plan)
        return {"selected_identity": plan["predecessor_identity"] if converged else plan["target_identity"], "stable": True, "state_preserved": True}, False
    raise AdapterError("activation_role_rejected")


def _failure_payload(contract: Mapping[str, object], role: str, *, forward_state_possible: bool) -> dict[str, object]:
    payload = {key: False for key in contract["roles"][role]["payload_keys"]}
    if role in {"continuity_transition", "continuity_reconcile"}:
        payload.update(
            {
                "continuity_state": "transition_ambiguous" if forward_state_possible else "transition_required",
                "forward_state_possible": forward_state_possible,
                "provider_state_effect": "ambiguous" if forward_state_possible else "none",
            }
        )
    return payload


def build_role_result(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    role: str,
    call_index: int,
    progress: _ProgressEmitter | None = None,
) -> dict[str, object]:
    validated_contract = contract_v1.validate_contract(contract)
    validated_plan = contract_v1.validate_plan(validated_contract, plan)
    try:
        payload, mutation = _payload(
            validated_contract,
            validated_plan,
            role,
            progress=progress,
        )
    except AdapterError as error:
        durable_infrastructure = role in {"recovery_install", "recovery_arm"} and (
            _recovery_obligation_path(validated_contract, validated_plan).exists()
            or _recovery_obligation_path(
                validated_contract, validated_plan
            ).is_symlink()
        )
        infrastructure_mutated = error.infrastructure_mutated or durable_infrastructure
        if infrastructure_mutated and error.product_mutated:
            mutation_scope = "recovery_infrastructure_and_product"
        elif infrastructure_mutated:
            mutation_scope = "recovery_infrastructure"
        elif error.product_mutated:
            mutation_scope = "product"
        else:
            mutation_scope = "none"
        return contract_v1.build_result(
            validated_contract,
            validated_plan,
            role=role,
            role_call=call_index,
            status="rejected",
            result_class="rejected",
            payload=_failure_payload(
                validated_contract,
                role,
                forward_state_possible=error.forward_state_possible,
            ),
            persistent_mutation=(
                error.product_mutated or infrastructure_mutated
            ),
            mutation_scope=mutation_scope,
        )
    except Exception:
        # Unexpected role failures remain raw-free and indeterminate.  Once a
        # role can overlap product mutation, the projection is deliberately
        # conservative so the engine can only converge, never continue.
        forward = role in {"continuity_transition", "continuity_reconcile"}
        infrastructure = role in {"recovery_install", "recovery_arm"} and (
            _recovery_obligation_path(validated_contract, validated_plan).exists()
            or _recovery_obligation_path(
                validated_contract, validated_plan
            ).is_symlink()
        )
        product = (
            not infrastructure
            and contract_v1.failure_can_converge(validated_contract, role)
        )
        return contract_v1.build_result(
            validated_contract,
            validated_plan,
            role=role,
            role_call=call_index,
            status="indeterminate",
            result_class="indeterminate",
            payload=_failure_payload(
                validated_contract,
                role,
                forward_state_possible=forward,
            ),
            persistent_mutation=infrastructure or product,
            mutation_scope=(
                "recovery_infrastructure"
                if infrastructure
                else "product"
                if product
                else "none"
            ),
        )
    mutation_scope = (
        "recovery_infrastructure"
        if mutation and role in {"recovery_install", "recovery_arm"}
        else "recovery_infrastructure"
        if mutation
        and role in {"converge", "recover"}
        and _infrastructure_only_convergence_required(
            validated_contract, validated_plan
        )
        else "product"
        if mutation
        else "none"
    )
    return contract_v1.build_result(
        validated_contract,
        validated_plan,
        role=role,
        role_call=call_index,
        status="ready" if role in contract_v1.READINESS_ROLES else "success",
        result_class=str(validated_contract["roles"][role]["success_result_class"]),
        payload=payload,
        persistent_mutation=mutation,
        mutation_scope=mutation_scope,
    )


def _load_bound(path: Path, *, maximum: int = MAX_JSON_BYTES) -> dict[str, object]:
    return _read_json(path, maximum=maximum)


def main(argv: Sequence[str] | None = None) -> int:
    parser = CanonicalArgumentParser(allow_abbrev=False)
    parser.add_argument("--activation-contract", type=Path, required=True)
    parser.add_argument("--activation-plan", type=Path, required=True)
    parser.add_argument("--activation-role", required=True)
    parser.add_argument("--activation-call-index", type=int, required=True)
    try:
        values = parser.parse_args(argv)
        contract = contract_v1.validate_contract(_load_bound(values.activation_contract))
        plan = contract_v1.validate_plan(contract, _load_bound(values.activation_plan))
        launcher_v1.verify_loaded_runtime_modules(
            contract,
            plan,
            {
                "scripts/p08_activation_contract_v1.py": contract_v1,
                "scripts/p08_activation_launcher_v1.py": launcher_v1,
                "scripts/p08_activation_production_adapter_v1.py": sys.modules[__name__],
            },
        )
        role = values.activation_role
        call_index = values.activation_call_index
        if role not in contract["roles"] or call_index < 1 or call_index > contract["roles"][role]["call_budget"]:
            raise AdapterError("activation_invocation_rejected")
        progress = _ProgressEmitter(contract, plan, role)
        progress.emit("startup")
        progress.emit("source_lineage")
        if role not in {"prepare", "formal1", "formal2"}:
            progress.emit("inputs")
        result = build_role_result(
            contract,
            plan,
            role=role,
            call_index=call_index,
            progress=progress,
        )
        if result["status"] in {"ready", "success"}:
            if role not in {"prepare", "formal1", "formal2"}:
                progress.emit("execute")
            progress.emit("canonical_serialization")
            if not progress.complete:
                raise AdapterError("progress_incomplete")
    except Exception:
        # Before a valid contract and plan exist there is no safe schema-bound
        # stdout projection.  The source-owned launcher classifies this as an
        # indeterminate capture without exposing the exception or stderr.
        return 1
    sys.stdout.buffer.write(contract_v1.canonical_bytes(result))
    return 0 if result["status"] in {"ready", "success"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
