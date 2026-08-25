#!/usr/bin/env python3
"""Activate the bounded Owner Profile writer with exact rollback snapshots."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import tempfile
import time
from typing import Callable, Mapping, Sequence

from install_owner_profile_service_identity_v1 import validate_service_identity
from install_owner_profile_write_code_v1 import (
    OwnerProfileCodeInstallError,
    validate_installed_code_release,
)
from owner_profile_write_environment_v1 import (
    OwnerProfileWriteTarget,
    parse_environment,
    render_environment,
)
from prepare_owner_profile_write_state_v1 import (
    LEGACY_PROFILE_RELEASE_ROOT,
    WRITE_ROOT,
    prepare_write_state,
    restore_write_state_root,
)


CORE_SERVICE = "myuna-core@qq.service"
READ_SERVICE = "myuna-owner-profile-read-v1.service"
READ_SOCKET = "myuna-owner-profile-read-v1.socket"
WRITER_SERVICE = "myuna-owner-profile-write-v1.service"
WRITER_SOCKET = "myuna-owner-profile-write-v1.socket"
LOCAL_PROVIDER_SERVICE = "myuna-local-provider-v1.service"
LIVE_CONFIRMATION = "I_UNDERSTAND_P07C_WILL_RESTART_MYUNA_CORE_AND_PROFILE_READ"
DEPLOY_ROOT = Path("/srv/myuna/repos/deploy")
CORE_RELEASE_ROOT = Path("/srv/myuna/releases/core")
CONTROL_ROOT = Path("/var/lib/myuna-owner-profile-write-control-v1")
BACKUP_ROOT = CONTROL_ROOT / "backups"
JOURNAL_PATH = CONTROL_ROOT / "PENDING.json"
RECEIPT_ROOT = CONTROL_ROOT / "receipts"
CORE_ENV_SOURCE = Path("config/telegram-owner-p07c-local-profile-write-v1.env")
READ_PROFILE_SOURCE = Path("config/capabilities/owner-private-profile-read-v1.json")
WRITE_PROFILE_SOURCE = Path("config/capabilities/owner-private-profile-write-v1.json")
MANIFEST_SOURCE = Path(
    "config/capabilities/telegram-owner-v6-p07c-local-profile-write-v1.json"
)
ACTIVATION_SOURCE = Path("scripts/activate_owner_profile_write_v1.py")
ENVIRONMENT_SOURCE = Path("scripts/owner_profile_write_environment_v1.py")
PREPARE_SOURCE = Path("scripts/prepare_owner_profile_write_state_v1.py")
IDENTITY_SOURCE = Path("scripts/install_owner_profile_service_identity_v1.py")
WRITE_CODE_INSTALLER_SOURCE = Path(
    "scripts/install_owner_profile_write_code_v1.py"
)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
CONFIG_MODE = 0o644
PRIVATE_MODE = 0o600
WRITER_READ_MODE = 0o440
PRIVATE_DIRECTORY_MODE = 0o700
SERVICE_READ_DIRECTORY_MODE = 0o750
WRITER_CAPABILITY_KEY = "writer_capability_profile"


class OwnerProfileWriteActivationError(RuntimeError):
    """A deterministic content-free activation rejection."""


def _reject(code: str) -> OwnerProfileWriteActivationError:
    return OwnerProfileWriteActivationError(code)


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


@dataclass(frozen=True, slots=True)
class ActivationPaths:
    deploy_root: Path = DEPLOY_ROOT
    core_release_root: Path = CORE_RELEASE_ROOT
    writer_code_root: Path = Path(
        "/opt/myuna/owner-profile-write-v1/releases"
    )
    writer_environment: Path = Path(
        "/etc/myuna-owner-profile-write-v1/writer.env"
    )
    writer_capability_profile: Path = Path(
        "/opt/myuna/owner-profile-write-v1/capability/"
        "owner-private-profile-write-v1.json"
    )
    writer_service: Path = Path("/etc/systemd/system") / WRITER_SERVICE
    writer_socket: Path = Path("/etc/systemd/system") / WRITER_SOCKET
    writer_tmpfiles: Path = Path(
        "/etc/tmpfiles.d/myuna-owner-profile-write-v1.conf"
    )
    read_profile: Path = Path(
        "/etc/myuna/capabilities/owner-private-profile-read-v1.json"
    )
    write_profile: Path = Path(
        "/etc/myuna/capabilities/owner-private-profile-write-v1.json"
    )
    capability_manifest: Path = Path(
        "/etc/myuna/capabilities/telegram-owner-v6-p07c-local-profile-write-v1.json"
    )
    core_environment: Path = Path("/etc/myuna/p07c-local-profile-write-v1.env")
    core_dropin: Path = Path(
        "/etc/systemd/system/myuna-core@qq.service.d/"
        "zzzzzzzz-p07c-profile-write-v1.conf"
    )
    control_root: Path = CONTROL_ROOT
    backup_root: Path = BACKUP_ROOT
    journal: Path = JOURNAL_PATH
    receipt_root: Path = RECEIPT_ROOT
    write_root: Path = WRITE_ROOT


@dataclass(frozen=True, slots=True)
class FileSnapshot:
    existed: bool
    payload: bytes | None
    mode: int | None
    uid: int | None
    gid: int | None


@dataclass(frozen=True, slots=True)
class ServiceSnapshot:
    writer_socket_active: bool
    writer_socket_enabled: bool
    writer_service_active: bool


def render_core_dropin() -> bytes:
    return (
        "[Unit]\n"
        "Wants=myuna-local-provider-v1.service "
        "myuna-owner-profile-read-v1.socket "
        "myuna-owner-profile-write-v1.socket\n"
        "After=myuna-local-provider-v1.service "
        "myuna-owner-profile-read-v1.socket "
        "myuna-owner-profile-write-v1.socket\n\n"
        "[Service]\n"
        "EnvironmentFile=/etc/myuna/p07c-local-profile-write-v1.env\n"
    ).encode("ascii")


def _read_regular(path: Path, *, maximum: int = 256_000) -> bytes:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as exc:
        raise _reject("activation_source_unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or not payload
        or len(payload) != metadata.st_size
        or len(payload) > maximum
    ):
        raise _reject("activation_source_rejected")
    return payload


def _load_json(payload: bytes, *, code: str) -> dict[str, object]:
    try:
        result = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _reject(code) from exc
    if not isinstance(result, dict):
        raise _reject(code)
    return result


def _validate_core_environment(payload: bytes) -> None:
    try:
        lines = payload.decode("ascii").splitlines()
        values = dict(line.split("=", 1) for line in lines)
    except (UnicodeError, ValueError) as exc:
        raise _reject("activation_core_environment_rejected") from exc
    if (
        len(values) != len(lines)
        or values.get("MYUNA_PROVIDERS_ENABLED") != "local"
        or values.get("MYUNA_OWNER_PROFILE_READ_ENABLED") != "true"
        or values.get("MYUNA_OWNER_PROFILE_WRITE_ENABLED") != "true"
        or values.get("MYUNA_OWNER_MEMORY_READ_ENABLED") != "false"
        or values.get("MYUNA_OWNER_PROFILE_CAPABILITY_PROFILE")
        != "/etc/myuna/capabilities/owner-private-profile-read-v1.json"
        or values.get("MYUNA_OWNER_PROFILE_WRITE_WORKER_SOCKET")
        != "/run/myuna-owner-profile-write-v1/profile-write.sock"
        or any("deepseek" in value.casefold() for value in values.values())
    ):
        raise _reject("activation_core_environment_rejected")


def candidate_files(
    target: OwnerProfileWriteTarget,
    *,
    paths: ActivationPaths = ActivationPaths(),
) -> dict[str, tuple[Path, bytes, int]]:
    core_release = paths.core_release_root / target.core_release_sha256
    release = paths.writer_code_root / target.write_code_release_sha256
    if (
        core_release.name != target.core_release_sha256
        or core_release.is_symlink()
        or not core_release.is_dir()
        or release.name != target.write_code_release_sha256
        or release.is_symlink()
        or not release.is_dir()
    ):
        raise _reject("activation_core_release_rejected")
    environment = render_environment(target)
    if parse_environment(environment) != target:
        raise _reject("activation_writer_environment_rejected")
    service = _read_regular(release / "deploy" / WRITER_SERVICE)
    socket_unit = _read_regular(release / "deploy" / WRITER_SOCKET)
    tmpfiles = _read_regular(
        release / "deploy/myuna-owner-profile-write-v1.tmpfiles.conf"
    )
    required_service = {
        b"User=myuna_owner_profile",
        b"Group=myuna_owner_profile",
        b"ExecStart=/usr/bin/python3 -m myuna_core.owner_profile.write_socket_worker",
        b"RestrictAddressFamilies=AF_UNIX AF_INET",
        b"IPAddressDeny=any",
        b"IPAddressAllow=localhost",
        b"ReadOnlyPaths=/opt/myuna/owner-profile-write-v1 /etc/myuna-owner-profile-write-v1",
    }
    required_socket = {
        b"ListenStream=/run/myuna-owner-profile-write-v1/profile-write.sock",
        b"SocketUser=myuna_owner_profile",
        b"SocketGroup=myuna",
        b"SocketMode=0660",
        b"Service=myuna-owner-profile-write-v1.service",
    }
    expected_tmpfiles = (
        b"d /run/myuna-owner-profile-write-v1 0750 "
        b"myuna_owner_profile myuna -\n"
        b"d /var/log/myuna-owner-profile-write-v1 0700 "
        b"myuna_owner_profile myuna_owner_profile -\n"
    )
    if (
        not required_service.issubset(set(service.splitlines()))
        or not required_socket.issubset(set(socket_unit.splitlines()))
        or tmpfiles != expected_tmpfiles
    ):
        raise _reject("activation_writer_unit_rejected")
    core_environment = _read_regular(paths.deploy_root / CORE_ENV_SOURCE)
    _validate_core_environment(core_environment)
    read_profile = _read_regular(paths.deploy_root / READ_PROFILE_SOURCE)
    write_profile = _read_regular(paths.deploy_root / WRITE_PROFILE_SOURCE)
    manifest = _read_regular(paths.deploy_root / MANIFEST_SOURCE)
    read_document = _load_json(read_profile, code="activation_read_profile_rejected")
    write_document = _load_json(write_profile, code="activation_write_profile_rejected")
    manifest_document = _load_json(manifest, code="activation_manifest_rejected")
    if (
        read_document.get("profile_id") != "owner-private-profile-read-v1"
        or read_document.get("memory_protocol") != "profile-v1"
        or write_document.get("profile_id") != "owner-private-profile-write-v1"
        or write_document.get("memory_protocol") != "profile-write-v1"
        or write_document.get("subject", {}).get("channel_kinds")
        != ["astrbot_telegram"]
        or manifest_document.get("service", {}).get("response_scope")
        != "owner_private_dev_profile_write_v1"
        or manifest_document.get("models", {}).get("default", {}).get("provider")
        != "local"
        or manifest_document.get("capabilities", {})
        .get("long_term_memory_write", {})
        .get("enabled")
        is not True
    ):
        raise _reject("activation_capability_rejected")
    return {
        "writer_environment": (
            paths.writer_environment,
            environment,
            PRIVATE_MODE,
        ),
        WRITER_CAPABILITY_KEY: (
            paths.writer_capability_profile,
            write_profile,
            WRITER_READ_MODE,
        ),
        "writer_service": (paths.writer_service, service, CONFIG_MODE),
        "writer_socket": (paths.writer_socket, socket_unit, CONFIG_MODE),
        "writer_tmpfiles": (paths.writer_tmpfiles, tmpfiles, CONFIG_MODE),
        "read_profile": (paths.read_profile, read_profile, CONFIG_MODE),
        "write_profile": (paths.write_profile, write_profile, CONFIG_MODE),
        "capability_manifest": (
            paths.capability_manifest,
            manifest,
            CONFIG_MODE,
        ),
        "core_environment": (
            paths.core_environment,
            core_environment,
            CONFIG_MODE,
        ),
        "core_dropin": (
            paths.core_dropin,
            render_core_dropin(),
            CONFIG_MODE,
        ),
    }


def _ensure_private_directory(path: Path, *, uid: int, gid: int) -> None:
    try:
        path.mkdir(mode=PRIVATE_DIRECTORY_MODE, parents=False)
        os.chown(path, uid, gid)
        os.chmod(path, PRIVATE_DIRECTORY_MODE)
    except FileExistsError:
        pass
    except OSError as exc:
        raise _reject("activation_storage_unavailable") from exc
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != PRIVATE_DIRECTORY_MODE
        or metadata.st_uid != uid
        or metadata.st_gid != gid
    ):
        raise _reject("activation_storage_rejected")


def _ensure_parent(path: Path, *, uid: int, gid: int, private: bool) -> None:
    if path.exists() or path.is_symlink():
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or (private and mode != PRIVATE_DIRECTORY_MODE)
            or (private and (metadata.st_uid != uid or metadata.st_gid != gid))
            or (not private and bool(mode & 0o022))
        ):
            raise _reject("activation_parent_rejected")
        return
    if not private:
        raise _reject("activation_parent_rejected")
    _ensure_private_directory(path, uid=uid, gid=gid)


def _service_read_directory(
    path: Path,
    *,
    uid: int,
    gid: int,
    create: bool,
) -> bool:
    created = False
    if not path.exists() and not path.is_symlink():
        if not create:
            return False
        try:
            path.mkdir(mode=SERVICE_READ_DIRECTORY_MODE, parents=False)
            os.chown(path, uid, gid)
            os.chmod(path, SERVICE_READ_DIRECTORY_MODE)
            created = True
        except FileExistsError:
            created = False
        except OSError as exc:
            raise _reject("activation_storage_unavailable") from exc
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise _reject("activation_storage_unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != SERVICE_READ_DIRECTORY_MODE
        or metadata.st_uid != uid
        or metadata.st_gid != gid
    ):
        raise _reject("activation_parent_rejected")
    return created


def _atomic_write(path: Path, payload: bytes, *, mode: int, uid: int, gid: int) -> None:
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written < 1:
                    raise _reject("activation_write_unavailable")
                view = view[written:]
            os.fsync(descriptor)
            os.fchown(descriptor, uid, gid)
            os.fchmod(descriptor, mode)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        temporary = None
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OwnerProfileWriteActivationError:
        raise
    except OSError as exc:
        raise _reject("activation_write_unavailable") from exc
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def _write_new(path: Path, payload: bytes, *, mode: int, uid: int, gid: int) -> None:
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.",
            dir=path.parent,
        )
        try:
            os.fchown(descriptor, uid, gid)
            os.fchmod(descriptor, mode)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written < 1:
                    raise _reject("activation_write_unavailable")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise _reject("activation_receipt_conflict") from exc
        os.unlink(temporary)
        temporary = None
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OwnerProfileWriteActivationError:
        raise
    except OSError as exc:
        raise _reject("activation_write_unavailable") from exc
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def _snapshot(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int,
) -> FileSnapshot:
    if not path.exists() and not path.is_symlink():
        return FileSnapshot(False, None, None, None, None)
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as exc:
        raise _reject("activation_prestate_unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or stat.S_IMODE(metadata.st_mode) != expected_mode
    ):
        raise _reject("activation_prestate_rejected")
    return FileSnapshot(
        True,
        payload,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
    )


def _run(arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            timeout=240,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _reject("activation_command_unavailable") from exc
    if check and result.returncode != 0:
        raise _reject("activation_command_rejected")
    return result


def _systemctl(*arguments: str, check: bool = True) -> None:
    _run(["/usr/bin/systemctl", *arguments], check=check)


def _unit_state(kind: str, unit: str) -> bool:
    return _run(
        ["/usr/bin/systemctl", kind, "--quiet", unit],
        check=False,
    ).returncode == 0


def _show(unit: str, property_name: str) -> str:
    return _run(
        ["/usr/bin/systemctl", "show", unit, "-p", property_name, "--value"]
    ).stdout.strip()


def _service_snapshot() -> ServiceSnapshot:
    return ServiceSnapshot(
        writer_socket_active=_unit_state("is-active", WRITER_SOCKET),
        writer_socket_enabled=_unit_state("is-enabled", WRITER_SOCKET),
        writer_service_active=_unit_state("is-active", WRITER_SERVICE),
    )


def _backup(
    candidates: Mapping[str, tuple[Path, bytes, int]],
    snapshots: Mapping[str, FileSnapshot],
    services: ServiceSnapshot,
    *,
    paths: ActivationPaths,
    root_uid: int,
    root_gid: int,
) -> Path:
    _ensure_parent(paths.backup_root.parent, uid=root_uid, gid=root_gid, private=False)
    _ensure_private_directory(paths.backup_root, uid=root_uid, gid=root_gid)
    name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{time.time_ns()}"
    backup = paths.backup_root / name
    _ensure_private_directory(backup, uid=root_uid, gid=root_gid)
    records: dict[str, object] = {}
    for key, snapshot in snapshots.items():
        record: dict[str, object] = {
            "existed": snapshot.existed,
            "candidate_sha256": sha256(candidates[key][1]).hexdigest(),
        }
        if snapshot.existed:
            assert snapshot.payload is not None
            _atomic_write(
                backup / key,
                snapshot.payload,
                mode=PRIVATE_MODE,
                uid=root_uid,
                gid=root_gid,
            )
            record["backup_sha256"] = sha256(snapshot.payload).hexdigest()
            record["mode"] = snapshot.mode
        records[key] = record
    _atomic_write(
        backup / "MANIFEST.json",
        _canonical(
            {
                "schema": "myuna.owner-profile-write-activation-backup.v1",
                "files": records,
                "services": {
                    "writer_socket_active": services.writer_socket_active,
                    "writer_socket_enabled": services.writer_socket_enabled,
                    "writer_service_active": services.writer_service_active,
                },
                "raw_content_recorded": False,
                "profile_digest_recorded": False,
            }
        ),
        mode=PRIVATE_MODE,
        uid=root_uid,
        gid=root_gid,
    )
    return backup


def _restore_files(
    candidates: Mapping[str, tuple[Path, bytes, int]],
    snapshots: Mapping[str, FileSnapshot],
) -> None:
    for key, (path, candidate, _) in candidates.items():
        snapshot = snapshots[key]
        if path.exists() or path.is_symlink():
            if path.is_symlink():
                raise _reject("activation_rollback_drift")
            current = path.read_bytes()
            original = snapshot.payload if snapshot.existed else None
            if current not in {candidate, original}:
                raise _reject("activation_rollback_drift")
        if snapshot.existed:
            assert (
                snapshot.payload is not None
                and snapshot.mode is not None
                and snapshot.uid is not None
                and snapshot.gid is not None
            )
            _atomic_write(
                path,
                snapshot.payload,
                mode=snapshot.mode,
                uid=snapshot.uid,
                gid=snapshot.gid,
            )
        elif path.exists():
            path.unlink()


PrepareState = Callable[..., bool]
RestoreState = Callable[..., bool]


def activate(
    target: OwnerProfileWriteTarget,
    *,
    initial_profile_revision: int,
    initial_profile_sha256: str,
    service_uid: int,
    service_gid: int,
    paths: ActivationPaths = ActivationPaths(),
    root_uid: int = 0,
    root_gid: int = 0,
    prepare_state: PrepareState = prepare_write_state,
    restore_state: RestoreState = restore_write_state_root,
) -> dict[str, object]:
    if (
        os.geteuid() != root_uid
        or _DIGEST.fullmatch(initial_profile_sha256) is None
        or target.owner_profile_uid != service_uid
        or paths.journal.exists()
        or paths.journal.is_symlink()
    ):
        raise _reject("activation_preflight_rejected")
    expected_working_directory = (
        paths.core_release_root / target.core_release_sha256
    ).as_posix()
    if _show(CORE_SERVICE, "WorkingDirectory") != expected_working_directory:
        raise _reject("activation_core_release_not_selected")
    provider_exec = _show(LOCAL_PROVIDER_SERVICE, "ExecStart")
    if any(
        required not in provider_exec
        for required in (
            "--host 127.0.0.1",
            "--alias myuna-local-owner-v1",
            "--offline",
            "--log-disable",
        )
    ):
        raise _reject("activation_local_provider_boundary_rejected")
    if not all(
        _unit_state("is-active", unit)
        for unit in (CORE_SERVICE, READ_SERVICE, READ_SOCKET, LOCAL_PROVIDER_SERVICE)
    ):
        raise _reject("activation_required_service_unavailable")
    candidates = candidate_files(target, paths=paths)
    for key, (path, _, _) in candidates.items():
        if key == WRITER_CAPABILITY_KEY:
            _ensure_parent(
                path.parent.parent,
                uid=root_uid,
                gid=root_gid,
                private=False,
            )
            _service_read_directory(
                path.parent,
                uid=root_uid,
                gid=service_gid,
                create=False,
            )
            continue
        private_parent = path.parent.name == "myuna-owner-profile-write-v1"
        _ensure_parent(
            path.parent,
            uid=root_uid,
            gid=root_gid,
            private=private_parent,
        )
    _ensure_parent(paths.control_root.parent, uid=root_uid, gid=root_gid, private=False)
    _ensure_private_directory(paths.control_root, uid=root_uid, gid=root_gid)
    _ensure_private_directory(paths.receipt_root, uid=root_uid, gid=root_gid)
    snapshots: dict[str, FileSnapshot] = {}
    for key, (path, _, mode) in candidates.items():
        snapshots[key] = _snapshot(
            path,
            expected_uid=root_uid,
            expected_gid=(service_gid if key == WRITER_CAPABILITY_KEY else root_gid),
            expected_mode=mode,
        )
    services = _service_snapshot()
    backup = _backup(
        candidates,
        snapshots,
        services,
        paths=paths,
        root_uid=root_uid,
        root_gid=root_gid,
    )
    _atomic_write(
        paths.journal,
        _canonical(
            {
                "schema": "myuna.owner-profile-write-activation-journal.v1",
                "status": "pending",
                "backup": backup.name,
                "core_release_pinned": True,
                "initial_profile_revision": initial_profile_revision,
                "raw_content_recorded": False,
                "profile_digest_recorded": False,
            }
        ),
        mode=PRIVATE_MODE,
        uid=root_uid,
        gid=root_gid,
    )
    ownership_changed = False
    capability_parent_preexisted = paths.writer_capability_profile.parent.exists()
    mutated = False
    commit_started = False
    try:
        _systemctl("stop", WRITER_SERVICE, check=False)
        _systemctl("disable", "--now", WRITER_SOCKET, check=False)
        ownership_changed = prepare_state(
            source_release=LEGACY_PROFILE_RELEASE_ROOT
            / f"r{initial_profile_revision}-{initial_profile_sha256}",
            source_sha256=initial_profile_sha256,
            write_root=paths.write_root,
            root_uid=root_uid,
            root_gid=root_gid,
            service_uid=service_uid,
            service_gid=service_gid,
            core_pythonpath=Path(target.core_pythonpath),
        )
        mutated = True
        _service_read_directory(
            paths.writer_capability_profile.parent,
            uid=root_uid,
            gid=service_gid,
            create=True,
        )
        for key, (path, payload, mode) in candidates.items():
            _atomic_write(
                path,
                payload,
                mode=mode,
                uid=root_uid,
                gid=(service_gid if key == WRITER_CAPABILITY_KEY else root_gid),
            )
        service_name = pwd.getpwuid(service_uid).pw_name
        access = _run(
            [
                "/usr/sbin/runuser",
                "-u",
                service_name,
                "--",
                "/usr/bin/test",
                "-r",
                str(paths.writer_capability_profile),
            ],
            check=False,
        )
        if access.returncode != 0:
            raise _reject("activation_writer_capability_unreadable")
        _systemctl("daemon-reload")
        _run(["/usr/bin/systemd-tmpfiles", "--create", str(paths.writer_tmpfiles)])
        _systemctl("enable", "--now", WRITER_SOCKET)
        _systemctl("restart", READ_SERVICE)
        _systemctl("restart", CORE_SERVICE)
        if not all(
            _unit_state("is-active", unit)
            for unit in (
                CORE_SERVICE,
                READ_SERVICE,
                READ_SOCKET,
                WRITER_SOCKET,
                LOCAL_PROVIDER_SERVICE,
            )
        ) or not _unit_state("is-enabled", WRITER_SOCKET):
            raise _reject("activation_poststate_rejected")
        receipt = {
            "schema": "myuna.owner-profile-write-activation-receipt.v1",
            "status": "PROFILE_WRITE_LIVE_READY_AWAITING_OWNER_E2E",
            "initial_profile_revision": initial_profile_revision,
            "backup": backup.name,
            "receipt_id": backup.name,
            "core_release_pinned": True,
            "writer_socket_active": True,
            "writer_socket_enabled": True,
            "local_provider_only": True,
            "writer_capability_isolated": True,
            "owner_channel_e2e_performed": False,
            "memory_write_performed": False,
            "raw_content_recorded": False,
            "profile_digest_recorded": False,
            "profile_identity_recorded": False,
        }
        commit_started = True
        _write_new(
            paths.receipt_root / f"{backup.name}.json",
            _canonical(receipt),
            mode=PRIVATE_MODE,
            uid=root_uid,
            gid=root_gid,
        )
        paths.journal.unlink()
        return receipt
    except Exception as exc:
        if commit_started:
            raise _reject("activation_commit_recovery_required") from exc
        try:
            _systemctl("stop", WRITER_SERVICE, check=False)
            _systemctl("disable", "--now", WRITER_SOCKET, check=False)
            if mutated:
                _restore_files(
                    candidates,
                    snapshots,
                )
                if (
                    not capability_parent_preexisted
                    and paths.writer_capability_profile.parent.exists()
                ):
                    paths.writer_capability_profile.parent.rmdir()
                _systemctl("daemon-reload")
                _systemctl("restart", READ_SERVICE)
                _systemctl("restart", CORE_SERVICE)
            if ownership_changed:
                restore_state(
                    write_root=paths.write_root,
                    root_uid=root_uid,
                    root_gid=root_gid,
                    service_uid=service_uid,
                    service_gid=service_gid,
                )
            if services.writer_socket_enabled:
                _systemctl("enable", WRITER_SOCKET)
            if services.writer_socket_active:
                _systemctl("start", WRITER_SOCKET)
            if services.writer_service_active:
                _systemctl("start", WRITER_SERVICE)
            if paths.journal.exists() and not paths.journal.is_symlink():
                paths.journal.unlink()
        except Exception as rollback_exc:
            raise _reject("activation_rollback_failed") from rollback_exc
        raise


def _verify_git_source(root: Path, *, expected_commit: str) -> None:
    if _COMMIT.fullmatch(expected_commit) is None:
        raise _reject("activation_source_commit_rejected")
    files = (
        CORE_ENV_SOURCE,
        READ_PROFILE_SOURCE,
        WRITE_PROFILE_SOURCE,
        MANIFEST_SOURCE,
        ACTIVATION_SOURCE,
        ENVIRONMENT_SOURCE,
        PREPARE_SOURCE,
        IDENTITY_SOURCE,
        WRITE_CODE_INSTALLER_SOURCE,
    )
    head = _run(
        ["git", "-c", f"safe.directory={root}", "-C", str(root), "rev-parse", "HEAD"]
    ).stdout.strip()
    status = _run(
        [
            "git",
            "-c",
            f"safe.directory={root}",
            "-C",
            str(root),
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            *(str(path) for path in files),
        ]
    ).stdout.strip()
    if head != expected_commit or status:
        raise _reject("activation_source_commit_rejected")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core-release-sha256", required=True)
    parser.add_argument("--write-code-release-sha256", required=True)
    parser.add_argument("--initial-profile-revision", required=True, type=int)
    parser.add_argument("--initial-profile-sha256", required=True)
    parser.add_argument("--expected-deploy-commit", required=True)
    parser.add_argument("--live-confirmation", required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.live_confirmation != LIVE_CONFIRMATION:
            raise _reject("live_confirmation_rejected")
        service_uid, service_gid = validate_service_identity()
        validate_installed_code_release(
            arguments.write_code_release_sha256,
            gid=service_gid,
        )
        core_account = pwd.getpwnam("myuna")
        target = OwnerProfileWriteTarget(
            core_release_sha256=arguments.core_release_sha256,
            write_code_release_sha256=(
                arguments.write_code_release_sha256
            ),
            owner_profile_uid=service_uid,
            core_peer_uid=int(core_account.pw_uid),
        )
        _verify_git_source(DEPLOY_ROOT, expected_commit=arguments.expected_deploy_commit)
        receipt = activate(
            target,
            initial_profile_revision=arguments.initial_profile_revision,
            initial_profile_sha256=arguments.initial_profile_sha256,
            service_uid=service_uid,
            service_gid=service_gid,
        )
        print(json.dumps(receipt, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
        return 0
    except (
        OSError,
        ValueError,
        OwnerProfileCodeInstallError,
        OwnerProfileWriteActivationError,
    ) as exc:
        print(
            json.dumps(
                {
                    "status": "REJECTED",
                    "error_category": str(exc),
                    "raw_content_recorded": False,
                    "profile_digest_recorded": False,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
