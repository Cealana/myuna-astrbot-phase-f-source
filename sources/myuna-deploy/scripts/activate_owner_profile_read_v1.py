#!/usr/bin/env python3
"""Activate one exact local-only Owner Profile read service release."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
from typing import Mapping, Sequence

from install_owner_profile_read_code_v1 import (
    FILE_MODE as CODE_FILE_MODE,
    MANIFEST_FILENAME,
    MANIFEST_SCHEMA,
    RELEASE_MODE as CODE_RELEASE_MODE,
    SOURCE_FILES,
)
from install_owner_profile_service_identity_v1 import validate_service_identity
from myuna_core.owner_profile.loader import load_approved_profile
from owner_profile_read_selector_v1 import (
    OwnerProfileReadTarget,
    parse_environment,
    render_environment,
)


SERVICE_UNIT_NAME = "myuna-owner-profile-read-v1.service"
SOCKET_UNIT_NAME = "myuna-owner-profile-read-v1.socket"
ENVIRONMENT_NAME = "owner-profile-read-v1.env"
TMPFILES_NAME = "myuna-owner-profile-read-v1.conf"
CODE_RELEASE_ROOT = Path("/opt/myuna/owner-profile-read-v1/releases")
PROFILE_RELEASE_ROOT = Path("/var/lib/myuna-owner-profile-v1/releases")
ENVIRONMENT_PATH = Path("/etc/myuna-owner-profile-read-v1") / "selector.env"
SERVICE_UNIT_PATH = Path("/etc/systemd/system") / SERVICE_UNIT_NAME
SOCKET_UNIT_PATH = Path("/etc/systemd/system") / SOCKET_UNIT_NAME
TMPFILES_PATH = Path("/etc/tmpfiles.d") / TMPFILES_NAME
ACTIVATION_ROOT = Path("/var/lib/myuna-owner-profile-v1/activation")
BACKUP_ROOT = ACTIVATION_ROOT / "backups"
RECEIPT_PATH = ACTIVATION_ROOT / "LAST_ACTIVATION.json"
JOURNAL_PATH = ACTIVATION_ROOT / "PENDING.json"
UNIT_MODE = 0o644
ENVIRONMENT_MODE = 0o600
PRIVATE_MODE = 0o600
PRIVATE_DIRECTORY_MODE = 0o700
MAX_CODE_MANIFEST_BYTES = 64_000
MAX_CONFIG_BYTES = 128_000
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


class OwnerProfileActivationError(RuntimeError):
    """A deterministic content-free activation rejection."""


@dataclass(frozen=True, slots=True)
class ActivationPaths:
    code_release_root: Path = CODE_RELEASE_ROOT
    profile_release_root: Path = PROFILE_RELEASE_ROOT
    environment: Path = ENVIRONMENT_PATH
    service_unit: Path = SERVICE_UNIT_PATH
    socket_unit: Path = SOCKET_UNIT_PATH
    tmpfiles: Path = TMPFILES_PATH
    backup_root: Path = BACKUP_ROOT
    activation_root: Path = ACTIVATION_ROOT
    receipt: Path = RECEIPT_PATH
    journal: Path = JOURNAL_PATH


@dataclass(frozen=True, slots=True)
class FileSnapshot:
    existed: bool
    payload: bytes | None
    mode: int | None
    uid: int | None
    gid: int | None


@dataclass(frozen=True, slots=True)
class ServiceSnapshot:
    socket_active: bool
    socket_enabled: bool
    service_active: bool


def _reject(code: str) -> OwnerProfileActivationError:
    return OwnerProfileActivationError(code)


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


def _expected_code_directories() -> frozenset[str]:
    directories: set[str] = set()
    for relative in SOURCE_FILES:
        parent = Path(relative).parent
        while parent != Path("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    return frozenset(directories)


def _read_regular(
    path: Path,
    *,
    maximum: int,
    mode: int,
    uid: int,
    gid: int,
    error: str,
) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise _reject(error) from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) != mode
        or before.st_uid != uid
        or before.st_gid != gid
        or before.st_nlink != 1
        or before.st_size < 1
        or before.st_size > maximum
    ):
        raise _reject(error)
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise _reject(error) from exc
    try:
        opened = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != mode
            or opened.st_uid != uid
            or opened.st_gid != gid
            or opened.st_nlink != 1
        ):
            raise _reject(error)
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(4096, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OwnerProfileActivationError:
        raise
    except OSError as exc:
        raise _reject(error) from exc
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    if not payload or len(payload) > maximum or len(payload) != before.st_size:
        raise _reject(error)
    return payload


def validate_code_release(
    target: OwnerProfileReadTarget,
    *,
    paths: ActivationPaths,
    service_gid: int,
    root_uid: int = 0,
) -> tuple[Path, str]:
    release = paths.code_release_root / target.code_release_sha256
    if release.name != target.code_release_sha256:
        raise _reject("activation_code_identity_rejected")
    try:
        entries = (release, *release.rglob("*"))
        actual_files: set[str] = set()
        actual_directories: set[str] = set()
        for entry in entries:
            metadata = entry.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != root_uid
                or metadata.st_gid != service_gid
            ):
                raise _reject("activation_code_metadata_rejected")
            relative = entry.relative_to(release).as_posix()
            if stat.S_ISDIR(metadata.st_mode):
                if stat.S_IMODE(metadata.st_mode) != CODE_RELEASE_MODE:
                    raise _reject("activation_code_metadata_rejected")
                if entry != release:
                    actual_directories.add(relative)
            elif stat.S_ISREG(metadata.st_mode):
                if (
                    stat.S_IMODE(metadata.st_mode) != CODE_FILE_MODE
                    or metadata.st_nlink != 1
                ):
                    raise _reject("activation_code_metadata_rejected")
                actual_files.add(relative)
            else:
                raise _reject("activation_code_metadata_rejected")
    except OwnerProfileActivationError:
        raise
    except OSError as exc:
        raise _reject("activation_code_unavailable") from exc
    if actual_files != {MANIFEST_FILENAME, *SOURCE_FILES}:
        raise _reject("activation_code_file_set_rejected")
    if actual_directories != _expected_code_directories():
        raise _reject("activation_code_file_set_rejected")
    manifest_bytes = _read_regular(
        release / MANIFEST_FILENAME,
        maximum=MAX_CODE_MANIFEST_BYTES,
        mode=CODE_FILE_MODE,
        uid=root_uid,
        gid=service_gid,
        error="activation_code_manifest_rejected",
    )
    if sha256(manifest_bytes).hexdigest() != target.code_release_sha256:
        raise _reject("activation_code_identity_rejected")
    try:
        manifest = json.loads(manifest_bytes.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _reject("activation_code_manifest_rejected") from exc
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema", "component", "source_commit", "files"}
        or manifest.get("schema") != MANIFEST_SCHEMA
        or manifest.get("component") != "owner_profile_read_v1"
        or not isinstance(manifest.get("source_commit"), str)
        or _COMMIT.fullmatch(str(manifest.get("source_commit"))) is None
    ):
        raise _reject("activation_code_manifest_rejected")
    files = manifest.get("files")
    if not isinstance(files, list) or len(files) != len(SOURCE_FILES):
        raise _reject("activation_code_manifest_rejected")
    for relative, record in zip(SOURCE_FILES, files, strict=True):
        if (
            not isinstance(record, dict)
            or set(record) != {"path", "bytes", "sha256", "mode"}
            or record.get("path") != relative
            or record.get("mode") != "0440"
            or isinstance(record.get("bytes"), bool)
            or not isinstance(record.get("bytes"), int)
            or int(record["bytes"]) < 1
            or not isinstance(record.get("sha256"), str)
            or _DIGEST.fullmatch(str(record.get("sha256"))) is None
        ):
            raise _reject("activation_code_manifest_rejected")
        payload = _read_regular(
            release / relative,
            maximum=256_000,
            mode=CODE_FILE_MODE,
            uid=root_uid,
            gid=service_gid,
            error="activation_code_content_rejected",
        )
        if len(payload) != record["bytes"] or sha256(payload).hexdigest() != record["sha256"]:
            raise _reject("activation_code_content_rejected")
    return release, str(manifest["source_commit"])


def validate_profile_release(
    target: OwnerProfileReadTarget,
    *,
    paths: ActivationPaths,
) -> None:
    release = paths.profile_release_root / (
        f"r{target.profile_revision}-{target.profile_sha256}"
    )
    if release.name != f"r{target.profile_revision}-{target.profile_sha256}":
        raise _reject("activation_profile_identity_rejected")
    try:
        profile = load_approved_profile(
            release,
            expected_sha256=target.profile_sha256,
            expected_owner_uid=target.profile_owner_uid,
        )
    except Exception as exc:
        raise _reject("activation_profile_rejected") from exc
    if profile.profile_revision != target.profile_revision:
        raise _reject("activation_profile_identity_rejected")


def candidate_files(
    target: OwnerProfileReadTarget,
    code_release: Path,
    *,
    paths: ActivationPaths,
) -> dict[str, tuple[Path, bytes, int]]:
    environment = render_environment(target)
    if parse_environment(environment) != target:
        raise _reject("activation_selector_rejected")
    try:
        service = (code_release / "deploy" / SERVICE_UNIT_NAME).read_bytes()
        socket_unit = (
            code_release / "deploy" / SOCKET_UNIT_NAME
        ).read_bytes()
        tmpfiles = (
            code_release
            / "deploy"
            / "myuna-owner-profile-read-v1.tmpfiles.conf"
        ).read_bytes()
    except OSError as exc:
        raise _reject("activation_unit_contract_rejected") from exc
    required_service_lines = {
        b"User=myuna_owner_profile",
        b"Group=myuna_owner_profile",
        b"EnvironmentFile=/etc/myuna-owner-profile-read-v1/selector.env",
        b"ExecStart=/usr/bin/python3 -m myuna_core.owner_profile.socket_worker",
        b"PrivateNetwork=true",
        b"RestrictAddressFamilies=AF_UNIX",
        (
            b"ReadOnlyPaths=/var/lib/myuna-owner-profile-v1 "
            b"/var/lib/myuna-owner-profile-write-v1"
        ),
    }
    required_socket_lines = {
        b"ListenStream=/run/myuna-owner-profile-read-v1/profile.sock",
        b"SocketUser=myuna_owner_profile",
        b"SocketGroup=myuna",
        b"SocketMode=0660",
        b"Service=myuna-owner-profile-read-v1.service",
    }
    if (
        not required_service_lines.issubset(set(service.splitlines()))
        or not required_socket_lines.issubset(set(socket_unit.splitlines()))
        or tmpfiles
        != b"d /run/myuna-owner-profile-read-v1 0750 myuna_owner_profile myuna -\n"
    ):
        raise _reject("activation_unit_contract_rejected")
    return {
        "environment": (paths.environment, environment, ENVIRONMENT_MODE),
        "service_unit": (
            paths.service_unit,
            service,
            UNIT_MODE,
        ),
        "socket_unit": (
            paths.socket_unit,
            socket_unit,
            UNIT_MODE,
        ),
        "tmpfiles": (
            paths.tmpfiles,
            tmpfiles,
            UNIT_MODE,
        ),
    }


def _snapshot(path: Path, *, mode: int, uid: int, gid: int) -> FileSnapshot:
    if not path.exists() and not path.is_symlink():
        return FileSnapshot(False, None, None, None, None)
    payload = _read_regular(
        path,
        maximum=MAX_CONFIG_BYTES,
        mode=mode,
        uid=uid,
        gid=gid,
        error="activation_prestate_rejected",
    )
    return FileSnapshot(True, payload, mode, uid, gid)


def _validate_directory(path: Path, *, mode: int, uid: int, gid: int) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise _reject("activation_storage_unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_uid != uid
        or metadata.st_gid != gid
    ):
        raise _reject("activation_storage_rejected")


def _ensure_private_directory(path: Path, *, uid: int, gid: int) -> None:
    try:
        path.mkdir(mode=PRIVATE_DIRECTORY_MODE)
        os.chown(path, uid, gid)
        os.chmod(path, PRIVATE_DIRECTORY_MODE)
    except FileExistsError:
        pass
    except OSError as exc:
        raise _reject("activation_storage_unavailable") from exc
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise _reject("activation_storage_unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != PRIVATE_DIRECTORY_MODE
        or metadata.st_uid != uid
        or metadata.st_gid != gid
    ):
        raise _reject("activation_storage_rejected")


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
        parent_descriptor = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except OwnerProfileActivationError:
        raise
    except OSError as exc:
        raise _reject("activation_write_unavailable") from exc
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def _run(arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _reject("activation_service_unavailable") from exc
    if check and completed.returncode != 0:
        raise _reject("activation_service_rejected")
    return completed


def _systemctl(*arguments: str, check: bool = True) -> None:
    _run(["/usr/bin/systemctl", *arguments], check=check)


def _unit_state(kind: str, unit: str) -> bool:
    completed = _run(
        ["/usr/bin/systemctl", kind, "--quiet", unit],
        check=False,
    )
    return completed.returncode == 0


def _service_snapshot() -> ServiceSnapshot:
    return ServiceSnapshot(
        socket_active=_unit_state("is-active", SOCKET_UNIT_NAME),
        socket_enabled=_unit_state("is-enabled", SOCKET_UNIT_NAME),
        service_active=_unit_state("is-active", SERVICE_UNIT_NAME),
    )


def _backup(
    candidates: Mapping[str, tuple[Path, bytes, int]],
    snapshots: Mapping[str, FileSnapshot],
    services: ServiceSnapshot,
    *,
    paths: ActivationPaths,
    uid: int,
    gid: int,
) -> Path:
    _ensure_private_directory(paths.backup_root, uid=uid, gid=gid)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = paths.backup_root / f"{stamp}-{time.time_ns()}"
    try:
        backup.mkdir(mode=PRIVATE_DIRECTORY_MODE)
        os.chown(backup, uid, gid)
        os.chmod(backup, PRIVATE_DIRECTORY_MODE)
    except OSError as exc:
        raise _reject("activation_backup_unavailable") from exc
    records: dict[str, object] = {}
    for key, snapshot in snapshots.items():
        candidate_payload = candidates[key][1]
        record: dict[str, object] = {
            "existed": snapshot.existed,
            "candidate_sha256": sha256(candidate_payload).hexdigest(),
        }
        if snapshot.existed:
            assert snapshot.payload is not None
            backup_file = backup / key
            _atomic_write(
                backup_file,
                snapshot.payload,
                mode=PRIVATE_MODE,
                uid=uid,
                gid=gid,
            )
            record.update(
                {
                    "backup_sha256": sha256(snapshot.payload).hexdigest(),
                    "mode": snapshot.mode,
                    "uid": snapshot.uid,
                    "gid": snapshot.gid,
                }
            )
        records[key] = record
    manifest = {
        "schema": "myuna.owner-profile-read-activation-backup.v1",
        "files": records,
        "services": {
            "socket_active": services.socket_active,
            "socket_enabled": services.socket_enabled,
            "service_active": services.service_active,
        },
    }
    _atomic_write(
        backup / "MANIFEST.json",
        _canonical(manifest),
        mode=PRIVATE_MODE,
        uid=uid,
        gid=gid,
    )
    return backup


def _rollback(
    candidates: Mapping[str, tuple[Path, bytes, int]],
    snapshots: Mapping[str, FileSnapshot],
    services: ServiceSnapshot,
    *,
    uid: int,
    gid: int,
) -> None:
    _systemctl("disable", "--now", SOCKET_UNIT_NAME, check=False)
    _systemctl("stop", SERVICE_UNIT_NAME, check=False)
    for key, (path, candidate_payload, _) in candidates.items():
        snapshot = snapshots[key]
        if path.exists() or path.is_symlink():
            if path.is_symlink():
                raise _reject("activation_rollback_drift")
            try:
                current = path.read_bytes()
            except OSError as exc:
                raise _reject("activation_rollback_drift") from exc
            original = snapshot.payload if snapshot.existed else None
            if current not in {candidate_payload, original}:
                raise _reject("activation_rollback_drift")
        if snapshot.existed:
            assert snapshot.payload is not None
            assert snapshot.mode is not None
            assert snapshot.uid is not None
            assert snapshot.gid is not None
            _atomic_write(
                path,
                snapshot.payload,
                mode=snapshot.mode,
                uid=snapshot.uid,
                gid=snapshot.gid,
            )
        elif path.exists() or path.is_symlink():
            if path.is_symlink():
                raise _reject("activation_rollback_drift")
            path.unlink()
    _systemctl("daemon-reload")
    if services.socket_enabled:
        _systemctl("enable", SOCKET_UNIT_NAME)
    else:
        _systemctl("disable", SOCKET_UNIT_NAME, check=False)
    if services.socket_active:
        _systemctl("start", SOCKET_UNIT_NAME)
    if services.service_active:
        _systemctl("start", SERVICE_UNIT_NAME)
    if _service_snapshot() != services:
        raise _reject("activation_rollback_failed")


def activate(
    target: OwnerProfileReadTarget,
    *,
    paths: ActivationPaths = ActivationPaths(),
    root_uid: int = 0,
    root_gid: int = 0,
    service_gid: int,
) -> dict[str, object]:
    if os.geteuid() != root_uid:
        raise _reject("activation_requires_root")
    if paths.journal.exists() or paths.journal.is_symlink():
        raise _reject("activation_recovery_required")
    _validate_directory(
        paths.environment.parent.parent,
        mode=0o755,
        uid=root_uid,
        gid=root_gid,
    )
    _ensure_private_directory(
        paths.environment.parent,
        uid=root_uid,
        gid=root_gid,
    )
    _validate_directory(paths.service_unit.parent, mode=0o755, uid=root_uid, gid=root_gid)
    _validate_directory(paths.socket_unit.parent, mode=0o755, uid=root_uid, gid=root_gid)
    _validate_directory(paths.tmpfiles.parent, mode=0o755, uid=root_uid, gid=root_gid)
    code_release, source_commit = validate_code_release(
        target,
        paths=paths,
        service_gid=service_gid,
        root_uid=root_uid,
    )
    validate_profile_release(target, paths=paths)
    candidates = candidate_files(target, code_release, paths=paths)
    snapshots = {
        key: _snapshot(path, mode=mode, uid=root_uid, gid=root_gid)
        for key, (path, _, mode) in candidates.items()
    }
    services = _service_snapshot()
    _validate_directory(
        paths.activation_root.parent,
        mode=0o710,
        uid=root_uid,
        gid=service_gid,
    )
    _ensure_private_directory(paths.activation_root, uid=root_uid, gid=root_gid)
    backup = _backup(
        candidates,
        snapshots,
        services,
        paths=paths,
        uid=root_uid,
        gid=root_gid,
    )
    journal = {
        "schema": "myuna.owner-profile-read-activation-journal.v1",
        "status": "pending",
        "backup": backup.name,
        "code_release_sha256": target.code_release_sha256,
        "profile_revision": target.profile_revision,
        "raw_content_recorded": False,
        "profile_digest_recorded": False,
    }
    _atomic_write(
        paths.journal,
        _canonical(journal),
        mode=PRIVATE_MODE,
        uid=root_uid,
        gid=root_gid,
    )
    mutated = False
    try:
        mutated = True
        for path, payload, mode in candidates.values():
            _atomic_write(path, payload, mode=mode, uid=root_uid, gid=root_gid)
        _systemctl("daemon-reload")
        _run(["/usr/bin/systemd-tmpfiles", "--create", str(paths.tmpfiles)])
        _systemctl("enable", "--now", SOCKET_UNIT_NAME)
        if not _unit_state("is-active", SOCKET_UNIT_NAME):
            raise _reject("activation_socket_not_active")
        if not _unit_state("is-enabled", SOCKET_UNIT_NAME):
            raise _reject("activation_socket_not_enabled")
        receipt = {
            "schema": "myuna.owner-profile-read-activation-receipt.v1",
            "status": "LOCAL_READ_SERVICE_READY_PROVIDER_EGRESS_BLOCKED",
            "profile_revision": target.profile_revision,
            "code_source_commit": source_commit,
            "code_release_sha256": target.code_release_sha256,
            "backup": backup.name,
            "socket_active": True,
            "socket_enabled": True,
            "provider_context_enabled": False,
            "owner_channel_e2e_performed": False,
            "raw_content_recorded": False,
            "profile_digest_recorded": False,
            "profile_identity_recorded": False,
        }
        _atomic_write(
            paths.receipt,
            _canonical(receipt),
            mode=PRIVATE_MODE,
            uid=root_uid,
            gid=root_gid,
        )
        paths.journal.unlink()
        return receipt
    except Exception as exc:
        if mutated:
            try:
                _rollback(
                    candidates,
                    snapshots,
                    services,
                    uid=root_uid,
                    gid=root_gid,
                )
                if paths.journal.exists() and not paths.journal.is_symlink():
                    paths.journal.unlink()
            except Exception as rollback_exc:
                raise _reject("activation_rollback_failed") from rollback_exc
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--code-release-sha256", required=True)
    parser.add_argument("--profile-revision", required=True, type=int)
    parser.add_argument("--profile-sha256", required=True)
    arguments = parser.parse_args(argv)
    try:
        service_uid, service_gid = validate_service_identity()
        target = OwnerProfileReadTarget(
            code_release_sha256=arguments.code_release_sha256,
            profile_revision=arguments.profile_revision,
            profile_sha256=arguments.profile_sha256,
            profile_owner_uid=service_uid,
        )
        receipt = activate(target, service_gid=service_gid)
        print(json.dumps(receipt, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
        return 0
    except (OSError, OwnerProfileActivationError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "status": "REJECTED",
                    "error_category": str(exc),
                    "raw_content_recorded": False,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
