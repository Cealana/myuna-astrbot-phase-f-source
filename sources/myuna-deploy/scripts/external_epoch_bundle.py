#!/usr/bin/env python3
"""Content-free immutable bundle contract for a stopped SQLite WAL epoch."""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import stat
from typing import Mapping


BUNDLE_SCHEMA = "myuna.external-epoch-immutable-bundle.v1"
BUNDLE_DIGEST_ALGORITHM = "sha256-canonical-file-digests-v1"
_BUNDLE_NAMES = ("epoch.db", "epoch.db-wal", "epoch.db-shm")


class ExternalEpochBundleRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ExternalEpochBundleRejected(code)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"


def _digest_file(path: Path) -> str:
    digest = sha256()
    try:
        with path.open("rb") as handle:
            while block := handle.read(1024 * 1024):
                digest.update(block)
    except OSError as exc:
        raise ExternalEpochBundleRejected("bundle_file_unavailable") from exc
    return digest.hexdigest()


def bundle_paths(database: str | Path) -> dict[str, Path]:
    database_path = Path(database)
    _require(database_path.is_absolute(), "bundle_database_path_rejected")
    _require(database_path.name == "epoch.db", "bundle_database_name_rejected")
    return {
        "epoch.db": database_path,
        "epoch.db-shm": Path(f"{database_path}-shm"),
        "epoch.db-wal": Path(f"{database_path}-wal"),
    }


def inspect_epoch_bundle(
    database: str | Path,
    *,
    expected_file_mode: int,
    expected_parent_mode: int,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
) -> dict[str, object]:
    paths = bundle_paths(database)
    database_path = paths["epoch.db"]
    parent = database_path.parent
    try:
        parent_metadata = parent.lstat()
    except OSError as exc:
        raise ExternalEpochBundleRejected("bundle_parent_unavailable") from exc
    _require(
        not parent.is_symlink() and stat.S_ISDIR(parent_metadata.st_mode),
        "bundle_parent_type_rejected",
    )
    _require(
        stat.S_IMODE(parent_metadata.st_mode) == expected_parent_mode,
        "bundle_parent_permission_rejected",
    )
    if expected_uid is not None:
        _require(parent_metadata.st_uid == expected_uid, "bundle_parent_owner_rejected")
    if expected_gid is not None:
        _require(parent_metadata.st_gid == expected_gid, "bundle_parent_owner_rejected")

    presence: dict[str, bool] = {}
    metadata_by_name: dict[str, os.stat_result] = {}
    for name in _BUNDLE_NAMES:
        path = paths[name]
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            presence[name] = False
            continue
        except OSError as exc:
            raise ExternalEpochBundleRejected("bundle_file_unavailable") from exc
        presence[name] = True
        _require(
            not path.is_symlink() and stat.S_ISREG(metadata.st_mode),
            "bundle_file_type_rejected",
        )
        _require(
            stat.S_IMODE(metadata.st_mode) == expected_file_mode,
            "bundle_file_permission_rejected",
        )
        if expected_uid is not None:
            _require(metadata.st_uid == expected_uid, "bundle_file_owner_rejected")
        if expected_gid is not None:
            _require(metadata.st_gid == expected_gid, "bundle_file_owner_rejected")
        metadata_by_name[name] = metadata

    _require(presence["epoch.db"], "bundle_database_missing")
    wal_present = presence["epoch.db-wal"]
    shm_present = presence["epoch.db-shm"]
    _require(wal_present == shm_present, "bundle_partial_sidecar_rejected")

    files: list[dict[str, object]] = []
    permissions: dict[str, dict[str, int]] = {}
    for name in sorted(metadata_by_name):
        metadata = metadata_by_name[name]
        files.append(
            {
                "name": name,
                "sha256": _digest_file(paths[name]),
                "size": metadata.st_size,
            }
        )
        permissions[name] = {
            "gid": metadata.st_gid,
            "mode": stat.S_IMODE(metadata.st_mode),
            "uid": metadata.st_uid,
        }

    digest_projection = {
        "algorithm": BUNDLE_DIGEST_ALGORITHM,
        "files": files,
        "schema": BUNDLE_SCHEMA,
    }
    return {
        "bundle_digest": sha256(_canonical(digest_projection)).hexdigest(),
        "bundle_projection": digest_projection,
        "file_permissions": permissions,
        "parent_permission": {
            "gid": parent_metadata.st_gid,
            "mode": stat.S_IMODE(parent_metadata.st_mode),
            "uid": parent_metadata.st_uid,
        },
    }


def require_same_bundle(
    first: Mapping[str, object],
    second: Mapping[str, object],
) -> str:
    first_digest = first.get("bundle_digest")
    second_digest = second.get("bundle_digest")
    _require(
        isinstance(first_digest, str)
        and first_digest == second_digest
        and first.get("bundle_projection") == second.get("bundle_projection"),
        "bundle_digest_drifted",
    )
    return first_digest


def seal_epoch_bundle(
    database: str | Path,
    *,
    expected_bundle_digest: str,
    source_uid: int,
    source_gid: int,
    sealed_gid: int,
) -> dict[str, object]:
    before = inspect_epoch_bundle(
        database,
        expected_file_mode=0o600,
        expected_parent_mode=0o700,
        expected_uid=source_uid,
        expected_gid=source_gid,
    )
    _require(
        before["bundle_digest"] == expected_bundle_digest,
        "bundle_digest_mismatch",
    )
    paths = bundle_paths(database)
    projection = before["bundle_projection"]
    assert isinstance(projection, dict)
    files = projection["files"]
    assert isinstance(files, list)
    for entry in files:
        assert isinstance(entry, dict)
        path = paths[str(entry["name"])]
        os.chown(path, 0, sealed_gid)
        os.chmod(path, 0o440)
    parent = Path(database).parent
    os.chown(parent, 0, sealed_gid)
    os.chmod(parent, 0o550)
    after = inspect_epoch_bundle(
        database,
        expected_file_mode=0o440,
        expected_parent_mode=0o550,
        expected_uid=0,
        expected_gid=sealed_gid,
    )
    require_same_bundle(before, after)
    return after


def restore_epoch_bundle_permissions(
    database: str | Path,
    *,
    prestate: Mapping[str, object],
    expected_bundle_digest: str,
) -> dict[str, object]:
    projection = prestate.get("bundle_projection")
    file_permissions = prestate.get("file_permissions")
    parent_permission = prestate.get("parent_permission")
    _require(
        isinstance(projection, dict)
        and isinstance(file_permissions, dict)
        and isinstance(parent_permission, dict),
        "bundle_prestate_rejected",
    )
    _require(
        prestate.get("bundle_digest") == expected_bundle_digest,
        "bundle_prestate_digest_rejected",
    )
    files = projection.get("files")
    _require(isinstance(files, list) and bool(files), "bundle_prestate_rejected")
    paths = bundle_paths(database)
    expected_names = {str(entry.get("name")) for entry in files if isinstance(entry, dict)}
    _require(expected_names == set(file_permissions), "bundle_prestate_rejected")
    actual_names = {
        name for name, path in paths.items() if path.exists() or path.is_symlink()
    }
    _require(actual_names == expected_names, "bundle_file_set_drifted")
    for name in sorted(expected_names):
        permission = file_permissions.get(name)
        _require(isinstance(permission, dict), "bundle_prestate_rejected")
        path = paths[name]
        metadata = path.lstat()
        _require(
            not path.is_symlink() and stat.S_ISREG(metadata.st_mode),
            "bundle_file_type_rejected",
        )
        os.chown(path, int(permission["uid"]), int(permission["gid"]))
        os.chmod(path, int(permission["mode"]))
    parent = Path(database).parent
    os.chown(parent, int(parent_permission["uid"]), int(parent_permission["gid"]))
    os.chmod(parent, int(parent_permission["mode"]))
    restored = inspect_epoch_bundle(
        database,
        expected_file_mode=int(next(iter(file_permissions.values()))["mode"]),
        expected_parent_mode=int(parent_permission["mode"]),
        expected_uid=int(next(iter(file_permissions.values()))["uid"]),
        expected_gid=int(next(iter(file_permissions.values()))["gid"]),
    )
    _require(
        restored["bundle_digest"] == expected_bundle_digest,
        "bundle_rollback_digest_rejected",
    )
    return restored
