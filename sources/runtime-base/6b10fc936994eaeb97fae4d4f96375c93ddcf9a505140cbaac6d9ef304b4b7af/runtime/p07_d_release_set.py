from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
from typing import Mapping

from myuna_core.external_context.release_set import P07DReleaseSet


MAX_RELEASE_SET_BYTES = 64 * 1024
MAX_PROTECTED_JSON_BYTES = 64 * 1024


class ProtectedReleaseSetRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ProtectedReleaseSetRejected(code)


@dataclass(frozen=True, slots=True)
class ProtectedReleaseSetSnapshot:
    release_set: P07DReleaseSet
    file_digest: str
    device: int
    inode: int
    size: int
    uid: int
    gid: int
    mode: int

    def audit_projection(self) -> dict[str, object]:
        return {
            "file_digest": self.file_digest,
            "generation": self.release_set.generation,
            "release_set_id": self.release_set.release_set_id,
            "size": self.size,
        }


@dataclass(frozen=True, slots=True)
class ProtectedJsonSnapshot:
    payload: object
    file_digest: str
    device: int
    inode: int
    size: int
    uid: int
    gid: int
    mode: int


def _metadata(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int,
) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProtectedReleaseSetRejected("release_set_file_unavailable") from exc
    _require(not path.is_symlink() and stat.S_ISREG(metadata.st_mode), "release_set_file_type_rejected")
    _require(metadata.st_uid == expected_uid and metadata.st_gid == expected_gid, "release_set_file_owner_rejected")
    _require(stat.S_IMODE(metadata.st_mode) == expected_mode, "release_set_file_mode_rejected")
    _require(1 <= metadata.st_size <= MAX_RELEASE_SET_BYTES, "release_set_file_size_rejected")
    return metadata


def load_protected_release_set_snapshot(
    path: str | Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int = 0o640,
) -> ProtectedReleaseSetSnapshot:
    selected = Path(path)
    _require(selected.is_absolute(), "release_set_path_rejected")
    before = _metadata(
        selected,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        expected_mode=expected_mode,
    )
    try:
        with selected.open("rb", buffering=0) as stream:
            raw = stream.read(MAX_RELEASE_SET_BYTES + 1)
    except OSError as exc:
        raise ProtectedReleaseSetRejected("release_set_file_unavailable") from exc
    _require(len(raw) <= MAX_RELEASE_SET_BYTES, "release_set_file_size_rejected")
    after = _metadata(
        selected,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        expected_mode=expected_mode,
    )
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_uid,
        item.st_gid,
        stat.S_IMODE(item.st_mode),
    )
    _require(identity(before) == identity(after), "release_set_snapshot_drifted")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
        release_set = P07DReleaseSet.from_payload(document)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise ProtectedReleaseSetRejected("release_set_document_rejected") from exc
    return ProtectedReleaseSetSnapshot(
        release_set=release_set,
        file_digest=sha256(raw).hexdigest(),
        device=after.st_dev,
        inode=after.st_ino,
        size=after.st_size,
        uid=after.st_uid,
        gid=after.st_gid,
        mode=stat.S_IMODE(after.st_mode),
    )


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        _require(key not in result, "protected_json_duplicate_field")
        result[key] = value
    return result


def load_protected_json_snapshot(
    path: str | Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int = 0o640,
    maximum_bytes: int = MAX_PROTECTED_JSON_BYTES,
) -> ProtectedJsonSnapshot:
    selected = Path(path)
    _require(selected.is_absolute(), "protected_json_path_rejected")
    _require(1 <= maximum_bytes <= MAX_PROTECTED_JSON_BYTES, "protected_json_size_rejected")
    before = _metadata(
        selected,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        expected_mode=expected_mode,
    )
    _require(before.st_size <= maximum_bytes, "protected_json_size_rejected")
    descriptor = -1
    try:
        descriptor = os.open(
            selected,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        raw = os.read(descriptor, maximum_bytes + 1)
        after = os.fstat(descriptor)
        path_state = selected.lstat()
    except OSError as exc:
        raise ProtectedReleaseSetRejected("protected_json_unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_uid", "st_gid", "st_mode")
    _require(
        all(getattr(before, name) == getattr(opened, name) == getattr(after, name) == getattr(path_state, name) for name in stable),
        "protected_json_snapshot_drifted",
    )
    _require(len(raw) == before.st_size and len(raw) <= maximum_bytes, "protected_json_size_rejected")
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProtectedReleaseSetRejected("protected_json_document_rejected") from None
    return ProtectedJsonSnapshot(
        payload=payload,
        file_digest=sha256(raw).hexdigest(),
        device=after.st_dev,
        inode=after.st_ino,
        size=after.st_size,
        uid=after.st_uid,
        gid=after.st_gid,
        mode=stat.S_IMODE(after.st_mode),
    )


def runtime_binding_digest(
    *,
    channel_kind: str,
    client_id: str,
    principal_id: str,
    namespace_id: str,
) -> str:
    payload = {
        "channel_kind": channel_kind,
        "client_id": client_id,
        "namespace_id": namespace_id,
        "principal_id": principal_id,
        "schema": "myuna.p07-d-runtime-binding.v1",
    }
    return sha256(
        b"myuna-p07-d-runtime-binding-v1\0"
        + json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


def require_same_release_set_snapshot(
    first: ProtectedReleaseSetSnapshot,
    second: ProtectedReleaseSetSnapshot,
) -> None:
    _require(first == second, "release_set_snapshot_drifted")


def require_runtime_binding_projection(
    snapshot: ProtectedReleaseSetSnapshot,
    *,
    runtime_config_path: Path,
    runtime_config_digest: str,
    binding_digest: str,
    channel_kind: str,
    principal_id: str,
    namespace_id: str,
) -> None:
    projected: Mapping[str, object] = snapshot.release_set.runtime_config
    _require(projected["path"] == runtime_config_path.as_posix(), "release_set_runtime_config_mismatch")
    _require(projected["digest"] == runtime_config_digest, "release_set_runtime_config_mismatch")
    _require(projected["binding_digest"] == binding_digest, "release_set_runtime_config_mismatch")
    _require(projected["channel_kind"] == channel_kind, "release_set_runtime_config_mismatch")
    _require(projected["principal_id"] == principal_id, "release_set_runtime_config_mismatch")
    _require(projected["namespace_id"] == namespace_id, "release_set_runtime_config_mismatch")


def require_effective_credential_projection(
    snapshot: ProtectedReleaseSetSnapshot,
    *,
    name: str,
    source: Path,
    dropin_set_digest: str,
    projection_digest: str,
    effective_count: int,
) -> None:
    projected: Mapping[str, object] = snapshot.release_set.credential
    _require(projected["name"] == name, "release_set_credential_mismatch")
    _require(projected["effective_source"] == source.as_posix(), "release_set_credential_mismatch")
    _require(projected["dropin_set_digest"] == dropin_set_digest, "release_set_credential_mismatch")
    _require(projected["projection_digest"] == projection_digest, "release_set_credential_mismatch")
    _require(projected["effective_count"] == effective_count == 1, "release_set_credential_mismatch")
