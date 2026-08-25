from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import stat
from dataclasses import dataclass
from typing import Mapping

from .release_set import P07DReleaseSet, ReleaseSetRejected


P07_D_RELEASE_SET_PATH = Path(
    "/etc/myuna-telegram-gateway/p07-d-release-set-v1.json"
)
P07_D_RELEASE_SET_ENABLED_ENV = "MYUNA_P07_D_RELEASE_SET_ENABLED"
MAX_RELEASE_SET_BYTES = 64 * 1024


class ReleaseSetBindingRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ReleaseSetFileSnapshot:
    release_set: P07DReleaseSet
    file_digest: str


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ReleaseSetBindingRejected(code)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseSetBindingRejected("release_set_duplicate_field")
        result[key] = value
    return result


def load_release_set_file(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int = 0o640,
) -> P07DReleaseSet:
    return load_release_set_file_snapshot(
        path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        expected_mode=expected_mode,
    ).release_set


def load_release_set_file_snapshot(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int = 0o640,
) -> ReleaseSetFileSnapshot:
    _require(path.is_absolute(), "release_set_path_rejected")
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode), "release_set_type_rejected")
        _require(before.st_uid == expected_uid and before.st_gid == expected_gid, "release_set_owner_rejected")
        _require(stat.S_IMODE(before.st_mode) == expected_mode, "release_set_mode_rejected")
        _require(1 <= before.st_size <= MAX_RELEASE_SET_BYTES, "release_set_size_rejected")
        raw = os.read(descriptor, MAX_RELEASE_SET_BYTES + 1)
        after = os.fstat(descriptor)
        path_state = path.lstat()
        stable = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_size", "st_mtime_ns")
        _require(len(raw) == before.st_size, "release_set_snapshot_drifted")
        _require(all(getattr(before, name) == getattr(after, name) for name in stable), "release_set_snapshot_drifted")
        _require(not stat.S_ISLNK(path_state.st_mode), "release_set_type_rejected")
        _require(all(getattr(before, name) == getattr(path_state, name) for name in stable), "release_set_snapshot_drifted")
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
        selected = P07DReleaseSet.from_payload(payload)
        _require(sha256(raw).hexdigest() != "0" * 64, "release_set_document_rejected")
        return ReleaseSetFileSnapshot(
            release_set=selected,
            file_digest=sha256(raw).hexdigest(),
        )
    except ReleaseSetBindingRejected:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ReleaseSetRejected, TypeError, ValueError):
        raise ReleaseSetBindingRejected("release_set_document_rejected") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def release_set_enabled(environ: Mapping[str, str]) -> bool:
    raw = environ.get(P07_D_RELEASE_SET_ENABLED_ENV, "false").strip().lower()
    _require(raw in {"true", "false"}, "release_set_enablement_rejected")
    return raw == "true"


def load_release_set_from_environ(
    environ: Mapping[str, str],
    *,
    expected_gid: int = 0,
) -> P07DReleaseSet | None:
    snapshot = load_release_set_snapshot_from_environ(
        environ,
        expected_gid=expected_gid,
    )
    return None if snapshot is None else snapshot.release_set


def load_release_set_snapshot_from_environ(
    environ: Mapping[str, str],
    *,
    expected_gid: int = 0,
) -> ReleaseSetFileSnapshot | None:
    if not release_set_enabled(environ):
        return None
    return load_release_set_file_snapshot(
        P07_D_RELEASE_SET_PATH,
        expected_uid=0,
        expected_gid=expected_gid,
    )
