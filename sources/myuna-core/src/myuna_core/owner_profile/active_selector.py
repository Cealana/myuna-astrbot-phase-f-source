from __future__ import annotations

from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from .contracts import OwnerProfile, OwnerProfileError
from .loader import load_approved_profile


SELECTOR_SCHEMA_VERSION = 1
SELECTOR_TYPE = "owner_profile_active_selector_v1"
SELECTOR_FILENAME = "active.json"
SELECTOR_LOCK_FILENAME = "selector.lock"
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
MAX_SELECTOR_BYTES = 4_096
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SELECTOR_KEYS = {
    "profile_id",
    "profile_revision",
    "profile_sha256",
    "schema_version",
    "selector_type",
}


class ActiveProfileSelectorError(OwnerProfileError):
    pass


def _reject(code: str, *, retryable: bool = False) -> ActiveProfileSelectorError:
    return ActiveProfileSelectorError(code, retryable=retryable)


def _uid(value: int | None) -> int:
    result = os.geteuid() if value is None else value
    if isinstance(result, bool) or not isinstance(result, int) or result < 0:
        raise _reject("profile_selector_permission_drift")
    return result


def _validate_metadata(
    metadata: os.stat_result,
    *,
    directory: bool,
    expected_uid: int,
) -> None:
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    expected_mode = PRIVATE_DIRECTORY_MODE if directory else PRIVATE_FILE_MODE
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not expected_type(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != expected_mode
        or metadata.st_uid != expected_uid
        or (not directory and metadata.st_nlink != 1)
    ):
        raise _reject("profile_selector_permission_drift")


@dataclass(frozen=True, slots=True)
class ActiveProfileTarget:
    profile_id: str
    profile_revision: int
    profile_sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.profile_id, str)
            or _SAFE_LABEL.fullmatch(self.profile_id) is None
            or isinstance(self.profile_revision, bool)
            or not isinstance(self.profile_revision, int)
            or self.profile_revision < 1
            or not isinstance(self.profile_sha256, str)
            or _DIGEST.fullmatch(self.profile_sha256) is None
        ):
            raise _reject("malformed_profile_selector")

    @classmethod
    def from_profile(cls, profile: OwnerProfile) -> ActiveProfileTarget:
        return cls(
            profile_id=profile.profile_id,
            profile_revision=profile.profile_revision,
            profile_sha256=profile.sha256,
        )

    @property
    def release_name(self) -> str:
        return f"r{self.profile_revision}-{self.profile_sha256}"


def render_active_profile_target(target: ActiveProfileTarget) -> bytes:
    if not isinstance(target, ActiveProfileTarget):
        raise TypeError("target must be ActiveProfileTarget")
    return (
        json.dumps(
            {
                "profile_id": target.profile_id,
                "profile_revision": target.profile_revision,
                "profile_sha256": target.profile_sha256,
                "schema_version": SELECTOR_SCHEMA_VERSION,
                "selector_type": SELECTOR_TYPE,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def parse_active_profile_target(payload: bytes) -> ActiveProfileTarget:
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_SELECTOR_BYTES:
        raise _reject("malformed_profile_selector")
    try:
        parsed = json.loads(payload.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _reject("malformed_profile_selector") from exc
    if (
        not isinstance(parsed, dict)
        or set(parsed) != _SELECTOR_KEYS
        or parsed.get("schema_version") != SELECTOR_SCHEMA_VERSION
        or parsed.get("selector_type") != SELECTOR_TYPE
    ):
        raise _reject("unknown_profile_selector_schema")
    target = ActiveProfileTarget(
        profile_id=parsed.get("profile_id"),
        profile_revision=parsed.get("profile_revision"),
        profile_sha256=parsed.get("profile_sha256"),
    )
    if render_active_profile_target(target) != payload:
        raise _reject("malformed_profile_selector")
    return target


def _read_private_file(path: Path, *, expected_uid: int) -> bytes:
    try:
        before = path.lstat()
        _validate_metadata(before, directory=False, expected_uid=expected_uid)
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except ActiveProfileSelectorError:
        raise
    except OSError as exc:
        raise _reject("profile_selector_unavailable", retryable=True) from exc
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise _reject("profile_selector_permission_drift")
        _validate_metadata(opened, directory=False, expected_uid=expected_uid)
        payload = os.read(descriptor, MAX_SELECTOR_BYTES + 1)
    finally:
        os.close(descriptor)
    if not payload or len(payload) > MAX_SELECTOR_BYTES:
        raise _reject("malformed_profile_selector")
    return payload


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def load_active_profile_target(
    profile_root: Path,
    *,
    expected_uid: int | None = None,
) -> ActiveProfileTarget:
    if not isinstance(profile_root, Path) or not profile_root.is_absolute():
        raise _reject("invalid_profile_selector_path")
    uid = _uid(expected_uid)
    try:
        _validate_metadata(profile_root.lstat(), directory=True, expected_uid=uid)
    except ActiveProfileSelectorError:
        raise
    except OSError as exc:
        raise _reject("profile_selector_unavailable", retryable=True) from exc
    return parse_active_profile_target(
        _read_private_file(profile_root / SELECTOR_FILENAME, expected_uid=uid)
    )


def load_active_profile(
    profile_root: Path,
    *,
    expected_uid: int | None = None,
) -> OwnerProfile:
    uid = _uid(expected_uid)
    target = load_active_profile_target(profile_root, expected_uid=uid)
    profile = load_approved_profile(
        profile_root / "releases" / target.release_name,
        expected_sha256=target.profile_sha256,
        expected_owner_uid=uid,
    )
    if profile.profile_id != target.profile_id:
        raise _reject("profile_selector_target_drift")
    return profile


def initialize_active_profile_store(
    profile_root: Path,
    *,
    expected_uid: int | None = None,
) -> None:
    if not isinstance(profile_root, Path) or not profile_root.is_absolute():
        raise _reject("invalid_profile_selector_path")
    uid = _uid(expected_uid)
    for directory in (profile_root, profile_root / "releases"):
        try:
            os.mkdir(directory, PRIVATE_DIRECTORY_MODE)
        except FileExistsError:
            pass
        except OSError as exc:
            raise _reject("profile_selector_unavailable", retryable=True) from exc
        _validate_metadata(directory.lstat(), directory=True, expected_uid=uid)
    lock = profile_root / SELECTOR_LOCK_FILENAME
    try:
        descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT, PRIVATE_FILE_MODE)
        os.close(descriptor)
    except OSError as exc:
        raise _reject("profile_selector_unavailable", retryable=True) from exc
    _validate_metadata(lock.lstat(), directory=False, expected_uid=uid)


def install_active_profile_target(
    profile_root: Path,
    target: ActiveProfileTarget,
    *,
    expected_current: ActiveProfileTarget | None,
    expected_uid: int | None = None,
) -> bool:
    uid = _uid(expected_uid)
    release = profile_root / "releases" / target.release_name
    profile = load_approved_profile(
        release,
        expected_sha256=target.profile_sha256,
        expected_owner_uid=uid,
    )
    if profile.profile_id != target.profile_id:
        raise _reject("profile_selector_target_drift")
    lock_path = profile_root / SELECTOR_LOCK_FILENAME
    _validate_metadata(profile_root.lstat(), directory=True, expected_uid=uid)
    _validate_metadata(lock_path.lstat(), directory=False, expected_uid=uid)
    descriptor = os.open(
        lock_path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    temporary: str | None = None
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        selector = profile_root / SELECTOR_FILENAME
        if selector.exists() or selector.is_symlink():
            current = parse_active_profile_target(
                _read_private_file(selector, expected_uid=uid)
            )
            if current == target:
                return False
            if current != expected_current:
                raise _reject("profile_selector_prestate_drift")
        elif expected_current is not None:
            raise _reject("profile_selector_prestate_drift")
        payload = render_active_profile_target(target)
        file_descriptor, temporary = tempfile.mkstemp(
            prefix=f".{SELECTOR_FILENAME}.",
            dir=profile_root,
        )
        try:
            os.fchmod(file_descriptor, PRIVATE_FILE_MODE)
            view = memoryview(payload)
            while view:
                written = os.write(file_descriptor, view)
                if written < 1:
                    raise OSError("short selector write")
                view = view[written:]
            os.fsync(file_descriptor)
            _validate_metadata(
                os.fstat(file_descriptor), directory=False, expected_uid=uid
            )
        finally:
            os.close(file_descriptor)
        os.replace(temporary, selector)
        temporary = None
        _fsync_directory(profile_root)
        _read_private_file(selector, expected_uid=uid)
        return True
    except ActiveProfileSelectorError:
        raise
    except OSError as exc:
        raise _reject("profile_selector_unavailable", retryable=True) from exc
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
        os.close(descriptor)
