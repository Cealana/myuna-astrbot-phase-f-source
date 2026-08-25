from __future__ import annotations

import fcntl
import os
from pathlib import Path
import re
import stat

from .lifecycle import (
    MAX_EVENT_BYTES,
    MAX_EVENTS,
    LifecycleEvent,
    LifecycleState,
    OwnerProfileLifecycleError,
    apply_lifecycle_event,
    replay_lifecycle,
)


_EVENT_FILE = re.compile(r"^([0-9]{6})-([0-9a-f]{64})\.json$")
_PENDING_FILE = re.compile(r"^\.pending-([0-9]{6})-([0-9a-f]{64})\.json$")


def _reject(code: str, *, retryable: bool = False) -> OwnerProfileLifecycleError:
    return OwnerProfileLifecycleError(code, retryable=retryable)


def _validate_uid(value: int | None) -> int:
    uid = os.geteuid() if value is None else value
    if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
        raise _reject("lifecycle_permission_drift")
    return uid


def _validate_metadata(
    metadata: os.stat_result,
    *,
    directory: bool,
    expected_uid: int,
    allowed_nlinks: frozenset[int] = frozenset({1}),
) -> None:
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    expected_mode = 0o700 if directory else 0o600
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not expected_type(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != expected_mode
        or (not directory and metadata.st_nlink not in allowed_nlinks)
        or metadata.st_uid != expected_uid
    ):
        raise _reject("lifecycle_permission_drift")


def initialize_lifecycle_ledger(
    directory: Path,
    *,
    expected_uid: int | None = None,
) -> None:
    if not isinstance(directory, Path) or not directory.is_absolute():
        raise _reject("lifecycle_path_rejected")
    uid = _validate_uid(expected_uid)
    try:
        os.mkdir(directory, 0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise _reject("lifecycle_unavailable", retryable=True) from exc
    try:
        metadata = directory.lstat()
    except OSError as exc:
        raise _reject("lifecycle_unavailable", retryable=True) from exc
    _validate_metadata(metadata, directory=True, expected_uid=uid)


def _open_ledger_directory(directory: Path, *, expected_uid: int) -> int:
    if not isinstance(directory, Path) or not directory.is_absolute():
        raise _reject("lifecycle_path_rejected")
    try:
        before = directory.lstat()
        _validate_metadata(before, directory=True, expected_uid=expected_uid)
        descriptor = os.open(
            directory,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OwnerProfileLifecycleError:
        raise
    except OSError as exc:
        raise _reject("lifecycle_unavailable", retryable=True) from exc
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise _reject("lifecycle_permission_drift")
        _validate_metadata(opened, directory=True, expected_uid=expected_uid)
    except OwnerProfileLifecycleError:
        os.close(descriptor)
        raise
    except OSError as exc:
        os.close(descriptor)
        raise _reject("lifecycle_unavailable", retryable=True) from exc
    return descriptor


def _lock(descriptor: int, operation: int) -> None:
    try:
        fcntl.flock(descriptor, operation)
    except OSError as exc:
        raise _reject("lifecycle_unavailable", retryable=True) from exc


def _read_event_file(
    directory_descriptor: int,
    filename: str,
    *,
    expected_uid: int,
    allowed_nlinks: frozenset[int] = frozenset({1}),
) -> bytes:
    try:
        before = os.stat(
            filename, dir_fd=directory_descriptor, follow_symlinks=False
        )
        _validate_metadata(
            before,
            directory=False,
            expected_uid=expected_uid,
            allowed_nlinks=allowed_nlinks,
        )
        descriptor = os.open(
            filename,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
    except FileNotFoundError as exc:
        raise _reject("lifecycle_file_missing", retryable=True) from exc
    except OwnerProfileLifecycleError:
        raise
    except OSError as exc:
        raise _reject("lifecycle_unavailable", retryable=True) from exc
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise _reject("lifecycle_permission_drift")
        _validate_metadata(
            opened,
            directory=False,
            expected_uid=expected_uid,
            allowed_nlinks=allowed_nlinks,
        )
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_EVENT_BYTES:
            chunk = os.read(descriptor, min(4096, MAX_EVENT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        payload = b"".join(chunks)
    except OwnerProfileLifecycleError:
        raise
    except OSError as exc:
        raise _reject("lifecycle_unavailable", retryable=True) from exc
    finally:
        os.close(descriptor)
    if not payload or len(payload) > MAX_EVENT_BYTES:
        raise _reject("invalid_event")
    return payload


def _event_entries(
    directory_descriptor: int,
    *,
    ignored_pending_name: str | None = None,
) -> tuple[tuple[str, int, str], ...]:
    try:
        names = os.listdir(directory_descriptor)
    except OSError as exc:
        raise _reject("lifecycle_unavailable", retryable=True) from exc
    entries: list[tuple[str, int, str]] = []
    for name in names:
        match = _EVENT_FILE.fullmatch(name)
        if _PENDING_FILE.fullmatch(name) is not None:
            if name == ignored_pending_name:
                continue
            raise _reject("lifecycle_recovery_required", retryable=True)
        if match is None:
            raise _reject("lifecycle_permission_drift")
        entries.append((name, int(match.group(1)), match.group(2)))
    if len(entries) > MAX_EVENTS:
        raise _reject("event_chain_rejected")
    return tuple(sorted(entries, key=lambda item: item[0]))


def _load_locked(
    directory_descriptor: int,
    *,
    profile_id: str,
    expected_uid: int,
    ignored_pending_name: str | None = None,
    allowed_hardlinked_event_name: str | None = None,
) -> LifecycleState:
    payloads: list[bytes] = []
    for expected_sequence, (name, sequence, expected_digest) in enumerate(
        _event_entries(
            directory_descriptor,
            ignored_pending_name=ignored_pending_name,
        ),
        start=1,
    ):
        if sequence != expected_sequence:
            raise _reject("event_chain_rejected")
        payload = _read_event_file(
            directory_descriptor,
            name,
            expected_uid=expected_uid,
            allowed_nlinks=(
                frozenset({1, 2})
                if name == allowed_hardlinked_event_name
                else frozenset({1})
            ),
        )
        parsed = LifecycleEvent.from_bytes(payload)
        if parsed.sequence != sequence or parsed.sha256 != expected_digest:
            raise _reject("event_chain_rejected")
        payloads.append(payload)
    return replay_lifecycle(profile_id, tuple(payloads))


def load_lifecycle_ledger(
    directory: Path,
    *,
    profile_id: str,
    expected_uid: int | None = None,
) -> LifecycleState:
    uid = _validate_uid(expected_uid)
    descriptor = _open_ledger_directory(directory, expected_uid=uid)
    try:
        _lock(descriptor, fcntl.LOCK_SH)
        return _load_locked(
            descriptor,
            profile_id=profile_id,
            expected_uid=uid,
        )
    finally:
        os.close(descriptor)


def _recover_exact_pending(
    directory_descriptor: int,
    *,
    filename: str,
    payload: bytes,
    expected_uid: int,
    profile_id: str,
) -> LifecycleState | None:
    pending_name = ".pending-" + filename
    try:
        names = os.listdir(directory_descriptor)
    except OSError as exc:
        raise _reject("lifecycle_unavailable", retryable=True) from exc
    pending_names = {name for name in names if _PENDING_FILE.fullmatch(name)}
    if pending_names - {pending_name}:
        raise _reject("lifecycle_recovery_required", retryable=True)
    if pending_name not in pending_names:
        return None
    pending_payload = _read_event_file(
        directory_descriptor,
        pending_name,
        expected_uid=expected_uid,
        allowed_nlinks=frozenset({1, 2}),
    )
    if pending_payload != payload:
        raise _reject("event_chain_rejected")
    published = False
    try:
        published_payload = _read_event_file(
            directory_descriptor,
            filename,
            expected_uid=expected_uid,
            allowed_nlinks=frozenset({1, 2}),
        )
    except OwnerProfileLifecycleError as exc:
        if exc.code != "lifecycle_file_missing":
            raise
    else:
        published = True
        if published_payload != payload:
            raise _reject("event_chain_rejected")
    state = _load_locked(
        directory_descriptor,
        profile_id=profile_id,
        expected_uid=expected_uid,
        ignored_pending_name=pending_name,
        allowed_hardlinked_event_name=filename if published else None,
    )
    if not published:
        next_state = apply_lifecycle_event(state, LifecycleEvent.from_bytes(payload))
        try:
            os.link(
                pending_name,
                filename,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise _reject("event_chain_rejected") from exc
        except OSError as link_error:
            raise _reject("lifecycle_unavailable", retryable=True) from link_error
    else:
        next_state = state
    try:
        os.unlink(pending_name, dir_fd=directory_descriptor)
        os.fsync(directory_descriptor)
    except OSError as exc:
        raise _reject("lifecycle_unavailable", retryable=True) from exc
    return next_state


def append_lifecycle_event(
    directory: Path,
    event: LifecycleEvent,
    *,
    expected_uid: int | None = None,
) -> LifecycleState:
    uid = _validate_uid(expected_uid)
    filename = f"{event.sequence:06d}-{event.sha256}.json"
    payload = event.canonical_bytes()
    descriptor = _open_ledger_directory(directory, expected_uid=uid)
    try:
        _lock(descriptor, fcntl.LOCK_EX)
        recovered = _recover_exact_pending(
            descriptor,
            filename=filename,
            payload=payload,
            expected_uid=uid,
            profile_id=event.profile_id,
        )
        if recovered is not None:
            return recovered
        current = _load_locked(
            descriptor, profile_id=event.profile_id, expected_uid=uid
        )
        try:
            existing = _read_event_file(
                descriptor,
                filename,
                expected_uid=uid,
            )
        except OwnerProfileLifecycleError as exc:
            if exc.code != "lifecycle_file_missing":
                raise
        else:
            if existing != payload:
                raise _reject("event_chain_rejected")
            return _load_locked(
                descriptor,
                profile_id=event.profile_id,
                expected_uid=uid,
            )

        next_state = apply_lifecycle_event(current, event)
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        pending_name = ".pending-" + filename
        try:
            event_descriptor = os.open(
                pending_name,
                flags,
                0o600,
                dir_fd=descriptor,
            )
        except FileExistsError as exc:
            raise _reject("lifecycle_recovery_required", retryable=True) from exc
        except OSError as exc:
            raise _reject("lifecycle_unavailable", retryable=True) from exc
        try:
            os.fchmod(event_descriptor, 0o600)
            view = memoryview(payload)
            while view:
                written = os.write(event_descriptor, view)
                if written < 1:
                    raise _reject("lifecycle_unavailable", retryable=True)
                view = view[written:]
            os.fsync(event_descriptor)
        except OSError as exc:
            raise _reject("lifecycle_unavailable", retryable=True) from exc
        finally:
            os.close(event_descriptor)
        published_state = _recover_exact_pending(
            descriptor,
            filename=filename,
            payload=payload,
            expected_uid=uid,
            profile_id=event.profile_id,
        )
        if published_state != next_state:
            raise _reject("event_chain_rejected")
        return published_state
    finally:
        os.close(descriptor)
