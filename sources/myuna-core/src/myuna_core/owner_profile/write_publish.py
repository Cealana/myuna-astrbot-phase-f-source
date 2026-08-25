from __future__ import annotations

import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
from typing import Callable

from .approval import (
    APPROVAL_DECISION,
    APPROVAL_SCOPE,
    APPROVAL_TYPE,
    verify_profile_approval,
)
from .active_selector import (
    ActiveProfileTarget,
    install_active_profile_target,
    load_active_profile_target,
)
from .contracts import PROFILE_FILENAME, RECEIPT_FILENAME, OwnerProfile, OwnerProfileError
from .lifecycle import LifecycleEvent, LifecycleState
from .lifecycle_ledger import append_lifecycle_event, load_lifecycle_ledger
from .loader import build_receipt, parse_profile_bytes, parse_receipt_bytes
from .write_runtime import PublishedProfileCandidate
from .write_store import StoredProfileCandidate


RELEASE_ROOT_MODE = 0o700
RELEASE_MODE = 0o700
FILE_MODE = 0o600
_RELEASE_FILES = frozenset({PROFILE_FILENAME, RECEIPT_FILENAME})


class OwnerProfilePublishError(OwnerProfileError):
    pass


def _reject(code: str, *, retryable: bool = False) -> OwnerProfilePublishError:
    return OwnerProfilePublishError(code, retryable=retryable)


def _uid(value: int | None) -> int:
    result = os.geteuid() if value is None else value
    if isinstance(result, bool) or not isinstance(result, int) or result < 0:
        raise _reject("profile_publish_permission_drift")
    return result


def _validate_metadata(
    metadata: os.stat_result,
    *,
    directory: bool,
    expected_uid: int,
) -> None:
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    expected_mode = RELEASE_MODE if directory else FILE_MODE
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not expected_type(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != expected_mode
        or metadata.st_uid != expected_uid
        or (not directory and metadata.st_nlink != 1)
    ):
        raise _reject("profile_publish_permission_drift")


def initialize_profile_release_store(
    root: Path,
    *,
    expected_uid: int | None = None,
) -> None:
    if not isinstance(root, Path) or not root.is_absolute():
        raise _reject("profile_publish_path_rejected")
    uid = _uid(expected_uid)
    try:
        os.mkdir(root, RELEASE_ROOT_MODE)
    except FileExistsError:
        pass
    except OSError as exc:
        raise _reject("profile_publish_unavailable", retryable=True) from exc
    _validate_metadata(root.lstat(), directory=True, expected_uid=uid)
    lock = root / "publish.lock"
    try:
        descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT, FILE_MODE)
        os.close(descriptor)
    except OSError as exc:
        raise _reject("profile_publish_unavailable", retryable=True) from exc
    _validate_metadata(lock.lstat(), directory=False, expected_uid=uid)


def build_channel_approval_bytes(profile: OwnerProfile) -> bytes:
    payload = {
        "approval_scope": APPROVAL_SCOPE,
        "approval_type": APPROVAL_TYPE,
        "decision": APPROVAL_DECISION,
        "profile_id": profile.profile_id,
        "profile_revision": profile.profile_revision,
        "profile_schema_version": 1,
        "profile_sha256": profile.sha256,
        "schema_version": 1,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"
    verify_profile_approval(profile, encoded)
    return encoded


def build_release_receipt_bytes(profile_bytes: bytes) -> bytes:
    encoded = json.dumps(
        build_receipt(profile_bytes),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"
    receipt = parse_receipt_bytes(encoded)
    profile = parse_profile_bytes(profile_bytes)
    if receipt.profile_sha256 != profile.sha256:
        raise _reject("profile_publish_digest_mismatch")
    return encoded


def _read_file(path: Path, *, maximum: int, expected_uid: int) -> bytes:
    try:
        before = path.lstat()
        _validate_metadata(before, directory=False, expected_uid=expected_uid)
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OwnerProfilePublishError:
        raise
    except OSError as exc:
        raise _reject("profile_publish_unavailable", retryable=True) from exc
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise _reject("profile_publish_permission_drift")
        _validate_metadata(opened, directory=False, expected_uid=expected_uid)
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(4096, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    if not payload or len(payload) > maximum:
        raise _reject("profile_publish_release_drift")
    return payload


def _verify_release(
    release: Path,
    *,
    profile_bytes: bytes,
    receipt_bytes: bytes,
    expected_uid: int,
) -> None:
    _validate_metadata(release.lstat(), directory=True, expected_uid=expected_uid)
    try:
        names = frozenset(os.listdir(release))
    except OSError as exc:
        raise _reject("profile_publish_unavailable", retryable=True) from exc
    if names != _RELEASE_FILES:
        raise _reject("profile_publish_release_drift")
    if (
        _read_file(
            release / PROFILE_FILENAME,
            maximum=len(profile_bytes),
            expected_uid=expected_uid,
        )
        != profile_bytes
        or _read_file(
            release / RECEIPT_FILENAME,
            maximum=len(receipt_bytes),
            expected_uid=expected_uid,
        )
        != receipt_bytes
    ):
        raise _reject("profile_publish_release_drift")


def _write_file(path: Path, payload: bytes, *, expected_uid: int) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            FILE_MODE,
        )
    except OSError as exc:
        raise _reject("profile_publish_unavailable", retryable=True) from exc
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short Profile release write")
            view = view[written:]
        os.fsync(descriptor)
        _validate_metadata(os.fstat(descriptor), directory=False, expected_uid=expected_uid)
    except OSError as exc:
        raise _reject("profile_publish_unavailable", retryable=True) from exc
    finally:
        os.close(descriptor)


def _pending_entries(root: Path) -> tuple[str, ...]:
    try:
        return tuple(
            sorted(name for name in os.listdir(root) if name.startswith(".pending-"))
        )
    except OSError as exc:
        raise _reject("profile_publish_unavailable", retryable=True) from exc


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def install_immutable_profile_release(
    root: Path,
    profile_bytes: bytes,
    *,
    expected_uid: int | None = None,
    failpoint: Callable[[str], None] | None = None,
) -> tuple[Path, bool]:
    uid = _uid(expected_uid)
    profile = parse_profile_bytes(profile_bytes)
    receipt_bytes = build_release_receipt_bytes(profile_bytes)
    release_name = f"r{profile.profile_revision}-{profile.sha256}"
    destination = root / release_name
    pending = root / f".pending-{release_name}"
    _validate_metadata(root.lstat(), directory=True, expected_uid=uid)
    lock_path = root / "publish.lock"
    _validate_metadata(lock_path.lstat(), directory=False, expected_uid=uid)
    descriptor = os.open(
        lock_path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        pending_names = _pending_entries(root)
        if pending_names:
            if pending_names != (pending.name,):
                raise _reject("profile_publish_recovery_required", retryable=True)
            _verify_release(
                pending,
                profile_bytes=profile_bytes,
                receipt_bytes=receipt_bytes,
                expected_uid=uid,
            )
            if destination.exists():
                _verify_release(
                    destination,
                    profile_bytes=profile_bytes,
                    receipt_bytes=receipt_bytes,
                    expected_uid=uid,
                )
                raise _reject("profile_publish_recovery_required", retryable=True)
            os.rename(pending, destination)
            _fsync_directory(root)
            return destination, False
        if destination.exists():
            _verify_release(
                destination,
                profile_bytes=profile_bytes,
                receipt_bytes=receipt_bytes,
                expected_uid=uid,
            )
            return destination, True
        try:
            os.mkdir(pending, RELEASE_MODE)
        except OSError as exc:
            raise _reject("profile_publish_unavailable", retryable=True) from exc
        _validate_metadata(pending.lstat(), directory=True, expected_uid=uid)
        _write_file(pending / PROFILE_FILENAME, profile_bytes, expected_uid=uid)
        _write_file(pending / RECEIPT_FILENAME, receipt_bytes, expected_uid=uid)
        _fsync_directory(pending)
        if failpoint is not None:
            failpoint("release_files_fsynced")
        os.rename(pending, destination)
        _fsync_directory(root)
        return destination, False
    finally:
        os.close(descriptor)


def _event(
    state: LifecycleState,
    *,
    event_type: str,
    event_id: str,
    record: StoredProfileCandidate,
    confirmation_sha256: str | None,
) -> LifecycleEvent:
    return LifecycleEvent(
        event_type=event_type,
        event_id=event_id,
        sequence=state.last_sequence + 1,
        previous_event_sha256=state.last_event_sha256,
        profile_id=parse_profile_bytes(record.target_profile_bytes).profile_id,
        base_revision=record.base_revision,
        base_sha256=record.base_sha256,
        target_revision=record.target_revision,
        target_sha256=record.target_sha256,
        confirmation_sha256=confirmation_sha256,
        reason_category=(
            "myuna_analyzed_candidate"
            if event_type == "candidate_prepared"
            else "owner_confirmed"
        ),
    )


def publish_stored_profile_candidate(
    *,
    profile_root: Path,
    lifecycle_ledger: Path,
    active_profile: OwnerProfile,
    record: StoredProfileCandidate,
    expected_uid: int | None = None,
    failpoint: Callable[[str], None] | None = None,
) -> PublishedProfileCandidate:
    uid = _uid(expected_uid)
    release_root = profile_root / "releases"
    target = parse_profile_bytes(record.target_profile_bytes)
    active_target = ActiveProfileTarget.from_profile(active_profile)
    selected_target = load_active_profile_target(profile_root, expected_uid=uid)
    if selected_target != active_target:
        raise _reject("profile_publish_selector_drift")
    base_target = ActiveProfileTarget(
        profile_id=target.profile_id,
        profile_revision=record.base_revision,
        profile_sha256=record.base_sha256,
    )
    target_selector = ActiveProfileTarget.from_profile(target)
    state = load_lifecycle_ledger(
        lifecycle_ledger,
        profile_id=active_profile.profile_id,
        expected_uid=uid,
    )
    existing = state.revisions.get(record.target_revision)
    if existing is not None and existing.status == "published":
        if (
            state.active_revision != record.target_revision
            or existing.profile_sha256 != record.target_sha256
            or active_target not in {base_target, target_selector}
        ):
            raise _reject("profile_publish_state_drift")
        install_immutable_profile_release(
            release_root,
            record.target_profile_bytes,
            expected_uid=uid,
        )
        install_active_profile_target(
            profile_root,
            target_selector,
            expected_current=base_target,
            expected_uid=uid,
        )
        return PublishedProfileCandidate(
            target_revision=target.profile_revision,
            target_sha256=target.sha256,
            already_published=True,
        )
    base_state = state.revisions.get(record.base_revision)
    if (
        active_profile.profile_revision != record.base_revision
        or active_profile.sha256 != record.base_sha256
        or state.active_revision != record.base_revision
        or base_state is None
        or base_state.profile_sha256 != record.base_sha256
        or target.profile_revision != record.target_revision
        or target.sha256 != record.target_sha256
    ):
        raise _reject("profile_publish_base_drift")
    install_immutable_profile_release(
        release_root,
        record.target_profile_bytes,
        expected_uid=uid,
        failpoint=failpoint,
    )
    approval_bytes = build_channel_approval_bytes(target)
    confirmation_sha256 = sha256(approval_bytes).hexdigest()
    state = load_lifecycle_ledger(
        lifecycle_ledger,
        profile_id=target.profile_id,
        expected_uid=uid,
    )
    record_state = state.revisions.get(record.target_revision)
    prefix = record.record_sha256[:24]
    if record_state is None:
        state = append_lifecycle_event(
            lifecycle_ledger,
            _event(
                state,
                event_type="candidate_prepared",
                event_id=f"p07c-prepared-{prefix}",
                record=record,
                confirmation_sha256=None,
            ),
            expected_uid=uid,
        )
        record_state = state.revisions[record.target_revision]
    if record_state.profile_sha256 != record.target_sha256:
        raise _reject("profile_publish_state_drift")
    if record_state.status == "prepared":
        state = append_lifecycle_event(
            lifecycle_ledger,
            _event(
                state,
                event_type="owner_confirmed",
                event_id=f"p07c-confirmed-{prefix}",
                record=record,
                confirmation_sha256=confirmation_sha256,
            ),
            expected_uid=uid,
        )
        record_state = state.revisions[record.target_revision]
    if record_state.status == "confirmed":
        state = append_lifecycle_event(
            lifecycle_ledger,
            _event(
                state,
                event_type="published",
                event_id=f"p07c-published-{prefix}",
                record=record,
                confirmation_sha256=confirmation_sha256,
            ),
            expected_uid=uid,
        )
        record_state = state.revisions[record.target_revision]
    if record_state.status != "published" or state.active_revision != record.target_revision:
        raise _reject("profile_publish_state_drift")
    if failpoint is not None:
        failpoint("lifecycle_published")
    install_active_profile_target(
        profile_root,
        target_selector,
        expected_current=active_target,
        expected_uid=uid,
    )
    return PublishedProfileCandidate(
        target_revision=target.profile_revision,
        target_sha256=target.sha256,
    )


def publish_audit_projection(
    *,
    outcome: str,
    target_revision: int = 0,
    already_published: bool = False,
    error_category: str | None = None,
) -> dict[str, object]:
    if outcome not in {"accepted", "rejected", "failed"}:
        raise ValueError("unsupported publish outcome")
    return {
        "event_namespace": "owner_profile_candidate_publish_v1",
        "outcome": outcome,
        "target_revision": target_revision,
        "already_published": already_published,
        "release_created": outcome == "accepted" and not already_published,
        "memory_write_performed": outcome == "accepted",
        "raw_input_recorded": False,
        "candidate_content_recorded": False,
        "profile_content_recorded": False,
        "identity_recorded": False,
        "confirmation_code_recorded": False,
        "profile_digest_recorded": False,
        "profile_path_recorded": False,
        "legacy_namespace_written": False,
        "error_category": error_category,
    }
