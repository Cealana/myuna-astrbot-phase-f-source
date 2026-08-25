from __future__ import annotations

from base64 import b64decode, b64encode
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat

from .contracts import OwnerProfileError
from .loader import parse_profile_bytes
from .write_candidate import PreparedProfileCandidate, validate_confirmation_code


STORE_SCHEMA_VERSION = 1
RECORD_TYPE = "owner_profile_pending_candidate_v1"
POINTER_TYPE = "owner_profile_candidate_pointer_v1"
MAX_RECORD_BYTES = 131_072
MAX_POINTER_BYTES = 4_096
MAX_TTL = timedelta(days=7)
MIN_TTL = timedelta(minutes=5)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CANDIDATE_FILE = re.compile(r"^([0-9a-f]{64})\.json$")
_POINTER_FILE = re.compile(r"^([0-9a-f]{64})\.json$")
_PENDING_POINTER = re.compile(r"^\.pending-([0-9a-f]{64})-([0-9a-f]{64})\.json$")
_RECORD_KEYS = {
    "base_revision",
    "base_sha256",
    "change_summary",
    "confirmation_code",
    "created_at",
    "expires_at",
    "record_type",
    "schema_version",
    "scope_sha256",
    "target_profile_base64",
    "target_revision",
    "target_sha256",
}
_POINTER_KEYS = {
    "candidate_record_sha256",
    "consumed_at",
    "expires_at",
    "pointer_type",
    "schema_version",
    "scope_sha256",
    "state",
}


class OwnerProfileCandidateStoreError(OwnerProfileError):
    pass


def _reject(code: str, *, retryable: bool = False) -> OwnerProfileCandidateStoreError:
    return OwnerProfileCandidateStoreError(code, retryable=retryable)


def _utc(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise _reject(f"candidate_{label}_invalid")
    return value.astimezone(timezone.utc)


def _parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise _reject("malformed_candidate_record")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _reject("malformed_candidate_record") from exc
    return _utc(parsed, label)


def _digest(value: object) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _reject("malformed_candidate_record")
    return value


def candidate_scope_sha256(
    *,
    channel_kind: str,
    conversation_kind: str,
    authority_level: str,
    binding_id: str,
    principal_id: str,
    namespace_id: str,
    conversation_id: str,
) -> str:
    if (
        channel_kind != "astrbot_telegram"
        or conversation_kind != "private"
        or authority_level != "owner"
    ):
        raise _reject("candidate_scope_rejected")
    values = (binding_id, principal_id, namespace_id, conversation_id)
    if any(
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or "\x00" in value
        for value in values
    ):
        raise _reject("candidate_scope_rejected")
    payload = json.dumps(
        {
            "binding_id": binding_id,
            "channel_kind": channel_kind,
            "conversation_id": conversation_id,
            "namespace_id": namespace_id,
            "principal_id": principal_id,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return sha256(b"myuna-owner-profile-candidate-scope-v1\0" + payload).hexdigest()


@dataclass(frozen=True, slots=True)
class StoredProfileCandidate:
    record_sha256: str
    scope_sha256: str
    base_revision: int
    base_sha256: str
    target_revision: int
    target_sha256: str
    target_profile_bytes: bytes
    confirmation_code: str
    created_at: datetime
    expires_at: datetime
    added_sections: int
    updated_sections: int
    removed_sections: int


@dataclass(frozen=True, slots=True)
class CandidatePointer:
    scope_sha256: str
    candidate_record_sha256: str
    state: str
    expires_at: datetime
    consumed_at: datetime | None


def _record_payload(
    candidate: PreparedProfileCandidate,
    *,
    scope_sha256: str,
    created_at: datetime,
    expires_at: datetime,
) -> bytes:
    _digest(scope_sha256)
    payload = {
        "base_revision": candidate.base_revision,
        "base_sha256": candidate.base_sha256,
        "change_summary": {
            "added_sections": candidate.summary.added_sections,
            "removed_sections": candidate.summary.removed_sections,
            "updated_sections": candidate.summary.updated_sections,
        },
        "confirmation_code": candidate.confirmation_code,
        "created_at": created_at.isoformat(timespec="microseconds"),
        "expires_at": expires_at.isoformat(timespec="microseconds"),
        "record_type": RECORD_TYPE,
        "schema_version": STORE_SCHEMA_VERSION,
        "scope_sha256": scope_sha256,
        "target_profile_base64": b64encode(candidate.target_bytes).decode("ascii"),
        "target_revision": candidate.target.profile_revision,
        "target_sha256": candidate.target.sha256,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"
    if len(encoded) > MAX_RECORD_BYTES:
        raise _reject("candidate_record_oversize")
    return encoded


def parse_candidate_record(payload: bytes) -> StoredProfileCandidate:
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_RECORD_BYTES:
        raise _reject("candidate_record_oversize")
    try:
        parsed = json.loads(payload.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _reject("malformed_candidate_record") from exc
    if (
        not isinstance(parsed, dict)
        or set(parsed) != _RECORD_KEYS
        or parsed["schema_version"] != STORE_SCHEMA_VERSION
        or parsed["record_type"] != RECORD_TYPE
    ):
        raise _reject("malformed_candidate_record")
    created_at = _parse_time(parsed["created_at"], "created_at")
    expires_at = _parse_time(parsed["expires_at"], "expiry")
    if not MIN_TTL <= expires_at - created_at <= MAX_TTL:
        raise _reject("malformed_candidate_record")
    base_revision = parsed["base_revision"]
    target_revision = parsed["target_revision"]
    if (
        isinstance(base_revision, bool)
        or not isinstance(base_revision, int)
        or base_revision < 1
        or isinstance(target_revision, bool)
        or target_revision != base_revision + 1
    ):
        raise _reject("malformed_candidate_record")
    confirmation_code = validate_confirmation_code(parsed["confirmation_code"])
    try:
        target_bytes = b64decode(parsed["target_profile_base64"], validate=True)
    except (TypeError, ValueError) as exc:
        raise _reject("malformed_candidate_record") from exc
    target = parse_profile_bytes(target_bytes)
    target_sha256 = _digest(parsed["target_sha256"])
    if target.profile_revision != target_revision or target.sha256 != target_sha256:
        raise _reject("candidate_digest_mismatch")
    if confirmation_code != target_sha256[:12].upper():
        raise _reject("candidate_digest_mismatch")
    summary = parsed["change_summary"]
    if (
        not isinstance(summary, dict)
        or set(summary) != {"added_sections", "updated_sections", "removed_sections"}
        or any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in summary.values())
        or summary["removed_sections"] != 0
        or summary["added_sections"] + summary["updated_sections"] < 1
    ):
        raise _reject("malformed_candidate_record")
    return StoredProfileCandidate(
        record_sha256=sha256(payload).hexdigest(),
        scope_sha256=_digest(parsed["scope_sha256"]),
        base_revision=base_revision,
        base_sha256=_digest(parsed["base_sha256"]),
        target_revision=target_revision,
        target_sha256=target_sha256,
        target_profile_bytes=target_bytes,
        confirmation_code=confirmation_code,
        created_at=created_at,
        expires_at=expires_at,
        added_sections=summary["added_sections"],
        updated_sections=summary["updated_sections"],
        removed_sections=summary["removed_sections"],
    )


def _pointer_payload(pointer: CandidatePointer) -> bytes:
    payload = {
        "candidate_record_sha256": pointer.candidate_record_sha256,
        "consumed_at": (
            pointer.consumed_at.isoformat(timespec="microseconds")
            if pointer.consumed_at is not None
            else None
        ),
        "expires_at": pointer.expires_at.isoformat(timespec="microseconds"),
        "pointer_type": POINTER_TYPE,
        "schema_version": STORE_SCHEMA_VERSION,
        "scope_sha256": pointer.scope_sha256,
        "state": pointer.state,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"
    if len(encoded) > MAX_POINTER_BYTES:
        raise _reject("candidate_pointer_oversize")
    return encoded


def parse_candidate_pointer(payload: bytes) -> CandidatePointer:
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_POINTER_BYTES:
        raise _reject("candidate_pointer_oversize")
    try:
        parsed = json.loads(payload.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _reject("malformed_candidate_pointer") from exc
    if (
        not isinstance(parsed, dict)
        or set(parsed) != _POINTER_KEYS
        or parsed["schema_version"] != STORE_SCHEMA_VERSION
        or parsed["pointer_type"] != POINTER_TYPE
        or parsed["state"] not in {"pending", "consumed", "cancelled"}
    ):
        raise _reject("malformed_candidate_pointer")
    consumed = parsed["consumed_at"]
    consumed_at = None if consumed is None else _parse_time(consumed, "consumed_at")
    if (parsed["state"] in {"consumed", "cancelled"}) != (consumed_at is not None):
        raise _reject("malformed_candidate_pointer")
    return CandidatePointer(
        scope_sha256=_digest(parsed["scope_sha256"]),
        candidate_record_sha256=_digest(parsed["candidate_record_sha256"]),
        state=parsed["state"],
        expires_at=_parse_time(parsed["expires_at"], "expiry"),
        consumed_at=consumed_at,
    )


def _validate_metadata(
    metadata: os.stat_result,
    *,
    directory: bool,
    expected_uid: int,
) -> None:
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    expected_mode = 0o700 if directory else 0o600
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not expected_type(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != expected_mode
        or metadata.st_uid != expected_uid
        or (not directory and metadata.st_nlink != 1)
    ):
        raise _reject("candidate_store_permission_drift")


def _uid(value: int | None) -> int:
    result = os.geteuid() if value is None else value
    if isinstance(result, bool) or not isinstance(result, int) or result < 0:
        raise _reject("candidate_store_permission_drift")
    return result


def initialize_candidate_store(root: Path, *, expected_uid: int | None = None) -> None:
    if not isinstance(root, Path) or not root.is_absolute():
        raise _reject("candidate_store_path_rejected")
    uid = _uid(expected_uid)
    for directory in (root, root / "candidates", root / "scopes"):
        try:
            os.mkdir(directory, 0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise _reject("candidate_store_unavailable", retryable=True) from exc
        _validate_metadata(directory.lstat(), directory=True, expected_uid=uid)
    lock_path = root / "store.lock"
    try:
        descriptor = os.open(
            lock_path,
            os.O_WRONLY | os.O_CREAT | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        os.close(descriptor)
        _validate_metadata(lock_path.lstat(), directory=False, expected_uid=uid)
    except OwnerProfileCandidateStoreError:
        raise
    except OSError as exc:
        raise _reject("candidate_store_unavailable", retryable=True) from exc


def validate_candidate_store(root: Path, *, expected_uid: int | None = None) -> None:
    """Validate an existing store without creating or rewriting any entry."""

    if not isinstance(root, Path) or not root.is_absolute():
        raise _reject("candidate_store_path_rejected")
    uid = _uid(expected_uid)
    descriptor = _open_lock(root, expected_uid=uid, exclusive=False)
    os.close(descriptor)


def _open_lock(root: Path, *, expected_uid: int, exclusive: bool) -> int:
    for directory in (root, root / "candidates", root / "scopes"):
        _validate_metadata(directory.lstat(), directory=True, expected_uid=expected_uid)
    lock_path = root / "store.lock"
    _validate_metadata(lock_path.lstat(), directory=False, expected_uid=expected_uid)
    try:
        descriptor = os.open(
            lock_path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        _validate_metadata(os.fstat(descriptor), directory=False, expected_uid=expected_uid)
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        return descriptor
    except OwnerProfileCandidateStoreError:
        raise
    except OSError as exc:
        raise _reject("candidate_store_unavailable", retryable=True) from exc


def _read_file(path: Path, *, maximum: int, expected_uid: int) -> bytes:
    try:
        before = path.lstat()
        _validate_metadata(before, directory=False, expected_uid=expected_uid)
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except FileNotFoundError:
        raise
    except OwnerProfileCandidateStoreError:
        raise
    except OSError as exc:
        raise _reject("candidate_store_unavailable", retryable=True) from exc
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise _reject("candidate_store_permission_drift")
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
        raise _reject("candidate_store_record_oversize")
    return payload


def _write_new(path: Path, payload: bytes, *, expected_uid: int) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError:
        existing = _read_file(path, maximum=len(payload), expected_uid=expected_uid)
        if existing != payload:
            raise _reject("candidate_digest_mismatch")
        return
    except OSError as exc:
        raise _reject("candidate_store_unavailable", retryable=True) from exc
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short candidate write")
            view = view[written:]
        os.fsync(descriptor)
        _validate_metadata(os.fstat(descriptor), directory=False, expected_uid=expected_uid)
    except OSError as exc:
        raise _reject("candidate_store_unavailable", retryable=True) from exc
    finally:
        os.close(descriptor)


def _assert_pointer_directory_clean(scopes: Path) -> None:
    try:
        names = os.listdir(scopes)
    except OSError as exc:
        raise _reject("candidate_store_unavailable", retryable=True) from exc
    if any(_PENDING_POINTER.fullmatch(name) for name in names):
        raise _reject("candidate_store_recovery_required", retryable=True)
    if any(_POINTER_FILE.fullmatch(name) is None for name in names):
        raise _reject("candidate_store_permission_drift")


def _write_pointer_atomic(
    scopes: Path,
    pointer: CandidatePointer,
    *,
    expected_uid: int,
) -> None:
    _assert_pointer_directory_clean(scopes)
    payload = _pointer_payload(pointer)
    payload_sha256 = sha256(payload).hexdigest()
    pending = scopes / f".pending-{pointer.scope_sha256}-{payload_sha256}.json"
    target = scopes / f"{pointer.scope_sha256}.json"
    _write_new(pending, payload, expected_uid=expected_uid)
    try:
        os.replace(pending, target)
        directory_descriptor = os.open(
            scopes,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as exc:
        raise _reject("candidate_store_unavailable", retryable=True) from exc


def _load_pointer(
    scopes: Path,
    *,
    scope_sha256: str,
    expected_uid: int,
) -> CandidatePointer:
    _assert_pointer_directory_clean(scopes)
    payload = _read_file(
        scopes / f"{scope_sha256}.json",
        maximum=MAX_POINTER_BYTES,
        expected_uid=expected_uid,
    )
    pointer = parse_candidate_pointer(payload)
    if pointer.scope_sha256 != scope_sha256:
        raise _reject("candidate_scope_rejected")
    return pointer


def stage_profile_candidate(
    root: Path,
    candidate: PreparedProfileCandidate,
    *,
    scope_sha256: str,
    now: datetime,
    ttl: timedelta = MAX_TTL,
    expected_uid: int | None = None,
) -> StoredProfileCandidate:
    uid = _uid(expected_uid)
    current = _utc(now, "created_at")
    if not MIN_TTL <= ttl <= MAX_TTL:
        raise _reject("candidate_expiry_invalid")
    expires = current + ttl
    payload = _record_payload(
        candidate,
        scope_sha256=_digest(scope_sha256),
        created_at=current,
        expires_at=expires,
    )
    record = parse_candidate_record(payload)
    lock = _open_lock(root, expected_uid=uid, exclusive=True)
    try:
        scopes = root / "scopes"
        candidates = root / "candidates"
        _assert_pointer_directory_clean(scopes)
        try:
            existing = _load_pointer(
                scopes,
                scope_sha256=scope_sha256,
                expected_uid=uid,
            )
        except FileNotFoundError:
            existing = None
        if existing is not None and existing.state == "pending" and current < existing.expires_at:
            if existing.candidate_record_sha256 == record.record_sha256:
                return record
            raise _reject("candidate_pending_exists")
        _write_new(
            candidates / f"{record.record_sha256}.json",
            payload,
            expected_uid=uid,
        )
        _write_pointer_atomic(
            scopes,
            CandidatePointer(
                scope_sha256=scope_sha256,
                candidate_record_sha256=record.record_sha256,
                state="pending",
                expires_at=expires,
                consumed_at=None,
            ),
            expected_uid=uid,
        )
        return record
    finally:
        os.close(lock)


def load_pending_candidate(
    root: Path,
    *,
    scope_sha256: str,
    confirmation_code: str,
    now: datetime,
    expected_uid: int | None = None,
) -> StoredProfileCandidate:
    uid = _uid(expected_uid)
    current = _utc(now, "confirmation_time")
    code = validate_confirmation_code(confirmation_code)
    lock = _open_lock(root, expected_uid=uid, exclusive=False)
    try:
        try:
            pointer = _load_pointer(
                root / "scopes",
                scope_sha256=_digest(scope_sha256),
                expected_uid=uid,
            )
        except FileNotFoundError:
            raise _reject("candidate_not_found") from None
        if pointer.state != "pending":
            raise _reject("candidate_already_consumed")
        if current >= pointer.expires_at:
            raise _reject("candidate_expired")
        payload = _read_file(
            root / "candidates" / f"{pointer.candidate_record_sha256}.json",
            maximum=MAX_RECORD_BYTES,
            expected_uid=uid,
        )
        if sha256(payload).hexdigest() != pointer.candidate_record_sha256:
            raise _reject("candidate_digest_mismatch")
        record = parse_candidate_record(payload)
        if (
            record.scope_sha256 != scope_sha256
            or record.confirmation_code != code
            or record.expires_at != pointer.expires_at
        ):
            raise _reject("candidate_confirmation_rejected")
        return record
    finally:
        os.close(lock)


def mark_candidate_consumed(
    root: Path,
    *,
    scope_sha256: str,
    candidate_record_sha256: str,
    confirmation_code: str,
    now: datetime,
    expected_uid: int | None = None,
) -> CandidatePointer:
    uid = _uid(expected_uid)
    current = _utc(now, "consumed_at")
    record = load_pending_candidate(
        root,
        scope_sha256=scope_sha256,
        confirmation_code=confirmation_code,
        now=current,
        expected_uid=uid,
    )
    if record.record_sha256 != _digest(candidate_record_sha256):
        raise _reject("candidate_digest_mismatch")
    lock = _open_lock(root, expected_uid=uid, exclusive=True)
    try:
        pointer = _load_pointer(
            root / "scopes",
            scope_sha256=scope_sha256,
            expected_uid=uid,
        )
        if (
            pointer.state != "pending"
            or pointer.candidate_record_sha256 != candidate_record_sha256
            or current >= pointer.expires_at
        ):
            raise _reject("candidate_confirmation_rejected")
        consumed = CandidatePointer(
            scope_sha256=scope_sha256,
            candidate_record_sha256=candidate_record_sha256,
            state="consumed",
            expires_at=pointer.expires_at,
            consumed_at=current,
        )
        _write_pointer_atomic(root / "scopes", consumed, expected_uid=uid)
        return consumed
    finally:
        os.close(lock)


def cancel_pending_candidate(
    root: Path,
    *,
    scope_sha256: str,
    confirmation_code: str,
    now: datetime,
    expected_uid: int | None = None,
) -> CandidatePointer:
    uid = _uid(expected_uid)
    current = _utc(now, "cancelled_at")
    record = load_pending_candidate(
        root,
        scope_sha256=scope_sha256,
        confirmation_code=confirmation_code,
        now=current,
        expected_uid=uid,
    )
    lock = _open_lock(root, expected_uid=uid, exclusive=True)
    try:
        pointer = _load_pointer(
            root / "scopes",
            scope_sha256=scope_sha256,
            expected_uid=uid,
        )
        if (
            pointer.state != "pending"
            or pointer.candidate_record_sha256 != record.record_sha256
            or current >= pointer.expires_at
        ):
            raise _reject("candidate_confirmation_rejected")
        cancelled = CandidatePointer(
            scope_sha256=scope_sha256,
            candidate_record_sha256=record.record_sha256,
            state="cancelled",
            expires_at=pointer.expires_at,
            consumed_at=current,
        )
        _write_pointer_atomic(root / "scopes", cancelled, expected_uid=uid)
        return cancelled
    finally:
        os.close(lock)
