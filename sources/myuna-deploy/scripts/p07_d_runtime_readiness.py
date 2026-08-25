from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Callable, Mapping


SCHEMA = "myuna.p07-d-runtime-readiness.v1"
FILE_NAME = "RUNTIME_READY.json"
_INVOCATION = re.compile(r"^[0-9a-f]{32}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RECEIPT_KEYS = {
    "database_path",
    "epoch_id",
    "epoch_metadata_digest",
    "generation",
    "invocation_id",
    "pid",
    "release_set_id",
    "runtime_config_digest",
    "schema",
    "selector_digest",
}


class RuntimeReadinessRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise RuntimeReadinessRejected(code)


def canonical(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii") + b"\n"


def content_free_metadata_digest(metadata: Mapping[str, object]) -> str:
    return sha256(b"myuna-p07-d-epoch-metadata-v1\0" + canonical(dict(metadata))).hexdigest()


def readiness_path(database_path: str | Path) -> Path:
    selected = Path(database_path)
    _require(selected.is_absolute() and selected.name == "epoch.db", "runtime_readiness_path_rejected")
    return selected.parent / FILE_NAME


@dataclass(frozen=True, slots=True)
class RuntimeReadinessReceipt:
    generation: int
    release_set_id: str
    epoch_id: str
    database_path: str
    selector_digest: str
    runtime_config_digest: str
    epoch_metadata_digest: str
    invocation_id: str
    pid: int

    def as_payload(self) -> dict[str, object]:
        return {
            "database_path": self.database_path,
            "epoch_id": self.epoch_id,
            "epoch_metadata_digest": self.epoch_metadata_digest,
            "generation": self.generation,
            "invocation_id": self.invocation_id,
            "pid": self.pid,
            "release_set_id": self.release_set_id,
            "runtime_config_digest": self.runtime_config_digest,
            "schema": SCHEMA,
            "selector_digest": self.selector_digest,
        }


@dataclass(frozen=True, slots=True)
class RuntimeProcessObservation:
    active_state: str
    sub_state: str
    result: str
    nrestarts: int
    main_pid: int
    invocation_id: str


def _validate_receipt(receipt: RuntimeReadinessReceipt) -> None:
    _require(type(receipt.generation) is int and receipt.generation >= 9, "runtime_readiness_generation_rejected")
    _require(_SHA256.fullmatch(receipt.release_set_id) is not None, "runtime_readiness_release_set_rejected")
    _require(_SAFE_ID.fullmatch(receipt.epoch_id) is not None, "runtime_readiness_epoch_rejected")
    _require(Path(receipt.database_path).is_absolute(), "runtime_readiness_path_rejected")
    for value in (
        receipt.selector_digest,
        receipt.runtime_config_digest,
        receipt.epoch_metadata_digest,
    ):
        _require(_SHA256.fullmatch(value) is not None, "runtime_readiness_digest_rejected")
    _require(_INVOCATION.fullmatch(receipt.invocation_id) is not None, "runtime_readiness_invocation_rejected")
    _require(type(receipt.pid) is int and receipt.pid > 0, "runtime_readiness_pid_rejected")


def publish_runtime_readiness(
    database_path: str | Path,
    *,
    generation: int,
    release_set_id: str,
    epoch_id: str,
    selector_digest: str,
    runtime_config_digest: str,
    epoch_metadata: Mapping[str, object],
    invocation_id: str | None = None,
    pid: int | None = None,
) -> RuntimeReadinessReceipt:
    selected_database = Path(database_path)
    selected_invocation = invocation_id or os.environ.get("INVOCATION_ID", "")
    receipt = RuntimeReadinessReceipt(
        generation=generation,
        release_set_id=release_set_id,
        epoch_id=epoch_id,
        database_path=selected_database.as_posix(),
        selector_digest=selector_digest,
        runtime_config_digest=runtime_config_digest,
        epoch_metadata_digest=content_free_metadata_digest(epoch_metadata),
        invocation_id=selected_invocation,
        pid=os.getpid() if pid is None else pid,
    )
    _validate_receipt(receipt)
    target = readiness_path(selected_database)
    parent = target.parent
    metadata = parent.stat()
    _require(
        not parent.is_symlink()
        and parent.is_dir()
        and metadata.st_uid == os.geteuid()
        and metadata.st_gid == os.getegid()
        and stat.S_IMODE(metadata.st_mode) == 0o700,
        "runtime_readiness_parent_rejected",
    )
    if target.exists() or target.is_symlink():
        existing = inspect_runtime_readiness(
            target,
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
            expected_generation=generation,
            expected_release_set_id=release_set_id,
            expected_epoch_id=epoch_id,
            expected_database_path=selected_database.as_posix(),
            expected_selector_digest=selector_digest,
            expected_runtime_config_digest=runtime_config_digest,
        )
        if existing == receipt:
            return receipt
    payload = canonical(receipt.as_payload())
    temporary = parent / f".{FILE_NAME}.{selected_invocation}.{receipt.pid}.tmp"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(temporary, flags, 0o600)
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
        parent_descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except RuntimeReadinessRejected:
        raise
    except OSError:
        raise RuntimeReadinessRejected("runtime_readiness_publish_failed") from None
    observed = inspect_runtime_readiness(
        target,
        expected_uid=os.geteuid(),
        expected_gid=os.getegid(),
        expected_generation=generation,
        expected_release_set_id=release_set_id,
        expected_epoch_id=epoch_id,
        expected_database_path=selected_database.as_posix(),
        expected_selector_digest=selector_digest,
        expected_runtime_config_digest=runtime_config_digest,
    )
    _require(observed == receipt, "runtime_readiness_publish_drifted")
    return receipt


def inspect_runtime_readiness(
    path: str | Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_generation: int,
    expected_release_set_id: str,
    expected_epoch_id: str,
    expected_database_path: str,
    expected_selector_digest: str,
    expected_runtime_config_digest: str,
) -> RuntimeReadinessReceipt:
    selected = Path(path)
    try:
        metadata = selected.lstat()
    except FileNotFoundError:
        raise RuntimeReadinessRejected("runtime_readiness_absent") from None
    except OSError:
        raise RuntimeReadinessRejected("runtime_readiness_unavailable") from None
    _require(not selected.is_symlink() and stat.S_ISREG(metadata.st_mode), "runtime_readiness_type_rejected")
    _require(
        metadata.st_uid == expected_uid
        and metadata.st_gid == expected_gid
        and stat.S_IMODE(metadata.st_mode) == 0o600
        and metadata.st_size <= 4096,
        "runtime_readiness_permission_rejected",
    )
    try:
        raw = selected.read_bytes()
        payload = json.loads(raw.decode("ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise RuntimeReadinessRejected("runtime_readiness_document_rejected") from None
    _require(isinstance(payload, dict) and set(payload) == _RECEIPT_KEYS, "runtime_readiness_document_rejected")
    _require(raw == canonical(payload), "runtime_readiness_canonical_rejected")
    receipt = RuntimeReadinessReceipt(
        generation=payload["generation"],
        release_set_id=payload["release_set_id"],
        epoch_id=payload["epoch_id"],
        database_path=payload["database_path"],
        selector_digest=payload["selector_digest"],
        runtime_config_digest=payload["runtime_config_digest"],
        epoch_metadata_digest=payload["epoch_metadata_digest"],
        invocation_id=payload["invocation_id"],
        pid=payload["pid"],
    )
    _validate_receipt(receipt)
    _require(
        receipt.generation == expected_generation
        and receipt.release_set_id == expected_release_set_id
        and receipt.epoch_id == expected_epoch_id
        and receipt.database_path == expected_database_path
        and receipt.selector_digest == expected_selector_digest
        and receipt.runtime_config_digest == expected_runtime_config_digest,
        "runtime_readiness_binding_rejected",
    )
    return receipt


def wait_for_runtime_readiness(
    *,
    path: str | Path,
    expected_uid: int,
    expected_gid: int,
    expected_generation: int,
    expected_release_set_id: str,
    expected_epoch_id: str,
    expected_database_path: str,
    expected_selector_digest: str,
    expected_runtime_config_digest: str,
    observe_process: Callable[[], RuntimeProcessObservation],
    timeout_seconds: float = 30.0,
    poll_seconds: float = 0.25,
    stable_seconds: float = 5.0,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> RuntimeReadinessReceipt:
    _require(0 < poll_seconds <= 1 and 0 <= stable_seconds <= 60 and timeout_seconds >= stable_seconds, "runtime_readiness_window_rejected")
    deadline = monotonic() + timeout_seconds
    first_process: RuntimeProcessObservation | None = None
    while monotonic() <= deadline:
        process = observe_process()
        _require(
            process.active_state in {"active", "activating"}
            and process.result in {"", "success"}
            and process.nrestarts == 0
            and process.main_pid > 0
            and _INVOCATION.fullmatch(process.invocation_id) is not None,
            "runtime_startup_failed_before_readiness",
        )
        if first_process is None:
            first_process = process
        _require(
            process.main_pid == first_process.main_pid
            and process.invocation_id == first_process.invocation_id
            and process.nrestarts == first_process.nrestarts,
            "runtime_startup_identity_drifted",
        )
        try:
            receipt = inspect_runtime_readiness(
                path,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
                expected_generation=expected_generation,
                expected_release_set_id=expected_release_set_id,
                expected_epoch_id=expected_epoch_id,
                expected_database_path=expected_database_path,
                expected_selector_digest=expected_selector_digest,
                expected_runtime_config_digest=expected_runtime_config_digest,
            )
        except RuntimeReadinessRejected as exc:
            if exc.code != "runtime_readiness_absent":
                raise
            sleep(poll_seconds)
            continue
        _require(
            receipt.invocation_id == process.invocation_id and receipt.pid == process.main_pid,
            "runtime_readiness_process_mismatch",
        )
        sleep(stable_seconds)
        final_process = observe_process()
        _require(
            final_process.active_state == "active"
            and final_process.sub_state == "running"
            and final_process.result == "success"
            and final_process.nrestarts == process.nrestarts
            and final_process.main_pid == process.main_pid
            and final_process.invocation_id == process.invocation_id,
            "runtime_readiness_not_stable",
        )
        return receipt
    raise RuntimeReadinessRejected("runtime_readiness_timeout")
