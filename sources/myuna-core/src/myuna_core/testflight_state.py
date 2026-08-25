from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import re
import stat


_SAFE_VERSION = re.compile(r"^v[0-9]+$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class TestFlightStateError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TestFlightStateRecord:
    version: str
    first_activation_completed: bool
    activated_at: datetime
    activation_id: str

    def to_payload(self) -> dict[str, object]:
        return {
            "activation_id": self.activation_id,
            "activated_at": self.activated_at.isoformat(),
            "first_activation_completed": self.first_activation_completed,
            "schema": "myuna.testflight-state.v1",
            "version": self.version,
        }


class FileTestFlightStateStore:
    """Version-scoped, create-once TestFlight state with no service authority."""

    def __init__(self, root: Path) -> None:
        if not root.is_absolute():
            raise TestFlightStateError("TestFlight state root must be absolute")
        self.root = root

    def _path(self, version: str) -> Path:
        if _SAFE_VERSION.fullmatch(version) is None:
            raise TestFlightStateError("invalid TestFlight version")
        return self.root / f"{version}.json"

    def read(self, version: str) -> TestFlightStateRecord | None:
        path = self._path(version)
        if not path.exists():
            return None
        try:
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
                raise ValueError
            payload = json.loads(path.read_text(encoding="utf-8"))
            if set(payload) != {
                "activation_id",
                "activated_at",
                "first_activation_completed",
                "schema",
                "version",
            }:
                raise ValueError
            if (
                payload["schema"] != "myuna.testflight-state.v1"
                or payload["version"] != version
                or payload["first_activation_completed"] is not True
                or _SAFE_ID.fullmatch(payload["activation_id"]) is None
            ):
                raise ValueError
            activated_at = datetime.fromisoformat(payload["activated_at"])
            if activated_at.tzinfo is None or activated_at.utcoffset() is None:
                raise ValueError
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise TestFlightStateError("TestFlight state is invalid") from exc
        return TestFlightStateRecord(
            version=version,
            first_activation_completed=True,
            activated_at=activated_at,
            activation_id=payload["activation_id"],
        )

    def activate_once(
        self,
        version: str,
        *,
        activated_at: datetime,
        activation_id: str,
    ) -> tuple[TestFlightStateRecord, bool]:
        if activated_at.tzinfo is None or activated_at.utcoffset() is None:
            raise TestFlightStateError("activation time must include a timezone")
        if _SAFE_ID.fullmatch(activation_id) is None:
            raise TestFlightStateError("activation ID is invalid")
        existing = self.read(version)
        if existing is not None:
            return existing, False
        if not self.root.parent.is_dir():
            raise TestFlightStateError("TestFlight state parent is unavailable")
        self.root.mkdir(exist_ok=True, mode=0o700)
        self.root.chmod(0o700)
        record = TestFlightStateRecord(version, True, activated_at, activation_id)
        encoded = (
            json.dumps(record.to_payload(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        path = self._path(version)
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            concurrent = self.read(version)
            if concurrent is None:
                raise TestFlightStateError("concurrent TestFlight state is unavailable")
            return concurrent, False
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        directory_descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        return record, True
