from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from pathlib import Path
from typing import Any
import fcntl
import json
import os
import re
import stat
import tempfile
import threading

from .base import ModelRequest, ModelResponse, request_input_token_upper_bound
from .registry import ModelSpec


_RESERVATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_REASONS = frozenset({"transport_failure", "invalid_response", "upstream_failure"})
_ROLLOVER_SCHEMA = "myuna.provider-budget-auto-rollover.v1"
_BASE_STATE_FIELDS = frozenset(
    {"schema_version", "date_utc", "daily_limit_usd", "spent_usd", "reservations"}
)
_ROLLOVER_FIELDS = frozenset(
    {
        "schema",
        "previous_date_utc",
        "current_date_utc",
        "archive_file",
        "archive_sha256",
        "reservation_active",
        "reservation_uncertain",
        "rolled_at_utc",
        "receipt_file",
    }
)
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MILLION = Decimal(1_000_000)

Clock = Callable[[], datetime]
Failpoint = Callable[[str], None]


class BudgetError(RuntimeError):
    pass


class BudgetExceededError(BudgetError):
    pass


class BudgetAccountingError(BudgetError):
    pass


def actual_cost_usd(spec: ModelSpec, response: ModelResponse) -> Decimal:
    pricing = spec.pricing
    return (
        Decimal(response.cache_hit_tokens) * pricing.cache_hit_input_per_million_usd
        + Decimal(response.cache_miss_tokens) * pricing.cache_miss_input_per_million_usd
        + Decimal(response.output_tokens) * pricing.output_per_million_usd
    ) / _MILLION


def worst_case_cost_usd(spec: ModelSpec, request: ModelRequest) -> Decimal:
    pricing = spec.pricing
    input_upper_bound = request_input_token_upper_bound(request)
    return (
        Decimal(input_upper_bound) * pricing.cache_miss_input_per_million_usd
        + Decimal(request.max_output_tokens) * pricing.output_per_million_usd
    ) / _MILLION


class DailyBudgetLedger:
    """Fail-closed UTC daily budget ledger with persistent reservations."""

    def __init__(
        self,
        path: Path,
        *,
        daily_limit_usd: Decimal,
        clock: Clock | None = None,
        failpoint: Failpoint | None = None,
    ) -> None:
        if daily_limit_usd <= 0:
            raise ValueError("daily_limit_usd must be positive")
        self.path = path
        self.lock_path = path.with_suffix(path.suffix + ".lock")
        self.archive_root = path.parent / "archive"
        self.receipt_root = path.parent / "rollover-receipts"
        self.daily_limit_usd = daily_limit_usd
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._failpoint = failpoint
        self._thread_lock = threading.Lock()

    def reserve(self, reservation_id: str, amount_usd: Decimal) -> None:
        self._validate_id(reservation_id)
        self._validate_amount(amount_usd)
        with self._locked_state(write_back=True) as (state, now):
            reservations = state["reservations"]
            if reservation_id in reservations:
                raise BudgetAccountingError("duplicate budget reservation")
            committed = _decimal(state["spent_usd"])
            reserved = sum(
                (_decimal(item["reserved_usd"]) for item in reservations.values()),
                Decimal(0),
            )
            if committed + reserved + amount_usd > self.daily_limit_usd:
                raise BudgetExceededError("daily provider budget would be exceeded")
            reservations[reservation_id] = {
                "reserved_usd": str(amount_usd),
                "state": "active",
                "created_at": now.isoformat(),
            }

    def settle(self, reservation_id: str, accounted_usd: Decimal) -> None:
        self._validate_id(reservation_id)
        self._validate_amount(accounted_usd, allow_zero=True)
        with self._locked_state(write_back=True) as (state, _):
            item = self._get_reservation(state, reservation_id)
            reserved = _decimal(item["reserved_usd"])
            if accounted_usd > reserved:
                raise BudgetAccountingError("settlement exceeded the reserved budget")
            state["spent_usd"] = str(_decimal(state["spent_usd"]) + accounted_usd)
            del state["reservations"][reservation_id]

    def cancel(self, reservation_id: str) -> None:
        self._validate_id(reservation_id)
        with self._locked_state(write_back=True) as (state, _):
            self._get_reservation(state, reservation_id)
            del state["reservations"][reservation_id]

    def mark_uncertain(self, reservation_id: str, *, reason: str) -> None:
        self._validate_id(reservation_id)
        if reason not in _REASONS:
            raise ValueError("invalid uncertain billing reason")
        with self._locked_state(write_back=True) as (state, _):
            item = self._get_reservation(state, reservation_id)
            item["state"] = "uncertain"
            item["reason"] = reason

    def snapshot(self) -> dict[str, Any]:
        with self._locked_state(write_back=False) as (state, _):
            return json.loads(json.dumps(state))

    @contextmanager
    def _locked_state(
        self,
        *,
        write_back: bool,
    ) -> Iterator[tuple[dict[str, Any], datetime]]:
        with self._thread_lock:
            descriptor: int | None = None
            locked = False
            try:
                self._ensure_private_directory(self.path.parent)
                flags = os.O_RDWR | os.O_CREAT
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(self.lock_path, flags, 0o600)
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    raise BudgetAccountingError("budget lock failed validation")
                os.fchmod(descriptor, 0o600)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                locked = True
                now = self._authoritative_now()
                state = self._load_state(now)
                yield state, now
                if write_back:
                    self._write_state(state)
            except BudgetError:
                raise
            except OSError as exc:
                raise BudgetAccountingError("budget accounting storage unavailable") from exc
            finally:
                if descriptor is not None:
                    if locked:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                    os.close(descriptor)

    def _authoritative_now(self) -> datetime:
        value = self._clock()
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise BudgetAccountingError("budget clock must be timezone-aware")
        return value.astimezone(timezone.utc)

    def _load_state(self, now: datetime) -> dict[str, Any]:
        today = now.date()
        if self.path.is_symlink():
            raise BudgetAccountingError("budget ledger failed validation")
        if not self.path.exists():
            state = self._new_state(today.isoformat())
            self._write_state(state)
            return state
        original = self._read_private_bytes(self.path)
        try:
            state = json.loads(original.decode("utf-8"))
            recorded_date = self._validate_state(state)
        except (
            KeyError,
            TypeError,
            UnicodeDecodeError,
            ValueError,
            json.JSONDecodeError,
            InvalidOperation,
        ) as exc:
            raise BudgetAccountingError("budget ledger failed validation") from exc
        if recorded_date > today:
            raise BudgetAccountingError("budget clock regression detected")
        if "rollover" in state:
            self._ensure_rollover_artifacts(state["rollover"])
        if recorded_date < today:
            return self._rollover(original, state, now)
        return state

    def _validate_state(self, state: object) -> date:
        if not isinstance(state, dict):
            raise ValueError
        fields = frozenset(state)
        if fields not in {
            _BASE_STATE_FIELDS,
            _BASE_STATE_FIELDS | {"rollover"},
        }:
            raise ValueError
        if type(state["schema_version"]) is not int or state["schema_version"] != 1:
            raise ValueError
        recorded_date = _parse_date(state["date_utc"])
        if state["daily_limit_usd"] != str(self.daily_limit_usd):
            raise ValueError
        spent = _decimal_string(state["spent_usd"])
        reservations = state["reservations"]
        if not isinstance(reservations, dict):
            raise ValueError
        reserved = Decimal(0)
        for key, item in reservations.items():
            self._validate_id(key)
            if not isinstance(item, dict):
                raise ValueError
            reservation_state = item.get("state")
            expected_fields = {"reserved_usd", "state", "created_at"}
            if reservation_state == "uncertain":
                expected_fields.add("reason")
            if set(item) != expected_fields or reservation_state not in {
                "active",
                "uncertain",
            }:
                raise ValueError
            amount = _decimal_string(item["reserved_usd"])
            self._validate_amount(amount)
            _parse_utc_timestamp(item["created_at"])
            if reservation_state == "uncertain" and item["reason"] not in _REASONS:
                raise ValueError
            reserved += amount
        if spent + reserved > self.daily_limit_usd:
            raise ValueError
        if "rollover" in state:
            self._validate_rollover(state["rollover"], recorded_date)
        return recorded_date

    def _validate_rollover(self, rollover: object, recorded_date: date) -> None:
        if not isinstance(rollover, dict) or frozenset(rollover) != _ROLLOVER_FIELDS:
            raise ValueError
        if rollover["schema"] != _ROLLOVER_SCHEMA:
            raise ValueError
        previous_date = _parse_date(rollover["previous_date_utc"])
        current_date = _parse_date(rollover["current_date_utc"])
        digest = rollover["archive_sha256"]
        if (
            current_date != recorded_date
            or previous_date >= current_date
            or not isinstance(digest, str)
            or _HEX_DIGEST.fullmatch(digest) is None
        ):
            raise ValueError
        expected_archive = f"{self.path.stem}-{previous_date.isoformat()}-{digest}.json"
        expected_receipt = f"auto-rollover-{current_date.isoformat()}-{digest}.json"
        if (
            rollover["archive_file"] != expected_archive
            or rollover["receipt_file"] != expected_receipt
        ):
            raise ValueError
        for field in ("reservation_active", "reservation_uncertain"):
            value = rollover[field]
            if type(value) is not int or value < 0:
                raise ValueError
        _parse_utc_timestamp(rollover["rolled_at_utc"])

    def _rollover(
        self,
        original: bytes,
        previous: dict[str, Any],
        now: datetime,
    ) -> dict[str, Any]:
        previous_date = previous["date_utc"]
        current_date = now.date().isoformat()
        digest = sha256(original).hexdigest()
        archive_file = f"{self.path.stem}-{previous_date}-{digest}.json"
        receipt_file = f"auto-rollover-{current_date}-{digest}.json"
        active = sum(
            1 for item in previous["reservations"].values() if item["state"] == "active"
        )
        uncertain = sum(
            1
            for item in previous["reservations"].values()
            if item["state"] == "uncertain"
        )
        rollover = {
            "schema": _ROLLOVER_SCHEMA,
            "previous_date_utc": previous_date,
            "current_date_utc": current_date,
            "archive_file": archive_file,
            "archive_sha256": digest,
            "reservation_active": active,
            "reservation_uncertain": uncertain,
            "rolled_at_utc": now.isoformat(),
            "receipt_file": receipt_file,
        }
        self._ensure_private_directory(self.archive_root)
        self._publish_once(self.archive_root / archive_file, original)
        self._hit_failpoint("rollover.after_archive")
        current = self._new_state(current_date)
        current["rollover"] = rollover
        self._write_state(current)
        self._hit_failpoint("rollover.after_ledger_replace")
        self._ensure_rollover_artifacts(rollover)
        self._hit_failpoint("rollover.after_receipt")
        return current

    def _ensure_rollover_artifacts(self, rollover: dict[str, Any]) -> None:
        self._ensure_private_directory(self.archive_root, create=False)
        archive = self.archive_root / rollover["archive_file"]
        archived = self._read_private_bytes(archive)
        if sha256(archived).hexdigest() != rollover["archive_sha256"]:
            raise BudgetAccountingError("budget archive failed validation")
        self._ensure_private_directory(self.receipt_root)
        receipt = self._receipt_bytes(rollover)
        self._publish_once(self.receipt_root / rollover["receipt_file"], receipt)

    def _receipt_bytes(self, rollover: dict[str, Any]) -> bytes:
        return _canonical_bytes(
            {
                "schema": _ROLLOVER_SCHEMA,
                "status": "ROLLED_OVER",
                "previous_date": rollover["previous_date_utc"],
                "current_date": rollover["current_date_utc"],
                "archive_file": rollover["archive_file"],
                "archive_sha256": rollover["archive_sha256"],
                "reservation_active": rollover["reservation_active"],
                "reservation_uncertain": rollover["reservation_uncertain"],
                "raw_ids_recorded": False,
                "amounts_recorded": False,
                "recorded_at": rollover["rolled_at_utc"],
            }
        )

    def _new_state(self, today: str) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "date_utc": today,
            "daily_limit_usd": str(self.daily_limit_usd),
            "spent_usd": "0",
            "reservations": {},
        }

    def _write_state(self, state: dict[str, Any]) -> None:
        self._atomic_replace(self.path, _canonical_bytes(state))

    def _atomic_replace(self, path: Path, payload: bytes) -> None:
        temporary = self._write_temporary(path, payload)
        try:
            os.replace(temporary, path)
            self._fsync_directory(path.parent)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise

    def _publish_once(self, path: Path, payload: bytes) -> None:
        if path.is_symlink():
            raise BudgetAccountingError("budget archive failed validation")
        if path.exists():
            if self._read_private_bytes(path) != payload:
                raise BudgetAccountingError("budget archive drifted")
            return
        temporary = self._write_temporary(path, payload)
        try:
            try:
                os.link(temporary, path, follow_symlinks=False)
            except FileExistsError:
                if path.is_symlink() or self._read_private_bytes(path) != payload:
                    raise BudgetAccountingError("budget archive drifted")
            temporary.unlink(missing_ok=True)
            self._fsync_directory(path.parent)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise

    @staticmethod
    def _write_temporary(path: Path, payload: bytes) -> Path:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            dir=path.parent,
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            return temporary
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            temporary.unlink(missing_ok=True)
            raise

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _ensure_private_directory(path: Path, *, create: bool = True) -> None:
        if path.is_symlink():
            raise BudgetAccountingError("budget directory failed validation")
        created = not path.exists()
        if created:
            if not create:
                raise BudgetAccountingError("budget directory is missing")
            path.mkdir(parents=True, mode=0o700, exist_ok=True)
            path.chmod(0o700)
        metadata = path.stat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise BudgetAccountingError("budget directory failed validation")

    @staticmethod
    def _read_private_bytes(path: Path) -> bytes:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise BudgetAccountingError("budget file failed validation")
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                return handle.read()
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _hit_failpoint(self, name: str) -> None:
        if self._failpoint is not None:
            self._failpoint(name)

    @staticmethod
    def _validate_id(reservation_id: str) -> None:
        if not _RESERVATION_ID.fullmatch(reservation_id):
            raise ValueError("invalid budget reservation identifier")

    @staticmethod
    def _validate_amount(amount_usd: Decimal, *, allow_zero: bool = False) -> None:
        if not amount_usd.is_finite() or amount_usd < 0 or (amount_usd == 0 and not allow_zero):
            raise ValueError("invalid budget amount")

    @staticmethod
    def _get_reservation(state: dict[str, Any], reservation_id: str) -> dict[str, Any]:
        try:
            return state["reservations"][reservation_id]
        except KeyError as exc:
            raise BudgetAccountingError("budget reservation does not exist") from exc


def _decimal(value: Any) -> Decimal:
    result = Decimal(str(value))
    if not result.is_finite() or result < 0:
        raise ValueError
    return result


def _decimal_string(value: object) -> Decimal:
    if not isinstance(value, str):
        raise ValueError
    return _decimal(value)


def _parse_date(value: object) -> date:
    if not isinstance(value, str):
        raise ValueError
    parsed = datetime.strptime(value, "%Y-%m-%d").date()
    if parsed.isoformat() != value:
        raise ValueError
    return parsed


def _parse_utc_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError
    return parsed.astimezone(timezone.utc)


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
