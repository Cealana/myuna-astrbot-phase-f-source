from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from threading import Lock
from typing import Protocol, runtime_checkable

from .errors import IdempotencyConflictError, IdempotencyInProgressError
from .models import OperationResult, require_safe_id


class IdempotencyStatus(StrEnum):
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"


@dataclass(frozen=True, slots=True)
class IdempotencyRecord:
    idempotency_key: str
    request_digest: str
    operation_id: str
    status: IdempotencyStatus
    result: OperationResult | None = None

    def __post_init__(self) -> None:
        require_safe_id(self.idempotency_key, "idempotency_key")
        require_safe_id(self.operation_id, "operation_id")
        if len(self.request_digest) != 64 or any(
            character not in "0123456789abcdef" for character in self.request_digest
        ):
            raise ValueError("request_digest must be SHA-256 hex")
        if (self.status is IdempotencyStatus.COMPLETED) != (self.result is not None):
            raise ValueError("completed idempotency records require a result")


@runtime_checkable
class IdempotencyLedger(Protocol):
    def lookup(self, idempotency_key: str, request_digest: str) -> OperationResult | None: ...

    def claim(
        self,
        idempotency_key: str,
        request_digest: str,
        operation_id: str,
    ) -> None: ...

    def complete(
        self,
        idempotency_key: str,
        request_digest: str,
        result: OperationResult,
    ) -> None: ...

    def replace_completed(
        self,
        idempotency_key: str,
        request_digest: str,
        result: OperationResult,
    ) -> None: ...

    def abandon(self, idempotency_key: str, request_digest: str) -> None: ...


class InMemoryIdempotencyLedger:
    """In-memory test double; dangerous production operations need a database ledger."""

    def __init__(self) -> None:
        self._records: dict[str, IdempotencyRecord] = {}
        self._lock = Lock()

    @staticmethod
    def _verify_digest(record: IdempotencyRecord, request_digest: str) -> None:
        if record.request_digest != request_digest:
            raise IdempotencyConflictError("idempotency key is bound to another request")

    def lookup(self, idempotency_key: str, request_digest: str) -> OperationResult | None:
        with self._lock:
            record = self._records.get(idempotency_key)
            if record is None:
                return None
            self._verify_digest(record, request_digest)
            if record.status is IdempotencyStatus.IN_PROGRESS:
                raise IdempotencyInProgressError("operation is already in progress")
            return record.result

    def claim(
        self,
        idempotency_key: str,
        request_digest: str,
        operation_id: str,
    ) -> None:
        record = IdempotencyRecord(
            idempotency_key=idempotency_key,
            request_digest=request_digest,
            operation_id=operation_id,
            status=IdempotencyStatus.IN_PROGRESS,
        )
        with self._lock:
            existing = self._records.get(idempotency_key)
            if existing is not None:
                self._verify_digest(existing, request_digest)
                raise IdempotencyInProgressError("operation is already claimed")
            self._records[idempotency_key] = record

    def complete(
        self,
        idempotency_key: str,
        request_digest: str,
        result: OperationResult,
    ) -> None:
        with self._lock:
            record = self._records.get(idempotency_key)
            if record is None:
                raise IdempotencyConflictError("idempotency claim does not exist")
            self._verify_digest(record, request_digest)
            if record.status is not IdempotencyStatus.IN_PROGRESS:
                raise IdempotencyConflictError("idempotency claim is already complete")
            if result.operation_id != record.operation_id:
                raise IdempotencyConflictError("result operation_id does not match the claim")
            self._records[idempotency_key] = replace(
                record,
                status=IdempotencyStatus.COMPLETED,
                result=result,
            )

    def replace_completed(
        self,
        idempotency_key: str,
        request_digest: str,
        result: OperationResult,
    ) -> None:
        with self._lock:
            record = self._records.get(idempotency_key)
            if record is None:
                raise IdempotencyConflictError("idempotency record does not exist")
            self._verify_digest(record, request_digest)
            if record.status is not IdempotencyStatus.COMPLETED:
                raise IdempotencyConflictError("idempotency record is not complete")
            if result.operation_id != record.operation_id:
                raise IdempotencyConflictError("replacement operation_id does not match the claim")
            self._records[idempotency_key] = replace(record, result=result)

    def abandon(self, idempotency_key: str, request_digest: str) -> None:
        with self._lock:
            record = self._records.get(idempotency_key)
            if record is None:
                return
            self._verify_digest(record, request_digest)
            if record.status is not IdempotencyStatus.IN_PROGRESS:
                raise IdempotencyConflictError("completed idempotency records cannot be abandoned")
            del self._records[idempotency_key]

    def get_record(self, idempotency_key: str) -> IdempotencyRecord | None:
        with self._lock:
            return self._records.get(idempotency_key)

    def all_records(self) -> tuple[IdempotencyRecord, ...]:
        with self._lock:
            return tuple(self._records[key] for key in sorted(self._records))
