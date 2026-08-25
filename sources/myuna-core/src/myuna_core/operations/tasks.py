from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from threading import Lock
from typing import Protocol, runtime_checkable

from .models import OperationOrigin, TaskStatus, require_aware, require_safe_id


@dataclass(frozen=True, slots=True)
class TaskRecord:
    task_id: str
    correlation_id: str
    owner_principal_id: str
    origin: OperationOrigin
    task_kind: str
    status: TaskStatus
    created_at: datetime
    updated_at: datetime
    operation_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for value, label in (
            (self.task_id, "task_id"),
            (self.correlation_id, "correlation_id"),
            (self.owner_principal_id, "owner_principal_id"),
            (self.task_kind, "task_kind"),
        ):
            require_safe_id(value, label)
        for operation_id in self.operation_ids:
            require_safe_id(operation_id, "operation_id")
        if not isinstance(self.origin, OperationOrigin):
            raise ValueError("origin must be an OperationOrigin")
        if not isinstance(self.status, TaskStatus):
            raise ValueError("status must be a TaskStatus")
        if len(self.operation_ids) != len(set(self.operation_ids)):
            raise ValueError("operation_ids must not contain duplicates")
        created = require_aware(self.created_at, "created_at")
        updated = require_aware(self.updated_at, "updated_at")
        if updated < created:
            raise ValueError("updated_at must not precede created_at")
        object.__setattr__(self, "created_at", created)
        object.__setattr__(self, "updated_at", updated)


@runtime_checkable
class TaskStore(Protocol):
    def append(self, record: TaskRecord) -> None: ...

    def get(self, task_id: str) -> TaskRecord | None: ...

    def transition(self, task_id: str, status: TaskStatus, *, at: datetime) -> TaskRecord: ...


class InMemoryTaskStore:
    """Authoritative semantics for tests only; OpenClaw never owns this store."""

    _TRANSITIONS = {
        TaskStatus.PENDING: frozenset({TaskStatus.RUNNING, TaskStatus.CANCELLED}),
        TaskStatus.RUNNING: frozenset(
            {TaskStatus.SUCCEEDED, TaskStatus.FAILED, TaskStatus.CANCELLED}
        ),
        TaskStatus.SUCCEEDED: frozenset(),
        TaskStatus.FAILED: frozenset(),
        TaskStatus.CANCELLED: frozenset(),
    }

    def __init__(self) -> None:
        self._records: dict[str, TaskRecord] = {}
        self._lock = Lock()

    def append(self, record: TaskRecord) -> None:
        with self._lock:
            if record.task_id in self._records:
                raise ValueError("task_id already exists")
            self._records[record.task_id] = record

    def get(self, task_id: str) -> TaskRecord | None:
        with self._lock:
            return self._records.get(task_id)

    def transition(self, task_id: str, status: TaskStatus, *, at: datetime) -> TaskRecord:
        if not isinstance(status, TaskStatus):
            raise ValueError("status must be a TaskStatus")
        at = require_aware(at, "at")
        with self._lock:
            record = self._records.get(task_id)
            if record is None:
                raise KeyError("task record was not found")
            if at < record.updated_at:
                raise ValueError("task transition time must be monotonic")
            if status not in self._TRANSITIONS[record.status]:
                raise ValueError("invalid task status transition")
            updated = replace(record, status=status, updated_at=at)
            self._records[task_id] = updated
            return updated

    def attach_operation(self, task_id: str, operation_id: str, *, at: datetime) -> TaskRecord:
        require_safe_id(operation_id, "operation_id")
        at = require_aware(at, "at")
        with self._lock:
            record = self._records.get(task_id)
            if record is None:
                raise KeyError("task record was not found")
            if at < record.updated_at:
                raise ValueError("task update time must be monotonic")
            if record.status in {
                TaskStatus.SUCCEEDED,
                TaskStatus.FAILED,
                TaskStatus.CANCELLED,
            }:
                raise ValueError("operations cannot be attached to a terminal task")
            if operation_id in record.operation_ids:
                raise ValueError("operation is already attached to the task")
            updated = replace(
                record,
                operation_ids=record.operation_ids + (operation_id,),
                updated_at=at,
            )
            self._records[task_id] = updated
            return updated
