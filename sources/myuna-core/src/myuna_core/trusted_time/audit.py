from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class TrustedTimeAuditEvent:
    operation: str
    outcome: str
    error_category: str | None
    continuity: str
    source_class: str
    uncertainty_bucket: str
    drift_bucket: str
    retryable: bool

    def public_payload(self) -> dict[str, object]:
        return {
            "continuity": self.continuity,
            "drift_bucket": self.drift_bucket,
            "error_category": self.error_category,
            "operation": self.operation,
            "outcome": self.outcome,
            "retryable": self.retryable,
            "source_class": self.source_class,
            "uncertainty_bucket": self.uncertainty_bucket,
        }


@runtime_checkable
class TrustedTimeAuditSink(Protocol):
    """A sink for fixed categories; events contain no instant, sequence, path or identity."""

    def emit(self, event: TrustedTimeAuditEvent) -> None: ...
