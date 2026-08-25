from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Mapping, Protocol, runtime_checkable

from .contracts import TemporalContextError, safe_label, utc


TIME_SOURCE_CLASSES = frozenset({"synthetic", "trusted_local", "trusted_remote"})


@dataclass(frozen=True, slots=True)
class TrustedTimeSample:
    instant: datetime
    source: str
    source_class: str
    sequence: int
    authority: str | None = None
    uncertainty_microseconds: int | None = None
    synchronized: bool | None = None
    boot_id: str | None = None
    monotonic_ns: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "instant", utc(self.instant, "trusted_time"))
        safe_label(self.source, "trusted_time_source")
        if self.source_class not in TIME_SOURCE_CLASSES:
            raise TemporalContextError("trusted_time_source_class_invalid")
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 1
        ):
            raise TemporalContextError("trusted_time_sequence_invalid")
        evidence = (
            self.authority,
            self.uncertainty_microseconds,
            self.synchronized,
            self.boot_id,
            self.monotonic_ns,
        )
        if any(value is None for value in evidence) and not all(
            value is None for value in evidence
        ):
            raise TemporalContextError("trusted_time_evidence_incomplete")
        if all(value is not None for value in evidence):
            safe_label(self.authority, "trusted_time_authority")  # type: ignore[arg-type]
            safe_label(self.boot_id, "trusted_time_boot_id")  # type: ignore[arg-type]
            if (
                isinstance(self.uncertainty_microseconds, bool)
                or not isinstance(self.uncertainty_microseconds, int)
                or self.uncertainty_microseconds < 0
                or not isinstance(self.synchronized, bool)
                or isinstance(self.monotonic_ns, bool)
                or not isinstance(self.monotonic_ns, int)
                or self.monotonic_ns < 0
            ):
                raise TemporalContextError("trusted_time_evidence_invalid")

    @property
    def evidence_complete(self) -> bool:
        return self.authority is not None

    def as_payload(self) -> dict[str, object]:
        return {
            "authority": self.authority,
            "boot_id": self.boot_id,
            "instant": self.instant.isoformat(timespec="microseconds"),
            "monotonic_ns": self.monotonic_ns,
            "sequence": self.sequence,
            "source": self.source,
            "source_class": self.source_class,
            "synchronized": self.synchronized,
            "uncertainty_microseconds": self.uncertainty_microseconds,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> TrustedTimeSample:
        expected = {
            "authority",
            "boot_id",
            "instant",
            "monotonic_ns",
            "sequence",
            "source",
            "source_class",
            "synchronized",
            "uncertainty_microseconds",
        }
        if set(payload) != expected or not isinstance(payload["instant"], str):
            raise TemporalContextError("trusted_time_sample_schema_invalid")
        try:
            instant = datetime.fromisoformat(payload["instant"])
        except ValueError:
            raise TemporalContextError("trusted_time_sample_schema_invalid") from None
        return cls(
            instant=instant,
            source=payload["source"],  # type: ignore[arg-type]
            source_class=payload["source_class"],  # type: ignore[arg-type]
            sequence=payload["sequence"],  # type: ignore[arg-type]
            authority=payload["authority"],  # type: ignore[arg-type]
            uncertainty_microseconds=payload["uncertainty_microseconds"],  # type: ignore[arg-type]
            synchronized=payload["synchronized"],  # type: ignore[arg-type]
            boot_id=payload["boot_id"],  # type: ignore[arg-type]
            monotonic_ns=payload["monotonic_ns"],  # type: ignore[arg-type]
        )


@runtime_checkable
class TrustedTimePort(Protocol):
    """P10-B integration port. P08 supplies no concrete clock provider."""

    def sample(self) -> TrustedTimeSample: ...


class TrustedTimeGuard:
    def __init__(
        self,
        *,
        source: str | None = None,
        sequence: int | None = None,
        instant: datetime | None = None,
    ) -> None:
        if (source is None) is not (sequence is None) or (source is None) is not (
            instant is None
        ):
            raise TemporalContextError("trusted_time_watermark_invalid")
        if source is not None:
            safe_label(source, "trusted_time_watermark_source")
            if (
                isinstance(sequence, bool)
                or not isinstance(sequence, int)
                or sequence < 1
            ):
                raise TemporalContextError("trusted_time_watermark_invalid")
        self._source = source
        self._sequence = sequence
        self._instant = utc(instant, "trusted_time_watermark") if instant is not None else None

    def accept(self, sample: TrustedTimeSample) -> None:
        if self._source is not None:
            if sample.source != self._source:
                raise TemporalContextError("trusted_time_source_drift")
            assert self._sequence is not None and self._instant is not None
            if sample.sequence <= self._sequence:
                raise TemporalContextError("trusted_time_sequence_regression")
            if sample.instant < self._instant:
                raise TemporalContextError("trusted_time_regression")
        self._source = sample.source
        self._sequence = sample.sequence
        self._instant = sample.instant

    @property
    def watermark(self) -> tuple[str, int, datetime] | None:
        if self._source is None:
            return None
        assert self._sequence is not None and self._instant is not None
        return self._source, self._sequence, self._instant
