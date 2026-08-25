from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Iterable


class RuntimeStateError(ValueError):
    pass


class RuntimeStateStatus(str, Enum):
    CURRENT = "current"
    LAST_KNOWN = "last-known"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class RuntimeStateValue:
    subject: str
    category: str
    key: str
    value: str | int | float | bool | None
    status: RuntimeStateStatus
    source: str
    observed_at: datetime | None
    confidence: float
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        for value in (self.subject, self.category, self.key, self.source):
            if not value or not isinstance(value, str):
                raise RuntimeStateError("runtime state identity is invalid")
        if not 0.0 <= self.confidence <= 1.0:
            raise RuntimeStateError("runtime state confidence is invalid")
        if self.status is RuntimeStateStatus.UNKNOWN:
            if self.value is not None or self.confidence != 0.0:
                raise RuntimeStateError("unknown runtime state cannot claim a value")
        elif self.value is None or self.observed_at is None:
            raise RuntimeStateError("known runtime state requires value and time")
        if self.observed_at is not None and (
            self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None
        ):
            raise RuntimeStateError("runtime state time must include a timezone")
        if self.expires_at is not None and (
            self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None
        ):
            raise RuntimeStateError("runtime state expiry must include a timezone")
        if (
            self.expires_at is not None
            and self.observed_at is not None
            and self.expires_at <= self.observed_at
        ):
            raise RuntimeStateError("runtime state expiry is invalid")


class RuntimeStateRegistry:
    """Read-only typed registry assembled from independently verified sources."""

    def __init__(self, values: Iterable[RuntimeStateValue] = ()) -> None:
        indexed: dict[tuple[str, str, str], RuntimeStateValue] = {}
        for value in values:
            key = (value.subject.casefold(), value.category.casefold(), value.key.casefold())
            if key in indexed:
                raise RuntimeStateError("duplicate runtime state key")
            indexed[key] = value
        self._values = indexed

    def select(self, subject: str, category: str) -> tuple[RuntimeStateValue, ...]:
        prefix = (subject.casefold(), category.casefold())
        return tuple(
            value
            for key, value in sorted(self._values.items())
            if key[:2] == prefix
        )


@dataclass(frozen=True, slots=True)
class CheckResult:
    subject: str
    category: str
    text: str
    status: RuntimeStateStatus


class CheckHandler:
    def __init__(self, registry: RuntimeStateRegistry) -> None:
        self.registry = registry

    def render(self, *, subject: str = "MYUNA", category: str = "概览") -> CheckResult:
        values = self.registry.select(subject, category)
        header = f"[CHECK · {subject.upper()} · {category}]"
        if not values:
            text = (
                header
                + "\n\n当前状态：未知"
                + "\n状态更新时间：未知"
                + "\n数据来源：Runtime State Registry / unavailable"
                + "\n可信度：0.00"
            )
            return CheckResult(subject, category, text, RuntimeStateStatus.UNKNOWN)
        lines = [header, ""]
        for value in values:
            rendered = "未知" if value.status is RuntimeStateStatus.UNKNOWN else str(value.value)
            lines.append(f"{value.key}：{rendered}")
        newest = max(
            (value.observed_at for value in values if value.observed_at is not None),
            default=None,
        )
        lines.extend(
            [
                f"状态更新时间：{newest.isoformat() if newest else '未知'}",
                "数据来源：" + ", ".join(dict.fromkeys(value.source for value in values)),
                f"可信度：{min(value.confidence for value in values):.2f}",
            ]
        )
        statuses = {value.status for value in values}
        if RuntimeStateStatus.CURRENT in statuses:
            overall = RuntimeStateStatus.CURRENT
        elif RuntimeStateStatus.LAST_KNOWN in statuses:
            overall = RuntimeStateStatus.LAST_KNOWN
        else:
            overall = RuntimeStateStatus.UNKNOWN
        return CheckResult(subject, category, "\n".join(lines), overall)
