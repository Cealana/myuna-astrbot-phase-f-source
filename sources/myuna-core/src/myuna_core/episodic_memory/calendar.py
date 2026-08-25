from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .contracts import (
    DEFAULT_CALENDAR_ZONE,
    SUPPORTED_CALENDAR_ZONES,
    EpisodicMemoryError,
    require_utc,
)


@dataclass(frozen=True, slots=True)
class UtcInterval:
    start: datetime
    end: datetime
    calendar_zone: str
    local_date: date

    def __post_init__(self) -> None:
        start = require_utc(self.start, "interval_start")
        end = require_utc(self.end, "interval_end")
        if start >= end:
            raise EpisodicMemoryError("calendar_interval_invalid")
        object.__setattr__(self, "start", start)
        object.__setattr__(self, "end", end)


def _zone(zone_name: str) -> ZoneInfo:
    if zone_name not in SUPPORTED_CALENDAR_ZONES:
        raise EpisodicMemoryError("calendar_zone_unsupported")
    try:
        return ZoneInfo(zone_name)
    except ZoneInfoNotFoundError:
        raise EpisodicMemoryError("timezone_database_unavailable") from None


def local_date_interval(selected: date, zone_name: str = DEFAULT_CALENDAR_ZONE) -> UtcInterval:
    zone = _zone(zone_name)
    local_start = datetime.combine(selected, time.min, tzinfo=zone)
    local_end = datetime.combine(selected + timedelta(days=1), time.min, tzinfo=zone)
    return UtcInterval(
        start=local_start.astimezone(timezone.utc),
        end=local_end.astimezone(timezone.utc),
        calendar_zone=zone_name,
        local_date=selected,
    )


def resolve_relative_date(
    relation: str,
    *,
    reference_utc: datetime,
    zone_name: str = DEFAULT_CALENDAR_ZONE,
) -> UtcInterval:
    normalized = relation.strip().casefold()
    offsets = {
        "today": 0,
        "今天": 0,
        "yesterday": -1,
        "昨天": -1,
        "tomorrow": 1,
        "明天": 1,
    }
    if normalized not in offsets:
        raise EpisodicMemoryError("relative_date_unknown")
    zone = _zone(zone_name)
    reference = require_utc(reference_utc, "reference_time")
    selected = reference.astimezone(zone).date() + timedelta(days=offsets[normalized])
    return local_date_interval(selected, zone_name)
