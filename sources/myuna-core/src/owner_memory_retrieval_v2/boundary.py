from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Iterable


EXPECTED_NAMESPACE = "ns-owner-cealana-private"
RECENT_DAYS = 3


def parse_datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed


def eligible_records(
    records: Iterable[dict[str, Any]],
    *,
    horizon: str,
    at: datetime,
    filtered: Counter[str],
) -> list[dict[str, Any]]:
    """Apply deterministic trust, sensitivity, status, and time boundaries."""

    if horizon not in {"recent", "deep"}:
        raise ValueError("invalid retrieval horizon")
    cutoff = at - timedelta(days=RECENT_DAYS)
    eligible = []
    for record in records:
        if record.get("namespace_id") != EXPECTED_NAMESPACE:
            filtered["namespace_mismatch"] += 1
            continue
        if record.get("sensitivity") != "normal":
            filtered["sensitivity_not_normal"] += 1
            continue
        if record.get("confirmation_level") != "user_confirmed":
            filtered["not_user_confirmed"] += 1
            continue
        if record.get("memory_status") not in {"confirmed", "provisional"}:
            filtered["inactive_status"] += 1
            continue
        occurred_at = parse_datetime(record.get("occurred_at"))
        if occurred_at is None:
            filtered["missing_time"] += 1
            continue
        if horizon == "recent" and occurred_at < cutoff:
            filtered["outside_recent_window"] += 1
            continue
        eligible.append(record)
    return eligible
