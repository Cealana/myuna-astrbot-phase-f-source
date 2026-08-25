from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from zoneinfo import ZoneInfo

from myuna_core.episodic_memory import (
    ArchivedContent,
    CompleteTurn,
    CompleteTurnDraft,
    TurnTimeBinding,
)


def digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def make_turn(
    sequence: int,
    previous: str,
    *,
    owner: str = "Owner synthetic message",
    assistant: str = "Myuna synthetic reply",
    instant: datetime | None = None,
    zone_name: str = "Asia/Shanghai",
    epoch_id: str = "synthetic-epoch",
    release: str = "1" * 64,
) -> CompleteTurn:
    selected = instant or datetime(2026, 8, 8, sequence % 20, tzinfo=timezone.utc)
    local = selected.astimezone(ZoneInfo(zone_name))
    offset = local.utcoffset()
    assert offset is not None
    sample = selected + timedelta(seconds=1)
    time_binding = TurnTimeBinding(
        status="exact",
        calendar_zone=zone_name,
        received_monotonic_ns=100,
        committed_monotonic_ns=200,
        delivered_monotonic_ns=300,
        sample_instant_utc=sample,
        received_at_utc=selected - timedelta(seconds=2),
        committed_at_utc=selected - timedelta(seconds=1),
        delivered_at_utc=selected,
        local_calendar_representation=local.isoformat(timespec="microseconds"),
        event_offset_minutes=int(offset.total_seconds() // 60),
        uncertainty_microseconds=1_000,
        synchronized=True,
        source="synthetic-trusted-time",
        source_class="synthetic",
        authority="synthetic-authority",
        boot_id=f"synthetic-boot-{sequence}",
        sequence=sequence,
        sample_monotonic_ns=400,
        quality_codes=("trusted_exact",),
    )
    draft = CompleteTurnDraft(
        turn_id=f"synthetic-turn-{sequence}",
        sequence=sequence,
        owner=ArchivedContent("text", owner),
        assistant=ArchivedContent("text", assistant),
        time_binding=time_binding,
        epoch_id=epoch_id,
        release_set_id=release,
        request_digest=digest(f"request-{sequence}-{owner}"),
        response_digest=digest(f"response-{sequence}-{assistant}"),
        delivery_ack_digest=digest(f"ack-{sequence}"),
        previous_turn_digest=previous,
        provenance_categories=("owner_current_message", "ordinary_external_turn"),
    )
    return CompleteTurn.create(draft)


def make_turns(count: int, *, text_size: int = 8) -> tuple[CompleteTurn, ...]:
    previous = "0" * 64
    result = []
    for sequence in range(1, count + 1):
        turn = make_turn(
            sequence,
            previous,
            owner=f"Owner {sequence} " + "甲" * text_size,
            assistant=f"Myuna {sequence} " + "乙" * text_size,
        )
        result.append(turn)
        previous = turn.turn_digest
    return tuple(result)
