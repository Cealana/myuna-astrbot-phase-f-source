from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import BinaryIO, Callable, Mapping

from .vision_input import (
    VisionInputContractError,
    VisionInputEnvelope,
    VisionMediaDescriptor,
    verify_media_bytes,
)
from .vision_media_boundary import (
    DISPOSAL_SCHEMA_VERSION,
    LEASE_SCHEMA_VERSION,
    TICKET_SCHEMA_VERSION,
    VisionMediaBoundaryError,
    VisionMediaDisposalReceipt,
    VisionMediaLease,
    VisionMediaStagingPolicy,
    VisionMediaStagingTicket,
    validate_lease,
    validate_ticket,
)


def _reject() -> VisionMediaBoundaryError:
    return VisionMediaBoundaryError("vision media boundary rejected")


@dataclass(slots=True)
class _Stage:
    ticket: VisionMediaStagingTicket
    content: dict[str, bytes]
    leased_media: set[str]
    used_leases: set[str]
    disposal_reason: str | None = None
    disposal_receipts: tuple[VisionMediaDisposalReceipt, ...] = ()


class InMemoryVisionMediaStagingFake:
    """Deterministic test double with no filesystem, network, or live clock access."""

    def __init__(
        self,
        *,
        policy: VisionMediaStagingPolicy,
        now: Callable[[], datetime],
        next_id: Callable[[str], str],
    ) -> None:
        if policy.status != "inactive_candidate":
            raise ValueError("Fake staging accepts inactive candidate policy only")
        self.policy = policy
        self.now = now
        self.next_id = next_id
        self._stages: dict[str, _Stage] = {}
        self._leases: dict[str, tuple[str, VisionMediaLease]] = {}

    @staticmethod
    def _utc(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Fake clock must be timezone-aware")
        return value.astimezone(timezone.utc)

    def stage_verified_streams(
        self,
        *,
        envelope: VisionInputEnvelope,
        streams: Mapping[str, BinaryIO],
        expires_at: datetime,
    ) -> VisionMediaStagingTicket:
        try:
            created_at = self._utc(self.now())
            expires_at = self._utc(expires_at)
            if (
                expires_at <= created_at
                or expires_at - created_at
                > timedelta(seconds=self.policy.maximum_ttl_seconds)
                or set(streams) != {item.media_id for item in envelope.media}
            ):
                raise _reject()
            content: dict[str, bytes] = {}
            for descriptor in envelope.media:
                value = streams[descriptor.media_id].read(descriptor.byte_length + 1)
                if not isinstance(value, bytes):
                    raise _reject()
                verify_media_bytes(descriptor, value)
                content[descriptor.media_id] = value
            stage_id = self.next_id("stage")
            if stage_id in self._stages:
                raise _reject()
            ticket = VisionMediaStagingTicket(
                schema_version=TICKET_SCHEMA_VERSION,
                stage_id=stage_id,
                request_id=envelope.context.request_id,
                trace_id=envelope.context.trace_id,
                media=envelope.media,
                created_at=created_at,
                expires_at=expires_at,
                storage_scope=self.policy.storage_scope,
            )
            validate_ticket(
                envelope=envelope,
                ticket=ticket,
                policy=self.policy,
                now=created_at,
            )
            self._stages[stage_id] = _Stage(
                ticket=ticket,
                content=content,
                leased_media=set(),
                used_leases=set(),
            )
            return ticket
        except (
            KeyError,
            TypeError,
            ValueError,
            VisionInputContractError,
            VisionMediaBoundaryError,
        ):
            raise _reject() from None

    def lease_once(
        self,
        *,
        ticket: VisionMediaStagingTicket,
        media_id: str,
        now: datetime,
    ) -> VisionMediaLease:
        try:
            current = self._utc(now)
            stage = self._stages[ticket.stage_id]
            if (
                stage.ticket != ticket
                or stage.disposal_reason is not None
                or ticket.expires_at <= current
                or media_id not in stage.content
                or media_id in stage.leased_media
            ):
                raise _reject()
            lease_id = self.next_id("lease")
            if lease_id in self._leases:
                raise _reject()
            lease = VisionMediaLease(
                schema_version=LEASE_SCHEMA_VERSION,
                lease_id=lease_id,
                stage_id=ticket.stage_id,
                media_id=media_id,
                request_id=ticket.request_id,
                issued_at=current,
                expires_at=min(ticket.expires_at, current + timedelta(seconds=60)),
            )
            validate_lease(ticket=ticket, lease=lease, now=current)
            stage.leased_media.add(media_id)
            self._leases[lease_id] = (ticket.stage_id, lease)
            return lease
        except (KeyError, TypeError, ValueError, VisionMediaBoundaryError):
            raise _reject() from None

    def read_once(self, lease: VisionMediaLease, *, maximum_bytes: int) -> bytes:
        try:
            stage_id, stored_lease = self._leases[lease.lease_id]
            stage = self._stages[stage_id]
            current = self._utc(self.now())
            descriptor = validate_lease(ticket=stage.ticket, lease=lease, now=current)
            if (
                stored_lease != lease
                or lease.lease_id in stage.used_leases
                or stage.disposal_reason is not None
                or not isinstance(maximum_bytes, int)
                or maximum_bytes < descriptor.byte_length
            ):
                raise _reject()
            value = stage.content.pop(lease.media_id)
            verify_media_bytes(descriptor, value)
            stage.used_leases.add(lease.lease_id)
            return value
        except (
            KeyError,
            TypeError,
            ValueError,
            VisionInputContractError,
            VisionMediaBoundaryError,
        ):
            raise _reject() from None

    def dispose(
        self,
        ticket: VisionMediaStagingTicket,
        *,
        reason: str,
        now: datetime,
    ) -> tuple[VisionMediaDisposalReceipt, ...]:
        try:
            stage = self._stages[ticket.stage_id]
            current = self._utc(now)
            if stage.ticket != ticket:
                raise _reject()
            if stage.disposal_reason is not None:
                if stage.disposal_reason != reason:
                    raise _reject()
                return stage.disposal_receipts
            receipts = tuple(
                VisionMediaDisposalReceipt(
                    schema_version=DISPOSAL_SCHEMA_VERSION,
                    stage_id=ticket.stage_id,
                    media_id=descriptor.media_id,
                    disposed_at=current,
                    reason=reason,
                    byte_length=descriptor.byte_length,
                    content_sha256=descriptor.content_sha256,
                )
                for descriptor in ticket.media
            )
            stage.content.clear()
            stage.disposal_reason = reason
            stage.disposal_receipts = receipts
            return receipts
        except (KeyError, TypeError, ValueError, VisionMediaBoundaryError):
            raise _reject() from None

    def expire(self, *, now: datetime) -> tuple[VisionMediaDisposalReceipt, ...]:
        current = self._utc(now)
        receipts: list[VisionMediaDisposalReceipt] = []
        for stage in tuple(self._stages.values()):
            if stage.disposal_reason is None and stage.ticket.expires_at <= current:
                receipts.extend(self.dispose(stage.ticket, reason="expired", now=current))
        return tuple(receipts)

    def staged_byte_count(self) -> int:
        """Test-only metric; never returns content or identity."""

        return sum(len(value) for stage in self._stages.values() for value in stage.content.values())
