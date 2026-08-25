"""Identity-free sender for Telegram media metadata Shadow."""

from __future__ import annotations

from dataclasses import dataclass
import json
import socket
import time
from uuid import UUID


EVENT_SCHEMA = "myuna.telegram-media-metadata-shadow.event.v1"
MAX_DATAGRAM_BYTES = 2048
COUNT_BUCKETS = frozenset({"1", "2-4"})


@dataclass(frozen=True, slots=True)
class TelegramMediaMetadataJob:
    observation_uuid: str
    attachment_count_bucket: str
    caption_present: bool

    def __post_init__(self) -> None:
        UUID(self.observation_uuid)
        if self.attachment_count_bucket not in COUNT_BUCKETS:
            raise ValueError("invalid attachment count bucket")
        if type(self.caption_present) is not bool:
            raise TypeError("caption_present must be boolean")


def build_media_metadata_shadow_event(
    job: TelegramMediaMetadataJob,
    *,
    monotonic_ns: int | None = None,
) -> bytes:
    if not isinstance(job, TelegramMediaMetadataJob):
        raise TypeError("invalid media metadata job")
    event: dict[str, object] = {
        "attachment_count_bucket": job.attachment_count_bucket,
        "attachment_kind": "image_component",
        "boundary": "verified_owner_private_media_pre_download",
        "caption_present": job.caption_present,
        "enqueue_monotonic_ns": monotonic_ns or time.monotonic_ns(),
        "observation_uuid": job.observation_uuid,
        "schema": EVENT_SCHEMA,
    }
    encoded = json.dumps(
        event,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    if len(encoded) > MAX_DATAGRAM_BYTES:
        raise ValueError("media metadata Shadow event exceeds limit")
    return encoded


def enqueue_media_metadata_shadow(
    socket_path: str,
    job: TelegramMediaMetadataJob,
) -> str:
    try:
        payload = build_media_metadata_shadow_event(job)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            client.setblocking(False)
            client.connect(socket_path)
            client.send(payload)
        finally:
            client.close()
        return "enqueued"
    except (OSError, TypeError, UnicodeError, ValueError):
        return "unavailable"
