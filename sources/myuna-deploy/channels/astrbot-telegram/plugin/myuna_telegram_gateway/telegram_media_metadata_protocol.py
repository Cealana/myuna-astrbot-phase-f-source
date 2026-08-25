"""Signed, content-free Telegram image-shape envelope.

This module deliberately has no AstrBot or Telegram SDK dependency so the
same exact source can be reused by the isolated authentication worker.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import hmac
import json
import re
import secrets
import socket
from typing import Mapping


SCHEMA = "myuna.telegram-media-auth-event.v1"
CHANNEL_KIND = "astrbot_telegram"
SIGNATURE_DOMAIN = b"myuna-telegram-media-auth-envelope-v1\0"
MAX_DATAGRAM_BYTES = 4096
_TELEGRAM_ACCOUNT = re.compile(r"^[1-9][0-9]{0,19}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_SIGNATURE = re.compile(r"^[0-9a-f]{64}$")
_COUNT_BUCKETS = frozenset({"1", "2-4"})


class MediaMetadataEnvelopeRejected(PermissionError):
    """Fail-closed error without event, identity, or media detail."""


def _reject() -> MediaMetadataEnvelopeRejected:
    return MediaMetadataEnvelopeRejected("media metadata envelope rejected")


def _event_time(raw_timestamp: object, now: datetime) -> datetime:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("clock must be timezone-aware")
    if isinstance(raw_timestamp, (int, float)) and not isinstance(raw_timestamp, bool):
        try:
            parsed = datetime.fromtimestamp(float(raw_timestamp), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            parsed = now
    else:
        parsed = now
    return parsed.astimezone(timezone.utc)


def _opaque_id(secret: bytes, domain: bytes, value: str, prefix: str) -> str:
    digest = hmac.new(secret, domain + b"\0" + value.encode("utf-8"), sha256)
    return f"{prefix}-{digest.hexdigest()[:40]}"


def _count_bucket(image_count: int) -> str:
    if image_count == 1:
        return "1"
    if 2 <= image_count <= 4:
        return "2-4"
    raise ValueError("unsupported image count")


def should_observe_private_image_shape(
    *,
    sender_id: str,
    is_private_chat: bool,
    sender_is_bot: bool | None,
    image_count: int,
    parts_supported: bool,
) -> bool:
    if not is_private_chat or sender_is_bot is not False or not parts_supported:
        return False
    if _TELEGRAM_ACCOUNT.fullmatch(sender_id) is None:
        return False
    return 1 <= image_count <= 4


def _canonical_event(event: Mapping[str, object]) -> bytes:
    return json.dumps(
        dict(event),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def build_signed_media_shadow_envelope(
    *,
    sender_id: str,
    message_id: object,
    raw_timestamp: object,
    image_count: int,
    caption_present: bool,
    signing_secret: bytes,
    channel_instance: str,
    now: datetime | None = None,
    nonce: str | None = None,
) -> dict[str, object]:
    if _TELEGRAM_ACCOUNT.fullmatch(sender_id) is None:
        raise ValueError("unsupported account")
    if _SAFE_ID.fullmatch(channel_instance) is None:
        raise ValueError("unsupported channel instance")
    if len(signing_secret) < 32 or type(caption_present) is not bool:
        raise ValueError("invalid media metadata envelope")
    selected_nonce = nonce or secrets.token_urlsafe(32)
    if _NONCE.fullmatch(selected_nonce) is None:
        raise ValueError("invalid nonce")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    occurred_at = _event_time(raw_timestamp, current)
    source_id = str(message_id) if message_id is not None else secrets.token_hex(24)
    event: dict[str, object] = {
        "actor_account_id": sender_id,
        "attachment_count_bucket": _count_bucket(image_count),
        "attachment_kind": "image_component",
        "caption_present": caption_present,
        "channel": CHANNEL_KIND,
        "channel_instance": channel_instance,
        "conversation_kind": "private",
        "event_id": _opaque_id(
            signing_secret,
            b"myuna-telegram-media-event-v1",
            f"{sender_id}\0{source_id}",
            "evt",
        ),
        "nonce": selected_nonce,
        "schema": SCHEMA,
        "timestamp": occurred_at.isoformat(timespec="microseconds"),
        "trace_id": f"trace-{secrets.token_hex(16)}",
    }
    signature = hmac.new(
        signing_secret,
        SIGNATURE_DOMAIN + _canonical_event(event),
        sha256,
    ).hexdigest()
    return {"event": event, "signature": signature}


@dataclass(frozen=True, slots=True)
class VerifiedMediaShapeEvent:
    actor_account_id: str = field(repr=False)
    channel_instance: str = ""
    event_id: str = ""
    trace_id: str = ""
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    nonce: str = field(default="", repr=False)
    attachment_count_bucket: str = ""
    caption_present: bool = False


def verify_signed_media_shadow_envelope(
    payload: object,
    *,
    signing_secret: bytes,
) -> VerifiedMediaShapeEvent:
    try:
        if len(signing_secret) < 32:
            raise ValueError("invalid secret")
        if not isinstance(payload, Mapping) or set(payload) != {"event", "signature"}:
            raise ValueError("invalid envelope")
        event = payload["event"]
        signature = payload["signature"]
        expected_fields = {
            "actor_account_id",
            "attachment_count_bucket",
            "attachment_kind",
            "caption_present",
            "channel",
            "channel_instance",
            "conversation_kind",
            "event_id",
            "nonce",
            "schema",
            "timestamp",
            "trace_id",
        }
        if not isinstance(event, Mapping) or set(event) != expected_fields:
            raise ValueError("invalid event")
        if not isinstance(signature, str) or _SIGNATURE.fullmatch(signature) is None:
            raise ValueError("invalid signature")
        expected = hmac.new(
            signing_secret,
            SIGNATURE_DOMAIN + _canonical_event(event),
            sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("invalid signature")
        actor = event["actor_account_id"]
        instance = event["channel_instance"]
        event_id = event["event_id"]
        trace_id = event["trace_id"]
        nonce = event["nonce"]
        if not isinstance(actor, str) or _TELEGRAM_ACCOUNT.fullmatch(actor) is None:
            raise ValueError("invalid account")
        if any(not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None for value in (instance, event_id, trace_id)):
            raise ValueError("invalid identifier")
        if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
            raise ValueError("invalid nonce")
        if event["schema"] != SCHEMA or event["channel"] != CHANNEL_KIND:
            raise ValueError("invalid boundary")
        if event["conversation_kind"] != "private":
            raise ValueError("invalid conversation")
        if event["attachment_kind"] != "image_component":
            raise ValueError("invalid attachment kind")
        count_bucket = event["attachment_count_bucket"]
        if count_bucket not in _COUNT_BUCKETS or type(event["caption_present"]) is not bool:
            raise ValueError("invalid shape")
        timestamp = event["timestamp"]
        if not isinstance(timestamp, str):
            raise ValueError("invalid timestamp")
        occurred_at = datetime.fromisoformat(timestamp)
        if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
            raise ValueError("invalid timestamp")
        return VerifiedMediaShapeEvent(
            actor_account_id=actor,
            channel_instance=instance,
            event_id=event_id,
            trace_id=trace_id,
            occurred_at=occurred_at.astimezone(timezone.utc),
            nonce=nonce,
            attachment_count_bucket=str(count_bucket),
            caption_present=event["caption_present"],
        )
    except (KeyError, TypeError, ValueError):
        raise _reject() from None


def encode_media_shadow_envelope(payload: Mapping[str, object]) -> bytes:
    encoded = json.dumps(
        dict(payload),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    if not encoded or len(encoded) > MAX_DATAGRAM_BYTES:
        raise ValueError("media metadata envelope exceeds limit")
    return encoded


def send_media_shadow_envelope(socket_path: str, payload: Mapping[str, object]) -> str:
    """Attempt one non-blocking datagram send; never retry or raise."""

    try:
        encoded = encode_media_shadow_envelope(payload)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            client.setblocking(False)
            client.connect(socket_path)
            client.send(encoded)
        finally:
            client.close()
        return "enqueued"
    except (OSError, TypeError, UnicodeError, ValueError):
        return "unavailable"
