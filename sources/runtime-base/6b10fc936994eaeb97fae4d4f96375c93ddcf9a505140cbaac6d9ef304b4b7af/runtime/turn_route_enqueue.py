"""Non-blocking post-reply sender for Turn/Route metadata-only Shadow."""

from __future__ import annotations

import json
import socket
import time
from uuid import UUID


MAX_QUERY_CHARACTERS = 4096
MAX_DATAGRAM_BYTES = 16_384
ALLOWED_ACTUAL_ROUTES = frozenset(
    {
        "local_low_risk",
        "deepseek_default",
        "deepseek_pro",
        "openai_or_independent_review",
        "fallback",
        "unknown",
    }
)


def build_turn_route_event(
    request_uuid: str,
    query: str,
    actual_route: str,
    *,
    monotonic_ns: int | None = None,
) -> bytes:
    UUID(request_uuid)
    if not isinstance(query, str) or not query.strip():
        raise ValueError("invalid_event")
    if len(query) > MAX_QUERY_CHARACTERS:
        raise ValueError("invalid_event")
    if actual_route not in ALLOWED_ACTUAL_ROUTES:
        raise ValueError("invalid_event")
    event = {
        "schema_version": 1,
        "boundary": "verified_owner_private_text_post_reply",
        "request_uuid": request_uuid,
        "query": query,
        "input_character_count": len(query),
        "event_count": 1,
        "actual_route": actual_route,
        "enqueue_monotonic_ns": monotonic_ns or time.monotonic_ns(),
    }
    encoded = json.dumps(
        event,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > MAX_DATAGRAM_BYTES:
        raise ValueError("invalid_event")
    return encoded


def enqueue_turn_route_after_reply(
    socket_path: str,
    request_uuid: str,
    query: str,
    actual_route: str,
) -> str:
    """Attempt one non-blocking datagram send; never retry or raise."""

    try:
        payload = build_turn_route_event(request_uuid, query, actual_route)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            client.setblocking(False)
            client.connect(socket_path)
            client.send(payload)
        finally:
            client.close()
        return "enqueued"
    except (OSError, UnicodeError, ValueError, TypeError):
        return "unavailable"
