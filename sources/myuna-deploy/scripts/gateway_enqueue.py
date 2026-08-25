"""Best-effort, post-reply sender for the local Shadow Unix datagram socket."""

from __future__ import annotations

import json
import os
import socket
import stat
import time
from uuid import UUID


MAX_QUERY_CHARACTERS = 256
MAX_DATAGRAM_BYTES = 4096


def approved_marker_enabled(path: str) -> bool:
    """Accept only a root-owned, non-writable regular-file activation marker."""

    try:
        metadata = os.stat(path, follow_symlinks=False)
        return (
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == 0
            and stat.S_IMODE(metadata.st_mode) & 0o022 == 0
        )
    except OSError:
        return False


def enqueue_after_reply(socket_path: str, request_uuid: str, query: str) -> str:
    """Try one non-blocking AF_UNIX datagram send and never raise to the caller."""

    try:
        UUID(request_uuid)
        if not isinstance(query, str) or not query.strip() or len(query) > MAX_QUERY_CHARACTERS:
            return "invalid_event"
        payload = json.dumps(
            {
                "schema_version": 1,
                "boundary": "verified_owner_private_text",
                "request_uuid": request_uuid,
                "query": query,
                "enqueue_monotonic_ns": time.monotonic_ns(),
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(payload) > MAX_DATAGRAM_BYTES:
            return "invalid_event"
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
