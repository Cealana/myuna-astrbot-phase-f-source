#!/usr/bin/env python3
"""Authenticate Telegram image-shape events and emit identity-free metadata."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
from typing import Mapping
from uuid import uuid4

from myuna_core.identity import account_fingerprint
from telegram_media_metadata_protocol import (
    CHANNEL_KIND,
    MAX_DATAGRAM_BYTES,
    MediaMetadataEnvelopeRejected,
    VerifiedMediaShapeEvent,
    verify_signed_media_shadow_envelope,
)
from telegram_media_metadata_shadow_enqueue import (
    TelegramMediaMetadataJob,
    enqueue_media_metadata_shadow,
)


CONFIG_PATH = Path("/etc/myuna-telegram-gateway/owner-runtime-v1.json")
SHADOW_SOCKET = "/run/myuna-telegram-media-metadata-shadow/shadow.sock"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class MediaShadowAuthRejected(PermissionError):
    """Fail-closed without identity or event detail."""


@dataclass(frozen=True, slots=True)
class AuthConfig:
    binding_id: str
    principal_id: str
    namespace_id: str
    channel_instance: str

    @classmethod
    def from_payload(cls, payload: object) -> "AuthConfig":
        if not isinstance(payload, Mapping):
            raise MediaShadowAuthRejected("media Shadow auth rejected")
        required = {"binding_id", "principal_id", "namespace_id", "channel_instance", "channel_kind"}
        if not required <= set(payload) or payload.get("channel_kind") != CHANNEL_KIND:
            raise MediaShadowAuthRejected("media Shadow auth rejected")
        values = {key: payload[key] for key in required - {"channel_kind"}}
        if any(not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None for value in values.values()):
            raise MediaShadowAuthRejected("media Shadow auth rejected")
        return cls(**values)


def _load_config(path: Path = CONFIG_PATH) -> AuthConfig:
    try:
        metadata = path.stat()
        if path.is_symlink() or not path.is_file() or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o027:
            raise MediaShadowAuthRejected("media Shadow auth rejected")
        return AuthConfig.from_payload(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise MediaShadowAuthRejected("media Shadow auth rejected") from None


def _read_credential(name: str) -> bytes:
    directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if not directory:
        raise MediaShadowAuthRejected("media Shadow auth rejected")
    try:
        value = (Path(directory) / name).read_bytes().strip()
    except OSError:
        raise MediaShadowAuthRejected("media Shadow auth rejected") from None
    if len(value) < 32:
        raise MediaShadowAuthRejected("media Shadow auth rejected")
    return value


def _psql_scalar(sql: str, variables: Mapping[str, str]) -> str:
    command = [
        "/usr/bin/psql",
        "--dbname=myuna_dev",
        "--username=myuna_telegram_gateway_app",
        "--host=/var/run/postgresql",
        "--no-psqlrc",
        "--no-align",
        "--tuples-only",
        "--set=ON_ERROR_STOP=1",
    ]
    for key, value in variables.items():
        command.append(f"--set={key}={value}")
    result = subprocess.run(
        command,
        input=sql + "\n",
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        raise MediaShadowAuthRejected("media Shadow auth rejected")
    return result.stdout.strip()


def _claim(event: VerifiedMediaShapeEvent, now: datetime) -> bool:
    nonce_fingerprint = sha256(
        b"myuna-channel-nonce-v1\0" + event.nonce.encode("ascii")
    ).hexdigest()
    expires_at = now + timedelta(minutes=9)
    result = _psql_scalar(
        "SELECT gateway_runtime.claim_telegram_inbound_event("
        ":'channel_instance', :'event_id', :'nonce_fingerprint', "
        ":'payload_sha256', :'occurred_at'::timestamptz, :'expires_at'::timestamptz);",
        {
            "channel_instance": event.channel_instance,
            "event_id": event.event_id,
            "nonce_fingerprint": nonce_fingerprint,
            "payload_sha256": sha256(
                f"media-shape\0{event.event_id}\0{event.trace_id}".encode("utf-8")
            ).hexdigest(),
            "occurred_at": event.occurred_at.isoformat(timespec="microseconds"),
            "expires_at": expires_at.isoformat(timespec="microseconds"),
        },
    )
    return result == "t"


def _owner_verified(event: VerifiedMediaShapeEvent, config: AuthConfig, pepper: bytes) -> bool:
    fingerprint = account_fingerprint(CHANNEL_KIND, event.actor_account_id, pepper)
    result = _psql_scalar(
        "SELECT concat_ws('|', binding_id, principal_id, namespace_id) "
        "FROM gateway_runtime.resolve_verified_telegram_owner_binding(:'account_fingerprint');",
        {"account_fingerprint": fingerprint},
    )
    expected = f"{config.binding_id}|{config.principal_id}|{config.namespace_id}"
    return hmac.compare_digest(result, expected)


def _record(event: VerifiedMediaShapeEvent, outcome: str, code: str) -> bool:
    return _psql_scalar(
        "SELECT gateway_runtime.record_telegram_inbound_outcome("
        ":'channel_instance', :'event_id', :'outcome', :'code');",
        {
            "channel_instance": event.channel_instance,
            "event_id": event.event_id,
            "outcome": outcome,
            "code": code,
        },
    ) == "t"


class SlidingRateLimiter:
    def __init__(self, limit: int = 60) -> None:
        self.limit = limit
        self.events: dict[str, deque[datetime]] = defaultdict(deque)

    def allow(self, principal_id: str, now: datetime) -> bool:
        cutoff = now - timedelta(minutes=10)
        queue = self.events[principal_id]
        while queue and queue[0] < cutoff:
            queue.popleft()
        if len(queue) >= self.limit:
            return False
        queue.append(now)
        return True


def authenticate_and_enqueue(
    payload: object,
    *,
    config: AuthConfig,
    signing_secret: bytes,
    identity_pepper: bytes,
    limiter: SlidingRateLimiter,
    now: datetime,
    claim=_claim,
    owner_verified=_owner_verified,
    record=_record,
    enqueue=enqueue_media_metadata_shadow,
) -> bool:
    try:
        event = verify_signed_media_shadow_envelope(payload, signing_secret=signing_secret)
        current = now.astimezone(timezone.utc)
        if event.channel_instance != config.channel_instance:
            raise MediaShadowAuthRejected("media Shadow auth rejected")
        if event.occurred_at < current - timedelta(minutes=5) or event.occurred_at > current + timedelta(seconds=30):
            raise MediaShadowAuthRejected("media Shadow auth rejected")
        if not claim(event, current):
            raise MediaShadowAuthRejected("media Shadow auth rejected")
        if not owner_verified(event, config, identity_pepper):
            record(event, "rejected", "media_shadow_owner_unverified")
            return False
        if not limiter.allow(config.principal_id, current):
            record(event, "failed", "media_shadow_rate_limited")
            return False
        result = enqueue(
            SHADOW_SOCKET,
            TelegramMediaMetadataJob(
                observation_uuid=str(uuid4()),
                attachment_count_bucket=event.attachment_count_bucket,
                caption_present=event.caption_present,
            ),
        )
        if result != "enqueued":
            record(event, "failed", "media_shadow_observer_unavailable")
            return False
        return record(event, "accepted", "media_shadow_observed")
    except (MediaMetadataEnvelopeRejected, MediaShadowAuthRejected, OSError, subprocess.SubprocessError, TypeError, ValueError):
        return False


def serve() -> None:
    if os.geteuid() == 0 or int(os.environ.get("LISTEN_FDS", "0")) != 1:
        raise SystemExit("Telegram media Shadow auth requires its systemd socket and non-root identity")
    config = _load_config()
    signing_secret = _read_credential("channel-signing")
    identity_pepper = _read_credential("identity-pepper")
    if hmac.compare_digest(signing_secret, identity_pepper):
        raise SystemExit("media Shadow credentials must be distinct")
    limiter = SlidingRateLimiter()
    print("telegram media Shadow auth stage=ready", flush=True)
    with socket.fromfd(3, socket.AF_UNIX, socket.SOCK_DGRAM) as server:
        while True:
            datagram = server.recv(MAX_DATAGRAM_BYTES + 1)
            try:
                payload = json.loads(datagram.decode("ascii"))
            except (UnicodeError, json.JSONDecodeError):
                print("telegram media Shadow auth stage=safe_drop", flush=True)
                continue
            if not authenticate_and_enqueue(
                payload,
                config=config,
                signing_secret=signing_secret,
                identity_pepper=identity_pepper,
                limiter=limiter,
                now=datetime.now(timezone.utc),
            ):
                print("telegram media Shadow auth stage=safe_drop", flush=True)


if __name__ == "__main__":
    serve()
