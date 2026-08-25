#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
import time
from typing import Callable, Mapping
from urllib import parse, request

from myuna_core.identity import account_fingerprint
from telegram_bot_token_intake import TOKEN_PATH, TokenIntakeRejected, validate_token
from telegram_owner_binding import CHANNEL_KIND, SCHEMA


EVIDENCE_PATH = Path(
    "/var/lib/myuna-telegram-gateway/owner-discovery-v1.json"
)
IDENTITY_PEPPER_PATH = Path(
    "/etc/myuna-telegram-gateway/secrets/identity-pepper-v1"
)
_TELEGRAM_ID = re.compile(r"^[1-9][0-9]{0,19}$")
_START_CHALLENGE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")


class DiscoveryRejected(RuntimeError):
    """Content-free rejection; raw Telegram identity must never be emitted."""


def _api_call(
    token: str,
    method: str,
    parameters: Mapping[str, object],
    *,
    timeout: float,
) -> object:
    encoded = parse.urlencode(parameters)
    endpoint = f"https://api.telegram.org/bot{token}/{method}?{encoded}"
    try:
        with request.urlopen(endpoint, timeout=timeout) as response:
            raw = response.read(65537)
    except Exception:
        raise DiscoveryRejected("Telegram discovery transport rejected") from None
    if len(raw) > 65536:
        raise DiscoveryRejected("Telegram discovery response rejected")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise DiscoveryRejected("Telegram discovery response rejected") from None
    if (
        not isinstance(payload, Mapping)
        or payload.get("ok") is not True
        or "result" not in payload
    ):
        raise DiscoveryRejected("Telegram discovery response rejected")
    return payload["result"]


def private_start_sender_id(update: object, challenge: str) -> str | None:
    if _START_CHALLENGE.fullmatch(challenge) is None:
        raise DiscoveryRejected("Telegram discovery rejected")
    if not isinstance(update, Mapping):
        return None
    message = update.get("message")
    expected = f"/start {challenge}"
    if (
        not isinstance(message, Mapping)
        or not isinstance(message.get("text"), str)
        or not hmac.compare_digest(message["text"], expected)
    ):
        return None
    sender = message.get("from")
    chat = message.get("chat")
    if not isinstance(sender, Mapping) or not isinstance(chat, Mapping):
        return None
    if sender.get("is_bot") is not False or chat.get("type") != "private":
        return None
    sender_id = str(sender.get("id", ""))
    chat_id = str(chat.get("id", ""))
    if (
        _TELEGRAM_ID.fullmatch(sender_id) is None
        or not hmac.compare_digest(sender_id, chat_id)
    ):
        return None
    return sender_id


def build_discovery_evidence(
    sender_id: str,
    identity_pepper: bytes,
    *,
    now: datetime,
) -> dict[str, object]:
    if _TELEGRAM_ID.fullmatch(sender_id) is None:
        raise DiscoveryRejected("Telegram discovery rejected")
    if len(identity_pepper) < 32 or now.tzinfo is None:
        raise DiscoveryRejected("Telegram discovery rejected")
    current = now.astimezone(timezone.utc)
    return {
        "account_fingerprint": account_fingerprint(
            CHANNEL_KIND,
            sender_id,
            identity_pepper,
        ),
        "channel_kind": CHANNEL_KIND,
        "discovery_command_challenge_stored": False,
        "discovery_command_was_scoped": True,
        "discovered_at": current.isoformat(timespec="seconds"),
        "expires_at": (current + timedelta(minutes=20)).isoformat(timespec="seconds"),
        "raw_account_id_stored": False,
        "result": "telegram-private-start-discovered",
        "schema": SCHEMA,
    }


def discover_private_start(
    token: str,
    identity_pepper: bytes,
    *,
    challenge: str,
    api_call: Callable[[str, str, Mapping[str, object]], object],
    deadline_seconds: int = 180,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, object]:
    if _START_CHALLENGE.fullmatch(challenge) is None:
        raise DiscoveryRejected("Telegram discovery rejected")
    me = api_call(token, "getMe", {})
    if not isinstance(me, Mapping) or me.get("is_bot") is not True:
        raise DiscoveryRejected("Telegram discovery rejected")

    webhook = api_call(token, "getWebhookInfo", {})
    if not isinstance(webhook, Mapping) or webhook.get("url") != "":
        raise DiscoveryRejected("Telegram discovery requires polling-only Bot state")

    latest = api_call(token, "getUpdates", {"offset": -1, "timeout": 0})
    offset = 0
    if isinstance(latest, list) and latest:
        last = latest[-1]
        if isinstance(last, Mapping) and isinstance(last.get("update_id"), int):
            offset = int(last["update_id"]) + 1

    deadline = clock() + deadline_seconds
    while clock() < deadline:
        updates = api_call(
            token,
            "getUpdates",
            {
                "allowed_updates": json.dumps(["message"]),
                "offset": offset,
                "timeout": 20,
            },
        )
        if not isinstance(updates, list):
            raise DiscoveryRejected("Telegram discovery rejected")
        for update in updates:
            if isinstance(update, Mapping) and isinstance(update.get("update_id"), int):
                offset = max(offset, int(update["update_id"]) + 1)
            sender_id = private_start_sender_id(update, challenge)
            if sender_id is not None:
                return build_discovery_evidence(
                    sender_id,
                    identity_pepper,
                    now=datetime.now(timezone.utc),
                )
    raise DiscoveryRejected("Telegram discovery timed out")


def _read_secret(path: Path, *, token: bool = False) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise DiscoveryRejected("Telegram discovery rejected")
    metadata = path.stat()
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise DiscoveryRejected("Telegram discovery rejected")
    raw = path.read_bytes().strip()
    if token:
        try:
            return validate_token(raw)
        except TokenIntakeRejected:
            raise DiscoveryRejected("Telegram discovery rejected") from None
    if len(raw) < 32:
        raise DiscoveryRejected("Telegram discovery rejected")
    return raw


def _write_evidence(payload: Mapping[str, object]) -> str:
    EVIDENCE_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(EVIDENCE_PATH.parent, 0, 0)
    os.chmod(EVIDENCE_PATH.parent, 0o700)
    serialized = (
        json.dumps(dict(payload), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    descriptor: int | None = None
    temporary_name: str | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".owner-discovery-",
            dir=EVIDENCE_PATH.parent,
        )
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, 0, 0)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, EVIDENCE_PATH)
        temporary_name = None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)
    return sha256(serialized).hexdigest()


def main() -> int:
    if os.geteuid() != 0:
        raise DiscoveryRejected("local root authority is required")
    token_buffer = bytearray(_read_secret(TOKEN_PATH, token=True))
    pepper_buffer = bytearray(_read_secret(IDENTITY_PEPPER_PATH))
    challenge = secrets.token_urlsafe(32)
    try:
        token = bytes(token_buffer).decode("ascii")
        print(
            json.dumps(
                {
                    "action": "send-private-command-to-bot",
                    "command": f"/start {challenge}",
                    "expires_in_seconds": 180,
                    "result": "telegram-owner-discovery-challenge-ready",
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
            flush=True,
        )
        evidence = discover_private_start(
            token,
            bytes(pepper_buffer),
            challenge=challenge,
            api_call=lambda t, method, params: _api_call(
                t,
                method,
                params,
                timeout=30,
            ),
        )
        evidence_sha256 = _write_evidence(evidence)
    finally:
        token = ""
        challenge = ""
        for buffer in (token_buffer, pepper_buffer):
            for index in range(len(buffer)):
                buffer[index] = 0

    fingerprint = str(evidence["account_fingerprint"])
    print(
        json.dumps(
            {
                "evidence_sha256": evidence_sha256,
                "fingerprint_preview": f"{fingerprint[:8]}...{fingerprint[-8:]}",
                "raw_account_id_stored": False,
                "result": "telegram-private-start-discovered",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, DiscoveryRejected):
        print("Telegram Owner discovery rejected", file=sys.stderr)
        raise SystemExit(1) from None
