from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import hmac
import json
import re
from threading import Lock
from typing import Callable, Mapping

from .identity import AuthenticatedContext, IdentityRegistry, IdentityResolutionError


SCHEMA_VERSION = "myuna.channel.v1"
ASTRBOT_QQ_CHANNEL = "astrbot_qq"
ASTRBOT_TELEGRAM_CHANNEL = "astrbot_telegram"
SUPPORTED_CHANNELS = frozenset(
    {
        ASTRBOT_QQ_CHANNEL,
        ASTRBOT_TELEGRAM_CHANNEL,
    }
)

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_SIGNATURE = re.compile(r"^[0-9a-f]{64}$")
_CONVERSATION_KINDS = frozenset({"private", "group"})


class GatewayEnvelopeError(PermissionError):
    """Fail-closed gateway error without identity or signature detail."""


def _reject() -> GatewayEnvelopeError:
    return GatewayEnvelopeError("gateway envelope rejected")


def _require_safe_id(value: str, label: str) -> None:
    if _SAFE_ID.fullmatch(value) is None:
        raise ValueError(f"{label} must be a safe opaque identifier")


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp must be an ISO-8601 string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a timezone offset")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class ConsentContext:
    memory_candidate: bool = False
    tools: bool = False
    media_processing: bool = False

    def as_payload(self) -> dict[str, bool]:
        return {
            "media_processing": self.media_processing,
            "memory_candidate": self.memory_candidate,
            "tools": self.tools,
        }


@dataclass(frozen=True, slots=True)
class ChannelEvent:
    schema_version: str
    event_id: str
    channel: str
    channel_instance: str
    actor_account_id: str = field(repr=False)
    conversation_id: str
    conversation_kind: str
    occurred_at: datetime
    message_text: str
    reply_to: str | None
    delivery_capabilities: tuple[str, ...]
    consent_context: ConsentContext
    trace_id: str
    nonce: str = field(repr=False)

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported channel schema")
        if self.channel not in SUPPORTED_CHANNELS:
            raise ValueError("unsupported channel")
        for value, label in (
            (self.event_id, "event_id"),
            (self.channel_instance, "channel_instance"),
            (self.conversation_id, "conversation_id"),
            (self.trace_id, "trace_id"),
        ):
            _require_safe_id(value, label)
        if not self.actor_account_id or len(self.actor_account_id) > 512:
            raise ValueError("actor account id must be non-empty and bounded")
        if self.actor_account_id != self.actor_account_id.strip():
            raise ValueError("actor account id must not contain surrounding whitespace")
        if self.conversation_kind not in _CONVERSATION_KINDS:
            raise ValueError("unsupported conversation kind")
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("event timestamp must include a timezone offset")
        object.__setattr__(self, "occurred_at", self.occurred_at.astimezone(timezone.utc))
        if not self.message_text.strip() or len(self.message_text) > 4000:
            raise ValueError("message text must contain 1-4000 characters")
        if self.reply_to is not None:
            _require_safe_id(self.reply_to, "reply_to")
        if self.delivery_capabilities != ("text",):
            raise ValueError("v1 gateway supports text delivery only")
        if _NONCE.fullmatch(self.nonce) is None:
            raise ValueError("nonce must be a 32-128 character opaque value")

    def as_payload(self) -> dict[str, object]:
        return {
            "actor_account_id": self.actor_account_id,
            "channel": self.channel,
            "channel_instance": self.channel_instance,
            "consent_context": self.consent_context.as_payload(),
            "conversation_id": self.conversation_id,
            "conversation_kind": self.conversation_kind,
            "delivery_capabilities": list(self.delivery_capabilities),
            "event_id": self.event_id,
            "message_parts": [{"text": self.message_text, "type": "text"}],
            "nonce": self.nonce,
            "reply_to": self.reply_to,
            "schema_version": self.schema_version,
            "timestamp": self.occurred_at.isoformat(timespec="microseconds"),
            "trace_id": self.trace_id,
        }

    @classmethod
    def from_payload(cls, payload: object) -> ChannelEvent:
        try:
            if not isinstance(payload, Mapping):
                raise ValueError("event must be an object")
            required = {
                "actor_account_id",
                "channel",
                "channel_instance",
                "consent_context",
                "conversation_id",
                "conversation_kind",
                "delivery_capabilities",
                "event_id",
                "message_parts",
                "nonce",
                "reply_to",
                "schema_version",
                "timestamp",
                "trace_id",
            }
            if set(payload) != required:
                raise ValueError("event fields do not match the v1 schema")

            parts = payload["message_parts"]
            if (
                not isinstance(parts, list)
                or len(parts) != 1
                or not isinstance(parts[0], Mapping)
                or set(parts[0]) != {"type", "text"}
                or parts[0].get("type") != "text"
                or not isinstance(parts[0].get("text"), str)
            ):
                raise ValueError("v1 gateway accepts exactly one text part")

            raw_consent = payload["consent_context"]
            if (
                not isinstance(raw_consent, Mapping)
                or set(raw_consent)
                != {"memory_candidate", "tools", "media_processing"}
                or any(not isinstance(value, bool) for value in raw_consent.values())
            ):
                raise ValueError("invalid consent context")

            capabilities = payload["delivery_capabilities"]
            if capabilities != ["text"]:
                raise ValueError("invalid delivery capabilities")

            string_fields = {
                name: payload[name]
                for name in (
                    "actor_account_id",
                    "channel",
                    "channel_instance",
                    "conversation_id",
                    "conversation_kind",
                    "event_id",
                    "nonce",
                    "schema_version",
                    "trace_id",
                )
            }
            if any(not isinstance(value, str) for value in string_fields.values()):
                raise ValueError("gateway identifiers must be strings")
            reply_to = payload["reply_to"]
            if reply_to is not None and not isinstance(reply_to, str):
                raise ValueError("reply_to must be null or a string")

            return cls(
                schema_version=string_fields["schema_version"],
                event_id=string_fields["event_id"],
                channel=string_fields["channel"],
                channel_instance=string_fields["channel_instance"],
                actor_account_id=string_fields["actor_account_id"],
                conversation_id=string_fields["conversation_id"],
                conversation_kind=string_fields["conversation_kind"],
                occurred_at=_parse_timestamp(payload["timestamp"]),
                message_text=str(parts[0]["text"]),
                reply_to=reply_to,
                delivery_capabilities=("text",),
                consent_context=ConsentContext(
                    memory_candidate=raw_consent["memory_candidate"],
                    tools=raw_consent["tools"],
                    media_processing=raw_consent["media_processing"],
                ),
                trace_id=string_fields["trace_id"],
                nonce=string_fields["nonce"],
            )
        except (KeyError, TypeError, ValueError):
            raise _reject() from None


def canonical_event_bytes(event: ChannelEvent) -> bytes:
    return json.dumps(
        event.as_payload(),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sign_channel_event(event: ChannelEvent, gateway_secret: bytes) -> str:
    if len(gateway_secret) < 32:
        raise ValueError("gateway signing secret must contain at least 32 bytes")
    message = b"myuna-channel-envelope-v1\0" + canonical_event_bytes(event)
    return hmac.new(gateway_secret, message, sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class SignedChannelEnvelope:
    event: ChannelEvent
    signature: str = field(repr=False)

    def __post_init__(self) -> None:
        if _SIGNATURE.fullmatch(self.signature) is None:
            raise ValueError("signature must be lowercase SHA-256 hex")

    def as_payload(self) -> dict[str, object]:
        return {"event": self.event.as_payload(), "signature": self.signature}

    @classmethod
    def from_payload(cls, payload: object) -> SignedChannelEnvelope:
        try:
            if not isinstance(payload, Mapping) or set(payload) != {"event", "signature"}:
                raise ValueError("signed envelope fields do not match the v1 schema")
            signature = payload["signature"]
            if not isinstance(signature, str):
                raise ValueError("signature must be a string")
            return cls(event=ChannelEvent.from_payload(payload["event"]), signature=signature)
        except (TypeError, ValueError, GatewayEnvelopeError):
            raise _reject() from None


def build_signed_envelope(
    event: ChannelEvent,
    gateway_secret: bytes,
) -> SignedChannelEnvelope:
    return SignedChannelEnvelope(
        event=event,
        signature=sign_channel_event(event, gateway_secret),
    )


@dataclass(frozen=True, slots=True)
class VerifiedChannelMessage:
    context: AuthenticatedContext
    event_id: str
    channel_instance: str
    conversation_id: str
    conversation_kind: str
    occurred_at: datetime
    message_text: str
    reply_to: str | None
    trace_id: str
    delivery_capabilities: tuple[str, ...]
    consent_context: ConsentContext

    def conversation_payload(self) -> dict[str, object]:
        """Return only the current loopback conversation fields; identity stays out of prompts."""

        return {
            "high_quality": False,
            "messages": [{"content": self.message_text, "role": "user"}],
            "mode": "myuna",
            "risk_level": "low",
            "synthetic_memory": False,
            "task_class": "ordinary_chat",
        }

    def audit_details(self) -> dict[str, object]:
        """Return identifiers safe for private operational audit, never the raw account id."""

        return {
            "binding_id": self.context.binding_id,
            "channel": self.context.channel_kind,
            "channel_instance": self.channel_instance,
            "conversation_kind": self.conversation_kind,
            "event_id": self.event_id,
            "namespace_id": self.context.namespace_id,
            "principal_id": self.context.principal_id,
            "trace_id": self.trace_id,
        }


class InMemoryReplayWindow:
    """Bounded dev defense-in-depth; live activation still needs durable idempotency."""

    def __init__(self, *, ttl: timedelta = timedelta(minutes=10), max_events: int = 4096) -> None:
        if ttl <= timedelta(0):
            raise ValueError("replay ttl must be positive")
        if not 128 <= max_events <= 1_000_000:
            raise ValueError("replay event limit is outside the supported range")
        self.ttl = ttl
        self.max_events = max_events
        self._events: dict[tuple[str, str, str], tuple[datetime, tuple[str, str, str]]] = {}
        self._nonces: dict[tuple[str, str, str], datetime] = {}
        self._lock = Lock()

    def claim(self, event: ChannelEvent, *, now: datetime) -> None:
        event_key = (event.channel, event.channel_instance, event.event_id)
        nonce_key = (event.channel, event.channel_instance, event.nonce)
        cutoff = now - self.ttl
        with self._lock:
            stale = [key for key, (seen_at, _) in self._events.items() if seen_at < cutoff]
            for key in stale:
                _, old_nonce_key = self._events.pop(key)
                self._nonces.pop(old_nonce_key, None)
            if event_key in self._events or nonce_key in self._nonces:
                raise _reject()
            if len(self._events) >= self.max_events:
                oldest_key = min(self._events, key=lambda key: self._events[key][0])
                _, old_nonce_key = self._events.pop(oldest_key)
                self._nonces.pop(old_nonce_key, None)
            self._events[event_key] = (now, nonce_key)
            self._nonces[nonce_key] = now


class GatewayVerifier:
    def __init__(
        self,
        registry: IdentityRegistry,
        *,
        identity_pepper: bytes,
        gateway_secret: bytes,
        replay_window: InMemoryReplayWindow | None = None,
        now: Callable[[], datetime] | None = None,
        maximum_age: timedelta = timedelta(minutes=5),
        maximum_future_skew: timedelta = timedelta(seconds=30),
        allowed_conversation_kinds: frozenset[str] = frozenset({"private"}),
    ) -> None:
        if len(identity_pepper) < 32 or len(gateway_secret) < 32:
            raise ValueError("gateway and identity secrets must each contain at least 32 bytes")
        if hmac.compare_digest(identity_pepper, gateway_secret):
            raise ValueError("gateway and identity secrets must be distinct")
        if maximum_age <= timedelta(0) or maximum_future_skew < timedelta(0):
            raise ValueError("gateway clock windows are invalid")
        if not allowed_conversation_kinds or not allowed_conversation_kinds <= _CONVERSATION_KINDS:
            raise ValueError("allowed conversation kinds are invalid")
        self.registry = registry
        self.identity_pepper = identity_pepper
        self.gateway_secret = gateway_secret
        self.replay_window = replay_window or InMemoryReplayWindow()
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.maximum_age = maximum_age
        self.maximum_future_skew = maximum_future_skew
        self.allowed_conversation_kinds = allowed_conversation_kinds

    def verify(self, payload: object) -> VerifiedChannelMessage:
        try:
            envelope = SignedChannelEnvelope.from_payload(payload)
            expected = sign_channel_event(envelope.event, self.gateway_secret)
            if not hmac.compare_digest(envelope.signature, expected):
                raise _reject()

            now = self.now()
            if now.tzinfo is None or now.utcoffset() is None:
                raise ValueError("gateway verifier clock must be timezone-aware")
            now = now.astimezone(timezone.utc)
            if envelope.event.occurred_at < now - self.maximum_age:
                raise _reject()
            if envelope.event.occurred_at > now + self.maximum_future_skew:
                raise _reject()
            if envelope.event.conversation_kind not in self.allowed_conversation_kinds:
                raise _reject()
            consent = envelope.event.consent_context
            if consent.memory_candidate or consent.tools or consent.media_processing:
                raise _reject()

            context = self.registry.resolve(
                channel_kind=envelope.event.channel,
                stable_account_id=envelope.event.actor_account_id,
                pepper=self.identity_pepper,
            )
            self.replay_window.claim(envelope.event, now=now)
            return VerifiedChannelMessage(
                context=context,
                event_id=envelope.event.event_id,
                channel_instance=envelope.event.channel_instance,
                conversation_id=envelope.event.conversation_id,
                conversation_kind=envelope.event.conversation_kind,
                occurred_at=envelope.event.occurred_at,
                message_text=envelope.event.message_text,
                reply_to=envelope.event.reply_to,
                trace_id=envelope.event.trace_id,
                delivery_capabilities=envelope.event.delivery_capabilities,
                consent_context=envelope.event.consent_context,
            )
        except (GatewayEnvelopeError, IdentityResolutionError, TypeError, ValueError):
            raise _reject() from None
