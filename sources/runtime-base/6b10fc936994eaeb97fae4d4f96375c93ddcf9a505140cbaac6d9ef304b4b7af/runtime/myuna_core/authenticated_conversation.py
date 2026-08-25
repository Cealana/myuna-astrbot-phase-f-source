from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Mapping

from .channel_gateway import SUPPORTED_CHANNELS, VerifiedChannelMessage


SCHEMA_VERSION = "myuna.authenticated-conversation-context.v1"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_AUTHORITY_LEVELS = frozenset({"owner", "member", "service", "test"})
_CONVERSATION_KINDS = frozenset({"private", "group"})


class AuthenticatedConversationContextError(PermissionError):
    """Fail-closed error that does not disclose which identity field failed."""


def _reject() -> AuthenticatedConversationContextError:
    return AuthenticatedConversationContextError(
        "authenticated conversation context rejected"
    )


def _require_safe_id(value: str, label: str) -> None:
    if _SAFE_ID.fullmatch(value) is None:
        raise ValueError(f"{label} must be a safe opaque identifier")


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("occurred_at must be an ISO-8601 string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("occurred_at must include a timezone offset")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class AuthenticatedConversationContext:
    """Trusted request metadata kept outside model-visible conversation content.

    The context is derived only after both the channel client and the channel
    account have been authenticated.  It intentionally contains no raw account
    identifier, account fingerprint, credential, message text, or prompt data.
    """

    schema_version: str
    request_id: str
    correlation_id: str
    client_id: str
    channel_kind: str
    binding_id: str
    principal_id: str
    namespace_id: str
    authority_level: str
    channel_instance: str
    conversation_id: str
    conversation_kind: str
    event_id: str
    trace_id: str
    occurred_at: datetime
    delivery_capabilities: tuple[str, ...]
    consent_memory_candidate: bool = False
    consent_tools: bool = False
    consent_media_processing: bool = False

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported authenticated conversation context schema")
        for value, label in (
            (self.request_id, "request_id"),
            (self.correlation_id, "correlation_id"),
            (self.client_id, "client_id"),
            (self.binding_id, "binding_id"),
            (self.principal_id, "principal_id"),
            (self.namespace_id, "namespace_id"),
            (self.channel_instance, "channel_instance"),
            (self.conversation_id, "conversation_id"),
            (self.event_id, "event_id"),
            (self.trace_id, "trace_id"),
        ):
            _require_safe_id(value, label)
        if self.channel_kind not in SUPPORTED_CHANNELS:
            raise ValueError("unsupported authenticated channel")
        if self.authority_level not in _AUTHORITY_LEVELS:
            raise ValueError("unsupported authority level")
        if self.conversation_kind not in _CONVERSATION_KINDS:
            raise ValueError("unsupported conversation kind")
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("occurred_at must include a timezone offset")
        object.__setattr__(
            self,
            "occurred_at",
            self.occurred_at.astimezone(timezone.utc),
        )
        if self.delivery_capabilities != ("text",):
            raise ValueError("v1 authenticated context supports text delivery only")

    @classmethod
    def from_verified_channel_message(
        cls,
        message: VerifiedChannelMessage,
        *,
        authenticated_client_id: str,
        authenticated_channel_kind: str,
        request_id: str,
        correlation_id: str | None = None,
    ) -> AuthenticatedConversationContext:
        """Bind an authenticated HTTP client to an independently verified event."""

        try:
            if authenticated_channel_kind != message.context.channel_kind:
                raise _reject()
            return cls(
                schema_version=SCHEMA_VERSION,
                request_id=request_id,
                correlation_id=correlation_id or request_id,
                client_id=authenticated_client_id,
                channel_kind=authenticated_channel_kind,
                binding_id=message.context.binding_id,
                principal_id=message.context.principal_id,
                namespace_id=message.context.namespace_id,
                authority_level=message.context.authority_level,
                channel_instance=message.channel_instance,
                conversation_id=message.conversation_id,
                conversation_kind=message.conversation_kind,
                event_id=message.event_id,
                trace_id=message.trace_id,
                occurred_at=message.occurred_at,
                delivery_capabilities=message.delivery_capabilities,
                consent_memory_candidate=message.consent_context.memory_candidate,
                consent_tools=message.consent_context.tools,
                consent_media_processing=message.consent_context.media_processing,
            )
        except (AuthenticatedConversationContextError, TypeError, ValueError):
            raise _reject() from None

    def as_payload(self) -> dict[str, object]:
        """Return a strict internal payload with no account or credential material."""

        return {
            "authority_level": self.authority_level,
            "binding_id": self.binding_id,
            "channel_instance": self.channel_instance,
            "channel_kind": self.channel_kind,
            "client_id": self.client_id,
            "consent": {
                "media_processing": self.consent_media_processing,
                "memory_candidate": self.consent_memory_candidate,
                "tools": self.consent_tools,
            },
            "conversation_id": self.conversation_id,
            "conversation_kind": self.conversation_kind,
            "correlation_id": self.correlation_id,
            "delivery_capabilities": list(self.delivery_capabilities),
            "event_id": self.event_id,
            "namespace_id": self.namespace_id,
            "occurred_at": self.occurred_at.isoformat(timespec="microseconds"),
            "principal_id": self.principal_id,
            "request_id": self.request_id,
            "schema_version": self.schema_version,
            "trace_id": self.trace_id,
        }

    @classmethod
    def from_payload(
        cls,
        payload: object,
        *,
        authenticated_client_id: str,
        authenticated_channel_kind: str,
    ) -> AuthenticatedConversationContext:
        """Parse metadata only after transport authentication has succeeded."""

        try:
            if not isinstance(payload, Mapping):
                raise ValueError("context must be an object")
            required = {
                "authority_level",
                "binding_id",
                "channel_instance",
                "channel_kind",
                "client_id",
                "consent",
                "conversation_id",
                "conversation_kind",
                "correlation_id",
                "delivery_capabilities",
                "event_id",
                "namespace_id",
                "occurred_at",
                "principal_id",
                "request_id",
                "schema_version",
                "trace_id",
            }
            if set(payload) != required:
                raise ValueError("context fields do not match the v1 schema")
            string_fields = {
                key: payload[key]
                for key in required
                - {"consent", "delivery_capabilities", "occurred_at"}
            }
            if any(not isinstance(value, str) for value in string_fields.values()):
                raise ValueError("context identifiers must be strings")
            if payload["client_id"] != authenticated_client_id:
                raise _reject()
            if payload["channel_kind"] != authenticated_channel_kind:
                raise _reject()
            consent = payload["consent"]
            if (
                not isinstance(consent, Mapping)
                or set(consent) != {"media_processing", "memory_candidate", "tools"}
                or any(not isinstance(value, bool) for value in consent.values())
            ):
                raise ValueError("context consent is invalid")
            delivery = payload["delivery_capabilities"]
            if delivery != ["text"]:
                raise ValueError("context delivery capabilities are invalid")
            return cls(
                schema_version=string_fields["schema_version"],
                request_id=string_fields["request_id"],
                correlation_id=string_fields["correlation_id"],
                client_id=string_fields["client_id"],
                channel_kind=string_fields["channel_kind"],
                binding_id=string_fields["binding_id"],
                principal_id=string_fields["principal_id"],
                namespace_id=string_fields["namespace_id"],
                authority_level=string_fields["authority_level"],
                channel_instance=string_fields["channel_instance"],
                conversation_id=string_fields["conversation_id"],
                conversation_kind=string_fields["conversation_kind"],
                event_id=string_fields["event_id"],
                trace_id=string_fields["trace_id"],
                occurred_at=_parse_timestamp(payload["occurred_at"]),
                delivery_capabilities=("text",),
                consent_memory_candidate=consent["memory_candidate"],
                consent_tools=consent["tools"],
                consent_media_processing=consent["media_processing"],
            )
        except (AuthenticatedConversationContextError, KeyError, TypeError, ValueError):
            raise _reject() from None

    def audit_details(self) -> dict[str, object]:
        return {
            "binding_id": self.binding_id,
            "channel_kind": self.channel_kind,
            "client_id": self.client_id,
            "conversation_kind": self.conversation_kind,
            "correlation_id": self.correlation_id,
            "event_id": self.event_id,
            "namespace_id": self.namespace_id,
            "principal_id": self.principal_id,
            "request_id": self.request_id,
            "trace_id": self.trace_id,
        }
