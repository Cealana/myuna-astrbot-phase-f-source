from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Mapping

from .authenticated_conversation import AuthenticatedConversationContext
from .channel_gateway import SUPPORTED_CHANNELS


SCHEMA_VERSION = 1
OWNER_PRIVATE_NO_MEMORY_SCOPE = "owner_private_dev_no_memory"
OWNER_PRIVATE_READONLY_MEMORY_V1_SCOPE = "owner_private_dev_readonly_memory_v1"
OWNER_PRIVATE_READONLY_MEMORY_V2_SCOPE = "owner_private_dev_readonly_memory_v2"
OWNER_PRIVATE_PROFILE_READ_V1_SCOPE = "owner_private_dev_profile_read_v1"
OWNER_PRIVATE_PROFILE_WRITE_V1_SCOPE = "owner_private_dev_profile_write_v1"
_SUPPORTED_RESPONSE_SCOPES = frozenset(
    {
        OWNER_PRIVATE_NO_MEMORY_SCOPE,
        OWNER_PRIVATE_READONLY_MEMORY_V1_SCOPE,
        OWNER_PRIVATE_READONLY_MEMORY_V2_SCOPE,
        OWNER_PRIVATE_PROFILE_READ_V1_SCOPE,
        OWNER_PRIVATE_PROFILE_WRITE_V1_SCOPE,
    }
)
_CAPABILITIES = frozenset(
    {
        "conversation",
        "long_term_memory_read",
        "long_term_memory_write",
        "vision",
        "tools",
        "external_data",
        "external_actions",
        "system_administration",
    }
)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class ChannelCapabilityProfileError(PermissionError):
    """Fail-closed channel-neutral authorization error."""


def _reject() -> ChannelCapabilityProfileError:
    return ChannelCapabilityProfileError("channel capability profile rejected")


def _require_exact_keys(
    document: Mapping[str, object],
    expected: set[str] | frozenset[str],
    label: str,
) -> None:
    if set(document) != set(expected):
        raise ValueError(f"{label} fields do not match the v1 schema")


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{label} must be a safe identifier")
    return value


def _string_set(
    value: object,
    *,
    label: str,
    allowed: frozenset[str],
) -> frozenset[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) for item in value)
        or len(value) != len(set(value))
    ):
        raise ValueError(f"{label} must be a non-empty unique string list")
    parsed = frozenset(value)
    if not parsed <= allowed:
        raise ValueError(f"{label} contains unsupported values")
    return parsed


@dataclass(frozen=True, slots=True)
class ChannelAuthorizationDecision:
    profile_id: str
    channel_kind: str
    principal_id: str
    namespace_id: str
    granted_capabilities: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ChannelNeutralCapabilityProfile:
    """Deterministic owner-private grants shared by isolated channel adapters."""

    schema_version: int
    profile_id: str
    environment: str
    response_scope: str
    allowed_channel_kinds: frozenset[str]
    allowed_conversation_kinds: frozenset[str]
    allowed_authority_levels: frozenset[str]
    delivery_capabilities: frozenset[str]
    memory_protocol: str
    capabilities: Mapping[str, bool]

    @classmethod
    def from_document(cls, document: object) -> ChannelNeutralCapabilityProfile:
        try:
            if not isinstance(document, Mapping):
                raise ValueError("profile must be an object")
            _require_exact_keys(
                document,
                {
                    "schema_version",
                    "profile_id",
                    "environment",
                    "response_scope",
                    "subject",
                    "delivery_capabilities",
                    "memory_protocol",
                    "capabilities",
                },
                "profile",
            )
            if document["schema_version"] != SCHEMA_VERSION:
                raise ValueError("unsupported channel capability profile schema")
            environment = document["environment"]
            if environment != "dev":
                raise ValueError("v1 channel capability profiles are restricted to dev")
            response_scope = document["response_scope"]
            if response_scope not in _SUPPORTED_RESPONSE_SCOPES:
                raise ValueError("unsupported owner-private response scope")

            subject = document["subject"]
            if not isinstance(subject, Mapping):
                raise ValueError("subject must be an object")
            _require_exact_keys(
                subject,
                {"channel_kinds", "conversation_kinds", "authority_levels"},
                "subject",
            )
            channels = _string_set(
                subject["channel_kinds"],
                label="subject.channel_kinds",
                allowed=SUPPORTED_CHANNELS,
            )
            conversation_kinds = _string_set(
                subject["conversation_kinds"],
                label="subject.conversation_kinds",
                allowed=frozenset({"private"}),
            )
            authority_levels = _string_set(
                subject["authority_levels"],
                label="subject.authority_levels",
                allowed=frozenset({"owner"}),
            )
            delivery = _string_set(
                document["delivery_capabilities"],
                label="delivery_capabilities",
                allowed=frozenset({"text"}),
            )

            capability_document = document["capabilities"]
            if not isinstance(capability_document, Mapping):
                raise ValueError("capabilities must be an object")
            _require_exact_keys(capability_document, _CAPABILITIES, "capabilities")
            if any(not isinstance(value, bool) for value in capability_document.values()):
                raise ValueError("capability grants must be boolean")
            capabilities = dict(capability_document)
            if not capabilities["conversation"]:
                raise ValueError("conversation must remain enabled")
            if any(
                capabilities[name]
                for name in (
                    "vision",
                    "tools",
                    "external_data",
                    "external_actions",
                    "system_administration",
                )
            ):
                raise ValueError("v1 vision, tool, external, and admin grants are forbidden")

            memory_protocol = document["memory_protocol"]
            expected_memory = {
                OWNER_PRIVATE_NO_MEMORY_SCOPE: ("none", False, False),
                OWNER_PRIVATE_READONLY_MEMORY_V1_SCOPE: ("v1", True, False),
                OWNER_PRIVATE_READONLY_MEMORY_V2_SCOPE: ("v2", True, False),
                OWNER_PRIVATE_PROFILE_READ_V1_SCOPE: ("profile-v1", True, False),
                OWNER_PRIVATE_PROFILE_WRITE_V1_SCOPE: (
                    "profile-write-v1",
                    True,
                    True,
                ),
            }[response_scope]
            if (
                memory_protocol != expected_memory[0]
                or capabilities["long_term_memory_read"] is not expected_memory[1]
                or capabilities["long_term_memory_write"] is not expected_memory[2]
            ):
                raise ValueError("memory protocol does not match the response scope")

            return cls(
                schema_version=SCHEMA_VERSION,
                profile_id=_identifier(document["profile_id"], "profile_id"),
                environment=environment,
                response_scope=response_scope,
                allowed_channel_kinds=channels,
                allowed_conversation_kinds=conversation_kinds,
                allowed_authority_levels=authority_levels,
                delivery_capabilities=delivery,
                memory_protocol=memory_protocol,
                capabilities=MappingProxyType(capabilities),
            )
        except (KeyError, TypeError, ValueError):
            raise _reject() from None

    @classmethod
    def load(cls, path: Path) -> ChannelNeutralCapabilityProfile:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            raise _reject() from None
        return cls.from_document(document)

    def authorize(
        self,
        context: AuthenticatedConversationContext,
        *,
        requested_capabilities: tuple[str, ...] = ("conversation",),
    ) -> ChannelAuthorizationDecision:
        try:
            if context.channel_kind not in self.allowed_channel_kinds:
                raise _reject()
            if context.conversation_kind not in self.allowed_conversation_kinds:
                raise _reject()
            if context.authority_level not in self.allowed_authority_levels:
                raise _reject()
            if not set(context.delivery_capabilities) <= self.delivery_capabilities:
                raise _reject()
            if (
                len(requested_capabilities) != len(set(requested_capabilities))
                or any(name not in _CAPABILITIES for name in requested_capabilities)
                or any(not self.capabilities[name] for name in requested_capabilities)
            ):
                raise _reject()
            if context.consent_memory_candidate and not self.capabilities[
                "long_term_memory_write"
            ]:
                raise _reject()
            if context.consent_tools and not self.capabilities["tools"]:
                raise _reject()
            if context.consent_media_processing and not self.capabilities["vision"]:
                raise _reject()
            return ChannelAuthorizationDecision(
                profile_id=self.profile_id,
                channel_kind=context.channel_kind,
                principal_id=context.principal_id,
                namespace_id=context.namespace_id,
                granted_capabilities=tuple(sorted(requested_capabilities)),
            )
        except (ChannelCapabilityProfileError, KeyError, TypeError, ValueError):
            raise _reject() from None
