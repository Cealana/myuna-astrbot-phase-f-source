from __future__ import annotations

from dataclasses import dataclass

from myuna_core.authenticated_conversation import AuthenticatedConversationContext
from myuna_core.channel_capability import (
    OWNER_PRIVATE_PROFILE_READ_V1_SCOPE,
    OWNER_PRIVATE_PROFILE_WRITE_V1_SCOPE,
    ChannelCapabilityProfileError,
    ChannelNeutralCapabilityProfile,
)


OWNER_PROFILE_RUNTIME_CAPABILITY_SCOPE = (
    "verified owner private text; owner profile baseline; read-only bounded sections"
)
EXTERNAL_PROFILE_EGRESS_PURPOSE = "telegram_owner_profile_external_generation_v1"
EXTERNAL_PROFILE_PROJECTION_POLICY = "p07-hybrid-external-generation-v1"
EXTERNAL_PROFILE_PROJECTION_POLICIES = frozenset(
    {
        EXTERNAL_PROFILE_PROJECTION_POLICY,
        "p01b-contextual-visual-interpretation-v1",
        "p07-raw-first-episodic-v1",
    }
)
EXTERNAL_PROFILE_MODEL = "deepseek-v4-flash"
FORBIDDEN_PROFILE_PROVIDERS = frozenset({"deepseek"})
_SUPPORTED_PROVIDER_NAMES = frozenset({"local", "openai"})
_OWNER_PROFILE_CLIENT_BY_CHANNEL = {
    "astrbot_qq": "qq-owner-private",
    "astrbot_telegram": "telegram-owner-private",
}


class OwnerProfileAccessError(PermissionError):
    def __init__(self, code: str) -> None:
        super().__init__("Owner Profile access rejected")
        self.code = code


@dataclass(frozen=True, slots=True)
class OwnerProfileAccessDecision:
    channel_kind: str
    principal_id: str
    namespace_id: str
    provider_name: str


class OwnerProfileAccessPolicy:
    """Intersect authenticated Owner scope with an explicit provider egress grant."""

    def __init__(
        self,
        capability_profile: ChannelNeutralCapabilityProfile,
        *,
        provider_allowlist: frozenset[str],
    ) -> None:
        supported_profiles = {
            OWNER_PRIVATE_PROFILE_READ_V1_SCOPE: "profile-v1",
            OWNER_PRIVATE_PROFILE_WRITE_V1_SCOPE: "profile-write-v1",
        }
        if capability_profile.response_scope not in supported_profiles:
            raise ValueError("channel profile is not an Owner Profile scope")
        if capability_profile.memory_protocol != supported_profiles[
            capability_profile.response_scope
        ]:
            raise ValueError("channel profile memory protocol drifted")
        if not provider_allowlist:
            raise ValueError("Profile provider allowlist cannot be empty")
        if (
            not provider_allowlist <= _SUPPORTED_PROVIDER_NAMES
            or provider_allowlist & FORBIDDEN_PROFILE_PROVIDERS
        ):
            raise ValueError("Profile provider allowlist is unsafe")
        self.capability_profile = capability_profile
        self.provider_allowlist = provider_allowlist

    def authorize(
        self,
        context: AuthenticatedConversationContext | None,
        *,
        provider_name: str,
    ) -> OwnerProfileAccessDecision:
        if context is None:
            raise OwnerProfileAccessError("authenticated_context_required")
        if provider_name in FORBIDDEN_PROFILE_PROVIDERS:
            raise OwnerProfileAccessError("provider_egress_forbidden")
        if provider_name not in self.provider_allowlist:
            raise OwnerProfileAccessError("provider_not_authorized")
        try:
            if context.client_id != _OWNER_PROFILE_CLIENT_BY_CHANNEL.get(
                context.channel_kind
            ):
                raise ChannelCapabilityProfileError("owner client binding rejected")
            decision = self.capability_profile.authorize(
                context,
                requested_capabilities=("conversation", "long_term_memory_read"),
            )
        except ChannelCapabilityProfileError:
            raise OwnerProfileAccessError("owner_channel_scope_rejected") from None
        return OwnerProfileAccessDecision(
            channel_kind=decision.channel_kind,
            principal_id=decision.principal_id,
            namespace_id=decision.namespace_id,
            provider_name=provider_name,
        )


class OwnerProfileExternalEgressPolicy:
    """Narrow Owner-approved exception; the default read policy stays local-only."""

    def __init__(self, capability_profile: ChannelNeutralCapabilityProfile) -> None:
        if capability_profile.response_scope != OWNER_PRIVATE_PROFILE_READ_V1_SCOPE:
            raise ValueError("external Profile egress requires the read-only Profile scope")
        if capability_profile.memory_protocol != "profile-v1":
            raise ValueError("external Profile egress memory protocol drifted")
        self.capability_profile = capability_profile

    def authorize(
        self,
        context: AuthenticatedConversationContext | None,
        *,
        provider_name: str,
        model_name: str,
        egress_purpose: str,
        projection_policy_version: str,
    ) -> OwnerProfileAccessDecision:
        if context is None:
            raise OwnerProfileAccessError("authenticated_context_required")
        if provider_name != "deepseek":
            raise OwnerProfileAccessError("external_provider_not_authorized")
        if model_name != EXTERNAL_PROFILE_MODEL:
            raise OwnerProfileAccessError("external_model_not_authorized")
        if egress_purpose != EXTERNAL_PROFILE_EGRESS_PURPOSE:
            raise OwnerProfileAccessError("external_egress_purpose_rejected")
        if projection_policy_version not in EXTERNAL_PROFILE_PROJECTION_POLICIES:
            raise OwnerProfileAccessError("external_projection_policy_rejected")
        if (
            context.channel_kind != "astrbot_telegram"
            or context.client_id != "telegram-owner-private"
        ):
            raise OwnerProfileAccessError("external_owner_channel_scope_rejected")
        try:
            decision = self.capability_profile.authorize(
                context,
                requested_capabilities=("conversation", "long_term_memory_read"),
            )
        except ChannelCapabilityProfileError:
            raise OwnerProfileAccessError("external_owner_channel_scope_rejected") from None
        return OwnerProfileAccessDecision(
            channel_kind=decision.channel_kind,
            principal_id=decision.principal_id,
            namespace_id=decision.namespace_id,
            provider_name=provider_name,
        )
