from __future__ import annotations

from datetime import datetime, timezone
import unittest

from myuna_core.authenticated_conversation import (
    SCHEMA_VERSION as CONTEXT_SCHEMA_VERSION,
    AuthenticatedConversationContext,
)
from myuna_core.channel_capability import ChannelNeutralCapabilityProfile
from myuna_core.owner_profile.access import (
    EXTERNAL_PROFILE_EGRESS_PURPOSE,
    EXTERNAL_PROFILE_MODEL,
    EXTERNAL_PROFILE_PROJECTION_POLICY,
    OwnerProfileAccessError,
    OwnerProfileAccessPolicy,
    OwnerProfileExternalEgressPolicy,
)


def profile_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "profile_id": "owner-private-profile-read-v1",
        "environment": "dev",
        "response_scope": "owner_private_dev_profile_read_v1",
        "subject": {
            "channel_kinds": ["astrbot_telegram"],
            "conversation_kinds": ["private"],
            "authority_levels": ["owner"],
        },
        "delivery_capabilities": ["text"],
        "memory_protocol": "profile-v1",
        "capabilities": {
            "conversation": True,
            "long_term_memory_read": True,
            "long_term_memory_write": False,
            "vision": False,
            "tools": False,
            "external_data": False,
            "external_actions": False,
            "system_administration": False,
        },
    }


def context(**overrides: object) -> AuthenticatedConversationContext:
    values: dict[str, object] = {
        "schema_version": CONTEXT_SCHEMA_VERSION,
        "request_id": "req-1",
        "correlation_id": "corr-1",
        "client_id": "telegram-owner-private",
        "channel_kind": "astrbot_telegram",
        "binding_id": "binding-owner",
        "principal_id": "principal-owner",
        "namespace_id": "namespace-owner",
        "authority_level": "owner",
        "channel_instance": "telegram-primary",
        "conversation_id": "conversation-private",
        "conversation_kind": "private",
        "event_id": "event-1",
        "trace_id": "trace-1",
        "occurred_at": datetime(2026, 8, 1, tzinfo=timezone.utc),
        "delivery_capabilities": ("text",),
    }
    values.update(overrides)
    return AuthenticatedConversationContext(**values)  # type: ignore[arg-type]


class OwnerProfileAccessPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = ChannelNeutralCapabilityProfile.from_document(profile_document())
        self.policy = OwnerProfileAccessPolicy(
            self.profile,
            provider_allowlist=frozenset({"local"}),
        )

    def test_authenticated_owner_private_channel_and_local_provider_are_allowed(self) -> None:
        decision = self.policy.authorize(context(), provider_name="local")
        self.assertEqual(decision.channel_kind, "astrbot_telegram")
        self.assertEqual(decision.provider_name, "local")

    def test_deepseek_is_structurally_forbidden_even_if_requested(self) -> None:
        with self.assertRaises(OwnerProfileAccessError) as caught:
            self.policy.authorize(context(), provider_name="deepseek")
        self.assertEqual(caught.exception.code, "provider_egress_forbidden")

    def test_missing_authenticated_context_fails_closed(self) -> None:
        with self.assertRaises(OwnerProfileAccessError) as caught:
            self.policy.authorize(None, provider_name="local")
        self.assertEqual(caught.exception.code, "authenticated_context_required")

    def test_wrong_channel_or_authority_fails_closed(self) -> None:
        for changed in (
            {"channel_kind": "astrbot_qq"},
            {"client_id": "telegram-non-owner-client"},
            {"authority_level": "member"},
            {"conversation_kind": "group"},
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(OwnerProfileAccessError) as caught:
                    self.policy.authorize(context(**changed), provider_name="local")
                self.assertEqual(caught.exception.code, "owner_channel_scope_rejected")

    def test_unsafe_provider_allowlist_is_rejected_at_startup(self) -> None:
        for providers in (frozenset(), frozenset({"deepseek"}), frozenset({"unknown"})):
            with self.subTest(providers=providers):
                with self.assertRaises(ValueError):
                    OwnerProfileAccessPolicy(
                        self.profile,
                        provider_allowlist=providers,
                    )

    def test_external_egress_is_a_purpose_bound_telegram_only_exception(self) -> None:
        policy = OwnerProfileExternalEgressPolicy(self.profile)
        decision = policy.authorize(
            context(),
            provider_name="deepseek",
            model_name=EXTERNAL_PROFILE_MODEL,
            egress_purpose=EXTERNAL_PROFILE_EGRESS_PURPOSE,
            projection_policy_version=EXTERNAL_PROFILE_PROJECTION_POLICY,
        )
        self.assertEqual(decision.provider_name, "deepseek")
        for changes, code in (
            ({"channel_kind": "astrbot_qq", "client_id": "qq-owner-private"},
             "external_owner_channel_scope_rejected"),
            ({"client_id": "telegram-non-owner-client"},
             "external_owner_channel_scope_rejected"),
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(OwnerProfileAccessError) as caught:
                    policy.authorize(
                        context(**changes),
                        provider_name="deepseek",
                        model_name=EXTERNAL_PROFILE_MODEL,
                        egress_purpose=EXTERNAL_PROFILE_EGRESS_PURPOSE,
                        projection_policy_version=EXTERNAL_PROFILE_PROJECTION_POLICY,
                    )
                self.assertEqual(caught.exception.code, code)

    def test_external_egress_rejects_provider_purpose_and_policy_drift(self) -> None:
        policy = OwnerProfileExternalEgressPolicy(self.profile)
        for provider, model, purpose, projection, code in (
            (
                "local",
                EXTERNAL_PROFILE_MODEL,
                EXTERNAL_PROFILE_EGRESS_PURPOSE,
                EXTERNAL_PROFILE_PROJECTION_POLICY,
                "external_provider_not_authorized",
            ),
            (
                "deepseek",
                "deepseek-v4-pro",
                EXTERNAL_PROFILE_EGRESS_PURPOSE,
                EXTERNAL_PROFILE_PROJECTION_POLICY,
                "external_model_not_authorized",
            ),
            (
                "deepseek",
                EXTERNAL_PROFILE_MODEL,
                "other-purpose",
                EXTERNAL_PROFILE_PROJECTION_POLICY,
                "external_egress_purpose_rejected",
            ),
            (
                "deepseek",
                EXTERNAL_PROFILE_MODEL,
                EXTERNAL_PROFILE_EGRESS_PURPOSE,
                "future-policy",
                "external_projection_policy_rejected",
            ),
        ):
            with self.subTest(code=code):
                with self.assertRaises(OwnerProfileAccessError) as caught:
                    policy.authorize(
                        context(),
                        provider_name=provider,
                        model_name=model,
                        egress_purpose=purpose,
                        projection_policy_version=projection,
                    )
                self.assertEqual(caught.exception.code, code)


if __name__ == "__main__":
    unittest.main()
