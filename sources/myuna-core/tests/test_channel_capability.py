from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import unittest

from myuna_core.authenticated_conversation import (
    SCHEMA_VERSION as CONTEXT_SCHEMA_VERSION,
    AuthenticatedConversationContext,
)
from myuna_core.channel_capability import (
    ChannelCapabilityProfileError,
    ChannelNeutralCapabilityProfile,
)
from myuna_core.channel_gateway import ASTRBOT_QQ_CHANNEL, ASTRBOT_TELEGRAM_CHANNEL


def profile_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "profile_id": "owner-private-text-readonly-memory-v2",
        "environment": "dev",
        "response_scope": "owner_private_dev_readonly_memory_v2",
        "subject": {
            "channel_kinds": [ASTRBOT_QQ_CHANNEL, ASTRBOT_TELEGRAM_CHANNEL],
            "conversation_kinds": ["private"],
            "authority_levels": ["owner"],
        },
        "delivery_capabilities": ["text"],
        "memory_protocol": "v2",
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


def context(
    channel: str,
    *,
    authority: str = "owner",
    conversation_kind: str = "private",
    consent_memory_candidate: bool = False,
    consent_tools: bool = False,
) -> AuthenticatedConversationContext:
    return AuthenticatedConversationContext(
        schema_version=CONTEXT_SCHEMA_VERSION,
        request_id="request-profile-0001",
        correlation_id="correlation-profile-0001",
        client_id=f"client-{channel}",
        channel_kind=channel,
        binding_id=f"binding-{channel}-owner",
        principal_id="principal-owner-test",
        namespace_id="namespace-owner-private",
        authority_level=authority,
        channel_instance=f"instance-{channel}",
        conversation_id=f"conversation-{channel}-private",
        conversation_kind=conversation_kind,
        event_id=f"event-{channel}-0001",
        trace_id=f"trace-{channel}-0001",
        occurred_at=datetime(2026, 7, 27, tzinfo=timezone.utc),
        delivery_capabilities=("text",),
        consent_memory_candidate=consent_memory_candidate,
        consent_tools=consent_tools,
    )


class ChannelNeutralCapabilityProfileTests(unittest.TestCase):
    def test_one_profile_authorizes_both_isolated_owner_channels(self) -> None:
        profile = ChannelNeutralCapabilityProfile.from_document(profile_document())
        decisions = [
            profile.authorize(
                context(channel),
                requested_capabilities=("conversation", "long_term_memory_read"),
            )
            for channel in (ASTRBOT_QQ_CHANNEL, ASTRBOT_TELEGRAM_CHANNEL)
        ]
        self.assertEqual(
            {decision.channel_kind for decision in decisions},
            {ASTRBOT_QQ_CHANNEL, ASTRBOT_TELEGRAM_CHANNEL},
        )
        self.assertEqual({decision.namespace_id for decision in decisions}, {"namespace-owner-private"})

    def test_profile_has_no_qq_named_capability_or_channel_in_response_scope(self) -> None:
        document = profile_document()
        self.assertNotIn("qq_channel", document["capabilities"])
        self.assertNotIn("qq", str(document["response_scope"]).casefold())
        profile = ChannelNeutralCapabilityProfile.from_document(document)
        self.assertEqual(profile.memory_protocol, "v2")

    def test_member_group_unknown_capability_and_unavailable_consent_fail_closed(self) -> None:
        profile = ChannelNeutralCapabilityProfile.from_document(profile_document())
        cases = (
            (context(ASTRBOT_QQ_CHANNEL, authority="member"), ("conversation",)),
            (context(ASTRBOT_QQ_CHANNEL, conversation_kind="group"), ("conversation",)),
            (context(ASTRBOT_QQ_CHANNEL), ("vision",)),
            (context(ASTRBOT_QQ_CHANNEL, consent_tools=True), ("conversation",)),
        )
        for candidate, requested in cases:
            with self.subTest(candidate=candidate, requested=requested):
                with self.assertRaisesRegex(
                    ChannelCapabilityProfileError,
                    "^channel capability profile rejected$",
                ):
                    profile.authorize(candidate, requested_capabilities=requested)

    def test_memory_scope_protocol_and_grant_must_match(self) -> None:
        for mutate in (
            lambda document: document.update(memory_protocol="v1"),
            lambda document: document["capabilities"].update(long_term_memory_read=False),
            lambda document: document["capabilities"].update(long_term_memory_write=True),
        ):
            document = deepcopy(profile_document())
            mutate(document)
            with self.assertRaises(ChannelCapabilityProfileError):
                ChannelNeutralCapabilityProfile.from_document(document)

    def test_schema_is_exact_and_future_power_stays_disabled(self) -> None:
        document = profile_document()
        document["unexpected"] = True
        with self.assertRaises(ChannelCapabilityProfileError):
            ChannelNeutralCapabilityProfile.from_document(document)

        for capability in (
            "vision",
            "tools",
            "external_data",
            "external_actions",
            "system_administration",
        ):
            document = deepcopy(profile_document())
            document["capabilities"][capability] = True
            with self.subTest(capability=capability):
                with self.assertRaises(ChannelCapabilityProfileError):
                    ChannelNeutralCapabilityProfile.from_document(document)

    def test_profile_write_scope_is_narrow_and_requires_explicit_consent(self) -> None:
        document = profile_document()
        document["profile_id"] = "owner-private-profile-write-v1"
        document["response_scope"] = "owner_private_dev_profile_write_v1"
        document["subject"]["channel_kinds"] = [ASTRBOT_TELEGRAM_CHANNEL]
        document["memory_protocol"] = "profile-write-v1"
        document["capabilities"]["long_term_memory_write"] = True
        profile = ChannelNeutralCapabilityProfile.from_document(document)
        decision = profile.authorize(
            context(
                ASTRBOT_TELEGRAM_CHANNEL,
                consent_memory_candidate=True,
            ),
            requested_capabilities=(
                "conversation",
                "long_term_memory_read",
                "long_term_memory_write",
            ),
        )
        self.assertEqual(decision.channel_kind, ASTRBOT_TELEGRAM_CHANNEL)
        with self.assertRaises(ChannelCapabilityProfileError):
            profile.authorize(
                context(ASTRBOT_QQ_CHANNEL, consent_memory_candidate=True),
                requested_capabilities=("conversation", "long_term_memory_write"),
            )

    def test_write_grant_is_rejected_outside_exact_write_scope(self) -> None:
        document = profile_document()
        document["capabilities"]["long_term_memory_write"] = True
        with self.assertRaises(ChannelCapabilityProfileError):
            ChannelNeutralCapabilityProfile.from_document(document)


if __name__ == "__main__":
    unittest.main()
