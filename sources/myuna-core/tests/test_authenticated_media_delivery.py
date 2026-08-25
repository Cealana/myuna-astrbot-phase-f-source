from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from io import BytesIO
import unittest

from myuna_core.authenticated_conversation import (
    SCHEMA_VERSION as CONTEXT_SCHEMA_VERSION,
    AuthenticatedConversationContext,
)
from myuna_core.authenticated_media_delivery import (
    DELIVERY_SCHEMA_VERSION,
    AuthenticatedMediaDelivery,
    AuthenticatedMediaDeliveryError,
    AuthenticatedMediaDeliveryPolicy,
)
from myuna_core.channel_capability import ChannelAuthorizationDecision
from myuna_core.fake_vision_media_staging import InMemoryVisionMediaStagingFake
from myuna_core.vision_input import VisionMediaDescriptor
from myuna_core.vision_media_boundary import (
    VisionMediaBoundaryError,
    VisionMediaStagingPolicy,
)


NOW = datetime(2026, 7, 27, 2, 0, tzinfo=timezone.utc)
CONTENT = b"offline-synthetic-image"


def context(*, consent: bool = True) -> AuthenticatedConversationContext:
    return AuthenticatedConversationContext(
        schema_version=CONTEXT_SCHEMA_VERSION,
        request_id="request-media-0001",
        correlation_id="correlation-media-0001",
        client_id="client-telegram-owner",
        channel_kind="astrbot_telegram",
        binding_id="binding-telegram-owner",
        principal_id="principal-owner",
        namespace_id="namespace-owner-private",
        authority_level="owner",
        channel_instance="instance-telegram",
        conversation_id="conversation-telegram-private",
        conversation_kind="private",
        event_id="event-media-0001",
        trace_id="trace-media-0001",
        occurred_at=NOW,
        delivery_capabilities=("text",),
        consent_media_processing=consent,
    )


def descriptor() -> VisionMediaDescriptor:
    return VisionMediaDescriptor(
        media_id="media-0001",
        content_sha256=hashlib.sha256(CONTENT).hexdigest(),
        mime_type="image/png",
        byte_length=len(CONTENT),
        width=640,
        height=480,
    )


def delivery() -> AuthenticatedMediaDelivery:
    return AuthenticatedMediaDelivery(
        schema_version=DELIVERY_SCHEMA_VERSION,
        delivery_id="delivery-0001",
        context=context(),
        media=(descriptor(),),
        user_question="这张图片里有什么？",
        analysis_modes=("question_answer",),
        received_at=NOW + timedelta(seconds=1),
    )


def delivery_policy_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "policy_id": "authenticated-owner-media-candidate-v1",
        "status": "inactive_candidate",
        "subject": {
            "channel_kinds": ["astrbot_qq", "astrbot_telegram"],
            "conversation_kinds": ["private"],
            "authority_levels": ["owner"],
        },
        "required_capability": "vision",
        "maximum_age_seconds": 300,
        "maximum_future_skew_seconds": 30,
        "maximum_media_count": 4,
    }


def staging_policy_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "policy_id": "vision-media-staging-candidate-v1",
        "status": "inactive_candidate",
        "storage_scope": "private-ephemeral-media-v1",
        "maximum_ttl_seconds": 300,
        "maximum_reads_per_media": 1,
        "filesystem_guards": {
            "require_private_owner": True,
            "require_regular_file": True,
            "reject_symlinks": True,
        },
        "side_effects": {
            "allow_persistent_copy": False,
            "allow_remote_fetch": False,
            "secure_disposal_required": True,
        },
    }


def decision(*, capability: str = "vision") -> ChannelAuthorizationDecision:
    return ChannelAuthorizationDecision(
        profile_id="offline-media-test-profile",
        channel_kind="astrbot_telegram",
        principal_id="principal-owner",
        namespace_id="namespace-owner-private",
        granted_capabilities=(capability,),
    )


class IdFactory:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    def __call__(self, prefix: str) -> str:
        self.counts[prefix] = self.counts.get(prefix, 0) + 1
        return f"{prefix}-{self.counts[prefix]:04d}"


class AuthenticatedMediaDeliveryTests(unittest.TestCase):
    def test_owner_media_delivery_becomes_vision_envelope_offline(self) -> None:
        policy = AuthenticatedMediaDeliveryPolicy.from_document(delivery_policy_document())
        envelope = policy.evaluate_offline(
            delivery(),
            decision(),
            now=NOW + timedelta(seconds=2),
        )
        self.assertEqual(envelope.context.principal_id, "principal-owner")
        self.assertEqual(envelope.media, (descriptor(),))
        flattened = repr(delivery().audit_metadata())
        self.assertNotIn("这张图片", flattened)
        self.assertNotIn("offline-synthetic-image", flattened)

    def test_missing_consent_capability_or_owner_scope_fails_closed(self) -> None:
        with self.assertRaises(AuthenticatedMediaDeliveryError):
            AuthenticatedMediaDelivery(
                schema_version=DELIVERY_SCHEMA_VERSION,
                delivery_id="delivery-0002",
                context=context(consent=False),
                media=(descriptor(),),
                user_question="describe",
                analysis_modes=("describe",),
                received_at=NOW + timedelta(seconds=1),
            )
        policy = AuthenticatedMediaDeliveryPolicy.from_document(delivery_policy_document())
        with self.assertRaises(AuthenticatedMediaDeliveryError):
            policy.evaluate_offline(
                delivery(),
                decision(capability="conversation"),
                now=NOW + timedelta(seconds=2),
            )

    def test_delivery_policy_is_exact_and_inactive(self) -> None:
        document = delivery_policy_document()
        document["status"] = "active"
        with self.assertRaises(AuthenticatedMediaDeliveryError):
            AuthenticatedMediaDeliveryPolicy.from_document(document)

    def test_recent_delivery_cannot_wrap_a_stale_authenticated_event(self) -> None:
        stale_context = replace(
            context(),
            occurred_at=NOW - timedelta(seconds=600),
        )
        candidate = AuthenticatedMediaDelivery(
            schema_version=DELIVERY_SCHEMA_VERSION,
            delivery_id="delivery-stale-context",
            context=stale_context,
            media=(descriptor(),),
            user_question="describe",
            analysis_modes=("describe",),
            received_at=NOW + timedelta(seconds=1),
        )
        with self.assertRaises(AuthenticatedMediaDeliveryError):
            AuthenticatedMediaDeliveryPolicy.from_document(
                delivery_policy_document()
            ).evaluate_offline(
                candidate,
                decision(),
                now=NOW + timedelta(seconds=2),
            )
        document = deepcopy(delivery_policy_document())
        document["unexpected"] = True
        with self.assertRaises(AuthenticatedMediaDeliveryError):
            AuthenticatedMediaDeliveryPolicy.from_document(document)

    def test_fake_stages_reads_once_and_disposes_without_filesystem(self) -> None:
        current = [NOW + timedelta(seconds=2)]
        fake = InMemoryVisionMediaStagingFake(
            policy=VisionMediaStagingPolicy.from_document(staging_policy_document()),
            now=lambda: current[0],
            next_id=IdFactory(),
        )
        envelope = delivery().to_vision_envelope()
        ticket = fake.stage_verified_streams(
            envelope=envelope,
            streams={"media-0001": BytesIO(CONTENT)},
            expires_at=current[0] + timedelta(seconds=300),
        )
        self.assertEqual(fake.staged_byte_count(), len(CONTENT))
        lease = fake.lease_once(ticket=ticket, media_id="media-0001", now=current[0])
        self.assertEqual(fake.read_once(lease, maximum_bytes=1024), CONTENT)
        self.assertEqual(fake.staged_byte_count(), 0)
        with self.assertRaises(VisionMediaBoundaryError):
            fake.read_once(lease, maximum_bytes=1024)
        receipts = fake.dispose(ticket, reason="consumed", now=current[0])
        self.assertEqual(receipts[0].reason, "consumed")
        self.assertEqual(fake.dispose(ticket, reason="consumed", now=current[0]), receipts)

    def test_fake_rejects_hash_mismatch_and_expires_unread_bytes(self) -> None:
        current = [NOW + timedelta(seconds=2)]
        fake = InMemoryVisionMediaStagingFake(
            policy=VisionMediaStagingPolicy.from_document(staging_policy_document()),
            now=lambda: current[0],
            next_id=IdFactory(),
        )
        with self.assertRaises(VisionMediaBoundaryError):
            fake.stage_verified_streams(
                envelope=delivery().to_vision_envelope(),
                streams={"media-0001": BytesIO(CONTENT + b"tampered")},
                expires_at=current[0] + timedelta(seconds=300),
            )
        ticket = fake.stage_verified_streams(
            envelope=delivery().to_vision_envelope(),
            streams={"media-0001": BytesIO(CONTENT)},
            expires_at=current[0] + timedelta(seconds=30),
        )
        current[0] += timedelta(seconds=31)
        receipts = fake.expire(now=current[0])
        self.assertEqual(receipts[0].stage_id, ticket.stage_id)
        self.assertEqual(receipts[0].reason, "expired")
        self.assertEqual(fake.staged_byte_count(), 0)


if __name__ == "__main__":
    unittest.main()
