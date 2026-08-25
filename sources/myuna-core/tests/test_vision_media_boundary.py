from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import unittest

from myuna_core.authenticated_conversation import (
    SCHEMA_VERSION as CONTEXT_SCHEMA_VERSION,
    AuthenticatedConversationContext,
)
from myuna_core.vision_input import (
    INPUT_SCHEMA_VERSION,
    VisionInputEnvelope,
    VisionMediaDescriptor,
)
from myuna_core.vision_media_boundary import (
    LEASE_SCHEMA_VERSION,
    TICKET_SCHEMA_VERSION,
    VisionMediaBoundaryError,
    VisionMediaLease,
    VisionMediaStagingPolicy,
    VisionMediaStagingTicket,
    validate_lease,
    validate_ticket,
)


NOW = datetime(2026, 7, 27, 1, 30, tzinfo=timezone.utc)


def policy_document() -> dict[str, object]:
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


def descriptor() -> VisionMediaDescriptor:
    return VisionMediaDescriptor(
        media_id="media-boundary-0001",
        content_sha256=hashlib.sha256(b"image").hexdigest(),
        mime_type="image/png",
        byte_length=5,
        width=32,
        height=32,
    )


def envelope() -> VisionInputEnvelope:
    context = AuthenticatedConversationContext(
        schema_version=CONTEXT_SCHEMA_VERSION,
        request_id="request-boundary-0001",
        correlation_id="correlation-boundary-0001",
        client_id="client-telegram-owner",
        channel_kind="astrbot_telegram",
        binding_id="binding-telegram-owner",
        principal_id="principal-owner",
        namespace_id="namespace-owner-private",
        authority_level="owner",
        channel_instance="instance-telegram",
        conversation_id="conversation-telegram-private",
        conversation_kind="private",
        event_id="event-boundary-0001",
        trace_id="trace-boundary-0001",
        occurred_at=NOW,
        delivery_capabilities=("text",),
        consent_media_processing=True,
    )
    return VisionInputEnvelope(
        schema_version=INPUT_SCHEMA_VERSION,
        context=context,
        media=(descriptor(),),
        user_question="图片里有什么？",
    )


def ticket() -> VisionMediaStagingTicket:
    return VisionMediaStagingTicket(
        schema_version=TICKET_SCHEMA_VERSION,
        stage_id="stage-0001",
        request_id="request-boundary-0001",
        trace_id="trace-boundary-0001",
        media=(descriptor(),),
        created_at=NOW,
        expires_at=NOW + timedelta(seconds=300),
        storage_scope="private-ephemeral-media-v1",
    )


class VisionMediaBoundaryTests(unittest.TestCase):
    def test_ticket_and_single_read_lease_bind_to_request_and_media(self) -> None:
        policy = VisionMediaStagingPolicy.from_document(policy_document())
        selected_ticket = ticket()
        validate_ticket(
            envelope=envelope(),
            ticket=selected_ticket,
            policy=policy,
            now=NOW + timedelta(seconds=1),
        )
        lease = VisionMediaLease(
            schema_version=LEASE_SCHEMA_VERSION,
            lease_id="lease-0001",
            stage_id=selected_ticket.stage_id,
            media_id="media-boundary-0001",
            request_id=selected_ticket.request_id,
            issued_at=NOW + timedelta(seconds=1),
            expires_at=NOW + timedelta(seconds=60),
        )
        self.assertEqual(
            validate_lease(ticket=selected_ticket, lease=lease, now=NOW + timedelta(seconds=2)),
            descriptor(),
        )

    def test_expired_or_cross_request_ticket_and_lease_fail_closed(self) -> None:
        policy = VisionMediaStagingPolicy.from_document(policy_document())
        with self.assertRaises(VisionMediaBoundaryError):
            validate_ticket(
                envelope=envelope(),
                ticket=ticket(),
                policy=policy,
                now=NOW + timedelta(seconds=301),
            )
        bad_lease = VisionMediaLease(
            schema_version=LEASE_SCHEMA_VERSION,
            lease_id="lease-0002",
            stage_id="stage-other",
            media_id="media-boundary-0001",
            request_id="request-boundary-0001",
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=30),
        )
        with self.assertRaises(VisionMediaBoundaryError):
            validate_lease(ticket=ticket(), lease=bad_lease, now=NOW + timedelta(seconds=1))

    def test_policy_forbids_persistence_remote_fetch_and_multiple_reads(self) -> None:
        mutations = (
            lambda value: value["side_effects"].update(allow_persistent_copy=True),
            lambda value: value["side_effects"].update(allow_remote_fetch=True),
            lambda value: value.update(maximum_reads_per_media=2),
            lambda value: value["filesystem_guards"].update(reject_symlinks=False),
        )
        for mutate in mutations:
            document = deepcopy(policy_document())
            mutate(document)
            with self.assertRaises(VisionMediaBoundaryError):
                VisionMediaStagingPolicy.from_document(document)

    def test_audit_ticket_exposes_no_path_handle_question_or_identity(self) -> None:
        flattened = repr(ticket().audit_metadata()).casefold()
        for forbidden in (
            "path",
            "url",
            "handle",
            "图片里有什么",
            "principal",
            "binding",
            "account",
        ):
            self.assertNotIn(forbidden, flattened)


if __name__ == "__main__":
    unittest.main()
