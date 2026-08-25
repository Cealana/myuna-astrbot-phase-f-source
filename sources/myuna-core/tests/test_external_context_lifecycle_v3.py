from __future__ import annotations

from datetime import datetime, timezone
import unittest

from myuna_core.authenticated_conversation import (
    SCHEMA_VERSION as AUTH_SCHEMA,
    AuthenticatedConversationContext,
)
from myuna_core.external_context.contracts import (
    EgressSafetySignals,
    ExternalContextEnvelope,
    ExternalSummary,
    ExternalTurn,
    ExternalTurnProvenance,
    ZERO_DIGEST,
    current_message_digest,
)
from myuna_core.external_context.lifecycle_v3 import (
    ReleaseBoundExternalContext,
    ReleaseBoundLifecycleRejected,
    ReleaseBoundSummaryCandidate,
    ReleaseBoundSummaryJob,
    ReleaseBoundTurnProvenance,
)


RID = "a" * 64
OVERLAY = "f" * 64


def context() -> AuthenticatedConversationContext:
    return AuthenticatedConversationContext(
        schema_version=AUTH_SCHEMA,
        request_id="request-synthetic-1",
        correlation_id="correlation-synthetic-1",
        client_id="telegram-owner-private",
        channel_kind="astrbot_telegram",
        binding_id="binding-synthetic-owner",
        principal_id="principal-synthetic-owner",
        namespace_id="namespace-synthetic-owner",
        authority_level="owner",
        channel_instance="telegram-synthetic",
        conversation_id="conversation-synthetic",
        conversation_kind="private",
        event_id="event-synthetic-1",
        trace_id="trace-synthetic-1",
        occurred_at=datetime(2026, 8, 4, tzinfo=timezone.utc),
        delivery_capabilities=("text",),
    )


def envelope() -> ExternalContextEnvelope:
    auth = context()
    message = "Unicode synthetic 涓枃"
    return ExternalContextEnvelope(
        epoch_id="telegram-owner-private-external-d-reset-v1",
        epoch_revision=0,
        turn_sequence=0,
        parent_digest=ZERO_DIGEST,
        channel_kind="astrbot_telegram",
        principal_id=auth.principal_id,
        namespace_id=auth.namespace_id,
        current_message=message,
        current_message_digest=current_message_digest(auth, message),
        summary=None,
        recent_turns=(),
        safety=EgressSafetySignals(classifier_available=True),
    )


class ReleaseBoundLifecycleTests(unittest.TestCase):
    def test_context_and_provenance_round_trip_bind_release_set(self) -> None:
        wrapped = ReleaseBoundExternalContext(RID, envelope())
        self.assertEqual(
            ReleaseBoundExternalContext.from_payload(wrapped.as_payload(), context=context()),
            wrapped,
        )
        provenance = ExternalTurnProvenance(
            epoch_id=wrapped.envelope.epoch_id,
            epoch_revision=0,
            projection_digest="b" * 64,
            sources=("owner_current_message",),
            profile_revisions=(),
            summary_version=None,
            recent_turn_start=None,
            recent_turn_end=None,
        )
        bound = ReleaseBoundTurnProvenance(RID, provenance)
        self.assertEqual(ReleaseBoundTurnProvenance.from_payload(bound.as_payload()), bound)

    def test_overlay_context_and_provenance_use_new_exact_schemas(self) -> None:
        wrapped = ReleaseBoundExternalContext(
            RID,
            envelope(),
            policy_overlay_id=OVERLAY,
        )
        self.assertEqual(
            wrapped.as_payload()["schema"],
            "myuna.external-context-release-bound.v2",
        )
        self.assertEqual(
            ReleaseBoundExternalContext.from_payload(
                wrapped.as_payload(), context=context()
            ),
            wrapped,
        )
        provenance = ExternalTurnProvenance(
            epoch_id=wrapped.envelope.epoch_id,
            epoch_revision=0,
            projection_digest="b" * 64,
            sources=("owner_current_message",),
            profile_revisions=(),
            summary_version=None,
            recent_turn_start=None,
            recent_turn_end=None,
        )
        bound = ReleaseBoundTurnProvenance(
            RID,
            provenance,
            policy_overlay_id=OVERLAY,
        )
        self.assertEqual(
            bound.as_payload()["schema"],
            "myuna.external-turn-provenance.v3",
        )
        self.assertEqual(
            ReleaseBoundTurnProvenance.from_payload(bound.as_payload()), bound
        )

        mixed = wrapped.as_payload()
        mixed.pop("policy_overlay_id")
        with self.assertRaisesRegex(
            ReleaseBoundLifecycleRejected, "fields_rejected"
        ):
            ReleaseBoundExternalContext.from_payload(mixed, context=context())

    def test_summary_job_and_candidate_bind_release_set_and_range(self) -> None:
        turn = ExternalTurn.create(
            sequence=1,
            parent_digest=ZERO_DIGEST,
            user_message="synthetic user",
            assistant_reply="synthetic assistant",
        )
        job = ReleaseBoundSummaryJob.create(
            release_set_id=RID,
            epoch_id="telegram-owner-private-external-d-reset-v1",
            base_revision=1,
            summary_version=1,
            covered_end=1,
            covered_terminal_digest=turn.digest,
            profile_revisions=(),
            prior_summary=None,
            turns=(turn,),
        )
        self.assertEqual(ReleaseBoundSummaryJob.from_payload(job.as_payload()), job)
        summary = ExternalSummary.create(
            summary_version=1,
            covered_start=1,
            covered_end=1,
            covered_terminal_digest=turn.digest,
            profile_revisions=(),
            content="bounded synthetic summary",
        )
        candidate = ReleaseBoundSummaryCandidate(RID, job.digest, summary)
        candidate.validate_for(job)

    def test_mixed_release_set_and_payload_drift_fail_closed(self) -> None:
        wrapped = ReleaseBoundExternalContext(RID, envelope()).as_payload()
        wrapped["release_set_id"] = "c" * 64
        # A different valid id is structurally valid, but the caller must compare it
        # to the protected release-set snapshot. Malformed and field drift are local.
        parsed = ReleaseBoundExternalContext.from_payload(wrapped, context=context())
        self.assertEqual(parsed.release_set_id, "c" * 64)
        wrapped["unexpected"] = True
        with self.assertRaisesRegex(ReleaseBoundLifecycleRejected, "fields_rejected"):
            ReleaseBoundExternalContext.from_payload(wrapped, context=context())

    def test_candidate_replay_mismatch_is_rejected(self) -> None:
        turn = ExternalTurn.create(
            sequence=1,
            parent_digest=ZERO_DIGEST,
            user_message="u",
            assistant_reply="a",
        )
        job = ReleaseBoundSummaryJob.create(
            release_set_id=RID,
            epoch_id="telegram-owner-private-external-d-reset-v1",
            base_revision=1,
            summary_version=1,
            covered_end=1,
            covered_terminal_digest=turn.digest,
            profile_revisions=(),
            prior_summary=None,
            turns=(turn,),
        )
        summary = ExternalSummary.create(
            summary_version=1,
            covered_start=1,
            covered_end=1,
            covered_terminal_digest=turn.digest,
            profile_revisions=(),
            content="summary",
        )
        with self.assertRaisesRegex(ReleaseBoundLifecycleRejected, "job_mismatch"):
            ReleaseBoundSummaryCandidate(RID, "d" * 64, summary).validate_for(job)
        with self.assertRaisesRegex(ReleaseBoundLifecycleRejected, "release_set_mismatch"):
            ReleaseBoundSummaryCandidate("e" * 64, job.digest, summary).validate_for(job)


if __name__ == "__main__":
    unittest.main()
