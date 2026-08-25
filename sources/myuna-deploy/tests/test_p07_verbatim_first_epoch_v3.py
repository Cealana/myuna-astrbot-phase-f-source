from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest

from myuna_core.authenticated_conversation import (
    SCHEMA_VERSION as AUTH_SCHEMA,
    AuthenticatedConversationContext,
)
from myuna_core.external_context.contracts import (
    EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY,
    EgressSafetySignals,
    ExternalTurnProvenance,
)
from myuna_core.external_context.lifecycle_v3 import ReleaseBoundTurnProvenance

from external_context_epoch_v3 import (
    ExternalEpochV3Binding,
    ExternalEpochV3Rejected,
    ExternalEpochV3Store,
)


RID = "b" * 64
OVERLAY = "c" * 64
EPOCH = "telegram-owner-private-external-verbatim-synthetic"


def context(index: int) -> AuthenticatedConversationContext:
    return AuthenticatedConversationContext(
        schema_version=AUTH_SCHEMA,
        request_id=f"request-verbatim-{index}",
        correlation_id=f"correlation-verbatim-{index}",
        client_id="telegram-owner-private",
        channel_kind="astrbot_telegram",
        binding_id="binding-verbatim-owner",
        principal_id="principal-verbatim-owner",
        namespace_id="namespace-verbatim-owner",
        authority_level="owner",
        channel_instance="telegram-synthetic",
        conversation_id="conversation-verbatim",
        conversation_kind="private",
        event_id=f"event-verbatim-{index}",
        trace_id=f"trace-verbatim-{index}",
        occurred_at=(
            datetime(2026, 8, 7, 12, 0, tzinfo=timezone.utc)
            + timedelta(seconds=index)
        ),
        delivery_capabilities=("text",),
    )


def binding() -> ExternalEpochV3Binding:
    return ExternalEpochV3Binding(
        channel_kind="astrbot_telegram",
        client_id="telegram-owner-private",
        principal_id="principal-verbatim-owner",
        namespace_id="namespace-verbatim-owner",
    )


def provenance(revision: int, recent_end: int | None) -> ReleaseBoundTurnProvenance:
    return ReleaseBoundTurnProvenance(
        RID,
        ExternalTurnProvenance(
            epoch_id=EPOCH,
            epoch_revision=revision,
            projection_digest=(f"{revision + 1:x}" * 64)[:64],
            sources=(
                ("owner_current_message",)
                if recent_end is None
                else ("ordinary_external_turn", "owner_current_message")
            ),
            profile_revisions=(),
            summary_version=None,
            recent_turn_start=None if recent_end is None else 1,
            recent_turn_end=recent_end,
        ),
        policy_overlay_id=OVERLAY,
    )


class P07VerbatimFirstEpochV3Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "epoch" / "epoch.db"
        self.store = ExternalEpochV3Store(
            self.database,
            epoch_id=EPOCH,
            release_set_id=RID,
            binding=binding(),
            projection_policy_version=EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY,
            policy_overlay_id=OVERLAY,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def deliver(self, index: int) -> None:
        auth = context(index)
        token = self.store.begin_turn(
            auth,
            f"synthetic user message {index}",
            EgressSafetySignals(classifier_available=True),
        )
        payload = self.store.context_payload(auth, token)["external_context"]
        self.assertEqual(
            payload["projection_policy_version"],
            EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY,
        )
        self.assertEqual(
            self.store.context_payload(auth, token)["policy_overlay_id"],
            OVERLAY,
        )
        delivery_token = sha256(f"delivery-{index}".encode("ascii")).hexdigest()
        self.store.prepare_delivery(
            auth,
            token,
            delivery_token=delivery_token,
            assistant_reply=f"synthetic assistant reply {index}",
            provenance=provenance(
                token.base_revision,
                None if index == 1 else index - 1,
            ),
        )
        self.store.resolve_delivery(
            delivery_token=delivery_token,
            outcome="delivered",
        )

    def test_sixty_four_committed_turns_remain_verbatim_projectable(self) -> None:
        for index in range(1, 65):
            self.deliver(index)

        auth = context(65)
        token = self.store.begin_turn(
            auth,
            "synthetic boundary request",
            EgressSafetySignals(classifier_available=True),
        )
        payload = self.store.context_payload(auth, token)["external_context"]
        self.assertEqual(len(payload["recent_turns"]), 64)
        self.assertEqual(payload["recent_turns"][0]["sequence"], 1)
        self.assertEqual(payload["recent_turns"][-1]["sequence"], 64)
        self.assertIsNone(payload["summary"])
        self.store.cancel_pending(auth, token)
        metadata = self.store.public_metadata()
        self.assertEqual(metadata["turn_count"], 64)
        self.assertEqual(metadata["summary_count"], 0)
        self.assertEqual(metadata["queued_summary_count"], 1)

    def test_unknown_projection_policy_fails_before_epoch_initialization(self) -> None:
        other = Path(self.temp.name) / "unknown" / "epoch.db"
        with self.assertRaises(ExternalEpochV3Rejected) as caught:
            ExternalEpochV3Store(
                other,
                epoch_id=EPOCH,
                release_set_id=RID,
                binding=binding(),
                projection_policy_version="future-policy",
            )
        self.assertEqual(caught.exception.code, "epoch_v3_projection_policy_rejected")
        self.assertFalse(other.exists())


if __name__ == "__main__":
    unittest.main()
