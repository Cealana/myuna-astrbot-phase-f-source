from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import tempfile
import unittest

from myuna_core.external_context.contracts import (
    EXTERNAL_PROJECTION_POLICY,
    EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY,
    EXTERNAL_VISUAL_PROJECTION_POLICY,
    EgressSafetySignals,
    ExternalTurnProvenance,
)
from myuna_core.external_context.lifecycle_v3 import (
    ReleaseBoundTurnProvenance,
)

from external_context_epoch_v3 import (
    ExternalEpochV3Rejected,
    ExternalEpochV3Store,
)
from tests.test_p07_verbatim_first_epoch_v3 import (
    EPOCH,
    OVERLAY,
    RID,
    binding,
    context,
)


def provenance(
    revision: int,
    *,
    overlay_id: str | None = OVERLAY,
) -> ReleaseBoundTurnProvenance:
    return ReleaseBoundTurnProvenance(
        RID,
        ExternalTurnProvenance(
            epoch_id=EPOCH,
            epoch_revision=revision,
            projection_digest=sha256(
                f"policy-overlay-projection-{revision}".encode("ascii")
            ).hexdigest(),
            sources=("owner_current_message",),
            profile_revisions=(),
            summary_version=None,
            recent_turn_start=None,
            recent_turn_end=None,
        ),
        policy_overlay_id=overlay_id,
    )


class PolicyOverlayEpochV3Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "epoch" / "epoch.db"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def store(self) -> ExternalEpochV3Store:
        return ExternalEpochV3Store(
            self.database,
            epoch_id=EPOCH,
            release_set_id=RID,
            binding=binding(),
            projection_policy_version=EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY,
            policy_overlay_id=OVERLAY,
        )

    def test_verbatim_policy_cannot_exist_without_overlay_binding(self) -> None:
        with self.assertRaisesRegex(
            ExternalEpochV3Rejected, "epoch_v3_policy_overlay_rejected"
        ):
            ExternalEpochV3Store(
                self.database,
                epoch_id=EPOCH,
                release_set_id=RID,
                binding=binding(),
                projection_policy_version=(
                    EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY
                ),
            )
        self.assertFalse(self.database.exists())

    def test_exact_overlay_wrapper_and_delivery_provenance_commit(self) -> None:
        store = self.store()
        auth = context(1)
        pending = store.begin_turn(
            auth,
            "synthetic overlay message",
            EgressSafetySignals(classifier_available=True),
        )
        payload = store.context_payload(auth, pending)
        self.assertEqual(
            payload["schema"], "myuna.external-context-release-bound.v2"
        )
        self.assertEqual(payload["release_set_id"], RID)
        self.assertEqual(payload["policy_overlay_id"], OVERLAY)
        self.assertEqual(
            payload["external_context"]["projection_policy_version"],
            EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY,
        )
        delivery_token = "d" * 64
        store.prepare_delivery(
            auth,
            pending,
            delivery_token=delivery_token,
            assistant_reply="synthetic overlay reply",
            provenance=provenance(pending.base_revision),
        )
        store.resolve_delivery(
            delivery_token=delivery_token,
            outcome="delivered",
        )
        metadata = store.public_metadata()
        self.assertEqual(metadata["turn_count"], 1)
        self.assertEqual(metadata["pending_count"], 0)

    def test_wrong_overlay_provenance_rejects_before_commit(self) -> None:
        store = self.store()
        auth = context(1)
        pending = store.begin_turn(
            auth,
            "synthetic mismatch",
            EgressSafetySignals(classifier_available=True),
        )
        with self.assertRaisesRegex(
            ExternalEpochV3Rejected,
            "epoch_v3_provenance_policy_overlay_rejected",
        ):
            store.prepare_delivery(
                auth,
                pending,
                delivery_token="e" * 64,
                assistant_reply="must not commit",
                provenance=provenance(
                    pending.base_revision,
                    overlay_id="9" * 64,
                ),
            )
        metadata = store.public_metadata()
        self.assertEqual(metadata["turn_count"], 0)
        self.assertEqual(metadata["pending_count"], 1)
        store.cancel_pending(auth, pending)

    def test_overlay_absence_reopens_same_epoch_as_compressed_without_rewrite(self) -> None:
        store = self.store()
        auth = context(1)
        pending = store.begin_turn(
            auth,
            "synthetic persisted turn",
            EgressSafetySignals(classifier_available=True),
        )
        store.prepare_delivery(
            auth,
            pending,
            delivery_token="f" * 64,
            assistant_reply="synthetic persisted reply",
            provenance=provenance(pending.base_revision),
        )
        store.resolve_delivery(delivery_token="f" * 64, outcome="delivered")
        before = store.public_metadata()

        compressed = ExternalEpochV3Store(
            self.database,
            epoch_id=EPOCH,
            release_set_id=RID,
            binding=binding(),
            projection_policy_version=EXTERNAL_PROJECTION_POLICY,
        )
        self.assertEqual(compressed.public_metadata(), before)
        next_auth = context(2)
        next_pending = compressed.begin_turn(
            next_auth,
            "synthetic compressed rollback",
            EgressSafetySignals(classifier_available=True),
        )
        payload = compressed.context_payload(next_auth, next_pending)
        self.assertEqual(
            payload["schema"], "myuna.external-context-release-bound.v1"
        )
        self.assertNotIn("policy_overlay_id", payload)
        compressed.cancel_pending(next_auth, next_pending)

    def test_visual_evidence_keeps_visual_policy_under_overlay(self) -> None:
        store = self.store()
        auth = context(1)
        pending = store.begin_turn(
            auth,
            "synthetic caption",
            EgressSafetySignals(classifier_available=True),
        )
        payload = store.context_payload(
            auth,
            pending,
            visual_event={
                "caption_present": True,
                "observation": "synthetic bounded visual observation",
                "schema": "myuna.telegram-visual-evidence.v1",
                "source": "gemini_visual_extraction",
            },
        )
        self.assertEqual(payload["policy_overlay_id"], OVERLAY)
        self.assertEqual(
            payload["external_context"]["projection_policy_version"],
            EXTERNAL_VISUAL_PROJECTION_POLICY,
        )
        store.cancel_pending(auth, pending)


if __name__ == "__main__":
    unittest.main()
