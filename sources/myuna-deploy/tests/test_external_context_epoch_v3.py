from __future__ import annotations

from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import sqlite3
import tempfile
import unittest

from myuna_core.authenticated_conversation import (
    SCHEMA_VERSION as AUTH_SCHEMA,
    AuthenticatedConversationContext,
)
from myuna_core.external_context.contracts import (
    EgressSafetySignals,
    ExternalSummary,
    ExternalTurnProvenance,
)
from myuna_core.external_context.lifecycle_v3 import (
    ReleaseBoundSummaryCandidate,
    ReleaseBoundTurnProvenance,
)

from external_context_epoch_v3 import (
    ExternalEpochV3Binding,
    ExternalEpochV3Rejected,
    ExternalEpochV3Store,
    SQLITE_SCHEMA,
)


RID = "a" * 64
EPOCH = "telegram-owner-private-external-d-reset-v1"


def context(index: int) -> AuthenticatedConversationContext:
    return AuthenticatedConversationContext(
        schema_version=AUTH_SCHEMA,
        request_id=f"request-synthetic-{index}",
        correlation_id=f"correlation-synthetic-{index}",
        client_id="telegram-owner-private",
        channel_kind="astrbot_telegram",
        binding_id="binding-synthetic-owner",
        principal_id="principal-synthetic-owner",
        namespace_id="namespace-synthetic-owner",
        authority_level="owner",
        channel_instance="telegram-synthetic",
        conversation_id="conversation-synthetic",
        conversation_kind="private",
        event_id=f"event-synthetic-{index}",
        trace_id=f"trace-synthetic-{index}",
        occurred_at=datetime(2026, 8, 4, 12, index, tzinfo=timezone.utc),
        delivery_capabilities=("text",),
    )


def binding() -> ExternalEpochV3Binding:
    return ExternalEpochV3Binding(
        channel_kind="astrbot_telegram",
        client_id="telegram-owner-private",
        principal_id="principal-synthetic-owner",
        namespace_id="namespace-synthetic-owner",
    )


def provenance(revision: int, recent_end: int | None) -> ReleaseBoundTurnProvenance:
    sources = ["owner_current_message"]
    if recent_end is not None:
        sources.append("ordinary_external_turn")
    return ReleaseBoundTurnProvenance(
        RID,
        ExternalTurnProvenance(
            epoch_id=EPOCH,
            epoch_revision=revision,
            projection_digest=(f"{revision + 1:x}" * 64)[:64],
            sources=tuple(sources),
            profile_revisions=(),
            summary_version=None,
            recent_turn_start=None if recent_end is None else 1,
            recent_turn_end=recent_end,
        ),
    )


class EpochV3Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "epoch" / "epoch.db"
        self.store = ExternalEpochV3Store(
            self.database,
            epoch_id=EPOCH,
            release_set_id=RID,
            binding=binding(),
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def deliver(self, index: int) -> object:
        auth = context(index)
        token = self.store.begin_turn(
            auth,
            f"synthetic user {index} 涓枃",
            EgressSafetySignals(classifier_available=True),
        )
        payload = self.store.context_payload(auth, token)
        self.assertEqual(payload["release_set_id"], RID)
        delivery_token = f"{index:x}" * 64
        self.store.prepare_delivery(
            auth,
            token,
            delivery_token=delivery_token,
            assistant_reply=f"synthetic assistant {index}",
            provenance=provenance(token.base_revision, None if index == 1 else index - 1),
        )
        return self.store.resolve_delivery(delivery_token=delivery_token, outcome="delivered")

    def test_atomic_initialization_and_duplicate_startup(self) -> None:
        again = ExternalEpochV3Store(
            self.database,
            epoch_id=EPOCH,
            release_set_id=RID,
            binding=binding(),
        )
        self.assertEqual(again.public_metadata()["schema"], SQLITE_SCHEMA)
        self.assertEqual(again.public_metadata()["turn_count"], 0)

    def test_projection_readiness_is_content_free_non_mutating_and_bounded(self) -> None:
        self.assertEqual(self.store.projection_readiness(context(1)), "ready")
        pending = self.store.begin_turn(
            context(1),
            "synthetic pending message",
            EgressSafetySignals(classifier_available=True),
        )
        self.assertEqual(
            self.store.projection_readiness(context(2)),
            "external_turn_already_pending",
        )
        self.store.cancel_pending(context(1), pending)
        self.assertEqual(self.store.projection_readiness(context(2)), "ready")

        for index in range(1, 8):
            self.deliver(index)
        before = self.store.public_metadata()
        self.assertEqual(
            self.store.projection_readiness(context(8)),
            "external_summary_required",
        )
        self.assertEqual(self.store.public_metadata(), before)

    def test_query_only_existing_metadata_does_not_initialize_or_mutate(self) -> None:
        before = self.database.stat().st_mtime_ns
        metadata = ExternalEpochV3Store.inspect_existing_metadata(
            self.database,
            epoch_id=EPOCH,
            release_set_id=RID,
            binding=binding(),
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )
        self.assertEqual(metadata["selected_revision"], 0)
        self.assertEqual(metadata["turn_count"], 0)
        self.assertEqual(metadata["pending_count"], 0)
        self.assertEqual(self.database.stat().st_mtime_ns, before)

    def test_concurrent_startup_converges_on_one_exact_schema(self) -> None:
        database = Path(self.temp.name) / "concurrent" / "epoch.db"

        def open_store(_: int) -> dict[str, object]:
            return ExternalEpochV3Store(
                database,
                epoch_id=EPOCH,
                release_set_id=RID,
                binding=binding(),
            ).public_metadata()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(open_store, range(2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0]["selected_revision"], 0)

    def test_delivery_ack_is_durable_idempotent_and_conflict_closed(self) -> None:
        first = self.deliver(1)
        replay = self.store.resolve_delivery(delivery_token="1" * 64, outcome="delivered")
        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.committed_revision, first.committed_revision)
        with self.assertRaisesRegex(ExternalEpochV3Rejected, "outcome_conflict"):
            self.store.resolve_delivery(delivery_token="1" * 64, outcome="cancelled")
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM delivery_intents").fetchone()[0],
                0,
            )
            columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(delivery_receipts)")
            }
        self.assertNotIn("assistant_reply", columns)
        self.assertNotIn("provenance_json", columns)

    def test_crash_prepared_delivery_is_abandoned_and_late_ack_rejected(self) -> None:
        auth = context(1)
        token = self.store.begin_turn(
            auth,
            "synthetic crash message",
            EgressSafetySignals(classifier_available=True),
        )
        self.store.prepare_delivery(
            auth,
            token,
            delivery_token="f" * 64,
            assistant_reply="synthetic reply",
            provenance=provenance(0, None),
        )
        recovered = self.store.startup_recover()
        self.assertEqual(recovered.abandoned_deliveries, 1)
        self.assertEqual(self.store.public_metadata()["pending_count"], 0)
        with self.assertRaisesRegex(ExternalEpochV3Rejected, "outcome_conflict"):
            self.store.resolve_delivery(delivery_token="f" * 64, outcome="delivered")

    def test_unprepared_turn_can_be_cancelled_but_prepared_turn_cannot(self) -> None:
        auth = context(1)
        token = self.store.begin_turn(
            auth,
            "synthetic cancellable message",
            EgressSafetySignals(classifier_available=True),
        )
        self.store.cancel_pending(auth, token)
        self.assertEqual(self.store.public_metadata()["pending_count"], 0)

        token = self.store.begin_turn(
            auth,
            "synthetic prepared message",
            EgressSafetySignals(classifier_available=True),
        )
        self.store.prepare_delivery(
            auth,
            token,
            delivery_token="e" * 64,
            assistant_reply="synthetic reply",
            provenance=provenance(0, None),
        )
        with self.assertRaisesRegex(ExternalEpochV3Rejected, "already_prepared"):
            self.store.cancel_pending(auth, token)

    def test_summary_failure_does_not_block_headroom_and_commit_rebases(self) -> None:
        for index in range(1, 5):
            result = self.deliver(index)
        self.assertTrue(result.summary_job_queued)
        job = self.store.acquire_summary_job(worker_id="worker-synthetic")
        self.assertIsNotNone(job)
        assert job is not None
        self.store.record_summary_failure(
            worker_id="worker-synthetic",
            job_digest=job.digest,
        )
        fifth = self.deliver(5)
        self.assertFalse(fifth.summary_job_queued)
        retried = self.store.acquire_summary_job(worker_id="worker-synthetic")
        self.assertEqual(retried, job)
        summary = ExternalSummary.create(
            summary_version=job.job.summary_version,
            covered_start=job.job.covered_start,
            covered_end=job.job.covered_end,
            covered_terminal_digest=job.job.covered_terminal_digest,
            profile_revisions=job.job.profile_revisions,
            content="synthetic bounded rolling summary",
        )
        revision = self.store.commit_summary_candidate(
            worker_id="worker-synthetic",
            job=job,
            candidate=ReleaseBoundSummaryCandidate(RID, job.digest, summary),
        )
        metadata = self.store.public_metadata()
        self.assertEqual(revision, 6)
        self.assertEqual(metadata["turn_count"], 5)
        self.assertEqual(metadata["summary_count"], 1)
        self.assertEqual(metadata["queued_summary_count"], 0)

    def test_crash_left_summary_lease_requeues_without_clock(self) -> None:
        for index in range(1, 5):
            self.deliver(index)
        job = self.store.acquire_summary_job(worker_id="worker-one")
        self.assertIsNotNone(job)
        recovered = self.store.startup_recover()
        self.assertEqual(recovered.requeued_summary_jobs, 1)
        self.assertEqual(
            self.store.acquire_summary_job(worker_id="worker-two"),
            job,
        )

    def test_summary_retries_are_bounded_and_terminal_failure_stays_nonblocking_until_cap(self) -> None:
        for index in range(1, 5):
            self.deliver(index)
        job = None
        for attempt in range(1, 4):
            job = self.store.acquire_summary_job(worker_id="worker-bounded")
            self.assertIsNotNone(job)
            assert job is not None
            retryable = self.store.record_summary_failure(
                worker_id="worker-bounded",
                job_digest=job.digest,
            )
            self.assertEqual(retryable, attempt < 3)
        self.assertIsNone(
            self.store.acquire_summary_job(worker_id="worker-bounded")
        )
        metadata = self.store.public_metadata()
        self.assertEqual(metadata["blocked_summary_count"], 1)
        self.assertEqual(metadata["queued_summary_count"], 0)
        fifth = self.deliver(5)
        self.assertFalse(fifth.summary_job_queued)

    def test_crash_on_final_summary_attempt_becomes_terminal_without_another_provider_call(self) -> None:
        for index in range(1, 5):
            self.deliver(index)
        for _ in range(2):
            job = self.store.acquire_summary_job(worker_id="worker-crash")
            assert job is not None
            self.assertTrue(
                self.store.record_summary_failure(
                    worker_id="worker-crash",
                    job_digest=job.digest,
                )
            )
        self.assertIsNotNone(
            self.store.acquire_summary_job(worker_id="worker-crash")
        )
        recovered = self.store.startup_recover()
        self.assertEqual(recovered.requeued_summary_jobs, 0)
        self.assertEqual(recovered.blocked_summary_jobs, 1)
        self.assertIsNone(
            self.store.acquire_summary_job(worker_id="worker-after-crash")
        )

    def test_soft_summary_failure_is_nonblocking_until_typed_hard_cap(self) -> None:
        for index in range(1, 8):
            self.deliver(index)
        auth = context(8)
        token = self.store.begin_turn(
            auth,
            "synthetic hard-cap message",
            EgressSafetySignals(classifier_available=True),
        )
        with self.assertRaisesRegex(ExternalEpochV3Rejected, "external_summary_backpressure"):
            self.store.context_payload(auth, token)
        self.store.cancel_pending(auth, token)

    def test_corrupt_unknown_schema_and_permission_type_fail_closed(self) -> None:
        other_root = Path(self.temp.name) / "other"
        other_root.mkdir(mode=0o700)
        corrupt = other_root / "epoch.db"
        with sqlite3.connect(corrupt) as connection:
            connection.execute("CREATE TABLE unexpected(value TEXT)")
        corrupt.chmod(0o600)
        with self.assertRaisesRegex(ExternalEpochV3Rejected, "schema_rejected"):
            ExternalEpochV3Store(
                corrupt,
                epoch_id=EPOCH,
                release_set_id=RID,
                binding=binding(),
            )
        symlink = Path(self.temp.name) / "linked"
        symlink.symlink_to(other_root, target_is_directory=True)
        with self.assertRaisesRegex(ExternalEpochV3Rejected, "parent_type_rejected"):
            ExternalEpochV3Store(
                symlink / "epoch.db",
                epoch_id=EPOCH,
                release_set_id=RID,
                binding=binding(),
            )
        self.database.chmod(0o644)
        with self.assertRaisesRegex(ExternalEpochV3Rejected, "permission_drift"):
            ExternalEpochV3Store(
                self.database,
                epoch_id=EPOCH,
                release_set_id=RID,
                binding=binding(),
            )

    def test_parent_permission_and_unknown_column_drift_fail_closed(self) -> None:
        self.database.parent.chmod(0o750)
        with self.assertRaisesRegex(ExternalEpochV3Rejected, "permission_drift"):
            ExternalEpochV3Store(
                self.database,
                epoch_id=EPOCH,
                release_set_id=RID,
                binding=binding(),
            )
        self.database.parent.chmod(0o700)
        with sqlite3.connect(self.database) as connection:
            connection.execute("ALTER TABLE epoch_state ADD COLUMN unexpected TEXT")
        self.database.chmod(0o600)
        with self.assertRaisesRegex(ExternalEpochV3Rejected, "columns_rejected"):
            ExternalEpochV3Store(
                self.database,
                epoch_id=EPOCH,
                release_set_id=RID,
                binding=binding(),
            )

    def test_release_set_and_binding_drift_are_rejected_before_mutation(self) -> None:
        with self.assertRaisesRegex(ExternalEpochV3Rejected, "state_identity_rejected"):
            ExternalEpochV3Store(
                self.database,
                epoch_id=EPOCH,
                release_set_id="b" * 64,
                binding=binding(),
            )
        wrong = ExternalEpochV3Binding(
            channel_kind="astrbot_telegram",
            client_id="telegram-owner-private",
            principal_id="principal-other",
            namespace_id="namespace-synthetic-owner",
        )
        with self.assertRaisesRegex(ExternalEpochV3Rejected, "state_binding_rejected"):
            ExternalEpochV3Store(
                self.database,
                epoch_id=EPOCH,
                release_set_id=RID,
                binding=wrong,
            )


if __name__ == "__main__":
    unittest.main()
