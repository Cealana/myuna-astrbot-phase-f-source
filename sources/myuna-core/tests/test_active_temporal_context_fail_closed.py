from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from myuna_core.active_temporal_context.access import AuthorizedTemporalScope
from myuna_core.active_temporal_context.contracts import TemporalContextError, TemporalFactDraft
from myuna_core.active_temporal_context.store import (
    MAX_DATABASE_BYTES,
    TemporalContextStore,
)
from myuna_core.active_temporal_context.time import TrustedTimeSample


NOW = datetime(2030, 1, 2, 9, 0, tzinfo=timezone.utc)
SCOPE = AuthorizedTemporalScope("telegram", "a" * 64)


def clock(sequence: int, *, at: datetime | None = None) -> TrustedTimeSample:
    return TrustedTimeSample(
        at or NOW + timedelta(seconds=sequence),
        "fake-clock",
        "synthetic",
        sequence,
    )


def draft() -> TemporalFactDraft:
    return TemporalFactDraft(
        "current_task",
        "task-alpha",
        "Finish synthetic task alpha.",
        "owner_statement",
        "telegram",
        "source-1",
        NOW,
        None,
        NOW + timedelta(days=2),
    )


class FailClosedStoreTest(unittest.TestCase):
    def private_dir(self):
        temporary = tempfile.TemporaryDirectory()
        os.chmod(temporary.name, 0o700)
        return temporary, Path(temporary.name)

    def test_unknown_schema_corrupt_oversize_and_type_drift(self) -> None:
        temporary, root = self.private_dir()
        try:
            unknown = root / "unknown.sqlite3"
            connection = sqlite3.connect(unknown)
            connection.close()
            os.chmod(unknown, 0o600)
            with self.assertRaisesRegex(TemporalContextError, "schema_unknown"):
                TemporalContextStore(unknown)
            corrupt = root / "corrupt.sqlite3"
            corrupt.write_bytes(b"not-a-sqlite-database")
            os.chmod(corrupt, 0o600)
            with self.assertRaisesRegex(TemporalContextError, "database_corrupt"):
                TemporalContextStore(corrupt)
            oversize = root / "oversize.sqlite3"
            with oversize.open("wb") as handle:
                handle.truncate(MAX_DATABASE_BYTES + 1)
            os.chmod(oversize, 0o600)
            with self.assertRaisesRegex(TemporalContextError, "database_oversize"):
                TemporalContextStore(oversize)
            symlink = root / "symlink.sqlite3"
            symlink.symlink_to(unknown)
            with self.assertRaisesRegex(TemporalContextError, "database_type_drift"):
                TemporalContextStore(symlink)
        finally:
            temporary.cleanup()

    def test_permission_drift_fails_closed(self) -> None:
        temporary, root = self.private_dir()
        try:
            path = root / "temporal.sqlite3"
            TemporalContextStore.create(path)
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(TemporalContextError, "database_permission_drift"):
                TemporalContextStore(path)
        finally:
            temporary.cleanup()

    def test_invalid_busy_timeout_is_rejected_before_open(self) -> None:
        temporary, root = self.private_dir()
        try:
            path = root / "temporal.sqlite3"
            TemporalContextStore.create(path)
            for invalid in (-1, 6, float("nan"), True):
                with self.subTest(invalid=invalid):
                    with self.assertRaisesRegex(
                        TemporalContextError, "database_timeout_invalid"
                    ):
                        TemporalContextStore(path, timeout_seconds=invalid)
        finally:
            temporary.cleanup()

    def test_writer_lock_fails_closed_as_retryable_busy(self) -> None:
        temporary, root = self.private_dir()
        try:
            path = root / "temporal.sqlite3"
            TemporalContextStore.create(path)
            locked = sqlite3.connect(path, isolation_level=None)
            locked.execute("BEGIN IMMEDIATE")
            try:
                store = TemporalContextStore(path, timeout_seconds=0.001)
                with self.assertRaisesRegex(TemporalContextError, "database_busy") as raised:
                    store.propose_mutation(
                        SCOPE,
                        request_id="prepare-locked",
                        action="create",
                        draft=draft(),
                        sample=clock(1),
                        confirmation_code="CODE-LOCKED",
                    )
                self.assertTrue(raised.exception.retryable)
            finally:
                locked.rollback()
                locked.close()
        finally:
            temporary.cleanup()

    def test_crash_before_commit_leaves_no_visible_mutation(self) -> None:
        temporary, root = self.private_dir()
        try:
            path = root / "temporal.sqlite3"
            base = TemporalContextStore.create(path)
            proposal = base.propose_mutation(
                SCOPE,
                request_id="prepare-1",
                action="create",
                draft=draft(),
                sample=clock(1),
                confirmation_code="CODE-1",
            )

            def inject(stage: str) -> None:
                if stage == "before_commit":
                    raise RuntimeError("synthetic crash")

            crashing = TemporalContextStore(path, failure_injector=inject)
            with self.assertRaisesRegex(TemporalContextError, "transaction_aborted"):
                crashing.confirm_mutation(
                    SCOPE,
                    request_id="confirm-1",
                    proposal_id=proposal.proposal_id,
                    confirmation_code=proposal.confirmation_code,
                    sample=clock(2),
                )
            reopened = TemporalContextStore(path)
            self.assertEqual(reopened.content_free_counts()["facts"], 0)
        finally:
            temporary.cleanup()

    def test_ambiguous_after_commit_recovers_only_by_exact_idempotency(self) -> None:
        temporary, root = self.private_dir()
        try:
            path = root / "temporal.sqlite3"
            base = TemporalContextStore.create(path)
            proposal = base.propose_mutation(
                SCOPE,
                request_id="prepare-1",
                action="create",
                draft=draft(),
                sample=clock(1),
                confirmation_code="CODE-1",
            )

            def inject(stage: str) -> None:
                if stage == "after_commit":
                    raise RuntimeError("synthetic lost acknowledgement")

            ambiguous = TemporalContextStore(path, failure_injector=inject)
            with self.assertRaisesRegex(TemporalContextError, "commit_outcome_unknown"):
                ambiguous.confirm_mutation(
                    SCOPE,
                    request_id="confirm-1",
                    proposal_id=proposal.proposal_id,
                    confirmation_code=proposal.confirmation_code,
                    sample=clock(2),
                )
            reopened = TemporalContextStore(path)
            result = reopened.confirm_mutation(
                SCOPE,
                request_id="confirm-1",
                proposal_id=proposal.proposal_id,
                confirmation_code=proposal.confirmation_code,
                sample=clock(3),
            )
            self.assertEqual(result.outcome, "active")
            with self.assertRaisesRegex(TemporalContextError, "idempotency_conflict"):
                reopened.confirm_mutation(
                    SCOPE,
                    request_id="confirm-1",
                    proposal_id=proposal.proposal_id,
                    confirmation_code="OTHER-CODE",
                    sample=clock(4),
                )
        finally:
            temporary.cleanup()

    def test_time_regression_and_event_state_drift_fail_closed(self) -> None:
        temporary, root = self.private_dir()
        try:
            path = root / "temporal.sqlite3"
            store = TemporalContextStore.create(path)
            proposal = store.propose_mutation(
                SCOPE,
                request_id="prepare-1",
                action="create",
                draft=draft(),
                sample=clock(2),
                confirmation_code="CODE-1",
            )
            with self.assertRaisesRegex(TemporalContextError, "sequence_regression"):
                TemporalContextStore(path).confirm_mutation(
                    SCOPE,
                    request_id="confirm-regressed",
                    proposal_id=proposal.proposal_id,
                    confirmation_code=proposal.confirmation_code,
                    sample=clock(2),
                )
            result = TemporalContextStore(path).confirm_mutation(
                SCOPE,
                request_id="confirm-1",
                proposal_id=proposal.proposal_id,
                confirmation_code=proposal.confirmation_code,
                sample=clock(3),
            )
            connection = sqlite3.connect(path)
            connection.execute(
                "UPDATE facts SET state='revoked' WHERE fact_id=?", (result.fact.fact_id,)
            )
            connection.commit()
            connection.close()
            with self.assertRaisesRegex(TemporalContextError, "database_corrupt"):
                TemporalContextStore(path)
        finally:
            temporary.cleanup()

    def test_proposal_envelope_column_drift_fails_closed(self) -> None:
        temporary, root = self.private_dir()
        try:
            path = root / "temporal.sqlite3"
            store = TemporalContextStore.create(path)
            proposal = store.propose_mutation(
                SCOPE,
                request_id="prepare-envelope",
                action="create",
                draft=draft(),
                sample=clock(1),
                confirmation_code="CODE-ENVELOPE",
            )
            connection = sqlite3.connect(path)
            connection.execute(
                "UPDATE proposals SET action='revoke' WHERE proposal_id=?",
                (proposal.proposal_id,),
            )
            connection.commit()
            connection.close()
            with self.assertRaisesRegex(TemporalContextError, "database_corrupt"):
                TemporalContextStore(path).confirm_mutation(
                    SCOPE,
                    request_id="confirm-envelope",
                    proposal_id=proposal.proposal_id,
                    confirmation_code=proposal.confirmation_code,
                    sample=clock(2),
                )
        finally:
            temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
