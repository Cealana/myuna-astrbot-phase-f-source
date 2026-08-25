from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import tempfile
import unittest

from myuna_core.active_temporal_context.access import AuthorizedTemporalScope
from myuna_core.active_temporal_context.contracts import TemporalFactDraft
from myuna_core.active_temporal_context.store import TemporalContextStore
from myuna_core.active_temporal_context.time import TrustedTimeSample


NOW = datetime(2030, 1, 2, 9, 0, tzinfo=timezone.utc)
SCOPE = AuthorizedTemporalScope("telegram", "a" * 64)


class StoreCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        os.chmod(self.temporary.name, 0o700)
        self.path = Path(self.temporary.name) / "temporal.sqlite3"
        self.store = TemporalContextStore.create(self.path)
        self.sequence = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def clock(self, *, hours: int = 0) -> TrustedTimeSample:
        self.sequence += 1
        return TrustedTimeSample(
            instant=NOW + timedelta(hours=hours, seconds=self.sequence),
            source="fake-clock",
            source_class="synthetic",
            sequence=self.sequence,
        )

    def draft(
        self,
        summary: str = "Finish synthetic task alpha.",
        *,
        slot: str = "task-alpha",
        source_ref: str = "source-1",
        hours: int = 0,
    ) -> TemporalFactDraft:
        start = NOW + timedelta(hours=hours)
        return TemporalFactDraft(
            category="current_task",
            slot_key=slot,
            summary=summary,
            source_kind="owner_statement",
            source_channel="telegram",
            source_ref=source_ref,
            valid_from=start,
            valid_to=None,
            expires_at=start + timedelta(days=2),
        )

    def confirm(self, *, proposal, request: str):
        return self.store.confirm_mutation(
            SCOPE,
            request_id=request,
            proposal_id=proposal.proposal_id,
            confirmation_code=proposal.confirmation_code,
            sample=self.clock(),
        )

    def create_fact(self, *, summary: str = "Finish synthetic task alpha."):
        proposal = self.store.propose_mutation(
            SCOPE,
            request_id=f"prepare-{self.sequence + 1}",
            action="create",
            draft=self.draft(summary),
            sample=self.clock(),
            confirmation_code="CODE-0001",
        )
        return self.confirm(proposal=proposal, request=f"confirm-{self.sequence + 1}")

    def test_create_duplicate_conflict_and_retrieval(self) -> None:
        first = self.create_fact()
        self.assertEqual(first.outcome, "active")
        self.assertEqual(first.fact.observed_at, NOW + timedelta(seconds=1))
        before = self.store.content_free_counts()
        duplicate_proposal = self.store.propose_mutation(
            SCOPE,
            request_id="prepare-duplicate",
            action="create",
            draft=self.draft(source_ref="source-2"),
            sample=self.clock(),
            confirmation_code="CODE-0002",
        )
        duplicate = self.confirm(proposal=duplicate_proposal, request="confirm-duplicate")
        self.assertEqual(duplicate.outcome, "no_change")
        self.assertFalse(duplicate.event_written)
        self.assertEqual(self.store.content_free_counts()["events"], before["events"])
        conflict_proposal = self.store.propose_mutation(
            SCOPE,
            request_id="prepare-conflict",
            action="create",
            draft=self.draft("Do a different synthetic task."),
            sample=self.clock(),
            confirmation_code="CODE-0003",
        )
        conflict = self.confirm(proposal=conflict_proposal, request="confirm-conflict")
        self.assertEqual(conflict.outcome, "conflict")
        self.assertEqual(conflict.fact.state, "conflicted")
        facts = self.store.active_facts(SCOPE, self.clock())
        self.assertEqual([fact.fact_id for fact in facts], [first.fact.fact_id])
        with self.assertRaisesRegex(Exception, "read_scope_rejected"):
            self.store.active_facts(
                AuthorizedTemporalScope("qq", "b" * 64), self.clock()
            )

    def test_supersede_refresh_revoke_and_restore(self) -> None:
        first = self.create_fact()
        replace = self.store.propose_mutation(
            SCOPE,
            request_id="prepare-supersede",
            action="supersede",
            target_fact_id=first.fact.fact_id,
            draft=self.draft("Finish synthetic task beta.", source_ref="source-2"),
            sample=self.clock(),
            confirmation_code="CODE-1001",
        )
        superseded = self.confirm(proposal=replace, request="confirm-supersede")
        self.assertEqual(superseded.outcome, "supersede")
        refresh = self.store.propose_mutation(
            SCOPE,
            request_id="prepare-refresh",
            action="refresh",
            target_fact_id=superseded.fact.fact_id,
            draft=self.draft(
                "Finish synthetic task beta.", source_ref="source-3", hours=1
            ),
            sample=self.clock(),
            confirmation_code="CODE-1002",
        )
        refreshed = self.confirm(proposal=refresh, request="confirm-refresh")
        self.assertEqual(refreshed.outcome, "refresh")
        revoke = self.store.propose_mutation(
            SCOPE,
            request_id="prepare-revoke",
            action="revoke",
            target_fact_id=refreshed.fact.fact_id,
            sample=self.clock(),
            confirmation_code="CODE-1003",
        )
        revoked = self.confirm(proposal=revoke, request="confirm-revoke")
        self.assertEqual(revoked.fact.state, "revoked")
        restore = self.store.propose_mutation(
            SCOPE,
            request_id="prepare-restore",
            action="restore",
            target_fact_id=revoked.fact.fact_id,
            draft=self.draft(
                "Finish synthetic task beta.", source_ref="source-4", hours=2
            ),
            sample=self.clock(),
            confirmation_code="CODE-1004",
        )
        restored = self.confirm(proposal=restore, request="confirm-restore")
        self.assertEqual(restored.outcome, "restored")
        self.assertGreater(restored.fact.revision, revoked.fact.revision)

    def test_confirmation_scope_code_expiry_and_idempotency(self) -> None:
        proposal = self.store.propose_mutation(
            SCOPE,
            request_id="prepare-auth",
            action="create",
            draft=self.draft(),
            sample=self.clock(),
            confirmation_code="CODE-2001",
        )
        with self.assertRaisesRegex(Exception, "proposal_scope_rejected"):
            self.store.confirm_mutation(
                AuthorizedTemporalScope("telegram", "b" * 64),
                request_id="confirm-wrong-scope",
                proposal_id=proposal.proposal_id,
                confirmation_code=proposal.confirmation_code,
                sample=self.clock(),
            )
        with self.assertRaisesRegex(Exception, "write_scope_rejected"):
            self.store.confirm_mutation(
                AuthorizedTemporalScope("qq", SCOPE.scope_sha256),
                request_id="confirm-qq",
                proposal_id=proposal.proposal_id,
                confirmation_code=proposal.confirmation_code,
                sample=self.clock(),
            )
        with self.assertRaisesRegex(Exception, "confirmation_rejected"):
            self.store.confirm_mutation(
                SCOPE,
                request_id="confirm-wrong-code",
                proposal_id=proposal.proposal_id,
                confirmation_code="WRONG-CODE",
                sample=self.clock(),
            )
        result = self.confirm(proposal=proposal, request="confirm-auth")
        replay = self.store.confirm_mutation(
            SCOPE,
            request_id="confirm-auth",
            proposal_id=proposal.proposal_id,
            confirmation_code=proposal.confirmation_code,
            sample=self.clock(),
        )
        self.assertEqual(replay, result)

    def test_expiry_is_immediate_on_read_and_committable_with_fake_time(self) -> None:
        result = self.create_fact()
        future = self.clock(hours=72)
        self.assertEqual(self.store.active_facts(SCOPE, future), ())
        later = self.clock(hours=73)
        self.assertEqual(self.store.expire_due(later), 1)
        self.assertEqual(self.store.active_facts(SCOPE, self.clock(hours=74)), ())
        self.assertEqual(result.fact.state, "active")

    def test_expired_pending_proposals_do_not_consume_live_capacity(self) -> None:
        first = self.store.propose_mutation(
            SCOPE,
            request_id="prepare-expiring",
            action="create",
            draft=self.draft(),
            sample=self.clock(),
            ttl=timedelta(minutes=1),
            confirmation_code="CODE-EXPIRING",
        )
        second = self.store.propose_mutation(
            SCOPE,
            request_id="prepare-after-expiry",
            action="create",
            draft=self.draft(source_ref="source-2"),
            sample=self.clock(hours=1),
            confirmation_code="CODE-AFTER",
        )
        self.assertNotEqual(first.proposal_id, second.proposal_id)
        self.assertEqual(self.store.content_free_counts()["pending_proposals"], 1)


if __name__ == "__main__":
    unittest.main()
