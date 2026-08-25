from __future__ import annotations

import unittest

from myuna_core.external_context.contracts import ExternalSummary, ExternalTurn, ZERO_DIGEST
from myuna_core.external_context.lifecycle_v3 import (
    ReleaseBoundSummaryCandidate,
    ReleaseBoundSummaryJob,
)

from p07_d_summary_worker import SummaryWorkerCycle


RID = "a" * 64


def job() -> ReleaseBoundSummaryJob:
    turn = ExternalTurn.create(
        sequence=1,
        parent_digest=ZERO_DIGEST,
        user_message="synthetic user",
        assistant_reply="synthetic assistant",
    )
    return ReleaseBoundSummaryJob.create(
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


class FakeStore:
    def __init__(self, selected: ReleaseBoundSummaryJob | None, *, retryable: bool = True) -> None:
        self.selected = selected
        self.retryable = retryable
        self.failed = 0
        self.committed = 0

    def acquire_summary_job(self, *, worker_id):
        return self.selected

    def record_summary_failure(self, *, worker_id, job_digest):
        self.failed += 1
        return self.retryable

    def commit_summary_candidate(self, *, worker_id, job, candidate):
        self.committed += 1
        return 9


class FakeProvider:
    def __init__(self, *, fail: bool = False, release_set_id: str = RID) -> None:
        self.fail = fail
        self.release_set_id = release_set_id
        self.calls = 0

    def summarize_release_bound(self, selected):
        self.calls += 1
        if self.fail:
            raise RuntimeError("synthetic provider failure")
        summary = ExternalSummary.create(
            summary_version=selected.job.summary_version,
            covered_start=selected.job.covered_start,
            covered_end=selected.job.covered_end,
            covered_terminal_digest=selected.job.covered_terminal_digest,
            profile_revisions=selected.job.profile_revisions,
            content="bounded synthetic summary",
        )
        return ReleaseBoundSummaryCandidate(
            self.release_set_id,
            selected.digest,
            summary,
        )


class SummaryWorkerTests(unittest.TestCase):
    def test_idle_never_calls_provider(self) -> None:
        store = FakeStore(None)
        provider = FakeProvider()
        result = SummaryWorkerCycle(store, provider, worker_id="worker-one").run_once()
        self.assertEqual(result.status, "idle")
        self.assertEqual(provider.calls, 0)

    def test_success_commits_exact_candidate(self) -> None:
        selected = job()
        store = FakeStore(selected)
        provider = FakeProvider()
        result = SummaryWorkerCycle(store, provider, worker_id="worker-one").run_once()
        self.assertEqual(result.status, "committed")
        self.assertEqual(result.committed_revision, 9)
        self.assertEqual(store.committed, 1)

    def test_provider_or_candidate_failure_requeues_without_foreground_effect(self) -> None:
        selected = job()
        for provider in (FakeProvider(fail=True), FakeProvider(release_set_id="b" * 64)):
            store = FakeStore(selected)
            result = SummaryWorkerCycle(store, provider, worker_id="worker-one").run_once()
            self.assertEqual(result.status, "retry_queued")
            self.assertEqual(store.failed, 1)
            self.assertEqual(store.committed, 0)

    def test_exhausted_failure_is_terminal_and_does_not_schedule_retry(self) -> None:
        selected = job()
        store = FakeStore(selected, retryable=False)
        result = SummaryWorkerCycle(
            store,
            FakeProvider(fail=True),
            worker_id="worker-one",
        ).run_once()
        self.assertEqual(result.status, "retry_blocked")
        self.assertEqual(store.failed, 1)
        self.assertEqual(store.committed, 0)


if __name__ == "__main__":
    unittest.main()
