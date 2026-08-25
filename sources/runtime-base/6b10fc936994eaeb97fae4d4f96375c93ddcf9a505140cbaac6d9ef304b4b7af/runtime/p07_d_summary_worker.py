from __future__ import annotations

from dataclasses import dataclass
from threading import Event, Lock, Thread
from typing import Protocol

from myuna_core.external_context.lifecycle_v3 import (
    ReleaseBoundSummaryCandidate,
    ReleaseBoundSummaryJob,
)


class SummaryLifecycleStore(Protocol):
    def acquire_summary_job(self, *, worker_id: str) -> ReleaseBoundSummaryJob | None: ...

    def record_summary_failure(self, *, worker_id: str, job_digest: str) -> bool: ...

    def commit_summary_candidate(
        self,
        *,
        worker_id: str,
        job: ReleaseBoundSummaryJob,
        candidate: ReleaseBoundSummaryCandidate,
    ) -> int: ...


class SummaryProviderPort(Protocol):
    def summarize_release_bound(
        self,
        job: ReleaseBoundSummaryJob,
    ) -> ReleaseBoundSummaryCandidate: ...


@dataclass(frozen=True, slots=True)
class SummaryCycleResult:
    status: str
    job_digest: str | None = None
    committed_revision: int | None = None


class SummaryWorkerCycle:
    """One bounded, content-free summary attempt outside the foreground turn."""

    def __init__(
        self,
        store: SummaryLifecycleStore,
        provider: SummaryProviderPort,
        *,
        worker_id: str,
    ) -> None:
        self.store = store
        self.provider = provider
        self.worker_id = worker_id

    def run_once(self) -> SummaryCycleResult:
        job = self.store.acquire_summary_job(worker_id=self.worker_id)
        if job is None:
            return SummaryCycleResult("idle")
        try:
            candidate = self.provider.summarize_release_bound(job)
            candidate.validate_for(job)
            revision = self.store.commit_summary_candidate(
                worker_id=self.worker_id,
                job=job,
                candidate=candidate,
            )
            return SummaryCycleResult("committed", job.digest, revision)
        except Exception:
            try:
                retryable = self.store.record_summary_failure(
                    worker_id=self.worker_id,
                    job_digest=job.digest,
                )
            except Exception as exc:
                raise RuntimeError("summary_failure_receipt_unavailable") from exc
            return SummaryCycleResult(
                "retry_queued" if retryable else "retry_blocked",
                job.digest,
            )


class BackgroundSummaryWorker:
    """Single in-process worker with bounded periodic retry and crash-safe DB lease."""

    def __init__(
        self,
        cycle: SummaryWorkerCycle,
        *,
        retry_interval_seconds: float = 30.0,
    ) -> None:
        if not 1.0 <= retry_interval_seconds <= 300.0:
            raise ValueError("summary retry interval rejected")
        self.cycle = cycle
        self.retry_interval_seconds = retry_interval_seconds
        self._wake = Event()
        self._stop = Event()
        self._lock = Lock()
        self._thread: Thread | None = None

    def start(self) -> None:
        with self._lock:
            if self._thread is not None:
                raise RuntimeError("summary worker already started")
            self._thread = Thread(
                target=self._run,
                name="p07-d-summary-worker",
                daemon=True,
            )
            self._thread.start()
        self.trigger()

    def trigger(self) -> None:
        self._wake.set()

    def stop(self, *, timeout_seconds: float = 5.0) -> None:
        self._stop.set()
        self._wake.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout_seconds)

    def _run(self) -> None:
        retry_due = False
        while not self._stop.is_set():
            self._wake.wait(
                self.retry_interval_seconds if retry_due else None
            )
            self._wake.clear()
            if self._stop.is_set():
                return
            try:
                result = self.cycle.run_once()
            except Exception:
                retry_due = True
                continue
            retry_due = result.status == "retry_queued"
