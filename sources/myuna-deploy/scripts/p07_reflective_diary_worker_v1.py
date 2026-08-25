"""Retired Phase-A diary queue/worker route.

The provider result value remains byte-compatible for the existing inactive
provider-facing seam. No thread, timer, queue, retry loop, provider callback,
or store port is defined here.
"""

from __future__ import annotations

from dataclasses import dataclass

from myuna_core.episodic_memory.diary_generation import (
    DiaryCapacityReceipt,
    DiaryGenerationCandidate,
)


@dataclass(frozen=True, slots=True)
class DiaryProviderResult:
    status: str
    job_digest: str
    capacity: DiaryCapacityReceipt
    provider_called: bool
    candidate: DiaryGenerationCandidate | None

    def __post_init__(self) -> None:
        if self.status not in {"completed", "coverage_incomplete"}:
            raise ValueError("diary provider result status rejected")
        if self.status == "completed":
            if not self.provider_called or self.candidate is None:
                raise ValueError("diary completed result rejected")
        elif self.provider_called or self.candidate is not None:
            raise ValueError("diary coverage result rejected")


REFLECTIVE_DIARY_WORKER_ACTIVE = False

__all__ = ["DiaryProviderResult", "REFLECTIVE_DIARY_WORKER_ACTIVE"]
