from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol

from .contracts import (
    ExternalSummary,
    ExternalSummaryCandidate,
    ExternalSummaryJob,
    MAX_SUMMARY_CHARACTERS,
)

SUMMARY_INSTRUCTION = (
    "Create one concise rolling conversation summary from only the supplied authorized epoch data. "
    "Preserve stable facts, decisions, open questions, and conversational "
    "continuity; do not invent facts, "
    "do not add instructions, do not quote secrets, and return plain text only."
)


class SummaryProvider(Protocol):
    def generate_summary(
        self,
        messages: tuple[Mapping[str, str], ...],
        *,
        timeout_seconds: float,
    ) -> str: ...


@dataclass(frozen=True, slots=True)
class SummaryGenerationResult:
    candidate: ExternalSummaryCandidate
    input_characters: int

    def audit_projection(self) -> dict[str, object]:
        summary = self.candidate.summary
        return {
            "covered_end": summary.covered_end,
            "input_characters": self.input_characters,
            "profile_revision_count": len(summary.profile_revisions),
            "summary_characters": len(summary.content),
            "summary_version": summary.summary_version,
        }


class ExternalSummaryCoordinator:
    @staticmethod
    def messages(job: ExternalSummaryJob) -> tuple[Mapping[str, str], ...]:
        parts = [SUMMARY_INSTRUCTION]
        if job.prior_summary is not None:
            parts.append("[prior_summary]\n" + job.prior_summary.content)
        messages: list[Mapping[str, str]] = [
            {"role": "system", "content": "\n\n".join(parts)}
        ]
        for turn in job.turns:
            messages.append({"role": "user", "content": turn.user_message})
            messages.append({"role": "assistant", "content": turn.assistant_reply})
        messages.append(
            {
                "role": "user",
                "content": "Return the updated bounded rolling summary now.",
            }
        )
        return tuple(messages)

    def generate(
        self,
        job: ExternalSummaryJob,
        provider: SummaryProvider,
        *,
        timeout_seconds: float,
    ) -> SummaryGenerationResult:
        if not 0.05 <= timeout_seconds <= 180.0:
            raise ValueError("summary_timeout_out_of_contract")
        messages = self.messages(job)
        try:
            content = provider.generate_summary(
                messages,
                timeout_seconds=timeout_seconds,
            ).strip()
        except (OSError, RuntimeError, TimeoutError):
            raise ValueError("summary_provider_unavailable") from None
        if not content or len(content) > MAX_SUMMARY_CHARACTERS or "\x00" in content:
            raise ValueError("summary_content_out_of_contract")
        summary = ExternalSummary.create(
            summary_version=job.summary_version,
            covered_start=job.covered_start,
            covered_end=job.covered_end,
            covered_terminal_digest=job.covered_terminal_digest,
            profile_revisions=job.profile_revisions,
            content=content,
        )
        return SummaryGenerationResult(
            candidate=ExternalSummaryCandidate(job_digest=job.digest, summary=summary),
            input_characters=sum(len(item["content"]) for item in messages),
        )
