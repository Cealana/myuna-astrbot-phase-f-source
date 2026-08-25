from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class QueryPlan:
    policy_version: str
    intent: str
    primary_horizon: str
    allow_deep_fallback: bool
    max_results: int
    concepts: tuple[str, ...]
    reason_codes: tuple[str, ...]
    query_fingerprint: str
    query_characters: int

    def audit_metadata(self) -> dict[str, object]:
        """Return content-free fields safe for structured audit."""

        return asdict(self)


@dataclass(frozen=True, slots=True)
class CandidateScore:
    memory_id: str
    semantic_score: float
    final_score: float
    concept_score: float
    primary_text_score: float
    support_text_score: float
    matched_concepts: tuple[str, ...]
    reason_codes: tuple[str, ...]

    def audit_metadata(self) -> dict[str, object]:
        return {
            "memory_id": self.memory_id,
            "semantic_score": self.semantic_score,
            "final_score": self.final_score,
            "concept_score": self.concept_score,
            "primary_text_score": self.primary_text_score,
            "support_text_score": self.support_text_score,
            "matched_concepts": list(self.matched_concepts),
            "reason_codes": list(self.reason_codes),
        }


@dataclass(frozen=True, slots=True)
class SelectionResult:
    plan: QueryPlan
    horizon_used: str
    fallback_used: bool
    records: tuple[dict[str, Any], ...]
    scores: tuple[CandidateScore, ...]
    filtered: dict[str, int]

    def audit_metadata(self) -> dict[str, object]:
        return {
            "policy_version": self.plan.policy_version,
            "intent": self.plan.intent,
            "primary_horizon": self.plan.primary_horizon,
            "horizon_used": self.horizon_used,
            "fallback_used": self.fallback_used,
            "hit_count": len(self.records),
            "hit_ids": [score.memory_id for score in self.scores],
            "candidate_scores": [score.audit_metadata() for score in self.scores],
            "filtered": dict(self.filtered),
            "model_called": False,
            "memory_write_performed": False,
            "restricted_included": False,
        }
