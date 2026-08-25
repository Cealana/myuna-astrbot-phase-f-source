from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Mapping
import argparse
import json

from .in_memory import InMemoryStore
from .models import (
    ConfirmationLevel,
    MemoryCandidate,
    MemoryKind,
    MemoryQuery,
    MemorySource,
    SourceKind,
    TimePrecision,
)
from .policy import DefaultMemoryPolicy
from .retrieval import ExplainableRetriever


def _parse_datetime(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _candidate(case: Mapping[str, Any]) -> MemoryCandidate:
    recorded_at = datetime.fromisoformat(str(case["recorded_at"]))
    source = MemorySource(
        source_id=f"source-{case['case_id']}",
        kind=SourceKind(str(case.get("source_kind", "conversation"))),
        reference=f"synthetic://{case['case_id']}",
        captured_at=recorded_at,
        metadata={"synthetic": True},
    )
    return MemoryCandidate(
        memory_id=str(case["memory_id"]),
        source=source,
        kind=MemoryKind(str(case["kind"])),
        text=str(case["text"]),
        occurred_at=datetime.fromisoformat(str(case["occurred_at"])),
        recorded_at=recorded_at,
        timezone=str(case["timezone"]),
        time_precision=TimePrecision(str(case["time_precision"])),
        time_phrase=case.get("time_phrase"),
        exact_quote=case.get("exact_quote"),
        scope=tuple(str(value) for value in case.get("scope", ["global"])),
        importance=float(case.get("importance", 0.5)),
        sensitivity=str(case.get("sensitivity", "normal")),
        tags=tuple(str(value) for value in case.get("tags", [])),
        confirmation=ConfirmationLevel(str(case.get("confirmation", "observed"))),
        directive_text=str(case.get("directive_text", "")),
        supersedes_id=case.get("supersedes_id"),
        expires_at=_parse_datetime(case.get("expires_at")),
        metadata={"synthetic_case_id": str(case["case_id"])},
    )


class SyntheticEvaluationHarness:
    """Runs deterministic policy and retrieval checks over fictional Chinese data."""

    def __init__(self, fixture_path: Path) -> None:
        self.fixture_path = fixture_path

    def run(self) -> dict[str, Any]:
        cases = [
            json.loads(line)
            for line in self.fixture_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        policy = DefaultMemoryPolicy()
        store = InMemoryStore()
        policy_results: list[dict[str, Any]] = []

        for case in (item for item in cases if item["type"] == "candidate"):
            candidate = _candidate(case)
            decision = policy.evaluate(candidate, candidate.recorded_at)
            passed = decision.action.value == case["expected_policy_action"]
            policy_results.append(
                {
                    "case_id": case["case_id"],
                    "expected": case["expected_policy_action"],
                    "actual": decision.action.value,
                    "passed": passed,
                }
            )
            record = policy.materialize(candidate, decision)
            if record is not None:
                store.append(record)

        retriever = ExplainableRetriever(store)
        retrieval_results: list[dict[str, Any]] = []
        for case in (item for item in cases if item["type"] == "query"):
            query = MemoryQuery(
                text=str(case["text"]),
                scope=tuple(str(value) for value in case.get("scope", ["global"])),
                at=_parse_datetime(case.get("at")),
                proactive=bool(case.get("proactive", False)),
                limit=int(case.get("limit", 5)),
            )
            result = retriever.retrieve(query)
            actual_top = result.hits[0].record.memory_id if result.hits else None
            expected_top = case.get("expected_top_id")
            retrieval_results.append(
                {
                    "case_id": case["case_id"],
                    "expected_top_id": expected_top,
                    "actual_top_id": actual_top,
                    "passed": actual_top == expected_top,
                    "trace": {
                        "strategy_version": result.trace.strategy_version,
                        "examined": result.trace.examined,
                        "eligible": result.trace.eligible,
                        "filtered": dict(result.trace.filtered),
                    },
                }
            )

        all_results = [*policy_results, *retrieval_results]
        return {
            "stage": "memory-stage-0",
            "dataset": self.fixture_path.name,
            "synthetic_only": True,
            "policy_cases": len(policy_results),
            "retrieval_cases": len(retrieval_results),
            "passed": sum(1 for result in all_results if result["passed"]),
            "failed": sum(1 for result in all_results if not result["passed"]),
            "policy_results": policy_results,
            "retrieval_results": retrieval_results,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the synthetic-only Memory Stage 0 evaluation")
    parser.add_argument("fixture", type=Path)
    args = parser.parse_args()
    result = SyntheticEvaluationHarness(args.fixture).run()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
