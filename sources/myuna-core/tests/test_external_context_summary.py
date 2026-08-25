from __future__ import annotations

import unittest

from myuna_core.external_context.contracts import (
    ExternalContextError, ExternalSummaryCandidate, ExternalSummaryJob,
    ExternalTurn, ExternalTurnProvenance, ZERO_DIGEST,
)
from myuna_core.external_context.summary import ExternalSummaryCoordinator


class FakeProvider:
    def __init__(self, result: str = "Synthetic bounded summary.") -> None:
        self.result = result
        self.calls = 0
    def generate_summary(self, messages, *, timeout_seconds):
        self.calls += 1
        return self.result


def job() -> ExternalSummaryJob:
    first = ExternalTurn.create(sequence=1, parent_digest=ZERO_DIGEST, user_message="Synthetic user one", assistant_reply="Synthetic reply one")
    second = ExternalTurn.create(sequence=2, parent_digest=first.digest, user_message="Synthetic user two", assistant_reply="Synthetic reply two")
    return ExternalSummaryJob.create(epoch_id="epoch-synthetic", base_revision=2, summary_version=1,
        covered_end=2, covered_terminal_digest=second.digest, profile_revisions=(3,), prior_summary=None, turns=(first, second))


class ExternalSummaryTests(unittest.TestCase):
    def test_provenance_round_trip_and_unknown_fails_closed(self):
        value = ExternalTurnProvenance(epoch_id="epoch-synthetic", epoch_revision=2,
            projection_digest="a" * 64, sources=("owner_profile_selected", "owner_current_message"),
            profile_revisions=(3,), summary_version=None, recent_turn_start=None, recent_turn_end=None)
        self.assertEqual(ExternalTurnProvenance.from_payload(value.as_payload()), value)
        unknown = ExternalTurnProvenance(
            epoch_id="epoch-synthetic",
            epoch_revision=2,
            projection_digest="b" * 64,
            sources=("unknown",),
            profile_revisions=(),
            summary_version=None,
            recent_turn_start=None,
            recent_turn_end=None,
        )
        self.assertEqual(
            ExternalTurnProvenance.from_payload(unknown.as_payload()),
            unknown,
        )
        with self.assertRaises(ExternalContextError):
            ExternalTurnProvenance(epoch_id="epoch-synthetic", epoch_revision=2,
                projection_digest="a" * 64, sources=("unknown", "owner_current_message"),
                profile_revisions=(), summary_version=None, recent_turn_start=None, recent_turn_end=None)

    def test_job_digest_chain_and_candidate_binding(self):
        selected = job()
        self.assertEqual(ExternalSummaryJob.from_payload(selected.as_payload()), selected)
        result = ExternalSummaryCoordinator().generate(selected, FakeProvider(), timeout_seconds=10)
        parsed = ExternalSummaryCandidate.from_payload(result.candidate.as_payload())
        self.assertEqual(parsed.job_digest, selected.digest)
        self.assertEqual(parsed.summary.covered_terminal_digest, selected.covered_terminal_digest)

    def test_corrupt_job_and_oversize_summary_fail_closed(self):
        payload = job().as_payload()
        payload["covered_end"] = 3
        with self.assertRaises(ExternalContextError):
            ExternalSummaryJob.from_payload(payload)
        with self.assertRaises(ValueError):
            ExternalSummaryCoordinator().generate(job(), FakeProvider("x" * 4001), timeout_seconds=10)

    def test_provider_failure_is_typed(self):
        class Broken:
            def generate_summary(self, messages, *, timeout_seconds):
                raise OSError("synthetic")
        with self.assertRaisesRegex(ValueError, "summary_provider_unavailable"):
            ExternalSummaryCoordinator().generate(job(), Broken(), timeout_seconds=10)


if __name__ == "__main__":
    unittest.main()
