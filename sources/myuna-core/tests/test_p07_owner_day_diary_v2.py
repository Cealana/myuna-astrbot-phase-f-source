from __future__ import annotations

from datetime import date, datetime, timezone
import unittest

from myuna_core.active_temporal_context.time import TrustedTimeSample
from myuna_core.episodic_memory import (
    ContextLimits,
    OWNER_DAY_ADDENDUM_PURPOSE,
    OWNER_DAY_FINAL_PURPOSE,
    OWNER_DAY_PREVIEW_PURPOSE,
    EpisodicMemoryError,
    OwnerDayPolicy,
    OwnerDayDiaryCandidate,
    OwnerDayDiaryJob,
    OwnerDayDiaryGenerationCoordinator,
    build_owner_day_diary_job,
    owner_day_interval,
    owner_day_label,
)
from myuna_core.episodic_memory.contracts import semantic_digest
from tests.episodic_memory_fixtures import make_turn


def trusted_sample(instant: datetime) -> TrustedTimeSample:
    return TrustedTimeSample(
        instant=instant,
        source="myuna-trusted-local-v1",
        source_class="trusted_local",
        sequence=77,
        authority="systemd-timesyncd",
        uncertainty_microseconds=1_000,
        synchronized=True,
        boot_id="synthetic-owner-day-boot",
        monotonic_ns=77_000,
    )


class OwnerDayDiaryV2Tests(unittest.TestCase):
    @staticmethod
    def _identity() -> dict[str, str]:
        return {
            "archive_id": "owner-day-synthetic-archive",
            "memory_release_set_id": "1" * 64,
            "parent_release_set_id": "2" * 64,
            "persona_digest": "3" * 64,
            "policy_overlay_id": "4" * 64,
        }

    def test_shanghai_six_am_boundary_not_midnight(self) -> None:
        policy = OwnerDayPolicy()
        self.assertEqual(
            owner_day_label(datetime(2026, 8, 7, 21, 59, tzinfo=timezone.utc), policy),
            date(2026, 8, 7),
        )
        self.assertEqual(
            owner_day_label(datetime(2026, 8, 7, 22, 0, tzinfo=timezone.utc), policy),
            date(2026, 8, 8),
        )

    def test_los_angeles_dst_and_invalid_boundaries(self) -> None:
        policy = OwnerDayPolicy(
            calendar_zone="America/Los_Angeles", boundary_local_time="06:00"
        )
        spring = owner_day_interval(date(2026, 3, 7), policy)
        fall = owner_day_interval(date(2026, 10, 31), policy)
        self.assertEqual((spring.end_utc - spring.start_utc).total_seconds(), 23 * 3600)
        self.assertEqual((fall.end_utc - fall.start_utc).total_seconds(), 25 * 3600)
        with self.assertRaisesRegex(EpisodicMemoryError, "owner_day_boundary_nonexistent"):
            owner_day_interval(
                date(2026, 3, 8),
                OwnerDayPolicy(
                    calendar_zone="America/Los_Angeles", boundary_local_time="02:30"
                ),
            )
        with self.assertRaisesRegex(EpisodicMemoryError, "owner_day_boundary_ambiguous"):
            owner_day_interval(
                date(2026, 11, 1),
                OwnerDayPolicy(
                    calendar_zone="America/Los_Angeles", boundary_local_time="01:30"
                ),
            )

    @staticmethod
    def _turns():
        first = make_turn(
            1,
            "0" * 64,
            owner="Cealana suggests a riverside walk",
            assistant="Myuna agrees and changes clothes",
            instant=datetime(2026, 8, 8, 1, tzinfo=timezone.utc),
        )
        second = make_turn(
            2,
            first.turn_digest,
            owner="Goodnight",
            assistant="Goodnight, I will remember today",
            instant=datetime(2026, 8, 8, 20, tzinfo=timezone.utc),
        )
        return first, second

    def test_preview_final_and_addendum_are_watermark_bound(self) -> None:
        turns = self._turns()
        bindings = {turn.draft.sequence: turn.draft.time_binding for turn in turns}
        policy = OwnerDayPolicy()
        preview = build_owner_day_diary_job(
            turns=turns,
            effective_bindings=bindings,
            owner_day=date(2026, 8, 8),
            policy=policy,
            purpose=OWNER_DAY_PREVIEW_PURPOSE,
            generation_time_sample=trusted_sample(
                datetime(2026, 8, 8, 20, 1, tzinfo=timezone.utc)
            ),
            target_revision=1,
            supersedes_revision=None,
            **self._identity(),
        )
        self.assertEqual(preview.source_watermark, 2)
        self.assertEqual(preview.audit_projection()["source_turn_count"], 2)
        with self.assertRaisesRegex(EpisodicMemoryError, "owner_day_not_closed"):
            build_owner_day_diary_job(
                turns=turns,
                effective_bindings=bindings,
                owner_day=date(2026, 8, 8),
                policy=policy,
                purpose=OWNER_DAY_FINAL_PURPOSE,
                generation_time_sample=trusted_sample(
                    datetime(2026, 8, 8, 20, 1, tzinfo=timezone.utc)
                ),
                target_revision=1,
                supersedes_revision=None,
                **self._identity(),
            )
        final = build_owner_day_diary_job(
            turns=turns,
            effective_bindings=bindings,
            owner_day=date(2026, 8, 8),
            policy=policy,
            purpose=OWNER_DAY_FINAL_PURPOSE,
            generation_time_sample=trusted_sample(
                datetime(2026, 8, 8, 22, tzinfo=timezone.utc)
            ),
            target_revision=1,
            supersedes_revision=None,
            **self._identity(),
        )
        addendum = build_owner_day_diary_job(
            turns=turns,
            effective_bindings=bindings,
            owner_day=date(2026, 8, 8),
            policy=policy,
            purpose=OWNER_DAY_ADDENDUM_PURPOSE,
            generation_time_sample=trusted_sample(
                datetime(2026, 8, 8, 21, tzinfo=timezone.utc)
            ),
            target_revision=2,
            supersedes_revision=1,
            **self._identity(),
        )
        self.assertEqual(final.source_watermark, addendum.source_watermark)
        self.assertNotEqual(final.job_digest, addendum.job_digest)

    def test_capacity_precedes_provider_and_candidate_covers_every_turn(self) -> None:
        turns = self._turns()
        persona_context = "Synthetic Myuna persona context"
        identity = self._identity() | {
            "persona_digest": semantic_digest(
                "myuna-p07-owner-day-diary-persona-context-v2",
                {"persona_context": persona_context},
            )
        }
        job = build_owner_day_diary_job(
            turns=turns,
            effective_bindings={
                turn.draft.sequence: turn.draft.time_binding for turn in turns
            },
            owner_day=date(2026, 8, 8),
            policy=OwnerDayPolicy(),
            purpose=OWNER_DAY_PREVIEW_PURPOSE,
            generation_time_sample=trusted_sample(
                datetime(2026, 8, 8, 20, 1, tzinfo=timezone.utc)
            ),
            target_revision=1,
            supersedes_revision=None,
            **identity,
        )

        class Provider:
            calls = 0

            def generate_owner_day_diary(self, messages, *, timeout_seconds):
                self.calls += 1
                statements = []
                for turn in turns:
                    statements.append(
                        {
                            "kind": "factual_observation",
                            "source_episode_digests": [],
                            "source_sequences": [turn.draft.sequence],
                            "source_turn_digests": [turn.turn_digest],
                            "statement_id": f"statement-{turn.draft.sequence}",
                            "text": f"Synthetic fact {turn.draft.sequence}",
                        }
                    )
                import json

                return json.dumps(
                    {
                        "job_digest": job.job_digest,
                        "schema": "myuna.p07-owner-day-diary-candidate.v2",
                        "statements": statements,
                    }
                )

        provider = Provider()
        blocked = OwnerDayDiaryGenerationCoordinator(
            limits=ContextLimits(10, 10, 10, 10, 0, 0, 0),
            token_counter=lambda messages: 1,
        ).generate(
            job,
            persona_context=persona_context,
            provider=provider,
            created_at_utc=job.as_of_utc,
        )
        self.assertEqual(blocked.status, "coverage_incomplete")
        self.assertFalse(blocked.provider_called)
        self.assertEqual(provider.calls, 0)
        completed = OwnerDayDiaryGenerationCoordinator(
            limits=ContextLimits(200_000, 199_000, 1_198_096, 999_232, 4_000, 16_000, 4_000),
            token_counter=lambda messages: 128,
        ).generate(
            job,
            persona_context=persona_context,
            provider=provider,
            created_at_utc=job.as_of_utc,
        )
        self.assertEqual(completed.status, "completed")
        self.assertTrue(completed.provider_called)
        self.assertEqual(provider.calls, 1)
        self.assertEqual(
            completed.candidate.revision.audit_projection()["source_turn_count"],
            2,
        )
        self.assertEqual(
            OwnerDayDiaryJob.from_payload(job.as_payload()).job_digest,
            job.job_digest,
        )
        candidate = OwnerDayDiaryCandidate.from_payload(
            completed.candidate.as_payload()
        )
        self.assertEqual(candidate.candidate_digest, completed.candidate.candidate_digest)
        self.assertNotEqual(
            job.egress_policy_digest,
            build_owner_day_diary_job(
                turns=turns,
                effective_bindings={
                    turn.draft.sequence: turn.draft.time_binding for turn in turns
                },
                owner_day=date(2026, 8, 8),
                policy=OwnerDayPolicy(),
                purpose=OWNER_DAY_ADDENDUM_PURPOSE,
                generation_time_sample=trusted_sample(
                    datetime(2026, 8, 8, 20, 2, tzinfo=timezone.utc)
                ),
                target_revision=1,
                supersedes_revision=None,
                **identity,
            ).egress_policy_digest,
        )

    def test_generation_time_requires_complete_synchronized_p10b_evidence(self) -> None:
        turns = self._turns()
        incomplete = TrustedTimeSample(
            instant=datetime(2026, 8, 8, 20, 1, tzinfo=timezone.utc),
            source="myuna-trusted-local-v1",
            source_class="trusted_local",
            sequence=78,
        )
        with self.assertRaisesRegex(
            EpisodicMemoryError, "owner_day_generation_time_rejected"
        ):
            build_owner_day_diary_job(
                turns=turns,
                effective_bindings={
                    turn.draft.sequence: turn.draft.time_binding for turn in turns
                },
                owner_day=date(2026, 8, 8),
                policy=OwnerDayPolicy(),
                purpose=OWNER_DAY_PREVIEW_PURPOSE,
                generation_time_sample=incomplete,
                target_revision=1,
                supersedes_revision=None,
                **self._identity(),
            )


if __name__ == "__main__":
    unittest.main()
