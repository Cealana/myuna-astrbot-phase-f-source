from __future__ import annotations

from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
import json
import unittest

from myuna_core.episodic_memory import (
    ContextLimits,
    DiaryGenerationCandidate,
    EpisodicMemoryError,
    ReflectiveDiaryGenerationCoordinator,
    build_closed_day_job,
)
from myuna_core.episodic_memory.contracts import semantic_digest

from tests.episodic_memory_fixtures import digest, make_turn


PERSONA = "Synthetic Myuna persona context."
PERSONA_DIGEST = semantic_digest(
    "myuna-p07-reflective-diary-persona-context-v1",
    {"persona_context": PERSONA},
)


def day_archive():
    first = make_turn(
        1,
        "0" * 64,
        owner="Cealana建议去江边走走。",
        assistant="Myuna表示赞同并去换衣服。",
        instant=datetime(2026, 8, 8, 1, tzinfo=timezone.utc),
    )
    second = make_turn(
        2,
        first.turn_digest,
        owner="晚上八点在江边见。",
        assistant="好，我会记得这项约定。",
        instant=datetime(2026, 8, 8, 2, tzinfo=timezone.utc),
    )
    closure = make_turn(
        3,
        second.turn_digest,
        owner="新的一天开始了。",
        assistant="嗯，昨天已经结束了。",
        instant=datetime(2026, 8, 8, 17, tzinfo=timezone.utc),
    )
    return first, second, closure


def job_for_day():
    first, second, closure = day_archive()
    return build_closed_day_job(
        turns=(first, second, closure),
        corrections=(),
        day=date(2026, 8, 8),
        calendar_zone="Asia/Shanghai",
        closure_binding=closure.draft.time_binding,
        target_revision=1,
        generation_kind="contemporaneous",
        supersedes_revision=None,
        memory_release_set_id="a" * 64,
        parent_release_set_id="b" * 64,
        policy_overlay_id="c" * 64,
        archive_id="synthetic-archive",
        persona_digest=PERSONA_DIGEST,
    )


def candidate_text(job, *, sequences=(1, 2)) -> str:
    turns = {turn.draft.sequence: turn for turn in job.source_turns}
    statements = []
    for sequence in sequences:
        statements.append(
            {
                "kind": "factual_observation",
                "source_episode_digests": [],
                "source_sequences": [sequence],
                "source_turn_digests": [turns[sequence].turn_digest],
                "statement_id": f"fact-{sequence}",
                "text": f"合成事实 {sequence}",
            }
        )
    statements.extend(
        [
            {
                "kind": "interpretation_reflection",
                "source_episode_digests": [],
                "source_sequences": list(sequences),
                "source_turn_digests": [turns[sequence].turn_digest for sequence in sequences],
                "statement_id": "reflection-1",
                "text": "我很喜欢这份轻松的约定。",
            },
            {
                "kind": "uncertainty",
                "source_episode_digests": [],
                "source_sequences": [],
                "source_turn_digests": [],
                "statement_id": "uncertainty-1",
                "text": "我还不确定天气会不会变化。",
            },
            {
                "kind": "intention",
                "source_episode_digests": [],
                "source_sequences": [sequences[-1]],
                "source_turn_digests": [turns[sequences[-1]].turn_digest],
                "statement_id": "intention-1",
                "text": "我想认真记住晚上的约定。",
            },
        ]
    )
    return json.dumps(
        {
            "job_digest": job.job_digest,
            "schema": "myuna.p07-reflective-diary-candidate.v1",
            "statements": statements,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


class Provider:
    def __init__(self, job) -> None:
        self.job = job
        self.calls = 0

    def generate_diary(self, messages, *, timeout_seconds):
        self.calls += 1
        self.messages = messages
        self.timeout_seconds = timeout_seconds
        return candidate_text(self.job)


class ReflectiveDiaryGenerationTests(unittest.TestCase):
    def test_closed_day_uses_every_eligible_turn_once_and_candidate_is_source_complete(self):
        job = job_for_day()
        self.assertEqual(tuple(turn.draft.sequence for turn in job.source_turns), (1, 2))
        provider = Provider(job)
        result = ReflectiveDiaryGenerationCoordinator(
            limits=ContextLimits(),
            token_counter=lambda messages: sum(
                len(item["content"].encode("utf-8")) for item in messages
            ),
        ).generate(
            job,
            persona_context=PERSONA,
            provider=provider,
            created_at_utc=datetime(2026, 8, 8, 17, 1, tzinfo=timezone.utc),
        )
        self.assertEqual(result.status, "completed")
        self.assertTrue(result.provider_called)
        self.assertEqual(provider.calls, 1)
        self.assertIsInstance(result.candidate, DiaryGenerationCandidate)
        self.assertEqual(result.candidate.entry.source_sequences, (1, 2))
        self.assertNotIn("Cealana", str(result.audit_projection()))

    def test_capacity_overflow_creates_no_provider_call(self):
        job = job_for_day()
        provider = Provider(job)
        result = ReflectiveDiaryGenerationCoordinator(
            limits=ContextLimits(
                request_characters=10,
                projection_characters=10,
                serialized_bytes=10,
                input_tokens=10,
                output_reserve_characters=1,
                output_reserve_bytes=1,
                output_reserve_tokens=1,
            ),
            token_counter=lambda messages: 1,
        ).generate(
            job,
            persona_context=PERSONA,
            provider=provider,
            created_at_utc=datetime(2026, 8, 8, 17, 1, tzinfo=timezone.utc),
        )
        self.assertEqual(result.status, "coverage_incomplete")
        self.assertFalse(result.provider_called)
        self.assertEqual(provider.calls, 0)

    def test_partial_candidate_cannot_claim_complete_day(self):
        job = job_for_day()
        with self.assertRaisesRegex(
            EpisodicMemoryError,
            "diary_provider_output_coverage_incomplete",
        ):
            DiaryGenerationCandidate.from_provider_text(
                candidate_text(job, sequences=(1,)),
                job=job,
                created_at_utc=datetime(2026, 8, 8, 17, 1, tzinfo=timezone.utc),
            )

    def test_source_digest_or_persona_drift_fails_before_provider(self):
        job = job_for_day()
        with self.assertRaisesRegex(EpisodicMemoryError, "diary_persona_context_drifted"):
            ReflectiveDiaryGenerationCoordinator(
                limits=ContextLimits(),
                token_counter=lambda messages: 1,
            ).generate(
                job,
                persona_context="wrong persona",
                provider=Provider(job),
                created_at_utc=datetime(2026, 8, 8, 17, 1, tzinfo=timezone.utc),
            )
        with self.assertRaisesRegex(EpisodicMemoryError, "source_selection_digest_mismatch"):
            replace(job, source_selection_digest=digest("drift"))

    def test_day_not_closed_and_unresolved_source_fail_without_generation(self):
        first, second, closure = day_archive()
        with self.assertRaisesRegex(EpisodicMemoryError, "diary_day_not_closed"):
            build_closed_day_job(
                turns=(first, second),
                corrections=(),
                day=date(2026, 8, 8),
                calendar_zone="Asia/Shanghai",
                closure_binding=second.draft.time_binding,
                target_revision=1,
                generation_kind="contemporaneous",
                supersedes_revision=None,
                memory_release_set_id="a" * 64,
                parent_release_set_id="b" * 64,
                policy_overlay_id="c" * 64,
                archive_id="synthetic-archive",
                persona_digest=PERSONA_DIGEST,
            )
        unresolved_binding = replace(
            first.draft.time_binding,
            status="unresolved",
            sample_instant_utc=None,
            received_at_utc=None,
            committed_at_utc=None,
            delivered_at_utc=None,
            local_calendar_representation=None,
            event_offset_minutes=None,
            uncertainty_microseconds=None,
            synchronized=False,
            source=None,
            source_class=None,
            authority=None,
            boot_id=None,
            sequence=None,
            sample_monotonic_ns=None,
            quality_codes=("trusted_time_unavailable",),
        )
        unresolved_draft = replace(first.draft, time_binding=unresolved_binding)
        unresolved = type(first).create(unresolved_draft)
        second_after = replace(second.draft, previous_turn_digest=unresolved.turn_digest)
        second_rechained = type(second).create(second_after)
        closure_after = replace(closure.draft, previous_turn_digest=second_rechained.turn_digest)
        closure_rechained = type(closure).create(closure_after)
        with self.assertRaisesRegex(EpisodicMemoryError, "diary_day_source_time_incomplete"):
            build_closed_day_job(
                turns=(unresolved, second_rechained, closure_rechained),
                corrections=(),
                day=date(2026, 8, 8),
                calendar_zone="Asia/Shanghai",
                closure_binding=closure_rechained.draft.time_binding,
                target_revision=1,
                generation_kind="contemporaneous",
                supersedes_revision=None,
                memory_release_set_id="a" * 64,
                parent_release_set_id="b" * 64,
                policy_overlay_id="c" * 64,
                archive_id="synthetic-archive",
                persona_digest=PERSONA_DIGEST,
            )

    def test_original_zone_day_is_stable_across_los_angeles_dst(self):
        first = make_turn(
            1,
            "0" * 64,
            instant=datetime(2026, 11, 1, 8, 30, tzinfo=timezone.utc),
            zone_name="America/Los_Angeles",
        )
        closure = make_turn(
            2,
            first.turn_digest,
            instant=datetime(2026, 11, 2, 8, 30, tzinfo=timezone.utc),
            zone_name="America/Los_Angeles",
        )
        job = build_closed_day_job(
            turns=(first, closure),
            corrections=(),
            day=date(2026, 11, 1),
            calendar_zone="America/Los_Angeles",
            closure_binding=closure.draft.time_binding,
            target_revision=1,
            generation_kind="contemporaneous",
            supersedes_revision=None,
            memory_release_set_id="a" * 64,
            parent_release_set_id="b" * 64,
            policy_overlay_id="c" * 64,
            archive_id="synthetic-archive",
            persona_digest=PERSONA_DIGEST,
        )
        self.assertEqual(job.calendar_zone, "America/Los_Angeles")
        self.assertEqual(tuple(turn.draft.sequence for turn in job.source_turns), (1,))


if __name__ == "__main__":
    unittest.main()
