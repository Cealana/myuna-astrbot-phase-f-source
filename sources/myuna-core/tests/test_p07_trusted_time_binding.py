from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from myuna_core.active_temporal_context.time import TrustedTimeSample
from myuna_core.episodic_memory import (
    CompleteTurn,
    EpisodicCapsule,
    EpisodicMemoryError,
    LosslessArchiveStore,
    TurnTimeCorrection,
    bind_exact_turn_time,
    build_snapshot,
    render_trusted_current_time,
    sample_once_and_bind,
    trusted_time_audit,
    unresolved_turn_time,
)
from myuna_core.trusted_time.contracts import (
    SynchronizationEvidence,
    TrustedTimeWatermark,
    UtcObservation,
)

from tests.episodic_memory_fixtures import digest, make_turn
from tests.test_p07_episodic_index_retrieval import riverside


NOW = datetime(2026, 8, 8, 1, 0, 1, tzinfo=timezone.utc)


def time_parts(
    *,
    sequence: int = 1,
    instant: datetime = NOW,
    monotonic_ns: int = 4_000_000_000,
    boot_id: str = "synthetic-boot-a",
    synchronized: bool = True,
    uncertainty: timedelta = timedelta(milliseconds=1),
) -> tuple[TrustedTimeSample, UtcObservation, TrustedTimeWatermark]:
    sample = TrustedTimeSample(instant, "myuna-trusted-local-v1", "trusted_local", sequence)
    observation = UtcObservation(
        instant,
        monotonic_ns,
        boot_id,
        SynchronizationEvidence(synchronized, uncertainty, "systemd-timesyncd"),
    )
    return sample, observation, TrustedTimeWatermark(sample.source, sequence, instant)


class FakePort:
    def __init__(self, sample: TrustedTimeSample) -> None:
        self.value = sample
        self.calls = 0

    def sample(self) -> TrustedTimeSample:
        self.calls += 1
        return self.value


class FakeEvidence:
    def __init__(self, observation: UtcObservation, watermark: TrustedTimeWatermark) -> None:
        self.observation = observation
        self.watermark = watermark
        self.calls = 0

    def evidence_for_sample(
        self, sample: TrustedTimeSample
    ) -> tuple[UtcObservation, TrustedTimeWatermark]:
        self.calls += 1
        self.asserted_sample = sample
        return self.observation, self.watermark


class TrustedTimeBindingTests(unittest.TestCase):
    def test_one_sample_per_turn_no_polling_and_every_turn_prompt_projection(self) -> None:
        sample, observation, watermark = time_parts()
        port = FakePort(sample)
        evidence = FakeEvidence(observation, watermark)
        binding = sample_once_and_bind(
            port=port,
            evidence_port=evidence,
            received_monotonic_ns=1_000_000_000,
            committed_monotonic_ns=2_000_000_000,
            delivered_monotonic_ns=3_000_000_000,
            captured_at_utc=NOW + timedelta(milliseconds=100),
        )
        self.assertEqual(port.calls, 1)
        self.assertEqual(evidence.calls, 1)
        self.assertLessEqual(
            binding.received_at_utc,
            binding.committed_at_utc,
        )
        self.assertLessEqual(binding.committed_at_utc, binding.delivered_at_utc)
        prompt = render_trusted_current_time(binding)
        self.assertIn("status=exact", prompt)
        self.assertIn("zone=Asia/Shanghai", prompt)
        self.assertNotIn(observation.boot_id, prompt)
        self.assertEqual(trusted_time_audit(binding)["status"], "exact")

    def test_regression_stale_uncertain_unsynchronized_and_reboot_continuity(self) -> None:
        sample, observation, watermark = time_parts()
        first = bind_exact_turn_time(
            sample=sample,
            observation=observation,
            watermark=watermark,
            received_monotonic_ns=1,
            committed_monotonic_ns=2,
            delivered_monotonic_ns=3,
            captured_at_utc=NOW,
        )
        stale_sample, stale_observation, stale_watermark = time_parts(
            sequence=2, instant=NOW + timedelta(seconds=1), monotonic_ns=10
        )
        with self.assertRaisesRegex(EpisodicMemoryError, "trusted_time_stale"):
            bind_exact_turn_time(
                sample=stale_sample,
                observation=stale_observation,
                watermark=stale_watermark,
                received_monotonic_ns=4,
                committed_monotonic_ns=5,
                delivered_monotonic_ns=6,
                captured_at_utc=NOW + timedelta(seconds=10),
                previous=first,
            )
        regressed, regressed_observation, regressed_watermark = time_parts(
            sequence=1, instant=NOW + timedelta(seconds=1), monotonic_ns=10
        )
        with self.assertRaisesRegex(EpisodicMemoryError, "sequence_regression"):
            bind_exact_turn_time(
                sample=regressed,
                observation=regressed_observation,
                watermark=regressed_watermark,
                received_monotonic_ns=4,
                committed_monotonic_ns=5,
                delivered_monotonic_ns=6,
                captured_at_utc=NOW + timedelta(seconds=1),
                previous=first,
            )
        uncertain, uncertain_observation, uncertain_watermark = time_parts(
            uncertainty=timedelta(seconds=2)
        )
        with self.assertRaisesRegex(EpisodicMemoryError, "binding_mismatch"):
            bind_exact_turn_time(
                sample=uncertain,
                observation=uncertain_observation,
                watermark=uncertain_watermark,
                received_monotonic_ns=1,
                committed_monotonic_ns=2,
                delivered_monotonic_ns=3,
                captured_at_utc=NOW,
            )
        reboot_sample, reboot_observation, reboot_watermark = time_parts(
            sequence=2,
            instant=NOW + timedelta(seconds=1),
            monotonic_ns=10,
            boot_id="synthetic-boot-b",
        )
        reboot = bind_exact_turn_time(
            sample=reboot_sample,
            observation=reboot_observation,
            watermark=reboot_watermark,
            received_monotonic_ns=1,
            committed_monotonic_ns=2,
            delivered_monotonic_ns=3,
            captured_at_utc=NOW + timedelta(seconds=1),
            previous=first,
        )
        self.assertEqual(reboot.boot_id, "synthetic-boot-b")

    def test_unresolved_time_never_drops_raw_and_correction_is_append_only(self) -> None:
        base = make_turn(1, "0" * 64)
        unresolved = unresolved_turn_time(
            reason_code="trusted_time_unavailable",
            received_monotonic_ns=1,
            committed_monotonic_ns=2,
            delivered_monotonic_ns=3,
        )
        turn = CompleteTurn.create(replace(base.draft, time_binding=unresolved))
        with tempfile.TemporaryDirectory() as directory:
            store = LosslessArchiveStore(Path(directory) / "archive.sqlite3")
            store.initialize()
            store.append_complete_turn(turn.draft)
            self.assertEqual(store.metadata()["turn_count"], 1)
            sample, observation, watermark = time_parts()
            exact = bind_exact_turn_time(
                sample=sample,
                observation=observation,
                watermark=watermark,
                received_monotonic_ns=1,
                committed_monotonic_ns=2,
                delivered_monotonic_ns=3,
                captured_at_utc=NOW,
            )
            correction = TurnTimeCorrection(
                correction_id="time-correction-1",
                turn_id=turn.draft.turn_id,
                turn_digest=turn.turn_digest,
                original_binding_digest=unresolved.binding_digest,
                corrected_binding=exact,
                reason_code="trusted_time_reconciled",
                created_at_utc=NOW + timedelta(seconds=1),
                provenance_digest=digest("synthetic-time-reconciliation"),
            )
            store.append_time_correction(correction)
            store.append_time_correction(correction)
            loaded = store.turns()[0]
            self.assertEqual(loaded.draft.time_binding.status, "unresolved")
            self.assertEqual(store.metadata()["time_correction_count"], 1)

    def test_unresolved_time_prohibits_calendar_episode_grouping(self) -> None:
        turn, primitive = riverside()
        unresolved = unresolved_turn_time(
            reason_code="trusted_time_regression",
            received_monotonic_ns=1,
            committed_monotonic_ns=2,
            delivered_monotonic_ns=3,
        )
        changed = CompleteTurn.create(replace(turn.draft, time_binding=unresolved))
        primitive = replace(
            primitive,
            source_turn_digest=changed.turn_digest,
            coverage_state="coverage_incomplete",
        )
        base = build_snapshot((changed,), (primitive,))
        capsule = EpisodicCapsule(
            capsule_id="date-unresolved",
            capsule_kind="date",
            source_start=1,
            source_end=1,
            source_terminal_digest=changed.turn_digest,
            primitive_digests=(base.primitives[0].primitive_digest,),
            label="unresolved day",
            coverage_state=base.primitives[0].coverage_state,
        )
        with self.assertRaisesRegex(EpisodicMemoryError, "capsule_time_unresolved"):
            build_snapshot((changed,), base.primitives, (capsule,))


if __name__ == "__main__":
    unittest.main()
