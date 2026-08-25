from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from myuna_core.active_temporal_context.protocol import build_active_snapshot_receipt
from myuna_core.episodic_memory import (
    SEMANTIC_WRITE_BOUNDARY,
    TEMPORAL_VALIDITY_OWNERSHIP,
    EpisodicMemoryError,
    TemporalEndpoint,
    TemporalIntervalEpisode,
    TemporalIntervalRevision,
    project_all_active_temporal_items,
    recall_interval_episodes,
    require_exact_time_for_temporal_mutation,
    unresolved_turn_time,
)
from myuna_core.episodic_memory.temporal_validity import (
    project_resident_temporal_items,
)

from tests.episodic_memory_fixtures import digest, make_turn


START = datetime(2026, 8, 1, 2, tzinfo=timezone.utc)
END = datetime(2026, 8, 3, 14, tzinfo=timezone.utc)


def endpoint(kind: str, instant: datetime | None = None) -> TemporalEndpoint:
    return TemporalEndpoint(
        kind=kind,
        calendar_zone="Asia/Shanghai",
        trusted_time_binding_digest=digest(f"time-{kind}-{instant}"),
        uncertainty_microseconds=1_000,
        instant_utc=instant,
    )


def revisions() -> tuple[TemporalIntervalRevision, ...]:
    planned = TemporalIntervalRevision(
        interval_id="shanghai-trip-2026-08",
        revision=1,
        state="planned",
        statement="Cealana计划于2026-08-01前往上海。",
        conflict_key="owner_location",
        start=endpoint("exact", START),
        end=endpoint("open"),
        source_turn_sequences=(1,),
        source_turn_digests=(digest("turn-1"),),
        p08_revision=1,
        p08_event_sequence=1,
        p08_event_kind="activate",
        previous_revision_digest="0" * 64,
    )
    started = TemporalIntervalRevision(
        interval_id=planned.interval_id,
        revision=2,
        state="confirmed_started",
        statement="Cealana已确认在上海旅行。",
        conflict_key=planned.conflict_key,
        start=endpoint("exact", START),
        end=endpoint("open"),
        source_turn_sequences=(1, 2),
        source_turn_digests=(digest("turn-1"), digest("turn-2")),
        p08_revision=2,
        p08_event_sequence=2,
        p08_event_kind="confirm",
        previous_revision_digest=planned.revision_digest,
    )
    ended = TemporalIntervalRevision(
        interval_id=planned.interval_id,
        revision=3,
        state="ended",
        statement="Cealana在上海的旅行于2026-08-03结束。",
        conflict_key=planned.conflict_key,
        start=endpoint("exact", START),
        end=endpoint("exact", END),
        source_turn_sequences=(1, 2, 3),
        source_turn_digests=(digest("turn-1"), digest("turn-2"), digest("turn-3")),
        p08_revision=3,
        p08_event_sequence=17,
        p08_event_kind="expire",
        previous_revision_digest=started.revision_digest,
    )
    return planned, started, ended


def receipt_for_binding(binding):
    trusted_time = {
        "authority": binding.authority,
        "boot_id": binding.boot_id,
        "instant": binding.sample_instant_utc.isoformat(timespec="microseconds"),
        "monotonic_ns": binding.sample_monotonic_ns,
        "sequence": binding.sequence,
        "source": binding.source,
        "source_class": binding.source_class,
        "synchronized": binding.synchronized,
        "uncertainty_microseconds": binding.uncertainty_microseconds,
    }
    return build_active_snapshot_receipt(
        request_id="synthetic-resident-snapshot",
        after_event_sequence=0,
        fact_count=0,
        lifecycle_transitions=(),
        lifecycle_watermark=0,
        lifecycle_has_more=False,
        trusted_time=trusted_time,
    )


class TemporalValiditySeamTests(unittest.TestCase):
    def resident_projection(
        self,
        episodes: tuple[TemporalIntervalEpisode, ...],
        *,
        instant: datetime,
        source_complete: bool = True,
        receipt_binding=None,
        token_counter=lambda fragments: sum(
            len(value.encode("utf-8")) for value in fragments
        ),
    ):
        binding = make_turn(
            1,
            "0" * 64,
            instant=instant - timedelta(seconds=1),
        ).draft.time_binding
        return project_resident_temporal_items(
            episodes,
            source_snapshot_digest=digest("temporal-snapshot"),
            source_complete=source_complete,
            trusted_time_binding=binding,
            active_snapshot_receipt=receipt_for_binding(
                binding if receipt_binding is None else receipt_binding
            ),
            maximum_characters=10_000,
            maximum_serialized_bytes=40_000,
            maximum_tokens=40_000,
            token_counter=token_counter,
        )

    def test_planned_started_ended_chain_becomes_long_term_interval_episode(self) -> None:
        planned, started, ended = revisions()
        episode = TemporalIntervalEpisode.create((planned, started, ended))
        self.assertEqual(episode.terminal_state, "ended")
        self.assertTrue(episode.raw_hydration_required)
        self.assertEqual(recall_interval_episodes("上海", (episode,)), (episode,))
        self.assertEqual(ended.end.instant_utc, END)
        self.assertEqual((ended.p08_event_sequence, ended.p08_revision), (17, 3))

    def test_p08_source_values_require_exact_types_and_terminal_pairing(self) -> None:
        planned, _, ended = revisions()
        for name, source, changes, code in (
            (
                "sequence_bool",
                planned,
                {"p08_event_sequence": True},
                "p08_event_sequence_invalid",
            ),
            (
                "kind_subclass_or_unknown",
                planned,
                {"p08_event_kind": "unknown"},
                "p08_event_kind_invalid",
            ),
            (
                "terminal_kind_substitution",
                ended,
                {"p08_event_kind": "revoke"},
                "p08_terminal_event_kind_mismatch",
            ),
        ):
            with self.subTest(name=name), self.assertRaisesRegex(
                EpisodicMemoryError, code
            ):
                replace(source, **changes)

    def test_plan_cannot_claim_observed_started_state(self) -> None:
        planned, _, _ = revisions()
        with self.assertRaisesRegex(EpisodicMemoryError, "plan_claims_started"):
            TemporalIntervalRevision(
                interval_id="invalid-plan",
                revision=1,
                state="planned",
                statement="Cealana正在上海旅行。",
                conflict_key="owner_location",
                start=planned.start,
                end=planned.end,
                source_turn_sequences=(1,),
                source_turn_digests=(digest("turn"),),
                p08_revision=1,
                p08_event_sequence=1,
                p08_event_kind="activate",
                previous_revision_digest="0" * 64,
            )

    def test_all_active_nonconflicting_items_are_always_on_or_whole_layer_overflows(self) -> None:
        planned, started, _ = revisions()
        other = TemporalIntervalRevision(
            interval_id="camera-course",
            revision=1,
            state="observed",
            statement="Cealana当前有摄影课程。",
            conflict_key="owner_course",
            start=endpoint("exact", START),
            end=endpoint("open"),
            source_turn_sequences=(4,),
            source_turn_digests=(digest("turn-4"),),
            p08_revision=4,
            p08_event_sequence=4,
            p08_event_kind="activate",
            previous_revision_digest="0" * 64,
        )
        projection = project_all_active_temporal_items(
            (started, other),
            maximum_characters=10_000,
            maximum_serialized_bytes=20_000,
            maximum_tokens=10_000,
            token_counter=lambda fragments: sum(len(value) for value in fragments),
        )
        self.assertTrue(projection.occupancy.fit)
        self.assertEqual(len(projection.fragments), 2)
        overflow = project_all_active_temporal_items(
            (started, other),
            maximum_characters=10,
            maximum_serialized_bytes=20_000,
            maximum_tokens=10_000,
            token_counter=lambda fragments: sum(len(value) for value in fragments),
        )
        self.assertFalse(overflow.occupancy.fit)
        self.assertEqual(overflow.fragments, ())
        self.assertEqual(overflow.occupancy.item_count, 2)

    def test_source_conflict_fails_closed_and_items_are_preserved(self) -> None:
        planned, started, _ = revisions()
        with self.assertRaisesRegex(EpisodicMemoryError, "source_conflict"):
            project_all_active_temporal_items(
                (planned, started),
                maximum_characters=10_000,
                maximum_serialized_bytes=20_000,
                maximum_tokens=10_000,
                token_counter=lambda fragments: 1,
            )

    def test_open_cancelled_and_timezone_boundary_contracts(self) -> None:
        planned, _, _ = revisions()
        cancelled = TemporalIntervalRevision(
            interval_id=planned.interval_id,
            revision=2,
            state="cancelled",
            statement="Cealana取消了上海旅行计划。",
            conflict_key=planned.conflict_key,
            start=planned.start,
            end=endpoint("unknown"),
            source_turn_sequences=(1, 2),
            source_turn_digests=(digest("turn-1"), digest("turn-2")),
            p08_revision=2,
            p08_event_sequence=2,
            p08_event_kind="revoke",
            previous_revision_digest=planned.revision_digest,
        )
        self.assertEqual(
            TemporalIntervalEpisode.create((planned, cancelled)).terminal_state,
            "cancelled",
        )
        los_angeles_end = TemporalEndpoint(
            kind="exact",
            calendar_zone="America/Los_Angeles",
            trusted_time_binding_digest=digest("la-time"),
            uncertainty_microseconds=1_000,
            instant_utc=END,
        )
        with self.assertRaisesRegex(EpisodicMemoryError, "zone_mismatch"):
            TemporalIntervalRevision(
                interval_id="mixed-zone",
                revision=1,
                state="ended",
                statement="Synthetic ended interval.",
                conflict_key="synthetic",
                start=planned.start,
                end=los_angeles_end,
                source_turn_sequences=(1,),
                source_turn_digests=(digest("turn"),),
                p08_revision=1,
                p08_event_sequence=1,
                p08_event_kind="expire",
                previous_revision_digest="0" * 64,
            )

    def test_ownership_and_profile_boundary_are_explicit(self) -> None:
        self.assertEqual(TEMPORAL_VALIDITY_OWNERSHIP["active_interval_store_and_expiry"], "P08")
        self.assertEqual(TEMPORAL_VALIDITY_OWNERSHIP["trusted_time_provider"], "P10-B")
        self.assertEqual(
            SEMANTIC_WRITE_BOUNDARY["stable_profile_fact"],
            "proposal_confirmation_required",
        )
        self.assertNotIn("effective", " ".join(TEMPORAL_VALIDITY_OWNERSHIP))

    def test_unresolved_time_cannot_drive_p08_expiry_or_interval_mutation(self) -> None:
        unresolved = unresolved_turn_time(
            reason_code="trusted_time_unavailable",
            received_monotonic_ns=1,
            committed_monotonic_ns=2,
            delivered_monotonic_ns=3,
        )
        with self.assertRaisesRegex(EpisodicMemoryError, "temporal_mutation_time_unresolved"):
            require_exact_time_for_temporal_mutation(unresolved)

    def test_resident_states_and_exact_boundaries_are_deterministic(self) -> None:
        states = ("planned", "observed", "confirmed_started", "changed")
        episodes = []
        for index, state in enumerate(states, start=1):
            revision = TemporalIntervalRevision(
                interval_id=f"resident-{state}",
                revision=1,
                state=state,
                statement=f"Synthetic {state} temporal item.",
                conflict_key=f"resident_slot_{index}",
                start=endpoint("exact", START),
                end=endpoint("exact", END),
                source_turn_sequences=(index,),
                source_turn_digests=(digest(f"resident-turn-{index}"),),
                p08_revision=index,
                p08_event_sequence=index,
                p08_event_kind="refresh" if state == "changed" else "activate",
                previous_revision_digest="0" * 64,
            )
            episodes.append(TemporalIntervalEpisode.create((revision,)))
        at_start = self.resident_projection(tuple(episodes), instant=START)
        self.assertEqual(at_start.state, "available")
        self.assertEqual(at_start.occupancy.item_count, 4)
        self.assertEqual(len(at_start.fragments), 4)
        before_end = self.resident_projection(
            tuple(episodes),
            instant=END - timedelta(seconds=2),
        )
        self.assertEqual(before_end.state, "available")
        at_end = self.resident_projection(tuple(episodes), instant=END)
        self.assertEqual(at_end.state, "available_empty")
        self.assertEqual(at_end.fragments, ())

    def test_resident_projection_rejects_substituted_trusted_binding(self) -> None:
        revision = TemporalIntervalRevision(
            interval_id="resident-receipt-binding",
            revision=1,
            state="planned",
            statement="Synthetic receipt-bound temporal item.",
            conflict_key="receipt_bound_slot",
            start=endpoint("exact", START),
            end=endpoint("exact", END),
            source_turn_sequences=(1,),
            source_turn_digests=(digest("receipt-bound-turn"),),
            p08_revision=1,
            p08_event_sequence=1,
            p08_event_kind="activate",
            previous_revision_digest="0" * 64,
        )
        original_binding = make_turn(
            1,
            "0" * 64,
            instant=START - timedelta(seconds=1),
        ).draft.time_binding
        changed_binding = make_turn(
            1,
            "0" * 64,
            instant=START - timedelta(seconds=2),
        ).draft.time_binding
        original = project_resident_temporal_items(
            (TemporalIntervalEpisode.create((revision,)),),
            source_snapshot_digest=digest("temporal-snapshot"),
            source_complete=True,
            trusted_time_binding=original_binding,
            active_snapshot_receipt=receipt_for_binding(original_binding),
            maximum_characters=10_000,
            maximum_serialized_bytes=40_000,
            maximum_tokens=40_000,
            token_counter=lambda fragments: 1,
        )
        substituted = project_resident_temporal_items(
            (TemporalIntervalEpisode.create((revision,)),),
            source_snapshot_digest=digest("temporal-snapshot"),
            source_complete=True,
            trusted_time_binding=changed_binding,
            active_snapshot_receipt=receipt_for_binding(original_binding),
            maximum_characters=10_000,
            maximum_serialized_bytes=40_000,
            maximum_tokens=40_000,
            token_counter=lambda fragments: 1,
        )
        self.assertEqual(original.state, "available")
        self.assertEqual(substituted.state, "conflict")
        self.assertEqual(substituted.reason_category, "source_receipt_conflict")
        self.assertEqual(substituted.fragments, ())

    def test_end_cancel_conflict_and_unavailable_never_emit_partial_text(self) -> None:
        planned, started, ended = revisions()
        ended_episode = TemporalIntervalEpisode.create((planned, started, ended))
        cancelled = TemporalIntervalRevision(
            interval_id="cancelled-resident",
            revision=1,
            state="cancelled",
            statement="Synthetic cancelled temporal item.",
            conflict_key="cancelled_slot",
            start=endpoint("exact", START),
            end=endpoint("unknown"),
            source_turn_sequences=(4,),
            source_turn_digests=(digest("cancelled-turn"),),
            p08_revision=4,
            p08_event_sequence=4,
            p08_event_kind="revoke",
            previous_revision_digest="0" * 64,
        )
        cancelled_episode = TemporalIntervalEpisode.create((cancelled,))
        before = (ended_episode.episode_digest, cancelled_episode.episode_digest)
        closed = self.resident_projection(
            (ended_episode, cancelled_episode),
            instant=START,
        )
        self.assertEqual(closed.state, "available_empty")
        self.assertEqual(
            before,
            (ended_episode.episode_digest, cancelled_episode.episode_digest),
        )
        unavailable = self.resident_projection((), instant=START, source_complete=False)
        self.assertEqual(unavailable.state, "unavailable")
        self.assertEqual(unavailable.reason_category, "source_incomplete")
        self.assertEqual(unavailable.fragments, ())
        no_oracle = self.resident_projection((), instant=START, token_counter=None)
        self.assertEqual(no_oracle.state, "unavailable")
        self.assertEqual(no_oracle.reason_category, "token_oracle_unavailable")

    def test_duplicate_conflict_key_rejects_the_whole_resident_layer(self) -> None:
        first = TemporalIntervalRevision(
            interval_id="resident-conflict-a",
            revision=1,
            state="observed",
            statement="Synthetic conflict A.",
            conflict_key="shared_slot",
            start=endpoint("exact", START),
            end=endpoint("exact", END),
            source_turn_sequences=(1,),
            source_turn_digests=(digest("conflict-a"),),
            p08_revision=1,
            p08_event_sequence=1,
            p08_event_kind="activate",
            previous_revision_digest="0" * 64,
        )
        second = TemporalIntervalRevision(
            interval_id="resident-conflict-b",
            revision=1,
            state="changed",
            statement="Synthetic conflict B.",
            conflict_key="shared_slot",
            start=endpoint("exact", START),
            end=endpoint("exact", END),
            source_turn_sequences=(2,),
            source_turn_digests=(digest("conflict-b"),),
            p08_revision=2,
            p08_event_sequence=2,
            p08_event_kind="refresh",
            previous_revision_digest="0" * 64,
        )
        projection = self.resident_projection(
            (
                TemporalIntervalEpisode.create((first,)),
                TemporalIntervalEpisode.create((second,)),
            ),
            instant=START,
        )
        self.assertEqual(projection.state, "conflict")
        self.assertEqual(projection.fragments, ())


if __name__ == "__main__":
    unittest.main()
