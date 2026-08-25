from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from myuna_core.episodic_memory import (
    CompleteTurn,
    EpisodicMemoryError,
    TemporalIntervalIndexStore,
    advance_temporal_interval_index,
)
from myuna_core.episodic_memory.index import derive_snapshot
from myuna_core.active_temporal_context.protocol import build_active_snapshot_receipt
from tests.episodic_memory_fixtures import make_turn


NOW = datetime(2026, 8, 1, 2, tzinfo=timezone.utc)
_advance_temporal_interval_index = advance_temporal_interval_index


def _receipt(prior, transitions, observed_watermark, has_more):
    return build_active_snapshot_receipt(
        request_id="synthetic-interval-bridge",
        after_event_sequence=prior.after_event_sequence,
        fact_count=0,
        lifecycle_transitions=transitions,
        lifecycle_watermark=observed_watermark,
        lifecycle_has_more=has_more,
        trusted_time={
            "authority": "synthetic-authority",
            "boot_id": "synthetic-boot",
            "instant": "2026-08-01T02:00:00.000000+00:00",
            "monotonic_ns": 100,
            "sequence": 1,
            "source": "synthetic-source",
            "source_class": "synthetic",
            "synchronized": True,
            "uncertainty_microseconds": 1_000,
        },
    )


def advance_temporal_interval_index(
    prior,
    transitions,
    *,
    observed_watermark,
    has_more,
    archive_turns,
    archive_head_digest,
):
    return _advance_temporal_interval_index(
        prior,
        transitions,
        observed_watermark=observed_watermark,
        has_more=has_more,
        archive_turns=archive_turns,
        archive_head_digest=archive_head_digest,
        active_snapshot_receipt=_receipt(
            prior,
            transitions,
            observed_watermark,
            has_more,
        ),
    )


def temporal_turn(sequence: int, previous: str, event_id: str, command: str) -> CompleteTurn:
    base = make_turn(sequence, previous, owner=command, assistant="Synthetic accepted")
    draft = replace(
        base.draft,
        turn_id="turn-" + event_id,
        provenance_categories=("control_isolated", "control_temporal_isolated"),
    )
    return CompleteTurn.create(draft)


def transition(
    sequence: int,
    *,
    source_ref: str,
    movement: str = "proposed->active",
    state: str = "active",
    category: str = "temporary_plan",
    slot: str = "shanghai-trip",
    source_kind: str = "owner_statement",
    event_kind: str | None = None,
    revision: int | None = None,
    reason: str = "synthetic_reason",
    supersedes_fact_id: str | None = None,
) -> dict[str, object]:
    return {
        "category": category,
        "event_kind": event_kind or ("confirm" if sequence == 1 else "expire"),
        "event_sequence": sequence,
        "expires_at": "2026-08-03T16:00:00.000000+00:00",
        "fact_id": f"tf_synthetic_{sequence}",
        "occurred_at": NOW.isoformat(timespec="microseconds"),
        "reason": reason,
        "revision": sequence if revision is None else revision,
        "slot_key": slot,
        "source_kind": source_kind,
        "source_ref": source_ref,
        "state": state,
        "supersedes_fact_id": supersedes_fact_id,
        "transition": movement,
        "trusted_time_source_class": "synthetic",
        "valid_from": "2026-08-01T00:00:00.000000+00:00",
        "valid_to": "2026-08-03T16:00:00.000000+00:00",
    }


class TemporalIntervalBridgeTests(unittest.TestCase):
    def test_receipt_preserves_event_sequence_distinct_from_fact_revision(self) -> None:
        turn = temporal_turn(
            1,
            "0" * 64,
            "telegram-event-distinct-source-values",
            "/temporal add temporary_plan shanghai-trip 3 distinct source values",
        )
        initial = TemporalIntervalIndexStore(Path("unused")).read(
            archive_head_digest=turn.turn_digest,
            initial_event_sequence=16,
        )
        source = transition(
            17,
            source_ref="telegram-event-distinct-source-values",
            event_kind="confirm",
            revision=3,
        )
        selected = advance_temporal_interval_index(
            initial,
            (source,),
            observed_watermark=17,
            has_more=False,
            archive_turns=(turn,),
            archive_head_digest=turn.turn_digest,
        )
        revision = selected.episodes[0].revisions[0]
        self.assertEqual(revision.p08_event_sequence, 17)
        self.assertEqual(revision.p08_revision, 3)
        self.assertEqual(revision.p08_event_kind, "confirm")
        self.assertNotEqual(
            revision.revision_digest,
            replace(revision, p08_event_sequence=18).revision_digest,
        )

    def test_planned_interval_is_raw_bound_and_expiry_appends_revision(self) -> None:
        first = temporal_turn(
            1,
            "0" * 64,
            "telegram-event-1",
            "/temporal add temporary_plan shanghai-trip 3 Cealana计划去上海旅行",
        )
        initial = TemporalIntervalIndexStore(
            Path("unused")
        ).read(archive_head_digest=first.turn_digest)
        active = advance_temporal_interval_index(
            initial,
            (transition(1, source_ref="telegram-event-1"),),
            observed_watermark=1,
            has_more=False,
            archive_turns=(first,),
            archive_head_digest=first.turn_digest,
        )
        self.assertEqual(active.episodes[0].terminal_state, "planned")
        self.assertEqual(
            active.episodes[0].revisions[0].source_turn_digests,
            (first.turn_digest,),
        )
        ended_event = transition(
            2,
            source_ref="telegram-event-1",
            movement="active->expired",
            state="expired",
        )
        ended = advance_temporal_interval_index(
            active,
            (ended_event,),
            observed_watermark=2,
            has_more=False,
            archive_turns=(first,),
            archive_head_digest=first.turn_digest,
        )
        self.assertEqual(ended.episodes[0].terminal_state, "ended")
        self.assertEqual(len(ended.episodes[0].revisions), 2)
        self.assertTrue(ended.episodes[0].raw_hydration_required)

    def test_index_source_reference_binds_exact_temporal_revision_closure(self) -> None:
        turn = temporal_turn(
            1,
            "0" * 64,
            "telegram-event-index-source",
            "/temporal add temporary_plan shanghai-trip 3 synthetic plan",
        )
        initial = TemporalIntervalIndexStore(Path("unused")).read(
            archive_head_digest=turn.turn_digest
        )
        active = advance_temporal_interval_index(
            initial,
            (transition(1, source_ref="telegram-event-index-source"),),
            observed_watermark=1,
            has_more=False,
            archive_turns=(turn,),
            archive_head_digest=turn.turn_digest,
        )
        snapshot = derive_snapshot((turn,), temporal_snapshot=active)
        reference = snapshot.source_references[0]
        revision = active.episodes[0].revisions[0]
        self.assertEqual(reference.temporal_interval_ids, (revision.interval_id,))
        self.assertEqual(
            reference.temporal_revision_digests,
            (revision.revision_digest,),
        )
        self.assertEqual(
            reference.temporal_episode_digests,
            (active.episodes[0].episode_digest,),
        )
        drifted = temporal_turn(
            1,
            "0" * 64,
            "telegram-event-index-source",
            "/temporal add temporary_plan shanghai-trip 3 substituted plan",
        )
        with self.assertRaisesRegex(EpisodicMemoryError, "index_temporal_archive_conflict"):
            derive_snapshot((drifted,), temporal_snapshot=active)
        wrong_head = TemporalIntervalIndexStore(Path("unused")).read(
            archive_head_digest="0" * 64
        )
        with self.assertRaisesRegex(EpisodicMemoryError, "index_temporal_archive_conflict"):
            derive_snapshot((turn,), temporal_snapshot=wrong_head)

    def test_missing_source_blocks_interval_without_inventing_statement(self) -> None:
        initial = TemporalIntervalIndexStore(Path("unused")).read(
            archive_head_digest="0" * 64
        )
        selected = advance_temporal_interval_index(
            initial,
            (transition(1, source_ref="old-unmigrated-event"),),
            observed_watermark=1,
            has_more=False,
            archive_turns=(),
            archive_head_digest="0" * 64,
        )
        self.assertEqual(selected.episodes, ())
        self.assertEqual(selected.unresolved_event_sequences, (1,))
        self.assertEqual(len(selected.blocked_interval_ids), 1)

    def test_owner_confirmed_temporary_plan_is_confirmed_started(self) -> None:
        first = temporal_turn(
            1,
            "0" * 64,
            "telegram-event-confirmed",
            "/temporal add temporary_plan shanghai-trip 3 Cealana计划去上海旅行",
        )
        initial = TemporalIntervalIndexStore(Path("unused")).read(
            archive_head_digest=first.turn_digest
        )
        active = advance_temporal_interval_index(
            initial,
            (
                transition(
                    1,
                    source_ref="telegram-event-confirmed",
                    source_kind="owner_confirmation",
                ),
            ),
            observed_watermark=1,
            has_more=False,
            archive_turns=(first,),
            archive_head_digest=first.turn_digest,
        )
        self.assertEqual(active.episodes[0].terminal_state, "confirmed_started")

    def test_observed_changed_superseded_and_cancelled_semantics_remain_distinct(self) -> None:
        first = temporal_turn(
            1,
            "0" * 64,
            "telegram-event-lifecycle",
            "/temporal add current_status shanghai-trip 3 Synthetic observed state",
        )
        initial = TemporalIntervalIndexStore(Path("unused")).read(
            archive_head_digest=first.turn_digest
        )
        observed = advance_temporal_interval_index(
            initial,
            (
                transition(
                    1,
                    source_ref="telegram-event-lifecycle",
                    category="current_status",
                    event_kind="activate",
                    reason="owner_observed",
                ),
            ),
            observed_watermark=1,
            has_more=False,
            archive_turns=(first,),
            archive_head_digest=first.turn_digest,
        )
        self.assertEqual(observed.episodes[0].terminal_state, "observed")

        superseding = transition(
            2,
            source_ref="telegram-event-lifecycle",
            category="current_status",
            movement="active->superseded+active",
            state="active",
            event_kind="supersede",
            supersedes_fact_id="tf_synthetic_1",
        )
        self.assertEqual(superseding["transition"], "active->superseded+active")
        self.assertEqual(superseding["supersedes_fact_id"], "tf_synthetic_1")
        changed = advance_temporal_interval_index(
            observed,
            (superseding,),
            observed_watermark=2,
            has_more=False,
            archive_turns=(first,),
            archive_head_digest=first.turn_digest,
        )
        self.assertEqual(changed.episodes[0].terminal_state, "changed")

        cancelled = advance_temporal_interval_index(
            changed,
            (
                transition(
                    3,
                    source_ref="telegram-event-lifecycle",
                    category="current_status",
                    movement="active->revoked",
                    state="revoked",
                    event_kind="revoke",
                ),
            ),
            observed_watermark=3,
            has_more=False,
            archive_turns=(first,),
            archive_head_digest=first.turn_digest,
        )
        self.assertEqual(cancelled.episodes[0].terminal_state, "cancelled")

    def test_cursor_gap_replay_and_store_round_trip_fail_closed(self) -> None:
        first = temporal_turn(
            1,
            "0" * 64,
            "telegram-event-1",
            "/temporal add temporary_plan shanghai-trip 3 Synthetic trip",
        )
        initial = TemporalIntervalIndexStore(Path("unused")).read(
            archive_head_digest=first.turn_digest
        )
        with self.assertRaisesRegex(
            EpisodicMemoryError, "temporal_transition_sequence_drifted"
        ):
            advance_temporal_interval_index(
                initial,
                (transition(2, source_ref="telegram-event-1"),),
                observed_watermark=2,
                has_more=False,
                archive_turns=(first,),
                archive_head_digest=first.turn_digest,
            )
        selected = advance_temporal_interval_index(
            initial,
            (transition(1, source_ref="telegram-event-1"),),
            observed_watermark=1,
            has_more=False,
            archive_turns=(first,),
            archive_head_digest=first.turn_digest,
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = TemporalIntervalIndexStore(Path(temporary) / "intervals.json")
            store.write(selected)
            self.assertEqual(
                store.read(archive_head_digest=first.turn_digest),
                selected,
            )

            current_payload = json.loads(store.path.read_text(encoding="utf-8"))
            for name, mutate in {
                "v1_schema": lambda value: value.__setitem__(
                    "schema", "myuna.p07-temporal-interval-index.v1"
                ),
                "missing_event_sequence": lambda value: value["episodes"][0][
                    "revisions"
                ][0].pop("p08_event_sequence"),
            }.items():
                rejected = Path(temporary) / f"{name}.json"
                payload = json.loads(json.dumps(current_payload))
                mutate(payload)
                rejected.write_text(
                    json.dumps(payload, separators=(",", ":"), sort_keys=True),
                    encoding="utf-8",
                )
                with self.subTest(name=name), self.assertRaises(EpisodicMemoryError):
                    TemporalIntervalIndexStore(rejected).read(
                        archive_head_digest=first.turn_digest
                    )

    def test_source_receipt_rejects_lifecycle_field_substitution_before_advance(
        self,
    ) -> None:
        first = temporal_turn(
            1,
            "0" * 64,
            "telegram-event-receipt",
            "/temporal add temporary_plan shanghai-trip 3 Receipt bound trip",
        )
        initial = TemporalIntervalIndexStore(Path("unused")).read(
            archive_head_digest=first.turn_digest
        )
        original = transition(1, source_ref="telegram-event-receipt")
        receipt = _receipt(initial, (original,), 1, False)
        substitutions = {
            "event_kind": "expire",
            "event_sequence": 2,
            "revision": 999,
            "fact_id": "tf_substituted_fact",
            "slot_key": "substituted-slot",
            "source_ref": "substituted-source",
            "transition": "active->expired",
        }
        for field, value in substitutions.items():
            changed = dict(original)
            changed[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                EpisodicMemoryError,
                "temporal_active_snapshot_receipt_rejected",
            ):
                _advance_temporal_interval_index(
                    initial,
                    (changed,),
                    observed_watermark=1,
                    has_more=False,
                    archive_turns=(first,),
                    archive_head_digest=first.turn_digest,
                    active_snapshot_receipt=receipt,
                )
            self.assertEqual(initial.episodes, ())
            self.assertEqual(initial.after_event_sequence, 0)

        accepted = _advance_temporal_interval_index(
            initial,
            (original,),
            observed_watermark=1,
            has_more=False,
            archive_turns=(first,),
            archive_head_digest=first.turn_digest,
            active_snapshot_receipt=receipt,
        )
        self.assertEqual(accepted.episodes[0].revisions[0].p08_revision, 1)
        self.assertEqual(
            accepted.schema,
            "myuna.p07-temporal-interval-index.v2",
        )

        second = transition(
            2,
            source_ref="telegram-event-receipt",
            movement="active->expired",
            state="expired",
            event_kind="expire",
        )
        ordered_receipt = _receipt(initial, (original, second), 2, False)
        with self.assertRaisesRegex(
            EpisodicMemoryError,
            "temporal_active_snapshot_receipt_rejected",
        ):
            _advance_temporal_interval_index(
                initial,
                (second, original),
                observed_watermark=2,
                has_more=False,
                archive_turns=(first,),
                archive_head_digest=first.turn_digest,
                active_snapshot_receipt=ordered_receipt,
            )


if __name__ == "__main__":
    unittest.main()
