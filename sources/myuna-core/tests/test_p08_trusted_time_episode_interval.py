from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from zoneinfo import ZoneInfo

from myuna_core.episodic_memory.contracts import (
    ArchivedContent,
    EpisodicMemoryError,
    TurnTimeBinding,
    TurnTimeCorrection,
)
from myuna_core.episodic_memory.delivery import DeliveryJournal, DeliveryPreparation
from myuna_core.episodic_memory.owner_day import (
    OwnerDayPolicy,
    owner_day_interval,
)
from myuna_core.episodic_memory.store import LosslessArchiveStore
from myuna_core.episodic_memory import store as store_module
from myuna_core.episodic_memory.trusted_time import finalize_prompt_time_binding


RECEIVED_NS = 1_000_000_000
SAMPLE_NS = 2_000_000_000
COMMITTED_NS = 2_500_000_000
DELIVERED_NS = 3_000_000_000


def digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def exact_prompt(
    *,
    sample_instant: datetime | None = None,
    calendar_zone: str = "Asia/Shanghai",
) -> TurnTimeBinding:
    sample = sample_instant or datetime(2026, 8, 8, 12, tzinfo=timezone.utc)
    received = sample - timedelta(seconds=1)
    local = sample.astimezone(ZoneInfo(calendar_zone))
    offset = local.utcoffset()
    assert offset is not None
    return TurnTimeBinding(
        status="exact",
        calendar_zone=calendar_zone,
        received_monotonic_ns=RECEIVED_NS,
        committed_monotonic_ns=SAMPLE_NS,
        delivered_monotonic_ns=SAMPLE_NS,
        sample_instant_utc=sample,
        received_at_utc=received,
        committed_at_utc=sample,
        delivered_at_utc=sample,
        local_calendar_representation=local.isoformat(timespec="microseconds"),
        event_offset_minutes=int(offset.total_seconds() // 60),
        uncertainty_microseconds=1_000,
        synchronized=True,
        source="synthetic-trusted-time",
        source_class="synthetic",
        authority="synthetic-authority",
        boot_id="synthetic-boot",
        sequence=1,
        sample_monotonic_ns=SAMPLE_NS,
        quality_codes=("trusted_exact",),
    )


def preparation(
    index: int = 1,
    *,
    binding: TurnTimeBinding | None = None,
) -> DeliveryPreparation:
    selected = binding or exact_prompt()
    return DeliveryPreparation(
        delivery_token=digest(f"delivery-token-{index}"),
        turn_id=f"synthetic-p08-turn-{index}",
        owner=ArchivedContent("text", f"private synthetic owner {index}"),
        assistant=ArchivedContent("text", f"private synthetic assistant {index}"),
        prompt_time_binding=selected,
        source_occurred_at_utc=datetime(2026, 8, 8, 12, tzinfo=timezone.utc),
        committed_monotonic_ns=COMMITTED_NS,
        epoch_id="synthetic-memory-archive",
        release_set_id=digest("synthetic-release"),
        request_digest=digest(f"synthetic-request-{index}"),
        response_digest=digest(f"synthetic-response-{index}"),
        expected_archive_turn_count=None,
        expected_archive_head_digest=None,
        provenance_categories=("authenticated_owner_private",),
        provenance_digest=digest(f"synthetic-provenance-{index}"),
    )


class TrustedTimeEpisodeIntervalTests(unittest.TestCase):
    def open_journal(self, directory: str) -> tuple[LosslessArchiveStore, DeliveryJournal]:
        store = LosslessArchiveStore(Path(directory) / "archive.sqlite3")
        store.initialize()
        return store, DeliveryJournal(store)

    def test_open_cancel_and_stronger_late_delivery_have_stable_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, journal = self.open_journal(directory)
            selected = preparation()
            policy = OwnerDayPolicy()
            opened = journal.prepare_episode(selected, owner_day_policy=policy)
            self.assertFalse(opened.replayed)
            self.assertEqual(opened.episode.state, "OPEN_EXACT_START")
            self.assertIsNotNone(opened.episode.start_utc)
            self.assertIsNone(opened.episode.end_utc)
            self.assertNotIn(selected.owner.text, json.dumps(opened.episode.audit_projection()))
            replayed_open = journal.prepare_episode(selected, owner_day_policy=policy)
            self.assertTrue(replayed_open.replayed)
            self.assertEqual(replayed_open.episode, opened.episode)

            cancelled = journal.resolve(
                delivery_token=selected.delivery_token,
                outcome="cancelled",
                delivered_monotonic_ns=None,
                owner_day_policy=policy,
            )
            self.assertEqual(cancelled.episode.state, "CANCELLED_UNRESOLVED")
            self.assertEqual(cancelled.episode.episode_id, opened.episode.episode_id)
            self.assertFalse(cancelled.archived)
            late = journal.resolve(
                delivery_token=selected.delivery_token,
                outcome="delivered",
                delivered_monotonic_ns=DELIVERED_NS,
                delivered_boot_id=selected.prompt_time_binding.boot_id,
                owner_day_policy=policy,
            )
            self.assertEqual(late.episode.state, "CLOSED_EXACT")
            self.assertEqual(late.episode.episode_id, opened.episode.episode_id)
            self.assertEqual(late.episode.interval_duration_ns, 2_000_000_000)
            self.assertEqual(store.metadata()["turn_count"], 1)

    def test_missing_marker_never_samples_clock_and_preserves_unresolved_fact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, journal = self.open_journal(directory)
            selected = preparation()
            journal.prepare(selected)
            with patch("time.monotonic_ns", side_effect=AssertionError("clock forbidden")) as clock:
                resolved = journal.resolve(
                    delivery_token=selected.delivery_token,
                    outcome="delivered",
                    delivered_monotonic_ns=None,
                    owner_day_policy=OwnerDayPolicy(),
                )
            clock.assert_not_called()
            self.assertTrue(resolved.archived)
            self.assertIsNone(resolved.delivered_monotonic_ns)
            self.assertEqual(resolved.complete_turn.draft.time_binding.status, "unresolved")
            self.assertIn(
                "delivery_close_evidence_missing",
                resolved.complete_turn.draft.time_binding.quality_codes,
            )
            self.assertEqual(resolved.episode.state, "CLOSED_TIME_UNRESOLVED")
            self.assertIsNone(resolved.episode.end_utc)
            self.assertIsNone(resolved.episode.interval_duration_ns)
            self.assertIsNone(resolved.episode.owner_day)
            self.assertEqual(store.metadata()["turn_count"], 1)

    def test_callback_boot_identity_is_bound_and_cross_boot_stays_unresolved(self) -> None:
        cases = (
            (None, "delivery_boot_continuity_unproven"),
            ("synthetic-new-boot", "delivery_callback_boot_identity_mismatched"),
            ("malformed boot identity", "delivery_callback_boot_identity_malformed"),
        )
        for index, (callback_boot_id, reason) in enumerate(cases, start=1):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as directory:
                store, journal = self.open_journal(directory)
                selected = preparation(index)
                journal.prepare(selected)
                first = journal.resolve(
                    delivery_token=selected.delivery_token,
                    outcome="delivered",
                    delivered_monotonic_ns=DELIVERED_NS,
                    delivered_boot_id=callback_boot_id,
                    owner_day_policy=OwnerDayPolicy(),
                )
                self.assertEqual(first.delivered_monotonic_ns, DELIVERED_NS)
                self.assertEqual(first.delivered_boot_id, callback_boot_id)
                self.assertEqual(first.episode.state, "CLOSED_TIME_UNRESOLVED")
                self.assertIn(
                    reason,
                    first.complete_turn.draft.time_binding.quality_codes,
                )
                self.assertIsNone(first.episode.end_utc)
                self.assertIsNone(first.episode.owner_day)
                sidecar = store.path.with_name(store.path.name + "-journal")
                before = (store.path.read_bytes(), sidecar.read_bytes(), store.metadata())
                replay = journal.resolve(
                    delivery_token=selected.delivery_token,
                    outcome="delivered",
                    delivered_monotonic_ns=None,
                    delivered_boot_id=None,
                    owner_day_policy=OwnerDayPolicy(),
                )
                self.assertTrue(replay.replayed)
                self.assertEqual(replay.delivered_monotonic_ns, DELIVERED_NS)
                self.assertEqual(replay.delivered_boot_id, callback_boot_id)
                self.assertEqual(replay.complete_turn, first.complete_turn)
                self.assertEqual(replay.episode, first.episode)
                self.assertEqual(
                    (store.path.read_bytes(), sidecar.read_bytes(), store.metadata()),
                    before,
                )
                with self.assertRaisesRegex(
                    EpisodicMemoryError, "delivery_resolution_replay_conflict"
                ):
                    journal.resolve(
                        delivery_token=selected.delivery_token,
                        outcome="delivered",
                        delivered_monotonic_ns=DELIVERED_NS,
                        delivered_boot_id="substituted-boot",
                    )
                self.assertEqual(
                    (store.path.read_bytes(), sidecar.read_bytes(), store.metadata()),
                    before,
                )

    def test_exact_and_unresolved_replay_are_zero_mutation_and_substitution_rejects(self) -> None:
        for marker in (DELIVERED_NS, None):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as directory:
                store, journal = self.open_journal(directory)
                selected = preparation()
                journal.prepare(selected)
                first = journal.resolve(
                    delivery_token=selected.delivery_token,
                    outcome="delivered",
                    delivered_monotonic_ns=marker,
                    delivered_boot_id=(
                        selected.prompt_time_binding.boot_id
                        if marker is not None
                        else None
                    ),
                )
                sidecar = store.path.with_name(store.path.name + "-journal")
                before = (store.path.read_bytes(), sidecar.read_bytes(), store.metadata())
                replay = journal.resolve(
                    delivery_token=selected.delivery_token,
                    outcome="delivered",
                    delivered_monotonic_ns=None,
                )
                self.assertTrue(replay.replayed)
                self.assertEqual(
                    replay.delivered_boot_id,
                    selected.prompt_time_binding.boot_id
                    if marker is not None
                    else None,
                )
                self.assertEqual(replay.episode, first.episode)
                self.assertEqual(replay.delivery_ack_digest, first.delivery_ack_digest)
                self.assertEqual(
                    (store.path.read_bytes(), sidecar.read_bytes(), store.metadata()),
                    before,
                )
                conflicting = DELIVERED_NS + 1 if marker is not None else DELIVERED_NS
                with self.assertRaisesRegex(
                    EpisodicMemoryError, "delivery_resolution_replay_conflict"
                ):
                    journal.resolve(
                        delivery_token=selected.delivery_token,
                        outcome="delivered",
                        delivered_monotonic_ns=conflicting,
                    )
                if marker is not None:
                    with self.assertRaisesRegex(
                        EpisodicMemoryError, "delivery_resolution_replay_conflict"
                    ):
                        journal.resolve(
                            delivery_token=selected.delivery_token,
                            outcome="delivered",
                            delivered_monotonic_ns=marker,
                            delivered_boot_id="substituted-boot",
                        )

    def test_regression_and_duration_overflow_preserve_raw_as_unresolved(self) -> None:
        cases = (
            (COMMITTED_NS - 1, "delivery_close_monotonic_regression"),
            (
                RECEIVED_NS + 181 * 1_000_000_000,
                "delivery_close_duration_out_of_contract",
            ),
        )
        for index, (marker, reason) in enumerate(cases, start=1):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as directory:
                store, journal = self.open_journal(directory)
                selected = preparation(index)
                journal.prepare(selected)
                resolved = journal.resolve(
                    delivery_token=selected.delivery_token,
                    outcome="delivered",
                    delivered_monotonic_ns=marker,
                    delivered_boot_id=selected.prompt_time_binding.boot_id,
                )
                self.assertEqual(resolved.episode.state, "CLOSED_TIME_UNRESOLVED")
                self.assertEqual(resolved.delivered_monotonic_ns, marker)
                self.assertIn(reason, resolved.complete_turn.draft.time_binding.quality_codes)
                self.assertEqual(store.metadata()["turn_count"], 1)

    def test_append_only_correction_changes_projection_not_historical_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, journal = self.open_journal(directory)
            selected = preparation()
            journal.prepare(selected)
            unresolved = journal.resolve(
                delivery_token=selected.delivery_token,
                outcome="delivered",
                delivered_monotonic_ns=None,
                owner_day_policy=OwnerDayPolicy(),
            )
            corrected_binding = finalize_prompt_time_binding(
                selected.prompt_time_binding,
                committed_monotonic_ns=COMMITTED_NS,
                delivered_monotonic_ns=DELIVERED_NS,
            )
            correction = TurnTimeCorrection(
                correction_id="synthetic-p08-correction-1",
                turn_id=selected.turn_id,
                turn_digest=unresolved.complete_turn.turn_digest,
                original_binding_digest=(
                    unresolved.complete_turn.draft.time_binding.binding_digest
                ),
                corrected_binding=corrected_binding,
                reason_code="explicit_late_time_evidence",
                created_at_utc=datetime(2026, 8, 8, 13, tzinfo=timezone.utc),
                provenance_digest=digest("synthetic-correction-provenance"),
            )
            self.assertEqual(store.append_time_correction(correction), correction.correction_digest)
            self.assertEqual(store.append_time_correction(correction), correction.correction_digest)
            before_replay = (store.path.read_bytes(), store.metadata())
            corrected = journal.resolve(
                delivery_token=selected.delivery_token,
                outcome="delivered",
                delivered_monotonic_ns=None,
                owner_day_policy=OwnerDayPolicy(),
            )
            self.assertTrue(corrected.replayed)
            self.assertEqual(corrected.episode.state, "CLOSED_EXACT")
            self.assertEqual(corrected.episode.episode_id, unresolved.episode.episode_id)
            self.assertEqual(corrected.complete_turn.turn_digest, unresolved.complete_turn.turn_digest)
            self.assertEqual(corrected.delivery_ack_digest, unresolved.delivery_ack_digest)
            self.assertEqual(corrected.episode.correction_digests, (correction.correction_digest,))
            self.assertNotEqual(
                corrected.episode.projection_digest, unresolved.episode.projection_digest
            )
            self.assertEqual((store.path.read_bytes(), store.metadata()), before_replay)

    def test_conflicting_corrections_fail_closed_without_rewriting_original_turn(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, journal = self.open_journal(directory)
            selected = preparation()
            journal.prepare(selected)
            unresolved = journal.resolve(
                delivery_token=selected.delivery_token,
                outcome="delivered",
                delivered_monotonic_ns=None,
            )
            original = unresolved.complete_turn.draft.time_binding
            first_binding = finalize_prompt_time_binding(
                selected.prompt_time_binding,
                committed_monotonic_ns=COMMITTED_NS,
                delivered_monotonic_ns=DELIVERED_NS,
            )
            second_binding = finalize_prompt_time_binding(
                selected.prompt_time_binding,
                committed_monotonic_ns=COMMITTED_NS,
                delivered_monotonic_ns=DELIVERED_NS + 1_000_000_000,
            )
            for index, binding in enumerate((first_binding, second_binding), start=1):
                store.append_time_correction(
                    TurnTimeCorrection(
                        correction_id=f"synthetic-conflicting-correction-{index}",
                        turn_id=selected.turn_id,
                        turn_digest=unresolved.complete_turn.turn_digest,
                        original_binding_digest=original.binding_digest,
                        corrected_binding=binding,
                        reason_code="synthetic_conflict",
                        created_at_utc=datetime(2026, 8, 8, 13, index, tzinfo=timezone.utc),
                        provenance_digest=digest(f"conflict-provenance-{index}"),
                    )
                )
            turn_before = store.turns()[0]
            with self.assertRaisesRegex(
                EpisodicMemoryError, "delivery_episode_correction_conflicted"
            ):
                journal.resolve(
                    delivery_token=selected.delivery_token,
                    outcome="delivered",
                    delivered_monotonic_ns=None,
                )
            self.assertEqual(store.turns()[0], turn_before)

    def test_crash_replay_and_two_writer_serialization_preserve_episode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, journal = self.open_journal(directory)
            selected = preparation()
            with self.assertRaisesRegex(
                EpisodicMemoryError, "delivery_prepare_crash_before_commit"
            ):
                store.prepare_delivery_episode(
                    selected,
                    crash_stage="before_commit",
                )
            self.assertEqual(journal.unresolved_preparations(), ())
            with self.assertRaisesRegex(
                EpisodicMemoryError, "delivery_prepare_crash_after_commit"
            ):
                store.prepare_delivery_episode(
                    selected,
                    crash_stage="after_commit_before_return",
                )
            opened = journal.prepare_episode(selected)
            self.assertTrue(opened.replayed)
            self.assertEqual(opened.episode.state, "OPEN_EXACT_START")

            with self.assertRaisesRegex(
                EpisodicMemoryError, "delivery_resolution_crash_before_commit"
            ):
                journal.resolve(
                    delivery_token=selected.delivery_token,
                    outcome="delivered",
                    delivered_monotonic_ns=None,
                    crash_stage="before_commit",
                )
            self.assertEqual(store.metadata()["turn_count"], 0)
            self.assertEqual(len(journal.unresolved_preparations()), 1)

        with tempfile.TemporaryDirectory() as directory:
            store, journal = self.open_journal(directory)
            selected = preparation()
            journal.prepare(selected)
            with self.assertRaisesRegex(
                EpisodicMemoryError, "delivery_resolution_crash_after_commit"
            ):
                journal.resolve(
                    delivery_token=selected.delivery_token,
                    outcome="delivered",
                    delivered_monotonic_ns=None,
                    crash_stage="after_commit_before_return",
                )
            replay = journal.resolve(
                delivery_token=selected.delivery_token,
                outcome="delivered",
                delivered_monotonic_ns=None,
            )
            self.assertTrue(replay.replayed)
            self.assertEqual(replay.episode.state, "CLOSED_TIME_UNRESOLVED")
            self.assertEqual(store.metadata()["turn_count"], 1)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "archive.sqlite3"
            first_store = LosslessArchiveStore(path)
            first_store.initialize()
            second_store = LosslessArchiveStore(path)
            first = DeliveryJournal(first_store)
            second = DeliveryJournal(second_store)
            selected = preparation()
            first.prepare(selected)
            results: list[object] = []

            def close(journal: DeliveryJournal) -> None:
                results.append(
                    journal.resolve(
                        delivery_token=selected.delivery_token,
                        outcome="delivered",
                        delivered_monotonic_ns=DELIVERED_NS,
                        delivered_boot_id=selected.prompt_time_binding.boot_id,
                    )
                )

            threads = (threading.Thread(target=close, args=(first,)), threading.Thread(target=close, args=(second,)))
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
            self.assertEqual(len(results), 2)
            self.assertEqual({result.episode.episode_id for result in results}, {results[0].episode.episode_id})
            self.assertEqual(first_store.metadata()["turn_count"], 1)

    def test_closed_descriptor_number_reuse_does_not_impersonate_old_connection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "archive.sqlite3"
            replacement = root / "replacement.bin"
            archive.write_bytes(b"archive")
            replacement.write_bytes(b"replacement")
            descriptor = os.open(archive, os.O_RDONLY)
            reopened: list[int] = []

            class CloseAndReuse:
                def close(self) -> None:
                    os.close(descriptor)
                    reopened.append(os.open(replacement, os.O_RDONLY))

            try:
                store_module._close_connection(CloseAndReuse(), descriptor)
                self.assertEqual(reopened, [descriptor])
            finally:
                for selected in reopened:
                    os.close(selected)

            same_inode_descriptor = os.open(archive, os.O_RDONLY)
            same_inode_reopened: list[int] = []

            class CloseAndReuseSameInode:
                def close(self) -> None:
                    os.close(same_inode_descriptor)
                    same_inode_reopened.append(os.open(archive, os.O_RDONLY))

            try:
                store_module._close_connection(
                    CloseAndReuseSameInode(), same_inode_descriptor
                )
                self.assertEqual(same_inode_reopened, [same_inode_descriptor])
            finally:
                for selected in same_inode_reopened:
                    os.close(selected)

            leaked = os.open(archive, os.O_RDONLY)

            class DoesNotClose:
                @staticmethod
                def close() -> None:
                    return None

            try:
                with self.assertRaisesRegex(
                    EpisodicMemoryError,
                    "archive_connection_close_unconfirmed",
                ):
                    store_module._close_connection(DoesNotClose(), leaked)
            finally:
                os.close(leaked)

            close_exception_descriptor = os.open(archive, os.O_RDONLY)

            class CloseRaises:
                @staticmethod
                def close() -> None:
                    raise RuntimeError("synthetic close failure")

            try:
                with self.assertRaisesRegex(
                    EpisodicMemoryError,
                    "archive_connection_close_unconfirmed",
                ):
                    store_module._close_connection(
                        CloseRaises(), close_exception_descriptor
                    )
            finally:
                os.close(close_exception_descriptor)

            identity = store_module._regular_identity(archive)
            descriptor_a = os.open(archive, os.O_RDONLY)
            descriptor_b = os.open(archive, os.O_RDONLY)
            try:
                with self.assertRaisesRegex(
                    EpisodicMemoryError, "archive_connection_identity_ambiguous"
                ):
                    store_module._new_connection_descriptor(
                        {},
                        {
                            descriptor_a: identity,
                            descriptor_b: identity,
                        },
                        identity,
                    )
                with self.assertRaisesRegex(
                    EpisodicMemoryError, "archive_connection_identity_ambiguous"
                ):
                    store_module._new_connection_descriptor({}, {}, identity)
            finally:
                os.close(descriptor_a)
                os.close(descriptor_b)

    def test_owner_day_correction_changes_only_effective_projection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, journal = self.open_journal(directory)
            selected = preparation(
                binding=exact_prompt(
                    sample_instant=datetime(2026, 8, 8, 21, tzinfo=timezone.utc)
                )
            )
            policy = OwnerDayPolicy()
            journal.prepare_episode(selected, owner_day_policy=policy)
            first = journal.resolve(
                delivery_token=selected.delivery_token,
                outcome="delivered",
                delivered_monotonic_ns=DELIVERED_NS,
                delivered_boot_id=selected.prompt_time_binding.boot_id,
                owner_day_policy=policy,
            )
            self.assertEqual(first.episode.owner_day.isoformat(), "2026-08-08")
            original = first.complete_turn.draft.time_binding
            shift = timedelta(hours=2)
            corrected_delivered = original.delivered_at_utc + shift
            corrected = replace(
                original,
                sample_instant_utc=original.sample_instant_utc + shift,
                received_at_utc=original.received_at_utc + shift,
                committed_at_utc=original.committed_at_utc + shift,
                delivered_at_utc=corrected_delivered,
                local_calendar_representation=corrected_delivered.astimezone(
                    ZoneInfo(original.calendar_zone)
                ).isoformat(timespec="microseconds"),
            )
            correction = TurnTimeCorrection(
                correction_id="synthetic-owner-day-correction",
                turn_id=selected.turn_id,
                turn_digest=first.complete_turn.turn_digest,
                original_binding_digest=original.binding_digest,
                corrected_binding=corrected,
                reason_code="explicit_owner_day_correction",
                created_at_utc=datetime(2026, 8, 9, 1, tzinfo=timezone.utc),
                provenance_digest=digest("owner-day-correction-provenance"),
            )
            store.append_time_correction(correction)
            before_replay = (store.path.read_bytes(), store.metadata())
            replay = journal.resolve(
                delivery_token=selected.delivery_token,
                outcome="delivered",
                delivered_monotonic_ns=None,
                owner_day_policy=policy,
            )
            self.assertTrue(replay.replayed)
            self.assertEqual(first.episode.owner_day.isoformat(), "2026-08-08")
            self.assertEqual(replay.episode.owner_day.isoformat(), "2026-08-09")
            self.assertEqual(replay.episode.episode_id, first.episode.episode_id)
            self.assertEqual(
                replay.complete_turn.turn_digest,
                first.complete_turn.turn_digest,
            )
            self.assertEqual(
                replay.episode.correction_digests,
                (correction.correction_digest,),
            )
            self.assertEqual((store.path.read_bytes(), store.metadata()), before_replay)

    def test_owner_day_boundary_cross_midnight_and_dst_ambiguity_are_exact(self) -> None:
        boundary_sample = datetime(2026, 8, 8, 21, 59, 59, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            _, journal = self.open_journal(directory)
            selected = preparation(binding=exact_prompt(sample_instant=boundary_sample))
            policy = OwnerDayPolicy()
            journal.prepare_episode(selected, owner_day_policy=policy)
            closed = journal.resolve(
                delivery_token=selected.delivery_token,
                outcome="delivered",
                delivered_monotonic_ns=DELIVERED_NS,
                delivered_boot_id=selected.prompt_time_binding.boot_id,
                owner_day_policy=policy,
            )
            self.assertEqual(closed.episode.owner_day.isoformat(), "2026-08-09")
            self.assertLess(closed.episode.start_utc, closed.episode.end_utc)

        with self.assertRaisesRegex(
            EpisodicMemoryError, "owner_day_boundary_nonexistent"
        ):
            owner_day_interval(
                datetime(2026, 3, 8).date(),
                OwnerDayPolicy(
                    calendar_zone="America/Los_Angeles",
                    boundary_local_time="02:30",
                ),
            )
        with self.assertRaisesRegex(
            EpisodicMemoryError, "owner_day_boundary_ambiguous"
        ):
            owner_day_interval(
                datetime(2026, 11, 1).date(),
                OwnerDayPolicy(
                    calendar_zone="America/Los_Angeles",
                    boundary_local_time="01:30",
                ),
            )


if __name__ == "__main__":
    unittest.main()
