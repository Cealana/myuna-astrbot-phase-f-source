from __future__ import annotations

from dataclasses import replace
import inspect
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from myuna_core.episodic_memory.contracts import ArchivedContent, EpisodicMemoryError
from myuna_core.episodic_memory.delivery import DeliveryJournal, DeliveryPreparation
from myuna_core.episodic_memory.store import LosslessArchiveStore
from tests.episodic_memory_fixtures import digest, make_turn


def preparation(index: int = 1) -> DeliveryPreparation:
    turn = make_turn(index, "0" * 64)
    return DeliveryPreparation(
        delivery_token=digest(f"delivery-token-{index}"),
        turn_id=turn.draft.turn_id,
        owner=turn.draft.owner,
        assistant=turn.draft.assistant,
        prompt_time_binding=turn.draft.time_binding,
        source_occurred_at_utc=turn.draft.time_binding.delivered_at_utc,
        committed_monotonic_ns=500,
        epoch_id="synthetic-memory-archive",
        release_set_id="b" * 64,
        request_digest=turn.draft.request_digest,
        response_digest=turn.draft.response_digest,
        expected_archive_turn_count=0,
        expected_archive_head_digest="0" * 64,
        provenance_categories=("authenticated_owner_private",),
        provenance_digest=digest(f"synthetic-provenance-{index}"),
    )


class DeliveryJournalTests(unittest.TestCase):
    def test_every_mutating_command_begins_before_integrity_reads(self) -> None:
        for name in (
            "append_complete_turn",
            "append_lifecycle",
            "append_time_correction",
            "prepare_delivery",
            "resolve_delivery",
        ):
            source = inspect.getsource(getattr(LosslessArchiveStore, name))
            self.assertGreaterEqual(source.find('execute("BEGIN IMMEDIATE")'), 0)
            self.assertLess(
                source.find('execute("BEGIN IMMEDIATE")'),
                source.find("self._verify_connection(connection)"),
            )

    def test_many_unresolved_and_out_of_order_resolution_share_one_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = LosslessArchiveStore(root / "archive.sqlite3")
            archive.initialize()
            journal = DeliveryJournal(archive)
            selected = tuple(preparation(index) for index in range(1, 34))
            selected = (
                replace(
                    selected[0],
                    expected_archive_turn_count=None,
                    expected_archive_head_digest=None,
                ),
                *selected[1:],
            )
            for item in selected:
                self.assertFalse(journal.prepare(item))
            self.assertEqual(len(journal.unresolved_preparations()), 33)
            later = journal.resolve(
                delivery_token=selected[-1].delivery_token,
                outcome="delivered",
                delivered_monotonic_ns=600,
                delivered_boot_id=selected[-1].prompt_time_binding.boot_id,
            )
            earlier = journal.resolve(
                delivery_token=selected[0].delivery_token,
                outcome="delivered",
                delivered_monotonic_ns=700,
                delivered_boot_id=selected[0].prompt_time_binding.boot_id,
            )
            self.assertEqual(later.complete_turn.draft.sequence, 1)
            self.assertEqual(earlier.complete_turn.draft.sequence, 2)
            self.assertEqual(later.complete_turn.draft.turn_id, selected[-1].turn_id)
            self.assertEqual(archive.turns(), (later.complete_turn, earlier.complete_turn))
            self.assertEqual(len(journal.unresolved_preparations()), 31)
            self.assertEqual(journal.recoverable(), ())
            before = archive.path.read_bytes()
            sidecar = archive.path.with_name(archive.path.name + "-journal")
            sidecar_before = sidecar.read_bytes()
            with self.assertRaisesRegex(
                EpisodicMemoryError,
                "delivery_preparation_stale_head",
            ):
                journal.prepare(preparation(34))
            self.assertEqual(archive.path.read_bytes(), before)
            self.assertEqual(sidecar.read_bytes(), sidecar_before)

    def test_cancel_is_non_erasing_and_late_delivered_is_stronger(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = LosslessArchiveStore(root / "archive.sqlite3")
            archive.initialize()
            journal = DeliveryJournal(archive)
            first = preparation()
            journal.prepare(first)
            cancelled = journal.resolve(
                delivery_token=first.delivery_token,
                outcome="cancelled",
                delivered_monotonic_ns=None,
            )
            self.assertEqual(cancelled.outcome, "cancelled")
            self.assertEqual(archive.metadata()["turn_count"], 0)
            delivered = journal.resolve(
                delivery_token=first.delivery_token,
                outcome="delivered",
                delivered_monotonic_ns=600,
                delivered_boot_id=first.prompt_time_binding.boot_id,
            )
            self.assertEqual(delivered.complete_turn.draft.sequence, 1)
            self.assertEqual(journal.metadata()["late_delivered_after_cancelled_count"], 1)
            with self.assertRaisesRegex(
                EpisodicMemoryError, "delivery_outcome_downgrade_rejected"
            ):
                journal.resolve(
                    delivery_token=first.delivery_token,
                    outcome="cancelled",
                    delivered_monotonic_ns=None,
                )

    def test_exact_replay_is_zero_mutation_and_substitution_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = LosslessArchiveStore(root / "archive.sqlite3")
            archive.initialize()
            journal = DeliveryJournal(archive)
            selected = preparation()
            self.assertFalse(journal.prepare(selected))
            preparation_bytes = archive.path.read_bytes()
            sidecar = archive.path.with_name(archive.path.name + "-journal")
            preparation_sidecar = sidecar.read_bytes()
            self.assertTrue(journal.prepare(selected))
            self.assertEqual(archive.path.read_bytes(), preparation_bytes)
            self.assertEqual(sidecar.read_bytes(), preparation_sidecar)
            with self.assertRaisesRegex(
                EpisodicMemoryError, "delivery_preparation_replay_conflict"
            ):
                journal.prepare(
                    replace(
                        selected,
                        owner=ArchivedContent("text", "substituted synthetic owner"),
                    )
                )
            self.assertEqual(archive.path.read_bytes(), preparation_bytes)
            self.assertEqual(sidecar.read_bytes(), preparation_sidecar)
            first = journal.resolve(
                delivery_token=selected.delivery_token,
                outcome="delivered",
                delivered_monotonic_ns=600,
                delivered_boot_id=selected.prompt_time_binding.boot_id,
            )
            before = archive.path.read_bytes()
            sidecar_before = sidecar.read_bytes()
            counts = journal.metadata()
            replay = journal.resolve(
                delivery_token=selected.delivery_token,
                outcome="delivered",
                delivered_monotonic_ns=None,
            )
            self.assertTrue(replay.replayed)
            self.assertEqual(replay.complete_turn, first.complete_turn)
            self.assertEqual(replay.delivered_monotonic_ns, 600)
            self.assertEqual(
                replay.delivered_boot_id,
                selected.prompt_time_binding.boot_id,
            )
            self.assertEqual(replay.delivery_ack_digest, first.delivery_ack_digest)
            self.assertEqual(journal.metadata(), counts)
            self.assertEqual(archive.path.read_bytes(), before)
            self.assertEqual(sidecar.read_bytes(), sidecar_before)
            with self.assertRaisesRegex(
                EpisodicMemoryError,
                "delivery_resolution_replay_conflict",
            ):
                journal.resolve(
                    delivery_token=selected.delivery_token,
                    outcome="delivered",
                    delivered_monotonic_ns=601,
                    delivered_boot_id=selected.prompt_time_binding.boot_id,
                )
            with self.assertRaisesRegex(
                EpisodicMemoryError,
                "delivery_resolution_replay_conflict",
            ):
                journal.resolve(
                    delivery_token=selected.delivery_token,
                    outcome="delivered",
                    delivered_monotonic_ns=600,
                    delivered_boot_id="substituted-boot",
                )
            self.assertEqual(archive.path.read_bytes(), before)
            self.assertEqual(sidecar.read_bytes(), sidecar_before)

    def test_serialized_mutating_verification_allows_two_writers_to_converge(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "archive.sqlite3"
            first_store = LosslessArchiveStore(path)
            first_store.initialize()
            second_store = LosslessArchiveStore(path)
            first_journal = DeliveryJournal(first_store)
            second_journal = DeliveryJournal(second_store)
            first = preparation(1)
            second = preparation(2)
            self.assertFalse(first_journal.prepare(first))
            self.assertFalse(first_journal.prepare(second))
            transaction_started = threading.Event()
            release_first = threading.Event()
            second_started = threading.Event()
            original_verify = first_store._verify_connection
            outcomes: dict[str, object] = {}

            def held_verify(connection):
                self.assertTrue(connection.in_transaction)
                transaction_started.set()
                self.assertTrue(release_first.wait(timeout=2.0))
                original_verify(connection)

            def resolve_first() -> None:
                outcomes["first"] = first_journal.resolve(
                    delivery_token=first.delivery_token,
                    outcome="delivered",
                    delivered_monotonic_ns=600,
                    delivered_boot_id=first.prompt_time_binding.boot_id,
                )

            def resolve_second() -> None:
                second_started.set()
                outcomes["second"] = second_journal.resolve(
                    delivery_token=second.delivery_token,
                    outcome="delivered",
                    delivered_monotonic_ns=700,
                    delivered_boot_id=second.prompt_time_binding.boot_id,
                )

            with patch.object(first_store, "_verify_connection", side_effect=held_verify):
                first_thread = threading.Thread(target=resolve_first)
                second_thread = threading.Thread(target=resolve_second)
                first_thread.start()
                self.assertTrue(transaction_started.wait(timeout=2.0))
                second_thread.start()
                self.assertTrue(second_started.wait(timeout=2.0))
                release_first.set()
                first_thread.join(timeout=4.0)
                second_thread.join(timeout=4.0)
            self.assertFalse(first_thread.is_alive())
            self.assertFalse(second_thread.is_alive())
            self.assertEqual(set(outcomes), {"first", "second"})
            self.assertEqual(first_store.metadata()["turn_count"], 2)
            self.assertEqual(
                tuple(turn.draft.sequence for turn in first_store.turns()),
                (1, 2),
            )

    def test_resolution_crash_boundaries_converge_by_exact_replay(self) -> None:
        for stage in ("before_commit", "at_commit_boundary"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                archive = LosslessArchiveStore(Path(directory) / "archive.sqlite3")
                archive.initialize()
                journal = DeliveryJournal(archive)
                selected = preparation()
                journal.prepare(selected)
                with self.assertRaisesRegex(
                    EpisodicMemoryError, "delivery_resolution_crash_before_commit"
                ):
                    journal.resolve(
                        delivery_token=selected.delivery_token,
                        outcome="delivered",
                        delivered_monotonic_ns=600,
                        delivered_boot_id=selected.prompt_time_binding.boot_id,
                        crash_stage=stage,
                    )
                self.assertEqual(archive.metadata()["turn_count"], 0)
                self.assertFalse(
                    journal.resolve(
                        delivery_token=selected.delivery_token,
                        outcome="delivered",
                        delivered_monotonic_ns=600,
                        delivered_boot_id=selected.prompt_time_binding.boot_id,
                    ).replayed
                )
        with tempfile.TemporaryDirectory() as directory:
            archive = LosslessArchiveStore(Path(directory) / "archive.sqlite3")
            archive.initialize()
            journal = DeliveryJournal(archive)
            selected = preparation()
            journal.prepare(selected)
            with self.assertRaisesRegex(
                EpisodicMemoryError, "delivery_resolution_crash_after_commit"
            ):
                journal.resolve(
                    delivery_token=selected.delivery_token,
                    outcome="delivered",
                    delivered_monotonic_ns=600,
                    delivered_boot_id=selected.prompt_time_binding.boot_id,
                    crash_stage="after_commit_before_return",
                )
            replay = journal.resolve(
                delivery_token=selected.delivery_token,
                outcome="delivered",
                delivered_monotonic_ns=600,
                delivered_boot_id=selected.prompt_time_binding.boot_id,
            )
            self.assertTrue(replay.replayed)
            self.assertEqual(archive.metadata()["turn_count"], 1)

    def test_each_factual_command_opens_exactly_one_connection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = LosslessArchiveStore(Path(directory) / "archive.sqlite3")
            archive.initialize()
            journal = DeliveryJournal(archive)
            selected = preparation()
            from myuna_core.episodic_memory import store as store_module

            original = store_module.sqlite3.connect
            calls: list[object] = []

            def counted(*args, **kwargs):
                calls.append(args[0])
                return original(*args, **kwargs)

            with patch.object(store_module.sqlite3, "connect", side_effect=counted):
                journal.prepare(selected)
                self.assertEqual(len(calls), 1)
                journal.resolve(
                    delivery_token=selected.delivery_token,
                    outcome="delivered",
                    delivered_monotonic_ns=600,
                    delivered_boot_id=selected.prompt_time_binding.boot_id,
                )
                self.assertEqual(len(calls), 2)
                journal.resolve(
                    delivery_token=selected.delivery_token,
                    outcome="delivered",
                    delivered_monotonic_ns=600,
                )
                self.assertEqual(len(calls), 3)
                with self.assertRaisesRegex(EpisodicMemoryError, "delivery_token_unknown"):
                    journal.resolve(
                        delivery_token="f" * 64,
                        outcome="delivered",
                        delivered_monotonic_ns=700,
                    )
                self.assertEqual(len(calls), 4)


if __name__ == "__main__":
    unittest.main()
