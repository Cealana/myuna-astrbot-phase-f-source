from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from myuna_core.episodic_memory import (
    EGRESS_POLICY_RAW_HYDRATION,
    CompleteTurn,
    EpisodicCapsule,
    EpisodicMemoryError,
    EpisodicQuery,
    RecallEgressPolicy,
    TurnPrimitive,
    build_snapshot,
    fetch_relevant_raw,
    read_snapshot,
    search_relevant_sources,
    select_relevant_raw,
    verify_snapshot,
    write_snapshot,
)
from myuna_core.episodic_memory.contracts import (
    CONTROL_ISOLATED_CATEGORY,
    semantic_digest,
)

from tests.episodic_memory_fixtures import digest, make_turn
from myuna_core.episodic_memory.index import derive_snapshot, recover_or_write_snapshot


def riverside() -> tuple[CompleteTurn, TurnPrimitive]:
    turn = make_turn(
        1,
        "0" * 64,
        owner="Cealana建议去江边走走，时间是18:30，如果不下雨就出发。",
        assistant="Myuna表示赞同并去换衣服，带2件外套。",
    )
    primitive = TurnPrimitive(
        source_sequence=1,
        source_turn_id=turn.draft.turn_id,
        source_turn_digest=turn.turn_digest,
        actors=("Cealana", "Myuna"),
        proposals_assertions=("Cealana建议去江边走走",),
        stances=("Myuna表示赞同",),
        actions_state_changes=("去换衣服",),
        locations=("江边",),
        times=("18:30",),
        numbers=("18:30", "2"),
        negations_conditions=("如果", "不"),
    )
    return turn, primitive


class EpisodicIndexRetrievalTests(unittest.TestCase):
    @staticmethod
    def _policy() -> RecallEgressPolicy:
        return RecallEgressPolicy(
            EGRESS_POLICY_RAW_HYDRATION,
            digest("synthetic-authorized-egress-policy"),
        )

    def test_deterministic_rebuild_catalogs_synthetic_riverside_turn(self) -> None:
        turn, _primitive = riverside()
        first = derive_snapshot((turn,))
        second = derive_snapshot((turn,))
        self.assertEqual(first.snapshot_digest, second.snapshot_digest)
        self.assertEqual(first.capsules[0].capsule_kind, "turn")
        self.assertIn("Cealana", first.capsules[0].label)
        self.assertIn("江边", first.capsules[0].label)
        self.assertIn("18:30", first.capsules[0].label)
        self.assertNotIn(turn.draft.owner.text, first.capsules[0].label)

    def test_date_and_related_event_capsules_are_source_bound(self) -> None:
        first = make_turn(
            1,
            "0" * 64,
            owner="Cealana建议去江边走走。",
            assistant="Myuna赞同去江边。",
        )
        second = make_turn(
            2,
            first.turn_digest,
            owner="Cealana准备出发去江边。",
            assistant="Myuna开始换衣服。",
        )
        snapshot = derive_snapshot((first, second))
        date_capsules = tuple(
            item for item in snapshot.capsules if item.capsule_kind == "date"
        )
        event_capsules = tuple(
            item for item in snapshot.capsules if item.capsule_kind == "event"
        )
        self.assertEqual(len(date_capsules), 1)
        self.assertEqual(
            (date_capsules[0].source_start, date_capsules[0].source_end),
            (1, 2),
        )
        self.assertEqual(len(event_capsules), 1)
        self.assertEqual(
            event_capsules[0].source_terminal_digest,
            second.turn_digest,
        )

    def test_v2_source_closure_and_manifest_are_stable_and_chain_closed(self) -> None:
        first = make_turn(1, "0" * 64, owner="Synthetic first source")
        second = make_turn(
            2,
            first.turn_digest,
            owner="Synthetic second source",
        )
        snapshot = derive_snapshot((first, second))
        repeated = derive_snapshot((first, second))
        self.assertEqual(snapshot, repeated)
        self.assertEqual(
            tuple(item.sequence for item in snapshot.source_references),
            (1, 2),
        )
        manifest, manifest_digest = snapshot.source_manifest((2, 1, 2))
        self.assertEqual(manifest["source_sequences"], [1, 2])
        self.assertEqual(
            manifest["source_turn_ids"],
            [first.draft.turn_id, second.draft.turn_id],
        )
        self.assertEqual(
            manifest["source_release_set_ids"],
            [first.draft.release_set_id, second.draft.release_set_id],
        )
        self.assertEqual(len(manifest_digest), 64)
        self.assertNotIn(first.draft.owner.text, str(manifest))
        source_payload = snapshot.source_references[1].semantic_payload()
        source_payload["previous_turn_digest"] = "f" * 64
        drifted_reference = replace(
            snapshot.source_references[1],
            previous_turn_digest="f" * 64,
            source_reference_digest=semantic_digest(
                "myuna-p07-episodic-source-reference-v2",
                source_payload,
            ),
        )
        with self.assertRaisesRegex(EpisodicMemoryError, "index_source_chain_drifted"):
            replace(
                snapshot,
                source_references=(snapshot.source_references[0], drifted_reference),
            )

    def test_isolated_control_turn_is_retained_but_never_selected(self) -> None:
        control = make_turn(
            1,
            "0" * 64,
            owner="/Check synthetic status",
            assistant="Synthetic check reply",
        )
        control = CompleteTurn.create(
            replace(
                control.draft,
                provenance_categories=(
                    "authenticated_owner_private",
                    CONTROL_ISOLATED_CATEGORY,
                    "control_check_isolated",
                ),
            )
        )
        ordinary = make_turn(
            2,
            control.turn_digest,
            owner="Cealana建议去江边。",
            assistant="Myuna赞同。",
        )
        snapshot = derive_snapshot((control, ordinary))
        policy = RecallEgressPolicy(
            EGRESS_POLICY_RAW_HYDRATION,
            digest("synthetic-authorized-egress-policy"),
        )
        control_result = select_relevant_raw(
            query=EpisodicQuery("Check synthetic status"),
            turns=(control, ordinary),
            index=snapshot,
            egress_policy=policy,
        )
        ordinary_result = select_relevant_raw(
            query=EpisodicQuery("Cealana 江边"),
            turns=(control, ordinary),
            index=snapshot,
            egress_policy=policy,
        )
        self.assertEqual(control_result.hydrated_turns, ())
        self.assertEqual(ordinary_result.hydrated_turns, (ordinary,))

    def test_riverside_actor_action_stance_numbers_and_negation_are_covered(self) -> None:
        turn, primitive = riverside()
        snapshot = build_snapshot((turn,), (primitive,))
        self.assertEqual(snapshot.primitives[0].coverage_state, "complete")
        capsule = EpisodicCapsule(
            capsule_id="event-riverside-1",
            capsule_kind="event",
            source_start=1,
            source_end=1,
            source_terminal_digest=turn.turn_digest,
            primitive_digests=(snapshot.primitives[0].primitive_digest,),
            label="Cealana与Myuna讨论江边散步",
            coverage_state="complete",
        )
        snapshot = build_snapshot((turn,), snapshot.primitives, (capsule,))
        policy = RecallEgressPolicy(
            EGRESS_POLICY_RAW_HYDRATION,
            digest("synthetic-authorized-egress-policy"),
        )
        selected = select_relevant_raw(
            query=EpisodicQuery("准确回忆江边的承诺", require_exact=True),
            turns=(turn,),
            index=snapshot,
            egress_policy=policy,
        )
        self.assertEqual(selected.hydrated_turns, (turn,))
        self.assertTrue(selected.exact_raw_required)
        self.assertNotIn("Cealana", str(selected.audit_projection()))

    def test_search_fetch_and_typed_outcomes_never_return_index_text(self) -> None:
        turn, _primitive = riverside()
        snapshot = derive_snapshot((turn,))
        searched = search_relevant_sources(
            query=EpisodicQuery("江边"),
            index=snapshot,
            egress_policy=self._policy(),
        )
        self.assertEqual(searched.state, "available")
        self.assertEqual(searched.hydrated_turns, ())
        self.assertNotIn(turn.draft.owner.text, str(searched.audit_projection()))
        fetched = fetch_relevant_raw(
            selection=searched,
            turns=(turn,),
            index=snapshot,
        )
        self.assertEqual(fetched.hydrated_turns, (turn,))
        empty = select_relevant_raw(
            query=EpisodicQuery("unmatched synthetic phrase"),
            turns=(turn,),
            index=snapshot,
            egress_policy=self._policy(),
        )
        self.assertEqual(empty.state, "available_empty")
        self.assertEqual(empty.hydrated_turns, ())
        drifted = make_turn(1, "0" * 64, owner="substituted source")
        conflict = fetch_relevant_raw(
            selection=searched,
            turns=(drifted,),
            index=snapshot,
        )
        self.assertEqual(conflict.state, "conflict")
        self.assertEqual(conflict.reason_category, "source_closure_conflict")
        self.assertEqual(conflict.hydrated_turns, ())
        with self.assertRaisesRegex(
            EpisodicMemoryError,
            "retrieval_selection_digest_mismatch",
        ):
            replace(searched, selection_digest="f" * 64)
        other = derive_snapshot((drifted,))
        mixed = fetch_relevant_raw(
            selection=searched,
            turns=(drifted,),
            index=other,
        )
        self.assertEqual(mixed.reason_category, "search_snapshot_conflict")

    def test_missing_coverage_cannot_be_claimed_complete(self) -> None:
        turn, primitive = riverside()
        incomplete = replace(primitive, numbers=(), negations_conditions=())
        snapshot = build_snapshot((turn,), (incomplete,))
        self.assertEqual(snapshot.primitives[0].coverage_state, "coverage_incomplete")
        self.assertIn("number_coverage_incomplete", snapshot.primitives[0].ambiguity_codes)
        with self.assertRaisesRegex(EpisodicMemoryError, "capsule_coverage_mismatch"):
            build_snapshot(
                (turn,),
                snapshot.primitives,
                (
                    EpisodicCapsule(
                        capsule_id="bad-complete-capsule",
                        capsule_kind="event",
                        source_start=1,
                        source_end=1,
                        source_terminal_digest=turn.turn_digest,
                        primitive_digests=(snapshot.primitives[0].primitive_digest,),
                        label="incorrectly complete",
                        coverage_state="complete",
                    ),
                ),
            )

    def test_index_is_rebuildable_replay_safe_and_source_bound(self) -> None:
        turn, primitive = riverside()
        snapshot = build_snapshot((turn,), (primitive,))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "index.json"
            write_snapshot(path, snapshot)
            loaded = read_snapshot(path)
            verify_snapshot(loaded, (turn,))
            drifted = make_turn(1, "0" * 64, owner="different source turn")
            with self.assertRaises(EpisodicMemoryError):
                verify_snapshot(loaded, (drifted,))
        with self.assertRaisesRegex(EpisodicMemoryError, "primitive_source_pointer_drifted"):
            build_snapshot((turn,), (replace(primitive, source_turn_digest="e" * 64),))

    def test_partial_index_sidecar_is_not_silently_reused(self) -> None:
        turn, primitive = riverside()
        snapshot = build_snapshot((turn,), (primitive,))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "index.json"
            with self.assertRaisesRegex(EpisodicMemoryError, "index_crash_before_replace"):
                write_snapshot(path, snapshot, crash_before_replace=True)
            self.assertFalse(path.exists())
            self.assertTrue(path.with_name("index.json.next").exists())
            with self.assertRaisesRegex(EpisodicMemoryError, "index_path_rejected"):
                write_snapshot(path, snapshot)

    def test_verified_crash_sidecar_is_promoted_from_raw_authority(self) -> None:
        turn, primitive = riverside()
        snapshot = build_snapshot((turn,), (primitive,))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "index.json"
            with self.assertRaisesRegex(EpisodicMemoryError, "index_crash_before_replace"):
                write_snapshot(path, snapshot, crash_before_replace=True)
            self.assertTrue(recover_or_write_snapshot(path, (turn,)))
            self.assertFalse(path.with_name("index.json.next").exists())
            verify_snapshot(read_snapshot(path), (turn,))
            drifted = make_turn(1, "0" * 64, owner="drifted raw source")
            with self.assertRaises(EpisodicMemoryError):
                recover_or_write_snapshot(path, (drifted,))

    def test_explicit_rebuild_repairs_only_safe_corrupt_derivative(self) -> None:
        turn, _primitive = riverside()
        snapshot = derive_snapshot((turn,))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "index.json"
            write_snapshot(path, snapshot)
            canonical = path.read_bytes()
            path.write_bytes(b"{\n")
            with self.assertRaises(EpisodicMemoryError):
                recover_or_write_snapshot(path, (turn,))
            self.assertTrue(
                recover_or_write_snapshot(
                    path,
                    (turn,),
                    explicit_rebuild=True,
                )
            )
            self.assertEqual(path.read_bytes(), canonical)
            os.chmod(path, 0o640)
            with self.assertRaisesRegex(EpisodicMemoryError, "index_type_rejected"):
                recover_or_write_snapshot(
                    path,
                    (turn,),
                    explicit_rebuild=True,
                )

    def test_lost_replace_return_converges_without_second_publication(self) -> None:
        turn, _primitive = riverside()
        snapshot = derive_snapshot((turn,))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "index.json"
            real_replace = os.replace

            def replace_then_lose_return(source, target):
                real_replace(source, target)
                raise OSError("synthetic lost return")

            with patch(
                "myuna_core.episodic_memory.index.os.replace",
                side_effect=replace_then_lose_return,
            ):
                with self.assertRaisesRegex(
                    EpisodicMemoryError,
                    "index_write_unavailable",
                ):
                    write_snapshot(path, snapshot)
            self.assertEqual(read_snapshot(path), snapshot)
            self.assertFalse(recover_or_write_snapshot(path, (turn,)))

    def test_symlink_and_hardlink_snapshot_targets_fail_closed(self) -> None:
        turn, _primitive = riverside()
        snapshot = derive_snapshot((turn,))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            write_snapshot(target, snapshot)
            hardlink = root / "hardlink.json"
            os.link(target, hardlink)
            with self.assertRaisesRegex(EpisodicMemoryError, "index_type_rejected"):
                read_snapshot(target)
            hardlink.unlink()
            target.unlink()
            target.symlink_to(root / "missing.json")
            with self.assertRaisesRegex(EpisodicMemoryError, "index_type_rejected"):
                recover_or_write_snapshot(
                    target,
                    (turn,),
                    explicit_rebuild=True,
                )

    def test_default_egress_denies_historical_raw_before_selection(self) -> None:
        turn, primitive = riverside()
        snapshot = build_snapshot((turn,), (primitive,))
        with self.assertRaisesRegex(EpisodicMemoryError, "historical_raw_egress_not_authorized"):
            select_relevant_raw(
                query=EpisodicQuery("江边"),
                turns=(turn,),
                index=snapshot,
                egress_policy=RecallEgressPolicy(),
            )

    def test_conflicting_same_range_capsules_fail_closed(self) -> None:
        turn, primitive = riverside()
        base = build_snapshot((turn,), (primitive,))
        capsules = tuple(
            EpisodicCapsule(
                capsule_id=f"conflict-{index}",
                capsule_kind="event",
                source_start=1,
                source_end=1,
                source_terminal_digest=turn.turn_digest,
                primitive_digests=(base.primitives[0].primitive_digest,),
                label=label,
                coverage_state="complete",
            )
            for index, label in enumerate(("江边", "海边"), start=1)
        )
        with self.assertRaisesRegex(EpisodicMemoryError, "capsule_conflict"):
            build_snapshot((turn,), base.primitives, capsules)


if __name__ == "__main__":
    unittest.main()
