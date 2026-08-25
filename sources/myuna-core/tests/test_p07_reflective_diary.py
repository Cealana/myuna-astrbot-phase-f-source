from __future__ import annotations

from dataclasses import replace
from datetime import date, datetime, timezone
import json
import sqlite3
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from myuna_core.episodic_memory import (
    SEMANTIC_WRITE_BOUNDARY,
    OWNER_DAY_DIARY_MODEL,
    OWNER_DAY_DIARY_MODEL_ROLE,
    OWNER_DAY_PREVIEW_PURPOSE,
    CompleteTurn,
    DiaryJobEvent,
    DiaryStatement,
    EpisodicMemoryError,
    OwnerDayDiaryRevision,
    OwnerDayPolicy,
    ReflectiveDiaryEntry,
    ReflectiveDiaryStore,
    REFLECTIVE_DIARY_EGRESS_V1_DIGEST,
    REFLECTIVE_DIARY_STYLE_V1_DIGEST,
    plan_diary_recall,
    resolve_relative_date,
)
from myuna_core.episodic_memory import diary as diary_module
from myuna_core.episodic_memory.contracts import (
    PrefixCapsule,
    PrefixCompactionPolicy,
    TurnTimeCorrection,
    semantic_digest,
)
from myuna_core.episodic_memory.index import EpisodicIndexSnapshot, derive_snapshot
from myuna_core.episodic_memory.context import verify_prefix_capsule
from myuna_core.episodic_memory.temporal_bridge import TemporalIntervalIndexSnapshot
from myuna_core.episodic_memory import temporal_bridge as temporal_bridge_module
from myuna_core.episodic_memory.temporal_validity import (
    TemporalEndpoint,
    TemporalIntervalEpisode,
    TemporalIntervalRevision,
)
from myuna_core.owner_profile.contracts import ProfileStateIntent

from tests.episodic_memory_fixtures import digest, make_turn


def entry_for(
    turn: CompleteTurn,
    *,
    revision: int = 1,
    kind: str = "contemporaneous",
) -> ReflectiveDiaryEntry:
    return ReflectiveDiaryEntry(
        day=date(2026, 8, 8),
        calendar_zone="Asia/Shanghai",
        revision=revision,
        created_at_utc=datetime(2026, 8, 8, 16, tzinfo=timezone.utc),
        model_role="p07_external_daily_reflective_diary",
        model_version="synthetic-no-provider-v1",
        persona_digest=digest("effective-v6-synthetic"),
        release_set_id="1" * 64,
        generation_kind=kind,
        reason_code="synthetic_fixture",
        statements=(
            DiaryStatement(
                "fact-1",
                "factual_observation",
                "Cealana提出去江边。",
                (turn.draft.sequence,),
                (turn.turn_digest,),
            ),
            DiaryStatement(
                "reflection-1",
                "interpretation_reflection",
                "我觉得这个提议让当天变得轻松。",
                (turn.draft.sequence,),
                (turn.turn_digest,),
            ),
            DiaryStatement(
                "uncertainty-1",
                "uncertainty",
                "我不确定天气是否会改变计划。",
            ),
            DiaryStatement(
                "intention-1",
                "intention",
                "以后遇到类似安排时，我想先确认天气。",
            ),
        ),
        source_selection_digest=digest("source-selection"),
        egress_policy_digest=REFLECTIVE_DIARY_EGRESS_V1_DIGEST,
        style_contract_digest=REFLECTIVE_DIARY_STYLE_V1_DIGEST,
        closure_binding_digest=digest("closure-binding"),
        source_sequences=(turn.draft.sequence,),
        source_turn_digests=(turn.turn_digest,),
        supersedes_revision=(revision - 1 if revision > 1 else None),
    )


def source_manifest_for(
    turn: CompleteTurn,
) -> tuple[EpisodicIndexSnapshot, dict[str, object], str]:
    snapshot = derive_snapshot((turn,))
    manifest, manifest_digest = snapshot.source_manifest((turn.draft.sequence,))
    return snapshot, manifest, manifest_digest


def diary_store(
    path: Path,
    snapshot: EpisodicIndexSnapshot | None = None,
    turns: tuple[CompleteTurn, ...] = (),
    temporal_snapshot: TemporalIntervalIndexSnapshot | None = None,
) -> ReflectiveDiaryStore:
    def load_current_snapshot() -> tuple[
        EpisodicIndexSnapshot,
        tuple[CompleteTurn, ...],
        TemporalIntervalIndexSnapshot,
    ]:
        if snapshot is None:
            raise EpisodicMemoryError("synthetic_current_snapshot_unavailable")
        selected_temporal = temporal_snapshot or TemporalIntervalIndexSnapshot.empty(
            snapshot.archive_head_digest
        )
        return snapshot, turns, selected_temporal

    return ReflectiveDiaryStore(
        path,
        current_source_snapshot_loader=load_current_snapshot,
    )


def profile_source_fields(
    snapshot: EpisodicIndexSnapshot,
    turn: CompleteTurn,
) -> dict[str, str]:
    reference = snapshot.source_references[turn.draft.sequence - 1]
    return {
        "delivery_ack_digest": turn.draft.delivery_ack_digest,
        "delivered_source_reference_digest": reference.source_reference_digest,
    }


def terminal_temporal_snapshot(
    turn: CompleteTurn,
    *,
    state: str = "ended",
    interval_id: str = "ti_" + "a" * 64,
    event_sequence: int = 17,
) -> TemporalIntervalIndexSnapshot:
    delivered = turn.draft.time_binding.delivered_at_utc
    assert delivered is not None
    endpoint = TemporalEndpoint(
        kind="exact",
        calendar_zone=turn.draft.time_binding.calendar_zone,
        trusted_time_binding_digest=turn.draft.time_binding.binding_digest,
        uncertainty_microseconds=0,
        instant_utc=delivered,
    )
    revision = TemporalIntervalRevision(
        interval_id=interval_id,
        revision=1,
        state=state,
        statement="Synthetic terminal interval statement",
        conflict_key="synthetic-terminal-interval",
        start=endpoint,
        end=endpoint,
        source_turn_sequences=(turn.draft.sequence,),
        source_turn_digests=(turn.turn_digest,),
        p08_revision=3,
        p08_event_sequence=event_sequence,
        p08_event_kind="expire" if state == "ended" else "revoke",
        previous_revision_digest="0" * 64,
    )
    episode = TemporalIntervalEpisode.create((revision,))
    semantic = {
        "after_event_sequence": event_sequence,
        "archive_head_digest": turn.turn_digest,
        "blocked_interval_ids": [],
        "episodes": [episode.payload()],
        "observed_watermark": event_sequence,
        "schema": temporal_bridge_module.TEMPORAL_INTERVAL_INDEX_SCHEMA,
        "unresolved_event_sequences": [],
    }
    return TemporalIntervalIndexSnapshot(
        after_event_sequence=event_sequence,
        observed_watermark=event_sequence,
        archive_head_digest=turn.turn_digest,
        episodes=(episode,),
        unresolved_event_sequences=(),
        blocked_interval_ids=(),
        snapshot_digest=temporal_bridge_module._digest(
            "myuna-p07-temporal-index-v2", semantic
        ),
    )


def prefix_capsule_for(
    turn: CompleteTurn,
    snapshot: EpisodicIndexSnapshot,
    *,
    revision: int = 1,
    parent_digest: str = "0" * 64,
    text: str = "Owner synthetic message",
) -> PrefixCapsule:
    policy = PrefixCompactionPolicy.balanced_default()
    source_characters = len(turn.draft.owner.text) + len(turn.draft.assistant.text)
    source_bytes = len(turn.draft.owner.text.encode("utf-8")) + len(
        turn.draft.assistant.text.encode("utf-8")
    )
    capsule_bytes = len(text.encode("utf-8"))
    return PrefixCapsule(
        capsule_id="synthetic-prefix-capsule",
        revision=revision,
        parent_capsule_digest=parent_digest,
        archive_id=snapshot.archive_id,
        epoch_id=turn.draft.epoch_id,
        source_snapshot_head_digest=snapshot.archive_head_digest,
        source_snapshot_turn_count=snapshot.archive_turn_count,
        source_start=1,
        source_end=1,
        source_turn_ids=(turn.draft.turn_id,),
        source_turn_digests=(turn.turn_digest,),
        source_original_zones=(turn.draft.time_binding.calendar_zone,),
        source_characters=source_characters,
        source_bytes=source_bytes,
        source_tokens=source_bytes,
        capsule_text=text,
        capsule_characters=len(text),
        capsule_bytes=capsule_bytes,
        capsule_tokens=capsule_bytes,
        character_ratio_milli=source_characters * 1_000 // len(text),
        byte_ratio_milli=source_bytes * 1_000 // capsule_bytes,
        token_ratio_milli=source_bytes * 1_000 // capsule_bytes,
        policy_version=policy.policy_version,
        policy_digest=policy.policy_digest,
        generator_version="synthetic-direct-from-raw-v1",
        model_provider_class="synthetic-offline",
        token_oracle_id=policy.token_oracle_id,
        created_at_utc=datetime(2026, 8, 9, tzinfo=timezone.utc),
        source_time_start_utc=turn.draft.time_binding.delivered_at_utc,
        source_time_end_utc=turn.draft.time_binding.delivered_at_utc,
        omission_counts=(("omitted_detail", 1),),
        risk_class="continuity_orientation",
        projection_eligible=True,
    )


def prefix_receipt_for(
    capsule: PrefixCapsule,
    turns: tuple[CompleteTurn, ...],
):
    return verify_prefix_capsule(
        capsule,
        turns=turns,
        archive_id=capsule.archive_id,
        archive_head_digest=turns[-1].turn_digest,
        policy=PrefixCompactionPolicy.balanced_default(),
        token_counter=prefix_token_counter,
        expected_generator_version="synthetic-direct-from-raw-v1",
        expected_model_provider_class="synthetic-offline",
        expected_created_at_utc=datetime(2026, 8, 9, tzinfo=timezone.utc),
    )


def prefix_token_counter(messages) -> int:
    return sum(len(item["content"].encode("utf-8")) for item in messages)


def owner_day_revision_for(
    turn: CompleteTurn,
    *,
    revision: int = 1,
) -> OwnerDayDiaryRevision:
    policy = OwnerDayPolicy()
    return OwnerDayDiaryRevision(
        job_digest=digest(f"owner-day-job-{revision}"),
        purpose=OWNER_DAY_PREVIEW_PURPOSE,
        owner_day="2026-08-08",
        policy_digest=policy.policy_digest,
        calendar_zone=policy.calendar_zone,
        boundary_local_time=policy.boundary_local_time,
        soft_close_grace_seconds=policy.soft_close_grace_seconds,
        revision=revision,
        created_at_utc=datetime(2026, 8, 8, 16 + revision, tzinfo=timezone.utc),
        model=OWNER_DAY_DIARY_MODEL,
        model_role=OWNER_DAY_DIARY_MODEL_ROLE,
        persona_digest=digest("synthetic-owner-day-persona"),
        memory_release_set_id=turn.draft.release_set_id,
        source_selection_digest=digest(f"owner-day-selection-{revision}"),
        source_sequences=(turn.draft.sequence,),
        source_turn_digests=(turn.turn_digest,),
        statements=(
            DiaryStatement(
                f"owner-day-fact-{revision}",
                "factual_observation",
                "Synthetic source-bound owner-day fact.",
                (turn.draft.sequence,),
                (turn.turn_digest,),
            ),
        ),
        supersedes_revision=(None if revision == 1 else revision - 1),
    )


class ReflectiveDiaryTests(unittest.TestCase):
    def test_diary_separates_fact_reflection_uncertainty_and_intention(self) -> None:
        turn = make_turn(
            1,
            "0" * 64,
            owner="Cealana提出去江边。",
            assistant="Myuna表示赞同。",
        )
        entry = entry_for(turn)
        self.assertEqual(
            {statement.kind for statement in entry.statements},
            {
                "factual_observation",
                "interpretation_reflection",
                "uncertainty",
                "intention",
            },
        )
        self.assertEqual(entry.calendar_zone, "Asia/Shanghai")
        self.assertEqual(entry.model_role, "p07_external_daily_reflective_diary")
        self.assertNotEqual(entry.entry_digest, turn.turn_digest)
        plan = plan_diary_recall((entry,), exact_factual_detail_requested=True)
        self.assertTrue(plan.perspective_available)
        self.assertTrue(plan.raw_hydration_required)
        self.assertEqual(plan.source_sequences, (1,))

    def test_append_only_revision_late_backfill_and_idempotent_rebuild(self) -> None:
        turn = make_turn(1, "0" * 64)
        first = entry_for(turn)
        second = entry_for(turn, revision=2, kind="late_backfill")
        snapshot, manifest, manifest_digest = source_manifest_for(turn)
        with tempfile.TemporaryDirectory() as directory:
            store = diary_store(
                Path(directory) / "diary.sqlite3", snapshot, (turn,)
            )
            store.initialize()
            self.assertEqual(
                store.append_reflective_revision(
                    entry=first,
                    turns=(turn,),
                    source_snapshot=snapshot,
                    source_manifest=manifest,
                    source_manifest_digest=manifest_digest,
                ),
                first.entry_digest,
            )
            self.assertEqual(
                store.append_reflective_revision(
                    entry=first,
                    turns=(turn,),
                    source_snapshot=snapshot,
                    source_manifest=manifest,
                    source_manifest_digest=manifest_digest,
                ),
                first.entry_digest,
            )
            store.append_reflective_revision(
                entry=second,
                turns=(turn,),
                source_snapshot=snapshot,
                source_manifest=manifest,
                source_manifest_digest=manifest_digest,
            )
            projection = store.audit_projection()
            self.assertEqual(projection["reflective_revision_count"], 2)
            self.assertEqual(projection["owner_day_revision_count"], 0)
            self.assertFalse(projection["job_queue_active"])
            self.assertEqual(store.reflective_revisions(), (first, second))
            self.assertEqual(store.current_reflective_revisions(), (second,))
            self.assertNotIn("江边", str(projection))

    def test_revision_rollback_and_lost_commit_return_converge_exactly(self) -> None:
        turn = make_turn(1, "0" * 64)
        entry = entry_for(turn)
        snapshot, manifest, manifest_digest = source_manifest_for(turn)

        class FaultConnection(sqlite3.Connection):
            mode = "before_commit"
            fired = False

            def execute(self, sql, parameters=()):
                result = super().execute(sql, parameters)
                normalized = " ".join(sql.split()).upper()
                if not type(self).fired and (
                    (
                        type(self).mode == "before_commit"
                        and normalized.startswith("INSERT INTO DIARY_ENTRIES")
                    )
                    or (
                        type(self).mode == "after_commit"
                        and normalized == "COMMIT"
                    )
                ):
                    type(self).fired = True
                    raise sqlite3.OperationalError("synthetic lost operation return")
                return result

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "diary.sqlite3"
            store = diary_store(path, snapshot, (turn,))
            store.initialize()
            pristine = {
                item.name: item.read_bytes()
                for item in root.iterdir()
                if item.is_file()
            }
            original_connect = diary_module.sqlite3.connect

            def fault_connect(*args, **kwargs):
                return original_connect(*args, factory=FaultConnection, **kwargs)

            FaultConnection.mode = "before_commit"
            FaultConnection.fired = False
            with patch.object(
                diary_module.sqlite3,
                "connect",
                side_effect=fault_connect,
            ):
                with self.assertRaisesRegex(
                    EpisodicMemoryError,
                    "diary_write_failed",
                ):
                    store.append_reflective_revision(
                        entry=entry,
                        turns=(turn,),
                        source_snapshot=snapshot,
                        source_manifest=manifest,
                        source_manifest_digest=manifest_digest,
                    )
            self.assertEqual(
                {
                    item.name: item.read_bytes()
                    for item in root.iterdir()
                    if item.is_file()
                },
                pristine,
            )
            FaultConnection.mode = "after_commit"
            FaultConnection.fired = False
            with patch.object(
                diary_module.sqlite3,
                "connect",
                side_effect=fault_connect,
            ):
                with self.assertRaisesRegex(
                    EpisodicMemoryError,
                    "diary_write_failed",
                ):
                    store.append_reflective_revision(
                        entry=entry,
                        turns=(turn,),
                        source_snapshot=snapshot,
                        source_manifest=manifest,
                        source_manifest_digest=manifest_digest,
                    )
            self.assertEqual(
                store.append_reflective_revision(
                    entry=entry,
                    turns=(turn,),
                    source_snapshot=snapshot,
                    source_manifest=manifest,
                    source_manifest_digest=manifest_digest,
                ),
                entry.entry_digest,
            )
            self.assertEqual(store.reflective_revisions(), (entry,))

    def test_retired_job_queue_rejects_without_derivative_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "diary.sqlite3"
            store = diary_store(path)
            store.initialize()
            gap = DiaryJobEvent(
                job_id="diary-gap-2026-08-09-r1",
                day=date(2026, 8, 9),
                calendar_zone="Asia/Shanghai",
                target_revision=1,
                event_kind="missing",
                attempt=3,
                reason_code="bounded_retry_exhausted",
                occurred_at_utc=datetime(2026, 8, 9, 16, tzinfo=timezone.utc),
            )
            before = path.read_bytes()
            with self.assertRaisesRegex(EpisodicMemoryError, "diary_job_queue_retired"):
                store.append_job_event(gap)
            self.assertEqual(path.read_bytes(), before)
            with self.assertRaisesRegex(EpisodicMemoryError, "diary_job_queue_retired"):
                store.job_events()
            projection = store.audit_projection()
            self.assertEqual(projection["reflective_revision_count"], 0)
            self.assertEqual(projection["owner_day_revision_count"], 0)
            self.assertFalse(projection["job_queue_active"])
        self.assertEqual(
            SEMANTIC_WRITE_BOUNDARY["daily_reflective_diary"],
            "automatic_subjective_derivative_no_semantic_promotion",
        )
        self.assertEqual(
            SEMANTIC_WRITE_BOUNDARY["stable_profile_fact"],
            "proposal_confirmation_required",
        )

    def test_diary_fact_requires_raw_pointer_and_pointer_drift_fails(self) -> None:
        with self.assertRaisesRegex(EpisodicMemoryError, "diary_fact_source_required"):
            DiaryStatement("bad-fact", "factual_observation", "unsupported fact")
        turn = make_turn(1, "0" * 64)
        entry = entry_for(turn)
        drifted = make_turn(1, "0" * 64, owner="different")
        snapshot, manifest, manifest_digest = source_manifest_for(turn)
        with tempfile.TemporaryDirectory() as directory:
            store = diary_store(
                Path(directory) / "diary.sqlite3", snapshot, (turn,)
            )
            store.initialize()
            with self.assertRaisesRegex(EpisodicMemoryError, "diary_source_pointer_drifted"):
                store.append_reflective_revision(
                    entry=entry,
                    turns=(drifted,),
                    source_snapshot=snapshot,
                    source_manifest=manifest,
                    source_manifest_digest=manifest_digest,
                )

    def test_diary_day_keeps_original_zone_across_dst_and_default_changes(self) -> None:
        reference = datetime(2026, 11, 1, 3, 30, tzinfo=timezone.utc)
        shanghai = resolve_relative_date("今天", reference_utc=reference)
        los_angeles = resolve_relative_date(
            "今天", reference_utc=reference, zone_name="America/Los_Angeles"
        )
        self.assertEqual(shanghai.calendar_zone, "Asia/Shanghai")
        self.assertEqual(los_angeles.calendar_zone, "America/Los_Angeles")
        self.assertNotEqual(shanghai.local_date, los_angeles.local_date)

    def test_owner_day_revisions_share_one_store_and_verify_raw_source_closure(self) -> None:
        turn = make_turn(1, "0" * 64)
        snapshot = derive_snapshot((turn,))
        manifest, manifest_digest = snapshot.source_manifest((1,))
        first = owner_day_revision_for(turn)
        second = owner_day_revision_for(turn, revision=2)
        with tempfile.TemporaryDirectory() as directory:
            store = diary_store(
                Path(directory) / "diary.sqlite3", snapshot, (turn,)
            )
            store.initialize()
            self.assertEqual(
                store.append_owner_day_revision(
                    revision=first,
                    turns=(turn,),
                    source_snapshot=snapshot,
                    source_manifest=manifest,
                    source_manifest_digest=manifest_digest,
                ),
                first.revision_digest,
            )
            self.assertEqual(
                store.append_owner_day_revision(
                    revision=first,
                    turns=(turn,),
                    source_snapshot=snapshot,
                    source_manifest=manifest,
                    source_manifest_digest=manifest_digest,
                ),
                first.revision_digest,
            )
            store.append_owner_day_revision(
                revision=second,
                turns=(turn,),
                source_snapshot=snapshot,
                source_manifest=manifest,
                source_manifest_digest=manifest_digest,
            )
            self.assertEqual(store.owner_day_revisions(), (first, second))
            self.assertEqual(store.current_owner_day_revisions(), (second,))
            closure = store.verify_source_closure(snapshot)
            self.assertEqual(closure["owner_day_state"], "available")
            self.assertEqual(closure["reflective_state"], "unavailable")
            drifted = derive_snapshot(
                (make_turn(1, "0" * 64, owner="Synthetic substituted raw"),)
            )
            with self.assertRaisesRegex(
                EpisodicMemoryError,
                "diary_source_closure_conflict",
            ):
                store.verify_source_closure(drifted)

    def test_append_accepts_selected_turn_from_full_current_snapshot(self) -> None:
        first_turn = make_turn(1, "0" * 64)
        selected_turn = make_turn(2, first_turn.turn_digest)
        snapshot = derive_snapshot((first_turn, selected_turn))
        manifest, manifest_digest = snapshot.source_manifest((2,))
        entry = entry_for(selected_turn)
        owner_day = owner_day_revision_for(selected_turn)
        with tempfile.TemporaryDirectory() as directory:
            store = diary_store(
                Path(directory) / "diary.sqlite3",
                snapshot,
                (first_turn, selected_turn),
            )
            store.initialize()
            self.assertEqual(
                store.append_reflective_revision(
                    entry=entry,
                    turns=(selected_turn,),
                    source_snapshot=snapshot,
                    source_manifest=manifest,
                    source_manifest_digest=manifest_digest,
                ),
                entry.entry_digest,
            )
            self.assertEqual(
                store.append_owner_day_revision(
                    revision=owner_day,
                    turns=(selected_turn,),
                    source_snapshot=snapshot,
                    source_manifest=manifest,
                    source_manifest_digest=manifest_digest,
                ),
                owner_day.revision_digest,
            )

    def test_append_rejects_snapshot_manifest_and_time_substitution_before_mutation(
        self,
    ) -> None:
        turn = make_turn(1, "0" * 64)
        snapshot, manifest, manifest_digest = source_manifest_for(turn)
        entry = entry_for(turn)
        owner_day = owner_day_revision_for(turn)
        substitutions = {
            "archive_turn_count": {"archive_turn_count": 2},
            "source_sequence": {
                "archive_turn_count": 2,
                "source_sequences": [2],
            },
            "source_turn_id": {"source_turn_ids": ["substituted-source-turn"]},
            "source_reference_digest": {"source_reference_digests": ["2" * 64]},
            "source_epoch_id": {"source_epoch_ids": ["substituted-source-epoch"]},
            "source_release_set_id": {"source_release_set_ids": ["3" * 64]},
            "snapshot_digest": {"snapshot_digest": "4" * 64},
            "source_closure_digest": {"source_closure_digest": "5" * 64},
            "temporal_snapshot_digest": {"temporal_snapshot_digest": "6" * 64},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "diary.sqlite3"
            store = diary_store(path, snapshot, (turn,))
            store.initialize()

            def state() -> dict[str, bytes]:
                return {
                    item.name: item.read_bytes()
                    for item in root.iterdir()
                    if item.is_file()
                }

            pristine = state()
            for label, changes in substitutions.items():
                expected_code = (
                    "diary_source_manifest_binding_mismatch"
                    if label == "source_sequence"
                    else "diary_source_manifest_snapshot_mismatch"
                )
                with self.subTest(kind="reflective_manifest", field=label):
                    submitted = {
                        key: (list(value) if isinstance(value, list) else value)
                        for key, value in manifest.items()
                    }
                    submitted.update(changes)
                    submitted_digest = semantic_digest(
                        "myuna-p07-derivative-source-manifest-v1",
                        submitted,
                    )
                    with self.assertRaisesRegex(EpisodicMemoryError, expected_code):
                        store.append_reflective_revision(
                            entry=entry,
                            turns=(turn,),
                            source_snapshot=snapshot,
                            source_manifest=submitted,
                            source_manifest_digest=submitted_digest,
                        )
                    self.assertEqual(state(), pristine)
                    self.assertEqual(store.reflective_revisions(), ())
                with self.subTest(kind="owner_day_manifest", field=label):
                    with self.assertRaisesRegex(EpisodicMemoryError, expected_code):
                        store.append_owner_day_revision(
                            revision=owner_day,
                            turns=(turn,),
                            source_snapshot=snapshot,
                            source_manifest=submitted,
                            source_manifest_digest=submitted_digest,
                        )
                    self.assertEqual(state(), pristine)
                    self.assertEqual(store.owner_day_revisions(), ())

            zone_policy = OwnerDayPolicy(calendar_zone="America/Los_Angeles")
            with self.assertRaisesRegex(
                EpisodicMemoryError,
                "diary_source_calendar_zone_mismatch",
            ):
                store.append_reflective_revision(
                    entry=replace(entry, calendar_zone=zone_policy.calendar_zone),
                    turns=(turn,),
                    source_snapshot=snapshot,
                    source_manifest=manifest,
                    source_manifest_digest=manifest_digest,
                )
            for substituted_owner_day in (
                replace(owner_day, owner_day="2026-08-09"),
                replace(
                    owner_day,
                    calendar_zone=zone_policy.calendar_zone,
                    policy_digest=zone_policy.policy_digest,
                ),
            ):
                with self.assertRaisesRegex(
                    EpisodicMemoryError,
                    "owner_day_source_snapshot_mismatch",
                ):
                    store.append_owner_day_revision(
                        revision=substituted_owner_day,
                        turns=(turn,),
                        source_snapshot=snapshot,
                        source_manifest=manifest,
                        source_manifest_digest=manifest_digest,
                    )
                self.assertEqual(state(), pristine)
            self.assertEqual(store.audit_projection()["reflective_revision_count"], 0)
            self.assertEqual(store.audit_projection()["owner_day_revision_count"], 0)

    def test_append_rejects_internally_consistent_noncurrent_source_closures(
        self,
    ) -> None:
        turn = make_turn(1, "0" * 64)
        current = derive_snapshot((turn,))
        temporal_variant = derive_snapshot(
            (turn,),
            temporal_snapshot=TemporalIntervalIndexSnapshot.empty(
                turn.turn_digest,
                initial_event_sequence=1,
            ),
        )
        correction = TurnTimeCorrection(
            correction_id="synthetic-effective-time-substitution",
            turn_id=turn.draft.turn_id,
            turn_digest=turn.turn_digest,
            original_binding_digest=turn.draft.time_binding.binding_digest,
            corrected_binding=replace(
                turn.draft.time_binding,
                source="synthetic-substituted-time-source",
            ),
            reason_code="synthetic_effective_time_substitution",
            created_at_utc=datetime(2026, 8, 9, tzinfo=timezone.utc),
            provenance_digest=digest("synthetic-effective-time-provenance"),
        )
        effective_time_variant = derive_snapshot((turn,), corrections=(correction,))
        entry = entry_for(turn)
        owner_day = owner_day_revision_for(turn)
        for variant_name, submitted_snapshot in (
            ("temporal", temporal_variant),
            ("effective_time", effective_time_variant),
        ):
            manifest, manifest_digest = submitted_snapshot.source_manifest((1,))
            for route in ("reflective", "owner_day"):
                with self.subTest(variant=variant_name, route=route):
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        path = root / "diary.sqlite3"
                        store = diary_store(path, current, (turn,))
                        store.initialize()
                        pristine = {
                            item.name: item.read_bytes()
                            for item in root.iterdir()
                            if item.is_file()
                        }
                        before = store.audit_projection()
                        with patch.object(
                            store,
                            "_connect",
                            wraps=store._connect,
                        ) as connect:
                            with self.assertRaisesRegex(
                                EpisodicMemoryError,
                                "diary_current_source_snapshot_mismatch",
                            ):
                                if route == "reflective":
                                    store.append_reflective_revision(
                                        entry=entry,
                                        turns=(turn,),
                                        source_snapshot=submitted_snapshot,
                                        source_manifest=manifest,
                                        source_manifest_digest=manifest_digest,
                                    )
                                else:
                                    store.append_owner_day_revision(
                                        revision=owner_day,
                                        turns=(turn,),
                                        source_snapshot=submitted_snapshot,
                                        source_manifest=manifest,
                                        source_manifest_digest=manifest_digest,
                                    )
                            connect.assert_not_called()
                        self.assertEqual(
                            {
                                item.name: item.read_bytes()
                                for item in root.iterdir()
                                if item.is_file()
                            },
                            pristine,
                        )
                        self.assertEqual(store.audit_projection(), before)

    def test_append_rejects_stale_previously_valid_snapshot_after_advance(
        self,
    ) -> None:
        first_turn = make_turn(1, "0" * 64)
        second_turn = make_turn(2, first_turn.turn_digest)
        stale_snapshot = derive_snapshot((first_turn,))
        current_authority = [
            (
                stale_snapshot,
                (first_turn,),
                TemporalIntervalIndexSnapshot.empty(
                    stale_snapshot.archive_head_digest
                ),
            )
        ]
        stale_manifest, stale_manifest_digest = stale_snapshot.source_manifest((1,))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "diary.sqlite3"
            store = ReflectiveDiaryStore(
                path,
                current_source_snapshot_loader=lambda: current_authority[0],
            )
            store.initialize()
            store.append_reflective_revision(
                entry=entry_for(first_turn),
                turns=(first_turn,),
                source_snapshot=stale_snapshot,
                source_manifest=stale_manifest,
                source_manifest_digest=stale_manifest_digest,
            )
            store.append_owner_day_revision(
                revision=owner_day_revision_for(first_turn),
                turns=(first_turn,),
                source_snapshot=stale_snapshot,
                source_manifest=stale_manifest,
                source_manifest_digest=stale_manifest_digest,
            )
            advanced_snapshot = derive_snapshot((first_turn, second_turn))
            current_authority[0] = (
                advanced_snapshot,
                (first_turn, second_turn),
                TemporalIntervalIndexSnapshot.empty(
                    advanced_snapshot.archive_head_digest
                ),
            )
            pristine = {
                item.name: item.read_bytes()
                for item in root.iterdir()
                if item.is_file()
            }
            before = store.audit_projection()
            for route in ("reflective", "owner_day"):
                with self.subTest(route=route):
                    with patch.object(
                        store,
                        "_connect",
                        wraps=store._connect,
                    ) as connect:
                        with self.assertRaisesRegex(
                            EpisodicMemoryError,
                            "diary_current_source_snapshot_mismatch",
                        ):
                            if route == "reflective":
                                store.append_reflective_revision(
                                    entry=entry_for(
                                        first_turn,
                                        revision=2,
                                        kind="late_backfill",
                                    ),
                                    turns=(first_turn,),
                                    source_snapshot=stale_snapshot,
                                    source_manifest=stale_manifest,
                                    source_manifest_digest=stale_manifest_digest,
                                )
                            else:
                                store.append_owner_day_revision(
                                    revision=owner_day_revision_for(first_turn, revision=2),
                                    turns=(first_turn,),
                                    source_snapshot=stale_snapshot,
                                    source_manifest=stale_manifest,
                                    source_manifest_digest=stale_manifest_digest,
                                )
                        connect.assert_not_called()
                    self.assertEqual(
                        {
                            item.name: item.read_bytes()
                            for item in root.iterdir()
                            if item.is_file()
                        },
                        pristine,
                    )
                    self.assertEqual(store.audit_projection(), before)

    def test_current_source_authority_failure_and_ambiguity_precede_open(
        self,
    ) -> None:
        turn = make_turn(1, "0" * 64)
        snapshot, manifest, manifest_digest = source_manifest_for(turn)
        entry = entry_for(turn)
        owner_day = owner_day_revision_for(turn)

        def unavailable() -> tuple[
            EpisodicIndexSnapshot,
            tuple[CompleteTurn, ...],
            TemporalIntervalIndexSnapshot,
        ]:
            raise EpisodicMemoryError("synthetic_current_snapshot_unavailable")

        for authority_name, loader, expected_code in (
            (
                "unavailable",
                unavailable,
                "diary_current_source_authority_unavailable",
            ),
            (
                "ambiguous",
                lambda: object(),
                "diary_current_source_authority_ambiguous",
            ),
        ):
            for route in ("reflective", "owner_day"):
                with self.subTest(authority=authority_name, route=route):
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        path = root / "diary.sqlite3"
                        store = ReflectiveDiaryStore(
                            path,
                            current_source_snapshot_loader=loader,  # type: ignore[arg-type]
                        )
                        store.initialize()
                        pristine = {
                            item.name: item.read_bytes()
                            for item in root.iterdir()
                            if item.is_file()
                        }
                        before = store.audit_projection()
                        with patch.object(
                            store,
                            "_connect",
                            wraps=store._connect,
                        ) as connect:
                            with self.assertRaisesRegex(
                                EpisodicMemoryError,
                                expected_code,
                            ):
                                if route == "reflective":
                                    store.append_reflective_revision(
                                        entry=entry,
                                        turns=(turn,),
                                        source_snapshot=snapshot,
                                        source_manifest=manifest,
                                        source_manifest_digest=manifest_digest,
                                    )
                                else:
                                    store.append_owner_day_revision(
                                        revision=owner_day,
                                        turns=(turn,),
                                        source_snapshot=snapshot,
                                        source_manifest=manifest,
                                        source_manifest_digest=manifest_digest,
                                    )
                            connect.assert_not_called()
                        self.assertEqual(
                            {
                                item.name: item.read_bytes()
                                for item in root.iterdir()
                                if item.is_file()
                            },
                            pristine,
                        )
                        self.assertEqual(store.audit_projection(), before)

    def test_schema_and_row_drift_block_every_later_revision(self) -> None:
        turn = make_turn(1, "0" * 64)
        entry = entry_for(turn)
        snapshot, manifest, manifest_digest = source_manifest_for(turn)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "diary.sqlite3"
            store = diary_store(path, snapshot, (turn,))
            store.initialize()
            store.append_reflective_revision(
                entry=entry,
                turns=(turn,),
                source_snapshot=snapshot,
                source_manifest=manifest,
                source_manifest_digest=manifest_digest,
            )
            connection = sqlite3.connect(path)
            connection.execute("DROP TRIGGER diary_entries_no_update")
            connection.commit()
            connection.close()
            tampered = path.read_bytes()
            with self.assertRaisesRegex(EpisodicMemoryError, "diary_schema_rejected"):
                store.append_reflective_revision(
                    entry=entry_for(turn, revision=2, kind="late_backfill"),
                    turns=(turn,),
                    source_snapshot=snapshot,
                    source_manifest=manifest,
                    source_manifest_digest=manifest_digest,
                )
            self.assertEqual(path.read_bytes(), tampered)
            rejected = path.read_bytes()
            with self.assertRaisesRegex(EpisodicMemoryError, "diary_schema_rejected"):
                store.audit_projection()
            self.assertEqual(path.read_bytes(), rejected)

    def test_v3_and_queue_table_are_rejected_without_migration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "diary.sqlite3"
            store = diary_store(path)
            store.initialize()
            connection = sqlite3.connect(path)
            connection.execute("PRAGMA user_version = 3")
            connection.commit()
            connection.close()
            before = path.read_bytes()
            with self.assertRaisesRegex(EpisodicMemoryError, "diary_schema_rejected"):
                diary_store(path).initialize()
            self.assertEqual(path.read_bytes(), before)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "diary.sqlite3"
            store = diary_store(path)
            store.initialize()
            connection = sqlite3.connect(path)
            connection.execute("CREATE TABLE diary_job_events(event_digest TEXT)")
            connection.commit()
            connection.close()
            before = path.read_bytes()
            with self.assertRaisesRegex(EpisodicMemoryError, "diary_schema_rejected"):
                store.audit_projection()
            self.assertEqual(path.read_bytes(), before)

    def test_missing_authored_revision_is_typed_unavailable(self) -> None:
        plan = plan_diary_recall((), exact_factual_detail_requested=False)
        self.assertEqual(plan.state, "unavailable")
        self.assertEqual(plan.reason_category, "authored_revision_absent")
        self.assertFalse(plan.perspective_available)

    def test_prefix_capsule_is_append_only_source_bound_and_replay_safe(self) -> None:
        turn = make_turn(1, "0" * 64)
        snapshot = derive_snapshot((turn,))
        capsule = prefix_capsule_for(turn, snapshot)
        receipt = prefix_receipt_for(capsule, (turn,))
        self.assertIsInstance(receipt, tuple)
        self.assertEqual(receipt[0], capsule)
        self.assertEqual(len(receipt[1]), 64)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "diary.sqlite3"
            store = diary_store(path, snapshot, (turn,))
            store.initialize()
            self.assertEqual(
                store.append_prefix_capsule(
                    capsule,
                    source_snapshot=snapshot,
                    verification_receipt=receipt,
                    token_counter=prefix_token_counter,
                ),
                capsule.capsule_digest,
            )
            before = path.read_bytes()
            self.assertEqual(
                store.append_prefix_capsule(
                    capsule,
                    source_snapshot=snapshot,
                    verification_receipt=receipt,
                    token_counter=prefix_token_counter,
                ),
                capsule.capsule_digest,
            )
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(store.prefix_capsules(), (capsule,))
            self.assertEqual(store.audit_projection()["prefix_capsule_count"], 1)
            with (
                patch.object(store, "_load_current_source_authority") as loader,
                patch.object(store, "_connect") as connect,
                self.assertRaisesRegex(
                    EpisodicMemoryError,
                    "prefix_capsule_policy_binding_mismatch",
                ),
            ):
                store.append_prefix_capsule(
                    replace(capsule, policy_digest=digest("substituted-policy")),
                    source_snapshot=snapshot,
                    verification_receipt=receipt,
                    token_counter=prefix_token_counter,
                )
            loader.assert_not_called()
            connect.assert_not_called()
            self.assertEqual(path.read_bytes(), before)
            with self.assertRaisesRegex(
                EpisodicMemoryError,
                "prefix_capsule_regeneration_conflict",
            ):
                regenerated = replace(
                    capsule,
                    revision=2,
                    parent_capsule_digest=capsule.capsule_digest,
                )
                store.append_prefix_capsule(
                    regenerated,
                    source_snapshot=snapshot,
                    verification_receipt=prefix_receipt_for(
                        regenerated,
                        (turn,),
                    ),
                    token_counter=prefix_token_counter,
                )
            self.assertEqual(path.read_bytes(), before)
            connection = sqlite3.connect(path)
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE prefix_capsule_revisions SET source_end = 2"
                )
            connection.close()
            advanced_turn = make_turn(2, turn.turn_digest)
            advanced = derive_snapshot((turn, advanced_turn))
            with patch.object(store, "_connect") as connect:
                with self.assertRaisesRegex(
                    EpisodicMemoryError,
                    "prefix_capsule_source_snapshot_mismatch",
                ):
                    store.append_prefix_capsule(
                        capsule,
                        source_snapshot=advanced,
                        verification_receipt=receipt,
                        token_counter=prefix_token_counter,
                    )
                connect.assert_not_called()
            self.assertEqual(path.read_bytes(), before)

            forged = replace(
                capsule,
                source_characters=capsule.source_characters + 1,
                character_ratio_milli=(
                    (capsule.source_characters + 1)
                    * 1_000
                    // capsule.capsule_characters
                ),
            )
            with (
                patch.object(store, "_connect") as connect,
                self.assertRaisesRegex(
                    EpisodicMemoryError,
                    "prefix_(?:verification_capsule|capsule_capacity_binding)_mismatch",
                ),
            ):
                store.append_prefix_capsule(
                    forged,
                    source_snapshot=snapshot,
                    verification_receipt=receipt,
                    token_counter=prefix_token_counter,
                )
            connect.assert_not_called()
            self.assertEqual(path.read_bytes(), before)

            with (
                patch.object(store, "_connect") as connect,
                self.assertRaisesRegex(
                    EpisodicMemoryError,
                    "prefix_verified_source_closure_invalid",
                ),
            ):
                store.append_prefix_capsule(
                    capsule,
                    source_snapshot=snapshot,
                    verification_receipt=(capsule, "not-a-digest"),
                    token_counter=prefix_token_counter,
                )
            connect.assert_not_called()
            self.assertEqual(path.read_bytes(), before)

            snapshots = iter(
                (
                    (
                        snapshot,
                        (turn,),
                        TemporalIntervalIndexSnapshot.empty(
                            snapshot.archive_head_digest
                        ),
                    ),
                    (
                        advanced,
                        (turn, advanced_turn),
                        TemporalIntervalIndexSnapshot.empty(
                            advanced.archive_head_digest
                        ),
                    ),
                )
            )
            advancing_store = ReflectiveDiaryStore(
                path,
                current_source_snapshot_loader=lambda: next(snapshots),
            )
            with self.assertRaisesRegex(
                EpisodicMemoryError,
                "prefix_capsule_source_snapshot_mismatch",
            ):
                advancing_store.append_prefix_capsule(
                    capsule,
                    source_snapshot=snapshot,
                    verification_receipt=receipt,
                    token_counter=prefix_token_counter,
                )
            self.assertEqual(path.read_bytes(), before)

    def test_prefix_capsule_commit_recomputes_all_forged_metrics(
        self,
    ) -> None:
        turn = make_turn(1, "0" * 64)
        snapshot = derive_snapshot((turn,))
        capsule = prefix_capsule_for(turn, snapshot)
        receipt = prefix_receipt_for(capsule, (turn,))
        cases = (
            (
                "source_characters",
                (
                    ("source_characters", capsule.source_characters + 1),
                    (
                        "character_ratio_milli",
                        (capsule.source_characters + 1)
                        * 1_000
                        // capsule.capsule_characters,
                    ),
                ),
            ),
            (
                "source_bytes",
                (
                    ("source_bytes", capsule.source_bytes + 1),
                    (
                        "byte_ratio_milli",
                        (capsule.source_bytes + 1) * 1_000 // capsule.capsule_bytes,
                    ),
                ),
            ),
            (
                "source_tokens",
                (
                    ("source_tokens", capsule.source_tokens + 1),
                    (
                        "token_ratio_milli",
                        (capsule.source_tokens + 1)
                        * 1_000
                        // capsule.capsule_tokens,
                    ),
                ),
            ),
            (
                "capsule_characters",
                (
                    ("capsule_characters", capsule.capsule_characters + 1),
                    (
                        "character_ratio_milli",
                        capsule.source_characters
                        * 1_000
                        // (capsule.capsule_characters + 1),
                    ),
                ),
            ),
            (
                "capsule_bytes",
                (
                    ("capsule_bytes", capsule.capsule_bytes + 1),
                    (
                        "byte_ratio_milli",
                        capsule.source_bytes * 1_000 // (capsule.capsule_bytes + 1),
                    ),
                ),
            ),
            (
                "capsule_tokens",
                (
                    ("capsule_tokens", capsule.capsule_tokens + 1),
                    (
                        "token_ratio_milli",
                        capsule.source_tokens
                        * 1_000
                        // (capsule.capsule_tokens + 1),
                    ),
                ),
            ),
            (
                "character_ratio_milli",
                (("character_ratio_milli", capsule.character_ratio_milli + 1),),
            ),
            (
                "byte_ratio_milli",
                (("byte_ratio_milli", capsule.byte_ratio_milli + 1),),
            ),
            (
                "token_ratio_milli",
                (("token_ratio_milli", capsule.token_ratio_milli + 1),),
            ),
        )
        for name, changes in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                forged = replace(capsule)
                for field, value in changes:
                    object.__setattr__(forged, field, value)
                self.assertNotEqual(forged.capsule_digest, capsule.capsule_digest)
                forged_receipt = (forged, receipt[1])
                path = Path(directory) / "diary.sqlite3"
                store = diary_store(path, snapshot, (turn,))
                store.initialize()
                before = path.read_bytes()
                self.assertEqual(store.audit_projection()["prefix_capsule_count"], 0)
                with (
                    patch.object(store, "_connect") as connect,
                    self.assertRaisesRegex(
                        EpisodicMemoryError,
                        "prefix_capsule_(?:capacity_binding|size|ratio)_mismatch",
                    ),
                ):
                    store.append_prefix_capsule(
                        forged,
                        source_snapshot=snapshot,
                        verification_receipt=forged_receipt,
                        token_counter=prefix_token_counter,
                    )
                connect.assert_not_called()
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual(store.audit_projection()["prefix_capsule_count"], 0)

    def test_prefix_capsule_commit_rejects_equal_value_wrong_types(self) -> None:
        turn = make_turn(1, "0" * 64, owner="a", assistant="b")
        snapshot = derive_snapshot((turn,))
        capsule = prefix_capsule_for(turn, snapshot, text="x")
        receipt = prefix_receipt_for(capsule, (turn,))
        cases = tuple(
            (name, float(getattr(capsule, name)))
            for name in (
                "source_characters",
                "source_bytes",
                "source_tokens",
                "capsule_characters",
                "capsule_bytes",
                "capsule_tokens",
                "character_ratio_milli",
                "byte_ratio_milli",
                "token_ratio_milli",
            )
        ) + tuple(
            (name, True)
            for name in (
                "capsule_characters",
                "capsule_bytes",
                "capsule_tokens",
            )
        )
        for name, value in cases:
            with self.subTest(field=name, value_type=type(value).__name__):
                forged = replace(capsule)
                object.__setattr__(forged, name, value)
                forged_receipt = (forged, receipt[1])
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "diary.sqlite3"
                    store = diary_store(path, snapshot, (turn,))
                    store.initialize()
                    before = path.read_bytes()
                    with (
                        patch.object(store, "_connect") as connect,
                        self.assertRaisesRegex(
                            EpisodicMemoryError,
                            "prefix_capsule_primitive_type_invalid",
                        ),
                    ):
                        store.append_prefix_capsule(
                            forged,
                            source_snapshot=snapshot,
                            verification_receipt=forged_receipt,
                            token_counter=prefix_token_counter,
                        )
                    connect.assert_not_called()
                    self.assertEqual(path.read_bytes(), before)
                    self.assertEqual(
                        store.audit_projection()["prefix_capsule_count"],
                        0,
                    )

    def test_prefix_capsule_persistence_is_canonical_and_reconstructable(
        self,
    ) -> None:
        turn = make_turn(1, "0" * 64)
        snapshot = derive_snapshot((turn,))
        capsule = prefix_capsule_for(turn, snapshot)
        receipt = prefix_receipt_for(capsule, (turn,))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "diary.sqlite3"
            store = diary_store(path, snapshot, (turn,))
            store.initialize()
            store.append_prefix_capsule(
                capsule,
                source_snapshot=snapshot,
                verification_receipt=receipt,
                token_counter=prefix_token_counter,
            )
            connection = sqlite3.connect(path)
            row = connection.execute(
                "SELECT typeof(capsule_id), typeof(revision), "
                "typeof(capsule_digest), typeof(parent_capsule_digest), "
                "typeof(source_end), typeof(payload_json), payload_json "
                "FROM prefix_capsule_revisions"
            ).fetchone()
            connection.close()
            self.assertEqual(row[:6], ("text", "integer", "text", "text", "integer", "text"))
            self.assertEqual(
                row[6],
                diary_module.canonical_bytes(capsule.payload()).decode("utf-8"),
            )
            self.assertEqual(diary_module._prefix_capsule_from_json(row[6]), capsule)
            reopened = diary_store(path, snapshot, (turn,))
            self.assertEqual(reopened.prefix_capsules(), (capsule,))

        invalid_payloads = (
            '{"schema":"x","schema":"x"}',
            '{"value":NaN}',
            diary_module.canonical_bytes(capsule.payload()).decode("utf-8") + " ",
        )
        for payload_json in invalid_payloads:
            with self.subTest(payload=payload_json[-12:]), self.assertRaisesRegex(
                EpisodicMemoryError,
                "prefix_capsule_payload_noncanonical",
            ):
                diary_module._prefix_capsule_from_json(payload_json)

    def test_prefix_capsule_sqlite_types_and_columns_are_authoritative(self) -> None:
        turn = make_turn(1, "0" * 64)
        snapshot = derive_snapshot((turn,))
        capsule = prefix_capsule_for(turn, snapshot)
        payload_json = diary_module.canonical_bytes(capsule.payload()).decode("utf-8")
        cases = (
            ("wrong_storage_type", capsule.capsule_id, 1.5),
            ("payload_column_disagreement", "substituted-capsule", 1),
        )
        for name, capsule_id, revision in cases:
            with self.subTest(name=name):
                connection = sqlite3.connect(":memory:")
                connection.row_factory = sqlite3.Row
                connection.execute(
                    "CREATE TABLE prefix_capsule_revisions ("
                    "capsule_id, revision, capsule_digest, "
                    "parent_capsule_digest, source_end, payload_json)"
                )
                connection.execute(
                    "INSERT INTO prefix_capsule_revisions VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        capsule_id,
                        revision,
                        capsule.capsule_digest,
                        capsule.parent_capsule_digest,
                        capsule.source_end,
                        payload_json,
                    ),
                )
                store = diary_store(Path("synthetic-unused.sqlite3"))
                with self.assertRaisesRegex(
                    EpisodicMemoryError,
                    "prefix_capsule_chain_drifted",
                ):
                    store._prefix_capsule_records(connection)
                connection.close()

    def test_profile_v2_event_current_atomic_replay_and_reopen(self) -> None:
        turn = make_turn(1, "0" * 64)
        snapshot = derive_snapshot((turn,))
        intent = ProfileStateIntent(
            intent_id="profile-intent-1",
            action="initialize",
            module_id="relationship_state",
            field_id="relationship_state.intimacy_headline",
            actor="owner",
            reason_category="owner_confirmed",
            requested_value=12_500,
            requested_delta=None,
            expected_event_digest="0" * 64,
            raw_source_digest=snapshot.source_closure_digest,
            p08_source_digest=snapshot.temporal_snapshot_digest,
            trusted_time_digest=turn.draft.time_binding.binding_digest,
            delivered_turn_id=turn.draft.turn_id,
            **profile_source_fields(snapshot, turn),
            delivered_at_utc=turn.draft.time_binding.delivered_at_utc.isoformat(
                timespec="microseconds"
            ).replace("+00:00", "Z"),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "diary.sqlite3"
            store = diary_store(path, snapshot, (turn,))
            store.initialize()
            initial = store.current_profile_values()
            self.assertEqual(len(initial), 8)
            self.assertTrue(all(item.state == "uninitialized" for item in initial))
            receipt = store.append_profile_state_intent(intent)
            self.assertTrue(receipt.mutated)
            current = store.current_profile_values()[0]
            self.assertEqual(current.scaled_value, 12_500)
            before_replay = path.read_bytes()
            replay = store.append_profile_state_intent(intent)
            self.assertTrue(replay.replayed)
            self.assertFalse(replay.mutated)
            self.assertEqual(replay.event_digest, receipt.event_digest)
            self.assertEqual(path.read_bytes(), before_replay)
            reopened = diary_store(path, snapshot, (turn,))
            self.assertEqual(reopened.current_profile_values()[0], current)
            connection = sqlite3.connect(path)
            row = connection.execute(
                "SELECT typeof(sequence), typeof(event_id), typeof(intent_digest), "
                "typeof(event_digest), typeof(payload_json) FROM profile_state_events"
            ).fetchone()
            triggers = {
                item[0]
                for item in connection.execute(
                    "SELECT name FROM sqlite_schema WHERE type='trigger' "
                    "AND name LIKE 'profile_state_events_no_%'"
                )
            }
            connection.close()
            self.assertEqual(row, ("integer", "text", "text", "text", "text"))
            self.assertEqual(
                triggers,
                {
                    "profile_state_events_no_update",
                    "profile_state_events_no_delete",
                },
            )

    def test_profile_v2_correction_and_exact_rollback_target_are_append_only(
        self,
    ) -> None:
        turn = make_turn(1, "0" * 64)
        snapshot = derive_snapshot((turn,))
        delivered_at = turn.draft.time_binding.delivered_at_utc.isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")

        def intent(
            intent_id: str,
            *,
            action: str,
            value: int,
            head: str,
            target_id: str | None = None,
            target_digest: str | None = None,
        ) -> ProfileStateIntent:
            return ProfileStateIntent(
                intent_id=intent_id,
                action=action,
                module_id="relationship_state",
                field_id="relationship_state.intimacy_headline",
                actor="owner",
                reason_category=(
                    "owner_correction" if action == "correct" else "owner_rollback"
                    if action == "rollback"
                    else "owner_confirmed"
                ),
                requested_value=value,
                requested_delta=None,
                expected_event_digest=head,
                raw_source_digest=snapshot.source_closure_digest,
                p08_source_digest=snapshot.temporal_snapshot_digest,
                trusted_time_digest=turn.draft.time_binding.binding_digest,
                delivered_turn_id=turn.draft.turn_id,
                **profile_source_fields(snapshot, turn),
                delivered_at_utc=delivered_at,
                rollback_target_event_id=target_id,
                rollback_target_event_digest=target_digest,
            )

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "diary.sqlite3"
            store = diary_store(path, snapshot, (turn,))
            store.initialize()
            initialized = store.append_profile_state_intent(
                intent(
                    "profile-rollback-initialize",
                    action="initialize",
                    value=12_500,
                    head="0" * 64,
                )
            )
            corrected = store.append_profile_state_intent(
                intent(
                    "profile-distinct-correction",
                    action="correct",
                    value=25_000,
                    head=initialized.event_digest or "",
                )
            )
            target = store.profile_rollback_target(
                "relationship_state.intimacy_headline",
                12_500,
            )
            rollback = intent(
                "profile-exact-rollback",
                action="rollback",
                value=12_500,
                head=corrected.event_digest or "",
                target_id=target.event_id,
                target_digest=target.event_digest,
            )
            pristine = path.read_bytes()
            forged = replace(
                rollback,
                intent_id="profile-forged-rollback-target",
                rollback_target_event_digest="f" * 64,
            )
            with self.assertRaisesRegex(
                EpisodicMemoryError,
                "profile_state_rollback_target_mismatch",
            ):
                store.append_profile_state_intent(forged)
            self.assertEqual(path.read_bytes(), pristine)
            committed = store.append_profile_state_intent(rollback)
            self.assertTrue(committed.mutated)
            self.assertEqual(store.current_profile_values()[0].scaled_value, 12_500)
            after = path.read_bytes()
            replay = store.append_profile_state_intent(rollback)
            self.assertTrue(replay.replayed)
            self.assertFalse(replay.mutated)
            self.assertEqual(path.read_bytes(), after)
            connection = sqlite3.connect(path)
            rows = tuple(
                connection.execute(
                    "SELECT payload_json FROM profile_state_events ORDER BY sequence"
                )
            )
            connection.close()
            self.assertEqual(len(rows), 3)
            rollback_payload = json.loads(rows[-1][0])
            self.assertEqual(rollback_payload["action"], "rollback")
            self.assertEqual(
                rollback_payload["rollback_target_event_id"],
                target.event_id,
            )
            self.assertEqual(
                rollback_payload["rollback_target_event_digest"],
                target.event_digest,
            )

    def test_profile_v2_source_substitution_rejects_before_derivative_open(
        self,
    ) -> None:
        turn = make_turn(1, "0" * 64)
        snapshot = derive_snapshot((turn,))
        delivered_at = turn.draft.time_binding.delivered_at_utc.isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")
        valid = ProfileStateIntent(
            intent_id="profile-intent-source-binding",
            action="initialize",
            module_id="relationship_state",
            field_id="relationship_state.intimacy_headline",
            actor="owner",
            reason_category="owner_confirmed",
            requested_value=12_500,
            requested_delta=None,
            expected_event_digest="0" * 64,
            raw_source_digest=snapshot.source_closure_digest,
            p08_source_digest=snapshot.temporal_snapshot_digest,
            trusted_time_digest=turn.draft.time_binding.binding_digest,
            delivered_turn_id=turn.draft.turn_id,
            **profile_source_fields(snapshot, turn),
            delivered_at_utc=delivered_at,
        )
        substitutions = (
            ("raw", replace(valid, raw_source_digest="1" * 64)),
            ("p08", replace(valid, p08_source_digest="2" * 64)),
            ("trusted_time", replace(valid, trusted_time_digest="3" * 64)),
            ("turn", replace(valid, delivered_turn_id="substituted-turn")),
            ("delivery_ack", replace(valid, delivery_ack_digest="4" * 64)),
            (
                "source_reference",
                replace(valid, delivered_source_reference_digest="5" * 64),
            ),
            (
                "delivered_at",
                replace(valid, delivered_at_utc="2026-08-20T00:00:00.000000Z"),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "diary.sqlite3"
            store = diary_store(path, snapshot, (turn,))
            store.initialize()
            pristine = path.read_bytes()
            for name, substituted in substitutions:
                with self.subTest(name=name), patch.object(
                    store, "_connect", wraps=store._connect
                ) as connect:
                    with self.assertRaises(EpisodicMemoryError):
                        store.append_profile_state_intent(substituted)
                    connect.assert_not_called()
                    self.assertEqual(path.read_bytes(), pristine)

    def test_profile_v2_source_advance_between_preopen_and_begin_preserves_bytes(
        self,
    ) -> None:
        first_turn = make_turn(1, "0" * 64)
        second_turn = make_turn(2, first_turn.turn_digest)
        first_snapshot = derive_snapshot((first_turn,))
        second_snapshot = derive_snapshot((first_turn, second_turn))
        authorities = iter(
            (
                (
                    first_snapshot,
                    (first_turn,),
                    TemporalIntervalIndexSnapshot.empty(
                        first_snapshot.archive_head_digest
                    ),
                ),
                (
                    second_snapshot,
                    (first_turn, second_turn),
                    TemporalIntervalIndexSnapshot.empty(
                        second_snapshot.archive_head_digest
                    ),
                ),
            )
        )
        delivered_at = first_turn.draft.time_binding.delivered_at_utc.isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")
        intent = ProfileStateIntent(
            intent_id="profile-post-begin-source-advance",
            action="initialize",
            module_id="relationship_state",
            field_id="relationship_state.intimacy_headline",
            actor="owner",
            reason_category="owner_confirmed",
            requested_value=12_500,
            requested_delta=None,
            expected_event_digest="0" * 64,
            raw_source_digest=first_snapshot.source_closure_digest,
            p08_source_digest=first_snapshot.temporal_snapshot_digest,
            trusted_time_digest=first_turn.draft.time_binding.binding_digest,
            delivered_turn_id=first_turn.draft.turn_id,
            **profile_source_fields(first_snapshot, first_turn),
            delivered_at_utc=delivered_at,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "diary.sqlite3"
            store = ReflectiveDiaryStore(
                path,
                current_source_snapshot_loader=lambda: next(authorities),
            )
            store.initialize()
            pristine = path.read_bytes()
            with self.assertRaisesRegex(
                EpisodicMemoryError,
                "profile_state_raw_source_mismatch",
            ):
                store.append_profile_state_intent(intent)
            self.assertEqual(path.read_bytes(), pristine)
            connection = sqlite3.connect(path)
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM profile_state_events"
                ).fetchone()[0],
                0,
            )
            connection.close()

    def test_profile_v2_episode_end_is_bounded_and_exactly_once(self) -> None:
        turn = make_turn(1, "0" * 64)
        temporal_snapshot = terminal_temporal_snapshot(turn)
        snapshot = derive_snapshot((turn,), temporal_snapshot=temporal_snapshot)
        terminal_episode = temporal_snapshot.episodes[0]
        terminal_revision = terminal_episode.revisions[-1]
        terminal_reference = snapshot.source_references[0]
        delivered_at = turn.draft.time_binding.delivered_at_utc.isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")

        def intent(
            intent_id: str,
            *,
            action: str,
            actor: str,
            reason: str,
            requested_value: int | None,
            requested_delta: int | None,
            expected: str,
            episode: str | None = None,
        ) -> ProfileStateIntent:
            return ProfileStateIntent(
                intent_id=intent_id,
                action=action,
                module_id="relationship_state",
                field_id="relationship_state.intimacy_headline",
                actor=actor,
                reason_category=reason,
                requested_value=requested_value,
                requested_delta=requested_delta,
                expected_event_digest=expected,
                raw_source_digest=snapshot.source_closure_digest,
                p08_source_digest=snapshot.temporal_snapshot_digest,
                trusted_time_digest=turn.draft.time_binding.binding_digest,
                delivered_turn_id=turn.draft.turn_id,
                **profile_source_fields(snapshot, turn),
                delivered_at_utc=delivered_at,
                episode_revision_id=episode,
                p08_episode_id=(
                    terminal_episode.episode_digest if episode is not None else None
                ),
                p08_interval_id=(
                    terminal_episode.interval_id if episode is not None else None
                ),
                p08_terminal_revision=(
                    terminal_revision.revision if episode is not None else None
                ),
                p08_terminal_revision_digest=(
                    terminal_revision.revision_digest if episode is not None else None
                ),
                p08_terminal_event_sequence=(
                    terminal_revision.p08_event_sequence
                    if episode is not None
                    else None
                ),
                p08_terminal_event_kind=(
                    terminal_revision.p08_event_kind if episode is not None else None
                ),
                p08_source_reference_digest=(
                    terminal_reference.source_reference_digest
                    if episode is not None
                    else None
                ),
            )

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "diary.sqlite3"
            store = diary_store(
                path,
                snapshot,
                (turn,),
                temporal_snapshot,
            )
            store.initialize()
            initialized = store.append_profile_state_intent(
                intent(
                    "profile-initialize-for-episode",
                    action="initialize",
                    actor="owner",
                    reason="owner_confirmed",
                    requested_value=12_500,
                    requested_delta=None,
                    expected="0" * 64,
                )
            )
            episode = intent(
                "profile-episode-slot-1-r3-e17",
                action="delta",
                actor="myuna",
                reason="episode_end",
                requested_value=None,
                requested_delta=20_000,
                expected=initialized.event_digest,
                episode="p08-terminal-" + terminal_revision.revision_digest[:48],
            )
            committed = store.append_profile_state_intent(episode)
            self.assertTrue(committed.mutated)
            self.assertEqual(store.current_profile_values()[0].scaled_value, 32_500)
            connection = sqlite3.connect(path)
            payload = connection.execute(
                "SELECT payload_json FROM profile_state_events WHERE event_id = ?",
                (episode.intent_id,),
            ).fetchone()[0]
            connection.close()
            event_payload = json.loads(payload)
            self.assertEqual(event_payload["requested_delta"], 20_000)
            self.assertEqual(event_payload["applied_delta"], 20_000)
            pristine = path.read_bytes()
            pristine_current = store.current_profile_values()
            connection = sqlite3.connect(path)
            pristine_event_count = connection.execute(
                "SELECT COUNT(*) FROM profile_state_events"
            ).fetchone()[0]
            connection.close()
            source_substitutions = {
                "episode_id": {"p08_episode_id": "b" * 64},
                "interval_id": {"p08_interval_id": "ti_" + "b" * 64},
                "revision": {"p08_terminal_revision": 999},
                "revision_digest": {"p08_terminal_revision_digest": "c" * 64},
                "event_sequence": {"p08_terminal_event_sequence": 999},
                "surrogate_revision_as_sequence": {
                    "p08_terminal_event_sequence": terminal_revision.p08_revision
                },
                "event_kind": {"p08_terminal_event_kind": "revoke"},
                "source_reference": {"p08_source_reference_digest": "d" * 64},
                "derived_revision_id": {
                    "episode_revision_id": "p08-terminal-" + "e" * 48
                },
                "self_consistent_forged_terminal": {
                    "episode_revision_id": "p08-terminal-" + "f" * 48,
                    "p08_episode_id": "a" * 64,
                    "p08_interval_id": "ti_" + "f" * 64,
                    "p08_terminal_revision": 999,
                    "p08_terminal_revision_digest": "f" * 64,
                    "p08_terminal_event_sequence": 999,
                    "p08_terminal_event_kind": "revoke",
                    "p08_source_reference_digest": "f" * 64,
                },
            }
            for name, changes in source_substitutions.items():
                substituted = replace(
                    episode,
                    intent_id="profile-forged-terminal-" + name.replace("_", "-"),
                    **changes,
                )
                with self.subTest(name=name), patch.object(
                    store, "_connect", wraps=store._connect
                ) as connect:
                    with self.assertRaisesRegex(
                        EpisodicMemoryError,
                        "profile_state_terminal_source_mismatch",
                    ):
                        store.append_profile_state_intent(substituted)
                    connect.assert_not_called()
                    self.assertEqual(path.read_bytes(), pristine)
                    self.assertEqual(store.current_profile_values(), pristine_current)
                    connection = sqlite3.connect(path)
                    self.assertEqual(
                        connection.execute(
                            "SELECT COUNT(*) FROM profile_state_events"
                        ).fetchone()[0],
                        pristine_event_count,
                    )
                    connection.close()
            replay = store.append_profile_state_intent(episode)
            self.assertTrue(replay.replayed)
            self.assertEqual(path.read_bytes(), pristine)
            duplicate = replace(
                episode,
                intent_id="profile-episode-slot-1-r3-e17-duplicate",
                expected_event_digest=committed.event_digest,
            )
            with self.assertRaisesRegex(
                EpisodicMemoryError, "profile_state_episode_replay_conflict"
            ):
                store.append_profile_state_intent(duplicate)
            self.assertEqual(path.read_bytes(), pristine)
            oversize = replace(
                episode,
                intent_id="profile-episode-slot-2-r1-e18",
                episode_revision_id="slot-2-terminal-r1-e18",
                requested_delta=20_001,
                expected_event_digest=committed.event_digest,
            )
            with patch.object(store, "_connect", wraps=store._connect) as connect:
                with self.assertRaisesRegex(
                    EpisodicMemoryError, "profile_state_delta_limit_rejected"
                ):
                    store.append_profile_state_intent(oversize)
                connect.assert_not_called()
            self.assertEqual(path.read_bytes(), pristine)

    def test_profile_v2_cancel_terminal_variant_is_exactly_source_bound(self) -> None:
        turn = make_turn(1, "0" * 64)
        temporal_snapshot = terminal_temporal_snapshot(
            turn,
            state="cancelled",
            interval_id="ti_" + "c" * 64,
            event_sequence=23,
        )
        snapshot = derive_snapshot((turn,), temporal_snapshot=temporal_snapshot)
        episode = temporal_snapshot.episodes[0]
        terminal = episode.revisions[-1]
        source_reference = snapshot.source_references[0]
        delivered_at = turn.draft.time_binding.delivered_at_utc.isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")

        def intent(
            intent_id: str,
            *,
            actor: str,
            action: str,
            reason: str,
            value: int | None,
            delta: int | None,
            head: str,
        ) -> ProfileStateIntent:
            terminal_fields = (
                {
                    "episode_revision_id": (
                        "p08-terminal-" + terminal.revision_digest[:48]
                    ),
                    "p08_episode_id": episode.episode_digest,
                    "p08_interval_id": episode.interval_id,
                    "p08_terminal_revision": terminal.revision,
                    "p08_terminal_revision_digest": terminal.revision_digest,
                    "p08_terminal_event_sequence": terminal.p08_event_sequence,
                    "p08_terminal_event_kind": terminal.p08_event_kind,
                    "p08_source_reference_digest": (
                        source_reference.source_reference_digest
                    ),
                }
                if reason == "episode_end"
                else {}
            )
            return ProfileStateIntent(
                intent_id=intent_id,
                action=action,
                module_id="relationship_state",
                field_id="relationship_state.intimacy_headline",
                actor=actor,
                reason_category=reason,
                requested_value=value,
                requested_delta=delta,
                expected_event_digest=head,
                raw_source_digest=snapshot.source_closure_digest,
                p08_source_digest=snapshot.temporal_snapshot_digest,
                trusted_time_digest=turn.draft.time_binding.binding_digest,
                delivered_turn_id=turn.draft.turn_id,
                **profile_source_fields(snapshot, turn),
                delivered_at_utc=delivered_at,
                **terminal_fields,
            )

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "diary.sqlite3"
            store = diary_store(path, snapshot, (turn,), temporal_snapshot)
            store.initialize()
            initialized = store.append_profile_state_intent(
                intent(
                    "profile-cancel-variant-init",
                    actor="owner",
                    action="initialize",
                    reason="owner_confirmed",
                    value=0,
                    delta=None,
                    head="0" * 64,
                )
            )
            committed = store.append_profile_state_intent(
                intent(
                    "profile-cancel-variant-delta",
                    actor="myuna",
                    action="delta",
                    reason="episode_end",
                    value=None,
                    delta=-10_000,
                    head=initialized.event_digest or "",
                )
            )
            self.assertTrue(committed.mutated)
            self.assertEqual(store.current_profile_values()[0].scaled_value, -10_000)

    def test_profile_v2_corrupt_current_is_read_only_until_explicit_rebuild(
        self,
    ) -> None:
        turn = make_turn(1, "0" * 64)
        snapshot = derive_snapshot((turn,))
        delivered_at = turn.draft.time_binding.delivered_at_utc.isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")
        intent = ProfileStateIntent(
            intent_id="profile-current-rebuild-source",
            action="initialize",
            module_id="relationship_state",
            field_id="relationship_state.intimacy_headline",
            actor="owner",
            reason_category="owner_confirmed",
            requested_value=12_500,
            requested_delta=None,
            expected_event_digest="0" * 64,
            raw_source_digest=snapshot.source_closure_digest,
            p08_source_digest=snapshot.temporal_snapshot_digest,
            trusted_time_digest=turn.draft.time_binding.binding_digest,
            delivered_turn_id=turn.draft.turn_id,
            **profile_source_fields(snapshot, turn),
            delivered_at_utc=delivered_at,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "diary.sqlite3"
            store = diary_store(path, snapshot, (turn,))
            store.initialize()
            store.append_profile_state_intent(intent)
            connection = sqlite3.connect(path)
            events_before = tuple(
                connection.execute(
                    "SELECT sequence, event_id, event_digest, payload_json "
                    "FROM profile_state_events ORDER BY sequence"
                )
            )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE profile_state_events SET event_id = 'forbidden'"
                )
            connection.execute(
                "UPDATE profile_current_projection SET scaled_value = 999 "
                "WHERE field_id = 'relationship_state.intimacy_headline'"
            )
            connection.commit()
            connection.close()
            corrupt = path.read_bytes()
            with self.assertRaisesRegex(
                EpisodicMemoryError, "profile_state_projection_drifted"
            ):
                store.current_profile_values()
            self.assertEqual(path.read_bytes(), corrupt)
            rebuilt = store.rebuild_profile_current_values()
            self.assertEqual(rebuilt[0].scaled_value, 12_500)
            self.assertEqual(store.current_profile_values(), rebuilt)
            connection = sqlite3.connect(path)
            events_after = tuple(
                connection.execute(
                    "SELECT sequence, event_id, event_digest, payload_json "
                    "FROM profile_state_events ORDER BY sequence"
                )
            )
            connection.close()
            self.assertEqual(events_after, events_before)


if __name__ == "__main__":
    unittest.main()
