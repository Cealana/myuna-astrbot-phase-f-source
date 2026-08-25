from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from myuna_core.active_temporal_context.time import TrustedTimeSample
from myuna_core.active_temporal_context.protocol import build_active_snapshot_receipt
from myuna_core.authenticated_conversation import (
    SCHEMA_VERSION as AUTH_SCHEMA,
    AuthenticatedConversationContext,
)
from myuna_core.external_context.contracts import EgressSafetySignals
from myuna_core.episodic_memory.contracts import (
    HISTORICAL_RAW_RECALL_EGRESS_V1_DIGEST,
    REFLECTIVE_DIARY_EGRESS_V1_DIGEST,
    REFLECTIVE_DIARY_STYLE_V1_DIGEST,
    TurnTimeCorrection,
    calendar_zone_selection_digest,
)
from myuna_core.episodic_memory.runtime_context import EpisodicTurnProvenance
from myuna_core.episodic_memory.owner_day import OwnerDayPolicy
from myuna_core.episodic_memory import store as store_module

import p07_owner_private_memory_runtime_v1 as runtime
import p07_owner_day_diary_v2 as diary
import telegram_owner_runtime_gateway as gateway


class FakeConnection:
    def __init__(self) -> None:
        self.sent = bytearray()

    def sendall(self, value: bytes) -> None:
        self.sent.extend(value)


def auth(index: int = 1) -> AuthenticatedConversationContext:
    return AuthenticatedConversationContext(
        schema_version=AUTH_SCHEMA,
        request_id=f"request-synthetic-p08-{index}",
        correlation_id=f"correlation-synthetic-p08-{index}",
        client_id="telegram-owner-private",
        channel_kind="astrbot_telegram",
        binding_id="binding-synthetic-owner",
        principal_id="principal-synthetic-owner",
        namespace_id="namespace-synthetic-owner",
        authority_level="owner",
        channel_instance="telegram-synthetic",
        conversation_id="conversation-synthetic",
        conversation_kind="private",
        event_id=f"event-synthetic-p08-{index}",
        trace_id=f"trace-synthetic-p08-{index}",
        occurred_at=datetime(2026, 8, 8, tzinfo=timezone.utc),
        delivery_capabilities=("text",),
    )


def sample() -> TrustedTimeSample:
    return TrustedTimeSample(
        datetime(2026, 8, 8, 12, tzinfo=timezone.utc),
        "myuna-trusted-local-v1",
        "trusted_local",
        7,
        authority="systemd-timesyncd",
        uncertainty_microseconds=1_000,
        synchronized=True,
        boot_id="synthetic-boot",
        monotonic_ns=200,
    )


def selection(root: Path) -> runtime.OwnerPrivateMemorySelection:
    runtime_root = root / "owner-private-memory-runtime-v1"
    runtime_root.mkdir(mode=0o700, parents=False, exist_ok=True)
    return runtime.OwnerPrivateMemorySelection(
        memory_release_set_id="a" * 64,
        parent_release_set_id="b" * 64,
        parent_manifest_digest="c" * 64,
        parent_selector_digest="d" * 64,
        parent_epoch_id="telegram-owner-private-external-d-reset-v7",
        parent_epoch_revision=63,
        policy_overlay_id="e" * 64,
        archive_id="owner-private-memory-runtime-v1",
        runtime_root=runtime_root,
        expected_uid=os.geteuid(),
        expected_gid=os.getegid(),
        egress_policy_digest=HISTORICAL_RAW_RECALL_EGRESS_V1_DIGEST,
        diary_egress_policy_digest=REFLECTIVE_DIARY_EGRESS_V1_DIGEST,
        diary_style_contract_digest=REFLECTIVE_DIARY_STYLE_V1_DIGEST,
        diary_persona_digest="6" * 64,
        diary_model="deepseek-v4-flash",
        diary_model_role="p07_external_daily_reflective_diary",
        p08_lifecycle_start_watermark=0,
        calendar_zone="Asia/Shanghai",
        calendar_zone_config_digest=calendar_zone_selection_digest("Asia/Shanghai"),
    )


def owner_day_selection(
    root: Path,
) -> tuple[diary.OwnerPrivateMemorySelectionV4, diary.OwnerDayDiarySelectionV2]:
    runtime_root = root / "owner-private-memory-runtime-v1"
    runtime_root.mkdir(mode=0o700, parents=False, exist_ok=True)
    memory = diary.OwnerPrivateMemorySelectionV4(
        memory_release_set_id="a" * 64,
        parent_release_set_id="b" * 64,
        parent_manifest_digest="c" * 64,
        parent_selector_digest="d" * 64,
        parent_epoch_id="telegram-owner-private-external-d-reset-v7",
        parent_epoch_revision=63,
        policy_overlay_id="e" * 64,
        archive_id="owner-private-memory-runtime-v1",
        runtime_root=runtime_root,
        expected_uid=os.geteuid(),
        expected_gid=os.getegid(),
        egress_policy_digest=HISTORICAL_RAW_RECALL_EGRESS_V1_DIGEST,
        p08_lifecycle_start_watermark=0,
        calendar_zone="Asia/Shanghai",
        calendar_zone_config_digest=calendar_zone_selection_digest("Asia/Shanghai"),
    )
    selected_diary = diary.OwnerDayDiarySelectionV2(
        memory_release_set_id=memory.memory_release_set_id,
        parent_release_set_id=memory.parent_release_set_id,
        policy_overlay_id=memory.policy_overlay_id,
        archive_id=memory.archive_id,
        expected_uid=memory.expected_uid,
        expected_gid=memory.expected_gid,
        owner_day_policy=OwnerDayPolicy(),
        persona_digest="9" * 64,
    )
    return memory, selected_diary


def provenance(context) -> EpisodicTurnProvenance:
    return EpisodicTurnProvenance(
        parent_release_set_id=context.parent_release_set_id,
        policy_overlay_id=context.policy_overlay_id,
        parent_epoch_id=context.parent_epoch_id,
        parent_epoch_revision=context.parent_epoch_revision,
        archive_id=context.archive_id,
        archive_head_digest=context.archive_head_digest,
        archive_turn_count=context.archive_turn_count,
        recall_state=context.recall_state,
        recall_reason_category=context.recall_reason_category,
        recall_source_closure_digest=context.recall_source_closure_digest,
        recall_selection_digest=context.recall_selection_digest,
        projection_digest="1" * 64,
        selection_digest="2" * 64,
        source_ranges=(),
        profile_revisions=(),
        trusted_time_binding_digest=context.trusted_time_binding.binding_digest,
        temporal_projection_digest=context.temporal_projection_digest,
        temporal_coverage_state=context.temporal_coverage_state,
        temporal_state=context.temporal_state,
        temporal_reason_category=context.temporal_reason_category,
        temporal_source_closure_digest=context.temporal_source_closure_digest,
        temporal_selection_digest=context.temporal_selection_digest,
    )


def prepare(
    memory: runtime.OwnerPrivateMemoryRuntime,
    *,
    token: str,
    turn_id: str,
    index: int,
) -> runtime.PreparedMemoryTurn:
    trusted_sample = sample()
    context = memory.build_context(
        authenticated_context=auth(index),
        current_message=f"Synthetic P08 owner turn {index}",
        received_monotonic_ns=100,
        p08_temporal_coverage_state="complete",
        trusted_time_sample=trusted_sample,
        trusted_time_unresolved_reason=None,
        active_snapshot_receipt=build_active_snapshot_receipt(
            request_id=f"synthetic-p08-active-{index}",
            after_event_sequence=0,
            fact_count=0,
            lifecycle_transitions=(),
            lifecycle_watermark=0,
            lifecycle_has_more=False,
            trusted_time=trusted_sample.as_payload(),
        ),
        safety=EgressSafetySignals(classifier_available=True),
    )
    return memory.prepare_delivery(
        delivery_token=token,
        turn_id=turn_id,
        runtime_context=context,
        assistant_reply=f"Synthetic P08 assistant turn {index}",
        provenance=provenance(context),
        committed_monotonic_ns=300,
        source_occurred_at_utc=auth(index).occurred_at,
    )


def callback(
    memory: runtime.OwnerPrivateMemoryRuntime,
    *,
    token: str,
    outcome: str,
    boot_id: str | None = "synthetic-boot",
) -> bool:
    with patch.object(
        gateway, "read_current_boot_identity", return_value=boot_id
    ):
        return gateway._process_memory_delivery_outcome(
            FakeConnection(),
            {
                "delivery_token": token,
                "outcome": outcome,
                "schema": gateway.DELIVERY_OUTCOME_SCHEMA,
            },
            memory_runtime=memory,
        )


class TrustedTimeEpisodeIntervalIntegrationTests(unittest.TestCase):
    def test_gateway_captures_one_marker_for_first_close_and_none_for_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
                token = "4" * 64
                opened = prepare(
                    memory,
                    token=token,
                    turn_id="synthetic-p08-gateway-delivered",
                    index=1,
                )
                self.assertEqual(opened.episode.state, "OPEN_EXACT_START")
                with patch.object(gateway, "_audit_stage"), patch.object(
                    gateway.time, "monotonic_ns", return_value=400
                ) as clock:
                    self.assertTrue(callback(memory, token=token, outcome="delivered"))
                    self.assertTrue(callback(memory, token=token, outcome="delivered"))
                clock.assert_called_once_with()
                stored = memory.journal.resolve(
                    delivery_token=token,
                    outcome="delivered",
                    delivered_monotonic_ns=None,
                )
                self.assertTrue(stored.replayed)
                self.assertEqual(stored.delivered_monotonic_ns, 400)
                self.assertEqual(stored.episode.state, "CLOSED_EXACT")
                self.assertEqual(stored.episode.episode_id, opened.episode.episode_id)
                self.assertEqual(memory.archive.metadata()["turn_count"], 1)

    def test_gateway_boot_mismatch_or_absence_preserves_unresolved_raw_close(self) -> None:
        for index, boot_id in enumerate(("synthetic-new-boot", None), start=10):
            with self.subTest(boot_id=boot_id), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with patch.object(runtime, "RUNTIME_ROOT", root):
                    memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                    memory.initialize()
                    token = str(index % 10) * 64
                    prepare(
                        memory,
                        token=token,
                        turn_id=f"synthetic-p08-gateway-boot-{index}",
                        index=index,
                    )
                    with patch.object(gateway, "_audit_stage"), patch.object(
                        gateway.time, "monotonic_ns", return_value=400
                    ):
                        self.assertTrue(
                            callback(
                                memory,
                                token=token,
                                outcome="delivered",
                                boot_id=boot_id,
                            )
                        )
                    stored = memory.journal.resolve(
                        delivery_token=token,
                        outcome="delivered",
                        delivered_monotonic_ns=None,
                        delivered_boot_id=None,
                    )
                    self.assertTrue(stored.replayed)
                    self.assertEqual(stored.delivered_monotonic_ns, 400)
                    self.assertEqual(stored.delivered_boot_id, boot_id)
                    self.assertEqual(stored.episode.state, "CLOSED_TIME_UNRESOLVED")
                    self.assertIsNone(stored.episode.end_utc)
                    self.assertIsNone(stored.episode.owner_day)

    def test_factual_connection_closes_before_derivative_consumers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
                token = "8" * 64
                prepare(
                    memory,
                    token=token,
                    turn_id="synthetic-p08-close-before-derivatives",
                    index=8,
                )
                closed = False
                original_close = store_module._close_connection
                original_archive = memory._archive_resolution

                def tracked_close(*args, **kwargs) -> None:
                    nonlocal closed
                    original_close(*args, **kwargs)
                    closed = True

                def assert_closed(resolution):
                    self.assertTrue(closed)
                    return original_archive(resolution)

                with patch.object(
                    store_module, "_close_connection", side_effect=tracked_close
                ), patch.object(
                    memory, "_archive_resolution", side_effect=assert_closed
                ):
                    outcome = memory.resolve_delivery(
                        delivery_token=token,
                        outcome="delivered",
                        delivered_monotonic_ns=400,
                        delivered_boot_id="synthetic-boot",
                    )
                self.assertTrue(closed)
                self.assertTrue(outcome.archive_written)

    def test_cancel_never_samples_close_marker_and_late_delivery_does_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
                token = "5" * 64
                prepare(
                    memory,
                    token=token,
                    turn_id="synthetic-p08-gateway-cancelled",
                    index=2,
                )
                with patch.object(gateway, "_audit_stage"), patch.object(
                    gateway.time, "monotonic_ns", return_value=400
                ) as clock:
                    self.assertTrue(callback(memory, token=token, outcome="cancelled"))
                    clock.assert_not_called()
                    cancelled = memory.journal.resolve(
                        delivery_token=token,
                        outcome="cancelled",
                        delivered_monotonic_ns=None,
                    )
                    self.assertEqual(cancelled.episode.state, "CANCELLED_UNRESOLVED")
                    self.assertTrue(callback(memory, token=token, outcome="delivered"))
                clock.assert_called_once_with()
                delivered = memory.journal.resolve(
                    delivery_token=token,
                    outcome="delivered",
                    delivered_monotonic_ns=None,
                )
                self.assertEqual(delivered.episode.state, "CLOSED_EXACT")
                self.assertEqual(
                    memory.journal.metadata()["late_delivered_after_cancelled_count"], 1
                )

    def test_missing_first_close_marker_is_raw_fact_without_derivative_day_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
                diary_before = memory.diary.path.read_bytes()
                token = "6" * 64
                prepare(
                    memory,
                    token=token,
                    turn_id="synthetic-p08-missing-marker",
                    index=3,
                )
                with patch("time.monotonic_ns", side_effect=AssertionError("forbidden")) as clock:
                    outcome = memory.resolve_delivery(
                        delivery_token=token,
                        outcome="delivered",
                        delivered_monotonic_ns=None,
                    )
                clock.assert_not_called()
                self.assertTrue(outcome.archive_written)
                self.assertTrue(outcome.index_current)
                self.assertFalse(outcome.diary_pending)
                self.assertIsNone(outcome.derivative_gap_code)
                self.assertEqual(outcome.episode.state, "CLOSED_TIME_UNRESOLVED")
                self.assertIsNone(outcome.episode.end_utc)
                self.assertIsNone(outcome.episode.owner_day)
                self.assertEqual(memory.diary.owner_day_revisions(), ())
                replay = memory.resolve_delivery(
                    delivery_token=token,
                    outcome="delivered",
                    delivered_monotonic_ns=None,
                )
                self.assertTrue(replay.replayed)
                self.assertEqual(replay.episode, outcome.episode)
                self.assertEqual(memory.archive.metadata()["turn_count"], 1)
                self.assertEqual(memory.diary.path.read_bytes(), diary_before)

    def test_owner_day_correction_requires_explicit_revision_without_replay_fanout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                selected_memory, selected_diary = owner_day_selection(root)
                memory = runtime.OwnerPrivateMemoryRuntime(
                    selected_memory,
                    owner_day_diary=selected_diary,
                )
                memory.initialize()
                token = "7" * 64
                prepare(
                    memory,
                    token=token,
                    turn_id="synthetic-p08-owner-day-correction",
                    index=4,
                )
                first = memory.resolve_delivery(
                    delivery_token=token,
                    outcome="delivered",
                    delivered_monotonic_ns=400,
                    delivered_boot_id="synthetic-boot",
                )
                original = memory.archive.turns()[0].draft.time_binding
                shift = timedelta(days=1)
                corrected_delivered = original.delivered_at_utc + shift
                corrected = replace(
                    original,
                    sample_instant_utc=original.sample_instant_utc + shift,
                    received_at_utc=original.received_at_utc + shift,
                    committed_at_utc=original.committed_at_utc + shift,
                    delivered_at_utc=corrected_delivered,
                    local_calendar_representation=corrected_delivered.astimezone(
                        timezone(timedelta(hours=8))
                    ).isoformat(timespec="microseconds"),
                )
                correction = TurnTimeCorrection(
                    correction_id="synthetic-runtime-owner-day-correction",
                    turn_id="synthetic-p08-owner-day-correction",
                    turn_digest=memory.archive.turns()[0].turn_digest,
                    original_binding_digest=original.binding_digest,
                    corrected_binding=corrected,
                    reason_code="explicit_owner_day_correction",
                    created_at_utc=datetime(2026, 8, 9, 13, tzinfo=timezone.utc),
                    provenance_digest="8" * 64,
                )
                memory.archive.append_time_correction(correction)
                archive_before = (
                    memory.archive.path.read_bytes(),
                    memory.archive.metadata(),
                )
                diary_before = (
                    memory.diary.path.read_bytes(),
                    memory.diary.audit_projection(),
                    memory.diary.owner_day_revisions(),
                )
                self.assertEqual(diary_before[2], ())
                replay = memory.resolve_delivery(
                    delivery_token=token,
                    outcome="delivered",
                    delivered_monotonic_ns=None,
                )
                self.assertTrue(replay.replayed)
                self.assertIsNone(replay.derivative_gap_code)
                self.assertFalse(replay.diary_pending)
                self.assertEqual(
                    (
                        memory.diary.path.read_bytes(),
                        memory.diary.audit_projection(),
                        memory.diary.owner_day_revisions(),
                    ),
                    diary_before,
                )
                self.assertEqual(
                    (memory.archive.path.read_bytes(), memory.archive.metadata()),
                    archive_before,
                )
                self.assertEqual(replay.episode.episode_id, first.episode.episode_id)
                self.assertNotEqual(replay.episode.owner_day, first.episode.owner_day)


if __name__ == "__main__":
    unittest.main()
