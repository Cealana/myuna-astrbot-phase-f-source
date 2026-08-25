from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from myuna_core.authenticated_conversation import (
    SCHEMA_VERSION as AUTH_SCHEMA,
    AuthenticatedConversationContext,
)
from myuna_core.active_temporal_context.time import TrustedTimeSample
from myuna_core.active_temporal_context.protocol import (
    ActiveSnapshotReceipt,
    build_active_snapshot_receipt,
)
from myuna_core.external_context.contracts import EgressSafetySignals, current_message_digest
from myuna_core.episodic_memory.contracts import (
    HISTORICAL_RAW_RECALL_EGRESS_V1_DIGEST,
    REFLECTIVE_DIARY_EGRESS_V1_DIGEST,
    REFLECTIVE_DIARY_STYLE_V1_DIGEST,
    EpisodicMemoryError,
    calendar_zone_selection_digest,
    semantic_digest,
)
from myuna_core.episodic_memory.runtime_context import EpisodicTurnProvenance
from myuna_core.memory_aware_turn_protocol import ServerIntentProposal

import p07_owner_private_memory_runtime_v1 as runtime


def auth() -> AuthenticatedConversationContext:
    return AuthenticatedConversationContext(
        schema_version=AUTH_SCHEMA,
        request_id="request-synthetic-runtime",
        correlation_id="correlation-synthetic-runtime",
        client_id="telegram-owner-private",
        channel_kind="astrbot_telegram",
        binding_id="binding-synthetic-owner",
        principal_id="principal-synthetic-owner",
        namespace_id="namespace-synthetic-owner",
        authority_level="owner",
        channel_instance="telegram-synthetic",
        conversation_id="conversation-synthetic",
        conversation_kind="private",
        event_id="event-synthetic-runtime",
        trace_id="trace-synthetic-runtime",
        occurred_at=datetime(2026, 8, 8, tzinfo=timezone.utc),
        delivery_capabilities=("text",),
    )


def sample() -> TrustedTimeSample:
    return TrustedTimeSample(
        datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc),
        "myuna-trusted-local-v1",
        "trusted_local",
        7,
        authority="systemd-timesyncd",
        uncertainty_microseconds=1_000,
        synchronized=True,
        boot_id="synthetic-boot",
        monotonic_ns=200,
    )


def active_receipt(
    *,
    transitions: tuple[dict[str, object], ...] = (),
    watermark: int = 0,
    has_more: bool = False,
    after_event_sequence: int = 0,
    selected_sample: TrustedTimeSample | None = None,
) -> ActiveSnapshotReceipt:
    trusted = sample() if selected_sample is None else selected_sample
    return build_active_snapshot_receipt(
        request_id="synthetic-active-snapshot",
        after_event_sequence=after_event_sequence,
        fact_count=0,
        lifecycle_transitions=transitions,
        lifecycle_watermark=watermark,
        lifecycle_has_more=has_more,
        trusted_time=trusted.as_payload(),
    )


def temporal_transition(
    sequence: int,
    *,
    terminal: str | None = None,
    revision: int | None = None,
) -> dict[str, object]:
    return {
        "category": "temporary_plan",
        "event_kind": terminal or "confirm",
        "event_sequence": sequence,
        "expires_at": "2026-08-11T12:00:00.000000+00:00",
        "fact_id": "tf_profile_terminal_source",
        "occurred_at": "2026-08-08T12:00:00.000000+00:00",
        "reason": "synthetic_terminal_reason",
        "revision": sequence if revision is None else revision,
        "slot_key": "profile-terminal-source",
        "source_kind": "owner_statement",
        "source_ref": "profile-terminal-source",
        "state": "active" if terminal is None else "expired",
        "supersedes_fact_id": None,
        "transition": "proposed->active" if terminal is None else "active->expired",
        "trusted_time_source_class": "trusted_local",
        "valid_from": "2026-08-08T12:00:00.000000+00:00",
        "valid_to": "2026-08-11T12:00:00.000000+00:00",
    }


def deliver_profile_control(
    memory: runtime.OwnerPrivateMemoryRuntime,
    *,
    token: str,
    owner_message: str,
):
    memory.prepare_control_delivery(
        delivery_token=token,
        turn_id="turn-profile-control-" + token[:12],
        control_kind="profile_v2",
        authenticated_context=auth(),
        owner_message=owner_message,
        assistant_reply="synthetic profile control reply",
        received_monotonic_ns=100,
        committed_monotonic_ns=250,
        source_occurred_at_utc=datetime(2026, 8, 8, tzinfo=timezone.utc),
        trusted_time_sample=sample(),
        trusted_time_unresolved_reason=None,
    )
    return memory.resolve_delivery(
        delivery_token=token,
        outcome="delivered",
        delivered_monotonic_ns=300,
        delivered_boot_id="synthetic-boot",
    )


def selection(
    root: Path, *, calendar_zone: str = "Asia/Shanghai"
) -> runtime.OwnerPrivateMemorySelection:
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
        calendar_zone=calendar_zone,
        calendar_zone_config_digest=calendar_zone_selection_digest(calendar_zone),
    )


def provenance(context) -> EpisodicTurnProvenance:
    return EpisodicTurnProvenance(
        parent_release_set_id=context.parent_release_set_id,
        policy_overlay_id=context.policy_overlay_id,
        parent_epoch_id=context.parent_epoch_id,
        parent_epoch_revision=context.parent_epoch_revision,
        archive_id=context.archive_id,
        archive_head_digest=context.archive_head_digest,
        archive_turn_count=context.archive_turn_count,
        projection_digest="1" * 64,
        selection_digest="2" * 64,
        source_ranges=(),
        profile_revisions=(),
        recall_state=context.recall_state,
        recall_reason_category=context.recall_reason_category,
        recall_source_closure_digest=context.recall_source_closure_digest,
        recall_selection_digest=context.recall_selection_digest,
        trusted_time_binding_digest=context.trusted_time_binding.binding_digest,
        temporal_projection_digest=context.temporal_projection_digest,
        temporal_coverage_state=context.temporal_coverage_state,
        temporal_state=context.temporal_state,
        temporal_reason_category=context.temporal_reason_category,
        temporal_source_closure_digest=context.temporal_source_closure_digest,
        temporal_selection_digest=context.temporal_selection_digest,
    )


class OwnerPrivateMemoryRuntimeTests(unittest.TestCase):
    def test_source_receipt_preflight_precedes_all_derivative_reads(self) -> None:
        transition = {
            "category": "temporary_plan",
            "event_kind": "confirm",
            "event_sequence": 1,
            "expires_at": "2026-08-11T12:00:00.000000+00:00",
            "fact_id": "tf_synthetic_preflight_1",
            "occurred_at": "2026-08-08T12:00:00.000000+00:00",
            "reason": "owner_confirmed",
            "revision": 1,
            "slot_key": "synthetic-preflight",
            "source_kind": "owner_statement",
            "source_ref": "telegram-event-preflight-1",
            "state": "active",
            "supersedes_fact_id": None,
            "transition": "proposed->active",
            "trusted_time_source_class": "trusted_local",
            "valid_from": "2026-08-08T12:00:00.000000+00:00",
            "valid_to": "2026-08-11T12:00:00.000000+00:00",
        }
        alternate_time = TrustedTimeSample(
            datetime(2026, 8, 8, 12, 0, 1, tzinfo=timezone.utc),
            "myuna-trusted-local-v1",
            "trusted_local",
            8,
            authority="systemd-timesyncd",
            uncertainty_microseconds=1_000,
            synchronized=True,
            boot_id="synthetic-boot",
            monotonic_ns=201,
        )
        substitutions = (
            (
                "trusted_time",
                active_receipt(selected_sample=alternate_time),
                (),
                0,
            ),
            (
                "p08_revision",
                active_receipt(transitions=(transition,), watermark=1),
                (transition | {"revision": 999},),
                1,
            ),
        )
        for name, receipt, transitions, watermark in substitutions:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with patch.object(runtime, "RUNTIME_ROOT", root):
                    memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                    memory.initialize()
                    temporal_before = memory.temporal_index.path.read_bytes()
                    episodic_before = memory.index_path.read_bytes()
                    with (
                        patch.object(
                            memory.temporal_index,
                            "read",
                            wraps=memory.temporal_index.read,
                        ) as temporal_read,
                        patch.object(
                            runtime,
                            "read_snapshot",
                            wraps=runtime.read_snapshot,
                        ) as episodic_read,
                    ):
                        context = memory.build_context(
                            authenticated_context=auth(),
                            current_message="Synthetic receipt preflight",
                            received_monotonic_ns=100,
                            p08_temporal_coverage_state="complete",
                            trusted_time_sample=sample(),
                            trusted_time_unresolved_reason=None,
                            active_snapshot_receipt=receipt,
                            temporal_lifecycle_transitions=transitions,
                            temporal_lifecycle_watermark=watermark,
                            temporal_lifecycle_has_more=False,
                            safety=EgressSafetySignals(classifier_available=True),
                        )
                    self.assertEqual(temporal_read.call_count, 0)
                    self.assertEqual(episodic_read.call_count, 0)
                    self.assertEqual(context.temporal_state, "conflict")
                    self.assertEqual(
                        context.temporal_reason_category,
                        "source_receipt_conflict",
                    )
                    self.assertEqual(context.recall_state, "conflict")
                    self.assertEqual(memory.temporal_index.path.read_bytes(), temporal_before)
                    self.assertEqual(memory.index_path.read_bytes(), episodic_before)

    def test_valid_source_receipt_tuple_retains_derivative_projection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
                with (
                    patch.object(
                        memory.temporal_index,
                        "read",
                        wraps=memory.temporal_index.read,
                    ) as temporal_read,
                    patch.object(
                        runtime,
                        "read_snapshot",
                        wraps=runtime.read_snapshot,
                    ) as episodic_read,
                ):
                    context = memory.build_context(
                        authenticated_context=auth(),
                        current_message="Synthetic valid receipt tuple",
                        received_monotonic_ns=100,
                        p08_temporal_coverage_state="complete",
                        trusted_time_sample=sample(),
                        trusted_time_unresolved_reason=None,
                        active_snapshot_receipt=active_receipt(),
                        safety=EgressSafetySignals(classifier_available=True),
                    )
                self.assertEqual(context.temporal_state, "available_empty")
                self.assertGreaterEqual(temporal_read.call_count, 1)
                self.assertGreaterEqual(episodic_read.call_count, 1)

    def test_active_route_requires_precreated_runtime_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                selected = selection(root)
                selected.runtime_root.rmdir()
                with self.assertRaisesRegex(
                    EpisodicMemoryError, "memory_runtime_root_precreation_required"
                ):
                    runtime.require_precreated_runtime_root(selected)
                memory = runtime.OwnerPrivateMemoryRuntime(selected)
                memory.initialize()
                self.assertTrue(selected.runtime_root.is_dir())

    def test_diary_current_snapshot_authority_is_bound_to_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
                bound = memory.diary._current_source_snapshot_loader
                self.assertIs(bound.__self__, memory)
                self.assertEqual(
                    memory.diary._load_current_source_snapshot(),
                    runtime.read_snapshot(memory.index_path),
                )
                before = memory.diary.path.read_bytes()
                with patch.object(
                    memory.archive,
                    "turns",
                    side_effect=EpisodicMemoryError(
                        "synthetic_current_snapshot_unavailable"
                    ),
                ):
                    with self.assertRaisesRegex(
                        EpisodicMemoryError,
                        "diary_current_source_authority_unavailable",
                    ):
                        memory.diary._load_current_source_snapshot()
                self.assertEqual(memory.diary.path.read_bytes(), before)

    def test_factual_close_precedes_derivatives_and_replay_has_zero_fanout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
                context = memory.build_context(
                    authenticated_context=auth(),
                    current_message="Synthetic close-before-derivative turn",
                    received_monotonic_ns=100,
                    p08_temporal_coverage_state="complete",
                    trusted_time_sample=sample(),
                    trusted_time_unresolved_reason=None,
                    active_snapshot_receipt=active_receipt(),
                    safety=EgressSafetySignals(classifier_available=True),
                )
                token = "8" * 64
                from myuna_core.episodic_memory import store as store_module

                original_connect = store_module.sqlite3.connect
                with patch.object(
                    store_module.sqlite3,
                    "connect",
                    wraps=original_connect,
                ) as prepare_connect:
                    memory.prepare_delivery(
                        delivery_token=token,
                        turn_id="synthetic-close-before-derivative",
                        runtime_context=context,
                        assistant_reply="Synthetic detached derivative reply",
                        provenance=provenance(context),
                        committed_monotonic_ns=300,
                        source_occurred_at_utc=auth().occurred_at,
                    )
                self.assertEqual(prepare_connect.call_count, 1)

                class TrackingConnection(sqlite3.Connection):
                    active = 0

                    def __init__(self, *args, **kwargs):
                        super().__init__(*args, **kwargs)
                        type(self).active += 1

                    def close(self):
                        type(self).active -= 1
                        return super().close()

                def tracked_connect(*args, **kwargs):
                    return original_connect(*args, factory=TrackingConnection, **kwargs)

                derivative_calls = []

                def detached_derivative(*args, **kwargs):
                    derivative_calls.append((args, kwargs))
                    self.assertEqual(TrackingConnection.active, 0)
                    raise EpisodicMemoryError("synthetic_derivative_failure")

                with (
                    patch.object(store_module.sqlite3, "connect", side_effect=tracked_connect),
                    patch.object(
                        runtime,
                        "recover_or_write_snapshot",
                        side_effect=detached_derivative,
                    ),
                ):
                    outcome = memory.resolve_delivery(
                        delivery_token=token,
                        outcome="delivered",
                        delivered_monotonic_ns=400,
                        delivered_boot_id="synthetic-boot",
                    )
                    replay = memory.resolve_delivery(
                        delivery_token=token,
                        outcome="delivered",
                        delivered_monotonic_ns=400,
                        delivered_boot_id="synthetic-boot",
                    )
                self.assertEqual(outcome.derivative_gap_code, "synthetic_derivative_failure")
                self.assertTrue(replay.replayed)
                self.assertEqual(len(derivative_calls), 1)
                self.assertEqual(memory.archive.metadata()["turn_count"], 1)

    def test_cancelled_callback_can_be_followed_by_late_exact_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
                context = memory.build_context(
                    authenticated_context=auth(),
                    current_message="Synthetic late delivered truth",
                    received_monotonic_ns=100,
                    p08_temporal_coverage_state="complete",
                    trusted_time_sample=sample(),
                    trusted_time_unresolved_reason=None,
                    active_snapshot_receipt=active_receipt(),
                    safety=EgressSafetySignals(classifier_available=True),
                )
                token = "9" * 64
                memory.prepare_delivery(
                    delivery_token=token,
                    turn_id="synthetic-late-delivered",
                    runtime_context=context,
                    assistant_reply="Synthetic eventual delivery",
                    provenance=provenance(context),
                    committed_monotonic_ns=300,
                    source_occurred_at_utc=auth().occurred_at,
                )
                memory.resolve_delivery(
                    delivery_token=token,
                    outcome="cancelled",
                    delivered_monotonic_ns=None,
                )
                delivered = memory.resolve_delivery(
                    delivery_token=token,
                    outcome="delivered",
                    delivered_monotonic_ns=400,
                    delivered_boot_id="synthetic-boot",
                )
                self.assertTrue(delivered.archive_written)
                self.assertEqual(memory.archive.metadata()["turn_count"], 1)
                self.assertEqual(
                    memory.journal.metadata()["late_delivered_after_cancelled_count"],
                    1,
                )

    def test_p08_transition_indexes_only_new_raw_bound_temporal_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
                from myuna_core.episodic_memory import store as store_module

                original_connect = store_module.sqlite3.connect
                with patch.object(
                    store_module.sqlite3,
                    "connect",
                    wraps=original_connect,
                ) as prepare_connect:
                    memory.prepare_control_delivery(
                        delivery_token="9" * 64,
                        turn_id="turn-telegram-event-temporal-1",
                        control_kind="temporal",
                        authenticated_context=auth(),
                        owner_message=(
                            "/temporal add temporary_plan shanghai-trip 3 "
                            "Cealana计划去上海旅行"
                        ),
                        assistant_reply="Synthetic proposal accepted",
                        received_monotonic_ns=100,
                        committed_monotonic_ns=250,
                        source_occurred_at_utc=datetime(
                            2026, 8, 8, 12, tzinfo=timezone.utc
                        ),
                        trusted_time_sample=sample(),
                        trusted_time_unresolved_reason=None,
                    )
                self.assertEqual(prepare_connect.call_count, 1)
                memory.resolve_delivery(
                    delivery_token="9" * 64,
                    outcome="delivered",
                    delivered_monotonic_ns=300,
                    delivered_boot_id="synthetic-boot",
                )
                transition = {
                    "category": "temporary_plan",
                    "event_kind": "confirm",
                    "event_sequence": 1,
                    "expires_at": "2026-08-11T12:00:00.000000+00:00",
                    "fact_id": "tf_synthetic_temporal_1",
                    "occurred_at": "2026-08-08T12:00:00.000000+00:00",
                    "reason": "owner_confirmed",
                    "revision": 1,
                    "slot_key": "shanghai-trip",
                    "source_kind": "owner_statement",
                    "source_ref": "telegram-event-temporal-1",
                    "state": "active",
                    "supersedes_fact_id": None,
                    "transition": "proposed->active",
                    "trusted_time_source_class": "trusted_local",
                    "valid_from": "2026-08-08T12:00:00.000000+00:00",
                    "valid_to": "2026-08-11T12:00:00.000000+00:00",
                }
                context = memory.build_context(
                    authenticated_context=auth(),
                    current_message="Synthetic ordinary follow-up",
                    received_monotonic_ns=100,
                    p08_temporal_coverage_state="complete",
                    trusted_time_sample=sample(),
                    trusted_time_unresolved_reason=None,
                    active_snapshot_receipt=active_receipt(
                        transitions=(transition,),
                        watermark=1,
                    ),
                    safety=EgressSafetySignals(classifier_available=True),
                    temporal_lifecycle_transitions=(transition,),
                    temporal_lifecycle_watermark=1,
                    temporal_lifecycle_has_more=False,
                )
                audit = memory.audit_projection()["temporal_interval_index"]
                self.assertEqual(audit["episode_count"], 1)
                self.assertEqual(audit["unresolved_event_count"], 0)
                interval = memory.temporal_index.read(
                    archive_head_digest=memory.archive.metadata()["head_digest"],
                    initial_event_sequence=0,
                )
                self.assertEqual(
                    interval.episodes[0].terminal_state,
                    "confirmed_started",
                )
                self.assertEqual(context.temporal_state, "available")
                self.assertEqual(context.temporal_item_count, 1)
                self.assertIn("Cealana计划去上海旅行", context.temporal_context)
                self.assertNotIn(
                    "active_temporal_validity_context_v1",
                    context.temporal_context,
                )
                derivative_before = memory.temporal_index.path.read_bytes()
                replay = memory.build_context(
                    authenticated_context=auth(),
                    current_message="Synthetic exact temporal replay",
                    received_monotonic_ns=100,
                    p08_temporal_coverage_state="complete",
                    trusted_time_sample=sample(),
                    trusted_time_unresolved_reason=None,
                    active_snapshot_receipt=active_receipt(
                        watermark=1,
                        after_event_sequence=1,
                    ),
                    safety=EgressSafetySignals(classifier_available=True),
                    temporal_lifecycle_transitions=(),
                    temporal_lifecycle_watermark=1,
                    temporal_lifecycle_has_more=False,
                )
                self.assertEqual(replay.temporal_state, "available")
                self.assertEqual(
                    memory.temporal_index.path.read_bytes(),
                    derivative_before,
                )

    def test_relative_date_uses_bound_owner_calendar_zone_and_never_guesses(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
                original = runtime.search_relevant_sources
                observed = []

                def capture(**kwargs):
                    observed.append(kwargs["query"])
                    return original(**kwargs)

                with patch.object(runtime, "search_relevant_sources", side_effect=capture):
                    memory.build_context(
                        authenticated_context=auth(),
                        current_message="昨天发生了什么？",
                        received_monotonic_ns=100,
                        p08_temporal_coverage_state="complete",
                        trusted_time_sample=sample(),
                        trusted_time_unresolved_reason=None,
                        active_snapshot_receipt=active_receipt(),
                        safety=EgressSafetySignals(classifier_available=True),
                    )
                self.assertEqual(
                    observed[0].start_utc,
                    datetime(2026, 8, 6, 16, 0, tzinfo=timezone.utc),
                )
                self.assertEqual(
                    observed[0].end_utc,
                    datetime(2026, 8, 7, 16, 0, tzinfo=timezone.utc),
                )
                unavailable = memory.build_context(
                    authenticated_context=auth(),
                    current_message="昨天发生了什么？",
                    received_monotonic_ns=100,
                    p08_temporal_coverage_state="unavailable",
                    trusted_time_sample=None,
                    trusted_time_unresolved_reason="trusted_time_unavailable",
                    safety=EgressSafetySignals(classifier_available=True),
                )
                self.assertEqual(unavailable.recall_state, "unavailable")
                self.assertEqual(
                    unavailable.recall_reason_category,
                    "trusted_time_unavailable",
                )
                self.assertEqual(unavailable.candidate_turns, ())

    def test_zone_switch_reuses_sample_and_changes_only_calendar_projection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                shanghai = runtime.OwnerPrivateMemoryRuntime(selection(root))
                los_angeles = runtime.OwnerPrivateMemoryRuntime(
                    selection(root, calendar_zone="America/Los_Angeles")
                )
                shanghai_binding = shanghai._bind_prompt_time(
                    received_monotonic_ns=100,
                    trusted_time_sample=sample(),
                    trusted_time_unresolved_reason=None,
                )
                la_binding = los_angeles._bind_prompt_time(
                    received_monotonic_ns=100,
                    trusted_time_sample=sample(),
                    trusted_time_unresolved_reason=None,
                )
                self.assertEqual(
                    shanghai_binding.sample_instant_utc,
                    la_binding.sample_instant_utc,
                )
                self.assertEqual(shanghai_binding.sequence, la_binding.sequence)
                self.assertEqual(shanghai_binding.boot_id, la_binding.boot_id)
                self.assertNotEqual(
                    shanghai_binding.local_calendar_representation,
                    la_binding.local_calendar_representation,
                )

    def test_los_angeles_dst_gap_uses_iana_offsets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = runtime.OwnerPrivateMemoryRuntime(
                    selection(root, calendar_zone="America/Los_Angeles")
                )
                before = TrustedTimeSample(
                    datetime(2026, 3, 8, 9, 59, tzinfo=timezone.utc),
                    "myuna-trusted-local-v1",
                    "trusted_local",
                    8,
                    authority="systemd-timesyncd",
                    uncertainty_microseconds=1_000,
                    synchronized=True,
                    boot_id="synthetic-boot",
                    monotonic_ns=300,
                )
                after = TrustedTimeSample(
                    datetime(2026, 3, 8, 10, 1, tzinfo=timezone.utc),
                    "myuna-trusted-local-v1",
                    "trusted_local",
                    9,
                    authority="systemd-timesyncd",
                    uncertainty_microseconds=1_000,
                    synchronized=True,
                    boot_id="synthetic-boot",
                    monotonic_ns=400,
                )
                before_binding = memory._bind_prompt_time(
                    received_monotonic_ns=300,
                    trusted_time_sample=before,
                    trusted_time_unresolved_reason=None,
                )
                after_binding = memory._bind_prompt_time(
                    received_monotonic_ns=400,
                    trusted_time_sample=after,
                    trusted_time_unresolved_reason=None,
                )
                self.assertEqual(before_binding.event_offset_minutes, -480)
                self.assertEqual(after_binding.event_offset_minutes, -420)
                self.assertIn("01:59", before_binding.local_calendar_representation)
                self.assertIn("03:01", after_binding.local_calendar_representation)

    def test_existing_root_or_file_acl_drift_fails_before_repair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                selected = selection(root)
                memory = runtime.OwnerPrivateMemoryRuntime(selected)
                memory.initialize()
                os.chmod(selected.runtime_root, 0o750)
                with self.assertRaisesRegex(
                    EpisodicMemoryError, "root_permissions_rejected"
                ):
                    runtime.OwnerPrivateMemoryRuntime(selected).initialize()
                self.assertEqual(selected.runtime_root.stat().st_mode & 0o777, 0o750)

    def test_corrupt_index_is_typed_unavailable_and_not_repaired_by_recall(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
                memory.index_path.write_bytes(b"{\n")
                corrupt = memory.index_path.read_bytes()
                unavailable = memory.build_context(
                    authenticated_context=auth(),
                    current_message="Synthetic recall with corrupt derivative",
                    received_monotonic_ns=100,
                    p08_temporal_coverage_state="complete",
                    trusted_time_sample=sample(),
                    trusted_time_unresolved_reason=None,
                    active_snapshot_receipt=active_receipt(),
                    safety=EgressSafetySignals(classifier_available=True),
                )
                self.assertEqual(unavailable.recall_state, "unavailable")
                self.assertEqual(
                    unavailable.recall_reason_category,
                    "index_unavailable",
                )
                self.assertEqual(unavailable.candidate_turns, ())
                self.assertEqual(memory.index_path.read_bytes(), corrupt)
    def test_temporal_source_advance_does_not_repair_corrupt_index(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
                memory.prepare_control_delivery(
                    delivery_token="a" * 64,
                    turn_id="turn-telegram-event-temporal-corrupt-index",
                    control_kind="temporal",
                    authenticated_context=auth(),
                    owner_message=(
                        "/temporal add temporary_plan corrupt-index-trip 3 "
                        "Cealana plans a synthetic trip"
                    ),
                    assistant_reply="Synthetic proposal accepted",
                    received_monotonic_ns=100,
                    committed_monotonic_ns=250,
                    source_occurred_at_utc=datetime(
                        2026, 8, 8, 12, tzinfo=timezone.utc
                    ),
                    trusted_time_sample=sample(),
                    trusted_time_unresolved_reason=None,
                )
                memory.resolve_delivery(
                    delivery_token="a" * 64,
                    outcome="delivered",
                    delivered_monotonic_ns=300,
                    delivered_boot_id="synthetic-boot",
                )
                memory.index_path.write_bytes(b"{\n")
                corrupt = memory.index_path.read_bytes()
                transition = {
                    "category": "temporary_plan",
                    "event_kind": "confirm",
                    "event_sequence": 1,
                    "expires_at": "2026-08-11T12:00:00.000000+00:00",
                    "fact_id": "tf_synthetic_corrupt_index_trip",
                    "occurred_at": "2026-08-08T12:00:00.000000+00:00",
                    "reason": "owner_confirmed",
                    "revision": 1,
                    "slot_key": "corrupt-index-trip",
                    "source_kind": "owner_statement",
                    "source_ref": "telegram-event-temporal-corrupt-index",
                    "state": "active",
                    "supersedes_fact_id": None,
                    "transition": "proposed->active",
                    "trusted_time_source_class": "trusted_local",
                    "valid_from": "2026-08-08T12:00:00.000000+00:00",
                    "valid_to": "2026-08-11T12:00:00.000000+00:00",
                }
                unavailable = memory.build_context(
                    authenticated_context=auth(),
                    current_message="Synthetic temporal advance with corrupt index",
                    received_monotonic_ns=100,
                    p08_temporal_coverage_state="complete",
                    trusted_time_sample=sample(),
                    trusted_time_unresolved_reason=None,
                    active_snapshot_receipt=active_receipt(
                        transitions=(transition,),
                        watermark=1,
                    ),
                    safety=EgressSafetySignals(classifier_available=True),
                    temporal_lifecycle_transitions=(transition,),
                    temporal_lifecycle_watermark=1,
                    temporal_lifecycle_has_more=False,
                )
                self.assertEqual(memory.archive.metadata()["turn_count"], 1)
                self.assertEqual(unavailable.recall_state, "unavailable")
                self.assertEqual(
                    unavailable.recall_reason_category,
                    "index_unavailable",
                )
                self.assertEqual(unavailable.candidate_turns, ())
                self.assertEqual(memory.index_path.read_bytes(), corrupt)
                temporal = memory.temporal_index.read(
                    archive_head_digest=memory.archive.metadata()["head_digest"],
                    initial_event_sequence=0,
                )
                self.assertEqual(len(temporal.episodes), 1)

    def test_profile_v2_commits_only_after_delivery_and_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
                proposal_token = "a" * 64
                memory.prepare_control_delivery(
                    delivery_token=proposal_token,
                    turn_id="turn-profile-proposal",
                    control_kind="profile_v2",
                    authenticated_context=auth(),
                    owner_message="将亲密度设为 12.5",
                    assistant_reply="synthetic proposal reply",
                    received_monotonic_ns=100,
                    committed_monotonic_ns=200,
                    source_occurred_at_utc=datetime(2026, 8, 8, tzinfo=timezone.utc),
                    trusted_time_sample=sample(),
                    trusted_time_unresolved_reason=None,
                )
                self.assertEqual(memory.diary.current_profile_values()[0].state, "uninitialized")
                proposed = memory.resolve_delivery(
                    delivery_token=proposal_token,
                    outcome="delivered",
                    delivered_monotonic_ns=300,
                    delivered_boot_id="synthetic-boot",
                )
                self.assertIsNone(proposed.derivative_gap_code)
                self.assertEqual(memory.diary.current_profile_values()[0].state, "uninitialized")
                proposal = memory.diary.current_profile_proposal(
                    "profile-" + proposal_token[:24], 1
                )
                self.assertEqual(proposal.proposal_value, 125_000)

                confirmation_token = "b" * 64
                memory.prepare_control_delivery(
                    delivery_token=confirmation_token,
                    turn_id="turn-profile-confirmation",
                    control_kind="profile_v2",
                    authenticated_context=auth(),
                    owner_message=(
                        "确认亲密度提案 profile-" + proposal_token[:24] + " v1"
                    ),
                    assistant_reply="synthetic confirmation reply",
                    received_monotonic_ns=100,
                    committed_monotonic_ns=250,
                    source_occurred_at_utc=datetime(2026, 8, 8, tzinfo=timezone.utc),
                    trusted_time_sample=sample(),
                    trusted_time_unresolved_reason=None,
                )
                confirmed = memory.resolve_delivery(
                    delivery_token=confirmation_token,
                    outcome="delivered",
                    delivered_monotonic_ns=300,
                    delivered_boot_id="synthetic-boot",
                )
                self.assertIsNone(confirmed.derivative_gap_code)
                current = memory.diary.current_profile_values()[0]
                self.assertEqual(current.state, "current")
                self.assertEqual(current.scaled_value, 125_000)
                before = memory.diary.path.read_bytes()
                replay = memory.resolve_delivery(
                    delivery_token=confirmation_token,
                    outcome="delivered",
                    delivered_monotonic_ns=300,
                    delivered_boot_id="synthetic-boot",
                )
                self.assertTrue(replay.replayed)
                self.assertEqual(memory.diary.path.read_bytes(), before)

    def test_profile_v2_typed_episode_end_stages_only_for_delivered_turns(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
                before_unbound = memory.diary.path.read_bytes()
                with self.assertRaisesRegex(
                    EpisodicMemoryError,
                    "profile_state_delivery_token_unbound",
                ):
                    memory.stage_profile_server_intents(
                        "f" * 64,
                        (
                            ServerIntentProposal.profile_state(
                                intent_id="profile-autonomous-not-sent",
                                requested_delta=1_000,
                            ),
                        ),
                    )
                self.assertEqual(memory._pending_profile_requests, {})
                self.assertEqual(memory.diary.path.read_bytes(), before_unbound)
                memory.prepare_control_delivery(
                    delivery_token="0" * 64,
                    turn_id="turn-profile-terminal-source",
                    control_kind="temporal",
                    authenticated_context=auth(),
                    owner_message=(
                        "/temporal add temporary_plan profile-terminal-source 3 "
                        "Synthetic Profile terminal source"
                    ),
                    assistant_reply="Synthetic terminal source accepted",
                    received_monotonic_ns=100,
                    committed_monotonic_ns=250,
                    source_occurred_at_utc=datetime(
                        2026, 8, 8, 12, tzinfo=timezone.utc
                    ),
                    trusted_time_sample=sample(),
                    trusted_time_unresolved_reason=None,
                )
                memory.resolve_delivery(
                    delivery_token="0" * 64,
                    outcome="delivered",
                    delivered_monotonic_ns=300,
                    delivered_boot_id="synthetic-boot",
                )
                active = temporal_transition(1)
                memory.build_context(
                    authenticated_context=auth(),
                    current_message="Synthetic active source",
                    received_monotonic_ns=100,
                    p08_temporal_coverage_state="complete",
                    trusted_time_sample=sample(),
                    trusted_time_unresolved_reason=None,
                    active_snapshot_receipt=active_receipt(
                        transitions=(active,),
                        watermark=1,
                    ),
                    temporal_lifecycle_transitions=(active,),
                    temporal_lifecycle_watermark=1,
                    temporal_lifecycle_has_more=False,
                    safety=EgressSafetySignals(classifier_available=True),
                )
                ended = temporal_transition(2, terminal="expire", revision=3)
                memory.build_context(
                    authenticated_context=auth(),
                    current_message="Synthetic terminal source",
                    received_monotonic_ns=100,
                    p08_temporal_coverage_state="complete",
                    trusted_time_sample=sample(),
                    trusted_time_unresolved_reason=None,
                    active_snapshot_receipt=active_receipt(
                        transitions=(ended,),
                        watermark=2,
                        after_event_sequence=1,
                    ),
                    temporal_lifecycle_transitions=(ended,),
                    temporal_lifecycle_watermark=2,
                    temporal_lifecycle_has_more=False,
                    safety=EgressSafetySignals(classifier_available=True),
                )
                temporal_snapshot = memory.temporal_index.read(
                    archive_head_digest=memory.archive.metadata()["head_digest"],
                    initial_event_sequence=0,
                )
                episode = temporal_snapshot.episodes[0]
                self.assertEqual(episode.terminal_state, "ended")
                self.assertEqual(
                    (
                        episode.revisions[-1].p08_event_sequence,
                        episode.revisions[-1].p08_revision,
                        episode.revisions[-1].p08_event_kind,
                    ),
                    (2, 3, "expire"),
                )

                proposal_token = "1" * 64
                deliver_profile_control(
                    memory,
                    token=proposal_token,
                    owner_message="将亲密度设为 0",
                )
                deliver_profile_control(
                    memory,
                    token="2" * 64,
                    owner_message=(
                        "确认亲密度提案 profile-" + proposal_token[:24] + " v1"
                    ),
                )
                self.assertEqual(
                    memory.diary.current_profile_values()[0].scaled_value,
                    0,
                )

                def prepare_noop(token: str) -> None:
                    context = memory.build_context(
                        authenticated_context=auth(),
                        current_message="Synthetic ordinary delivered turn",
                        received_monotonic_ns=100,
                        p08_temporal_coverage_state="complete",
                        trusted_time_sample=sample(),
                        trusted_time_unresolved_reason=None,
                        active_snapshot_receipt=active_receipt(
                            watermark=2,
                            after_event_sequence=2,
                        ),
                        temporal_lifecycle_watermark=2,
                        safety=EgressSafetySignals(classifier_available=True),
                    )
                    memory.prepare_delivery(
                        delivery_token=token,
                        turn_id="synthetic-profile-autonomous-" + token[:12],
                        runtime_context=context,
                        assistant_reply="Synthetic delivered response",
                        provenance=provenance(context),
                        committed_monotonic_ns=250,
                        source_occurred_at_utc=datetime(
                            2026, 8, 8, 12, tzinfo=timezone.utc
                        ),
                    )

                cancelled_token = "3" * 64
                prepare_noop(cancelled_token)
                memory.stage_profile_server_intents(
                    cancelled_token,
                    (
                        ServerIntentProposal.profile_state(
                            intent_id="profile-autonomous-cancelled",
                            requested_delta=10_000,
                            reason_category="episode_end",
                            source_interval_id=episode.interval_id,
                        ),
                    ),
                )
                before_cancel = memory.diary.path.read_bytes()
                memory.resolve_delivery(
                    delivery_token=cancelled_token,
                    outcome="cancelled",
                    delivered_monotonic_ns=None,
                )
                self.assertEqual(memory.diary.path.read_bytes(), before_cancel)
                self.assertNotIn(cancelled_token, memory._pending_profile_requests)

                ordinary_token = "d" * 64
                prepare_noop(ordinary_token)
                memory.stage_profile_server_intents(
                    ordinary_token,
                    (
                        ServerIntentProposal.profile_state(
                            intent_id="profile-autonomous-delivered-turn",
                            requested_delta=5_000,
                        ),
                    ),
                )
                ordinary = memory.resolve_delivery(
                    delivery_token=ordinary_token,
                    outcome="delivered",
                    delivered_monotonic_ns=300,
                    delivered_boot_id="synthetic-boot",
                )
                self.assertIsNone(ordinary.derivative_gap_code)
                self.assertEqual(
                    memory.diary.current_profile_values()[0].scaled_value,
                    5_000,
                )

                delivered_token = "4" * 64
                prepare_noop(delivered_token)
                memory.stage_profile_server_intents(
                    delivered_token,
                    (
                        ServerIntentProposal.profile_state(
                            intent_id="profile-autonomous-delivered",
                            requested_delta=10_000,
                            reason_category="episode_end",
                            source_interval_id=episode.interval_id,
                        ),
                    ),
                )
                committed = memory.resolve_delivery(
                    delivery_token=delivered_token,
                    outcome="delivered",
                    delivered_monotonic_ns=300,
                    delivered_boot_id="synthetic-boot",
                )
                self.assertIsNone(committed.derivative_gap_code)
                self.assertEqual(
                    memory.diary.current_profile_values()[0].scaled_value,
                    15_000,
                )
                committed_bytes = memory.diary.path.read_bytes()
                replay = memory.resolve_delivery(
                    delivery_token=delivered_token,
                    outcome="delivered",
                    delivered_monotonic_ns=300,
                    delivered_boot_id="synthetic-boot",
                )
                self.assertTrue(replay.replayed)
                self.assertEqual(memory.diary.path.read_bytes(), committed_bytes)

                crash_token = "5" * 64
                prepare_noop(crash_token)
                memory.stage_profile_server_intents(
                    crash_token,
                    (
                        ServerIntentProposal.profile_state(
                            intent_id="profile-autonomous-pre-callback-crash",
                            requested_delta=10_000,
                            reason_category="episode_end",
                            source_interval_id=episode.interval_id,
                        ),
                    ),
                )
                restarted = runtime.OwnerPrivateMemoryRuntime(selection(root))
                restarted.initialize()
                self.assertEqual(restarted._pending_profile_requests, {})
                self.assertEqual(memory.diary.path.read_bytes(), committed_bytes)

                substituted_token = "6" * 64
                prepare_noop(substituted_token)
                memory.stage_profile_server_intents(
                    substituted_token,
                    (
                        ServerIntentProposal.profile_state(
                            intent_id="profile-autonomous-substituted",
                            requested_delta=10_000,
                            reason_category="episode_end",
                            source_interval_id="ti_" + "f" * 64,
                        ),
                    ),
                )
                substituted = memory.resolve_delivery(
                    delivery_token=substituted_token,
                    outcome="delivered",
                    delivered_monotonic_ns=300,
                    delivered_boot_id="synthetic-boot",
                )
                self.assertEqual(
                    substituted.derivative_gap_code,
                    "profile_state_terminal_source_mismatch",
                )
                self.assertEqual(memory.diary.path.read_bytes(), committed_bytes)
                self.assertEqual(
                    memory.diary.current_profile_values()[0].scaled_value,
                    15_000,
                )

    def test_profile_v2_runtime_correction_rollback_and_projection_states(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
                proposal_token = "7" * 64
                deliver_profile_control(
                    memory,
                    token=proposal_token,
                    owner_message="将亲密度设为 0",
                )
                deliver_profile_control(
                    memory,
                    token="8" * 64,
                    owner_message=(
                        "确认亲密度提案 profile-" + proposal_token[:24] + " v1"
                    ),
                )
                corrected = deliver_profile_control(
                    memory,
                    token="9" * 64,
                    owner_message="将亲密度修正为 2.5",
                )
                self.assertIsNone(corrected.derivative_gap_code)
                self.assertEqual(
                    memory.diary.current_profile_values()[0].scaled_value,
                    25_000,
                )
                rolled_back = deliver_profile_control(
                    memory,
                    token="a" * 64,
                    owner_message="将亲密度回滚到 0",
                )
                self.assertIsNone(rolled_back.derivative_gap_code)
                self.assertEqual(
                    memory.diary.current_profile_values()[0].scaled_value,
                    0,
                )
                connection = sqlite3.connect(memory.diary.path)
                payloads = tuple(
                    json.loads(row[0])
                    for row in connection.execute(
                        "SELECT payload_json FROM profile_state_events ORDER BY sequence"
                    )
                )
                connection.close()
                self.assertEqual(payloads[-2]["action"], "correct")
                self.assertEqual(payloads[-1]["action"], "rollback")
                self.assertIsNotNone(payloads[-1]["rollback_target_event_id"])
                self.assertIsNotNone(payloads[-1]["rollback_target_event_digest"])

                build_args = {
                    "authenticated_context": auth(),
                    "current_message": "Synthetic Profile projection state",
                    "received_monotonic_ns": 100,
                    "p08_temporal_coverage_state": "complete",
                    "trusted_time_sample": sample(),
                    "trusted_time_unresolved_reason": None,
                    "active_snapshot_receipt": active_receipt(),
                    "safety": EgressSafetySignals(classifier_available=True),
                }
                with patch.object(
                    memory.diary,
                    "current_profile_values",
                    side_effect=EpisodicMemoryError("profile_state_unavailable"),
                ):
                    unavailable = memory.build_context(**build_args)
                self.assertEqual(unavailable.profile_v2_state, "unavailable")
                with patch.object(
                    memory.diary,
                    "current_profile_values",
                    side_effect=EpisodicMemoryError("profile_state_projection_drifted"),
                ):
                    conflict = memory.build_context(**build_args)
                self.assertEqual(conflict.profile_v2_state, "conflict")

    def test_corrupt_temporal_derivative_is_conflict_and_not_repaired(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
                corrupt = b'{"schema":"corrupt-temporal-derivative"}'
                memory.temporal_index.path.write_bytes(corrupt)
                context = memory.build_context(
                    authenticated_context=auth(),
                    current_message="Synthetic temporal conflict",
                    received_monotonic_ns=100,
                    p08_temporal_coverage_state="complete",
                    trusted_time_sample=sample(),
                    trusted_time_unresolved_reason=None,
                    active_snapshot_receipt=active_receipt(),
                    safety=EgressSafetySignals(classifier_available=True),
                )
                self.assertEqual(context.temporal_state, "conflict")
                self.assertEqual(
                    context.temporal_reason_category,
                    "source_derivative_conflict",
                )
                self.assertEqual(context.temporal_item_count, 0)
                self.assertEqual(memory.temporal_index.path.read_bytes(), corrupt)

    def test_substituted_trusted_time_receipt_is_conflict_and_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
                before = memory.temporal_index.path.read_bytes()
                substituted_sample = TrustedTimeSample(
                    datetime(2026, 8, 8, 12, 0, 1, tzinfo=timezone.utc),
                    "myuna-trusted-local-v1",
                    "trusted_local",
                    8,
                    authority="systemd-timesyncd",
                    uncertainty_microseconds=1_000,
                    synchronized=True,
                    boot_id="synthetic-boot",
                    monotonic_ns=201,
                )
                context = memory.build_context(
                    authenticated_context=auth(),
                    current_message="Synthetic substituted trusted-time receipt",
                    received_monotonic_ns=100,
                    p08_temporal_coverage_state="complete",
                    trusted_time_sample=sample(),
                    trusted_time_unresolved_reason=None,
                    active_snapshot_receipt=active_receipt(
                        selected_sample=substituted_sample
                    ),
                    safety=EgressSafetySignals(classifier_available=True),
                )
                self.assertEqual(context.temporal_state, "conflict")
                self.assertEqual(
                    context.temporal_reason_category,
                    "source_receipt_conflict",
                )
                self.assertEqual(memory.temporal_index.path.read_bytes(), before)

    def test_incomplete_temporal_source_is_unavailable_and_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
                before = memory.temporal_index.path.read_bytes()
                context = memory.build_context(
                    authenticated_context=auth(),
                    current_message="Synthetic incomplete temporal source",
                    received_monotonic_ns=100,
                    p08_temporal_coverage_state="complete",
                    trusted_time_sample=sample(),
                    trusted_time_unresolved_reason=None,
                    active_snapshot_receipt=active_receipt(has_more=True),
                    safety=EgressSafetySignals(classifier_available=True),
                    temporal_lifecycle_watermark=0,
                    temporal_lifecycle_has_more=True,
                )
                self.assertEqual(context.temporal_state, "unavailable")
                self.assertEqual(
                    context.temporal_reason_category,
                    "source_incomplete",
                )
                self.assertEqual(context.temporal_item_count, 0)
                self.assertEqual(memory.temporal_index.path.read_bytes(), before)

    def test_unavailable_trusted_time_preserves_delivered_raw_with_typed_gap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
                context = memory.build_context(
                    authenticated_context=auth(),
                    current_message="Synthetic unresolved-time turn",
                    received_monotonic_ns=100,
                    p08_temporal_coverage_state="unavailable",
                    trusted_time_sample=None,
                    trusted_time_unresolved_reason="trusted_time_unavailable",
                    safety=EgressSafetySignals(classifier_available=True),
                )
                memory.prepare_delivery(
                    delivery_token="7" * 64,
                    turn_id="synthetic-unresolved-time-turn",
                    runtime_context=context,
                    assistant_reply="Synthetic delivered reply",
                    provenance=provenance(context),
                    committed_monotonic_ns=300,
                    source_occurred_at_utc=auth().occurred_at,
                )
                outcome = memory.resolve_delivery(
                    delivery_token="7" * 64,
                    outcome="delivered",
                    delivered_monotonic_ns=400,
                )
                self.assertTrue(outcome.archive_written)
                self.assertTrue(outcome.index_current)
                self.assertFalse(outcome.diary_pending)
                self.assertIsNone(outcome.derivative_gap_code)
                archived = memory.archive.turns()[0]
                self.assertEqual(archived.draft.time_binding.status, "unresolved")
                self.assertIn(
                    "trusted_time_unresolved", archived.draft.provenance_categories
                )
                source = runtime.read_snapshot(memory.index_path).source_references[0]
                self.assertEqual(source.time_status, "unresolved")

    def test_new_turn_archives_exactly_once_after_delivery_ack_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                selected = selection(root)
                memory = runtime.OwnerPrivateMemoryRuntime(selected)
                initial = memory.initialize()
                self.assertEqual(initial["archive"]["turn_count"], 0)
                self.assertTrue(initial["no_old_data_migration"])
                context = memory.build_context(
                    authenticated_context=auth(),
                    current_message="Cealana建议去江边走走。",
                    received_monotonic_ns=100,
                    p08_temporal_coverage_state="complete",
                    trusted_time_sample=sample(),
                    trusted_time_unresolved_reason=None,
                    active_snapshot_receipt=active_receipt(),
                    safety=EgressSafetySignals(classifier_available=True),
                )
                token = "4" * 64
                prepared = memory.prepare_delivery(
                    delivery_token=token,
                    turn_id="synthetic-delivered-turn",
                    runtime_context=context,
                    assistant_reply="Myuna表示赞同并去换衣服。",
                    provenance=provenance(context),
                    committed_monotonic_ns=300,
                    source_occurred_at_utc=auth().occurred_at,
                )
                self.assertFalse(prepared.replayed)
                self.assertEqual(memory.archive.metadata()["turn_count"], 0)
                outcome = memory.resolve_delivery(
                    delivery_token=token,
                    outcome="delivered",
                    delivered_monotonic_ns=400,
                    delivered_boot_id="synthetic-boot",
                )
                replay = memory.resolve_delivery(
                    delivery_token=token,
                    outcome="delivered",
                    delivered_monotonic_ns=None,
                )
                self.assertTrue(outcome.archive_written)
                self.assertTrue(outcome.index_current)
                self.assertFalse(outcome.diary_pending)
                self.assertTrue(replay.replayed)
                self.assertEqual(
                    replay.delivered_monotonic_ns,
                    outcome.delivered_monotonic_ns,
                )
                self.assertEqual(
                    replay.delivery_ack_digest,
                    outcome.delivery_ack_digest,
                )
                self.assertEqual(memory.archive.metadata()["turn_count"], 1)
                restarted = runtime.OwnerPrivateMemoryRuntime(selected)
                audit = restarted.initialize()
                self.assertEqual(audit["archive"]["turn_count"], 1)
                self.assertEqual(audit["startup_recovered_count"], 0)

    def test_cancelled_or_half_turn_never_enters_complete_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = runtime.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
                context = memory.build_context(
                    authenticated_context=auth(),
                    current_message="Synthetic half turn",
                    received_monotonic_ns=100,
                    p08_temporal_coverage_state="complete",
                    trusted_time_sample=sample(),
                    trusted_time_unresolved_reason=None,
                    active_snapshot_receipt=active_receipt(),
                    safety=EgressSafetySignals(classifier_available=True),
                )
                memory.prepare_delivery(
                    delivery_token="5" * 64,
                    turn_id="synthetic-cancelled-turn",
                    runtime_context=context,
                    assistant_reply="Synthetic reply not delivered",
                    provenance=provenance(context),
                    committed_monotonic_ns=300,
                    source_occurred_at_utc=auth().occurred_at,
                )
                outcome = memory.resolve_delivery(
                    delivery_token="5" * 64,
                    outcome="cancelled",
                    delivered_monotonic_ns=None,
                )
                self.assertFalse(outcome.archive_written)
                self.assertEqual(memory.archive.metadata()["turn_count"], 0)
                self.assertEqual(memory.archive.metadata()["lifecycle_count"], 1)

    def test_selector_is_closed_and_absence_preserves_compressed_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selector = root / "selector.json"
            self.assertIsNone(
                runtime.load_selected_memory_runtime(
                    selector,
                    expected_selector_gid=os.getegid(),
                )
            )
            with patch.object(runtime, "RUNTIME_ROOT", root):
                selected = selection(root)
                payload = {
                    "archive_id": selected.archive_id,
                    "calendar_zone": selected.calendar_zone,
                    "calendar_zone_config_digest": (
                        selected.calendar_zone_config_digest
                    ),
                    "channel_kind": runtime.CHANNEL_KIND,
                    "client_id": runtime.CORE_CLIENT_ID,
                    "diary_egress_policy_digest": REFLECTIVE_DIARY_EGRESS_V1_DIGEST,
                    "diary_model": selected.diary_model,
                    "diary_model_role": selected.diary_model_role,
                    "diary_persona_digest": selected.diary_persona_digest,
                    "diary_rollback_mode": "local-only",
                    "diary_style_contract_digest": REFLECTIVE_DIARY_STYLE_V1_DIGEST,
                    "egress_policy_digest": HISTORICAL_RAW_RECALL_EGRESS_V1_DIGEST,
                    "egress_policy_mode": "p07-historical-raw-recall-egress-v1",
                    "expected_gid": selected.expected_gid,
                    "expected_uid": selected.expected_uid,
                    "memory_release_set_id": selected.memory_release_set_id,
                    "no_old_data_migration": True,
                    "p15_handoff_schema": "myuna.p07-p15-prompt-ownership-handoff.v1",
                    "p15_projection_active": False,
                    "parent_epoch_id": selected.parent_epoch_id,
                    "parent_epoch_revision": selected.parent_epoch_revision,
                    "parent_manifest_digest": selected.parent_manifest_digest,
                    "parent_release_set_id": selected.parent_release_set_id,
                    "parent_selector_digest": selected.parent_selector_digest,
                    "p08_lifecycle_start_watermark": (
                        selected.p08_lifecycle_start_watermark
                    ),
                    "policy_overlay_id": selected.policy_overlay_id,
                    "prompt_owner": "p07-owner-private-episodic-runtime-v1",
                    "runtime_root": selected.runtime_root.as_posix(),
                    "schema": runtime.SELECTOR_SCHEMA,
                    "status": "active",
                    "summary_used": False,
                }
                selector.write_text(json.dumps(payload), "utf-8")
                os.chmod(selector, 0o640)
                loaded = runtime.load_selected_memory_runtime(
                    selector,
                    expected_selector_gid=os.getegid(),
                )
                self.assertEqual(loaded, selected)
                payload["calendar_zone_config_digest"] = "f" * 64
                selector.write_text(json.dumps(payload), "utf-8")
                with self.assertRaisesRegex(
                    EpisodicMemoryError, "calendar_zone_selection_drifted"
                ):
                    runtime.load_selected_memory_runtime(
                        selector,
                        expected_selector_gid=os.getegid(),
                    )
                payload["calendar_zone_config_digest"] = (
                    selected.calendar_zone_config_digest
                )
                payload["egress_policy_digest"] = "f" * 64
                selector.write_text(json.dumps(payload), "utf-8")
                with self.assertRaisesRegex(EpisodicMemoryError, "egress_policy_drifted"):
                    runtime.load_selected_memory_runtime(
                        selector,
                        expected_selector_gid=os.getegid(),
                    )

    def test_diary_egress_selector_absence_is_local_only_and_exact_binding_is_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selector = root / "diary-egress-selector.json"
            self.assertIsNone(
                runtime.load_selected_diary_egress(
                    selector,
                    expected_selector_gid=os.getegid(),
                )
            )
            with patch.object(runtime, "RUNTIME_ROOT", root):
                memory = selection(root)
                payload = {
                    "archive_id": memory.archive_id,
                    "channel_kind": runtime.CHANNEL_KIND,
                    "client_id": runtime.CORE_CLIENT_ID,
                    "complete_closed_day_required": True,
                    "egress_policy_digest": memory.diary_egress_policy_digest,
                    "expected_gid": memory.expected_gid,
                    "expected_uid": memory.expected_uid,
                    "memory_release_set_id": memory.memory_release_set_id,
                    "model": memory.diary_model,
                    "model_role": memory.diary_model_role,
                    "no_old_data_migration": True,
                    "parent_release_set_id": memory.parent_release_set_id,
                    "partial_day_provider_call": False,
                    "persona_digest": memory.diary_persona_digest,
                    "policy_overlay_id": memory.policy_overlay_id,
                    "rollback_mode": "local-only-disabled",
                    "schema": runtime.DIARY_EGRESS_SELECTOR_SCHEMA,
                    "status": "active",
                    "style_contract_digest": memory.diary_style_contract_digest,
                }
                selector.write_text(json.dumps(payload), "utf-8")
                os.chmod(selector, 0o640)
                selected = runtime.load_selected_diary_egress(
                    selector,
                    expected_selector_gid=os.getegid(),
                )
                self.assertIsNotNone(selected)
                selected.validate_for(memory)
                payload["parent_release_set_id"] = "f" * 64
                selector.write_text(json.dumps(payload), "utf-8")
                drifted = runtime.load_selected_diary_egress(
                    selector,
                    expected_selector_gid=os.getegid(),
                )
                with self.assertRaisesRegex(
                    EpisodicMemoryError,
                    "diary_egress_selector_binding_drifted",
                ):
                    drifted.validate_for(memory)
                os.chmod(selector, 0o600)
                with self.assertRaisesRegex(
                    EpisodicMemoryError,
                    "diary_egress_selector_permissions_rejected",
                ):
                    runtime.load_selected_diary_egress(
                        selector,
                        expected_selector_gid=os.getegid(),
                    )


if __name__ == "__main__":
    unittest.main()
