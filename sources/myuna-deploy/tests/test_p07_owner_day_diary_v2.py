from __future__ import annotations

from datetime import date, datetime, timezone
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from myuna_core.authenticated_conversation import (
    SCHEMA_VERSION as AUTH_SCHEMA,
    AuthenticatedConversationContext,
)
from myuna_core.active_temporal_context.time import TrustedTimeSample
from myuna_core.episodic_memory import EpisodicMemoryError, OwnerDayPolicy

import p07_owner_day_diary_v2 as diary
import p07_owner_private_memory_runtime_v1 as runtime


def auth(*, channel: str = "astrbot_telegram") -> AuthenticatedConversationContext:
    return AuthenticatedConversationContext(
        schema_version=AUTH_SCHEMA,
        request_id="request-owner-day-synthetic",
        correlation_id="correlation-owner-day-synthetic",
        client_id="telegram-owner-private",
        channel_kind=channel,
        binding_id="binding-owner-day-synthetic",
        principal_id="principal-owner-day-synthetic",
        namespace_id="namespace-owner-day-synthetic",
        authority_level="owner",
        channel_instance="telegram-synthetic",
        conversation_id="conversation-synthetic",
        conversation_kind="private",
        event_id="event-owner-day-synthetic",
        trace_id="trace-owner-day-synthetic",
        occurred_at=datetime(2026, 8, 8, tzinfo=timezone.utc),
        delivery_capabilities=("text",),
    )


def trusted_time() -> TrustedTimeSample:
    return TrustedTimeSample(
        datetime(2026, 8, 8, 20, 0, tzinfo=timezone.utc),
        "myuna-trusted-local-v1",
        "trusted_local",
        7,
        authority="systemd-timesyncd",
        uncertainty_microseconds=1_000,
        synchronized=True,
        boot_id="synthetic-boot",
        monotonic_ns=200,
    )


class OwnerDayRuntimeV2Tests(unittest.TestCase):
    @staticmethod
    def memory_selection(root: Path) -> diary.OwnerPrivateMemorySelectionV4:
        return diary.OwnerPrivateMemorySelectionV4(
            memory_release_set_id="1" * 64,
            parent_release_set_id="2" * 64,
            parent_manifest_digest="3" * 64,
            parent_selector_digest="4" * 64,
            parent_epoch_id="telegram-owner-private-external-d-reset-v7",
            parent_epoch_revision=118,
            policy_overlay_id="5" * 64,
            archive_id=root.name,
            runtime_root=root,
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
            egress_policy_digest=diary.HISTORICAL_RAW_RECALL_EGRESS_V1_DIGEST,
            p08_lifecycle_start_watermark=9,
            calendar_zone="Asia/Shanghai",
            calendar_zone_config_digest=diary.calendar_zone_selection_digest(
                "Asia/Shanghai"
            ),
        )

    @staticmethod
    def diary_selection(
        memory: diary.OwnerPrivateMemorySelectionV4,
    ) -> diary.OwnerDayDiarySelectionV2:
        return diary.OwnerDayDiarySelectionV2(
            memory_release_set_id=memory.memory_release_set_id,
            parent_release_set_id=memory.parent_release_set_id,
            policy_overlay_id=memory.policy_overlay_id,
            archive_id=memory.archive_id,
            expected_uid=memory.expected_uid,
            expected_gid=memory.expected_gid,
            owner_day_policy=OwnerDayPolicy(),
            persona_digest="6" * 64,
        )

    @staticmethod
    def deliver(
        memory: runtime.OwnerPrivateMemoryRuntime,
        *,
        token: str = "7" * 64,
    ):
        memory.prepare_control_delivery(
            delivery_token=token,
            turn_id="turn-owner-day-synthetic-1",
            control_kind="diary",
            authenticated_context=auth(),
            owner_message="晚安",
            assistant_reply="Synthetic delivered reply",
            received_monotonic_ns=100,
            committed_monotonic_ns=250,
            source_occurred_at_utc=datetime(
                2026, 8, 8, 20, tzinfo=timezone.utc
            ),
            trusted_time_sample=trusted_time(),
            trusted_time_unresolved_reason=None,
        )
        return memory.resolve_delivery(
            delivery_token=token,
            outcome="delivered",
            delivered_monotonic_ns=300,
            delivered_boot_id="synthetic-boot",
        )

    def test_memory_selector_has_no_diary_identity(self) -> None:
        selection = self.memory_selection(Path("/synthetic-owner-memory-v4"))
        payload = selection.payload()
        self.assertFalse(payload["diary_coupled"])
        self.assertFalse(any("diary_model" in key for key in payload))
        self.assertEqual(
            diary.OwnerPrivateMemorySelectionV4.from_payload(payload), selection
        )

    def test_diary_selector_binds_distinct_closed_and_preview_egress(self) -> None:
        memory = self.memory_selection(Path("/synthetic-owner-memory-v4"))
        selected = self.diary_selection(memory)
        selected.validate_for(memory)
        self.assertNotEqual(
            selected.closed_egress_binding_digest,
            selected.preview_egress_binding_digest,
        )
        self.assertEqual(
            diary.OwnerDayDiarySelectionV2.from_payload(selected.payload()), selected
        )
        drifted = selected.payload()
        drifted["model_role"] = "p07_external_reflective_diary"
        with self.assertRaisesRegex(EpisodicMemoryError, "contract_drifted"):
            diary.OwnerDayDiarySelectionV2.from_payload(drifted)

    def test_runtime_uses_one_derivative_database_and_no_worker_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "owner-memory-v4"
            memory = runtime.OwnerPrivateMemoryRuntime(self.memory_selection(root))
            audit = memory.initialize()
            self.assertTrue((root / "reflective-diary.sqlite3").is_file())
            self.assertFalse((root / "owner-day-state.json").exists())
            self.assertFalse((root / "owner-day-state.jsonl").exists())
            self.assertEqual(audit["diary"]["selected"], False)
            self.assertEqual(audit["diary"]["worker_capable"], False)
            self.assertEqual(audit["diary"]["provider_capable"], False)
            self.assertEqual(audit["diary"]["owner_day_revision_count"], 0)

    def test_mixed_or_orphan_diary_selectors_fail_closed(self) -> None:
        successor = self.memory_selection(Path("/synthetic-owner-memory-v4"))
        with (
            mock.patch.object(
                runtime, "load_selected_memory_runtime", return_value=object()
            ),
            mock.patch.object(
                runtime,
                "load_selected_memory_runtime_v4",
                return_value=successor,
            ),
            mock.patch.object(
                runtime, "load_selected_diary_egress", return_value=None
            ),
            mock.patch.object(
                runtime,
                "load_selected_owner_day_diary_v2",
                return_value=None,
            ),
            self.assertRaisesRegex(EpisodicMemoryError, "mixed_generation"),
        ):
            runtime.load_selected_memory_configuration(
                expected_selector_gid=os.getegid()
            )
        with (
            mock.patch.object(
                runtime, "load_selected_memory_runtime", return_value=None
            ),
            mock.patch.object(
                runtime, "load_selected_memory_runtime_v4", return_value=None
            ),
            mock.patch.object(
                runtime, "load_selected_diary_egress", return_value=None
            ),
            mock.patch.object(
                runtime,
                "load_selected_owner_day_diary_v2",
                return_value=object(),
            ),
            self.assertRaisesRegex(EpisodicMemoryError, "without_memory"),
        ):
            runtime.load_selected_memory_configuration(
                expected_selector_gid=os.getegid()
            )

    def test_delivery_and_replay_do_not_author_or_repair_diary_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "owner-memory-v4"
            selected_memory = self.memory_selection(root)
            memory = runtime.OwnerPrivateMemoryRuntime(
                selected_memory,
                owner_day_diary=self.diary_selection(selected_memory),
            )
            memory.initialize()
            before = memory.diary.path.read_bytes()
            delivered = self.deliver(memory)
            after_delivered = memory.diary.path.read_bytes()
            replay = memory.resolve_delivery(
                delivery_token="7" * 64,
                outcome="delivered",
                delivered_monotonic_ns=None,
            )
            after_replay = memory.diary.path.read_bytes()
            self.assertTrue(delivered.index_current)
            self.assertFalse(delivered.diary_pending)
            self.assertTrue(replay.replayed)
            self.assertEqual(before, after_delivered)
            self.assertEqual(after_delivered, after_replay)
            self.assertEqual(
                memory.diary.audit_projection()["reflective_revision_count"], 0
            )
            self.assertEqual(
                memory.diary.audit_projection()["owner_day_revision_count"], 0
            )

    def test_explicit_rebuild_repairs_index_gap_without_authored_diary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "owner-memory-v4"
            selected_memory = self.memory_selection(root)
            memory = runtime.OwnerPrivateMemoryRuntime(
                selected_memory,
                owner_day_diary=self.diary_selection(selected_memory),
            )
            memory.initialize()
            diary_before = memory.diary.path.read_bytes()
            with mock.patch.object(
                runtime,
                "recover_or_write_snapshot",
                side_effect=EpisodicMemoryError("synthetic_owner_day_gap"),
            ):
                delivered = self.deliver(memory)
            self.assertEqual(
                delivered.derivative_gap_code, "synthetic_owner_day_gap"
            )
            replay = memory.resolve_delivery(
                delivery_token="7" * 64,
                outcome="delivered",
                delivered_monotonic_ns=None,
            )
            self.assertTrue(replay.replayed)
            self.assertFalse(replay.index_current)
            rebuilt = memory.rebuild_derivatives()
            self.assertEqual(rebuilt["archive_turn_count"], 1)
            self.assertEqual(diary_before, memory.diary.path.read_bytes())
            self.assertEqual(rebuilt["diary"]["reflective_revision_count"], 0)
            self.assertEqual(rebuilt["diary"]["owner_day_revision_count"], 0)

    def test_persistence_route_is_retired_but_pure_state_semantics_remain(self) -> None:
        self.assertFalse(hasattr(diary, "OwnerDayStateStore"))
        self.assertFalse(hasattr(runtime.OwnerPrivateMemoryRuntime, "owner_day_state"))
        policy = OwnerDayPolicy()
        state = diary.state_for_delivered_turn(
            None,
            policy=policy,
            delivered_at_utc=datetime(2026, 8, 8, 20, tzinfo=timezone.utc),
            turn_sequence=1,
            turn_digest="1" * 64,
        )
        replay = diary.state_for_delivered_turn(
            state,
            policy=policy,
            delivered_at_utc=datetime(2026, 8, 8, 20, tzinfo=timezone.utc),
            turn_sequence=1,
            turn_digest="1" * 64,
        )
        self.assertEqual(replay, state)
        with self.assertRaisesRegex(EpisodicMemoryError, "replayed_or_gapped"):
            diary.state_for_delivered_turn(
                state,
                policy=policy,
                delivered_at_utc=datetime(2026, 8, 8, 21, tzinfo=timezone.utc),
                turn_sequence=3,
                turn_digest="3" * 64,
            )

    def test_owner_day_and_action_semantics_are_deterministic(self) -> None:
        policy = OwnerDayPolicy()
        instant = datetime(2026, 8, 8, 8, tzinfo=timezone.utc)
        self.assertEqual(diary.owner_day_label(instant, policy), date(2026, 8, 8))
        self.assertEqual(
            diary.owner_day_label(
                instant,
                OwnerDayPolicy(calendar_zone="America/Los_Angeles"),
            ),
            date(2026, 8, 7),
        )
        state = diary.state_for_delivered_turn(
            None,
            policy=policy,
            delivered_at_utc=datetime(2026, 8, 8, 20, tzinfo=timezone.utc),
            turn_sequence=1,
            turn_digest="1" * 64,
        )
        action = diary.admit_owner_day_action(
            auth(),
            "晚安",
            turn_sequence=1,
            turn_digest="1" * 64,
            issued_at_utc=datetime(2026, 8, 8, 20, 1, tzinfo=timezone.utc),
        )
        pending = diary.apply_bedtime_action(state, action, policy)  # type: ignore[arg-type]
        self.assertTrue(
            diary.soft_close_ready(
                pending,
                datetime(2026, 8, 8, 22, 0, tzinfo=timezone.utc),
            )
        )
        with self.assertRaisesRegex(
            EpisodicMemoryError, "owner_day_action_identity_rejected"
        ):
            diary.admit_owner_day_action(
                auth(channel="astrbot_qq"),
                "/Diary preview",
                turn_sequence=1,
                turn_digest="1" * 64,
                issued_at_utc=datetime(
                    2026, 8, 8, 20, 1, tzinfo=timezone.utc
                ),
            )


if __name__ == "__main__":
    unittest.main()
