from __future__ import annotations

import ast
from dataclasses import replace
from datetime import datetime, timezone
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from myuna_core.active_temporal_context.time import TrustedTimeSample
from myuna_core.active_temporal_context.protocol import build_active_snapshot_receipt
from myuna_core.external_context.projection import ProjectionBudget
from myuna_core.episodic_memory.contracts import (
    EpisodicMemoryError,
    PrefixCapsule,
    PrefixCompactionPolicy,
)
from myuna_core.episodic_memory.context import (
    ContextOccupancy,
    PrefixCompactionPlan,
)
from myuna_core.episodic_memory.runtime_context import (
    EpisodicProjectionBuilder,
    EpisodicRuntimeContext,
)
from myuna_core.memory_aware_turn_protocol import (
    MEMORY_OPERATIONS,
    FinalBranch,
    MemoryAwareTurnError,
    MemoryCatalog,
    MemoryCatalogEntry,
    MemoryRequest,
    ServerIntentProposal,
    TurnBudget,
    create_memory_outcome,
    create_turn_step,
    final_for_turn,
    request_for_turn,
)

import p07_owner_private_memory_runtime_v1 as memory_module
import telegram_owner_runtime_gateway as gateway
from context_window_policy import ConversationHistory, InMemoryContextStore
from telegram_runtime_config import RuntimeConfig
from turn_pacing_policy import BoundedTurnPacingPolicy


ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = (
    ROOT / "channels" / "astrbot-telegram" / "plugin" / "myuna_telegram_gateway" / "protocol.py"
)


def _protocol():
    spec = importlib.util.spec_from_file_location("p07_memory_gateway_protocol", PROTOCOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeConnection:
    def __init__(self, payload: object) -> None:
        self.request = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8") + b"\n"
        self.sent = bytearray()

    def settimeout(self, _value: float) -> None:
        pass

    def recv(self, _size: int) -> bytes:
        selected, self.request = self.request, b""
        return selected

    def sendall(self, value: bytes) -> None:
        self.sent.extend(value)


def config() -> RuntimeConfig:
    return RuntimeConfig(
        channel_kind="astrbot_telegram",
        binding_id="binding-synthetic-owner",
        principal_id="principal-synthetic-owner",
        namespace_id="namespace-synthetic-owner",
        finalization_digest="1" * 64,
        evidence_sha256="2" * 64,
        channel_instance="telegram-synthetic",
        core_host="127.0.0.1",
        core_port=19001,
        max_requests_per_ten_minutes=60,
        max_history_messages=128,
        max_history_characters=131_072,
    )


def selection(root: Path) -> memory_module.OwnerPrivateMemorySelection:
    runtime_root = root / "owner-private-memory-gateway-v1"
    runtime_root.mkdir(mode=0o700, parents=False, exist_ok=True)
    return memory_module.OwnerPrivateMemorySelection(
        memory_release_set_id="a" * 64,
        parent_release_set_id="b" * 64,
        parent_manifest_digest="c" * 64,
        parent_selector_digest="d" * 64,
        parent_epoch_id="telegram-owner-private-external-d-reset-v7",
        parent_epoch_revision=63,
        policy_overlay_id="e" * 64,
        archive_id="owner-private-memory-gateway-v1",
        runtime_root=runtime_root,
        expected_uid=os.geteuid(),
        expected_gid=os.getegid(),
        egress_policy_digest=memory_module.HISTORICAL_RAW_RECALL_EGRESS_V1_DIGEST,
        diary_egress_policy_digest=memory_module.REFLECTIVE_DIARY_EGRESS_V1_DIGEST,
        diary_style_contract_digest=memory_module.REFLECTIVE_DIARY_STYLE_V1_DIGEST,
        diary_persona_digest="6" * 64,
        diary_model="deepseek-v4-flash",
        diary_model_role="p07_external_daily_reflective_diary",
        p08_lifecycle_start_watermark=0,
        calendar_zone="Asia/Shanghai",
        calendar_zone_config_digest=(
            memory_module.calendar_zone_selection_digest("Asia/Shanghai")
        ),
    )


def temporal_response(
    request_id: str,
    *,
    after_event_sequence: int = 0,
) -> dict[str, object]:
    sample = TrustedTimeSample(
        datetime(2026, 8, 8, 12, tzinfo=timezone.utc),
        "myuna-trusted-local-v1",
        "trusted_local",
        9,
        authority="systemd-timesyncd",
        uncertainty_microseconds=1_000,
        synchronized=True,
        boot_id="synthetic-boot",
        monotonic_ns=10**18,
    )
    output: dict[str, object] = {
        "context": "[p08_rendered_context_must_not_reach_prompt]",
        "fact_count": 0,
        "lifecycle_has_more": False,
        "lifecycle_transitions": [],
        "lifecycle_watermark": 0,
        "projection_digest": "3" * 64,
        "trusted_time": sample.as_payload(),
    }
    output["active_snapshot_receipt"] = build_active_snapshot_receipt(
        request_id=request_id,
        after_event_sequence=after_event_sequence,
        fact_count=0,
        lifecycle_transitions=(),
        lifecycle_watermark=0,
        lifecycle_has_more=False,
        trusted_time=sample.as_payload(),
    ).as_payload()
    return {
        "schema": "myuna.active-temporal-context-protocol.v1",
        "request_id": request_id,
        "ok": True,
        "operation": "snapshot_active",
        "output": output,
        "model_called": False,
        "profile_written": False,
        "session_written": False,
        "legacy_namespace_written": False,
    }


class SyntheticCore:
    def __init__(self, selected_config: RuntimeConfig) -> None:
        self.config = selected_config
        self.calls = 0

    def chat(self, messages, *, decision, external_context=None):
        self.calls += 1
        self.asserted_messages = messages
        if external_context is None:
            return gateway.CoreReply(
                reply="Synthetic isolated control reply",
                actual_route="local_control",
                provenance=None,
            )
        authenticated = gateway._authenticated_context(decision, self.config)
        context = EpisodicRuntimeContext.from_payload(
            external_context,
            authenticated_context=authenticated,
        )
        definition = "Synthetic approved Definition"
        projection, provenance = EpisodicProjectionBuilder(
            ProjectionBudget(200_000, 1_198_096, 999_232),
            token_counter=lambda values: sum(
                len(item["content"].encode("utf-8")) for item in values
            ),
        ).build(
            definition=definition,
            definition_digest=sha256(definition.encode()).hexdigest(),
            context=context,
            profile=None,
        )
        self.projection = projection
        return gateway.CoreReply(
            reply="Myuna synthetic delivered reply",
            actual_route="deepseek_default",
            provenance=provenance,
        )


class OwnerPrivateMemoryGatewayIntegrationTests(unittest.TestCase):
    def test_delivery_v2_rejects_trace_substitution_before_runtime_access(self) -> None:
        signing_secret = b"synthetic-telegram-signing-secret-32-bytes"
        trace_id = "trace-" + "a" * 32
        token = gateway._trace_bound_delivery_token(signing_secret, trace_id)

        class UnopenedRuntime:
            calls = 0

            def delivery_close_evidence_required(self, _token):
                self.calls += 1
                raise AssertionError("runtime must remain unopened")

        runtime = UnopenedRuntime()
        with self.assertRaises(gateway.RuntimeRejected):
            gateway._process_memory_delivery_outcome(
                FakeConnection({}),
                {
                    "delivery_token": token,
                    "outcome": "delivered",
                    "schema": gateway.DELIVERY_OUTCOME_SCHEMA,
                    "trace_id": "trace-" + "b" * 32,
                },
                memory_runtime=runtime,
                signing_secret=signing_secret,
            )
        self.assertEqual(runtime.calls, 0)

    def test_profile_v2_proposal_commits_only_after_delivered_callback(self) -> None:
        protocol = _protocol()
        selected_config = config()
        signing_secret = b"synthetic-telegram-signing-secret-32-bytes"
        now = datetime.now(timezone.utc)
        signed = protocol.build_signed_envelope(
            sender_id="123456789",
            message_text="将亲密度设为 12.5",
            message_id="synthetic-profile-v2-proposal",
            raw_timestamp=now.timestamp(),
            signing_secret=signing_secret,
            channel_instance=selected_config.channel_instance,
            now=now,
            nonce_factory=lambda: "p" * 32,
        )
        request = {
            "event": signed["event"],
            "routing": {"hybrid_external_generation": True},
            "signature": signed["signature"],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(memory_module, "RUNTIME_ROOT", root):
                memory = memory_module.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
            core = SyntheticCore(selected_config)

            def send_temporal(payload):
                return temporal_response(
                    str(payload["request_id"]),
                    after_event_sequence=int(
                        payload["input"]["after_event_sequence"]
                    ),
                )

            connection = FakeConnection(request)
            common = dict(
                config=selected_config,
                signing_secret=signing_secret,
                identity_pepper=b"synthetic-identity-pepper-32-bytes",
                core=core,
                limiter=gateway.SlidingRateLimiter(60),
                history=ConversationHistory(128, 131_072, store=InMemoryContextStore()),
                hybrid_enabled=True,
                memory_runtime=memory,
                pending_deliveries={},
                pacing_policy=BoundedTurnPacingPolicy(maximum_delay_seconds=5),
                requested_pacing_seconds=0,
            )
            with (
                patch.object(gateway, "claim_inbound", return_value=True),
                patch.object(gateway, "resolve_verified_owner", return_value=True),
                patch.object(gateway, "record_outcome", return_value=True),
                patch.object(gateway, "send_temporal_request", side_effect=send_temporal),
            ):
                gateway.process_connection(connection, **common)
            response = json.loads(bytes(connection.sent).splitlines()[0])
            self.assertEqual(response["kind"], "accepted_reply")
            self.assertEqual(core.calls, 0)
            proposal_id = "profile-" + response["delivery_token"][:24]
            with self.assertRaises(EpisodicMemoryError):
                memory.diary.current_profile_proposal(proposal_id, 1)

            ack = FakeConnection(
                {
                    "delivery_token": response["delivery_token"],
                    "outcome": "delivered",
                    "schema": gateway.DELIVERY_OUTCOME_SCHEMA,
                    "trace_id": signed["event"]["trace_id"],
                }
            )
            with patch.object(
                gateway,
                "read_current_boot_identity",
                return_value="synthetic-boot",
            ):
                gateway.process_connection(ack, **common)
            proposal = memory.diary.current_profile_proposal(proposal_id, 1)
            self.assertEqual(proposal.proposal_value, 125_000)
            self.assertEqual(proposal.delivered_turn_id, memory.archive.turns()[-1].draft.turn_id)

    def test_temporal_help_archives_isolated_with_the_single_p10_sample(self) -> None:
        protocol = _protocol()
        selected_config = config()
        signing_secret = b"synthetic-telegram-signing-secret-32-bytes"
        now = datetime.now(timezone.utc)
        signed = protocol.build_signed_envelope(
            sender_id="123456789",
            message_text="/temporal",
            message_id="synthetic-temporal-help",
            raw_timestamp=now.timestamp(),
            signing_secret=signing_secret,
            channel_instance=selected_config.channel_instance,
            now=now,
            nonce_factory=lambda: "t" * 32,
        )
        request = {
            "event": signed["event"],
            "routing": {"hybrid_external_generation": True},
            "signature": signed["signature"],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(memory_module, "RUNTIME_ROOT", root):
                memory = memory_module.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
            core = SyntheticCore(selected_config)
            calls = []

            def send_temporal(payload):
                calls.append(payload)
                return temporal_response(
                    str(payload["request_id"]),
                    after_event_sequence=int(
                        payload["input"]["after_event_sequence"]
                    ),
                )

            connection = FakeConnection(request)
            common = dict(
                config=selected_config,
                signing_secret=signing_secret,
                identity_pepper=b"synthetic-identity-pepper-32-bytes",
                core=core,
                limiter=gateway.SlidingRateLimiter(60),
                history=ConversationHistory(128, 131_072, store=InMemoryContextStore()),
                hybrid_enabled=True,
                memory_runtime=memory,
                pending_deliveries={},
                pacing_policy=BoundedTurnPacingPolicy(maximum_delay_seconds=5),
                requested_pacing_seconds=0,
            )
            with (
                patch.object(gateway, "claim_inbound", return_value=True),
                patch.object(gateway, "resolve_verified_owner", return_value=True),
                patch.object(gateway, "record_outcome", return_value=True),
                patch.object(gateway, "send_temporal_request", side_effect=send_temporal),
            ):
                gateway.process_connection(connection, **common)
            response = json.loads(bytes(connection.sent).splitlines()[0])
            self.assertEqual(response["kind"], "accepted_reply")
            self.assertEqual(len(calls), 1)
            self.assertEqual(core.calls, 0)
            ack = FakeConnection(
                {
                    "delivery_token": response["delivery_token"],
                    "outcome": "delivered",
                    "schema": gateway.DELIVERY_OUTCOME_SCHEMA,
                    "trace_id": signed["event"]["trace_id"],
                }
            )
            with patch.object(
                gateway,
                "read_current_boot_identity",
                return_value="synthetic-boot",
            ):
                gateway.process_connection(ack, **common)
            archived = memory.archive.turns()[0]
            self.assertFalse(archived.model_history_eligible)
            self.assertEqual(archived.draft.time_binding.sequence, 9)
            self.assertIn(
                "control_temporal_isolated",
                archived.draft.provenance_categories,
            )

    def test_check_turn_is_archived_exactly_once_but_excluded_from_chat_history(self) -> None:
        protocol = _protocol()
        selected_config = config()
        signing_secret = b"synthetic-telegram-signing-secret-32-bytes"
        now = datetime.now(timezone.utc)

        def envelope(message: str, message_id: str, nonce: str):
            signed = protocol.build_signed_envelope(
                sender_id="123456789",
                message_text=message,
                message_id=message_id,
                raw_timestamp=now.timestamp(),
                signing_secret=signing_secret,
                channel_instance=selected_config.channel_instance,
                now=now,
                nonce_factory=lambda: nonce,
            )
            return {
                "event": signed["event"],
                "routing": {"hybrid_external_generation": True},
                "signature": signed["signature"],
            }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(memory_module, "RUNTIME_ROOT", root):
                memory = memory_module.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
            core = SyntheticCore(selected_config)

            def send_temporal(payload):
                return temporal_response(
                    str(payload["request_id"]),
                    after_event_sequence=int(
                        payload["input"]["after_event_sequence"]
                    ),
                )

            common = dict(
                config=selected_config,
                signing_secret=signing_secret,
                identity_pepper=b"synthetic-identity-pepper-32-bytes",
                core=core,
                limiter=gateway.SlidingRateLimiter(60),
                history=ConversationHistory(128, 131_072, store=InMemoryContextStore()),
                hybrid_enabled=True,
                memory_runtime=memory,
                pending_deliveries={},
                pacing_policy=BoundedTurnPacingPolicy(maximum_delay_seconds=5),
                requested_pacing_seconds=0,
            )
            with (
                patch.object(gateway, "claim_inbound", return_value=True),
                patch.object(gateway, "resolve_verified_owner", return_value=True),
                patch.object(gateway, "record_outcome", return_value=True),
                patch.object(gateway, "send_temporal_request", side_effect=send_temporal),
                patch.object(
                    gateway,
                    "read_current_boot_identity",
                    return_value="synthetic-boot",
                ),
            ):
                control_payload = envelope(
                    "/Check synthetic", "synthetic-control-1", "c" * 32
                )
                control_connection = FakeConnection(control_payload)
                gateway.process_connection(control_connection, **common)
                control_response = json.loads(bytes(control_connection.sent).splitlines()[0])
                self.assertEqual(control_response["kind"], "accepted_reply")
                self.assertIn("delivery_token", control_response)
                ack = FakeConnection(
                    {
                        "delivery_token": control_response["delivery_token"],
                        "outcome": "delivered",
                        "schema": gateway.DELIVERY_OUTCOME_SCHEMA,
                        "trace_id": control_payload["event"]["trace_id"],
                    }
                )
                gateway.process_connection(ack, **common)
                ordinary_connection = FakeConnection(
                    envelope(
                        "Cealana建议去江边走走。",
                        "synthetic-ordinary-after-control",
                        "d" * 32,
                    )
                )
                gateway.process_connection(ordinary_connection, **common)

            archived = memory.archive.turns()
            self.assertEqual(len(archived), 1)
            self.assertFalse(archived[0].model_history_eligible)
            projected = "\n".join(
                item["content"] for item in core.projection.messages
            )
            self.assertNotIn("/Check synthetic", projected)
            self.assertIn("Cealana建议去江边走走。", projected)

    def test_temporal_unavailable_still_archives_delivered_turn_as_unresolved(self) -> None:
        protocol = _protocol()
        selected_config = config()
        signing_secret = b"synthetic-telegram-signing-secret-32-bytes"
        now = datetime.now(timezone.utc)
        envelope = protocol.build_signed_envelope(
            sender_id="123456789",
            message_text="Synthetic trusted-time unavailable turn",
            message_id="synthetic-memory-unresolved-1",
            raw_timestamp=now.timestamp(),
            signing_secret=signing_secret,
            channel_instance=selected_config.channel_instance,
            now=now,
            nonce_factory=lambda: "u" * 32,
        )
        request = {
            "event": envelope["event"],
            "routing": {"hybrid_external_generation": True},
            "signature": envelope["signature"],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(memory_module, "RUNTIME_ROOT", root):
                memory = memory_module.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
            core = SyntheticCore(selected_config)
            connection = FakeConnection(request)
            with (
                patch.object(gateway, "claim_inbound", return_value=True),
                patch.object(gateway, "resolve_verified_owner", return_value=True),
                patch.object(gateway, "record_outcome", return_value=True),
                patch.object(
                    gateway,
                    "send_temporal_request",
                    side_effect=gateway.TemporalGatewayRejected(
                        "trusted_time_unavailable", retryable=True
                    ),
                ),
            ):
                gateway.process_connection(
                    connection,
                    config=selected_config,
                    signing_secret=signing_secret,
                    identity_pepper=b"synthetic-identity-pepper-32-bytes",
                    core=core,
                    limiter=gateway.SlidingRateLimiter(60),
                    history=ConversationHistory(128, 131_072, store=InMemoryContextStore()),
                    hybrid_enabled=True,
                    memory_runtime=memory,
                    pending_deliveries={},
                    pacing_policy=BoundedTurnPacingPolicy(maximum_delay_seconds=5),
                    requested_pacing_seconds=0,
                )
            response = json.loads(bytes(connection.sent).splitlines()[0])
            self.assertEqual(response["kind"], "accepted_reply")
            self.assertEqual(core.projection.temporal_coverage_state, "unavailable")
            delivery = FakeConnection(
                {
                    "delivery_token": response["delivery_token"],
                    "outcome": "delivered",
                    "schema": gateway.DELIVERY_OUTCOME_SCHEMA,
                    "trace_id": envelope["event"]["trace_id"],
                }
            )
            gateway.process_connection(
                delivery,
                config=selected_config,
                signing_secret=signing_secret,
                identity_pepper=b"synthetic-identity-pepper-32-bytes",
                core=core,
                limiter=gateway.SlidingRateLimiter(60),
                history=ConversationHistory(128, 131_072, store=InMemoryContextStore()),
                hybrid_enabled=True,
                memory_runtime=memory,
                pending_deliveries={},
                pacing_policy=BoundedTurnPacingPolicy(maximum_delay_seconds=5),
                requested_pacing_seconds=0,
            )
            archived = memory.archive.turns()[0]
            self.assertEqual(archived.draft.time_binding.status, "unresolved")

    def test_authenticated_ingress_projection_and_delivery_ack_append_once(self) -> None:
        protocol = _protocol()
        selected_config = config()
        signing_secret = b"synthetic-telegram-signing-secret-32-bytes"
        now = datetime.now(timezone.utc)
        envelope = protocol.build_signed_envelope(
            sender_id="123456789",
            message_text="Cealana建议去江边走走。",
            message_id="synthetic-memory-1",
            raw_timestamp=now.timestamp(),
            signing_secret=signing_secret,
            channel_instance=selected_config.channel_instance,
            now=now,
            nonce_factory=lambda: "n" * 32,
        )
        request = {
            "event": envelope["event"],
            "routing": {"hybrid_external_generation": True},
            "signature": envelope["signature"],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(memory_module, "RUNTIME_ROOT", root):
                memory = memory_module.OwnerPrivateMemoryRuntime(selection(root))
                memory.initialize()
            core = SyntheticCore(selected_config)
            outcomes = []

            def send_temporal(payload):
                return temporal_response(
                    str(payload["request_id"]),
                    after_event_sequence=int(
                        payload["input"]["after_event_sequence"]
                    ),
                )

            connection = FakeConnection(request)
            with (
                patch.object(gateway, "claim_inbound", return_value=True),
                patch.object(gateway, "resolve_verified_owner", return_value=True),
                patch.object(
                    gateway,
                    "record_outcome",
                    side_effect=lambda _decision, outcome, code: outcomes.append((outcome, code)) or True,
                ),
                patch.object(gateway, "send_temporal_request", side_effect=send_temporal),
            ):
                gateway.process_connection(
                    connection,
                    config=selected_config,
                    signing_secret=signing_secret,
                    identity_pepper=b"synthetic-identity-pepper-32-bytes",
                    core=core,
                    limiter=gateway.SlidingRateLimiter(60),
                    history=ConversationHistory(
                        128,
                        131_072,
                        store=InMemoryContextStore(),
                    ),
                    hybrid_enabled=True,
                    memory_runtime=memory,
                    pending_deliveries={},
                    pacing_policy=BoundedTurnPacingPolicy(maximum_delay_seconds=5),
                    requested_pacing_seconds=0,
                )
            response = json.loads(bytes(connection.sent).splitlines()[0])
            self.assertEqual(response["kind"], "accepted_reply")
            self.assertEqual(core.calls, 1)
            self.assertEqual(core.asserted_messages, [{"role": "user", "content": "Cealana建议去江边走走。"}])
            self.assertIsNone(core.projection.summary_version)
            projected = "\n".join(
                item["content"] for item in core.projection.messages
            )
            self.assertNotIn("p08_rendered_context_must_not_reach_prompt", projected)
            self.assertIn("resident_temporal_projection_v1", projected)
            self.assertEqual(memory.archive.metadata()["turn_count"], 0)
            delivery = FakeConnection(
                {
                    "delivery_token": response["delivery_token"],
                    "outcome": "delivered",
                    "schema": gateway.DELIVERY_OUTCOME_SCHEMA,
                    "trace_id": envelope["event"]["trace_id"],
                }
            )
            with patch.object(
                gateway,
                "read_current_boot_identity",
                return_value="synthetic-boot",
            ):
                gateway.process_connection(
                    delivery,
                    config=selected_config,
                    signing_secret=signing_secret,
                    identity_pepper=b"synthetic-identity-pepper-32-bytes",
                    core=core,
                    limiter=gateway.SlidingRateLimiter(60),
                    history=ConversationHistory(
                        128,
                        131_072,
                        store=InMemoryContextStore(),
                    ),
                    hybrid_enabled=True,
                    memory_runtime=memory,
                    pending_deliveries={},
                    pacing_policy=BoundedTurnPacingPolicy(maximum_delay_seconds=5),
                    requested_pacing_seconds=0,
                )
            self.assertEqual(memory.archive.metadata()["turn_count"], 1)
            self.assertEqual(memory.journal.metadata()["pending_count"], 0)
            self.assertIn(("accepted", "owner_runtime_replied"), outcomes)
            stored = memory.journal.resolve(
                delivery_token=response["delivery_token"],
                outcome="delivered",
                delivered_monotonic_ns=None,
            )
            before = {
                path.relative_to(root): path.read_bytes()
                for path in root.rglob("*")
                if path.is_file() and not path.is_symlink()
            }
            duplicate = FakeConnection({})
            with patch.object(
                gateway.time, "monotonic_ns", return_value=stored.delivered_monotonic_ns + 1
            ) as clock:
                self.assertTrue(
                    gateway._process_memory_delivery_outcome(
                        duplicate,
                        {
                            "delivery_token": response["delivery_token"],
                            "outcome": "delivered",
                            "schema": gateway.DELIVERY_OUTCOME_SCHEMA,
                            "trace_id": envelope["event"]["trace_id"],
                        },
                        memory_runtime=memory,
                        signing_secret=signing_secret,
                    )
                )
                clock.assert_not_called()
            after = {
                path.relative_to(root): path.read_bytes()
                for path in root.rglob("*")
                if path.is_file() and not path.is_symlink()
            }
            replay = memory.journal.resolve(
                delivery_token=response["delivery_token"],
                outcome="delivered",
                delivered_monotonic_ns=None,
            )
            self.assertTrue(replay.replayed)
            self.assertEqual(replay.delivered_monotonic_ns, stored.delivered_monotonic_ns)
            self.assertEqual(replay.delivery_ack_digest, stored.delivery_ack_digest)
            self.assertEqual(after, before)
            turn = memory.archive.turns()[0]
            snapshot = memory._load_current_source_snapshot()
            policy = PrefixCompactionPolicy.balanced_default()
            text = "江边建议已记录"
            source_characters = len(turn.draft.owner.text) + len(
                turn.draft.assistant.text
            )
            source_bytes = len(turn.draft.owner.text.encode("utf-8")) + len(
                turn.draft.assistant.text.encode("utf-8")
            )
            capsule_bytes = len(text.encode("utf-8"))
            capsule = PrefixCapsule(
                capsule_id="synthetic-gateway-prefix",
                revision=1,
                parent_capsule_digest="0" * 64,
                archive_id=snapshot.archive_id,
                epoch_id=turn.draft.epoch_id,
                source_snapshot_head_digest=snapshot.archive_head_digest,
                source_snapshot_turn_count=1,
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
            occupancy = ContextOccupancy(
                policy_version=policy.policy_version,
                total_complete_turns=1,
                projected_complete_turns=0,
                raw_history_characters=0,
                fixed_context_characters=1,
                current_turn_characters=1,
                projection_characters=1,
                request_characters=1,
                serialized_bytes=1,
                input_tokens=1,
                request_headroom=5_000,
                projection_headroom=5_000,
                serialized_headroom=15_000,
                token_headroom=15_000,
                limiting_oracle=None,
                fit=True,
                capsule_used_count=1,
            )
            generation_plan = PrefixCompactionPlan(
                action="generate_prefix_capsule",
                policy_version=policy.policy_version,
                capsule=None,
                raw_turns=(),
                prefix_end=1,
                recent_tail_start=2,
                overflow_action=None,
                reason_code="minimum_prefix_generation_required",
                occupancy=occupancy,
            )
            submitted = replace(capsule)
            original_from_payload = PrefixCapsule.from_payload
            reconstruction_calls = 0
            changed = False
            committed = []

            def controlled_from_payload(payload):
                nonlocal reconstruction_calls
                reconstruction_calls += 1
                if reconstruction_calls == 1:
                    return submitted
                return original_from_payload(payload)

            def adversarial_token_counter(messages):
                nonlocal changed
                if not changed:
                    object.__setattr__(submitted, "revision", True)
                    changed = True
                return sum(len(item["content"].encode("utf-8")) for item in messages)

            def capture_commit(canonical, receipt, counter):
                committed.append((canonical, receipt, counter))
                return canonical.capsule_digest

            with patch.object(
                PrefixCapsule,
                "from_payload",
                side_effect=controlled_from_payload,
            ):
                canonical = gateway.run_dynamic_prefix_capsule_generation(
                    (turn,),
                    plan=generation_plan,
                    archive_id=snapshot.archive_id,
                    archive_head_digest=snapshot.archive_head_digest,
                    policy=policy,
                    generator_version=capsule.generator_version,
                    model_provider_class=capsule.model_provider_class,
                    trusted_created_at_utc=capsule.created_at_utc,
                    token_counter=adversarial_token_counter,
                    generate=lambda _turns, _repair: capsule.payload(),
                    commit=capture_commit,
                )
            self.assertTrue(changed)
            self.assertIs(type(submitted.revision), bool)
            self.assertEqual(reconstruction_calls, 2)
            self.assertEqual(len(committed), 1)
            self.assertIsNot(canonical, submitted)
            self.assertIs(canonical, committed[0][0])
            self.assertIs(canonical, committed[0][1][0])
            self.assertIs(type(canonical.revision), int)
            self.assertEqual(canonical.revision, 1)
            self.assertIs(committed[0][2], adversarial_token_counter)

            generated = gateway.run_dynamic_prefix_capsule_generation(
                (turn,),
                plan=generation_plan,
                archive_id=snapshot.archive_id,
                archive_head_digest=snapshot.archive_head_digest,
                policy=policy,
                generator_version=capsule.generator_version,
                model_provider_class=capsule.model_provider_class,
                trusted_created_at_utc=capsule.created_at_utc,
                token_counter=lambda messages: sum(
                    len(item["content"].encode("utf-8")) for item in messages
                ),
                generate=lambda _turns, _repair: capsule.payload(),
                commit=memory.commit_prefix_capsule,
            )
            self.assertEqual(generated, capsule)
            capsule_bytes_before_replay = memory.diary.path.read_bytes()
            self.assertEqual(
                gateway.run_dynamic_prefix_capsule_generation(
                    (turn,),
                    plan=generation_plan,
                    archive_id=snapshot.archive_id,
                    archive_head_digest=snapshot.archive_head_digest,
                    policy=policy,
                    generator_version=capsule.generator_version,
                    model_provider_class=capsule.model_provider_class,
                    trusted_created_at_utc=capsule.created_at_utc,
                    token_counter=lambda messages: sum(
                        len(item["content"].encode("utf-8")) for item in messages
                    ),
                    generate=lambda _turns, _repair: capsule.payload(),
                    commit=memory.commit_prefix_capsule,
                ),
                capsule,
            )
            self.assertEqual(
                memory.diary.path.read_bytes(), capsule_bytes_before_replay
            )
            with patch.object(memory, "commit_prefix_capsule") as commit:
                with self.assertRaisesRegex(
                    EpisodicMemoryError,
                    "prefix_capsule_source_binding_mismatch",
                ):
                    gateway.run_dynamic_prefix_capsule_generation(
                        (turn,),
                        plan=generation_plan,
                        archive_id=snapshot.archive_id,
                        archive_head_digest=snapshot.archive_head_digest,
                        policy=policy,
                        generator_version=capsule.generator_version,
                        model_provider_class=capsule.model_provider_class,
                        trusted_created_at_utc=capsule.created_at_utc,
                        token_counter=lambda messages: sum(
                            len(item["content"].encode("utf-8"))
                            for item in messages
                        ),
                        generate=lambda _turns, _repair: replace(
                            capsule,
                            source_turn_ids=("substituted-turn",),
                        ).payload(),
                        commit=commit,
                    )
                commit.assert_not_called()
            with patch.object(memory, "commit_prefix_capsule") as commit:
                with self.assertRaisesRegex(
                    EpisodicMemoryError,
                    "prefix_capsule_generation_binding_mismatch",
                ):
                    gateway.run_dynamic_prefix_capsule_generation(
                        (turn,),
                        plan=generation_plan,
                        archive_id=snapshot.archive_id,
                        archive_head_digest=snapshot.archive_head_digest,
                        policy=policy,
                        generator_version=capsule.generator_version,
                        model_provider_class=capsule.model_provider_class,
                        trusted_created_at_utc=capsule.created_at_utc,
                        token_counter=lambda messages: sum(
                            len(item["content"].encode("utf-8"))
                            for item in messages
                        ),
                        generate=lambda _turns, _repair: replace(
                            capsule,
                            generator_version="substituted-generator-v1",
                        ).payload(),
                        commit=commit,
                    )
                commit.assert_not_called()

            attempts: list[bool] = []

            def repair_once(_turns, repair):
                attempts.append(repair)
                if not repair:
                    return {"schema": "malformed"}
                return capsule.payload()

            before_repair = memory.diary.path.read_bytes()
            self.assertEqual(
                gateway.run_dynamic_prefix_capsule_generation(
                    (turn,),
                    plan=generation_plan,
                    archive_id=snapshot.archive_id,
                    archive_head_digest=snapshot.archive_head_digest,
                    policy=policy,
                    generator_version=capsule.generator_version,
                    model_provider_class=capsule.model_provider_class,
                    trusted_created_at_utc=capsule.created_at_utc,
                    token_counter=lambda messages: sum(
                        len(item["content"].encode("utf-8"))
                        for item in messages
                    ),
                    generate=repair_once,
                    commit=memory.commit_prefix_capsule,
                ),
                capsule,
            )
            self.assertEqual(attempts, [False, True])
            self.assertEqual(memory.diary.path.read_bytes(), before_repair)

    def test_dynamic_prefix_generation_seam_is_inactive_and_nonrecursive(self) -> None:
        gateway_path = ROOT / "scripts" / "telegram_owner_runtime_gateway.py"
        tree = ast.parse(gateway_path.read_text(encoding="utf-8"))
        definitions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and node.name == "run_dynamic_prefix_capsule_generation"
        ]
        self.assertEqual(len(definitions), 1)
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and (
                isinstance(node.func, ast.Name)
                and node.func.id == "run_dynamic_prefix_capsule_generation"
                or isinstance(node.func, ast.Attribute)
                and node.func.attr == "run_dynamic_prefix_capsule_generation"
            )
        ]
        self.assertEqual(calls, [])
        names = {
            node.id
            for node in ast.walk(definitions[0])
            if isinstance(node, ast.Name)
        }
        self.assertFalse(
            names
            & {
                "BackgroundSummaryWorker",
                "ExternalSummaryCandidate",
                "ExternalSummaryJob",
                "ReleaseBoundSummaryCandidate",
                "ReleaseBoundSummaryJob",
            }
        )


def _phase_b_catalog(
    operations: tuple[str, ...] = MEMORY_OPERATIONS,
) -> MemoryCatalog:
    scopes = {
        "p07_search_references": "raw-search",
        "p07_fetch_sources": "raw-fetch",
        "p08_temporal_read": "temporal",
        "profile_read": "profile",
        "p10b_trusted_time_read": "trusted-time",
    }
    entries = [
        MemoryCatalogEntry(
            operation=operation,
            scope_id=scopes[operation],
            availability="available",
            snapshot_digest=sha256(f"snapshot-{operation}".encode()).hexdigest(),
            source_closure_digest=sha256(f"closure-{operation}".encode()).hexdigest(),
        )
        for operation in operations
    ]
    return MemoryCatalog(tuple(sorted(entries, key=lambda item: (item.operation, item.scope_id))))


def _phase_b_turn(
    message: str = "Synthetic resident question",
    *,
    budget: TurnBudget | None = None,
    catalog: MemoryCatalog | None = None,
):
    return create_turn_step(
        owner_principal_id="synthetic-owner",
        conversation_id="synthetic-conversation",
        turn_id="synthetic-turn",
        request_id="synthetic-request",
        owner_message=message,
        catalog=_phase_b_catalog() if catalog is None else catalog,
        budget=TurnBudget(absolute_deadline_ns=10_000) if budget is None else budget,
    )


def _phase_b_unvalidated_request(
    turn,
    *,
    operation="profile_read",
    scope_id="profile",
    query="synthetic query",
    selection_digest=None,
    parent_receipt_digest=None,
):
    return MemoryRequest(
        operation=operation,
        scope_id=scope_id,
        query=query,
        turn_digest=turn.turn_digest,
        catalog_digest=turn.catalog.digest,
        snapshot_digest=turn.catalog.snapshot_digest,
        source_closure_digest=turn.catalog.source_closure_digest,
        continuation_digest=turn.continuation_digest,
        budget_digest=turn.budget.digest,
        obligation_digest=turn.obligation_digest,
        round_index=turn.round_index,
        selection_digest=selection_digest,
        parent_receipt_digest=parent_receipt_digest,
    )


class InactiveMemoryAwareTurnLoopTests(unittest.TestCase):
    def test_isolated_history_grammar_rejects_missing_evidence(self) -> None:
        for owner_message in (
            "接着我们的计划往下走",
            "继续我们的计划吧",
        ):
            with self.subTest(owner_message=owner_message):
                memory_calls = 0

                def memory_read(_request):
                    nonlocal memory_calls
                    memory_calls += 1
                    raise AssertionError("zero-retrieval final must fail first")

                with self.assertRaisesRegex(
                    MemoryAwareTurnError,
                    "repair_budget_exhausted",
                ):
                    gateway.run_memory_aware_turn_loop(
                        _phase_b_turn(owner_message),
                        provider_step=lambda current, _repair: (
                            final_for_turn(
                                current,
                                owner_message="Unsupported resident answer",
                            ),
                            1,
                        ),
                        memory_read=memory_read,
                        monotonic_ns=lambda: 1,
                    )
                self.assertEqual(memory_calls, 0)

        for owner_message in (
            "What did we decide?",
            "What decision did we make last time?",
        ):
            with self.subTest(owner_message=owner_message):
                memory_operations: list[str] = []

                def provider_step(current, _repair):
                    if current.round_index == 0:
                        return request_for_turn(
                            current,
                            operation="p07_search_references",
                            scope_id="raw-search",
                            query="prior decision",
                        ), 1
                    return final_for_turn(
                        current,
                        owner_message="The selected option was Alpha.",
                    ), 1

                def memory_read(request):
                    memory_operations.append(request.operation)
                    return create_memory_outcome(
                        request,
                        status="available",
                        values=("reference-only",),
                    )

                with self.assertRaisesRegex(
                    MemoryAwareTurnError,
                    "repair_budget_exhausted",
                ):
                    gateway.run_memory_aware_turn_loop(
                        _phase_b_turn(owner_message),
                        provider_step=provider_step,
                        memory_read=memory_read,
                        monotonic_ns=lambda: 1,
                    )
                self.assertEqual(memory_operations, ["p07_search_references"])

    def test_resident_decision_and_action_requests_do_not_read_memory(self) -> None:
        for owner_message in (
            "Help me make a decision about dinner",
            "What should we decide for dinner?",
            "请帮我决定晚饭吃什么",
            "继续搅拌汤",
            "接着加热晚餐",
            "against",
            "pasta",
            "priceless",
        ):
            with self.subTest(owner_message=owner_message):
                result = gateway.run_memory_aware_turn_loop(
                    _phase_b_turn(owner_message),
                    provider_step=lambda current, _repair: (
                        final_for_turn(current, owner_message="Resident-only answer"),
                        1,
                    ),
                    memory_read=lambda _request: (_ for _ in ()).throw(
                        AssertionError("resident-only request must not read memory")
                    ),
                    monotonic_ns=lambda: 1,
                )
                self.assertEqual(result.retrieval_rounds, 0)

    def test_resident_final_uses_one_step_and_zero_memory_callbacks(self) -> None:
        turn = _phase_b_turn()
        calls: list[str] = []

        def provider_step(current, repair):
            calls.append(f"provider:{repair}")
            return final_for_turn(current, owner_message="Synthetic final reply"), 1

        def memory_read(_request):
            calls.append("memory")
            raise AssertionError("resident final must not read memory")

        result = gateway.run_memory_aware_turn_loop(
            turn,
            provider_step=provider_step,
            memory_read=memory_read,
            monotonic_ns=lambda: 1,
        )

        self.assertEqual(result.owner_message, "Synthetic final reply")
        self.assertEqual(result.retrieval_rounds, 0)
        self.assertEqual(calls, ["provider:False"])

    def test_search_fetch_final_executes_one_fixed_request_per_round(self) -> None:
        turn = _phase_b_turn("Remember the previous exact quote")
        provider_calls: list[tuple[int, bool]] = []
        memory_calls: list[str] = []

        def provider_step(current, repair):
            provider_calls.append((current.round_index, repair))
            if current.round_index == 0:
                return (
                    request_for_turn(
                        current,
                        operation="p07_search_references",
                        scope_id="raw-search",
                        query="previous source",
                    ),
                    1,
                )
            if current.round_index == 1:
                search_receipt = current.receipts[0]
                return (
                    request_for_turn(
                        current,
                        operation="p07_fetch_sources",
                        scope_id="raw-fetch",
                        query="exact source",
                        selection_digest=search_receipt.selection_digest,
                        parent_receipt_digest=search_receipt.digest,
                    ),
                    1,
                )
            return final_for_turn(
                current,
                owner_message="The precise original quote is supported.",
            ), 1

        def memory_read(request):
            memory_calls.append(request.operation)
            if request.operation == "p07_search_references":
                return create_memory_outcome(
                    request,
                    status="available",
                    values=("synthetic-reference",),
                )
            if request.operation == "p07_fetch_sources":
                return create_memory_outcome(
                    request,
                    status="available",
                    values=("synthetic-complete-source",),
                )
            raise AssertionError("unexpected operation")

        result = gateway.run_memory_aware_turn_loop(
            turn,
            provider_step=provider_step,
            memory_read=memory_read,
            monotonic_ns=lambda: 1,
        )

        self.assertEqual(memory_calls, ["p07_search_references", "p07_fetch_sources"])
        self.assertEqual(provider_calls, [(0, False), (1, False), (2, False)])
        self.assertEqual(result.retrieval_rounds, 2)
        self.assertEqual(result.provider_attempts_used, 3)

    def test_two_scope_dependency_reconstructs_same_final_deterministically(self) -> None:
        projections: list[dict[str, object]] = []
        for _ in range(2):
            turn = _phase_b_turn("Remember before our relationship changed")

            def provider_step(current, repair):
                self.assertFalse(repair)
                if current.round_index == 0:
                    return request_for_turn(
                        current,
                        operation="p07_search_references",
                        scope_id="raw-search",
                        query="bounded history",
                    ), 1
                if current.round_index == 1:
                    return request_for_turn(
                        current,
                        operation="profile_read",
                        scope_id="profile",
                        query="bounded relationship state",
                    ), 1
                return final_for_turn(current, owner_message="Synthetic supported answer"), 1

            result = gateway.run_memory_aware_turn_loop(
                turn,
                provider_step=provider_step,
                memory_read=lambda request: create_memory_outcome(
                    request,
                    status="available",
                    values=(f"value-{request.operation}",),
                ),
                monotonic_ns=lambda: 1,
            )
            projections.append(result.content_free_projection())
        self.assertEqual(projections[0], projections[1])

    def test_semantically_duplicate_query_rejects_before_second_callback(self) -> None:
        variants = (
            ("Profile Evidence", "profile evidence"),
            ("profile   evidence", " profile evidence "),
            ("profile-evidence!", "profile evidence"),
            ("Ｐｒｏｆｉｌｅ，Ｅｖｉｄｅｎｃｅ！", "profile evidence"),
            ("café evidence", "cafe\u0301 evidence"),
            ("记忆证据", "记忆，证据"),
        )
        for first_query, second_query in variants:
            with self.subTest(first_query=first_query, second_query=second_query):
                turn = _phase_b_turn(
                    budget=TurnBudget(
                        absolute_deadline_ns=10_000,
                        max_retrieval_rounds=3,
                        max_provider_attempts=5,
                    )
                )
                memory_calls = 0

                def provider_step(current, _repair):
                    query = first_query if current.round_index == 0 else second_query
                    return request_for_turn(
                        current,
                        operation="profile_read",
                        scope_id="profile",
                        query=query,
                    ), 1

                def memory_read(request):
                    nonlocal memory_calls
                    memory_calls += 1
                    return create_memory_outcome(
                        request,
                        status="available",
                        values=("synthetic-profile",),
                    )

                with self.assertRaisesRegex(
                    MemoryAwareTurnError,
                    "memory_request_no_progress",
                ):
                    gateway.run_memory_aware_turn_loop(
                        turn,
                        provider_step=provider_step,
                        memory_read=memory_read,
                        monotonic_ns=lambda: 1,
                    )
                self.assertEqual(memory_calls, 1)

    def test_genuine_query_refinement_remains_admissible(self) -> None:
        turn = _phase_b_turn()
        memory_calls: list[str] = []

        def provider_step(current, _repair):
            if current.round_index == 0:
                query = "profile evidence"
            elif current.round_index == 1:
                query = "profile evidence relationship"
            else:
                return final_for_turn(
                    current,
                    owner_message="Synthetic refined answer",
                ), 1
            return request_for_turn(
                current,
                operation="profile_read",
                scope_id="profile",
                query=query,
            ), 1

        def memory_read(request):
            memory_calls.append(request.query)
            return create_memory_outcome(
                request,
                status="available",
                values=("synthetic-profile",),
            )

        result = gateway.run_memory_aware_turn_loop(
            turn,
            provider_step=provider_step,
            memory_read=memory_read,
            monotonic_ns=lambda: 1,
        )
        self.assertEqual(
            memory_calls,
            ["profile evidence", "profile evidence relationship"],
        )
        self.assertEqual(result.retrieval_rounds, 2)

    def test_request_preflight_rejects_every_invalid_binding_before_callback(self) -> None:
        turn = _phase_b_turn()
        valid = _phase_b_unvalidated_request(turn)
        invalid_cases = (
            (replace(valid, turn_digest="f" * 64), 1, "memory_request_binding_mismatch"),
            (
                replace(valid, continuation_digest="e" * 64),
                1,
                "memory_request_binding_mismatch",
            ),
            (
                replace(valid, scope_id="unauthorized"),
                1,
                "catalog_scope_not_authorized",
            ),
            (
                _phase_b_unvalidated_request(
                    turn,
                    operation="p07_fetch_sources",
                    scope_id="raw-fetch",
                    selection_digest="d" * 64,
                    parent_receipt_digest="c" * 64,
                ),
                1,
                "fetch_search_binding_mismatch",
            ),
            (replace(valid, query="，！？ …"), 1, "memory_query_canonical_empty"),
            (valid, 5, "provider_attempt_budget_exhausted"),
        )

        for request, attempts, code in invalid_cases:
            with self.subTest(code=code):
                memory_calls = 0

                def memory_read(_request):
                    nonlocal memory_calls
                    memory_calls += 1
                    raise AssertionError("preflight rejection must precede callback")

                with self.assertRaisesRegex(MemoryAwareTurnError, code):
                    gateway.run_memory_aware_turn_loop(
                        turn,
                        provider_step=lambda _current, _repair: (request, attempts),
                        memory_read=memory_read,
                        monotonic_ns=lambda: 1,
                    )
                self.assertEqual(memory_calls, 0)

        exhausted = _phase_b_turn(
            budget=TurnBudget(
                absolute_deadline_ns=10_000,
                max_retrieval_rounds=1,
                max_provider_attempts=3,
            )
        )
        first = request_for_turn(
            exhausted,
            operation="profile_read",
            scope_id="profile",
            query="first",
        )
        first_result, first_receipt = create_memory_outcome(
            first,
            status="available",
            values=("synthetic-profile",),
        )
        exhausted = gateway.advance_with_memory(
            exhausted,
            first,
            first_result,
            first_receipt,
            provider_attempts=1,
        )
        exhausted_request = _phase_b_unvalidated_request(exhausted)
        memory_calls = 0

        def memory_read(_request):
            nonlocal memory_calls
            memory_calls += 1
            raise AssertionError("round rejection must precede callback")

        with self.assertRaisesRegex(
            MemoryAwareTurnError,
            "retrieval_round_budget_exhausted",
        ):
            gateway.run_memory_aware_turn_loop(
                exhausted,
                provider_step=lambda _current, _repair: (exhausted_request, 1),
                memory_read=memory_read,
                monotonic_ns=lambda: 1,
            )
        self.assertEqual(memory_calls, 0)

    def test_missing_required_catalog_operations_fail_closed_without_callback(self) -> None:
        turn = _phase_b_turn(
            "Do you recall the exact source for our prior decision?",
            catalog=_phase_b_catalog(("profile_read",)),
        )
        memory_calls = 0

        def memory_read(_request):
            nonlocal memory_calls
            memory_calls += 1
            raise AssertionError("missing catalog operation must not call memory")

        with self.assertRaisesRegex(
            MemoryAwareTurnError,
            "uncertain_evidence_answer_rejected",
        ):
            gateway.run_memory_aware_turn_loop(
                turn,
                provider_step=lambda current, _repair: (
                    final_for_turn(
                        current,
                        owner_message="Unsupported evidence-complete answer",
                    ),
                    1,
                ),
                memory_read=memory_read,
                monotonic_ns=lambda: 1,
            )
        self.assertEqual(memory_calls, 0)

        result = gateway.run_memory_aware_turn_loop(
            turn,
            provider_step=lambda current, _repair: (
                final_for_turn(
                    current,
                    owner_message="I need clarification before answering",
                    resolution="clarify",
                ),
                1,
            ),
            memory_read=memory_read,
            monotonic_ns=lambda: 1,
        )
        self.assertEqual(memory_calls, 0)
        self.assertEqual(result.resolution, "clarify")
        self.assertEqual(result.retrieval_rounds, 0)

    def test_callback_outcome_is_revalidated_and_oversize_body_is_content_free(self) -> None:
        turn = _phase_b_turn(
            "x",
            budget=TurnBudget(
                absolute_deadline_ns=10_000,
                max_characters=8,
                max_utf8_bytes=100,
            ),
        )
        request = request_for_turn(
            turn,
            operation="profile_read",
            scope_id="profile",
            query="bounded",
        )
        calls = 0
        private_body = "synthetic-private-body"

        def memory_read(selected):
            nonlocal calls
            calls += 1
            return create_memory_outcome(
                selected,
                status="available",
                values=(private_body,),
            )

        with self.assertRaisesRegex(
            MemoryAwareTurnError,
            "result_character_budget_exhausted",
        ) as captured:
            gateway.run_memory_aware_turn_loop(
                turn,
                provider_step=lambda _current, _repair: (request, 1),
                memory_read=memory_read,
                monotonic_ns=lambda: 1,
            )
        self.assertEqual(calls, 1)
        self.assertEqual(turn.results, ())
        self.assertEqual(turn.receipts, ())
        projection = captured.exception.content_free_projection(turn)
        self.assertNotIn(private_body, json.dumps(projection, sort_keys=True))

        other = replace(request, query="other binding")
        calls = 0

        def substituted_read(_selected):
            nonlocal calls
            calls += 1
            return create_memory_outcome(
                other,
                status="available",
                values=("other",),
            )

        with self.assertRaisesRegex(MemoryAwareTurnError, "result_binding_mismatch"):
            gateway.run_memory_aware_turn_loop(
                _phase_b_turn(),
                provider_step=lambda current, _repair: (
                    request_for_turn(
                        current,
                        operation="profile_read",
                        scope_id="profile",
                        query="bounded",
                    ),
                    1,
                ),
                memory_read=substituted_read,
                monotonic_ns=lambda: 1,
            )
        self.assertEqual(calls, 1)

    def test_schema_repair_is_once_and_charged_to_same_budget(self) -> None:
        turn = _phase_b_turn()
        repair_flags: list[bool] = []

        def provider_step(current, repair):
            repair_flags.append(repair)
            if not repair:
                raise MemoryAwareTurnError(
                    "provider_response_invalid",
                    attempts=2,
                    repairable=True,
                )
            return final_for_turn(current, owner_message="Synthetic repaired answer"), 1

        result = gateway.run_memory_aware_turn_loop(
            turn,
            provider_step=provider_step,
            memory_read=lambda _request: (_ for _ in ()).throw(AssertionError()),
            monotonic_ns=lambda: 1,
        )
        self.assertEqual(repair_flags, [False, True])
        self.assertEqual(result.provider_attempts_used, 3)

    def test_missing_final_evidence_is_repaired_without_memory_side_effect(self) -> None:
        turn = _phase_b_turn("Remember the previous event")
        memory_calls = 0

        def provider_step(current, repair):
            if current.round_index == 0:
                return request_for_turn(
                    current,
                    operation="p07_search_references",
                    scope_id="raw-search",
                    query="previous event",
                ), 1
            if not repair:
                return FinalBranch(
                    owner_message="Synthetic answer",
                    resolution="answer",
                    receipt_digests=(),
                    uncertainty_statuses=(),
                ), 1
            return final_for_turn(current, owner_message="Synthetic answer"), 1

        def memory_read(request):
            nonlocal memory_calls
            memory_calls += 1
            return create_memory_outcome(
                request,
                status="available",
                values=("synthetic-reference",),
            )

        result = gateway.run_memory_aware_turn_loop(
            turn,
            provider_step=provider_step,
            memory_read=memory_read,
            monotonic_ns=lambda: 1,
        )
        self.assertEqual(memory_calls, 1)
        self.assertEqual(result.provider_attempts_used, 3)

    def test_failed_repair_terminates_and_does_not_reset_budget(self) -> None:
        turn = _phase_b_turn()
        calls = 0

        def provider_step(_current, _repair):
            nonlocal calls
            calls += 1
            raise MemoryAwareTurnError(
                "provider_response_invalid",
                attempts=2,
                repairable=True,
            )

        with self.assertRaises(MemoryAwareTurnError):
            gateway.run_memory_aware_turn_loop(
                turn,
                provider_step=provider_step,
                memory_read=lambda _request: (_ for _ in ()).throw(AssertionError()),
                monotonic_ns=lambda: 1,
            )
        self.assertEqual(calls, 2)

    def test_absolute_deadline_stops_before_memory_callback(self) -> None:
        turn = _phase_b_turn(
            budget=TurnBudget(absolute_deadline_ns=3),
        )
        ticks = iter((1, 3))
        memory_calls = 0

        def memory_read(_request):
            nonlocal memory_calls
            memory_calls += 1
            raise AssertionError("deadline must stop first")

        with self.assertRaisesRegex(MemoryAwareTurnError, "absolute_deadline_exhausted"):
            gateway.run_memory_aware_turn_loop(
                turn,
                provider_step=lambda current, _repair: (
                    request_for_turn(
                        current,
                        operation="profile_read",
                        scope_id="profile",
                        query="bounded profile",
                    ),
                    1,
                ),
                memory_read=memory_read,
                monotonic_ns=lambda: next(ticks),
            )
        self.assertEqual(memory_calls, 0)

    def test_uncertain_status_cannot_return_answer(self) -> None:
        turn = _phase_b_turn("Our relationship changed")

        def provider_step(current, _repair):
            if current.round_index == 0:
                return request_for_turn(
                    current,
                    operation="profile_read",
                    scope_id="profile",
                    query="bounded relationship",
                ), 1
            return FinalBranch(
                owner_message="Unsafe invented answer",
                resolution="answer",
                receipt_digests=tuple(item.digest for item in current.receipts),
                uncertainty_statuses=("unavailable",),
            ), 1

        with self.assertRaisesRegex(MemoryAwareTurnError, "uncertain_evidence_answer_rejected"):
            gateway.run_memory_aware_turn_loop(
                turn,
                provider_step=provider_step,
                memory_read=lambda request: create_memory_outcome(
                    request,
                    status="unavailable",
                ),
                monotonic_ns=lambda: 1,
            )

    def test_final_value_exposes_only_typed_owner_message_for_future_rendering(self) -> None:
        turn = _phase_b_turn()
        intent_digest = sha256(b"synthetic-proposal").hexdigest()
        result = gateway.run_memory_aware_turn_loop(
            turn,
            provider_step=lambda current, _repair: (
                final_for_turn(
                    current,
                    owner_message="Owner-visible synthetic reply",
                    server_intents=(
                        ServerIntentProposal(
                            intent_id="proposal-synthetic",
                            kind="follow_up_proposal",
                            proposal_digest=intent_digest,
                        ),
                    ),
                ),
                1,
            ),
            memory_read=lambda _request: (_ for _ in ()).throw(AssertionError()),
            monotonic_ns=lambda: 1,
        )
        self.assertEqual(result.owner_message, "Owner-visible synthetic reply")
        self.assertNotIn(intent_digest, result.owner_message)
        self.assertEqual(result.content_free_projection()["server_intent_count"], 1)

    def test_typed_profile_intent_stages_without_provider_or_memory_callback(
        self,
    ) -> None:
        turn = _phase_b_turn()
        proposal = ServerIntentProposal.profile_state(
            intent_id="profile-gateway-staging-synthetic",
            requested_delta=10_000,
        )
        provider_calls = 0
        memory_calls = 0

        def provider_step(current, _repair):
            nonlocal provider_calls
            provider_calls += 1
            return (
                final_for_turn(
                    current,
                    owner_message="Owner-visible synthetic Profile reply",
                    server_intents=(proposal,),
                ),
                1,
            )

        def memory_read(_request):
            nonlocal memory_calls
            memory_calls += 1
            raise AssertionError("no retrieval callback expected")

        result = gateway.run_memory_aware_turn_loop(
            turn,
            provider_step=provider_step,
            memory_read=memory_read,
            monotonic_ns=lambda: 1,
        )
        memory_runtime = Mock(spec=memory_module.OwnerPrivateMemoryRuntime)
        gateway.stage_memory_aware_profile_intents(
            memory_runtime,
            delivery_token="a" * 64,
            final=result,
        )
        memory_runtime.stage_profile_server_intents.assert_called_once_with(
            "a" * 64,
            (proposal,),
        )
        self.assertEqual(provider_calls, 1)
        self.assertEqual(memory_calls, 0)
        self.assertNotIn(proposal.proposal_digest, result.owner_message)

    def test_inactive_loop_has_no_production_call_edge(self) -> None:
        source = (ROOT / "scripts" / "telegram_owner_runtime_gateway.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        calls: list[int] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "run_memory_aware_turn_loop":
                    calls.append(node.lineno)
        self.assertEqual(calls, [])

        loop = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "run_memory_aware_turn_loop"
        )
        loop_calls: dict[str, list[int]] = {}
        for node in ast.walk(loop):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                loop_calls.setdefault(node.func.id, []).append(node.lineno)
        self.assertEqual(len(loop_calls["preflight_memory_request"]), 1)
        self.assertEqual(len(loop_calls["memory_request_progress_fingerprint"]), 1)
        self.assertEqual(len(loop_calls["memory_read"]), 1)
        self.assertLess(
            loop_calls["preflight_memory_request"][0],
            loop_calls["memory_read"][0],
        )
        self.assertLess(
            loop_calls["memory_request_progress_fingerprint"][0],
            loop_calls["memory_read"][0],
        )
        self.assertGreater(
            loop_calls["advance_with_memory"][0],
            loop_calls["memory_read"][0],
        )
        self.assertNotIn("run_memory_aware_turn_loop", gateway.main.__code__.co_names)
        self.assertNotIn("run_memory_aware_turn_loop", gateway.process_connection.__code__.co_names)
        self.assertNotIn(
            "run_memory_aware_turn_loop",
            gateway.LoopbackCoreClient.chat.__code__.co_names,
        )

    def test_loop_uses_no_http_delivery_or_product_state(self) -> None:
        turn = _phase_b_turn()
        with (
            patch.object(gateway, "HTTPConnection") as http,
            patch.object(gateway, "_respond") as respond,
            patch.object(gateway, "_process_memory_delivery_outcome") as delivery,
        ):
            result = gateway.run_memory_aware_turn_loop(
                turn,
                provider_step=lambda current, _repair: (
                    final_for_turn(current, owner_message="Synthetic detached answer"),
                    1,
                ),
                memory_read=lambda _request: (_ for _ in ()).throw(AssertionError()),
                monotonic_ns=lambda: 1,
            )
        self.assertEqual(result.owner_message, "Synthetic detached answer")
        http.assert_not_called()
        respond.assert_not_called()
        delivery.assert_not_called()

    def test_crash_before_transition_leaves_no_product_mutation(self) -> None:
        turn = _phase_b_turn()
        state = {"memory_calls": 0, "effects": []}

        def provider_step(_current, _repair):
            raise MemoryAwareTurnError("synthetic_crash", attempts=1)

        def memory_read(_request):
            state["memory_calls"] += 1
            raise AssertionError("unreachable")

        with self.assertRaisesRegex(MemoryAwareTurnError, "synthetic_crash"):
            gateway.run_memory_aware_turn_loop(
                turn,
                provider_step=provider_step,
                memory_read=memory_read,
                monotonic_ns=lambda: 1,
            )
        self.assertEqual(state, {"memory_calls": 0, "effects": []})


if __name__ == "__main__":
    unittest.main()
