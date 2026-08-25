from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from myuna_core.authenticated_conversation import (
    SCHEMA_VERSION,
    AuthenticatedConversationContext,
)
from myuna_core.channel_capability import ChannelNeutralCapabilityProfile
from scripts.gateway_runtime_kernel import (
    DuplicateInboundEvent,
    GatewayCoreUnavailable,
    GatewayInboundMessage,
    GatewayReplyRejected,
    GatewayRuntimeKernel,
)
from myuna_core.external_context.contracts import (
    EgressSafetySignals,
    ExternalTurnProvenance,
)
from scripts.external_context_epoch import ExternalEpochStore


def profile() -> ChannelNeutralCapabilityProfile:
    return ChannelNeutralCapabilityProfile.from_document(
        {
            "schema_version": 1,
            "profile_id": "owner-private-text-readonly-memory-v2",
            "environment": "dev",
            "response_scope": "owner_private_dev_readonly_memory_v2",
            "subject": {
                "channel_kinds": ["astrbot_qq", "astrbot_telegram"],
                "conversation_kinds": ["private"],
                "authority_levels": ["owner"],
            },
            "delivery_capabilities": ["text"],
            "memory_protocol": "v2",
            "capabilities": {
                "conversation": True,
                "long_term_memory_read": True,
                "long_term_memory_write": False,
                "vision": False,
                "tools": False,
                "external_data": False,
                "external_actions": False,
                "system_administration": False,
            },
        }
    )


def context(channel: str, *, index: int = 1) -> AuthenticatedConversationContext:
    return AuthenticatedConversationContext(
        schema_version=SCHEMA_VERSION,
        request_id=f"request-{channel}-{index}",
        correlation_id=f"correlation-{channel}-{index}",
        client_id=f"client-{channel}",
        channel_kind=channel,
        binding_id=f"binding-{channel}-owner",
        principal_id="principal-owner",
        namespace_id="namespace-owner-private",
        authority_level="owner",
        channel_instance=f"instance-{channel}",
        conversation_id=f"conversation-{channel}",
        conversation_kind="private",
        event_id=f"event-{channel}-{index}",
        trace_id=f"trace-{channel}-{index}",
        occurred_at=datetime(2026, 7, 27, tzinfo=timezone.utc),
        delivery_capabilities=("text",),
    )


class FakeLedger:
    def __init__(self) -> None:
        self.claimed: set[str] = set()
        self.outcomes: list[tuple[str, str]] = []

    def claim(self, *, event_id: str, request_id: str) -> bool:
        if event_id in self.claimed:
            return False
        self.claimed.add(event_id)
        return True

    def complete(self, *, event_id: str, outcome: str) -> None:
        self.outcomes.append((event_id, outcome))


class FakeLimiter:
    def allow(self, *, principal_id: str, channel_kind: str) -> bool:
        return True


class FakeHistory:
    def __init__(self) -> None:
        self.values: dict[object, list[dict[str, str]]] = {}
        self.load_calls = 0
        self.append_calls = 0

    def load(self, key):
        self.load_calls += 1
        return tuple(self.values.get(key, ()))

    def append(self, key, *, user_message: str, assistant_reply: str) -> None:
        self.append_calls += 1
        self.values.setdefault(key, []).extend(
            (
                {"role": "user", "content": user_message},
                {"role": "assistant", "content": assistant_reply},
            )
        )


class FakeCore:
    def __init__(
        self,
        *,
        failure: str | None = None,
        reply: str = "收到",
    ) -> None:
        self.failure = failure
        self.reply = reply
        self.payloads: list[object] = []

    def chat(self, payload):
        self.payloads.append(payload)
        if self.failure:
            raise GatewayCoreUnavailable(self.failure)
        response = {"reply": self.reply}
        external = payload.get("external_context")
        if external is not None:
            response["external_turn_provenance"] = ExternalTurnProvenance(
                epoch_id=external["epoch_id"],
                epoch_revision=external["epoch_revision"],
                projection_digest="a" * 64,
                sources=("owner_current_message",),
                profile_revisions=(),
                summary_version=None,
                recent_turn_start=None,
                recent_turn_end=None,
            ).as_payload()
        return response


class FakeObserver:
    def __init__(self) -> None:
        self.events: list[object] = []

    def observe(self, metadata) -> None:
        self.events.append(dict(metadata))


class FakeExternalEpoch:
    def __init__(self) -> None:
        self.pending = object()
        self.begun = []
        self.committed = []
        self.cancelled = []

    def begin_turn(self, context, current_message, safety):
        self.begun.append((context.request_id, current_message, safety))
        return self.pending

    def context_payload(self, context, token):
        if token is not self.pending:
            raise RuntimeError("bad token")
        return {
            "schema": "synthetic-external-envelope",
            "current_message": self.begun[-1][1],
            "epoch_id": "epoch-synthetic",
            "epoch_revision": 0,
        }

    def commit_delivery(self, context, token, assistant_reply, provenance):
        self.committed.append((context.request_id, token, assistant_reply, provenance))

    def cancel_pending(self, context, token):
        self.cancelled.append((context.request_id, token))


class GatewayRuntimeKernelTests(unittest.TestCase):
    def kernel(self, *, core: FakeCore | None = None, external=None):
        ledger = FakeLedger()
        history = FakeHistory()
        observer = FakeObserver()
        selected_core = core or FakeCore()
        return (
            GatewayRuntimeKernel(
                capability_profile=profile(),
                event_ledger=ledger,
                rate_limiter=FakeLimiter(),
                session_context=history,
                core=selected_core,
                failure_observer=observer,
                external_context_epoch=external,
            ),
            ledger,
            history,
            selected_core,
            observer,
        )

    def test_qq_and_telegram_share_one_kernel_but_keep_channel_identity(self) -> None:
        kernel, ledger, history, core, _ = self.kernel()
        results = []
        for index, channel in enumerate(("astrbot_qq", "astrbot_telegram"), 1):
            results.append(
                kernel.handle(
                    GatewayInboundMessage(
                        context(channel, index=index),
                        session_id="owner-shared-session-0001",
                        message_text=f"message-{index}",
                    )
                )
            )
        self.assertEqual([result.reply for result in results], ["收到", "收到"])
        self.assertEqual(
            [payload["authenticated_context"]["channel_kind"] for payload in core.payloads],
            ["astrbot_qq", "astrbot_telegram"],
        )
        self.assertEqual(len(history.values), 1)
        self.assertEqual([outcome for _, outcome in ledger.outcomes], ["delivered", "delivered"])

    def test_identity_metadata_is_separate_from_model_visible_conversation(self) -> None:
        kernel, _, _, core, _ = self.kernel()
        kernel.handle(
            GatewayInboundMessage(
                context=context("astrbot_telegram"),
                session_id="owner-session-0002",
                message_text="hello",
            )
        )
        payload = core.payloads[0]
        self.assertEqual(set(payload), {"authenticated_context", "conversation"})
        flattened_conversation = repr(payload["conversation"])
        for forbidden in ("principal", "namespace", "binding", "client_id"):
            self.assertNotIn(forbidden, flattened_conversation)

    def test_capabilities_are_declared_per_inbound_message(self) -> None:
        kernel, _, _, core, _ = self.kernel()
        kernel.handle(
            GatewayInboundMessage(
                context=context("astrbot_telegram"),
                session_id="owner-session-0005",
                message_text="hello",
                requested_capabilities=("conversation",),
            )
        )
        self.assertEqual(
            core.payloads[0]["authenticated_context"]["channel_kind"],
            "astrbot_telegram",
        )

    def test_duplicate_is_rejected_before_a_second_core_call(self) -> None:
        kernel, _, _, core, _ = self.kernel()
        inbound = GatewayInboundMessage(
            context=context("astrbot_qq"),
            session_id="owner-session-0003",
            message_text="hello",
        )
        kernel.handle(inbound)
        with self.assertRaises(DuplicateInboundEvent):
            kernel.handle(inbound)
        self.assertEqual(len(core.payloads), 1)

    def test_core_failure_observer_receives_metadata_only(self) -> None:
        kernel, ledger, _, _, observer = self.kernel(
            core=FakeCore(failure="provider_unavailable")
        )
        with self.assertRaises(GatewayCoreUnavailable):
            kernel.handle(
                GatewayInboundMessage(
                    context=context("astrbot_telegram"),
                    session_id="owner-session-0004",
                    message_text="private message body",
                )
            )
        self.assertEqual(ledger.outcomes[0][1], "core_unavailable")
        flattened = repr(observer.events)
        self.assertIn("provider_unavailable", flattened)
        self.assertNotIn("private message body", flattened)

    def test_hybrid_path_uses_current_message_only_and_commits_after_ack(self) -> None:
        external = FakeExternalEpoch()
        kernel, ledger, history, core, _ = self.kernel(external=external)
        selected_context = context("astrbot_telegram")
        inbound = GatewayInboundMessage(
            context=selected_context,
            session_id="owner-session-hybrid-1",
            message_text="synthetic current only",
            external_generation=True,
            egress_safety=EgressSafetySignals(),
        )
        result = kernel.handle(inbound)
        self.assertEqual(history.load_calls, 0)
        self.assertEqual(history.append_calls, 0)
        self.assertEqual(
            core.payloads[0]["conversation"]["messages"],
            [{"role": "user", "content": "synthetic current only"}],
        )
        self.assertIn("external_context", core.payloads[0])
        self.assertEqual(ledger.outcomes, [])
        self.assertEqual(external.committed, [])
        kernel.acknowledge_delivery_for_context(selected_context, result)
        self.assertEqual(len(external.committed), 1)
        self.assertEqual(ledger.outcomes[-1][1], "delivered")

    def test_real_external_epoch_commits_complete_turn_only_after_delivery_ack(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            external = ExternalEpochStore(
                Path(temporary_directory) / "epoch.sqlite3",
                epoch_id="epoch-synthetic-integration",
            )
            kernel, ledger, history, core, _ = self.kernel(external=external)
            selected_context = replace(
                context("astrbot_telegram", index=22),
                client_id="telegram-owner-private",
            )
            result = kernel.handle(
                GatewayInboundMessage(
                    context=selected_context,
                    session_id="owner-session-hybrid-integration",
                    message_text="synthetic delivery-ack integration",
                    external_generation=True,
                )
            )
            self.assertEqual(external.public_metadata()["pending_count"], 1)
            self.assertEqual(external.public_metadata()["turn_count"], 0)
            self.assertEqual(history.load_calls, 0)
            self.assertEqual(history.append_calls, 0)
            self.assertEqual(
                core.payloads[0]["external_context"]["recent_turns"],
                [],
            )
            self.assertEqual(ledger.outcomes, [])

            kernel.acknowledge_delivery_for_context(selected_context, result)

            metadata = external.public_metadata()
            self.assertEqual(metadata["pending_count"], 0)
            self.assertEqual(metadata["turn_count"], 1)
            self.assertEqual(metadata["selected_revision"], 1)
            self.assertEqual(ledger.outcomes[-1][1], "delivered")

    def test_hybrid_delivery_failure_cancels_without_legacy_append(self) -> None:
        external = FakeExternalEpoch()
        kernel, ledger, history, _, _ = self.kernel(external=external)
        selected_context = context("astrbot_telegram")
        result = kernel.handle(
            GatewayInboundMessage(
                context=selected_context,
                session_id="owner-session-hybrid-2",
                message_text="synthetic delivery failure",
                external_generation=True,
            )
        )
        kernel.reject_delivery_for_context(selected_context, result)
        self.assertEqual(len(external.cancelled), 1)
        self.assertEqual(history.append_calls, 0)
        self.assertEqual(ledger.outcomes[-1][1], "delivery_failed")

    def test_hybrid_core_failure_cancels_pending(self) -> None:
        external = FakeExternalEpoch()
        core = FakeCore(failure="provider_unavailable")
        kernel, _, history, _, _ = self.kernel(core=core, external=external)
        with self.assertRaises(GatewayCoreUnavailable):
            kernel.handle(
                GatewayInboundMessage(
                    context=context("astrbot_telegram"),
                    session_id="owner-session-hybrid-3",
                    message_text="synthetic provider failure",
                    external_generation=True,
                )
            )
        self.assertEqual(len(external.cancelled), 1)
        self.assertEqual(history.append_calls, 0)

    def test_hybrid_oversize_reply_is_rejected_before_delivery(self) -> None:
        external = FakeExternalEpoch()
        core = FakeCore(reply="答" * 4_001)
        kernel, ledger, history, _, _ = self.kernel(core=core, external=external)
        with self.assertRaises(GatewayReplyRejected):
            kernel.handle(
                GatewayInboundMessage(
                    context=context("astrbot_telegram"),
                    session_id="owner-session-hybrid-oversize",
                    message_text="synthetic oversize reply",
                    external_generation=True,
                )
            )
        self.assertEqual(len(external.cancelled), 1)
        self.assertEqual(history.append_calls, 0)
        self.assertEqual(ledger.outcomes[-1][1], "reply_rejected")

    def test_hybrid_failure_audit_omits_identity_and_message(self) -> None:
        external = FakeExternalEpoch()
        core = FakeCore(failure="provider_unavailable")
        kernel, _, _, _, observer = self.kernel(core=core, external=external)
        selected_context = context("astrbot_telegram")
        with self.assertRaises(GatewayCoreUnavailable):
            kernel.handle(
                GatewayInboundMessage(
                    context=selected_context,
                    session_id="owner-session-hybrid-privacy",
                    message_text="synthetic private body",
                    external_generation=True,
                )
            )
        flattened = repr(observer.events)
        for forbidden in (
            "synthetic private body",
            selected_context.principal_id,
            selected_context.namespace_id,
            selected_context.binding_id,
            selected_context.client_id,
        ):
            self.assertNotIn(forbidden, flattened)

    def test_qq_cannot_enable_hybrid_external_generation(self) -> None:
        with self.assertRaises(ValueError):
            GatewayInboundMessage(
                context=context("astrbot_qq"),
                session_id="owner-session-hybrid-4",
                message_text="synthetic qq request",
                external_generation=True,
            )


if __name__ == "__main__":
    unittest.main()
