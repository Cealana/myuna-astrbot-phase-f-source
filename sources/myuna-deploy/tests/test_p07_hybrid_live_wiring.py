from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORE_ROOT = ROOT.parent / "core" / "src"
sys.path.insert(0, str(ROOT / "scripts"))

import telegram_owner_runtime_gateway as runtime

from myuna_core.authenticated_conversation import AuthenticatedConversationContext
from myuna_core.external_context.contracts import (
    ExternalSummary,
    ExternalSummaryCandidate,
    ExternalSummaryJob,
    ExternalTurn,
    ExternalTurnProvenance,
    ZERO_DIGEST,
)


def context() -> AuthenticatedConversationContext:
    return AuthenticatedConversationContext.from_payload(
        {
            "authority_level": "owner",
            "binding_id": "binding-synthetic",
            "channel_instance": "telegram-owner-dev",
            "channel_kind": "astrbot_telegram",
            "client_id": "telegram-owner-private",
            "consent": {
                "media_processing": False,
                "memory_candidate": False,
                "tools": False,
            },
            "conversation_id": "conv-synthetic",
            "conversation_kind": "private",
            "correlation_id": "trace-synthetic",
            "delivery_capabilities": ["text"],
            "event_id": "evt-synthetic",
            "namespace_id": "namespace-synthetic",
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "principal_id": "principal-synthetic",
            "request_id": "request-synthetic",
            "schema_version": "myuna.authenticated-conversation-context.v1",
            "trace_id": "trace-synthetic",
        },
        authenticated_client_id="telegram-owner-private",
        authenticated_channel_kind="astrbot_telegram",
    )


class FakeEpoch:
    def __init__(self) -> None:
        self.committed = []
        self.cancelled = []
        self.summary_job = None
        self.summaries = []

    def commit_delivery(self, selected, token, reply, provenance):
        self.committed.append((selected, token, reply, provenance))
        return SimpleNamespace(summary_job=self.summary_job)

    def commit_summary_candidate(self, selected, job, candidate):
        self.summaries.append((selected, job, candidate))

    def cancel_pending(self, selected, token):
        self.cancelled.append((selected, token))


class P07HybridLiveWiringTests(unittest.TestCase):
    @staticmethod
    def provenance():
        return ExternalTurnProvenance(
            epoch_id="epoch-synthetic",
            epoch_revision=0,
            projection_digest="a" * 64,
            sources=("owner_current_message",),
            profile_revisions=(),
            summary_version=None,
            recent_turn_start=None,
            recent_turn_end=None,
        )

    @staticmethod
    def summary_job():
        turn = ExternalTurn.create(
            sequence=1,
            parent_digest=ZERO_DIGEST,
            user_message="Synthetic current message.",
            assistant_reply="Synthetic delivered reply.",
        )
        return ExternalSummaryJob.create(
            epoch_id="epoch-synthetic",
            base_revision=1,
            summary_version=1,
            covered_end=1,
            covered_terminal_digest=turn.digest,
            profile_revisions=(),
            prior_summary=None,
            turns=(turn,),
        )

    def test_hybrid_gate_defaults_off_and_is_exact(self) -> None:
        self.assertFalse(runtime._hybrid_enabled({}))
        self.assertTrue(runtime._hybrid_enabled({runtime.HYBRID_ENABLED_ENV: "true"}))
        with self.assertRaises(runtime.RuntimeRejected):
            runtime._hybrid_enabled({runtime.HYBRID_ENABLED_ENV: "enabled"})

    def test_delivery_ack_commits_only_after_explicit_outcome(self) -> None:
        selected = context()
        pending = runtime.PendingDelivery(
            selected,
            object(),
            self.provenance(),
            "synthetic reply",
        )
        token = "a" * 64
        deliveries = {token: pending}
        epoch = FakeEpoch()
        server, client = socket.socketpair()
        try:
            handled = runtime._process_delivery_outcome(
                server,
                {
                    "delivery_token": token,
                    "outcome": "delivered",
                    "schema": runtime.DELIVERY_OUTCOME_SCHEMA,
                },
                external_epoch=epoch,
                core=SimpleNamespace(),
                pending_deliveries=deliveries,
            )
            self.assertTrue(handled)
            self.assertEqual(len(epoch.committed), 1)
            self.assertEqual(epoch.cancelled, [])
            self.assertNotIn(token, deliveries)
            response = json.loads(client.recv(512).split(b"\n", 1)[0])
            self.assertEqual(response["status"], "accepted")
        finally:
            server.close()
            client.close()

    def test_cancelled_pacing_never_commits(self) -> None:
        selected = context()
        pending = runtime.PendingDelivery(
            selected,
            object(),
            self.provenance(),
            "synthetic reply",
        )
        token = "b" * 64
        deliveries = {token: pending}
        epoch = FakeEpoch()
        server, client = socket.socketpair()
        try:
            runtime._process_delivery_outcome(
                server,
                {
                    "delivery_token": token,
                    "outcome": "cancelled",
                    "schema": runtime.DELIVERY_OUTCOME_SCHEMA,
                },
                external_epoch=epoch,
                core=SimpleNamespace(),
                pending_deliveries=deliveries,
            )
            self.assertEqual(epoch.committed, [])
            self.assertEqual(len(epoch.cancelled), 1)
        finally:
            server.close()
            client.close()

    def test_delivery_ack_triggers_bound_summary_commit(self) -> None:
        selected = context()
        epoch = FakeEpoch()
        epoch.summary_job = self.summary_job()
        summary = ExternalSummary.create(
            summary_version=epoch.summary_job.summary_version,
            covered_start=epoch.summary_job.covered_start,
            covered_end=epoch.summary_job.covered_end,
            covered_terminal_digest=epoch.summary_job.covered_terminal_digest,
            profile_revisions=(),
            content="Synthetic rolling summary.",
        )
        candidate = ExternalSummaryCandidate(
            job_digest=epoch.summary_job.digest,
            summary=summary,
        )
        core = SimpleNamespace(summarize=lambda job: candidate)
        token = "c" * 64
        deliveries = {
            token: runtime.PendingDelivery(
                selected,
                object(),
                self.provenance(),
                "synthetic reply",
            )
        }
        server, client = socket.socketpair()
        try:
            runtime._process_delivery_outcome(
                server,
                {
                    "delivery_token": token,
                    "outcome": "delivered",
                    "schema": runtime.DELIVERY_OUTCOME_SCHEMA,
                },
                external_epoch=epoch,
                core=core,
                pending_deliveries=deliveries,
            )
            self.assertEqual(len(epoch.summaries), 1)
            self.assertEqual(epoch.summaries[0][2], candidate)
        finally:
            server.close()
            client.close()

    def test_plugin_marks_only_plain_text_path_for_hybrid(self) -> None:
        source = (
            ROOT
            / "channels/astrbot-telegram/plugin/myuna_telegram_gateway/main.py"
        ).read_text(encoding="utf-8")
        marker = 'envelope["routing"] = {"hybrid_external_generation": True}'
        self.assertEqual(source.count(marker), 1)
        self.assertIn("@filter.after_message_sent()", source)

    def test_visual_path_uses_signed_structured_routing_and_epoch_projection(self) -> None:
        plugin = (
            ROOT
            / "channels/astrbot-telegram/plugin/myuna_telegram_gateway/main.py"
        ).read_text(encoding="utf-8")
        runtime_source = (
            ROOT / "scripts/telegram_owner_runtime_gateway.py"
        ).read_text(encoding="utf-8")
        image_path = plugin.split("if image is not None:", 1)[1].split(
            "parts_are_bounded", 1
        )[0]
        self.assertIn("attach_signed_visual_event", image_path)
        self.assertIn("message_text=current_request", image_path)
        self.assertNotIn("_compose_vision_message", image_path)
        self.assertIn("visual_event=decision.visual_event", runtime_source)
        self.assertIn("_verify_visual_routing", runtime_source)

    def test_runtime_rejection_after_epoch_begin_uses_cancel_path(self) -> None:
        source = (ROOT / "scripts/telegram_owner_runtime_gateway.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("except (CoreUnavailable, RuntimeRejected) as exc:", source)
        guarded = source.split(
            "except (CoreUnavailable, RuntimeRejected) as exc:", 1
        )[1].split("record_outcome", 1)[0]
        self.assertIn("external_epoch.cancel_pending", guarded)
        self.assertIn("if isinstance(exc, RuntimeRejected):", guarded)

    def test_startup_and_projection_failure_are_fail_closed(self) -> None:
        source = (ROOT / "scripts/telegram_owner_runtime_gateway.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("external_epoch.discard_all_uncommitted_after_restart()", source)
        projection = source.split("external_context = external_epoch.context_payload", 1)[1]
        bounded = projection.split("messages =", 1)[0]
        self.assertIn(
            "except (ExternalEpochRejected, ExternalEpochV3Rejected):",
            bounded,
        )
        self.assertIn("external_epoch.cancel_pending", bounded)


if __name__ == "__main__":
    unittest.main()
