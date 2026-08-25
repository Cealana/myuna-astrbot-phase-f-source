from __future__ import annotations

import json
from pathlib import Path
import socket
import tempfile
import unittest

from myuna_core.external_context.contracts import EgressSafetySignals
from myuna_core.http_api import _parse_hybrid_chat_envelope
from myuna_core.http_client_auth import LoadedHttpClientCredential

import telegram_owner_runtime_gateway as runtime
from external_context_epoch_v3 import ExternalEpochV3Store
from tests.test_external_context_epoch_v3 import (
    EPOCH,
    RID,
    binding,
    context,
    provenance,
)


class TriggerOnlyWorker:
    def __init__(self) -> None:
        self.trigger_count = 0

    def trigger(self) -> None:
        self.trigger_count += 1


class GatewayEpochV3WiringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = ExternalEpochV3Store(
            Path(self.temp.name) / "epoch" / "epoch.db",
            epoch_id=EPOCH,
            release_set_id=RID,
            binding=binding(),
        )
        self.worker = TriggerOnlyWorker()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def prepare(self, index: int) -> str:
        auth = context(index)
        pending = self.store.begin_turn(
            auth,
            f"synthetic user {index}",
            EgressSafetySignals(classifier_available=True),
        )
        self.store.context_payload(auth, pending)
        delivery_token = f"{index:x}" * 64
        self.store.prepare_delivery(
            auth,
            pending,
            delivery_token=delivery_token,
            assistant_reply=f"synthetic assistant {index}",
            provenance=provenance(
                pending.base_revision,
                None if index == 1 else index - 1,
            ),
        )
        return delivery_token

    def outcome(self, token: str, outcome: str = "delivered") -> dict[str, object]:
        server, client = socket.socketpair()
        try:
            handled = runtime._process_delivery_outcome(
                server,
                {
                    "delivery_token": token,
                    "outcome": outcome,
                    "schema": runtime.DELIVERY_OUTCOME_SCHEMA,
                },
                external_epoch=self.store,
                core=object(),
                pending_deliveries={},
                summary_worker=self.worker,
            )
            self.assertTrue(handled)
            return json.loads(client.recv(4096).split(b"\n", 1)[0])
        finally:
            server.close()
            client.close()

    def test_durable_outcome_does_not_depend_on_in_memory_pending_map(self) -> None:
        token = self.prepare(1)
        self.assertEqual(self.outcome(token)["status"], "accepted")
        self.assertEqual(self.outcome(token)["status"], "accepted")
        self.assertEqual(self.store.public_metadata()["turn_count"], 1)
        self.assertEqual(self.worker.trigger_count, 0)

    def test_delivery_ack_queues_summary_worker_without_foreground_provider(self) -> None:
        for index in range(1, 5):
            self.outcome(self.prepare(index))
        self.assertEqual(self.worker.trigger_count, 1)
        self.assertEqual(self.store.public_metadata()["queued_summary_count"], 1)

    def test_visual_event_remains_typed_inside_release_bound_context(self) -> None:
        auth = context(1)
        pending = self.store.begin_turn(
            auth,
            "synthetic caption",
            EgressSafetySignals(classifier_available=True),
        )
        payload = self.store.context_payload(
            auth,
            pending,
            visual_event={
                "caption_present": True,
                "observation": "synthetic bounded observation",
                "schema": "myuna.telegram-visual-evidence.v1",
                "source": "gemini_visual_extraction",
            },
        )
        self.assertEqual(payload["schema"], "myuna.external-context-release-bound.v1")
        self.assertEqual(
            payload["external_context"]["schema"],
            "myuna.external-context-envelope.v2",
        )
        self.store.cancel_pending(auth, pending)

    def test_runtime_release_bound_payload_matches_core_http_parser(self) -> None:
        auth = context(1)
        message = "synthetic current message"
        pending = self.store.begin_turn(
            auth,
            message,
            EgressSafetySignals(classifier_available=True),
        )
        external = self.store.context_payload(auth, pending)
        client = LoadedHttpClientCredential(
            client_id=auth.client_id,
            channel_kind=auth.channel_kind,
            token="synthetic-test-token",
        )
        conversation, parsed_auth, parsed_external = _parse_hybrid_chat_envelope(
            {
                "authenticated_context": auth.as_payload(),
                "conversation": {
                    "messages": [{"role": "user", "content": message}],
                    "synthetic_memory": False,
                },
                "external_context": external,
            },
            client,
            expected_release_set_id=RID,
        )
        self.assertEqual(conversation["messages"][-1]["content"], message)
        self.assertEqual(parsed_auth, auth)
        self.assertEqual(parsed_external, external)
        self.store.cancel_pending(auth, pending)


if __name__ == "__main__":
    unittest.main()
