from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from myuna_core.active_temporal_context import (
    ActiveTemporalContextRuntime,
    TemporalContextStore,
    TrustedTimeSample,
)
from myuna_core.active_temporal_context.protocol import (
    BOUNDARY,
    CONTENT_FREE_STATUS_SCHEMA,
    CONTENT_FREE_STATUS_SOURCE_IDENTITY,
    SCHEMA,
)
from myuna_core.active_temporal_context.service import (
    CLIENT_ID,
    CHANNEL_KIND,
    initialize_state,
    serve_connection,
)
from myuna_core.authenticated_conversation import AuthenticatedConversationContext


NOW = datetime(2026, 8, 5, 7, 0, tzinfo=timezone.utc)


class _Clock:
    def sample(self) -> TrustedTimeSample:
        return TrustedTimeSample(NOW, "synthetic-v1", "synthetic", 1)


class _EvidenceClock:
    def sample(self) -> TrustedTimeSample:
        return TrustedTimeSample(
            NOW,
            "myuna-trusted-local-v1",
            "trusted_local",
            1,
            authority="synthetic-authority",
            uncertainty_microseconds=1_000,
            synchronized=True,
            boot_id="synthetic-boot",
            monotonic_ns=1_000,
        )


def _context() -> AuthenticatedConversationContext:
    return AuthenticatedConversationContext(
        schema_version="myuna.authenticated-conversation-context.v1",
        request_id="request-v1",
        correlation_id="request-v1",
        client_id=CLIENT_ID,
        channel_kind=CHANNEL_KIND,
        binding_id="binding-v1",
        principal_id="owner-v1",
        namespace_id="telegram-owner-v1",
        authority_level="owner",
        channel_instance="telegram-primary",
        conversation_id="owner-private-v1",
        conversation_kind="private",
        event_id="event-v1",
        trace_id="trace-v1",
        occurred_at=NOW,
        delivery_capabilities=("text",),
    )


class ActiveTemporalServiceTests(unittest.TestCase):
    def test_initialization_creates_exact_empty_private_databases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "myuna-active-temporal-context-v1"
            root.mkdir(mode=0o700)
            with patch("os.geteuid", return_value=os.getuid()):
                initialize_state(root, expected_uid=os.getuid())
            paths = sorted(path.name for path in root.iterdir())
            self.assertEqual(
                paths,
                ["temporal-context.sqlite3", "trusted-time.sqlite3"],
            )
            for path in root.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with patch("os.geteuid", return_value=os.getuid()):
                with self.assertRaises(RuntimeError):
                    initialize_state(root, expected_uid=os.getuid())

    def test_socket_rejects_wrong_peer_before_parsing_or_sampling(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "private"
            root.mkdir(mode=0o700)
            runtime = ActiveTemporalContextRuntime(
                TemporalContextStore.create(root / "temporal.sqlite3"),
                _EvidenceClock(),
            )
            server, client = socket.socketpair()
            try:
                payload = {
                    "schema": SCHEMA,
                    "boundary": BOUNDARY,
                    "operation": "retrieve",
                    "request_id": "request-v1",
                    "authenticated_context": _context().as_payload(),
                    "input": {"query": "plan", "categories": [], "slot_keys": []},
                }
                client.sendall(json.dumps(payload).encode() + b"\n")
                client.shutdown(socket.SHUT_WR)
                serve_connection(server, runtime, expected_peer_uid=os.getuid() + 1000)
                response = json.loads(client.recv(4096))
                self.assertFalse(response["ok"])
                self.assertEqual(response["error"]["code"], "temporal_unavailable")
            finally:
                server.close()
                client.close()

    def test_socket_accepts_exact_peer_and_authenticated_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "private"
            root.mkdir(mode=0o700)
            runtime = ActiveTemporalContextRuntime(
                TemporalContextStore.create(root / "temporal.sqlite3"),
                _Clock(),
            )
            server, client = socket.socketpair()
            try:
                payload = {
                    "schema": SCHEMA,
                    "boundary": BOUNDARY,
                    "operation": "retrieve",
                    "request_id": "request-v1",
                    "authenticated_context": _context().as_payload(),
                    "input": {"query": "plan", "categories": [], "slot_keys": []},
                }
                client.sendall(json.dumps(payload).encode() + b"\n")
                client.shutdown(socket.SHUT_WR)
                serve_connection(server, runtime, expected_peer_uid=os.getuid())
                response = json.loads(client.recv(4096))
                self.assertTrue(response["ok"])
                self.assertEqual(response["output"]["state"], "empty")
            finally:
                server.close()
                client.close()

    def test_socket_status_operation_is_content_free_and_source_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "private"
            root.mkdir(mode=0o700)
            runtime = ActiveTemporalContextRuntime(
                TemporalContextStore.create(root / "temporal.sqlite3"),
                _EvidenceClock(),
            )
            context = _context()
            scope_digest = runtime.access_policy.authorize_read(context).scope_sha256
            server, client = socket.socketpair()
            try:
                payload = {
                    "schema": SCHEMA,
                    "boundary": BOUNDARY,
                    "operation": "status_content_free",
                    "request_id": "request-v1",
                    "authenticated_context": context.as_payload(),
                    "input": {
                        "expected_scope_digest": scope_digest,
                        "expected_source_identity": CONTENT_FREE_STATUS_SOURCE_IDENTITY,
                        "minimum_lifecycle_watermark": 0,
                        "request_nonce": "a" * 64,
                        "response_schema": CONTENT_FREE_STATUS_SCHEMA,
                    },
                }
                client.sendall(json.dumps(payload).encode() + b"\n")
                client.shutdown(socket.SHUT_WR)
                serve_connection(server, runtime, expected_peer_uid=os.getuid())
                response = json.loads(client.recv(16_384))
                self.assertTrue(response["ok"])
                self.assertEqual(response["output"]["lifecycle_watermark"], 0)
                for field in (
                    "channel_called",
                    "health_called",
                    "private_content_returned",
                    "provider_called",
                ):
                    self.assertIs(response[field], False)
                serialized = json.dumps(response, ensure_ascii=False, sort_keys=True)
                for forbidden in ('"context":', '"query":', '"fact_id":', '"source_ref":'):
                    self.assertNotIn(forbidden, serialized)
            finally:
                server.close()
                client.close()


if __name__ == "__main__":
    unittest.main()
