from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CORE_SRC = Path("/srv/myuna/repos/core/src")
sys.path.insert(0, str(CORE_SRC))
sys.path.insert(0, str(ROOT / "scripts"))

import p08_temporal_gateway_v1 as gateway
import p08_existing_state_upgrade_v1 as upgrade
import p08_temporal_service_v1 as service
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
from myuna_core.authenticated_conversation import AuthenticatedConversationContext


NOW = datetime(2026, 8, 10, 0, 0, tzinfo=timezone.utc)


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
        client_id=service.core_service.CLIENT_ID,
        channel_kind=service.core_service.CHANNEL_KIND,
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


class _Connection:
    def __init__(self) -> None:
        self.timeout: float | None = None
        self.sent = b""

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def sendall(self, value: bytes) -> None:
        self.sent += value


def _payload(connection: _Connection) -> dict[str, object]:
    return json.loads(connection.sent.decode("utf-8", "strict"))


class P08TemporalServiceProjectionTests(unittest.TestCase):
    def test_trusted_time_capability_lifecycle_is_started_ready_and_stopped(self) -> None:
        class Capability:
            def __init__(self, *, ready: bool = True) -> None:
                self.ready = ready
                self.state = "stopped"
                self.startup_calls = 0
                self.shutdown_calls = 0

            def startup(self):
                self.startup_calls += 1
                self.state = "ready" if self.ready else "failed"
                return self.lifecycle_snapshot()

            def lifecycle_snapshot(self):
                return SimpleNamespace(
                    accepting_requests=self.state == "ready",
                    state=SimpleNamespace(value=self.state),
                )

            def shutdown(self):
                self.shutdown_calls += 1
                self.state = "stopped"
                return self.lifecycle_snapshot()

        store = mock.Mock()
        store.trusted_time_watermark.return_value = None
        capabilities = [Capability(), Capability()]
        runtimes = [
            SimpleNamespace(trusted_time=capabilities[0]),
            SimpleNamespace(trusted_time=capabilities[1]),
        ]
        with (
            mock.patch.object(service.core_service.os, "geteuid", return_value=1001),
            mock.patch.object(service.core_service, "_state_root", return_value=Path("/synthetic")),
            mock.patch.object(service, "TemporalContextStore", return_value=store),
            mock.patch.object(service, "DurableTrustedTimeProvider", return_value=object()),
            mock.patch.object(
                service,
                "TrustedTimeCapability",
                side_effect=capabilities,
            ),
            mock.patch.object(
                service,
                "ActiveTemporalContextRuntime",
                side_effect=runtimes,
            ) as runtime_factory,
        ):
            first = service.build_runtime_from_environment(
                {"MYUNA_P08_SERVICE_UID": "1001"}
            )
            second = service.build_runtime_from_environment(
                {"MYUNA_P08_SERVICE_UID": "1001"}
            )
        self.assertIs(first, runtimes[0])
        self.assertIs(second, runtimes[1])
        self.assertEqual([item.startup_calls for item in capabilities], [1, 1])
        self.assertEqual(runtime_factory.call_count, 2)
        for item in capabilities:
            service._stop_trusted_time_capability(item)
            self.assertEqual(item.shutdown_calls, 1)
            self.assertEqual(item.state, "stopped")

        rejected = Capability(ready=False)
        with (
            mock.patch.object(service.core_service.os, "geteuid", return_value=1001),
            mock.patch.object(service.core_service, "_state_root", return_value=Path("/synthetic")),
            mock.patch.object(service, "TemporalContextStore", return_value=store),
            mock.patch.object(service, "DurableTrustedTimeProvider", return_value=object()),
            mock.patch.object(service, "TrustedTimeCapability", return_value=rejected),
            self.assertRaisesRegex(
                RuntimeError, "trusted_time_capability_startup_rejected"
            ),
        ):
            service.build_runtime_from_environment(
                {"MYUNA_P08_SERVICE_UID": "1001"}
            )
        self.assertEqual(rejected.startup_calls, 1)
        self.assertEqual(rejected.shutdown_calls, 1)
        self.assertEqual(rejected.state, "stopped")

        crashing = Capability()
        crashing.state = "ready"
        server = mock.Mock()
        server.accept.side_effect = RuntimeError("synthetic-crash")
        socket_context = mock.MagicMock()
        socket_context.__enter__.return_value = server
        socket_context.__exit__.return_value = False
        with (
            mock.patch.object(service.core_service.os, "geteuid", return_value=1001),
            mock.patch.dict(
                service.core_service.os.environ,
                {
                    "MYUNA_P08_SERVICE_UID": "1001",
                    "MYUNA_P08_TELEGRAM_UID": "1002",
                },
            ),
            mock.patch.object(
                service,
                "build_runtime_from_environment",
                return_value=SimpleNamespace(trusted_time=crashing),
            ),
            mock.patch.object(
                service,
                "TrustedTimeCapability",
                Capability,
            ),
            mock.patch.object(
                service,
                "inherited_systemd_socket",
                return_value=socket_context,
            ),
            self.assertRaisesRegex(RuntimeError, "synthetic-crash"),
        ):
            service.serve_systemd_socket()
        self.assertEqual(crashing.shutdown_calls, 1)
        self.assertEqual(crashing.state, "stopped")

        degraded = Capability()
        degraded.state = "ready"
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False
        server = mock.Mock()
        server.accept.return_value = (connection, None)
        socket_context = mock.MagicMock()
        socket_context.__enter__.return_value = server
        socket_context.__exit__.return_value = False

        def degrade(*_args, **_kwargs):
            degraded.state = "degraded"

        with (
            mock.patch.object(service.core_service.os, "geteuid", return_value=1001),
            mock.patch.dict(
                service.core_service.os.environ,
                {
                    "MYUNA_P08_SERVICE_UID": "1001",
                    "MYUNA_P08_TELEGRAM_UID": "1002",
                },
            ),
            mock.patch.object(
                service,
                "build_runtime_from_environment",
                return_value=SimpleNamespace(trusted_time=degraded),
            ),
            mock.patch.object(service, "TrustedTimeCapability", Capability),
            mock.patch.object(
                service,
                "inherited_systemd_socket",
                return_value=socket_context,
            ),
            mock.patch.object(service, "serve_connection", side_effect=degrade),
            self.assertRaisesRegex(
                RuntimeError, "trusted_time_capability_not_ready"
            ),
        ):
            service.serve_systemd_socket()
        self.assertEqual(degraded.shutdown_calls, 1)
        self.assertEqual(degraded.state, "stopped")

    def test_exact_authenticated_status_request_is_accepted_offline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = ActiveTemporalContextRuntime(
                TemporalContextStore.create(root / "temporal.sqlite3"),
                _EvidenceClock(),
            )
            context = _context()
            scope_digest = runtime.access_policy.authorize_read(context).scope_sha256
            request = {
                "authenticated_context": context.as_payload(),
                "boundary": BOUNDARY,
                "input": {
                    "expected_scope_digest": scope_digest,
                    "expected_source_identity": CONTENT_FREE_STATUS_SOURCE_IDENTITY,
                    "minimum_lifecycle_watermark": 0,
                    "request_nonce": "a" * 64,
                    "response_schema": CONTENT_FREE_STATUS_SCHEMA,
                },
                "operation": "status_content_free",
                "request_id": "request-v1",
                "schema": SCHEMA,
            }
            server, client = socket.socketpair()
            try:
                client.sendall(
                    json.dumps(
                        request,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode("ascii")
                    + b"\n"
                )
                client.shutdown(socket.SHUT_WR)
                service.serve_connection(
                    server,
                    runtime,
                    expected_peer_uid=os.getuid(),
                )
                response = json.loads(client.recv(16_384))
            finally:
                server.close()
                client.close()
            self.assertTrue(response["ok"])
            self.assertEqual(response["operation"], "status_content_free")
            self.assertNotIn("content_free_rejection", response)
            self.assertFalse(response["private_content_returned"])

    def test_source_owned_service_contract_rejects_runtime_or_client_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = (
                upgrade.CLIENT_PATH,
                upgrade.SERVICE_SOURCE_PATH,
            )
            for relative in paths:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            core_service = root / upgrade.SERVICE_PATH
            core_service.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(
                CORE_SRC / "myuna_core/active_temporal_context/service.py",
                core_service,
            )
            runtime = root / upgrade.SERVICE_ENTRYPOINT_PATH
            runtime.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / upgrade.SERVICE_SOURCE_PATH, runtime)

            contract = upgrade.server_rejection_contract(root)
            self.assertEqual(contract["entrypoint"], "p08_temporal_service_v1")
            self.assertEqual(
                contract["rejection_subprojection"]["source_identity"],
                service.SERVER_REJECTION_SOURCE_IDENTITY,
            )
            runtime.write_bytes(runtime.read_bytes() + b"\n# substituted\n")
            with self.assertRaises(upgrade.UpgradeRejected):
                upgrade.server_rejection_contract(root)

    def test_projection_contract_is_exact_deterministic_and_client_bound(self) -> None:
        self.assertEqual(
            service.SERVER_REJECTION_SOURCE_IDENTITY,
            gateway.SERVER_REJECTION_SOURCE_IDENTITY,
        )
        self.assertEqual(
            service._SERVER_REJECTION_POLICY,
            gateway._SERVER_REJECTION_POLICY,
        )
        expected_keys = {
            "category",
            "persistent_mutation",
            "private_content_included",
            "projection_digest",
            "raw_cause_included",
            "retryable",
            "schema",
            "source_contract_identity",
            "stage",
        }
        for stage in service._SERVER_REJECTION_POLICY:
            with self.subTest(stage=stage):
                first = service.server_rejection_projection(stage)
                second = service.server_rejection_projection(stage)
                self.assertEqual(first, second)
                self.assertEqual(set(first), expected_keys)
                self.assertEqual(
                    service.parse_server_rejection_projection(first)[0],
                    stage,
                )
                client = gateway.parse_content_free_server_rejection(first)
                self.assertEqual(client.stage, stage)
                self.assertFalse(first["persistent_mutation"])
                self.assertFalse(first["private_content_included"])
                self.assertFalse(first["raw_cause_included"])

        base = service.server_rejection_projection("service_peer_boundary")
        mutations = {
            "unknown": {**base, "stage": "private/path/value"},
            "category": {**base, "category": "raw_exception"},
            "retryable": {**base, "retryable": True},
            "retryable_type": {**base, "retryable": 0},
            "mixed_source": {**base, "source_contract_identity": "0" * 64},
            "digest": {**base, "projection_digest": "0" * 64},
            "extra": {**base, "exception": "private/raw/cause"},
        }
        for name, payload in mutations.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                gateway.parse_content_free_server_rejection(payload)

    def test_runtime_subprojection_is_exact_nonce_bound_and_content_free(self) -> None:
        nonce = "d" * 64
        self.assertEqual(
            service.STATUS_RUNTIME_REJECTION_SOURCE_IDENTITY,
            gateway.STATUS_RUNTIME_REJECTION_SOURCE_IDENTITY,
        )
        self.assertEqual(
            service._STATUS_RUNTIME_REJECTION_POLICY,
            gateway._STATUS_RUNTIME_REJECTION_POLICY,
        )
        expected_keys = {
            "category",
            "error_category",
            "persistent_mutation",
            "private_content_included",
            "projection_digest",
            "provider_state_effect",
            "raw_cause_included",
            "request_nonce",
            "retryable",
            "schema",
            "source_contract_identity",
            "stage",
        }
        for stage in service._STATUS_RUNTIME_REJECTION_POLICY:
            with self.subTest(stage=stage):
                error_category = (
                    "trusted_time_unavailable"
                    if stage == "trusted_time_boundary"
                    else None
                )
                projection = service.status_runtime_rejection_projection(
                    stage,
                    request_nonce=nonce,
                    error_category=error_category,
                )
                self.assertEqual(set(projection), expected_keys)
                self.assertFalse(projection["persistent_mutation"])
                self.assertFalse(projection["private_content_included"])
                self.assertFalse(projection["raw_cause_included"])
                parsed = service.parse_status_runtime_rejection_projection(
                    projection,
                    expected_request_nonce=nonce,
                )
                self.assertEqual(parsed[0], stage)
                self.assertEqual(parsed[1], projection["error_category"])
                self.assertEqual(parsed[2], projection["retryable"])
                self.assertEqual(parsed[3], projection["provider_state_effect"])
                client = gateway.parse_content_free_runtime_rejection(
                    projection,
                    expected_request_nonce=nonce,
                )
                self.assertEqual(client.stage, stage)

        base = service.status_runtime_rejection_projection(
            "trusted_time_boundary",
            request_nonce=nonce,
            error_category="trusted_time_unavailable",
        )
        for mutation in (
            {**base, "request_nonce": "e" * 64},
            {**base, "source_contract_identity": "0" * 64},
            {**base, "projection_digest": "0" * 64},
            {**base, "raw_cause": "PRIVATE/raw/path/value"},
        ):
            with self.assertRaises(ValueError):
                gateway.parse_content_free_runtime_rejection(
                    mutation,
                    expected_request_nonce=nonce,
                )

        for category, (retryable, state_effect) in (
            service._TRUSTED_TIME_REJECTION_POLICY.items()
        ):
            projection = service.status_runtime_rejection_projection(
                "trusted_time_boundary",
                request_nonce=nonce,
                error_category=category,
            )
            self.assertEqual(projection["error_category"], category)
            self.assertIs(projection["retryable"], retryable)
            self.assertEqual(projection["provider_state_effect"], state_effect)

    def test_runtime_failures_map_to_one_allowlisted_substage(self) -> None:
        nonce = "f" * 64
        cases = (
            (
                service.TemporalContextError(
                    "trusted_time_unavailable", retryable=True
                ),
                "trusted_time_boundary",
                "trusted_time_unavailable",
            ),
            (
                service.TemporalContextError(
                    "trusted_time_unsynchronized", retryable=True
                ),
                "trusted_time_boundary",
                "trusted_time_unsynchronized",
            ),
            (
                service.TemporalContextError(
                    "trusted_time_regression", retryable=False
                ),
                "trusted_time_boundary",
                "trusted_time_regression",
            ),
            (
                service.TemporalContextError(
                    "trusted_time_state_corrupt", retryable=False
                ),
                "trusted_time_boundary",
                "trusted_time_state_corrupt",
            ),
            (
                service.TemporalContextError(
                    "trusted_time_persistence_ambiguous", retryable=True
                ),
                "trusted_time_boundary",
                "trusted_time_persistence_ambiguous",
            ),
            (
                service.TemporalContextError("database_corrupt"),
                "store_state_boundary",
                "store_state_rejected",
            ),
            (
                service.TemporalProtocolError("status_scope_mismatch"),
                "status_projection_boundary",
                "status_projection_rejected",
            ),
            (
                RuntimeError("PRIVATE/raw/cause"),
                "status_runtime_unknown_boundary",
                "runtime_unknown_rejected",
            ),
        )
        for failure, expected_stage, expected_category in cases:
            connection = _Connection()
            with (
                self.subTest(stage=expected_stage),
                mock.patch.object(service.core_service, "_peer_uid", return_value=1001),
                mock.patch.object(
                    service.core_service,
                    "read_one_request",
                    return_value=b"synthetic-request",
                ),
                mock.patch.object(
                    service,
                    "parse_request_bytes",
                    return_value=(
                        "request-v1",
                        "status_content_free",
                        object(),
                        {"request_nonce": nonce},
                    ),
                ),
                mock.patch.object(service, "execute_request", side_effect=failure),
            ):
                service.serve_connection(
                    connection,
                    mock.Mock(),
                    expected_peer_uid=1001,
                )
            response = _payload(connection)
            self.assertEqual(
                response["content_free_rejection"]["stage"],
                "status_runtime_boundary",
            )
            runtime = response["content_free_runtime_rejection"]
            self.assertEqual(runtime["stage"], expected_stage)
            self.assertEqual(runtime["error_category"], expected_category)
            if expected_category == "trusted_time_persistence_ambiguous":
                self.assertEqual(runtime["provider_state_effect"], "ambiguous")
            else:
                self.assertEqual(runtime["provider_state_effect"], "none")
            gateway.parse_content_free_runtime_rejection(
                runtime,
                expected_request_nonce=nonce,
            )
            self.assertNotIn("PRIVATE", connection.sent.decode("utf-8"))

    def test_peer_protocol_and_runtime_failures_map_once_without_raw_cause(self) -> None:
        raw_cause = "PRIVATE/raw/path/credential/value"
        cases = (
            (
                "service_peer_boundary",
                mock.patch.object(
                    service.core_service,
                    "_peer_uid",
                    side_effect=RuntimeError(raw_cause),
                ),
                None,
                "temporal_unavailable",
                True,
            ),
            (
                "authenticated_context_protocol_boundary",
                mock.patch.object(
                    service,
                    "parse_request_bytes",
                    side_effect=ValueError(raw_cause),
                ),
                None,
                "invalid_request",
                False,
            ),
            (
                "status_runtime_boundary",
                mock.patch.object(
                    service,
                    "execute_request",
                    side_effect=RuntimeError(raw_cause),
                ),
                (
                    "request-v1",
                    "status_content_free",
                    object(),
                    {},
                ),
                "temporal_unavailable",
                True,
            ),
        )
        for stage, failure, parsed, error_code, error_retryable in cases:
            connection = _Connection()
            with (
                self.subTest(stage=stage),
                mock.patch.object(service.core_service, "_peer_uid", return_value=1001),
                mock.patch.object(
                    service.core_service,
                    "read_one_request",
                    return_value=b"synthetic-request",
                ),
                mock.patch.object(
                    service,
                    "parse_request_bytes",
                    return_value=parsed,
                ),
                failure,
            ):
                service.serve_connection(
                    connection,
                    mock.Mock(),
                    expected_peer_uid=1001,
                )
            response = _payload(connection)
            self.assertFalse(response["ok"])
            self.assertEqual(response["error"]["code"], error_code)
            self.assertIs(response["error"]["retryable"], error_retryable)
            projection = response["content_free_rejection"]
            self.assertEqual(projection["stage"], stage)
            service.parse_server_rejection_projection(projection)
            self.assertNotIn(raw_cause, connection.sent.decode("utf-8"))

    def test_invalid_status_input_stays_at_protocol_boundary(self) -> None:
        connection = _Connection()
        with (
            mock.patch.object(service.core_service, "_peer_uid", return_value=1001),
            mock.patch.object(
                service.core_service,
                "read_one_request",
                return_value=b"synthetic-request",
            ),
            mock.patch.object(
                service,
                "parse_request_bytes",
                return_value=(
                    "request-v1",
                    "status_content_free",
                    object(),
                    {},
                ),
            ),
            mock.patch.object(
                service,
                "execute_request",
                side_effect=service.TemporalProtocolError("invalid_request"),
            ),
        ):
            service.serve_connection(
                connection,
                mock.Mock(),
                expected_peer_uid=1001,
            )
        response = _payload(connection)
        self.assertEqual(response["request_id"], "request-v1")
        self.assertEqual(
            response["content_free_rejection"]["stage"],
            "authenticated_context_protocol_boundary",
        )

    def test_success_and_non_status_paths_preserve_core_response_semantics(self) -> None:
        status_connection = _Connection()
        status = {
            "schema": "myuna.active-temporal-context-protocol.v1",
            "operation": "status_content_free",
            "ok": True,
            "request_id": "request-v1",
            "output": {"synthetic": True},
            "model_called": False,
            "profile_written": False,
            "session_written": False,
            "legacy_namespace_written": False,
            "channel_called": False,
            "health_called": False,
            "private_content_returned": False,
            "provider_called": False,
        }
        with (
            mock.patch.object(service.core_service, "_peer_uid", return_value=1001),
            mock.patch.object(
                service.core_service,
                "read_one_request",
                return_value=b"synthetic-status",
            ),
            mock.patch.object(
                service,
                "parse_request_bytes",
                return_value=(
                    "request-v1",
                    "status_content_free",
                    object(),
                    {},
                ),
            ),
            mock.patch.object(service, "execute_request", return_value=status),
        ):
            service.serve_connection(
                status_connection,
                mock.Mock(),
                expected_peer_uid=1001,
            )
        self.assertEqual(_payload(status_connection), status)

        non_status_connection = _Connection()
        expected = b'{"ok":true,"synthetic":true}'
        with (
            mock.patch.object(service.core_service, "_peer_uid", return_value=1001),
            mock.patch.object(
                service.core_service,
                "read_one_request",
                return_value=b"synthetic-retrieve",
            ),
            mock.patch.object(
                service,
                "parse_request_bytes",
                return_value=("request-v2", "retrieve", object(), {}),
            ),
            mock.patch.object(service, "process_request", return_value=expected) as process,
        ):
            service.serve_connection(
                non_status_connection,
                mock.Mock(),
                expected_peer_uid=1001,
            )
        self.assertEqual(non_status_connection.sent, expected)
        process.assert_called_once()


if __name__ == "__main__":
    unittest.main()
