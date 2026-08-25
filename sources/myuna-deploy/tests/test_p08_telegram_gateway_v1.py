from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
PLUGIN = ROOT / "channels/astrbot-telegram/plugin/myuna_telegram_gateway"
sys.path.insert(0, str(SCRIPTS))

import p08_temporal_gateway_v1 as temporal
import telegram_runtime_config as runtime_config_contract


def _load_plugin_protocol():
    spec = importlib.util.spec_from_file_location(
        "p08_plugin_protocol_test", PLUGIN / "protocol.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _context(request_id: str) -> dict[str, object]:
    return {
        "authority_level": "owner",
        "binding_id": "binding-owner-v1",
        "channel_instance": "telegram-owner-dev",
        "channel_kind": "astrbot_telegram",
        "client_id": "telegram-owner-runtime-v1",
        "consent": {
            "media_processing": False,
            "memory_candidate": True,
            "tools": False,
        },
        "conversation_id": "conv-owner-v1",
        "conversation_kind": "private",
        "correlation_id": "trace-owner-v1",
        "delivery_capabilities": ["text"],
        "event_id": "evt-owner-v1",
        "namespace_id": "namespace-owner-v1",
        "occurred_at": "2026-08-05T12:00:00.000000+00:00",
        "principal_id": "principal-owner-v1",
        "request_id": request_id,
        "schema_version": "myuna.authenticated-conversation-context.v1",
        "trace_id": "trace-owner-v1",
    }


def _status_context(request_id: str) -> dict[str, object]:
    value = _context(request_id)
    value["conversation_id"] = temporal.STATUS_CONVERSATION_ID
    return value


def _active_response(
    *,
    request_id: str = "gateway-active-v1",
    after_event_sequence: int = 0,
    transitions: list[dict[str, object]] | None = None,
    lifecycle_watermark: int = 0,
    lifecycle_has_more: bool = False,
) -> dict[str, object]:
    selected_transitions = [] if transitions is None else transitions
    trusted_time = {
        "authority": "synthetic-authority",
        "boot_id": "synthetic-boot",
        "instant": "2026-08-08T12:00:00.000000+00:00",
        "monotonic_ns": 100,
        "sequence": 7,
        "source": "myuna-trusted-local-v1",
        "source_class": "trusted_local",
        "synchronized": True,
        "uncertainty_microseconds": 1000,
    }
    output: dict[str, object] = {
        "context": "[active_temporal_validity_context_v1 all_or_none=true]",
        "fact_count": 0,
        "lifecycle_has_more": lifecycle_has_more,
        "lifecycle_transitions": selected_transitions,
        "lifecycle_watermark": lifecycle_watermark,
        "projection_digest": "a" * 64,
        "trusted_time": trusted_time,
    }
    output["active_snapshot_receipt"] = (
        temporal.temporal_protocol_contract.build_active_snapshot_receipt(
            request_id=request_id,
            after_event_sequence=after_event_sequence,
            fact_count=0,
            lifecycle_transitions=selected_transitions,
            lifecycle_watermark=lifecycle_watermark,
            lifecycle_has_more=lifecycle_has_more,
            trusted_time=trusted_time,
        ).as_payload()
    )
    return {
        "schema": temporal.SCHEMA,
        "operation": "snapshot_active",
        "ok": True,
        "request_id": request_id,
        "output": output,
        "model_called": False,
        "profile_written": False,
        "session_written": False,
        "legacy_namespace_written": False,
    }


def _status_response(
    *,
    request_id: str,
    request_nonce: str,
    scope_digest: str,
    lifecycle_watermark: int = 7,
) -> dict[str, object]:
    stable = {
        "active_fact_count": 2,
        "active_set_complete": True,
        "active_set_digest": "1" * 64,
        "lifecycle_complete": True,
        "lifecycle_digest": "2" * 64,
        "lifecycle_event_count": lifecycle_watermark,
        "lifecycle_watermark": lifecycle_watermark,
        "pending_proposal_count": 1,
        "scope_binding_digest": scope_digest,
        "source_identity": temporal.CONTENT_FREE_STATUS_SOURCE_IDENTITY,
        "status_schema": temporal.CONTENT_FREE_STATUS_SCHEMA,
        "total_fact_count": 3,
        "trusted_time_binding_digest": "4" * 64,
        "trusted_time_evidence_complete": True,
    }
    status_digest = temporal._canonical_digest(
        "myuna-p08-content-free-status-v1", stable
    )
    output = {
        **stable,
        "request_nonce": request_nonce,
        "response_digest": temporal._canonical_digest(
            "myuna-p08-content-free-status-v1",
            {
                "request_nonce": request_nonce,
                "source_identity": temporal.CONTENT_FREE_STATUS_SOURCE_IDENTITY,
                "status_digest": status_digest,
            },
        ),
        "status_digest": status_digest,
    }
    return {
        "channel_called": False,
        "health_called": False,
        "legacy_namespace_written": False,
        "model_called": False,
        "ok": True,
        "operation": temporal.STATUS_OPERATION,
        "output": output,
        "private_content_returned": False,
        "profile_written": False,
        "provider_called": False,
        "request_id": request_id,
        "schema": temporal.SCHEMA,
        "session_written": False,
    }


def _runtime_payload() -> dict[str, object]:
    return {
        "binding_id": "binding-owner-v1",
        "channel_instance": "telegram-owner-dev",
        "channel_kind": "astrbot_telegram",
        "core_host": "127.0.0.1",
        "core_port": 18765,
        "evidence_sha256": "6" * 64,
        "finalization_digest": "7" * 64,
        "max_history_characters": 131072,
        "max_history_messages": 128,
        "max_requests_per_ten_minutes": 20,
        "namespace_id": "namespace-owner-v1",
        "principal_id": "principal-owner-v1",
    }


def _runtime_config() -> runtime_config_contract.RuntimeConfig:
    return runtime_config_contract.RuntimeConfig.from_payload(_runtime_payload())


class TemporalCommandTests(unittest.TestCase):
    def test_content_free_status_request_is_authenticated_and_contains_no_query(self) -> None:
        request_id = "p08-status-test-v1"
        nonce = "a" * 64
        request = temporal.build_content_free_status_request(
            authenticated_context=_status_context(request_id),
            request_id=request_id,
            request_nonce=nonce,
            minimum_lifecycle_watermark=6,
        )
        self.assertEqual(request["operation"], temporal.STATUS_OPERATION)
        self.assertEqual(
            set(request["input"]),
            {
                "expected_scope_digest",
                "expected_source_identity",
                "minimum_lifecycle_watermark",
                "request_nonce",
                "response_schema",
            },
        )
        serialized = json.dumps(request, ensure_ascii=True, sort_keys=True)
        for forbidden in ("query", "summary", "fact_id", "source_ref", "profile"):
            self.assertNotIn(f'"{forbidden}"', serialized)
        for field, value in (
            ("authority_level", "member"),
            ("conversation_kind", "group"),
            ("channel_kind", "qq"),
            ("conversation_id", "another-conversation"),
        ):
            context = _status_context(request_id)
            context[field] = value
            with self.subTest(field=field), self.assertRaises(
                temporal.TemporalGatewayRejected
            ):
                temporal.build_content_free_status_request(
                    authenticated_context=context,
                    request_id=request_id,
                    request_nonce=nonce,
                )

    def test_content_free_status_response_is_nonce_bound_complete_and_bounded(self) -> None:
        request_id = "p08-status-test-v1"
        scope_digest = "b" * 64
        first = _status_response(
            request_id=request_id,
            request_nonce="c" * 64,
            scope_digest=scope_digest,
        )
        second = _status_response(
            request_id=request_id,
            request_nonce="d" * 64,
            scope_digest=scope_digest,
        )
        parsed = temporal.parse_content_free_status_response(
            first,
            request_id=request_id,
            request_nonce="c" * 64,
            expected_scope_digest=scope_digest,
            minimum_lifecycle_watermark=7,
        )
        self.assertEqual(parsed.lifecycle_watermark, 7)
        self.assertEqual(first["output"]["status_digest"], second["output"]["status_digest"])
        self.assertNotEqual(
            first["output"]["response_digest"], second["output"]["response_digest"]
        )
        serialized = json.dumps(first, ensure_ascii=True, sort_keys=True)
        for forbidden in ("query", "summary", "context", "fact_id", "source_ref"):
            self.assertNotIn(f'"{forbidden}"', serialized)

    def test_content_free_status_rejects_replay_stale_extra_and_malformed(self) -> None:
        request_id = "p08-status-test-v1"
        nonce = "e" * 64
        scope_digest = "f" * 64
        base = _status_response(
            request_id=request_id,
            request_nonce=nonce,
            scope_digest=scope_digest,
        )
        cases: list[tuple[str, dict[str, object], dict[str, object]]] = []
        replay = json.loads(json.dumps(base))
        cases.append(("replay", replay, {"request_nonce": "0" * 64}))
        stale = json.loads(json.dumps(base))
        cases.append(("stale", stale, {"minimum_lifecycle_watermark": 8}))
        extra = json.loads(json.dumps(base))
        extra["output"]["temporal_text"] = "forbidden"
        cases.append(("extra", extra, {}))
        malformed = json.loads(json.dumps(base))
        malformed["output"]["active_fact_count"] = temporal.MAX_STATUS_FACTS + 1
        cases.append(("malformed", malformed, {}))
        source = json.loads(json.dumps(base))
        source["output"]["source_identity"] = "0" * 64
        cases.append(("source", source, {}))
        for name, payload, overrides in cases:
            with self.subTest(name=name), self.assertRaises(
                temporal.TemporalGatewayRejected
            ):
                temporal.parse_content_free_status_response(
                    payload,
                    request_id=request_id,
                    request_nonce=str(overrides.get("request_nonce", nonce)),
                    expected_scope_digest=scope_digest,
                    minimum_lifecycle_watermark=int(
                        overrides.get("minimum_lifecycle_watermark", 0)
                    ),
                )

    def test_content_free_status_helper_is_fixed_identity_bounded_and_typed(self) -> None:
        config = _runtime_config()
        scope_digest = temporal.content_free_scope_digest(
            binding_id=config.binding_id,
            principal_id=config.principal_id,
            namespace_id=config.namespace_id,
            channel_kind=config.channel_kind,
            channel_instance=config.channel_instance,
        )
        response = _status_response(
            request_id="unused",
            request_nonce="8" * 64,
            scope_digest=scope_digest,
        )
        projection = response["output"]
        completed = mock.Mock(
            returncode=0,
            stdout=json.dumps(projection, ensure_ascii=True, sort_keys=True) + "\n",
        )
        with mock.patch.object(temporal.subprocess, "run", return_value=completed) as run:
            status = temporal.run_content_free_status_helper(config)
        self.assertEqual(status.lifecycle_watermark, 7)
        command = run.call_args.args[0]
        self.assertEqual(command[:2], ["/usr/bin/env", "-i"])
        self.assertNotIn("/usr/sbin/runuser", command)
        self.assertEqual(command[-1], "--content-free-status")
        self.assertNotIn("snapshot_active", command)
        with mock.patch.object(
            temporal.subprocess,
            "run",
            side_effect=temporal.subprocess.TimeoutExpired(command, 15),
        ), self.assertRaisesRegex(
            temporal.TemporalGatewayRejected, "temporal_status_unavailable"
        ):
            temporal.run_content_free_status_helper(config)

    def test_content_free_status_helper_drops_identity_before_config_or_socket(self) -> None:
        account = mock.Mock(pw_uid=988, pw_gid=982)
        order: list[str] = []
        with (
            mock.patch.object(temporal.pwd, "getpwnam", return_value=account),
            mock.patch.object(temporal.os, "geteuid", side_effect=[0, 988]),
            mock.patch.object(temporal.os, "getegid", side_effect=[0, 982]),
            mock.patch.object(
                temporal.os, "initgroups", side_effect=lambda *_: order.append("groups")
            ) as groups,
            mock.patch.object(
                temporal.os, "setgid", side_effect=lambda *_: order.append("gid")
            ) as setgid,
            mock.patch.object(
                temporal.os, "setuid", side_effect=lambda *_: order.append("uid")
            ) as setuid,
        ):
            temporal.enter_content_free_status_identity()
        self.assertEqual(order, ["groups", "gid", "uid"])
        groups.assert_called_once_with(temporal.STATUS_RUNTIME_USER, 982)
        setgid.assert_called_once_with(982)
        setuid.assert_called_once_with(988)

        with (
            mock.patch.object(temporal.pwd, "getpwnam", return_value=account),
            mock.patch.object(temporal.os, "geteuid", return_value=1234),
            mock.patch.object(temporal.os, "getegid", return_value=1234),
            self.assertRaisesRegex(
                temporal.TemporalGatewayRejected, "temporal_status_unavailable"
            ),
        ):
            temporal.enter_content_free_status_identity()

    def test_content_free_status_main_enters_identity_before_runtime_access(self) -> None:
        order: list[str] = []
        status = mock.Mock()
        status.projection.return_value = {"status": "content-free"}
        with (
            mock.patch.object(
                temporal,
                "enter_content_free_status_identity",
                side_effect=lambda: order.append("identity"),
            ),
            mock.patch.object(
                temporal,
                "load_protected_status_runtime_config",
                side_effect=lambda: order.append("config") or object(),
            ),
            mock.patch.object(
                temporal,
                "query_content_free_status",
                side_effect=lambda _config, *, request_nonce: (
                    order.append(f"socket:{request_nonce}") or status
                ),
            ),
            mock.patch.object(temporal.sys.stdout, "write"),
            mock.patch.dict(
                temporal.os.environ,
                {temporal.STATUS_INVOCATION_NONCE_ENV: "9" * 64},
            ),
        ):
            self.assertEqual(temporal.main(["--content-free-status"]), 0)
        self.assertEqual(order, ["identity", "config", f"socket:{'9' * 64}"])

    def test_content_free_status_main_uses_one_controller_nonce_end_to_end(self) -> None:
        nonce = "a" * 64
        status = mock.Mock()
        status.projection.return_value = {"request_nonce": nonce}
        with (
            mock.patch.object(temporal, "enter_content_free_status_identity"),
            mock.patch.object(
                temporal, "load_protected_status_runtime_config", return_value=object()
            ),
            mock.patch.object(
                temporal, "query_content_free_status", return_value=status
            ) as query,
            mock.patch.object(temporal.sys.stdout, "write"),
            mock.patch.dict(
                temporal.os.environ,
                {temporal.STATUS_INVOCATION_NONCE_ENV: nonce},
            ),
        ):
            self.assertEqual(temporal.main(["--content-free-status"]), 0)
        query.assert_called_once_with(mock.ANY, request_nonce=nonce)

    def test_query_content_free_status_reuses_supplied_nonce(self) -> None:
        nonce = "b" * 64
        config = mock.Mock(
            channel_kind=temporal.STATUS_CHANNEL_KIND,
            binding_id="binding",
            principal_id="principal",
            namespace_id="namespace",
            channel_instance="instance",
        )
        response = {
            "output": {
                "request_nonce": nonce,
                "scope_binding_digest": temporal.content_free_scope_digest(
                    binding_id="binding",
                    principal_id="principal",
                    namespace_id="namespace",
                    channel_kind=temporal.STATUS_CHANNEL_KIND,
                    channel_instance="instance",
                ),
                "source_identity": temporal.CONTENT_FREE_STATUS_SOURCE_IDENTITY,
                "status_schema": temporal.CONTENT_FREE_STATUS_SCHEMA,
                "lifecycle_watermark": 0,
            }
        }
        parsed = mock.Mock()
        with (
            mock.patch.object(temporal, "_coerce_status_runtime_config", return_value=config),
            mock.patch.object(temporal, "send_temporal_request", return_value=response) as send,
            mock.patch.object(
                temporal, "parse_content_free_status_response", return_value=parsed
            ),
            mock.patch.object(temporal.secrets, "token_hex") as generated,
        ):
            self.assertIs(
                temporal.query_content_free_status(config, request_nonce=nonce), parsed
            )
        generated.assert_not_called()
        self.assertEqual(send.call_args.args[0]["input"]["request_nonce"], nonce)

    def test_content_free_rejection_bytes_are_strict_and_nonce_bound(self) -> None:
        nonce = "c" * 64
        projection = temporal.ContentFreeStatusRejection.from_stage(
            "server_status_runtime_rejection", invocation_nonce=nonce
        ).projection()
        raw = json.dumps(projection, separators=(",", ":"), sort_keys=True).encode()
        parsed = temporal.parse_content_free_status_rejection_bytes(
            raw, expected_invocation_nonce=nonce
        )
        self.assertEqual(parsed.projection(), projection)
        invalid = [
            b"",
            b"not-json",
            raw + b"x",
            raw.replace(nonce.encode(), ("d" * 64).encode()),
            b"{" + b'"schema":1,' + raw[1:],
            b"x" * (temporal.MAX_STATUS_HELPER_OUTPUT_BYTES + 1),
        ]
        for payload in invalid:
            with self.subTest(payload_size=len(payload)), self.assertRaises(ValueError):
                temporal.parse_content_free_status_rejection_bytes(
                    payload, expected_invocation_nonce=nonce
                )

    def test_content_free_status_stage_contract_is_exact_and_source_bound(self) -> None:
        nonce = "a" * 64
        expected_keys = {
            "category",
            "invocation_nonce",
            "persistent_mutation",
            "projection_digest",
            "result",
            "retryable",
            "schema",
            "stage",
            "stage_contract_identity",
        }
        for stage, (category, retryable) in temporal._STATUS_STAGE_POLICY.items():
            with self.subTest(stage=stage):
                rejection = temporal.ContentFreeStatusRejection.from_stage(
                    stage, invocation_nonce=nonce
                )
                projection = rejection.projection()
                self.assertEqual(set(projection), expected_keys)
                self.assertEqual(projection["category"], category)
                self.assertIs(projection["retryable"], retryable)
                self.assertIs(projection["persistent_mutation"], False)
                self.assertEqual(
                    temporal.parse_content_free_status_rejection(
                        projection,
                        expected_invocation_nonce=nonce,
                    ),
                    rejection,
                )

        base = temporal.ContentFreeStatusRejection.from_stage(
            "transport_connect", invocation_nonce=nonce
        ).projection()
        mutations = {
            "unknown_stage": {**base, "stage": "injected/private/path"},
            "category": {**base, "category": "raw_exception"},
            "retryable": {**base, "retryable": False},
            "retryable_type": {**base, "retryable": 1},
            "mutation_type": {**base, "persistent_mutation": 0},
            "mixed_source": {**base, "stage_contract_identity": "0" * 64},
            "replay": {**base, "invocation_nonce": "b" * 64},
            "digest": {**base, "projection_digest": "0" * 64},
            "extra": {**base, "stderr": "private-value"},
        }
        for name, payload in mutations.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                temporal.parse_content_free_status_rejection(
                    payload,
                    expected_invocation_nonce=nonce,
                )

    def test_server_rejection_subprojection_maps_exact_boundaries_and_fails_closed(self) -> None:
        request_id = "p08-stage-request-v1"
        expected = {
            "service_peer_boundary": "server_service_peer_rejection",
            "authenticated_context_protocol_boundary": (
                "server_authenticated_context_protocol_rejection"
            ),
            "status_runtime_boundary": "server_status_runtime_rejection",
        }
        for server_stage, status_stage in expected.items():
            rejection = temporal.ContentFreeServerRejection.from_stage(server_stage)
            response = {
                "content_free_rejection": rejection.projection(),
                "error": {
                    "code": rejection.error_code,
                    "retryable": rejection.error_retryable,
                },
                "ok": False,
                "request_id": request_id,
                "schema": temporal.SCHEMA,
            }
            raw = json.dumps(
                response,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            with self.subTest(stage=server_stage), self.assertRaises(
                temporal.TemporalGatewayRejected
            ) as caught:
                temporal._read_response(
                    raw,
                    request_id=request_id,
                    content_free_status=True,
                )
            self.assertEqual(caught.exception.code, "temporal_status_unavailable")
            self.assertIs(caught.exception.retryable, False)
            self.assertEqual(caught.exception.status_stage, status_stage)

        base = temporal.ContentFreeServerRejection.from_stage(
            "status_runtime_boundary"
        )
        valid = {
            "content_free_rejection": base.projection(),
            "error": {
                "code": base.error_code,
                "retryable": base.error_retryable,
            },
            "ok": False,
            "request_id": request_id,
            "schema": temporal.SCHEMA,
        }
        mutations = {
            "mixed_error": {
                **valid,
                "error": {"code": "invalid_request", "retryable": False},
            },
            "mixed_source": {
                **valid,
                "content_free_rejection": {
                    **base.projection(),
                    "source_contract_identity": "0" * 64,
                },
            },
            "extra": {**valid, "stderr": "PRIVATE/raw/cause"},
        }
        for name, response in mutations.items():
            raw = json.dumps(
                response,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            with self.subTest(name=name), self.assertRaises(
                temporal.TemporalGatewayRejected
            ) as caught:
                temporal._read_response(
                    raw,
                    request_id=request_id,
                    content_free_status=True,
                )
            self.assertEqual(caught.exception.status_stage, "response_projection")

    def test_status_runtime_subprojection_preserves_generic_p07_projection(self) -> None:
        request_id = "p08-stage-request-v1"
        nonce = "9" * 64
        server = temporal.ContentFreeServerRejection.from_stage(
            "status_runtime_boundary"
        )
        runtime = temporal.ContentFreeRuntimeRejection.from_stage(
            "trusted_time_boundary",
            request_nonce=nonce,
            error_category="trusted_time_unavailable",
        )
        response = {
            "content_free_rejection": server.projection(),
            "content_free_runtime_rejection": runtime.projection(),
            "error": {
                "code": server.error_code,
                "retryable": server.error_retryable,
            },
            "ok": False,
            "request_id": request_id,
            "schema": temporal.SCHEMA,
        }
        raw = json.dumps(response, separators=(",", ":"), sort_keys=True).encode(
            "ascii"
        )
        with self.assertRaises(temporal.TemporalGatewayRejected) as caught:
            temporal._read_response(
                raw,
                request_id=request_id,
                content_free_status=True,
                expected_status_nonce=nonce,
            )
        error = caught.exception
        self.assertEqual(error.status_stage, "server_status_runtime_rejection")
        self.assertEqual(error.status_runtime_rejection, runtime)
        self.assertEqual(
            error.status_rejection.runtime_rejection,
            runtime,
        )
        detailed = error.status_rejection.projection()
        parsed = temporal.parse_content_free_status_rejection(
            detailed,
            expected_invocation_nonce=nonce,
        )
        self.assertEqual(parsed.runtime_rejection, runtime)

        generic = temporal.content_free_status_rejection_projection(error)
        self.assertEqual(generic, error.status_rejection.legacy_projection())
        self.assertEqual(generic["schema"], temporal.STATUS_STAGE_SCHEMA)
        self.assertNotIn("runtime_rejection", generic)

    def test_status_runtime_subprojection_rejects_mixed_nonce_source_and_raw_data(self) -> None:
        request_id = "p08-stage-request-v1"
        nonce = "8" * 64
        server = temporal.ContentFreeServerRejection.from_stage(
            "status_runtime_boundary"
        )
        runtime = temporal.ContentFreeRuntimeRejection.from_stage(
            "store_state_boundary",
            request_nonce=nonce,
        )
        base = {
            "content_free_rejection": server.projection(),
            "content_free_runtime_rejection": runtime.projection(),
            "error": {
                "code": server.error_code,
                "retryable": server.error_retryable,
            },
            "ok": False,
            "request_id": request_id,
            "schema": temporal.SCHEMA,
        }
        mutations = (
            {**base, "content_free_runtime_rejection": {
                **runtime.projection(), "request_nonce": "7" * 64
            }},
            {**base, "content_free_runtime_rejection": {
                **runtime.projection(), "source_contract_identity": "0" * 64
            }},
            {**base, "content_free_runtime_rejection": {
                **runtime.projection(), "raw_cause": "PRIVATE/raw/cause"
            }},
            {**base, "content_free_runtime_rejection": {
                **runtime.projection(), "error_category": "trusted_time_unavailable"
            }},
        )
        for response in mutations:
            raw = json.dumps(
                response,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            with self.assertRaises(temporal.TemporalGatewayRejected) as caught:
                temporal._read_response(
                    raw,
                    request_id=request_id,
                    content_free_status=True,
                    expected_status_nonce=nonce,
                )
            self.assertEqual(caught.exception.status_stage, "response_projection")

        trusted = temporal.ContentFreeRuntimeRejection.from_stage(
            "trusted_time_boundary",
            request_nonce=nonce,
            error_category="trusted_time_persistence_ambiguous",
        )
        trusted_base = {
            **base,
            "content_free_runtime_rejection": trusted.projection(),
        }
        for projection in (
            {**trusted.projection(), "retryable": False},
            {**trusted.projection(), "provider_state_effect": "none"},
            {**trusted.projection(), "error_category": "trusted_time_unknown"},
            {**trusted.projection(), "projection_digest": "0" * 64},
        ):
            response = {
                **trusted_base,
                "content_free_runtime_rejection": projection,
            }
            raw = json.dumps(
                response,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            with self.assertRaises(temporal.TemporalGatewayRejected) as caught:
                temporal._read_response(
                    raw,
                    request_id=request_id,
                    content_free_status=True,
                    expected_status_nonce=nonce,
                )
            self.assertEqual(caught.exception.status_stage, "response_projection")

    def test_content_free_status_child_projects_fixed_stages_without_leakage(self) -> None:
        nonce = "c" * 64

        def invoke(**patches: object) -> tuple[int, dict[str, object], str]:
            output = io.StringIO()
            with (
                mock.patch.dict(
                    temporal.os.environ,
                    {temporal.STATUS_INVOCATION_NONCE_ENV: nonce},
                ),
                mock.patch.object(
                    temporal,
                    "enter_content_free_status_identity",
                    side_effect=patches.get("identity"),
                ),
                mock.patch.object(
                    temporal,
                    "load_protected_status_runtime_config",
                    side_effect=patches.get("config"),
                    return_value=object(),
                ),
                mock.patch.object(
                    temporal,
                    "query_content_free_status",
                    side_effect=patches.get("query"),
                ),
                mock.patch.object(temporal.sys, "stdout", output),
            ):
                result = temporal.main(["--content-free-status"])
            serialized = output.getvalue()
            return result, json.loads(serialized), serialized

        raw = "PRIVATE/path/token/value"
        cases = {
            "pre_socket_privilege_identity": {"identity": RuntimeError(raw)},
            "pre_socket_protected_config": {"config": RuntimeError(raw)},
            "transport_connect": {
                "query": temporal._status_stage_rejected(
                    "temporal_status_unavailable", "transport_connect"
                )
            },
            "response_projection": {"query": RuntimeError(raw)},
        }
        for expected_stage, patches in cases.items():
            with self.subTest(stage=expected_stage):
                result, projection, serialized = invoke(**patches)
                self.assertEqual(result, 1)
                self.assertEqual(projection["stage"], expected_stage)
                self.assertNotIn(raw, serialized)
                temporal.parse_content_free_status_rejection(
                    projection,
                    expected_invocation_nonce=nonce,
                )

        with (
            mock.patch.dict(temporal.os.environ, {}, clear=True),
            mock.patch.object(temporal.sys, "stdout", io.StringIO()),
        ):
            self.assertEqual(temporal.main(["--content-free-status"]), 2)

    def test_content_free_status_parent_maps_failures_once_and_preserves_generic_code(self) -> None:
        config = _runtime_config()
        nonce = "d" * 64
        timeout = temporal.subprocess.TimeoutExpired(["helper"], 15)
        cases = {
            "parent_timeout": {"side_effect": timeout},
            "parent_spawn": {"side_effect": OSError("raw-private-path")},
            "parent_empty": {
                "return_value": mock.Mock(returncode=1, stdout="", stderr="raw")
            },
            "parent_oversize": {
                "return_value": mock.Mock(
                    returncode=1,
                    stdout="x" * (temporal.MAX_STATUS_HELPER_OUTPUT_BYTES + 1),
                    stderr="raw",
                )
            },
            "parent_malformed": {
                "return_value": mock.Mock(
                    returncode=1, stdout="{malformed", stderr="raw-private"
                )
            },
        }
        for expected_stage, behavior in cases.items():
            with (
                self.subTest(stage=expected_stage),
                mock.patch.object(temporal.secrets, "token_hex", return_value=nonce),
                mock.patch.object(
                    temporal,
                    "content_free_status_pythonpath",
                    return_value=(Path("/core"), Path("/deploy")),
                ),
                mock.patch.object(temporal.subprocess, "run", **behavior) as run,
                self.assertRaises(temporal.TemporalGatewayRejected) as caught,
            ):
                temporal.run_content_free_status_helper(config)
            self.assertEqual(caught.exception.code, "temporal_status_unavailable")
            self.assertIs(caught.exception.retryable, True)
            self.assertEqual(caught.exception.status_stage, expected_stage)
            self.assertNotIn(
                "raw-private",
                json.dumps(
                    temporal.content_free_status_rejection_projection(
                        caught.exception
                    ),
                    sort_keys=True,
                ),
            )
            run.assert_called_once()

        child = temporal.ContentFreeStatusRejection.from_stage(
            "server_peer_auth_protocol_rejection",
            invocation_nonce=nonce,
        ).projection()
        completed = mock.Mock(
            returncode=1,
            stdout=json.dumps(child, separators=(",", ":"), sort_keys=True) + "\n",
            stderr="raw-private-server-response",
        )
        with (
            mock.patch.object(temporal.secrets, "token_hex", return_value=nonce),
            mock.patch.object(
                temporal,
                "content_free_status_pythonpath",
                return_value=(Path("/core"), Path("/deploy")),
            ),
            mock.patch.object(temporal.subprocess, "run", return_value=completed),
            self.assertRaises(temporal.TemporalGatewayRejected) as caught,
        ):
            temporal.run_content_free_status_helper(config)
        self.assertEqual(caught.exception.code, "temporal_status_unavailable")
        self.assertIs(caught.exception.retryable, True)
        self.assertEqual(
            caught.exception.status_stage,
            "server_peer_auth_protocol_rejection",
        )
        self.assertEqual(
            temporal.content_free_status_rejection_projection(caught.exception),
            child,
        )

    def test_content_free_status_transport_stages_are_deterministic(self) -> None:
        payload = {"request_id": "p08-stage-request-v1"}

        def invoke(fake: mock.MagicMock) -> temporal.TemporalGatewayRejected:
            context = mock.MagicMock()
            context.__enter__.return_value = fake
            with (
                mock.patch.object(temporal.socket, "socket", return_value=context),
                self.assertRaises(temporal.TemporalGatewayRejected) as caught,
            ):
                temporal.send_temporal_request(
                    payload,
                    content_free_status=True,
                )
            return caught.exception

        connect = mock.MagicMock()
        connect.connect.side_effect = OSError("private-socket-path")
        self.assertEqual(invoke(connect).status_stage, "transport_connect")

        timeout = mock.MagicMock()
        timeout.recv.side_effect = temporal.socket.timeout("private-timeout")
        self.assertEqual(invoke(timeout).status_stage, "transport_timeout")

        eof = mock.MagicMock()
        eof.recv.return_value = b""
        self.assertEqual(invoke(eof).status_stage, "transport_eof")

        malformed = mock.MagicMock()
        malformed.recv.return_value = b"{invalid\n"
        self.assertEqual(invoke(malformed).status_stage, "response_parse")

        rejected = mock.MagicMock()
        rejected.recv.return_value = (
            json.dumps(
                {
                    "error": {"code": "invalid_request", "retryable": False},
                    "ok": False,
                    "request_id": "p08-stage-request-v1",
                    "schema": temporal.SCHEMA,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )
        self.assertEqual(
            invoke(rejected).status_stage,
            "server_peer_auth_protocol_rejection",
        )

    def test_content_free_status_source_watermark_and_projection_stages_fail_closed(self) -> None:
        config = _runtime_config()
        nonce = "e" * 64
        request_id = f"p08-status-{nonce[:32]}"
        scope_digest = temporal.content_free_scope_digest(
            binding_id=config.binding_id,
            principal_id=config.principal_id,
            namespace_id=config.namespace_id,
            channel_kind=config.channel_kind,
            channel_instance=config.channel_instance,
        )
        response = _status_response(
            request_id=request_id,
            request_nonce=nonce,
            scope_digest=scope_digest,
        )
        response["output"]["source_identity"] = "0" * 64
        with (
            mock.patch.object(temporal.secrets, "token_hex", return_value=nonce),
            mock.patch.object(
                temporal,
                "send_temporal_request",
                return_value=response,
            ),
            self.assertRaises(temporal.TemporalGatewayRejected) as caught,
        ):
            temporal.query_content_free_status(config)
        self.assertEqual(
            caught.exception.status_stage,
            "response_schema_source_watermark",
        )

        projection = _status_response(
            request_id=request_id,
            request_nonce=nonce,
            scope_digest=scope_digest,
        )["output"]
        projection["active_set_digest"] = "0" * 64
        with self.assertRaises(temporal.TemporalGatewayRejected) as caught:
            temporal.parse_content_free_status_projection(
                projection,
                expected_scope_digest=scope_digest,
            )
        self.assertEqual(caught.exception.status_stage, "response_projection")

    def test_status_runtime_config_is_self_contained_and_exact(self) -> None:
        status_config = temporal.StatusRuntimeConfig.from_payload(_runtime_payload())
        source_config = _runtime_config()
        self.assertEqual(
            temporal._coerce_status_runtime_config(source_config),
            status_config,
        )
        with self.assertRaises(temporal.TemporalGatewayRejected):
            temporal._coerce_status_runtime_config(object())
        for field, value in (
            ("channel_kind", "qq"),
            ("core_host", "0.0.0.0"),
            ("core_port", True),
            ("max_history_messages", 127),
            ("max_history_characters", 3999),
        ):
            payload = _runtime_payload()
            payload[field] = value
            with self.assertRaises(temporal.TemporalGatewayRejected):
                temporal.StatusRuntimeConfig.from_payload(payload)

    def test_protected_status_runtime_config_rejects_permission_and_duplicate_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.json"
            path.write_text(
                json.dumps(_runtime_payload(), separators=(",", ":"), sort_keys=True),
                encoding="utf-8",
            )
            path.chmod(0o640)
            metadata = path.stat()
            parsed = temporal.parse_protected_status_runtime_config(
                path,
                expected_uid=metadata.st_uid,
                expected_gid=metadata.st_gid,
            )
            self.assertEqual(parsed.binding_id, "binding-owner-v1")

            path.chmod(0o600)
            with self.assertRaises(temporal.TemporalGatewayRejected):
                temporal.parse_protected_status_runtime_config(
                    path,
                    expected_uid=metadata.st_uid,
                    expected_gid=metadata.st_gid,
                )
            path.chmod(0o640)
            path.write_text(
                '{"binding_id":"first","binding_id":"second"}',
                encoding="utf-8",
            )
            with self.assertRaises(temporal.TemporalGatewayRejected):
                temporal.parse_protected_status_runtime_config(
                    path,
                    expected_uid=os.geteuid(),
                    expected_gid=os.getegid(),
                )

    def test_active_snapshot_request_and_response_are_exact(self) -> None:
        request = temporal.build_active_snapshot_request(
            authenticated_context=_context("gateway-active-v1"),
            request_id="gateway-active-v1",
        )
        self.assertEqual(request["operation"], "snapshot_active")
        self.assertEqual(request["input"], {"after_event_sequence": 0})
        response = _active_response()
        parsed = temporal.parse_active_snapshot_response(
            response,
            request_id="gateway-active-v1",
            after_event_sequence=0,
        )
        self.assertEqual(parsed.fact_count, 0)
        self.assertEqual(parsed.lifecycle_watermark, 0)
        self.assertFalse(parsed.lifecycle_has_more)
        self.assertTrue(parsed.trusted_time.evidence_complete)
        self.assertIsNotNone(parsed.active_snapshot_receipt)

    def test_active_snapshot_receipt_rejects_request_cursor_and_payload_substitution(
        self,
    ) -> None:
        response = _active_response()
        cases = []
        wrong_request = json.loads(json.dumps(response))
        wrong_request["request_id"] = "gateway-active-substituted"
        cases.append(("request", wrong_request, "gateway-active-v1", 0))
        changed_time = json.loads(json.dumps(response))
        changed_time["output"]["trusted_time"]["sequence"] = 8
        cases.append(("trusted_time", changed_time, "gateway-active-v1", 0))
        changed_count = json.loads(json.dumps(response))
        changed_count["output"]["fact_count"] = 1
        cases.append(("fact_count", changed_count, "gateway-active-v1", 0))
        for name, payload, request_id, cursor in cases:
            with self.subTest(name=name), self.assertRaises(
                temporal.TemporalGatewayRejected
            ):
                temporal.parse_active_snapshot_response(
                    payload,
                    request_id=request_id,
                    after_event_sequence=cursor,
                )
        with self.assertRaises(temporal.TemporalGatewayRejected):
            temporal.parse_active_snapshot_response(
                response,
                request_id="gateway-active-v1",
                after_event_sequence=1,
            )
        transition = {
            "category": "temporary_plan",
            "event_kind": "confirm",
            "event_sequence": 1,
            "expires_at": "2026-08-11T12:00:00.000000+00:00",
            "fact_id": "tf_synthetic_1",
            "occurred_at": "2026-08-08T12:00:00.000000+00:00",
            "reason": "owner_confirmed",
            "revision": 1,
            "slot_key": "synthetic-plan",
            "source_kind": "owner_confirmation",
            "source_ref": "telegram-event-1",
            "state": "active",
            "supersedes_fact_id": None,
            "transition": "proposed->active",
            "trusted_time_source_class": "trusted_local",
            "valid_from": "2026-08-08T12:00:00.000000+00:00",
            "valid_to": "2026-08-11T12:00:00.000000+00:00",
        }
        lifecycle = _active_response(
            transitions=[transition],
            lifecycle_watermark=1,
        )
        accepted = temporal.parse_active_snapshot_response(
            lifecycle,
            request_id="gateway-active-v1",
            after_event_sequence=0,
        )
        self.assertEqual(accepted.lifecycle_transitions[0]["revision"], 1)
        changed_lifecycle = json.loads(json.dumps(lifecycle))
        changed_lifecycle["output"]["lifecycle_transitions"][0]["revision"] = 999
        with self.assertRaises(temporal.TemporalGatewayRejected):
            temporal.parse_active_snapshot_response(
                changed_lifecycle,
                request_id="gateway-active-v1",
                after_event_sequence=0,
            )

    def test_active_snapshot_rejects_partial_time_or_temporal_projection(self) -> None:
        base = _active_response()
        for mutate in ("missing_time_evidence", "bad_digest", "oversized_context"):
            payload = json.loads(json.dumps(base))
            if mutate == "missing_time_evidence":
                del payload["output"]["trusted_time"]["boot_id"]
            elif mutate == "bad_digest":
                payload["output"]["projection_digest"] = "not-a-digest"
            else:
                payload["output"]["context"] = "x" * 12_001
            with self.subTest(mutate=mutate), self.assertRaises(
                temporal.TemporalGatewayRejected
            ):
                temporal.parse_active_snapshot_response(
                    payload,
                    request_id="gateway-active-v1",
                    after_event_sequence=0,
                )

    def test_unavailable_snapshot_is_typed_and_contains_no_claimed_fact(self) -> None:
        snapshot = temporal.unresolved_active_snapshot("trusted_time_unavailable")
        self.assertEqual(snapshot.coverage_state, "unavailable")
        self.assertEqual(snapshot.fact_count, 0)
        self.assertIsNone(snapshot.trusted_time)
        self.assertIn("coverage=unavailable", snapshot.context)
        with self.assertRaises(temporal.TemporalGatewayRejected):
            temporal.unresolved_active_snapshot("unsafe reason")

    def test_parser_and_plugin_admission_are_explicit(self) -> None:
        plugin = _load_plugin_protocol()
        accepted = (
            "/temporal get 当前任务",
            "/temporal add current_task current 3 '准备离开服务器'",
            "/temporal revoke tf_0123456789abcdef0123456789abcdef",
            "/temporal confirm tp_0123456789abcdef0123456789abcdef ABCDEF123456",
        )
        for value in accepted:
            with self.subTest(value=value):
                self.assertIsNotNone(temporal.parse_temporal_command(value))
                self.assertTrue(plugin.temporal_command_is_explicit(value))
                self.assertTrue(
                    plugin.should_forward_private_plain_text(
                        sender_id="123456789",
                        is_private_chat=True,
                        has_plain_text_only=True,
                        sender_is_bot=False,
                        message_text=value,
                    )
                )
        for value in ("temporal get x", "/status", "/temporal\nget x"):
            with self.subTest(value=value):
                self.assertIsNone(temporal.parse_temporal_command(value))

    def test_write_consent_is_narrow(self) -> None:
        self.assertFalse(
            temporal.temporal_intent_grants_candidate_consent(
                "/temporal get 当前任务"
            )
        )
        self.assertTrue(
            temporal.temporal_intent_grants_candidate_consent(
                "/temporal add current_task current 3 内容"
            )
        )
        self.assertFalse(temporal.temporal_intent_grants_candidate_consent("ordinary"))

    def test_create_request_is_protocol_exact(self) -> None:
        command = temporal.parse_temporal_command(
            "/temporal add current_task current 3 '准备离开服务器'"
        )
        assert command is not None
        payload = temporal.build_request(
            command,
            authenticated_context=_context("gateway-request-v1"),
            request_id="gateway-request-v1",
            event_id="evt-owner-v1",
            occurred_at=datetime(2026, 8, 5, 12, tzinfo=timezone.utc),
        )
        self.assertEqual(payload["schema"], temporal.SCHEMA)
        self.assertEqual(payload["operation"], "propose")
        draft = payload["input"]["draft"]
        self.assertEqual(draft["source_kind"], "owner_statement")
        self.assertEqual(draft["source_ref"], "evt-owner-v1")
        self.assertEqual(draft["expires_at"], "2026-08-08T12:00:00.000000+00:00")
        self.assertTrue(payload["input"]["explicit_intent"])

    def test_invalid_category_duration_and_identifier_fail_closed(self) -> None:
        values = (
            "/temporal add stable_profile slot 3 text",
            "/temporal add current_task slot 0 text",
            "/temporal add current_task 'bad slot' 3 text",
        )
        for value in values:
            command = temporal.parse_temporal_command(value)
            assert command is not None
            with self.subTest(value=value), self.assertRaises(
                temporal.TemporalGatewayRejected
            ):
                temporal.build_request(
                    command,
                    authenticated_context=_context("gateway-request-v1"),
                    request_id="gateway-request-v1",
                    event_id="evt-owner-v1",
                    occurred_at=datetime.now(timezone.utc),
                )

    def test_response_requires_no_other_store_or_model_effects(self) -> None:
        raw = json.dumps(
            {
                "schema": temporal.SCHEMA,
                "operation": "retrieve",
                "ok": True,
                "request_id": "gateway-request-v1",
                "output": {
                    "state": "empty",
                    "query_characters": 2,
                    "context": None,
                    "fact_count": 0,
                },
                "model_called": False,
                "profile_written": False,
                "session_written": False,
                "legacy_namespace_written": False,
            },
            separators=(",", ":"),
        ).encode()
        response = temporal._read_response(raw, request_id="gateway-request-v1")
        command = temporal.parse_temporal_command("/temporal get 当前")
        assert command is not None
        self.assertEqual(
            temporal.render_temporal_reply(command, response),
            "目前没有找到相关的临时信息。",
        )
        mutated = json.loads(raw)
        mutated["profile_written"] = True
        with self.assertRaises(temporal.TemporalGatewayRejected):
            temporal._read_response(
                json.dumps(mutated).encode(), request_id="gateway-request-v1"
            )

    def test_transport_is_af_unix_bounded(self) -> None:
        payload = {
            "schema": temporal.SCHEMA,
            "boundary": temporal.BOUNDARY,
            "operation": "retrieve",
            "request_id": "gateway-request-v1",
            "authenticated_context": _context("gateway-request-v1"),
            "input": {"query": "x", "categories": [], "slot_keys": []},
        }
        fake = mock.MagicMock()
        fake.recv.side_effect = [
            json.dumps(
                {
                    "schema": temporal.SCHEMA,
                    "operation": "retrieve",
                    "ok": True,
                    "request_id": "gateway-request-v1",
                    "output": {
                        "state": "empty",
                        "query_characters": 1,
                        "context": None,
                        "fact_count": 0,
                    },
                    "model_called": False,
                    "profile_written": False,
                    "session_written": False,
                    "legacy_namespace_written": False,
                },
                separators=(",", ":"),
            ).encode()
            + b"\n"
        ]
        context = mock.MagicMock()
        context.__enter__.return_value = fake
        with mock.patch.object(temporal.socket, "socket", return_value=context) as create:
            response = temporal.send_temporal_request(payload)
        create.assert_called_once_with(temporal.socket.AF_UNIX, temporal.socket.SOCK_STREAM)
        fake.connect.assert_called_once_with(temporal.SOCKET_PATH)
        self.assertTrue(response["ok"])

    def test_unavailable_reply_is_fixed_and_temporal_specific(self) -> None:
        self.assertEqual(
            temporal.unavailable_reply(),
            "临时信息服务现在不可用；这次没有读取或写入临时信息，请稍后再试",
        )


class GatewayWiringTests(unittest.TestCase):
    def test_gateway_routes_temporal_before_core_chat(self) -> None:
        source = (SCRIPTS / "telegram_owner_runtime_gateway.py").read_text("utf-8")
        temporal_index = source.index("temporal_command = parse_temporal_command")
        core_index = source.index("core_reply = core.chat", temporal_index)
        self.assertLess(temporal_index, core_index)
        self.assertIn("owner_runtime_temporal_replied", source)
        self.assertIn("gateway-temporal-unavailable", source)
        self.assertIn("temporal_unavailable_reply", source)
        self.assertIn("temporal_intent_grants_candidate_consent", source)

    def test_p16_maps_temporal_service_failures(self) -> None:
        source = (SCRIPTS / "user_visible_fault_v1.py").read_text("utf-8")
        for code in (
            "temporal_context_unavailable",
            "temporal_service_inactive",
            "temporal_socket_inactive",
        ):
            self.assertIn(f'"{code}": "MYU-TEMPORAL-01"', source)


if __name__ == "__main__":
    unittest.main()
