"""P08 service entrypoint with a content-free rejection subprojection.

The Core protocol and runtime remain authoritative.  This Deploy-owned entrypoint
only separates three server-side failure boundaries for the authenticated
``status_content_free`` diagnostic path.  Ordinary protocol operations retain
the Core process_request behavior, and no raw exception or request value is
placed on the wire.
"""

from __future__ import annotations

from hashlib import sha256
import json
import re
import socket
from typing import Mapping

from myuna_core.active_temporal_context import service as core_service
from myuna_core.active_temporal_context.contracts import TemporalContextError
from myuna_core.active_temporal_context.protocol import (
    MAX_RESPONSE_BYTES,
    TemporalProtocolError,
    error_response,
    execute_request,
    parse_request_bytes,
    process_request,
)
from myuna_core.active_temporal_context.runtime import ActiveTemporalContextRuntime
from myuna_core.active_temporal_context.store import TemporalContextStore
from myuna_core.trusted_time import (
    DurableTrustedTimeProvider,
    LinuxAdjtimexSynchronizationProbe,
    SystemUtcObservationSource,
    TrustedTimeCapability,
    TrustedTimeWatermark,
)


SERVER_REJECTION_SCHEMA = "myuna.p08-server-rejection-subprojection.v1"
SERVER_REJECTION_SOURCE_DOMAIN = "myuna-p08-server-rejection-subprojection-v1"
STATUS_RUNTIME_REJECTION_SCHEMA = "myuna.p08-status-runtime-subprojection.v2"
STATUS_RUNTIME_REJECTION_SOURCE_DOMAIN = "myuna-p08-status-runtime-subprojection-v2"

# stage -> (category, retryable, protocol error code, protocol retryable)
_SERVER_REJECTION_POLICY: dict[str, tuple[str, bool, str, bool]] = {
    "service_peer_boundary": (
        "peer_rejected",
        False,
        "temporal_unavailable",
        True,
    ),
    "authenticated_context_protocol_boundary": (
        "protocol_rejected",
        False,
        "invalid_request",
        False,
    ),
    "status_runtime_boundary": (
        "runtime_unavailable",
        False,
        "temporal_unavailable",
        True,
    ),
}

# This projection is deliberately coarser than the underlying fixed error codes.
# It identifies the source-owned runtime boundary without exposing raw exception
# text, paths, state, temporal facts, or credentials.  Every substage remains
# non-retryable: the caller must preserve the one-shot activation result.
_STATUS_RUNTIME_REJECTION_POLICY: dict[str, tuple[str, bool]] = {
    "trusted_time_boundary": ("trusted_time_rejected", False),
    "store_state_boundary": ("store_state_rejected", False),
    "status_projection_boundary": ("status_projection_rejected", False),
    "response_encoding_boundary": ("response_encoding_rejected", False),
    "status_runtime_unknown_boundary": ("runtime_unknown_rejected", False),
}

# Exact P10-B error code -> (retryable, provider state effect).  This is a
# source-owned allowlist, not a caller declaration.  Audit failure is marked
# ambiguous because the fixed error alone cannot prove whether an accepted
# sample was already committed before audit projection failed.
_TRUSTED_TIME_REJECTION_POLICY: dict[str, tuple[bool, str]] = {
    "trusted_time_permission_denied": (False, "none"),
    "trusted_time_unavailable": (True, "none"),
    "trusted_time_timeout": (True, "none"),
    "trusted_time_unsynchronized": (True, "none"),
    "trusted_time_uncertainty_exceeded": (True, "none"),
    "trusted_time_regression": (False, "none"),
    "trusted_time_drift_exceeded": (True, "none"),
    "trusted_time_source_drift": (False, "none"),
    "trusted_time_state_corrupt": (False, "none"),
    "trusted_time_state_permission_drift": (False, "none"),
    "trusted_time_persistence_ambiguous": (True, "ambiguous"),
    "trusted_time_audit_unavailable": (True, "ambiguous"),
    "trusted_time_sequence_exhausted": (False, "none"),
}


def _canonical(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        dict(payload),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


SERVER_REJECTION_SOURCE_IDENTITY = sha256(
    SERVER_REJECTION_SOURCE_DOMAIN.encode("ascii")
    + b"\0"
    + _canonical(
        {
            "schema": SERVER_REJECTION_SCHEMA,
            "stage_policy": {
                stage: {
                    "category": policy[0],
                    "error_code": policy[2],
                    "error_retryable": policy[3],
                    "retryable": policy[1],
                }
                for stage, policy in _SERVER_REJECTION_POLICY.items()
            },
        }
    )
).hexdigest()
STATUS_RUNTIME_REJECTION_SOURCE_IDENTITY = sha256(
    STATUS_RUNTIME_REJECTION_SOURCE_DOMAIN.encode("ascii")
    + b"\0"
    + _canonical(
        {
            "schema": STATUS_RUNTIME_REJECTION_SCHEMA,
            "stage_policy": {
                stage: {"category": policy[0], "retryable": policy[1]}
                for stage, policy in _STATUS_RUNTIME_REJECTION_POLICY.items()
            },
            "trusted_time_policy": {
                category: {
                    "provider_state_effect": policy[1],
                    "retryable": policy[0],
                }
                for category, policy in _TRUSTED_TIME_REJECTION_POLICY.items()
            },
        }
    )
).hexdigest()


def status_runtime_rejection_projection(
    stage: str,
    *,
    request_nonce: str,
    error_category: str | None = None,
) -> dict[str, object]:
    policy = _STATUS_RUNTIME_REJECTION_POLICY.get(stage)
    if policy is None or re.fullmatch(r"[0-9a-f]{64}", request_nonce) is None:
        raise ValueError("status_runtime_rejection_stage_rejected")
    if stage == "trusted_time_boundary":
        trusted_policy = _TRUSTED_TIME_REJECTION_POLICY.get(error_category or "")
        if trusted_policy is None:
            raise ValueError("status_runtime_rejection_category_rejected")
        retryable, provider_state_effect = trusted_policy
        projected_error_category = error_category
    else:
        if error_category is not None:
            raise ValueError("status_runtime_rejection_category_rejected")
        retryable = policy[1]
        provider_state_effect = "none"
        projected_error_category = policy[0]
    stable: dict[str, object] = {
        "category": policy[0],
        "error_category": projected_error_category,
        "persistent_mutation": False,
        "private_content_included": False,
        "provider_state_effect": provider_state_effect,
        "raw_cause_included": False,
        "request_nonce": request_nonce,
        "retryable": retryable,
        "schema": STATUS_RUNTIME_REJECTION_SCHEMA,
        "source_contract_identity": STATUS_RUNTIME_REJECTION_SOURCE_IDENTITY,
        "stage": stage,
    }
    return {
        **stable,
        "projection_digest": sha256(
            b"myuna-p08-status-runtime-rejection-projection-v2\0"
            + _canonical(stable)
        ).hexdigest(),
    }


def parse_status_runtime_rejection_projection(
    payload: object,
    *,
    expected_request_nonce: str,
) -> tuple[str, str, bool, str]:
    if not isinstance(payload, Mapping) or set(payload) != {
        "category",
        "error_category",
        "persistent_mutation",
        "private_content_included",
        "provider_state_effect",
        "projection_digest",
        "raw_cause_included",
        "request_nonce",
        "retryable",
        "schema",
        "source_contract_identity",
        "stage",
    }:
        raise ValueError("status_runtime_rejection_projection_rejected")
    stage = payload.get("stage")
    if not isinstance(stage, str):
        raise ValueError("status_runtime_rejection_projection_rejected")
    expected = status_runtime_rejection_projection(
        stage,
        request_nonce=expected_request_nonce,
        error_category=(
            payload.get("error_category")
            if stage == "trusted_time_boundary"
            and isinstance(payload.get("error_category"), str)
            else None
        ),
    )
    if any(
        type(payload.get(key)) is not type(value) or payload.get(key) != value
        for key, value in expected.items()
    ):
        raise ValueError("status_runtime_rejection_projection_rejected")
    return (
        stage,
        str(expected["error_category"]),
        bool(expected["retryable"]),
        str(expected["provider_state_effect"]),
    )


def _status_runtime_stage(error: object) -> tuple[str, str | None]:
    code = getattr(error, "code", "")
    if isinstance(code, str) and code in _TRUSTED_TIME_REJECTION_POLICY:
        expected_retryable = _TRUSTED_TIME_REJECTION_POLICY[code][0]
        if type(getattr(error, "retryable", None)) is bool and (
            getattr(error, "retryable") is expected_retryable
        ):
            return "trusted_time_boundary", code
        return "status_runtime_unknown_boundary", None
    if isinstance(code, str) and (
        code.startswith("database_")
        or code.startswith("schema_")
        or code == "read_scope_rejected"
    ):
        return "store_state_boundary", None
    if isinstance(error, TemporalProtocolError) and code in {
        "status_lifecycle_stale",
        "status_scope_mismatch",
    }:
        return "status_projection_boundary", None
    return "status_runtime_unknown_boundary", None


def server_rejection_projection(stage: str) -> dict[str, object]:
    policy = _SERVER_REJECTION_POLICY.get(stage)
    if policy is None:
        raise ValueError("server_rejection_stage_rejected")
    stable: dict[str, object] = {
        "category": policy[0],
        "persistent_mutation": False,
        "private_content_included": False,
        "raw_cause_included": False,
        "retryable": policy[1],
        "schema": SERVER_REJECTION_SCHEMA,
        "source_contract_identity": SERVER_REJECTION_SOURCE_IDENTITY,
        "stage": stage,
    }
    return {
        **stable,
        "projection_digest": sha256(
            b"myuna-p08-server-rejection-projection-v1\0" + _canonical(stable)
        ).hexdigest(),
    }


def parse_server_rejection_projection(payload: object) -> tuple[str, str, bool]:
    if not isinstance(payload, Mapping) or set(payload) != {
        "category",
        "persistent_mutation",
        "private_content_included",
        "projection_digest",
        "raw_cause_included",
        "retryable",
        "schema",
        "source_contract_identity",
        "stage",
    }:
        raise ValueError("server_rejection_projection_rejected")
    stage = payload.get("stage")
    if not isinstance(stage, str):
        raise ValueError("server_rejection_projection_rejected")
    expected = server_rejection_projection(stage)
    if any(
        type(payload.get(key)) is not type(value) or payload.get(key) != value
        for key, value in expected.items()
    ):
        raise ValueError("server_rejection_projection_rejected")
    policy = _SERVER_REJECTION_POLICY[stage]
    return stage, policy[2], policy[3]


def _server_rejection_response(
    stage: str,
    *,
    request_id: str | None = None,
    runtime_stage: str | None = None,
    runtime_error_category: str | None = None,
    request_nonce: str | None = None,
) -> bytes:
    policy = _SERVER_REJECTION_POLICY.get(stage)
    if policy is None:
        raise ValueError("server_rejection_stage_rejected")
    response = error_response(
        request_id,
        TemporalProtocolError(policy[2], retryable=policy[3]),
    )
    response["content_free_rejection"] = server_rejection_projection(stage)
    if runtime_stage is not None:
        if stage != "status_runtime_boundary" or not isinstance(request_nonce, str):
            raise ValueError("status_runtime_rejection_mixed")
        response["content_free_runtime_rejection"] = (
            status_runtime_rejection_projection(
                runtime_stage,
                request_nonce=request_nonce,
                error_category=runtime_error_category,
            )
        )
    return _canonical(response)


def _encode_status_response(
    response: Mapping[str, object],
    *,
    request_id: str,
    request_nonce: str,
) -> bytes:
    encoded = json.dumps(
        dict(response),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > MAX_RESPONSE_BYTES:
        return _server_rejection_response(
            "status_runtime_boundary",
            request_id=request_id,
            runtime_stage="response_encoding_boundary",
            request_nonce=request_nonce,
        )
    return encoded


def serve_connection(
    connection: socket.socket,
    runtime: ActiveTemporalContextRuntime,
    *,
    expected_peer_uid: int,
) -> None:
    connection.settimeout(core_service.MAX_CONNECTION_SECONDS)
    request_id: str | None = None
    try:
        try:
            if core_service._peer_uid(connection) != expected_peer_uid:
                raise RuntimeError("peer_identity_rejected")
            raw = core_service.read_one_request(connection)
        except (OSError, RuntimeError, TimeoutError):
            response = _server_rejection_response("service_peer_boundary")
        else:
            try:
                request_id, operation, context, payload = parse_request_bytes(
                    raw,
                    authenticated_client_id=core_service.CLIENT_ID,
                    authenticated_channel_kind=core_service.CHANNEL_KIND,
                )
            except Exception:
                response = _server_rejection_response(
                    "authenticated_context_protocol_boundary"
                )
            else:
                if operation != "status_content_free":
                    response = process_request(
                        raw,
                        runtime,
                        authenticated_client_id=core_service.CLIENT_ID,
                        authenticated_channel_kind=core_service.CHANNEL_KIND,
                    )
                else:
                    request_nonce = payload.get("request_nonce")
                    try:
                        status = execute_request(
                            runtime,
                            operation=operation,
                            request_id=request_id,
                            context=context,
                            payload=payload,
                        )
                    except TemporalProtocolError as error:
                        stage = (
                            "authenticated_context_protocol_boundary"
                            if error.code == "invalid_request"
                            else "status_runtime_boundary"
                        )
                        runtime_stage, runtime_error_category = (
                            _status_runtime_stage(error)
                            if stage == "status_runtime_boundary"
                            else (None, None)
                        )
                        response = _server_rejection_response(
                            stage,
                            request_id=request_id,
                            runtime_stage=(
                                runtime_stage
                                if isinstance(request_nonce, str)
                                and re.fullmatch(r"[0-9a-f]{64}", request_nonce)
                                else None
                            ),
                            request_nonce=(
                                request_nonce
                                if isinstance(request_nonce, str)
                                and re.fullmatch(r"[0-9a-f]{64}", request_nonce)
                                else None
                            ),
                            runtime_error_category=runtime_error_category,
                        )
                    except TemporalContextError as error:
                        runtime_stage, runtime_error_category = (
                            _status_runtime_stage(error)
                        )
                        response = _server_rejection_response(
                            "status_runtime_boundary",
                            request_id=request_id,
                            runtime_stage=(
                                runtime_stage
                                if isinstance(request_nonce, str)
                                and re.fullmatch(r"[0-9a-f]{64}", request_nonce)
                                else None
                            ),
                            request_nonce=(
                                request_nonce
                                if isinstance(request_nonce, str)
                                and re.fullmatch(r"[0-9a-f]{64}", request_nonce)
                                else None
                            ),
                            runtime_error_category=runtime_error_category,
                        )
                    except Exception:
                        response = _server_rejection_response(
                            "status_runtime_boundary",
                            request_id=request_id,
                            runtime_stage=(
                                "status_runtime_unknown_boundary"
                                if isinstance(request_nonce, str)
                                and re.fullmatch(r"[0-9a-f]{64}", request_nonce)
                                else None
                            ),
                            request_nonce=(
                                request_nonce
                                if isinstance(request_nonce, str)
                                and re.fullmatch(r"[0-9a-f]{64}", request_nonce)
                                else None
                            ),
                        )
                    else:
                        response = _encode_status_response(
                            status,
                            request_id=request_id,
                            request_nonce=request_nonce,
                        )
        connection.sendall(response)
    except OSError:
        return


# Preserve the existing initialization and socket helpers.  Runtime composition
# is Deploy-owned so the installed release must exercise the source-owned
# capability lifecycle instead of injecting the durable provider directly.
initialize_state = core_service.initialize_state
inherited_systemd_socket = core_service.inherited_systemd_socket


def _stop_trusted_time_capability(capability: TrustedTimeCapability) -> None:
    snapshot = capability.lifecycle_snapshot()
    if snapshot.state.value != "stopped":
        snapshot = capability.shutdown()
    if snapshot.state.value != "stopped" or snapshot.accepting_requests:
        raise RuntimeError("trusted_time_capability_stop_rejected")


def build_runtime_from_environment(
    environ: Mapping[str, str] | None = None,
) -> ActiveTemporalContextRuntime:
    source = core_service.os.environ if environ is None else environ
    expected_uid = core_service._positive_int(source, "MYUNA_P08_SERVICE_UID")
    if core_service.os.geteuid() != expected_uid:
        raise RuntimeError("service_identity_rejected")
    root = core_service._state_root(source, expected_uid=expected_uid)
    store = TemporalContextStore(
        root / core_service.TEMPORAL_DATABASE_NAME,
        expected_uid=expected_uid,
    )
    watermark = store.trusted_time_watermark()
    provider_watermark = (
        None
        if watermark is None
        else TrustedTimeWatermark(
            source=watermark[0],
            sequence=watermark[1],
            instant=watermark[2],
        )
    )
    provider = DurableTrustedTimeProvider(
        root / core_service.TRUSTED_TIME_DATABASE_NAME,
        SystemUtcObservationSource(LinuxAdjtimexSynchronizationProbe()),
        consumer_watermark=provider_watermark,
        expected_uid=expected_uid,
    )
    capability = TrustedTimeCapability(provider)
    try:
        snapshot = capability.startup()
        if not snapshot.accepting_requests or snapshot.state.value != "ready":
            raise RuntimeError("trusted_time_capability_not_ready")
    except Exception:
        _stop_trusted_time_capability(capability)
        raise RuntimeError("trusted_time_capability_startup_rejected") from None
    return ActiveTemporalContextRuntime(store, capability)


def serve_systemd_socket() -> None:
    if core_service.os.geteuid() == 0:
        raise RuntimeError("refusing_to_run_as_root")
    peer_uid = core_service._positive_int(
        core_service.os.environ,
        "MYUNA_P08_TELEGRAM_UID",
    )
    runtime = build_runtime_from_environment()
    capability = runtime.trusted_time
    if not isinstance(capability, TrustedTimeCapability):
        raise RuntimeError("trusted_time_capability_binding_rejected")
    try:
        with inherited_systemd_socket() as server:
            while True:
                connection, _ = server.accept()
                with connection:
                    serve_connection(
                        connection,
                        runtime,
                        expected_peer_uid=peer_uid,
                    )
                if not capability.lifecycle_snapshot().accepting_requests:
                    _stop_trusted_time_capability(capability)
                    raise RuntimeError("trusted_time_capability_not_ready")
    finally:
        _stop_trusted_time_capability(capability)


def main() -> int:
    serve_systemd_socket()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
