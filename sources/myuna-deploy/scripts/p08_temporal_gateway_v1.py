"""Strict Telegram Owner-private client for the P08 temporal service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import grp
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shlex
import socket
import stat
import subprocess
import sys
from typing import Mapping

import myuna_core.active_temporal_context.protocol as temporal_protocol_contract
from myuna_core.active_temporal_context.protocol import (
    ActiveSnapshotReceipt,
    CONTENT_FREE_STATUS_SCHEMA,
    CONTENT_FREE_STATUS_SOURCE_IDENTITY,
    MAX_EVENTS,
    MAX_FACTS,
    MAX_PENDING_PROPOSALS,
)
from myuna_core.active_temporal_context.time import TrustedTimeSample
from myuna_core.authenticated_conversation import AuthenticatedConversationContext

SCHEMA = "myuna.active-temporal-context-protocol.v1"
BOUNDARY = "authenticated_telegram_owner_private_temporal_context"
SOCKET_PATH = "/run/myuna-active-temporal-context-v1/temporal.sock"
MAX_WIRE_BYTES = 16_384
MAX_REPLY_CHARACTERS = 4_000
MAX_STATUS_FACTS = MAX_FACTS
MAX_STATUS_EVENTS = MAX_EVENTS
MAX_STATUS_PENDING_PROPOSALS = MAX_PENDING_PROPOSALS
STATUS_RUNTIME_USER = "myuna-gateway-telegram"
STATUS_CLIENT_ID = "telegram-owner-runtime-v1"
STATUS_CONVERSATION_ID = "owner-private-lifecycle-status-v1"
STATUS_OPERATION = "status_content_free"
STATUS_RUNTIME_CONFIG_PATH = Path(
    "/etc/myuna-telegram-gateway/owner-runtime-v1.json"
)
STATUS_RUNTIME_GROUP = "myuna-gateway-telegram"
STATUS_CHANNEL_KIND = "astrbot_telegram"
MAX_STATUS_RUNTIME_CONFIG_BYTES = 8192
MAX_STATUS_HELPER_OUTPUT_BYTES = 8192
STATUS_STAGE_SCHEMA = "myuna.p08-content-free-status-stage.v1"
SERVER_REJECTION_SCHEMA = "myuna.p08-server-rejection-subprojection.v1"
SERVER_REJECTION_SOURCE_DOMAIN = "myuna-p08-server-rejection-subprojection-v1"
STATUS_RUNTIME_REJECTION_SCHEMA = "myuna.p08-status-runtime-subprojection.v2"
STATUS_RUNTIME_REJECTION_SOURCE_DOMAIN = "myuna-p08-status-runtime-subprojection-v2"
STATUS_RUNTIME_STAGE_SCHEMA = "myuna.p08-content-free-status-runtime-stage.v1"
STATUS_INVOCATION_NONCE_ENV = "MYUNA_P08_STATUS_INVOCATION_NONCE"
MIN_HISTORY_MESSAGES = 2
MAX_HISTORY_MESSAGES = 256
MIN_HISTORY_CHARACTERS = 4_000
MAX_HISTORY_CHARACTERS = 262_144

_STATUS_STAGE_POLICY: dict[str, tuple[str, bool]] = {
    "pre_socket_source_identity": ("source_identity_rejected", False),
    "pre_socket_privilege_identity": ("privilege_identity_rejected", False),
    "pre_socket_protected_config": ("protected_config_rejected", False),
    "transport_connect": ("transport_unavailable", True),
    "transport_timeout": ("transport_timeout", True),
    "transport_eof": ("transport_eof", True),
    "transport_io": ("transport_unavailable", True),
    "transport_oversize": ("transport_rejected", True),
    "server_peer_auth_protocol_rejection": ("server_rejected", False),
    "server_service_peer_rejection": ("server_peer_rejected", False),
    "server_authenticated_context_protocol_rejection": (
        "server_protocol_rejected",
        False,
    ),
    "server_status_runtime_rejection": ("server_runtime_rejected", False),
    "response_parse": ("response_malformed", False),
    "response_projection": ("projection_rejected", False),
    "response_schema_source_watermark": ("source_contract_rejected", False),
    "parent_spawn": ("parent_unavailable", True),
    "parent_timeout": ("parent_timeout", True),
    "parent_empty": ("parent_empty", True),
    "parent_oversize": ("parent_oversize", False),
    "parent_malformed": ("parent_malformed", False),
}

# Must remain byte-for-byte semantically equal to the Deploy-owned P08 service
# entrypoint.  The client validates the complete fixed projection and its
# source identity before mapping it to an external generic failure stage.
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
_SERVER_TO_STATUS_STAGE = {
    "service_peer_boundary": "server_service_peer_rejection",
    "authenticated_context_protocol_boundary": (
        "server_authenticated_context_protocol_rejection"
    ),
    "status_runtime_boundary": "server_status_runtime_rejection",
}
_STATUS_RUNTIME_REJECTION_POLICY: dict[str, tuple[str, bool]] = {
    "trusted_time_boundary": ("trusted_time_rejected", False),
    "store_state_boundary": ("store_state_rejected", False),
    "status_projection_boundary": ("status_projection_rejected", False),
    "response_encoding_boundary": ("response_encoding_rejected", False),
    "status_runtime_unknown_boundary": ("runtime_unknown_rejected", False),
}
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
SERVER_REJECTION_SOURCE_IDENTITY = sha256(
    SERVER_REJECTION_SOURCE_DOMAIN.encode("ascii")
    + b"\0"
    + json.dumps(
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
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
).hexdigest()
STATUS_RUNTIME_REJECTION_SOURCE_IDENTITY = sha256(
    STATUS_RUNTIME_REJECTION_SOURCE_DOMAIN.encode("ascii")
    + b"\0"
    + json.dumps(
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
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
).hexdigest()
STATUS_STAGE_SOURCE_IDENTITY = sha256(
    b"myuna-p08-content-free-status-stage-contract-v1\0"
    + json.dumps(
        {
            "schema": STATUS_STAGE_SCHEMA,
            "stage_policy": {
                stage: {"category": category, "retryable": retryable}
                for stage, (category, retryable) in _STATUS_STAGE_POLICY.items()
            },
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
).hexdigest()
STATUS_RUNTIME_STAGE_SOURCE_IDENTITY = sha256(
    b"myuna-p08-content-free-status-runtime-stage-contract-v1\0"
    + json.dumps(
        {
            "generic_stage_contract_identity": STATUS_STAGE_SOURCE_IDENTITY,
            "runtime_rejection_source_identity": (
                STATUS_RUNTIME_REJECTION_SOURCE_IDENTITY
            ),
            "schema": STATUS_RUNTIME_STAGE_SCHEMA,
            "stage": "server_status_runtime_rejection",
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
).hexdigest()

_COMMAND = re.compile(r"^/temporal(?:[ \t]+(.*))?$", re.IGNORECASE)
_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_CATEGORIES = frozenset(
    {
        "current_task",
        "short_term_status",
        "temporary_plan",
        "next_action",
        "deadline",
        "waiting_item",
        "temporary_constraint",
        "temporary_availability",
        "short_lived_preference",
    }
)
_DRAFT_ACTIONS = frozenset({"add", "supersede", "refresh", "restore"})
_WRITE_ACTIONS = _DRAFT_ACTIONS | {"revoke", "confirm"}
_USAGE = (
    "用法：/temporal get <查询>；/temporal add <类别> <槽位> <1-30天> <内容>；"
    "/temporal supersede|refresh|restore <fact_id> <类别> <槽位> <1-30天> <内容>；"
    "/temporal revoke <fact_id>；/temporal confirm <proposal_id> <确认码>"
)
_UNAVAILABLE = "临时信息服务现在不可用；这次没有读取或写入临时信息，请稍后再试"


class TemporalGatewayRejected(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        retryable: bool = False,
        status_stage: str | None = None,
        status_rejection: "ContentFreeStatusRejection | None" = None,
        status_runtime_rejection: "ContentFreeRuntimeRejection | None" = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable
        self.status_stage = status_stage
        self.status_rejection = status_rejection
        self.status_runtime_rejection = status_runtime_rejection
        if status_stage is not None:
            policy = _STATUS_STAGE_POLICY.get(status_stage)
            if policy is None:
                raise ValueError("invalid_content_free_status_stage")
        if status_rejection is not None and (
            status_stage != status_rejection.stage
        ):
            raise ValueError("mixed_content_free_status_rejection")
        if status_runtime_rejection is not None and (
            status_stage != "server_status_runtime_rejection"
            or status_rejection is None
            or status_rejection.runtime_rejection != status_runtime_rejection
        ):
            raise ValueError("mixed_content_free_status_runtime_rejection")


@dataclass(frozen=True, slots=True)
class ContentFreeRuntimeRejection:
    stage: str
    category: str
    error_category: str
    provider_state_effect: str
    retryable: bool
    request_nonce: str

    @classmethod
    def from_stage(
        cls,
        stage: str,
        *,
        request_nonce: str,
        error_category: str | None = None,
    ) -> "ContentFreeRuntimeRejection":
        policy = _STATUS_RUNTIME_REJECTION_POLICY.get(stage)
        if policy is None or re.fullmatch(r"[0-9a-f]{64}", request_nonce) is None:
            raise ValueError("invalid_content_free_runtime_rejection")
        if stage == "trusted_time_boundary":
            trusted_policy = _TRUSTED_TIME_REJECTION_POLICY.get(
                error_category or ""
            )
            if trusted_policy is None:
                raise ValueError("invalid_content_free_runtime_rejection")
            retryable, provider_state_effect = trusted_policy
            projected_error_category = error_category
        else:
            if error_category is not None:
                raise ValueError("invalid_content_free_runtime_rejection")
            retryable = policy[1]
            provider_state_effect = "none"
            projected_error_category = policy[0]
        return cls(
            stage=stage,
            category=policy[0],
            error_category=projected_error_category,
            provider_state_effect=provider_state_effect,
            retryable=retryable,
            request_nonce=request_nonce,
        )

    def projection(self) -> dict[str, object]:
        stable: dict[str, object] = {
            "category": self.category,
            "error_category": self.error_category,
            "persistent_mutation": False,
            "private_content_included": False,
            "provider_state_effect": self.provider_state_effect,
            "raw_cause_included": False,
            "request_nonce": self.request_nonce,
            "retryable": self.retryable,
            "schema": STATUS_RUNTIME_REJECTION_SCHEMA,
            "source_contract_identity": STATUS_RUNTIME_REJECTION_SOURCE_IDENTITY,
            "stage": self.stage,
        }
        return {
            **stable,
            "projection_digest": sha256(
                b"myuna-p08-status-runtime-rejection-projection-v2\0"
                + json.dumps(
                    stable,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii")
            ).hexdigest(),
        }


def parse_content_free_runtime_rejection(
    payload: object,
    *,
    expected_request_nonce: str,
) -> ContentFreeRuntimeRejection:
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
        raise ValueError("invalid_content_free_runtime_rejection")
    stage = payload.get("stage")
    if not isinstance(stage, str):
        raise ValueError("invalid_content_free_runtime_rejection")
    rejection = ContentFreeRuntimeRejection.from_stage(
        stage,
        request_nonce=expected_request_nonce,
        error_category=(
            payload.get("error_category")
            if stage == "trusted_time_boundary"
            and isinstance(payload.get("error_category"), str)
            else None
        ),
    )
    expected = rejection.projection()
    if any(
        type(payload.get(key)) is not type(value) or payload.get(key) != value
        for key, value in expected.items()
    ):
        raise ValueError("invalid_content_free_runtime_rejection")
    return rejection


@dataclass(frozen=True, slots=True)
class ContentFreeStatusRejection:
    stage: str
    category: str
    retryable: bool
    invocation_nonce: str
    runtime_rejection: ContentFreeRuntimeRejection | None = None

    @classmethod
    def from_stage(
        cls,
        stage: str,
        *,
        invocation_nonce: str,
        runtime_rejection: ContentFreeRuntimeRejection | None = None,
    ) -> "ContentFreeStatusRejection":
        policy = _STATUS_STAGE_POLICY.get(stage)
        if policy is None or re.fullmatch(r"[0-9a-f]{64}", invocation_nonce) is None:
            raise ValueError("invalid_content_free_status_rejection")
        if runtime_rejection is not None and (
            stage != "server_status_runtime_rejection"
            or runtime_rejection.request_nonce != invocation_nonce
        ):
            raise ValueError("invalid_content_free_status_runtime_rejection")
        return cls(
            stage=stage,
            category=policy[0],
            retryable=policy[1],
            invocation_nonce=invocation_nonce,
            runtime_rejection=runtime_rejection,
        )

    def legacy_projection(self) -> dict[str, object]:
        stable: dict[str, object] = {
            "category": self.category,
            "invocation_nonce": self.invocation_nonce,
            "persistent_mutation": False,
            "result": "rejected",
            "retryable": self.retryable,
            "schema": STATUS_STAGE_SCHEMA,
            "stage": self.stage,
            "stage_contract_identity": STATUS_STAGE_SOURCE_IDENTITY,
        }
        return {
            **stable,
            "projection_digest": sha256(
                b"myuna-p08-content-free-status-stage-projection-v1\0"
                + json.dumps(
                    stable,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii")
            ).hexdigest(),
        }

    def projection(self) -> dict[str, object]:
        if self.runtime_rejection is None:
            return self.legacy_projection()
        stable: dict[str, object] = {
            "category": self.category,
            "invocation_nonce": self.invocation_nonce,
            "persistent_mutation": False,
            "result": "rejected",
            "retryable": self.retryable,
            "runtime_rejection": self.runtime_rejection.projection(),
            "schema": STATUS_RUNTIME_STAGE_SCHEMA,
            "stage": self.stage,
            "stage_contract_identity": STATUS_RUNTIME_STAGE_SOURCE_IDENTITY,
        }
        return {
            **stable,
            "projection_digest": sha256(
                b"myuna-p08-content-free-status-runtime-stage-projection-v1\0"
                + json.dumps(
                    stable,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii")
            ).hexdigest(),
        }


def parse_content_free_status_rejection(
    payload: object,
    *,
    expected_invocation_nonce: str,
) -> ContentFreeStatusRejection:
    if isinstance(payload, Mapping) and payload.get("schema") == STATUS_RUNTIME_STAGE_SCHEMA:
        expected_keys = {
            "category",
            "invocation_nonce",
            "persistent_mutation",
            "projection_digest",
            "result",
            "retryable",
            "runtime_rejection",
            "schema",
            "stage",
            "stage_contract_identity",
        }
        if set(payload) != expected_keys:
            raise ValueError("invalid_content_free_status_rejection")
        runtime_rejection = parse_content_free_runtime_rejection(
            payload.get("runtime_rejection"),
            expected_request_nonce=expected_invocation_nonce,
        )
        rejection = ContentFreeStatusRejection.from_stage(
            "server_status_runtime_rejection",
            invocation_nonce=expected_invocation_nonce,
            runtime_rejection=runtime_rejection,
        )
        expected = rejection.projection()
        if any(
            type(payload.get(key)) is not type(value) or payload.get(key) != value
            for key, value in expected.items()
        ):
            raise ValueError("invalid_content_free_status_rejection")
        return rejection
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
    if not isinstance(payload, Mapping) or set(payload) != expected_keys:
        raise ValueError("invalid_content_free_status_rejection")
    stage = payload.get("stage")
    if not isinstance(stage, str):
        raise ValueError("invalid_content_free_status_rejection")
    rejection = ContentFreeStatusRejection.from_stage(
        stage, invocation_nonce=expected_invocation_nonce
    )
    expected = rejection.projection()
    if any(
        type(payload.get(key)) is not type(value) or payload.get(key) != value
        for key, value in expected.items()
    ):
        raise ValueError("invalid_content_free_status_rejection")
    return rejection


def parse_content_free_status_rejection_bytes(
    payload: bytes,
    *,
    expected_invocation_nonce: str,
) -> ContentFreeStatusRejection:
    """Strictly decode one bounded, content-free child rejection envelope."""

    if not isinstance(payload, bytes) or not (
        0 < len(payload) <= MAX_STATUS_HELPER_OUTPUT_BYTES
    ):
        raise ValueError("invalid_content_free_status_rejection")
    try:
        decoded = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=_strict_status_runtime_object,
        )
    except (UnicodeError, json.JSONDecodeError, _DuplicateStatusRuntimeKey) as exc:
        raise ValueError("invalid_content_free_status_rejection") from exc
    return parse_content_free_status_rejection(
        decoded,
        expected_invocation_nonce=expected_invocation_nonce,
    )


def content_free_status_rejection_projection(
    error: TemporalGatewayRejected,
) -> dict[str, object]:
    if not isinstance(error, TemporalGatewayRejected) or error.status_rejection is None:
        raise ValueError("content_free_status_stage_unavailable")
    projection = error.status_rejection.legacy_projection()
    parse_content_free_status_rejection(
        projection,
        expected_invocation_nonce=error.status_rejection.invocation_nonce,
    )
    return projection


@dataclass(frozen=True, slots=True)
class ContentFreeServerRejection:
    stage: str
    category: str
    retryable: bool
    error_code: str
    error_retryable: bool

    @classmethod
    def from_stage(cls, stage: str) -> "ContentFreeServerRejection":
        policy = _SERVER_REJECTION_POLICY.get(stage)
        if policy is None:
            raise ValueError("invalid_content_free_server_rejection")
        return cls(
            stage=stage,
            category=policy[0],
            retryable=policy[1],
            error_code=policy[2],
            error_retryable=policy[3],
        )

    def projection(self) -> dict[str, object]:
        stable: dict[str, object] = {
            "category": self.category,
            "persistent_mutation": False,
            "private_content_included": False,
            "raw_cause_included": False,
            "retryable": self.retryable,
            "schema": SERVER_REJECTION_SCHEMA,
            "source_contract_identity": SERVER_REJECTION_SOURCE_IDENTITY,
            "stage": self.stage,
        }
        return {
            **stable,
            "projection_digest": sha256(
                b"myuna-p08-server-rejection-projection-v1\0"
                + json.dumps(
                    stable,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii")
            ).hexdigest(),
        }


def parse_content_free_server_rejection(
    payload: object,
) -> ContentFreeServerRejection:
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
        raise ValueError("invalid_content_free_server_rejection")
    stage = payload.get("stage")
    if not isinstance(stage, str):
        raise ValueError("invalid_content_free_server_rejection")
    rejection = ContentFreeServerRejection.from_stage(stage)
    expected = rejection.projection()
    if any(
        type(payload.get(key)) is not type(value) or payload.get(key) != value
        for key, value in expected.items()
    ):
        raise ValueError("invalid_content_free_server_rejection")
    return rejection


def _status_stage_rejected(
    code: str,
    stage: str,
    *,
    runtime_rejection: ContentFreeRuntimeRejection | None = None,
    invocation_nonce: str | None = None,
) -> TemporalGatewayRejected:
    policy = _STATUS_STAGE_POLICY.get(stage)
    if policy is None:
        raise ValueError("invalid_content_free_status_stage")
    if runtime_rejection is None:
        return TemporalGatewayRejected(
            code,
            retryable=policy[1],
            status_stage=stage,
        )
    if invocation_nonce != runtime_rejection.request_nonce:
        raise ValueError("mixed_content_free_status_runtime_rejection")
    rejection = ContentFreeStatusRejection.from_stage(
        stage,
        invocation_nonce=runtime_rejection.request_nonce,
        runtime_rejection=runtime_rejection,
    )
    return TemporalGatewayRejected(
        code,
        retryable=policy[1],
        status_stage=stage,
        status_rejection=rejection,
        status_runtime_rejection=runtime_rejection,
    )


def _parent_status_rejected(
    code: str,
    stage: str,
    *,
    invocation_nonce: str,
) -> TemporalGatewayRejected:
    rejection = ContentFreeStatusRejection.from_stage(
        stage, invocation_nonce=invocation_nonce
    )
    return TemporalGatewayRejected(
        code,
        retryable=True,
        status_stage=stage,
        status_rejection=rejection,
    )


class _DuplicateStatusRuntimeKey(ValueError):
    pass


def _strict_status_runtime_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise _DuplicateStatusRuntimeKey(key)
        payload[key] = value
    return payload


@dataclass(frozen=True, slots=True)
class StatusRuntimeConfig:
    """Minimal self-contained view of the protected Telegram runtime config.

    The status child deliberately does not import the broader Telegram/P07
    runtime graph.  It accepts the same exact protected payload and retains
    only fields needed to authenticate the content-free P08 request.
    """

    channel_kind: str
    binding_id: str
    principal_id: str
    namespace_id: str
    finalization_digest: str
    evidence_sha256: str
    channel_instance: str
    core_host: str
    core_port: int
    max_requests_per_ten_minutes: int
    max_history_messages: int
    max_history_characters: int

    @classmethod
    def from_payload(cls, payload: object) -> "StatusRuntimeConfig":
        required = {
            "binding_id",
            "channel_kind",
            "channel_instance",
            "core_host",
            "core_port",
            "evidence_sha256",
            "finalization_digest",
            "max_history_characters",
            "max_history_messages",
            "max_requests_per_ten_minutes",
            "namespace_id",
            "principal_id",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise TemporalGatewayRejected("temporal_status_rejected", retryable=True)
        if payload["channel_kind"] != STATUS_CHANNEL_KIND:
            raise TemporalGatewayRejected("temporal_status_rejected", retryable=True)
        for key in ("binding_id", "namespace_id", "principal_id", "channel_instance"):
            value = payload[key]
            if not isinstance(value, str) or _SAFE.fullmatch(value) is None:
                raise TemporalGatewayRejected(
                    "temporal_status_rejected", retryable=True
                )
        for key in ("evidence_sha256", "finalization_digest"):
            value = payload[key]
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise TemporalGatewayRejected(
                    "temporal_status_rejected", retryable=True
                )
        core_port = payload["core_port"]
        request_limit = payload["max_requests_per_ten_minutes"]
        history_messages = payload["max_history_messages"]
        history_characters = payload["max_history_characters"]
        if payload["core_host"] != "127.0.0.1":
            raise TemporalGatewayRejected("temporal_status_rejected", retryable=True)
        if (
            not isinstance(core_port, int)
            or isinstance(core_port, bool)
            or not 1024 <= core_port <= 65535
            or not isinstance(request_limit, int)
            or isinstance(request_limit, bool)
            or not 1 <= request_limit <= 60
            or not isinstance(history_messages, int)
            or isinstance(history_messages, bool)
            or not MIN_HISTORY_MESSAGES <= history_messages <= MAX_HISTORY_MESSAGES
            or history_messages % 2
            or not isinstance(history_characters, int)
            or isinstance(history_characters, bool)
            or not MIN_HISTORY_CHARACTERS
            <= history_characters
            <= MAX_HISTORY_CHARACTERS
        ):
            raise TemporalGatewayRejected("temporal_status_rejected", retryable=True)
        return cls(
            channel_kind=STATUS_CHANNEL_KIND,
            binding_id=str(payload["binding_id"]),
            principal_id=str(payload["principal_id"]),
            namespace_id=str(payload["namespace_id"]),
            finalization_digest=str(payload["finalization_digest"]),
            evidence_sha256=str(payload["evidence_sha256"]),
            channel_instance=str(payload["channel_instance"]),
            core_host="127.0.0.1",
            core_port=core_port,
            max_requests_per_ten_minutes=request_limit,
            max_history_messages=history_messages,
            max_history_characters=history_characters,
        )


def parse_protected_status_runtime_config(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int = 0o640,
) -> StatusRuntimeConfig:
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
            os, "O_NOFOLLOW", 0
        )
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_gid != expected_gid
            or stat.S_IMODE(before.st_mode) != expected_mode
            or before.st_size <= 0
            or before.st_size > MAX_STATUS_RUNTIME_CONFIG_BYTES
        ):
            raise TemporalGatewayRejected("temporal_status_rejected", retryable=True)
        chunks: list[bytes] = []
        remaining = MAX_STATUS_RUNTIME_CONFIG_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        path_metadata = path.lstat()
        stable_fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_size")
        if (
            len(raw) != before.st_size
            or len(raw) > MAX_STATUS_RUNTIME_CONFIG_BYTES
            or any(
                getattr(before, field) != getattr(after, field)
                for field in stable_fields
            )
            or stat.S_ISLNK(path_metadata.st_mode)
            or any(
                getattr(before, field) != getattr(path_metadata, field)
                for field in stable_fields
            )
        ):
            raise TemporalGatewayRejected("temporal_status_rejected", retryable=True)
        payload = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_strict_status_runtime_object
        )
        return StatusRuntimeConfig.from_payload(payload)
    except TemporalGatewayRejected:
        raise
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        _DuplicateStatusRuntimeKey,
    ):
        raise TemporalGatewayRejected(
            "temporal_status_rejected", retryable=True
        ) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def load_protected_status_runtime_config() -> StatusRuntimeConfig:
    try:
        expected_gid = grp.getgrnam(STATUS_RUNTIME_GROUP).gr_gid
    except KeyError:
        raise TemporalGatewayRejected(
            "temporal_status_rejected", retryable=True
        ) from None
    return parse_protected_status_runtime_config(
        STATUS_RUNTIME_CONFIG_PATH,
        expected_uid=0,
        expected_gid=expected_gid,
        expected_mode=0o640,
    )


def _coerce_status_runtime_config(config: object) -> StatusRuntimeConfig:
    if isinstance(config, StatusRuntimeConfig):
        return config
    try:
        import telegram_runtime_config as runtime_config_contract
    except ImportError:
        raise TemporalGatewayRejected(
            "temporal_status_rejected", retryable=True
        ) from None
    if not isinstance(config, runtime_config_contract.RuntimeConfig):
        raise TemporalGatewayRejected("temporal_status_rejected", retryable=True)
    return StatusRuntimeConfig(
        channel_kind=config.channel_kind,
        binding_id=config.binding_id,
        principal_id=config.principal_id,
        namespace_id=config.namespace_id,
        finalization_digest=config.finalization_digest,
        evidence_sha256=config.evidence_sha256,
        channel_instance=config.channel_instance,
        core_host=config.core_host,
        core_port=config.core_port,
        max_requests_per_ten_minutes=config.max_requests_per_ten_minutes,
        max_history_messages=config.max_history_messages,
        max_history_characters=config.max_history_characters,
    )


def enter_content_free_status_identity() -> None:
    """Drop a source-launched helper to the fixed Telegram gateway identity.

    The production controller imports this reviewed source as root from a
    protected repository.  The restricted Telegram identity cannot traverse
    that repository, so dropping identity before Python opens this file makes
    the helper unavailable before it can reach the P08 socket.  Import first,
    then irreversibly drop privileges before loading runtime configuration or
    opening the socket.  An already-correct identity is accepted for offline
    and service-identity tests; every other non-root identity fails closed.
    """

    try:
        account = pwd.getpwnam(STATUS_RUNTIME_USER)
    except KeyError:
        raise TemporalGatewayRejected(
            "temporal_status_unavailable", retryable=True
        ) from None
    current_uid = os.geteuid()
    current_gid = os.getegid()
    if current_uid == account.pw_uid and current_gid == account.pw_gid:
        return
    if current_uid != 0:
        raise TemporalGatewayRejected(
            "temporal_status_unavailable", retryable=True
        )
    try:
        os.initgroups(STATUS_RUNTIME_USER, account.pw_gid)
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    except OSError:
        raise TemporalGatewayRejected(
            "temporal_status_unavailable", retryable=True
        ) from None
    if os.geteuid() != account.pw_uid or os.getegid() != account.pw_gid:
        raise TemporalGatewayRejected(
            "temporal_status_unavailable", retryable=True
        )


def content_free_status_pythonpath() -> tuple[Path, Path]:
    """Derive the two exact, already-imported source roots for the child.

    No caller path is accepted.  The P08 Core source root comes from the
    reviewed protocol module already imported by this process; the Deploy root
    comes from this helper.  Every local dependency must be a regular,
    non-symlink file before a child can be created.
    """

    try:
        source = Path(__file__)
        protocol_file = Path(str(temporal_protocol_contract.__file__))
        source_metadata = source.lstat()
        protocol_metadata = protocol_file.lstat()
        source = source.resolve(strict=True)
        protocol_file = protocol_file.resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError):
        raise TemporalGatewayRejected(
            "temporal_status_unavailable", retryable=True
        ) from None
    if (
        not stat.S_ISREG(source_metadata.st_mode)
        or stat.S_ISLNK(source_metadata.st_mode)
        or not stat.S_ISREG(protocol_metadata.st_mode)
        or stat.S_ISLNK(protocol_metadata.st_mode)
    ):
        raise TemporalGatewayRejected("temporal_status_unavailable", retryable=True)
    deploy_root = source.parent
    try:
        core_root = protocol_file.parents[2]
    except IndexError:
        raise TemporalGatewayRejected(
            "temporal_status_unavailable", retryable=True
        ) from None
    for path in (source, protocol_file):
        try:
            metadata = path.lstat()
        except OSError:
            raise TemporalGatewayRejected(
                "temporal_status_unavailable", retryable=True
            ) from None
        if not path.is_file() or path.is_symlink() or metadata.st_size <= 0:
            raise TemporalGatewayRejected(
                "temporal_status_unavailable", retryable=True
            )
    if not (core_root / "myuna_core").is_dir():
        raise TemporalGatewayRejected("temporal_status_unavailable", retryable=True)
    return core_root, deploy_root


@dataclass(frozen=True, slots=True)
class TemporalCommand:
    action: str
    arguments: tuple[str, ...]

    @property
    def writes(self) -> bool:
        return self.action in _WRITE_ACTIONS


@dataclass(frozen=True, slots=True)
class ActiveTemporalGatewaySnapshot:
    context: str
    fact_count: int
    projection_digest: str
    coverage_state: str
    trusted_time: TrustedTimeSample | None
    trusted_time_unresolved_reason: str | None
    active_snapshot_receipt: ActiveSnapshotReceipt | None = None
    lifecycle_transitions: tuple[Mapping[str, object], ...] = ()
    lifecycle_watermark: int = 0
    lifecycle_has_more: bool = False


@dataclass(frozen=True, slots=True)
class ContentFreeTemporalGatewayStatus:
    active_fact_count: int
    active_set_digest: str
    lifecycle_digest: str
    lifecycle_event_count: int
    lifecycle_watermark: int
    pending_proposal_count: int
    request_nonce: str
    response_digest: str
    scope_binding_digest: str
    source_identity: str
    status_digest: str
    total_fact_count: int
    trusted_time_binding_digest: str

    def projection(self) -> dict[str, object]:
        return {
            "active_fact_count": self.active_fact_count,
            "active_set_complete": True,
            "active_set_digest": self.active_set_digest,
            "lifecycle_complete": True,
            "lifecycle_digest": self.lifecycle_digest,
            "lifecycle_event_count": self.lifecycle_event_count,
            "lifecycle_watermark": self.lifecycle_watermark,
            "pending_proposal_count": self.pending_proposal_count,
            "request_nonce": self.request_nonce,
            "response_digest": self.response_digest,
            "scope_binding_digest": self.scope_binding_digest,
            "source_identity": self.source_identity,
            "status_digest": self.status_digest,
            "status_schema": CONTENT_FREE_STATUS_SCHEMA,
            "total_fact_count": self.total_fact_count,
            "trusted_time_binding_digest": self.trusted_time_binding_digest,
            "trusted_time_evidence_complete": True,
        }


def _canonical_digest(domain: str, payload: Mapping[str, object]) -> str:
    return sha256(
        domain.encode("ascii")
        + b"\0"
        + json.dumps(
            dict(payload),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


def content_free_scope_digest(
    *,
    binding_id: str,
    principal_id: str,
    namespace_id: str,
    channel_kind: str,
    channel_instance: str,
) -> str:
    values = (
        binding_id,
        principal_id,
        namespace_id,
        channel_kind,
        channel_instance,
        STATUS_CONVERSATION_ID,
    )
    if any(not isinstance(value, str) or _SAFE.fullmatch(value) is None for value in values):
        raise TemporalGatewayRejected("invalid_request")
    return sha256(
        b"myuna-active-temporal-scope-v1\0" + "\0".join(values).encode("utf-8")
    ).hexdigest()


def unresolved_active_snapshot(reason_code: str) -> ActiveTemporalGatewaySnapshot:
    if not isinstance(reason_code, str) or _SAFE.fullmatch(reason_code) is None:
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    context = (
        "[active_temporal_validity_context_v1 all_or_none=true "
        "coverage=unavailable exact_time_claim_allowed=false]"
    )
    semantic = {
        "context_digest": sha256(context.encode("utf-8")).hexdigest(),
        "coverage_state": "unavailable",
        "reason_code": reason_code,
        "schema": "myuna.active-temporal-snapshot-unresolved.v1",
    }
    return ActiveTemporalGatewaySnapshot(
        context=context,
        fact_count=0,
        projection_digest=sha256(
            json.dumps(
                semantic,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        ).hexdigest(),
        coverage_state="unavailable",
        trusted_time=None,
        trusted_time_unresolved_reason=reason_code,
        active_snapshot_receipt=None,
        lifecycle_transitions=(),
        lifecycle_watermark=0,
        lifecycle_has_more=False,
    )


def build_active_snapshot_request(
    *,
    authenticated_context: Mapping[str, object],
    request_id: str,
    after_event_sequence: int = 0,
) -> dict[str, object]:
    _safe(request_id)
    if (
        isinstance(after_event_sequence, bool)
        or not isinstance(after_event_sequence, int)
        or after_event_sequence < 0
    ):
        raise TemporalGatewayRejected("invalid_request")
    return {
        "schema": SCHEMA,
        "boundary": BOUNDARY,
        "operation": "snapshot_active",
        "request_id": request_id,
        "authenticated_context": dict(authenticated_context),
        "input": {"after_event_sequence": after_event_sequence},
    }


def build_content_free_status_request(
    *,
    authenticated_context: Mapping[str, object],
    request_id: str,
    request_nonce: str,
    minimum_lifecycle_watermark: int = 0,
) -> dict[str, object]:
    _safe(request_id)
    if re.fullmatch(r"[0-9a-f]{64}", request_nonce) is None:
        raise TemporalGatewayRejected("invalid_request")
    if (
        isinstance(minimum_lifecycle_watermark, bool)
        or not isinstance(minimum_lifecycle_watermark, int)
        or minimum_lifecycle_watermark < 0
    ):
        raise TemporalGatewayRejected("invalid_request")
    try:
        context = AuthenticatedConversationContext.from_payload(
            authenticated_context,
            authenticated_client_id=STATUS_CLIENT_ID,
            authenticated_channel_kind="astrbot_telegram",
        )
    except Exception:
        raise TemporalGatewayRejected("invalid_request") from None
    if (
        context.request_id != request_id
        or context.authority_level != "owner"
        or context.conversation_kind != "private"
        or context.conversation_id != STATUS_CONVERSATION_ID
    ):
        raise TemporalGatewayRejected("invalid_request")
    scope_digest = content_free_scope_digest(
        binding_id=context.binding_id,
        principal_id=context.principal_id,
        namespace_id=context.namespace_id,
        channel_kind=context.channel_kind,
        channel_instance=context.channel_instance,
    )
    return {
        "schema": SCHEMA,
        "boundary": BOUNDARY,
        "operation": STATUS_OPERATION,
        "request_id": request_id,
        "authenticated_context": dict(authenticated_context),
        "input": {
            "expected_scope_digest": scope_digest,
            "expected_source_identity": CONTENT_FREE_STATUS_SOURCE_IDENTITY,
            "minimum_lifecycle_watermark": minimum_lifecycle_watermark,
            "request_nonce": request_nonce,
            "response_schema": CONTENT_FREE_STATUS_SCHEMA,
        },
    }


def parse_content_free_status_response(
    response: Mapping[str, object],
    *,
    request_id: str,
    request_nonce: str,
    expected_scope_digest: str,
    minimum_lifecycle_watermark: int = 0,
) -> ContentFreeTemporalGatewayStatus:
    if (
        isinstance(minimum_lifecycle_watermark, bool)
        or not isinstance(minimum_lifecycle_watermark, int)
        or minimum_lifecycle_watermark < 0
    ):
        raise TemporalGatewayRejected("temporal_status_rejected", retryable=True)
    expected_top_level = {
        "channel_called",
        "health_called",
        "legacy_namespace_written",
        "model_called",
        "ok",
        "operation",
        "output",
        "private_content_returned",
        "profile_written",
        "provider_called",
        "request_id",
        "schema",
        "session_written",
    }
    if (
        set(response) != expected_top_level
        or response.get("schema") != SCHEMA
        or response.get("operation") != STATUS_OPERATION
        or response.get("ok") is not True
        or response.get("request_id") != request_id
        or any(
            response.get(field) is not False
            for field in (
                "channel_called",
                "health_called",
                "legacy_namespace_written",
                "model_called",
                "private_content_returned",
                "profile_written",
                "provider_called",
                "session_written",
            )
        )
    ):
        raise TemporalGatewayRejected("temporal_status_rejected", retryable=True)
    output = response.get("output")
    expected_output = {
        "active_fact_count",
        "active_set_complete",
        "active_set_digest",
        "lifecycle_complete",
        "lifecycle_digest",
        "lifecycle_event_count",
        "lifecycle_watermark",
        "pending_proposal_count",
        "request_nonce",
        "response_digest",
        "scope_binding_digest",
        "source_identity",
        "status_digest",
        "status_schema",
        "total_fact_count",
        "trusted_time_binding_digest",
        "trusted_time_evidence_complete",
    }
    if not isinstance(output, Mapping) or set(output) != expected_output:
        raise TemporalGatewayRejected("temporal_status_rejected", retryable=True)
    count_limits = {
        "active_fact_count": MAX_STATUS_FACTS,
        "lifecycle_event_count": MAX_STATUS_EVENTS,
        "lifecycle_watermark": MAX_STATUS_EVENTS,
        "pending_proposal_count": MAX_STATUS_PENDING_PROPOSALS,
        "total_fact_count": MAX_STATUS_FACTS,
    }
    if any(
        isinstance(output[field], bool)
        or not isinstance(output[field], int)
        or not 0 <= int(output[field]) <= maximum
        for field, maximum in count_limits.items()
    ):
        raise TemporalGatewayRejected("temporal_status_rejected", retryable=True)
    if (
        output["active_fact_count"] > output["total_fact_count"]
        or output["lifecycle_event_count"] != output["lifecycle_watermark"]
        or output["lifecycle_watermark"] < minimum_lifecycle_watermark
        or output["active_set_complete"] is not True
        or output["lifecycle_complete"] is not True
        or output["trusted_time_evidence_complete"] is not True
        or output["request_nonce"] != request_nonce
        or output["scope_binding_digest"] != expected_scope_digest
        or output["source_identity"] != CONTENT_FREE_STATUS_SOURCE_IDENTITY
        or output["status_schema"] != CONTENT_FREE_STATUS_SCHEMA
    ):
        raise TemporalGatewayRejected("temporal_status_rejected", retryable=True)
    for field in (
        "active_set_digest",
        "lifecycle_digest",
        "response_digest",
        "scope_binding_digest",
        "source_identity",
        "status_digest",
        "trusted_time_binding_digest",
    ):
        if not isinstance(output[field], str) or re.fullmatch(
            r"[0-9a-f]{64}", output[field]
        ) is None:
            raise TemporalGatewayRejected("temporal_status_rejected", retryable=True)
    stable_status = {
        key: output[key]
        for key in expected_output
        - {"request_nonce", "response_digest", "status_digest"}
    }
    status_digest = _canonical_digest(
        "myuna-p08-content-free-status-v1", stable_status
    )
    response_digest = _canonical_digest(
        "myuna-p08-content-free-status-v1",
        {
            "request_nonce": request_nonce,
            "source_identity": CONTENT_FREE_STATUS_SOURCE_IDENTITY,
            "status_digest": status_digest,
        },
    )
    if (
        output["status_digest"] != status_digest
        or output["response_digest"] != response_digest
    ):
        raise TemporalGatewayRejected("temporal_status_rejected", retryable=True)
    return ContentFreeTemporalGatewayStatus(
        active_fact_count=int(output["active_fact_count"]),
        active_set_digest=str(output["active_set_digest"]),
        lifecycle_digest=str(output["lifecycle_digest"]),
        lifecycle_event_count=int(output["lifecycle_event_count"]),
        lifecycle_watermark=int(output["lifecycle_watermark"]),
        pending_proposal_count=int(output["pending_proposal_count"]),
        request_nonce=str(output["request_nonce"]),
        response_digest=str(output["response_digest"]),
        scope_binding_digest=str(output["scope_binding_digest"]),
        source_identity=str(output["source_identity"]),
        status_digest=str(output["status_digest"]),
        total_fact_count=int(output["total_fact_count"]),
        trusted_time_binding_digest=str(output["trusted_time_binding_digest"]),
    )


def parse_active_snapshot_response(
    response: Mapping[str, object],
    *,
    request_id: str,
    after_event_sequence: int,
) -> ActiveTemporalGatewaySnapshot:
    expected_top_level = {
        "legacy_namespace_written",
        "model_called",
        "ok",
        "operation",
        "output",
        "profile_written",
        "request_id",
        "schema",
        "session_written",
    }
    if (
        _SAFE.fullmatch(request_id) is None
        or isinstance(after_event_sequence, bool)
        or not isinstance(after_event_sequence, int)
        or after_event_sequence < 0
        or set(response) != expected_top_level
        or response.get("schema") != SCHEMA
        or response.get("operation") != "snapshot_active"
        or response.get("ok") is not True
        or response.get("request_id") != request_id
        or any(
            response.get(field) is not False
            for field in (
                "legacy_namespace_written",
                "model_called",
                "profile_written",
                "session_written",
            )
        )
    ):
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    output = response.get("output")
    if not isinstance(output, Mapping) or set(output) != {
        "active_snapshot_receipt",
        "context",
        "fact_count",
        "lifecycle_has_more",
        "lifecycle_transitions",
        "lifecycle_watermark",
        "projection_digest",
        "trusted_time",
    }:
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    if (
        not isinstance(output["context"], str)
        or len(output["context"]) > 12_000
        or isinstance(output["fact_count"], bool)
        or not isinstance(output["fact_count"], int)
        or output["fact_count"] < 0
        or not isinstance(output["projection_digest"], str)
        or re.fullmatch(r"[0-9a-f]{64}", output["projection_digest"]) is None
        or not isinstance(output["trusted_time"], Mapping)
        or not isinstance(output["lifecycle_has_more"], bool)
        or not isinstance(output["lifecycle_transitions"], list)
        or len(output["lifecycle_transitions"]) > 4
        or isinstance(output["lifecycle_watermark"], bool)
        or not isinstance(output["lifecycle_watermark"], int)
        or output["lifecycle_watermark"] < 0
    ):
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    transitions: list[Mapping[str, object]] = []
    expected_transition_fields = {
        "category",
        "event_kind",
        "event_sequence",
        "expires_at",
        "fact_id",
        "occurred_at",
        "reason",
        "revision",
        "slot_key",
        "source_kind",
        "source_ref",
        "state",
        "supersedes_fact_id",
        "transition",
        "trusted_time_source_class",
        "valid_from",
        "valid_to",
    }
    previous_sequence = 0
    for item in output["lifecycle_transitions"]:
        if (
            not isinstance(item, Mapping)
            or set(item) != expected_transition_fields
            or isinstance(item["event_sequence"], bool)
            or not isinstance(item["event_sequence"], int)
            or item["event_sequence"] <= previous_sequence
        ):
            raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
        previous_sequence = item["event_sequence"]
        transitions.append(dict(item))
    sample = parse_trusted_time_response(response)
    try:
        receipt = ActiveSnapshotReceipt.from_payload(
            output["active_snapshot_receipt"]
        )
    except Exception:
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True) from None
    if (
        not receipt.matches_source_tuple(
            request_id=request_id,
            after_event_sequence=after_event_sequence,
            fact_count=output["fact_count"],
            transitions=transitions,
            lifecycle_watermark=output["lifecycle_watermark"],
            lifecycle_has_more=output["lifecycle_has_more"],
            trusted_time=sample.as_payload(),
        )
    ):
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    return ActiveTemporalGatewaySnapshot(
        context=output["context"],
        fact_count=output["fact_count"],
        projection_digest=output["projection_digest"],
        coverage_state="complete",
        trusted_time=sample,
        trusted_time_unresolved_reason=None,
        active_snapshot_receipt=receipt,
        lifecycle_transitions=tuple(transitions),
        lifecycle_watermark=output["lifecycle_watermark"],
        lifecycle_has_more=output["lifecycle_has_more"],
    )


def parse_trusted_time_response(
    response: Mapping[str, object],
) -> TrustedTimeSample:
    """Read the one P10-B sample already bound to this P08 operation."""

    output = response.get("output")
    if not isinstance(output, Mapping) or not isinstance(
        output.get("trusted_time"), Mapping
    ):
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    try:
        sample = TrustedTimeSample.from_payload(output["trusted_time"])
    except Exception:
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True) from None
    if not sample.evidence_complete or sample.synchronized is not True:
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    return sample


def is_temporal_command(value: object) -> bool:
    return isinstance(value, str) and _COMMAND.fullmatch(value.strip()) is not None


def parse_temporal_command(value: object) -> TemporalCommand | None:
    if not isinstance(value, str):
        return None
    match = _COMMAND.fullmatch(value.strip())
    if match is None:
        return None
    parameter = match.group(1)
    if parameter is None:
        return TemporalCommand("help", ())
    try:
        parts = shlex.split(parameter, posix=True)
    except ValueError:
        return TemporalCommand("help", ())
    if not parts:
        return TemporalCommand("help", ())
    action = parts[0].casefold()
    arguments = tuple(parts[1:])
    if action == "get" and len(arguments) >= 1:
        return TemporalCommand(action, (" ".join(arguments),))
    if action == "add" and len(arguments) >= 4:
        return TemporalCommand(action, (*arguments[:3], " ".join(arguments[3:])))
    if action in {"supersede", "refresh", "restore"} and len(arguments) >= 5:
        return TemporalCommand(action, (*arguments[:4], " ".join(arguments[4:])))
    if action == "revoke" and len(arguments) == 1:
        return TemporalCommand(action, arguments)
    if action == "confirm" and len(arguments) == 2:
        return TemporalCommand(action, arguments)
    return TemporalCommand("help", ())


def temporal_intent_grants_candidate_consent(value: object) -> bool:
    command = parse_temporal_command(value)
    return command is not None and command.writes


def _safe(value: str) -> str:
    if _SAFE.fullmatch(value) is None:
        raise TemporalGatewayRejected("invalid_request")
    return value


def _days(value: str) -> int:
    try:
        days = int(value)
    except ValueError:
        raise TemporalGatewayRejected("invalid_request") from None
    if not 1 <= days <= 30:
        raise TemporalGatewayRejected("invalid_request")
    return days


def _draft(
    *,
    category: str,
    slot_key: str,
    days: str,
    summary: str,
    source_kind: str,
    source_ref: str,
    occurred_at: datetime,
) -> dict[str, object]:
    if category not in _CATEGORIES:
        raise TemporalGatewayRejected("invalid_request")
    _safe(slot_key)
    _safe(source_ref)
    if (
        not summary
        or summary != summary.strip()
        or "\x00" in summary
        or len(summary) > 500
    ):
        raise TemporalGatewayRejected("invalid_request")
    if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
        raise TemporalGatewayRejected("invalid_request")
    valid_from = occurred_at.astimezone(timezone.utc)
    expires_at = valid_from + timedelta(days=_days(days))
    return {
        "category": category,
        "expires_at": expires_at.isoformat(timespec="microseconds"),
        "slot_key": slot_key,
        "source_channel": "telegram",
        "source_kind": source_kind,
        "source_ref": source_ref,
        "summary": summary,
        "valid_from": valid_from.isoformat(timespec="microseconds"),
        "valid_to": None,
    }


def build_request(
    command: TemporalCommand,
    *,
    authenticated_context: Mapping[str, object],
    request_id: str,
    event_id: str,
    occurred_at: datetime,
) -> dict[str, object]:
    if command.action == "help":
        raise TemporalGatewayRejected("usage_requested")
    _safe(request_id)
    _safe(event_id)
    if command.action == "get":
        operation = "retrieve"
        payload: dict[str, object] = {
            "query": command.arguments[0],
            "categories": [],
            "slot_keys": [],
        }
    elif command.action == "confirm":
        operation = "confirm"
        payload = {
            "explicit_intent": True,
            "proposal_id": _safe(command.arguments[0]),
            "confirmation_code": _safe(command.arguments[1]),
        }
    else:
        operation = "propose"
        target: str | None = None
        draft: dict[str, object] | None = None
        if command.action == "revoke":
            target = _safe(command.arguments[0])
            action = "revoke"
        else:
            action = "create" if command.action == "add" else command.action
            offset = 0 if command.action == "add" else 1
            if offset:
                target = _safe(command.arguments[0])
            category, slot_key, days, summary = command.arguments[offset : offset + 4]
            source_kind = {
                "add": "owner_statement",
                "supersede": "owner_statement",
                "refresh": "owner_refresh",
                "restore": "owner_restore",
            }[command.action]
            draft = _draft(
                category=category,
                slot_key=slot_key,
                days=days,
                summary=summary,
                source_kind=source_kind,
                source_ref=event_id,
                occurred_at=occurred_at,
            )
        payload = {
            "explicit_intent": True,
            "action": action,
            "draft": draft,
            "target_fact_id": target,
            "ttl_seconds": 600,
        }
    return {
        "schema": SCHEMA,
        "boundary": BOUNDARY,
        "operation": operation,
        "request_id": request_id,
        "authenticated_context": dict(authenticated_context),
        "input": payload,
    }


def _read_response(
    raw: bytes,
    *,
    request_id: str,
    content_free_status: bool = False,
    expected_status_nonce: str | None = None,
) -> dict[str, object]:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        if content_free_status:
            raise _status_stage_rejected(
                "temporal_status_rejected", "response_parse"
            ) from None
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True) from None
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        if content_free_status:
            raise _status_stage_rejected(
                "temporal_status_rejected", "response_schema_source_watermark"
            )
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    if payload.get("request_id") not in {None, request_id}:
        if content_free_status:
            raise _status_stage_rejected(
                "temporal_status_rejected", "response_projection"
            )
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    if payload.get("ok") is False:
        error = payload.get("error")
        if (
            not isinstance(error, dict)
            or set(error) != {"code", "retryable"}
            or not isinstance(error.get("code"), str)
            or type(error.get("retryable")) is not bool
        ):
            if content_free_status:
                raise _status_stage_rejected(
                    "temporal_status_rejected",
                    "response_projection",
                )
            raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
        if content_free_status:
            rejection_payload = payload.get("content_free_rejection")
            runtime_rejection_payload = payload.get(
                "content_free_runtime_rejection"
            )
            expected_keys = {"error", "ok", "schema"}
            if "request_id" in payload:
                expected_keys.add("request_id")
            if rejection_payload is None:
                if set(payload) != expected_keys:
                    raise _status_stage_rejected(
                        "temporal_status_rejected",
                        "response_projection",
                    )
                raise _status_stage_rejected(
                    "temporal_status_unavailable",
                    "server_peer_auth_protocol_rejection",
                )
            expected_keys.add("content_free_rejection")
            if runtime_rejection_payload is not None:
                expected_keys.add("content_free_runtime_rejection")
            if set(payload) != expected_keys:
                raise _status_stage_rejected(
                    "temporal_status_rejected",
                    "response_projection",
                )
            try:
                rejection = parse_content_free_server_rejection(
                    rejection_payload
                )
            except ValueError:
                raise _status_stage_rejected(
                    "temporal_status_rejected",
                    "response_projection",
                ) from None
            if (
                error.get("code") != rejection.error_code
                or error.get("retryable") is not rejection.error_retryable
            ):
                raise _status_stage_rejected(
                    "temporal_status_rejected",
                    "response_projection",
                )
            stage = _SERVER_TO_STATUS_STAGE.get(rejection.stage)
            if stage is None:
                raise _status_stage_rejected(
                    "temporal_status_rejected",
                    "response_projection",
                )
            runtime_rejection: ContentFreeRuntimeRejection | None = None
            if runtime_rejection_payload is not None:
                if (
                    rejection.stage != "status_runtime_boundary"
                    or not isinstance(expected_status_nonce, str)
                ):
                    raise _status_stage_rejected(
                        "temporal_status_rejected",
                        "response_projection",
                    )
                try:
                    runtime_rejection = parse_content_free_runtime_rejection(
                        runtime_rejection_payload,
                        expected_request_nonce=expected_status_nonce,
                    )
                except ValueError:
                    raise _status_stage_rejected(
                        "temporal_status_rejected",
                        "response_projection",
                    ) from None
            elif rejection.stage != "status_runtime_boundary":
                runtime_rejection = None
            raise _status_stage_rejected(
                "temporal_status_unavailable",
                stage,
                runtime_rejection=runtime_rejection,
                invocation_nonce=(
                    expected_status_nonce if runtime_rejection is not None else None
                ),
            )
        raise TemporalGatewayRejected(error["code"], retryable=error["retryable"])
    if payload.get("ok") is not True or payload.get("request_id") != request_id:
        if content_free_status:
            raise _status_stage_rejected(
                "temporal_status_rejected", "response_projection"
            )
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    if not isinstance(payload.get("operation"), str) or not isinstance(
        payload.get("output"), dict
    ):
        if content_free_status:
            raise _status_stage_rejected(
                "temporal_status_rejected", "response_projection"
            )
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    for field in (
        "model_called",
        "profile_written",
        "session_written",
        "legacy_namespace_written",
    ):
        if payload.get(field) is not False:
            if content_free_status:
                raise _status_stage_rejected(
                    "temporal_status_rejected", "response_projection"
                )
            raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    return payload


def send_temporal_request(
    payload: Mapping[str, object],
    *,
    socket_path: str = SOCKET_PATH,
    timeout: float = 5.0,
    content_free_status: bool = False,
) -> dict[str, object]:
    expected_status_nonce: str | None = None
    if content_free_status:
        request_input = payload.get("input")
        candidate_nonce = (
            request_input.get("request_nonce")
            if isinstance(request_input, Mapping)
            else None
        )
        if isinstance(candidate_nonce, str) and re.fullmatch(
            r"[0-9a-f]{64}", candidate_nonce
        ) is not None:
            expected_status_nonce = candidate_nonce
    raw = json.dumps(
        dict(payload), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8") + b"\n"
    if len(raw) > MAX_WIRE_BYTES:
        raise TemporalGatewayRejected("invalid_request")
    response = bytearray()
    connected = False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(socket_path)
            connected = True
            client.sendall(raw)
            client.shutdown(socket.SHUT_WR)
            while len(response) <= MAX_WIRE_BYTES:
                chunk = client.recv(1024)
                if not chunk:
                    break
                response.extend(chunk)
                if b"\n" in chunk:
                    break
    except socket.timeout:
        if content_free_status:
            raise _status_stage_rejected(
                "temporal_status_unavailable", "transport_timeout"
            ) from None
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True) from None
    except OSError:
        if content_free_status:
            stage = "transport_io" if connected else "transport_connect"
            raise _status_stage_rejected(
                "temporal_status_unavailable", stage
            ) from None
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True) from None
    if len(response) > MAX_WIRE_BYTES:
        if content_free_status:
            raise _status_stage_rejected(
                "temporal_status_rejected", "transport_oversize"
            )
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    first = bytes(response).split(b"\n", 1)[0]
    if content_free_status and not first:
        raise _status_stage_rejected(
            "temporal_status_unavailable", "transport_eof"
        )
    return _read_response(
        first,
        request_id=str(payload["request_id"]),
        content_free_status=content_free_status,
        expected_status_nonce=expected_status_nonce,
    )


def _content_free_status_context(
    config: object,
    *,
    request_id: str,
    request_nonce: str,
) -> AuthenticatedConversationContext:
    status_config = _coerce_status_runtime_config(config)
    return AuthenticatedConversationContext(
        schema_version="myuna.authenticated-conversation-context.v1",
        request_id=request_id,
        correlation_id=request_id,
        client_id=STATUS_CLIENT_ID,
        channel_kind=status_config.channel_kind,
        binding_id=status_config.binding_id,
        principal_id=status_config.principal_id,
        namespace_id=status_config.namespace_id,
        authority_level="owner",
        channel_instance=status_config.channel_instance,
        conversation_id=STATUS_CONVERSATION_ID,
        conversation_kind="private",
        event_id=f"p08-status-event-{request_nonce[:32]}",
        trace_id=f"p08-status-trace-{request_nonce[:32]}",
        occurred_at=datetime.now(timezone.utc),
        delivery_capabilities=("text",),
        consent_memory_candidate=False,
        consent_tools=False,
        consent_media_processing=False,
    )


def query_content_free_status(
    config: object,
    *,
    request_nonce: str | None = None,
    minimum_lifecycle_watermark: int = 0,
) -> ContentFreeTemporalGatewayStatus:
    status_config = _coerce_status_runtime_config(config)
    selected_nonce = secrets.token_hex(32) if request_nonce is None else request_nonce
    if not isinstance(selected_nonce, str) or re.fullmatch(
        r"[0-9a-f]{64}", selected_nonce
    ) is None:
        raise _status_stage_rejected(
            "temporal_status_rejected", "response_schema_source_watermark"
        )
    request_nonce = selected_nonce
    request_id = f"p08-status-{request_nonce[:32]}"
    context = _content_free_status_context(
        status_config,
        request_id=request_id,
        request_nonce=request_nonce,
    )
    request = build_content_free_status_request(
        authenticated_context=context.as_payload(),
        request_id=request_id,
        request_nonce=request_nonce,
        minimum_lifecycle_watermark=minimum_lifecycle_watermark,
    )
    response = send_temporal_request(request, content_free_status=True)
    expected_scope_digest = content_free_scope_digest(
        binding_id=status_config.binding_id,
        principal_id=status_config.principal_id,
        namespace_id=status_config.namespace_id,
        channel_kind=status_config.channel_kind,
        channel_instance=status_config.channel_instance,
    )
    output = response.get("output")
    if (
        not isinstance(output, Mapping)
        or output.get("request_nonce") != request_nonce
        or output.get("scope_binding_digest") != expected_scope_digest
        or output.get("source_identity") != CONTENT_FREE_STATUS_SOURCE_IDENTITY
        or output.get("status_schema") != CONTENT_FREE_STATUS_SCHEMA
        or isinstance(output.get("lifecycle_watermark"), bool)
        or not isinstance(output.get("lifecycle_watermark"), int)
        or int(output["lifecycle_watermark"]) < minimum_lifecycle_watermark
    ):
        raise _status_stage_rejected(
            "temporal_status_rejected", "response_schema_source_watermark"
        )
    try:
        return parse_content_free_status_response(
            response,
            request_id=request_id,
            request_nonce=request_nonce,
            expected_scope_digest=expected_scope_digest,
            minimum_lifecycle_watermark=minimum_lifecycle_watermark,
        )
    except TemporalGatewayRejected as error:
        if error.status_stage is not None:
            raise
        raise _status_stage_rejected(
            "temporal_status_rejected", "response_projection"
        ) from None


def parse_content_free_status_projection(
    payload: object,
    *,
    expected_scope_digest: str,
) -> ContentFreeTemporalGatewayStatus:
    if not isinstance(payload, Mapping):
        raise _status_stage_rejected(
            "temporal_status_rejected", "response_projection"
        )
    request_nonce = payload.get("request_nonce")
    if not isinstance(request_nonce, str) or re.fullmatch(
        r"[0-9a-f]{64}", request_nonce
    ) is None:
        raise _status_stage_rejected(
            "temporal_status_rejected", "response_schema_source_watermark"
        )
    if (
        payload.get("scope_binding_digest") != expected_scope_digest
        or payload.get("source_identity") != CONTENT_FREE_STATUS_SOURCE_IDENTITY
        or payload.get("status_schema") != CONTENT_FREE_STATUS_SCHEMA
    ):
        raise _status_stage_rejected(
            "temporal_status_rejected", "response_schema_source_watermark"
        )
    request_id = "p08-status-projection-verification"
    response = {
        "channel_called": False,
        "health_called": False,
        "legacy_namespace_written": False,
        "model_called": False,
        "ok": True,
        "operation": STATUS_OPERATION,
        "output": dict(payload),
        "private_content_returned": False,
        "profile_written": False,
        "provider_called": False,
        "request_id": request_id,
        "schema": SCHEMA,
        "session_written": False,
    }
    try:
        return parse_content_free_status_response(
            response,
            request_id=request_id,
            request_nonce=request_nonce,
            expected_scope_digest=expected_scope_digest,
        )
    except TemporalGatewayRejected as error:
        if error.status_stage is not None:
            raise
        raise _status_stage_rejected(
            "temporal_status_rejected", "response_projection"
        ) from None


def run_content_free_status_helper(
    config: object,
) -> ContentFreeTemporalGatewayStatus:
    invocation_nonce = secrets.token_hex(32)
    try:
        status_config = _coerce_status_runtime_config(config)
    except Exception:
        raise _parent_status_rejected(
            "temporal_status_rejected",
            "pre_socket_protected_config",
            invocation_nonce=invocation_nonce,
        ) from None
    try:
        source = Path(__file__).resolve(strict=True)
        core_root, deploy_root = content_free_status_pythonpath()
    except Exception:
        raise _parent_status_rejected(
            "temporal_status_unavailable",
            "pre_socket_source_identity",
            invocation_nonce=invocation_nonce,
        ) from None
    try:
        completed = subprocess.run(
            [
                "/usr/bin/env",
                "-i",
                "LANG=C",
                "LC_ALL=C",
                "PATH=/usr/bin",
                f"PYTHONPATH={os.pathsep.join((str(core_root), str(deploy_root)))}",
                "PYTHONDONTWRITEBYTECODE=1",
                f"{STATUS_INVOCATION_NONCE_ENV}={invocation_nonce}",
                "/usr/bin/python3",
                "-B",
                str(source),
                "--content-free-status",
            ],
            check=False,
            capture_output=True,
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/usr/sbin",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            text=True,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        raise _parent_status_rejected(
            "temporal_status_unavailable",
            "parent_timeout",
            invocation_nonce=invocation_nonce,
        ) from None
    except (OSError, subprocess.SubprocessError):
        raise _parent_status_rejected(
            "temporal_status_unavailable",
            "parent_spawn",
            invocation_nonce=invocation_nonce,
        ) from None
    if not completed.stdout:
        raise _parent_status_rejected(
            "temporal_status_unavailable",
            "parent_empty",
            invocation_nonce=invocation_nonce,
        )
    try:
        output_size = len(completed.stdout.encode("utf-8"))
    except UnicodeError:
        output_size = MAX_STATUS_HELPER_OUTPUT_BYTES + 1
    if output_size > MAX_STATUS_HELPER_OUTPUT_BYTES:
        raise _parent_status_rejected(
            "temporal_status_unavailable",
            "parent_oversize",
            invocation_nonce=invocation_nonce,
        )
    try:
        payload = json.loads(
            completed.stdout,
            object_pairs_hook=_strict_status_runtime_object,
        )
    except (UnicodeError, json.JSONDecodeError, _DuplicateStatusRuntimeKey):
        code = (
            "temporal_status_unavailable"
            if completed.returncode != 0
            else "temporal_status_rejected"
        )
        raise _parent_status_rejected(
            code,
            "parent_malformed",
            invocation_nonce=invocation_nonce,
        ) from None
    if completed.returncode != 0:
        try:
            rejection = parse_content_free_status_rejection(
                payload,
                expected_invocation_nonce=invocation_nonce,
            )
        except ValueError:
            raise _parent_status_rejected(
                "temporal_status_unavailable",
                "parent_malformed",
                invocation_nonce=invocation_nonce,
            ) from None
        raise TemporalGatewayRejected(
            "temporal_status_unavailable",
            retryable=True,
            status_stage=rejection.stage,
            status_rejection=rejection,
        )
    expected_scope_digest = content_free_scope_digest(
        binding_id=status_config.binding_id,
        principal_id=status_config.principal_id,
        namespace_id=status_config.namespace_id,
        channel_kind=status_config.channel_kind,
        channel_instance=status_config.channel_instance,
    )
    try:
        return parse_content_free_status_projection(
            payload,
            expected_scope_digest=expected_scope_digest,
        )
    except TemporalGatewayRejected as error:
        stage = error.status_stage or "response_projection"
        raise _parent_status_rejected(
            "temporal_status_rejected",
            stage,
            invocation_nonce=invocation_nonce,
        ) from None


def render_temporal_reply(command: TemporalCommand, response: Mapping[str, object]) -> str:
    output = response.get("output")
    if not isinstance(output, Mapping):
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    if command.action == "get":
        if output.get("state") == "empty" and output.get("fact_count") == 0:
            reply = "目前没有找到相关的临时信息。"
        elif (
            output.get("state") == "selected"
            and isinstance(output.get("fact_count"), int)
            and isinstance(output.get("context"), str)
        ):
            lines = output["context"].splitlines()[1:]
            if not lines:
                raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
            reply = "当前临时信息：\n" + "\n".join(lines)
        else:
            raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    elif command.action == "confirm":
        outcome = output.get("outcome")
        fact_id = output.get("fact_id")
        if not isinstance(outcome, str) or (fact_id is not None and not isinstance(fact_id, str)):
            raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
        suffix = "" if fact_id is None else f"（fact_id={fact_id}）"
        reply = f"临时信息变更已确认：{outcome}{suffix}"
    else:
        proposal_id = output.get("proposal_id")
        confirmation_code = output.get("confirmation_code")
        if not isinstance(proposal_id, str) or not isinstance(confirmation_code, str):
            raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
        reply = (
            "已准备临时信息变更；请在10分钟内发送：\n"
            f"/temporal confirm {proposal_id} {confirmation_code}"
        )
    if not reply or len(reply) > MAX_REPLY_CHARACTERS:
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    return reply


def usage_reply() -> str:
    return _USAGE


def unavailable_reply() -> str:
    return _UNAVAILABLE


def _write_content_free_status_rejection(
    stage: str,
    *,
    invocation_nonce: str,
    runtime_rejection: ContentFreeRuntimeRejection | None = None,
) -> None:
    rejection = ContentFreeStatusRejection.from_stage(
        stage,
        invocation_nonce=invocation_nonce,
        runtime_rejection=runtime_rejection,
    )
    sys.stdout.write(
        json.dumps(
            rejection.projection(),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


def main(argv: list[str] | None = None) -> int:
    selected = sys.argv[1:] if argv is None else argv
    if selected != ["--content-free-status"]:
        return 2
    invocation_nonce = os.environ.get(STATUS_INVOCATION_NONCE_ENV, "")
    if re.fullmatch(r"[0-9a-f]{64}", invocation_nonce) is None:
        return 2
    try:
        enter_content_free_status_identity()
    except Exception:
        _write_content_free_status_rejection(
            "pre_socket_privilege_identity",
            invocation_nonce=invocation_nonce,
        )
        return 1
    try:
        config = load_protected_status_runtime_config()
    except Exception:
        _write_content_free_status_rejection(
            "pre_socket_protected_config",
            invocation_nonce=invocation_nonce,
        )
        return 1
    try:
        status = query_content_free_status(config, request_nonce=invocation_nonce)
    except Exception as error:
        stage = (
            error.status_stage
            if isinstance(error, TemporalGatewayRejected)
            and error.status_stage in _STATUS_STAGE_POLICY
            else "response_projection"
        )
        _write_content_free_status_rejection(
            stage,
            invocation_nonce=invocation_nonce,
            runtime_rejection=(
                error.status_runtime_rejection
                if isinstance(error, TemporalGatewayRejected)
                else None
            ),
        )
        return 1
    sys.stdout.write(
        json.dumps(
            status.projection(),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
