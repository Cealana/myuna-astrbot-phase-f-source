#!/usr/bin/env python3
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import hmac
from http.client import HTTPConnection, HTTPException
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import time
from typing import Callable, Mapping
from uuid import uuid4

from degradation_shadow_enqueue import DegradationShadowJob
from gateway_degradation_protocol import (
    GatewayDegradationProtocolError,
    deterministic_core_unreachable_projection,
    deterministic_gateway_failure_provenance,
    deterministic_gateway_projection,
    unknown_core_failure_provenance,
    validate_core_failure_provenance,
    validate_core_failure_response_with_provenance,
    validate_safe_degradation,
)
from gateway_recovery_episode import (
    RECOVERY_NOTICE_TEXT,
    RecoveryEpisodeRejected,
    RecoveryEpisodeStore,
)
from gateway_post_reply import (
    PostConnectionFanout,
    ShadowJob,
    serve_accepted_connection,
)
from incident_history_runtime_adapter_v1 import build_incident_history_job
from context_window_policy import (
    ContextWindowPolicy,
    ContextWindowRejected,
    ConversationHistory,
    InMemoryContextStore,
    SqliteContextStore,
)

from myuna_core.channel_gateway import (
    GatewayEnvelopeError,
    SignedChannelEnvelope,
    sign_channel_event,
)
from myuna_core.identity import account_fingerprint
from myuna_core.memory_aware_turn_protocol import (
    FinalBranch,
    FinalValue,
    MemoryAwareTurnError,
    MemoryReceipt,
    MemoryRequest,
    MemoryResult,
    TurnStepRequest,
    advance_for_repair,
    advance_with_memory,
    complete_turn,
    memory_request_progress_fingerprint,
    preflight_memory_request,
)
from myuna_core.authenticated_conversation import AuthenticatedConversationContext
from myuna_core.external_context.contracts import (
    EgressSafetySignals,
    ExternalContextError,
    ExternalSummaryCandidate,
    ExternalSummaryJob,
    ExternalTurnProvenance,
)
from myuna_core.external_context.lifecycle_v3 import (
    RELEASE_BOUND_CONTEXT_OVERLAY_SCHEMA,
    RELEASE_BOUND_CONTEXT_SCHEMA,
    ReleaseBoundExternalContext,
    ReleaseBoundLifecycleRejected,
    ReleaseBoundSummaryCandidate,
    ReleaseBoundSummaryJob,
    ReleaseBoundTurnProvenance,
)
from myuna_core.external_context.policy_overlay import (
    load_selected_policy_overlay,
    release_digest_from_path,
)
from myuna_core.external_context.safety import enforce_external_egress_safety
from myuna_core.episodic_memory.contracts import (
    CompleteTurn,
    EpisodicMemoryError,
    PrefixCapsule,
    PrefixCompactionPolicy,
)
from myuna_core.episodic_memory.context import (
    PrefixCompactionPlan,
    verify_prefix_capsule,
)
from myuna_core.episodic_memory.trusted_time import read_current_boot_identity
from myuna_core.episodic_memory.diary_generation import (
    DiaryCapacityReceipt,
    DiaryGenerationCandidate,
    DiaryGenerationJob,
)
from myuna_core.owner_profile.contracts import OwnerProfileError
from myuna_core.owner_profile.write_intent import parse_profile_v2_structural_request
from myuna_core.episodic_memory.runtime_context import (
    RUNTIME_CONTEXT_SCHEMA,
    EpisodicRuntimeContext,
    EpisodicTurnProvenance,
)
from external_context_epoch import (
    ExternalEpochRejected,
    ExternalEpochStore,
)
from external_context_epoch_v3 import (
    ExternalEpochV3Binding,
    ExternalEpochV3Rejected,
    ExternalEpochV3Store,
)
from p07_d_release_set import (
    ProtectedReleaseSetRejected,
    load_protected_json_snapshot,
    load_protected_release_set_snapshot,
    require_same_release_set_snapshot,
    require_runtime_binding_projection,
    runtime_binding_digest,
)
from p07_d_runtime_readiness import publish_runtime_readiness
from p07_d_summary_worker import (
    BackgroundSummaryWorker,
    SummaryWorkerCycle,
)
from p07_reflective_diary_worker_v1 import DiaryProviderResult
from p08_temporal_gateway_v1 import (
    build_active_snapshot_request,
    parse_active_snapshot_response,
    parse_trusted_time_response,
    unresolved_active_snapshot,
    TemporalGatewayRejected,
    build_request as build_temporal_request,
    parse_temporal_command,
    render_temporal_reply,
    send_temporal_request,
    temporal_intent_grants_candidate_consent,
    unavailable_reply as temporal_unavailable_reply,
    usage_reply as temporal_usage_reply,
)
from p07_owner_private_memory_runtime_v1 import (
    MemoryDeliveryOutcome,
    OwnerPrivateMemorySelection,
    OwnerPrivateMemoryRuntime,
    load_selected_memory_configuration,
    require_precreated_runtime_root,
)
from p07_owner_day_diary_v2 import (
    OwnerPrivateMemorySelectionV4,
)
from telegram_runtime_config import (
    CHANNEL_KIND,
    CONFIG_PATH,
    CORE_CLIENT_ID,
    RuntimeConfigRejected as RuntimeRejected,
)
import telegram_runtime_config as runtime_config_contract
from turn_pacing_policy import BoundedTurnPacingPolicy, TurnPacingRejected
AUTHENTICATED_CONTEXT_SCHEMA_VERSION = "myuna.authenticated-conversation-context.v1"
CONTEXT_DATABASE_PATH = Path(
    "/var/lib/myuna-telegram-gateway/session-context/context.db"
)
RECOVERY_DATABASE_PATH = Path(
    "/var/lib/myuna-telegram-gateway/session-context/recovery-episode.db"
)
CONTEXT_NAMESPACE = "telegram-owner-private-v1"
CONTEXT_STORE_MODE_ENV = "MYUNA_SESSION_CONTEXT_STORE"
CORE_REQUEST_TIMEOUT_SECONDS = 165
GATEWAY_RESPONSE_SCHEMA = "myuna.gateway-response.v3"
DELIVERY_OUTCOME_SCHEMA = "myuna.telegram-delivery-outcome.v2"
EXTERNAL_EPOCH_SELECTOR_PATH = Path(
    "/etc/myuna-telegram-gateway/external-epoch-selector-v2.json"
)
EXTERNAL_EPOCH_ROOT = Path(
    "/var/lib/myuna-telegram-gateway/external-context-epochs"
)
P07_D_RELEASE_SET_PATH = Path(
    "/etc/myuna-telegram-gateway/p07-d-release-set-v1.json"
)
_EXTERNAL_EPOCH_GENERATIONS = {
    4: (
        "telegram-owner-private-external-v4",
        "telegram-owner-private-external-v1",
    ),
    5: (
        "telegram-owner-private-external-d-v1",
        "telegram-owner-private-external-v4",
    ),
    6: (
        "telegram-owner-private-external-d-v2",
        "telegram-owner-private-external-v4",
    ),
    7: (
        "telegram-owner-private-external-d-reset-v1",
        "telegram-owner-private-external-v4",
    ),
    8: (
        "telegram-owner-private-external-d-reset-v2",
        "telegram-owner-private-external-v4",
    ),
    9: (
        "telegram-owner-private-external-d-reset-v3",
        "telegram-owner-private-external-v4",
    ),
    10: (
        "telegram-owner-private-external-d-reset-v4",
        "telegram-owner-private-external-v4",
    ),
    11: (
        "telegram-owner-private-external-d-reset-v5",
        "telegram-owner-private-external-v4",
    ),
    12: (
        "telegram-owner-private-external-d-reset-v6",
        "telegram-owner-private-external-d-reset-v5",
    ),
    13: (
        "telegram-owner-private-external-d-reset-v7",
        "telegram-owner-private-external-d-reset-v5",
    ),
}
HYBRID_ENABLED_ENV = "MYUNA_P07_HYBRID_EXTERNAL_ENABLED"
HYBRID_PACING_SECONDS_ENV = "MYUNA_P07_HYBRID_PACING_SECONDS"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DIARY = re.compile(r"^/diary(?:[ \t]+([^\r\n]+))?$", re.IGNORECASE)
_BENCHMARK = re.compile(r"^/benchmark(?:[ \t]+([^\r\n]+))?$", re.IGNORECASE)
_BENCHMARK_CONFIRM = re.compile(r"^confirm[ \t]+([0-9a-f]{12})$", re.IGNORECASE)
_BENCHMARK_CANCEL = re.compile(r"^cancel[ \t]+([0-9a-f]{12})$", re.IGNORECASE)
_CHECK = re.compile(r"^/check(?:[ \t]+[^\r\n]+)?$", re.IGNORECASE)
_MAX_DIARY_SOURCE_CHARACTERS = 3_500
_MAX_REQUEST_BYTES = 32768
_MAX_CORE_RESPONSE_BYTES = 65536
_DELIVERY_TOKEN = re.compile(r"^[0-9a-f]{64}$")

VISUAL_EVENT_SCHEMA = "myuna.telegram-visual-evidence.v1"
VISUAL_EVENT_SOURCE = "gemini_visual_extraction"
VISUAL_PREFLIGHT_ROUTING = {
    "hybrid_external_generation": True,
    "visual_preflight": True,
}
_CONTEXT_PROJECTION_UNAVAILABLE_CODES = frozenset({
    "external_summary_required",
    "external_turn_already_pending",
    "external_context_unavailable",
})
MAX_VISUAL_OBSERVATION_CHARACTERS = 240
_VISUAL_SIGNATURE_DOMAIN = b"myuna-telegram-visual-event-v1\0"


def _profile_v2_control_reply(
    request: Mapping[str, object],
    delivery_token: str,
) -> str:
    action = request.get("action")
    if action == "propose_manifest":
        proposal_id = "profile-" + delivery_token[:24]
        return (
            f"已记录亲密度变更提案 {proposal_id} v1；"
            f"请回复“确认亲密度提案 {proposal_id} v1”后应用。"
        )
    if action == "confirm_manifest":
        return "已确认该亲密度提案；仅在本回复送达后应用。"
    if action == "cancel_manifest":
        return "已取消该亲密度提案；仅在本回复送达后记录。"
    if action == "freeze":
        return "已接受冻结亲密度请求；仅在本回复送达后生效。"
    if action == "unfreeze":
        return "已接受解冻亲密度请求；仅在本回复送达后生效。"
    if action == "rollback":
        return "已接受亲密度回滚请求；仅在本回复送达后生效。"
    raise RuntimeRejected("runtime rejected")


def _verify_visual_routing(
    routing: object,
    *,
    event_signature: object,
    signing_secret: bytes,
) -> dict[str, object]:
    if (
        not isinstance(routing, Mapping)
        or set(routing)
        != {
            "hybrid_external_generation",
            "visual_event",
            "visual_event_signature",
        }
        or routing["hybrid_external_generation"] is not True
        or not isinstance(event_signature, str)
        or _SHA256.fullmatch(event_signature) is None
    ):
        raise RuntimeRejected("runtime rejected")
    visual_event = routing["visual_event"]
    if (
        not isinstance(visual_event, Mapping)
        or set(visual_event)
        != {"caption_present", "observation", "schema", "source"}
        or visual_event["schema"] != VISUAL_EVENT_SCHEMA
        or visual_event["source"] != VISUAL_EVENT_SOURCE
        or not isinstance(visual_event["caption_present"], bool)
        or not isinstance(visual_event["observation"], str)
        or not visual_event["observation"].strip()
        or "\x00" in visual_event["observation"]
        or len(visual_event["observation"]) > MAX_VISUAL_OBSERVATION_CHARACTERS
    ):
        raise RuntimeRejected("runtime rejected")
    signature = routing["visual_event_signature"]
    if not isinstance(signature, str) or _SHA256.fullmatch(signature) is None:
        raise RuntimeRejected("runtime rejected")
    canonical = json.dumps(
        dict(visual_event),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    expected = hmac.new(
        signing_secret,
        _VISUAL_SIGNATURE_DOMAIN
        + event_signature.encode("ascii")
        + b"\0"
        + canonical,
        sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise RuntimeRejected("runtime rejected")
    return dict(visual_event)


class CoreUnavailable(RuntimeError):
    """Loopback Core was unavailable or returned an unsafe response."""

    def __init__(
        self,
        projection: object,
        *,
        projection_source: str,
        failure_provenance: object | None = None,
        http_status: int | None = None,
    ) -> None:
        super().__init__("core unavailable")
        self.projection = validate_safe_degradation(projection)
        if projection_source not in {"core", "gateway"}:
            raise ValueError("invalid degradation projection source")
        self.projection_source = projection_source
        if failure_provenance is None:
            if projection_source == "gateway":
                failure_provenance = deterministic_gateway_failure_provenance(
                    str(self.projection["safe_detail_code"])
                )
            else:
                failure_provenance = unknown_core_failure_provenance()
        self.failure_provenance = validate_core_failure_provenance(
            failure_provenance
        )
        if http_status is not None and (
            type(http_status) is not int or not 100 <= http_status <= 599
        ):
            raise ValueError("invalid Core HTTP status")
        self.http_status = http_status


@dataclass(frozen=True, slots=True)
class ExternalEpochSelection:
    database_path: Path
    epoch_id: str
    generation: int
    previous_epoch_bundle_digest: str
    previous_epoch_bundle_schema: str
    previous_epoch_id: str

    @classmethod
    def from_payload(cls, payload: object) -> "ExternalEpochSelection":
        required = {
            "schema",
            "status",
            "channel_kind",
            "client_id",
            "database_path",
            "epoch_id",
            "generation",
            "previous_epoch_bundle_digest",
            "previous_epoch_bundle_schema",
            "previous_epoch_id",
        }
        if not isinstance(payload, dict) or set(payload) != required:
            raise RuntimeRejected("runtime rejected")
        if payload["schema"] != "myuna.external-epoch-selector.v2":
            raise RuntimeRejected("runtime rejected")
        if payload["status"] != "active":
            raise RuntimeRejected("runtime rejected")
        if payload["channel_kind"] != CHANNEL_KIND:
            raise RuntimeRejected("runtime rejected")
        if payload["client_id"] != CORE_CLIENT_ID:
            raise RuntimeRejected("runtime rejected")
        epoch_id = payload["epoch_id"]
        previous_epoch_id = payload["previous_epoch_id"]
        previous_epoch_bundle_digest = payload["previous_epoch_bundle_digest"]
        previous_epoch_bundle_schema = payload["previous_epoch_bundle_schema"]
        generation = payload["generation"]
        database_path_value = payload["database_path"]
        if not isinstance(epoch_id, str) or _SAFE_ID.fullmatch(epoch_id) is None:
            raise RuntimeRejected("runtime rejected")
        if (
            not isinstance(previous_epoch_id, str)
            or _SAFE_ID.fullmatch(previous_epoch_id) is None
            or previous_epoch_id == epoch_id
        ):
            raise RuntimeRejected("runtime rejected")
        if (
            not isinstance(previous_epoch_bundle_digest, str)
            or _SHA256.fullmatch(previous_epoch_bundle_digest) is None
        ):
            raise RuntimeRejected("runtime rejected")
        if previous_epoch_bundle_schema != "myuna.external-epoch-immutable-bundle.v1":
            raise RuntimeRejected("runtime rejected")
        if type(generation) is not int or generation not in _EXTERNAL_EPOCH_GENERATIONS:
            raise RuntimeRejected("runtime rejected")
        expected_epoch_id, expected_previous_epoch_id = _EXTERNAL_EPOCH_GENERATIONS[generation]
        if epoch_id != expected_epoch_id or previous_epoch_id != expected_previous_epoch_id:
            raise RuntimeRejected("runtime rejected")
        if not isinstance(database_path_value, str):
            raise RuntimeRejected("runtime rejected")
        database_path = Path(database_path_value)
        expected_path = EXTERNAL_EPOCH_ROOT / epoch_id / "epoch.db"
        if (
            not database_path.is_absolute()
            or database_path != expected_path
            or str(database_path) != database_path_value
        ):
            raise RuntimeRejected("runtime rejected")
        return cls(
            database_path=database_path,
            epoch_id=epoch_id,
            generation=generation,
            previous_epoch_bundle_digest=previous_epoch_bundle_digest,
            previous_epoch_bundle_schema=previous_epoch_bundle_schema,
            previous_epoch_id=previous_epoch_id,
        )


def diary_command_is_explicit(message_text: object) -> bool:
    if not isinstance(message_text, str):
        return False
    candidate = message_text.strip()
    match = _DIARY.fullmatch(candidate)
    if match is None:
        return False
    parameter = match.group(1)
    return parameter is None or (
        bool(parameter.strip())
        and len(parameter.strip()) <= _MAX_DIARY_SOURCE_CHARACTERS
        and "\x00" not in parameter
    )


def benchmark_intent_grants_profile_consent(message_text: object) -> bool:
    """Recognize only Core's Benchmark-only Profile mutation grammar."""

    if not isinstance(message_text, str):
        return False
    candidate = message_text.strip()
    match = _BENCHMARK.fullmatch(candidate)
    if match is None or match.group(1) is None:
        return False
    parameter = match.group(1).strip()
    if _BENCHMARK_CONFIRM.fullmatch(parameter) or _BENCHMARK_CANCEL.fullmatch(parameter):
        return True
    return bool(
        parameter
        and not parameter.casefold().startswith(("confirm", "cancel"))
        and len(parameter) <= _MAX_DIARY_SOURCE_CHARACTERS
        and "\x00" not in parameter
    )


def check_command_is_explicit(message_text: object) -> bool:
    """Recognize only Core's exact, whole-message /Check command grammar."""

    return (
        isinstance(message_text, str)
        and _CHECK.fullmatch(message_text.strip()) is not None
    )


def _audit_stage(code: str) -> None:
    """Emit fixed stage codes only; never include event or reply values."""

    print(f"telegram owner runtime gateway stage={code}", flush=True)


def _audit_trace_marker(trace_id: str, stage: str, status: str) -> None:
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", trace_id) is None:
        raise RuntimeRejected("runtime rejected")
    if stage not in {
        "af_unix_request_accepted",
        "delivery_callback_received",
        "factual_close_committed",
        "factual_close_cancelled",
        "factual_close_replayed",
    }:
        raise RuntimeRejected("runtime rejected")
    if status not in {"succeeded", "cancelled", "replayed"}:
        raise RuntimeRejected("runtime rejected")
    print(
        "myuna_e2e_marker version=1 "
        f"trace_id={trace_id} stage={stage} attempt=1 round=0 status={status}",
        flush=True,
    )


def _build_context_store() -> InMemoryContextStore | SqliteContextStore:
    mode = os.environ.get(CONTEXT_STORE_MODE_ENV, "memory")
    if mode == "memory":
        return InMemoryContextStore()
    if mode == "sqlite-v1":
        return SqliteContextStore(
            CONTEXT_DATABASE_PATH,
            namespace=CONTEXT_NAMESPACE,
        )
    raise RuntimeRejected("runtime rejected")


def _load_external_epoch_selection() -> ExternalEpochSelection:
    return ExternalEpochSelection.from_payload(
        _load_protected_json(EXTERNAL_EPOCH_SELECTOR_PATH)
    )


def _load_external_epoch_selection_snapshot(
    *,
    expected_gid: int,
) -> tuple[ExternalEpochSelection, str]:
    snapshot = load_protected_json_snapshot(
        EXTERNAL_EPOCH_SELECTOR_PATH,
        expected_uid=0,
        expected_gid=expected_gid,
        expected_mode=0o640,
    )
    return ExternalEpochSelection.from_payload(snapshot.payload), snapshot.file_digest


def _commit_reply_best_effort(
    history: ConversationHistory,
    conversation_id: str,
    messages: list[dict[str, str]],
    reply: str,
) -> bool:
    try:
        history.commit_reply(conversation_id, messages, reply)
        return True
    except ContextWindowRejected:
        _audit_stage("context_persistence_degraded")
        return False


RuntimeConfig = runtime_config_contract.RuntimeConfig


def _recovery_scope_key(config: RuntimeConfig) -> str:
    canonical_scope = "\0".join(
        (
            config.channel_kind,
            config.channel_instance,
            config.binding_id,
            config.principal_id,
            config.namespace_id,
        )
    ).encode("utf-8")
    return "scope-" + sha256(
        b"myuna-telegram-recovery-scope-v1\0" + canonical_scope
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class RuntimeDecision:
    event_id: str
    channel_kind: str
    channel_instance: str
    conversation_id: str
    occurred_at: datetime
    nonce_fingerprint: str
    payload_sha256: str
    trace_id: str
    account_fingerprint: str = field(repr=False)
    message_text: str = field(repr=False)
    visual_event: Mapping[str, object] | None = field(default=None, repr=False)
    hybrid_external_generation: bool = False


@dataclass(frozen=True, slots=True)
class CoreReply:
    reply: str
    actual_route: str
    provenance: (
        ExternalTurnProvenance
        | ReleaseBoundTurnProvenance
        | EpisodicTurnProvenance
        | None
    ) = None


@dataclass(frozen=True, slots=True)
class PendingDelivery:
    context: AuthenticatedConversationContext
    epoch_token: object
    provenance: ExternalTurnProvenance
    reply: str = field(repr=False)


def run_dynamic_prefix_capsule_generation(
    raw_turns: tuple[CompleteTurn, ...],
    *,
    plan: PrefixCompactionPlan,
    archive_id: str,
    archive_head_digest: str,
    policy: PrefixCompactionPolicy,
    generator_version: str,
    model_provider_class: str,
    trusted_created_at_utc: datetime,
    token_counter: Callable[[tuple[Mapping[str, str], ...]], int] | None,
    generate: Callable[
        [tuple[CompleteTurn, ...], bool],
        Mapping[str, object],
    ],
    commit: Callable[
        [
            PrefixCapsule,
            tuple[PrefixCapsule, str],
            Callable[[tuple[Mapping[str, str], ...]], int] | None,
        ],
        str,
    ],
) -> PrefixCapsule:
    """Run the inactive injected-only direct-from-raw capsule boundary."""

    if (
        not raw_turns
        or plan.action != "generate_prefix_capsule"
        or plan.prefix_end < 1
        or plan.prefix_end > len(raw_turns)
        or tuple(turn.draft.sequence for turn in raw_turns)
        != tuple(range(1, len(raw_turns) + 1))
    ):
        raise EpisodicMemoryError("prefix_capsule_raw_prefix_rejected")
    raw_prefix = tuple(
        turn
        for turn in raw_turns[: plan.prefix_end]
        if turn.model_history_eligible
    )
    if not raw_prefix:
        raise EpisodicMemoryError("prefix_capsule_raw_prefix_rejected")
    capsule: PrefixCapsule | None = None
    receipt: tuple[PrefixCapsule, str] | None = None
    for repair in (False, True):
        try:
            candidate = PrefixCapsule.from_payload(generate(raw_prefix, repair))
            if (
                candidate.generator_version != generator_version
                or candidate.model_provider_class != model_provider_class
                or candidate.created_at_utc != trusted_created_at_utc
            ):
                raise EpisodicMemoryError(
                    "prefix_capsule_generation_binding_mismatch"
                )
            verified = verify_prefix_capsule(
                candidate,
                turns=raw_turns,
                archive_id=archive_id,
                archive_head_digest=archive_head_digest,
                policy=policy,
                token_counter=token_counter,
                expected_generator_version=generator_version,
                expected_model_provider_class=model_provider_class,
                expected_created_at_utc=trusted_created_at_utc,
            )
            canonical_candidate = verified[0]
            if (
                canonical_candidate.source_end != plan.prefix_end
                or canonical_candidate.source_snapshot_turn_count != len(raw_turns)
                or canonical_candidate.source_snapshot_head_digest
                != archive_head_digest
            ):
                raise EpisodicMemoryError(
                    "prefix_capsule_generation_binding_mismatch"
                )
            capsule = canonical_candidate
            receipt = verified
            break
        except EpisodicMemoryError:
            if repair:
                raise
    if capsule is None or receipt is None:
        raise EpisodicMemoryError("prefix_capsule_generation_failed")
    persisted = commit(capsule, receipt, token_counter)
    if persisted != capsule.capsule_digest:
        raise EpisodicMemoryError("prefix_capsule_commit_receipt_mismatch")
    return capsule


def run_memory_aware_turn_loop(
    initial_turn: TurnStepRequest,
    *,
    provider_step: Callable[
        [TurnStepRequest, bool],
        tuple[MemoryRequest | FinalBranch, int],
    ],
    memory_read: Callable[
        [MemoryRequest],
        tuple[MemoryResult, MemoryReceipt],
    ],
    monotonic_ns: Callable[[], int],
) -> FinalValue:
    """Run the inactive, injected-only memory-aware turn state machine."""

    turn = initial_turn
    repair = False
    seen_requests: set[str] = set()

    def require_time() -> None:
        current = monotonic_ns()
        if (
            isinstance(current, bool)
            or not isinstance(current, int)
            or current < 0
            or current >= turn.budget.absolute_deadline_ns
        ):
            raise MemoryAwareTurnError("absolute_deadline_exhausted")

    while True:
        require_time()
        try:
            branch, provider_attempts = provider_step(turn, repair)
        except MemoryAwareTurnError as exc:
            require_time()
            if not exc.repairable or exc.attempts < 1:
                raise
            turn = advance_for_repair(turn, provider_attempts=exc.attempts)
            repair = True
            continue
        require_time()

        if isinstance(branch, MemoryRequest):
            preflight_memory_request(
                turn,
                branch,
                provider_attempts=provider_attempts,
            )
            progress_key = memory_request_progress_fingerprint(branch)
            if progress_key in seen_requests:
                raise MemoryAwareTurnError("memory_request_no_progress")
            seen_requests.add(progress_key)
            result, receipt = memory_read(branch)
            require_time()
            turn = advance_with_memory(
                turn,
                branch,
                result,
                receipt,
                provider_attempts=provider_attempts,
            )
            repair = False
            continue

        if not isinstance(branch, FinalBranch):
            raise MemoryAwareTurnError("provider_branch_type_invalid")
        try:
            return complete_turn(
                turn,
                branch,
                provider_attempts=provider_attempts,
            )
        except MemoryAwareTurnError as exc:
            if not exc.repairable:
                raise
            turn = advance_for_repair(
                turn,
                provider_attempts=provider_attempts,
            )
            repair = True


def stage_memory_aware_profile_intents(
    memory_runtime: OwnerPrivateMemoryRuntime,
    *,
    delivery_token: str,
    final: FinalValue,
) -> None:
    """Bind inactive typed server intents to an already prepared delivery."""

    if (
        type(final) is not FinalValue
        or _DELIVERY_TOKEN.fullmatch(delivery_token) is None
    ):
        raise RuntimeRejected("runtime rejected")
    memory_runtime.stage_profile_server_intents(
        delivery_token,
        final.server_intents,
    )


def _hybrid_enabled(environ: Mapping[str, str] | None = None) -> bool:
    source = os.environ if environ is None else environ
    raw = source.get(HYBRID_ENABLED_ENV, "false").strip().lower()
    if raw not in {"true", "false"}:
        raise RuntimeRejected("runtime rejected")
    return raw == "true"


def _pacing_policy(environ: Mapping[str, str] | None = None) -> tuple[BoundedTurnPacingPolicy, float]:
    source = os.environ if environ is None else environ
    try:
        requested = float(source.get(HYBRID_PACING_SECONDS_ENV, "2"))
        policy = BoundedTurnPacingPolicy(maximum_delay_seconds=5.0)
        policy.plan(requested_delay_seconds=requested)
    except (ValueError, TurnPacingRejected):
        raise RuntimeRejected("runtime rejected") from None
    return policy, requested


def _authenticated_context(decision: RuntimeDecision, config: RuntimeConfig) -> AuthenticatedConversationContext:
    return AuthenticatedConversationContext.from_payload(
        build_authenticated_context(decision, config),
        authenticated_client_id=CORE_CLIENT_ID,
        authenticated_channel_kind=CHANNEL_KIND,
    )


def _delivery_token(signing_secret: bytes, context: AuthenticatedConversationContext) -> str:
    return hmac.new(
        signing_secret,
        b"myuna-p07-delivery-ack-v2\0" + context.trace_id.encode("ascii"),
        sha256,
    ).hexdigest()


def _trace_bound_delivery_token(signing_secret: bytes, trace_id: object) -> str:
    if not isinstance(trace_id, str) or _SAFE_ID.fullmatch(trace_id) is None:
        raise RuntimeRejected("runtime rejected")
    return hmac.new(
        signing_secret,
        b"myuna-p07-delivery-ack-v2\0" + trace_id.encode("ascii"),
        sha256,
    ).hexdigest()


def bounded_actual_route(payload: Mapping[str, object]) -> str:
    """Map Core metadata to a content-free enum used only by Route Shadow."""

    provider = payload.get("provider")
    model = payload.get("model")
    if provider == "deepseek" and model == "deepseek-v4-flash":
        return "deepseek_default"
    if provider == "deepseek" and model == "deepseek-v4-pro":
        return "deepseek_pro"
    return "unknown"


def _load_protected_json(path: Path) -> object:
    try:
        metadata = path.stat()
        mode = stat.S_IMODE(metadata.st_mode)
        if metadata.st_uid != 0 or mode & 0o027:
            raise RuntimeRejected("runtime rejected")
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise RuntimeRejected("runtime rejected") from None


def _read_credential(name: str) -> bytes:
    directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if not directory:
        raise RuntimeRejected("runtime rejected")
    try:
        secret = (Path(directory) / name).read_bytes().strip()
    except OSError:
        raise RuntimeRejected("runtime rejected") from None
    if len(secret) < 32:
        raise RuntimeRejected("runtime rejected")
    return secret


def evaluate_runtime_envelope(
    payload: object,
    *,
    config: RuntimeConfig,
    signing_secret: bytes,
    identity_pepper: bytes,
    now: datetime,
) -> RuntimeDecision:
    try:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("clock is not timezone-aware")
        current = now.astimezone(timezone.utc)
        hybrid_external_generation = False
        visual_routing: object | None = None
        visual_event: dict[str, object] | None = None
        signed_payload = payload
        if isinstance(payload, Mapping) and "routing" in payload:
            if set(payload) != {"event", "routing", "signature"}:
                raise RuntimeRejected("runtime rejected")
            routing = payload["routing"]
            if routing == {"hybrid_external_generation": True}:
                pass
            else:
                visual_routing = routing
            hybrid_external_generation = True
            signed_payload = {
                "event": payload["event"],
                "signature": payload["signature"],
            }
        envelope = SignedChannelEnvelope.from_payload(signed_payload)
        expected_signature = sign_channel_event(envelope.event, signing_secret)
        if not hmac.compare_digest(envelope.signature, expected_signature):
            raise RuntimeRejected("runtime rejected")
        if visual_routing is not None:
            visual_event = _verify_visual_routing(
                visual_routing,
                event_signature=envelope.signature,
                signing_secret=signing_secret,
            )
        event = envelope.event
        if event.channel != config.channel_kind:
            raise RuntimeRejected("runtime rejected")
        if event.channel_instance != config.channel_instance:
            raise RuntimeRejected("runtime rejected")
        if event.occurred_at < current - timedelta(minutes=5):
            raise RuntimeRejected("runtime rejected")
        if event.occurred_at > current + timedelta(seconds=30):
            raise RuntimeRejected("runtime rejected")
        if event.conversation_kind != "private":
            raise RuntimeRejected("runtime rejected")
        if event.delivery_capabilities != ("text",):
            raise RuntimeRejected("runtime rejected")
        consent = event.consent_context
        if consent.memory_candidate or consent.tools or consent.media_processing:
            raise RuntimeRejected("runtime rejected")
        fingerprint = account_fingerprint(
            event.channel,
            event.actor_account_id,
            identity_pepper,
        )
        canonical_envelope = json.dumps(
            (
                dict(payload)
                if visual_event is not None and isinstance(payload, Mapping)
                else envelope.as_payload()
            ),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return RuntimeDecision(
            event_id=event.event_id,
            channel_kind=event.channel,
            channel_instance=event.channel_instance,
            conversation_id=event.conversation_id,
            occurred_at=event.occurred_at,
            nonce_fingerprint=sha256(
                b"myuna-channel-nonce-v1\0" + event.nonce.encode("ascii")
            ).hexdigest(),
            payload_sha256=sha256(canonical_envelope).hexdigest(),
            trace_id=event.trace_id,
            hybrid_external_generation=hybrid_external_generation,
            account_fingerprint=fingerprint,
            message_text=event.message_text.strip(),
            visual_event=visual_event,
        )
    except (GatewayEnvelopeError, RuntimeRejected, TypeError, ValueError):
        raise RuntimeRejected("runtime rejected") from None


def _psql_scalar(sql: str, variables: dict[str, str]) -> str:
    command = [
        "/usr/bin/psql",
        "--dbname=myuna_dev",
        "--username=myuna_telegram_gateway_app",
        "--host=/var/run/postgresql",
        "--no-psqlrc",
        "--no-align",
        "--tuples-only",
        "--set=ON_ERROR_STOP=1",
    ]
    for key, value in variables.items():
        command.append(f"--set={key}={value}")
    result = subprocess.run(
        command,
        input=sql + "\n",
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        _audit_stage("database_rejected")
        raise RuntimeRejected("runtime rejected")
    return result.stdout.strip()


def claim_inbound(decision: RuntimeDecision, now: datetime) -> bool:
    expires_at = now.astimezone(timezone.utc) + timedelta(minutes=9)
    result = _psql_scalar(
        "SELECT gateway_runtime.claim_telegram_inbound_event("
        ":'channel_instance', :'event_id', :'nonce_fingerprint', "
        ":'payload_sha256', :'occurred_at'::timestamptz, :'expires_at'::timestamptz);",
        {
            "channel_instance": decision.channel_instance,
            "event_id": decision.event_id,
            "nonce_fingerprint": decision.nonce_fingerprint,
            "payload_sha256": decision.payload_sha256,
            "occurred_at": decision.occurred_at.isoformat(timespec="microseconds"),
            "expires_at": expires_at.isoformat(timespec="microseconds"),
        },
    )
    return result == "t"


def record_outcome(decision: RuntimeDecision, outcome: str, code: str) -> bool:
    result = _psql_scalar(
        "SELECT gateway_runtime.record_telegram_inbound_outcome("
        ":'channel_instance', :'event_id', :'outcome', :'code');",
        {
            "channel_instance": decision.channel_instance,
            "event_id": decision.event_id,
            "outcome": outcome,
            "code": code,
        },
    )
    return result == "t"


def resolve_verified_owner(decision: RuntimeDecision, config: RuntimeConfig) -> bool:
    result = _psql_scalar(
        "SELECT concat_ws('|', binding_id, principal_id, namespace_id) "
        "FROM gateway_runtime.resolve_verified_telegram_owner_binding("
        ":'account_fingerprint');",
        {
            "account_fingerprint": decision.account_fingerprint,
        },
    )
    expected = f"{config.binding_id}|{config.principal_id}|{config.namespace_id}"
    return hmac.compare_digest(result, expected)


class SlidingRateLimiter:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self._events: dict[str, deque[datetime]] = defaultdict(deque)

    def allow(self, principal_id: str, now: datetime) -> bool:
        cutoff = now - timedelta(minutes=10)
        events = self._events[principal_id]
        while events and events[0] < cutoff:
            events.popleft()
        if len(events) >= self.limit:
            return False
        events.append(now)
        return True


def request_id_for_decision(decision: RuntimeDecision) -> str:
    request_digest = sha256(
        (decision.channel_kind + "\0" + decision.event_id + "\0" + decision.trace_id).encode(
            "utf-8"
        )
    ).hexdigest()[:32]
    return "gateway-" + request_digest


def build_authenticated_context(
    decision: RuntimeDecision,
    config: RuntimeConfig,
) -> dict[str, object]:
    return {
        "authority_level": "owner",
        "binding_id": config.binding_id,
        "channel_instance": decision.channel_instance,
        "channel_kind": decision.channel_kind,
        "client_id": CORE_CLIENT_ID,
        "consent": {
            "media_processing": False,
            "memory_candidate": benchmark_intent_grants_profile_consent(
                decision.message_text
            )
            or temporal_intent_grants_candidate_consent(decision.message_text),
            "tools": False,
        },
        "conversation_id": decision.conversation_id,
        "conversation_kind": "private",
        "correlation_id": decision.trace_id,
        "delivery_capabilities": ["text"],
        "event_id": decision.event_id,
        "namespace_id": config.namespace_id,
        "occurred_at": decision.occurred_at.isoformat(timespec="microseconds"),
        "principal_id": config.principal_id,
        "request_id": request_id_for_decision(decision),
        "schema_version": AUTHENTICATED_CONTEXT_SCHEMA_VERSION,
        "trace_id": decision.trace_id,
    }


class LoopbackCoreClient:
    def __init__(self, config: RuntimeConfig, token: bytes) -> None:
        try:
            self.token = token.decode("ascii")
        except UnicodeDecodeError:
            raise RuntimeRejected("runtime rejected") from None
        self.config = config

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        decision: RuntimeDecision,
        external_context: Mapping[str, object] | None = None,
    ) -> CoreReply:
        authenticated_context = build_authenticated_context(
            decision,
            self.config,
        )
        request_payload: dict[str, object] = {
            "authenticated_context": authenticated_context,
            "conversation": {
                "high_quality": False,
                "messages": messages,
                "mode": "myuna",
                "risk_level": "low",
                "synthetic_memory": False,
                "task_class": "ordinary_chat",
            },
        }
        if external_context is not None:
            if messages != [{"role": "user", "content": decision.message_text}]:
                raise RuntimeRejected("runtime rejected")
            request_payload["external_context"] = dict(external_context)
        body = json.dumps(
            request_payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        connection = HTTPConnection(
            self.config.core_host,
            self.config.core_port,
            timeout=CORE_REQUEST_TIMEOUT_SECONDS,
        )
        try:
            connection.request(
                "POST",
                "/v1/chat",
                body=body,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                    "X-Myuna-Channel-Kind": CHANNEL_KIND,
                    "X-Myuna-Client-Id": CORE_CLIENT_ID,
                },
            )
            response = connection.getresponse()
            response_status = response.status
            raw = response.read(_MAX_CORE_RESPONSE_BYTES + 1)
        except (OSError, HTTPException):
            raise CoreUnavailable(
                deterministic_core_unreachable_projection(),
                projection_source="gateway",
            ) from None
        finally:
            connection.close()
        if len(raw) > _MAX_CORE_RESPONSE_BYTES:
            raise CoreUnavailable(
                deterministic_gateway_projection("gateway-core-invalid-response"),
                projection_source="gateway",
            )
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise CoreUnavailable(
                deterministic_gateway_projection("gateway-core-invalid-response"),
                projection_source="gateway",
            ) from None
        if response_status != 200:
            try:
                projection, failure_provenance = (
                    validate_core_failure_response_with_provenance(
                        response_status, payload
                    )
                )
            except GatewayDegradationProtocolError:
                raise CoreUnavailable(
                    deterministic_gateway_projection("gateway-core-invalid-response"),
                    projection_source="gateway",
                ) from None
            raise CoreUnavailable(
                projection,
                projection_source="core",
                failure_provenance=failure_provenance,
                http_status=response_status,
            )
        if not isinstance(payload, dict):
            raise CoreUnavailable(
                deterministic_gateway_projection("gateway-core-invalid-response"),
                projection_source="gateway",
            )
        reply = payload.get("reply")
        synthetic = payload.get("synthetic_memory")
        provenance_payload = payload.get("external_turn_provenance")
        if (
            not isinstance(reply, str)
            or not reply.strip()
            or len(reply) > 4000
            or not isinstance(synthetic, dict)
            or synthetic.get("used") is not False
        ):
            raise CoreUnavailable(
                deterministic_gateway_projection("gateway-core-invalid-response"),
                projection_source="gateway",
            )
        provenance = None
        try:
            if external_context is None:
                if provenance_payload is not None:
                    raise ExternalContextError("unexpected_turn_provenance")
            elif external_context.get("schema") in {
                RELEASE_BOUND_CONTEXT_SCHEMA,
                RELEASE_BOUND_CONTEXT_OVERLAY_SCHEMA,
            }:
                authenticated = _authenticated_context(decision, self.config)
                bound_context = ReleaseBoundExternalContext.from_payload(
                    external_context,
                    context=authenticated,
                )
                provenance = ReleaseBoundTurnProvenance.from_payload(
                    provenance_payload
                )
                if (
                    provenance.release_set_id != bound_context.release_set_id
                    or provenance.policy_overlay_id
                    != bound_context.policy_overlay_id
                    or provenance.provenance.epoch_id
                    != bound_context.envelope.epoch_id
                    or provenance.provenance.epoch_revision
                    != bound_context.envelope.epoch_revision
                ):
                    raise ExternalContextError("turn_provenance_binding_mismatch")
            elif external_context.get("schema") == RUNTIME_CONTEXT_SCHEMA:
                authenticated = _authenticated_context(decision, self.config)
                episodic_context = EpisodicRuntimeContext.from_payload(
                    external_context,
                    authenticated_context=authenticated,
                )
                provenance = EpisodicTurnProvenance.from_payload(provenance_payload)
                if (
                    provenance.parent_release_set_id
                    != episodic_context.parent_release_set_id
                    or provenance.policy_overlay_id
                    != episodic_context.policy_overlay_id
                    or provenance.parent_epoch_id != episodic_context.parent_epoch_id
                    or provenance.parent_epoch_revision
                    != episodic_context.parent_epoch_revision
                    or provenance.archive_id != episodic_context.archive_id
                    or provenance.archive_head_digest
                    != episodic_context.archive_head_digest
                    or provenance.archive_turn_count
                    != episodic_context.archive_turn_count
                ):
                    raise ExternalContextError("turn_provenance_binding_mismatch")
            else:
                provenance = ExternalTurnProvenance.from_payload(provenance_payload)
                if (
                    provenance.epoch_id != external_context.get("epoch_id")
                    or provenance.epoch_revision
                    != external_context.get("epoch_revision")
                ):
                    raise ExternalContextError("turn_provenance_binding_mismatch")
        except (
            EpisodicMemoryError,
            ExternalContextError,
            ReleaseBoundLifecycleRejected,
        ):
            raise CoreUnavailable(
                deterministic_gateway_projection("gateway-core-invalid-response"),
                projection_source="gateway",
            ) from None
        return CoreReply(
            reply=reply.strip(),
            actual_route=bounded_actual_route(payload),
            provenance=provenance,
        )

    def summarize(self, job: ExternalSummaryJob) -> ExternalSummaryCandidate:
        body = json.dumps(
            {"summary_job": job.as_payload()},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        connection = HTTPConnection(
            self.config.core_host,
            self.config.core_port,
            timeout=CORE_REQUEST_TIMEOUT_SECONDS,
        )
        try:
            connection.request(
                "POST",
                "/v1/external-summary",
                body=body,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                    "X-Myuna-Channel-Kind": CHANNEL_KIND,
                    "X-Myuna-Client-Id": CORE_CLIENT_ID,
                },
            )
            response = connection.getresponse()
            response_status = response.status
            raw = response.read(_MAX_CORE_RESPONSE_BYTES + 1)
        except (OSError, HTTPException):
            raise CoreUnavailable(
                deterministic_core_unreachable_projection(),
                projection_source="gateway",
            ) from None
        finally:
            connection.close()
        if len(raw) > _MAX_CORE_RESPONSE_BYTES:
            raise RuntimeRejected("runtime rejected")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeRejected("runtime rejected") from None
        if response_status != 200:
            try:
                projection, failure_provenance = (
                    validate_core_failure_response_with_provenance(
                        response_status, payload
                    )
                )
            except GatewayDegradationProtocolError:
                raise RuntimeRejected("runtime rejected") from None
            raise CoreUnavailable(
                projection,
                projection_source="core",
                failure_provenance=failure_provenance,
                http_status=response_status,
            )
        if (
            not isinstance(payload, Mapping)
            or payload.get("provider") != "deepseek"
            or payload.get("model") != "deepseek-v4-flash"
            or payload.get("route_reason") != "p07_external_rolling_summary"
        ):
            raise RuntimeRejected("runtime rejected")
        try:
            candidate = ExternalSummaryCandidate.from_payload(
                payload.get("summary_candidate")
            )
        except ExternalContextError:
            raise RuntimeRejected("runtime rejected") from None
        if candidate.job_digest != job.digest:
            raise RuntimeRejected("runtime rejected")
        return candidate

    def summarize_release_bound(
        self,
        job: ReleaseBoundSummaryJob,
    ) -> ReleaseBoundSummaryCandidate:
        body = json.dumps(
            {"summary_job": job.as_payload()},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        connection = HTTPConnection(
            self.config.core_host,
            self.config.core_port,
            timeout=CORE_REQUEST_TIMEOUT_SECONDS,
        )
        try:
            connection.request(
                "POST",
                "/v1/external-summary",
                body=body,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                    "X-Myuna-Channel-Kind": CHANNEL_KIND,
                    "X-Myuna-Client-Id": CORE_CLIENT_ID,
                },
            )
            response = connection.getresponse()
            response_status = response.status
            raw = response.read(_MAX_CORE_RESPONSE_BYTES + 1)
        except (OSError, HTTPException):
            raise CoreUnavailable(
                deterministic_core_unreachable_projection(),
                projection_source="gateway",
            ) from None
        finally:
            connection.close()
        if len(raw) > _MAX_CORE_RESPONSE_BYTES:
            raise RuntimeRejected("runtime rejected")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeRejected("runtime rejected") from None
        if response_status != 200:
            try:
                projection, failure_provenance = (
                    validate_core_failure_response_with_provenance(
                        response_status, payload
                    )
                )
            except GatewayDegradationProtocolError:
                raise RuntimeRejected("runtime rejected") from None
            raise CoreUnavailable(
                projection,
                projection_source="core",
                failure_provenance=failure_provenance,
                http_status=response_status,
            )
        if (
            not isinstance(payload, Mapping)
            or payload.get("provider") != "deepseek"
            or payload.get("model") != "deepseek-v4-flash"
            or payload.get("route_reason") != "p07_external_rolling_summary"
        ):
            raise RuntimeRejected("runtime rejected")
        try:
            candidate = ReleaseBoundSummaryCandidate.from_payload(
                payload.get("summary_candidate")
            )
            candidate.validate_for(job)
        except ReleaseBoundLifecycleRejected:
            raise RuntimeRejected("runtime rejected") from None
        return candidate

    def generate_reflective_diary(
        self,
        job: DiaryGenerationJob,
    ) -> DiaryProviderResult:
        body = json.dumps(
            {"diary_job": job.as_payload()},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        connection = HTTPConnection(
            self.config.core_host,
            self.config.core_port,
            timeout=CORE_REQUEST_TIMEOUT_SECONDS,
        )
        try:
            connection.request(
                "POST",
                "/v1/reflective-diary",
                body=body,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                    "X-Myuna-Channel-Kind": CHANNEL_KIND,
                    "X-Myuna-Client-Id": CORE_CLIENT_ID,
                },
            )
            response = connection.getresponse()
            response_status = response.status
            raw = response.read(_MAX_CORE_RESPONSE_BYTES + 1)
        except (OSError, HTTPException):
            raise CoreUnavailable(
                deterministic_core_unreachable_projection(),
                projection_source="gateway",
            ) from None
        finally:
            connection.close()
        if len(raw) > _MAX_CORE_RESPONSE_BYTES:
            raise RuntimeRejected("runtime rejected")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeRejected("runtime rejected") from None
        if response_status != 200:
            try:
                projection, failure_provenance = (
                    validate_core_failure_response_with_provenance(
                        response_status,
                        payload,
                    )
                )
            except GatewayDegradationProtocolError:
                raise RuntimeRejected("runtime rejected") from None
            raise CoreUnavailable(
                projection,
                projection_source="core",
                failure_provenance=failure_provenance,
                http_status=response_status,
            )
        if (
            not isinstance(payload, Mapping)
            or payload.get("provider") != "deepseek"
            or payload.get("model") != "deepseek-v4-flash"
            or payload.get("route_reason") != "p07_external_reflective_diary"
            or payload.get("job_digest") != job.job_digest
            or not isinstance(payload.get("provider_called"), bool)
        ):
            raise RuntimeRejected("runtime rejected")
        try:
            capacity = DiaryCapacityReceipt.from_payload(payload.get("capacity"))
            status = payload.get("status")
            candidate_payload = payload.get("candidate")
            candidate = (
                None
                if candidate_payload is None
                else DiaryGenerationCandidate.from_payload(candidate_payload)
            )
            result = DiaryProviderResult(
                status=status,  # type: ignore[arg-type]
                job_digest=job.job_digest,
                capacity=capacity,
                provider_called=payload["provider_called"],  # type: ignore[arg-type]
                candidate=candidate,
            )
        except (EpisodicMemoryError, TypeError, ValueError):
            raise RuntimeRejected("runtime rejected") from None
        if result.status == "completed":
            assert result.candidate is not None
            if (
                result.candidate.job_digest != job.job_digest
                or not result.capacity.fit
            ):
                raise RuntimeRejected("runtime rejected")
        elif result.capacity.fit:
            raise RuntimeRejected("runtime rejected")
        return result


def _read_request(connection: socket.socket) -> object:
    connection.settimeout(5)
    request = bytearray()
    while len(request) <= _MAX_REQUEST_BYTES:
        chunk = connection.recv(4096)
        if not chunk:
            break
        request.extend(chunk)
        if b"\n" in chunk:
            break
    if len(request) > _MAX_REQUEST_BYTES or b"\n" not in request:
        raise RuntimeRejected("runtime rejected")
    try:
        return json.loads(bytes(request).split(b"\n", 1)[0])
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeRejected("runtime rejected") from None


def _respond(
    connection: socket.socket,
    status: str,
    reply: str | None = None,
    *,
    recovery_notice: bool = False,
    delivery_token: str | None = None,
    pacing_seconds: float = 0.0,
) -> bool:
    if status == "accepted" and reply is not None:
        if delivery_token is not None:
            if _DELIVERY_TOKEN.fullmatch(delivery_token) is None:
                raise RuntimeRejected("runtime rejected")
            payload: dict[str, object] = {
                "kind": "accepted_reply",
                "delivery_token": delivery_token,
                "pacing_seconds": pacing_seconds,
                "reply": reply,
                "schema": GATEWAY_RESPONSE_SCHEMA,
            }
            if recovery_notice:
                payload["recovery_notice"] = RECOVERY_NOTICE_TEXT
        elif recovery_notice:
            payload = {
                "kind": "accepted_reply",
                "recovery_notice": RECOVERY_NOTICE_TEXT,
                "reply": reply,
                "schema": GATEWAY_RESPONSE_SCHEMA,
            }
        else:
            payload = {
                "code": "owner-runtime-reply",
                "reply": reply,
                "status": "accepted",
            }
    elif status == "duplicate":
        payload = {
            "kind": "duplicate_suppressed",
            "schema": GATEWAY_RESPONSE_SCHEMA,
        }
    elif status == "unavailable":
        payload = {"code": "owner-runtime-unavailable", "status": "rejected"}
    else:
        payload = {"code": "owner-runtime-rejected", "status": "rejected"}
    try:
        connection.sendall(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            + b"\n"
        )
        return True
    except OSError:
        return False

def _safe_context_detail_code(code: object) -> str:
    if isinstance(code, str):
        if code in {
            "external_summary_required",
            "external_summary_backpressure",
        }:
            return "external_summary_required"
        if code in {
            "external_turn_already_pending",
            "epoch_v3_turn_pending",
            "epoch_v3_delivery_pending",
        }:
            return "external_turn_already_pending"
    return "external_context_unavailable"


def _respond_visual_preflight(
    connection: socket.socket,
    *,
    ready: bool,
    safe_detail_code: str | None = None,
) -> None:
    if ready:
        payload = {
            "kind": "visual_preflight_ready",
            "schema": GATEWAY_RESPONSE_SCHEMA,
        }
    else:
        if safe_detail_code not in _CONTEXT_PROJECTION_UNAVAILABLE_CODES:
            raise RuntimeRejected("runtime rejected")
        payload = {
            "kind": "visual_preflight_unavailable",
            "safe_detail_code": safe_detail_code,
            "schema": GATEWAY_RESPONSE_SCHEMA,
        }
    try:
        connection.sendall(
            json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii")
            + b"\n"
        )
    except OSError:
        pass


def _respond_context_projection_unavailable(
    connection: socket.socket,
    safe_detail_code: str,
) -> None:
    if safe_detail_code not in _CONTEXT_PROJECTION_UNAVAILABLE_CODES:
        safe_detail_code = "external_context_unavailable"
    payload = {
        "kind": "context_projection_unavailable",
        "safe_detail_code": safe_detail_code,
        "schema": GATEWAY_RESPONSE_SCHEMA,
    }
    try:
        connection.sendall(
            json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii")
            + b"\n"
        )
    except OSError:
        pass


def _process_memory_delivery_outcome(
    connection: socket.socket,
    payload: object,
    *,
    memory_runtime: OwnerPrivateMemoryRuntime,
    signing_secret: bytes,
) -> bool:
    if not isinstance(payload, Mapping) or payload.get("schema") != DELIVERY_OUTCOME_SCHEMA:
        return False
    if set(payload) != {"delivery_token", "outcome", "schema", "trace_id"}:
        raise RuntimeRejected("runtime rejected")
    delivery_token = payload["delivery_token"]
    outcome = payload["outcome"]
    trace_id = payload["trace_id"]
    if (
        not isinstance(delivery_token, str)
        or _DELIVERY_TOKEN.fullmatch(delivery_token) is None
        or not isinstance(outcome, str)
        or outcome not in {"delivered", "cancelled"}
        or not hmac.compare_digest(
            delivery_token,
            _trace_bound_delivery_token(signing_secret, trace_id),
        )
    ):
        raise RuntimeRejected("runtime rejected")
    _audit_trace_marker(trace_id, "delivery_callback_received", "succeeded")
    delivered_monotonic_ns = None
    delivered_boot_id = None
    if outcome == "delivered" and memory_runtime.delivery_close_evidence_required(
        delivery_token
    ):
        delivered_monotonic_ns = time.monotonic_ns()
        delivered_boot_id = read_current_boot_identity()
    resolved = memory_runtime.resolve_delivery(
        delivery_token=delivery_token,
        outcome=outcome,
        delivered_monotonic_ns=delivered_monotonic_ns,
        delivered_boot_id=delivered_boot_id,
    )
    _audit_trace_marker(
        trace_id,
        "factual_close_replayed" if resolved.replayed else (
            "factual_close_committed"
            if resolved.outcome == "delivered"
            else "factual_close_cancelled"
        ),
        "replayed" if resolved.replayed else (
            "succeeded" if resolved.outcome == "delivered" else "cancelled"
        ),
    )
    response = {
        "schema": DELIVERY_OUTCOME_SCHEMA,
        "status": "accepted",
    }
    connection.sendall(
        json.dumps(response, separators=(",", ":"), sort_keys=True).encode("ascii")
        + b"\n"
    )
    _audit_stage(
        "memory_delivery_replayed"
        if resolved.replayed
        else (
            "memory_delivery_archived"
            if resolved.outcome == "delivered"
            else "memory_delivery_cancelled"
        )
    )
    if resolved.derivative_gap_code is not None:
        _audit_stage("memory_derivative_gap")
    return True


def _process_delivery_outcome(
    connection: socket.socket,
    payload: object,
    *,
    external_epoch: ExternalEpochStore | ExternalEpochV3Store,
    core: LoopbackCoreClient,
    pending_deliveries: dict[str, PendingDelivery],
    signing_secret: bytes,
    summary_worker: BackgroundSummaryWorker | None = None,
) -> bool:
    if not isinstance(payload, Mapping) or payload.get("schema") != DELIVERY_OUTCOME_SCHEMA:
        return False
    if set(payload) != {"delivery_token", "outcome", "schema", "trace_id"}:
        raise RuntimeRejected("runtime rejected")
    delivery_token = payload["delivery_token"]
    outcome = payload["outcome"]
    trace_id = payload["trace_id"]
    if (
        not isinstance(delivery_token, str)
        or _DELIVERY_TOKEN.fullmatch(delivery_token) is None
        or not isinstance(outcome, str)
        or outcome not in {"delivered", "cancelled"}
        or not hmac.compare_digest(
            delivery_token,
            _trace_bound_delivery_token(signing_secret, trace_id),
        )
    ):
        raise RuntimeRejected("runtime rejected")
    _audit_trace_marker(trace_id, "delivery_callback_received", "succeeded")
    if isinstance(external_epoch, ExternalEpochV3Store):
        if summary_worker is None:
            raise RuntimeRejected("runtime rejected")
        resolution = external_epoch.resolve_delivery(
            delivery_token=delivery_token,
            outcome=outcome,
        )
        _audit_trace_marker(
            trace_id,
            "factual_close_replayed" if resolution.replayed else (
                "factual_close_committed"
                if outcome == "delivered"
                else "factual_close_cancelled"
            ),
            "replayed" if resolution.replayed else (
                "succeeded" if outcome == "delivered" else "cancelled"
            ),
        )
        response = {
            "schema": DELIVERY_OUTCOME_SCHEMA,
            "status": "accepted",
        }
        connection.sendall(
            json.dumps(response, separators=(",", ":"), sort_keys=True).encode("ascii")
            + b"\n"
        )
        _audit_stage(
            "delivery_replayed"
            if resolution.replayed
            else ("delivery_committed" if outcome == "delivered" else "delivery_cancelled")
        )
        if resolution.summary_job_queued:
            summary_worker.trigger()
            _audit_stage("external_summary_queued")
        return True
    pending = pending_deliveries.get(delivery_token)
    if pending is None:
        raise RuntimeRejected("runtime rejected")
    if pending.context.trace_id != trace_id:
        raise RuntimeRejected("runtime rejected")
    committed = None
    if outcome == "delivered":
        committed = external_epoch.commit_delivery(
            pending.context,
            pending.epoch_token,
            pending.reply,
            pending.provenance,
        )
    else:
        external_epoch.cancel_pending(pending.context, pending.epoch_token)
    _audit_trace_marker(
        trace_id,
        "factual_close_committed" if outcome == "delivered" else "factual_close_cancelled",
        "succeeded" if outcome == "delivered" else "cancelled",
    )
    pending_deliveries.pop(delivery_token, None)
    response = {
        "schema": DELIVERY_OUTCOME_SCHEMA,
        "status": "accepted",
    }
    connection.sendall(
        json.dumps(response, separators=(",", ":"), sort_keys=True).encode("ascii")
        + b"\n"
    )
    _audit_stage("delivery_committed" if outcome == "delivered" else "delivery_cancelled")
    if committed is not None and committed.summary_job is not None:
        try:
            candidate = core.summarize(committed.summary_job)
            external_epoch.commit_summary_candidate(
                pending.context,
                committed.summary_job,
                candidate,
            )
            _audit_stage("external_summary_committed")
        except (
            CoreUnavailable,
            ExternalEpochRejected,
            RuntimeRejected,
        ):
            _audit_stage("external_summary_pending")
    return True


def _degradation_fanout(
    projection: object,
    *,
    projection_source: str,
    request_id: str,
    failure_provenance: object | None = None,
    http_status: int | None = None,
    elapsed_seconds: float | None = None,
    release_set_id: str | None = None,
    pending_after: int | None = None,
) -> PostConnectionFanout | None:
    try:
        job = DegradationShadowJob.from_projection(
            projection,
            projection_source=projection_source,
            channel="telegram",
            request_id=request_id,
        )
        history_job = None
        if failure_provenance is not None:
            try:
                history_job = build_incident_history_job(
                    job,
                    failure_provenance=failure_provenance,
                    http_status=http_status,
                    elapsed_seconds=elapsed_seconds,
                    release_set_id=release_set_id,
                    pending_after=pending_after,
                )
            except (GatewayDegradationProtocolError, TypeError, ValueError):
                history_job = None
        return PostConnectionFanout(
            degradation=job,
            incident_history=history_job,
        )
    except (GatewayDegradationProtocolError, TypeError, ValueError):
        return None


def _episode_projection(projection: Mapping[str, object]) -> dict[str, object]:
    fields = (
        "schema",
        "status",
        "category",
        "fingerprint",
        "recovery_state",
        "retryable",
        "owner_action_required",
    )
    return {field: projection[field] for field in fields}

def _process_visual_preflight(
    connection: socket.socket,
    payload: object,
    *,
    config: RuntimeConfig,
    signing_secret: bytes,
    identity_pepper: bytes,
    hybrid_enabled: bool,
    external_epoch: ExternalEpochStore | ExternalEpochV3Store | None,
    memory_runtime: OwnerPrivateMemoryRuntime | None = None,
) -> bool:
    if not (
        isinstance(payload, Mapping)
        and payload.get("routing") == VISUAL_PREFLIGHT_ROUTING
    ):
        return False
    if set(payload) != {"event", "routing", "signature"}:
        raise RuntimeRejected("runtime rejected")
    decision = evaluate_runtime_envelope(
        {"event": payload["event"], "signature": payload["signature"]},
        config=config,
        signing_secret=signing_secret,
        identity_pepper=identity_pepper,
        now=datetime.now(timezone.utc),
    )
    _audit_stage("visual_preflight_envelope_verified")
    if not resolve_verified_owner(decision, config):
        _audit_stage("visual_preflight_identity_rejected")
        _respond(connection, "rejected")
        return True
    _audit_stage("visual_preflight_identity_verified")
    if not hybrid_enabled or (external_epoch is None and memory_runtime is None):
        _audit_stage("visual_preflight_unavailable")
        _respond_visual_preflight(
            connection,
            ready=False,
            safe_detail_code="external_context_unavailable",
        )
        return True
    if memory_runtime is not None:
        try:
            memory_runtime.content_free_ready()
            readiness = "ready"
        except EpisodicMemoryError as exc:
            readiness = _safe_context_detail_code(exc.code)
    else:
        assert external_epoch is not None
        try:
            readiness = external_epoch.projection_readiness(
                _authenticated_context(decision, config)
            )
        except (ExternalEpochRejected, ExternalEpochV3Rejected) as exc:
            readiness = _safe_context_detail_code(exc.code)
    if readiness == "ready":
        _audit_stage("visual_preflight_ready")
        _respond_visual_preflight(connection, ready=True)
    else:
        _audit_stage("visual_preflight_unavailable")
        _respond_visual_preflight(
            connection,
            ready=False,
            safe_detail_code=_safe_context_detail_code(readiness),
        )
    return True


def process_connection(
    connection: socket.socket,
    *,
    config: RuntimeConfig,
    signing_secret: bytes,
    identity_pepper: bytes,
    core: LoopbackCoreClient,
    limiter: SlidingRateLimiter,
    history: ConversationHistory,
    recovery_store: RecoveryEpisodeStore | None = None,
    hybrid_enabled: bool = False,
    external_epoch: ExternalEpochStore | ExternalEpochV3Store | None = None,
    memory_runtime: OwnerPrivateMemoryRuntime | None = None,
    pending_deliveries: dict[str, PendingDelivery] | None = None,
    summary_worker: BackgroundSummaryWorker | None = None,
    pacing_policy: BoundedTurnPacingPolicy | None = None,
    requested_pacing_seconds: float = 0.0,
) -> PostConnectionFanout | None:
    decision: RuntimeDecision | None = None
    incident_started = time.monotonic()
    incident_release_set_id = (
        memory_runtime.selection.memory_release_set_id
        if memory_runtime is not None
        else getattr(external_epoch, "release_set_id", None)
    )

    def incident_elapsed() -> float:
        return max(0.0, time.monotonic() - incident_started)

    def incident_pending_after() -> int | None:
        return len(pending_deliveries) if pending_deliveries is not None else None

    try:
        payload = _read_request(connection)
        if memory_runtime is not None:
            if _process_memory_delivery_outcome(
                connection,
                payload,
                memory_runtime=memory_runtime,
                signing_secret=signing_secret,
            ):
                return None
        if external_epoch is not None and pending_deliveries is not None:
            if _process_delivery_outcome(
                connection,
                payload,
                external_epoch=external_epoch,
                core=core,
                pending_deliveries=pending_deliveries,
                signing_secret=signing_secret,
                summary_worker=summary_worker,
            ):
                return None
        if _process_visual_preflight(
            connection,
            payload,
            config=config,
            signing_secret=signing_secret,
            identity_pepper=identity_pepper,
            hybrid_enabled=hybrid_enabled,
            external_epoch=external_epoch,
            memory_runtime=memory_runtime,
        ):
            return None
        now = datetime.now(timezone.utc)
        decision = evaluate_runtime_envelope(
            payload,
            config=config,
            signing_secret=signing_secret,
            identity_pepper=identity_pepper,
            now=now,
        )
        _audit_trace_marker(decision.trace_id, "af_unix_request_accepted", "succeeded")
        received_monotonic_ns = time.monotonic_ns()
        _audit_stage("envelope_verified")
        if not claim_inbound(decision, now):
            _audit_stage("durable_replay_rejected")
            _respond(connection, "duplicate")
            return None
        _audit_stage("durable_claimed")
        if not resolve_verified_owner(decision, config):
            record_outcome(decision, "rejected", "owner_binding_unverified")
            _audit_stage("identity_rejected")
            _respond(connection, "rejected")
            return
        _audit_stage("identity_verified")
        if not limiter.allow(config.principal_id, now):
            record_outcome(decision, "failed", "owner_runtime_rate_limited")
            _audit_stage("rate_limited")
            _respond(connection, "unavailable")
            return _degradation_fanout(
                deterministic_gateway_projection("gateway-owner-rate-limited"),
                projection_source="gateway",
                request_id=request_id_for_decision(decision),
                failure_provenance=deterministic_gateway_failure_provenance(
                    "gateway-owner-rate-limited"
                ),
                elapsed_seconds=incident_elapsed(),
                release_set_id=incident_release_set_id,
                pending_after=incident_pending_after(),
            )
        temporal_command = parse_temporal_command(decision.message_text)
        if temporal_command is not None:
            try:
                control_context = _authenticated_context(decision, config)
                control_sample = None
                control_unresolved_reason = None
                if temporal_command.action == "help":
                    temporal_reply = temporal_usage_reply()
                    if memory_runtime is not None:
                        try:
                            control_request_id = (
                                request_id_for_decision(decision)
                                + "-temporal-help-time"
                            )
                            control_snapshot = parse_active_snapshot_response(
                                send_temporal_request(
                                    build_active_snapshot_request(
                                        authenticated_context=build_authenticated_context(
                                            decision, config
                                        ),
                                        request_id=control_request_id,
                                    )
                                ),
                                request_id=control_request_id,
                                after_event_sequence=0,
                            )
                            control_sample = control_snapshot.trusted_time
                        except TemporalGatewayRejected as exc:
                            control_unresolved_reason = exc.code
                else:
                    context_payload = build_authenticated_context(decision, config)
                    temporal_request = build_temporal_request(
                        temporal_command,
                        authenticated_context=context_payload,
                        request_id=request_id_for_decision(decision),
                        event_id=decision.event_id,
                        occurred_at=decision.occurred_at,
                    )
                    temporal_response = send_temporal_request(temporal_request)
                    temporal_reply = render_temporal_reply(
                        temporal_command,
                        temporal_response,
                    )
                    control_sample = parse_trusted_time_response(temporal_response)
                control_delivery_token = None
                if memory_runtime is not None:
                    control_delivery_token = _delivery_token(
                        signing_secret, control_context
                    )
                    memory_runtime.prepare_control_delivery(
                        delivery_token=control_delivery_token,
                        turn_id="turn-" + decision.event_id,
                        control_kind="temporal",
                        authenticated_context=control_context,
                        owner_message=decision.message_text,
                        assistant_reply=temporal_reply,
                        received_monotonic_ns=received_monotonic_ns,
                        committed_monotonic_ns=time.monotonic_ns(),
                        source_occurred_at_utc=control_context.occurred_at,
                        trusted_time_sample=control_sample,
                        trusted_time_unresolved_reason=control_unresolved_reason,
                    )
                if not record_outcome(
                    decision, "accepted", "owner_runtime_temporal_replied"
                ):
                    if control_delivery_token is not None:
                        memory_runtime.resolve_delivery(
                            delivery_token=control_delivery_token,
                            outcome="cancelled",
                            delivered_monotonic_ns=None,
                        )
                    raise RuntimeRejected("runtime rejected")
                _audit_stage("temporal_context_replied")
                sent = _respond(
                    connection,
                    "accepted",
                    temporal_reply,
                    delivery_token=control_delivery_token,
                )
                if not sent and control_delivery_token is not None:
                    memory_runtime.resolve_delivery(
                        delivery_token=control_delivery_token,
                        outcome="cancelled",
                        delivered_monotonic_ns=None,
                    )
                    _audit_stage("delivery_cancelled_before_channel_accept")
                return None
            except TemporalGatewayRejected as exc:
                if memory_runtime is not None:
                    memory_runtime.record_incomplete_turn(
                        turn_id="turn-" + decision.event_id,
                        authenticated_context=_authenticated_context(decision, config),
                        owner_message=decision.message_text,
                        source_occurred_at_utc=decision.occurred_at,
                        reason_code="temporal_control_failed",
                    )
                record_outcome(
                    decision, "failed", "owner_runtime_temporal_unavailable"
                )
                _audit_stage("temporal_context_unavailable")
                _respond(connection, "accepted", temporal_unavailable_reply())
                return _degradation_fanout(
                    deterministic_gateway_projection(
                        "gateway-temporal-unavailable"
                    ),
                    projection_source="gateway",
                    request_id=request_id_for_decision(decision),
                    failure_provenance=deterministic_gateway_failure_provenance(
                        "gateway-temporal-unavailable"
                    ),
                    elapsed_seconds=incident_elapsed(),
                    release_set_id=incident_release_set_id,
                    pending_after=incident_pending_after(),
                )
        diary_control = diary_command_is_explicit(decision.message_text)
        benchmark_control = benchmark_intent_grants_profile_consent(
            decision.message_text
        )
        try:
            profile_v2_request = parse_profile_v2_structural_request(
                decision.message_text
            )
        except OwnerProfileError:
            record_outcome(
                decision, "failed", "owner_runtime_profile_v2_intent_rejected"
            )
            _respond(connection, "accepted", "该 Profile 状态请求不明确，未写入。")
            return None
        profile_v2_control = profile_v2_request is not None
        check_control = check_command_is_explicit(decision.message_text)
        use_hybrid = (
            hybrid_enabled
            and decision.hybrid_external_generation
            and not diary_control
            and not benchmark_control
            and not profile_v2_control
            and not check_control
        )
        if decision.hybrid_external_generation and not hybrid_enabled:
            raise RuntimeRejected("runtime rejected")
        external_context: Mapping[str, object] | None = None
        epoch_token: object | None = None
        authenticated_context: AuthenticatedConversationContext | None = None
        memory_context: EpisodicRuntimeContext | None = None
        control_trusted_time_sample = None
        control_trusted_time_unresolved_reason: str | None = None
        if use_hybrid:
            if pacing_policy is None:
                raise RuntimeRejected("runtime rejected")
            authenticated_context = _authenticated_context(decision, config)
            safety = EgressSafetySignals(classifier_available=True)
            enforce_external_egress_safety(decision.message_text, safety)
            if memory_runtime is not None:
                try:
                    temporal_request_id = (
                        request_id_for_decision(decision) + "-active"
                    )
                    temporal_after_event_sequence = (
                        memory_runtime.p08_lifecycle_cursor()
                    )
                    temporal_request = build_active_snapshot_request(
                        authenticated_context=build_authenticated_context(decision, config),
                        request_id=temporal_request_id,
                        after_event_sequence=temporal_after_event_sequence,
                    )
                    try:
                        temporal_snapshot = parse_active_snapshot_response(
                            send_temporal_request(temporal_request),
                            request_id=temporal_request_id,
                            after_event_sequence=(
                                temporal_after_event_sequence
                            ),
                        )
                    except TemporalGatewayRejected as exc:
                        if exc.code == "active_projection_overflow":
                            raise
                        temporal_snapshot = unresolved_active_snapshot(exc.code)
                        _audit_stage("trusted_time_temporal_coverage_unresolved")
                    memory_context = memory_runtime.build_context(
                        authenticated_context=authenticated_context,
                        current_message=decision.message_text,
                        received_monotonic_ns=received_monotonic_ns,
                        p08_temporal_coverage_state=temporal_snapshot.coverage_state,
                        temporal_lifecycle_transitions=(
                            temporal_snapshot.lifecycle_transitions
                        ),
                        temporal_lifecycle_watermark=(
                            temporal_snapshot.lifecycle_watermark
                        ),
                        temporal_lifecycle_has_more=(
                            temporal_snapshot.lifecycle_has_more
                        ),
                        trusted_time_sample=temporal_snapshot.trusted_time,
                        trusted_time_unresolved_reason=(
                            temporal_snapshot.trusted_time_unresolved_reason
                        ),
                        active_snapshot_receipt=(
                            temporal_snapshot.active_snapshot_receipt
                        ),
                        safety=safety,
                        visual_event=decision.visual_event,
                    )
                    external_context = memory_context.as_payload()
                except (EpisodicMemoryError, TemporalGatewayRejected) as exc:
                    memory_runtime.record_incomplete_turn(
                        turn_id="turn-" + request_id_for_decision(decision),
                        authenticated_context=authenticated_context,
                        owner_message=decision.message_text,
                        source_occurred_at_utc=authenticated_context.occurred_at,
                        reason_code="memory_context_failed",
                    )
                    record_outcome(
                        decision,
                        "failed",
                        "owner_runtime_memory_context_unavailable",
                    )
                    _audit_stage("memory_context_unavailable")
                    _respond_context_projection_unavailable(
                        connection,
                        _safe_context_detail_code(getattr(exc, "code", None)),
                    )
                    return None
            else:
                if external_epoch is None or pending_deliveries is None:
                    raise RuntimeRejected("runtime rejected")
                pending_summary = (
                    None
                    if isinstance(external_epoch, ExternalEpochV3Store)
                    else external_epoch.pending_summary_job(authenticated_context)
                )
                if pending_summary is not None:
                    try:
                        candidate = core.summarize(pending_summary)
                        external_epoch.commit_summary_candidate(
                            authenticated_context,
                            pending_summary,
                            candidate,
                        )
                        _audit_stage("external_summary_recovered")
                    except (
                        CoreUnavailable,
                        ExternalEpochRejected,
                        RuntimeRejected,
                    ):
                        raise ExternalEpochRejected(
                            "external_summary_generation_unavailable"
                        ) from None
                try:
                    epoch_token = external_epoch.begin_turn(
                        authenticated_context,
                        decision.message_text,
                        safety,
                    )
                    external_context = external_epoch.context_payload(
                        authenticated_context,
                        epoch_token,
                        visual_event=decision.visual_event,
                    )
                except (ExternalEpochRejected, ExternalEpochV3Rejected) as exc:
                    if epoch_token is not None:
                        try:
                            external_epoch.cancel_pending(authenticated_context, epoch_token)
                        except (ExternalEpochRejected, ExternalEpochV3Rejected):
                            _audit_stage("external_pending_cancel_failed")
                    _audit_stage("external_context_unavailable")
                    _respond_context_projection_unavailable(
                        connection,
                        _safe_context_detail_code(exc.code),
                    )
                    return None
            messages = [{"role": "user", "content": decision.message_text}]
        else:
            if memory_runtime is not None and (
                diary_control
                or benchmark_control
                or profile_v2_control
                or check_control
            ):
                authenticated_context = _authenticated_context(decision, config)
                try:
                    control_request_id = (
                        request_id_for_decision(decision) + "-control-time"
                    )
                    control_snapshot = parse_active_snapshot_response(
                        send_temporal_request(
                            build_active_snapshot_request(
                                authenticated_context=build_authenticated_context(
                                    decision, config
                                ),
                                request_id=control_request_id,
                            )
                        ),
                        request_id=control_request_id,
                        after_event_sequence=0,
                    )
                    control_trusted_time_sample = control_snapshot.trusted_time
                except TemporalGatewayRejected as exc:
                    control_trusted_time_unresolved_reason = exc.code
                    _audit_stage("control_trusted_time_unresolved")
            messages = (
                [{"role": "user", "content": decision.message_text}]
                if (
                    use_hybrid
                    or diary_control
                    or benchmark_control
                    or profile_v2_control
                    or check_control
                )
                else history.request_messages(
                    decision.conversation_id,
                    decision.message_text,
                )
            )
        core_reply = None
        if profile_v2_control:
            if authenticated_context is None or profile_v2_request is None:
                raise RuntimeRejected("runtime rejected")
            reply = _profile_v2_control_reply(
                profile_v2_request,
                _delivery_token(signing_secret, authenticated_context),
            )
        else:
            try:
                core_reply = core.chat(
                    messages,
                    decision=decision,
                    external_context=external_context,
                )
            except (CoreUnavailable, RuntimeRejected) as exc:
                if epoch_token is not None and authenticated_context is not None and external_epoch is not None:
                    try:
                        external_epoch.cancel_pending(authenticated_context, epoch_token)
                    except (ExternalEpochRejected, ExternalEpochV3Rejected):
                        _audit_stage("external_pending_cancel_failed")
                if isinstance(exc, RuntimeRejected):
                    raise
                if memory_runtime is not None and authenticated_context is not None:
                    memory_runtime.record_incomplete_turn(
                        turn_id="turn-" + request_id_for_decision(decision),
                        authenticated_context=authenticated_context,
                        owner_message=decision.message_text,
                        source_occurred_at_utc=authenticated_context.occurred_at,
                        reason_code="core_reply_failed",
                    )
                record_outcome(decision, "failed", "owner_runtime_core_unavailable")
                _audit_stage("core_unavailable")
                if recovery_store is not None:
                    try:
                        recovery_store.mark_active(
                            _episode_projection(exc.projection),
                            now=datetime.now(timezone.utc),
                        )
                    except RecoveryEpisodeRejected:
                        _audit_stage("recovery_state_unavailable")
                _respond(connection, "unavailable")
                return _degradation_fanout(
                    exc.projection,
                    projection_source=exc.projection_source,
                    request_id=request_id_for_decision(decision),
                    failure_provenance=exc.failure_provenance,
                    http_status=exc.http_status,
                    elapsed_seconds=incident_elapsed(),
                    release_set_id=incident_release_set_id,
                    pending_after=incident_pending_after(),
                )
            reply = core_reply.reply
        prepared_v3_delivery_token: str | None = None
        prepared_memory_delivery_token: str | None = None
        if use_hybrid and memory_runtime is not None:
            if (
                authenticated_context is None
                or memory_context is None
                or core_reply is None
                or not isinstance(core_reply.provenance, EpisodicTurnProvenance)
            ):
                raise RuntimeRejected("runtime rejected")
            prepared_memory_delivery_token = _delivery_token(
                signing_secret,
                authenticated_context,
            )
            memory_runtime.prepare_delivery(
                delivery_token=prepared_memory_delivery_token,
                turn_id="turn-" + request_id_for_decision(decision),
                runtime_context=memory_context,
                assistant_reply=reply,
                provenance=core_reply.provenance,
                committed_monotonic_ns=time.monotonic_ns(),
                source_occurred_at_utc=authenticated_context.occurred_at,
            )
        elif memory_runtime is not None and (
            diary_control or benchmark_control or profile_v2_control or check_control
        ):
            if authenticated_context is None:
                raise RuntimeRejected("runtime rejected")
            prepared_memory_delivery_token = _delivery_token(
                signing_secret,
                authenticated_context,
            )
            memory_runtime.prepare_control_delivery(
                delivery_token=prepared_memory_delivery_token,
                turn_id="turn-" + request_id_for_decision(decision),
                control_kind=(
                    "diary"
                    if diary_control
                    else "benchmark"
                    if benchmark_control
                    else "profile_v2"
                    if profile_v2_control
                    else "check"
                ),
                authenticated_context=authenticated_context,
                owner_message=decision.message_text,
                assistant_reply=reply,
                received_monotonic_ns=received_monotonic_ns,
                committed_monotonic_ns=time.monotonic_ns(),
                source_occurred_at_utc=authenticated_context.occurred_at,
                trusted_time_sample=control_trusted_time_sample,
                trusted_time_unresolved_reason=(
                    control_trusted_time_unresolved_reason
                ),
            )
        elif use_hybrid and isinstance(external_epoch, ExternalEpochV3Store):
            assert authenticated_context is not None
            assert epoch_token is not None
            if not isinstance(core_reply.provenance, ReleaseBoundTurnProvenance):
                raise RuntimeRejected("runtime rejected")
            prepared_v3_delivery_token = _delivery_token(
                signing_secret,
                authenticated_context,
            )
            external_epoch.prepare_delivery(
                authenticated_context,
                epoch_token,
                delivery_token=prepared_v3_delivery_token,
                assistant_reply=reply,
                provenance=core_reply.provenance,
            )
        if not record_outcome(decision, "accepted", "owner_runtime_replied"):
            if prepared_memory_delivery_token is not None:
                assert memory_runtime is not None
                memory_runtime.resolve_delivery(
                    delivery_token=prepared_memory_delivery_token,
                    outcome="cancelled",
                    delivered_monotonic_ns=None,
                )
            elif prepared_v3_delivery_token is not None:
                external_epoch.resolve_delivery(
                    delivery_token=prepared_v3_delivery_token,
                    outcome="cancelled",
                )
            raise RuntimeRejected("runtime rejected")
        if diary_control:
            _audit_stage("diary_context_isolated")
        elif benchmark_control:
            _audit_stage("benchmark_profile_context_isolated")
        elif profile_v2_control:
            _audit_stage("profile_v2_context_isolated")
        elif check_control:
            _audit_stage("check_context_isolated")
        elif not use_hybrid:
            _commit_reply_best_effort(
                history,
                decision.conversation_id,
                messages,
                reply,
            )
        recovery_notice = False
        if recovery_store is not None:
            try:
                recovery_notice = recovery_store.claim_recovery_notice(
                    now=datetime.now(timezone.utc)
                )
            except RecoveryEpisodeRejected:
                _audit_stage("recovery_state_unavailable")
        _audit_stage("reply_accepted")
        delivery_token: str | None = None
        pacing_seconds = 0.0
        if prepared_memory_delivery_token is not None:
            delivery_token = prepared_memory_delivery_token
        if use_hybrid:
            assert authenticated_context is not None
            assert pacing_policy is not None
            if core_reply.provenance is None:
                raise RuntimeRejected("runtime rejected")
            if memory_runtime is not None:
                if prepared_memory_delivery_token is None:
                    raise RuntimeRejected("runtime rejected")
                delivery_token = prepared_memory_delivery_token
            elif isinstance(external_epoch, ExternalEpochV3Store):
                assert epoch_token is not None
                if prepared_v3_delivery_token is None:
                    raise RuntimeRejected("runtime rejected")
                delivery_token = prepared_v3_delivery_token
            else:
                assert epoch_token is not None
                assert pending_deliveries is not None
                delivery_token = _delivery_token(signing_secret, authenticated_context)
                if delivery_token in pending_deliveries:
                    raise RuntimeRejected("runtime rejected")
                if not isinstance(core_reply.provenance, ExternalTurnProvenance):
                    raise RuntimeRejected("runtime rejected")
                pending_deliveries[delivery_token] = PendingDelivery(
                    context=authenticated_context,
                    epoch_token=epoch_token,
                    provenance=core_reply.provenance,
                    reply=reply,
                )
            pacing_seconds = pacing_policy.plan(
                requested_delay_seconds=requested_pacing_seconds,
                is_recovery_notice=recovery_notice,
            ).delay_seconds
        response_sent = _respond(
            connection,
            "accepted",
            reply,
            recovery_notice=recovery_notice,
            delivery_token=delivery_token,
            pacing_seconds=pacing_seconds,
        )
        if prepared_memory_delivery_token is not None and not response_sent:
            memory_runtime.resolve_delivery(
                delivery_token=prepared_memory_delivery_token,
                outcome="cancelled",
                delivered_monotonic_ns=None,
            )
            _audit_stage("delivery_cancelled_before_channel_accept")
        elif (
            use_hybrid
            and isinstance(external_epoch, ExternalEpochV3Store)
            and not response_sent
        ):
            if delivery_token is None:
                raise RuntimeRejected("runtime rejected")
            external_epoch.resolve_delivery(
                delivery_token=delivery_token,
                outcome="cancelled",
            )
            _audit_stage("delivery_cancelled_before_channel_accept")
        if use_hybrid:
            return None
        return PostConnectionFanout(
            accepted=ShadowJob(
                request_uuid=str(uuid4()),
                query=decision.message_text,
                actual_route=(
                    "local_control"
                    if profile_v2_control
                    else core_reply.actual_route
                ),
            )
        )
    except (ExternalEpochRejected, ExternalEpochV3Rejected) as exc:
        if exc.code.startswith("external_summary") or exc.code.startswith("summary_"):
            _audit_stage("external_summary_lifecycle_unavailable")
            _respond(connection, "unavailable")
            if decision is not None:
                return _degradation_fanout(
                    deterministic_gateway_projection(
                        "gateway-core-unreachable"
                    ),
                    projection_source="gateway",
                    request_id=request_id_for_decision(decision),
                )
        _audit_stage("generic_rejection")
        _respond(connection, "rejected")
    except EpisodicMemoryError:
        if decision is not None:
            record_outcome(
                decision,
                "failed",
                "owner_runtime_memory_boundary_unavailable",
            )
        _audit_stage("memory_boundary_unavailable")
        _respond_context_projection_unavailable(
            connection,
            "external_context_unavailable",
        )
    except (
        ContextWindowRejected,
        ExternalContextError,
        RuntimeRejected,
        OSError,
        subprocess.SubprocessError,
        TurnPacingRejected,
    ):
        _audit_stage("generic_rejection")
        _respond(connection, "rejected")
    return None


def _release_set_runtime(
    *,
    config_snapshot: runtime_config_contract.ProtectedRuntimeConfigSnapshot,
    selection: ExternalEpochSelection,
    core: LoopbackCoreClient,
) -> tuple[ExternalEpochV3Store, BackgroundSummaryWorker]:
    config = config_snapshot.config
    selected_again, selector_digest = _load_external_epoch_selection_snapshot(
        expected_gid=config_snapshot.gid,
    )
    if selected_again != selection:
        raise RuntimeRejected("runtime rejected")
    first = load_protected_release_set_snapshot(
        P07_D_RELEASE_SET_PATH,
        expected_uid=0,
        expected_gid=0,
    )
    second = load_protected_release_set_snapshot(
        P07_D_RELEASE_SET_PATH,
        expected_uid=0,
        expected_gid=0,
    )
    require_same_release_set_snapshot(first, second)
    release_set = first.release_set
    if (
        release_set.generation != selection.generation
        or release_set.selector["path"] != EXTERNAL_EPOCH_SELECTOR_PATH.as_posix()
        or release_set.selector["digest"] != selector_digest
        or release_set.selector["generation"] != selection.generation
        or release_set.epoch["epoch_id"] != selection.epoch_id
        or release_set.epoch["database_path"] != selection.database_path.as_posix()
        or release_set.epoch["uid"] != os.geteuid()
        or release_set.epoch["gid"] != os.getegid()
        or release_set.runtime_config["uid"] != config_snapshot.uid
        or release_set.runtime_config["gid"] != config_snapshot.gid
        or release_set.runtime_config["mode"] != config_snapshot.mode
    ):
        raise RuntimeRejected("runtime rejected")
    binding_digest = runtime_binding_digest(
        channel_kind=config.channel_kind,
        client_id=CORE_CLIENT_ID,
        principal_id=config.principal_id,
        namespace_id=config.namespace_id,
    )
    require_runtime_binding_projection(
        first,
        runtime_config_path=CONFIG_PATH,
        runtime_config_digest=config_snapshot.content_sha256,
        binding_digest=binding_digest,
        channel_kind=config.channel_kind,
        principal_id=config.principal_id,
        namespace_id=config.namespace_id,
    )
    policy_overlay = load_selected_policy_overlay(
        parent_release_set=release_set,
        parent_manifest_file_digest=getattr(first, "file_digest", None),
        component_kind="runtime",
        current_component_release_digest=release_digest_from_path(
            Path(__file__), component="runtime"
        ),
        expected_uid=0,
        expected_gid=config_snapshot.gid,
    )
    store = ExternalEpochV3Store(
        selection.database_path,
        epoch_id=selection.epoch_id,
        release_set_id=release_set.release_set_id,
        binding=ExternalEpochV3Binding(
            channel_kind=config.channel_kind,
            client_id=CORE_CLIENT_ID,
            principal_id=config.principal_id,
            namespace_id=config.namespace_id,
        ),
        projection_policy_version=(
            release_set.projection_policy_version
            if policy_overlay is None
            else str(policy_overlay.policy["policy_version"])
        ),
        policy_overlay_id=(
            None if policy_overlay is None else policy_overlay.overlay_id
        ),
        expected_uid=release_set.epoch["uid"],
        expected_gid=release_set.epoch["gid"],
    )
    store.startup_recover()
    if release_set.generation >= 9:
        publish_runtime_readiness(
            selection.database_path,
            generation=release_set.generation,
            release_set_id=release_set.release_set_id,
            epoch_id=selection.epoch_id,
            selector_digest=selector_digest,
            runtime_config_digest=config_snapshot.content_sha256,
            epoch_metadata=store.public_metadata(),
        )
    worker = BackgroundSummaryWorker(
        SummaryWorkerCycle(
            store,
            core,
            worker_id="gateway-summary-worker",
        )
    )
    return store, worker


def main() -> int:
    if os.geteuid() == 0:
        raise SystemExit("refusing to run Telegram owner runtime gateway as root")
    if int(os.environ.get("LISTEN_FDS", "0")) != 1:
        raise SystemExit("Telegram owner runtime gateway requires one systemd socket")
    runtime_config_snapshot = runtime_config_contract.load_protected_runtime_config_snapshot()
    config = runtime_config_snapshot.config
    signing_secret = _read_credential("channel-signing")
    identity_pepper = _read_credential("identity-pepper")
    core_token = _read_credential("core-token")
    if hmac.compare_digest(signing_secret, identity_pepper):
        raise SystemExit("gateway secrets must be distinct")
    core = LoopbackCoreClient(config, core_token)
    limiter = SlidingRateLimiter(config.max_requests_per_ten_minutes)
    history = ConversationHistory(
        config.max_history_messages,
        config.max_history_characters,
        store=_build_context_store(),
    )
    recovery_store = RecoveryEpisodeStore(
        RECOVERY_DATABASE_PATH,
        _recovery_scope_key(config),
    )
    hybrid_enabled = _hybrid_enabled()
    external_epoch = None
    memory_runtime = None
    pending_deliveries: dict[str, PendingDelivery] = {}
    pacing_policy = None
    summary_worker = None
    requested_pacing_seconds = 0.0
    if hybrid_enabled:
        memory_selection, owner_day_diary = load_selected_memory_configuration(
            expected_selector_gid=runtime_config_snapshot.gid,
        )
        if memory_selection is not None:
            if (
                memory_selection.expected_uid != os.geteuid()
                or memory_selection.expected_gid != os.getegid()
            ):
                raise SystemExit("memory runtime service identity rejected")
            parent_selection, parent_selector_digest = _load_external_epoch_selection_snapshot(
                expected_gid=runtime_config_snapshot.gid,
            )
            parent_snapshot = load_protected_release_set_snapshot(
                P07_D_RELEASE_SET_PATH,
                expected_uid=0,
                expected_gid=0,
            )
            parent_release = parent_snapshot.release_set
            if (
                parent_selection.epoch_id != memory_selection.parent_epoch_id
                or parent_release.release_set_id
                != memory_selection.parent_release_set_id
                or parent_selector_digest != memory_selection.parent_selector_digest
                or parent_snapshot.file_digest
                != memory_selection.parent_manifest_digest
            ):
                raise SystemExit("memory runtime parent binding rejected")
            if (
                isinstance(memory_selection, OwnerPrivateMemorySelectionV4)
                and owner_day_diary is not None
            ):
                raise SystemExit(
                    "owner-day diary v2 provider adapter not selected by this source"
                )
            require_precreated_runtime_root(memory_selection)
            memory_runtime = OwnerPrivateMemoryRuntime(
                memory_selection,
                owner_day_diary=owner_day_diary,
            )
            memory_runtime.initialize()
        else:
            external_epoch_selection = _load_external_epoch_selection()
            if external_epoch_selection.generation in {7, 8, 9, 10, 11, 12, 13}:
                external_epoch, summary_worker = _release_set_runtime(
                    config_snapshot=runtime_config_snapshot,
                    selection=external_epoch_selection,
                    core=core,
                )
                summary_worker.start()
            else:
                external_epoch = ExternalEpochStore(
                    external_epoch_selection.database_path,
                    epoch_id=external_epoch_selection.epoch_id,
                    startup_binding=runtime_config_contract.external_epoch_binding_from_runtime_config(
                        config
                    ),
                )
                external_epoch.discard_all_uncommitted_after_restart()
        pacing_policy, requested_pacing_seconds = _pacing_policy()
    _audit_stage("ready")
    with socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM) as server:
        while True:
            connection, _ = server.accept()
            serve_accepted_connection(
                connection,
                lambda accepted_connection: process_connection(
                    accepted_connection,
                    config=config,
                    signing_secret=signing_secret,
                    identity_pepper=identity_pepper,
                    core=core,
                    limiter=limiter,
                    history=history,
                    recovery_store=recovery_store,
                    hybrid_enabled=hybrid_enabled,
                    external_epoch=external_epoch,
                    memory_runtime=memory_runtime,
                    pending_deliveries=pending_deliveries,
                    summary_worker=summary_worker,
                    pacing_policy=pacing_policy,
                    requested_pacing_seconds=requested_pacing_seconds,
                ),
            )


if __name__ == "__main__":
    raise SystemExit(main())
