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
import socket
import stat
import subprocess
import time
from typing import Mapping
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
    RecentRequestGuard,
    SqliteContextStore,
)

from myuna_core.channel_gateway import (
    GatewayEnvelopeError,
    SignedChannelEnvelope,
    sign_channel_event,
)
from myuna_core.identity import account_fingerprint


CONFIG_PATH = Path("/etc/myuna-gateway/qq-owner-runtime-v1.json")
CHANNEL_KIND = "astrbot_qq"
CORE_CLIENT_ID = "qq-owner-private"
AUTHENTICATED_CONTEXT_SCHEMA_VERSION = "myuna.authenticated-conversation-context.v1"
CONTEXT_DATABASE_PATH = Path(
    "/var/lib/myuna-gateway/session-context/context.db"
)
CONTEXT_NAMESPACE = "qq-owner-private-v1"
CONTEXT_STORE_MODE_ENV = "MYUNA_SESSION_CONTEXT_STORE"
CORE_REQUEST_TIMEOUT_SECONDS = 70
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_REQUEST_BYTES = 32768
_MAX_CORE_RESPONSE_BYTES = 65536


class RuntimeRejected(PermissionError):
    """Fail-closed runtime rejection without account or message detail."""


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


def _audit_stage(code: str) -> None:
    """Emit fixed stage codes only; never include event or reply values."""

    print(f"qq owner runtime gateway stage={code}", flush=True)


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


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
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
    def from_payload(cls, payload: object) -> "RuntimeConfig":
        required = {
            "binding_id",
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
            raise RuntimeRejected("runtime rejected")
        for key in ("binding_id", "namespace_id", "principal_id"):
            value = payload[key]
            if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
                raise RuntimeRejected("runtime rejected")
        channel_instance = payload["channel_instance"]
        if (
            not isinstance(channel_instance, str)
            or _SAFE_ID.fullmatch(channel_instance) is None
        ):
            raise RuntimeRejected("runtime rejected")
        for key in ("evidence_sha256", "finalization_digest"):
            value = payload[key]
            if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
                raise RuntimeRejected("runtime rejected")
        if payload["core_host"] != "127.0.0.1":
            raise RuntimeRejected("runtime rejected")
        core_port = payload["core_port"]
        request_limit = payload["max_requests_per_ten_minutes"]
        history_messages = payload["max_history_messages"]
        history_characters = payload["max_history_characters"]
        if not isinstance(core_port, int) or not 1024 <= core_port <= 65535:
            raise RuntimeRejected("runtime rejected")
        if not isinstance(request_limit, int) or not 1 <= request_limit <= 60:
            raise RuntimeRejected("runtime rejected")
        try:
            history_policy = ContextWindowPolicy(
                max_messages=history_messages,
                max_characters=history_characters,
            )
        except ContextWindowRejected:
            raise RuntimeRejected("runtime rejected")
        return cls(
            binding_id=str(payload["binding_id"]),
            principal_id=str(payload["principal_id"]),
            namespace_id=str(payload["namespace_id"]),
            finalization_digest=str(payload["finalization_digest"]),
            evidence_sha256=str(payload["evidence_sha256"]),
            channel_instance=channel_instance,
            core_host="127.0.0.1",
            core_port=core_port,
            max_requests_per_ten_minutes=request_limit,
            max_history_messages=history_policy.max_messages,
            max_history_characters=history_policy.max_characters,
        )


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


@dataclass(frozen=True, slots=True)
class CoreReply:
    reply: str
    actual_route: str


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
        envelope = SignedChannelEnvelope.from_payload(payload)
        expected_signature = sign_channel_event(envelope.event, signing_secret)
        if not hmac.compare_digest(envelope.signature, expected_signature):
            raise RuntimeRejected("runtime rejected")
        event = envelope.event
        if event.channel != CHANNEL_KIND:
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
            envelope.as_payload(),
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
            account_fingerprint=fingerprint,
            message_text=event.message_text.strip(),
        )
    except (GatewayEnvelopeError, RuntimeRejected, TypeError, ValueError):
        raise RuntimeRejected("runtime rejected") from None


def _psql_scalar(sql: str, variables: dict[str, str]) -> str:
    command = [
        "/usr/bin/psql",
        "--dbname=myuna_dev",
        "--username=myuna_gateway_app",
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
        "SELECT gateway_runtime.claim_inbound_event("
        ":'channel_kind', :'channel_instance', :'event_id', :'nonce_fingerprint', "
        ":'payload_sha256', :'occurred_at'::timestamptz, :'expires_at'::timestamptz);",
        {
            "channel_kind": decision.channel_kind,
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
        "SELECT gateway_runtime.record_inbound_outcome("
        ":'channel_kind', :'channel_instance', :'event_id', :'outcome', :'code');",
        {
            "channel_kind": decision.channel_kind,
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
        "FROM gateway_runtime.resolve_verified_binding("
        ":'channel_kind', :'account_fingerprint');",
        {
            "channel_kind": decision.channel_kind,
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
            "memory_candidate": False,
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
    ) -> CoreReply:
        authenticated_context = build_authenticated_context(
            decision,
            self.config,
        )
        body = json.dumps(
            {
                "authenticated_context": authenticated_context,
                "conversation": {
                    "high_quality": False,
                    "messages": messages,
                    "mode": "myuna",
                    "risk_level": "low",
                    "synthetic_memory": False,
                    "task_class": "ordinary_chat",
                },
            },
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
        return CoreReply(
            reply=reply.strip(),
            actual_route=bounded_actual_route(payload),
        )


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


def _respond(connection: socket.socket, status: str, reply: str | None = None) -> None:
    if status == "accepted" and reply is not None:
        payload: dict[str, str] = {
            "code": "owner-runtime-reply",
            "reply": reply,
            "status": "accepted",
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
    except OSError:
        pass


def _degradation_fanout(
    projection: object,
    *,
    projection_source: str,
    request_id: str,
    failure_provenance: object | None = None,
    http_status: int | None = None,
    elapsed_seconds: float | None = None,
) -> PostConnectionFanout | None:
    try:
        job = DegradationShadowJob.from_projection(
            projection,
            projection_source=projection_source,
            channel="qq",
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
                    release_set_id=None,
                    pending_after=None,
                )
            except (GatewayDegradationProtocolError, TypeError, ValueError):
                history_job = None
        return PostConnectionFanout(
            degradation=job,
            incident_history=history_job,
        )
    except (GatewayDegradationProtocolError, TypeError, ValueError):
        return None


def process_connection(
    connection: socket.socket,
    *,
    config: RuntimeConfig,
    signing_secret: bytes,
    identity_pepper: bytes,
    core: LoopbackCoreClient,
    limiter: SlidingRateLimiter,
    history: ConversationHistory,
    request_guard: RecentRequestGuard,
) -> PostConnectionFanout | None:
    decision: RuntimeDecision | None = None
    incident_started = time.monotonic()

    def incident_elapsed() -> float:
        return max(0.0, time.monotonic() - incident_started)

    try:
        payload = _read_request(connection)
        now = datetime.now(timezone.utc)
        decision = evaluate_runtime_envelope(
            payload,
            config=config,
            signing_secret=signing_secret,
            identity_pepper=identity_pepper,
            now=now,
        )
        _audit_stage("envelope_verified")
        if not claim_inbound(decision, now):
            _audit_stage("durable_replay_rejected")
            raise RuntimeRejected("runtime rejected")
        _audit_stage("durable_claimed")
        if not resolve_verified_owner(decision, config):
            record_outcome(decision, "rejected", "owner_binding_unverified")
            _audit_stage("identity_rejected")
            _respond(connection, "rejected")
            return
        _audit_stage("identity_verified")
        if not request_guard.claim(
            decision.conversation_id,
            decision.message_text,
            now,
        ):
            record_outcome(decision, "failed", "owner_runtime_duplicate_suppressed")
            _audit_stage("duplicate_suppressed")
            _respond(connection, "unavailable")
            return _degradation_fanout(
                deterministic_gateway_projection(
                    "gateway-owner-duplicate-suppressed"
                ),
                projection_source="gateway",
                request_id=request_id_for_decision(decision),
                failure_provenance=deterministic_gateway_failure_provenance(
                    "gateway-owner-duplicate-suppressed"
                ),
                elapsed_seconds=incident_elapsed(),
            )
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
            )
        messages = history.request_messages(
            decision.conversation_id,
            decision.message_text,
        )
        try:
            core_reply = core.chat(messages, decision=decision)
        except CoreUnavailable as exc:
            record_outcome(decision, "failed", "owner_runtime_core_unavailable")
            _audit_stage("core_unavailable")
            _respond(connection, "unavailable")
            return _degradation_fanout(
                exc.projection,
                projection_source=exc.projection_source,
                request_id=request_id_for_decision(decision),
                failure_provenance=exc.failure_provenance,
                http_status=exc.http_status,
                elapsed_seconds=incident_elapsed(),
            )
        reply = core_reply.reply
        if not record_outcome(decision, "accepted", "owner_runtime_replied"):
            raise RuntimeRejected("runtime rejected")
        _commit_reply_best_effort(
            history,
            decision.conversation_id,
            messages,
            reply,
        )
        _audit_stage("reply_accepted")
        _respond(connection, "accepted", reply)
        return PostConnectionFanout(
            accepted=ShadowJob(
                request_uuid=str(uuid4()),
                query=decision.message_text,
                actual_route=core_reply.actual_route,
            )
        )
    except (
        ContextWindowRejected,
        RuntimeRejected,
        OSError,
        subprocess.SubprocessError,
    ):
        _audit_stage("generic_rejection")
        _respond(connection, "rejected")
    return None


def main() -> int:
    if os.geteuid() == 0:
        raise SystemExit("refusing to run QQ owner runtime gateway as root")
    if int(os.environ.get("LISTEN_FDS", "0")) != 1:
        raise SystemExit("QQ owner runtime gateway requires one systemd socket")
    config = RuntimeConfig.from_payload(_load_protected_json(CONFIG_PATH))
    signing_secret = _read_credential("channel-signing")
    identity_pepper = _read_credential("identity-pepper")
    core_token = _read_credential("core-token")
    if hmac.compare_digest(signing_secret, identity_pepper):
        raise SystemExit("gateway secrets must be distinct")
    core = LoopbackCoreClient(config, core_token)
    limiter = SlidingRateLimiter(config.max_requests_per_ten_minutes)
    request_guard = RecentRequestGuard(namespace=CONTEXT_NAMESPACE)
    history = ConversationHistory(
        config.max_history_messages,
        config.max_history_characters,
        store=_build_context_store(),
    )
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
                    request_guard=request_guard,
                ),
            )


if __name__ == "__main__":
    raise SystemExit(main())
