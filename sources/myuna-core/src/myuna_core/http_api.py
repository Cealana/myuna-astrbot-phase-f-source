from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4
import json
from typing import Mapping, Protocol

from . import __version__
from .audit import AuditLogger
from .authenticated_conversation import (
    AuthenticatedConversationContext,
    AuthenticatedConversationContextError,
)
from .config import Settings
from .conversation import (
    ConversationError,
    ConversationGuardError,
    ConversationInputError,
    ConversationPreProviderError,
    ConversationProfileError,
    DevConversationEngine,
)
from .degradation_bridge import CoreFailureCode
from .degradation_http import (
    attach_core_failure_metadata,
    attach_provider_failure_metadata,
    output_repair_failure_provenance,
    pre_provider_failure_provenance,
    safe_pre_provider_failure_gate,
    unknown_core_failure_provenance,
)
from .http_client_auth import (
    LoadedHttpClientCredential,
    authenticate_http_client,
    load_http_client_credentials,
)
from .external_context.contracts import ExternalContextError
from .external_context.lifecycle_v3 import (
    RELEASE_BOUND_CONTEXT_OVERLAY_SCHEMA,
    RELEASE_BOUND_CONTEXT_SCHEMA,
    ReleaseBoundExternalContext,
    ReleaseBoundLifecycleRejected,
)
from .providers import BudgetAccountingError, BudgetExceededError, ProviderError
from .router import ModelRouter


class HybridConversationPort(Protocol):
    @property
    def release_set_id(self) -> str | None: ...

    @property
    def policy_overlay_id(self) -> str | None: ...

    def converse_external(
        self,
        conversation_payload: object,
        external_context_payload: Mapping[str, object],
        *,
        request_id: str,
        authenticated_context: AuthenticatedConversationContext,
    ) -> object: ...

    def summarize_external(
        self,
        summary_job_payload: Mapping[str, object],
        *,
        request_id: str,
    ) -> object: ...

    def generate_reflective_diary(
        self,
        diary_job_payload: Mapping[str, object],
        *,
        request_id: str,
    ) -> object: ...


def _parse_chat_envelope(
    payload: object,
    authenticated_client: LoadedHttpClientCredential,
) -> tuple[object, AuthenticatedConversationContext | None]:
    if not isinstance(payload, dict):
        return payload, None
    envelope_fields = {"authenticated_context", "conversation"}
    present = set(payload) & envelope_fields
    if not present:
        return payload, None
    if set(payload) != envelope_fields:
        raise ConversationInputError(
            "authenticated chat envelope fields do not match the v1 schema"
        )
    try:
        context = AuthenticatedConversationContext.from_payload(
            payload["authenticated_context"],
            authenticated_client_id=authenticated_client.client_id,
            authenticated_channel_kind=authenticated_client.channel_kind,
        )
    except AuthenticatedConversationContextError:
        raise ConversationInputError(
            "authenticated chat envelope was rejected"
        ) from None
    return payload["conversation"], context


def _parse_hybrid_chat_envelope(
    payload: object,
    authenticated_client: LoadedHttpClientCredential,
    *,
    expected_release_set_id: str | None = None,
    expected_policy_overlay_id: str | None = None,
) -> tuple[
    object,
    AuthenticatedConversationContext | None,
    Mapping[str, object] | None,
]:
    if not isinstance(payload, dict) or "external_context" not in payload:
        conversation, context = _parse_chat_envelope(payload, authenticated_client)
        return conversation, context, None
    if set(payload) != {"authenticated_context", "conversation", "external_context"}:
        raise ConversationInputError(
            "hybrid chat envelope fields do not match the v1 schema"
        )
    conversation, context = _parse_chat_envelope(
        {
            "authenticated_context": payload["authenticated_context"],
            "conversation": payload["conversation"],
        },
        authenticated_client,
    )
    if context is None or context.channel_kind != "astrbot_telegram":
        raise ConversationInputError("hybrid chat requires authenticated Telegram context")
    external_context = payload["external_context"]
    if not isinstance(external_context, Mapping):
        raise ConversationInputError("external_context must be an object")
    if not isinstance(conversation, Mapping):
        raise ConversationInputError("hybrid conversation must be an object")
    current_message: object
    if external_context.get("schema") in {
        RELEASE_BOUND_CONTEXT_SCHEMA,
        RELEASE_BOUND_CONTEXT_OVERLAY_SCHEMA,
    }:
        if (
            expected_release_set_id is None
            or external_context.get("release_set_id") != expected_release_set_id
        ):
            raise ConversationInputError(
                "release-bound external context release set was rejected"
            )
        try:
            release_bound_context = ReleaseBoundExternalContext.from_payload(
                external_context,
                context=context,
            )
        except (ExternalContextError, ReleaseBoundLifecycleRejected):
            raise ConversationInputError(
                "release-bound external context was rejected"
            ) from None
        if release_bound_context.policy_overlay_id != expected_policy_overlay_id:
            raise ConversationInputError(
                "release-bound external context policy overlay was rejected"
            )
        current_message = release_bound_context.envelope.current_message
    elif {
        "external_context",
        "policy_overlay_id",
        "release_set_id",
    } & set(external_context):
        raise ConversationInputError(
            "release-bound external context schema was rejected"
        )
    else:
        current_message = external_context.get("current_message")
    messages = conversation.get("messages")
    if (
        not isinstance(messages, list)
        or len(messages) != 1
        or not isinstance(messages[0], dict)
        or set(messages[0]) != {"role", "content"}
        or messages[0].get("role") != "user"
        or messages[0].get("content") != current_message
    ):
        raise ConversationInputError(
            "hybrid conversation must contain only the bound current Owner message"
        )
    return conversation, context, external_context


def make_handler(
    settings: Settings,
    audit: AuditLogger,
    engine: DevConversationEngine | None,
    http_clients: tuple[LoadedHttpClientCredential, ...],
    hybrid_engine: HybridConversationPort | None = None,
) -> type[BaseHTTPRequestHandler]:
    router = ModelRouter(settings)

    class Handler(BaseHTTPRequestHandler):
        server_version = "MyunaCoreBootstrap/0.1"

        def _send_json(self, status: int, payload: dict[str, object]) -> None:
            body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            request_id = str(uuid4())
            status = router.status()

            if self.path == "/healthz":
                code = 200
                payload: dict[str, object] = {
                    "status": "alive",
                    "environment": settings.environment,
                    "version": __version__,
                }
            elif self.path == "/readyz":
                runtime_ready = status.ready and engine is not None and bool(http_clients)
                code = 200 if runtime_ready else 503
                payload = {
                    "status": "ready" if runtime_ready else "not_ready",
                    "reasons": list(status.reasons),
                }
            elif self.path == "/v1/status":
                code = 200
                payload = {
                    "environment": settings.environment,
                    "definition_release": status.definition_release,
                    "enabled_providers": list(status.enabled_providers),
                    "ready": status.ready and engine is not None,
                    "reasons": list(status.reasons),
                    "loopback_only": True,
                    "conversation_active": engine is not None,
                }
            else:
                code = 404
                payload = {"error": "not_found"}

            audit.emit(
                "http_request",
                outcome="ok" if code < 400 else "rejected",
                request_id=request_id,
                details={"method": "GET", "path": self.path, "status": code},
            )
            self._send_json(code, payload)

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
            request_id = str(uuid4())
            code = 500
            payload: dict[str, object]
            authenticated_client: LoadedHttpClientCredential | None = None
            persona_grounding_class = "unknown"
            profile_called: bool | None = False
            try:
                if self.path not in {
                    "/v1/chat",
                    "/v1/external-summary",
                    "/v1/owner-day-diary",
                    "/v1/reflective-diary",
                }:
                    code = 404
                    payload = {"error": "not_found"}
                elif engine is None or not http_clients:
                    code = 503
                    payload = attach_core_failure_metadata(
                        {
                            "error": "runtime_not_activated",
                            "reasons": list(router.status().reasons),
                        },
                        request_id=request_id,
                        code=CoreFailureCode.CORE_RUNTIME_NOT_READY,
                        provenance=pre_provider_failure_provenance(
                            "core_readiness",
                            failure_gate="core_runtime_not_ready",
                        ),
                    )
                else:
                    authenticated_client = authenticate_http_client(
                        self.headers.get("Authorization", ""),
                        self.headers.get("X-Myuna-Client-Id", ""),
                        self.headers.get("X-Myuna-Channel-Kind", ""),
                        http_clients,
                    )
                    if authenticated_client is None:
                        code = 401
                        payload = {"error": "unauthorized"}
                    elif self.headers.get_content_type() != "application/json":
                        code = 415
                        payload = {"error": "content_type_must_be_application_json"}
                    else:
                        length = self._content_length()
                        raw = self.rfile.read(length)
                        request_payload = json.loads(raw.decode("utf-8"))
                        if self.path in {
                            "/v1/external-summary",
                            "/v1/owner-day-diary",
                            "/v1/reflective-diary",
                        }:
                            envelope_field = {
                                "/v1/external-summary": "summary_job",
                                "/v1/owner-day-diary": "owner_day_diary_job",
                                "/v1/reflective-diary": "diary_job",
                            }[self.path]
                            if (
                                authenticated_client.channel_kind != "astrbot_telegram"
                                or hybrid_engine is None
                                or not isinstance(request_payload, Mapping)
                                or set(request_payload) != {envelope_field}
                                or not isinstance(request_payload[envelope_field], Mapping)
                            ):
                                raise ConversationInputError(
                                    "external derivative envelope rejected"
                                )
                            if envelope_field == "summary_job":
                                result = hybrid_engine.summarize_external(
                                    request_payload[envelope_field],
                                    request_id=request_id,
                                )
                            elif envelope_field == "owner_day_diary_job":
                                result = hybrid_engine.generate_owner_day_diary(
                                    request_payload[envelope_field],
                                    request_id=request_id,
                                )
                            else:
                                result = hybrid_engine.generate_reflective_diary(
                                    request_payload[envelope_field],
                                    request_id=request_id,
                                )
                        else:
                            (
                                conversation_payload,
                                authenticated_context,
                                external_context_payload,
                            ) = _parse_hybrid_chat_envelope(
                                request_payload,
                                authenticated_client,
                                expected_release_set_id=(
                                    None
                                    if hybrid_engine is None
                                    else hybrid_engine.release_set_id
                                ),
                                expected_policy_overlay_id=(
                                    None
                                    if hybrid_engine is None
                                    else getattr(
                                        hybrid_engine,
                                        "policy_overlay_id",
                                        None,
                                    )
                                ),
                            )
                            if external_context_payload is not None:
                                persona_grounding_class = "not_evaluated"
                                profile_called = True
                            if external_context_payload is not None:
                                if authenticated_context is None or hybrid_engine is None:
                                    raise ConversationError(
                                        "hybrid external generation is not activated"
                                    )
                                audit.emit_trace_marker(
                                    trace_id=authenticated_context.trace_id,
                                    stage="core_request_started",
                                    status="started",
                                )
                                result = hybrid_engine.converse_external(
                                    conversation_payload,
                                    external_context_payload,
                                    request_id=request_id,
                                    authenticated_context=authenticated_context,
                                )
                                audit.emit_trace_marker(
                                    trace_id=authenticated_context.trace_id,
                                    stage="core_response_returned",
                                    status="succeeded",
                                )
                            elif authenticated_context is None:
                                result = engine.converse(
                                    conversation_payload, request_id=request_id
                                )
                            else:
                                result = engine.converse(
                                    conversation_payload,
                                    request_id=request_id,
                                    authenticated_context=authenticated_context,
                                )
                        code = 200
                        public_payload = getattr(result, "public_payload", None)
                        if not callable(public_payload):
                            raise ConversationError("conversation result contract rejected")
                        payload = public_payload()
            except (UnicodeDecodeError, json.JSONDecodeError):
                code = 400
                payload = {"error": "invalid_json"}
            except ConversationInputError:
                code = 400
                payload = attach_core_failure_metadata(
                    {"error": "invalid_conversation_request"},
                    request_id=request_id,
                    code=CoreFailureCode.CORE_REQUEST_REJECTED,
                    provenance=pre_provider_failure_provenance(
                        "request_parser",
                        persona_grounding_class=persona_grounding_class,
                        failure_gate="core_request_rejected",
                    ),
                )
            except BudgetExceededError:
                code = 429
                payload = attach_core_failure_metadata(
                    {"error": "provider_daily_budget_exceeded"},
                    request_id=request_id,
                    code=CoreFailureCode.PROVIDER_DAILY_BUDGET_EXCEEDED,
                    provenance=pre_provider_failure_provenance(
                        "core_pre_provider",
                        profile_called=profile_called,
                        persona_grounding_class=persona_grounding_class,
                        failure_gate="provider_daily_budget_exceeded",
                    ),
                )
            except BudgetAccountingError:
                code = 503
                payload = attach_core_failure_metadata(
                    {"error": "provider_budget_accounting_unavailable"},
                    request_id=request_id,
                    code=CoreFailureCode.PROVIDER_BUDGET_ACCOUNTING_FAILED,
                    provenance=pre_provider_failure_provenance(
                        "core_pre_provider",
                        profile_called=profile_called,
                        persona_grounding_class=persona_grounding_class,
                        failure_gate="provider_budget_accounting_failed",
                    ),
                )
            except ConversationPreProviderError as exc:
                code = 503
                payload = attach_core_failure_metadata(
                    {"error": "runtime_fail_closed"},
                    request_id=request_id,
                    code=CoreFailureCode.CORE_RUNTIME_FAIL_CLOSED,
                    provenance=pre_provider_failure_provenance(
                        "core_pre_provider",
                        profile_called=profile_called,
                        persona_grounding_class=persona_grounding_class,
                        failure_gate=safe_pre_provider_failure_gate(exc.code),
                    ),
                )
            except ConversationProfileError:
                code = 503
                payload = attach_core_failure_metadata(
                    {"error": "profile_unavailable"},
                    request_id=request_id,
                    code=CoreFailureCode.OWNER_MEMORY_READ_FAILED,
                    provenance=pre_provider_failure_provenance(
                        "profile_projection",
                        profile_called=True,
                        persona_grounding_class=persona_grounding_class,
                        failure_gate="owner_memory_read_failed",
                    ),
                )
            except ProviderError as exc:
                code = 503 if exc.retryable else 502
                payload = attach_provider_failure_metadata(
                    {"error": "provider_unavailable", "retryable": exc.retryable},
                    request_id=request_id,
                    provider_code=exc.code,
                    attempt_count=exc.attempts,
                    profile_called=profile_called,
                    persona_grounding_class=persona_grounding_class,
                )
            except ConversationGuardError:
                code = 502
                payload = attach_core_failure_metadata(
                    {"error": "reply_failed_runtime_guard"},
                    request_id=request_id,
                    code=CoreFailureCode.REPLY_RUNTIME_GUARD_REJECTED,
                    provenance=output_repair_failure_provenance(
                        attempt_count=None,
                        profile_called=profile_called,
                        persona_grounding_class=persona_grounding_class,
                    ),
                )
            except (ConversationError, ValueError, OSError):
                code = 503
                payload = attach_core_failure_metadata(
                    {"error": "runtime_fail_closed"},
                    request_id=request_id,
                    code=CoreFailureCode.CORE_RUNTIME_FAIL_CLOSED,
                    provenance=unknown_core_failure_provenance(
                        persona_grounding_class=persona_grounding_class
                    ),
                )
            except Exception:
                code = 500
                payload = attach_core_failure_metadata(
                    {"error": "internal_error"},
                    request_id=request_id,
                    code=CoreFailureCode.CORE_RUNTIME_FAIL_CLOSED,
                    provenance=unknown_core_failure_provenance(
                        persona_grounding_class=persona_grounding_class
                    ),
                )
            audit_details: dict[str, object] = {
                "method": "POST",
                "path": self.path,
                "status": code,
            }
            if authenticated_client is not None:
                audit_details.update(
                    {
                        "authenticated_channel_kind": (
                            authenticated_client.channel_kind
                        ),
                        "authenticated_client_id": authenticated_client.client_id,
                    }
                )
            audit.emit(
                "http_request",
                outcome="ok" if code < 400 else "rejected",
                request_id=request_id,
                details=audit_details,
            )
            self._send_json(code, payload)

        def _content_length(self) -> int:
            raw = self.headers.get("Content-Length")
            if raw is None:
                raise ConversationInputError("Content-Length is required")
            try:
                length = int(raw)
            except ValueError as exc:
                raise ConversationInputError("Content-Length must be an integer") from exc
            if not 1 <= length <= settings.http_max_body_bytes:
                raise ConversationInputError("request body size is outside the allowed range")
            return length

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def build_server(
    settings: Settings,
    audit: AuditLogger,
    *,
    engine: DevConversationEngine | None = None,
    hybrid_engine: HybridConversationPort | None = None,
    dev_token: str | None = None,
    http_clients: tuple[LoadedHttpClientCredential, ...] | None = None,
) -> ThreadingHTTPServer:
    if settings.ready:
        if engine is None:
            engine = DevConversationEngine(settings, audit)
        if http_clients is None:
            if dev_token is not None:
                http_clients = (
                    LoadedHttpClientCredential(
                        client_id="legacy-dev",
                        channel_kind="loopback_dev",
                        token=dev_token,
                        identity_headers_required=False,
                    ),
                )
            else:
                http_clients = load_http_client_credentials(
                    settings.http_client_credentials,
                    legacy_credential_name=settings.dev_token_credential,
                )
    if http_clients is None:
        http_clients = ()
    return ThreadingHTTPServer(
        (settings.bind_host, settings.port),
        make_handler(
            settings,
            audit,
            engine,
            http_clients,
            hybrid_engine=hybrid_engine,
        ),
    )
