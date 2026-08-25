from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping, Protocol, Sequence

from myuna_core.authenticated_conversation import AuthenticatedConversationContext
from myuna_core.channel_capability import ChannelNeutralCapabilityProfile
from myuna_core.external_context.contracts import (
    MAX_REPLY_CHARACTERS,
    EgressSafetySignals,
    ExternalTurnProvenance,
)


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_ROLES = frozenset({"user", "assistant"})


def _external_audit_details(
    context: AuthenticatedConversationContext,
) -> dict[str, object]:
    """Content-free correlation without principal, namespace, binding or client IDs."""

    return {
        "channel_kind": context.channel_kind,
        "correlation_id": context.correlation_id,
        "event_id": context.event_id,
        "request_id": context.request_id,
        "trace_id": context.trace_id,
    }


class GatewayKernelError(RuntimeError):
    """Base error for the channel-neutral gateway runtime kernel."""


class DuplicateInboundEvent(GatewayKernelError):
    pass


class GatewayRateLimitExceeded(GatewayKernelError):
    pass


class GatewayCoreUnavailable(GatewayKernelError):
    """Typed transport failure supplied by a Core client adapter."""

    def __init__(self, failure_code: str) -> None:
        if _SAFE_ID.fullmatch(failure_code) is None:
            raise ValueError("Core failure code must be a safe identifier")
        super().__init__("Core is unavailable")
        self.failure_code = failure_code


class GatewayReplyRejected(GatewayKernelError):
    pass


class GatewayExternalContextRejected(GatewayKernelError):
    def __init__(self, failure_code: str) -> None:
        if _SAFE_ID.fullmatch(failure_code) is None:
            raise ValueError("external context failure code must be a safe identifier")
        super().__init__("external context rejected")
        self.failure_code = failure_code


@dataclass(frozen=True, slots=True)
class GatewaySessionKey:
    namespace_id: str
    session_id: str

    def __post_init__(self) -> None:
        for value in (self.namespace_id, self.session_id):
            if _SAFE_ID.fullmatch(value) is None:
                raise ValueError("gateway session key is unsafe")


@dataclass(frozen=True, slots=True)
class GatewayInboundMessage:
    context: AuthenticatedConversationContext
    session_id: str
    message_text: str
    task_class: str = "ordinary_chat"
    risk_level: str = "low"
    high_quality: bool = False
    external_generation: bool = False
    egress_safety: EgressSafetySignals = EgressSafetySignals()
    requested_capabilities: tuple[str, ...] = (
        "conversation",
        "long_term_memory_read",
    )

    def __post_init__(self) -> None:
        if _SAFE_ID.fullmatch(self.session_id) is None:
            raise ValueError("session_id must be a safe opaque identifier")
        if not self.message_text.strip() or len(self.message_text) > 4000:
            raise ValueError("message text must contain 1-4000 characters")
        if _SAFE_ID.fullmatch(self.task_class) is None:
            raise ValueError("task_class must be a safe identifier")
        if self.risk_level not in {"low", "medium", "high"}:
            raise ValueError("risk_level is unsupported")
        if not self.requested_capabilities:
            raise ValueError("at least one requested capability is required")
        if len(set(self.requested_capabilities)) != len(self.requested_capabilities):
            raise ValueError("requested capabilities must be unique")
        for capability in self.requested_capabilities:
            if _SAFE_ID.fullmatch(capability) is None:
                raise ValueError("requested capability is unsafe")
        if self.external_generation and self.context.channel_kind != "astrbot_telegram":
            raise ValueError("external generation is Telegram Owner-private only")

    @property
    def session_key(self) -> GatewaySessionKey:
        return GatewaySessionKey(
            namespace_id=self.context.namespace_id,
            session_id=self.session_id,
        )


@dataclass(frozen=True, slots=True)
class GatewayCoreRequest:
    context: AuthenticatedConversationContext
    messages: tuple[Mapping[str, str], ...]
    task_class: str
    risk_level: str
    high_quality: bool
    external_context: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if not self.messages or len(self.messages) > 256:
            raise ValueError("Core request messages are outside the supported range")
        for message in self.messages:
            if set(message) != {"role", "content"}:
                raise ValueError("Core request message fields are invalid")
            if message["role"] not in _ROLES:
                raise ValueError("Core request message role is invalid")
            if not isinstance(message["content"], str) or not message["content"]:
                raise ValueError("Core request message content is invalid")

    def as_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "authenticated_context": self.context.as_payload(),
            "conversation": {
                "high_quality": self.high_quality,
                "messages": [dict(message) for message in self.messages],
                "mode": "myuna",
                "risk_level": self.risk_level,
                "synthetic_memory": False,
                "task_class": self.task_class,
            },
        }
        if self.external_context is not None:
            payload["external_context"] = dict(self.external_context)
        return payload


@dataclass(frozen=True, slots=True)
class GatewayKernelResult:
    reply: str
    request_id: str
    event_id: str
    channel_kind: str
    session_key: GatewaySessionKey
    delivery_commit_token: object | None = None
    delivery_provenance: ExternalTurnProvenance | None = None


class EventLedgerPort(Protocol):
    def claim(self, *, event_id: str, request_id: str) -> bool: ...

    def complete(self, *, event_id: str, outcome: str) -> None: ...


class RateLimiterPort(Protocol):
    def allow(self, *, principal_id: str, channel_kind: str) -> bool: ...


class SessionContextPort(Protocol):
    def load(self, key: GatewaySessionKey) -> Sequence[Mapping[str, str]]: ...

    def append(
        self,
        key: GatewaySessionKey,
        *,
        user_message: str,
        assistant_reply: str,
    ) -> None: ...


class CoreConversationPort(Protocol):
    def chat(self, payload: Mapping[str, object]) -> Mapping[str, object]: ...


class FailureObserverPort(Protocol):
    def observe(self, metadata: Mapping[str, object]) -> None: ...


class ExternalContextEpochPort(Protocol):
    def begin_turn(
        self,
        context: AuthenticatedConversationContext,
        current_message: str,
        safety: EgressSafetySignals,
    ) -> object: ...

    def context_payload(
        self,
        context: AuthenticatedConversationContext,
        token: object,
    ) -> Mapping[str, object]: ...

    def commit_delivery(
        self,
        context: AuthenticatedConversationContext,
        token: object,
        assistant_reply: str,
        provenance: ExternalTurnProvenance,
    ) -> object: ...

    def cancel_pending(
        self,
        context: AuthenticatedConversationContext,
        token: object,
    ) -> None: ...


class GatewayRuntimeKernel:
    """Pure channel-neutral orchestration over injected state and transport ports."""

    def __init__(
        self,
        *,
        capability_profile: ChannelNeutralCapabilityProfile,
        event_ledger: EventLedgerPort,
        rate_limiter: RateLimiterPort,
        session_context: SessionContextPort,
        core: CoreConversationPort,
        failure_observer: FailureObserverPort,
        external_context_epoch: ExternalContextEpochPort | None = None,
    ) -> None:
        self.capability_profile = capability_profile
        self.event_ledger = event_ledger
        self.rate_limiter = rate_limiter
        self.session_context = session_context
        self.core = core
        self.failure_observer = failure_observer
        self.external_context_epoch = external_context_epoch

    def prepare_request(
        self,
        inbound: GatewayInboundMessage,
        *,
        external_context: Mapping[str, object] | None = None,
    ) -> GatewayCoreRequest:
        self.capability_profile.authorize(
            inbound.context,
            requested_capabilities=inbound.requested_capabilities,
        )
        if inbound.external_generation:
            if external_context is None:
                raise GatewayExternalContextRejected("external_context_required")
            messages = ({"role": "user", "content": inbound.message_text},)
        else:
            if external_context is not None:
                raise GatewayExternalContextRejected("unexpected_external_context")
            history = tuple(self.session_context.load(inbound.session_key))
            messages = (*history, {"role": "user", "content": inbound.message_text})
        return GatewayCoreRequest(
            context=inbound.context,
            messages=messages,
            task_class=inbound.task_class,
            risk_level=inbound.risk_level,
            high_quality=inbound.high_quality,
            external_context=external_context,
        )

    def handle(self, inbound: GatewayInboundMessage) -> GatewayKernelResult:
        context = inbound.context
        self.capability_profile.authorize(
            context,
            requested_capabilities=inbound.requested_capabilities,
        )
        if not self.event_ledger.claim(
            event_id=context.event_id,
            request_id=context.request_id,
        ):
            raise DuplicateInboundEvent("inbound event already claimed")
        if not self.rate_limiter.allow(
            principal_id=context.principal_id,
            channel_kind=context.channel_kind,
        ):
            self.event_ledger.complete(event_id=context.event_id, outcome="rate_limited")
            raise GatewayRateLimitExceeded("gateway rate limit exceeded")

        delivery_token: object | None = None
        try:
            external_payload = None
            if inbound.external_generation:
                if self.external_context_epoch is None:
                    raise GatewayExternalContextRejected("external_epoch_port_unavailable")
                delivery_token = self.external_context_epoch.begin_turn(
                    context,
                    inbound.message_text,
                    inbound.egress_safety,
                )
                external_payload = self.external_context_epoch.context_payload(
                    context,
                    delivery_token,
                )
            request = self.prepare_request(
                inbound,
                external_context=external_payload,
            )
        except GatewayExternalContextRejected:
            self.event_ledger.complete(
                event_id=context.event_id,
                outcome="external_context_rejected",
            )
            raise
        except Exception as exc:
            if delivery_token is not None and self.external_context_epoch is not None:
                try:
                    self.external_context_epoch.cancel_pending(context, delivery_token)
                except Exception:
                    pass
            failure_code = getattr(exc, "code", "external_context_rejected")
            self.event_ledger.complete(
                event_id=context.event_id,
                outcome="external_context_rejected",
            )
            self.failure_observer.observe(
                {
                    **_external_audit_details(context),
                    "failure_code": failure_code,
                    "stage": "external_context",
                }
            )
            raise GatewayExternalContextRejected(failure_code) from None

        try:
            response = self.core.chat(request.as_payload())
        except GatewayCoreUnavailable as exc:
            if delivery_token is not None and self.external_context_epoch is not None:
                try:
                    self.external_context_epoch.cancel_pending(context, delivery_token)
                except Exception as cancel_exc:
                    failure_code = getattr(
                        cancel_exc,
                        "code",
                        "pending_turn_cancel_failed",
                    )
                    raise GatewayExternalContextRejected(failure_code) from None
            self.event_ledger.complete(event_id=context.event_id, outcome="core_unavailable")
            self.failure_observer.observe(
                {
                    **(
                        _external_audit_details(context)
                        if delivery_token is not None
                        else context.audit_details()
                    ),
                    "failure_code": exc.failure_code,
                    "stage": "core_request",
                }
            )
            raise

        expected_response_fields = (
            {"reply", "external_turn_provenance"}
            if delivery_token is not None
            else {"reply"}
        )
        if set(response) != expected_response_fields or not isinstance(response["reply"], str):
            if delivery_token is not None and self.external_context_epoch is not None:
                try:
                    self.external_context_epoch.cancel_pending(context, delivery_token)
                except Exception as cancel_exc:
                    failure_code = getattr(
                        cancel_exc,
                        "code",
                        "pending_turn_cancel_failed",
                    )
                    raise GatewayExternalContextRejected(failure_code) from None
            self.event_ledger.complete(event_id=context.event_id, outcome="reply_rejected")
            self.failure_observer.observe(
                {
                    **(
                        _external_audit_details(context)
                        if delivery_token is not None
                        else context.audit_details()
                    ),
                    "failure_code": "invalid_core_reply",
                    "stage": "core_reply",
                }
            )
            raise GatewayReplyRejected("Core reply contract rejected")
        reply = response["reply"].strip()
        provenance = None
        if delivery_token is not None:
            try:
                provenance = ExternalTurnProvenance.from_payload(
                    response["external_turn_provenance"]
                )
                if (
                    provenance.epoch_id != external_payload.get("epoch_id")
                    or provenance.epoch_revision
                    != external_payload.get("epoch_revision")
                ):
                    raise ValueError("provenance binding drift")
            except (TypeError, ValueError):
                try:
                    self.external_context_epoch.cancel_pending(context, delivery_token)
                except Exception:
                    pass
                raise GatewayReplyRejected("Core reply provenance rejected") from None
        if not reply or (
            delivery_token is not None
            and (len(reply) > MAX_REPLY_CHARACTERS or "\x00" in reply)
        ):
            if delivery_token is not None and self.external_context_epoch is not None:
                try:
                    self.external_context_epoch.cancel_pending(context, delivery_token)
                except Exception as cancel_exc:
                    failure_code = getattr(
                        cancel_exc,
                        "code",
                        "pending_turn_cancel_failed",
                    )
                    raise GatewayExternalContextRejected(failure_code) from None
            self.event_ledger.complete(event_id=context.event_id, outcome="reply_rejected")
            raise GatewayReplyRejected("Core reply contract rejected")

        if delivery_token is None:
            self.session_context.append(
                inbound.session_key,
                user_message=inbound.message_text,
                assistant_reply=reply,
            )
            self.event_ledger.complete(event_id=context.event_id, outcome="delivered")
        return GatewayKernelResult(
            reply=reply,
            request_id=context.request_id,
            event_id=context.event_id,
            channel_kind=context.channel_kind,
            session_key=inbound.session_key,
            delivery_commit_token=delivery_token,
            delivery_provenance=provenance,
        )

    def acknowledge_delivery_for_context(
        self,
        context: AuthenticatedConversationContext,
        result: GatewayKernelResult,
    ) -> None:
        if (
            result.delivery_commit_token is None
            or result.delivery_provenance is None
            or self.external_context_epoch is None
        ):
            raise GatewayExternalContextRejected("delivery_ack_token_required")
        if (
            result.channel_kind != "astrbot_telegram"
            or context.channel_kind != result.channel_kind
            or context.namespace_id != result.session_key.namespace_id
            or context.request_id != result.request_id
            or context.event_id != result.event_id
        ):
            raise GatewayExternalContextRejected("delivery_ack_binding_rejected")
        try:
            self.external_context_epoch.commit_delivery(
                context,
                result.delivery_commit_token,
                result.reply,
                result.delivery_provenance,
            )
        except Exception as exc:
            code = getattr(exc, "code", "delivery_commit_failed")
            raise GatewayExternalContextRejected(code) from None
        self.event_ledger.complete(event_id=result.event_id, outcome="delivered")

    def reject_delivery_for_context(
        self,
        context: AuthenticatedConversationContext,
        result: GatewayKernelResult,
    ) -> None:
        if result.delivery_commit_token is None or self.external_context_epoch is None:
            raise GatewayExternalContextRejected("delivery_ack_token_required")
        if (
            result.channel_kind != "astrbot_telegram"
            or context.channel_kind != result.channel_kind
            or context.namespace_id != result.session_key.namespace_id
            or context.event_id != result.event_id
            or context.request_id != result.request_id
        ):
            raise GatewayExternalContextRejected("delivery_ack_binding_rejected")
        try:
            self.external_context_epoch.cancel_pending(
                context,
                result.delivery_commit_token,
            )
        except Exception as exc:
            code = getattr(exc, "code", "pending_turn_cancel_failed")
            raise GatewayExternalContextRejected(code) from None
        self.event_ledger.complete(event_id=result.event_id, outcome="delivery_failed")
