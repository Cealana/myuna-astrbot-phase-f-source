from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Protocol

from myuna_core.authenticated_conversation import AuthenticatedConversationContext
from myuna_core.audit import AuditLogger
from myuna_core.channel_capability import (
    OWNER_PRIVATE_PROFILE_WRITE_V1_SCOPE,
    ChannelCapabilityProfileError,
    ChannelNeutralCapabilityProfile,
)
from myuna_core.providers.base import ModelProvider

from .contracts import OwnerProfile, OwnerProfileError, RetrievalResult
from .write_candidate import (
    CandidateAnalysis,
    PreparedProfileCandidate,
    analyze_candidate_with_local_provider,
    build_candidate_retrieval_query,
    candidate_audit_projection,
    prepare_profile_candidate,
    render_candidate_preview,
)
from .write_intent import BenchmarkWriteIntent, parse_benchmark_write_intent
from .loader import parse_profile_bytes
from .write_store import (
    StoredProfileCandidate,
    cancel_pending_candidate,
    candidate_scope_sha256,
    load_pending_candidate,
    mark_candidate_consumed,
    stage_profile_candidate,
)


WRITE_RUNTIME_SCOPE = (
    "verified Telegram Owner-private text; local candidate analysis; "
    "Owner-confirmed immutable Profile revision"
)


class OwnerProfileWriteAccessError(PermissionError):
    def __init__(self, code: str) -> None:
        super().__init__("Owner Profile write access rejected")
        self.code = code


@dataclass(frozen=True, slots=True)
class OwnerProfileWriteAccessDecision:
    channel_kind: str
    scope_sha256: str


class OwnerProfileWriteAccessPolicy:
    def __init__(self, capability_profile: ChannelNeutralCapabilityProfile) -> None:
        if (
            capability_profile.response_scope != OWNER_PRIVATE_PROFILE_WRITE_V1_SCOPE
            or capability_profile.memory_protocol != "profile-write-v1"
        ):
            raise ValueError("channel profile is not the Owner Profile write scope")
        self.capability_profile = capability_profile

    def authorize(
        self,
        context: AuthenticatedConversationContext | None,
        *,
        provider_name: str,
    ) -> OwnerProfileWriteAccessDecision:
        if context is None:
            raise OwnerProfileWriteAccessError("authenticated_context_required")
        if provider_name != "local":
            raise OwnerProfileWriteAccessError("candidate_provider_forbidden")
        if not context.consent_memory_candidate:
            raise OwnerProfileWriteAccessError("memory_candidate_consent_required")
        if context.client_id != "telegram-owner-private":
            raise OwnerProfileWriteAccessError("owner_channel_scope_rejected")
        try:
            self.capability_profile.authorize(
                context,
                requested_capabilities=(
                    "conversation",
                    "long_term_memory_read",
                    "long_term_memory_write",
                ),
            )
        except ChannelCapabilityProfileError:
            raise OwnerProfileWriteAccessError("owner_channel_scope_rejected") from None
        try:
            scope = candidate_scope_sha256(
                channel_kind=context.channel_kind,
                conversation_kind=context.conversation_kind,
                authority_level=context.authority_level,
                binding_id=context.binding_id,
                principal_id=context.principal_id,
                namespace_id=context.namespace_id,
                conversation_id=context.conversation_id,
            )
        except OwnerProfileError:
            raise OwnerProfileWriteAccessError("owner_channel_scope_rejected") from None
        return OwnerProfileWriteAccessDecision(
            channel_kind=context.channel_kind,
            scope_sha256=scope,
        )


class OwnerProfileReadRuntime(Protocol):
    def retrieve(
        self,
        query: str,
        *,
        request_id: str,
        channel_kind: str,
    ) -> RetrievalResult:
        ...


@dataclass(frozen=True, slots=True)
class PublishedProfileCandidate:
    target_revision: int
    target_sha256: str
    already_published: bool = False


class OwnerProfileCandidateBackend(Protocol):
    def prepare(
        self,
        analysis: CandidateAnalysis,
        *,
        scope_sha256: str,
        now: datetime,
    ) -> PreparedProfileCandidate:
        ...

    def confirm(
        self,
        *,
        scope_sha256: str,
        confirmation_code: str,
        now: datetime,
    ) -> PublishedProfileCandidate:
        ...

    def cancel(
        self,
        *,
        scope_sha256: str,
        confirmation_code: str,
        now: datetime,
    ) -> None:
        ...


class FilesystemOwnerProfileCandidateBackend:
    """Private candidate persistence with an injected idempotent publisher.

    The publisher is the only component allowed to create a release or append lifecycle
    events. It must verify the same base revision/digest and be idempotent by target digest.
    """

    def __init__(
        self,
        *,
        store_root: Path,
        active_profile_loader: Callable[[], OwnerProfile],
        publisher: Callable[[StoredProfileCandidate], PublishedProfileCandidate],
        expected_uid: int | None = None,
    ) -> None:
        self.store_root = store_root
        self.active_profile_loader = active_profile_loader
        self.publisher = publisher
        self.expected_uid = expected_uid

    def prepare(
        self,
        analysis: CandidateAnalysis,
        *,
        scope_sha256: str,
        now: datetime,
    ) -> PreparedProfileCandidate:
        base = self.active_profile_loader()
        candidate = prepare_profile_candidate(base, analysis)
        stage_profile_candidate(
            self.store_root,
            candidate,
            scope_sha256=scope_sha256,
            now=now,
            expected_uid=self.expected_uid,
        )
        return candidate

    def confirm(
        self,
        *,
        scope_sha256: str,
        confirmation_code: str,
        now: datetime,
    ) -> PublishedProfileCandidate:
        stored = load_pending_candidate(
            self.store_root,
            scope_sha256=scope_sha256,
            confirmation_code=confirmation_code,
            now=now,
            expected_uid=self.expected_uid,
        )
        active = self.active_profile_loader()
        target = parse_profile_bytes(stored.target_profile_bytes)
        if (active.profile_revision, active.sha256) not in {
            (stored.base_revision, stored.base_sha256),
            (target.profile_revision, target.sha256),
        }:
            raise OwnerProfileError("candidate_base_revision_stale")
        published = self.publisher(stored)
        if (
            published.target_revision != stored.target_revision
            or published.target_sha256 != stored.target_sha256
        ):
            raise OwnerProfileError("candidate_publish_mismatch")
        mark_candidate_consumed(
            self.store_root,
            scope_sha256=scope_sha256,
            candidate_record_sha256=stored.record_sha256,
            confirmation_code=confirmation_code,
            now=now,
            expected_uid=self.expected_uid,
        )
        return published

    def cancel(
        self,
        *,
        scope_sha256: str,
        confirmation_code: str,
        now: datetime,
    ) -> None:
        cancel_pending_candidate(
            self.store_root,
            scope_sha256=scope_sha256,
            confirmation_code=confirmation_code,
            now=now,
            expected_uid=self.expected_uid,
        )


@dataclass(frozen=True, slots=True)
class OwnerProfileWriteResult:
    action: str
    reply: str
    memory_write_performed: bool
    target_revision: int


class OwnerProfileWriteRuntime:
    def __init__(
        self,
        *,
        access_policy: OwnerProfileWriteAccessPolicy,
        read_runtime: OwnerProfileReadRuntime,
        provider: ModelProvider,
        backend: OwnerProfileCandidateBackend,
        audit: AuditLogger,
    ) -> None:
        self.access_policy = access_policy
        self.read_runtime = read_runtime
        self.provider = provider
        self.backend = backend
        self.audit = audit

    def handle(
        self,
        text: str,
        *,
        request_id: str,
        authenticated_context: AuthenticatedConversationContext | None,
        now: datetime,
    ) -> OwnerProfileWriteResult:
        intent = parse_benchmark_write_intent(text)
        if intent is None:
            raise OwnerProfileError("candidate_intent_required")
        access = self.access_policy.authorize(
            authenticated_context,
            provider_name=self.provider.name,
        )
        if intent.action == "propose":
            return self._propose(
                intent,
                access=access,
                request_id=request_id,
                now=now,
            )
        if intent.confirmation_code is None:
            raise OwnerProfileError("candidate_confirmation_rejected")
        if intent.action == "confirm":
            published = self.backend.confirm(
                scope_sha256=access.scope_sha256,
                confirmation_code=intent.confirmation_code,
                now=now,
            )
            self._emit(
                operation="publish",
                outcome="accepted",
                request_id=request_id,
                target_revision=published.target_revision,
                memory_write_performed=True,
            )
            return OwnerProfileWriteResult(
                action="published",
                reply=f"长期记忆已写入 revision {published.target_revision}。",
                memory_write_performed=True,
                target_revision=published.target_revision,
            )
        if intent.action == "cancel":
            self.backend.cancel(
                scope_sha256=access.scope_sha256,
                confirmation_code=intent.confirmation_code,
                now=now,
            )
            self._emit(
                operation="cancel",
                outcome="accepted",
                request_id=request_id,
                target_revision=0,
                memory_write_performed=False,
            )
            return OwnerProfileWriteResult(
                action="cancelled",
                reply="长期记忆候选已取消；没有写入。",
                memory_write_performed=False,
                target_revision=0,
            )
        raise OwnerProfileError("candidate_intent_rejected")

    def _propose(
        self,
        intent: BenchmarkWriteIntent,
        *,
        access: OwnerProfileWriteAccessDecision,
        request_id: str,
        now: datetime,
    ) -> OwnerProfileWriteResult:
        if intent.source_text is None:
            raise OwnerProfileError("candidate_source_out_of_contract")
        selection = self.read_runtime.retrieve(
            build_candidate_retrieval_query(intent.source_text),
            request_id=f"{request_id}-profile-context",
            channel_kind=access.channel_kind,
        )
        analysis = analyze_candidate_with_local_provider(
            self.provider,
            request_id=f"{request_id}-candidate-analysis",
            source_text=intent.source_text,
            relevant_profile_context=(
                selection.context if selection.state == "selected" else None
            ),
        )
        if analysis.outcome != "candidate":
            replies = {
                "no_change": "没有发现需要新增或更新的稳定长期信息，因此没有写入。",
                "needs_owner_resolution": "发现了冲突或歧义，需要你进一步说明；目前没有写入。",
                "temporal_only": "这段内容属于时效信息，应留给 P08；目前没有写入长期 Profile。",
            }
            self._emit(
                operation="analyse",
                outcome="empty",
                request_id=request_id,
                target_revision=0,
                memory_write_performed=False,
                analysis=analysis,
            )
            return OwnerProfileWriteResult(
                action=analysis.outcome,
                reply=replies[analysis.outcome],
                memory_write_performed=False,
                target_revision=0,
            )
        candidate = self.backend.prepare(
            analysis,
            scope_sha256=access.scope_sha256,
            now=now,
        )
        self._emit(
            operation="prepare",
            outcome="accepted",
            request_id=request_id,
            target_revision=candidate.target.profile_revision,
            memory_write_performed=False,
            analysis=analysis,
            candidate=candidate,
        )
        return OwnerProfileWriteResult(
            action="prepared",
            reply=render_candidate_preview(candidate),
            memory_write_performed=False,
            target_revision=candidate.target.profile_revision,
        )

    def _emit(
        self,
        *,
        operation: str,
        outcome: str,
        request_id: str,
        target_revision: int,
        memory_write_performed: bool,
        analysis: CandidateAnalysis | None = None,
        candidate: PreparedProfileCandidate | None = None,
    ) -> None:
        details = dict(
            candidate_audit_projection(
                operation=operation,
                outcome=outcome,
                analysis=analysis,
                candidate=candidate,
            )
        )
        event = str(details.pop("event_namespace"))
        projected_outcome = str(details.pop("outcome"))
        details["target_revision"] = target_revision
        details["memory_write_performed"] = memory_write_performed
        self.audit.emit(
            event,
            outcome=projected_outcome,
            request_id=request_id,
            details=details,
        )
