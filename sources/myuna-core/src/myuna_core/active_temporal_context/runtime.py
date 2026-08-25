from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
import json

from myuna_core.authenticated_conversation import AuthenticatedConversationContext
from myuna_core.trusted_time.errors import TrustedTimeError

from .access import TemporalAccessPolicy
from .contracts import (
    PreparedTemporalProposal,
    TemporalContextError,
    TemporalFactDraft,
    TemporalMutationResult,
    TemporalRetrievalResult,
)
from .store import TemporalContextStore
from .time import TrustedTimePort


MAX_ACTIVE_SNAPSHOT_CHARACTERS = 12_000
MAX_LIFECYCLE_TRANSITIONS_PER_SNAPSHOT = 4


@dataclass(frozen=True, slots=True)
class ActiveTemporalSnapshot:
    sample: object
    context: str
    fact_count: int
    projection_digest: str
    lifecycle_transitions: tuple[object, ...] = ()
    lifecycle_watermark: int = 0
    lifecycle_has_more: bool = False

    def audit_projection(self) -> dict[str, object]:
        return {
            "fact_count": self.fact_count,
            "projection_digest": self.projection_digest,
            "lifecycle_has_more": self.lifecycle_has_more,
            "lifecycle_transition_count": len(self.lifecycle_transitions),
            "lifecycle_watermark": self.lifecycle_watermark,
            "trusted_time_sequence": getattr(self.sample, "sequence", None),
            "trusted_time_source_class": getattr(self.sample, "source_class", None),
        }


@dataclass(frozen=True, slots=True)
class ContentFreeTemporalStatus:
    sample: object
    active_fact_count: int
    active_set_complete: bool
    active_set_digest: str
    lifecycle_complete: bool
    lifecycle_digest: str
    lifecycle_event_count: int
    lifecycle_watermark: int
    pending_proposal_count: int
    scope_binding_digest: str
    total_fact_count: int
    trusted_time_binding_digest: str

    def audit_projection(self) -> dict[str, object]:
        return {
            "active_fact_count": self.active_fact_count,
            "active_set_complete": self.active_set_complete,
            "active_set_digest": self.active_set_digest,
            "lifecycle_complete": self.lifecycle_complete,
            "lifecycle_digest": self.lifecycle_digest,
            "lifecycle_event_count": self.lifecycle_event_count,
            "lifecycle_watermark": self.lifecycle_watermark,
            "pending_proposal_count": self.pending_proposal_count,
            "scope_binding_digest": self.scope_binding_digest,
            "total_fact_count": self.total_fact_count,
            "trusted_time_binding_digest": self.trusted_time_binding_digest,
            "trusted_time_evidence_complete": True,
        }


class ActiveTemporalContextRuntime:
    """Bind P08 access/store operations to exactly one P10-B time sample.

    This adapter is deliberately transport-neutral.  It never accepts a wall-clock
    value from a caller and never falls back to message, filesystem or database time.
    """

    def __init__(
        self,
        store: TemporalContextStore,
        trusted_time: TrustedTimePort,
        *,
        access_policy: TemporalAccessPolicy | None = None,
    ) -> None:
        if not isinstance(store, TemporalContextStore):
            raise TypeError("store must be TemporalContextStore")
        if not isinstance(trusted_time, TrustedTimePort):
            raise TypeError("trusted_time must implement TrustedTimePort")
        self.store = store
        self.trusted_time = trusted_time
        self.access_policy = access_policy or TemporalAccessPolicy()

    def _sample(self):
        try:
            return self.trusted_time.sample()
        except TrustedTimeError as error:
            raise TemporalContextError(error.code, retryable=error.retryable) from None
        except TemporalContextError:
            raise
        except Exception:
            raise TemporalContextError("trusted_time_unavailable", retryable=True) from None

    def retrieve(
        self,
        context: AuthenticatedConversationContext,
        *,
        query: str,
        categories: tuple[str, ...] = (),
        slot_keys: tuple[str, ...] = (),
    ) -> TemporalRetrievalResult:
        result, _sample = self.retrieve_with_sample(
            context,
            query=query,
            categories=categories,
            slot_keys=slot_keys,
        )
        return result

    def retrieve_with_sample(
        self,
        context: AuthenticatedConversationContext,
        *,
        query: str,
        categories: tuple[str, ...] = (),
        slot_keys: tuple[str, ...] = (),
    ):
        scope = self.access_policy.authorize_read(context)
        sample = self._sample()
        return self.store.retrieve(
            scope,
            sample,
            query=query,
            categories=categories,
            slot_keys=slot_keys,
        ), sample

    def snapshot_active(
        self,
        context: AuthenticatedConversationContext,
        *,
        after_event_sequence: int = 0,
    ) -> ActiveTemporalSnapshot:
        """Return every active item or a typed overflow; never silently truncate."""

        scope = self.access_policy.authorize_read(context)
        sample = self._sample()
        if not getattr(sample, "evidence_complete", False):
            raise TemporalContextError("trusted_time_evidence_unavailable", retryable=True)
        facts, transitions, watermark, has_more = self.store.active_facts_with_lifecycle(
            scope,
            sample,
            after_event_sequence=after_event_sequence,
            maximum_events=MAX_LIFECYCLE_TRANSITIONS_PER_SNAPSHOT,
        )
        ordered = tuple(
            sorted(facts, key=lambda item: (item.category, item.slot_key, item.fact_id))
        )
        lines = (
            "[active_temporal_validity_context_v1 all_or_none=true "
            "profile_promotion=false]",
            *(
                f"- [{fact.category}:{fact.slot_key} state={fact.state} "
                f"valid_from={fact.valid_from.isoformat(timespec='seconds')} "
                f"valid_until={fact.effective_end.isoformat(timespec='seconds')} "
                f"source={fact.source_kind}:{fact.source_ref}] {fact.summary}"
                for fact in ordered
            ),
        )
        rendered = "\n".join(lines)
        if len(rendered) > MAX_ACTIVE_SNAPSHOT_CHARACTERS:
            raise TemporalContextError("active_projection_overflow")
        semantic = {
            "context_digest": sha256(rendered.encode("utf-8")).hexdigest(),
            "facts": [
                {
                    "fact_id": fact.fact_id,
                    "revision": fact.revision,
                    "source_ref": fact.source_ref,
                    "state": fact.state,
                }
                for fact in ordered
            ],
            "sample": sample.as_payload(),
            "schema": "myuna.active-temporal-snapshot.v1",
        }
        digest = sha256(
            json.dumps(
                semantic,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        return ActiveTemporalSnapshot(
            sample,
            rendered,
            len(ordered),
            digest,
            transitions,
            watermark,
            has_more,
        )

    def content_free_status(
        self,
        context: AuthenticatedConversationContext,
    ) -> ContentFreeTemporalStatus:
        """Return complete P08 lifecycle identity without temporal text."""

        scope = self.access_policy.authorize_read(context)
        sample = self._sample()
        if not getattr(sample, "evidence_complete", False) or not getattr(
            sample, "synchronized", False
        ):
            raise TemporalContextError("trusted_time_evidence_unavailable", retryable=True)
        status = self.store.content_free_lifecycle_status(scope, sample)
        trusted_time_identity = {
            "authority": sample.authority,
            "boot_id": sample.boot_id,
            "source": sample.source,
            "source_class": sample.source_class,
            "synchronized": sample.synchronized,
            "uncertainty_microseconds": sample.uncertainty_microseconds,
        }
        trusted_time_binding_digest = sha256(
            b"myuna-p08-content-free-trusted-time-binding-v1\0"
            + json.dumps(
                trusted_time_identity,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        ).hexdigest()
        return ContentFreeTemporalStatus(
            sample=sample,
            scope_binding_digest=scope.scope_sha256,
            trusted_time_binding_digest=trusted_time_binding_digest,
            **status,
        )

    def propose(
        self,
        context: AuthenticatedConversationContext,
        *,
        explicit_intent: bool,
        request_id: str,
        action: str,
        draft: TemporalFactDraft | None = None,
        target_fact_id: str | None = None,
        ttl: timedelta = timedelta(minutes=10),
    ) -> PreparedTemporalProposal:
        result, _sample = self.propose_with_sample(
            context,
            explicit_intent=explicit_intent,
            request_id=request_id,
            action=action,
            draft=draft,
            target_fact_id=target_fact_id,
            ttl=ttl,
        )
        return result

    def propose_with_sample(
        self,
        context: AuthenticatedConversationContext,
        *,
        explicit_intent: bool,
        request_id: str,
        action: str,
        draft: TemporalFactDraft | None = None,
        target_fact_id: str | None = None,
        ttl: timedelta = timedelta(minutes=10),
    ):
        scope = self.access_policy.authorize_write(
            context,
            explicit_intent=explicit_intent,
        )
        sample = self._sample()
        return self.store.propose_mutation(
            scope,
            request_id=request_id,
            action=action,
            sample=sample,
            draft=draft,
            target_fact_id=target_fact_id,
            ttl=ttl,
        ), sample

    def confirm(
        self,
        context: AuthenticatedConversationContext,
        *,
        explicit_intent: bool,
        request_id: str,
        proposal_id: str,
        confirmation_code: str,
    ) -> TemporalMutationResult:
        result, _sample = self.confirm_with_sample(
            context,
            explicit_intent=explicit_intent,
            request_id=request_id,
            proposal_id=proposal_id,
            confirmation_code=confirmation_code,
        )
        return result

    def confirm_with_sample(
        self,
        context: AuthenticatedConversationContext,
        *,
        explicit_intent: bool,
        request_id: str,
        proposal_id: str,
        confirmation_code: str,
    ):
        scope = self.access_policy.authorize_write(
            context,
            explicit_intent=explicit_intent,
        )
        sample = self._sample()
        return self.store.confirm_mutation(
            scope,
            request_id=request_id,
            proposal_id=proposal_id,
            confirmation_code=confirmation_code,
            sample=sample,
        ), sample

    def expire_due(self) -> int:
        return self.store.expire_due(self._sample())
