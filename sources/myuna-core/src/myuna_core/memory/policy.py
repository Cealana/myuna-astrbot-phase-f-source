from __future__ import annotations

from datetime import datetime, timedelta

from .models import (
    CURRENT_SCHEMA_VERSION,
    ConfirmationLevel,
    MemoryCandidate,
    MemoryKind,
    MemoryRecord,
    MemoryStatus,
    PolicyAction,
    PolicyDecision,
    SourceKind,
)


SEALED_ARCHIVE_DIRECTIVES = (
    "不要添加到记忆",
    "不要加入记忆",
    "不进入长期记忆",
    "不要记录这一段",
    "这是测试",
    "不需要记忆",
    "仅限本次会话",
)
DISCARD_DIRECTIVES = (
    "完全不要保存",
    "不要留下任何副本",
    "彻底不留存",
    "不要保存在任何地方",
)
SUPPRESS_DIRECTIVES = (
    "忘了吧",
    "就当没说",
    "这件事算了",
)


class DefaultMemoryPolicy:
    """Real-memory v1 policy: deterministic and free of model calls."""

    policy_version = "memory-policy-v1.0"

    def __init__(
        self,
        current_state_ttl: timedelta = timedelta(days=30),
        light_review_delay: timedelta = timedelta(days=3),
        consolidation_delay: timedelta = timedelta(days=7),
        low_activity_delay: timedelta = timedelta(days=30),
        deletion_recovery_delay: timedelta = timedelta(days=90),
    ) -> None:
        self.current_state_ttl = current_state_ttl
        self.light_review_delay = light_review_delay
        self.consolidation_delay = consolidation_delay
        self.low_activity_delay = low_activity_delay
        self.deletion_recovery_delay = deletion_recovery_delay
        if not (
            timedelta(0) < light_review_delay <= consolidation_delay <= low_activity_delay
        ):
            raise ValueError("memory lifecycle delays must satisfy 0 < review <= consolidate <= low")

    def _provisional_schedule(self, now: datetime) -> dict[str, datetime]:
        return {
            "review_after": now + self.light_review_delay,
            "consolidate_after": now + self.consolidation_delay,
            "low_activity_after": now + self.low_activity_delay,
        }

    def evaluate(self, candidate: MemoryCandidate, now: datetime) -> PolicyDecision:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("now must be timezone-aware")

        if candidate.source.kind is SourceKind.OPERATIONAL_RECORD:
            return PolicyDecision(
                action=PolicyAction.STORE_AS_EXTERNAL_RECORD,
                status=None,
                reason_codes=("operational_record_is_not_personal_memory",),
            )

        directive = candidate.directive_text.replace(" ", "")
        if any(marker in directive for marker in DISCARD_DIRECTIVES):
            return PolicyDecision(
                action=PolicyAction.DISCARD,
                status=MemoryStatus.EXCLUDED,
                reason_codes=("explicit_no_storage_anywhere",),
            )

        if any(marker in directive for marker in SEALED_ARCHIVE_DIRECTIVES):
            return PolicyDecision(
                action=PolicyAction.SEALED_ARCHIVE,
                status=MemoryStatus.EXCLUDED,
                reason_codes=("sealed_no_recall_archive",),
                archive_receipt_required=True,
            )

        if any(marker in directive for marker in SUPPRESS_DIRECTIVES):
            return PolicyDecision(
                action=PolicyAction.RETAIN_SUPPRESSED,
                status=MemoryStatus.SUPPRESSED,
                reason_codes=("colloquial_forget_is_not_deletion",),
                do_not_surface_proactively=True,
            )

        if candidate.kind is MemoryKind.CURRENT_STATE:
            schedule = self._provisional_schedule(now)
            return PolicyDecision(
                action=PolicyAction.RETAIN_PROVISIONAL,
                status=MemoryStatus.PROVISIONAL,
                reason_codes=("temporary_current_state", "ask_when_uncertain"),
                expires_at=candidate.expires_at or now + self.current_state_ttl,
                **schedule,
            )

        if (
            candidate.confirmation is ConfirmationLevel.MODEL_INFERRED
            or candidate.source.kind is SourceKind.MODEL_INFERENCE
        ):
            schedule = self._provisional_schedule(now)
            return PolicyDecision(
                action=PolicyAction.RETAIN_PROVISIONAL,
                status=MemoryStatus.PROVISIONAL,
                reason_codes=("model_inference_cannot_self_confirm",),
                **schedule,
            )

        if candidate.confirmation is ConfirmationLevel.USER_CONFIRMED:
            return PolicyDecision(
                action=PolicyAction.RETAIN_CONFIRMED,
                status=MemoryStatus.CONFIRMED,
                reason_codes=("user_confirmed",),
            )

        schedule = self._provisional_schedule(now)
        return PolicyDecision(
            action=PolicyAction.RETAIN_PROVISIONAL,
            status=MemoryStatus.PROVISIONAL,
            reason_codes=("awaiting_confirmation_or_consolidation", "ask_when_uncertain"),
            **schedule,
        )

    def materialize(
        self,
        candidate: MemoryCandidate,
        decision: PolicyDecision,
    ) -> MemoryRecord | None:
        if decision.action in {
            PolicyAction.EXCLUDE,
            PolicyAction.SESSION_ONLY,
            PolicyAction.SEALED_ARCHIVE,
            PolicyAction.DISCARD,
            PolicyAction.STORE_AS_EXTERNAL_RECORD,
        }:
            return None
        if decision.status is None:
            raise ValueError("retained decisions require a status")
        return MemoryRecord(
            memory_id=candidate.memory_id,
            schema_version=CURRENT_SCHEMA_VERSION,
            policy_version=self.policy_version,
            source=candidate.source,
            kind=candidate.kind,
            status=decision.status,
            confirmation=candidate.confirmation,
            text=candidate.text,
            occurred_at=candidate.occurred_at,
            recorded_at=candidate.recorded_at,
            timezone=candidate.timezone,
            time_precision=candidate.time_precision,
            time_phrase=candidate.time_phrase,
            exact_quote=candidate.exact_quote,
            scope=candidate.scope,
            importance=candidate.importance,
            sensitivity=candidate.sensitivity,
            tags=candidate.tags,
            do_not_surface_proactively=decision.do_not_surface_proactively,
            expires_at=decision.expires_at or candidate.expires_at,
            supersedes_id=candidate.supersedes_id,
            policy_reasons=decision.reason_codes,
            metadata=candidate.metadata,
            rationale=candidate.rationale,
            review_after=decision.review_after or candidate.review_after,
            consolidate_after=decision.consolidate_after or candidate.consolidate_after,
            low_activity_after=decision.low_activity_after or candidate.low_activity_after,
        )
