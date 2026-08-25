from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date, datetime
from hashlib import sha256
from typing import TYPE_CHECKING, Mapping

from .contracts import (
    ArchivedContent,
    CompleteTurn,
    CompleteTurnDraft,
    EpisodicMemoryError,
    TurnTimeCorrection,
    TurnTimeBinding,
    require_digest,
    require_id,
    semantic_digest,
    require_utc,
)
from .owner_day import OwnerDayPolicy, owner_day_label

if TYPE_CHECKING:
    from .store import LosslessArchiveStore

DELIVERY_JOURNAL_SCHEMA = "myuna.owner-private-memory-delivery-facts.v2"
FACTUAL_DELIVERY_EPISODE_SCHEMA = "myuna.p08-factual-delivery-episode.v1"
FACTUAL_DELIVERY_EPISODE_STATES = frozenset(
    {
        "OPEN_EXACT_START",
        "OPEN_TIME_UNRESOLVED",
        "CANCELLED_UNRESOLVED",
        "CLOSED_EXACT",
        "CLOSED_TIME_UNRESOLVED",
    }
)


@dataclass(frozen=True, slots=True)
class DeliveryPreparation:
    delivery_token: str
    turn_id: str
    owner: ArchivedContent
    assistant: ArchivedContent
    prompt_time_binding: TurnTimeBinding
    source_occurred_at_utc: datetime
    committed_monotonic_ns: int
    epoch_id: str
    release_set_id: str
    request_digest: str
    response_digest: str
    expected_archive_turn_count: int | None
    expected_archive_head_digest: str | None
    provenance_categories: tuple[str, ...]
    provenance_digest: str

    def __post_init__(self) -> None:
        require_digest(self.delivery_token, "delivery_token")
        require_id(self.turn_id, "turn_id")
        if (self.expected_archive_turn_count is None) != (
            self.expected_archive_head_digest is None
        ):
            raise EpisodicMemoryError("delivery_archive_head_binding_invalid")
        if self.expected_archive_turn_count is not None:
            if (
                isinstance(self.expected_archive_turn_count, bool)
                or not isinstance(self.expected_archive_turn_count, int)
                or self.expected_archive_turn_count < 0
            ):
                raise EpisodicMemoryError("delivery_archive_turn_count_invalid")
            require_digest(
                self.expected_archive_head_digest,  # type: ignore[arg-type]
                "delivery_expected_head",
            )
        object.__setattr__(
            self,
            "source_occurred_at_utc",
            require_utc(self.source_occurred_at_utc, "delivery_source_occurred_at"),
        )
        if (
            isinstance(self.committed_monotonic_ns, bool)
            or not isinstance(self.committed_monotonic_ns, int)
            or self.committed_monotonic_ns < self.prompt_time_binding.received_monotonic_ns
        ):
            raise EpisodicMemoryError("delivery_committed_monotonic_invalid")
        require_id(self.epoch_id, "delivery_epoch_id")
        for value, label in (
            (self.release_set_id, "delivery_release_set"),
            (self.request_digest, "delivery_request"),
            (self.response_digest, "delivery_response"),
            (self.provenance_digest, "delivery_provenance"),
        ):
            require_digest(value, label)
        if not self.provenance_categories or len(set(self.provenance_categories)) != len(
            self.provenance_categories
        ):
            raise EpisodicMemoryError("delivery_provenance_categories_invalid")
        for category in self.provenance_categories:
            require_id(category, "delivery_provenance_category")

    def payload(self) -> dict[str, object]:
        if (
            self.expected_archive_turn_count is None
            or self.expected_archive_head_digest is None
        ):
            raise EpisodicMemoryError("delivery_preparation_unbound")
        return {
            "assistant": {
                "kind": self.assistant.kind,
                "media_identity_digest": self.assistant.media_identity_digest,
                "text": self.assistant.text,
            },
            "delivery_token": self.delivery_token,
            "committed_monotonic_ns": self.committed_monotonic_ns,
            "epoch_id": self.epoch_id,
            "expected_archive_head_digest": self.expected_archive_head_digest,
            "expected_archive_turn_count": self.expected_archive_turn_count,
            "owner": {
                "kind": self.owner.kind,
                "media_identity_digest": self.owner.media_identity_digest,
                "text": self.owner.text,
            },
            "prompt_time_binding": self.prompt_time_binding.payload(),
            "source_occurred_at_utc": self.source_occurred_at_utc.isoformat(
                timespec="microseconds"
            ),
            "provenance_categories": list(self.provenance_categories),
            "provenance_digest": self.provenance_digest,
            "release_set_id": self.release_set_id,
            "request_digest": self.request_digest,
            "response_digest": self.response_digest,
            "turn_id": self.turn_id,
        }

    @property
    def preparation_digest(self) -> str:
        return semantic_digest("myuna-p07-delivery-preparation-v1", self.payload())

    def bind_archive_head(
        self,
        *,
        turn_count: int,
        head_digest: str,
    ) -> DeliveryPreparation:
        if (
            self.expected_archive_turn_count is not None
            and self.expected_archive_turn_count != turn_count
        ) or (
            self.expected_archive_head_digest is not None
            and self.expected_archive_head_digest != head_digest
        ):
            raise EpisodicMemoryError("delivery_preparation_stale_head")
        return replace(
            self,
            expected_archive_turn_count=turn_count,
            expected_archive_head_digest=head_digest,
        )

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> DeliveryPreparation:
        expected = {
            "assistant",
            "committed_monotonic_ns",
            "delivery_token",
            "epoch_id",
            "expected_archive_head_digest",
            "expected_archive_turn_count",
            "owner",
            "prompt_time_binding",
            "source_occurred_at_utc",
            "provenance_categories",
            "provenance_digest",
            "release_set_id",
            "request_digest",
            "response_digest",
            "turn_id",
        }
        if (
            set(payload) != expected
            or not isinstance(payload["owner"], Mapping)
            or not isinstance(payload["assistant"], Mapping)
            or not isinstance(payload["prompt_time_binding"], Mapping)
            or not isinstance(payload["provenance_categories"], list)
        ):
            raise EpisodicMemoryError("delivery_preparation_schema_rejected")

        def content(value: Mapping[str, object]) -> ArchivedContent:
            if set(value) != {"kind", "media_identity_digest", "text"}:
                raise EpisodicMemoryError("delivery_content_schema_rejected")
            return ArchivedContent(
                value["kind"],  # type: ignore[arg-type]
                value["text"],  # type: ignore[arg-type]
                value["media_identity_digest"],  # type: ignore[arg-type]
            )

        return cls(
            delivery_token=payload["delivery_token"],  # type: ignore[arg-type]
            turn_id=payload["turn_id"],  # type: ignore[arg-type]
            owner=content(payload["owner"]),
            assistant=content(payload["assistant"]),
            prompt_time_binding=TurnTimeBinding.from_payload(payload["prompt_time_binding"]),
            source_occurred_at_utc=datetime.fromisoformat(
                payload["source_occurred_at_utc"]  # type: ignore[arg-type]
            ),
            committed_monotonic_ns=payload["committed_monotonic_ns"],  # type: ignore[arg-type]
            epoch_id=payload["epoch_id"],  # type: ignore[arg-type]
            release_set_id=payload["release_set_id"],  # type: ignore[arg-type]
            request_digest=payload["request_digest"],  # type: ignore[arg-type]
            response_digest=payload["response_digest"],  # type: ignore[arg-type]
            expected_archive_turn_count=payload[
                "expected_archive_turn_count"
            ],  # type: ignore[arg-type]
            expected_archive_head_digest=payload[
                "expected_archive_head_digest"
            ],  # type: ignore[arg-type]
            provenance_categories=tuple(payload["provenance_categories"]),  # type: ignore[arg-type]
            provenance_digest=payload["provenance_digest"],  # type: ignore[arg-type]
        )

    def complete_turn_draft(
        self,
        *,
        sequence: int,
        previous_turn_digest: str,
        final_time_binding: TurnTimeBinding,
        delivery_ack_digest: str,
    ) -> CompleteTurnDraft:
        require_digest(delivery_ack_digest, "delivery_ack")
        require_digest(previous_turn_digest, "delivery_parent")
        return CompleteTurnDraft(
            turn_id=self.turn_id,
            sequence=sequence,
            owner=self.owner,
            assistant=self.assistant,
            time_binding=final_time_binding,
            epoch_id=self.epoch_id,
            release_set_id=self.release_set_id,
            request_digest=self.request_digest,
            response_digest=self.response_digest,
            delivery_ack_digest=delivery_ack_digest,
            previous_turn_digest=previous_turn_digest,
            provenance_categories=self.provenance_categories,
        )


@dataclass(frozen=True, slots=True)
class FactualDeliveryEpisodeV1:
    """Content-free projection of one preparation/event/turn fact set."""

    archive_identity: str
    turn_id: str
    request_digest: str
    delivery_token: str
    preparation_digest: str
    state: str
    delivery_event_digest: str | None
    complete_turn_digest: str | None
    start_time_binding_digest: str
    original_time_binding_digest: str | None
    effective_time_binding_digest: str | None
    correction_digests: tuple[str, ...]
    owner_day_policy_digest: str | None
    start_utc: datetime | None
    end_utc: datetime | None
    interval_duration_ns: int | None
    owner_day: date | None
    schema: str = FACTUAL_DELIVERY_EPISODE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != FACTUAL_DELIVERY_EPISODE_SCHEMA:
            raise EpisodicMemoryError("delivery_episode_schema_rejected")
        require_id(self.archive_identity, "delivery_episode_archive")
        require_id(self.turn_id, "delivery_episode_turn")
        for value, label in (
            (self.request_digest, "delivery_episode_request"),
            (self.delivery_token, "delivery_episode_token"),
            (self.preparation_digest, "delivery_episode_preparation"),
            (self.start_time_binding_digest, "delivery_episode_start_binding"),
        ):
            require_digest(value, label)
        for value, label in (
            (self.delivery_event_digest, "delivery_episode_event"),
            (self.complete_turn_digest, "delivery_episode_turn_digest"),
            (self.original_time_binding_digest, "delivery_episode_original_time"),
            (self.effective_time_binding_digest, "delivery_episode_effective_time"),
            (self.owner_day_policy_digest, "delivery_episode_owner_day_policy"),
        ):
            if value is not None:
                require_digest(value, label)
        if self.state not in FACTUAL_DELIVERY_EPISODE_STATES:
            raise EpisodicMemoryError("delivery_episode_state_rejected")
        if len(set(self.correction_digests)) != len(self.correction_digests):
            raise EpisodicMemoryError("delivery_episode_correction_duplicate")
        for digest in self.correction_digests:
            require_digest(digest, "delivery_episode_correction")
        for name in ("start_utc", "end_utc"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, require_utc(value, name))
        if self.state == "CLOSED_EXACT":
            if (
                self.delivery_event_digest is None
                or self.complete_turn_digest is None
                or self.original_time_binding_digest is None
                or self.effective_time_binding_digest is None
                or self.start_utc is None
                or self.end_utc is None
                or self.interval_duration_ns is None
                or self.start_utc > self.end_utc
                or isinstance(self.interval_duration_ns, bool)
                or not isinstance(self.interval_duration_ns, int)
                or self.interval_duration_ns < 0
            ):
                raise EpisodicMemoryError("delivery_episode_exact_incomplete")
            if (self.owner_day_policy_digest is None) != (self.owner_day is None):
                raise EpisodicMemoryError("delivery_episode_owner_day_incomplete")
        else:
            if (
                self.end_utc is not None
                or self.interval_duration_ns is not None
                or self.owner_day is not None
            ):
                raise EpisodicMemoryError("delivery_episode_unresolved_claims_exact")
        if self.state.startswith("OPEN_") and (
            self.delivery_event_digest is not None
            or self.complete_turn_digest is not None
            or self.original_time_binding_digest is not None
            or self.effective_time_binding_digest is not None
            or self.correction_digests
        ):
            raise EpisodicMemoryError("delivery_episode_open_has_close_fact")
        if self.state == "CANCELLED_UNRESOLVED" and (
            self.delivery_event_digest is None
            or self.complete_turn_digest is not None
            or self.original_time_binding_digest is not None
            or self.effective_time_binding_digest is not None
            or self.correction_digests
        ):
            raise EpisodicMemoryError("delivery_episode_cancelled_fact_invalid")

    @property
    def episode_id(self) -> str:
        return semantic_digest(
            "myuna-p08-factual-delivery-episode-identity-v1",
            {
                "archive_identity": self.archive_identity,
                "request_digest": self.request_digest,
                "schema": self.schema,
                "turn_id": self.turn_id,
            },
        )

    def payload(self) -> dict[str, object]:
        timestamp = lambda value: (  # noqa: E731 - local canonical encoder
            None if value is None else value.isoformat(timespec="microseconds")
        )
        return {
            "archive_identity": self.archive_identity,
            "complete_turn_digest": self.complete_turn_digest,
            "correction_digests": list(self.correction_digests),
            "delivery_event_digest": self.delivery_event_digest,
            "delivery_token": self.delivery_token,
            "effective_time_binding_digest": self.effective_time_binding_digest,
            "end_utc": timestamp(self.end_utc),
            "episode_id": self.episode_id,
            "interval_duration_ns": self.interval_duration_ns,
            "original_time_binding_digest": self.original_time_binding_digest,
            "owner_day": None if self.owner_day is None else self.owner_day.isoformat(),
            "owner_day_policy_digest": self.owner_day_policy_digest,
            "preparation_digest": self.preparation_digest,
            "request_digest": self.request_digest,
            "schema": self.schema,
            "start_time_binding_digest": self.start_time_binding_digest,
            "start_utc": timestamp(self.start_utc),
            "state": self.state,
            "turn_id": self.turn_id,
        }

    @property
    def projection_digest(self) -> str:
        return semantic_digest(
            "myuna-p08-factual-delivery-episode-projection-v1", self.payload()
        )

    def audit_projection(self) -> dict[str, object]:
        return self.payload() | {"projection_digest": self.projection_digest}

    @classmethod
    def derive(
        cls,
        preparation: DeliveryPreparation,
        *,
        outcome: str | None = None,
        delivery_event_digest: str | None = None,
        delivered_monotonic_ns: int | None = None,
        delivery_ack_digest: str | None = None,
        complete_turn: CompleteTurn | None = None,
        time_corrections: tuple[TurnTimeCorrection, ...] = (),
        owner_day_policy: OwnerDayPolicy | None = None,
    ) -> FactualDeliveryEpisodeV1:
        policy_digest = (
            None if owner_day_policy is None else owner_day_policy.policy_digest
        )
        start_binding = preparation.prompt_time_binding
        matching_corrections = tuple(
            correction
            for correction in time_corrections
            if correction.turn_id == preparation.turn_id
        )
        start_utc = (
            start_binding.received_at_utc if start_binding.status == "exact" else None
        )
        if outcome is None:
            if any(
                value is not None
                for value in (
                    delivery_event_digest,
                    delivered_monotonic_ns,
                    delivery_ack_digest,
                    complete_turn,
                )
            ) or matching_corrections:
                raise EpisodicMemoryError("delivery_episode_open_fact_mixed")
            return cls(
                archive_identity=preparation.epoch_id,
                turn_id=preparation.turn_id,
                request_digest=preparation.request_digest,
                delivery_token=preparation.delivery_token,
                preparation_digest=preparation.preparation_digest,
                state=(
                    "OPEN_EXACT_START"
                    if start_binding.status == "exact"
                    else "OPEN_TIME_UNRESOLVED"
                ),
                delivery_event_digest=None,
                complete_turn_digest=None,
                start_time_binding_digest=start_binding.binding_digest,
                original_time_binding_digest=None,
                effective_time_binding_digest=None,
                correction_digests=(),
                owner_day_policy_digest=policy_digest,
                start_utc=start_utc,
                end_utc=None,
                interval_duration_ns=None,
                owner_day=None,
            )
        if outcome == "cancelled":
            if (
                delivery_event_digest is None
                or delivered_monotonic_ns is not None
                or delivery_ack_digest is not None
                or complete_turn is not None
                or matching_corrections
            ):
                raise EpisodicMemoryError("delivery_episode_cancelled_fact_mixed")
            return cls(
                archive_identity=preparation.epoch_id,
                turn_id=preparation.turn_id,
                request_digest=preparation.request_digest,
                delivery_token=preparation.delivery_token,
                preparation_digest=preparation.preparation_digest,
                state="CANCELLED_UNRESOLVED",
                delivery_event_digest=delivery_event_digest,
                complete_turn_digest=None,
                start_time_binding_digest=start_binding.binding_digest,
                original_time_binding_digest=None,
                effective_time_binding_digest=None,
                correction_digests=(),
                owner_day_policy_digest=policy_digest,
                start_utc=start_utc,
                end_utc=None,
                interval_duration_ns=None,
                owner_day=None,
            )
        if outcome != "delivered":
            raise EpisodicMemoryError("delivery_episode_outcome_rejected")
        if delivery_event_digest is None or delivery_ack_digest is None or complete_turn is None:
            raise EpisodicMemoryError("delivery_episode_close_fact_incomplete")
        require_digest(delivery_ack_digest, "delivery_episode_ack")
        draft = complete_turn.draft
        if (
            draft.turn_id != preparation.turn_id
            or draft.owner != preparation.owner
            or draft.assistant != preparation.assistant
            or draft.epoch_id != preparation.epoch_id
            or draft.release_set_id != preparation.release_set_id
            or draft.request_digest != preparation.request_digest
            or draft.response_digest != preparation.response_digest
            or draft.delivery_ack_digest != delivery_ack_digest
            or draft.provenance_categories != preparation.provenance_categories
        ):
            raise EpisodicMemoryError("delivery_episode_turn_binding_drifted")
        if delivered_monotonic_ns is not None and (
            isinstance(delivered_monotonic_ns, bool)
            or not isinstance(delivered_monotonic_ns, int)
            or delivered_monotonic_ns < 0
        ):
            raise EpisodicMemoryError("delivery_episode_close_marker_invalid")
        original = draft.time_binding
        if original.status == "exact" and (
            delivered_monotonic_ns is None
            or original.delivered_monotonic_ns != delivered_monotonic_ns
        ):
            raise EpisodicMemoryError("delivery_episode_close_marker_drifted")
        selected: TurnTimeCorrection | None = None
        selected_digests: list[str] = []
        selected_ids: set[str] = set()
        for correction in time_corrections:
            if correction.turn_id != preparation.turn_id:
                continue
            if (
                correction.correction_id in selected_ids
                or correction.turn_digest != complete_turn.turn_digest
                or correction.original_binding_digest != original.binding_digest
            ):
                raise EpisodicMemoryError("delivery_episode_correction_source_drifted")
            if (
                selected is not None
                and selected.corrected_binding.binding_digest
                != correction.corrected_binding.binding_digest
            ):
                raise EpisodicMemoryError("delivery_episode_correction_conflicted")
            selected = correction
            selected_ids.add(correction.correction_id)
            selected_digests.append(correction.correction_digest)
        effective = original if selected is None else selected.corrected_binding
        if effective.status != "exact":
            return cls(
                archive_identity=preparation.epoch_id,
                turn_id=preparation.turn_id,
                request_digest=preparation.request_digest,
                delivery_token=preparation.delivery_token,
                preparation_digest=preparation.preparation_digest,
                state="CLOSED_TIME_UNRESOLVED",
                delivery_event_digest=delivery_event_digest,
                complete_turn_digest=complete_turn.turn_digest,
                start_time_binding_digest=start_binding.binding_digest,
                original_time_binding_digest=original.binding_digest,
                effective_time_binding_digest=effective.binding_digest,
                correction_digests=tuple(selected_digests),
                owner_day_policy_digest=policy_digest,
                start_utc=start_utc,
                end_utc=None,
                interval_duration_ns=None,
                owner_day=None,
            )
        assert effective.received_at_utc is not None
        assert effective.delivered_at_utc is not None
        day = (
            None
            if owner_day_policy is None
            else owner_day_label(effective.delivered_at_utc, owner_day_policy)
        )
        return cls(
            archive_identity=preparation.epoch_id,
            turn_id=preparation.turn_id,
            request_digest=preparation.request_digest,
            delivery_token=preparation.delivery_token,
            preparation_digest=preparation.preparation_digest,
            state="CLOSED_EXACT",
            delivery_event_digest=delivery_event_digest,
            complete_turn_digest=complete_turn.turn_digest,
            start_time_binding_digest=start_binding.binding_digest,
            original_time_binding_digest=original.binding_digest,
            effective_time_binding_digest=effective.binding_digest,
            correction_digests=tuple(selected_digests),
            owner_day_policy_digest=policy_digest,
            start_utc=effective.received_at_utc,
            end_utc=effective.delivered_at_utc,
            interval_duration_ns=(
                effective.delivered_monotonic_ns - effective.received_monotonic_ns
            ),
            owner_day=day,
        )


@dataclass(frozen=True, slots=True)
class DeliveryPreparationResolution:
    preparation: DeliveryPreparation
    replayed: bool
    episode: FactualDeliveryEpisodeV1


@dataclass(frozen=True, slots=True)
class DeliveryResolution:
    preparation: DeliveryPreparation
    outcome: str
    delivered_monotonic_ns: int | None
    delivered_boot_id: str | None
    delivery_ack_digest: str | None
    archived: bool
    replayed: bool
    episode: FactualDeliveryEpisodeV1
    complete_turn: CompleteTurn | None = None
    archive_turns: tuple[CompleteTurn, ...] = ()
    time_corrections: tuple[TurnTimeCorrection, ...] = ()


class DeliveryJournal:
    """Stateless compatibility facade over the sole raw factual store."""

    def __init__(self, store: LosslessArchiveStore) -> None:
        self.store = store

    def initialize(self) -> None:
        self.store.initialize()

    def prepare(self, preparation: DeliveryPreparation) -> bool:
        result = self.store.prepare_delivery(preparation)
        if not isinstance(result, bool):
            raise EpisodicMemoryError("delivery_preparation_result_rejected")
        return result

    def prepare_episode(
        self,
        preparation: DeliveryPreparation,
        *,
        owner_day_policy: OwnerDayPolicy | None = None,
    ) -> DeliveryPreparationResolution:
        return self.store.prepare_delivery_episode(
            preparation, owner_day_policy=owner_day_policy
        )

    def resolve(
        self,
        *,
        delivery_token: str,
        outcome: str,
        delivered_monotonic_ns: int | None,
        delivered_boot_id: str | None = None,
        owner_day_policy: OwnerDayPolicy | None = None,
        crash_stage: str | None = None,
    ) -> DeliveryResolution:
        return self.store.resolve_delivery(
            delivery_token=delivery_token,
            outcome=outcome,
            delivered_monotonic_ns=delivered_monotonic_ns,
            delivered_boot_id=delivered_boot_id,
            owner_day_policy=owner_day_policy,
            crash_stage=crash_stage,
        )

    def close_evidence_required(self, delivery_token: str) -> bool:
        return self.store.delivery_close_evidence_required(delivery_token)

    def recoverable(self) -> tuple[DeliveryResolution, ...]:
        return ()

    def unresolved_preparations(self) -> tuple[DeliveryPreparation, ...]:
        return self.store.unresolved_preparations()

    def metadata(self) -> dict[str, object]:
        return self.store.delivery_metadata()


def response_digest(reply: str) -> str:
    if not isinstance(reply, str) or not reply:
        raise EpisodicMemoryError("delivery_reply_invalid")
    return sha256(b"myuna-p07-assistant-reply-v1\0" + reply.encode("utf-8")).hexdigest()
