from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import json
from typing import Callable, Mapping, Sequence

from myuna_core.authenticated_conversation import AuthenticatedConversationContext
from myuna_core.external_context.contracts import (
    EgressSafetySignals,
    ExternalContextError,
    VisualEvidence,
    current_message_digest,
    projection_digest,
)
from myuna_core.external_context.projection import (
    MAX_PROFILE_CONTEXT_CHARACTERS,
    MAX_PROFILE_SECTIONS,
    TRUSTED_VISUAL_SOURCE_INSTRUCTION,
    UNTRUSTED_VISUAL_OBSERVATION_LABEL,
    ExternalProjection,
    ProjectionBudget,
)
from myuna_core.external_context.safety import enforce_external_egress_safety
from myuna_core.owner_profile.contracts import RetrievalResult
from myuna_core.owner_profile.retrieval import render_profile_context

from .contracts import (
    CONTEXT_POLICY_DYNAMIC_PREFIX,
    CONTEXT_POLICY_RAW_FIRST,
    EGRESS_POLICY_HISTORICAL_RAW_RECALL_V1,
    HISTORICAL_RAW_RECALL_EGRESS_V1_DIGEST,
    CompleteTurn,
    EpisodicMemoryError,
    PrefixCapsule,
    PrefixCompactionPolicy,
    TurnTimeBinding,
    canonical_bytes,
    require_digest,
    require_id,
    semantic_digest,
)
from .context import (
    ContextLimits,
    ContextOccupancy,
    count_offline_token_units,
    plan_dynamic_prefix,
)
from .trusted_time import render_trusted_current_time


RUNTIME_CONTEXT_SCHEMA = "myuna.p07-owner-private-episodic-runtime-context.v3"
TURN_PROVENANCE_SCHEMA = "myuna.p07-owner-private-episodic-turn-provenance.v3"
TEMPORARY_PROMPT_OWNER = "p07-owner-private-episodic-runtime-v1"
P15_HANDOFF_SCHEMA = "myuna.p07-p15-prompt-ownership-handoff.v1"
MAX_TEMPORAL_CONTEXT_CHARACTERS = 12_000
MAX_CANDIDATE_TURNS = 4_096


def _ranges(sequences: Sequence[int]) -> tuple[tuple[int, int], ...]:
    result: list[tuple[int, int]] = []
    for sequence in sorted(sequences):
        if result and sequence == result[-1][1] + 1:
            result[-1] = (result[-1][0], sequence)
        else:
            result.append((sequence, sequence))
    return tuple(result)


@dataclass(frozen=True, slots=True)
class EpisodicRuntimeContext:
    parent_release_set_id: str
    policy_overlay_id: str
    parent_epoch_id: str
    parent_epoch_revision: int
    archive_id: str
    archive_turn_count: int
    archive_head_digest: str
    candidate_turns: tuple[CompleteTurn, ...]
    required_sequences: tuple[int, ...]
    all_raw_candidate: bool
    coverage_state: str
    current_message: str
    current_message_digest: str
    trusted_time_binding: TurnTimeBinding
    temporal_context: str
    temporal_item_count: int
    temporal_projection_digest: str
    temporal_coverage_state: str
    temporal_state: str
    temporal_reason_category: str | None
    temporal_source_closure_digest: str
    temporal_selection_digest: str
    egress_policy_mode: str
    egress_policy_digest: str
    safety: EgressSafetySignals
    profile_v2_context: str = ""
    profile_v2_item_count: int = 0
    profile_v2_projection_digest: str = "0" * 64
    profile_v2_state: str = "available_empty"
    recall_state: str = "available"
    recall_reason_category: str | None = None
    recall_source_closure_digest: str = "0" * 64
    recall_selection_digest: str = "0" * 64
    visual_evidence: VisualEvidence | None = None
    context_policy_version: str = CONTEXT_POLICY_RAW_FIRST
    prompt_owner: str = TEMPORARY_PROMPT_OWNER
    p15_projection_active: bool = False
    p15_handoff_schema: str = P15_HANDOFF_SCHEMA
    summary_used: bool = False
    old_history_migrated: bool = False
    schema: str = RUNTIME_CONTEXT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != RUNTIME_CONTEXT_SCHEMA:
            raise EpisodicMemoryError("runtime_context_schema_unknown")
        require_digest(self.parent_release_set_id, "runtime_parent_release_set")
        require_digest(self.policy_overlay_id, "runtime_policy_overlay")
        require_id(self.parent_epoch_id, "runtime_parent_epoch")
        if (
            isinstance(self.parent_epoch_revision, bool)
            or not isinstance(self.parent_epoch_revision, int)
            or self.parent_epoch_revision < 0
        ):
            raise EpisodicMemoryError("runtime_parent_revision_invalid")
        require_id(self.archive_id, "runtime_archive_id")
        require_digest(self.archive_head_digest, "runtime_archive_head")
        require_digest(self.recall_source_closure_digest, "runtime_recall_source_closure")
        require_digest(self.recall_selection_digest, "runtime_recall_selection")
        if self.recall_state not in {
            "available",
            "available_empty",
            "unavailable",
            "conflict",
        }:
            raise EpisodicMemoryError("runtime_recall_state_unknown")
        if self.recall_state in {"available", "available_empty"}:
            if self.recall_reason_category is not None:
                raise EpisodicMemoryError("runtime_recall_reason_rejected")
        elif self.recall_reason_category is None:
            raise EpisodicMemoryError("runtime_recall_reason_missing")
        else:
            require_id(self.recall_reason_category, "runtime_recall_reason")
        if (
            isinstance(self.archive_turn_count, bool)
            or not isinstance(self.archive_turn_count, int)
            or self.archive_turn_count < 0
            or len(self.candidate_turns) > MAX_CANDIDATE_TURNS
        ):
            raise EpisodicMemoryError("runtime_archive_count_invalid")
        if self.context_policy_version != CONTEXT_POLICY_RAW_FIRST:
            raise EpisodicMemoryError("runtime_context_policy_rejected")
        if self.egress_policy_mode != EGRESS_POLICY_HISTORICAL_RAW_RECALL_V1:
            raise EpisodicMemoryError("historical_raw_egress_not_authorized")
        require_digest(self.egress_policy_digest, "runtime_egress_policy")
        if self.egress_policy_digest != HISTORICAL_RAW_RECALL_EGRESS_V1_DIGEST:
            raise EpisodicMemoryError("runtime_egress_policy_drifted")
        if self.prompt_owner != TEMPORARY_PROMPT_OWNER or self.p15_projection_active:
            raise EpisodicMemoryError("runtime_prompt_owner_conflict")
        if self.p15_handoff_schema != P15_HANDOFF_SCHEMA:
            raise EpisodicMemoryError("runtime_p15_handoff_unknown")
        if self.summary_used or self.old_history_migrated:
            raise EpisodicMemoryError("runtime_forbidden_history_source")
        if self.coverage_state not in {"complete", "coverage_incomplete"}:
            raise EpisodicMemoryError("runtime_coverage_state_unknown")
        if self.recall_state in {"unavailable", "conflict"} and (
            self.candidate_turns or self.required_sequences or self.all_raw_candidate
        ):
            raise EpisodicMemoryError("runtime_recall_failure_contains_raw")
        if self.recall_state == "available_empty" and self.required_sequences:
            raise EpisodicMemoryError("runtime_recall_empty_contains_selection")
        if not self.current_message or self.current_message != self.current_message.strip():
            raise EpisodicMemoryError("runtime_current_message_invalid")
        require_digest(self.current_message_digest, "runtime_current_message")
        if len(self.temporal_context) > MAX_TEMPORAL_CONTEXT_CHARACTERS:
            raise EpisodicMemoryError("temporal_active_layer_overflow")
        if (
            isinstance(self.temporal_item_count, bool)
            or not isinstance(self.temporal_item_count, int)
            or self.temporal_item_count < 0
        ):
            raise EpisodicMemoryError("runtime_temporal_count_invalid")
        require_digest(self.temporal_projection_digest, "runtime_temporal_projection")
        require_digest(
            self.temporal_source_closure_digest,
            "runtime_temporal_source_closure",
        )
        require_digest(self.temporal_selection_digest, "runtime_temporal_selection")
        if self.temporal_state not in {
            "available",
            "available_empty",
            "unavailable",
            "conflict",
        }:
            raise EpisodicMemoryError("runtime_temporal_state_unknown")
        if self.temporal_state in {"available", "available_empty"}:
            if self.temporal_reason_category is not None:
                raise EpisodicMemoryError("runtime_temporal_reason_rejected")
        elif self.temporal_reason_category is None:
            raise EpisodicMemoryError("runtime_temporal_reason_missing")
        else:
            require_id(self.temporal_reason_category, "runtime_temporal_reason")
        if self.temporal_coverage_state not in {"complete", "unavailable"}:
            raise EpisodicMemoryError("runtime_temporal_coverage_unknown")
        expected_coverage = (
            "complete"
            if self.temporal_state in {"available", "available_empty"}
            else "unavailable"
        )
        if self.temporal_coverage_state != expected_coverage:
            raise EpisodicMemoryError("runtime_temporal_state_coverage_conflict")
        if self.temporal_state == "available" and (
            self.temporal_item_count < 1 or not self.temporal_context
        ):
            raise EpisodicMemoryError("runtime_temporal_available_empty")
        if self.temporal_state != "available" and self.temporal_item_count != 0:
            raise EpisodicMemoryError("runtime_temporal_nonavailable_contains_items")
        if self.temporal_state != "available" and (
            self.temporal_item_count != 0
            or f"state={self.temporal_state}" not in self.temporal_context
        ):
            raise EpisodicMemoryError("runtime_temporal_coverage_invalid")
        if not isinstance(self.safety, EgressSafetySignals):
            raise EpisodicMemoryError("runtime_safety_invalid")
        if (
            type(self.profile_v2_context) is not str
            or type(self.profile_v2_item_count) is not int
            or self.profile_v2_item_count < 0
            or self.profile_v2_state
            not in {
                "available",
                "available_empty",
                "uninitialized",
                "unavailable",
                "conflict",
            }
        ):
            raise EpisodicMemoryError("runtime_profile_v2_projection_rejected")
        require_digest(
            self.profile_v2_projection_digest, "runtime_profile_v2_projection"
        )
        if self.profile_v2_state == "available":
            if not self.profile_v2_context or self.profile_v2_item_count < 1:
                raise EpisodicMemoryError("runtime_profile_v2_projection_rejected")
        elif self.profile_v2_context or self.profile_v2_item_count != 0:
            raise EpisodicMemoryError("runtime_profile_v2_projection_rejected")
        sequences = tuple(turn.draft.sequence for turn in self.candidate_turns)
        if sequences != tuple(sorted(set(sequences))):
            raise EpisodicMemoryError("runtime_candidate_order_invalid")
        if any(sequence < 1 or sequence > self.archive_turn_count for sequence in sequences):
            raise EpisodicMemoryError("runtime_candidate_sequence_invalid")
        required = tuple(sorted(set(self.required_sequences)))
        if required != self.required_sequences or not set(required) <= set(sequences):
            raise EpisodicMemoryError("runtime_required_sequence_missing")
        prior: CompleteTurn | None = None
        for turn in self.candidate_turns:
            if prior is not None and turn.draft.sequence == prior.draft.sequence + 1:
                if turn.draft.previous_turn_digest != prior.turn_digest:
                    raise EpisodicMemoryError("runtime_candidate_chain_drifted")
            prior = turn
        if self.all_raw_candidate:
            if sequences != tuple(range(1, self.archive_turn_count + 1)):
                raise EpisodicMemoryError("runtime_all_raw_candidate_incomplete")
            previous = "0" * 64
            for turn in self.candidate_turns:
                if turn.draft.previous_turn_digest != previous:
                    raise EpisodicMemoryError("runtime_archive_chain_drifted")
                previous = turn.turn_digest
            if previous != self.archive_head_digest:
                raise EpisodicMemoryError("runtime_archive_head_drifted")
        elif (
            self.candidate_turns
            and self.candidate_turns[-1].draft.sequence == self.archive_turn_count
        ):
            if self.candidate_turns[-1].turn_digest != self.archive_head_digest:
                raise EpisodicMemoryError("runtime_archive_head_drifted")

    def semantic_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "all_raw_candidate": self.all_raw_candidate,
            "archive_head_digest": self.archive_head_digest,
            "archive_id": self.archive_id,
            "archive_turn_count": self.archive_turn_count,
            "candidate_turns": [turn.payload() for turn in self.candidate_turns],
            "context_policy_version": self.context_policy_version,
            "coverage_state": self.coverage_state,
            "current_message": self.current_message,
            "current_message_digest": self.current_message_digest,
            "egress_policy_digest": self.egress_policy_digest,
            "egress_policy_mode": self.egress_policy_mode,
            "old_history_migrated": self.old_history_migrated,
            "profile_v2_context": self.profile_v2_context,
            "profile_v2_item_count": self.profile_v2_item_count,
            "profile_v2_projection_digest": self.profile_v2_projection_digest,
            "profile_v2_state": self.profile_v2_state,
            "p15_handoff_schema": self.p15_handoff_schema,
            "p15_projection_active": self.p15_projection_active,
            "parent_epoch_id": self.parent_epoch_id,
            "parent_epoch_revision": self.parent_epoch_revision,
            "parent_release_set_id": self.parent_release_set_id,
            "policy_overlay_id": self.policy_overlay_id,
            "prompt_owner": self.prompt_owner,
            "recall_reason_category": self.recall_reason_category,
            "recall_selection_digest": self.recall_selection_digest,
            "recall_source_closure_digest": self.recall_source_closure_digest,
            "recall_state": self.recall_state,
            "required_sequences": list(self.required_sequences),
            "safety": self.safety.as_payload(),
            "schema": self.schema,
            "summary_used": self.summary_used,
            "temporal_context": self.temporal_context,
            "temporal_item_count": self.temporal_item_count,
            "temporal_reason_category": self.temporal_reason_category,
            "temporal_coverage_state": self.temporal_coverage_state,
            "temporal_projection_digest": self.temporal_projection_digest,
            "temporal_selection_digest": self.temporal_selection_digest,
            "temporal_source_closure_digest": self.temporal_source_closure_digest,
            "temporal_state": self.temporal_state,
            "trusted_time_binding": self.trusted_time_binding.payload(),
            "visual_evidence": (
                None if self.visual_evidence is None else self.visual_evidence.as_payload()
            ),
        }
        return payload

    @property
    def context_digest(self) -> str:
        return semantic_digest("myuna-p07-episodic-runtime-context-v3", self.semantic_payload())

    def as_payload(self) -> dict[str, object]:
        return self.semantic_payload() | {"context_digest": self.context_digest}

    @classmethod
    def from_payload(
        cls,
        payload: Mapping[str, object],
        *,
        authenticated_context: AuthenticatedConversationContext,
    ) -> EpisodicRuntimeContext:
        semantic_fields = {
            "all_raw_candidate",
            "archive_head_digest",
            "archive_id",
            "archive_turn_count",
            "candidate_turns",
            "context_policy_version",
            "coverage_state",
            "current_message",
            "current_message_digest",
            "egress_policy_digest",
            "egress_policy_mode",
            "old_history_migrated",
            "profile_v2_context",
            "profile_v2_item_count",
            "profile_v2_projection_digest",
            "profile_v2_state",
            "p15_handoff_schema",
            "p15_projection_active",
            "parent_epoch_id",
            "parent_epoch_revision",
            "parent_release_set_id",
            "policy_overlay_id",
            "prompt_owner",
            "recall_reason_category",
            "recall_selection_digest",
            "recall_source_closure_digest",
            "recall_state",
            "required_sequences",
            "safety",
            "schema",
            "summary_used",
            "temporal_context",
            "temporal_item_count",
            "temporal_reason_category",
            "temporal_coverage_state",
            "temporal_projection_digest",
            "temporal_selection_digest",
            "temporal_source_closure_digest",
            "temporal_state",
            "trusted_time_binding",
            "visual_evidence",
        }
        if (
            set(payload) != semantic_fields | {"context_digest"}
            or not isinstance(payload["candidate_turns"], list)
            or not isinstance(payload["required_sequences"], list)
            or not isinstance(payload["trusted_time_binding"], Mapping)
        ):
            raise EpisodicMemoryError("runtime_context_fields_rejected")
        message = payload["current_message"]
        if not isinstance(message, str) or payload[
            "current_message_digest"
        ] != current_message_digest(authenticated_context, message):
            raise EpisodicMemoryError("runtime_current_message_digest_mismatch")
        visual_payload = payload["visual_evidence"]
        selected = cls(
            parent_release_set_id=payload["parent_release_set_id"],  # type: ignore[arg-type]
            policy_overlay_id=payload["policy_overlay_id"],  # type: ignore[arg-type]
            parent_epoch_id=payload["parent_epoch_id"],  # type: ignore[arg-type]
            parent_epoch_revision=payload["parent_epoch_revision"],  # type: ignore[arg-type]
            archive_id=payload["archive_id"],  # type: ignore[arg-type]
            archive_turn_count=payload["archive_turn_count"],  # type: ignore[arg-type]
            archive_head_digest=payload["archive_head_digest"],  # type: ignore[arg-type]
            recall_state=payload["recall_state"],  # type: ignore[arg-type]
            recall_reason_category=payload[  # type: ignore[arg-type]
                "recall_reason_category"
            ],
            recall_source_closure_digest=payload[  # type: ignore[arg-type]
                "recall_source_closure_digest"
            ],
            recall_selection_digest=payload["recall_selection_digest"],  # type: ignore[arg-type]
            candidate_turns=tuple(  # type: ignore[arg-type]
                CompleteTurn.from_payload(item) for item in payload["candidate_turns"]
            ),
            required_sequences=tuple(payload["required_sequences"]),  # type: ignore[arg-type]
            all_raw_candidate=payload["all_raw_candidate"],  # type: ignore[arg-type]
            coverage_state=payload["coverage_state"],  # type: ignore[arg-type]
            current_message=message,
            current_message_digest=payload[  # type: ignore[arg-type]
                "current_message_digest"
            ],
            trusted_time_binding=TurnTimeBinding.from_payload(
                payload["trusted_time_binding"]
            ),
            temporal_context=payload["temporal_context"],  # type: ignore[arg-type]
            temporal_item_count=payload["temporal_item_count"],  # type: ignore[arg-type]
            temporal_reason_category=payload[  # type: ignore[arg-type]
                "temporal_reason_category"
            ],
            temporal_coverage_state=payload[  # type: ignore[arg-type]
                "temporal_coverage_state"
            ],
            temporal_projection_digest=payload[  # type: ignore[arg-type]
                "temporal_projection_digest"
            ],
            temporal_selection_digest=payload[  # type: ignore[arg-type]
                "temporal_selection_digest"
            ],
            temporal_source_closure_digest=payload[  # type: ignore[arg-type]
                "temporal_source_closure_digest"
            ],
            temporal_state=payload["temporal_state"],  # type: ignore[arg-type]
            egress_policy_mode=payload["egress_policy_mode"],  # type: ignore[arg-type]
            egress_policy_digest=payload["egress_policy_digest"],  # type: ignore[arg-type]
            safety=EgressSafetySignals.from_payload(payload["safety"]),
            visual_evidence=(
                None
                if visual_payload is None
                else VisualEvidence.from_payload(
                    visual_payload,
                    context=authenticated_context,
                    current_message=message,
                )
            ),
            context_policy_version=payload[  # type: ignore[arg-type]
                "context_policy_version"
            ],
            prompt_owner=payload["prompt_owner"],  # type: ignore[arg-type]
            p15_projection_active=payload["p15_projection_active"],  # type: ignore[arg-type]
            p15_handoff_schema=payload["p15_handoff_schema"],  # type: ignore[arg-type]
            summary_used=payload["summary_used"],  # type: ignore[arg-type]
            old_history_migrated=payload["old_history_migrated"],  # type: ignore[arg-type]
            profile_v2_context=payload["profile_v2_context"],  # type: ignore[arg-type]
            profile_v2_item_count=payload["profile_v2_item_count"],  # type: ignore[arg-type]
            profile_v2_projection_digest=payload[  # type: ignore[arg-type]
                "profile_v2_projection_digest"
            ],
            profile_v2_state=payload["profile_v2_state"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )
        require_digest(  # type: ignore[arg-type]
            payload["context_digest"], "runtime_context_digest"
        )
        if selected.context_digest != payload["context_digest"]:
            raise EpisodicMemoryError("runtime_context_digest_mismatch")
        return selected


@dataclass(frozen=True, slots=True)
class EpisodicTurnProvenance:
    parent_release_set_id: str
    policy_overlay_id: str
    parent_epoch_id: str
    parent_epoch_revision: int
    archive_id: str
    archive_head_digest: str
    archive_turn_count: int
    projection_digest: str
    selection_digest: str
    source_ranges: tuple[tuple[int, int], ...]
    profile_revisions: tuple[int, ...]
    trusted_time_binding_digest: str
    temporal_projection_digest: str
    temporal_coverage_state: str
    temporal_state: str
    temporal_reason_category: str | None
    temporal_source_closure_digest: str
    temporal_selection_digest: str
    recall_state: str = "available"
    recall_reason_category: str | None = None
    recall_source_closure_digest: str = "0" * 64
    recall_selection_digest: str = "0" * 64
    prefix_capsule_digest: str | None = None
    prefix_policy_digest: str | None = None
    prefix_source_range: tuple[int, int] | None = None
    prefix_token_oracle_id: str | None = None
    context_policy_version: str = CONTEXT_POLICY_RAW_FIRST
    prompt_owner: str = TEMPORARY_PROMPT_OWNER
    schema: str = TURN_PROVENANCE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != TURN_PROVENANCE_SCHEMA:
            raise EpisodicMemoryError("episodic_provenance_schema_unknown")
        for value, label in (
            (self.parent_release_set_id, "provenance_parent_release"),
            (self.policy_overlay_id, "provenance_policy_overlay"),
            (self.archive_head_digest, "provenance_archive_head"),
            (self.recall_source_closure_digest, "provenance_recall_source_closure"),
            (self.recall_selection_digest, "provenance_recall_selection"),
            (self.projection_digest, "provenance_projection"),
            (self.selection_digest, "provenance_selection"),
            (self.trusted_time_binding_digest, "provenance_trusted_time"),
            (self.temporal_projection_digest, "provenance_temporal"),
            (
                self.temporal_source_closure_digest,
                "provenance_temporal_source_closure",
            ),
            (self.temporal_selection_digest, "provenance_temporal_selection"),
        ):
            require_digest(value, label)
        require_id(self.parent_epoch_id, "provenance_parent_epoch")
        require_id(self.archive_id, "provenance_archive_id")
        if self.recall_state not in {
            "available",
            "available_empty",
            "unavailable",
            "conflict",
        }:
            raise EpisodicMemoryError("provenance_recall_state_unknown")
        if self.recall_state in {"available", "available_empty"}:
            if self.recall_reason_category is not None:
                raise EpisodicMemoryError("provenance_recall_reason_rejected")
        elif self.recall_reason_category is None:
            raise EpisodicMemoryError("provenance_recall_reason_missing")
        else:
            require_id(self.recall_reason_category, "provenance_recall_reason")
        if (
            isinstance(self.parent_epoch_revision, bool)
            or not isinstance(self.parent_epoch_revision, int)
            or self.parent_epoch_revision < 0
            or isinstance(self.archive_turn_count, bool)
            or not isinstance(self.archive_turn_count, int)
            or self.archive_turn_count < 0
        ):
            raise EpisodicMemoryError("episodic_provenance_count_invalid")
        if self.context_policy_version not in {
            CONTEXT_POLICY_RAW_FIRST,
            CONTEXT_POLICY_DYNAMIC_PREFIX,
        }:
            raise EpisodicMemoryError("episodic_provenance_policy_rejected")
        prefix_values = (
            self.prefix_capsule_digest,
            self.prefix_policy_digest,
            self.prefix_source_range,
            self.prefix_token_oracle_id,
        )
        if any(value is not None for value in prefix_values):
            if any(value is None for value in prefix_values):
                raise EpisodicMemoryError("provenance_prefix_binding_incomplete")
            require_digest(
                self.prefix_capsule_digest,  # type: ignore[arg-type]
                "provenance_prefix_capsule",
            )
            require_digest(
                self.prefix_policy_digest,  # type: ignore[arg-type]
                "provenance_prefix_policy",
            )
            require_id(
                self.prefix_token_oracle_id,  # type: ignore[arg-type]
                "provenance_prefix_token_oracle",
            )
            if (
                self.context_policy_version != CONTEXT_POLICY_DYNAMIC_PREFIX
                or not isinstance(self.prefix_source_range, tuple)
                or len(self.prefix_source_range) != 2
                or self.prefix_source_range[0] != 1
                or self.prefix_source_range[1] < 1
                or self.prefix_source_range[1] > self.archive_turn_count
            ):
                raise EpisodicMemoryError("provenance_prefix_range_rejected")
        elif self.context_policy_version == CONTEXT_POLICY_DYNAMIC_PREFIX:
            # Dynamic raw-first may fit all raw without creating a capsule.
            pass
        if self.prompt_owner != TEMPORARY_PROMPT_OWNER:
            raise EpisodicMemoryError("provenance_prompt_owner_rejected")
        if self.temporal_coverage_state not in {"complete", "unavailable"}:
            raise EpisodicMemoryError("provenance_temporal_coverage_unknown")
        if self.temporal_state not in {
            "available",
            "available_empty",
            "unavailable",
            "conflict",
        }:
            raise EpisodicMemoryError("provenance_temporal_state_unknown")
        if self.temporal_state in {"available", "available_empty"}:
            if self.temporal_reason_category is not None:
                raise EpisodicMemoryError("provenance_temporal_reason_rejected")
        elif self.temporal_reason_category is None:
            raise EpisodicMemoryError("provenance_temporal_reason_missing")
        else:
            require_id(self.temporal_reason_category, "provenance_temporal_reason")
        if self.temporal_coverage_state != (
            "complete"
            if self.temporal_state in {"available", "available_empty"}
            else "unavailable"
        ):
            raise EpisodicMemoryError("provenance_temporal_state_coverage_conflict")
        if (
            tuple(sorted(set(self.profile_revisions))) != self.profile_revisions
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 1
                for value in self.profile_revisions
            )
        ):
            raise EpisodicMemoryError("episodic_provenance_profile_revisions_invalid")
        prior_end = 0
        for item in self.source_ranges:
            if (
                not isinstance(item, tuple)
                or len(item) != 2
                or any(isinstance(value, bool) or not isinstance(value, int) for value in item)
                or item[0] < 1
                or item[1] < item[0]
                or item[1] > self.archive_turn_count
                or item[0] <= prior_end
            ):
                raise EpisodicMemoryError("episodic_provenance_ranges_rejected")
            prior_end = item[1]

    def as_payload(self) -> dict[str, object]:
        return {
            "archive_head_digest": self.archive_head_digest,
            "archive_id": self.archive_id,
            "archive_turn_count": self.archive_turn_count,
            "context_policy_version": self.context_policy_version,
            "parent_epoch_id": self.parent_epoch_id,
            "parent_epoch_revision": self.parent_epoch_revision,
            "parent_release_set_id": self.parent_release_set_id,
            "policy_overlay_id": self.policy_overlay_id,
            "profile_revisions": list(self.profile_revisions),
            "prefix_capsule_digest": self.prefix_capsule_digest,
            "prefix_policy_digest": self.prefix_policy_digest,
            "prefix_source_range": (
                None
                if self.prefix_source_range is None
                else list(self.prefix_source_range)
            ),
            "prefix_token_oracle_id": self.prefix_token_oracle_id,
            "projection_digest": self.projection_digest,
            "prompt_owner": self.prompt_owner,
            "recall_reason_category": self.recall_reason_category,
            "recall_selection_digest": self.recall_selection_digest,
            "recall_source_closure_digest": self.recall_source_closure_digest,
            "recall_state": self.recall_state,
            "schema": self.schema,
            "selection_digest": self.selection_digest,
            "source_ranges": [list(item) for item in self.source_ranges],
            "temporal_projection_digest": self.temporal_projection_digest,
            "temporal_reason_category": self.temporal_reason_category,
            "temporal_selection_digest": self.temporal_selection_digest,
            "temporal_source_closure_digest": self.temporal_source_closure_digest,
            "temporal_state": self.temporal_state,
            "temporal_coverage_state": self.temporal_coverage_state,
            "trusted_time_binding_digest": self.trusted_time_binding_digest,
        }

    @classmethod
    def from_payload(cls, payload: object) -> EpisodicTurnProvenance:
        expected = {
            "archive_head_digest",
            "archive_id",
            "archive_turn_count",
            "context_policy_version",
            "parent_epoch_id",
            "parent_epoch_revision",
            "parent_release_set_id",
            "policy_overlay_id",
            "profile_revisions",
            "prefix_capsule_digest",
            "prefix_policy_digest",
            "prefix_source_range",
            "prefix_token_oracle_id",
            "projection_digest",
            "prompt_owner",
            "recall_reason_category",
            "recall_selection_digest",
            "recall_source_closure_digest",
            "recall_state",
            "schema",
            "selection_digest",
            "source_ranges",
            "temporal_projection_digest",
            "temporal_reason_category",
            "temporal_selection_digest",
            "temporal_source_closure_digest",
            "temporal_state",
            "temporal_coverage_state",
            "trusted_time_binding_digest",
        }
        if (
            not isinstance(payload, Mapping)
            or set(payload) != expected
            or not isinstance(payload["profile_revisions"], list)
            or not isinstance(payload["source_ranges"], list)
        ):
            raise EpisodicMemoryError("episodic_provenance_fields_rejected")
        try:
            ranges = tuple((item[0], item[1]) for item in payload["source_ranges"])
            prefix_range = (
                None
                if payload["prefix_source_range"] is None
                else (
                    payload["prefix_source_range"][0],  # type: ignore[index]
                    payload["prefix_source_range"][1],  # type: ignore[index]
                )
            )
        except (IndexError, TypeError):
            raise EpisodicMemoryError("episodic_provenance_ranges_rejected") from None
        return cls(
            parent_release_set_id=payload["parent_release_set_id"],  # type: ignore[arg-type]
            policy_overlay_id=payload["policy_overlay_id"],  # type: ignore[arg-type]
            parent_epoch_id=payload["parent_epoch_id"],  # type: ignore[arg-type]
            parent_epoch_revision=payload["parent_epoch_revision"],  # type: ignore[arg-type]
            archive_id=payload["archive_id"],  # type: ignore[arg-type]
            archive_head_digest=payload["archive_head_digest"],  # type: ignore[arg-type]
            archive_turn_count=payload["archive_turn_count"],  # type: ignore[arg-type]
            recall_state=payload["recall_state"],  # type: ignore[arg-type]
            recall_reason_category=payload[  # type: ignore[arg-type]
                "recall_reason_category"
            ],
            recall_source_closure_digest=payload[  # type: ignore[arg-type]
                "recall_source_closure_digest"
            ],
            recall_selection_digest=payload["recall_selection_digest"],  # type: ignore[arg-type]
            projection_digest=payload["projection_digest"],  # type: ignore[arg-type]
            selection_digest=payload["selection_digest"],  # type: ignore[arg-type]
            source_ranges=ranges,
            profile_revisions=tuple(payload["profile_revisions"]),  # type: ignore[arg-type]
            prefix_capsule_digest=payload["prefix_capsule_digest"],  # type: ignore[arg-type]
            prefix_policy_digest=payload["prefix_policy_digest"],  # type: ignore[arg-type]
            prefix_source_range=prefix_range,  # type: ignore[arg-type]
            prefix_token_oracle_id=payload["prefix_token_oracle_id"],  # type: ignore[arg-type]
            trusted_time_binding_digest=payload[  # type: ignore[arg-type]
                "trusted_time_binding_digest"
            ],
            temporal_projection_digest=payload[  # type: ignore[arg-type]
                "temporal_projection_digest"
            ],
            temporal_reason_category=payload[  # type: ignore[arg-type]
                "temporal_reason_category"
            ],
            temporal_selection_digest=payload[  # type: ignore[arg-type]
                "temporal_selection_digest"
            ],
            temporal_source_closure_digest=payload[  # type: ignore[arg-type]
                "temporal_source_closure_digest"
            ],
            temporal_state=payload["temporal_state"],  # type: ignore[arg-type]
            temporal_coverage_state=payload[  # type: ignore[arg-type]
                "temporal_coverage_state"
            ],
            context_policy_version=payload["context_policy_version"],  # type: ignore[arg-type]
            prompt_owner=payload["prompt_owner"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )


class EpisodicProjectionBuilder:
    def __init__(
        self,
        budget: ProjectionBudget,
        *,
        token_counter: Callable[[tuple[Mapping[str, str], ...]], int] | None,
        context_limits: ContextLimits | None = None,
    ) -> None:
        self.budget = budget
        self.token_counter = token_counter
        self.context_limits = context_limits or ContextLimits(
            request_characters=budget.max_total_characters,
            projection_characters=budget.max_total_characters,
            serialized_bytes=budget.max_serialized_bytes,
            input_tokens=budget.max_input_tokens,
            output_reserve_characters=0,
            output_reserve_bytes=0,
            output_reserve_tokens=0,
        )
        if (
            self.context_limits.projection_characters
            > self.context_limits.request_characters
            or self.context_limits.projection_characters > budget.max_total_characters
            or self.context_limits.serialized_bytes > budget.max_serialized_bytes
            or self.context_limits.input_tokens > budget.max_input_tokens
        ):
            raise EpisodicMemoryError("context_oracle_contract_drifted")

    def _evaluate(
        self,
        *,
        system_content: str,
        turns: Sequence[CompleteTurn],
        context: EpisodicRuntimeContext,
        capsule: PrefixCapsule | None = None,
        prefix_policy: PrefixCompactionPolicy | None = None,
    ) -> tuple[tuple[Mapping[str, str], ...], ContextOccupancy]:
        messages: list[Mapping[str, str]] = [{"role": "system", "content": system_content}]
        capsule_characters = 0
        if capsule is not None:
            capsule_content = canonical_bytes(
                {
                    "capsule_digest": capsule.capsule_digest,
                    "capsule_text": capsule.capsule_text,
                    "instruction_trust": "untrusted_derivative_data",
                    "schema": "myuna.p07-prefix-capsule-prompt-envelope.v1",
                    "source_end": capsule.source_end,
                    "source_start": capsule.source_start,
                }
            ).decode("utf-8")
            capsule_characters = len(capsule_content)
            messages.append({"role": "assistant", "content": capsule_content})
        for turn in turns:
            messages.extend(
                (
                    {"role": "user", "content": turn.draft.owner.text},
                    {"role": "assistant", "content": turn.draft.assistant.text},
                )
            )
        if context.visual_evidence is not None:
            messages.append(
                {
                    "role": "assistant",
                    "content": UNTRUSTED_VISUAL_OBSERVATION_LABEL
                    + context.visual_evidence.observation,
                }
            )
        messages.append({"role": "user", "content": context.current_message})
        frozen = tuple(messages)
        fixed_characters = len(system_content) + capsule_characters
        raw_characters = sum(
            len(turn.draft.owner.text) + len(turn.draft.assistant.text)
            for turn in turns
        )
        if context.visual_evidence is not None:
            fixed_characters += len(UNTRUSTED_VISUAL_OBSERVATION_LABEL) + len(
                context.visual_evidence.observation
            )
        projection_characters = (
            fixed_characters + raw_characters + len(context.current_message)
        )
        request_characters = (
            projection_characters + self.context_limits.output_reserve_characters
            + (0 if prefix_policy is None else prefix_policy.repair_reserve_characters)
        )
        serialized = len(
            json.dumps(
                [dict(item) for item in frozen],
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ) + self.context_limits.output_reserve_bytes + (
            0 if prefix_policy is None else prefix_policy.repair_reserve_bytes
        )
        tokens = (
            count_offline_token_units(self.token_counter, frozen)
            + self.context_limits.output_reserve_tokens
            + (0 if prefix_policy is None else prefix_policy.repair_reserve_tokens)
        )
        headrooms = {
            "request_characters": (
                self.context_limits.request_characters - request_characters
            ),
            "projection_characters": (
                self.context_limits.projection_characters - projection_characters
            ),
            "serialized_bytes": self.context_limits.serialized_bytes - serialized,
            "input_tokens": self.context_limits.input_tokens - tokens,
        }
        limiting = min(headrooms, key=headrooms.__getitem__)
        fit = all(value >= 0 for value in headrooms.values())
        occupancy = ContextOccupancy(
            policy_version=context.context_policy_version,
            total_complete_turns=context.archive_turn_count,
            projected_complete_turns=len(turns),
            raw_history_characters=raw_characters,
            fixed_context_characters=fixed_characters,
            current_turn_characters=len(context.current_message),
            projection_characters=projection_characters,
            request_characters=request_characters,
            serialized_bytes=serialized,
            input_tokens=tokens,
            request_headroom=headrooms["request_characters"],
            projection_headroom=headrooms["projection_characters"],
            serialized_headroom=headrooms["serialized_bytes"],
            token_headroom=headrooms["input_tokens"],
            limiting_oracle=None if fit else limiting,
            fit=fit,
            capsule_used_count=0 if capsule is None else 1,
        )
        return frozen, occupancy

    def build(
        self,
        *,
        definition: str,
        definition_digest: str,
        context: EpisodicRuntimeContext,
        profile: RetrievalResult | None,
        prefix_policy: PrefixCompactionPolicy | None = None,
        prefix_capsules: Sequence[PrefixCapsule] = (),
        prefix_risk_class: str | None = None,
        source_sensitive_claim: bool | None = None,
        prefix_envelope_evaluate: (
            Callable[[int, tuple[CompleteTurn, ...]], ContextOccupancy] | None
        ) = None,
        prefix_generator_version: str | None = None,
        prefix_model_provider_class: str | None = None,
        prefix_created_at_utc: datetime | None = None,
    ) -> tuple[ExternalProjection, EpisodicTurnProvenance]:
        if sha256(definition.encode("utf-8")).hexdigest() != definition_digest:
            raise EpisodicMemoryError("definition_digest_mismatch")
        enforce_external_egress_safety(context.current_message, context.safety)
        if prefix_risk_class is None:
            prefix_risk_class = "continuity_orientation"
        if source_sensitive_claim is None:
            source_sensitive_claim = False
        if context.visual_evidence is not None:
            enforce_external_egress_safety(context.visual_evidence.observation, context.safety)
        profile_context = None
        profile_revision = None
        profile_digest_value = None
        profile_count = 0
        if profile is not None:
            if (
                profile.state not in {"empty", "selected"}
                or len(profile.sections) > MAX_PROFILE_SECTIONS
            ):
                raise EpisodicMemoryError("profile_state_out_of_contract")
            if profile.sections:
                profile_context = render_profile_context(list(profile.sections))
                if len(profile_context) > MAX_PROFILE_CONTEXT_CHARACTERS:
                    raise EpisodicMemoryError("profile_context_characters_exceeded")
                profile_revision = profile.profile_revision
                profile_digest_value = profile.profile_sha256
                profile_count = len(profile.sections)
        trusted_parts = ["[approved_definition]\n" + definition]
        if context.visual_evidence is not None:
            trusted_parts.append(TRUSTED_VISUAL_SOURCE_INSTRUCTION)
        trusted_parts.append(render_trusted_current_time(context.trusted_time_binding))
        if context.temporal_context:
            trusted_parts.append(context.temporal_context)
        if context.profile_v2_state == "available":
            trusted_parts.append(
                "[owner_profile_v2_current]\n" + context.profile_v2_context
            )
        if profile_context is not None:
            trusted_parts.append("[owner_profile_selected]\n" + profile_context)
        trusted_parts.append(
            "[memory_authority raw_archive=true cumulative_summary=false "
            f"prompt_owner={context.prompt_owner}]"
        )
        system_content = "\n\n".join(trusted_parts)
        candidates = tuple(
            turn for turn in context.candidate_turns if turn.model_history_eligible
        )

        def evaluate(
            capsule: PrefixCapsule | None = None,
            turns: Sequence[CompleteTurn] = (),
        ):
            frozen, occupancy = self._evaluate(
                system_content=system_content,
                turns=turns,
                context=context,
                capsule=capsule,
                prefix_policy=prefix_policy,
            )
            return frozen, occupancy

        selected_capsule: PrefixCapsule | None = None
        selected = tuple(candidates)
        if prefix_policy is not None:
            if not context.all_raw_candidate or context.coverage_state != "complete":
                raise EpisodicMemoryError("historical_raw_coverage_incomplete")

            def evaluate_envelope(
                prefix_end: int,
                turns: tuple[CompleteTurn, ...],
            ) -> ContextOccupancy:
                if prefix_envelope_evaluate is None:
                    raise EpisodicMemoryError(
                        "prefix_capsule_envelope_unavailable"
                    )
                return prefix_envelope_evaluate(prefix_end, turns)

            plan = plan_dynamic_prefix(
                archive_turns=context.candidate_turns,
                turns=selected,
                required_sequences=context.required_sequences,
                archive_id=context.archive_id,
                archive_head_digest=context.archive_head_digest,
                policy=prefix_policy,
                capsules=tuple(prefix_capsules),
                risk_class=prefix_risk_class,
                source_sensitive_claim=source_sensitive_claim,
                token_counter=self.token_counter,
                evaluate=lambda capsule, turns: evaluate(capsule, turns)[1],
                evaluate_envelope=evaluate_envelope,
                expected_generator_version=prefix_generator_version or "",
                expected_model_provider_class=prefix_model_provider_class or "",
                expected_created_at_utc=(
                    prefix_created_at_utc
                    if prefix_created_at_utc is not None
                    else datetime.min.replace(tzinfo=context.trusted_time_binding.delivered_at_utc.tzinfo)
                ),
            )
            if plan.action == "overflow":
                raise EpisodicMemoryError(
                    f"context_dynamic_prefix_{plan.action}_required"
                )
            if plan.action == "generate_prefix_capsule":
                raise EpisodicMemoryError(
                    "context_dynamic_prefix_generation_required"
                )
            selected = plan.raw_turns
            selected_capsule = plan.capsule
            frozen, occupancy = evaluate(selected_capsule, selected)
        else:
            frozen, occupancy = evaluate(None, selected)
            if not occupancy.fit:
                if context.coverage_state != "complete":
                    raise EpisodicMemoryError("historical_raw_coverage_incomplete")
                by_sequence = {turn.draft.sequence: turn for turn in candidates}
                selected_numbers = set(context.required_sequences)
                selected = tuple(
                    by_sequence[number] for number in sorted(selected_numbers)
                )
                frozen, occupancy = evaluate(None, selected)
                if not occupancy.fit:
                    raise EpisodicMemoryError("context_relevant_raw_budget_limited")
                for turn in reversed(candidates):
                    if turn.draft.sequence in selected_numbers:
                        continue
                    trial_numbers = selected_numbers | {turn.draft.sequence}
                    trial = tuple(
                        by_sequence[number] for number in sorted(trial_numbers)
                    )
                    trial_result = evaluate(None, trial)
                    if trial_result[1].fit:
                        selected_numbers = trial_numbers
                        selected = trial
                        frozen, occupancy = trial_result
                    else:
                        break
        if not occupancy.fit:
            raise EpisodicMemoryError("context_capacity_exceeded")
        selected_sequences = tuple(turn.draft.sequence for turn in selected)
        source_ranges = _ranges(selected_sequences)
        selection_digest = semantic_digest(
            "myuna-p07-runtime-selection-v1",
            {
                "archive_head_digest": context.archive_head_digest,
                "prefix_capsule_digest": (
                    None
                    if selected_capsule is None
                    else selected_capsule.capsule_digest
                ),
                "prefix_policy_digest": (
                    None
                    if selected_capsule is None or prefix_policy is None
                    else prefix_policy.policy_digest
                ),
                "source_turn_digests": [turn.turn_digest for turn in selected],
                "source_ranges": [list(item) for item in source_ranges],
            },
        )
        component_order = ["approved_definition", "trusted_current_time"]
        if context.temporal_context:
            component_order.append("active_temporal_validity")
        if context.profile_v2_state == "available":
            component_order.append("owner_profile_v2_current")
        if profile_context is not None:
            component_order.append("owner_profile_selected")
        if selected_capsule is not None:
            component_order.append("source_linked_prefix_capsule")
        if selected:
            component_order.append("historical_owner_private_raw_turn")
        if context.visual_evidence is not None:
            component_order.extend(
                ("trusted_visual_source_instruction", "untrusted_visual_observation")
            )
        component_order.append("owner_current_message")
        projection = ExternalProjection(
            messages=frozen,
            component_order=tuple(component_order),
            character_count=occupancy.projection_characters,
            serialized_bytes=occupancy.serialized_bytes,
            input_tokens=occupancy.input_tokens,
            definition_digest=definition_digest,
            profile_revision=profile_revision,
            profile_digest=profile_digest_value,
            profile_section_count=profile_count,
            summary_version=None,
            recent_turn_count=0,
            recent_turn_start=None,
            recent_turn_end=None,
            projection_policy_version=(
                CONTEXT_POLICY_DYNAMIC_PREFIX
                if prefix_policy is not None
                else context.context_policy_version
            ),
            epoch_id=context.parent_epoch_id,
            epoch_revision=context.parent_epoch_revision,
            visual_evidence_present=context.visual_evidence is not None,
            archive_head_digest=context.archive_head_digest,
            archive_turn_count=context.archive_turn_count,
            episodic_selected_count=len(selected),
            episodic_source_ranges=source_ranges,
            episodic_selection_digest=selection_digest,
            trusted_time_binding_digest=context.trusted_time_binding.binding_digest,
            temporal_projection_digest=context.temporal_projection_digest,
            temporal_coverage_state=context.temporal_coverage_state,
            prompt_owner=context.prompt_owner,
            coverage_state=context.coverage_state,
            request_character_count=occupancy.request_characters,
            request_character_limit=self.context_limits.request_characters,
            projection_character_limit=self.context_limits.projection_characters,
            request_character_headroom=occupancy.request_headroom,
            projection_character_headroom=occupancy.projection_headroom,
            serialized_byte_headroom=occupancy.serialized_headroom,
            input_token_headroom=occupancy.token_headroom,
            limiting_oracle=occupancy.limiting_oracle,
            prefix_capsule_digest=(
                None
                if selected_capsule is None
                else selected_capsule.capsule_digest
            ),
            prefix_policy_digest=(
                None
                if selected_capsule is None or prefix_policy is None
                else prefix_policy.policy_digest
            ),
            prefix_source_range=(
                None
                if selected_capsule is None
                else (
                    selected_capsule.source_start,
                    selected_capsule.source_end,
                )
            ),
            prefix_token_oracle_id=(
                None
                if selected_capsule is None
                else selected_capsule.token_oracle_id
            ),
            prefix_repair_reserve_characters=(
                None
                if prefix_policy is None
                else prefix_policy.repair_reserve_characters
            ),
            prefix_repair_reserve_bytes=(
                None
                if prefix_policy is None
                else prefix_policy.repair_reserve_bytes
            ),
            prefix_repair_reserve_tokens=(
                None
                if prefix_policy is None
                else prefix_policy.repair_reserve_tokens
            ),
        )
        provenance = EpisodicTurnProvenance(
            parent_release_set_id=context.parent_release_set_id,
            policy_overlay_id=context.policy_overlay_id,
            parent_epoch_id=context.parent_epoch_id,
            parent_epoch_revision=context.parent_epoch_revision,
            archive_id=context.archive_id,
            archive_head_digest=context.archive_head_digest,
            archive_turn_count=context.archive_turn_count,
            recall_state=context.recall_state,
            recall_reason_category=context.recall_reason_category,
            recall_source_closure_digest=context.recall_source_closure_digest,
            recall_selection_digest=context.recall_selection_digest,
            projection_digest=projection_digest(frozen),
            selection_digest=selection_digest,
            source_ranges=source_ranges,
            profile_revisions=(() if profile_revision is None else (profile_revision,)),
            trusted_time_binding_digest=context.trusted_time_binding.binding_digest,
            temporal_projection_digest=context.temporal_projection_digest,
            temporal_coverage_state=context.temporal_coverage_state,
            temporal_state=context.temporal_state,
            temporal_reason_category=context.temporal_reason_category,
            temporal_source_closure_digest=context.temporal_source_closure_digest,
            temporal_selection_digest=context.temporal_selection_digest,
            prefix_capsule_digest=(
                None
                if selected_capsule is None
                else selected_capsule.capsule_digest
            ),
            prefix_policy_digest=(
                None
                if selected_capsule is None or prefix_policy is None
                else prefix_policy.policy_digest
            ),
            prefix_source_range=(
                None
                if selected_capsule is None
                else (
                    selected_capsule.source_start,
                    selected_capsule.source_end,
                )
            ),
            prefix_token_oracle_id=(
                None
                if selected_capsule is None
                else selected_capsule.token_oracle_id
            ),
            context_policy_version=(
                CONTEXT_POLICY_DYNAMIC_PREFIX
                if prefix_policy is not None
                else context.context_policy_version
            ),
        )
        return projection, provenance
