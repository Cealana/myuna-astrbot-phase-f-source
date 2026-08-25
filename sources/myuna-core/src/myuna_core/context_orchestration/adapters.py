from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Mapping

from myuna_core.active_temporal_context.contracts import (
    SCHEMA_LABEL as TEMPORAL_SCHEMA,
    TemporalRetrievalResult,
)
from myuna_core.affinity import (
    CAPABILITY_ID as AFFINITY_CAPABILITY_ID,
    SCHEMA_LABEL as AFFINITY_SCHEMA,
    AffinityCapabilityContract,
    P15AffinityRelevancePort,
)
from myuna_core.authenticated_conversation import AuthenticatedConversationContext
from myuna_core.definition import DefinitionRelease
from myuna_core.external_context.contracts import ExternalContextEnvelope, VisualEvidence
from myuna_core.external_context.release_set import (
    P07DReleaseSet,
    RELEASE_SET_EPOCH_ID_12,
    RELEASE_SET_EPOCH_SCHEMA,
    RELEASE_SET_EPOCH_VERSION,
    RELEASE_SET_GENERATION_12,
    RELEASE_SET_SCHEMA,
)
from myuna_core.owner_profile.contracts import RetrievalResult as ProfileRetrievalResult
from myuna_core.trusted_time.contracts import TrustedTimeWatermark, UtcObservation

from .contracts import (
    AffinityStateLane,
    ContextCandidate,
    CurrentMessageLane,
    DefinitionLane,
    ExternalContextLanes,
    P15ContractError,
    ProfileLane,
    RecentTurnLane,
    SourceProvenance,
    SummaryLane,
    TemporalLane,
    TrustedTimeState,
    VisualObservationLane,
)


GENERATION12_CORE_COMMIT = "8529ef1f5f24ded15824bdbf0c6f826b0539b8d4"
GENERATION12_DEPLOY_COMMIT = "2819d5cf8fd979ffa1c0bf26b0eaa7411663557b"
COMBINED_RELEASE_SET_SCHEMA = "myuna.p08-p07-combined-release-set.v1"

P09_SOURCE_MAIN_COMMIT = "31250bbd015c07ddefaca889d8c56ddf28971a12"
P09_SOURCE_MAIN_TREE = "e23d1259c233a6ab88cfd9b6c30c7463cf383e03"
P09_SCHEMA = AFFINITY_SCHEMA
P09_CAPABILITY_ID = AFFINITY_CAPABILITY_ID
P09_CAPABILITY_DIGEST = "bc28be2f125bb7099859dd366d54d59f48053db670ad2d841482c15fa50d5096"
P09_P15_INTERFACE = "myuna.affinity-relevance-port.v1"
P09_P15_PORT = P15AffinityRelevancePort


def _provenance(
    *, schema: str, version: int, revision: int, source_ref: str
) -> SourceProvenance:
    return SourceProvenance(True, True, schema, version, revision, source_ref)


@dataclass(frozen=True, slots=True)
class Generation12Binding:
    core_commit: str
    deploy_commit: str
    release_set_schema: str
    combined_schema: str
    generation: int
    epoch_schema: str
    epoch_version: int
    epoch_id: str

    @classmethod
    def validate(
        cls,
        release_set: P07DReleaseSet,
        combined_payload: Mapping[str, object],
        *,
        core_commit: str,
        deploy_commit: str,
    ) -> Generation12Binding:
        if not isinstance(release_set, P07DReleaseSet):
            raise P15ContractError("generation12_release_set_type_mismatch")
        if core_commit != GENERATION12_CORE_COMMIT or deploy_commit != GENERATION12_DEPLOY_COMMIT:
            raise P15ContractError("generation12_source_identity_mismatch")
        if release_set.schema != RELEASE_SET_SCHEMA or release_set.generation != 12:
            raise P15ContractError("generation12_release_set_identity_mismatch")
        epoch = release_set.epoch
        if (
            epoch.get("schema") != RELEASE_SET_EPOCH_SCHEMA
            or epoch.get("schema_version") != RELEASE_SET_EPOCH_VERSION
            or epoch.get("epoch_id") != RELEASE_SET_EPOCH_ID_12
        ):
            raise P15ContractError("generation12_epoch_identity_mismatch")
        if set(combined_payload) != {
            "p07",
            "p08",
            "release_set_id",
            "rollback",
            "schema",
            "telegram_plugin",
        } or combined_payload.get("schema") != COMBINED_RELEASE_SET_SCHEMA:
            raise P15ContractError("generation12_combined_schema_unknown")
        p07 = combined_payload.get("p07")
        if not isinstance(p07, Mapping):
            raise P15ContractError("generation12_combined_p07_missing")
        if set(p07) != {
            "core_release_digest",
            "credential_projection_digest",
            "epoch_id",
            "epoch_path",
            "generation",
            "release_set_id",
            "runtime_config_digest",
            "runtime_release_digest",
            "selector_digest",
        }:
            raise P15ContractError("generation12_combined_p07_fields_mismatch")
        if (
            p07.get("generation") != 12
            or p07.get("epoch_id") != RELEASE_SET_EPOCH_ID_12
            or p07.get("release_set_id") != release_set.release_set_id
        ):
            raise P15ContractError("generation12_combined_p07_identity_mismatch")
        return cls(
            core_commit,
            deploy_commit,
            release_set.schema,
            COMBINED_RELEASE_SET_SCHEMA,
            RELEASE_SET_GENERATION_12,
            RELEASE_SET_EPOCH_SCHEMA,
            RELEASE_SET_EPOCH_VERSION,
            RELEASE_SET_EPOCH_ID_12,
        )


@dataclass(frozen=True, slots=True)
class AffinityCapabilityBinding:
    source_main_commit: str
    source_main_tree: str
    schema: str
    capability_id: str
    capability_digest: str
    prompt_projection_active: bool

    @classmethod
    def validate(
        cls,
        contract: AffinityCapabilityContract,
        *,
        source_main_commit: str,
        source_main_tree: str,
    ) -> AffinityCapabilityBinding:
        if (
            source_main_commit != P09_SOURCE_MAIN_COMMIT
            or source_main_tree != P09_SOURCE_MAIN_TREE
        ):
            raise P15ContractError("p09_source_main_identity_mismatch")
        if not isinstance(contract, AffinityCapabilityContract):
            raise P15ContractError("p09_capability_type_mismatch")
        if contract.digest != P09_CAPABILITY_DIGEST:
            raise P15ContractError("p09_capability_digest_mismatch")
        if contract.schema != P09_SCHEMA or contract.capability_id != P09_CAPABILITY_ID:
            raise P15ContractError("p09_capability_identity_mismatch")
        p15 = [
            item
            for item in contract.dependencies
            if item.dependency == "p15_relevance"
        ]
        if (
            len(p15) != 1
            or p15[0].interface_schema != P09_P15_INTERFACE
            or p15[0].status != "dependency_checkpoint"
            or p15[0].reads_content
            or p15[0].writes_state
        ):
            raise P15ContractError("p09_p15_interface_mismatch")
        if any(
            (
                contract.active,
                contract.bootstrap_active,
                contract.persistence_active,
                contract.writer_active,
                contract.retrieval_active,
                contract.prompt_projection_active,
                contract.legacy_trust_migration_active,
            )
        ):
            raise P15ContractError("p09_foundation_unexpectedly_active")
        if contract.synthetic_machine_only is not True:
            raise P15ContractError("p09_foundation_scope_mismatch")
        return cls(
            source_main_commit,
            source_main_tree,
            P09_SCHEMA,
            P09_CAPABILITY_ID,
            contract.digest,
            False,
        )


def adapt_definition(
    release: DefinitionRelease,
    content: str,
    *,
    relevance: int = 100,
) -> DefinitionLane:
    candidate = ContextCandidate(
        "definition",
        "definition",
        _provenance(
            schema="myuna.definition-release.v1",
            version=1,
            revision=1,
            source_ref=release.release_id,
        ),
        (content,),
        relevance,
        0,
        True,
        "policy",
    )
    return DefinitionLane(candidate, verified_release=release.verified_files > 0)


def adapt_current_message(
    context: AuthenticatedConversationContext,
    content: str,
    *,
    requires_trusted_time: bool = False,
    continuity_required: bool = False,
) -> CurrentMessageLane:
    candidate = ContextCandidate(
        "current",
        "current_message",
        _provenance(
            schema=context.schema_version,
            version=1,
            revision=0,
            source_ref=context.event_id,
        ),
        (content,),
        100,
        0,
        True,
        "current_intent",
    )
    return CurrentMessageLane(
        candidate,
        authenticated=context.authority_level == "owner",
        requires_trusted_time=requires_trusted_time,
        continuity_required=continuity_required,
    )


def adapt_profile(result: ProfileRetrievalResult) -> tuple[ProfileLane, ...]:
    known = result.state == "available"
    return tuple(
        ProfileLane(
            ContextCandidate(
                f"profile-{section.rank}",
                "profile",
                SourceProvenance(
                    known,
                    True,
                    "owner_profile_baseline.v1",
                    1,
                    result.profile_revision,
                    section.source_ref,
                ),
                (section.body,),
                max(1, 101 - section.rank),
                section.rank,
                False,
                "stable_fact",
            )
        )
        for section in result.sections
    )


def adapt_temporal(result: TemporalRetrievalResult) -> tuple[TemporalLane, ...]:
    known = result.state == "available"
    lanes: list[TemporalLane] = []
    for rank, fact in enumerate(result.facts, start=1):
        state = (
            "active"
            if fact.state == "active"
            else "expired"
            if fact.state == "expired"
            else "stale"
        )
        lanes.append(
            TemporalLane(
                ContextCandidate(
                    f"temporal-{fact.fact_id}",
                    "temporal",
                    SourceProvenance(
                        known,
                        True,
                        TEMPORAL_SCHEMA,
                        1,
                        fact.revision,
                        fact.source_ref,
                    ),
                    (fact.summary,),
                    max(1, 101 - rank),
                    rank,
                    False,
                    "current_time_bounded_fact",
                    state=state,
                    conflict_key=fact.slot_key,
                ),
                fact.expires_at,
            )
        )
    return tuple(lanes)


def adapt_trusted_time(
    observation: UtcObservation | None,
    watermark: TrustedTimeWatermark | None,
) -> TrustedTimeState:
    if (
        observation is None
        or watermark is None
        or not observation.evidence.synchronized
        or observation.instant < watermark.instant
    ):
        return TrustedTimeState("unavailable", None)
    return TrustedTimeState(
        "available",
        observation.instant,
        source=watermark.source,
        sequence=watermark.sequence,
    )


def adapt_external_context(
    envelope: ExternalContextEnvelope,
    binding: Generation12Binding,
    *,
    continuity_reset: bool = False,
) -> ExternalContextLanes:
    if binding.generation != 12 or binding.epoch_id != RELEASE_SET_EPOCH_ID_12:
        raise P15ContractError("generation12_binding_required")
    summary = None
    if envelope.summary is not None:
        source = envelope.summary
        summary = SummaryLane(
            ContextCandidate(
                "external-summary",
                "external_summary",
                _provenance(
                    schema="myuna.external-authorized-summary.v1",
                    version=1,
                    revision=source.summary_version,
                    source_ref=envelope.epoch_id,
                ),
                (source.content,),
                50,
                source.covered_end,
                False,
                "continuity",
            ),
            source.covered_start,
            source.covered_end,
            integrity_known=True,
        )
    recent = tuple(
        RecentTurnLane(
            ContextCandidate(
                f"external-turn-{turn.sequence}",
                "external_recent_turn",
                _provenance(
                    schema="myuna.external-authorized-turn.v1",
                    version=1,
                    revision=envelope.epoch_revision,
                    source_ref=f"{envelope.epoch_id}:{turn.sequence}",
                ),
                (turn.user_message, turn.assistant_reply),
                60,
                turn.sequence,
                False,
                "continuity",
            ),
            turn.sequence,
            "delivered",
        )
        for turn in envelope.recent_turns
    )
    return ExternalContextLanes(
        summary,
        recent,
        continuity_reset=continuity_reset,
        reset_reason="authorized_generation_transition" if continuity_reset else "none",
    )


def adapt_visual_observation(
    evidence: VisualEvidence,
    *,
    confidence: float,
    relevance: int,
    essential_for_current: bool,
) -> VisualObservationLane:
    return VisualObservationLane(
        ContextCandidate(
            "visual-observation",
            "visual_observation",
            _provenance(
                schema=evidence.schema,
                version=1,
                revision=0,
                source_ref=evidence.evidence_digest,
            ),
            (evidence.observation,),
            relevance,
            0,
            essential_for_current,
            "visual_evidence",
        ),
        confidence,
    )


def adapt_affinity_projection(
    binding: AffinityCapabilityBinding,
    content_fragments: tuple[str, ...],
    *,
    revision: int,
    source_ref: str,
    relevance: int,
) -> AffinityStateLane:
    if not binding.prompt_projection_active:
        raise P15ContractError("p09_prompt_projection_unavailable")
    return AffinityStateLane(
        ContextCandidate(
            "affinity-state",
            "affinity_state",
            _provenance(
                schema=binding.schema,
                version=1,
                revision=revision,
                source_ref=source_ref,
            ),
            content_fragments,
            relevance,
            0,
            False,
            "style",
        ),
        "ready",
        binding.capability_digest,
    )
