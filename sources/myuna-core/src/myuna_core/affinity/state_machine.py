from __future__ import annotations

from dataclasses import dataclass

from .contracts import (
    AffinityDimensionState,
    AffinityError,
    AffinitySnapshot,
    AffinityTimeSample,
    AffinityUpdate,
)


_CONFIDENCE_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True, slots=True)
class AffinityTransition:
    outcome: str
    changed: bool
    snapshot: AffinitySnapshot
    diagnostic_code: str


class SyntheticAffinityStateMachine:
    """Pure deterministic reducer; deliberately rejects non-synthetic time and sources."""

    def transition(
        self,
        snapshot: AffinitySnapshot,
        update: AffinityUpdate,
        sample: AffinityTimeSample,
    ) -> AffinityTransition:
        if sample.source_class != "synthetic" or update.source_kind != "synthetic_fixture":
            raise AffinityError("affinity_live_transition_forbidden")
        if snapshot.namespace_id != update.namespace_id:
            raise AffinityError("affinity_namespace_mismatch")
        if update.sequence != snapshot.revision + 1:
            raise AffinityError("affinity_sequence_regression")
        if sample.sequence <= snapshot.time_sequence:
            raise AffinityError("trusted_time_sequence_regression")
        if snapshot.observed_at is not None and sample.instant <= snapshot.observed_at:
            raise AffinityError("trusted_time_regression")

        states = {item.dimension: item for item in snapshot.dimensions}
        current = states.get(update.dimension) if update.dimension is not None else None

        if update.action == "abstain":
            return AffinityTransition(
                outcome="abstained",
                changed=False,
                snapshot=self._advance(snapshot, states, update, sample),
                diagnostic_code="affinity_abstained",
            )
        assert update.dimension is not None

        if update.action == "propose":
            if current is not None and current.state != "revoked":
                raise AffinityError("affinity_proposal_requires_empty_state")
            states[update.dimension] = self._asserting_state("provisional", update, sample)
            outcome = "proposed"
        elif update.action == "confirm":
            if current is None or current.state != "provisional":
                raise AffinityError("affinity_confirmation_requires_provisional")
            if current.value != update.value:
                raise AffinityError("affinity_confirmation_value_mismatch")
            if _CONFIDENCE_RANK[update.confidence] < _CONFIDENCE_RANK[current.confidence]:
                raise AffinityError("affinity_confirmation_confidence_regression")
            evidence = tuple(sorted(set(current.evidence_refs) | set(update.evidence_refs)))
            if evidence == current.evidence_refs:
                raise AffinityError("affinity_confirmation_requires_new_evidence")
            states[update.dimension] = AffinityDimensionState(
                dimension=update.dimension,
                state="confirmed",
                value=update.value,
                confidence=update.confidence,
                evidence_refs=evidence,
                revision=update.sequence,
                updated_at=sample.instant,
            )
            outcome = "confirmed"
        elif update.action == "update":
            if current is None or current.state not in {"provisional", "confirmed"}:
                raise AffinityError("affinity_update_requires_asserted_state")
            if current.value == update.value:
                raise AffinityError("affinity_update_no_change")
            states[update.dimension] = self._asserting_state("provisional", update, sample)
            outcome = "updated_provisional"
        elif update.action == "conflict":
            if current is None or current.state not in {"provisional", "confirmed"}:
                raise AffinityError("affinity_conflict_requires_asserted_state")
            if current.value == update.value:
                raise AffinityError("affinity_conflict_requires_distinct_value")
            states[update.dimension] = AffinityDimensionState(
                dimension=update.dimension,
                state="conflicted",
                value=None,
                confidence="none",
                evidence_refs=tuple(
                    sorted(set(current.evidence_refs) | set(update.evidence_refs))
                ),
                revision=update.sequence,
                updated_at=sample.instant,
            )
            outcome = "conflicted"
        elif update.action == "repair":
            if current is None or current.state != "conflicted":
                raise AffinityError("affinity_repair_requires_conflict")
            if update.confidence != "high" or len(update.evidence_refs) < 2:
                raise AffinityError("affinity_repair_evidence_insufficient")
            states[update.dimension] = self._asserting_state("provisional", update, sample)
            outcome = "repaired_provisional"
        elif update.action == "revoke":
            if current is None or current.state == "revoked":
                raise AffinityError("affinity_revoke_requires_active_state")
            states[update.dimension] = AffinityDimensionState(
                dimension=update.dimension,
                state="revoked",
                value=None,
                confidence="none",
                evidence_refs=update.evidence_refs,
                revision=update.sequence,
                updated_at=sample.instant,
            )
            outcome = "revoked"
        else:  # pragma: no cover - AffinityUpdate validates the allowlist.
            raise AffinityError("affinity_action_invalid")

        return AffinityTransition(
            outcome=outcome,
            changed=True,
            snapshot=self._advance(snapshot, states, update, sample),
            diagnostic_code="affinity_update_applied",
        )

    @staticmethod
    def _asserting_state(
        state: str,
        update: AffinityUpdate,
        sample: AffinityTimeSample,
    ) -> AffinityDimensionState:
        assert update.dimension is not None
        return AffinityDimensionState(
            dimension=update.dimension,
            state=state,
            value=update.value,
            confidence=update.confidence,
            evidence_refs=update.evidence_refs,
            revision=update.sequence,
            updated_at=sample.instant,
        )

    @staticmethod
    def _advance(
        snapshot: AffinitySnapshot,
        states: dict[str, AffinityDimensionState],
        update: AffinityUpdate,
        sample: AffinityTimeSample,
    ) -> AffinitySnapshot:
        return AffinitySnapshot(
            namespace_id=snapshot.namespace_id,
            revision=update.sequence,
            dimensions=tuple(sorted(states.values(), key=lambda item: item.dimension)),
            observed_at=sample.instant,
            time_sequence=sample.sequence,
            time_source=sample.source,
        )
