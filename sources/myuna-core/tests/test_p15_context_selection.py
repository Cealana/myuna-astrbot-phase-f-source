from __future__ import annotations

from datetime import datetime, timezone
import unittest

from myuna_core.context_orchestration.contracts import (
    AffinityStateLane,
    ContextCandidate,
    CurrentMessageLane,
    DefinitionLane,
    ExternalContextLanes,
    P15SelectionInput,
    P15ContractError,
    ProfileLane,
    RecentTurnLane,
    SelectionBudget,
    SourceProvenance,
    SummaryLane,
    TemporalLane,
    TrustedTimeState,
    VisualObservationLane,
)
from myuna_core.context_orchestration.selection import select_context


NOW = datetime(2026, 8, 5, tzinfo=timezone.utc)


def provenance(
    source: str,
    *,
    known: bool = True,
    schema_known: bool = True,
) -> SourceProvenance:
    return SourceProvenance(
        known,
        schema_known,
        f"myuna.synthetic-{source}.v1",
        1,
        1,
        f"synthetic:{source}",
    )


def candidate(
    candidate_id: str,
    source_kind: str,
    content: str | tuple[str, ...],
    *,
    relevance: int = 50,
    upstream_rank: int = 0,
    essential: bool = False,
    domain: str | None = None,
    state: str = "active",
    known: bool = True,
    schema_known: bool = True,
    conflict_key: str | None = None,
    conflicts_with_current: bool = False,
    material_conflict: bool = False,
) -> ContextCandidate:
    fragments = (content,) if isinstance(content, str) else content
    domains = {
        "definition": "policy",
        "current_message": "current_intent",
        "profile": "stable_fact",
        "temporal": "current_time_bounded_fact",
        "external_summary": "continuity",
        "external_recent_turn": "continuity",
        "visual_observation": "visual_evidence",
        "affinity_state": "style",
    }
    return ContextCandidate(
        candidate_id,
        source_kind,
        provenance(source_kind, known=known, schema_known=schema_known),
        fragments,
        relevance,
        upstream_rank,
        essential,
        domain or domains[source_kind],
        state,
        conflict_key,
        conflicts_with_current,
        material_conflict,
    )


def request(
    *,
    current: CurrentMessageLane | None = None,
    profile: tuple[ProfileLane, ...] = (),
    temporal: tuple[TemporalLane, ...] = (),
    summary: SummaryLane | None = None,
    recent: tuple[RecentTurnLane, ...] = (),
    visual: VisualObservationLane | None = None,
    affinity: AffinityStateLane | None = None,
    time_available: bool = True,
    budget: SelectionBudget = SelectionBudget(50_000, 100_000),
    replay_snapshot_match: bool = True,
    continuity_reset: bool = False,
) -> P15SelectionInput:
    return P15SelectionInput(
        "event-1",
        budget,
        TrustedTimeState("available", NOW, "synthetic-time", 1)
        if time_available
        else TrustedTimeState("unavailable", None),
        replay_snapshot_match,
        DefinitionLane(candidate("definition", "definition", "policy", relevance=100), True),
        current
        or CurrentMessageLane(
            candidate("current", "current_message", "request", relevance=100),
            True,
        ),
        profile,
        temporal,
        ExternalContextLanes(
            summary,
            recent,
            continuity_reset,
            "authorized_generation_transition" if continuity_reset else "none",
        ),
        visual,
        affinity,
    )


def selected_ids(result: object) -> list[str]:
    return [item.candidate_id for item in result.selected]


def reasons(result: object) -> dict[str, str]:
    return {item.candidate_id: item.reason for item in result.decisions}


class P15SelectionOracleTests(unittest.TestCase):
    def test_all_typed_sources_render_in_frozen_order(self) -> None:
        profile = ProfileLane(candidate("p1", "profile", "stable", relevance=70))
        temporal = TemporalLane(
            candidate("t1", "temporal", "temporary", relevance=80),
            NOW.replace(day=6),
        )
        summary = SummaryLane(candidate("s1", "external_summary", "older"), 1, 1, True)
        recent = RecentTurnLane(
            candidate("r2", "external_recent_turn", ("user", "reply")),
            2,
            "delivered",
        )
        visual = VisualObservationLane(
            candidate("v1", "visual_observation", "seen", relevance=90),
            0.9,
        )
        affinity = AffinityStateLane(
            candidate("a1", "affinity_state", "style", relevance=20),
            "ready",
            "a" * 64,
        )
        result = select_context(
            request(
                profile=(profile,),
                temporal=(temporal,),
                summary=summary,
                recent=(recent,),
                visual=visual,
                affinity=affinity,
            )
        )
        self.assertEqual(
            selected_ids(result),
            ["definition", "p1", "t1", "s1", "r2", "v1", "a1", "current"],
        )
        self.assertEqual(result.status, "select")
        self.assertFalse(result.fault)

    def test_unknown_optional_drops_and_unknown_required_abstains(self) -> None:
        unknown = ProfileLane(candidate("p", "profile", "unknown", known=False))
        optional_result = select_context(request(profile=(unknown,)))
        self.assertEqual(selected_ids(optional_result), ["definition", "current"])
        self.assertEqual(reasons(optional_result)["p"], "drop_unknown_provenance")

        current = CurrentMessageLane(
            candidate("current", "current_message", "request", known=False),
            True,
        )
        required_result = select_context(request(current=current))
        self.assertEqual(required_result.status, "abstain")
        self.assertEqual(selected_ids(required_result), [])
        self.assertEqual(reasons(required_result)["current"], "abstain_required_provenance")

    def test_trusted_time_unavailable_clarifies_without_guessing(self) -> None:
        current = CurrentMessageLane(
            candidate("current", "current_message", "deadline?"),
            True,
            requires_trusted_time=True,
        )
        temporal = TemporalLane(candidate("t1", "temporal", "tomorrow"), NOW.replace(day=6))
        result = select_context(
            request(current=current, temporal=(temporal,), time_available=False)
        )
        self.assertEqual(result.status, "clarify")
        self.assertEqual(selected_ids(result), ["definition", "current"])
        self.assertEqual(reasons(result)["t1"], "drop_trusted_time_unavailable")

    def test_stale_expired_and_boundary_are_dropped(self) -> None:
        stale = ProfileLane(candidate("p1", "profile", "old", state="stale"))
        expired = TemporalLane(candidate("t1", "temporal", "past"), NOW.replace(day=4))
        boundary = TemporalLane(candidate("t2", "temporal", "now"), NOW)
        result = select_context(request(profile=(stale,), temporal=(expired, boundary)))
        self.assertEqual(selected_ids(result), ["definition", "current"])
        self.assertEqual(reasons(result)["p1"], "drop_stale")
        self.assertEqual(reasons(result)["t1"], "drop_expired")
        self.assertEqual(reasons(result)["t2"], "drop_expired")

    def test_visual_low_confidence_and_material_conflict_clarify(self) -> None:
        low = VisualObservationLane(
            candidate("v1", "visual_observation", "uncertain", essential=True),
            0.2,
        )
        low_result = select_context(request(visual=low))
        self.assertEqual(low_result.status, "clarify")
        self.assertEqual(reasons(low_result)["v1"], "drop_low_confidence")

        conflict = VisualObservationLane(
            candidate(
                "v2",
                "visual_observation",
                "conflict",
                conflicts_with_current=True,
                material_conflict=True,
            ),
            0.9,
        )
        conflict_result = select_context(request(visual=conflict))
        self.assertEqual(conflict_result.status, "clarify")
        self.assertEqual(reasons(conflict_result)["v2"], "drop_conflict_shadowed")

    def test_nfkc_duplicate_preserves_original_selected_fragments(self) -> None:
        profile = ProfileLane(candidate("p1", "profile", "ＡＢＣ", relevance=90))
        summary = SummaryLane(
            candidate("s1", "external_summary", "abc", relevance=50, domain="stable_fact"),
            1,
            1,
            True,
        )
        result = select_context(request(profile=(profile,), summary=summary))
        self.assertEqual(selected_ids(result), ["definition", "p1", "current"])
        self.assertEqual(result.selected[1].content_fragments, ("ＡＢＣ",))
        self.assertEqual(reasons(result)["s1"], "drop_duplicate")

    def test_domain_authority_and_ambiguous_peer_conflict(self) -> None:
        profile = ProfileLane(
            candidate(
                "p1",
                "profile",
                "usual",
                domain="current_time_bounded_fact",
                conflict_key="mode",
            )
        )
        temporal = TemporalLane(
            candidate("t1", "temporal", "temporary", conflict_key="mode"),
            NOW.replace(day=6),
        )
        result = select_context(request(profile=(profile,), temporal=(temporal,)))
        self.assertEqual(selected_ids(result), ["definition", "t1", "current"])
        self.assertEqual(reasons(result)["p1"], "drop_conflict_shadowed")

        peers = (
            ProfileLane(candidate("left", "profile", "left", conflict_key="choice")),
            ProfileLane(candidate("right", "profile", "right", conflict_key="choice")),
        )
        peer_result = select_context(request(profile=peers))
        self.assertEqual(peer_result.status, "clarify")
        self.assertEqual(selected_ids(peer_result), ["definition", "current"])
        self.assertEqual(reasons(peer_result)["left"], "drop_conflict_ambiguous")
        self.assertEqual(reasons(peer_result)["right"], "drop_conflict_ambiguous")

    def test_summary_continuity_gap_overlap_and_integrity(self) -> None:
        summary = SummaryLane(candidate("s", "external_summary", "through three"), 1, 3, True)
        overlap = RecentTurnLane(candidate("r3", "external_recent_turn", "three"), 3, "delivered")
        next_turn = RecentTurnLane(candidate("r4", "external_recent_turn", "four"), 4, "delivered")
        result = select_context(request(summary=summary, recent=(overlap, next_turn)))
        self.assertEqual(selected_ids(result), ["definition", "s", "r4", "current"])
        self.assertEqual(reasons(result)["r3"], "drop_duplicate")

        continuity_current = CurrentMessageLane(
            candidate("current", "current_message", "continue"),
            True,
            continuity_required=True,
        )
        gap = RecentTurnLane(candidate("r5", "external_recent_turn", "five"), 5, "delivered")
        gap_result = select_context(
            request(current=continuity_current, summary=summary, recent=(gap,))
        )
        self.assertEqual(gap_result.status, "clarify")
        self.assertEqual(selected_ids(gap_result), ["definition", "r5", "current"])
        self.assertEqual(reasons(gap_result)["s"], "drop_summary_gap")

        internal_gap = (
            RecentTurnLane(
                candidate("r4-gap", "external_recent_turn", "four"),
                4,
                "delivered",
            ),
            RecentTurnLane(
                candidate("r6-gap", "external_recent_turn", "six"),
                6,
                "delivered",
            ),
        )
        internal_result = select_context(
            request(
                current=continuity_current,
                summary=summary,
                recent=internal_gap,
            )
        )
        self.assertEqual(internal_result.status, "clarify")
        self.assertEqual(reasons(internal_result)["s"], "drop_summary_gap")

        unknown = SummaryLane(candidate("bad", "external_summary", "unknown"), 1, 1, False)
        abstained = select_context(request(summary=unknown))
        self.assertEqual(abstained.status, "abstain")
        self.assertEqual(reasons(abstained)["bad"], "abstain_summary_integrity")

    def test_delivery_replay_and_crash_are_excluded(self) -> None:
        turns = (
            RecentTurnLane(candidate("failed", "external_recent_turn", "failed"), 1, "failed"),
            RecentTurnLane(candidate("pending", "external_recent_turn", "pending"), 2, "pending"),
            RecentTurnLane(
                candidate("orphan", "external_recent_turn", "orphan"),
                3,
                "crash_orphaned",
            ),
            RecentTurnLane(candidate("ok", "external_recent_turn", "ok"), 4, "delivered"),
            RecentTurnLane(
                candidate("replay", "external_recent_turn", "ok"),
                5,
                "delivered",
                replay_of="ok",
            ),
        )
        result = select_context(request(recent=turns))
        self.assertEqual(selected_ids(result), ["definition", "ok", "current"])
        self.assertEqual(reasons(result)["failed"], "drop_delivery_not_committed")
        self.assertEqual(reasons(result)["pending"], "drop_delivery_not_committed")
        self.assertEqual(reasons(result)["orphan"], "drop_delivery_not_committed")
        self.assertEqual(reasons(result)["replay"], "drop_replay_duplicate")

    def test_budget_lane_cap_low_relevance_and_no_truncation(self) -> None:
        high = ProfileLane(candidate("high", "profile", "1234567890", relevance=90))
        low = TemporalLane(
            candidate("low", "temporal", "abcdefghij", relevance=80),
            NOW.replace(day=6),
        )
        result = select_context(
            request(
                profile=(high,),
                temporal=(low,),
                budget=SelectionBudget(23, 23),
            )
        )
        self.assertEqual(selected_ids(result), ["definition", "high", "current"])
        self.assertEqual(reasons(result)["low"], "drop_budget")
        self.assertEqual(result.selected[1].content_fragments, ("1234567890",))

        profiles = tuple(
            ProfileLane(candidate(f"p{index}", "profile", str(index), relevance=100-index))
            for index in range(1, 5)
        )
        capped = select_context(request(profile=profiles))
        self.assertEqual(selected_ids(capped), ["definition", "p1", "p2", "p3", "current"])
        self.assertEqual(reasons(capped)["p4"], "drop_lane_cap")

        irrelevant = ProfileLane(candidate("zero", "profile", "unrelated", relevance=0))
        dropped = select_context(request(profile=(irrelevant,)))
        self.assertEqual(reasons(dropped)["zero"], "drop_low_relevance")

    def test_required_oversize_and_snapshot_drift_abstain(self) -> None:
        oversize = CurrentMessageLane(
            candidate("current", "current_message", "x" * 4_001),
            True,
        )
        result = select_context(request(current=oversize))
        self.assertEqual(result.status, "abstain")
        self.assertEqual(reasons(result)["current"], "abstain_required_oversize")

        drift = select_context(request(replay_snapshot_match=False))
        self.assertEqual(drift.status, "abstain")
        self.assertEqual(reasons(drift)["request"], "abstain_replay_snapshot_drift")

    def test_optional_oversize_unknown_schema_and_invalid_unicode_fail_closed(self) -> None:
        oversize = ProfileLane(candidate("huge", "profile", "x" * 6_001))
        oversize_result = select_context(request(profile=(oversize,)))
        self.assertEqual(reasons(oversize_result)["huge"], "drop_lane_cap")

        unknown_schema = ProfileLane(
            candidate("schema", "profile", "value", schema_known=False)
        )
        schema_result = select_context(request(profile=(unknown_schema,)))
        self.assertEqual(reasons(schema_result)["schema"], "drop_unknown_schema")

        with self.assertRaisesRegex(P15ContractError, "candidate_content_out_of_contract"):
            candidate("surrogate", "profile", "\ud800")

        with self.assertRaisesRegex(P15ContractError, "candidate_domain_source_mismatch"):
            candidate("wrong-domain", "profile", "value", domain="policy")

    def test_affinity_unavailable_is_optional_and_reset_is_non_fault(self) -> None:
        unavailable = AffinityStateLane(
            candidate("a", "affinity_state", "style"),
            "unavailable",
            "b" * 64,
        )
        result = select_context(request(affinity=unavailable, continuity_reset=True))
        self.assertEqual(selected_ids(result), ["definition", "current"])
        self.assertEqual(reasons(result)["a"], "drop_capability_unavailable")
        self.assertTrue(result.normal_transition)
        self.assertFalse(result.fault)

    def test_snapshot_and_audit_are_content_free_and_deterministic(self) -> None:
        turn = RecentTurnLane(
            candidate("r1", "external_recent_turn", ("raw user", "raw reply")),
            1,
            "delivered",
        )
        first = select_context(request(recent=(turn,)))
        second = select_context(request(recent=(turn,)))
        self.assertEqual(first.audit_payload(), second.audit_payload())
        self.assertNotIn("raw user", str(first.audit_payload()))
        self.assertNotIn("raw reply", str(first.audit_payload()))
        selected = next(item for item in first.selected if item.candidate_id == "r1")
        self.assertEqual(selected.content_fragments, ("raw user", "raw reply"))


if __name__ == "__main__":
    unittest.main()
