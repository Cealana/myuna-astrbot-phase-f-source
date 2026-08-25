from __future__ import annotations

from dataclasses import replace
import json
import unittest

from myuna_core.owner_profile.contracts import (
    PROFILE_ORDINARY_DELTA_LIMIT,
    OwnerProfile,
    OwnerProfileError,
    OwnerProfileSection,
    ProfileStateIntent,
    profile_v2_manifests,
)
from myuna_core.owner_profile.lifecycle import (
    GENESIS_DIGEST,
    LifecycleEvent,
    LifecycleState,
    OwnerProfileLifecycleError,
    apply_lifecycle_event,
    compare_profile_revisions,
    lifecycle_audit_projection,
    replay_lifecycle,
    evaluate_profile_state_transition,
    initial_profile_current,
    rebuild_profile_current,
)


PROFILE_ID = "synthetic-owner-profile"


def event(
    state: LifecycleState,
    event_type: str,
    *,
    target_revision: int,
    target_sha256: str,
    base_revision: int | None = None,
    base_sha256: str | None = None,
    confirmation_sha256: str | None = None,
    reason_category: str = "owner_requested",
) -> LifecycleEvent:
    return LifecycleEvent(
        event_type=event_type,
        event_id=f"event-{state.last_sequence + 1}-{event_type}",
        sequence=state.last_sequence + 1,
        previous_event_sha256=state.last_event_sha256,
        profile_id=PROFILE_ID,
        base_revision=base_revision,
        base_sha256=base_sha256,
        target_revision=target_revision,
        target_sha256=target_sha256,
        confirmation_sha256=confirmation_sha256,
        reason_category=reason_category,
    )


def registered_state() -> tuple[LifecycleState, list[LifecycleEvent]]:
    state = LifecycleState.empty(PROFILE_ID)
    baseline = event(
        state,
        "baseline_registered",
        target_revision=2,
        target_sha256="2" * 64,
        confirmation_sha256="a" * 64,
        reason_category="initial_registration",
    )
    return apply_lifecycle_event(state, baseline), [baseline]


def confirmed_candidate() -> tuple[LifecycleState, list[LifecycleEvent]]:
    state, events = registered_state()
    prepared = event(
        state,
        "candidate_prepared",
        base_revision=2,
        base_sha256="2" * 64,
        target_revision=3,
        target_sha256="3" * 64,
        reason_category="owner_authored_revision",
    )
    state = apply_lifecycle_event(state, prepared)
    confirmed = event(
        state,
        "owner_confirmed",
        base_revision=2,
        base_sha256="2" * 64,
        target_revision=3,
        target_sha256="3" * 64,
        confirmation_sha256="b" * 64,
        reason_category="owner_confirmed",
    )
    return apply_lifecycle_event(state, confirmed), [*events, prepared, confirmed]


def published_candidate() -> tuple[LifecycleState, list[LifecycleEvent]]:
    state, events = confirmed_candidate()
    published = event(
        state,
        "published",
        base_revision=2,
        base_sha256="2" * 64,
        target_revision=3,
        target_sha256="3" * 64,
        confirmation_sha256="b" * 64,
        reason_category="owner_confirmed",
    )
    return apply_lifecycle_event(state, published), [*events, published]


def synthetic_profile(
    revision: int,
    digest_character: str,
    sections: tuple[OwnerProfileSection, ...],
) -> OwnerProfile:
    return OwnerProfile(
        profile_id=PROFILE_ID,
        profile_revision=revision,
        sections=sections,
        sha256=digest_character * 64,
        byte_count=256,
    )


class OwnerProfileLifecycleTests(unittest.TestCase):
    def test_full_revision_revoke_restore_delete_and_purge_lifecycle(self) -> None:
        state, events = published_candidate()
        self.assertEqual(state.active_revision, 3)
        self.assertEqual(state.revisions[2].status, "superseded")

        restore_two = event(
            state,
            "restored",
            target_revision=2,
            target_sha256="2" * 64,
            confirmation_sha256="c" * 64,
            reason_category="rollback",
        )
        state = apply_lifecycle_event(state, restore_two)
        delete_three = event(
            state,
            "deletion_requested",
            target_revision=3,
            target_sha256="3" * 64,
            confirmation_sha256="d" * 64,
            reason_category="privacy_removal",
        )
        state = apply_lifecycle_event(state, delete_three)
        cancel_delete = event(
            state,
            "deletion_cancelled",
            target_revision=3,
            target_sha256="3" * 64,
            confirmation_sha256="e" * 64,
            reason_category="owner_requested",
        )
        state = apply_lifecycle_event(state, cancel_delete)
        restore_three = event(
            state,
            "restored",
            target_revision=3,
            target_sha256="3" * 64,
            confirmation_sha256="f" * 64,
            reason_category="owner_requested",
        )
        state = apply_lifecycle_event(state, restore_three)
        restore_two_again = event(
            state,
            "restored",
            target_revision=2,
            target_sha256="2" * 64,
            confirmation_sha256="1" * 64,
            reason_category="rollback",
        )
        state = apply_lifecycle_event(state, restore_two_again)
        delete_three_again = event(
            state,
            "deletion_requested",
            target_revision=3,
            target_sha256="3" * 64,
            confirmation_sha256="4" * 64,
            reason_category="privacy_removal",
        )
        state = apply_lifecycle_event(state, delete_three_again)
        purge_three = event(
            state,
            "purged",
            target_revision=3,
            target_sha256="3" * 64,
            confirmation_sha256="5" * 64,
            reason_category="privacy_removal",
        )
        state = apply_lifecycle_event(state, purge_three)
        restore_purged = event(
            state,
            "restored",
            target_revision=3,
            target_sha256="3" * 64,
            confirmation_sha256="6" * 64,
            reason_category="rollback",
        )
        with self.assertRaisesRegex(
            OwnerProfileLifecycleError,
            "state_transition_rejected",
        ):
            apply_lifecycle_event(state, restore_purged)
        events.extend(
            (
                restore_two,
                delete_three,
                cancel_delete,
                restore_three,
                restore_two_again,
                delete_three_again,
                purge_three,
            )
        )

        self.assertEqual(state.active_revision, 2)
        self.assertEqual(state.revisions[2].status, "published")
        self.assertEqual(state.revisions[3].status, "purged")
        replayed = replay_lifecycle(
            PROFILE_ID,
            tuple(item.canonical_bytes() for item in events),
        )
        self.assertEqual(replayed, state)

    def test_confirmation_and_publication_order_fail_closed(self) -> None:
        state, _ = registered_state()
        confirm_without_candidate = event(
            state,
            "owner_confirmed",
            base_revision=2,
            base_sha256="2" * 64,
            target_revision=3,
            target_sha256="3" * 64,
            confirmation_sha256="a" * 64,
            reason_category="owner_confirmed",
        )
        with self.assertRaisesRegex(
            OwnerProfileLifecycleError, "state_transition_rejected"
        ):
            apply_lifecycle_event(state, confirm_without_candidate)

        state, _ = confirmed_candidate()
        drifted_publish = event(
            state,
            "published",
            base_revision=2,
            base_sha256="9" * 64,
            target_revision=3,
            target_sha256="3" * 64,
            confirmation_sha256="b" * 64,
            reason_category="owner_confirmed",
        )
        with self.assertRaisesRegex(
            OwnerProfileLifecycleError, "state_transition_rejected"
        ):
            apply_lifecycle_event(state, drifted_publish)

        wrong_confirmation = event(
            state,
            "published",
            base_revision=2,
            base_sha256="2" * 64,
            target_revision=3,
            target_sha256="3" * 64,
            confirmation_sha256="c" * 64,
            reason_category="owner_confirmed",
        )
        with self.assertRaisesRegex(
            OwnerProfileLifecycleError, "state_transition_rejected"
        ):
            apply_lifecycle_event(state, wrong_confirmation)

    def test_active_or_purged_release_cannot_be_deleted_or_restored(self) -> None:
        state, _ = published_candidate()
        delete_active = event(
            state,
            "deletion_requested",
            target_revision=3,
            target_sha256="3" * 64,
            confirmation_sha256="a" * 64,
            reason_category="privacy_removal",
        )
        with self.assertRaisesRegex(
            OwnerProfileLifecycleError, "state_transition_rejected"
        ):
            apply_lifecycle_event(state, delete_active)

        restore_active = event(
            state,
            "restored",
            target_revision=3,
            target_sha256="3" * 64,
            confirmation_sha256="b" * 64,
            reason_category="rollback",
        )
        with self.assertRaisesRegex(
            OwnerProfileLifecycleError,
            "state_transition_rejected",
        ):
            apply_lifecycle_event(state, restore_active)

    def test_chain_sequence_previous_digest_and_event_id_are_strict(self) -> None:
        state, events = registered_state()
        valid = event(
            state,
            "candidate_prepared",
            base_revision=2,
            base_sha256="2" * 64,
            target_revision=3,
            target_sha256="3" * 64,
            reason_category="owner_authored_revision",
        )
        candidates = (
            replace_event(valid, sequence=valid.sequence + 1),
            replace_event(valid, previous_event_sha256="9" * 64),
            replace_event(valid, event_id=events[0].event_id),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaisesRegex(
                OwnerProfileLifecycleError, "event_chain_rejected"
            ):
                apply_lifecycle_event(state, candidate)

        same_digest = event(
            state,
            "candidate_prepared",
            base_revision=2,
            base_sha256="2" * 64,
            target_revision=3,
            target_sha256="2" * 64,
            reason_category="owner_authored_revision",
        )
        with self.assertRaisesRegex(
            OwnerProfileLifecycleError,
            "state_transition_rejected",
        ):
            apply_lifecycle_event(state, same_digest)

    def test_event_encoding_is_deterministic_and_unknown_fields_reject(self) -> None:
        state, events = registered_state()
        encoded = events[0].canonical_bytes()
        self.assertEqual(LifecycleEvent.from_bytes(encoded), events[0])
        self.assertEqual(LifecycleEvent.from_bytes(encoded).sha256, events[0].sha256)
        payload = json.loads(encoded)
        payload["unknown"] = True
        with self.assertRaisesRegex(OwnerProfileLifecycleError, "invalid_event"):
            LifecycleEvent.from_bytes(json.dumps(payload).encode("ascii"))
        self.assertEqual(state.last_event_sha256, events[0].sha256)
        self.assertNotEqual(state.last_event_sha256, GENESIS_DIGEST)

        invalid_variants = (
            {"schema_version": True},
            {"reason_category": "owner_requested"},
            {"base_revision": 1, "base_sha256": "1" * 64},
        )
        for changes in invalid_variants:
            with self.subTest(changes=changes), self.assertRaisesRegex(
                OwnerProfileLifecycleError,
                "invalid_event",
            ):
                replace_event(events[0], **changes)

    def test_profile_revision_comparison_is_content_free(self) -> None:
        base = synthetic_profile(
            2,
            "2",
            (
                OwnerProfileSection(
                    "section-a",
                    "topic-a",
                    "long_term_preference",
                    "Synthetic A",
                    "Synthetic stable preference A",
                    ("alpha",),
                ),
                OwnerProfileSection(
                    "section-b",
                    "topic-b",
                    "ongoing_project",
                    "Synthetic B",
                    "Synthetic ongoing project B",
                    ("beta",),
                ),
            ),
        )
        candidate = synthetic_profile(
            3,
            "3",
            (
                OwnerProfileSection(
                    "section-a",
                    "topic-a",
                    "long_term_preference",
                    "Synthetic A revised",
                    "Synthetic stable preference A revised",
                    ("alpha",),
                ),
                OwnerProfileSection(
                    "section-c",
                    "topic-c",
                    "long_term_goal",
                    "Synthetic C",
                    "Synthetic long-term goal C",
                    ("gamma",),
                ),
            ),
        )
        summary = compare_profile_revisions(base, candidate)
        self.assertEqual(summary.added_sections, 1)
        self.assertEqual(summary.updated_sections, 1)
        self.assertEqual(summary.removed_sections, 1)
        serialized = json.dumps(
            {
                "base_revision": summary.base_revision,
                "target_revision": summary.target_revision,
                "added_sections": summary.added_sections,
                "updated_sections": summary.updated_sections,
                "removed_sections": summary.removed_sections,
            }
        )
        self.assertNotIn("Synthetic", serialized)

    def test_profile_revision_comparison_rejects_no_semantic_change(self) -> None:
        sections = (
            OwnerProfileSection(
                "section-a",
                "topic-a",
                "long_term_preference",
                "Synthetic A",
                "Synthetic stable preference A",
                ("alpha",),
            ),
        )
        base = synthetic_profile(2, "2", sections)
        candidate = synthetic_profile(3, "3", sections)
        with self.assertRaisesRegex(
            OwnerProfileLifecycleError,
            "revision_comparison_rejected",
        ):
            compare_profile_revisions(base, candidate)

    def test_audit_projection_excludes_private_fields(self) -> None:
        _, events = registered_state()
        projection = lifecycle_audit_projection(events[0], outcome="accepted")
        serialized = json.dumps(projection, sort_keys=True)
        for forbidden in (
            PROFILE_ID,
            events[0].event_id,
            events[0].target_sha256,
            events[0].confirmation_sha256,
            "profile_sha256",
            "event_id",
        ):
            self.assertNotIn(str(forbidden), serialized)
        self.assertEqual(projection["release_effect_category"], "none")
        self.assertFalse(projection["raw_content_recorded"])
        self.assertFalse(projection["legacy_namespace_written"])

        for error_category in (
            "lifecycle_path_rejected",
            "lifecycle_permission_drift",
            "lifecycle_recovery_required",
        ):
            with self.subTest(error_category=error_category):
                failed = lifecycle_audit_projection(
                    None,
                    outcome="failed",
                    error_category=error_category,
                )
                self.assertEqual(failed["error_category"], error_category)

    def test_v2_manifests_are_preprovisioned_but_not_zero_initialized(self) -> None:
        manifests = profile_v2_manifests()
        self.assertEqual(len(manifests), 8)
        self.assertEqual(len({item.module_id for item in manifests}), 8)
        relationship = manifests[0]
        self.assertEqual(relationship.field_id, "relationship_state.intimacy_headline")
        self.assertEqual(relationship.display_name, "亲密度")
        current = initial_profile_current(relationship)
        self.assertEqual(current.state, "uninitialized")
        self.assertIsNone(current.scaled_value)
        self.assertNotEqual(current.scaled_value, 0)

    def test_v2_fixed_point_transition_rebuild_freeze_and_saturation(self) -> None:
        manifest = profile_v2_manifests()[0]
        current = initial_profile_current(manifest)
        initialized = profile_state_intent(
            "intent-init", action="initialize", actor="owner", value=20_000
        )
        first, current, receipt = evaluate_profile_state_transition(
            manifest, current, initialized
        )
        self.assertIsNotNone(first)
        self.assertEqual(current.scaled_value, 20_000)
        self.assertTrue(receipt.mutated)
        assert first is not None
        delta = profile_state_intent(
            "intent-delta",
            action="delta",
            actor="myuna",
            delta=PROFILE_ORDINARY_DELTA_LIMIT,
            head=current.last_event_digest,
        )
        second, current, _ = evaluate_profile_state_transition(manifest, current, delta)
        assert second is not None
        self.assertEqual(current.scaled_value, 40_000)
        self.assertEqual(rebuild_profile_current(manifest, (first, second)), current)
        frozen, current, _ = evaluate_profile_state_transition(
            manifest,
            current,
            profile_state_intent(
                "intent-freeze",
                action="freeze",
                actor="owner",
                head=current.last_event_digest,
            ),
        )
        self.assertEqual(current.state, "frozen")
        self.assertIsNotNone(frozen)
        with self.assertRaisesRegex(OwnerProfileLifecycleError, "delta_rejected"):
            evaluate_profile_state_transition(
                manifest,
                current,
                profile_state_intent(
                    "intent-frozen-delta",
                    action="delta",
                    actor="myuna",
                    delta=1,
                    head=current.last_event_digest,
                ),
            )

    def test_v2_owner_only_fixed_point_rejects_myuna_authority(self) -> None:
        catalog = profile_v2_manifests()[0]
        owner_only = replace(
            catalog,
            authority="owner",
            autonomous_enabled=False,
        )
        with self.assertRaisesRegex(
            OwnerProfileError,
            "profile_manifest_authority_rejected",
        ):
            owner_only.require_action_policy(
                actor="myuna",
                action="delta",
                reason_category="delivered_turn",
            )
        current = initial_profile_current(owner_only)
        with self.assertRaisesRegex(
            OwnerProfileLifecycleError,
            "profile_state_binding_rejected",
        ):
            evaluate_profile_state_transition(
                owner_only,
                current,
                profile_state_intent(
                    "owner-only-myuna-delta",
                    action="delta",
                    actor="myuna",
                    delta=10_000,
                    head=current.last_event_digest,
                ),
            )
        self.assertEqual(current, initial_profile_current(owner_only))

    def test_v2_wrong_types_and_over_cap_delta_reject(self) -> None:
        with self.assertRaises(OwnerProfileError):
            profile_state_intent(
                "intent-bool", action="initialize", actor="owner", value=True
            )
        manifest = profile_v2_manifests()[0]
        _, current, _ = evaluate_profile_state_transition(
            manifest,
            initial_profile_current(manifest),
            profile_state_intent(
                "intent-init-over", action="initialize", actor="owner", value=0
            ),
        )
        with self.assertRaisesRegex(OwnerProfileLifecycleError, "delta_limit"):
            evaluate_profile_state_transition(
                manifest,
                current,
                profile_state_intent(
                    "intent-over-cap",
                    action="delta",
                    actor="myuna",
                    delta=PROFILE_ORDINARY_DELTA_LIMIT + 1,
                    head=current.last_event_digest,
                ),
            )


def replace_event(source: LifecycleEvent, **changes: object) -> LifecycleEvent:
    payload = source.as_payload()
    payload.update(changes)
    return LifecycleEvent(**payload)  # type: ignore[arg-type]


def profile_state_intent(
    intent_id: str,
    *,
    action: str,
    actor: str,
    value: int | None = None,
    delta: int | None = None,
    head: str | None = None,
) -> ProfileStateIntent:
    owner_reasons = {
        "correct": "owner_correction",
        "freeze": "owner_freeze",
        "rollback": "owner_rollback",
    }
    return ProfileStateIntent(
        intent_id=intent_id,
        action=action,
        module_id="relationship_state",
        field_id="relationship_state.intimacy_headline",
        actor=actor,
        reason_category=(
            owner_reasons.get(action, "owner_confirmed")
            if actor == "owner"
            else "delivered_turn"
        ),
        requested_value=value,
        requested_delta=delta,
        expected_event_digest=head,
        raw_source_digest="1" * 64,
        p08_source_digest="2" * 64,
        trusted_time_digest="3" * 64,
        delivered_turn_id="turn-1",
        delivery_ack_digest="4" * 64,
        delivered_source_reference_digest="5" * 64,
        delivered_at_utc="2026-08-20T00:00:00.000000Z",
    )


if __name__ == "__main__":
    unittest.main()
