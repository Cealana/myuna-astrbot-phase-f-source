from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest

from myuna_core.affinity import (
    FIXTURE_SCHEMA,
    AffinityError,
    AffinitySnapshot,
    AffinityTimeSample,
    AffinityUpdate,
    SyntheticAffinityStateMachine,
)


ROOT = Path(__file__).resolve().parents[1]
T0 = datetime(2040, 1, 2, 3, 4, tzinfo=timezone.utc)


def sample(sequence: int, *, source_class: str = "synthetic") -> AffinityTimeSample:
    return AffinityTimeSample(
        instant=T0 + timedelta(seconds=sequence),
        sequence=sequence,
        source="synthetic-clock",
        source_class=source_class,
    )


class AffinityFoundationStateMachineTests(unittest.TestCase):
    def setUp(self) -> None:
        path = ROOT / "fixtures" / "affinity" / "p09-v7-structured-affinity-v1.json"
        self.fixture_bytes = path.read_bytes()
        self.fixture = json.loads(self.fixture_bytes)
        self.assertEqual(self.fixture["fixture_schema"], FIXTURE_SCHEMA)
        self.machine = SyntheticAffinityStateMachine()

    def test_fixture_is_deterministic_and_exercises_abstain_conflict_repair(self) -> None:
        snapshot = AffinitySnapshot.empty(self.fixture["namespace_id"])
        outcomes = []
        digests = []
        for index, payload in enumerate(self.fixture["events"], start=1):
            transition = self.machine.transition(
                snapshot,
                AffinityUpdate.from_payload(payload),
                sample(index),
            )
            snapshot = transition.snapshot
            outcomes.append(transition.outcome)
            digests.append(snapshot.digest)

        self.assertEqual(
            outcomes,
            ["abstained", "proposed", "confirmed", "conflicted", "repaired_provisional"],
        )
        self.assertEqual(snapshot.revision, 5)
        self.assertEqual(snapshot.dimensions[0].state, "provisional")
        self.assertEqual(snapshot.dimensions[0].value, 20)
        self.assertEqual(snapshot.dimensions[0].confidence, "high")
        self.assertEqual(len(set(digests)), len(digests))

        replay = AffinitySnapshot.empty(self.fixture["namespace_id"])
        replay_digests = []
        for index, payload in enumerate(self.fixture["events"], start=1):
            replay = self.machine.transition(
                replay,
                AffinityUpdate.from_payload(payload),
                sample(index),
            ).snapshot
            replay_digests.append(replay.digest)
        self.assertEqual(replay_digests, digests)

    def test_abstention_advances_sequence_without_creating_a_value(self) -> None:
        snapshot = AffinitySnapshot.empty("synthetic.owner-alpha")
        transition = self.machine.transition(
            snapshot,
            AffinityUpdate.from_payload(self.fixture["events"][0]),
            sample(1),
        )
        self.assertFalse(transition.changed)
        self.assertEqual(transition.snapshot.revision, 1)
        self.assertEqual(transition.snapshot.dimensions, ())

    def test_confirmation_requires_new_evidence_and_non_regressing_confidence(self) -> None:
        snapshot = AffinitySnapshot.empty("synthetic.owner-alpha")
        proposed = AffinityUpdate.from_payload(self.fixture["events"][1])
        proposed = AffinityUpdate.from_payload(proposed.as_payload() | {"sequence": 1})
        snapshot = self.machine.transition(snapshot, proposed, sample(1)).snapshot
        duplicate = AffinityUpdate.from_payload(
            self.fixture["events"][2]
            | {
                "confidence": "low",
                "evidence_refs": ["synthetic.profile.1"],
                "sequence": 2,
            }
        )
        with self.assertRaisesRegex(AffinityError, "requires_new_evidence"):
            self.machine.transition(snapshot, duplicate, sample(2))

    def test_conflict_hides_value_and_repair_never_self_confirms(self) -> None:
        snapshot = AffinitySnapshot.empty("synthetic.owner-alpha")
        events = self.fixture["events"][1:]
        adjusted = [dict(item, sequence=index) for index, item in enumerate(events, start=1)]
        for index, payload in enumerate(adjusted[:3], start=1):
            snapshot = self.machine.transition(
                snapshot, AffinityUpdate.from_payload(payload), sample(index)
            ).snapshot
        self.assertEqual(snapshot.dimensions[0].state, "conflicted")
        self.assertIsNone(snapshot.dimensions[0].value)
        self.assertEqual(snapshot.dimensions[0].confidence, "none")
        snapshot = self.machine.transition(
            snapshot,
            AffinityUpdate.from_payload(adjusted[3]),
            sample(4),
        ).snapshot
        self.assertEqual(snapshot.dimensions[0].state, "provisional")

    def test_live_or_unfrozen_time_source_is_rejected(self) -> None:
        snapshot = AffinitySnapshot.empty("synthetic.owner-alpha")
        update = AffinityUpdate.from_payload(
            self.fixture["events"][1] | {"sequence": 1}
        )
        with self.assertRaisesRegex(AffinityError, "affinity_live_transition_forbidden"):
            self.machine.transition(snapshot, update, sample(1, source_class="trusted_local"))

    def test_sequence_and_time_regression_fail_closed(self) -> None:
        snapshot = AffinitySnapshot.empty("synthetic.owner-alpha")
        update = AffinityUpdate.from_payload(
            self.fixture["events"][1] | {"sequence": 2}
        )
        with self.assertRaisesRegex(AffinityError, "affinity_sequence_regression"):
            self.machine.transition(snapshot, update, sample(1))

    def test_update_returns_to_provisional_and_revoke_clears_the_value(self) -> None:
        snapshot = AffinitySnapshot.empty("synthetic.owner-alpha")
        proposed = AffinityUpdate.from_payload(
            self.fixture["events"][1] | {"sequence": 1}
        )
        snapshot = self.machine.transition(snapshot, proposed, sample(1)).snapshot
        confirmed = AffinityUpdate.from_payload(
            self.fixture["events"][2] | {"sequence": 2}
        )
        snapshot = self.machine.transition(snapshot, confirmed, sample(2)).snapshot
        updated = AffinityUpdate.from_payload(
            self.fixture["events"][1]
            | {
                "action": "update",
                "event_id": "synthetic-event-update",
                "evidence_refs": ["synthetic.context.update"],
                "sequence": 3,
                "value": 20,
            }
        )
        snapshot = self.machine.transition(snapshot, updated, sample(3)).snapshot
        self.assertEqual(snapshot.dimensions[0].state, "provisional")
        self.assertEqual(snapshot.dimensions[0].value, 20)
        revoked = AffinityUpdate.from_payload(
            self.fixture["events"][0]
            | {
                "abstention_reason": None,
                "action": "revoke",
                "event_id": "synthetic-event-revoke",
                "evidence_refs": ["synthetic.owner.revoke"],
                "sequence": 4,
            }
        )
        snapshot = self.machine.transition(snapshot, revoked, sample(4)).snapshot
        self.assertEqual(snapshot.dimensions[0].state, "revoked")
        self.assertIsNone(snapshot.dimensions[0].value)
        self.assertEqual(snapshot.dimensions[0].confidence, "none")


if __name__ == "__main__":
    unittest.main()
