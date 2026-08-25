from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import p08_forward_continuity_orchestration_v1 as continuity
from myuna_core.trusted_time import (
    DurableTrustedTimeProvider,
    SynchronizationEvidence,
    TrustedTimeUnavailableError,
    UtcObservation,
)


T0 = datetime(2042, 5, 9, 12, 0, tzinfo=timezone.utc)


def observation(second: float, monotonic_ns: int) -> UtcObservation:
    return UtcObservation(
        instant=T0 + timedelta(seconds=second),
        monotonic_ns=monotonic_ns,
        boot_id="boot-aaaaaaaa",
        evidence=SynchronizationEvidence(
            synchronized=True,
            uncertainty=timedelta(milliseconds=10),
            authority="kernel-sync-v1",
        ),
    )


class QueueSource:
    def __init__(self, *values: object) -> None:
        self.values = list(values)

    def observe(self, timeout_seconds: float) -> UtcObservation:
        del timeout_seconds
        if not self.values:
            raise TrustedTimeUnavailableError()
        value = self.values.pop(0)
        if isinstance(value, BaseException):
            raise value
        assert isinstance(value, UtcObservation)
        return value


class ForwardContinuityOrchestrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.path = self.root / "trusted-time.sqlite3"
        DurableTrustedTimeProvider.create(
            self.path, QueueSource(observation(0, 1_000_000_000))
        ).sample()
        self.plan_digest = "a" * 64
        self.strategy_digest = "b" * 64
        self.incident_digest = "c" * 64

    def tearDown(self) -> None:
        self.temp.cleanup()

    def provider(self, *, failure_injector=None) -> DurableTrustedTimeProvider:
        return DurableTrustedTimeProvider(
            self.path,
            QueueSource(observation(4.2, 3_000_000_000)),
            failure_injector=failure_injector,
        )

    def call_transition(self, provider=None):
        persisted: list[bytes] = []
        result = continuity.transition(
            provider or self.provider(),
            action_owned=True,
            plan_digest=self.plan_digest,
            strategy_digest=self.strategy_digest,
            incident_digest=self.incident_digest,
            persist_protected=persisted.append,
        )
        self.assertEqual(len(persisted), 1)
        return result, json.loads(persisted[0].decode("ascii"))

    def test_readiness_is_metadata_only_and_transition_is_explicit(self) -> None:
        ready = continuity.readiness(
            plan_digest=self.plan_digest, strategy_digest=self.strategy_digest
        )
        self.assertEqual(ready["status"], "ready")
        self.assertFalse(ready["opaque_content_read"])
        self.assertFalse(ready["persistent_mutation"])
        contract = continuity.contract()
        self.assertFalse(contract["automatic_startup_transition"])
        self.assertTrue(contract["transition_explicit"])
        with self.assertRaises(continuity.ForwardContinuityRejected):
            continuity.assess(
                self.provider(),
                action_owned=False,
                plan_digest=self.plan_digest,
                strategy_digest=self.strategy_digest,
            )

    def test_commit_persists_protected_binding_before_state_change(self) -> None:
        result, protected = self.call_transition()
        self.assertEqual(result["status"], "committed")
        self.assertEqual(result["state_effect"], "committed")
        self.assertTrue(result["persistent_mutation"])
        self.assertFalse(result["private_content_included"])
        self.assertFalse(protected["content_free_export_allowed"])
        restored = continuity.restore_protected_binding(
            protected,
            plan_digest=self.plan_digest,
            strategy_digest=self.strategy_digest,
        )
        self.assertEqual(restored[0].assessment_digest, result["assessment_digest"])
        self.assertEqual(restored[1].authorization_digest, result["authorization_digest"])

    def test_postcommit_ambiguity_reconciles_without_replay(self) -> None:
        def fail(stage: str) -> None:
            if stage == "transition_after_commit":
                raise RuntimeError("synthetic")

        result, protected = self.call_transition(self.provider(failure_injector=fail))
        self.assertEqual(result["status"], "committed_reconciled")
        self.assertEqual(result["state_effect"], "committed")
        reconciled = continuity.reconcile(
            DurableTrustedTimeProvider(self.path, QueueSource()),
            protected,
            action_owned=True,
            plan_digest=self.plan_digest,
            strategy_digest=self.strategy_digest,
        )
        self.assertEqual(reconciled["status"], "committed")
        self.assertEqual(reconciled["state_effect"], "committed")
        self.assertFalse(reconciled["persistent_mutation"])

    def test_precommit_failure_keeps_old_anchor_and_does_not_replay(self) -> None:
        before = self.path.read_bytes()

        def fail(stage: str) -> None:
            if stage == "transition_before_commit":
                raise RuntimeError("synthetic")

        persisted: list[bytes] = []
        with self.assertRaises(continuity.ForwardContinuityRejected) as caught:
            continuity.transition(
                self.provider(failure_injector=fail),
                action_owned=True,
                plan_digest=self.plan_digest,
                strategy_digest=self.strategy_digest,
                incident_digest=self.incident_digest,
                persist_protected=persisted.append,
            )
        self.assertEqual(caught.exception.code, "transition_precommit_rejected")
        self.assertEqual(caught.exception.state_effect, "none")
        self.assertEqual(self.path.read_bytes(), before)
        reconciled = continuity.reconcile(
            DurableTrustedTimeProvider(self.path, QueueSource()),
            json.loads(persisted[0].decode("ascii")),
            action_owned=True,
            plan_digest=self.plan_digest,
            strategy_digest=self.strategy_digest,
        )
        self.assertEqual(reconciled["status"], "not_committed")
        self.assertEqual(reconciled["state_effect"], "none")

    def test_postcommit_reconcile_failure_is_typed_ambiguous_and_never_replayed(self) -> None:
        def fail(stage: str) -> None:
            if stage == "transition_after_commit":
                raise RuntimeError("synthetic")

        base = self.provider(failure_injector=fail)

        class ReconcileRejectingProvider:
            def assess_continuity(self):
                return base.assess_continuity()

            def transition_forward(self, assessment, authorization):
                return base.transition_forward(assessment, authorization)

            def reconcile_forward_transition(self, assessment, authorization):
                del assessment, authorization
                raise RuntimeError("synthetic private detail")

            def validate_state(self):
                return base.validate_state()

        persisted: list[bytes] = []
        with self.assertRaises(continuity.ForwardContinuityRejected) as caught:
            continuity.transition(
                ReconcileRejectingProvider(),
                action_owned=True,
                plan_digest=self.plan_digest,
                strategy_digest=self.strategy_digest,
                incident_digest=self.incident_digest,
                persist_protected=persisted.append,
            )
        self.assertEqual(caught.exception.code, "transition_reconcile_rejected")
        self.assertEqual(caught.exception.state_effect, "ambiguous")
        self.assertEqual(len(persisted), 1)

    def test_protected_binding_substitution_and_partial_persist_fail_closed(self) -> None:
        persisted: list[bytes] = []

        def reject_persist(raw: bytes) -> None:
            persisted.append(raw)
            raise OSError("synthetic")

        before = self.path.read_bytes()
        with self.assertRaises(OSError):
            continuity.transition(
                self.provider(),
                action_owned=True,
                plan_digest=self.plan_digest,
                strategy_digest=self.strategy_digest,
                incident_digest=self.incident_digest,
                persist_protected=reject_persist,
            )
        self.assertEqual(self.path.read_bytes(), before)
        payload = json.loads(persisted[0].decode("ascii"))
        payload["strategy_digest"] = "d" * 64
        with self.assertRaises(continuity.ForwardContinuityRejected):
            continuity.restore_protected_binding(
                payload,
                plan_digest=self.plan_digest,
                strategy_digest=self.strategy_digest,
            )

    def test_forward_state_validates_and_predecessor_source_remains_compatible(self) -> None:
        self.call_transition()
        next_provider = DurableTrustedTimeProvider(
            self.path, QueueSource(observation(5.2, 4_000_000_000))
        )
        self.assertEqual(next_provider.sample().sequence, 3)
        verified = continuity.validate_forward_state(
            DurableTrustedTimeProvider(self.path, QueueSource())
        )
        self.assertEqual(verified["status"], "valid")
        self.assertFalse(verified["state_bytes_restored"])

        predecessor = Path(
            "/opt/myuna/active-temporal/releases/"
            + continuity.PREDECESSOR_RELEASE_DIGEST
            + "/src"
        )
        self.assertTrue(predecessor.is_dir())
        script = """
from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
from myuna_core.trusted_time import DurableTrustedTimeProvider, SynchronizationEvidence, UtcObservation
class Source:
    def observe(self, timeout_seconds):
        return UtcObservation(instant=datetime(2042,5,9,12,0,tzinfo=timezone.utc)+timedelta(seconds=6.2),monotonic_ns=5_000_000_000,boot_id='boot-aaaaaaaa',evidence=SynchronizationEvidence(synchronized=True,uncertainty=timedelta(milliseconds=10),authority='kernel-sync-v1'))
assert DurableTrustedTimeProvider(Path(os.environ['DB']), Source()).sample().sequence == 4
"""
        environment = {
            "DB": str(self.path),
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(predecessor),
        }
        completed = subprocess.run(
            ["/usr/bin/python3", "-c", script],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )
        self.assertEqual(
            (completed.returncode, completed.stdout, completed.stderr),
            (0, b"", b""),
        )
        connection = sqlite3.connect(self.path)
        self.assertEqual(
            connection.execute("SELECT COUNT(*) FROM continuity_anchor_history").fetchone()[0],
            1,
        )
        connection.close()


if __name__ == "__main__":
    unittest.main()
