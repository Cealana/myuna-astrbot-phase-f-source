from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from threading import Lock
import unittest

from myuna_core.trusted_time import (
    DurableTrustedTimeProvider,
    ForwardContinuityAuthorization,
    SynchronizationEvidence,
    TrustedTimeContinuityIneligibleError,
    TrustedTimePersistenceAmbiguousError,
    TrustedTimeSourceDriftError,
    TrustedTimeStateCorruptError,
    TrustedTimeTransitionExpiredError,
    TrustedTimeTransitionRejectedError,
    TrustedTimeTransitionReplayError,
    TrustedTimeUnavailableError,
    TrustedTimeUncertainError,
    TrustedTimeUnsynchronizedError,
    TrustedTimeWatermark,
    UtcObservation,
)


T0 = datetime(2042, 5, 9, 12, 0, tzinfo=timezone.utc)
AUTHORITY = "kernel-sync-v1"
BOOT_A = "boot-aaaaaaaa"
BOOT_B = "boot-bbbbbbbb"
SOURCE_CONTRACT = "a" * 64
SOURCE_EVIDENCE = "b" * 64
LINEAGE = "c" * 64
AUTHORIZATION_IDENTITY = "d" * 64


def observation(
    second: float,
    monotonic_ns: int,
    *,
    boot_id: str = BOOT_A,
    authority: str = AUTHORITY,
    synchronized: bool = True,
    uncertainty_ms: int = 10,
) -> UtcObservation:
    return UtcObservation(
        instant=T0 + timedelta(seconds=second),
        monotonic_ns=monotonic_ns,
        boot_id=boot_id,
        evidence=SynchronizationEvidence(
            synchronized=synchronized,
            uncertainty=timedelta(milliseconds=uncertainty_ms),
            authority=authority,
        ),
    )


class QueueSource:
    def __init__(self, *values: object) -> None:
        self.values = list(values)
        self.lock = Lock()

    def observe(self, timeout_seconds: float) -> UtcObservation:
        with self.lock:
            if not self.values:
                raise TrustedTimeUnavailableError()
            value = self.values.pop(0)
        if isinstance(value, BaseException):
            raise value
        assert isinstance(value, UtcObservation)
        return value


class MonotonicClock:
    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class ForwardContinuityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.path = self.root / "trusted-time.sqlite3"
        self.clock = MonotonicClock(10_000_000_000)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def create(self, source: QueueSource, **kwargs: object) -> DurableTrustedTimeProvider:
        return DurableTrustedTimeProvider.create(
            self.path,
            source,
            transition_monotonic_ns=self.clock,
            **kwargs,
        )

    def reopen(self, source: QueueSource, **kwargs: object) -> DurableTrustedTimeProvider:
        return DurableTrustedTimeProvider(
            self.path,
            source,
            transition_monotonic_ns=self.clock,
            **kwargs,
        )

    @staticmethod
    def authorization(assessment, transition_id: str = "transition-0001", **kwargs):
        tolerance = kwargs.pop("residual_tolerance_microseconds", 50_000)
        max_age = kwargs.pop("max_age_seconds", 60)
        return ForwardContinuityAuthorization.bind(
            assessment,
            transition_id=transition_id,
            source_contract_digest=SOURCE_CONTRACT,
            source_evidence_digest=SOURCE_EVIDENCE,
            lineage_digest=LINEAGE,
            authorization_identity_digest=AUTHORIZATION_IDENTITY,
            residual_tolerance_microseconds=tolerance,
            max_age_seconds=max_age,
            **kwargs,
        )

    def seed(self, *, second: float = 0, monotonic_ns: int = 1_000_000_000) -> None:
        sample = self.create(QueueSource(observation(second, monotonic_ns))).sample()
        self.assertEqual(sample.sequence, 1)

    def assess_forward(self, *, second: float = 4.2, monotonic_ns: int = 3_000_000_000):
        return self.reopen(QueueSource(observation(second, monotonic_ns))).assess_continuity()

    def test_read_only_assessment_is_repeatable_content_free_and_does_not_mutate(self) -> None:
        self.seed()
        before = sha256(self.path.read_bytes()).hexdigest()
        first = self.assess_forward()
        middle = sha256(self.path.read_bytes()).hexdigest()
        second = self.assess_forward()
        after = sha256(self.path.read_bytes()).hexdigest()

        self.assertEqual((before, middle, after), (before, before, before))
        self.assertEqual(first.public_payload(), second.public_payload())
        self.assertEqual(first.status, "forward_transition_required")
        self.assertEqual(first.continuity, "same_boot")
        self.assertEqual(first.eligibility, "explicit_forward_transition")
        self.assertEqual(first.direction, "forward")
        self.assertFalse(first.persistent_mutation)
        payload = first.public_payload()
        for forbidden in (
            "instant",
            "sequence",
            "monotonic_ns",
            "boot_id",
            "authority",
            "path",
            "residual_microseconds",
        ):
            self.assertNotIn(forbidden, payload)
            self.assertNotIn(forbidden, repr(first))

    def test_within_threshold_and_boot_transition_remain_ordinary_sample_paths(self) -> None:
        self.seed()
        within = self.reopen(
            QueueSource(observation(3.9, 3_000_000_000))
        ).assess_continuity()
        self.assertEqual(
            (within.status, within.continuity, within.eligibility),
            ("within_policy", "same_boot", "ordinary_sample"),
        )
        with self.assertRaises(TrustedTimeContinuityIneligibleError):
            self.authorization(within)

        rebooted = self.reopen(
            QueueSource(observation(1, 1, boot_id=BOOT_B))
        ).assess_continuity()
        self.assertEqual(
            (rebooted.status, rebooted.continuity, rebooted.eligibility),
            ("within_policy", "boot_transition", "ordinary_sample"),
        )

        sample = self.reopen(QueueSource(observation(1.9, 3_000_000_000))).sample()
        self.assertEqual(sample.sequence, 2)

    def test_backward_or_mixed_continuity_is_ineligible(self) -> None:
        self.seed(second=10, monotonic_ns=1_000_000_000)
        with self.assertRaises(TrustedTimeContinuityIneligibleError):
            self.reopen(
                QueueSource(observation(11, 5_000_000_000))
            ).assess_continuity()

    def test_assessment_sync_and_uncertainty_rejections_do_not_mutate(self) -> None:
        self.seed()
        before = sha256(self.path.read_bytes()).hexdigest()
        with self.assertRaises(TrustedTimeUnsynchronizedError):
            self.reopen(
                QueueSource(observation(4.2, 3_000_000_000, synchronized=False))
            ).assess_continuity()
        with self.assertRaises(TrustedTimeUncertainError):
            self.reopen(
                QueueSource(observation(4.2, 3_000_000_000, uncertainty_ms=1001))
            ).assess_continuity()
        self.assertEqual(sha256(self.path.read_bytes()).hexdigest(), before)
        with self.assertRaises(TrustedTimeSourceDriftError):
            self.reopen(
                QueueSource(observation(14.2, 3_000_000_000, authority="other-authority"))
            ).assess_continuity()

    def test_successful_transition_advances_once_and_preserves_old_anchor(self) -> None:
        self.seed()
        assessment = self.assess_forward()
        authorization = self.authorization(assessment)
        receipt = self.reopen(QueueSource()).transition_forward(
            assessment,
            authorization,
        )

        self.assertEqual(receipt.status, "committed")
        self.assertTrue(receipt.persistent_mutation)
        self.assertEqual(receipt.sequence_relation, "strictly_advanced")
        self.assertNotIn("sequence", receipt.public_payload())
        self.assertNotIn("instant", receipt.public_payload())

        connection = sqlite3.connect(self.path)
        history_payload = json.loads(
            connection.execute(
                "SELECT payload FROM continuity_anchor_history"
            ).fetchone()[0]
        )
        old = history_payload["anchor"]
        current = connection.execute(
            "SELECT sequence, instant, monotonic_ns, boot_id FROM clock_state WHERE singleton=1"
        ).fetchone()
        transition_count = connection.execute(
            "SELECT value FROM metadata WHERE key='continuity_transition_count'"
        ).fetchone()[0]
        connection.close()
        self.assertEqual(
            (
                old["sequence"],
                old["instant"],
                old["monotonic_ns"],
                old["boot_id"],
            ),
            (1, T0.isoformat(timespec="microseconds"), 1_000_000_000, BOOT_A),
        )
        self.assertEqual(
            current,
            (
                2,
                (T0 + timedelta(seconds=4.2)).isoformat(timespec="microseconds"),
                3_000_000_000,
                BOOT_A,
            ),
        )
        self.assertEqual(transition_count, "1")

        next_sample = self.reopen(
            QueueSource(observation(5.2, 4_000_000_000))
        ).sample()
        self.assertEqual(next_sample.sequence, 3)
        self.reopen(QueueSource()).validate_state()

    def test_consumer_watermark_is_a_strict_sequence_and_instant_floor(self) -> None:
        self.seed()
        watermark = TrustedTimeWatermark(
            source="myuna-trusted-local-v1",
            sequence=7,
            instant=T0 + timedelta(seconds=1),
        )
        assessment = self.reopen(
            QueueSource(observation(4.2, 3_000_000_000)),
            consumer_watermark=watermark,
        ).assess_continuity()
        receipt = self.reopen(
            QueueSource(),
            consumer_watermark=watermark,
        ).transition_forward(assessment, self.authorization(assessment))
        self.assertEqual(receipt.sequence_relation, "strictly_advanced")
        connection = sqlite3.connect(self.path)
        sequence, instant = connection.execute(
            "SELECT sequence, instant FROM clock_state WHERE singleton=1"
        ).fetchone()
        connection.close()
        self.assertEqual(sequence, 8)
        self.assertGreaterEqual(datetime.fromisoformat(instant), watermark.instant)

    def test_before_commit_failure_rolls_back_exactly_and_reconciles_not_committed(self) -> None:
        self.seed()
        assessment = self.assess_forward()
        authorization = self.authorization(assessment)
        before = sha256(self.path.read_bytes()).hexdigest()

        for failure_stage in ("transition_after_history", "transition_before_commit"):
            with self.subTest(failure_stage=failure_stage):
                def fail(phase: str) -> None:
                    if phase == failure_stage:
                        raise RuntimeError("synthetic crash")

                with self.assertRaises(TrustedTimeUnavailableError):
                    self.reopen(QueueSource(), failure_injector=fail).transition_forward(
                        assessment,
                        authorization,
                    )
                self.assertEqual(sha256(self.path.read_bytes()).hexdigest(), before)
        reconciled = self.reopen(QueueSource()).reconcile_forward_transition(
            assessment,
            authorization,
        )
        self.assertEqual(reconciled.status, "not_committed")
        self.assertFalse(reconciled.persistent_mutation)

    def test_after_commit_ambiguity_reconciles_committed_and_replay_fails(self) -> None:
        self.seed()
        assessment = self.assess_forward()
        authorization = self.authorization(assessment)

        def fail(phase: str) -> None:
            if phase == "transition_after_commit":
                raise RuntimeError("synthetic lost receipt")

        with self.assertRaises(TrustedTimePersistenceAmbiguousError):
            self.reopen(QueueSource(), failure_injector=fail).transition_forward(
                assessment,
                authorization,
            )
        reconciled = self.reopen(QueueSource()).reconcile_forward_transition(
            assessment,
            authorization,
        )
        self.assertEqual(reconciled.status, "committed")
        with self.assertRaises(TrustedTimeTransitionReplayError):
            self.reopen(QueueSource()).transition_forward(assessment, authorization)

    def test_concurrent_same_anchor_has_exactly_one_commit(self) -> None:
        self.seed()
        assessment = self.assess_forward()
        authorization = self.authorization(assessment)
        providers = [self.reopen(QueueSource()) for _ in range(8)]

        def transition(provider):
            try:
                return provider.transition_forward(assessment, authorization).status
            except (TrustedTimeTransitionReplayError, TrustedTimeTransitionRejectedError):
                return "rejected"

        with ThreadPoolExecutor(max_workers=8) as executor:
            outcomes = list(executor.map(transition, providers))
        self.assertEqual(outcomes.count("committed"), 1)
        self.assertEqual(outcomes.count("rejected"), 7)

    def test_expiry_and_assessment_or_authorization_substitution_fail_closed(self) -> None:
        self.seed()
        assessment = self.assess_forward()
        authorization = self.authorization(assessment, max_age_seconds=1)
        self.clock.value += 2_000_000_000
        with self.assertRaises(TrustedTimeTransitionExpiredError):
            self.reopen(QueueSource()).transition_forward(assessment, authorization)

        self.clock.value = 10_000_000_000
        substituted_assessment = replace(assessment, evidence_digest="e" * 64)
        with self.assertRaises(TrustedTimeTransitionRejectedError):
            self.reopen(QueueSource()).transition_forward(
                substituted_assessment,
                self.authorization(assessment, transition_id="transition-0002"),
            )
        substituted_authorization = replace(
            self.authorization(assessment, transition_id="transition-0003"),
            assessment_digest="f" * 64,
        )
        with self.assertRaises(TrustedTimeTransitionRejectedError):
            self.reopen(QueueSource()).transition_forward(
                assessment,
                substituted_authorization,
            )
        substituted_residual = replace(
            assessment,
            _signed_residual_microseconds=assessment._signed_residual_microseconds + 1,
        )
        with self.assertRaises(TrustedTimeTransitionRejectedError):
            self.reopen(QueueSource()).transition_forward(
                substituted_residual,
                self.authorization(
                    substituted_residual,
                    transition_id="transition-0004",
                ),
            )
        substituted_clock = replace(
            assessment,
            _assessed_monotonic_ns=assessment._assessed_monotonic_ns + 1,
        )
        with self.assertRaises(TrustedTimeTransitionRejectedError):
            self.reopen(QueueSource()).transition_forward(
                substituted_clock,
                self.authorization(
                    substituted_clock,
                    transition_id="transition-0005",
                ),
            )

    def test_history_chain_is_append_only_and_truncation_fails_validation(self) -> None:
        self.seed()
        first_assessment = self.assess_forward()
        first_receipt = self.reopen(QueueSource()).transition_forward(
            first_assessment,
            self.authorization(first_assessment, transition_id="transition-0001"),
        )
        second_assessment = self.reopen(
            QueueSource(observation(8.5, 5_000_000_000))
        ).assess_continuity()
        second_receipt = self.reopen(QueueSource()).transition_forward(
            second_assessment,
            self.authorization(second_assessment, transition_id="transition-0002"),
        )

        connection = sqlite3.connect(self.path)
        rows = connection.execute(
            "SELECT history_id, prior_history_head, record_digest "
            "FROM continuity_anchor_history ORDER BY history_id"
        ).fetchall()
        head = connection.execute(
            "SELECT value FROM metadata WHERE key='continuity_transition_head'"
        ).fetchone()[0]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1][1], first_receipt.transition_digest)
        self.assertEqual(head, second_receipt.transition_digest)
        connection.execute("DELETE FROM continuity_anchor_history WHERE history_id=1")
        connection.commit()
        connection.close()
        with self.assertRaises(TrustedTimeStateCorruptError):
            self.reopen(QueueSource())

    def test_partial_transition_residue_is_never_treated_as_legacy_state(self) -> None:
        self.seed()
        connection = sqlite3.connect(self.path)
        connection.execute("CREATE TABLE continuity_anchor_history (synthetic TEXT) STRICT")
        connection.commit()
        connection.close()
        with self.assertRaises(TrustedTimeStateCorruptError):
            self.reopen(QueueSource())

    def test_transition_is_explicit_max_one_and_not_wired_into_consumer_runtime(self) -> None:
        self.seed()
        assessment = self.assess_forward()
        authorization = self.authorization(assessment)
        self.assertEqual(authorization.max_attempts, 1)
        payload = authorization.public_payload()
        self.assertEqual(payload["direction"], "forward")
        for forbidden in (
            "instant",
            "sequence",
            "monotonic_ns",
            "boot_id",
            "authority",
            "residual_lower_microseconds",
            "residual_upper_microseconds",
        ):
            self.assertNotIn(forbidden, payload)

        source_root = Path(__file__).parents[1] / "src" / "myuna_core"
        consumer = "\n".join(
            (source_root / "active_temporal_context" / name).read_text(encoding="utf-8")
            for name in ("runtime.py", "service.py")
        )
        self.assertNotIn("transition_forward", consumer)
        self.assertNotIn("assess_continuity", consumer)
        trusted_source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (source_root / "trusted_time").glob("*.py")
        )
        for forbidden in (
            "import socket",
            "import subprocess",
            "owner_profile",
            "session_context",
            "relevance_selector",
            "os.environ",
        ):
            self.assertNotIn(forbidden, trusted_source)


if __name__ == "__main__":
    unittest.main()
