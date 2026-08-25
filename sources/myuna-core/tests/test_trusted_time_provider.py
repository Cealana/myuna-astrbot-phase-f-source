from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from threading import Lock
import unittest

from myuna_core.active_temporal_context.time import TrustedTimeGuard, TrustedTimePort
from myuna_core.capability_runtime import CapabilityLifecyclePort, CapabilityLifecycleState
from myuna_core.trusted_time import (
    DurableTrustedTimeProvider,
    SynchronizationEvidence,
    SystemUtcObservationSource,
    TrustedTimeAuditEvent,
    TrustedTimeAuditUnavailableError,
    TrustedTimeCapability,
    TrustedTimeDriftError,
    TrustedTimePersistenceAmbiguousError,
    TrustedTimePolicy,
    TrustedTimeRegressionError,
    TrustedTimeSourceDriftError,
    TrustedTimeStateCorruptError,
    TrustedTimeStatePermissionError,
    TrustedTimeTimeoutError,
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


def observation(
    second: float,
    sequence_ns: int,
    *,
    boot_id: str = BOOT_A,
    synchronized: bool = True,
    uncertainty_ms: int = 10,
    authority: str = AUTHORITY,
) -> UtcObservation:
    return UtcObservation(
        instant=T0 + timedelta(seconds=second),
        monotonic_ns=sequence_ns,
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
        self.last_timeout = timeout_seconds
        with self.lock:
            if not self.values:
                raise TrustedTimeUnavailableError()
            value = self.values.pop(0)
        if isinstance(value, BaseException):
            raise value
        assert isinstance(value, UtcObservation)
        return value


class AuditSink:
    def __init__(self, *, fail: bool = False) -> None:
        self.events: list[TrustedTimeAuditEvent] = []
        self.fail = fail

    def emit(self, event: TrustedTimeAuditEvent) -> None:
        if self.fail:
            raise RuntimeError("synthetic private detail")
        self.events.append(event)


class TrustedTimeProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.parent = Path(self.temp.name)
        self.parent.chmod(0o700)
        self.path = self.parent / "trusted-time.sqlite3"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def create(
        self,
        source: QueueSource,
        **kwargs: object,
    ) -> DurableTrustedTimeProvider:
        return DurableTrustedTimeProvider.create(self.path, source, **kwargs)

    def reopen(
        self,
        source: QueueSource,
        **kwargs: object,
    ) -> DurableTrustedTimeProvider:
        return DurableTrustedTimeProvider(self.path, source, **kwargs)

    def test_normal_sampling_is_utc_monotonic_and_p08_compatible(self) -> None:
        sink = AuditSink()
        provider = self.create(
            QueueSource(
                observation(0, 1_000_000_000),
                observation(1, 2_000_000_000),
            ),
            audit_sink=sink,
        )

        first = provider.sample()
        second = provider.sample()
        guard = TrustedTimeGuard()
        guard.accept(first)
        guard.accept(second)

        self.assertIsInstance(provider, TrustedTimePort)
        self.assertEqual((first.sequence, second.sequence), (1, 2))
        self.assertEqual(second.instant.tzinfo, timezone.utc)
        self.assertEqual([event.outcome for event in sink.events], ["accepted", "accepted"])
        payload = sink.events[-1].public_payload()
        self.assertEqual(payload["continuity"], "same_boot")
        for forbidden in ("instant", "sequence", "path", "boot_id", "identity"):
            self.assertNotIn(forbidden, payload)

    def test_offset_observation_normalizes_and_naive_time_fails_closed(self) -> None:
        offset = timezone(timedelta(hours=8))
        normalized = UtcObservation(
            instant=datetime(2042, 5, 9, 20, 0, tzinfo=offset),
            monotonic_ns=1,
            boot_id=BOOT_A,
            evidence=SynchronizationEvidence(True, timedelta(milliseconds=1), AUTHORITY),
        )
        self.assertEqual(normalized.instant, T0)
        with self.assertRaises(TrustedTimeStateCorruptError):
            UtcObservation(
                instant=datetime(2042, 5, 9, 12, 0),
                monotonic_ns=1,
                boot_id=BOOT_A,
                evidence=SynchronizationEvidence(
                    True, timedelta(milliseconds=1), AUTHORITY
                ),
            )

    def test_unsynchronized_uncertain_unavailable_and_timeout_fail_closed(self) -> None:
        cases = (
            (
                observation(0, 1, synchronized=False),
                TrustedTimeUnsynchronizedError,
            ),
            (observation(0, 1, uncertainty_ms=1001), TrustedTimeUncertainError),
            (TrustedTimeUnavailableError(), TrustedTimeUnavailableError),
            (TrustedTimeTimeoutError(), TrustedTimeTimeoutError),
        )
        for index, (value, expected) in enumerate(cases):
            with self.subTest(index=index):
                path = self.parent / f"case-{index}.sqlite3"
                provider = DurableTrustedTimeProvider.create(path, QueueSource(value))
                with self.assertRaises(expected):
                    provider.sample()
                retry = DurableTrustedTimeProvider(
                    path, QueueSource(observation(0, 2))
                ).sample()
                self.assertEqual(retry.sequence, 1)

    def test_same_boot_regression_and_drift_do_not_advance_state(self) -> None:
        provider = self.create(
            QueueSource(
                observation(10, 10_000_000_000),
                observation(9, 11_000_000_000),
            )
        )
        self.assertEqual(provider.sample().sequence, 1)
        with self.assertRaises(TrustedTimeRegressionError):
            provider.sample()
        drifted = self.reopen(
            QueueSource(observation(20, 11_000_000_000))
        )
        with self.assertRaises(TrustedTimeDriftError):
            drifted.sample()
        recovered = self.reopen(
            QueueSource(observation(11, 11_000_000_000))
        ).sample()
        self.assertEqual(recovered.sequence, 2)

    def test_restart_and_consumer_watermark_advance_strictly(self) -> None:
        first = self.create(QueueSource(observation(10, 10, boot_id=BOOT_A))).sample()
        restarted = self.reopen(
            QueueSource(observation(11, 1, boot_id=BOOT_B)),
            consumer_watermark=TrustedTimeWatermark(
                source=first.source,
                sequence=7,
                instant=T0 + timedelta(seconds=10),
            ),
        ).sample()
        self.assertEqual(restarted.sequence, 8)
        self.assertGreaterEqual(restarted.instant, first.instant)

        with self.assertRaises(TrustedTimeRegressionError):
            self.reopen(
                QueueSource(observation(9, 2, boot_id="boot-cccccccc")),
                consumer_watermark=TrustedTimeWatermark(
                    source=first.source,
                    sequence=8,
                    instant=restarted.instant,
                ),
            ).sample()

    def test_consumer_source_and_observation_authority_drift_fail_closed(self) -> None:
        policy = TrustedTimePolicy()
        with self.assertRaises(TrustedTimeSourceDriftError):
            self.create(
                QueueSource(observation(0, 1)),
                consumer_watermark=TrustedTimeWatermark(
                    source="other-source",
                    sequence=1,
                    instant=T0,
                ),
            )
        provider = self.create(QueueSource(observation(0, 1)))
        provider.sample()
        with self.assertRaises(TrustedTimeSourceDriftError):
            self.reopen(
                QueueSource(observation(1, 2, authority="different-authority")),
                policy=policy,
            ).sample()

    def test_before_commit_rollback_and_after_commit_ambiguity_are_safe(self) -> None:
        def before(phase: str) -> None:
            if phase == "before_commit":
                raise RuntimeError("synthetic crash")

        provider = self.create(
            QueueSource(observation(0, 1)), failure_injector=before
        )
        with self.assertRaises(TrustedTimeUnavailableError):
            provider.sample()
        self.assertEqual(
            self.reopen(QueueSource(observation(0, 2))).sample().sequence,
            1,
        )

        def after(phase: str) -> None:
            if phase == "after_commit":
                raise RuntimeError("synthetic lost response")

        ambiguous = self.reopen(
            QueueSource(observation(1, 1_000_000_002)),
            failure_injector=after,
        )
        with self.assertRaises(TrustedTimePersistenceAmbiguousError):
            ambiguous.sample()
        next_sample = self.reopen(
            QueueSource(observation(2, 2_000_000_002))
        ).sample()
        self.assertEqual(next_sample.sequence, 3)

    def test_corrupt_schema_permissions_and_symlink_fail_closed(self) -> None:
        with self.assertRaises(TrustedTimeStatePermissionError):
            DurableTrustedTimeProvider.create(
                Path("relative.sqlite3"), QueueSource(observation(0, 1))
            )
        self.create(QueueSource(observation(0, 1)))
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA user_version=99")
        connection.close()
        with self.assertRaises(TrustedTimeStateCorruptError):
            self.reopen(QueueSource(observation(0, 1)))

        other = self.parent / "permission.sqlite3"
        DurableTrustedTimeProvider.create(other, QueueSource(observation(0, 1)))
        other.chmod(0o644)
        with self.assertRaises(TrustedTimeStatePermissionError):
            DurableTrustedTimeProvider(other, QueueSource(observation(0, 1)))

        target = self.parent / "target"
        target.write_text("synthetic", encoding="utf-8")
        link = self.parent / "link.sqlite3"
        link.symlink_to(target)
        with self.assertRaises(TrustedTimeStatePermissionError):
            DurableTrustedTimeProvider(link, QueueSource(observation(0, 1)))

    def test_concurrent_providers_allocate_unique_sequences(self) -> None:
        values = [observation(index, index * 1_000_000_000) for index in range(8)]
        source = QueueSource(*values)
        self.create(source)
        providers = [self.reopen(source) for _ in range(8)]
        with ThreadPoolExecutor(max_workers=8) as executor:
            samples = list(executor.map(lambda item: item.sample(), providers))
        self.assertEqual(sorted(sample.sequence for sample in samples), list(range(1, 9)))

    def test_audit_failure_returns_no_sample_and_exposes_no_detail(self) -> None:
        provider = self.create(
            QueueSource(observation(0, 1)), audit_sink=AuditSink(fail=True)
        )
        with self.assertRaises(TrustedTimeAuditUnavailableError) as raised:
            provider.sample()
        self.assertEqual(
            self.reopen(
                QueueSource(observation(1, 1_000_000_001))
            ).sample().sequence,
            2,
        )
        self.assertEqual(
            raised.exception.public_payload(),
            {"code": "trusted_time_audit_unavailable", "retryable": True},
        )

    def test_busy_timeout_returns_no_sample_or_state_advance(self) -> None:
        self.create(QueueSource(observation(0, 1)))
        lock = sqlite3.connect(self.path, isolation_level=None)
        lock.execute("BEGIN IMMEDIATE")
        try:
            with self.assertRaises(TrustedTimeTimeoutError):
                self.reopen(QueueSource(observation(0, 1))).sample()
        finally:
            lock.rollback()
            lock.close()
        self.assertEqual(self.reopen(QueueSource(observation(0, 1))).sample().sequence, 1)

    def test_system_source_requires_explicit_sync_evidence_and_honors_timeout(self) -> None:
        source = SystemUtcObservationSource(
            lambda timeout: SynchronizationEvidence(
                True, timedelta(milliseconds=5), AUTHORITY
            ),
            now=lambda: T0,
            monotonic_ns=lambda: 42,
            boot_id_reader=lambda: BOOT_A,
            elapsed=iter((10.0, 10.5)).__next__,
        )
        observed = source.observe(1.0)
        self.assertEqual(observed.instant, T0)
        slow = SystemUtcObservationSource(
            lambda timeout: SynchronizationEvidence(
                True, timedelta(milliseconds=5), AUTHORITY
            ),
            now=lambda: T0,
            monotonic_ns=lambda: 42,
            boot_id_reader=lambda: BOOT_A,
            elapsed=iter((10.0, 12.0)).__next__,
        )
        with self.assertRaises(TrustedTimeTimeoutError):
            slow.observe(1.0)

    def test_capability_lifecycle_fails_closed_and_recovers(self) -> None:
        provider = self.create(
            QueueSource(
                TrustedTimeUnavailableError(),
                observation(0, 1),
            )
        )
        capability = TrustedTimeCapability(provider)
        self.assertIsInstance(capability, CapabilityLifecyclePort)
        self.assertIsInstance(capability, TrustedTimePort)
        with self.assertRaises(TrustedTimeUnavailableError):
            capability.sample()
        self.assertEqual(capability.startup().state, CapabilityLifecycleState.READY)
        with self.assertRaises(TrustedTimeUnavailableError):
            capability.sample()
        self.assertEqual(
            capability.lifecycle_snapshot().state,
            CapabilityLifecycleState.DEGRADED,
        )
        self.assertEqual(capability.recover().state, CapabilityLifecycleState.READY)
        self.assertEqual(capability.sample().sequence, 1)

    def test_source_has_no_channel_content_network_or_cross_layer_write(self) -> None:
        root = Path(__file__).parents[1] / "src" / "myuna_core" / "trusted_time"
        text = "\n".join(path.read_text(encoding="utf-8") for path in root.glob("*.py"))
        for forbidden in (
            "import aiohttp",
            "import httpx",
            "import requests",
            "import socket",
            "import subprocess",
            "owner_profile",
            "session_context",
            "relevance_selector",
        ):
            self.assertNotIn(forbidden, text)
        self.assertNotIn("os.environ", text)
        self.assertNotIn("datetime.now()", text)


if __name__ == "__main__":
    unittest.main()
