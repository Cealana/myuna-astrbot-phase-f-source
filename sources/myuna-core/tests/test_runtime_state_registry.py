from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from myuna_core.runtime_state import (
    CheckHandler,
    RuntimeStateError,
    RuntimeStateRegistry,
    RuntimeStateStatus,
    RuntimeStateValue,
)


class RuntimeStateRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 7, 26, 15, 0, tzinfo=timezone.utc)

    def test_unknown_check_is_explicit_and_model_free(self) -> None:
        result = CheckHandler(RuntimeStateRegistry()).render(
            subject="MYUNA",
            category="姿势",
        )
        self.assertIs(result.status, RuntimeStateStatus.UNKNOWN)
        self.assertIn("当前状态：未知", result.text)
        self.assertIn("数据来源：Runtime State Registry / unavailable", result.text)
        self.assertNotIn("Myuna:", result.text)
        self.assertNotIn("*", result.text)

    def test_current_check_preserves_source_time_and_confidence(self) -> None:
        value = RuntimeStateValue(
            subject="MYUNA",
            category="模块",
            key="记忆读取",
            value=True,
            status=RuntimeStateStatus.CURRENT,
            source="Capability Manifest",
            observed_at=self.now,
            confidence=1.0,
            expires_at=self.now + timedelta(minutes=5),
        )
        result = CheckHandler(RuntimeStateRegistry((value,))).render(
            subject="MYUNA",
            category="模块",
        )
        self.assertIn("记忆读取：True", result.text)
        self.assertIn(self.now.isoformat(), result.text)
        self.assertIn("Capability Manifest", result.text)
        self.assertIn("可信度：1.00", result.text)

    def test_unknown_value_cannot_claim_data(self) -> None:
        with self.assertRaises(RuntimeStateError):
            RuntimeStateValue(
                subject="MYUNA",
                category="环境",
                key="天气",
                value="晴",
                status=RuntimeStateStatus.UNKNOWN,
                source="none",
                observed_at=None,
                confidence=0.0,
            )

    def test_duplicate_state_key_fails_closed(self) -> None:
        value = RuntimeStateValue(
            subject="MYUNA",
            category="模块",
            key="Core",
            value="healthy",
            status=RuntimeStateStatus.CURRENT,
            source="healthz",
            observed_at=self.now,
            confidence=1.0,
        )
        with self.assertRaises(RuntimeStateError):
            RuntimeStateRegistry((value, value))

    def test_last_known_only_result_is_not_reported_as_current(self) -> None:
        value = RuntimeStateValue(
            subject="MYUNA",
            category="模块",
            key="Core",
            value="healthy-at-last-observation",
            status=RuntimeStateStatus.LAST_KNOWN,
            source="healthz",
            observed_at=self.now,
            confidence=0.8,
        )
        result = CheckHandler(RuntimeStateRegistry((value,))).render(
            subject="MYUNA",
            category="模块",
        )
        self.assertIs(result.status, RuntimeStateStatus.LAST_KNOWN)

    def test_runtime_times_must_be_timezone_aware(self) -> None:
        with self.assertRaises(RuntimeStateError):
            RuntimeStateValue(
                subject="MYUNA",
                category="模块",
                key="Core",
                value="healthy",
                status=RuntimeStateStatus.CURRENT,
                source="healthz",
                observed_at=datetime(2026, 7, 26, 15, 0),
                confidence=1.0,
            )


if __name__ == "__main__":
    unittest.main()
