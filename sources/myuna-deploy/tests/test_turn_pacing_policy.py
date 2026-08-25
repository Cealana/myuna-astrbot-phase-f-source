from __future__ import annotations

import unittest

from scripts.turn_pacing_policy import BoundedTurnPacingPolicy, TurnPacingRejected


class TurnPacingPolicyTests(unittest.TestCase):
    def test_a15_normal_pacing_is_bounded_and_cancellable(self) -> None:
        policy = BoundedTurnPacingPolicy(maximum_delay_seconds=8.0)
        plan = policy.plan(requested_delay_seconds=60.0)
        self.assertEqual(plan.delay_seconds, 8.0)
        self.assertTrue(plan.cancellable)
        self.assertIsNone(plan.bypass_reason)
        cancelled = policy.plan(requested_delay_seconds=8.0, cancelled=True)
        self.assertEqual(cancelled.delay_seconds, 0.0)
        self.assertEqual(cancelled.bypass_reason, "cancelled")

    def test_a15_errors_and_recovery_notices_bypass_pacing(self) -> None:
        policy = BoundedTurnPacingPolicy(maximum_delay_seconds=8.0)
        error = policy.plan(requested_delay_seconds=8.0, is_error=True)
        recovery = policy.plan(
            requested_delay_seconds=8.0,
            is_recovery_notice=True,
        )
        self.assertEqual(error.delay_seconds, 0.0)
        self.assertEqual(recovery.delay_seconds, 0.0)
        self.assertEqual(error.bypass_reason, "error")
        self.assertEqual(recovery.bypass_reason, "recovery_notice")

    def test_a15_non_finite_or_non_numeric_delays_are_rejected(self) -> None:
        policy = BoundedTurnPacingPolicy(maximum_delay_seconds=8.0)
        for value in (float("nan"), float("inf"), True, "8"):
            with self.subTest(value=value):
                with self.assertRaises(TurnPacingRejected):
                    policy.plan(requested_delay_seconds=value)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
