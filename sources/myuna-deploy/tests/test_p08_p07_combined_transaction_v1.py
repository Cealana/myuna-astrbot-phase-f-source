from __future__ import annotations

import unittest

from p08_p07_combined_transaction_v1 import (
    CombinedReleaseSetTransaction,
    CombinedTransactionRejected,
)


class TypedFailure(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class FakeBackend:
    def __init__(self, fail_phase: str | None = None, rollback_fail: str | None = None) -> None:
        self.fail_phase = fail_phase
        self.rollback_fail = rollback_fail
        self.events: list[str] = []
        self.prestate = "a" * 64

    def _apply(self, phase: str) -> None:
        self.events.append(f"apply:{phase}")
        if self.fail_phase == phase:
            raise TypedFailure(f"{phase}_synthetic_failure")

    def _rollback(self, phase: str) -> None:
        self.events.append(f"rollback:{phase}")
        if self.rollback_fail == phase:
            raise TypedFailure(f"{phase}_synthetic_rollback_failure")

    def capture_prestate(self) -> str:
        self.events.append("capture")
        return self.prestate

    def verify_preflight(self, prestate_digest: str) -> None:
        self.events.append("preflight")
        if self.fail_phase == "preflight":
            raise TypedFailure("preflight_synthetic_failure")
        if prestate_digest != self.prestate:
            raise TypedFailure("prestate_drifted")

    def apply_p07(self) -> None:
        self._apply("p07")

    def apply_telegram_plugin(self) -> None:
        self._apply("telegram_plugin")

    def apply_p08(self) -> None:
        self._apply("p08")

    def observe_target(self) -> str:
        self.events.append("observe:target")
        if self.fail_phase == "acceptance":
            raise TypedFailure("target_acceptance_failed")
        return "b" * 64

    def rollback_p08(self) -> None:
        self._rollback("p08")

    def rollback_telegram_plugin(self) -> None:
        self._rollback("telegram_plugin")

    def rollback_p07(self) -> None:
        self._rollback("p07")

    def observe_prestate(self, expected_digest: str) -> str:
        self.events.append("observe:prestate")
        return expected_digest


class CombinedTransactionTests(unittest.TestCase):
    def test_success_applies_exact_order(self) -> None:
        backend = FakeBackend()
        result = CombinedReleaseSetTransaction(
            backend,
            combined_release_set_id="c" * 64,
        ).run()
        self.assertEqual(result.apply_order, ("p07", "telegram_plugin", "p08"))
        self.assertEqual(result.rollback_order, ("p08", "telegram_plugin", "p07"))
        self.assertEqual(
            backend.events,
            [
                "capture",
                "preflight",
                "apply:p07",
                "apply:telegram_plugin",
                "apply:p08",
                "observe:target",
            ],
        )

    def test_each_partial_failure_rolls_back_all_attempted_phases_in_reverse(self) -> None:
        expected = {
            "p07": ["rollback:p07"],
            "telegram_plugin": ["rollback:telegram_plugin", "rollback:p07"],
            "p08": ["rollback:p08", "rollback:telegram_plugin", "rollback:p07"],
            "acceptance": ["rollback:p08", "rollback:telegram_plugin", "rollback:p07"],
        }
        for phase, rollback_events in expected.items():
            backend = FakeBackend(fail_phase=phase)
            with self.subTest(phase=phase):
                with self.assertRaises(CombinedTransactionRejected) as captured:
                    CombinedReleaseSetTransaction(
                        backend,
                        combined_release_set_id="c" * 64,
                    ).run()
                self.assertEqual(captured.exception.code, "combined_activation_rolled_back")
                self.assertEqual(
                    [event for event in backend.events if event.startswith("rollback:")],
                    rollback_events,
                )
                self.assertEqual(backend.events[-1], "observe:prestate")

    def test_rollback_failure_is_typed_but_later_rollbacks_still_run(self) -> None:
        backend = FakeBackend(fail_phase="p08", rollback_fail="telegram_plugin")
        with self.assertRaises(CombinedTransactionRejected) as captured:
            CombinedReleaseSetTransaction(
                backend,
                combined_release_set_id="c" * 64,
            ).run()
        self.assertEqual(captured.exception.code, "combined_functional_rollback_failed")
        self.assertEqual(
            captured.exception.rollback_failure_code,
            "telegram_plugin_synthetic_rollback_failure",
        )
        self.assertIn("rollback:p07", backend.events)


if __name__ == "__main__":
    unittest.main()
