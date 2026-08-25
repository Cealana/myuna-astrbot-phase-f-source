from __future__ import annotations

import unittest

from p07_policy_overlay_transaction import (
    AtomicPolicyOverlayTransaction,
    PolicyOverlayObservation,
    PolicyOverlayTransactionRejected,
)


class FakeBackend:
    def __init__(self, *, fail_at: str | None = None, rollback_fail: bool = False) -> None:
        self.fail_at = fail_at
        self.rollback_fail = rollback_fail
        self.calls: list[str] = []
        self.target_observations = 0
        self.prestate_observations = 0

    def _call(self, name: str) -> None:
        self.calls.append(name)
        if self.fail_at == name:
            error = RuntimeError(name)
            error.code = f"typed_{name}"  # type: ignore[attr-defined]
            raise error

    def create_plan_bound_backup(self) -> None:
        self._call("backup")

    def consume_attempt(self) -> int:
        self._call("attempt")
        return 1

    def install_inactive_releases(self) -> None:
        self._call("install")

    def stop_target_services(self) -> None:
        self._call("stop")

    def verify_target_services_stopped(self) -> None:
        self._call("stopped")

    def apply_target(self) -> None:
        self._call("apply")

    def daemon_reload(self) -> None:
        self._call("reload")

    def start_target_services(self) -> None:
        self._call("start")

    def observe_target(self) -> PolicyOverlayObservation:
        self._call("observe_target")
        self.target_observations += 1
        return PolicyOverlayObservation("target", 0, True)

    def restore_prestate(self) -> None:
        self._call("restore")
        if self.rollback_fail:
            error = RuntimeError("restore")
            error.code = "typed_restore_failed"  # type: ignore[attr-defined]
            raise error

    def observe_prestate(self) -> PolicyOverlayObservation:
        self._call("observe_prestate")
        self.prestate_observations += 1
        return PolicyOverlayObservation("prestate", 0, True)

    def expected_prestate(self) -> PolicyOverlayObservation:
        self._call("expected_prestate")
        return PolicyOverlayObservation("prestate", 0, True)


class PolicyOverlayTransactionTests(unittest.TestCase):
    def test_backup_precedes_attempt_and_success_is_observed_twice(self) -> None:
        backend = FakeBackend()
        result = AtomicPolicyOverlayTransaction(backend).run()
        self.assertEqual(result.attempt, 1)
        self.assertEqual(backend.calls[:2], ["backup", "attempt"])
        self.assertEqual(backend.target_observations, 2)
        self.assertNotIn("restore", backend.calls)

    def test_activation_failure_preserves_typed_cause_and_rolls_back_once(self) -> None:
        backend = FakeBackend(fail_at="apply")
        with self.assertRaises(PolicyOverlayTransactionRejected) as raised:
            AtomicPolicyOverlayTransaction(backend).run()
        self.assertEqual(
            raised.exception.code,
            "policy_overlay_activation_failed_rollback_verified",
        )
        self.assertEqual(raised.exception.activation_failure_code, "typed_apply")
        self.assertEqual(backend.calls.count("restore"), 1)
        self.assertEqual(backend.prestate_observations, 2)
        self.assertEqual(backend.calls[:2], ["backup", "attempt"])

    def test_rollback_failure_is_independent_typed_gate(self) -> None:
        backend = FakeBackend(fail_at="apply", rollback_fail=True)
        with self.assertRaises(PolicyOverlayTransactionRejected) as raised:
            AtomicPolicyOverlayTransaction(backend).run()
        self.assertEqual(raised.exception.code, "policy_overlay_rollback_failed")
        self.assertEqual(raised.exception.activation_failure_code, "typed_apply")
        self.assertEqual(
            raised.exception.rollback_failure_code,
            "typed_restore_failed",
        )

    def test_backup_failure_does_not_consume_attempt_or_rollback(self) -> None:
        backend = FakeBackend(fail_at="backup")
        with self.assertRaises(RuntimeError):
            AtomicPolicyOverlayTransaction(backend).run()
        self.assertEqual(backend.calls, ["backup"])


if __name__ == "__main__":
    unittest.main()
