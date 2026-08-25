from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from myuna_core.operations.approval import InMemoryApprovalLedger
from myuna_core.operations.catalog import DEFAULT_OPERATION_CATALOG
from myuna_core.operations.errors import (
    ApprovalAlreadyConsumedError,
    ApprovalDeniedError,
    ApprovalExpiredError,
    HopLimitExceededError,
    IdempotencyConflictError,
    OperationLoopDetectedError,
    RecoveryModeViolationError,
)
from myuna_core.operations.guard import OperationLoopGuard
from myuna_core.operations.idempotency import InMemoryIdempotencyLedger
from myuna_core.operations.models import (
    ApprovalStatus,
    OperationOrigin,
    OperationRequest,
    OperationResult,
    OperationStatus,
    RiskLevel,
    TaskStatus,
)
from myuna_core.operations.policy import OperationExecutionContext, OperationPolicy
from myuna_core.operations.tasks import InMemoryTaskStore, TaskRecord


NOW = datetime(2042, 5, 9, 12, 0, tzinfo=timezone.utc)
NONCE = "synthetic-approval-nonce-00000001"


def request(
    *,
    request_id: str = "request-policy-0001",
    idempotency_key: str = "idempotency-policy-0001",
    operation: str = "myuna.restart",
    target: str = "myuna-core@qq.service",
    origin: OperationOrigin = OperationOrigin.MYUNA,
    risk: RiskLevel = RiskLevel.LEVEL_0,
    hop_count: int = 0,
    route_trace: tuple[str, ...] = (),
) -> OperationRequest:
    return OperationRequest(
        request_id=request_id,
        correlation_id="correlation-policy-0001",
        idempotency_key=idempotency_key,
        origin=origin,
        actor="principal-test-owner",
        operation=operation,
        target=target,
        arguments={},
        risk_level=risk,
        timeout_seconds=30,
        requires_approval=False,
        reason="synthetic policy test",
        created_at=NOW,
        hop_count=hop_count,
        route_trace=route_trace,
    )


def success_result(operation_request: OperationRequest) -> OperationResult:
    return OperationResult(
        request_id=operation_request.request_id,
        operation_id="operation-policy-0001",
        status=OperationStatus.SUCCEEDED,
        success=True,
        started_at=NOW,
        finished_at=NOW,
        exit_code=0,
        summary="synthetic success",
    )


class OpenClawPolicyLedgersAndTasksTests(unittest.TestCase):
    def test_catalog_risk_overrides_caller_downgrade_and_requires_approval(self) -> None:
        _, decision = OperationPolicy(DEFAULT_OPERATION_CATALOG).evaluate(
            request(risk=RiskLevel.LEVEL_0),
            OperationExecutionContext(),
        )
        self.assertEqual(decision.effective_risk, RiskLevel.LEVEL_2)
        self.assertTrue(decision.approval_required)
        self.assertIn("caller_risk_upgraded_to_catalog", decision.reason_codes)
        self.assertIn("caller_cannot_disable_catalog_approval", decision.reason_codes)

    def test_recovery_mode_is_narrow_and_cannot_be_originated_by_myuna(self) -> None:
        policy = OperationPolicy(DEFAULT_OPERATION_CATALOG)
        with self.assertRaises(RecoveryModeViolationError):
            policy.evaluate(
                request(operation="myuna.health", origin=OperationOrigin.MYUNA),
                OperationExecutionContext(recovery_mode=True),
            )
        with self.assertRaises(RecoveryModeViolationError):
            policy.evaluate(
                request(
                    operation="recovery.check_myuna",
                    origin=OperationOrigin.CEALANA_REMOTE,
                ),
                OperationExecutionContext(recovery_mode=False),
            )
        _, decision = policy.evaluate(
            request(
                operation="recovery.check_myuna",
                origin=OperationOrigin.CEALANA_REMOTE,
            ),
            OperationExecutionContext(recovery_mode=True),
        )
        self.assertTrue(decision.allowed)

    def test_hop_and_loop_guard_fail_closed(self) -> None:
        guard = OperationLoopGuard(max_hops=4)
        advanced = guard.advance(request(), "openclaw")
        self.assertEqual(advanced.hop_count, 1)
        self.assertEqual(advanced.route_trace, ("openclaw",))
        with self.assertRaises(OperationLoopDetectedError):
            guard.advance(
                request(hop_count=1, route_trace=("openclaw",)),
                "openclaw",
            )
        with self.assertRaises(HopLimitExceededError):
            guard.advance(
                request(
                    hop_count=4,
                    route_trace=("gateway", "myuna", "policy", "adapter"),
                ),
                "openclaw",
            )

    def test_approval_is_exact_request_bound_expiring_and_one_time(self) -> None:
        ledger = InMemoryApprovalLedger()
        original = request()
        record = ledger.create(
            original,
            approval_id="approval-policy-0001",
            operation_id="operation-policy-0001",
            approver_principal_id="principal-test-owner",
            nonce=NONCE,
            expires_at=NOW + timedelta(minutes=5),
            effective_risk=RiskLevel.LEVEL_2,
            impact_summary="restart one synthetic service",
            rollback_summary="verify and restore synthetic service",
        )
        self.assertEqual(record.risk_level, RiskLevel.LEVEL_2)
        approved = ledger.approve(
            record.approval_id,
            approver_principal_id="principal-test-owner",
            nonce=NONCE,
            decided_at=NOW + timedelta(seconds=1),
        )
        self.assertEqual(approved.status, ApprovalStatus.APPROVED)
        with self.assertRaises(ApprovalDeniedError):
            ledger.consume(
                record.approval_id,
                operation_id="operation-policy-0001",
                request_digest="f" * 64,
                now=NOW + timedelta(seconds=2),
            )
        consumed = ledger.consume(
            record.approval_id,
            operation_id="operation-policy-0001",
            request_digest=original.request_digest,
            now=NOW + timedelta(seconds=2),
        )
        self.assertEqual(consumed.status, ApprovalStatus.CONSUMED)
        with self.assertRaises(ApprovalAlreadyConsumedError):
            ledger.consume(
                record.approval_id,
                operation_id="operation-policy-0001",
                request_digest=original.request_digest,
                now=NOW + timedelta(seconds=3),
            )

    def test_approval_expiry_fails_closed(self) -> None:
        ledger = InMemoryApprovalLedger()
        original = request()
        ledger.create(
            original,
            approval_id="approval-policy-expired",
            operation_id="operation-policy-expired",
            approver_principal_id="principal-test-owner",
            nonce=NONCE,
            expires_at=NOW + timedelta(seconds=1),
            effective_risk=RiskLevel.LEVEL_2,
            impact_summary="synthetic impact",
            rollback_summary="synthetic rollback",
        )
        with self.assertRaises(ApprovalExpiredError):
            ledger.approve(
                "approval-policy-expired",
                approver_principal_id="principal-test-owner",
                nonce=NONCE,
                decided_at=NOW + timedelta(seconds=2),
            )

    def test_approval_timestamps_are_monotonic(self) -> None:
        ledger = InMemoryApprovalLedger()
        original = request()
        ledger.create(
            original,
            approval_id="approval-policy-time",
            operation_id="operation-policy-time",
            approver_principal_id="principal-test-owner",
            nonce=NONCE,
            expires_at=NOW + timedelta(minutes=5),
            effective_risk=RiskLevel.LEVEL_2,
            impact_summary="synthetic impact",
            rollback_summary="synthetic rollback",
        )
        with self.assertRaises(ApprovalDeniedError):
            ledger.approve(
                "approval-policy-time",
                approver_principal_id="principal-test-owner",
                nonce=NONCE,
                decided_at=NOW - timedelta(seconds=1),
            )

    def test_idempotency_replays_result_and_rejects_key_rebinding(self) -> None:
        ledger = InMemoryIdempotencyLedger()
        original = request()
        result = success_result(original)
        ledger.claim(original.idempotency_key, original.request_digest, result.operation_id)
        ledger.complete(original.idempotency_key, original.request_digest, result)
        self.assertIs(ledger.lookup(original.idempotency_key, original.request_digest), result)
        with self.assertRaises(IdempotencyConflictError):
            ledger.lookup(original.idempotency_key, "e" * 64)

    def test_idempotency_result_must_match_claimed_operation(self) -> None:
        ledger = InMemoryIdempotencyLedger()
        original = request()
        ledger.claim(
            original.idempotency_key,
            original.request_digest,
            "operation-policy-claimed",
        )
        with self.assertRaises(IdempotencyConflictError):
            ledger.complete(
                original.idempotency_key,
                original.request_digest,
                success_result(original),
            )

    def test_task_store_is_authoritative_and_transition_bounded(self) -> None:
        store = InMemoryTaskStore()
        record = TaskRecord(
            task_id="task-policy-0001",
            correlation_id="correlation-policy-0001",
            owner_principal_id="principal-test-owner",
            origin=OperationOrigin.CEALANA_REMOTE,
            task_kind="system_operation",
            status=TaskStatus.PENDING,
            created_at=NOW,
            updated_at=NOW,
        )
        store.append(record)
        running = store.transition(record.task_id, TaskStatus.RUNNING, at=NOW)
        attached = store.attach_operation(
            record.task_id,
            "operation-policy-0001",
            at=NOW,
        )
        self.assertEqual(running.status, TaskStatus.RUNNING)
        self.assertEqual(attached.operation_ids, ("operation-policy-0001",))
        store.transition(record.task_id, TaskStatus.SUCCEEDED, at=NOW)
        with self.assertRaises(ValueError):
            store.transition(record.task_id, TaskStatus.RUNNING, at=NOW)


if __name__ == "__main__":
    unittest.main()
