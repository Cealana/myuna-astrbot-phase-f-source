from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from myuna_core.audit import AuditLogger
from myuna_core.integrations.openclaw import (
    FakeOpenClawAdapter,
    FakeOperationOutcome,
    OpenClawAdapter,
)
from myuna_core.operations.audit import OperationAuditLogger
from myuna_core.operations.errors import (
    ApprovalRequiredError,
    IdempotencyConflictError,
    InvalidOperationArgumentsError,
    RecoveryModeViolationError,
)
from myuna_core.operations.models import (
    ApprovalStatus,
    NotificationRequest,
    OperationErrorDetail,
    OperationOrigin,
    OperationRequest,
    OperationStatus,
    RiskLevel,
)
from myuna_core.operations.policy import OperationExecutionContext


NOW = datetime(2042, 5, 9, 12, 0, tzinfo=timezone.utc)
NONCE = "synthetic-approval-nonce-00000001"


def request(
    operation: str,
    target: str,
    *,
    suffix: str,
    origin: OperationOrigin = OperationOrigin.MYUNA,
    arguments=None,
    risk: RiskLevel = RiskLevel.LEVEL_0,
    timeout: int = 30,
    idempotency_key: str | None = None,
) -> OperationRequest:
    return OperationRequest(
        request_id=f"request-fake-{suffix}",
        correlation_id=f"correlation-fake-{suffix}",
        idempotency_key=idempotency_key or f"idempotency-fake-{suffix}",
        origin=origin,
        actor="principal-test-owner",
        operation=operation,
        target=target,
        arguments=arguments or {},
        risk_level=risk,
        timeout_seconds=timeout,
        requires_approval=False,
        reason="synthetic fake adapter test",
        created_at=NOW,
    )


def approve(
    adapter: FakeOpenClawAdapter,
    operation_request: OperationRequest,
    *,
    approval_id: str,
    context: OperationExecutionContext = OperationExecutionContext(),
) -> OperationExecutionContext:
    adapter.request_approval(
        operation_request,
        context=context,
        approval_id=approval_id,
        approver_principal_id="principal-test-owner",
        nonce=NONCE,
        expires_at=NOW + timedelta(minutes=5),
        impact_summary="synthetic operation impact",
        rollback_summary="synthetic rollback and verification",
    )
    adapter.approvals.approve(
        approval_id,
        approver_principal_id="principal-test-owner",
        nonce=NONCE,
        decided_at=NOW + timedelta(seconds=1),
    )
    return OperationExecutionContext(
        recovery_mode=context.recovery_mode,
        approval_id=approval_id,
    )


class OpenClawFakeAdapterTests(unittest.TestCase):
    def test_fake_implements_protocol_without_real_transport(self) -> None:
        adapter = FakeOpenClawAdapter(now=lambda: NOW)
        self.assertIsInstance(adapter, OpenClawAdapter)
        source = Path(__file__).parents[1] / "src/myuna_core/integrations/openclaw/fake.py"
        text = source.read_text(encoding="utf-8")
        for forbidden in (
            "import requests",
            "import socket",
            "import subprocess",
            "os.system",
            "Popen(",
            "urlopen(",
        ):
            self.assertNotIn(forbidden, text)

    def test_read_only_operation_is_idempotent_and_executes_once(self) -> None:
        adapter = FakeOpenClawAdapter(now=lambda: NOW)
        health = request(
            "myuna.health",
            "myuna-core@qq.service",
            suffix="health",
        )
        first = adapter.health_check(health)
        second = adapter.health_check(health)
        self.assertTrue(first.success)
        self.assertIs(first, second)
        self.assertEqual(adapter.execution_count("myuna.health"), 1)

    def test_dangerous_operation_requires_and_consumes_exact_approval(self) -> None:
        adapter = FakeOpenClawAdapter(now=lambda: NOW + timedelta(seconds=2))
        restart = request(
            "myuna.restart",
            "myuna-core@qq.service",
            suffix="restart",
            risk=RiskLevel.LEVEL_0,
        )
        with self.assertRaises(ApprovalRequiredError):
            adapter.run_operation(restart)
        context = approve(adapter, restart, approval_id="approval-fake-restart")
        result = adapter.run_operation(restart, context=context)
        self.assertTrue(result.success)
        self.assertEqual(result.approval_status, ApprovalStatus.CONSUMED)
        record = adapter.approvals.get("approval-fake-restart")
        self.assertIsNotNone(record)
        self.assertEqual(record.risk_level, RiskLevel.LEVEL_2)
        self.assertEqual(adapter.execution_count("myuna.restart"), 1)
        replay = adapter.run_operation(restart)
        self.assertIs(replay, result)
        self.assertEqual(adapter.execution_count("myuna.restart"), 1)

    def test_reused_idempotency_key_with_changed_request_fails_closed(self) -> None:
        adapter = FakeOpenClawAdapter(now=lambda: NOW)
        first = request(
            "myuna.health",
            "myuna-core@qq.service",
            suffix="idempotency-a",
            idempotency_key="idempotency-fake-shared",
        )
        second = request(
            "myuna.status",
            "myuna-core@qq.service",
            suffix="idempotency-b",
            idempotency_key="idempotency-fake-shared",
        )
        adapter.run_operation(first)
        with self.assertRaises(IdempotencyConflictError):
            adapter.run_operation(second)

    def test_outputs_are_bounded_redacted_and_audit_is_metadata_only(self) -> None:
        secret = "sk-syntheticsecret123456789"
        outcome = FakeOperationOutcome(
            summary=f"api_key={secret}",
            structured_data={"api_key": secret, "state": "healthy"},
            stdout_excerpt=f"Bearer {secret} " + "x" * 3000,
            stderr_excerpt=f"token={secret} " + "y" * 3000,
        )
        with TemporaryDirectory() as temp:
            audit = AuditLogger(Path(temp), "dev")
            adapter = FakeOpenClawAdapter(
                now=lambda: NOW,
                outcomes={"myuna.status": outcome},
                audit=OperationAuditLogger(audit),
            )
            status = request(
                "myuna.status",
                "myuna-core@qq.service",
                suffix="redaction",
            )
            result = adapter.get_service_status(status)
            flattened = repr(result.public_payload())
            audit_text = audit.path.read_text(encoding="utf-8")
            self.assertNotIn(secret, flattened)
            self.assertNotIn(secret, audit_text)
            self.assertNotIn("synthetic fake adapter test", audit_text)
            self.assertEqual(result.structured_data["api_key"], "[REDACTED]")
            self.assertLessEqual(
                len(result.stdout_excerpt) + len(result.stderr_excerpt),
                2048,
            )
            self.assertTrue(result.truncated)
            self.assertIn("openclaw.operation.requested", audit_text)
            self.assertIn("openclaw.operation.finished", audit_text)

    def test_timeout_and_unavailable_are_typed_results(self) -> None:
        timeout_adapter = FakeOpenClawAdapter(
            now=lambda: NOW,
            outcomes={
                "myuna.health": FakeOperationOutcome(duration_seconds=20),
            },
        )
        timed = timeout_adapter.run_operation(
            request(
                "myuna.health",
                "myuna-core@qq.service",
                suffix="timeout",
                timeout=10,
            )
        )
        self.assertEqual(timed.status, OperationStatus.TIMED_OUT)
        self.assertEqual(timed.error.code, "operation_timeout")

        unavailable_adapter = FakeOpenClawAdapter(
            now=lambda: NOW,
            outcomes={
                "myuna.health": FakeOperationOutcome(
                    status=OperationStatus.FAILED,
                    summary="fake OpenClaw unavailable",
                    exit_code=None,
                    error=OperationErrorDetail(
                        "openclaw_unavailable",
                        "fake OpenClaw unavailable",
                        True,
                    ),
                )
            },
        )
        unavailable = unavailable_adapter.run_operation(
            request(
                "myuna.health",
                "myuna-core@qq.service",
                suffix="unavailable",
            )
        )
        self.assertEqual(unavailable.status, OperationStatus.FAILED)
        self.assertTrue(unavailable.error.retryable)

    def test_recovery_playbook_requires_recovery_mode(self) -> None:
        adapter = FakeOpenClawAdapter(now=lambda: NOW)
        recovery = request(
            "recovery.check_myuna",
            "myuna-core@qq.service",
            suffix="recovery",
            origin=OperationOrigin.CEALANA_REMOTE,
        )
        with self.assertRaises(RecoveryModeViolationError):
            adapter.run_playbook(recovery, context=OperationExecutionContext())
        result = adapter.run_playbook(
            recovery,
            context=OperationExecutionContext(recovery_mode=True),
        )
        self.assertTrue(result.success)

    def test_running_fake_operation_can_be_cancelled_with_approval(self) -> None:
        adapter = FakeOpenClawAdapter(
            now=lambda: NOW + timedelta(seconds=2),
            outcomes={
                "recovery.collect_diagnostics": FakeOperationOutcome(
                    status=OperationStatus.RUNNING,
                    summary="fake diagnostics running",
                    exit_code=None,
                )
            },
        )
        diagnostics = request(
            "recovery.collect_diagnostics",
            "myuna-core@qq.service",
            suffix="diagnostics",
            origin=OperationOrigin.CEALANA_REMOTE,
            risk=RiskLevel.LEVEL_1,
            timeout=60,
        )
        recovery_context = OperationExecutionContext(recovery_mode=True)
        running = adapter.run_playbook(diagnostics, context=recovery_context)
        self.assertEqual(running.status, OperationStatus.RUNNING)

        cancellation = request(
            "operation.cancel",
            "active-operation",
            suffix="cancel",
            origin=OperationOrigin.CEALANA_REMOTE,
            arguments={"operation_id": running.operation_id},
        )
        cancellation_context = approve(
            adapter,
            cancellation,
            approval_id="approval-fake-cancel",
            context=recovery_context,
        )
        cancelled = adapter.cancel_operation(cancellation, context=cancellation_context)
        self.assertTrue(cancelled.success)
        self.assertEqual(
            adapter.get_operation_status(running.operation_id).status,
            OperationStatus.CANCELLED,
        )

    def test_notification_is_recorded_only_and_method_boundaries_are_strict(self) -> None:
        adapter = FakeOpenClawAdapter(now=lambda: NOW)
        notification = NotificationRequest(
            notification_id="notification-fake-0001",
            correlation_id="correlation-fake-notification",
            recipient_principal_id="principal-test-owner",
            template_id="operation-completed-v1",
            variables={"audit_reference": "audit-synthetic"},
            created_at=NOW,
        )
        first = adapter.send_notification(notification)
        second = adapter.send_notification(notification)
        self.assertEqual(first, second)
        self.assertEqual(first.status, "fake_recorded")

        wrong = request(
            "host.metrics",
            "server-ubuntu",
            suffix="wrong-method",
        )
        with self.assertRaises(InvalidOperationArgumentsError):
            adapter.health_check(wrong)


if __name__ == "__main__":
    unittest.main()
