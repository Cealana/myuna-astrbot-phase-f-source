from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from myuna_core.audit import AuditLogger
from myuna_core.capability_runtime import (
    CapabilityLifecycleController,
    CapabilityLifecyclePort,
    CapabilityLifecycleState,
    CapabilityRuntimeAuditProjector,
    CapabilityRuntimePort,
    InvalidLifecycleTransitionError,
    LegacyOpenClawCapabilityShim,
    LifecycleActionFailedError,
)
from myuna_core.integrations.openclaw import FakeOpenClawAdapter, FakeOperationOutcome
from myuna_core.operations.catalog import DEFAULT_OPERATION_CATALOG
from myuna_core.operations.errors import ApprovalRequiredError
from myuna_core.operations.models import (
    NotificationRequest,
    OperationOrigin,
    OperationRequest,
    OperationStatus,
    RiskLevel,
)
from myuna_core.operations.policy import OperationExecutionContext, OperationPolicy


NOW = datetime(2042, 5, 9, 12, 0, tzinfo=timezone.utc)


def request(
    operation: str = "myuna.health",
    *,
    suffix: str = "neutral",
    risk: RiskLevel = RiskLevel.LEVEL_0,
    arguments=None,
    origin: OperationOrigin = OperationOrigin.MYUNA,
    target: str = "myuna-core@qq.service",
) -> OperationRequest:
    return OperationRequest(
        request_id=f"request-capability-{suffix}",
        correlation_id=f"correlation-capability-{suffix}",
        idempotency_key=f"idempotency-capability-{suffix}",
        origin=origin,
        actor="principal-test-owner",
        operation=operation,
        target=target,
        arguments=arguments or {},
        risk_level=risk,
        timeout_seconds=30,
        requires_approval=False,
        reason="synthetic neutral capability test",
        created_at=NOW,
    )


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


class CapabilityRuntimeFoundationTests(unittest.TestCase):
    def test_legacy_shim_implements_neutral_port_and_preserves_payload_bytes(self) -> None:
        operation_request = request()
        legacy_adapter = FakeOpenClawAdapter(now=lambda: NOW)
        neutral_adapter = FakeOpenClawAdapter(now=lambda: NOW)
        shim = LegacyOpenClawCapabilityShim(neutral_adapter)

        legacy_request_bytes = canonical_bytes(operation_request.canonical_payload())
        neutral_request_bytes = canonical_bytes(operation_request.canonical_payload())
        legacy_result = legacy_adapter.run_operation(operation_request)
        neutral_result = shim.execute(operation_request)

        self.assertIsInstance(shim, CapabilityRuntimePort)
        self.assertEqual(shim.runtime_id, neutral_adapter.adapter_id)
        self.assertEqual(legacy_request_bytes, neutral_request_bytes)
        self.assertEqual(
            canonical_bytes(legacy_result.public_payload()),
            canonical_bytes(neutral_result.public_payload()),
        )
        self.assertEqual(
            shim.get_execution_status(neutral_result.operation_id),
            neutral_result,
        )

    def test_legacy_shim_forwards_typed_errors_approval_and_notification(self) -> None:
        adapter = FakeOpenClawAdapter(now=lambda: NOW)
        shim = LegacyOpenClawCapabilityShim(adapter)
        restart = request("myuna.restart", suffix="approval")

        with self.assertRaises(ApprovalRequiredError):
            shim.execute(restart)

        approval = shim.submit_approval_request(
            restart,
            approval_id="approval-capability-shim",
            approver_principal_id="principal-test-owner",
            nonce="synthetic-approval-nonce-00000001",
            expires_at=NOW + timedelta(minutes=5),
            impact_summary="synthetic impact",
            rollback_summary="synthetic rollback",
        )
        self.assertEqual(approval.request_digest, restart.request_digest)

        notification = NotificationRequest(
            notification_id="notification-capability-shim",
            correlation_id=restart.correlation_id,
            recipient_principal_id="principal-test-owner",
            template_id="operation-completed-v1",
            variables={"audit_reference": "audit-synthetic"},
            created_at=NOW,
        )
        self.assertEqual(shim.notify(notification), adapter.send_notification(notification))

    def test_legacy_shim_forwards_cancellation_with_exact_approval(self) -> None:
        adapter = FakeOpenClawAdapter(
            now=lambda: NOW + timedelta(seconds=2),
            outcomes={
                "recovery.collect_diagnostics": FakeOperationOutcome(
                    status=OperationStatus.RUNNING,
                    summary="synthetic diagnostics running",
                    exit_code=None,
                )
            },
        )
        shim = LegacyOpenClawCapabilityShim(adapter)
        recovery_context = OperationExecutionContext(recovery_mode=True)
        diagnostics = request(
            "recovery.collect_diagnostics",
            suffix="running",
            origin=OperationOrigin.CEALANA_REMOTE,
            risk=RiskLevel.LEVEL_1,
        )
        running = shim.execute(diagnostics, context=recovery_context)
        cancellation = request(
            "operation.cancel",
            suffix="cancel",
            origin=OperationOrigin.CEALANA_REMOTE,
            target="active-operation",
            arguments={"operation_id": running.operation_id},
        )
        nonce = "synthetic-approval-nonce-00000002"
        approval = shim.submit_approval_request(
            cancellation,
            context=recovery_context,
            approval_id="approval-capability-cancel",
            approver_principal_id="principal-test-owner",
            nonce=nonce,
            expires_at=NOW + timedelta(minutes=5),
            impact_summary="synthetic cancellation impact",
            rollback_summary="synthetic cancellation rollback",
        )
        adapter.approvals.approve(
            approval.approval_id,
            approver_principal_id="principal-test-owner",
            nonce=nonce,
            decided_at=NOW + timedelta(seconds=1),
        )
        cancelled = shim.cancel(
            cancellation,
            context=OperationExecutionContext(
                recovery_mode=True,
                approval_id=approval.approval_id,
            ),
        )

        self.assertTrue(cancelled.success)
        self.assertEqual(
            shim.get_execution_status(running.operation_id).status,
            OperationStatus.CANCELLED,
        )

    def test_lifecycle_start_stop_is_deterministic_and_idempotent(self) -> None:
        calls: list[str] = []
        controller = CapabilityLifecycleController("runtime-synthetic")

        initial = controller.lifecycle_snapshot()
        started = controller.startup(lambda: calls.append("start"))
        repeated_start = controller.startup(lambda: calls.append("unexpected"))
        stopped = controller.shutdown(lambda: calls.append("stop"))
        repeated_stop = controller.shutdown(lambda: calls.append("unexpected"))

        self.assertEqual(initial.state, CapabilityLifecycleState.STOPPED)
        self.assertIsInstance(controller, CapabilityLifecyclePort)
        self.assertEqual(initial.revision, 0)
        self.assertEqual(started.state, CapabilityLifecycleState.READY)
        self.assertTrue(started.accepting_requests)
        self.assertEqual(started.revision, 2)
        self.assertEqual(repeated_start, started)
        self.assertEqual(stopped.state, CapabilityLifecycleState.STOPPED)
        self.assertFalse(stopped.accepting_requests)
        self.assertEqual(stopped.revision, 4)
        self.assertEqual(repeated_stop, stopped)
        self.assertEqual(calls, ["start", "stop"])

    def test_lifecycle_degrade_recover_and_invalid_transition_fail_closed(self) -> None:
        controller = CapabilityLifecycleController("runtime-recovery")
        controller.startup()
        degraded = controller.degrade("dependency_unavailable")
        repeated = controller.degrade("dependency_unavailable")
        recovered = controller.recover()

        self.assertEqual(degraded.state, CapabilityLifecycleState.DEGRADED)
        self.assertEqual(repeated, degraded)
        self.assertEqual(recovered.state, CapabilityLifecycleState.READY)
        self.assertEqual(recovered.reason_code, "recovery_succeeded")
        with self.assertRaises(InvalidLifecycleTransitionError):
            controller.recover()

    def test_lifecycle_action_failure_exposes_only_structured_category(self) -> None:
        controller = CapabilityLifecycleController("runtime-failure")
        sensitive = "synthetic-private-detail"

        def fail() -> None:
            raise RuntimeError(sensitive)

        with self.assertRaises(LifecycleActionFailedError) as raised:
            controller.startup(fail)
        snapshot = controller.lifecycle_snapshot()
        payload = raised.exception.public_payload()

        self.assertEqual(snapshot.state, CapabilityLifecycleState.FAILED)
        self.assertEqual(snapshot.reason_code, "startup_failed")
        self.assertEqual(payload["code"], "lifecycle_action_failed")
        self.assertEqual(payload["details"], {"phase": "startup"})
        self.assertNotIn(sensitive, repr(payload))
        self.assertIsNone(raised.exception.__cause__)

    def test_neutral_audit_projection_is_separate_from_legacy_namespace(self) -> None:
        operation_request = request(suffix="audit")
        context = OperationExecutionContext()
        _, decision = OperationPolicy(DEFAULT_OPERATION_CATALOG).evaluate(
            operation_request,
            context,
        )
        adapter = FakeOpenClawAdapter(now=lambda: NOW)
        result = adapter.run_operation(operation_request)

        with TemporaryDirectory() as temp:
            audit = AuditLogger(Path(temp), "dev")
            projector = CapabilityRuntimeAuditProjector(audit)
            reference = projector.emit_request(
                adapter.adapter_id,
                operation_request,
                decision,
                context,
            )
            projector.emit_result(adapter.adapter_id, operation_request, result)
            text = audit.path.read_text(encoding="utf-8")

        self.assertTrue(reference.startswith("audit-"))
        self.assertGreaterEqual(text.count(reference), 2)
        self.assertIn("capability_runtime.operation.requested", text)
        self.assertIn("capability_runtime.operation.finished", text)
        self.assertNotIn("openclaw.operation.", text)
        self.assertNotIn(operation_request.reason, text)

    def test_foundation_contains_no_transport_process_or_network_client(self) -> None:
        root = (
            Path(__file__).parents[1]
            / "src"
            / "myuna_core"
            / "capability_runtime"
        )
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(root.glob("*.py"))
        )
        for forbidden in (
            "import aiohttp",
            "import httpx",
            "import requests",
            "import socket",
            "import subprocess",
            "os.system",
            "Popen(",
            "urlopen(",
        ):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
