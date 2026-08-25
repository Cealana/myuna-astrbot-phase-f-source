from __future__ import annotations

from datetime import datetime, timezone
import unittest

from myuna_core.operations.catalog import DEFAULT_OPERATION_CATALOG
from myuna_core.operations.errors import (
    InvalidOperationArgumentsError,
    OperationNotAllowedError,
    UnknownOperationError,
)
from myuna_core.operations.models import (
    ApprovalStatus,
    OperationErrorDetail,
    OperationOrigin,
    OperationRequest,
    OperationResult,
    OperationStatus,
    RiskLevel,
)


NOW = datetime(2042, 5, 9, 12, 0, tzinfo=timezone.utc)


def request(
    operation: str = "myuna.health",
    target: str = "myuna-core@qq.service",
    *,
    arguments=None,
    risk: RiskLevel = RiskLevel.LEVEL_0,
    timeout: int = 10,
) -> OperationRequest:
    return OperationRequest(
        request_id="request-test-0001",
        correlation_id="correlation-test-0001",
        idempotency_key="idempotency-test-0001",
        origin=OperationOrigin.MYUNA,
        actor="principal-test-owner",
        operation=operation,
        target=target,
        arguments=arguments or {},
        risk_level=risk,
        timeout_seconds=timeout,
        requires_approval=False,
        reason="synthetic contract test",
        created_at=NOW,
    )


class OpenClawModelsAndCatalogTests(unittest.TestCase):
    def test_request_is_immutable_canonical_and_digest_bound(self) -> None:
        operation = request(
            arguments={"lines": 20, "filters": ["warning"]},
            operation="myuna.recent_logs",
        )
        with self.assertRaises(TypeError):
            operation.arguments["lines"] = 50
        self.assertEqual(operation.arguments["filters"], ("warning",))
        self.assertEqual(len(operation.request_digest), 64)

        changed = OperationRequest(
            **{
                **operation.canonical_payload(),
                "arguments": {"lines": 21, "filters": ["warning"]},
                "origin": OperationOrigin.MYUNA,
                "risk_level": RiskLevel.LEVEL_0,
                "route_trace": (),
                "created_at": NOW,
            }
        )
        self.assertNotEqual(operation.request_digest, changed.request_digest)

    def test_request_rejects_naive_time_and_secret_bearing_argument_names(self) -> None:
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            OperationRequest(
                request_id="request-test-naive",
                correlation_id="correlation-test-naive",
                idempotency_key="idempotency-test-naive",
                origin=OperationOrigin.MYUNA,
                actor="principal-test-owner",
                operation="myuna.health",
                target="myuna-core@qq.service",
                arguments={},
                risk_level=RiskLevel.LEVEL_0,
                timeout_seconds=10,
                requires_approval=False,
                reason="synthetic",
                created_at=datetime(2042, 5, 9, 12, 0),
            )
        with self.assertRaisesRegex(ValueError, "secret-bearing"):
            request(arguments={"api_key": "synthetic-secret"})
        with self.assertRaisesRegex(ValueError, "secret-shaped"):
            request(arguments={"contains": "token=synthetic-secret-value"})

    def test_result_redacts_secret_patterns_and_sensitive_fields(self) -> None:
        result = OperationResult(
            request_id="request-test-result",
            operation_id="operation-test-result",
            status=OperationStatus.FAILED,
            success=False,
            started_at=NOW,
            finished_at=NOW,
            exit_code=1,
            summary="api_key=sk-syntheticsecret123",
            structured_data={
                "api_key": "sk-syntheticsecret123",
                "safe": "Bearer abcdefghijklmnop",
            },
            stdout_excerpt="token=synthetic-token-value",
            stderr_excerpt="https://invalid/?secret=synthetic-secret",
            approval_status=ApprovalStatus.NOT_REQUIRED,
            audit_reference="audit-test-result",
            error=OperationErrorDetail("openclaw_unavailable", "unavailable", True),
        )
        flattened = repr(result.public_payload())
        self.assertNotIn("syntheticsecret", flattened)
        self.assertNotIn("synthetic-token-value", flattened)
        self.assertNotIn("abcdefgh", flattened)
        self.assertEqual(result.structured_data["api_key"], "[REDACTED]")

    def test_catalog_has_only_structured_allowlisted_operations(self) -> None:
        definitions = DEFAULT_OPERATION_CATALOG.all_definitions()
        names = {definition.name for definition in definitions}
        self.assertIn("myuna.health", names)
        self.assertIn("recovery.rollback_last_known_good_config", names)
        self.assertIn("operation.cancel", names)
        self.assertNotIn("shell.execute", names)
        self.assertTrue(
            all(definition.handler_id.startswith("catalog.") for definition in definitions)
        )

    def test_catalog_rejects_unknown_forbidden_target_timeout_and_arguments(self) -> None:
        with self.assertRaises(OperationNotAllowedError):
            DEFAULT_OPERATION_CATALOG.validate(
                request("shell.execute", "server-ubuntu")
            )
        with self.assertRaises(UnknownOperationError):
            DEFAULT_OPERATION_CATALOG.validate(
                request("unknown.inspect", "server-ubuntu")
            )
        with self.assertRaises(OperationNotAllowedError):
            DEFAULT_OPERATION_CATALOG.validate(
                request("service.status", "not-allowlisted.service")
            )
        with self.assertRaises(InvalidOperationArgumentsError):
            DEFAULT_OPERATION_CATALOG.validate(
                request("myuna.health", "myuna-core@qq.service", timeout=31)
            )
        with self.assertRaises(InvalidOperationArgumentsError):
            DEFAULT_OPERATION_CATALOG.validate(
                request(
                    "myuna.recent_logs",
                    "myuna-core@qq.service",
                    arguments={"lines": 201},
                )
            )


if __name__ == "__main__":
    unittest.main()
