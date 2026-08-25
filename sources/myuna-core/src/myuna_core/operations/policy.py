from __future__ import annotations

from dataclasses import dataclass

from .catalog import OperationCatalog, OperationDefinition
from .errors import OperationNotAllowedError, RecoveryModeViolationError
from .models import OperationOrigin, OperationRequest, RiskLevel


@dataclass(frozen=True, slots=True)
class OperationExecutionContext:
    recovery_mode: bool = False
    approval_id: str | None = None


@dataclass(frozen=True, slots=True)
class OperationPolicyDecision:
    allowed: bool
    effective_risk: RiskLevel
    approval_required: bool
    strong_approval_required: bool
    reason_codes: tuple[str, ...]


class OperationPolicy:
    """Deterministic policy. A model can request an operation but cannot authorize it."""

    def __init__(self, catalog: OperationCatalog) -> None:
        self.catalog = catalog

    def evaluate(
        self,
        request: OperationRequest,
        context: OperationExecutionContext,
    ) -> tuple[OperationDefinition, OperationPolicyDecision]:
        definition = self.catalog.validate(request)

        if request.origin is OperationOrigin.RECOVERY and not context.recovery_mode:
            raise RecoveryModeViolationError("recovery origin requires recovery mode")
        if context.recovery_mode:
            if request.origin is OperationOrigin.MYUNA:
                raise RecoveryModeViolationError("Myuna cannot originate its own recovery path")
            if not definition.allowed_in_recovery:
                raise RecoveryModeViolationError("operation is not allowed in recovery mode")
        elif request.operation.startswith("recovery."):
            raise RecoveryModeViolationError("recovery playbooks require recovery mode")

        effective_risk = max(
            (definition.risk_level, request.risk_level),
            key=lambda risk: risk.rank,
        )
        if effective_risk is RiskLevel.FORBIDDEN:
            raise OperationNotAllowedError("operation risk is forbidden")

        reasons = [f"catalog_{definition.risk_level.value}"]
        if request.risk_level.rank < definition.risk_level.rank:
            reasons.append("caller_risk_upgraded_to_catalog")
        elif request.risk_level.rank > definition.risk_level.rank:
            reasons.append("caller_requested_stricter_risk")
        approval_required = (
            definition.requires_approval
            or request.requires_approval
            or effective_risk.rank >= RiskLevel.LEVEL_2.rank
        )
        if definition.requires_approval and not request.requires_approval:
            reasons.append("caller_cannot_disable_catalog_approval")
        if approval_required:
            reasons.append("approval_required")
        if context.recovery_mode:
            reasons.append("recovery_catalog_restricted")

        return definition, OperationPolicyDecision(
            allowed=True,
            effective_risk=effective_risk,
            approval_required=approval_required,
            strong_approval_required=effective_risk is RiskLevel.LEVEL_3,
            reason_codes=tuple(reasons),
        )

