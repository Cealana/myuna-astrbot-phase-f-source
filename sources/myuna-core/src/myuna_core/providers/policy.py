from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
import re

from myuna_core.capabilities import (
    OWNER_PRIVATE_PROFILE_WRITE_V1_SCOPE,
    RuntimeCapabilityManifest,
    is_owner_memory_response_scope,
)

from .registry import get_model_spec


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
RiskLevel = Literal["low", "medium", "high"]


@dataclass(frozen=True, slots=True)
class RoutingRequest:
    request_id: str
    task_class: str
    requested_capabilities: tuple[str, ...] = ("conversation",)
    risk_level: RiskLevel = "low"
    prior_fast_failures: int = 0
    repair_failed: bool = False
    user_requested_high_quality: bool = False

    def __post_init__(self) -> None:
        for value, label in (
            (self.request_id, "request_id"),
            (self.task_class, "task_class"),
        ):
            if _IDENTIFIER.fullmatch(value) is None:
                raise ValueError(f"{label} must be a safe identifier")
        if self.risk_level not in {"low", "medium", "high"}:
            raise ValueError("risk_level must be low, medium, or high")
        if not 0 <= self.prior_fast_failures <= 100:
            raise ValueError("prior_fast_failures must be between 0 and 100")
        if len(self.requested_capabilities) != len(set(self.requested_capabilities)):
            raise ValueError("requested_capabilities must not contain duplicates")
        if any(_IDENTIFIER.fullmatch(item) is None for item in self.requested_capabilities):
            raise ValueError("requested_capabilities must be safe identifiers")


@dataclass(frozen=True, slots=True)
class RouteDecision:
    action: Literal["route", "block"]
    route_reason: str
    provider: str | None
    model: str | None
    thinking: str | None
    max_repair_attempts: int
    blocked_capabilities: tuple[str, ...] = ()


class StagingPolicyRouter:
    """Deterministic dev policy router; it never calls a provider itself."""

    def __init__(self, manifest: RuntimeCapabilityManifest) -> None:
        if manifest.environment != "dev":
            raise ValueError("policy router is restricted to dev")
        if manifest.external_listener_enabled:
            raise ValueError("policy router forbids external listeners")
        if not manifest.capability_enabled("conversation"):
            raise ValueError("policy router requires conversation capability")
        if any(
            manifest.authorizations[name]
            for name in ("tools", "external_network_listener")
        ):
            raise ValueError("policy router received unsafe runtime authorizations")
        read_only_memory = (
            is_owner_memory_response_scope(manifest.response_scope)
            and manifest.capability_enabled("long_term_memory_read")
            and not manifest.capability_enabled("long_term_memory_write")
        )
        owner_confirmed_profile_write = (
            manifest.response_scope == OWNER_PRIVATE_PROFILE_WRITE_V1_SCOPE
            and manifest.capability_enabled("long_term_memory_read")
            and manifest.capability_enabled("long_term_memory_write")
        )
        if manifest.authorizations["real_memory"] and not (
            read_only_memory or owner_confirmed_profile_write
        ):
            raise ValueError("policy router received unsafe real-memory authorization")
        for profile in (manifest.default_model, manifest.escalation_model):
            spec = get_model_spec(profile.model, provider=profile.provider)
            if profile.thinking == "enabled" and not spec.supports_thinking:
                raise ValueError("model profile enables unsupported thinking")
        self.manifest = manifest

    def decide(self, request: RoutingRequest) -> RouteDecision:
        blocked = tuple(
            sorted(
                capability
                for capability in request.requested_capabilities
                if not self.manifest.capability_enabled(capability)
            )
        )
        if blocked:
            return RouteDecision(
                action="block",
                route_reason="policy_block_unavailable_capability",
                provider=None,
                model=None,
                thinking=None,
                max_repair_attempts=0,
                blocked_capabilities=blocked,
            )

        use_escalation = False
        reason = "policy_flash_default"
        if request.task_class in self.manifest.pro_task_classes:
            use_escalation = True
            reason = f"policy_pro_{request.task_class}"
        elif request.repair_failed:
            use_escalation = True
            reason = "policy_pro_repair_failed"
        elif (
            request.prior_fast_failures
            >= self.manifest.fast_failures_before_escalation
        ):
            use_escalation = True
            reason = "policy_pro_repeated_fast_failure"
        elif request.user_requested_high_quality:
            use_escalation = True
            reason = "policy_pro_user_quality_request"
        elif request.risk_level == "high" and self.manifest.high_risk_uses_escalation:
            use_escalation = True
            reason = "policy_pro_high_risk_review"

        profile = (
            self.manifest.escalation_model
            if use_escalation
            else self.manifest.default_model
        )
        return RouteDecision(
            action="route",
            route_reason=reason,
            provider=profile.provider,
            model=profile.model,
            thinking=profile.thinking,
            max_repair_attempts=self.manifest.max_repair_attempts,
        )
