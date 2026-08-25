from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
from hashlib import sha256
from time import monotonic
from typing import Any
import json

from myuna_core.audit import AuditLogger

from .base import ModelProvider, ModelRequest, ModelResponse, ProviderError
from .budget import (
    BudgetAccountingError,
    DailyBudgetLedger,
    actual_cost_usd,
    worst_case_cost_usd,
)
from .local import project_local_request
from .registry import get_model_spec


class AuditedBudgetedProvider:
    """Adds fail-closed budget control and content-free audit metadata."""

    def __init__(
        self,
        provider: ModelProvider,
        *,
        budget: DailyBudgetLedger,
        audit: AuditLogger,
    ) -> None:
        self._provider = provider
        self._budget = budget
        self._audit = audit
        self.name = provider.name
        self.default_model = provider.default_model
        self.max_attempts = provider.max_attempts

    def generate(self, request: ModelRequest) -> ModelResponse:
        model_id = request.model or self.default_model
        spec = get_model_spec(model_id, provider=self.name)
        single_attempt_limit = worst_case_cost_usd(spec, request)
        reservation = single_attempt_limit * self.max_attempts
        reservation_id = f"provider:{request.request_id}"
        metadata = self._request_metadata(
            request,
            model_id,
            reservation,
            provider=self.name,
        )
        try:
            self._budget.reserve(reservation_id, reservation)
        except BudgetAccountingError:
            self._emit_accounting_failure(request.request_id, stage="reserve")
            raise
        self._audit.emit(
            "provider.request",
            request_id=request.request_id,
            details=metadata,
        )
        started = monotonic()
        try:
            response = self._provider.generate(request)
        except ProviderError as exc:
            accounting_error: BudgetAccountingError | None = None
            accounting_stage = "mark_uncertain" if exc.billing_uncertain else "cancel"
            try:
                if exc.billing_uncertain:
                    reason = (
                        "invalid_response"
                        if exc.code == "invalid_response"
                        else "transport_failure"
                        if exc.code == "transport_failure"
                        else "upstream_failure"
                    )
                    self._budget.mark_uncertain(reservation_id, reason=reason)
                else:
                    self._budget.cancel(reservation_id)
            except BudgetAccountingError as caught:
                accounting_error = caught
                self._emit_accounting_failure(
                    request.request_id,
                    stage=accounting_stage,
                )
            self._audit.emit(
                "provider.response",
                outcome="error",
                request_id=request.request_id,
                details={
                    **metadata,
                    "latency_ms": round((monotonic() - started) * 1000, 3),
                    "attempts": exc.attempts,
                    "error_code": exc.code,
                    "retryable": exc.retryable,
                    "status_code": exc.status_code,
                    "billing_uncertain": exc.billing_uncertain,
                },
            )
            if accounting_error is not None:
                raise accounting_error from exc
            raise

        actual = actual_cost_usd(spec, response)
        accounted = actual + single_attempt_limit * (response.attempts - 1)
        try:
            self._budget.settle(reservation_id, accounted)
        except BudgetAccountingError:
            self._emit_accounting_failure(request.request_id, stage="settle")
            raise
        response = replace(response, cost_usd=actual, budget_accounted_usd=accounted)
        self._audit.emit(
            "provider.response",
            request_id=request.request_id,
            details={
                **metadata,
                "latency_ms": round((monotonic() - started) * 1000, 3),
                "attempts": response.attempts,
                "finish_reason": response.finish_reason,
                "input_tokens": response.input_tokens,
                "output_tokens": response.output_tokens,
                "cache_hit_tokens": response.cache_hit_tokens,
                "cache_miss_tokens": response.cache_miss_tokens,
                "reasoning_tokens": response.reasoning_tokens,
                "actual_cost_usd": str(actual),
                "budget_accounted_usd": str(accounted),
                "pricing_snapshot": spec.pricing_snapshot,
            },
        )
        return response

    def _emit_accounting_failure(self, request_id: str, *, stage: str) -> None:
        self._audit.emit(
            "provider.budget_accounting",
            outcome="error",
            request_id=request_id,
            details={
                "classification": "provider_budget_accounting_failed",
                "stage": stage,
            },
        )

    @staticmethod
    def _request_metadata(
        request: ModelRequest,
        model_id: str,
        reservation: Any,
        *,
        provider: str,
    ) -> dict[str, Any]:
        structure = {
            "request_id": request.request_id,
            "roles": [message["role"] for message in request.messages],
            "lengths": [len(message["content"]) for message in request.messages],
            "max_output_tokens": request.max_output_tokens,
            "definition_projection": request.definition_projection,
        }
        fingerprint = sha256(
            json.dumps(structure, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return {
            "provider": provider,
            "model": model_id,
            "request_fingerprint": fingerprint,
            "caller": request.caller,
            "route_reason": request.route_reason,
            "message_count": len(request.messages),
            "input_characters": sum(len(message["content"]) for message in request.messages),
            "max_output_tokens": request.max_output_tokens,
            "thinking": request.thinking,
            "reasoning_effort": request.reasoning_effort,
            "response_format": request.response_format,
            "definition_projection": request.definition_projection,
            "reserved_usd": str(reservation),
        }


class AuditedLocalProvider:
    """Content-free audit wrapper for a zero-billing loopback provider."""

    def __init__(self, provider: ModelProvider, *, audit: AuditLogger) -> None:
        if provider.name != "local":
            raise ValueError("AuditedLocalProvider requires provider=local")
        self._provider = provider
        self._audit = audit
        self.name = provider.name
        self.default_model = provider.default_model
        self.max_attempts = provider.max_attempts

    def generate(self, request: ModelRequest) -> ModelResponse:
        projection = project_local_request(request)
        request = projection.request
        model_id = request.model or self.default_model
        spec = get_model_spec(model_id, provider=self.name)
        metadata = AuditedBudgetedProvider._request_metadata(
            request,
            model_id,
            0,
            provider=self.name,
        )
        metadata.update(
            {
                "input_projection": (
                    projection.name
                ),
                "original_input_characters": (
                    projection.original_input_characters
                ),
                "omitted_message_count": projection.omitted_message_count,
                "omitted_input_characters": projection.omitted_input_characters,
            }
        )
        self._audit.emit(
            "provider.request",
            request_id=request.request_id,
            details=metadata,
        )
        started = monotonic()
        try:
            response = self._provider.generate(request)
        except ProviderError as exc:
            self._audit.emit(
                "provider.response",
                outcome="error",
                request_id=request.request_id,
                details={
                    **metadata,
                    "latency_ms": round((monotonic() - started) * 1000, 3),
                    "attempts": exc.attempts,
                    "error_code": exc.code,
                    "retryable": exc.retryable,
                    "status_code": exc.status_code,
                    "billing_uncertain": False,
                },
            )
            raise
        response = replace(
            response,
            cost_usd=Decimal(0),
            budget_accounted_usd=Decimal(0),
        )
        self._audit.emit(
            "provider.response",
            request_id=request.request_id,
            details={
                **metadata,
                "latency_ms": round((monotonic() - started) * 1000, 3),
                "attempts": response.attempts,
                "finish_reason": response.finish_reason,
                "input_tokens": response.input_tokens,
                "output_tokens": response.output_tokens,
                "cache_hit_tokens": response.cache_hit_tokens,
                "cache_miss_tokens": response.cache_miss_tokens,
                "reasoning_tokens": response.reasoning_tokens,
                "actual_cost_usd": "0",
                "budget_accounted_usd": "0",
                "pricing_snapshot": spec.pricing_snapshot,
            },
        )
        return response
