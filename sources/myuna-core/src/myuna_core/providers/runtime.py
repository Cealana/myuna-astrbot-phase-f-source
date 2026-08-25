from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Mapping
import os

from myuna_core.audit import AuditLogger

from .audited import AuditedBudgetedProvider, AuditedLocalProvider
from .budget import DailyBudgetLedger
from .credentials import load_systemd_credential
from .deepseek import DeepSeekProvider
from .local import LOCAL_MODEL_ALIAS, LocalOpenAIProvider, normalize_loopback_base_url
from .registry import get_model_spec


CORE_RUNTIME_MAX_ATTEMPTS = 1


@dataclass(frozen=True, slots=True)
class DeepSeekRuntimeSettings:
    model: str
    daily_budget_usd: Decimal
    timeout_seconds: float
    max_attempts: int
    live_calls_enabled: bool


@dataclass(frozen=True, slots=True)
class LocalRuntimeSettings:
    model: str
    base_url: str
    timeout_seconds: float
    max_attempts: int
    live_calls_enabled: bool


def _live_calls_enabled(source: Mapping[str, str]) -> bool:
    live_raw = source.get("MYUNA_PROVIDER_LIVE_CALLS_ENABLED", "false").strip().lower()
    if live_raw not in {"true", "false"}:
        raise ValueError("MYUNA_PROVIDER_LIVE_CALLS_ENABLED must be true or false")
    return live_raw == "true"


def load_deepseek_runtime_settings(
    environ: Mapping[str, str] | None = None,
) -> DeepSeekRuntimeSettings:
    source = os.environ if environ is None else environ
    model = source.get("MYUNA_DEEPSEEK_MODEL", "deepseek-v4-flash").strip()
    get_model_spec(model)
    try:
        budget = Decimal(source.get("MYUNA_DEEPSEEK_DAILY_BUDGET_USD", "1.00"))
    except InvalidOperation as exc:
        raise ValueError("MYUNA_DEEPSEEK_DAILY_BUDGET_USD must be a decimal") from exc
    if not budget.is_finite() or not Decimal("0.01") <= budget <= Decimal("100"):
        raise ValueError("MYUNA_DEEPSEEK_DAILY_BUDGET_USD must be between 0.01 and 100")
    try:
        timeout = float(source.get("MYUNA_DEEPSEEK_TIMEOUT_SECONDS", "60"))
    except ValueError as exc:
        raise ValueError("MYUNA_DEEPSEEK_TIMEOUT_SECONDS must be numeric") from exc
    if not 1 <= timeout <= 300:
        raise ValueError("MYUNA_DEEPSEEK_TIMEOUT_SECONDS must be between 1 and 300")
    try:
        configured_attempts = int(source.get("MYUNA_DEEPSEEK_MAX_ATTEMPTS", "2"))
    except ValueError as exc:
        raise ValueError("MYUNA_DEEPSEEK_MAX_ATTEMPTS must be an integer") from exc
    if not 1 <= configured_attempts <= 3:
        raise ValueError("MYUNA_DEEPSEEK_MAX_ATTEMPTS must be between 1 and 3")
    return DeepSeekRuntimeSettings(
        model=model,
        daily_budget_usd=budget,
        timeout_seconds=timeout,
        # The Core runtime must fit inside the owner-private Gateway deadline.
        # Keep accepting the reviewed legacy configuration range, but never let
        # runtime construction turn one chat request into multiple provider calls.
        max_attempts=min(configured_attempts, CORE_RUNTIME_MAX_ATTEMPTS),
        live_calls_enabled=_live_calls_enabled(source),
    )


def load_local_runtime_settings(
    environ: Mapping[str, str] | None = None,
) -> LocalRuntimeSettings:
    source = os.environ if environ is None else environ
    model = source.get("MYUNA_LOCAL_PROVIDER_MODEL", LOCAL_MODEL_ALIAS).strip()
    get_model_spec(model, provider="local")
    base_url = normalize_loopback_base_url(
        source.get("MYUNA_LOCAL_PROVIDER_BASE_URL", "").strip()
    )
    try:
        timeout = float(source.get("MYUNA_LOCAL_PROVIDER_TIMEOUT_SECONDS", "120"))
    except ValueError as exc:
        raise ValueError("MYUNA_LOCAL_PROVIDER_TIMEOUT_SECONDS must be numeric") from exc
    if not 1 <= timeout <= 300:
        raise ValueError("MYUNA_LOCAL_PROVIDER_TIMEOUT_SECONDS must be between 1 and 300")
    return LocalRuntimeSettings(
        model=model,
        base_url=base_url,
        timeout_seconds=timeout,
        max_attempts=CORE_RUNTIME_MAX_ATTEMPTS,
        live_calls_enabled=_live_calls_enabled(source),
    )


def build_deepseek_runtime_provider(
    *,
    data_dir: Path,
    audit: AuditLogger,
    environ: Mapping[str, str] | None = None,
) -> AuditedBudgetedProvider:
    settings = load_deepseek_runtime_settings(environ)
    if not settings.live_calls_enabled:
        raise RuntimeError("live provider calls are disabled by configuration")
    api_key = load_systemd_credential(environ=environ)
    raw = DeepSeekProvider(
        api_key=api_key,
        default_model=settings.model,
        timeout_seconds=settings.timeout_seconds,
        max_attempts=settings.max_attempts,
    )
    budget = DailyBudgetLedger(
        data_dir / "provider-budget" / "deepseek.json",
        daily_limit_usd=settings.daily_budget_usd,
    )
    return AuditedBudgetedProvider(raw, budget=budget, audit=audit)


def build_local_runtime_provider(
    *,
    audit: AuditLogger,
    environ: Mapping[str, str] | None = None,
) -> AuditedLocalProvider:
    settings = load_local_runtime_settings(environ)
    if not settings.live_calls_enabled:
        raise RuntimeError("live provider calls are disabled by configuration")
    raw = LocalOpenAIProvider(
        default_model=settings.model,
        base_url=settings.base_url,
        timeout_seconds=settings.timeout_seconds,
        max_attempts=settings.max_attempts,
    )
    return AuditedLocalProvider(raw, audit=audit)
