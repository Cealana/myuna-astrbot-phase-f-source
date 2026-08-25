"""Provider adapters remain opt-in; importing this package performs no network calls."""

from .base import ModelRequest, ModelResponse, ProviderError
from .audited import AuditedBudgetedProvider, AuditedLocalProvider
from .budget import BudgetAccountingError, BudgetExceededError, DailyBudgetLedger
from .credentials import CredentialError, load_systemd_credential
from .deepseek import DeepSeekProvider
from .local import LOCAL_MODEL_ALIAS, LocalOpenAIProvider, normalize_loopback_base_url
from .registry import get_model_spec, registered_models
from .runtime import (
    DeepSeekRuntimeSettings,
    LocalRuntimeSettings,
    build_deepseek_runtime_provider,
    build_local_runtime_provider,
    load_deepseek_runtime_settings,
    load_local_runtime_settings,
)

__all__ = (
    "AuditedBudgetedProvider",
    "AuditedLocalProvider",
    "BudgetAccountingError",
    "BudgetExceededError",
    "CredentialError",
    "DailyBudgetLedger",
    "DeepSeekRuntimeSettings",
    "DeepSeekProvider",
    "LOCAL_MODEL_ALIAS",
    "LocalOpenAIProvider",
    "LocalRuntimeSettings",
    "ModelRequest",
    "ModelResponse",
    "ProviderError",
    "build_deepseek_runtime_provider",
    "build_local_runtime_provider",
    "get_model_spec",
    "load_systemd_credential",
    "load_deepseek_runtime_settings",
    "load_local_runtime_settings",
    "normalize_loopback_base_url",
    "registered_models",
)
