from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal


DEEPSEEK_BASE_URL = "https://api.deepseek.com"
PRICING_SNAPSHOT = "2026-07-15"
LOCAL_RUNTIME_POLICY_SNAPSHOT = "p07-local-loopback-v1"


@dataclass(frozen=True, slots=True)
class ModelPricing:
    cache_hit_input_per_million_usd: Decimal
    cache_miss_input_per_million_usd: Decimal
    output_per_million_usd: Decimal


@dataclass(frozen=True, slots=True)
class ModelSpec:
    provider: str
    model_id: str
    context_tokens: int
    max_output_tokens: int
    supports_thinking: bool
    supports_json_output: bool
    supports_tool_calls: bool
    pricing: ModelPricing
    pricing_snapshot: str


_MODELS = {
    "myuna-local-owner-v1": ModelSpec(
        provider="local",
        model_id="myuna-local-owner-v1",
        context_tokens=32_768,
        max_output_tokens=4_096,
        supports_thinking=False,
        supports_json_output=True,
        supports_tool_calls=False,
        pricing=ModelPricing(
            cache_hit_input_per_million_usd=Decimal("0"),
            cache_miss_input_per_million_usd=Decimal("0"),
            output_per_million_usd=Decimal("0"),
        ),
        pricing_snapshot=LOCAL_RUNTIME_POLICY_SNAPSHOT,
    ),
    "deepseek-v4-flash": ModelSpec(
        provider="deepseek",
        model_id="deepseek-v4-flash",
        context_tokens=1_000_000,
        max_output_tokens=384_000,
        supports_thinking=True,
        supports_json_output=True,
        supports_tool_calls=True,
        pricing=ModelPricing(
            cache_hit_input_per_million_usd=Decimal("0.0028"),
            cache_miss_input_per_million_usd=Decimal("0.14"),
            output_per_million_usd=Decimal("0.28"),
        ),
        pricing_snapshot=PRICING_SNAPSHOT,
    ),
    "deepseek-v4-pro": ModelSpec(
        provider="deepseek",
        model_id="deepseek-v4-pro",
        context_tokens=1_000_000,
        max_output_tokens=384_000,
        supports_thinking=True,
        supports_json_output=True,
        supports_tool_calls=True,
        pricing=ModelPricing(
            cache_hit_input_per_million_usd=Decimal("0.003625"),
            cache_miss_input_per_million_usd=Decimal("0.435"),
            output_per_million_usd=Decimal("0.87"),
        ),
        pricing_snapshot=PRICING_SNAPSHOT,
    ),
}


def get_model_spec(model_id: str, *, provider: str = "deepseek") -> ModelSpec:
    try:
        spec = _MODELS[model_id]
    except KeyError as exc:
        raise ValueError(f"unregistered model: {model_id}") from exc
    if spec.provider != provider:
        raise ValueError(f"model {model_id} is not registered for {provider}")
    return spec


def registered_models(*, provider: str | None = None) -> tuple[ModelSpec, ...]:
    specs = tuple(_MODELS.values())
    if provider is None:
        return specs
    return tuple(spec for spec in specs if spec.provider == provider)
