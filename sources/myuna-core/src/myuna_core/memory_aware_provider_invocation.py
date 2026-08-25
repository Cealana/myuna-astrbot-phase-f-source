"""Provider-facing invocation seam for the memory-aware turn protocol."""

from __future__ import annotations

from typing import Mapping

from .memory_aware_turn_protocol import (
    FinalBranch,
    MemoryAwareTurnError,
    MemoryRequest,
    TurnStepRequest,
    _bounded_integer,
    _canonical,
    parse_provider_step,
)
from .providers.base import (
    ModelProvider,
    ModelRequest,
    ModelResponse,
    ProviderError,
    request_input_token_upper_bound,
)


_MODEL_INPUT_LIMIT = 200_000


def _provider_messages(
    turn: TurnStepRequest,
    *,
    repair: bool,
) -> tuple[Mapping[str, str], ...]:
    system_message = (
        "Return one strict JSON object matching the supplied memory-aware turn schema. "
        "Choose exactly one memory_request or final branch and preserve every binding."
    )
    user_message = _canonical(turn.provider_payload(repair=repair)).decode("utf-8")
    return (
        {"role": "system", "content": system_message},
        {"role": "user", "content": user_message},
    )


def invoke_provider_step(
    provider: ModelProvider,
    turn: TurnStepRequest,
    *,
    repair: bool = False,
) -> tuple[MemoryRequest | FinalBranch, int]:
    """Invoke one provider step after exact protocol and budget preflight."""

    messages = _provider_messages(turn, repair=repair)
    total_characters = sum(len(message["content"]) for message in messages)
    total_bytes = sum(len(message["content"].encode("utf-8")) for message in messages)
    if total_characters > turn.budget.max_characters or total_bytes > turn.budget.max_utf8_bytes:
        raise MemoryAwareTurnError("provider_input_budget_exhausted")
    request = ModelRequest(
        request_id="memory-turn-" + turn.continuation_digest[:32],
        messages=messages,
        max_output_tokens=turn.budget.output_token_reservation,
        max_input_characters=_MODEL_INPUT_LIMIT,
        thinking="disabled",
        response_format="json_object",
        route_reason="memory_aware_turn_step",
        caller="myuna_core",
    )
    if request_input_token_upper_bound(request) > turn.budget.max_input_token_upper_bound:
        raise MemoryAwareTurnError("provider_input_token_budget_exhausted")
    try:
        response = provider.generate(request)
    except ProviderError as exc:
        attempts = (
            exc.attempts
            if isinstance(exc.attempts, int) and not isinstance(exc.attempts, bool)
            else 1
        )
        raise MemoryAwareTurnError("provider_rejected", attempts=attempts) from None
    if not isinstance(response, ModelResponse):
        raise MemoryAwareTurnError("provider_response_type_invalid", attempts=1)
    attempts = _bounded_integer(
        response.attempts,
        "provider_attempt_count_invalid",
        minimum=1,
        maximum=5,
    )
    if response.output_tokens < 0 or response.output_tokens > turn.budget.output_token_reservation:
        raise MemoryAwareTurnError("provider_output_token_budget_exhausted", attempts=attempts)
    try:
        branch = parse_provider_step(response.text, turn)
    except MemoryAwareTurnError as exc:
        raise MemoryAwareTurnError(
            exc.code,
            attempts=attempts,
            repairable=exc.repairable,
        ) from None
    return branch, attempts
