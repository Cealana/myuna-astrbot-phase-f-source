from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Literal, Mapping, Protocol
import re

from ..prompt_budget import (
    DEFAULT_MODEL_INPUT_MAX_CHARACTERS,
    MAX_MODEL_INPUT_MAX_CHARACTERS,
    PromptBudgetPolicyError,
    validate_model_input_characters,
    validate_model_input_limit,
)


ThinkingMode = Literal["enabled", "disabled"]
ReasoningEffort = Literal["high", "max"]
ResponseFormat = Literal["text", "json_object"]
DefinitionProjection = Literal["full", "local_core_sections"]
InputProjection = Literal[
    "default",
    "owner_profile_bounded_v1",
    "local_repair_bounded_v1",
]

MAX_MESSAGES = 256
MAX_INPUT_CHARACTERS = MAX_MODEL_INPUT_MAX_CHARACTERS
MAX_OUTPUT_TOKENS = 32_768
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_ALLOWED_ROLES = frozenset({"system", "user", "assistant"})


class ProviderError(RuntimeError):
    """A safe, typed provider failure that never includes upstream content."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool,
        status_code: int | None = None,
        billing_uncertain: bool = False,
        attempts: int = 1,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable
        self.status_code = status_code
        self.billing_uncertain = billing_uncertain
        self.attempts = attempts


@dataclass(frozen=True, slots=True)
class ModelRequest:
    request_id: str
    messages: tuple[Mapping[str, str], ...]
    max_output_tokens: int
    max_input_characters: int = DEFAULT_MODEL_INPUT_MAX_CHARACTERS
    model: str | None = None
    thinking: ThinkingMode = "disabled"
    reasoning_effort: ReasoningEffort | None = None
    response_format: ResponseFormat = "text"
    definition_projection: DefinitionProjection = "full"
    input_projection: InputProjection = "default"
    input_projection_tail_messages: int = 0
    route_reason: str = "user_request"
    caller: str = "myuna_core"

    def __post_init__(self) -> None:
        validate_request(self)


@dataclass(frozen=True, slots=True)
class ModelResponse:
    provider: str
    model: str
    text: str
    input_tokens: int
    output_tokens: int
    cache_hit_tokens: int
    cache_miss_tokens: int
    reasoning_tokens: int
    finish_reason: str
    attempts: int = 1
    cost_usd: Decimal | None = None
    budget_accounted_usd: Decimal | None = None


class ModelProvider(Protocol):
    name: str
    default_model: str
    max_attempts: int

    def generate(self, request: ModelRequest) -> ModelResponse:
        """Generate a response or raise ProviderError."""
        ...


def validate_request(request: ModelRequest) -> None:
    if not _IDENTIFIER.fullmatch(request.request_id):
        raise ValueError("request_id must be a safe 1-128 character identifier")
    if not _IDENTIFIER.fullmatch(request.route_reason):
        raise ValueError("route_reason must be a safe 1-128 character label")
    if not _IDENTIFIER.fullmatch(request.caller):
        raise ValueError("caller must be a safe 1-128 character label")
    if request.model is not None and not _IDENTIFIER.fullmatch(request.model):
        raise ValueError("model must be a safe identifier")
    if request.thinking not in {"enabled", "disabled"}:
        raise ValueError("thinking must be enabled or disabled")
    if request.reasoning_effort not in {None, "high", "max"}:
        raise ValueError("reasoning_effort must be high or max")
    if request.thinking == "disabled" and request.reasoning_effort is not None:
        raise ValueError("reasoning_effort requires thinking=enabled")
    if request.response_format not in {"text", "json_object"}:
        raise ValueError("response_format must be text or json_object")
    if request.definition_projection not in {"full", "local_core_sections"}:
        raise ValueError(
            "definition_projection must be full or local_core_sections"
        )
    if request.input_projection not in {
        "default",
        "owner_profile_bounded_v1",
        "local_repair_bounded_v1",
    }:
        raise ValueError(
            "input_projection must be default, owner_profile_bounded_v1, "
            "or local_repair_bounded_v1"
        )
    if request.input_projection == "default":
        if request.input_projection_tail_messages != 0:
            raise ValueError(
                "default input_projection requires zero tail messages"
            )
    elif (
        request.input_projection == "owner_profile_bounded_v1"
        and request.input_projection_tail_messages not in {1, 3, 5}
    ):
        raise ValueError(
            "owner_profile_bounded_v1 requires 1, 3, or 5 tail messages"
        )
    elif (
        request.input_projection == "local_repair_bounded_v1"
        and request.input_projection_tail_messages != 3
    ):
        raise ValueError(
            "local_repair_bounded_v1 requires exactly 3 tail messages"
        )
    if not 1 <= request.max_output_tokens <= MAX_OUTPUT_TOKENS:
        raise ValueError(f"max_output_tokens must be between 1 and {MAX_OUTPUT_TOKENS}")
    try:
        validate_model_input_limit(request.max_input_characters)
    except PromptBudgetPolicyError as exc:
        raise ValueError(str(exc)) from None
    if not 1 <= len(request.messages) <= MAX_MESSAGES:
        raise ValueError(f"messages must contain between 1 and {MAX_MESSAGES} entries")

    total_characters = 0
    mentions_json = False
    for message in request.messages:
        if set(message) != {"role", "content"}:
            raise ValueError("each message must contain only role and content")
        role = message.get("role")
        content = message.get("content")
        if role not in _ALLOWED_ROLES:
            raise ValueError("provider dev accepts only system, user, and assistant roles")
        if not isinstance(content, str) or not content:
            raise ValueError("message content must be a non-empty string")
        total_characters += len(content)
        mentions_json = mentions_json or "json" in content.casefold()
    if request.input_projection in {
        "owner_profile_bounded_v1",
        "local_repair_bounded_v1",
    }:
        tail_count = request.input_projection_tail_messages
        if (
            len(request.messages) < tail_count + 1
            or request.messages[0]["role"] != "system"
            or any(message["role"] == "system" for message in request.messages[1:])
        ):
            raise ValueError(
                "bounded input projection requires one leading system message"
            )
        expected_tail_roles = tuple(
            "user" if index % 2 == 0 else "assistant"
            for index in range(tail_count)
        )
        actual_tail_roles = tuple(
            message["role"] for message in request.messages[-tail_count:]
        )
        if actual_tail_roles != expected_tail_roles:
            raise ValueError(
                "bounded input projection tail must alternate user and assistant"
            )
    try:
        validate_model_input_characters(
            total_characters,
            max_characters=request.max_input_characters,
        )
    except PromptBudgetPolicyError as exc:
        raise ValueError(str(exc)) from None
    if request.response_format == "json_object" and not mentions_json:
        raise ValueError("json_object requests must explicitly instruct the model to produce JSON")


def request_input_token_upper_bound(request: ModelRequest) -> int:
    """Conservative preflight estimate used only for budget reservation."""

    message_bytes = sum(len(message["content"].encode("utf-8")) for message in request.messages)
    framing_allowance = 32 * len(request.messages) + 64
    return message_bytes + framing_allowance
