from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit
import json

from .base import ModelRequest, ModelResponse, ProviderError
from .registry import get_model_spec
from .transport import (
    JsonTransport,
    LOCAL_PROVIDER_PORT,
    LoopbackUrllibJsonTransport,
    TransportFailure,
    TransportResponse,
)


LOCAL_MODEL_ALIAS = "myuna-local-owner-v1"
LOCAL_MAX_INPUT_CHARACTERS = 14_000
LOCAL_CONTEXT_PROJECTION_NOTICE = (
    "\n\n[Bounded local context]\n"
    "Older complete turns were omitted; system policy and the final user message "
    "remain authoritative."
)
_FINISH_REASONS = frozenset({"stop", "length"})
_HTTP_ERRORS = {
    400: ("invalid_request", False),
    404: ("model_unavailable", False),
    408: ("local_timeout", True),
    429: ("local_busy", True),
    500: ("local_server_error", True),
    502: ("local_server_error", True),
    503: ("local_unavailable", True),
    504: ("local_timeout", True),
}


@dataclass(frozen=True, slots=True)
class LocalInputProjection:
    request: ModelRequest
    applied: bool
    name: str
    original_input_characters: int
    omitted_message_count: int
    omitted_input_characters: int


def project_local_request(request: ModelRequest) -> LocalInputProjection:
    """Keep one trusted system prompt and the newest complete conversation turns."""

    messages = request.messages
    original_characters = sum(len(message["content"]) for message in messages)
    if request.input_projection in {
        "owner_profile_bounded_v1",
        "local_repair_bounded_v1",
    }:
        tail_count = request.input_projection_tail_messages
        projected_messages = (messages[0], *messages[-tail_count:])
        retained_characters = sum(
            len(message["content"]) for message in projected_messages
        )
        return LocalInputProjection(
            request=replace(request, messages=projected_messages),
            applied=True,
            name=request.input_projection,
            original_input_characters=original_characters,
            omitted_message_count=len(messages) - len(projected_messages),
            omitted_input_characters=(
                original_characters - retained_characters
            ),
        )
    unchanged = LocalInputProjection(
        request=request,
        applied=False,
        name="none",
        original_input_characters=original_characters,
        omitted_message_count=0,
        omitted_input_characters=0,
    )
    if original_characters <= LOCAL_MAX_INPUT_CHARACTERS:
        return unchanged
    if (
        len(messages) < 2
        or messages[0]["role"] != "system"
        or messages[-1]["role"] != "user"
        or any(message["role"] == "system" for message in messages[1:])
    ):
        return unchanged

    history = messages[1:-1]
    if len(history) % 2 != 0 or any(
        history[index]["role"] != "user"
        or history[index + 1]["role"] != "assistant"
        for index in range(0, len(history), 2)
    ):
        return unchanged

    projected_system = {
        "role": "system",
        "content": messages[0]["content"] + LOCAL_CONTEXT_PROJECTION_NOTICE,
    }
    final_user = messages[-1]
    protected_characters = len(projected_system["content"]) + len(
        final_user["content"]
    )
    if protected_characters > LOCAL_MAX_INPUT_CHARACTERS:
        return unchanged

    remaining = LOCAL_MAX_INPUT_CHARACTERS - protected_characters
    retained_pairs: list[tuple[Mapping[str, str], Mapping[str, str]]] = []
    for index in range(len(history) - 2, -1, -2):
        pair = (history[index], history[index + 1])
        pair_characters = len(pair[0]["content"]) + len(pair[1]["content"])
        if pair_characters > remaining:
            break
        retained_pairs.append(pair)
        remaining -= pair_characters
    retained_pairs.reverse()
    retained_history = tuple(
        message for pair in retained_pairs for message in pair
    )
    projected_messages = (
        projected_system,
        *retained_history,
        final_user,
    )
    retained_original_characters = (
        len(messages[0]["content"])
        + sum(len(message["content"]) for message in retained_history)
        + len(final_user["content"])
    )
    return LocalInputProjection(
        request=replace(request, messages=projected_messages),
        applied=True,
        name="local_recent_complete_turns_v1",
        original_input_characters=original_characters,
        omitted_message_count=len(messages) - 2 - len(retained_history),
        omitted_input_characters=(
            original_characters - retained_original_characters
        ),
    )


def normalize_loopback_base_url(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("local provider base URL is required")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("local provider base URL is invalid") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or port is None
        or port != LOCAL_PROVIDER_PORT
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path.rstrip("/") != "/v1"
    ):
        raise ValueError("local provider base URL must be explicit loopback HTTP /v1")
    return urlunsplit(("http", f"127.0.0.1:{port}", "/v1", "", ""))


class LocalOpenAIProvider:
    """Strict single-attempt adapter for an explicitly selected loopback runtime."""

    name = "local"

    def __init__(
        self,
        *,
        default_model: str,
        base_url: str,
        transport: JsonTransport | None = None,
        timeout_seconds: float = 120.0,
        max_attempts: int = 1,
    ) -> None:
        get_model_spec(default_model, provider="local")
        if not 1.0 <= timeout_seconds <= 300.0:
            raise ValueError("timeout_seconds must be between 1 and 300")
        if max_attempts != 1:
            raise ValueError("local provider permits exactly one attempt")
        self.default_model = default_model
        self._base_url = normalize_loopback_base_url(base_url)
        self._transport = transport or LoopbackUrllibJsonTransport()
        self._timeout_seconds = timeout_seconds
        self.max_attempts = max_attempts

    def generate(self, request: ModelRequest) -> ModelResponse:
        model_id = request.model or self.default_model
        spec = get_model_spec(model_id, provider="local")
        if request.max_output_tokens > spec.max_output_tokens:
            raise ProviderError(
                "invalid_request",
                "max_output_tokens exceeds the registered local model limit",
                retryable=False,
            )
        if (
            sum(len(message["content"]) for message in request.messages)
            > LOCAL_MAX_INPUT_CHARACTERS
        ):
            raise ProviderError(
                "input_too_large",
                "local provider input exceeds the reviewed limit",
                retryable=False,
            )
        if request.thinking != "disabled" or request.reasoning_effort is not None:
            raise ProviderError(
                "unsupported_thinking",
                "local provider thinking is not authorized",
                retryable=False,
            )
        if request.response_format == "json_object" and not spec.supports_json_output:
            raise ProviderError(
                "unsupported_response_format",
                "local model does not support JSON output",
                retryable=False,
            )
        payload: dict[str, Any] = {
            "model": model_id,
            "messages": [dict(message) for message in request.messages],
            "max_tokens": request.max_output_tokens,
            "stream": False,
        }
        if request.response_format == "json_object":
            payload["response_format"] = {"type": "json_object"}
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "myuna-core-local-provider/1.0",
        }
        try:
            response = self._transport.post_json(
                f"{self._base_url}/chat/completions",
                headers=headers,
                payload=payload,
                timeout_seconds=self._timeout_seconds,
            )
        except TransportFailure as exc:
            raise ProviderError(
                "transport_failure",
                "local provider request failed",
                retryable=True,
                billing_uncertain=False,
                attempts=1,
            ) from exc
        if response.status_code == 200:
            return self._parse_success(response, model_id)
        if 300 <= response.status_code <= 399:
            raise ProviderError(
                "endpoint_redirect_forbidden",
                "local provider redirect was rejected",
                retryable=False,
                status_code=response.status_code,
                attempts=1,
            )
        code, retryable = _HTTP_ERRORS.get(
            response.status_code,
            ("local_http_error", 500 <= response.status_code <= 599),
        )
        raise ProviderError(
            code,
            f"local provider returned HTTP {response.status_code}",
            retryable=retryable,
            status_code=response.status_code,
            billing_uncertain=False,
            attempts=1,
        )

    @staticmethod
    def _parse_success(
        response: TransportResponse,
        requested_model: str,
    ) -> ModelResponse:
        try:
            document = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderError(
                "invalid_response",
                "local provider returned invalid JSON",
                retryable=False,
                attempts=1,
            ) from exc
        try:
            if not isinstance(document, Mapping):
                raise TypeError
            model = _required_string(document, "model")
            if model != requested_model:
                raise ValueError("model mismatch")
            choices = document["choices"]
            if not isinstance(choices, list) or len(choices) != 1:
                raise TypeError
            choice = choices[0]
            if not isinstance(choice, Mapping):
                raise TypeError
            finish_reason = _required_string(choice, "finish_reason")
            if finish_reason not in _FINISH_REASONS:
                raise ValueError("unsupported finish reason")
            message = choice["message"]
            if not isinstance(message, Mapping):
                raise TypeError
            text = _required_string(message, "content")
            usage = document["usage"]
            if not isinstance(usage, Mapping):
                raise TypeError
            input_tokens = _nonnegative_int(usage, "prompt_tokens")
            output_tokens = _nonnegative_int(usage, "completion_tokens")
            details = usage.get("completion_tokens_details", {})
            if details is None:
                details = {}
            if not isinstance(details, Mapping):
                raise TypeError
            reasoning_tokens = _optional_nonnegative_int(
                details,
                "reasoning_tokens",
                0,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderError(
                "invalid_response",
                "local provider response failed schema validation",
                retryable=False,
                attempts=1,
            ) from exc
        return ModelResponse(
            provider="local",
            model=model,
            text=text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_hit_tokens=0,
            cache_miss_tokens=input_tokens,
            reasoning_tokens=reasoning_tokens,
            finish_reason=finish_reason,
            attempts=1,
        )


def _required_string(document: Mapping[str, Any], key: str) -> str:
    value = document[key]
    if not isinstance(value, str) or not value:
        raise TypeError
    return value


def _nonnegative_int(document: Mapping[str, Any], key: str) -> int:
    value = document[key]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TypeError
    return value


def _optional_nonnegative_int(
    document: Mapping[str, Any],
    key: str,
    default: int,
) -> int:
    if key not in document:
        return default
    return _nonnegative_int(document, key)
