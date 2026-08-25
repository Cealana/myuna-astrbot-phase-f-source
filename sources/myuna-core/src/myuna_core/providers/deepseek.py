from __future__ import annotations

from collections.abc import Callable
from typing import Any, Mapping
import json
import time

from .base import ModelRequest, ModelResponse, ProviderError
from .registry import DEEPSEEK_BASE_URL, get_model_spec
from .transport import JsonTransport, TransportFailure, TransportResponse, UrllibJsonTransport


_FINISH_REASONS = frozenset(
    {"stop", "length", "content_filter", "tool_calls", "insufficient_system_resource"}
)
_HTTP_ERRORS = {
    400: ("invalid_request", False, False),
    401: ("authentication_failed", False, False),
    402: ("insufficient_balance", False, False),
    422: ("invalid_parameters", False, False),
    429: ("rate_limited", True, False),
    500: ("upstream_server_error", True, True),
    503: ("upstream_overloaded", True, True),
}


class DeepSeekProvider:
    name = "deepseek"

    def __init__(
        self,
        *,
        api_key: str,
        default_model: str,
        transport: JsonTransport | None = None,
        base_url: str = DEEPSEEK_BASE_URL,
        timeout_seconds: float = 60.0,
        max_attempts: int = 2,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not api_key or "\n" in api_key or "\r" in api_key:
            raise ValueError("api_key must be a non-empty single-line value")
        get_model_spec(default_model)
        if base_url.rstrip("/") != DEEPSEEK_BASE_URL:
            raise ValueError("Provider Dev permits only the reviewed DeepSeek base URL")
        if not 1.0 <= timeout_seconds <= 300.0:
            raise ValueError("timeout_seconds must be between 1 and 300")
        if not 1 <= max_attempts <= 3:
            raise ValueError("max_attempts must be between 1 and 3")
        self._api_key = api_key
        self.default_model = default_model
        self._transport = transport or UrllibJsonTransport()
        self._base_url = DEEPSEEK_BASE_URL
        self._timeout_seconds = timeout_seconds
        self.max_attempts = max_attempts
        self._sleep = sleep

    def generate(self, request: ModelRequest) -> ModelResponse:
        model_id = request.model or self.default_model
        spec = get_model_spec(model_id)
        if request.max_output_tokens > spec.max_output_tokens:
            raise ProviderError(
                "invalid_request",
                "max_output_tokens exceeds the registered model limit",
                retryable=False,
            )
        payload = self._build_payload(request, model_id)
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "myuna-core-provider-dev/0.3",
        }

        last_error: ProviderError | None = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                response = self._transport.post_json(
                    f"{self._base_url}/chat/completions",
                    headers=headers,
                    payload=payload,
                    timeout_seconds=self._timeout_seconds,
                )
            except TransportFailure:
                last_error = ProviderError(
                    "transport_failure",
                    "DeepSeek network request failed",
                    retryable=True,
                    billing_uncertain=True,
                    attempts=attempt,
                )
            else:
                if response.status_code == 200:
                    return self._parse_success(response, model_id, attempt)
                last_error = self._map_http_error(response.status_code, attempt)

            if not last_error.retryable or attempt == self.max_attempts:
                raise last_error
            self._sleep(min(0.5 * (2 ** (attempt - 1)), 2.0))

        raise RuntimeError("unreachable")

    @staticmethod
    def _build_payload(request: ModelRequest, model_id: str) -> dict[str, Any]:
        thinking: dict[str, str] = {"type": request.thinking}
        if request.reasoning_effort is not None:
            thinking["reasoning_effort"] = request.reasoning_effort
        return {
            "model": model_id,
            "messages": [dict(message) for message in request.messages],
            "max_tokens": request.max_output_tokens,
            "thinking": thinking,
            "response_format": {"type": request.response_format},
            "stream": False,
        }

    @staticmethod
    def _map_http_error(status_code: int, attempt: int) -> ProviderError:
        code, retryable, uncertain = _HTTP_ERRORS.get(
            status_code,
            (
                "upstream_http_error",
                500 <= status_code <= 599,
                500 <= status_code <= 599,
            ),
        )
        return ProviderError(
            code,
            f"DeepSeek returned HTTP {status_code}",
            retryable=retryable,
            status_code=status_code,
            billing_uncertain=uncertain,
            attempts=attempt,
        )

    @staticmethod
    def _parse_success(
        response: TransportResponse,
        requested_model: str,
        attempts: int,
    ) -> ModelResponse:
        try:
            document = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderError(
                "invalid_response",
                "DeepSeek returned invalid JSON",
                retryable=False,
                billing_uncertain=True,
                attempts=attempts,
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
            if finish_reason not in _FINISH_REASONS or finish_reason == "tool_calls":
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
            cache_hit_tokens = _optional_nonnegative_int(usage, "prompt_cache_hit_tokens", 0)
            cache_miss_tokens = _optional_nonnegative_int(
                usage,
                "prompt_cache_miss_tokens",
                input_tokens - cache_hit_tokens,
            )
            if cache_hit_tokens + cache_miss_tokens != input_tokens:
                raise ValueError("cache usage mismatch")
            details = usage.get("completion_tokens_details", {})
            if details is None:
                details = {}
            if not isinstance(details, Mapping):
                raise TypeError
            reasoning_tokens = _optional_nonnegative_int(details, "reasoning_tokens", 0)
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderError(
                "invalid_response",
                "DeepSeek response failed schema validation",
                retryable=False,
                billing_uncertain=True,
                attempts=attempts,
            ) from exc

        # reasoning_content is intentionally neither returned nor retained.
        return ModelResponse(
            provider="deepseek",
            model=model,
            text=text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_hit_tokens=cache_hit_tokens,
            cache_miss_tokens=cache_miss_tokens,
            reasoning_tokens=reasoning_tokens,
            finish_reason=finish_reason,
            attempts=attempts,
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


def _optional_nonnegative_int(document: Mapping[str, Any], key: str, default: int) -> int:
    if key not in document:
        if default < 0:
            raise ValueError
        return default
    return _nonnegative_int(document, key)
