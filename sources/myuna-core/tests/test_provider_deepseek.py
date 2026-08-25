from __future__ import annotations

from typing import Any, Mapping
import json
import unittest

from myuna_core.providers import DeepSeekProvider, ModelRequest, ProviderError
from myuna_core.providers.transport import TransportFailure, TransportResponse


def successful_response(*, model: str = "deepseek-v4-flash") -> TransportResponse:
    document = {
        "id": "mock-completion",
        "object": "chat.completion",
        "model": model,
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": "mock answer",
                    "reasoning_content": "must never be retained",
                },
            }
        ],
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 20,
            "prompt_cache_hit_tokens": 40,
            "prompt_cache_miss_tokens": 60,
            "total_tokens": 120,
            "completion_tokens_details": {"reasoning_tokens": 7},
        },
    }
    return TransportResponse(200, json.dumps(document).encode(), {})


class FakeTransport:
    def __init__(self, results: list[TransportResponse | BaseException]) -> None:
        self.results = results
        self.calls: list[dict[str, Any]] = []

    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        payload: Mapping[str, Any],
        timeout_seconds: float,
    ) -> TransportResponse:
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers),
                "payload": dict(payload),
                "timeout_seconds": timeout_seconds,
            }
        )
        result = self.results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


class DeepSeekProviderTests(unittest.TestCase):
    def request(self, **overrides: Any) -> ModelRequest:
        values: dict[str, Any] = {
            "request_id": "request-1",
            "messages": ({"role": "user", "content": "hello"},),
            "max_output_tokens": 100,
            "route_reason": "normal_chat",
        }
        values.update(overrides)
        return ModelRequest(**values)

    def test_payload_explicitly_disables_thinking_and_response_is_strictly_parsed(self) -> None:
        transport = FakeTransport([successful_response()])
        provider = DeepSeekProvider(
            api_key="mock-secret-key",
            default_model="deepseek-v4-flash",
            transport=transport,
            sleep=lambda _: None,
        )
        response = provider.generate(self.request())

        self.assertEqual(response.text, "mock answer")
        self.assertEqual(response.reasoning_tokens, 7)
        self.assertEqual(response.attempts, 1)
        self.assertEqual(transport.calls[0]["payload"]["thinking"], {"type": "disabled"})
        self.assertEqual(
            transport.calls[0]["headers"]["Authorization"],
            "Bearer mock-secret-key",
        )
        self.assertEqual(transport.calls[0]["url"], "https://api.deepseek.com/chat/completions")

    def test_thinking_effort_and_json_output_are_explicit(self) -> None:
        transport = FakeTransport([successful_response()])
        provider = DeepSeekProvider(
            api_key="mock-secret-key",
            default_model="deepseek-v4-flash",
            transport=transport,
        )
        provider.generate(
            self.request(
                messages=({"role": "user", "content": "Return a JSON object."},),
                thinking="enabled",
                reasoning_effort="max",
                response_format="json_object",
            )
        )
        payload = transport.calls[0]["payload"]
        self.assertEqual(payload["thinking"], {"type": "enabled", "reasoning_effort": "max"})
        self.assertEqual(payload["response_format"], {"type": "json_object"})

    def test_retry_is_bounded_for_retryable_http_status(self) -> None:
        transport = FakeTransport([TransportResponse(503, b"ignored", {}), successful_response()])
        delays: list[float] = []
        provider = DeepSeekProvider(
            api_key="mock-secret-key",
            default_model="deepseek-v4-flash",
            transport=transport,
            max_attempts=2,
            sleep=delays.append,
        )
        response = provider.generate(self.request())
        self.assertEqual(response.attempts, 2)
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual(delays, [0.5])

    def test_authentication_error_is_not_retried(self) -> None:
        transport = FakeTransport([TransportResponse(401, b"do not parse me", {})])
        provider = DeepSeekProvider(
            api_key="mock-secret-key",
            default_model="deepseek-v4-flash",
            transport=transport,
            max_attempts=3,
        )
        with self.assertRaises(ProviderError) as caught:
            provider.generate(self.request())
        self.assertEqual(caught.exception.code, "authentication_failed")
        self.assertFalse(caught.exception.retryable)
        self.assertFalse(caught.exception.billing_uncertain)
        self.assertEqual(len(transport.calls), 1)

    def test_transport_failure_is_typed_and_billing_uncertain(self) -> None:
        transport = FakeTransport([TransportFailure("unsafe detail")])
        provider = DeepSeekProvider(
            api_key="mock-secret-key",
            default_model="deepseek-v4-flash",
            transport=transport,
            max_attempts=1,
        )
        with self.assertRaises(ProviderError) as caught:
            provider.generate(self.request())
        self.assertEqual(caught.exception.code, "transport_failure")
        self.assertTrue(caught.exception.billing_uncertain)
        self.assertNotIn("unsafe detail", str(caught.exception))

    def test_invalid_success_response_is_rejected_without_reasoning_leak(self) -> None:
        body = json.dumps(
            {
                "model": "deepseek-v4-flash",
                "choices": [{"finish_reason": "stop", "message": {"reasoning_content": "secret"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            }
        ).encode()
        provider = DeepSeekProvider(
            api_key="mock-secret-key",
            default_model="deepseek-v4-flash",
            transport=FakeTransport([TransportResponse(200, body, {})]),
        )
        with self.assertRaises(ProviderError) as caught:
            provider.generate(self.request())
        self.assertEqual(caught.exception.code, "invalid_response")
        self.assertNotIn("secret", str(caught.exception))

    def test_request_validation_rejects_uninstructed_json_and_tool_role(self) -> None:
        with self.assertRaises(ValueError):
            self.request(response_format="json_object")
        with self.assertRaises(ValueError):
            self.request(messages=({"role": "tool", "content": "unsafe"},))


if __name__ == "__main__":
    unittest.main()
