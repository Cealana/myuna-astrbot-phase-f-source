from __future__ import annotations

from typing import Any, Mapping
import json
import unittest

from myuna_core.providers import LocalOpenAIProvider, ModelRequest, ProviderError
from myuna_core.providers.local import (
    LOCAL_MAX_INPUT_CHARACTERS,
    LOCAL_MODEL_ALIAS,
    normalize_loopback_base_url,
)
from myuna_core.providers.transport import TransportFailure, TransportResponse


class FakeTransport:
    def __init__(self, result: TransportResponse | BaseException) -> None:
        self.result = result
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
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def successful_response() -> TransportResponse:
    return TransportResponse(
        200,
        json.dumps(
            {
                "model": LOCAL_MODEL_ALIAS,
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": "synthetic local answer",
                            "reasoning_content": "must not be retained",
                        },
                    }
                ],
                "usage": {
                    "prompt_tokens": 20,
                    "completion_tokens": 4,
                },
            }
        ).encode("utf-8"),
        {},
    )


class LocalOpenAIProviderTests(unittest.TestCase):
    def request(self, **overrides: Any) -> ModelRequest:
        values: dict[str, Any] = {
            "request_id": "local-request-1",
            "messages": ({"role": "user", "content": "synthetic prompt"},),
            "max_output_tokens": 256,
            "route_reason": "normal_chat",
            "model": LOCAL_MODEL_ALIAS,
        }
        values.update(overrides)
        return ModelRequest(**values)

    def provider(self, result: TransportResponse | BaseException) -> LocalOpenAIProvider:
        return LocalOpenAIProvider(
            default_model=LOCAL_MODEL_ALIAS,
            base_url="http://127.0.0.1:879/v1/",
            transport=FakeTransport(result),
        )

    def test_loopback_url_is_literal_bounded_and_canonical(self) -> None:
        self.assertEqual(
            normalize_loopback_base_url("http://127.0.0.1:879/v1/"),
            "http://127.0.0.1:879/v1",
        )
        for unsafe in (
            "https://127.0.0.1:879/v1",
            "http://localhost:879/v1",
            "http://127.0.0.1/v1",
            "http://127.0.0.1:11434/v1",
            "http://127.0.0.1:879/v2",
            "http://user@127.0.0.1:879/v1",
            "http://127.0.0.1:879/v1?redirect=1",
        ):
            with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                normalize_loopback_base_url(unsafe)

    def test_payload_has_no_credential_and_response_is_strict(self) -> None:
        transport = FakeTransport(successful_response())
        provider = LocalOpenAIProvider(
            default_model=LOCAL_MODEL_ALIAS,
            base_url="http://127.0.0.1:879/v1",
            transport=transport,
        )
        response = provider.generate(self.request())
        self.assertEqual(response.provider, "local")
        self.assertEqual(response.text, "synthetic local answer")
        self.assertEqual(response.cost_usd, None)
        call = transport.calls[0]
        self.assertEqual(
            call["url"],
            "http://127.0.0.1:879/v1/chat/completions",
        )
        self.assertNotIn("Authorization", call["headers"])
        self.assertEqual(call["payload"]["stream"], False)
        self.assertNotIn("thinking", call["payload"])
        self.assertNotIn("response_format", call["payload"])

    def test_thinking_retry_and_redirect_are_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "exactly one attempt"):
            LocalOpenAIProvider(
                default_model=LOCAL_MODEL_ALIAS,
                base_url="http://127.0.0.1:879/v1",
                max_attempts=2,
            )
        with self.assertRaises(ProviderError) as thinking:
            self.provider(successful_response()).generate(
                self.request(thinking="enabled", reasoning_effort="high")
            )
        self.assertEqual(thinking.exception.code, "unsupported_thinking")
        with self.assertRaises(ProviderError) as redirect:
            self.provider(TransportResponse(302, b"ignored", {})).generate(
                self.request()
            )
        self.assertEqual(redirect.exception.code, "endpoint_redirect_forbidden")

        with self.assertRaises(ProviderError) as oversized:
            self.provider(successful_response()).generate(
                self.request(
                    messages=(
                        {
                            "role": "user",
                            "content": "x" * (LOCAL_MAX_INPUT_CHARACTERS + 1),
                        },
                    ),
                )
            )
        self.assertEqual(oversized.exception.code, "input_too_large")

    def test_transport_http_and_malformed_response_are_content_free(self) -> None:
        with self.assertRaises(ProviderError) as transport:
            self.provider(TransportFailure("private detail")).generate(self.request())
        self.assertEqual(transport.exception.code, "transport_failure")
        self.assertFalse(transport.exception.billing_uncertain)
        self.assertNotIn("private detail", str(transport.exception))

        with self.assertRaises(ProviderError) as unavailable:
            self.provider(TransportResponse(503, b"private upstream", {})).generate(
                self.request()
            )
        self.assertEqual(unavailable.exception.code, "local_unavailable")
        self.assertNotIn("private upstream", str(unavailable.exception))

        malformed = successful_response()
        document = json.loads(malformed.body)
        document["model"] = "wrong-model"
        with self.assertRaises(ProviderError) as invalid:
            self.provider(
                TransportResponse(200, json.dumps(document).encode("utf-8"), {})
            ).generate(self.request())
        self.assertEqual(invalid.exception.code, "invalid_response")
        self.assertNotIn("wrong-model", str(invalid.exception))


if __name__ == "__main__":
    unittest.main()
