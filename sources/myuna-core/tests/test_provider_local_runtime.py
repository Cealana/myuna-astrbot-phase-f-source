from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from tempfile import TemporaryDirectory
import json
import unittest

from myuna_core.audit import AuditLogger
from myuna_core.conversation import DevConversationEngine
from myuna_core.providers import (
    AuditedLocalProvider,
    LOCAL_MODEL_ALIAS,
    LocalOpenAIProvider,
    ModelRequest,
    ProviderError,
)
from myuna_core.providers.local import (
    LOCAL_CONTEXT_PROJECTION_NOTICE,
    LOCAL_MAX_INPUT_CHARACTERS,
    normalize_loopback_base_url,
)
from myuna_core.providers.registry import get_model_spec
from myuna_core.providers.runtime import (
    build_local_runtime_provider,
    load_local_runtime_settings,
)
from myuna_core.providers.transport import (
    LoopbackUrllibJsonTransport,
    TransportFailure,
)

from test_provider_local import FakeTransport, successful_response


class ProviderLocalRuntimeTests(unittest.TestCase):
    def test_runtime_requires_explicit_loopback_endpoint_and_defaults_off(self) -> None:
        with self.assertRaisesRegex(ValueError, "base URL is required"):
            load_local_runtime_settings({})
        settings = load_local_runtime_settings(
            {"MYUNA_LOCAL_PROVIDER_BASE_URL": "http://127.0.0.1:879/v1"}
        )
        self.assertEqual(settings.model, LOCAL_MODEL_ALIAS)
        self.assertEqual(settings.max_attempts, 1)
        self.assertFalse(settings.live_calls_enabled)
        self.assertEqual(settings.timeout_seconds, 120)

    def test_runtime_rejects_external_or_ambiguous_endpoint(self) -> None:
        for endpoint in (
            "https://127.0.0.1:879/v1",
            "http://localhost:879/v1",
            "http://192.168.1.2:879/v1",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                load_local_runtime_settings(
                    {"MYUNA_LOCAL_PROVIDER_BASE_URL": endpoint}
                )
        with self.assertRaises(ValueError):
            load_local_runtime_settings(
                {
                    "MYUNA_LOCAL_PROVIDER_BASE_URL": "http://127.0.0.1:879/v1",
                    "MYUNA_PROVIDER_LIVE_CALLS_ENABLED": "yes",
                }
            )

    def test_factory_stops_before_any_call_when_live_calls_are_off(self) -> None:
        with TemporaryDirectory() as temp:
            with self.assertRaisesRegex(RuntimeError, "live provider calls are disabled"):
                build_local_runtime_provider(
                    audit=AuditLogger(Path(temp) / "logs", "dev"),
                    environ={
                        "MYUNA_LOCAL_PROVIDER_BASE_URL": (
                            "http://127.0.0.1:879/v1"
                        )
                    },
                )

    def test_audited_local_provider_is_zero_cost_and_content_free(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            audit = AuditLogger(root / "logs", "dev")
            raw = LocalOpenAIProvider(
                default_model=LOCAL_MODEL_ALIAS,
                base_url="http://127.0.0.1:879/v1",
                transport=FakeTransport(successful_response()),
            )
            provider = AuditedLocalProvider(raw, audit=audit)
            response = provider.generate(
                ModelRequest(
                    request_id="local-audit-1",
                    messages=(
                        {"role": "user", "content": "synthetic private-like prompt"},
                    ),
                    max_output_tokens=256,
                    model=LOCAL_MODEL_ALIAS,
                    route_reason="normal_chat",
                )
            )
            self.assertEqual(response.cost_usd, Decimal(0))
            self.assertEqual(response.budget_accounted_usd, Decimal(0))
            records = [
                json.loads(line)
                for line in audit.path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual([item["event"] for item in records], [
                "provider.request",
                "provider.response",
            ])
            self.assertEqual(records[0]["details"]["provider"], "local")
            self.assertEqual(
                records[0]["details"]["definition_projection"],
                "full",
            )
            self.assertEqual(records[-1]["details"]["actual_cost_usd"], "0")
            serialized = audit.path.read_text(encoding="utf-8")
            self.assertNotIn("synthetic private-like prompt", serialized)
            self.assertNotIn("synthetic local answer", serialized)
            self.assertNotIn("must not be retained", serialized)

    def test_audited_local_provider_projects_only_recent_complete_turns(self) -> None:
        with TemporaryDirectory() as temp:
            audit = AuditLogger(Path(temp) / "logs", "dev")
            transport = FakeTransport(successful_response())
            raw = LocalOpenAIProvider(
                default_model=LOCAL_MODEL_ALIAS,
                base_url="http://127.0.0.1:879/v1",
                transport=transport,
            )
            provider = AuditedLocalProvider(raw, audit=audit)
            messages: list[dict[str, str]] = [
                {"role": "system", "content": "s" * 10_000}
            ]
            for index in range(40):
                messages.extend(
                    (
                        {"role": "user", "content": f"u{index}-" + "x" * 500},
                        {
                            "role": "assistant",
                            "content": f"a{index}-" + "y" * 500,
                        },
                    )
                )
            messages.append({"role": "user", "content": "final-owner-question"})
            provider.generate(
                ModelRequest(
                    request_id="local-projected-1",
                    messages=tuple(messages),
                    max_output_tokens=256,
                    model=LOCAL_MODEL_ALIAS,
                    definition_projection="local_core_sections",
                    route_reason="normal_chat",
                )
            )

            projected = transport.calls[0]["payload"]["messages"]
            self.assertLess(len(projected), len(messages))
            self.assertLessEqual(
                sum(len(message["content"]) for message in projected),
                LOCAL_MAX_INPUT_CHARACTERS,
            )
            self.assertEqual(projected[0]["role"], "system")
            self.assertIn(LOCAL_CONTEXT_PROJECTION_NOTICE, projected[0]["content"])
            self.assertEqual(projected[-1], messages[-1])
            self.assertEqual(
                [message["role"] for message in projected[1:]],
                ["user", "assistant"] * ((len(projected) - 2) // 2)
                + ["user"],
            )

            records = [
                json.loads(line)
                for line in audit.path.read_text(encoding="utf-8").splitlines()
            ]
            details = records[0]["details"]
            self.assertEqual(
                details["input_projection"],
                "local_recent_complete_turns_v1",
            )
            self.assertEqual(
                details["original_input_characters"],
                sum(len(message["content"]) for message in messages),
            )
            self.assertGreater(details["omitted_message_count"], 0)
            self.assertGreater(details["omitted_input_characters"], 0)
            self.assertEqual(
                details["definition_projection"],
                "local_core_sections",
            )
            self.assertEqual(
                details["input_characters"],
                sum(len(message["content"]) for message in projected),
            )
            serialized = audit.path.read_text(encoding="utf-8")
            self.assertNotIn("final-owner-question", serialized)

    def test_owner_profile_projection_excludes_prior_assistant_context(self) -> None:
        with TemporaryDirectory() as temp:
            audit = AuditLogger(Path(temp) / "logs", "dev")
            transport = FakeTransport(successful_response())
            provider = AuditedLocalProvider(
                LocalOpenAIProvider(
                    default_model=LOCAL_MODEL_ALIAS,
                    base_url="http://127.0.0.1:879/v1",
                    transport=transport,
                ),
                audit=audit,
            )
            prior_wrong_answer = "PRIOR_WRONG_ASSISTANT_ANSWER"
            final_query = "\u8bf7\u53ea\u6839\u636e Profile \u590d\u8ff0\u6211\u7684\u9879\u76ee\u51b3\u7b56\u4f18\u5148\u7ea7"
            messages = (
                {"role": "system", "content": "trusted profile system context"},
                {"role": "user", "content": "old question"},
                {"role": "assistant", "content": prior_wrong_answer},
                {"role": "user", "content": final_query},
            )
            provider.generate(
                ModelRequest(
                    request_id="local-owner-profile-projected-1",
                    messages=messages,
                    max_output_tokens=192,
                    model=LOCAL_MODEL_ALIAS,
                    definition_projection="local_core_sections",
                    input_projection="owner_profile_bounded_v1",
                    input_projection_tail_messages=1,
                    route_reason="normal_chat",
                )
            )

            projected = transport.calls[0]["payload"]["messages"]
            self.assertEqual(
                projected,
                [messages[0], messages[-1]],
            )
            self.assertNotIn(prior_wrong_answer, json.dumps(projected))
            records = [
                json.loads(line)
                for line in audit.path.read_text(encoding="utf-8").splitlines()
            ]
            details = records[0]["details"]
            self.assertEqual(
                details["input_projection"],
                "owner_profile_bounded_v1",
            )
            self.assertEqual(details["omitted_message_count"], 2)
            self.assertGreater(details["omitted_input_characters"], 0)
            serialized = audit.path.read_text(encoding="utf-8")
            self.assertNotIn(prior_wrong_answer, serialized)
            self.assertNotIn(final_query, serialized)

    def test_owner_profile_repair_projection_keeps_only_current_exchange(self) -> None:
        with TemporaryDirectory() as temp:
            transport = FakeTransport(successful_response())
            provider = AuditedLocalProvider(
                LocalOpenAIProvider(
                    default_model=LOCAL_MODEL_ALIAS,
                    base_url="http://127.0.0.1:879/v1",
                    transport=transport,
                ),
                audit=AuditLogger(Path(temp) / "logs", "dev"),
            )
            messages = (
                {"role": "system", "content": "trusted profile context"},
                {"role": "user", "content": "stale question"},
                {"role": "assistant", "content": "stale wrong answer"},
                {"role": "user", "content": "current profile question"},
                {"role": "assistant", "content": "candidate answer"},
                {"role": "user", "content": "repair instruction"},
            )
            provider.generate(
                ModelRequest(
                    request_id="local-owner-profile-repair-projected-1",
                    messages=messages,
                    max_output_tokens=192,
                    model=LOCAL_MODEL_ALIAS,
                    input_projection="owner_profile_bounded_v1",
                    input_projection_tail_messages=3,
                    route_reason="normal_chat_repair",
                )
            )
            self.assertEqual(
                transport.calls[0]["payload"]["messages"],
                [messages[0], *messages[-3:]],
            )

    def test_local_repair_projection_is_explicit_and_bounded(self) -> None:
        with TemporaryDirectory() as temp:
            audit = AuditLogger(Path(temp) / "logs", "dev")
            transport = FakeTransport(successful_response())
            provider = AuditedLocalProvider(
                LocalOpenAIProvider(
                    default_model=LOCAL_MODEL_ALIAS,
                    base_url="http://127.0.0.1:879/v1",
                    transport=transport,
                ),
                audit=audit,
            )
            messages: list[dict[str, str]] = [
                {"role": "system", "content": "s" * 5_000}
            ]
            for index in range(63):
                messages.extend(
                    (
                        {"role": "user", "content": f"u{index}" + "u" * 80},
                        {
                            "role": "assistant",
                            "content": f"a{index}" + "a" * 80,
                        },
                    )
                )
            messages.extend(
                (
                    {"role": "user", "content": "current ordinary question"},
                    {"role": "assistant", "content": "rejected echo candidate"},
                    {"role": "user", "content": "bounded repair instruction"},
                )
            )
            self.assertGreater(
                sum(len(message["content"]) for message in messages),
                14_000,
            )

            provider.generate(
                ModelRequest(
                    request_id="local-ordinary-repair-projected-1",
                    messages=tuple(messages),
                    max_output_tokens=192,
                    model=LOCAL_MODEL_ALIAS,
                    input_projection="local_repair_bounded_v1",
                    input_projection_tail_messages=3,
                    route_reason="normal_chat_repair",
                )
            )

            self.assertEqual(
                transport.calls[0]["payload"]["messages"],
                [messages[0], *messages[-3:]],
            )
            records = [
                json.loads(line)
                for line in audit.path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(
                records[0]["details"]["input_projection"],
                "local_repair_bounded_v1",
            )
            self.assertEqual(records[0]["details"]["message_count"], 4)
            self.assertEqual(
                records[0]["details"]["omitted_message_count"],
                len(messages) - 4,
            )

    def test_local_repair_projection_honors_final_character_ceiling(self) -> None:
        with TemporaryDirectory() as temp:
            audit = AuditLogger(Path(temp) / "logs", "dev")
            transport = FakeTransport(successful_response())
            provider = AuditedLocalProvider(
                LocalOpenAIProvider(
                    default_model=LOCAL_MODEL_ALIAS,
                    base_url="http://127.0.0.1:879/v1",
                    transport=transport,
                ),
                audit=audit,
            )
            messages = (
                {"role": "system", "content": "s" * 13_500},
                {"role": "user", "content": "u" * 200},
                {"role": "assistant", "content": "a" * 200},
                {"role": "user", "content": "r" * 200},
            )

            with self.assertRaises(ProviderError) as rejected:
                provider.generate(
                    ModelRequest(
                        request_id="local-repair-final-character-ceiling-1",
                        messages=messages,
                        max_output_tokens=192,
                        model=LOCAL_MODEL_ALIAS,
                        input_projection="local_repair_bounded_v1",
                        input_projection_tail_messages=3,
                        route_reason="normal_chat_repair",
                    )
                )

            self.assertEqual(rejected.exception.code, "input_too_large")
            self.assertEqual(transport.calls, [])
            records = [
                json.loads(line)
                for line in audit.path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(records[0]["event"], "provider.request")
            self.assertEqual(records[0]["details"]["message_count"], 4)
            self.assertEqual(records[0]["details"]["input_characters"], 14_100)
            self.assertEqual(records[1]["event"], "provider.response")
            self.assertEqual(records[1]["outcome"], "error")
            self.assertEqual(records[1]["details"]["error_code"], "input_too_large")

    def test_local_repair_projection_contract_rejects_non_three_message_tail(self) -> None:
        with self.assertRaisesRegex(ValueError, "requires exactly 3 tail messages"):
            ModelRequest(
                request_id="local-repair-invalid-tail-count-1",
                messages=(
                    {"role": "system", "content": "trusted system"},
                    {"role": "user", "content": "final user"},
                ),
                max_output_tokens=192,
                model=LOCAL_MODEL_ALIAS,
                input_projection="local_repair_bounded_v1",
                input_projection_tail_messages=1,
            )

    def test_owner_profile_projection_contract_rejects_malformed_tail(self) -> None:
        with self.assertRaisesRegex(ValueError, "tail must alternate"):
            ModelRequest(
                request_id="local-owner-profile-invalid-tail-1",
                messages=(
                    {"role": "system", "content": "trusted system"},
                    {"role": "assistant", "content": "invalid final role"},
                ),
                max_output_tokens=192,
                model=LOCAL_MODEL_ALIAS,
                input_projection="owner_profile_bounded_v1",
                input_projection_tail_messages=1,
            )

    def test_local_projection_accepts_core_sections_sized_protected_prompt(self) -> None:
        with TemporaryDirectory() as temp:
            audit = AuditLogger(Path(temp) / "logs", "dev")
            transport = FakeTransport(successful_response())
            provider = AuditedLocalProvider(
                LocalOpenAIProvider(
                    default_model=LOCAL_MODEL_ALIAS,
                    base_url="http://127.0.0.1:879/v1",
                    transport=transport,
                ),
                audit=audit,
            )
            messages: list[dict[str, str]] = [
                {"role": "system", "content": "s" * 13_500}
            ]
            for index in range(52):
                messages.extend(
                    (
                        {"role": "user", "content": f"u{index}"},
                        {"role": "assistant", "content": f"a{index}"},
                    )
                )
            messages.append({"role": "user", "content": "final"})

            provider.generate(
                ModelRequest(
                    request_id="local-entrypoint-projected-1",
                    messages=tuple(messages),
                    max_output_tokens=256,
                    model=LOCAL_MODEL_ALIAS,
                    definition_projection="local_core_sections",
                    route_reason="normal_chat",
                )
            )

            projected = transport.calls[0]["payload"]["messages"]
            self.assertLessEqual(
                sum(len(message["content"]) for message in projected),
                LOCAL_MAX_INPUT_CHARACTERS,
            )
            self.assertEqual(projected[0]["role"], "system")
            self.assertEqual(projected[-1]["content"], "final")

    def test_local_projection_fails_closed_on_non_turn_history(self) -> None:
        with TemporaryDirectory() as temp:
            audit = AuditLogger(Path(temp) / "logs", "dev")
            transport = FakeTransport(successful_response())
            raw = LocalOpenAIProvider(
                default_model=LOCAL_MODEL_ALIAS,
                base_url="http://127.0.0.1:879/v1",
                transport=transport,
            )
            provider = AuditedLocalProvider(raw, audit=audit)
            with self.assertRaises(ProviderError) as rejected:
                provider.generate(
                    ModelRequest(
                        request_id="local-projection-rejected-1",
                        messages=(
                            {"role": "system", "content": "s" * 10_000},
                            {"role": "user", "content": "x" * 15_000},
                            {"role": "user", "content": "final"},
                        ),
                        max_output_tokens=256,
                        model=LOCAL_MODEL_ALIAS,
                        route_reason="normal_chat",
                    )
                )
            self.assertEqual(rejected.exception.code, "input_too_large")
            self.assertEqual(transport.calls, [])
            records = [
                json.loads(line)
                for line in audit.path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(records[0]["details"]["input_projection"], "none")
            self.assertEqual(records[0]["details"]["omitted_message_count"], 0)
            self.assertEqual(records[-1]["details"]["error_code"], "input_too_large")

    def test_transport_has_independent_loopback_guard(self) -> None:
        transport = LoopbackUrllibJsonTransport()
        for endpoint in (
            "http://example.com/v1/chat/completions",
            "http://127.0.0.1:11434/v1/chat/completions",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(TransportFailure):
                transport.post_json(
                    endpoint,
                    headers={},
                    payload={"synthetic": True},
                    timeout_seconds=1,
                )

    def test_registry_and_conversation_factory_accept_local_alias(self) -> None:
        spec = get_model_spec(LOCAL_MODEL_ALIAS, provider="local")
        self.assertEqual(spec.context_tokens, 32_768)
        self.assertFalse(spec.supports_thinking)
        self.assertEqual(spec.pricing.output_per_million_usd, Decimal(0))

        sentinel = object()
        engine = object.__new__(DevConversationEngine)
        engine.settings = SimpleNamespace(
            enabled_providers=("local",),
            data_dir=Path("/synthetic"),
        )
        engine.audit = object()
        engine._providers = {}
        engine._provider_factory = lambda model: sentinel
        self.assertIs(
            engine._provider_for("local", LOCAL_MODEL_ALIAS),
            sentinel,
        )
        self.assertIs(
            engine._provider_for("local", LOCAL_MODEL_ALIAS),
            sentinel,
        )

    def test_base_url_normalization_has_no_secret_or_path_variance(self) -> None:
        self.assertEqual(
            normalize_loopback_base_url("http://127.0.0.1:879/v1"),
            "http://127.0.0.1:879/v1",
        )


if __name__ == "__main__":
    unittest.main()
