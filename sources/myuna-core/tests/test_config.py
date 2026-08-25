from __future__ import annotations

import unittest

from myuna_core.config import ConfigurationError, load_settings


class SettingsTests(unittest.TestCase):
    def test_safe_defaults_are_not_ready(self) -> None:
        settings = load_settings({})
        self.assertEqual(settings.environment, "dev")
        self.assertEqual(settings.bind_host, "127.0.0.1")
        self.assertFalse(settings.ready)
        self.assertFalse(settings.memory_worker_enabled)
        self.assertTrue(settings.memory_synthetic_only)
        self.assertIsNone(settings.memory_synthetic_fixture)
        self.assertIsNone(settings.memory_synthetic_fixture_sha256)
        self.assertIsNone(settings.memory_synthetic_at)
        self.assertFalse(settings.owner_memory_read_enabled)
        self.assertEqual(settings.http_client_credentials, ())
        self.assertEqual(settings.owner_memory_protocol, "v1")
        self.assertEqual(settings.owner_memory_timeout_ms, 1200)
        self.assertFalse(settings.owner_profile_read_enabled)
        self.assertFalse(settings.owner_profile_write_enabled)
        self.assertEqual(settings.owner_profile_write_timeout_ms, 150000)
        self.assertEqual(settings.owner_profile_provider_allowlist, ())
        self.assertIsNone(settings.owner_profile_capability_profile_path)
        self.assertIsNone(settings.local_provider_base_url)
        self.assertEqual(settings.local_provider_model, "myuna-local-owner-v1")
        self.assertEqual(settings.local_provider_timeout_seconds, 120)
        self.assertEqual(settings.definition_prompt_max_characters, 300000)
        self.assertEqual(settings.model_input_max_characters, 400000)
        self.assertEqual(
            settings.readiness_reasons,
            (
                "no_approved_definition",
                "no_definition_path",
                "no_capability_manifest",
                "no_enabled_provider",
                "no_dev_api_token",
            ),
        )

    def test_provider_list_is_normalized(self) -> None:
        settings = load_settings(
            {
                "MYUNA_ENV": "staging",
                "MYUNA_PORT": "18081",
                "MYUNA_DEFINITION_RELEASE": "v5-test-only",
                "MYUNA_DEFINITION_PATH": "/srv/myuna/environments/dev/definition/current",
                "MYUNA_CAPABILITY_MANIFEST": "/srv/myuna/capabilities/dev.json",
                "MYUNA_PROVIDERS_ENABLED": "OpenAI, deepseek,openai",
                "MYUNA_DEV_TOKEN_CREDENTIAL": "myuna_dev_token",
            }
        )
        self.assertEqual(settings.enabled_providers, ("openai", "deepseek"))
        self.assertTrue(settings.ready)

    def test_local_provider_requires_exact_privileged_loopback_endpoint(self) -> None:
        enabled = load_settings(
            {
                "MYUNA_PROVIDERS_ENABLED": "local",
                "MYUNA_LOCAL_PROVIDER_BASE_URL": "http://127.0.0.1:879/v1/",
                "MYUNA_LOCAL_PROVIDER_TIMEOUT_SECONDS": "90",
            }
        )
        self.assertEqual(
            enabled.local_provider_base_url,
            "http://127.0.0.1:879/v1",
        )
        self.assertEqual(enabled.local_provider_model, "myuna-local-owner-v1")
        self.assertEqual(enabled.local_provider_timeout_seconds, 90)
        invalid = (
            {},
            {"MYUNA_LOCAL_PROVIDER_BASE_URL": "http://127.0.0.1:11434/v1"},
            {"MYUNA_LOCAL_PROVIDER_BASE_URL": "http://localhost:879/v1"},
            {
                "MYUNA_LOCAL_PROVIDER_BASE_URL": "http://127.0.0.1:879/v1",
                "MYUNA_LOCAL_PROVIDER_MODEL": "unknown-local-model",
            },
            {
                "MYUNA_LOCAL_PROVIDER_BASE_URL": "http://127.0.0.1:879/v1",
                "MYUNA_LOCAL_PROVIDER_TIMEOUT_SECONDS": "301",
            },
        )
        for overrides in invalid:
            with self.subTest(overrides=overrides), self.assertRaises(
                ConfigurationError
            ):
                load_settings(
                    {
                        "MYUNA_PROVIDERS_ENABLED": "local",
                        **overrides,
                    }
                )

    def test_channel_scoped_http_credentials_are_parsed_and_ready(self) -> None:
        settings = load_settings(
            {
                "MYUNA_ENV": "dev",
                "MYUNA_DEFINITION_RELEASE": "v5-test-only",
                "MYUNA_DEFINITION_PATH": "/srv/myuna/environments/dev/definition/current",
                "MYUNA_CAPABILITY_MANIFEST": "/srv/myuna/capabilities/dev.json",
                "MYUNA_PROVIDERS_ENABLED": "deepseek",
                "MYUNA_HTTP_CLIENT_CREDENTIALS": (
                    "qq-owner-private:astrbot_qq:qq_owner_core_token,"
                    "telegram-owner-private:astrbot_telegram:"
                    "telegram_owner_core_token"
                ),
            }
        )
        self.assertTrue(settings.ready)
        self.assertIsNone(settings.dev_token_credential)
        self.assertEqual(
            tuple(
                (item.client_id, item.channel_kind, item.credential_name)
                for item in settings.http_client_credentials
            ),
            (
                ("qq-owner-private", "astrbot_qq", "qq_owner_core_token"),
                (
                    "telegram-owner-private",
                    "astrbot_telegram",
                    "telegram_owner_core_token",
                ),
            ),
        )

    def test_legacy_and_channel_scoped_http_credentials_cannot_mix(self) -> None:
        with self.assertRaises(ConfigurationError):
            load_settings(
                {
                    "MYUNA_DEV_TOKEN_CREDENTIAL": "qq_owner_core_token",
                    "MYUNA_HTTP_CLIENT_CREDENTIALS": (
                        "qq-owner-private:astrbot_qq:qq_owner_core_token"
                    ),
                }
            )

    def test_channel_scoped_http_credentials_reject_ambiguous_entries(self) -> None:
        invalid_values = (
            "qq-owner-private:astrbot_qq",
            "qq-owner-private:unknown:qq_owner_core_token",
            (
                "qq-owner-private:astrbot_qq:qq_owner_core_token,"
                "qq-owner-private:astrbot_telegram:telegram_owner_core_token"
            ),
            (
                "qq-owner-private:astrbot_qq:shared,"
                "telegram-owner-private:astrbot_telegram:shared"
            ),
            (
                "qq-owner-private:astrbot_qq:qq_owner_core_token,"
                "telegram-owner-private:astrbot_qq:telegram_owner_core_token"
            ),
        )
        for value in invalid_values:
            with self.subTest(value=value), self.assertRaises(ConfigurationError):
                load_settings({"MYUNA_HTTP_CLIENT_CREDENTIALS": value})

    def test_external_binding_is_rejected(self) -> None:
        with self.assertRaises(ConfigurationError):
            load_settings({"MYUNA_BIND_HOST": "0.0.0.0"})

    def test_invalid_port_is_rejected(self) -> None:
        with self.assertRaises(ConfigurationError):
            load_settings({"MYUNA_PORT": "80"})

    def test_stage5_worker_can_only_be_synthetic_dev(self) -> None:
        worker = {
            "MYUNA_MEMORY_WORKER_ENABLED": "true",
            "MYUNA_MEMORY_SYNTHETIC_FIXTURE": "/srv/myuna/synthetic.jsonl",
            "MYUNA_MEMORY_SYNTHETIC_FIXTURE_SHA256": "A" * 64,
            "MYUNA_MEMORY_SYNTHETIC_AT": "2042-08-01T12:00:00+08:00",
        }
        enabled = load_settings(worker)
        self.assertTrue(enabled.memory_worker_enabled)
        with self.assertRaises(ConfigurationError):
            load_settings(
                {
                    **worker,
                    "MYUNA_ENV": "staging",
                }
            )
        with self.assertRaises(ConfigurationError):
            load_settings(
                {
                    **worker,
                    "MYUNA_MEMORY_SYNTHETIC_ONLY": "false",
                }
            )
        with self.assertRaises(ConfigurationError):
            load_settings({"MYUNA_MEMORY_WORKER_ENABLED": "true"})
        with self.assertRaises(ConfigurationError):
            load_settings(
                {
                    **worker,
                    "MYUNA_MEMORY_SYNTHETIC_AT": "2042-08-01T12:00:00",
                }
            )

    def test_stage5_worker_socket_must_be_absolute(self) -> None:
        with self.assertRaises(ConfigurationError):
            load_settings({"MYUNA_MEMORY_WORKER_SOCKET": "relative.sock"})

    def test_owner_memory_readonly_v1_has_fixed_fail_closed_configuration(self) -> None:
        enabled = load_settings({"MYUNA_OWNER_MEMORY_READ_ENABLED": "true"})
        self.assertTrue(enabled.owner_memory_read_enabled)
        with self.assertRaises(ConfigurationError):
            load_settings(
                {
                    "MYUNA_OWNER_MEMORY_READ_ENABLED": "true",
                    "MYUNA_ENV": "staging",
                }
            )
        with self.assertRaises(ConfigurationError):
            load_settings(
                {
                    "MYUNA_OWNER_MEMORY_READ_ENABLED": "true",
                    "MYUNA_MEMORY_WORKER_ENABLED": "true",
                    "MYUNA_MEMORY_SYNTHETIC_FIXTURE": "/srv/myuna/synthetic.jsonl",
                    "MYUNA_MEMORY_SYNTHETIC_FIXTURE_SHA256": "A" * 64,
                    "MYUNA_MEMORY_SYNTHETIC_AT": "2042-08-01T12:00:00+08:00",
                }
            )
        with self.assertRaises(ConfigurationError):
            load_settings(
                {
                    "MYUNA_OWNER_MEMORY_READ_ENABLED": "true",
                    "MYUNA_OWNER_MEMORY_WORKER_SOCKET": "/run/other.sock",
                }
            )
        with self.assertRaises(ConfigurationError):
            load_settings({"MYUNA_OWNER_MEMORY_TIMEOUT_MS": "5000"})

    def test_owner_memory_readonly_v2_has_distinct_fixed_socket(self) -> None:
        enabled = load_settings(
            {
                "MYUNA_OWNER_MEMORY_READ_ENABLED": "true",
                "MYUNA_OWNER_MEMORY_PROTOCOL": "v2",
            }
        )
        self.assertEqual(enabled.owner_memory_protocol, "v2")
        self.assertEqual(
            str(enabled.owner_memory_worker_socket),
            "/run/myuna-owner-memory-read-v2/worker.sock",
        )
        with self.assertRaises(ConfigurationError):
            load_settings(
                {
                    "MYUNA_OWNER_MEMORY_READ_ENABLED": "true",
                    "MYUNA_OWNER_MEMORY_PROTOCOL": "v2",
                    "MYUNA_OWNER_MEMORY_WORKER_SOCKET": (
                        "/run/myuna-owner-memory-read-v1/worker.sock"
                    ),
                }
            )
        with self.assertRaises(ConfigurationError):
            load_settings({"MYUNA_OWNER_MEMORY_PROTOCOL": "v3"})

    def test_owner_profile_has_fixed_fail_closed_configuration(self) -> None:
        enabled = load_settings(
            {
                "MYUNA_OWNER_PROFILE_READ_ENABLED": "true",
                "MYUNA_OWNER_PROFILE_CAPABILITY_PROFILE": "/srv/profile-capability.json",
                "MYUNA_OWNER_PROFILE_PROVIDER_ALLOWLIST": "local,openai",
            }
        )
        self.assertTrue(enabled.owner_profile_read_enabled)
        self.assertEqual(
            str(enabled.owner_profile_worker_socket),
            "/run/myuna-owner-profile-read-v1/profile.sock",
        )
        self.assertEqual(enabled.owner_profile_timeout_ms, 500)
        self.assertEqual(
            enabled.owner_profile_provider_allowlist,
            ("local", "openai"),
        )
        invalid = (
            {"MYUNA_ENV": "staging"},
            {"MYUNA_OWNER_PROFILE_WORKER_SOCKET": "/run/other.sock"},
            {"MYUNA_OWNER_PROFILE_CAPABILITY_PROFILE": "relative.json"},
            {"MYUNA_OWNER_PROFILE_PROVIDER_ALLOWLIST": "deepseek"},
            {"MYUNA_OWNER_PROFILE_PROVIDER_ALLOWLIST": ""},
            {"MYUNA_OWNER_PROFILE_TIMEOUT_MS": "49"},
            {"MYUNA_OWNER_MEMORY_READ_ENABLED": "true"},
            {
                "MYUNA_MEMORY_WORKER_ENABLED": "true",
                "MYUNA_MEMORY_SYNTHETIC_FIXTURE": "/srv/myuna/synthetic.jsonl",
                "MYUNA_MEMORY_SYNTHETIC_FIXTURE_SHA256": "A" * 64,
                "MYUNA_MEMORY_SYNTHETIC_AT": "2042-08-01T12:00:00+08:00",
            },
        )
        baseline = {
            "MYUNA_OWNER_PROFILE_READ_ENABLED": "true",
            "MYUNA_OWNER_PROFILE_CAPABILITY_PROFILE": "/srv/profile-capability.json",
            "MYUNA_OWNER_PROFILE_PROVIDER_ALLOWLIST": "local",
        }
        for overrides in invalid:
            with self.subTest(overrides=overrides), self.assertRaises(
                ConfigurationError
            ):
                load_settings({**baseline, **overrides})

    def test_owner_profile_write_requires_read_and_local_only_fixed_socket(self) -> None:
        baseline = {
            "MYUNA_OWNER_PROFILE_READ_ENABLED": "true",
            "MYUNA_OWNER_PROFILE_WRITE_ENABLED": "true",
            "MYUNA_OWNER_PROFILE_CAPABILITY_PROFILE": "/srv/profile-capability.json",
            "MYUNA_OWNER_PROFILE_PROVIDER_ALLOWLIST": "local",
        }
        enabled = load_settings(baseline)
        self.assertTrue(enabled.owner_profile_write_enabled)
        self.assertEqual(
            str(enabled.owner_profile_write_worker_socket),
            "/run/myuna-owner-profile-write-v1/profile-write.sock",
        )
        invalid = (
            {"MYUNA_OWNER_PROFILE_READ_ENABLED": "false"},
            {"MYUNA_OWNER_PROFILE_PROVIDER_ALLOWLIST": "local,openai"},
            {
                "MYUNA_OWNER_PROFILE_WRITE_WORKER_SOCKET":
                    "/run/unreviewed-profile-write.sock"
            },
            {"MYUNA_OWNER_PROFILE_WRITE_TIMEOUT_MS": "999"},
            {"MYUNA_OWNER_PROFILE_WRITE_TIMEOUT_MS": "180001"},
        )
        for overrides in invalid:
            with self.subTest(overrides=overrides), self.assertRaises(
                ConfigurationError
            ):
                load_settings({**baseline, **overrides})

    def test_runtime_paths_must_be_absolute(self) -> None:
        with self.assertRaises(ConfigurationError):
            load_settings({"MYUNA_DEFINITION_PATH": "relative"})
        with self.assertRaises(ConfigurationError):
            load_settings({"MYUNA_CAPABILITY_MANIFEST": "relative"})

    def test_http_body_limit_is_bounded(self) -> None:
        self.assertEqual(load_settings({}).http_max_body_bytes, 65536)
        with self.assertRaises(ConfigurationError):
            load_settings({"MYUNA_HTTP_MAX_BODY_BYTES": "100"})

    def test_short_term_context_window_defaults_and_bounds(self) -> None:
        defaults = load_settings({})
        self.assertEqual(defaults.conversation_max_messages, 12)
        self.assertEqual(defaults.conversation_max_characters, 16000)

        expanded = load_settings(
            {
                "MYUNA_CONTEXT_MAX_MESSAGES": "256",
                "MYUNA_CONTEXT_MAX_CHARACTERS": "262144",
            }
        )
        self.assertEqual(expanded.conversation_max_messages, 256)
        self.assertEqual(expanded.conversation_max_characters, 262144)

        for invalid in ("1", "13", "258", "not-an-integer"):
            with self.subTest(max_messages=invalid):
                with self.assertRaises(ConfigurationError):
                    load_settings({"MYUNA_CONTEXT_MAX_MESSAGES": invalid})

    def test_prompt_budget_is_separate_from_short_term_context(self) -> None:
        settings = load_settings(
            {
                "MYUNA_DEFINITION_PROMPT_MAX_CHARACTERS": "360000",
                "MYUNA_MODEL_INPUT_MAX_CHARACTERS": "500000",
            }
        )
        self.assertEqual(settings.definition_prompt_max_characters, 360000)
        self.assertEqual(settings.model_input_max_characters, 500000)
        self.assertEqual(settings.conversation_max_messages, 12)
        self.assertEqual(settings.conversation_max_characters, 16000)

    def test_prompt_budget_rejects_invalid_bounds_and_headroom(self) -> None:
        invalid_environments = (
            {"MYUNA_DEFINITION_PROMPT_MAX_CHARACTERS": "not-an-integer"},
            {"MYUNA_DEFINITION_PROMPT_MAX_CHARACTERS": "109999"},
            {"MYUNA_DEFINITION_PROMPT_MAX_CHARACTERS": "524289"},
            {"MYUNA_MODEL_INPUT_MAX_CHARACTERS": "199999"},
            {"MYUNA_MODEL_INPUT_MAX_CHARACTERS": "700001"},
            {
                "MYUNA_DEFINITION_PROMPT_MAX_CHARACTERS": "300000",
                "MYUNA_MODEL_INPUT_MAX_CHARACTERS": "365535",
            },
        )
        for environment in invalid_environments:
            with self.subTest(environment=environment):
                with self.assertRaises(ConfigurationError):
                    load_settings(environment)


if __name__ == "__main__":
    unittest.main()
