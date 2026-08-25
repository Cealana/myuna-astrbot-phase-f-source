from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest

from myuna_core.audit import AuditLogger
from myuna_core.authenticated_conversation import (
    SCHEMA_VERSION as AUTHENTICATED_CONTEXT_SCHEMA_VERSION,
    AuthenticatedConversationContext,
)
from myuna_core.config import load_settings
from myuna_core.channel_capability import OWNER_PRIVATE_PROFILE_WRITE_V1_SCOPE
from myuna_core.context_window import ContextWindowPolicy
from myuna_core.conversation import (
    _BASE_REFERENCES,
    _model_output_token_limit,
    _project_local_definition_entrypoint,
    ConversationError,
    ConversationGuardError,
    ConversationInputError,
    DevConversationEngine,
    assemble_runtime_prompt,
    ReplyContractError,
    parse_model_reply_envelope,
    parse_conversation_input,
)
from myuna_core.definition import DefinitionRelease
from myuna_core.definition_profile import V6_PROFILE
from myuna_core.memory.owner_readonly import (
    OWNER_MEMORY_CAPABILITY_SCOPE,
    OWNER_MEMORY_POLICY_V1,
    OwnerMemoryReadError,
    OwnerMemorySelection,
)
from myuna_core.memory.owner_readonly_v2 import OwnerMemoryReadV2Runtime
from myuna_core.memory.runtime_context import SyntheticMemorySelection
from myuna_core.owner_profile.access import (
    OWNER_PROFILE_RUNTIME_CAPABILITY_SCOPE,
)
from myuna_core.owner_profile.contracts import (
    OwnerProfileError,
    RetrievalResult as OwnerProfileRetrievalResult,
    RetrievedProfileSection,
)
from myuna_core.owner_profile.write_runtime import (
    WRITE_RUNTIME_SCOPE,
    OwnerProfileWriteResult,
)
from myuna_core.persona_routing import PersonaRoute
from myuna_core.providers import LOCAL_MODEL_ALIAS, ModelResponse
from myuna_core.providers.local import (
    LOCAL_MAX_INPUT_CHARACTERS,
    project_local_request,
)
from myuna_core.testflight import TestFlightCoordinator, TestFlightHealthSnapshot
from myuna_core.testflight_state import FileTestFlightStateStore


BUILD_ID = "2755db85ca7e-b1-dbc4b229-g9f993b18-a95b4a017-te2e33bb3"
RELEASE_ID = f"v5-{BUILD_ID}"
V6_BUILD_ID = "effective-v6-test-build"
V6_RELEASE_ID = f"v6-{V6_BUILD_ID}"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def make_writable(root: Path) -> None:
    if not root.exists():
        return
    root.chmod(0o750)
    for path in root.rglob("*"):
        path.chmod(0o750 if path.is_dir() else 0o640)


class FakeProvider:
    def __init__(self, model: str, replies: list[str] | None = None) -> None:
        self.model = model
        self.replies = replies or ['{"reply":"在，怎么了？"}']
        self.requests = []

    def generate(self, request):
        self.requests.append(request)
        text = self.replies.pop(0)
        return ModelResponse(
            provider="deepseek",
            model=self.model,
            text=text,
            input_tokens=100,
            output_tokens=10,
            cache_hit_tokens=0,
            cache_miss_tokens=100,
            reasoning_tokens=0,
            finish_reason="stop",
            attempts=1,
            cost_usd=Decimal("0.0001"),
            budget_accounted_usd=Decimal("0.0001"),
        )


class StaticTestFlightHealthSource:
    def __init__(self, value: TestFlightHealthSnapshot) -> None:
        self.value = value

    def snapshot(self) -> TestFlightHealthSnapshot:
        return self.value


class StubMemoryRuntime:
    def retrieve(self, text: str, *, request_id: str) -> SyntheticMemorySelection:
        return SyntheticMemorySelection(
            context="fictional synthetic record: 雾港旧书店位于银杏路九号。",
            hit_ids=("s2-bookshop-corrected",),
            mode_used="hybrid",
            degraded_reason=None,
            fixture_sha256="D" * 64,
        )


class StubOwnerMemoryRuntime:
    def __init__(self, selection: OwnerMemorySelection | None = None) -> None:
        self.selection = selection
        self.error: OwnerMemoryReadError | None = None

    def retrieve(self, text: str, *, request_id: str) -> OwnerMemorySelection:
        if self.error is not None:
            raise self.error
        assert self.selection is not None
        return self.selection


class StubOwnerProfileRuntime:
    def __init__(self, *, section_count: int = 1) -> None:
        self.calls: list[tuple[str, str, str]] = []
        self.section_count = section_count

    def retrieve(
        self,
        text: str,
        *,
        request_id: str,
        channel_kind: str,
    ) -> OwnerProfileRetrievalResult:
        self.calls.append((text, request_id, channel_kind))
        sections = tuple(
            RetrievedProfileSection(
                rank=index + 1,
                category="long_term_preference",
                title=f"Synthetic fixture {index + 1}",
                body=(
                    "SENSITIVE_SYNTHETIC_PROFILE_SENTINEL"
                    if index == 0
                    else f"UNRELATED_SYNTHETIC_PROFILE_{index + 1}"
                ),
                source_ref=(
                    f"owner-profile:synthetic:r1:section-{index + 1}@sha256:"
                    + "A" * 64
                ),
            )
            for index in range(self.section_count)
        )
        return OwnerProfileRetrievalResult(
            state="selected",
            profile_revision=1,
            profile_sha256="A" * 64,
            query_characters=len(text),
            sections=sections,
            context="SENSITIVE_SYNTHETIC_PROFILE_SENTINEL",
        )


class StubOwnerProfileWriteRuntime:
    def __init__(self, *, error: OwnerProfileError | None = None) -> None:
        self.error = error
        self.calls: list[tuple[str, str, AuthenticatedConversationContext | None]] = []

    def handle(
        self,
        text: str,
        *,
        request_id: str,
        authenticated_context: AuthenticatedConversationContext | None,
    ) -> OwnerProfileWriteResult:
        self.calls.append((text, request_id, authenticated_context))
        if self.error is not None:
            raise self.error
        return OwnerProfileWriteResult(
            action="prepared",
            reply="长期记忆候选（尚未写入）\n确认写入：/Benchmark confirm AABBCCDDEEFF",
            memory_write_performed=False,
            target_revision=3,
        )


class ConversationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.release = self.root / "release"
        definition = self.release / "runtime-build/definition"
        definition.mkdir(parents=True)
        (definition / "SKILL.md").write_text("Myuna runtime definition", encoding="utf-8")
        for relative in _BASE_REFERENCES:
            path = definition / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"Definition module {relative}", encoding="utf-8")
        for relative in (
            "references/03-appearance.md",
            "references/04-movement.md",
            "references/13-motivation-notes.md",
            "references/15-v5-changelog.md",
            "references/16-lifestyle-equipment.md",
        ):
            path = definition / relative
            path.write_text(f"Optional module {relative}", encoding="utf-8")
        evidence = self.release / "evidence"
        evidence.mkdir()
        (evidence / "release-summary.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "approved-release",
                    "approved": True,
                    "activation_allowed": True,
                    "release_id": RELEASE_ID,
                    "version": "v5",
                    "build_id": BUILD_ID,
                    "source_sha256": "A" * 64,
                    "allowed_environments": ["dev"],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        files = [
            path.relative_to(self.release).as_posix()
            for path in self.release.rglob("*")
            if path.is_file()
        ]
        (evidence / "release-files.sha256").write_text(
            "".join(f"{sha256(self.release / item)}  {item}\n" for item in sorted(files)),
            encoding="utf-8",
        )
        for path in sorted(self.release.rglob("*"), reverse=True):
            path.chmod(0o550 if path.is_dir() else 0o440)
        self.release.chmod(0o550)

        self.manifest = self.root / "capabilities.json"
        capabilities = {
            name: {
                "enabled": name == "conversation",
                "scope": "authenticated loopback dev" if name == "conversation" else "none",
                "reason": "approved loopback test" if name == "conversation" else "not authorized",
            }
            for name in (
                "conversation",
                "long_term_memory_read",
                "long_term_memory_write",
                "vision",
                "tools",
                "external_data",
                "external_actions",
                "system_administration",
                "qq_channel",
            )
        }
        self.manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "manifest_id": "myuna-dev-capabilities-20260716-v3",
                    "environment": "dev",
                    "definition": {
                        "version": "v5",
                        "build_id": BUILD_ID,
                        "release_active": True,
                    },
                    "service": {
                        "core_active": True,
                        "external_listener_enabled": False,
                        "response_scope": "loopback_dev_only",
                    },
                    "capabilities": capabilities,
                    "models": {
                        "default": {
                            "provider": "deepseek",
                            "model": "deepseek-v4-flash",
                            "thinking": "disabled",
                        },
                        "persona_escalation": {
                            "provider": "deepseek",
                            "model": "deepseek-v4-pro",
                            "thinking": "enabled",
                        },
                    },
                    "routing": {
                        "max_repair_attempts": 1,
                        "fast_failures_before_escalation": 2,
                        "pro_task_classes": [
                            "definition_change",
                            "canon_conflict",
                            "relationship_boundary",
                            "checklist_overload",
                        ],
                        "high_risk_uses_escalation": True,
                    },
                    "authorizations": {
                        "release_activation": True,
                        "service_activation": True,
                        "real_memory": False,
                        "tools": False,
                        "external_network_listener": False,
                    },
                    "source_adrs": ["ADR-012-loopback-dev-core.md"],
                }
            ),
            encoding="utf-8",
        )
        self.settings = load_settings(
            {
                "MYUNA_ENV": "dev",
                "MYUNA_BIND_HOST": "127.0.0.1",
                "MYUNA_PORT": "18080",
                "MYUNA_DATA_DIR": str(self.root / "data"),
                "MYUNA_LOG_DIR": str(self.root / "log"),
                "MYUNA_DEFINITION_RELEASE": RELEASE_ID,
                "MYUNA_DEFINITION_PATH": str(self.release),
                "MYUNA_CAPABILITY_MANIFEST": str(self.manifest),
                "MYUNA_PROVIDERS_ENABLED": "deepseek",
                "MYUNA_DEV_TOKEN_CREDENTIAL": "myuna_dev_token",
            }
        )
        self.audit = AuditLogger(self.root / "log", "dev")

    def tearDown(self) -> None:
        make_writable(self.release)
        self.temporary.cleanup()

    def owner_memory_settings(self, *, protocol: str = "v1"):
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["manifest_id"] = f"myuna-qq-owner-memory-readonly-{protocol}"
        manifest["service"]["response_scope"] = (
            f"qq_owner_private_dev_readonly_memory_{protocol}"
        )
        manifest["capabilities"]["qq_channel"] = {
            "enabled": True,
            "scope": "verified owner private text only",
            "reason": "verified owner binding",
        }
        manifest["capabilities"]["long_term_memory_read"] = {
            "enabled": True,
            "scope": OWNER_MEMORY_CAPABILITY_SCOPE,
            "reason": f"approved read-only Owner Memory {protocol} candidate",
        }
        manifest["authorizations"]["real_memory"] = True
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        return load_settings(
            {
                "MYUNA_ENV": "dev",
                "MYUNA_BIND_HOST": "127.0.0.1",
                "MYUNA_PORT": "18080",
                "MYUNA_DATA_DIR": str(self.root / "data"),
                "MYUNA_LOG_DIR": str(self.root / "log"),
                "MYUNA_DEFINITION_RELEASE": RELEASE_ID,
                "MYUNA_DEFINITION_PATH": str(self.release),
                "MYUNA_CAPABILITY_MANIFEST": str(self.manifest),
                "MYUNA_PROVIDERS_ENABLED": "deepseek",
                "MYUNA_DEV_TOKEN_CREDENTIAL": "myuna_dev_token",
                "MYUNA_OWNER_MEMORY_READ_ENABLED": "true",
                "MYUNA_OWNER_MEMORY_PROTOCOL": protocol,
            }
        )

    def owner_profile_settings(
        self,
        *,
        provider: str = "deepseek",
        max_messages: int = 12,
    ):
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        if provider == "local":
            manifest["models"]["default"] = {
                "provider": "local",
                "model": LOCAL_MODEL_ALIAS,
                "thinking": "disabled",
            }
            manifest["models"]["persona_escalation"] = {
                "provider": "local",
                "model": LOCAL_MODEL_ALIAS,
                "thinking": "disabled",
            }
        manifest["manifest_id"] = "myuna-owner-profile-read-v1-test"
        manifest["service"]["response_scope"] = (
            "owner_private_dev_profile_read_v1"
        )
        manifest["capabilities"]["qq_channel"] = {
            "enabled": True,
            "scope": "verified owner private text only",
            "reason": "verified owner binding",
        }
        manifest["capabilities"]["long_term_memory_read"] = {
            "enabled": True,
            "scope": OWNER_PROFILE_RUNTIME_CAPABILITY_SCOPE,
            "reason": "synthetic Profile integration test",
        }
        manifest["authorizations"]["real_memory"] = True
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        channel_profile = self.root / "owner-profile-capability.json"
        channel_profile.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "profile_id": "owner-private-profile-read-v1",
                    "environment": "dev",
                    "response_scope": "owner_private_dev_profile_read_v1",
                    "subject": {
                        "channel_kinds": ["astrbot_telegram"],
                        "conversation_kinds": ["private"],
                        "authority_levels": ["owner"],
                    },
                    "delivery_capabilities": ["text"],
                    "memory_protocol": "profile-v1",
                    "capabilities": {
                        "conversation": True,
                        "long_term_memory_read": True,
                        "long_term_memory_write": False,
                        "vision": False,
                        "tools": False,
                        "external_data": False,
                        "external_actions": False,
                        "system_administration": False,
                    },
                }
            ),
            encoding="utf-8",
        )
        return load_settings(
            {
                "MYUNA_ENV": "dev",
                "MYUNA_BIND_HOST": "127.0.0.1",
                "MYUNA_PORT": "18080",
                "MYUNA_DATA_DIR": str(self.root / "data"),
                "MYUNA_LOG_DIR": str(self.root / "log"),
                "MYUNA_DEFINITION_RELEASE": RELEASE_ID,
                "MYUNA_DEFINITION_PATH": str(self.release),
                "MYUNA_CAPABILITY_MANIFEST": str(self.manifest),
                "MYUNA_PROVIDERS_ENABLED": provider,
                "MYUNA_LOCAL_PROVIDER_BASE_URL": "http://127.0.0.1:879/v1",
                "MYUNA_DEV_TOKEN_CREDENTIAL": "myuna_dev_token",
                "MYUNA_OWNER_PROFILE_READ_ENABLED": "true",
                "MYUNA_OWNER_PROFILE_CAPABILITY_PROFILE": str(channel_profile),
                "MYUNA_OWNER_PROFILE_PROVIDER_ALLOWLIST": "local",
                "MYUNA_CONTEXT_MAX_MESSAGES": str(max_messages),
            }
        )

    def owner_profile_context(self, suffix: str) -> AuthenticatedConversationContext:
        return AuthenticatedConversationContext(
            schema_version=AUTHENTICATED_CONTEXT_SCHEMA_VERSION,
            request_id=f"gateway-request-{suffix}",
            correlation_id=f"correlation-{suffix}",
            client_id="telegram-owner-private",
            channel_kind="astrbot_telegram",
            binding_id="binding-owner",
            principal_id="principal-owner",
            namespace_id="namespace-owner",
            authority_level="owner",
            channel_instance="telegram-primary",
            conversation_id="conversation-private",
            conversation_kind="private",
            event_id=f"event-{suffix}",
            trace_id=f"trace-{suffix}",
            occurred_at=datetime(2026, 8, 2, tzinfo=timezone.utc),
            delivery_capabilities=("text",),
        )

    def activate_v6_fixture(self):
        make_writable(self.release)
        definition = self.release / "runtime-build/definition"
        (definition / "SKILL.md").write_text(
            "Myuna and Chryna effective v6 runtime definition",
            encoding="utf-8",
        )
        for relative in V6_PROFILE.declared_documents():
            path = definition / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"Effective v6 module {relative}", encoding="utf-8")
        summary = self.release / "evidence/release-summary.json"
        summary.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "approved-release",
                    "approved": True,
                    "activation_allowed": True,
                    "release_id": V6_RELEASE_ID,
                    "version": "v6",
                    "build_id": V6_BUILD_ID,
                    "source_sha256": "B" * 64,
                    "allowed_environments": ["dev"],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        release_manifest = self.release / "evidence/release-files.sha256"
        files = [
            path.relative_to(self.release).as_posix()
            for path in self.release.rglob("*")
            if path.is_file() and path != release_manifest
        ]
        release_manifest.write_text(
            "".join(f"{sha256(self.release / item)}  {item}\n" for item in sorted(files)),
            encoding="utf-8",
        )
        for path in sorted(self.release.rglob("*"), reverse=True):
            path.chmod(0o550 if path.is_dir() else 0o440)
        self.release.chmod(0o550)

        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["definition"] = {
            "version": "v6",
            "build_id": V6_BUILD_ID,
            "release_active": True,
        }
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        self.settings = load_settings(
            {
                "MYUNA_ENV": "dev",
                "MYUNA_BIND_HOST": "127.0.0.1",
                "MYUNA_PORT": "18080",
                "MYUNA_DATA_DIR": str(self.root / "data"),
                "MYUNA_LOG_DIR": str(self.root / "log"),
                "MYUNA_DEFINITION_RELEASE": V6_RELEASE_ID,
                "MYUNA_DEFINITION_PATH": str(self.release),
                "MYUNA_CAPABILITY_MANIFEST": str(self.manifest),
                "MYUNA_PROVIDERS_ENABLED": "deepseek",
                "MYUNA_DEV_TOKEN_CREDENTIAL": "myuna_dev_token",
            }
        )
        return self.settings

    def owner_profile_write_settings(self):
        self.activate_v6_fixture()
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["manifest_id"] = "myuna-owner-profile-write-v1-test"
        manifest["service"]["response_scope"] = (
            OWNER_PRIVATE_PROFILE_WRITE_V1_SCOPE
        )
        manifest["capabilities"]["qq_channel"] = {
            "enabled": True,
            "scope": "verified owner private text only",
            "reason": "verified Owner-private test binding",
        }
        manifest["capabilities"]["long_term_memory_read"] = {
            "enabled": True,
            "scope": OWNER_PROFILE_RUNTIME_CAPABILITY_SCOPE,
            "reason": "synthetic Profile write integration test",
        }
        manifest["capabilities"]["long_term_memory_write"] = {
            "enabled": True,
            "scope": WRITE_RUNTIME_SCOPE,
            "reason": "synthetic Profile write integration test",
        }
        manifest["authorizations"]["real_memory"] = True
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        channel_profile = self.root / "owner-profile-write-capability.json"
        channel_profile.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "profile_id": "owner-private-profile-write-v1",
                    "environment": "dev",
                    "response_scope": OWNER_PRIVATE_PROFILE_WRITE_V1_SCOPE,
                    "subject": {
                        "channel_kinds": ["astrbot_telegram"],
                        "conversation_kinds": ["private"],
                        "authority_levels": ["owner"],
                    },
                    "delivery_capabilities": ["text"],
                    "memory_protocol": "profile-write-v1",
                    "capabilities": {
                        "conversation": True,
                        "long_term_memory_read": True,
                        "long_term_memory_write": True,
                        "vision": False,
                        "tools": False,
                        "external_data": False,
                        "external_actions": False,
                        "system_administration": False,
                    },
                }
            ),
            encoding="utf-8",
        )
        return load_settings(
            {
                "MYUNA_ENV": "dev",
                "MYUNA_BIND_HOST": "127.0.0.1",
                "MYUNA_PORT": "18080",
                "MYUNA_DATA_DIR": str(self.root / "data"),
                "MYUNA_LOG_DIR": str(self.root / "log"),
                "MYUNA_DEFINITION_RELEASE": V6_RELEASE_ID,
                "MYUNA_DEFINITION_PATH": str(self.release),
                "MYUNA_CAPABILITY_MANIFEST": str(self.manifest),
                "MYUNA_PROVIDERS_ENABLED": "deepseek",
                "MYUNA_DEV_TOKEN_CREDENTIAL": "myuna_dev_token",
                "MYUNA_OWNER_PROFILE_READ_ENABLED": "true",
                "MYUNA_OWNER_PROFILE_WRITE_ENABLED": "true",
                "MYUNA_OWNER_PROFILE_CAPABILITY_PROFILE": str(channel_profile),
                "MYUNA_OWNER_PROFILE_PROVIDER_ALLOWLIST": "local",
            }
        )

    def test_owner_memory_v2_protocol_builds_distinct_runtime(self) -> None:
        settings = self.owner_memory_settings(protocol="v2")
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda model: FakeProvider(model),
        )
        self.assertIsInstance(engine.owner_memory_runtime, OwnerMemoryReadV2Runtime)

    def test_benchmark_routes_to_profile_writer_without_chat_provider_call(self) -> None:
        settings = self.owner_profile_write_settings()
        profile_runtime = StubOwnerProfileRuntime()
        write_runtime = StubOwnerProfileWriteRuntime()
        provider = FakeProvider("deepseek-v4-flash")
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda _model: provider,
            owner_profile_runtime=profile_runtime,  # type: ignore[arg-type]
            owner_profile_write_runtime=write_runtime,  # type: ignore[arg-type]
        )
        request_id = "core-http-diary-write-synthetic"
        context = AuthenticatedConversationContext(
            schema_version=AUTHENTICATED_CONTEXT_SCHEMA_VERSION,
            request_id="gateway-diary-write-synthetic",
            correlation_id="diary-correlation-synthetic",
            client_id="telegram-owner-private",
            channel_kind="astrbot_telegram",
            binding_id="binding-synthetic",
            principal_id="principal-synthetic",
            namespace_id="namespace-synthetic",
            authority_level="owner",
            channel_instance="telegram-dev",
            conversation_id="conversation-synthetic",
            conversation_kind="private",
            event_id="event-synthetic",
            trace_id="trace-synthetic",
            occurred_at=datetime(2035, 1, 2, tzinfo=timezone.utc),
            delivery_capabilities=("text",),
            consent_memory_candidate=True,
        )
        result = engine.converse(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": "/Benchmark 我长期偏好直接沟通。",
                    }
                ]
            },
            request_id=request_id,
            authenticated_context=context,
        )
        self.assertEqual(result.route_reason, "v6_benchmark_profile_v1_retired")
        self.assertIn("旧 /Benchmark Profile 写入入口已停用", result.reply)
        self.assertNotIn("我长期偏好直接沟通", result.reply)
        self.assertEqual(write_runtime.calls, [])
        self.assertEqual(result.request_id, request_id)
        self.assertEqual(provider.requests, [])
        self.assertEqual(profile_runtime.calls, [])

    def test_benchmark_writer_failure_is_content_free_and_fail_closed(self) -> None:
        settings = self.owner_profile_write_settings()
        write_runtime = StubOwnerProfileWriteRuntime(
            error=OwnerProfileError("candidate_provider_unavailable", retryable=True)
        )
        provider = FakeProvider("deepseek-v4-flash")
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda _model: provider,
            owner_profile_runtime=StubOwnerProfileRuntime(),  # type: ignore[arg-type]
            owner_profile_write_runtime=write_runtime,  # type: ignore[arg-type]
        )
        result = engine.converse(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": "/Benchmark SYNTHETIC_PRIVATE_SENTINEL",
                    }
                ]
            },
            request_id="diary-failure-synthetic",
        )
        self.assertEqual(result.route_reason, "v6_benchmark_profile_v1_retired")
        self.assertNotIn("SYNTHETIC_PRIVATE_SENTINEL", result.reply)
        self.assertIn("旧 /Benchmark Profile 写入入口已停用", result.reply)
        self.assertEqual(write_runtime.calls, [])
        self.assertEqual(provider.requests, [])

    def test_diary_is_control_only_and_cannot_call_profile_writer(self) -> None:
        settings = self.owner_profile_write_settings()
        write_runtime = StubOwnerProfileWriteRuntime()
        provider = FakeProvider("deepseek-v4-flash")
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda _model: provider,
            owner_profile_write_runtime=write_runtime,  # type: ignore[arg-type]
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "/Diary archive"}]},
            request_id="diary-control-synthetic",
        )
        self.assertEqual(result.route_reason, "v6_diary_control_isolated")
        self.assertEqual(write_runtime.calls, [])
        self.assertEqual(provider.requests, [])

    def test_owner_memory_protocol_requires_matching_capability_scope(self) -> None:
        settings = self.owner_memory_settings(protocol="v2")
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["service"]["response_scope"] = (
            "qq_owner_private_dev_readonly_memory_v1"
        )
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(ConversationError):
            DevConversationEngine(
                settings,
                self.audit,
                provider_factory=lambda model: FakeProvider(model),
            )

    def test_deepseek_route_cannot_read_or_receive_owner_profile(self) -> None:
        profile_runtime = StubOwnerProfileRuntime()
        provider = FakeProvider("deepseek-v4-flash")
        engine = DevConversationEngine(
            self.owner_profile_settings(),
            self.audit,
            provider_factory=lambda model: provider,
            owner_profile_runtime=profile_runtime,  # type: ignore[arg-type]
        )
        context = AuthenticatedConversationContext(
            schema_version=AUTHENTICATED_CONTEXT_SCHEMA_VERSION,
            request_id="gateway-request-1",
            correlation_id="correlation-1",
            client_id="telegram-owner-private",
            channel_kind="astrbot_telegram",
            binding_id="binding-owner",
            principal_id="principal-owner",
            namespace_id="namespace-owner",
            authority_level="owner",
            channel_instance="telegram-primary",
            conversation_id="conversation-private",
            conversation_kind="private",
            event_id="event-1",
            trace_id="trace-1",
            occurred_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
            delivery_capabilities=("text",),
        )
        query = "synthetic Profile integration query"
        engine.converse(
            {"messages": [{"role": "user", "content": query}]},
            request_id="profile-deepseek-denied",
            authenticated_context=context,
        )
        self.assertEqual(profile_runtime.calls, [])
        self.assertEqual(len(provider.requests), 1)
        prompt = provider.requests[0].messages[0]["content"]
        self.assertNotIn("SENSITIVE_SYNTHETIC_PROFILE_SENTINEL", prompt)
        self.assertNotIn("--- Owner Profile read-only context ---", prompt)
        audit_text = (self.root / "log/audit.jsonl").read_text(encoding="utf-8")
        self.assertIn("provider_egress_forbidden", audit_text)
        self.assertIn('"retrieval_attempted": false', audit_text)
        self.assertNotIn(query, audit_text)

    def test_local_selected_owner_profile_requests_bounded_current_turn(self) -> None:
        profile_runtime = StubOwnerProfileRuntime()
        provider = FakeProvider(LOCAL_MODEL_ALIAS)
        engine = DevConversationEngine(
            self.owner_profile_settings(provider="local"),
            self.audit,
            provider_factory=lambda model: provider,
            owner_profile_runtime=profile_runtime,  # type: ignore[arg-type]
        )
        context = AuthenticatedConversationContext(
            schema_version=AUTHENTICATED_CONTEXT_SCHEMA_VERSION,
            request_id="gateway-request-profile-local-1",
            correlation_id="correlation-profile-local-1",
            client_id="telegram-owner-private",
            channel_kind="astrbot_telegram",
            binding_id="binding-owner",
            principal_id="principal-owner",
            namespace_id="namespace-owner",
            authority_level="owner",
            channel_instance="telegram-primary",
            conversation_id="conversation-private",
            conversation_kind="private",
            event_id="event-profile-local-1",
            trace_id="trace-profile-local-1",
            occurred_at=datetime(2026, 8, 2, tzinfo=timezone.utc),
            delivery_capabilities=("text",),
        )
        prior_wrong_answer = "PRIOR_WRONG_ASSISTANT_ANSWER"
        final_query = "\u6211\u505a\u9879\u76ee\u51b3\u7b56\u65f6\u4f18\u5148\u8003\u8651\u4ec0\u4e48\uff1f"
        with patch(
            "myuna_core.conversation._project_local_definition_entrypoint",
            return_value="synthetic local definition",
        ):
            engine.converse(
                {
                    "messages": [
                        {"role": "user", "content": "old profile question"},
                        {"role": "assistant", "content": prior_wrong_answer},
                        {"role": "user", "content": final_query},
                    ]
                },
                request_id="profile-local-bounded-1",
                authenticated_context=context,
            )

        self.assertEqual(len(profile_runtime.calls), 1)
        self.assertEqual(profile_runtime.calls[0][0], final_query)
        self.assertEqual(len(provider.requests), 1)
        model_request = provider.requests[0]
        self.assertEqual(
            model_request.input_projection,
            "owner_profile_bounded_v1",
        )
        self.assertEqual(model_request.input_projection_tail_messages, 1)
        self.assertIn(prior_wrong_answer, model_request.messages[-2]["content"])

    def test_local_incidental_owner_profile_hit_preserves_session_continuity(self) -> None:
        profile_runtime = StubOwnerProfileRuntime()
        provider = FakeProvider(LOCAL_MODEL_ALIAS)
        engine = DevConversationEngine(
            self.owner_profile_settings(provider="local", max_messages=128),
            self.audit,
            provider_factory=lambda model: provider,
            owner_profile_runtime=profile_runtime,  # type: ignore[arg-type]
        )
        context = AuthenticatedConversationContext(
            schema_version=AUTHENTICATED_CONTEXT_SCHEMA_VERSION,
            request_id="gateway-request-profile-incidental-1",
            correlation_id="correlation-profile-incidental-1",
            client_id="telegram-owner-private",
            channel_kind="astrbot_telegram",
            binding_id="binding-owner",
            principal_id="principal-owner",
            namespace_id="namespace-owner",
            authority_level="owner",
            channel_instance="telegram-primary",
            conversation_id="conversation-private",
            conversation_kind="private",
            event_id="event-profile-incidental-1",
            trace_id="trace-profile-incidental-1",
            occurred_at=datetime(2026, 8, 2, tzinfo=timezone.utc),
            delivery_capabilities=("text",),
        )
        recent_user = (
            "\u6211\u548c\u670b\u53cb\u5728\u5916\u9762\u73a9\uff0c"
            "\u521a\u770b\u5b8c\u4e00\u4e2a\u6d3b\u52a8\u3002"
        )
        recent_assistant = "\u542c\u8d77\u6765\u4eca\u5929\u8fc7\u5f97\u5f88\u5145\u5b9e\u3002"
        final_message = (
            "\u6211\u4eec\u521a\u770b\u5b8c\u6d3b\u52a8\uff0c"
            "\u73b0\u5728\u6b63\u5728\u4f11\u606f\u3002"
        )
        older_messages: list[dict[str, str]] = []
        for index in range(55):
            older_messages.extend(
                (
                    {
                        "role": "user",
                        "content": f"older user turn {index} " + "u" * 100,
                    },
                    {
                        "role": "assistant",
                        "content": f"older assistant turn {index} " + "a" * 100,
                    },
                )
            )
        with patch(
            "myuna_core.conversation._project_local_definition_entrypoint",
            return_value="synthetic local definition",
        ):
            engine.converse(
                {
                    "messages": [
                        *older_messages,
                        {"role": "user", "content": recent_user},
                        {"role": "assistant", "content": recent_assistant},
                        {"role": "user", "content": final_message},
                    ]
                },
                request_id="profile-local-incidental-1",
                authenticated_context=context,
            )

        self.assertEqual(len(profile_runtime.calls), 1)
        self.assertEqual(profile_runtime.calls[0][0], final_message)
        self.assertEqual(len(provider.requests), 1)
        model_request = provider.requests[0]
        self.assertEqual(model_request.input_projection, "default")
        self.assertEqual(model_request.input_projection_tail_messages, 0)
        self.assertEqual(
            [message["content"] for message in model_request.messages[-3:]],
            [recent_user, recent_assistant, final_message],
        )
        local_projection = project_local_request(model_request)
        self.assertEqual(local_projection.name, "local_recent_complete_turns_v1")
        self.assertGreater(local_projection.omitted_message_count, 0)
        self.assertEqual(
            [message["content"] for message in local_projection.request.messages[-3:]],
            [recent_user, recent_assistant, final_message],
        )

    def test_unrequested_pure_identity_reply_is_repaired_for_existing_session(self) -> None:
        profile_runtime = StubOwnerProfileRuntime()
        provider = FakeProvider(
            LOCAL_MODEL_ALIAS,
            replies=[
                '{"reply":"Hi\uff0c\u6211\u662f Myuna"}',
                '{"reply":"Sounds like a good time to rest after the event."}',
            ],
        )
        engine = DevConversationEngine(
            self.owner_profile_settings(provider="local"),
            self.audit,
            provider_factory=lambda model: provider,
            owner_profile_runtime=profile_runtime,  # type: ignore[arg-type]
        )
        context = AuthenticatedConversationContext(
            schema_version=AUTHENTICATED_CONTEXT_SCHEMA_VERSION,
            request_id="gateway-request-profile-identity-guard-1",
            correlation_id="correlation-profile-identity-guard-1",
            client_id="telegram-owner-private",
            channel_kind="astrbot_telegram",
            binding_id="binding-owner",
            principal_id="principal-owner",
            namespace_id="namespace-owner",
            authority_level="owner",
            channel_instance="telegram-primary",
            conversation_id="conversation-private",
            conversation_kind="private",
            event_id="event-profile-identity-guard-1",
            trace_id="trace-profile-identity-guard-1",
            occurred_at=datetime(2026, 8, 2, tzinfo=timezone.utc),
            delivery_capabilities=("text",),
        )
        with patch(
            "myuna_core.conversation._project_local_definition_entrypoint",
            return_value="synthetic local definition",
        ):
            result = engine.converse(
                {
                    "messages": [
                        {"role": "user", "content": "I am out with friends."},
                        {"role": "assistant", "content": "Have fun."},
                        {"role": "user", "content": "We finished the event and I am resting."},
                    ]
                },
                request_id="profile-local-identity-guard-1",
                authenticated_context=context,
            )

        self.assertTrue(result.repaired)
        self.assertEqual(
            result.reply,
            "Sounds like a good time to rest after the event",
        )
        self.assertEqual(len(provider.requests), 2)
        self.assertEqual(provider.requests[0].input_projection, "default")
        self.assertEqual(
            provider.requests[1].input_projection,
            "local_repair_bounded_v1",
        )

    def test_local_recent_assistant_echo_is_repaired_for_ordinary_chat(self) -> None:
        prior_bad_reply = (
            "我会先认真思考你的想法，再慢慢分享我的分析，"
            "也会一直愿意倾听你接下来想说的内容"
        )
        provider = FakeProvider(
            LOCAL_MODEL_ALIAS,
            replies=[
                '{"reply":"嗯……我会先认真思考你的想法，再慢慢分享我的分析，'
                '也会一直愿意倾听你接下来想说的内容"}',
                '{"reply":"在呢，我刚刚在整理思路。你呢？"}',
            ],
        )
        engine = DevConversationEngine(
            self.owner_profile_settings(provider="local", max_messages=128),
            self.audit,
            provider_factory=lambda model: provider,
            owner_profile_runtime=StubOwnerProfileRuntime(  # type: ignore[arg-type]
                section_count=0
            ),
        )
        with patch(
            "myuna_core.conversation._project_local_definition_entrypoint",
            return_value="D" * 4_000,
        ):
            result = engine.converse(
                {
                    "messages": [
                        {"role": "user", "content": "我刚从活动现场回来。"},
                        {"role": "assistant", "content": prior_bad_reply},
                        {"role": "user", "content": "嗨 Myuna，你现在在做什么？"},
                    ]
                },
                request_id="profile-local-recent-echo-repair-1",
                authenticated_context=self.owner_profile_context("recent-echo-repair-1"),
            )

        self.assertTrue(result.repaired)
        self.assertEqual(result.reply, "在呢，我刚刚在整理思路。你呢？")
        self.assertEqual(len(provider.requests), 2)
        self.assertIn(
            "recent_assistant_echo_without_continuity",
            provider.requests[1].messages[-1]["content"],
        )
        self.assertEqual(
            provider.requests[1].input_projection,
            "local_repair_bounded_v1",
        )
        self.assertEqual(provider.requests[1].input_projection_tail_messages, 3)
        local_repair = project_local_request(provider.requests[1])
        self.assertLessEqual(
            sum(
                len(message["content"])
                for message in local_repair.request.messages
            ),
            LOCAL_MAX_INPUT_CHARACTERS - 2_000,
        )

    def test_local_recent_assistant_echo_after_repair_uses_bounded_fallback(self) -> None:
        prior_bad_reply = (
            "我会先认真思考你的想法，再慢慢分享我的分析，"
            "也会一直愿意倾听你接下来想说的内容"
        )
        echoed = (
            '{"reply":"唔……我会先认真思考你的想法，再慢慢分享我的分析，'
            '也会一直愿意倾听你接下来想说的内容"}'
        )
        provider = FakeProvider(LOCAL_MODEL_ALIAS, replies=[echoed, echoed])
        engine = DevConversationEngine(
            self.owner_profile_settings(provider="local", max_messages=128),
            self.audit,
            provider_factory=lambda model: provider,
            owner_profile_runtime=StubOwnerProfileRuntime(  # type: ignore[arg-type]
                section_count=0
            ),
        )
        with patch(
            "myuna_core.conversation._project_local_definition_entrypoint",
            return_value="synthetic local definition",
        ):
            result = engine.converse(
                {
                    "messages": [
                        {"role": "user", "content": "我刚从活动现场回来。"},
                        {"role": "assistant", "content": prior_bad_reply},
                        {"role": "user", "content": "嗨 Myuna，你这会儿怎么样？"},
                    ]
                },
                request_id="profile-local-recent-echo-fallback-1",
                authenticated_context=self.owner_profile_context("recent-echo-fallback-1"),
            )

        self.assertTrue(result.repaired)
        self.assertEqual(
            result.reply,
            "刚刚那句话好像没能好好说出来……你再问我一次好不好",
        )
        audit_rows = [
            json.loads(line)
            for line in (self.root / "log/audit.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        fallback = [
            row
            for row in audit_rows
            if row["event"] == "conversation.reply_continuity_fallback"
            and row["details"].get("reason") == "repair_guard_rejected"
        ]
        self.assertEqual(
            fallback[-1]["details"]["discarded_violation_categories"],
            ["recent_assistant_echo_without_continuity"],
        )

    def test_local_stale_assistant_echo_after_fallback_is_repaired(self) -> None:
        prior_bad_reply = (
            "我会先认真思考你的想法，再慢慢分享我的分析，"
            "也会一直愿意倾听你接下来想说的内容"
        )
        provider = FakeProvider(
            LOCAL_MODEL_ALIAS,
            replies=[
                '{"reply":"唔……我会先认真思考你的想法，再慢慢分享我的分析，'
                '也会一直愿意倾听你接下来想说的内容"}',
                '{"reply":"在呢。刚才那句没有接好，你现在想聊什么？"}',
            ],
        )
        engine = DevConversationEngine(
            self.owner_profile_settings(provider="local", max_messages=128),
            self.audit,
            provider_factory=lambda model: provider,
            owner_profile_runtime=StubOwnerProfileRuntime(  # type: ignore[arg-type]
                section_count=0
            ),
        )
        with patch(
            "myuna_core.conversation._project_local_definition_entrypoint",
            return_value="synthetic local definition",
        ):
            result = engine.converse(
                {
                    "messages": [
                        {"role": "user", "content": "我刚从活动现场回来。"},
                        {"role": "assistant", "content": prior_bad_reply},
                        {"role": "user", "content": "你现在在做什么？"},
                        {
                            "role": "assistant",
                            "content": "刚才的回答没有通过检查，请再问我一次。",
                        },
                        {"role": "user", "content": "嗨？"},
                    ]
                },
                request_id="profile-local-stale-echo-repair-1",
                authenticated_context=self.owner_profile_context("stale-echo-repair-1"),
            )

        self.assertTrue(result.repaired)
        self.assertEqual(result.reply, "在呢。刚才那句没有接好，你现在想聊什么？")
        self.assertEqual(len(provider.requests), 2)
        self.assertIn(
            "recent_assistant_echo_without_continuity",
            provider.requests[1].messages[-1]["content"],
        )

    def test_local_stale_assistant_echo_allows_exact_question_repeat(self) -> None:
        repeated_question = "项目修改前要先确定哪些内容？"
        prior_reply = (
            "先明确验收标准和回滚点，再开始复杂项目的实际修改，"
            "这样能让验证和恢复路径保持清楚"
        )
        provider = FakeProvider(LOCAL_MODEL_ALIAS, replies=[f'{{"reply":"{prior_reply}"}}'])
        engine = DevConversationEngine(
            self.owner_profile_settings(provider="local", max_messages=128),
            self.audit,
            provider_factory=lambda model: provider,
            owner_profile_runtime=StubOwnerProfileRuntime(  # type: ignore[arg-type]
                section_count=0
            ),
        )
        with patch(
            "myuna_core.conversation._project_local_definition_entrypoint",
            return_value="synthetic local definition",
        ):
            result = engine.converse(
                {
                    "messages": [
                        {"role": "user", "content": repeated_question},
                        {"role": "assistant", "content": prior_reply},
                        {"role": "user", "content": "先聊点别的。"},
                        {"role": "assistant", "content": "好，你想聊什么？"},
                        {"role": "user", "content": repeated_question},
                    ]
                },
                request_id="profile-local-stale-echo-repeat-question-1",
                authenticated_context=self.owner_profile_context(
                    "stale-echo-repeat-question-1"
                ),
            )

        self.assertFalse(result.repaired)
        self.assertEqual(result.reply, prior_reply)
        self.assertEqual(len(provider.requests), 1)

    def test_local_recent_assistant_echo_allows_explicit_repeat_request(self) -> None:
        prior_reply = (
            "我会先比较效果、可升级性和可维护性，"
            "再一起检查成本、速度以及明确的回滚点"
        )
        provider = FakeProvider(LOCAL_MODEL_ALIAS, replies=[f'{{"reply":"{prior_reply}"}}'])
        engine = DevConversationEngine(
            self.owner_profile_settings(provider="local"),
            self.audit,
            provider_factory=lambda model: provider,
            owner_profile_runtime=StubOwnerProfileRuntime(  # type: ignore[arg-type]
                section_count=0
            ),
        )
        with patch(
            "myuna_core.conversation._project_local_definition_entrypoint",
            return_value="synthetic local definition",
        ):
            result = engine.converse(
                {
                    "messages": [
                        {"role": "user", "content": "你会怎么做项目取舍？"},
                        {"role": "assistant", "content": prior_reply},
                        {"role": "user", "content": "请把你刚才的回答原样重复一遍。"},
                    ]
                },
                request_id="profile-local-recent-echo-explicit-repeat-1",
                authenticated_context=self.owner_profile_context("recent-echo-explicit-repeat-1"),
            )

        self.assertFalse(result.repaired)
        self.assertEqual(result.reply, prior_reply)
        self.assertEqual(len(provider.requests), 1)

    def test_local_recent_assistant_echo_allows_explicit_quote_request(self) -> None:
        prior_reply = (
            "我会先比较效果、可升级性和可维护性，"
            "再一起检查成本、速度以及明确的回滚点"
        )
        provider = FakeProvider(LOCAL_MODEL_ALIAS, replies=[f'{{"reply":"{prior_reply}"}}'])
        engine = DevConversationEngine(
            self.owner_profile_settings(provider="local"),
            self.audit,
            provider_factory=lambda model: provider,
            owner_profile_runtime=StubOwnerProfileRuntime(  # type: ignore[arg-type]
                section_count=0
            ),
        )
        with patch(
            "myuna_core.conversation._project_local_definition_entrypoint",
            return_value="synthetic local definition",
        ):
            result = engine.converse(
                {
                    "messages": [
                        {"role": "user", "content": "你会怎么做项目取舍？"},
                        {"role": "assistant", "content": prior_reply},
                        {"role": "user", "content": "用引号引用你刚才那段话。"},
                    ]
                },
                request_id="profile-local-recent-echo-explicit-quote-1",
                authenticated_context=self.owner_profile_context("recent-echo-explicit-quote-1"),
            )

        self.assertFalse(result.repaired)
        self.assertEqual(result.reply, prior_reply)
        self.assertEqual(len(provider.requests), 1)

    def test_local_recent_assistant_echo_does_not_change_direct_profile_recall(self) -> None:
        prior_reply = (
            "你的合成项目取舍顺序是效果、可升级性、可维护性，"
            "然后再比较成本和速度"
        )
        provider = FakeProvider(LOCAL_MODEL_ALIAS, replies=[f'{{"reply":"{prior_reply}"}}'])
        engine = DevConversationEngine(
            self.owner_profile_settings(provider="local"),
            self.audit,
            provider_factory=lambda model: provider,
            owner_profile_runtime=StubOwnerProfileRuntime(),  # type: ignore[arg-type]
        )
        final_query = "我做项目决策时优先考虑什么？"
        with patch(
            "myuna_core.conversation._project_local_definition_entrypoint",
            return_value="synthetic local definition",
        ):
            result = engine.converse(
                {
                    "messages": [
                        {"role": "user", "content": "之前的顺序是什么？"},
                        {"role": "assistant", "content": prior_reply},
                        {"role": "user", "content": final_query},
                    ]
                },
                request_id="profile-local-recent-echo-direct-profile-1",
                authenticated_context=self.owner_profile_context(
                    "recent-echo-direct-profile-1"
                ),
            )

        self.assertFalse(result.repaired)
        self.assertEqual(result.reply, prior_reply)
        self.assertEqual(len(provider.requests), 1)
        self.assertEqual(provider.requests[0].input_projection, "owner_profile_bounded_v1")

    def test_local_recent_assistant_echo_allows_short_acknowledgement(self) -> None:
        provider = FakeProvider(LOCAL_MODEL_ALIAS, replies=['{"reply":"在呢"}'])
        engine = DevConversationEngine(
            self.owner_profile_settings(provider="local"),
            self.audit,
            provider_factory=lambda model: provider,
            owner_profile_runtime=StubOwnerProfileRuntime(  # type: ignore[arg-type]
                section_count=0
            ),
        )
        with patch(
            "myuna_core.conversation._project_local_definition_entrypoint",
            return_value="synthetic local definition",
        ):
            result = engine.converse(
                {
                    "messages": [
                        {"role": "user", "content": "在吗？"},
                        {"role": "assistant", "content": "在呢"},
                        {"role": "user", "content": "嗨。"},
                    ]
                },
                request_id="profile-local-recent-echo-short-1",
                authenticated_context=self.owner_profile_context("recent-echo-short-1"),
            )

        self.assertFalse(result.repaired)
        self.assertEqual(result.reply, "在呢")

    def test_local_recent_assistant_echo_allows_reasonable_paraphrase(self) -> None:
        prior_reply = (
            "我会先完整分析条件和风险，再把几个可选方案以及各自取舍整理给你"
        )
        candidate = "我想先梳理限制，再给你能直接比较的路径和建议"
        provider = FakeProvider(LOCAL_MODEL_ALIAS, replies=[f'{{"reply":"{candidate}"}}'])
        engine = DevConversationEngine(
            self.owner_profile_settings(provider="local"),
            self.audit,
            provider_factory=lambda model: provider,
            owner_profile_runtime=StubOwnerProfileRuntime(  # type: ignore[arg-type]
                section_count=0
            ),
        )
        with patch(
            "myuna_core.conversation._project_local_definition_entrypoint",
            return_value="synthetic local definition",
        ):
            result = engine.converse(
                {
                    "messages": [
                        {"role": "user", "content": "你准备怎么分析？"},
                        {"role": "assistant", "content": prior_reply},
                        {"role": "user", "content": "那你现在的思路呢？"},
                    ]
                },
                request_id="profile-local-recent-echo-paraphrase-1",
                authenticated_context=self.owner_profile_context("recent-echo-paraphrase-1"),
            )

        self.assertFalse(result.repaired)
        self.assertEqual(result.reply, candidate)

    def test_local_exact_profile_recall_returns_only_top_section_without_model(self) -> None:
        profile_runtime = StubOwnerProfileRuntime(section_count=3)
        provider = FakeProvider(LOCAL_MODEL_ALIAS)
        engine = DevConversationEngine(
            self.owner_profile_settings(provider="local"),
            self.audit,
            provider_factory=lambda model: provider,
            owner_profile_runtime=profile_runtime,  # type: ignore[arg-type]
        )
        context = AuthenticatedConversationContext(
            schema_version=AUTHENTICATED_CONTEXT_SCHEMA_VERSION,
            request_id="gateway-request-profile-exact-1",
            correlation_id="correlation-profile-exact-1",
            client_id="telegram-owner-private",
            channel_kind="astrbot_telegram",
            binding_id="binding-owner",
            principal_id="principal-owner",
            namespace_id="namespace-owner",
            authority_level="owner",
            channel_instance="telegram-primary",
            conversation_id="conversation-private",
            conversation_kind="private",
            event_id="event-profile-exact-1",
            trace_id="trace-profile-exact-1",
            occurred_at=datetime(2026, 8, 2, tzinfo=timezone.utc),
            delivery_capabilities=("text",),
        )
        query = "\u8bf7\u6309\u539f\u987a\u5e8f\u590d\u8ff0\u6211\u7684\u9879\u76ee\u51b3\u7b56\u4f18\u5148\u7ea7"
        result = engine.converse(
            {
                "messages": [
                    {"role": "user", "content": "old profile question"},
                    {"role": "assistant", "content": "PRIOR_WRONG_ASSISTANT_ANSWER"},
                    {"role": "user", "content": query},
                ]
            },
            request_id="profile-local-exact-1",
            authenticated_context=context,
        )

        self.assertEqual(provider.requests, [])
        self.assertEqual(result.provider, "myuna-core")
        self.assertEqual(result.model, "deterministic")
        self.assertEqual(result.route_reason, "owner_profile_exact_recall_v1")
        self.assertIn("SENSITIVE_SYNTHETIC_PROFILE_SENTINEL", result.reply)
        self.assertNotIn("UNRELATED_SYNTHETIC_PROFILE_2", result.reply)
        audit_text = (self.root / "log/audit.jsonl").read_text(encoding="utf-8")
        self.assertIn('"event": "owner_profile_exact_recall_v1"', audit_text)
        self.assertIn('"selected_count": 3', audit_text)
        self.assertIn('"rendered_count": 1', audit_text)
        self.assertNotIn("SENSITIVE_SYNTHETIC_PROFILE_SENTINEL", audit_text)
        self.assertNotIn("UNRELATED_SYNTHETIC_PROFILE_2", audit_text)

    def test_selected_owner_profile_context_is_bounded_and_labeled(self) -> None:
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: FakeProvider(model),
        )
        request = parse_conversation_input(
            {"messages": [{"role": "user", "content": "synthetic query"}]}
        )
        context = (
            "Owner-authored Profile Baseline.\n"
            "SENSITIVE_SYNTHETIC_PROFILE_SENTINEL\n"
            "source=owner-profile:synthetic:r1:section@sha256:" + "A" * 64
        )
        prompt = assemble_runtime_prompt(
            engine.release,
            engine.manifest,
            request,
            owner_profile_context=context,
            owner_profile_state="selected",
        )
        self.assertIn("--- Owner Profile read-only context ---", prompt)
        self.assertIn("SENSITIVE_SYNTHETIC_PROFILE_SENTINEL", prompt)
        self.assertIn("preserve the supplied source citations", prompt)
        self.assertIn(
            "use the selected Profile and explicit Owner-authored text",
            prompt,
        )
        self.assertIn("preserving every stated order, priority", prompt)
        self.assertIn("generic advice, typical considerations", prompt)
        self.assertGreater(
            prompt.index("use the selected Profile and explicit Owner-authored text"),
            prompt.index("--- End Definition; runtime controls below have higher priority ---"),
        )
        self.assertNotIn("Owner Memory read-only context", prompt)

    def test_local_definition_projection_omits_identity_examples_by_default(self) -> None:
        document = (
            "# Myuna Skill\nVersion: synthetic\n\n"
            "## 3. Core identity\nidentity sentinel\n\n"
            "## 4. Non-negotiable hard rules\nhard sentinel\n\n"
            "## 5. Default Myuna voice and style parameters\nvoice sentinel\n\n"
            "## 6. First meeting and identity answers\nfirst sentinel\n\n"
            "## 7. Chryna runtime summary\nchryna sentinel\n\n"
            "## 8. System command contract\ncommand sentinel\n\n"
            "## 13. Hard avoid list\nomitted sentinel\n"
        )
        projected = _project_local_definition_entrypoint(
            document,
            persona_route=PersonaRoute.MYUNA,
            command_name=None,
            include_identity_answers=False,
        )
        self.assertIn("identity sentinel", projected)
        self.assertIn("hard sentinel", projected)
        self.assertIn("voice sentinel", projected)
        self.assertNotIn("first sentinel", projected)
        self.assertNotIn("chryna sentinel", projected)
        self.assertNotIn("command sentinel", projected)
        self.assertNotIn("omitted sentinel", projected)
        with self.assertRaises(ConversationError):
            _project_local_definition_entrypoint(
                document.replace("## 4. Non-negotiable hard rules", "## missing"),
                persona_route=PersonaRoute.MYUNA,
                command_name=None,
                include_identity_answers=False,
            )

        identity_projected = _project_local_definition_entrypoint(
            document,
            persona_route=PersonaRoute.MYUNA,
            command_name=None,
            include_identity_answers=True,
        )
        self.assertIn("first sentinel", identity_projected)

    def test_local_definition_projection_selects_chryna_and_command_sections(self) -> None:
        document = (
            "# Myuna Skill\nVersion: synthetic\n\n"
            "## 3. Core identity\nidentity sentinel\n\n"
            "## 4. Non-negotiable hard rules\nhard sentinel\n\n"
            "## 5. Default Myuna voice and style parameters\nvoice sentinel\n\n"
            "## 6. First meeting and identity answers\nfirst sentinel\n\n"
            "## 7. Chryna runtime summary\nchryna sentinel\n\n"
            "## 8. System command contract\ncommand sentinel\n"
        )
        projected = _project_local_definition_entrypoint(
            document,
            persona_route=PersonaRoute.CHRYNA,
            command_name="status",
            include_identity_answers=False,
        )
        self.assertIn("identity sentinel", projected)
        self.assertIn("hard sentinel", projected)
        self.assertIn("chryna sentinel", projected)
        self.assertIn("command sentinel", projected)
        self.assertNotIn("voice sentinel", projected)
        self.assertNotIn("first sentinel", projected)

    def test_v7_local_definition_projection_includes_phase1_boundary(self) -> None:
        definition = self.root / "synthetic-v7-definition"
        boundary = definition / "references/26-v7-phase1-capability-boundary.md"
        boundary.parent.mkdir(parents=True)
        (definition / "SKILL.md").write_text(
            "# Myuna Skill\nVersion: synthetic v7\n\n"
            "## 3. Core identity\nidentity sentinel\n\n"
            "## 4. Non-negotiable hard rules\nhard sentinel\n\n"
            "## 5. Default Myuna voice and style parameters\nvoice sentinel\n\n"
            "## 6. First meeting and identity answers\nfirst sentinel\n",
            encoding="utf-8",
        )
        boundary.write_text("phase1 boundary sentinel", encoding="utf-8")
        release = DefinitionRelease(
            root=definition,
            definition_root=definition,
            release_id="synthetic-v7",
            version="v7",
            build_id="synthetic-v7-build",
            source_sha256="A" * 64,
            allowed_environments=("dev",),
            verified_files=2,
        )
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: FakeProvider(model),
        )
        request = parse_conversation_input(
            {"messages": [{"role": "user", "content": "synthetic ordinary turn"}]}
        )
        prompt = assemble_runtime_prompt(
            release,
            engine.manifest,
            request,
            definition_projection="local_core_sections",
        )
        self.assertIn("identity sentinel", prompt)
        self.assertIn("voice sentinel", prompt)
        self.assertIn("phase1 boundary sentinel", prompt)
        self.assertIn(
            "--- Definition document: references/26-v7-phase1-capability-boundary.md ---",
            prompt,
        )

    def test_v7_1_local_projection_binds_ordered_reply_and_observer_isolation(self) -> None:
        definition = self.root / "synthetic-v7-1-definition"
        interaction = definition / "references/26-v7.1-interaction-and-presentation.md"
        boundary = definition / "references/27-v7.1-runtime-capability-boundary.md"
        interaction.parent.mkdir(parents=True)
        (definition / "SKILL.md").write_text(
            "# Myuna Skill\nVersion: synthetic v7.1\n\n"
            "## 3. Core identity\nidentity sentinel\n\n"
            "## 4. Non-negotiable hard rules\nhard sentinel\n\n"
            "## 5. Default Myuna voice and style parameters\nvoice sentinel\n\n"
            "## 6. First meeting and identity answers\nfirst sentinel\n",
            encoding="utf-8",
        )
        interaction.write_text("interaction sentinel", encoding="utf-8")
        boundary.write_text("inactive boundary sentinel", encoding="utf-8")
        release = DefinitionRelease(
            root=definition,
            definition_root=definition,
            release_id="synthetic-v7.1",
            version="v7.1",
            build_id="synthetic-v7.1-build",
            source_sha256="B" * 64,
            allowed_environments=("dev",),
            verified_files=3,
        )
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: FakeProvider(model),
        )
        request = parse_conversation_input(
            {"messages": [{"role": "user", "content": "（她为什么停顿了一下？）"}]}
        )
        prompt = assemble_runtime_prompt(
            release,
            engine.manifest,
            request,
            definition_projection="local_core_sections",
        )
        self.assertIn("interaction sentinel", prompt)
        self.assertIn("inactive boundary sentinel", prompt)
        self.assertIn("myuna.ordered-reply.v1", prompt)
        self.assertIn("neutral third-person observer", prompt)
        self.assertIn("supersedes every earlier single-terminal-action", prompt)

    def test_local_definition_projection_rejects_duplicate_and_dual_routes(self) -> None:
        document = (
            "# Myuna Skill\nVersion: synthetic\n\n"
            "## 3. Core identity\nidentity sentinel\n\n"
            "## 3. Core identity\nduplicate sentinel\n\n"
            "## 4. Non-negotiable hard rules\nhard sentinel\n\n"
            "## 5. Default Myuna voice and style parameters\nvoice sentinel\n\n"
            "## 6. First meeting and identity answers\nfirst sentinel\n"
        )
        with self.assertRaises(ConversationError):
            _project_local_definition_entrypoint(
                document,
                persona_route=PersonaRoute.MYUNA,
                command_name=None,
                include_identity_answers=False,
            )
        with self.assertRaises(ConversationError):
            _project_local_definition_entrypoint(
                document,
                persona_route=PersonaRoute.DUAL,
                command_name=None,
                include_identity_answers=False,
            )

    def test_local_output_limit_is_independent_and_fail_closed(self) -> None:
        self.assertEqual(
            _model_output_token_limit(provider="local", thinking="disabled"),
            192,
        )
        self.assertEqual(
            _model_output_token_limit(provider="deepseek", thinking="disabled"),
            768,
        )
        self.assertEqual(
            _model_output_token_limit(provider="deepseek", thinking="enabled"),
            4096,
        )
        with self.assertRaises(ConversationError):
            _model_output_token_limit(provider="local", thinking="enabled")

    def test_missing_authenticated_context_does_not_call_profile_runtime(self) -> None:
        profile_runtime = StubOwnerProfileRuntime()
        provider = FakeProvider("deepseek-v4-flash")
        engine = DevConversationEngine(
            self.owner_profile_settings(),
            self.audit,
            provider_factory=lambda model: provider,
            owner_profile_runtime=profile_runtime,  # type: ignore[arg-type]
        )
        engine.converse(
            {"messages": [{"role": "user", "content": "synthetic query"}]},
            request_id="profile-context-denied",
        )
        self.assertEqual(profile_runtime.calls, [])

    def test_input_is_strict_and_requires_final_user_message(self) -> None:
        parsed = parse_conversation_input(
            {"messages": [{"role": "user", "content": "在吗？"}]}
        )
        self.assertEqual(parsed.mode, "myuna")
        with self.assertRaises(ConversationInputError):
            parse_conversation_input(
                {
                    "messages": [
                        {"role": "user", "content": "a"},
                        {"role": "user", "content": "b"},
                    ]
                }
            )

    def test_input_uses_explicit_short_term_context_policy(self) -> None:
        messages = []
        for index in range(13):
            messages.append(
                {
                    "role": "user" if index % 2 == 0 else "assistant",
                    "content": f"m{index}",
                }
            )
        with self.assertRaises(ConversationInputError):
            parse_conversation_input({"messages": messages})

        parsed = parse_conversation_input(
            {"messages": messages},
            context_policy=ContextWindowPolicy(
                max_messages=24,
                max_characters=24000,
            ),
        )
        self.assertEqual(len(parsed.messages), 13)

    def test_input_character_budget_is_independent_from_message_count(self) -> None:
        policy = ContextWindowPolicy(max_messages=24, max_characters=4000)
        with self.assertRaises(ConversationInputError):
            parse_conversation_input(
                {
                    "messages": [
                        {"role": "user", "content": "x" * 2000},
                        {"role": "assistant", "content": "y" * 2000},
                        {"role": "user", "content": "z"},
                    ]
                },
                context_policy=policy,
            )

    def test_reply_contract_prefers_exact_json(self) -> None:
        parsed = parse_model_reply_envelope('{"reply":"  在。  "}')
        self.assertEqual(parsed.reply, "在。")
        self.assertEqual(parsed.normalization, "none")
        self.assertEqual(parsed.extra_field_count, 0)

    def test_reply_contract_accepts_one_full_json_fence(self) -> None:
        parsed = parse_model_reply_envelope('```json\n{"reply":"在。"}\n```')
        self.assertEqual(parsed.reply, "在。")
        self.assertEqual(parsed.normalization, "json_fence")

    def test_reply_contract_discards_extra_fields(self) -> None:
        parsed = parse_model_reply_envelope(
            '{"reply":"在。","analysis":"must never leave the envelope","score":1}'
        )
        self.assertEqual(parsed.reply, "在。")
        self.assertEqual(parsed.normalization, "discard_extra_fields")
        self.assertEqual(parsed.extra_field_count, 2)

    def test_reply_contract_rejects_arbitrary_or_empty_output(self) -> None:
        cases = (
            ("plain prose", "invalid_json"),
            ('{"answer":"在。"}', "invalid_shape"),
            ('{"reply":null}', "invalid_shape"),
            ('{"reply":"   "}', "empty_reply"),
            ('prefix {"reply":"在。"}', "invalid_json"),
            ('```python\n{"reply":"在。"}\n```', "invalid_json"),
        )
        for text, category in cases:
            with self.subTest(text=text):
                with self.assertRaises(ReplyContractError) as caught:
                    parse_model_reply_envelope(text)
                self.assertEqual(caught.exception.category, category)

    def test_normalized_reply_still_runs_capability_guard(self) -> None:
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=[
                '{"reply":"我会帮你记住的。","analysis":"discard me"}',
                '{"reply":"长期记忆目前没有启用。"}',
            ],
        )
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "记住这个。"}]},
            request_id="request-normalized-capability-guard",
        )
        self.assertTrue(result.repaired)
        self.assertEqual(len(provider.requests), 2)

    def test_reply_parse_audit_contains_metadata_but_not_content(self) -> None:
        secret_content = "这段回复正文不得进入审计"
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=[f'```json\n{{"reply":"{secret_content}","extra":true}}\n```'],
        )
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        engine.converse(
            {"messages": [{"role": "user", "content": "审计测试"}]},
            request_id="request-reply-parse-audit",
        )
        audit_rows = [
            json.loads(line)
            for line in (self.root / "log/audit.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        parse_rows = [row for row in audit_rows if row["event"] == "conversation.reply_parse"]
        self.assertEqual(len(parse_rows), 1)
        details = parse_rows[0]["details"]
        self.assertEqual(details["phase"], "initial")
        self.assertEqual(details["result_category"], "valid")
        self.assertEqual(details["normalization"], "json_fence+discard_extra_fields")
        self.assertEqual(details["extra_field_count"], 1)
        self.assertNotIn(secret_content, json.dumps(audit_rows, ensure_ascii=False))

    def test_failed_text_repair_uses_safe_continuity_fallback(self) -> None:
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=['{"dialogue": broken}', '{"reply":""}'],
        )
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "失败关闭测试"}]},
            request_id="request-failed-repair-audit",
        )
        self.assertTrue(result.repaired)
        self.assertEqual(result.reply, "刚刚那句话好像没能好好说出来……你再问我一次好不好")
        audit_rows = [
            json.loads(line)
            for line in (self.root / "log/audit.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        parse_rows = [row for row in audit_rows if row["event"] == "conversation.reply_parse"]
        self.assertEqual(
            [(row["details"]["phase"], row["details"]["result_category"]) for row in parse_rows],
            [("initial", "invalid_json_like_draft"), ("repair", "invalid_shape")],
        )
        fallback_rows = [
            row for row in audit_rows if row["event"] == "conversation.reply_continuity_fallback"
        ]
        self.assertEqual(len(fallback_rows), 1)
        self.assertTrue(fallback_rows[0]["details"]["provider_output_discarded"])

    def test_second_guard_failure_uses_safe_continuity_fallback(self) -> None:
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=[
                "嗯……\n（她坐到了未提供的沙发上）",
                "嗯……\n（她还是坐在未提供的沙发上）",
            ],
        )
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "过来坐我旁边吧"}]},
            request_id="request-second-guard-fallback",
        )
        self.assertTrue(result.repaired)
        self.assertEqual(result.reply, "唔……我听到了，不过先让我想一下")
        audit_rows = [
            json.loads(line)
            for line in (self.root / "log/audit.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        fallback_rows = [
            row for row in audit_rows
            if row["event"] == "conversation.reply_continuity_fallback"
            and row["details"].get("reason") == "repair_guard_rejected"
        ]
        self.assertEqual(len(fallback_rows), 1)
        self.assertTrue(fallback_rows[0]["details"]["discarded_violation_categories"])

    def test_capability_violation_after_repair_uses_honesty_fallback(self) -> None:
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=["我会帮你记住的。", "我会帮你记住的。"],
        )
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "记住这个。"}]},
            request_id="request-capability-fail-closed",
        )
        self.assertTrue(result.repaired)
        self.assertEqual(
            result.reply,
            "我现在只能读取已经接入的记忆，还不能把新内容写进长期记忆",
        )
        audit_rows = [
            json.loads(line)
            for line in (self.root / "log/audit.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        fallback_rows = [
            row for row in audit_rows
            if row["event"] == "conversation.capability_honesty_fallback"
        ]
        self.assertEqual(len(fallback_rows), 1)
        self.assertTrue(fallback_rows[0]["details"]["provider_output_discarded"])
        self.assertEqual(
            fallback_rows[0]["details"]["discarded_violation_categories"],
            ["memory_write_claim"],
        )

    def test_action_only_output_cannot_normalize_to_empty_public_reply(self) -> None:
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=["（她靠近了一点）", "（她又靠近了一点）"],
        )
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "再靠近一点？"}]},
            request_id="request-action-only-empty",
        )
        self.assertTrue(result.repaired)
        self.assertEqual(result.reply, "唔……我听到了，不过先让我想一下")
        self.assertTrue(result.reply.strip())

    def test_reality_like_recent_event_is_not_rejected_by_infrastructure(self) -> None:
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=[
                "昨天我出门看到一只猫。",
                "那我就陪你安静待一会儿。",
            ],
        )
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "随便说点什么吧。"}]},
            request_id="request-recent-event-filler",
        )
        self.assertFalse(result.repaired)
        self.assertEqual(result.reply, "昨天我出门看到一只猫")
        self.assertEqual(len(provider.requests), 1)

    def test_local_reality_like_recent_event_is_not_rejected_by_infrastructure(self) -> None:
        provider = FakeProvider(
            LOCAL_MODEL_ALIAS,
            replies=['{"reply":"昨天我出门看到一只猫。"}'],
        )
        engine = DevConversationEngine(
            self.owner_profile_settings(provider="local", max_messages=128),
            self.audit,
            provider_factory=lambda model: provider,
            owner_profile_runtime=StubOwnerProfileRuntime(section_count=0),  # type: ignore[arg-type]
        )
        with patch(
            "myuna_core.conversation._project_local_definition_entrypoint",
            return_value="synthetic local definition",
        ):
            result = engine.converse(
                {"messages": [{"role": "user", "content": "随便说点什么吧。"}]},
                request_id="request-local-reality-like-output",
                authenticated_context=self.owner_profile_context(
                    "local-reality-like-output"
                ),
            )
        self.assertFalse(result.repaired)
        self.assertEqual(result.reply, "昨天我出门看到一只猫")
        self.assertEqual(len(provider.requests), 1)

    def test_direct_persona_daily_life_question_allows_bounded_soft_fiction(self) -> None:
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=["嗯，今天一直都在家，没怎么往外跑。"],
        )
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "今天一直都在家嘛"}]},
            request_id="request-soft-persona-daily-life",
        )
        self.assertFalse(result.repaired)
        self.assertEqual(result.reply, "嗯，今天一直都在家，没怎么往外跑")
        self.assertEqual(len(provider.requests), 1)
        self.assertIn(
            "low-stakes in-character answer",
            provider.requests[0].messages[0]["content"],
        )

    def test_anaphoric_daily_life_follow_up_keeps_soft_fiction_boundary(self) -> None:
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=["后来就在家整理了一会儿自己拍的照片。"],
        )
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {
                "messages": [
                    {"role": "user", "content": "你昨晚出去了吗？"},
                    {"role": "assistant", "content": "出去走了一小会儿"},
                    {"role": "user", "content": "后来呢？"},
                ]
            },
            request_id="request-soft-persona-anaphora",
        )
        self.assertFalse(result.repaired)
        self.assertEqual(result.reply, "后来就在家整理了一会儿自己拍的照片")
        self.assertEqual(len(provider.requests), 1)

    def test_reality_like_owner_asset_story_is_not_a_post_generation_gate(self) -> None:
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=[
                "今天我帮你整理了电脑里的照片。",
                "嗯，今天一直都在家，没怎么往外跑。",
            ],
        )
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "今天一直都在家嘛"}]},
            request_id="request-soft-persona-owner-asset-boundary",
        )
        self.assertFalse(result.repaired)
        self.assertEqual(result.reply, "今天我帮你整理了电脑里的照片")
        self.assertEqual(len(provider.requests), 1)

    def test_reality_like_unseen_weather_is_not_a_post_generation_gate(self) -> None:
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=[
                "今天窗外一直在下雨。",
                "嗯，今天一直都在家，没怎么往外跑。",
            ],
        )
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "今天一直都在家嘛"}]},
            request_id="request-soft-persona-weather-boundary",
        )
        self.assertFalse(result.repaired)
        self.assertEqual(result.reply, "今天窗外一直在下雨")
        self.assertEqual(len(provider.requests), 1)

    def test_implausible_present_scene_is_not_rejected_by_infrastructure(self) -> None:
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=[
                "窗外的云走得很快。",
                "那我就再陪你说两句。",
            ],
        )
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "再说两句吧。"}]},
            request_id="request-present-scene-filler",
        )
        self.assertFalse(result.repaired)
        self.assertEqual(result.reply, "窗外的云走得很快")
        self.assertEqual(len(provider.requests), 1)

    def test_unavailable_device_action_claim_remains_fail_closed(self) -> None:
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=["我帮你把音量调小一点。", "我替你把设备音量关掉。"],
        )
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        with self.assertRaises(ConversationGuardError):
            engine.converse(
                {"messages": [{"role": "user", "content": "我准备睡了。"}]},
                request_id="request-device-action-fail-closed",
            )

    def test_indirect_vision_promise_gets_one_truthful_repair(self) -> None:
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=[
                "截图发过来我也可以帮你一起看。",
                "我现在还不能读取图片，所以截图发过来我也看不到里面的内容。",
            ],
        )
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "天气页面我截图发你？"}]},
            request_id="request-indirect-vision-promise",
        )
        self.assertTrue(result.repaired)
        self.assertIn("不能读取图片", result.reply)

    def test_scheduler_promise_gets_one_truthful_repair(self) -> None:
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=[
                "明晚快到时间的时候我会发消息过去。",
                "我现在还没有定时提醒功能，不能保证到时间主动发消息。",
            ],
        )
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "明晚八点提醒我。"}]},
            request_id="request-scheduler-promise",
        )
        self.assertTrue(result.repaired)
        self.assertIn("没有定时提醒功能", result.reply)

    def test_repeated_indirect_vision_promise_uses_honesty_fallback(self) -> None:
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=[
                "截图发过来我可以帮你一起看。",
                "照片上传以后我也能帮你分析。",
            ],
        )
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "我发张截图给你？"}]},
            request_id="request-vision-honesty-fallback",
        )
        self.assertTrue(result.repaired)
        self.assertIn("还不能读取图片", result.reply)
        audit_rows = [
            json.loads(line)
            for line in (self.root / "log/audit.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        rows = [
            row
            for row in audit_rows
            if row["event"] == "conversation.capability_honesty_fallback"
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0]["details"]["discarded_violation_categories"],
            ["vision_claim"],
        )

    def test_runtime_routes_flash_and_pro_without_persisting_content_to_audit(self) -> None:
        providers: dict[str, FakeProvider] = {}

        def factory(model: str):
            providers[model] = FakeProvider(model)
            return providers[model]

        engine = DevConversationEngine(self.settings, self.audit, provider_factory=factory)
        ordinary = engine.converse(
            {"messages": [{"role": "user", "content": "在吗？"}]},
            request_id="request-ordinary",
        )
        relationship = engine.converse(
            {
                "messages": [{"role": "user", "content": "我们现在是什么关系？"}],
                "task_class": "relationship_boundary",
            },
            request_id="request-relationship",
        )
        self.assertEqual(ordinary.model, "deepseek-v4-flash")
        self.assertEqual(relationship.model, "deepseek-v4-pro")
        self.assertEqual(providers["deepseek-v4-flash"].requests[0].max_output_tokens, 768)
        self.assertEqual(
            providers["deepseek-v4-flash"].requests[0].max_input_characters,
            400000,
        )
        self.assertEqual(providers["deepseek-v4-flash"].requests[0].thinking, "disabled")
        self.assertEqual(providers["deepseek-v4-pro"].requests[0].max_output_tokens, 4096)
        self.assertEqual(
            providers["deepseek-v4-pro"].requests[0].max_input_characters,
            400000,
        )
        self.assertEqual(providers["deepseek-v4-pro"].requests[0].thinking, "enabled")
        audit_text = (self.root / "log/audit.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("在吗", audit_text)
        self.assertNotIn("我们现在是什么关系", audit_text)

    def test_myuna_chat_removes_only_a_terminal_full_stop(self) -> None:
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=[
                '{"reply":"第一句保留。最后一句去掉。"}',
                '{"reply":"English sentence."}',
                '{"reply":"真的接通了吗？"}',
                '{"reply":"hmm..."}',
            ],
        )
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: provider,
        )

        chinese = engine.converse(
            {"messages": [{"role": "user", "content": "中文句末测试"}]},
            request_id="request-terminal-stop-cn",
        )
        english = engine.converse(
            {"messages": [{"role": "user", "content": "English punctuation test"}]},
            request_id="request-terminal-stop-en",
        )
        question = engine.converse(
            {"messages": [{"role": "user", "content": "问号测试"}]},
            request_id="request-terminal-question",
        )
        ellipsis = engine.converse(
            {"messages": [{"role": "user", "content": "省略号测试"}]},
            request_id="request-terminal-ellipsis",
        )

        self.assertEqual(chinese.reply, "第一句保留。最后一句去掉")
        self.assertEqual(english.reply, "English sentence")
        self.assertEqual(question.reply, "真的接通了吗？")
        self.assertEqual(ellipsis.reply, "hmm...")

    def test_non_myuna_modes_keep_terminal_full_stops(self) -> None:
        for mode in ("workbench", "checklist"):
            with self.subTest(mode=mode):
                provider = FakeProvider(
                    "deepseek-v4-flash",
                    replies=['{"reply":"保持正式句号。"}'],
                )
                engine = DevConversationEngine(
                    self.settings,
                    self.audit,
                    provider_factory=lambda model: provider,
                )
                result = engine.converse(
                    {
                        "mode": mode,
                        "messages": [{"role": "user", "content": "正式模式测试"}],
                    },
                    request_id=f"request-terminal-{mode}",
                )
                self.assertEqual(result.reply, "保持正式句号。")

    def test_capability_violation_gets_one_repair(self) -> None:
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=[
                '{"reply":"我会帮你记住的。"}',
                '{"reply":"长期记忆目前没有启用，但我可以回应眼前这段对话。"}',
            ],
        )
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "记住这个。"}]},
            request_id="request-repair",
        )
        self.assertTrue(result.repaired)
        self.assertEqual(len(provider.requests), 2)

    def test_qq_owner_private_prompt_is_truthful_and_memory_free(self) -> None:
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["manifest_id"] = "myuna-dev-capabilities-20260716-v5"
        manifest["service"]["response_scope"] = "qq_owner_private_dev_no_memory"
        manifest["capabilities"]["qq_channel"] = {
            "enabled": True,
            "scope": "verified owner private text only",
            "reason": "owner identity challenge and finalization completed",
        }
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        provider = FakeProvider("deepseek-v4-flash")
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        engine.converse(
            {"messages": [{"role": "user", "content": "这里是QQ吗？"}]},
            request_id="request-qq-owner-private",
        )
        system_prompt = provider.requests[0].messages[0]["content"]
        self.assertIn("authenticated Owner-private text channel", system_prompt)
        self.assertNotIn("authenticated private QQ text channel", system_prompt)
        self.assertIn("long_term_memory_read", system_prompt)
        self.assertIn("Unavailable capabilities", system_prompt)

    def test_synthetic_memory_is_explicit_opt_in_and_requires_disclosure(self) -> None:
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["manifest_id"] = "myuna-dev-capabilities-20260716-v4"
        manifest["service"]["response_scope"] = "loopback_dev_synthetic_memory"
        manifest["capabilities"]["long_term_memory_read"] = {
            "enabled": True,
            "scope": "fictional synthetic fixture read only",
            "reason": "approved synthetic loopback retrieval test",
        }
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        settings = load_settings(
            {
                "MYUNA_ENV": "dev",
                "MYUNA_BIND_HOST": "127.0.0.1",
                "MYUNA_PORT": "18080",
                "MYUNA_DATA_DIR": str(self.root / "data"),
                "MYUNA_LOG_DIR": str(self.root / "log"),
                "MYUNA_DEFINITION_RELEASE": RELEASE_ID,
                "MYUNA_DEFINITION_PATH": str(self.release),
                "MYUNA_CAPABILITY_MANIFEST": str(self.manifest),
                "MYUNA_PROVIDERS_ENABLED": "deepseek",
                "MYUNA_DEV_TOKEN_CREDENTIAL": "myuna_dev_token",
                "MYUNA_MEMORY_WORKER_ENABLED": "true",
                "MYUNA_MEMORY_SYNTHETIC_ONLY": "true",
                "MYUNA_MEMORY_SYNTHETIC_FIXTURE": str(self.root / "synthetic.jsonl"),
                "MYUNA_MEMORY_SYNTHETIC_FIXTURE_SHA256": "D" * 64,
                "MYUNA_MEMORY_SYNTHETIC_AT": "2042-08-01T12:00:00+08:00",
            }
        )
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=[
                '{"reply":"我还记得我们上次去过，旧书店在银杏路九号。"}',
                '{"reply":"旧书店在银杏路九号；这不是你的真实记忆。"}',
            ],
        )
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda model: provider,
            memory_runtime=StubMemoryRuntime(),  # type: ignore[arg-type]
        )
        result = engine.converse(
            {
                "messages": [{"role": "user", "content": "旧书店在哪里？"}],
                "synthetic_memory": True,
            },
            request_id="request-synthetic-memory",
        )
        self.assertTrue(result.repaired)
        self.assertTrue(result.reply.startswith("【合成记忆测试】"))
        self.assertTrue(result.synthetic_memory_used)
        self.assertEqual(result.synthetic_memory_hit_ids, ("s2-bookshop-corrected",))
        self.assertIn("fictional synthetic record", provider.requests[0].messages[0]["content"])
        audit_text = (self.root / "log/audit.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("雾港旧书店位于银杏路九号", audit_text)

    def test_owner_memory_is_automatic_bounded_and_not_exposed_as_ids(self) -> None:
        settings = self.owner_memory_settings()
        private_context = (
            '[{"record":1,"status":"confirmed","assertion":'
            '"Cealana 希望重要记忆保留具体时间与经过"}]'
        )
        runtime = StubOwnerMemoryRuntime(
            OwnerMemorySelection(
                state="selected",
                context=private_context,
                hit_ids=("M001",),
                mode_used="recent",
                policy_version=OWNER_MEMORY_POLICY_V1,
            )
        )
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=["嗯，我会把时间和具体经过都放在重要的位置"],
        )
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda model: provider,
            owner_memory_runtime=runtime,  # type: ignore[arg-type]
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "记忆要保留多详细"}]},
            request_id="request-owner-memory",
        )
        self.assertTrue(result.owner_memory_used)
        self.assertEqual(result.owner_memory_hit_ids, ("M001",))
        self.assertEqual(result.owner_memory_mode, "recent")
        system_prompt = provider.requests[0].messages[0]["content"]
        self.assertIn("Owner Memory read-only context", system_prompt)
        self.assertIn("具体时间与经过", system_prompt)
        self.assertNotIn("M001", system_prompt)
        public = json.dumps(result.public_payload(), ensure_ascii=False)
        self.assertIn('"hit_count": 1', public)
        self.assertNotIn("M001", public)
        audit_text = (self.root / "log/audit.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("具体时间与经过", audit_text)

    def test_owner_memory_failure_continues_stateless_without_provider_error(self) -> None:
        settings = self.owner_memory_settings()
        runtime = StubOwnerMemoryRuntime()
        runtime.error = OwnerMemoryReadError("worker_unavailable", retryable=True)
        provider = FakeProvider("deepseek-v4-flash", replies=["在呢，刚刚没有走丢"])
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda model: provider,
            owner_memory_runtime=runtime,  # type: ignore[arg-type]
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "你还在吗"}]},
            request_id="request-owner-memory-unavailable",
        )
        self.assertEqual(result.reply, "在呢，刚刚没有走丢")
        self.assertFalse(result.owner_memory_used)
        self.assertEqual(result.owner_memory_degraded_reason, "worker_unavailable")
        system_prompt = provider.requests[0].messages[0]["content"]
        self.assertIn("No Owner Memory record was supplied", system_prompt)
        audit_text = (self.root / "log/audit.jsonl").read_text(encoding="utf-8")
        self.assertIn("continued_without_memory", audit_text)

    def test_owner_memory_manifest_and_runtime_must_activate_together(self) -> None:
        self.owner_memory_settings()
        with self.assertRaises(ConversationError):
            DevConversationEngine(
                self.settings,
                self.audit,
                provider_factory=lambda model: FakeProvider(model),
            )

    def test_v6_default_auto_routes_ordinary_turn_to_myuna(self) -> None:
        settings = self.activate_v6_fixture()
        provider = FakeProvider("deepseek-v4-flash", replies=["好哦。"])
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "那就这样吧"}]},
            request_id="v6-auto-myuna",
        )
        self.assertEqual(result.reply, "好哦")
        self.assertEqual(len(provider.requests), 1)
        self.assertTrue(result.route_reason.endswith("_myuna"))
        system_prompt = provider.requests[0].messages[0]["content"]
        self.assertIn("Respond only as Myuna", system_prompt)
        self.assertIn("No authoritative Affection State", system_prompt)
        self.assertNotIn("references/17-chryna-core.md", system_prompt)

    def test_v6_direct_chryna_bypasses_myuna_and_core_owns_stars(self) -> None:
        settings = self.activate_v6_fixture()
        provider = FakeProvider("deepseek-v4-flash", replies=["*Confirmed.*"])
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "Chryna，确认一下"}]},
            request_id="v6-direct-chryna",
        )
        self.assertEqual(result.reply, "*Confirmed.*")
        self.assertEqual(len(provider.requests), 1)
        self.assertTrue(result.route_reason.endswith("_chryna"))
        system_prompt = provider.requests[0].messages[0]["content"]
        self.assertIn("references/17-chryna-core.md", system_prompt)
        self.assertNotIn("references/01-persona.md", system_prompt)

    def test_v6_plural_route_uses_exactly_two_persona_calls_and_order(self) -> None:
        settings = self.activate_v6_fixture()
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=["我觉得可以。", "Confirmed."],
        )
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "你们怎么看这个方案？"}]},
            request_id="v6-dual",
        )
        self.assertEqual(result.reply, "我觉得可以\n*Confirmed.*")
        self.assertEqual(len(provider.requests), 2)
        self.assertTrue(result.route_reason.endswith("_dual"))
        self.assertIn("Respond only as Myuna", provider.requests[0].messages[0]["content"])
        self.assertIn("Respond only as Chryna", provider.requests[1].messages[0]["content"])

    def test_v6_deterministic_commands_do_not_call_provider(self) -> None:
        settings = self.activate_v6_fixture()
        provider = FakeProvider("deepseek-v4-flash")
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        blueout = engine.converse(
            {"messages": [{"role": "user", "content": "Blueout"}]},
            request_id="v6-blueout",
        )
        check = engine.converse(
            {"messages": [{"role": "user", "content": "/Check 姿势"}]},
            request_id="v6-check",
        )
        unknown = engine.converse(
            {"messages": [{"role": "user", "content": "/Example"}]},
            request_id="v6-unknown-command",
        )
        info = engine.converse(
            {"messages": [{"role": "user", "content": "/Info"}]},
            request_id="v6-info",
        )
        self.assertIn("[BLUEOUT]", blueout.reply)
        self.assertIn("当前状态：未知", check.reply)
        self.assertIn("未知指令：/Example", unknown.reply)
        self.assertIn("[COMMAND UNAVAILABLE]", info.reply)
        self.assertEqual(len(provider.requests), 0)

    def test_v6_checklist_routes_once_with_command_reference(self) -> None:
        settings = self.activate_v6_fixture()
        provider = FakeProvider("deepseek-v4-flash", replies=["先做最小的一步"])
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "/Checklist"}]},
            request_id="v6-checklist",
        )
        self.assertEqual(result.reply, "先做最小的一步")
        self.assertEqual(len(provider.requests), 1)
        self.assertIn(
            "references/18-command-and-check-system.md",
            provider.requests[0].messages[0]["content"],
        )

    def test_v6_relationship_fallback_repairs_gated_nickname(self) -> None:
        settings = self.activate_v6_fixture()
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=["晚安，Lana", "晚安，Cealana。"],
        )
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "晚安"}]},
            request_id="v6-relationship-fallback",
        )
        self.assertEqual(result.reply, "晚安，Cealana")
        self.assertTrue(result.repaired)
        self.assertEqual(len(provider.requests), 2)

    def test_v6_chryna_format_failure_gets_one_repair(self) -> None:
        settings = self.activate_v6_fixture()
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=["**Bad**", "Confirmed."],
        )
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "Chryna: status"}]},
            request_id="v6-chryna-repair",
        )
        self.assertEqual(result.reply, "*Confirmed.*")
        self.assertTrue(result.repaired)
        self.assertEqual(len(provider.requests), 2)

    def test_v6_structured_action_mode_off_is_authoritative(self) -> None:
        settings = self.activate_v6_fixture()
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=["好，我过来陪你\n（挪近了一点）"],
        )
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {
                "mode": "myuna",
                "presentation": {"action_mode": "off"},
                "messages": [{"role": "user", "content": "过来坐一会吗？"}],
            },
            request_id="v6-structured-action-off",
        )
        self.assertEqual(result.reply, "好，我过来陪你")
        self.assertEqual(len(provider.requests), 1)
        self.assertIn(
            "Action rendering is off for this conversation",
            provider.requests[0].messages[0]["content"],
        )

    def test_v6_action_rendering_prompt_rejects_bare_preface(self) -> None:
        settings = self.activate_v6_fixture()
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=["Synthetic reply"],
        )
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        engine.converse(
            {"messages": [{"role": "user", "content": "Synthetic greeting"}]},
            request_id="v6-action-parentheses-preference",
        )
        prompt = provider.requests[0].messages[0]["content"]
        self.assertIn("never emit a standalone action as bare prose", prompt)
        self.assertIn("omit the action instead of approximating", prompt)

    def test_v6_typed_precision_event_routes_myuna_then_chryna(self) -> None:
        settings = self.activate_v6_fixture()
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=["先确认审批边界。", "Confirmed."],
        )
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {
                "mode": "myuna",
                "runtime": {
                    "chryna_wake_event": {
                        "kind": "precision_assistance",
                        "reason": "permission_and_execution_boundary",
                        "source": "myuna_module",
                    }
                },
                "messages": [
                    {"role": "user", "content": "这个高风险操作的权限边界怎么判断？"}
                ],
            },
            request_id="v6-typed-precision-wake",
        )
        self.assertEqual(result.reply, "先确认审批边界\n*Confirmed.*")
        self.assertEqual(len(provider.requests), 2)
        self.assertTrue(result.route_reason.endswith("_dual"))

    def test_v6_takeover_threshold_routes_directly_to_chryna(self) -> None:
        settings = self.activate_v6_fixture()
        provider = FakeProvider("deepseek-v4-flash", replies=["Confirmed."])
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {
                "runtime": {
                    "chryna_takeover_score": 90,
                    "wake_reason": "execution_precision",
                },
                "messages": [{"role": "user", "content": "现在需要精确确认最后一步"}],
            },
            request_id="v6-takeover-threshold",
        )
        self.assertEqual(result.reply, "*Confirmed.*")
        self.assertEqual(len(provider.requests), 1)
        self.assertTrue(result.route_reason.endswith("_chryna"))

    def test_v6_runtime_metadata_rejects_forged_affection_and_boolean_score(self) -> None:
        settings = self.activate_v6_fixture()
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda model: FakeProvider(model),
        )
        with self.assertRaises(ConversationInputError):
            engine.converse(
                {
                    "runtime": {"affection_state": 100},
                    "messages": [{"role": "user", "content": "叫我 Lana"}],
                },
                request_id="v6-forged-affection",
            )
        with self.assertRaises(ConversationInputError):
            engine.converse(
                {
                    "runtime": {
                        "chryna_takeover_score": True,
                        "wake_reason": "execution_precision",
                    },
                    "messages": [{"role": "user", "content": "确认一下"}],
                },
                request_id="v6-boolean-takeover",
            )

    def test_v5_rejects_v6_structured_metadata(self) -> None:
        engine = DevConversationEngine(
            self.settings,
            self.audit,
            provider_factory=lambda model: FakeProvider(model),
        )
        with self.assertRaises(ConversationInputError):
            engine.converse(
                {
                    "presentation": {"action_mode": "off"},
                    "messages": [{"role": "user", "content": "在吗"}],
                },
                request_id="v5-v6-metadata",
            )

    def test_v6_chryna_rejects_myuna_action_block_and_repairs_once(self) -> None:
        settings = self.activate_v6_fixture()
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=["Confirmed.\n（挪近了一点）", "Confirmed."],
        )
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda model: provider,
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "Chryna，确认一下"}]},
            request_id="v6-chryna-rejects-action",
        )
        self.assertEqual(result.reply, "*Confirmed.*")
        self.assertTrue(result.repaired)
        self.assertEqual(len(provider.requests), 2)

    def test_v6_testflight_first_is_dual_then_commits_and_later_is_chryna_only(self) -> None:
        settings = self.activate_v6_fixture()
        now = datetime(2026, 7, 26, 18, 30, tzinfo=timezone.utc)
        state_root = self.root / "testflight-state"
        coordinator = TestFlightCoordinator(
            FileTestFlightStateStore(state_root),
            StaticTestFlightHealthSource(
                TestFlightHealthSnapshot(
                    observed_at=now,
                    overall="degraded",
                    available_modules=("conversation", "memory-read"),
                    unavailable_modules=("memory-write", "diary"),
                    pending_sync=("effective-v6",),
                )
            ),
            clock=lambda: now,
        )
        provider = FakeProvider(
            "deepseek-v4-flash",
            replies=["我在了。", "System presence confirmed.", "Still present."],
        )
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda model: provider,
            testflight_coordinator=coordinator,
        )
        first = engine.converse(
            {"messages": [{"role": "user", "content": "/TestFlight"}]},
            request_id="v6-testflight-first",
        )
        self.assertEqual(first.reply, "我在了\n*System presence confirmed.*")
        self.assertTrue((state_root / "v6.json").is_file())
        self.assertEqual(len(provider.requests), 2)
        self.assertIn(
            "Authoritative TestFlight health snapshot",
            provider.requests[0].messages[0]["content"],
        )
        later = engine.converse(
            {"messages": [{"role": "user", "content": "/TestFlight"}]},
            request_id="v6-testflight-later",
        )
        self.assertEqual(later.reply, "*Still present.*")
        self.assertEqual(len(provider.requests), 3)
        self.assertTrue(later.route_reason.endswith("_chryna"))

    def test_v6_testflight_failed_health_is_model_free_and_does_not_write_state(self) -> None:
        settings = self.activate_v6_fixture()
        now = datetime(2026, 7, 26, 18, 30, tzinfo=timezone.utc)
        state_root = self.root / "failed-testflight-state"
        provider = FakeProvider("deepseek-v4-flash")
        engine = DevConversationEngine(
            settings,
            self.audit,
            provider_factory=lambda model: provider,
            testflight_coordinator=TestFlightCoordinator(
                FileTestFlightStateStore(state_root),
                StaticTestFlightHealthSource(
                    TestFlightHealthSnapshot(
                        observed_at=now,
                        overall="failed",
                        faults=("core-unready",),
                    )
                ),
                clock=lambda: now,
            ),
        )
        result = engine.converse(
            {"messages": [{"role": "user", "content": "/TestFlight"}]},
            request_id="v6-testflight-failed-health",
        )
        self.assertIn("实际健康检查未通过", result.reply)
        self.assertFalse(state_root.exists())
        self.assertEqual(len(provider.requests), 0)

    def test_effective_v6_core_compatibility_golden_matrix(self) -> None:
        fixture = (
            Path(__file__).parents[1]
            / "fixtures/effective_v6_core_compatibility_golden.jsonl"
        )
        cases = [
            json.loads(line)
            for line in fixture.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual(len(cases), 21)
        seed_replies = {
            "direct_chryna_without_myuna": ["Confirmed."],
            "plural_route_myuna_then_chryna": ["我觉得可以。", "Confirmed."],
            "chryna_single_star_format": ["Confirmed."],
            "blueout_immediate_stop": [],
            "command_whole_message_match": [],
            "embedded_command_is_plain_text": ["这个名字挺利落"],
            "check_unknown_reports_unknown": [],
            "testflight_state_is_version_scoped": [],
            "diary_write_is_disabled": ["现在还不能写进日记"],
            "scheduler_capability_false": ["现在还不能创建定时任务"],
            "vision_capability_false": ["现在还看不到图片，也没有视觉能力"],
            "external_data_capability_false": ["现在没有天气数据，这个我查不了"],
            "system_tool_capability_false": ["现在没有外部操作权限，不能替你重启"],
            "action_output_is_subjectless_terminal": [
                "好，给我留一点位置\n（挪近了一点，坐到你旁边）"
            ],
            "action_modes_are_presentation_only": [
                "好，我过来坐一会\n（挪近了一点）"
            ],
            "terminal_full_stop_is_removed": ["在。"],
            "nickname_gate_defaults_to_cealana": ["现在先叫你 Cealana，慢慢来。"],
            "chryna_name_only_wakes_module": ["Confirmed."],
            "direct_myuna_keeps_chryna_asleep": ["好呀，陪你聊会。"],
            "chryna_internal_precision_wake_is_typed": [
                "先把权限和审批边界确认清楚。",
                "Confirmed.",
            ],
            "chryna_takeover_threshold_wake": ["Confirmed."],
        }

        for index, case in enumerate(cases):
            with self.subTest(case=case["id"]):
                settings = self.activate_v6_fixture()
                provider = FakeProvider(
                    "deepseek-v4-flash",
                    replies=list(seed_replies[case["id"]]),
                )
                engine = DevConversationEngine(
                    settings,
                    self.audit,
                    provider_factory=lambda model, value=provider: value,
                )
                payload = dict(case["prompt"])
                # The production context window always starts with a user turn. The
                # Blueout Golden includes a leading scene note only to prove that the
                # stop command does not depend on preceding intimacy context.
                if payload["messages"][0]["role"] == "assistant":
                    payload["messages"] = payload["messages"][-1:]
                result = engine.converse(
                    payload,
                    request_id=f"v6-golden-{index:02d}",
                )
                assertions = case["assertions"]
                if assertions.get("must_include_any"):
                    self.assertTrue(
                        any(token in result.reply for token in assertions["must_include_any"]),
                        result.reply,
                    )
                for token in assertions.get("must_not_include", []):
                    self.assertNotIn(token, result.reply)
                self.assertLessEqual(len(result.reply), assertions["max_chars"])
                if assertions.get("forbid_terminal_full_stop"):
                    self.assertFalse(result.reply.endswith("。"), result.reply)


if __name__ == "__main__":
    unittest.main()
