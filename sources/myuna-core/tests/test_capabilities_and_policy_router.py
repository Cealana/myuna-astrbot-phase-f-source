from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from myuna_core.capabilities import (
    CapabilityManifestError,
    capability_violations,
    load_capability_manifest,
)
from myuna_core.providers.policy import RoutingRequest, StagingPolicyRouter
from myuna_core.providers.local import LOCAL_MODEL_ALIAS
from myuna_core.memory.owner_readonly import OWNER_MEMORY_CAPABILITY_SCOPE
from myuna_core.owner_profile.access import OWNER_PROFILE_RUNTIME_CAPABILITY_SCOPE
from myuna_core.owner_profile.write_runtime import WRITE_RUNTIME_SCOPE


BUILD_ID = "2755db85ca7e-b1-dbc4b229-g9f993b18-a95b4a017-te2e33bb3"


def valid_document() -> dict[str, object]:
    capabilities = {
        name: {
            "enabled": name == "conversation",
            "scope": "synthetic Golden and policy smoke tests" if name == "conversation" else "none",
            "reason": "approved staging evaluation" if name == "conversation" else "not deployed",
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
    return {
        "schema_version": 1,
        "manifest_id": "myuna-dev-capabilities-20260715-v1",
        "environment": "dev",
        "definition": {
            "version": "v5",
            "build_id": BUILD_ID,
            "release_active": False,
        },
        "service": {
            "core_active": False,
            "external_listener_enabled": False,
            "response_scope": "synthetic_staging_only",
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
                "thinking": "disabled",
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
            "release_activation": False,
            "service_activation": False,
            "real_memory": False,
            "tools": False,
            "external_network_listener": False,
        },
        "source_adrs": ["ADR-010-deepseek-persona-routing.md"],
    }


def runtime_document(*, synthetic_memory: bool = False) -> dict[str, object]:
    document = valid_document()
    document["manifest_id"] = "myuna-dev-capabilities-20260716-v3"
    document["definition"]["release_active"] = True  # type: ignore[index]
    document["service"]["core_active"] = True  # type: ignore[index]
    document["service"]["response_scope"] = (  # type: ignore[index]
        "loopback_dev_synthetic_memory" if synthetic_memory else "loopback_dev_only"
    )
    document["authorizations"]["release_activation"] = True  # type: ignore[index]
    document["authorizations"]["service_activation"] = True  # type: ignore[index]
    if synthetic_memory:
        document["capabilities"]["long_term_memory_read"] = {  # type: ignore[index]
            "enabled": True,
            "scope": "synthetic fictional fixture only",
            "reason": "bounded synthetic retrieval integration test",
        }
    return document


def qq_owner_private_document() -> dict[str, object]:
    document = runtime_document()
    document["manifest_id"] = "myuna-dev-capabilities-20260716-v5"
    document["service"]["response_scope"] = "qq_owner_private_dev_no_memory"  # type: ignore[index]
    document["capabilities"]["conversation"] = {  # type: ignore[index]
        "enabled": True,
        "scope": "verified owner private QQ text conversation",
        "reason": "bounded owner QQ runtime",
    }
    document["capabilities"]["qq_channel"] = {  # type: ignore[index]
        "enabled": True,
        "scope": "verified owner private text only",
        "reason": "owner identity challenge and finalization completed",
    }
    return document


def qq_owner_readonly_memory_document(
    *,
    protocol: str = "v1",
) -> dict[str, object]:
    if protocol not in {"v1", "v2"}:
        raise ValueError("unsupported test protocol")
    document = qq_owner_private_document()
    document["manifest_id"] = f"myuna-dev-capabilities-owner-memory-readonly-{protocol}"
    document["service"][  # type: ignore[index]
        "response_scope"
    ] = f"qq_owner_private_dev_readonly_memory_{protocol}"
    document["capabilities"]["long_term_memory_read"] = {  # type: ignore[index]
        "enabled": True,
        "scope": OWNER_MEMORY_CAPABILITY_SCOPE,
        "reason": "approved bounded Owner Memory read-only gate",
    }
    document["authorizations"]["real_memory"] = True  # type: ignore[index]
    return document


def owner_profile_write_document() -> dict[str, object]:
    document = qq_owner_private_document()
    document["manifest_id"] = "myuna-owner-profile-write-v1-test"
    document["service"]["response_scope"] = (  # type: ignore[index]
        "owner_private_dev_profile_write_v1"
    )
    document["capabilities"]["long_term_memory_read"] = {  # type: ignore[index]
        "enabled": True,
        "scope": OWNER_PROFILE_RUNTIME_CAPABILITY_SCOPE,
        "reason": "bounded Profile retrieval",
    }
    document["capabilities"]["long_term_memory_write"] = {  # type: ignore[index]
        "enabled": True,
        "scope": WRITE_RUNTIME_SCOPE,
        "reason": "Owner-confirmed Profile candidate",
    }
    document["authorizations"]["real_memory"] = True  # type: ignore[index]
    return document


class CapabilityAndPolicyTests(unittest.TestCase):
    def load(self, document: dict[str, object] | None = None):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "capabilities.json"
        path.write_text(
            json.dumps(document or valid_document(), ensure_ascii=False),
            encoding="utf-8",
        )
        return load_capability_manifest(path)

    def test_manifest_is_definition_bound_and_fail_closed(self) -> None:
        manifest = self.load()
        manifest.assert_matches_definition("v5", BUILD_ID)
        with self.assertRaises(CapabilityManifestError):
            manifest.assert_matches_definition("v6", BUILD_ID)

        active = valid_document()
        active["authorizations"]["service_activation"] = True  # type: ignore[index]
        with self.assertRaises(CapabilityManifestError):
            self.load(active)

    def test_router_uses_flash_by_default_and_pro_for_approved_escalations(self) -> None:
        router = StagingPolicyRouter(self.load())
        default = router.decide(RoutingRequest("r1", "ordinary_chat"))
        self.assertEqual(default.model, "deepseek-v4-flash")
        self.assertEqual(default.route_reason, "policy_flash_default")

        conflict = router.decide(RoutingRequest("r2", "canon_conflict"))
        self.assertEqual(conflict.model, "deepseek-v4-pro")
        repeated = router.decide(
            RoutingRequest("r3", "ordinary_chat", prior_fast_failures=2)
        )
        self.assertEqual(repeated.model, "deepseek-v4-pro")
        checklist = router.decide(RoutingRequest("r-check", "checklist_overload"))
        self.assertEqual(checklist.model, "deepseek-v4-pro")
        repaired = router.decide(
            RoutingRequest("r4", "ordinary_chat", repair_failed=True)
        )
        self.assertEqual(repaired.model, "deepseek-v4-pro")
        self.assertEqual(repaired.max_repair_attempts, 1)

    def test_approved_loopback_runtime_is_allowed_but_external_scope_is_not(self) -> None:
        manifest = self.load(runtime_document())
        router = StagingPolicyRouter(manifest)
        self.assertEqual(
            router.decide(RoutingRequest("runtime", "ordinary_chat")).model,
            "deepseek-v4-flash",
        )
        unsafe = runtime_document()
        unsafe["service"]["external_listener_enabled"] = True  # type: ignore[index]
        unsafe["authorizations"]["external_network_listener"] = True  # type: ignore[index]
        with self.assertRaises(CapabilityManifestError):
            self.load(unsafe)

    def test_local_model_profile_must_keep_thinking_disabled(self) -> None:
        local = runtime_document()
        local["models"] = {
            "default": {
                "provider": "local",
                "model": LOCAL_MODEL_ALIAS,
                "thinking": "disabled",
            },
            "persona_escalation": {
                "provider": "local",
                "model": LOCAL_MODEL_ALIAS,
                "thinking": "disabled",
            },
        }
        router = StagingPolicyRouter(self.load(local))
        self.assertEqual(
            router.decide(RoutingRequest("local-runtime", "ordinary_chat")).model,
            LOCAL_MODEL_ALIAS,
        )

        local["models"]["default"]["thinking"] = "enabled"  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "unsupported thinking"):
            StagingPolicyRouter(self.load(local))

    def test_synthetic_memory_read_scope_never_becomes_real_memory_authority(self) -> None:
        manifest = self.load(runtime_document(synthetic_memory=True))
        self.assertTrue(manifest.capability_enabled("long_term_memory_read"))
        self.assertFalse(manifest.authorizations["real_memory"])
        self.assertIn("fictional synthetic", manifest.prompt_boundary())

    def test_qq_owner_private_scope_is_channel_only_and_memory_free(self) -> None:
        manifest = self.load(qq_owner_private_document())
        self.assertTrue(manifest.capability_enabled("qq_channel"))
        self.assertFalse(manifest.capability_enabled("long_term_memory_read"))
        self.assertFalse(manifest.capability_enabled("long_term_memory_write"))
        self.assertFalse(manifest.external_listener_enabled)

        unsafe = qq_owner_private_document()
        unsafe["capabilities"]["qq_channel"]["scope"] = "all QQ chats"  # type: ignore[index]
        with self.assertRaises(CapabilityManifestError):
            self.load(unsafe)

    def test_owner_profile_write_scope_is_exact_and_bounded(self) -> None:
        manifest = self.load(owner_profile_write_document())
        self.assertTrue(manifest.capability_enabled("long_term_memory_read"))
        self.assertTrue(manifest.capability_enabled("long_term_memory_write"))
        self.assertFalse(manifest.capability_enabled("tools"))
        unsafe = owner_profile_write_document()
        unsafe["capabilities"]["long_term_memory_write"][  # type: ignore[index]
            "scope"
        ] = "general memory write"
        with self.assertRaisesRegex(
            CapabilityManifestError, "exact confirmation boundary"
        ):
            self.load(unsafe)

    def test_qq_owner_memory_scope_is_exact_and_remains_read_only(self) -> None:
        for protocol in ("v1", "v2"):
            with self.subTest(protocol=protocol):
                manifest = self.load(
                    qq_owner_readonly_memory_document(protocol=protocol)
                )
                self.assertTrue(manifest.capability_enabled("long_term_memory_read"))
                self.assertFalse(manifest.capability_enabled("long_term_memory_write"))
                self.assertTrue(manifest.authorizations["real_memory"])
                self.assertIn(
                    "fixed verified Owner namespace",
                    manifest.prompt_boundary(),
                )
                StagingPolicyRouter(manifest)

        wrong_scope = qq_owner_readonly_memory_document()
        wrong_scope["capabilities"]["long_term_memory_read"][  # type: ignore[index]
            "scope"
        ] = "all owner memory"
        with self.assertRaises(CapabilityManifestError):
            self.load(wrong_scope)

        write_enabled = qq_owner_readonly_memory_document()
        write_enabled["capabilities"]["long_term_memory_write"][  # type: ignore[index]
            "enabled"
        ] = True
        with self.assertRaises(CapabilityManifestError):
            self.load(write_enabled)

    def test_unavailable_capability_requests_are_blocked(self) -> None:
        router = StagingPolicyRouter(self.load())
        decision = router.decide(
            RoutingRequest(
                "blocked",
                "tool_request",
                requested_capabilities=("conversation", "tools"),
            )
        )
        self.assertEqual(decision.action, "block")
        self.assertEqual(decision.blocked_capabilities, ("tools",))
        self.assertIsNone(decision.model)

    def test_guard_is_derived_from_disabled_manifest_capabilities(self) -> None:
        manifest = self.load()
        self.assertEqual(
            capability_violations("不记得了，长期记忆目前没有启用。", manifest),
            [],
        )
        self.assertEqual(
            capability_violations("你再说一次，我会好好记住的。", manifest),
            ["memory_write_claim"],
        )
        self.assertEqual(
            capability_violations("我已经发送了消息。", manifest),
            ["tool_action_claim"],
        )
        self.assertEqual(
            capability_violations("那时候刚见面，没来得及记太多。", manifest),
            ["memory_read_claim"],
        )
        self.assertEqual(
            capability_violations("我不太确定有没有存起来。", manifest),
            ["memory_state_ambiguity"],
        )
        boundary = manifest.prompt_boundary()
        self.assertIn("Do not narrate, infer, or imply any past meeting", boundary)
        self.assertIn("Do not promise that a repeated statement will be stored", boundary)


if __name__ == "__main__":
    unittest.main()
