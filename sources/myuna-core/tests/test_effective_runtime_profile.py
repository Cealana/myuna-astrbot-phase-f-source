from __future__ import annotations

from copy import deepcopy
import unittest

from myuna_core.effective_runtime_profile import (
    EffectiveRuntimeProfile,
    EffectiveRuntimeProfileError,
)


def reference(component_id: str, path: str, digest: str) -> dict[str, str]:
    return {
        "component_id": component_id,
        "source_kind": "repository_file",
        "source_reference": path,
        "content_sha256": digest,
    }


def document() -> dict[str, object]:
    names = {
        "core_release": ("core-release", "/srv/myuna/releases/core/a", "1" * 64),
        "definition_release": (
            "definition-release",
            "/srv/myuna/repos/definition/releases/v6/release/evidence/files.sha256",
            "2" * 64,
        ),
        "channel_capability_profile": (
            "channel-profile",
            "/srv/myuna/repos/deploy/config/capabilities/profile.json",
            "3" * 64,
        ),
        "memory_adapter": (
            "memory-adapter",
            "/srv/myuna/repos/core/src/myuna_core/memory/adapter.py",
            "4" * 64,
        ),
        "reply_contract": (
            "reply-contract",
            "/srv/myuna/repos/core/src/myuna_core/conversation.py",
            "5" * 64,
        ),
        "provider_policy": (
            "provider-policy",
            "/srv/myuna/repos/core/src/myuna_core/providers/policy.py",
            "6" * 64,
        ),
        "prompt_budget": (
            "prompt-budget",
            "/srv/myuna/repos/deploy/config/prompt-budget.json",
            "7" * 64,
        ),
    }
    components = {
        name: reference(component_id, path, digest)
        for name, (component_id, path, digest) in names.items()
    }
    components["core_release"]["source_kind"] = "immutable_release"
    components["definition_release"]["source_kind"] = "immutable_release"
    return {
        "schema_version": 1,
        "profile_id": "effective-v6-owner-private-candidate-v1",
        "environment": "dev",
        "state": "inactive_candidate",
        "components": components,
        "shadow_observers": [],
        "activation": {
            "automatic": False,
            "selected": False,
            "installed": False,
            "requires_new_plan_digest": True,
            "requires_live_preflight": True,
        },
    }


class EffectiveRuntimeProfileTests(unittest.TestCase):
    def test_profile_has_one_complete_component_identity_and_stable_digest(self) -> None:
        profile = EffectiveRuntimeProfile.from_document(document())
        self.assertEqual(len(profile.components), 7)
        self.assertEqual(profile, EffectiveRuntimeProfile.from_document(profile.as_document()))
        self.assertEqual(len(profile.profile_sha256), 64)
        self.assertEqual(profile.profile_sha256, EffectiveRuntimeProfile.from_document(document()).profile_sha256)

    def test_profile_cannot_select_install_or_activate_itself(self) -> None:
        for field in ("automatic", "selected", "installed"):
            candidate = deepcopy(document())
            candidate["activation"][field] = True
            with self.subTest(field=field):
                with self.assertRaises(EffectiveRuntimeProfileError):
                    EffectiveRuntimeProfile.from_document(candidate)

    def test_profile_requires_new_digest_and_live_preflight(self) -> None:
        for field in ("requires_new_plan_digest", "requires_live_preflight"):
            candidate = deepcopy(document())
            candidate["activation"][field] = False
            with self.subTest(field=field):
                with self.assertRaises(EffectiveRuntimeProfileError):
                    EffectiveRuntimeProfile.from_document(candidate)

    def test_missing_extra_duplicate_or_invalid_component_fails_closed(self) -> None:
        missing = deepcopy(document())
        del missing["components"]["memory_adapter"]
        extra = deepcopy(document())
        extra["components"]["vision"] = reference(
            "vision", "/srv/myuna/repos/core/vision.py", "8" * 64
        )
        duplicate = deepcopy(document())
        duplicate["components"]["prompt_budget"]["component_id"] = "provider-policy"
        invalid_digest = deepcopy(document())
        invalid_digest["components"]["core_release"]["content_sha256"] = "not-a-digest"
        for candidate in (missing, extra, duplicate, invalid_digest):
            with self.assertRaises(EffectiveRuntimeProfileError):
                EffectiveRuntimeProfile.from_document(candidate)

    def test_secrets_runtime_state_and_unapproved_roots_are_rejected(self) -> None:
        paths = (
            "/etc/myuna/secrets/token",
            "/run/myuna/socket",
            "/srv/myuna/repos/deploy/secrets/value",
            "relative/path",
        )
        for path in paths:
            candidate = deepcopy(document())
            candidate["components"]["provider_policy"]["source_reference"] = path
            with self.subTest(path=path):
                with self.assertRaises(EffectiveRuntimeProfileError):
                    EffectiveRuntimeProfile.from_document(candidate)


if __name__ == "__main__":
    unittest.main()
