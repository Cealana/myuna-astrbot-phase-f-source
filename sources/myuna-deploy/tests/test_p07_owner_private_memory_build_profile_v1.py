from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import re
import unittest

from scripts import build_p07_hybrid_live_releases_v1 as builder


DEPLOY = Path(__file__).resolve().parents[1]
CORE = Path(
    os.environ.get(
        "P07_MEMORY_CORE_SOURCE",
        "/srv/myuna/repos/core",
    )
)


class OwnerPrivateMemoryBuildProfileTests(unittest.TestCase):
    def test_profile_is_additive_closed_and_keeps_parent_rollback(self) -> None:
        self.assertEqual(
            builder._OWNER_PRIVATE_MEMORY_RUNTIME_PROFILE,
            "p07-owner-private-memory-v1",
        )
        self.assertEqual(
            set(builder._OWNER_PRIVATE_MEMORY_OVERLAYS)
            - set(builder._RUNTIME_OVERLAYS),
            {
                "p07_owner_day_diary_v2.py",
                "p07_owner_private_memory_runtime_v1.py",
                "p07_reflective_diary_worker_v1.py",
            },
        )
        contract = builder._OWNER_PRIVATE_MEMORY_CONTRACT
        self.assertEqual(contract["archive"], "new-delivered-turns-only")
        self.assertFalse(contract["existing_history_migration"])
        self.assertFalse(contract["summary_used"])
        self.assertTrue(contract["compressed_parent_rollback"])
        self.assertFalse(contract["p15_projection_active"])
        self.assertEqual(contract["default_calendar_zone"], "Asia/Shanghai")
        self.assertEqual(
            contract["calendar_zones"],
            ["America/Los_Angeles", "Asia/Shanghai"],
        )
        self.assertEqual(
            contract["calendar_zone_selector"], "digest-bound-iana-owner-day-v2"
        )
        self.assertEqual(
            contract["p08_lifecycle"],
            "activation-watermark-new-events-only",
        )
        diary = contract["reflective_diary"]
        self.assertTrue(diary["complete_day_required"])
        self.assertEqual(diary["partial_day_diary"], "preview-only-never-final")
        self.assertEqual(diary["default_owner_day_boundary"], "06:00")
        self.assertEqual(
            diary["generation"], "disabled-unless-independent-v2-selector"
        )
        self.assertEqual(
            diary["overflow"],
            "coverage-incomplete-no-provider-call",
        )
        self.assertEqual(diary["rollback"], "local-only-disabled")
        self.assertEqual(diary["selector"], "digest-bound-separate-v2")
        self.assertEqual(
            diary["core_provider_gate"],
            "protected-exact-egress-binding-digest",
        )

    @unittest.skipUnless(CORE.is_dir(), "exact Core worktree required")
    def test_import_closure_contains_runtime_memory_and_no_forbidden_provider(self) -> None:
        forbidden = tuple(
            prefix
            for prefix in builder._FORBIDDEN_RUNTIME_CORE_PREFIXES
            if prefix
            not in {
                "myuna_core.active_temporal_context",
                "myuna_core.capability_runtime",
                "myuna_core.trusted_time",
            }
        )
        closure = builder.runtime_core_import_closure(
            CORE,
            root_modules=builder.runtime_overlay_core_root_modules(
                DEPLOY,
                CORE,
                builder._OWNER_PRIVATE_MEMORY_OVERLAYS,
            ),
            forbidden_prefixes=forbidden,
        )
        self.assertIn(
            "myuna_core/episodic_memory/runtime_context.py",
            closure,
        )
        self.assertIn("myuna_core/episodic_memory/delivery.py", closure)
        self.assertIn("myuna_core/episodic_memory/temporal_bridge.py", closure)
        self.assertIn("myuna_core/episodic_memory/diary_generation.py", closure)
        self.assertIn("myuna_core/episodic_memory/owner_day.py", closure)
        self.assertIn("myuna_core/episodic_memory/owner_day_generation.py", closure)
        self.assertIn("myuna_core/active_temporal_context/time.py", closure)
        self.assertIn("myuna_core/active_temporal_context/protocol.py", closure)
        self.assertIn("myuna_core/memory_aware_turn_protocol.py", closure)
        self.assertIn("myuna_core/owner_profile/write_intent.py", closure)
        self.assertNotIn("myuna_core/owner_profile/write_candidate.py", closure)
        self.assertFalse(
            any(path.startswith("myuna_core/providers/") for path in closure)
        )

    def test_provider_invocation_has_no_active_runtime_caller(self) -> None:
        production_paths = tuple((DEPLOY / "scripts").glob("*.py"))
        callers = []
        for path in production_paths:
            source = path.read_text(encoding="utf-8")
            if re.search(r"\binvoke_provider_step\b", source):
                callers.append(path.name)
        self.assertEqual(callers, [])
        gateway = (DEPLOY / "scripts/telegram_owner_runtime_gateway.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("from myuna_core.memory_aware_turn_protocol import", gateway)
        self.assertNotIn("memory_aware_provider_invocation", gateway)

    def test_changed_runtime_sources_parse_and_contract_is_content_free(self) -> None:
        paths = (
            DEPLOY / "scripts/p07_owner_private_memory_runtime_v1.py",
            DEPLOY / "scripts/p07_owner_day_diary_v2.py",
            DEPLOY / "scripts/p07_reflective_diary_worker_v1.py",
            DEPLOY / "scripts/telegram_owner_runtime_gateway.py",
            DEPLOY / "scripts/p08_temporal_gateway_v1.py",
            DEPLOY / "scripts/build_p07_hybrid_live_releases_v1.py",
            DEPLOY / "scripts/p07_owner_private_memory_runtime_artifact_v1.py",
        )
        for path in paths:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        serialized = json.dumps(
            builder._OWNER_PRIVATE_MEMORY_CONTRACT,
            separators=(",", ":"),
            sort_keys=True,
        )
        for forbidden in (
            "credential_value",
            "private_message",
            "provider_payload",
            "secret",
        ):
            self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main()
