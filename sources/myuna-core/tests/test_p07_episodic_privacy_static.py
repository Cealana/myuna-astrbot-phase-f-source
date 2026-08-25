from __future__ import annotations

import ast
from pathlib import Path
import unittest

from myuna_core.episodic_memory import (
    ContextLimits,
    DynamicContextOracle,
    project_all_active_temporal_items,
)

from tests.episodic_memory_fixtures import make_turns


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "myuna_core" / "episodic_memory"


class EpisodicPrivacyStaticTests(unittest.TestCase):
    def test_package_has_no_provider_channel_network_or_duplicate_p08_store_import(self) -> None:
        prohibited = {
            "httpx",
            "requests",
            "urllib.request",
            "myuna_core.channels",
            "myuna_core.providers",
            "myuna_core.active_temporal_context.store",
            "myuna_core.owner_profile.write_runtime",
        }
        imported: set[str] = set()
        for path in PACKAGE.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module is not None:
                    imported.add(node.module)
        self.assertTrue(prohibited.isdisjoint(imported))

    def test_content_free_occupancy_never_contains_raw_or_fixed_context(self) -> None:
        turns = make_turns(2, text_size=4)
        temporal = project_all_active_temporal_items(
            (),
            maximum_characters=1_000,
            maximum_serialized_bytes=1_000,
            maximum_tokens=1_000,
            token_counter=lambda fragments: 0,
        )
        projection = DynamicContextOracle(
            ContextLimits(), token_counter=lambda messages: len(messages)
        ).project_all_or_fail(
            fixed_messages=({"role": "system", "content": "PRIVATE SYNTHETIC FIXED"},),
            turns=turns,
            current_message="PRIVATE SYNTHETIC CURRENT",
            trusted_time_binding=turns[-1].draft.time_binding,
            temporal_projection=temporal,
        )
        audit = str(projection.occupancy.audit_projection())
        self.assertNotIn("PRIVATE", audit)
        self.assertNotIn("Owner", audit)
        self.assertNotIn("Myuna", audit)

    def test_source_exposes_no_delete_retention_or_profile_promotion_api(self) -> None:
        exported = (PACKAGE / "__init__.py").read_text(encoding="utf-8")
        self.assertNotIn("delete_turn", exported)
        self.assertNotIn("compact_raw", exported)
        self.assertNotIn("promote_profile", exported)

    def test_raw_authority_has_no_reverse_edge_to_derivative_modules(self) -> None:
        derivative_names = {
            "diary",
            "index",
            "retrieval",
            "runtime_context",
        }
        for name in ("contracts.py", "store.py", "delivery.py"):
            path = PACKAGE / name
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            imported = {
                node.module.rsplit(".", 1)[-1]
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module is not None
            }
            self.assertTrue(derivative_names.isdisjoint(imported), name)

    def test_derivative_store_has_no_active_queue_thread_or_provider_route(self) -> None:
        source = (PACKAGE / "diary.py").read_text(encoding="utf-8")
        self.assertNotIn("CREATE TABLE diary_job_events", source)
        self.assertNotIn("threading", source)
        self.assertNotIn("Thread(", source)
        self.assertNotIn("provider.generate", source)
        self.assertIn("diary_job_queue_retired", source)


if __name__ == "__main__":
    unittest.main()
