from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from myuna_core.definition_profile import (
    DefinitionProfile,
    DefinitionProfileError,
    V5_PROFILE,
    V6_PROFILE,
    V7_PROFILE,
    V7_1_PROFILE,
    definition_profile_for,
)


class DefinitionProfileTests(unittest.TestCase):
    def test_versions_are_explicit(self) -> None:
        self.assertIs(definition_profile_for("v5"), V5_PROFILE)
        self.assertIs(definition_profile_for(" V6 "), V6_PROFILE)
        self.assertIs(definition_profile_for("v7"), V7_PROFILE)
        self.assertIs(definition_profile_for(" V7.1 "), V7_1_PROFILE)
        with self.assertRaises(DefinitionProfileError):
            definition_profile_for("v8")

    def test_v6_role_and_command_documents_are_selected_only_when_needed(self) -> None:
        ordinary = V6_PROFILE.select()
        chryna = V6_PROFILE.select(persona_route="chryna")
        check = V6_PROFILE.select(command_name="check")
        self.assertNotIn("references/17-chryna-core.md", ordinary)
        self.assertIn("references/17-chryna-core.md", chryna)
        self.assertNotIn("references/18-command-and-check-system.md", ordinary)
        self.assertIn("references/18-command-and-check-system.md", check)
        self.assertNotIn("references/01-persona.md", chryna)
        self.assertIn("references/16-hard-constraints-v6.md", chryna)

    def test_profile_deduplicates_shared_documents(self) -> None:
        selected = V6_PROFILE.select(
            persona_route="dual",
            command_name="testflight",
        )
        self.assertEqual(len(selected), len(set(selected)))

    def test_unknown_routes_topics_and_commands_fail_closed(self) -> None:
        for kwargs in (
            {"topic_tags": ("typo",)},
            {"persona_route": "unknown"},
            {"command_name": "unknown"},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(DefinitionProfileError):
                    V6_PROFILE.select(**kwargs)

    def test_v6_large_references_are_not_loaded_for_every_turn(self) -> None:
        ordinary = V6_PROFILE.select()
        for relative in (
            "references/03-appearance.md",
            "references/04-movement.md",
            "references/09-memory-policy.md",
            "references/11-tooling.md",
            "references/17-chryna-core.md",
            "references/18-command-and-check-system.md",
            "references/20-dialogue-style-reference.md",
            "references/25-server-reconciliation-changelog.md",
        ):
            with self.subTest(relative=relative):
                self.assertNotIn(relative, ordinary)

    def test_v7_phase1_excludes_future_affinity_documents(self) -> None:
        declared = set(V7_PROFILE.declared_documents())
        ordinary = V7_PROFILE.select()
        boundary = "references/26-v7-phase1-capability-boundary.md"
        self.assertIn(boundary, ordinary)
        self.assertNotIn("references/08-parameters.md", declared)
        self.assertNotIn("references/09-memory-policy.md", declared)
        self.assertNotIn("references/10-retrieval-policy.md", declared)
        self.assertNotIn("references/11-tooling.md", declared)
        self.assertNotIn("references/v7-relationship-state-and-continuity.md", declared)
        for topic in ("parameters", "memory", "tooling", "maintenance", "temporal"):
            with self.subTest(topic=topic):
                self.assertEqual(V7_PROFILE.select(topic_tags=(topic,)), ordinary)

    def test_v7_relationship_is_qualitative_and_boundary_guarded(self) -> None:
        selected = V7_PROFILE.select(topic_tags=("relationship",))
        self.assertIn("references/06-relationships.md", selected)
        self.assertIn("references/26-v7-phase1-capability-boundary.md", selected)
        self.assertNotIn("references/v7-relationship-state-and-continuity.md", selected)

    def test_v7_commands_always_include_phase1_boundary(self) -> None:
        boundary = "references/26-v7-phase1-capability-boundary.md"
        for command in V7_PROFILE.commands:
            with self.subTest(command=command):
                self.assertIn(boundary, V7_PROFILE.select(command_name=command))

    def test_v7_1_profile_binds_authoring_and_inactive_runtime_boundaries(self) -> None:
        interaction = "references/26-v7.1-interaction-and-presentation.md"
        boundary = "references/27-v7.1-runtime-capability-boundary.md"
        ordinary = V7_1_PROFILE.select()
        self.assertIn(interaction, ordinary)
        self.assertIn(boundary, ordinary)
        selected = V7_1_PROFILE.select(topic_tags=("relationship",))
        self.assertIn("references/v7-relationship-state-and-continuity.md", selected)
        self.assertIn(boundary, selected)
        for command in V7_1_PROFILE.commands:
            with self.subTest(command=command):
                self.assertIn(boundary, V7_1_PROFILE.select(command_name=command))

    def test_declared_documents_cover_every_branch(self) -> None:
        declared = set(V6_PROFILE.declared_documents())
        for relative in V6_PROFILE.select(
            topic_tags=V6_PROFILE.topics,
            persona_route="dual",
            command_name="diary",
        ):
            self.assertIn(relative, declared)

    def test_profile_rejects_raw_source_and_technical_paths(self) -> None:
        for relative in (
            "references/raw-source/hidden.md",
            "technical/runtime.md",
            "../outside.md",
        ):
            with self.subTest(relative=relative):
                with self.assertRaises(DefinitionProfileError):
                    DefinitionProfile("v6", (relative,))

    def test_validate_tree_fails_closed_for_missing_document(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(DefinitionProfileError):
                V6_PROFILE.validate_tree(root)


if __name__ == "__main__":
    unittest.main()
