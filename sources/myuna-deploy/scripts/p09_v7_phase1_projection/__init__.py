"""Importable, static V7 Phase-1 projection for the Telegram runtime."""

from .conversation import local_core_sections_paths
from .definition_profile import validate_definition_profile_projection


def validate_projection() -> None:
    validate_definition_profile_projection()
    if local_core_sections_paths("v7") != (
        "SKILL.md",
        "references/26-v7-phase1-capability-boundary.md",
    ):
        raise RuntimeError("v7_conversation_projection_rejected")
