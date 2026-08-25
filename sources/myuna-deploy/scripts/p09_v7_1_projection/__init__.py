"""Importable, inactive V7.1 projection for the Telegram runtime."""

from .adapter import adapter_policy_for, preserve_rendered_reply
from .conversation import local_core_sections_paths
from .definition_profile import validate_definition_profile_projection


def validate_projection() -> None:
    validate_definition_profile_projection()
    if local_core_sections_paths("v7.1") != (
        "SKILL.md",
        "references/26-v7.1-interaction-and-presentation.md",
        "references/27-v7.1-runtime-capability-boundary.md",
    ):
        raise RuntimeError("v7_1_conversation_projection_rejected")
    observer = adapter_policy_for(
        "（synthetic observer question?）",
        hybrid_external_generation=True,
    )
    if (
        observer.route != "observer_inquiry"
        or observer.legacy_history_write
        or observer.external_epoch_write
        or observer.background_polling
    ):
        raise RuntimeError("v7_1_observer_projection_rejected")
    if preserve_rendered_reply("first\n\nsecond") != "first\n\nsecond":
        raise RuntimeError("v7_1_ordered_reply_projection_rejected")
