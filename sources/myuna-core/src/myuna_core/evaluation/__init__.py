"""Offline-safe evaluation helpers. Importing this package performs no model call."""

from .golden import (
    assemble_system_prompt,
    capability_violations,
    evaluate_reply,
    load_approved_cases,
    parse_model_reply,
    verify_staging_build,
)

__all__ = (
    "assemble_system_prompt",
    "capability_violations",
    "evaluate_reply",
    "load_approved_cases",
    "parse_model_reply",
    "verify_staging_build",
)
