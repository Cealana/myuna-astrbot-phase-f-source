"""Exact V7.1 Definition and ordered-reply projection paths."""

from __future__ import annotations


INTERACTION_CONTRACT = "references/26-v7.1-interaction-and-presentation.md"
CAPABILITY_BOUNDARY = "references/27-v7.1-runtime-capability-boundary.md"


def local_core_sections_paths(release_version: str) -> tuple[str, ...]:
    normalized = release_version.strip().casefold()
    if normalized == "v7.1":
        return ("SKILL.md", INTERACTION_CONTRACT, CAPABILITY_BOUNDARY)
    if normalized in {"v5", "v6"}:
        return ("SKILL.md",)
    raise ValueError("unsupported Definition projection version")
