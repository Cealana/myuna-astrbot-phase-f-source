"""Narrow projection of the V7 local-core-sections path contract."""

from __future__ import annotations


CAPABILITY_BOUNDARY = "references/26-v7-phase1-capability-boundary.md"


def local_core_sections_paths(release_version: str) -> tuple[str, ...]:
    normalized = release_version.strip().casefold()
    if normalized == "v7":
        return ("SKILL.md", CAPABILITY_BOUNDARY)
    if normalized in {"v5", "v6"}:
        return ("SKILL.md",)
    raise ValueError("unsupported Definition projection version")
