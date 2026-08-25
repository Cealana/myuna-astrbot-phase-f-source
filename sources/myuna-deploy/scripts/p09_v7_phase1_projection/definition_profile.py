"""Static assertions for the exact V7 Phase-1 Definition profile."""

from __future__ import annotations

from myuna_core.definition_profile import V7_PROFILE


CAPABILITY_BOUNDARY = "references/26-v7-phase1-capability-boundary.md"
FORBIDDEN_DYNAMIC_DOCUMENTS = frozenset(
    {
        "references/08-parameters.md",
        "references/09-memory-policy.md",
        "references/10-retrieval-policy.md",
        "references/11-tooling.md",
        "references/12-conflicts-and-versioning.md",
        "references/14-processing-policy.md",
    }
)


def validate_definition_profile_projection() -> None:
    declared = V7_PROFILE.declared_documents()
    ordinary = V7_PROFILE.select()
    if V7_PROFILE.version != "v7":
        raise RuntimeError("v7_profile_version_rejected")
    if len(declared) != 18 or len(ordinary) != 10:
        raise RuntimeError("v7_profile_inventory_rejected")
    if CAPABILITY_BOUNDARY not in ordinary:
        raise RuntimeError("v7_capability_boundary_rejected")
    if FORBIDDEN_DYNAMIC_DOCUMENTS.intersection(declared):
        raise RuntimeError("v7_dynamic_document_rejected")
