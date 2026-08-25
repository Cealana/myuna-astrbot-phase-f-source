"""Static assertions for the exact inactive V7.1 Definition profile."""

from __future__ import annotations

from myuna_core.definition_profile import V7_1_PROFILE


INTERACTION_CONTRACT = "references/26-v7.1-interaction-and-presentation.md"
CAPABILITY_BOUNDARY = "references/27-v7.1-runtime-capability-boundary.md"
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
    declared = V7_1_PROFILE.declared_documents()
    ordinary = V7_1_PROFILE.select()
    if V7_1_PROFILE.version != "v7.1":
        raise RuntimeError("v7_1_profile_version_rejected")
    if len(declared) != 20 or len(ordinary) != 11:
        raise RuntimeError("v7_1_profile_inventory_rejected")
    if INTERACTION_CONTRACT not in ordinary or CAPABILITY_BOUNDARY not in ordinary:
        raise RuntimeError("v7_1_boundary_rejected")
    if FORBIDDEN_DYNAMIC_DOCUMENTS.intersection(declared):
        raise RuntimeError("v7_1_dynamic_document_rejected")
