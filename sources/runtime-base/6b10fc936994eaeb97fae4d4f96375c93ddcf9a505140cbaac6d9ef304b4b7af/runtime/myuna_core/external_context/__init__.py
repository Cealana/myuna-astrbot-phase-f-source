"""Typed source foundation for P07 external-authorized conversation epochs."""

from .contracts import (
    EXTERNAL_CONTEXT_SCHEMA,
    EXTERNAL_PROJECTION_POLICY,
    EXTERNAL_VISUAL_CONTEXT_SCHEMA,
    EXTERNAL_VISUAL_PROJECTION_POLICY,
    ExternalContextEnvelope,
    ExternalContextError,
    ExternalSummary,
    ExternalTurn,
    EgressSafetySignals,
    VisualEvidence,
    current_message_digest,
    visual_evidence_digest,
)
from .projection import (
    ExternalProjection,
    ExternalProjectionBuilder,
    ProjectionBudget,
)
from .runtime import (
    HybridExternalGenerationCoordinator,
    HybridGenerationError,
    HybridGenerationResult,
)

__all__ = [
    "EXTERNAL_CONTEXT_SCHEMA",
    "EXTERNAL_PROJECTION_POLICY",
    "EXTERNAL_VISUAL_CONTEXT_SCHEMA",
    "EXTERNAL_VISUAL_PROJECTION_POLICY",
    "EgressSafetySignals",
    "ExternalContextEnvelope",
    "ExternalContextError",
    "ExternalProjection",
    "ExternalProjectionBuilder",
    "ExternalSummary",
    "ExternalTurn",
    "HybridExternalGenerationCoordinator",
    "HybridGenerationError",
    "HybridGenerationResult",
    "ProjectionBudget",
    "VisualEvidence",
    "current_message_digest",
    "visual_evidence_digest",
]
