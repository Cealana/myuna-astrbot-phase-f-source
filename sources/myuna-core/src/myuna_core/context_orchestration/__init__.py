"""Typed, source-only P15 relevance and retention foundation."""

from .adapters import AffinityCapabilityBinding, Generation12Binding
from .contracts import (
    P15_CONTRACT_SCHEMA,
    P15_INPUT_SCHEMA,
    P15_RESULT_SCHEMA,
    P15SelectionInput,
    P15SelectionResult,
)
from .selection import select_context

__all__ = [
    "P15_CONTRACT_SCHEMA",
    "P15_INPUT_SCHEMA",
    "P15_RESULT_SCHEMA",
    "P15SelectionInput",
    "P15SelectionResult",
    "AffinityCapabilityBinding",
    "Generation12Binding",
    "select_context",
]
