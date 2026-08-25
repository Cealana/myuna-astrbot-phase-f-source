from __future__ import annotations

from typing import Any

from .concepts import normalize
from .scoring import record_chunks


def _ngrams(text: str, size: int = 3) -> set[str]:
    compact = normalize(text)
    if not compact:
        return set()
    if len(compact) <= size:
        return {compact}
    return {compact[index : index + size] for index in range(len(compact) - size + 1)}


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def near_duplicate(candidate: dict[str, Any], selected: dict[str, Any]) -> bool:
    """Keep deep recall useful by suppressing near-identical runner-ups."""

    candidate_text = " ".join(record_chunks(candidate, support=False))
    selected_text = " ".join(record_chunks(selected, support=False))
    text_overlap = _jaccard(_ngrams(candidate_text), _ngrams(selected_text))
    tag_overlap = _jaccard(
        set(map(str, candidate.get("tags") or [])),
        set(map(str, selected.get("tags") or [])),
    )
    scope_overlap = _jaccard(
        set(map(str, candidate.get("scope") or [])),
        set(map(str, selected.get("scope") or [])),
    )
    return text_overlap >= 0.72 or (
        text_overlap >= 0.48 and tag_overlap >= 0.67 and scope_overlap >= 0.67
    )
