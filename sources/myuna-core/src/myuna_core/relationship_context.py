from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re


class RelationshipContextError(ValueError):
    pass


_GATED_NICKNAMES = frozenset({"Lana", "Lana-chan", "Darling", "Honey"})
_NICKNAME_PATTERNS = {
    nickname: re.compile(
        rf"(?<![A-Za-z0-9_-]){re.escape(nickname)}(?![A-Za-z0-9_-])",
        re.IGNORECASE,
    )
    for nickname in _GATED_NICKNAMES
}


@dataclass(frozen=True, slots=True)
class AuthoritativeRelationshipState:
    source: str
    observed_at: datetime
    allowed_nicknames: tuple[str, ...]
    affection_score: int | None = None

    def __post_init__(self) -> None:
        if not self.source:
            raise RelationshipContextError("relationship source is required")
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise RelationshipContextError("relationship time must include a timezone")
        if "Cealana" not in self.allowed_nicknames:
            raise RelationshipContextError("Cealana must remain an allowed name")
        if len(set(self.allowed_nicknames)) != len(self.allowed_nicknames):
            raise RelationshipContextError("relationship nickname allowlist contains duplicates")
        if self.affection_score is not None and (
            not isinstance(self.affection_score, int)
            or isinstance(self.affection_score, bool)
            or not 0 <= self.affection_score <= 100
        ):
            raise RelationshipContextError("affection score must be from 0 through 100")


@dataclass(frozen=True, slots=True)
class RelationshipContext:
    authoritative: bool
    allowed_nicknames: tuple[str, ...]
    source: str
    affection_score: int | None

    @classmethod
    def conservative_default(cls) -> "RelationshipContext":
        return cls(False, ("Cealana",), "runtime-state-unavailable", None)

    @classmethod
    def from_state(
        cls,
        state: AuthoritativeRelationshipState | None,
    ) -> "RelationshipContext":
        if state is None:
            return cls.conservative_default()
        return cls(True, state.allowed_nicknames, state.source, state.affection_score)

    def allows(self, nickname: str) -> bool:
        return nickname in self.allowed_nicknames

    def validate_reply(self, reply: str) -> tuple[str, ...]:
        violations = [
            f"gated_nickname_without_authority:{nickname}"
            for nickname in sorted(_GATED_NICKNAMES)
            if _NICKNAME_PATTERNS[nickname].search(reply) and not self.allows(nickname)
        ]
        return tuple(violations)

    def prompt_boundary(self) -> str:
        allowed = ", ".join(self.allowed_nicknames)
        if not self.authoritative:
            return (
                "No authoritative Affection State is available. Do not infer a relationship "
                f"stage from conversational warmth. Allowed owner name: {allowed}."
            )
        return (
            "Use only the authoritative relationship nickname allowlist. "
            f"Allowed owner names: {allowed}. The numeric score is runtime metadata, not dialogue."
        )
