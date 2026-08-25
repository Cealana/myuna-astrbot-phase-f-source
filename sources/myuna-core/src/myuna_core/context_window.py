from __future__ import annotations

from dataclasses import dataclass


DEFAULT_CONTEXT_MAX_MESSAGES = 12
DEFAULT_CONTEXT_MAX_CHARACTERS = 16_000
MIN_CONTEXT_MAX_MESSAGES = 2
MAX_CONTEXT_MAX_MESSAGES = 256
MIN_CONTEXT_MAX_CHARACTERS = 4_000
MAX_CONTEXT_MAX_CHARACTERS = 262_144


class ContextWindowPolicyError(ValueError):
    """Raised when a short-term conversation-window policy is unsafe."""


@dataclass(frozen=True, slots=True)
class ContextWindowPolicy:
    """Deterministic limits for volatile short-term conversation context.

    This policy only bounds messages already supplied by an authenticated
    channel gateway. It does not retrieve medium-term state or long-term
    memory and it does not make either source authoritative.
    """

    max_messages: int = DEFAULT_CONTEXT_MAX_MESSAGES
    max_characters: int = DEFAULT_CONTEXT_MAX_CHARACTERS

    def __post_init__(self) -> None:
        if (
            not isinstance(self.max_messages, int)
            or isinstance(self.max_messages, bool)
            or not MIN_CONTEXT_MAX_MESSAGES
            <= self.max_messages
            <= MAX_CONTEXT_MAX_MESSAGES
            or self.max_messages % 2
        ):
            raise ContextWindowPolicyError(
                "context max messages must be an even integer between 2 and 256"
            )
        if (
            not isinstance(self.max_characters, int)
            or isinstance(self.max_characters, bool)
            or not MIN_CONTEXT_MAX_CHARACTERS
            <= self.max_characters
            <= MAX_CONTEXT_MAX_CHARACTERS
        ):
            raise ContextWindowPolicyError(
                "context max characters must be between 4000 and 262144"
            )

    @classmethod
    def default(cls) -> "ContextWindowPolicy":
        return cls()

    def public_metadata(self) -> dict[str, int | str]:
        return {
            "policy": "volatile-short-term-context-v1",
            "max_messages": self.max_messages,
            "max_characters": self.max_characters,
        }
