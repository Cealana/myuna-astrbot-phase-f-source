from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence


DEFAULT_DEFINITION_PROMPT_MAX_CHARACTERS = 300_000
DEFAULT_MODEL_INPUT_MAX_CHARACTERS = 400_000
MIN_DEFINITION_PROMPT_MAX_CHARACTERS = 110_000
MAX_DEFINITION_PROMPT_MAX_CHARACTERS = 524_288
MIN_MODEL_INPUT_MAX_CHARACTERS = 200_000
MAX_MODEL_INPUT_MAX_CHARACTERS = 700_000
MIN_MODEL_INPUT_HEADROOM_CHARACTERS = 65_536


class PromptBudgetPolicyError(ValueError):
    """Raised when prompt budgets or assembled input violate a safety boundary."""


def _bounded_integer(
    value: int,
    *,
    field_name: str,
    minimum: int,
    maximum: int,
) -> None:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise PromptBudgetPolicyError(
            f"{field_name} must be an integer between {minimum} and {maximum}"
        )


def validate_model_input_limit(value: int) -> None:
    _bounded_integer(
        value,
        field_name="model input max characters",
        minimum=MIN_MODEL_INPUT_MAX_CHARACTERS,
        maximum=MAX_MODEL_INPUT_MAX_CHARACTERS,
    )


def validate_model_input_characters(
    characters: int,
    *,
    max_characters: int,
) -> int:
    validate_model_input_limit(max_characters)
    if not isinstance(characters, int) or isinstance(characters, bool) or characters < 0:
        raise PromptBudgetPolicyError(
            "combined model input character count must be a non-negative integer"
        )
    if characters > max_characters:
        raise PromptBudgetPolicyError(
            "combined model input exceeds configured "
            f"{max_characters} character budget"
        )
    return characters


@dataclass(frozen=True, slots=True)
class PromptBudgetPolicy:
    """Independent budgets for Definition assembly and complete model input.

    Character counts are deterministic Core-side safety limits. They are not
    token counts and do not advertise a provider's context-window capacity.
    """

    definition_prompt_max_characters: int = (
        DEFAULT_DEFINITION_PROMPT_MAX_CHARACTERS
    )
    model_input_max_characters: int = DEFAULT_MODEL_INPUT_MAX_CHARACTERS

    def __post_init__(self) -> None:
        _bounded_integer(
            self.definition_prompt_max_characters,
            field_name="Definition prompt max characters",
            minimum=MIN_DEFINITION_PROMPT_MAX_CHARACTERS,
            maximum=MAX_DEFINITION_PROMPT_MAX_CHARACTERS,
        )
        validate_model_input_limit(self.model_input_max_characters)
        if (
            self.model_input_max_characters
            - self.definition_prompt_max_characters
            < MIN_MODEL_INPUT_HEADROOM_CHARACTERS
        ):
            raise PromptBudgetPolicyError(
                "model input budget must reserve at least 65536 characters "
                "beyond the Definition prompt budget"
            )

    @classmethod
    def default(cls) -> "PromptBudgetPolicy":
        return cls()

    def validate_definition_prompt(self, prompt: str) -> int:
        if not isinstance(prompt, str):
            raise PromptBudgetPolicyError("assembled Definition prompt must be text")
        characters = len(prompt)
        if characters > self.definition_prompt_max_characters:
            raise PromptBudgetPolicyError(
                "assembled runtime Definition context exceeds configured "
                f"{self.definition_prompt_max_characters} character budget"
            )
        return characters

    def validate_model_messages(
        self,
        messages: Sequence[Mapping[str, str]],
    ) -> int:
        characters = 0
        for message in messages:
            content = message.get("content")
            if not isinstance(content, str):
                raise PromptBudgetPolicyError("model message content must be text")
            characters += len(content)
        return validate_model_input_characters(
            characters,
            max_characters=self.model_input_max_characters,
        )

    def public_metadata(self) -> dict[str, int | str]:
        return {
            "policy": "prompt-budget-v1",
            "unit": "characters",
            "definition_prompt_max_characters": (
                self.definition_prompt_max_characters
            ),
            "model_input_max_characters": self.model_input_max_characters,
            "minimum_model_input_headroom_characters": (
                MIN_MODEL_INPUT_HEADROOM_CHARACTERS
            ),
        }
