from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re


class PersonaOutputError(ValueError):
    pass


class PersonaKind(str, Enum):
    MYUNA = "myuna"
    CHRYNA = "chryna"


@dataclass(frozen=True, slots=True)
class PersonaModule:
    kind: PersonaKind
    role_prompt: str
    reference_role: str

    def validate_draft(self, text: str) -> str:
        if not isinstance(text, str):
            raise PersonaOutputError("invalid_persona_draft")
        candidate = text.strip()
        if not candidate or "\x00" in candidate or len(candidate) > 12000:
            raise PersonaOutputError("invalid_persona_draft")
        return candidate


MYUNA_MODULE = PersonaModule(
    kind=PersonaKind.MYUNA,
    role_prompt=(
        "Respond only as Myuna. Do not simulate or quote Chryna. Preserve runtime "
        "capability truth and return one bounded natural-language draft."
    ),
    reference_role="myuna",
)


CHRYNA_MODULE = PersonaModule(
    kind=PersonaKind.CHRYNA,
    role_prompt=(
        "Respond only as Chryna: concise, precise, low-emotion, and operationally "
        "honest. Structured multiline analysis is allowed when useful. Return the "
        "inner text only; Core owns the single-star wrapper."
    ),
    reference_role="chryna",
)


_SPEAKER_LABEL = re.compile(r"^\s*(?:Chryna|科莱娜)\s*[:：]", re.I)
_MYUNA_ACTION_BLOCK = re.compile(r"（[^（）\n]{1,240}）")


def normalize_chryna_inner(text: str) -> str:
    candidate = CHRYNA_MODULE.validate_draft(text)
    if "**" in candidate:
        raise PersonaOutputError("chryna_double_star_forbidden")
    if _SPEAKER_LABEL.search(candidate):
        raise PersonaOutputError("chryna_speaker_label_forbidden")
    if _MYUNA_ACTION_BLOCK.search(candidate):
        raise PersonaOutputError("chryna_myuna_action_format_forbidden")
    if candidate.startswith("*") or candidate.endswith("*"):
        if not (candidate.startswith("*") and candidate.endswith("*")):
            raise PersonaOutputError("chryna_star_wrapper_unbalanced")
        candidate = candidate[1:-1].strip()
    if not candidate or "*" in candidate:
        raise PersonaOutputError("chryna_inner_shape_invalid")
    return candidate


@dataclass(frozen=True, slots=True)
class ComposedReply:
    reply: str
    personas: tuple[PersonaKind, ...]
    degraded: bool = False


class DualReplyComposer:
    def compose_chryna(self, chryna_draft: str) -> ComposedReply:
        inner = normalize_chryna_inner(chryna_draft)
        return ComposedReply(f"*{inner}*", (PersonaKind.CHRYNA,))

    def compose_dual(self, myuna_draft: str, chryna_draft: str) -> ComposedReply:
        myuna = MYUNA_MODULE.validate_draft(myuna_draft)
        inner = normalize_chryna_inner(chryna_draft)
        return ComposedReply(
            myuna + "\n*" + inner + "*",
            (PersonaKind.MYUNA, PersonaKind.CHRYNA),
        )
