from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Iterable, Mapping


class DefinitionProfileError(RuntimeError):
    """Raised when a versioned runtime Definition profile is unsafe or incomplete."""


def _validate_relative_document(relative: str) -> str:
    pure = PurePosixPath(relative)
    if (
        pure.is_absolute()
        or any(part in {"", ".", ".."} for part in pure.parts)
        or pure.suffix != ".md"
        or "raw-source" in pure.parts
        or "technical" in pure.parts
    ):
        raise DefinitionProfileError(f"unsafe runtime Definition path: {relative}")
    return pure.as_posix()


@dataclass(frozen=True, slots=True)
class DefinitionProfile:
    version: str
    always: tuple[str, ...]
    topics: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    persona_bases: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    personas: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    commands: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.version not in {"v5", "v6", "v7", "v7.1"}:
            raise DefinitionProfileError("unsupported Definition profile version")
        normalized_mappings: list[Mapping[str, tuple[str, ...]]] = []
        values = [*self.always]
        for mapping in (self.topics, self.persona_bases, self.personas, self.commands):
            normalized: dict[str, tuple[str, ...]] = {}
            for key, paths in mapping.items():
                if not key or not isinstance(key, str):
                    raise DefinitionProfileError("Definition profile key is invalid")
                if key != key.casefold() or not isinstance(paths, tuple):
                    raise DefinitionProfileError("Definition profile mapping is not canonical")
                normalized[key] = paths
                values.extend(paths)
            normalized_mappings.append(MappingProxyType(normalized))
        object.__setattr__(self, "topics", normalized_mappings[0])
        object.__setattr__(self, "persona_bases", normalized_mappings[1])
        object.__setattr__(self, "personas", normalized_mappings[2])
        object.__setattr__(self, "commands", normalized_mappings[3])
        for relative in values:
            _validate_relative_document(relative)

    def select(
        self,
        *,
        topic_tags: Iterable[str] = (),
        persona_route: str = "myuna",
        command_name: str | None = None,
    ) -> tuple[str, ...]:
        selected = list(self.persona_bases.get(persona_route, self.always))
        for topic in topic_tags:
            if topic not in self.topics:
                raise DefinitionProfileError(f"unknown Definition topic: {topic}")
            selected.extend(self.topics[topic])
        if persona_route != "myuna" and persona_route not in self.personas:
            raise DefinitionProfileError(
                f"unsupported persona route for {self.version}: {persona_route}"
            )
        selected.extend(self.personas.get(persona_route, ()))
        if command_name is not None:
            normalized_command = command_name.casefold()
            if normalized_command not in self.commands:
                raise DefinitionProfileError(
                    f"unknown Definition command for {self.version}: {command_name}"
                )
            selected.extend(self.commands[normalized_command])
        return tuple(dict.fromkeys(selected))

    def declared_documents(self) -> tuple[str, ...]:
        declared = list(self.always)
        for mapping in (self.topics, self.persona_bases, self.personas, self.commands):
            for paths in mapping.values():
                declared.extend(paths)
        return tuple(dict.fromkeys(declared))

    def validate_tree(self, definition_root: Path) -> int:
        if not definition_root.is_dir():
            raise DefinitionProfileError("Definition root is unavailable")
        declared = self.declared_documents()
        missing = [relative for relative in declared if not (definition_root / relative).is_file()]
        if missing:
            raise DefinitionProfileError(
                "runtime Definition profile is missing: " + ", ".join(missing)
            )
        return len(declared)


V5_PROFILE = DefinitionProfile(
    version="v5",
    always=(
        "references/00-overview.md",
        "references/01-persona.md",
        "references/02-voice.md",
        "references/05-behavior.md",
        "references/06-relationships.md",
        "references/07-worldbuilding.md",
        "references/08-parameters.md",
        "references/09-memory-policy.md",
        "references/10-retrieval-policy.md",
        "references/11-tooling.md",
        "references/12-conflicts-and-versioning.md",
        "references/14-processing-policy.md",
        "references/17-effective-v5-overlay-policy.md",
        "references/18-owner-action-input-contract.md",
        "references/19-human-reticence-and-disclosure.md",
        "references/20-owner-action-clarification-v2.md",
        "references/21-typed-turn-draft-and-reply-reliability-v1.md",
        "references/22-subjectless-action-voice-v1.md",
    ),
    topics={
        "appearance": (
            "references/03-appearance.md",
            "references/16-lifestyle-equipment.md",
        ),
        "movement": ("references/04-movement.md",),
        "motivation": (
            "references/13-motivation-notes.md",
            "references/15-v5-changelog.md",
        ),
    },
)


V6_PROFILE = DefinitionProfile(
    version="v6",
    always=(
        "references/00-overview.md",
        "references/01-persona.md",
        "references/02-voice.md",
        "references/05-behavior.md",
        "references/06-relationships.md",
        "references/16-hard-constraints-v6.md",
        "references/22-ordinary-workbench-and-disclosure-boundary.md",
        "references/23-owner-action-input-and-rendering.md",
        "references/24-reply-presentation-contract.md",
    ),
    topics={
        "appearance": (
            "references/03-appearance.md",
            "references/21-lifestyle-equipment-server-clarifications.md",
        ),
        "movement": ("references/04-movement.md",),
        "worldbuilding": ("references/07-worldbuilding.md",),
        "parameters": ("references/08-parameters.md",),
        "memory": (
            "references/09-memory-policy.md",
            "references/10-retrieval-policy.md",
        ),
        "tooling": ("references/11-tooling.md",),
        "maintenance": (
            "references/12-conflicts-and-versioning.md",
            "references/14-processing-policy.md",
            "references/25-server-reconciliation-changelog.md",
        ),
        "motivation": (
            "references/13-motivation-notes.md",
            "references/19-v6-changelog.md",
        ),
        "style_examples": ("references/20-dialogue-style-reference.md",),
    },
    persona_bases={
        "chryna": (
            "references/00-overview.md",
            "references/16-hard-constraints-v6.md",
            "references/22-ordinary-workbench-and-disclosure-boundary.md",
            "references/24-reply-presentation-contract.md",
        ),
    },
    personas={
        "chryna": ("references/17-chryna-core.md",),
        "dual": ("references/17-chryna-core.md",),
    },
    commands={
        "check": ("references/18-command-and-check-system.md",),
        "testflight": ("references/18-command-and-check-system.md",),
        "checklist": ("references/18-command-and-check-system.md",),
        "info": ("references/18-command-and-check-system.md",),
        "workbench": ("references/18-command-and-check-system.md",),
        "exitworkbench": ("references/18-command-and-check-system.md",),
        "blueout": ("references/18-command-and-check-system.md",),
        "diary": ("references/18-command-and-check-system.md",),
    },
)


_V7_PHASE1_BOUNDARY = "references/26-v7-phase1-capability-boundary.md"


V7_PROFILE = DefinitionProfile(
    version="v7",
    always=(
        "references/00-overview.md",
        "references/01-persona.md",
        "references/02-voice.md",
        "references/05-behavior.md",
        "references/06-relationships.md",
        "references/16-hard-constraints-v6.md",
        "references/22-ordinary-workbench-and-disclosure-boundary.md",
        "references/23-owner-action-input-and-rendering.md",
        "references/24-reply-presentation-contract.md",
        _V7_PHASE1_BOUNDARY,
    ),
    topics={
        "appearance": (
            "references/03-appearance.md",
            "references/21-lifestyle-equipment-server-clarifications.md",
        ),
        "movement": ("references/04-movement.md",),
        "worldbuilding": ("references/07-worldbuilding.md",),
        "parameters": (_V7_PHASE1_BOUNDARY,),
        "memory": (_V7_PHASE1_BOUNDARY,),
        "tooling": (_V7_PHASE1_BOUNDARY,),
        "maintenance": (_V7_PHASE1_BOUNDARY,),
        "motivation": ("references/13-motivation-notes.md",),
        "style_examples": ("references/20-dialogue-style-reference.md",),
        "relationship": (
            "references/06-relationships.md",
            _V7_PHASE1_BOUNDARY,
        ),
        "temporal": (_V7_PHASE1_BOUNDARY,),
    },
    persona_bases={
        "chryna": (
            "references/00-overview.md",
            "references/16-hard-constraints-v6.md",
            "references/22-ordinary-workbench-and-disclosure-boundary.md",
            "references/24-reply-presentation-contract.md",
            _V7_PHASE1_BOUNDARY,
        ),
    },
    personas={
        "chryna": ("references/17-chryna-core.md",),
        "dual": ("references/17-chryna-core.md",),
    },
    commands={
        "check": ("references/18-command-and-check-system.md", _V7_PHASE1_BOUNDARY),
        "testflight": (
            "references/18-command-and-check-system.md",
            _V7_PHASE1_BOUNDARY,
        ),
        "checklist": (
            "references/18-command-and-check-system.md",
            _V7_PHASE1_BOUNDARY,
        ),
        "info": ("references/18-command-and-check-system.md", _V7_PHASE1_BOUNDARY),
        "workbench": (
            "references/18-command-and-check-system.md",
            _V7_PHASE1_BOUNDARY,
        ),
        "exitworkbench": (
            "references/18-command-and-check-system.md",
            _V7_PHASE1_BOUNDARY,
        ),
        "blueout": (
            "references/18-command-and-check-system.md",
            _V7_PHASE1_BOUNDARY,
        ),
        "diary": ("references/18-command-and-check-system.md", _V7_PHASE1_BOUNDARY),
    },
)


_V7_1_INTERACTION_CONTRACT = "references/26-v7.1-interaction-and-presentation.md"
_V7_1_RUNTIME_BOUNDARY = "references/27-v7.1-runtime-capability-boundary.md"


V7_1_PROFILE = DefinitionProfile(
    version="v7.1",
    always=(
        "references/00-overview.md",
        "references/01-persona.md",
        "references/02-voice.md",
        "references/05-behavior.md",
        "references/06-relationships.md",
        "references/16-hard-constraints-v6.md",
        "references/22-ordinary-workbench-and-disclosure-boundary.md",
        "references/23-owner-action-input-and-rendering.md",
        "references/24-reply-presentation-contract.md",
        _V7_1_INTERACTION_CONTRACT,
        _V7_1_RUNTIME_BOUNDARY,
    ),
    topics={
        "appearance": (
            "references/03-appearance.md",
            "references/21-lifestyle-equipment-server-clarifications.md",
        ),
        "movement": ("references/04-movement.md",),
        "worldbuilding": ("references/07-worldbuilding.md",),
        "parameters": (_V7_1_RUNTIME_BOUNDARY,),
        "memory": (_V7_1_RUNTIME_BOUNDARY,),
        "tooling": (_V7_1_RUNTIME_BOUNDARY,),
        "maintenance": (_V7_1_RUNTIME_BOUNDARY,),
        "motivation": ("references/13-motivation-notes.md",),
        "style_examples": ("references/20-dialogue-style-reference.md",),
        "relationship": (
            "references/06-relationships.md",
            "references/v7-relationship-state-and-continuity.md",
            _V7_1_RUNTIME_BOUNDARY,
        ),
        "temporal": (_V7_1_RUNTIME_BOUNDARY,),
    },
    persona_bases={
        "chryna": (
            "references/00-overview.md",
            "references/16-hard-constraints-v6.md",
            "references/22-ordinary-workbench-and-disclosure-boundary.md",
            "references/24-reply-presentation-contract.md",
            _V7_1_RUNTIME_BOUNDARY,
        ),
    },
    personas={
        "chryna": ("references/17-chryna-core.md",),
        "dual": ("references/17-chryna-core.md",),
    },
    commands={
        "check": ("references/18-command-and-check-system.md", _V7_1_RUNTIME_BOUNDARY),
        "testflight": (
            "references/18-command-and-check-system.md",
            _V7_1_RUNTIME_BOUNDARY,
        ),
        "checklist": (
            "references/18-command-and-check-system.md",
            _V7_1_RUNTIME_BOUNDARY,
        ),
        "info": ("references/18-command-and-check-system.md", _V7_1_RUNTIME_BOUNDARY),
        "workbench": (
            "references/18-command-and-check-system.md",
            _V7_1_RUNTIME_BOUNDARY,
        ),
        "exitworkbench": (
            "references/18-command-and-check-system.md",
            _V7_1_RUNTIME_BOUNDARY,
        ),
        "blueout": (
            "references/18-command-and-check-system.md",
            _V7_1_RUNTIME_BOUNDARY,
        ),
        "diary": ("references/18-command-and-check-system.md", _V7_1_RUNTIME_BOUNDARY),
    },
)


def definition_profile_for(version: str) -> DefinitionProfile:
    normalized = version.strip().casefold()
    if normalized == "v5":
        return V5_PROFILE
    if normalized == "v6":
        return V6_PROFILE
    if normalized == "v7":
        return V7_PROFILE
    if normalized == "v7.1":
        return V7_1_PROFILE
    raise DefinitionProfileError(f"no runtime Definition profile for {version!r}")
