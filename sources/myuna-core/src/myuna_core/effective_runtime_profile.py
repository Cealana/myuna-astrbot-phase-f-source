from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from types import MappingProxyType
from typing import Mapping


SCHEMA_VERSION = 1
INACTIVE_STATE = "inactive_candidate"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_COMPONENTS = frozenset(
    {
        "core_release",
        "definition_release",
        "channel_capability_profile",
        "memory_adapter",
        "reply_contract",
        "provider_policy",
        "prompt_budget",
    }
)
_SOURCE_KINDS = frozenset({"immutable_release", "repository_file"})
_ALLOWED_ROOTS = (
    PurePosixPath("/srv/myuna/releases/core"),
    PurePosixPath("/srv/myuna/repos/core"),
    PurePosixPath("/srv/myuna/repos/deploy"),
    PurePosixPath("/srv/myuna/repos/definition/releases"),
)


class EffectiveRuntimeProfileError(ValueError):
    """Raised when an inactive runtime composition is unsafe or ambiguous."""


def _reject() -> EffectiveRuntimeProfileError:
    return EffectiveRuntimeProfileError("effective runtime profile rejected")


def _exact(document: Mapping[str, object], expected: set[str] | frozenset[str]) -> None:
    if set(document) != set(expected):
        raise ValueError("effective runtime profile fields do not match the v1 schema")


def _identifier(value: object) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError("component identifier is unsafe")
    return value


def _source_reference(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("component source reference must be a path")
    path = PurePosixPath(value)
    if not path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("component source reference must be a canonical absolute path")
    if not any(path == root or root in path.parents for root in _ALLOWED_ROOTS):
        raise ValueError("component source reference is outside approved roots")
    if any(part.casefold() in {"secret", "secrets", "credentials"} for part in path.parts):
        raise ValueError("component source reference cannot address secrets")
    return path.as_posix()


@dataclass(frozen=True, slots=True)
class RuntimeComponentReference:
    component_id: str
    source_kind: str
    source_reference: str
    content_sha256: str

    @classmethod
    def from_document(cls, document: object) -> RuntimeComponentReference:
        if not isinstance(document, Mapping):
            raise ValueError("component reference must be an object")
        _exact(
            document,
            {"component_id", "source_kind", "source_reference", "content_sha256"},
        )
        source_kind = document["source_kind"]
        if source_kind not in _SOURCE_KINDS:
            raise ValueError("unsupported component source kind")
        digest = document["content_sha256"]
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise ValueError("component digest must be lowercase SHA-256")
        return cls(
            component_id=_identifier(document["component_id"]),
            source_kind=source_kind,
            source_reference=_source_reference(document["source_reference"]),
            content_sha256=digest,
        )

    def as_document(self) -> dict[str, str]:
        return {
            "component_id": self.component_id,
            "source_kind": self.source_kind,
            "source_reference": self.source_reference,
            "content_sha256": self.content_sha256,
        }


@dataclass(frozen=True, slots=True)
class EffectiveRuntimeProfile:
    schema_version: int
    profile_id: str
    environment: str
    state: str
    components: Mapping[str, RuntimeComponentReference]
    shadow_observers: tuple[RuntimeComponentReference, ...]
    automatic_activation: bool
    selected: bool
    installed: bool
    requires_new_plan_digest: bool
    requires_live_preflight: bool

    @classmethod
    def from_document(cls, document: object) -> EffectiveRuntimeProfile:
        try:
            if not isinstance(document, Mapping):
                raise ValueError("profile must be an object")
            _exact(
                document,
                {
                    "schema_version",
                    "profile_id",
                    "environment",
                    "state",
                    "components",
                    "shadow_observers",
                    "activation",
                },
            )
            if document["schema_version"] != SCHEMA_VERSION:
                raise ValueError("unsupported effective runtime profile schema")
            if document["environment"] != "dev":
                raise ValueError("v1 effective runtime profiles are restricted to dev")
            if document["state"] != INACTIVE_STATE:
                raise ValueError("v1 effective runtime profile must remain inactive")

            raw_components = document["components"]
            if not isinstance(raw_components, Mapping):
                raise ValueError("components must be an object")
            _exact(raw_components, _REQUIRED_COMPONENTS)
            components = {
                name: RuntimeComponentReference.from_document(reference)
                for name, reference in raw_components.items()
            }

            raw_shadows = document["shadow_observers"]
            if not isinstance(raw_shadows, list) or len(raw_shadows) > 16:
                raise ValueError("shadow observers must be a bounded list")
            shadows = tuple(
                RuntimeComponentReference.from_document(reference)
                for reference in raw_shadows
            )
            all_references = [*components.values(), *shadows]
            identities = [reference.component_id for reference in all_references]
            if len(identities) != len(set(identities)):
                raise ValueError("component identifiers must be unique")

            activation = document["activation"]
            if not isinstance(activation, Mapping):
                raise ValueError("activation must be an object")
            _exact(
                activation,
                {
                    "automatic",
                    "selected",
                    "installed",
                    "requires_new_plan_digest",
                    "requires_live_preflight",
                },
            )
            if any(not isinstance(value, bool) for value in activation.values()):
                raise ValueError("activation fields must be boolean")
            if (
                activation["automatic"]
                or activation["selected"]
                or activation["installed"]
                or not activation["requires_new_plan_digest"]
                or not activation["requires_live_preflight"]
            ):
                raise ValueError("repository-only profile cannot grant activation")

            return cls(
                schema_version=SCHEMA_VERSION,
                profile_id=_identifier(document["profile_id"]),
                environment="dev",
                state=INACTIVE_STATE,
                components=MappingProxyType(components),
                shadow_observers=shadows,
                automatic_activation=False,
                selected=False,
                installed=False,
                requires_new_plan_digest=True,
                requires_live_preflight=True,
            )
        except (KeyError, TypeError, ValueError):
            raise _reject() from None

    @classmethod
    def load(cls, path: Path) -> EffectiveRuntimeProfile:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            raise _reject() from None
        return cls.from_document(document)

    def as_document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "profile_id": self.profile_id,
            "environment": self.environment,
            "state": self.state,
            "components": {
                name: reference.as_document()
                for name, reference in sorted(self.components.items())
            },
            "shadow_observers": [
                reference.as_document() for reference in self.shadow_observers
            ],
            "activation": {
                "automatic": self.automatic_activation,
                "selected": self.selected,
                "installed": self.installed,
                "requires_new_plan_digest": self.requires_new_plan_digest,
                "requires_live_preflight": self.requires_live_preflight,
            },
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.as_document(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @property
    def profile_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def component(self, name: str) -> RuntimeComponentReference:
        try:
            return self.components[name]
        except KeyError as exc:
            raise EffectiveRuntimeProfileError("unknown runtime component") from exc
