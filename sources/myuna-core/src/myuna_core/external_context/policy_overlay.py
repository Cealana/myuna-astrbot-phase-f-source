"""Versioned, fail-closed P07 projection-policy overlay contract.

The persisted schema-v3 epoch remains bound to its immutable parent release
set. This module only permits a separately selected projection policy when the
manifest, selector, marker, and transition state form one exact protected
snapshot. Absence is the parent compressed policy; partial state is an error.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Mapping

from .contracts import (
    EXTERNAL_PROJECTION_POLICY,
    EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY,
    MAX_RECENT_CHARACTERS,
    MAX_RECENT_TURNS,
    MAX_VERBATIM_RECENT_CHARACTERS,
    MAX_VERBATIM_RECENT_TURNS,
)
from .release_set import P07DReleaseSet


POLICY_OVERLAY_SCHEMA = "myuna.p07-policy-overlay.v1"
POLICY_OVERLAY_SELECTOR_SCHEMA = "myuna.p07-policy-overlay-selector.v1"
POLICY_OVERLAY_MARKER_SCHEMA = "myuna.p07-policy-overlay-marker.v1"
POLICY_OVERLAY_STATE_SCHEMA = "myuna.p07-policy-overlay-state.v1"
POLICY_OVERLAY_MANIFEST_PATH = Path(
    "/etc/myuna-telegram-gateway/p07-policy-overlay-v1.json"
)
POLICY_OVERLAY_SELECTOR_PATH = Path(
    "/etc/myuna-telegram-gateway/p07-policy-overlay-selector-v1.json"
)
POLICY_OVERLAY_MARKER_PATH = Path(
    "/etc/myuna-telegram-gateway/p07-policy-overlay-marker-v1.json"
)
POLICY_OVERLAY_STATE_PATH = Path(
    "/etc/myuna-telegram-gateway/p07-policy-overlay-state-v1.json"
)
POLICY_OVERLAY_MAX_BYTES = 64 * 1024
POLICY_OVERLAY_MAX_INPUT_CHARACTERS = 200_000
POLICY_OVERLAY_MAX_PROJECTION_CHARACTERS = 199_000
POLICY_OVERLAY_MAX_SERIALIZED_BYTES = 1_198_096
POLICY_OVERLAY_MAX_INPUT_TOKENS = 999_232
ZERO_DIGEST = "0" * 64

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class PolicyOverlayRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise PolicyOverlayRejected(code)


def _canonical(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def canonical_document(payload: Mapping[str, object]) -> bytes:
    return _canonical(payload) + b"\n"


def _digest(domain: bytes, payload: Mapping[str, object]) -> str:
    return sha256(domain + b"\0" + _canonical(payload)).hexdigest()


def _sha(value: object, code: str) -> str:
    _require(isinstance(value, str) and _SHA256.fullmatch(value) is not None, code)
    return value


def _safe_id(value: object, code: str) -> str:
    _require(isinstance(value, str) and _SAFE_ID.fullmatch(value) is not None, code)
    return value


def _exact_mapping(
    value: object,
    keys: set[str],
    code: str,
) -> Mapping[str, object]:
    _require(isinstance(value, Mapping) and set(value) == keys, code)
    return value


def _frozen(value: object, code: str) -> Mapping[str, object]:
    _require(isinstance(value, Mapping), code)
    return MappingProxyType(dict(value))


def projection_policy_contract() -> dict[str, object]:
    payload = {
        "compressed_fallback_max_characters": MAX_RECENT_CHARACTERS,
        "compressed_fallback_max_turns": MAX_RECENT_TURNS,
        "compressed_fallback_policy": EXTERNAL_PROJECTION_POLICY,
        "max_complete_turns": MAX_VERBATIM_RECENT_TURNS,
        "max_input_characters": POLICY_OVERLAY_MAX_INPUT_CHARACTERS,
        "max_input_tokens": POLICY_OVERLAY_MAX_INPUT_TOKENS,
        "max_projection_characters": POLICY_OVERLAY_MAX_PROJECTION_CHARACTERS,
        "max_recent_characters": MAX_VERBATIM_RECENT_CHARACTERS,
        "max_serialized_bytes": POLICY_OVERLAY_MAX_SERIALIZED_BYTES,
        "overflow_behavior": "bounded-compressed-fallback-or-fail-closed",
        "policy_version": EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY,
    }
    return {
        **payload,
        "policy_digest": _digest(b"myuna-p07-policy-overlay-policy-v1", payload),
    }


@dataclass(frozen=True, slots=True)
class PolicyOverlay:
    parent: Mapping[str, object]
    components: Mapping[str, object]
    runtime_config: Mapping[str, object]
    credential: Mapping[str, object]
    policy: Mapping[str, object]
    rollback: Mapping[str, object]
    provenance: Mapping[str, object]
    overlay_id: str
    schema: str = POLICY_OVERLAY_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "parent", _frozen(self.parent, "policy_overlay_parent_rejected")
        )
        object.__setattr__(
            self,
            "components",
            _frozen(self.components, "policy_overlay_components_rejected"),
        )
        object.__setattr__(
            self,
            "runtime_config",
            _frozen(self.runtime_config, "policy_overlay_runtime_config_rejected"),
        )
        object.__setattr__(
            self,
            "credential",
            _frozen(self.credential, "policy_overlay_credential_rejected"),
        )
        object.__setattr__(
            self, "policy", _frozen(self.policy, "policy_overlay_policy_rejected")
        )
        object.__setattr__(
            self,
            "rollback",
            _frozen(self.rollback, "policy_overlay_rollback_rejected"),
        )
        object.__setattr__(
            self,
            "provenance",
            _frozen(self.provenance, "policy_overlay_provenance_rejected"),
        )
        _require(self.schema == POLICY_OVERLAY_SCHEMA, "policy_overlay_schema_unknown")
        _sha(self.overlay_id, "policy_overlay_id_rejected")

        parent = _exact_mapping(
            self.parent,
            {
                "epoch_id",
                "epoch_identity_digest",
                "epoch_path",
                "manifest_file_digest",
                "release_set_id",
                "selector_digest",
            },
            "policy_overlay_parent_rejected",
        )
        for field in (
            "epoch_identity_digest",
            "manifest_file_digest",
            "release_set_id",
            "selector_digest",
        ):
            _sha(parent[field], "policy_overlay_parent_rejected")
        _safe_id(parent["epoch_id"], "policy_overlay_parent_rejected")
        _require(
            isinstance(parent["epoch_path"], str)
            and parent["epoch_path"].startswith("/")
            and ".." not in Path(parent["epoch_path"]).parts,
            "policy_overlay_parent_rejected",
        )

        components = _exact_mapping(
            self.components,
            {
                "core_release_digest",
                "plugin_config_digest",
                "plugin_release_digest",
                "runtime_release_digest",
            },
            "policy_overlay_components_rejected",
        )
        for value in components.values():
            _sha(value, "policy_overlay_components_rejected")

        runtime_config = _exact_mapping(
            self.runtime_config,
            {"binding_digest", "content_digest"},
            "policy_overlay_runtime_config_rejected",
        )
        for value in runtime_config.values():
            _sha(value, "policy_overlay_runtime_config_rejected")

        credential = _exact_mapping(
            self.credential,
            {"dropin_set_digest", "effective_count", "projection_digest"},
            "policy_overlay_credential_rejected",
        )
        _require(
            credential["effective_count"] == 1,
            "policy_overlay_credential_rejected",
        )
        _sha(
            credential["dropin_set_digest"],
            "policy_overlay_credential_rejected",
        )
        _sha(
            credential["projection_digest"],
            "policy_overlay_credential_rejected",
        )

        _require(
            dict(self.policy) == projection_policy_contract(),
            "policy_overlay_policy_rejected",
        )

        rollback = _exact_mapping(
            self.rollback,
            {
                "active_files_absent_selects_parent",
                "parent_policy_version",
                "persistent_epoch_rewritten",
                "rollback_mode",
            },
            "policy_overlay_rollback_rejected",
        )
        _require(
            rollback
            == {
                "active_files_absent_selects_parent": True,
                "parent_policy_version": EXTERNAL_PROJECTION_POLICY,
                "persistent_epoch_rewritten": False,
                "rollback_mode": "remove-active-overlay-preserve-terminal-state",
            },
            "policy_overlay_rollback_rejected",
        )

        provenance = _exact_mapping(
            self.provenance,
            {"content_free", "core_commit", "deploy_commit", "schema"},
            "policy_overlay_provenance_rejected",
        )
        _require(
            provenance["content_free"] is True
            and provenance["schema"]
            == "myuna.p07-policy-overlay-provenance.v1",
            "policy_overlay_provenance_rejected",
        )
        for field in ("core_commit", "deploy_commit"):
            _require(
                isinstance(provenance[field], str)
                and re.fullmatch(r"[0-9a-f]{40}", provenance[field]) is not None,
                "policy_overlay_provenance_rejected",
            )
        _require(
            self.overlay_id
            == _digest(b"myuna-p07-policy-overlay-v1", self.digest_payload()),
            "policy_overlay_digest_mismatch",
        )

    def digest_payload(self) -> dict[str, object]:
        return {
            "components": dict(self.components),
            "credential": dict(self.credential),
            "parent": dict(self.parent),
            "policy": dict(self.policy),
            "provenance": dict(self.provenance),
            "rollback": dict(self.rollback),
            "runtime_config": dict(self.runtime_config),
            "schema": self.schema,
        }

    def as_payload(self) -> dict[str, object]:
        return {**self.digest_payload(), "overlay_id": self.overlay_id}

    @classmethod
    def create(
        cls,
        *,
        parent_release_set: P07DReleaseSet,
        parent_manifest_file_digest: str,
        core_release_digest: str,
        runtime_release_digest: str,
        plugin_release_digest: str,
        plugin_config_digest: str,
        core_commit: str,
        deploy_commit: str,
    ) -> "PolicyOverlay":
        _require(
            parent_release_set.projection_policy_version
            == EXTERNAL_PROJECTION_POLICY,
            "policy_overlay_parent_policy_rejected",
        )
        payload = {
            "components": {
                "core_release_digest": core_release_digest,
                "plugin_config_digest": plugin_config_digest,
                "plugin_release_digest": plugin_release_digest,
                "runtime_release_digest": runtime_release_digest,
            },
            "credential": {
                "dropin_set_digest": parent_release_set.credential[
                    "dropin_set_digest"
                ],
                "effective_count": parent_release_set.credential[
                    "effective_count"
                ],
                "projection_digest": parent_release_set.credential[
                    "projection_digest"
                ],
            },
            "parent": {
                "epoch_id": parent_release_set.epoch["epoch_id"],
                "epoch_identity_digest": parent_release_set.epoch_identity_digest,
                "epoch_path": parent_release_set.epoch["database_path"],
                "manifest_file_digest": parent_manifest_file_digest,
                "release_set_id": parent_release_set.release_set_id,
                "selector_digest": parent_release_set.selector["digest"],
            },
            "policy": projection_policy_contract(),
            "provenance": {
                "content_free": True,
                "core_commit": core_commit,
                "deploy_commit": deploy_commit,
                "schema": "myuna.p07-policy-overlay-provenance.v1",
            },
            "rollback": {
                "active_files_absent_selects_parent": True,
                "parent_policy_version": EXTERNAL_PROJECTION_POLICY,
                "persistent_epoch_rewritten": False,
                "rollback_mode": "remove-active-overlay-preserve-terminal-state",
            },
            "runtime_config": {
                "binding_digest": parent_release_set.runtime_config[
                    "binding_digest"
                ],
                "content_digest": parent_release_set.runtime_config["digest"],
            },
            "schema": POLICY_OVERLAY_SCHEMA,
        }
        return cls(
            parent=payload["parent"],
            components=payload["components"],
            runtime_config=payload["runtime_config"],
            credential=payload["credential"],
            policy=payload["policy"],
            rollback=payload["rollback"],
            provenance=payload["provenance"],
            overlay_id=_digest(b"myuna-p07-policy-overlay-v1", payload),
        )

    @classmethod
    def from_payload(cls, payload: object) -> "PolicyOverlay":
        required = {
            "components",
            "credential",
            "overlay_id",
            "parent",
            "policy",
            "provenance",
            "rollback",
            "runtime_config",
            "schema",
        }
        _require(
            isinstance(payload, Mapping) and set(payload) == required,
            "policy_overlay_fields_rejected",
        )
        return cls(
            parent=payload["parent"],  # type: ignore[arg-type]
            components=payload["components"],  # type: ignore[arg-type]
            runtime_config=payload["runtime_config"],  # type: ignore[arg-type]
            credential=payload["credential"],  # type: ignore[arg-type]
            policy=payload["policy"],  # type: ignore[arg-type]
            rollback=payload["rollback"],  # type: ignore[arg-type]
            provenance=payload["provenance"],  # type: ignore[arg-type]
            overlay_id=payload["overlay_id"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class PolicyOverlayState:
    sequence: int
    status: str
    overlay_id: str | None
    previous_state_digest: str
    state_digest: str
    schema: str = POLICY_OVERLAY_STATE_SCHEMA

    def __post_init__(self) -> None:
        _require(
            self.schema == POLICY_OVERLAY_STATE_SCHEMA,
            "policy_overlay_state_schema_unknown",
        )
        _require(
            type(self.sequence) is int and self.sequence >= 1,
            "policy_overlay_state_sequence_rejected",
        )
        _require(
            self.status in {"active", "compressed"},
            "policy_overlay_state_status_rejected",
        )
        _sha(
            self.previous_state_digest,
            "policy_overlay_state_previous_rejected",
        )
        _sha(self.state_digest, "policy_overlay_state_digest_rejected")
        if self.status == "active":
            _sha(self.overlay_id, "policy_overlay_state_overlay_rejected")
        else:
            _require(
                self.overlay_id is None,
                "policy_overlay_state_overlay_rejected",
            )
        _require(
            self.state_digest
            == _digest(
                b"myuna-p07-policy-overlay-state-v1", self.digest_payload()
            ),
            "policy_overlay_state_digest_mismatch",
        )

    def digest_payload(self) -> dict[str, object]:
        return {
            "overlay_id": self.overlay_id,
            "previous_state_digest": self.previous_state_digest,
            "schema": self.schema,
            "sequence": self.sequence,
            "status": self.status,
        }

    def as_payload(self) -> dict[str, object]:
        return {**self.digest_payload(), "state_digest": self.state_digest}

    @classmethod
    def create(
        cls,
        *,
        sequence: int,
        status: str,
        overlay_id: str | None,
        previous_state_digest: str,
    ) -> "PolicyOverlayState":
        payload = {
            "overlay_id": overlay_id,
            "previous_state_digest": previous_state_digest,
            "schema": POLICY_OVERLAY_STATE_SCHEMA,
            "sequence": sequence,
            "status": status,
        }
        return cls(
            sequence=sequence,
            status=status,
            overlay_id=overlay_id,
            previous_state_digest=previous_state_digest,
            state_digest=_digest(
                b"myuna-p07-policy-overlay-state-v1", payload
            ),
        )

    @classmethod
    def from_payload(cls, payload: object) -> "PolicyOverlayState":
        required = {
            "overlay_id",
            "previous_state_digest",
            "schema",
            "sequence",
            "state_digest",
            "status",
        }
        _require(
            isinstance(payload, Mapping) and set(payload) == required,
            "policy_overlay_state_fields_rejected",
        )
        return cls(
            sequence=payload["sequence"],  # type: ignore[arg-type]
            status=payload["status"],  # type: ignore[arg-type]
            overlay_id=payload["overlay_id"],  # type: ignore[arg-type]
            previous_state_digest=payload["previous_state_digest"],  # type: ignore[arg-type]
            state_digest=payload["state_digest"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )


def require_policy_overlay_transition(
    previous: PolicyOverlayState | None,
    current: PolicyOverlayState,
) -> None:
    if previous is None:
        _require(
            current.sequence == 1
            and current.status == "active"
            and current.previous_state_digest == ZERO_DIGEST,
            "policy_overlay_transition_rejected",
        )
        return
    _require(
        current.sequence == previous.sequence + 1
        and current.previous_state_digest == previous.state_digest,
        "policy_overlay_transition_rejected",
    )
    if previous.status == "active":
        _require(
            current.status == "compressed",
            "policy_overlay_transition_rejected",
        )
    else:
        _require(
            current.status == "active"
            and current.overlay_id is not None,
            "policy_overlay_transition_rejected",
        )


@dataclass(frozen=True, slots=True)
class PolicyOverlaySelector:
    overlay_id: str
    manifest_file_digest: str
    state_digest: str
    sequence: int
    selector_id: str
    schema: str = POLICY_OVERLAY_SELECTOR_SCHEMA

    def __post_init__(self) -> None:
        _require(
            self.schema == POLICY_OVERLAY_SELECTOR_SCHEMA,
            "policy_overlay_selector_schema_unknown",
        )
        for value in (
            self.overlay_id,
            self.manifest_file_digest,
            self.state_digest,
            self.selector_id,
        ):
            _sha(value, "policy_overlay_selector_rejected")
        _require(
            type(self.sequence) is int and self.sequence >= 1,
            "policy_overlay_selector_rejected",
        )
        _require(
            self.selector_id
            == _digest(
                b"myuna-p07-policy-overlay-selector-v1", self.digest_payload()
            ),
            "policy_overlay_selector_digest_mismatch",
        )

    def digest_payload(self) -> dict[str, object]:
        return {
            "manifest_file_digest": self.manifest_file_digest,
            "overlay_id": self.overlay_id,
            "schema": self.schema,
            "sequence": self.sequence,
            "state_digest": self.state_digest,
        }

    def as_payload(self) -> dict[str, object]:
        return {**self.digest_payload(), "selector_id": self.selector_id}

    @classmethod
    def create(
        cls, overlay: PolicyOverlay, state: PolicyOverlayState
    ) -> "PolicyOverlaySelector":
        _require(
            state.status == "active" and state.overlay_id == overlay.overlay_id,
            "policy_overlay_selector_state_rejected",
        )
        manifest_digest = sha256(
            canonical_document(overlay.as_payload())
        ).hexdigest()
        payload = {
            "manifest_file_digest": manifest_digest,
            "overlay_id": overlay.overlay_id,
            "schema": POLICY_OVERLAY_SELECTOR_SCHEMA,
            "sequence": state.sequence,
            "state_digest": state.state_digest,
        }
        return cls(
            overlay_id=overlay.overlay_id,
            manifest_file_digest=manifest_digest,
            state_digest=state.state_digest,
            sequence=state.sequence,
            selector_id=_digest(
                b"myuna-p07-policy-overlay-selector-v1", payload
            ),
        )

    @classmethod
    def from_payload(cls, payload: object) -> "PolicyOverlaySelector":
        required = {
            "manifest_file_digest",
            "overlay_id",
            "schema",
            "selector_id",
            "sequence",
            "state_digest",
        }
        _require(
            isinstance(payload, Mapping) and set(payload) == required,
            "policy_overlay_selector_fields_rejected",
        )
        return cls(
            overlay_id=payload["overlay_id"],  # type: ignore[arg-type]
            manifest_file_digest=payload["manifest_file_digest"],  # type: ignore[arg-type]
            state_digest=payload["state_digest"],  # type: ignore[arg-type]
            sequence=payload["sequence"],  # type: ignore[arg-type]
            selector_id=payload["selector_id"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class PolicyOverlayMarker:
    overlay_id: str
    selector_id: str
    selector_file_digest: str
    state_digest: str
    state_file_digest: str
    sequence: int
    marker_id: str
    schema: str = POLICY_OVERLAY_MARKER_SCHEMA

    def __post_init__(self) -> None:
        _require(
            self.schema == POLICY_OVERLAY_MARKER_SCHEMA,
            "policy_overlay_marker_schema_unknown",
        )
        for value in (
            self.overlay_id,
            self.selector_id,
            self.selector_file_digest,
            self.state_digest,
            self.state_file_digest,
            self.marker_id,
        ):
            _sha(value, "policy_overlay_marker_rejected")
        _require(
            type(self.sequence) is int and self.sequence >= 1,
            "policy_overlay_marker_rejected",
        )
        _require(
            self.marker_id
            == _digest(
                b"myuna-p07-policy-overlay-marker-v1", self.digest_payload()
            ),
            "policy_overlay_marker_digest_mismatch",
        )

    def digest_payload(self) -> dict[str, object]:
        return {
            "overlay_id": self.overlay_id,
            "schema": self.schema,
            "selector_file_digest": self.selector_file_digest,
            "selector_id": self.selector_id,
            "sequence": self.sequence,
            "state_digest": self.state_digest,
            "state_file_digest": self.state_file_digest,
        }

    def as_payload(self) -> dict[str, object]:
        return {**self.digest_payload(), "marker_id": self.marker_id}

    @classmethod
    def create(
        cls,
        selector: PolicyOverlaySelector,
        state: PolicyOverlayState,
    ) -> "PolicyOverlayMarker":
        _require(
            selector.overlay_id == state.overlay_id
            and selector.state_digest == state.state_digest
            and selector.sequence == state.sequence,
            "policy_overlay_marker_state_rejected",
        )
        payload = {
            "overlay_id": selector.overlay_id,
            "schema": POLICY_OVERLAY_MARKER_SCHEMA,
            "selector_file_digest": sha256(
                canonical_document(selector.as_payload())
            ).hexdigest(),
            "selector_id": selector.selector_id,
            "sequence": state.sequence,
            "state_digest": state.state_digest,
            "state_file_digest": sha256(
                canonical_document(state.as_payload())
            ).hexdigest(),
        }
        return cls(
            overlay_id=selector.overlay_id,
            selector_id=selector.selector_id,
            selector_file_digest=payload[
                "selector_file_digest"
            ],  # type: ignore[arg-type]
            state_digest=state.state_digest,
            state_file_digest=payload[
                "state_file_digest"
            ],  # type: ignore[arg-type]
            sequence=state.sequence,
            marker_id=_digest(
                b"myuna-p07-policy-overlay-marker-v1", payload
            ),
        )

    @classmethod
    def from_payload(cls, payload: object) -> "PolicyOverlayMarker":
        required = {
            "marker_id",
            "overlay_id",
            "schema",
            "selector_file_digest",
            "selector_id",
            "sequence",
            "state_digest",
            "state_file_digest",
        }
        _require(
            isinstance(payload, Mapping) and set(payload) == required,
            "policy_overlay_marker_fields_rejected",
        )
        return cls(
            overlay_id=payload["overlay_id"],  # type: ignore[arg-type]
            selector_id=payload["selector_id"],  # type: ignore[arg-type]
            selector_file_digest=payload["selector_file_digest"],  # type: ignore[arg-type]
            state_digest=payload["state_digest"],  # type: ignore[arg-type]
            state_file_digest=payload["state_file_digest"],  # type: ignore[arg-type]
            sequence=payload["sequence"],  # type: ignore[arg-type]
            marker_id=payload["marker_id"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class _ProtectedDocument:
    payload: object
    file_digest: str


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        _require(key not in result, "policy_overlay_duplicate_field")
        result[key] = value
    return result


def _load_document(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int,
) -> _ProtectedDocument:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == expected_uid
            and before.st_gid == expected_gid
            and stat.S_IMODE(before.st_mode) == expected_mode
            and 1 <= before.st_size <= POLICY_OVERLAY_MAX_BYTES,
            "policy_overlay_file_metadata_rejected",
        )
        raw = os.read(descriptor, POLICY_OVERLAY_MAX_BYTES + 1)
        after = os.fstat(descriptor)
        path_state = path.lstat()
        stable = (
            "st_dev",
            "st_ino",
            "st_uid",
            "st_gid",
            "st_mode",
            "st_size",
            "st_mtime_ns",
        )
        _require(
            len(raw) == before.st_size
            and not stat.S_ISLNK(path_state.st_mode)
            and all(
                getattr(before, name)
                == getattr(after, name)
                == getattr(path_state, name)
                for name in stable
            ),
            "policy_overlay_file_snapshot_drifted",
        )
        payload = json.loads(
            raw.decode("ascii"), object_pairs_hook=_strict_object
        )
        return _ProtectedDocument(
            payload=payload, file_digest=sha256(raw).hexdigest()
        )
    except PolicyOverlayRejected:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
        raise PolicyOverlayRejected("policy_overlay_file_rejected") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise PolicyOverlayRejected("policy_overlay_file_rejected") from None
    return True


def load_selected_policy_overlay(
    *,
    parent_release_set: P07DReleaseSet,
    parent_manifest_file_digest: str | None,
    component_kind: str,
    current_component_release_digest: str | None,
    expected_uid: int = 0,
    expected_gid: int = 0,
    expected_mode: int = 0o640,
    manifest_path: Path = POLICY_OVERLAY_MANIFEST_PATH,
    selector_path: Path = POLICY_OVERLAY_SELECTOR_PATH,
    marker_path: Path = POLICY_OVERLAY_MARKER_PATH,
    state_path: Path = POLICY_OVERLAY_STATE_PATH,
) -> PolicyOverlay | None:
    """Resolve one protected overlay snapshot; never interpret partial state."""

    _require(
        component_kind in {"core", "runtime"},
        "policy_overlay_component_kind_rejected",
    )
    active_paths = (manifest_path, selector_path, marker_path)
    active_presence = tuple(_exists(path) for path in active_paths)
    state_present = _exists(state_path)
    if not any(active_presence) and not state_present:
        return None
    if not any(active_presence) and state_present:
        state_doc = _load_document(
            state_path,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            expected_mode=expected_mode,
        )
        state = PolicyOverlayState.from_payload(state_doc.payload)
        _require(
            state.status == "compressed", "policy_overlay_partial_state_rejected"
        )
        return None
    _require(
        all(active_presence) and state_present,
        "policy_overlay_partial_state_rejected",
    )
    _require(
        isinstance(parent_manifest_file_digest, str),
        "policy_overlay_parent_rejected",
    )

    manifest_doc = _load_document(
        manifest_path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        expected_mode=expected_mode,
    )
    selector_doc = _load_document(
        selector_path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        expected_mode=expected_mode,
    )
    marker_doc = _load_document(
        marker_path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        expected_mode=expected_mode,
    )
    state_doc = _load_document(
        state_path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        expected_mode=expected_mode,
    )
    overlay = PolicyOverlay.from_payload(manifest_doc.payload)
    selector = PolicyOverlaySelector.from_payload(selector_doc.payload)
    marker = PolicyOverlayMarker.from_payload(marker_doc.payload)
    state = PolicyOverlayState.from_payload(state_doc.payload)
    _require(state.status == "active", "policy_overlay_state_not_active")
    _require(
        overlay.overlay_id
        == selector.overlay_id
        == marker.overlay_id
        == state.overlay_id
        and selector.manifest_file_digest == manifest_doc.file_digest
        and marker.selector_id == selector.selector_id
        and marker.selector_file_digest == selector_doc.file_digest
        and marker.state_digest == selector.state_digest == state.state_digest
        and marker.state_file_digest == state_doc.file_digest
        and marker.sequence == selector.sequence == state.sequence,
        "policy_overlay_snapshot_mismatch",
    )
    parent = overlay.parent
    _require(
        parent_release_set.projection_policy_version
        == EXTERNAL_PROJECTION_POLICY
        and parent["release_set_id"] == parent_release_set.release_set_id
        and parent["manifest_file_digest"]
        == _sha(parent_manifest_file_digest, "policy_overlay_parent_rejected")
        and parent["selector_digest"]
        == parent_release_set.selector["digest"]
        and parent["epoch_id"] == parent_release_set.epoch["epoch_id"]
        and parent["epoch_path"]
        == parent_release_set.epoch["database_path"]
        and parent["epoch_identity_digest"]
        == parent_release_set.epoch_identity_digest
        and overlay.runtime_config["content_digest"]
        == parent_release_set.runtime_config["digest"]
        and overlay.runtime_config["binding_digest"]
        == parent_release_set.runtime_config["binding_digest"]
        and overlay.credential["projection_digest"]
        == parent_release_set.credential["projection_digest"]
        and overlay.credential["dropin_set_digest"]
        == parent_release_set.credential["dropin_set_digest"]
        and overlay.credential["effective_count"]
        == parent_release_set.credential["effective_count"],
        "policy_overlay_parent_mismatch",
    )
    _sha(
        current_component_release_digest,
        "policy_overlay_component_identity_rejected",
    )
    field = (
        "core_release_digest"
        if component_kind == "core"
        else "runtime_release_digest"
    )
    _require(
        overlay.components[field] == current_component_release_digest,
        "policy_overlay_component_identity_mismatch",
    )
    return overlay


def release_digest_from_path(path: Path, *, component: str) -> str | None:
    """Return an immutable release-directory digest, or None outside a release."""

    _require(
        component in {"core", "runtime"},
        "policy_overlay_component_kind_rejected",
    )
    marker = "core" if component == "core" else "telegram-owner-runtime"
    parts = path.resolve().parts
    for index, value in enumerate(parts[:-1]):
        if value == marker and index + 1 < len(parts):
            candidate = parts[index + 1]
            if _SHA256.fullmatch(candidate) is not None:
                return candidate
    return None


def require_overlay_component_set(
    overlay: PolicyOverlay,
    *,
    core_release_digest: str,
    runtime_release_digest: str,
    plugin_release_digest: str,
    plugin_config_digest: str,
) -> None:
    """Require the complete composite artifact set during build or T2 gates."""

    expected = {
        "core_release_digest": _sha(
            core_release_digest, "policy_overlay_components_rejected"
        ),
        "plugin_config_digest": _sha(
            plugin_config_digest, "policy_overlay_components_rejected"
        ),
        "plugin_release_digest": _sha(
            plugin_release_digest, "policy_overlay_components_rejected"
        ),
        "runtime_release_digest": _sha(
            runtime_release_digest, "policy_overlay_components_rejected"
        ),
    }
    _require(
        dict(overlay.components) == expected,
        "policy_overlay_component_set_mismatch",
    )
