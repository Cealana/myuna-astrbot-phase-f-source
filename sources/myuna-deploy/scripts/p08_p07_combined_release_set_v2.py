from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import PurePosixPath
import re
from types import MappingProxyType
from typing import Mapping


SCHEMA = "myuna.p08-p07-combined-release-set.v2"
GENERATION = 13
EPOCH_ID = "telegram-owner-private-external-d-reset-v7"
EPOCH_PATH = (
    "/var/lib/myuna-telegram-gateway/external-context-epochs/"
    "telegram-owner-private-external-d-reset-v7/epoch.db"
)
ROLLBACK_ORDER = ("p08", "telegram_plugin", "p07")
_SHA = re.compile(r"^[0-9a-f]{64}$")


class CombinedReleaseSetRejected(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise CombinedReleaseSetRejected(code)


def _canonical(value: Mapping[str, object]) -> bytes:
    return json.dumps(dict(value), ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")


def _digest(value: Mapping[str, object]) -> str:
    return sha256(b"myuna-p08-p07-combined-release-set-v2\0" + _canonical(value)).hexdigest()


def _sha(value: object, code: str) -> str:
    _require(isinstance(value, str) and _SHA.fullmatch(value) is not None, code)
    return value


def _path(value: object, code: str) -> str:
    _require(isinstance(value, str) and value.startswith("/"), code)
    path = PurePosixPath(value)
    _require(value == path.as_posix() and ".." not in path.parts, code)
    return value


def _mapping(value: object, keys: set[str], code: str) -> dict[str, object]:
    _require(isinstance(value, Mapping) and set(value) == keys, code)
    return dict(value)


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class CombinedReleaseSet:
    p07: Mapping[str, object]
    telegram_plugin: Mapping[str, object]
    p08: Mapping[str, object]
    rollback: Mapping[str, object]
    release_set_id: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        _require(self.schema == SCHEMA, "combined_schema_rejected")
        p07 = _mapping(
            self.p07,
            {
                "core_release_digest",
                "credential_projection_digest",
                "epoch_id",
                "epoch_path",
                "generation",
                "release_set_id",
                "runtime_config_digest",
                "runtime_release_digest",
                "selector_digest",
            },
            "combined_p07_rejected",
        )
        _require(p07["generation"] == GENERATION, "combined_p07_rejected")
        _require(p07["epoch_id"] == EPOCH_ID, "combined_p07_rejected")
        _require(p07["epoch_path"] == EPOCH_PATH, "combined_p07_rejected")
        for field in (
            "core_release_digest",
            "credential_projection_digest",
            "release_set_id",
            "runtime_config_digest",
            "runtime_release_digest",
            "selector_digest",
        ):
            _sha(p07[field], "combined_p07_rejected")
        plugin = _mapping(
            self.telegram_plugin,
            {
                "main_sha256",
                "protocol_sha256",
                "release_digest",
                "selected_config_path",
                "selected_config_prestate_digest",
                "selected_config_target_digest",
            },
            "combined_plugin_rejected",
        )
        for field in (
            "main_sha256",
            "protocol_sha256",
            "release_digest",
            "selected_config_prestate_digest",
            "selected_config_target_digest",
        ):
            _sha(plugin[field], "combined_plugin_rejected")
        _path(plugin["selected_config_path"], "combined_plugin_rejected")
        p08 = _mapping(
            self.p08,
            {
                "activation_contract_digest", "release_digest", "selector_path",
                "selector_schema", "service", "socket", "units_digest",
            },
            "combined_p08_rejected",
        )
        _sha(p08["activation_contract_digest"], "combined_p08_rejected")
        _sha(p08["release_digest"], "combined_p08_rejected")
        _sha(p08["units_digest"], "combined_p08_rejected")
        _path(p08["selector_path"], "combined_p08_rejected")
        _require(p08["selector_schema"] == "myuna.p08-active-temporal-selector.v1", "combined_p08_rejected")
        _require(p08["service"] == "myuna-active-temporal-context-v1.service", "combined_p08_rejected")
        _require(p08["socket"] == "myuna-active-temporal-context-v1.socket", "combined_p08_rejected")
        rollback = _mapping(
            self.rollback,
            {
                "combined_prestate_digest",
                "desired_service_states_digest",
                "p08_prestate",
                "previous_core_release_digest",
                "previous_epoch_bundle_digest",
                "previous_epoch_permissions_digest",
                "previous_generation",
                "previous_plugin_config_digest",
                "previous_plugin_release_digest",
                "previous_release_set_digest",
                "previous_release_set_id",
                "previous_runtime_release_digest",
                "previous_selector_digest",
                "reverse_order",
            },
            "combined_rollback_rejected",
        )
        _require(rollback["previous_generation"] == 11, "combined_rollback_rejected")
        _require(rollback["p08_prestate"] == "absent", "combined_rollback_rejected")
        _require(
            isinstance(rollback["reverse_order"], (list, tuple))
            and tuple(rollback["reverse_order"]) == ROLLBACK_ORDER,
            "combined_rollback_rejected",
        )
        for field in (
            "combined_prestate_digest",
            "desired_service_states_digest",
            "previous_core_release_digest",
            "previous_epoch_bundle_digest",
            "previous_epoch_permissions_digest",
            "previous_plugin_config_digest",
            "previous_plugin_release_digest",
            "previous_release_set_digest",
            "previous_release_set_id",
            "previous_runtime_release_digest",
            "previous_selector_digest",
        ):
            _sha(rollback[field], "combined_rollback_rejected")
        _sha(self.release_set_id, "combined_release_set_id_rejected")
        _require(self.release_set_id == _digest(self.digest_payload()), "combined_release_set_digest_mismatch")
        object.__setattr__(self, "p07", _freeze(p07))
        object.__setattr__(self, "telegram_plugin", _freeze(plugin))
        object.__setattr__(self, "p08", _freeze(p08))
        object.__setattr__(self, "rollback", _freeze(rollback))

    def digest_payload(self) -> dict[str, object]:
        rollback = dict(self.rollback)
        rollback["reverse_order"] = list(self.rollback["reverse_order"])
        return {
            "p07": dict(self.p07),
            "p08": dict(self.p08),
            "rollback": rollback,
            "schema": self.schema,
            "telegram_plugin": dict(self.telegram_plugin),
        }

    def as_payload(self) -> dict[str, object]:
        return {**self.digest_payload(), "release_set_id": self.release_set_id}

    @classmethod
    def create(
        cls,
        *,
        p07: Mapping[str, object],
        telegram_plugin: Mapping[str, object],
        p08: Mapping[str, object],
        rollback: Mapping[str, object],
    ) -> "CombinedReleaseSet":
        payload = {
            "p07": dict(p07),
            "p08": dict(p08),
            "rollback": dict(rollback),
            "schema": SCHEMA,
            "telegram_plugin": dict(telegram_plugin),
        }
        return cls(
            p07=payload["p07"],
            telegram_plugin=payload["telegram_plugin"],
            p08=payload["p08"],
            rollback=payload["rollback"],
            release_set_id=_digest(payload),
        )

    @classmethod
    def from_payload(cls, value: object) -> "CombinedReleaseSet":
        required = {"p07", "p08", "release_set_id", "rollback", "schema", "telegram_plugin"}
        _require(isinstance(value, Mapping) and set(value) == required, "combined_fields_rejected")
        return cls(
            p07=value["p07"],  # type: ignore[arg-type]
            telegram_plugin=value["telegram_plugin"],  # type: ignore[arg-type]
            p08=value["p08"],  # type: ignore[arg-type]
            rollback=value["rollback"],  # type: ignore[arg-type]
            release_set_id=value["release_set_id"],  # type: ignore[arg-type]
            schema=value["schema"],  # type: ignore[arg-type]
        )
