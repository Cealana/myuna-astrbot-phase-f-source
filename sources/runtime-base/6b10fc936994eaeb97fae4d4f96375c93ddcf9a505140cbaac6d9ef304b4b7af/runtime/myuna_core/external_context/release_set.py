from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import PurePosixPath
import re
from types import MappingProxyType
from typing import Mapping


RELEASE_SET_SCHEMA = "myuna.p07-d-release-set.v1"
RELEASE_SET_EPOCH_SCHEMA = "myuna.external-authorized-epoch.v3"
RELEASE_SET_EPOCH_VERSION = 3
RELEASE_SET_GENERATION_7 = 7
RELEASE_SET_EPOCH_ID_7 = "telegram-owner-private-external-d-reset-v1"
RELEASE_SET_EPOCH_PATH_7 = (
    "/var/lib/myuna-telegram-gateway/external-context-epochs/"
    "telegram-owner-private-external-d-reset-v1/epoch.db"
)
RELEASE_SET_GENERATION_8 = 8
RELEASE_SET_EPOCH_ID_8 = "telegram-owner-private-external-d-reset-v2"
RELEASE_SET_EPOCH_PATH_8 = (
    "/var/lib/myuna-telegram-gateway/external-context-epochs/"
    "telegram-owner-private-external-d-reset-v2/epoch.db"
)
RELEASE_SET_GENERATION_9 = 9
RELEASE_SET_EPOCH_ID_9 = "telegram-owner-private-external-d-reset-v3"
RELEASE_SET_EPOCH_PATH_9 = (
    "/var/lib/myuna-telegram-gateway/external-context-epochs/"
    "telegram-owner-private-external-d-reset-v3/epoch.db"
)
RELEASE_SET_GENERATION_10 = 10
RELEASE_SET_EPOCH_ID_10 = "telegram-owner-private-external-d-reset-v4"
RELEASE_SET_EPOCH_PATH_10 = (
    "/var/lib/myuna-telegram-gateway/external-context-epochs/"
    "telegram-owner-private-external-d-reset-v4/epoch.db"
)
RELEASE_SET_GENERATION_11 = 11
RELEASE_SET_EPOCH_ID_11 = "telegram-owner-private-external-d-reset-v5"
RELEASE_SET_EPOCH_PATH_11 = (
    "/var/lib/myuna-telegram-gateway/external-context-epochs/"
    "telegram-owner-private-external-d-reset-v5/epoch.db"
)
RELEASE_SET_GENERATION_12 = 12
RELEASE_SET_EPOCH_ID_12 = "telegram-owner-private-external-d-reset-v6"
RELEASE_SET_EPOCH_PATH_12 = (
    "/var/lib/myuna-telegram-gateway/external-context-epochs/"
    "telegram-owner-private-external-d-reset-v6/epoch.db"
)
RELEASE_SET_GENERATION_13 = 13
RELEASE_SET_EPOCH_ID_13 = "telegram-owner-private-external-d-reset-v7"
RELEASE_SET_EPOCH_PATH_13 = (
    "/var/lib/myuna-telegram-gateway/external-context-epochs/"
    "telegram-owner-private-external-d-reset-v7/epoch.db"
)
RELEASE_SET_GENERATION = RELEASE_SET_GENERATION_13
RELEASE_SET_EPOCH_ID = RELEASE_SET_EPOCH_ID_13
RELEASE_SET_EPOCH_PATH = RELEASE_SET_EPOCH_PATH_13
_RELEASE_SET_EPOCH_IDENTITIES = MappingProxyType(
    {
        RELEASE_SET_GENERATION_7: (RELEASE_SET_EPOCH_ID_7, RELEASE_SET_EPOCH_PATH_7),
        RELEASE_SET_GENERATION_8: (RELEASE_SET_EPOCH_ID_8, RELEASE_SET_EPOCH_PATH_8),
        RELEASE_SET_GENERATION_9: (RELEASE_SET_EPOCH_ID_9, RELEASE_SET_EPOCH_PATH_9),
        RELEASE_SET_GENERATION_10: (RELEASE_SET_EPOCH_ID_10, RELEASE_SET_EPOCH_PATH_10),
        RELEASE_SET_GENERATION_11: (RELEASE_SET_EPOCH_ID_11, RELEASE_SET_EPOCH_PATH_11),
        RELEASE_SET_GENERATION_12: (RELEASE_SET_EPOCH_ID_12, RELEASE_SET_EPOCH_PATH_12),
        RELEASE_SET_GENERATION_13: (RELEASE_SET_EPOCH_ID_13, RELEASE_SET_EPOCH_PATH_13),
    }
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_UNIT = re.compile(r"^[A-Za-z0-9_.@-]+\.(?:service|socket)$")


class ReleaseSetRejected(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ReleaseSetRejected(code)


def _canonical(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _digest(payload: Mapping[str, object]) -> str:
    return sha256(b"myuna-p07-d-release-set-v1\0" + _canonical(payload)).hexdigest()


def _sha(value: object, code: str) -> str:
    _require(isinstance(value, str) and _SHA256.fullmatch(value) is not None, code)
    return value


def _safe_id(value: object, code: str) -> str:
    _require(isinstance(value, str) and _SAFE_ID.fullmatch(value) is not None, code)
    return value


def _absolute_file(value: object, code: str) -> str:
    _require(isinstance(value, str) and value.startswith("/"), code)
    path = PurePosixPath(value)
    _require(".." not in path.parts and value == path.as_posix(), code)
    return value


def _exact_mapping(value: object, keys: set[str], code: str) -> Mapping[str, object]:
    _require(isinstance(value, Mapping) and set(value) == keys, code)
    return value


def _mode(value: object, expected: int, code: str) -> int:
    _require(type(value) is int and value == expected, code)
    return value


def _identity(value: object, code: str) -> int:
    _require(type(value) is int and value >= 0, code)
    return value


def _frozen_mapping(value: object, code: str) -> Mapping[str, object]:
    _require(isinstance(value, Mapping), code)
    return MappingProxyType(dict(value))


def release_set_epoch_identity(generation: int) -> tuple[str, str]:
    _require(
        type(generation) is int and generation in _RELEASE_SET_EPOCH_IDENTITIES,
        "release_set_generation_rejected",
    )
    return _RELEASE_SET_EPOCH_IDENTITIES[generation]


@dataclass(frozen=True, slots=True)
class P07DReleaseSet:
    core: Mapping[str, object]
    telegram_runtime: Mapping[str, object]
    selector: Mapping[str, object]
    runtime_config: Mapping[str, object]
    credential: Mapping[str, object]
    epoch: Mapping[str, object]
    services: tuple[Mapping[str, object], ...]
    rollback: Mapping[str, object]
    release_set_id: str
    generation: int = RELEASE_SET_GENERATION
    schema: str = RELEASE_SET_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "core", _frozen_mapping(self.core, "release_set_core_rejected"))
        object.__setattr__(
            self,
            "telegram_runtime",
            _frozen_mapping(self.telegram_runtime, "release_set_runtime_rejected"),
        )
        object.__setattr__(self, "selector", _frozen_mapping(self.selector, "release_set_selector_rejected"))
        object.__setattr__(
            self,
            "runtime_config",
            _frozen_mapping(self.runtime_config, "release_set_runtime_config_rejected"),
        )
        object.__setattr__(self, "credential", _frozen_mapping(self.credential, "release_set_credential_rejected"))
        object.__setattr__(self, "epoch", _frozen_mapping(self.epoch, "release_set_epoch_rejected"))
        object.__setattr__(
            self,
            "services",
            tuple(_frozen_mapping(item, "release_set_services_rejected") for item in self.services),
        )
        object.__setattr__(self, "rollback", _frozen_mapping(self.rollback, "release_set_rollback_rejected"))
        _require(self.schema == RELEASE_SET_SCHEMA, "release_set_schema_unknown")
        expected_epoch_id, expected_epoch_path = release_set_epoch_identity(self.generation)
        _sha(self.release_set_id, "release_set_id_rejected")

        core = _exact_mapping(
            self.core,
            {"entrypoint", "file_count", "inventory_digest", "release_digest", "tree_digest"},
            "release_set_core_rejected",
        )
        _absolute_file(core["entrypoint"], "release_set_core_rejected")
        _require(type(core["file_count"]) is int and core["file_count"] > 0, "release_set_core_rejected")
        for field in ("inventory_digest", "release_digest", "tree_digest"):
            _sha(core[field], "release_set_core_rejected")

        runtime = _exact_mapping(
            self.telegram_runtime,
            {"entrypoint", "file_count", "inventory_digest", "release_digest"},
            "release_set_runtime_rejected",
        )
        _absolute_file(runtime["entrypoint"], "release_set_runtime_rejected")
        _require(type(runtime["file_count"]) is int and runtime["file_count"] > 0, "release_set_runtime_rejected")
        for field in ("inventory_digest", "release_digest"):
            _sha(runtime[field], "release_set_runtime_rejected")

        selector = _exact_mapping(
            self.selector,
            {"digest", "generation", "path", "schema"},
            "release_set_selector_rejected",
        )
        _absolute_file(selector["path"], "release_set_selector_rejected")
        _sha(selector["digest"], "release_set_selector_rejected")
        _require(selector["generation"] == self.generation, "release_set_selector_rejected")
        _safe_id(selector["schema"], "release_set_selector_rejected")

        runtime_config = _exact_mapping(
            self.runtime_config,
            {
                "binding_digest", "channel_kind", "digest", "gid", "mode",
                "namespace_id", "path", "principal_id", "uid",
            },
            "release_set_runtime_config_rejected",
        )
        _absolute_file(runtime_config["path"], "release_set_runtime_config_rejected")
        _sha(runtime_config["digest"], "release_set_runtime_config_rejected")
        _sha(runtime_config["binding_digest"], "release_set_runtime_config_rejected")
        _require(runtime_config["channel_kind"] == "astrbot_telegram", "release_set_runtime_config_rejected")
        _safe_id(runtime_config["principal_id"], "release_set_runtime_config_rejected")
        _safe_id(runtime_config["namespace_id"], "release_set_runtime_config_rejected")
        _identity(runtime_config["uid"], "release_set_runtime_config_rejected")
        _identity(runtime_config["gid"], "release_set_runtime_config_rejected")
        _mode(runtime_config["mode"], 0o640, "release_set_runtime_config_rejected")

        credential = _exact_mapping(
            self.credential,
            {
                "dropin_set_digest", "effective_count", "effective_source", "name",
                "projection_digest", "source_category",
            },
            "release_set_credential_rejected",
        )
        _require(credential["name"] == "deepseek_api_key", "release_set_credential_rejected")
        _require(credential["effective_count"] == 1, "release_set_credential_rejected")
        _absolute_file(credential["effective_source"], "release_set_credential_rejected")
        _require(credential["source_category"] == "systemd_load_credential", "release_set_credential_rejected")
        _sha(credential["dropin_set_digest"], "release_set_credential_rejected")
        _sha(credential["projection_digest"], "release_set_credential_rejected")

        epoch = _exact_mapping(
            self.epoch,
            {
                "database_path", "directory_mode", "epoch_id", "file_mode", "gid",
                "schema", "schema_version", "uid",
            },
            "release_set_epoch_rejected",
        )
        _require(epoch["epoch_id"] == expected_epoch_id, "release_set_epoch_rejected")
        _require(epoch["database_path"] == expected_epoch_path, "release_set_epoch_rejected")
        _require(epoch["schema"] == RELEASE_SET_EPOCH_SCHEMA, "release_set_epoch_rejected")
        _require(epoch["schema_version"] == RELEASE_SET_EPOCH_VERSION, "release_set_epoch_rejected")
        _identity(epoch["uid"], "release_set_epoch_rejected")
        _identity(epoch["gid"], "release_set_epoch_rejected")
        _mode(epoch["directory_mode"], 0o700, "release_set_epoch_rejected")
        _mode(epoch["file_mode"], 0o600, "release_set_epoch_rejected")

        _require(len(self.services) == 3, "release_set_services_rejected")
        units: set[str] = set()
        kinds: set[str] = set()
        for service in self.services:
            projected = _exact_mapping(
                service,
                {
                    "binding_digest", "desired_state", "gid", "kind",
                    "stable_observation_seconds", "uid", "unit",
                },
                "release_set_services_rejected",
            )
            unit = projected["unit"]
            _require(isinstance(unit, str) and _UNIT.fullmatch(unit) is not None, "release_set_services_rejected")
            _require(unit not in units, "release_set_services_rejected")
            units.add(unit)
            _require(projected["kind"] in {"core", "telegram", "telegram_socket"}, "release_set_services_rejected")
            _require(projected["kind"] not in kinds, "release_set_services_rejected")
            kinds.add(projected["kind"])
            _require(projected["desired_state"] == "active", "release_set_services_rejected")
            _sha(projected["binding_digest"], "release_set_services_rejected")
            _identity(projected["uid"], "release_set_services_rejected")
            _identity(projected["gid"], "release_set_services_rejected")
            _require(
                type(projected["stable_observation_seconds"]) is int
                and 5 <= projected["stable_observation_seconds"] <= 60,
                "release_set_services_rejected",
            )

        rollback = _exact_mapping(
            self.rollback,
            {
                "core_release_digest", "desired_service_states_digest",
                "epoch_bundle_digest", "manifest_digest", "runtime_release_digest",
                "selector_digest",
            },
            "release_set_rollback_rejected",
        )
        for value in rollback.values():
            _sha(value, "release_set_rollback_rejected")

        _require(self.release_set_id == _digest(self.digest_payload()), "release_set_digest_mismatch")

    @property
    def epoch_identity_digest(self) -> str:
        return sha256(
            b"myuna-p07-d-epoch-identity-v1\0"
            + _canonical(
                {
                    **dict(self.epoch),
                    "release_set_id": self.release_set_id,
                }
            )
        ).hexdigest()

    def digest_payload(self) -> dict[str, object]:
        return {
            "core": dict(self.core),
            "credential": dict(self.credential),
            "epoch": dict(self.epoch),
            "generation": self.generation,
            "rollback": dict(self.rollback),
            "runtime_config": dict(self.runtime_config),
            "schema": self.schema,
            "selector": dict(self.selector),
            "services": [dict(item) for item in self.services],
            "telegram_runtime": dict(self.telegram_runtime),
        }

    def as_payload(self) -> dict[str, object]:
        return {**self.digest_payload(), "release_set_id": self.release_set_id}

    @classmethod
    def create(cls, **fields: object) -> "P07DReleaseSet":
        required = {
            "core", "credential", "epoch", "rollback", "runtime_config",
            "selector", "services", "telegram_runtime",
        }
        _require(required.issubset(fields) and set(fields) <= required | {"generation", "schema"}, "release_set_fields_rejected")
        services = fields["services"]
        _require(isinstance(services, (list, tuple)), "release_set_services_rejected")
        payload = {
            "core": fields["core"],
            "credential": fields["credential"],
            "epoch": fields["epoch"],
            "generation": fields.get("generation", RELEASE_SET_GENERATION),
            "rollback": fields["rollback"],
            "runtime_config": fields["runtime_config"],
            "schema": fields.get("schema", RELEASE_SET_SCHEMA),
            "selector": fields["selector"],
            "services": list(services),
            "telegram_runtime": fields["telegram_runtime"],
        }
        return cls(
            core=payload["core"],  # type: ignore[arg-type]
            telegram_runtime=payload["telegram_runtime"],  # type: ignore[arg-type]
            selector=payload["selector"],  # type: ignore[arg-type]
            runtime_config=payload["runtime_config"],  # type: ignore[arg-type]
            credential=payload["credential"],  # type: ignore[arg-type]
            epoch=payload["epoch"],  # type: ignore[arg-type]
            services=tuple(payload["services"]),  # type: ignore[arg-type]
            rollback=payload["rollback"],  # type: ignore[arg-type]
            release_set_id=_digest(payload),
            generation=payload["generation"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )

    @classmethod
    def from_payload(cls, payload: object) -> "P07DReleaseSet":
        required = {
            "core", "credential", "epoch", "generation", "release_set_id",
            "rollback", "runtime_config", "schema", "selector", "services",
            "telegram_runtime",
        }
        _require(isinstance(payload, Mapping) and set(payload) == required, "release_set_fields_rejected")
        _require(isinstance(payload["services"], list), "release_set_services_rejected")
        return cls(
            core=payload["core"],  # type: ignore[arg-type]
            telegram_runtime=payload["telegram_runtime"],  # type: ignore[arg-type]
            selector=payload["selector"],  # type: ignore[arg-type]
            runtime_config=payload["runtime_config"],  # type: ignore[arg-type]
            credential=payload["credential"],  # type: ignore[arg-type]
            epoch=payload["epoch"],  # type: ignore[arg-type]
            services=tuple(payload["services"]),  # type: ignore[arg-type]
            rollback=payload["rollback"],  # type: ignore[arg-type]
            release_set_id=payload["release_set_id"],  # type: ignore[arg-type]
            generation=payload["generation"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )
