from __future__ import annotations

from pathlib import Path
from typing import Mapping, Sequence

from external_epoch_bundle import BUNDLE_SCHEMA
from myuna_core.external_context.release_set import (
    P07DReleaseSet,
    RELEASE_SET_EPOCH_ID_11,
    RELEASE_SET_EPOCH_ID_12,
    RELEASE_SET_EPOCH_PATH_12,
    RELEASE_SET_EPOCH_SCHEMA,
    RELEASE_SET_EPOCH_VERSION,
    RELEASE_SET_GENERATION_12,
    RELEASE_SET_GENERATION_11,
)
from p07_d_generation8_release_set import (
    canonical,
    digest,
    rollback_manifest_digest,
    service_binding_digest,
)


GENERATION = RELEASE_SET_GENERATION_12
RELEASE_SET_EPOCH_ID = RELEASE_SET_EPOCH_ID_12
RELEASE_SET_EPOCH_PATH = RELEASE_SET_EPOCH_PATH_12
SELECTOR_SCHEMA = "myuna.external-epoch-selector.v2"
PREVIOUS_GENERATION = RELEASE_SET_GENERATION_11
PREVIOUS_EPOCH_ID = RELEASE_SET_EPOCH_ID_11


class Generation12ReleaseSetRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise Generation12ReleaseSetRejected(code)


def selector_payload(previous_bundle_digest: str) -> dict[str, object]:
    _require(
        isinstance(previous_bundle_digest, str)
        and len(previous_bundle_digest) == 64
        and all(character in "0123456789abcdef" for character in previous_bundle_digest),
        "generation12_bundle_digest_rejected",
    )
    return {
        "channel_kind": "astrbot_telegram",
        "client_id": "telegram-owner-private",
        "database_path": RELEASE_SET_EPOCH_PATH,
        "epoch_id": RELEASE_SET_EPOCH_ID,
        "generation": GENERATION,
        "previous_epoch_bundle_digest": previous_bundle_digest,
        "previous_epoch_bundle_schema": BUNDLE_SCHEMA,
        "previous_epoch_id": PREVIOUS_EPOCH_ID,
        "schema": SELECTOR_SCHEMA,
        "status": "active",
    }


def build_release_set(
    *,
    core: Mapping[str, object],
    telegram_runtime: Mapping[str, object],
    selector: Mapping[str, object],
    runtime_config: Mapping[str, object],
    credential: Mapping[str, object],
    epoch_uid: int,
    epoch_gid: int,
    services: Sequence[Mapping[str, object]],
    rollback: Mapping[str, object],
) -> P07DReleaseSet:
    return P07DReleaseSet.create(
        core=dict(core),
        telegram_runtime=dict(telegram_runtime),
        selector=dict(selector),
        runtime_config=dict(runtime_config),
        credential=dict(credential),
        epoch={
            "database_path": RELEASE_SET_EPOCH_PATH,
            "directory_mode": 0o700,
            "epoch_id": RELEASE_SET_EPOCH_ID,
            "file_mode": 0o600,
            "gid": epoch_gid,
            "schema": RELEASE_SET_EPOCH_SCHEMA,
            "schema_version": RELEASE_SET_EPOCH_VERSION,
            "uid": epoch_uid,
        },
        services=tuple(dict(item) for item in services),
        rollback=dict(rollback),
        generation=GENERATION,
    )


def protected_manifest_path() -> Path:
    return Path("/etc/myuna-telegram-gateway/p07-d-release-set-v1.json")
