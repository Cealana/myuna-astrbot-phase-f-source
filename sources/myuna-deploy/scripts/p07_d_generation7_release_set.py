from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Mapping, Sequence

from myuna_core.external_context.release_set import (
    P07DReleaseSet,
    RELEASE_SET_EPOCH_ID_7,
    RELEASE_SET_EPOCH_PATH_7,
    RELEASE_SET_EPOCH_SCHEMA,
    RELEASE_SET_EPOCH_VERSION,
    RELEASE_SET_GENERATION_7,
)


GENERATION = RELEASE_SET_GENERATION_7
RELEASE_SET_EPOCH_ID = RELEASE_SET_EPOCH_ID_7
RELEASE_SET_EPOCH_PATH = RELEASE_SET_EPOCH_PATH_7
SELECTOR_SCHEMA = "myuna.external-epoch-selector.v2"
BUNDLE_SCHEMA = "myuna.external-epoch-bundle.v1"
B_V4_EPOCH_ID = "telegram-owner-private-external-v4"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class Generation7ReleaseSetRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise Generation7ReleaseSetRejected(code)


def canonical(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii") + b"\n"


def digest(domain: str, value: object) -> str:
    _require(bool(domain) and domain.isascii(), "generation7_digest_domain_rejected")
    return sha256(domain.encode("ascii") + b"\0" + canonical(value)).hexdigest()


def selector_payload(previous_bundle_digest: str) -> dict[str, object]:
    _require(_SHA256.fullmatch(previous_bundle_digest) is not None, "generation7_bundle_digest_rejected")
    return {
        "channel_kind": "astrbot_telegram",
        "client_id": "telegram-owner-private",
        "database_path": RELEASE_SET_EPOCH_PATH,
        "epoch_id": RELEASE_SET_EPOCH_ID,
        "generation": GENERATION,
        "previous_epoch_bundle_digest": previous_bundle_digest,
        "previous_epoch_bundle_schema": BUNDLE_SCHEMA,
        "previous_epoch_id": B_V4_EPOCH_ID,
        "schema": SELECTOR_SCHEMA,
        "status": "active",
    }


def service_binding_digest(
    *,
    kind: str,
    unit: str,
    uid: int,
    gid: int,
    binding_files: Mapping[str, str],
    release_set_acl_digest: str,
) -> str:
    _require(kind in {"core", "telegram", "telegram_socket"}, "generation7_service_kind_rejected")
    _require(unit.endswith((".service", ".socket")), "generation7_service_unit_rejected")
    _require(uid >= 0 and gid >= 0, "generation7_service_identity_rejected")
    _require(_SHA256.fullmatch(release_set_acl_digest) is not None, "generation7_acl_digest_rejected")
    _require(
        bool(binding_files)
        and all(isinstance(path, str) and path.startswith("/") for path in binding_files)
        and all(_SHA256.fullmatch(value) is not None for value in binding_files.values()),
        "generation7_service_files_rejected",
    )
    return digest(
        "myuna-p07-d-service-binding-v1",
        {
            "binding_files": dict(sorted(binding_files.items())),
            "desired_state": "active",
            "gid": gid,
            "kind": kind,
            "release_set_acl_digest": release_set_acl_digest,
            "uid": uid,
            "unit": unit,
        },
    )


def rollback_manifest_digest(payload: Mapping[str, object]) -> str:
    return digest("myuna-p07-d-rollback-manifest-v1", dict(payload))


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
    return Path("/etc/myuna/p07-d-release-set-v1.json")
