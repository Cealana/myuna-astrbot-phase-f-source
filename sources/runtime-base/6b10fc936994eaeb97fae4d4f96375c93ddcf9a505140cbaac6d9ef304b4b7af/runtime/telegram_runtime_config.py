#!/usr/bin/env python3
"""Single protected RuntimeConfig parser and external-epoch binding contract."""

from __future__ import annotations

from dataclasses import dataclass
import grp
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
from typing import Mapping

from context_window_policy import ContextWindowPolicy, ContextWindowRejected
from external_context_epoch import ExternalEpochBinding


CONFIG_PATH = Path("/etc/myuna-telegram-gateway/owner-runtime-v1.json")
CHANNEL_KIND = "astrbot_telegram"
CORE_CLIENT_ID = "telegram-owner-private"
RUNTIME_GROUP = "myuna-gateway-telegram"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_RUNTIME_CONFIG_BYTES = 8192


class RuntimeConfigRejected(PermissionError):
    """Fail-closed rejection that never projects config or identity values."""


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    channel_kind: str
    binding_id: str
    principal_id: str
    namespace_id: str
    finalization_digest: str
    evidence_sha256: str
    channel_instance: str
    core_host: str
    core_port: int
    max_requests_per_ten_minutes: int
    max_history_messages: int
    max_history_characters: int

    @classmethod
    def from_payload(cls, payload: object) -> "RuntimeConfig":
        required = {
            "binding_id",
            "channel_kind",
            "channel_instance",
            "core_host",
            "core_port",
            "evidence_sha256",
            "finalization_digest",
            "max_history_characters",
            "max_history_messages",
            "max_requests_per_ten_minutes",
            "namespace_id",
            "principal_id",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise RuntimeConfigRejected("runtime rejected")
        if payload["channel_kind"] != CHANNEL_KIND:
            raise RuntimeConfigRejected("runtime rejected")
        for key in ("binding_id", "namespace_id", "principal_id"):
            value = payload[key]
            if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
                raise RuntimeConfigRejected("runtime rejected")
        channel_instance = payload["channel_instance"]
        if (
            not isinstance(channel_instance, str)
            or _SAFE_ID.fullmatch(channel_instance) is None
        ):
            raise RuntimeConfigRejected("runtime rejected")
        for key in ("evidence_sha256", "finalization_digest"):
            value = payload[key]
            if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
                raise RuntimeConfigRejected("runtime rejected")
        if payload["core_host"] != "127.0.0.1":
            raise RuntimeConfigRejected("runtime rejected")
        core_port = payload["core_port"]
        request_limit = payload["max_requests_per_ten_minutes"]
        history_messages = payload["max_history_messages"]
        history_characters = payload["max_history_characters"]
        if not isinstance(core_port, int) or not 1024 <= core_port <= 65535:
            raise RuntimeConfigRejected("runtime rejected")
        if not isinstance(request_limit, int) or not 1 <= request_limit <= 60:
            raise RuntimeConfigRejected("runtime rejected")
        try:
            history_policy = ContextWindowPolicy(
                max_messages=history_messages,
                max_characters=history_characters,
            )
        except ContextWindowRejected:
            raise RuntimeConfigRejected("runtime rejected") from None
        return cls(
            channel_kind=CHANNEL_KIND,
            binding_id=str(payload["binding_id"]),
            principal_id=str(payload["principal_id"]),
            namespace_id=str(payload["namespace_id"]),
            finalization_digest=str(payload["finalization_digest"]),
            evidence_sha256=str(payload["evidence_sha256"]),
            channel_instance=channel_instance,
            core_host="127.0.0.1",
            core_port=core_port,
            max_requests_per_ten_minutes=request_limit,
            max_history_messages=history_policy.max_messages,
            max_history_characters=history_policy.max_characters,
        )


@dataclass(frozen=True, slots=True)
class ProtectedRuntimeConfigSnapshot:
    """Content-free identity for one protected RuntimeConfig file snapshot."""

    config: RuntimeConfig
    content_sha256: str
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    size: int

    def projection(self) -> dict[str, object]:
        return {
            "schema": "myuna.telegram-protected-runtime-config-snapshot.v1",
            "content_sha256": self.content_sha256,
            "device": self.device,
            "inode": self.inode,
            "uid": self.uid,
            "gid": self.gid,
            "mode": self.mode,
            "size": self.size,
        }


class _DuplicateJsonKey(ValueError):
    pass


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise _DuplicateJsonKey(key)
        payload[key] = value
    return payload


def parse_protected_runtime_config_snapshot(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int = 0o640,
) -> ProtectedRuntimeConfigSnapshot:
    """Read one exact protected config snapshot without links or defaults."""

    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_gid != expected_gid
            or stat.S_IMODE(before.st_mode) != expected_mode
            or before.st_size <= 0
            or before.st_size > _MAX_RUNTIME_CONFIG_BYTES
        ):
            raise RuntimeConfigRejected("runtime rejected")
        chunks: list[bytes] = []
        remaining = _MAX_RUNTIME_CONFIG_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        path_metadata = path.lstat()
        stable_fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_size")
        if (
            len(raw) != before.st_size
            or len(raw) > _MAX_RUNTIME_CONFIG_BYTES
            or any(getattr(before, field) != getattr(after, field) for field in stable_fields)
            or stat.S_ISLNK(path_metadata.st_mode)
            or any(getattr(before, field) != getattr(path_metadata, field) for field in stable_fields)
        ):
            raise RuntimeConfigRejected("runtime rejected")
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_json_object)
        config = RuntimeConfig.from_payload(payload)
        return ProtectedRuntimeConfigSnapshot(
            config=config,
            content_sha256=sha256(raw).hexdigest(),
            device=before.st_dev,
            inode=before.st_ino,
            uid=before.st_uid,
            gid=before.st_gid,
            mode=stat.S_IMODE(before.st_mode),
            size=before.st_size,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, _DuplicateJsonKey):
        raise RuntimeConfigRejected("runtime rejected") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def load_protected_runtime_config_snapshot() -> ProtectedRuntimeConfigSnapshot:
    try:
        expected_gid = grp.getgrnam(RUNTIME_GROUP).gr_gid
    except KeyError:
        raise RuntimeConfigRejected("runtime rejected") from None
    return parse_protected_runtime_config_snapshot(
        CONFIG_PATH,
        expected_uid=0,
        expected_gid=expected_gid,
        expected_mode=0o640,
    )


def external_epoch_binding_from_runtime_config(
    config: RuntimeConfig,
) -> ExternalEpochBinding:
    if not isinstance(config, RuntimeConfig):
        raise RuntimeConfigRejected("runtime rejected")
    return ExternalEpochBinding(
        channel_kind=config.channel_kind,
        client_id=CORE_CLIENT_ID,
        principal_id=config.principal_id,
        namespace_id=config.namespace_id,
    )
