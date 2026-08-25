#!/usr/bin/env python3
"""Source-bound identity for the P07 owner-private Telegram runtime artifact.

The hybrid runtime directory is a locator only.  Authority comes from one
canonical manifest that binds exact Core/Deploy source, complete file bytes and
modes, the source-derived Telegram plugin, memory-only policy, immutable
cross-Program compatibility claims, and fixed service identities.
"""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Mapping

import p07_transactional_plugin_artifact_v1 as plugin_artifact
from p07_p10_memory_successor_contract_v3 import (
    digest as memory_successor_contract_digest_v3,
)


SOURCE_ID = "p07-owner-private-memory-runtime-artifact-source-binding-v1"
BINDING_SCHEMA = "myuna.p07-owner-private-memory-runtime-artifact-binding.v1"
PROJECTION_SCHEMA = "myuna.p07-owner-private-memory-runtime-artifact-projection.v1"
HYBRID_RUNTIME_SCHEMA = "myuna.p07-hybrid-telegram-runtime.v2"
RUNTIME_PROFILE = "p07-owner-private-memory-v1"
DIRECTORY_MODE = "0550"
FILE_MODE = "0440"
PROGRAMS = frozenset({"p01", "p08", "p09", "p10", "p15", "p16"})
SERVICE_IDENTITY = {
    "container": "myuna-astrbot-telegram-dev",
    "core_unit": "myuna-core@qq.service",
    "telegram_socket": "myuna-telegram-owner-runtime-dev.socket",
    "telegram_unit": "myuna-telegram-owner-runtime-dev.service",
}
MEMORY_CONTRACT = {
    "archive": "new-delivered-turns-only",
    "calendar_zone_selector": "digest-bound-iana-owner-day-v2",
    "calendar_zones": ["America/Los_Angeles", "Asia/Shanghai"],
    "default_calendar_zone": "Asia/Shanghai",
    "compressed_parent_rollback": True,
    "control_turns": "lossless-archive-model-history-isolated",
    "egress_policy": "p07-historical-raw-recall-egress-v1",
    "existing_history_migration": False,
    "reflective_diary": {
        "archive_authority": "local-lossless-raw",
        "complete_day_required": True,
        "egress_policy": "p07-reflective-diary-egress-v1",
        "default_owner_day_boundary": "06:00",
        "generation": "disabled-unless-independent-v2-selector",
        "model": "deepseek-v4-flash",
        "model_role": "p07_external_owner_day_reflective_diary_v2",
        "one_provider_call_per_attempt": True,
        "overflow": "coverage-incomplete-no-provider-call",
        "open_day_preview": "typed-owner-private-as-of-watermark-v1",
        "partial_day_diary": "preview-only-never-final",
        "revisions": "append-only",
        "rollback": "local-only-disabled",
        "selector": "digest-bound-separate-v2",
        "soft_close": "reversible-grace-120-minutes-default",
        "core_provider_gate": "protected-exact-egress-binding-digest",
        "statement_kinds": [
            "factual_observation",
            "interpretation_reflection",
            "uncertainty",
            "intention",
        ],
    },
    "p08_lifecycle": "activation-watermark-new-events-only",
    "p08_temporal_interval_index": "raw-source-bound-derivative",
    "p15_projection_active": False,
    "prompt_owner": "p07-owner-private-episodic-runtime-v1",
    "schema": "myuna.p07-owner-private-memory-runtime-build-contract.v1",
    "source_identity_contract_digest": memory_successor_contract_digest_v3(),
    "summary_used": False,
}

_SHA = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


class RuntimeArtifactRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def require(condition: bool, code: str) -> None:
    if not condition:
        raise RuntimeArtifactRejected(code)


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii") + b"\n"


def digest(domain: str, value: object) -> str:
    return sha256(domain.encode("ascii") + b"\0" + canonical(value).rstrip()).hexdigest()


def _sha(value: object, code: str) -> str:
    require(isinstance(value, str) and _SHA.fullmatch(value) is not None, code)
    return value


def _commit(value: object, code: str) -> str:
    require(isinstance(value, str) and _COMMIT.fullmatch(value) is not None, code)
    return value


def _plugin_projection(value: Mapping[str, object]) -> dict[str, object]:
    try:
        return plugin_artifact.binding_projection(value)
    except plugin_artifact.PluginArtifactRejected as exc:
        raise RuntimeArtifactRejected("runtime_artifact_plugin_rejected") from exc


def _validated_plugin_projection(value: Mapping[str, object]) -> dict[str, object]:
    try:
        return plugin_artifact.validate_binding_projection(value)
    except plugin_artifact.PluginArtifactRejected as exc:
        raise RuntimeArtifactRejected("runtime_artifact_plugin_rejected") from exc


def validate_file_inventory(value: object) -> dict[str, dict[str, object]]:
    require(isinstance(value, Mapping) and bool(value), "runtime_artifact_inventory_rejected")
    selected: dict[str, dict[str, object]] = {}
    for relative, row in sorted(value.items()):
        pure = PurePosixPath(str(relative))
        require(
            isinstance(relative, str)
            and pure.as_posix() == relative
            and not pure.is_absolute()
            and ".." not in pure.parts
            and isinstance(row, Mapping),
            "runtime_artifact_inventory_rejected",
        )
        item = dict(row)
        require(
            set(item) == {"mode", "sha256", "size"}
            and item.get("mode") == FILE_MODE
            and type(item.get("size")) is int
            and int(item["size"]) >= 0,
            "runtime_artifact_inventory_rejected",
        )
        _sha(item.get("sha256"), "runtime_artifact_inventory_rejected")
        selected[relative] = item
    return selected


def validate_program_boundaries(value: object) -> dict[str, dict[str, object]]:
    require(
        isinstance(value, Mapping) and set(value) == PROGRAMS,
        "runtime_artifact_boundary_rejected",
    )
    result: dict[str, dict[str, object]] = {}
    for program, row in sorted(value.items()):
        require(isinstance(row, Mapping), "runtime_artifact_boundary_rejected")
        item = dict(row)
        require(
            set(item) == {"identity_digest", "mutation_allowed", "state"}
            and item.get("mutation_allowed") is False
            and item.get("state") == "immutable_no_mutation",
            "runtime_artifact_boundary_rejected",
        )
        _sha(item.get("identity_digest"), "runtime_artifact_boundary_rejected")
        result[str(program)] = item
    return result


def build_binding(
    *,
    source_core_commit: str,
    source_core_tree: str,
    source_deploy_commit: str,
    source_deploy_tree: str,
    base_release_digest: str,
    file_inventory: Mapping[str, object],
    plugin_binding: Mapping[str, object],
    memory_contract: Mapping[str, object],
    source_policy: Mapping[str, object],
    program_boundaries: Mapping[str, object],
) -> dict[str, object]:
    source = {
        "core_commit": _commit(source_core_commit, "runtime_artifact_source_rejected"),
        "core_tree": _commit(source_core_tree, "runtime_artifact_source_rejected"),
        "deploy_commit": _commit(source_deploy_commit, "runtime_artifact_source_rejected"),
        "deploy_tree": _commit(source_deploy_tree, "runtime_artifact_source_rejected"),
    }
    base = _sha(base_release_digest, "runtime_artifact_base_rejected")
    inventory = validate_file_inventory(file_inventory)
    plugin = _plugin_projection(plugin_binding)
    boundaries = validate_program_boundaries(program_boundaries)
    contract = dict(memory_contract)
    policy = dict(source_policy)
    require(
        contract.get("archive") == "new-delivered-turns-only"
        and contract.get("existing_history_migration") is False
        and contract.get("summary_used") is False
        and contract.get("compressed_parent_rollback") is True
        and contract.get("p15_projection_active") is False,
        "runtime_artifact_memory_policy_rejected",
    )
    p07_semantic = {
        "memory_contract_digest": digest("p07_runtime_memory_contract", contract),
        "production_policy_digest": digest("p07_runtime_production_policy", policy),
        "runtime_profile": RUNTIME_PROFILE,
        "state": "target_memory_only_diary_inert",
    }
    artifact = {
        "base_release_digest": base,
        "directory_mode": DIRECTORY_MODE,
        "file_count": len(inventory),
        "file_inventory_digest": digest("p07_runtime_file_inventory", inventory),
        "file_mode": FILE_MODE,
    }
    compatibility = {
        "digest": digest(
            "p07_runtime_compatibility",
            {"p07": p07_semantic, "programs": boundaries},
        ),
        "p07": p07_semantic,
        "programs": boundaries,
    }
    semantic = {
        "artifact": artifact,
        "compatibility": compatibility,
        "plugin": plugin,
        "schema": BINDING_SCHEMA,
        "service_identity": dict(SERVICE_IDENTITY),
        "source": source,
    }
    return {
        **semantic,
        "binding_digest": digest("p07_runtime_artifact_binding", semantic),
    }


def validate_binding(value: Mapping[str, object]) -> dict[str, object]:
    selected = dict(value)
    require(
        set(selected)
        == {
            "artifact",
            "binding_digest",
            "compatibility",
            "plugin",
            "schema",
            "service_identity",
            "source",
        }
        and selected.get("schema") == BINDING_SCHEMA,
        "runtime_artifact_binding_rejected",
    )
    source = selected.get("source")
    artifact = selected.get("artifact")
    compatibility = selected.get("compatibility")
    require(
        isinstance(source, Mapping)
        and isinstance(artifact, Mapping)
        and isinstance(compatibility, Mapping),
        "runtime_artifact_binding_rejected",
    )
    source = dict(source)
    artifact = dict(artifact)
    compatibility = dict(compatibility)
    require(
        set(source) == {"core_commit", "core_tree", "deploy_commit", "deploy_tree"},
        "runtime_artifact_source_rejected",
    )
    for field in source:
        _commit(source[field], "runtime_artifact_source_rejected")
    require(
        set(artifact)
        == {
            "base_release_digest",
            "directory_mode",
            "file_count",
            "file_inventory_digest",
            "file_mode",
        }
        and artifact.get("directory_mode") == DIRECTORY_MODE
        and artifact.get("file_mode") == FILE_MODE
        and type(artifact.get("file_count")) is int
        and int(artifact["file_count"]) > 0,
        "runtime_artifact_inventory_rejected",
    )
    _sha(artifact.get("base_release_digest"), "runtime_artifact_base_rejected")
    _sha(artifact.get("file_inventory_digest"), "runtime_artifact_inventory_rejected")
    require(
        set(compatibility) == {"digest", "p07", "programs"}
        and isinstance(compatibility.get("p07"), Mapping),
        "runtime_artifact_boundary_rejected",
    )
    p07 = dict(compatibility["p07"])
    require(
        set(p07)
        == {
            "memory_contract_digest",
            "production_policy_digest",
            "runtime_profile",
            "state",
        }
        and p07.get("runtime_profile") == RUNTIME_PROFILE
        and p07.get("state") == "target_memory_only_diary_inert",
        "runtime_artifact_memory_policy_rejected",
    )
    _sha(p07.get("memory_contract_digest"), "runtime_artifact_memory_policy_rejected")
    _sha(p07.get("production_policy_digest"), "runtime_artifact_memory_policy_rejected")
    programs = validate_program_boundaries(compatibility["programs"])
    require(
        compatibility.get("digest")
        == digest("p07_runtime_compatibility", {"p07": p07, "programs": programs}),
        "runtime_artifact_boundary_rejected",
    )
    plugin = _validated_plugin_projection(selected["plugin"])
    require(
        selected.get("service_identity") == SERVICE_IDENTITY,
        "runtime_artifact_service_identity_rejected",
    )
    semantic = {key: selected[key] for key in selected if key != "binding_digest"}
    require(
        selected.get("binding_digest")
        == digest("p07_runtime_artifact_binding", semantic),
        "runtime_artifact_binding_digest_rejected",
    )
    return {
        **selected,
        "artifact": artifact,
        "compatibility": {**compatibility, "p07": p07, "programs": programs},
        "plugin": plugin,
        "source": source,
    }


def projection_from_manifest(
    manifest: Mapping[str, object], *, manifest_bytes: bytes
) -> dict[str, object]:
    selected = dict(manifest)
    required = {
        "base_release_digest",
        "core_import_closure",
        "files",
        "owner_private_memory_contract",
        "owner_private_memory_runtime_binding",
        "release_digest",
        "runtime_profile",
        "schema",
        "source_core_commit",
        "source_core_tree",
        "source_deploy_commit",
        "source_deploy_tree",
    }
    require(
        set(selected) == required
        and selected.get("schema") == HYBRID_RUNTIME_SCHEMA
        and selected.get("runtime_profile") == RUNTIME_PROFILE
        and canonical(selected) == manifest_bytes,
        "runtime_artifact_manifest_rejected",
    )
    files = validate_file_inventory(selected["files"])
    binding = validate_binding(selected["owner_private_memory_runtime_binding"])
    source = binding["source"]
    require(
        source
        == {
            "core_commit": selected["source_core_commit"],
            "core_tree": selected["source_core_tree"],
            "deploy_commit": selected["source_deploy_commit"],
            "deploy_tree": selected["source_deploy_tree"],
        }
        and binding["artifact"]
        == {
            "base_release_digest": selected["base_release_digest"],
            "directory_mode": DIRECTORY_MODE,
            "file_count": len(files),
            "file_inventory_digest": digest("p07_runtime_file_inventory", files),
            "file_mode": FILE_MODE,
        }
        and binding["compatibility"]["p07"]["memory_contract_digest"]
        == digest("p07_runtime_memory_contract", dict(selected["owner_private_memory_contract"])),
        "runtime_artifact_manifest_binding_rejected",
    )
    unsigned = {key: selected[key] for key in selected if key != "release_digest"}
    require(
        selected.get("release_digest") == sha256(canonical(unsigned)).hexdigest(),
        "runtime_artifact_release_digest_rejected",
    )
    semantic = {
        "artifact": binding["artifact"],
        "compatibility_digest": binding["compatibility"]["digest"],
        "hybrid_manifest_sha256": sha256(manifest_bytes).hexdigest(),
        "plugin": binding["plugin"],
        "release_digest": selected["release_digest"],
        "runtime_binding_digest": binding["binding_digest"],
        "runtime_profile": RUNTIME_PROFILE,
        "schema": PROJECTION_SCHEMA,
        "service_identity_digest": digest(
            "p07_runtime_service_identity", SERVICE_IDENTITY
        ),
        "source": source,
        "source_id": SOURCE_ID,
    }
    return {
        **semantic,
        "projection_digest": digest("p07_runtime_artifact_projection", semantic),
    }


def validate_projection(value: Mapping[str, object]) -> dict[str, object]:
    selected = dict(value)
    require(
        set(selected)
        == {
            "artifact",
            "compatibility_digest",
            "hybrid_manifest_sha256",
            "plugin",
            "projection_digest",
            "release_digest",
            "runtime_binding_digest",
            "runtime_profile",
            "schema",
            "service_identity_digest",
            "source",
            "source_id",
        }
        and selected.get("schema") == PROJECTION_SCHEMA
        and selected.get("source_id") == SOURCE_ID
        and selected.get("runtime_profile") == RUNTIME_PROFILE
        and isinstance(selected.get("artifact"), Mapping)
        and isinstance(selected.get("source"), Mapping),
        "runtime_artifact_projection_rejected",
    )
    artifact = dict(selected["artifact"])
    source = dict(selected["source"])
    require(
        set(artifact)
        == {
            "base_release_digest",
            "directory_mode",
            "file_count",
            "file_inventory_digest",
            "file_mode",
        }
        and artifact.get("directory_mode") == DIRECTORY_MODE
        and artifact.get("file_mode") == FILE_MODE
        and type(artifact.get("file_count")) is int
        and int(artifact["file_count"]) > 0
        and set(source)
        == {"core_commit", "core_tree", "deploy_commit", "deploy_tree"},
        "runtime_artifact_projection_rejected",
    )
    _sha(artifact.get("base_release_digest"), "runtime_artifact_projection_rejected")
    _sha(artifact.get("file_inventory_digest"), "runtime_artifact_projection_rejected")
    for field in (
        "compatibility_digest",
        "hybrid_manifest_sha256",
        "projection_digest",
        "release_digest",
        "runtime_binding_digest",
        "service_identity_digest",
    ):
        _sha(selected.get(field), "runtime_artifact_projection_rejected")
    _validated_plugin_projection(selected["plugin"])
    for field in ("core_commit", "core_tree", "deploy_commit", "deploy_tree"):
        _commit(source.get(field), "runtime_artifact_projection_rejected")
    require(
        selected.get("service_identity_digest")
        == digest("p07_runtime_service_identity", SERVICE_IDENTITY),
        "runtime_artifact_projection_rejected",
    )
    semantic = {key: selected[key] for key in selected if key != "projection_digest"}
    require(
        selected.get("projection_digest")
        == digest("p07_runtime_artifact_projection", semantic),
        "runtime_artifact_projection_rejected",
    )
    return selected


def read_canonical_manifest(candidate: Path) -> tuple[dict[str, object], bytes]:
    path = candidate / "P07_HYBRID_MANIFEST.json"
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeArtifactRejected("runtime_artifact_manifest_rejected") from exc
    require(isinstance(payload, dict), "runtime_artifact_manifest_rejected")
    projection_from_manifest(payload, manifest_bytes=raw)
    return payload, raw


def verify_candidate(candidate: Path) -> tuple[dict[str, object], dict[str, object]]:
    require(
        candidate.is_dir()
        and not candidate.is_symlink()
        and stat.S_IMODE(candidate.lstat().st_mode) == int(DIRECTORY_MODE, 8),
        "runtime_artifact_root_rejected",
    )
    manifest, raw = read_canonical_manifest(candidate)
    expected = validate_file_inventory(manifest["files"])
    actual: dict[str, dict[str, object]] = {}
    all_paths: set[str] = set()
    for path in sorted(candidate.rglob("*"), key=lambda item: item.relative_to(candidate).as_posix()):
        relative = path.relative_to(candidate).as_posix()
        metadata = path.lstat()
        require(
            not stat.S_ISLNK(metadata.st_mode)
            and (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink == 1),
            "runtime_artifact_type_rejected",
        )
        if stat.S_ISDIR(metadata.st_mode):
            require(
                stat.S_IMODE(metadata.st_mode) == int(DIRECTORY_MODE, 8),
                "runtime_artifact_mode_rejected",
            )
            continue
        require(
            stat.S_ISREG(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == int(FILE_MODE, 8),
            "runtime_artifact_mode_rejected",
        )
        all_paths.add(relative)
        if relative == "P07_HYBRID_MANIFEST.json":
            require(path.read_bytes() == raw, "runtime_artifact_manifest_rejected")
            continue
        payload = path.read_bytes()
        actual[relative] = {
            "mode": FILE_MODE,
            "sha256": sha256(payload).hexdigest(),
            "size": len(payload),
        }
    require(
        actual == expected
        and all_paths == {"P07_HYBRID_MANIFEST.json", *expected}
        and not any(
            "__pycache__" in relative or relative.endswith((".pyc", ".pyo"))
            for relative in all_paths
        ),
        "runtime_artifact_inventory_rejected",
    )
    return manifest, projection_from_manifest(manifest, manifest_bytes=raw)
