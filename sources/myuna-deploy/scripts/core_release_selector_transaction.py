"""Pure contracts for a Core Release Selector R4 inactive transaction bundle.

The module accepts bytes and mappings only.  It has no filesystem, subprocess,
network, systemd, or service lifecycle API.  It seals a future R4C activation
plan first, derives the runtime binding from that plan digest, and validates a
complete forward/rollback transaction tree.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import PurePosixPath
import re
from typing import Mapping, Sequence

from core_release_selector import (
    canonical_json_bytes,
    load_runtime_binding,
    parse_json_document,
)


ACTIVATION_PLAN_SCHEMA = "myuna.core-release-selector.r4c-activation-plan.v1"
ACTIVATION_PLAN_STATUS = "sealed_pending_explicit_owner_approval"
TRANSACTION_MANIFEST_SCHEMA = (
    "myuna.core-release-selector.r4b-transaction-manifest.v1"
)
TRANSACTION_STATUS = "inactive_not_installed_not_active"
MIGRATION_EVIDENCE_SCHEMA = (
    "myuna.core-release-selector.r4b-migration-evidence.v1"
)
DELETE_LIST_SCHEMA = "myuna.core-release-selector.r4b-delete-list.v1"

UNIT = "myuna-core@qq.service"
INSTANCE = "qq"
GATEWAY_UNIT = "myuna-qq-owner-runtime-dev.service"
SELECTOR_NAME = "10-core-release-selector-v1.conf"
GUARD_NAME = "05-core-release-selector-guard-v1.conf"
RUNTIME_BINDING_LIVE_PATH = "/etc/myuna/core-release-selector/qq.binding.json"

MANIFEST_PATH = "TRANSACTION_MANIFEST.json"
ACTIVATION_PLAN_PATH = "activation/R4C_ACTIVATION_PLAN.json"
RUNTIME_BINDING_PATH = "runtime/qq.binding.json"
ROLLBACK_BASE_PATH = "rollback/myuna-core@.service"
MIGRATION_EVIDENCE_PATH = "evidence/MIGRATION_SUMMARY.json"
DELETE_LIST_PATH = "evidence/DELETE_LIST.json"
FINAL_PREFIX = "final/dropins/"
ROLLBACK_PREFIX = "rollback/dropins/"

TREE_DIGEST_ALGORITHM = "myuna-path-content-tree-sha256-v1"
PLAN_DIGEST_ALGORITHM = "sha256-canonical-json-v1"
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")
_HEX_40 = re.compile(r"^[a-f0-9]{40}$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]*$")

ACTIVATION_SEQUENCE = (
    "verify exact prestate and installed transaction",
    "stop Gateway explicitly",
    "install runtime binding and complete final Core drop-in set",
    "remove exactly the approved legacy drop-ins",
    "systemctl daemon-reload",
    "restart Core exactly once",
    "verify Core health and active release evidence",
    "start Gateway explicitly",
    "verify Gateway health",
)
HEALTH_CHECKS = (
    "Core active and running",
    "Core restart count increased by no more than one",
    "Core WorkingDirectory equals the canonical release path",
    "Core Verifier accepts binding, drop-ins, verifier, and release tree",
    "Gateway active and running after Core health succeeds",
)
ALLOWED_SCOPE = (
    "Apply the exact installed transaction to myuna-core@qq.service.",
    "Stop and start only myuna-qq-owner-runtime-dev.service as sequenced.",
    "Run one daemon-reload and one controlled Core restart.",
    "Automatically restore the exact prestate on any failed postcondition.",
)
FORBIDDEN_SCOPE = (
    "Modify the Core payload, Definition, Capability, EnvironmentFile, secrets, network, QQ account, model, memory, tools, vision, OpenClaw, Turn Manager, or Minecraft.",
    "Select any release other than the sealed canonical release.",
    "Execute arbitrary shell supplied by a model or chat message.",
    "Activate without the exact R4C plan digest and a separate explicit Owner approval.",
)


class TransactionContractError(RuntimeError):
    """A deterministic transaction contract rejection."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise TransactionContractError(code)


def digest(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def _exact(
    value: object, fields: set[str], code: str
) -> dict[str, object]:
    require(isinstance(value, dict) and set(value) == fields, code)
    return value


def _digest(value: object, code: str) -> str:
    require(
        isinstance(value, str) and _HEX_64.fullmatch(value) is not None,
        code,
    )
    return value


def _commit(value: object, code: str) -> str:
    require(
        isinstance(value, str) and _HEX_40.fullmatch(value) is not None,
        code,
    )
    return value


def _text(value: object, code: str) -> str:
    require(isinstance(value, str) and value != "", code)
    return value


def _name(value: object, code: str) -> str:
    require(
        isinstance(value, str) and _SAFE_NAME.fullmatch(value) is not None,
        code,
    )
    return value


def _digest_map(value: object, code: str) -> dict[str, str]:
    require(isinstance(value, dict), code)
    answer: dict[str, str] = {}
    for raw_name, raw_digest in value.items():
        name = _name(raw_name, code)
        answer[name] = _digest(raw_digest, code)
    return answer


def _safe_relative_path(value: str) -> str:
    require(isinstance(value, str) and value != "", "transaction path rejected")
    path = PurePosixPath(value)
    require(
        not path.is_absolute()
        and ".." not in path.parts
        and "." not in path.parts
        and path.as_posix() == value,
        "transaction path rejected",
    )
    return value


def transaction_tree_digest(payloads: Mapping[str, bytes]) -> str:
    require(
        isinstance(payloads, Mapping)
        and payloads
        and all(
            isinstance(path, str) and isinstance(payload, bytes)
            for path, payload in payloads.items()
        ),
        "transaction payload mapping rejected",
    )
    combined = sha256()
    for raw_path in sorted(payloads):
        path = _safe_relative_path(raw_path).encode("utf-8")
        payload = payloads[raw_path]
        combined.update(len(path).to_bytes(4, "big"))
        combined.update(path)
        combined.update(len(payload).to_bytes(8, "big"))
        combined.update(payload)
    return combined.hexdigest()


def build_activation_plan(
    *,
    deploy_commit: str,
    core_commit: str,
    migration_contract_sha256: str,
    r3b_plan_digest: str,
    binding_intent_sha256: str,
    verifier_sha256: str,
    base_template_sha256: str,
    prestate_dropin_sha256: Mapping[str, str],
    prestate_effective_owner: str,
    prestate_working_directory: str,
    target_release_path: str,
    target_tree_sha256: str,
    target_file_count: int,
    final_dropin_sha256: Mapping[str, str],
    write_dropin_sha256: Mapping[str, str],
    deletes: Sequence[str],
    gateway_fragment_sha256: str,
    gateway_dropin_sha256: Mapping[str, str],
) -> bytes:
    prestate = dict(sorted(prestate_dropin_sha256.items()))
    final = dict(sorted(final_dropin_sha256.items()))
    writes = dict(sorted(write_dropin_sha256.items()))
    deleted = sorted(deletes)
    require(
        set(writes) <= set(final)
        and set(deleted) <= set(prestate)
        and set(final) == (set(prestate) - set(deleted)) | set(writes),
        "activation migration set rejected",
    )
    rollback_snapshot_sha256 = digest(canonical_json_bytes(prestate))
    payload = {
        "schema": ACTIVATION_PLAN_SCHEMA,
        "status": ACTIVATION_PLAN_STATUS,
        "unit": UNIT,
        "instance": INSTANCE,
        "plan_digest_algorithm": PLAN_DIGEST_ALGORITHM,
        "source": {
            "deploy_commit": deploy_commit,
            "core_commit": core_commit,
            "migration_contract_sha256": migration_contract_sha256,
            "r3b_plan_digest": r3b_plan_digest,
            "binding_intent_sha256": binding_intent_sha256,
            "verifier_sha256": verifier_sha256,
        },
        "prestate": {
            "base_template_sha256": base_template_sha256,
            "dropin_sha256": prestate,
            "effective_owner": prestate_effective_owner,
            "effective_working_directory": prestate_working_directory,
            "runtime_binding_present": False,
            "selector_guard_present": False,
            "core_required_active": True,
            "gateway_required_active": True,
            "need_daemon_reload": False,
        },
        "target": {
            "release_path": target_release_path,
            "tree_sha256": target_tree_sha256,
            "file_count": target_file_count,
            "final_dropin_sha256": final,
            "write_dropin_sha256": writes,
            "delete_dropins": deleted,
            "only_release_owner": SELECTOR_NAME,
            "runtime_binding_path": RUNTIME_BINDING_LIVE_PATH,
        },
        "gateway": {
            "unit": GATEWAY_UNIT,
            "fragment_sha256": gateway_fragment_sha256,
            "dropin_sha256": dict(sorted(gateway_dropin_sha256.items())),
            "stop_before_core_restart": True,
            "start_only_after_core_health": True,
        },
        "activation": {
            "sequence": list(ACTIVATION_SEQUENCE),
            "health_checks": list(HEALTH_CHECKS),
            "automatic_rollback": True,
            "maximum_core_restart_count_increase": 1,
        },
        "rollback": {
            "snapshot_sha256": rollback_snapshot_sha256,
            "restore_exact_dropins": True,
            "remove_new_runtime_binding": True,
            "daemon_reload_after_restore": True,
            "restart_core_after_restore": True,
            "restore_gateway_running_state": True,
        },
        "scope": {
            "allowed": list(ALLOWED_SCOPE),
            "forbidden": list(FORBIDDEN_SCOPE),
        },
    }
    rendered = canonical_json_bytes(payload)
    load_activation_plan(rendered)
    return rendered


def load_activation_plan(payload: bytes) -> dict[str, object]:
    require(isinstance(payload, bytes), "activation plan bytes rejected")
    try:
        raw = parse_json_document(payload)
    except Exception as exc:
        raise TransactionContractError("activation plan JSON rejected") from exc
    root = _exact(
        raw,
        {
            "schema",
            "status",
            "unit",
            "instance",
            "plan_digest_algorithm",
            "source",
            "prestate",
            "target",
            "gateway",
            "activation",
            "rollback",
            "scope",
        },
        "activation plan rejected",
    )
    require(
        root["schema"] == ACTIVATION_PLAN_SCHEMA
        and root["status"] == ACTIVATION_PLAN_STATUS
        and root["unit"] == UNIT
        and root["instance"] == INSTANCE
        and root["plan_digest_algorithm"] == PLAN_DIGEST_ALGORITHM,
        "activation plan identity rejected",
    )
    source = _exact(
        root["source"],
        {
            "deploy_commit",
            "core_commit",
            "migration_contract_sha256",
            "r3b_plan_digest",
            "binding_intent_sha256",
            "verifier_sha256",
        },
        "activation source rejected",
    )
    _commit(source["deploy_commit"], "activation source rejected")
    _commit(source["core_commit"], "activation source rejected")
    for name in (
        "migration_contract_sha256",
        "r3b_plan_digest",
        "binding_intent_sha256",
        "verifier_sha256",
    ):
        _digest(source[name], "activation source rejected")
    prestate = _exact(
        root["prestate"],
        {
            "base_template_sha256",
            "dropin_sha256",
            "effective_owner",
            "effective_working_directory",
            "runtime_binding_present",
            "selector_guard_present",
            "core_required_active",
            "gateway_required_active",
            "need_daemon_reload",
        },
        "activation prestate rejected",
    )
    _digest(prestate["base_template_sha256"], "activation prestate rejected")
    before = _digest_map(prestate["dropin_sha256"], "activation prestate rejected")
    _name(prestate["effective_owner"], "activation prestate rejected")
    _text(prestate["effective_working_directory"], "activation prestate rejected")
    require(
        prestate["runtime_binding_present"] is False
        and prestate["selector_guard_present"] is False
        and prestate["core_required_active"] is True
        and prestate["gateway_required_active"] is True
        and prestate["need_daemon_reload"] is False,
        "activation prestate rejected",
    )
    target = _exact(
        root["target"],
        {
            "release_path",
            "tree_sha256",
            "file_count",
            "final_dropin_sha256",
            "write_dropin_sha256",
            "delete_dropins",
            "only_release_owner",
            "runtime_binding_path",
        },
        "activation target rejected",
    )
    _text(target["release_path"], "activation target rejected")
    _digest(target["tree_sha256"], "activation target rejected")
    require(
        type(target["file_count"]) is int and target["file_count"] > 0,
        "activation target rejected",
    )
    final = _digest_map(
        target["final_dropin_sha256"], "activation target rejected"
    )
    writes = _digest_map(
        target["write_dropin_sha256"], "activation target rejected"
    )
    deletes = target["delete_dropins"]
    require(
        isinstance(deletes, list)
        and all(
            isinstance(item, str)
            and _SAFE_NAME.fullmatch(item) is not None
            for item in deletes
        )
        and deletes == sorted(set(deletes)),
        "activation target rejected",
    )
    require(
        set(writes) <= set(final)
        and set(deletes) <= set(before)
        and set(final) == (set(before) - set(deletes)) | set(writes)
        and target["only_release_owner"] == SELECTOR_NAME
        and target["runtime_binding_path"] == RUNTIME_BINDING_LIVE_PATH,
        "activation migration set rejected",
    )
    gateway = _exact(
        root["gateway"],
        {
            "unit",
            "fragment_sha256",
            "dropin_sha256",
            "stop_before_core_restart",
            "start_only_after_core_health",
        },
        "activation gateway rejected",
    )
    require(
        gateway["unit"] == GATEWAY_UNIT
        and gateway["stop_before_core_restart"] is True
        and gateway["start_only_after_core_health"] is True,
        "activation gateway rejected",
    )
    _digest(gateway["fragment_sha256"], "activation gateway rejected")
    require(
        bool(_digest_map(gateway["dropin_sha256"], "activation gateway rejected")),
        "activation gateway rejected",
    )
    activation = _exact(
        root["activation"],
        {
            "sequence",
            "health_checks",
            "automatic_rollback",
            "maximum_core_restart_count_increase",
        },
        "activation sequence rejected",
    )
    require(
        activation["sequence"] == list(ACTIVATION_SEQUENCE)
        and activation["health_checks"] == list(HEALTH_CHECKS)
        and activation["automatic_rollback"] is True
        and activation["maximum_core_restart_count_increase"] == 1,
        "activation sequence rejected",
    )
    rollback = _exact(
        root["rollback"],
        {
            "snapshot_sha256",
            "restore_exact_dropins",
            "remove_new_runtime_binding",
            "daemon_reload_after_restore",
            "restart_core_after_restore",
            "restore_gateway_running_state",
        },
        "activation rollback rejected",
    )
    require(
        rollback["snapshot_sha256"] == digest(canonical_json_bytes(before))
        and all(
            rollback[field] is True
            for field in (
                "restore_exact_dropins",
                "remove_new_runtime_binding",
                "daemon_reload_after_restore",
                "restart_core_after_restore",
                "restore_gateway_running_state",
            )
        ),
        "activation rollback rejected",
    )
    scope = _exact(root["scope"], {"allowed", "forbidden"}, "activation scope rejected")
    require(
        scope["allowed"] == list(ALLOWED_SCOPE)
        and scope["forbidden"] == list(FORBIDDEN_SCOPE),
        "activation scope rejected",
    )
    require(canonical_json_bytes(root) == payload, "activation plan not canonical")
    return root


@dataclass(frozen=True)
class TransactionEvidence:
    activation_plan_digest: str
    runtime_binding_sha256: str
    transaction_tree_sha256: str
    artifact_count: int
    final_dropin_count: int
    rollback_dropin_count: int

    def to_payload(self) -> dict[str, object]:
        return {
            "activation_plan_digest": self.activation_plan_digest,
            "runtime_binding_sha256": self.runtime_binding_sha256,
            "transaction_tree_sha256": self.transaction_tree_sha256,
            "artifact_count": self.artifact_count,
            "final_dropin_count": self.final_dropin_count,
            "rollback_dropin_count": self.rollback_dropin_count,
        }


def build_transaction_payloads(
    *,
    activation_plan: bytes,
    runtime_binding: bytes,
    base_template: bytes,
    rollback_dropins: Mapping[str, bytes],
    final_dropins: Mapping[str, bytes],
    write_dropins: Mapping[str, bytes],
    deletes: Sequence[str],
) -> dict[str, bytes]:
    plan = load_activation_plan(activation_plan)
    approval_digest = digest(activation_plan)
    try:
        binding = load_runtime_binding(parse_json_document(runtime_binding))
    except Exception as exc:
        raise TransactionContractError("runtime binding rejected") from exc
    target = plan["target"]
    prestate = plan["prestate"]
    require(
        binding.approval_plan_digest == approval_digest
        and binding.selected_release.release_path.as_posix()
        == target["release_path"]
        and binding.selected_release.tree_sha256 == target["tree_sha256"]
        and binding.selected_release.file_count == target["file_count"],
        "runtime binding activation plan mismatch",
    )
    rollback_hashes = {
        name: digest(payload) for name, payload in sorted(rollback_dropins.items())
    }
    final_hashes = {
        name: digest(payload) for name, payload in sorted(final_dropins.items())
    }
    write_hashes = {
        name: digest(payload) for name, payload in sorted(write_dropins.items())
    }
    require(
        digest(base_template) == prestate["base_template_sha256"]
        and rollback_hashes == prestate["dropin_sha256"]
        and final_hashes == target["final_dropin_sha256"]
        and write_hashes == target["write_dropin_sha256"]
        and list(sorted(deletes)) == target["delete_dropins"],
        "transaction migration evidence mismatch",
    )
    evidence = {
        "schema": MIGRATION_EVIDENCE_SCHEMA,
        "approval_plan_digest": approval_digest,
        "runtime_binding_sha256": digest(runtime_binding),
        "base_template_sha256": digest(base_template),
        "writes": write_hashes,
        "deletes": list(sorted(deletes)),
        "final_dropins": final_hashes,
        "rollback_dropins": rollback_hashes,
        "only_release_owner": SELECTOR_NAME,
    }
    delete_list = {
        "schema": DELETE_LIST_SCHEMA,
        "approval_plan_digest": approval_digest,
        "dropins": list(sorted(deletes)),
    }
    artifacts: dict[str, bytes] = {
        ACTIVATION_PLAN_PATH: activation_plan,
        RUNTIME_BINDING_PATH: runtime_binding,
        ROLLBACK_BASE_PATH: base_template,
        MIGRATION_EVIDENCE_PATH: canonical_json_bytes(evidence),
        DELETE_LIST_PATH: canonical_json_bytes(delete_list),
    }
    for name, payload in sorted(final_dropins.items()):
        artifacts[FINAL_PREFIX + _name(name, "final drop-in name rejected")] = payload
    for name, payload in sorted(rollback_dropins.items()):
        artifacts[ROLLBACK_PREFIX + _name(name, "rollback drop-in name rejected")] = payload
    manifest = {
        "schema": TRANSACTION_MANIFEST_SCHEMA,
        "status": TRANSACTION_STATUS,
        "unit": UNIT,
        "instance": INSTANCE,
        "activation_plan_digest": approval_digest,
        "transaction_tree_digest_algorithm": TREE_DIGEST_ALGORITHM,
        "artifacts": {
            path: digest(payload) for path, payload in sorted(artifacts.items())
        },
        "runtime_paths_written": False,
        "systemd_changed": False,
        "daemon_reload_performed": False,
        "service_lifecycle_performed": False,
        "selected_or_activated": False,
    }
    artifacts[MANIFEST_PATH] = canonical_json_bytes(manifest)
    validate_transaction_payloads(artifacts)
    return artifacts


def _prefixed_payload_hashes(
    payloads: Mapping[str, bytes], prefix: str
) -> dict[str, str]:
    output: dict[str, str] = {}
    for path, payload in payloads.items():
        if path.startswith(prefix):
            name = path[len(prefix) :]
            require("/" not in name, "transaction artifact path rejected")
            output[_name(name, "transaction artifact name rejected")] = digest(payload)
    return dict(sorted(output.items()))


def validate_transaction_payloads(
    payloads: Mapping[str, bytes],
) -> TransactionEvidence:
    require(
        isinstance(payloads, Mapping)
        and MANIFEST_PATH in payloads
        and all(
            isinstance(path, str) and isinstance(payload, bytes)
            for path, payload in payloads.items()
        ),
        "transaction payloads rejected",
    )
    for path in payloads:
        _safe_relative_path(path)
    try:
        manifest = parse_json_document(payloads[MANIFEST_PATH])
    except Exception as exc:
        raise TransactionContractError("transaction manifest JSON rejected") from exc
    manifest = _exact(
        manifest,
        {
            "schema",
            "status",
            "unit",
            "instance",
            "activation_plan_digest",
            "transaction_tree_digest_algorithm",
            "artifacts",
            "runtime_paths_written",
            "systemd_changed",
            "daemon_reload_performed",
            "service_lifecycle_performed",
            "selected_or_activated",
        },
        "transaction manifest rejected",
    )
    require(
        manifest["schema"] == TRANSACTION_MANIFEST_SCHEMA
        and manifest["status"] == TRANSACTION_STATUS
        and manifest["unit"] == UNIT
        and manifest["instance"] == INSTANCE
        and manifest["transaction_tree_digest_algorithm"]
        == TREE_DIGEST_ALGORITHM
        and all(
            manifest[field] is False
            for field in (
                "runtime_paths_written",
                "systemd_changed",
                "daemon_reload_performed",
                "service_lifecycle_performed",
                "selected_or_activated",
            )
        ),
        "transaction manifest identity rejected",
    )
    artifacts = manifest["artifacts"]
    require(
        isinstance(artifacts, dict)
        and set(artifacts) == set(payloads) - {MANIFEST_PATH},
        "transaction artifact set rejected",
    )
    for path, expected_digest in artifacts.items():
        _safe_relative_path(path)
        require(
            _digest(expected_digest, "transaction artifact digest rejected")
            == digest(payloads[path]),
            "transaction artifact drift rejected",
        )
    required = {
        ACTIVATION_PLAN_PATH,
        RUNTIME_BINDING_PATH,
        ROLLBACK_BASE_PATH,
        MIGRATION_EVIDENCE_PATH,
        DELETE_LIST_PATH,
    }
    require(required <= set(payloads), "transaction required artifact missing")
    activation_plan = payloads[ACTIVATION_PLAN_PATH]
    plan = load_activation_plan(activation_plan)
    approval_digest = digest(activation_plan)
    require(
        manifest["activation_plan_digest"] == approval_digest,
        "transaction approval digest rejected",
    )
    try:
        binding = load_runtime_binding(
            parse_json_document(payloads[RUNTIME_BINDING_PATH])
        )
    except Exception as exc:
        raise TransactionContractError("transaction runtime binding rejected") from exc
    target = plan["target"]
    prestate = plan["prestate"]
    require(
        binding.approval_plan_digest == approval_digest
        and binding.selected_release.release_path.as_posix()
        == target["release_path"]
        and binding.selected_release.tree_sha256 == target["tree_sha256"]
        and binding.selected_release.file_count == target["file_count"],
        "transaction runtime binding rejected",
    )
    final_hashes = _prefixed_payload_hashes(payloads, FINAL_PREFIX)
    rollback_hashes = _prefixed_payload_hashes(payloads, ROLLBACK_PREFIX)
    require(
        final_hashes == target["final_dropin_sha256"]
        and rollback_hashes == prestate["dropin_sha256"]
        and digest(payloads[ROLLBACK_BASE_PATH])
        == prestate["base_template_sha256"],
        "transaction snapshot rejected",
    )
    try:
        evidence = parse_json_document(payloads[MIGRATION_EVIDENCE_PATH])
    except Exception as exc:
        raise TransactionContractError("migration evidence JSON rejected") from exc
    evidence = _exact(
        evidence,
        {
            "schema",
            "approval_plan_digest",
            "runtime_binding_sha256",
            "base_template_sha256",
            "writes",
            "deletes",
            "final_dropins",
            "rollback_dropins",
            "only_release_owner",
        },
        "migration evidence rejected",
    )
    require(
        evidence["schema"] == MIGRATION_EVIDENCE_SCHEMA
        and evidence["approval_plan_digest"] == approval_digest
        and evidence["runtime_binding_sha256"]
        == digest(payloads[RUNTIME_BINDING_PATH])
        and evidence["base_template_sha256"] == prestate["base_template_sha256"]
        and evidence["writes"] == target["write_dropin_sha256"]
        and evidence["deletes"] == target["delete_dropins"]
        and evidence["final_dropins"] == target["final_dropin_sha256"]
        and evidence["rollback_dropins"] == prestate["dropin_sha256"]
        and evidence["only_release_owner"] == SELECTOR_NAME,
        "migration evidence rejected",
    )
    try:
        delete_list = parse_json_document(payloads[DELETE_LIST_PATH])
    except Exception as exc:
        raise TransactionContractError("delete list JSON rejected") from exc
    require(
        delete_list
        == {
            "schema": DELETE_LIST_SCHEMA,
            "approval_plan_digest": approval_digest,
            "dropins": target["delete_dropins"],
        },
        "delete list rejected",
    )
    require(
        canonical_json_bytes(manifest) == payloads[MANIFEST_PATH],
        "transaction manifest not canonical",
    )
    return TransactionEvidence(
        activation_plan_digest=approval_digest,
        runtime_binding_sha256=digest(payloads[RUNTIME_BINDING_PATH]),
        transaction_tree_sha256=transaction_tree_digest(payloads),
        artifact_count=len(payloads),
        final_dropin_count=len(final_hashes),
        rollback_dropin_count=len(rollback_hashes),
    )
