"""Socket-aware Core Release Selector transaction contracts.

This module is a pure-data v2 wrapper around the already reviewed v1
transaction contract.  It preserves every v1 Core migration invariant while
adding the systemd socket that can activate the QQ Gateway to the sealed
prestate, activation sequence, health checks, and rollback contract.

The module accepts bytes and mappings only.  It has no filesystem, subprocess,
network, systemd, or service lifecycle API.
"""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from typing import Mapping, Sequence

from core_release_selector import (
    canonical_json_bytes,
    load_runtime_binding,
    parse_json_document,
)
import core_release_selector_transaction as v1


ACTIVATION_PLAN_SCHEMA = "myuna.core-release-selector.r4c-activation-plan.v2"
TRANSACTION_MANIFEST_SCHEMA = (
    "myuna.core-release-selector.r4b-transaction-manifest.v2"
)
MIGRATION_EVIDENCE_SCHEMA = (
    "myuna.core-release-selector.r4b-migration-evidence.v2"
)
DELETE_LIST_SCHEMA = "myuna.core-release-selector.r4b-delete-list.v2"
GATEWAY_SOCKET_UNIT = "myuna-qq-owner-runtime-dev.socket"

ACTIVATION_SEQUENCE = (
    "verify exact prestate and installed transaction",
    "stop Gateway socket explicitly",
    "verify Gateway socket inactive before stopping Gateway service",
    "stop Gateway service explicitly",
    "verify Gateway service inactive before changing Core",
    "install runtime binding and complete final Core drop-in set",
    "remove exactly the approved legacy drop-ins",
    "systemctl daemon-reload",
    "restart Core exactly once",
    "verify Core health and active release evidence",
    "start Gateway socket explicitly",
    "verify Gateway socket active and listening",
    "start Gateway service explicitly",
    "verify Gateway service health and socket trigger relationship",
)
HEALTH_CHECKS = (
    "Core active and running",
    "Core restart count increased by no more than one",
    "Core WorkingDirectory equals the canonical release path",
    "Core Verifier accepts binding, drop-ins, verifier, and release tree",
    "Gateway socket active and running before Gateway service resumes",
    "Gateway socket still triggers only the sealed Gateway service",
    "Gateway service active and running after Core health succeeds",
)
ALLOWED_SCOPE = (
    "Apply the exact installed transaction to myuna-core@qq.service.",
    "Stop and start only myuna-qq-owner-runtime-dev.socket and myuna-qq-owner-runtime-dev.service in the sealed order.",
    "Run one daemon-reload and one controlled Core restart.",
    "Automatically restore the exact Core, Gateway socket, and Gateway service prestate on any failed postcondition.",
)
FORBIDDEN_SCOPE = (
    "Modify the Core payload, Definition, Capability, EnvironmentFile, secrets, network, QQ account, model, memory, tools, vision, OpenClaw, Turn Manager, or Minecraft.",
    "Select any release other than the sealed canonical release.",
    "Execute arbitrary shell supplied by a model or chat message.",
    "Activate the superseded v1 transaction or activate without the exact v2 R4C plan digest and a separate explicit Owner approval.",
)

TransactionContractError = v1.TransactionContractError
TransactionEvidence = v1.TransactionEvidence
digest = v1.digest
transaction_tree_digest = v1.transaction_tree_digest


def require(condition: bool, code: str) -> None:
    if not condition:
        raise TransactionContractError(code)


def _exact(
    value: object, fields: set[str], code: str
) -> dict[str, object]:
    require(isinstance(value, dict) and set(value) == fields, code)
    return value


def _digest_map(value: object, code: str) -> dict[str, str]:
    require(isinstance(value, dict), code)
    answer: dict[str, str] = {}
    for name, expected in value.items():
        require(
            isinstance(name, str)
            and isinstance(expected, str)
            and len(expected) == 64
            and all(character in "0123456789abcdef" for character in expected),
            code,
        )
        answer[name] = expected
    return answer


def _as_v1_plan(root: Mapping[str, object]) -> dict[str, object]:
    legacy = deepcopy(dict(root))
    legacy["schema"] = v1.ACTIVATION_PLAN_SCHEMA
    gateway = dict(legacy["gateway"])
    gateway.pop("socket")
    gateway.pop("service_triggered_by_socket")
    legacy["gateway"] = gateway
    legacy["activation"] = {
        "sequence": list(v1.ACTIVATION_SEQUENCE),
        "health_checks": list(v1.HEALTH_CHECKS),
        "automatic_rollback": True,
        "maximum_core_restart_count_increase": 1,
    }
    rollback = dict(legacy["rollback"])
    rollback.pop("restore_gateway_socket_running_state")
    legacy["rollback"] = rollback
    legacy["scope"] = {
        "allowed": list(v1.ALLOWED_SCOPE),
        "forbidden": list(v1.FORBIDDEN_SCOPE),
    }
    return legacy


def build_activation_plan(
    *,
    gateway_socket_fragment_sha256: str,
    gateway_socket_dropin_sha256: Mapping[str, str],
    gateway_socket_listen_stream: str,
    gateway_socket_unit_file_state: str,
    gateway_socket_substate: str,
    **legacy_arguments: object,
) -> bytes:
    legacy_payload = v1.build_activation_plan(**legacy_arguments)
    root = parse_json_document(legacy_payload)
    root["schema"] = ACTIVATION_PLAN_SCHEMA
    gateway = dict(root["gateway"])
    gateway["service_triggered_by_socket"] = True
    gateway["socket"] = {
        "unit": GATEWAY_SOCKET_UNIT,
        "fragment_sha256": gateway_socket_fragment_sha256,
        "dropin_sha256": dict(sorted(gateway_socket_dropin_sha256.items())),
        "listen_stream": gateway_socket_listen_stream,
        "unit_file_state": gateway_socket_unit_file_state,
        "required_active": True,
        "required_substate": gateway_socket_substate,
        "stop_before_gateway_service": True,
        "start_before_gateway_service": True,
    }
    root["gateway"] = gateway
    root["activation"] = {
        "sequence": list(ACTIVATION_SEQUENCE),
        "health_checks": list(HEALTH_CHECKS),
        "automatic_rollback": True,
        "maximum_core_restart_count_increase": 1,
    }
    rollback = dict(root["rollback"])
    rollback["restore_gateway_socket_running_state"] = True
    root["rollback"] = rollback
    root["scope"] = {
        "allowed": list(ALLOWED_SCOPE),
        "forbidden": list(FORBIDDEN_SCOPE),
    }
    rendered = canonical_json_bytes(root)
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
        "activation plan v2 rejected",
    )
    require(
        root["schema"] == ACTIVATION_PLAN_SCHEMA,
        "activation plan v2 identity rejected",
    )
    gateway = _exact(
        root["gateway"],
        {
            "unit",
            "fragment_sha256",
            "dropin_sha256",
            "stop_before_core_restart",
            "start_only_after_core_health",
            "service_triggered_by_socket",
            "socket",
        },
        "activation gateway v2 rejected",
    )
    require(
        gateway["service_triggered_by_socket"] is True,
        "activation gateway socket trigger rejected",
    )
    socket = _exact(
        gateway["socket"],
        {
            "unit",
            "fragment_sha256",
            "dropin_sha256",
            "listen_stream",
            "unit_file_state",
            "required_active",
            "required_substate",
            "stop_before_gateway_service",
            "start_before_gateway_service",
        },
        "activation gateway socket rejected",
    )
    require(
        socket["unit"] == GATEWAY_SOCKET_UNIT
        and isinstance(socket["fragment_sha256"], str)
        and len(socket["fragment_sha256"]) == 64
        and all(
            character in "0123456789abcdef"
            for character in socket["fragment_sha256"]
        )
        and socket["listen_stream"] == "/run/myuna-gateway/qq-owner.sock"
        and socket["unit_file_state"] == "enabled"
        and socket["required_active"] is True
        and socket["required_substate"] == "running"
        and socket["stop_before_gateway_service"] is True
        and socket["start_before_gateway_service"] is True,
        "activation gateway socket rejected",
    )
    _digest_map(socket["dropin_sha256"], "activation gateway socket rejected")
    activation = _exact(
        root["activation"],
        {
            "sequence",
            "health_checks",
            "automatic_rollback",
            "maximum_core_restart_count_increase",
        },
        "activation sequence v2 rejected",
    )
    require(
        activation["sequence"] == list(ACTIVATION_SEQUENCE)
        and activation["health_checks"] == list(HEALTH_CHECKS)
        and activation["automatic_rollback"] is True
        and activation["maximum_core_restart_count_increase"] == 1,
        "activation sequence v2 rejected",
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
            "restore_gateway_socket_running_state",
        },
        "activation rollback v2 rejected",
    )
    require(
        rollback["restore_gateway_socket_running_state"] is True,
        "activation socket rollback rejected",
    )
    scope = _exact(
        root["scope"], {"allowed", "forbidden"}, "activation scope v2 rejected"
    )
    require(
        scope["allowed"] == list(ALLOWED_SCOPE)
        and scope["forbidden"] == list(FORBIDDEN_SCOPE),
        "activation scope v2 rejected",
    )
    legacy = _as_v1_plan(root)
    v1.load_activation_plan(canonical_json_bytes(legacy))
    require(canonical_json_bytes(root) == payload, "activation plan not canonical")
    return root


def _rebind_runtime_binding(payload: bytes, approval_digest: str) -> bytes:
    try:
        raw = parse_json_document(payload)
    except Exception as exc:
        raise TransactionContractError("runtime binding rejected") from exc
    require(
        isinstance(raw, dict) and "approval_plan_digest" in raw,
        "runtime binding rejected",
    )
    raw["approval_plan_digest"] = approval_digest
    return canonical_json_bytes(raw)


def _v1_proxy_payloads(
    payloads: Mapping[str, bytes],
) -> dict[str, bytes]:
    proxy = dict(payloads)
    root = load_activation_plan(proxy[v1.ACTIVATION_PLAN_PATH])
    legacy_plan = canonical_json_bytes(_as_v1_plan(root))
    legacy_digest = digest(legacy_plan)
    proxy[v1.ACTIVATION_PLAN_PATH] = legacy_plan
    proxy[v1.RUNTIME_BINDING_PATH] = _rebind_runtime_binding(
        proxy[v1.RUNTIME_BINDING_PATH], legacy_digest
    )
    evidence = parse_json_document(proxy[v1.MIGRATION_EVIDENCE_PATH])
    evidence["schema"] = v1.MIGRATION_EVIDENCE_SCHEMA
    evidence["approval_plan_digest"] = legacy_digest
    evidence["runtime_binding_sha256"] = digest(proxy[v1.RUNTIME_BINDING_PATH])
    proxy[v1.MIGRATION_EVIDENCE_PATH] = canonical_json_bytes(evidence)
    delete_list = parse_json_document(proxy[v1.DELETE_LIST_PATH])
    delete_list["schema"] = v1.DELETE_LIST_SCHEMA
    delete_list["approval_plan_digest"] = legacy_digest
    proxy[v1.DELETE_LIST_PATH] = canonical_json_bytes(delete_list)
    manifest = parse_json_document(proxy[v1.MANIFEST_PATH])
    manifest["schema"] = v1.TRANSACTION_MANIFEST_SCHEMA
    manifest["activation_plan_digest"] = legacy_digest
    manifest["artifacts"] = {
        path: digest(content)
        for path, content in sorted(proxy.items())
        if path != v1.MANIFEST_PATH
    }
    proxy[v1.MANIFEST_PATH] = canonical_json_bytes(manifest)
    return proxy


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
        binding_document = parse_json_document(runtime_binding)
        binding = load_runtime_binding(binding_document)
    except Exception as exc:
        raise TransactionContractError("runtime binding rejected") from exc
    target = plan["target"]
    require(
        binding.approval_plan_digest == approval_digest
        and binding.selected_release.release_path.as_posix()
        == target["release_path"]
        and binding.selected_release.tree_sha256 == target["tree_sha256"]
        and binding.selected_release.file_count == target["file_count"],
        "runtime binding activation plan mismatch",
    )
    legacy_plan = canonical_json_bytes(_as_v1_plan(plan))
    legacy_payloads = v1.build_transaction_payloads(
        activation_plan=legacy_plan,
        runtime_binding=_rebind_runtime_binding(
            runtime_binding, digest(legacy_plan)
        ),
        base_template=base_template,
        rollback_dropins=rollback_dropins,
        final_dropins=final_dropins,
        write_dropins=write_dropins,
        deletes=deletes,
    )
    payloads = dict(legacy_payloads)
    payloads[v1.ACTIVATION_PLAN_PATH] = activation_plan
    payloads[v1.RUNTIME_BINDING_PATH] = runtime_binding
    evidence = parse_json_document(payloads[v1.MIGRATION_EVIDENCE_PATH])
    evidence["schema"] = MIGRATION_EVIDENCE_SCHEMA
    evidence["approval_plan_digest"] = approval_digest
    evidence["runtime_binding_sha256"] = digest(runtime_binding)
    payloads[v1.MIGRATION_EVIDENCE_PATH] = canonical_json_bytes(evidence)
    delete_list = parse_json_document(payloads[v1.DELETE_LIST_PATH])
    delete_list["schema"] = DELETE_LIST_SCHEMA
    delete_list["approval_plan_digest"] = approval_digest
    payloads[v1.DELETE_LIST_PATH] = canonical_json_bytes(delete_list)
    manifest = parse_json_document(payloads[v1.MANIFEST_PATH])
    manifest["schema"] = TRANSACTION_MANIFEST_SCHEMA
    manifest["activation_plan_digest"] = approval_digest
    manifest["artifacts"] = {
        path: digest(content)
        for path, content in sorted(payloads.items())
        if path != v1.MANIFEST_PATH
    }
    payloads[v1.MANIFEST_PATH] = canonical_json_bytes(manifest)
    validate_transaction_payloads(payloads)
    return payloads


def validate_transaction_payloads(
    payloads: Mapping[str, bytes],
) -> TransactionEvidence:
    require(
        isinstance(payloads, Mapping)
        and v1.MANIFEST_PATH in payloads
        and v1.ACTIVATION_PLAN_PATH in payloads
        and v1.RUNTIME_BINDING_PATH in payloads,
        "transaction payloads v2 rejected",
    )
    manifest = parse_json_document(payloads[v1.MANIFEST_PATH])
    require(
        isinstance(manifest, dict)
        and manifest.get("schema") == TRANSACTION_MANIFEST_SCHEMA
        and manifest.get("activation_plan_digest")
        == digest(payloads[v1.ACTIVATION_PLAN_PATH])
        and manifest.get("artifacts")
        == {
            path: digest(content)
            for path, content in sorted(payloads.items())
            if path != v1.MANIFEST_PATH
        },
        "transaction manifest v2 rejected",
    )
    plan = load_activation_plan(payloads[v1.ACTIVATION_PLAN_PATH])
    approval_digest = digest(payloads[v1.ACTIVATION_PLAN_PATH])
    try:
        binding = load_runtime_binding(
            parse_json_document(payloads[v1.RUNTIME_BINDING_PATH])
        )
    except Exception as exc:
        raise TransactionContractError(
            "transaction runtime binding v2 rejected"
        ) from exc
    require(
        binding.approval_plan_digest == approval_digest,
        "transaction runtime binding v2 rejected",
    )
    evidence = parse_json_document(payloads[v1.MIGRATION_EVIDENCE_PATH])
    delete_list = parse_json_document(payloads[v1.DELETE_LIST_PATH])
    require(
        isinstance(evidence, dict)
        and evidence.get("schema") == MIGRATION_EVIDENCE_SCHEMA
        and evidence.get("approval_plan_digest") == approval_digest
        and evidence.get("runtime_binding_sha256")
        == digest(payloads[v1.RUNTIME_BINDING_PATH])
        and isinstance(delete_list, dict)
        and delete_list.get("schema") == DELETE_LIST_SCHEMA
        and delete_list.get("approval_plan_digest") == approval_digest,
        "transaction evidence v2 rejected",
    )
    legacy_evidence = v1.validate_transaction_payloads(
        _v1_proxy_payloads(payloads)
    )
    require(
        canonical_json_bytes(manifest) == payloads[v1.MANIFEST_PATH],
        "transaction manifest v2 not canonical",
    )
    return TransactionEvidence(
        activation_plan_digest=approval_digest,
        runtime_binding_sha256=digest(payloads[v1.RUNTIME_BINDING_PATH]),
        transaction_tree_sha256=transaction_tree_digest(payloads),
        artifact_count=len(payloads),
        final_dropin_count=legacy_evidence.final_dropin_count,
        rollback_dropin_count=legacy_evidence.rollback_dropin_count,
    )
