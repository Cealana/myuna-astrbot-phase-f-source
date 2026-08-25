#!/usr/bin/env python3
"""P08-only, existing-state-preserving upgrade contract.

This source owns the narrow upgrade from the exact selected P08 predecessor to
an exact v2 release.  P08 state is treated as opaque bytes: the controller
never imports sqlite3 and never interprets, migrates, or deletes state rows.

The live entry points are intentionally inert unless an exact plan is supplied
and the caller is root.  Unit tests use only synthetic roots and fixtures.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Callable, Mapping, Sequence


CONTRACT_SCHEMA = "myuna.p08-existing-state-compatibility.v1"
FIXTURE_SCHEMA = "myuna.p08-source-owned-protocol-fixtures.v1"
STATE_SCHEMA = "myuna.p08-opaque-state-descriptor.v1"
STATE_METADATA_SCHEMA = "myuna.p08-opaque-state-metadata.v1"
STATE_BACKUP_METADATA_SCHEMA = "myuna.p08-opaque-state-backup-metadata.v1"
PLAN_SCHEMA = "myuna.p08-existing-state-upgrade-plan.v1"
JOURNAL_SCHEMA = "myuna.p08-existing-state-upgrade-journal.v1"
RECEIPT_SCHEMA = "myuna.p08-existing-state-upgrade-receipt.v1"

RELEASE_SCHEMA = "myuna.p08-active-temporal-code-release.v2"
SELECTOR_SCHEMA = "myuna.p08-active-temporal-selector.v1"
GATEWAY_RELEASE_SCHEMA = "myuna.p07-hybrid-telegram-runtime.v2"
PROTOCOL_SCHEMA = "myuna.active-temporal-context-protocol.v1"
STATUS_SCHEMA = "myuna.active-temporal-content-free-status.v1"
STATUS_RUNTIME_SCHEMA = "myuna.p08-content-free-status-runtime-closure.v2"
STATUS_STAGE_SCHEMA = "myuna.p08-content-free-status-stage.v1"
STATUS_RUNTIME_REJECTION_SCHEMA = "myuna.p08-status-runtime-subprojection.v2"
STATUS_RUNTIME_STAGE_SCHEMA = "myuna.p08-content-free-status-runtime-stage.v1"
TRUSTED_TIME_CAPABILITY_CLOSURE_SCHEMA = (
    "myuna.p08-trusted-time-capability-closure.v1"
)

PREDECESSOR_RELEASE_DIGEST = (
    "9a767797c9e4ee9ac3e417e2e00fdcabb68b6fcafeddcec090b05eb3ef9b103f"
)
PREDECESSOR_CORE_COMMIT = "107b33c5239582e186372b7a8c1b38e0c49e8902"
PREDECESSOR_DEPLOY_COMMIT = "7b0279968e10453a49a0cb18ae8953724d9b71c9"
TARGET_CORE_COMMIT = "065ef4b647f63925ae20bb564007c127433c0b81"

PREDECESSOR_CLIENT_SHA256 = (
    "798f834102af16efd47d7ddc3fa72904a6ca86d01fd02b354aadf65607594894"
)
TARGET_CLIENT_SHA256 = (
    "41e9ce1529db4a245e1be7c3d6b11aadc0e53175cf4d5804fde41c046e1ff612"
)
PREDECESSOR_PROTOCOL_SHA256 = (
    "bdbb5ca0adb0ecdcaf635eb93efe97f92778f7a0fe90ecf0f5be04ac58c66960"
)
TARGET_PROTOCOL_SHA256 = (
    "197dc45906628f97e347629c25ef970c39cae9dad13d67665a5836ea86845082"
)
SERVICE_SHA256 = "4317d83cfc7a658c7063baeda512a3d56c960e64d2add676748241195c507ada"
TARGET_SERVICE_ENTRYPOINT_SHA256 = (
    "17a1b96dd4634444ab7e90d0653512941a2fed6d70913f42ff1470c8bdd17f66"
)
SERVICE_UNIT_SHA256 = (
    "699662ffc743518be4a499c0598259ac686b17f531671c969a3de73311fd44f8"
)
TARGET_SERVICE_UNIT_SHA256 = (
    "545427759c39fa17620de47fc279b67dd183cc0e3c4d26eb1650676e22b7ca18"
)
SOCKET_UNIT_SHA256 = (
    "1dc226e5030388b36f1a9b08d1c4e49cb0c0d39489f1fbbaff2ab6e891a6df2a"
)
SYSUSERS_SHA256 = "ca9bcd0918173314690be52cc0a431cb2af29420de43516e500ed06ebf053415"
TMPFILES_SHA256 = "37a8558b1feae9b48dc6eacd41415ad49f4c5b76d2a5491142ca3007ac69e68c"

PREDECESSOR_SELECTOR_SHA256 = (
    "8ce714a5b6a61dff48dc882145b5e32ebcf81859cb70f22036cc1b81b9fc72e5"
)
PREDECESSOR_SELECTOR_ENV_SHA256 = (
    "1ddfc6a469e4c6d0098911d43959a1a8b263df98a33b961ce0dec6dbb820e4b6"
)
PREDECESSOR_PLAN_DIGEST = (
    "246f1f862225e2c176a192495c04cdf3095f42c5694312299efa11e1e6072f28"
)
ACTIVE_GATEWAY_MANIFEST_DIGEST = (
    "67674dd16c55c02b9e5edc2f81dd763314a669843ff99ea95c6a51f9acd7e5fe"
)
ACTIVE_GATEWAY_RELEASE_DIGEST = (
    "7baf48da3715ee2e1446ebf04a40ba8183c990fcf7f9505d9df465dc04e3d421"
)
ACTIVE_PLUGIN_DIGEST = (
    "c98aeeb7110df151ad21f1b5812bffbf51814229c77474ce814c28e4e73e8fc8"
)

LEGACY_OPERATIONS = ("confirm", "propose", "retrieve")
TARGET_OPERATIONS = (
    "confirm",
    "propose",
    "retrieve",
    "snapshot_active",
    "status_content_free",
)

SERVICE = "myuna-active-temporal-context-v1.service"
SOCKET = "myuna-active-temporal-context-v1.socket"
CONFIG_ROOT = Path("/etc/myuna-active-temporal-context-v1")
SELECTOR_JSON = CONFIG_ROOT / "selector.json"
SELECTOR_ENV = CONFIG_ROOT / "selector.env"
UNIT_ROOT = Path("/etc/systemd/system")
STATE_ROOT = Path("/var/lib/myuna-active-temporal-context-v1")
RELEASE_ROOT = Path("/opt/myuna/active-temporal/releases")
EVIDENCE_ROOT = Path("/var/lib/myuna-activation-backups/p08-existing-state-upgrade-v1")
GATEWAY_RELEASE_ROOT = Path("/opt/myuna/context24-gateway/telegram/releases")

PROTOCOL_PATH = Path("src/myuna_core/active_temporal_context/protocol.py")
SERVICE_PATH = Path("src/myuna_core/active_temporal_context/service.py")
SERVICE_SOURCE_PATH = Path("scripts/p08_temporal_service_v1.py")
SERVICE_ENTRYPOINT_PATH = Path("src/p08_temporal_service_v1.py")
CLIENT_PATH = Path("scripts/p08_temporal_gateway_v1.py")
SERVICE_UNIT_PATH = Path("systemd") / SERVICE
SOCKET_UNIT_PATH = Path("systemd") / SOCKET
SYSUSERS_PATH = Path("systemd/myuna-active-temporal-context-v1.sysusers.conf")
TMPFILES_PATH = Path("systemd/myuna-active-temporal-context-v1.tmpfiles.conf")
CONTROLLER_PATH = Path("scripts/p08_existing_state_upgrade_v1.py")
STATUS_RUNTIME_PATHS = (
    CLIENT_PATH,
)
TRUSTED_TIME_CAPABILITY_ENTRYPOINTS = (
    SERVICE_ENTRYPOINT_PATH,
    Path("src/myuna_core/trusted_time/runtime.py"),
)
TRUSTED_TIME_CAPABILITY_REQUIRED_PATHS = {
    Path("src/myuna_core/__init__.py"),
    Path("src/myuna_core/audit.py"),
    Path("src/myuna_core/capability_runtime/__init__.py"),
    Path("src/myuna_core/capability_runtime/audit.py"),
    Path("src/myuna_core/capability_runtime/compatibility.py"),
    Path("src/myuna_core/capability_runtime/errors.py"),
    Path("src/myuna_core/capability_runtime/lifecycle.py"),
    Path("src/myuna_core/capability_runtime/ports.py"),
    Path("src/myuna_core/integrations/__init__.py"),
    Path("src/myuna_core/integrations/openclaw/__init__.py"),
    Path("src/myuna_core/integrations/openclaw/base.py"),
    Path("src/myuna_core/integrations/openclaw/fake.py"),
    Path("src/myuna_core/operations/__init__.py"),
    Path("src/myuna_core/operations/approval.py"),
    Path("src/myuna_core/operations/audit.py"),
    Path("src/myuna_core/operations/catalog.py"),
    Path("src/myuna_core/operations/errors.py"),
    Path("src/myuna_core/operations/guard.py"),
    Path("src/myuna_core/operations/idempotency.py"),
    Path("src/myuna_core/operations/models.py"),
    Path("src/myuna_core/operations/policy.py"),
    Path("src/myuna_core/operations/tasks.py"),
    Path("src/myuna_core/trusted_time/runtime.py"),
    SERVICE_ENTRYPOINT_PATH,
}

STATE_FILES = ("temporal-context.sqlite3", "trusted-time.sqlite3")
STATE_FILE_ROLES = {
    "temporal-context.sqlite3": "temporal_context_store",
    "trusted-time.sqlite3": "trusted_time_store",
}
MAX_JSON_BYTES = 1_048_576
MAX_SOURCE_BYTES = 524_288
MAX_STATE_FILE_BYTES = 1_073_741_824
MAX_RELEASE_FILES = 128
SAFE_COMMIT = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,95}$")


class UpgradeRejected(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        activation_failure_code: str | None = None,
        rollback_failure_code: str | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.activation_failure_code = activation_failure_code
        self.rollback_failure_code = rollback_failure_code


def require(condition: bool, code: str) -> None:
    if not condition:
        raise UpgradeRejected(code)


def canonical(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def digest_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def digest_file(path: Path) -> str:
    digest = sha256()
    try:
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        raise UpgradeRejected("file_read_rejected") from exc
    return digest.hexdigest()


def _rooted(root: Path, absolute: Path) -> Path:
    return absolute if root == Path("/") else root / str(absolute).lstrip("/")


def _load_json(path: Path, *, code: str) -> dict[str, object]:
    try:
        metadata = path.lstat()
        require(
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and 0 < metadata.st_size <= MAX_JSON_BYTES,
            code,
        )
        raw = path.read_bytes()
        require(len(raw) == metadata.st_size, code)
        text = raw.decode("utf-8", "strict")
        payload = json.loads(text)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UpgradeRejected(code) from exc
    require(isinstance(payload, dict), code)
    return payload


def _release_inventory(root: Path) -> list[dict[str, object]]:
    require(root.is_dir() and not root.is_symlink(), "release_root_rejected")
    rows: list[dict[str, object]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        require(not stat.S_ISLNK(metadata.st_mode), "release_symlink_rejected")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        require(stat.S_ISREG(metadata.st_mode), "release_type_rejected")
        if relative == "manifest.json":
            continue
        require(
            "__pycache__" not in path.parts and path.suffix not in {".pyc", ".pyo"},
            "release_bytecode_rejected",
        )
        rows.append(
            {
                "path": relative,
                "sha256": digest_file(path),
                "size": metadata.st_size,
            }
        )
    require(0 < len(rows) <= MAX_RELEASE_FILES, "release_inventory_rejected")
    return rows


def _validate_release_manifest(
    root: Path,
    *,
    require_named_digest: bool,
) -> tuple[dict[str, object], str]:
    manifest = _load_json(root / "manifest.json", code="release_manifest_rejected")
    require(manifest.get("schema") == RELEASE_SCHEMA, "release_schema_rejected")
    require(
        SAFE_COMMIT.fullmatch(str(manifest.get("core_commit"))) is not None
        and SAFE_COMMIT.fullmatch(str(manifest.get("deploy_commit"))) is not None,
        "release_source_identity_rejected",
    )
    require(manifest.get("files") == _release_inventory(root), "release_inventory_rejected")
    release_digest = digest_bytes(canonical(manifest))
    if require_named_digest:
        require(root.name == release_digest, "release_digest_rejected")
    return manifest, release_digest


def _literal_strings(module: ast.Module) -> dict[str, str]:
    values: dict[str, str] = {}
    for node in module.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, SyntaxError):
            continue
        if isinstance(value, str):
            require(target.id not in values, "source_contract_rejected")
            values[target.id] = value
    return values


def _parse_source(path: Path) -> ast.Module:
    try:
        metadata = path.lstat()
        require(
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and 0 < metadata.st_size <= MAX_SOURCE_BYTES,
            "source_contract_rejected",
        )
        return ast.parse(path.read_text("utf-8", "strict"), filename=str(path))
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise UpgradeRejected("source_contract_rejected") from exc


def _server_contract(path: Path) -> dict[str, object]:
    module = _parse_source(path)
    literals = _literal_strings(module)
    operation_nodes: list[ast.AST] = []
    for node in module.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == "_OPERATIONS":
            operation_nodes.append(node.value)
    require(len(operation_nodes) == 1, "server_operations_rejected")
    value = operation_nodes[0]
    require(
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id == "frozenset"
        and len(value.args) == 1
        and not value.keywords,
        "server_operations_rejected",
    )
    try:
        operations = ast.literal_eval(value.args[0])
    except (ValueError, SyntaxError) as exc:
        raise UpgradeRejected("server_operations_rejected") from exc
    require(
        isinstance(operations, set)
        and operations
        and len(operations) <= 32
        and all(isinstance(item, str) and SAFE_CODE.fullmatch(item) for item in operations),
        "server_operations_rejected",
    )
    require(literals.get("SCHEMA") == PROTOCOL_SCHEMA, "server_schema_rejected")
    status_schema = literals.get("CONTENT_FREE_STATUS_SCHEMA")
    if "status_content_free" in operations:
        require(status_schema == STATUS_SCHEMA, "server_status_schema_rejected")
    return {
        "content_free_status_schema": status_schema,
        "operations": sorted(operations),
        "schema": literals["SCHEMA"],
        "sha256": digest_file(path),
        "source_path": PROTOCOL_PATH.as_posix(),
    }


def _literal_policy(
    module: ast.Module,
    name: str,
    *,
    width: int,
    code: str,
) -> dict[str, tuple[object, ...]]:
    nodes = [
        node.value
        for node in module.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == name
        and node.value is not None
    ]
    require(len(nodes) == 1, code)
    try:
        policy = ast.literal_eval(nodes[0])
    except (ValueError, SyntaxError) as exc:
        raise UpgradeRejected(code) from exc
    require(
        isinstance(policy, dict)
        and all(
            isinstance(stage, str)
            and SAFE_CODE.fullmatch(stage) is not None
            and isinstance(values, tuple)
            and len(values) == width
            for stage, values in policy.items()
        ),
        code,
    )
    return policy


def _server_rejection_identity(
    *,
    schema: str,
    source_domain: str,
    policy: Mapping[str, tuple[object, ...]],
) -> str:
    require(
        schema == "myuna.p08-server-rejection-subprojection.v1"
        and source_domain == "myuna-p08-server-rejection-subprojection-v1"
        and set(policy)
        == {
            "authenticated_context_protocol_boundary",
            "service_peer_boundary",
            "status_runtime_boundary",
        }
        and all(
            len(values) == 4
            and isinstance(values[0], str)
            and SAFE_CODE.fullmatch(values[0]) is not None
            and type(values[1]) is bool
            and isinstance(values[2], str)
            and SAFE_CODE.fullmatch(values[2]) is not None
            and type(values[3]) is bool
            for values in policy.values()
        ),
        "server_rejection_policy_rejected",
    )
    contract = {
        "schema": schema,
        "stage_policy": {
            stage: {
                "category": values[0],
                "error_code": values[2],
                "error_retryable": values[3],
                "retryable": values[1],
            }
            for stage, values in policy.items()
        },
    }
    return digest_bytes(source_domain.encode("ascii") + b"\0" + canonical(contract))


def _status_runtime_rejection_identity(
    *,
    schema: str,
    source_domain: str,
    policy: Mapping[str, tuple[object, ...]],
    trusted_time_policy: Mapping[str, tuple[object, ...]],
) -> str:
    require(
        schema == STATUS_RUNTIME_REJECTION_SCHEMA
        and source_domain == "myuna-p08-status-runtime-subprojection-v2"
        and set(policy)
        == {
            "response_encoding_boundary",
            "status_projection_boundary",
            "status_runtime_unknown_boundary",
            "store_state_boundary",
            "trusted_time_boundary",
        }
        and all(
            len(values) == 2
            and isinstance(values[0], str)
            and SAFE_CODE.fullmatch(values[0]) is not None
            and type(values[1]) is bool
            and values[1] is False
            for values in policy.values()
        ),
        "status_runtime_rejection_policy_rejected",
    )
    expected_trusted_time = {
        "trusted_time_permission_denied": (False, "none"),
        "trusted_time_unavailable": (True, "none"),
        "trusted_time_timeout": (True, "none"),
        "trusted_time_unsynchronized": (True, "none"),
        "trusted_time_uncertainty_exceeded": (True, "none"),
        "trusted_time_regression": (False, "none"),
        "trusted_time_drift_exceeded": (True, "none"),
        "trusted_time_source_drift": (False, "none"),
        "trusted_time_state_corrupt": (False, "none"),
        "trusted_time_state_permission_drift": (False, "none"),
        "trusted_time_persistence_ambiguous": (True, "ambiguous"),
        "trusted_time_audit_unavailable": (True, "ambiguous"),
        "trusted_time_sequence_exhausted": (False, "none"),
    }
    require(
        dict(trusted_time_policy) == expected_trusted_time,
        "trusted_time_rejection_policy_rejected",
    )
    contract = {
        "schema": schema,
        "stage_policy": {
            stage: {"category": values[0], "retryable": values[1]}
            for stage, values in policy.items()
        },
        "trusted_time_policy": {
            category: {
                "provider_state_effect": values[1],
                "retryable": values[0],
            }
            for category, values in trusted_time_policy.items()
        },
    }
    return digest_bytes(source_domain.encode("ascii") + b"\0" + canonical(contract))


def _local_module_path(root: Path, module_name: str) -> Path | None:
    if not module_name.startswith("myuna_core"):
        return None
    relative = Path("src", *module_name.split("."))
    source = root / relative.with_suffix(".py")
    package = root / relative / "__init__.py"
    if source.is_file() and not source.is_symlink():
        return source.relative_to(root)
    if package.is_file() and not package.is_symlink():
        return package.relative_to(root)
    return None


def _module_name(path: Path) -> tuple[str, str]:
    relative = path.relative_to("src")
    if relative.name == "__init__.py":
        module = ".".join(relative.parent.parts)
        return module, module
    module = ".".join(relative.with_suffix("").parts)
    return module, module.rsplit(".", 1)[0]


def _trusted_time_local_import_closure(root: Path) -> list[Path]:
    pending = list(TRUSTED_TIME_CAPABILITY_ENTRYPOINTS)
    observed: set[Path] = set()
    while pending:
        relative = pending.pop()
        if relative in observed:
            continue
        path = root / relative
        require(
            path.is_file()
            and not path.is_symlink()
            and 0 < path.stat().st_size <= MAX_SOURCE_BYTES,
            "trusted_time_capability_closure_rejected",
        )
        observed.add(relative)
        if relative.parts[0] != "src" or relative.name == "p08_temporal_service_v1.py":
            package = ""
        else:
            _, package = _module_name(relative)
        try:
            module = ast.parse(path.read_text("utf-8"), filename=relative.as_posix())
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise UpgradeRejected("trusted_time_capability_closure_rejected") from exc
        imports: set[str] = set()
        for node in ast.walk(module):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    parts = package.split(".") if package else []
                    keep = len(parts) - node.level + 1
                    if keep < 0:
                        raise UpgradeRejected(
                            "trusted_time_capability_closure_rejected"
                        )
                    base = ".".join(
                        parts[:keep] + ([node.module] if node.module else [])
                    )
                else:
                    base = node.module or ""
                if base:
                    imports.add(base)
                imports.update(
                    ".".join(part for part in (base, alias.name) if part)
                    for alias in node.names
                )
        for imported in sorted(imports):
            candidate = _local_module_path(root, imported)
            if candidate is not None and candidate not in observed:
                pending.append(candidate)
            parts = imported.split(".")
            for index in range(1, len(parts)):
                parent = _local_module_path(root, ".".join(parts[:index]))
                if parent is not None and parent not in observed:
                    pending.append(parent)
    return sorted(observed)


def trusted_time_capability_contract(root: Path) -> dict[str, object]:
    closure = _trusted_time_local_import_closure(root)
    require(
        TRUSTED_TIME_CAPABILITY_REQUIRED_PATHS.issubset(set(closure)),
        "trusted_time_capability_closure_rejected",
    )
    service = _parse_source(root / SERVICE_ENTRYPOINT_PATH)
    function_names = {
        node.name for node in service.body if isinstance(node, ast.FunctionDef)
    }
    source = (root / SERVICE_ENTRYPOINT_PATH).read_text("utf-8")
    require(
        "TrustedTimeCapability" in source
        and "capability.startup()" in source
        and "snapshot.accepting_requests" in source
        and "capability.shutdown()" in source
        and {
            "_stop_trusted_time_capability",
            "build_runtime_from_environment",
            "serve_systemd_socket",
        }.issubset(function_names),
        "trusted_time_capability_composition_rejected",
    )
    files = [
        {
            "path": relative.as_posix(),
            "sha256": digest_file(root / relative),
            "size": (root / relative).stat().st_size,
        }
        for relative in closure
    ]
    body = {
        "closure_files": files,
        "composition": {
            "direct_provider_injection": False,
            "require_ready": True,
            "shutdown_on_failure": True,
            "shutdown_on_service_exit": True,
            "startup_once": True,
        },
        "opaque_state_schema_migration": False,
        "runtime_id": "trusted-time-capability-v1",
        "schema": TRUSTED_TIME_CAPABILITY_CLOSURE_SCHEMA,
    }
    return {
        **body,
        "source_identity": digest_bytes(
            b"myuna-p08-trusted-time-capability-closure-v1\0"
            + canonical(body)
        ),
    }


def server_rejection_contract(root: Path) -> dict[str, object]:
    source_path = root / SERVICE_SOURCE_PATH
    runtime_path = root / SERVICE_ENTRYPOINT_PATH
    core_service_path = root / SERVICE_PATH
    client_path = root / CLIENT_PATH
    service = _parse_source(source_path)
    runtime = _parse_source(runtime_path)
    client = _parse_source(client_path)
    require(
        digest_file(source_path) == digest_file(runtime_path)
        and ast.dump(service, include_attributes=False)
        == ast.dump(runtime, include_attributes=False),
        "server_rejection_runtime_substitution_rejected",
    )
    service_literals = _literal_strings(service)
    client_literals = _literal_strings(client)
    service_policy = _literal_policy(
        service,
        "_SERVER_REJECTION_POLICY",
        width=4,
        code="server_rejection_policy_rejected",
    )
    client_policy = _literal_policy(
        client,
        "_SERVER_REJECTION_POLICY",
        width=4,
        code="server_rejection_client_policy_rejected",
    )
    require(service_policy == client_policy, "server_rejection_mixed_policy_rejected")
    service_runtime_policy = _literal_policy(
        service,
        "_STATUS_RUNTIME_REJECTION_POLICY",
        width=2,
        code="status_runtime_rejection_policy_rejected",
    )
    client_runtime_policy = _literal_policy(
        client,
        "_STATUS_RUNTIME_REJECTION_POLICY",
        width=2,
        code="status_runtime_rejection_client_policy_rejected",
    )
    require(
        service_runtime_policy == client_runtime_policy,
        "status_runtime_rejection_mixed_policy_rejected",
    )
    service_trusted_time_policy = _literal_policy(
        service,
        "_TRUSTED_TIME_REJECTION_POLICY",
        width=2,
        code="trusted_time_rejection_policy_rejected",
    )
    client_trusted_time_policy = _literal_policy(
        client,
        "_TRUSTED_TIME_REJECTION_POLICY",
        width=2,
        code="trusted_time_rejection_client_policy_rejected",
    )
    require(
        service_trusted_time_policy == client_trusted_time_policy,
        "trusted_time_rejection_mixed_policy_rejected",
    )
    identity = _server_rejection_identity(
        schema=service_literals.get("SERVER_REJECTION_SCHEMA", ""),
        source_domain=service_literals.get("SERVER_REJECTION_SOURCE_DOMAIN", ""),
        policy=service_policy,
    )
    runtime_identity = _status_runtime_rejection_identity(
        schema=service_literals.get("STATUS_RUNTIME_REJECTION_SCHEMA", ""),
        source_domain=service_literals.get(
            "STATUS_RUNTIME_REJECTION_SOURCE_DOMAIN", ""
        ),
        policy=service_runtime_policy,
        trusted_time_policy=service_trusted_time_policy,
    )
    require(
        client_literals.get("SERVER_REJECTION_SCHEMA")
        == service_literals.get("SERVER_REJECTION_SCHEMA")
        and client_literals.get("SERVER_REJECTION_SOURCE_DOMAIN")
        == service_literals.get("SERVER_REJECTION_SOURCE_DOMAIN")
        and client_literals.get("STATUS_RUNTIME_REJECTION_SCHEMA")
        == service_literals.get("STATUS_RUNTIME_REJECTION_SCHEMA")
        and client_literals.get("STATUS_RUNTIME_REJECTION_SOURCE_DOMAIN")
        == service_literals.get("STATUS_RUNTIME_REJECTION_SOURCE_DOMAIN")
        and {
            "parse_server_rejection_projection",
            "parse_status_runtime_rejection_projection",
            "server_rejection_projection",
            "serve_connection",
            "status_runtime_rejection_projection",
        }.issubset(
            {
                node.name
                for node in service.body
                if isinstance(node, ast.FunctionDef)
            }
        )
        and "parse_content_free_server_rejection"
        in {
            node.name
            for node in client.body
            if isinstance(node, ast.FunctionDef)
        },
        "server_rejection_source_contract_rejected",
    )
    return {
        "client_binding": {
            "sha256": digest_file(client_path),
            "source_contract_identity": identity,
            "source_path": CLIENT_PATH.as_posix(),
        },
        "core_service": {
            "sha256": digest_file(core_service_path),
            "source_path": SERVICE_PATH.as_posix(),
        },
        "entrypoint": "p08_temporal_service_v1",
        "rejection_subprojection": {
            "persistent_mutation": False,
            "private_content_included": False,
            "raw_cause_included": False,
            "rejections": [
                {
                    "category": values[0],
                    "error_code": values[2],
                    "error_retryable": values[3],
                    "retryable": values[1],
                    "stage": stage,
                }
                for stage, values in sorted(service_policy.items())
            ],
            "schema": service_literals["SERVER_REJECTION_SCHEMA"],
            "source_identity": identity,
        },
        "runtime_rejection_subprojection": {
            "persistent_mutation": False,
            "private_content_included": False,
            "raw_cause_included": False,
            "rejections": [
                {
                    "category": values[0],
                    "retryable": values[1],
                    "stage": stage,
                }
                for stage, values in sorted(service_runtime_policy.items())
            ],
            "request_nonce_bound": True,
            "schema": service_literals["STATUS_RUNTIME_REJECTION_SCHEMA"],
            "source_identity": runtime_identity,
            "trusted_time_rejections": [
                {
                    "error_category": category,
                    "provider_state_effect": values[1],
                    "retryable": values[0],
                }
                for category, values in sorted(
                    service_trusted_time_policy.items()
                )
            ],
        },
        "runtime_path": SERVICE_ENTRYPOINT_PATH.as_posix(),
        "sha256": digest_file(runtime_path),
        "source_path": SERVICE_SOURCE_PATH.as_posix(),
    }


def status_runtime_contract(root: Path) -> dict[str, object]:
    client = _parse_source(root / CLIENT_PATH)
    literals = _literal_strings(client)

    def imported_roots(module: ast.Module) -> set[str]:
        observed: set[str] = set()
        for node in module.body:
            if isinstance(node, ast.Import):
                observed.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                observed.add(node.module.split(".", 1)[0])
        return observed

    client_imports = imported_roots(client)
    class_names = {
        node.name for node in client.body if isinstance(node, ast.ClassDef)
    }
    function_names = {
        node.name for node in client.body if isinstance(node, ast.FunctionDef)
    }
    stage_policy_nodes = [
        node.value
        for node in client.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "_STATUS_STAGE_POLICY"
        and node.value is not None
    ]
    require(len(stage_policy_nodes) == 1, "status_stage_policy_rejected")
    try:
        stage_policy = ast.literal_eval(stage_policy_nodes[0])
    except (ValueError, SyntaxError) as exc:
        raise UpgradeRejected("status_stage_policy_rejected") from exc
    require(
        isinstance(stage_policy, dict)
        and 12 <= len(stage_policy) <= 32
        and all(
            isinstance(stage, str)
            and SAFE_CODE.fullmatch(stage) is not None
            and isinstance(policy, tuple)
            and len(policy) == 2
            and isinstance(policy[0], str)
            and SAFE_CODE.fullmatch(policy[0]) is not None
            and type(policy[1]) is bool
            for stage, policy in stage_policy.items()
        ),
        "status_stage_policy_rejected",
    )
    required_stages = {
        "pre_socket_source_identity",
        "pre_socket_privilege_identity",
        "pre_socket_protected_config",
        "transport_connect",
        "transport_timeout",
        "transport_eof",
        "server_peer_auth_protocol_rejection",
        "server_service_peer_rejection",
        "server_authenticated_context_protocol_rejection",
        "server_status_runtime_rejection",
        "response_parse",
        "response_projection",
        "response_schema_source_watermark",
        "parent_spawn",
        "parent_timeout",
        "parent_empty",
        "parent_oversize",
        "parent_malformed",
    }
    require(
        required_stages.issubset(stage_policy)
        and literals.get("STATUS_STAGE_SCHEMA") == STATUS_STAGE_SCHEMA,
        "status_stage_policy_rejected",
    )
    stage_contract = {
        "schema": STATUS_STAGE_SCHEMA,
        "stage_policy": {
            stage: {"category": policy[0], "retryable": policy[1]}
            for stage, policy in stage_policy.items()
        },
    }
    stage_source_identity = digest_bytes(
        b"myuna-p08-content-free-status-stage-contract-v1\0"
        + canonical(stage_contract)
    )
    server_policy = _literal_policy(
        client,
        "_SERVER_REJECTION_POLICY",
        width=4,
        code="server_rejection_client_policy_rejected",
    )
    server_identity = _server_rejection_identity(
        schema=literals.get("SERVER_REJECTION_SCHEMA", ""),
        source_domain=literals.get("SERVER_REJECTION_SOURCE_DOMAIN", ""),
        policy=server_policy,
    )
    runtime_policy = _literal_policy(
        client,
        "_STATUS_RUNTIME_REJECTION_POLICY",
        width=2,
        code="status_runtime_rejection_client_policy_rejected",
    )
    trusted_time_policy = _literal_policy(
        client,
        "_TRUSTED_TIME_REJECTION_POLICY",
        width=2,
        code="trusted_time_rejection_client_policy_rejected",
    )
    runtime_identity = _status_runtime_rejection_identity(
        schema=literals.get("STATUS_RUNTIME_REJECTION_SCHEMA", ""),
        source_domain=literals.get(
            "STATUS_RUNTIME_REJECTION_SOURCE_DOMAIN", ""
        ),
        policy=runtime_policy,
        trusted_time_policy=trusted_time_policy,
    )
    runtime_stage_contract = {
        "generic_stage_contract_identity": stage_source_identity,
        "runtime_rejection_source_identity": runtime_identity,
        "schema": STATUS_RUNTIME_STAGE_SCHEMA,
        "stage": "server_status_runtime_rejection",
    }
    runtime_stage_identity = digest_bytes(
        b"myuna-p08-content-free-status-runtime-stage-contract-v1\0"
        + canonical(runtime_stage_contract)
    )
    mapping_nodes = [
        node.value
        for node in client.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "_SERVER_TO_STATUS_STAGE"
    ]
    require(len(mapping_nodes) == 1, "server_rejection_mapping_rejected")
    try:
        server_mapping = ast.literal_eval(mapping_nodes[0])
    except (ValueError, SyntaxError) as exc:
        raise UpgradeRejected("server_rejection_mapping_rejected") from exc
    require(
        server_mapping
        == {
            "authenticated_context_protocol_boundary": (
                "server_authenticated_context_protocol_rejection"
            ),
            "service_peer_boundary": "server_service_peer_rejection",
            "status_runtime_boundary": "server_status_runtime_rejection",
        }
        and set(server_mapping.values()).issubset(stage_policy),
        "server_rejection_mapping_rejected",
    )
    require(
        "telegram_runtime_config" not in client_imports
        and "StatusRuntimeConfig" in class_names
        and {
            "content_free_status_rejection_projection",
            "load_protected_status_runtime_config",
            "parse_content_free_runtime_rejection",
            "parse_content_free_status_rejection",
            "parse_protected_status_runtime_config",
            "run_content_free_status_helper",
        }.issubset(function_names),
        "status_runtime_imports_rejected",
    )
    files: list[dict[str, object]] = []
    for relative in STATUS_RUNTIME_PATHS:
        path = root / relative
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise UpgradeRejected("status_runtime_inventory_rejected") from exc
        require(
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and 0 < metadata.st_size <= MAX_SOURCE_BYTES,
            "status_runtime_inventory_rejected",
        )
        files.append(
            {
                "path": relative.as_posix(),
                "sha256": digest_file(path),
                "size": metadata.st_size,
            }
        )
    return {
        "entrypoint": CLIENT_PATH.as_posix(),
        "files": files,
        "pythonpath": ["src", "scripts"],
        "schema": STATUS_RUNTIME_SCHEMA,
        "stage_projection": {
            "persistent_mutation": False,
            "raw_output_included": False,
            "rejections": [
                {
                    "category": policy[0],
                    "retryable": policy[1],
                    "stage": stage,
                }
                for stage, policy in sorted(stage_policy.items())
            ],
            "schema": STATUS_STAGE_SCHEMA,
            "source_identity": stage_source_identity,
        },
        "server_rejection_binding": {
            "mapping": dict(sorted(server_mapping.items())),
            "schema": literals["SERVER_REJECTION_SCHEMA"],
            "source_identity": server_identity,
        },
        "status_runtime_subprojection": {
            "generic_projection_preserved": True,
            "persistent_mutation": False,
            "raw_output_included": False,
            "rejections": [
                {
                    "category": policy[0],
                    "retryable": policy[1],
                    "stage": stage,
                }
                for stage, policy in sorted(runtime_policy.items())
            ],
            "request_nonce_bound": True,
            "schema": STATUS_RUNTIME_REJECTION_SCHEMA,
            "source_identity": runtime_identity,
            "stage_projection_schema": STATUS_RUNTIME_STAGE_SCHEMA,
            "stage_projection_source_identity": runtime_stage_identity,
            "trusted_time_rejections": [
                {
                    "error_category": category,
                    "provider_state_effect": policy[1],
                    "retryable": policy[0],
                }
                for category, policy in sorted(trusted_time_policy.items())
            ],
        },
    }


def _function(module: ast.Module, name: str) -> ast.FunctionDef | None:
    matches = [
        node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    require(len(matches) <= 1, "client_operations_rejected")
    return matches[0] if matches else None


def _returned_operations(
    function: ast.FunctionDef,
    *,
    literals: Mapping[str, str],
) -> set[str]:
    result: set[str] = set()
    for node in ast.walk(function):
        if not isinstance(node, ast.Return) or not isinstance(node.value, ast.Dict):
            continue
        for key, value in zip(node.value.keys, node.value.values, strict=True):
            if not isinstance(key, ast.Constant) or key.value != "operation":
                continue
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                result.add(value.value)
            elif isinstance(value, ast.Name) and value.id in literals:
                result.add(literals[value.id])
            elif isinstance(value, ast.Name) and value.id == "operation":
                assignments = []
                for candidate in ast.walk(function):
                    if not isinstance(candidate, ast.Assign):
                        continue
                    if any(
                        isinstance(target, ast.Name) and target.id == "operation"
                        for target in candidate.targets
                    ):
                        assignments.append(candidate.value)
                for assigned in assignments:
                    require(
                        isinstance(assigned, ast.Constant)
                        and isinstance(assigned.value, str),
                        "client_operations_rejected",
                    )
                    result.add(assigned.value)
            else:
                raise UpgradeRejected("client_operations_rejected")
    return result


def _client_contract(path: Path) -> dict[str, object]:
    module = _parse_source(path)
    literals = _literal_strings(module)
    require(
        literals.get("SCHEMA") == PROTOCOL_SCHEMA
        and literals.get("BOUNDARY")
        == "authenticated_telegram_owner_private_temporal_context",
        "client_schema_rejected",
    )
    operations: set[str] = set()
    required = _function(module, "build_request")
    require(required is not None, "client_operations_rejected")
    operations.update(_returned_operations(required, literals=literals))
    for name in ("build_active_snapshot_request", "build_content_free_status_request"):
        function = _function(module, name)
        if function is not None:
            operations.update(_returned_operations(function, literals=literals))
    require(
        operations
        and len(operations) <= 16
        and all(SAFE_CODE.fullmatch(item) for item in operations),
        "client_operations_rejected",
    )
    return {
        "operations": sorted(operations),
        "schema": literals["SCHEMA"],
        "sha256": digest_file(path),
        "source_path": CLIENT_PATH.as_posix(),
    }


_FIXTURE_PROGRAM = r'''import importlib.util
import json
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import sys

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("fixture_import_rejected")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

old = load("p08_fixture_old_client", Path(sys.argv[1]))
new = load("p08_fixture_new_client", Path(sys.argv[2]))
from myuna_core.active_temporal_context import protocol

def context(request_id, *, status=False):
    return {
        "authority_level": "owner",
        "binding_id": "binding-synthetic-v1",
        "channel_instance": "telegram-synthetic-v1",
        "channel_kind": "astrbot_telegram",
        "client_id": "telegram-owner-runtime-v1",
        "consent": {"media_processing": False, "memory_candidate": True, "tools": False},
        "conversation_id": "owner-private-lifecycle-status-v1" if status else "conversation-synthetic-v1",
        "conversation_kind": "private",
        "correlation_id": "correlation-synthetic-v1",
        "delivery_capabilities": ["text"],
        "event_id": "event-synthetic-v1",
        "namespace_id": "namespace-synthetic-v1",
        "occurred_at": "2026-08-09T00:00:00.000000+00:00",
        "principal_id": "principal-synthetic-v1",
        "request_id": request_id,
        "schema_version": "myuna.authenticated-conversation-context.v1",
        "trace_id": "trace-synthetic-v1",
    }

when = datetime(2026, 8, 9, tzinfo=timezone.utc)
cases = []
for action, arguments, expected in (
    ("get", ("synthetic query",), "retrieve"),
    ("add", ("current_task", "synthetic-slot", "2", "synthetic summary"), "propose"),
    ("confirm", ("proposal-synthetic-v1", "code-synthetic-v1"), "confirm"),
):
    request_id = "request-" + expected + "-synthetic-v1"
    request = old.build_request(
        old.TemporalCommand(action, arguments),
        authenticated_context=context(request_id),
        request_id=request_id,
        event_id="event-synthetic-v1",
        occurred_at=when,
    )
    cases.append(("active_predecessor_client", expected, request))

request_id = "request-snapshot-synthetic-v1"
cases.append((
    "reviewed_target_client",
    "snapshot_active",
    new.build_active_snapshot_request(
        authenticated_context=context(request_id),
        request_id=request_id,
        after_event_sequence=0,
    ),
))
request_id = "request-status-synthetic-v1"
cases.append((
    "reviewed_target_client",
    "status_content_free",
    new.build_content_free_status_request(
        authenticated_context=context(request_id, status=True),
        request_id=request_id,
        request_nonce="a" * 64,
        minimum_lifecycle_watermark=0,
    ),
))

rows = []
for client_role, expected, request in cases:
    raw = json.dumps(request, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    request_id, observed, parsed_context, parsed_input = protocol.parse_request_bytes(
        raw,
        authenticated_client_id="telegram-owner-runtime-v1",
        authenticated_channel_kind="astrbot_telegram",
    )
    if observed != expected or request_id != request["request_id"] or not parsed_input:
        raise RuntimeError("fixture_protocol_rejected")
    rows.append({
        "client_role": client_role,
        "operation": observed,
        "request_sha256": sha256(raw).hexdigest(),
    })
rows.sort(key=lambda row: row["operation"])
print(json.dumps(rows, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
'''


def _run_synthetic_fixtures(
    *,
    predecessor_client: Path,
    target_client: Path,
    target_root: Path,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="p08-fixture-") as directory:
        stub = Path(directory)
        (stub / "telegram_runtime_config.py").write_text(
            "# deterministic import-only fixture\n", "utf-8"
        )
        environment = {
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONPATH": os.pathsep.join(
                [str(target_root / "src"), str(stub)]
            ),
        }
        try:
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    _FIXTURE_PROGRAM,
                    str(predecessor_client),
                    str(target_client),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise UpgradeRejected("compatibility_fixture_rejected") from exc
    require(
        completed.returncode == 0 and 0 < len(completed.stdout) <= 65_536,
        "compatibility_fixture_rejected",
    )
    try:
        rows = json.loads(completed.stdout.decode("ascii", "strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise UpgradeRejected("compatibility_fixture_rejected") from exc
    require(
        isinstance(rows, list)
        and [row.get("operation") for row in rows] == list(TARGET_OPERATIONS)
        and all(
            isinstance(row, dict)
            and set(row) == {"client_role", "operation", "request_sha256"}
            and HEX64.fullmatch(str(row.get("request_sha256"))) is not None
            for row in rows
        ),
        "compatibility_fixture_rejected",
    )
    return {
        "cases": rows,
        "fixture_digest": digest_bytes(canonical(rows)),
        "schema": FIXTURE_SCHEMA,
    }


def validate_predecessor_release(root: Path) -> dict[str, object]:
    manifest, release_digest = _validate_release_manifest(
        root, require_named_digest=True
    )
    require(
        release_digest == PREDECESSOR_RELEASE_DIGEST
        and manifest.get("core_commit") == PREDECESSOR_CORE_COMMIT
        and manifest.get("deploy_commit") == PREDECESSOR_DEPLOY_COMMIT,
        "predecessor_release_rejected",
    )
    expected = {
        CLIENT_PATH: PREDECESSOR_CLIENT_SHA256,
        PROTOCOL_PATH: PREDECESSOR_PROTOCOL_SHA256,
        SERVICE_PATH: SERVICE_SHA256,
        SERVICE_UNIT_PATH: SERVICE_UNIT_SHA256,
        SOCKET_UNIT_PATH: SOCKET_UNIT_SHA256,
        SYSUSERS_PATH: SYSUSERS_SHA256,
        TMPFILES_PATH: TMPFILES_SHA256,
    }
    require(
        all(digest_file(root / path) == digest for path, digest in expected.items()),
        "predecessor_artifact_rejected",
    )
    require(
        _client_contract(root / CLIENT_PATH)["operations"] == list(LEGACY_OPERATIONS)
        and _server_contract(root / PROTOCOL_PATH)["operations"]
        == list(LEGACY_OPERATIONS),
        "predecessor_contract_rejected",
    )
    return manifest


def derive_compatibility_closure(
    *,
    predecessor_release: Path,
    target_root: Path,
    target_service_unit_sha256: str = TARGET_SERVICE_UNIT_SHA256,
    target_socket_unit_sha256: str = SOCKET_UNIT_SHA256,
) -> dict[str, object]:
    validate_predecessor_release(predecessor_release)
    require(
        HEX64.fullmatch(target_service_unit_sha256) is not None
        and HEX64.fullmatch(target_socket_unit_sha256) is not None,
        "target_unit_identity_rejected",
    )
    expected_target = {
        CLIENT_PATH: TARGET_CLIENT_SHA256,
        PROTOCOL_PATH: TARGET_PROTOCOL_SHA256,
        SERVICE_PATH: SERVICE_SHA256,
        SERVICE_ENTRYPOINT_PATH: TARGET_SERVICE_ENTRYPOINT_SHA256,
        SERVICE_UNIT_PATH: target_service_unit_sha256,
        SOCKET_UNIT_PATH: target_socket_unit_sha256,
        SYSUSERS_PATH: SYSUSERS_SHA256,
        TMPFILES_PATH: TMPFILES_SHA256,
    }
    require(
        all(
            (target_root / path).is_file()
            and not (target_root / path).is_symlink()
            and digest_file(target_root / path) == digest
            for path, digest in expected_target.items()
        ),
        "target_artifact_rejected",
    )
    predecessor_client = _client_contract(predecessor_release / CLIENT_PATH)
    predecessor_server = _server_contract(predecessor_release / PROTOCOL_PATH)
    target_client = _client_contract(target_root / CLIENT_PATH)
    target_server = _server_contract(target_root / PROTOCOL_PATH)
    require(
        predecessor_client["operations"] == list(LEGACY_OPERATIONS)
        and predecessor_server["operations"] == list(LEGACY_OPERATIONS)
        and target_client["operations"] == list(TARGET_OPERATIONS)
        and target_server["operations"] == list(TARGET_OPERATIONS)
        and set(predecessor_client["operations"]).issubset(
            set(target_server["operations"])
        )
        and "status_content_free" in target_client["operations"],
        "operation_compatibility_rejected",
    )
    fixtures = _run_synthetic_fixtures(
        predecessor_client=predecessor_release / CLIENT_PATH,
        target_client=target_root / CLIENT_PATH,
        target_root=target_root,
    )
    capability_contract = trusted_time_capability_contract(target_root)
    return {
        "active_gateway_client": predecessor_client,
        "legacy_operation_subset": list(LEGACY_OPERATIONS),
        "predecessor_core_commit": PREDECESSOR_CORE_COMMIT,
        "predecessor_deploy_commit": PREDECESSOR_DEPLOY_COMMIT,
        "predecessor_release_digest": PREDECESSOR_RELEASE_DIGEST,
        "predecessor_server": predecessor_server,
        "schema": CONTRACT_SCHEMA,
        "service_semantics": {
            "core_service_sha256": SERVICE_SHA256,
            "entrypoint": "p08_temporal_service_v1",
            "entrypoint_sha256": TARGET_SERVICE_ENTRYPOINT_SHA256,
            "server_rejection_subprojection": server_rejection_contract(
                target_root
            )["rejection_subprojection"],
            "service_unit_sha256": target_service_unit_sha256,
            "socket_unit_sha256": target_socket_unit_sha256,
            "state_schema_migration": False,
            "sysusers_sha256": SYSUSERS_SHA256,
            "tmpfiles_sha256": TMPFILES_SHA256,
            "trusted_time_capability_source_identity": capability_contract[
                "source_identity"
            ],
        },
        "status_helper_client": target_client,
        "status_runtime": status_runtime_contract(target_root),
        "synthetic_protocol_fixtures": fixtures,
        "target_server": target_server,
    }


def validate_target_release(
    *,
    root: Path,
    predecessor_release: Path,
    expected_core_commit: str = TARGET_CORE_COMMIT,
) -> tuple[dict[str, object], str]:
    manifest, release_digest = _validate_release_manifest(
        root, require_named_digest=True
    )
    require(
        SAFE_COMMIT.fullmatch(expected_core_commit) is not None
        and manifest.get("core_commit") == expected_core_commit,
        "target_core_rejected",
    )
    observed = manifest.get("upgrade_compatibility")
    expected = derive_compatibility_closure(
        predecessor_release=predecessor_release,
        target_root=root,
    )
    require(observed == expected, "target_compatibility_rejected")
    client = manifest.get("gateway_client")
    require(
        isinstance(client, dict)
        and client.get("sha256") == TARGET_CLIENT_SHA256,
        "target_client_rejected",
    )
    require(
        manifest.get("gateway_status_runtime") == status_runtime_contract(root),
        "target_status_runtime_rejected",
    )
    protocol = manifest.get("protocol_contract")
    require(
        isinstance(protocol, dict)
        and protocol.get("sha256") == TARGET_PROTOCOL_SHA256,
        "target_protocol_rejected",
    )
    require(
        manifest.get("entrypoint") == "p08_temporal_service_v1"
        and manifest.get("service_contract") == server_rejection_contract(root),
        "target_service_rejection_contract_rejected",
    )
    require(
        manifest.get("trusted_time_capability_contract")
        == trusted_time_capability_contract(root),
        "target_trusted_time_capability_contract_rejected",
    )
    return manifest, release_digest


def validate_active_gateway_runtime(root: Path) -> dict[str, object]:
    manifest = _load_json(
        root / "P07_HYBRID_MANIFEST.json", code="gateway_manifest_rejected"
    )
    release_digest = manifest.get("release_digest")
    unsigned = {key: value for key, value in manifest.items() if key != "release_digest"}
    require(
        manifest.get("schema") == GATEWAY_RELEASE_SCHEMA
        and HEX64.fullmatch(str(release_digest)) is not None
        and release_digest == ACTIVE_GATEWAY_RELEASE_DIGEST
        and root.name == release_digest
        and release_digest == digest_bytes(canonical(unsigned) + b"\n")
        and manifest.get("source_core_commit") == PREDECESSOR_CORE_COMMIT
        and manifest.get("source_deploy_commit") == PREDECESSOR_DEPLOY_COMMIT
        and digest_bytes(canonical(manifest)) == ACTIVE_GATEWAY_MANIFEST_DIGEST,
        "gateway_manifest_rejected",
    )
    files = manifest.get("files")
    require(isinstance(files, dict), "gateway_manifest_rejected")
    observed: dict[str, dict[str, object]] = {}
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        require(not stat.S_ISLNK(metadata.st_mode), "gateway_symlink_rejected")
        if not stat.S_ISREG(metadata.st_mode):
            continue
        relative = path.relative_to(root).as_posix()
        if relative == "P07_HYBRID_MANIFEST.json":
            continue
        observed[relative] = {
            "sha256": digest_file(path),
            "size": metadata.st_size,
        }
    require(files == observed, "gateway_inventory_rejected")
    client = root / "runtime/p08_temporal_gateway_v1.py"
    contract = _client_contract(client)
    require(
        contract["sha256"] == PREDECESSOR_CLIENT_SHA256
        and contract["operations"] == list(LEGACY_OPERATIONS),
        "gateway_client_rejected",
    )
    return {
        "client_contract": contract,
        "manifest_digest": ACTIVE_GATEWAY_MANIFEST_DIGEST,
        "release_digest": release_digest,
        "release_path": str(root.resolve()),
    }


def _file_projection(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise UpgradeRejected("public_prestate_rejected") from exc
    require(
        stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
        "public_prestate_rejected",
    )
    return {
        "gid": metadata.st_gid,
        "mode": stat.S_IMODE(metadata.st_mode),
        "sha256": digest_file(path),
        "size": metadata.st_size,
        "uid": metadata.st_uid,
    }


def describe_opaque_state(
    root: Path,
    *,
    expected_uid: int,
    expected_gid: int,
) -> dict[str, object]:
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise UpgradeRejected("state_root_rejected") from exc
    require(
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == 0o700
        and metadata.st_uid == expected_uid
        and metadata.st_gid == expected_gid,
        "state_root_permission_rejected",
    )
    try:
        observed = sorted(path.name for path in root.iterdir())
    except OSError as exc:
        raise UpgradeRejected("state_inventory_rejected") from exc
    require(observed == sorted(STATE_FILES), "state_inventory_rejected")
    files: list[dict[str, object]] = []
    for name in STATE_FILES:
        path = root / name
        try:
            item = path.lstat()
        except OSError as exc:
            raise UpgradeRejected("state_file_rejected") from exc
        require(
            stat.S_ISREG(item.st_mode)
            and not stat.S_ISLNK(item.st_mode)
            and item.st_nlink == 1,
            "state_file_type_rejected",
        )
        require(
            stat.S_IMODE(item.st_mode) == 0o600
            and item.st_uid == expected_uid
            and item.st_gid == expected_gid,
            "state_file_permission_rejected",
        )
        require(
            0 < item.st_size <= MAX_STATE_FILE_BYTES,
            "state_file_size_rejected",
        )
        files.append(
            {
                "gid": item.st_gid,
                "mode": stat.S_IMODE(item.st_mode),
                "mtime_ns": item.st_mtime_ns,
                "name": name,
                "sha256": digest_file(path),
                "size": item.st_size,
                "uid": item.st_uid,
            }
        )
    try:
        after = root.lstat()
    except OSError as exc:
        raise UpgradeRejected("state_root_rejected") from exc
    require(
        _stat_generation(after) == _stat_generation(metadata)
        and after.st_mode == metadata.st_mode
        and after.st_nlink == metadata.st_nlink
        and after.st_uid == metadata.st_uid
        and after.st_gid == metadata.st_gid,
        "state_inventory_drifted",
    )
    return {
        "files": files,
        "root": {
            "gid": metadata.st_gid,
            "mode": stat.S_IMODE(metadata.st_mode),
            "uid": metadata.st_uid,
        },
        "schema": STATE_SCHEMA,
    }


def _stat_generation(metadata: os.stat_result) -> dict[str, int]:
    return {
        "ctime_ns": metadata.st_ctime_ns,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mtime_ns": metadata.st_mtime_ns,
    }


def describe_opaque_state_metadata(
    root: Path,
    *,
    expected_uid: int,
    expected_gid: int,
) -> dict[str, object]:
    """Describe opaque state without opening or hashing either state file."""

    try:
        metadata = root.lstat()
    except OSError as exc:
        raise UpgradeRejected("state_root_rejected") from exc
    require(
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_nlink >= 2
        and stat.S_IMODE(metadata.st_mode) == 0o700
        and metadata.st_uid == expected_uid
        and metadata.st_gid == expected_gid,
        "state_root_permission_rejected",
    )
    try:
        observed = sorted(path.name for path in root.iterdir())
    except OSError as exc:
        raise UpgradeRejected("state_inventory_rejected") from exc
    require(observed == sorted(STATE_FILES), "state_inventory_rejected")
    files: list[dict[str, object]] = []
    for name in STATE_FILES:
        path = root / name
        try:
            item = path.lstat()
        except OSError as exc:
            raise UpgradeRejected("state_file_rejected") from exc
        require(
            stat.S_ISREG(item.st_mode)
            and not stat.S_ISLNK(item.st_mode)
            and item.st_nlink == 1,
            "state_file_type_rejected",
        )
        require(
            stat.S_IMODE(item.st_mode) == 0o600
            and item.st_uid == expected_uid
            and item.st_gid == expected_gid,
            "state_file_permission_rejected",
        )
        require(
            0 < item.st_size <= MAX_STATE_FILE_BYTES,
            "state_file_size_rejected",
        )
        files.append(
            {
                "generation": _stat_generation(item),
                "gid": item.st_gid,
                "mode": stat.S_IMODE(item.st_mode),
                "name": name,
                "nlink": item.st_nlink,
                "path_role": STATE_FILE_ROLES[name],
                "size": item.st_size,
                "type": "regular_file",
                "uid": item.st_uid,
            }
        )
    try:
        after = root.lstat()
    except OSError as exc:
        raise UpgradeRejected("state_root_rejected") from exc
    require(
        _stat_generation(after) == _stat_generation(metadata)
        and after.st_mode == metadata.st_mode
        and after.st_nlink == metadata.st_nlink
        and after.st_uid == metadata.st_uid
        and after.st_gid == metadata.st_gid,
        "state_inventory_drifted",
    )
    return {
        "content_bytes_read": False,
        "files": files,
        "root": {
            "generation": _stat_generation(metadata),
            "gid": metadata.st_gid,
            "mode": stat.S_IMODE(metadata.st_mode),
            "nlink": metadata.st_nlink,
            "path_role": "opaque_state_root",
            "type": "directory",
            "uid": metadata.st_uid,
        },
        "schema": STATE_METADATA_SCHEMA,
    }


def validate_opaque_backup_metadata(
    *,
    backup: Path,
    expected: Mapping[str, object],
    expected_uid: int,
    expected_gid: int,
) -> dict[str, object]:
    """Validate an opaque backup without opening or hashing its data files."""

    manifest = _load_json(backup / "STATE.json", code="state_backup_manifest_rejected")
    require(manifest == expected, "state_backup_manifest_rejected")
    data = describe_opaque_state_metadata(
        backup / "data",
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    rows = expected.get("files")
    require(
        isinstance(rows, list)
        and [
            row.get("name") if isinstance(row, dict) else None
            for row in rows
        ]
        == list(STATE_FILES),
        "state_descriptor_rejected",
    )
    expected_by_name = {
        str(row.get("name")): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("name"), str)
    }
    require(set(expected_by_name) == set(STATE_FILES), "state_descriptor_rejected")
    metadata_rows = data.get("files")
    require(isinstance(metadata_rows, list), "state_backup_metadata_rejected")
    for row in metadata_rows:
        require(isinstance(row, dict), "state_backup_metadata_rejected")
        expected_row = expected_by_name.get(str(row.get("name")))
        generation = row.get("generation")
        require(
            isinstance(expected_row, dict)
            and isinstance(generation, dict)
            and row.get("mode") == expected_row.get("mode")
            and row.get("uid") == expected_row.get("uid")
            and row.get("gid") == expected_row.get("gid")
            and row.get("size") == expected_row.get("size")
            and generation.get("mtime_ns") == expected_row.get("mtime_ns"),
            "state_backup_metadata_rejected",
        )
    try:
        backup_metadata = backup.lstat()
        manifest_metadata = (backup / "STATE.json").lstat()
    except OSError as exc:
        raise UpgradeRejected("state_backup_metadata_rejected") from exc
    require(
        stat.S_ISDIR(backup_metadata.st_mode)
        and not stat.S_ISLNK(backup_metadata.st_mode)
        and stat.S_IMODE(backup_metadata.st_mode) == 0o700
        and stat.S_ISREG(manifest_metadata.st_mode)
        and not stat.S_ISLNK(manifest_metadata.st_mode)
        and manifest_metadata.st_nlink == 1
        and stat.S_IMODE(manifest_metadata.st_mode) == 0o600,
        "state_backup_metadata_rejected",
    )
    require(
        backup_metadata.st_uid == os.geteuid()
        and backup_metadata.st_gid == os.getegid()
        and manifest_metadata.st_uid == os.geteuid()
        and manifest_metadata.st_gid == os.getegid(),
        "state_backup_metadata_rejected",
    )
    observed = sorted(
        path.relative_to(backup).as_posix()
        for path in backup.rglob("*")
    )
    require(
        observed
        == ["STATE.json", "data", *[f"data/{name}" for name in STATE_FILES]],
        "state_backup_inventory_rejected",
    )
    return {
        "backup": {
            "generation": _stat_generation(backup_metadata),
            "gid": backup_metadata.st_gid,
            "mode": stat.S_IMODE(backup_metadata.st_mode),
            "nlink": backup_metadata.st_nlink,
            "type": "directory",
            "uid": backup_metadata.st_uid,
        },
        "content_bytes_read": False,
        "data": data,
        "manifest": {
            "generation": _stat_generation(manifest_metadata),
            "gid": manifest_metadata.st_gid,
            "mode": stat.S_IMODE(manifest_metadata.st_mode),
            "nlink": manifest_metadata.st_nlink,
            "size": manifest_metadata.st_size,
            "type": "regular_file",
            "uid": manifest_metadata.st_uid,
        },
        "schema": STATE_BACKUP_METADATA_SCHEMA,
    }


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _set_identity(path: Path, *, uid: int, gid: int) -> None:
    metadata = path.lstat()
    if metadata.st_uid == uid and metadata.st_gid == gid:
        return
    require(os.geteuid() == 0, "identity_change_requires_root")
    os.chown(path, uid, gid, follow_symlinks=False)


def _exclusive_write(
    path: Path,
    payload: bytes,
    *,
    mode: int,
    uid: int | None = None,
    gid: int | None = None,
) -> None:
    """Durably publish exact bytes without inheriting the caller's umask."""

    require(
        path.parent.is_dir() and not path.parent.is_symlink(),
        "exclusive_write_parent_rejected",
    )
    require(
        not path.exists() and not path.is_symlink(),
        "exclusive_write_target_exists",
    )
    require(
        not any(path.parent.glob(f".{path.name}.*.stage")),
        "exclusive_write_residue_rejected",
    )
    require(
        type(mode) is int and 0 <= mode <= 0o777,
        "exclusive_write_mode_rejected",
    )
    expected_uid = os.geteuid() if uid is None else uid
    expected_gid = os.getegid() if gid is None else gid
    require(
        type(expected_uid) is int
        and expected_uid >= 0
        and type(expected_gid) is int
        and expected_gid >= 0,
        "exclusive_write_identity_rejected",
    )

    descriptor, temporary_text = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".stage", dir=path.parent
    )
    temporary = Path(temporary_text)
    linked = False
    payload_sha256 = digest_bytes(payload)

    def verify_descriptor(selected: int, *, expected_nlink: int) -> None:
        before = os.fstat(selected)
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == expected_nlink
            and stat.S_IMODE(before.st_mode) == mode
            and before.st_uid == expected_uid
            and before.st_gid == expected_gid
            and before.st_size == len(payload),
            "exclusive_write_readback_rejected",
        )
        os.lseek(selected, 0, os.SEEK_SET)
        digest = sha256()
        observed_size = 0
        while True:
            chunk = os.read(selected, 1024 * 1024)
            if not chunk:
                break
            observed_size += len(chunk)
            digest.update(chunk)
        after = os.fstat(selected)
        require(
            observed_size == len(payload)
            and digest.hexdigest() == payload_sha256
            and (after.st_dev, after.st_ino, after.st_nlink, after.st_mode)
            == (before.st_dev, before.st_ino, before.st_nlink, before.st_mode)
            and (after.st_uid, after.st_gid, after.st_size)
            == (before.st_uid, before.st_gid, before.st_size),
            "exclusive_write_readback_rejected",
        )

    try:
        os.fchmod(descriptor, mode)
        if os.geteuid() == 0:
            os.fchown(descriptor, expected_uid, expected_gid)
        else:
            current = os.fstat(descriptor)
            require(
                current.st_uid == expected_uid and current.st_gid == expected_gid,
                "identity_change_requires_root",
            )
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            require(written > 0, "exclusive_write_short_write")
            offset += written
        os.fsync(descriptor)
        verify_descriptor(descriptor, expected_nlink=1)
        _fsync_directory(path.parent)
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise UpgradeRejected("exclusive_write_target_exists") from exc
        except OSError as exc:
            raise UpgradeRejected("exclusive_write_finalize_rejected") from exc
        linked = True
        _fsync_directory(path.parent)
        temporary.unlink()
        _fsync_directory(path.parent)
        linked = False
        os.close(descriptor)
        descriptor = -1
        final_descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            verify_descriptor(final_descriptor, expected_nlink=1)
        finally:
            os.close(final_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()
            _fsync_directory(path.parent)
        require(not linked, "exclusive_write_finalize_rejected")


def _atomic_write(path: Path, payload: bytes, *, mode: int, uid: int, gid: int) -> None:
    require(path.parent.is_dir() and not path.parent.is_symlink(), "atomic_parent_rejected")
    descriptor, temporary_text = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_text)
    try:
        os.fchmod(descriptor, mode)
        if os.geteuid() == 0:
            os.fchown(descriptor, uid, gid)
        else:
            current = os.fstat(descriptor)
            require(current.st_uid == uid and current.st_gid == gid, "identity_change_requires_root")
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _copy_exact_file(source: Path, destination: Path, row: Mapping[str, object]) -> None:
    source_descriptor = os.open(
        source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    )
    destination_descriptor = -1
    try:
        before = os.fstat(source_descriptor)
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and before.st_size == row["size"]
            and before.st_mtime_ns == row["mtime_ns"]
            and stat.S_IMODE(before.st_mode) == row["mode"]
            and before.st_uid == row["uid"]
            and before.st_gid == row["gid"],
            "state_copy_source_drifted",
        )
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            int(row["mode"]),
        )
        digest = sha256()
        total = 0
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            offset = 0
            while offset < len(chunk):
                offset += os.write(destination_descriptor, chunk[offset:])
        os.fsync(destination_descriptor)
        if os.geteuid() == 0:
            os.fchown(destination_descriptor, int(row["uid"]), int(row["gid"]))
        else:
            created = os.fstat(destination_descriptor)
            require(
                created.st_uid == row["uid"] and created.st_gid == row["gid"],
                "identity_change_requires_root",
            )
        os.fchmod(destination_descriptor, int(row["mode"]))
        after = os.fstat(source_descriptor)
        require(
            total == row["size"]
            and digest.hexdigest() == row["sha256"]
            and before.st_size == after.st_size
            and before.st_mtime_ns == after.st_mtime_ns
            and before.st_ino == after.st_ino
            and before.st_dev == after.st_dev,
            "state_copy_source_drifted",
        )
    finally:
        os.close(source_descriptor)
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
    os.utime(
        destination,
        ns=(int(row["mtime_ns"]), int(row["mtime_ns"])),
        follow_symlinks=False,
    )


def backup_opaque_state(
    *,
    source: Path,
    backup: Path,
    expected: Mapping[str, object],
    expected_uid: int,
    expected_gid: int,
) -> dict[str, object]:
    require(
        not backup.exists() and not backup.is_symlink(), "state_backup_preexisting"
    )
    require(
        describe_opaque_state(
            source, expected_uid=expected_uid, expected_gid=expected_gid
        )
        == expected,
        "state_preflight_drifted",
    )
    backup.mkdir(mode=0o700)
    data = backup / "data"
    data.mkdir(mode=0o700)
    _set_identity(data, uid=expected_uid, gid=expected_gid)
    rows = expected.get("files")
    require(isinstance(rows, list), "state_descriptor_rejected")
    for row in rows:
        require(isinstance(row, dict), "state_descriptor_rejected")
        _copy_exact_file(source / str(row["name"]), data / str(row["name"]), row)
    require(
        describe_opaque_state(
            source, expected_uid=expected_uid, expected_gid=expected_gid
        )
        == expected,
        "state_backup_source_drifted",
    )
    require(
        describe_opaque_state(data, expected_uid=expected_uid, expected_gid=expected_gid)
        == expected,
        "state_backup_readback_rejected",
    )
    _exclusive_write(backup / "STATE.json", canonical(expected), mode=0o600)
    _fsync_directory(data)
    _fsync_directory(backup)
    return dict(expected)


def validate_opaque_backup(
    *,
    backup: Path,
    expected: Mapping[str, object],
    expected_uid: int,
    expected_gid: int,
) -> None:
    manifest = _load_json(backup / "STATE.json", code="state_backup_manifest_rejected")
    require(manifest == expected, "state_backup_manifest_rejected")
    require(
        describe_opaque_state(
            backup / "data", expected_uid=expected_uid, expected_gid=expected_gid
        )
        == expected,
        "state_backup_readback_rejected",
    )
    observed = sorted(
        path.relative_to(backup).as_posix()
        for path in backup.rglob("*")
    )
    require(
        observed
        == ["STATE.json", "data", *[f"data/{name}" for name in STATE_FILES]],
        "state_backup_inventory_rejected",
    )


def restore_opaque_state(
    *,
    target: Path,
    backup: Path,
    expected: Mapping[str, object],
    expected_uid: int,
    expected_gid: int,
    plan_digest: str,
) -> None:
    require(HEX64.fullmatch(plan_digest) is not None, "plan_digest_rejected")
    validate_opaque_backup(
        backup=backup,
        expected=expected,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    stage = target.parent / f".{target.name}.restore-{plan_digest[:16]}"
    displaced = backup / "displaced-state-tree"
    if target.exists() and not target.is_symlink():
        try:
            if (
                describe_opaque_state(
                    target, expected_uid=expected_uid, expected_gid=expected_gid
                )
                == expected
            ):
                return
        except UpgradeRejected:
            raise
        require(
            not stage.exists()
            and not stage.is_symlink()
            and not displaced.exists()
            and not displaced.is_symlink(),
            "state_restore_artifact_preexisting",
        )
        current = describe_opaque_state(
            target, expected_uid=expected_uid, expected_gid=expected_gid
        )
        backup_opaque_state(
            source=target,
            backup=backup / "displaced-copy",
            expected=current,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        backup_opaque_state(
            source=backup / "data",
            backup=stage,
            expected=expected,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        staged_data = stage / "data"
        require(
            target.parent.stat().st_dev == backup.stat().st_dev,
            "state_restore_filesystem_rejected",
        )
        os.replace(target, displaced)
        os.replace(staged_data, target)
        _fsync_directory(target.parent)
    elif not target.exists() and displaced.exists() and stage.exists():
        staged_data = stage / "data"
        require(staged_data.is_dir() and not staged_data.is_symlink(), "state_restore_stage_rejected")
        os.replace(staged_data, target)
        _fsync_directory(target.parent)
    else:
        raise UpgradeRejected("state_restore_prestate_rejected")
    require(
        describe_opaque_state(
            target, expected_uid=expected_uid, expected_gid=expected_gid
        )
        == expected,
        "state_restore_readback_rejected",
    )


def _expected_public_hashes() -> dict[Path, str]:
    return {
        SELECTOR_JSON: PREDECESSOR_SELECTOR_SHA256,
        SELECTOR_ENV: PREDECESSOR_SELECTOR_ENV_SHA256,
        UNIT_ROOT / SERVICE: SERVICE_UNIT_SHA256,
        UNIT_ROOT / SOCKET: SOCKET_UNIT_SHA256,
    }


def _validate_predecessor_public(root: Path) -> dict[str, dict[str, object]]:
    projections: dict[str, dict[str, object]] = {}
    for absolute, expected_digest in _expected_public_hashes().items():
        path = _rooted(root, absolute)
        projection = _file_projection(path)
        require(projection["sha256"] == expected_digest, "public_prestate_rejected")
        if root == Path("/"):
            require(
                projection["uid"] == 0
                and projection["gid"] == 0
                and projection["mode"]
                == (0o600 if absolute in {SELECTOR_JSON, SELECTOR_ENV} else 0o644),
                "public_prestate_permission_rejected",
            )
        projections[str(absolute)] = projection
    selector = _load_json(
        _rooted(root, SELECTOR_JSON), code="predecessor_selector_rejected"
    )
    require(
        selector
        == {
            "core_commit": PREDECESSOR_CORE_COMMIT,
            "deploy_commit": PREDECESSOR_DEPLOY_COMMIT,
            "gateway_client_sha256": PREDECESSOR_CLIENT_SHA256,
            "gateway_manifest_digest": ACTIVE_GATEWAY_MANIFEST_DIGEST,
            "plan_digest": PREDECESSOR_PLAN_DIGEST,
            "plugin_digest": ACTIVE_PLUGIN_DIGEST,
            "release_digest": PREDECESSOR_RELEASE_DIGEST,
            "release_path": str(RELEASE_ROOT / PREDECESSOR_RELEASE_DIGEST),
            "schema": SELECTOR_SCHEMA,
        },
        "predecessor_selector_rejected",
    )
    return projections


def _identity(root: Path, synthetic_identity: tuple[int, int, int] | None) -> tuple[int, int, int]:
    if synthetic_identity is not None:
        require(root != Path("/"), "synthetic_identity_rejected")
        uid, gid, telegram_uid = synthetic_identity
        require(min(uid, gid, telegram_uid) >= 0, "synthetic_identity_rejected")
        return uid, gid, telegram_uid
    require(root == Path("/"), "synthetic_identity_required")
    service = pwd.getpwnam("myuna_active_temporal")
    telegram = pwd.getpwnam("myuna-gateway-telegram")
    return service.pw_uid, service.pw_gid, telegram.pw_uid


def _capture_unit_state() -> dict[str, str]:
    def query(arguments: Sequence[str]) -> str:
        try:
            result = subprocess.run(
                list(arguments),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
                env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise UpgradeRejected("unit_state_rejected") from exc
        require(len(result.stdout) <= 4096, "unit_state_rejected")
        return result.stdout.decode("ascii", "strict").strip()

    return {
        "service_active": query(["/usr/bin/systemctl", "is-active", SERVICE]),
        "socket_active": query(["/usr/bin/systemctl", "is-active", SOCKET]),
        "socket_enabled": query(["/usr/bin/systemctl", "is-enabled", SOCKET]),
    }


def _validate_unit_state(value: Mapping[str, object]) -> dict[str, str]:
    expected = {
        "service_active": "active",
        "socket_active": "active",
        "socket_enabled": "enabled",
    }
    require(dict(value) == expected, "unit_state_rejected")
    return expected


@dataclass(frozen=True, slots=True)
class UpgradePlan:
    payload: dict[str, object]

    @property
    def digest(self) -> str:
        return digest_bytes(canonical(self.payload))

    def as_payload(self) -> dict[str, object]:
        return {"plan_digest": self.digest, "schema": PLAN_SCHEMA, **self.payload}


def prepare_plan(
    *,
    predecessor_release: Path,
    target_release: Path,
    active_gateway_runtime: Path,
    root: Path = Path("/"),
    synthetic_identity: tuple[int, int, int] | None = None,
    unit_state: Mapping[str, object] | None = None,
) -> UpgradePlan:
    validate_predecessor_release(predecessor_release)
    target_manifest, target_digest = validate_target_release(
        root=target_release,
        predecessor_release=predecessor_release,
    )
    gateway = validate_active_gateway_runtime(active_gateway_runtime)
    public = _validate_predecessor_public(root)
    if unit_state is None:
        require(root == Path("/"), "synthetic_unit_state_required")
        selected_unit_state = _validate_unit_state(_capture_unit_state())
    else:
        require(root != Path("/"), "synthetic_unit_state_rejected")
        selected_unit_state = _validate_unit_state(unit_state)
    service_uid, service_gid, telegram_uid = _identity(root, synthetic_identity)
    state = describe_opaque_state(
        _rooted(root, STATE_ROOT),
        expected_uid=service_uid,
        expected_gid=service_gid,
    )
    target = _rooted(root, RELEASE_ROOT / target_digest)
    require(
        not target.exists() and not target.is_symlink(), "target_release_preexisting"
    )
    compatibility = target_manifest["upgrade_compatibility"]
    assert isinstance(compatibility, dict)
    payload: dict[str, object] = {
        "active_gateway_runtime": gateway,
        "allowed_mutation_paths": [
            str(RELEASE_ROOT / target_digest),
            str(SELECTOR_JSON),
            str(SELECTOR_ENV),
            str(UNIT_ROOT / SERVICE),
            str(UNIT_ROOT / SOCKET),
            str(STATE_ROOT),
            str(EVIDENCE_ROOT),
        ],
        "compatibility_digest": digest_bytes(canonical(compatibility)),
        "forbidden_program_mutations": [
            "P01",
            "P07",
            "P09",
            "P10",
            "P15",
            "P16",
            "generation13",
            "owner_profile",
            "session_history",
        ],
        "identity": {
            "service_gid": service_gid,
            "service_uid": service_uid,
            "telegram_uid": telegram_uid,
        },
        "predecessor": {
            "core_commit": PREDECESSOR_CORE_COMMIT,
            "deploy_commit": PREDECESSOR_DEPLOY_COMMIT,
            "release_digest": PREDECESSOR_RELEASE_DIGEST,
            "release_path": str(predecessor_release.resolve()),
        },
        "public_prestate": public,
        "state_prestate": state,
        "target": {
            "core_commit": target_manifest["core_commit"],
            "deploy_commit": target_manifest["deploy_commit"],
            "release_digest": target_digest,
            "release_source": str(target_release.resolve()),
            "release_target": str(RELEASE_ROOT / target_digest),
        },
        "unit_prestate": selected_unit_state,
    }
    return UpgradePlan(payload)


def validate_plan(payload: Mapping[str, object]) -> dict[str, object]:
    raw = dict(payload)
    plan_digest = raw.pop("plan_digest", None)
    require(raw.pop("schema", None) == PLAN_SCHEMA, "plan_schema_rejected")
    require(
        HEX64.fullmatch(str(plan_digest)) is not None
        and plan_digest == digest_bytes(canonical(raw)),
        "plan_digest_rejected",
    )
    require(
        set(raw)
        == {
            "active_gateway_runtime",
            "allowed_mutation_paths",
            "compatibility_digest",
            "forbidden_program_mutations",
            "identity",
            "predecessor",
            "public_prestate",
            "state_prestate",
            "target",
            "unit_prestate",
        },
        "plan_fields_rejected",
    )
    require(
        raw.get("forbidden_program_mutations")
        == [
            "P01",
            "P07",
            "P09",
            "P10",
            "P15",
            "P16",
            "generation13",
            "owner_profile",
            "session_history",
        ],
        "plan_scope_rejected",
    )
    target = raw.get("target")
    predecessor = raw.get("predecessor")
    identity = raw.get("identity")
    gateway = raw.get("active_gateway_runtime")
    require(
        isinstance(target, dict)
        and isinstance(predecessor, dict)
        and isinstance(identity, dict)
        and isinstance(gateway, dict)
        and set(predecessor)
        == {"core_commit", "deploy_commit", "release_digest", "release_path"}
        and set(target)
        == {
            "core_commit",
            "deploy_commit",
            "release_digest",
            "release_source",
            "release_target",
        }
        and set(identity) == {"service_uid", "service_gid", "telegram_uid"}
        and set(gateway)
        == {"client_contract", "manifest_digest", "release_digest", "release_path"}
        and predecessor.get("release_digest") == PREDECESSOR_RELEASE_DIGEST
        and predecessor.get("core_commit") == PREDECESSOR_CORE_COMMIT
        and predecessor.get("deploy_commit") == PREDECESSOR_DEPLOY_COMMIT
        and predecessor.get("release_path")
        == str(RELEASE_ROOT / PREDECESSOR_RELEASE_DIGEST)
        and target.get("core_commit") == TARGET_CORE_COMMIT
        and SAFE_COMMIT.fullmatch(str(target.get("deploy_commit"))) is not None
        and HEX64.fullmatch(str(target.get("release_digest"))) is not None
        and target.get("release_target")
        == str(RELEASE_ROOT / str(target.get("release_digest")))
        and Path(str(target.get("release_source"))).is_absolute()
        and Path(str(target.get("release_source"))).name
        == target.get("release_digest")
        and all(
            type(identity.get(key)) is int and int(identity[key]) >= 0
            for key in ("service_uid", "service_gid", "telegram_uid")
        )
        and gateway.get("manifest_digest") == ACTIVE_GATEWAY_MANIFEST_DIGEST
        and gateway.get("release_digest") == ACTIVE_GATEWAY_RELEASE_DIGEST
        and gateway.get("release_path")
        == str(GATEWAY_RELEASE_ROOT / ACTIVE_GATEWAY_RELEASE_DIGEST)
        and isinstance(gateway.get("client_contract"), dict)
        and set(gateway["client_contract"])
        == {"operations", "schema", "sha256", "source_path"}
        and gateway["client_contract"].get("sha256") == PREDECESSOR_CLIENT_SHA256
        and gateway["client_contract"].get("operations") == list(LEGACY_OPERATIONS)
        and gateway["client_contract"].get("schema") == PROTOCOL_SCHEMA
        and gateway["client_contract"].get("source_path") == CLIENT_PATH.as_posix()
        and HEX64.fullmatch(str(raw.get("compatibility_digest"))) is not None,
        "plan_contract_rejected",
    )
    expected_allowed = [
        str(RELEASE_ROOT / str(target["release_digest"])),
        str(SELECTOR_JSON),
        str(SELECTOR_ENV),
        str(UNIT_ROOT / SERVICE),
        str(UNIT_ROOT / SOCKET),
        str(STATE_ROOT),
        str(EVIDENCE_ROOT),
    ]
    require(
        raw.get("allowed_mutation_paths") == expected_allowed,
        "plan_allowed_paths_rejected",
    )
    public = raw.get("public_prestate")
    expected_public = _expected_public_hashes()
    require(
        isinstance(public, dict)
        and set(public) == {str(path) for path in expected_public},
        "plan_public_prestate_rejected",
    )
    for absolute, expected_digest in expected_public.items():
        projection = public[str(absolute)]
        require(
            isinstance(projection, dict)
            and set(projection) == {"gid", "mode", "sha256", "size", "uid"}
            and projection.get("sha256") == expected_digest
            and projection.get("mode")
            == (0o600 if absolute in {SELECTOR_JSON, SELECTOR_ENV} else 0o644)
            and type(projection.get("size")) is int
            and int(projection["size"]) > 0
            and type(projection.get("uid")) is int
            and type(projection.get("gid")) is int,
            "plan_public_prestate_rejected",
        )
    state = raw.get("state_prestate")
    require(
        isinstance(state, dict)
        and set(state) == {"files", "root", "schema"}
        and state.get("schema") == STATE_SCHEMA
        and isinstance(state.get("root"), dict)
        and state["root"]
        == {
            "gid": identity["service_gid"],
            "mode": 0o700,
            "uid": identity["service_uid"],
        }
        and isinstance(state.get("files"), list)
        and len(state["files"]) == len(STATE_FILES),
        "plan_state_prestate_rejected",
    )
    for name, row in zip(STATE_FILES, state["files"], strict=True):
        require(
            isinstance(row, dict)
            and set(row)
            == {"gid", "mode", "mtime_ns", "name", "sha256", "size", "uid"}
            and row.get("name") == name
            and row.get("mode") == 0o600
            and row.get("uid") == identity["service_uid"]
            and row.get("gid") == identity["service_gid"]
            and type(row.get("mtime_ns")) is int
            and int(row["mtime_ns"]) >= 0
            and type(row.get("size")) is int
            and 0 < int(row["size"]) <= MAX_STATE_FILE_BYTES
            and HEX64.fullmatch(str(row.get("sha256"))) is not None,
            "plan_state_prestate_rejected",
        )
    require(
        raw.get("unit_prestate")
        == {
            "service_active": "active",
            "socket_active": "active",
            "socket_enabled": "enabled",
        },
        "plan_unit_prestate_rejected",
    )
    return {"plan_digest": plan_digest, "schema": PLAN_SCHEMA, **raw}


_STAGES = (
    "prepared",
    "public_backup_verified",
    "stop_started",
    "services_stopped",
    "pre_target_state_preserved",
    "state_backup_verified",
    "release_installed",
    "selector_applied",
    "target_started",
    "target_verified",
    "rollback_started",
    "state_restored",
    "public_restored",
    "predecessor_started",
    "rolled_back",
    "rollback_failed",
)


def _journal(plan: Mapping[str, object], *, stage: str, events: list[str]) -> dict[str, object]:
    require(stage in _STAGES and all(item in _STAGES for item in events), "journal_rejected")
    return {
        "attempts": 1,
        "events": list(events),
        "model_called": False,
        "other_program_mutated": False,
        "plan_digest": plan["plan_digest"],
        "private_content_parsed": False,
        "schema": JOURNAL_SCHEMA,
        "stage": stage,
    }


def _write_journal(path: Path, payload: Mapping[str, object]) -> None:
    require(payload.get("schema") == JOURNAL_SCHEMA, "journal_rejected")
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    _atomic_write(path, canonical(payload), mode=0o600, uid=os.geteuid(), gid=os.getegid())


def _load_journal(path: Path, plan: Mapping[str, object]) -> dict[str, object]:
    payload = _load_json(path, code="journal_rejected")
    require(
        set(payload)
        == {
            "attempts",
            "events",
            "model_called",
            "other_program_mutated",
            "plan_digest",
            "private_content_parsed",
            "schema",
            "stage",
        }
        and payload.get("schema") == JOURNAL_SCHEMA
        and payload.get("plan_digest") == plan["plan_digest"]
        and payload.get("attempts") == 1
        and payload.get("private_content_parsed") is False
        and payload.get("model_called") is False
        and payload.get("other_program_mutated") is False
        and payload.get("stage") in _STAGES
        and isinstance(payload.get("events"), list)
        and payload.get("events")[:1] == ["prepared"]
        and payload.get("events")[-1:] == [payload.get("stage")]
        and len(payload.get("events")) == len(set(payload.get("events")))
        and all(item in _STAGES for item in payload.get("events")),
        "journal_rejected",
    )
    return payload


def _validate_evidence_plan(
    evidence: Path,
    plan: Mapping[str, object],
    *,
    root: Path,
) -> None:
    require(
        evidence == _rooted(root, EVIDENCE_ROOT / str(plan["plan_digest"])),
        "evidence_path_rejected",
    )
    try:
        root_metadata = evidence.lstat()
        plan_path = evidence / "PLAN.json"
        plan_metadata = plan_path.lstat()
    except OSError as exc:
        raise UpgradeRejected("evidence_plan_rejected") from exc
    require(
        stat.S_ISDIR(root_metadata.st_mode)
        and not stat.S_ISLNK(root_metadata.st_mode)
        and stat.S_IMODE(root_metadata.st_mode) == 0o700
        and root_metadata.st_uid == os.geteuid()
        and root_metadata.st_gid == os.getegid()
        and stat.S_ISREG(plan_metadata.st_mode)
        and not stat.S_ISLNK(plan_metadata.st_mode)
        and stat.S_IMODE(plan_metadata.st_mode) == 0o600
        and plan_metadata.st_uid == os.geteuid()
        and plan_metadata.st_gid == os.getegid()
        and plan_metadata.st_size == len(canonical(plan))
        and plan_path.read_bytes() == canonical(plan),
        "evidence_plan_rejected",
    )


Runner = Callable[[list[str]], None]
StageHook = Callable[[str], None]


def _run(command: list[str]) -> None:
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
            env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise UpgradeRejected("command_failed") from exc
    require(completed.returncode == 0, "command_failed")


def _advance(
    *,
    journal_path: Path,
    plan: Mapping[str, object],
    journal: Mapping[str, object],
    stage: str,
    stage_hook: StageHook | None,
) -> dict[str, object]:
    events = list(journal["events"])
    events.append(stage)
    updated = _journal(plan, stage=stage, events=events)
    _write_journal(journal_path, updated)
    if stage_hook is not None:
        stage_hook(stage)
    return updated


def _copy_public_backup(root: Path, backup: Path, plan: Mapping[str, object]) -> None:
    require(not backup.exists() and not backup.is_symlink(), "public_backup_preexisting")
    backup.mkdir(mode=0o700)
    prestate = plan["public_prestate"]
    assert isinstance(prestate, dict)
    manifest: dict[str, object] = {}
    for text, projection in sorted(prestate.items()):
        assert isinstance(projection, dict)
        source = _rooted(root, Path(text))
        name = digest_bytes(text.encode("ascii"))
        destination = backup / name
        _exclusive_write(
            destination,
            source.read_bytes(),
            mode=int(projection["mode"]),
            uid=int(projection["uid"]),
            gid=int(projection["gid"]),
        )
        require(_file_projection(source) == projection, "public_prestate_drifted")
        manifest[text] = {**projection, "backup_name": name}
    _exclusive_write(backup / "PUBLIC.json", canonical(manifest), mode=0o600)
    for text, projection in sorted(prestate.items()):
        require(
            _file_projection(_rooted(root, Path(text))) == projection,
            "public_prestate_drifted",
        )
    _validate_public_backup(backup, plan)


def _validate_public_backup(backup: Path, plan: Mapping[str, object]) -> None:
    try:
        root_metadata = backup.lstat()
    except OSError as exc:
        raise UpgradeRejected("public_backup_rejected") from exc
    require(
        stat.S_ISDIR(root_metadata.st_mode)
        and not stat.S_ISLNK(root_metadata.st_mode)
        and stat.S_IMODE(root_metadata.st_mode) == 0o700
        and root_metadata.st_uid == os.geteuid()
        and root_metadata.st_gid == os.getegid(),
        "public_backup_rejected",
    )
    prestate = plan.get("public_prestate")
    require(isinstance(prestate, dict), "public_backup_rejected")
    expected_manifest = {
        text: {
            **projection,
            "backup_name": digest_bytes(text.encode("ascii")),
        }
        for text, projection in sorted(prestate.items())
        if isinstance(projection, dict)
    }
    require(
        len(expected_manifest) == len(prestate), "public_backup_rejected"
    )
    manifest_path = backup / "PUBLIC.json"
    manifest = _load_json(manifest_path, code="public_backup_rejected")
    require(manifest == expected_manifest, "public_backup_rejected")
    manifest_metadata = manifest_path.lstat()
    require(
        stat.S_ISREG(manifest_metadata.st_mode)
        and not stat.S_ISLNK(manifest_metadata.st_mode)
        and stat.S_IMODE(manifest_metadata.st_mode) == 0o600
        and manifest_metadata.st_uid == os.geteuid()
        and manifest_metadata.st_gid == os.getegid()
        and manifest_metadata.st_size == len(canonical(manifest)),
        "public_backup_rejected",
    )
    expected_files = {"PUBLIC.json"}
    for text, projection in sorted(prestate.items()):
        assert isinstance(projection, dict)
        name = digest_bytes(text.encode("ascii"))
        expected_files.add(name)
        path = backup / name
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise UpgradeRejected("public_backup_rejected") from exc
        require(
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_nlink == 1
            and stat.S_IMODE(metadata.st_mode) == projection["mode"]
            and metadata.st_uid == projection["uid"]
            and metadata.st_gid == projection["gid"]
            and metadata.st_size == projection["size"]
            and digest_file(path) == projection["sha256"],
            "public_backup_rejected",
        )
    observed: set[str] = set()
    for path in backup.rglob("*"):
        metadata = path.lstat()
        require(
            stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
            "public_backup_rejected",
        )
        observed.add(path.relative_to(backup).as_posix())
    require(observed == expected_files, "public_backup_rejected")


def _restore_public(root: Path, backup: Path, plan: Mapping[str, object]) -> None:
    _validate_public_backup(backup, plan)
    manifest = _load_json(backup / "PUBLIC.json", code="public_backup_rejected")
    prestate = plan["public_prestate"]
    require(isinstance(prestate, dict), "public_backup_rejected")
    for text, projection in sorted(prestate.items()):
        require(isinstance(projection, dict), "public_backup_rejected")
        row = manifest.get(text)
        require(isinstance(row, dict), "public_backup_rejected")
        name = row.get("backup_name")
        require(isinstance(name, str) and HEX64.fullmatch(name), "public_backup_rejected")
        source = backup / name
        require(
            source.is_file()
            and not source.is_symlink()
            and digest_file(source) == projection["sha256"],
            "public_backup_rejected",
        )
        destination = _rooted(root, Path(text))
        _atomic_write(
            destination,
            source.read_bytes(),
            mode=int(projection["mode"]),
            uid=int(projection["uid"]),
            gid=int(projection["gid"]),
        )
        require(_file_projection(destination) == projection, "public_restore_rejected")


def _install_release(
    root: Path,
    plan: Mapping[str, object],
    *,
    expected_core_commit: str = TARGET_CORE_COMMIT,
) -> Path:
    target = plan["target"]
    predecessor = plan["predecessor"]
    assert isinstance(target, dict) and isinstance(predecessor, dict)
    source = Path(str(target["release_source"]))
    destination = _rooted(root, Path(str(target["release_target"])))
    require(not destination.exists() and not destination.is_symlink(), "target_release_preexisting")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination, symlinks=False)
    for path in [destination, *destination.rglob("*")]:
        require(not path.is_symlink(), "target_release_symlink_rejected")
        os.chmod(
            path,
            (0o555 if path.is_dir() else 0o444)
            if root == Path("/")
            else (0o755 if path.is_dir() else 0o644),
        )
        if root == Path("/"):
            os.chown(path, 0, 0, follow_symlinks=False)
    manifest, observed = validate_target_release(
        root=destination,
        predecessor_release=Path(str(predecessor["release_path"])),
        expected_core_commit=expected_core_commit,
    )
    require(
        observed == target["release_digest"]
        and manifest["core_commit"] == target["core_commit"]
        and manifest["deploy_commit"] == target["deploy_commit"],
        "installed_release_rejected",
    )
    return destination


def _target_selector(plan: Mapping[str, object]) -> bytes:
    target = plan["target"]
    gateway = plan["active_gateway_runtime"]
    assert isinstance(target, dict) and isinstance(gateway, dict)
    return canonical(
        {
            "core_commit": target["core_commit"],
            "deploy_commit": target["deploy_commit"],
            "gateway_client_sha256": PREDECESSOR_CLIENT_SHA256,
            "gateway_manifest_digest": ACTIVE_GATEWAY_MANIFEST_DIGEST,
            "plan_digest": plan["plan_digest"],
            "plugin_digest": ACTIVE_PLUGIN_DIGEST,
            "release_digest": target["release_digest"],
            "release_path": target["release_target"],
            "schema": SELECTOR_SCHEMA,
        }
    ) + b"\n"


def _apply_target_public(root: Path, installed: Path, plan: Mapping[str, object]) -> None:
    identity = plan["identity"]
    assert isinstance(identity, dict)
    _atomic_write(
        _rooted(root, SELECTOR_JSON),
        _target_selector(plan),
        mode=0o600,
        uid=0 if root == Path("/") else os.geteuid(),
        gid=0 if root == Path("/") else os.getegid(),
    )
    environment = (
        f"PYTHONPATH={plan['target']['release_target']}/src\n"
        f"MYUNA_P08_STATE_ROOT={STATE_ROOT}\n"
        f"MYUNA_P08_SERVICE_UID={identity['service_uid']}\n"
        f"MYUNA_P08_TELEGRAM_UID={identity['telegram_uid']}\n"
    ).encode("ascii")
    _atomic_write(
        _rooted(root, SELECTOR_ENV),
        environment,
        mode=0o600,
        uid=0 if root == Path("/") else os.geteuid(),
        gid=0 if root == Path("/") else os.getegid(),
    )
    for relative, absolute in (
        (SERVICE_UNIT_PATH, UNIT_ROOT / SERVICE),
        (SOCKET_UNIT_PATH, UNIT_ROOT / SOCKET),
    ):
        _atomic_write(
            _rooted(root, absolute),
            (installed / relative).read_bytes(),
            mode=0o644,
            uid=0 if root == Path("/") else os.geteuid(),
            gid=0 if root == Path("/") else os.getegid(),
        )


def _verify_target(root: Path, plan: Mapping[str, object]) -> None:
    selector = _load_json(_rooted(root, SELECTOR_JSON), code="target_selector_rejected")
    require(
        canonical(selector) + b"\n" == _target_selector(plan),
        "target_selector_rejected",
    )
    require(
        digest_file(_rooted(root, UNIT_ROOT / SERVICE))
        == TARGET_SERVICE_UNIT_SHA256
        and digest_file(_rooted(root, UNIT_ROOT / SOCKET)) == SOCKET_UNIT_SHA256,
        "target_unit_rejected",
    )
    identity = plan["identity"]
    assert isinstance(identity, dict)
    require(
        describe_opaque_state(
            _rooted(root, STATE_ROOT),
            expected_uid=int(identity["service_uid"]),
            expected_gid=int(identity["service_gid"]),
        )
        == plan["state_prestate"],
        "target_state_changed",
    )


def _stop(runner: Runner) -> None:
    runner(["/usr/bin/systemctl", "stop", SOCKET])
    runner(["/usr/bin/systemctl", "stop", SERVICE])


def _start(runner: Runner) -> None:
    runner(["/usr/bin/systemctl", "daemon-reload"])
    runner(["/usr/bin/systemctl", "enable", "--now", SOCKET])
    runner(["/usr/bin/systemctl", "start", SERVICE])
    runner(["/usr/bin/systemctl", "is-active", "--quiet", SOCKET])
    runner(["/usr/bin/systemctl", "is-active", "--quiet", SERVICE])


def _rollback(
    *,
    root: Path,
    plan: Mapping[str, object],
    evidence: Path,
    journal: Mapping[str, object],
    runner: Runner,
    stage_hook: StageHook | None,
) -> dict[str, object]:
    journal_path = evidence / "JOURNAL.json"
    events = set(journal["events"])
    if "rollback_started" not in events:
        journal = _advance(
            journal_path=journal_path,
            plan=plan,
            journal=journal,
            stage="rollback_started",
            stage_hook=stage_hook,
        )
        events.add("rollback_started")
    _stop(runner)
    identity = plan["identity"]
    assert isinstance(identity, dict)
    state_root = _rooted(root, STATE_ROOT)
    if "state_restored" not in events:
        if (
            describe_opaque_state(
                state_root,
                expected_uid=int(identity["service_uid"]),
                expected_gid=int(identity["service_gid"]),
            )
            != plan["state_prestate"]
        ):
            restore_opaque_state(
                target=state_root,
                backup=evidence / "state",
                expected=plan["state_prestate"],
                expected_uid=int(identity["service_uid"]),
                expected_gid=int(identity["service_gid"]),
                plan_digest=str(plan["plan_digest"]),
            )
        journal = _advance(
            journal_path=journal_path,
            plan=plan,
            journal=journal,
            stage="state_restored",
            stage_hook=stage_hook,
        )
        events.add("state_restored")
    if "public_restored" not in events:
        _restore_public(root, evidence / "public", plan)
        journal = _advance(
            journal_path=journal_path,
            plan=plan,
            journal=journal,
            stage="public_restored",
            stage_hook=stage_hook,
        )
        events.add("public_restored")
    if "predecessor_started" not in events:
        _start(runner)
        journal = _advance(
            journal_path=journal_path,
            plan=plan,
            journal=journal,
            stage="predecessor_started",
            stage_hook=stage_hook,
        )
        events.add("predecessor_started")
    require(
        _validate_predecessor_public(root) == plan["public_prestate"],
        "rollback_public_rejected",
    )
    require(
        describe_opaque_state(
            _rooted(root, STATE_ROOT),
            expected_uid=int(identity["service_uid"]),
            expected_gid=int(identity["service_gid"]),
        )
        == plan["state_prestate"],
        "rollback_state_rejected",
    )
    return _advance(
        journal_path=journal_path,
        plan=plan,
        journal=journal,
        stage="rolled_back",
        stage_hook=stage_hook,
    )


def _converge_pre_target_failure(
    *,
    root: Path,
    plan: Mapping[str, object],
    evidence: Path,
    journal: Mapping[str, object],
    runner: Runner,
    stage_hook: StageHook | None,
) -> dict[str, object]:
    """Restore predecessor service semantics without selecting state backup bytes."""

    journal_path = evidence / "JOURNAL.json"
    events = set(journal["events"])
    if "pre_target_state_preserved" not in events:
        journal = _advance(
            journal_path=journal_path,
            plan=plan,
            journal=journal,
            stage="pre_target_state_preserved",
            stage_hook=stage_hook,
        )
        events.add("pre_target_state_preserved")
    _stop(runner)
    if "public_restored" not in events:
        _restore_public(root, evidence / "public", plan)
        journal = _advance(
            journal_path=journal_path,
            plan=plan,
            journal=journal,
            stage="public_restored",
            stage_hook=stage_hook,
        )
        events.add("public_restored")
    if "predecessor_started" not in events:
        _start(runner)
        journal = _advance(
            journal_path=journal_path,
            plan=plan,
            journal=journal,
            stage="predecessor_started",
            stage_hook=stage_hook,
        )
        events.add("predecessor_started")
    require(
        _validate_predecessor_public(root) == plan["public_prestate"],
        "pre_target_public_recovery_rejected",
    )
    return _advance(
        journal_path=journal_path,
        plan=plan,
        journal=journal,
        stage="rolled_back",
        stage_hook=stage_hook,
    )


def execute_plan(
    payload: Mapping[str, object],
    *,
    root: Path = Path("/"),
    synthetic_identity: tuple[int, int, int] | None = None,
    unit_state: Mapping[str, object] | None = None,
    runner: Runner = _run,
    stage_hook: StageHook | None = None,
) -> dict[str, object]:
    if root == Path("/"):
        require(os.geteuid() == 0, "root_required")
    plan = validate_plan(payload)
    predecessor = plan["predecessor"]
    target = plan["target"]
    gateway = plan["active_gateway_runtime"]
    assert isinstance(predecessor, dict) and isinstance(target, dict) and isinstance(gateway, dict)
    evidence = _rooted(root, EVIDENCE_ROOT / str(plan["plan_digest"]))
    require(
        not evidence.exists() and not evidence.is_symlink(), "activation_replayed"
    )
    fresh = prepare_plan(
        predecessor_release=Path(str(predecessor["release_path"])),
        target_release=Path(str(target["release_source"])),
        active_gateway_runtime=Path(str(gateway["release_path"])),
        root=root,
        synthetic_identity=synthetic_identity,
        unit_state=unit_state,
    ).as_payload()
    require(fresh == plan, "plan_drifted")
    evidence.parent.mkdir(parents=True, exist_ok=True)
    try:
        evidence.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise UpgradeRejected("activation_replayed") from exc
    _exclusive_write(evidence / "PLAN.json", canonical(plan), mode=0o600)
    _validate_evidence_plan(evidence, plan, root=root)
    journal = _journal(plan, stage="prepared", events=["prepared"])
    journal_path = evidence / "JOURNAL.json"
    _write_journal(journal_path, journal)
    if stage_hook is not None:
        stage_hook("prepared")
    try:
        _copy_public_backup(root, evidence / "public", plan)
        journal = _advance(
            journal_path=journal_path,
            plan=plan,
            journal=journal,
            stage="public_backup_verified",
            stage_hook=stage_hook,
        )
        journal = _advance(
            journal_path=journal_path,
            plan=plan,
            journal=journal,
            stage="stop_started",
            stage_hook=stage_hook,
        )
        _stop(runner)
        journal = _advance(
            journal_path=journal_path,
            plan=plan,
            journal=journal,
            stage="services_stopped",
            stage_hook=stage_hook,
        )
        identity = plan["identity"]
        assert isinstance(identity, dict)
        current_state = describe_opaque_state(
            _rooted(root, STATE_ROOT),
            expected_uid=int(identity["service_uid"]),
            expected_gid=int(identity["service_gid"]),
        )
        if current_state != plan["state_prestate"]:
            journal = _converge_pre_target_failure(
                root=root,
                plan=plan,
                evidence=evidence,
                journal=journal,
                runner=runner,
                stage_hook=stage_hook,
            )
            raise UpgradeRejected("pre_target_state_drift_preserved")
        backup_opaque_state(
            source=_rooted(root, STATE_ROOT),
            backup=evidence / "state",
            expected=plan["state_prestate"],
            expected_uid=int(identity["service_uid"]),
            expected_gid=int(identity["service_gid"]),
        )
        journal = _advance(
            journal_path=journal_path,
            plan=plan,
            journal=journal,
            stage="state_backup_verified",
            stage_hook=stage_hook,
        )
        installed = _install_release(root, plan)
        journal = _advance(
            journal_path=journal_path,
            plan=plan,
            journal=journal,
            stage="release_installed",
            stage_hook=stage_hook,
        )
        _apply_target_public(root, installed, plan)
        journal = _advance(
            journal_path=journal_path,
            plan=plan,
            journal=journal,
            stage="selector_applied",
            stage_hook=stage_hook,
        )
        _start(runner)
        journal = _advance(
            journal_path=journal_path,
            plan=plan,
            journal=journal,
            stage="target_started",
            stage_hook=stage_hook,
        )
        _verify_target(root, plan)
        journal = _advance(
            journal_path=journal_path,
            plan=plan,
            journal=journal,
            stage="target_verified",
            stage_hook=stage_hook,
        )
        receipt = {
            "channel_called": False,
            "model_called": False,
            "other_program_mutated": False,
            "plan_digest": plan["plan_digest"],
            "private_content_parsed": False,
            "release_digest": target["release_digest"],
            "schema": RECEIPT_SCHEMA,
            "state_bytes_preserved": True,
            "status": "target_verified",
        }
        _exclusive_write(evidence / "RECEIPT.json", canonical(receipt), mode=0o600)
        return receipt
    except Exception as activation_error:
        activation_code = (
            activation_error.code
            if isinstance(activation_error, UpgradeRejected)
            else "activation_failed"
        )
        events = set(journal["events"])
        if journal["stage"] == "rolled_back" and activation_code.startswith(
            "pre_target_state_"
        ):
            raise activation_error
        if not events.intersection(
            {
                "stop_started",
                "services_stopped",
                "state_backup_verified",
                "release_installed",
                "selector_applied",
                "target_started",
                "target_verified",
            }
        ):
            raise UpgradeRejected(
                "pre_attempt_failed", activation_failure_code=activation_code
            ) from activation_error
        if "state_backup_verified" not in events:
            try:
                journal = _converge_pre_target_failure(
                    root=root,
                    plan=plan,
                    evidence=evidence,
                    journal=journal,
                    runner=runner,
                    stage_hook=stage_hook,
                )
            except Exception as convergence_error:
                convergence_code = (
                    convergence_error.code
                    if isinstance(convergence_error, UpgradeRejected)
                    else "pre_target_convergence_failed"
                )
                raise UpgradeRejected(
                    "pre_target_convergence_failed",
                    activation_failure_code=activation_code,
                    rollback_failure_code=convergence_code,
                ) from convergence_error
            raise UpgradeRejected(
                "pre_target_failure_predecessor_restored",
                activation_failure_code=activation_code,
            ) from activation_error
        try:
            journal = _rollback(
                root=root,
                plan=plan,
                evidence=evidence,
                journal=journal,
                runner=runner,
                stage_hook=stage_hook,
            )
        except Exception as rollback_error:
            rollback_code = (
                rollback_error.code
                if isinstance(rollback_error, UpgradeRejected)
                else "rollback_failed"
            )
            try:
                _advance(
                    journal_path=journal_path,
                    plan=plan,
                    journal=journal,
                    stage="rollback_failed",
                    stage_hook=None,
                )
            except Exception:
                pass
            raise UpgradeRejected(
                "activation_rollback_failed",
                activation_failure_code=activation_code,
                rollback_failure_code=rollback_code,
            ) from rollback_error
        raise UpgradeRejected(
            "activation_failed_rollback_verified",
            activation_failure_code=activation_code,
        ) from activation_error


def recover_plan(
    payload: Mapping[str, object],
    *,
    root: Path = Path("/"),
    runner: Runner = _run,
    stage_hook: StageHook | None = None,
) -> dict[str, object]:
    if root == Path("/"):
        require(os.geteuid() == 0, "root_required")
    plan = validate_plan(payload)
    evidence = _rooted(root, EVIDENCE_ROOT / str(plan["plan_digest"]))
    _validate_evidence_plan(evidence, plan, root=root)
    journal = _load_journal(evidence / "JOURNAL.json", plan)
    stage = str(journal["stage"])
    require(stage != "target_verified", "completed_activation_recovery_rejected")
    require(stage != "rolled_back", "rollback_replayed")
    require(stage != "rollback_failed", "rollback_failed_hard_stop")
    if stage in {"prepared", "public_backup_verified"}:
        if stage == "public_backup_verified":
            _validate_public_backup(evidence / "public", plan)
        require(
            _validate_predecessor_public(root) == plan["public_prestate"],
            "pre_attempt_recovery_rejected",
        )
        return _advance(
            journal_path=evidence / "JOURNAL.json",
            plan=plan,
            journal=journal,
            stage="rolled_back",
            stage_hook=stage_hook,
        )
    events = set(journal["events"])
    if "state_backup_verified" not in events or "pre_target_state_preserved" in events:
        return _converge_pre_target_failure(
            root=root,
            plan=plan,
            evidence=evidence,
            journal=journal,
            runner=runner,
            stage_hook=stage_hook,
        )
    return _rollback(
        root=root,
        plan=plan,
        evidence=evidence,
        journal=journal,
        runner=runner,
        stage_hook=stage_hook,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    preflight = commands.add_parser("preflight")
    preflight.add_argument("--predecessor-release", type=Path, required=True)
    preflight.add_argument("--target-release", type=Path, required=True)
    preflight.add_argument("--active-gateway-runtime", type=Path, required=True)
    activate = commands.add_parser("activate")
    activate.add_argument("--plan", type=Path, required=True)
    recover = commands.add_parser("recover")
    recover.add_argument("--plan", type=Path, required=True)
    values = parser.parse_args()
    if values.command == "preflight":
        plan = prepare_plan(
            predecessor_release=values.predecessor_release.resolve(),
            target_release=values.target_release.resolve(),
            active_gateway_runtime=values.active_gateway_runtime.resolve(),
        )
        print(canonical(plan.as_payload()).decode("ascii"))
        return 0
    payload = _load_json(values.plan.resolve(), code="plan_json_rejected")
    result = execute_plan(payload) if values.command == "activate" else recover_plan(payload)
    print(canonical(result).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
