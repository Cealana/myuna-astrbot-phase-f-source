#!/usr/bin/env python3
"""Protected installed-target full-chain shadow for the P08 activation engine."""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import json
import os
import shutil
import socket
import stat
from typing import Mapping

import p08_activation_contract_v1 as contract_v1
import p08_activation_production_adapter_v1 as adapter_v1
import p08_activation_supervisor_v1 as supervisor_v1
import build_p08_active_temporal_release_v2 as legacy_builder


@dataclass(frozen=True)
class InstalledShadowScenario:
    continuity: str = "no_transition_required"
    transition: str = "committed"
    reconcile: str = "committed"
    acceptance: str = "accept"
    fault_role: str | None = None
    fault_kind: str | None = None


# This is the exact legacy unit shape represented by the synthetic predecessor.
# The target unit is deliberately not reused: rollback authority keeps the old
# service entrypoint while the target runtime requires the reviewed -P/-S seam.
_SYNTHETIC_PREDECESSOR_SERVICE_UNIT = b"""[Unit]
Description=Myuna active temporal context private worker v1
Requires=myuna-active-temporal-context-v1.socket
After=myuna-active-temporal-context-v1.socket

[Service]
Type=simple
User=myuna_active_temporal
Group=myuna_active_temporal
EnvironmentFile=/etc/myuna-active-temporal-context-v1/selector.env
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/usr/bin/python3 -B -m myuna_core.active_temporal_context.service
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX
ReadWritePaths=/var/lib/myuna-active-temporal-context-v1
UMask=0077
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
"""

_SYNTHETIC_PREDECESSOR_SOCKET_UNIT = b"""[Unit]
Description=Myuna active temporal context private socket v1

[Socket]
ListenStream=/run/myuna-active-temporal-context-v1/temporal.sock
SocketUser=myuna_active_temporal
SocketGroup=myuna-gateway-telegram
SocketMode=0660
RemoveOnStop=yes
Service=myuna-active-temporal-context-v1.service

[Install]
WantedBy=sockets.target
"""


def _rooted(root: Path, absolute: str) -> Path:
    return root / absolute.lstrip("/")


def _write(path: Path, raw: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)


def _copy_regular(source: Path, destination: Path) -> None:
    details = source.lstat()
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        raise RuntimeError("shadow_source_rejected")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(stat.S_IMODE(details.st_mode))


def _synthetic_predecessor_files(
    deploy_root: Path,
    *,
    core_commit: str,
    deploy_commit: str,
) -> dict[str, tuple[bytes, int]]:
    files: dict[str, tuple[bytes, int]] = {
        "scripts/p08_temporal_gateway_v1.py": (
            b"# synthetic immutable predecessor status helper\n",
            0o644,
        ),
        "src/p08_temporal_service_v1.py": (
            b"# synthetic immutable predecessor service\n",
            0o644,
        ),
        "systemd/myuna-active-temporal-context-v1.service": (
            _SYNTHETIC_PREDECESSOR_SERVICE_UNIT,
            0o644,
        ),
        "systemd/myuna-active-temporal-context-v1.socket": (
            _SYNTHETIC_PREDECESSOR_SOCKET_UNIT,
            0o644,
        ),
    }
    manifest_files = [
        {"path": path, "sha256": sha256(raw).hexdigest(), "size": len(raw)}
        for path, (raw, _) in sorted(files.items())
    ]
    status_helper = next(
        row
        for row in manifest_files
        if row["path"] == "scripts/p08_temporal_gateway_v1.py"
    )
    manifest = {
        "core_commit": core_commit,
        "deploy_commit": deploy_commit,
        "files": manifest_files,
        "gateway_client": {
            "runtime_path": "runtime/p08_temporal_gateway_v1.py",
            "sha256": status_helper["sha256"],
            "source_path": status_helper["path"],
        },
        "schema": contract_v1.RELEASE_SCHEMA,
        "upgrade_compatibility": {
            "active_gateway_client": {
                "operations": list(contract_v1.PREDECESSOR_RUNTIME_OPERATIONS),
                "schema": "myuna.active-temporal-context-protocol.v1",
                "sha256": "a" * 64,
                "source_path": status_helper["path"],
            },
            "legacy_operation_subset": list(
                contract_v1.PREDECESSOR_RUNTIME_OPERATIONS
            ),
            "predecessor_core_commit": core_commit,
            "predecessor_deploy_commit": deploy_commit,
            "predecessor_release_digest": "9" * 64,
            "schema": "myuna.p08-existing-state-compatibility.v1",
            "status_helper_client": {
                "operations": list(contract_v1.PREDECESSOR_STATUS_OPERATIONS),
                "schema": "myuna.active-temporal-context-protocol.v1",
                "sha256": status_helper["sha256"],
                "source_path": status_helper["path"],
            },
            "status_runtime": {
                "entrypoint": status_helper["path"],
                "files": [dict(status_helper)],
                "pythonpath": ["src", "scripts"],
                "schema": "myuna.p08-content-free-status-runtime-closure.v1",
            },
        },
    }
    files["manifest.json"] = (contract_v1.canonical_bytes(manifest), 0o644)
    return files


def synthetic_predecessor_binding(
    deploy_root: Path,
    *,
    release_identity: str,
    core_commit: str = "1" * 40,
    deploy_commit: str = "2" * 40,
) -> dict[str, object]:
    files = _synthetic_predecessor_files(
        deploy_root,
        core_commit=core_commit,
        deploy_commit=deploy_commit,
    )
    inventory = [
        {
            "path": path,
            "type": "file",
            "mode": mode,
            "uid": os.getuid(),
            "gid": os.getgid(),
            "size": len(raw),
            "sha256": sha256(raw).hexdigest(),
        }
        for path, (raw, mode) in sorted(files.items())
    ]
    directories = [
        {
            "path": ".",
            "type": "directory",
            "mode": 0o755,
            "uid": os.getuid(),
            "gid": os.getgid(),
            "nlink": 5,
        },
        {
            "path": "scripts",
            "type": "directory",
            "mode": 0o755,
            "uid": os.getuid(),
            "gid": os.getgid(),
            "nlink": 2,
        },
        {
            "path": "src",
            "type": "directory",
            "mode": 0o755,
            "uid": os.getuid(),
            "gid": os.getgid(),
            "nlink": 2,
        },
        {
            "path": "systemd",
            "type": "directory",
            "mode": 0o755,
            "uid": os.getuid(),
            "gid": os.getgid(),
            "nlink": 2,
        },
    ]
    manifest_raw = files["manifest.json"][0]
    manifest = json.loads(manifest_raw)
    return contract_v1.build_predecessor_binding(
        release_identity=release_identity,
        manifest_sha256=sha256(manifest_raw).hexdigest(),
        manifest_size=len(manifest_raw),
        manifest=manifest,
        inventory=inventory,
        directories=directories,
        unit_semantics=contract_v1.build_unit_semantics(
            files["systemd/myuna-active-temporal-context-v1.service"][0],
            files["systemd/myuna-active-temporal-context-v1.socket"][0],
        ),
    )


def _install_synthetic_predecessor(
    deploy_root: Path,
    destination: Path,
    *,
    core_commit: str,
    deploy_commit: str,
) -> None:
    destination.mkdir(parents=True, mode=0o755)
    for relative, (raw, mode) in _synthetic_predecessor_files(
        deploy_root,
        core_commit=core_commit,
        deploy_commit=deploy_commit,
    ).items():
        _write(destination / relative, raw, mode)
    for directory in (
        destination,
        destination / "scripts",
        destination / "src",
        destination / "systemd",
    ):
        directory.chmod(0o755)


def create_target_release(
    deploy_root: Path,
    target_root: Path,
    contract: Mapping[str, object],
    *,
    core_root: Path = Path("/srv/myuna/repos/core"),
) -> None:
    validated = contract_v1.validate_contract(contract)
    if target_root.exists() or target_root.is_symlink():
        raise RuntimeError("shadow_target_exists")
    target_root.mkdir(parents=True, mode=0o755)
    for relative in legacy_builder.CORE_FILES:
        _copy_regular(core_root / relative, target_root / relative)
    for relative_root in legacy_builder.CORE_DIRECTORIES:
        source_root = core_root / relative_root
        for source in sorted(source_root.rglob("*.py")):
            _copy_regular(source, target_root / source.relative_to(core_root))
    for relative in legacy_builder.DEPLOY_FILES:
        _copy_regular(deploy_root / relative, target_root / relative)
    _copy_regular(
        deploy_root / "scripts/p08_activation_synthetic_acceptance_v1.py",
        target_root / "scripts/p08_activation_synthetic_acceptance_v1.py",
    )
    for relative in (
        *contract_v1.REQUIRED_ENGINE_SOURCE_PATHS,
        "scripts/p08_activation_shadow_v1.py",
        "scripts/p08_activation_installed_shadow_v1.py",
    ):
        _copy_regular(deploy_root / relative, target_root / relative)
    host = validated["launcher"]["top_level_entry"]["host_launcher"]
    try:
        host_raw = base64.b64decode(
            b"".join(
                (target_root / str(host["base64_path"])).read_bytes().split()
            ),
            validate=True,
        )
    except (OSError, binascii.Error):
        raise RuntimeError("shadow_windows_entry_rejected") from None
    if (
        len(host_raw) != host["size"]
        or sha256(host_raw).hexdigest() != host["sha256"]
        or sha256(
            (target_root / str(host["source_path"])).read_bytes()
        ).hexdigest()
        != host["source_sha256"]
    ):
        raise RuntimeError("shadow_windows_entry_rejected")
    _write(target_root / str(host["artifact_path"]), host_raw, 0o555)
    _write(
        target_root / "contracts/P08_ACTIVATION_CONTRACT.json",
        contract_v1.canonical_bytes(validated),
        0o644,
    )
    _write(
        target_root / "contracts/P08_LEGACY_LINEAGE_INDEX.json",
        contract_v1.canonical_bytes(validated["lineage"]),
        0o644,
    )
    for path in (
        target_root,
        *sorted(item for item in target_root.rglob("*") if item.is_dir()),
    ):
        path.chmod(0o755)
    files = []
    for path in sorted(target_root.rglob("*")):
        details = path.lstat()
        if stat.S_ISDIR(details.st_mode) and not stat.S_ISLNK(details.st_mode):
            continue
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise RuntimeError("shadow_target_inventory_rejected")
        files.append(
            {
                "path": path.relative_to(target_root).as_posix(),
                "size": details.st_size,
                "sha256": sha256(path.read_bytes()).hexdigest(),
            }
        )
    manifest = {
        "activation_engine_contract": contract_v1.release_manifest_binding(validated),
        "core_commit": validated["engine_source"]["core_commit"],
        "current_selected_upgrade_contract": {"synthetic": True},
        "deploy_commit": validated["engine_source"]["deploy_commit"],
        "entrypoint": "p08_temporal_service_v1",
        "files": files,
        "formal_preflight_launcher_contract": {"synthetic": True},
        "forward_continuity_contract": {"synthetic": True},
        "gateway_client": {"synthetic": True},
        "gateway_status_runtime": {"synthetic": True},
        "legacy_activation_architecture_authoritative": False,
        "p07_single_nonce_integration": {"synthetic": True},
        "post_target_action_contract": {"synthetic": True},
        "protocol_contract": {"synthetic": True},
        "protocol_schema": "synthetic",
        "runtime_profile": "synthetic",
        "schema": contract_v1.RELEASE_SCHEMA,
        "service_contract": {"synthetic": True},
        "state_schema": "synthetic",
        "trusted_time_capability_contract": {"synthetic": True},
        "trusted_time_schema": "synthetic",
        "upgrade_compatibility": {"synthetic": True},
    }
    if set(manifest) != set(contract_v1.RELEASE_MANIFEST_KEYS):
        raise RuntimeError("shadow_target_manifest_rejected")
    _write(
        target_root / "manifest.json",
        contract_v1.canonical_bytes(manifest),
        0o644,
    )


def create_world(
    contract: Mapping[str, object],
    *,
    root: Path,
    target_source: Path,
    predecessor_identity: str,
    scenario: InstalledShadowScenario,
) -> dict[str, object]:
    if root.exists() or root.is_symlink():
        raise RuntimeError("shadow_root_exists")
    root.mkdir(mode=0o700)
    fixed = contract["production_adapter"]["fixed_paths"]
    predecessor = contract["compatibility"]["predecessor"]
    if predecessor["release_identity"] != predecessor_identity:
        raise RuntimeError("shadow_predecessor_rejected")
    release_root = _rooted(root, str(fixed["release_root"]))
    release_root.mkdir(parents=True, mode=0o755)
    _install_synthetic_predecessor(
        deploy_root=Path(contract["engine_source"]["deploy_root"]),
        destination=release_root / predecessor_identity,
        core_commit=str(predecessor["core_commit"]),
        deploy_commit=str(predecessor["deploy_commit"]),
    )
    _write(
        _rooted(root, str(fixed["synthetic_account_state"])),
        contract_v1.canonical_bytes(
            {
                "schema": contract_v1.ACCOUNT_PROJECTION_SCHEMA,
                **json.loads(
                    contract_v1.canonical_bytes(
                        contract["production_adapter"]["accounts"]
                    )
                ),
            }
        ),
        0o600,
    )
    selector = {
        "core_commit": predecessor["core_commit"],
        "deploy_commit": predecessor["deploy_commit"],
        "gateway_client_sha256": predecessor["public_binding"]["selector"]["gateway_client_sha256"],
        "gateway_manifest_digest": "4" * 64,
        "plan_digest": "5" * 64,
        "plugin_digest": "6" * 64,
        "release_digest": predecessor_identity,
        "release_path": f"{fixed['release_root']}/{predecessor_identity}",
        "schema": contract_v1.SELECTOR_SCHEMA,
    }
    _write(
        _rooted(root, str(fixed["selector"])),
        contract_v1.canonical_bytes(selector),
        0o600,
    )
    _write(
        _rooted(root, str(fixed["environment"])),
        (
            f"PYTHONPATH={fixed['release_root']}/{predecessor_identity}/src\n"
            f"MYUNA_P08_STATE_ROOT={fixed['state_root']}\n"
            f"MYUNA_P08_SERVICE_UID={contract['production_adapter']['accounts']['service']['uid']}\n"
            f"MYUNA_P08_TELEGRAM_UID={contract['production_adapter']['accounts']['gateway']['uid']}\n"
        ).encode("ascii"),
        0o600,
    )
    for role, relative in (
        ("service_unit", "systemd/myuna-active-temporal-context-v1.service"),
        ("socket_unit", "systemd/myuna-active-temporal-context-v1.socket"),
    ):
        _copy_regular(
            release_root / predecessor_identity / relative,
            _rooted(root, str(fixed[role])),
        )
        _rooted(root, str(fixed[role])).chmod(0o644)
    state = _rooted(root, str(fixed["state_root"]))
    state.mkdir(parents=True, mode=0o700)
    _write(state / "temporal-context.sqlite3", b"SYNTHETIC_TEMPORAL_STATE_V1\n", 0o600)
    _write(state / "trusted-time.sqlite3", b"SYNTHETIC_TRUSTED_TIME_STATE_V1\n", 0o600)
    _write(state / "synthetic-forward-history", b"not_committed\n", 0o600)
    _write(
        state / "synthetic-continuity.json",
        contract_v1.canonical_bytes(
            {
                "schema": "myuna.p08-activation-synthetic-continuity.v1",
                "assessment": scenario.continuity,
                "transition": scenario.transition,
                "reconcile": scenario.reconcile,
            }
        ),
        0o600,
    )
    _write(
        state / "synthetic-control.json",
        contract_v1.canonical_bytes(
            {
                "schema": "myuna.p08-activation-synthetic-control.v1",
                "acceptance": scenario.acceptance,
                "fault_role": scenario.fault_role,
                "fault_kind": scenario.fault_kind,
            }
        ),
        0o600,
    )
    service_account = contract["production_adapter"]["accounts"]["service"]
    for owned in (state, *sorted(state.iterdir())):
        os.chown(owned, int(service_account["uid"]), int(service_account["gid"]))
    socket_path = _rooted(root, str(fixed["socket_endpoint"]))
    socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        endpoint.bind(str(socket_path))
    finally:
        endpoint.close()
    os.chmod(
        socket_path,
        int(str(predecessor["unit_runtime"]["socket"]["socket_mode"]), 8),
    )
    os.chown(
        socket_path,
        int(contract["production_adapter"]["accounts"]["service"]["uid"]),
        int(contract["production_adapter"]["accounts"]["gateway"]["gid"]),
    )
    socket_details = socket_path.lstat()
    _write(
        _rooted(root, str(fixed["synthetic_unit_state"])),
        contract_v1.canonical_bytes(
            {
                "effective": {
                    "schema": contract_v1.UNIT_RUNTIME_SCHEMA,
                    "service": {
                        **dict(predecessor["unit_runtime"]["service"]),
                        "active_state": "active",
                        "sub_state": "running",
                    },
                    "socket": {
                        **dict(predecessor["unit_runtime"]["socket"]),
                        "active_state": "active",
                        "sub_state": "running",
                    },
                },
                "coupled_state": "service_running",
                "schema": contract_v1.UNIT_STATE_SCHEMA,
                "service_active": True,
                "service_active_enter_monotonic_usec": 1,
                "service_enabled": False,
                "service_main_pid": 1001,
                "service_process": {
                    **dict(predecessor["unit_runtime"]["service"]["process_identity"]),
                    "pid": 1001,
                    "start_ticks": 1,
                },
                "service_restarts": 0,
                "socket_active": True,
                "socket_active_enter_monotonic_usec": 1,
                "socket_enabled": True,
                "socket_inode": {
                    "schema": contract_v1.SOCKET_INODE_SCHEMA,
                    "path": str(fixed["socket_endpoint"]),
                    "type": "socket",
                    "mode": stat.S_IMODE(socket_details.st_mode),
                    "uid": socket_details.st_uid,
                    "gid": socket_details.st_gid,
                    "nlink": socket_details.st_nlink,
                },
                "socket_n_accepted": 0,
                "socket_n_connections": 0,
            }
        ),
        0o600,
    )
    contract_path = target_source / "contracts/P08_ACTIVATION_CONTRACT.json"
    execution = adapter_v1.construct_execution(
        contract,
        root=root,
        backend="synthetic",
        target_source_path=target_source,
        acceptance_scope_digest="7" * 64,
    )
    prestate = contract_v1.digest_value(
        {
            "accounts": execution["account_projection"],
            "opaque": execution["opaque_prestate"],
            "predecessor_release": execution["predecessor_release"],
            "public": execution["public_prestate"],
            "units": execution["unit_prestate"],
        }
    )
    plan = contract_v1.build_plan(
        contract,
        sequence_identity="8" * 64,
        invocation_nonce="9" * 64,
        prestate_identity=prestate,
        predecessor_identity=predecessor_identity,
        target_identity=target_source.name,
        execution=execution,
    )
    sequence = adapter_v1.sequence_root(contract, plan)
    sequence.mkdir(parents=True, mode=0o700)
    os.chmod(sequence.parent.parent, 0o700)
    os.chmod(sequence.parent, 0o700)
    os.chmod(sequence, 0o700)
    plan_path = sequence / "PLAN.json"
    _write(plan_path, contract_v1.canonical_bytes(plan), 0o600)
    return {"contract_path": contract_path, "plan": plan, "plan_path": plan_path}


def run_installed_shadow(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    contract_path: Path,
    plan_path: Path,
    deploy_root: Path,
) -> dict[str, object]:
    if deploy_root != Path(str(contract["engine_source"]["deploy_root"])):
        raise RuntimeError("shadow_source_root_rejected")
    strategy = adapter_v1._strategy_root(contract, plan["execution"])
    claim_path = strategy / "STRATEGY.LAUNCH.CLAIM.json"
    if not claim_path.exists():
        strategy.mkdir(parents=True, exist_ok=True, mode=0o700)
        strategy.chmod(0o700)
        claim = contract_v1.build_strategy_launch_claim(
            contract,
            entry_nonce=str(plan["sequence_identity"]),
            root=str(plan["execution"]["root"]),
            backend=str(plan["execution"]["backend"]),
            target_source_path=str(plan["execution"]["target_source_path"]),
            target_inventory_digest=str(
                plan["execution"]["target_inventory_digest"]
            ),
            target_directories_digest=str(
                plan["execution"]["target_directories_digest"]
            ),
            acceptance_scope_digest=str(
                plan["execution"]["acceptance_scope_digest"]
            ),
            prestate_identity=str(plan["prestate_identity"]),
        )
        _write(claim_path, contract_v1.canonical_bytes(claim), 0o600)
    terminal = supervisor_v1.execute_or_recover(
        contract,
        plan,
        contract_path=contract_path,
        plan_path=plan_path,
        deploy_root=Path(str(plan["execution"]["target_source_path"])),
    )
    body = {
        "schema": "myuna.p08-activation-installed-shadow-result.v1",
        "contract_digest": contract["contract_digest"],
        "plan_digest": plan["plan_digest"],
        "terminal_status": terminal["terminal_status"],
        "last_role": terminal["last_role"],
        "action_claimed": terminal["action_claimed"],
        "product_mutated": terminal["product_mutated"],
        "infrastructure_mutated": terminal["infrastructure_mutated"],
        "mutation_scope": terminal["mutation_scope"],
        "transition_state": terminal["transition_state"],
        "transition_committed": terminal["transition_committed"],
        "forward_state_possible": terminal["forward_state_possible"],
        "state_restore_scope": terminal["state_restore_scope"],
        "role_counts": terminal["role_counts"],
        "capture_count": terminal["capture_count"],
        "capture_chain_digest": terminal["capture_chain_digest"],
        "production_mutation": False,
        "raw_output_included": False,
    }
    return {**body, "shadow_digest": contract_v1.digest_value(body)}
