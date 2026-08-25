#!/usr/bin/env python3
"""Source-owned P08 repair/rollback contract after a completed target switch.

This module is intentionally inactive.  It validates one immutable completed
``target_verified`` lineage, keeps opaque state as authoritative bytes, and
defines two identity-separated, single-attempt actions for a later T2 gate.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
from typing import Callable, Mapping, Sequence

import p08_existing_state_upgrade_v1 as upgrade
import p08_temporal_gateway_v1 as temporal_gateway


REPAIR_PLAN_SCHEMA = "myuna.p08-post-target-repair-plan.v3"
ROLLBACK_PLAN_SCHEMA = "myuna.p08-post-target-rollback-plan.v3"
REPAIR_JOURNAL_SCHEMA = "myuna.p08-post-target-repair-journal.v3"
ROLLBACK_JOURNAL_SCHEMA = "myuna.p08-post-target-rollback-journal.v3"
REPAIR_LEDGER_SCHEMA = "myuna.p08-post-target-repair-ledger.v2"
ROLLBACK_LEDGER_SCHEMA = "myuna.p08-post-target-rollback-ledger.v2"
REPAIR_RECEIPT_SCHEMA = "myuna.p08-post-target-repair-receipt.v2"
ROLLBACK_RECEIPT_SCHEMA = "myuna.p08-post-target-rollback-receipt.v2"
INCIDENT_SCHEMA = "myuna.p08-post-target-incident.v1"
READINESS_SCHEMA = "myuna.p08-post-target-action-readiness.v1"
ACTION_STATE_BINDING_SCHEMA = "myuna.p08-post-target-action-state-binding.v1"
CONTENT_FREE_STATUS_SCHEMA = "myuna.active-temporal-content-free-status.v1"
CONTENT_FREE_STATUS_INVOCATION_NONCE_ENV = "MYUNA_P08_STATUS_INVOCATION_NONCE"
READY_UNIT_STATE = {
    "service_active": "active",
    "socket_active": "active",
    "socket_enabled": "enabled",
}

COMPLETED_PLAN_DIGEST = (
    "4cac67c3aeaed98e7254015399efb024444a25f5e804703f9e4234dde38e7eed"
)
COMPLETED_PLAN_SHA256 = (
    "efb4d085179b8c1b2ca7ec57d036ea52fb91a345fb9fa5d388f1c7c10393e740"
)
COMPLETED_JOURNAL_SHA256 = (
    "5bff53afce58c6a01f179f0a5385f072f43ab3ed798775785bcac350ac1e913b"
)
COMPLETED_RECEIPT_SHA256 = (
    "2190ab24f63a0f62aaa8bc571fc8cd44d97f66575444c7ed684da947aa0916de"
)
FAILED_ACCEPTANCE_RECEIPT_SHA256 = (
    "853a4ff7ed826439c77650691036dbfebb00bd3e759c696c514eba7c56044f9a"
)
FAILED_ACCEPTANCE_STATUS = "hard_stop_content_free_protocol_not_accepted"
FAILED_ACCEPTANCE_SEQUENCE_ID = (
    "e747c895c4ad09c9c9cb4d1ff48473288a61953d9d4a741a99623f266b4a2859"
)
FAILED_ACCEPTANCE_RECEIPT_PATH = (
    upgrade.EVIDENCE_ROOT
    / "superseding-formal-preflight-sequences-v1"
    / FAILED_ACCEPTANCE_SEQUENCE_ID
    / "POST_ACTIVATION_FAILURE.json"
)

COMPLETED_TARGET_RELEASE_DIGEST = (
    "cba8f788cf61aa5548eebe73e10578533fc5b3cdbff81463d0868741dd8eb5ff"
)
COMPLETED_TARGET_MANIFEST_SHA256 = (
    "20dbffba8374abcc170b91eb0136bcf26a16d6805a1afcfd841f769c494e648b"
)
COMPLETED_TARGET_CLIENT_SHA256 = (
    "32e615f8d7a4ce18f2d0e31021b14c984a31640b143b0da7ec7aa779a418f325"
)
COMPLETED_TARGET_SERVICE_UNIT_SHA256 = (
    "699662ffc743518be4a499c0598259ac686b17f531671c969a3de73311fd44f8"
)
COMPLETED_TARGET_SOCKET_UNIT_SHA256 = (
    "1dc226e5030388b36f1a9b08d1c4e49cb0c0d39489f1fbbaff2ab6e891a6df2a"
)
COMPLETED_TARGET_DEPLOY_COMMIT = "390f0a6455bddaa97b2c2116ec42e4f9e63ffbae"
COMPLETED_TARGET_SELECTOR_SHA256 = (
    "c7f49e7aa60d5e80d222cd2d2c138ee9856a5336c0f9e63d065fff276fb5d70d"
)
COMPLETED_TARGET_SELECTOR_ENV_SHA256 = (
    "e587e9f72b065c10686a6b25bf95db32c714d3c97e95292c6d8d1b0ab2587c1e"
)

COMPLETED_EVIDENCE_ROOT = upgrade.EVIDENCE_ROOT / COMPLETED_PLAN_DIGEST
POST_ACTION_EVIDENCE_ROOT = Path(
    "/var/lib/myuna-activation-backups/p08-post-target-action-v1"
)

_ACTIONS = frozenset({"repair", "rollback"})
_COMMON_STAGES = frozenset(
    {
        "prepared",
        "current_public_backed_up",
        "current_state_backed_up",
        "attempt_owned",
        "services_stopped",
        "release_installed",
        "public_applied",
        "target_started",
        "protocol_acceptance_called",
        "target_accepted",
        "predecessor_verified",
        "convergence_owned",
        "recovered_current_target",
        "convergence_failed",
    }
)
Runner = Callable[[Sequence[str]], None]
StageHook = Callable[[str], None]
AcceptanceRunner = Callable[[Path], Mapping[str, object]]


class PostTargetRejected(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        action_failure_code: str | None = None,
        convergence_failure_code: str | None = None,
        content_free_failure_projection: Mapping[str, object] | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.action_failure_code = action_failure_code
        self.convergence_failure_code = convergence_failure_code
        self.content_free_failure_projection = content_free_failure_projection


def require(condition: bool, code: str) -> None:
    if not condition:
        raise PostTargetRejected(code)


def canonical(payload: object) -> bytes:
    return json.dumps(
        payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def digest_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def _release_metadata_inventory(root: Path) -> list[dict[str, object]]:
    require(root.is_dir() and not root.is_symlink(), "repair_release_rejected")
    rows: list[dict[str, object]] = []
    for path in [root, *sorted(root.rglob("*"))]:
        metadata = path.lstat()
        require(not stat.S_ISLNK(metadata.st_mode), "repair_release_link_rejected")
        relative = "." if path == root else path.relative_to(root).as_posix()
        if stat.S_ISDIR(metadata.st_mode):
            rows.append(
                {
                    "gid": metadata.st_gid,
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "path": relative,
                    "type": "directory",
                    "uid": metadata.st_uid,
                }
            )
            continue
        require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_nlink == 1
            and "__pycache__" not in path.parts
            and path.suffix not in {".pyc", ".pyo"},
            "repair_release_inventory_rejected",
        )
        rows.append(
            {
                "gid": metadata.st_gid,
                "mode": stat.S_IMODE(metadata.st_mode),
                "nlink": metadata.st_nlink,
                "path": relative,
                "sha256": upgrade.digest_file(path),
                "size": metadata.st_size,
                "type": "file",
                "uid": metadata.st_uid,
            }
        )
    require(1 < len(rows) <= upgrade.MAX_RELEASE_FILES * 4, "repair_release_inventory_rejected")
    return rows


def _installed_inventory_from_source(
    rows: Sequence[Mapping[str, object]], *, live: bool
) -> list[dict[str, object]]:
    uid = 0 if live else os.geteuid()
    gid = 0 if live else os.getegid()
    result: list[dict[str, object]] = []
    for source in rows:
        row = dict(source)
        row["uid"] = uid
        row["gid"] = gid
        if row.get("type") == "directory":
            row["mode"] = 0o555 if live else 0o755
        else:
            row["mode"] = 0o444 if live else 0o644
        result.append(row)
    return result


def _validate_repair_release_contract(root: Path) -> tuple[dict[str, object], str, dict[str, object]]:
    manifest, release_digest = upgrade._validate_release_manifest(
        root, require_named_digest=True
    )
    require(manifest.get("core_commit") == upgrade.TARGET_CORE_COMMIT, "repair_release_core_rejected")
    controller_path = root / "scripts/p08_post_target_action_v1.py"
    controller_sha256 = upgrade.digest_file(controller_path)
    require(
        controller_sha256 == upgrade.digest_file(Path(__file__).resolve()),
        "repair_controller_identity_rejected",
    )
    contract = manifest.get("post_target_action_contract")
    require(
        contract
        == {
            "action_state_binding_schema": ACTION_STATE_BINDING_SCHEMA,
            "incident_max_actions": 1,
            "live_execute_implemented": True,
            "max_attempts_per_action_plan": 1,
            "readiness_schema": READINESS_SCHEMA,
            "repair_plan_schema": REPAIR_PLAN_SCHEMA,
            "rollback_plan_schema": ROLLBACK_PLAN_SCHEMA,
            "sha256": controller_sha256,
            "source_path": "scripts/p08_post_target_action_v1.py",
        },
        "repair_execute_contract_rejected",
    )
    rows = _release_metadata_inventory(root)
    identity = {
        "installed_inventory_sha256": digest_bytes(
            canonical(_installed_inventory_from_source(rows, live=True))
        ),
        "manifest_sha256": upgrade.digest_file(root / "manifest.json"),
        "post_target_action_sha256": controller_sha256,
        "source_inventory_sha256": digest_bytes(canonical(rows)),
    }
    return manifest, release_digest, identity


def validate_failed_acceptance_receipt(root: Path) -> dict[str, object]:
    path = _rooted(root, FAILED_ACCEPTANCE_RECEIPT_PATH)
    require(
        upgrade.digest_file(path) == FAILED_ACCEPTANCE_RECEIPT_SHA256,
        "failure_receipt_identity_rejected",
    )
    payload = _load_json(path, code="failure_receipt_rejected")
    require(
        payload.get("schema")
        == "myuna.p08-superseding-post-activation-acceptance-failure.v1"
        and payload.get("status") == FAILED_ACCEPTANCE_STATUS
        and payload.get("sequence_id") == FAILED_ACCEPTANCE_SEQUENCE_ID
        and payload.get("activation_calls") == 1
        and payload.get("protocol_acceptance_calls") == 1
        and payload.get("protocol_process_created") is True
        and payload.get("protocol_retry") is False
        and payload.get("rollback_executed") is False
        and payload.get("live_release_digest") == COMPLETED_TARGET_RELEASE_DIGEST
        and payload.get("opaque_state_exact") is True
        and payload.get("controller_status") == "target_verified"
        and payload.get("controller_receipt_sha256") == COMPLETED_RECEIPT_SHA256,
        "failure_receipt_rejected",
    )
    return {
        "path": str(FAILED_ACCEPTANCE_RECEIPT_PATH),
        "schema": payload["schema"],
        "sequence_id": FAILED_ACCEPTANCE_SEQUENCE_ID,
        "sha256": FAILED_ACCEPTANCE_RECEIPT_SHA256,
        "status": FAILED_ACCEPTANCE_STATUS,
    }


def _rooted(root: Path, absolute: Path) -> Path:
    return absolute if root == Path("/") else root / str(absolute).lstrip("/")


def _load_json(path: Path, *, code: str) -> dict[str, object]:
    try:
        metadata = path.lstat()
        require(
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and 0 < metadata.st_size <= upgrade.MAX_JSON_BYTES,
            code,
        )
        raw = path.read_bytes()
        require(len(raw) == metadata.st_size, code)
        value = json.loads(raw.decode("utf-8", "strict"))
    except PostTargetRejected:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PostTargetRejected(code) from exc
    require(isinstance(value, dict), code)
    return value


def _schemas(action: str) -> tuple[str, str, str, str]:
    require(action in _ACTIONS, "action_identity_rejected")
    if action == "repair":
        return (
            REPAIR_PLAN_SCHEMA,
            REPAIR_JOURNAL_SCHEMA,
            REPAIR_LEDGER_SCHEMA,
            REPAIR_RECEIPT_SCHEMA,
        )
    return (
        ROLLBACK_PLAN_SCHEMA,
        ROLLBACK_JOURNAL_SCHEMA,
        ROLLBACK_LEDGER_SCHEMA,
        ROLLBACK_RECEIPT_SCHEMA,
    )


def validate_completed_target_release(root: Path) -> dict[str, object]:
    manifest, release_digest = upgrade._validate_release_manifest(
        root, require_named_digest=True
    )
    require(
        release_digest == COMPLETED_TARGET_RELEASE_DIGEST
        and upgrade.digest_file(root / "manifest.json")
        == COMPLETED_TARGET_MANIFEST_SHA256
        and manifest.get("core_commit") == upgrade.TARGET_CORE_COMMIT
        and manifest.get("deploy_commit") == COMPLETED_TARGET_DEPLOY_COMMIT,
        "completed_target_release_rejected",
    )
    expected = {
        upgrade.CLIENT_PATH: COMPLETED_TARGET_CLIENT_SHA256,
        upgrade.PROTOCOL_PATH: upgrade.TARGET_PROTOCOL_SHA256,
        upgrade.SERVICE_PATH: upgrade.SERVICE_SHA256,
        upgrade.SERVICE_UNIT_PATH: COMPLETED_TARGET_SERVICE_UNIT_SHA256,
        upgrade.SOCKET_UNIT_PATH: COMPLETED_TARGET_SOCKET_UNIT_SHA256,
        upgrade.SYSUSERS_PATH: upgrade.SYSUSERS_SHA256,
        upgrade.TMPFILES_PATH: upgrade.TMPFILES_SHA256,
    }
    require(
        all(upgrade.digest_file(root / path) == value for path, value in expected.items()),
        "completed_target_artifact_rejected",
    )
    return manifest


def validate_completed_evidence(
    root: Path, *, read_state_bytes: bool = True
) -> dict[str, object]:
    evidence = _rooted(root, COMPLETED_EVIDENCE_ROOT)
    plan_path = evidence / "PLAN.json"
    journal_path = evidence / "JOURNAL.json"
    receipt_path = evidence / "RECEIPT.json"
    require(
        upgrade.digest_file(plan_path) == COMPLETED_PLAN_SHA256
        and upgrade.digest_file(journal_path) == COMPLETED_JOURNAL_SHA256
        and upgrade.digest_file(receipt_path) == COMPLETED_RECEIPT_SHA256,
        "completed_evidence_identity_rejected",
    )
    plan = upgrade.validate_plan(_load_json(plan_path, code="completed_plan_rejected"))
    require(plan.get("plan_digest") == COMPLETED_PLAN_DIGEST, "completed_plan_rejected")
    journal = upgrade._load_journal(journal_path, plan)
    require(
        journal.get("stage") == "target_verified"
        and journal.get("events")
        == [
            "prepared",
            "public_backup_verified",
            "stop_started",
            "services_stopped",
            "state_backup_verified",
            "release_installed",
            "selector_applied",
            "target_started",
            "target_verified",
        ],
        "completed_journal_rejected",
    )
    receipt = _load_json(receipt_path, code="completed_receipt_rejected")
    require(
        receipt
        == {
            "channel_called": False,
            "model_called": False,
            "other_program_mutated": False,
            "plan_digest": COMPLETED_PLAN_DIGEST,
            "private_content_parsed": False,
            "release_digest": COMPLETED_TARGET_RELEASE_DIGEST,
            "schema": upgrade.RECEIPT_SCHEMA,
            "state_bytes_preserved": True,
            "status": "target_verified",
        },
        "completed_receipt_rejected",
    )
    target = plan.get("target")
    predecessor = plan.get("predecessor")
    identity = plan.get("identity")
    require(
        isinstance(target, dict)
        and isinstance(predecessor, dict)
        and isinstance(identity, dict)
        and target.get("release_digest") == COMPLETED_TARGET_RELEASE_DIGEST
        and target.get("deploy_commit") == COMPLETED_TARGET_DEPLOY_COMMIT,
        "completed_plan_rejected",
    )
    predecessor_path = _rooted(root, Path(str(predecessor["release_path"])))
    target_path = _rooted(root, Path(str(target["release_target"])))
    upgrade.validate_predecessor_release(predecessor_path)
    validate_completed_target_release(target_path)
    upgrade._validate_public_backup(evidence / "public", plan)
    state_prestate = plan.get("state_prestate")
    require(isinstance(state_prestate, dict), "completed_state_backup_rejected")
    if read_state_bytes:
        upgrade.validate_opaque_backup(
            backup=evidence / "state",
            expected=state_prestate,
            expected_uid=int(identity["service_uid"]),
            expected_gid=int(identity["service_gid"]),
        )
    else:
        upgrade.validate_opaque_backup_metadata(
            backup=evidence / "state",
            expected=state_prestate,
            expected_uid=int(identity["service_uid"]),
            expected_gid=int(identity["service_gid"]),
        )
    return plan


def _predecessor_backup_binding(
    root: Path, completed: Mapping[str, object]
) -> dict[str, object]:
    evidence = _rooted(root, COMPLETED_EVIDENCE_ROOT)
    predecessor = completed.get("predecessor")
    state_prestate = completed.get("state_prestate")
    require(
        isinstance(predecessor, dict) and isinstance(state_prestate, dict),
        "predecessor_backup_rejected",
    )
    identity = completed.get("identity")
    require(isinstance(identity, dict), "predecessor_backup_rejected")
    metadata = upgrade.validate_opaque_backup_metadata(
        backup=evidence / "state",
        expected=state_prestate,
        expected_uid=int(identity["service_uid"]),
        expected_gid=int(identity["service_gid"]),
    )
    return {
        "evidence_root": str(COMPLETED_EVIDENCE_ROOT),
        "predecessor_release_digest": upgrade.PREDECESSOR_RELEASE_DIGEST,
        "predecessor_release_path": predecessor["release_path"],
        "public_manifest_sha256": upgrade.digest_file(evidence / "public/PUBLIC.json"),
        "state_inventory_sha256": digest_bytes(canonical(state_prestate)),
        "state_backup_metadata_sha256": digest_bytes(canonical(metadata)),
        "state_manifest_sha256": upgrade.digest_file(evidence / "state/STATE.json"),
    }


def validate_repair_release(
    *, root: Path, predecessor_release: Path
) -> tuple[dict[str, object], str, dict[str, object]]:
    reviewed_manifest, reviewed_digest = upgrade.validate_target_release(
        root=root, predecessor_release=predecessor_release
    )
    manifest, release_digest, identity = _validate_repair_release_contract(root)
    require(
        manifest == reviewed_manifest and release_digest == reviewed_digest,
        "repair_release_contract_mixed",
    )
    return manifest, release_digest, identity


def _incident_binding(
    *, current: Mapping[str, object], failure: Mapping[str, object]
) -> dict[str, object]:
    public = current.get("public")
    state = current.get("state")
    require(
        current.get("release_digest") == COMPLETED_TARGET_RELEASE_DIGEST
        and isinstance(public, dict)
        and isinstance(state, dict),
        "incident_origin_rejected",
    )
    origin = {
        "completed_plan_digest": COMPLETED_PLAN_DIGEST,
        "current_release_digest": COMPLETED_TARGET_RELEASE_DIGEST,
        "current_selector_env_sha256": COMPLETED_TARGET_SELECTOR_ENV_SHA256,
        "current_selector_sha256": COMPLETED_TARGET_SELECTOR_SHA256,
        "failure_receipt_sha256": failure.get("sha256"),
        "failure_sequence_id": FAILED_ACCEPTANCE_SEQUENCE_ID,
        "schema": INCIDENT_SCHEMA,
    }
    return {**origin, "incident_digest": digest_bytes(canonical(origin))}


def _expected_completed_selector() -> dict[str, object]:
    return {
        "core_commit": upgrade.TARGET_CORE_COMMIT,
        "deploy_commit": COMPLETED_TARGET_DEPLOY_COMMIT,
        "gateway_client_sha256": upgrade.PREDECESSOR_CLIENT_SHA256,
        "gateway_manifest_digest": upgrade.ACTIVE_GATEWAY_MANIFEST_DIGEST,
        "plan_digest": COMPLETED_PLAN_DIGEST,
        "plugin_digest": upgrade.ACTIVE_PLUGIN_DIGEST,
        "release_digest": COMPLETED_TARGET_RELEASE_DIGEST,
        "release_path": str(upgrade.RELEASE_ROOT / COMPLETED_TARGET_RELEASE_DIGEST),
        "schema": upgrade.SELECTOR_SCHEMA,
    }


def capture_current_target(
    *,
    root: Path,
    completed_plan: Mapping[str, object],
    unit_state: Mapping[str, object] | None,
) -> dict[str, object]:
    identity = completed_plan.get("identity")
    require(isinstance(identity, dict), "completed_plan_rejected")
    public: dict[str, dict[str, object]] = {}
    expected = {
        upgrade.SELECTOR_JSON: (COMPLETED_TARGET_SELECTOR_SHA256, 0o600),
        upgrade.SELECTOR_ENV: (COMPLETED_TARGET_SELECTOR_ENV_SHA256, 0o600),
        upgrade.UNIT_ROOT / upgrade.SERVICE: (
            COMPLETED_TARGET_SERVICE_UNIT_SHA256,
            0o644,
        ),
        upgrade.UNIT_ROOT / upgrade.SOCKET: (
            COMPLETED_TARGET_SOCKET_UNIT_SHA256,
            0o644,
        ),
    }
    for absolute, (expected_digest, expected_mode) in expected.items():
        projection = upgrade._file_projection(_rooted(root, absolute))
        require(
            projection.get("sha256") == expected_digest
            and projection.get("mode") == expected_mode
            and (
                root != Path("/")
                or (projection.get("uid") == 0 and projection.get("gid") == 0)
            ),
            "current_public_rejected",
        )
        public[str(absolute)] = projection
    selector = _load_json(
        _rooted(root, upgrade.SELECTOR_JSON), code="current_selector_rejected"
    )
    require(selector == _expected_completed_selector(), "current_selector_rejected")
    target_path = _rooted(
        root, upgrade.RELEASE_ROOT / COMPLETED_TARGET_RELEASE_DIGEST
    )
    validate_completed_target_release(target_path)
    if unit_state is None:
        require(root == Path("/"), "synthetic_unit_state_required")
        selected_units = upgrade._validate_unit_state(upgrade._capture_unit_state())
    else:
        require(root != Path("/"), "synthetic_unit_state_rejected")
        selected_units = upgrade._validate_unit_state(unit_state)
    state = upgrade.describe_opaque_state_metadata(
        _rooted(root, upgrade.STATE_ROOT),
        expected_uid=int(identity["service_uid"]),
        expected_gid=int(identity["service_gid"]),
    )
    return {
        "public": public,
        "release_digest": COMPLETED_TARGET_RELEASE_DIGEST,
        "release_manifest_sha256": COMPLETED_TARGET_MANIFEST_SHA256,
        "state": state,
        "units": selected_units,
    }


def _action_plan(payload: Mapping[str, object], *, action: str) -> dict[str, object]:
    plan_schema, _, _, _ = _schemas(action)
    body = dict(payload)
    plan_digest = digest_bytes(canonical(body))
    return {**body, "plan_digest": plan_digest, "schema": plan_schema}


def prepare_action(
    *,
    action: str,
    repair_release: Path | None = None,
    root: Path = Path("/"),
    unit_state: Mapping[str, object] | None = None,
) -> dict[str, object]:
    if root == Path("/"):
        require(os.geteuid() == 0, "root_required")
    _schemas(action)
    completed = validate_completed_evidence(root, read_state_bytes=False)
    failure = validate_failed_acceptance_receipt(root)
    current = capture_current_target(
        root=root, completed_plan=completed, unit_state=unit_state
    )
    predecessor_backup = _predecessor_backup_binding(root, completed)
    incident = _incident_binding(current=current, failure=failure)
    repair_target: dict[str, object] | None = None
    if action == "repair":
        require(repair_release is not None, "repair_release_required")
        predecessor = completed["predecessor"]
        assert isinstance(predecessor, dict)
        predecessor_path = _rooted(root, Path(str(predecessor["release_path"])))
        manifest, release_digest, repair_identity = validate_repair_release(
            root=repair_release, predecessor_release=predecessor_path
        )
        destination = _rooted(root, upgrade.RELEASE_ROOT / release_digest)
        require(
            not destination.exists() and not destination.is_symlink(),
            "repair_release_preexisting",
        )
        repair_target = {
            "core_commit": manifest["core_commit"],
            "deploy_commit": manifest["deploy_commit"],
            "installed_inventory_sha256": repair_identity[
                "installed_inventory_sha256"
            ],
            "release_digest": release_digest,
            "release_manifest_sha256": repair_identity["manifest_sha256"],
            "release_source": str(repair_release.resolve()),
            "release_target": str(upgrade.RELEASE_ROOT / release_digest),
            "source_inventory_sha256": repair_identity[
                "source_inventory_sha256"
            ],
            "post_target_action_sha256": repair_identity[
                "post_target_action_sha256"
            ],
        }
    else:
        require(repair_release is None, "rollback_release_rejected")
    mutation_paths = [
        str(upgrade.SELECTOR_JSON),
        str(upgrade.SELECTOR_ENV),
        str(upgrade.UNIT_ROOT / upgrade.SERVICE),
        str(upgrade.UNIT_ROOT / upgrade.SOCKET),
        str(
            POST_ACTION_EVIDENCE_ROOT
            / "incidents"
            / str(incident["incident_digest"])
        ),
    ]
    if repair_target is not None:
        mutation_paths.insert(0, str(repair_target["release_target"]))
    return _action_plan(
        {
            "action": action,
            "allowed_mutation_paths": mutation_paths,
            "completed_evidence": {
                "journal_sha256": COMPLETED_JOURNAL_SHA256,
                "plan_digest": COMPLETED_PLAN_DIGEST,
                "plan_sha256": COMPLETED_PLAN_SHA256,
                "receipt_sha256": COMPLETED_RECEIPT_SHA256,
                "status": "target_verified",
            },
            "current_target": current,
            "failure_receipt": failure,
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
            "incident": incident,
            "opaque_content_read_deferred_to_action_owned_backup": True,
            "opaque_state_policy": "preserve_current_authoritative_bytes",
            "predecessor_backup": predecessor_backup,
            "repair_target": repair_target,
            "single_bounded_action": True,
        },
        action=action,
    )


def _valid_stat_generation(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"ctime_ns", "device", "inode", "mtime_ns"}
        and all(isinstance(item, int) and item >= 0 for item in value.values())
    )


def _validate_state_metadata_projection(value: object) -> dict[str, object]:
    require(
        isinstance(value, dict)
        and set(value) == {"content_bytes_read", "files", "root", "schema"}
        and value.get("schema") == upgrade.STATE_METADATA_SCHEMA
        and value.get("content_bytes_read") is False,
        "opaque_state_metadata_rejected",
    )
    root = value.get("root")
    require(
        isinstance(root, dict)
        and set(root)
        == {"generation", "gid", "mode", "nlink", "path_role", "type", "uid"}
        and _valid_stat_generation(root.get("generation"))
        and root.get("path_role") == "opaque_state_root"
        and root.get("type") == "directory"
        and root.get("mode") == 0o700
        and isinstance(root.get("nlink"), int)
        and int(root["nlink"]) >= 2
        and all(
            isinstance(root.get(key), int) and int(root[key]) >= 0
            for key in ("uid", "gid")
        ),
        "opaque_state_metadata_rejected",
    )
    files = value.get("files")
    require(
        isinstance(files, list) and len(files) == len(upgrade.STATE_FILES),
        "opaque_state_metadata_rejected",
    )
    for row, name in zip(files, upgrade.STATE_FILES, strict=True):
        require(
            isinstance(row, dict)
            and set(row)
            == {
                "generation",
                "gid",
                "mode",
                "name",
                "nlink",
                "path_role",
                "size",
                "type",
                "uid",
            }
            and row.get("name") == name
            and row.get("path_role") == upgrade.STATE_FILE_ROLES[name]
            and row.get("type") == "regular_file"
            and row.get("nlink") == 1
            and row.get("mode") == 0o600
            and _valid_stat_generation(row.get("generation"))
            and isinstance(row.get("size"), int)
            and 0 < int(row["size"]) <= upgrade.MAX_STATE_FILE_BYTES
            and all(
                isinstance(row.get(key), int) and int(row[key]) >= 0
                for key in ("uid", "gid")
            ),
            "opaque_state_metadata_rejected",
        )
    return dict(value)


def validate_action_plan(
    payload: Mapping[str, object], *, expected_action: str
) -> dict[str, object]:
    plan_schema, _, _, _ = _schemas(expected_action)
    raw = dict(payload)
    plan_digest = raw.pop("plan_digest", None)
    require(raw.pop("schema", None) == plan_schema, "action_plan_schema_rejected")
    require(
        isinstance(plan_digest, str)
        and upgrade.HEX64.fullmatch(plan_digest) is not None
        and plan_digest == digest_bytes(canonical(raw)),
        "action_plan_digest_rejected",
    )
    require(
        set(raw)
        == {
            "action",
            "allowed_mutation_paths",
            "completed_evidence",
            "current_target",
            "failure_receipt",
            "forbidden_program_mutations",
            "incident",
            "opaque_content_read_deferred_to_action_owned_backup",
            "opaque_state_policy",
            "predecessor_backup",
            "repair_target",
            "single_bounded_action",
        }
        and raw.get("action") == expected_action
        and raw.get("single_bounded_action") is True
        and raw.get("opaque_content_read_deferred_to_action_owned_backup") is True
        and raw.get("opaque_state_policy")
        == "preserve_current_authoritative_bytes"
        and raw.get("forbidden_program_mutations")
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
        "action_plan_scope_rejected",
    )
    require(
        raw.get("completed_evidence")
        == {
            "journal_sha256": COMPLETED_JOURNAL_SHA256,
            "plan_digest": COMPLETED_PLAN_DIGEST,
            "plan_sha256": COMPLETED_PLAN_SHA256,
            "receipt_sha256": COMPLETED_RECEIPT_SHA256,
            "status": "target_verified",
        }
        and raw.get("failure_receipt")
        == {
            "path": str(FAILED_ACCEPTANCE_RECEIPT_PATH),
            "schema": "myuna.p08-superseding-post-activation-acceptance-failure.v1",
            "sequence_id": FAILED_ACCEPTANCE_SEQUENCE_ID,
            "sha256": FAILED_ACCEPTANCE_RECEIPT_SHA256,
            "status": FAILED_ACCEPTANCE_STATUS,
        },
        "action_origin_rejected",
    )
    current = raw.get("current_target")
    require(
        isinstance(current, dict)
        and set(current)
        == {"public", "release_digest", "release_manifest_sha256", "state", "units"}
        and current.get("release_digest") == COMPLETED_TARGET_RELEASE_DIGEST
        and current.get("release_manifest_sha256")
        == COMPLETED_TARGET_MANIFEST_SHA256
        and isinstance(current.get("public"), dict)
        and set(current["public"])
        == {
            str(upgrade.SELECTOR_JSON),
            str(upgrade.SELECTOR_ENV),
            str(upgrade.UNIT_ROOT / upgrade.SERVICE),
            str(upgrade.UNIT_ROOT / upgrade.SOCKET),
        }
        and isinstance(current.get("state"), dict)
        and current.get("units")
        == {
            "service_active": "active",
            "socket_active": "active",
            "socket_enabled": "enabled",
        },
        "action_current_target_rejected",
    )
    _validate_state_metadata_projection(current["state"])
    failure = raw["failure_receipt"]
    assert isinstance(failure, dict)
    require(
        raw.get("incident") == _incident_binding(current=current, failure=failure),
        "action_incident_rejected",
    )
    predecessor_backup = raw.get("predecessor_backup")
    require(
        isinstance(predecessor_backup, dict)
        and set(predecessor_backup)
        == {
            "evidence_root",
            "predecessor_release_digest",
            "predecessor_release_path",
            "public_manifest_sha256",
            "state_backup_metadata_sha256",
            "state_inventory_sha256",
            "state_manifest_sha256",
        }
        and predecessor_backup.get("evidence_root") == str(COMPLETED_EVIDENCE_ROOT)
        and predecessor_backup.get("predecessor_release_digest")
        == upgrade.PREDECESSOR_RELEASE_DIGEST
        and predecessor_backup.get("predecessor_release_path")
        == str(upgrade.RELEASE_ROOT / upgrade.PREDECESSOR_RELEASE_DIGEST)
        and all(
            upgrade.HEX64.fullmatch(str(predecessor_backup.get(key))) is not None
            for key in (
                "public_manifest_sha256",
                "state_backup_metadata_sha256",
                "state_inventory_sha256",
                "state_manifest_sha256",
            )
        ),
        "predecessor_backup_rejected",
    )
    repair_target = raw.get("repair_target")
    incident = raw["incident"]
    assert isinstance(incident, dict)
    expected_paths = [
        str(upgrade.SELECTOR_JSON),
        str(upgrade.SELECTOR_ENV),
        str(upgrade.UNIT_ROOT / upgrade.SERVICE),
        str(upgrade.UNIT_ROOT / upgrade.SOCKET),
        str(
            POST_ACTION_EVIDENCE_ROOT
            / "incidents"
            / str(incident["incident_digest"])
        ),
    ]
    if expected_action == "repair":
        require(
            isinstance(repair_target, dict)
            and set(repair_target)
            == {
                "core_commit",
                "deploy_commit",
                "installed_inventory_sha256",
                "post_target_action_sha256",
                "release_digest",
                "release_manifest_sha256",
                "release_source",
                "release_target",
                "source_inventory_sha256",
            }
            and repair_target.get("core_commit") == upgrade.TARGET_CORE_COMMIT
            and upgrade.SAFE_COMMIT.fullmatch(
                str(repair_target.get("deploy_commit"))
            )
            is not None
            and upgrade.HEX64.fullmatch(
                str(repair_target.get("release_digest"))
            )
            is not None
            and repair_target.get("release_target")
            == str(upgrade.RELEASE_ROOT / str(repair_target.get("release_digest")))
            and Path(str(repair_target.get("release_source"))).is_absolute()
            and Path(str(repair_target.get("release_source"))).name
            == repair_target.get("release_digest"),
            "repair_target_rejected",
        )
        require(
            all(
                upgrade.HEX64.fullmatch(str(repair_target.get(key))) is not None
                for key in (
                    "installed_inventory_sha256",
                    "post_target_action_sha256",
                    "release_manifest_sha256",
                    "source_inventory_sha256",
                )
            ),
            "repair_target_identity_rejected",
        )
        expected_paths.insert(0, str(repair_target["release_target"]))
    else:
        require(repair_target is None, "rollback_target_rejected")
    require(
        raw.get("allowed_mutation_paths") == expected_paths,
        "action_allowed_paths_rejected",
    )
    return {**raw, "plan_digest": plan_digest, "schema": plan_schema}


def verify_action_plan(
    payload: Mapping[str, object],
    *,
    expected_action: str,
    root: Path = Path("/"),
    unit_state: Mapping[str, object] | None = None,
) -> dict[str, object]:
    plan = validate_action_plan(payload, expected_action=expected_action)
    completed = validate_completed_evidence(root, read_state_bytes=False)
    require(
        validate_failed_acceptance_receipt(root) == plan["failure_receipt"],
        "failure_receipt_drifted",
    )
    require(
        _predecessor_backup_binding(root, completed) == plan["predecessor_backup"],
        "predecessor_backup_drifted",
    )
    observed = capture_current_target(
        root=root, completed_plan=completed, unit_state=unit_state
    )
    require(observed == plan["current_target"], "action_current_target_drifted")
    if expected_action == "repair":
        repair = plan["repair_target"]
        predecessor = completed["predecessor"]
        assert isinstance(repair, dict) and isinstance(predecessor, dict)
        source = Path(str(repair["release_source"]))
        predecessor_path = _rooted(root, Path(str(predecessor["release_path"])))
        manifest, release_digest, identity = validate_repair_release(
            root=source, predecessor_release=predecessor_path
        )
        require(
            release_digest == repair["release_digest"]
            and manifest.get("core_commit") == repair["core_commit"]
            and manifest.get("deploy_commit") == repair["deploy_commit"]
            and identity["installed_inventory_sha256"]
            == repair["installed_inventory_sha256"]
            and identity["manifest_sha256"]
            == repair["release_manifest_sha256"]
            and identity["post_target_action_sha256"]
            == repair["post_target_action_sha256"]
            and identity["source_inventory_sha256"]
            == repair["source_inventory_sha256"]
            and not _rooted(root, Path(str(repair["release_target"]))).exists(),
            "repair_target_drifted",
        )
    return plan


def preflight_action(
    *,
    action: str,
    repair_release: Path | None = None,
    root: Path = Path("/"),
    unit_state: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Return a canonical ready projection without persistent mutation."""

    plan = prepare_action(
        action=action,
        repair_release=repair_release,
        root=root,
        unit_state=unit_state,
    )
    verified = verify_action_plan(
        plan,
        expected_action=action,
        root=root,
        unit_state=unit_state,
    )
    require(verified == plan, "action_preflight_mixed")
    return {
        "action": action,
        "opaque_content_read": False,
        "opaque_content_read_deferred_to_action_owned_backup": True,
        "persistent_mutation": False,
        "plan": verified,
        "plan_digest": verified["plan_digest"],
        "schema": READINESS_SCHEMA,
        "status": "ready",
    }


def _action_evidence(root: Path, plan: Mapping[str, object]) -> Path:
    incident = plan.get("incident")
    require(isinstance(incident, dict), "action_incident_rejected")
    return _rooted(
        root,
        POST_ACTION_EVIDENCE_ROOT
        / "incidents"
        / str(incident["incident_digest"]),
    )


def _validate_owned_directory(path: Path, *, code: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PostTargetRejected(code) from exc
    require(
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == 0o700
        and metadata.st_uid == os.geteuid()
        and metadata.st_gid == os.getegid(),
        code,
    )


def _validate_owned_file(
    path: Path, payload: bytes, *, code: str, mode: int = 0o600
) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PostTargetRejected(code) from exc
    require(
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_nlink == 1
        and stat.S_IMODE(metadata.st_mode) == mode
        and metadata.st_uid == os.geteuid()
        and metadata.st_gid == os.getegid()
        and metadata.st_size == len(payload)
        and upgrade.digest_file(path) == digest_bytes(payload),
        code,
    )


def _ensure_evidence_parent(root: Path) -> Path:
    base = _rooted(root, POST_ACTION_EVIDENCE_ROOT)
    require(base.parent.is_dir() and not base.parent.is_symlink(), "action_parent_rejected")
    for path in (base, base / "incidents"):
        try:
            os.mkdir(path, 0o700)
            upgrade._fsync_directory(path.parent)
        except FileExistsError:
            pass
        except OSError as exc:
            raise PostTargetRejected("action_parent_rejected") from exc
        _validate_owned_directory(path, code="action_parent_rejected")
    return base / "incidents"


def _claim_action_evidence(root: Path, plan: Mapping[str, object]) -> Path:
    parent = _ensure_evidence_parent(root)
    evidence = _action_evidence(root, plan)
    require(evidence.parent == parent, "action_evidence_path_rejected")
    try:
        os.mkdir(evidence, 0o700)
        upgrade._fsync_directory(parent)
    except FileExistsError as exc:
        raise PostTargetRejected("incident_action_already_consumed") from exc
    except OSError as exc:
        raise PostTargetRejected("action_evidence_create_rejected") from exc
    _validate_owned_directory(evidence, code="action_evidence_create_rejected")
    return evidence


def _journal_sequence(action: str) -> tuple[str, ...]:
    _schemas(action)
    common = (
        "prepared",
        "current_public_backed_up",
        "current_state_backed_up",
        "attempt_owned",
        "services_stopped",
    )
    if action == "repair":
        return common + (
            "release_installed",
            "public_applied",
            "target_started",
            "protocol_acceptance_called",
            "target_accepted",
        )
    return common + ("public_applied", "target_started", "predecessor_verified")


def _validate_journal_events(action: str, events: Sequence[str]) -> None:
    require(events and len(events) == len(set(events)), "action_journal_rejected")
    happy = _journal_sequence(action)
    selected = tuple(events)
    if "convergence_owned" not in selected:
        require(selected == happy[: len(selected)], "action_journal_rejected")
        return
    index = selected.index("convergence_owned")
    require(
        index >= 4
        and selected[:index] == happy[:index]
        and selected[index:]
        in {
            ("convergence_owned",),
            ("convergence_owned", "recovered_current_target"),
            ("convergence_owned", "convergence_failed"),
        },
        "action_journal_rejected",
    )


def _load_action_journal(
    path: Path, *, action: str, plan_digest: str
) -> dict[str, object]:
    _, journal_schema, _, _ = _schemas(action)
    payload = _load_json(path, code="action_journal_rejected")
    events = payload.get("events")
    require(
        set(payload) == {"action", "attempts", "events", "plan_digest", "schema", "stage"}
        and payload.get("action") == action
        and payload.get("attempts") == 1
        and payload.get("plan_digest") == plan_digest
        and payload.get("schema") == journal_schema
        and isinstance(events, list)
        and all(isinstance(item, str) for item in events)
        and payload.get("stage") == events[-1],
        "action_journal_rejected",
    )
    _validate_journal_events(action, events)
    return payload


def _verify_state_metadata_unchanged(
    *, root: Path, plan: Mapping[str, object], completed: Mapping[str, object]
) -> dict[str, object]:
    identity = completed.get("identity")
    current = plan.get("current_target")
    require(
        isinstance(identity, dict) and isinstance(current, dict),
        "opaque_state_metadata_rejected",
    )
    expected = _validate_state_metadata_projection(current.get("state"))
    observed = upgrade.describe_opaque_state_metadata(
        _rooted(root, upgrade.STATE_ROOT),
        expected_uid=int(identity["service_uid"]),
        expected_gid=int(identity["service_gid"]),
    )
    require(observed == expected, "opaque_state_metadata_drifted")
    return observed


def _action_state_binding(
    *, plan: Mapping[str, object], exact: Mapping[str, object]
) -> dict[str, object]:
    current = plan.get("current_target")
    require(isinstance(current, dict), "action_state_binding_rejected")
    metadata = _validate_state_metadata_projection(current.get("state"))
    return {
        "backup_path": "current-state",
        "content_bytes_read": True,
        "content_read_deferred_from_readiness": True,
        "metadata_projection_sha256": digest_bytes(canonical(metadata)),
        "plan_digest": plan["plan_digest"],
        "schema": ACTION_STATE_BINDING_SCHEMA,
        "state_descriptor_sha256": digest_bytes(canonical(exact)),
    }


def _stage_action_owned_state_backup(
    *,
    root: Path,
    plan: Mapping[str, object],
    completed: Mapping[str, object],
    evidence: Path,
) -> dict[str, object]:
    identity = completed.get("identity")
    require(isinstance(identity, dict), "action_state_binding_rejected")
    _verify_state_metadata_unchanged(root=root, plan=plan, completed=completed)
    source = _rooted(root, upgrade.STATE_ROOT)
    exact = upgrade.describe_opaque_state(
        source,
        expected_uid=int(identity["service_uid"]),
        expected_gid=int(identity["service_gid"]),
    )
    _verify_state_metadata_unchanged(root=root, plan=plan, completed=completed)
    backup = evidence / "current-state"
    upgrade.backup_opaque_state(
        source=source,
        backup=backup,
        expected=exact,
        expected_uid=int(identity["service_uid"]),
        expected_gid=int(identity["service_gid"]),
    )
    _verify_state_metadata_unchanged(root=root, plan=plan, completed=completed)
    binding = _action_state_binding(plan=plan, exact=exact)
    upgrade._exclusive_write(
        evidence / "STATE_BINDING.json", canonical(binding), mode=0o600
    )
    _load_action_owned_state_backup(
        root=root, plan=plan, completed=completed, evidence=evidence
    )
    return exact


def _load_action_owned_state_backup(
    *,
    root: Path,
    plan: Mapping[str, object],
    completed: Mapping[str, object],
    evidence: Path,
) -> dict[str, object]:
    identity = completed.get("identity")
    require(isinstance(identity, dict), "action_state_binding_rejected")
    binding_path = evidence / "STATE_BINDING.json"
    binding = _load_json(binding_path, code="action_state_binding_rejected")
    backup = evidence / "current-state"
    exact = _load_json(
        backup / "STATE.json", code="action_state_backup_manifest_rejected"
    )
    require(
        binding == _action_state_binding(plan=plan, exact=exact),
        "action_state_binding_rejected",
    )
    _validate_owned_file(
        binding_path,
        canonical(binding),
        code="action_state_binding_rejected",
    )
    upgrade.validate_opaque_backup(
        backup=backup,
        expected=exact,
        expected_uid=int(identity["service_uid"]),
        expected_gid=int(identity["service_gid"]),
    )
    return exact


def _verify_action_owned_state_matches_current(
    *,
    root: Path,
    plan: Mapping[str, object],
    completed: Mapping[str, object],
    evidence: Path,
) -> dict[str, object]:
    exact = _load_action_owned_state_backup(
        root=root, plan=plan, completed=completed, evidence=evidence
    )
    identity = completed.get("identity")
    require(isinstance(identity, dict), "action_state_binding_rejected")
    _verify_state_metadata_unchanged(root=root, plan=plan, completed=completed)
    observed = upgrade.describe_opaque_state(
        _rooted(root, upgrade.STATE_ROOT),
        expected_uid=int(identity["service_uid"]),
        expected_gid=int(identity["service_gid"]),
    )
    require(observed == exact, "action_owned_state_drifted")
    return exact


def _restore_action_owned_state(
    *,
    root: Path,
    plan: Mapping[str, object],
    completed: Mapping[str, object],
    evidence: Path,
) -> dict[str, object]:
    exact = _load_action_owned_state_backup(
        root=root, plan=plan, completed=completed, evidence=evidence
    )
    identity = completed.get("identity")
    require(isinstance(identity, dict), "action_state_binding_rejected")
    upgrade.restore_opaque_state(
        target=_rooted(root, upgrade.STATE_ROOT),
        backup=evidence / "current-state",
        expected=exact,
        expected_uid=int(identity["service_uid"]),
        expected_gid=int(identity["service_gid"]),
        plan_digest=str(plan["plan_digest"]),
    )
    return exact


def stage_action_plan(
    payload: Mapping[str, object],
    *,
    expected_action: str,
    root: Path,
    unit_state: Mapping[str, object] | None = None,
) -> Path:
    """Consume the one incident action and stage all pre-stop ownership."""

    if root == Path("/"):
        require(os.geteuid() == 0, "root_required")
    plan = verify_action_plan(
        payload,
        expected_action=expected_action,
        root=root,
        unit_state=unit_state,
    )
    evidence = _claim_action_evidence(root, plan)
    upgrade._exclusive_write(evidence / "PLAN.json", canonical(plan), mode=0o600)
    _, _, ledger_schema, _ = _schemas(expected_action)
    ledger = {
        "action": expected_action,
        "attempts": 1,
        "consumed": True,
        "incident_digest": plan["incident"]["incident_digest"],
        "plan_digest": plan["plan_digest"],
        "schema": ledger_schema,
    }
    upgrade._exclusive_write(
        evidence / "LEDGER.json", canonical(ledger), mode=0o600
    )
    _write_journal(
        evidence / "JOURNAL.json",
        action=expected_action,
        plan_digest=str(plan["plan_digest"]),
        events=["prepared"],
    )
    completed = validate_completed_evidence(root, read_state_bytes=True)
    require(
        _predecessor_backup_binding(root, completed) == plan["predecessor_backup"],
        "predecessor_backup_drifted",
    )
    current_adapter = _current_public_adapter(plan)
    upgrade._copy_public_backup(root, evidence / "current-public", current_adapter)
    _write_journal(
        evidence / "JOURNAL.json",
        action=expected_action,
        plan_digest=str(plan["plan_digest"]),
        events=["prepared", "current_public_backed_up"],
    )
    _stage_action_owned_state_backup(
        root=root,
        plan=plan,
        completed=completed,
        evidence=evidence,
    )
    _write_journal(
        evidence / "JOURNAL.json",
        action=expected_action,
        plan_digest=str(plan["plan_digest"]),
        events=[
            "prepared",
            "current_public_backed_up",
            "current_state_backed_up",
        ],
    )
    _write_journal(
        evidence / "JOURNAL.json",
        action=expected_action,
        plan_digest=str(plan["plan_digest"]),
        events=[
            "prepared",
            "current_public_backed_up",
            "current_state_backed_up",
            "attempt_owned",
        ],
    )
    return evidence


def verify_staged_action(
    payload: Mapping[str, object],
    *,
    expected_action: str,
    root: Path,
    unit_state: Mapping[str, object] | None = None,
) -> tuple[dict[str, object], Path]:
    plan = verify_action_plan(
        payload,
        expected_action=expected_action,
        root=root,
        unit_state=unit_state,
    )
    evidence = _action_evidence(root, plan)
    _validate_owned_directory(evidence, code="staged_action_rejected")
    _, _, ledger_schema, _ = _schemas(expected_action)
    ledger = {
        "action": expected_action,
        "attempts": 1,
        "consumed": True,
        "incident_digest": plan["incident"]["incident_digest"],
        "plan_digest": plan["plan_digest"],
        "schema": ledger_schema,
    }
    _validate_owned_file(
        evidence / "PLAN.json", canonical(plan), code="staged_plan_rejected"
    )
    _validate_owned_file(
        evidence / "LEDGER.json", canonical(ledger), code="action_ledger_rejected"
    )
    require(
        _load_json(evidence / "PLAN.json", code="staged_plan_rejected") == plan
        and _load_json(evidence / "LEDGER.json", code="action_ledger_rejected")
        == ledger,
        "staged_action_rejected",
    )
    journal = _load_action_journal(
        evidence / "JOURNAL.json",
        action=expected_action,
        plan_digest=str(plan["plan_digest"]),
    )
    _validate_owned_file(
        evidence / "JOURNAL.json",
        canonical(journal),
        code="action_journal_rejected",
    )
    require(journal["stage"] == "attempt_owned", "staged_action_rejected")
    upgrade._validate_public_backup(
        evidence / "current-public", _current_public_adapter(plan)
    )
    completed = validate_completed_evidence(root, read_state_bytes=True)
    require(
        _predecessor_backup_binding(root, completed) == plan["predecessor_backup"],
        "predecessor_backup_drifted",
    )
    _verify_action_owned_state_matches_current(
        root=root,
        plan=plan,
        completed=completed,
        evidence=evidence,
    )
    return plan, evidence


def stage_synthetic_action_plan(
    payload: Mapping[str, object],
    *,
    expected_action: str,
    root: Path,
    unit_state: Mapping[str, object],
) -> Path:
    require(root != Path("/"), "synthetic_root_rejected")
    return stage_action_plan(
        payload,
        expected_action=expected_action,
        root=root,
        unit_state=unit_state,
    )


def verify_staged_synthetic_action(
    payload: Mapping[str, object],
    *,
    expected_action: str,
    root: Path,
    unit_state: Mapping[str, object],
) -> tuple[dict[str, object], Path]:
    require(root != Path("/"), "synthetic_root_rejected")
    return verify_staged_action(
        payload,
        expected_action=expected_action,
        root=root,
        unit_state=unit_state,
    )


def _write_journal(
    path: Path,
    *,
    action: str,
    plan_digest: str,
    events: list[str],
) -> None:
    _, journal_schema, _, _ = _schemas(action)
    require(all(item in _COMMON_STAGES for item in events), "action_journal_rejected")
    _validate_journal_events(action, events)
    payload = {
        "action": action,
        "attempts": 1,
        "events": events,
        "plan_digest": plan_digest,
        "schema": journal_schema,
        "stage": events[-1],
    }
    if path.exists():
        upgrade._atomic_write(
            path,
            canonical(payload),
            mode=0o600,
            uid=os.geteuid(),
            gid=os.getegid(),
        )
    else:
        upgrade._exclusive_write(path, canonical(payload), mode=0o600)


def _current_public_adapter(plan: Mapping[str, object]) -> dict[str, object]:
    current = plan["current_target"]
    assert isinstance(current, dict)
    return {"public_prestate": current["public"]}


def _install_repair_release(
    *, root: Path, adapter: Mapping[str, object], repair: Mapping[str, object]
) -> Path:
    source = Path(str(repair["release_source"]))
    source_rows = _release_metadata_inventory(source)
    require(
        digest_bytes(canonical(source_rows)) == repair["source_inventory_sha256"],
        "repair_source_inventory_drifted",
    )
    installed = upgrade._install_release(root, adapter)
    installed_rows = _release_metadata_inventory(installed)
    expected = _installed_inventory_from_source(
        source_rows, live=root == Path("/")
    )
    require(installed_rows == expected, "installed_release_metadata_rejected")
    if root == Path("/"):
        require(
            digest_bytes(canonical(installed_rows))
            == repair["installed_inventory_sha256"],
            "installed_release_inventory_rejected",
        )
    return installed


def _start_service_then_socket(runner: Runner) -> None:
    runner(["/usr/bin/systemctl", "daemon-reload"])
    runner(["/usr/bin/systemctl", "start", upgrade.SERVICE])
    runner(["/usr/bin/systemctl", "enable", upgrade.SOCKET])
    runner(["/usr/bin/systemctl", "start", upgrade.SOCKET])
    runner(["/usr/bin/systemctl", "is-active", "--quiet", upgrade.SERVICE])
    runner(["/usr/bin/systemctl", "is-active", "--quiet", upgrade.SOCKET])


def _validate_content_free_acceptance(payload: Mapping[str, object]) -> str:
    expected = {
        "active_fact_count",
        "active_set_complete",
        "active_set_digest",
        "lifecycle_complete",
        "lifecycle_digest",
        "lifecycle_event_count",
        "lifecycle_watermark",
        "pending_proposal_count",
        "request_nonce",
        "response_digest",
        "scope_binding_digest",
        "source_identity",
        "status_digest",
        "status_schema",
        "total_fact_count",
        "trusted_time_binding_digest",
        "trusted_time_evidence_complete",
    }
    require(set(payload) == expected, "protocol_acceptance_rejected")
    require(
        payload.get("active_set_complete") is True
        and payload.get("lifecycle_complete") is True
        and payload.get("trusted_time_evidence_complete") is True
        and payload.get("status_schema") == CONTENT_FREE_STATUS_SCHEMA,
        "protocol_acceptance_rejected",
    )
    for key in (
        "active_fact_count",
        "lifecycle_event_count",
        "lifecycle_watermark",
        "pending_proposal_count",
        "total_fact_count",
    ):
        require(type(payload.get(key)) is int and int(payload[key]) >= 0, "protocol_acceptance_rejected")
    for key in (
        "active_set_digest",
        "lifecycle_digest",
        "request_nonce",
        "response_digest",
        "scope_binding_digest",
        "source_identity",
        "status_digest",
        "trusted_time_binding_digest",
    ):
        require(
            isinstance(payload.get(key), str)
            and upgrade.HEX64.fullmatch(str(payload[key])) is not None,
            "protocol_acceptance_rejected",
        )
    return digest_bytes(canonical(dict(payload)))


def _run_content_free_acceptance(release: Path) -> Mapping[str, object]:
    helper = release / upgrade.CLIENT_PATH
    require(
        release.parent == upgrade.RELEASE_ROOT
        and release.name != COMPLETED_TARGET_RELEASE_DIGEST
        and helper.is_file()
        and not helper.is_symlink(),
        "protocol_acceptance_path_rejected",
    )
    invocation_nonce = secrets.token_hex(32)
    require(
        upgrade.HEX64.fullmatch(invocation_nonce) is not None,
        "protocol_acceptance_invocation_rejected",
    )
    try:
        completed = subprocess.run(
            ["/usr/bin/python3", "-B", str(helper), "--content-free-status"],
            check=False,
            cwd=release,
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/usr/sbin",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": os.pathsep.join(
                    (str(release / "src"), str(release / "scripts"))
                ),
                CONTENT_FREE_STATUS_INVOCATION_NONCE_ENV: invocation_nonce,
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PostTargetRejected("protocol_acceptance_unavailable") from exc
    if completed.returncode != 0:
        try:
            rejection = temporal_gateway.parse_content_free_status_rejection_bytes(
                completed.stdout,
                expected_invocation_nonce=invocation_nonce,
            )
        except ValueError:
            raise PostTargetRejected("protocol_acceptance_failed") from None
        raise PostTargetRejected(
            "protocol_acceptance_failed",
            content_free_failure_projection=rejection.projection(),
        )
    require(0 < len(completed.stdout) <= 8192, "protocol_acceptance_rejected")
    try:
        payload = json.loads(
            completed.stdout.decode("utf-8", "strict"),
            object_pairs_hook=temporal_gateway._strict_status_runtime_object,
        )
    except (
        UnicodeError,
        json.JSONDecodeError,
        temporal_gateway._DuplicateStatusRuntimeKey,
    ) as exc:
        raise PostTargetRejected("protocol_acceptance_rejected") from exc
    require(isinstance(payload, dict), "protocol_acceptance_rejected")
    require(
        payload.get("request_nonce") == invocation_nonce,
        "protocol_acceptance_rejected",
    )
    return payload


def protocol_acceptance_contract(root: Path) -> dict[str, object]:
    source = root / "scripts/p08_post_target_action_v1.py"
    return {
        "child_rejection_schema": temporal_gateway.STATUS_STAGE_SCHEMA,
        "child_stage_contract_identity": temporal_gateway.STATUS_STAGE_SOURCE_IDENTITY,
        "failure_stages": sorted(
            stage
            for stage in temporal_gateway._STATUS_STAGE_POLICY
            if not stage.startswith("parent_")
        ),
        "helper_calls": 1,
        "invocation_nonce_environment": CONTENT_FREE_STATUS_INVOCATION_NONCE_ENV,
        "nonce_chain": [
            "controller_generated",
            "helper_request",
            "server_echo",
            "helper_projection",
            "controller_validation",
        ],
        "raw_stderr_retained": False,
        "runtime_child_rejection_schema": (
            temporal_gateway.STATUS_RUNTIME_STAGE_SCHEMA
        ),
        "runtime_child_stage_contract_identity": (
            temporal_gateway.STATUS_RUNTIME_STAGE_SOURCE_IDENTITY
        ),
        "runtime_failure_substages": sorted(
            temporal_gateway._STATUS_RUNTIME_REJECTION_POLICY
        ),
        "runtime_generic_projection_preserved": True,
        "runtime_request_nonce_bound": True,
        "retry_or_fallback": False,
        "schema": "myuna.p08-protocol-acceptance-contract.v1",
        "sha256": upgrade.digest_file(source),
        "source_path": "scripts/p08_post_target_action_v1.py",
    }


def _receipt(
    *,
    action: str,
    plan: Mapping[str, object],
    status: str,
    acceptance_projection_sha256: str | None = None,
    action_failure_code: str | None = None,
    convergence_failure_code: str | None = None,
) -> dict[str, object]:
    _, _, _, receipt_schema = _schemas(action)
    return {
        "acceptance_projection_sha256": acceptance_projection_sha256,
        "action": action,
        "action_failure_code": action_failure_code,
        "channel_called": False,
        "convergence_failure_code": convergence_failure_code,
        "incident_digest": plan["incident"]["incident_digest"],
        "model_called": False,
        "other_program_mutated": False,
        "plan_digest": plan["plan_digest"],
        "private_content_parsed": False,
        "schema": receipt_schema,
        "state_bytes_preserved": True,
        "status": status,
    }


def _synthetic_content_free_acceptance(_: Path) -> Mapping[str, object]:
    return {
        "active_fact_count": 0,
        "active_set_complete": True,
        "active_set_digest": "1" * 64,
        "lifecycle_complete": True,
        "lifecycle_digest": "2" * 64,
        "lifecycle_event_count": 0,
        "lifecycle_watermark": 0,
        "pending_proposal_count": 0,
        "request_nonce": "3" * 64,
        "response_digest": "4" * 64,
        "scope_binding_digest": "5" * 64,
        "source_identity": "6" * 64,
        "status_digest": "7" * 64,
        "status_schema": CONTENT_FREE_STATUS_SCHEMA,
        "total_fact_count": 0,
        "trusted_time_binding_digest": "8" * 64,
        "trusted_time_evidence_complete": True,
    }


def _verify_current_target_restored(
    *,
    root: Path,
    plan: Mapping[str, object],
    completed: Mapping[str, object],
    exact_state: Mapping[str, object],
    unit_state: Mapping[str, object] | None,
) -> None:
    observed = capture_current_target(
        root=root, completed_plan=completed, unit_state=unit_state
    )
    expected = plan.get("current_target")
    require(isinstance(expected, dict), "current_target_restore_rejected")
    observed_state = observed.pop("state", None)
    expected_state = json.loads(
        canonical(_validate_state_metadata_projection(expected["state"])).decode("ascii")
    )
    expected_without_state = dict(expected)
    expected_without_state.pop("state", None)
    require(observed == expected_without_state, "current_target_restore_rejected")
    require(
        isinstance(observed_state, dict), "current_target_restore_rejected"
    )
    observed_state = json.loads(canonical(observed_state).decode("ascii"))
    for projection in (observed_state, expected_state):
        root_projection = projection.get("root")
        require(isinstance(root_projection, dict), "current_target_restore_rejected")
        root_projection.pop("generation", None)
        rows = projection.get("files")
        require(isinstance(rows, list), "current_target_restore_rejected")
        for row in rows:
            require(isinstance(row, dict), "current_target_restore_rejected")
            row.pop("generation", None)
    require(observed_state == expected_state, "current_target_restore_rejected")
    identity = completed.get("identity")
    require(isinstance(identity, dict), "current_target_restore_rejected")
    require(
        upgrade.describe_opaque_state(
            _rooted(root, upgrade.STATE_ROOT),
            expected_uid=int(identity["service_uid"]),
            expected_gid=int(identity["service_gid"]),
        )
        == exact_state,
        "current_target_restore_rejected",
    )


def _restore_current_target_once(
    *,
    root: Path,
    plan: Mapping[str, object],
    completed: Mapping[str, object],
    evidence: Path,
    runner: Runner,
    unit_state: Mapping[str, object] | None,
) -> None:
    upgrade._stop(runner)
    upgrade._restore_public(
        root, evidence / "current-public", _current_public_adapter(plan)
    )
    exact_state = _restore_action_owned_state(
        root=root,
        plan=plan,
        completed=completed,
        evidence=evidence,
    )
    _start_service_then_socket(runner)
    _verify_current_target_restored(
        root=root,
        plan=plan,
        completed=completed,
        exact_state=exact_state,
        unit_state=unit_state,
    )


def execute_staged_action(
    payload: Mapping[str, object],
    *,
    expected_action: str,
    root: Path = Path("/"),
    unit_state: Mapping[str, object] | None = None,
    runner: Runner = upgrade._run,
    acceptance_runner: AcceptanceRunner = _run_content_free_acceptance,
    stage_hook: StageHook | None = None,
) -> dict[str, object]:
    if root == Path("/"):
        require(os.geteuid() == 0, "root_required")
    plan, evidence = verify_staged_action(
        payload,
        expected_action=expected_action,
        root=root,
        unit_state=unit_state,
    )
    require(not (evidence / "RECEIPT.json").exists(), "action_replay_rejected")
    completed = validate_completed_evidence(root, read_state_bytes=True)
    journal_path = evidence / "JOURNAL.json"
    journal = _load_action_journal(
        journal_path,
        action=expected_action,
        plan_digest=str(plan["plan_digest"]),
    )
    events = list(journal["events"])

    def advance(stage: str) -> None:
        events.append(stage)
        _write_journal(
            journal_path,
            action=expected_action,
            plan_digest=str(plan["plan_digest"]),
            events=events,
        )
        if stage_hook is not None:
            stage_hook(stage)

    exact_state = _verify_action_owned_state_matches_current(
        root=root,
        plan=plan,
        completed=completed,
        evidence=evidence,
    )
    try:
        upgrade._stop(runner)
        advance("services_stopped")
        require(
            _verify_action_owned_state_matches_current(
                root=root,
                plan=plan,
                completed=completed,
                evidence=evidence,
            )
            == exact_state,
            "action_owned_state_drifted",
        )
        acceptance_sha256: str | None = None
        if expected_action == "repair":
            repair = plan["repair_target"]
            assert isinstance(repair, dict)
            adapter = {
                "active_gateway_runtime": completed["active_gateway_runtime"],
                "identity": completed["identity"],
                "plan_digest": plan["plan_digest"],
                "predecessor": completed["predecessor"],
                "state_prestate": exact_state,
                "target": repair,
            }
            installed = _install_repair_release(
                root=root, adapter=adapter, repair=repair
            )
            advance("release_installed")
            upgrade._apply_target_public(root, installed, adapter)
        else:
            predecessor_path = _rooted(
                root, upgrade.RELEASE_ROOT / upgrade.PREDECESSOR_RELEASE_DIGEST
            )
            upgrade.validate_predecessor_release(predecessor_path)
            upgrade._restore_public(
                root,
                _rooted(root, COMPLETED_EVIDENCE_ROOT) / "public",
                completed,
            )
        advance("public_applied")
        _start_service_then_socket(runner)
        advance("target_started")
        require(
            _verify_action_owned_state_matches_current(
                root=root,
                plan=plan,
                completed=completed,
                evidence=evidence,
            )
            == exact_state,
            "action_owned_state_drifted",
        )
        if expected_action == "repair":
            upgrade._verify_target(root, adapter)
            advance("protocol_acceptance_called")
            acceptance_sha256 = _validate_content_free_acceptance(
                acceptance_runner(installed)
            )
            advance("target_accepted")
            status = "repair_target_accepted"
        else:
            upgrade._validate_predecessor_public(root)
            advance("predecessor_verified")
            status = "rollback_predecessor_verified"
        receipt = _receipt(
            action=expected_action,
            plan=plan,
            status=status,
            acceptance_projection_sha256=acceptance_sha256,
        )
        upgrade._exclusive_write(
            evidence / "RECEIPT.json", canonical(receipt), mode=0o600
        )
        return receipt
    except Exception as action_error:
        action_code = str(getattr(action_error, "code", "action_failed"))
        try:
            advance("convergence_owned")
            _restore_current_target_once(
                root=root,
                plan=plan,
                completed=completed,
                evidence=evidence,
                runner=runner,
                unit_state=unit_state,
            )
            advance("recovered_current_target")
            failure = _receipt(
                action=expected_action,
                plan=plan,
                status="action_failed_current_target_restored",
                action_failure_code=action_code,
            )
            upgrade._exclusive_write(
                evidence / "RECEIPT.json", canonical(failure), mode=0o600
            )
        except Exception as convergence_error:
            convergence_code = str(
                getattr(convergence_error, "code", "convergence_failed")
            )
            try:
                advance("convergence_failed")
                failure = _receipt(
                    action=expected_action,
                    plan=plan,
                    status="action_failed_convergence_failed",
                    action_failure_code=action_code,
                    convergence_failure_code=convergence_code,
                )
                upgrade._exclusive_write(
                    evidence / "RECEIPT.json", canonical(failure), mode=0o600
                )
            except Exception:
                pass
            raise PostTargetRejected(
                "action_failed_convergence_failed",
                action_failure_code=action_code,
                convergence_failure_code=convergence_code,
            ) from convergence_error
        raise PostTargetRejected(
            "action_failed_current_target_restored",
            action_failure_code=action_code,
        ) from action_error


def recover_interrupted_action(
    payload: Mapping[str, object],
    *,
    expected_action: str,
    root: Path = Path("/"),
    unit_state: Mapping[str, object] | None = None,
    runner: Runner = upgrade._run,
) -> dict[str, object]:
    if root == Path("/"):
        require(os.geteuid() == 0, "root_required")
    plan = validate_action_plan(payload, expected_action=expected_action)
    completed = validate_completed_evidence(root, read_state_bytes=True)
    require(
        validate_failed_acceptance_receipt(root) == plan["failure_receipt"]
        and _predecessor_backup_binding(root, completed)
        == plan["predecessor_backup"],
        "interrupted_action_origin_rejected",
    )
    evidence = _action_evidence(root, plan)
    _validate_owned_directory(evidence, code="staged_action_rejected")
    _validate_owned_file(
        evidence / "PLAN.json", canonical(plan), code="staged_plan_rejected"
    )
    require(
        _load_json(evidence / "PLAN.json", code="staged_plan_rejected") == plan,
        "staged_plan_rejected",
    )
    _, _, ledger_schema, _ = _schemas(expected_action)
    ledger = {
        "action": expected_action,
        "attempts": 1,
        "consumed": True,
        "incident_digest": plan["incident"]["incident_digest"],
        "plan_digest": plan["plan_digest"],
        "schema": ledger_schema,
    }
    _validate_owned_file(
        evidence / "LEDGER.json", canonical(ledger), code="action_ledger_rejected"
    )
    require(
        _load_json(evidence / "LEDGER.json", code="action_ledger_rejected")
        == ledger
        and not (evidence / "RECEIPT.json").exists(),
        "interrupted_action_replay_rejected",
    )
    upgrade._validate_public_backup(
        evidence / "current-public", _current_public_adapter(plan)
    )
    _load_action_owned_state_backup(
        root=root,
        plan=plan,
        completed=completed,
        evidence=evidence,
    )
    journal_path = evidence / "JOURNAL.json"
    journal = _load_action_journal(
        journal_path,
        action=expected_action,
        plan_digest=str(plan["plan_digest"]),
    )
    _validate_owned_file(
        journal_path, canonical(journal), code="action_journal_rejected"
    )
    events = list(journal["events"])
    require(
        journal["stage"] not in {"target_accepted", "predecessor_verified"},
        "interrupted_action_already_terminal",
    )
    require(
        "convergence_owned" not in events,
        "interrupted_convergence_already_consumed",
    )
    require(
        "attempt_owned" in events,
        "interrupted_before_attempt_no_recovery",
    )
    events.append("convergence_owned")
    _write_journal(
        journal_path,
        action=expected_action,
        plan_digest=str(plan["plan_digest"]),
        events=events,
    )
    try:
        _restore_current_target_once(
            root=root,
            plan=plan,
            completed=completed,
            evidence=evidence,
            runner=runner,
            unit_state=unit_state,
        )
        events.append("recovered_current_target")
        _write_journal(
            journal_path,
            action=expected_action,
            plan_digest=str(plan["plan_digest"]),
            events=events,
        )
        receipt = _receipt(
            action=expected_action,
            plan=plan,
            status="interrupted_action_current_target_restored",
            action_failure_code="interrupted_action",
        )
        upgrade._exclusive_write(
            evidence / "RECEIPT.json", canonical(receipt), mode=0o600
        )
        return receipt
    except Exception as convergence_error:
        convergence_code = str(
            getattr(convergence_error, "code", "convergence_failed")
        )
        events.append("convergence_failed")
        _write_journal(
            journal_path,
            action=expected_action,
            plan_digest=str(plan["plan_digest"]),
            events=events,
        )
        receipt = _receipt(
            action=expected_action,
            plan=plan,
            status="interrupted_action_convergence_failed",
            action_failure_code="interrupted_action",
            convergence_failure_code=convergence_code,
        )
        upgrade._exclusive_write(
            evidence / "RECEIPT.json", canonical(receipt), mode=0o600
        )
        raise PostTargetRejected(
            "interrupted_action_convergence_failed",
            action_failure_code="interrupted_action",
            convergence_failure_code=convergence_code,
        ) from convergence_error


def execute_live_action(
    payload: Mapping[str, object], *, expected_action: str
) -> dict[str, object]:
    stage_action_plan(payload, expected_action=expected_action, root=Path("/"))
    return execute_staged_action(
        payload,
        expected_action=expected_action,
        root=Path("/"),
        runner=upgrade._run,
        acceptance_runner=_run_content_free_acceptance,
    )


def recover_live_action(
    payload: Mapping[str, object], *, expected_action: str
) -> dict[str, object]:
    return recover_interrupted_action(
        payload,
        expected_action=expected_action,
        root=Path("/"),
        runner=upgrade._run,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_repair = commands.add_parser("prepare-repair")
    prepare_repair.add_argument("--repair-release", type=Path, required=True)
    commands.add_parser("prepare-rollback")
    preflight_repair = commands.add_parser("preflight-repair")
    preflight_repair.add_argument("--repair-release", type=Path, required=True)
    preflight_repair.add_argument("--synthetic-root", type=Path)
    preflight_rollback = commands.add_parser("preflight-rollback")
    preflight_rollback.add_argument("--synthetic-root", type=Path)
    for command in (
        "execute-repair",
        "execute-rollback",
        "recover-repair",
        "recover-rollback",
    ):
        selected = commands.add_parser(command)
        selected.add_argument("--plan", type=Path, required=True)
    values = parser.parse_args(argv)
    try:
        if values.command == "prepare-repair":
            result = prepare_action(
                action="repair", repair_release=values.repair_release.resolve()
            )
        elif values.command == "prepare-rollback":
            result = prepare_action(action="rollback")
        elif values.command == "preflight-repair":
            selected_root = (
                values.synthetic_root.resolve()
                if values.synthetic_root is not None
                else Path("/")
            )
            require(
                selected_root != Path("/") or values.synthetic_root is None,
                "synthetic_root_rejected",
            )
            result = preflight_action(
                action="repair",
                repair_release=values.repair_release.resolve(),
                root=selected_root,
                unit_state=(
                    READY_UNIT_STATE
                    if values.synthetic_root is not None
                    else None
                ),
            )
        elif values.command == "preflight-rollback":
            selected_root = (
                values.synthetic_root.resolve()
                if values.synthetic_root is not None
                else Path("/")
            )
            require(
                selected_root != Path("/") or values.synthetic_root is None,
                "synthetic_root_rejected",
            )
            result = preflight_action(
                action="rollback",
                root=selected_root,
                unit_state=(
                    READY_UNIT_STATE
                    if values.synthetic_root is not None
                    else None
                ),
            )
        else:
            action = "repair" if values.command.endswith("repair") else "rollback"
            payload = _load_json(values.plan.resolve(), code="action_plan_file_rejected")
            if values.command.startswith("execute-"):
                result = execute_live_action(payload, expected_action=action)
            else:
                result = recover_live_action(payload, expected_action=action)
    except PostTargetRejected as exc:
        print(
            canonical(
                {
                    "code": exc.code,
                    "schema": "myuna.p08-post-target-action-cli-result.v1",
                    "status": "rejected",
                }
            ).decode("ascii")
        )
        return 2
    except Exception:
        print(
            canonical(
                {
                    "code": "unexpected_failure",
                    "schema": "myuna.p08-post-target-action-cli-result.v1",
                    "status": "rejected",
                }
            ).decode("ascii")
        )
        return 3
    print(canonical(result).decode("ascii"))
    return 0


def simulate_staged_action(
    payload: Mapping[str, object],
    *,
    expected_action: str,
    root: Path,
    unit_state: Mapping[str, object],
    runner: Runner,
    acceptance_runner: AcceptanceRunner = _synthetic_content_free_acceptance,
    stage_hook: StageHook | None = None,
) -> dict[str, object]:
    require(root != Path("/"), "synthetic_root_rejected")
    return execute_staged_action(
        payload,
        expected_action=expected_action,
        root=root,
        unit_state=unit_state,
        runner=runner,
        acceptance_runner=acceptance_runner,
        stage_hook=stage_hook,
    )


if __name__ == "__main__":
    raise SystemExit(main())
