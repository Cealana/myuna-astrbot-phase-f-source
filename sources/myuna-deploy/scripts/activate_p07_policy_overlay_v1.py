#!/usr/bin/env python3
"""Exact-parent P07 projection-policy overlay activation and rollback.

The accepted generation-13 release set and schema-v3 epoch remain immutable.
This controller only changes the selected Core/runtime composite and the four
protected policy-overlay documents.  Preflight is content-free and performs no
backup, attempt-ledger, service, selector, or overlay mutation.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import time
from typing import Mapping

import activate_p08_active_temporal_context_v1 as p08_activation
from activate_p07_d_generation13_v1 import (
    CORE_CREDENTIAL_SOURCE,
    CORE_DROPIN_ROOT,
    EFFECTIVE_CREDENTIAL,
    EFFECTIVE_V6_ENV,
    OWNER_RUNTIME_CONFIG,
    RELEASE_SET_PATH,
    _credential_projection,
    _load_v6_release,
)
from activate_p07_external_epoch_rollover_v1 import (
    CORE_SERVICE,
    SELECTOR_PATH,
    TELEGRAM_CONFIG,
    TELEGRAM_DROPIN,
    load_target_runtime_config_snapshot,
)
from activate_p07_hybrid_external_generation_v1 import (
    CONTAINER,
    CORE_BINDING,
    CORE_GATE,
    CORE_RELEASE_ROOT,
    CORE_SELECTOR,
    PLUGIN_ROOT,
    RUNTIME_ROOT,
    TELEGRAM_RUNTIME_USER,
    TELEGRAM_SERVICE,
    TELEGRAM_SOCKET,
    active,
    atomic_write,
    core_evidence,
    digest_file,
    install_tree,
    render_core_binding,
    render_telegram_dropin,
    run,
    show,
    systemctl,
    tree_inventory,
    validate_immutable_release_tree,
    validate_plugin,
    validate_runtime,
    verify_runtime_startup_smoke,
)
from build_p07_policy_overlay_v1 import validate_source, verify_bundle
from external_context_epoch_v3 import (
    ExternalEpochV3Binding,
    ExternalEpochV3Store,
)
from myuna_core.external_context.policy_overlay import (
    POLICY_OVERLAY_MANIFEST_PATH,
    POLICY_OVERLAY_MARKER_PATH,
    POLICY_OVERLAY_SELECTOR_PATH,
    POLICY_OVERLAY_STATE_PATH,
    PolicyOverlay,
    load_selected_policy_overlay,
    require_overlay_component_set,
)
from myuna_core.external_context.release_set import P07DReleaseSet
from p07_d_release_set import load_protected_release_set_snapshot
from p07_d_release_set_acl import inspect_release_set_acl
from p07_policy_overlay_acl import (
    apply_policy_overlay_acl,
    inspect_policy_overlay_acl,
)
from p07_policy_overlay_transaction import (
    AtomicPolicyOverlayTransaction,
    PolicyOverlayObservation,
    PolicyOverlayTransactionRejected,
)


SCHEMA = "myuna.p07-policy-overlay-activation.v1"
ATTEMPT_SCHEMA = "myuna.p07-policy-overlay-attempt-ledger.v1"
STATE_ROOT = Path("/var/lib/myuna-telegram-gateway/p07-policy-overlay-v1")
BACKUP_ROOT = Path("/var/backups/myuna/p07-policy-overlay-v1")
ATTEMPT_LEDGER = STATE_ROOT / "ATTEMPT_LEDGER.json"
MAX_ATTEMPTS = 2
OVERLAY_PATHS = {
    "overlay-manifest.json": POLICY_OVERLAY_MANIFEST_PATH,
    "overlay-marker.json": POLICY_OVERLAY_MARKER_PATH,
    "overlay-selector.json": POLICY_OVERLAY_SELECTOR_PATH,
    "overlay-state.json": POLICY_OVERLAY_STATE_PATH,
}
_SHA = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_TYPED = re.compile(r"^[a-z][a-z0-9_]{2,127}$")


class PolicyOverlayActivationRejected(RuntimeError):
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
        raise PolicyOverlayActivationRejected(code)


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"


def digest_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def digest(domain: str, value: object) -> str:
    return sha256(
        domain.encode("ascii") + b"\0" + canonical(value).rstrip(b"\n")
    ).hexdigest()


def _safe_file(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PolicyOverlayActivationRejected("protected_file_unavailable") from exc
    require(
        not path.is_symlink() and stat.S_ISREG(metadata.st_mode),
        "protected_file_type_rejected",
    )
    return {
        "gid": metadata.st_gid,
        "mode": stat.S_IMODE(metadata.st_mode),
        "path": path.as_posix(),
        "sha256": digest_file(path),
        "size": metadata.st_size,
        "uid": metadata.st_uid,
    }


def _absent(path: Path) -> bool:
    return not path.exists() and not path.is_symlink()


def _require_overlay_absent() -> None:
    require(
        all(_absent(path) for path in OVERLAY_PATHS.values()),
        "policy_overlay_prestate_not_absent",
    )


def _verify_rollback_roots() -> dict[str, object]:
    parents = {
        "backup_parent": BACKUP_ROOT.parent,
        "overlay_parent": POLICY_OVERLAY_MANIFEST_PATH.parent,
        "state_parent": STATE_ROOT.parent,
    }
    expected_owners = {
        "backup_parent": pwd.getpwnam("myuna").pw_uid,
        "overlay_parent": 0,
        "state_parent": pwd.getpwnam(TELEGRAM_RUNTIME_USER).pw_uid,
    }
    projections: dict[str, object] = {}
    for name, path in parents.items():
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise PolicyOverlayActivationRejected(
                "policy_overlay_rollback_parent_unavailable"
            ) from exc
        require(
            not path.is_symlink()
            and stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == expected_owners[name]
            and stat.S_IMODE(metadata.st_mode) & 0o002 == 0,
            "policy_overlay_rollback_parent_rejected",
        )
        projections[name] = {
            "device": metadata.st_dev,
            "gid": metadata.st_gid,
            "mode": stat.S_IMODE(metadata.st_mode),
            "path": path.as_posix(),
            "uid": metadata.st_uid,
        }
    require(
        parents["backup_parent"].stat().st_dev
        == parents["overlay_parent"].stat().st_dev,
        "policy_overlay_rollback_filesystem_rejected",
    )
    for tool in (Path("/usr/bin/getfacl"), Path("/usr/bin/setfacl")):
        metadata = tool.lstat()
        require(
            not tool.is_symlink()
            and stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == 0
            and os.access(tool, os.X_OK),
            "policy_overlay_acl_tool_rejected",
        )
    return projections


def _service(unit: str) -> dict[str, object]:
    restarts = show(unit, "NRestarts")
    require(
        restarts.isdigit() or (unit.endswith(".socket") and restarts == ""),
        "service_restart_projection_rejected",
    )
    return {
        "active_state": show(unit, "ActiveState"),
        "nrestarts": int(restarts or "0"),
        "result": show(unit, "Result"),
        "sub_state": show(unit, "SubState"),
        "unit": unit,
    }


def _services() -> tuple[dict[str, object], ...]:
    return tuple(
        _service(unit)
        for unit in (
            CORE_SERVICE,
            TELEGRAM_SERVICE,
            TELEGRAM_SOCKET,
            p08_activation.SERVICE,
            p08_activation.SOCKET,
        )
    )


def _services_stable(values: tuple[dict[str, object], ...]) -> bool:
    return all(
        item["active_state"] == "active"
        and item["result"] == "success"
        and item["sub_state"] in {"running", "listening"}
        for item in values
    )


def _container_projection() -> dict[str, object]:
    value = run(
        [
            "/usr/bin/docker",
            "inspect",
            CONTAINER,
            "--format",
            "{{.State.Status}} {{.RestartCount}}",
        ],
        timeout=30,
    ).split()
    require(
        len(value) == 2 and value[0] == "running" and value[1].isdigit(),
        "telegram_container_rejected",
    )
    return {"restart_count": int(value[1]), "status": value[0]}


def _release_from_working_directory(unit: str) -> str:
    candidate = Path(show(unit, "WorkingDirectory")).name
    require(_SHA.fullmatch(candidate) is not None, "core_release_projection_rejected")
    return candidate


def _runtime_from_exec_start() -> str:
    selected = re.findall(r"/telegram-owner-runtime/([0-9a-f]{64})/runtime/", show(TELEGRAM_SERVICE, "ExecStart"))
    require(len(set(selected)) == 1, "runtime_release_projection_rejected")
    return selected[0]


def _plugin_projection() -> tuple[str, str]:
    projection = _safe_file(TELEGRAM_CONFIG)
    try:
        payload = json.loads(TELEGRAM_CONFIG.read_text("ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PolicyOverlayActivationRejected("plugin_config_rejected") from exc
    require(
        isinstance(payload, Mapping)
        and isinstance(payload.get("gateway_release"), str)
        and _SHA.fullmatch(str(payload["gateway_release"])) is not None,
        "plugin_config_rejected",
    )
    return str(payload["gateway_release"]), str(projection["sha256"])


def _epoch_metadata(
    parent: P07DReleaseSet,
    *,
    expected_revision: int,
    expected_turns: int,
    expected_summaries: int,
) -> dict[str, object]:
    runtime = load_target_runtime_config_snapshot()
    observed = ExternalEpochV3Store.inspect_existing_metadata(
        str(parent.epoch["database_path"]),
        epoch_id=str(parent.epoch["epoch_id"]),
        release_set_id=parent.release_set_id,
        binding=ExternalEpochV3Binding(
            channel_kind=runtime.config.channel_kind,
            client_id="telegram-owner-private",
            principal_id=runtime.config.principal_id,
            namespace_id=runtime.config.namespace_id,
        ),
        expected_uid=int(parent.epoch["uid"]),
        expected_gid=int(parent.epoch["gid"]),
    )
    require(
        observed.get("schema") == "myuna.external-authorized-epoch.v3"
        and observed.get("selected_revision") == expected_revision
        and observed.get("max_revision") == expected_revision
        and observed.get("turn_count") == expected_turns
        and observed.get("summary_count") == expected_summaries
        and observed.get("pending_count") == 0
        and observed.get("queued_summary_count") == 0
        and observed.get("blocked_summary_count") == 0
        and observed.get("abandoned_delivery_count") == 0,
        "policy_overlay_epoch_metadata_rejected",
    )
    return observed


def _attempt_count() -> int:
    if _absent(ATTEMPT_LEDGER):
        return 0
    try:
        metadata = ATTEMPT_LEDGER.lstat()
        payload = json.loads(ATTEMPT_LEDGER.read_text("ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PolicyOverlayActivationRejected("policy_overlay_attempt_ledger_rejected") from exc
    require(
        not ATTEMPT_LEDGER.is_symlink()
        and stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == 0
        and stat.S_IMODE(metadata.st_mode) == 0o600
        and isinstance(payload, Mapping)
        and set(payload) == {"attempts", "last_plan_sha256", "schema"}
        and payload["schema"] == ATTEMPT_SCHEMA
        and type(payload["attempts"]) is int
        and 0 <= int(payload["attempts"]) <= MAX_ATTEMPTS
        and _SHA.fullmatch(str(payload["last_plan_sha256"])) is not None,
        "policy_overlay_attempt_ledger_rejected",
    )
    return int(payload["attempts"])


def _overlay_from_bundle(bundle_root: Path, parent: P07DReleaseSet) -> tuple[dict[str, object], PolicyOverlay, dict[str, bytes]]:
    manifest = verify_bundle(bundle_root, parent_release_set=parent)
    documents = {
        name: (bundle_root / name).read_bytes() for name in OVERLAY_PATHS
    }
    try:
        overlay = PolicyOverlay.from_payload(json.loads(documents["overlay-manifest.json"].decode("ascii")))
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise PolicyOverlayActivationRejected("policy_overlay_bundle_rejected") from exc
    return manifest, overlay, documents


@dataclass(slots=True)
class PreparedPolicyOverlayActivation:
    core_candidate: Path
    runtime_candidate: Path
    plugin_candidate: Path
    bundle_root: Path
    core_commit: str
    deploy_commit: str
    parent: P07DReleaseSet
    parent_manifest_digest: str
    parent_selector_digest: str
    overlay: PolicyOverlay
    overlay_documents: dict[str, bytes]
    overlay_bundle_manifest: dict[str, object]
    core_release: str
    runtime_release: str
    plugin_release: str
    plugin_config_digest: str
    target_core_binding: bytes
    target_core_selector: bytes
    target_telegram_dropin: bytes
    prestate: dict[str, object]
    prestate_payloads: dict[str, bytes]
    plan_bytes: bytes
    expected_revision: int
    expected_turns: int
    expected_summaries: int

    @property
    def plan_digest(self) -> str:
        return digest_bytes(self.plan_bytes)


def prepare_activation(
    *,
    core_source: Path,
    deploy_source: Path,
    core_candidate: Path,
    runtime_candidate: Path,
    plugin_candidate: Path,
    overlay_bundle: Path,
    core_commit: str,
    deploy_commit: str,
    expected_parent_release_set_id: str,
    expected_parent_manifest_digest: str,
    expected_parent_selector_digest: str,
    expected_live_core_release: str,
    expected_live_runtime_release: str,
    expected_plugin_release: str,
    expected_plugin_config_digest: str,
    expected_effective_v6_digest: str,
    expected_revision: int,
    expected_turns: int,
    expected_summaries: int,
    expected_attempts: int,
) -> PreparedPolicyOverlayActivation:
    require(os.geteuid() == 0, "root_identity_required")
    for value in (
        expected_parent_release_set_id,
        expected_parent_manifest_digest,
        expected_parent_selector_digest,
        expected_live_core_release,
        expected_live_runtime_release,
        expected_plugin_release,
        expected_plugin_config_digest,
        expected_effective_v6_digest,
    ):
        require(_SHA.fullmatch(value) is not None, "expected_digest_rejected")
    require(
        _COMMIT.fullmatch(core_commit) is not None
        and _COMMIT.fullmatch(deploy_commit) is not None,
        "source_commit_rejected",
    )
    validate_source(core_source, core_commit)
    validate_source(deploy_source, deploy_commit)
    require(_attempt_count() == expected_attempts, "policy_overlay_attempt_lineage_drifted")
    require(expected_attempts == 0, "policy_overlay_attempt_one_required")
    _require_overlay_absent()
    require(_absent(STATE_ROOT) and _absent(BACKUP_ROOT), "policy_overlay_series_preexisting")
    rollback_roots = _verify_rollback_roots()

    snapshot = load_protected_release_set_snapshot(RELEASE_SET_PATH, expected_uid=0, expected_gid=0)
    parent = snapshot.release_set
    require(
        parent.generation == 13
        and parent.release_set_id == expected_parent_release_set_id
        and snapshot.file_digest == expected_parent_manifest_digest
        and parent.selector["digest"] == expected_parent_selector_digest
        and digest_file(SELECTOR_PATH) == expected_parent_selector_digest
        and parent.epoch["epoch_id"] == "telegram-owner-private-external-d-reset-v7",
        "policy_overlay_parent_drifted",
    )
    core_identity = pwd.getpwnam("myuna")
    telegram_identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
    inspect_release_set_acl(
        RELEASE_SET_PATH,
        core_uid=core_identity.pw_uid,
        telegram_uid=telegram_identity.pw_uid,
    )
    runtime_config = load_target_runtime_config_snapshot()
    require(
        runtime_config.content_sha256 == parent.runtime_config["digest"],
        "policy_overlay_runtime_config_drifted",
    )
    credential = _credential_projection()
    require(
        credential["effective_count"] == parent.credential["effective_count"] == 1
        and credential["dropin_set_digest"] == parent.credential["dropin_set_digest"]
        and credential["projection_digest"] == parent.credential["projection_digest"],
        "policy_overlay_credential_drifted",
    )
    require(
        _release_from_working_directory(CORE_SERVICE) == expected_live_core_release
        and _runtime_from_exec_start() == expected_live_runtime_release,
        "policy_overlay_live_release_drifted",
    )
    plugin_release, plugin_config_digest = _plugin_projection()
    require(
        plugin_release == expected_plugin_release
        and plugin_config_digest == expected_plugin_config_digest,
        "policy_overlay_plugin_drifted",
    )
    require(
        digest_file(EFFECTIVE_V6_ENV) == expected_effective_v6_digest
        and _load_v6_release().startswith("v6-"),
        "policy_overlay_effective_v6_drifted",
    )
    require(
        active(CORE_SERVICE)
        and active(TELEGRAM_SERVICE)
        and active(TELEGRAM_SOCKET)
        and active(p08_activation.SERVICE)
        and active(p08_activation.SOCKET),
        "policy_overlay_service_prestate_rejected",
    )
    first_services = _services()
    first_container = _container_projection()
    time.sleep(0.25)
    second_services = _services()
    second_container = _container_projection()
    require(
        first_services == second_services
        and first_container == second_container
        and _services_stable(second_services),
        "policy_overlay_live_prestate_unstable",
    )
    epoch = _epoch_metadata(
        parent,
        expected_revision=expected_revision,
        expected_turns=expected_turns,
        expected_summaries=expected_summaries,
    )

    core, _artifact, _receipt = core_evidence(core_candidate)
    require(
        core.source_commit == core_commit and core.tree_sha256 == core_candidate.name,
        "policy_overlay_core_candidate_rejected",
    )
    runtime_release = validate_runtime(runtime_candidate, core_commit, deploy_commit)
    verify_runtime_startup_smoke(runtime_candidate)
    plugin_candidate_release = validate_plugin(plugin_candidate)
    require(
        plugin_candidate_release == plugin_release == plugin_candidate.name,
        "policy_overlay_plugin_candidate_rejected",
    )
    bundle_manifest, overlay, overlay_documents = _overlay_from_bundle(overlay_bundle, parent)
    require(
        bundle_manifest.get("source")
        == {"core_commit": core_commit, "deploy_commit": deploy_commit},
        "policy_overlay_bundle_source_rejected",
    )
    require_overlay_component_set(
        overlay,
        core_release_digest=core.tree_sha256,
        runtime_release_digest=runtime_release,
        plugin_release_digest=plugin_release,
        plugin_config_digest=plugin_config_digest,
    )

    prestate_files = {
        "core_binding": _safe_file(CORE_BINDING),
        "core_gate": _safe_file(CORE_GATE),
        "core_selector": _safe_file(CORE_SELECTOR),
        "effective_v6": _safe_file(EFFECTIVE_V6_ENV),
        "epoch_selector": _safe_file(SELECTOR_PATH),
        "owner_runtime_config": _safe_file(OWNER_RUNTIME_CONFIG),
        "parent_manifest": _safe_file(RELEASE_SET_PATH),
        "telegram_config": _safe_file(TELEGRAM_CONFIG),
        "telegram_dropin": _safe_file(TELEGRAM_DROPIN),
    }
    prestate = {
        "container": second_container,
        "credential": credential,
        "epoch": epoch,
        "files": prestate_files,
        "live": {
            "core_release": expected_live_core_release,
            "plugin_release": plugin_release,
            "runtime_release": expected_live_runtime_release,
        },
        "overlay_absent": True,
        "parent_release_set_id": parent.release_set_id,
        "services": list(second_services),
    }
    prestate_digest = digest("myuna-p07-policy-overlay-prestate-v1", prestate)
    approval_seed = digest(
        "myuna-p07-policy-overlay-approval-seed-v1",
        {
            "bundle_id": bundle_manifest["bundle_id"],
            "core_commit": core_commit,
            "core_release": core.tree_sha256,
            "deploy_commit": deploy_commit,
            "executor_sha256": digest_file(Path(__file__).resolve()),
            "prestate_digest": prestate_digest,
            "runtime_release": runtime_release,
        },
    )
    core_binding, core_selector = render_core_binding(core, approval_seed)
    telegram_dropin = render_telegram_dropin(runtime_release)
    acl_contract = {
        "core_uid": core_identity.pw_uid,
        "file_gid": runtime_config.gid,
        "file_mode": 0o640,
        "file_uid": 0,
        "telegram_uid": telegram_identity.pw_uid,
    }
    plan = {
        "attempt": {"maximum": MAX_ATTEMPTS, "next": 1, "prior": expected_attempts},
        "boundaries": {
            "channel_called": False,
            "database_rows_read": False,
            "epoch_rewritten": False,
            "health_called": False,
            "model_called": False,
            "private_content_read": False,
            "provider_called": False,
        },
        "executor_sha256": digest_file(Path(__file__).resolve()),
        "overlay": {
            "acl_contract": acl_contract,
            "bundle_id": bundle_manifest["bundle_id"],
            "bundle_manifest_sha256": digest_file(overlay_bundle / "bundle-manifest.json"),
            "documents": {
                name: digest_bytes(payload)
                for name, payload in sorted(overlay_documents.items())
            },
            "overlay_id": overlay.overlay_id,
        },
        "parent": {
            "epoch_id": parent.epoch["epoch_id"],
            "manifest_sha256": snapshot.file_digest,
            "release_set_id": parent.release_set_id,
            "selector_sha256": digest_file(SELECTOR_PATH),
        },
        "prestate_digest": prestate_digest,
        "rollback": {
            "active_overlay_absent": True,
            "exact_config_bytes": True,
            "functional_service_acceptance": True,
            "persistent_epoch_rewritten": False,
            "roots": rollback_roots,
        },
        "schema": SCHEMA,
        "source": {"core_commit": core_commit, "deploy_commit": deploy_commit},
        "target": {
            "approval_seed": approval_seed,
            "core_binding_sha256": digest_bytes(core_binding),
            "core_release": core.tree_sha256,
            "core_selector_sha256": digest_bytes(core_selector),
            "plugin_config_sha256": plugin_config_digest,
            "plugin_release": plugin_release,
            "runtime_release": runtime_release,
            "telegram_dropin_sha256": digest_bytes(telegram_dropin),
        },
    }
    return PreparedPolicyOverlayActivation(
        core_candidate=core_candidate,
        runtime_candidate=runtime_candidate,
        plugin_candidate=plugin_candidate,
        bundle_root=overlay_bundle,
        core_commit=core_commit,
        deploy_commit=deploy_commit,
        parent=parent,
        parent_manifest_digest=snapshot.file_digest,
        parent_selector_digest=digest_file(SELECTOR_PATH),
        overlay=overlay,
        overlay_documents=overlay_documents,
        overlay_bundle_manifest=bundle_manifest,
        core_release=core.tree_sha256,
        runtime_release=runtime_release,
        plugin_release=plugin_release,
        plugin_config_digest=plugin_config_digest,
        target_core_binding=core_binding,
        target_core_selector=core_selector,
        target_telegram_dropin=telegram_dropin,
        prestate=prestate,
        prestate_payloads={
            "CORE_BINDING": CORE_BINDING.read_bytes(),
            "CORE_SELECTOR": CORE_SELECTOR.read_bytes(),
            "TELEGRAM_DROPIN": TELEGRAM_DROPIN.read_bytes(),
        },
        plan_bytes=canonical(plan),
        expected_revision=expected_revision,
        expected_turns=expected_turns,
        expected_summaries=expected_summaries,
    )


def preflight_projection(prepared: PreparedPolicyOverlayActivation) -> dict[str, object]:
    return {
        "attempts": 0,
        "channel_called": False,
        "health_called": False,
        "maximum_attempts": MAX_ATTEMPTS,
        "model_called": False,
        "mutation_performed": False,
        "next_attempt": 1,
        "overlay_bundle_id": prepared.overlay_bundle_manifest["bundle_id"],
        "overlay_id": prepared.overlay.overlay_id,
        "parent_release_set_id": prepared.parent.release_set_id,
        "plan_sha256": prepared.plan_digest,
        "private_content_read": False,
        "provider_called": False,
        "schema": SCHEMA,
        "status": "ready",
    }


class LivePolicyOverlayBackend:
    def __init__(self, prepared: PreparedPolicyOverlayActivation) -> None:
        self.prepared = prepared
        self.backup_root = BACKUP_ROOT / prepared.plan_digest

    def create_plan_bound_backup(self) -> None:
        require(_absent(BACKUP_ROOT), "policy_overlay_backup_root_preexisting")
        BACKUP_ROOT.mkdir(parents=True, mode=0o700)
        os.chown(BACKUP_ROOT, 0, 0)
        os.chmod(BACKUP_ROOT, 0o700)
        require(
            BACKUP_ROOT.stat().st_dev == POLICY_OVERLAY_MANIFEST_PATH.parent.stat().st_dev,
            "policy_overlay_backup_filesystem_rejected",
        )
        self.backup_root.mkdir(mode=0o700)
        os.chown(self.backup_root, 0, 0)
        atomic_write(self.backup_root / "PLAN.json", self.prepared.plan_bytes, mode=0o600)
        atomic_write(self.backup_root / "PRESTATE.json", canonical(self.prepared.prestate), mode=0o600)
        for name, payload in self.prepared.prestate_payloads.items():
            atomic_write(self.backup_root / name, payload, mode=0o600)

    def consume_attempt(self) -> int:
        require(_attempt_count() == 0, "policy_overlay_attempt_lineage_drifted")
        STATE_ROOT.mkdir(parents=True, mode=0o700)
        os.chown(STATE_ROOT, 0, 0)
        os.chmod(STATE_ROOT, 0o700)
        atomic_write(
            ATTEMPT_LEDGER,
            canonical({"attempts": 1, "last_plan_sha256": self.prepared.plan_digest, "schema": ATTEMPT_SCHEMA}),
            mode=0o600,
        )
        return 1

    def install_inactive_releases(self) -> None:
        core_gid = pwd.getpwnam("myuna").pw_gid
        telegram_gid = pwd.getpwnam(TELEGRAM_RUNTIME_USER).pw_gid
        core_target = CORE_RELEASE_ROOT / self.prepared.core_release
        runtime_target = RUNTIME_ROOT / self.prepared.runtime_release
        install_tree(self.prepared.core_candidate, core_target, gid=core_gid, directory_mode=0o550, file_mode=0o440)
        validate_immutable_release_tree(core_target, core_evidence(self.prepared.core_candidate)[0])
        install_tree(self.prepared.runtime_candidate, runtime_target, gid=telegram_gid, directory_mode=0o550, file_mode=0o440)
        require(
            tree_inventory(self.prepared.runtime_candidate) == tree_inventory(runtime_target),
            "policy_overlay_installed_runtime_drifted",
        )

    def stop_target_services(self) -> None:
        systemctl("stop", TELEGRAM_SOCKET, TELEGRAM_SERVICE, CORE_SERVICE)

    def verify_target_services_stopped(self) -> None:
        require(
            not active(CORE_SERVICE)
            and not active(TELEGRAM_SERVICE)
            and not active(TELEGRAM_SOCKET),
            "policy_overlay_services_not_stopped",
        )

    def apply_target(self) -> None:
        _require_overlay_absent()
        runtime_config = load_target_runtime_config_snapshot()
        core_uid = pwd.getpwnam("myuna").pw_uid
        telegram_uid = pwd.getpwnam(TELEGRAM_RUNTIME_USER).pw_uid
        atomic_write(CORE_BINDING, self.prepared.target_core_binding, mode=0o640, gid=pwd.getpwnam("myuna").pw_gid)
        atomic_write(CORE_SELECTOR, self.prepared.target_core_selector, mode=0o644)
        atomic_write(TELEGRAM_DROPIN, self.prepared.target_telegram_dropin, mode=0o644)
        for name in (
            "overlay-manifest.json",
            "overlay-state.json",
            "overlay-selector.json",
            "overlay-marker.json",
        ):
            path = OVERLAY_PATHS[name]
            atomic_write(path, self.prepared.overlay_documents[name], mode=0o600, gid=runtime_config.gid)
            apply_policy_overlay_acl(
                path,
                core_uid=core_uid,
                telegram_uid=telegram_uid,
                file_gid=runtime_config.gid,
            )

    def daemon_reload(self) -> None:
        systemctl("daemon-reload")

    def start_target_services(self) -> None:
        systemctl("start", CORE_SERVICE)
        systemctl("start", TELEGRAM_SOCKET, TELEGRAM_SERVICE)

    def _cross_identity_overlay_smoke(self) -> None:
        runtime_gid = load_target_runtime_config_snapshot().gid
        for user, pythonpath, component, release in (
            ("myuna", CORE_RELEASE_ROOT / self.prepared.core_release / "src", "core", self.prepared.core_release),
            (TELEGRAM_RUNTIME_USER, RUNTIME_ROOT / self.prepared.runtime_release / "runtime", "runtime", self.prepared.runtime_release),
        ):
            program = (
                "import json;from pathlib import Path;"
                "from myuna_core.external_context.release_set import P07DReleaseSet;"
                "from myuna_core.external_context.policy_overlay import load_selected_policy_overlay;"
                f"raw=Path({str(RELEASE_SET_PATH)!r}).read_bytes();"
                "parent=P07DReleaseSet.from_payload(json.loads(raw.decode('ascii')));"
                f"selected=load_selected_policy_overlay(parent_release_set=parent,parent_manifest_file_digest={self.prepared.parent_manifest_digest!r},component_kind={component!r},current_component_release_digest={release!r},expected_uid=0,expected_gid={runtime_gid});"
                f"assert selected is not None and selected.overlay_id=={self.prepared.overlay.overlay_id!r}"
            )
            completed = subprocess.run(
                [
                    "/usr/sbin/runuser",
                    "-u",
                    user,
                    "--",
                    "/usr/bin/env",
                    "-i",
                    "PATH=/usr/bin",
                    f"PYTHONPATH={pythonpath}",
                    "PYTHONDONTWRITEBYTECODE=1",
                    "/usr/bin/python3",
                    "-B",
                    "-c",
                    program,
                ],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
            require(completed.returncode == 0, "policy_overlay_cross_identity_smoke_rejected")

    def _observation(self, *, target: bool) -> PolicyOverlayObservation:
        time.sleep(3)
        snapshot = load_protected_release_set_snapshot(RELEASE_SET_PATH, expected_uid=0, expected_gid=0)
        require(
            snapshot.release_set == self.prepared.parent
            and snapshot.file_digest == self.prepared.parent_manifest_digest
            and digest_file(SELECTOR_PATH) == self.prepared.parent_selector_digest
            and digest_file(TELEGRAM_CONFIG) == self.prepared.plugin_config_digest
            and digest_file(EFFECTIVE_V6_ENV) == self.prepared.prestate["files"]["effective_v6"]["sha256"],
            "policy_overlay_parent_postflight_drifted",
        )
        epoch = _epoch_metadata(
            self.prepared.parent,
            expected_revision=self.prepared.expected_revision,
            expected_turns=self.prepared.expected_turns,
            expected_summaries=self.prepared.expected_summaries,
        )
        services = _services()
        container = _container_projection()
        require(_services_stable(services), "policy_overlay_service_postflight_rejected")
        if target:
            require(
                _release_from_working_directory(CORE_SERVICE) == self.prepared.core_release
                and _runtime_from_exec_start() == self.prepared.runtime_release
                and CORE_BINDING.read_bytes() == self.prepared.target_core_binding
                and CORE_SELECTOR.read_bytes() == self.prepared.target_core_selector
                and TELEGRAM_DROPIN.read_bytes() == self.prepared.target_telegram_dropin,
                "policy_overlay_target_binding_rejected",
            )
            runtime_gid = load_target_runtime_config_snapshot().gid
            core_uid = pwd.getpwnam("myuna").pw_uid
            telegram_uid = pwd.getpwnam(TELEGRAM_RUNTIME_USER).pw_uid
            for name, path in OVERLAY_PATHS.items():
                require(
                    digest_file(path) == digest_bytes(self.prepared.overlay_documents[name]),
                    "policy_overlay_document_drifted",
                )
                inspect_policy_overlay_acl(
                    path,
                    core_uid=core_uid,
                    telegram_uid=telegram_uid,
                    file_gid=runtime_gid,
                )
            self._cross_identity_overlay_smoke()
            state_payload = {
                "container": container,
                "epoch": epoch,
                "overlay_id": self.prepared.overlay.overlay_id,
                "parent_release_set_id": self.prepared.parent.release_set_id,
                "services": [
                    {key: value for key, value in item.items() if key != "nrestarts"}
                    for item in services
                ],
                "target": {"core": self.prepared.core_release, "runtime": self.prepared.runtime_release},
            }
        else:
            _require_overlay_absent()
            require(
                _release_from_working_directory(CORE_SERVICE) == self.prepared.prestate["live"]["core_release"]
                and _runtime_from_exec_start() == self.prepared.prestate["live"]["runtime_release"]
                and CORE_BINDING.read_bytes() == self.prepared.prestate_payloads["CORE_BINDING"]
                and CORE_SELECTOR.read_bytes() == self.prepared.prestate_payloads["CORE_SELECTOR"]
                and TELEGRAM_DROPIN.read_bytes() == self.prepared.prestate_payloads["TELEGRAM_DROPIN"],
                "policy_overlay_rollback_binding_rejected",
            )
            state_payload = {
                "container": container,
                "epoch": epoch,
                "overlay_absent": True,
                "parent_release_set_id": self.prepared.parent.release_set_id,
                "services": [
                    {key: value for key, value in item.items() if key != "nrestarts"}
                    for item in services
                ],
                "target": {
                    "core": self.prepared.prestate["live"]["core_release"],
                    "runtime": self.prepared.prestate["live"]["runtime_release"],
                },
            }
        return PolicyOverlayObservation(
            state_digest=digest("myuna-p07-policy-overlay-functional-observation-v1", state_payload),
            service_restart_total=sum(int(item["nrestarts"]) for item in services) + int(container["restart_count"]),
            services_stable=True,
        )

    def observe_target(self) -> PolicyOverlayObservation:
        return self._observation(target=True)

    def restore_prestate(self) -> None:
        for name in (
            "overlay-marker.json",
            "overlay-selector.json",
            "overlay-manifest.json",
            "overlay-state.json",
        ):
            source = OVERLAY_PATHS[name]
            if not _absent(source):
                destination = self.backup_root / f"FAILED-ACTIVE-{name}"
                require(_absent(destination), "policy_overlay_rollback_evidence_exists")
                os.replace(source, destination)
        atomic_write(CORE_BINDING, self.prepared.prestate_payloads["CORE_BINDING"], mode=int(self.prepared.prestate["files"]["core_binding"]["mode"]), gid=int(self.prepared.prestate["files"]["core_binding"]["gid"]))
        atomic_write(CORE_SELECTOR, self.prepared.prestate_payloads["CORE_SELECTOR"], mode=int(self.prepared.prestate["files"]["core_selector"]["mode"]), gid=int(self.prepared.prestate["files"]["core_selector"]["gid"]))
        atomic_write(TELEGRAM_DROPIN, self.prepared.prestate_payloads["TELEGRAM_DROPIN"], mode=int(self.prepared.prestate["files"]["telegram_dropin"]["mode"]), gid=int(self.prepared.prestate["files"]["telegram_dropin"]["gid"]))

    def observe_prestate(self) -> PolicyOverlayObservation:
        return self._observation(target=False)

    def expected_prestate(self) -> PolicyOverlayObservation:
        services = tuple(self.prepared.prestate["services"])
        container = self.prepared.prestate["container"]
        state_payload = {
            "container": container,
            "epoch": self.prepared.prestate["epoch"],
            "overlay_absent": True,
            "parent_release_set_id": self.prepared.parent.release_set_id,
            "services": [
                {key: value for key, value in item.items() if key != "nrestarts"}
                for item in services
            ],
            "target": {
                "core": self.prepared.prestate["live"]["core_release"],
                "runtime": self.prepared.prestate["live"]["runtime_release"],
            },
        }
        return PolicyOverlayObservation(
            state_digest=digest("myuna-p07-policy-overlay-functional-observation-v1", state_payload),
            service_restart_total=sum(int(item["nrestarts"]) for item in services) + int(container["restart_count"]),
            services_stable=True,
        )


def _failure_projection(exc: BaseException) -> dict[str, str]:
    result: dict[str, str] = {}
    for attribute, field in (
        ("code", "failure_gate"),
        ("activation_failure_code", "activation_failure_gate"),
        ("rollback_failure_code", "rollback_failure_gate"),
    ):
        value = getattr(exc, attribute, None)
        if isinstance(value, str) and _TYPED.fullmatch(value) is not None:
            result[field] = value
    if "failure_gate" not in result:
        result["failure_gate"] = "policy_overlay_activation_rejected"
    return result


def activate(
    prepared: PreparedPolicyOverlayActivation,
    *,
    expected_plan_sha256: str | None,
    preflight_only: bool,
) -> dict[str, object]:
    if expected_plan_sha256 is not None:
        require(prepared.plan_digest == expected_plan_sha256, "policy_overlay_plan_drifted")
    if preflight_only:
        return preflight_projection(prepared)
    require(expected_plan_sha256 is not None, "policy_overlay_expected_plan_required")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backend = LivePolicyOverlayBackend(prepared)
    journal = STATE_ROOT / f"JOURNAL-{stamp}-{prepared.plan_digest[:12]}.json"
    try:
        result = AtomicPolicyOverlayTransaction(backend).run()
        receipt = {
            "attempt": result.attempt,
            "channel_called": False,
            "health_called": False,
            "model_called": False,
            "overlay_id": prepared.overlay.overlay_id,
            "parent_release_set_id": prepared.parent.release_set_id,
            "plan_sha256": prepared.plan_digest,
            "private_content_read": False,
            "provider_called": False,
            "schema": SCHEMA,
            "status": "ACTIVE_WAITING_OWNER_ORGANIC_TELEGRAM_E2E",
        }
        atomic_write(journal, canonical(receipt), mode=0o600)
        atomic_write(STATE_ROOT / f"RECEIPT-{stamp}-{prepared.plan_digest[:12]}.json", canonical(receipt), mode=0o600)
        return receipt
    except PolicyOverlayTransactionRejected as exc:
        failure = {
            "attempt": 1,
            **_failure_projection(exc),
            "plan_sha256": prepared.plan_digest,
            "schema": SCHEMA,
            "status": (
                "hard_stop_rollback_failed"
                if exc.rollback_failure_code is not None
                else "activation_failed_rollback_verified"
            ),
        }
        if STATE_ROOT.exists():
            atomic_write(journal, canonical(failure), mode=0o600)
            atomic_write(STATE_ROOT / f"RECEIPT-{stamp}-{prepared.plan_digest[:12]}.json", canonical(failure), mode=0o600)
        raise PolicyOverlayActivationRejected(
            exc.code,
            activation_failure_code=exc.activation_failure_code,
            rollback_failure_code=exc.rollback_failure_code,
        ) from exc


def parser() -> argparse.ArgumentParser:
    selected = argparse.ArgumentParser()
    selected.add_argument("--core-source", type=Path, required=True)
    selected.add_argument("--deploy-source", type=Path, required=True)
    selected.add_argument("--core-candidate", type=Path, required=True)
    selected.add_argument("--runtime-candidate", type=Path, required=True)
    selected.add_argument("--plugin-candidate", type=Path, required=True)
    selected.add_argument("--overlay-bundle", type=Path, required=True)
    selected.add_argument("--core-commit", required=True)
    selected.add_argument("--deploy-commit", required=True)
    selected.add_argument("--expected-parent-release-set-id", required=True)
    selected.add_argument("--expected-parent-manifest-digest", required=True)
    selected.add_argument("--expected-parent-selector-digest", required=True)
    selected.add_argument("--expected-live-core-release", required=True)
    selected.add_argument("--expected-live-runtime-release", required=True)
    selected.add_argument("--expected-plugin-release", required=True)
    selected.add_argument("--expected-plugin-config-digest", required=True)
    selected.add_argument("--expected-effective-v6-digest", required=True)
    selected.add_argument("--expected-revision", type=int, required=True)
    selected.add_argument("--expected-turns", type=int, required=True)
    selected.add_argument("--expected-summaries", type=int, required=True)
    selected.add_argument("--expected-attempts", type=int, default=0)
    selected.add_argument("--expected-plan-sha256")
    selected.add_argument("--preflight-only", action="store_true")
    return selected


def main() -> int:
    arguments = parser().parse_args()
    try:
        prepared = prepare_activation(
            core_source=arguments.core_source.resolve(),
            deploy_source=arguments.deploy_source.resolve(),
            core_candidate=arguments.core_candidate.resolve(),
            runtime_candidate=arguments.runtime_candidate.resolve(),
            plugin_candidate=arguments.plugin_candidate.resolve(),
            overlay_bundle=arguments.overlay_bundle.resolve(),
            core_commit=arguments.core_commit,
            deploy_commit=arguments.deploy_commit,
            expected_parent_release_set_id=arguments.expected_parent_release_set_id,
            expected_parent_manifest_digest=arguments.expected_parent_manifest_digest,
            expected_parent_selector_digest=arguments.expected_parent_selector_digest,
            expected_live_core_release=arguments.expected_live_core_release,
            expected_live_runtime_release=arguments.expected_live_runtime_release,
            expected_plugin_release=arguments.expected_plugin_release,
            expected_plugin_config_digest=arguments.expected_plugin_config_digest,
            expected_effective_v6_digest=arguments.expected_effective_v6_digest,
            expected_revision=arguments.expected_revision,
            expected_turns=arguments.expected_turns,
            expected_summaries=arguments.expected_summaries,
            expected_attempts=arguments.expected_attempts,
        )
        result = activate(
            prepared,
            expected_plan_sha256=arguments.expected_plan_sha256,
            preflight_only=arguments.preflight_only,
        )
    except Exception as exc:
        print(json.dumps({"schema": SCHEMA, "status": "rejected", **_failure_projection(exc)}, separators=(",", ":"), sort_keys=True))
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
