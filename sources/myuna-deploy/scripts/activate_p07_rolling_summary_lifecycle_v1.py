#!/usr/bin/env python3
"""One-attempt generation-6 activation for the P07-D rolling-summary epoch."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import grp
import json
import os
from pathlib import Path
import pwd
import re
import sqlite3
import stat
import subprocess
import time

from activate_p07_hybrid_external_generation_v1 import (
    ActivationRejected, CORE_BINDING, CORE_GATE, CORE_RELEASE_ROOT,
    CORE_SELECTOR, RUNTIME_ROOT, TELEGRAM_RUNTIME_USER, TELEGRAM_SERVICE,
    TELEGRAM_SOCKET, active, atomic_write, canonical, core_evidence,
    digest_bytes, digest_file, install_tree, optional_bytes, read_json,
    render_core_binding, render_core_gate, render_telegram_dropin,
    restore_optional, show, systemctl, tree_inventory,
    validate_immutable_release_tree, validate_runtime, VERIFIER_PATH,
    verify_credential_binding, verify_effective_credential,
    verify_runtime_startup_smoke,
)
from activate_p07_external_epoch_rollover_v1 import (
    CORE_SERVICE, SELECTOR_PATH, SELECTOR_SCHEMA, TELEGRAM_CONFIG,
    TELEGRAM_DROPIN, NEW_EPOCH_DATABASE as B_V4_EPOCH_DATABASE,
    NEW_EPOCH_ID as B_V4_EPOCH_ID, RolloverRejected, failure_code,
    inspect_epoch_metadata, load_target_runtime_config_snapshot, require,
    require_resume_config_not_binding_source,
    validate_selector_payload as validate_b_v4_selector_payload,
    verify_empty_epoch_from_runtime_config, verify_new_epoch_startup_smoke,
)
from external_context_epoch import (
    SQLITE_SCHEMA, SQLITE_SCHEMA_VERSION, ExternalEpochRejected,
)
from external_epoch_bundle import (
    BUNDLE_SCHEMA, ExternalEpochBundleRejected, inspect_epoch_bundle,
    require_same_bundle, restore_epoch_bundle_permissions, seal_epoch_bundle,
)


SCHEMA = "myuna.p07-rolling-summary-activation.v2"
NEW_EPOCH_ID = "telegram-owner-private-external-d-v2"
NEW_EPOCH_DATABASE = (
    Path("/var/lib/myuna-telegram-gateway/external-context-epochs")
    / NEW_EPOCH_ID / "epoch.db"
)
GENERATION = 6
BACKUP_ROOT = Path("/var/backups/myuna/p07-rolling-summary-activation-v1")
STATE_ROOT = Path("/var/lib/myuna-telegram-gateway/p07-rolling-summary-activation-v1")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def verify_core_response_contract(core_candidate: Path) -> None:
    """Require the Core response field that generation 6 commits durably."""
    probe = (
        "from myuna_core.external_context.live import HybridPublicResult;"
        "from myuna_core.providers.base import ModelResponse;"
        "r=ModelResponse(provider='synthetic',model='synthetic',text='ok',"
        "input_tokens=0,output_tokens=0,cache_hit_tokens=0,cache_miss_tokens=0,"
        "reasoning_tokens=0,finish_reason='stop');"
        "p=HybridPublicResult(request_id='synthetic',reply='ok',response=r,"
        "repaired=False).public_payload();"
        "assert 'external_turn_provenance' in p and p['external_turn_provenance'] is None"
    )
    completed = subprocess.run(
        ["/usr/bin/python3", "-B", "-c", probe],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        env={
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": f"{core_candidate / 'src'}",
        },
    )
    require(completed.returncode == 0, "core_response_contract_rejected")


def persist_stopped_bundle_prestate(
    backup_root: Path, bundle_prestate: dict[str, object]
) -> None:
    """Persist the post-stop stable bundle identity needed by later rollback."""
    require(
        isinstance(bundle_prestate.get("bundle_digest"), str)
        and _DIGEST.fullmatch(str(bundle_prestate["bundle_digest"])) is not None,
        "stopped_bundle_prestate_rejected",
    )
    atomic_write(
        backup_root / "STOPPED_BUNDLE_PRESTATE.json",
        canonical(bundle_prestate),
        mode=0o600,
    )


def selector_payload(previous_bundle_digest: str) -> dict[str, object]:
    require(_DIGEST.fullmatch(previous_bundle_digest) is not None,
            "old_epoch_bundle_digest_rejected")
    return {
        "channel_kind": "astrbot_telegram",
        "client_id": "telegram-owner-private",
        "database_path": NEW_EPOCH_DATABASE.as_posix(),
        "epoch_id": NEW_EPOCH_ID,
        "generation": GENERATION,
        "previous_epoch_bundle_digest": previous_bundle_digest,
        "previous_epoch_bundle_schema": BUNDLE_SCHEMA,
        "previous_epoch_id": B_V4_EPOCH_ID,
        "schema": SELECTOR_SCHEMA,
        "status": "active",
    }


def validate_selector_payload(payload: object) -> dict[str, object]:
    require(isinstance(payload, dict) and set(payload) == set(selector_payload("0" * 64)),
            "selector_fields_rejected")
    checks = (
        (payload.get("schema") == SELECTOR_SCHEMA, "selector_schema_rejected"),
        (payload.get("status") == "active", "selector_status_rejected"),
        (payload.get("channel_kind") == "astrbot_telegram", "selector_channel_rejected"),
        (payload.get("client_id") == "telegram-owner-private", "selector_client_rejected"),
        (payload.get("generation") == GENERATION, "selector_generation_rejected"),
        (payload.get("previous_epoch_id") == B_V4_EPOCH_ID, "selector_previous_rejected"),
        (payload.get("epoch_id") == NEW_EPOCH_ID, "selector_epoch_rejected"),
        (payload.get("database_path") == NEW_EPOCH_DATABASE.as_posix(), "selector_path_rejected"),
        (payload.get("previous_epoch_bundle_schema") == BUNDLE_SCHEMA,
         "selector_bundle_schema_rejected"),
    )
    for condition, code in checks:
        require(condition, code)
    digest = payload.get("previous_epoch_bundle_digest")
    require(isinstance(digest, str) and _DIGEST.fullmatch(digest) is not None,
            "selector_digest_rejected")
    return payload


def load_previous_selector() -> tuple[bytes, dict[str, object]]:
    metadata = SELECTOR_PATH.lstat()
    telegram_gid = grp.getgrnam("myuna-gateway-telegram").gr_gid
    require(
        not SELECTOR_PATH.is_symlink() and stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == 0 and metadata.st_gid == telegram_gid
        and stat.S_IMODE(metadata.st_mode) == 0o640,
        "selector_prestate_metadata_rejected",
    )
    raw = SELECTOR_PATH.read_bytes()
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RolloverRejected("selector_prestate_rejected") from exc
    validate_b_v4_selector_payload(payload)
    require(raw == canonical(payload), "selector_prestate_noncanonical_rejected")
    require(
        payload["database_path"] == B_V4_EPOCH_DATABASE.as_posix()
        and payload["epoch_id"] == B_V4_EPOCH_ID and payload["generation"] == 4,
        "selector_prestate_rejected",
    )
    return raw, payload


def require_expected_old_epoch(metadata: dict[str, object], *, revision: int,
                               turns: int, summaries: int, pending: int) -> None:
    checks = (
        (metadata.get("schema_name") == "myuna.external-authorized-epoch.v1", "old_epoch_schema_rejected"),
        (metadata.get("schema_version") == 1, "old_epoch_schema_rejected"),
        (metadata.get("epoch_id") == B_V4_EPOCH_ID, "old_epoch_id_rejected"),
        (metadata.get("selected_revision") == revision, "old_epoch_revision_rejected"),
        (metadata.get("max_revision") == revision, "old_epoch_revision_rejected"),
        (metadata.get("turn_count") == turns, "old_epoch_turn_count_rejected"),
        (metadata.get("summary_count") == summaries, "old_epoch_summary_count_rejected"),
        (metadata.get("pending_count") == pending, "old_epoch_pending_count_rejected"),
        (pending == 0, "old_epoch_pending_rejected"),
    )
    for condition, code in checks:
        require(condition, code)


def inspect_old_bundle(expected_sha256: str) -> dict[str, object]:
    identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
    bundle = inspect_epoch_bundle(
        B_V4_EPOCH_DATABASE, expected_file_mode=0o600,
        expected_parent_mode=0o700, expected_uid=identity.pw_uid,
        expected_gid=identity.pw_gid,
    )
    files = bundle["bundle_projection"]["files"]
    database = next((entry for entry in files if entry.get("name") == "epoch.db"), None)
    require(isinstance(database, dict) and database.get("sha256") == expected_sha256,
            "old_epoch_digest_drifted")
    return bundle


def seal_old_epoch(expected_bundle_digest: str) -> dict[str, object]:
    identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
    return seal_epoch_bundle(
        B_V4_EPOCH_DATABASE, expected_bundle_digest=expected_bundle_digest,
        source_uid=identity.pw_uid, source_gid=identity.pw_gid,
        sealed_gid=grp.getgrnam("myuna-gateway-telegram").gr_gid,
    )


def restore_old_epoch_permissions(prestate: dict[str, object], *,
                                  expected_bundle_digest: str) -> None:
    restore_epoch_bundle_permissions(
        B_V4_EPOCH_DATABASE, prestate=prestate,
        expected_bundle_digest=expected_bundle_digest,
    )


def require_existing_epoch_root(root: Path) -> None:
    metadata = root.lstat()
    telegram_gid = grp.getgrnam("myuna-gateway-telegram").gr_gid
    require(
        not root.is_symlink() and stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == 0 and metadata.st_gid == telegram_gid
        and stat.S_IMODE(metadata.st_mode) == 0o710,
        "epoch_root_metadata_rejected",
    )


def prepare_new_epoch_parent() -> None:
    identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
    root = NEW_EPOCH_DATABASE.parent.parent
    require_existing_epoch_root(root)
    NEW_EPOCH_DATABASE.parent.mkdir(mode=0o700, exist_ok=False)
    os.chown(NEW_EPOCH_DATABASE.parent, identity.pw_uid, identity.pw_gid)
    os.chmod(NEW_EPOCH_DATABASE.parent, 0o700)


def verify_live_prestate(*, expected_core_release: str,
                         expected_runtime_release: str,
                         expected_plugin_release: str,
                         expected_old_sha256: str, revision: int, turns: int,
                         summaries: int, pending: int) -> dict[str, object]:
    require(active(CORE_SERVICE), "core_prestate_inactive")
    require(active(TELEGRAM_SOCKET) and active(TELEGRAM_SERVICE),
            "telegram_prestate_inactive")
    verify_credential_binding()
    verify_effective_credential()
    require(show(CORE_SERVICE, "WorkingDirectory").endswith(expected_core_release),
            "core_prestate_drifted")
    require(f"/{expected_runtime_release}/runtime/telegram_owner_runtime_gateway.py"
            in show(TELEGRAM_SERVICE, "ExecStart"), "runtime_prestate_drifted")
    config = read_json(TELEGRAM_CONFIG)
    require_resume_config_not_binding_source(config)
    require(config.get("gateway_release") == expected_plugin_release,
            "plugin_prestate_drifted")
    previous_selector, payload = load_previous_selector()
    require_existing_epoch_root(NEW_EPOCH_DATABASE.parent.parent)
    require(not NEW_EPOCH_DATABASE.parent.exists()
            and not NEW_EPOCH_DATABASE.parent.is_symlink(),
            "new_epoch_prestate_rejected")
    before = load_target_runtime_config_snapshot()
    old_bundle = inspect_old_bundle(expected_old_sha256)
    old_metadata = inspect_epoch_metadata(B_V4_EPOCH_DATABASE)
    require_expected_old_epoch(old_metadata, revision=revision, turns=turns,
                               summaries=summaries, pending=pending)
    after = load_target_runtime_config_snapshot()
    require(after.projection() == before.projection(),
            "runtime_config_changed_during_preflight")
    return {
        "core_binding_sha256": digest_file(CORE_BINDING),
        "core_gate_present": CORE_GATE.exists(),
        "core_gate_sha256": (
            digest_file(CORE_GATE) if CORE_GATE.exists() else None
        ),
        "core_release": expected_core_release,
        "core_selector_sha256": digest_file(CORE_SELECTOR),
        "old_epoch": {**old_bundle, "logical_metadata": old_metadata},
        "plugin_release": expected_plugin_release,
        "previous_selector_generation": payload["generation"],
        "previous_selector_sha256": digest_bytes(previous_selector),
        "runtime_config": after.projection(),
        "runtime_dropin_sha256": digest_file(TELEGRAM_DROPIN),
        "runtime_release": expected_runtime_release,
        "telegram_service_restarts": int(show(TELEGRAM_SERVICE, "NRestarts")),
    }


def build_plan(core_candidate: Path, runtime_candidate: Path, *,
               core_commit: str, deploy_commit: str,
               prestate: dict[str, object]) -> bytes:
    return canonical({
        "boundaries": {
            "channel": "authenticated-telegram-owner-private-only",
            "legacy_session_migrated": False,
            "model_or_channel_called": False,
            "old_epoch_content_changed": False,
            "profile_writer_or_qq_changed": False,
        },
        "executor_sha256": digest_file(Path(__file__).resolve()),
        "prestate": prestate,
        "rollback": {
            "core_binding_selector_gate": "restore-exact-present-bytes",
            "exact_dropin_bytes": True,
            "old_epoch_permissions": "restore-exact",
            "preserve_failed_new_epoch": True,
            "selector_prestate": "restore-exact-present-bytes",
        },
        "schema": SCHEMA,
        "selector_contract": {
            "bundle_schema": BUNDLE_SCHEMA,
            "generation": GENERATION,
            "new_epoch_id": NEW_EPOCH_ID,
            "old_epoch_id": B_V4_EPOCH_ID,
            "previous_epoch_bundle_digest": "bind-after-offline-stable-verification",
            "schema": SELECTOR_SCHEMA,
        },
        "status": "standing-authority-bounded-attempt",
        "target": {
            "core_commit": core_commit,
            "core_release": core_candidate.name,
            "deploy_commit": deploy_commit,
            "new_epoch_empty": True,
            "old_epoch_read_only": True,
            "runtime_release": runtime_candidate.name,
            "sqlite_schema": SQLITE_SCHEMA,
            "sqlite_schema_version": SQLITE_SCHEMA_VERSION,
        },
    })


def backup(
    plan: bytes, prestate: dict[str, object]
) -> tuple[Path, dict[str, bytes | None]]:
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(BACKUP_ROOT, 0o700)
    root = BACKUP_ROOT / digest_bytes(plan)
    require(not root.exists(), "activation_attempt_already_exists")
    root.mkdir(mode=0o700)
    payloads = {
        "CORE_BINDING": CORE_BINDING.read_bytes(),
        "CORE_SELECTOR": CORE_SELECTOR.read_bytes(),
        "CORE_GATE": optional_bytes(CORE_GATE),
        "TELEGRAM_DROPIN": TELEGRAM_DROPIN.read_bytes(),
        "SELECTOR": optional_bytes(SELECTOR_PATH),
    }
    require(payloads["SELECTOR"] is not None, "selector_prestate_rejected")
    atomic_write(root / "PLAN.json", plan, mode=0o600)
    atomic_write(root / "PRESTATE.json", canonical(prestate), mode=0o600)
    for name, payload in payloads.items():
        if payload is not None:
            atomic_write(root / name, payload, mode=0o600)
    return root, payloads


def stop_telegram() -> None:
    systemctl("stop", TELEGRAM_SOCKET, TELEGRAM_SERVICE)


def start_telegram() -> None:
    systemctl("daemon-reload")
    systemctl("start", TELEGRAM_SOCKET, TELEGRAM_SERVICE)


def restore_prestate(prestate: dict[str, object],
                     payloads: dict[str, bytes | None], *,
                     bundle_prestate: dict[str, object],
                     current_bundle_digest: str,
                     restore_bundle_permissions_needed: bool) -> None:
    stop_telegram()
    dropin = payloads["TELEGRAM_DROPIN"]
    selector = payloads["SELECTOR"]
    require(dropin is not None and selector is not None,
            "rollback_payload_rejected")
    atomic_write(TELEGRAM_DROPIN, dropin, mode=0o644)
    telegram_gid = grp.getgrnam("myuna-gateway-telegram").gr_gid
    restore_optional(SELECTOR_PATH, selector, mode=0o640, gid=telegram_gid)
    if restore_bundle_permissions_needed:
        restore_old_epoch_permissions(
            bundle_prestate, expected_bundle_digest=current_bundle_digest,
        )
    myuna_gid = grp.getgrnam("myuna").gr_gid
    core_binding = payloads["CORE_BINDING"]
    core_selector = payloads["CORE_SELECTOR"]
    require(core_binding is not None and core_selector is not None,
            "rollback_payload_rejected")
    atomic_write(CORE_BINDING, core_binding, mode=0o640, gid=myuna_gid)
    atomic_write(CORE_SELECTOR, core_selector, mode=0o644)
    restore_optional(CORE_GATE, payloads["CORE_GATE"], mode=0o644)
    systemctl("daemon-reload")
    systemctl("restart", CORE_SERVICE)
    systemctl("start", TELEGRAM_SOCKET, TELEGRAM_SERVICE)
    deadline = time.monotonic() + 30
    while not (active(TELEGRAM_SOCKET) and active(TELEGRAM_SERVICE)):
        require(time.monotonic() < deadline, "rollback_service_rejected")
        time.sleep(1)
    require(digest_file(TELEGRAM_DROPIN) == prestate["runtime_dropin_sha256"],
            "rollback_dropin_rejected")
    require(show(CORE_SERVICE, "WorkingDirectory").endswith(
            str(prestate["core_release"])), "rollback_core_rejected")
    require(digest_file(CORE_BINDING) == prestate["core_binding_sha256"],
            "rollback_core_binding_rejected")
    require(digest_file(CORE_SELECTOR) == prestate["core_selector_sha256"],
            "rollback_core_selector_rejected")
    if prestate["core_gate_present"]:
        require(CORE_GATE.is_file() and not CORE_GATE.is_symlink()
                and digest_file(CORE_GATE) == prestate["core_gate_sha256"],
                "rollback_core_gate_rejected")
    else:
        require(not CORE_GATE.exists(), "rollback_core_gate_rejected")
    require(f"/{prestate['runtime_release']}/runtime/telegram_owner_runtime_gateway.py"
            in show(TELEGRAM_SERVICE, "ExecStart"), "rollback_runtime_rejected")
    restored, payload = load_previous_selector()
    require(restored == selector
            and digest_bytes(restored) == prestate["previous_selector_sha256"]
            and payload["generation"] == 4, "rollback_selector_rejected")


def verify_target(core_release: str, runtime_digest: str,
                  sealed_bundle_digest: str,
                  selector: bytes,
                  expected_runtime_config: dict[str, object]) -> dict[str, object]:
    core_path = CORE_RELEASE_ROOT / core_release
    require(active(CORE_SERVICE), "target_core_inactive")
    require(show(CORE_SERVICE, "WorkingDirectory") == core_path.as_posix(),
            "target_core_rejected")
    require(CORE_GATE.read_bytes() == render_core_gate(),
            "target_core_gate_rejected")
    verify_effective_credential()
    verifier = subprocess.run(
        ["/usr/bin/python3", str(VERIFIER_PATH), "verify-active"],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=30, cwd=core_path,
        env={"PYTHONDONTWRITEBYTECODE": "1",
             "PYTHONPATH": f"{core_path / 'src'}"},
    )
    require(verifier.returncode == 0, "target_core_verifier_rejected")
    require(active(TELEGRAM_SOCKET) and active(TELEGRAM_SERVICE),
            "target_service_inactive")
    require(show(TELEGRAM_SERVICE, "NRestarts") == "0",
            "target_service_restart_drifted")
    require(f"/{runtime_digest}/runtime/telegram_owner_runtime_gateway.py"
            in show(TELEGRAM_SERVICE, "ExecStart"), "target_runtime_rejected")
    require(SELECTOR_PATH.read_bytes() == selector, "target_selector_rejected")
    selector_metadata = SELECTOR_PATH.lstat()
    telegram_gid = grp.getgrnam("myuna-gateway-telegram").gr_gid
    require(not SELECTOR_PATH.is_symlink()
            and stat.S_ISREG(selector_metadata.st_mode)
            and selector_metadata.st_uid == 0
            and selector_metadata.st_gid == telegram_gid
            and stat.S_IMODE(selector_metadata.st_mode) == 0o640,
            "target_selector_permission_rejected")
    sealed = inspect_epoch_bundle(
        B_V4_EPOCH_DATABASE, expected_file_mode=0o440,
        expected_parent_mode=0o550, expected_uid=0,
        expected_gid=telegram_gid,
    )
    require(sealed["bundle_digest"] == sealed_bundle_digest,
            "target_old_epoch_bundle_rejected")
    identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
    require_resume_config_not_binding_source(read_json(TELEGRAM_CONFIG))
    empty = verify_empty_epoch_from_runtime_config(
        NEW_EPOCH_DATABASE, expected_config_projection=expected_runtime_config,
        expected_uid=identity.pw_uid, expected_gid=identity.pw_gid,
        expected_epoch_id=NEW_EPOCH_ID,
    )
    require(empty["initialized"] is True, "target_new_epoch_not_initialized")
    return {
        "core_release": core_release,
        "new_epoch_empty": True,
        "new_epoch_id": NEW_EPOCH_ID,
        "old_epoch_bundle_digest": sealed_bundle_digest,
        "old_epoch_bundle_schema": BUNDLE_SCHEMA,
        "old_epoch_read_only": True,
        "runtime_release": runtime_digest,
        "selector_generation": GENERATION,
        "selector_sha256": digest_bytes(selector),
        **empty,
    }


def activate(core_candidate: Path, runtime_candidate: Path, *,
             core_commit: str, deploy_commit: str,
             expected_core_release: str, expected_runtime_release: str,
             expected_plugin_release: str, expected_old_sha256: str,
             expected_revision: int, expected_turns: int,
             expected_summaries: int, expected_pending: int,
             expected_plan_sha256: str | None,
             preflight_only: bool) -> dict[str, object]:
    require(os.geteuid() == 0, "root_identity_required")
    for value, code in ((core_commit, "core_commit_rejected"),
                        (deploy_commit, "deploy_commit_rejected")):
        require(_COMMIT.fullmatch(value) is not None, code)
    for value, code in (
        (expected_core_release, "core_release_rejected"),
        (expected_runtime_release, "runtime_release_rejected"),
        (expected_plugin_release, "plugin_release_rejected"),
        (expected_old_sha256, "old_epoch_digest_rejected"),
    ):
        require(_DIGEST.fullmatch(value) is not None, code)
    core, _artifact, _receipt = core_evidence(core_candidate)
    require(core.source_commit == core_commit, "core_commit_drifted")
    require(core.tree_sha256 == core_candidate.name,
            "core_release_candidate_rejected")
    verify_core_response_contract(core_candidate)
    runtime_digest = validate_runtime(runtime_candidate, core_commit, deploy_commit)
    verify_runtime_startup_smoke(runtime_candidate)
    verify_new_epoch_startup_smoke(runtime_candidate,
                                   expected_epoch_id=NEW_EPOCH_ID)
    prestate = verify_live_prestate(
        expected_core_release=expected_core_release,
        expected_runtime_release=expected_runtime_release,
        expected_plugin_release=expected_plugin_release,
        expected_old_sha256=expected_old_sha256, revision=expected_revision,
        turns=expected_turns, summaries=expected_summaries,
        pending=expected_pending,
    )
    plan = build_plan(core_candidate, runtime_candidate, core_commit=core_commit,
                      deploy_commit=deploy_commit, prestate=prestate)
    plan_sha256 = digest_bytes(plan)
    if expected_plan_sha256 is not None:
        require(plan_sha256 == expected_plan_sha256, "plan_digest_drifted")
    if preflight_only:
        return {"plan_sha256": plan_sha256, "status": "ready"}
    require(expected_plan_sha256 is not None, "expected_plan_required")
    backup_root, backup_payloads = backup(plan, prestate)
    old_selector = backup_payloads["SELECTOR"]
    require(old_selector is not None, "selector_prestate_rejected")
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_ROOT, 0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    journal = STATE_ROOT / f"JOURNAL-{stamp}-{plan_sha256[:12]}.json"
    atomic_write(journal, canonical({"plan_sha256": plan_sha256,
                                     "schema": SCHEMA,
                                     "status": "activating"}), mode=0o600)
    telegram_gid = grp.getgrnam("myuna-gateway-telegram").gr_gid
    mutated = False
    rollback_bundle_prestate = dict(prestate["old_epoch"])
    current_bundle_digest = str(rollback_bundle_prestate["bundle_digest"])
    restore_bundle_permissions_needed = False
    try:
        myuna_gid = grp.getgrnam("myuna").gr_gid
        install_tree(core_candidate, CORE_RELEASE_ROOT / core.tree_sha256,
                     gid=myuna_gid, directory_mode=0o550, file_mode=0o440)
        validate_immutable_release_tree(
            CORE_RELEASE_ROOT / core.tree_sha256, core
        )
        install_tree(runtime_candidate, RUNTIME_ROOT / runtime_digest,
                     gid=telegram_gid, directory_mode=0o550, file_mode=0o440)
        require(tree_inventory(runtime_candidate)
                == tree_inventory(RUNTIME_ROOT / runtime_digest),
                "installed_runtime_drifted")
        mutated = True
        stop_telegram()
        previous_selector, _ = load_previous_selector()
        require(previous_selector == old_selector,
                "selector_changed_during_activation")
        metadata = inspect_epoch_metadata(B_V4_EPOCH_DATABASE)
        require_expected_old_epoch(
            metadata, revision=expected_revision, turns=expected_turns,
            summaries=expected_summaries, pending=expected_pending,
        )
        identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
        first = inspect_epoch_bundle(
            B_V4_EPOCH_DATABASE, expected_file_mode=0o600,
            expected_parent_mode=0o700, expected_uid=identity.pw_uid,
            expected_gid=identity.pw_gid,
        )
        time.sleep(0.25)
        second = inspect_epoch_bundle(
            B_V4_EPOCH_DATABASE, expected_file_mode=0o600,
            expected_parent_mode=0o700, expected_uid=identity.pw_uid,
            expected_gid=identity.pw_gid,
        )
        current_bundle_digest = require_same_bundle(first, second)
        rollback_bundle_prestate = second
        persist_stopped_bundle_prestate(backup_root, second)
        require(not NEW_EPOCH_DATABASE.parent.exists(), "new_epoch_preexisting")
        restore_bundle_permissions_needed = True
        seal_old_epoch(current_bundle_digest)
        prepare_new_epoch_parent()
        selector = canonical(selector_payload(current_bundle_digest))
        atomic_write(SELECTOR_PATH, selector, mode=0o640, gid=telegram_gid)
        atomic_write(TELEGRAM_DROPIN, render_telegram_dropin(runtime_digest),
                     mode=0o644)
        binding, core_selector = render_core_binding(core, plan_sha256)
        atomic_write(CORE_BINDING, binding, mode=0o640, gid=myuna_gid)
        atomic_write(CORE_SELECTOR, core_selector, mode=0o644)
        atomic_write(CORE_GATE, render_core_gate(), mode=0o644)
        systemctl("daemon-reload")
        systemctl("restart", CORE_SERVICE)
        systemctl("start", TELEGRAM_SOCKET, TELEGRAM_SERVICE)
        deadline = time.monotonic() + 30
        while True:
            try:
                target = verify_target(core.tree_sha256, runtime_digest,
                                       current_bundle_digest,
                                       selector, dict(prestate["runtime_config"]))
                break
            except (ExternalEpochBundleRejected, ExternalEpochRejected,
                    RolloverRejected, FileNotFoundError, sqlite3.Error):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(1)
        receipt = {
            "backup": backup_root.name,
            "channel_called": False,
            "legacy_session_migrated": False,
            "model_called": False,
            "plan_sha256": plan_sha256,
            "profile_or_writer_changed": False,
            "qq_changed": False,
            "raw_content_recorded": False,
            "schema": SCHEMA,
            "secret_recorded": False,
            "status": "ACTIVE_WAITING_OWNER_ORGANIC_TELEGRAM_E2E",
            **target,
        }
        atomic_write(journal, canonical(receipt), mode=0o600)
        atomic_write(STATE_ROOT / f"RECEIPT-{stamp}-{plan_sha256[:12]}.json",
                     canonical(receipt), mode=0o600)
        return receipt
    except Exception as exc:
        rollback = "not_needed"
        if mutated:
            restore_prestate(
                prestate, backup_payloads,
                bundle_prestate=rollback_bundle_prestate,
                current_bundle_digest=current_bundle_digest,
                restore_bundle_permissions_needed=restore_bundle_permissions_needed,
            )
            rollback = "verified"
        atomic_write(journal, canonical({
            "channel_called": False,
            "failure_gate": failure_code(exc),
            "model_called": False,
            "plan_sha256": plan_sha256,
            "raw_content_recorded": False,
            "rollback": rollback,
            "schema": SCHEMA,
            "status": "rolled_back" if mutated else "failed_before_mutation",
        }), mode=0o600)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core-candidate", required=True, type=Path)
    parser.add_argument("--runtime-candidate", required=True, type=Path)
    parser.add_argument("--core-commit", required=True)
    parser.add_argument("--deploy-commit", required=True)
    parser.add_argument("--expected-core-release", required=True)
    parser.add_argument("--expected-runtime-release", required=True)
    parser.add_argument("--expected-plugin-release", required=True)
    parser.add_argument("--expected-old-epoch-sha256", required=True)
    parser.add_argument("--expected-revision", required=True, type=int)
    parser.add_argument("--expected-turns", required=True, type=int)
    parser.add_argument("--expected-summaries", required=True, type=int)
    parser.add_argument("--expected-pending", required=True, type=int)
    parser.add_argument("--expected-plan-sha256")
    parser.add_argument("--preflight-only", action="store_true")
    arguments = parser.parse_args()
    try:
        result = activate(
            arguments.core_candidate.resolve(),
            arguments.runtime_candidate.resolve(),
            core_commit=arguments.core_commit, deploy_commit=arguments.deploy_commit,
            expected_core_release=arguments.expected_core_release,
            expected_runtime_release=arguments.expected_runtime_release,
            expected_plugin_release=arguments.expected_plugin_release,
            expected_old_sha256=arguments.expected_old_epoch_sha256,
            expected_revision=arguments.expected_revision,
            expected_turns=arguments.expected_turns,
            expected_summaries=arguments.expected_summaries,
            expected_pending=arguments.expected_pending,
            expected_plan_sha256=arguments.expected_plan_sha256,
            preflight_only=arguments.preflight_only,
        )
    except (ActivationRejected, ExternalEpochBundleRejected,
            ExternalEpochRejected, RolloverRejected, OSError, sqlite3.Error,
            ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"failure_gate": failure_code(exc),
                          "status": "rejected"}, separators=(",", ":"),
                         sort_keys=True))
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
