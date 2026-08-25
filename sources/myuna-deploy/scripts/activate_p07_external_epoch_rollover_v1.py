#!/usr/bin/env python3
"""One-attempt P07 external epoch rollover with exact, content-free rollback."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import grp
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time

from activate_p07_hybrid_external_generation_v1 import (
    ActivationRejected,
    RUNTIME_ROOT,
    TELEGRAM_RUNTIME_USER,
    TELEGRAM_SERVICE,
    TELEGRAM_SOCKET,
    active,
    atomic_write,
    canonical,
    digest_bytes,
    digest_file,
    install_tree,
    optional_bytes,
    read_json,
    render_telegram_dropin,
    restore_optional,
    show,
    systemctl,
    tree_inventory,
    validate_runtime,
    verify_credential_binding,
    verify_effective_credential,
    verify_runtime_startup_smoke,
)
from external_epoch_bundle import (
    BUNDLE_SCHEMA,
    ExternalEpochBundleRejected,
    inspect_epoch_bundle,
    require_same_bundle,
    restore_epoch_bundle_permissions,
    seal_epoch_bundle,
)
from external_context_epoch import (
    SQLITE_SCHEMA,
    SQLITE_SCHEMA_VERSION,
    ZERO_DIGEST,
    ExternalEpochBinding,
    ExternalEpochRejected,
    verify_epoch_schema,
)
import telegram_runtime_config as runtime_config_contract


SCHEMA = "myuna.p07-external-epoch-rollover-activation.v1"
SELECTOR_SCHEMA = "myuna.external-epoch-selector.v2"
SELECTOR_PATH = Path("/etc/myuna-telegram-gateway/external-epoch-selector-v2.json")
OLD_EPOCH_DATABASE = Path(
    "/var/lib/myuna-telegram-gateway/external-context-v1/epoch.db"
)
NEW_EPOCH_ROOT = Path(
    "/var/lib/myuna-telegram-gateway/external-context-epochs"
)
NEW_EPOCH_ID = "telegram-owner-private-external-v4"
NEW_EPOCH_DATABASE = NEW_EPOCH_ROOT / NEW_EPOCH_ID / "epoch.db"
OLD_EPOCH_ID = "telegram-owner-private-external-v1"
TELEGRAM_DROPIN = Path(
    "/etc/systemd/system/myuna-telegram-owner-runtime-dev.service.d/"
    "zzzzzzzzzzz-p07-hybrid-external-v1.conf"
)
TELEGRAM_CONFIG = Path("/etc/myuna-telegram-gateway/r5-resume-v1.json")
CORE_SERVICE = "myuna-core@qq.service"
BACKUP_ROOT = Path("/var/backups/myuna/p07-external-epoch-rollover-v1")
STATE_ROOT = Path("/var/lib/myuna-telegram-gateway/p07-external-epoch-rollover-v1")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_RUNTIME_BINDING_FIELDS = frozenset({"channel_kind", "principal_id", "namespace_id"})


class RolloverRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def require(condition: bool, code: str) -> None:
    if not condition:
        raise RolloverRejected(code)


def failure_code(error: BaseException) -> str:
    if isinstance(error, RolloverRejected):
        return error.code
    if isinstance(error, ActivationRejected):
        return error.code
    if isinstance(error, ExternalEpochBundleRejected):
        return error.code
    if isinstance(error, ExternalEpochRejected):
        return error.code
    if isinstance(error, sqlite3.Error):
        return "epoch_metadata_rejected"
    if isinstance(error, OSError):
        return "filesystem_operation_rejected"
    return "rollover_rejected"


def require_resume_config_not_binding_source(payload: object) -> None:
    require(
        isinstance(payload, dict)
        and _RUNTIME_BINDING_FIELDS.isdisjoint(payload),
        "runtime_config_conflicting_source_rejected",
    )


def load_target_runtime_config_snapshot(
) -> runtime_config_contract.ProtectedRuntimeConfigSnapshot:
    try:
        return runtime_config_contract.load_protected_runtime_config_snapshot()
    except runtime_config_contract.RuntimeConfigRejected:
        raise RolloverRejected("runtime_config_source_rejected") from None


def verify_empty_epoch_from_runtime_config(
    database: Path,
    *,
    expected_config_projection: dict[str, object],
    expected_uid: int,
    expected_gid: int,
    expected_epoch_id: str = NEW_EPOCH_ID,
    snapshot_loader=None,
) -> dict[str, object]:
    if snapshot_loader is None:
        snapshot_loader = load_target_runtime_config_snapshot
    before = snapshot_loader()
    require(
        before.projection() == expected_config_projection,
        "runtime_config_snapshot_drifted",
    )
    binding = runtime_config_contract.external_epoch_binding_from_runtime_config(
        before.config
    )
    empty = inspect_empty_epoch(
        database,
        binding=binding,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        expected_epoch_id=expected_epoch_id,
    )
    after = snapshot_loader()
    require(
        after.projection() == before.projection()
        and runtime_config_contract.external_epoch_binding_from_runtime_config(
            after.config
        )
        == binding,
        "runtime_config_changed_during_verification",
    )
    return empty


def selector_payload(previous_bundle_digest: str) -> dict[str, object]:
    require(
        _DIGEST.fullmatch(previous_bundle_digest) is not None,
        "old_epoch_bundle_digest_rejected",
    )
    return {
        "channel_kind": "astrbot_telegram",
        "client_id": "telegram-owner-private",
        "database_path": NEW_EPOCH_DATABASE.as_posix(),
        "epoch_id": NEW_EPOCH_ID,
        "generation": 4,
        "previous_epoch_bundle_digest": previous_bundle_digest,
        "previous_epoch_bundle_schema": BUNDLE_SCHEMA,
        "previous_epoch_id": OLD_EPOCH_ID,
        "schema": SELECTOR_SCHEMA,
        "status": "active",
    }


def validate_selector_payload(payload: object) -> dict[str, object]:
    expected_fields = set(selector_payload("0" * 64))
    require(isinstance(payload, dict) and set(payload) == expected_fields, "selector_fields_rejected")
    require(payload.get("schema") == SELECTOR_SCHEMA, "selector_schema_rejected")
    require(payload.get("status") == "active", "selector_status_rejected")
    require(payload.get("channel_kind") == "astrbot_telegram", "selector_channel_rejected")
    require(payload.get("client_id") == "telegram-owner-private", "selector_client_rejected")
    require(payload.get("generation") == 4, "selector_generation_rejected")
    require(payload.get("previous_epoch_id") == OLD_EPOCH_ID, "selector_previous_rejected")
    require(payload.get("epoch_id") == NEW_EPOCH_ID, "selector_epoch_rejected")
    require(payload.get("database_path") == NEW_EPOCH_DATABASE.as_posix(), "selector_path_rejected")
    previous_bundle_digest = payload.get("previous_epoch_bundle_digest")
    require(
        isinstance(previous_bundle_digest, str)
        and _DIGEST.fullmatch(previous_bundle_digest) is not None,
        "selector_digest_rejected",
    )
    require(
        payload.get("previous_epoch_bundle_schema") == BUNDLE_SCHEMA,
        "selector_bundle_schema_rejected",
    )
    return payload


def _regular_metadata(path: Path) -> os.stat_result:
    metadata = path.lstat()
    require(not path.is_symlink() and stat.S_ISREG(metadata.st_mode), "epoch_type_rejected")
    return metadata


def inspect_epoch_metadata(database: Path) -> dict[str, object]:
    """Read only schema/revision/count metadata; never select turn or summary content."""

    _regular_metadata(database)
    uri = database.as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=2.0)
    try:
        connection.execute("PRAGMA query_only = ON")
        state = connection.execute(
            "SELECT schema_name, schema_version, epoch_id, selected_revision, "
            "max_revision FROM epoch_state WHERE singleton = 1"
        ).fetchone()
        require(state is not None and len(state) == 5, "epoch_state_rejected")
        turn_count = connection.execute("SELECT COUNT(*) FROM committed_turns").fetchone()[0]
        summary_count = connection.execute("SELECT COUNT(*) FROM committed_summaries").fetchone()[0]
        pending_count = connection.execute("SELECT COUNT(*) FROM pending_turns").fetchone()[0]
    finally:
        connection.close()
    return {
        "epoch_id": state[2],
        "max_revision": state[4],
        "pending_count": pending_count,
        "schema_name": state[0],
        "schema_version": state[1],
        "selected_revision": state[3],
        "summary_count": summary_count,
        "turn_count": turn_count,
    }


def inspect_empty_epoch(
    database: Path,
    *,
    binding: ExternalEpochBinding,
    expected_uid: int,
    expected_gid: int,
    expected_epoch_id: str = NEW_EPOCH_ID,
) -> dict[str, object]:
    parent = database.parent.lstat()
    require(
        not database.parent.is_symlink()
        and stat.S_ISDIR(parent.st_mode)
        and stat.S_IMODE(parent.st_mode) == 0o700
        and parent.st_uid == expected_uid
        and parent.st_gid == expected_gid,
        "new_epoch_parent_metadata_rejected",
    )
    sidecars = (Path(f"{database}-wal"), Path(f"{database}-shm"))
    sidecar_presence = tuple(path.exists() or path.is_symlink() for path in sidecars)
    require(
        sidecar_presence in ((False, False), (True, True)),
        "new_epoch_partial_sidecar_rejected",
    )
    for path in (database, *(path for path, present in zip(sidecars, sidecar_presence) if present)):
        metadata = _regular_metadata(path)
        require(
            metadata.st_uid == expected_uid
            and metadata.st_gid == expected_gid
            and stat.S_IMODE(metadata.st_mode) == 0o600,
            "new_epoch_file_metadata_rejected",
        )
    uri = database.as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=2.0)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        verify_epoch_schema(connection)
        states = connection.execute("SELECT * FROM epoch_state LIMIT 2").fetchall()
        require(len(states) == 1, "new_epoch_state_cardinality_rejected")
        state = states[0]
        require(
            state["schema_name"] == SQLITE_SCHEMA
            and state["schema_version"] == SQLITE_SCHEMA_VERSION
            and state["epoch_id"] == expected_epoch_id,
            "new_epoch_identity_rejected",
        )
        require(
            state["channel_kind"] == binding.channel_kind
            and state["principal_id"] == binding.principal_id
            and state["namespace_id"] == binding.namespace_id,
            "new_epoch_binding_rejected",
        )
        require(
            state["selected_revision"] == 0
            and state["max_revision"] == 0
            and state["latest_sequence"] == 0
            and state["latest_digest"] == ZERO_DIGEST,
            "new_epoch_initial_state_rejected",
        )
        revisions = connection.execute(
            "SELECT revision, selected_sequence, selected_digest, summary_version "
            "FROM epoch_revisions LIMIT 2"
        ).fetchall()
        require(
            len(revisions) == 1
            and revisions[0]["revision"] == 0
            and revisions[0]["selected_sequence"] == 0
            and revisions[0]["selected_digest"] == ZERO_DIGEST
            and revisions[0]["summary_version"] is None,
            "new_epoch_initial_revision_rejected",
        )
        turn_count = connection.execute("SELECT COUNT(*) FROM committed_turns").fetchone()[0]
        summary_count = connection.execute("SELECT COUNT(*) FROM committed_summaries").fetchone()[0]
        pending_count = connection.execute("SELECT COUNT(*) FROM pending_turns").fetchone()[0]
        provenance_count = connection.execute(
            "SELECT COUNT(*) FROM committed_turn_provenance"
        ).fetchone()[0]
        pending_summary_count = connection.execute(
            "SELECT COUNT(*) FROM summary_jobs WHERE status = 'pending'"
        ).fetchone()[0]
        require(
            turn_count == 0
            and summary_count == 0
            and pending_count == 0
            and provenance_count == 0
            and pending_summary_count == 0,
            "new_epoch_not_empty",
        )
    finally:
        connection.close()
    return {
        "initialized": True,
        "max_revision": 0,
        "pending_count": pending_count,
        "pending_summary_count": pending_summary_count,
        "provenance_count": provenance_count,
        "schema_name": SQLITE_SCHEMA,
        "schema_version": SQLITE_SCHEMA_VERSION,
        "selected_revision": 0,
        "summary_count": summary_count,
        "turn_count": turn_count,
    }


def require_expected_old_epoch(
    metadata: dict[str, object],
    *,
    revision: int,
    turns: int,
    summaries: int,
    pending: int,
) -> None:
    require(metadata.get("schema_name") == "myuna.external-authorized-epoch.v1", "old_epoch_schema_rejected")
    require(metadata.get("schema_version") == 1, "old_epoch_schema_rejected")
    require(metadata.get("epoch_id") == OLD_EPOCH_ID, "old_epoch_id_rejected")
    require(metadata.get("selected_revision") == revision, "old_epoch_revision_rejected")
    require(metadata.get("max_revision") == revision, "old_epoch_revision_rejected")
    require(metadata.get("turn_count") == turns, "old_epoch_turn_count_rejected")
    require(metadata.get("summary_count") == summaries, "old_epoch_summary_count_rejected")
    require(metadata.get("pending_count") == pending, "old_epoch_pending_count_rejected")


def validate_old_epoch_paths(
    expected_sha256: str,
 ) -> dict[str, object]:
    identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
    bundle = inspect_epoch_bundle(
        OLD_EPOCH_DATABASE,
        expected_file_mode=0o600,
        expected_parent_mode=0o700,
        expected_uid=identity.pw_uid,
        expected_gid=identity.pw_gid,
    )
    projection = bundle["bundle_projection"]
    assert isinstance(projection, dict)
    files = projection["files"]
    assert isinstance(files, list)
    database = next(
        (entry for entry in files if isinstance(entry, dict) and entry.get("name") == "epoch.db"),
        None,
    )
    require(
        isinstance(database, dict) and database.get("sha256") == expected_sha256,
        "old_epoch_digest_drifted",
    )
    return bundle


def seal_old_epoch(expected_bundle_digest: str) -> dict[str, object]:
    identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
    telegram_gid = grp.getgrnam("myuna-gateway-telegram").gr_gid
    return seal_epoch_bundle(
        OLD_EPOCH_DATABASE,
        expected_bundle_digest=expected_bundle_digest,
        source_uid=identity.pw_uid,
        source_gid=identity.pw_gid,
        sealed_gid=telegram_gid,
    )


def restore_old_epoch_permissions(
    prestate: dict[str, object],
    *,
    expected_bundle_digest: str,
) -> None:
    restore_epoch_bundle_permissions(
        OLD_EPOCH_DATABASE,
        prestate=prestate,
        expected_bundle_digest=expected_bundle_digest,
    )


def prepare_new_epoch_parent() -> None:
    identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
    NEW_EPOCH_ROOT.mkdir(parents=True, exist_ok=True)
    require(not NEW_EPOCH_ROOT.is_symlink() and NEW_EPOCH_ROOT.is_dir(), "new_epoch_root_rejected")
    os.chown(NEW_EPOCH_ROOT, 0, identity.pw_gid)
    os.chmod(NEW_EPOCH_ROOT, 0o710)
    NEW_EPOCH_DATABASE.parent.mkdir(mode=0o700, exist_ok=False)
    os.chown(NEW_EPOCH_DATABASE.parent, identity.pw_uid, identity.pw_gid)
    os.chmod(NEW_EPOCH_DATABASE.parent, 0o700)


def verify_new_epoch_startup_smoke(
    runtime_candidate: Path,
    *,
    expected_epoch_id: str = NEW_EPOCH_ID,
) -> None:
    identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
    release_root = Path(tempfile.mkdtemp(prefix="p07-epoch-runtime-smoke-"))
    state_root = Path(tempfile.mkdtemp(prefix="p07-epoch-state-smoke-"))
    config_root = Path(tempfile.mkdtemp(prefix="p07-epoch-config-smoke-"))
    release = release_root / "release"
    database = state_root / "epoch.db"
    config_path = config_root / "owner-runtime-v1.json"
    try:
        shutil.copytree(runtime_candidate, release)
        os.chown(release_root, 0, identity.pw_gid)
        os.chmod(release_root, 0o550)
        for path in (release, *release.rglob("*")):
            require(not path.is_symlink(), "runtime_startup_type_rejected")
            os.chown(path, 0, identity.pw_gid)
            os.chmod(path, 0o550 if path.is_dir() else 0o440)
        os.chown(state_root, identity.pw_uid, identity.pw_gid)
        os.chmod(state_root, 0o700)
        os.chown(config_root, 0, identity.pw_gid)
        os.chmod(config_root, 0o750)
        config_path.write_bytes(
            canonical(
                {
                    "binding_id": "binding-synthetic",
                    "channel_kind": "astrbot_telegram",
                    "channel_instance": "telegram-synthetic",
                    "core_host": "127.0.0.1",
                    "core_port": 48080,
                    "evidence_sha256": "a" * 64,
                    "finalization_digest": "b" * 64,
                    "max_history_characters": 16000,
                    "max_history_messages": 128,
                    "max_requests_per_ten_minutes": 20,
                    "namespace_id": "owner-synthetic-private",
                    "principal_id": "owner-synthetic",
                }
            )
        )
        os.chown(config_path, 0, identity.pw_gid)
        os.chmod(config_path, 0o640)
        program = (
            "import os,sys\n"
            "sys.dont_write_bytecode=True\n"
            "assert os.environ.get('PYTHONDONTWRITEBYTECODE')=='1'\n"
            "def deny_network(event,args):\n"
            "    if event.startswith('socket.'):\n"
            "        raise RuntimeError('network_forbidden')\n"
            "sys.addaudithook(deny_network)\n"
            "from external_context_epoch import ExternalEpochStore\n"
            "from pathlib import Path\n"
            "import telegram_runtime_config as runtime_config_contract\n"
            f"snapshot=runtime_config_contract.parse_protected_runtime_config_snapshot(Path({config_path.as_posix()!r}),expected_uid=0,expected_gid={identity.pw_gid},expected_mode=0o640)\n"
            "binding=runtime_config_contract.external_epoch_binding_from_runtime_config(snapshot.config)\n"
            f"database={database.as_posix()!r}\n"
            f"first=ExternalEpochStore(database,epoch_id={expected_epoch_id!r},startup_binding=binding)\n"
            f"assert first.public_metadata()=={{'initialized':True,'max_revision':0,'pending_count':0,'pending_summary_count':0,'provenance_count':0,'schema':{SQLITE_SCHEMA!r},'selected_revision':0,'summary_count':0,'turn_count':0}}\n"
            f"second=ExternalEpochStore(database,epoch_id={expected_epoch_id!r},startup_binding=binding)\n"
            "assert second.public_metadata()['max_revision']==0\n"
        )
        completed = subprocess.run(
            [
                "/usr/sbin/runuser",
                "-u",
                TELEGRAM_RUNTIME_USER,
                "--",
                "/usr/bin/env",
                "-i",
                "PATH=/usr/bin",
                f"PYTHONPATH={release / 'runtime'}",
                "PYTHONDONTWRITEBYTECODE=1",
                "/usr/bin/python3",
                "-B",
                "-c",
                program,
            ],
            check=False,
            cwd=release / "runtime",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        require(completed.returncode == 0, "new_epoch_startup_smoke_rejected")
        def load_synthetic_snapshot() -> runtime_config_contract.ProtectedRuntimeConfigSnapshot:
            return runtime_config_contract.parse_protected_runtime_config_snapshot(
                config_path,
                expected_uid=0,
                expected_gid=identity.pw_gid,
                expected_mode=0o640,
            )

        config_snapshot = load_synthetic_snapshot()
        verify_empty_epoch_from_runtime_config(
            database,
            expected_config_projection=config_snapshot.projection(),
            expected_uid=identity.pw_uid,
            expected_gid=identity.pw_gid,
            expected_epoch_id=expected_epoch_id,
            snapshot_loader=load_synthetic_snapshot,
        )
        require(
            not any(
                path.name == "__pycache__" or path.suffix == ".pyc"
                for path in release.rglob("*")
            ),
            "new_epoch_startup_bytecode_rejected",
        )
    except subprocess.TimeoutExpired as exc:
        raise RolloverRejected("new_epoch_startup_smoke_rejected") from exc
    finally:
        shutil.rmtree(release_root)
        shutil.rmtree(state_root)
        shutil.rmtree(config_root)


def verify_live_prestate(
    *,
    expected_core_release: str,
    expected_runtime_release: str,
    expected_plugin_release: str,
    expected_old_sha256: str,
    revision: int,
    turns: int,
    summaries: int,
    pending: int,
) -> dict[str, object]:
    require(active(CORE_SERVICE), "core_prestate_inactive")
    require(active(TELEGRAM_SOCKET) and active(TELEGRAM_SERVICE), "telegram_prestate_inactive")
    verify_credential_binding()
    verify_effective_credential()
    require(show(CORE_SERVICE, "WorkingDirectory").endswith(expected_core_release), "core_prestate_drifted")
    require(f"/{expected_runtime_release}/runtime/telegram_owner_runtime_gateway.py" in show(TELEGRAM_SERVICE, "ExecStart"), "runtime_prestate_drifted")
    config = read_json(TELEGRAM_CONFIG)
    require_resume_config_not_binding_source(config)
    require(config.get("gateway_release") == expected_plugin_release, "plugin_prestate_drifted")
    runtime_config_before = load_target_runtime_config_snapshot()
    require(not SELECTOR_PATH.exists() and not SELECTOR_PATH.is_symlink(), "selector_prestate_rejected")
    require(
        not NEW_EPOCH_DATABASE.parent.exists()
        and not NEW_EPOCH_DATABASE.parent.is_symlink(),
        "new_epoch_prestate_rejected",
    )
    old_bundle = validate_old_epoch_paths(expected_old_sha256)
    old_metadata = inspect_epoch_metadata(OLD_EPOCH_DATABASE)
    require_expected_old_epoch(
        old_metadata,
        revision=revision,
        turns=turns,
        summaries=summaries,
        pending=pending,
    )
    require(pending == 0, "old_epoch_pending_rejected")
    runtime_config_after = load_target_runtime_config_snapshot()
    require(
        runtime_config_after.projection() == runtime_config_before.projection(),
        "runtime_config_changed_during_preflight",
    )
    return {
        "core_release": expected_core_release,
        "old_epoch": {
            **old_bundle,
            "logical_metadata": old_metadata,
        },
        "plugin_release": expected_plugin_release,
        "runtime_dropin_sha256": digest_file(TELEGRAM_DROPIN),
        "runtime_config": runtime_config_after.projection(),
        "runtime_release": expected_runtime_release,
        "telegram_service_restarts": int(show(TELEGRAM_SERVICE, "NRestarts")),
    }


def build_plan(
    runtime_candidate: Path,
    *,
    core_commit: str,
    deploy_commit: str,
    prestate: dict[str, object],
) -> bytes:
    return canonical(
        {
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
                "exact_dropin_bytes": True,
                "old_epoch_permissions": "restore-exact",
                "preserve_failed_new_epoch": True,
                "selector_prestate": "absent",
            },
            "schema": SCHEMA,
            "selector_contract": {
                "bundle_schema": BUNDLE_SCHEMA,
                "generation": 4,
                "new_epoch_id": NEW_EPOCH_ID,
                "old_epoch_id": OLD_EPOCH_ID,
                "previous_epoch_bundle_digest": "bind-after-offline-stable-verification",
                "schema": SELECTOR_SCHEMA,
            },
            "status": "owner_authorized_single_attempt",
            "target": {
                "core_commit": core_commit,
                "deploy_commit": deploy_commit,
                "new_epoch_empty": True,
                "old_epoch_read_only": True,
                "runtime_release": runtime_candidate.name,
            },
        }
    )


def backup(plan: bytes, prestate: dict[str, object]) -> tuple[Path, bytes, bytes | None]:
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(BACKUP_ROOT, 0o700)
    root = BACKUP_ROOT / digest_bytes(plan)
    require(not root.exists(), "activation_attempt_already_exists")
    root.mkdir(mode=0o700)
    dropin = TELEGRAM_DROPIN.read_bytes()
    selector = optional_bytes(SELECTOR_PATH)
    atomic_write(root / "PLAN.json", plan, mode=0o600)
    atomic_write(root / "PRESTATE.json", canonical(prestate), mode=0o600)
    atomic_write(root / "TELEGRAM_DROPIN", dropin, mode=0o600)
    return root, dropin, selector


def stop_telegram() -> None:
    systemctl("stop", TELEGRAM_SOCKET, TELEGRAM_SERVICE)


def start_telegram() -> None:
    systemctl("daemon-reload")
    systemctl("start", TELEGRAM_SOCKET, TELEGRAM_SERVICE)


def restore_prestate(
    prestate: dict[str, object],
    dropin: bytes,
    selector: bytes | None,
    *,
    bundle_prestate: dict[str, object],
    current_bundle_digest: str,
    restore_bundle_permissions_needed: bool,
) -> None:
    stop_telegram()
    atomic_write(TELEGRAM_DROPIN, dropin, mode=0o644)
    telegram_gid = grp.getgrnam("myuna-gateway-telegram").gr_gid
    restore_optional(SELECTOR_PATH, selector, mode=0o640, gid=telegram_gid)
    if restore_bundle_permissions_needed:
        restore_old_epoch_permissions(
            bundle_prestate,
            expected_bundle_digest=current_bundle_digest,
        )
    start_telegram()
    deadline = time.monotonic() + 30
    while not (active(TELEGRAM_SOCKET) and active(TELEGRAM_SERVICE)):
        require(time.monotonic() < deadline, "rollback_service_rejected")
        time.sleep(1)
    require(digest_file(TELEGRAM_DROPIN) == prestate["runtime_dropin_sha256"], "rollback_dropin_rejected")
    require(f"/{prestate['runtime_release']}/runtime/telegram_owner_runtime_gateway.py" in show(TELEGRAM_SERVICE, "ExecStart"), "rollback_runtime_rejected")
    require(not SELECTOR_PATH.exists() and not SELECTOR_PATH.is_symlink(), "rollback_selector_rejected")


def verify_target(
    runtime_digest: str,
    sealed_bundle_digest: str,
    selector: bytes,
    expected_runtime_config: dict[str, object],
) -> dict[str, object]:
    require(active(TELEGRAM_SOCKET) and active(TELEGRAM_SERVICE), "target_service_inactive")
    require(show(TELEGRAM_SERVICE, "NRestarts") == "0", "target_service_restart_drifted")
    require(f"/{runtime_digest}/runtime/telegram_owner_runtime_gateway.py" in show(TELEGRAM_SERVICE, "ExecStart"), "target_runtime_rejected")
    require(SELECTOR_PATH.read_bytes() == selector, "target_selector_rejected")
    selector_stat = _regular_metadata(SELECTOR_PATH)
    require(selector_stat.st_uid == 0 and stat.S_IMODE(selector_stat.st_mode) == 0o640, "target_selector_permission_rejected")
    telegram_gid = grp.getgrnam("myuna-gateway-telegram").gr_gid
    sealed_bundle = inspect_epoch_bundle(
        OLD_EPOCH_DATABASE,
        expected_file_mode=0o440,
        expected_parent_mode=0o550,
        expected_uid=0,
        expected_gid=telegram_gid,
    )
    require(
        sealed_bundle["bundle_digest"] == sealed_bundle_digest,
        "target_old_epoch_bundle_rejected",
    )
    new_parent = NEW_EPOCH_DATABASE.parent.stat()
    new_database = _regular_metadata(NEW_EPOCH_DATABASE)
    identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
    require(new_parent.st_uid == identity.pw_uid and stat.S_IMODE(new_parent.st_mode) == 0o700, "target_new_epoch_parent_rejected")
    require(new_database.st_uid == identity.pw_uid and stat.S_IMODE(new_database.st_mode) == 0o600, "target_new_epoch_database_rejected")
    require_resume_config_not_binding_source(read_json(TELEGRAM_CONFIG))
    empty = verify_empty_epoch_from_runtime_config(
        NEW_EPOCH_DATABASE,
        expected_config_projection=expected_runtime_config,
        expected_uid=identity.pw_uid,
        expected_gid=identity.pw_gid,
    )
    require(empty["initialized"] is True, "target_new_epoch_not_initialized")
    return {
        "new_epoch_empty": True,
        "new_epoch_id": NEW_EPOCH_ID,
        "old_epoch_bundle_digest": sealed_bundle_digest,
        "old_epoch_bundle_schema": BUNDLE_SCHEMA,
        "old_epoch_read_only": True,
        "runtime_release": runtime_digest,
        "selector_sha256": digest_bytes(selector),
    }


def activate(
    runtime_candidate: Path,
    *,
    core_commit: str,
    deploy_commit: str,
    expected_core_release: str,
    expected_runtime_release: str,
    expected_plugin_release: str,
    expected_old_sha256: str,
    expected_revision: int,
    expected_turns: int,
    expected_summaries: int,
    expected_pending: int,
    expected_plan_sha256: str | None,
    preflight_only: bool,
) -> dict[str, object]:
    require(os.geteuid() == 0, "root_identity_required")
    for value, code in ((core_commit, "core_commit_rejected"), (deploy_commit, "deploy_commit_rejected")):
        require(_COMMIT.fullmatch(value) is not None, code)
    for value, code in (
        (expected_core_release, "core_release_rejected"),
        (expected_runtime_release, "runtime_release_rejected"),
        (expected_plugin_release, "plugin_release_rejected"),
        (expected_old_sha256, "old_epoch_digest_rejected"),
    ):
        require(_DIGEST.fullmatch(value) is not None, code)
    runtime_digest = validate_runtime(runtime_candidate, core_commit, deploy_commit)
    verify_runtime_startup_smoke(runtime_candidate)
    verify_new_epoch_startup_smoke(runtime_candidate)
    prestate = verify_live_prestate(
        expected_core_release=expected_core_release,
        expected_runtime_release=expected_runtime_release,
        expected_plugin_release=expected_plugin_release,
        expected_old_sha256=expected_old_sha256,
        revision=expected_revision,
        turns=expected_turns,
        summaries=expected_summaries,
        pending=expected_pending,
    )
    plan = build_plan(
        runtime_candidate,
        core_commit=core_commit,
        deploy_commit=deploy_commit,
        prestate=prestate,
    )
    plan_sha256 = digest_bytes(plan)
    if expected_plan_sha256 is not None:
        require(plan_sha256 == expected_plan_sha256, "plan_digest_drifted")
    if preflight_only:
        return {"plan_sha256": plan_sha256, "status": "ready"}
    require(expected_plan_sha256 is not None, "expected_plan_required")
    backup_root, old_dropin, old_selector = backup(plan, prestate)
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_ROOT, 0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    journal = STATE_ROOT / f"JOURNAL-{stamp}-{plan_sha256[:12]}.json"
    atomic_write(journal, canonical({"plan_sha256": plan_sha256, "schema": SCHEMA, "status": "activating"}), mode=0o600)
    telegram_gid = grp.getgrnam("myuna-gateway-telegram").gr_gid
    mutated = False
    rollback_bundle_prestate = dict(prestate["old_epoch"])
    current_bundle_digest = str(rollback_bundle_prestate["bundle_digest"])
    restore_bundle_permissions_needed = False
    try:
        install_tree(
            runtime_candidate,
            RUNTIME_ROOT / runtime_digest,
            gid=telegram_gid,
            directory_mode=0o550,
            file_mode=0o440,
        )
        require(tree_inventory(runtime_candidate) == tree_inventory(RUNTIME_ROOT / runtime_digest), "installed_runtime_drifted")
        stop_telegram()
        mutated = True
        quiesced_metadata = inspect_epoch_metadata(OLD_EPOCH_DATABASE)
        require_expected_old_epoch(
            quiesced_metadata,
            revision=expected_revision,
            turns=expected_turns,
            summaries=expected_summaries,
            pending=expected_pending,
        )
        identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
        quiesced_bundle_first = inspect_epoch_bundle(
            OLD_EPOCH_DATABASE,
            expected_file_mode=0o600,
            expected_parent_mode=0o700,
            expected_uid=identity.pw_uid,
            expected_gid=identity.pw_gid,
        )
        time.sleep(0.25)
        quiesced_bundle_second = inspect_epoch_bundle(
            OLD_EPOCH_DATABASE,
            expected_file_mode=0o600,
            expected_parent_mode=0o700,
            expected_uid=identity.pw_uid,
            expected_gid=identity.pw_gid,
        )
        current_bundle_digest = require_same_bundle(
            quiesced_bundle_first,
            quiesced_bundle_second,
        )
        rollback_bundle_prestate = quiesced_bundle_second
        require(not NEW_EPOCH_DATABASE.parent.exists(), "new_epoch_preexisting")
        restore_bundle_permissions_needed = True
        seal_old_epoch(current_bundle_digest)
        prepare_new_epoch_parent()
        selector = canonical(selector_payload(current_bundle_digest))
        atomic_write(SELECTOR_PATH, selector, mode=0o640, gid=telegram_gid)
        atomic_write(TELEGRAM_DROPIN, render_telegram_dropin(runtime_digest), mode=0o644)
        start_telegram()
        deadline = time.monotonic() + 30
        while True:
            try:
                target = verify_target(
                    runtime_digest,
                    current_bundle_digest,
                    selector,
                    dict(prestate["runtime_config"]),
                )
                break
            except (
                ExternalEpochBundleRejected,
                ExternalEpochRejected,
                RolloverRejected,
                FileNotFoundError,
                sqlite3.Error,
            ):
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
            "status": "ACTIVE_WAITING_OWNER_ORGANIC_TELEGRAM_RECOVERY_E2E",
            **target,
        }
        atomic_write(journal, canonical(receipt), mode=0o600)
        atomic_write(STATE_ROOT / f"RECEIPT-{stamp}-{plan_sha256[:12]}.json", canonical(receipt), mode=0o600)
        return receipt
    except Exception as exc:
        rollback = "not_needed"
        if mutated:
            restore_prestate(
                prestate,
                old_dropin,
                old_selector,
                bundle_prestate=rollback_bundle_prestate,
                current_bundle_digest=current_bundle_digest,
                restore_bundle_permissions_needed=restore_bundle_permissions_needed,
            )
            rollback = "verified"
        atomic_write(
            journal,
            canonical(
                {
                    "channel_called": False,
                    "failure_gate": failure_code(exc),
                    "model_called": False,
                    "plan_sha256": plan_sha256,
                    "raw_content_recorded": False,
                    "rollback": rollback,
                    "schema": SCHEMA,
                    "status": "rolled_back" if mutated else "failed_before_mutation",
                }
            ),
            mode=0o600,
        )
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
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
            arguments.runtime_candidate.resolve(),
            core_commit=arguments.core_commit,
            deploy_commit=arguments.deploy_commit,
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
    except (
        ActivationRejected,
        ExternalEpochBundleRejected,
        ExternalEpochRejected,
        RolloverRejected,
        OSError,
        sqlite3.Error,
        ValueError,
        subprocess.SubprocessError,
    ) as exc:
        print(json.dumps({"failure_gate": failure_code(exc), "status": "rejected"}, separators=(",", ":"), sort_keys=True))
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
