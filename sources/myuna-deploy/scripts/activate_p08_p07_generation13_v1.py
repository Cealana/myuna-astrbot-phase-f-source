#!/usr/bin/env python3
"""Atomic generation-13 P07 + Telegram plugin + P08 coordinator.

This module is source-only until a separate T2 gate binds an exact plan digest.
All journal and receipt fields are content-free metadata.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pwd
import re
import stat
import time
from typing import Mapping

import activate_p08_active_temporal_context_v1 as p08_activation
from activate_p07_d_generation13_v1 import (
    Generation13ActivationRejected,
    Generation13LiveBackend,
    PreparedActivation as P07PreparedActivation,
    activate as activate_p07_component,
    canonical,
    digest,
    prepare_activation as prepare_p07_activation,
)
from activate_p07_hybrid_external_generation_v1 import (
    PLUGIN_ROOT,
    TELEGRAM_CONFIG,
    TELEGRAM_RUNTIME_USER,
    TELEGRAM_SERVICE,
    TELEGRAM_SOCKET,
    atomic_write,
    digest_bytes,
    digest_file,
    install_tree,
    show,
    systemctl,
    tree_inventory,
)
from build_telegram_gateway_release_v1 import verify_release as verify_plugin_release
from p07_d_generation13_release_set import phase_f_selected_target
from p08_p07_combined_release_set_v2 import CombinedReleaseSet
from p08_p07_combined_transaction_v1 import (
    CombinedReleaseSetTransaction,
    CombinedTransactionRejected,
)


PLAN_SCHEMA = "myuna.p08-p07-generation13-activation-plan.v1"
JOURNAL_SCHEMA = "myuna.p08-p07-generation13-journal.v1"
RECEIPT_SCHEMA = "myuna.p08-p07-generation13-receipt.v1"
STATE_ROOT = Path("/var/lib/myuna-telegram-gateway/p08-p07-generation13-v1")
BACKUP_ROOT = Path("/var/backups/myuna/p08-p07-generation13-v1")
ATTEMPT_LEDGER = STATE_ROOT / "ATTEMPT_LEDGER.json"
MAX_ATTEMPTS = 2
_SHA = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


class CombinedActivationRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def require(condition: bool, code: str) -> None:
    if not condition:
        raise CombinedActivationRejected(code)


def _safe_json(path: Path) -> dict[str, object]:
    metadata = path.lstat()
    require(
        stat.S_ISREG(metadata.st_mode) and not path.is_symlink(),
        "json_type_rejected",
    )
    try:
        payload = json.loads(path.read_text("ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CombinedActivationRejected("json_document_rejected") from exc
    require(isinstance(payload, dict), "json_document_rejected")
    return payload


def _plugin_evidence(plugin_release: Path) -> dict[str, object]:
    digest_value = plugin_release.name
    require(_SHA.fullmatch(digest_value) is not None, "plugin_release_name_rejected")
    document = _safe_json(plugin_release.parent / f"{digest_value}.manifest.json")
    require(
        document.get("release_digest") == digest_value
        and verify_plugin_release(plugin_release.parent, document),
        "plugin_release_rejected",
    )
    plugin = plugin_release / "channels/astrbot-telegram/plugin/myuna_telegram_gateway"
    main = plugin / "main.py"
    protocol = plugin / "protocol.py"
    require(main.is_file() and protocol.is_file(), "plugin_inventory_rejected")
    return {
        "candidate_path": plugin_release.as_posix(),
        "main_sha256": digest_file(main),
        "plugin_path": plugin.parent.as_posix(),
        "protocol_sha256": digest_file(protocol),
        "release_digest": digest_value,
    }


def _plugin_config(plugin_release_digest: str) -> bytes:
    target = PLUGIN_ROOT / plugin_release_digest
    return canonical(
        {
            "channel_root": "/srv/myuna/channels/astrbot-telegram/dev",
            "compose_file": (
                target / "channels/astrbot-telegram/compose.dev.yml"
            ).as_posix(),
            "gateway_release": plugin_release_digest,
            "plugin_root": (
                target
                / "channels/astrbot-telegram/plugin/myuna_telegram_gateway"
            ).as_posix(),
            "schema": "myuna.telegram.r5-boot-resume-config.v1",
        }
    )


def _p08_activation_contract_digest(plan: Mapping[str, object]) -> str:
    required = {
        "core_commit",
        "deploy_commit",
        "files_prestate",
        "gateway_client_sha256",
        "gateway_manifest_digest",
        "gateway_runtime",
        "plan_digest",
        "plugin",
        "plugin_digest",
        "release_digest",
        "release_source",
        "release_target",
        "schema",
        "state_prestate",
    }
    require(set(plan) == required, "p08_activation_contract_fields_rejected")
    path_bound = {"gateway_runtime", "plan_digest", "plugin", "release_source"}
    semantic = {key: plan[key] for key in sorted(required - path_bound)}
    return digest("myuna-p08-activation-contract-v1", semantic)


def _previous_plugin_release(config_bytes: bytes) -> str:
    try:
        payload = json.loads(config_bytes)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CombinedActivationRejected("plugin_config_rejected") from exc
    require(
        isinstance(payload, dict)
        and payload.get("schema") == "myuna.telegram.r5-boot-resume-config.v1"
        and _SHA.fullmatch(str(payload.get("gateway_release"))) is not None,
        "plugin_config_rejected",
    )
    return str(payload["gateway_release"])


def _permissions_digest(bundle: Mapping[str, object]) -> str:
    projection = bundle.get("bundle_projection")
    require(isinstance(projection, dict), "previous_bundle_projection_rejected")
    files = projection.get("files")
    require(isinstance(files, list), "previous_bundle_projection_rejected")
    content_free = []
    for item in files:
        require(isinstance(item, dict), "previous_bundle_projection_rejected")
        content_free.append(
            {
                key: item.get(key)
                for key in ("gid", "mode", "name", "state", "uid")
            }
        )
    return digest(
        "myuna-p08-p07-generation13-previous-epoch-permissions-v1",
        {"files": content_free, "parent": projection.get("parent")},
    )


def _units_digest(p08_release: Path) -> str:
    rows = []
    for name in (
        p08_activation.SERVICE,
        p08_activation.SOCKET,
        "myuna-active-temporal-context-v1.sysusers.conf",
        "myuna-active-temporal-context-v1.tmpfiles.conf",
    ):
        path = p08_release / "systemd" / name
        require(path.is_file() and not path.is_symlink(), "p08_unit_inventory_rejected")
        rows.append({"name": name, "sha256": digest_file(path)})
    return digest("myuna-p08-generation13-unit-set-v1", rows)


@dataclass(slots=True)
class PreparedCombinedActivation:
    p07: P07PreparedActivation
    p08_plan: dict[str, object]
    plugin_candidate: Path
    plugin_release_digest: str
    plugin_target_config: bytes
    combined_release_set: CombinedReleaseSet
    plan_payload: dict[str, object]

    @property
    def plan_digest(self) -> str:
        return digest_bytes(canonical(self.plan_payload))

    def as_payload(self) -> dict[str, object]:
        return {
            "schema": PLAN_SCHEMA,
            "plan_digest": self.plan_digest,
            **self.plan_payload,
        }


def prepare_combined_activation(
    *,
    core_candidate: Path,
    runtime_candidate: Path,
    p08_release: Path,
    plugin_release: Path,
    core_commit: str,
    deploy_commit: str,
    expected_core_release: str,
    expected_runtime_release: str,
    expected_definition_release: str,
    expected_previous_epoch_sha256: str,
    expected_previous_release_set_id: str,
    expected_revision: int,
    expected_turns: int,
    expected_summaries: int,
    expected_pending: int,
) -> PreparedCombinedActivation:
    require(_COMMIT.fullmatch(core_commit) is not None, "core_commit_rejected")
    require(_COMMIT.fullmatch(deploy_commit) is not None, "deploy_commit_rejected")
    p07 = prepare_p07_activation(
        core_candidate,
        runtime_candidate,
        core_commit=core_commit,
        deploy_commit=deploy_commit,
        expected_core_release=expected_core_release,
        expected_runtime_release=expected_runtime_release,
        expected_definition_release=expected_definition_release,
        expected_previous_epoch_sha256=expected_previous_epoch_sha256,
        expected_previous_release_set_id=expected_previous_release_set_id,
        expected_revision=expected_revision,
        expected_turns=expected_turns,
        expected_summaries=expected_summaries,
        expected_pending=expected_pending,
    )
    p07_component_preflight = activate_p07_component(
        p07,
        expected_plan_sha256=p07.plan_digest,
        preflight_only=True,
    )
    require(
        p07_component_preflight.get("status") == "ready"
        and p07_component_preflight.get("release_set_id")
        == p07.release_set.release_set_id,
        "p07_component_preflight_rejected",
    )
    plugin = _plugin_evidence(plugin_release)
    plugin_path = Path(str(plugin["plugin_path"]))
    p08_plan = p08_activation.prepare_plan(
        release=p08_release,
        gateway_runtime=runtime_candidate,
        plugin=plugin_path,
    ).as_payload()
    require(
        p08_plan["core_commit"] == core_commit
        and p08_plan["deploy_commit"] == deploy_commit,
        "p08_source_identity_rejected",
    )
    config_prestate = TELEGRAM_CONFIG.read_bytes()
    previous_plugin_release = _previous_plugin_release(config_prestate)
    target_config = _plugin_config(str(plugin["release_digest"]))
    p07.target_telegram_config_digest = digest_bytes(target_config)
    previous_bundle = p07.prestate["previous_bundle"]
    require(isinstance(previous_bundle, dict), "previous_bundle_projection_rejected")
    files = p07.prestate["files"]
    require(isinstance(files, dict), "p07_prestate_rejected")
    release_projection = files.get("release_set")
    require(isinstance(release_projection, dict), "previous_release_set_projection_rejected")
    p08_prestate = p08_plan.get("files_prestate")
    require(
        isinstance(p08_prestate, dict)
        and all(
            isinstance(item, dict) and item.get("state") == "absent"
            for item in p08_prestate.values()
        )
        and p08_plan.get("state_prestate") == "absent",
        "p08_prestate_not_absent",
    )
    combined_prestate = {
        "p07_prestate_digest": digest(
            "myuna-p08-p07-generation13-p07-prestate-v1", p07.prestate
        ),
        "p08_files": p08_prestate,
        "plugin_config_sha256": digest_bytes(config_prestate),
        "previous_plugin_release": previous_plugin_release,
    }
    combined = CombinedReleaseSet.create(
        p07={
            "core_release_digest": p07.release_set.core["release_digest"],
            "credential_projection_digest": p07.release_set.credential["projection_digest"],
            "epoch_id": p07.release_set.epoch["epoch_id"],
            "epoch_path": p07.release_set.epoch["database_path"],
            "generation": p07.release_set.generation,
            "release_set_id": p07.release_set.release_set_id,
            "runtime_config_digest": p07.release_set.runtime_config["digest"],
            "runtime_release_digest": p07.release_set.telegram_runtime["release_digest"],
            "selector_digest": p07.release_set.selector["digest"],
        },
        telegram_plugin={
            "main_sha256": plugin["main_sha256"],
            "protocol_sha256": plugin["protocol_sha256"],
            "release_digest": plugin["release_digest"],
            "selected_config_path": TELEGRAM_CONFIG.as_posix(),
            "selected_config_prestate_digest": digest_bytes(config_prestate),
            "selected_config_target_digest": digest_bytes(target_config),
        },
        p08={
            "activation_contract_digest": _p08_activation_contract_digest(p08_plan),
            "release_digest": p08_plan["release_digest"],
            "selector_path": p08_activation.SELECTOR_JSON.as_posix(),
            "selector_schema": p08_activation.SELECTOR_SCHEMA,
            "service": p08_activation.SERVICE,
            "socket": p08_activation.SOCKET,
            "units_digest": _units_digest(p08_release),
        },
        rollback={
            "combined_prestate_digest": digest(
                "myuna-p08-p07-generation13-combined-prestate-v1",
                combined_prestate,
            ),
            "desired_service_states_digest": p07.release_set.rollback["desired_service_states_digest"],
            "p08_prestate": "absent",
            "previous_core_release_digest": p07.release_set.rollback["core_release_digest"],
            "previous_epoch_bundle_digest": p07.release_set.rollback["epoch_bundle_digest"],
            "previous_epoch_permissions_digest": _permissions_digest(previous_bundle),
            "previous_generation": 11,
            "previous_plugin_config_digest": digest_bytes(config_prestate),
            "previous_plugin_release_digest": previous_plugin_release,
            "previous_release_set_digest": release_projection["sha256"],
            "previous_release_set_id": expected_previous_release_set_id,
            "previous_runtime_release_digest": p07.release_set.rollback["runtime_release_digest"],
            "previous_selector_digest": p07.release_set.rollback["selector_digest"],
            "reverse_order": ["p08", "telegram_plugin", "p07"],
        },
    )
    plan_payload = {
        "boundaries": {
            "channel": "authenticated-telegram-owner-private-only",
            "continuity": "external-context-reset-accepted",
            "definition_profile": "effective-v6",
            "model_channel_provider_called": False,
            "old_epoch_content_migrated": False,
            "other_program_live_changed": False,
        },
        "combined_release_set": combined.as_payload(),
        "inputs": {
            "core_candidate": core_candidate.as_posix(),
            "core_commit": core_commit,
            "deploy_commit": deploy_commit,
            "expected_core_release": expected_core_release,
            "expected_definition_release": expected_definition_release,
            "expected_pending": expected_pending,
            "expected_previous_epoch_sha256": expected_previous_epoch_sha256,
            "expected_previous_release_set_id": expected_previous_release_set_id,
            "expected_revision": expected_revision,
            "expected_runtime_release": expected_runtime_release,
            "expected_summaries": expected_summaries,
            "expected_turns": expected_turns,
            "p08_release": p08_release.as_posix(),
            "plugin_release": plugin_release.as_posix(),
            "runtime_candidate": runtime_candidate.as_posix(),
        },
        "p07_plan_digest": p07.plan_digest,
        "p08_plan": p08_plan,
        "plugin_target_config_sha256": digest_bytes(target_config),
    }
    return PreparedCombinedActivation(
        p07=p07,
        p08_plan=p08_plan,
        plugin_candidate=plugin_release,
        plugin_release_digest=str(plugin["release_digest"]),
        plugin_target_config=target_config,
        combined_release_set=combined,
        plan_payload=plan_payload,
    )


class LiveCombinedBackend:
    def __init__(self, prepared: PreparedCombinedActivation, backup_root: Path) -> None:
        self.prepared = prepared
        self.backup_root = backup_root
        p07_backup = backup_root / "p07"
        p07_backup.mkdir(mode=0o700)
        self.p07_backend = Generation13LiveBackend(prepared.p07, p07_backup)
        self.p07_prestate = None
        self.plugin_prestate = TELEGRAM_CONFIG.read_bytes()

    def capture_prestate(self) -> str:
        self.p07_prestate = self.p07_backend.capture_prestate()
        return self.prepared.combined_release_set.rollback["combined_prestate_digest"]

    def verify_preflight(self, prestate_digest: str) -> None:
        require(
            prestate_digest
            == self.prepared.combined_release_set.rollback["combined_prestate_digest"],
            "combined_prestate_drifted",
        )
        assert self.p07_prestate is not None
        self.p07_backend.verify_rollback_ready(self.p07_prestate)

    def apply_p07(self) -> None:
        snapshot = self.p07_backend.load_target_snapshot()
        self.p07_backend.observe_target_preflight(snapshot)
        self.p07_backend.stop_target_services()
        self.p07_backend.verify_target_services_stopped()
        self.p07_backend.apply_target_release_set(snapshot)
        self.p07_backend.daemon_reload()
        self.p07_backend.start_target_core()

    def apply_telegram_plugin(self) -> None:
        identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
        install_tree(
            self.prepared.plugin_candidate,
            PLUGIN_ROOT / self.prepared.plugin_release_digest,
            gid=identity.pw_gid,
            directory_mode=0o550,
            file_mode=0o440,
        )
        require(
            tree_inventory(self.prepared.plugin_candidate)
            == tree_inventory(PLUGIN_ROOT / self.prepared.plugin_release_digest),
            "installed_plugin_inventory_rejected",
        )
        atomic_write(TELEGRAM_CONFIG, self.prepared.plugin_target_config, mode=0o600)
        self.p07_backend.start_target_telegram()

    def apply_p08(self) -> None:
        p08_activation.execute_plan(self.prepared.p08_plan)

    def observe_target(self) -> str:
        p07_observation = self.p07_backend.observe_target()
        require(
            TELEGRAM_CONFIG.read_bytes() == self.prepared.plugin_target_config,
            "plugin_target_config_rejected",
        )
        require(
            tree_inventory(self.prepared.plugin_candidate)
            == tree_inventory(PLUGIN_ROOT / self.prepared.plugin_release_digest),
            "installed_plugin_inventory_rejected",
        )
        p08_selector = _safe_json(p08_activation.SELECTOR_JSON)
        require(
            p08_selector.get("schema") == p08_activation.SELECTOR_SCHEMA
            and p08_selector.get("plan_digest")
            == self.prepared.p08_plan["plan_digest"]
            and p08_selector.get("release_digest")
            == self.prepared.p08_plan["release_digest"]
            and p08_selector.get("plugin_digest")
            == self.prepared.p08_plan["plugin_digest"],
            "p08_selector_rejected",
        )
        p08_activation._validate_state_files(
            p08_activation.STATE_ROOT,
            service_uid=pwd.getpwnam("myuna_active_temporal").pw_uid,
        )
        for unit in (p08_activation.SERVICE, p08_activation.SOCKET):
            require(
                p08_activation.subprocess.run(
                    ["/usr/bin/systemctl", "is-active", "--quiet", unit],
                    stdin=p08_activation.subprocess.DEVNULL,
                    stdout=p08_activation.subprocess.DEVNULL,
                    stderr=p08_activation.subprocess.DEVNULL,
                    check=False,
                    timeout=10,
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
                ).returncode
                == 0,
                "p08_service_inactive",
            )
        first = {
            unit: {
                "active": show(unit, "ActiveState"),
                "result": show(unit, "Result"),
                "restarts": show(unit, "NRestarts") or "0",
                "sub": show(unit, "SubState"),
            }
            for unit in (p08_activation.SERVICE, p08_activation.SOCKET)
        }
        time.sleep(5)
        second = {
            unit: {
                "active": show(unit, "ActiveState"),
                "result": show(unit, "Result"),
                "restarts": show(unit, "NRestarts") or "0",
                "sub": show(unit, "SubState"),
            }
            for unit in (p08_activation.SERVICE, p08_activation.SOCKET)
        }
        require(first == second, "p08_service_stability_rejected")
        require(
            all(
                value["active"] == "active"
                and value["result"] == "success"
                and str(value["restarts"]).isdigit()
                for value in second.values()
            ),
            "p08_service_stability_rejected",
        )
        return digest(
            "myuna-p08-p07-generation13-target-observation-v1",
            {
                "combined_release_set_id": self.prepared.combined_release_set.release_set_id,
                "p07_release_set_id": p07_observation.selected_release_set_id,
                "p08_plan_digest": self.prepared.p08_plan["plan_digest"],
                "plugin_config_sha256": digest_file(TELEGRAM_CONFIG),
            },
        )

    def rollback_p08(self) -> None:
        p08_backup = (
            p08_activation.BACKUP_ROOT
            / str(self.prepared.p08_plan["plan_digest"])
        )
        if not p08_backup.exists() and not p08_backup.is_symlink():
            require(
                not p08_activation.STATE_ROOT.exists()
                and not p08_activation.STATE_ROOT.is_symlink()
                and all(
                    isinstance(projection, dict)
                    and projection.get("state") == "absent"
                    and not Path(path).exists()
                    and not Path(path).is_symlink()
                    for path, projection in self.prepared.p08_plan[
                        "files_prestate"
                    ].items()
                ),
                "p08_partial_rollback_evidence_missing",
            )
            return
        p08_activation.rollback_activated_plan(self.prepared.p08_plan)

    def rollback_telegram_plugin(self) -> None:
        systemctl("stop", TELEGRAM_SOCKET, TELEGRAM_SERVICE)
        atomic_write(TELEGRAM_CONFIG, self.plugin_prestate, mode=0o600)

    def rollback_p07(self) -> None:
        assert self.p07_prestate is not None
        self.p07_backend.stop_target_services()
        self.p07_backend.verify_target_services_stopped()
        self.p07_backend.restore_prestate(self.p07_prestate)
        self.p07_backend.daemon_reload()
        self.p07_backend.start_prestate_services(self.p07_prestate)
        observed = self.p07_backend.observe_prestate()
        expected = self.p07_backend.expected_rollback_observation(self.p07_prestate)
        require(observed == expected, "p07_functional_rollback_rejected")

    def observe_prestate(self, expected_digest: str) -> str:
        require(
            TELEGRAM_CONFIG.read_bytes() == self.plugin_prestate,
            "plugin_rollback_rejected",
        )
        return expected_digest


def _attempt_count() -> int:
    if not ATTEMPT_LEDGER.exists() and not ATTEMPT_LEDGER.is_symlink():
        return 0
    payload = _safe_json(ATTEMPT_LEDGER)
    require(
        payload.get("schema") == "myuna.p08-p07-generation13-attempt-ledger.v1"
        and type(payload.get("attempts")) is int
        and 0 <= int(payload["attempts"]) <= MAX_ATTEMPTS,
        "attempt_ledger_rejected",
    )
    return int(payload["attempts"])


def _consume_attempt(plan_digest: str) -> int:
    count = _attempt_count()
    require(count < MAX_ATTEMPTS, "live_attempt_budget_exhausted")
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_ROOT, 0o700)
    count += 1
    atomic_write(
        ATTEMPT_LEDGER,
        canonical(
            {
                "attempts": count,
                "last_plan_sha256": plan_digest,
                "schema": "myuna.p08-p07-generation13-attempt-ledger.v1",
            }
        ),
        mode=0o600,
    )
    return count


def activate_combined(
    prepared: PreparedCombinedActivation,
    *,
    expected_plan_digest: str | None,
    preflight_only: bool,
) -> dict[str, object]:
    attempts = _attempt_count()
    require(attempts < MAX_ATTEMPTS, "live_attempt_budget_exhausted")
    if expected_plan_digest is not None:
        require(prepared.plan_digest == expected_plan_digest, "plan_digest_drifted")
    if preflight_only:
        return {
            "attempts": attempts,
            "combined_release_set_id": prepared.combined_release_set.release_set_id,
            "plan_digest": prepared.plan_digest,
            "status": "ready",
        }
    if phase_f_selected_target(Path(__file__).resolve().parent):
        raise CombinedActivationRejected("phase_f_canonical_owner_required")
    require(expected_plan_digest is not None, "expected_plan_required")
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(BACKUP_ROOT, 0o700)
    backup = BACKUP_ROOT / prepared.plan_digest
    require(not backup.exists() and not backup.is_symlink(), "activation_evidence_preexisting")
    backup.mkdir(mode=0o700)
    atomic_write(backup / "PLAN.json", canonical(prepared.as_payload()), mode=0o600)
    attempt = _consume_attempt(prepared.plan_digest)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    journal_path = STATE_ROOT / f"JOURNAL-{stamp}-{prepared.plan_digest[:12]}.json"
    journal_rows: list[dict[str, object]] = []

    def journal(phase: str, status: str) -> None:
        journal_rows.append({"phase": phase, "status": status})
        atomic_write(
            journal_path,
            canonical(
                {
                    "attempt": attempt,
                    "events": journal_rows,
                    "plan_digest": prepared.plan_digest,
                    "schema": JOURNAL_SCHEMA,
                }
            ),
            mode=0o600,
        )

    transaction = CombinedReleaseSetTransaction(
        LiveCombinedBackend(prepared, backup),
        combined_release_set_id=prepared.combined_release_set.release_set_id,
        journal=journal,
    )
    try:
        result = transaction.run()
    except CombinedTransactionRejected as exc:
        failure_receipt = {
            "activation_failure_gate": exc.activation_failure_code,
            "attempt": attempt,
            "channel_called": False,
            "combined_release_set_id": prepared.combined_release_set.release_set_id,
            "failure_gate": exc.code,
            "model_or_provider_called": False,
            "plan_digest": prepared.plan_digest,
            "private_content_read": False,
            "rollback_failure_gate": exc.rollback_failure_code,
            "schema": RECEIPT_SCHEMA,
            "status": "rolled_back_or_hard_stop",
        }
        atomic_write(
            STATE_ROOT / f"RECEIPT-{stamp}-{prepared.plan_digest[:12]}.json",
            canonical(failure_receipt),
            mode=0o600,
        )
        raise
    receipt = {
        "attempt": attempt,
        "channel_called": False,
        "combined_release_set_id": result.combined_release_set_id,
        "continuity": "external-context-reset-accepted",
        "definition_profile": "effective-v6",
        "model_or_provider_called": False,
        "plan_digest": prepared.plan_digest,
        "private_content_read": False,
        "schema": RECEIPT_SCHEMA,
        "status": "ACTIVE_WAITING_OWNER_ORGANIC_TELEGRAM_E2E",
        "target_observation_digest": result.target_observation_digest,
    }
    atomic_write(
        STATE_ROOT / f"RECEIPT-{stamp}-{prepared.plan_digest[:12]}.json",
        canonical(receipt),
        mode=0o600,
    )
    return receipt


def _prepare_from_inputs(inputs: Mapping[str, object]) -> PreparedCombinedActivation:
    return prepare_combined_activation(
        core_candidate=Path(str(inputs["core_candidate"])),
        runtime_candidate=Path(str(inputs["runtime_candidate"])),
        p08_release=Path(str(inputs["p08_release"])),
        plugin_release=Path(str(inputs["plugin_release"])),
        core_commit=str(inputs["core_commit"]),
        deploy_commit=str(inputs["deploy_commit"]),
        expected_core_release=str(inputs["expected_core_release"]),
        expected_runtime_release=str(inputs["expected_runtime_release"]),
        expected_definition_release=str(inputs["expected_definition_release"]),
        expected_previous_epoch_sha256=str(inputs["expected_previous_epoch_sha256"]),
        expected_previous_release_set_id=str(inputs["expected_previous_release_set_id"]),
        expected_revision=int(inputs["expected_revision"]),
        expected_turns=int(inputs["expected_turns"]),
        expected_summaries=int(inputs["expected_summaries"]),
        expected_pending=int(inputs["expected_pending"]),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--core-candidate", required=True, type=Path)
    prepare.add_argument("--runtime-candidate", required=True, type=Path)
    prepare.add_argument("--p08-release", required=True, type=Path)
    prepare.add_argument("--plugin-release", required=True, type=Path)
    prepare.add_argument("--core-commit", required=True)
    prepare.add_argument("--deploy-commit", required=True)
    prepare.add_argument("--expected-core-release", required=True)
    prepare.add_argument("--expected-runtime-release", required=True)
    prepare.add_argument("--expected-definition-release", required=True)
    prepare.add_argument("--expected-previous-epoch-sha256", required=True)
    prepare.add_argument("--expected-previous-release-set-id", required=True)
    prepare.add_argument("--expected-revision", required=True, type=int)
    prepare.add_argument("--expected-turns", required=True, type=int)
    prepare.add_argument("--expected-summaries", required=True, type=int)
    prepare.add_argument("--expected-pending", required=True, type=int)
    execute = commands.add_parser("execute")
    execute.add_argument("--plan", required=True, type=Path)
    execute.add_argument("--expected-plan-digest")
    execute.add_argument("--preflight-only", action="store_true")
    values = parser.parse_args()
    try:
        if values.command == "prepare":
            prepared = prepare_combined_activation(
                core_candidate=values.core_candidate.resolve(),
                runtime_candidate=values.runtime_candidate.resolve(),
                p08_release=values.p08_release.resolve(),
                plugin_release=values.plugin_release.resolve(),
                core_commit=values.core_commit,
                deploy_commit=values.deploy_commit,
                expected_core_release=values.expected_core_release,
                expected_runtime_release=values.expected_runtime_release,
                expected_definition_release=values.expected_definition_release,
                expected_previous_epoch_sha256=values.expected_previous_epoch_sha256,
                expected_previous_release_set_id=values.expected_previous_release_set_id,
                expected_revision=values.expected_revision,
                expected_turns=values.expected_turns,
                expected_summaries=values.expected_summaries,
                expected_pending=values.expected_pending,
            )
            result = prepared.as_payload()
        else:
            raw = _safe_json(values.plan.resolve())
            plan_digest = raw.pop("plan_digest", None)
            require(raw.pop("schema", None) == PLAN_SCHEMA, "plan_schema_rejected")
            require(plan_digest == digest_bytes(canonical(raw)), "plan_digest_rejected")
            inputs = raw.get("inputs")
            require(isinstance(inputs, dict), "plan_inputs_rejected")
            prepared = _prepare_from_inputs(inputs)
            require(prepared.plan_payload == raw, "plan_recompute_drifted")
            result = activate_combined(
                prepared,
                expected_plan_digest=values.expected_plan_digest,
                preflight_only=values.preflight_only,
            )
    except (
        CombinedActivationRejected,
        CombinedTransactionRejected,
        Generation13ActivationRejected,
        p08_activation.ActivationRejected,
        OSError,
        ValueError,
    ) as exc:
        code = getattr(exc, "code", None)
        print(
            json.dumps(
                {
                    "failure_gate": code
                    if isinstance(code, str) and re.fullmatch(r"[a-z][a-z0-9_]{2,127}", code)
                    else "combined_activation_rejected",
                    "status": "rejected",
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
