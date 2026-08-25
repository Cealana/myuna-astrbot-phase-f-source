from __future__ import annotations

from contextlib import contextmanager, nullcontext, redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import threading
import unittest
from unittest import mock

import p08_current_selected_upgrade_v1 as current
import p08_existing_state_upgrade_v1 as upgrade
import p08_formal_preflight_launcher_v1 as formal_launcher
import p08_post_target_action_v1 as post
from test_p08_existing_state_upgrade_v1 import (
    PREDECESSOR,
    RecordingRunner,
    UNIT_STATE,
    _synthetic_host,
    _target_release,
)


class SyntheticCrash(BaseException):
    pass


def _synthetic_forward_transition(
    root: Path,
    plan: dict[str, object],
    origin: dict[str, object],
    evidence: Path,
    persist,
) -> dict[str, object]:
    del root, origin, evidence
    persist(
        current.canonical(
            {
                "content_free_export_allowed": False,
                "plan_digest": plan["plan_digest"],
                "schema": "synthetic.p08-forward-binding.private.v1",
            }
        )
    )
    return {
        "replay_allowed": False,
        "state_effect": "committed",
        "status": "committed",
    }


def _synthetic_forward_reconcile(
    root: Path,
    plan: dict[str, object],
    origin: dict[str, object],
    evidence: Path,
) -> dict[str, object]:
    del root, plan, origin, evidence
    return {
        "replay_allowed": False,
        "state_effect": "committed",
        "status": "committed",
    }


def _synthetic_forward_reconcile_not_committed(
    root: Path,
    plan: dict[str, object],
    origin: dict[str, object],
    evidence: Path,
) -> dict[str, object]:
    del root, plan, origin, evidence
    return {
        "replay_allowed": False,
        "state_effect": "none",
        "status": "not_committed",
    }


def _synthetic_forward_state_verifier(
    root: Path, plan: dict[str, object], origin: dict[str, object]
) -> dict[str, object]:
    del root, plan, origin
    return {"history_preserved": True, "status": "valid"}


def _reject_forward_state_verifier(
    root: Path, plan: dict[str, object], origin: dict[str, object]
) -> dict[str, object]:
    del root, plan, origin
    raise AssertionError("forward state verifier must not run before commit")


def _write_json(path: Path, payload: object, mode: int = 0o600) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(current.canonical(payload))
    path.chmod(mode)
    return upgrade.digest_file(path)


def _retag_candidate(root: Path) -> Path:
    release = _target_release(root)
    for relative in (formal_launcher.LAUNCHER_RELATIVE, formal_launcher.BUILDER_RELATIVE):
        source = Path(current.__file__).resolve().parents[1] / relative
        destination = release / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(stat.S_IMODE(source.stat().st_mode))
    manifest_path = release / "manifest.json"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    manifest["core_commit"] = current.continuity.CORE_COMMIT
    manifest["p07_single_nonce_integration"] = (
        current.p07_single_nonce_integration_contract()
    )
    launcher_contract = formal_launcher.release_contract(release)
    binding_body = {
        "host": {"contract_digest": "e" * 64},
        "launcher": launcher_contract,
        "source_binding": {"binding_digest": "f" * 64},
    }
    manifest["formal_preflight_launcher_contract"] = {
        **binding_body,
        "contract_digest": formal_launcher.digest_bytes(
            formal_launcher.canonical(binding_body)
        ),
    }
    manifest["current_selected_upgrade_contract"] = current.release_contract(release)
    manifest["files"] = upgrade._release_inventory(release)
    raw = upgrade.canonical(manifest)
    manifest_path.write_bytes(raw + b"\n")
    target = release.parent / sha256(raw).hexdigest()
    release.rename(target)
    return target


def _selector_bytes(*, digest: str, deploy_commit: str, plan_digest: str) -> bytes:
    return (
        upgrade.canonical(
            {
                "core_commit": upgrade.TARGET_CORE_COMMIT,
                "deploy_commit": deploy_commit,
                "gateway_client_sha256": upgrade.PREDECESSOR_CLIENT_SHA256,
                "gateway_manifest_digest": upgrade.ACTIVE_GATEWAY_MANIFEST_DIGEST,
                "plan_digest": plan_digest,
                "plugin_digest": upgrade.ACTIVE_PLUGIN_DIGEST,
                "release_digest": digest,
                "release_path": str(upgrade.RELEASE_ROOT / digest),
                "schema": upgrade.SELECTOR_SCHEMA,
            }
        )
        + b"\n"
    )


@contextmanager
def _fixture(root: Path):
    selected = _target_release(root / "selected")
    host, identity = _synthetic_host(root)
    release_root = host / str(upgrade.RELEASE_ROOT).lstrip("/")
    release_root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(selected, release_root / selected.name)
    shutil.copytree(PREDECESSOR, release_root / PREDECESSOR.name)

    selected_manifest = json.loads((selected / "manifest.json").read_text("utf-8"))
    selected_deploy = str(selected_manifest["deploy_commit"])
    accepted_plan_digest = "a" * 64
    selector = _selector_bytes(
        digest=selected.name,
        deploy_commit=selected_deploy,
        plan_digest=accepted_plan_digest,
    )
    selector_env = (
        f"PYTHONPATH={upgrade.RELEASE_ROOT / selected.name}/src\n"
        f"MYUNA_P08_STATE_ROOT={upgrade.STATE_ROOT}\n"
        f"MYUNA_P08_SERVICE_UID={identity[0]}\n"
        f"MYUNA_P08_TELEGRAM_UID={identity[2]}\n"
    ).encode("ascii")
    public = {
        upgrade.SELECTOR_JSON: (selector, 0o600),
        upgrade.SELECTOR_ENV: (selector_env, 0o600),
        upgrade.UNIT_ROOT / upgrade.SERVICE: (
            (selected / upgrade.SERVICE_UNIT_PATH).read_bytes(),
            0o644,
        ),
        upgrade.UNIT_ROOT / upgrade.SOCKET: (
            (selected / upgrade.SOCKET_UNIT_PATH).read_bytes(),
            0o644,
        ),
    }
    for absolute, (payload, mode) in public.items():
        path = host / str(absolute).lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.chmod(mode)

    activation_root = host / "var/lib/myuna-activation-backups"
    activation_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    origin_root = activation_root / "synthetic-current-selected-origin"
    origin = {
        "active_gateway_runtime": {},
        "identity": {
            "service_gid": identity[1],
            "service_uid": identity[0],
            "telegram_uid": identity[2],
        },
        "plan_digest": "b" * 64,
        "predecessor": {
            "release_digest": upgrade.PREDECESSOR_RELEASE_DIGEST,
            "release_path": str(upgrade.RELEASE_ROOT / upgrade.PREDECESSOR_RELEASE_DIGEST),
        },
        "schema": upgrade.PLAN_SCHEMA,
    }
    origin_hashes = {
        "ORIGIN_PLAN_SHA256": _write_json(origin_root / "PLAN.json", origin),
        "ORIGIN_JOURNAL_SHA256": _write_json(
            origin_root / "JOURNAL.json", {"stage": "target_verified"}
        ),
        "ORIGIN_RECEIPT_SHA256": _write_json(
            origin_root / "RECEIPT.json",
            {"state_bytes_preserved": True, "status": "target_verified"},
        ),
    }

    accepted_incident = "c" * 64
    accepted_root = activation_root / "synthetic-accepted" / accepted_incident
    accepted_plan = {
        "action": "repair",
        "incident": {"incident_digest": accepted_incident},
        "plan_digest": accepted_plan_digest,
        "repair_target": {
            "release_digest": selected.name,
            "release_manifest_sha256": upgrade.digest_file(selected / "manifest.json"),
        },
        "schema": post.REPAIR_PLAN_SCHEMA,
        "single_bounded_action": True,
    }
    accepted_ledger = {
        "action": "repair",
        "attempts": 1,
        "consumed": True,
        "schema": post.REPAIR_LEDGER_SCHEMA,
    }
    accepted_journal = {"schema": post.REPAIR_JOURNAL_SCHEMA, "stage": "target_accepted"}
    accepted_receipt = {
        "schema": post.REPAIR_RECEIPT_SCHEMA,
        "state_bytes_preserved": True,
        "status": "repair_target_accepted",
    }
    public_manifest = {"synthetic": "public-backup"}
    state_manifest = {"synthetic": "opaque-state-backup-descriptor"}
    state_manifest_sha = _write_json(
        accepted_root / "current-state/STATE.json", state_manifest
    )
    accepted_binding = {
        "plan_digest": accepted_plan_digest,
        "schema": post.ACTION_STATE_BINDING_SCHEMA,
        "state_descriptor_sha256": state_manifest_sha,
    }
    accepted_hashes = {
        "ACCEPTED_PLAN_SHA256": _write_json(accepted_root / "PLAN.json", accepted_plan),
        "ACCEPTED_LEDGER_SHA256": _write_json(accepted_root / "LEDGER.json", accepted_ledger),
        "ACCEPTED_JOURNAL_SHA256": _write_json(accepted_root / "JOURNAL.json", accepted_journal),
        "ACCEPTED_RECEIPT_SHA256": _write_json(accepted_root / "RECEIPT.json", accepted_receipt),
        "ACCEPTED_STATE_BINDING_SHA256": _write_json(
            accepted_root / "STATE_BINDING.json", accepted_binding
        ),
        "ACCEPTED_PUBLIC_MANIFEST_SHA256": _write_json(
            accepted_root / "current-public/PUBLIC.json", public_manifest
        ),
        "ACCEPTED_STATE_MANIFEST_SHA256": state_manifest_sha,
    }

    failed_incident = "d" * 64
    failed_plan_digest = "e" * 64
    failed_strategy_digest = "f" * 64
    failed_controller_sha256 = "1" * 64
    failed_target_digest = "2" * 64
    failed_root = activation_root / "synthetic-failed" / failed_incident
    failed_public = {
        str(absolute): upgrade._file_projection(host / str(absolute).lstrip("/"))
        for absolute in sorted(public, key=str)
    }
    failed_plan = {
        "action": "upgrade",
        "current_target": {
            "public": failed_public,
            "release_digest": selected.name,
        },
        "incident": {"incident_digest": failed_incident},
        "plan_digest": failed_plan_digest,
        "schema": current.FAILED_PLAN_SCHEMA,
        "single_bounded_action": True,
        "strategy": {
            "controller_sha256": failed_controller_sha256,
            "strategy_digest": failed_strategy_digest,
        },
        "target": {"release_digest": failed_target_digest},
    }
    failed_ledger = {
        "action": "upgrade",
        "attempts": 1,
        "consumed": True,
        "incident_digest": failed_incident,
        "plan_digest": failed_plan_digest,
        "schema": current.FAILED_LEDGER_SCHEMA,
    }
    failed_journal = {
        "events": ["prepared"],
        "plan_digest": failed_plan_digest,
        "schema": current.FAILED_JOURNAL_SCHEMA,
        "stage": "prepared",
    }
    failed_backup = failed_root / "current-public"
    failed_backup.mkdir(parents=True, mode=0o700)
    failed_manifest: dict[str, object] = {}
    for text, projection in sorted(failed_public.items()):
        name = current.digest_bytes(text.encode("ascii"))
        source = host / text.lstrip("/")
        destination = failed_backup / name
        destination.write_bytes(source.read_bytes())
        destination.chmod(
            0o600 if int(projection["mode"]) == 0o644 else int(projection["mode"])
        )
        failed_manifest[text] = {**projection, "backup_name": name}
    failed_hashes = {
        "FAILED_PLAN_SHA256": _write_json(failed_root / "PLAN.json", failed_plan),
        "FAILED_LEDGER_SHA256": _write_json(failed_root / "LEDGER.json", failed_ledger),
        "FAILED_JOURNAL_SHA256": _write_json(failed_root / "JOURNAL.json", failed_journal),
        "FAILED_PUBLIC_MANIFEST_SHA256": _write_json(
            failed_backup / "PUBLIC.json", failed_manifest
        ),
    }

    terminal_incident = "3" * 64
    terminal_plan_digest = "4" * 64
    terminal_strategy_digest = "5" * 64
    terminal_controller_sha256 = "6" * 64
    terminal_target_digest = "7" * 64
    terminal_root = activation_root / "synthetic-terminal" / terminal_incident
    terminal_plan = {
        "action": "upgrade",
        "current_target": {"release_digest": selected.name},
        "incident": {"incident_digest": terminal_incident},
        "plan_digest": terminal_plan_digest,
        "schema": current.TERMINAL_PLAN_SCHEMA,
        "single_bounded_action": True,
        "strategy": {
            "controller_sha256": terminal_controller_sha256,
            "strategy_digest": terminal_strategy_digest,
        },
        "target": {"release_digest": terminal_target_digest},
    }
    terminal_ledger = {
        "action": "upgrade",
        "attempts": 1,
        "consumed": True,
        "incident_digest": terminal_incident,
        "plan_digest": terminal_plan_digest,
        "schema": current.TERMINAL_LEDGER_SCHEMA,
    }
    terminal_journal = {
        "action": "upgrade",
        "attempts": 1,
        "events": [
            "prepared",
            "current_public_backed_up",
            "current_state_backed_up",
            "attempt_owned",
            "services_stopped",
            "release_installed",
            "public_applied",
            "target_started",
            "protocol_acceptance_called",
            "convergence_owned",
            "predecessor_restored",
        ],
        "plan_digest": terminal_plan_digest,
        "schema": current.TERMINAL_JOURNAL_SCHEMA,
        "stage": "predecessor_restored",
    }
    terminal_public_manifest = {"synthetic": "terminal-public-backup"}
    terminal_state_manifest = {"synthetic": "terminal-state-backup"}
    terminal_state_sha = _write_json(
        terminal_root / "current-state/STATE.json", terminal_state_manifest
    )
    terminal_binding = {
        "plan_digest": terminal_plan_digest,
        "schema": current.TERMINAL_STATE_BINDING_SCHEMA,
        "state_descriptor_sha256": terminal_state_sha,
    }
    terminal_receipt = {
        "acceptance_projection_sha256": None,
        "action": "upgrade",
        "action_failure_code": "protocol_acceptance_failed",
        "channel_called": False,
        "convergence_failure_code": None,
        "incident_digest": terminal_incident,
        "model_called": False,
        "other_program_mutated": False,
        "plan_digest": terminal_plan_digest,
        "predecessor_release_digest": selected.name,
        "private_content_parsed": False,
        "schema": current.TERMINAL_RECEIPT_SCHEMA,
        "state_bytes_preserved": True,
        "status": "action_failed_predecessor_restored",
        "target_release_digest": terminal_target_digest,
    }
    terminal_hashes = {
        "TERMINAL_PLAN_SHA256": _write_json(terminal_root / "PLAN.json", terminal_plan),
        "TERMINAL_LEDGER_SHA256": _write_json(
            terminal_root / "LEDGER.json", terminal_ledger
        ),
        "TERMINAL_JOURNAL_SHA256": _write_json(
            terminal_root / "JOURNAL.json", terminal_journal
        ),
        "TERMINAL_RECEIPT_SHA256": _write_json(
            terminal_root / "RECEIPT.json", terminal_receipt
        ),
        "TERMINAL_STATE_BINDING_SHA256": _write_json(
            terminal_root / "STATE_BINDING.json", terminal_binding
        ),
        "TERMINAL_PUBLIC_MANIFEST_SHA256": _write_json(
            terminal_root / "current-public/PUBLIC.json", terminal_public_manifest
        ),
        "TERMINAL_STATE_MANIFEST_SHA256": terminal_state_sha,
    }

    v2_terminal_incident = "8" * 64
    v2_terminal_plan_digest = "9" * 64
    v2_terminal_strategy_digest = "a" * 64
    v2_terminal_controller_sha256 = "b" * 64
    v2_terminal_target_digest = "c" * 64
    v2_terminal_root = activation_root / "synthetic-v2-terminal" / v2_terminal_incident
    v2_terminal_plan = {
        "action": "upgrade",
        "current_target": {"release_digest": selected.name},
        "incident": {"incident_digest": v2_terminal_incident},
        "plan_digest": v2_terminal_plan_digest,
        "schema": "myuna.p08-current-selected-protocol-acceptance-repair-plan.v2",
        "single_bounded_action": True,
        "strategy": {
            "controller_sha256": v2_terminal_controller_sha256,
            "strategy_digest": v2_terminal_strategy_digest,
        },
        "target": {"release_digest": v2_terminal_target_digest},
    }
    v2_terminal_ledger = {
        "action": "upgrade",
        "attempts": 1,
        "consumed": True,
        "incident_digest": v2_terminal_incident,
        "plan_digest": v2_terminal_plan_digest,
        "schema": "myuna.p08-current-selected-protocol-acceptance-repair-ledger.v2",
    }
    v2_terminal_journal = {
        "action": "upgrade",
        "attempts": 1,
        "events": list(terminal_journal["events"]),
        "plan_digest": v2_terminal_plan_digest,
        "schema": "myuna.p08-current-selected-protocol-acceptance-repair-journal.v2",
        "stage": "predecessor_restored",
    }
    v2_terminal_public_manifest = {"synthetic": "v2-terminal-public-backup"}
    v2_terminal_state_manifest = {"synthetic": "v2-terminal-state-backup"}
    v2_terminal_state_sha = _write_json(
        v2_terminal_root / "current-state/STATE.json", v2_terminal_state_manifest
    )
    v2_terminal_binding = {
        "plan_digest": v2_terminal_plan_digest,
        "schema": "myuna.p08-current-selected-protocol-acceptance-repair-state-binding.v2",
        "state_descriptor_sha256": v2_terminal_state_sha,
    }
    v2_terminal_receipt = {
        "acceptance_projection_sha256": None,
        "action": "upgrade",
        "action_failure_code": "protocol_acceptance_failed",
        "channel_called": False,
        "convergence_failure_code": None,
        "incident_digest": v2_terminal_incident,
        "model_called": False,
        "other_program_mutated": False,
        "plan_digest": v2_terminal_plan_digest,
        "predecessor_release_digest": selected.name,
        "private_content_parsed": False,
        "schema": "myuna.p08-current-selected-protocol-acceptance-repair-receipt.v2",
        "state_bytes_preserved": True,
        "status": "action_failed_predecessor_restored",
        "target_release_digest": v2_terminal_target_digest,
    }
    v2_terminal_hashes = {
        "V2_TERMINAL_PLAN_SHA256": _write_json(
            v2_terminal_root / "PLAN.json", v2_terminal_plan
        ),
        "V2_TERMINAL_LEDGER_SHA256": _write_json(
            v2_terminal_root / "LEDGER.json", v2_terminal_ledger
        ),
        "V2_TERMINAL_JOURNAL_SHA256": _write_json(
            v2_terminal_root / "JOURNAL.json", v2_terminal_journal
        ),
        "V2_TERMINAL_RECEIPT_SHA256": _write_json(
            v2_terminal_root / "RECEIPT.json", v2_terminal_receipt
        ),
        "V2_TERMINAL_STATE_BINDING_SHA256": _write_json(
            v2_terminal_root / "STATE_BINDING.json", v2_terminal_binding
        ),
        "V2_TERMINAL_PUBLIC_MANIFEST_SHA256": _write_json(
            v2_terminal_root / "current-public/PUBLIC.json",
            v2_terminal_public_manifest,
        ),
        "V2_TERMINAL_STATE_MANIFEST_SHA256": v2_terminal_state_sha,
    }

    v4_terminal_incident = "d" * 64
    v4_terminal_plan_digest = "e" * 64
    v4_terminal_strategy_digest = "f" * 64
    v4_terminal_controller_sha256 = "1" * 64
    v4_terminal_target_digest = "2" * 64
    v4_terminal_root = activation_root / "synthetic-v4-terminal" / v4_terminal_incident
    v4_terminal_plan = {
        "action": "upgrade",
        "current_target": {"release_digest": selected.name},
        "incident": {"incident_digest": v4_terminal_incident},
        "plan_digest": v4_terminal_plan_digest,
        "schema": "myuna.p08-current-selected-protocol-acceptance-repair-plan.v4",
        "single_bounded_action": True,
        "strategy": {
            "controller_sha256": v4_terminal_controller_sha256,
            "strategy_digest": v4_terminal_strategy_digest,
        },
        "target": {"release_digest": v4_terminal_target_digest},
    }
    v4_terminal_ledger = {
        "action": "upgrade",
        "attempts": 1,
        "consumed": True,
        "incident_digest": v4_terminal_incident,
        "plan_digest": v4_terminal_plan_digest,
        "schema": "myuna.p08-current-selected-protocol-acceptance-repair-ledger.v4",
    }
    v4_terminal_journal = {
        "action": "upgrade",
        "attempts": 1,
        "events": list(terminal_journal["events"]),
        "plan_digest": v4_terminal_plan_digest,
        "schema": "myuna.p08-current-selected-protocol-acceptance-repair-journal.v4",
        "stage": "predecessor_restored",
    }
    v4_terminal_public_manifest = {"synthetic": "v4-terminal-public-backup"}
    v4_terminal_state_manifest = {"synthetic": "v4-terminal-state-backup"}
    v4_terminal_state_sha = _write_json(
        v4_terminal_root / "current-state/STATE.json", v4_terminal_state_manifest
    )
    v4_terminal_binding = {
        "plan_digest": v4_terminal_plan_digest,
        "schema": "myuna.p08-current-selected-protocol-acceptance-repair-state-binding.v4",
        "state_descriptor_sha256": v4_terminal_state_sha,
    }
    v4_terminal_receipt = {
        "acceptance_projection_sha256": None,
        "action": "upgrade",
        "action_failure_code": "protocol_acceptance_failed",
        "channel_called": False,
        "convergence_failure_code": None,
        "incident_digest": v4_terminal_incident,
        "model_called": False,
        "other_program_mutated": False,
        "plan_digest": v4_terminal_plan_digest,
        "predecessor_release_digest": selected.name,
        "private_content_parsed": False,
        "schema": "myuna.p08-current-selected-protocol-acceptance-repair-receipt.v4",
        "state_bytes_preserved": True,
        "status": "action_failed_predecessor_restored",
        "target_release_digest": v4_terminal_target_digest,
    }
    v4_terminal_hashes = {
        "V4_TERMINAL_PLAN_SHA256": _write_json(
            v4_terminal_root / "PLAN.json", v4_terminal_plan
        ),
        "V4_TERMINAL_LEDGER_SHA256": _write_json(
            v4_terminal_root / "LEDGER.json", v4_terminal_ledger
        ),
        "V4_TERMINAL_JOURNAL_SHA256": _write_json(
            v4_terminal_root / "JOURNAL.json", v4_terminal_journal
        ),
        "V4_TERMINAL_RECEIPT_SHA256": _write_json(
            v4_terminal_root / "RECEIPT.json", v4_terminal_receipt
        ),
        "V4_TERMINAL_STATE_BINDING_SHA256": _write_json(
            v4_terminal_root / "STATE_BINDING.json", v4_terminal_binding
        ),
        "V4_TERMINAL_PUBLIC_MANIFEST_SHA256": _write_json(
            v4_terminal_root / "current-public/PUBLIC.json",
            v4_terminal_public_manifest,
        ),
        "V4_TERMINAL_STATE_MANIFEST_SHA256": v4_terminal_state_sha,
    }

    v5_terminal_incident = "4" * 64
    v5_terminal_plan_digest = "5" * 64
    v5_terminal_strategy_digest = "6" * 64
    v5_terminal_controller_sha256 = "7" * 64
    v5_terminal_target_digest = "8" * 64
    v5_terminal_root = activation_root / "synthetic-v5-terminal" / v5_terminal_incident
    v5_terminal_plan = {
        "action": "upgrade",
        "current_target": {"release_digest": selected.name},
        "incident": {"incident_digest": v5_terminal_incident},
        "plan_digest": v5_terminal_plan_digest,
        "schema": "myuna.p08-current-selected-status-runtime-repair-plan.v5",
        "single_bounded_action": True,
        "strategy": {
            "controller_sha256": v5_terminal_controller_sha256,
            "strategy_digest": v5_terminal_strategy_digest,
        },
        "target": {"release_digest": v5_terminal_target_digest},
    }
    v5_terminal_ledger = {
        "action": "upgrade",
        "attempts": 1,
        "consumed": True,
        "incident_digest": v5_terminal_incident,
        "plan_digest": v5_terminal_plan_digest,
        "schema": "myuna.p08-current-selected-status-runtime-repair-ledger.v5",
    }
    v5_terminal_journal = {
        "action": "upgrade",
        "attempts": 1,
        "events": list(terminal_journal["events"]),
        "plan_digest": v5_terminal_plan_digest,
        "schema": "myuna.p08-current-selected-status-runtime-repair-journal.v5",
        "stage": "predecessor_restored",
    }
    v5_terminal_public_manifest = {"synthetic": "v5-terminal-public-backup"}
    v5_terminal_state_manifest = {"synthetic": "v5-terminal-state-backup"}
    v5_terminal_state_sha = _write_json(
        v5_terminal_root / "current-state/STATE.json", v5_terminal_state_manifest
    )
    v5_terminal_binding = {
        "plan_digest": v5_terminal_plan_digest,
        "schema": "myuna.p08-current-selected-status-runtime-repair-state-binding.v5",
        "state_descriptor_sha256": v5_terminal_state_sha,
    }
    v5_terminal_receipt = {
        "acceptance_projection_sha256": None,
        "action": "upgrade",
        "action_failure_code": "protocol_acceptance_failed",
        "channel_called": False,
        "convergence_failure_code": None,
        "incident_digest": v5_terminal_incident,
        "model_called": False,
        "other_program_mutated": False,
        "plan_digest": v5_terminal_plan_digest,
        "predecessor_release_digest": selected.name,
        "private_content_parsed": False,
        "schema": "myuna.p08-current-selected-status-runtime-repair-receipt.v5",
        "state_bytes_preserved": True,
        "status": "action_failed_predecessor_restored",
        "target_release_digest": v5_terminal_target_digest,
    }
    v5_terminal_hashes = {
        "V5_TERMINAL_PLAN_SHA256": _write_json(
            v5_terminal_root / "PLAN.json", v5_terminal_plan
        ),
        "V5_TERMINAL_LEDGER_SHA256": _write_json(
            v5_terminal_root / "LEDGER.json", v5_terminal_ledger
        ),
        "V5_TERMINAL_JOURNAL_SHA256": _write_json(
            v5_terminal_root / "JOURNAL.json", v5_terminal_journal
        ),
        "V5_TERMINAL_RECEIPT_SHA256": _write_json(
            v5_terminal_root / "RECEIPT.json", v5_terminal_receipt
        ),
        "V5_TERMINAL_STATE_BINDING_SHA256": _write_json(
            v5_terminal_root / "STATE_BINDING.json", v5_terminal_binding
        ),
        "V5_TERMINAL_PUBLIC_MANIFEST_SHA256": _write_json(
            v5_terminal_root / "current-public/PUBLIC.json",
            v5_terminal_public_manifest,
        ),
        "V5_TERMINAL_STATE_MANIFEST_SHA256": v5_terminal_state_sha,
    }

    v7_residue_root = activation_root / "synthetic-v7-prepare-residue"
    v7_residue_root.mkdir(mode=0o700)
    v7_plan_input = v7_residue_root / "PLAN.INPUT.json"
    v7_plan_input.write_bytes(b"")
    v7_plan_input.chmod(0o600)
    v7_stderr = v7_residue_root / "PREPARE.STDERR.bin"
    v7_stderr.write_bytes(b"x" * current.V7_PREPARE_STDERR_SIZE)
    v7_stderr.chmod(0o600)
    v7_root_metadata = v7_residue_root.lstat()

    v8_evidence_root = activation_root / "synthetic-v8-closed-sequence"
    v8_prepare_identity = "a" * 64
    v8_prepare_capture_identity = "b" * 64
    v8_prepare_plan_digest = "c" * 64
    v8_formal_sequence_identity = "d" * 64
    v8_formal_call_nonce = "e" * 64
    v8_formal_started_ns = 100
    v8_formal_ended_ns = 30_000_000_100
    v8_prepare = v8_evidence_root / "prepare-captures" / v8_prepare_identity
    v8_formal = (
        v8_evidence_root / "formal-sequences" / v8_formal_sequence_identity
    )
    v8_prepare_files = {
        "CAPTURE.json": _write_json(
            v8_prepare / "CAPTURE.json",
            {
                "prepare_identity": v8_prepare_identity,
                "raw_output_retained": False,
                "schema": "myuna.p08-prepare-capture.v1",
                "status": "ready",
                "timed_out": False,
            },
        ),
        "CLAIM.json": _write_json(
            v8_prepare / "CLAIM.json", {"schema": "synthetic.v8-claim.v1"}
        ),
        "PLAN.INPUT.json": _write_json(
            v8_prepare / "PLAN.INPUT.json", {"schema": "synthetic.v8-plan.v1"}
        ),
        "PREPARE.json": _write_json(
            v8_prepare / "PREPARE.json",
            {"schema": "synthetic.v8-prepare.v1"},
        ),
        "RESULT.json": _write_json(
            v8_prepare / "RESULT.json",
            {
                "capture_identity_sha256": v8_prepare_capture_identity,
                "persistent_product_mutation": False,
                "plan_digest": v8_prepare_plan_digest,
                "prepare_identity": v8_prepare_identity,
                "schema": "myuna.p08-prepare-capture-result.v1",
                "status": "ready",
            },
        ),
    }
    v8_formal_files = {
        "CALL-1.CAPTURE.json": _write_json(
            v8_formal / "CALL-1.CAPTURE.json",
            {
                "call_index": 1,
                "call_nonce": v8_formal_call_nonce,
                "ended_ns": v8_formal_ended_ns,
                "raw_output_retained": False,
                "schema": "myuna.p08-formal-preflight-capture.v2",
                "sequence_identity": v8_formal_sequence_identity,
                "signal": 9,
                "started_ns": v8_formal_started_ns,
                "status": "indeterminate",
                "stderr_sha256": current.EMPTY_SHA256,
                "stderr_size": 0,
                "stdout_sha256": current.EMPTY_SHA256,
                "stdout_size": 0,
                "timed_out": True,
            },
        ),
        "CALL-1.CLAIM.json": _write_json(
            v8_formal / "CALL-1.CLAIM.json",
            {"schema": "synthetic.v8-formal-claim.v1"},
        ),
        "SEQUENCE.json": _write_json(
            v8_formal / "SEQUENCE.json",
            {"schema": "synthetic.v8-sequence.v1"},
        ),
    }
    for directory in (
        v8_evidence_root,
        v8_prepare.parent,
        v8_prepare,
        v8_formal.parent,
        v8_formal,
    ):
        directory.chmod(0o700)

    v9_evidence_root = activation_root / "synthetic-v9-closed-sequence"
    v9_prepare_identity = "1" * 64
    v9_prepare_invocation_identity = "2" * 64
    v9_prepare_capture_identity = "3" * 64
    v9_prepare_result_identity = "4" * 64
    v9_plan_digest = "5" * 64
    v9_formal_sequence_identity = "6" * 64
    v9_formal_invocation_identity = "7" * 64
    v9_formal_result_identity = "8" * 64
    v9_formal_stdout_sha256 = "9" * 64
    v9_prepare_phase_trace_sha256 = "a" * 64
    v9_formal_phase_trace_sha256 = "b" * 64
    v9_formal_call_nonces = ("c" * 64, "d" * 64)
    v9_prepare = v9_evidence_root / "prepare-captures" / v9_prepare_identity
    v9_formal = (
        v9_evidence_root / "formal-sequences" / v9_formal_sequence_identity
    )
    v9_plan = {
        "plan_digest": v9_plan_digest,
        "schema": "myuna.p08-current-selected-formal-timeout-repair-plan.v9",
    }
    v9_plan_sha256 = _write_json(v9_prepare / "PLAN.INPUT.json", v9_plan)
    v9_prepare_files = {
        "CAPTURE.json": _write_json(
            v9_prepare / "CAPTURE.json",
            {
                "invocation_identity_sha256": v9_prepare_invocation_identity,
                "parsed_result_identity_sha256": v9_prepare_result_identity,
                "phase_liveness_event_count": 5,
                "phase_liveness_last_phase": formal_launcher.PHASE_CANONICAL_SERIALIZATION,
                "phase_liveness_trace_sha256": v9_prepare_phase_trace_sha256,
                "prepare_identity": v9_prepare_identity,
                "raw_output_retained": False,
                "schema": "myuna.p08-prepare-capture.v2",
                "status": "ready",
                "stderr_size": 0,
                "stdout_sha256": v9_plan_sha256,
                "stdout_size": 28_958,
                "timed_out": False,
            },
        ),
        "CLAIM.json": _write_json(
            v9_prepare / "CLAIM.json", {"schema": "synthetic.v9-claim.v1"}
        ),
        "PLAN.INPUT.json": v9_plan_sha256,
        "PREPARE.json": _write_json(
            v9_prepare / "PREPARE.json", {"schema": "synthetic.v9-prepare.v1"}
        ),
        "RESULT.json": _write_json(
            v9_prepare / "RESULT.json",
            {
                "capture_identity_sha256": v9_prepare_capture_identity,
                "persistent_product_mutation": False,
                "plan_digest": v9_plan_digest,
                "plan_sha256": v9_plan_sha256,
                "prepare_identity": v9_prepare_identity,
                "schema": "myuna.p08-prepare-capture-result.v2",
                "status": "ready",
            },
        ),
    }
    v9_formal_files: dict[str, str] = {}
    for call_index in (1, 2):
        v9_formal_files[f"CALL-{call_index}.CAPTURE.json"] = _write_json(
            v9_formal / f"CALL-{call_index}.CAPTURE.json",
            {
                "call_index": call_index,
                "call_nonce": v9_formal_call_nonces[call_index - 1],
                "canonical_result": True,
                "drain_completed": True,
                "exit_code": 0,
                "invocation_identity_sha256": v9_formal_invocation_identity,
                "parsed_result_identity_sha256": v9_formal_result_identity,
                "phase_liveness_event_count": 6,
                "phase_liveness_last_phase": formal_launcher.PHASE_CANONICAL_SERIALIZATION,
                "phase_liveness_trace_sha256": v9_formal_phase_trace_sha256,
                "process_created": True,
                "raw_output_retained": False,
                "schema": "myuna.p08-formal-preflight-capture.v3",
                "sequence_identity": v9_formal_sequence_identity,
                "status": "ready",
                "stderr_size": 0,
                "stdout_sha256": v9_formal_stdout_sha256,
                "stdout_size": 29_253,
                "termination_escalated": False,
                "timed_out": False,
            },
        )
        v9_formal_files[f"CALL-{call_index}.CLAIM.json"] = _write_json(
            v9_formal / f"CALL-{call_index}.CLAIM.json",
            {"schema": f"synthetic.v9-formal-claim-{call_index}.v1"},
        )
    v9_formal_files["RESULT.json"] = _write_json(
        v9_formal / "RESULT.json",
        {
            "calls": 2,
            "invocation_identity_sha256": v9_formal_invocation_identity,
            "persistent_product_mutation": False,
            "result_identity_sha256": v9_formal_result_identity,
            "schema": "myuna.p08-formal-preflight-sequence-result.v3",
            "sequence_identity": v9_formal_sequence_identity,
            "status": "ready",
            "stdout_sha256": v9_formal_stdout_sha256,
        },
    )
    v9_formal_files["SEQUENCE.json"] = _write_json(
        v9_formal / "SEQUENCE.json", {"schema": "synthetic.v9-sequence.v1"}
    )
    for directory in (
        v9_evidence_root,
        v9_prepare.parent,
        v9_prepare,
        v9_formal.parent,
        v9_formal,
    ):
        directory.chmod(0o700)

    v10_incident_digest = "e" * 64
    v10_plan_digest = "f" * 64
    v10_strategy_digest = "0" * 64
    v10_target_digest = "1" * 64
    v10_target_manifest_sha256 = "2" * 64
    v10_root = activation_root / "synthetic-v10-terminal"
    v10_evidence = v10_root / "incidents" / v10_incident_digest
    v10_state_manifest = {"synthetic": "v10-forward-state-preserved"}
    v10_state_manifest_sha256 = _write_json(
        v10_evidence / "current-state/STATE.json", v10_state_manifest
    )
    v10_plan = {
        "action": "upgrade",
        "incident": {"incident_digest": v10_incident_digest},
        "plan_digest": v10_plan_digest,
        "schema": "myuna.p08-current-selected-drift-launcher-repair-plan.v10",
        "strategy": {"strategy_digest": v10_strategy_digest},
        "target": {
            "release_digest": v10_target_digest,
            "release_manifest_sha256": v10_target_manifest_sha256,
        },
    }
    v10_ledger = {
        "attempts": 1,
        "consumed": True,
        "schema": "myuna.p08-current-selected-drift-launcher-repair-ledger.v10",
    }
    v10_journal = {
        "schema": "myuna.p08-current-selected-drift-launcher-repair-journal.v10",
        "stage": "predecessor_restored",
    }
    v10_receipt = {
        "action_failure_code": "protocol_acceptance_failed",
        "schema": "myuna.p08-current-selected-drift-launcher-repair-receipt.v10",
        "state_bytes_preserved": True,
        "status": "action_failed_predecessor_restored",
    }
    v10_binding = {
        "plan_digest": v10_plan_digest,
        "schema": "myuna.p08-current-selected-drift-launcher-repair-state-binding.v10",
        "state_descriptor_sha256": v10_state_manifest_sha256,
    }
    v10_public = {"synthetic": "v10-public-backup"}
    v10_hashes = {
        "V10_PLAN_SHA256": _write_json(v10_evidence / "PLAN.json", v10_plan),
        "V10_LEDGER_SHA256": _write_json(v10_evidence / "LEDGER.json", v10_ledger),
        "V10_JOURNAL_SHA256": _write_json(v10_evidence / "JOURNAL.json", v10_journal),
        "V10_RECEIPT_SHA256": _write_json(v10_evidence / "RECEIPT.json", v10_receipt),
        "V10_STATE_BINDING_SHA256": _write_json(
            v10_evidence / "STATE_BINDING.json", v10_binding
        ),
        "V10_PUBLIC_MANIFEST_SHA256": _write_json(
            v10_evidence / "current-public/PUBLIC.json", v10_public
        ),
        "V10_STATE_MANIFEST_SHA256": v10_state_manifest_sha256,
    }

    v11_evidence_root = activation_root / "synthetic-v11-closed-sequence"
    v11_prepare_identity = "3" * 64
    v11_prepare_capture_identity = "4" * 64
    v11_plan_digest = "5" * 64
    v11_formal_sequence_identity = "6" * 64
    v11_formal_call_nonce = "7" * 64
    v11_formal_invocation_identity = "8" * 64
    v11_formal_stdout_sha256 = "9" * 64
    v11_formal_phase_trace_sha256 = "a" * 64
    v11_prepare = (
        v11_evidence_root / "prepare-captures" / v11_prepare_identity
    )
    v11_formal = (
        v11_evidence_root
        / "formal-sequences"
        / v11_formal_sequence_identity
    )
    v11_plan = {
        "plan_digest": v11_plan_digest,
        "schema": "myuna.p08-current-selected-forward-continuity-repair-plan.v11",
    }
    v11_plan_sha256 = _write_json(v11_prepare / "PLAN.INPUT.json", v11_plan)
    v11_prepare_files = {
        "CAPTURE.json": _write_json(
            v11_prepare / "CAPTURE.json",
            {
                "prepare_identity": v11_prepare_identity,
                "raw_output_retained": False,
                "schema": "myuna.p08-prepare-capture.v2",
                "status": "ready",
                "stderr_size": 0,
                "timed_out": False,
            },
        ),
        "CLAIM.json": _write_json(
            v11_prepare / "CLAIM.json", {"schema": "synthetic.v11-claim.v1"}
        ),
        "PLAN.INPUT.json": v11_plan_sha256,
        "PREPARE.json": _write_json(
            v11_prepare / "PREPARE.json",
            {"schema": "synthetic.v11-prepare.v1"},
        ),
        "RESULT.json": _write_json(
            v11_prepare / "RESULT.json",
            {
                "capture_identity_sha256": v11_prepare_capture_identity,
                "persistent_product_mutation": False,
                "plan_digest": v11_plan_digest,
                "plan_sha256": v11_plan_sha256,
                "prepare_identity": v11_prepare_identity,
                "schema": "myuna.p08-prepare-capture-result.v2",
                "status": "ready",
            },
        ),
    }
    v11_formal_files = {
        "CALL-1.CAPTURE.json": _write_json(
            v11_formal / "CALL-1.CAPTURE.json",
            {
                "call_index": 1,
                "call_nonce": v11_formal_call_nonce,
                "canonical_result": False,
                "drain_completed": True,
                "exit_code": 0,
                "invocation_identity_sha256": v11_formal_invocation_identity,
                "parsed_result_identity_sha256": None,
                "phase_liveness_error": None,
                "phase_liveness_event_count": 6,
                "phase_liveness_last_phase": formal_launcher.PHASE_CANONICAL_SERIALIZATION,
                "phase_liveness_trace_sha256": v11_formal_phase_trace_sha256,
                "process_created": True,
                "raw_output_retained": False,
                "schema": "myuna.p08-formal-preflight-capture.v3",
                "sequence_identity": v11_formal_sequence_identity,
                "status": "indeterminate",
                "stderr_sha256": current.EMPTY_SHA256,
                "stderr_size": 0,
                "stdout_sha256": v11_formal_stdout_sha256,
                "stdout_size": 39_400,
                "termination_escalated": False,
                "timed_out": False,
            },
        ),
        "CALL-1.CLAIM.json": _write_json(
            v11_formal / "CALL-1.CLAIM.json",
            {"schema": "synthetic.v11-formal-claim.v1"},
        ),
        "SEQUENCE.json": _write_json(
            v11_formal / "SEQUENCE.json",
            {"schema": "synthetic.v11-sequence.v1"},
        ),
    }
    for directory in (
        v11_evidence_root,
        v11_prepare.parent,
        v11_prepare,
        v11_formal.parent,
        v11_formal,
    ):
        directory.chmod(0o700)

    v12_evidence_root = activation_root / "synthetic-v12-rejected-prepare"
    v12_prepare_identity = "b" * 64
    v12_prepare_invocation_identity = "c" * 64
    v12_prepare_result_identity = "d" * 64
    v12_prepare = (
        v12_evidence_root / "prepare-captures" / v12_prepare_identity
    )
    v12_prepare_files = {
        "CAPTURE.json": _write_json(
            v12_prepare / "CAPTURE.json",
            {
                "canonical_result": True,
                "drain_completed": True,
                "exit_code": 2,
                "invocation_identity_sha256": v12_prepare_invocation_identity,
                "parsed_result_identity_sha256": v12_prepare_result_identity,
                "prepare_identity": v12_prepare_identity,
                "process_created": True,
                "raw_output_retained": False,
                "result_detail": "typed_rejection:v11_closed_sequence_rejected",
                "schema": "myuna.p08-prepare-capture.v2",
                "status": "rejected",
                "stderr_sha256": current.EMPTY_SHA256,
                "stderr_size": 0,
                "target_release_digest": current.V12_TARGET_RELEASE_DIGEST,
                "termination_escalated": False,
                "timed_out": False,
            },
        ),
        "CLAIM.json": _write_json(
            v12_prepare / "CLAIM.json", {"schema": "synthetic.v12-claim.v1"}
        ),
        "PREPARE.json": _write_json(
            v12_prepare / "PREPARE.json",
            {"schema": "synthetic.v12-prepare.v1"},
        ),
    }
    for directory in (
        v12_evidence_root,
        v12_prepare.parent,
        v12_prepare,
    ):
        directory.chmod(0o700)

    selected_rows = post._release_metadata_inventory(selected)
    values = {
        **origin_hashes,
        **accepted_hashes,
        **failed_hashes,
        **terminal_hashes,
        **v2_terminal_hashes,
        **v4_terminal_hashes,
        **v5_terminal_hashes,
        **v10_hashes,
        "ACCEPTED_EVIDENCE_ROOT": Path("/var/lib/myuna-activation-backups/synthetic-accepted")
        / accepted_incident,
        "ACCEPTED_INCIDENT_DIGEST": accepted_incident,
        "FAILED_CONTROLLER_SHA256": failed_controller_sha256,
        "FAILED_EVIDENCE_ROOT": Path(
            "/var/lib/myuna-activation-backups/synthetic-failed"
        )
        / failed_incident,
        "FAILED_INCIDENT_DIGEST": failed_incident,
        "FAILED_PLAN_DIGEST": failed_plan_digest,
        "FAILED_STRATEGY_DIGEST": failed_strategy_digest,
        "FAILED_TARGET_RELEASE_DIGEST": failed_target_digest,
        "ORIGIN_EVIDENCE_ROOT": Path("/var/lib/myuna-activation-backups/synthetic-current-selected-origin"),
        "ORIGIN_PLAN_DIGEST": origin["plan_digest"],
        "PREDECESSOR_CLIENT_SHA256": upgrade.digest_file(selected / upgrade.CLIENT_PATH),
        "PREDECESSOR_CORE_COMMIT": upgrade.TARGET_CORE_COMMIT,
        "PREDECESSOR_DEPLOY_COMMIT": selected_deploy,
        "PREDECESSOR_INSTALLED_INVENTORY_SHA256": current.digest_bytes(
            current.canonical(
                post._installed_inventory_from_source(selected_rows, live=False)
            )
        ),
        "PREDECESSOR_MANIFEST_SHA256": upgrade.digest_file(selected / "manifest.json"),
        "PREDECESSOR_PLAN_DIGEST": accepted_plan_digest,
        "PREDECESSOR_RELEASE_DIGEST": selected.name,
        "PREDECESSOR_SELECTOR_ENV_SHA256": current.digest_bytes(selector_env),
        "PREDECESSOR_SELECTOR_SHA256": current.digest_bytes(selector),
        "PREDECESSOR_SERVICE_UNIT_SHA256": upgrade.digest_file(
            selected / upgrade.SERVICE_UNIT_PATH
        ),
        "PREDECESSOR_SOCKET_UNIT_SHA256": upgrade.digest_file(
            selected / upgrade.SOCKET_UNIT_PATH
        ),
        "TERMINAL_CONTROLLER_SHA256": terminal_controller_sha256,
        "TERMINAL_EVIDENCE_ROOT": Path(
            "/var/lib/myuna-activation-backups/synthetic-terminal"
        )
        / terminal_incident,
        "TERMINAL_INCIDENT_DIGEST": terminal_incident,
        "TERMINAL_PLAN_DIGEST": terminal_plan_digest,
        "TERMINAL_STRATEGY_DIGEST": terminal_strategy_digest,
        "TERMINAL_TARGET_RELEASE_DIGEST": terminal_target_digest,
        "V2_TERMINAL_CONTROLLER_SHA256": v2_terminal_controller_sha256,
        "V2_TERMINAL_EVIDENCE_ROOT": Path(
            "/var/lib/myuna-activation-backups/synthetic-v2-terminal"
        )
        / v2_terminal_incident,
        "V2_TERMINAL_INCIDENT_DIGEST": v2_terminal_incident,
        "V2_TERMINAL_PLAN_DIGEST": v2_terminal_plan_digest,
        "V2_TERMINAL_STRATEGY_DIGEST": v2_terminal_strategy_digest,
        "V2_TERMINAL_TARGET_RELEASE_DIGEST": v2_terminal_target_digest,
        "V4_TERMINAL_CONTROLLER_SHA256": v4_terminal_controller_sha256,
        "V4_TERMINAL_EVIDENCE_ROOT": Path(
            "/var/lib/myuna-activation-backups/synthetic-v4-terminal"
        )
        / v4_terminal_incident,
        "V4_TERMINAL_HANDOFF_SHA256": "3" * 64,
        "V4_TERMINAL_INCIDENT_DIGEST": v4_terminal_incident,
        "V4_TERMINAL_PLAN_DIGEST": v4_terminal_plan_digest,
        "V4_TERMINAL_STRATEGY_DIGEST": v4_terminal_strategy_digest,
        "V4_TERMINAL_TARGET_RELEASE_DIGEST": v4_terminal_target_digest,
        "V5_TERMINAL_CONTROLLER_SHA256": v5_terminal_controller_sha256,
        "V5_TERMINAL_EVIDENCE_ROOT": Path(
            "/var/lib/myuna-activation-backups/synthetic-v5-terminal"
        )
        / v5_terminal_incident,
        "V5_TERMINAL_HANDOFF_SHA256": "9" * 64,
        "V5_TERMINAL_INCIDENT_DIGEST": v5_terminal_incident,
        "V5_TERMINAL_PLAN_DIGEST": v5_terminal_plan_digest,
        "V5_TERMINAL_STRATEGY_DIGEST": v5_terminal_strategy_digest,
        "V5_TERMINAL_TARGET_RELEASE_DIGEST": v5_terminal_target_digest,
        "V7_EVIDENCE_ROOT": Path(
            "/var/lib/myuna-activation-backups/synthetic-v7-prepare-residue"
        ),
        "V7_RESIDUE_ROOT_GID": v7_root_metadata.st_gid,
        "V7_RESIDUE_ROOT_CTIME_EPOCH": int(v7_root_metadata.st_ctime),
        "V7_RESIDUE_ROOT_NLINK": v7_root_metadata.st_nlink,
        "V7_RESIDUE_ROOT_MTIME_EPOCH": int(v7_root_metadata.st_mtime),
        "V7_RESIDUE_ROOT_SIZE": v7_root_metadata.st_size,
        "V7_RESIDUE_ROOT_UID": v7_root_metadata.st_uid,
        "V8_EVIDENCE_ROOT": Path(
            "/var/lib/myuna-activation-backups/synthetic-v8-closed-sequence"
        ),
        "V8_FORMAL_CALL1_NONCE": v8_formal_call_nonce,
        "V8_FORMAL_ENDED_NS": v8_formal_ended_ns,
        "V8_FORMAL_FILES": v8_formal_files,
        "V8_FORMAL_SEQUENCE_IDENTITY": v8_formal_sequence_identity,
        "V8_FORMAL_STARTED_NS": v8_formal_started_ns,
        "V8_PREPARE_CAPTURE_IDENTITY": v8_prepare_capture_identity,
        "V8_PREPARE_FILES": v8_prepare_files,
        "V8_PREPARE_IDENTITY": v8_prepare_identity,
        "V8_PREPARE_PLAN_DIGEST": v8_prepare_plan_digest,
        "V9_EVIDENCE_ROOT": Path(
            "/var/lib/myuna-activation-backups/synthetic-v9-closed-sequence"
        ),
        "V9_FORMAL_CALL_NONCES": v9_formal_call_nonces,
        "V9_FORMAL_FILES": v9_formal_files,
        "V9_FORMAL_INVOCATION_IDENTITY": v9_formal_invocation_identity,
        "V9_FORMAL_PHASE_TRACE_SHA256": v9_formal_phase_trace_sha256,
        "V9_FORMAL_RESULT_IDENTITY": v9_formal_result_identity,
        "V9_FORMAL_SEQUENCE_IDENTITY": v9_formal_sequence_identity,
        "V9_FORMAL_STDOUT_SHA256": v9_formal_stdout_sha256,
        "V9_PLAN_DIGEST": v9_plan_digest,
        "V9_PLAN_SHA256": v9_plan_sha256,
        "V9_PREPARE_CAPTURE_IDENTITY": v9_prepare_capture_identity,
        "V9_PREPARE_FILES": v9_prepare_files,
        "V9_PREPARE_IDENTITY": v9_prepare_identity,
        "V9_PREPARE_INVOCATION_IDENTITY": v9_prepare_invocation_identity,
        "V9_PREPARE_PHASE_TRACE_SHA256": v9_prepare_phase_trace_sha256,
        "V9_PREPARE_RESULT_IDENTITY": v9_prepare_result_identity,
        "V10_EVIDENCE_ROOT": Path(
            "/var/lib/myuna-activation-backups/synthetic-v10-terminal"
        ),
        "V10_INCIDENT_DIGEST": v10_incident_digest,
        "V10_PLAN_DIGEST": v10_plan_digest,
        "V10_STRATEGY_DIGEST": v10_strategy_digest,
        "V10_TARGET_MANIFEST_SHA256": v10_target_manifest_sha256,
        "V10_TARGET_RELEASE_DIGEST": v10_target_digest,
        "V11_EVIDENCE_ROOT": Path(
            "/var/lib/myuna-activation-backups/synthetic-v11-closed-sequence"
        ),
        "V11_FORMAL_CALL_NONCE": v11_formal_call_nonce,
        "V11_FORMAL_FILES": v11_formal_files,
        "V11_FORMAL_INVOCATION_IDENTITY": v11_formal_invocation_identity,
        "V11_FORMAL_PHASE_TRACE_SHA256": v11_formal_phase_trace_sha256,
        "V11_FORMAL_SEQUENCE_IDENTITY": v11_formal_sequence_identity,
        "V11_FORMAL_STDOUT_SHA256": v11_formal_stdout_sha256,
        "V11_PLAN_DIGEST": v11_plan_digest,
        "V11_PLAN_SHA256": v11_plan_sha256,
        "V11_PREPARE_CAPTURE_IDENTITY": v11_prepare_capture_identity,
        "V11_PREPARE_FILES": v11_prepare_files,
        "V11_PREPARE_IDENTITY": v11_prepare_identity,
        "V12_EVIDENCE_ROOT": Path(
            "/var/lib/myuna-activation-backups/synthetic-v12-rejected-prepare"
        ),
        "V12_PREPARE_FILES": v12_prepare_files,
        "V12_PREPARE_IDENTITY": v12_prepare_identity,
        "V12_PREPARE_INVOCATION_IDENTITY": v12_prepare_invocation_identity,
        "V12_PREPARE_RESULT_IDENTITY": v12_prepare_result_identity,
    }
    with mock.patch.multiple(current, **values):
        candidate = _retag_candidate(root / "candidate")
        yield host, candidate, identity


@unittest.skipUnless(PREDECESSOR.is_dir(), "exact P08 compatibility predecessor required")
class CurrentSelectedUpgradeContractTests(unittest.TestCase):
    def test_controller_cli_arguments_typed_rejections_and_unexpected_are_canonical(self) -> None:
        cases = (
            (
                [],
                None,
                "typed_rejection",
                "controller_argument_rejected",
                False,
            ),
            (
                ["prepare", "--target-release", "/synthetic/target"],
                current.CurrentSelectedUpgradeRejected("synthetic_typed_rejection"),
                "typed_rejection",
                "synthetic_typed_rejection",
                False,
            ),
            (
                ["prepare", "--target-release", "/synthetic/target"],
                RuntimeError("private unexpected detail"),
                "unexpected_controller_failure",
                "unexpected_controller_failure",
                False,
            ),
            (
                ["execute", "--plan", "/synthetic/plan"],
                RuntimeError("private action detail"),
                "unexpected_controller_failure",
                "unexpected_controller_failure",
                True,
            ),
        )
        for argv, failure, category, code, action_effects in cases:
            with self.subTest(code=code):
                stdout = io.StringIO()
                stderr = io.StringIO()
                patch = (
                    mock.patch.object(
                        current,
                        "_load_json" if argv and argv[0] == "execute" else "prepare_plan",
                        side_effect=failure,
                    )
                    if failure is not None
                    else nullcontext()
                )
                with patch, redirect_stdout(stdout), redirect_stderr(stderr):
                    result = current.main(argv)
                self.assertEqual(result, 2)
                self.assertEqual(stderr.getvalue(), "")
                payload = json.loads(stdout.getvalue())
                self.assertEqual(payload["schema"], current.CLI_RESULT_SCHEMA)
                self.assertEqual(payload["category"], category)
                self.assertEqual(payload["code"], code)
                self.assertFalse(payload["retryable"])
                self.assertEqual(payload["persistent_mutation"], action_effects)
                self.assertEqual(payload["opaque_content_read"], action_effects)
                self.assertNotIn("private", stdout.getvalue())

    def test_verify_cli_is_drift_role_only_and_emits_exact_phase_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _fixture(Path(directory)) as (
            host,
            candidate,
            unused_identity,
        ):
            plan = current.prepare_plan(
                target_release=candidate,
                root=host,
                unit_state=UNIT_STATE,
            )
            plan_path = host / "synthetic-plan.json"
            _write_json(plan_path, plan)
            phases: list[str] = []
            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch.dict(
                os.environ,
                {
                    formal_launcher.PHASE_ROLE_ENV: formal_launcher.ROLE_DRIFT,
                },
                clear=False,
            ), mock.patch.object(
                formal_launcher, "emit_phase", side_effect=phases.append
            ), redirect_stdout(stdout), redirect_stderr(stderr):
                result = current.main(
                    [
                        "verify",
                        "--plan",
                        str(plan_path),
                        "--synthetic-root",
                        str(host),
                    ]
                )
            self.assertEqual(result, 0)
            self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(
                phases,
                list(formal_launcher.ROLE_PHASES[formal_launcher.ROLE_DRIFT]),
            )
            self.assertEqual(json.loads(stdout.getvalue()), plan)

    def test_v7_prepare_residue_is_metadata_only_bound_and_substitution_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _fixture(Path(directory)) as (
            host,
            unused_candidate,
            unused_identity,
        ):
            projection = current.validate_v7_prepare_residue(host)
            self.assertTrue(projection["metadata_verified"])
            self.assertFalse(projection["content_opened"])
            self.assertFalse(projection["restore_authority"])
            stderr_path = current._rooted(
                host, current.V7_EVIDENCE_ROOT / "PREPARE.STDERR.bin"
            )
            stderr_path.write_bytes(
                b"x" * (current.V7_PREPARE_STDERR_SIZE + 1)
            )
            with self.assertRaisesRegex(
                current.CurrentSelectedUpgradeRejected,
                "v7_prepare_residue_rejected",
            ):
                current.validate_v7_prepare_residue(host)

    def test_all_immutable_sequence_lineages_are_revalidated_after_prepare(self) -> None:
        variants = {
            "v7": (
                "v7_prepare_residue_rejected",
                lambda host: current._v7_prepare_residue_path(host)
                / "PREPARE.STDERR.bin",
            ),
            "v8": (
                "v8_closed_sequence_rejected",
                lambda host: current._v8_closed_sequence_path(host)
                / "formal-sequences"
                / current.V8_FORMAL_SEQUENCE_IDENTITY
                / "CALL-1.CAPTURE.json",
            ),
            "v9": (
                "v9_closed_sequence_rejected",
                lambda host: current._v9_closed_sequence_path(host)
                / "formal-sequences"
                / current.V9_FORMAL_SEQUENCE_IDENTITY
                / "RESULT.json",
            ),
            "v12": (
                "v12_rejected_prepare_rejected",
                lambda host: current._v12_rejected_prepare_path(host)
                / "prepare-captures"
                / current.V12_PREPARE_IDENTITY
                / "CAPTURE.json",
            ),
        }
        for selected, (code, path_for) in variants.items():
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as directory:
                with _fixture(Path(directory)) as (host, candidate, _):
                    plan = current.prepare_plan(
                        target_release=candidate,
                        root=host,
                        unit_state=UNIT_STATE,
                    )
                    path = path_for(host)
                    path.write_bytes(path.read_bytes() + b"x")
                    with self.assertRaisesRegex(
                        current.CurrentSelectedUpgradeRejected, code
                    ):
                        current.verify_plan(
                            plan, root=host, unit_state=UNIT_STATE
                        )

    def test_post_claim_lineage_drift_consumes_before_backup_or_unit_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _fixture(Path(directory)) as (
            host,
            candidate,
            unused_identity,
        ):
            plan = current.prepare_plan(
                target_release=candidate, root=host, unit_state=UNIT_STATE
            )
            original_claim = current._claim_evidence

            def claim_then_drift(root: Path, selected_plan: dict[str, object]) -> Path:
                evidence = original_claim(root, selected_plan)
                stderr_path = current._v7_prepare_residue_path(root) / "PREPARE.STDERR.bin"
                stderr_path.write_bytes(stderr_path.read_bytes() + b"x")
                return evidence

            with mock.patch.object(
                current, "_claim_evidence", side_effect=claim_then_drift
            ), mock.patch.object(
                upgrade, "_copy_public_backup"
            ) as public_backup, mock.patch.object(
                current, "_stage_state_backup"
            ) as state_backup, mock.patch.object(
                upgrade, "_stop"
            ) as stop:
                with self.assertRaisesRegex(
                    current.CurrentSelectedUpgradeRejected,
                    "v7_prepare_residue_rejected",
                ):
                    current.stage_plan(plan, root=host, unit_state=UNIT_STATE)
            public_backup.assert_not_called()
            state_backup.assert_not_called()
            stop.assert_not_called()
            evidence = current._evidence_path(host, plan)
            ledger = json.loads((evidence / "LEDGER.json").read_text("ascii"))
            journal = json.loads((evidence / "JOURNAL.json").read_text("ascii"))
            self.assertTrue(ledger["consumed"])
            self.assertEqual(ledger["attempts"], 1)
            self.assertEqual(journal["stage"], "prepared")
            self.assertFalse((evidence / "current-public").exists())
            self.assertFalse((evidence / "current-state").exists())

    def test_source_contract_binds_authoritative_terminal_state_and_new_namespace(self) -> None:
        self.assertEqual(
            current.AUTHORITATIVE_TERMINAL_STATE_MANIFEST_SHA256,
            "55d3a3f91a20848fd9f66603f3684b4068401d2fd419d61094ce58ef39188eeb",
        )
        self.assertEqual(
            current.TERMINAL_STATE_MANIFEST_SHA256,
            current.AUTHORITATIVE_TERMINAL_STATE_MANIFEST_SHA256,
        )
        self.assertNotEqual(
            current.TERMINAL_STATE_MANIFEST_SHA256,
            current.PRESTATE_REJECTION_EXPECTED_STATE_MANIFEST_SHA256,
        )
        rejection = current.prestate_rejection_contract()
        self.assertEqual(
            rejection["handoff_sha256"],
            "46c5102165f9c60b859baedf1c98911caa4b28da3ed8d4afa0f061137fb23c3e",
        )
        self.assertEqual(rejection["source_owned_prepare_calls"], 1)
        self.assertEqual(rejection["formal_preflight_calls"], 0)
        self.assertEqual(rejection["new_incident_namespaces"], 0)
        self.assertEqual(rejection["live_mutations"], 0)
        self.assertTrue(current.STRATEGY_SCHEMA.endswith(".v13"))
        self.assertTrue(current.PLAN_SCHEMA.endswith(".v13"))
        self.assertTrue(current.INCIDENT_SCHEMA.endswith(".v13"))
        self.assertEqual(
            current.NONZERO_STAGE_T0_HANDOFF_SHA256,
            "834965b619cb4f02993da9513866bde04ceb409b7d5d82f6ec0612fa51386515",
        )
        self.assertEqual(
            current.V2_TERMINAL_INCIDENT_DIGEST,
            "0831b1c7d0c64d03fab0c79727304f013a6541319d71e63135344b014b84c647",
        )
        self.assertEqual(
            current.V4_TERMINAL_INCIDENT_DIGEST,
            "00456f72a12bbd7b9751fe083a8d42caf77160cc2c700410d941dc984d9eddce",
        )
        self.assertEqual(
            current.V5_TERMINAL_INCIDENT_DIGEST,
            "e4ac524463fa42cba9773170f1b838e7cee005e19b7833eb9fb0214dc971036b",
        )
        self.assertEqual(
            current.V8_T2_TERMINAL_HANDOFF_SHA256,
            "370fbcab3de185aad1ab61ba71a75c02b2afdb3b1e9c314ba8d9af30341a2c89",
        )
        self.assertEqual(
            current.V8_TIMEOUT_T0_HANDOFF_SHA256,
            "83ddd065c5d0a03b38d7c0933dcf335ce77988e994502e3cf46e7595dfcb1368",
        )
        self.assertEqual(
            current.V8_FORMAL_FILES["CALL-1.CAPTURE.json"],
            "67118a3872589a93a8d65057532fc171ac9f1d0cada05c1c1e64b6a2b2f90e7d",
        )
        self.assertEqual(
            str(current.EVIDENCE_ROOT),
            "/var/lib/myuna-activation-backups/"
            "p08-current-selected-forward-continuity-lineage-sha-repair-v13",
        )
        self.assertEqual(
            current.v10_terminal_contract()["status"],
            "trusted_time_drift_exceeded_predecessor_restored",
        )
        self.assertFalse(current.v10_terminal_contract()["reopen_authority"])
        self.assertEqual(
            current.v11_closed_sequence_contract()["formal"]["calls_consumed"],
            1,
        )
        self.assertFalse(
            current.v11_closed_sequence_contract()["reopen_authority"]
        )
        self.assertEqual(
            current.v12_rejected_prepare_contract()["prepare"]["status"],
            "rejected",
        )
        self.assertFalse(
            current.v12_rejected_prepare_contract()["reopen_authority"]
        )

    def test_v11_authoritative_stdout_sha_is_exact_and_malformed_legacy_rejects(self) -> None:
        authoritative = (
            "15a8389b8145cc57bb2093d65bf2de0f4ae98abea8805b99bb38ae61b0a19009"
        )
        malformed = (
            "15a8389b8145cc57bb2093d65bf2de0f4ae98abea8805b99bb38ae6b0a19009"
        )
        single_character_drift = (
            "05a8389b8145cc57bb2093d65bf2de0f4ae98abea8805b99bb38ae61b0a19009"
        )
        self.assertEqual(current.V11_FORMAL_STDOUT_SHA256, authoritative)
        self.assertEqual(len(current.V11_FORMAL_STDOUT_SHA256), 64)
        self.assertEqual(len(malformed), 63)
        self.assertEqual(len(single_character_drift), 64)
        with tempfile.TemporaryDirectory() as directory, _fixture(Path(directory)) as (
            host,
            unused_candidate,
            unused_identity,
        ):
            self.assertTrue(current.validate_v11_closed_sequence(host)["metadata_verified"])
            for rejected_sha in (malformed, single_character_drift):
                with self.subTest(rejected_sha=rejected_sha), mock.patch.object(
                    current, "V11_FORMAL_STDOUT_SHA256", rejected_sha
                ):
                    with self.assertRaisesRegex(
                        current.CurrentSelectedUpgradeRejected,
                        "v11_closed_sequence_rejected",
                    ):
                        current.validate_v11_closed_sequence(host)

    def test_v8_closed_sequence_is_exact_immutable_and_substitution_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _fixture(Path(directory)) as (
            host,
            unused_candidate,
            unused_identity,
        ):
            projection = current.validate_v8_closed_sequence(host)
            self.assertEqual(projection["formal_calls_consumed"], 1)
            self.assertEqual(projection["sequence_status"], "closed_timeout")
            self.assertFalse(projection["reopen_authority"])
            self.assertFalse(projection["restore_authority"])
            capture = current._v8_closed_sequence_path(host) / (
                "formal-sequences/"
                f"{current.V8_FORMAL_SEQUENCE_IDENTITY}/CALL-1.CAPTURE.json"
            )
            capture.write_bytes(capture.read_bytes() + b"x")
            with self.assertRaisesRegex(
                current.CurrentSelectedUpgradeRejected,
                "v8_closed_sequence_rejected",
            ):
                current.validate_v8_closed_sequence(host)

    def test_v9_closed_sequence_is_exact_immutable_and_variants_reject(self) -> None:
        variants = ("missing", "mixed", "replayed", "tampered")
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory, _fixture(
                Path(directory)
            ) as (
                host,
                unused_candidate,
                unused_identity,
            ):
                projection = current.validate_v9_closed_sequence(host)
                self.assertEqual(projection["formal_calls_consumed"], 2)
                self.assertEqual(projection["drift_calls_consumed"], 1)
                self.assertFalse(projection["reopen_authority"])
                selected = current._v9_closed_sequence_path(host)
                formal = (
                    selected
                    / "formal-sequences"
                    / current.V9_FORMAL_SEQUENCE_IDENTITY
                )
                if variant == "missing":
                    (formal / "RESULT.json").rename(formal / "RESULT.missing")
                elif variant == "mixed":
                    (formal / "MIXED.json").write_bytes(b"{}\n")
                elif variant == "replayed":
                    capture = formal / "CALL-2.CAPTURE.json"
                    capture.write_bytes(
                        (formal / "CALL-1.CAPTURE.json").read_bytes()
                    )
                else:
                    capture = formal / "CALL-1.CAPTURE.json"
                    capture.write_bytes(capture.read_bytes() + b"x")
                with self.assertRaisesRegex(
                    current.CurrentSelectedUpgradeRejected,
                    "v9_closed_sequence_rejected",
                ):
                    current.validate_v9_closed_sequence(host)

    def test_v11_closed_sequence_is_exact_immutable_and_variants_reject(self) -> None:
        variants = ("missing", "mixed", "replayed", "tampered")
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory, _fixture(
                Path(directory)
            ) as (
                host,
                unused_candidate,
                unused_identity,
            ):
                projection = current.validate_v11_closed_sequence(host)
                self.assertEqual(projection["formal_calls_consumed"], 1)
                self.assertEqual(
                    projection["sequence_status"], "closed_indeterminate"
                )
                self.assertFalse(projection["reopen_authority"])
                selected = current._v11_closed_sequence_path(host)
                formal = (
                    selected
                    / "formal-sequences"
                    / current.V11_FORMAL_SEQUENCE_IDENTITY
                )
                if variant == "missing":
                    (formal / "CALL-1.CLAIM.json").rename(
                        formal / "CALL-1.CLAIM.missing"
                    )
                elif variant == "mixed":
                    (formal / "CALL-2.CLAIM.json").write_bytes(b"{}\n")
                elif variant == "replayed":
                    (formal / "RESULT.json").write_bytes(
                        (formal / "CALL-1.CAPTURE.json").read_bytes()
                    )
                else:
                    capture = formal / "CALL-1.CAPTURE.json"
                    capture.write_bytes(capture.read_bytes() + b"x")
                with self.assertRaisesRegex(
                    current.CurrentSelectedUpgradeRejected,
                    "v11_closed_sequence_rejected",
                ):
                    current.validate_v11_closed_sequence(host)

    def test_v12_rejected_prepare_is_exact_immutable_and_variants_reject(self) -> None:
        variants = (
            "missing",
            "wrong_inventory",
            "mixed_sequence",
            "replayed",
            "raw_tainted",
            "tampered",
            "wrong_mode",
        )
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory, _fixture(
                Path(directory)
            ) as (
                host,
                unused_candidate,
                unused_identity,
            ):
                projection = current.validate_v12_rejected_prepare(host)
                self.assertEqual(projection["formal_calls_consumed"], 0)
                self.assertEqual(projection["prepare_status"], "rejected")
                self.assertFalse(projection["reopen_authority"])
                selected = current._v12_rejected_prepare_path(host)
                prepare_root = selected / "prepare-captures"
                prepare = prepare_root / current.V12_PREPARE_IDENTITY
                if variant == "missing":
                    (prepare / "CLAIM.json").rename(prepare / "CLAIM.missing")
                elif variant == "wrong_inventory":
                    (prepare / "EXTRA.json").write_bytes(b"{}\n")
                elif variant == "mixed_sequence":
                    (selected / "formal-sequences").mkdir(mode=0o700)
                elif variant == "replayed":
                    replay = prepare_root / ("e" * 64)
                    replay.mkdir(mode=0o700)
                elif variant == "raw_tainted":
                    capture = prepare / "CAPTURE.json"
                    payload = json.loads(capture.read_text("ascii"))
                    payload["raw_error"] = "must-not-be-accepted"
                    _write_json(capture, payload)
                elif variant == "tampered":
                    capture = prepare / "CAPTURE.json"
                    capture.write_bytes(capture.read_bytes() + b"x")
                else:
                    (prepare / "CAPTURE.json").chmod(0o644)
                with self.assertRaisesRegex(
                    current.CurrentSelectedUpgradeRejected,
                    "v12_rejected_prepare_rejected",
                ):
                    current.validate_v12_rejected_prepare(host)

    @unittest.skipUnless(os.geteuid() == 0, "root required for UID/GID negative")
    def test_v12_rejected_prepare_wrong_uid_gid_rejects(self) -> None:
        for uid, gid in ((1, 0), (0, 1)):
            with self.subTest(uid=uid, gid=gid), tempfile.TemporaryDirectory() as directory, _fixture(
                Path(directory)
            ) as (
                host,
                unused_candidate,
                unused_identity,
            ):
                prepare = (
                    current._v12_rejected_prepare_path(host)
                    / "prepare-captures"
                    / current.V12_PREPARE_IDENTITY
                    / "CAPTURE.json"
                )
                os.chown(prepare, uid, gid)
                with self.assertRaisesRegex(
                    current.CurrentSelectedUpgradeRejected,
                    "v12_rejected_prepare_rejected",
                ):
                    current.validate_v12_rejected_prepare(host)

    def test_v13_strategy_rejects_v12_source_build_strategy_substitution(self) -> None:
        exact = current.strategy_contract()
        self.assertEqual(
            exact["v12_rejected_prepare"], current.v12_rejected_prepare_contract()
        )
        self.assertEqual(exact["v12_controller_sha256"], current.V12_CONTROLLER_SHA256)
        self.assertEqual(exact["v12_launcher_sha256"], current.V12_LAUNCHER_SHA256)
        self.assertEqual(exact["v12_strategy_digest"], current.V12_STRATEGY_DIGEST)
        with tempfile.TemporaryDirectory() as directory, _fixture(Path(directory)) as (
            host,
            candidate,
            unused_identity,
        ):
            plan = current.prepare_plan(
                target_release=candidate,
                root=host,
                unit_state=UNIT_STATE,
            )
            for key in (
                "v12_controller_sha256",
                "v12_launcher_sha256",
                "v12_strategy_digest",
                "v12_target_manifest_sha256",
                "v12_target_release_digest",
            ):
                with self.subTest(key=key):
                    substituted = json.loads(json.dumps(plan))
                    strategy = substituted["strategy"]
                    strategy[key] = "f" * 64
                    strategy_body = dict(strategy)
                    strategy_body.pop("strategy_digest")
                    strategy["strategy_digest"] = current.digest_bytes(
                        current.canonical(strategy_body)
                    )
                    raw = dict(substituted)
                    raw.pop("plan_digest")
                    raw.pop("schema")
                    substituted = current._plan(raw)
                    with self.assertRaisesRegex(
                        current.CurrentSelectedUpgradeRejected,
                        "strategy_identity_rejected",
                    ):
                        current.validate_plan(substituted)

    def test_terminal_evidence_identity_contract_accepts_exact_and_rejects_variants(self) -> None:
        exact = current.terminal_evidence_identity_contract()
        self.assertEqual(
            exact["current-state/STATE.json"],
            current.AUTHORITATIVE_TERMINAL_STATE_MANIFEST_SHA256,
        )
        self.assertEqual(current.validate_terminal_evidence_identities(exact), exact)
        variants = []
        wrong_constant = dict(exact)
        wrong_constant["current-state/STATE.json"] = (
            current.PRESTATE_REJECTION_EXPECTED_STATE_MANIFEST_SHA256
        )
        variants.append(wrong_constant)
        single_character = dict(exact)
        single_character["current-state/STATE.json"] = (
            exact["current-state/STATE.json"][:-1] + "a"
        )
        variants.append(single_character)
        substituted = dict(exact)
        substituted["PLAN.json"] = exact["RECEIPT.json"]
        variants.append(substituted)
        stale = dict(exact)
        stale.pop("STATE_BINDING.json")
        variants.append(stale)
        mixed = dict(exact)
        mixed["unexpected.json"] = "0" * 64
        variants.append(mixed)
        for observed in variants:
            with self.subTest(observed=observed):
                with self.assertRaisesRegex(
                    current.CurrentSelectedUpgradeRejected,
                    "terminal_lineage_identity_rejected",
                ):
                    current.validate_terminal_evidence_identities(observed)

    def test_source_has_no_private_parser_or_other_program_mutator(self) -> None:
        source = Path(current.__file__).read_text("utf-8")
        self.assertNotIn("import sqlite3", source)
        self.assertNotIn("from sqlite3", source)
        self.assertNotIn("readline(", source)
        self.assertNotIn("p07_owner_private_memory", source)
        self.assertNotIn("/var/lib/myuna-activation-backups/p07", source)
        self.assertNotIn("telegram", source.lower().replace("telegram_uid", ""))
        self.assertNotIn("TrustedTimeProvider", source)
        self.assertNotIn("provider.sample(", source)
        self.assertNotIn("channel", source.lower().replace("channel_called", ""))
        self.assertNotIn("shutil.rmtree", source)
        self.assertNotIn("unlink(", source)

    def test_metadata_only_preflight_is_identical_and_reads_no_state_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with _fixture(Path(directory)) as (host, candidate, _):
                forbidden = {
                    (host / str(upgrade.STATE_ROOT).lstrip("/") / name).resolve()
                    for name in upgrade.STATE_FILES
                }
                original_open = Path.open

                def guarded_open(selected: Path, *args, **kwargs):
                    if selected.resolve() in forbidden:
                        raise AssertionError("opaque state bytes read")
                    return original_open(selected, *args, **kwargs)

                with mock.patch.object(Path, "open", new=guarded_open):
                    first = current.preflight(
                        target_release=candidate, root=host, unit_state=UNIT_STATE
                    )
                    second = current.preflight(
                        target_release=candidate, root=host, unit_state=UNIT_STATE
                    )
                self.assertEqual(current.canonical(first), current.canonical(second))
                self.assertEqual(first["status"], "ready")
                self.assertFalse(first["opaque_content_read"])
                self.assertFalse(first["persistent_mutation"])
                self.assertTrue(first["opaque_content_read_deferred_to_action_owned_backup"])
                self.assertFalse(
                    (host / str(current.EVIDENCE_ROOT).lstrip("/")).exists()
                )

    def test_real_controller_success_bytes_are_launcher_canonical_ready(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _fixture(Path(directory)) as (
            host,
            candidate,
            unused_identity,
        ):
            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch.dict(
                os.environ,
                {formal_launcher.PHASE_ROLE_ENV: formal_launcher.ROLE_FORMAL},
                clear=False,
            ), mock.patch.object(
                formal_launcher, "emit_phase"
            ), redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = current.main(
                    [
                        "preflight",
                        "--target-release",
                        str(candidate),
                        "--synthetic-root",
                        str(host),
                    ]
                )
            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr.getvalue(), "")
            raw = stdout.getvalue().encode("ascii")
            payload = json.loads(raw.decode("ascii"))
            self.assertEqual(
                set(payload),
                {
                    "forward_continuity",
                    "opaque_content_read",
                    "opaque_content_read_deferred_to_action_owned_backup",
                    "persistent_mutation",
                    "plan",
                    "plan_digest",
                    "schema",
                    "status",
                },
            )
            events = tuple(
                {
                    "monotonic_ns": index,
                    "nonce": "a" * 64,
                    "phase": phase,
                    "role": formal_launcher.ROLE_FORMAL,
                    "schema": formal_launcher.PHASE_LIVENESS_SCHEMA,
                    "sequence": index,
                }
                for index, phase in enumerate(
                    formal_launcher.ROLE_PHASES[formal_launcher.ROLE_FORMAL], 1
                )
            )
            observation = formal_launcher.ProcessObservation(
                process_created=True,
                pid=123,
                started_ns=1,
                ended_ns=2,
                returncode=0,
                timed_out=False,
                stdout=raw,
                stderr=b"",
                progress_valid=True,
                progress_complete=True,
                progress_events=events,
                progress_error=None,
            )
            parsed = formal_launcher._parse_child(observation)
            self.assertEqual(parsed[0], "ready")
            self.assertTrue(parsed[3])
            body = {
                "argv_identity_sha256": "1" * 64,
                "controller_sha256": "2" * 64,
                "cwd": str(host),
                "environment_identity_sha256": "3" * 64,
                "hard_timeout_seconds": formal_launcher.ROLE_TIMEOUT_SECONDS[
                    formal_launcher.ROLE_FORMAL
                ],
                "host_contract_digest": "4" * 64,
                "launcher_contract_digest": "5" * 64,
                "no_progress_timeout_seconds": (
                    formal_launcher.ROLE_NO_PROGRESS_TIMEOUT_SECONDS[
                        formal_launcher.ROLE_FORMAL
                    ]
                ),
                "phase_liveness_contract_digest": "6" * 64,
                "role": formal_launcher.ROLE_FORMAL,
                "schema": formal_launcher.LAUNCHER_SCHEMA,
                "source_binding_digest": "7" * 64,
                "target_release_digest": candidate.name,
            }
            invocation = {
                **body,
                "invocation_identity_sha256": formal_launcher.digest_bytes(
                    formal_launcher.canonical(body)
                ),
                "_argv": [str(formal_launcher.INTERPRETER), "synthetic"],
                "_environment": {"PYTHONDONTWRITEBYTECODE": "1"},
            }
            capture = formal_launcher.capture_formal_call(
                invocation=invocation,
                evidence_root=host / "synthetic-launcher-evidence",
                call_index=1,
                runner=lambda *unused: observation,
            )
            self.assertEqual(capture["status"], "ready")
            self.assertTrue(capture["canonical_result"])
            self.assertFalse(capture["raw_output_retained"])
            durable = b"".join(
                path.read_bytes()
                for path in (host / "synthetic-launcher-evidence").rglob("*.json")
            )
            self.assertNotIn(raw, durable)

    def test_plan_binds_new_strategy_target_and_p08_only_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with _fixture(Path(directory)) as (host, candidate, _):
                plan = current.prepare_plan(
                    target_release=candidate, root=host, unit_state=UNIT_STATE
                )
                self.assertEqual(plan["action"], "upgrade")
                self.assertEqual(plan["strategy"]["max_attempts"], 1)
                self.assertEqual(
                    plan["accepted_predecessor_lineage"]["status"], "target_accepted"
                )
                self.assertEqual(
                    plan["failed_predecessor_lineage"]["status"],
                    "prestop_public_backup_mode_rejected",
                )
                self.assertFalse(
                    plan["failed_predecessor_lineage"]["restore_authority"]
                )
                self.assertEqual(
                    plan["strategy"]["failed_incident_digest"],
                    current.FAILED_INCIDENT_DIGEST,
                )
                self.assertEqual(
                    plan["strategy"]["terminal_incident_digest"],
                    current.TERMINAL_INCIDENT_DIGEST,
                )
                self.assertEqual(
                    plan["terminal_predecessor_lineage"]["status"],
                    "protocol_acceptance_failed_predecessor_restored",
                )
                self.assertFalse(
                    plan["terminal_predecessor_lineage"]["restore_authority"]
                )
                self.assertEqual(
                    plan["strategy"]["v2_terminal_incident_digest"],
                    current.V2_TERMINAL_INCIDENT_DIGEST,
                )
                self.assertEqual(
                    plan["v2_terminal_predecessor_lineage"]["status"],
                    "protocol_acceptance_failed_predecessor_restored",
                )
                self.assertFalse(
                    plan["v2_terminal_predecessor_lineage"]["restore_authority"]
                )
                self.assertEqual(
                    plan["strategy"]["v4_terminal_incident_digest"],
                    current.V4_TERMINAL_INCIDENT_DIGEST,
                )
                self.assertEqual(
                    plan["v4_terminal_predecessor_lineage"]["status"],
                    "server_status_runtime_rejected_predecessor_restored",
                )
                self.assertFalse(
                    plan["v4_terminal_predecessor_lineage"]["restore_authority"]
                )
                self.assertEqual(
                    plan["strategy"]["v5_terminal_incident_digest"],
                    current.V5_TERMINAL_INCIDENT_DIGEST,
                )
                self.assertEqual(
                    plan["v5_terminal_predecessor_lineage"]["status"],
                    "trusted_time_rejected_predecessor_restored",
                )
                self.assertFalse(
                    plan["v5_terminal_predecessor_lineage"]["restore_authority"]
                )
                self.assertEqual(
                    plan["strategy"]["p08_trusted_time_t0_handoff_sha256"],
                    current.P08_TRUSTED_TIME_T0_HANDOFF_SHA256,
                )
                self.assertEqual(
                    plan["strategy"]["p10b_trusted_time_t0_handoff_sha256"],
                    current.P10B_TRUSTED_TIME_T0_HANDOFF_SHA256,
                )
                self.assertEqual(
                    plan["prestate_rejection_lineage"],
                    current.prestate_rejection_contract(),
                )
                self.assertEqual(
                    plan["incident"]["prestate_rejection_handoff_sha256"],
                    current.PRESTATE_REJECTION_HANDOFF_SHA256,
                )
                self.assertEqual(
                    plan["incident"]["nonzero_stage_t0_handoff_sha256"],
                    current.NONZERO_STAGE_T0_HANDOFF_SHA256,
                )
                self.assertEqual(
                    plan["incident"]["p07_integration_handoff_sha256"],
                    current.P07_INTEGRATION_HANDOFF_SHA256,
                )
                self.assertEqual(
                    plan["strategy"]["p07_single_nonce_integration"],
                    current.p07_single_nonce_integration_contract(),
                )
                self.assertEqual(
                    plan["strategy"]["single_nonce_stage_t1_handoff_sha256"],
                    current.SINGLE_NONCE_STAGE_T1_HANDOFF_SHA256,
                )
                self.assertEqual(plan["current_target"]["release_digest"], current.PREDECESSOR_RELEASE_DIGEST)
                self.assertEqual(plan["target"]["release_digest"], candidate.name)
                self.assertNotIn(str(upgrade.STATE_ROOT), plan["allowed_mutation_paths"])
                self.assertIn("P07", plan["forbidden_program_mutations"])
                self.assertEqual(current.verify_plan(plan, root=host, unit_state=UNIT_STATE), plan)

    def test_p07_single_nonce_integration_contract_is_exact_and_canonical(self) -> None:
        contract = current.p07_single_nonce_integration_contract()
        body = {key: value for key, value in contract.items() if key != "contract_digest"}
        self.assertEqual(contract["schema"], current.P07_INTEGRATION_SCHEMA)
        self.assertEqual(
            contract["handoff_sha256"], current.P07_INTEGRATION_HANDOFF_SHA256
        )
        self.assertEqual(
            contract["deploy_commit"], current.P07_INTEGRATION_DEPLOY_COMMIT
        )
        self.assertEqual(
            contract["runtime_release_digest"], current.P07_RUNTIME_RELEASE_DIGEST
        )
        self.assertEqual(
            contract["transactional_bundle_digest"],
            current.P07_TRANSACTIONAL_BUNDLE_DIGEST,
        )
        self.assertEqual(
            contract["fresh_strategy_digest"], current.P07_FRESH_STRATEGY_DIGEST
        )
        self.assertEqual(
            contract["contract_digest"], current.digest_bytes(current.canonical(body))
        )

    def test_failed_incident_is_immutable_and_never_restore_authority(self) -> None:
        for selected in ("receipt", "mode_rewrite"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as directory:
                with _fixture(Path(directory)) as (host, _, _):
                    lineage = current.validate_failed_lineage(host)
                    self.assertFalse(lineage["restore_authority"])
                    failed = host / str(current.FAILED_EVIDENCE_ROOT).lstrip("/")
                    if selected == "receipt":
                        _write_json(failed / "RECEIPT.json", {"status": "invented"})
                    else:
                        text = str(upgrade.UNIT_ROOT / upgrade.SERVICE)
                        name = current.digest_bytes(text.encode("ascii"))
                        (failed / "current-public" / name).chmod(0o644)
                    with self.assertRaises(current.CurrentSelectedUpgradeRejected):
                        current.validate_failed_lineage(host)

    def test_terminal_incident_is_immutable_consumed_and_never_reused(self) -> None:
        for selected in ("receipt", "journal"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as directory:
                with _fixture(Path(directory)) as (host, _, _):
                    lineage = current.validate_terminal_lineage(host)
                    self.assertFalse(lineage["restore_authority"])
                    self.assertEqual(
                        lineage["status"],
                        "protocol_acceptance_failed_predecessor_restored",
                    )
                    terminal = host / str(current.TERMINAL_EVIDENCE_ROOT).lstrip("/")
                    if selected == "receipt":
                        _write_json(
                            terminal / "RECEIPT.json",
                            {"status": "upgrade_target_accepted"},
                        )
                    else:
                        _write_json(
                            terminal / "JOURNAL.json",
                            {"stage": "target_accepted"},
                        )
                    with self.assertRaises(current.CurrentSelectedUpgradeRejected):
                        current.validate_terminal_lineage(host)

    def test_verify_plan_rejects_terminal_evidence_drift_after_prepare(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with _fixture(Path(directory)) as (host, candidate, _):
                plan = current.prepare_plan(
                    target_release=candidate, root=host, unit_state=UNIT_STATE
                )
                terminal = host / str(current.TERMINAL_EVIDENCE_ROOT).lstrip("/")
                _write_json(
                    terminal / "RECEIPT.json",
                    {"status": "stale-replay-substitution"},
                )
                with self.assertRaisesRegex(
                    current.CurrentSelectedUpgradeRejected,
                    "terminal_lineage_identity_rejected",
                ):
                    current.verify_plan(plan, root=host, unit_state=UNIT_STATE)

    def test_v2_terminal_incident_is_immutable_consumed_and_source_bound(self) -> None:
        for selected in ("receipt", "plan", "state-binding"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as directory:
                with _fixture(Path(directory)) as (host, _, _):
                    lineage = current.validate_v2_terminal_lineage(host)
                    self.assertFalse(lineage["restore_authority"])
                    terminal = host / str(current.V2_TERMINAL_EVIDENCE_ROOT).lstrip("/")
                    name = {
                        "receipt": "RECEIPT.json",
                        "plan": "PLAN.json",
                        "state-binding": "STATE_BINDING.json",
                    }[selected]
                    path = terminal / name
                    original = path.read_bytes()
                    path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
                    with self.assertRaisesRegex(
                        current.CurrentSelectedUpgradeRejected,
                        "v2_terminal_lineage_identity_rejected",
                    ):
                        current.validate_v2_terminal_lineage(host)

    def test_v4_terminal_incident_is_immutable_consumed_and_source_bound(self) -> None:
        for selected in ("receipt", "plan", "state-binding"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as directory:
                with _fixture(Path(directory)) as (host, _, _):
                    lineage = current.validate_v4_terminal_lineage(host)
                    self.assertFalse(lineage["restore_authority"])
                    self.assertEqual(
                        lineage["status"],
                        "server_status_runtime_rejected_predecessor_restored",
                    )
                    terminal = host / str(current.V4_TERMINAL_EVIDENCE_ROOT).lstrip("/")
                    name = {
                        "receipt": "RECEIPT.json",
                        "plan": "PLAN.json",
                        "state-binding": "STATE_BINDING.json",
                    }[selected]
                    path = terminal / name
                    original = path.read_bytes()
                    path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
                    with self.assertRaisesRegex(
                        current.CurrentSelectedUpgradeRejected,
                        "v4_terminal_lineage_identity_rejected",
                    ):
                        current.validate_v4_terminal_lineage(host)

    def test_v5_terminal_incident_is_immutable_consumed_and_source_bound(self) -> None:
        for selected in ("receipt", "plan", "state-binding"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as directory:
                with _fixture(Path(directory)) as (host, _, _):
                    lineage = current.validate_v5_terminal_lineage(host)
                    self.assertFalse(lineage["restore_authority"])
                    self.assertEqual(
                        lineage["status"],
                        "trusted_time_rejected_predecessor_restored",
                    )
                    terminal = host / str(current.V5_TERMINAL_EVIDENCE_ROOT).lstrip("/")
                    name = {
                        "receipt": "RECEIPT.json",
                        "plan": "PLAN.json",
                        "state-binding": "STATE_BINDING.json",
                    }[selected]
                    path = terminal / name
                    original = path.read_bytes()
                    path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
                    with self.assertRaisesRegex(
                        current.CurrentSelectedUpgradeRejected,
                        "v5_terminal_lineage_identity_rejected",
                    ):
                        current.validate_v5_terminal_lineage(host)

    def test_mixed_plan_lineage_target_and_allowed_paths_fail_closed(self) -> None:
        for selected in (
            "lineage",
            "failed_lineage",
            "terminal_lineage",
            "v2_terminal_lineage",
            "v4_terminal_lineage",
            "v5_terminal_lineage",
            "prestate_rejection",
            "p07_integration",
            "replay",
            "target",
            "paths",
        ):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as directory:
                with _fixture(Path(directory)) as (host, candidate, _):
                    plan = current.prepare_plan(
                        target_release=candidate, root=host, unit_state=UNIT_STATE
                    )
                    changed = json.loads(json.dumps(plan))
                    if selected == "lineage":
                        changed["accepted_predecessor_lineage"]["receipt_sha256"] = "0" * 64
                    elif selected == "failed_lineage":
                        changed["failed_predecessor_lineage"]["restore_authority"] = True
                    elif selected == "terminal_lineage":
                        changed["terminal_predecessor_lineage"]["receipt_sha256"] = "0" * 64
                    elif selected == "v2_terminal_lineage":
                        changed["v2_terminal_predecessor_lineage"]["receipt_sha256"] = "0" * 64
                    elif selected == "v4_terminal_lineage":
                        changed["v4_terminal_predecessor_lineage"]["receipt_sha256"] = "0" * 64
                    elif selected == "v5_terminal_lineage":
                        changed["v5_terminal_predecessor_lineage"]["receipt_sha256"] = "0" * 64
                    elif selected == "prestate_rejection":
                        changed["prestate_rejection_lineage"]["handoff_sha256"] = "0" * 64
                    elif selected == "p07_integration":
                        changed["strategy"]["p07_single_nonce_integration"][
                            "runtime_release_digest"
                        ] = "0" * 64
                    elif selected == "replay":
                        changed["strategy"]["schema"] = (
                            "myuna.p08-current-selected-protocol-acceptance-repair-strategy.v1"
                        )
                    elif selected == "target":
                        changed["target"]["controller_sha256"] = "0" * 64
                    else:
                        changed["allowed_mutation_paths"].append("/etc/passwd")
                    body = {k: v for k, v in changed.items() if k not in {"schema", "plan_digest"}}
                    changed["plan_digest"] = current.digest_bytes(current.canonical(body))
                    with self.assertRaises(current.CurrentSelectedUpgradeRejected):
                        current.validate_plan(changed)

    def test_stage_is_opaque_exact_before_stop_and_o_excl_max_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with _fixture(Path(directory)) as (host, candidate, _):
                plan = current.prepare_plan(
                    target_release=candidate, root=host, unit_state=UNIT_STATE
                )
                evidence = current.stage_plan(plan, root=host, unit_state=UNIT_STATE)
                self.assertTrue((evidence / "PLAN.json").is_file())
                self.assertTrue((evidence / "STATE_BINDING.json").is_file())
                journal = json.loads((evidence / "JOURNAL.json").read_text("ascii"))
                self.assertEqual(journal["stage"], "attempt_owned")
                ledger = json.loads((evidence / "LEDGER.json").read_text("ascii"))
                self.assertEqual(ledger["attempts"], 1)
                self.assertTrue(ledger["consumed"])
                with self.assertRaisesRegex(
                    current.CurrentSelectedUpgradeRejected, "incident_already_consumed"
                ):
                    current.stage_plan(plan, root=host, unit_state=UNIT_STATE)

    def test_secure_umask_stage_has_exact_mixed_public_backup_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with _fixture(Path(directory)) as (host, candidate, _):
                plan = current.prepare_plan(
                    target_release=candidate, root=host, unit_state=UNIT_STATE
                )
                previous = os.umask(0o077)
                try:
                    evidence = current.stage_plan(
                        plan, root=host, unit_state=UNIT_STATE
                    )
                finally:
                    os.umask(previous)
                backup = evidence / "current-public"
                upgrade._validate_public_backup(backup, current._public_adapter(plan))
                modes = {
                    text: stat.S_IMODE(
                        (backup / current.digest_bytes(text.encode("ascii"))).stat().st_mode
                    )
                    for text in plan["current_target"]["public"]
                }
                self.assertEqual(modes[str(upgrade.SELECTOR_JSON)], 0o600)
                self.assertEqual(modes[str(upgrade.SELECTOR_ENV)], 0o600)
                self.assertEqual(
                    modes[str(upgrade.UNIT_ROOT / upgrade.SERVICE)], 0o644
                )
                self.assertEqual(
                    modes[str(upgrade.UNIT_ROOT / upgrade.SOCKET)], 0o644
                )
                self.assertEqual(list(backup.glob(".*.stage")), [])

    def test_invalid_public_backup_consumes_before_state_or_unit_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with _fixture(Path(directory)) as (host, candidate, _):
                plan = current.prepare_plan(
                    target_release=candidate, root=host, unit_state=UNIT_STATE
                )
                original_write = upgrade._exclusive_write

                def narrow_unit_mode(
                    path: Path,
                    payload: bytes,
                    *,
                    mode: int,
                    uid: int | None = None,
                    gid: int | None = None,
                ) -> None:
                    original_write(path, payload, mode=mode, uid=uid, gid=gid)
                    if mode == 0o644:
                        path.chmod(0o600)

                with mock.patch.object(
                    upgrade, "_exclusive_write", side_effect=narrow_unit_mode
                ), mock.patch.object(current, "_stage_state_backup") as state_backup, mock.patch.object(
                    upgrade, "_stop"
                ) as stop:
                    with self.assertRaisesRegex(
                        upgrade.UpgradeRejected, "public_backup_rejected"
                    ):
                        current.stage_plan(plan, root=host, unit_state=UNIT_STATE)
                state_backup.assert_not_called()
                stop.assert_not_called()
                evidence = current._evidence_path(host, plan)
                ledger = json.loads((evidence / "LEDGER.json").read_text("ascii"))
                journal = json.loads((evidence / "JOURNAL.json").read_text("ascii"))
                self.assertTrue(ledger["consumed"])
                self.assertEqual(ledger["attempts"], 1)
                self.assertEqual(journal["stage"], "prepared")
                self.assertFalse((evidence / "current-state").exists())
                self.assertFalse((evidence / "RECEIPT.json").exists())
                self.assertFalse(
                    (
                        host
                        / str(upgrade.RELEASE_ROOT).lstrip("/")
                        / candidate.name
                    ).exists()
                )

    def test_concurrent_claim_has_exactly_one_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with _fixture(Path(directory)) as (host, candidate, _):
                plan = current.prepare_plan(
                    target_release=candidate, root=host, unit_state=UNIT_STATE
                )
                barrier = threading.Barrier(2)
                outcomes: list[str] = []

                def claim() -> None:
                    barrier.wait()
                    try:
                        current.stage_plan(plan, root=host, unit_state=UNIT_STATE)
                        outcomes.append("claimed")
                    except current.CurrentSelectedUpgradeRejected as exc:
                        outcomes.append(exc.code)

                workers = [threading.Thread(target=claim) for _ in range(2)]
                for worker in workers:
                    worker.start()
                for worker in workers:
                    worker.join(timeout=10)
                self.assertEqual(outcomes.count("claimed"), 1)
                self.assertEqual(outcomes.count("incident_already_consumed"), 1)

    def test_partial_state_backup_consumes_incident_before_stop(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with _fixture(Path(directory)) as (host, candidate, _):
                plan = current.prepare_plan(
                    target_release=candidate, root=host, unit_state=UNIT_STATE
                )
                original = upgrade._copy_exact_file
                calls = 0

                def fail_after_first(source: Path, destination: Path, row) -> None:
                    nonlocal calls
                    original(source, destination, row)
                    calls += 1
                    if calls == 1:
                        raise upgrade.UpgradeRejected("synthetic_partial_backup")

                with mock.patch.object(
                    upgrade, "_copy_exact_file", side_effect=fail_after_first
                ):
                    with self.assertRaisesRegex(
                        upgrade.UpgradeRejected, "synthetic_partial_backup"
                    ):
                        current.stage_plan(plan, root=host, unit_state=UNIT_STATE)
                evidence = current._evidence_path(host, plan)
                self.assertTrue((evidence / "PLAN.json").is_file())
                self.assertTrue((evidence / "LEDGER.json").is_file())
                self.assertFalse((evidence / "RECEIPT.json").exists())
                journal = json.loads((evidence / "JOURNAL.json").read_text("ascii"))
                self.assertEqual(journal["stage"], "current_public_backed_up")
                with self.assertRaisesRegex(
                    current.CurrentSelectedUpgradeRejected,
                    "incident_already_consumed",
                ):
                    current.stage_plan(plan, root=host, unit_state=UNIT_STATE)

    def test_state_drift_after_claim_consumes_without_any_stop(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with _fixture(Path(directory)) as (host, candidate, _):
                plan = current.prepare_plan(
                    target_release=candidate, root=host, unit_state=UNIT_STATE
                )
                original = upgrade._copy_public_backup

                def mutate_then_copy(root, backup, adapter):
                    original(root, backup, adapter)
                    state = root / str(upgrade.STATE_ROOT).lstrip("/") / upgrade.STATE_FILES[0]
                    state.write_bytes(b"synthetic-race")
                    state.chmod(0o600)

                with mock.patch.object(upgrade, "_copy_public_backup", side_effect=mutate_then_copy):
                    with self.assertRaises(
                        (current.CurrentSelectedUpgradeRejected, upgrade.UpgradeRejected)
                    ):
                        current.stage_plan(plan, root=host, unit_state=UNIT_STATE)
                evidence = current._evidence_path(host, plan)
                self.assertTrue((evidence / "LEDGER.json").is_file())
                journal = json.loads((evidence / "JOURNAL.json").read_text("ascii"))
                self.assertEqual(journal["stage"], "current_public_backed_up")

    def test_synthetic_success_order_and_single_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with _fixture(Path(directory)) as (host, candidate, _):
                plan = current.prepare_plan(
                    target_release=candidate, root=host, unit_state=UNIT_STATE
                )
                current.stage_plan(plan, root=host, unit_state=UNIT_STATE)
                runner = RecordingRunner()
                calls: list[Path] = []

                def accept(release: Path):
                    calls.append(release)
                    return post._synthetic_content_free_acceptance(release)

                receipt = current.execute_staged_plan(
                    plan,
                    root=host,
                    unit_state=UNIT_STATE,
                    runner=runner,
                    acceptance_runner=accept,
                    forward_transition_runner=_synthetic_forward_transition,
                    forward_state_verifier=_synthetic_forward_state_verifier,
                )
                self.assertEqual(receipt["status"], "upgrade_target_accepted")
                self.assertIsNone(receipt["protocol_acceptance_failure"])
                self.assertEqual(
                    receipt["forward_continuity_result"]["state_effect"], "committed"
                )
                self.assertFalse(receipt["state_bytes_restored"])
                self.assertFalse(receipt["trusted_time_state_rollback"])
                self.assertEqual(calls, [host / str(upgrade.RELEASE_ROOT / candidate.name).lstrip("/")])
                self.assertEqual(
                    runner.events[:2],
                    [
                        ("/usr/bin/systemctl", "stop", upgrade.SOCKET),
                        ("/usr/bin/systemctl", "stop", upgrade.SERVICE),
                    ],
                )
                service_start = runner.events.index(("/usr/bin/systemctl", "start", upgrade.SERVICE))
                socket_start = runner.events.index(("/usr/bin/systemctl", "start", upgrade.SOCKET))
                self.assertLess(service_start, socket_start)

    def test_acceptance_failure_rolls_back_once_to_exact_current_selection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with _fixture(Path(directory)) as (host, candidate, identity):
                state_root = host / str(upgrade.STATE_ROOT).lstrip("/")
                before = upgrade.describe_opaque_state(
                    state_root, expected_uid=identity[0], expected_gid=identity[1]
                )
                plan = current.prepare_plan(
                    target_release=candidate, root=host, unit_state=UNIT_STATE
                )
                current.stage_plan(plan, root=host, unit_state=UNIT_STATE)

                def reject(_: Path):
                    raise current.CurrentSelectedUpgradeRejected("synthetic_acceptance_failure")

                runner = RecordingRunner()
                with self.assertRaisesRegex(
                    current.CurrentSelectedUpgradeRejected,
                    "action_failed_predecessor_restored",
                ):
                    current.execute_staged_plan(
                        plan,
                        root=host,
                        unit_state=UNIT_STATE,
                        runner=runner,
                        acceptance_runner=reject,
                        forward_transition_runner=_synthetic_forward_transition,
                        forward_state_verifier=_synthetic_forward_state_verifier,
                    )
                selector = json.loads(
                    (host / str(upgrade.SELECTOR_JSON).lstrip("/")).read_text("utf-8")
                )
                self.assertEqual(selector["release_digest"], current.PREDECESSOR_RELEASE_DIGEST)
                self.assertEqual(
                    upgrade.describe_opaque_state(
                        state_root, expected_uid=identity[0], expected_gid=identity[1]
                    ),
                    before,
                )
                receipt = json.loads(
                    (current._evidence_path(host, plan) / "RECEIPT.json").read_text("ascii")
                )
                self.assertEqual(receipt["status"], "action_failed_predecessor_restored")
                self.assertEqual(receipt["predecessor_release_digest"], current.PREDECESSOR_RELEASE_DIGEST)
                self.assertIsNone(receipt["protocol_acceptance_failure"])
                self.assertFalse(receipt["state_bytes_restored"])
                self.assertFalse(receipt["trusted_time_state_rollback"])

    def test_valid_content_free_child_stage_is_preserved_after_bounded_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with _fixture(Path(directory)) as (host, candidate, _):
                plan = current.prepare_plan(
                    target_release=candidate, root=host, unit_state=UNIT_STATE
                )
                current.stage_plan(plan, root=host, unit_state=UNIT_STATE)
                nonce = "d" * 64
                runtime_rejection = (
                    post.temporal_gateway.ContentFreeRuntimeRejection.from_stage(
                        "store_state_boundary",
                        request_nonce=nonce,
                    )
                )
                projection = post.temporal_gateway.ContentFreeStatusRejection.from_stage(
                    "server_status_runtime_rejection",
                    invocation_nonce=nonce,
                    runtime_rejection=runtime_rejection,
                ).projection()

                def reject(_: Path):
                    raise post.PostTargetRejected(
                        "protocol_acceptance_failed",
                        content_free_failure_projection=projection,
                    )

                with self.assertRaisesRegex(
                    current.CurrentSelectedUpgradeRejected,
                    "action_failed_predecessor_restored",
                ):
                    current.execute_staged_plan(
                        plan,
                        root=host,
                        unit_state=UNIT_STATE,
                        runner=RecordingRunner(),
                        acceptance_runner=reject,
                        forward_transition_runner=_synthetic_forward_transition,
                        forward_state_verifier=_synthetic_forward_state_verifier,
                    )
                receipt = json.loads(
                    (current._evidence_path(host, plan) / "RECEIPT.json").read_text(
                        "ascii"
                    )
                )
                self.assertEqual(receipt["protocol_acceptance_failure"], projection)
                self.assertEqual(
                    receipt["protocol_acceptance_failure"]["runtime_rejection"][
                        "stage"
                    ],
                    "store_state_boundary",
                )
                rendered = current.canonical(receipt).decode("ascii")
                self.assertNotIn("PRIVATE/raw/cause", rendered)
                self.assertFalse(
                    receipt["protocol_acceptance_failure"]["runtime_rejection"][
                        "raw_cause_included"
                    ]
                )

    def test_invalid_content_free_child_stage_remains_generic_after_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with _fixture(Path(directory)) as (host, candidate, _):
                plan = current.prepare_plan(
                    target_release=candidate, root=host, unit_state=UNIT_STATE
                )
                current.stage_plan(plan, root=host, unit_state=UNIT_STATE)
                projection = post.temporal_gateway.ContentFreeStatusRejection.from_stage(
                    "transport_connect", invocation_nonce="e" * 64
                ).projection()
                projection["stage"] = "unknown-or-mixed"

                def reject(_: Path):
                    raise post.PostTargetRejected(
                        "protocol_acceptance_failed",
                        content_free_failure_projection=projection,
                    )

                with self.assertRaisesRegex(
                    current.CurrentSelectedUpgradeRejected,
                    "action_failed_predecessor_restored",
                ):
                    current.execute_staged_plan(
                        plan,
                        root=host,
                        unit_state=UNIT_STATE,
                        runner=RecordingRunner(),
                        acceptance_runner=reject,
                        forward_transition_runner=_synthetic_forward_transition,
                        forward_state_verifier=_synthetic_forward_state_verifier,
                    )
                receipt = json.loads(
                    (current._evidence_path(host, plan) / "RECEIPT.json").read_text(
                        "ascii"
                    )
                )
                self.assertIsNone(receipt["protocol_acceptance_failure"])

    def test_crash_after_stop_recovers_once_and_replay_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with _fixture(Path(directory)) as (host, candidate, _):
                plan = current.prepare_plan(
                    target_release=candidate, root=host, unit_state=UNIT_STATE
                )
                current.stage_plan(plan, root=host, unit_state=UNIT_STATE)

                def crash(stage: str) -> None:
                    if stage == "services_stopped":
                        raise SyntheticCrash()

                with self.assertRaises(SyntheticCrash):
                    current.execute_staged_plan(
                        plan,
                        root=host,
                        unit_state=UNIT_STATE,
                        runner=RecordingRunner(),
                        acceptance_runner=post._synthetic_content_free_acceptance,
                        stage_hook=crash,
                    )
                receipt = current.recover_interrupted_plan(
                    plan,
                    root=host,
                    unit_state=UNIT_STATE,
                    runner=RecordingRunner(),
                )
                self.assertEqual(receipt["status"], "interrupted_action_predecessor_restored")
                with self.assertRaisesRegex(
                    current.CurrentSelectedUpgradeRejected, "recovery_replay_rejected"
                ):
                    current.recover_interrupted_plan(
                        plan,
                        root=host,
                        unit_state=UNIT_STATE,
                        runner=RecordingRunner(),
                    )

    def test_precommit_failure_and_binding_window_preserve_old_anchor_without_restore(self) -> None:
        for selected in ("typed_precommit", "binding_window_crash"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as directory:
                with _fixture(Path(directory)) as (host, candidate, identity):
                    state_root = host / str(upgrade.STATE_ROOT).lstrip("/")
                    before = upgrade.describe_opaque_state(
                        state_root,
                        expected_uid=identity[0],
                        expected_gid=identity[1],
                    )
                    plan = current.prepare_plan(
                        target_release=candidate, root=host, unit_state=UNIT_STATE
                    )
                    current.stage_plan(plan, root=host, unit_state=UNIT_STATE)

                    def transition(root, plan, origin, evidence, persist):
                        del root, origin, evidence
                        persist(
                            current.canonical(
                                {
                                    "content_free_export_allowed": False,
                                    "plan_digest": plan["plan_digest"],
                                    "schema": "synthetic.p08-forward-binding.private.v1",
                                }
                            )
                        )
                        if selected == "binding_window_crash":
                            raise SyntheticCrash()
                        raise current.continuity.ForwardContinuityRejected(
                            "synthetic_precommit_rejected",
                            state_effect="none",
                            projection={"state_effect": "none", "status": "precommit_rejected"},
                        )

                    with mock.patch.object(
                        upgrade,
                        "restore_opaque_state",
                        side_effect=AssertionError("state restore is forbidden"),
                    ):
                        if selected == "typed_precommit":
                            with self.assertRaisesRegex(
                                current.CurrentSelectedUpgradeRejected,
                                "action_failed_predecessor_restored",
                            ):
                                current.execute_staged_plan(
                                    plan,
                                    root=host,
                                    unit_state=UNIT_STATE,
                                    runner=RecordingRunner(),
                                    forward_transition_runner=transition,
                                    forward_state_verifier=_reject_forward_state_verifier,
                                )
                        else:
                            with self.assertRaises(SyntheticCrash):
                                current.execute_staged_plan(
                                    plan,
                                    root=host,
                                    unit_state=UNIT_STATE,
                                    runner=RecordingRunner(),
                                    forward_transition_runner=transition,
                                    forward_state_verifier=_reject_forward_state_verifier,
                                )
                            receipt = current.recover_interrupted_plan(
                                plan,
                                root=host,
                                unit_state=UNIT_STATE,
                                runner=RecordingRunner(),
                                forward_reconcile_runner=(
                                    _synthetic_forward_reconcile_not_committed
                                ),
                                forward_state_verifier=_reject_forward_state_verifier,
                            )
                            self.assertEqual(
                                receipt["status"],
                                "interrupted_action_predecessor_restored",
                            )
                    self.assertEqual(
                        upgrade.describe_opaque_state(
                            state_root,
                            expected_uid=identity[0],
                            expected_gid=identity[1],
                        ),
                        before,
                    )

    def test_crash_after_forward_state_change_preserves_authoritative_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with _fixture(Path(directory)) as (host, candidate, identity):
                state_root = host / str(upgrade.STATE_ROOT).lstrip("/")
                before = upgrade.describe_opaque_state(
                    state_root, expected_uid=identity[0], expected_gid=identity[1]
                )
                plan = current.prepare_plan(
                    target_release=candidate, root=host, unit_state=UNIT_STATE
                )
                current.stage_plan(plan, root=host, unit_state=UNIT_STATE)

                def mutate_and_crash(stage: str) -> None:
                    if stage == "target_started":
                        target = state_root / upgrade.STATE_FILES[0]
                        target.write_bytes(b"synthetic-target-state-change")
                        target.chmod(0o600)
                        raise SyntheticCrash()

                with self.assertRaises(SyntheticCrash):
                    current.execute_staged_plan(
                        plan,
                        root=host,
                        unit_state=UNIT_STATE,
                        runner=RecordingRunner(),
                        acceptance_runner=post._synthetic_content_free_acceptance,
                        forward_transition_runner=_synthetic_forward_transition,
                        forward_state_verifier=_synthetic_forward_state_verifier,
                        stage_hook=mutate_and_crash,
                    )
                receipt = current.recover_interrupted_plan(
                    plan,
                    root=host,
                    unit_state=UNIT_STATE,
                    runner=RecordingRunner(),
                    forward_reconcile_runner=_synthetic_forward_reconcile,
                    forward_state_verifier=_synthetic_forward_state_verifier,
                )
                self.assertEqual(receipt["status"], "interrupted_action_predecessor_restored")
                after = upgrade.describe_opaque_state(
                    state_root, expected_uid=identity[0], expected_gid=identity[1]
                )
                self.assertNotEqual(after, before)
                self.assertEqual(
                    upgrade.digest_file(state_root / upgrade.STATE_FILES[0]),
                    upgrade.digest_bytes(b"synthetic-target-state-change"),
                )
                self.assertFalse(receipt["state_bytes_restored"])
                self.assertFalse(receipt["trusted_time_state_rollback"])

    def test_crash_during_convergence_consumes_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with _fixture(Path(directory)) as (host, candidate, _):
                plan = current.prepare_plan(
                    target_release=candidate, root=host, unit_state=UNIT_STATE
                )
                current.stage_plan(plan, root=host, unit_state=UNIT_STATE)

                def crash_after_stop(stage: str) -> None:
                    if stage == "services_stopped":
                        raise SyntheticCrash()

                with self.assertRaises(SyntheticCrash):
                    current.execute_staged_plan(
                        plan,
                        root=host,
                        unit_state=UNIT_STATE,
                        runner=RecordingRunner(),
                        stage_hook=crash_after_stop,
                    )

                def crash_convergence(_: list[str]) -> None:
                    raise SyntheticCrash()

                with self.assertRaises(SyntheticCrash):
                    current.recover_interrupted_plan(
                        plan,
                        root=host,
                        unit_state=UNIT_STATE,
                        runner=crash_convergence,
                    )
                with self.assertRaisesRegex(
                    current.CurrentSelectedUpgradeRejected,
                    "recovery_already_consumed",
                ):
                    current.recover_interrupted_plan(
                        plan,
                        root=host,
                        unit_state=UNIT_STATE,
                        runner=RecordingRunner(),
                    )

    def test_permission_type_and_source_substitution_fail_closed(self) -> None:
        for selected in ("permission", "symlink", "source"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as directory:
                with _fixture(Path(directory)) as (host, candidate, _):
                    if selected == "permission":
                        selector = host / str(upgrade.SELECTOR_JSON).lstrip("/")
                        selector.chmod(0o644)
                    elif selected == "symlink":
                        selector = host / str(upgrade.SELECTOR_JSON).lstrip("/")
                        replacement = selector.with_suffix(".link")
                        replacement.symlink_to(selector.name)
                        selector.unlink()
                        replacement.rename(selector)
                    else:
                        helper = candidate / upgrade.CLIENT_PATH
                        helper.write_bytes(helper.read_bytes() + b"\n# substitution\n")
                    with self.assertRaises(
                        (current.CurrentSelectedUpgradeRejected, upgrade.UpgradeRejected)
                    ):
                        current.prepare_plan(
                            target_release=candidate, root=host, unit_state=UNIT_STATE
                        )


if __name__ == "__main__":
    unittest.main()
