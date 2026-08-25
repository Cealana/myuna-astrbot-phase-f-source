#!/usr/bin/env python3
"""Rollback-bound P01-B/P16 incident recovery preserving prior evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import grp
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import time
from typing import Callable, Mapping

import activate_p07_hybrid_external_generation_v1 as p07
import activate_p16_phase1_t2_v1 as p16
from core_release_selector import load_runtime_binding, parse_json_document
from external_context_epoch_v3 import (
    ExternalEpochV3Binding,
    ExternalEpochV3Store,
    SQLITE_SCHEMA as EXTERNAL_EPOCH_SCHEMA,
)
from p07_d_runtime_readiness import content_free_metadata_digest
from p07_d_generation13_release_set import phase_f_selected_target
import telegram_runtime_config as runtime_config_contract
from telegram_runtime_config import CORE_CLIENT_ID
from p01b_p16_successor_contract_v1 import (
    ACTIVATION_RECEIPT_SCHEMA,
    ATTEMPT_SCHEMA,
    EPOCH_ANCHOR_SCHEMA,
    EPOCH_ANCHOR_SCOPE,
    MAX_ATTEMPTS,
    ROLLBACK_RECEIPT_SCHEMA,
    attempt_payload,
    build_selector,
    canonical,
    digest,
    marker_payload,
    selector_digest,
    validate_bundle,
    validate_epoch_anchor_binding,
)
from p16_phase1_t2_contract_v1 import (
    build_selector as build_p16_selector,
    digest as p16_digest,
    validate_attempt_lineage as validate_p16_lineage,
)


LIVE_PLAN_SCHEMA = "myuna.p01b-p16-incident-recovery-live-plan.v1"
PREFLIGHT_STATUS = "ready_for_exactly_one_p01b_incident_recovery_attempt"
ACTIVE_STATUS = "active_waiting_owner_minimal_photo_e2e"
STATE_ROOT = Path("/var/lib/myuna-telegram-gateway/p01b-p16-incident-recovery-v1")
ATTEMPT_ROOT = STATE_ROOT / "attempts"
RECEIPT_ROOT = STATE_ROOT / "receipts"
LOCK_PATH = STATE_ROOT / "ATTEMPTS.lock"
SELECTOR_PATH = STATE_ROOT / "SELECTOR.json"
MARKER_PATH = STATE_ROOT / "ENABLED.json"
BACKUP_ROOT = Path("/var/backups/myuna/p01b-p16-incident-recovery-v1")
LEGACY_STATE_ROOT = Path("/var/lib/myuna-telegram-gateway/p01b-p16-successor-v1")
LEGACY_ATTEMPT = LEGACY_STATE_ROOT / "attempts/attempt-0001.json"
LEGACY_ATTEMPT2 = LEGACY_STATE_ROOT / "attempts/attempt-0002.json"
LEGACY_FAILURE_RECEIPT = LEGACY_STATE_ROOT / "receipts/failure-attempt-0001.json"
P01B_DROPIN = Path(
    "/etc/systemd/system/myuna-telegram-owner-runtime-dev.service.d/"
    "zzzzzzzzzzzzzz-p01b-contextual-visual-v2.conf"
)
P16_RECEIPT_DIGEST = (
    "1d708c6ed927a96cba200cc430af5bfc7137db1316b47f2765f12df9fd5a181b"
)
TELEGRAM_RESTART_DELAY_SECONDS = 5.0
TELEGRAM_ADDITIONAL_STABLE_SECONDS = 5.0
TELEGRAM_CONVERGENCE_SECONDS = (
    TELEGRAM_RESTART_DELAY_SECONDS + TELEGRAM_ADDITIONAL_STABLE_SECONDS
)
PRE_ATTEMPT_CAPTURE_PHASE = "pre_attempt_capture"
POST_ATTEMPT_ROLLBACK_PHASE = "post_attempt_rollback"
_PLAN_BOUNDARIES = {
    "channel": "authenticated-telegram-owner-private-only",
    "core_restart": False,
    "p16_lineage_consumed_or_rewritten": False,
    "p16_marker_selector_history_preserved": True,
    "legacy_p01b_attempt2_consumed_or_relabelled": False,
    "incident_recovery_lineage_is_distinct": True,
    "incident_attempt_budget_reset": False,
    "incident_attempt2_requires_separate_gate": True,
    "p08_or_epoch_mutated": False,
    "qq_mutated": False,
    "model_or_provider_call": False,
    "health_call": False,
    "private_content_read": False,
}
_INVOCATION = re.compile(r"^[0-9a-f]{32}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_EPOCH_FIELDS = {
    "abandoned_delivery_count",
    "blocked_summary_count",
    "delivered_intent_count",
    "epoch_id",
    "max_revision",
    "pending_count",
    "queued_summary_count",
    "release_set_id",
    "schema",
    "selected_revision",
    "summary_count",
    "turn_count",
}
_SERVICE_OBSERVATION_FIELDS = {
    "active_state",
    "binding_digest",
    "exec_start",
    "invocation_id",
    "nrestarts",
    "pid",
    "result",
    "sub_state",
    "working_directory",
}
_READINESS_BASE_FIELDS = {
    "epoch_metadata_digest",
    "generation",
    "release_set_id",
    "runtime_config_digest",
    "schema",
    "selector_digest",
}
_READINESS_PROBE_FIELDS = _READINESS_BASE_FIELDS | {
    "invocation_id",
    "pid",
    "service_invocation_id",
    "service_pid",
}
_READINESS_PRESTART_FIELDS = _READINESS_BASE_FIELDS | {"process_binding_digest"}
_READINESS_CONVERGED_FIELDS = _READINESS_PROBE_FIELDS | {
    "nrestarts",
    "process_binding_digest",
    "service_binding_digest",
    "stable_seconds",
}
_READINESS_IDENTITY_PROJECTION_FIELDS = {
    "epoch_digest_semantics",
    "generation",
    "release_set_id",
    "runtime_config_digest",
    "schema",
    "selector_digest",
    "startup_epoch_metadata_digest",
    "startup_identity_digest",
}
_GENERATION13_PROJECTION_FIELDS = {
    "accepted_epoch_anchor",
    "epoch",
    "generation13_dropin",
    "p07_release_set",
    "p07_selector",
    "p08",
    "readiness",
    "runtime_config",
}
_EPOCH_CHECKPOINT_FIELDS = {
    "abandoned_delivery_count",
    "blocked_summary_count",
    "delivered_intent_count",
    "delivery_in_progress_count",
    "max_revision",
    "metadata_digest",
    "pending_count",
    "queued_summary_count",
    "selected_revision",
    "summary_count",
    "turn_count",
}


class P01BActivationRejected(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        service_alias: str | None = None,
        phase: str | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.service_alias = service_alias
        self.phase = phase


def require(condition: bool, code: str) -> None:
    if not condition:
        raise P01BActivationRejected(code)


def _sha(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def _read_json(path: Path, maximum: int = 8_000_000) -> dict[str, object]:
    raw = p16._read_regular(path, maximum=maximum)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise P01BActivationRejected("json_rejected") from exc
    require(isinstance(value, dict), "json_rejected")
    return value


def _git_identity(root: Path, expected: str) -> dict[str, object]:
    return p16._git_identity(root, expected)


def _load_bundle_context(bundle_root: Path) -> dict[str, object]:
    bundle = validate_bundle(
        _read_json(bundle_root / "P01B_P16_INCIDENT_RECOVERY_BUNDLE.json")
    )
    artifacts: dict[str, Path] = {}
    inventories: dict[str, dict[str, object]] = {}
    for name, record in bundle["artifacts"].items():
        inventory = p16._inventory_document(bundle_root, name)
        require(
            p16_digest("myuna-p16-artifact-inventory-v1", inventory)
            == record["inventory_digest"],
            "artifact_inventory_digest_drifted",
        )
        root = bundle_root / name / str(record["release_digest"])
        p16._validate_artifact(
            root,
            inventory,
            str(record["release_digest"]),
            int(record["file_count"]),
        )
        artifacts[name] = root
        inventories[name] = inventory
    return {"bundle": bundle, "artifacts": artifacts, "inventories": inventories}


_SERVICE_TARGETS = {
    "core": (p16.CORE_SERVICE, False),
    "telegram": (p16.TELEGRAM_SERVICE, False),
    "telegram_socket": (p16.TELEGRAM_SOCKET, True),
    "p08": (p16.P08_SERVICE, False),
    "p08_socket": (p16.P08_SOCKET, True),
}


def _service_rejected(alias: str, phase: str, code: str) -> P01BActivationRejected:
    return P01BActivationRejected(
        f"target_{alias}_{phase}_{code}", service_alias=alias, phase=phase
    )


def _stable_service(alias: str, *, phase: str) -> dict[str, object]:
    require(alias in _SERVICE_TARGETS, "service_alias_rejected")
    unit, socket = _SERVICE_TARGETS[alias]
    try:
        observed = p16._service_projection(unit, socket=socket)
        p16._require_active(observed, socket=socket)
    except p16.P16Phase1T2Rejected as exc:
        raise _service_rejected(alias, phase, str(exc.code)) from exc
    return {
        "active_state": observed["active_state"],
        "sub_state": observed["sub_state"],
        "result": observed["result"],
        "nrestarts": observed["nrestarts"],
        "binding_digest": observed["binding_digest"],
    }


def _service_prestate(*, phase: str = "initial_service_snapshot") -> dict[str, object]:
    return {
        alias: _stable_service(alias, phase=phase) for alias in _SERVICE_TARGETS
    }


def _mount_projection(
    mounts: object, *, expected_plugin_digest: str | None = None
) -> dict[str, object]:
    require(isinstance(mounts, list) and bool(mounts), "container_mounts_rejected")
    semantic_rows: list[dict[str, object]] = []
    identity_rows: list[dict[str, object]] = []
    plugin_bound = expected_plugin_digest is None
    for raw in mounts:
        require(isinstance(raw, dict), "container_mounts_rejected")
        mount_type = raw.get("Type")
        source = raw.get("Source")
        destination = raw.get("Destination")
        read_write = raw.get("RW")
        propagation = raw.get("Propagation", "")
        name = raw.get("Name", "")
        require(
            isinstance(mount_type, str)
            and mount_type in {"bind", "volume", "tmpfs"}
            and isinstance(source, str)
            and isinstance(destination, str)
            and destination.startswith("/")
            and type(read_write) is bool
            and isinstance(propagation, str)
            and isinstance(name, str),
            "container_mounts_rejected",
        )
        semantic = {
            "destination": destination,
            "propagation": propagation,
            "read_only": not read_write,
            "type": mount_type,
        }
        identity = {
            **semantic,
            "name_sha256": _sha(name.encode("utf-8")),
            "source_sha256": _sha(source.encode("utf-8")),
        }
        semantic_rows.append(semantic)
        identity_rows.append(identity)
        if expected_plugin_digest is not None and expected_plugin_digest in source:
            plugin_bound = True
    semantic_rows.sort(key=lambda row: canonical(row))
    identity_rows.sort(key=lambda row: canonical(row))
    require(plugin_bound, "target_plugin_mount_rejected")
    return {
        "semantic_rows": semantic_rows,
        "identity_rows": identity_rows,
        "semantic_digest": digest("myuna-p01b-mount-semantic-v1", semantic_rows),
        "identity_digest": digest("myuna-p01b-mount-identity-v1", identity_rows),
        "candidate_plugin_bound": plugin_bound,
    }


def _container_projection(*, expected_plugin_digest: str | None = None) -> dict[str, object]:
    require(p07.container_healthy(), "container_unhealthy")
    raw = p16._run(
        [
            "/usr/bin/docker",
            "inspect",
            p07.CONTAINER,
            "--format",
            "{{json .Mounts}}",
        ],
        timeout=10,
    )
    try:
        mounts = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise P01BActivationRejected("container_mounts_rejected") from exc
    projection = _mount_projection(
        mounts, expected_plugin_digest=expected_plugin_digest
    )
    return {
        "state": "running_healthy_restart_zero",
        **projection,
    }


def _p16_attempt_projection(
    p16_bundle: Mapping[str, object],
) -> tuple[dict[str, object], list[dict[str, object]]]:
    lineage = validate_p16_lineage(
        p16_bundle["attempt_lineage"], p16._successor_identity(p16_bundle)
    )
    attempts = p16._read_successor_attempts(p16_bundle, lineage)
    activation_attempts = p16._successor_activation_receipt_attempts(
        p16_bundle, lineage
    )
    require(
        len(attempts) == 1 and activation_attempts == {1},
        "predecessor_p16_attempt_drifted",
    )
    matching_receipts: list[dict[str, object]] = []
    matching_paths: list[Path] = []
    for path in sorted(p16.SUCCESSOR_RECEIPT_ROOT.glob("*.json")):
        value = p16._read_canonical(path, maximum=64_000)
        if value.get("attempt_series_id") == lineage["attempt_series_id"]:
            matching_receipts.append(value)
            matching_paths.append(path)
    require(
        len(matching_receipts) == 1
        and matching_receipts[0].get("receipt_digest") == P16_RECEIPT_DIGEST,
        "predecessor_p16_receipt_drifted",
    )
    projections = [p16._file_projection(path) for path in matching_paths]
    return (
        {
            "attempts": 1,
            "maximum_attempts": 2,
            "attempt_series_id": lineage["attempt_series_id"],
            "strategy_digest": digest(
                "myuna-p01b-predecessor-p16-strategy-v1",
                lineage["strategy_id"],
            ),
            "terminal_attempt_digest": attempts[0]["attempt_digest"],
            "activation_receipt_digest": P16_RECEIPT_DIGEST,
            "activation_receipt_projection": projections[0],
        },
        attempts,
    )


def _p16_projection(
    predecessor_root: Path,
    expected: Mapping[str, object],
) -> dict[str, object]:
    context = p16._load_bundle_context(predecessor_root)
    bundle = context["bundle"]
    manifest = predecessor_root / "P16_PHASE1_T2_BUNDLE.json"
    require(
        bundle["bundle_digest"] == expected["bundle_digest"]
        and _sha(manifest.read_bytes()) == expected["bundle_manifest_sha256"],
        "predecessor_p16_bundle_drifted",
    )
    require(bundle["artifacts"] == expected["artifacts"], "predecessor_p16_artifact_drifted")
    p16_selector = build_p16_selector(bundle)
    live_selector = p16._read_canonical(p16.INCIDENT_HISTORY_SELECTOR, maximum=64_000)
    selector_value_digest = p16_digest(
        "myuna-p16-incident-history-selector-v1", p16_selector
    )
    live_marker = p16._read_canonical(p16.INCIDENT_HISTORY_MARKER, maximum=4096)
    require(live_selector == p16_selector, "predecessor_p16_selector_drifted")
    require(
        live_marker
        == json.loads(
            p16._marker_payload(str(bundle["bundle_digest"]), selector_value_digest)
        ),
        "predecessor_p16_marker_drifted",
    )
    attempts, _rows = _p16_attempt_projection(bundle)
    require(
        attempts["attempt_series_id"] == expected["attempt_series_id"]
        and attempts["strategy_digest"] == expected["strategy_digest"]
        and attempts["activation_receipt_digest"]
        == expected["activation_receipt_digest"],
        "predecessor_p16_lineage_drifted",
    )
    telegram = p16._service_projection(p16.TELEGRAM_SERVICE)
    telegram_user = pwd.getpwnam(p16.TELEGRAM_RUNTIME_USER)
    history = p16._history_projection(telegram_user.pw_uid, telegram_user.pw_gid)
    return {
        "bundle_manifest": p16._file_projection(manifest),
        "selector": p16._file_projection(p16.INCIDENT_HISTORY_SELECTOR),
        "marker": p16._file_projection(p16.INCIDENT_HISTORY_MARKER),
        "dropin": p16._file_projection(p16.P16_TELEGRAM_DROPIN),
        "attempt": attempts,
        "history": history,
    }


def _typed_epoch_projection(
    metadata: object,
    *,
    expected_epoch_id: str,
    expected_release_set_id: str,
    expected_schema: str = EXTERNAL_EPOCH_SCHEMA,
) -> dict[str, object]:
    require(
        isinstance(metadata, dict) and set(metadata) == _EPOCH_FIELDS,
        "epoch_metadata_rejected",
    )
    for field in _EPOCH_FIELDS - {"epoch_id", "release_set_id", "schema"}:
        require(
            type(metadata[field]) is int and metadata[field] >= 0,
            "epoch_metadata_rejected",
        )
    for field in ("epoch_id", "release_set_id", "schema"):
        require(
            isinstance(metadata[field], str) and bool(metadata[field]),
            "epoch_metadata_rejected",
        )
    require(
        metadata["epoch_id"] == expected_epoch_id
        and metadata["release_set_id"] == expected_release_set_id
        and metadata["schema"] == expected_schema,
        "epoch_identity_rejected",
    )
    require(
        metadata["selected_revision"] == metadata["max_revision"]
        and metadata["selected_revision"]
        == metadata["turn_count"] + metadata["summary_count"]
        and metadata["turn_count"] == metadata["delivered_intent_count"]
        and metadata["pending_count"] == 0
        and metadata["queued_summary_count"] == 0
        and metadata["abandoned_delivery_count"] == 0
        and metadata["blocked_summary_count"] == 0,
        "epoch_not_quiescent",
    )
    normalized = {key: metadata[key] for key in sorted(metadata)}
    identity = {
        "epoch_id": normalized["epoch_id"],
        "release_set_id": normalized["release_set_id"],
        "schema": normalized["schema"],
    }
    return {
        "metadata": normalized,
        "metadata_digest": content_free_metadata_digest(normalized),
        "identity_digest": digest(
            "myuna-p01b-current-epoch-identity-v1", identity
        ),
        "delivery_in_progress_count": normalized["pending_count"],
        "quiescent": True,
    }


def _validate_epoch_anchor(value: object) -> dict[str, object]:
    require(
        isinstance(value, dict)
        and set(value)
        == {
            "accepted_checkpoint",
            "anchor_digest",
            "content_free",
            "owner_decision_scope",
            "private_content_included",
            "schema",
            "source_handoff_sha256",
            "status",
        },
        "epoch_anchor_rejected",
    )
    checkpoint = value["accepted_checkpoint"]
    require(
        isinstance(checkpoint, dict)
        and set(checkpoint) == _EPOCH_CHECKPOINT_FIELDS,
        "epoch_anchor_rejected",
    )
    for field in _EPOCH_CHECKPOINT_FIELDS - {"metadata_digest"}:
        require(
            type(checkpoint[field]) is int and checkpoint[field] >= 0,
            "epoch_anchor_rejected",
        )
    require(
        isinstance(checkpoint["metadata_digest"], str)
        and _DIGEST.fullmatch(checkpoint["metadata_digest"]) is not None
        and checkpoint["selected_revision"] == checkpoint["max_revision"]
        and checkpoint["selected_revision"]
        == checkpoint["turn_count"] + checkpoint["summary_count"]
        and checkpoint["turn_count"] == checkpoint["delivered_intent_count"]
        and all(
            checkpoint[field] == 0
            for field in (
                "pending_count",
                "queued_summary_count",
                "abandoned_delivery_count",
                "blocked_summary_count",
                "delivery_in_progress_count",
            )
        )
        and value["schema"] == EPOCH_ANCHOR_SCHEMA
        and value["status"] == "owner_accepted"
        and value["owner_decision_scope"] == EPOCH_ANCHOR_SCOPE
        and value["content_free"] is True
        and value["private_content_included"] is False
        and isinstance(value["source_handoff_sha256"], str)
        and _DIGEST.fullmatch(value["source_handoff_sha256"]) is not None,
        "epoch_anchor_rejected",
    )
    unsigned = {key: value[key] for key in value if key != "anchor_digest"}
    require(
        value["anchor_digest"]
        == digest("myuna.p01b-p16-incident-recovery-epoch-anchor.v1", unsigned),
        "epoch_anchor_digest_rejected",
    )
    return dict(value)


def _load_epoch_anchor(path: Path) -> dict[str, object]:
    try:
        value = p16._read_canonical(path, maximum=16_000)
    except BaseException as exc:
        raise P01BActivationRejected("epoch_anchor_rejected") from exc
    return _validate_epoch_anchor(value)


def _require_bundle_epoch_anchor(
    bundle: Mapping[str, object],
    anchor: Mapping[str, object],
    *,
    source_path: Path | None = None,
) -> dict[str, object]:
    validated_anchor = _validate_epoch_anchor(anchor)
    try:
        binding = validate_epoch_anchor_binding(bundle.get("epoch_anchor"))
    except BaseException as exc:
        raise P01BActivationRejected("bundle_epoch_anchor_rejected") from exc
    document = {
        key: binding[key]
        for key in binding
        if key != "anchor_file_sha256"
    }
    require(document == validated_anchor, "bundle_epoch_anchor_rejected")
    if source_path is not None:
        try:
            raw = source_path.read_bytes()
        except BaseException as exc:
            raise P01BActivationRejected("bundle_epoch_anchor_rejected") from exc
        require(
            _sha(raw) == binding["anchor_file_sha256"],
            "bundle_epoch_anchor_rejected",
        )
    return validated_anchor


def _epoch_checkpoint(epoch: Mapping[str, object]) -> dict[str, object]:
    metadata = epoch["metadata"]
    return {
        "abandoned_delivery_count": metadata["abandoned_delivery_count"],
        "blocked_summary_count": metadata["blocked_summary_count"],
        "delivered_intent_count": metadata["delivered_intent_count"],
        "delivery_in_progress_count": epoch["delivery_in_progress_count"],
        "max_revision": metadata["max_revision"],
        "metadata_digest": epoch["metadata_digest"],
        "pending_count": metadata["pending_count"],
        "queued_summary_count": metadata["queued_summary_count"],
        "selected_revision": metadata["selected_revision"],
        "summary_count": metadata["summary_count"],
        "turn_count": metadata["turn_count"],
    }


def _require_epoch_anchor(
    epoch: Mapping[str, object], anchor: Mapping[str, object]
) -> None:
    validated = _validate_epoch_anchor(anchor)
    require(
        _epoch_checkpoint(epoch) == validated["accepted_checkpoint"],
        "epoch_anchor_mismatch",
    )


def _validate_runtime_readiness_base(
    readiness: Mapping[str, object],
    release_set: object,
    *,
    allowed_fields: set[str],
) -> None:
    require(
        isinstance(readiness, Mapping) and set(readiness) == allowed_fields,
        "startup_readiness_shape_rejected",
    )
    require(
        readiness["schema"] == "myuna.p07-d-runtime-readiness.v1"
        and type(readiness["generation"]) is int
        and readiness["generation"] == 13
        and readiness["release_set_id"] == release_set.release_set_id
        and readiness["selector_digest"] == release_set.selector["digest"]
        and readiness["runtime_config_digest"]
        == release_set.runtime_config["digest"],
        "startup_readiness_identity_rejected",
    )
    for field in (
        "release_set_id",
        "selector_digest",
        "runtime_config_digest",
        "epoch_metadata_digest",
    ):
        require(
            isinstance(readiness[field], str)
            and _DIGEST.fullmatch(str(readiness[field])) is not None,
            "startup_readiness_type_rejected",
        )
    if allowed_fields == _READINESS_PRESTART_FIELDS:
        require(
            isinstance(readiness["process_binding_digest"], str)
            and _DIGEST.fullmatch(str(readiness["process_binding_digest"]))
            is not None,
            "startup_readiness_type_rejected",
        )
    if (
        allowed_fields == _READINESS_PROBE_FIELDS
        or allowed_fields == _READINESS_CONVERGED_FIELDS
    ):
        for field in ("pid", "service_pid"):
            require(
                type(readiness[field]) is int and int(readiness[field]) > 0,
                "startup_readiness_type_rejected",
            )
        for field in ("invocation_id", "service_invocation_id"):
            require(
                isinstance(readiness[field], str)
                and _INVOCATION.fullmatch(str(readiness[field])) is not None,
                "startup_readiness_type_rejected",
            )
    if allowed_fields == _READINESS_CONVERGED_FIELDS:
        for field in ("process_binding_digest", "service_binding_digest"):
            require(
                isinstance(readiness[field], str)
                and _DIGEST.fullmatch(str(readiness[field])) is not None,
                "startup_readiness_type_rejected",
            )
        require(
            readiness["pid"] == readiness["service_pid"]
            and readiness["invocation_id"] == readiness["service_invocation_id"]
            and type(readiness["nrestarts"]) is int
            and readiness["nrestarts"] == 0
            and type(readiness["stable_seconds"]) in {int, float}
            and readiness["stable_seconds"] >= TELEGRAM_CONVERGENCE_SECONDS,
            "startup_readiness_convergence_rejected",
        )


def _readiness_identity_projection(
    readiness: Mapping[str, object], release_set: object
) -> dict[str, object]:
    fields = set(readiness)
    require(
        fields == _READINESS_PRESTART_FIELDS
        or fields == _READINESS_PROBE_FIELDS
        or fields == _READINESS_CONVERGED_FIELDS,
        "startup_readiness_shape_rejected",
    )
    _validate_runtime_readiness_base(
        readiness, release_set, allowed_fields=fields
    )
    identity = {
        key: readiness[key]
        for key in sorted(_READINESS_BASE_FIELDS - {"epoch_metadata_digest"})
    }
    return {
        **identity,
        "startup_identity_digest": digest(
            "myuna.p01b-startup-readiness-identity-v1", identity
        ),
        "startup_epoch_metadata_digest": readiness["epoch_metadata_digest"],
        "epoch_digest_semantics": "startup_observation_only_not_current_epoch_gate",
    }


def _query_epoch_metadata(release_set: object) -> dict[str, object]:
    snapshot = runtime_config_contract.load_protected_runtime_config_snapshot()
    config = snapshot.config
    return ExternalEpochV3Store.inspect_existing_metadata(
        release_set.epoch["database_path"],
        epoch_id=release_set.epoch["epoch_id"],
        release_set_id=release_set.release_set_id,
        binding=ExternalEpochV3Binding(
            channel_kind=config.channel_kind,
            client_id=CORE_CLIENT_ID,
            principal_id=config.principal_id,
            namespace_id=config.namespace_id,
        ),
        expected_uid=release_set.epoch["uid"],
        expected_gid=release_set.epoch["gid"],
    )


def _quiescent_epoch_projection(
    release_set: object,
    *,
    reader: Callable[[object], dict[str, object]] = _query_epoch_metadata,
    sleep: Callable[[float], None] = time.sleep,
    settle_seconds: float = 0.25,
) -> dict[str, object]:
    expected_epoch_id = str(release_set.epoch["epoch_id"])
    expected_release_set_id = str(release_set.release_set_id)
    first = _typed_epoch_projection(
        reader(release_set),
        expected_epoch_id=expected_epoch_id,
        expected_release_set_id=expected_release_set_id,
    )
    sleep(settle_seconds)
    second = _typed_epoch_projection(
        reader(release_set),
        expected_epoch_id=expected_epoch_id,
        expected_release_set_id=expected_release_set_id,
    )
    require(first == second, "epoch_not_quiescent")
    return first


def _runtime_readiness_probe(
    release_set: object, telegram: Mapping[str, object]
) -> dict[str, object]:
    identity = pwd.getpwnam(p16.TELEGRAM_RUNTIME_USER)
    receipt = p16.inspect_runtime_readiness(
        p16.readiness_path(p16.RELEASE_SET_EPOCH_PATH),
        expected_uid=identity.pw_uid,
        expected_gid=identity.pw_gid,
        expected_generation=13,
        expected_release_set_id=release_set.release_set_id,
        expected_epoch_id=release_set.epoch["epoch_id"],
        expected_database_path=p16.RELEASE_SET_EPOCH_PATH,
        expected_selector_digest=release_set.selector["digest"],
        expected_runtime_config_digest=release_set.runtime_config["digest"],
    )
    return {
        "schema": "myuna.p07-d-runtime-readiness.v1",
        "generation": receipt.generation,
        "release_set_id": receipt.release_set_id,
        "selector_digest": receipt.selector_digest,
        "runtime_config_digest": receipt.runtime_config_digest,
        "epoch_metadata_digest": receipt.epoch_metadata_digest,
        "pid": receipt.pid,
        "invocation_id": receipt.invocation_id,
        "service_pid": telegram["pid"],
        "service_invocation_id": telegram["invocation_id"],
    }


def _wait_telegram_convergence(
    release_set: object,
    *,
    expected_binding_digest: str,
    observe: Callable[[], Mapping[str, object]] | None = None,
    readiness_probe: Callable[[object, Mapping[str, object]], Mapping[str, object]] = _runtime_readiness_probe,
    timeout_seconds: float = 120.0,
    poll_seconds: float = 0.25,
    stable_seconds: float = TELEGRAM_CONVERGENCE_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    require(
        timeout_seconds >= stable_seconds >= TELEGRAM_CONVERGENCE_SECONDS
        and 0 < poll_seconds <= 1,
        "telegram_convergence_window_rejected",
    )
    observe = observe or (lambda: p16._service_projection(p16.TELEGRAM_SERVICE))
    started = monotonic()
    deadline = started + timeout_seconds
    stable_since: float | None = None
    stable_identity: tuple[int, str, str] | None = None
    last_transient = "service_not_observed"
    while monotonic() <= deadline:
        now = monotonic()
        try:
            current = dict(observe())
        except p16.P16Phase1T2Rejected as exc:
            last_transient = str(exc.code)
            if last_transient != "target_service_inactive":
                raise _service_rejected(
                    "telegram", "telegram_readiness_stability", last_transient
                ) from exc
            current = {}
        except P01BActivationRejected:
            raise
        except BaseException as exc:
            raise _service_rejected(
                "telegram",
                "telegram_readiness_stability",
                "service_observation_rejected",
            ) from exc
        if current:
            if set(current) != _SERVICE_OBSERVATION_FIELDS:
                raise _service_rejected(
                    "telegram",
                    "telegram_readiness_stability",
                    "service_observation_shape_rejected",
                )
            if (
                not isinstance(current["active_state"], str)
                or not isinstance(current["sub_state"], str)
                or not isinstance(current["result"], str)
                or type(current["nrestarts"]) is not int
                or type(current["pid"]) is not int
                or not isinstance(current["invocation_id"], str)
                or not isinstance(current["binding_digest"], str)
                or _DIGEST.fullmatch(str(current["binding_digest"])) is None
                or not isinstance(current["exec_start"], str)
                or not isinstance(current["working_directory"], str)
            ):
                raise _service_rejected(
                    "telegram",
                    "telegram_readiness_stability",
                    "service_observation_type_rejected",
                )
            if current["result"] not in {"", "success"}:
                raise _service_rejected(
                    "telegram", "telegram_readiness_stability", "service_failed"
                )
            if current["nrestarts"] != 0:
                raise _service_rejected(
                    "telegram",
                    "telegram_readiness_stability",
                    "service_restart_drifted",
                )
        active = (
            current.get("active_state") == "active"
            and current.get("sub_state") == "running"
            and type(current.get("pid")) is int
            and int(current.get("pid", 0)) > 0
            and isinstance(current.get("invocation_id"), str)
            and _INVOCATION.fullmatch(str(current.get("invocation_id"))) is not None
        )
        if active:
            if current.get("binding_digest") != expected_binding_digest:
                raise _service_rejected(
                    "telegram", "telegram_readiness_stability", "binding_drifted"
                )
            identity = (
                int(current["pid"]),
                str(current["invocation_id"]),
                str(current["binding_digest"]),
            )
            try:
                receipt = dict(readiness_probe(release_set, current))
                _validate_runtime_readiness_base(
                    receipt,
                    release_set,
                    allowed_fields=_READINESS_PROBE_FIELDS,
                )
            except p16.RuntimeReadinessRejected as exc:
                if str(exc.code) != "runtime_readiness_absent":
                    raise _service_rejected(
                        "telegram",
                        "telegram_readiness_stability",
                        str(exc.code),
                    ) from exc
                last_transient = "readiness_absent"
                receipt = {}
            except P01BActivationRejected as exc:
                raise _service_rejected(
                    "telegram", "telegram_readiness_stability", str(exc.code)
                ) from exc
            except BaseException as exc:
                raise _service_rejected(
                    "telegram",
                    "telegram_readiness_stability",
                    "readiness_probe_rejected",
                ) from exc
            ready = (
                receipt.get("pid") == identity[0]
                and receipt.get("invocation_id") == identity[1]
                and receipt.get("service_pid") == identity[0]
                and receipt.get("service_invocation_id") == identity[1]
            )
            if ready:
                now = monotonic()
                if stable_identity != identity:
                    if stable_identity is not None and stable_since is not None:
                        raise _service_rejected(
                            "telegram",
                            "telegram_readiness_stability",
                            "identity_drifted_after_readiness",
                        )
                    stable_identity = identity
                    stable_since = now
                if stable_since is not None and now - stable_since >= stable_seconds:
                    return {
                        **receipt,
                        "process_binding_digest": digest(
                            "myuna-p01b-telegram-convergence-process-v1",
                            {"pid": identity[0], "invocation_id": identity[1]},
                        ),
                        "service_binding_digest": identity[2],
                        "nrestarts": 0,
                        "stable_seconds": stable_seconds,
                    }
            else:
                if receipt:
                    last_transient = "readiness_process_mismatch"
                stable_since = None
                stable_identity = None
        else:
            last_transient = "service_not_active"
            stable_since = None
            stable_identity = None
        sleep(poll_seconds)
    raise _service_rejected(
        "telegram",
        "telegram_readiness_stability",
        f"convergence_timeout_{last_transient}",
    )


def _generation13_projection(
    predecessor_bundle: Mapping[str, object],
    *,
    accepted_epoch_anchor: Mapping[str, object],
    readiness_override: Mapping[str, object] | None = None,
) -> dict[str, object]:
    compatibility = predecessor_bundle["compatibility"]
    base = predecessor_bundle["generation13_base"]
    release_set = p16._p07_snapshot(str(compatibility["p07_release_set_id"]))
    p08 = p16._p08_selection(
        str(base["p08_release_digest"]), str(compatibility["p08_plan_digest"])
    )
    if readiness_override is None:
        telegram = p16._service_projection(p16.TELEGRAM_SERVICE)
        try:
            readiness = p16._readiness_projection(release_set, telegram)
        except p16.P16Phase1T2Rejected as exc:
            raise _service_rejected(
                "telegram", "initial_service_snapshot", str(exc.code)
            ) from exc
    else:
        readiness = dict(readiness_override)
    readiness_identity = _readiness_identity_projection(readiness, release_set)
    epoch = _quiescent_epoch_projection(release_set)
    _require_epoch_anchor(epoch, accepted_epoch_anchor)
    return {
        "p07_release_set": p16._file_projection(p16.RELEASE_SET_PATH),
        "p07_selector": p16._file_projection(p16.P07_SELECTOR),
        "runtime_config": p16._file_projection(p16.OWNER_RUNTIME_CONFIG),
        "generation13_dropin": p16._file_projection(p16.GENERATION13_TELEGRAM_DROPIN),
        "p08": p08,
        "readiness": readiness_identity,
        "epoch": epoch,
        "accepted_epoch_anchor": _validate_epoch_anchor(accepted_epoch_anchor),
    }


def _restart_stable_generation13_projection(
    projection: Mapping[str, object],
    *,
    require_fresh_startup_epoch: bool,
) -> dict[str, object]:
    require(
        isinstance(projection, Mapping)
        and set(projection) == _GENERATION13_PROJECTION_FIELDS,
        "generation13_projection_shape_rejected",
    )
    readiness = projection["readiness"]
    epoch = projection["epoch"]
    require(
        isinstance(readiness, Mapping)
        and set(readiness) == _READINESS_IDENTITY_PROJECTION_FIELDS
        and isinstance(epoch, Mapping)
        and set(epoch)
        == {
            "delivery_in_progress_count",
            "identity_digest",
            "metadata",
            "metadata_digest",
            "quiescent",
        }
        and isinstance(epoch.get("metadata"), Mapping),
        "generation13_readiness_shape_rejected",
    )
    epoch_metadata = epoch["metadata"]
    require(
        set(epoch_metadata) == _EPOCH_FIELDS,
        "generation13_epoch_shape_rejected",
    )
    typed_epoch = _typed_epoch_projection(
        dict(epoch_metadata),
        expected_epoch_id=str(epoch_metadata.get("epoch_id", "")),
        expected_release_set_id=str(epoch_metadata.get("release_set_id", "")),
        expected_schema=str(epoch_metadata.get("schema", "")),
    )
    require(typed_epoch == epoch, "generation13_epoch_projection_rejected")
    require(
        readiness["schema"] == "myuna.p07-d-runtime-readiness.v1"
        and type(readiness["generation"]) is int
        and readiness["generation"] == 13
        and readiness["epoch_digest_semantics"]
        == "startup_observation_only_not_current_epoch_gate",
        "generation13_readiness_identity_rejected",
    )
    for field in (
        "release_set_id",
        "runtime_config_digest",
        "selector_digest",
        "startup_epoch_metadata_digest",
        "startup_identity_digest",
    ):
        require(
            isinstance(readiness[field], str)
            and _DIGEST.fullmatch(str(readiness[field])) is not None,
            "generation13_readiness_type_rejected",
        )
    if require_fresh_startup_epoch:
        require(
            readiness["startup_epoch_metadata_digest"] == epoch["metadata_digest"],
            "post_restart_startup_epoch_drifted",
        )
    stable_readiness = {
        key: readiness[key]
        for key in sorted(
            _READINESS_IDENTITY_PROJECTION_FIELDS
            - {"startup_epoch_metadata_digest"}
        )
    }
    return {**projection, "readiness": stable_readiness}


def _require_post_restart_generation13_convergence(
    current: Mapping[str, object],
    expected: Mapping[str, object],
    *,
    code: str,
) -> None:
    require(
        _restart_stable_generation13_projection(
            current, require_fresh_startup_epoch=True
        )
        == _restart_stable_generation13_projection(
            expected, require_fresh_startup_epoch=False
        ),
        code,
    )


def _selected_components() -> dict[str, str]:
    binding = load_runtime_binding(parse_json_document(p16.CORE_BINDING.read_bytes()))
    config = p16._read_canonical_legacy(p16.TELEGRAM_CONFIG, maximum=64_000)
    plugin = config.get("gateway_release")
    require(isinstance(plugin, str), "plugin_selection_rejected")
    service = p16._service_projection(p16.TELEGRAM_SERVICE)
    return {
        "core": binding.selected_release.tree_sha256,
        "plugin": plugin,
        "runtime_binding_digest": str(service["binding_digest"]),
        "runtime_execstart": str(service["exec_start"]),
    }


def _verify_legacy_incident(bundle: Mapping[str, object]) -> dict[str, object]:
    incident = bundle["incident_predecessor"]
    require(p16._absent(LEGACY_ATTEMPT2), "legacy_p01b_attempt2_present")
    attempt = _read_json(LEGACY_ATTEMPT, maximum=4096)
    receipt = _read_json(LEGACY_FAILURE_RECEIPT, maximum=64_000)
    require(
        _sha(LEGACY_ATTEMPT.read_bytes()) == incident["legacy_attempt_file_sha256"]
        and _sha(LEGACY_FAILURE_RECEIPT.read_bytes())
        == incident["legacy_failure_receipt_file_sha256"],
        "legacy_incident_evidence_drifted",
    )
    require(
        attempt.get("attempt") == 1
        and attempt.get("maximum_attempts") == 2
        and attempt.get("content_free") is True
        and receipt.get("attempt") == 1
        and receipt.get("status") == incident["legacy_failure_status"]
        and receipt.get("failure_stage") == incident["legacy_failure_stage"]
        and receipt.get("failure_gate") == incident["legacy_failure_gate"]
        and receipt.get("rollback") == incident["legacy_rollback"]
        and receipt.get("rollback_gate") == incident["legacy_rollback_gate"]
        and receipt.get("p16_attempt2_consumed") is False
        and receipt.get("p16_lineage_rewritten") is False
        and all(
            receipt.get(field) is False
            for field in (
                "private_content_read",
                "channel_called",
                "model_called",
                "provider_called",
                "health_called",
            )
        ),
        "legacy_incident_evidence_rejected",
    )
    return {
        "attempt": 1,
        "attempt_file_sha256": incident["legacy_attempt_file_sha256"],
        "attempt2_prohibited": True,
        "failure_receipt_file_sha256": incident[
            "legacy_failure_receipt_file_sha256"
        ],
        "failure_status": incident["legacy_failure_status"],
    }


def _validate_recovery_attempt(
    value: object,
    *,
    file_sha256: str,
    recovery: Mapping[str, object],
) -> dict[str, object]:
    require(isinstance(value, dict), "recovery_attempt_rejected")
    required = {
        "attempt",
        "attempt_digest",
        "attempt_series_id",
        "bundle_digest",
        "content_free",
        "lineage_digest",
        "live_plan_digest",
        "maximum_attempts",
        "previous_attempt_digest",
        "recorded_at",
        "schema",
        "strategy_id",
    }
    require(set(value) == required, "recovery_attempt_rejected")
    unsigned = {key: value[key] for key in required - {"attempt_digest"}}
    require(
        file_sha256 == recovery["attempt_file_sha256"]
        and value["schema"] == ATTEMPT_SCHEMA
        and value["attempt"] == recovery["attempt"] == 1
        and value["maximum_attempts"] == recovery["maximum_attempts"] == MAX_ATTEMPTS
        and value["bundle_digest"] == recovery["bundle_digest"]
        and value["attempt_series_id"] == recovery["attempt_series_id"]
        and value["strategy_id"] == recovery["strategy_id"]
        and value["lineage_digest"] == recovery["lineage_digest"]
        and value["live_plan_digest"] == recovery["live_plan_digest"]
        and value["previous_attempt_digest"] is None
        and isinstance(value["recorded_at"], str)
        and value["recorded_at"].endswith("Z")
        and value["content_free"] is True
        and value["attempt_digest"] == recovery["attempt_digest"]
        and value["attempt_digest"]
        == digest("myuna-p01b-p16-incident-recovery-attempt-v1", unsigned),
        "recovery_attempt_rejected",
    )
    return dict(value)


def _verify_recovery_incident(
    bundle: Mapping[str, object],
    attempt: Mapping[str, object],
) -> dict[str, object]:
    recovery = bundle["recovery_predecessor"]
    failure_receipt = RECEIPT_ROOT / "failure-attempt-0001.json"
    p16._require_root_file(
        failure_receipt,
        mode=0o600,
        code="recovery_failure_receipt_rejected",
    )
    receipt_bytes = failure_receipt.read_bytes()
    receipt = _read_json(failure_receipt, maximum=64_000)
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    require(
        attempt["attempt_digest"] == recovery["attempt_digest"]
        and _sha(receipt_bytes) == recovery["failure_receipt_file_sha256"]
        and receipt.get("receipt_digest") == recovery["failure_receipt_digest"]
        and receipt.get("receipt_digest")
        == digest("myuna-p01b-p16-incident-recovery-receipt-v1", unsigned)
        and receipt.get("schema") == ACTIVATION_RECEIPT_SCHEMA
        and receipt.get("status") == recovery["failure_status"]
        and receipt.get("attempt") == recovery["attempt"]
        and receipt.get("bundle_digest") == recovery["bundle_digest"]
        and receipt.get("live_plan_digest") == recovery["live_plan_digest"]
        and receipt.get("failure_stage") == recovery["failure_stage"]
        and receipt.get("failure_gate") == recovery["failure_gate"]
        and receipt.get("failure_service_alias") == recovery["failure_service_alias"]
        and receipt.get("failure_phase") == recovery["failure_phase"]
        and receipt.get("rollback") == recovery["rollback"]
        and receipt.get("rollback_gate") == recovery["rollback_gate"]
        and all(
            receipt.get(field) is False
            for field in (
                "p16_attempt2_consumed",
                "legacy_p01b_attempt2_consumed",
                "legacy_p01b_attempt2_relabelled",
                "p16_lineage_rewritten",
                "private_content_read",
                "channel_called",
                "model_called",
                "provider_called",
                "health_called",
            )
        ),
        "recovery_failure_receipt_rejected",
    )
    return {
        "attempt": recovery["attempt"],
        "attempt_digest": recovery["attempt_digest"],
        "attempt_file_sha256": recovery["attempt_file_sha256"],
        "attempt_series_id": recovery["attempt_series_id"],
        "attempt2_authorized": False,
        "failure_receipt_digest": recovery["failure_receipt_digest"],
        "failure_receipt_file_sha256": recovery["failure_receipt_file_sha256"],
        "failure_status": recovery["failure_status"],
    }


def _attempt_rows(bundle: Mapping[str, object]) -> list[dict[str, object]]:
    if p16._absent(STATE_ROOT):
        return []
    p16._require_root_directory(STATE_ROOT, mode=0o700, code="attempt_state_rejected")
    allowed_root = {"attempts", "receipts", "ATTEMPTS.lock", "SELECTOR.json", "ENABLED.json"}
    names = {path.name for path in STATE_ROOT.iterdir()}
    require(names.issubset(allowed_root), "attempt_state_rejected")
    if p16._absent(ATTEMPT_ROOT):
        return []
    p16._require_root_directory(ATTEMPT_ROOT, mode=0o700, code="attempt_state_rejected")
    names = {path.name for path in ATTEMPT_ROOT.iterdir()}
    expected = {f"attempt-{number:04d}.json" for number in range(1, len(names) + 1)}
    require(names == expected and len(names) <= MAX_ATTEMPTS, "attempt_state_partial")
    rows: list[dict[str, object]] = []
    previous: str | None = None
    for number in range(1, len(names) + 1):
        path = ATTEMPT_ROOT / f"attempt-{number:04d}.json"
        p16._require_root_file(path, mode=0o600, code="attempt_state_rejected")
        raw = path.read_bytes()
        value = _read_json(path, maximum=4096)
        if number == 1:
            value = _validate_recovery_attempt(
                value,
                file_sha256=_sha(raw),
                recovery=bundle["recovery_predecessor"],
            )
        else:
            expected_value = attempt_payload(
                bundle,
                attempt=number,
                live_plan_digest=str(value.get("live_plan_digest", "")),
                previous_attempt_digest=previous,
                recorded_at=str(value.get("recorded_at", "")),
            )
            require(value == expected_value, "attempt_state_rejected")
        previous = str(value["attempt_digest"])
        rows.append(value)
    return rows


def _require_attempt_phase_lineage(
    bundle: Mapping[str, object],
    attempts: list[dict[str, object]],
    *,
    phase: str,
    rollback_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    require(
        phase in {PRE_ATTEMPT_CAPTURE_PHASE, POST_ATTEMPT_ROLLBACK_PHASE},
        "attempt_phase_rejected",
    )
    lineage = bundle.get("lineage")
    recovery = bundle.get("recovery_predecessor")
    require(
        isinstance(lineage, Mapping)
        and isinstance(recovery, Mapping)
        and lineage.get("consumed_incident_attempts") == 1
        and lineage.get("remaining_incident_attempts") == 1
        and lineage.get("maximum_attempts") == MAX_ATTEMPTS == 2
        and lineage.get("attempt_budget_reset") is False
        and lineage.get("incident_attempt2_authorized") is False
        and lineage.get("legacy_p01b_attempt2_prohibited") is True
        and lineage.get("predecessor_p16_attempts") == 1
        and lineage.get("predecessor_p16_unused_attempt_preserved") is True,
        "recovery_attempt_lineage_rejected",
    )
    require(
        isinstance(attempts, list)
        and bool(attempts)
        and isinstance(attempts[0], dict)
        and attempts[0].get("attempt") == 1
        and attempts[0].get("attempt_digest") == recovery.get("attempt_digest")
        and attempts[0].get("attempt_series_id")
        == lineage.get("attempt_series_id")
        == recovery.get("attempt_series_id")
        and attempts[0].get("bundle_digest") == recovery.get("bundle_digest")
        and attempts[0].get("previous_attempt_digest") is None,
        "recovery_attempt_lineage_rejected",
    )
    if phase == PRE_ATTEMPT_CAPTURE_PHASE:
        require(
            rollback_plan is None and len(attempts) == 1,
            "recovery_attempt_lineage_rejected",
        )
        return {
            "phase": phase,
            "attempts": 1,
            "next_attempt": 2,
            "maximum_attempts": MAX_ATTEMPTS,
        }

    required_plan = {
        "accepted_epoch_anchor",
        "attempt_series_id",
        "boundaries",
        "bundle_digest",
        "executor_sha256",
        "live_plan_digest",
        "maximum_attempts",
        "next_attempt",
        "prestate",
        "schema",
        "status",
    }
    require(
        isinstance(rollback_plan, Mapping)
        and set(rollback_plan) == required_plan,
        "rollback_attempt_plan_rejected",
    )
    unsigned_plan = {
        key: rollback_plan[key]
        for key in rollback_plan
        if key != "live_plan_digest"
    }
    prestate = rollback_plan["prestate"]
    require(
        rollback_plan["schema"] == LIVE_PLAN_SCHEMA
        and rollback_plan["status"] == PREFLIGHT_STATUS
        and rollback_plan["bundle_digest"] == bundle.get("bundle_digest")
        and rollback_plan["attempt_series_id"] == lineage.get("attempt_series_id")
        and rollback_plan["next_attempt"] == 2
        and rollback_plan["maximum_attempts"] == MAX_ATTEMPTS
        and isinstance(rollback_plan["executor_sha256"], str)
        and _DIGEST.fullmatch(str(rollback_plan["executor_sha256"])) is not None
        and rollback_plan["boundaries"] == _PLAN_BOUNDARIES
        and isinstance(prestate, Mapping)
        and prestate.get("p01b_attempts") == 1
        and rollback_plan["accepted_epoch_anchor"]
        == prestate.get("accepted_epoch_anchor")
        and _require_bundle_epoch_anchor(
            bundle, rollback_plan["accepted_epoch_anchor"]
        )
        == rollback_plan["accepted_epoch_anchor"]
        and rollback_plan["live_plan_digest"]
        == digest(
            "myuna-p01b-p16-incident-recovery-live-plan-v1", unsigned_plan
        ),
        "rollback_attempt_plan_rejected",
    )
    _normalized_recovery_prestate(
        prestate, require_fresh_startup_epoch=False
    )
    require(len(attempts) == MAX_ATTEMPTS, "recovery_attempt_lineage_rejected")
    second = attempts[1]
    require(isinstance(second, dict), "recovery_attempt_lineage_rejected")
    expected_second = attempt_payload(
        bundle,
        attempt=2,
        live_plan_digest=str(rollback_plan["live_plan_digest"]),
        previous_attempt_digest=str(attempts[0]["attempt_digest"]),
        recorded_at=str(second.get("recorded_at", "")),
    )
    require(
        second == expected_second,
        "recovery_attempt_lineage_rejected",
    )
    return {
        "phase": phase,
        "attempts": 2,
        "next_attempt": None,
        "maximum_attempts": MAX_ATTEMPTS,
        "live_plan_digest": rollback_plan["live_plan_digest"],
    }


def _capture_prestate(
    bundle_context: Mapping[str, object],
    predecessor_root: Path,
    core_source_root: Path,
    deploy_source_root: Path,
    accepted_epoch_anchor: Mapping[str, object],
    *,
    attempt_phase: str = PRE_ATTEMPT_CAPTURE_PHASE,
    rollback_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    require(os.geteuid() == 0, "root_required")
    bundle = bundle_context["bundle"]
    accepted_epoch_anchor = _require_bundle_epoch_anchor(
        bundle, accepted_epoch_anchor
    )
    _git_identity(core_source_root, str(bundle["core_source_commit"]))
    _git_identity(deploy_source_root, str(bundle["deploy_source_commit"]))
    controller = deploy_source_root / "scripts/activate_p01b_p16_successor_v1.py"
    require(
        _sha(controller.read_bytes()) == bundle["controller_source_sha256"],
        "controller_source_drifted",
    )
    attempts = _attempt_rows(bundle)
    _require_attempt_phase_lineage(
        bundle,
        attempts,
        phase=attempt_phase,
        rollback_plan=rollback_plan,
    )
    require(p16._absent(MARKER_PATH) and p16._absent(SELECTOR_PATH), "p01b_already_active")
    require(p16._absent(P01B_DROPIN), "p01b_dropin_prestate_rejected")
    legacy_incident = _verify_legacy_incident(bundle)
    recovery_incident = _verify_recovery_incident(bundle, attempts[0])
    predecessor_context = p16._load_bundle_context(predecessor_root)
    predecessor = predecessor_context["bundle"]
    p16_evidence = _p16_projection(predecessor_root, bundle["predecessor"])
    components = _selected_components()
    expected_artifacts = bundle["predecessor"]["artifacts"]
    require(
        components["core"] == expected_artifacts["core"]["release_digest"]
        and expected_artifacts["telegram_runtime"]["release_digest"] in components["runtime_execstart"]
        and components["plugin"]
        == expected_artifacts["telegram_plugin"]["release_digest"],
        "predecessor_component_selection_drifted",
    )
    services = _service_prestate()
    container = _container_projection(
        expected_plugin_digest=str(expected_artifacts["telegram_plugin"]["release_digest"])
    )
    generation13 = _generation13_projection(
        predecessor, accepted_epoch_anchor=accepted_epoch_anchor
    )
    return {
        "accepted_epoch_anchor": _validate_epoch_anchor(accepted_epoch_anchor),
        "p16": p16_evidence,
        "legacy_incident": legacy_incident,
        "recovery_incident": recovery_incident,
        "restorable_state": {
            "components": {
                "core": components["core"],
                "plugin": components["plugin"],
                "runtime_binding_digest": components["runtime_binding_digest"],
                "runtime_release_digest": expected_artifacts["telegram_runtime"]["release_digest"],
            },
            "files": {
                "telegram_config": p16._file_projection(p16.TELEGRAM_CONFIG),
                "p16_dropin": p16._file_projection(p16.P16_TELEGRAM_DROPIN),
                "core_binding": p16._file_projection(p16.CORE_BINDING),
                "core_selector": p16._file_projection(p16.CORE_SELECTOR),
            },
        },
        "dynamic_invariants": {
            "services": services,
            "container": container,
            "generation13": generation13,
        },
        "p01b_attempts": len(attempts),
        "private_content_read": False,
        "channel_called": False,
        "model_called": False,
        "provider_called": False,
        "health_called": False,
    }


def _plan(
    bundle: Mapping[str, object], prestate: Mapping[str, object], executor: Path
) -> dict[str, object]:
    unsigned = {
        "schema": LIVE_PLAN_SCHEMA,
        "status": PREFLIGHT_STATUS,
        "bundle_digest": bundle["bundle_digest"],
        "attempt_series_id": bundle["lineage"]["attempt_series_id"],
        "next_attempt": int(prestate["p01b_attempts"]) + 1,
        "maximum_attempts": MAX_ATTEMPTS,
        "executor_sha256": _sha(executor.read_bytes()),
        "accepted_epoch_anchor": prestate["accepted_epoch_anchor"],
        "prestate": prestate,
        "boundaries": dict(_PLAN_BOUNDARIES),
    }
    return {
        **unsigned,
        "live_plan_digest": digest("myuna-p01b-p16-incident-recovery-live-plan-v1", unsigned),
    }


def prepare_live(
    *,
    bundle_root: Path,
    predecessor_bundle_root: Path,
    core_source_root: Path,
    deploy_source_root: Path,
    accepted_epoch_anchor_path: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    context = _load_bundle_context(bundle_root)
    accepted_epoch_anchor = _load_epoch_anchor(accepted_epoch_anchor_path)
    accepted_epoch_anchor = _require_bundle_epoch_anchor(
        context["bundle"],
        accepted_epoch_anchor,
        source_path=accepted_epoch_anchor_path,
    )
    prestate = _capture_prestate(
        context,
        predecessor_bundle_root,
        core_source_root,
        deploy_source_root,
        accepted_epoch_anchor,
    )
    return (
        {**context, "accepted_epoch_anchor": accepted_epoch_anchor},
        _plan(context["bundle"], prestate, Path(__file__).resolve()),
    )


def _mkdir_root(path: Path, mode: int) -> None:
    if p16._absent(path):
        try:
            path.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            # A concurrent actor may win creation; exact ownership/type/mode
            # validation below remains authoritative.
            pass
    metadata = path.lstat()
    require(
        path.is_dir()
        and not path.is_symlink()
        and metadata.st_uid == 0
        and metadata.st_gid == 0,
        "protected_directory_rejected",
    )
    os.chmod(path, mode)
    p16._fsync_directory(path.parent)


def _consume_attempt(bundle: Mapping[str, object], plan_digest: str) -> dict[str, object]:
    _mkdir_root(STATE_ROOT, 0o700)
    descriptor = os.open(LOCK_PATH, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(descriptor)
        require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == 0
            and metadata.st_gid == 0
            and stat.S_IMODE(metadata.st_mode) == 0o600,
            "attempt_lock_rejected",
        )
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        rows = _attempt_rows(bundle)
        require(len(rows) < MAX_ATTEMPTS, "attempt_budget_exhausted")
        _require_attempt_phase_lineage(
            bundle,
            rows,
            phase=PRE_ATTEMPT_CAPTURE_PHASE,
        )
        _mkdir_root(ATTEMPT_ROOT, 0o700)
        number = len(rows) + 1
        value = attempt_payload(
            bundle,
            attempt=number,
            live_plan_digest=plan_digest,
            previous_attempt_digest=(None if not rows else str(rows[-1]["attempt_digest"])),
            recorded_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )
        p16._atomic_write(
            ATTEMPT_ROOT / f"attempt-{number:04d}.json",
            canonical(value) + b"\n",
            mode=0o600,
            uid=0,
            gid=0,
            exclusive=True,
        )
        require(_attempt_rows(bundle)[-1] == value, "attempt_commit_rejected")
        return value
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _render_dropin(core: Path, runtime: Path) -> bytes:
    return (
        "[Service]\n"
        "ExecStart=\n"
        f"ExecStart=/usr/bin/python3 {runtime}/runtime/telegram_owner_runtime_gateway.py\n"
        f"Environment=PYTHONPATH={core}/src:{runtime}/runtime\n"
        f"ReadWritePaths={p16.INCIDENT_HISTORY_ROOT / 'telegram'}\n"
    ).encode("ascii")


def _backup_file(root: Path, name: str, source: Path) -> dict[str, object]:
    return p16._backup_file(root, name, source)


def _create_backup(plan: Mapping[str, object]) -> Path:
    _mkdir_root(BACKUP_ROOT, 0o700)
    root = BACKUP_ROOT / str(plan["live_plan_digest"])
    require(p16._absent(root), "backup_already_exists")
    root.mkdir(mode=0o700)
    files = {
        "telegram_config": _backup_file(root, "TELEGRAM_CONFIG", p16.TELEGRAM_CONFIG),
        "p16_dropin": _backup_file(root, "P16_DROPIN", p16.P16_TELEGRAM_DROPIN),
        "p16_selector": _backup_file(root, "P16_SELECTOR", p16.INCIDENT_HISTORY_SELECTOR),
        "p16_marker": _backup_file(root, "P16_MARKER", p16.INCIDENT_HISTORY_MARKER),
        "p07_selector": _backup_file(root, "P07_SELECTOR", p16.P07_SELECTOR),
        "p07_release_set": _backup_file(root, "P07_RELEASE_SET", p16.RELEASE_SET_PATH),
        "p08_selector": _backup_file(root, "P08_SELECTOR", p16.p08_activation.SELECTOR_JSON),
    }
    document = {"schema": "myuna.p01b-p16-incident-recovery-backup.v1", "plan": plan, "files": files}
    p16._atomic_write(
        root / "BACKUP.json", canonical(document) + b"\n", mode=0o600, uid=0, gid=0, exclusive=True
    )
    _verify_backup(root, plan)
    return root


def _verify_backup(root: Path, plan: Mapping[str, object]) -> dict[str, object]:
    p16._require_root_directory(root, mode=0o700, code="backup_rejected")
    document = _read_json(root / "BACKUP.json", maximum=1_000_000)
    require(document.get("plan") == plan, "backup_plan_rejected")
    for record in document.get("files", {}).values():
        require(isinstance(record, dict), "backup_file_rejected")
        backup_name = record.get("backup_name")
        require(isinstance(backup_name, str), "backup_file_rejected")
        path = root / backup_name
        projection = p16._file_projection(path)
        source = record["source"]
        require(
            projection["sha256"] == source["sha256"]
            and projection["size"] == source["size"]
            and projection["uid"] == 0
            and projection["gid"] == 0
            and projection["mode"] == "0600"
            and projection["type"] == "regular_no_symlink",
            "backup_file_rejected",
        )
    return document


def _install_targets(context: Mapping[str, object]) -> None:
    telegram_gid = grp.getgrnam("myuna-gateway-telegram").gr_gid
    for name, destination in (
        ("telegram_runtime", p16.RUNTIME_ROOT),
        ("telegram_plugin", p16.PLUGIN_ROOT),
    ):
        p16._install_artifact(
            context["artifacts"][name],
            destination,
            context["inventories"][name],
            gid=telegram_gid if name == "telegram_runtime" else 0,
        )


def _write_selector(bundle: Mapping[str, object]) -> None:
    _mkdir_root(STATE_ROOT, 0o700)
    p16._atomic_write(
        SELECTOR_PATH,
        canonical(build_selector(bundle)) + b"\n",
        mode=0o600,
        uid=0,
        gid=0,
        exclusive=True,
    )


def _target_projection(
    context: Mapping[str, object], prestate: Mapping[str, object], *, marker: bool
) -> dict[str, object]:
    bundle = context["bundle"]
    artifacts = context["artifacts"]
    require(p16._read_canonical(SELECTOR_PATH, maximum=64_000) == build_selector(bundle), "target_selector_rejected")
    if marker:
        require(p16._read_canonical(MARKER_PATH, maximum=4096) == marker_payload(bundle), "target_marker_rejected")
    else:
        require(p16._absent(MARKER_PATH), "target_marker_order_rejected")
    files = prestate["restorable_state"]["files"]
    require(p16._file_projection(p16.P16_TELEGRAM_DROPIN) == files["p16_dropin"], "p16_dropin_changed")
    require(p16._file_projection(p16.CORE_BINDING) == files["core_binding"], "core_binding_changed")
    require(p16._file_projection(p16.CORE_SELECTOR) == files["core_selector"], "core_selector_changed")
    require(p16._file_projection(P01B_DROPIN)["sha256"] == _sha(_render_dropin(artifacts["core"], artifacts["telegram_runtime"])), "target_dropin_rejected")
    expected_config = p07.render_telegram_config(str(bundle["artifacts"]["telegram_plugin"]["release_digest"]))
    require(p16.TELEGRAM_CONFIG.read_bytes() == expected_config, "target_plugin_config_rejected")
    target_container = _container_projection(
        expected_plugin_digest=str(bundle["artifacts"]["telegram_plugin"]["release_digest"])
    )
    services = {
        alias: _stable_service(alias, phase="target_static_service_snapshot")
        for alias in ("core", "telegram_socket", "p08", "p08_socket")
    }
    pre_services = prestate["dynamic_invariants"]["services"]
    require(services["core"] == pre_services["core"], "core_service_changed")
    require(services["p08"] == pre_services["p08"], "p08_service_changed")
    require(services["p08_socket"] == pre_services["p08_socket"], "p08_socket_changed")
    predecessor_root = context["predecessor_root"]
    require(_p16_projection(predecessor_root, bundle["predecessor"]) == prestate["p16"], "p16_evidence_changed")
    predecessor_bundle = p16._load_bundle_context(predecessor_root)["bundle"]
    release_set = p16._p07_snapshot(
        str(predecessor_bundle["compatibility"]["p07_release_set_id"])
    )
    runtime_digest = str(bundle["artifacts"]["telegram_runtime"]["release_digest"])

    def observe_candidate() -> Mapping[str, object]:
        observed = p16._service_projection(p16.TELEGRAM_SERVICE)
        if runtime_digest not in str(observed.get("exec_start", "")):
            raise _service_rejected(
                "telegram", "telegram_readiness_stability", "release_binding_drifted"
            )
        return observed

    initial = observe_candidate()
    readiness = _wait_telegram_convergence(
        release_set,
        expected_binding_digest=str(initial["binding_digest"]),
        observe=observe_candidate,
    )
    _require_post_restart_generation13_convergence(
        _generation13_projection(
            predecessor_bundle,
            accepted_epoch_anchor=prestate["accepted_epoch_anchor"],
            readiness_override=readiness,
        ),
        prestate["dynamic_invariants"]["generation13"],
        code="generation13_changed",
    )
    p16_selector = build_p16_selector(predecessor_bundle)
    p16._service_identity_smoke(
        artifacts["telegram_runtime"],
        p16_digest("myuna-p16-incident-history-selector-v1", p16_selector),
        grp.getgrnam("myuna-gateway-telegram").gr_gid,
        marker_expected=True,
    )
    return {
        "selector_digest": selector_digest(bundle),
        "services_active": True,
        "container": "running_healthy_restart_zero",
        "container_semantic_digest": target_container["semantic_digest"],
        "container_identity_digest": target_container["identity_digest"],
        "telegram_process_binding_digest": readiness["process_binding_digest"],
        "telegram_service_binding_digest": readiness["service_binding_digest"],
        "telegram_stable_seconds": readiness["stable_seconds"],
        "p16_preserved": True,
        "generation13_p08_preserved": True,
    }


def _restore_service_states(prestate: Mapping[str, object]) -> None:
    p16._systemctl("start", p16.TELEGRAM_SOCKET, p16.TELEGRAM_SERVICE, timeout=120)


def _normalized_recovery_prestate(
    value: Mapping[str, object],
    *,
    require_fresh_startup_epoch: bool,
) -> dict[str, object]:
    required = {
        "accepted_epoch_anchor",
        "channel_called",
        "dynamic_invariants",
        "health_called",
        "legacy_incident",
        "recovery_incident",
        "model_called",
        "p01b_attempts",
        "p16",
        "private_content_read",
        "provider_called",
        "restorable_state",
    }
    require(
        isinstance(value, Mapping) and set(value) == required,
        "rollback_prestate_shape_rejected",
    )
    dynamic = value["dynamic_invariants"]
    restorable = value["restorable_state"]
    require(
        isinstance(dynamic, Mapping)
        and set(dynamic) == {"container", "generation13", "services"}
        and isinstance(restorable, Mapping)
        and set(restorable) == {"components", "files"},
        "rollback_prestate_shape_rejected",
    )
    normalized_dynamic = {
        **dynamic,
        "generation13": _restart_stable_generation13_projection(
            dynamic["generation13"],
            require_fresh_startup_epoch=require_fresh_startup_epoch,
        ),
    }
    return {**value, "dynamic_invariants": normalized_dynamic}


def _require_rollback_prestate_convergence(
    current: Mapping[str, object], expected: Mapping[str, object]
) -> None:
    require(
        _normalized_recovery_prestate(
            current, require_fresh_startup_epoch=True
        )
        == _normalized_recovery_prestate(
            expected, require_fresh_startup_epoch=False
        ),
        "rollback_prestate_rejected",
    )


def _restore_prestate(
    backup_root: Path,
    plan: Mapping[str, object],
    context: Mapping[str, object],
) -> dict[str, object]:
    backup = _verify_backup(backup_root, plan)
    files = backup["files"]
    if not p16._absent(MARKER_PATH):
        MARKER_PATH.unlink()
        p16._fsync_directory(MARKER_PATH.parent)
    p16._systemctl("stop", p16.TELEGRAM_SOCKET, p16.TELEGRAM_SERVICE, timeout=120)
    p16._restore_exact(p16.TELEGRAM_CONFIG, backup_root / files["telegram_config"]["backup_name"], files["telegram_config"]["source"])
    if not p16._absent(P01B_DROPIN):
        P01B_DROPIN.unlink()
        p16._fsync_directory(P01B_DROPIN.parent)
    if not p16._absent(SELECTOR_PATH):
        SELECTOR_PATH.unlink()
        p16._fsync_directory(SELECTOR_PATH.parent)
    p16._systemctl("daemon-reload")
    p07.run_resume_controller()
    _restore_service_states(plan["prestate"])
    deadline = time.monotonic() + 90
    while True:
        try:
            current = _capture_prestate(
                context,
                context["predecessor_root"],
                context["core_source_root"],
                context["deploy_source_root"],
                plan["accepted_epoch_anchor"],
                attempt_phase=POST_ATTEMPT_ROLLBACK_PHASE,
                rollback_plan=plan,
            )
            expected = dict(plan["prestate"])
            expected["p01b_attempts"] = current["p01b_attempts"]
            _require_rollback_prestate_convergence(current, expected)
            return {"rollback": "verified", "p16_preserved": True}
        except P01BActivationRejected:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _write_receipt(root: Path, name: str, payload: Mapping[str, object]) -> Path:
    _mkdir_root(root, 0o700)
    unsigned = dict(payload)
    value = {
        **unsigned,
        "receipt_digest": digest("myuna-p01b-p16-incident-recovery-receipt-v1", unsigned),
    }
    path = root / name
    p16._atomic_write(path, canonical(value) + b"\n", mode=0o600, uid=0, gid=0, exclusive=True)
    return path


def activate(
    *,
    bundle_root: Path,
    predecessor_bundle_root: Path,
    core_source_root: Path,
    deploy_source_root: Path,
    accepted_epoch_anchor_path: Path,
    expected_live_plan_digest: str,
    confirmation: str,
) -> dict[str, object]:
    context, plan = prepare_live(
        bundle_root=bundle_root,
        predecessor_bundle_root=predecessor_bundle_root,
        core_source_root=core_source_root,
        deploy_source_root=deploy_source_root,
        accepted_epoch_anchor_path=accepted_epoch_anchor_path,
    )
    require(
        plan["live_plan_digest"] == expected_live_plan_digest
        and confirmation == f"ACTIVATE:{expected_live_plan_digest}",
        "activation_confirmation_rejected",
    )
    if phase_f_selected_target(Path(__file__).resolve().parent):
        raise P01BActivationRejected("phase_f_canonical_owner_required")
    context = {
        **context,
        "predecessor_root": predecessor_bundle_root,
        "core_source_root": core_source_root,
        "deploy_source_root": deploy_source_root,
    }
    backup_root = _create_backup(plan)
    attempt = _consume_attempt(context["bundle"], expected_live_plan_digest)
    stage = "install_artifacts"
    live_mutated = False
    try:
        _install_targets(context)
        stage = "write_selector"
        live_mutated = True
        _write_selector(context["bundle"])
        stage = "stop_telegram"
        p16._systemctl("stop", p16.TELEGRAM_SOCKET, p16.TELEGRAM_SERVICE, timeout=120)
        stage = "select_runtime_plugin_overlay"
        p16._atomic_write(
            p16.TELEGRAM_CONFIG,
            p07.render_telegram_config(str(context["bundle"]["artifacts"]["telegram_plugin"]["release_digest"])),
            mode=0o600,
            uid=0,
            gid=0,
            exclusive=False,
        )
        p16._atomic_write(
            P01B_DROPIN,
            _render_dropin(context["artifacts"]["core"], context["artifacts"]["telegram_runtime"]),
            mode=0o644,
            uid=0,
            gid=0,
            exclusive=False,
        )
        p16._systemctl("daemon-reload")
        stage = "resume_controller"
        p07.run_resume_controller()
        stage = "restore_service_states"
        _restore_service_states(plan["prestate"])
        stage = "verify_target_before_marker"
        target = _target_projection(context, plan["prestate"], marker=False)
        stage = "enable_marker_last"
        p16._atomic_write(
            MARKER_PATH,
            canonical(marker_payload(context["bundle"])) + b"\n",
            mode=0o600,
            uid=0,
            gid=0,
            exclusive=True,
        )
        stage = "verify_enabled_target"
        target = _target_projection(context, plan["prestate"], marker=True)
        payload = {
            "schema": ACTIVATION_RECEIPT_SCHEMA,
            "status": ACTIVE_STATUS,
            "attempt": attempt["attempt"],
            "maximum_attempts": MAX_ATTEMPTS,
            "attempt_digest": attempt["attempt_digest"],
            "attempt_series_id": context["bundle"]["lineage"]["attempt_series_id"],
            "bundle_digest": context["bundle"]["bundle_digest"],
            "live_plan_digest": expected_live_plan_digest,
            "backup": backup_root.name,
            "p16_attempt2_consumed": False,
            "legacy_p01b_attempt2_consumed": False,
            "legacy_p01b_attempt2_relabelled": False,
            "p16_lineage_rewritten": False,
            "private_content_read": False,
            "channel_called": False,
            "model_called": False,
            "provider_called": False,
            "health_called": False,
            **target,
        }
        receipt = _write_receipt(RECEIPT_ROOT, f"activation-attempt-{attempt['attempt']:04d}.json", payload)
        return {**payload, "receipt": receipt.name}
    except BaseException as exc:
        rollback = "not_needed"
        rollback_gate = None
        if live_mutated:
            try:
                _restore_prestate(backup_root, plan, context)
                rollback = "verified"
            except BaseException as rollback_exc:
                rollback = "failed"
                rollback_gate = getattr(rollback_exc, "code", type(rollback_exc).__name__)
        failure = {
            "schema": ACTIVATION_RECEIPT_SCHEMA,
            "status": "hard_stop_rollback_failed" if rollback == "failed" else "activation_failed_rolled_back",
            "attempt": attempt["attempt"],
            "bundle_digest": context["bundle"]["bundle_digest"],
            "live_plan_digest": expected_live_plan_digest,
            "failure_stage": stage,
            "failure_gate": getattr(exc, "code", type(exc).__name__),
            "failure_service_alias": getattr(exc, "service_alias", None),
            "failure_phase": getattr(exc, "phase", None),
            "rollback": rollback,
            "rollback_gate": rollback_gate,
            "p16_attempt2_consumed": False,
            "legacy_p01b_attempt2_consumed": False,
            "legacy_p01b_attempt2_relabelled": False,
            "p16_lineage_rewritten": False,
            "private_content_read": False,
            "channel_called": False,
            "model_called": False,
            "provider_called": False,
            "health_called": False,
        }
        _write_receipt(RECEIPT_ROOT, f"failure-attempt-{attempt['attempt']:04d}.json", failure)
        raise


def rollback(
    *,
    bundle_root: Path,
    predecessor_bundle_root: Path,
    core_source_root: Path,
    deploy_source_root: Path,
    expected_live_plan_digest: str,
) -> dict[str, object]:
    context = _load_bundle_context(bundle_root)
    context = {
        **context,
        "predecessor_root": predecessor_bundle_root,
        "core_source_root": core_source_root,
        "deploy_source_root": deploy_source_root,
    }
    receipt = _read_json(RECEIPT_ROOT / "activation-attempt-0001.json", maximum=64_000)
    require(
        receipt.get("schema") == ACTIVATION_RECEIPT_SCHEMA
        and receipt.get("status") == ACTIVE_STATUS
        and receipt.get("live_plan_digest") == expected_live_plan_digest
        and receipt.get("bundle_digest") == context["bundle"]["bundle_digest"],
        "rollback_receipt_rejected",
    )
    backup_root = BACKUP_ROOT / expected_live_plan_digest
    backup = _read_json(backup_root / "BACKUP.json", maximum=1_000_000)
    result = _restore_prestate(backup_root, backup["plan"], context)
    payload = {
        "schema": ROLLBACK_RECEIPT_SCHEMA,
        "status": "rolled_back_verified",
        "bundle_digest": context["bundle"]["bundle_digest"],
        "live_plan_digest": expected_live_plan_digest,
        "p16_attempt2_consumed": False,
        "legacy_p01b_attempt2_consumed": False,
        "legacy_p01b_attempt2_relabelled": False,
        "p16_lineage_rewritten": False,
        "private_content_read": False,
        "channel_called": False,
        "model_called": False,
        "provider_called": False,
        "health_called": False,
        **result,
    }
    _write_receipt(RECEIPT_ROOT, "rollback-attempt-0001.json", payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-root", required=True, type=Path)
    parser.add_argument("--predecessor-bundle-root", required=True, type=Path)
    parser.add_argument("--core-source-root", required=True, type=Path)
    parser.add_argument("--deploy-source-root", required=True, type=Path)
    parser.add_argument("--accepted-epoch-anchor", type=Path)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--activate", action="store_true")
    parser.add_argument("--rollback", action="store_true")
    parser.add_argument("--expected-live-plan-digest")
    parser.add_argument("--confirmation")
    args = parser.parse_args()
    require(sum((args.preflight_only, args.activate, args.rollback)) == 1, "mode_rejected")
    common = {
        "bundle_root": args.bundle_root,
        "predecessor_bundle_root": args.predecessor_bundle_root,
        "core_source_root": args.core_source_root,
        "deploy_source_root": args.deploy_source_root,
    }
    try:
        if args.preflight_only:
            require(
                isinstance(args.accepted_epoch_anchor, Path),
                "epoch_anchor_required",
            )
            _context, plan = prepare_live(
                **common,
                accepted_epoch_anchor_path=args.accepted_epoch_anchor,
            )
            output = {
                "status": PREFLIGHT_STATUS,
                "live_plan_digest": plan["live_plan_digest"],
                "prestate_digest": digest("myuna-p01b-p16-incident-recovery-prestate-v1", plan["prestate"]),
                "next_attempt": plan["next_attempt"],
                "maximum_attempts": MAX_ATTEMPTS,
                "p16_attempt2_consumed": False,
                "legacy_p01b_attempt2_consumed": False,
                "legacy_p01b_attempt2_relabelled": False,
                "mutation_performed": False,
                "private_content_read": False,
                "channel_called": False,
                "model_called": False,
                "provider_called": False,
                "health_called": False,
            }
        elif args.activate:
            require(isinstance(args.expected_live_plan_digest, str), "plan_digest_required")
            require(
                isinstance(args.accepted_epoch_anchor, Path),
                "epoch_anchor_required",
            )
            output = activate(
                **common,
                accepted_epoch_anchor_path=args.accepted_epoch_anchor,
                expected_live_plan_digest=args.expected_live_plan_digest,
                confirmation=str(args.confirmation or ""),
            )
        else:
            require(isinstance(args.expected_live_plan_digest, str), "plan_digest_required")
            output = rollback(
                **common,
                expected_live_plan_digest=args.expected_live_plan_digest,
            )
    except BaseException as exc:
        print(
            json.dumps(
                {"status": "rejected", "error_code": getattr(exc, "code", type(exc).__name__)},
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(output, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
