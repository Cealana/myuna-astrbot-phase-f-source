#!/usr/bin/env python3
"""Deterministic contract for the P01-B/P16 incident-recovery successor."""

from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Mapping


BUNDLE_SCHEMA = "myuna.p01b-p16-incident-recovery-bundle.v3"
LINEAGE_SCHEMA = "myuna.p01b-p16-incident-recovery-lineage.v3"
SELECTOR_SCHEMA = "myuna.p01b-contextual-visual-selector.v5"
MARKER_SCHEMA = "myuna.p01b-contextual-visual-enabled.v5"
ATTEMPT_SCHEMA = "myuna.p01b-p16-incident-recovery-attempt.v1"
ACTIVATION_RECEIPT_SCHEMA = "myuna.p01b-p16-incident-recovery-activation-receipt.v1"
ROLLBACK_RECEIPT_SCHEMA = "myuna.p01b-p16-incident-recovery-rollback-receipt.v1"
EPOCH_ANCHOR_SCHEMA = "myuna.p01b-p16-incident-recovery-epoch-anchor.v1"
EPOCH_ANCHOR_SCOPE = "p01b_readiness_t1_repair_and_future_epoch_equality_gate_only"
MAX_ATTEMPTS = 2

_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class P01BSuccessorContractRejected(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def digest(domain: str, value: object) -> str:
    return sha256(domain.encode("ascii") + b"\0" + canonical(value)).hexdigest()


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise P01BSuccessorContractRejected(code)


def _hex40(value: object) -> bool:
    return isinstance(value, str) and _HEX40.fullmatch(value) is not None


def _hex64(value: object) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def _artifact(value: object) -> dict[str, object]:
    _require(isinstance(value, dict), "artifact_rejected")
    _require(
        set(value) == {"file_count", "inventory_digest", "release_digest"}
        and type(value["file_count"]) is int
        and value["file_count"] > 0
        and _hex64(value["inventory_digest"])
        and _hex64(value["release_digest"]),
        "artifact_rejected",
    )
    return dict(value)


def validate_epoch_anchor_binding(value: object) -> dict[str, object]:
    _require(isinstance(value, dict), "epoch_anchor_binding_rejected")
    required = {
        "accepted_checkpoint",
        "anchor_digest",
        "anchor_file_sha256",
        "content_free",
        "owner_decision_scope",
        "private_content_included",
        "schema",
        "source_handoff_sha256",
        "status",
    }
    _require(set(value) == required, "epoch_anchor_binding_rejected")
    checkpoint = value["accepted_checkpoint"]
    checkpoint_fields = {
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
    _require(
        isinstance(checkpoint, dict)
        and set(checkpoint) == checkpoint_fields,
        "epoch_anchor_binding_rejected",
    )
    for field in checkpoint_fields - {"metadata_digest"}:
        _require(
            type(checkpoint[field]) is int and checkpoint[field] >= 0,
            "epoch_anchor_binding_rejected",
        )
    _require(
        _hex64(checkpoint["metadata_digest"])
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
        and _hex64(value["source_handoff_sha256"])
        and _hex64(value["anchor_file_sha256"])
        and _hex64(value["anchor_digest"]),
        "epoch_anchor_binding_rejected",
    )
    anchor_unsigned = {
        key: value[key]
        for key in required - {"anchor_digest", "anchor_file_sha256"}
    }
    _require(
        value["anchor_digest"]
        == digest("myuna.p01b-p16-incident-recovery-epoch-anchor.v1", anchor_unsigned),
        "epoch_anchor_binding_digest_rejected",
    )
    return {**dict(value), "accepted_checkpoint": dict(checkpoint)}


def _predecessor(value: object) -> dict[str, object]:
    _require(isinstance(value, dict), "predecessor_rejected")
    required = {
        "activation_receipt_digest",
        "artifacts",
        "attempt_series_id",
        "attempts",
        "bundle_digest",
        "bundle_manifest_sha256",
        "content_free",
        "maximum_attempts",
        "strategy_digest",
    }
    _require(set(value) == required, "predecessor_rejected")
    artifacts = value["artifacts"]
    _require(
        isinstance(artifacts, dict)
        and set(artifacts)
        == {"core", "p16_adapter", "telegram_plugin", "telegram_runtime"},
        "predecessor_rejected",
    )
    normalized = {name: _artifact(record) for name, record in artifacts.items()}
    _require(
        all(
            _hex64(value[name])
            for name in (
                "activation_receipt_digest",
                "attempt_series_id",
                "bundle_digest",
                "bundle_manifest_sha256",
                "strategy_digest",
            )
        )
        and value["attempts"] == 1
        and value["maximum_attempts"] == 2
        and value["content_free"] is True,
        "predecessor_rejected",
    )
    return {**dict(value), "artifacts": normalized}


def _incident_predecessor(value: object) -> dict[str, object]:
    _require(isinstance(value, dict), "incident_predecessor_rejected")
    required = {
        "content_free",
        "legacy_attempt",
        "legacy_attempt2_prohibited",
        "legacy_attempt_file_sha256",
        "legacy_failure_gate",
        "legacy_failure_receipt_file_sha256",
        "legacy_failure_stage",
        "legacy_failure_status",
        "legacy_maximum_attempts",
        "legacy_rollback",
        "legacy_rollback_gate",
    }
    _require(set(value) == required, "incident_predecessor_rejected")
    _require(
        value["content_free"] is True
        and value["legacy_attempt"] == 1
        and value["legacy_maximum_attempts"] == 2
        and value["legacy_attempt2_prohibited"] is True
        and _hex64(value["legacy_attempt_file_sha256"])
        and _hex64(value["legacy_failure_receipt_file_sha256"])
        and value["legacy_failure_status"] == "hard_stop_rollback_failed"
        and value["legacy_failure_stage"] == "verify_target_before_marker"
        and value["legacy_failure_gate"] == "target_service_inactive"
        and value["legacy_rollback"] == "failed"
        and value["legacy_rollback_gate"] == "rollback_prestate_rejected",
        "incident_predecessor_rejected",
    )
    return dict(value)


def _recovery_predecessor(value: object) -> dict[str, object]:
    _require(isinstance(value, dict), "recovery_predecessor_rejected")
    required = {
        "attempt",
        "attempt2_authorized",
        "attempt_digest",
        "attempt_file_sha256",
        "attempt_series_id",
        "bundle_digest",
        "bundle_manifest_sha256",
        "content_free",
        "failure_gate",
        "failure_phase",
        "failure_receipt_digest",
        "failure_receipt_file_sha256",
        "failure_service_alias",
        "failure_stage",
        "failure_status",
        "lineage_digest",
        "live_plan_digest",
        "maximum_attempts",
        "rollback",
        "rollback_gate",
        "strategy_id",
    }
    _require(set(value) == required, "recovery_predecessor_rejected")
    _require(
        type(value["attempt"]) is int
        and value["attempt"] == 1
        and type(value["maximum_attempts"]) is int
        and value["maximum_attempts"] == MAX_ATTEMPTS
        and value["attempt2_authorized"] is False
        and value["content_free"] is True
        and all(
            _hex64(value[name])
            for name in (
                "attempt_digest",
                "attempt_file_sha256",
                "attempt_series_id",
                "bundle_digest",
                "bundle_manifest_sha256",
                "failure_receipt_digest",
                "failure_receipt_file_sha256",
                "lineage_digest",
                "live_plan_digest",
                "strategy_id",
            )
        )
        and value["failure_status"] == "hard_stop_rollback_failed"
        and value["failure_stage"] == "verify_target_before_marker"
        and value["failure_gate"]
        == "target_telegram_telegram_readiness_stability_convergence_timeout"
        and value["failure_service_alias"] == "telegram"
        and value["failure_phase"] == "telegram_readiness_stability"
        and value["rollback"] == "failed"
        and value["rollback_gate"] == "rollback_prestate_rejected",
        "recovery_predecessor_rejected",
    )
    return dict(value)


def build_lineage(identity: Mapping[str, object]) -> dict[str, object]:
    predecessor = _predecessor(identity["predecessor"])
    incident = _incident_predecessor(identity["incident_predecessor"])
    recovery = _recovery_predecessor(identity["recovery_predecessor"])
    epoch_anchor = validate_epoch_anchor_binding(identity["epoch_anchor"])
    target = identity["artifacts"]
    strategy_basis = {
        "schema": LINEAGE_SCHEMA,
        "predecessor_p16_bundle_digest": predecessor["bundle_digest"],
        "predecessor_p16_attempt_series_id": predecessor["attempt_series_id"],
        "predecessor_p16_strategy_digest": predecessor["strategy_digest"],
        "predecessor_p16_attempts": 1,
        "predecessor_p16_unused_attempt_preserved": True,
        "consumed_legacy_p01b_attempt": incident["legacy_attempt"],
        "legacy_p01b_attempt2_prohibited": True,
        "legacy_p01b_attempt_file_sha256": incident["legacy_attempt_file_sha256"],
        "legacy_p01b_failure_receipt_file_sha256": incident[
            "legacy_failure_receipt_file_sha256"
        ],
        "predecessor_incident_attempt_series_id": recovery["attempt_series_id"],
        "predecessor_incident_strategy_id": recovery["strategy_id"],
        "predecessor_incident_lineage_digest": recovery["lineage_digest"],
        "predecessor_incident_bundle_digest": recovery["bundle_digest"],
        "predecessor_incident_bundle_manifest_sha256": recovery[
            "bundle_manifest_sha256"
        ],
        "predecessor_incident_attempt": recovery["attempt"],
        "predecessor_incident_attempt_digest": recovery["attempt_digest"],
        "predecessor_incident_attempt_file_sha256": recovery[
            "attempt_file_sha256"
        ],
        "predecessor_incident_live_plan_digest": recovery["live_plan_digest"],
        "predecessor_incident_failure_receipt_digest": recovery[
            "failure_receipt_digest"
        ],
        "predecessor_incident_failure_receipt_file_sha256": recovery[
            "failure_receipt_file_sha256"
        ],
        "consumed_incident_attempts": recovery["attempt"],
        "remaining_incident_attempts": MAX_ATTEMPTS - recovery["attempt"],
        "attempt_budget_reset": False,
        "incident_attempt2_authorized": False,
        "epoch_anchor": epoch_anchor,
        "core_source_commit": identity["core_source_commit"],
        "deploy_source_commit": identity["deploy_source_commit"],
        "target_release_digests": {
            name: target[name]["release_digest"]
            for name in sorted(target)
        },
        "maximum_attempts": MAX_ATTEMPTS,
    }
    strategy_id = digest("myuna-p01b-p16-incident-recovery-strategy-v3", strategy_basis)
    series_basis = {
        **strategy_basis,
        "strategy_id": strategy_id,
        "state_namespace": "p01b-p16-incident-recovery-v1",
    }
    return {
        "schema": LINEAGE_SCHEMA,
        "maximum_attempts": MAX_ATTEMPTS,
        "predecessor_p16_attempts": 1,
        "predecessor_p16_unused_attempt_preserved": True,
        "consumed_legacy_p01b_attempt": 1,
        "legacy_p01b_attempt2_prohibited": True,
        "consumed_incident_attempts": 1,
        "remaining_incident_attempts": 1,
        "attempt_budget_reset": False,
        "incident_attempt2_authorized": False,
        "predecessor_incident_attempt_digest": recovery["attempt_digest"],
        "predecessor_incident_bundle_digest": recovery["bundle_digest"],
        "strategy_id": strategy_id,
        "attempt_series_id": recovery["attempt_series_id"],
        "lineage_digest": digest(
            "myuna-p01b-p16-incident-recovery-lineage-v3", series_basis
        ),
    }


def build_bundle(identity_value: object) -> dict[str, object]:
    _require(isinstance(identity_value, dict), "bundle_identity_rejected")
    identity = dict(identity_value)
    required = {
        "artifacts",
        "content_free",
        "controller_source_sha256",
        "core_source_commit",
        "deploy_source_commit",
        "epoch_anchor",
        "predecessor",
        "incident_predecessor",
        "recovery_predecessor",
        "schema",
        "status",
    }
    _require(set(identity) == required, "bundle_identity_rejected")
    _require(
        identity["schema"] == BUNDLE_SCHEMA
        and identity["status"] == "built_inactive"
        and identity["content_free"] is True
        and _hex40(identity["core_source_commit"])
        and _hex40(identity["deploy_source_commit"])
        and _hex64(identity["controller_source_sha256"]),
        "bundle_identity_rejected",
    )
    predecessor = _predecessor(identity["predecessor"])
    incident_predecessor = _incident_predecessor(identity["incident_predecessor"])
    recovery_predecessor = _recovery_predecessor(identity["recovery_predecessor"])
    epoch_anchor = validate_epoch_anchor_binding(identity["epoch_anchor"])
    artifacts = identity["artifacts"]
    _require(
        isinstance(artifacts, dict)
        and set(artifacts)
        == {"core", "p16_adapter", "telegram_plugin", "telegram_runtime"},
        "bundle_identity_rejected",
    )
    normalized_artifacts = {
        name: _artifact(record) for name, record in artifacts.items()
    }
    _require(
        normalized_artifacts["core"] == predecessor["artifacts"]["core"]
        and normalized_artifacts["p16_adapter"]
        == predecessor["artifacts"]["p16_adapter"]
        and normalized_artifacts["telegram_runtime"]
        != predecessor["artifacts"]["telegram_runtime"]
        and normalized_artifacts["telegram_plugin"]
        != predecessor["artifacts"]["telegram_plugin"],
        "bundle_artifact_boundary_rejected",
    )
    identity = {
        **identity,
        "predecessor": predecessor,
        "incident_predecessor": incident_predecessor,
        "recovery_predecessor": recovery_predecessor,
        "epoch_anchor": epoch_anchor,
        "artifacts": normalized_artifacts,
    }
    unsigned = {**identity, "lineage": build_lineage(identity)}
    bundle = {
        **unsigned,
        "bundle_digest": digest("myuna-p01b-p16-incident-recovery-bundle-v3", unsigned),
    }
    return bundle


def validate_bundle(value: object) -> dict[str, object]:
    _require(isinstance(value, dict), "bundle_rejected")
    required = {
        "artifacts",
        "bundle_digest",
        "content_free",
        "controller_source_sha256",
        "core_source_commit",
        "deploy_source_commit",
        "epoch_anchor",
        "lineage",
        "predecessor",
        "incident_predecessor",
        "recovery_predecessor",
        "schema",
        "status",
    }
    _require(set(value) == required, "bundle_rejected")
    identity = {key: value[key] for key in required - {"bundle_digest", "lineage"}}
    rebuilt = build_bundle(identity)
    _require(rebuilt == value, "bundle_digest_rejected")
    return dict(value)


def build_selector(bundle_value: object) -> dict[str, object]:
    bundle = validate_bundle(bundle_value)
    artifacts = bundle["artifacts"]
    selector = {
        "schema": SELECTOR_SCHEMA,
        "status": "approved",
        "channel": "telegram-owner-private",
        "bundle_digest": bundle["bundle_digest"],
        "attempt_series_id": bundle["lineage"]["attempt_series_id"],
        "strategy_id": bundle["lineage"]["strategy_id"],
        "predecessor_p16_bundle_digest": bundle["predecessor"]["bundle_digest"],
        "predecessor_p16_selector_semantics": "preserved_immutable_base",
        "predecessor_p16_unused_attempt_preserved": True,
        "consumed_p01b_attempt": bundle["lineage"]["consumed_incident_attempts"],
        "remaining_p01b_attempts": bundle["lineage"]["remaining_incident_attempts"],
        "attempt_budget_reset": False,
        "p01b_attempt2_authorized": False,
        "legacy_p01b_attempt2_prohibited": True,
        "incident_failure_receipt_file_sha256": bundle["incident_predecessor"][
            "legacy_failure_receipt_file_sha256"
        ],
        "current_incident_failure_receipt_file_sha256": bundle[
            "recovery_predecessor"
        ]["failure_receipt_file_sha256"],
        "epoch_anchor_file_sha256": bundle["epoch_anchor"]["anchor_file_sha256"],
        "epoch_anchor_digest": bundle["epoch_anchor"]["anchor_digest"],
        "epoch_anchor_metadata_digest": bundle["epoch_anchor"][
            "accepted_checkpoint"
        ]["metadata_digest"],
        "core_release_digest": artifacts["core"]["release_digest"],
        "runtime_release_digest": artifacts["telegram_runtime"]["release_digest"],
        "plugin_release_digest": artifacts["telegram_plugin"]["release_digest"],
        "p16_adapter_release_digest": artifacts["p16_adapter"]["release_digest"],
        "trusted_visual_instruction_separate": True,
        "authenticated_caption_separate": True,
        "untrusted_observation_separate": True,
        "caption_sent_to_gemini_by_default": False,
    }
    return selector


def selector_digest(bundle_value: object) -> str:
    return digest("myuna-p01b-contextual-visual-selector-v5", build_selector(bundle_value))


def marker_payload(bundle_value: object) -> dict[str, object]:
    bundle = validate_bundle(bundle_value)
    return {
        "schema": MARKER_SCHEMA,
        "status": "enabled",
        "bundle_digest": bundle["bundle_digest"],
        "selector_digest": selector_digest(bundle),
        "attempt_series_id": bundle["lineage"]["attempt_series_id"],
    }


def attempt_payload(
    bundle_value: object,
    *,
    attempt: int,
    live_plan_digest: str,
    previous_attempt_digest: str | None,
    recorded_at: str,
) -> dict[str, object]:
    bundle = validate_bundle(bundle_value)
    recovery = bundle["recovery_predecessor"]
    _require(
        type(attempt) is int
        and attempt == recovery["attempt"] + 1 == MAX_ATTEMPTS,
        "attempt_rejected",
    )
    _require(_hex64(live_plan_digest), "attempt_rejected")
    _require(
        previous_attempt_digest == recovery["attempt_digest"],
        "attempt_rejected",
    )
    _require(isinstance(recorded_at, str) and recorded_at.endswith("Z"), "attempt_rejected")
    unsigned = {
        "schema": ATTEMPT_SCHEMA,
        "attempt": attempt,
        "maximum_attempts": MAX_ATTEMPTS,
        "bundle_digest": bundle["bundle_digest"],
        "attempt_series_id": bundle["lineage"]["attempt_series_id"],
        "strategy_id": bundle["lineage"]["strategy_id"],
        "lineage_digest": bundle["lineage"]["lineage_digest"],
        "live_plan_digest": live_plan_digest,
        "previous_attempt_digest": previous_attempt_digest,
        "recorded_at": recorded_at,
        "content_free": True,
    }
    return {
        **unsigned,
        "attempt_digest": digest(
            "myuna-p01b-p16-incident-recovery-attempt-v1", unsigned
        ),
    }
