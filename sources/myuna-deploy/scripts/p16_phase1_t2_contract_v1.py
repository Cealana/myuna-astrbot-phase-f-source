"""Strict, content-free P16 Phase 1 T2 design contract.

This module constructs an inactive activation design from deterministic source
artifacts and a previously accepted generation-13 checkpoint.  It never reads
live services, configuration, channel data, logs, Profile state or databases.
"""

from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Mapping

from incident_history_runtime_adapter_v1 import (
    INCIDENT_HISTORY_MARKER,
    INCIDENT_HISTORY_ROOT,
    INCIDENT_HISTORY_SELECTOR,
    INCIDENT_HISTORY_SELECTOR_SCHEMA,
    validate_incident_history_selector,
)


BUNDLE_SCHEMA = "myuna.p16-phase1-t2-bundle.v3"
CHECKPOINT_SCHEMA = "myuna.p16-generation13-accepted-checkpoint.v1"
PLAN_SCHEMA = "myuna.p16-phase1-t2-design-plan.v1"
PREFLIGHT_SCHEMA = "myuna.p16-phase1-t2-read-only-preflight.v1"
MARKER_CONTRACT_SCHEMA = "myuna.p16-incident-history-marker-contract.v1"
ATTEMPT_LINEAGE_SCHEMA_V1 = "myuna.p16-successor-attempt-series-lineage.v1"
ATTEMPT_LINEAGE_SCHEMA = "myuna.p16-successor-attempt-series-lineage.v2"
ATTEMPT_TRANSITION_RECEIPT_SCHEMA_V1 = (
    "myuna.p16-successor-attempt-consumption-receipt.v1"
)
ATTEMPT_TRANSITION_RECEIPT_SCHEMA = (
    "myuna.p16-successor-attempt-consumption-receipt.v2"
)

_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")

_ARTIFACT_NAMES = frozenset(
    {"core", "telegram_runtime", "telegram_plugin", "p16_adapter"}
)
_ARTIFACT_FIELDS = frozenset(
    {"release_digest", "inventory_digest", "file_count"}
)
_BASE_FIELDS = frozenset(
    {
        "core_release_digest",
        "runtime_release_digest",
        "plugin_release_digest",
        "p08_release_digest",
    }
)
_COMPATIBILITY_FIELDS = frozenset(
    {
        "combined_release_set_id",
        "p07_release_set_id",
        "p08_plan_digest",
        "effective_definition_id",
        "generation",
        "epoch_schema",
    }
)
_BUNDLE_IDENTITY_FIELDS = frozenset(
    {
        "schema",
        "status",
        "core_source_commit",
        "deploy_source_commit",
        "controller_source_sha256",
        "generation13_base",
        "artifacts",
        "compatibility",
        "content_free",
    }
)
_BUNDLE_FIELDS = frozenset(
    {
        *_BUNDLE_IDENTITY_FIELDS,
        "attempt_lineage",
        "bundle_digest",
    }
)
_ATTEMPT_LINEAGE_FIELDS = frozenset(
    {
        "schema",
        "status",
        "strategy_id",
        "strategy_class",
        "strategy_relation",
        "strategy_change_digest",
        "predecessor_snapshot_digest",
        "predecessor_remaining_attempts_retired",
        "attempt_series_id",
        "successor_identity_digest",
        "terminal_predecessor",
        "maximum_attempts",
        "attempts_inherited",
        "state_action",
        "state_namespace",
        "attempt_receipt_schema",
        "lineage_digest",
    }
)
_ATTEMPT_LINEAGE_V1_FIELDS = frozenset(
    {
        "schema",
        "status",
        "strategy_id",
        "attempt_series_id",
        "successor_identity_digest",
        "terminal_predecessor",
        "maximum_attempts",
        "attempts_inherited",
        "state_action",
        "state_namespace",
        "attempt_receipt_schema",
        "lineage_digest",
    }
)
_ATTEMPT_PREDECESSOR_FIELDS = frozenset(
    {
        "series_schema",
        "attempt_series_id",
        "ledger_schema",
        "ledger_sha256",
        "bundle_digest",
        "live_plan_digest",
        "transition_schema",
        "transition_digest",
        "transition_file_sha256",
        "activation_receipt_schema",
        "activation_receipt_digest",
        "activation_receipt_file_sha256",
        "activation_backup_digest",
        "activation_backup_manifest_sha256",
        "marker_schema",
        "marker_sha256",
        "selector_schema",
        "selector_sha256",
        "selector_digest",
        "dropin_sha256",
        "active_core_release_digest",
        "active_runtime_release_digest",
        "active_plugin_release_digest",
        "active_adapter_release_digest",
        "active_core_source_commit",
        "active_deploy_source_commit",
        "attempts",
        "maximum_attempts",
    }
)
_ACTIVE_ATTEMPT_PREDECESSOR_FIELDS = frozenset(
    {
        "snapshot_schema",
        "snapshot_digest",
        "bundle_digest",
        "bundle_manifest_sha256",
        "lineage_schema",
        "lineage_digest",
        "attempt_series_id",
        "strategy_id",
        "attempts",
        "maximum_attempts",
        "attempt_digest",
        "attempt_file_sha256",
        "activation_receipt_schema",
        "activation_receipt_digest",
        "activation_receipt_file_sha256",
        "live_plan_digest",
        "activation_backup_schema",
        "activation_backup_digest",
        "activation_backup_manifest_sha256",
        "marker_sha256",
        "selector_sha256",
        "selector_digest",
        "dropin_sha256",
        "active_core_release_digest",
        "active_runtime_release_digest",
        "active_plugin_release_digest",
        "active_adapter_release_digest",
        "active_core_source_commit",
        "active_deploy_source_commit",
        "history_file_sha256",
        "history_file_size",
        "core_service_binding_digest",
        "telegram_service_binding_digest",
        "telegram_socket_binding_digest",
        "p08_service_binding_digest",
        "p08_socket_binding_digest",
    }
)
_CHECKPOINT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "checkpoint_date",
        "observation_scope",
        "source",
        "plan_digest",
        "combined_release_set_id",
        "p07_release_set_id",
        "artifacts",
        "effective_definition_id",
        "epoch",
        "aggregate",
        "service_acceptance",
        "receipt_schema",
        "content_free",
        "private_content_read",
    }
)

_ACCEPTED_CHECKPOINT_SOURCE = {
    "core_commit": "107b33c5239582e186372b7a8c1b38e0c49e8902",
    "deploy_commit": "7b0279968e10453a49a0cb18ae8953724d9b71c9",
}
_ACCEPTED_AGGREGATE = {
    "selected_revision": 1,
    "max_revision": 1,
    "turns": 1,
    "delivered_intents": 1,
    "summaries": 0,
    "pending": 0,
    "queued": 0,
    "abandoned": 0,
    "blocked": 0,
}

_LEGACY_ATTEMPT_PREDECESSOR = {
    "series_schema": "myuna.p16-attempt-series-lineage.v1",
    "attempt_series_id": "4cf6e58dc4c9e7ff1739bf5fb9ef4c53015816035afe7f2688c67bc2e298825e",
    "ledger_schema": "myuna.p16-phase1-t2-attempt-ledger.v1",
    "ledger_sha256": "33279e3bed1d3af5efaf48d8e0a416ffef113bb20b42094c2af90228382b6aa8",
    "bundle_digest": "8083194816861adb07a2ba107a5c04d591bb477c7517b05554fe92af5608401e",
    "live_plan_digest": "ffbcd3109db7245f5a412370f0d00366c9a4883916b87675863f8d9cca08ef2e",
    "transition_schema": "myuna.p16-attempt-series-transition-receipt.v1",
    "transition_digest": "b745f79b8e21b8665d6d7e18b8dec2064b3145a8e85ca02f89638cfe86c4c356",
    "transition_file_sha256": "2520c9a56b5a9bbb98f40d5511a1fab64bfce90c8d059fa8f88c4232ddc6dfc1",
    "activation_receipt_schema": "myuna.p16-phase1-t2-activation-receipt.v1",
    "activation_receipt_digest": "f7de3274ae6569e1b5527c496da8f9f8ad2b7d0e8da5d4ef1ee2560570c91864",
    "activation_receipt_file_sha256": "7ecf1ba283462ec1df125c5304f437f9e82b738c754393a8d4952455c7a097c8",
    "activation_backup_digest": "5775f948f20841d8cccbe8663276801787786deda645c814dbcf1009c977db2d",
    "activation_backup_manifest_sha256": "488678f7e3c51b59e861784ebad582acd4f2bb25e71e10ae35cfc244d8493764",
    "marker_schema": "myuna.p16-incident-history-enabled.v1",
    "marker_sha256": "7ebc04e7ed1d93b259fcff8e9380403e708f84282047df952df80e9c9d620002",
    "selector_schema": "myuna.p16-incident-history-selector.v1",
    "selector_sha256": "f681c2a6f4e294ceb4ca71f946c2c98a466f3b81e1035fd05e7e93cd744fa2ec",
    "selector_digest": "d0a882d4dac492d15f0982fcad78a869a2977533f8f4450453f8c6b68e6b81f2",
    "dropin_sha256": "aa0a22b2037d1178fb0d6fa5fe3f024ac7fdca70bad742956b70362b1c6703f6",
    "active_core_release_digest": "a13a63b29e4b929b904029cdb9a63f53e732e6bfb497199d9fd66cae11bfeb8a",
    "active_runtime_release_digest": "5aee99e9616db878e0f4c56f14f9cbbd7c0ea8768fd08d7480508d82f9f088f2",
    "active_plugin_release_digest": "0aa958c2575814e3e2abbfe219a6d651f0bb156c45812f9cd39e51d4da512012",
    "active_adapter_release_digest": "189b8bceeeca8f6294359d00353cc5671387f4133ddea71623fe4d41147741cf",
    "active_core_source_commit": "439de21d7e70422eecc80a0d9b33e6c9bfa18787",
    "active_deploy_source_commit": "7a13937e01e60b456ec2e6c27f8604122133856d",
    "attempts": 2,
    "maximum_attempts": 2,
}

_ACTIVE_ATTEMPT_PREDECESSOR = {
    "snapshot_schema": "myuna.p16-active-successor-predecessor-snapshot.v1",
    "snapshot_digest": "939cbcbef2d07a9295e0077d69d3f1ec34f9b74708a84f1c26c8e4cc0b458934",
    "bundle_digest": "839e08f7cbbedacc950ed9606e8ddad62c82df6613eeb99b1a4b22f56688b6b6",
    "bundle_manifest_sha256": "6b85fc666987e633c699c6fa727403f2e50d5d3addfff893815db61c86fa124c",
    "lineage_schema": ATTEMPT_LINEAGE_SCHEMA_V1,
    "lineage_digest": "4530fa888882d7b9f8d46728b98d43ac6b27b7a6182e37c37e17c9b331c34613",
    "attempt_series_id": "b3fd8bc96a6438b316bf9fbd079fa33e8dc9aea27638d5d2fcb5837593e657ee",
    "strategy_id": "p16-preprovider-provenance-v2-successor",
    "attempts": 1,
    "maximum_attempts": 2,
    "attempt_digest": "ec582183bc6bc6a78685acae9894bcb6c3df93ba2d44d280df11db5f849c03d4",
    "attempt_file_sha256": "be6efb7f843ba0e01a305797682371488eaefa5089787201f7301aa399a59fb0",
    "activation_receipt_schema": "myuna.p16-phase1-t2-activation-receipt.v1",
    "activation_receipt_digest": "2e2ca358a31058656e0d9d3ccc84443625e9f9b08d117fedf26128e095ccb45c",
    "activation_receipt_file_sha256": "c74a6ff0252fabe7f03339aa6a8318ce7c99755b44ef958e3cc069f5fbb03246",
    "live_plan_digest": "a0643b1740da6d4a54f228ae5fc14a019c19e9bb6929c2e1f3ab7b152b6bebe8",
    "activation_backup_schema": "myuna.p16-phase1-t2-backup.v1",
    "activation_backup_digest": "562cae8d21ae9e3774f0d58a748161acdd0853c4ea35cd1a42356ee8e95939a8",
    "activation_backup_manifest_sha256": "a844ee45155b3a66200a6534184be580a461ac1fe6ccbaeac052c70b3345fe84",
    "marker_sha256": "b038da855d6942dd449b22c66586171a743254fd84f5497bd72220ed7cdc090b",
    "selector_sha256": "52cc2298201a8e9f78296d5fba1b7843538a78378edb3aa8cf096ee81bc8cdab",
    "selector_digest": "3143b9a5158c159123d438253707e39879f588cb758e1d20df969b3ce783dc97",
    "dropin_sha256": "bb1f3f58affabe3d46c9762ab6ecf36fd0b7267c80ad7398dd6783751b4fbddc",
    "active_core_release_digest": "cff15e112631e56100078a6b2ac4767294401fd41ad9e603d1baec83685d0329",
    "active_runtime_release_digest": "6ef4feffbf3aa0bc189ec3fa8d17c3b25ca773f295be4599aa83ee36b22d6b30",
    "active_plugin_release_digest": "0aa958c2575814e3e2abbfe219a6d651f0bb156c45812f9cd39e51d4da512012",
    "active_adapter_release_digest": "de362103a3512d4b1a70b4e2e76b8142e4fb850dcff0507fd61b2df07088cab4",
    "active_core_source_commit": "c1c7317d9c80839d283d82d62f63377f64b5e639",
    "active_deploy_source_commit": "13ecd815d74a68122ddd65bf656c8fb51af0c100",
    "history_file_sha256": "6fdb4ff72efb7af9c2c3c214c4328d7b95970204a2a2b24bf380863c41bf5852",
    "history_file_size": 3088,
    "core_service_binding_digest": "c63d80a925f0acc0f0accb2274a79d21d2a0c7e0cbba82586c7b6485326063dc",
    "telegram_service_binding_digest": "d070b8261f1e8d1cb87ee4ba807817a19104c53dfb4eced8976e9191ad0449fd",
    "telegram_socket_binding_digest": "7ead847cae7ff40227cdb57e529e8ae94c0d9ee5167e1de9267cee507d97e4b8",
    "p08_service_binding_digest": "29d6a787dbcfd696a0f1eaf53e2674c0c9328b6e5b00099a71c670193f1f0ce9",
    "p08_socket_binding_digest": "abc284be7ffbf033445fdccfe34cd623d583821599925013b9411a8a8ea46286",
}
INCIDENT_RECEIPT_FIELDS = (
    "schema",
    "observed_at",
    "trusted_time_status",
    "channel",
    "release_set_id_status",
    "release_set_id",
    "category",
    "stage",
    "typed_namespace",
    "typed_gate",
    "latency_bucket",
    "http_outcome_class",
    "provider_outcome_class",
    "attempt_count",
    "retryable",
    "provider_called",
    "model_called",
    "profile_called",
    "memory_called",
    "tool_called",
    "persona_grounding_class",
    "output_guard_applied",
    "service_observation_class",
    "restart_observation_class",
    "epoch_revision_delta",
    "turn_delta",
    "summary_delta",
    "pending_after",
    "delivery_delta",
    "incident_ref_status",
    "incident_ref",
    "public_code_status",
    "public_code",
    "fingerprint_status",
    "fingerprint_digest",
    "sequence",
    "event_digest",
    "previous_event_digest",
    "occurrence_digest",
)

FORBIDDEN_FIELDS = (
    "message",
    "caption",
    "media",
    "identity",
    "request_id",
    "prompt",
    "response",
    "profile",
    "session_content",
    "db_row",
    "raw_log",
    "raw_error",
    "stack",
    "secret",
    "credential",
    "provider_payload",
    "model_response",
    "path",
    "token",
    "cost",
    "amount",
    "arbitrary_details",
)


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def digest(domain: str, value: object) -> str:
    return sha256(domain.encode("ascii") + b"\0" + canonical(value)).hexdigest()


def _hex(value: object, label: str, pattern: re.Pattern[str] = _HEX64) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")
    return value


def _exact_mapping(value: object, fields: frozenset[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} fields are invalid")
    return dict(value)


def _build_legacy_attempt_lineage(successor_identity: dict[str, object]) -> dict[str, object]:
    predecessor = dict(_LEGACY_ATTEMPT_PREDECESSOR)
    successor_identity_digest = digest(
        "myuna-p16-attempt-successor-identity-v2", successor_identity
    )
    series_id = digest(
        "myuna-p16-successor-attempt-series-v1",
        {
            "terminal_attempt_series_id": predecessor["attempt_series_id"],
            "terminal_transition_digest": predecessor["transition_digest"],
            "successor_identity_digest": successor_identity_digest,
            "strategy_id": "p16-preprovider-provenance-v2-successor",
            "maximum_attempts": 2,
        },
    )
    unsigned = {
        "schema": ATTEMPT_LINEAGE_SCHEMA_V1,
        "status": "approved_independent_successor",
        "strategy_id": "p16-preprovider-provenance-v2-successor",
        "attempt_series_id": series_id,
        "successor_identity_digest": successor_identity_digest,
        "terminal_predecessor": predecessor,
        "maximum_attempts": 2,
        "attempts_inherited": 0,
        "state_action": "new_append_only_series_no_rewrite",
        "state_namespace": "p16-successor-attempt-series-v1",
        "attempt_receipt_schema": ATTEMPT_TRANSITION_RECEIPT_SCHEMA_V1,
    }
    return {
        **unsigned,
        "lineage_digest": digest(
            "myuna-p16-successor-attempt-series-lineage-v1", unsigned
        ),
    }


def build_attempt_lineage(successor_identity_value: object) -> dict[str, object]:
    successor_identity = _exact_mapping(
        successor_identity_value,
        _BUNDLE_IDENTITY_FIELDS,
        "attempt successor identity",
    )
    if (
        successor_identity["schema"] != BUNDLE_SCHEMA
        or successor_identity["status"] != "built_inactive"
        or successor_identity["content_free"] is not True
    ):
        raise ValueError("attempt successor identity is invalid")
    predecessor = dict(_ACTIVE_ATTEMPT_PREDECESSOR)
    if (
        successor_identity["core_source_commit"]
        == predecessor["active_core_source_commit"]
        or successor_identity["artifacts"]["core"]["release_digest"]
        == predecessor["active_core_release_digest"]
    ):
        raise ValueError("successor strategy has no Core behavior change")
    successor_identity_digest = digest(
        "myuna-p16-attempt-successor-identity-v3", successor_identity
    )
    strategy_id = "p16-projection-budget-alignment-v1"
    strategy_class = "attributed_core_projection_capacity_source_change"
    strategy_relation = "supersedes_failed_strategy_without_retry_or_reset"
    strategy_change_digest = digest(
        "myuna-p16-projection-budget-strategy-change-v1",
        {
            "predecessor_core_source": predecessor["active_core_source_commit"],
            "successor_core_source": successor_identity["core_source_commit"],
            "predecessor_core_release": predecessor["active_core_release_digest"],
            "successor_core_release": successor_identity["artifacts"]["core"]["release_digest"],
            "failure_gate": "projection_character_budget_exceeded",
            "stage": "core_pre_provider",
        },
    )
    series_id = digest(
        "myuna-p16-successor-attempt-series-v2",
        {
            "predecessor_snapshot_digest": predecessor["snapshot_digest"],
            "predecessor_attempt_series_id": predecessor["attempt_series_id"],
            "predecessor_attempt_digest": predecessor["attempt_digest"],
            "successor_identity_digest": successor_identity_digest,
            "strategy_id": strategy_id,
            "strategy_change_digest": strategy_change_digest,
            "maximum_attempts": 2,
        },
    )
    unsigned = {
        "schema": ATTEMPT_LINEAGE_SCHEMA,
        "status": "approved_independent_successor",
        "strategy_id": strategy_id,
        "strategy_class": strategy_class,
        "strategy_relation": strategy_relation,
        "strategy_change_digest": strategy_change_digest,
        "predecessor_snapshot_digest": predecessor["snapshot_digest"],
        "predecessor_remaining_attempts_retired": 1,
        "attempt_series_id": series_id,
        "successor_identity_digest": successor_identity_digest,
        "terminal_predecessor": predecessor,
        "maximum_attempts": 2,
        "attempts_inherited": 0,
        "state_action": "new_append_only_series_after_explicit_strategy_retirement",
        "state_namespace": "p16-projection-budget-attempt-series-v1",
        "attempt_receipt_schema": ATTEMPT_TRANSITION_RECEIPT_SCHEMA,
    }
    return {
        **unsigned,
        "lineage_digest": digest(
            "myuna-p16-successor-attempt-series-lineage-v2", unsigned
        ),
    }


def validate_attempt_lineage(
    value: object,
    successor_identity_value: object,
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("attempt lineage fields are invalid")
    schema = value.get("schema")
    fields = (
        _ATTEMPT_LINEAGE_V1_FIELDS
        if schema == ATTEMPT_LINEAGE_SCHEMA_V1
        else _ATTEMPT_LINEAGE_FIELDS
    )
    lineage = _exact_mapping(value, fields, "attempt lineage")
    predecessor_fields = (
        _ATTEMPT_PREDECESSOR_FIELDS
        if schema == ATTEMPT_LINEAGE_SCHEMA_V1
        else _ACTIVE_ATTEMPT_PREDECESSOR_FIELDS
    )
    predecessor = _exact_mapping(
        lineage["terminal_predecessor"],
        predecessor_fields,
        "terminal attempt predecessor",
    )
    for field, item in predecessor.items():
        if field.endswith("digest") or field.endswith("sha256"):
            _hex(item, f"attempt predecessor {field}")
    successor_identity = _exact_mapping(
        successor_identity_value, _BUNDLE_IDENTITY_FIELDS, "attempt successor identity"
    )
    expected = (
        _build_legacy_attempt_lineage(successor_identity)
        if schema == ATTEMPT_LINEAGE_SCHEMA_V1
        else build_attempt_lineage(successor_identity)
    )
    if lineage != expected:
        raise ValueError("attempt lineage drifted")
    return lineage


def validate_bundle(value: object) -> dict[str, object]:
    bundle = _exact_mapping(value, _BUNDLE_FIELDS, "bundle")
    if bundle["schema"] != BUNDLE_SCHEMA or bundle["status"] != "built_inactive":
        raise ValueError("bundle identity is invalid")
    _hex(bundle["core_source_commit"], "core source", _HEX40)
    _hex(bundle["deploy_source_commit"], "Deploy source", _HEX40)
    _hex(bundle["controller_source_sha256"], "controller source")
    base = _exact_mapping(bundle["generation13_base"], _BASE_FIELDS, "generation13 base")
    for field, item in base.items():
        _hex(item, field)
    artifacts = _exact_mapping(bundle["artifacts"], _ARTIFACT_NAMES, "artifacts")
    for name, value_item in artifacts.items():
        artifact = _exact_mapping(value_item, _ARTIFACT_FIELDS, f"{name} artifact")
        _hex(artifact["release_digest"], f"{name} release")
        _hex(artifact["inventory_digest"], f"{name} inventory")
        if type(artifact["file_count"]) is not int or not 1 <= artifact["file_count"] <= 10000:
            raise ValueError(f"{name} file count is invalid")
    compatibility = _exact_mapping(
        bundle["compatibility"], _COMPATIBILITY_FIELDS, "compatibility"
    )
    for field in ("combined_release_set_id", "p07_release_set_id", "p08_plan_digest"):
        _hex(compatibility[field], field)
    if (
        compatibility["generation"] != 13
        or compatibility["epoch_schema"] != "myuna.external-authorized-epoch.v3"
        or not isinstance(compatibility["effective_definition_id"], str)
        or _SAFE_ID.fullmatch(compatibility["effective_definition_id"]) is None
    ):
        raise ValueError("compatibility scope is invalid")
    if bundle["content_free"] is not True:
        raise ValueError("bundle is not content-free")
    successor_identity = {
        key: bundle[key] for key in _BUNDLE_IDENTITY_FIELDS
    }
    validate_attempt_lineage(bundle["attempt_lineage"], successor_identity)
    unsigned = {key: item for key, item in bundle.items() if key != "bundle_digest"}
    if bundle["bundle_digest"] != digest("myuna-p16-phase1-t2-bundle-v3", unsigned):
        raise ValueError("bundle digest drifted")
    return bundle


def validate_checkpoint(value: object) -> dict[str, object]:
    checkpoint = _exact_mapping(value, _CHECKPOINT_FIELDS, "checkpoint")
    if (
        checkpoint["schema"] != CHECKPOINT_SCHEMA
        or checkpoint["status"] != "owner_e2e_accepted"
        or checkpoint["checkpoint_date"] != "2026-08-06 Asia/Shanghai"
        or checkpoint["observation_scope"] != "accepted_checkpoint_not_fresh_live"
        or checkpoint["content_free"] is not True
        or checkpoint["private_content_read"] is not False
    ):
        raise ValueError("checkpoint identity is invalid")
    source = _exact_mapping(
        checkpoint["source"], frozenset({"core_commit", "deploy_commit"}), "checkpoint source"
    )
    _hex(source["core_commit"], "checkpoint Core source", _HEX40)
    _hex(source["deploy_commit"], "checkpoint Deploy source", _HEX40)
    if source != _ACCEPTED_CHECKPOINT_SOURCE:
        raise ValueError("checkpoint source identity drifted")
    for field in ("plan_digest", "combined_release_set_id", "p07_release_set_id"):
        _hex(checkpoint[field], field)
    artifacts = _exact_mapping(checkpoint["artifacts"], _BASE_FIELDS, "checkpoint artifacts")
    for field, item in artifacts.items():
        _hex(item, field)
    if (
        not isinstance(checkpoint["effective_definition_id"], str)
        or _SAFE_ID.fullmatch(checkpoint["effective_definition_id"]) is None
    ):
        raise ValueError("checkpoint definition is invalid")
    epoch = _exact_mapping(
        checkpoint["epoch"],
        frozenset({"generation", "epoch_id", "schema"}),
        "checkpoint epoch",
    )
    if (
        epoch["generation"] != 13
        or epoch["schema"] != "myuna.external-authorized-epoch.v3"
        or not isinstance(epoch["epoch_id"], str)
        or _SAFE_ID.fullmatch(epoch["epoch_id"]) is None
    ):
        raise ValueError("checkpoint epoch is invalid")
    aggregate = _exact_mapping(
        checkpoint["aggregate"],
        frozenset(
            {
                "selected_revision",
                "max_revision",
                "turns",
                "delivered_intents",
                "summaries",
                "pending",
                "queued",
                "abandoned",
                "blocked",
            }
        ),
        "checkpoint aggregate",
    )
    if any(type(item) is not int or item < 0 for item in aggregate.values()):
        raise ValueError("checkpoint aggregate is invalid")
    if aggregate != _ACCEPTED_AGGREGATE:
        raise ValueError("checkpoint aggregate drifted")
    service = _exact_mapping(
        checkpoint["service_acceptance"],
        frozenset({"core", "telegram_runtime", "telegram_socket", "p08_service", "p08_socket", "restart_class"}),
        "checkpoint service acceptance",
    )
    if any(service[field] != "active_running" for field in service if field != "restart_class"):
        raise ValueError("checkpoint service state is invalid")
    if service["restart_class"] != "zero_over_two_observations":
        raise ValueError("checkpoint restart class is invalid")
    if checkpoint["receipt_schema"] != "myuna.p08-p07-generation13-receipt.v1":
        raise ValueError("checkpoint receipt schema is invalid")
    return checkpoint


def build_selector(bundle_value: object) -> dict[str, object]:
    bundle = validate_bundle(bundle_value)
    artifacts = bundle["artifacts"]
    selector = {
        "schema": INCIDENT_HISTORY_SELECTOR_SCHEMA,
        "status": "approved",
        "channel": "telegram",
        "marker_path": str(INCIDENT_HISTORY_MARKER),
        "history_root": str(INCIDENT_HISTORY_ROOT),
        "capacity": 128,
        "bundle_digest": bundle["bundle_digest"],
        "core_release_digest": artifacts["core"]["release_digest"],
        "runtime_release_digest": artifacts["telegram_runtime"]["release_digest"],
        "plugin_release_digest": artifacts["telegram_plugin"]["release_digest"],
        "adapter_release_digest": artifacts["p16_adapter"]["release_digest"],
        "core_source_commit": bundle["core_source_commit"],
        "deploy_source_commit": bundle["deploy_source_commit"],
        "public_reply_contract": "unchanged",
        "write_boundary": "post_response_failure_only",
    }
    return validate_incident_history_selector(selector)


def _marker_contract() -> dict[str, object]:
    marker = {
        "schema": MARKER_CONTRACT_SCHEMA,
        "path": str(INCIDENT_HISTORY_MARKER),
        "type": "regular_no_symlink",
        "owner": "root",
        "group": "root",
        "mode": "0440",
        "install_state": "absent",
        "enable_order": "selector_then_marker",
        "disable_order": "marker_then_selector",
    }
    marker["marker_contract_digest"] = digest(
        "myuna-p16-incident-history-marker-contract-v1", marker
    )
    return marker


def build_design_plan(bundle_value: object, checkpoint_value: object) -> dict[str, object]:
    bundle = validate_bundle(bundle_value)
    checkpoint = validate_checkpoint(checkpoint_value)
    base = bundle["generation13_base"]
    if checkpoint["artifacts"] != base:
        raise ValueError("checkpoint and bundle generation13 artifacts differ")
    compatibility = bundle["compatibility"]
    if (
        checkpoint["combined_release_set_id"] != compatibility["combined_release_set_id"]
        or checkpoint["p07_release_set_id"] != compatibility["p07_release_set_id"]
        or checkpoint["effective_definition_id"] != compatibility["effective_definition_id"]
        or checkpoint["epoch"]["generation"] != compatibility["generation"]
        or checkpoint["epoch"]["schema"] != compatibility["epoch_schema"]
    ):
        raise ValueError("checkpoint compatibility drifted")
    selector = build_selector(bundle)
    selector_digest = digest("myuna-p16-incident-history-selector-v1", selector)
    marker = _marker_contract()
    checkpoint_digest = digest("myuna-p16-generation13-accepted-checkpoint-v1", checkpoint)
    unsigned = {
        "schema": PLAN_SCHEMA,
        "status": "design_ready_live_preflight_required",
        "activation_ready": False,
        "activation_authority": "not_granted",
        "fresh_live_preflight_required": True,
        "bundle_digest": bundle["bundle_digest"],
        "attempt_lineage": bundle["attempt_lineage"],
        "source": {
            "core_commit": bundle["core_source_commit"],
            "deploy_commit": bundle["deploy_source_commit"],
        },
        "generation13_accepted_checkpoint": {
            "checkpoint_digest": checkpoint_digest,
            "observation_scope": checkpoint["observation_scope"],
            "combined_release_set_id": checkpoint["combined_release_set_id"],
            "p07_release_set_id": checkpoint["p07_release_set_id"],
            "artifacts": checkpoint["artifacts"],
            "effective_definition_id": checkpoint["effective_definition_id"],
            "epoch": checkpoint["epoch"],
            "aggregate": checkpoint["aggregate"],
            "service_acceptance": checkpoint["service_acceptance"],
        },
        "selector": {"payload": selector, "selector_digest": selector_digest},
        "marker": marker,
        "least_privilege": {
            "service_user": "myuna-gateway-telegram",
            "service_group": "myuna-gateway-telegram",
            "selector_owner": "root",
            "selector_group": "myuna-gateway-telegram",
            "selector_mode": "0440",
            "read_write_paths": [
                "/var/lib/myuna-fault-diagnostics/incident-history-v1/telegram"
            ],
            "capability_bounding_set": "empty",
            "no_new_privileges": True,
            "acl_policy": "no_unlisted_entries",
        },
        "storage": {
            "parent": {
                "path": str(INCIDENT_HISTORY_ROOT),
                "type": "directory_no_symlink",
                "owner": "root",
                "group": "root",
                "mode": "0751",
                "acl": "no_unlisted_entries",
            },
            "channel": {
                "path": str(INCIDENT_HISTORY_ROOT / "telegram"),
                "type": "directory_no_symlink",
                "owner": "myuna-gateway-telegram",
                "group": "myuna-gateway-telegram",
                "mode": "0700",
                "acl": "no_unlisted_entries",
            },
            "state_mode": "0640",
            "lock_mode": "0600",
            "capacity": 128,
            "maximum_state_bytes": 8_000_000,
            "append_semantics": "exact_duplicate_idempotent_digest_chained",
            "rollup_semantics": "bounded_manifest_digest_no_silent_overwrite",
            "durability": "exclusive_no_follow_lock_atomic_replace_file_and_directory_fsync",
            "drift_policy": "type_permission_symlink_crash_replay_concurrency_digest_drift_fail_closed",
        },
        "receipt": {
            "request_boundary": "authenticated_owner_private_text_after_identity_claim",
            "fields": list(INCIDENT_RECEIPT_FIELDS),
            "forbidden_fields": list(FORBIDDEN_FIELDS),
            "correlation": "actual_incident_ref_only_no_sentinel_or_fabrication",
            "public_reply_contract": "unchanged",
        },
        "canary": {
            "executor": "owner_only",
            "channel": "existing_authenticated_owner_private_telegram",
            "request_class": "one_natural_ordinary_text",
            "task_must_not_send": True,
            "expected_reply_count": 1,
            "public_reply_contract": "unchanged",
            "content_retention": "none",
            "allowed_correlation": ["utc_or_cst_time", "latency_bucket", "opaque_incident_ref_if_present"],
            "fault_injection": False,
        },
        "rollback": {
            "prestate": "fresh_exact_live_preflight_must_bind_before_mutation",
            "prestate_fields": [
                "combined_and_p07_release_sets",
                "core_runtime_plugin_p08_selectors",
                "effective_definition",
                "selector_marker_and_dropin_state",
                "service_socket_state_and_restart_counters",
                "epoch_schema_revision_turn_summary_pending_delivery_counts",
                "history_type_owner_mode_acl_size_count_and_digest_if_present",
                "runtime_config_and_credential_identity_digests",
            ],
            "backup_namespace": "p16-phase1-t2-v1/content-addressed-by-live-prestate-digest",
            "backup_properties": "immutable_exact_bytes_owner_mode_acl_type_digest",
            "disable_order": ["remove_marker", "remove_selector", "restore_release_and_unit_binding"],
            "uninstall_order": ["remove_marker", "remove_selector", "remove_dropin", "remove_unselected_artifacts"],
            "restore_service_state": "exact_fresh_prestate",
            "desired_service_state": {
                "core": "active_running",
                "telegram_runtime": "active_running",
                "telegram_socket": "active_running",
                "p08_service": "active_running",
                "p08_socket": "active_running",
            },
            "history_action": "preserve_no_delete_on_rollback_or_uninstall",
            "functional_acceptance": [
                "selected_release_identities_restored",
                "selector_and_marker_state_restored",
                "service_and_socket_state_restored",
                "restart_counters_stable",
                "history_digest_and_count_preserved",
                "public_reply_contract_unchanged",
                "no_synthetic_incident_created",
            ],
        },
        "untouched_scope": [
            "old_epoch",
            "profile",
            "session",
            "writer",
            "qq",
            "p01b",
            "p09",
            "provider",
            "model",
        ],
    }
    plan = {**unsigned, "plan_digest": digest("myuna-p16-phase1-t2-design-plan-v1", unsigned)}
    return plan


def build_preflight(bundle_value: object, checkpoint_value: object) -> dict[str, object]:
    plan = build_design_plan(bundle_value, checkpoint_value)
    result = {
        "schema": PREFLIGHT_SCHEMA,
        "status": "design_ready_live_preflight_required",
        "activation_ready": False,
        "fresh_live_preflight_required": True,
        "bundle_digest": plan["bundle_digest"],
        "plan_digest": plan["plan_digest"],
        "selector_digest": plan["selector"]["selector_digest"],
        "marker_contract_digest": plan["marker"]["marker_contract_digest"],
        "accepted_checkpoint_digest": plan["generation13_accepted_checkpoint"]["checkpoint_digest"],
        "public_reply_contract": "unchanged",
        "content_free": True,
        "private_content_read": False,
        "live_observation_performed": False,
        "mutation_performed": False,
    }
    result["preflight_digest"] = digest(
        "myuna-p16-phase1-t2-read-only-preflight-v1", result
    )
    return result
