#!/usr/bin/env python3
"""Inactive, content-addressable P07 lossless episodic-memory contract."""

from __future__ import annotations

from hashlib import sha256
import json
from typing import Mapping


SCHEMA = "myuna.p07-lossless-episodic-memory-contract.v1"
RELEASE_SCHEMA = "myuna.p07-lossless-episodic-memory-inactive-release.v1"
ROLLBACK_RUNTIME = "compressed-generation13"
DEFAULT_EGRESS_POLICY = "p07-episodic-egress-deny-v1"

REQUEST_MAX_CHARACTERS = 200_000
PROJECTION_MAX_CHARACTERS = 199_000
SERIALIZED_MAX_BYTES = 1_198_096
TOKEN_MAX_INPUT = 999_232


class EpisodicContractRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def canonical(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"


def digest(domain: str, payload: Mapping[str, object]) -> str:
    return sha256(domain.encode("ascii") + b"\0" + canonical(payload).rstrip()).hexdigest()


def contract_payload() -> dict[str, object]:
    return {
        "archive": {
            "automatic_complete_delivered_turn_append": True,
            "complete_turn_unit": "one_owner_input_plus_one_delivered_myuna_reply",
            "cross_epoch_release_retention": True,
            "failure_half_turn_is_complete": False,
            "image_bytes_archived": False,
            "raw_is_sole_factual_authority": True,
            "rewrite_or_compaction": False,
            "text_and_authorized_image_description_only": True,
        },
        "calendar": {
            "default_zone": "Asia/Shanghai",
            "relative_date_maps_zone_day_to_utc_interval": True,
            "supported_zones": ["America/Los_Angeles", "Asia/Shanghai"],
            "utc_authoritative": True,
        },
        "compatibility": {
            "p01_visual_semantics_unchanged": True,
            "p10_check_isolated": True,
            "p16_attempt_lineage_unchanged": True,
            "v7_1_ordered_observer_semantics_unchanged": True,
        },
        "context": {
            "compressed_rollback": ROLLBACK_RUNTIME,
            "fixed_turn_ceiling": None,
            "no_summary_diagnostic": "all_complete_raw_or_fail_closed",
            "production": "raw_first_relevant_older_raw_plus_recent_raw_tail",
            "request_max_characters": REQUEST_MAX_CHARACTERS,
            "projection_max_characters": PROJECTION_MAX_CHARACTERS,
            "serialized_max_bytes": SERIALIZED_MAX_BYTES,
            "token_max_input": TOKEN_MAX_INPUT,
        },
        "diary": {
            "automatic_intended": True,
            "entry_authority": "myuna_subjective_perspective_not_fact_authority",
            "fact_reflection_uncertainty_intention_typed": True,
            "failure_blocks_archive_or_chat": False,
            "late_backfill_label_required": True,
            "profile_benchmark_p08_mutation": False,
            "revisions_append_only": True,
        },
        "episodic": {
            "capsule_of_capsule": False,
            "cumulative_summary": False,
            "index_authority": False,
            "raw_preferred": True,
            "rebuildable": True,
            "transient_recap_writeback": False,
        },
        "egress": {
            "default_policy": DEFAULT_EGRESS_POLICY,
            "historical_private_raw_selected_live": False,
            "policy_digest_required": True,
        },
        "ownership": {
            "active_temporal_validity_and_expiry": "P08",
            "lossless_raw_episodic_diary": "P07",
            "prompt_orchestration": "P15",
            "trusted_time_provider": "P10-B",
        },
        "priority": [
            "memory_foundation",
            "provenance_backed_information",
            "safe_server_computer_actions",
            "v7_1_live_and_optimization",
        ],
        "schema": SCHEMA,
        "semantic_boundary": {
            "archive_and_index_confirmation_required": False,
            "benchmark_profile_proposal_first": True,
            "subjective_state_auto_promotion": False,
            "temporal_validity_auto_profile_promotion": False,
        },
        "temporal_validity": {
            "active_layer_all_nonconflicting_or_typed_overflow": True,
            "expiry_deletes_or_migrates_raw": False,
            "interval_states": [
                "planned",
                "observed",
                "confirmed_started",
                "changed",
                "ended",
                "cancelled",
            ],
            "p07_duplicates_p08_store": False,
            "span_episode_raw_preferred": True,
        },
        "trusted_time": {
            "archive_survives_unavailable_time": True,
            "background_polling": False,
            "exact_calendar_on_unresolved": False,
            "one_sample_per_turn": True,
            "provider_owner": "P10-B",
            "unresolved_correction_append_only": True,
        },
        "t1_inactive": {
            "archive_population": False,
            "diary_schedule": False,
            "live_selector": False,
            "migration": False,
            "provider_call": False,
            "writer": False,
        },
    }


def contract_digest() -> str:
    return digest("myuna-p07-lossless-episodic-memory-contract-v1", contract_payload())


def require_exact_contract(payload: Mapping[str, object]) -> None:
    if dict(payload) != contract_payload():
        raise EpisodicContractRejected("episodic_contract_drifted")
