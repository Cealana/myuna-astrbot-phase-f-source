#!/usr/bin/env python3
"""Closed identities for the P07/P10 non-resetting policy-overlay strategy.

This module is intentionally source-only.  It defines the immutable predecessor,
attempt-lineage and current-source identities that a future live controller must
bind before it may delegate to the existing P07 policy-overlay transaction.
"""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Mapping


SCHEMA = "myuna.p07-p10-composite-overlay-contract.v1"
BUNDLE_SCHEMA = "myuna.p07-p10-composite-overlay-bundle.v1"
PLAN_SCHEMA = "myuna.p07-p10-composite-overlay-plan.v1"
PREFLIGHT_SCHEMA = "myuna.p07-p10-composite-overlay-preflight.v1"

PARENT_RELEASE_SET_ID = (
    "8d6f9df8f33cb573ba8ef1f4761acaef6c6b1acd831eed529ff6666e5afe8b32"
)
PARENT_MANIFEST_SHA256 = (
    "a0a2d2fb32f8f39adbe4f92501b5d737f89984bf3b9b0ff5900b2e8d81eeac5b"
)
PARENT_SELECTOR_SHA256 = (
    "55775bba2f38a708ca0feb9ae50e5a7bdfbb6ddcf21a255d02fdb34847bc559f"
)
PARENT_EPOCH_ID = "telegram-owner-private-external-d-reset-v7"
EFFECTIVE_V6_SHA256 = (
    "1cfa9213b3262f24dd322880585018c8f4ccb0fb1d1aa95e3ec52b5145cbf003"
)
COMPRESSED_RUNTIME_PROFILE = "p07-hybrid-v2"
VERBATIM_POLICY_VERSION = "p07-hybrid-verbatim-first-v1"

REQUEST_MAX_CHARACTERS = 200_000
PROJECTION_MAX_CHARACTERS = 199_000
PROJECTION_MAX_SERIALIZED_BYTES = 1_198_096
PROJECTION_MAX_TOKENS = 999_232
PROJECTION_MAX_COMPLETE_TURNS = 64

P07_REJECTED_CALL_HANDOFF_SHA256 = (
    "2b8ff2409791e1e7e66b53e8063d3310f63aedf0c308ebe0bf1d48ee588e0379"
)
P10_HANDOFF_SHA256 = (
    "4d796cccf8d62ab5639f8166e50a4ad4dc49fa5216edff45476d3a4e7440e9f4"
)
P09_HANDOFF_SHA256 = (
    "4bf4e15ce41c72e8287f26565a5980191ba6eada1083e74ed533104780109c94"
)
P16_HANDOFF_SHA256 = (
    "5f118c109ea1fd2c2e550a7cf0718666c600b385d908cf94854922c5ec0a3da5"
)
P01_HANDOFF_SHA256 = (
    "080be338c589689f3d43b1bf97753b66152817a404b3c1dbc8d035ed9cd2fbd6"
)

P16_BUNDLE_ID = (
    "f40c40b241f533c96681f521dbf38edd679246dc34604558436d3fe258683371"
)
P16_SERIES_ID = (
    "ff1bdc988477e0933eb945887bf274187a6babee4d6902c51fa2537f968f7805"
)
P16_PLAN_SHA256 = (
    "675f461f39742cff5188ef560ddbe50300a9b4b6dcc40e4dfb48678c609955d5"
)
P16_RECEIPT_SHA256 = (
    "1d708c6ed927a96cba200cc430af5bfc7137db1316b47f2765f12df9fd5a181b"
)
P16_ATTEMPT_FILE_SHA256 = (
    "da6a41e17ec88ee2d3dd7ea54feec1b277b3862aca93a2f8861235b31969d7fb"
)
P16_MARKER_SHA256 = (
    "949bc5034c4de6085f351709582a5b827b5e7e70d68258c243618d1a672e5d7f"
)
P16_SELECTOR_SHA256 = (
    "4ba93b342a92a04f491048ce209afa0a35966add4d2eabd18f8de7f0c5c2c413"
)
P16_MAXIMUM_ATTEMPTS = 2
P16_CONSUMED_ATTEMPTS = 1

P01_STRATEGY_ID = (
    "10b60c58c577688dcb3f2c63e53b904f8e9f6938fbf28509255f41b85d61106b"
)
P01_MAXIMUM_ATTEMPTS = 2
P01_CONSUMED_ATTEMPTS = 2

P07_MAXIMUM_ATTEMPTS = 2
P07_CONSUMED_ATTEMPTS = 0
P07_REJECTED_FORMAL_CALLS = 1

FUTURE_ACTIVATION_ORDER = (
    "plan_bound_backup",
    "consume_shared_p07_attempt",
    "install_inactive_releases",
    "stop_services",
    "write_core_runtime_bindings",
    "write_overlay_manifest_state_selector_marker",
    "start_services",
    "verify_fixed_fields",
)
FUTURE_ROLLBACK_ORDER = (
    "remove_overlay_marker",
    "preserve_failed_overlay_documents",
    "restore_core_runtime_bindings",
    "restart_services",
    "verify_effective_v6_compressed_parent_twice",
)

P10_SOURCE_IDENTITIES: Mapping[str, tuple[str, str]] = {
    "channels/astrbot-telegram/plugin/myuna_telegram_gateway/main.py": (
        "e7575614c089206364467f3083d044c035a8a0bb",
        "07e2e9aa89141c46d0d0e2c50e957a6f220cdc7ac19452120f66a1f968565191",
    ),
    "channels/astrbot-telegram/plugin/myuna_telegram_gateway/protocol.py": (
        "9edc478bba0c280b5c5b5828cb3a7e145f02dd38",
        "cd4403ca739f0920807f3f86259e87ff06966ab7642bdea812b95a72e2a5bfe1",
    ),
    "scripts/telegram_owner_runtime_gateway.py": (
        "4f81da83001607188dfcd1689d48ba327bd7d92d",
        "8e7b5da0155bdb31475808931a7baee6ee623b55425e22cc8ef2235d8b05001e",
    ),
    "tests/test_astrbot_telegram_gateway.py": (
        "b9a3e900b8ac5c786b44e4b24afa9ca87fc0384d",
        "16ed8dd26db70e7c5850b1d3b49dd595131b015d5c0391d0105069798c8246e1",
    ),
    "tests/test_p10_check_command_ingress_v1.py": (
        "ee0d5fe1d730ff3198c597f8bde68f28b66d8717",
        "349ef8d65a1bb725337159bdd8bfa39e1218845942e701d44ed97de69bfea259",
    ),
}

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


class CompositeContractRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def require(condition: bool, code: str) -> None:
    if not condition:
        raise CompositeContractRejected(code)


def canonical(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"


def digest(domain: str, payload: Mapping[str, object]) -> str:
    return sha256(
        domain.encode("ascii") + b"\0" + canonical(payload).rstrip(b"\n")
    ).hexdigest()


def contract_payload() -> dict[str, object]:
    return {
        "attempt_lineages": {
            "p01": {
                "consumed": P01_CONSUMED_ATTEMPTS,
                "maximum": P01_MAXIMUM_ATTEMPTS,
                "strategy_id": P01_STRATEGY_ID,
            },
            "p07": {
                "consumed": P07_CONSUMED_ATTEMPTS,
                "maximum": P07_MAXIMUM_ATTEMPTS,
                "rejected_formal_calls": P07_REJECTED_FORMAL_CALLS,
                "shared_state_namespace": "p07-policy-overlay-v1",
            },
            "p16": {
                "bundle_id": P16_BUNDLE_ID,
                "consumed": P16_CONSUMED_ATTEMPTS,
                "maximum": P16_MAXIMUM_ATTEMPTS,
                "plan_sha256": P16_PLAN_SHA256,
                "receipt_sha256": P16_RECEIPT_SHA256,
                "series_id": P16_SERIES_ID,
            },
        },
        "boundaries": {
            "check_external_message": False,
            "check_hybrid_epoch_read": False,
            "check_hybrid_epoch_write": False,
            "check_short_term_history_read": False,
            "check_short_term_history_write": False,
            "fresh_epoch": False,
            "persistent_data_rewrite": False,
            "p09_v7_selected": False,
            "p16_attempt_consumed": False,
        },
        "future_activation_order": list(FUTURE_ACTIVATION_ORDER),
        "future_rollback_order": list(FUTURE_ROLLBACK_ORDER),
        "evidence": {
            "p01_handoff_sha256": P01_HANDOFF_SHA256,
            "p07_rejected_call_handoff_sha256": P07_REJECTED_CALL_HANDOFF_SHA256,
            "p09_handoff_sha256": P09_HANDOFF_SHA256,
            "p10_handoff_sha256": P10_HANDOFF_SHA256,
            "p16_attempt_file_sha256": P16_ATTEMPT_FILE_SHA256,
            "p16_handoff_sha256": P16_HANDOFF_SHA256,
            "p16_marker_sha256": P16_MARKER_SHA256,
            "p16_selector_sha256": P16_SELECTOR_SHA256,
        },
        "parent": {
            "effective_v6_sha256": EFFECTIVE_V6_SHA256,
            "epoch_id": PARENT_EPOCH_ID,
            "manifest_sha256": PARENT_MANIFEST_SHA256,
            "release_set_id": PARENT_RELEASE_SET_ID,
            "selector_sha256": PARENT_SELECTOR_SHA256,
        },
        "policy": {
            "compressed_rollback": "overlay_absent_parent_exact",
            "maximum_complete_turns": PROJECTION_MAX_COMPLETE_TURNS,
            "projection_max_characters": PROJECTION_MAX_CHARACTERS,
            "projection_max_serialized_bytes": PROJECTION_MAX_SERIALIZED_BYTES,
            "projection_max_tokens": PROJECTION_MAX_TOKENS,
            "request_max_characters": REQUEST_MAX_CHARACTERS,
            "version": VERBATIM_POLICY_VERSION,
        },
        "profile": {
            "effective_definition": "v6",
            "p09_affinity_active": False,
            "runtime_profile": COMPRESSED_RUNTIME_PROFILE,
            "v7_selected": False,
        },
        "schema": SCHEMA,
    }


def contract_digest() -> str:
    return digest("myuna-p07-p10-composite-overlay-contract-v1", contract_payload())


def require_exact_contract(payload: Mapping[str, object]) -> None:
    require(dict(payload) == contract_payload(), "composite_contract_drifted")


def require_source_identity(
    *,
    core_commit: str,
    deploy_commit: str,
    p10_files: Mapping[str, Mapping[str, str]],
) -> None:
    require(
        _COMMIT.fullmatch(core_commit) is not None
        and _COMMIT.fullmatch(deploy_commit) is not None,
        "composite_source_commit_rejected",
    )
    require(set(p10_files) == set(P10_SOURCE_IDENTITIES), "p10_source_inventory_rejected")
    for path, (blob, content_sha256) in P10_SOURCE_IDENTITIES.items():
        selected = p10_files[path]
        require(
            set(selected) == {"git_blob", "sha256"}
            and selected["git_blob"] == blob
            and selected["sha256"] == content_sha256,
            "p10_source_identity_drifted",
        )


def require_digest(value: str, code: str) -> None:
    require(_SHA256.fullmatch(value) is not None, code)


def require_regular_digest(path: Path, expected: str, code: str) -> None:
    require_digest(expected, code)
    try:
        status = path.lstat()
        content = path.read_bytes()
    except OSError:
        raise CompositeContractRejected(code) from None
    require(path.is_file() and not path.is_symlink(), code)
    require(sha256(content).hexdigest() == expected and status.st_nlink == 1, code)
