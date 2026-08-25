"""Inactive P07/P10 reflective-diary successor source identity."""

from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Mapping

from p07_p10_memory_successor_contract_v2 import digest as predecessor_digest


SCHEMA = "myuna.p07-p10-memory-successor-contract.v3"
CALENDAR_ZONE_SELECTOR_SCHEMA = "myuna.p07-owner-private-memory-selector.v3"
PROFILE_MUTATION_COMMAND = "/Benchmark"
DIARY_PROFILE_CONSENT = False
DIARY_EGRESS_POLICY = "p07-reflective-diary-egress-v1"
DIARY_MODEL_ROLE = "p07_external_daily_reflective_diary"
P15_PROJECTION_ACTIVE = False
P07_ATTEMPTS_CONSUMED = 0
P07_ATTEMPTS_MAXIMUM = 2

SOURCE_IDENTITIES: Mapping[str, tuple[str, str]] = {
    "channels/astrbot-telegram/plugin/myuna_telegram_gateway/main.py": (
        "e7575614c089206364467f3083d044c035a8a0bb",
        "07e2e9aa89141c46d0d0e2c50e957a6f220cdc7ac19452120f66a1f968565191",
    ),
    "channels/astrbot-telegram/plugin/myuna_telegram_gateway/protocol.py": (
        "62fdfeee67c4c37ca4d6939e408d507e6155ab43",
        "7eaa4dd30d1b87572b4d3531ce07b5b776a6237914282aa5a9ded699e1313cf3",
    ),
    "scripts/build_p07_hybrid_live_releases_v1.py": (
        "a7d329dc68c6394e65ef56ed8ca2353a58b0a81b",
        "d763503dcc65f4c809c1667f49cc789f6089427c00e2311bc7fb955d95405eb5",
    ),
    "scripts/p07_owner_private_memory_runtime_v1.py": (
        "d8abd6832c789eaac9b035aa2b715503719e5ebb",
        "432e7862b318b2cde24fa1a36d1f20358f18f355eec3c59f8f7e17f8c0785e4b",
    ),
    "scripts/p07_reflective_diary_worker_v1.py": (
        "d5a52ff25933cfa30bf36f378e643d50f41aeb09",
        "c4259bc2786f8aeeb405445924540a8317e7f73840ff6ac4eaa96e32a8c4bdb3",
    ),
    "scripts/telegram_owner_runtime_gateway.py": (
        "052694c9b9f27453ffa371862173fae6dba9a8a1",
        "38bd99afd9fbd896d077f515a047a27337e372fafe26db7fd8cb6bb366da7c47",
    ),
    "tests/test_astrbot_telegram_gateway.py": (
        "5eb95867198162f8621397d3fd486d6ff429a0df",
        "1b5552184a53351a4257a70be4cd81fa2ea9969f142b7e29542f14a2788f372d",
    ),
    "tests/test_p10_check_command_ingress_v1.py": (
        "ee0d5fe1d730ff3198c597f8bde68f28b66d8717",
        "349ef8d65a1bb725337159bdd8bfa39e1218845942e701d44ed97de69bfea259",
    ),
}

_COMMIT = re.compile(r"^[0-9a-f]{40}$")


class MemorySuccessorContractRejected(RuntimeError):
    pass


def payload() -> dict[str, object]:
    return {
        "calendar_zone_selector_schema": CALENDAR_ZONE_SELECTOR_SCHEMA,
        "complete_closed_day_required": True,
        "compressed_generation13_rollback": True,
        "diary_egress_policy": DIARY_EGRESS_POLICY,
        "diary_model_role": DIARY_MODEL_ROLE,
        "diary_profile_consent": DIARY_PROFILE_CONSENT,
        "diary_selector_schema": "myuna.p07-reflective-diary-egress-selector.v1",
        "effective_definition": "v6",
        "existing_history_migration": False,
        "p07_attempts": {
            "consumed": P07_ATTEMPTS_CONSUMED,
            "maximum": P07_ATTEMPTS_MAXIMUM,
        },
        "p10_check_external_message": False,
        "p10_check_history_access": False,
        "p15_projection_active": P15_PROJECTION_ACTIVE,
        "partial_day_provider_call": False,
        "predecessor_contract_digest": predecessor_digest(),
        "profile_mutation_command": PROFILE_MUTATION_COMMAND,
        "rollback": "local-only-disabled",
        "schema": SCHEMA,
    }


def digest() -> str:
    encoded = json.dumps(
        payload(), ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return sha256(b"myuna-p07-p10-memory-successor-v3\0" + encoded).hexdigest()


def require_source_identity(
    *, core_commit: str, deploy_commit: str, files: Mapping[str, Mapping[str, str]]
) -> None:
    if _COMMIT.fullmatch(core_commit) is None or _COMMIT.fullmatch(deploy_commit) is None:
        raise MemorySuccessorContractRejected("source_commit_rejected")
    if set(files) != set(SOURCE_IDENTITIES):
        raise MemorySuccessorContractRejected("source_inventory_rejected")
    for path, expected in SOURCE_IDENTITIES.items():
        selected = files[path]
        if set(selected) != {"git_blob", "sha256"} or (
            selected["git_blob"], selected["sha256"]
        ) != expected:
            raise MemorySuccessorContractRejected("source_identity_drifted")
