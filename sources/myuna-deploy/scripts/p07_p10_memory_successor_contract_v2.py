"""Inactive P07/P10 source-identity successor for the memory-first T1 boundary."""

from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Mapping

from p07_p10_composite_overlay_contract_v1 import contract_digest as predecessor_digest


SCHEMA = "myuna.p07-p10-memory-successor-contract.v2"
CALENDAR_ZONE_SELECTOR_SCHEMA = "myuna.p07-owner-private-memory-selector.v2"
PROFILE_MUTATION_COMMAND = "/Benchmark"
DIARY_PROFILE_CONSENT = False
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
    "scripts/telegram_owner_runtime_gateway.py": (
        "3e3666b869ec931ad4fd69ca5dcd33200559d01b",
        "6dda5e0c62236ab2c09d8d682c0b5f6732dfd512d0af110d61ce9ea91db97555",
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
        "compressed_generation13_rollback": True,
        "diary_profile_consent": DIARY_PROFILE_CONSENT,
        "effective_definition": "v6",
        "p07_attempts": {
            "consumed": P07_ATTEMPTS_CONSUMED,
            "maximum": P07_ATTEMPTS_MAXIMUM,
        },
        "p10_check_external_message": False,
        "p10_check_history_access": False,
        "p15_projection_active": P15_PROJECTION_ACTIVE,
        "predecessor_contract_digest": predecessor_digest(),
        "profile_mutation_command": PROFILE_MUTATION_COMMAND,
        "schema": SCHEMA,
    }


def digest() -> str:
    encoded = json.dumps(
        payload(), ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return sha256(b"myuna-p07-p10-memory-successor-v2\0" + encoded).hexdigest()


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
