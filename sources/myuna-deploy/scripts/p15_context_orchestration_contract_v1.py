#!/usr/bin/env python3
"""Inactive, content-free P15 source identity contract."""

from __future__ import annotations

from hashlib import sha256
import json
from typing import Mapping


SCHEMA = "myuna.p15-deploy-contract.v1"
CORE_MODULE_SCHEMA = "myuna.p15-cross-source-orchestration-contract.v1"
GENERATION12_CORE_COMMIT = "8529ef1f5f24ded15824bdbf0c6f826b0539b8d4"
GENERATION12_DEPLOY_COMMIT = "2819d5cf8fd979ffa1c0bf26b0eaa7411663557b"
GENERATION12_RELEASE_SET_SCHEMA = "myuna.p07-d-release-set.v1"
GENERATION12_COMBINED_SCHEMA = "myuna.p08-p07-combined-release-set.v1"
GENERATION12_EPOCH_SCHEMA = "myuna.external-authorized-epoch.v3"
GENERATION12_EPOCH_ID = "telegram-owner-private-external-d-reset-v6"
P09_SOURCE_MAIN_COMMIT = "31250bbd015c07ddefaca889d8c56ddf28971a12"
P09_SOURCE_MAIN_TREE = "e23d1259c233a6ab88cfd9b6c30c7463cf383e03"
P09_SCHEMA = "myuna.structured-affinity.v1"
P09_CAPABILITY_ID = "p09-v7-structured-affinity-v1"
P09_CAPABILITY_DIGEST = "bc28be2f125bb7099859dd366d54d59f48053db670ad2d841482c15fa50d5096"
P09_P15_INTERFACE_SCHEMA = "myuna.affinity-relevance-port.v1"


class P15DeployContractError(ValueError):
    """Content-free dependency mismatch."""


def canonical_bytes(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def contract_payload() -> dict[str, object]:
    return {
        "activation_authorized": False,
        "core_module_schema": CORE_MODULE_SCHEMA,
        "generation12": {
            "combined_schema": GENERATION12_COMBINED_SCHEMA,
            "core_commit": GENERATION12_CORE_COMMIT,
            "deploy_commit": GENERATION12_DEPLOY_COMMIT,
            "epoch_id": GENERATION12_EPOCH_ID,
            "epoch_schema": GENERATION12_EPOCH_SCHEMA,
            "generation": 12,
            "release_set_schema": GENERATION12_RELEASE_SET_SCHEMA,
        },
        "p09": {
            "capability_digest": P09_CAPABILITY_DIGEST,
            "capability_id": P09_CAPABILITY_ID,
            "p15_interface_schema": P09_P15_INTERFACE_SCHEMA,
            "prompt_projection_active": False,
            "schema": P09_SCHEMA,
            "source_main_commit": P09_SOURCE_MAIN_COMMIT,
            "source_main_tree": P09_SOURCE_MAIN_TREE,
        },
        "runtime_builder_present": False,
        "schema": SCHEMA,
        "source_only": True,
    }


def contract_digest() -> str:
    return sha256(canonical_bytes(contract_payload())).hexdigest()


def verify_dependency_identity(
    *,
    core_commit: str,
    deploy_commit: str,
    p09_source_main_commit: str,
    p09_source_main_tree: str,
    p09_capability_digest: str,
) -> dict[str, object]:
    expected = (
        GENERATION12_CORE_COMMIT,
        GENERATION12_DEPLOY_COMMIT,
        P09_SOURCE_MAIN_COMMIT,
        P09_SOURCE_MAIN_TREE,
        P09_CAPABILITY_DIGEST,
    )
    observed = (
        core_commit,
        deploy_commit,
        p09_source_main_commit,
        p09_source_main_tree,
        p09_capability_digest,
    )
    if observed != expected:
        raise P15DeployContractError("p15_dependency_identity_mismatch")
    return {
        "activation_authorized": False,
        "contract_digest": contract_digest(),
        "dependency_identity": "verified",
        "schema": SCHEMA,
        "source_only": True,
    }


if __name__ == "__main__":
    print(json.dumps(contract_payload(), separators=(",", ":"), sort_keys=True))
