#!/usr/bin/env python3
"""Production-bound runtime seam for the P07 full-mutation transaction.

This module is intentionally additive.  It treats the earlier transactional
controller as an immutable parent contract, binds a new artifact manifest and
namespace, and supplies the production command/ledger/preflight seam that the
parent source deliberately did not contain.  Importing the module has no
filesystem or service side effects.
"""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
import errno
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import sqlite3
import stat
import subprocess
import secrets
from typing import Callable, Mapping, Protocol

import p07_full_mutation_set_v1 as mutation
import p07_owner_private_memory_production_plan as production
import p07_owner_private_memory_runtime_artifact_v1 as runtime_artifact
import p07_owner_private_memory_transactional_controller as parent
import p07_transactional_plugin_artifact_v1 as plugin_artifact
import p08_temporal_gateway_v1 as p08_gateway


HISTORICAL_TERMINAL_RUNTIME_SOURCE_ID = (
    "p07-owner-private-memory-transactional-runtime-source-bound-runtime-"
    "plugin-package-historical-evidence-artifact-root-v3"
)
HISTORICAL_TERMINAL_CLI_RESULT_SCHEMA = (
    "myuna.p07-owner-private-memory-transactional-runtime-cli-result.v5"
)
SOURCE_ID = (
    "p07-owner-private-memory-transactional-runtime-source-bound-runtime-"
    "plugin-package-source-first-single-factual-store-v8"
)
SOURCE_SCHEMA = "myuna.p07-owner-private-memory-transactional-runtime.v10"
PLAN_SCHEMA = "myuna.p07-owner-private-memory-transactional-runtime-plan.v5"
NAMESPACE_SCHEMA = "myuna.p07-owner-private-memory-transactional-runtime-namespace.v5"
LEDGER_SCHEMA = "myuna.p07-owner-private-memory-transactional-runtime-ledger.v5"
ATTEMPT_RECEIPT_SCHEMA = "myuna.p07-owner-private-memory-transactional-runtime-attempt-receipt.v5"
PREFLIGHT_SCHEMA = "myuna.p07-owner-private-memory-transactional-runtime-preflight.v5"
TERMINAL_RECEIPT_SCHEMA = "myuna.p07-owner-private-memory-transactional-runtime-receipt.v5"
BUNDLE_SCHEMA = "myuna.p07-owner-private-memory-transactional-runtime-bundle.v10"
BUNDLE_ID_DOMAIN = "myuna_p07_transactional_runtime_inactive_bundle_v10"
TERMINAL_BUNDLE_SCHEMA = "myuna.p07-owner-private-memory-transactional-runtime-bundle.v5"
TERMINAL_BUNDLE_ID_DOMAIN = "myuna_p07_transactional_runtime_inactive_bundle_v5"
REQUEST_SCHEMA = "myuna.p07-owner-private-memory-transactional-runtime-request.v5"
CLI_RESULT_SCHEMA = "myuna.p07-owner-private-memory-transactional-runtime-cli-result.v7"
PACKAGE_SCHEMA = "myuna.p07-owner-private-memory-after-payload-package.v1"
PACKAGE_CONTEXT_SCHEMA = "myuna.p07-owner-private-memory-after-payload-context.v3"
FRESH_PACKAGE_CONTEXT_SCHEMA = (
    "myuna.p07-owner-private-memory-after-payload-context.v4"
)
PACKAGE_RECEIPT_SCHEMA = "myuna.p07-owner-private-memory-after-payload-receipt.v1"
PACKAGE_COMPLETION_SCHEMA = "myuna.p07-owner-private-memory-after-payload-completion.v1"
REQUEST_CONSTRUCTOR_SCHEMA = (
    "myuna.p07-owner-private-memory-source-owned-request-constructor.v1"
)
REQUEST_CONSTRUCTOR_RECEIPT_SCHEMA = (
    "myuna.p07-owner-private-memory-source-owned-request-receipt.v1"
)
REQUEST_CONSTRUCTOR_COMPLETION_SCHEMA = (
    "myuna.p07-owner-private-memory-source-owned-request-completion.v1"
)
REQUEST_COLLECTION_SCHEMA = (
    "myuna.p07-owner-private-memory-source-owned-request-collection.v1"
)
FAILED_REQUEST_CONTINUATION_SCHEMA = (
    "myuna.p07-owner-private-memory-failed-request-continuation.v1"
)
FAILED_REQUEST_CONTINUATION_RECEIPT_SCHEMA = (
    "myuna.p07-owner-private-memory-failed-request-continuation-receipt.v1"
)
FAILED_REQUEST_CONTINUATION_COMPLETION_SCHEMA = (
    "myuna.p07-owner-private-memory-failed-request-continuation-completion.v1"
)
FAILED_REQUEST_CONTINUATION_STORAGE_SCHEMA = (
    "myuna.p07-owner-private-memory-failed-request-continuation-storage.v1"
)
IMMUTABLE_CONTINUATION_REFERENCE_SCHEMA = (
    "myuna.p07-owner-private-memory-immutable-continuation-reference.v3"
)
HISTORICAL_REQUEST_EVIDENCE_STORAGE_SCHEMA = (
    "myuna.p07-owner-private-memory-historical-request-evidence-storage.v1"
)
FRESH_STRATEGY_SCHEMA = (
    "myuna.p07-owner-private-memory-immutable-continuation-fresh-strategy.v3"
)
SOURCE_OWNED_ARTIFACT_ROOT_SCHEMA = (
    "myuna.p07-owner-private-memory-source-owned-artifact-roots.v1"
)
STATUS_INVOCATION_SCHEMA = (
    "myuna.p07-owner-private-memory-content-free-status-invocation.v1"
)
STATUS_INVOCATION_RESULT_SCHEMA = (
    "myuna.p07-owner-private-memory-content-free-status-invocation-result.v1"
)
STATUS_INVOCATION_COMPLETION_SCHEMA = (
    "myuna.p07-owner-private-memory-content-free-status-invocation-completion.v1"
)
REJECTION_STRATEGY_CONTEXT_SCHEMA = (
    "myuna.p07-owner-private-memory-rejection-strategy-context.v1"
)
REQUEST_CONSTRUCTOR_SOURCE_ID = (
    "p07-owner-private-memory-source-owned-transactional-request-v1"
)
REQUEST_COLLECTION_SOURCE_ID = (
    "p07-owner-private-memory-source-owned-request-collection-v1"
)
FAILED_REQUEST_CONTINUATION_SOURCE_ID = (
    "p07-owner-private-memory-immutable-failed-request-continuation-v1"
)
FAILED_REQUEST_CONTINUATION_STORAGE_SOURCE_ID = (
    "p07-owner-private-memory-failed-request-continuation-root-owned-storage-v1"
)
IMMUTABLE_CONTINUATION_REFERENCE_SOURCE_ID = (
    "p07-owner-private-memory-immutable-continuation-reference-v3"
)
HISTORICAL_REQUEST_EVIDENCE_STORAGE_SOURCE_ID = (
    "p07-owner-private-memory-historical-request-evidence-root-storage-v1"
)
FRESH_STRATEGY_SOURCE_ID = (
    "p07-owner-private-memory-immutable-continuation-fresh-max1-v3"
)
SOURCE_OWNED_ARTIFACT_ROOT_SOURCE_ID = (
    "p07-owner-private-memory-source-owned-artifact-roots-v1"
)
STATUS_INVOCATION_SOURCE_ID = (
    "p07-owner-private-memory-source-owned-content-free-status-invocation-v1"
)
STRATEGY_ID = "p07-owner-private-memory-transactional-runtime-max1"
MAXIMUM_ATTEMPTS = 1

CORE_SOURCE_COMMIT = parent.CORE_SOURCE_COMMIT
CORE_SOURCE_TREE = parent.CORE_SOURCE_TREE
DEPLOY_PARENT_COMMIT = "0063eb01e958379ad2afbb0aabf4e28c91b834be"
DEPLOY_PARENT_TREE = "6d6e99da80085936062a429f32d4ac0f8b2ca32b"
PREDECESSOR_RUNTIME_BUNDLE_ID = "075f6673f8065dbd8f16b7d87d4891c7b51de7e520f98fc93b6c9a74e65319c5"
PREDECESSOR_RUNTIME_MANIFEST_SHA256 = "3ab7149ea01d987dabeacf94ba13633ed117fbd18c971a89d905bbc723e41dea"
PARENT_CONTROLLER_BUNDLE_ID = "aa8cd28e882c75f4291e4c0cdf1aedbddadb4d8343a3f99adc8820e1fe25551a"
PARENT_CONTROLLER_MANIFEST_SHA256 = "495b92396a427f86adc20fa99409f9d8f2f3329ac4a6f52245a14335ea003bda"
IMMUTABLE_LINEAGE_EVIDENCE_DIGEST = "6719219d934bbc85b41d651b05b1fc537cd1de63c15a437bbd3da8e832050ca4"

STATE_ROOT = Path(
    "/var/lib/myuna-telegram-gateway/"
    "p07-owner-private-memory-transactional-runtime-max1"
)
BACKUP_ROOT = Path(
    "/var/backups/myuna/"
    "p07-owner-private-memory-transactional-runtime-max1"
)
PACKAGE_ROOT = Path(
    "/var/backups/myuna/"
    "p07-owner-private-memory-transactional-runtime-after-payload-packages-v1"
)
SOURCE_DECLARED_LEGACY_PACKAGE_ROOT = Path(PACKAGE_ROOT.as_posix())
FRESH_STATE_PARENT = Path("/var/lib/myuna-telegram-gateway")
FRESH_BACKUP_PARENT = Path("/var/backups/myuna")
FRESH_PACKAGE_PARENT = Path("/var/backups/myuna")
FRESH_STATUS_TRUSTED_ANCESTOR = Path("/var/lib")
FRESH_STATUS_PARENT = Path(
    "/var/lib/myuna-p07-owner-private-memory-content-free-status-invocations-v1"
)
SOURCE_OWNED_CORE_ROOT = Path("/srv/myuna/repos/core")
SOURCE_OWNED_DEPLOY_ROOT = Path("/srv/myuna/repos/deploy")
SOURCE_OWNED_RUNTIME_ARTIFACT_ROOT = Path(
    "/srv/myuna/builds/p07-p08-single-nonce-stage-integration-v1-final-runtime-a"
)
SOURCE_OWNED_TRANSACTIONAL_BUNDLE_ROOT = Path(
    "/srv/myuna/builds/p07-p08-single-nonce-stage-integration-v1-final-bundle-a"
)
SOURCE_OWNED_REQUEST_ROOT = Path(
    "/run/myuna-p07-owner-private-memory-source-owned-requests-v1"
)
SOURCE_OWNED_CONTINUATION_TRUSTED_ANCESTOR = Path("/var/lib")
SOURCE_OWNED_CONTINUATION_PARENT = Path(
    "/var/lib/myuna-p07-owner-private-memory-failed-request-continuations-v1"
)
SOURCE_OWNED_CONTINUATION_ROOT = SOURCE_OWNED_CONTINUATION_PARENT / "continuations"
LEGACY_GATEWAY_CONTINUATION_ROOT = Path(
    "/var/lib/myuna-telegram-gateway/"
    "p07-owner-private-memory-failed-request-continuations-v1"
)
SOURCE_OWNED_EVIDENCE_ROOT = Path("/mnt/d/MyunaOps-Active/handoffs")
SOURCE_OWNED_OWNER_ACCOUNT = "myuna"
MAX_SOURCE_OWNED_REQUEST_BYTES = 16 * 1024 * 1024
MAX_SOURCE_OWNED_REQUEST_COUNT = 2
MAX_FAILED_REQUEST_CONTINUATION_BYTES = 16 * 1024 * 1024
SOURCE_OWNED_CONTINUATION_UID = 0
SOURCE_OWNED_CONTINUATION_GID = 0
SOURCE_OWNED_CONTINUATION_TRUSTED_ANCESTOR_MODE = 0o755
SOURCE_OWNED_CONTINUATION_PARENT_MODE = 0o700
SOURCE_OWNED_CONTINUATION_ROOT_MODE = 0o700
SOURCE_OWNED_CONTINUATION_CHILD_MODE = 0o700
SOURCE_OWNED_CONTINUATION_FILE_MODE = 0o600
MAX_PACKAGE_OPERATIONS = 8192
MAX_PACKAGE_PAYLOAD_FILES = 4096
MAX_PACKAGE_PAYLOAD_BYTES = 256 * 1024 * 1024
MAX_PACKAGE_CONTEXT_BYTES = 16 * 1024 * 1024
MAX_PACKAGE_MANIFEST_BYTES = 16 * 1024 * 1024

SYSTEMCTL = "/usr/bin/systemctl"
DOCKER = "/usr/bin/docker"
PYTHON = "/usr/bin/python3"
CORE_UNIT = "myuna-core@qq.service"
TELEGRAM_UNIT = "myuna-telegram-owner-runtime-dev.service"
TELEGRAM_SOCKET = "myuna-telegram-owner-runtime-dev.socket"
CONTAINER = "myuna-astrbot-telegram-dev"

_REQUEST_ID_PATTERN = re.compile(r"^[0-9a-f]{64}$")
TELEGRAM_RESUME_CONTROLLER = (
    "/opt/myuna/telegram-r5/releases/"
    "06d06baf23e6f97cbfa37e8e6bde12a2fa1d495e7bc0b736239655c05ac57b53/"
    "telegram_r5_boot_resume.py"
)

_SHA = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_TYPED = re.compile(r"^[a-z][a-z0-9_]{2,127}$")
_MODES = frozenset(
    {
        "offline-self-test",
        "construct-request",
        "construct-continuation",
        "prepare-continuation",
        "prepare-package",
        "backup-contract",
        "ledger-create",
        "preflight-only",
        "activate",
        "postflight",
    }
)

TERMINAL_REQUEST_ID = "e0898eb085f2d4587f329b7a5dbd6fd9846651627ffb1a98892ddb826cd78ab7"
TERMINAL_REQUEST_SHA256 = "6fd0439d2a685f8534cdb0166dcd61c5414f82abb435308de33332f0acd8dcb9"
TERMINAL_REQUEST_RECEIPT_SHA256 = "ba27b742ab20e1fdd6adb85691f8f9f25d247916aa0ab974e29e184a5429be5f"
TERMINAL_REQUEST_COMPLETION_SHA256 = "925d584d17b681ae106e9ccfea46fa238a0372811e9cc2f741347993656f1537"
TERMINAL_REQUEST_COLLECTION_DIGEST = "9f952bf2015dbdaa25dc52d7d890f46695519a1164bc65cb9446ea26601204e8"
TERMINAL_REQUEST_BUNDLE_ID = "b3e2957a2140ead9f6aa736f64b992a84dd96ba6382dde27839daf6ce95c5866"
TERMINAL_REQUEST_MANIFEST_SHA256 = "e7435dcfca9b074faf7a8daf07f5860e15eb411f24df2af678039b01efec0fa6"
TERMINAL_REQUEST_DEPLOY_COMMIT = "f25dc1820d010d6db93d0bfd8ce0b299f2047069"
TERMINAL_REQUEST_DEPLOY_TREE = "9684b0e6fb74bf180dce4b3210eb5b138e02959a"
TERMINAL_REQUEST_PAYLOAD_TARGET_OWNER_UID = 999
TERMINAL_REQUEST_PAYLOAD_TARGET_OWNER_GID = 989
HISTORICAL_REQUEST_EVIDENCE_STORAGE_UID = 0
HISTORICAL_REQUEST_EVIDENCE_STORAGE_GID = 0
HISTORICAL_REQUEST_EVIDENCE_ROOT_MODE = 0o700
HISTORICAL_REQUEST_EVIDENCE_CHILD_MODE = 0o700
HISTORICAL_REQUEST_EVIDENCE_FILE_MODE = 0o600
HISTORICAL_REQUEST_EVIDENCE_FIRST_ID = (
    "6878766e5b152c79b088b32b1b5ba0e100867f461efb9edfed2b618c8aa43d4d"
)
HISTORICAL_REQUEST_EVIDENCE_CHILDREN = {
    HISTORICAL_REQUEST_EVIDENCE_FIRST_ID: {
        "directory": {
            "gid": HISTORICAL_REQUEST_EVIDENCE_STORAGE_GID,
            "mode": HISTORICAL_REQUEST_EVIDENCE_CHILD_MODE,
            "nlink": 2,
            "type": "directory",
            "uid": HISTORICAL_REQUEST_EVIDENCE_STORAGE_UID,
        },
        "files": {
            "completion.json": {
                "gid": HISTORICAL_REQUEST_EVIDENCE_STORAGE_GID,
                "mode": HISTORICAL_REQUEST_EVIDENCE_FILE_MODE,
                "nlink": 1,
                "sha256": "0b97bdbbd660e05e330c90fd1e80faf36aec3cc1ef543d51003b9d6d122d6b86",
                "size": 416,
                "type": "regular",
                "uid": HISTORICAL_REQUEST_EVIDENCE_STORAGE_UID,
            },
            "receipt.json": {
                "gid": HISTORICAL_REQUEST_EVIDENCE_STORAGE_GID,
                "mode": HISTORICAL_REQUEST_EVIDENCE_FILE_MODE,
                "nlink": 1,
                "sha256": "1ae934520c820e8cac53019e14bd06310c3bf56727b375a049a9a69225dfd93d",
                "size": 668,
                "type": "regular",
                "uid": HISTORICAL_REQUEST_EVIDENCE_STORAGE_UID,
            },
            "request.json": {
                "gid": HISTORICAL_REQUEST_EVIDENCE_STORAGE_GID,
                "mode": HISTORICAL_REQUEST_EVIDENCE_FILE_MODE,
                "nlink": 1,
                "sha256": "e81bc41a62c24ebd8fd0da05d8b79d906dd259406ae0e5a3c618afd4d678a3ef",
                "size": 15523,
                "type": "regular",
                "uid": HISTORICAL_REQUEST_EVIDENCE_STORAGE_UID,
            },
        },
    },
    TERMINAL_REQUEST_ID: {
        "directory": {
            "gid": HISTORICAL_REQUEST_EVIDENCE_STORAGE_GID,
            "mode": HISTORICAL_REQUEST_EVIDENCE_CHILD_MODE,
            "nlink": 2,
            "type": "directory",
            "uid": HISTORICAL_REQUEST_EVIDENCE_STORAGE_UID,
        },
        "files": {
            "completion.json": {
                "gid": HISTORICAL_REQUEST_EVIDENCE_STORAGE_GID,
                "mode": HISTORICAL_REQUEST_EVIDENCE_FILE_MODE,
                "nlink": 1,
                "sha256": TERMINAL_REQUEST_COMPLETION_SHA256,
                "size": 416,
                "type": "regular",
                "uid": HISTORICAL_REQUEST_EVIDENCE_STORAGE_UID,
            },
            "receipt.json": {
                "gid": HISTORICAL_REQUEST_EVIDENCE_STORAGE_GID,
                "mode": HISTORICAL_REQUEST_EVIDENCE_FILE_MODE,
                "nlink": 1,
                "sha256": TERMINAL_REQUEST_RECEIPT_SHA256,
                "size": 668,
                "type": "regular",
                "uid": HISTORICAL_REQUEST_EVIDENCE_STORAGE_UID,
            },
            "request.json": {
                "gid": HISTORICAL_REQUEST_EVIDENCE_STORAGE_GID,
                "mode": HISTORICAL_REQUEST_EVIDENCE_FILE_MODE,
                "nlink": 1,
                "sha256": TERMINAL_REQUEST_SHA256,
                "size": 15585,
                "type": "regular",
                "uid": HISTORICAL_REQUEST_EVIDENCE_STORAGE_UID,
            },
        },
    },
}
TERMINAL_REJECTION_REASON = "production_p08_content_free_status_unavailable"
TERMINAL_REJECTION_SHA256 = "e20027fca215f339c8d2a5074c79dd287749dd7ae522827cb038a2263c19864a"
TERMINAL_HANDOFF_NAME = (
    "P07_MEMORY_ONLY_TRANSACTIONAL_T2_FAIL_CLOSED_"
    "P08_CONTENT_FREE_STATUS_UNAVAILABLE_AFTER_APPEND_ONLY_REQUEST_2026-08-09.md"
)
TERMINAL_HANDOFF_SHA256 = "4108d6bb86df3942adbc6133a918c6c29b2c957457ab87ad3b43891ad7d5afb9"

IMMUTABLE_CONTINUATION_ID = (
    "18c7d00fc612f1fba3a3800d6f11d8797a8dbc7df711f86531a578a78537f080"
)
IMMUTABLE_CONTINUATION_HANDOFF_NAME = (
    "P07_MEMORY_ONLY_TRANSACTIONAL_T2_FAIL_CLOSED_"
    "P08_CONTENT_FREE_STATUS_UNAVAILABLE_AFTER_CURRENT_CONTINUATION_2026-08-09.md"
)
IMMUTABLE_CONTINUATION_HANDOFF_SHA256 = (
    "ad27ec7449dd42c7753105fc88295b6b5eaecce71b4ace103eaa343cafb66c53"
)
IMMUTABLE_CONTINUATION_REJECTION_PAYLOAD_SHA256 = (
    "4b2627a1dfe263329bd844436979a4907a7ef66efad27642408a04cf8e576bad"
)
IMMUTABLE_CONTINUATION_REJECTION_STDOUT_SHA256 = (
    "caa97b9ecc28bd993a8aab6e398b5ad71870ae5f918f0a6a20174b0963cfb5ea"
)
IMMUTABLE_CONTINUATION_FILES = {
    "completion.json": {
        "gid": 0,
        "mode": 0o600,
        "nlink": 1,
        "sha256": "d5b0519ddd81e1a8f34c1c1fd0f9758ab87337511c61a968e96e85963563364a",
        "size": 424,
        "type": "regular",
        "uid": 0,
    },
    "continuation.json": {
        "gid": 0,
        "mode": 0o600,
        "nlink": 1,
        "sha256": "43d57aacbc4cbb29e1c3cb6113c25bb4ac9fa0e057685a21e1fa80b1d0196a41",
        "size": 4464,
        "type": "regular",
        "uid": 0,
    },
    "receipt.json": {
        "gid": 0,
        "mode": 0o600,
        "nlink": 1,
        "sha256": "d693d642e64eab9f36100d7fc4e059def66d04b9c8bcbcc62c64ab0330730d7c",
        "size": 570,
        "type": "regular",
        "uid": 0,
    },
}
IMMUTABLE_CONTINUATION_HISTORICAL_SOURCE = {
    "bundle_id": "792ed9ff61640b42fca77860cc5cce4beddd4cbabe07142f612db4f6c608d8ec",
    "bundle_manifest_sha256": "051bfeba4236515f0abc6dcb1fd0e7dfed3eee4f093c813c2941f1bd60948b68",
    "core_commit": "065ef4b647f63925ae20bb564007c127433c0b81",
    "core_tree": "e1846c2b7f5aa7feed9c8e509c857306a0163993",
    "deploy_commit": "d2fe5dc288c3f853fb38e7dbe3d5f8cc8d38722a",
    "deploy_tree": "51740e39ed8d935f8e6fc29d3a7c315a551e3419",
    "hybrid_manifest_sha256": "e5d9640960ea1d12f7615f1c2465f66e58468d53004ec90fae8ad3769738c252",
    "runtime_digest": "b6d1f8526401a626af5756622afb8b267d144ef7c59b3780fc5573411a6e69ea",
}

P08_ACCEPTED_HANDOFF_NAME = (
    "P08_POST_TARGET_METADATA_ONLY_READINESS_T2_REPAIR_TARGET_ACCEPTED_2026-08-09.md"
)
P08_ACCEPTED_HANDOFF_SHA256 = "1e287ae36ce93218ae36466a1876deb8b434e03b1d1e7ceb43aaaceee106baae"
P08_ACCEPTED_STATUS = (
    "P08_POST_TARGET_METADATA_ONLY_READINESS_T2_REPAIR_TARGET_ACCEPTED_STOP_BEFORE_"
    "P07_P10B_OWNER_E2E"
)
P08_ACCEPTED_RELEASE = "1b589a474c56e138082f014724065dd57d38440b08c57b1497e5a4cb3cbe3e06"
P08_ACCEPTED_MANIFEST_SHA256 = "8ab396cd1333d74110169f712ccadf4f7efb7488dd320255bbd6b9a2e986a7a4"
P08_ACCEPTED_SOURCE_INVENTORY_DIGEST = "ba42fee6287e681c8ad40d5d7732967e3654d6e69782691545f54e3be1b7c31e"
P08_ACCEPTED_INSTALLED_INVENTORY_DIGEST = "a3fc5583b45c28f208cf74777d4aed33afe5d031ed7ec0f30e85da88969d9ef0"
P08_ACCEPTED_CONTROLLER_SHA256 = "c4c9fe867776f17d09d9ac04788b061da54e3bdb6d35e77e5909e107d37c4c0c"
P08_ACCEPTED_SELECTOR_SHA256 = "8695f581a33c2247149c4e9d39da1cc04be7fb133a4a9d985caf26709a606326"
P08_ACCEPTED_SELECTOR_ENV_SHA256 = "26a8cf72d81470727d91b93e5b26ee54322675a1700c27c6740f552025ba50ce"
P08_ACCEPTED_PROJECTION_DIGEST = "55aa4c36d5dce2f750be01d404a4d286971e791ff757da794dc96516d79f9e51"
P08_STATUS_CLIENT_SOURCE_PATH = "scripts/p08_temporal_gateway_v1.py"
P08_STATUS_CLIENT_SOURCE_SHA256 = "41e9ce1529db4a245e1be7c3d6b11aadc0e53175cf4d5804fde41c046e1ff612"
P08_STATUS_SERVICE_ENTRYPOINT_SOURCE_PATH = "scripts/p08_temporal_service_v1.py"
P08_STATUS_SERVICE_ENTRYPOINT_SHA256 = (
    "17a1b96dd4634444ab7e90d0653512941a2fed6d70913f42ff1470c8bdd17f66"
)
P08_STATUS_FUTURE_UNIT_SOURCE_PATH = (
    "systemd/myuna-active-temporal-context-v1.service"
)
P08_STATUS_FUTURE_UNIT_SHA256 = (
    "9ae84b0f5136078327fb24b4e2b7ca8652452efe3bcbdb6a8db6285505564fd3"
)
P08_STATUS_FUTURE_SOCKET_UNIT_SOURCE_PATH = (
    "systemd/myuna-active-temporal-context-v1.socket"
)
P08_STATUS_FUTURE_SOCKET_UNIT_SHA256 = (
    "4146b1497032b1e938f16cb87f944d09336641efe8b402ab52501fb005cbc1db"
)
P08_SERVER_REJECTION_CONTRACT_IDENTITY = (
    "8acfb73fd6a53a3b1d9f7c32f958eb354cdd0728aa7c28e4cbd7bc838e012227"
)
P08_STATUS_STAGE_CONTRACT_IDENTITY = (
    "8101704662bf49a83264936aa5e083b32747d530dd1dfd5a0f2216e02d5d2d32"
)
P08_STATUS_STAGE_INACTIVE_RELEASE_DIGEST = (
    "98f9c70465605e3be262435be68c043001e7ac6e1ea75ee60b1debb83c221c9d"
)
P08_STATUS_STAGE_INACTIVE_MANIFEST_SHA256 = (
    "d15772595ba04eaa9483ed007918db0e4289ef2df14be03b2f4d87dc4d90543c"
)
P08_STATUS_STAGE_INACTIVE_SOURCE_INVENTORY_DIGEST = (
    "3496f6436d2905aa45c1fbbc6680d47f81d8eb34d762bd02a604b96c9c034525"
)
P08_STATUS_STAGE_FUTURE_INSTALLED_INVENTORY_DIGEST = (
    "9f910de7bcb94fa04f0be66a28593e634182892f79354430f0c907dde32681bb"
)
P08_STATUS_STAGE_FULL_INVENTORY_DIGEST = (
    "23bad9a30e4a16503d27578664075fc95eeb5761bd0819840ee1f4fa838dc170"
)
P08_STATUS_STAGE_INACTIVE_CORE_COMMIT = CORE_SOURCE_COMMIT
P08_STATUS_STAGE_INACTIVE_CORE_TREE = CORE_SOURCE_TREE
P08_STATUS_STAGE_INACTIVE_DEPLOY_COMMIT = DEPLOY_PARENT_COMMIT
P08_STATUS_STAGE_INACTIVE_DEPLOY_TREE = DEPLOY_PARENT_TREE
P08_STATUS_STAGE_CONTROLLER_DIGEST = (
    "9bb92a157c1c961dfb52a4f259ea50d9fb3c4ee13275ea42bf7d5ae7a93d5ad1"
)
P08_STATUS_STAGE_STRATEGY_DIGEST = (
    "285ede124418a3564dea9405f75f7ccb16270a17a77de19da860c0cd1267ffaa"
)
P08_PROTOCOL_ACCEPTANCE_CONTRACT_DIGEST = (
    "7c8eff254acc20cab87213520a415d1aed6830aaea3f10d40a17b9de5a5c58ca"
)
P08_TARGET_SERVER_REJECTION_PROJECTION_SHA256 = (
    "7a2b52f1bba73517336b8eee148d6bdc3e85c87d56d92986353a2fbddf056dbd"
)
P08_TARGET_STATUS_STAGE_PROJECTION_SHA256 = (
    "0dcc7b77ce8e31dbe5fc3cd2fef095e36f80d02c700ad703e73bdf8cc5ee4829"
)
_ZERO_FLAGS = {
    "channel_called": False,
    "credential_value_read": False,
    "health_called": False,
    "live_mutated": False,
    "model_called": False,
    "old_history_migrated": False,
    "private_content_read": False,
    "provider_called": False,
}


class TransactionalRuntimeRejected(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        activation_failure_code: str | None = None,
        rollback_failure_code: str | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.activation_failure_code = activation_failure_code
        self.rollback_failure_code = rollback_failure_code


@dataclass(frozen=True, slots=True)
class _VerifiedRejectionStrategyContext:
    context_digest: str
    context_kind: str
    source_id: str
    strategy_digest: str
    strategy_id: str
    strategy_schema: str


def require(condition: bool, code: str) -> None:
    if not condition:
        raise TransactionalRuntimeRejected(code)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        require(key not in result, "transactional_runtime_duplicate_key")
        result[key] = value
    return result


def canonical(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"


def digest(domain: str, payload: object) -> str:
    return sha256(domain.encode("ascii") + b"\0" + canonical(payload).rstrip()).hexdigest()


def _legacy_strategy_contract() -> dict[str, object]:
    return {
        "maximum_attempts": MAXIMUM_ATTEMPTS,
        "predecessor_attempts": {
            "dual_state_v2": "1/1",
            "p07_policy_overlay_v1": "2/2",
        },
        "strategy_id": STRATEGY_ID,
    }


def _rejection_strategy_context_semantic(
    *,
    context_kind: str,
    strategy_id: str,
    strategy_digest: str,
    strategy_schema: str,
) -> dict[str, str]:
    return {
        "context_kind": context_kind,
        "schema": REJECTION_STRATEGY_CONTEXT_SCHEMA,
        "source_id": SOURCE_ID,
        "strategy_digest": strategy_digest,
        "strategy_id": strategy_id,
        "strategy_schema": strategy_schema,
    }


def _make_verified_rejection_strategy_context(
    *,
    context_kind: str,
    strategy_id: str,
    strategy_digest: str,
    strategy_schema: str,
) -> _VerifiedRejectionStrategyContext:
    require(
        context_kind in {"fresh", "legacy"}
        and isinstance(strategy_id, str)
        and bool(strategy_id)
        and _SHA.fullmatch(strategy_digest) is not None
        and isinstance(strategy_schema, str)
        and bool(strategy_schema),
        "transactional_runtime_rejection_strategy_context_rejected",
    )
    semantic = _rejection_strategy_context_semantic(
        context_kind=context_kind,
        strategy_id=strategy_id,
        strategy_digest=strategy_digest,
        strategy_schema=strategy_schema,
    )
    return _VerifiedRejectionStrategyContext(
        context_digest=digest("p07_rejection_strategy_context_v1", semantic),
        context_kind=context_kind,
        source_id=SOURCE_ID,
        strategy_digest=strategy_digest,
        strategy_id=strategy_id,
        strategy_schema=strategy_schema,
    )


def _validated_rejection_strategy_context(
    context: object,
) -> _VerifiedRejectionStrategyContext | None:
    if not isinstance(context, _VerifiedRejectionStrategyContext):
        return None
    try:
        semantic = _rejection_strategy_context_semantic(
            context_kind=context.context_kind,
            strategy_id=context.strategy_id,
            strategy_digest=context.strategy_digest,
            strategy_schema=context.strategy_schema,
        )
        if (
            context.source_id != SOURCE_ID
            or context.context_kind not in {"fresh", "legacy"}
            or _SHA.fullmatch(context.strategy_digest) is None
            or context.context_digest
            != digest("p07_rejection_strategy_context_v1", semantic)
        ):
            return None
        if context.context_kind == "legacy":
            legacy = _legacy_strategy_contract()
            if (
                context.strategy_id != STRATEGY_ID
                or context.strategy_schema != "legacy-exact-v1"
                or context.strategy_digest
                != digest("p07_legacy_rejection_strategy_v1", legacy)
            ):
                return None
        elif context.strategy_schema != FRESH_STRATEGY_SCHEMA:
            return None
    except (AttributeError, TypeError, ValueError):
        return None
    return context


def _verified_legacy_rejection_strategy_context(
    strategy: Mapping[str, object],
) -> _VerifiedRejectionStrategyContext:
    legacy = _legacy_strategy_contract()
    require(
        dict(strategy) == legacy,
        "transactional_runtime_rejection_strategy_context_rejected",
    )
    return _make_verified_rejection_strategy_context(
        context_kind="legacy",
        strategy_id=STRATEGY_ID,
        strategy_digest=digest("p07_legacy_rejection_strategy_v1", legacy),
        strategy_schema="legacy-exact-v1",
    )


def _verified_fresh_rejection_strategy_context(
    strategy: Mapping[str, object],
    *,
    runtime_manifest: Mapping[str, object],
    runtime_manifest_sha256: str,
    lineages: Mapping[str, object],
    continuation_reference: Mapping[str, object],
) -> _VerifiedRejectionStrategyContext:
    selected = validate_fresh_strategy_contract(
        strategy,
        runtime_manifest=runtime_manifest,
        runtime_manifest_sha256=runtime_manifest_sha256,
        lineages=lineages,
        continuation_reference=continuation_reference,
    )
    return _make_verified_rejection_strategy_context(
        context_kind="fresh",
        strategy_id=str(selected["strategy_id"]),
        strategy_digest=_require_sha(
            selected["strategy_digest"],
            "transactional_runtime_rejection_strategy_context_rejected",
        ),
        strategy_schema=FRESH_STRATEGY_SCHEMA,
    )


def _rejection_strategy_context_from_package_context(
    context: Mapping[str, object],
) -> _VerifiedRejectionStrategyContext:
    strategy = context.get("strategy")
    if not isinstance(strategy, Mapping):
        runtime_plan = context.get("runtime_plan")
        strategy = (
            runtime_plan.get("strategy")
            if isinstance(runtime_plan, Mapping)
            else None
        )
    require(
        isinstance(strategy, Mapping),
        "transactional_runtime_rejection_strategy_context_rejected",
    )
    if strategy.get("schema") == FRESH_STRATEGY_SCHEMA:
        reference = context.get("immutable_continuation_reference")
        require(
            isinstance(reference, Mapping),
            "transactional_runtime_rejection_strategy_context_rejected",
        )
        return _verified_fresh_rejection_strategy_context(
            strategy,
            runtime_manifest=context["runtime_manifest"],
            runtime_manifest_sha256=str(context["runtime_manifest_sha256"]),
            lineages=context["lineages"],
            continuation_reference=reference,
        )
    return _verified_legacy_rejection_strategy_context(strategy)


_REJECTION_STRATEGY_CONTEXT_ATTRIBUTE = (
    "_p07_verified_rejection_strategy_context"
)


def _attach_rejection_strategy_context(
    exc: BaseException, context: _VerifiedRejectionStrategyContext
) -> None:
    selected = _validated_rejection_strategy_context(context)
    if selected is None:
        return
    existing = getattr(exc, _REJECTION_STRATEGY_CONTEXT_ATTRIBUTE, None)
    try:
        if existing is None:
            setattr(exc, _REJECTION_STRATEGY_CONTEXT_ATTRIBUTE, selected)
        elif existing != selected:
            setattr(exc, _REJECTION_STRATEGY_CONTEXT_ATTRIBUTE, False)
    except (AttributeError, TypeError):
        return


def _call_with_rejection_strategy_context(
    context: _VerifiedRejectionStrategyContext,
    operation: Callable[[], dict[str, object]],
) -> dict[str, object]:
    require(
        _validated_rejection_strategy_context(context) is not None,
        "transactional_runtime_rejection_strategy_context_rejected",
    )
    try:
        return operation()
    except Exception as exc:
        _attach_rejection_strategy_context(exc, context)
        raise


def _require_with_rejection_strategy_context(
    condition: bool,
    code: str,
    context: _VerifiedRejectionStrategyContext,
) -> None:
    if condition:
        return
    exc = TransactionalRuntimeRejected(code)
    _attach_rejection_strategy_context(exc, context)
    raise exc


def _typed_error(exc: BaseException, fallback: str) -> str:
    value = getattr(exc, "code", None)
    if isinstance(value, str) and _TYPED.fullmatch(value) is not None:
        return value
    return fallback


def _p08_status_stage_evidence(
    exc: BaseException,
) -> tuple[dict[str, object] | None, str | None]:
    if _typed_error(exc, "") != "production_p08_content_free_status_unavailable":
        return None, None
    payload = getattr(exc, "p08_status_stage_projection", None)
    if not isinstance(payload, Mapping):
        return None, None
    try:
        stage = payload.get("stage")
        invocation_nonce = payload.get("invocation_nonce")
        if not isinstance(stage, str) or not isinstance(invocation_nonce, str):
            return None, None
        rejection = p08_gateway.ContentFreeStatusRejection.from_stage(
            stage, invocation_nonce=invocation_nonce
        )
        synthetic_error = p08_gateway.TemporalGatewayRejected(
            "temporal_status_unavailable",
            retryable=rejection.retryable,
            status_stage=stage,
            status_rejection=rejection,
        )
        expected = production.p08_status_stage_projection(synthetic_error)
        if expected is None or any(
            type(payload.get(key)) is not type(value) or payload.get(key) != value
            for key, value in expected.items()
        ) or set(payload) != set(expected):
            return None, None
        stage_contract = production.p08_status_stage_contract()
        binding = {
            "helper_source_path": P08_STATUS_CLIENT_SOURCE_PATH,
            "helper_source_sha256": P08_STATUS_CLIENT_SOURCE_SHA256,
            "future_installed_inventory_digest": (
                P08_STATUS_STAGE_FUTURE_INSTALLED_INVENTORY_DIGEST
            ),
            "reviewed_inactive_manifest_sha256": (
                P08_STATUS_STAGE_INACTIVE_MANIFEST_SHA256
            ),
            "reviewed_inactive_release_digest": (
                P08_STATUS_STAGE_INACTIVE_RELEASE_DIGEST
            ),
            "reviewed_inactive_source_inventory_digest": (
                P08_STATUS_STAGE_INACTIVE_SOURCE_INVENTORY_DIGEST
            ),
            "server_rejection_contract": (
                production.p08_server_rejection_contract()
            ),
            "service_entrypoint_sha256": (
                P08_STATUS_SERVICE_ENTRYPOINT_SHA256
            ),
            "stage_contract": stage_contract,
            "stage_projection": expected,
            "target_server_rejection_projection_sha256": (
                P08_TARGET_SERVER_REJECTION_PROJECTION_SHA256
            ),
            "target_status_stage_projection_sha256": (
                P08_TARGET_STATUS_STAGE_PROJECTION_SHA256
            ),
            "future_socket_unit_sha256": P08_STATUS_FUTURE_SOCKET_UNIT_SHA256,
            "future_unit_sha256": P08_STATUS_FUTURE_UNIT_SHA256,
        }
        return expected, digest("p07_p08_status_stage_rejected_evidence_v1", binding)
    except (AttributeError, TypeError, ValueError, production.ProductionPlanRejected):
        return None, None


def _runtime_rejection_projection(exc: BaseException) -> dict[str, object]:
    reason = _typed_error(exc, "transactional_runtime_request_rejected")
    rejection = _content_free_rejection(
        reason,
        strategy_context=getattr(
            exc, _REJECTION_STRATEGY_CONTEXT_ATTRIBUTE, None
        ),
    )
    rejection["activation_failure_code"] = getattr(
        exc, "activation_failure_code", None
    )
    rejection["rollback_failure_code"] = getattr(exc, "rollback_failure_code", None)
    stage_projection, stage_digest = _p08_status_stage_evidence(exc)
    if stage_projection is not None and stage_digest is not None:
        rejection["p08_status_stage_projection"] = stage_projection
        rejection["p08_status_stage_projection_digest"] = stage_digest
    return rejection


def _require_sha(value: object, code: str) -> str:
    require(isinstance(value, str) and _SHA.fullmatch(value) is not None, code)
    return value


def _require_commit(value: object, code: str) -> str:
    require(isinstance(value, str) and _COMMIT.fullmatch(value) is not None, code)
    return value


def _canonical_read(path: Path, code: str) -> dict[str, object]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("ascii"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TransactionalRuntimeRejected(code) from exc
    require(isinstance(payload, dict) and canonical(payload) == raw, code)
    return payload


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(path: Path, payload: bytes, *, mode: int) -> None:
    metadata = path.parent.lstat()
    require(
        stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
        "transactional_runtime_write_parent_rejected",
    )
    temporary = path.parent / f".{path.name}.{sha256(payload).hexdigest()[:16]}.tmp"
    require(
        not path.exists()
        and not path.is_symlink()
        and not temporary.exists()
        and not temporary.is_symlink(),
        "transactional_runtime_non_overwrite_rejected",
    )
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _replace_file(path: Path, payload: bytes, *, mode: int) -> None:
    metadata = path.parent.lstat()
    require(
        stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
        "transactional_runtime_write_parent_rejected",
    )
    temporary = path.parent / f".{path.name}.{sha256(payload).hexdigest()[:16]}.tmp"
    require(not temporary.exists() and not temporary.is_symlink(), "transactional_runtime_stale_temp_rejected")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _set_file_owner_and_fsync(path: Path, *, owner_uid: int, owner_gid: int) -> None:
    os.chown(path, owner_uid, owner_gid)
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def namespace_observation(*, state_root: Path, backup_root: Path) -> dict[str, object]:
    require(state_root.is_absolute() and backup_root.is_absolute(), "transactional_runtime_namespace_path_rejected")
    return {
        "backup_root_exists": backup_root.exists() or backup_root.is_symlink(),
        "ledger_exists": (state_root / "ATTEMPT_LEDGER.json").exists()
        or (state_root / "ATTEMPT_LEDGER.json").is_symlink(),
        "schema": NAMESPACE_SCHEMA,
        "source_id": SOURCE_ID,
        "state_root_exists": state_root.exists() or state_root.is_symlink(),
    }


def verify_namespace_absent(payload: Mapping[str, object]) -> dict[str, object]:
    selected = dict(payload)
    require(
        selected
        == {
            "backup_root_exists": False,
            "ledger_exists": False,
            "schema": NAMESPACE_SCHEMA,
            "source_id": SOURCE_ID,
            "state_root_exists": False,
        },
        "transactional_runtime_namespace_preexisting",
    )
    return selected


def absent_runtime_namespace() -> dict[str, object]:
    return {
        "backup_root_exists": False,
        "ledger_exists": False,
        "schema": NAMESPACE_SCHEMA,
        "source_id": SOURCE_ID,
        "state_root_exists": False,
    }


def verify_namespace_ready(payload: Mapping[str, object]) -> dict[str, object]:
    selected = dict(payload)
    require(
        selected
        == {
            "backup_root_exists": True,
            "ledger_exists": True,
            "schema": NAMESPACE_SCHEMA,
            "source_id": SOURCE_ID,
            "state_root_exists": True,
        },
        "transactional_runtime_namespace_not_ready",
    )
    return selected


def observe_parent_failed_start_namespace() -> dict[str, object]:
    return parent.verify_future_namespace_absent(
        parent.namespace_observation(
            state_root=parent.FUTURE_STATE_ROOT,
            backup_root=parent.FUTURE_BACKUP_ROOT,
        )
    )


def _validate_file_inventory(items: object) -> list[dict[str, object]]:
    require(isinstance(items, list) and bool(items), "transactional_runtime_bundle_inventory_rejected")
    result: list[dict[str, object]] = []
    paths: list[str] = []
    for item in items:
        require(
            isinstance(item, Mapping)
            and set(item) == {"mode", "path", "sha256", "size"}
            and item.get("mode") in {0o644, 0o755}
            and type(item.get("size")) is int
            and int(item["size"]) >= 0,
            "transactional_runtime_bundle_inventory_rejected",
        )
        path = str(item["path"])
        pure = PurePosixPath(path)
        require(
            path == pure.as_posix()
            and not pure.is_absolute()
            and ".." not in pure.parts
            and path not in paths,
            "transactional_runtime_bundle_inventory_rejected",
        )
        _require_sha(item["sha256"], "transactional_runtime_bundle_inventory_rejected")
        paths.append(path)
        result.append(dict(item))
    require(paths == sorted(paths), "transactional_runtime_bundle_inventory_rejected")
    return result


def _runtime_capability_identity(*, terminal_predecessor: bool) -> dict[str, bool]:
    capabilities = {
        "after_payload_package_source_present": True,
        "attempt_consumed": False,
        "backup_created": False,
        "installed": False,
        "immutable_continuation_reference_source_present": True,
        "ledger_created": False,
        "live_mutated": False,
        "plan_created": False,
        "preflight_executed": False,
        "production_adapter_source_present": True,
        "provider_called": False,
        "selected": False,
        "source_derived_fresh_max1_strategy_present": True,
        "source_owned_artifact_root_contract_present": True,
        "context_bound_rejection_envelope_source_present": True,
        "p08_server_rejection_subprojection_source_present": True,
        "source_owned_request_collection_present": True,
        "source_owned_request_constructor_present": True,
        "status_invocation_evidence_source_present": True,
        "state_created": False,
    }
    if not terminal_predecessor:
        capabilities.update(
            {
                "failed_request_continuation_materialized": False,
                "failed_request_continuation_source_present": True,
                "p08_status_stage_projection_source_present": True,
                "source_owned_request_collection_closed": True,
            }
        )
    return capabilities


def failed_request_continuation_storage_identity() -> dict[str, object]:
    """Return the source-owned, content-free persistent storage contract."""

    return {
        "child": {
            "link_count": 2,
            "mode": SOURCE_OWNED_CONTINUATION_CHILD_MODE,
            "role": "continuation-child",
        },
        "files": {
            "link_count": 1,
            "mode": SOURCE_OWNED_CONTINUATION_FILE_MODE,
            "role": "continuation-files",
        },
        "owner": {
            "gid": SOURCE_OWNED_CONTINUATION_GID,
            "uid": SOURCE_OWNED_CONTINUATION_UID,
        },
        "parent": {
            "initial_state": "absent",
            "link_count_after_materialization": 3,
            "mode": SOURCE_OWNED_CONTINUATION_PARENT_MODE,
            "path": SOURCE_OWNED_CONTINUATION_PARENT.as_posix(),
            "role": "continuation-protected-parent",
            "type": "directory",
        },
        "root": {
            "initial_state": "absent",
            "link_count_after_materialization": 3,
            "mode": SOURCE_OWNED_CONTINUATION_ROOT_MODE,
            "path": SOURCE_OWNED_CONTINUATION_ROOT.as_posix(),
            "role": "continuation-collection-root",
            "type": "directory",
        },
        "schema": FAILED_REQUEST_CONTINUATION_STORAGE_SCHEMA,
        "source_id": FAILED_REQUEST_CONTINUATION_STORAGE_SOURCE_ID,
        "trusted_ancestor": {
            "mode": SOURCE_OWNED_CONTINUATION_TRUSTED_ANCESTOR_MODE,
            "path": SOURCE_OWNED_CONTINUATION_TRUSTED_ANCESTOR.as_posix(),
            "role": "continuation-trusted-ancestor",
            "type": "directory",
        },
    }


def _validate_failed_request_continuation_storage_identity(
    value: object,
) -> dict[str, object]:
    selected = dict(value) if isinstance(value, Mapping) else {}
    require(
        selected == failed_request_continuation_storage_identity(),
        "transactional_runtime_failed_request_continuation_storage_identity_rejected",
    )
    return selected


def source_owned_artifact_root_contract() -> dict[str, object]:
    """Return the only production artifact roots accepted by this source.

    The A roots are fixed in reviewed source before the source commit is built.
    A/B comparison roots are deliberately not selected here: production cannot
    use caller input, environment variables, directory scans, or fallback logic
    to substitute either artifact root.
    """

    semantic = {
        "bundle_root": {
            "path": SOURCE_OWNED_TRANSACTIONAL_BUNDLE_ROOT.as_posix(),
            "role": "production-transactional-bundle-root",
        },
        "runtime_root": {
            "path": SOURCE_OWNED_RUNTIME_ARTIFACT_ROOT.as_posix(),
            "role": "production-runtime-artifact-root",
        },
        "schema": SOURCE_OWNED_ARTIFACT_ROOT_SCHEMA,
        "selection": {
            "caller_override_allowed": False,
            "directory_scan_allowed": False,
            "environment_override_allowed": False,
            "fallback_allowed": False,
            "search_latest_allowed": False,
            "symlink_allowed": False,
        },
        "source_id": SOURCE_OWNED_ARTIFACT_ROOT_SOURCE_ID,
    }
    return {
        **semantic,
        "identity_digest": digest("p07_source_owned_artifact_roots_v1", semantic),
    }


def _validate_source_owned_artifact_root_contract(
    value: object,
) -> dict[str, object]:
    selected = dict(value) if isinstance(value, Mapping) else {}
    require(
        selected == source_owned_artifact_root_contract(),
        "transactional_runtime_source_owned_artifact_root_contract_rejected",
    )
    return selected


def validate_runtime_artifact_manifest(
    manifest: Mapping[str, object],
    *,
    manifest_sha256: str,
    expected_bundle_id: str,
    expected_manifest_sha256: str,
    terminal_predecessor: bool = False,
) -> dict[str, object]:
    selected = dict(manifest)
    required = {
        "bundle_id",
        "capabilities",
        "files",
        "parent",
        "plugin",
        "runtime_artifact",
        "schema",
        "source",
    }
    if not terminal_predecessor:
        required.update(
            {"failed_request_continuation_storage", "source_owned_artifact_roots"}
        )
    expected_schema = TERMINAL_BUNDLE_SCHEMA if terminal_predecessor else BUNDLE_SCHEMA
    bundle_id_domain = (
        TERMINAL_BUNDLE_ID_DOMAIN if terminal_predecessor else BUNDLE_ID_DOMAIN
    )
    require(
        set(selected) == required and selected.get("schema") == expected_schema,
        "transactional_runtime_manifest_rejected",
    )
    _require_sha(manifest_sha256, "transactional_runtime_manifest_rejected")
    _require_sha(expected_bundle_id, "transactional_runtime_manifest_rejected")
    _require_sha(expected_manifest_sha256, "transactional_runtime_manifest_rejected")
    require(
        manifest_sha256 == expected_manifest_sha256
        and sha256(canonical(selected)).hexdigest() == expected_manifest_sha256,
        "transactional_runtime_manifest_digest_drifted",
    )
    source = selected.get("source")
    parent_identity = selected.get("parent")
    capabilities = selected.get("capabilities")
    plugin = selected.get("plugin")
    runtime_projection = selected.get("runtime_artifact")
    require(
        isinstance(source, Mapping)
        and set(source)
        == {
            "core_commit",
            "core_tree",
            "deploy_commit",
            "deploy_parent_commit",
            "deploy_parent_tree",
            "deploy_tree",
            "runtime_source_id",
        }
        and source.get("runtime_source_id") == SOURCE_ID
        and source.get("core_commit") == CORE_SOURCE_COMMIT
        and source.get("core_tree") == CORE_SOURCE_TREE
        and source.get("deploy_parent_commit") == DEPLOY_PARENT_COMMIT
        and source.get("deploy_parent_tree") == DEPLOY_PARENT_TREE,
        "transactional_runtime_source_identity_rejected",
    )
    _require_commit(source.get("deploy_commit"), "transactional_runtime_source_identity_rejected")
    _require_commit(source.get("deploy_tree"), "transactional_runtime_source_identity_rejected")
    require(
        isinstance(plugin, Mapping),
        "transactional_runtime_plugin_binding_rejected",
    )
    try:
        plugin = plugin_artifact.validate_binding(plugin)
    except plugin_artifact.PluginArtifactRejected as exc:
        raise TransactionalRuntimeRejected(exc.code) from exc
    require(
        isinstance(runtime_projection, Mapping),
        "transactional_runtime_artifact_binding_rejected",
    )
    try:
        runtime_projection = runtime_artifact.validate_projection(runtime_projection)
    except runtime_artifact.RuntimeArtifactRejected as exc:
        raise TransactionalRuntimeRejected(exc.code) from exc
    require(
        plugin["source"]["deploy_commit"] == source["deploy_commit"]
        and plugin["source"]["deploy_tree"] == source["deploy_tree"],
        "transactional_runtime_plugin_binding_rejected",
    )
    require(
        runtime_projection["source"]
        == {
            "core_commit": source["core_commit"],
            "core_tree": source["core_tree"],
            "deploy_commit": source["deploy_commit"],
            "deploy_tree": source["deploy_tree"],
        }
        and runtime_projection["plugin"]
        == plugin_artifact.binding_projection(plugin),
        "transactional_runtime_artifact_binding_rejected",
    )
    require(
        parent_identity
        == {
            "controller_bundle_id": PARENT_CONTROLLER_BUNDLE_ID,
            "controller_manifest_sha256": PARENT_CONTROLLER_MANIFEST_SHA256,
            "controller_source_id": parent.SOURCE_ID,
            "full_mutation_bundle_id": parent.FULL_MUTATION_BUNDLE_ID,
            "full_mutation_manifest_sha256": parent.FULL_MUTATION_MANIFEST_SHA256,
            "full_mutation_source_id": mutation.SOURCE_ID,
            "predecessor_runtime_bundle_id": PREDECESSOR_RUNTIME_BUNDLE_ID,
            "predecessor_runtime_manifest_sha256": PREDECESSOR_RUNTIME_MANIFEST_SHA256,
            "production_plan_source_id": production.SOURCE_ID,
        },
        "transactional_runtime_parent_identity_rejected",
    )
    require(
        capabilities
        == _runtime_capability_identity(terminal_predecessor=terminal_predecessor),
        "transactional_runtime_capability_identity_rejected",
    )
    if not terminal_predecessor:
        _validate_failed_request_continuation_storage_identity(
            selected["failed_request_continuation_storage"]
        )
        _validate_source_owned_artifact_root_contract(
            selected["source_owned_artifact_roots"]
        )
    files = _validate_file_inventory(selected["files"])
    semantic = {key: selected[key] for key in required - {"bundle_id"}}
    require(
        selected.get("bundle_id")
        == digest(bundle_id_domain, semantic)
        == expected_bundle_id,
        "transactional_runtime_bundle_identity_drifted",
    )
    return {
        **selected,
        "files": files,
        "plugin": plugin,
        "runtime_artifact": runtime_projection,
    }


def _validate_unit_projection(value: object, *, unit: str) -> dict[str, object]:
    require(
        isinstance(value, Mapping)
        and set(value) == {"active_state", "nrestarts", "sub_state", "unit"}
        and value.get("unit") == unit
        and value.get("active_state") in {"active", "inactive"}
        and isinstance(value.get("sub_state"), str)
        and bool(value.get("sub_state"))
        and type(value.get("nrestarts")) is int
        and int(value["nrestarts"]) >= 0,
        "transactional_runtime_service_projection_rejected",
    )
    return dict(value)


def validate_service_projection(value: Mapping[str, object]) -> dict[str, object]:
    selected = dict(value)
    require(
        set(selected) == {"container", "core", "telegram", "telegram_socket"},
        "transactional_runtime_service_projection_rejected",
    )
    container = selected["container"]
    require(
        isinstance(container, Mapping)
        and set(container) == {"health", "name", "restart_count", "state"}
        and container.get("name") == CONTAINER
        and container.get("state") in {"running", "stopped"}
        and container.get("health") in {"healthy", "none", "stopped"}
        and type(container.get("restart_count")) is int
        and int(container["restart_count"]) >= 0,
        "transactional_runtime_service_projection_rejected",
    )
    return {
        "container": dict(container),
        "core": _validate_unit_projection(selected["core"], unit=CORE_UNIT),
        "telegram": _validate_unit_projection(selected["telegram"], unit=TELEGRAM_UNIT),
        "telegram_socket": _validate_unit_projection(
            selected["telegram_socket"], unit=TELEGRAM_SOCKET
        ),
    }


def _target_service_projection(prestate: Mapping[str, object]) -> dict[str, object]:
    selected = validate_service_projection(prestate)
    return {
        "container": {
            "health": "healthy",
            "name": CONTAINER,
            "restart_count": selected["container"]["restart_count"],
            "state": "running",
        },
        "core": {
            "active_state": "active",
            "nrestarts": selected["core"]["nrestarts"],
            "sub_state": "running",
            "unit": CORE_UNIT,
        },
        "telegram": {
            "active_state": "active",
            "nrestarts": selected["telegram"]["nrestarts"],
            "sub_state": "running",
            "unit": TELEGRAM_UNIT,
        },
        "telegram_socket": {
            "active_state": "active",
            "nrestarts": selected["telegram_socket"]["nrestarts"],
            "sub_state": "listening",
            "unit": TELEGRAM_SOCKET,
        },
    }


def build_runtime_plan(
    *,
    parent_plan: Mapping[str, object],
    mutation_set: Mapping[str, object],
    production_identity: Mapping[str, object],
    lineages: Mapping[str, object],
    parent_namespace: Mapping[str, object],
    runtime_namespace: Mapping[str, object],
    runtime_manifest: Mapping[str, object],
    runtime_manifest_sha256: str,
    expected_runtime_bundle_id: str,
    expected_runtime_manifest_sha256: str,
    prestate_services: Mapping[str, object],
    fresh_strategy: Mapping[str, object] | None = None,
    continuation_reference: Mapping[str, object] | None = None,
    status_invocation_evidence: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Wrap one exact parent plan with the production runtime identity."""

    manifest = validate_runtime_artifact_manifest(
        runtime_manifest,
        manifest_sha256=runtime_manifest_sha256,
        expected_bundle_id=expected_runtime_bundle_id,
        expected_manifest_sha256=expected_runtime_manifest_sha256,
    )
    lineage = parent.validate_immutable_lineages(lineages)
    base_plan = parent.validate_plan(
        parent_plan,
        mutation_set=mutation_set,
        lineages=lineage,
        namespace=parent_namespace,
    )
    target_identity = production.validate_production_identity(
        parent_plan=base_plan,
        mutation_set=mutation_set,
        production_identity=production_identity,
    )
    verify_namespace_absent(runtime_namespace)
    source = manifest["source"]
    if fresh_strategy is None:
        strategy = _legacy_strategy_contract()
        selected_state_root = STATE_ROOT
        selected_backup_root = BACKUP_ROOT
        selected_package_root = PACKAGE_ROOT
    else:
        require(
            isinstance(continuation_reference, Mapping),
            "transactional_runtime_immutable_continuation_reference_rejected",
        )
        strategy = validate_fresh_strategy_contract(
            fresh_strategy,
            runtime_manifest=manifest,
            runtime_manifest_sha256=runtime_manifest_sha256,
            lineages=lineage,
            continuation_reference=continuation_reference,
        )
        selected_state_root = Path(str(strategy["storage"]["state_root"]))
        selected_backup_root = Path(str(strategy["storage"]["backup_root"]))
        selected_package_root = Path(str(strategy["storage"]["package_root"]))
        require(
            isinstance(status_invocation_evidence, Mapping)
            and status_invocation_evidence.get("strategy_id")
            == strategy["strategy_id"]
            and status_invocation_evidence.get("status") == "accepted"
            and _REQUEST_ID_PATTERN.fullmatch(
                str(status_invocation_evidence.get("invocation_id", ""))
            )
            is not None
            and all(
                _SHA.fullmatch(str(status_invocation_evidence.get(field, "")))
                is not None
                for field in (
                    "completion_sha256",
                    "helper_nonce_digest",
                    "projection_digest",
                    "result_digest",
                )
            )
            and status_invocation_evidence.get("stage_projection_digest") is None,
            "transactional_runtime_status_invocation_evidence_rejected",
        )
    plugin_projection = plugin_artifact.binding_projection(manifest["plugin"])
    runtime_projection = runtime_artifact.validate_projection(
        manifest["runtime_artifact"]
    )
    require(
        target_identity.get("plugin") == plugin_projection
        and target_identity.get("runtime_artifact") == runtime_projection,
        "transactional_runtime_artifact_binding_rejected",
    )
    storage = base_plan["storage"]
    require(
        base_plan["source"]
        == {
            "controller_source_id": parent.SOURCE_ID,
            "core_commit": CORE_SOURCE_COMMIT,
            "deploy_commit": source["deploy_commit"],
            "deploy_tree": source["deploy_tree"],
            "full_mutation_source_id": mutation.SOURCE_ID,
        }
        and base_plan["artifacts"]
        == {
            "controller_bundle_id": PARENT_CONTROLLER_BUNDLE_ID,
            "full_mutation_bundle_id": parent.FULL_MUTATION_BUNDLE_ID,
            "full_mutation_manifest_sha256": parent.FULL_MUTATION_MANIFEST_SHA256,
        },
        "transactional_runtime_parent_plan_identity_rejected",
    )
    require(
        storage["state_root"] == selected_state_root.as_posix()
        and storage["backup_root"] == selected_backup_root.as_posix(),
        "transactional_runtime_storage_identity_rejected",
    )
    prestate = validate_service_projection(prestate_services)
    semantic = {
        "artifacts": {
            "full_mutation_bundle_id": parent.FULL_MUTATION_BUNDLE_ID,
            "full_mutation_manifest_sha256": parent.FULL_MUTATION_MANIFEST_SHA256,
            "parent_controller_bundle_id": PARENT_CONTROLLER_BUNDLE_ID,
            "parent_controller_manifest_sha256": PARENT_CONTROLLER_MANIFEST_SHA256,
            "runtime_bundle_id": manifest["bundle_id"],
            "runtime_manifest_sha256": runtime_manifest_sha256,
            "target_plugin": plugin_projection,
            "target_runtime": runtime_projection,
        },
        "attempts": {"consumed": 0, "maximum": MAXIMUM_ATTEMPTS, "next": 1},
        "capabilities": dict(_ZERO_FLAGS),
        "immutable_terminal_evidence_digest": IMMUTABLE_LINEAGE_EVIDENCE_DIGEST,
        "lineage_evidence_digest": lineage["evidence_digest"],
        "parent_plan": base_plan,
        "parent_plan_id": base_plan["plan_id"],
        "production_identity": target_identity,
        "schema": PLAN_SCHEMA,
        "services": {
            "prestate": prestate,
            "target": _target_service_projection(prestate),
        },
        "source": {
            "core_commit": source["core_commit"],
            "core_tree": source["core_tree"],
            "deploy_commit": source["deploy_commit"],
            "deploy_tree": source["deploy_tree"],
            "full_mutation_source_id": mutation.SOURCE_ID,
            "parent_controller_source_id": parent.SOURCE_ID,
            "runtime_source_id": SOURCE_ID,
        },
        "storage": {
            "backup_path": storage["backup_path"],
            "backup_root": storage["backup_root"],
            "controller_journal_path": storage["journal_path"],
            "filesystem_journal_path": storage["filesystem_journal_path"],
            "package_root": selected_package_root.as_posix(),
            "state_root": storage["state_root"],
            "staging_path": storage["staging_path"],
        },
        "strategy": strategy,
    }
    if fresh_strategy is not None:
        semantic["status_invocation"] = dict(status_invocation_evidence)
    return {**semantic, "plan_id": digest("p07_transactional_runtime_plan", semantic)}


def validate_runtime_plan(
    payload: Mapping[str, object],
    *,
    mutation_set: Mapping[str, object],
    lineages: Mapping[str, object],
    parent_namespace: Mapping[str, object],
    runtime_namespace: Mapping[str, object],
    runtime_manifest: Mapping[str, object],
    runtime_manifest_sha256: str,
    expected_runtime_bundle_id: str,
    expected_runtime_manifest_sha256: str,
    continuation_reference: Mapping[str, object] | None = None,
) -> dict[str, object]:
    selected = dict(payload)
    required = {
        "artifacts",
        "attempts",
        "capabilities",
        "immutable_terminal_evidence_digest",
        "lineage_evidence_digest",
        "parent_plan",
        "parent_plan_id",
        "plan_id",
        "production_identity",
        "schema",
        "services",
        "source",
        "storage",
        "strategy",
    }
    require(
        isinstance(selected.get("strategy"), Mapping),
        "transactional_runtime_plan_rejected",
    )
    is_fresh = selected["strategy"].get("schema") == FRESH_STRATEGY_SCHEMA
    if is_fresh:
        required.add("status_invocation")
    require(
        set(selected) == required
        and selected.get("schema") == PLAN_SCHEMA
        and isinstance(selected.get("services"), Mapping),
        "transactional_runtime_plan_rejected",
    )
    rebuilt = build_runtime_plan(
        parent_plan=selected["parent_plan"],
        mutation_set=mutation_set,
        production_identity=selected["production_identity"],
        lineages=lineages,
        parent_namespace=parent_namespace,
        runtime_namespace=runtime_namespace,
        runtime_manifest=runtime_manifest,
        runtime_manifest_sha256=runtime_manifest_sha256,
        expected_runtime_bundle_id=expected_runtime_bundle_id,
        expected_runtime_manifest_sha256=expected_runtime_manifest_sha256,
        prestate_services=selected["services"]["prestate"],
        fresh_strategy=(
            selected["strategy"]
            if is_fresh
            else None
        ),
        continuation_reference=continuation_reference,
        status_invocation_evidence=(
            selected["status_invocation"] if is_fresh else None
        ),
    )
    require(selected == rebuilt, "transactional_runtime_plan_rejected")
    return rebuilt


@dataclass(frozen=True, slots=True)
class ProductionRuntimeMaterial:
    runtime_plan: Mapping[str, object]
    mutation_set: Mapping[str, object]
    before_payloads: Mapping[str, bytes]
    after_payloads: Mapping[str, bytes]

    def content_free_projection(self) -> dict[str, object]:
        def inventory(payloads: Mapping[str, bytes]) -> list[dict[str, object]]:
            return [
                {
                    "path_key_digest": digest(
                        "p07_transactional_runtime_payload_key", key
                    ),
                    "sha256": sha256(payload).hexdigest(),
                    "size": len(payload),
                }
                for key, payload in sorted(payloads.items())
            ]

        return {
            "after_payloads": inventory(self.after_payloads),
            "before_payloads": inventory(self.before_payloads),
            "mutation_set": dict(self.mutation_set),
            "runtime_plan": dict(self.runtime_plan),
            "schema": "myuna.p07-owner-private-memory-production-plan-package.v1",
        }


def construct_production_runtime_material(
    *,
    observer: production.ProtectedObserver,
    core_candidate: Path,
    runtime_candidate: Path,
    plugin_candidate: Path,
    lineages: Mapping[str, object],
    runtime_manifest: Mapping[str, object],
    runtime_manifest_sha256: str,
    expected_runtime_bundle_id: str,
    expected_runtime_manifest_sha256: str,
    fresh_strategy: Mapping[str, object] | None = None,
    continuation_reference: Mapping[str, object] | None = None,
) -> ProductionRuntimeMaterial:
    manifest = validate_runtime_artifact_manifest(
        runtime_manifest,
        manifest_sha256=runtime_manifest_sha256,
        expected_bundle_id=expected_runtime_bundle_id,
        expected_manifest_sha256=expected_runtime_manifest_sha256,
    )
    source = manifest["source"]
    if fresh_strategy is None:
        selected_state_root = STATE_ROOT
        selected_backup_root = BACKUP_ROOT
    else:
        require(
            isinstance(continuation_reference, Mapping),
            "transactional_runtime_immutable_continuation_reference_rejected",
        )
        selected_strategy = validate_fresh_strategy_contract(
            fresh_strategy,
            runtime_manifest=manifest,
            runtime_manifest_sha256=runtime_manifest_sha256,
            lineages=lineages,
            continuation_reference=continuation_reference,
        )
        observe_fresh_strategy_namespace(selected_strategy)
        selected_state_root = Path(str(selected_strategy["storage"]["state_root"]))
        selected_backup_root = Path(str(selected_strategy["storage"]["backup_root"]))
    artifacts = production.resolve_reviewed_artifacts(
        core_candidate=core_candidate,
        runtime_candidate=runtime_candidate,
        plugin_candidate=plugin_candidate,
        plugin_binding=manifest["plugin"],
        runtime_artifact_projection=manifest["runtime_artifact"],
        core_commit=str(source["core_commit"]),
        core_tree=str(source["core_tree"]),
        deploy_commit=str(source["deploy_commit"]),
        deploy_tree=str(source["deploy_tree"]),
    )
    parent_namespace = observe_parent_failed_start_namespace()
    material = production.build_production_material(
        observer=observer,
        artifacts=artifacts,
        lineages=lineages,
        namespace=parent_namespace,
        runtime_bundle_id=expected_runtime_bundle_id,
        runtime_manifest_sha256=runtime_manifest_sha256,
        controller_bundle_id=PARENT_CONTROLLER_BUNDLE_ID,
        state_root=selected_state_root,
        backup_root=selected_backup_root,
    )
    runtime_namespace = namespace_observation(
        state_root=selected_state_root,
        backup_root=selected_backup_root,
    )
    status_invocation_evidence: Mapping[str, object] | None = None
    if fresh_strategy is not None:
        require(
            isinstance(observer, SourceOwnedStatusEvidenceObserver),
            "transactional_runtime_status_invocation_observer_rejected",
        )
        status_invocation_evidence = observer.completed_evidence()
    plan = build_runtime_plan(
        parent_plan=material.parent_plan,
        mutation_set=material.mutation_set,
        production_identity=material.production_identity,
        lineages=lineages,
        parent_namespace=parent_namespace,
        runtime_namespace=runtime_namespace,
        runtime_manifest=runtime_manifest,
        runtime_manifest_sha256=runtime_manifest_sha256,
        expected_runtime_bundle_id=expected_runtime_bundle_id,
        expected_runtime_manifest_sha256=expected_runtime_manifest_sha256,
        prestate_services=material.service_projection,
        fresh_strategy=fresh_strategy,
        continuation_reference=continuation_reference,
        status_invocation_evidence=status_invocation_evidence,
    )
    return ProductionRuntimeMaterial(
        runtime_plan=plan,
        mutation_set=material.mutation_set,
        before_payloads=material.before_payloads,
        after_payloads=material.after_payloads,
    )


def _source_git(source: Path, *arguments: str) -> str:
    try:
        metadata = source.lstat()
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_source_root_rejected"
        ) from exc
    require(
        stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
        "transactional_runtime_source_root_rejected",
    )
    completed = subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            f"safe.directory={source.resolve()}",
            "-C",
            str(source.resolve()),
            *arguments,
        ],
        capture_output=True,
        check=False,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/usr/sbin"},
        text=True,
        timeout=120,
    )
    require(
        completed.returncode == 0,
        "transactional_runtime_source_identity_unavailable",
    )
    return completed.stdout.strip()


def _source_git_identity(source: Path) -> dict[str, str]:
    commit = _source_git(source, "rev-parse", "HEAD")
    tree = _source_git(source, "rev-parse", "HEAD^{tree}")
    require(
        _COMMIT.fullmatch(commit) is not None
        and _COMMIT.fullmatch(tree) is not None
        and not _source_git(source, "status", "--porcelain"),
        "transactional_runtime_source_identity_drifted",
    )
    return {"commit": commit, "tree": tree}


def _regular_file_identity(path: Path, *, code: str) -> dict[str, object]:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as exc:
        raise TransactionalRuntimeRejected(code) from exc
    require(
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_nlink == 1,
        code,
    )
    return {
        "mode": stat.S_IMODE(metadata.st_mode),
        "sha256": sha256(payload).hexdigest(),
        "size": metadata.st_size,
    }


def _single_digest_directory(root: Path, *, code: str) -> Path:
    try:
        metadata = root.lstat()
        entries = list(root.iterdir())
    except OSError as exc:
        raise TransactionalRuntimeRejected(code) from exc
    require(
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and len(entries) == 1,
        code,
    )
    candidate = entries[0]
    try:
        candidate_metadata = candidate.lstat()
    except OSError as exc:
        raise TransactionalRuntimeRejected(code) from exc
    require(
        _SHA.fullmatch(candidate.name) is not None
        and stat.S_ISDIR(candidate_metadata.st_mode)
        and not stat.S_ISLNK(candidate_metadata.st_mode),
        code,
    )
    return candidate


def _source_owned_bundle_manifest(bundle_root: Path) -> tuple[dict[str, object], str]:
    try:
        root_metadata = bundle_root.lstat()
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_source_owned_bundle_rejected"
        ) from exc
    require(
        stat.S_ISDIR(root_metadata.st_mode)
        and not stat.S_ISLNK(root_metadata.st_mode),
        "transactional_runtime_source_owned_bundle_rejected",
    )
    require(
        root_metadata.st_uid == 0
        and root_metadata.st_gid == 0
        and stat.S_IMODE(root_metadata.st_mode) == 0o750,
        "transactional_runtime_source_owned_bundle_rejected",
    )
    manifest_path = bundle_root / "manifest.json"
    manifest = _canonical_read(
        manifest_path, "transactional_runtime_source_owned_bundle_rejected"
    )
    manifest_sha = sha256(manifest_path.read_bytes()).hexdigest()
    manifest_metadata = manifest_path.lstat()
    require(
        stat.S_ISREG(manifest_metadata.st_mode)
        and not stat.S_ISLNK(manifest_metadata.st_mode)
        and manifest_metadata.st_nlink == 1
        and manifest_metadata.st_uid == 0
        and manifest_metadata.st_gid == 0
        and stat.S_IMODE(manifest_metadata.st_mode) == 0o644,
        "transactional_runtime_source_owned_bundle_rejected",
    )
    validated = validate_runtime_artifact_manifest(
        manifest,
        manifest_sha256=manifest_sha,
        expected_bundle_id=str(manifest.get("bundle_id", "")),
        expected_manifest_sha256=manifest_sha,
    )
    files = _validate_file_inventory(validated["files"])
    binding = plugin_artifact.validate_binding(validated["plugin"])
    release = str(binding["target"]["release_digest"])
    expected_paths = {"manifest.json", *(str(row["path"]) for row in files)}
    expected_paths.add(
        f"telegram-plugin/{release}{plugin_artifact.MANIFEST_SUFFIX}"
    )
    expected_paths.update(
        {
            f"telegram-plugin/{release}/{row['destination']}"
            for row in binding["source"]["files"]
        }
    )
    try:
        paths = sorted(bundle_root.rglob("*"))
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_source_owned_bundle_rejected"
        ) from exc
    actual_paths: set[str] = set()
    for path in paths:
        relative = path.relative_to(bundle_root).as_posix()
        metadata = path.lstat()
        require(
            not stat.S_ISLNK(metadata.st_mode),
            "transactional_runtime_source_owned_bundle_rejected",
        )
        if stat.S_ISDIR(metadata.st_mode):
            continue
        require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_nlink == 1
            and metadata.st_uid == 0
            and metadata.st_gid == 0,
            "transactional_runtime_source_owned_bundle_rejected",
        )
        actual_paths.add(relative)
    require(
        actual_paths == expected_paths,
        "transactional_runtime_source_owned_bundle_inventory_rejected",
    )
    for row in files:
        identity = _regular_file_identity(
            bundle_root / str(row["path"]),
            code="transactional_runtime_source_owned_bundle_inventory_rejected",
        )
        require(
            identity
            == {
                "mode": row["mode"],
                "sha256": row["sha256"],
                "size": row["size"],
            },
            "transactional_runtime_source_owned_bundle_inventory_rejected",
        )
    plugin_artifact.verify_candidate(
        bundle_root / "telegram-plugin" / release, binding
    )
    return validated, manifest_sha


def _source_owned_candidates(
    *, runtime_build_root: Path, bundle_root: Path, manifest: Mapping[str, object]
) -> tuple[Path, Path, Path]:
    try:
        metadata = runtime_build_root.lstat()
        names = {path.name for path in runtime_build_root.iterdir()}
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_source_owned_runtime_root_rejected"
        ) from exc
    require(
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_uid == 0
        and metadata.st_gid == 0
        and stat.S_IMODE(metadata.st_mode) == 0o755
        and names == {"core", "runtime"},
        "transactional_runtime_source_owned_runtime_root_rejected",
    )
    core_root = runtime_build_root / "core"
    try:
        core_entries = list(core_root.iterdir())
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_source_owned_core_artifact_rejected"
        ) from exc
    core_directories = [
        path
        for path in core_entries
        if path.is_dir() and not path.is_symlink() and _SHA.fullmatch(path.name)
    ]
    require(
        len(core_directories) == 1,
        "transactional_runtime_source_owned_core_artifact_rejected",
    )
    core_candidate = core_directories[0]
    release = core_candidate.name
    require(
        {path.name for path in core_entries}
        == {
            release,
            f"{release}.artifact.json",
            f"{release}.evidence.json",
            f"{release}.receipt.json",
        },
        "transactional_runtime_source_owned_core_artifact_rejected",
    )
    runtime_candidate = _single_digest_directory(
        runtime_build_root / "runtime",
        code="transactional_runtime_source_owned_runtime_artifact_rejected",
    )
    runtime_projection = runtime_artifact.validate_projection(
        manifest["runtime_artifact"]
    )
    require(
        runtime_candidate.name == runtime_projection["release_digest"],
        "transactional_runtime_source_owned_runtime_artifact_rejected",
    )
    binding = plugin_artifact.validate_binding(manifest["plugin"])
    plugin_candidate = (
        bundle_root
        / "telegram-plugin"
        / str(binding["target"]["release_digest"])
    )
    return core_candidate, runtime_candidate, plugin_candidate


def _source_owned_lineages(evidence_root: Path) -> dict[str, object]:
    require(
        evidence_root.is_absolute(),
        "transactional_runtime_source_owned_evidence_root_rejected",
    )
    return parent.verify_immutable_lineages(
        full_mutation_handoff=(
            evidence_root / "P07_FULL_MUTATION_SET_T1_SOURCE_MAINLINE_2026-08-08.md"
        ),
        root_cause_handoff=(
            evidence_root
            / "P07_DUAL_STATE_RECOVERY_V2_DROPIN_IDENTITY_T0_ARCHITECTURE_DIAGNOSIS_2026-08-08.md"
        ),
        terminal_handoff=(
            evidence_root
            / "P07_DUAL_STATE_RECOVERY_V2_ACTIVATION_FAILED_ROLLBACK_VERIFIED_PERMANENT_HARD_STOP_2026-08-08.md"
        ),
        predecessor_arguments={
            "hard_stop_handoff": (
                evidence_root
                / "P07_OWNER_PRIVATE_MEMORY_T2_ATTEMPT2_FAILED_ROLLBACK_VERIFIED_STRATEGY_EXHAUSTED_2026-08-08.md"
            ),
            "diagnosis_handoff": (
                evidence_root
                / "P07_OWNER_PRIVATE_MEMORY_CREDENTIAL_POSTFLIGHT_T0_DIAGNOSIS_2026-08-08.md"
            ),
            "dual_state_t1_handoff": (
                evidence_root
                / "P07_OWNER_PRIVATE_MEMORY_CREDENTIAL_POSTFLIGHT_T1_SOURCE_MAINLINE_2026-08-08.md"
            ),
            "formal_preflight_one": (
                evidence_root
                / "P07_OWNER_PRIVATE_MEMORY_ATTEMPT2_FORMAL_PREFLIGHT_1_2026-08-08.json"
            ),
            "formal_preflight_two": (
                evidence_root
                / "P07_OWNER_PRIVATE_MEMORY_ATTEMPT2_FORMAL_PREFLIGHT_2_2026-08-08.json"
            ),
            "state_root": parent.dual_state.LEGACY_STATE_ROOT,
            "backup_root": parent.dual_state.LEGACY_BACKUP_ROOT,
            "archive_root": parent.dual_state.LEGACY_ARCHIVE_ROOT,
        },
    )


def _source_owned_target_material(
    *,
    core_source: Path,
    deploy_source: Path,
    runtime_build_root: Path,
    bundle_root: Path,
    evidence_root: Path,
    owner_account: str,
    lineage_loader: Callable[[Path], Mapping[str, object]] = _source_owned_lineages,
) -> dict[str, object]:
    core_identity = _source_git_identity(core_source)
    deploy_identity = _source_git_identity(deploy_source)
    require(
        core_identity
        == {"commit": CORE_SOURCE_COMMIT, "tree": CORE_SOURCE_TREE},
        "transactional_runtime_source_owned_core_source_rejected",
    )
    manifest, manifest_sha = _source_owned_bundle_manifest(bundle_root)
    source = dict(manifest["source"])
    require(
        source["core_commit"] == core_identity["commit"]
        and source["core_tree"] == core_identity["tree"]
        and source["deploy_commit"] == deploy_identity["commit"]
        and source["deploy_tree"] == deploy_identity["tree"],
        "transactional_runtime_source_owned_source_binding_rejected",
    )
    core_candidate, runtime_candidate, plugin_candidate = _source_owned_candidates(
        runtime_build_root=runtime_build_root,
        bundle_root=bundle_root,
        manifest=manifest,
    )
    production.resolve_reviewed_artifacts(
        core_candidate=core_candidate,
        runtime_candidate=runtime_candidate,
        plugin_candidate=plugin_candidate,
        plugin_binding=manifest["plugin"],
        runtime_artifact_projection=manifest["runtime_artifact"],
        core_commit=core_identity["commit"],
        core_tree=core_identity["tree"],
        deploy_commit=deploy_identity["commit"],
        deploy_tree=deploy_identity["tree"],
    )
    lineages = parent.validate_immutable_lineages(lineage_loader(evidence_root))
    require(
        lineages["evidence_digest"] == IMMUTABLE_LINEAGE_EVIDENCE_DIGEST,
        "transactional_runtime_source_owned_lineage_rejected",
    )
    try:
        owner = pwd.getpwnam(owner_account)
    except KeyError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_source_owned_owner_rejected"
        ) from exc
    return {
        "core_candidate": core_candidate,
        "lineages": lineages,
        "manifest": manifest,
        "manifest_sha256": manifest_sha,
        "owner_gid": owner.pw_gid,
        "owner_uid": owner.pw_uid,
        "plugin_candidate": plugin_candidate,
        "runtime_candidate": runtime_candidate,
    }


def _construct_source_owned_prepare_request(
    *,
    core_source: Path,
    deploy_source: Path,
    runtime_build_root: Path,
    bundle_root: Path,
    evidence_root: Path,
    owner_account: str,
    lineage_loader: Callable[[Path], Mapping[str, object]] = _source_owned_lineages,
) -> dict[str, object]:
    material = _source_owned_target_material(
        core_source=core_source,
        deploy_source=deploy_source,
        runtime_build_root=runtime_build_root,
        bundle_root=bundle_root,
        evidence_root=evidence_root,
        owner_account=owner_account,
        lineage_loader=lineage_loader,
    )
    manifest = dict(material["manifest"])
    manifest_sha = str(material["manifest_sha256"])
    request = {
        "core_candidate": Path(material["core_candidate"]).as_posix(),
        "expected_runtime_bundle_id": manifest["bundle_id"],
        "expected_runtime_manifest_sha256": manifest_sha,
        "lineages": material["lineages"],
        "mode": "prepare-package",
        "owner_gid": material["owner_gid"],
        "owner_uid": material["owner_uid"],
        "plugin_candidate": Path(material["plugin_candidate"]).as_posix(),
        "runtime_candidate": Path(material["runtime_candidate"]).as_posix(),
        "runtime_manifest": manifest,
        "runtime_manifest_sha256": manifest_sha,
        "schema": REQUEST_SCHEMA,
    }
    _request_fields(
        request,
        mode="prepare-package",
        fields={
            "core_candidate",
            "expected_runtime_bundle_id",
            "expected_runtime_manifest_sha256",
            "lineages",
            "owner_gid",
            "owner_uid",
            "plugin_candidate",
            "runtime_candidate",
            "runtime_manifest",
            "runtime_manifest_sha256",
        },
    )
    require(
        len(canonical(request)) <= MAX_SOURCE_OWNED_REQUEST_BYTES,
        "transactional_runtime_source_owned_request_oversize",
    )
    return request


def construct_source_owned_prepare_request() -> dict[str, object]:
    """Build the sole production prepare request from fixed reviewed sources."""

    return _construct_source_owned_prepare_request(
        core_source=SOURCE_OWNED_CORE_ROOT,
        deploy_source=SOURCE_OWNED_DEPLOY_ROOT,
        runtime_build_root=SOURCE_OWNED_RUNTIME_ARTIFACT_ROOT,
        bundle_root=SOURCE_OWNED_TRANSACTIONAL_BUNDLE_ROOT,
        evidence_root=SOURCE_OWNED_EVIDENCE_ROOT,
        owner_account=SOURCE_OWNED_OWNER_ACCOUNT,
    )


def validate_source_owned_prepare_request(
    request: Mapping[str, object],
) -> dict[str, object]:
    rebuilt = construct_source_owned_prepare_request()
    selected = dict(request)
    require(
        selected == rebuilt and canonical(selected) == canonical(rebuilt),
        "transactional_runtime_source_owned_request_rejected",
    )
    return selected


def _request_package_semantic(request: Mapping[str, object]) -> dict[str, object]:
    selected = dict(request)
    request_bytes = canonical(selected)
    manifest = dict(selected["runtime_manifest"])
    semantic = {
        "bundle_id": manifest["bundle_id"],
        "constructor_source_id": REQUEST_CONSTRUCTOR_SOURCE_ID,
        "lineage_evidence_digest": selected["lineages"]["evidence_digest"],
        "request_schema": REQUEST_SCHEMA,
        "request_sha256": sha256(request_bytes).hexdigest(),
        "request_size": len(request_bytes),
        "runtime_manifest_sha256": selected["runtime_manifest_sha256"],
        "schema": REQUEST_CONSTRUCTOR_SCHEMA,
        "source": manifest["source"],
        "strategy_id": STRATEGY_ID,
    }
    return {
        **semantic,
        "request_id": digest("p07_source_owned_transactional_request", semantic),
    }


def _verify_request_package_file(
    path: Path, *, payload: bytes, mode: int, owner_uid: int, owner_gid: int
) -> None:
    identity = _regular_file_identity(
        path, code="transactional_runtime_source_owned_request_package_rejected"
    )
    metadata = path.lstat()
    require(
        identity
        == {"mode": mode, "sha256": sha256(payload).hexdigest(), "size": len(payload)}
        and metadata.st_uid == owner_uid
        and metadata.st_gid == owner_gid,
        "transactional_runtime_source_owned_request_package_rejected",
    )


def _request_collection_root_metadata(
    *, request_root: Path, owner_uid: int, owner_gid: int
) -> os.stat_result:
    try:
        metadata = request_root.lstat()
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_source_owned_request_collection_rejected"
        ) from exc
    require(
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == 0o700
        and metadata.st_uid == owner_uid
        and metadata.st_gid == owner_gid,
        "transactional_runtime_source_owned_request_collection_rejected",
    )
    return metadata


def _rename_no_replace(
    source: Path,
    target: Path,
    *,
    source_dir_fd: int = -100,
    target_dir_fd: int = -100,
) -> None:
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_source_owned_request_finalize_unavailable"
        ) from exc
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        source_dir_fd,
        os.fsencode(source),
        target_dir_fd,
        os.fsencode(target),
        1,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_source_owned_request_replay_rejected"
        )
    raise TransactionalRuntimeRejected(
        "transactional_runtime_source_owned_request_finalize_rejected"
    )


def _verify_request_collection_descriptor(
    *,
    descriptor: int,
    request_root: Path,
    owner_uid: int,
    owner_gid: int,
) -> os.stat_result:
    path_metadata = _request_collection_root_metadata(
        request_root=request_root, owner_uid=owner_uid, owner_gid=owner_gid
    )
    try:
        descriptor_metadata = os.fstat(descriptor)
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_source_owned_request_collection_rejected"
        ) from exc
    require(
        stat.S_ISDIR(descriptor_metadata.st_mode)
        and stat.S_IMODE(descriptor_metadata.st_mode) == 0o700
        and descriptor_metadata.st_uid == owner_uid
        and descriptor_metadata.st_gid == owner_gid
        and descriptor_metadata.st_dev == path_metadata.st_dev
        and descriptor_metadata.st_ino == path_metadata.st_ino,
        "transactional_runtime_source_owned_request_collection_rejected",
    )
    return descriptor_metadata


def _verify_source_owned_request_package(
    *,
    request: Mapping[str, object] | None,
    request_root: Path,
    request_id: str,
    owner_uid: int,
    owner_gid: int,
) -> dict[str, object]:
    require(
        bool(_REQUEST_ID_PATTERN.fullmatch(request_id)),
        "transactional_runtime_source_owned_request_identity_rejected",
    )
    package_path = request_root / request_id
    try:
        root_metadata = request_root.lstat()
        package_metadata = package_path.lstat()
        names = sorted(path.name for path in package_path.iterdir())
        stored_request = _canonical_read(
            package_path / "request.json",
            "transactional_runtime_source_owned_request_package_rejected",
        )
    except (OSError, TypeError, ValueError) as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_source_owned_request_package_rejected"
        ) from exc
    require(
        isinstance(stored_request, Mapping),
        "transactional_runtime_source_owned_request_package_rejected",
    )
    selected_request = dict(stored_request)
    if request is not None:
        require(
            selected_request == dict(request)
            and canonical(selected_request) == canonical(request),
            "transactional_runtime_source_owned_request_package_rejected",
        )
    try:
        semantic = _request_package_semantic(selected_request)
    except (KeyError, TypeError, ValueError) as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_source_owned_request_package_rejected"
        ) from exc
    require(
        request_id == semantic["request_id"],
        "transactional_runtime_source_owned_request_identity_rejected",
    )
    require(
        stat.S_ISDIR(root_metadata.st_mode)
        and not stat.S_ISLNK(root_metadata.st_mode)
        and stat.S_IMODE(root_metadata.st_mode) == 0o700
        and root_metadata.st_uid == owner_uid
        and root_metadata.st_gid == owner_gid
        and stat.S_ISDIR(package_metadata.st_mode)
        and not stat.S_ISLNK(package_metadata.st_mode)
        and stat.S_IMODE(package_metadata.st_mode) == 0o700
        and package_metadata.st_uid == owner_uid
        and package_metadata.st_gid == owner_gid
        and package_metadata.st_nlink == 2
        and names == ["completion.json", "receipt.json", "request.json"],
        "transactional_runtime_source_owned_request_package_rejected",
    )
    request_bytes = canonical(selected_request)
    receipt = _canonical_read(
        package_path / "receipt.json",
        "transactional_runtime_source_owned_request_package_rejected",
    )
    completion = _canonical_read(
        package_path / "completion.json",
        "transactional_runtime_source_owned_request_package_rejected",
    )
    expected_receipt = {
        "constructor_source_id": REQUEST_CONSTRUCTOR_SOURCE_ID,
        "flags": dict(_ZERO_FLAGS),
        "request_id": request_id,
        "request_sha256": semantic["request_sha256"],
        "request_size": semantic["request_size"],
        "schema": REQUEST_CONSTRUCTOR_RECEIPT_SCHEMA,
        "semantic_digest": digest("p07_source_owned_request_semantic", semantic),
        "status": "materialized",
    }
    receipt_bytes = canonical(expected_receipt)
    expected_completion = {
        "constructor_source_id": REQUEST_CONSTRUCTOR_SOURCE_ID,
        "receipt_sha256": sha256(receipt_bytes).hexdigest(),
        "request_id": request_id,
        "request_sha256": semantic["request_sha256"],
        "schema": REQUEST_CONSTRUCTOR_COMPLETION_SCHEMA,
    }
    completion_bytes = canonical(expected_completion)
    require(
        receipt == expected_receipt and completion == expected_completion,
        "transactional_runtime_source_owned_request_package_rejected",
    )
    for name, payload in (
        ("request.json", request_bytes),
        ("receipt.json", receipt_bytes),
        ("completion.json", completion_bytes),
    ):
        _verify_request_package_file(
            package_path / name,
            payload=payload,
            mode=0o600,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
    return {
        "completion_sha256": sha256(completion_bytes).hexdigest(),
        "constructor_source_id": REQUEST_CONSTRUCTOR_SOURCE_ID,
        "flags": dict(_ZERO_FLAGS),
        "receipt_sha256": sha256(receipt_bytes).hexdigest(),
        "request_id": request_id,
        "request_path": (package_path / "request.json").as_posix(),
        "request_sha256": semantic["request_sha256"],
        "schema": REQUEST_CONSTRUCTOR_RECEIPT_SCHEMA,
        "status": "verified",
    }


def _verify_source_owned_request_collection(
    *, request_root: Path, owner_uid: int, owner_gid: int
) -> dict[str, object]:
    initial_metadata = _request_collection_root_metadata(
        request_root=request_root, owner_uid=owner_uid, owner_gid=owner_gid
    )
    try:
        initial_names = sorted(path.name for path in request_root.iterdir())
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_source_owned_request_collection_rejected"
        ) from exc
    require(
        all(_REQUEST_ID_PATTERN.fullmatch(name) for name in initial_names),
        "transactional_runtime_source_owned_request_collection_rejected",
    )
    identities = []
    for request_id in initial_names:
        try:
            verified = _verify_source_owned_request_package(
                request=None,
                request_root=request_root,
                request_id=request_id,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            )
        except TransactionalRuntimeRejected as exc:
            raise TransactionalRuntimeRejected(
                "transactional_runtime_source_owned_request_collection_rejected"
            ) from exc
        identities.append(
            {
                "completion_sha256": verified["completion_sha256"],
                "receipt_sha256": verified["receipt_sha256"],
                "request_id": request_id,
                "request_sha256": verified["request_sha256"],
            }
        )
    try:
        final_metadata = request_root.lstat()
        final_names = sorted(path.name for path in request_root.iterdir())
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_source_owned_request_collection_rejected"
        ) from exc
    require(
        initial_names == final_names
        and initial_metadata.st_dev == final_metadata.st_dev
        and initial_metadata.st_ino == final_metadata.st_ino
        and final_metadata.st_nlink == 2 + len(final_names),
        "transactional_runtime_source_owned_request_collection_rejected",
    )
    semantic = {
        "requests": identities,
        "schema": REQUEST_COLLECTION_SCHEMA,
        "source_id": REQUEST_COLLECTION_SOURCE_ID,
    }
    return {
        "collection_count": len(identities),
        "collection_digest": digest("p07_source_owned_request_collection", semantic),
        "collection_schema": REQUEST_COLLECTION_SCHEMA,
        "collection_source_id": REQUEST_COLLECTION_SOURCE_ID,
    }


def _materialize_source_owned_request(
    *,
    request: Mapping[str, object],
    request_root: Path,
    owner_uid: int,
    owner_gid: int,
    maximum_count: int | None = None,
    crash_hook: Callable[[str], None] | None = None,
) -> dict[str, object]:
    require(
        request_root.is_absolute(),
        "transactional_runtime_source_owned_request_root_rejected",
    )
    semantic = _request_package_semantic(request)
    request_id = str(semantic["request_id"])
    request_bytes = canonical(request)
    receipt = {
        "constructor_source_id": REQUEST_CONSTRUCTOR_SOURCE_ID,
        "flags": dict(_ZERO_FLAGS),
        "request_id": request_id,
        "request_sha256": semantic["request_sha256"],
        "request_size": semantic["request_size"],
        "schema": REQUEST_CONSTRUCTOR_RECEIPT_SCHEMA,
        "semantic_digest": digest("p07_source_owned_request_semantic", semantic),
        "status": "materialized",
    }
    receipt_bytes = canonical(receipt)
    completion = {
        "constructor_source_id": REQUEST_CONSTRUCTOR_SOURCE_ID,
        "receipt_sha256": sha256(receipt_bytes).hexdigest(),
        "request_id": request_id,
        "request_sha256": semantic["request_sha256"],
        "schema": REQUEST_CONSTRUCTOR_COMPLETION_SCHEMA,
    }
    completion_bytes = canonical(completion)
    parent_path = request_root.parent
    try:
        parent_metadata = parent_path.lstat()
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_source_owned_request_parent_rejected"
        ) from exc
    require(
        stat.S_ISDIR(parent_metadata.st_mode)
        and not stat.S_ISLNK(parent_metadata.st_mode)
        and parent_metadata.st_uid == owner_uid
        and parent_metadata.st_gid == owner_gid
        and stat.S_IMODE(parent_metadata.st_mode) & 0o022 == 0,
        "transactional_runtime_source_owned_request_parent_rejected",
    )
    created = False
    try:
        request_root.mkdir(mode=0o700)
        created = True
    except FileExistsError:
        pass
    if created:
        os.chown(request_root, owner_uid, owner_gid)
        os.chmod(request_root, 0o700)
        _fsync_directory(parent_path)
        if crash_hook is not None:
            crash_hook("root_created")
    _request_collection_root_metadata(
        request_root=request_root, owner_uid=owner_uid, owner_gid=owner_gid
    )
    try:
        descriptor = os.open(
            request_root,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_source_owned_request_collection_rejected"
        ) from exc
    locked = False
    try:
        _verify_request_collection_descriptor(
            descriptor=descriptor,
            request_root=request_root,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                raise TransactionalRuntimeRejected(
                    "transactional_runtime_source_owned_request_concurrent_writer"
                ) from exc
            raise TransactionalRuntimeRejected(
                "transactional_runtime_source_owned_request_lock_rejected"
            ) from exc
        if crash_hook is not None:
            crash_hook("writer_locked")
        before = _verify_source_owned_request_collection(
            request_root=request_root, owner_uid=owner_uid, owner_gid=owner_gid
        )
        if maximum_count is not None:
            require(
                maximum_count >= 0
                and before["collection_count"] < maximum_count,
                "transactional_runtime_source_owned_request_collection_closed",
            )
        _verify_request_collection_descriptor(
            descriptor=descriptor,
            request_root=request_root,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        final_path = request_root / request_id
        temporary = request_root / f".{request_id}.tmp"
        require(
            not final_path.exists() and not final_path.is_symlink(),
            "transactional_runtime_source_owned_request_replay_rejected",
        )
        require(
            not temporary.exists() and not temporary.is_symlink(),
            "transactional_runtime_source_owned_request_collection_rejected",
        )
        temporary.mkdir(mode=0o700)
        os.chown(temporary, owner_uid, owner_gid)
        os.chmod(temporary, 0o700)
        _fsync_directory(request_root)
        if crash_hook is not None:
            crash_hook("temporary_created")
        _atomic_write(temporary / "request.json", request_bytes, mode=0o600)
        _set_file_owner_and_fsync(
            temporary / "request.json", owner_uid=owner_uid, owner_gid=owner_gid
        )
        _fsync_directory(temporary)
        if crash_hook is not None:
            crash_hook("request_written")
        _atomic_write(temporary / "receipt.json", receipt_bytes, mode=0o600)
        _set_file_owner_and_fsync(
            temporary / "receipt.json", owner_uid=owner_uid, owner_gid=owner_gid
        )
        _fsync_directory(temporary)
        if crash_hook is not None:
            crash_hook("receipt_written")
        _atomic_write(temporary / "completion.json", completion_bytes, mode=0o600)
        _set_file_owner_and_fsync(
            temporary / "completion.json", owner_uid=owner_uid, owner_gid=owner_gid
        )
        _fsync_directory(temporary)
        if crash_hook is not None:
            crash_hook("completion_written")
        for name, payload in (
            ("request.json", request_bytes),
            ("receipt.json", receipt_bytes),
            ("completion.json", completion_bytes),
        ):
            _verify_request_package_file(
                temporary / name,
                payload=payload,
                mode=0o600,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            )
        _verify_request_collection_descriptor(
            descriptor=descriptor,
            request_root=request_root,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        _rename_no_replace(
            Path(temporary.name),
            Path(final_path.name),
            source_dir_fd=descriptor,
            target_dir_fd=descriptor,
        )
        _fsync_directory(request_root)
        if crash_hook is not None:
            crash_hook("finalized")
        verified = _verify_source_owned_request_package(
            request=request,
            request_root=request_root,
            request_id=request_id,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        collection = _verify_source_owned_request_collection(
            request_root=request_root, owner_uid=owner_uid, owner_gid=owner_gid
        )
        _verify_request_collection_descriptor(
            descriptor=descriptor,
            request_root=request_root,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        require(
            collection["collection_count"] == before["collection_count"] + 1,
            "transactional_runtime_source_owned_request_collection_rejected",
        )
        return {
            **verified,
            **collection,
            "collection_count_before": before["collection_count"],
        }
    finally:
        try:
            if locked:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def materialize_source_owned_request() -> dict[str, object]:
    require(
        os.geteuid() == 0 and os.getegid() == 0,
        "transactional_runtime_source_owned_request_privilege_rejected",
    )
    request = construct_source_owned_prepare_request()
    return _materialize_source_owned_request(
        request=request,
        request_root=SOURCE_OWNED_REQUEST_ROOT,
        owner_uid=0,
        owner_gid=0,
        maximum_count=MAX_SOURCE_OWNED_REQUEST_COUNT,
    )


def _production_failed_request_contract() -> dict[str, object]:
    return {
        "p08_accepted": {
            "acceptance_projection_digest": P08_ACCEPTED_PROJECTION_DIGEST,
            "controller_sha256": P08_ACCEPTED_CONTROLLER_SHA256,
            "handoff_name": P08_ACCEPTED_HANDOFF_NAME,
            "handoff_sha256": P08_ACCEPTED_HANDOFF_SHA256,
            "installed_inventory_digest": P08_ACCEPTED_INSTALLED_INVENTORY_DIGEST,
            "manifest_sha256": P08_ACCEPTED_MANIFEST_SHA256,
            "release_digest": P08_ACCEPTED_RELEASE,
            "selector_env_sha256": P08_ACCEPTED_SELECTOR_ENV_SHA256,
            "selector_sha256": P08_ACCEPTED_SELECTOR_SHA256,
            "source_inventory_digest": P08_ACCEPTED_SOURCE_INVENTORY_DIGEST,
            "status": P08_ACCEPTED_STATUS,
        },
        "terminal": {
            "collection_count": MAX_SOURCE_OWNED_REQUEST_COUNT,
            "collection_digest": TERMINAL_REQUEST_COLLECTION_DIGEST,
            "completion_sha256": TERMINAL_REQUEST_COMPLETION_SHA256,
            "deploy_commit": TERMINAL_REQUEST_DEPLOY_COMMIT,
            "deploy_tree": TERMINAL_REQUEST_DEPLOY_TREE,
            "handoff_name": TERMINAL_HANDOFF_NAME,
            "handoff_sha256": TERMINAL_HANDOFF_SHA256,
            "manifest_sha256": TERMINAL_REQUEST_MANIFEST_SHA256,
            "payload_target_owner_gid": (
                TERMINAL_REQUEST_PAYLOAD_TARGET_OWNER_GID
            ),
            "payload_target_owner_uid": (
                TERMINAL_REQUEST_PAYLOAD_TARGET_OWNER_UID
            ),
            "receipt_sha256": TERMINAL_REQUEST_RECEIPT_SHA256,
            "rejection_reason": TERMINAL_REJECTION_REASON,
            "rejection_sha256": TERMINAL_REJECTION_SHA256,
            "request_id": TERMINAL_REQUEST_ID,
            "request_sha256": TERMINAL_REQUEST_SHA256,
            "runtime_bundle_id": TERMINAL_REQUEST_BUNDLE_ID,
        },
    }


def _historical_terminal_content_free_rejection(reason: str) -> dict[str, object]:
    """Reproduce the immutable v5 terminal envelope byte-for-byte."""

    return {
        "activation_failure_code": None,
        "flags": dict(_ZERO_FLAGS),
        "reason_code": reason,
        "rollback_failure_code": None,
        "schema": HISTORICAL_TERMINAL_CLI_RESULT_SCHEMA,
        "source_id": HISTORICAL_TERMINAL_RUNTIME_SOURCE_ID,
        "status": "rejected",
        "strategy_id": STRATEGY_ID,
    }


def _content_free_rejection(
    reason: str, *, strategy_context: object = None
) -> dict[str, object]:
    selected = _validated_rejection_strategy_context(strategy_context)
    projection: dict[str, object] = {
        "activation_failure_code": None,
        "flags": dict(_ZERO_FLAGS),
        "reason_code": reason,
        "rollback_failure_code": None,
        "schema": CLI_RESULT_SCHEMA,
        "source_id": SOURCE_ID,
        "status": "rejected",
        "strategy_context_schema": REJECTION_STRATEGY_CONTEXT_SCHEMA,
        "strategy_context_status": "unavailable",
    }
    if selected is not None:
        projection.update(
            {
                "strategy_context_digest": selected.context_digest,
                "strategy_context_status": f"{selected.context_kind}_verified",
                "strategy_digest": selected.strategy_digest,
                "strategy_id": selected.strategy_id,
                "strategy_schema": selected.strategy_schema,
            }
        )
    return projection


def _verified_evidence_sha256(
    evidence_root: Path, *, name: str, expected_sha256: str, code: str
) -> str:
    path = evidence_root / name
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as exc:
        raise TransactionalRuntimeRejected(code) from exc
    require(
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_nlink == 1
        and sha256(payload).hexdigest() == expected_sha256,
        code,
    )
    return expected_sha256


def _failed_request_intent_from_manifest(
    *,
    manifest: Mapping[str, object],
    manifest_sha256: str,
    lineages: Mapping[str, object],
    owner_uid: object,
    owner_gid: object,
    expected_terminal: Mapping[str, object] | None,
) -> dict[str, object]:
    selected_manifest = validate_runtime_artifact_manifest(
        manifest,
        manifest_sha256=_require_sha(
            manifest_sha256,
            "transactional_runtime_failed_request_intent_rejected",
        ),
        expected_bundle_id=_require_sha(
            manifest.get("bundle_id"),
            "transactional_runtime_failed_request_intent_rejected",
        ),
        expected_manifest_sha256=manifest_sha256,
        terminal_predecessor=expected_terminal is not None,
    )
    source = dict(selected_manifest["source"])
    runtime_projection = runtime_artifact.validate_projection(
        selected_manifest["runtime_artifact"]
    )
    plugin = plugin_artifact.validate_binding(selected_manifest["plugin"])
    selected_lineages = parent.validate_immutable_lineages(lineages)
    require(
        type(owner_uid) is int
        and int(owner_uid) >= 0
        and type(owner_gid) is int
        and int(owner_gid) >= 0,
        "transactional_runtime_failed_request_intent_rejected",
    )
    if expected_terminal is not None:
        require(
            source["core_commit"] == CORE_SOURCE_COMMIT
            and source["core_tree"] == CORE_SOURCE_TREE
            and source["deploy_commit"] == expected_terminal["deploy_commit"]
            and source["deploy_tree"] == expected_terminal["deploy_tree"]
            and selected_manifest["bundle_id"]
            == expected_terminal["runtime_bundle_id"]
            and manifest_sha256 == expected_terminal["manifest_sha256"]
            and owner_uid == expected_terminal["payload_target_owner_uid"]
            and owner_gid == expected_terminal["payload_target_owner_gid"],
            "transactional_runtime_failed_request_terminal_identity_rejected",
        )
    return {
        "core_commit": source["core_commit"],
        "core_tree": source["core_tree"],
        "lineage_evidence_digest": selected_lineages["evidence_digest"],
        "mode": "prepare-package",
        "owner_gid": owner_gid,
        "owner_uid": owner_uid,
        "plugin_source_id": plugin["schema"],
        "production_plan_source_id": manifest["parent"]["production_plan_source_id"],
        "runtime_profile": runtime_projection["runtime_profile"],
        "runtime_source_id": source["runtime_source_id"],
        "strategy_id": STRATEGY_ID,
    }


def _failed_request_intent_projection(
    request: Mapping[str, object], *, expected_terminal: Mapping[str, object] | None
) -> dict[str, object]:
    selected = _request_fields(
        request,
        mode="prepare-package",
        fields={
            "core_candidate",
            "expected_runtime_bundle_id",
            "expected_runtime_manifest_sha256",
            "lineages",
            "owner_gid",
            "owner_uid",
            "plugin_candidate",
            "runtime_candidate",
            "runtime_manifest",
            "runtime_manifest_sha256",
        },
    )
    require(
        isinstance(selected["runtime_manifest"], Mapping)
        and isinstance(selected["lineages"], Mapping),
        "transactional_runtime_failed_request_intent_rejected",
    )
    manifest_sha = _require_sha(
        selected["runtime_manifest_sha256"],
        "transactional_runtime_failed_request_intent_rejected",
    )
    manifest = validate_runtime_artifact_manifest(
        selected["runtime_manifest"],
        manifest_sha256=manifest_sha,
        expected_bundle_id=_require_sha(
            selected["expected_runtime_bundle_id"],
            "transactional_runtime_failed_request_intent_rejected",
        ),
        expected_manifest_sha256=_require_sha(
            selected["expected_runtime_manifest_sha256"],
            "transactional_runtime_failed_request_intent_rejected",
        ),
        terminal_predecessor=expected_terminal is not None,
    )
    return _failed_request_intent_from_manifest(
        manifest=manifest,
        manifest_sha256=manifest_sha,
        lineages=selected["lineages"],
        owner_uid=selected["owner_uid"],
        owner_gid=selected["owner_gid"],
        expected_terminal=expected_terminal,
    )


def _target_contract_from_manifest(
    *,
    manifest: Mapping[str, object],
    manifest_sha256: str,
    client_sha256: str,
    protocol_acceptance_source_sha256: str,
    service_entrypoint_sha256: str,
    future_unit_sha256: str,
    future_socket_unit_sha256: str,
) -> dict[str, object]:
    manifest = dict(manifest)
    source = dict(manifest["source"])
    runtime_projection = runtime_artifact.validate_projection(manifest["runtime_artifact"])
    plugin = plugin_artifact.validate_binding(manifest["plugin"])
    protocol_acceptance_contract = production.p08_protocol_acceptance_contract()
    require(
        protocol_acceptance_contract["contract_digest"]
        == P08_PROTOCOL_ACCEPTANCE_CONTRACT_DIGEST,
        "transactional_runtime_failed_request_p08_protocol_contract_rejected",
    )
    require(
        protocol_acceptance_source_sha256
        == protocol_acceptance_contract["sha256"],
        "transactional_runtime_failed_request_p08_protocol_source_rejected",
    )
    return {
        "bundle_id": manifest["bundle_id"],
        "bundle_manifest_sha256": manifest_sha256,
        "core_commit": source["core_commit"],
        "core_tree": source["core_tree"],
        "deploy_commit": source["deploy_commit"],
        "deploy_tree": source["deploy_tree"],
        "p08_status_client": {
            "client_id": p08_gateway.STATUS_CLIENT_ID,
            "operation": p08_gateway.STATUS_OPERATION,
            "protocol_schema": p08_gateway.SCHEMA,
            "reviewed_inactive_manifest_sha256": (
                P08_STATUS_STAGE_INACTIVE_MANIFEST_SHA256
            ),
            "reviewed_inactive_release_digest": (
                P08_STATUS_STAGE_INACTIVE_RELEASE_DIGEST
            ),
            "reviewed_inactive_source_inventory_digest": (
                P08_STATUS_STAGE_INACTIVE_SOURCE_INVENTORY_DIGEST
            ),
            "reviewed_future_installed_inventory_digest": (
                P08_STATUS_STAGE_FUTURE_INSTALLED_INVENTORY_DIGEST
            ),
            "reviewed_full_inventory_digest": (
                P08_STATUS_STAGE_FULL_INVENTORY_DIGEST
            ),
            "reviewed_inactive_controller_digest": (
                P08_STATUS_STAGE_CONTROLLER_DIGEST
            ),
            "reviewed_inactive_core_commit": (
                P08_STATUS_STAGE_INACTIVE_CORE_COMMIT
            ),
            "reviewed_inactive_core_tree": P08_STATUS_STAGE_INACTIVE_CORE_TREE,
            "reviewed_inactive_deploy_commit": (
                P08_STATUS_STAGE_INACTIVE_DEPLOY_COMMIT
            ),
            "reviewed_inactive_deploy_tree": (
                P08_STATUS_STAGE_INACTIVE_DEPLOY_TREE
            ),
            "reviewed_inactive_strategy_digest": (
                P08_STATUS_STAGE_STRATEGY_DIGEST
            ),
            "protocol_acceptance_contract": protocol_acceptance_contract,
            "protocol_acceptance_contract_digest": (
                P08_PROTOCOL_ACCEPTANCE_CONTRACT_DIGEST
            ),
            "protocol_acceptance_source_sha256": (
                protocol_acceptance_source_sha256
            ),
            "server_rejection_contract": (
                production.p08_server_rejection_contract()
            ),
            "server_rejection_contract_identity": (
                P08_SERVER_REJECTION_CONTRACT_IDENTITY
            ),
            "service_entrypoint_source_path": (
                P08_STATUS_SERVICE_ENTRYPOINT_SOURCE_PATH
            ),
            "service_entrypoint_sha256": service_entrypoint_sha256,
            "source_identity": p08_gateway.CONTENT_FREE_STATUS_SOURCE_IDENTITY,
            "source_path": P08_STATUS_CLIENT_SOURCE_PATH,
            "source_sha256": client_sha256,
            "status_stage_contract": production.p08_status_stage_contract(),
            "status_stage_contract_identity": (
                P08_STATUS_STAGE_CONTRACT_IDENTITY
            ),
            "status_schema": p08_gateway.CONTENT_FREE_STATUS_SCHEMA,
            "target_server_rejection_projection_sha256": (
                P08_TARGET_SERVER_REJECTION_PROJECTION_SHA256
            ),
            "target_status_stage_projection_sha256": (
                P08_TARGET_STATUS_STAGE_PROJECTION_SHA256
            ),
            "future_socket_unit_source_path": (
                P08_STATUS_FUTURE_SOCKET_UNIT_SOURCE_PATH
            ),
            "future_socket_unit_sha256": future_socket_unit_sha256,
            "future_unit_source_path": P08_STATUS_FUTURE_UNIT_SOURCE_PATH,
            "future_unit_sha256": future_unit_sha256,
        },
        "plugin_binding_digest": plugin["binding_digest"],
        "plugin_manifest_sha256": plugin["target"]["manifest_sha256"],
        "plugin_release_digest": plugin["target"]["release_digest"],
        "rollback_plugin_release_digest": plugin["rollback"]["release_digest"],
        "runtime_binding_digest": runtime_projection["runtime_binding_digest"],
        "runtime_compatibility_digest": runtime_projection["compatibility_digest"],
        "runtime_hybrid_manifest_sha256": runtime_projection[
            "hybrid_manifest_sha256"
        ],
        "runtime_projection_digest": runtime_projection["projection_digest"],
        "runtime_release_digest": runtime_projection["release_digest"],
        "runtime_service_identity_digest": runtime_projection[
            "service_identity_digest"
        ],
        "runtime_source_id": source["runtime_source_id"],
    }


def _target_contract_projection_from_manifest(
    manifest: Mapping[str, object],
    *,
    manifest_sha256: str,
    deploy_source: Path,
) -> dict[str, object]:
    selected_manifest = dict(manifest)
    client_path = deploy_source / P08_STATUS_CLIENT_SOURCE_PATH
    protocol_acceptance_source_path = (
        deploy_source / production.P08_PROTOCOL_ACCEPTANCE_SOURCE_PATH
    )
    service_entrypoint_path = (
        deploy_source / P08_STATUS_SERVICE_ENTRYPOINT_SOURCE_PATH
    )
    future_unit_path = deploy_source / P08_STATUS_FUTURE_UNIT_SOURCE_PATH
    future_socket_unit_path = (
        deploy_source / P08_STATUS_FUTURE_SOCKET_UNIT_SOURCE_PATH
    )
    client_identity = _regular_file_identity(
        client_path, code="transactional_runtime_failed_request_p08_client_rejected"
    )
    protocol_acceptance_source_identity = _regular_file_identity(
        protocol_acceptance_source_path,
        code="transactional_runtime_failed_request_p08_protocol_source_rejected",
    )
    service_entrypoint_identity = _regular_file_identity(
        service_entrypoint_path,
        code="transactional_runtime_failed_request_p08_service_rejected",
    )
    future_unit_identity = _regular_file_identity(
        future_unit_path,
        code="transactional_runtime_failed_request_p08_unit_rejected",
    )
    future_socket_unit_identity = _regular_file_identity(
        future_socket_unit_path,
        code="transactional_runtime_failed_request_p08_socket_unit_rejected",
    )
    require(
        client_identity["sha256"] == P08_STATUS_CLIENT_SOURCE_SHA256,
        "transactional_runtime_failed_request_p08_client_rejected",
    )
    require(
        protocol_acceptance_source_identity["sha256"]
        == production.P08_PROTOCOL_ACCEPTANCE_SOURCE_SHA256,
        "transactional_runtime_failed_request_p08_protocol_source_rejected",
    )
    require(
        service_entrypoint_identity["sha256"]
        == P08_STATUS_SERVICE_ENTRYPOINT_SHA256,
        "transactional_runtime_failed_request_p08_service_rejected",
    )
    require(
        future_unit_identity["sha256"] == P08_STATUS_FUTURE_UNIT_SHA256,
        "transactional_runtime_failed_request_p08_unit_rejected",
    )
    require(
        future_socket_unit_identity["sha256"]
        == P08_STATUS_FUTURE_SOCKET_UNIT_SHA256,
        "transactional_runtime_failed_request_p08_socket_unit_rejected",
    )
    return _target_contract_from_manifest(
        manifest=selected_manifest,
        manifest_sha256=manifest_sha256,
        client_sha256=str(client_identity["sha256"]),
        protocol_acceptance_source_sha256=str(
            protocol_acceptance_source_identity["sha256"]
        ),
        service_entrypoint_sha256=str(
            service_entrypoint_identity["sha256"]
        ),
        future_unit_sha256=str(future_unit_identity["sha256"]),
        future_socket_unit_sha256=str(
            future_socket_unit_identity["sha256"]
        ),
    )


def _allowed_continuation_source_paths() -> set[str]:
    return {
        "docs/ADR-077-p08-existing-state-upgrade-v1.md",
        "docs/ADR-078-p07-immutable-failed-request-continuation.md",
        "docs/ADR-079-p07-p08-content-free-status-stage-projection.md",
        "scripts/build_p07_hybrid_live_releases_v1.py",
        "scripts/build_p07_owner_private_memory_transactional_runtime.py",
        "scripts/build_p08_active_temporal_release_v2.py",
        "scripts/p07_owner_private_memory_production_plan.py",
        "scripts/p07_owner_private_memory_transactional_runtime.py",
        "scripts/p08_existing_state_upgrade_v1.py",
        "scripts/p08_post_target_action_v1.py",
        "scripts/p08_temporal_gateway_v1.py",
        "tests/test_build_p07_owner_private_memory_transactional_runtime.py",
        "tests/test_p07_hybrid_live_activation.py",
        "tests/test_p07_owner_private_memory_production_plan.py",
        "tests/test_p07_owner_private_memory_transactional_runtime.py",
        "tests/test_p08_activation_packaging_v1.py",
        "tests/test_p08_existing_state_upgrade_v1.py",
        "tests/test_p08_post_target_action_v1.py",
        "tests/test_p08_telegram_gateway_v1.py",
    }


def _build_failed_request_continuation_payload(
    *,
    terminal_request: Mapping[str, object],
    current_manifest: Mapping[str, object],
    current_manifest_sha256: str,
    current_lineages: Mapping[str, object],
    current_owner_uid: object,
    current_owner_gid: object,
    deploy_source: Path,
    contract: Mapping[str, object],
) -> dict[str, object]:
    terminal = dict(contract["terminal"])
    terminal_intent = _failed_request_intent_projection(
        terminal_request, expected_terminal=terminal
    )
    current_intent = _failed_request_intent_from_manifest(
        manifest=current_manifest,
        manifest_sha256=current_manifest_sha256,
        lineages=current_lineages,
        owner_uid=current_owner_uid,
        owner_gid=current_owner_gid,
        expected_terminal=None,
    )
    require(
        terminal_intent == current_intent,
        "transactional_runtime_failed_request_intent_drifted",
    )
    target = _target_contract_projection_from_manifest(
        current_manifest,
        manifest_sha256=current_manifest_sha256,
        deploy_source=deploy_source,
    )
    return _assemble_failed_request_continuation_payload(
        current_intent=current_intent,
        target_contract=target,
        contract=contract,
    )


def _assemble_failed_request_continuation_payload(
    *,
    current_intent: Mapping[str, object],
    target_contract: Mapping[str, object],
    contract: Mapping[str, object],
) -> dict[str, object]:
    terminal = dict(contract["terminal"])
    p08_accepted = dict(contract["p08_accepted"])
    semantic = {
        "flags": dict(_ZERO_FLAGS),
        "fresh_p08_status_required": True,
        "immutable_lineage_evidence_digest": IMMUTABLE_LINEAGE_EVIDENCE_DIGEST,
        "intent_digest": digest("p07_failed_request_intent", current_intent),
        "p08_accepted": p08_accepted,
        "request_collection": {
            "collection_count": terminal["collection_count"],
            "collection_digest": terminal["collection_digest"],
            "closed": True,
            "third_request_allowed": False,
        },
        "schema": FAILED_REQUEST_CONTINUATION_SCHEMA,
        "source_id": FAILED_REQUEST_CONTINUATION_SOURCE_ID,
        "status": "awaiting_fresh_p08_status",
        "target_contract": dict(target_contract),
        "terminal_rejection": {
            "reason": terminal["rejection_reason"],
            "reinterpreted_as_ready": False,
            "sha256": terminal["rejection_sha256"],
        },
        "terminal_request": {
            "completion_sha256": terminal["completion_sha256"],
            "handoff_sha256": terminal["handoff_sha256"],
            "receipt_sha256": terminal["receipt_sha256"],
            "replayed": False,
            "request_id": terminal["request_id"],
            "request_sha256": terminal["request_sha256"],
        },
    }
    return {
        **semantic,
        "continuation_id": digest("p07_immutable_failed_request_continuation", semantic),
    }


def _validate_failed_request_continuation_payload(
    payload: Mapping[str, object],
    *,
    runtime_manifest: Mapping[str, object],
    runtime_manifest_sha256: str,
    lineages: Mapping[str, object],
) -> dict[str, object]:
    manifest = dict(runtime_manifest)
    current_intent = _failed_request_intent_from_manifest(
        manifest=manifest,
        manifest_sha256=runtime_manifest_sha256,
        lineages=lineages,
        owner_uid=TERMINAL_REQUEST_PAYLOAD_TARGET_OWNER_UID,
        owner_gid=TERMINAL_REQUEST_PAYLOAD_TARGET_OWNER_GID,
        expected_terminal=None,
    )
    expected_target = _target_contract_from_manifest(
        manifest=manifest,
        manifest_sha256=runtime_manifest_sha256,
        client_sha256=P08_STATUS_CLIENT_SOURCE_SHA256,
        protocol_acceptance_source_sha256=(
            production.P08_PROTOCOL_ACCEPTANCE_SOURCE_SHA256
        ),
        service_entrypoint_sha256=P08_STATUS_SERVICE_ENTRYPOINT_SHA256,
        future_unit_sha256=P08_STATUS_FUTURE_UNIT_SHA256,
        future_socket_unit_sha256=P08_STATUS_FUTURE_SOCKET_UNIT_SHA256,
    )
    expected = _assemble_failed_request_continuation_payload(
        current_intent=current_intent,
        target_contract=expected_target,
        contract=_production_failed_request_contract(),
    )
    selected = dict(payload)
    require(
        selected == expected and canonical(selected) == canonical(expected),
        "transactional_runtime_failed_request_continuation_binding_rejected",
    )
    return selected


def _construct_failed_request_continuation(
    *,
    core_source: Path,
    deploy_source: Path,
    runtime_build_root: Path,
    bundle_root: Path,
    evidence_root: Path,
    request_root: Path,
    owner_uid: int,
    owner_gid: int,
    owner_account: str,
    contract: Mapping[str, object] | None = None,
    lineage_loader: Callable[[Path], Mapping[str, object]] = _source_owned_lineages,
) -> dict[str, object]:
    selected_contract = (
        _production_failed_request_contract() if contract is None else dict(contract)
    )
    terminal = dict(selected_contract["terminal"])
    p08_accepted = dict(selected_contract["p08_accepted"])
    collection = _verify_source_owned_request_collection(
        request_root=request_root, owner_uid=owner_uid, owner_gid=owner_gid
    )
    require(
        collection["collection_count"] == terminal["collection_count"]
        and collection["collection_digest"] == terminal["collection_digest"]
        and collection["collection_count"] == MAX_SOURCE_OWNED_REQUEST_COUNT,
        "transactional_runtime_failed_request_collection_rejected",
    )
    terminal_verified = _verify_source_owned_request_package(
        request=None,
        request_root=request_root,
        request_id=str(terminal["request_id"]),
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    require(
        terminal_verified["request_sha256"] == terminal["request_sha256"]
        and terminal_verified["receipt_sha256"] == terminal["receipt_sha256"]
        and terminal_verified["completion_sha256"] == terminal["completion_sha256"],
        "transactional_runtime_failed_request_terminal_identity_rejected",
    )
    terminal_request = _canonical_read(
        request_root / str(terminal["request_id"]) / "request.json",
        "transactional_runtime_failed_request_terminal_identity_rejected",
    )
    _verified_evidence_sha256(
        evidence_root,
        name=str(terminal["handoff_name"]),
        expected_sha256=str(terminal["handoff_sha256"]),
        code="transactional_runtime_failed_request_terminal_evidence_rejected",
    )
    _verified_evidence_sha256(
        evidence_root,
        name=str(p08_accepted["handoff_name"]),
        expected_sha256=str(p08_accepted["handoff_sha256"]),
        code="transactional_runtime_failed_request_p08_evidence_rejected",
    )
    rejection = _historical_terminal_content_free_rejection(
        str(terminal["rejection_reason"])
    )
    require(
        sha256(canonical(rejection)[:-1]).hexdigest()
        == terminal["rejection_sha256"],
        "transactional_runtime_failed_request_terminal_rejection_rejected",
    )
    if contract is None:
        require(
            _source_git(deploy_source, "merge-base", "--is-ancestor", TERMINAL_REQUEST_DEPLOY_COMMIT, "HEAD")
            == "",
            "transactional_runtime_failed_request_source_ancestry_rejected",
        )
        changed = {
            row
            for row in _source_git(
                deploy_source,
                "diff",
                "--name-only",
                f"{TERMINAL_REQUEST_DEPLOY_COMMIT}..HEAD",
            ).splitlines()
            if row
        }
        require(
            changed <= _allowed_continuation_source_paths(),
            "transactional_runtime_failed_request_source_scope_rejected",
        )
    current = _source_owned_target_material(
        core_source=core_source,
        deploy_source=deploy_source,
        runtime_build_root=runtime_build_root,
        bundle_root=bundle_root,
        evidence_root=evidence_root,
        owner_account=owner_account,
        lineage_loader=lineage_loader,
    )
    return _build_failed_request_continuation_payload(
        terminal_request=terminal_request,
        current_manifest=current["manifest"],
        current_manifest_sha256=str(current["manifest_sha256"]),
        current_lineages=current["lineages"],
        current_owner_uid=current["owner_uid"],
        current_owner_gid=current["owner_gid"],
        deploy_source=deploy_source,
        contract=selected_contract,
    )


def construct_failed_request_continuation() -> dict[str, object]:
    return _construct_failed_request_continuation(
        core_source=SOURCE_OWNED_CORE_ROOT,
        deploy_source=SOURCE_OWNED_DEPLOY_ROOT,
        runtime_build_root=SOURCE_OWNED_RUNTIME_ARTIFACT_ROOT,
        bundle_root=SOURCE_OWNED_TRANSACTIONAL_BUNDLE_ROOT,
        evidence_root=SOURCE_OWNED_EVIDENCE_ROOT,
        request_root=SOURCE_OWNED_REQUEST_ROOT,
        owner_uid=0,
        owner_gid=0,
        owner_account=SOURCE_OWNED_OWNER_ACCOUNT,
    )


def _continuation_file_identity(
    path: Path, *, payload: bytes, owner_uid: int, owner_gid: int
) -> None:
    metadata = path.lstat()
    require(
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == SOURCE_OWNED_CONTINUATION_FILE_MODE
        and metadata.st_uid == owner_uid
        and metadata.st_gid == owner_gid
        and metadata.st_nlink == 1
        and metadata.st_size == len(payload)
        and sha256(path.read_bytes()).hexdigest() == sha256(payload).hexdigest(),
        "transactional_runtime_failed_request_continuation_rejected",
    )


def _write_continuation_file_no_replace(
    path: Path, *, payload: bytes, owner_uid: int, owner_gid: int
) -> None:
    """Persist one continuation file without any overwrite race."""

    temporary = path.parent / f".{path.name}.{sha256(payload).hexdigest()[:16]}.tmp"
    require(
        not path.exists()
        and not path.is_symlink()
        and not temporary.exists()
        and not temporary.is_symlink(),
        "transactional_runtime_failed_request_continuation_file_write_rejected",
    )
    descriptor: int | None = None
    directory_descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            SOURCE_OWNED_CONTINUATION_FILE_MODE,
        )
        metadata = os.fstat(descriptor)
        if metadata.st_uid != owner_uid or metadata.st_gid != owner_gid:
            os.fchown(descriptor, owner_uid, owner_gid)
        os.fchmod(descriptor, SOURCE_OWNED_CONTINUATION_FILE_MODE)
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _continuation_file_identity(
            temporary,
            payload=payload,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        directory_descriptor = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        _rename_no_replace(
            Path(temporary.name),
            Path(path.name),
            source_dir_fd=directory_descriptor,
            target_dir_fd=directory_descriptor,
        )
        _fsync_directory(path.parent)
        _continuation_file_identity(
            path,
            payload=payload,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
    except (OSError, TransactionalRuntimeRejected) as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_failed_request_continuation_file_write_rejected"
        ) from exc
    finally:
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _continuation_directory_identity(
    path: Path,
    *,
    owner_uid: int,
    owner_gid: int,
    mode: int,
    link_count: int,
    entries: list[str],
    code: str,
) -> None:
    try:
        metadata = path.lstat()
        observed_entries = sorted(item.name for item in path.iterdir())
    except OSError as exc:
        raise TransactionalRuntimeRejected(code) from exc
    require(
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == mode
        and metadata.st_uid == owner_uid
        and metadata.st_gid == owner_gid
        and metadata.st_nlink == link_count
        and observed_entries == entries,
        code,
    )


def _verify_failed_request_continuation(
    *,
    continuation: Mapping[str, object],
    trusted_ancestor: Path,
    continuation_parent: Path,
    continuation_root: Path,
    owner_uid: int,
    owner_gid: int,
    trusted_ancestor_mode: int = SOURCE_OWNED_CONTINUATION_TRUSTED_ANCESTOR_MODE,
    parent_mode: int = SOURCE_OWNED_CONTINUATION_PARENT_MODE,
    root_mode: int = SOURCE_OWNED_CONTINUATION_ROOT_MODE,
) -> dict[str, object]:
    selected = dict(continuation)
    continuation_id = str(selected.get("continuation_id", ""))
    require(
        _REQUEST_ID_PATTERN.fullmatch(continuation_id) is not None,
        "transactional_runtime_failed_request_continuation_identity_rejected",
    )
    child = continuation_root / continuation_id
    try:
        ancestor_metadata = trusted_ancestor.lstat()
        parent_metadata = continuation_parent.lstat()
        root_metadata = continuation_root.lstat()
        child_metadata = child.lstat()
        parent_entries = sorted(path.name for path in continuation_parent.iterdir())
        root_entries = sorted(path.name for path in continuation_root.iterdir())
        child_entries = sorted(path.name for path in child.iterdir())
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_failed_request_continuation_rejected"
        ) from exc
    require(
        trusted_ancestor.is_absolute()
        and continuation_parent.parent == trusted_ancestor
        and continuation_root.parent == continuation_parent
        and stat.S_ISDIR(ancestor_metadata.st_mode)
        and not stat.S_ISLNK(ancestor_metadata.st_mode)
        and stat.S_IMODE(ancestor_metadata.st_mode) == trusted_ancestor_mode
        and ancestor_metadata.st_uid == owner_uid
        and ancestor_metadata.st_gid == owner_gid
        and stat.S_ISDIR(parent_metadata.st_mode)
        and not stat.S_ISLNK(parent_metadata.st_mode)
        and stat.S_IMODE(parent_metadata.st_mode) == parent_mode
        and parent_metadata.st_uid == owner_uid
        and parent_metadata.st_gid == owner_gid
        and parent_metadata.st_nlink == 3
        and parent_entries == [continuation_root.name]
        and stat.S_ISDIR(root_metadata.st_mode)
        and not stat.S_ISLNK(root_metadata.st_mode)
        and stat.S_IMODE(root_metadata.st_mode) == root_mode
        and root_metadata.st_uid == owner_uid
        and root_metadata.st_gid == owner_gid
        and root_metadata.st_nlink == 3
        and root_entries == [continuation_id]
        and stat.S_ISDIR(child_metadata.st_mode)
        and not stat.S_ISLNK(child_metadata.st_mode)
        and stat.S_IMODE(child_metadata.st_mode)
        == SOURCE_OWNED_CONTINUATION_CHILD_MODE
        and child_metadata.st_uid == owner_uid
        and child_metadata.st_gid == owner_gid
        and child_metadata.st_nlink == 2
        and child_entries == ["completion.json", "continuation.json", "receipt.json"],
        "transactional_runtime_failed_request_continuation_rejected",
    )
    stored = _canonical_read(
        child / "continuation.json",
        "transactional_runtime_failed_request_continuation_rejected",
    )
    require(
        stored == selected and canonical(stored) == canonical(selected),
        "transactional_runtime_failed_request_continuation_rejected",
    )
    continuation_bytes = canonical(selected)
    continuation_sha = sha256(continuation_bytes).hexdigest()
    receipt = {
        "continuation_id": continuation_id,
        "continuation_sha256": continuation_sha,
        "flags": dict(_ZERO_FLAGS),
        "schema": FAILED_REQUEST_CONTINUATION_RECEIPT_SCHEMA,
        "source_id": FAILED_REQUEST_CONTINUATION_SOURCE_ID,
        "status": "materialized",
    }
    receipt_bytes = canonical(receipt)
    completion = {
        "continuation_id": continuation_id,
        "continuation_sha256": continuation_sha,
        "receipt_sha256": sha256(receipt_bytes).hexdigest(),
        "schema": FAILED_REQUEST_CONTINUATION_COMPLETION_SCHEMA,
        "source_id": FAILED_REQUEST_CONTINUATION_SOURCE_ID,
    }
    completion_bytes = canonical(completion)
    require(
        _canonical_read(
            child / "receipt.json",
            "transactional_runtime_failed_request_continuation_rejected",
        )
        == receipt
        and _canonical_read(
            child / "completion.json",
            "transactional_runtime_failed_request_continuation_rejected",
        )
        == completion,
        "transactional_runtime_failed_request_continuation_rejected",
    )
    for name, payload in (
        ("continuation.json", continuation_bytes),
        ("receipt.json", receipt_bytes),
        ("completion.json", completion_bytes),
    ):
        _continuation_file_identity(
            child / name,
            payload=payload,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
    return {
        "completion_sha256": sha256(completion_bytes).hexdigest(),
        "continuation": selected,
        "continuation_id": continuation_id,
        "continuation_sha256": continuation_sha,
        "flags": dict(_ZERO_FLAGS),
        "receipt_sha256": sha256(receipt_bytes).hexdigest(),
        "schema": FAILED_REQUEST_CONTINUATION_RECEIPT_SCHEMA,
        "source_id": FAILED_REQUEST_CONTINUATION_SOURCE_ID,
        "status": "verified",
    }


def _materialize_failed_request_continuation(
    *,
    continuation: Mapping[str, object],
    trusted_ancestor: Path,
    continuation_parent: Path,
    continuation_root: Path,
    owner_uid: int,
    owner_gid: int,
    trusted_ancestor_mode: int = SOURCE_OWNED_CONTINUATION_TRUSTED_ANCESTOR_MODE,
    parent_mode: int = SOURCE_OWNED_CONTINUATION_PARENT_MODE,
    root_mode: int = SOURCE_OWNED_CONTINUATION_ROOT_MODE,
    crash_hook: Callable[[str], None] | None = None,
) -> dict[str, object]:
    selected = dict(continuation)
    continuation_id = str(selected["continuation_id"])
    try:
        ancestor_metadata = trusted_ancestor.lstat()
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_failed_request_continuation_namespace_rejected"
        ) from exc
    require(
        trusted_ancestor.is_absolute()
        and continuation_parent.is_absolute()
        and continuation_root.is_absolute()
        and continuation_parent.parent == trusted_ancestor
        and continuation_root.parent == continuation_parent
        and continuation_root != LEGACY_GATEWAY_CONTINUATION_ROOT
        and stat.S_ISDIR(ancestor_metadata.st_mode)
        and not stat.S_ISLNK(ancestor_metadata.st_mode)
        and stat.S_IMODE(ancestor_metadata.st_mode) == trusted_ancestor_mode
        and ancestor_metadata.st_uid == owner_uid
        and ancestor_metadata.st_gid == owner_gid
        and not continuation_parent.exists()
        and not continuation_parent.is_symlink()
        and not continuation_root.exists()
        and not continuation_root.is_symlink(),
        "transactional_runtime_failed_request_continuation_namespace_rejected",
    )
    try:
        continuation_parent.mkdir(mode=parent_mode)
        os.chown(continuation_parent, owner_uid, owner_gid)
        os.chmod(continuation_parent, parent_mode)
        _continuation_directory_identity(
            continuation_parent,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            mode=parent_mode,
            link_count=2,
            entries=[],
            code="transactional_runtime_failed_request_continuation_namespace_rejected",
        )
        _fsync_directory(trusted_ancestor)
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_failed_request_continuation_namespace_rejected"
        ) from exc
    if crash_hook is not None:
        crash_hook("parent_created")
    try:
        continuation_root.mkdir(mode=root_mode)
        os.chown(continuation_root, owner_uid, owner_gid)
        os.chmod(continuation_root, root_mode)
        _continuation_directory_identity(
            continuation_parent,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            mode=parent_mode,
            link_count=3,
            entries=[continuation_root.name],
            code="transactional_runtime_failed_request_continuation_namespace_rejected",
        )
        _continuation_directory_identity(
            continuation_root,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            mode=root_mode,
            link_count=2,
            entries=[],
            code="transactional_runtime_failed_request_continuation_namespace_rejected",
        )
        _fsync_directory(continuation_parent)
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_failed_request_continuation_namespace_rejected"
        ) from exc
    if crash_hook is not None:
        crash_hook("root_created")
    temporary = continuation_root / f".{continuation_id}.tmp"
    final = continuation_root / continuation_id
    temporary.mkdir(mode=SOURCE_OWNED_CONTINUATION_CHILD_MODE)
    os.chown(temporary, owner_uid, owner_gid)
    os.chmod(temporary, SOURCE_OWNED_CONTINUATION_CHILD_MODE)
    _fsync_directory(continuation_root)
    if crash_hook is not None:
        crash_hook("temporary_created")
    continuation_bytes = canonical(selected)
    receipt = {
        "continuation_id": continuation_id,
        "continuation_sha256": sha256(continuation_bytes).hexdigest(),
        "flags": dict(_ZERO_FLAGS),
        "schema": FAILED_REQUEST_CONTINUATION_RECEIPT_SCHEMA,
        "source_id": FAILED_REQUEST_CONTINUATION_SOURCE_ID,
        "status": "materialized",
    }
    receipt_bytes = canonical(receipt)
    completion = {
        "continuation_id": continuation_id,
        "continuation_sha256": sha256(continuation_bytes).hexdigest(),
        "receipt_sha256": sha256(receipt_bytes).hexdigest(),
        "schema": FAILED_REQUEST_CONTINUATION_COMPLETION_SCHEMA,
        "source_id": FAILED_REQUEST_CONTINUATION_SOURCE_ID,
    }
    for stage, name, payload in (
        ("continuation_written", "continuation.json", continuation_bytes),
        ("receipt_written", "receipt.json", receipt_bytes),
        ("completion_written", "completion.json", canonical(completion)),
    ):
        _write_continuation_file_no_replace(
            temporary / name,
            payload=payload,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        _fsync_directory(temporary)
        if crash_hook is not None:
            crash_hook(stage)
    descriptor = os.open(
        continuation_root,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        try:
            _rename_no_replace(
                Path(temporary.name),
                Path(final.name),
                source_dir_fd=descriptor,
                target_dir_fd=descriptor,
            )
        except TransactionalRuntimeRejected as exc:
            raise TransactionalRuntimeRejected(
                "transactional_runtime_failed_request_continuation_finalize_rejected"
            ) from exc
    finally:
        os.close(descriptor)
    _fsync_directory(continuation_root)
    if crash_hook is not None:
        crash_hook("finalized")
    return _verify_failed_request_continuation(
        continuation=selected,
        trusted_ancestor=trusted_ancestor,
        continuation_parent=continuation_parent,
        continuation_root=continuation_root,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        trusted_ancestor_mode=trusted_ancestor_mode,
        parent_mode=parent_mode,
        root_mode=root_mode,
    )


def materialize_failed_request_continuation() -> dict[str, object]:
    require(
        os.geteuid() == 0 and os.getegid() == 0,
        "transactional_runtime_failed_request_continuation_privilege_rejected",
    )
    continuation = construct_failed_request_continuation()
    return _materialize_failed_request_continuation(
        continuation=continuation,
        trusted_ancestor=SOURCE_OWNED_CONTINUATION_TRUSTED_ANCESTOR,
        continuation_parent=SOURCE_OWNED_CONTINUATION_PARENT,
        continuation_root=SOURCE_OWNED_CONTINUATION_ROOT,
        owner_uid=SOURCE_OWNED_CONTINUATION_UID,
        owner_gid=SOURCE_OWNED_CONTINUATION_GID,
    )


def verify_source_owned_failed_request_continuation(
    expected: Mapping[str, object] | None = None,
    *,
    owner_uid: int | None = None,
    owner_gid: int | None = None,
) -> dict[str, object]:
    selected_uid = SOURCE_OWNED_CONTINUATION_UID if owner_uid is None else owner_uid
    selected_gid = SOURCE_OWNED_CONTINUATION_GID if owner_gid is None else owner_gid
    selected = (
        construct_failed_request_continuation() if expected is None else dict(expected)
    )
    return _verify_failed_request_continuation(
        continuation=selected,
        trusted_ancestor=SOURCE_OWNED_CONTINUATION_TRUSTED_ANCESTOR,
        continuation_parent=SOURCE_OWNED_CONTINUATION_PARENT,
        continuation_root=SOURCE_OWNED_CONTINUATION_ROOT,
        owner_uid=selected_uid,
        owner_gid=selected_gid,
    )


def historical_request_evidence_storage_contract() -> dict[str, object]:
    """Bind immutable request evidence storage separately from payload ownership."""

    return {
        "children": json.loads(json.dumps(HISTORICAL_REQUEST_EVIDENCE_CHILDREN)),
        "closed": True,
        "collection_count": MAX_SOURCE_OWNED_REQUEST_COUNT,
        "collection_digest": TERMINAL_REQUEST_COLLECTION_DIGEST,
        "payload_target_owner": {
            "gid": TERMINAL_REQUEST_PAYLOAD_TARGET_OWNER_GID,
            "role": "terminal_request_payload_target_runtime_owner",
            "uid": TERMINAL_REQUEST_PAYLOAD_TARGET_OWNER_UID,
        },
        "root": {
            "gid": HISTORICAL_REQUEST_EVIDENCE_STORAGE_GID,
            "mode": HISTORICAL_REQUEST_EVIDENCE_ROOT_MODE,
            "nlink": 2 + MAX_SOURCE_OWNED_REQUEST_COUNT,
            "type": "directory",
            "uid": HISTORICAL_REQUEST_EVIDENCE_STORAGE_UID,
        },
        "schema": HISTORICAL_REQUEST_EVIDENCE_STORAGE_SCHEMA,
        "source_id": HISTORICAL_REQUEST_EVIDENCE_STORAGE_SOURCE_ID,
        "storage_owner": {
            "gid": HISTORICAL_REQUEST_EVIDENCE_STORAGE_GID,
            "role": "immutable_historical_request_evidence_storage_owner",
            "uid": HISTORICAL_REQUEST_EVIDENCE_STORAGE_UID,
        },
        "storage_role": "immutable_historical_request_evidence_collection",
        "terminal_request_id": TERMINAL_REQUEST_ID,
        "third_request_allowed": False,
    }


def _validate_historical_request_evidence_storage_contract(
    payload: Mapping[str, object], *, require_production_exact: bool
) -> dict[str, object]:
    selected = dict(payload)
    required = {
        "children",
        "closed",
        "collection_count",
        "collection_digest",
        "payload_target_owner",
        "root",
        "schema",
        "source_id",
        "storage_owner",
        "storage_role",
        "terminal_request_id",
        "third_request_allowed",
    }
    require(
        set(selected) == required
        and selected.get("schema") == HISTORICAL_REQUEST_EVIDENCE_STORAGE_SCHEMA
        and selected.get("source_id")
        == HISTORICAL_REQUEST_EVIDENCE_STORAGE_SOURCE_ID
        and selected.get("storage_role")
        == "immutable_historical_request_evidence_collection"
        and selected.get("closed") is True
        and selected.get("third_request_allowed") is False
        and selected.get("collection_count") == MAX_SOURCE_OWNED_REQUEST_COUNT
        and _SHA.fullmatch(str(selected.get("collection_digest", ""))) is not None
        and _REQUEST_ID_PATTERN.fullmatch(
            str(selected.get("terminal_request_id", ""))
        )
        is not None
        and isinstance(selected.get("children"), Mapping)
        and isinstance(selected.get("root"), Mapping)
        and isinstance(selected.get("storage_owner"), Mapping)
        and isinstance(selected.get("payload_target_owner"), Mapping),
        "transactional_runtime_historical_request_evidence_contract_rejected",
    )
    storage_owner = dict(selected["storage_owner"])
    payload_owner = dict(selected["payload_target_owner"])
    require(
        set(storage_owner) == {"gid", "role", "uid"}
        and storage_owner.get("role")
        == "immutable_historical_request_evidence_storage_owner"
        and type(storage_owner.get("uid")) is int
        and type(storage_owner.get("gid")) is int
        and int(storage_owner["uid"]) >= 0
        and int(storage_owner["gid"]) >= 0
        and set(payload_owner) == {"gid", "role", "uid"}
        and payload_owner.get("role")
        == "terminal_request_payload_target_runtime_owner"
        and type(payload_owner.get("uid")) is int
        and type(payload_owner.get("gid")) is int
        and int(payload_owner["uid"]) >= 0
        and int(payload_owner["gid"]) >= 0,
        "transactional_runtime_historical_request_evidence_contract_rejected",
    )
    root = dict(selected["root"])
    require(
        root
        == {
            "gid": storage_owner["gid"],
            "mode": HISTORICAL_REQUEST_EVIDENCE_ROOT_MODE,
            "nlink": 2 + MAX_SOURCE_OWNED_REQUEST_COUNT,
            "type": "directory",
            "uid": storage_owner["uid"],
        },
        "transactional_runtime_historical_request_evidence_contract_rejected",
    )
    children = dict(selected["children"])
    require(
        len(children) == MAX_SOURCE_OWNED_REQUEST_COUNT
        and selected["terminal_request_id"] in children
        and all(_REQUEST_ID_PATTERN.fullmatch(str(name)) for name in children),
        "transactional_runtime_historical_request_evidence_contract_rejected",
    )
    for child in children.values():
        require(
            isinstance(child, Mapping)
            and set(child) == {"directory", "files"}
            and isinstance(child.get("directory"), Mapping)
            and isinstance(child.get("files"), Mapping),
            "transactional_runtime_historical_request_evidence_contract_rejected",
        )
        require(
            dict(child["directory"])
            == {
                "gid": storage_owner["gid"],
                "mode": HISTORICAL_REQUEST_EVIDENCE_CHILD_MODE,
                "nlink": 2,
                "type": "directory",
                "uid": storage_owner["uid"],
            }
            and set(child["files"])
            == {"completion.json", "receipt.json", "request.json"},
            "transactional_runtime_historical_request_evidence_contract_rejected",
        )
        for file_identity in child["files"].values():
            require(
                isinstance(file_identity, Mapping)
                and set(file_identity)
                == {"gid", "mode", "nlink", "sha256", "size", "type", "uid"}
                and file_identity.get("gid") == storage_owner["gid"]
                and file_identity.get("uid") == storage_owner["uid"]
                and file_identity.get("mode")
                == HISTORICAL_REQUEST_EVIDENCE_FILE_MODE
                and file_identity.get("nlink") == 1
                and file_identity.get("type") == "regular"
                and _SHA.fullmatch(str(file_identity.get("sha256", "")))
                is not None
                and type(file_identity.get("size")) is int
                and int(file_identity["size"]) > 0,
                "transactional_runtime_historical_request_evidence_contract_rejected",
            )
    if require_production_exact:
        require(
            selected == historical_request_evidence_storage_contract(),
            "transactional_runtime_historical_request_evidence_contract_rejected",
        )
    return selected


def immutable_continuation_reference_contract() -> dict[str, object]:
    """Return the exact historical continuation as immutable predecessor evidence.

    This is deliberately not a target contract.  In particular, it does not
    compare the historical runtime/bundle with the current target and cannot
    turn the terminal P08 rejection into a ready result.
    """

    semantic = {
        "continuation": {
            "child": {
                "gid": 0,
                "mode": SOURCE_OWNED_CONTINUATION_CHILD_MODE,
                "nlink": 2,
                "type": "directory",
                "uid": 0,
            },
            "continuation_id": IMMUTABLE_CONTINUATION_ID,
            "files": dict(IMMUTABLE_CONTINUATION_FILES),
            "parent": {
                "gid": 0,
                "mode": SOURCE_OWNED_CONTINUATION_PARENT_MODE,
                "nlink": 3,
                "type": "directory",
                "uid": 0,
            },
            "root": {
                "gid": 0,
                "mode": SOURCE_OWNED_CONTINUATION_ROOT_MODE,
                "nlink": 3,
                "type": "directory",
                "uid": 0,
            },
        },
        "historical_target": dict(IMMUTABLE_CONTINUATION_HISTORICAL_SOURCE),
        "lineages": {
            "combined_verifier_digest": IMMUTABLE_LINEAGE_EVIDENCE_DIGEST,
            "dual_state_v2": "1/1",
            "p07_policy_overlay_v1": "2/2",
        },
        "request_collection": historical_request_evidence_storage_contract(),
        "schema": IMMUTABLE_CONTINUATION_REFERENCE_SCHEMA,
        "source_id": IMMUTABLE_CONTINUATION_REFERENCE_SOURCE_ID,
        "terminal_t2": {
            "handoff_name": IMMUTABLE_CONTINUATION_HANDOFF_NAME,
            "handoff_sha256": IMMUTABLE_CONTINUATION_HANDOFF_SHA256,
            "p08_rejection_payload_sha256": (
                IMMUTABLE_CONTINUATION_REJECTION_PAYLOAD_SHA256
            ),
            "p08_rejection_stdout_sha256": (
                IMMUTABLE_CONTINUATION_REJECTION_STDOUT_SHA256
            ),
            "reason": TERMINAL_REJECTION_REASON,
            "reinterpreted_as_ready": False,
            "status": (
                "p07_memory_only_transactional_t2_terminal_p08_status_unavailable"
            ),
        },
    }
    return {
        **semantic,
        "reference_digest": digest(
            "p07_immutable_continuation_reference_v3", semantic
        ),
    }


def _validate_immutable_continuation_reference_contract(
    payload: Mapping[str, object], *, require_production_exact: bool
) -> dict[str, object]:
    selected = dict(payload)
    required = {
        "continuation",
        "historical_target",
        "lineages",
        "reference_digest",
        "request_collection",
        "schema",
        "source_id",
        "terminal_t2",
    }
    require(
        set(selected) == required
        and selected.get("schema") == IMMUTABLE_CONTINUATION_REFERENCE_SCHEMA
        and selected.get("source_id") == IMMUTABLE_CONTINUATION_REFERENCE_SOURCE_ID
        and isinstance(selected.get("continuation"), Mapping)
        and isinstance(selected.get("historical_target"), Mapping)
        and isinstance(selected.get("lineages"), Mapping)
        and isinstance(selected.get("request_collection"), Mapping)
        and isinstance(selected.get("terminal_t2"), Mapping),
        "transactional_runtime_immutable_continuation_reference_rejected",
    )
    semantic = {key: selected[key] for key in required - {"reference_digest"}}
    require(
        selected.get("reference_digest")
        == digest("p07_immutable_continuation_reference_v3", semantic)
        and selected["terminal_t2"].get("reinterpreted_as_ready") is False
        and selected["terminal_t2"].get("reason") == TERMINAL_REJECTION_REASON
        and selected["request_collection"].get("collection_count")
        == MAX_SOURCE_OWNED_REQUEST_COUNT
        and bool(
            _REQUEST_ID_PATTERN.fullmatch(
                str(selected["continuation"].get("continuation_id", ""))
            )
        ),
        "transactional_runtime_immutable_continuation_reference_rejected",
    )
    _validate_historical_request_evidence_storage_contract(
        selected["request_collection"],
        require_production_exact=require_production_exact,
    )
    if require_production_exact:
        require(
            selected == immutable_continuation_reference_contract(),
            "transactional_runtime_immutable_continuation_reference_rejected",
        )
    return selected


def _fixed_path_identity(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_immutable_continuation_reference_rejected"
        ) from exc
    require(
        stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
        "transactional_runtime_immutable_continuation_reference_rejected",
    )
    return {
        "gid": metadata.st_gid,
        "mode": stat.S_IMODE(metadata.st_mode),
        "nlink": metadata.st_nlink,
        "sha256": sha256(payload).hexdigest(),
        "size": len(payload),
        "type": "regular",
        "uid": metadata.st_uid,
    }


def _verify_immutable_continuation_reference(
    *,
    reference: Mapping[str, object],
    continuation_parent: Path,
    continuation_root: Path,
    request_root: Path,
    evidence_root: Path,
) -> dict[str, object]:
    selected = _validate_immutable_continuation_reference_contract(
        reference, require_production_exact=False
    )
    continuation = dict(selected["continuation"])
    continuation_id = str(continuation["continuation_id"])
    child = continuation_root / continuation_id
    try:
        parent_metadata = continuation_parent.lstat()
        root_metadata = continuation_root.lstat()
        child_metadata = child.lstat()
        parent_names = sorted(path.name for path in continuation_parent.iterdir())
        root_names = sorted(path.name for path in continuation_root.iterdir())
        child_names = sorted(path.name for path in child.iterdir())
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_immutable_continuation_reference_rejected"
        ) from exc

    def directory_identity(metadata: os.stat_result) -> dict[str, object]:
        return {
            "gid": metadata.st_gid,
            "mode": stat.S_IMODE(metadata.st_mode),
            "nlink": metadata.st_nlink,
            "type": "directory" if stat.S_ISDIR(metadata.st_mode) else "other",
            "uid": metadata.st_uid,
        }

    require(
        continuation_parent.is_absolute()
        and continuation_root.parent == continuation_parent
        and not stat.S_ISLNK(parent_metadata.st_mode)
        and not stat.S_ISLNK(root_metadata.st_mode)
        and not stat.S_ISLNK(child_metadata.st_mode)
        and directory_identity(parent_metadata) == continuation["parent"]
        and directory_identity(root_metadata) == continuation["root"]
        and directory_identity(child_metadata) == continuation["child"]
        and parent_names == [continuation_root.name]
        and root_names == [continuation_id]
        and child_names == sorted(continuation["files"]),
        "transactional_runtime_immutable_continuation_reference_rejected",
    )
    observed_files = {
        name: _fixed_path_identity(child / name)
        for name in sorted(continuation["files"])
    }
    require(
        observed_files == continuation["files"],
        "transactional_runtime_immutable_continuation_reference_rejected",
    )
    stored = _canonical_read(
        child / "continuation.json",
        "transactional_runtime_immutable_continuation_reference_rejected",
    )
    receipt = _canonical_read(
        child / "receipt.json",
        "transactional_runtime_immutable_continuation_reference_rejected",
    )
    completion = _canonical_read(
        child / "completion.json",
        "transactional_runtime_immutable_continuation_reference_rejected",
    )
    require(
        canonical(stored) == (child / "continuation.json").read_bytes()
        and stored.get("continuation_id") == continuation_id
        and stored.get("fresh_p08_status_required") is True
        and receipt.get("continuation_id") == continuation_id
        and completion.get("continuation_id") == continuation_id
        and receipt.get("status") == "materialized"
        and completion.get("continuation_sha256")
        == observed_files["continuation.json"]["sha256"]
        and completion.get("receipt_sha256")
        == observed_files["receipt.json"]["sha256"],
        "transactional_runtime_immutable_continuation_reference_rejected",
    )
    request_evidence = _validate_historical_request_evidence_storage_contract(
        selected["request_collection"], require_production_exact=False
    )
    storage_owner = dict(request_evidence["storage_owner"])
    request_collection = _verify_source_owned_request_collection(
        request_root=request_root,
        owner_uid=int(storage_owner["uid"]),
        owner_gid=int(storage_owner["gid"]),
    )
    require(
        request_collection["collection_count"]
        == request_evidence["collection_count"]
        and request_collection["collection_digest"]
        == request_evidence["collection_digest"],
        "transactional_runtime_immutable_continuation_reference_rejected",
    )
    try:
        request_root_metadata = request_root.lstat()
        request_names = sorted(path.name for path in request_root.iterdir())
        observed_request_children = {}
        for request_id in sorted(request_evidence["children"]):
            request_child = request_root / request_id
            child_metadata = request_child.lstat()
            observed_request_children[request_id] = {
                "directory": directory_identity(child_metadata),
                "files": {
                    name: _fixed_path_identity(request_child / name)
                    for name in (
                        "completion.json",
                        "receipt.json",
                        "request.json",
                    )
                },
            }
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_immutable_continuation_reference_rejected"
        ) from exc
    require(
        directory_identity(request_root_metadata) == request_evidence["root"]
        and request_names == sorted(request_evidence["children"])
        and observed_request_children == request_evidence["children"],
        "transactional_runtime_immutable_continuation_reference_rejected",
    )
    terminal_request = _canonical_read(
        request_root
        / str(request_evidence["terminal_request_id"])
        / "request.json",
        "transactional_runtime_immutable_continuation_reference_rejected",
    )
    payload_target_owner = dict(request_evidence["payload_target_owner"])
    require(
        terminal_request.get("owner_uid") == payload_target_owner["uid"]
        and terminal_request.get("owner_gid") == payload_target_owner["gid"],
        "transactional_runtime_immutable_continuation_reference_rejected",
    )
    terminal = dict(selected["terminal_t2"])
    _verified_evidence_sha256(
        evidence_root,
        name=str(terminal["handoff_name"]),
        expected_sha256=str(terminal["handoff_sha256"]),
        code="transactional_runtime_immutable_continuation_reference_rejected",
    )
    return {
        "continuation_id": continuation_id,
        "files_digest": digest(
            "p07_immutable_continuation_files", observed_files
        ),
        "flags": dict(_ZERO_FLAGS),
        "reference_digest": selected["reference_digest"],
        "reinterpreted_as_ready": False,
        "schema": IMMUTABLE_CONTINUATION_REFERENCE_SCHEMA,
        "source_id": IMMUTABLE_CONTINUATION_REFERENCE_SOURCE_ID,
        "status": "verified_read_only",
    }


def verify_source_owned_immutable_continuation_reference() -> dict[str, object]:
    reference = _validate_immutable_continuation_reference_contract(
        immutable_continuation_reference_contract(), require_production_exact=True
    )
    return _verify_immutable_continuation_reference(
        reference=reference,
        continuation_parent=SOURCE_OWNED_CONTINUATION_PARENT,
        continuation_root=SOURCE_OWNED_CONTINUATION_ROOT,
        request_root=SOURCE_OWNED_REQUEST_ROOT,
        evidence_root=SOURCE_OWNED_EVIDENCE_ROOT,
    )


def build_fresh_strategy_contract(
    *,
    runtime_manifest: Mapping[str, object],
    runtime_manifest_sha256: str,
    lineages: Mapping[str, object],
    continuation_reference: Mapping[str, object],
) -> dict[str, object]:
    manifest = validate_runtime_artifact_manifest(
        runtime_manifest,
        manifest_sha256=runtime_manifest_sha256,
        expected_bundle_id=_require_sha(
            runtime_manifest.get("bundle_id"),
            "transactional_runtime_fresh_strategy_rejected",
        ),
        expected_manifest_sha256=runtime_manifest_sha256,
    )
    lineage = parent.validate_immutable_lineages(lineages)
    reference = _validate_immutable_continuation_reference_contract(
        continuation_reference, require_production_exact=True
    )
    source = dict(manifest["source"])
    identity_semantic = {
        "artifacts": {
            "bundle_id": manifest["bundle_id"],
            "bundle_manifest_sha256": runtime_manifest_sha256,
            "plugin": plugin_artifact.binding_projection(manifest["plugin"]),
            "runtime": runtime_artifact.validate_projection(
                manifest["runtime_artifact"]
            ),
            "source_owned_roots": _validate_source_owned_artifact_root_contract(
                manifest["source_owned_artifact_roots"]
            ),
        },
        "continuation_reference_digest": reference["reference_digest"],
        "lineage_evidence_digest": lineage["evidence_digest"],
        "maximum_attempts": MAXIMUM_ATTEMPTS,
        "predecessor_attempts": {
            "dual_state_v2": "1/1",
            "p07_policy_overlay_v1": "2/2",
            "terminal_continuation_t2": "terminal_before_attempt",
        },
        "root_roles": {
            "backup_parent": FRESH_BACKUP_PARENT.as_posix(),
            "package_parent": FRESH_PACKAGE_PARENT.as_posix(),
            "state_parent": FRESH_STATE_PARENT.as_posix(),
            "status_parent": FRESH_STATUS_PARENT.as_posix(),
        },
        "schema": FRESH_STRATEGY_SCHEMA,
        "source": {
            "core_commit": source["core_commit"],
            "core_tree": source["core_tree"],
            "deploy_commit": source["deploy_commit"],
            "deploy_tree": source["deploy_tree"],
            "runtime_source_id": SOURCE_ID,
            "strategy_source_id": FRESH_STRATEGY_SOURCE_ID,
        },
    }
    strategy_digest = digest("p07_fresh_nonresetting_strategy_v3", identity_semantic)
    strategy_id = f"p07-owner-private-memory-fresh-max1-{strategy_digest[:32]}"
    storage = {
        "backup_root": (
            FRESH_BACKUP_PARENT / strategy_id
        ).as_posix(),
        "package_root": (
            FRESH_PACKAGE_PARENT / f"{strategy_id}-after-payload-packages"
        ).as_posix(),
        "state_root": (FRESH_STATE_PARENT / strategy_id).as_posix(),
        "status_invocation_root": (
            FRESH_STATUS_PARENT / strategy_id
        ).as_posix(),
    }
    semantic = {**identity_semantic, "storage": storage, "strategy_id": strategy_id}
    return {
        **semantic,
        "strategy_digest": digest("p07_fresh_strategy_contract_v3", semantic),
    }


def validate_fresh_strategy_contract(
    payload: Mapping[str, object],
    *,
    runtime_manifest: Mapping[str, object],
    runtime_manifest_sha256: str,
    lineages: Mapping[str, object],
    continuation_reference: Mapping[str, object],
) -> dict[str, object]:
    expected = build_fresh_strategy_contract(
        runtime_manifest=runtime_manifest,
        runtime_manifest_sha256=runtime_manifest_sha256,
        lineages=lineages,
        continuation_reference=continuation_reference,
    )
    require(
        dict(payload) == expected,
        "transactional_runtime_fresh_strategy_rejected",
    )
    return expected


def observe_fresh_strategy_namespace(
    strategy: Mapping[str, object],
) -> dict[str, object]:
    storage = strategy.get("storage")
    require(
        isinstance(storage, Mapping),
        "transactional_runtime_fresh_strategy_namespace_rejected",
    )
    paths = {
        role: Path(str(storage[role]))
        for role in (
            "backup_root",
            "package_root",
            "state_root",
            "status_invocation_root",
        )
    }
    require(
        all(path.is_absolute() for path in paths.values()),
        "transactional_runtime_fresh_strategy_namespace_rejected",
    )
    observed = {
        role: {"exists": path.exists(), "symlink": path.is_symlink()}
        for role, path in sorted(paths.items())
    }
    require(
        all(not item["exists"] and not item["symlink"] for item in observed.values()),
        "transactional_runtime_fresh_strategy_namespace_rejected",
    )
    return {
        "paths": observed,
        "schema": "myuna.p07-owner-private-memory-fresh-strategy-namespace.v1",
        "strategy_id": strategy["strategy_id"],
    }


def _status_invocation_intent(
    *, strategy: Mapping[str, object], source_nonce: str
) -> dict[str, object]:
    _require_sha(source_nonce, "transactional_runtime_status_invocation_rejected")
    stage_contract = production.p08_status_stage_contract()
    protocol_acceptance_contract = production.p08_protocol_acceptance_contract()
    require(
        set(stage_contract)
        == {
            "schema",
            "server_rejection_contract",
            "stage_contract_identity",
            "stage_policy",
            "stage_policy_digest",
        }
        and stage_contract["schema"] == p08_gateway.STATUS_STAGE_SCHEMA
        and stage_contract["stage_contract_identity"]
        == p08_gateway.STATUS_STAGE_SOURCE_IDENTITY
        and stage_contract["stage_contract_identity"]
        == P08_STATUS_STAGE_CONTRACT_IDENTITY
        and isinstance(stage_contract["stage_policy"], Mapping)
        and len(stage_contract["stage_policy"]) == 20
        and stage_contract["server_rejection_contract"]
        == production.p08_server_rejection_contract()
        and stage_contract["server_rejection_contract"][
            "source_contract_identity"
        ]
        == P08_SERVER_REJECTION_CONTRACT_IDENTITY
        and _SHA.fullmatch(str(stage_contract["stage_policy_digest"])) is not None,
        "transactional_runtime_status_invocation_stage_contract_rejected",
    )
    require(
        set(protocol_acceptance_contract)
        == {
            "child_rejection_schema",
            "child_stage_contract_identity",
            "contract_digest",
            "failure_stages",
            "helper_calls",
            "invocation_nonce_environment",
            "nonce_chain",
            "raw_stderr_retained",
            "retry_or_fallback",
            "schema",
            "sha256",
            "source_path",
        }
        and protocol_acceptance_contract["contract_digest"]
        == P08_PROTOCOL_ACCEPTANCE_CONTRACT_DIGEST
        and protocol_acceptance_contract["child_stage_contract_identity"]
        == stage_contract["stage_contract_identity"]
        and protocol_acceptance_contract["helper_calls"] == 1
        and protocol_acceptance_contract["retry_or_fallback"] is False,
        "transactional_runtime_status_invocation_protocol_contract_rejected",
    )
    semantic = {
        "flags": dict(_ZERO_FLAGS),
        "helper": {
            "helper_source_path_digest": digest(
                "p07_status_helper_source_path", P08_STATUS_CLIENT_SOURCE_PATH
            ),
            "helper_source_sha256": P08_STATUS_CLIENT_SOURCE_SHA256,
            "future_installed_inventory_digest": (
                P08_STATUS_STAGE_FUTURE_INSTALLED_INVENTORY_DIGEST
            ),
            "future_socket_unit_sha256": P08_STATUS_FUTURE_SOCKET_UNIT_SHA256,
            "future_unit_sha256": P08_STATUS_FUTURE_UNIT_SHA256,
            "inactive_manifest_sha256": P08_STATUS_STAGE_INACTIVE_MANIFEST_SHA256,
            "inactive_release_digest": P08_STATUS_STAGE_INACTIVE_RELEASE_DIGEST,
            "inactive_source_inventory_digest": (
                P08_STATUS_STAGE_INACTIVE_SOURCE_INVENTORY_DIGEST
            ),
            "inactive_full_inventory_digest": (
                P08_STATUS_STAGE_FULL_INVENTORY_DIGEST
            ),
            "inactive_controller_digest": P08_STATUS_STAGE_CONTROLLER_DIGEST,
            "inactive_core_commit": P08_STATUS_STAGE_INACTIVE_CORE_COMMIT,
            "inactive_core_tree": P08_STATUS_STAGE_INACTIVE_CORE_TREE,
            "inactive_deploy_commit": P08_STATUS_STAGE_INACTIVE_DEPLOY_COMMIT,
            "inactive_deploy_tree": P08_STATUS_STAGE_INACTIVE_DEPLOY_TREE,
            "inactive_strategy_digest": P08_STATUS_STAGE_STRATEGY_DIGEST,
            "protocol_acceptance_contract_digest": (
                P08_PROTOCOL_ACCEPTANCE_CONTRACT_DIGEST
            ),
            "protocol_acceptance_evidence": {
                "failure_stage_set_digest": digest(
                    "p07_p08_protocol_acceptance_failure_stages",
                    protocol_acceptance_contract["failure_stages"],
                ),
                "helper_calls": protocol_acceptance_contract["helper_calls"],
                "nonce_chain_digest": digest(
                    "p07_p08_protocol_acceptance_nonce_chain",
                    protocol_acceptance_contract["nonce_chain"],
                ),
                "nonce_environment_digest": digest(
                    "p07_p08_protocol_acceptance_nonce_environment",
                    protocol_acceptance_contract[
                        "invocation_nonce_environment"
                    ],
                ),
                "raw_error_stream_retained": False,
                "retry_or_fallback": False,
                "schema": protocol_acceptance_contract["schema"],
                "source_sha256": protocol_acceptance_contract["sha256"],
            },
            "server_rejection_contract": stage_contract[
                "server_rejection_contract"
            ],
            "service_entrypoint_sha256": (
                P08_STATUS_SERVICE_ENTRYPOINT_SHA256
            ),
            "stage_contract_identity": p08_gateway.STATUS_STAGE_SOURCE_IDENTITY,
            "stage_policy_digest": stage_contract["stage_policy_digest"],
            "stage_schema": p08_gateway.STATUS_STAGE_SCHEMA,
            "target_server_rejection_projection_sha256": (
                P08_TARGET_SERVER_REJECTION_PROJECTION_SHA256
            ),
            "target_status_stage_projection_sha256": (
                P08_TARGET_STATUS_STAGE_PROJECTION_SHA256
            ),
        },
        "maximum_invocations": 1,
        "schema": STATUS_INVOCATION_SCHEMA,
        "source_id": STATUS_INVOCATION_SOURCE_ID,
        "source_nonce": source_nonce,
        "strategy_digest": strategy["strategy_digest"],
        "strategy_id": strategy["strategy_id"],
    }
    return {
        **semantic,
        "invocation_id": digest("p07_content_free_status_invocation_v1", semantic),
    }


def _status_result_projection(
    *,
    intent: Mapping[str, object],
    status: str,
    accepted: p08_gateway.ContentFreeTemporalGatewayStatus | None = None,
    rejected: Mapping[str, object] | None = None,
) -> dict[str, object]:
    require(
        status in {"accepted", "rejected"}
        and ((accepted is not None) != (rejected is not None)),
        "transactional_runtime_status_invocation_result_rejected",
    )
    if accepted is not None:
        projection = accepted.projection()
        allowed = {
            "active_fact_count",
            "active_set_complete",
            "active_set_digest",
            "lifecycle_complete",
            "lifecycle_digest",
            "lifecycle_event_count",
            "lifecycle_watermark",
            "pending_proposal_count",
            "request_nonce",
            "response_digest",
            "scope_binding_digest",
            "source_identity",
            "status_digest",
            "status_schema",
            "total_fact_count",
            "trusted_time_binding_digest",
            "trusted_time_evidence_complete",
        }
        require(
            set(projection) == allowed
            and all(
                type(projection[field]) is int and projection[field] >= 0
                for field in (
                    "active_fact_count",
                    "lifecycle_event_count",
                    "lifecycle_watermark",
                    "pending_proposal_count",
                    "total_fact_count",
                )
            )
            and projection["active_set_complete"] is True
            and projection["lifecycle_complete"] is True
            and projection["trusted_time_evidence_complete"] is True
            and all(
                _SHA.fullmatch(str(projection[field])) is not None
                for field in (
                    "active_set_digest",
                    "lifecycle_digest",
                    "request_nonce",
                    "response_digest",
                    "scope_binding_digest",
                    "source_identity",
                    "status_digest",
                    "trusted_time_binding_digest",
                )
            ),
            "transactional_runtime_status_invocation_result_rejected",
        )
        result_projection: dict[str, object] = {
            "accepted_projection": projection,
            "accepted_projection_digest": digest(
                "p07_status_invocation_accepted_projection", projection
            ),
        }
    else:
        selected = dict(rejected or {})
        try:
            p08_gateway.parse_content_free_status_rejection(
                selected,
                expected_invocation_nonce=str(selected.get("invocation_nonce", "")),
            )
        except ValueError as exc:
            raise TransactionalRuntimeRejected(
                "transactional_runtime_status_invocation_result_rejected"
            ) from exc
        require(
            selected.get("persistent_mutation") is False,
            "transactional_runtime_status_invocation_result_rejected",
        )
        result_projection = {
            "rejected_projection": selected,
            "rejected_projection_digest": digest(
                "p07_status_invocation_rejected_projection", selected
            ),
        }
    semantic = {
        "flags": dict(_ZERO_FLAGS),
        "invocation_id": intent["invocation_id"],
        "schema": STATUS_INVOCATION_RESULT_SCHEMA,
        "source_id": STATUS_INVOCATION_SOURCE_ID,
        "status": status,
        "strategy_id": intent["strategy_id"],
        **result_projection,
    }
    return {
        **semantic,
        "result_digest": digest("p07_content_free_status_result_v1", semantic),
    }


def _status_invocation_file(
    path: Path,
    *,
    expected: bytes,
    owner_uid: int,
    owner_gid: int,
) -> None:
    identity = _fixed_path_identity(path)
    require(
        identity
        == {
            "gid": owner_gid,
            "mode": 0o600,
            "nlink": 1,
            "sha256": sha256(expected).hexdigest(),
            "size": len(expected),
            "type": "regular",
            "uid": owner_uid,
        }
        and path.read_bytes() == expected,
        "transactional_runtime_status_invocation_evidence_rejected",
    )


def _write_status_file_no_replace(
    path: Path, *, payload: bytes, owner_uid: int, owner_gid: int
) -> None:
    temporary = path.parent / f".{path.name}.{sha256(payload).hexdigest()[:16]}.tmp"
    require(
        not path.exists()
        and not path.is_symlink()
        and not temporary.exists()
        and not temporary.is_symlink(),
        "transactional_runtime_status_invocation_replay_rejected",
    )
    descriptor: int | None = None
    directory_descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, owner_uid, owner_gid)
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _status_invocation_file(
            temporary,
            expected=payload,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        directory_descriptor = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        _rename_no_replace(
            Path(temporary.name),
            Path(path.name),
            source_dir_fd=directory_descriptor,
            target_dir_fd=directory_descriptor,
        )
        _fsync_directory(path.parent)
        _status_invocation_file(
            path,
            expected=payload,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
    except (OSError, TransactionalRuntimeRejected) as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_status_invocation_write_rejected"
        ) from exc
    finally:
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _create_status_directory(
    path: Path, *, owner_uid: int, owner_gid: int, mode: int
) -> None:
    try:
        path.mkdir(mode=mode)
        os.chown(path, owner_uid, owner_gid)
        os.chmod(path, mode)
        _fsync_directory(path.parent)
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_status_invocation_namespace_rejected"
        ) from exc


def _require_status_directory(
    path: Path,
    *,
    owner_uid: int,
    owner_gid: int,
    mode: int,
    entries: list[str],
) -> None:
    try:
        metadata = path.lstat()
        names = sorted(item.name for item in path.iterdir())
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_status_invocation_namespace_rejected"
        ) from exc
    require(
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == mode
        and metadata.st_uid == owner_uid
        and metadata.st_gid == owner_gid
        and names == entries,
        "transactional_runtime_status_invocation_namespace_rejected",
    )


def _begin_status_invocation(
    *,
    strategy: Mapping[str, object],
    trusted_ancestor: Path,
    status_parent: Path,
    status_root: Path,
    owner_uid: int,
    owner_gid: int,
    source_nonce: str | None = None,
    crash_hook: Callable[[str], None] | None = None,
) -> dict[str, object]:
    require(
        status_root == Path(str(strategy["storage"]["status_invocation_root"]))
        and status_parent == status_root.parent
        and status_parent.parent == trusted_ancestor,
        "transactional_runtime_status_invocation_namespace_rejected",
    )
    try:
        ancestor = trusted_ancestor.lstat()
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_status_invocation_namespace_rejected"
        ) from exc
    require(
        stat.S_ISDIR(ancestor.st_mode)
        and not stat.S_ISLNK(ancestor.st_mode)
        and ancestor.st_uid == owner_uid
        and ancestor.st_gid == owner_gid
        and stat.S_IMODE(ancestor.st_mode) & 0o022 == 0
        and not status_parent.exists()
        and not status_parent.is_symlink()
        and not status_root.exists()
        and not status_root.is_symlink(),
        "transactional_runtime_status_invocation_namespace_rejected",
    )
    _create_status_directory(
        status_parent, owner_uid=owner_uid, owner_gid=owner_gid, mode=0o700
    )
    if crash_hook is not None:
        crash_hook("parent_created")
    _create_status_directory(
        status_root, owner_uid=owner_uid, owner_gid=owner_gid, mode=0o700
    )
    if crash_hook is not None:
        crash_hook("root_created")
    nonce = secrets.token_hex(32) if source_nonce is None else source_nonce
    intent = _status_invocation_intent(strategy=strategy, source_nonce=nonce)
    child = status_root / str(intent["invocation_id"])
    _create_status_directory(child, owner_uid=owner_uid, owner_gid=owner_gid, mode=0o700)
    if crash_hook is not None:
        crash_hook("child_created")
    intent_bytes = canonical(intent)
    _write_status_file_no_replace(
        child / "intent.json",
        payload=intent_bytes,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    _fsync_directory(child)
    _status_invocation_file(
        child / "intent.json",
        expected=intent_bytes,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    if crash_hook is not None:
        crash_hook("intent_written")
    _require_status_directory(
        status_parent,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        mode=0o700,
        entries=[status_root.name],
    )
    _require_status_directory(
        status_root,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        mode=0o700,
        entries=[str(intent["invocation_id"])],
    )
    _require_status_directory(
        child,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        mode=0o700,
        entries=["intent.json"],
    )
    return {"child": child, "intent": intent}


def _complete_status_invocation(
    *,
    transaction: Mapping[str, object],
    result: Mapping[str, object],
    owner_uid: int,
    owner_gid: int,
    crash_hook: Callable[[str], None] | None = None,
) -> dict[str, object]:
    child = Path(str(transaction["child"]))
    intent = dict(transaction["intent"])
    result_bytes = canonical(dict(result))
    completion = {
        "intent_sha256": sha256(canonical(intent)).hexdigest(),
        "invocation_id": intent["invocation_id"],
        "result_sha256": sha256(result_bytes).hexdigest(),
        "schema": STATUS_INVOCATION_COMPLETION_SCHEMA,
        "source_id": STATUS_INVOCATION_SOURCE_ID,
        "strategy_id": intent["strategy_id"],
    }
    _write_status_file_no_replace(
        child / "result.json",
        payload=result_bytes,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    _fsync_directory(child)
    if crash_hook is not None:
        crash_hook("result_written")
    completion_bytes = canonical(completion)
    _write_status_file_no_replace(
        child / "completion.json",
        payload=completion_bytes,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    _fsync_directory(child)
    if crash_hook is not None:
        crash_hook("completion_written")
    for name, payload in (
        ("intent.json", canonical(intent)),
        ("result.json", result_bytes),
        ("completion.json", completion_bytes),
    ):
        _status_invocation_file(
            child / name,
            expected=payload,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
    _require_status_directory(
        child,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        mode=0o700,
        entries=["completion.json", "intent.json", "result.json"],
    )
    return {
        "completion_sha256": sha256(completion_bytes).hexdigest(),
        "flags": dict(_ZERO_FLAGS),
        "invocation_id": intent["invocation_id"],
        "result_digest": result["result_digest"],
        "status": result["status"],
        "strategy_id": intent["strategy_id"],
    }


def _verify_status_invocation_evidence(
    *,
    strategy: Mapping[str, object],
    status_parent: Path,
    status_root: Path,
    owner_uid: int,
    owner_gid: int,
) -> dict[str, object]:
    require(
        status_root == Path(str(strategy["storage"]["status_invocation_root"]))
        and status_parent == status_root.parent,
        "transactional_runtime_status_invocation_evidence_rejected",
    )
    _require_status_directory(
        status_parent,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        mode=0o700,
        entries=[status_root.name],
    )
    names = sorted(path.name for path in status_root.iterdir())
    require(
        len(names) == 1 and _REQUEST_ID_PATTERN.fullmatch(names[0]) is not None,
        "transactional_runtime_status_invocation_evidence_rejected",
    )
    child = status_root / names[0]
    _require_status_directory(
        child,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        mode=0o700,
        entries=["completion.json", "intent.json", "result.json"],
    )
    intent = _canonical_read(
        child / "intent.json",
        "transactional_runtime_status_invocation_evidence_rejected",
    )
    result = _canonical_read(
        child / "result.json",
        "transactional_runtime_status_invocation_evidence_rejected",
    )
    completion = _canonical_read(
        child / "completion.json",
        "transactional_runtime_status_invocation_evidence_rejected",
    )
    expected_intent = _status_invocation_intent(
        strategy=strategy, source_nonce=str(intent.get("source_nonce", ""))
    )
    require(
        intent == expected_intent
        and intent["invocation_id"] == names[0]
        and result.get("schema") == STATUS_INVOCATION_RESULT_SCHEMA
        and result.get("source_id") == STATUS_INVOCATION_SOURCE_ID
        and result.get("invocation_id") == names[0]
        and result.get("strategy_id") == strategy["strategy_id"]
        and result.get("status") in {"accepted", "rejected"}
        and result.get("flags") == _ZERO_FLAGS
        and completion
        == {
            "intent_sha256": sha256(canonical(intent)).hexdigest(),
            "invocation_id": names[0],
            "result_sha256": sha256(canonical(result)).hexdigest(),
            "schema": STATUS_INVOCATION_COMPLETION_SCHEMA,
            "source_id": STATUS_INVOCATION_SOURCE_ID,
            "strategy_id": strategy["strategy_id"],
        },
        "transactional_runtime_status_invocation_evidence_rejected",
    )
    base_result_fields = {
        "flags",
        "invocation_id",
        "result_digest",
        "schema",
        "source_id",
        "status",
        "strategy_id",
    }
    expected_result_fields = (
        base_result_fields | {"accepted_projection", "accepted_projection_digest"}
        if result.get("status") == "accepted"
        else base_result_fields | {"rejected_projection", "rejected_projection_digest"}
    )
    require(
        set(result) == expected_result_fields
        and set(completion)
        == {
            "intent_sha256",
            "invocation_id",
            "result_sha256",
            "schema",
            "source_id",
            "strategy_id",
        },
        "transactional_runtime_status_invocation_evidence_rejected",
    )
    result_semantic = {
        key: value for key, value in result.items() if key != "result_digest"
    }
    require(
        result.get("result_digest")
        == digest("p07_content_free_status_result_v1", result_semantic),
        "transactional_runtime_status_invocation_evidence_rejected",
    )
    if result["status"] == "accepted":
        projection = result.get("accepted_projection")
        require(
            isinstance(projection, Mapping),
            "transactional_runtime_status_invocation_evidence_rejected",
        )
        # Rebuild the allowlisted result from the persisted projection without
        # accepting unknown fields or caller-provided identities.
        require(
            result.get("accepted_projection_digest")
            == digest("p07_status_invocation_accepted_projection", projection),
            "transactional_runtime_status_invocation_evidence_rejected",
        )
        helper_nonce = str(projection.get("request_nonce", ""))
        stage_digest = None
        projection_digest = result["accepted_projection_digest"]
    else:
        projection = result.get("rejected_projection")
        require(
            isinstance(projection, Mapping),
            "transactional_runtime_status_invocation_evidence_rejected",
        )
        try:
            p08_gateway.parse_content_free_status_rejection(
                projection,
                expected_invocation_nonce=str(projection.get("invocation_nonce", "")),
            )
        except ValueError as exc:
            raise TransactionalRuntimeRejected(
                "transactional_runtime_status_invocation_evidence_rejected"
            ) from exc
        require(
            result.get("rejected_projection_digest")
            == digest("p07_status_invocation_rejected_projection", projection),
            "transactional_runtime_status_invocation_evidence_rejected",
        )
        helper_nonce = str(projection.get("invocation_nonce", ""))
        stage_digest = result["rejected_projection_digest"]
        projection_digest = result["rejected_projection_digest"]
    require(
        _SHA.fullmatch(helper_nonce) is not None,
        "transactional_runtime_status_invocation_evidence_rejected",
    )
    for name, payload in (
        ("intent.json", canonical(intent)),
        ("result.json", canonical(result)),
        ("completion.json", canonical(completion)),
    ):
        _status_invocation_file(
            child / name,
            expected=payload,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
    return {
        "completion_sha256": sha256(canonical(completion)).hexdigest(),
        "helper_nonce_digest": digest("p07_status_helper_nonce", helper_nonce),
        "invocation_id": names[0],
        "projection_digest": projection_digest,
        "result_digest": result["result_digest"],
        "stage_projection_digest": stage_digest,
        "status": result["status"],
        "strategy_id": strategy["strategy_id"],
    }


class SourceOwnedStatusEvidenceObserver(production.SystemProtectedObserver):
    """Run one helper call and seal only its allowlisted content-free projection."""

    def __init__(
        self,
        *,
        strategy: Mapping[str, object],
        rejection_context: _VerifiedRejectionStrategyContext,
        trusted_ancestor: Path,
        status_parent: Path,
        owner_uid: int,
        owner_gid: int,
        helper: Callable[[object], p08_gateway.ContentFreeTemporalGatewayStatus]
        | None = None,
        source_nonce: str | None = None,
    ) -> None:
        self.strategy = dict(strategy)
        selected_context = _validated_rejection_strategy_context(rejection_context)
        require(
            selected_context is not None
            and selected_context.context_kind == "fresh"
            and selected_context.strategy_id == self.strategy.get("strategy_id")
            and selected_context.strategy_digest
            == self.strategy.get("strategy_digest"),
            "transactional_runtime_rejection_strategy_context_rejected",
        )
        self.rejection_context = selected_context
        self.owner_uid = owner_uid
        self.owner_gid = owner_gid
        self.helper = helper or production.SystemProtectedObserver._p08_status
        self.trusted_ancestor = trusted_ancestor
        self.status_parent = status_parent
        self.source_nonce = source_nonce
        self.transaction: dict[str, object] | None = None
        self.called = False
        self.result: dict[str, object] | None = None

    def _p08_status(
        self, runtime_config: object
    ) -> p08_gateway.ContentFreeTemporalGatewayStatus:
        require(not self.called, "transactional_runtime_status_invocation_replay_rejected")
        self.called = True
        self.transaction = _begin_status_invocation(
            strategy=self.strategy,
            trusted_ancestor=self.trusted_ancestor,
            status_parent=self.status_parent,
            status_root=Path(
                str(self.strategy["storage"]["status_invocation_root"])
            ),
            owner_uid=self.owner_uid,
            owner_gid=self.owner_gid,
            source_nonce=self.source_nonce,
        )
        try:
            try:
                status = self.helper(runtime_config)
            except production.ProductionPlanRejected as exc:
                projection, _ = _p08_status_stage_evidence(exc)
                require(
                    projection is not None,
                    "transactional_runtime_status_invocation_unclassified_rejected",
                )
                result = _status_result_projection(
                    intent=self.transaction["intent"],
                    status="rejected",
                    rejected=projection,
                )
                self.result = _complete_status_invocation(
                    transaction=self.transaction,
                    result=result,
                    owner_uid=self.owner_uid,
                    owner_gid=self.owner_gid,
                )
                raise
            result = _status_result_projection(
                intent=self.transaction["intent"], status="accepted", accepted=status
            )
            self.result = _complete_status_invocation(
                transaction=self.transaction,
                result=result,
                owner_uid=self.owner_uid,
                owner_gid=self.owner_gid,
            )
            return status
        except Exception as exc:
            _attach_rejection_strategy_context(exc, self.rejection_context)
            raise

    def completed_evidence(self) -> dict[str, object]:
        require(
            self.called and self.result is not None,
            "transactional_runtime_status_invocation_incomplete",
        )
        verified = _verify_status_invocation_evidence(
            strategy=self.strategy,
            status_parent=Path(
                str(self.strategy["storage"]["status_invocation_root"])
            ).parent,
            status_root=Path(
                str(self.strategy["storage"]["status_invocation_root"])
            ),
            owner_uid=self.owner_uid,
            owner_gid=self.owner_gid,
        )
        require(
            verified["status"] == "accepted",
            "transactional_runtime_status_invocation_not_accepted",
        )
        return verified


def _ledger_semantic(
    plan: Mapping[str, object], *, package_id: str, package_digest: str
) -> dict[str, object]:
    return {
        "attempts": 0,
        "immutable_terminal_evidence_digest": plan["immutable_terminal_evidence_digest"],
        "last_attempt_receipt_sha256": None,
        "lineage_evidence_digest": plan["lineage_evidence_digest"],
        "maximum_attempts": plan["strategy"]["maximum_attempts"],
        "package_digest": package_digest,
        "package_id": package_id,
        "plan_id": plan["plan_id"],
        "schema": LEDGER_SCHEMA,
        "source_id": SOURCE_ID,
        "state": "ready",
        "strategy_id": plan["strategy"]["strategy_id"],
    }


def validate_ledger(
    payload: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    package_id: str,
    package_digest: str,
) -> dict[str, object]:
    selected = dict(payload)
    required = {
        "attempts",
        "immutable_terminal_evidence_digest",
        "last_attempt_receipt_sha256",
        "lineage_evidence_digest",
        "maximum_attempts",
        "package_digest",
        "package_id",
        "plan_id",
        "schema",
        "source_id",
        "state",
        "strategy_id",
    }
    require(
        set(selected) == required
        and selected.get("schema") == LEDGER_SCHEMA
        and selected.get("source_id") == SOURCE_ID
        and selected.get("strategy_id") == plan["strategy"]["strategy_id"]
        and selected.get("plan_id") == plan["plan_id"]
        and selected.get("immutable_terminal_evidence_digest")
        == plan["immutable_terminal_evidence_digest"]
        and selected.get("lineage_evidence_digest") == plan["lineage_evidence_digest"]
        and selected.get("maximum_attempts")
        == plan["strategy"]["maximum_attempts"]
        and selected.get("package_id") == package_id
        and selected.get("package_digest") == package_digest
        and selected.get("attempts") in {0, 1},
        "transactional_runtime_ledger_rejected",
    )
    if selected["attempts"] == 0:
        require(
            selected["state"] == "ready" and selected["last_attempt_receipt_sha256"] is None,
            "transactional_runtime_ledger_rejected",
        )
    else:
        require(selected["state"] == "consumed", "transactional_runtime_ledger_rejected")
        _require_sha(selected["last_attempt_receipt_sha256"], "transactional_runtime_ledger_rejected")
    return selected


def create_ledger(
    *,
    plan: Mapping[str, object],
    state_root: Path,
    owner_uid: int,
    owner_gid: int,
    package_id: str,
    package_digest: str,
) -> dict[str, object]:
    require(
        state_root.as_posix() == plan["storage"]["state_root"]
        and not state_root.exists()
        and not state_root.is_symlink(),
        "transactional_runtime_ledger_namespace_rejected",
    )
    parent_metadata = state_root.parent.lstat()
    require(
        stat.S_ISDIR(parent_metadata.st_mode) and not stat.S_ISLNK(parent_metadata.st_mode),
        "transactional_runtime_ledger_parent_rejected",
    )
    state_root.mkdir(mode=0o700)
    os.chown(state_root, owner_uid, owner_gid)
    os.chmod(state_root, 0o700)
    ledger = _ledger_semantic(
        plan, package_id=package_id, package_digest=package_digest
    )
    path = state_root / "ATTEMPT_LEDGER.json"
    _atomic_write(path, canonical(ledger), mode=0o600)
    os.chown(path, owner_uid, owner_gid)
    return verify_ledger_root(
        plan=plan,
        state_root=state_root,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        package_id=package_id,
        package_digest=package_digest,
        allow_runtime_files=False,
    )


def verify_ledger_root(
    *,
    plan: Mapping[str, object],
    state_root: Path,
    owner_uid: int,
    owner_gid: int,
    package_id: str,
    package_digest: str,
    allow_runtime_files: bool,
) -> dict[str, object]:
    try:
        root_metadata = state_root.lstat()
        ledger_path = state_root / "ATTEMPT_LEDGER.json"
        ledger_metadata = ledger_path.lstat()
        ledger = validate_ledger(
            _canonical_read(ledger_path, "transactional_runtime_ledger_rejected"),
            plan,
            package_id=package_id,
            package_digest=package_digest,
        )
    except OSError as exc:
        raise TransactionalRuntimeRejected("transactional_runtime_ledger_unavailable") from exc
    require(
        not stat.S_ISLNK(root_metadata.st_mode)
        and stat.S_ISDIR(root_metadata.st_mode)
        and stat.S_IMODE(root_metadata.st_mode) == 0o700
        and root_metadata.st_uid == owner_uid
        and root_metadata.st_gid == owner_gid
        and not stat.S_ISLNK(ledger_metadata.st_mode)
        and stat.S_ISREG(ledger_metadata.st_mode)
        and stat.S_IMODE(ledger_metadata.st_mode) == 0o600
        and ledger_metadata.st_uid == owner_uid
        and ledger_metadata.st_gid == owner_gid,
        "transactional_runtime_ledger_acl_rejected",
    )
    names = sorted(path.name for path in state_root.iterdir())
    if allow_runtime_files:
        allowed = {
            "ATTEMPT_LEDGER.json",
            "ATTEMPT-0001.json",
            Path(str(plan["storage"]["controller_journal_path"])).name,
            Path(str(plan["storage"]["filesystem_journal_path"])).name,
            Path(str(plan["storage"]["staging_path"])).name,
            f"RECEIPT-{plan['plan_id']}.json",
        }
        require(
            set(names) <= allowed,
            "transactional_runtime_state_inventory_rejected",
        )
        staging_name = Path(str(plan["storage"]["staging_path"])).name
        for name in names:
            if name == "ATTEMPT_LEDGER.json":
                continue
            metadata = (state_root / name).lstat()
            is_staging = name == staging_name
            require(
                not stat.S_ISLNK(metadata.st_mode)
                and (
                    stat.S_ISDIR(metadata.st_mode)
                    if is_staging
                    else stat.S_ISREG(metadata.st_mode)
                )
                and stat.S_IMODE(metadata.st_mode) == (0o700 if is_staging else 0o600)
                and metadata.st_uid == owner_uid
                and metadata.st_gid == owner_gid,
                "transactional_runtime_state_acl_rejected",
            )
    else:
        require(names == ["ATTEMPT_LEDGER.json"], "transactional_runtime_state_inventory_rejected")
    return ledger


def consume_ledger(
    *,
    plan: Mapping[str, object],
    state_root: Path,
    owner_uid: int,
    owner_gid: int,
    preflight_sha256: str,
    package_id: str,
    package_digest: str,
) -> dict[str, object]:
    _require_sha(preflight_sha256, "transactional_runtime_preflight_identity_rejected")
    ledger_path = state_root / "ATTEMPT_LEDGER.json"
    descriptor = os.open(
        ledger_path,
        os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        ledger = verify_ledger_root(
            plan=plan,
            state_root=state_root,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            package_id=package_id,
            package_digest=package_digest,
            allow_runtime_files=True,
        )
        require(
            {path.name for path in state_root.iterdir()}
            == {
                "ATTEMPT_LEDGER.json",
                Path(str(plan["storage"]["controller_journal_path"])).name,
                Path(str(plan["storage"]["staging_path"])).name,
            },
            "transactional_runtime_preconsume_inventory_rejected",
        )
        require(ledger["attempts"] == 0, "transactional_runtime_attempt_exhausted")
        semantic = {
            "attempt": 1,
            "content_retained": False,
            "lineage_evidence_digest": plan["lineage_evidence_digest"],
            "maximum_attempts": plan["strategy"]["maximum_attempts"],
            "package_digest": package_digest,
            "package_id": package_id,
            "plan_id": plan["plan_id"],
            "preflight_sha256": preflight_sha256,
            "private_content_read": False,
            "schema": ATTEMPT_RECEIPT_SCHEMA,
            "source_id": SOURCE_ID,
            "strategy_id": plan["strategy"]["strategy_id"],
        }
        receipt = {**semantic, "receipt_id": digest("p07_transactional_runtime_attempt", semantic)}
        receipt_path = state_root / "ATTEMPT-0001.json"
        _atomic_write(receipt_path, canonical(receipt), mode=0o600)
        os.chown(receipt_path, owner_uid, owner_gid)
        updated = {
            **ledger,
            "attempts": 1,
            "last_attempt_receipt_sha256": sha256(canonical(receipt)).hexdigest(),
            "state": "consumed",
        }
        _replace_file(ledger_path, canonical(updated), mode=0o600)
        os.chown(ledger_path, owner_uid, owner_gid)
        validate_ledger(
            updated,
            plan,
            package_id=package_id,
            package_digest=package_digest,
        )
        return receipt
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr_sha256: str


class CommandRunner(Protocol):
    def run(self, arguments: tuple[str, ...], *, timeout: int) -> CommandResult: ...


def allowed_commands() -> frozenset[tuple[str, ...]]:
    show = {
        (
            SYSTEMCTL,
            "show",
            unit,
            "--property=ActiveState",
            "--property=SubState",
            "--property=NRestarts",
            "--no-pager",
        )
        for unit in (CORE_UNIT, TELEGRAM_UNIT, TELEGRAM_SOCKET)
    }
    return frozenset(
        {
            (SYSTEMCTL, "stop", TELEGRAM_SOCKET, TELEGRAM_UNIT, CORE_UNIT),
            (SYSTEMCTL, "daemon-reload"),
            (SYSTEMCTL, "start", CORE_UNIT),
            (PYTHON, "-B", TELEGRAM_RESUME_CONTROLLER),
            (
                DOCKER,
                "inspect",
                CONTAINER,
                "--format={{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.RestartCount}}",
            ),
            *show,
        }
    )


class SubprocessCommandRunner:
    """Run only the exact source-bound service/container commands."""

    def run(self, arguments: tuple[str, ...], *, timeout: int) -> CommandResult:
        require(arguments in allowed_commands(), "transactional_runtime_command_not_allowlisted")
        completed = subprocess.run(
            list(arguments),
            check=False,
            capture_output=True,
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/usr/sbin",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            text=True,
            timeout=timeout,
        )
        stderr = completed.stderr.encode("utf-8", errors="replace")
        return CommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr_sha256=sha256(stderr).hexdigest(),
        )


def _run(runner: CommandRunner, arguments: tuple[str, ...], *, timeout: int, code: str) -> str:
    result = runner.run(arguments, timeout=timeout)
    require(result.returncode == 0, code)
    return result.stdout


def _unit_projection(runner: CommandRunner, unit: str) -> dict[str, object]:
    output = _run(
        runner,
        (
            SYSTEMCTL,
            "show",
            unit,
            "--property=ActiveState",
            "--property=SubState",
            "--property=NRestarts",
            "--no-pager",
        ),
        timeout=30,
        code="transactional_runtime_unit_projection_failed",
    )
    fields: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        require(separator == "=" and key not in fields, "transactional_runtime_unit_projection_rejected")
        fields[key] = value
    require(
        set(fields) == {"ActiveState", "NRestarts", "SubState"}
        and fields["NRestarts"].isdigit(),
        "transactional_runtime_unit_projection_rejected",
    )
    return {
        "active_state": fields["ActiveState"],
        "nrestarts": int(fields["NRestarts"]),
        "sub_state": fields["SubState"],
        "unit": unit,
    }


def observe_services(runner: CommandRunner) -> dict[str, object]:
    container_output = _run(
        runner,
        (
            DOCKER,
            "inspect",
            CONTAINER,
            "--format={{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.RestartCount}}",
        ),
        timeout=30,
        code="transactional_runtime_container_projection_failed",
    ).strip()
    parts = container_output.split("|")
    require(len(parts) == 3 and parts[2].isdigit(), "transactional_runtime_container_projection_rejected")
    return validate_service_projection(
        {
            "container": {
                "health": parts[1],
                "name": CONTAINER,
                "restart_count": int(parts[2]),
                "state": parts[0],
            },
            "core": _unit_projection(runner, CORE_UNIT),
            "telegram": _unit_projection(runner, TELEGRAM_UNIT),
            "telegram_socket": _unit_projection(runner, TELEGRAM_SOCKET),
        }
    )


def _verify_inventory(contract: Mapping[str, object], field: str, code: str) -> None:
    selected = mutation.validate_mutation_set(contract)
    observed = mutation.scan_contract_roots(selected)
    evidence = mutation.comparison_evidence(
        expected=selected[field],
        observed=observed,
        contract=selected,
        phase=field,
    )
    require(evidence["status"] == "match", code)


_SOURCE_FIRST_PROBE_NAME = "P07-SOURCE-FIRST-SQLITE-PLATFORM.sqlite3"


def _probe_identity(path: Path) -> tuple[int, int, int, int, int]:
    value = path.lstat()
    require(
        not path.is_symlink()
        and stat.S_ISREG(value.st_mode)
        and value.st_nlink == 1,
        "transactional_runtime_sqlite_probe_identity_rejected",
    )
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_gid,
        stat.S_IMODE(value.st_mode),
    )


def _probe_fd_inventory() -> dict[int, tuple[int, int, int, int, int]]:
    proc = Path("/proc/self/fd")
    require(proc.is_dir(), "transactional_runtime_sqlite_probe_fd_unavailable")
    inventory: dict[int, tuple[int, int, int, int, int]] = {}
    try:
        with os.scandir(proc) as entries:
            for entry in entries:
                try:
                    descriptor = int(entry.name)
                    value = entry.stat(follow_symlinks=True)
                except (OSError, ValueError):
                    continue
                inventory[descriptor] = (
                    value.st_dev,
                    value.st_ino,
                    value.st_uid,
                    value.st_gid,
                    stat.S_IMODE(value.st_mode),
                )
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_sqlite_probe_fd_unavailable"
        ) from exc
    return inventory


def _probe_connection_descriptor(
    before: Mapping[int, tuple[int, int, int, int, int]],
    after: Mapping[int, tuple[int, int, int, int, int]],
    identity: tuple[int, int, int, int, int],
) -> int:
    matches = tuple(
        descriptor
        for descriptor, observed in after.items()
        if observed[:2] == identity[:2] and before.get(descriptor) != observed
    )
    require(
        len(matches) == 1,
        "transactional_runtime_sqlite_probe_connection_identity_ambiguous",
    )
    return matches[0]


def _probe_descriptor_identity(
    descriptor: int,
) -> tuple[int, int, int, int, int]:
    try:
        value = os.stat(f"/proc/self/fd/{descriptor}")
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_sqlite_probe_connection_identity_unbound"
        ) from exc
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_gid,
        stat.S_IMODE(value.st_mode),
    )


def _verify_source_first_sqlite_platform(
    root: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    database_name: str,
    journal_name: str,
    fault_stage: str | None = None,
) -> dict[str, object]:
    require(
        fault_stage
        in {
            None,
            "before_commit",
            "after_commit_before_verification",
            "after_verification_before_cleanup",
        },
        "transactional_runtime_sqlite_probe_fault_stage_rejected",
    )
    root_state = root.lstat()
    require(
        not root.is_symlink()
        and stat.S_ISDIR(root_state.st_mode)
        and root_state.st_uid == expected_uid
        and root_state.st_gid == expected_gid
        and stat.S_IMODE(root_state.st_mode) == 0o700,
        "transactional_runtime_sqlite_probe_root_rejected",
    )
    require(
        database_name == production.FACTUAL_DATABASE_NAME
        and journal_name == production.FACTUAL_JOURNAL_NAME,
        "transactional_runtime_sqlite_probe_namespace_rejected",
    )
    target_database = root / database_name
    target_journal = root / journal_name
    require(
        not target_database.exists()
        and not target_database.is_symlink()
        and not target_journal.exists()
        and not target_journal.is_symlink(),
        "transactional_runtime_sqlite_probe_target_not_empty",
    )
    database = root / _SOURCE_FIRST_PROBE_NAME
    journal = database.with_name(database.name + "-journal")
    require(
        not database.exists()
        and not database.is_symlink()
        and not journal.exists()
        and not journal.is_symlink(),
        "transactional_runtime_sqlite_probe_collision",
    )
    connection: sqlite3.Connection | None = None
    connection_descriptor: int | None = None
    database_identity: tuple[int, int, int, int, int] | None = None
    journal_identity: tuple[int, int, int, int, int] | None = None
    committed = False
    verified = False
    failure: BaseException | None = None
    try:
        descriptor_inventory_before = _probe_fd_inventory()
        connection = sqlite3.connect(database, timeout=1.0, isolation_level=None)
        os.chown(database, expected_uid, expected_gid)
        os.chmod(database, 0o600)
        database_identity = _probe_identity(database)
        connection_descriptor = _probe_connection_descriptor(
            descriptor_inventory_before,
            _probe_fd_inventory(),
            database_identity,
        )
        require(
            database_identity[2:] == (expected_uid, expected_gid, 0o600),
            "transactional_runtime_sqlite_probe_identity_rejected",
        )
        mode = str(connection.execute("PRAGMA journal_mode=PERSIST").fetchone()[0]).lower()
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("CREATE TABLE source_first_probe(value INTEGER NOT NULL) STRICT")
        connection.execute("INSERT INTO source_first_probe VALUES (1)")
        if fault_stage == "before_commit":
            raise TransactionalRuntimeRejected(
                "transactional_runtime_sqlite_probe_before_commit"
            )
        connection.execute("COMMIT")
        committed = True
        require(
            journal.exists() and not journal.is_symlink(),
            "transactional_runtime_sqlite_probe_journal_rejected",
        )
        os.chown(journal, expected_uid, expected_gid)
        os.chmod(journal, 0o600)
        journal_identity = _probe_identity(journal)
        require(
            journal_identity[2:] == (expected_uid, expected_gid, 0o600),
            "transactional_runtime_sqlite_probe_journal_rejected",
        )
        if fault_stage == "after_commit_before_verification":
            raise TransactionalRuntimeRejected(
                "transactional_runtime_sqlite_probe_lost_return"
            )
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("INSERT INTO source_first_probe VALUES (2)")
        connection.execute("ROLLBACK")
        if journal.exists() or journal.is_symlink():
            require(
                _probe_identity(journal) == journal_identity,
                "transactional_runtime_sqlite_probe_journal_rejected",
            )
        database_list = connection.execute("PRAGMA database_list").fetchall()
        require(
            mode == production.FACTUAL_JOURNAL_MODE
            and int(connection.execute("PRAGMA synchronous").fetchone()[0])
            == production.FACTUAL_SYNCHRONOUS_LEVEL
            and connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
            and connection.execute("SELECT COUNT(*) FROM source_first_probe").fetchone()[0]
            == 1
            and len(database_list) == 1
            and database_list[0][1] == "main"
            and Path(str(database_list[0][2])).resolve() == database.resolve()
            and _probe_identity(database) == database_identity
            and _probe_descriptor_identity(connection_descriptor) == database_identity,
            "transactional_runtime_sqlite_probe_verification_rejected",
        )
        verified = True
        if fault_stage == "after_verification_before_cleanup":
            raise TransactionalRuntimeRejected(
                "transactional_runtime_sqlite_probe_lost_return"
            )
    except BaseException as exc:
        failure = exc
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
    finally:
        if connection is not None:
            connection.close()
    if database_identity is None:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_sqlite_probe_creation_ambiguous"
        ) from failure
    if connection_descriptor is not None:
        try:
            os.stat(f"/proc/self/fd/{connection_descriptor}")
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise TransactionalRuntimeRejected(
                "transactional_runtime_sqlite_probe_close_unconfirmed"
            ) from exc
        else:
            raise TransactionalRuntimeRejected(
                "transactional_runtime_sqlite_probe_close_unconfirmed"
            )
    current_database = _probe_identity(database)
    require(
        current_database == database_identity,
        "transactional_runtime_sqlite_probe_preserved_ambiguous",
    )
    if journal.exists() or journal.is_symlink():
        current_journal = _probe_identity(journal)
        if journal_identity is None:
            journal_identity = current_journal
        require(
            current_journal == journal_identity,
            "transactional_runtime_sqlite_probe_preserved_ambiguous",
        )
        journal.unlink()
    database.unlink()
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    require(
        not database.exists()
        and not database.is_symlink()
        and not journal.exists()
        and not journal.is_symlink(),
        "transactional_runtime_sqlite_probe_cleanup_rejected",
    )
    if failure is not None:
        raise failure.with_traceback(None)
    require(
        committed and verified,
        "transactional_runtime_sqlite_probe_verification_rejected",
    )
    return {
        "closed_before_return": True,
        "database_identity_verified": True,
        "journal_mode": production.FACTUAL_JOURNAL_MODE,
        "journal_namespace_verified": True,
        "residue_count": 0,
        "synchronous": production.FACTUAL_SYNCHRONOUS_LEVEL,
    }


class ContentSafeProductionHooks:
    """Concrete hooks; every external command is exact and injectable."""

    def __init__(
        self,
        *,
        runtime_plan: Mapping[str, object],
        mutation_set: Mapping[str, object],
        runner: CommandRunner,
        owner_uid: int,
        owner_gid: int,
        preflight_sha256: str,
        package_id: str,
        package_digest: str,
    ) -> None:
        self.runtime_plan = dict(runtime_plan)
        self.parent_plan = dict(runtime_plan["parent_plan"])
        self.contract = mutation.validate_mutation_set(mutation_set)
        self.runner = runner
        self.owner_uid = owner_uid
        self.owner_gid = owner_gid
        self.preflight_sha256 = preflight_sha256
        self.package_id = package_id
        self.package_digest = package_digest

    @property
    def state_root(self) -> Path:
        return Path(str(self.runtime_plan["storage"]["state_root"]))

    def consume_attempt(self, *, maximum_attempts: int) -> int:
        require(
            maximum_attempts == self.runtime_plan["strategy"]["maximum_attempts"] == 1,
            "transactional_runtime_attempt_limit_rejected",
        )
        receipt = consume_ledger(
            plan=self.runtime_plan,
            state_root=self.state_root,
            owner_uid=self.owner_uid,
            owner_gid=self.owner_gid,
            preflight_sha256=self.preflight_sha256,
            package_id=self.package_id,
            package_digest=self.package_digest,
        )
        return int(receipt["attempt"])

    def stop_target_services(self) -> None:
        _run(
            self.runner,
            (SYSTEMCTL, "stop", TELEGRAM_SOCKET, TELEGRAM_UNIT, CORE_UNIT),
            timeout=180,
            code="transactional_runtime_service_stop_failed",
        )

    def verify_target_services_stopped(self) -> None:
        for unit in (CORE_UNIT, TELEGRAM_UNIT, TELEGRAM_SOCKET):
            value = _unit_projection(self.runner, unit)
            require(value["active_state"] == "inactive", "transactional_runtime_services_not_stopped")

    def _verify_target_files(self) -> None:
        _verify_inventory(self.contract, "target_inventory", "transactional_runtime_target_inventory_drifted")
        parent.verify_root_transitions(self.parent_plan["root_transitions"], side="after")

    def verify_target_semantics(self) -> None:
        self._verify_target_files()
        archive = self.runtime_plan["production_identity"].get("archive")
        require(
            isinstance(archive, Mapping)
            and archive.get("root_precreated") is True
            and archive.get("empty") is True
            and archive.get("delivery_journal_retired") is True
            and archive.get("post_start_factual_audit") is False,
            "transactional_runtime_archive_platform_contract_rejected",
        )
        _verify_source_first_sqlite_platform(
            Path(str(archive["root"])),
            expected_uid=int(archive["database_uid"]),
            expected_gid=int(archive["database_gid"]),
            database_name=str(archive["database_name"]),
            journal_name=str(archive["journal_name"]),
        )

    def daemon_reload(self) -> None:
        _run(
            self.runner,
            (SYSTEMCTL, "daemon-reload"),
            timeout=60,
            code="transactional_runtime_daemon_reload_failed",
        )

    def start_core(self) -> None:
        _run(
            self.runner,
            (SYSTEMCTL, "start", CORE_UNIT),
            timeout=180,
            code="transactional_runtime_core_start_failed",
        )

    def verify_core(self) -> None:
        require(
            _unit_projection(self.runner, CORE_UNIT) == self.runtime_plan["services"]["target"]["core"],
            "transactional_runtime_core_postflight_drifted",
        )

    def start_telegram(self) -> None:
        _run(
            self.runner,
            (PYTHON, "-B", TELEGRAM_RESUME_CONTROLLER),
            timeout=420,
            code="transactional_runtime_telegram_resume_failed",
        )

    def verify_target(self) -> None:
        self._verify_target_files()
        require(
            observe_services(self.runner) == self.runtime_plan["services"]["target"],
            "transactional_runtime_target_postflight_drifted",
        )

    def verify_prestate_files(self) -> None:
        _verify_inventory(self.contract, "prestate_inventory", "transactional_runtime_prestate_inventory_drifted")
        parent.verify_root_transitions(self.parent_plan["root_transitions"], side="before")

    def restore_core(self) -> None:
        self.start_core()

    def verify_core_prestate(self) -> None:
        require(
            _unit_projection(self.runner, CORE_UNIT) == self.runtime_plan["services"]["prestate"]["core"],
            "transactional_runtime_core_prestate_drifted",
        )

    def restore_telegram(self) -> None:
        self.start_telegram()

    def verify_prestate(self) -> None:
        self.verify_prestate_files()
        require(
            observe_services(self.runner) == self.runtime_plan["services"]["prestate"],
            "transactional_runtime_prestate_postflight_drifted",
        )


class PreparedRuntimeBackend(parent.FullMutationTransactionBackend):
    """Use the already-created plan-bound backup; never overwrite it."""

    def create_backup(self) -> None:
        parent.verify_plan_bound_backup(
            plan=self.plan,
            mutation_set=self.contract,
            backup_path=self.storage.backup_path,
            owner_uid=self.owner_uid,
            owner_gid=self.owner_gid,
        )


def _backup_digest(path: Path) -> str:
    manifest = _canonical_read(path / "manifest.json", "transactional_runtime_backup_manifest_rejected")
    return sha256(canonical(manifest)).hexdigest()


def formal_preflight(
    *,
    runtime_plan: Mapping[str, object],
    mutation_set: Mapping[str, object],
    lineages: Mapping[str, object],
    parent_namespace: Mapping[str, object],
    runtime_manifest: Mapping[str, object],
    runtime_manifest_sha256: str,
    expected_runtime_bundle_id: str,
    expected_runtime_manifest_sha256: str,
    owner_uid: int,
    owner_gid: int,
    package_id: str,
    package_digest: str,
    runner: CommandRunner,
    continuation_reference: Mapping[str, object] | None = None,
) -> dict[str, object]:
    ledger = verify_ledger_root(
        plan=runtime_plan,
        state_root=Path(str(runtime_plan["storage"]["state_root"])),
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        package_id=package_id,
        package_digest=package_digest,
        allow_runtime_files=False,
    )
    runtime_namespace = verify_namespace_ready(
        namespace_observation(
            state_root=Path(str(runtime_plan["storage"]["state_root"])),
            backup_root=Path(str(runtime_plan["storage"]["backup_root"])),
        )
    )
    selected = dict(runtime_plan)
    require(
        ledger["attempts"] == 0
        and ledger["maximum_attempts"] == 1
        and selected["attempts"] == {"consumed": 0, "maximum": 1, "next": 1},
        "transactional_runtime_preflight_attempt_rejected",
    )
    # Validate the immutable plan by rebuilding it with an absent-namespace
    # projection.  The state created after plan freeze is then checked above.
    frozen_namespace = absent_runtime_namespace()
    validate_runtime_plan(
        selected,
        mutation_set=mutation_set,
        lineages=lineages,
        parent_namespace=parent_namespace,
        runtime_namespace=frozen_namespace,
        runtime_manifest=runtime_manifest,
        runtime_manifest_sha256=runtime_manifest_sha256,
        expected_runtime_bundle_id=expected_runtime_bundle_id,
        expected_runtime_manifest_sha256=expected_runtime_manifest_sha256,
        continuation_reference=continuation_reference,
    )
    require(runtime_namespace["backup_root_exists"], "transactional_runtime_backup_unavailable")
    backup_path = Path(str(selected["storage"]["backup_path"]))
    parent.verify_plan_bound_backup(
        plan=selected["parent_plan"],
        mutation_set=mutation_set,
        backup_path=backup_path,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    mutation.require_prestate(mutation_set)
    parent.verify_root_transitions(selected["parent_plan"]["root_transitions"], side="before")
    observed_services = observe_services(runner)
    require(
        observed_services == selected["services"]["prestate"],
        "transactional_runtime_preflight_service_drifted",
    )
    semantic = {
        "artifacts": selected["artifacts"],
        "attempts": 0,
        "backup_manifest_sha256": _backup_digest(backup_path),
        "flags": dict(_ZERO_FLAGS),
        "immutable_terminal_evidence_digest": selected[
            "immutable_terminal_evidence_digest"
        ],
        "lineage_evidence_digest": selected["lineage_evidence_digest"],
        "maximum_attempts": 1,
        "next_attempt": 1,
        "package_digest": package_digest,
        "package_id": package_id,
        "plan_id": selected["plan_id"],
        "prestate_service_digest": digest("p07_transactional_runtime_services", observed_services),
        "schema": PREFLIGHT_SCHEMA,
        "source_id": SOURCE_ID,
        "status": "ready",
        "strategy_id": selected["strategy"]["strategy_id"],
    }
    return {**semantic, "preflight_id": digest("p07_transactional_runtime_preflight", semantic)}


def validate_preflight(
    payload: Mapping[str, object],
    runtime_plan: Mapping[str, object],
    *,
    package_id: str,
    package_digest: str,
) -> dict[str, object]:
    selected = dict(payload)
    required = {
        "artifacts",
        "attempts",
        "backup_manifest_sha256",
        "flags",
        "immutable_terminal_evidence_digest",
        "lineage_evidence_digest",
        "maximum_attempts",
        "next_attempt",
        "package_digest",
        "package_id",
        "plan_id",
        "preflight_id",
        "prestate_service_digest",
        "schema",
        "source_id",
        "status",
        "strategy_id",
    }
    semantic = {key: selected.get(key) for key in required - {"preflight_id"}}
    require(
        set(selected) == required
        and selected.get("schema") == PREFLIGHT_SCHEMA
        and selected.get("source_id") == SOURCE_ID
        and selected.get("strategy_id")
        == runtime_plan["strategy"]["strategy_id"]
        and selected.get("status") == "ready"
        and selected.get("plan_id") == runtime_plan["plan_id"]
        and selected.get("artifacts") == runtime_plan["artifacts"]
        and selected.get("immutable_terminal_evidence_digest")
        == runtime_plan["immutable_terminal_evidence_digest"]
        and selected.get("lineage_evidence_digest") == runtime_plan["lineage_evidence_digest"]
        and selected.get("attempts") == 0
        and selected.get("next_attempt") == 1
        and selected.get("maximum_attempts") == 1
        and selected.get("package_id") == package_id
        and selected.get("package_digest") == package_digest
        and selected.get("flags") == _ZERO_FLAGS
        and selected.get("preflight_id")
        == digest("p07_transactional_runtime_preflight", semantic),
        "transactional_runtime_preflight_rejected",
    )
    _require_sha(selected["backup_manifest_sha256"], "transactional_runtime_preflight_rejected")
    _require_sha(selected["prestate_service_digest"], "transactional_runtime_preflight_rejected")
    return selected


def _payloads_from_contract(
    contract: Mapping[str, object], *, side: str, payload_root: Path | None = None
) -> dict[str, bytes]:
    selected = mutation.validate_mutation_set(contract)
    require(side in {"before", "after"}, "transactional_runtime_payload_side_rejected")
    roots = mutation.roots_by_id(selected)
    result: dict[str, bytes] = {}
    expected_payload_paths: set[str] = set()
    if payload_root is not None:
        metadata = payload_root.lstat()
        require(
            stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
            "transactional_runtime_payload_root_rejected",
        )
    for operation in selected["operations"]:
        state = operation[side]
        if not state["exists"]:
            continue
        key = mutation.path_key(str(operation["root_id"]), str(operation["logical_path"]))
        if side == "before":
            path = Path(str(roots[str(operation["root_id"])]["path"])) / str(operation["logical_path"])
        else:
            require(payload_root is not None, "transactional_runtime_payload_root_rejected")
            relative = f"{int(operation['order']):04d}-{digest('p07_runtime_payload_path', key)[:20]}.blob"
            expected_payload_paths.add(relative)
            path = payload_root / relative
        metadata = path.lstat()
        require(
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_size == state["size"],
            "transactional_runtime_payload_rejected",
        )
        payload = path.read_bytes()
        require(sha256(payload).hexdigest() == state["sha256"], "transactional_runtime_payload_rejected")
        result[key] = payload
    if payload_root is not None:
        actual = {
            path.relative_to(payload_root).as_posix()
            for path in payload_root.rglob("*")
            if path.is_file() or path.is_symlink()
        }
        require(actual == expected_payload_paths, "transactional_runtime_payload_inventory_rejected")
    return result


@dataclass(frozen=True, slots=True)
class VerifiedAfterPayloadPackage:
    package_id: str
    package_digest: str
    package_path: Path
    runtime_plan: Mapping[str, object]
    mutation_set: Mapping[str, object]
    context: Mapping[str, object]
    after_payloads: Mapping[str, bytes]


def _has_extended_acl(path: Path) -> bool:
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except (AttributeError, OSError) as exc:
        raise TransactionalRuntimeRejected("transactional_runtime_package_acl_unavailable") from exc
    return any(
        name in {"system.posix_acl_access", "system.posix_acl_default"}
        for name in names
    )


def _require_source_package_root(
    package_root: Path, *, must_exist: bool, expected_root: Path | None = None
) -> None:
    selected_expected = PACKAGE_ROOT if expected_root is None else expected_root
    try:
        parent_resolved = package_root.parent.resolve(strict=True)
        root_resolved = package_root.resolve(strict=must_exist)
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_package_root_identity_rejected"
        ) from exc
    require(
        package_root == selected_expected
        and package_root.is_absolute()
        and parent_resolved == package_root.parent
        and root_resolved == package_root,
        "transactional_runtime_package_root_identity_rejected",
    )


def _require_package_directory(
    path: Path,
    *,
    owner_uid: int,
    owner_gid: int,
    exact_mode: int | None,
    code: str,
) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise TransactionalRuntimeRejected(code) from exc
    mode = stat.S_IMODE(metadata.st_mode)
    require(
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_uid == owner_uid
        and metadata.st_gid == owner_gid
        and (mode == exact_mode if exact_mode is not None else mode & 0o022 == 0)
        and not _has_extended_acl(path),
        code,
    )
    return metadata


def _require_package_file(
    path: Path,
    *,
    owner_uid: int,
    owner_gid: int,
    expected_mode: int,
    expected_size: int,
    expected_sha256: str,
    code: str,
) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise TransactionalRuntimeRejected(code) from exc
    require(
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_nlink == 1
        and stat.S_IMODE(metadata.st_mode) == expected_mode
        and metadata.st_uid == owner_uid
        and metadata.st_gid == owner_gid
        and metadata.st_size == expected_size
        and not _has_extended_acl(path),
        code,
    )
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise TransactionalRuntimeRejected(code) from exc
    require(
        len(payload) == expected_size and sha256(payload).hexdigest() == expected_sha256,
        code,
    )
    return payload


def _exclusive_package_directory(
    path: Path,
    *,
    owner_uid: int,
    owner_gid: int,
) -> None:
    require(
        not path.exists() and not path.is_symlink(),
        "transactional_runtime_package_non_overwrite_rejected",
    )
    try:
        path.mkdir(mode=0o700)
        os.chmod(path, 0o700)
        os.chown(path, owner_uid, owner_gid)
        _fsync_directory(path.parent)
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_package_directory_create_failed"
        ) from exc
    _require_package_directory(
        path,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        exact_mode=0o700,
        code="transactional_runtime_package_directory_readback_rejected",
    )


def _read_canonical_package_document(
    path: Path,
    *,
    owner_uid: int,
    owner_gid: int,
    maximum_size: int,
    expected_sha256: str | None,
    code: str,
) -> tuple[dict[str, object], bytes]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise TransactionalRuntimeRejected(code) from exc
    require(
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_nlink == 1
        and stat.S_IMODE(metadata.st_mode) == 0o600
        and metadata.st_uid == owner_uid
        and metadata.st_gid == owner_gid
        and 0 < metadata.st_size <= maximum_size
        and not _has_extended_acl(path),
        code,
    )
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("ascii"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TransactionalRuntimeRejected(code) from exc
    require(
        isinstance(payload, dict)
        and len(raw) == metadata.st_size
        and canonical(payload) == raw
        and (expected_sha256 is None or sha256(raw).hexdigest() == expected_sha256),
        code,
    )
    return payload, raw


def _exclusive_package_write(
    path: Path,
    payload: bytes,
    *,
    owner_uid: int,
    owner_gid: int,
) -> None:
    temporary = path.parent / f".{path.name}.tmp"
    require(
        not path.exists()
        and not path.is_symlink()
        and not temporary.exists()
        and not temporary.is_symlink(),
        "transactional_runtime_package_non_overwrite_rejected",
    )
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.fchmod(descriptor, 0o600)
            os.fchown(descriptor, owner_uid, owner_gid)
        finally:
            os.close(descriptor)
        os.rename(temporary, path)
        _fsync_directory(path.parent)
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_package_write_failed"
        ) from exc
    _require_package_file(
        path,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        expected_mode=0o600,
        expected_size=len(payload),
        expected_sha256=sha256(payload).hexdigest(),
        code="transactional_runtime_package_write_readback_rejected",
    )


def _package_context(
    *,
    material: ProductionRuntimeMaterial,
    lineages: Mapping[str, object],
    parent_namespace: Mapping[str, object],
    runtime_manifest: Mapping[str, object],
    runtime_manifest_sha256: str,
    expected_runtime_bundle_id: str,
    expected_runtime_manifest_sha256: str,
    failed_request_continuation: Mapping[str, object] | None = None,
    immutable_continuation_reference: Mapping[str, object] | None = None,
    fresh_strategy: Mapping[str, object] | None = None,
) -> dict[str, object]:
    if fresh_strategy is not None:
        require(
            failed_request_continuation is None
            and isinstance(immutable_continuation_reference, Mapping),
            "transactional_runtime_package_context_rejected",
        )
        return {
            "expected_runtime_bundle_id": expected_runtime_bundle_id,
            "expected_runtime_manifest_sha256": expected_runtime_manifest_sha256,
            "immutable_continuation_reference": dict(
                immutable_continuation_reference
            ),
            "lineages": dict(lineages),
            "mutation_set": dict(material.mutation_set),
            "parent_namespace": dict(parent_namespace),
            "runtime_manifest": dict(runtime_manifest),
            "runtime_manifest_sha256": runtime_manifest_sha256,
            "runtime_plan": dict(material.runtime_plan),
            "schema": FRESH_PACKAGE_CONTEXT_SCHEMA,
            "source_id": SOURCE_ID,
            "strategy": dict(fresh_strategy),
            "strategy_id": fresh_strategy["strategy_id"],
        }
    require(
        isinstance(failed_request_continuation, Mapping)
        and immutable_continuation_reference is None,
        "transactional_runtime_package_context_rejected",
    )
    return {
        "expected_runtime_bundle_id": expected_runtime_bundle_id,
        "expected_runtime_manifest_sha256": expected_runtime_manifest_sha256,
        "failed_request_continuation": dict(failed_request_continuation),
        "lineages": dict(lineages),
        "mutation_set": dict(material.mutation_set),
        "parent_namespace": dict(parent_namespace),
        "runtime_manifest": dict(runtime_manifest),
        "runtime_manifest_sha256": runtime_manifest_sha256,
        "runtime_plan": dict(material.runtime_plan),
        "schema": PACKAGE_CONTEXT_SCHEMA,
        "source_id": SOURCE_ID,
        "strategy_id": STRATEGY_ID,
    }


def _validated_package_context(payload: Mapping[str, object]) -> dict[str, object]:
    selected = dict(payload)
    if selected.get("schema") == FRESH_PACKAGE_CONTEXT_SCHEMA:
        fresh_fields = {
            "expected_runtime_bundle_id",
            "expected_runtime_manifest_sha256",
            "immutable_continuation_reference",
            "lineages",
            "mutation_set",
            "parent_namespace",
            "runtime_manifest",
            "runtime_manifest_sha256",
            "runtime_plan",
        }
        require(
            set(selected)
            == {"schema", "source_id", "strategy", "strategy_id", *fresh_fields}
            and selected.get("source_id") == SOURCE_ID
            and isinstance(selected.get("strategy"), Mapping)
            and isinstance(selected.get("immutable_continuation_reference"), Mapping),
            "transactional_runtime_package_context_rejected",
        )
        request_context = {
            key: selected[key]
            for key in _CONTEXT_FIELDS
            if key != "failed_request_continuation"
        }
        request_context["failed_request_continuation"] = {}
        context = _validated_request_context(
            request_context,
            continuation_reference=selected["immutable_continuation_reference"],
        )
        reference = _validate_immutable_continuation_reference_contract(
            selected["immutable_continuation_reference"],
            require_production_exact=True,
        )
        strategy = validate_fresh_strategy_contract(
            selected["strategy"],
            runtime_manifest=context["runtime_manifest"],
            runtime_manifest_sha256=context["runtime_manifest_sha256"],
            lineages=context["lineages"],
            continuation_reference=reference,
        )
        require(
            selected.get("strategy_id") == strategy["strategy_id"]
            and context["runtime_plan"]["strategy"] == strategy
            and context["runtime_plan"]["storage"]["package_root"]
            == strategy["storage"]["package_root"],
            "transactional_runtime_package_context_rejected",
        )
        context.pop("failed_request_continuation", None)
        context["immutable_continuation_reference"] = reference
        context["strategy"] = strategy
        return context
    require(
        set(selected) == {"schema", "source_id", "strategy_id", *_CONTEXT_FIELDS}
        and selected.get("schema") == PACKAGE_CONTEXT_SCHEMA
        and selected.get("source_id") == SOURCE_ID
        and selected.get("strategy_id") == STRATEGY_ID,
        "transactional_runtime_package_context_rejected",
    )
    context = _validated_request_context(selected)
    context["failed_request_continuation"] = _validate_failed_request_continuation_payload(
        context["failed_request_continuation"],
        runtime_manifest=context["runtime_manifest"],
        runtime_manifest_sha256=context["runtime_manifest_sha256"],
        lineages=context["lineages"],
    )
    require(
        context["runtime_plan"]["storage"]["package_root"] == PACKAGE_ROOT.as_posix(),
        "transactional_runtime_package_root_identity_rejected",
    )
    return context


def _package_operation_entries(
    *,
    runtime_plan: Mapping[str, object],
    mutation_set: Mapping[str, object],
    after_payloads: Mapping[str, bytes],
) -> tuple[list[dict[str, object]], int, int]:
    contract = mutation.validate_mutation_set(mutation_set)
    operations = contract["operations"]
    require(
        0 < len(operations) <= MAX_PACKAGE_OPERATIONS,
        "transactional_runtime_package_operation_bound_rejected",
    )
    production_identity = runtime_plan.get("production_identity")
    require(isinstance(production_identity, Mapping), "transactional_runtime_package_role_rejected")
    path_roles = production_identity.get("path_roles")
    require(isinstance(path_roles, Mapping), "transactional_runtime_package_role_rejected")
    role_rows = path_roles.get("files")
    require(isinstance(role_rows, list), "transactional_runtime_package_role_rejected")
    roles: dict[str, str] = {}
    for row in role_rows:
        require(
            isinstance(row, Mapping)
            and isinstance(row.get("identity"), str)
            and isinstance(row.get("role"), str),
            "transactional_runtime_package_role_rejected",
        )
        identity = str(row["identity"])
        require(identity not in roles, "transactional_runtime_package_role_rejected")
        roles[identity] = str(row["role"])
    expected_payload_keys: set[str] = set()
    entries: list[dict[str, object]] = []
    total_size = 0
    for operation in operations:
        key = mutation.path_key(str(operation["root_id"]), str(operation["logical_path"]))
        identity = "file:" + key
        require(identity in roles, "transactional_runtime_package_role_rejected")
        after = dict(operation["after"])
        relative: str | None = None
        if after["exists"]:
            expected_payload_keys.add(key)
            require(key in after_payloads, "transactional_runtime_package_payload_set_rejected")
            payload = after_payloads[key]
            require(
                sha256(payload).hexdigest() == after["sha256"]
                and len(payload) == after["size"],
                "transactional_runtime_package_payload_rejected",
            )
            relative = (
                f"payloads/{int(operation['order']):04d}-"
                f"{digest('p07_runtime_payload_path', key)[:20]}.blob"
            )
            total_size += len(payload)
        entries.append(
            {
                "after": after,
                "kind": operation["kind"],
                "logical_path": operation["logical_path"],
                "operation_order": operation["order"],
                "path_key": key,
                "payload_path": relative,
                "role": roles[identity],
                "root_id": operation["root_id"],
            }
        )
    require(
        set(after_payloads) == expected_payload_keys
        and len(expected_payload_keys) <= MAX_PACKAGE_PAYLOAD_FILES
        and total_size <= MAX_PACKAGE_PAYLOAD_BYTES,
        "transactional_runtime_package_payload_bound_rejected",
    )
    return entries, len(expected_payload_keys), total_size


def _package_semantic(
    *, context: Mapping[str, object], after_payloads: Mapping[str, bytes]
) -> dict[str, object]:
    validated = _validated_package_context(context)
    runtime_plan = validated["runtime_plan"]
    contract = validated["mutation_set"]
    context_bytes = canonical(dict(context))
    require(
        len(context_bytes) <= MAX_PACKAGE_CONTEXT_BYTES,
        "transactional_runtime_package_context_bound_rejected",
    )
    operations, payload_count, payload_bytes = _package_operation_entries(
        runtime_plan=runtime_plan,
        mutation_set=contract,
        after_payloads=after_payloads,
    )
    p08_status = runtime_plan["parent_plan"]["public_prestate"]["p08_status"]
    require(isinstance(p08_status, Mapping), "transactional_runtime_package_p08_binding_rejected")
    p08_status = dict(p08_status)
    is_fresh = runtime_plan["strategy"].get("schema") == FRESH_STRATEGY_SCHEMA
    selected_status_schema = (
        p08_status.get("status_schema") if is_fresh else p08_status.get("schema")
    )
    require(
        isinstance(selected_status_schema, str)
        and bool(selected_status_schema)
        and isinstance(p08_status.get("source_identity"), str)
        and bool(p08_status.get("source_identity")),
        "transactional_runtime_package_p08_binding_rejected",
    )
    if is_fresh:
        require(
            runtime_plan["status_invocation"]["projection_digest"]
            == digest("p07_status_invocation_accepted_projection", p08_status),
            "transactional_runtime_status_invocation_prestate_drifted",
        )
    if "immutable_continuation_reference" in validated:
        reference = validated["immutable_continuation_reference"]
        predecessor = {
            "continuation_id": reference["continuation"]["continuation_id"],
            "fresh_p08_status_required": True,
            "reference_digest": reference["reference_digest"],
            "reinterpreted_as_ready": False,
            "terminal_handoff_sha256": reference["terminal_t2"]["handoff_sha256"],
            "terminal_rejection_payload_sha256": reference["terminal_t2"][
                "p08_rejection_payload_sha256"
            ],
        }
        predecessor_field = "immutable_continuation_reference"
    else:
        continuation = validated["failed_request_continuation"]
        predecessor = {
            "continuation_id": continuation["continuation_id"],
            "continuation_sha256": sha256(canonical(continuation)).hexdigest(),
            "fresh_p08_status_required": True,
            "terminal_request_id": continuation["terminal_request"]["request_id"],
            "terminal_rejection_sha256": continuation["terminal_rejection"]["sha256"],
        }
        predecessor_field = "failed_request_continuation"
    semantic = {
        "artifacts": runtime_plan["artifacts"],
        "context_sha256": sha256(context_bytes).hexdigest(),
        "context_size": len(context_bytes),
        "immutable_terminal_evidence_digest": runtime_plan[
            "immutable_terminal_evidence_digest"
        ],
        "limits": {
            "context_bytes": MAX_PACKAGE_CONTEXT_BYTES,
            "manifest_bytes": MAX_PACKAGE_MANIFEST_BYTES,
            "operations": MAX_PACKAGE_OPERATIONS,
            "payload_bytes": MAX_PACKAGE_PAYLOAD_BYTES,
            "payload_files": MAX_PACKAGE_PAYLOAD_FILES,
        },
        "lineage_evidence_digest": runtime_plan["lineage_evidence_digest"],
        "mutation_set_id": contract["mutation_set_id"],
        "operation_count": len(operations),
        "operations": operations,
        "p08_status": {
            "binding_digest": digest("p07_transactional_runtime_p08_status", p08_status),
            "schema": selected_status_schema,
            "source_identity": p08_status["source_identity"],
        },
        "payload_bytes": payload_bytes,
        "payload_count": payload_count,
        "plan_id": runtime_plan["plan_id"],
        "schema": PACKAGE_SCHEMA,
        "source": runtime_plan["source"],
        "source_id": SOURCE_ID,
        "strategy_id": runtime_plan["strategy"]["strategy_id"],
    }
    semantic[predecessor_field] = predecessor
    return semantic


def _package_receipt(
    *, manifest: Mapping[str, object], package_digest: str
) -> dict[str, object]:
    semantic = {
        "flags": dict(_ZERO_FLAGS),
        "operation_count": manifest["operation_count"],
        "package_digest": package_digest,
        "package_id": manifest["package_id"],
        "payload_bytes": manifest["payload_bytes"],
        "payload_count": manifest["payload_count"],
        "plan_id": manifest["plan_id"],
        "schema": PACKAGE_RECEIPT_SCHEMA,
        "source_id": SOURCE_ID,
        "status": "complete",
        "strategy_id": manifest["strategy_id"],
    }
    return {
        **semantic,
        "receipt_id": digest("p07_transactional_runtime_after_payload_receipt", semantic),
    }


def _package_completion(
    *, manifest: Mapping[str, object], package_digest: str, receipt: Mapping[str, object]
) -> dict[str, object]:
    return {
        "context_sha256": manifest["context_sha256"],
        "manifest_sha256": package_digest,
        "package_digest": package_digest,
        "package_id": manifest["package_id"],
        "receipt_sha256": sha256(canonical(receipt)).hexdigest(),
        "schema": PACKAGE_COMPLETION_SCHEMA,
        "source_id": SOURCE_ID,
        "strategy_id": manifest["strategy_id"],
    }


def materialize_after_payload_package(
    *,
    context: Mapping[str, object],
    after_payloads: Mapping[str, bytes],
    owner_uid: int,
    owner_gid: int,
    package_root: Path | None = None,
    stage_hook: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Create one protected package; dependency injection is unavailable to the CLI."""

    validated_context = _validated_package_context(context)
    expected_root = Path(
        str(validated_context["runtime_plan"]["storage"]["package_root"])
    )
    package_root = expected_root if package_root is None else package_root
    require(
        package_root == expected_root,
        "transactional_runtime_package_root_identity_rejected",
    )
    _require_source_package_root(
        package_root, must_exist=False, expected_root=expected_root
    )
    require(
        not package_root.exists()
        and not package_root.is_symlink(),
        "transactional_runtime_package_namespace_preexisting",
    )
    _require_package_directory(
        package_root.parent,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        exact_mode=None,
        code="transactional_runtime_package_parent_rejected",
    )
    semantic = _package_semantic(context=context, after_payloads=after_payloads)
    package_id = digest("p07_transactional_runtime_after_payload_package", semantic)
    manifest = {**semantic, "package_id": package_id}
    manifest_bytes = canonical(manifest)
    require(
        len(manifest_bytes) <= MAX_PACKAGE_MANIFEST_BYTES,
        "transactional_runtime_package_manifest_bound_rejected",
    )
    package_digest = sha256(manifest_bytes).hexdigest()
    receipt = _package_receipt(manifest=manifest, package_digest=package_digest)
    completion = _package_completion(
        manifest=manifest, package_digest=package_digest, receipt=receipt
    )
    _exclusive_package_directory(
        package_root,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    if stage_hook is not None:
        stage_hook("namespace_created")
    temporary = package_root / f".prepare-{package_id}"
    final = package_root / package_id
    require(
        not temporary.exists()
        and not temporary.is_symlink()
        and not final.exists()
        and not final.is_symlink(),
        "transactional_runtime_package_non_overwrite_rejected",
    )
    _exclusive_package_directory(
        temporary,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    payload_root = temporary / "payloads"
    _exclusive_package_directory(
        payload_root,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    if stage_hook is not None:
        stage_hook("staging_created")
    context_bytes = canonical(dict(context))
    _exclusive_package_write(
        temporary / "context.json",
        context_bytes,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    if stage_hook is not None:
        stage_hook("context_written")
    for entry in manifest["operations"]:
        relative = entry["payload_path"]
        if relative is None:
            continue
        payload = after_payloads[str(entry["path_key"])]
        target = temporary / str(relative)
        require(target.parent == payload_root, "transactional_runtime_package_path_rejected")
        _exclusive_package_write(
            target,
            payload,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        if stage_hook is not None:
            stage_hook(f"payload_written_{int(entry['operation_order']):04d}")
    _exclusive_package_write(
        temporary / "manifest.json",
        manifest_bytes,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    if stage_hook is not None:
        stage_hook("manifest_written")
    _exclusive_package_write(
        temporary / "receipt.json",
        canonical(receipt),
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    if stage_hook is not None:
        stage_hook("receipt_written")
    _exclusive_package_write(
        temporary / "COMPLETE.json",
        canonical(completion),
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    _fsync_directory(payload_root)
    _fsync_directory(temporary)
    if stage_hook is not None:
        stage_hook("completion_written")
    try:
        require(
            not final.exists() and not final.is_symlink(),
            "transactional_runtime_package_non_overwrite_rejected",
        )
        os.rename(temporary, final)
        _fsync_directory(package_root)
    except OSError as exc:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_package_finalize_failed"
        ) from exc
    if stage_hook is not None:
        stage_hook("finalized")
    verified = verify_after_payload_package(
        package_id=package_id,
        package_digest=package_digest,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        package_root=package_root,
    )
    require(
        verified.package_id == package_id and verified.package_digest == package_digest,
        "transactional_runtime_package_postflight_rejected",
    )
    return receipt


def verify_after_payload_package(
    *,
    package_id: str,
    package_digest: str,
    owner_uid: int,
    owner_gid: int,
    package_root: Path | None = None,
) -> VerifiedAfterPayloadPackage:
    package_root = PACKAGE_ROOT if package_root is None else package_root
    _require_source_package_root(
        package_root, must_exist=True, expected_root=package_root
    )
    _require_sha(package_id, "transactional_runtime_package_identity_rejected")
    _require_sha(package_digest, "transactional_runtime_package_identity_rejected")
    _require_package_directory(
        package_root,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        exact_mode=0o700,
        code="transactional_runtime_package_root_rejected",
    )
    require(
        sorted(path.name for path in package_root.iterdir()) == [package_id],
        "transactional_runtime_package_root_inventory_rejected",
    )
    package_path = package_root / package_id
    _require_package_directory(
        package_path,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        exact_mode=0o700,
        code="transactional_runtime_package_directory_rejected",
    )
    payload_root = package_path / "payloads"
    _require_package_directory(
        payload_root,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        exact_mode=0o700,
        code="transactional_runtime_package_payload_root_rejected",
    )
    require(
        sorted(path.name for path in package_path.iterdir())
        == ["COMPLETE.json", "context.json", "manifest.json", "payloads", "receipt.json"],
        "transactional_runtime_package_inventory_rejected",
    )
    manifest_path = package_path / "manifest.json"
    manifest, manifest_raw = _read_canonical_package_document(
        manifest_path,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        maximum_size=MAX_PACKAGE_MANIFEST_BYTES,
        expected_sha256=package_digest,
        code="transactional_runtime_package_manifest_rejected",
    )
    context_path = package_path / "context.json"
    context, context_raw = _read_canonical_package_document(
        context_path,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        maximum_size=MAX_PACKAGE_CONTEXT_BYTES,
        expected_sha256=_require_sha(
            manifest.get("context_sha256"),
            "transactional_runtime_package_context_rejected",
        ),
        code="transactional_runtime_package_context_rejected",
    )
    validated = _validated_package_context(context)
    require(
        validated["runtime_plan"]["storage"]["package_root"] == package_root.as_posix(),
        "transactional_runtime_package_root_identity_rejected",
    )
    after_payloads: dict[str, bytes] = {}
    expected_payload_paths: set[str] = set()
    for operation in validated["mutation_set"]["operations"]:
        if not operation["after"]["exists"]:
            continue
        key = mutation.path_key(str(operation["root_id"]), str(operation["logical_path"]))
        relative = (
            f"{int(operation['order']):04d}-"
            f"{digest('p07_runtime_payload_path', key)[:20]}.blob"
        )
        expected_payload_paths.add(relative)
        payload = _require_package_file(
            payload_root / relative,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            expected_mode=0o600,
            expected_size=int(operation["after"]["size"]),
            expected_sha256=str(operation["after"]["sha256"]),
            code="transactional_runtime_package_payload_readback_rejected",
        )
        after_payloads[key] = payload
    require(
        {
            path.name
            for path in payload_root.iterdir()
            if path.is_file() or path.is_symlink()
        }
        == expected_payload_paths
        and all(path.is_file() or path.is_symlink() for path in payload_root.iterdir()),
        "transactional_runtime_package_payload_inventory_rejected",
    )
    semantic = _package_semantic(context=context, after_payloads=after_payloads)
    expected_manifest = {
        **semantic,
        "package_id": digest("p07_transactional_runtime_after_payload_package", semantic),
    }
    require(
        manifest == expected_manifest and manifest["package_id"] == package_id,
        "transactional_runtime_package_manifest_rejected",
    )
    receipt, receipt_raw = _read_canonical_package_document(
        package_path / "receipt.json",
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        maximum_size=MAX_PACKAGE_CONTEXT_BYTES,
        expected_sha256=None,
        code="transactional_runtime_package_receipt_rejected",
    )
    expected_receipt = _package_receipt(
        manifest=manifest, package_digest=package_digest
    )
    require(receipt == expected_receipt, "transactional_runtime_package_receipt_rejected")
    require(receipt_raw == canonical(receipt), "transactional_runtime_package_receipt_rejected")
    completion, completion_raw = _read_canonical_package_document(
        package_path / "COMPLETE.json",
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        maximum_size=MAX_PACKAGE_CONTEXT_BYTES,
        expected_sha256=None,
        code="transactional_runtime_package_completion_rejected",
    )
    require(
        completion
        == _package_completion(
            manifest=manifest, package_digest=package_digest, receipt=receipt
        ),
        "transactional_runtime_package_completion_rejected",
    )
    require(
        completion_raw == canonical(completion),
        "transactional_runtime_package_completion_rejected",
    )
    return VerifiedAfterPayloadPackage(
        package_id=package_id,
        package_digest=package_digest,
        package_path=package_path,
        runtime_plan=validated["runtime_plan"],
        mutation_set=validated["mutation_set"],
        context=context,
        after_payloads=after_payloads,
    )


def _terminal_receipt(
    *,
    runtime_plan: Mapping[str, object],
    status: str,
    journal_projection: Mapping[str, object] | None,
    failure: BaseException | None,
    package_id: str,
    package_digest: str,
) -> dict[str, object]:
    require(
        status in {"activated", "pre_attempt_failed", "failed_rollback_verified", "rollback_failed"},
        "transactional_runtime_receipt_status_rejected",
    )
    semantic = {
        "activation_failure_code": (
            _typed_error(failure, "transactional_runtime_activation_failed") if failure is not None else None
        ),
        "content_retained": False,
        "journal_projection": dict(journal_projection) if journal_projection is not None else None,
        "package_digest": package_digest,
        "package_id": package_id,
        "plan_id": runtime_plan["plan_id"],
        "private_content_read": False,
        "rollback_failure_code": (
            getattr(failure, "rollback_failure_code", None) if failure is not None else None
        ),
        "schema": TERMINAL_RECEIPT_SCHEMA,
        "source_id": SOURCE_ID,
        "status": status,
        "strategy_id": runtime_plan["strategy"]["strategy_id"],
    }
    return {**semantic, "receipt_id": digest("p07_transactional_runtime_terminal_receipt", semantic)}


def execute_activation(
    *,
    runtime_plan: Mapping[str, object],
    mutation_set: Mapping[str, object],
    preflight_one: Mapping[str, object],
    preflight_two: Mapping[str, object],
    after_payloads: Mapping[str, bytes],
    package_id: str,
    package_digest: str,
    owner_uid: int,
    owner_gid: int,
    runner: CommandRunner,
) -> dict[str, object]:
    first = validate_preflight(
        preflight_one,
        runtime_plan,
        package_id=package_id,
        package_digest=package_digest,
    )
    second = validate_preflight(
        preflight_two,
        runtime_plan,
        package_id=package_id,
        package_digest=package_digest,
    )
    first_bytes = canonical(first)
    require(first_bytes == canonical(second), "transactional_runtime_preflight_pair_drifted")
    preflight_sha = sha256(first_bytes).hexdigest()
    state_root = Path(str(runtime_plan["storage"]["state_root"]))
    ledger = verify_ledger_root(
        plan=runtime_plan,
        state_root=state_root,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        package_id=package_id,
        package_digest=package_digest,
        allow_runtime_files=True,
    )
    require(ledger["attempts"] == 0, "transactional_runtime_attempt_exhausted")
    require(
        not Path(str(runtime_plan["storage"]["controller_journal_path"])).exists()
        and not Path(str(runtime_plan["storage"]["controller_journal_path"])).is_symlink(),
        "transactional_runtime_journal_preexisting",
    )
    contract = mutation.validate_mutation_set(mutation_set)
    before_payloads = _payloads_from_contract(contract, side="before")
    _package_operation_entries(
        runtime_plan=runtime_plan,
        mutation_set=contract,
        after_payloads=after_payloads,
    )
    storage = parent.TransactionStorage(
        backup_path=Path(str(runtime_plan["storage"]["backup_path"])),
        staging_path=Path(str(runtime_plan["storage"]["staging_path"])),
        filesystem_journal_path=Path(str(runtime_plan["storage"]["filesystem_journal_path"])),
        controller_journal_path=Path(str(runtime_plan["storage"]["controller_journal_path"])),
    )
    hooks = ContentSafeProductionHooks(
        runtime_plan=runtime_plan,
        mutation_set=contract,
        runner=runner,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        preflight_sha256=preflight_sha,
        package_id=package_id,
        package_digest=package_digest,
    )
    backend = PreparedRuntimeBackend(
        plan=runtime_plan["parent_plan"],
        mutation_set=contract,
        before_payloads=before_payloads,
        after_payloads=dict(after_payloads),
        storage=storage,
        hooks=hooks,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    receipt_path = state_root / f"RECEIPT-{runtime_plan['plan_id']}.json"
    try:
        journal = parent.execute_transaction(
            backend=backend,
            plan=runtime_plan["parent_plan"],
        )
        projection = parent.content_free_projection(journal, runtime_plan["parent_plan"])
        receipt = _terminal_receipt(
            runtime_plan=runtime_plan,
            status="activated",
            journal_projection=projection,
            failure=None,
            package_id=package_id,
            package_digest=package_digest,
        )
        _atomic_write(receipt_path, canonical(receipt), mode=0o600)
        os.chown(receipt_path, owner_uid, owner_gid)
        return receipt
    except Exception as exc:
        journal_projection: dict[str, object] | None = None
        if storage.controller_journal_path.exists():
            journal_projection = parent.content_free_projection(
                parent.load_journal(storage.controller_journal_path, runtime_plan["parent_plan"]),
                runtime_plan["parent_plan"],
            )
        rollback_failed = getattr(exc, "rollback_failure_code", None) is not None
        pre_attempt_failed = (
            getattr(exc, "code", None) == "transaction_pre_attempt_failed"
            or (
                journal_projection is not None
                and journal_projection.get("recovery_class") == "pre_attempt"
                and journal_projection.get("attempts") == 0
            )
        )
        status = (
            "rollback_failed"
            if rollback_failed
            else "pre_attempt_failed"
            if pre_attempt_failed
            else "failed_rollback_verified"
        )
        receipt = _terminal_receipt(
            runtime_plan=runtime_plan,
            status=status,
            journal_projection=journal_projection,
            failure=exc,
            package_id=package_id,
            package_digest=package_digest,
        )
        _atomic_write(receipt_path, canonical(receipt), mode=0o600)
        os.chown(receipt_path, owner_uid, owner_gid)
        raise TransactionalRuntimeRejected(
            "transactional_runtime_rollback_failed"
            if rollback_failed
            else "transactional_runtime_pre_attempt_failed"
            if pre_attempt_failed
            else "transactional_runtime_activation_failed_rollback_verified",
            activation_failure_code=_typed_error(exc, "transactional_runtime_activation_failed"),
            rollback_failure_code=getattr(exc, "rollback_failure_code", None),
        ) from exc


def postflight(
    *,
    runtime_plan: Mapping[str, object],
    state_root: Path,
    owner_uid: int,
    owner_gid: int,
    package_id: str,
    package_digest: str,
    runner: CommandRunner,
) -> dict[str, object]:
    ledger = verify_ledger_root(
        plan=runtime_plan,
        state_root=state_root,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        package_id=package_id,
        package_digest=package_digest,
        allow_runtime_files=True,
    )
    require(ledger["attempts"] == 1, "transactional_runtime_postflight_attempt_rejected")
    receipt_path = state_root / f"RECEIPT-{runtime_plan['plan_id']}.json"
    receipt = _canonical_read(receipt_path, "transactional_runtime_receipt_rejected")
    require(
        receipt.get("schema") == TERMINAL_RECEIPT_SCHEMA
        and receipt.get("source_id") == SOURCE_ID
        and receipt.get("strategy_id")
        == runtime_plan["strategy"]["strategy_id"]
        and receipt.get("plan_id") == runtime_plan["plan_id"]
        and receipt.get("package_id") == package_id
        and receipt.get("package_digest") == package_digest,
        "transactional_runtime_receipt_rejected",
    )
    status = receipt.get("status")
    expected = (
        runtime_plan["services"]["target"]
        if status == "activated"
        else runtime_plan["services"]["prestate"]
    )
    services = observe_services(runner)
    require(services == expected, "transactional_runtime_postflight_service_drifted")
    return {
        "attempts": 1,
        "content_retained": False,
        "maximum_attempts": 1,
        "package_digest": package_digest,
        "package_id": package_id,
        "plan_id": runtime_plan["plan_id"],
        "private_content_read": False,
        "receipt_id": receipt["receipt_id"],
        "schema": TERMINAL_RECEIPT_SCHEMA,
        "service_projection_digest": digest("p07_transactional_runtime_services", services),
        "status": status,
    }


_CONTEXT_FIELDS = {
    "expected_runtime_bundle_id",
    "expected_runtime_manifest_sha256",
    "failed_request_continuation",
    "lineages",
    "mutation_set",
    "parent_namespace",
    "runtime_manifest",
    "runtime_manifest_sha256",
    "runtime_plan",
}


def _request_fields(
    request: Mapping[str, object], *, mode: str, fields: set[str]
) -> dict[str, object]:
    selected = dict(request)
    require(
        mode in _MODES
        and selected.get("schema") == REQUEST_SCHEMA
        and selected.get("mode") == mode
        and set(selected) == {"schema", "mode", *fields},
        "transactional_runtime_request_rejected",
    )
    return selected


def _owner_ids(request: Mapping[str, object]) -> tuple[int, int]:
    owner_uid = request.get("owner_uid")
    owner_gid = request.get("owner_gid")
    require(
        type(owner_uid) is int
        and int(owner_uid) >= 0
        and type(owner_gid) is int
        and int(owner_gid) >= 0,
        "transactional_runtime_owner_identity_rejected",
    )
    return int(owner_uid), int(owner_gid)


def _validated_request_context(
    request: Mapping[str, object],
    *,
    continuation_reference: Mapping[str, object] | None = None,
) -> dict[str, object]:
    require(
        isinstance(request.get("runtime_plan"), Mapping)
        and isinstance(request.get("mutation_set"), Mapping)
        and isinstance(request.get("lineages"), Mapping)
        and (
            isinstance(request.get("failed_request_continuation"), Mapping)
            if continuation_reference is None
            else request.get("failed_request_continuation") == {}
        )
        and isinstance(request.get("parent_namespace"), Mapping)
        and isinstance(request.get("runtime_manifest"), Mapping),
        "transactional_runtime_request_rejected",
    )
    manifest_sha = _require_sha(
        request.get("runtime_manifest_sha256"), "transactional_runtime_manifest_rejected"
    )
    expected_bundle = _require_sha(
        request.get("expected_runtime_bundle_id"), "transactional_runtime_manifest_rejected"
    )
    expected_manifest = _require_sha(
        request.get("expected_runtime_manifest_sha256"),
        "transactional_runtime_manifest_rejected",
    )
    require(
        dict(request["parent_namespace"]) == observe_parent_failed_start_namespace(),
        "transactional_runtime_parent_namespace_drifted",
    )
    contract = mutation.validate_mutation_set(request["mutation_set"])
    plan = validate_runtime_plan(
        request["runtime_plan"],
        mutation_set=contract,
        lineages=request["lineages"],
        parent_namespace=request["parent_namespace"],
        runtime_namespace=absent_runtime_namespace(),
        runtime_manifest=request["runtime_manifest"],
        runtime_manifest_sha256=manifest_sha,
        expected_runtime_bundle_id=expected_bundle,
        expected_runtime_manifest_sha256=expected_manifest,
        continuation_reference=continuation_reference,
    )
    return {
        "expected_runtime_bundle_id": expected_bundle,
        "expected_runtime_manifest_sha256": expected_manifest,
        "failed_request_continuation": request["failed_request_continuation"],
        "lineages": request["lineages"],
        "mutation_set": contract,
        "parent_namespace": request["parent_namespace"],
        "runtime_manifest": request["runtime_manifest"],
        "runtime_manifest_sha256": manifest_sha,
        "runtime_plan": plan,
    }


def _prepare_package_from_target_material(
    *,
    target: Mapping[str, object],
    failed_request_continuation: Mapping[str, object] | None = None,
    immutable_continuation_reference: Mapping[str, object] | None = None,
    fresh_strategy: Mapping[str, object] | None = None,
    production_observer: production.ProtectedObserver,
    package_root: Path,
) -> dict[str, object]:
    selected = dict(target)
    require(
        set(selected)
        == {
            "core_candidate",
            "lineages",
            "manifest",
            "manifest_sha256",
            "owner_gid",
            "owner_uid",
            "plugin_candidate",
            "runtime_candidate",
        }
        and isinstance(selected["lineages"], Mapping)
        and isinstance(selected["manifest"], Mapping),
        "transactional_runtime_source_owned_target_rejected",
    )
    manifest = dict(selected["manifest"])
    manifest_sha = _require_sha(
        selected["manifest_sha256"], "transactional_runtime_manifest_rejected"
    )
    expected_bundle = _require_sha(
        manifest.get("bundle_id"), "transactional_runtime_manifest_rejected"
    )
    validate_runtime_artifact_manifest(
        manifest,
        manifest_sha256=manifest_sha,
        expected_bundle_id=expected_bundle,
        expected_manifest_sha256=manifest_sha,
    )
    if fresh_strategy is None:
        require(
            isinstance(failed_request_continuation, Mapping)
            and immutable_continuation_reference is None,
            "transactional_runtime_failed_request_continuation_required",
        )
        continuation = _validate_failed_request_continuation_payload(
            failed_request_continuation,
            runtime_manifest=manifest,
            runtime_manifest_sha256=manifest_sha,
            lineages=selected["lineages"],
        )
        reference = None
    else:
        require(
            failed_request_continuation is None
            and isinstance(immutable_continuation_reference, Mapping),
            "transactional_runtime_immutable_continuation_reference_rejected",
        )
        reference = _validate_immutable_continuation_reference_contract(
            immutable_continuation_reference, require_production_exact=True
        )
        validate_fresh_strategy_contract(
            fresh_strategy,
            runtime_manifest=manifest,
            runtime_manifest_sha256=manifest_sha,
            lineages=selected["lineages"],
            continuation_reference=reference,
        )
        continuation = None
    owner_uid, owner_gid = _owner_ids(
        {"owner_uid": selected["owner_uid"], "owner_gid": selected["owner_gid"]}
    )
    candidate_paths = {
        field: Path(selected[field])
        for field in ("core_candidate", "runtime_candidate", "plugin_candidate")
    }
    require(
        all(path.is_absolute() for path in candidate_paths.values()),
        "transactional_runtime_artifact_path_rejected",
    )
    material = construct_production_runtime_material(
        observer=production_observer,
        core_candidate=candidate_paths["core_candidate"],
        runtime_candidate=candidate_paths["runtime_candidate"],
        plugin_candidate=candidate_paths["plugin_candidate"],
        lineages=selected["lineages"],
        runtime_manifest=manifest,
        runtime_manifest_sha256=manifest_sha,
        expected_runtime_bundle_id=expected_bundle,
        expected_runtime_manifest_sha256=manifest_sha,
        fresh_strategy=fresh_strategy,
        continuation_reference=reference,
    )
    context = _package_context(
        material=material,
        lineages=selected["lineages"],
        parent_namespace=observe_parent_failed_start_namespace(),
        runtime_manifest=manifest,
        runtime_manifest_sha256=manifest_sha,
        expected_runtime_bundle_id=expected_bundle,
        expected_runtime_manifest_sha256=manifest_sha,
        failed_request_continuation=continuation,
        immutable_continuation_reference=reference,
        fresh_strategy=fresh_strategy,
    )
    return materialize_after_payload_package(
        context=context,
        after_payloads=material.after_payloads,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        package_root=package_root,
    )


def prepare_package_from_failed_request_continuation() -> dict[str, object]:
    """Build a fresh package from current source and immutable rejected-request evidence.

    The terminal request is verified but never dispatched.  The only live protocol
    reachable from this mode is the fresh P08 content-free status gate inside the
    reviewed production observer.
    """

    verified = verify_source_owned_failed_request_continuation()
    target = _source_owned_target_material(
        core_source=SOURCE_OWNED_CORE_ROOT,
        deploy_source=SOURCE_OWNED_DEPLOY_ROOT,
        runtime_build_root=SOURCE_OWNED_RUNTIME_ARTIFACT_ROOT,
        bundle_root=SOURCE_OWNED_TRANSACTIONAL_BUNDLE_ROOT,
        evidence_root=SOURCE_OWNED_EVIDENCE_ROOT,
        owner_account=SOURCE_OWNED_OWNER_ACCOUNT,
    )
    return _prepare_package_from_target_material(
        target=target,
        failed_request_continuation=verified["continuation"],
        production_observer=production.SystemProtectedObserver(),
        package_root=PACKAGE_ROOT,
    )


def prepare_package_from_immutable_continuation_reference() -> dict[str, object]:
    """Start one fresh strategy without replaying or relabelling old evidence."""

    verified_reference = verify_source_owned_immutable_continuation_reference()
    reference = immutable_continuation_reference_contract()
    require(
        verified_reference["reference_digest"] == reference["reference_digest"]
        and verified_reference["reinterpreted_as_ready"] is False,
        "transactional_runtime_immutable_continuation_reference_rejected",
    )
    target = _source_owned_target_material(
        core_source=SOURCE_OWNED_CORE_ROOT,
        deploy_source=SOURCE_OWNED_DEPLOY_ROOT,
        runtime_build_root=SOURCE_OWNED_RUNTIME_ARTIFACT_ROOT,
        bundle_root=SOURCE_OWNED_TRANSACTIONAL_BUNDLE_ROOT,
        evidence_root=SOURCE_OWNED_EVIDENCE_ROOT,
        owner_account=SOURCE_OWNED_OWNER_ACCOUNT,
    )
    strategy = build_fresh_strategy_contract(
        runtime_manifest=target["manifest"],
        runtime_manifest_sha256=str(target["manifest_sha256"]),
        lineages=target["lineages"],
        continuation_reference=reference,
    )
    rejection_context = _verified_fresh_rejection_strategy_context(
        strategy,
        runtime_manifest=target["manifest"],
        runtime_manifest_sha256=str(target["manifest_sha256"]),
        lineages=target["lineages"],
        continuation_reference=reference,
    )
    observe_fresh_strategy_namespace(strategy)
    observer = SourceOwnedStatusEvidenceObserver(
        strategy=strategy,
        rejection_context=rejection_context,
        trusted_ancestor=FRESH_STATUS_TRUSTED_ANCESTOR,
        status_parent=FRESH_STATUS_PARENT,
        owner_uid=0,
        owner_gid=0,
    )
    return _call_with_rejection_strategy_context(
        rejection_context,
        lambda: _prepare_package_from_target_material(
            target=target,
            immutable_continuation_reference=reference,
            fresh_strategy=strategy,
            production_observer=observer,
            package_root=Path(str(strategy["storage"]["package_root"])),
        ),
    )


def dispatch_request(
    *,
    mode: str,
    request: Mapping[str, object],
    runner: CommandRunner | None = None,
    production_observer: production.ProtectedObserver | None = None,
    package_root: Path | None = None,
    failed_request_continuation: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Dispatch one canonical reviewed request through the source-bound adapter."""

    direct_cli_execution = production_observer is None and package_root is None
    if mode == "prepare-package" and direct_cli_execution:
        raise TransactionalRuntimeRejected(
            "transactional_runtime_terminal_request_replay_rejected"
        )
    production_execution = (
        production_observer is None
        and package_root is None
        and PACKAGE_ROOT == SOURCE_DECLARED_LEGACY_PACKAGE_ROOT
    )
    production_strategy: Mapping[str, object] | None = None
    if production_execution:
        target = _source_owned_target_material(
            core_source=SOURCE_OWNED_CORE_ROOT,
            deploy_source=SOURCE_OWNED_DEPLOY_ROOT,
            runtime_build_root=SOURCE_OWNED_RUNTIME_ARTIFACT_ROOT,
            bundle_root=SOURCE_OWNED_TRANSACTIONAL_BUNDLE_ROOT,
            evidence_root=SOURCE_OWNED_EVIDENCE_ROOT,
            owner_account=SOURCE_OWNED_OWNER_ACCOUNT,
        )
        production_strategy = build_fresh_strategy_contract(
            runtime_manifest=target["manifest"],
            runtime_manifest_sha256=str(target["manifest_sha256"]),
            lineages=target["lineages"],
            continuation_reference=immutable_continuation_reference_contract(),
        )
        package_root = Path(str(production_strategy["storage"]["package_root"]))
    else:
        package_root = PACKAGE_ROOT if package_root is None else package_root
    require(mode != "offline-self-test", "transactional_runtime_mode_rejected")
    selected_runner = runner if runner is not None else SubprocessCommandRunner()
    if mode == "prepare-package":
        require(not production_execution, "transactional_runtime_terminal_request_replay_rejected")
        selected = _request_fields(
            request,
            mode=mode,
            fields={
                "core_candidate",
                "expected_runtime_bundle_id",
                "expected_runtime_manifest_sha256",
                "lineages",
                "owner_gid",
                "owner_uid",
                "plugin_candidate",
                "runtime_candidate",
                "runtime_manifest",
                "runtime_manifest_sha256",
            },
        )
        for field in ("lineages", "runtime_manifest"):
            require(isinstance(selected[field], Mapping), "transactional_runtime_request_rejected")
        require(
            isinstance(failed_request_continuation, Mapping),
            "transactional_runtime_failed_request_continuation_required",
        )
        owner_uid, owner_gid = _owner_ids(selected)
        manifest_sha = _require_sha(
            selected["runtime_manifest_sha256"], "transactional_runtime_manifest_rejected"
        )
        expected_bundle = _require_sha(
            selected["expected_runtime_bundle_id"], "transactional_runtime_manifest_rejected"
        )
        expected_manifest = _require_sha(
            selected["expected_runtime_manifest_sha256"],
            "transactional_runtime_manifest_rejected",
        )
        require(
            expected_bundle == selected["runtime_manifest"].get("bundle_id")
            and expected_manifest == manifest_sha,
            "transactional_runtime_manifest_rejected",
        )
        return _prepare_package_from_target_material(
            target={
                "core_candidate": Path(str(selected["core_candidate"])),
                "lineages": selected["lineages"],
                "manifest": selected["runtime_manifest"],
                "manifest_sha256": manifest_sha,
                "owner_gid": owner_gid,
                "owner_uid": owner_uid,
                "plugin_candidate": Path(str(selected["plugin_candidate"])),
                "runtime_candidate": Path(str(selected["runtime_candidate"])),
            },
            failed_request_continuation=failed_request_continuation,
            production_observer=(
                production_observer
                if production_observer is not None
                else production.SystemProtectedObserver()
            ),
            package_root=package_root,
        )

    extra_fields: set[str]
    if mode in {"backup-contract", "ledger-create", "preflight-only", "postflight"}:
        extra_fields = {"owner_gid", "owner_uid", "package_digest", "package_id"}
    elif mode == "activate":
        extra_fields = {
            "owner_gid",
            "owner_uid",
            "package_digest",
            "package_id",
            "preflight_one",
            "preflight_two",
        }
    else:
        raise TransactionalRuntimeRejected("transactional_runtime_mode_rejected")
    selected = _request_fields(request, mode=mode, fields=extra_fields)
    owner_uid, owner_gid = _owner_ids(selected)
    package = verify_after_payload_package(
        package_id=_require_sha(
            selected["package_id"], "transactional_runtime_package_identity_rejected"
        ),
        package_digest=_require_sha(
            selected["package_digest"], "transactional_runtime_package_identity_rejected"
        ),
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        package_root=package_root,
    )
    context = _validated_package_context(package.context)
    rejection_context = _rejection_strategy_context_from_package_context(context)
    if production_execution:
        _require_with_rejection_strategy_context(
            production_strategy is not None
            and context.get("strategy") == production_strategy
            and context.get("immutable_continuation_reference")
            == immutable_continuation_reference_contract(),
            "transactional_runtime_fresh_strategy_rejected",
            rejection_context,
        )
        source_owned_reference = _call_with_rejection_strategy_context(
            rejection_context,
            verify_source_owned_immutable_continuation_reference,
        )
        _require_with_rejection_strategy_context(
            source_owned_reference["reference_digest"]
            == context["immutable_continuation_reference"]["reference_digest"],
            "transactional_runtime_immutable_continuation_reference_rejected",
            rejection_context,
        )
        status_evidence = _call_with_rejection_strategy_context(
            rejection_context,
            lambda: _verify_status_invocation_evidence(
                strategy=production_strategy,
                status_parent=FRESH_STATUS_PARENT,
                status_root=Path(
                    str(production_strategy["storage"]["status_invocation_root"])
                ),
                owner_uid=0,
                owner_gid=0,
            ),
        )
        _require_with_rejection_strategy_context(
            status_evidence == context["runtime_plan"]["status_invocation"]
            and status_evidence["status"] == "accepted",
            "transactional_runtime_status_invocation_evidence_rejected",
            rejection_context,
        )
    plan = package.runtime_plan
    contract = package.mutation_set

    if mode == "backup-contract":
        backup_path = Path(str(plan["storage"]["backup_path"]))
        state_root = Path(str(plan["storage"]["state_root"]))
        _require_with_rejection_strategy_context(
            not backup_path.exists()
            and not backup_path.is_symlink()
            and not state_root.exists()
            and not state_root.is_symlink(),
            "transactional_runtime_backup_or_state_preexisting",
            rejection_context,
        )
        before_payloads = _payloads_from_contract(contract, side="before")
        backup_manifest = _call_with_rejection_strategy_context(
            rejection_context,
            lambda: parent.create_plan_bound_backup(
                plan=plan["parent_plan"],
                mutation_set=contract,
                backup_path=backup_path,
                before_payloads=before_payloads,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            ),
        )
        return {
            "backup_manifest_sha256": sha256(canonical(backup_manifest)).hexdigest(),
            "flags": dict(_ZERO_FLAGS),
            "package_digest": package.package_digest,
            "package_id": package.package_id,
            "plan_id": plan["plan_id"],
            "schema": "myuna.p07-owner-private-memory-transactional-runtime-backup-receipt.v1",
            "source_id": SOURCE_ID,
            "status": "created",
            "strategy_id": plan["strategy"]["strategy_id"],
        }
    if mode == "ledger-create":
        _call_with_rejection_strategy_context(
            rejection_context,
            lambda: parent.verify_plan_bound_backup(
                plan=plan["parent_plan"],
                mutation_set=contract,
                backup_path=Path(str(plan["storage"]["backup_path"])),
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            ),
        )
        return _call_with_rejection_strategy_context(
            rejection_context,
            lambda: create_ledger(
                plan=plan,
                state_root=Path(str(plan["storage"]["state_root"])),
                owner_uid=owner_uid,
                owner_gid=owner_gid,
                package_id=package.package_id,
                package_digest=package.package_digest,
            ),
        )
    if mode == "preflight-only":
        return _call_with_rejection_strategy_context(
            rejection_context,
            lambda: formal_preflight(
                runtime_plan=plan,
                mutation_set=contract,
                lineages=context["lineages"],
                parent_namespace=context["parent_namespace"],
                runtime_manifest=context["runtime_manifest"],
                runtime_manifest_sha256=context["runtime_manifest_sha256"],
                expected_runtime_bundle_id=context["expected_runtime_bundle_id"],
                expected_runtime_manifest_sha256=context[
                    "expected_runtime_manifest_sha256"
                ],
                owner_uid=owner_uid,
                owner_gid=owner_gid,
                package_id=package.package_id,
                package_digest=package.package_digest,
                runner=selected_runner,
                continuation_reference=context.get(
                    "immutable_continuation_reference"
                ),
            ),
        )
    if mode == "activate":
        _require_with_rejection_strategy_context(
            isinstance(selected["preflight_one"], Mapping)
            and isinstance(selected["preflight_two"], Mapping),
            "transactional_runtime_request_rejected",
            rejection_context,
        )
        return _call_with_rejection_strategy_context(
            rejection_context,
            lambda: execute_activation(
                runtime_plan=plan,
                mutation_set=contract,
                preflight_one=selected["preflight_one"],
                preflight_two=selected["preflight_two"],
                after_payloads=package.after_payloads,
                package_id=package.package_id,
                package_digest=package.package_digest,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
                runner=selected_runner,
            ),
        )
    return _call_with_rejection_strategy_context(
        rejection_context,
        lambda: postflight(
            runtime_plan=plan,
            state_root=Path(str(plan["storage"]["state_root"])),
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            package_id=package.package_id,
            package_digest=package.package_digest,
            runner=selected_runner,
        ),
    )


def capability_projection() -> dict[str, object]:
    return {
        "after_payload_package_source_present": True,
        "allowed_modes": sorted(_MODES),
        "context_bound_rejection_envelope_source_present": True,
        "p08_server_rejection_subprojection_source_present": True,
        "failed_request_continuation_materialized": False,
        "failed_request_continuation_source_id": FAILED_REQUEST_CONTINUATION_SOURCE_ID,
        "failed_request_continuation_source_present": True,
        "fresh_strategy_source_id": FRESH_STRATEGY_SOURCE_ID,
        "immutable_continuation_reference_source_id": (
            IMMUTABLE_CONTINUATION_REFERENCE_SOURCE_ID
        ),
        "immutable_continuation_reference_source_present": True,
        "live_controller_source_present": True,
        "legacy_strategy_id_read_only": STRATEGY_ID,
        "maximum_attempts": 1,
        "package_root_identity_digest": digest(
            "p07_transactional_runtime_package_root", PACKAGE_ROOT.as_posix()
        ),
        "package_schema": PACKAGE_SCHEMA,
        "parent_controller_source_id": parent.SOURCE_ID,
        "runtime_source_id": SOURCE_ID,
        "source_owned_artifact_roots": source_owned_artifact_root_contract(),
        "selected": False,
        "source_owned_request_collection_present": True,
        "source_owned_request_collection_closed": True,
        "source_owned_request_collection_maximum_count": MAX_SOURCE_OWNED_REQUEST_COUNT,
        "source_owned_request_collection_source_id": REQUEST_COLLECTION_SOURCE_ID,
        "source_owned_request_constructor_present": True,
        "source_owned_request_constructor_source_id": REQUEST_CONSTRUCTOR_SOURCE_ID,
        "status_invocation_evidence_source_id": STATUS_INVOCATION_SOURCE_ID,
        "status_invocation_evidence_source_present": True,
        "state_created": False,
        "fresh_strategy_identity_derived_at_runtime": True,
        "source_derived_fresh_max1_strategy_present": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=sorted(_MODES), required=True)
    parser.add_argument("--request", type=Path)
    values = parser.parse_args()
    if values.mode == "offline-self-test":
        if values.request is None:
            print(json.dumps(capability_projection(), ensure_ascii=True, sort_keys=True))
            return 0
        rejection = TransactionalRuntimeRejected("transactional_runtime_request_rejected")
    elif values.mode in {
        "construct-request",
        "construct-continuation",
        "prepare-continuation",
    }:
        if values.request is None:
            rejection = None
        else:
            rejection = TransactionalRuntimeRejected(
                "transactional_runtime_request_rejected"
            )
    else:
        rejection = None
    try:
        if rejection is not None:
            raise rejection
        if values.mode == "construct-request":
            result = materialize_source_owned_request()
        elif values.mode == "construct-continuation":
            raise TransactionalRuntimeRejected(
                "transactional_runtime_immutable_continuation_rematerialization_rejected"
            )
        elif values.mode == "prepare-continuation":
            result = prepare_package_from_immutable_continuation_reference()
        else:
            require(values.request is not None, "transactional_runtime_request_rejected")
            request = _canonical_read(values.request, "transactional_runtime_request_rejected")
            result = dispatch_request(mode=values.mode, request=request)
    except (
        TransactionalRuntimeRejected,
        parent.TransactionalControllerRejected,
        mutation.MutationSetRejected,
        production.ProductionPlanRejected,
    ) as exc:
        rejection = _runtime_rejection_projection(exc)
        print(canonical(rejection).decode("ascii"))
        return 2
    print(canonical(result).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
