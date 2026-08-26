#!/usr/bin/env python3
"""Finite source-owned plan for the supervised Phase-F product activation.

The module describes one product and one sequence. It has no caller supplied
program, graph, driver registry, capability negotiation, sidecar state, or recovery
authority. The controller builder supplies a sealed authority body; the
activation owner supplies fresh resource observations.
"""

from __future__ import annotations

import base64
from hashlib import sha256
import json
import re
from typing import Mapping


SOURCE_SCHEMA = "myuna.phase-f.fixed-product-source-authority.v1"
OBSERVATION_SCHEMA = "myuna.phase-f.fixed-product-observation.v1"
PLAN_SCHEMA = "myuna.phase-f.fixed-product-plan.v1"
RESULT_SCHEMA = "myuna.phase-f.fixed-product-result.v1"
ACCEPTED_DEPLOY_PARENT = "5f6e32c4abc0f7e23c29cdda94cb675ebf0d077b"
ACCEPTED_CORE_COMMIT = "4c13c0b20552b5d8a8720f180d0569405fed00b0"
ACCEPTED_CORE_TREE = "e43ae07babf5a448525d1035d400a37fde374a2b"
HYBRID_BUILDER_BLOB = "2c92a5f7d995fd08ed658d4cc905a6db6dd2ac65"
GATEWAY_BUILDER_BLOB = "d024c94b61b0eee820568073e578f04c57099cf2"
ACCEPTED_ASTRBOT_COMMIT = "2d617544d883ea6c31ec40fcce59d4cfaa904dd1"
ACCEPTED_RUNTIME_BASE = (
    "6b10fc936994eaeb97fae4d4f96375c93ddcf9a505140cbaac6d9ef304b4b7af"
)
R5_DURABILITY_BASELINE_CONTROLLER_RELEASE = (
    "7ebc81cf25d047c49f4555c85e1e6b90db66cfef8c25e47904b56ec2146bd4fc"
)
R5_DURABILITY_BASELINE_DEPLOY_COMMIT = (
    "3a538c218bd784d7f099244c7ef9cfac73add50a"
)
R5_DURABILITY_BASELINE_DEPLOY_PARENT = (
    "34efdf57bd9ee8a090bc40ebe10c90f5da534e42"
)
R5_DURABILITY_BASELINE_DEPLOY_TREE = (
    "dbf5e47ce8d853088c1dcec233b34ac6195f528e"
)
R5_DURABILITY_BASELINE_CORE_COMMIT = (
    "0d6885192307a75f6948e0085c3ca2c3c9f66676"
)
R5_DURABILITY_BASELINE_CORE_TREE = (
    "ff324d1f3b1822e9f4c18c6ee89e57451d03bc02"
)
R5_DURABILITY_BASELINE_CONFIG_SHA256 = (
    "0710c79b11aa9bcdccb6c73c83b60ac05626d16e33344ce17225136d0fed281c"
)
R5_DURABILITY_BASELINE_UNIT_SHA256 = (
    "0cd6edb71096a7e9ceccc996e912e5d0836c871053e88f47e9611e918351ed76"
)
R5_DURABILITY_BASELINE_PLUGIN_RELEASE = (
    "e62918292dba1ae2304396871a8070c4640091bfdf42a81327a550999e755c35"
)
R5_DURABILITY_TARGET_PLUGIN_RELEASE = (
    "a85c745dd40b4c29e8e49072475fdbed6454bbacbbe5d373cf6144b265aff4af"
)
R5_DURABILITY_TARGET_CONFIG_SHA256 = (
    "c1a20bd08ce3c56e1d273bed0e176c2f6a980d3c5373592c83a03db4d6412c63"
)
TRANSITIONAL_LINEAGE_LOWER = "d445af03f668370b47a4672cdc9a7119d9cfc7d6"
TRANSITIONAL_LINEAGE_UPPER = "34efdf57bd9ee8a090bc40ebe10c90f5da534e42"
ARCHIVE_CHILD_CREATOR_LINEAGE_UPPER = (
    "e93f926929c6ddc3d3d333f03ec6564dda31e12f"
)
TRANSITIONAL_INSTALL_ATTEMPT = 5
TRANSITIONAL_ATTEMPT_UNCONSUMED = False
TRANSITIONAL_WRITER_BOUNDARY = False
TRANSITIONAL_STAGE_ENTRY = "ARCHIVE_CHILD_NAME_CONVERGENCE_REQUIRED"
ATTEMPT5_PRODUCT_CONTROLLER_RELEASE = (
    "b78ef052c838dc896f98cb9ef8d2a0c96ae55b2d1146ede39d8e8753a976aa69"
)
ATTEMPT5_PRODUCT_DEPLOY_COMMIT = "a4a16a4f14ec3c762427a7b21de97f5af9910464"
ATTEMPT5_PRODUCT_DEPLOY_PARENT = "7341d9b60b4bf445bec56842df326edfd670e50d"
ATTEMPT5_PRODUCT_AUTHORITY_SHA256 = (
    "34a0e759e6fc7729e36d3355a2f617a06ac0bebee36bc445740db652c4dc23b0"
)
ATTEMPT5_PRODUCT_ENTRY_PLAN_SHA256 = (
    "bed60d0c4f567e389d0c5aa54b0300944f668c577b70d07ad268c9cec653d21a"
)
ATTEMPT5_OLD_CONTAINER_ID = (
    "42cca5e1e6c77aa3b1af30e326c8ef21875aa47a1ffca02ee68d718325dc1a82"
)
ATTEMPT5_OLD_CONTAINER_CONFIGURATION_SHA256 = (
    "2a42cb477ae4608f56ab353a6f8bbec6eca7cb0f5fccc0d3d5f0ecd7ebdf598d"
)
ATTEMPT5_OLD_CONTAINER_NETWORKS_SHA256 = (
    "c9d6252c391e4938725803f391425aaeebaf0fa8bbabc60c341f1231219e88a5"
)
TARGET_CHANNEL_ROOT = "/srv/myuna/channels/astrbot-telegram/dev"
TARGET_SIGNING_SECRET = (
    "/run/myuna-telegram-gateway/container-channel-signing-v1"
)
TARGET_RUNTIME_ROOT = "/run/myuna-telegram-gateway"
TARGET_MEDIA_AUTH_RUNTIME_ROOT = "/run/myuna-telegram-media-auth"
TARGET_COMPOSE_PROJECT = "myuna-telegram-r5-v1"
TARGET_COMPOSE_SERVICE = "astrbot-telegram"
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
PARENT_EPOCH_REVISION = 1
P08_LIFECYCLE_START_WATERMARK = 1
TARGET_IMAGE_PREFIX = "myuna/astrbot-phase-f-deterministic@sha256:"
CORE_RELEASE_ROOT = "/srv/myuna/releases/core"
RUNTIME_RELEASE_ROOT = "/opt/myuna/context24-gateway/telegram/releases"
PLUGIN_RELEASE_ROOT = "/opt/myuna/telegram-gateway/releases"
R5_CONFIG_PATH = "/etc/myuna-telegram-gateway/r5-resume-v1.json"
NETWORK_NAME = "myuna-astrbot-telegram-dev"
CONTAINER_NAME = "myuna-astrbot-telegram-dev"
ARCHIVE_PREFIX = CONTAINER_NAME + ".pre-"
MEMORY_RUNTIME_ROOT = "/var/lib/myuna-telegram-gateway/owner-private-memory-v1"
MEMORY_SELECTOR_PATH = (
    "/etc/myuna-telegram-gateway/p07-owner-private-memory-selector-v4.json"
)
MEMORY_RUNTIME_UID = 988
MEMORY_RUNTIME_GID = 982
TARGET_USER = f"{MEMORY_RUNTIME_UID}:{MEMORY_RUNTIME_GID}"
LEGACY_MEMORY_ARCHIVE_ID = "p07-owner-private-memory-v1-4cfdb84d81bb7c81"
LEGACY_MEMORY_ROOT_EVIDENCE_SHA256 = (
    "3dcd1d04b9e5955868508bc0a4c6de820f40007144c29f434ae96bc6e7aced52"
)
STABLE_ARCHIVE_CHILD_SCHEMA = "myuna.phase-f.stable-attempt-archive-child.v1"
STABLE_ARCHIVE_CHILD_CAPABILITY = "phase-f.fixed-product-supervised-activation"
STABLE_ARCHIVE_CHILD_ATTEMPT_ROOT = "phase-f-checkpointed-prefix-stagewise"
STABLE_ARCHIVE_CHILD_OLD_CONTAINER_ID = (
    "42cca5e1e6c77aa3b1af30e326c8ef21875aa47a1ffca02ee68d718325dc1a82"
)
ATTEMPT5_ARCHIVE_PARENT_IDENTITY = (
    "07e0d404d4816d7cce9f03bd4dd0dfd0674f5d3ea38d5a2d81d10995f9855e10"
)
ATTEMPT5_PRIOR_ARCHIVE_CHILD_IDENTITY = (
    "f1c6601a60a233ff9b498bf4b8f062ec89b776e390a8671a011f3ef13306f307"
)
ATTEMPT5_PRIOR_ARCHIVE_CHILD_NAME_SHA256 = (
    "5b2184347b78916b87b4e171bc651d47210ff1eba5ef5117e2ff0800520f395a"
)
_SELECTED_ROOT_PHASE_SCHEMA = (
    "myuna.phase-f.post-writer-selected-root-authority.v1"
)
_SELECTED_ROOT_PHASE_DOMAIN = "phase-f.fixed-product-supervised-activation"
_SELECTED_ROOT_PHASE = "POST_WRITER"
_SELECTED_ROOT_PHASE_VERSION = 1
_SELECTED_ROOT_NETWORK_PROJECTION_SHA256 = (
    "56605a22077783c6c780cb701b119b8a3375ac3804ba8d67da17b88087ef6eab"
)
_SELECTED_ROOT_PHASE_AUTHORITY_SHA256 = (
    "58d16ade22d99f18ca23541e8101f0e6dfe488404b7a20e014f4e6dab30ccbb0"
)
ATTEMPT5_PRIOR_CONTROLLER_RELEASE = (
    "24064115ccdd0ca83c2dd94a49349bfbb7f706cbbdfd609cb00212aba0caf564"
)

FILE_ROLES = {
    "/etc/myuna/core-release-selector/qq.binding.json": (
        "core_binding_selector",
        "0640",
    ),
    "/etc/systemd/system/myuna-core@qq.service.d/10-core-release-selector-v1.conf": (
        "core_release_selector_dropin",
        "0644",
    ),
    "/etc/systemd/system/myuna-core@qq.service.d/zzzzzzzzz-p07-hybrid-external-v1.conf": (
        "core_provider_gate_dropin",
        "0644",
    ),
    "/etc/systemd/system/myuna-core@qq.service.d/90-p07-owner-private-memory-v1.conf": (
        "core_memory_dropin",
        "0644",
    ),
    "/etc/myuna-telegram-gateway/r5-resume-v1.json": (
        "telegram_runtime_config",
        "0600",
    ),
    "/etc/systemd/system/myuna-telegram-owner-runtime-dev.service.d/zzzzzzzzzzz-p07-hybrid-external-v1.conf": (
        "telegram_runtime_dropin",
        "0644",
    ),
    "/etc/myuna-telegram-gateway/p07-owner-private-memory-selector-v4.json": (
        "memory_selector_v4",
        "0640",
    ),
}

FILE_OWNERS = {
    "/etc/myuna/core-release-selector/qq.binding.json": "root:myuna",
    "/etc/systemd/system/myuna-core@qq.service.d/10-core-release-selector-v1.conf": "root:root",
    "/etc/systemd/system/myuna-core@qq.service.d/zzzzzzzzz-p07-hybrid-external-v1.conf": "root:root",
    "/etc/systemd/system/myuna-core@qq.service.d/90-p07-owner-private-memory-v1.conf": "root:root",
    "/etc/myuna-telegram-gateway/r5-resume-v1.json": "root:root",
    "/etc/systemd/system/myuna-telegram-owner-runtime-dev.service.d/zzzzzzzzzzz-p07-hybrid-external-v1.conf": "root:root",
    "/etc/myuna-telegram-gateway/p07-owner-private-memory-selector-v4.json": (
        "root:myuna-gateway-telegram"
    ),
}

OLD_FILE_SHA256 = {
    "/etc/myuna/core-release-selector/qq.binding.json":
        "98a09f009f63c090031fb8523e1f8e81591fff87af7345e93c7e734b652e2fc6",
    "/etc/systemd/system/myuna-core@qq.service.d/10-core-release-selector-v1.conf":
        "9bff42fa1cc0e20f367bae215f74dad80130ec3f2d923c8b50d6bf8bbe50c1b4",
    "/etc/systemd/system/myuna-core@qq.service.d/zzzzzzzzz-p07-hybrid-external-v1.conf":
        "c7f7ca15868a241a624401b30bd29fa9c18598ed5be5a599cb1a6db29594c11e",
    "/etc/systemd/system/myuna-core@qq.service.d/90-p07-owner-private-memory-v1.conf":
        None,
    "/etc/myuna-telegram-gateway/r5-resume-v1.json":
        "740b8e090a6717b7d471f008302628cec8815ce0c49a90051065c9751d453ad0",
    "/etc/systemd/system/myuna-telegram-owner-runtime-dev.service.d/zzzzzzzzzzz-p07-hybrid-external-v1.conf":
        "6ac683f598471a3a2da512bd2ff012054ccb23ee2ee420e7b3a6300aeeb2e031",
    "/etc/myuna-telegram-gateway/p07-owner-private-memory-selector-v4.json":
        None,
}

FIXED_STAGES = (
    "STAGE_CORE_RELEASE",
    "STAGE_PLUGIN_RELEASE",
    "STAGE_RUNTIME_RELEASE",
    "STAGE_DERIVATIVE_IMAGE",
    "QUIESCE_RUNTIME_SERVICE",
    "QUIESCE_RUNTIME_SOCKET",
    "QUIESCE_CORE_SERVICE",
    "CREATE_SELECTED_RUNTIME_ROOT",
    "STOP_EXACT_OLD_CONTAINER",
    "CONVERGE_ARCHIVE_CHILD_NAME",
    "ARCHIVE_EXACT_OLD_CONTAINER",
    "INSTALL_SEVEN_TARGET_FILES_AND_RELOAD",
    "CREATE_EXACT_STOPPED_TARGET",
    "START_CORE_SERVICE",
    "START_RUNTIME_SOCKET",
    "ARM_AND_START_TARGET_ONCE",
    "RECOVER_ATTEMPT5_FAILED_TARGET_TO_CORRECTED_STOPPED",
)

IMMUTABLE_ARTIFACTS = ("core", "plugin", "runtime", "image")
IMMUTABLE_STAGES = (
    "STAGE_CORE_RELEASE",
    "STAGE_PLUGIN_RELEASE",
    "STAGE_RUNTIME_RELEASE",
    "STAGE_DERIVATIVE_IMAGE",
)
_IMMUTABLE_LINEAR_PREFIXES = {
    ("OLD", "OLD", "OLD", "OLD"): "OLD",
    ("TARGET", "OLD", "OLD", "OLD"): "CORE_RELEASE_TARGET",
    ("TARGET", "TARGET", "OLD", "OLD"): "PLUGIN_RELEASE_TARGET",
    ("TARGET", "TARGET", "TARGET", "OLD"): "RUNTIME_RELEASE_TARGET",
    ("TARGET", "TARGET", "TARGET", "TARGET"): "IMMUTABLE_TARGET",
}


def immutable_subset_prefix(states: object) -> str:
    selected = tuple(states) if isinstance(states, (list, tuple)) else ()
    if len(selected) != len(IMMUTABLE_ARTIFACTS) or any(
        state not in {"OLD", "TARGET"} for state in selected
    ):
        raise ValueError("immutable_subset_rejected")
    if selected in _IMMUTABLE_LINEAR_PREFIXES:
        return _IMMUTABLE_LINEAR_PREFIXES[selected]
    return "IMMUTABLE_SET_" + "_".join(
        f"{key.upper()}_{state}" for key, state in zip(IMMUTABLE_ARTIFACTS, selected)
    )


def immutable_subset_next_stage(states: object) -> str:
    selected = tuple(states) if isinstance(states, (list, tuple)) else ()
    immutable_subset_prefix(selected)
    for index, state in enumerate(selected):
        if state == "OLD":
            return IMMUTABLE_STAGES[index]
    return "QUIESCE_RUNTIME_SERVICE"


IMMUTABLE_SUBSETS = tuple(
    tuple("TARGET" if mask & (1 << index) else "OLD" for index in range(4))
    for mask in range(16)
)
CHECKPOINT_PREFIXES = tuple(
    immutable_subset_prefix(states) for states in IMMUTABLE_SUBSETS
) + (
    "RUNTIME_SERVICE_QUIESCED",
    "RUNTIME_SOCKET_QUIESCED",
    "CORE_SERVICE_QUIESCED",
    "SELECTED_ROOT_TARGET",
    "ARCHIVE_CHILD_NAME_CONVERGENCE_REQUIRED",
    "OLD_CONTAINER_STOPPED",
    "OLD_CONTAINER_ARCHIVED",
    "FILES_PARTIAL",
    "FILES_AND_UNITS_TARGET",
    "TARGET_CONTAINER_STOPPED",
    "CORE_SERVICE_TARGET",
    "READY_FOR_SUPERVISED_GATE",
    "POST_WRITER_MANUAL",
    "POST_WRITER_RECOVERY_REQUIRED",
)

CHECKPOINT_NEXT_STAGE = {
    **{
        immutable_subset_prefix(states): immutable_subset_next_stage(states)
        for states in IMMUTABLE_SUBSETS
    },
    "RUNTIME_SERVICE_QUIESCED": "QUIESCE_RUNTIME_SOCKET",
    "RUNTIME_SOCKET_QUIESCED": "QUIESCE_CORE_SERVICE",
    "CORE_SERVICE_QUIESCED": "CREATE_SELECTED_RUNTIME_ROOT",
    "SELECTED_ROOT_TARGET": "STOP_EXACT_OLD_CONTAINER",
    "ARCHIVE_CHILD_NAME_CONVERGENCE_REQUIRED": "CONVERGE_ARCHIVE_CHILD_NAME",
    "OLD_CONTAINER_STOPPED": "ARCHIVE_EXACT_OLD_CONTAINER",
    "OLD_CONTAINER_ARCHIVED": "INSTALL_SEVEN_TARGET_FILES_AND_RELOAD",
    "FILES_PARTIAL": "INSTALL_SEVEN_TARGET_FILES_AND_RELOAD",
    "FILES_AND_UNITS_TARGET": "RECOVER_ATTEMPT5_FAILED_TARGET_TO_CORRECTED_STOPPED",
    "TARGET_CONTAINER_STOPPED": None,
    "CORE_SERVICE_TARGET": "START_RUNTIME_SOCKET",
    "READY_FOR_SUPERVISED_GATE": "ARM_AND_START_TARGET_ONCE",
    "POST_WRITER_MANUAL": None,
    "POST_WRITER_RECOVERY_REQUIRED": "RECOVER_ATTEMPT5_FAILED_TARGET_TO_CORRECTED_STOPPED",
}
CHECKPOINT_STAGE_TARGET = {
    "STAGE_CORE_RELEASE": "CORE_RELEASE_TARGET",
    "STAGE_PLUGIN_RELEASE": "PLUGIN_RELEASE_TARGET",
    "STAGE_RUNTIME_RELEASE": "RUNTIME_RELEASE_TARGET",
    "STAGE_DERIVATIVE_IMAGE": "IMMUTABLE_TARGET",
    "QUIESCE_RUNTIME_SERVICE": "RUNTIME_SERVICE_QUIESCED",
    "QUIESCE_RUNTIME_SOCKET": "RUNTIME_SOCKET_QUIESCED",
    "QUIESCE_CORE_SERVICE": "CORE_SERVICE_QUIESCED",
    "CREATE_SELECTED_RUNTIME_ROOT": "SELECTED_ROOT_TARGET",
    "STOP_EXACT_OLD_CONTAINER": "OLD_CONTAINER_STOPPED",
    "CONVERGE_ARCHIVE_CHILD_NAME": "OLD_CONTAINER_STOPPED",
    "ARCHIVE_EXACT_OLD_CONTAINER": "OLD_CONTAINER_ARCHIVED",
    "INSTALL_SEVEN_TARGET_FILES_AND_RELOAD": "FILES_AND_UNITS_TARGET",
    "CREATE_EXACT_STOPPED_TARGET": "TARGET_CONTAINER_STOPPED",
    "START_CORE_SERVICE": "CORE_SERVICE_TARGET",
    "START_RUNTIME_SOCKET": "READY_FOR_SUPERVISED_GATE",
    "ARM_AND_START_TARGET_ONCE": "POST_WRITER_MANUAL",
    "RECOVER_ATTEMPT5_FAILED_TARGET_TO_CORRECTED_STOPPED": "TARGET_CONTAINER_STOPPED",
}


_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_STATE = frozenset({"OLD", "TARGET", "THIRD_STATE"})
_MEMORY_SELECTOR_FIELDS = frozenset(
    {
        "archive_id",
        "calendar_zone",
        "calendar_zone_config_digest",
        "channel_kind",
        "client_id",
        "diary_coupled",
        "egress_policy_digest",
        "egress_policy_mode",
        "expected_gid",
        "expected_uid",
        "memory_release_set_id",
        "no_old_data_migration",
        "p15_handoff_schema",
        "p15_projection_active",
        "p08_lifecycle_start_watermark",
        "parent_epoch_id",
        "parent_epoch_revision",
        "parent_manifest_digest",
        "parent_release_set_id",
        "parent_selector_digest",
        "policy_overlay_id",
        "prompt_owner",
        "runtime_root",
        "schema",
        "status",
        "summary_used",
    }
)


class ProductionPlanRejected(RuntimeError):
    """The sealed authority or fresh resource observation was rejected."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ProductionPlanRejected(code)


def canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def digest(domain: str, value: object) -> str:
    return sha256(domain.encode("ascii") + b"\0" + canonical(value)).hexdigest()


def _selected_root_phase_authority() -> dict[str, object]:
    """Return the sealed source phase; no caller or result receipt participates."""

    require(
        _SELECTED_ROOT_PHASE in {"PRE_WRITER", "POST_WRITER"},
        "fixed_selected_root_phase_authority_rejected",
    )
    post_writer = _SELECTED_ROOT_PHASE == "POST_WRITER"
    body: dict[str, object] = {
        "archive_parent_identity": ATTEMPT5_ARCHIVE_PARENT_IDENTITY,
        "attempt": TRANSITIONAL_INSTALL_ATTEMPT,
        "attempt6_absent": True,
        "attempt_consumed": post_writer,
        "domain": _SELECTED_ROOT_PHASE_DOMAIN,
        "network_projection_sha256": _SELECTED_ROOT_NETWORK_PROJECTION_SHA256,
        "phase": _SELECTED_ROOT_PHASE,
        "product_authority_sha256": ATTEMPT5_PRODUCT_AUTHORITY_SHA256,
        "product_controller_release": ATTEMPT5_PRODUCT_CONTROLLER_RELEASE,
        "product_plan_sha256": ATTEMPT5_PRODUCT_ENTRY_PLAN_SHA256,
        "schema": _SELECTED_ROOT_PHASE_SCHEMA,
        "selected_root_identity": ATTEMPT5_PRIOR_ARCHIVE_CHILD_IDENTITY,
        "version": _SELECTED_ROOT_PHASE_VERSION,
        "writer_bound": post_writer,
    }
    require(
        digest("phase_f_post_writer_selected_root_authority_v1", body)
        == _SELECTED_ROOT_PHASE_AUTHORITY_SHA256,
        "fixed_selected_root_phase_authority_rejected",
    )
    return body


def _attempt5_environment_contract() -> dict[str, object]:
    return {
        "env_file": "/etc/myuna/secrets/gemini-api-key-telegram-gateway.env",
        "explicit": [
            "HOME=/AstrBot/data/home",
            "MYUNA_GATEWAY_CHANNEL_INSTANCE=telegram-owner-dev",
            (
                "MYUNA_GATEWAY_SIGNING_SECRET="
                "/run/secrets/myuna-telegram-channel-signing-v1"
            ),
            "MYUNA_GATEWAY_SOCKET=/run/myuna-telegram-gateway/owner.sock",
            "MYUNA_MEDIA_SHADOW_SOCKET=/run/myuna-telegram-media-auth/shadow.sock",
            "PYTHONDONTWRITEBYTECODE=1",
            "TZ=Asia/Shanghai",
        ],
    }


def _attempt5_host_contract() -> dict[str, object]:
    return {
        "cap_drop": ["ALL"],
        "cpus": "1.00",
        "health": {
            "command": (
                "python -c \"import socket; "
                "s=socket.create_connection(('127.0.0.1',6185),3); s.close()\""
            ),
            "interval": "15s",
            "retries": 12,
            "start_period": "45s",
            "timeout": "5s",
        },
        "init": True,
        "log": {"driver": "json-file", "max_file": "5", "max_size": "10m"},
        "memory": "1024m",
        "pids_limit": 192,
        "publish": "127.0.0.1:6285:6185",
        "restart": {"maximum_retry_count": 0, "name": "no"},
        "security_opt": ["no-new-privileges=true"],
        "stop_timeout": 30,
        "tmpfs": f"/tmp:rw,nosuid,nodev,noexec,size=128m,uid={MEMORY_RUNTIME_UID},gid={MEMORY_RUNTIME_GID}",
    }


def _attempt5_mount_contract(authority: Mapping[str, object]) -> list[dict[str, object]]:
    releases = authority["releases"]
    assert isinstance(releases, Mapping)
    plugin = releases["plugin"]
    assert isinstance(plugin, Mapping)
    plugin_root = (
        f"{plugin['root']}/{plugin['digest']}/channels/astrbot-telegram/"
        "plugin/myuna_telegram_gateway"
    )
    return [
        {
            "destination": "/AstrBot/data",
            "readonly": False,
            "source": TARGET_CHANNEL_ROOT + "/astrbot-data",
        },
        {
            "destination": "/AstrBot/data/plugins/astrbot_plugin_myuna_telegram_gateway",
            "readonly": True,
            "source": plugin_root,
        },
        {
            "destination": "/run/secrets/myuna-telegram-channel-signing-v1",
            "readonly": True,
            "source": TARGET_SIGNING_SECRET,
        },
        {
            "destination": "/run/myuna-telegram-gateway",
            "readonly": True,
            "source": TARGET_RUNTIME_ROOT,
        },
        {
            "destination": "/run/myuna-telegram-media-auth",
            "readonly": True,
            "source": TARGET_MEDIA_AUTH_RUNTIME_ROOT,
        },
    ]


def _attempt5_base_create_arguments(effect: Mapping[str, object]) -> list[str]:
    mounts = effect["mounts"]
    environment = effect["environment"]
    host = effect["host"]
    assert isinstance(mounts, list)
    assert isinstance(environment, Mapping)
    assert isinstance(host, Mapping)
    health = host["health"]
    log = host["log"]
    assert isinstance(health, Mapping)
    assert isinstance(log, Mapping)
    arguments = [
        "/usr/bin/docker", "container", "create",
        "--name", str(effect["container_name"]),
        "--user", str(effect["user"]),
        "--init", "--restart", "no",
        "--env-file", str(environment["env_file"]),
    ]
    for value in environment["explicit"]:
        arguments.extend(("--env", str(value)))
    arguments.extend(("--publish", str(host["publish"])))
    for row in mounts:
        assert isinstance(row, Mapping)
        suffix = ",readonly" if row["readonly"] else ""
        arguments.extend(
            (
                "--mount",
                f"type=bind,src={row['source']},dst={row['destination']}{suffix}",
            )
        )
    arguments.extend(
        (
            "--network", str(effect["network_name"]),
            "--security-opt", "no-new-privileges=true",
            "--cap-drop", "ALL",
            "--pids-limit", str(host["pids_limit"]),
            "--memory", str(host["memory"]),
            "--cpus", str(host["cpus"]),
            "--tmpfs", str(host["tmpfs"]),
            "--stop-timeout", str(host["stop_timeout"]),
            "--health-cmd", str(health["command"]),
            "--health-interval", str(health["interval"]),
            "--health-timeout", str(health["timeout"]),
            "--health-retries", str(health["retries"]),
            "--health-start-period", str(health["start_period"]),
            "--log-driver", str(log["driver"]),
            "--log-opt", "max-size=" + str(log["max_size"]),
            "--log-opt", "max-file=" + str(log["max_file"]),
            "--label", "com.docker.compose.project=" + str(effect["project"]),
            "--label", "com.docker.compose.service=" + str(effect["service"]),
            "--label", "myuna.phase-f.plan-digest=" + str(effect["plan_digest"]),
            "--label", (
                "myuna.phase-f.target-config-digest="
                + str(effect["target_config_digest"])
            ),
            str(effect["image"]),
        )
    )
    return arguments


def _attempt5_target_effect(
    authority: Mapping[str, object],
    observation: Mapping[str, object],
) -> dict[str, object]:
    files = authority["files"]
    image = authority["image"]
    archive = observation["archive_name"]
    network = observation["network"]
    assert isinstance(files, Mapping)
    assert isinstance(image, Mapping)
    assert isinstance(archive, Mapping)
    assert isinstance(network, Mapping)
    body: dict[str, object] = {
        "archive_container_id": ATTEMPT5_OLD_CONTAINER_ID,
        "archive_name": ARCHIVE_PREFIX + str(authority["authority_sha256"])[:16],
        "archive_projection_sha256": archive["projection_sha256"],
        "attempt": TRANSITIONAL_INSTALL_ATTEMPT,
        "command": {"command": ["python", "main.py"], "entrypoint": None},
        "container_name": CONTAINER_NAME,
        "environment": _attempt5_environment_contract(),
        "host": _attempt5_host_contract(),
        "image": image["reference"],
        "mounts": _attempt5_mount_contract(authority),
        "network_name": NETWORK_NAME,
        "network_projection_sha256": network["projection_sha256"],
        "plan_digest": ATTEMPT5_PRODUCT_ENTRY_PLAN_SHA256,
        "project": TARGET_COMPOSE_PROJECT,
        "service": TARGET_COMPOSE_SERVICE,
        "target_config_digest": files[
            "/etc/myuna-telegram-gateway/r5-resume-v1.json"
        ]["payload_sha256"],
        "user": TARGET_USER,
        "writer": TRANSITIONAL_WRITER_BOUNDARY,
    }
    body["command_sha256"] = digest(
        "myuna.phase-f.container-command.v1", body["command"]
    )
    body["environment_sha256"] = digest(
        "phase_f_attempt5_target_environment_v1",
        sorted(body["environment"]["explicit"]),
    )
    body["host_sha256"] = digest(
        "phase_f_attempt5_target_host_v1", body["host"]
    )
    body["mounts_sha256"] = digest(
        "phase_f_attempt5_target_mounts_v1", body["mounts"]
    )
    body["network_sha256"] = digest(
        "phase_f_attempt5_target_network_v1",
        {
            "name": body["network_name"],
            "projection_sha256": body["network_projection_sha256"],
        },
    )
    body["create_arguments_sha256"] = digest(
        "phase_f_attempt5_target_create_arguments_v1",
        _attempt5_base_create_arguments(body),
    )
    return {
        **body,
        "effect_sha256": digest("phase_f_attempt5_target_effect_v1", body),
    }


def stable_attempt_archive_child_name() -> str:
    """Return the source-generation-independent Attempt-5 child identity."""

    body = {
        "archive_parent_identity": ATTEMPT5_ARCHIVE_PARENT_IDENTITY,
        "attempt": TRANSITIONAL_INSTALL_ATTEMPT,
        "attempt_root": STABLE_ARCHIVE_CHILD_ATTEMPT_ROOT,
        "capability": STABLE_ARCHIVE_CHILD_CAPABILITY,
        "original_old_container_identity": STABLE_ARCHIVE_CHILD_OLD_CONTAINER_ID,
        "schema": STABLE_ARCHIVE_CHILD_SCHEMA,
    }
    return (
        "p07-owner-private-memory-attempt-v1-"
        + digest("phase_f_stable_attempt_archive_child_v1", body)[:16]
    )


def image_member_set_sha256(receipt: Mapping[str, object]) -> str:
    return digest(
        "phase_f_fixed_image_member_set",
        {
            "image_id": receipt.get("image_id"),
            "image_reference": receipt.get("image_reference"),
            "layers": receipt.get("layers"),
            "platform": receipt.get("platform"),
        },
    )


def _object(value: object, keys: set[str], code: str) -> dict[str, object]:
    require(type(value) is dict and set(value) == keys, code)
    assert isinstance(value, dict)
    return value


def _hex(value: object, size: int, code: str) -> str:
    expression = _HEX40 if size == 40 else _HEX64
    require(type(value) is str and expression.fullmatch(value) is not None, code)
    assert isinstance(value, str)
    return value


def _member_rows(value: object, code: str) -> list[dict[str, object]]:
    require(type(value) is list and bool(value), code)
    assert isinstance(value, list)
    rows: list[dict[str, object]] = []
    previous = ""
    for selected in value:
        row = _object(selected, {"path", "sha256", "size"}, code)
        path = row["path"]
        require(
            type(path) is str
            and bool(path)
            and not str(path).startswith("/")
            and ".." not in str(path).split("/")
            and str(path) > previous
            and type(row["size"]) is int
            and int(row["size"]) >= 0,
            code,
        )
        previous = str(path)
        rows.append(
            {
                "path": str(path),
                "sha256": _hex(row["sha256"], 64, code),
                "size": int(row["size"]),
            }
        )
    return rows


def release_member_set_sha256(members: list[dict[str, object]]) -> str:
    directories = {"."}
    for row in members:
        parts = str(row["path"]).split("/")[:-1]
        for index in range(1, len(parts) + 1):
            directories.add("/".join(parts[:index]))
    by_path: dict[str, dict[str, object]] = {
        path: {"kind": "directory", "mode": "0550", "path": path}
        for path in directories
    }
    for row in members:
        by_path[str(row["path"])] = {
            "kind": "file",
            "mode": "0440",
            "path": str(row["path"]),
            "sha256": str(row["sha256"]),
            "size": int(row["size"]),
        }
    return sha256(canonical([by_path[path] for path in sorted(by_path)])).hexdigest()


def _release(value: object, key: str, root: str, code: str) -> dict[str, object]:
    row = _object(
        value,
        {
            "bundle_prefix",
            "digest",
            "directory_mode",
            "file_mode",
            "members",
            "member_set_sha256",
            "receipt_sha256",
            "root",
        },
        code,
    )
    digest_value = _hex(row["digest"], 64, code)
    require(
        row["root"] == root
        and row["bundle_prefix"] == f"staging/releases/{key}/{digest_value}"
        and row["directory_mode"] == "0550"
        and row["file_mode"] == "0440",
        code,
    )
    members = _member_rows(row["members"], code)
    require(
        row["member_set_sha256"] == release_member_set_sha256(members),
        code,
    )
    return {
        "bundle_prefix": str(row["bundle_prefix"]),
        "digest": digest_value,
        "directory_mode": "0550",
        "file_mode": "0440",
        "members": members,
        "member_set_sha256": _hex(row["member_set_sha256"], 64, code),
        "receipt_sha256": _hex(row["receipt_sha256"], 64, code),
        "root": root,
    }


def _target_file(path: str, value: object) -> dict[str, object]:
    role, mode = FILE_ROLES[path]
    row = _object(
        value,
        {
            "gid",
            "mode",
            "owner",
            "payload_b64",
            "payload_sha256",
            "role",
            "uid",
        },
        "fixed_file_authority_rejected",
    )
    require(
        row["role"] == role
        and row["mode"] == mode
        and row["owner"] == FILE_OWNERS[path]
        and type(row["uid"]) is int
        and type(row["gid"]) is int
        and int(row["uid"]) >= 0
        and int(row["gid"]) >= 0
        and type(row["payload_b64"]) is str,
        "fixed_file_authority_rejected",
    )
    try:
        payload = base64.b64decode(str(row["payload_b64"]), validate=True)
    except ValueError as exc:
        raise ProductionPlanRejected("fixed_file_authority_rejected") from exc
    require(
        bool(payload)
        and sha256(payload).hexdigest() == row["payload_sha256"]
        and _HEX64.fullmatch(str(row["payload_sha256"])) is not None,
        "fixed_file_authority_rejected",
    )
    return {
        "gid": int(row["gid"]),
        "mode": mode,
        "owner": FILE_OWNERS[path],
        "payload_b64": str(row["payload_b64"]),
        "payload_sha256": str(row["payload_sha256"]),
        "role": role,
        "uid": int(row["uid"]),
    }


def validate_source_authority(value: object) -> dict[str, object]:
    require(type(value) is dict, "fixed_source_authority_rejected")
    assert isinstance(value, dict)
    supplied_digest = value.get("authority_sha256")
    allowed = {
        "builder",
        "controller",
        "files",
        "image",
        "parent",
        "releases",
        "schema",
        "source",
    }
    require(
        frozenset(value) in {
            frozenset(allowed),
            frozenset((*allowed, "authority_sha256")),
        },
        "fixed_source_authority_rejected",
    )
    authority = _object(
        {key: value[key] for key in allowed},
        allowed,
        "fixed_source_authority_rejected",
    )
    require(authority["schema"] == SOURCE_SCHEMA, "fixed_source_authority_rejected")
    source = _object(
        authority["source"],
        {
            "core_commit",
            "core_tree",
            "deploy_commit",
            "deploy_parent",
            "deploy_tree",
        },
        "fixed_source_authority_rejected",
    )
    source_pair = (source["deploy_commit"], source["deploy_parent"])
    frozen_product_pair = (
        ATTEMPT5_PRODUCT_DEPLOY_COMMIT,
        ATTEMPT5_PRODUCT_DEPLOY_PARENT,
    )
    require(
        source["core_commit"] == ACCEPTED_CORE_COMMIT
        and source["core_tree"] == ACCEPTED_CORE_TREE
        and (
            source["deploy_parent"] == ACCEPTED_DEPLOY_PARENT
            or source_pair == frozen_product_pair
        ),
        "fixed_source_authority_rejected",
    )
    _hex(source["deploy_commit"], 40, "fixed_source_authority_rejected")
    _hex(source["deploy_tree"], 40, "fixed_source_authority_rejected")

    builder = _object(
        authority["builder"],
        {
            "astrbot_commit",
            "astrbot_tree",
            "base_image_digest",
            "gateway_builder_blob",
            "hybrid_builder_blob",
            "runtime_base_digest",
            "runtime_base_member_set_sha256",
            "tool_set_sha256",
        },
        "fixed_builder_authority_rejected",
    )
    require(
        builder["astrbot_commit"] == ACCEPTED_ASTRBOT_COMMIT
        and builder["hybrid_builder_blob"] == HYBRID_BUILDER_BLOB
        and builder["gateway_builder_blob"] == GATEWAY_BUILDER_BLOB
        and builder["runtime_base_digest"] == ACCEPTED_RUNTIME_BASE
        and builder["base_image_digest"]
        == "sha256:7546bddf1040419a455dd1ca683a5e9cf84436bbd85de17c7ac626d3af7affe4",
        "fixed_builder_authority_rejected",
    )
    _hex(builder["astrbot_tree"], 40, "fixed_builder_authority_rejected")
    for field in ("runtime_base_member_set_sha256", "tool_set_sha256"):
        _hex(builder[field], 64, "fixed_builder_authority_rejected")

    parent = _object(
        authority["parent"],
        {
            "epoch_id",
            "epoch_revision",
            "lifecycle_start_watermark",
            "manifest_sha256",
            "release_set_id",
            "selector_sha256",
        },
        "fixed_parent_authority_rejected",
    )
    require(
        parent
        == {
            "epoch_id": PARENT_EPOCH_ID,
            "epoch_revision": PARENT_EPOCH_REVISION,
            "lifecycle_start_watermark": P08_LIFECYCLE_START_WATERMARK,
            "manifest_sha256": PARENT_MANIFEST_SHA256,
            "release_set_id": PARENT_RELEASE_SET_ID,
            "selector_sha256": PARENT_SELECTOR_SHA256,
        },
        "fixed_parent_authority_rejected",
    )

    releases_value = _object(
        authority["releases"],
        {"core", "plugin", "runtime"},
        "fixed_release_authority_rejected",
    )
    releases = {
        "core": _release(
            releases_value["core"],
            "core",
            CORE_RELEASE_ROOT,
            "fixed_release_authority_rejected",
        ),
        "plugin": _release(
            releases_value["plugin"],
            "plugin",
            PLUGIN_RELEASE_ROOT,
            "fixed_release_authority_rejected",
        ),
        "runtime": _release(
            releases_value["runtime"],
            "runtime",
            RUNTIME_RELEASE_ROOT,
            "fixed_release_authority_rejected",
        ),
    }

    image = _object(
        authority["image"],
        {
            "archive_members",
            "archive_sha256",
            "archive_size",
            "digest",
            "member_set_sha256",
            "receipt",
            "reference",
            "receipt_sha256",
        },
        "fixed_image_authority_rejected",
    )
    require(
        type(image["reference"]) is str
        and str(image["reference"]).startswith(TARGET_IMAGE_PREFIX)
        and _HEX64.fullmatch(str(image["reference"])[len(TARGET_IMAGE_PREFIX):])
        is not None
        and image["digest"] == str(image["reference"])[len(TARGET_IMAGE_PREFIX):],
        "fixed_image_authority_rejected",
    )
    archive_sha256 = _hex(
        image["archive_sha256"], 64, "fixed_image_authority_rejected"
    )
    archive_members = _member_rows(
        image["archive_members"], "fixed_image_authority_rejected"
    )
    require(
        all(
            row["path"]
            == f"staging/image/{archive_sha256}.part-{index:06d}"
            for index, row in enumerate(archive_members)
        )
        and sum(int(row["size"]) for row in archive_members)
        == image["archive_size"]
        and type(image["archive_size"]) is int
        and int(image["archive_size"]) > 0
        and type(image["receipt"]) is dict
        and sha256(canonical(image["receipt"])).hexdigest()
        == image["receipt_sha256"]
        and image["receipt"].get("archive_sha256") == archive_sha256
        and image["receipt"].get("archive_size") == image["archive_size"]
        and image["receipt"].get("image_reference") == image["reference"]
        and image["receipt"].get("manifest_digest")
        == "sha256:" + str(image["digest"]),
        "fixed_image_authority_rejected",
    )
    require(
        image["member_set_sha256"]
        == image_member_set_sha256(image["receipt"]),
        "fixed_image_authority_rejected",
    )
    _hex(image["receipt_sha256"], 64, "fixed_image_authority_rejected")

    controller = _object(
        authority["controller"],
        {
            "config_sha256",
            "member_set_sha256",
            "source_receipt_sha256",
        },
        "fixed_controller_authority_rejected",
    )
    for field in controller:
        _hex(controller[field], 64, "fixed_controller_authority_rejected")

    files_value = _object(
        authority["files"],
        set(FILE_ROLES),
        "fixed_file_authority_rejected",
    )
    files = {
        path: _target_file(path, files_value[path])
        for path in sorted(FILE_ROLES)
    }
    selector_row = files[MEMORY_SELECTOR_PATH]
    selector_authority = {"files": {MEMORY_SELECTOR_PATH: selector_row}}
    try:
        _source_generated_memory_runtime(selector_authority)
    except ProductionPlanRejected:
        selected_memory_runtime(selector_authority)
    try:
        selector_payload = json.loads(
            base64.b64decode(
                str(selector_row["payload_b64"]), validate=True
            ).decode("ascii")
        )
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProductionPlanRejected(
            "fixed_memory_selector_authority_rejected"
        ) from exc
    require(
        type(selector_payload) is dict,
        "fixed_memory_selector_authority_rejected",
    )
    stable_name = stable_attempt_archive_child_name()
    selector_payload["archive_id"] = stable_name
    selector_payload["runtime_root"] = f"{MEMORY_RUNTIME_ROOT}/{stable_name}"
    selector_bytes = canonical(selector_payload)
    files[MEMORY_SELECTOR_PATH] = {
        **selector_row,
        "payload_b64": base64.b64encode(selector_bytes).decode("ascii"),
        "payload_sha256": sha256(selector_bytes).hexdigest(),
    }
    selected_memory_runtime({"files": files})
    require(
        controller["config_sha256"]
        == files["/etc/myuna-telegram-gateway/r5-resume-v1.json"][
            "payload_sha256"
        ],
        "fixed_controller_authority_rejected",
    )
    body = {
        "builder": dict(builder),
        "controller": dict(controller),
        "files": files,
        "image": dict(image),
        "parent": dict(parent),
        "releases": releases,
        "schema": SOURCE_SCHEMA,
        "source": dict(source),
    }
    computed_digest = digest("phase_f_fixed_source", body)
    if source_pair == frozen_product_pair:
        require(
            computed_digest == ATTEMPT5_PRODUCT_AUTHORITY_SHA256,
            "fixed_attempt5_product_authority_rejected",
        )
    if supplied_digest is not None:
        require(
            supplied_digest == computed_digest,
            "fixed_source_authority_rejected",
        )
    return {**body, "authority_sha256": computed_digest}


def r5_durability_target_config() -> bytes:
    """Return the sole source-owned R5 maintenance target payload."""

    payload = canonical(
        {
            "channel_root": TARGET_CHANNEL_ROOT,
            "compose_file": (
                f"{PLUGIN_RELEASE_ROOT}/{R5_DURABILITY_TARGET_PLUGIN_RELEASE}/"
                "channels/astrbot-telegram/compose.dev.yml"
            ),
            "gateway_release": R5_DURABILITY_TARGET_PLUGIN_RELEASE,
            "plugin_root": (
                f"{PLUGIN_RELEASE_ROOT}/{R5_DURABILITY_TARGET_PLUGIN_RELEASE}/"
                "channels/astrbot-telegram/plugin/myuna_telegram_gateway"
            ),
            "schema": "myuna.telegram.r5-boot-resume-config.v1",
        }
    )
    require(
        sha256(payload).hexdigest() == R5_DURABILITY_TARGET_CONFIG_SHA256,
        "r5_durability_target_config_rejected",
    )
    return payload


def validate_r5_durability_authority(
    baseline_value: Mapping[str, object],
    target_value: Mapping[str, object],
) -> dict[str, object]:
    """Admit one exact old-controller to source-command selection projection."""

    keys = {
        "builder",
        "controller",
        "files",
        "image",
        "parent",
        "releases",
        "schema",
        "source",
    }
    require(
        keys.issubset(baseline_value),
        "r5_durability_baseline_authority_rejected",
    )
    baseline = {key: baseline_value[key] for key in keys}
    baseline_source = baseline.get("source")
    baseline_controller = baseline.get("controller")
    baseline_releases = baseline.get("releases")
    baseline_files = baseline.get("files")
    require(
        type(baseline_source) is dict
        and baseline_source
        == {
            "core_commit": R5_DURABILITY_BASELINE_CORE_COMMIT,
            "core_tree": R5_DURABILITY_BASELINE_CORE_TREE,
            "deploy_commit": R5_DURABILITY_BASELINE_DEPLOY_COMMIT,
            "deploy_parent": R5_DURABILITY_BASELINE_DEPLOY_PARENT,
            "deploy_tree": R5_DURABILITY_BASELINE_DEPLOY_TREE,
        }
        and type(baseline_controller) is dict
        and baseline_controller.get("config_sha256")
        == R5_DURABILITY_BASELINE_CONFIG_SHA256
        and type(baseline_releases) is dict
        and type(baseline_releases.get("plugin")) is dict
        and baseline_releases["plugin"].get("digest")
        == R5_DURABILITY_BASELINE_PLUGIN_RELEASE
        and type(baseline_files) is dict
        and type(baseline_files.get(R5_CONFIG_PATH)) is dict
        and baseline_files[R5_CONFIG_PATH].get("payload_sha256")
        == R5_DURABILITY_BASELINE_CONFIG_SHA256,
        "r5_durability_baseline_authority_rejected",
    )

    target_input = {key: target_value[key] for key in keys}
    target = validate_source_authority(target_value)
    target_source = target["source"]
    target_controller = target["controller"]
    target_releases = target["releases"]
    target_files = target["files"]
    target_config = target_files[R5_CONFIG_PATH]
    try:
        target_payload = base64.b64decode(
            str(target_config["payload_b64"]), validate=True
        )
    except ValueError as exc:
        raise ProductionPlanRejected(
            "r5_durability_target_authority_rejected"
        ) from exc
    require(
        target_source["core_commit"] == ACCEPTED_CORE_COMMIT
        and target_source["core_tree"] == ACCEPTED_CORE_TREE
        and target_source["deploy_parent"] == ACCEPTED_DEPLOY_PARENT
        and target_controller["config_sha256"]
        == R5_DURABILITY_TARGET_CONFIG_SHA256
        and target_config["payload_sha256"]
        == R5_DURABILITY_TARGET_CONFIG_SHA256
        and target_payload == r5_durability_target_config()
        and target_releases["plugin"]["digest"]
        == R5_DURABILITY_TARGET_PLUGIN_RELEASE,
        "r5_durability_target_authority_rejected",
    )
    for field in ("builder", "image", "parent"):
        require(
            canonical(target_input[field]) == canonical(baseline[field]),
            "r5_durability_protected_authority_changed",
        )
    for release in ("core", "runtime"):
        require(
            canonical(target_input["releases"][release])
            == canonical(baseline_releases[release]),
            "r5_durability_protected_authority_changed",
        )
    for path in sorted(FILE_ROLES):
        if path != R5_CONFIG_PATH:
            require(
                canonical(target_input["files"][path])
                == canonical(baseline_files[path]),
                "r5_durability_protected_authority_changed",
            )
    return target


def source_contract() -> dict[str, object]:
    """Return the finite source-owned shape; it contains no runtime truth."""

    selected_root_phase = _selected_root_phase_authority()
    require(
        selected_root_phase["phase"] == "POST_WRITER",
        "fixed_selected_root_phase_authority_rejected",
    )
    return {
        "accepted_core_commit": ACCEPTED_CORE_COMMIT,
        "accepted_core_tree": ACCEPTED_CORE_TREE,
        "accepted_deploy_parent": ACCEPTED_DEPLOY_PARENT,
        "attempt5_product_authority_sha256": ATTEMPT5_PRODUCT_AUTHORITY_SHA256,
        "attempt5_product_controller_release": ATTEMPT5_PRODUCT_CONTROLLER_RELEASE,
        "attempt5_product_entry_plan_sha256": ATTEMPT5_PRODUCT_ENTRY_PLAN_SHA256,
        "archive_prefix": ARCHIVE_PREFIX,
        "astrbot_commit": ACCEPTED_ASTRBOT_COMMIT,
        "builder_blobs": [HYBRID_BUILDER_BLOB, GATEWAY_BUILDER_BLOB],
        "container": CONTAINER_NAME,
        "file_paths": sorted(FILE_ROLES),
        "fixed_stages": list(FIXED_STAGES),
        "image_repository": TARGET_IMAGE_PREFIX,
        "memory_runtime_root": MEMORY_RUNTIME_ROOT,
        "memory_runtime_prestate": {
            "expected_gid": MEMORY_RUNTIME_GID,
            "expected_uid": MEMORY_RUNTIME_UID,
            "legacy_archive_id": LEGACY_MEMORY_ARCHIVE_ID,
            "legacy_root_evidence_sha256": LEGACY_MEMORY_ROOT_EVIDENCE_SHA256,
            "selected_child_states": ["OLD", "TARGET"],
        },
        "network": NETWORK_NAME,
        "parent_release_set_id": PARENT_RELEASE_SET_ID,
        "post_writer_selected_root_authority_sha256": _SELECTED_ROOT_PHASE_AUTHORITY_SHA256,
        "runtime_base_digest": ACCEPTED_RUNTIME_BASE,
        "schema": SOURCE_SCHEMA,
    }


def authority_bundle_members(value: object) -> set[str]:
    authority = validate_source_authority(value)
    members = {
        str(row["path"]) for row in authority["image"]["archive_members"]
    }
    for release in authority["releases"].values():
        prefix = str(release["bundle_prefix"])
        members.update(
            f"{prefix}/{row['path']}" for row in release["members"]
        )
    return members


def source_policy() -> dict[str, object]:
    """Bind the immutable hybrid builder to this fixed supervised product."""

    contract = source_contract()
    return {
        "automatic_private_writer_recovery": False,
        "fixed_product_contract_sha256": digest(
            "phase_f_fixed_product_contract",
            contract,
        ),
        "private_content_required": False,
        "supervised_writer_boundary": True,
    }


def source_boundaries() -> dict[str, object]:
    """Retain the accepted builder's six immutable program boundary slots."""

    return {
        program: {
            "identity_digest": digest(
                "phase_f_fixed_immutable_program_boundary",
                {
                    "accepted_deploy_parent": ACCEPTED_DEPLOY_PARENT,
                    "program": program,
                    "target_mutation": False,
                },
            ),
            "mutation_allowed": False,
            "state": "immutable_no_mutation",
        }
        for program in ("p01", "p08", "p09", "p10", "p15", "p16")
    }


def _file_observation(
    path: str,
    value: object,
    target: Mapping[str, object],
) -> dict[str, object]:
    require(type(value) is dict, "fixed_file_observation_rejected")
    assert isinstance(value, dict)
    supplied_state = value.get("state")
    fields = {"gid", "identity", "kind", "mode", "payload_b64", "sha256", "uid"}
    require(
        frozenset(value) in {frozenset(fields), frozenset((*fields, "state"))},
        "fixed_file_observation_rejected",
    )
    row = _object(
        {key: value[key] for key in fields},
        fields,
        "fixed_file_observation_rejected",
    )
    kind = row["kind"]
    require(kind in {"absent", "regular"}, "fixed_file_observation_rejected")
    if kind == "absent":
        require(
            row["identity"] is None
            and row["uid"] is None
            and row["gid"] is None
            and row["mode"] is None
            and row["payload_b64"] is None
            and row["sha256"] is None,
            "fixed_file_observation_rejected",
        )
        current_sha: str | None = None
    else:
        require(
            type(row["identity"]) is str
            and bool(row["identity"])
            and type(row["uid"]) is int
            and int(row["uid"]) >= 0
            and type(row["gid"]) is int
            and int(row["gid"]) >= 0
            and type(row["mode"]) is str
            and re.fullmatch(r"0[0-7]{3}", str(row["mode"])) is not None
            and type(row["payload_b64"]) is str,
            "fixed_file_observation_rejected",
        )
        try:
            payload = base64.b64decode(str(row["payload_b64"]), validate=True)
        except ValueError as exc:
            raise ProductionPlanRejected("fixed_file_observation_rejected") from exc
        current_sha = sha256(payload).hexdigest()
        require(
            current_sha == row["sha256"]
            and _HEX64.fullmatch(str(row["sha256"])) is not None,
            "fixed_file_observation_rejected",
        )
    old_sha = OLD_FILE_SHA256[path]
    target_sha = str(target["payload_sha256"])
    state = (
        "TARGET"
        if current_sha == target_sha
        else "OLD"
        if current_sha == old_sha
        else "THIRD_STATE"
    )
    if supplied_state is not None:
        require(supplied_state == state, "fixed_file_observation_rejected")
    return {**row, "state": state}


def _state_row(value: object, keys: set[str], code: str) -> dict[str, object]:
    row = _object(value, keys | {"state"}, code)
    require(row["state"] in _STATE, code)
    return row


def _source_generated_memory_runtime(
    authority: Mapping[str, object],
) -> dict[str, object]:
    """Derive the one selected child from the sealed source-owned selector."""

    files = authority["files"]
    require(isinstance(files, Mapping), "fixed_memory_selector_authority_rejected")
    row = files[MEMORY_SELECTOR_PATH]
    require(isinstance(row, Mapping), "fixed_memory_selector_authority_rejected")
    try:
        payload = json.loads(
            base64.b64decode(str(row["payload_b64"]), validate=True).decode("ascii")
        )
    except (KeyError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProductionPlanRejected(
            "fixed_memory_selector_authority_rejected"
        ) from exc
    require(
        type(payload) is dict
        and frozenset(payload) == _MEMORY_SELECTOR_FIELDS
        and payload.get("schema")
        == "myuna.p07-owner-private-memory-selector.v4"
        and payload.get("status") == "active"
        and payload.get("no_old_data_migration") is True
        and payload.get("diary_coupled") is False
        and payload.get("p15_projection_active") is False
        and payload.get("summary_used") is False
        and payload.get("expected_uid") == MEMORY_RUNTIME_UID
        and payload.get("expected_gid") == MEMORY_RUNTIME_GID
        and payload.get("parent_release_set_id") == PARENT_RELEASE_SET_ID
        and payload.get("parent_manifest_digest") == PARENT_MANIFEST_SHA256
        and payload.get("parent_selector_digest") == PARENT_SELECTOR_SHA256
        and payload.get("parent_epoch_id") == PARENT_EPOCH_ID
        and payload.get("parent_epoch_revision") == PARENT_EPOCH_REVISION
        and payload.get("p08_lifecycle_start_watermark")
        == P08_LIFECYCLE_START_WATERMARK
        and payload.get("calendar_zone") == "Asia/Shanghai"
        and all(
            type(payload.get(field)) is str and bool(payload.get(field))
            for field in (
                "channel_kind",
                "client_id",
                "egress_policy_mode",
                "p15_handoff_schema",
                "prompt_owner",
            )
        )
        and all(
            type(payload.get(field)) is str
            and _HEX64.fullmatch(str(payload.get(field))) is not None
            for field in (
                "calendar_zone_config_digest",
                "egress_policy_digest",
                "memory_release_set_id",
                "policy_overlay_id",
            )
        )
        and type(payload.get("archive_id")) is str
        and re.fullmatch(
            r"p07-owner-private-memory-transactional-[0-9a-f]{16}",
            str(payload.get("archive_id")),
        )
        is not None,
        "fixed_memory_selector_authority_rejected",
    )
    archive_id = str(payload["archive_id"])
    runtime_root = f"{MEMORY_RUNTIME_ROOT}/{archive_id}"
    require(
        payload.get("runtime_root") == runtime_root
        and archive_id
        == "p07-owner-private-memory-transactional-"
        + str(payload["memory_release_set_id"])[:16]
        and archive_id != LEGACY_MEMORY_ARCHIVE_ID,
        "fixed_memory_selector_authority_rejected",
    )
    return {
        "archive_id": archive_id,
        "expected_gid": MEMORY_RUNTIME_GID,
        "expected_uid": MEMORY_RUNTIME_UID,
        "runtime_root": runtime_root,
    }


def selected_memory_runtime(authority: Mapping[str, object]) -> dict[str, object]:
    """Derive the stable Attempt-5 child from the sealed selector."""

    files = authority["files"]
    require(isinstance(files, Mapping), "fixed_memory_selector_authority_rejected")
    row = files[MEMORY_SELECTOR_PATH]
    require(isinstance(row, Mapping), "fixed_memory_selector_authority_rejected")
    try:
        payload = json.loads(
            base64.b64decode(str(row["payload_b64"]), validate=True).decode("ascii")
        )
    except (KeyError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProductionPlanRejected(
            "fixed_memory_selector_authority_rejected"
        ) from exc
    stable_name = stable_attempt_archive_child_name()
    stable_root = f"{MEMORY_RUNTIME_ROOT}/{stable_name}"
    require(
        type(payload) is dict
        and payload.get("archive_id") == stable_name
        and payload.get("runtime_root") == stable_root,
        "fixed_memory_selector_authority_rejected",
    )
    source_payload = dict(payload)
    source_name = (
        "p07-owner-private-memory-transactional-"
        + str(source_payload.get("memory_release_set_id"))[:16]
    )
    source_payload["archive_id"] = source_name
    source_payload["runtime_root"] = f"{MEMORY_RUNTIME_ROOT}/{source_name}"
    source_bytes = canonical(source_payload)
    source_row = {
        **dict(row),
        "payload_b64": base64.b64encode(source_bytes).decode("ascii"),
        "payload_sha256": sha256(source_bytes).hexdigest(),
    }
    _source_generated_memory_runtime(
        {"files": {MEMORY_SELECTOR_PATH: source_row}}
    )
    return {
        "archive_id": stable_name,
        "expected_gid": MEMORY_RUNTIME_GID,
        "expected_uid": MEMORY_RUNTIME_UID,
        "runtime_root": stable_root,
    }


def validate_observation(
    value: object,
    authority: Mapping[str, object],
) -> dict[str, object]:
    observation = _object(
        value,
        {
            "archive_name",
            "archive_root",
            "files",
            "network",
            "old_container",
            "parent",
            "releases",
            "schema",
            "services",
            "target_container",
        },
        "fixed_observation_rejected",
    )
    require(
        observation["schema"] == OBSERVATION_SCHEMA,
        "fixed_observation_rejected",
    )
    files_value = _object(
        observation["files"],
        set(FILE_ROLES),
        "fixed_file_observation_rejected",
    )
    target_files = authority["files"]
    assert isinstance(target_files, Mapping)
    files = {
        path: _file_observation(path, files_value[path], target_files[path])
        for path in sorted(FILE_ROLES)
    }
    releases_value = _object(
        observation["releases"],
        {"core", "image", "plugin", "runtime"},
        "fixed_release_observation_rejected",
    )
    releases = {
        key: _state_row(
            releases_value[key],
            {"identity"},
            "fixed_release_observation_rejected",
        )
        for key in sorted(releases_value)
    }
    authority_releases = authority["releases"]
    authority_image = authority["image"]
    assert isinstance(authority_releases, Mapping)
    assert isinstance(authority_image, Mapping)
    for key, row in releases.items():
        expected_identity = (
            authority_image["member_set_sha256"]
            if key == "image"
            else authority_releases[key]["member_set_sha256"]
        )
        require(
            (
                row["state"] == "OLD" and row["identity"] is None
            )
            or (
                row["state"] == "TARGET"
                and row["identity"] == expected_identity
            )
            or row["state"] == "THIRD_STATE",
            "fixed_release_observation_rejected",
        )
    parent = _state_row(
        observation["parent"],
        {"manifest_sha256", "selector_sha256"},
        "fixed_parent_observation_rejected",
    )
    require(
        parent["manifest_sha256"] in {None, PARENT_MANIFEST_SHA256}
        and parent["selector_sha256"] in {None, PARENT_SELECTOR_SHA256}
        and (
            parent["state"] != "TARGET"
            or (
                parent["manifest_sha256"] == PARENT_MANIFEST_SHA256
                and parent["selector_sha256"] == PARENT_SELECTOR_SHA256
            )
        ),
        "fixed_parent_observation_rejected",
    )
    services_value = _object(
        observation["services"],
        {"core", "runtime", "socket"},
        "fixed_service_observation_rejected",
    )
    services: dict[str, dict[str, object]] = {}
    for key in sorted(services_value):
        row = _object(
            services_value[key],
            {"active", "identity"},
            "fixed_service_observation_rejected",
        )
        require(
            type(row["active"]) is bool
            and type(row["identity"]) is str
            and bool(row["identity"]),
            "fixed_service_observation_rejected",
        )
        services[key] = dict(row)
    network = _state_row(
        observation["network"],
        {"identity", "member_ids", "name", "projection_sha256"},
        "fixed_network_observation_rejected",
    )
    require(
        network["name"] == NETWORK_NAME
        and type(network["identity"]) is str
        and bool(network["identity"])
        and type(network["projection_sha256"]) is str
        and _HEX64.fullmatch(str(network["projection_sha256"])) is not None
        and type(network["member_ids"]) is list
        and network["member_ids"] == sorted(set(network["member_ids"])),
        "fixed_network_observation_rejected",
    )
    old_container = _state_row(
        observation["old_container"],
        {"active", "identity", "name", "policy"},
        "fixed_container_observation_rejected",
    )
    target_container = _state_row(
        observation["target_container"],
        {"active", "identity", "name", "policy"},
        "fixed_container_observation_rejected",
    )
    for row in (old_container, target_container):
        require(
            type(row["active"]) is bool
            and (row["identity"] is None or type(row["identity"]) is str)
            and type(row["name"]) is str
            and type(row["policy"]) is str,
            "fixed_container_observation_rejected",
        )
    archive_name = _state_row(
        observation["archive_name"],
        {"identity", "name", "projection_sha256"},
        "fixed_archive_observation_rejected",
    )
    require(
        type(archive_name["name"]) is str
        and (
            archive_name["state"] == "OLD"
            and archive_name["identity"] is None
            and archive_name["projection_sha256"] is None
            or archive_name["state"] == "TARGET"
            and archive_name["identity"] == ATTEMPT5_OLD_CONTAINER_ID
            and type(archive_name["projection_sha256"]) is str
            and _HEX64.fullmatch(str(archive_name["projection_sha256"])) is not None
            or archive_name["state"] == "THIRD_STATE"
        ),
        "fixed_archive_observation_rejected",
    )
    archive_root = _state_row(
        observation["archive_root"],
        {
            "handle_count",
            "identity",
            "legacy_identity",
            "legacy_name",
            "path",
            "selected_identity",
            "selected_name",
            "selected_state",
        },
        "fixed_archive_observation_rejected",
    )
    selected = selected_memory_runtime(authority)
    require(
        archive_root["path"] == MEMORY_RUNTIME_ROOT
        and archive_root["legacy_name"] == LEGACY_MEMORY_ARCHIVE_ID
        and archive_root["selected_name"] == selected["archive_id"]
        and archive_root["selected_state"] in _STATE
        and (
            archive_root["handle_count"] is None
            or (
                type(archive_root["handle_count"]) is int
                and int(archive_root["handle_count"]) >= 0
            )
        )
        and (
            archive_root["identity"] is None
            or type(archive_root["identity"]) is str
        )
        and (
            archive_root["legacy_identity"] is None
            or type(archive_root["legacy_identity"]) is str
        )
        and (
            archive_root["selected_identity"] is None
            or type(archive_root["selected_identity"]) is str
        )
        and (
            archive_root["state"] != "TARGET"
            or (
                type(archive_root["identity"]) is str
                and type(archive_root["legacy_identity"]) is str
                and archive_root["selected_state"] in {"OLD", "TARGET"}
                and (
                    archive_root["selected_state"] != "TARGET"
                    or type(archive_root["selected_identity"]) is str
                )
                and archive_root["handle_count"] == 0
            )
        ),
        "fixed_archive_observation_rejected",
    )
    return {
        "archive_name": dict(archive_name),
        "archive_root": dict(archive_root),
        "files": files,
        "network": dict(network),
        "old_container": dict(old_container),
        "parent": dict(parent),
        "releases": releases,
        "schema": OBSERVATION_SCHEMA,
        "services": services,
        "target_container": dict(target_container),
    }


def build_fixed_plan(
    authority_value: object,
    observation_value: object,
) -> dict[str, object]:
    authority = validate_source_authority(authority_value)
    observation = validate_observation(observation_value, authority)
    archive_name = ARCHIVE_PREFIX + authority["authority_sha256"][:16]
    require(
        observation["archive_name"]["name"] == archive_name,
        "fixed_archive_observation_rejected",
    )
    plan_body = {
        "archive_name": archive_name,
        "authority": authority,
        "fixed_stages": list(FIXED_STAGES),
        "observation": observation,
        "schema": PLAN_SCHEMA,
        "target_effect": (
            _attempt5_target_effect(authority, observation)
            if observation["archive_name"]["state"] == "TARGET"
            else None
        ),
    }
    return {
        **plan_body,
        "plan_sha256": digest("phase_f_fixed_product_plan", plan_body),
    }


def validate_fixed_plan(value: object) -> dict[str, object]:
    plan = _object(
        value,
        {
            "archive_name",
            "authority",
            "fixed_stages",
            "observation",
            "plan_sha256",
            "schema",
            "target_effect",
        },
        "fixed_plan_rejected",
    )
    require(
        plan["schema"] == PLAN_SCHEMA
        and plan["fixed_stages"] == list(FIXED_STAGES),
        "fixed_plan_rejected",
    )
    authority = validate_source_authority(plan["authority"])
    observation = validate_observation(plan["observation"], authority)
    archive_name = ARCHIVE_PREFIX + authority["authority_sha256"][:16]
    require(
        observation["archive_name"]["name"] == archive_name,
        "fixed_archive_observation_rejected",
    )
    target_effect = (
        _attempt5_target_effect(authority, observation)
        if observation["archive_name"]["state"] == "TARGET"
        else None
    )
    require(
        plan["target_effect"] == target_effect,
        "fixed_target_effect_rejected",
    )
    body = {
        "archive_name": archive_name,
        "authority": authority,
        "fixed_stages": list(FIXED_STAGES),
        "observation": observation,
        "schema": PLAN_SCHEMA,
        "target_effect": target_effect,
    }
    require(
        plan["archive_name"] == body["archive_name"]
        and plan["plan_sha256"] == digest("phase_f_fixed_product_plan", body),
        "fixed_plan_rejected",
    )
    return {**body, "plan_sha256": str(plan["plan_sha256"])}
