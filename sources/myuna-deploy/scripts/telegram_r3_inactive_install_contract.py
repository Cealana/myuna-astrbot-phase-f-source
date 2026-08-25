#!/usr/bin/env python3
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Mapping

from render_telegram_systemd_units_r4 import build_rendered_unit_evidence


SCHEMA = "myuna.astrbot-telegram.r3-inactive-install-plan.v2"
STATUS = "candidate_not_installed_not_active"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_OBJECT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class TelegramInactiveInstallRejected(ValueError):
    """Raised when an inactive-install plan is not exact and fail-closed."""


def canonical_json(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _digest(value: str, label: str) -> str:
    if _SHA256.fullmatch(value) is None:
        raise TelegramInactiveInstallRejected(f"{label} rejected")
    return value


def _git_object(value: str, label: str) -> str:
    if _GIT_OBJECT.fullmatch(value) is None:
        raise TelegramInactiveInstallRejected(f"{label} rejected")
    return value


def build_inactive_install_plan(
    *,
    core_commit: str,
    deploy_commit: str,
    core_release_digest: str,
    gateway_release_digest: str,
) -> dict[str, object]:
    core_commit = _git_object(core_commit, "Core commit")
    deploy_commit = _git_object(deploy_commit, "Deploy commit")
    core_release = _digest(core_release_digest, "Core release")
    gateway_release = _digest(gateway_release_digest, "Gateway release")
    rendered_units = build_rendered_unit_evidence(
        REPOSITORY_ROOT,
        core_release_digest=core_release,
        gateway_release_digest=gateway_release,
    )
    return {
        "artifacts": {
            "core_commit": core_commit,
            "core_release_digest": core_release,
            "core_release_target": f"/srv/myuna/releases/core/{core_release}",
            "deploy_commit": deploy_commit,
            "gateway_release_digest": gateway_release,
            "gateway_release_target": (
                "/opt/myuna/telegram-gateway/releases/" + gateway_release
            ),
        },
        "created_identities": {
            "astrbot_container_uid_gid_source": "myuna-gateway-telegram",
            "linux_group": "myuna-gateway-telegram",
            "linux_user": "myuna-gateway-telegram",
            "login_shell": "/usr/sbin/nologin",
            "single_runtime_identity": True,
            "supplementary_groups": [],
        },
        "forbidden_effects": [
            "read_or_write_secret_values",
            "write_bot_token",
            "write_core_or_channel_credentials",
            "write_owner_binding",
            "run_telegram_discovery",
            "call_telegram_api",
            "modify_database_schema_roles_grants_or_rows",
            "write_core_environment",
            "write_core_systemd_dropin",
            "select_or_activate_core_release",
            "create_approval_marker",
            "enable_start_or_restart_service",
            "add_telegram_identity_to_myuna_group",
            "modify_qq_database_model_memory_definition_network_or_tools",
        ],
        "inactive_runtime": {
            "approval_markers": {
                "/etc/myuna-telegram-gateway/challenge-approved": "absent",
                "/etc/myuna-telegram-gateway/runtime-approved": "absent",
            },
            "core_environment_candidate": (
                "/opt/myuna/telegram-gateway/staging/"
                f"{gateway_release}/core/qq.env"
            ),
            "core_systemd_dropin_candidate": (
                "/opt/myuna/telegram-gateway/staging/"
                f"{gateway_release}/core/telegram-credential.conf"
            ),
            "content_addressed_systemd_units": rendered_units,
            "core_release_access": {
                "base_directory_mode": "0550",
                "base_file_mode": "0440",
                "base_owner_group": "root:myuna",
                "telegram_identity": "myuna-gateway-telegram",
                "telegram_runtime_access": (
                    "exact_release_user_acl_read_execute_only"
                ),
                "wider_myuna_group_membership": False,
            },
            "secrets_directory": {
                "path": "/etc/myuna-telegram-gateway/secrets",
                "required_empty": True,
            },
            "telegram_astrbot": {
                "config_rendered": False,
                "container_state": "absent_or_stopped",
                "token_present": False,
            },
            "service_states": {
                "myuna-telegram-owner-challenge-dev.service": "inactive",
                "myuna-telegram-owner-challenge-dev.socket": "disabled_inactive",
                "myuna-telegram-owner-runtime-dev.service": "inactive",
                "myuna-telegram-owner-runtime-dev.socket": "disabled_inactive",
            },
        },
        "operations": [
            "verify_exact_formal_commits_and_content_addressed_releases",
            "create_nologin_telegram_linux_identity_if_absent",
            "install_immutable_core_release_without_selecting_it",
            "install_immutable_telegram_gateway_release",
            "stage_but_do_not_apply_core_environment_and_dropin",
            "grant_exact_core_release_read_execute_acl_to_telegram_identity",
            "render_content_addressed_telegram_service_and_socket_units",
            "install_telegram_only_units_and_empty_runtime_directories",
            "daemon_reload_once_without_service_lifecycle_operations",
            "verify_markers_absent_units_disabled_and_services_inactive",
            "write_non_sensitive_install_receipt",
        ],
        "schema": SCHEMA,
        "status": STATUS,
    }


def plan_digest(plan: Mapping[str, object]) -> str:
    if plan.get("schema") != SCHEMA or plan.get("status") != STATUS:
        raise TelegramInactiveInstallRejected("inactive install plan rejected")
    return sha256(canonical_json(dict(plan))).hexdigest()
