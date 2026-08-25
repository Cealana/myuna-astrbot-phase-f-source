"""Pure contracts for upgrading one selected Myuna Core release to another.

This module has no filesystem, subprocess, network, systemd, secret, or service
lifecycle capability.  It only builds and validates canonical transaction data.
"""

from __future__ import annotations

from hashlib import sha256
from typing import Mapping

from core_release_selector import (
    ReleaseEvidence,
    RuntimeBinding,
    canonical_json_bytes,
    load_runtime_binding,
    parse_json_document,
)


PLAN_SCHEMA = "myuna.core-release-selector.selected-upgrade-plan.v1"
PLAN_STATUS = "sealed_pending_explicit_owner_approval"
BUNDLE_MANIFEST_SCHEMA = "myuna.core-release-selector.selected-upgrade-bundle.v1"
BUNDLE_STATUS = "work_only_not_installed_not_activated"
UNIT = "myuna-core@qq.service"
INSTANCE = "qq"
SELECTOR_DROPIN = "10-core-release-selector-v1.conf"
TELEGRAM_CREDENTIAL_DROPIN = "15-telegram-http-client-credential-v1.conf"

PLAN_PATH = "activation/UPGRADE_PLAN.json"
TARGET_BINDING_PATH = "target/qq.binding.json"
TARGET_SELECTOR_PATH = f"target/{SELECTOR_DROPIN}"
TARGET_ENV_PATH = "target/qq.env"
TARGET_CREDENTIAL_PATH = f"target/{TELEGRAM_CREDENTIAL_DROPIN}"
ROLLBACK_BINDING_PATH = "rollback/qq.binding.json"
ROLLBACK_SELECTOR_PATH = f"rollback/{SELECTOR_DROPIN}"
ROLLBACK_ENV_PATH = "rollback/qq.env"
MANIFEST_PATH = "TRANSACTION_MANIFEST.json"

LIFECYCLE = (
    "verify exact selected prestate and clean target release",
    "stop QQ Gateway socket before any Core file change",
    "verify QQ Gateway service inactive",
    "stop Core only when prestate records it active",
    "atomically replace binding selector environment and Telegram credential drop-in",
    "systemctl daemon-reload exactly once",
    "start Core and verify loopback health readiness and active selector binding",
    "restore QQ Gateway socket and service to their exact prestate",
)
ROLLBACK = (
    "stop only the Core started by this transaction",
    "restore exact old binding selector and environment",
    "remove the Telegram credential drop-in when it was absent in prestate",
    "systemctl daemon-reload exactly once after file restoration",
    "restore Core and QQ Gateway states to exact prestate",
    "preserve append-only failure journal and do not retry automatically",
)
ALLOWED = (
    "Apply only the digest-bound selected-to-selected Core upgrade bundle.",
    "Change only binding, selector drop-in, qq.env, and the dedicated Telegram credential drop-in.",
    "Use only fixed service lifecycle operations declared in the plan.",
    "Write non-sensitive journal and receipts.",
)
FORBIDDEN = (
    "Read, hash, print, or persist secret values.",
    "Execute arbitrary shell or model-generated commands.",
    "Modify Definition, model routing, memory, Turn Manager, OpenClaw, tools, vision, Minecraft, QQ account, NapCat, AstrBot, or network.",
    "Start the formal Telegram runtime or send any QQ or Telegram message.",
    "Reuse an earlier activation digest, transaction, or failed journal.",
)


class UpgradeContractError(ValueError):
    """Deterministic content-free contract rejection."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise UpgradeContractError(code)


def digest(payload: bytes) -> str:
    require(isinstance(payload, bytes), "payload_bytes_rejected")
    return sha256(payload).hexdigest()


def _digest(value: object, code: str) -> str:
    require(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value),
        code,
    )
    return value


def _commit(value: object, code: str) -> str:
    require(
        isinstance(value, str)
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value),
        code,
    )
    return value


def _exact(value: object, fields: set[str], code: str) -> dict[str, object]:
    require(isinstance(value, dict) and set(value) == fields, code)
    return value


def _digest_map(value: object, code: str) -> dict[str, str]:
    require(isinstance(value, dict), code)
    answer: dict[str, str] = {}
    for name, expected in value.items():
        require(isinstance(name, str) and name and "/" not in name, code)
        answer[name] = _digest(expected, code)
    return answer


def _service_states(value: object) -> dict[str, dict[str, str]]:
    expected_units = {
        UNIT,
        "myuna-qq-owner-runtime-dev.socket",
        "myuna-qq-owner-runtime-dev.service",
    }
    require(isinstance(value, dict) and set(value) == expected_units, "service_states_rejected")
    answer: dict[str, dict[str, str]] = {}
    allowed = {
        UNIT: {("active", "running"), ("inactive", "dead")},
        "myuna-qq-owner-runtime-dev.socket": {
            ("active", "listening"),
            ("active", "running"),
            ("inactive", "dead"),
        },
        "myuna-qq-owner-runtime-dev.service": {
            ("active", "running"),
            ("inactive", "dead"),
        },
    }
    for unit, raw in value.items():
        state = _exact(raw, {"active_state", "sub_state"}, "service_state_rejected")
        pair = (state["active_state"], state["sub_state"])
        require(pair in allowed[unit], "service_state_rejected")
        answer[unit] = {"active_state": pair[0], "sub_state": pair[1]}
    return answer


def _release_payload(release: ReleaseEvidence) -> dict[str, object]:
    require(isinstance(release, ReleaseEvidence), "release_evidence_rejected")
    return release.to_payload()


def build_upgrade_plan(
    *,
    deploy_commit: str,
    core_commit: str,
    current_binding: RuntimeBinding,
    target_release: ReleaseEvidence,
    verifier_sha256: str,
    base_unit_sha256: str,
    prestate_dropin_sha256: Mapping[str, str],
    target_dropin_sha256: Mapping[str, str],
    prestate_qq_env_sha256: str,
    target_qq_env_sha256: str,
    target_selector_sha256: str,
    target_credential_dropin_sha256: str,
    service_states: Mapping[str, Mapping[str, str]],
) -> bytes:
    require(isinstance(current_binding, RuntimeBinding), "current_binding_rejected")
    require(
        current_binding.selected_release.tree_sha256 != target_release.tree_sha256,
        "target_release_must_change",
    )
    prestate_dropins = _digest_map(dict(prestate_dropin_sha256), "prestate_dropins_rejected")
    target_dropins = _digest_map(dict(target_dropin_sha256), "target_dropins_rejected")
    require(
        target_dropins.get(SELECTOR_DROPIN) == target_selector_sha256
        and target_dropins.get(TELEGRAM_CREDENTIAL_DROPIN)
        == target_credential_dropin_sha256
        and set(target_dropins) == set(prestate_dropins) | {TELEGRAM_CREDENTIAL_DROPIN},
        "target_dropin_inventory_rejected",
    )
    states = _service_states({name: dict(state) for name, state in service_states.items()})
    payload = {
        "schema": PLAN_SCHEMA,
        "status": PLAN_STATUS,
        "unit": UNIT,
        "instance": INSTANCE,
        "source": {
            "deploy_commit": _commit(deploy_commit, "deploy_commit_rejected"),
            "core_commit": _commit(core_commit, "core_commit_rejected"),
            "verifier_sha256": _digest(verifier_sha256, "verifier_rejected"),
        },
        "prestate": {
            "binding_sha256": digest(canonical_json_bytes(current_binding.to_payload())),
            "selected_release": _release_payload(current_binding.selected_release),
            "base_unit_sha256": _digest(base_unit_sha256, "base_unit_rejected"),
            "dropin_sha256": dict(sorted(prestate_dropins.items())),
            "qq_env_sha256": _digest(prestate_qq_env_sha256, "prestate_env_rejected"),
            "telegram_credential_dropin_present": False,
            "service_states": states,
            "need_daemon_reload": False,
        },
        "target": {
            "selected_release": _release_payload(target_release),
            "dropin_sha256": dict(sorted(target_dropins.items())),
            "qq_env_sha256": _digest(target_qq_env_sha256, "target_env_rejected"),
            "selector_dropin_sha256": _digest(target_selector_sha256, "target_selector_rejected"),
            "telegram_credential_dropin_sha256": _digest(
                target_credential_dropin_sha256, "target_credential_rejected"
            ),
            "runtime_binding_approval": "this_plan_digest",
        },
        "lifecycle": list(LIFECYCLE),
        "rollback": list(ROLLBACK),
        "scope": {"allowed": list(ALLOWED), "forbidden": list(FORBIDDEN)},
    }
    rendered = canonical_json_bytes(payload)
    load_upgrade_plan(rendered)
    return rendered


def load_upgrade_plan(payload: bytes) -> dict[str, object]:
    require(isinstance(payload, bytes), "plan_bytes_rejected")
    try:
        root = parse_json_document(payload)
    except Exception as exc:
        raise UpgradeContractError("plan_json_rejected") from exc
    root = _exact(
        root,
        {"schema", "status", "unit", "instance", "source", "prestate", "target", "lifecycle", "rollback", "scope"},
        "plan_shape_rejected",
    )
    require(
        root["schema"] == PLAN_SCHEMA
        and root["status"] == PLAN_STATUS
        and root["unit"] == UNIT
        and root["instance"] == INSTANCE,
        "plan_identity_rejected",
    )
    source = _exact(root["source"], {"deploy_commit", "core_commit", "verifier_sha256"}, "plan_source_rejected")
    _commit(source["deploy_commit"], "plan_source_rejected")
    _commit(source["core_commit"], "plan_source_rejected")
    _digest(source["verifier_sha256"], "plan_source_rejected")
    prestate = _exact(
        root["prestate"],
        {"binding_sha256", "selected_release", "base_unit_sha256", "dropin_sha256", "qq_env_sha256", "telegram_credential_dropin_present", "service_states", "need_daemon_reload"},
        "plan_prestate_rejected",
    )
    _digest(prestate["binding_sha256"], "plan_prestate_rejected")
    current = ReleaseEvidence(**{
        "tree_sha256": prestate["selected_release"]["tree_sha256"],
        "source_commit": prestate["selected_release"]["source_commit"],
        "file_count": prestate["selected_release"]["file_count"],
        "artifact_manifest_sha256": prestate["selected_release"]["artifact_manifest_sha256"],
        "installation_receipt_sha256": prestate["selected_release"]["installation_receipt_sha256"],
    })
    require(current.to_payload() == prestate["selected_release"], "plan_current_release_rejected")
    _digest(prestate["base_unit_sha256"], "plan_prestate_rejected")
    prestate_dropins = _digest_map(prestate["dropin_sha256"], "plan_prestate_rejected")
    _digest(prestate["qq_env_sha256"], "plan_prestate_rejected")
    _service_states(prestate["service_states"])
    require(
        prestate["telegram_credential_dropin_present"] is False
        and prestate["need_daemon_reload"] is False,
        "plan_prestate_rejected",
    )
    target = _exact(
        root["target"],
        {"selected_release", "dropin_sha256", "qq_env_sha256", "selector_dropin_sha256", "telegram_credential_dropin_sha256", "runtime_binding_approval"},
        "plan_target_rejected",
    )
    target_release = ReleaseEvidence(**{
        "tree_sha256": target["selected_release"]["tree_sha256"],
        "source_commit": target["selected_release"]["source_commit"],
        "file_count": target["selected_release"]["file_count"],
        "artifact_manifest_sha256": target["selected_release"]["artifact_manifest_sha256"],
        "installation_receipt_sha256": target["selected_release"]["installation_receipt_sha256"],
    })
    target_dropins = _digest_map(target["dropin_sha256"], "plan_target_rejected")
    require(
        target_release.to_payload() == target["selected_release"]
        and target_release.tree_sha256 != current.tree_sha256
        and set(target_dropins) == set(prestate_dropins) | {TELEGRAM_CREDENTIAL_DROPIN}
        and target_dropins[SELECTOR_DROPIN] == target["selector_dropin_sha256"]
        and target_dropins[TELEGRAM_CREDENTIAL_DROPIN] == target["telegram_credential_dropin_sha256"]
        and target["runtime_binding_approval"] == "this_plan_digest",
        "plan_target_rejected",
    )
    _digest(target["qq_env_sha256"], "plan_target_rejected")
    require(
        root["lifecycle"] == list(LIFECYCLE)
        and root["rollback"] == list(ROLLBACK)
        and root["scope"] == {"allowed": list(ALLOWED), "forbidden": list(FORBIDDEN)},
        "plan_policy_rejected",
    )
    require(canonical_json_bytes(root) == payload, "plan_not_canonical")
    return root


def build_upgrade_bundle(
    *,
    plan: bytes,
    target_binding: bytes,
    target_selector: bytes,
    target_qq_env: bytes,
    target_credential_dropin: bytes,
    rollback_binding: bytes,
    rollback_selector: bytes,
    rollback_qq_env: bytes,
) -> dict[str, bytes]:
    root = load_upgrade_plan(plan)
    plan_digest = digest(plan)
    try:
        target_loaded = load_runtime_binding(parse_json_document(target_binding))
        rollback_loaded = load_runtime_binding(parse_json_document(rollback_binding))
    except Exception as exc:
        raise UpgradeContractError("bundle_binding_rejected") from exc
    require(
        target_loaded.approval_plan_digest == plan_digest
        and target_loaded.selected_release.to_payload() == root["target"]["selected_release"]
        and rollback_loaded.selected_release.to_payload() == root["prestate"]["selected_release"]
        and digest(rollback_binding) == root["prestate"]["binding_sha256"],
        "bundle_binding_rejected",
    )
    target_hashes = root["target"]["dropin_sha256"]
    require(
        digest(target_selector) == target_hashes[SELECTOR_DROPIN]
        and digest(target_credential_dropin) == target_hashes[TELEGRAM_CREDENTIAL_DROPIN]
        and digest(target_qq_env) == root["target"]["qq_env_sha256"]
        and digest(rollback_selector) == root["prestate"]["dropin_sha256"][SELECTOR_DROPIN]
        and digest(rollback_qq_env) == root["prestate"]["qq_env_sha256"],
        "bundle_payload_rejected",
    )
    artifacts = {
        PLAN_PATH: plan,
        TARGET_BINDING_PATH: target_binding,
        TARGET_SELECTOR_PATH: target_selector,
        TARGET_ENV_PATH: target_qq_env,
        TARGET_CREDENTIAL_PATH: target_credential_dropin,
        ROLLBACK_BINDING_PATH: rollback_binding,
        ROLLBACK_SELECTOR_PATH: rollback_selector,
        ROLLBACK_ENV_PATH: rollback_qq_env,
    }
    manifest = {
        "schema": BUNDLE_MANIFEST_SCHEMA,
        "status": BUNDLE_STATUS,
        "unit": UNIT,
        "instance": INSTANCE,
        "activation_plan_digest": plan_digest,
        "artifacts": {path: digest(payload) for path, payload in sorted(artifacts.items())},
        "installed": False,
        "activated": False,
        "service_lifecycle_performed": False,
    }
    artifacts[MANIFEST_PATH] = canonical_json_bytes(manifest)
    validate_upgrade_bundle(artifacts)
    return artifacts


def validate_upgrade_bundle(payloads: Mapping[str, bytes]) -> dict[str, object]:
    expected_paths = {
        PLAN_PATH,
        TARGET_BINDING_PATH,
        TARGET_SELECTOR_PATH,
        TARGET_ENV_PATH,
        TARGET_CREDENTIAL_PATH,
        ROLLBACK_BINDING_PATH,
        ROLLBACK_SELECTOR_PATH,
        ROLLBACK_ENV_PATH,
        MANIFEST_PATH,
    }
    require(isinstance(payloads, Mapping) and set(payloads) == expected_paths, "bundle_paths_rejected")
    rebuilt = build_upgrade_bundle_without_validation(payloads)
    require(rebuilt == payloads[MANIFEST_PATH], "bundle_manifest_rejected")
    build_upgrade_bundle_payload_checks(payloads)
    return parse_json_document(payloads[MANIFEST_PATH])


def build_upgrade_bundle_without_validation(payloads: Mapping[str, bytes]) -> bytes:
    plan = load_upgrade_plan(payloads[PLAN_PATH])
    manifest = {
        "schema": BUNDLE_MANIFEST_SCHEMA,
        "status": BUNDLE_STATUS,
        "unit": UNIT,
        "instance": INSTANCE,
        "activation_plan_digest": digest(payloads[PLAN_PATH]),
        "artifacts": {
            path: digest(payload)
            for path, payload in sorted(payloads.items())
            if path != MANIFEST_PATH
        },
        "installed": False,
        "activated": False,
        "service_lifecycle_performed": False,
    }
    require(plan["unit"] == UNIT, "bundle_plan_rejected")
    return canonical_json_bytes(manifest)


def build_upgrade_bundle_payload_checks(payloads: Mapping[str, bytes]) -> None:
    plan = load_upgrade_plan(payloads[PLAN_PATH])
    plan_digest = digest(payloads[PLAN_PATH])
    try:
        target_binding = load_runtime_binding(parse_json_document(payloads[TARGET_BINDING_PATH]))
        rollback_binding = load_runtime_binding(parse_json_document(payloads[ROLLBACK_BINDING_PATH]))
    except Exception as exc:
        raise UpgradeContractError("bundle_binding_rejected") from exc
    require(
        target_binding.approval_plan_digest == plan_digest
        and target_binding.selected_release.to_payload() == plan["target"]["selected_release"]
        and rollback_binding.selected_release.to_payload() == plan["prestate"]["selected_release"]
        and digest(payloads[ROLLBACK_BINDING_PATH]) == plan["prestate"]["binding_sha256"]
        and digest(payloads[TARGET_SELECTOR_PATH]) == plan["target"]["selector_dropin_sha256"]
        and digest(payloads[TARGET_ENV_PATH]) == plan["target"]["qq_env_sha256"]
        and digest(payloads[TARGET_CREDENTIAL_PATH]) == plan["target"]["telegram_credential_dropin_sha256"]
        and digest(payloads[ROLLBACK_SELECTOR_PATH]) == plan["prestate"]["dropin_sha256"][SELECTOR_DROPIN]
        and digest(payloads[ROLLBACK_ENV_PATH]) == plan["prestate"]["qq_env_sha256"],
        "bundle_payload_rejected",
    )

