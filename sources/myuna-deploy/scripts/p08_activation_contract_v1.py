#!/usr/bin/env python3
"""Single generated contract authority for the P08 activation engine.

This module intentionally owns every phase, role, schema, budget, result class
and compatibility binding used by the reset architecture.  Consumers validate
the compiled contract; they do not repeat these values as local allowlists.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Any, Mapping


ARCHITECTURE = "myuna.p08-activation-engine.v1"
CONTRACT_SCHEMA = "myuna.p08-activation-contract.v1"
PLAN_SCHEMA = "myuna.p08-activation-plan.v1"
RESULT_SCHEMA = "myuna.p08-activation-result.v1"
CAPTURE_SCHEMA = "myuna.p08-activation-capture.v1"
EVIDENCE_SCHEMA = "myuna.p08-activation-evidence.v1"
INVOCATION_SCHEMA = "myuna.p08-activation-invocation.v1"
PROGRESS_SCHEMA = "myuna.p08-activation-progress.v1"
SHADOW_SCHEMA = "myuna.p08-activation-shadow-result.v1"
STATE_MACHINE_SCHEMA = "myuna.p08-activation-state-machine.v1"
LEGACY_INDEX_SCHEMA = "myuna.p08-legacy-lineage-index.v1"
ENGINE_SOURCE_SCHEMA = "myuna.p08-activation-engine-source.v1"
PRODUCTION_ADAPTER_SCHEMA = "myuna.p08-activation-production-adapter.v1"
EXECUTION_SCHEMA = "myuna.p08-activation-execution.v2"
PUBLIC_FILE_SCHEMA = "myuna.p08-activation-public-file.v1"
OPAQUE_STATE_SCHEMA = "myuna.p08-activation-opaque-state-metadata.v1"
ACCOUNT_PROJECTION_SCHEMA = "myuna.p08-activation-account-projection.v2"
UNIT_STATE_SCHEMA = "myuna.p08-activation-unit-state.v6"
UNIT_SEMANTICS_SCHEMA = "myuna.p08-activation-unit-semantics.v1"
UNIT_RUNTIME_SCHEMA = "myuna.p08-activation-effective-unit-runtime.v4"
SYSTEMD_EFFECTIVE_UNIT_MODEL_SCHEMA = (
    "myuna.p08-systemd255-effective-unit-model.v1"
)
UNIT_ENABLEMENT_POLICY_SCHEMA = "myuna.p08-unit-enablement-policy.v1"
UNIT_COUPLED_STATE_SCHEMA = "myuna.p08-unit-coupled-state-machine.v1"
EXECUTION_SUBSTRATE_SCHEMA = "myuna.p08-execution-substrate.v1"
PROCESS_IDENTITY_SCHEMA = "myuna.p08-service-process-identity.v1"
NUMERIC_CREDENTIAL_LAUNCH_SCHEMA = "myuna.p08-numeric-credential-launch.v1"
RUNTIME_PACKAGE_SCHEMA = "myuna.p08-materialized-runtime.v1"
PREDECESSOR_RELEASE_SCHEMA = "myuna.p08-activation-predecessor-release.v2"
PREDECESSOR_CLIENT_ROLES_SCHEMA = "myuna.p08-predecessor-client-roles.v1"
JOURNAL_SCHEMA = "myuna.p08-activation-production-journal.v1"
LEDGER_SCHEMA = "myuna.p08-activation-production-ledger.v1"
OPAQUE_BACKUP_SCHEMA = "myuna.p08-activation-opaque-backup.v1"
CONTINUITY_BINDING_SCHEMA = "myuna.p08-activation-continuity-binding.v1"
UNIT_RECEIPT_SCHEMA = "myuna.p08-activation-unit-receipt.v5"
ACCEPTANCE_RECEIPT_SCHEMA = "myuna.p08-activation-acceptance-receipt.v2"
SUPERVISOR_RECEIPT_SCHEMA = "myuna.p08-activation-supervisor-receipt.v1"
ROLE_INTENT_SCHEMA = "myuna.p08-activation-role-intent.v1"
SUPERVISOR_FAILURE_SCHEMA = "myuna.p08-activation-supervisor-failure.v1"
SUPERVISOR_ENTRY_SCHEMA = "myuna.p08-activation-supervisor-entry.v1"
SUPERVISOR_PRECLAIM_RESULT_SCHEMA = (
    "myuna.p08-activation-supervisor-preclaim-result.v2"
)
SUPERVISOR_BOOTSTRAP_SCHEMA = "myuna.p08-activation-supervisor-bootstrap.v1"
SUPERVISOR_BOOTSTRAP_CAPTURE_SCHEMA = (
    "myuna.p08-activation-supervisor-bootstrap-capture.v1"
)
SUPERVISOR_BOOTSTRAP_INTENT_SCHEMA = (
    "myuna.p08-activation-supervisor-bootstrap-intent.v1"
)
TOP_LEVEL_ENTRY_SCHEMA = "myuna.p08-activation-top-level-entry.v1"
TOP_LEVEL_ENTRY_INTENT_SCHEMA = (
    "myuna.p08-activation-top-level-entry-intent.v1"
)
TOP_LEVEL_ENTRY_CAPTURE_SCHEMA = (
    "myuna.p08-activation-top-level-entry-capture.v2"
)
TOP_LEVEL_ENTRY_RESULT_SCHEMA = (
    "myuna.p08-activation-top-level-entry-result.v3"
)
WINDOWS_WSL_TRANSPORT_SCHEMA = "myuna.p08-windows-wsl-direct-transport.v1"
WINDOWS_WSL_CAPTURE_SCHEMA = "myuna.p08-windows-wsl-direct-capture.v1"
WINDOWS_WSL_CAPTURE_PERSIST_RESULT_SCHEMA = (
    "myuna.p08-windows-wsl-capture-persist-result.v1"
)
WINDOWS_HOST_LAUNCHER_SCHEMA = "myuna.p08-windows-host-launcher.v1"
SUPERVISOR_OUTER_TERMINAL_SCHEMA = (
    "myuna.p08-activation-supervisor-outer-terminal.v1"
)
SUPERVISOR_GUARDIAN_OBLIGATION_SCHEMA = (
    "myuna.p08-activation-supervisor-guardian-obligation.v1"
)
SUPERVISOR_GUARDIAN_MANAGER_INTENT_SCHEMA = (
    "myuna.p08-activation-supervisor-guardian-manager-intent.v1"
)
SUPERVISOR_GUARDIAN_TRANSIENT_SCHEMA = (
    "myuna.p08-activation-supervisor-guardian-transient.v1"
)
SUPERVISOR_GUARDIAN_TRANSIENT_SUBMISSION_SCHEMA = (
    "myuna.p08-activation-supervisor-guardian-transient-submission.v1"
)
SUPERVISOR_GUARDIAN_GENERATION_SCHEMA = (
    "myuna.p08-activation-supervisor-guardian-generation.v1"
)
SUPERVISOR_GUARDIAN_CHILD_SCHEMA = (
    "myuna.p08-activation-supervisor-guardian-child.v1"
)
SUPERVISOR_GUARDIAN_TERMINAL_SCHEMA = (
    "myuna.p08-activation-supervisor-guardian-terminal.v1"
)
SUPERVISOR_GUARDIAN_DISCHARGE_SCHEMA = (
    "myuna.p08-activation-supervisor-guardian-discharge.v1"
)
SUPERVISOR_STRATEGY_LAUNCH_CLAIM_SCHEMA = (
    "myuna.p08-activation-strategy-launch-claim.v1"
)
SUPERVISOR_STRATEGY_LAUNCH_TERMINAL_SCHEMA = (
    "myuna.p08-activation-strategy-launch-terminal.v1"
)
SUPERVISOR_STRATEGY_LAUNCH_PREMUTATION_TERMINAL_SCHEMA = (
    "myuna.p08-activation-strategy-launch-premutation-terminal.v1"
)
BOOT_RECOVERY_CONTRACT_SCHEMA = "myuna.p08-boot-recovery-contract.v1"
BOOT_RECOVERY_CLOSURE_SCHEMA = "myuna.p08-boot-recovery-closure.v1"
BOOT_RECOVERY_ARM_SCHEMA = "myuna.p08-boot-recovery-arm.v1"
BOOT_RECOVERY_DISARM_SCHEMA = "myuna.p08-boot-recovery-disarm.v1"
BOOT_RECOVERY_OWNER_SCHEMA = "myuna.p08-boot-recovery-owner.v1"
BOOT_RECOVERY_TERMINAL_SCHEMA = "myuna.p08-boot-recovery-terminal.v1"
BOOT_RECOVERY_STATE_MACHINE_SCHEMA = "myuna.p08-boot-recovery-state-machine.v1"
BOOT_RECOVERY_ENTRY_SCHEMA = "myuna.p08-boot-recovery-entry.v1"
BOOT_RECOVERY_UNIT_STATE_SCHEMA = "myuna.p08-boot-recovery-unit-state.v1"
BOOT_RECOVERY_REENTRY_SCHEMA = "myuna.p08-boot-recovery-reentry.v1"
BOOT_RECOVERY_TRANSACTION_SCHEMA = (
    "myuna.p08-boot-recovery-transaction-liveness.v1"
)
RECOVERY_INFRASTRUCTURE_MODEL_SCHEMA = (
    "myuna.p08-recovery-infrastructure-systemd255-model.v1"
)
RECOVERY_INFRASTRUCTURE_OBLIGATION_SCHEMA = (
    "myuna.p08-recovery-infrastructure-obligation.v2"
)
RECOVERY_INFRASTRUCTURE_INTENT_SCHEMA = (
    "myuna.p08-recovery-infrastructure-prefix-intent.v1"
)
RECOVERY_INFRASTRUCTURE_EVENT_SCHEMA = (
    "myuna.p08-recovery-infrastructure-event.v2"
)
RECOVERY_INFRASTRUCTURE_CONVERGENCE_SCHEMA = (
    "myuna.p08-recovery-infrastructure-convergence.v2"
)
RECOVERY_RESIDUE_NORMALIZATION_PLAN_SCHEMA = (
    "myuna.p08-recovery-residue-normalization-plan.v1"
)

# This ordered table is the sole source of pre-claim phase and rejection
# authority.  Bootstrap, launcher, adapter, Windows transport and tests consume
# the generated projection below; none keeps a separate category allowlist.
PRECLAIM_PHASE_DEFINITIONS = (
    ("arguments", ("bootstrap_arguments_rejected",)),
    ("contract", ("bootstrap_contract_rejected",)),
    ("top_level_intent", ("bootstrap_top_level_intent_rejected",)),
    ("target_closure", ("bootstrap_target_rejected",)),
    (
        "parent_process",
        ("bootstrap_process_rejected", "bootstrap_source_identity_rejected"),
    ),
    ("execution_contract", ("bootstrap_execution_contract_rejected",)),
    ("execution_arguments", ("bootstrap_execution_arguments_rejected",)),
    ("execution_public", ("bootstrap_execution_public_rejected",)),
    ("execution_selector", ("bootstrap_execution_selector_rejected",)),
    ("execution_predecessor", ("bootstrap_execution_predecessor_rejected",)),
    ("execution_opaque_metadata", ("bootstrap_execution_opaque_rejected",)),
    ("execution_accounts", ("bootstrap_execution_accounts_rejected",)),
    (
        "execution_unit_accounts",
        ("bootstrap_execution_unit_accounts_rejected",),
    ),
    ("execution_environment", ("bootstrap_execution_environment_rejected",)),
    (
        "execution_predecessor_public",
        ("bootstrap_execution_predecessor_public_rejected",),
    ),
    ("execution_target", ("bootstrap_execution_target_rejected",)),
    ("execution_systemd", ("bootstrap_execution_systemd_rejected",)),
    ("execution_units", ("bootstrap_execution_units_rejected",)),
    ("execution_validation", ("bootstrap_execution_validation_rejected",)),
    ("prestate_identity", ("bootstrap_prestate_identity_rejected",)),
    ("nonce", ("bootstrap_nonce_rejected",)),
    (
        "strategy_namespace",
        (
            "bootstrap_namespace_rejected",
            "bootstrap_strategy_already_claimed",
            "bootstrap_strategy_preclaim_residue_rejected",
        ),
    ),
    ("strategy_claim", ("bootstrap_strategy_claim_rejected",)),
)
PRECLAIM_UNEXPECTED_CATEGORY = "bootstrap_unexpected_preclaim_failure"
PRECLAIM_CONTRACT_SUBCATEGORY = "contract_validation_rejected"
PRECLAIM_UNEXPECTED_SUBCATEGORY = "unexpected_unclassified"

# Exact adapter categories reachable in each reviewed construct-execution
# phase.  This table is generated into the pre-claim contract and is the only
# place where the adapter's content-free cause vocabulary is authorized.
PRECLAIM_ADAPTER_SUBCATEGORIES = {
    "execution_arguments": (
        "execution_backend_rejected",
        "execution_root_rejected",
        "target_source_identity_rejected",
    ),
    "execution_public": (
        "file_identity_rejected",
        "file_read_rejected",
        "path_identity_rejected",
    ),
    "execution_selector": (
        "canonical_json_rejected",
        "file_read_rejected",
        "selector_compatibility_rejected",
        "selector_identity_rejected",
    ),
    "execution_predecessor": (
        "file_identity_rejected",
        "file_read_rejected",
        "predecessor_release_rejected",
        "target_bytecode_rejected",
        "target_directory_inventory_rejected",
        "target_import_substitution_rejected",
        "target_inventory_rejected",
        "target_manifest_binding_rejected",
        "tree_shape_rejected",
        "unit_semantics_rejected",
    ),
    "execution_opaque_metadata": (
        "directory_identity_rejected",
        "opaque_state_metadata_rejected",
        "path_identity_rejected",
        "tree_shape_rejected",
    ),
    "execution_accounts": (
        "account_projection_rejected",
        "canonical_json_rejected",
        "file_read_rejected",
    ),
    "execution_unit_accounts": (
        "file_read_rejected",
        "unit_account_binding_rejected",
        "unit_semantics_rejected",
    ),
    "execution_environment": (
        "environment_projection_rejected",
        "file_read_rejected",
        "gateway_identity_rejected",
    ),
    "execution_predecessor_public": (
        "environment_lineage_rejected",
        "predecessor_public_identity_rejected",
        "selector_lineage_rejected",
        "unit_semantics_rejected",
    ),
    "execution_target": (
        "file_identity_rejected",
        "file_read_rejected",
        "target_bytecode_rejected",
        "target_directory_inventory_rejected",
        "target_import_substitution_rejected",
        "target_inventory_rejected",
        "target_manifest_binding_rejected",
        "target_manifest_rejected",
        "tree_shape_rejected",
    ),
    "execution_systemd": (
        "execution_substrate_rejected",
        "file_identity_rejected",
        "file_read_rejected",
    ),
    "execution_units": (
        "execution_substrate_rejected",
        "service_process_identity_rejected",
        "socket_inode_rejected",
        "unit_dependency_injection_rejected",
        "unit_effective_closure_rejected",
        "unit_effective_dependency_rejected",
        "unit_effective_dropin_rejected",
        "unit_effective_exec_rejected",
        "unit_effective_policy_rejected",
        "unit_state_rejected",
        "unit_trigger_relation_rejected",
    ),
}
TOP_LEVEL_BASE_FAILURE_CATEGORIES = (
    "arguments_rejected",
    "contract_rejected",
    "target_rejected",
    "loaded_runtime_rejected",
    "intent_rejected",
    "process_identity_rejected",
    "intent_persistence_rejected",
    "capture_rejected",
    "capture_persistence_rejected",
    "result_persistence_rejected",
    "result_readback_rejected",
    "child_capture_indeterminate",
    "child_preclaim_evidence_rejected",
    "child_result_indeterminate",
)


def _preclaim_phase_rows() -> list[dict[str, object]]:
    return [
        {
            "ordinal": ordinal,
            "phase": phase,
            "rejection_categories": list(categories),
            "synthetic_adapter_fault_kinds": [
                {
                    "fault_kind": f"preclaim_{phase}_adapter_{subcategory}",
                    "subcategory": subcategory,
                }
                for subcategory in PRECLAIM_ADAPTER_SUBCATEGORIES.get(phase, ())
            ],
            "subcategory_sources": {
                "adapter": list(PRECLAIM_ADAPTER_SUBCATEGORIES.get(phase, ())),
                "bootstrap": list(categories),
                "contract": [PRECLAIM_CONTRACT_SUBCATEGORY],
                "unexpected": [PRECLAIM_UNEXPECTED_SUBCATEGORY],
            },
            "synthetic_fault_kind": f"preclaim_{phase}_rejected",
        }
        for ordinal, (phase, categories) in enumerate(
            PRECLAIM_PHASE_DEFINITIONS, start=1
        )
    ]


def _preclaim_contract() -> dict[str, object]:
    phases = _preclaim_phase_rows()
    return {
        "schema": SUPERVISOR_PRECLAIM_RESULT_SCHEMA,
        "result_filename": "PRECLAIM.RESULT.json",
        "ordered_phases": phases,
        "phase_map_digest": digest_value(phases),
        "unexpected_category": PRECLAIM_UNEXPECTED_CATEGORY,
        "typed_status": "rejected",
        "unexpected_status": "indeterminate",
        "product_mutation_state": "unmodified",
        "persistence": {
            "mode": 0o600,
            "o_excl": True,
            "fsync": True,
            "read_back_exact": True,
            "top_level_completion_allowed": True,
        },
        "zero_state_fields": [
            "action_started",
            "backup_created",
            "guardian_created",
            "incident_created",
            "launch_claim_created",
            "plan_created",
            "product_mutated",
            "strategy_root_created",
        ],
    }

SYNTHETIC_FAULT_KINDS = frozenset(
    {
        None,
        "rejected",
        "indeterminate",
        "outer_kill_before_plan",
        "outer_kill_after_mutation",
        "outer_noncanonical_after_mutation",
        "outer_oversized_after_mutation",
        "outer_kill_after_mutation_recovery_rejected",
        "guardian_capture_create_failed_after_mutation",
        "guardian_capture_write_failed_after_mutation",
        "guardian_capture_fsync_failed_after_mutation",
        "guardian_capture_readback_failed_after_mutation",
        "guardian_capture_validation_failed_after_mutation",
        "guardian_recovery_capture_persist_failed",
        "guardian_accepted_result_persist_failed",
        "guardian_accepted_terminal_persist_failed",
        "guardian_discharge_persist_failed",
        "guardian_hardstop_terminal_persist_failed",
        "guardian_bootstrap_sigkill_after_mutation",
        "guardian_manager_sigkill_after_plan",
        "guardian_manager_sigkill_after_mutation",
        "guardian_manager_sigkill_after_accepted_result",
        "guardian_manager_sigkill_after_accepted_terminal",
        "guardian_manager_sigkill_after_discharge",
        "guardian_obligation_persist_failed_before_plan",
        "preclaim_unexpected_exception",
    }
    | {row["synthetic_fault_kind"] for row in _preclaim_phase_rows()}
    | {
        fault["fault_kind"]
        for row in _preclaim_phase_rows()
        for fault in row["synthetic_adapter_fault_kinds"]
    }
    | {
        f"partial_{prefix}_{outcome}"
        for prefix in (
            "runtime_package",
            "recovery_unit",
            "recovery_enablement",
            "daemon_reload",
            "recovery_unit_start_no_arm",
            "closure_readback",
            "arm",
            "service_recovery_dropin",
            "socket_recovery_dropin",
            "product_gate_reload",
        )
        for outcome in ("rejected", "indeterminate")
    }
    | {
        f"intraprefix_{prefix}_{boundary}_{outcome}"
        for prefix in (
            "runtime_package",
            "recovery_unit",
            "recovery_enablement",
            "daemon_reload",
            "recovery_unit_start_no_arm",
            "closure_readback",
            "arm",
            "service_recovery_dropin",
            "socket_recovery_dropin",
            "product_gate_reload",
        )
        for boundary in (
            "pre_intent",
            "post_intent",
            "parent_ready",
            "stage_open",
            "stage_write",
            "stage_chmod",
            "stage_chown",
            "stage_fsync",
            "stage_readback",
            "stage_directory_open",
            "stage_directory_chmod",
            "stage_directory_chown",
            "stage_directory_fsync",
            "stage_file_open",
            "stage_file_write",
            "stage_file_chmod",
            "stage_file_chown",
            "stage_file_fsync",
            "stage_file_pre_publish",
            "stage_file_post_publish",
            "stage_file_readback",
            "stage_tree_readback",
            "pre_publish",
            "post_publish",
            "pre_effect",
            "post_effect",
            "pre_event",
            "post_event",
        )
        for outcome in ("rejected", "indeterminate", "kill")
    }
)
SOCKET_INODE_SCHEMA = "myuna.p08-activation-socket-inode.v1"
SELECTOR_SCHEMA = "myuna.p08-active-temporal-selector.v1"
RELEASE_SCHEMA = "myuna.p08-active-temporal-code-release.v3"
RELEASE_MANIFEST_KEYS = frozenset(
    {
        "activation_engine_contract",
        "core_commit",
        "current_selected_upgrade_contract",
        "deploy_commit",
        "entrypoint",
        "files",
        "formal_preflight_launcher_contract",
        "forward_continuity_contract",
        "gateway_client",
        "gateway_status_runtime",
        "legacy_activation_architecture_authoritative",
        "p07_single_nonce_integration",
        "post_target_action_contract",
        "protocol_contract",
        "protocol_schema",
        "runtime_profile",
        "schema",
        "service_contract",
        "state_schema",
        "trusted_time_capability_contract",
        "trusted_time_schema",
        "upgrade_compatibility",
    }
)

HEX64 = re.compile(r"^[0-9a-f]{64}$")
COMMIT40 = re.compile(r"^[0-9a-f]{40}$")
ROLE_NAME = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
SAFE_UNIT = re.compile(r"^[a-z0-9][a-z0-9_.@-]{1,127}$")
SYSTEMD_SPECIAL_UNIT_NAMES = ("-.mount",)


def is_safe_unit_name(value: object) -> bool:
    """Validate the reviewed systemd-255 unit-name subset.

    The root mount has the special escaped identity ``-.mount``.  It is the
    only accepted leading-hyphen name; accepting the general shape would turn
    malformed or caller-substituted dependency tokens into authority.
    """

    return isinstance(value, str) and (
        SAFE_UNIT.fullmatch(value) is not None
        or value in SYSTEMD_SPECIAL_UNIT_NAMES
    )

PRODUCTION_ADAPTER_PATH = "scripts/p08_activation_production_adapter_v1.py"
BOOT_RECOVERY_PATH = "scripts/p08_activation_boot_recovery_v1.py"
SUPERVISOR_BOOTSTRAP_PATH = "scripts/p08_activation_supervisor_bootstrap_v1.py"
TOP_LEVEL_ENTRY_PATH = "scripts/p08_activation_top_level_entry_v1.py"
WINDOWS_CAPTURE_PERSIST_PATH = (
    "scripts/p08_activation_windows_capture_persist_v1.py"
)
WINDOWS_HOST_LAUNCHER_SOURCE_PATH = (
    "scripts/p08_activation_windows_entry_v1.cs"
)
WINDOWS_HOST_LAUNCHER_BASE64_PATH = (
    "scripts/p08_activation_windows_entry_v1.exe.b64"
)
WINDOWS_HOST_LAUNCHER_ARTIFACT_PATH = (
    "windows/P08ActivationWindowsEntryV1.exe"
)
SUPERVISOR_GUARDIAN_MANAGER_PATH = (
    "scripts/p08_activation_guardian_manager_v1.py"
)
REQUIRED_ENGINE_SOURCE_PATHS = (
    BOOT_RECOVERY_PATH,
    "scripts/p08_activation_contract_v1.py",
    "scripts/p08_activation_credential_probe_v1.py",
    "scripts/p08_activation_engine_v1.py",
    SUPERVISOR_GUARDIAN_MANAGER_PATH,
    "scripts/p08_activation_launcher_v1.py",
    PRODUCTION_ADAPTER_PATH,
    SUPERVISOR_BOOTSTRAP_PATH,
    "scripts/p08_activation_supervisor_v1.py",
    TOP_LEVEL_ENTRY_PATH,
    WINDOWS_CAPTURE_PERSIST_PATH,
    WINDOWS_HOST_LAUNCHER_SOURCE_PATH,
    WINDOWS_HOST_LAUNCHER_BASE64_PATH,
    "scripts/p08_forward_continuity_orchestration_v1.py",
    "scripts/p08_temporal_gateway_v1.py",
)
PUBLIC_ROLES = ("environment", "selector", "service_unit", "socket_unit")
PREDECESSOR_RUNTIME_OPERATIONS = ("confirm", "propose", "retrieve")
PREDECESSOR_STATUS_OPERATIONS = (
    "confirm",
    "propose",
    "retrieve",
    "snapshot_active",
    "status_content_free",
)
PRODUCTION_PATHS = {
    "boot_recovery_arm": "/var/lib/myuna-activation-backups/p08-activation-engine-v1/BOOT.RECOVERY.ARM.json",
    "boot_recovery_boots": "/var/lib/myuna-activation-backups/p08-activation-engine-v1/boot-recovery",
    "boot_recovery_disarm": "/var/lib/myuna-activation-backups/p08-activation-engine-v1/BOOT.RECOVERY.DISARM.json",
    "environment": "/etc/myuna-active-temporal-context-v1/selector.env",
    "recovery_enablement": "/etc/systemd/system/multi-user.target.wants/myuna-p08-activation-recovery-v1.service",
    "recovery_runtime_root": "/usr/lib/myuna/p08-activation-engine-v1/recovery-runtime",
    "recovery_unit": "/etc/systemd/system/myuna-p08-activation-recovery-v1.service",
    "recovery_unit_name": "myuna-p08-activation-recovery-v1.service",
    "release_root": "/opt/myuna/active-temporal/releases",
    "selector": "/etc/myuna-active-temporal-context-v1/selector.json",
    "service_name": "myuna-active-temporal-context-v1.service",
    "service_recovery_dropin": "/etc/systemd/system/myuna-active-temporal-context-v1.service.d/10-p08-activation-recovery.conf",
    "service_unit": "/etc/systemd/system/myuna-active-temporal-context-v1.service",
    "socket_name": "myuna-active-temporal-context-v1.socket",
    "socket_endpoint": "/run/myuna-active-temporal-context-v1/temporal.sock",
    "socket_unit": "/etc/systemd/system/myuna-active-temporal-context-v1.socket",
    "socket_recovery_dropin": "/etc/systemd/system/myuna-active-temporal-context-v1.socket.d/10-p08-activation-recovery.conf",
    "state_root": "/var/lib/myuna-active-temporal-context-v1",
    "strategy_root": "/var/lib/myuna-activation-backups/p08-activation-engine-v1",
    "synthetic_account_state": "/var/lib/myuna-activation-engine-v1/account-state.json",
    "synthetic_recovery_state": "/var/lib/myuna-activation-engine-v1/recovery-state.json",
    "synthetic_unit_state": "/var/lib/myuna-activation-engine-v1/unit-state.json",
    "top_level_entry_root": "/var/lib/myuna-activation-entry-captures/p08-activation-engine-v1",
}

PRODUCTION_ACCOUNTS = {
    "gateway": {
        "gid": 982,
        "groups": [{"gid": 982, "name": "myuna-gateway-telegram"}],
        "primary_group": "myuna-gateway-telegram",
        "uid": 988,
        "user": "myuna-gateway-telegram",
    },
    "service": {
        "gid": 976,
        "groups": [{"gid": 976, "name": "myuna_active_temporal"}],
        "primary_group": "myuna_active_temporal",
        "uid": 976,
        "user": "myuna_active_temporal",
    },
}

# This is the sole source authority for the privileged host substrate used by
# the production adapter.  A package upgrade intentionally requires a new
# source/build review; construct may never bless an arbitrary current binary.
PRODUCTION_INTERPRETER = {
    "invocation_path": "/usr/bin/python3",
    "invocation_type": "symlink",
    "link_target": "python3.12",
    "mode": 0o755,
    "nlink": 1,
    "resolved_path": "/usr/bin/python3.12",
    "sha256": "1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118",
    "size": 8020928,
    "uid": 0,
    "gid": 0,
    "version_identity": "cpython-3.12.3",
}

# The Windows binary is transport only: it receives no product authority and
# cannot construct a plan.  The guest entrypoint reopens/validates this exact
# identity and then owns the one bootstrap child/capture boundary.  A Windows
# or WSL update intentionally requires a new source/build/full-chain review.
PRODUCTION_WINDOWS_WSL_TRANSPORT = {
    "schema": WINDOWS_WSL_TRANSPORT_SCHEMA,
    "windows_path": r"C:\WINDOWS\System32\wsl.exe",
    "guest_visible_path": "/mnt/c/Windows/System32/wsl.exe",
    "sha256": "3af4b1b77b118d01a74cd21c3542f684c173353251dbc6609955c053b4ed8b02",
    "size": 258048,
    "guest_mode": 0o544,
    "guest_uid": 1000,
    "guest_gid": 1000,
    "guest_nlink": 2,
    "version_authority": "pe_bytes_sha256",
    "distribution": "Server-Ubuntu",
    "kernel_release": "6.18.33.2-microsoft-standard-WSL2",
    "direct_exec": True,
    "host_shell_allowed": False,
    "guest_shell_allowed": False,
    "outer_descriptor_types": {"stdin": "fifo", "stdout": "fifo", "stderr": "fifo"},
    "outer_stdin_consumed": False,
    "child_stdin_target": "/dev/null",
    "host_stderr_classifications": [
        {
            "size": 0,
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
        {
            "size": 132,
            "sha256": "b280c454d6f559e56eb3f5ed39f3ba084b8d1744a3ff7fe016b21ff86dea1aca",
        },
    ],
}

# The checked-in base64 is the immutable, independently hashable materialized
# form of the reviewed C# source.  The release builder decodes it without a
# host shell and rejects every byte/size/source mismatch.  Rebuilding or
# changing the Windows/CLR substrate requires a new source/build review.
PRODUCTION_WINDOWS_HOST_LAUNCHER = {
    "schema": WINDOWS_HOST_LAUNCHER_SCHEMA,
    "source_path": WINDOWS_HOST_LAUNCHER_SOURCE_PATH,
    "source_sha256": "ef90b8c0a81dc9dadc3b718ae31c796b0fbbb7d7eb8d24ffc9b0f0f8f681ab1b",
    "base64_path": WINDOWS_HOST_LAUNCHER_BASE64_PATH,
    "artifact_path": WINDOWS_HOST_LAUNCHER_ARTIFACT_PATH,
    "sha256": "0eafbb29d14e5829386b2dd53685460f4a498991ea051ff1687b654c63f5b23f",
    "size": 29696,
    "clr_version": "4.0.30319.42000",
    "clr_path": r"C:\WINDOWS\Microsoft.NET\Framework64\v4.0.30319\clr.dll",
    "clr_sha256": "594b9e5daf414584e967c681f04a36b495d7cd39c18e1c45ff0632d511c1888e",
    "clr_size": 10000696,
    "mscorlib_path": r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll",
    "mscorlib_sha256": "a8cae3d326f7d973ca79cba849939d4837ad18d507ef6d5f6ebab802b7fb157a",
    "mscorlib_size": 5445432,
    "direct_create_process": True,
    "explicit_handle_allowlist": True,
    "host_shell_allowed": False,
    "kill_on_close_job": True,
    "closed_parent_stdin": True,
    "capture_schema": WINDOWS_WSL_CAPTURE_SCHEMA,
    "hard_deadline_seconds": 7270,
    "stdout_limit": 1_048_576,
    "stderr_limit": 65_536,
    "raw_output_retained": False,
}

PRODUCTION_SYSTEMD = {
    "schema": EXECUTION_SUBSTRATE_SCHEMA,
    "package_identity": "systemd-255.4-1ubuntu8.16-amd64",
    "manager": {
        "path": "/usr/lib/systemd/systemd",
        "mode": 0o755,
        "uid": 0,
        "gid": 0,
        "nlink": 1,
        "size": 100816,
        "sha256": "21941483d0d463b590b2bfb8ca818c81e70fd1f7f6b98d92e75395b90495f742",
    },
    "manager_proc_exe": "/proc/1/exe",
    "systemctl": {
        "path": "/usr/bin/systemctl",
        "mode": 0o755,
        "uid": 0,
        "gid": 0,
        "nlink": 1,
        "size": 1501304,
        "sha256": "7ba82b5ba146759c710e1b80fadaa3fdbc0f9b85c8fb2c8c3196b7b1a0037ef8",
    },
    "systemd_run": {
        "path": "/usr/bin/systemd-run",
        "mode": 0o755,
        "uid": 0,
        "gid": 0,
        "nlink": 1,
        "size": 68392,
        "sha256": "49f0bf95eb8a781b93853bf9fc981b4929dd0009f55a3e6db95534c0a2d11716",
    },
    "environment_scrubber": {
        "path": "/usr/bin/env",
        "mode": 0o755,
        "uid": 0,
        "gid": 0,
        "nlink": 1,
        "size": 48072,
        "sha256": "0aefff8f912fb75716c5d4de3b6acde93edbe8fa280fc8ee895c1226d3e373ef",
    },
    "credential_drop": {
        "path": "/usr/bin/setpriv",
        "mode": 0o755,
        "uid": 0,
        "gid": 0,
        "nlink": 1,
        "size": 39304,
        "sha256": "96b083b79c32fd2f0c29657e88e20c7495839349fc64ad5d0503f32d26bf8733",
        "version_identity": "util-linux-setpriv-2.39.3",
    },
    "unit_load_paths": [
        "/etc/systemd/system.control",
        "/run/systemd/system.control",
        "/run/systemd/transient",
        "/run/systemd/generator.early",
        "/etc/systemd/system",
        "/etc/systemd/system.attached",
        "/run/systemd/system",
        "/run/systemd/system.attached",
        "/run/systemd/generator",
        "/usr/local/lib/systemd/system",
        "/usr/lib/systemd/system",
        "/run/systemd/generator.late",
    ],
    "dependency_directory_suffixes": ["d", "requires", "upholds", "wants"],
    "version_identity": "systemd-255",
}


def _guardian_launcher_contract() -> dict[str, object]:
    return {
        "manager_entrypoint": SUPERVISOR_GUARDIAN_MANAGER_PATH,
        "obligation_schema": SUPERVISOR_GUARDIAN_OBLIGATION_SCHEMA,
        "manager_intent_schema": SUPERVISOR_GUARDIAN_MANAGER_INTENT_SCHEMA,
        "transient_schema": SUPERVISOR_GUARDIAN_TRANSIENT_SCHEMA,
        "transient_submission_schema": SUPERVISOR_GUARDIAN_TRANSIENT_SUBMISSION_SCHEMA,
        "generation_schema": SUPERVISOR_GUARDIAN_GENERATION_SCHEMA,
        "child_schema": SUPERVISOR_GUARDIAN_CHILD_SCHEMA,
        "terminal_schema": SUPERVISOR_GUARDIAN_TERMINAL_SCHEMA,
        "discharge_schema": SUPERVISOR_GUARDIAN_DISCHARGE_SCHEMA,
        "strategy_launch_claim_schema": SUPERVISOR_STRATEGY_LAUNCH_CLAIM_SCHEMA,
        "strategy_launch_terminal_schema": SUPERVISOR_STRATEGY_LAUNCH_TERMINAL_SCHEMA,
        "strategy_launch_premutation_terminal_schema": (
            SUPERVISOR_STRATEGY_LAUNCH_PREMUTATION_TERMINAL_SCHEMA
        ),
        "strategy_launch_max_count": 1,
        "manager_max_starts": 2,
        "recovery_max_count": 1,
        "hard_deadline_seconds": 7200,
        "convergence_grace_seconds": 3600,
        "poll_interval_ms": 50,
        "accepted_discharge_required": True,
        "bootstrap_product_recovery_authorized": False,
        "guardian_only_product_recovery": True,
        "synthetic_manager_process_group_isolated": True,
        "production_manager": "systemd_transient",
        # The transient guardian remains the sole same-boot action owner.  A
        # separately generated persistent gate now owns only reboot recovery:
        # it cannot replay the action and can preserve exact accepted evidence
        # or converge the same PLAN to its predecessor.
        "same_boot_guardian_only": False,
        "boot_resumable_recovery_implemented": True,
        "reboot_after_mutation_classification": (
            "boot_resumable_same_plan_recovery_gate_implemented"
        ),
        "production_transient": {
            "unit_name_prefix": "myuna-p08-activation-guardian-",
            "service_type": "exec",
            "restart": "on-failure",
            "restart_sec": 1,
            "start_limit_burst": 2,
            "start_limit_interval_seconds": 7200,
            "runtime_max_seconds": 7200,
            "kill_mode": "control-group",
            "no_new_privileges": True,
            "standard_input": "null",
            "standard_output": "null",
            "standard_error": "null",
            "slice": "system.slice",
            "state_properties": [
                "ActiveState",
                "SubState",
                "LoadState",
                "MainPID",
                "NRestarts",
                "ControlGroup",
                "Result",
                "ExecMainCode",
                "ExecMainStatus",
                "InvocationID",
            ],
            "result_classes": [
                "",
                "success",
                "exit-code",
                "signal",
                "timeout",
                "resources",
                "start-limit-hit",
            ],
            "cgroup_inactive_before_restart": True,
            "cgroup_single_manager_before_generation": True,
            "durable_terminal_exit_success": True,
            "unit_gc_preserves_evidence": True,
        },
    }


def _top_level_entry_contract() -> dict[str, object]:
    guardian = _guardian_launcher_contract()
    preclaim = _preclaim_contract()
    preclaim_categories = {
        category
        for row in preclaim["ordered_phases"]
        for category in row["rejection_categories"]
    }
    preclaim_categories.add(str(preclaim["unexpected_category"]))
    return {
        "schema": TOP_LEVEL_ENTRY_SCHEMA,
        "intent_schema": TOP_LEVEL_ENTRY_INTENT_SCHEMA,
        "capture_schema": TOP_LEVEL_ENTRY_CAPTURE_SCHEMA,
        "result_schema": TOP_LEVEL_ENTRY_RESULT_SCHEMA,
        "entrypoint": TOP_LEVEL_ENTRY_PATH,
        "child_entrypoint": SUPERVISOR_BOOTSTRAP_PATH,
        "capture_persist_entrypoint": WINDOWS_CAPTURE_PERSIST_PATH,
        "capture_persist_result_schema": WINDOWS_WSL_CAPTURE_PERSIST_RESULT_SCHEMA,
        "capture_persist_hard_deadline_seconds": 120,
        "evidence_root": PRODUCTION_PATHS["top_level_entry_root"],
        "transport": json.loads(canonical_bytes(PRODUCTION_WINDOWS_WSL_TRANSPORT)),
        "host_launcher": json.loads(
            canonical_bytes(PRODUCTION_WINDOWS_HOST_LAUNCHER)
        ),
        "loaded_modules": [
            TOP_LEVEL_ENTRY_PATH,
            "scripts/p08_activation_contract_v1.py",
            "scripts/p08_activation_launcher_v1.py",
            PRODUCTION_ADAPTER_PATH,
        ],
        # The child bootstrap owns a 7200 second guardian deadline.  The outer
        # capture budget is one fixed minute larger and never extends it.
        "hard_deadline_seconds": int(guardian["hard_deadline_seconds"]) + 60,
        "kill_grace_seconds": 2,
        "stdout_limit": 1_048_576,
        "stderr_limit": 65_536,
        "evidence_mode": 0o600,
        "directory_mode": 0o700,
        "raw_output_retained": False,
        "deterministic_scope_identity": True,
        "replay_allowed": False,
        "preclaim": preclaim,
        "result_failure_categories": sorted(
            set(TOP_LEVEL_BASE_FAILURE_CATEGORIES) | preclaim_categories
        ),
    }

# Every effective relationship with activation, stop, ordering, propagation,
# trigger, or reverse-authority semantics is projected.  The adapter consumes
# this list from the generated contract rather than keeping a local allowlist.
SYSTEMD_DEPENDENCY_PROPERTIES = (
    "After",
    "Before",
    "BindsTo",
    "BoundBy",
    "ConflictedBy",
    "Conflicts",
    "ConsistsOf",
    "JoinsNamespaceOf",
    "OnFailure",
    "OnSuccess",
    "PartOf",
    "PropagatesReloadTo",
    "PropagatesStopTo",
    "ReloadPropagatedFrom",
    "RequiredBy",
    "Requires",
    "Requisite",
    "RequisiteOf",
    "StopPropagatedFrom",
    "TriggeredBy",
    "Triggers",
    "UpheldBy",
    "Upholds",
    "WantedBy",
    "Wants",
)

# This is the one source-owned grammar for both packaged and installed unit
# files.  Unknown directives are rejected rather than silently acquiring
# execution authority through systemd defaults, drop-ins, or reset syntax.
UNIT_DEPENDENCY_DIRECTIVES = (
    "After",
    "Before",
    "BindsTo",
    "Conflicts",
    "DefaultDependencies",
    "Description",
    "JoinsNamespaceOf",
    "OnFailure",
    "OnSuccess",
    "PartOf",
    "PropagatesReloadTo",
    "PropagatesStopTo",
    "ReloadPropagatedFrom",
    "Requisite",
    "Requires",
    "StopPropagatedFrom",
    "Upholds",
    "Wants",
)

UNIT_SECTION_DIRECTIVES = {
    "service": {
        "Unit": UNIT_DEPENDENCY_DIRECTIVES,
        "Service": (
            "DynamicUser",
            "Environment",
            "EnvironmentFile",
            "ExecStart",
            "Group",
            "NoNewPrivileges",
            "PrivateDevices",
            "PrivateTmp",
            "ProtectControlGroups",
            "ProtectHome",
            "ProtectKernelModules",
            "ProtectKernelTunables",
            "ProtectSystem",
            "ReadWritePaths",
            "Restart",
            "RestartSec",
            "RestrictAddressFamilies",
            "SetLoginEnvironment",
            "SupplementaryGroups",
            "Type",
            "UMask",
            "User",
        ),
        "Install": ("Alias", "Also", "RequiredBy", "UpheldBy", "WantedBy"),
    },
    "socket": {
        "Unit": UNIT_DEPENDENCY_DIRECTIVES,
        "Socket": (
            "ListenStream",
            "RemoveOnStop",
            "Service",
            "SocketGroup",
            "SocketMode",
            "SocketUser",
        ),
        "Install": ("Alias", "Also", "RequiredBy", "UpheldBy", "WantedBy"),
    },
}

ROLE_ORDER = (
    "construct",
    "prepare",
    "formal1",
    "formal2",
    "exact_two",
    "drift",
    "claim",
    "backup",
    "stage",
    "recovery_install",
    "recovery_arm",
    "stop_socket",
    "stop_service",
    "install",
    "select",
    "continuity_assessment",
    "continuity_transition",
    "continuity_reconcile",
    "start_service",
    "start_socket",
    "accept_status",
    "converge",
    "recover",
    "postflight",
)

READINESS_ROLES = frozenset(
    {"construct", "prepare", "formal1", "formal2", "exact_two", "drift"}
)
MUTATION_ROLES = frozenset(
    {
        "claim",
        "backup",
        "stage",
        "recovery_install",
        "recovery_arm",
        "stop_socket",
        "stop_service",
        "install",
        "select",
        "start_service",
        "start_socket",
        "continuity_transition",
        "converge",
        "recover",
    }
)

CONTINUITY_STATES = (
    "no_transition_required",
    "transition_required",
    "transition_committed",
    "transition_ambiguous",
    "reconciled_committed",
    "reconciled_not_committed",
)

RESULT_CLASSES = (
    "ready",
    "verified",
    "claimed",
    "backed_up",
    "staged",
    "applied",
    "started",
    "continuity",
    "accepted",
    "converged",
    "recovered",
    "postflight",
    "rejected",
    "indeterminate",
)

MUTATION_SCOPES = (
    "none",
    "recovery_infrastructure",
    "product",
    "recovery_infrastructure_and_product",
)

_PHASE_EDGES = (
    ("construct", "prepare"),
    ("prepare", "formal1"),
    ("formal1", "formal2"),
    ("formal2", "exact_two"),
    ("exact_two", "drift"),
    ("drift", "claim"),
    ("claim", "backup"),
    ("backup", "stage"),
    ("stage", "recovery_install"),
    ("recovery_install", "recovery_arm"),
    ("recovery_arm", "stop_socket"),
    ("stop_socket", "stop_service"),
    ("stop_service", "install"),
    ("install", "select"),
    ("select", "continuity_assessment"),
    ("continuity_assessment", "continuity_transition"),
    ("continuity_assessment", "start_service"),
    ("continuity_transition", "continuity_reconcile"),
    ("continuity_transition", "start_service"),
    ("continuity_reconcile", "start_service"),
    ("continuity_reconcile", "converge"),
    ("start_service", "start_socket"),
    ("start_socket", "accept_status"),
    ("accept_status", "postflight"),
    ("converge", "recover"),
    ("recover", "postflight"),
)

_FAILURE_TO_CONVERGE = frozenset(
    {
        "recovery_install",
        "recovery_arm",
        "stop_socket",
        "stop_service",
        "install",
        "select",
        "start_service",
        "start_socket",
        "continuity_assessment",
        "continuity_transition",
        "continuity_reconcile",
        "accept_status",
        "postflight",
    }
)

_PAYLOAD_KEYS = {
    "construct": ("contract_verified",),
    "prepare": (
        "metadata_only",
        "opaque_content_read",
        "persistent_mutation",
    ),
    "formal1": (
        "metadata_only",
        "opaque_content_read",
        "persistent_mutation",
    ),
    "formal2": (
        "metadata_only",
        "opaque_content_read",
        "persistent_mutation",
    ),
    "exact_two": ("formal_calls", "byte_identical", "semantic_identical"),
    "drift": ("exact", "persistent_mutation"),
    "claim": ("incident_owned", "max_actions"),
    "backup": ("action_owned", "public_exact", "opaque_exact"),
    "stage": ("inventory_exact", "non_overwriting"),
    "recovery_install": (
        "runtime_exact",
        "unit_exact",
        "enablement_exact",
        "ordering_exact",
        "product_gate_exact",
    ),
    "recovery_arm": (
        "arm_exact",
        "action_backup_bound",
        "hazardous_mutation_started",
    ),
    "stop_socket": ("service_cascade_stopped", "socket_stopped"),
    "stop_service": ("dependency_state_exact", "service_stopped"),
    "install": ("installed_inventory_exact",),
    "select": ("selector_exact", "environment_exact", "units_exact"),
    "start_service": ("service_started", "socket_dependency_started"),
    "start_socket": ("dependency_state_exact", "socket_started"),
    "continuity_assessment": (
        "continuity_state",
        "transition_required",
        "provider_state_effect",
    ),
    "continuity_transition": (
        "continuity_state",
        "forward_state_possible",
        "provider_state_effect",
    ),
    "continuity_reconcile": (
        "continuity_state",
        "forward_state_possible",
        "provider_state_effect",
    ),
    "accept_status": ("accepted", "nonce_echo_exact", "source_bound"),
    "converge": (
        "code_public_predecessor",
        "trusted_time_history_restored",
        "state_restore_scope",
    ),
    "recover": ("converged", "orphan_count"),
    "postflight": ("selected_identity", "stable", "state_preserved"),
}

_ROLE_RESULT_CLASS = {
    "construct": "verified",
    "prepare": "ready",
    "formal1": "ready",
    "formal2": "ready",
    "exact_two": "verified",
    "drift": "verified",
    "claim": "claimed",
    "backup": "backed_up",
    "stage": "staged",
    "recovery_install": "applied",
    "recovery_arm": "claimed",
    "stop_socket": "applied",
    "stop_service": "applied",
    "install": "applied",
    "select": "applied",
    "start_service": "started",
    "start_socket": "started",
    "continuity_assessment": "continuity",
    "continuity_transition": "continuity",
    "continuity_reconcile": "continuity",
    "accept_status": "accepted",
    "converge": "converged",
    "recover": "recovered",
    "postflight": "postflight",
}


class ContractError(ValueError):
    pass


def canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("ascii") + b"\n"
    except (TypeError, ValueError):
        raise ContractError("canonical_value_rejected") from None


def digest_value(value: object) -> str:
    return sha256(canonical_bytes(value)).hexdigest()


def build_strategy_launch_claim(
    contract: Mapping[str, object],
    *,
    entry_nonce: str,
    root: str,
    backend: str,
    target_source_path: str,
    target_inventory_digest: str,
    target_directories_digest: str,
    acceptance_scope_digest: str,
    prestate_identity: str,
) -> dict[str, object]:
    """Build the one fixed launch authority above all random namespaces."""
    validated = validate_contract(contract)
    for value in (
        entry_nonce,
        target_inventory_digest,
        target_directories_digest,
        acceptance_scope_digest,
        prestate_identity,
    ):
        _hex64(value, "strategy_launch_claim_rejected")
    if backend not in {"synthetic", "systemd"}:
        raise ContractError("strategy_launch_claim_rejected")
    root_value = _absolute_path(root, "strategy_launch_claim_rejected")
    target_value = _absolute_path(
        target_source_path, "strategy_launch_claim_rejected"
    )
    fixed = validated["production_adapter"]["fixed_paths"]
    strategy_root = (
        root_value.rstrip("/") + "/" + str(fixed["strategy_root"]).lstrip("/")
    )
    body = {
        "schema": SUPERVISOR_STRATEGY_LAUNCH_CLAIM_SCHEMA,
        "architecture": ARCHITECTURE,
        "contract_digest": validated["contract_digest"],
        "entry_nonce": entry_nonce,
        "sequence_identity": entry_nonce,
        "root": root_value,
        "backend": backend,
        "strategy_root": strategy_root,
        "claim_path": strategy_root + "/STRATEGY.LAUNCH.CLAIM.json",
        "terminal_path": strategy_root + "/STRATEGY.LAUNCH.TERMINAL.json",
        "target_source_path": target_value,
        "target_inventory_digest": target_inventory_digest,
        "target_directories_digest": target_directories_digest,
        "acceptance_scope_digest": acceptance_scope_digest,
        "prestate_identity": prestate_identity,
        "predecessor_binding_digest": digest_value(
            validated["compatibility"]["predecessor"]
        ),
        "strategy_launch_max_count": 1,
        "raw_output_retained": False,
    }
    return validate_strategy_launch_claim(
        validated, {**body, "launch_claim_digest": digest_value(body)}
    )


def validate_strategy_launch_claim(
    contract: Mapping[str, object], value: object
) -> dict[str, object]:
    validated = validate_contract(contract)
    keys = {
        "acceptance_scope_digest",
        "architecture",
        "backend",
        "claim_path",
        "contract_digest",
        "entry_nonce",
        "launch_claim_digest",
        "predecessor_binding_digest",
        "prestate_identity",
        "raw_output_retained",
        "root",
        "schema",
        "sequence_identity",
        "strategy_launch_max_count",
        "strategy_root",
        "target_directories_digest",
        "target_inventory_digest",
        "target_source_path",
        "terminal_path",
    }
    _exact_keys(value, keys, "strategy_launch_claim_rejected")
    assert isinstance(value, Mapping)
    for key in (
        "acceptance_scope_digest",
        "contract_digest",
        "entry_nonce",
        "launch_claim_digest",
        "predecessor_binding_digest",
        "prestate_identity",
        "sequence_identity",
        "target_directories_digest",
        "target_inventory_digest",
    ):
        _hex64(value[key], "strategy_launch_claim_rejected")
    fixed = validated["production_adapter"]["fixed_paths"]
    root_value = _absolute_path(value["root"], "strategy_launch_claim_rejected")
    strategy_root = (
        root_value.rstrip("/") + "/" + str(fixed["strategy_root"]).lstrip("/")
    )
    unsigned = {
        key: item for key, item in value.items() if key != "launch_claim_digest"
    }
    if (
        value["schema"] != SUPERVISOR_STRATEGY_LAUNCH_CLAIM_SCHEMA
        or value["architecture"] != ARCHITECTURE
        or value["contract_digest"] != validated["contract_digest"]
        or value["entry_nonce"] != value["sequence_identity"]
        or value["backend"] not in {"synthetic", "systemd"}
        or value["strategy_root"] != strategy_root
        or value["claim_path"] != strategy_root + "/STRATEGY.LAUNCH.CLAIM.json"
        or value["terminal_path"]
        != strategy_root + "/STRATEGY.LAUNCH.TERMINAL.json"
        or value["predecessor_binding_digest"]
        != digest_value(validated["compatibility"]["predecessor"])
        or value["strategy_launch_max_count"] != 1
        or value["raw_output_retained"] is not False
        or value["launch_claim_digest"] != digest_value(unsigned)
    ):
        raise ContractError("strategy_launch_claim_rejected")
    _absolute_path(value["target_source_path"], "strategy_launch_claim_rejected")
    return json.loads(canonical_bytes(value))


def build_strategy_launch_premutation_terminal(
    contract: Mapping[str, object],
    claim: Mapping[str, object],
    outer_terminal: Mapping[str, object],
) -> dict[str, object]:
    """Finalize a consumed fixed claim that never created a guardian/PLAN."""
    validated = validate_contract(contract)
    launch = validate_strategy_launch_claim(validated, claim)
    outer = validate_supervisor_bootstrap_output(outer_terminal)
    if (
        outer.get("schema") != SUPERVISOR_OUTER_TERMINAL_SCHEMA
        or outer.get("contract_digest") != validated["contract_digest"]
        or outer.get("entry_nonce") != launch["entry_nonce"]
        or outer.get("terminal_status") != "premutation_hard_stop"
        or outer.get("product_state") != "unmodified"
        or outer.get("plan_digest") is not None
        or outer.get("recovery_count") != 0
    ):
        raise ContractError("strategy_launch_premutation_terminal_rejected")
    body = {
        "schema": SUPERVISOR_STRATEGY_LAUNCH_PREMUTATION_TERMINAL_SCHEMA,
        "architecture": ARCHITECTURE,
        "contract_digest": validated["contract_digest"],
        "launch_claim_digest": launch["launch_claim_digest"],
        "entry_nonce": launch["entry_nonce"],
        "sequence_identity": launch["sequence_identity"],
        "outer_terminal_digest": outer["terminal_digest"],
        "terminal_status": "premutation_hard_stop",
        "product_state": "unmodified",
        "plan_digest": None,
        "strategy_launch_finalized": True,
        "raw_output_included": False,
        "retry_authorized": False,
    }
    return validate_strategy_launch_premutation_terminal(
        validated,
        launch,
        outer,
        {**body, "launch_terminal_digest": digest_value(body)},
    )


def validate_strategy_launch_premutation_terminal(
    contract: Mapping[str, object],
    claim: Mapping[str, object],
    outer_terminal: Mapping[str, object],
    value: object,
) -> dict[str, object]:
    validated = validate_contract(contract)
    launch = validate_strategy_launch_claim(validated, claim)
    outer = validate_supervisor_bootstrap_output(outer_terminal)
    keys = {
        "architecture",
        "contract_digest",
        "entry_nonce",
        "launch_claim_digest",
        "launch_terminal_digest",
        "outer_terminal_digest",
        "plan_digest",
        "product_state",
        "raw_output_included",
        "retry_authorized",
        "schema",
        "sequence_identity",
        "strategy_launch_finalized",
        "terminal_status",
    }
    _exact_keys(value, keys, "strategy_launch_premutation_terminal_rejected")
    expected = {
        "schema": SUPERVISOR_STRATEGY_LAUNCH_PREMUTATION_TERMINAL_SCHEMA,
        "architecture": ARCHITECTURE,
        "contract_digest": validated["contract_digest"],
        "launch_claim_digest": launch["launch_claim_digest"],
        "entry_nonce": launch["entry_nonce"],
        "sequence_identity": launch["sequence_identity"],
        "outer_terminal_digest": outer.get("terminal_digest"),
        "terminal_status": "premutation_hard_stop",
        "product_state": "unmodified",
        "plan_digest": None,
        "strategy_launch_finalized": True,
        "raw_output_included": False,
        "retry_authorized": False,
    }
    projected = {**expected, "launch_terminal_digest": digest_value(expected)}
    if (
        outer.get("schema") != SUPERVISOR_OUTER_TERMINAL_SCHEMA
        or outer.get("contract_digest") != validated["contract_digest"]
        or outer.get("entry_nonce") != launch["entry_nonce"]
        or outer.get("terminal_status") != "premutation_hard_stop"
        or outer.get("product_state") != "unmodified"
        or outer.get("plan_digest") is not None
        or outer.get("recovery_count") != 0
        or value != projected
    ):
        raise ContractError("strategy_launch_premutation_terminal_rejected")
    return json.loads(canonical_bytes(projected))


def build_guardian_obligation(
    contract: Mapping[str, object],
    *,
    entry_nonce: str,
    root: str,
    backend: str,
    contract_path: str,
    target_source_path: str,
    target_inventory_digest: str,
    target_directories_digest: str,
    acceptance_scope_digest: str,
    launch_claim_digest: str,
    prestate_identity: str,
    bootstrap_pid: int,
    bootstrap_process_group: int,
    bootstrap_start_ticks: int,
    boot_identity_digest: str,
    monotonic_start_ns: int,
) -> dict[str, object]:
    validated = validate_contract(contract)
    for value in (
        entry_nonce,
        target_inventory_digest,
        target_directories_digest,
        acceptance_scope_digest,
        launch_claim_digest,
        prestate_identity,
        boot_identity_digest,
    ):
        _hex64(value, "guardian_obligation_rejected")
    if (
        backend not in {"synthetic", "systemd"}
        or not isinstance(bootstrap_pid, int)
        or isinstance(bootstrap_pid, bool)
        or bootstrap_pid < 1
        or not isinstance(bootstrap_process_group, int)
        or isinstance(bootstrap_process_group, bool)
        or bootstrap_process_group < 1
        or not isinstance(bootstrap_start_ticks, int)
        or isinstance(bootstrap_start_ticks, bool)
        or bootstrap_start_ticks < 1
        or not isinstance(monotonic_start_ns, int)
        or isinstance(monotonic_start_ns, bool)
        or monotonic_start_ns < 1
    ):
        raise ContractError("guardian_obligation_rejected")
    fixed = validated["production_adapter"]["fixed_paths"]
    plan_path = (
        str(root).rstrip("/")
        + "/"
        + str(fixed["strategy_root"]).lstrip("/")
        + "/sequences/"
        + entry_nonce
        + "/PLAN.json"
    )
    body = {
        "schema": SUPERVISOR_GUARDIAN_OBLIGATION_SCHEMA,
        "architecture": ARCHITECTURE,
        "contract_digest": validated["contract_digest"],
        "entry_nonce": entry_nonce,
        "sequence_identity": entry_nonce,
        "root": _absolute_path(root, "guardian_obligation_rejected"),
        "backend": backend,
        "manager_backend": (
            "synthetic_subprocess" if backend == "synthetic" else "systemd_transient"
        ),
        "contract_path": _absolute_path(
            contract_path, "guardian_obligation_rejected"
        ),
        "contract_sha256": sha256(canonical_bytes(validated)).hexdigest(),
        "target_source_path": _absolute_path(
            target_source_path, "guardian_obligation_rejected"
        ),
        "target_inventory_digest": target_inventory_digest,
        "target_directories_digest": target_directories_digest,
        "acceptance_scope_digest": acceptance_scope_digest,
        "launch_claim_digest": launch_claim_digest,
        "prestate_identity": prestate_identity,
        "plan_path": plan_path,
        "bootstrap_pid": bootstrap_pid,
        "bootstrap_process_group": bootstrap_process_group,
        "bootstrap_start_ticks": bootstrap_start_ticks,
        "boot_identity_digest": boot_identity_digest,
        "monotonic_start_ns": monotonic_start_ns,
        "monotonic_deadline_ns": monotonic_start_ns
        + int(
            validated["launcher"]["supervisor_bootstrap"]["guardian"][
                "hard_deadline_seconds"
            ]
        )
        * 1_000_000_000,
        "hard_deadline_seconds": validated["launcher"]["supervisor_bootstrap"][
            "guardian"
        ]["hard_deadline_seconds"],
        "manager_max_starts": 2,
        "recovery_max_count": 1,
        "accepted_discharge_required": True,
        "raw_output_retained": False,
    }
    return validate_guardian_obligation(
        validated, {**body, "obligation_digest": digest_value(body)}
    )


def validate_guardian_obligation(
    contract: Mapping[str, object], value: object
) -> dict[str, object]:
    validated = validate_contract(contract)
    keys = {
        "acceptance_scope_digest",
        "accepted_discharge_required",
        "architecture",
        "backend",
        "bootstrap_pid",
        "bootstrap_process_group",
        "bootstrap_start_ticks",
        "boot_identity_digest",
        "contract_digest",
        "contract_path",
        "contract_sha256",
        "entry_nonce",
        "manager_backend",
        "manager_max_starts",
        "obligation_digest",
        "hard_deadline_seconds",
        "launch_claim_digest",
        "monotonic_deadline_ns",
        "monotonic_start_ns",
        "plan_path",
        "prestate_identity",
        "raw_output_retained",
        "recovery_max_count",
        "root",
        "schema",
        "sequence_identity",
        "target_directories_digest",
        "target_inventory_digest",
        "target_source_path",
    }
    _exact_keys(value, keys, "guardian_obligation_rejected")
    assert isinstance(value, Mapping)
    for key in (
        "acceptance_scope_digest",
        "contract_digest",
        "contract_sha256",
        "entry_nonce",
        "obligation_digest",
        "launch_claim_digest",
        "prestate_identity",
        "boot_identity_digest",
        "target_directories_digest",
        "target_inventory_digest",
    ):
        _hex64(value[key], "guardian_obligation_rejected")
    expected_plan = (
        str(value["root"]).rstrip("/")
        + "/"
        + str(validated["production_adapter"]["fixed_paths"]["strategy_root"]).lstrip("/")
        + "/sequences/"
        + str(value["entry_nonce"])
        + "/PLAN.json"
    )
    if (
        value["schema"] != SUPERVISOR_GUARDIAN_OBLIGATION_SCHEMA
        or value["architecture"] != ARCHITECTURE
        or value["contract_digest"] != validated["contract_digest"]
        or value["contract_sha256"]
        != sha256(canonical_bytes(validated)).hexdigest()
        or value["sequence_identity"] != value["entry_nonce"]
        or value["backend"] not in {"synthetic", "systemd"}
        or value["manager_backend"]
        != (
            "synthetic_subprocess"
            if value["backend"] == "synthetic"
            else "systemd_transient"
        )
        or value["manager_max_starts"] != 2
        or value["recovery_max_count"] != 1
        or value["accepted_discharge_required"] is not True
        or value["raw_output_retained"] is not False
        or not isinstance(value["bootstrap_pid"], int)
        or isinstance(value["bootstrap_pid"], bool)
        or value["bootstrap_pid"] < 1
        or not isinstance(value["bootstrap_process_group"], int)
        or isinstance(value["bootstrap_process_group"], bool)
        or value["bootstrap_process_group"] < 1
        or not isinstance(value["bootstrap_start_ticks"], int)
        or isinstance(value["bootstrap_start_ticks"], bool)
        or value["bootstrap_start_ticks"] < 1
        or not isinstance(value["monotonic_start_ns"], int)
        or isinstance(value["monotonic_start_ns"], bool)
        or value["monotonic_start_ns"] < 1
        or not isinstance(value["monotonic_deadline_ns"], int)
        or isinstance(value["monotonic_deadline_ns"], bool)
        or value["monotonic_deadline_ns"]
        != value["monotonic_start_ns"]
        + int(
            validated["launcher"]["supervisor_bootstrap"]["guardian"][
                "hard_deadline_seconds"
            ]
        )
        * 1_000_000_000
        or value["hard_deadline_seconds"]
        != validated["launcher"]["supervisor_bootstrap"]["guardian"][
            "hard_deadline_seconds"
        ]
        or value["plan_path"] != expected_plan
    ):
        raise ContractError("guardian_obligation_rejected")
    for key in ("root", "contract_path", "target_source_path", "plan_path"):
        _absolute_path(value[key], "guardian_obligation_rejected")
    unsigned = {key: item for key, item in value.items() if key != "obligation_digest"}
    if value["obligation_digest"] != digest_value(unsigned):
        raise ContractError("guardian_obligation_rejected")
    return json.loads(canonical_bytes(value))


def _source_inventory_row(
    contract: Mapping[str, object], relative: str
) -> dict[str, object]:
    rows = [
        row
        for row in contract["engine_source"]["source_inventory"]
        if row["path"] == relative
    ]
    if len(rows) != 1:
        raise ContractError("guardian_source_identity_rejected")
    return dict(rows[0])


def build_guardian_manager_intent(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    *,
    obligation_path: str,
) -> dict[str, object]:
    validated = validate_contract(contract)
    bound = validate_guardian_obligation(validated, obligation)
    manager = _source_inventory_row(validated, SUPERVISOR_GUARDIAN_MANAGER_PATH)
    target = str(bound["target_source_path"])
    interpreter = validated["interpreter"]
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": target + "/scripts" + ":" + target + "/src",
    }
    argv = [
        str(interpreter["invocation_path"]),
        "-B",
        "-P",
        "-S",
        "-m",
        "p08_activation_guardian_manager_v1",
        "--guardian-contract",
        str(bound["contract_path"]),
        "--guardian-obligation",
        _absolute_path(obligation_path, "guardian_manager_intent_rejected"),
    ]
    body = {
        "schema": SUPERVISOR_GUARDIAN_MANAGER_INTENT_SCHEMA,
        "contract_digest": validated["contract_digest"],
        "obligation_digest": bound["obligation_digest"],
        "entry_nonce": bound["entry_nonce"],
        "manager_backend": bound["manager_backend"],
        "obligation_path": obligation_path,
        "contract_path": bound["contract_path"],
        "target_source_path": target,
        "interpreter_path": interpreter["invocation_path"],
        "interpreter_sha256": interpreter["sha256"],
        "entrypoint_path": target + "/" + SUPERVISOR_GUARDIAN_MANAGER_PATH,
        "entrypoint_sha256": manager["sha256"],
        "cwd": target,
        "uid": validated["runtime_identity"]["uid"],
        "gid": validated["runtime_identity"]["gid"],
        "groups": validated["runtime_identity"]["groups"],
        "umask": validated["launcher"]["umask"],
        "closed_stdin": True,
        "environment": environment,
        "argv": argv,
        "hard_deadline_seconds": validated["launcher"]["supervisor_bootstrap"][
            "guardian"
        ]["hard_deadline_seconds"],
        "manager_max_starts": 2,
        "raw_output_retained": False,
    }
    return validate_guardian_manager_intent(
        validated,
        bound,
        {**body, "manager_intent_digest": digest_value(body)},
    )


def validate_guardian_manager_intent(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    value: object,
) -> dict[str, object]:
    validated = validate_contract(contract)
    bound = validate_guardian_obligation(validated, obligation)
    keys = {
        "argv",
        "closed_stdin",
        "contract_digest",
        "contract_path",
        "cwd",
        "entry_nonce",
        "entrypoint_path",
        "entrypoint_sha256",
        "environment",
        "gid",
        "groups",
        "hard_deadline_seconds",
        "interpreter_path",
        "interpreter_sha256",
        "manager_backend",
        "manager_intent_digest",
        "manager_max_starts",
        "obligation_digest",
        "obligation_path",
        "raw_output_retained",
        "schema",
        "target_source_path",
        "uid",
        "umask",
    }
    _exact_keys(value, keys, "guardian_manager_intent_rejected")
    assert isinstance(value, Mapping)
    manager = _source_inventory_row(validated, SUPERVISOR_GUARDIAN_MANAGER_PATH)
    target = str(bound["target_source_path"])
    expected_environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": target + "/scripts:" + target + "/src",
    }
    expected_argv = [
        str(validated["interpreter"]["invocation_path"]),
        "-B",
        "-P",
        "-S",
        "-m",
        "p08_activation_guardian_manager_v1",
        "--guardian-contract",
        str(bound["contract_path"]),
        "--guardian-obligation",
        str(value["obligation_path"]),
    ]
    if (
        value["schema"] != SUPERVISOR_GUARDIAN_MANAGER_INTENT_SCHEMA
        or value["contract_digest"] != validated["contract_digest"]
        or value["obligation_digest"] != bound["obligation_digest"]
        or value["entry_nonce"] != bound["entry_nonce"]
        or value["manager_backend"] != bound["manager_backend"]
        or value["contract_path"] != bound["contract_path"]
        or value["target_source_path"] != target
        or value["interpreter_path"]
        != validated["interpreter"]["invocation_path"]
        or value["interpreter_sha256"] != validated["interpreter"]["sha256"]
        or value["entrypoint_path"]
        != target + "/" + SUPERVISOR_GUARDIAN_MANAGER_PATH
        or value["entrypoint_sha256"] != manager["sha256"]
        or value["cwd"] != target
        or value["uid"] != validated["runtime_identity"]["uid"]
        or value["gid"] != validated["runtime_identity"]["gid"]
        or value["groups"] != validated["runtime_identity"]["groups"]
        or value["umask"] != validated["launcher"]["umask"]
        or value["closed_stdin"] is not True
        or value["environment"] != expected_environment
        or value["argv"] != expected_argv
        or value["hard_deadline_seconds"]
        != validated["launcher"]["supervisor_bootstrap"]["guardian"][
            "hard_deadline_seconds"
        ]
        or value["manager_max_starts"] != 2
        or value["raw_output_retained"] is not False
    ):
        raise ContractError("guardian_manager_intent_rejected")
    for key in (
        "contract_digest",
        "entry_nonce",
        "entrypoint_sha256",
        "interpreter_sha256",
        "manager_intent_digest",
        "obligation_digest",
    ):
        _hex64(value[key], "guardian_manager_intent_rejected")
    for key in ("contract_path", "cwd", "entrypoint_path", "obligation_path", "target_source_path"):
        _absolute_path(value[key], "guardian_manager_intent_rejected")
    unsigned = {
        key: item for key, item in value.items() if key != "manager_intent_digest"
    }
    if value["manager_intent_digest"] != digest_value(unsigned):
        raise ContractError("guardian_manager_intent_rejected")
    return json.loads(canonical_bytes(value))


def _guardian_transient_body(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    manager_intent: Mapping[str, object],
) -> dict[str, object]:
    transient = contract["launcher"]["supervisor_bootstrap"]["guardian"][
        "production_transient"
    ]
    authority = contract["systemd_authority"]
    unit_name = (
        str(transient["unit_name_prefix"])
        + str(obligation["entry_nonce"])
        + ".service"
    )
    groups = [int(value) for value in manager_intent["groups"]]
    manager_environment = {
        str(key): str(manager_intent["environment"][key])
        for key in sorted(manager_intent["environment"])
    }
    credential_argv = [
        str(authority["environment_scrubber"]["path"]),
        "-i",
        *[
            key + "=" + manager_environment[key]
            for key in sorted(manager_environment)
        ],
        str(authority["credential_drop"]["path"]),
        "--reuid=" + str(manager_intent["uid"]),
        "--regid=" + str(manager_intent["gid"]),
        (
            "--groups=" + ",".join(str(value) for value in groups)
            if groups
            else "--clear-groups"
        ),
        "--no-new-privs",
        *[str(value) for value in manager_intent["argv"]],
    ]
    properties = {
        "Group": str(manager_intent["gid"]),
        "KillMode": str(transient["kill_mode"]),
        "NoNewPrivileges": "yes" if transient["no_new_privileges"] else "no",
        "Restart": str(transient["restart"]),
        "RestartSec": str(transient["restart_sec"]) + "s",
        "RuntimeMaxSec": str(transient["runtime_max_seconds"]) + "s",
        "Slice": str(transient["slice"]),
        "StandardError": str(transient["standard_error"]),
        "StandardInput": str(transient["standard_input"]),
        "StandardOutput": str(transient["standard_output"]),
        "StartLimitBurst": str(transient["start_limit_burst"]),
        "StartLimitIntervalSec": str(transient["start_limit_interval_seconds"])
        + "s",
        "UMask": "0077",
        "User": str(manager_intent["uid"]),
    }
    argv = [
        str(authority["systemd_run"]["path"]),
        "--quiet",
        "--no-block",
        "--system",
        "--unit=" + unit_name,
        "--service-type=" + str(transient["service_type"]),
        *[
            "--property=" + key + "=" + properties[key]
            for key in sorted(properties)
        ],
        "--working-directory=" + str(manager_intent["cwd"]),
        *credential_argv,
    ]
    body = {
        "schema": SUPERVISOR_GUARDIAN_TRANSIENT_SCHEMA,
        "contract_digest": contract["contract_digest"],
        "obligation_digest": obligation["obligation_digest"],
        "manager_intent_digest": manager_intent["manager_intent_digest"],
        "boot_identity_digest": obligation["boot_identity_digest"],
        "monotonic_start_ns": obligation["monotonic_start_ns"],
        "monotonic_deadline_ns": obligation["monotonic_deadline_ns"],
        "hard_deadline_seconds": obligation["hard_deadline_seconds"],
        "unit_name": unit_name,
        "systemd_run_path": authority["systemd_run"]["path"],
        "systemd_run_sha256": authority["systemd_run"]["sha256"],
        "systemctl_path": authority["systemctl"]["path"],
        "systemctl_sha256": authority["systemctl"]["sha256"],
        "environment_scrubber_path": authority["environment_scrubber"]["path"],
        "environment_scrubber_sha256": authority["environment_scrubber"]["sha256"],
        "credential_drop_path": authority["credential_drop"]["path"],
        "credential_drop_sha256": authority["credential_drop"]["sha256"],
        "manager_argv_digest": digest_value(manager_intent["argv"]),
        "credential_argv": credential_argv,
        "manager_environment": manager_environment,
        "properties": properties,
        "environment": {
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        },
        "argv": argv,
        "manager_max_starts": 2,
        "cgroup_inactive_before_restart": True,
        "cgroup_single_manager_before_generation": True,
        "durable_terminal_exit_success": True,
        "unit_gc_preserves_evidence": True,
        "raw_output_retained": False,
    }
    return body


def build_guardian_transient_launch(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    manager_intent: Mapping[str, object],
) -> dict[str, object]:
    validated = validate_contract(contract)
    bound = validate_guardian_obligation(validated, obligation)
    intent = validate_guardian_manager_intent(validated, bound, manager_intent)
    if bound["manager_backend"] != "systemd_transient":
        raise ContractError("guardian_transient_rejected")
    body = _guardian_transient_body(validated, bound, intent)
    return validate_guardian_transient_launch(
        validated,
        bound,
        intent,
        {**body, "transient_digest": digest_value(body)},
    )


def validate_guardian_transient_launch(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    manager_intent: Mapping[str, object],
    value: object,
) -> dict[str, object]:
    validated = validate_contract(contract)
    bound = validate_guardian_obligation(validated, obligation)
    intent = validate_guardian_manager_intent(validated, bound, manager_intent)
    if bound["manager_backend"] != "systemd_transient":
        raise ContractError("guardian_transient_rejected")
    body = _guardian_transient_body(validated, bound, intent)
    expected = {**body, "transient_digest": digest_value(body)}
    if value != expected:
        raise ContractError("guardian_transient_rejected")
    return json.loads(canonical_bytes(expected))


def build_guardian_transient_submission(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    manager_intent: Mapping[str, object],
    transient_launch: Mapping[str, object],
    *,
    returncode: int,
) -> dict[str, object]:
    validated = validate_contract(contract)
    transient = validate_guardian_transient_launch(
        validated, obligation, manager_intent, transient_launch
    )
    if (
        not isinstance(returncode, int)
        or isinstance(returncode, bool)
        or returncode != 0
        or transient["schema"] != SUPERVISOR_GUARDIAN_TRANSIENT_SCHEMA
    ):
        raise ContractError("guardian_transient_submission_rejected")
    body = {
        "schema": SUPERVISOR_GUARDIAN_TRANSIENT_SUBMISSION_SCHEMA,
        "contract_digest": validated["contract_digest"],
        "transient_digest": transient["transient_digest"],
        "unit_name": transient["unit_name"],
        "returncode": returncode,
        "raw_output_retained": False,
    }
    return validate_guardian_transient_submission(
        validated,
        obligation,
        manager_intent,
        {**body, "submission_digest": digest_value(body)},
    )


def validate_guardian_transient_submission(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    manager_intent: Mapping[str, object],
    value: object,
) -> dict[str, object]:
    validated = validate_contract(contract)
    transient = build_guardian_transient_launch(
        validated, obligation, manager_intent
    )
    keys = {
        "contract_digest",
        "raw_output_retained",
        "returncode",
        "schema",
        "submission_digest",
        "transient_digest",
        "unit_name",
    }
    _exact_keys(value, keys, "guardian_transient_submission_rejected")
    assert isinstance(value, Mapping)
    body = {key: item for key, item in value.items() if key != "submission_digest"}
    if (
        value["schema"] != SUPERVISOR_GUARDIAN_TRANSIENT_SUBMISSION_SCHEMA
        or value["contract_digest"] != validated["contract_digest"]
        or value["transient_digest"] != transient["transient_digest"]
        or value["unit_name"] != transient["unit_name"]
        or value["returncode"] != 0
        or value["raw_output_retained"] is not False
        or not isinstance(value["unit_name"], str)
        or not value["unit_name"].startswith("myuna-p08-activation-guardian-")
        or not value["unit_name"].endswith(".service")
        or value["submission_digest"] != digest_value(body)
    ):
        raise ContractError("guardian_transient_submission_rejected")
    _hex64(value["transient_digest"], "guardian_transient_submission_rejected")
    _hex64(value["submission_digest"], "guardian_transient_submission_rejected")
    return json.loads(canonical_bytes(value))


def build_guardian_child(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    *,
    generation: int,
    pid: int,
    process_group: int,
    start_ticks: int,
    child_entry_nonce: str,
    child_intent_digest: str,
    argv_digest: str,
    parent_nonce_sha256: str,
) -> dict[str, object]:
    validated = validate_contract(contract)
    bound = validate_guardian_obligation(validated, obligation)
    body = {
        "schema": SUPERVISOR_GUARDIAN_CHILD_SCHEMA,
        "contract_digest": validated["contract_digest"],
        "obligation_digest": bound["obligation_digest"],
        "entry_nonce": bound["entry_nonce"],
        "generation": generation,
        "pid": pid,
        "process_group": process_group,
        "start_ticks": start_ticks,
        "child_entry_nonce": child_entry_nonce,
        "child_intent_digest": child_intent_digest,
        "argv_digest": argv_digest,
        "parent_nonce_sha256": parent_nonce_sha256,
        "child_authorized_after_persistence": True,
        "raw_output_retained": False,
    }
    return validate_guardian_child(
        validated, bound, {**body, "child_digest": digest_value(body)}
    )


def validate_guardian_child(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    value: object,
) -> dict[str, object]:
    validated = validate_contract(contract)
    bound = validate_guardian_obligation(validated, obligation)
    keys = {
        "argv_digest",
        "child_authorized_after_persistence",
        "child_digest",
        "child_entry_nonce",
        "child_intent_digest",
        "contract_digest",
        "entry_nonce",
        "generation",
        "obligation_digest",
        "parent_nonce_sha256",
        "pid",
        "process_group",
        "raw_output_retained",
        "schema",
        "start_ticks",
    }
    _exact_keys(value, keys, "guardian_child_rejected")
    assert isinstance(value, Mapping)
    if (
        value["schema"] != SUPERVISOR_GUARDIAN_CHILD_SCHEMA
        or value["contract_digest"] != validated["contract_digest"]
        or value["obligation_digest"] != bound["obligation_digest"]
        or value["entry_nonce"] != bound["entry_nonce"]
        or value["generation"] not in {1, 2}
        or value["child_authorized_after_persistence"] is not True
        or value["raw_output_retained"] is not False
        or any(
            not isinstance(value[key], int)
            or isinstance(value[key], bool)
            or value[key] < 1
            for key in ("pid", "process_group", "start_ticks")
        )
    ):
        raise ContractError("guardian_child_rejected")
    for key in (
        "argv_digest",
        "child_entry_nonce",
        "child_intent_digest",
        "child_digest",
        "contract_digest",
        "entry_nonce",
        "obligation_digest",
        "parent_nonce_sha256",
    ):
        _hex64(value[key], "guardian_child_rejected")
    unsigned = {key: item for key, item in value.items() if key != "child_digest"}
    if value["child_digest"] != digest_value(unsigned):
        raise ContractError("guardian_child_rejected")
    return json.loads(canonical_bytes(value))


def build_guardian_generation(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    manager_intent: Mapping[str, object],
    *,
    generation: int,
    manager_pid: int,
    manager_process_group: int,
    manager_start_ticks: int,
) -> dict[str, object]:
    validated = validate_contract(contract)
    bound = validate_guardian_obligation(validated, obligation)
    intent = validate_guardian_manager_intent(validated, bound, manager_intent)
    body = {
        "schema": SUPERVISOR_GUARDIAN_GENERATION_SCHEMA,
        "contract_digest": validated["contract_digest"],
        "obligation_digest": bound["obligation_digest"],
        "manager_intent_digest": intent["manager_intent_digest"],
        "entry_nonce": bound["entry_nonce"],
        "generation": generation,
        "manager_pid": manager_pid,
        "manager_process_group": manager_process_group,
        "manager_start_ticks": manager_start_ticks,
        "separate_from_bootstrap_process_group": (
            manager_process_group != bound["bootstrap_process_group"]
        ),
        "raw_output_retained": False,
    }
    return validate_guardian_generation(
        validated,
        bound,
        intent,
        {**body, "generation_digest": digest_value(body)},
    )


def validate_guardian_generation(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    manager_intent: Mapping[str, object],
    value: object,
) -> dict[str, object]:
    validated = validate_contract(contract)
    bound = validate_guardian_obligation(validated, obligation)
    intent = validate_guardian_manager_intent(validated, bound, manager_intent)
    keys = {
        "contract_digest",
        "entry_nonce",
        "generation",
        "generation_digest",
        "manager_intent_digest",
        "manager_pid",
        "manager_process_group",
        "manager_start_ticks",
        "obligation_digest",
        "raw_output_retained",
        "schema",
        "separate_from_bootstrap_process_group",
    }
    _exact_keys(value, keys, "guardian_generation_rejected")
    assert isinstance(value, Mapping)
    if (
        value["schema"] != SUPERVISOR_GUARDIAN_GENERATION_SCHEMA
        or value["contract_digest"] != validated["contract_digest"]
        or value["obligation_digest"] != bound["obligation_digest"]
        or value["manager_intent_digest"] != intent["manager_intent_digest"]
        or value["entry_nonce"] != bound["entry_nonce"]
        or value["generation"] not in {1, 2}
        or not isinstance(value["manager_pid"], int)
        or isinstance(value["manager_pid"], bool)
        or value["manager_pid"] < 1
        or not isinstance(value["manager_process_group"], int)
        or isinstance(value["manager_process_group"], bool)
        or value["manager_process_group"] < 1
        or not isinstance(value["manager_start_ticks"], int)
        or isinstance(value["manager_start_ticks"], bool)
        or value["manager_start_ticks"] < 1
        or value["separate_from_bootstrap_process_group"] is not True
        or value["raw_output_retained"] is not False
    ):
        raise ContractError("guardian_generation_rejected")
    for key in (
        "contract_digest",
        "entry_nonce",
        "generation_digest",
        "manager_intent_digest",
        "obligation_digest",
    ):
        _hex64(value[key], "guardian_generation_rejected")
    unsigned = {key: item for key, item in value.items() if key != "generation_digest"}
    if value["generation_digest"] != digest_value(unsigned):
        raise ContractError("guardian_generation_rejected")
    return json.loads(canonical_bytes(value))


def build_guardian_terminal(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    *,
    terminal_status: str,
    product_state: str,
    plan_digest: str | None,
    result_digest: str,
    child_capture_digest: str | None,
    child_terminal_digest: str | None,
    acceptance_nonce: str | None,
    recovery_count: int,
    manager_generation: int,
    orphan_count: int,
) -> dict[str, object]:
    validated = validate_contract(contract)
    bound = validate_guardian_obligation(validated, obligation)
    body = {
        "schema": SUPERVISOR_GUARDIAN_TERMINAL_SCHEMA,
        "architecture": ARCHITECTURE,
        "contract_digest": validated["contract_digest"],
        "obligation_digest": bound["obligation_digest"],
        "entry_nonce": bound["entry_nonce"],
        "sequence_identity": bound["sequence_identity"],
        "terminal_status": terminal_status,
        "product_state": product_state,
        "plan_digest": plan_digest,
        "result_digest": result_digest,
        "child_capture_digest": child_capture_digest,
        "child_terminal_digest": child_terminal_digest,
        "acceptance_nonce": acceptance_nonce,
        "recovery_count": recovery_count,
        "manager_generation": manager_generation,
        "manager_reentry_count": manager_generation - 1,
        "guardian_process_group_isolated": True,
        "orphan_count": orphan_count,
        "accepted_discharge_required": terminal_status == "accepted",
        "raw_output_included": False,
        "retry_authorized": False,
    }
    return validate_guardian_terminal(
        validated,
        bound,
        {**body, "guardian_terminal_digest": digest_value(body)},
    )


def validate_guardian_terminal(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    value: object,
) -> dict[str, object]:
    validated = validate_contract(contract)
    bound = validate_guardian_obligation(validated, obligation)
    keys = {
        "acceptance_nonce",
        "accepted_discharge_required",
        "architecture",
        "child_capture_digest",
        "child_terminal_digest",
        "contract_digest",
        "entry_nonce",
        "guardian_process_group_isolated",
        "guardian_terminal_digest",
        "manager_generation",
        "manager_reentry_count",
        "obligation_digest",
        "orphan_count",
        "plan_digest",
        "product_state",
        "raw_output_included",
        "recovery_count",
        "result_digest",
        "retry_authorized",
        "schema",
        "sequence_identity",
        "terminal_status",
    }
    _exact_keys(value, keys, "guardian_terminal_rejected")
    assert isinstance(value, Mapping)
    for key in (
        "contract_digest",
        "entry_nonce",
        "guardian_terminal_digest",
        "obligation_digest",
        "result_digest",
        "sequence_identity",
    ):
        _hex64(value[key], "guardian_terminal_rejected")
    for key in (
        "acceptance_nonce",
        "child_capture_digest",
        "child_terminal_digest",
        "plan_digest",
    ):
        if value[key] is not None:
            _hex64(value[key], "guardian_terminal_rejected")
    statuses = {
        "accepted": "target_accepted",
        "premutation_hard_stop": "unmodified",
        "converged_hard_stop": "predecessor_converged",
        "convergence_failed_hard_stop": "unknown",
    }
    if (
        value["schema"] != SUPERVISOR_GUARDIAN_TERMINAL_SCHEMA
        or value["architecture"] != ARCHITECTURE
        or value["contract_digest"] != validated["contract_digest"]
        or value["obligation_digest"] != bound["obligation_digest"]
        or value["entry_nonce"] != bound["entry_nonce"]
        or value["sequence_identity"] != bound["sequence_identity"]
        or value["terminal_status"] not in statuses
        or value["product_state"] != statuses[value["terminal_status"]]
        or value["guardian_process_group_isolated"] is not True
        or value["raw_output_included"] is not False
        or value["retry_authorized"] is not False
        or value["accepted_discharge_required"]
        is not (value["terminal_status"] == "accepted")
        or value["manager_generation"] not in {1, 2}
        or value["manager_reentry_count"] != value["manager_generation"] - 1
        or value["recovery_count"] not in {0, 1}
        or value["orphan_count"] != 0
        or (
            value["terminal_status"] == "accepted"
            and (
                value["plan_digest"] is None
                or value["child_capture_digest"] is None
                or value["child_terminal_digest"] is None
                or value["acceptance_nonce"] is None
                or value["recovery_count"] != 0
            )
        )
        or (
            value["terminal_status"] != "accepted"
            and value["acceptance_nonce"] is not None
        )
    ):
        raise ContractError("guardian_terminal_rejected")
    unsigned = {
        key: item for key, item in value.items() if key != "guardian_terminal_digest"
    }
    if value["guardian_terminal_digest"] != digest_value(unsigned):
        raise ContractError("guardian_terminal_rejected")
    return json.loads(canonical_bytes(value))


def build_strategy_launch_terminal(
    contract: Mapping[str, object],
    claim: Mapping[str, object],
    obligation: Mapping[str, object],
    guardian_terminal: Mapping[str, object],
) -> dict[str, object]:
    validated = validate_contract(contract)
    launch = validate_strategy_launch_claim(validated, claim)
    bound = validate_guardian_obligation(validated, obligation)
    terminal = validate_guardian_terminal(validated, bound, guardian_terminal)
    if (
        launch["launch_claim_digest"] != bound["launch_claim_digest"]
        or launch["entry_nonce"] != bound["entry_nonce"]
        or launch["prestate_identity"] != bound["prestate_identity"]
    ):
        raise ContractError("strategy_launch_terminal_rejected")
    body = {
        "schema": SUPERVISOR_STRATEGY_LAUNCH_TERMINAL_SCHEMA,
        "architecture": ARCHITECTURE,
        "contract_digest": validated["contract_digest"],
        "launch_claim_digest": launch["launch_claim_digest"],
        "obligation_digest": bound["obligation_digest"],
        "entry_nonce": bound["entry_nonce"],
        "sequence_identity": bound["sequence_identity"],
        "guardian_terminal_digest": terminal["guardian_terminal_digest"],
        "terminal_status": terminal["terminal_status"],
        "product_state": terminal["product_state"],
        "plan_digest": terminal["plan_digest"],
        "acceptance_nonce": terminal["acceptance_nonce"],
        "strategy_launch_finalized": True,
        "raw_output_included": False,
        "retry_authorized": False,
    }
    return validate_strategy_launch_terminal(
        validated,
        launch,
        bound,
        terminal,
        {**body, "launch_terminal_digest": digest_value(body)},
    )


def validate_strategy_launch_terminal(
    contract: Mapping[str, object],
    claim: Mapping[str, object],
    obligation: Mapping[str, object],
    guardian_terminal: Mapping[str, object],
    value: object,
) -> dict[str, object]:
    validated = validate_contract(contract)
    launch = validate_strategy_launch_claim(validated, claim)
    bound = validate_guardian_obligation(validated, obligation)
    terminal = validate_guardian_terminal(validated, bound, guardian_terminal)
    keys = {
        "acceptance_nonce",
        "architecture",
        "contract_digest",
        "entry_nonce",
        "guardian_terminal_digest",
        "launch_claim_digest",
        "launch_terminal_digest",
        "obligation_digest",
        "plan_digest",
        "product_state",
        "raw_output_included",
        "retry_authorized",
        "schema",
        "sequence_identity",
        "strategy_launch_finalized",
        "terminal_status",
    }
    _exact_keys(value, keys, "strategy_launch_terminal_rejected")
    assert isinstance(value, Mapping)
    expected = {
        "schema": SUPERVISOR_STRATEGY_LAUNCH_TERMINAL_SCHEMA,
        "architecture": ARCHITECTURE,
        "contract_digest": validated["contract_digest"],
        "launch_claim_digest": launch["launch_claim_digest"],
        "obligation_digest": bound["obligation_digest"],
        "entry_nonce": bound["entry_nonce"],
        "sequence_identity": bound["sequence_identity"],
        "guardian_terminal_digest": terminal["guardian_terminal_digest"],
        "terminal_status": terminal["terminal_status"],
        "product_state": terminal["product_state"],
        "plan_digest": terminal["plan_digest"],
        "acceptance_nonce": terminal["acceptance_nonce"],
        "strategy_launch_finalized": True,
        "raw_output_included": False,
        "retry_authorized": False,
    }
    projected = {**expected, "launch_terminal_digest": digest_value(expected)}
    if (
        launch["launch_claim_digest"] != bound["launch_claim_digest"]
        or launch["entry_nonce"] != bound["entry_nonce"]
        or launch["prestate_identity"] != bound["prestate_identity"]
        or value != projected
    ):
        raise ContractError("strategy_launch_terminal_rejected")
    return json.loads(canonical_bytes(projected))


def build_guardian_discharge(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    terminal: Mapping[str, object],
) -> dict[str, object]:
    validated = validate_contract(contract)
    bound = validate_guardian_obligation(validated, obligation)
    accepted = validate_guardian_terminal(validated, bound, terminal)
    if accepted["terminal_status"] != "accepted":
        raise ContractError("guardian_discharge_rejected")
    body = {
        "schema": SUPERVISOR_GUARDIAN_DISCHARGE_SCHEMA,
        "contract_digest": validated["contract_digest"],
        "obligation_digest": bound["obligation_digest"],
        "sequence_identity": bound["sequence_identity"],
        "plan_digest": accepted["plan_digest"],
        "guardian_terminal_digest": accepted["guardian_terminal_digest"],
        "child_terminal_digest": accepted["child_terminal_digest"],
        "acceptance_nonce": accepted["acceptance_nonce"],
        "obligation_state": "discharged_accepted_target",
        "target_preserved": True,
        "raw_output_included": False,
    }
    return validate_guardian_discharge(
        validated, bound, accepted, {**body, "discharge_digest": digest_value(body)}
    )


def validate_guardian_discharge(
    contract: Mapping[str, object],
    obligation: Mapping[str, object],
    terminal: Mapping[str, object],
    value: object,
) -> dict[str, object]:
    validated = validate_contract(contract)
    bound = validate_guardian_obligation(validated, obligation)
    accepted = validate_guardian_terminal(validated, bound, terminal)
    keys = {
        "acceptance_nonce",
        "child_terminal_digest",
        "contract_digest",
        "discharge_digest",
        "guardian_terminal_digest",
        "obligation_digest",
        "obligation_state",
        "plan_digest",
        "raw_output_included",
        "schema",
        "sequence_identity",
        "target_preserved",
    }
    _exact_keys(value, keys, "guardian_discharge_rejected")
    assert isinstance(value, Mapping)
    if (
        accepted["terminal_status"] != "accepted"
        or value["schema"] != SUPERVISOR_GUARDIAN_DISCHARGE_SCHEMA
        or value["contract_digest"] != validated["contract_digest"]
        or value["obligation_digest"] != bound["obligation_digest"]
        or value["sequence_identity"] != bound["sequence_identity"]
        or value["plan_digest"] != accepted["plan_digest"]
        or value["guardian_terminal_digest"]
        != accepted["guardian_terminal_digest"]
        or value["child_terminal_digest"] != accepted["child_terminal_digest"]
        or value["acceptance_nonce"] != accepted["acceptance_nonce"]
        or value["obligation_state"] != "discharged_accepted_target"
        or value["target_preserved"] is not True
        or value["raw_output_included"] is not False
    ):
        raise ContractError("guardian_discharge_rejected")
    for key in (
        "acceptance_nonce",
        "child_terminal_digest",
        "contract_digest",
        "discharge_digest",
        "guardian_terminal_digest",
        "obligation_digest",
        "plan_digest",
        "sequence_identity",
    ):
        _hex64(value[key], "guardian_discharge_rejected")
    unsigned = {key: item for key, item in value.items() if key != "discharge_digest"}
    if value["discharge_digest"] != digest_value(unsigned):
        raise ContractError("guardian_discharge_rejected")
    return json.loads(canonical_bytes(value))


def preclaim_process_identity(intent: Mapping[str, object]) -> dict[str, object]:
    """Return the one content-free child-process identity used at both ends."""
    required = {
        "child_argv",
        "child_environment",
        "child_entrypoint_sha256",
        "child_stdin_target",
        "cwd",
        "gid",
        "groups",
        "interpreter_sha256",
        "uid",
    }
    if not required.issubset(intent):
        raise ContractError("supervisor_preclaim_intent_rejected")
    return {
        "argv_digest": digest_value(intent["child_argv"]),
        "environment_digest": digest_value(intent["child_environment"]),
        "interpreter_sha256": intent["interpreter_sha256"],
        "entrypoint_sha256": intent["child_entrypoint_sha256"],
        "cwd": intent["cwd"],
        "uid": intent["uid"],
        "gid": intent["gid"],
        "groups": intent["groups"],
        "stdin": intent["child_stdin_target"],
    }


def build_supervisor_preclaim_result(
    contract: Mapping[str, object],
    top_level_intent: Mapping[str, object],
    *,
    phase: str,
    category: str,
    cause_source: str,
    subcategory: str,
    classification: str,
    completed_phases: list[str],
    bootstrap_pid: int,
    bootstrap_start_ticks: int,
    bootstrap_process_group: int,
) -> dict[str, object]:
    validated = validate_contract(contract)
    preclaim = validated["launcher"]["top_level_entry"]["preclaim"]
    body = {
        "schema": SUPERVISOR_PRECLAIM_RESULT_SCHEMA,
        "architecture": ARCHITECTURE,
        "contract_digest": validated["contract_digest"],
        "source_identity_digest": digest_value(validated["engine_source"]),
        "acceptance_scope_digest": top_level_intent["acceptance_scope_digest"],
        "target_release_identity": str(top_level_intent["target_source_path"]).rsplit(
            "/", 1
        )[-1],
        "target_inventory_digest": top_level_intent["target_inventory_digest"],
        "target_directories_digest": top_level_intent[
            "target_directories_digest"
        ],
        "entry_identity": top_level_intent["entry_identity"],
        "intent_digest": top_level_intent["intent_digest"],
        "parent_nonce_sha256": top_level_intent["parent_nonce_sha256"],
        "process_identity_digest": digest_value(
            preclaim_process_identity(top_level_intent)
        ),
        "bootstrap_pid": bootstrap_pid,
        "bootstrap_start_ticks": bootstrap_start_ticks,
        "bootstrap_process_group": bootstrap_process_group,
        "phase": phase,
        "phase_ordinal": next(
            (
                row["ordinal"]
                for row in preclaim["ordered_phases"]
                if row["phase"] == phase
            ),
            None,
        ),
        "phase_map_digest": preclaim["phase_map_digest"],
        "completed_phases": list(completed_phases),
        "completed_phases_digest": digest_value(completed_phases),
        "category": category,
        "cause_source": cause_source,
        "subcategory": subcategory,
        "classification": classification,
        "status": (
            preclaim["typed_status"]
            if classification == "typed_rejection"
            else preclaim["unexpected_status"]
        ),
        "product_mutation_state": preclaim["product_mutation_state"],
        "strategy_root_created": False,
        "launch_claim_created": False,
        "guardian_created": False,
        "plan_created": False,
        "incident_created": False,
        "backup_created": False,
        "action_started": False,
        "product_mutated": False,
        "raw_output_included": False,
        "retry_authorized": False,
    }
    return validate_supervisor_preclaim_result(
        validated,
        top_level_intent,
        {**body, "result_digest": digest_value(body)},
    )


def validate_supervisor_preclaim_result(
    contract: Mapping[str, object],
    top_level_intent: Mapping[str, object],
    value: object,
) -> dict[str, object]:
    validated = validate_contract(contract)
    if not isinstance(top_level_intent, Mapping) or not isinstance(value, Mapping):
        raise ContractError("supervisor_preclaim_result_rejected")
    keys = {
        "acceptance_scope_digest",
        "action_started",
        "architecture",
        "backup_created",
        "bootstrap_pid",
        "bootstrap_process_group",
        "bootstrap_start_ticks",
        "category",
        "cause_source",
        "classification",
        "completed_phases",
        "completed_phases_digest",
        "contract_digest",
        "entry_identity",
        "guardian_created",
        "incident_created",
        "intent_digest",
        "launch_claim_created",
        "parent_nonce_sha256",
        "phase",
        "phase_map_digest",
        "phase_ordinal",
        "plan_created",
        "process_identity_digest",
        "product_mutated",
        "product_mutation_state",
        "raw_output_included",
        "result_digest",
        "retry_authorized",
        "schema",
        "source_identity_digest",
        "status",
        "strategy_root_created",
        "subcategory",
        "target_directories_digest",
        "target_inventory_digest",
        "target_release_identity",
    }
    _exact_keys(value, keys, "supervisor_preclaim_result_rejected")
    preclaim = validated["launcher"]["top_level_entry"]["preclaim"]
    rows = preclaim["ordered_phases"]
    matching = [row for row in rows if row["phase"] == value["phase"]]
    if len(matching) != 1:
        raise ContractError("supervisor_preclaim_result_rejected")
    row = matching[0]
    expected_completed = [
        item["phase"] for item in rows if item["ordinal"] < row["ordinal"]
    ]
    typed = value["classification"] == "typed_rejection"
    unexpected = value["classification"] == "unexpected_indeterminate"
    expected_status = (
        preclaim["typed_status"] if typed else preclaim["unexpected_status"]
    )
    expected_category = (
        value["category"] in row["rejection_categories"]
        if typed
        else value["category"] == preclaim["unexpected_category"]
    )
    source_categories = row["subcategory_sources"]
    expected_subcategory = (
        isinstance(source_categories, Mapping)
        and isinstance(value["cause_source"], str)
        and isinstance(value["subcategory"], str)
        and value["cause_source"] in source_categories
        and value["subcategory"] in source_categories[value["cause_source"]]
        if typed
        else value["cause_source"] == "unexpected"
        and value["subcategory"] == PRECLAIM_UNEXPECTED_SUBCATEGORY
    )
    target_release = str(top_level_intent.get("target_source_path", "")).rsplit(
        "/", 1
    )[-1]
    if (
        value["schema"] != SUPERVISOR_PRECLAIM_RESULT_SCHEMA
        or value["architecture"] != ARCHITECTURE
        or value["contract_digest"] != validated["contract_digest"]
        or value["source_identity_digest"] != digest_value(validated["engine_source"])
        or value["acceptance_scope_digest"]
        != top_level_intent.get("acceptance_scope_digest")
        or value["target_release_identity"] != target_release
        or value["target_inventory_digest"]
        != top_level_intent.get("target_inventory_digest")
        or value["target_directories_digest"]
        != top_level_intent.get("target_directories_digest")
        or value["entry_identity"] != top_level_intent.get("entry_identity")
        or value["intent_digest"] != top_level_intent.get("intent_digest")
        or value["parent_nonce_sha256"]
        != top_level_intent.get("parent_nonce_sha256")
        or value["process_identity_digest"]
        != digest_value(preclaim_process_identity(top_level_intent))
        or value["phase_ordinal"] != row["ordinal"]
        or value["phase_map_digest"] != preclaim["phase_map_digest"]
        or value["completed_phases"] != expected_completed
        or value["completed_phases_digest"] != digest_value(expected_completed)
        or not (typed or unexpected)
        or not expected_category
        or not expected_subcategory
        or value["status"] != expected_status
        or value["product_mutation_state"]
        != preclaim["product_mutation_state"]
        or value["raw_output_included"] is not False
        or value["retry_authorized"] is not False
        or any(value[field] is not False for field in preclaim["zero_state_fields"])
        or not isinstance(value["bootstrap_pid"], int)
        or isinstance(value["bootstrap_pid"], bool)
        or value["bootstrap_pid"] < 1
        or not isinstance(value["bootstrap_start_ticks"], int)
        or isinstance(value["bootstrap_start_ticks"], bool)
        or value["bootstrap_start_ticks"] < 1
        or value["bootstrap_process_group"] != value["bootstrap_pid"]
    ):
        raise ContractError("supervisor_preclaim_result_rejected")
    for key in (
        "acceptance_scope_digest",
        "completed_phases_digest",
        "contract_digest",
        "entry_identity",
        "intent_digest",
        "parent_nonce_sha256",
        "phase_map_digest",
        "process_identity_digest",
        "result_digest",
        "source_identity_digest",
        "target_directories_digest",
        "target_inventory_digest",
        "target_release_identity",
    ):
        _hex64(value[key], "supervisor_preclaim_result_rejected")
    unsigned = {key: item for key, item in value.items() if key != "result_digest"}
    if value["result_digest"] != digest_value(unsigned):
        raise ContractError("supervisor_preclaim_result_rejected")
    return json.loads(canonical_bytes(value))


def validate_supervisor_bootstrap_output(
    value: object,
    *,
    contract: Mapping[str, object] | None = None,
    top_level_intent: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Allow only the fixed content-free supervisor terminal projections."""
    if not isinstance(value, Mapping):
        raise ContractError("supervisor_bootstrap_output_rejected")
    if value.get("schema") == SUPERVISOR_PRECLAIM_RESULT_SCHEMA:
        if contract is None or top_level_intent is None:
            raise ContractError("supervisor_bootstrap_output_rejected")
        return validate_supervisor_preclaim_result(
            contract, top_level_intent, value
        )
    if value.get("schema") == SUPERVISOR_OUTER_TERMINAL_SCHEMA:
        keys = {
            "architecture",
            "capture_digest",
            "contract_digest",
            "entry_nonce",
            "orphan_count",
            "plan_digest",
            "product_state",
            "raw_output_included",
            "recovery_capture_digest",
            "recovery_count",
            "recovery_entry_nonce",
            "retry_authorized",
            "schema",
            "stage",
            "terminal_digest",
            "terminal_status",
        }
        _exact_keys(value, keys, "supervisor_bootstrap_output_rejected")
        for key in ("capture_digest", "contract_digest", "entry_nonce"):
            _hex64(value[key], "supervisor_bootstrap_output_rejected")
        for key in ("plan_digest", "recovery_capture_digest", "recovery_entry_nonce"):
            if value[key] is not None:
                _hex64(value[key], "supervisor_bootstrap_output_rejected")
        if (
            value["architecture"] != ARCHITECTURE
            or value["stage"] != "outer_capture_terminalization"
            or value["terminal_status"]
            not in {"premutation_hard_stop", "convergence_failed_hard_stop"}
            or value["product_state"] not in {"unmodified", "unknown"}
            or value["raw_output_included"] is not False
            or value["retry_authorized"] is not False
            or value["orphan_count"] != 0
            or value["recovery_count"] not in {0, 1}
            or (
                value["terminal_status"] == "premutation_hard_stop"
                and (
                    value["product_state"] != "unmodified"
                    or value["plan_digest"] is not None
                    or value["recovery_count"] != 0
                    or value["recovery_entry_nonce"] is not None
                    or value["recovery_capture_digest"] is not None
                )
            )
            or (
                value["terminal_status"] == "convergence_failed_hard_stop"
                and (
                    value["product_state"] != "unknown"
                    or (
                        value["recovery_count"] == 0
                        and (
                            value["recovery_entry_nonce"] is not None
                            or value["recovery_capture_digest"] is not None
                        )
                    )
                    or (
                        value["recovery_count"] == 1
                        and (
                            value["plan_digest"] is None
                            or value["recovery_entry_nonce"] is None
                            or value["recovery_capture_digest"] is None
                        )
                    )
                )
            )
        ):
            raise ContractError("supervisor_bootstrap_output_rejected")
        unsigned = {
            key: item for key, item in value.items() if key != "terminal_digest"
        }
        if value["terminal_digest"] != digest_value(unsigned):
            raise ContractError("supervisor_bootstrap_output_rejected")
        return json.loads(canonical_bytes(value))
    if value.get("schema") == SUPERVISOR_ENTRY_SCHEMA:
        _exact_keys(
            value,
            {
                "product_state",
                "raw_output_included",
                "retry_authorized",
                "schema",
                "stage",
                "status",
            },
            "supervisor_bootstrap_output_rejected",
        )
        if dict(value) != {
            "schema": SUPERVISOR_ENTRY_SCHEMA,
            "status": "indeterminate",
            "stage": "source_owned_entry",
            "product_state": "unknown",
            "raw_output_included": False,
            "retry_authorized": False,
        }:
            raise ContractError("supervisor_bootstrap_output_rejected")
        return dict(value)
    keys = {
        "action_claimed",
        "architecture",
        "capture_chain_digest",
        "capture_count",
        "capture_persistence_failures",
        "contract_digest",
        "forward_state_possible",
        "infrastructure_mutated",
        "invocation_failures",
        "last_role",
        "mutation_scope",
        "plan_digest",
        "product_mutated",
        "raw_output_included",
        "receipt_digest",
        "role_counts",
        "schema",
        "sequence_identity",
        "state_restore_scope",
        "terminal_status",
        "transition_committed",
        "transition_state",
        "trusted_time_history_restored",
    }
    _exact_keys(value, keys, "supervisor_bootstrap_output_rejected")
    for key in (
        "capture_chain_digest",
        "contract_digest",
        "plan_digest",
        "receipt_digest",
        "sequence_identity",
    ):
        _hex64(value[key], "supervisor_bootstrap_output_rejected")
    if (
        value["schema"] != SUPERVISOR_RECEIPT_SCHEMA
        or value["architecture"] != ARCHITECTURE
        or value["raw_output_included"] is not False
        or value["terminal_status"]
        not in {
            "accepted",
            "premutation_hard_stop",
            "converged_hard_stop",
            "convergence_failed_hard_stop",
        }
        or any(
            not isinstance(value[key], bool)
            for key in (
                "action_claimed",
                "forward_state_possible",
                "infrastructure_mutated",
                "product_mutated",
                "transition_committed",
                "trusted_time_history_restored",
            )
        )
        or any(
            not isinstance(value[key], int)
            or isinstance(value[key], bool)
            or value[key] < 0
            for key in (
                "capture_count",
                "capture_persistence_failures",
                "invocation_failures",
            )
        )
        or not isinstance(value["role_counts"], Mapping)
        or any(
            role not in ROLE_ORDER
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 1
            for role, count in value["role_counts"].items()
        )
        or not isinstance(value["last_role"], str)
        or value["last_role"] not in ROLE_ORDER
        or value["transition_state"] not in {*CONTINUITY_STATES, None}
        or value["mutation_scope"] not in MUTATION_SCOPES
        or value["infrastructure_mutated"] is not (
            value["mutation_scope"]
            in {"recovery_infrastructure", "recovery_infrastructure_and_product"}
        )
        or value["product_mutated"] is not (
            value["mutation_scope"]
            in {"product", "recovery_infrastructure_and_product"}
        )
        or value["state_restore_scope"]
        not in {
            "none",
            "p08_state_and_public",
            "code_public_only",
            "recovery_infrastructure_only",
            "recovery_infrastructure_and_product",
        }
    ):
        raise ContractError("supervisor_bootstrap_output_rejected")
    unsigned = {key: item for key, item in value.items() if key != "receipt_digest"}
    if value["receipt_digest"] != digest_value(unsigned):
        raise ContractError("supervisor_bootstrap_output_rejected")
    return json.loads(canonical_bytes(value))


def release_manifest_binding(contract: Mapping[str, object]) -> dict[str, object]:
    """Derive the one exact installed-release binding from the contract bytes."""
    validated = validate_contract(contract)
    return {
        "schema": CONTRACT_SCHEMA,
        "architecture": ARCHITECTURE,
        "contract_digest": validated["contract_digest"],
        "contract_path": "contracts/P08_ACTIVATION_CONTRACT.json",
        "contract_sha256": sha256(canonical_bytes(validated)).hexdigest(),
        "lineage_path": "contracts/P08_LEGACY_LINEAGE_INDEX.json",
        "lineage_sha256": sha256(
            canonical_bytes(validated["lineage"])
        ).hexdigest(),
        "interpreter_authority_digest": digest_value(validated["interpreter"]),
        "systemd_authority_digest": digest_value(validated["systemd_authority"]),
        "runtime_package_policy_digest": digest_value(
            validated["launcher"]["runtime_package"]
        ),
        "top_level_entrypoint": TOP_LEVEL_ENTRY_PATH,
        "windows_wsl_transport_digest": digest_value(
            validated["launcher"]["top_level_entry"]["transport"]
        ),
        "windows_host_launcher_digest": digest_value(
            validated["launcher"]["top_level_entry"]["host_launcher"]
        ),
        "unified_launcher": "scripts/p08_activation_launcher_v1.py",
        "engine_entrypoint": "scripts/p08_activation_engine_v1.py",
        "supervisor_entrypoint": SUPERVISOR_BOOTSTRAP_PATH,
        "supervisor_child_entrypoint": "scripts/p08_activation_supervisor_v1.py",
        "shadow_entrypoint": "scripts/p08_activation_shadow_v1.py",
        "installed_shadow_entrypoint": "scripts/p08_activation_installed_shadow_v1.py",
        "production_adapter_entrypoint": PRODUCTION_ADAPTER_PATH,
        "live_execute_implemented": True,
        "production_live_authorized": False,
    }


def _exact_keys(value: Mapping[str, Any], keys: set[str], error: str) -> None:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ContractError(error)


def _hex64(value: object, error: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise ContractError(error)
    return value


def _interpreter_authority(value: object) -> dict[str, object]:
    _exact_keys(
        value,
        set(PRODUCTION_INTERPRETER),
        "interpreter_identity_rejected",
    )
    assert isinstance(value, Mapping)
    if dict(value) != PRODUCTION_INTERPRETER:
        raise ContractError("interpreter_identity_rejected")
    return dict(value)


def _systemd_authority(value: object) -> dict[str, object]:
    _exact_keys(
        value,
        set(PRODUCTION_SYSTEMD) | {"dependency_properties"},
        "systemd_authority_rejected",
    )
    assert isinstance(value, Mapping)
    normalized = {**PRODUCTION_SYSTEMD, "dependency_properties": list(SYSTEMD_DEPENDENCY_PROPERTIES)}
    if dict(value) != normalized:
        raise ContractError("systemd_authority_rejected")
    return json.loads(canonical_bytes(value))


def _commit(value: object, error: str) -> str:
    if not isinstance(value, str) or not COMMIT40.fullmatch(value):
        raise ContractError(error)
    return value


def _absolute_path(value: object, error: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or "//" in value
        or "/../" in f"{value}/"
        or "/./" in f"{value}/"
    ):
        raise ContractError(error)
    return value


def _unit_semantics(value: object, *, expected_role: str) -> dict[str, object]:
    _exact_keys(
        value,
        {"role", "schema", "sections", "semantics_digest"},
        "unit_semantics_rejected",
    )
    assert isinstance(value, Mapping)
    if (
        value["schema"] != UNIT_SEMANTICS_SCHEMA
        or value["role"] != expected_role
        or expected_role not in UNIT_SECTION_DIRECTIVES
        or not isinstance(value["sections"], Mapping)
    ):
        raise ContractError("unit_semantics_rejected")
    expected_sections = UNIT_SECTION_DIRECTIVES[expected_role]
    if set(value["sections"]) != set(expected_sections):
        raise ContractError("unit_semantics_rejected")
    normalized: dict[str, dict[str, str]] = {}
    for section, directive_names in expected_sections.items():
        directives = value["sections"][section]
        if (
            not isinstance(directives, Mapping)
            or not directives
            or not set(directives).issubset(set(directive_names))
        ):
            raise ContractError("unit_semantics_rejected")
        projected: dict[str, str] = {}
        for name in directive_names:
            if name not in directives:
                continue
            directive = directives[name]
            if (
                not isinstance(directive, str)
                or not directive
                or "\x00" in directive
                or "\r" in directive
                or "\n" in directive
            ):
                raise ContractError("unit_semantics_rejected")
            projected[name] = directive
        normalized[section] = projected
    body = {
        "schema": UNIT_SEMANTICS_SCHEMA,
        "role": expected_role,
        "sections": normalized,
    }
    if value["semantics_digest"] != digest_value(body):
        raise ContractError("unit_semantics_rejected")
    return {**body, "semantics_digest": value["semantics_digest"]}


def parse_unit_semantics(raw: bytes, *, role: str) -> dict[str, object]:
    if (
        role not in UNIT_SECTION_DIRECTIVES
        or not isinstance(raw, bytes)
        or not raw
        or len(raw) > 64 * 1024
        or not raw.endswith(b"\n")
        or b"\r" in raw
        or b"\x00" in raw
    ):
        raise ContractError("unit_semantics_rejected")
    try:
        lines = raw.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError:
        raise ContractError("unit_semantics_rejected") from None
    expected_sections = UNIT_SECTION_DIRECTIVES[role]
    observed_sections: list[str] = []
    sections: dict[str, dict[str, str]] = {}
    current: str | None = None
    for line in lines:
        if not line:
            continue
        if line.startswith("#") or line.startswith(";"):
            raise ContractError("unit_semantics_rejected")
        if line.startswith("[") and line.endswith("]"):
            selected = line[1:-1]
            if selected not in expected_sections or selected in sections:
                raise ContractError("unit_semantics_rejected")
            observed_sections.append(selected)
            sections[selected] = {}
            current = selected
            continue
        if current is None or "=" not in line:
            raise ContractError("unit_semantics_rejected")
        name, directive = line.split("=", 1)
        if (
            name not in expected_sections[current]
            or name in sections[current]
            or not directive
        ):
            # Empty assignments are systemd reset directives.  Duplicate,
            # reset, wrong-section, and unknown execution directives all fail
            # before they can become rollback authority.
            raise ContractError("unit_semantics_rejected")
        sections[current][name] = directive
    if observed_sections != list(expected_sections):
        raise ContractError("unit_semantics_rejected")
    body = {
        "schema": UNIT_SEMANTICS_SCHEMA,
        "role": role,
        "sections": sections,
    }
    return _unit_semantics(
        {**body, "semantics_digest": digest_value(body)},
        expected_role=role,
    )


def build_unit_semantics(service_raw: bytes, socket_raw: bytes) -> dict[str, object]:
    return {
        "service": parse_unit_semantics(service_raw, role="service"),
        "socket": parse_unit_semantics(socket_raw, role="socket"),
    }


def _dependency_values(**selected: list[str]) -> dict[str, list[str]]:
    projected = {name: [] for name in SYSTEMD_DEPENDENCY_PROPERTIES}
    for name, values in selected.items():
        property_name = {
            "after": "After",
            "before": "Before",
            "conflicts": "Conflicts",
            "required_by": "RequiredBy",
            "requires": "Requires",
            "triggered_by": "TriggeredBy",
            "triggers": "Triggers",
            "wanted_by": "WantedBy",
            "wants": "Wants",
        }.get(name)
        if property_name is None:
            raise ContractError("unit_dependency_authority_rejected")
        if values != sorted(set(values)) or any(
            not is_safe_unit_name(value)
            for value in values
        ):
            raise ContractError("unit_dependency_authority_rejected")
        projected[property_name] = values
    return projected


def _systemd255_effective_unit_model() -> dict[str, object]:
    """Return the independently version-bound effective-unit authority.

    Source ``[Install]`` directives describe enablement intent.  They are not
    copied into manager reverse-dependency properties.  The rows below model
    the exact systemd-255 default/private-tmp/mount projection accepted for
    both the reviewed predecessor and target unit shapes.
    """

    service_dependencies = _dependency_values(
        after=sorted(
            {
                "-.mount",
                "basic.target",
                "sysinit.target",
                "system.slice",
                "systemd-journald.socket",
                "systemd-tmpfiles-setup.service",
                "tmp.mount",
                PRODUCTION_PATHS["socket_name"],
            }
        ),
        before=["shutdown.target"],
        conflicts=["shutdown.target"],
        requires=sorted(
            {
                "sysinit.target",
                "system.slice",
                PRODUCTION_PATHS["socket_name"],
            }
        ),
        triggered_by=[PRODUCTION_PATHS["socket_name"]],
        wants=["tmp.mount"],
        wanted_by=[],
    )
    socket_dependencies = _dependency_values(
        after=sorted({"-.mount", "sysinit.target", "system.slice"}),
        before=sorted(
            {
                PRODUCTION_PATHS["service_name"],
                "shutdown.target",
                "sockets.target",
            }
        ),
        conflicts=["shutdown.target"],
        required_by=[PRODUCTION_PATHS["service_name"]],
        requires=sorted({"sysinit.target", "system.slice"}),
        triggers=[PRODUCTION_PATHS["service_name"]],
        wanted_by=["sockets.target"],
    )
    runtime = {
        "service": {
            "dependencies": service_dependencies,
            "set_login_environment": "no",
        },
        "socket": {"dependencies": socket_dependencies},
    }
    body = {
        "schema": SYSTEMD_EFFECTIVE_UNIT_MODEL_SCHEMA,
        "systemd_version_identity": PRODUCTION_SYSTEMD["version_identity"],
        "systemd_package_identity": PRODUCTION_SYSTEMD["package_identity"],
        "mount_authority": {
            "root_path": "/",
            "root_unit": "-.mount",
            "private_tmp_path": "/tmp",
            "private_tmp_unit": "tmp.mount",
            "runtime_path": "/run",
            "runtime_root_mount_unit": "-.mount",
        },
        "implicit_default_units": [
            "-.mount",
            "basic.target",
            "shutdown.target",
            "sysinit.target",
            "system.slice",
            "systemd-journald.socket",
            "systemd-tmpfiles-setup.service",
            "tmp.mount",
        ],
        "source_install_is_runtime_reverse_dependency": False,
        "profiles": {
            "predecessor": json.loads(canonical_bytes(runtime)),
            "target": json.loads(canonical_bytes(runtime)),
        },
    }
    return {**body, "model_digest": digest_value(body)}


def _recovery_systemd255_effective_model(
    recovery_unit_raw: bytes,
) -> dict[str, object]:
    """Independently model systemd-255's recovery-manager unit projection.

    Source directives and manager-generated relations are deliberately kept in
    separate projections.  Consumers compare their union; neither side may
    silently promote a fresh manager edge into source authority.
    """

    rows = _parse_unit_directives(recovery_unit_raw)

    def tokens(section: str, key: str) -> list[str]:
        matches = [
            value.split(" ")
            for candidate_section, candidate_key, value in rows
            if candidate_section == section and candidate_key == key
        ]
        if len(matches) != 1:
            raise ContractError("boot_recovery_effective_model_rejected")
        result = matches[0]
        if result != list(dict.fromkeys(result)) or any(
            not is_safe_unit_name(value) for value in result
        ):
            raise ContractError("boot_recovery_effective_model_rejected")
        return sorted(result)

    fixed = PRODUCTION_PATHS
    source = _dependency_values(
        after=tokens("Unit", "After"),
        before=tokens("Unit", "Before"),
        conflicts=tokens("Unit", "Conflicts"),
        requires=tokens("Unit", "Requires"),
    )
    generated = _dependency_values(
        after=sorted(
            {
                "-.mount",
                "system.slice",
                "systemd-journald.socket",
                "systemd-tmpfiles-setup.service",
                "tmp.mount",
            }
        ),
        requires=["system.slice"],
        wants=["tmp.mount"],
    )
    enablement = _dependency_values(wanted_by=["multi-user.target"])
    product_gates = _dependency_values(
        required_by=[str(fixed["service_name"]), str(fixed["socket_name"])]
    )
    priming = {
        name: sorted(
            set(source[name]) | set(generated[name]) | set(enablement[name])
        )
        for name in SYSTEMD_DEPENDENCY_PROPERTIES
    }
    armed = {
        name: sorted(set(priming[name]) | set(product_gates[name]))
        for name in SYSTEMD_DEPENDENCY_PROPERTIES
    }
    body = {
        "schema": RECOVERY_INFRASTRUCTURE_MODEL_SCHEMA,
        "systemd_version_identity": PRODUCTION_SYSTEMD["version_identity"],
        "systemd_package_identity": PRODUCTION_SYSTEMD["package_identity"],
        "unit_name": str(fixed["recovery_unit_name"]),
        "source_dependencies": source,
        "manager_generated_dependencies": generated,
        "enablement_dependencies": enablement,
        "product_gate_reverse_dependencies": product_gates,
        "priming_effective_dependencies": priming,
        "armed_effective_dependencies": armed,
        "mount_authority": {
            "root_path": "/",
            "root_unit": "-.mount",
            "private_tmp_path": "/tmp",
            "private_tmp_unit": "tmp.mount",
            "slice_unit": "system.slice",
            "journal_socket": "systemd-journald.socket",
            "tmpfiles_service": "systemd-tmpfiles-setup.service",
        },
        "source_install_is_runtime_reverse_dependency": False,
        "enablement_artifact_is_runtime_reverse_dependency": True,
        "product_gate_reverse_edges_require_arm": True,
        "unknown_effective_dependency_allowed": False,
    }
    return {**body, "model_digest": digest_value(body)}


# Added after the dependency vocabulary is defined so the generated contract
# contains one canonical model rather than parallel launcher/adapter fixtures.
PRODUCTION_SYSTEMD["effective_unit_model"] = _systemd255_effective_unit_model()


def _source_dependency_tokens(section: Mapping[str, object]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for directive in UNIT_DEPENDENCY_DIRECTIVES:
        if directive in {"DefaultDependencies", "Description"}:
            continue
        raw = section.get(directive)
        if raw is None:
            result[directive] = []
            continue
        values = str(raw).split(" ")
        if (
            any(not value or not is_safe_unit_name(value) for value in values)
            or values != list(dict.fromkeys(values))
        ):
            raise ContractError("unit_dependency_authority_rejected")
        result[directive] = sorted(values)
    return result


def _unit_enablement_policy() -> dict[str, object]:
    body = {
        "schema": UNIT_ENABLEMENT_POLICY_SCHEMA,
        "service": {
            "activation": "explicit_or_socket",
            "enabled": False,
            "install_target": "multi-user.target",
            "unit_file_state": "disabled",
        },
        "socket": {
            "activation": "enabled_socket",
            "enabled": True,
            "install_target": "sockets.target",
            "unit_file_state": "enabled",
        },
    }
    return {**body, "policy_digest": digest_value(body)}


def _unit_coupled_state_machine() -> dict[str, object]:
    body = {
        "schema": UNIT_COUPLED_STATE_SCHEMA,
        "accept": False,
        "ready_state": "service_running",
        "states": [
            {
                "name": "failed_units",
                "service": ["failed", "failed"],
                "socket": ["failed", "failed"],
            },
            {
                "name": "failed_stopped",
                "service": ["failed", "failed"],
                "socket": ["inactive", "dead"],
            },
            {
                "name": "service_failed_socket_waiting",
                "service": ["failed", "failed"],
                "socket": ["active", "listening"],
            },
            {
                "name": "socket_failed",
                "service": ["inactive", "dead"],
                "socket": ["failed", "failed"],
            },
            {
                "name": "stopped",
                "service": ["inactive", "dead"],
                "socket": ["inactive", "dead"],
            },
            {
                "name": "socket_waiting",
                "service": ["inactive", "dead"],
                "socket": ["active", "listening"],
            },
            {
                "name": "service_running",
                "service": ["active", "running"],
                "socket": ["active", "running"],
            },
        ],
    }
    return {**body, "state_machine_digest": digest_value(body)}


def build_unit_runtime(
    unit_semantics: Mapping[str, object], *, profile: str = "target"
) -> dict[str, object]:
    if profile not in {"predecessor", "target"}:
        raise ContractError("unit_runtime_rejected")
    _exact_keys(
        unit_semantics,
        {"service", "socket"},
        "unit_runtime_rejected",
    )
    service = _unit_semantics(unit_semantics["service"], expected_role="service")
    socket = _unit_semantics(unit_semantics["socket"], expected_role="socket")
    service_sections = service["sections"]
    socket_sections = socket["sections"]
    service_unit = service_sections["Unit"]
    service_body = service_sections["Service"]
    service_install = service_sections["Install"]
    socket_body = socket_sections["Socket"]
    socket_install = socket_sections["Install"]
    socket_service = socket_body.get("Service")
    if (
        not isinstance(socket_service, str)
        or not is_safe_unit_name(socket_service)
    ):
        raise ContractError("unit_runtime_rejected")
    exec_start = str(service_body["ExecStart"]).split(" ")
    service_dependencies = _source_dependency_tokens(service_unit)
    socket_dependencies = _source_dependency_tokens(socket_sections["Unit"])
    requires = service_dependencies["Requires"]
    after = service_dependencies["After"]
    expected_predecessor_exec = [
        PRODUCTION_INTERPRETER["invocation_path"],
        "-B",
        "-m",
        "myuna_core.active_temporal_context.service",
    ]
    expected_safe_exec = [
        PRODUCTION_INTERPRETER["invocation_path"],
        "-B",
        "-P",
        "-S",
        "-m",
        "p08_temporal_service_v1",
    ]
    credential_drop = PRODUCTION_SYSTEMD["credential_drop"]
    expected_target_exec = [
        credential_drop["path"],
        f"--reuid={PRODUCTION_ACCOUNTS['service']['uid']}",
        f"--regid={PRODUCTION_ACCOUNTS['service']['gid']}",
        "--clear-groups",
        "--no-new-privs",
        *expected_safe_exec,
    ]
    expected_service_user = (
        "" if profile == "target" else PRODUCTION_ACCOUNTS["service"]["user"]
    )
    expected_service_group = (
        ""
        if profile == "target"
        else PRODUCTION_ACCOUNTS["service"]["primary_group"]
    )
    expected_socket_user = (
        str(PRODUCTION_ACCOUNTS["service"]["uid"])
        if profile == "target"
        else PRODUCTION_ACCOUNTS["service"]["user"]
    )
    expected_socket_group = (
        str(PRODUCTION_ACCOUNTS["gateway"]["gid"])
        if profile == "target"
        else PRODUCTION_ACCOUNTS["gateway"]["primary_group"]
    )
    if (
        any(not value for value in (*exec_start, *requires, *after))
        or requires != [PRODUCTION_PATHS["socket_name"]]
        or after != [PRODUCTION_PATHS["socket_name"]]
        or any(
            values
            for name, values in service_dependencies.items()
            if name not in {"After", "Requires"}
        )
        or any(socket_dependencies.values())
        or service_unit.get("DefaultDependencies", "yes") != "yes"
        or socket_sections["Unit"].get("DefaultDependencies", "yes") != "yes"
        or exec_start
        != (expected_target_exec if profile == "target" else expected_predecessor_exec)
        or service_body.get("User", "") != expected_service_user
        or service_body.get("Group", "") != expected_service_group
        or service_body["EnvironmentFile"] != PRODUCTION_PATHS["environment"]
        or set(service_install) != {"WantedBy"}
        or service_install["WantedBy"] != "multi-user.target"
        or socket_body["ListenStream"]
        != "/run/myuna-active-temporal-context-v1/temporal.sock"
        or socket_body["SocketUser"] != expected_socket_user
        or socket_body["SocketGroup"] != expected_socket_group
        or socket_body["SocketMode"] != "0660"
        or socket_service != PRODUCTION_PATHS["service_name"]
        or set(socket_install) != {"WantedBy"}
        or socket_install["WantedBy"] != "sockets.target"
        or service_body.get("DynamicUser", "no") != "no"
        or service_body.get("SupplementaryGroups") is not None
        or (
            profile == "target"
            and service_body.get("SetLoginEnvironment") != "no"
        )
        or (
            profile == "predecessor"
            and service_body.get("SetLoginEnvironment") not in {None, "no"}
        )
        or service_body["Type"] != ("exec" if profile == "target" else "simple")
    ):
        raise ContractError("unit_runtime_rejected")
    effective_model = PRODUCTION_SYSTEMD["effective_unit_model"]
    assert isinstance(effective_model, Mapping)
    profiles = effective_model["profiles"]
    assert isinstance(profiles, Mapping)
    profile_model = profiles[profile]
    assert isinstance(profile_model, Mapping)
    service_effective_dependencies = json.loads(
        canonical_bytes(profile_model["service"]["dependencies"])
    )
    socket_effective_dependencies = json.loads(
        canonical_bytes(profile_model["socket"]["dependencies"])
    )
    source_install = {
        "service": {"WantedBy": ["multi-user.target"]},
        "socket": {"WantedBy": ["sockets.target"]},
    }
    process_identity = {
        "schema": PROCESS_IDENTITY_SCHEMA,
        "argv": expected_safe_exec if profile == "target" else exec_start,
        "cgroup": f"/system.slice/{PRODUCTION_PATHS['service_name']}",
        "executable": {
            key: PRODUCTION_INTERPRETER[key]
            for key in (
                "invocation_path",
                "link_target",
                "mode",
                "nlink",
                "resolved_path",
                "sha256",
                "size",
                "uid",
                "gid",
                "version_identity",
            )
        },
        "gid": PRODUCTION_ACCOUNTS["service"]["gid"],
        "groups": (
            []
            if profile == "target"
            else [group["gid"] for group in PRODUCTION_ACCOUNTS["service"]["groups"]]
        ),
        "uid": PRODUCTION_ACCOUNTS["service"]["uid"],
    }
    credential_launch = (
        {
            "schema": NUMERIC_CREDENTIAL_LAUNCH_SCHEMA,
            "executable": dict(credential_drop),
            "argv": expected_target_exec,
            "uid": PRODUCTION_ACCOUNTS["service"]["uid"],
            "gid": PRODUCTION_ACCOUNTS["service"]["gid"],
            "groups": [],
            "no_new_privs": True,
            "exec_argv": expected_safe_exec,
        }
        if profile == "target"
        else None
    )
    execution_policy = {
        "Environment": service_body["Environment"],
        "NoNewPrivileges": service_body["NoNewPrivileges"],
        "PrivateDevices": service_body["PrivateDevices"],
        "PrivateTmp": service_body["PrivateTmp"],
        "ProtectControlGroups": service_body["ProtectControlGroups"],
        "ProtectHome": service_body["ProtectHome"],
        "ProtectKernelModules": service_body["ProtectKernelModules"],
        "ProtectKernelTunables": service_body["ProtectKernelTunables"],
        "ProtectSystem": service_body["ProtectSystem"],
        "ReadWritePaths": service_body["ReadWritePaths"],
        "Restart": service_body["Restart"],
        "RestartUSec": service_body["RestartSec"],
        "RestrictAddressFamilies": service_body["RestrictAddressFamilies"],
        "Type": service_body["Type"],
        "UMask": service_body["UMask"],
    }
    if execution_policy != {
        "Environment": "PYTHONDONTWRITEBYTECODE=1",
        "NoNewPrivileges": "yes",
        "PrivateDevices": "yes",
        "PrivateTmp": "yes",
        "ProtectControlGroups": "yes",
        "ProtectHome": "yes",
        "ProtectKernelModules": "yes",
        "ProtectKernelTunables": "yes",
        "ProtectSystem": "strict",
        "ReadWritePaths": PRODUCTION_PATHS["state_root"],
        "Restart": "on-failure",
        "RestartUSec": "2s",
        "RestrictAddressFamilies": "AF_UNIX",
        "Type": "exec" if profile == "target" else "simple",
        "UMask": "0077",
    }:
        raise ContractError("unit_runtime_rejected")
    body = {
        "coupled_state_machine": _unit_coupled_state_machine(),
        "enablement_policy": _unit_enablement_policy(),
        "profile": profile,
        "schema": UNIT_RUNTIME_SCHEMA,
        "source_install": source_install,
        "service": {
            "control_group": f"/system.slice/{PRODUCTION_PATHS['service_name']}",
            "credential_launch": credential_launch,
            "dependencies": service_effective_dependencies,
            "dependency_injection_paths": [],
            "drop_in_paths": [],
            "dynamic_user": "no",
            "environment_files": [PRODUCTION_PATHS["environment"]],
            "execution_policy": execution_policy,
            "exec_start_argv": exec_start,
            "fragment_path": PRODUCTION_PATHS["service_unit"],
            "group": expected_service_group,
            "load_state": "loaded",
            "ready_active_state": "active",
            "ready_sub_state": "running",
            "pam_name": "",
            "private_users": "no",
            "process_identity": process_identity,
            "set_login_environment": profile_model["service"][
                "set_login_environment"
            ],
            "slice": "system.slice",
            "supplementary_groups": [],
            "unit_file_state": "disabled",
            "user": expected_service_user,
        },
        "socket": {
            "control_group": f"/system.slice/{PRODUCTION_PATHS['socket_name']}",
            "dependencies": socket_effective_dependencies,
            "dependency_injection_paths": [],
            "drop_in_paths": [],
            "fragment_path": PRODUCTION_PATHS["socket_unit"],
            "listen_stream": socket_body["ListenStream"],
            "load_state": "loaded",
            "ready_active_state": "active",
            "ready_sub_state": "running",
            # The association is derived from the exact parsed [Socket]
            # Service= directive.  The production adapter independently
            # proves the corresponding runtime Triggers/TriggeredBy edges.
            "service": socket_service,
            "socket_group": expected_socket_group,
            "socket_mode": socket_body["SocketMode"],
            "socket_user": expected_socket_user,
            "slice": "system.slice",
            "unit_file_state": "enabled",
        },
    }
    return {**body, "runtime_digest": digest_value(body)}


def _unit_runtime(value: object) -> dict[str, object]:
    _exact_keys(
        value,
        {
            "coupled_state_machine",
            "enablement_policy",
            "profile",
            "runtime_digest",
            "schema",
            "service",
            "socket",
            "source_install",
        },
        "unit_runtime_rejected",
    )
    assert isinstance(value, Mapping)
    if (
        value["schema"] != UNIT_RUNTIME_SCHEMA
        or value["profile"] not in {"predecessor", "target"}
        or value["enablement_policy"] != _unit_enablement_policy()
        or value["coupled_state_machine"] != _unit_coupled_state_machine()
        or value["source_install"]
        != {
            "service": {"WantedBy": ["multi-user.target"]},
            "socket": {"WantedBy": ["sockets.target"]},
        }
    ):
        raise ContractError("unit_runtime_rejected")
    _exact_keys(
        value["service"],
        {
            "control_group",
            "credential_launch",
            "dependencies",
            "dependency_injection_paths",
            "drop_in_paths",
            "dynamic_user",
            "environment_files",
            "execution_policy",
            "exec_start_argv",
            "fragment_path",
            "group",
            "load_state",
            "pam_name",
            "private_users",
            "process_identity",
            "ready_active_state",
            "ready_sub_state",
            "set_login_environment",
            "slice",
            "supplementary_groups",
            "unit_file_state",
            "user",
        },
        "unit_runtime_rejected",
    )
    _exact_keys(
        value["socket"],
        {
            "control_group",
            "dependencies",
            "dependency_injection_paths",
            "drop_in_paths",
            "fragment_path",
            "listen_stream",
            "load_state",
            "ready_active_state",
            "ready_sub_state",
            "service",
            "socket_group",
            "socket_mode",
            "socket_user",
            "slice",
            "unit_file_state",
        },
        "unit_runtime_rejected",
    )
    for role in ("service", "socket"):
        row = value[role]
        assert isinstance(row, Mapping)
        dependencies = row["dependencies"]
        _exact_keys(
            dependencies,
            set(SYSTEMD_DEPENDENCY_PROPERTIES),
            "unit_runtime_rejected",
        )
        assert isinstance(dependencies, Mapping)
        for names in dependencies.values():
            if (
                not isinstance(names, list)
                or names != sorted(set(names))
                or any(
                    not is_safe_unit_name(name)
                    for name in names
                )
            ):
                raise ContractError("unit_runtime_rejected")
        gate_dropin = PRODUCTION_PATHS[f"{role}_recovery_dropin"]
        gate_directory = gate_dropin.rsplit("/", 1)[0]
        gate_enabled = row["drop_in_paths"] == [gate_dropin]
        if (
            row["drop_in_paths"] not in ([], [gate_dropin])
            or row["dependency_injection_paths"]
            != ([gate_directory] if gate_enabled else [])
            or (
                gate_enabled
                and (
                    PRODUCTION_PATHS["recovery_unit_name"]
                    not in dependencies["Requires"]
                    or PRODUCTION_PATHS["recovery_unit_name"]
                    not in dependencies["After"]
                )
            )
            or row["slice"] != "system.slice"
            or row["control_group"]
            != f"/system.slice/{PRODUCTION_PATHS[f'{role}_name']}"
        ):
            raise ContractError("unit_runtime_rejected")
    service = value["service"]
    assert isinstance(service, Mapping)
    process = service["process_identity"]
    execution_policy = service["execution_policy"]
    _exact_keys(
        execution_policy,
        {
            "Environment",
            "NoNewPrivileges",
            "PrivateDevices",
            "PrivateTmp",
            "ProtectControlGroups",
            "ProtectHome",
            "ProtectKernelModules",
            "ProtectKernelTunables",
            "ProtectSystem",
            "ReadWritePaths",
            "Restart",
            "RestartUSec",
            "RestrictAddressFamilies",
            "Type",
            "UMask",
        },
        "unit_runtime_rejected",
    )
    _exact_keys(
        process,
        {"argv", "cgroup", "executable", "gid", "groups", "schema", "uid"},
        "unit_runtime_rejected",
    )
    assert isinstance(process, Mapping)
    executable = process["executable"]
    _exact_keys(
        executable,
        {
            "gid",
            "invocation_path",
            "link_target",
            "mode",
            "nlink",
            "resolved_path",
            "sha256",
            "size",
            "uid",
            "version_identity",
        },
        "unit_runtime_rejected",
    )
    expected_process_argv = (
        [
            PRODUCTION_INTERPRETER["invocation_path"],
            "-B",
            "-P",
            "-S",
            "-m",
            "p08_temporal_service_v1",
        ]
        if value["profile"] == "target"
        else [
            PRODUCTION_INTERPRETER["invocation_path"],
            "-B",
            "-m",
            "myuna_core.active_temporal_context.service",
        ]
    )
    credential_drop = PRODUCTION_SYSTEMD["credential_drop"]
    expected_exec_start_argv = (
        [
            credential_drop["path"],
            f"--reuid={PRODUCTION_ACCOUNTS['service']['uid']}",
            f"--regid={PRODUCTION_ACCOUNTS['service']['gid']}",
            "--clear-groups",
            "--no-new-privs",
            *expected_process_argv,
        ]
        if value["profile"] == "target"
        else expected_process_argv
    )
    expected_credential_launch = (
        {
            "schema": NUMERIC_CREDENTIAL_LAUNCH_SCHEMA,
            "executable": dict(credential_drop),
            "argv": expected_exec_start_argv,
            "uid": PRODUCTION_ACCOUNTS["service"]["uid"],
            "gid": PRODUCTION_ACCOUNTS["service"]["gid"],
            "groups": [],
            "no_new_privs": True,
            "exec_argv": expected_process_argv,
        }
        if value["profile"] == "target"
        else None
    )
    expected_service_user = (
        "" if value["profile"] == "target" else PRODUCTION_ACCOUNTS["service"]["user"]
    )
    expected_service_group = (
        ""
        if value["profile"] == "target"
        else PRODUCTION_ACCOUNTS["service"]["primary_group"]
    )
    expected_socket_user = (
        str(PRODUCTION_ACCOUNTS["service"]["uid"])
        if value["profile"] == "target"
        else PRODUCTION_ACCOUNTS["service"]["user"]
    )
    expected_socket_group = (
        str(PRODUCTION_ACCOUNTS["gateway"]["gid"])
        if value["profile"] == "target"
        else PRODUCTION_ACCOUNTS["gateway"]["primary_group"]
    )
    socket = value["socket"]
    assert isinstance(socket, Mapping)
    if (
        process["schema"] != PROCESS_IDENTITY_SCHEMA
        or service["credential_launch"] != expected_credential_launch
        or service["exec_start_argv"] != expected_exec_start_argv
        or process["argv"] != expected_process_argv
        or process["cgroup"] != service["control_group"]
        or executable
        != {
            key: PRODUCTION_INTERPRETER[key]
            for key in (
                "invocation_path",
                "link_target",
                "mode",
                "nlink",
                "resolved_path",
                "sha256",
                "size",
                "uid",
                "gid",
                "version_identity",
            )
        }
        or process["uid"] != PRODUCTION_ACCOUNTS["service"]["uid"]
        or process["gid"] != PRODUCTION_ACCOUNTS["service"]["gid"]
        or process["groups"]
        != (
            []
            if value["profile"] == "target"
            else [group["gid"] for group in PRODUCTION_ACCOUNTS["service"]["groups"]]
        )
        or service["user"] != expected_service_user
        or service["group"] != expected_service_group
        or service["dynamic_user"] != "no"
        or service["supplementary_groups"] != []
        or service["pam_name"] != ""
        or service["private_users"] != "no"
        or service["set_login_environment"]
        != "no"
        or execution_policy["Type"]
        != ("exec" if value["profile"] == "target" else "simple")
        or socket["socket_user"] != expected_socket_user
        or socket["socket_group"] != expected_socket_group
    ):
        raise ContractError("unit_runtime_rejected")
    unsigned = {key: item for key, item in value.items() if key != "runtime_digest"}
    if value["runtime_digest"] != digest_value(unsigned):
        raise ContractError("unit_runtime_rejected")
    # Rebuilding from the unit semantics is the authoritative validation path;
    # callers compare this normalized object to the generated contract.
    return json.loads(canonical_bytes(value))


def _public_file(value: object, *, expected_path: str) -> dict[str, object]:
    keys = {"gid", "mode", "nlink", "path", "schema", "sha256", "size", "type", "uid"}
    _exact_keys(value, keys, "public_file_rejected")
    assert isinstance(value, Mapping)
    if (
        value["schema"] != PUBLIC_FILE_SCHEMA
        or value["path"] != expected_path
        or value["type"] != "file"
        or value["nlink"] != 1
        or not isinstance(value["mode"], int)
        or isinstance(value["mode"], bool)
        or value["mode"] not in {0o600, 0o644}
        or not isinstance(value["uid"], int)
        or isinstance(value["uid"], bool)
        or value["uid"] < 0
        or not isinstance(value["gid"], int)
        or isinstance(value["gid"], bool)
        or value["gid"] < 0
        or not isinstance(value["size"], int)
        or isinstance(value["size"], bool)
        or value["size"] < 1
    ):
        raise ContractError("public_file_rejected")
    _hex64(value["sha256"], "public_file_rejected")
    return dict(value)


def _opaque_state(value: object, *, expected_path: str) -> dict[str, object]:
    _exact_keys(value, {"entries", "root", "schema"}, "opaque_state_rejected")
    assert isinstance(value, Mapping)
    if value["schema"] != OPAQUE_STATE_SCHEMA:
        raise ContractError("opaque_state_rejected")
    root = value["root"]
    _exact_keys(
        root,
        {"gid", "mode", "nlink", "path", "type", "uid"},
        "opaque_state_rejected",
    )
    if (
        root["path"] != expected_path
        or root["type"] != "directory"
        or root["nlink"] < 1
        or not isinstance(root["mode"], int)
        or isinstance(root["mode"], bool)
        or root["mode"] < 0
        or root["mode"] > 0o7777
        or not isinstance(root["uid"], int)
        or isinstance(root["uid"], bool)
        or root["uid"] < 0
        or not isinstance(root["gid"], int)
        or isinstance(root["gid"], bool)
        or root["gid"] < 0
    ):
        raise ContractError("opaque_state_rejected")
    entries = value["entries"]
    if not isinstance(entries, list) or not entries:
        raise ContractError("opaque_state_rejected")
    observed_paths: list[str] = []
    for row in entries:
        _exact_keys(
            row,
            {"gid", "mode", "nlink", "path", "size", "type", "uid"},
            "opaque_state_rejected",
        )
        relative = row["path"]
        if (
            not isinstance(relative, str)
            or not relative
            or relative.startswith("/")
            or ".." in relative.split("/")
            or "/" in relative
            or row["type"] != "file"
            or row["nlink"] != 1
            or not isinstance(row["mode"], int)
            or isinstance(row["mode"], bool)
            or row["mode"] < 0
            or row["mode"] > 0o7777
            or not isinstance(row["uid"], int)
            or isinstance(row["uid"], bool)
            or row["uid"] < 0
            or not isinstance(row["gid"], int)
            or isinstance(row["gid"], bool)
            or row["gid"] < 0
            or not isinstance(row["size"], int)
            or isinstance(row["size"], bool)
            or row["size"] < 0
        ):
            raise ContractError("opaque_state_rejected")
        observed_paths.append(relative)
    if observed_paths != sorted(set(observed_paths)):
        raise ContractError("opaque_state_rejected")
    return {"schema": value["schema"], "root": dict(root), "entries": [dict(row) for row in entries]}


def _target_inventory(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or not value:
        raise ContractError("target_inventory_rejected")
    paths: list[str] = []
    rows: list[dict[str, object]] = []
    for row in value:
        _exact_keys(
            row,
            {"gid", "mode", "path", "sha256", "size", "type", "uid"},
            "target_inventory_rejected",
        )
        relative = row["path"]
        if (
            not isinstance(relative, str)
            or not relative
            or relative.startswith("/")
            or ".." in relative.split("/")
            or row["type"] != "file"
            or not isinstance(row["mode"], int)
            or isinstance(row["mode"], bool)
            or row["mode"] < 0
            or row["mode"] > 0o7777
            or not isinstance(row["uid"], int)
            or isinstance(row["uid"], bool)
            or row["uid"] < 0
            or not isinstance(row["gid"], int)
            or isinstance(row["gid"], bool)
            or row["gid"] < 0
            or not isinstance(row["size"], int)
            or isinstance(row["size"], bool)
            or row["size"] < 1
        ):
            raise ContractError("target_inventory_rejected")
        _hex64(row["sha256"], "target_inventory_rejected")
        paths.append(relative)
        rows.append(dict(row))
    if paths != sorted(set(paths)) or "manifest.json" not in paths:
        raise ContractError("target_inventory_rejected")
    return rows


def _target_directories(
    value: object,
    *,
    file_inventory: list[dict[str, object]],
) -> list[dict[str, object]]:
    if not isinstance(value, list) or not value:
        raise ContractError("target_directory_inventory_rejected")
    paths: list[str] = []
    rows: list[dict[str, object]] = []
    for row in value:
        _exact_keys(
            row,
            {"gid", "mode", "nlink", "path", "type", "uid"},
            "target_directory_inventory_rejected",
        )
        relative = row["path"]
        if (
            not isinstance(relative, str)
            or not relative
            or relative.startswith("/")
            or ".." in relative.split("/")
            or (relative != "." and "." in relative.split("/"))
            or row["type"] != "directory"
            or not isinstance(row["mode"], int)
            or isinstance(row["mode"], bool)
            or row["mode"] < 0
            or row["mode"] > 0o7777
            or not isinstance(row["uid"], int)
            or isinstance(row["uid"], bool)
            or row["uid"] < 0
            or not isinstance(row["gid"], int)
            or isinstance(row["gid"], bool)
            or row["gid"] < 0
            or not isinstance(row["nlink"], int)
            or isinstance(row["nlink"], bool)
            or row["nlink"] < 1
        ):
            raise ContractError("target_directory_inventory_rejected")
        paths.append(relative)
        rows.append(dict(row))
    expected = {"."}
    for file_row in file_inventory:
        parent = str(file_row["path"]).rsplit("/", 1)[0] if "/" in str(file_row["path"]) else "."
        while parent != ".":
            expected.add(parent)
            parent = parent.rsplit("/", 1)[0] if "/" in parent else "."
    if paths != sorted(set(paths)) or set(paths) != expected:
        raise ContractError("target_directory_inventory_rejected")
    return rows


def _client_role(
    value: object,
    *,
    expected_role: str,
    expected_operations: tuple[str, ...],
    include_runtime_path: bool,
) -> dict[str, object]:
    keys = {"operations", "protocol_schema", "role", "sha256", "source_path"}
    if include_runtime_path:
        keys.add("runtime_path")
    _exact_keys(value, keys, "predecessor_client_roles_rejected")
    assert isinstance(value, Mapping)
    source_path = value["source_path"]
    if (
        value["role"] != expected_role
        or value["protocol_schema"]
        != "myuna.active-temporal-context-protocol.v1"
        or value["operations"] != list(expected_operations)
        or not isinstance(source_path, str)
        or not source_path
        or source_path.startswith("/")
        or ".." in source_path.split("/")
        or re.fullmatch(r"(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+", source_path)
        is None
    ):
        raise ContractError("predecessor_client_roles_rejected")
    _hex64(value["sha256"], "predecessor_client_roles_rejected")
    if include_runtime_path:
        runtime_path = value["runtime_path"]
        if (
            not isinstance(runtime_path, str)
            or not runtime_path
            or runtime_path.startswith("/")
            or ".." in runtime_path.split("/")
            or re.fullmatch(
                r"(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+", runtime_path
            )
            is None
        ):
            raise ContractError("predecessor_client_roles_rejected")
    return dict(value)


def _predecessor_client_roles(
    value: object,
    *,
    inventory: list[dict[str, object]],
    manifest_sha256: str,
) -> dict[str, object]:
    _exact_keys(
        value,
        {
            "lineage",
            "role_digest",
            "roles",
            "schema",
            "selector_role",
        },
        "predecessor_client_roles_rejected",
    )
    assert isinstance(value, Mapping)
    if (
        value["schema"] != PREDECESSOR_CLIENT_ROLES_SCHEMA
        or value["selector_role"] != "legacy_runtime_client"
    ):
        raise ContractError("predecessor_client_roles_rejected")
    roles = value["roles"]
    _exact_keys(
        roles,
        {"legacy_runtime_client", "status_content_free_helper"},
        "predecessor_client_roles_rejected",
    )
    assert isinstance(roles, Mapping)
    runtime = _client_role(
        roles["legacy_runtime_client"],
        expected_role="legacy_runtime_client",
        expected_operations=PREDECESSOR_RUNTIME_OPERATIONS,
        include_runtime_path=False,
    )
    helper = _client_role(
        roles["status_content_free_helper"],
        expected_role="status_content_free_helper",
        expected_operations=PREDECESSOR_STATUS_OPERATIONS,
        include_runtime_path=True,
    )
    if (
        runtime["sha256"] == helper["sha256"]
        or runtime["source_path"] != helper["source_path"]
        or runtime["protocol_schema"] != helper["protocol_schema"]
    ):
        raise ContractError("predecessor_client_roles_rejected")
    lineage = value["lineage"]
    _exact_keys(
        lineage,
        {
            "compatibility_schema",
            "predecessor_core_commit",
            "predecessor_deploy_commit",
            "predecessor_release_digest",
            "selected_manifest_sha256",
            "status_runtime_digest",
            "upgrade_compatibility_digest",
        },
        "predecessor_client_roles_rejected",
    )
    assert isinstance(lineage, Mapping)
    if lineage["compatibility_schema"] != "myuna.p08-existing-state-compatibility.v1":
        raise ContractError("predecessor_client_roles_rejected")
    _commit(lineage["predecessor_core_commit"], "predecessor_client_roles_rejected")
    _commit(lineage["predecessor_deploy_commit"], "predecessor_client_roles_rejected")
    for key in (
        "predecessor_release_digest",
        "selected_manifest_sha256",
        "status_runtime_digest",
        "upgrade_compatibility_digest",
    ):
        _hex64(lineage[key], "predecessor_client_roles_rejected")
    if lineage["selected_manifest_sha256"] != manifest_sha256:
        raise ContractError("predecessor_client_roles_rejected")
    inventory_by_path = {str(row["path"]): row for row in inventory}
    helper_row = inventory_by_path.get(str(helper["source_path"]))
    if helper_row is None or helper_row["sha256"] != helper["sha256"]:
        raise ContractError("predecessor_client_roles_rejected")
    unsigned = {key: value[key] for key in value if key != "role_digest"}
    if value["role_digest"] != digest_value(unsigned):
        raise ContractError("predecessor_client_roles_rejected")
    return json.loads(canonical_bytes(value))


def build_predecessor_client_roles(
    manifest: Mapping[str, object],
    *,
    inventory: list[dict[str, object]],
    manifest_sha256: str,
) -> dict[str, object]:
    gateway = manifest.get("gateway_client")
    compatibility = manifest.get("upgrade_compatibility")
    if not isinstance(gateway, Mapping) or not isinstance(compatibility, Mapping):
        raise ContractError("predecessor_client_roles_rejected")
    _exact_keys(
        gateway,
        {"runtime_path", "sha256", "source_path"},
        "predecessor_client_roles_rejected",
    )
    runtime = compatibility.get("active_gateway_client")
    helper = compatibility.get("status_helper_client")
    status_runtime = compatibility.get("status_runtime")
    if not all(isinstance(item, Mapping) for item in (runtime, helper, status_runtime)):
        raise ContractError("predecessor_client_roles_rejected")
    assert isinstance(runtime, Mapping)
    assert isinstance(helper, Mapping)
    assert isinstance(status_runtime, Mapping)
    for row in (runtime, helper):
        _exact_keys(
            row,
            {"operations", "schema", "sha256", "source_path"},
            "predecessor_client_roles_rejected",
        )
    _exact_keys(
        status_runtime,
        {"entrypoint", "files", "pythonpath", "schema"},
        "predecessor_client_roles_rejected",
    )
    if (
        compatibility.get("schema") != "myuna.p08-existing-state-compatibility.v1"
        or compatibility.get("legacy_operation_subset")
        != list(PREDECESSOR_RUNTIME_OPERATIONS)
        or runtime.get("operations") != list(PREDECESSOR_RUNTIME_OPERATIONS)
        or helper.get("operations") != list(PREDECESSOR_STATUS_OPERATIONS)
        or gateway.get("sha256") != helper.get("sha256")
        or gateway.get("source_path") != helper.get("source_path")
        or status_runtime.get("entrypoint") != helper.get("source_path")
        or status_runtime.get("schema")
        != "myuna.p08-content-free-status-runtime-closure.v1"
        or status_runtime.get("pythonpath") != ["src", "scripts"]
    ):
        raise ContractError("predecessor_client_roles_rejected")
    inventory_by_path = {str(row["path"]): row for row in inventory}
    helper_row = inventory_by_path.get(str(helper.get("source_path")))
    expected_status_files = (
        [
            {
                "path": helper_row["path"],
                "sha256": helper_row["sha256"],
                "size": helper_row["size"],
            }
        ]
        if helper_row is not None
        else None
    )
    if (
        expected_status_files is None
        or status_runtime.get("files") != expected_status_files
        or helper_row["sha256"] != helper.get("sha256")
    ):
        raise ContractError("predecessor_client_roles_rejected")
    body = {
        "schema": PREDECESSOR_CLIENT_ROLES_SCHEMA,
        "selector_role": "legacy_runtime_client",
        "roles": {
            "legacy_runtime_client": {
                "role": "legacy_runtime_client",
                "protocol_schema": runtime.get("schema"),
                "sha256": runtime.get("sha256"),
                "source_path": runtime.get("source_path"),
                "operations": list(PREDECESSOR_RUNTIME_OPERATIONS),
            },
            "status_content_free_helper": {
                "role": "status_content_free_helper",
                "protocol_schema": helper.get("schema"),
                "sha256": helper.get("sha256"),
                "source_path": helper.get("source_path"),
                "runtime_path": gateway.get("runtime_path"),
                "operations": list(PREDECESSOR_STATUS_OPERATIONS),
            },
        },
        "lineage": {
            "compatibility_schema": compatibility.get("schema"),
            "predecessor_core_commit": compatibility.get("predecessor_core_commit"),
            "predecessor_deploy_commit": compatibility.get("predecessor_deploy_commit"),
            "predecessor_release_digest": compatibility.get("predecessor_release_digest"),
            "selected_manifest_sha256": manifest_sha256,
            "status_runtime_digest": digest_value(status_runtime),
            "upgrade_compatibility_digest": digest_value(compatibility),
        },
    }
    value = {**body, "role_digest": digest_value(body)}
    return _predecessor_client_roles(
        value,
        inventory=inventory,
        manifest_sha256=manifest_sha256,
    )


def build_predecessor_binding(
    *,
    release_identity: str,
    manifest_sha256: str,
    manifest_size: int,
    manifest: Mapping[str, object],
    inventory: list[dict[str, object]],
    directories: list[dict[str, object]],
    unit_semantics: Mapping[str, object],
) -> dict[str, object]:
    _hex64(release_identity, "predecessor_release_rejected")
    _hex64(manifest_sha256, "predecessor_release_rejected")
    if (
        not isinstance(manifest_size, int)
        or isinstance(manifest_size, bool)
        or manifest_size < 1
        or not isinstance(manifest, Mapping)
    ):
        raise ContractError("predecessor_release_rejected")
    core_commit = _commit(manifest.get("core_commit"), "predecessor_release_rejected")
    deploy_commit = _commit(
        manifest.get("deploy_commit"), "predecessor_release_rejected"
    )
    files = manifest.get("files")
    if not isinstance(files, list):
        raise ContractError("predecessor_release_rejected")
    normalized_inventory = _target_inventory(inventory)
    normalized_directories = _target_directories(
        directories,
        file_inventory=normalized_inventory,
    )
    client_roles = build_predecessor_client_roles(
        manifest,
        inventory=normalized_inventory,
        manifest_sha256=manifest_sha256,
    )
    expected_files = [
        {
            "path": row["path"],
            "sha256": row["sha256"],
            "size": row["size"],
        }
        for row in normalized_inventory
        if row["path"] != "manifest.json"
    ]
    if files != expected_files:
        raise ContractError("predecessor_release_rejected")
    semantics = {
        "service": _unit_semantics(
            unit_semantics.get("service") if isinstance(unit_semantics, Mapping) else None,
            expected_role="service",
        ),
        "socket": _unit_semantics(
            unit_semantics.get("socket") if isinstance(unit_semantics, Mapping) else None,
            expected_role="socket",
        ),
    }
    runtime = build_unit_runtime(semantics, profile="predecessor")
    rows_by_path = {str(row["path"]): row for row in normalized_inventory}
    service_row = rows_by_path.get(
        "systemd/myuna-active-temporal-context-v1.service"
    )
    socket_row = rows_by_path.get(
        "systemd/myuna-active-temporal-context-v1.socket"
    )
    manifest_row = rows_by_path.get("manifest.json")
    if (
        service_row is None
        or socket_row is None
        or manifest_row is None
        or manifest_row["sha256"] != manifest_sha256
        or manifest_row["size"] != manifest_size
    ):
        raise ContractError("predecessor_release_rejected")
    public_binding = {
        "environment": {
            "mode": 0o600,
            "pythonpath": (
                f"{PRODUCTION_PATHS['release_root']}/{release_identity}/src"
            ),
            "state_root": PRODUCTION_PATHS["state_root"],
        },
        "file_identity": {
            "environment": {"gid": 0, "mode": 0o600, "nlink": 1, "uid": 0},
            "selector": {"gid": 0, "mode": 0o600, "nlink": 1, "uid": 0},
            "service_unit": {
                "gid": 0,
                "mode": 0o644,
                "nlink": 1,
                "sha256": service_row["sha256"],
                "size": service_row["size"],
                "uid": 0,
            },
            "socket_unit": {
                "gid": 0,
                "mode": 0o644,
                "nlink": 1,
                "sha256": socket_row["sha256"],
                "size": socket_row["size"],
                "uid": 0,
            },
        },
        "selector": {
            "core_commit": core_commit,
            "deploy_commit": deploy_commit,
            "gateway_client_sha256": client_roles["roles"][
                "legacy_runtime_client"
            ]["sha256"],
            "release_digest": release_identity,
            "release_path": (
                f"{PRODUCTION_PATHS['release_root']}/{release_identity}"
            ),
            "schema": SELECTOR_SCHEMA,
        },
    }
    body = {
        "schema": PREDECESSOR_RELEASE_SCHEMA,
        "client_roles": client_roles,
        "release_identity": release_identity,
        "manifest_sha256": manifest_sha256,
        "manifest_size": manifest_size,
        "core_commit": core_commit,
        "deploy_commit": deploy_commit,
        "inventory": normalized_inventory,
        "inventory_digest": digest_value(normalized_inventory),
        "directories": normalized_directories,
        "directories_digest": digest_value(normalized_directories),
        "unit_semantics": semantics,
        "unit_runtime": runtime,
        "public_binding": public_binding,
    }
    return {**body, "source_lineage_digest": digest_value(body)}


def _predecessor_release(value: object) -> dict[str, object]:
    keys = {
        "client_roles",
        "core_commit",
        "deploy_commit",
        "directories",
        "directories_digest",
        "inventory",
        "inventory_digest",
        "manifest_sha256",
        "manifest_size",
        "public_binding",
        "release_identity",
        "schema",
        "source_lineage_digest",
        "unit_runtime",
        "unit_semantics",
    }
    _exact_keys(value, keys, "predecessor_release_rejected")
    assert isinstance(value, Mapping)
    if value["schema"] != PREDECESSOR_RELEASE_SCHEMA:
        raise ContractError("predecessor_release_rejected")
    _hex64(value["release_identity"], "predecessor_release_rejected")
    _hex64(value["manifest_sha256"], "predecessor_release_rejected")
    _commit(value["core_commit"], "predecessor_release_rejected")
    _commit(value["deploy_commit"], "predecessor_release_rejected")
    if (
        not isinstance(value["manifest_size"], int)
        or isinstance(value["manifest_size"], bool)
        or value["manifest_size"] < 1
    ):
        raise ContractError("predecessor_release_rejected")
    inventory = _target_inventory(value["inventory"])
    client_roles = _predecessor_client_roles(
        value["client_roles"],
        inventory=inventory,
        manifest_sha256=value["manifest_sha256"],
    )
    directories = _target_directories(
        value["directories"], file_inventory=inventory
    )
    if (
        value["inventory_digest"] != digest_value(inventory)
        or value["directories_digest"] != digest_value(directories)
    ):
        raise ContractError("predecessor_release_rejected")
    semantics = {
        "service": _unit_semantics(
            value["unit_semantics"].get("service")
            if isinstance(value["unit_semantics"], Mapping)
            else None,
            expected_role="service",
        ),
        "socket": _unit_semantics(
            value["unit_semantics"].get("socket")
            if isinstance(value["unit_semantics"], Mapping)
            else None,
            expected_role="socket",
        ),
    }
    runtime = _unit_runtime(value["unit_runtime"])
    if runtime != build_unit_runtime(semantics, profile="predecessor"):
        raise ContractError("predecessor_release_rejected")
    public = value["public_binding"]
    _exact_keys(
        public,
        {"environment", "file_identity", "selector"},
        "predecessor_release_rejected",
    )
    assert isinstance(public, Mapping)
    selector = public["selector"]
    _exact_keys(
        selector,
        {
            "core_commit",
            "deploy_commit",
            "gateway_client_sha256",
            "release_digest",
            "release_path",
            "schema",
        },
        "predecessor_release_rejected",
    )
    if (
        selector["schema"] != SELECTOR_SCHEMA
        or selector["core_commit"] != value["core_commit"]
        or selector["deploy_commit"] != value["deploy_commit"]
        or selector["release_digest"] != value["release_identity"]
        or selector["release_path"]
        != f"{PRODUCTION_PATHS['release_root']}/{value['release_identity']}"
        or selector["gateway_client_sha256"]
        != client_roles["roles"]["legacy_runtime_client"]["sha256"]
    ):
        raise ContractError("predecessor_release_rejected")
    _hex64(selector["gateway_client_sha256"], "predecessor_release_rejected")
    environment = public["environment"]
    _exact_keys(
        environment,
        {"mode", "pythonpath", "state_root"},
        "predecessor_release_rejected",
    )
    if (
        environment["mode"] != 0o600
        or environment["pythonpath"]
        != f"{PRODUCTION_PATHS['release_root']}/{value['release_identity']}/src"
        or environment["state_root"] != PRODUCTION_PATHS["state_root"]
    ):
        raise ContractError("predecessor_release_rejected")
    identities = public["file_identity"]
    _exact_keys(
        identities,
        set(PUBLIC_ROLES),
        "predecessor_release_rejected",
    )
    inventory_by_path = {str(row["path"]): row for row in inventory}
    for role in ("environment", "selector"):
        _exact_keys(
            identities[role],
            {"gid", "mode", "nlink", "uid"},
            "predecessor_release_rejected",
        )
        if identities[role] != {"gid": 0, "mode": 0o600, "nlink": 1, "uid": 0}:
            raise ContractError("predecessor_release_rejected")
    for role, relative in (
        ("service_unit", "systemd/myuna-active-temporal-context-v1.service"),
        ("socket_unit", "systemd/myuna-active-temporal-context-v1.socket"),
    ):
        _exact_keys(
            identities[role],
            {"gid", "mode", "nlink", "sha256", "size", "uid"},
            "predecessor_release_rejected",
        )
        row = inventory_by_path.get(relative)
        if row is None or identities[role] != {
            "gid": 0,
            "mode": 0o644,
            "nlink": 1,
            "sha256": row["sha256"],
            "size": row["size"],
            "uid": 0,
        }:
            raise ContractError("predecessor_release_rejected")
    normalized = {
        key: value[key] for key in keys if key != "source_lineage_digest"
    }
    normalized["inventory"] = inventory
    normalized["client_roles"] = client_roles
    normalized["directories"] = directories
    normalized["unit_semantics"] = semantics
    normalized["unit_runtime"] = runtime
    normalized["public_binding"] = json.loads(canonical_bytes(public))
    if value["source_lineage_digest"] != digest_value(normalized):
        raise ContractError("predecessor_release_rejected")
    return {**normalized, "source_lineage_digest": value["source_lineage_digest"]}


def _account_projection(
    value: object,
    *,
    account_contract: Mapping[str, object],
) -> dict[str, object]:
    _exact_keys(value, {"gateway", "schema", "service"}, "account_projection_rejected")
    assert isinstance(value, Mapping)
    if value["schema"] != ACCOUNT_PROJECTION_SCHEMA:
        raise ContractError("account_projection_rejected")
    projected: dict[str, object] = {"schema": ACCOUNT_PROJECTION_SCHEMA}
    for role in ("gateway", "service"):
        expected = account_contract[role]
        row = value[role]
        _exact_keys(
            row,
            {"gid", "groups", "primary_group", "uid", "user"},
            "account_projection_rejected",
        )
        assert isinstance(row, Mapping)
        groups = row["groups"]
        if not isinstance(groups, list) or not groups:
            raise ContractError("account_projection_rejected")
        normalized_groups: list[dict[str, object]] = []
        for group in groups:
            _exact_keys(group, {"gid", "name"}, "account_projection_rejected")
            assert isinstance(group, Mapping)
            if (
                not isinstance(group["name"], str)
                or not group["name"]
                or not isinstance(group["gid"], int)
                or isinstance(group["gid"], bool)
                or group["gid"] < 0
            ):
                raise ContractError("account_projection_rejected")
            normalized_groups.append(dict(group))
        if normalized_groups != sorted(
            normalized_groups, key=lambda group: (str(group["name"]), int(group["gid"]))
        ) or len({str(group["name"]) for group in normalized_groups}) != len(
            normalized_groups
        ):
            raise ContractError("account_projection_rejected")
        group_map = {str(group["name"]): int(group["gid"]) for group in normalized_groups}
        if (
            row["user"] != expected["user"]
            or row["primary_group"] != expected["primary_group"]
            or row["uid"] != expected["uid"]
            or row["gid"] != expected["gid"]
            or group_map.get(str(row["primary_group"])) != row["gid"]
            or normalized_groups != expected["groups"]
        ):
            raise ContractError("account_projection_rejected")
        projected[role] = {
            "user": row["user"],
            "uid": row["uid"],
            "primary_group": row["primary_group"],
            "gid": row["gid"],
            "groups": normalized_groups,
        }
    return projected


def _effective_unit_state(
    value: object, *, expected_runtime: Mapping[str, object] | None = None
) -> dict[str, object]:
    _exact_keys(value, {"schema", "service", "socket"}, "unit_state_rejected")
    assert isinstance(value, Mapping)
    if value["schema"] != UNIT_RUNTIME_SCHEMA:
        raise ContractError("unit_state_rejected")
    runtime = _unit_runtime(expected_runtime) if expected_runtime is not None else None
    projected: dict[str, object] = {"schema": UNIT_RUNTIME_SCHEMA}
    for role in ("service", "socket"):
        expected_static = runtime[role] if runtime is not None else None
        static_keys = (
            set(expected_static)
            if isinstance(expected_static, Mapping)
            else (
                {
                    "control_group",
                    "credential_launch",
                    "dependencies",
                    "dependency_injection_paths",
                    "drop_in_paths",
                    "dynamic_user",
                    "environment_files",
                    "execution_policy",
                    "exec_start_argv",
                    "fragment_path",
                    "group",
                    "load_state",
                    "pam_name",
                    "private_users",
                    "process_identity",
                    "ready_active_state",
                    "ready_sub_state",
                    "set_login_environment",
                    "slice",
                    "supplementary_groups",
                    "unit_file_state",
                    "user",
                }
                if role == "service"
                else {
                    "control_group",
                    "dependencies",
                    "dependency_injection_paths",
                    "drop_in_paths",
                    "fragment_path",
                    "listen_stream",
                    "load_state",
                    "ready_active_state",
                    "ready_sub_state",
                    "service",
                    "socket_group",
                    "socket_mode",
                    "socket_user",
                    "slice",
                    "unit_file_state",
                }
            )
        )
        row = value[role]
        _exact_keys(
            row,
            static_keys | {"active_state", "sub_state"},
            "unit_state_rejected",
        )
        assert isinstance(row, Mapping)
        if expected_static is not None and any(
            row[key] != expected_static[key] for key in static_keys
        ):
            raise ContractError("unit_state_rejected")
        if (
            not isinstance(row["active_state"], str)
            or re.fullmatch(r"[a-z][a-z0-9_-]{1,31}", row["active_state"])
            is None
            or not isinstance(row["sub_state"], str)
            or re.fullmatch(r"[a-z][a-z0-9_-]{1,31}", row["sub_state"])
            is None
        ):
            raise ContractError("unit_state_rejected")
        projected[role] = dict(row)
    return projected


def _coupled_unit_state_name(
    value: Mapping[str, object],
    effective: Mapping[str, object],
) -> str:
    service = effective["service"]
    socket = effective["socket"]
    assert isinstance(service, Mapping)
    assert isinstance(socket, Mapping)
    observed = {
        "service": [service["active_state"], service["sub_state"]],
        "socket": [socket["active_state"], socket["sub_state"]],
    }
    matches = [
        str(state["name"])
        for state in _unit_coupled_state_machine()["states"]
        if state["service"] == observed["service"]
        and state["socket"] == observed["socket"]
    ]
    policy = _unit_enablement_policy()
    if (
        len(matches) != 1
        or value["service_enabled"] is not policy["service"]["enabled"]
        or value["socket_enabled"] is not policy["socket"]["enabled"]
        or service["unit_file_state"] != policy["service"]["unit_file_state"]
        or socket["unit_file_state"] != policy["socket"]["unit_file_state"]
        or (value["service_active"] is True)
        != (service["active_state"] == "active")
        or (value["socket_active"] is True)
        != (socket["active_state"] == "active")
    ):
        raise ContractError("unit_state_rejected")
    return matches[0]


def _unit_snapshot(
    value: object, *, expected_runtime: Mapping[str, object] | None = None
) -> dict[str, object]:
    keys = {
        "coupled_state",
        "effective",
        "schema",
        "service_active",
        "service_active_enter_monotonic_usec",
        "service_enabled",
        "service_main_pid",
        "service_process",
        "service_restarts",
        "socket_active",
        "socket_active_enter_monotonic_usec",
        "socket_enabled",
        "socket_inode",
        "socket_n_accepted",
        "socket_n_connections",
    }
    _exact_keys(value, keys, "unit_state_rejected")
    assert isinstance(value, Mapping)
    if (
        value["schema"] != UNIT_STATE_SCHEMA
        or not isinstance(value["service_active"], bool)
        or not isinstance(value["service_enabled"], bool)
        or not isinstance(value["socket_active"], bool)
        or not isinstance(value["socket_enabled"], bool)
        or any(
            not isinstance(value[key], int)
            or isinstance(value[key], bool)
            or value[key] < 0
            for key in (
                "service_active_enter_monotonic_usec",
                "service_main_pid",
                "service_restarts",
                "socket_active_enter_monotonic_usec",
                "socket_n_accepted",
                "socket_n_connections",
            )
        )
    ):
        raise ContractError("unit_state_rejected")
    effective = _effective_unit_state(
        value["effective"], expected_runtime=expected_runtime
    )
    process = value["service_process"]
    if value["service_active"]:
        _exact_keys(
            process,
            {
                "argv",
                "cgroup",
                "executable",
                "gid",
                "groups",
                "pid",
                "schema",
                "start_ticks",
                "uid",
            },
            "unit_state_rejected",
        )
        assert isinstance(process, Mapping)
        expected_process = effective["service"]["process_identity"]
        if (
            process["schema"] != PROCESS_IDENTITY_SCHEMA
            or not isinstance(process["pid"], int)
            or isinstance(process["pid"], bool)
            or process["pid"] < 1
            or not isinstance(process["start_ticks"], int)
            or isinstance(process["start_ticks"], bool)
            or process["start_ticks"] < 1
            or process["pid"] != value["service_main_pid"]
            or any(
                process[key] != expected_process[key]
                for key in ("argv", "cgroup", "executable", "gid", "groups", "uid")
            )
        ):
            raise ContractError("unit_state_rejected")
        normalized_process: dict[str, object] | None = dict(process)
    else:
        if process is not None or value["service_main_pid"] != 0:
            raise ContractError("unit_state_rejected")
        normalized_process = None
    socket_inode = value["socket_inode"]
    if value["socket_active"]:
        _exact_keys(
            socket_inode,
            {"gid", "mode", "nlink", "path", "schema", "type", "uid"},
            "unit_state_rejected",
        )
        assert isinstance(socket_inode, Mapping)
        expected_socket_mode = int(str(effective["socket"]["socket_mode"]), 8)
        if socket_inode != {
            "schema": SOCKET_INODE_SCHEMA,
            "path": PRODUCTION_PATHS["socket_endpoint"],
            "type": "socket",
            "mode": expected_socket_mode,
            "uid": PRODUCTION_ACCOUNTS["service"]["uid"],
            "gid": PRODUCTION_ACCOUNTS["gateway"]["gid"],
            "nlink": 1,
        }:
            raise ContractError("unit_state_rejected")
        normalized_socket_inode: dict[str, object] | None = dict(socket_inode)
    else:
        if socket_inode is not None:
            raise ContractError("unit_state_rejected")
        normalized_socket_inode = None
    if (
        not isinstance(value["coupled_state"], str)
        or value["coupled_state"] != _coupled_unit_state_name(value, effective)
    ):
        raise ContractError("unit_state_rejected")
    return {
        **dict(value),
        "effective": effective,
        "service_process": normalized_process,
        "socket_inode": normalized_socket_inode,
    }


def _unit_state(
    value: object, *, expected_runtime: Mapping[str, object] | None = None
) -> dict[str, object]:
    """Validate a stable operational readiness projection.

    Mutation phases use ``_unit_snapshot`` because stopped units are a valid
    intermediate state.  Plans and readiness use this stricter function so a
    stable but inactive/restarting predecessor can never become ready merely
    by remaining byte-identical.
    """

    projected = _unit_snapshot(value, expected_runtime=expected_runtime)
    if (
        projected["service_active"] is not True
        or projected["service_enabled"] is not False
        or projected["socket_active"] is not True
        or projected["socket_enabled"] is not True
        or projected["service_restarts"] != 0
        or projected["service_main_pid"] < 1
        or projected["service_active_enter_monotonic_usec"] < 1
        or projected["socket_active_enter_monotonic_usec"] < 1
        or projected["socket_n_connections"] != 0
        or projected["effective"]["service"]["active_state"] != "active"
        or projected["effective"]["service"]["sub_state"] != "running"
        or projected["effective"]["socket"]["active_state"] != "active"
        or projected["effective"]["socket"]["sub_state"] != "running"
        or projected["coupled_state"]
        != _unit_coupled_state_machine()["ready_state"]
    ):
        raise ContractError("unit_state_rejected")
    return projected


def validate_execution(contract: Mapping[str, object], value: Mapping[str, object]) -> dict[str, object]:
    validated_contract = validate_contract(contract)
    keys = {
        "account_projection",
        "acceptance_scope_digest",
        "backend",
        "opaque_prestate",
        "predecessor_release",
        "public_prestate",
        "root",
        "schema",
        "selected_release_identity",
        "selector_compatibility",
        "execution_substrate",
        "runtime_package",
        "target_directories",
        "target_directories_digest",
        "target_inventory",
        "target_inventory_digest",
        "target_manifest_sha256",
        "target_source_path",
        "unit_prestate",
    }
    _exact_keys(value, keys, "execution_keys_rejected")
    if value["schema"] != EXECUTION_SCHEMA or value["backend"] not in {"synthetic", "systemd"}:
        raise ContractError("execution_schema_rejected")
    root = _absolute_path(value["root"], "execution_root_rejected")
    if (value["backend"] == "synthetic" and root == "/") or (
        value["backend"] == "systemd" and root != "/"
    ):
        raise ContractError("execution_root_rejected")
    if value["backend"] == "systemd":
        if value["execution_substrate"] != validated_contract["systemd_authority"]:
            raise ContractError("execution_substrate_rejected")
        execution_substrate: dict[str, object] | None = dict(
            value["execution_substrate"]
        )
    else:
        if value["execution_substrate"] is not None:
            raise ContractError("execution_substrate_rejected")
        execution_substrate = None
    target_source = _absolute_path(value["target_source_path"], "target_source_rejected")
    if HEX64.fullmatch(target_source.rstrip("/").rsplit("/", 1)[-1]) is None:
        raise ContractError("target_source_rejected")
    _hex64(value["target_manifest_sha256"], "target_source_rejected")
    _hex64(value["acceptance_scope_digest"], "acceptance_scope_rejected")
    _hex64(value["selected_release_identity"], "selected_release_identity_rejected")
    account_projection = _account_projection(
        value["account_projection"],
        account_contract=validated_contract["production_adapter"]["accounts"],
    )
    selector_compatibility = value["selector_compatibility"]
    _exact_keys(
        selector_compatibility,
        {"gateway_client_sha256", "gateway_manifest_digest", "plugin_digest"},
        "selector_compatibility_rejected",
    )
    for field in selector_compatibility.values():
        _hex64(field, "selector_compatibility_rejected")
    public = value["public_prestate"]
    _exact_keys(public, set(PUBLIC_ROLES), "public_prestate_rejected")
    fixed = validated_contract["production_adapter"]["fixed_paths"]
    public_rows = {
        role: _public_file(public[role], expected_path=str(fixed[role]))
        for role in PUBLIC_ROLES
    }
    opaque = _opaque_state(value["opaque_prestate"], expected_path=str(fixed["state_root"]))
    predecessor = _predecessor_release(value["predecessor_release"])
    expected_predecessor = validated_contract["compatibility"].get("predecessor")
    if (
        predecessor != expected_predecessor
        or predecessor["release_identity"] != value["selected_release_identity"]
    ):
        raise ContractError("predecessor_release_rejected")
    if (
        account_projection["service"]["uid"] != opaque["root"]["uid"]
        or account_projection["service"]["gid"] != opaque["root"]["gid"]
    ):
        raise ContractError("account_projection_rejected")
    inventory = _target_inventory(value["target_inventory"])
    if value["target_inventory_digest"] != digest_value(inventory):
        raise ContractError("target_inventory_rejected")
    directories = _target_directories(
        value["target_directories"],
        file_inventory=inventory,
    )
    if value["target_directories_digest"] != digest_value(directories):
        raise ContractError("target_directory_inventory_rejected")
    runtime_package = value["runtime_package"]
    _exact_keys(
        runtime_package,
        {
            "contract_digest",
            "directories_digest",
            "inventory_digest",
            "manifest_sha256",
            "root",
            "schema",
        },
        "runtime_package_rejected",
    )
    assert isinstance(runtime_package, Mapping)
    if (
        runtime_package["schema"] != RUNTIME_PACKAGE_SCHEMA
        or runtime_package["root"] != target_source
        or runtime_package["contract_digest"] != validated_contract["contract_digest"]
        or runtime_package["inventory_digest"] != value["target_inventory_digest"]
        or runtime_package["directories_digest"] != value["target_directories_digest"]
        or runtime_package["manifest_sha256"] != value["target_manifest_sha256"]
    ):
        raise ContractError("runtime_package_rejected")
    unit_prestate = _unit_state(
        value["unit_prestate"],
        expected_runtime=predecessor["unit_runtime"],
    )
    return {
        "schema": EXECUTION_SCHEMA,
        "backend": value["backend"],
        "account_projection": account_projection,
        "root": root,
        "target_source_path": target_source,
        "target_manifest_sha256": value["target_manifest_sha256"],
        "target_inventory": inventory,
        "target_inventory_digest": value["target_inventory_digest"],
        "target_directories": directories,
        "target_directories_digest": value["target_directories_digest"],
        "public_prestate": public_rows,
        "predecessor_release": predecessor,
        "opaque_prestate": opaque,
        "acceptance_scope_digest": value["acceptance_scope_digest"],
        "selected_release_identity": value["selected_release_identity"],
        "selector_compatibility": dict(selector_compatibility),
        "execution_substrate": execution_substrate,
        "runtime_package": dict(runtime_package),
        "unit_prestate": unit_prestate,
    }


def legacy_lineage_index() -> dict[str, object]:
    body = {
        "schema": LEGACY_INDEX_SCHEMA,
        "closed_architecture": "myuna.p08-current-selected-upgrade.v13",
        "failure_policy_sha256": (
            "1c98fc703ab833758c40ee5de50fa7883bb95b5baa6166750b9b7ba2dda3ec1"
        ),
        # Preserve the accepted architecture-reset baseline while binding the
        # cumulative project-policy count.  The latter is never derived from a
        # version, strategy or namespace name.
        "architecture_reset_failure_counted": 16,
        "architecture_reset_failure_excluded": 1,
        "failure_counted": 21,
        "failure_excluded": 1,
        "post_reset_counted_terminal_handoff_sha256": [
            "9f38cabea5425d654cde541cb3b9eed0a726b3c0490736ec3a82a60f36949897",
            "299489cd94b341f5f3f4a67a5bdc744d65fc910af3184f5edb160de0929760d3",
            "3c7065cb6047762774fb6b67aa08f18f7c8a44b4f8276f5507c13c95f4fdd7f15",
            "87761e4c00d2ec353ba46457de39ec6460d93e733f28da6e50cdb4a71a5fa0d9",
            "2cddf0f2768bdc9a876d14e94c02a36a1b2eb83299412a4281d07e72ae1a38ca",
        ],
        "v13_audit_handoff_sha256": (
            "1783041c6e474753f5929efbde27cd11433f5ed6fd4198b35ac989df2f8bc8e3"
        ),
        "v13_source_commit": "ff2e25cbf2249b6da99103ad45f65e89f345ad87",
        "v13_source_tree": "ae3e8e740e2bac8e055d3eb0f056ddc433ab48fb",
        "old_sequences_replayable": False,
        "old_incidents_resettable": False,
    }
    return {**body, "lineage_digest": digest_value(body)}


def _role_contracts() -> dict[str, object]:
    contracts: dict[str, object] = {}
    for role in ROLE_ORDER:
        if role == "prepare":
            hard_seconds, no_progress_seconds = 60, 45
        elif role in {"formal1", "formal2"}:
            hard_seconds, no_progress_seconds = 180, 75
        elif role in {"accept_status", "continuity_assessment"}:
            hard_seconds, no_progress_seconds = 30, 20
        elif role in {"converge", "recover"}:
            hard_seconds, no_progress_seconds = 120, 45
        else:
            hard_seconds, no_progress_seconds = 90, 45
        if role == "prepare":
            progress_phases = [
                "startup",
                "source_lineage",
                "current_public_snapshot",
                "plan_verify",
                "canonical_serialization",
            ]
        elif role in {"formal1", "formal2"}:
            progress_phases = [
                "startup",
                "source_lineage",
                "target_validation_pass1",
                "current_public_snapshot",
                "plan_verify",
                "target_validation_pass2",
                "canonical_serialization",
            ]
        else:
            progress_phases = [
                "startup",
                "source_lineage",
                "inputs",
                "execute",
                "canonical_serialization",
            ]
        contracts[role] = {
            "role": role,
            "call_budget": 2 if role == "postflight" else 1,
            "hard_deadline_seconds": hard_seconds,
            "no_progress_seconds": no_progress_seconds,
            "metadata_only": role in READINESS_ROLES,
            "mutation_allowed": role in MUTATION_ROLES,
            "payload_keys": list(_PAYLOAD_KEYS[role]),
            "progress_phases": progress_phases,
            "success_result_class": _ROLE_RESULT_CLASS[role],
        }
    return contracts


def _parse_unit_directives(raw: bytes) -> list[tuple[str, str, str]]:
    try:
        text = raw.decode("ascii", "strict")
    except UnicodeError:
        raise ContractError("boot_recovery_transaction_rejected") from None
    if not text.endswith("\n") or "\r" in text or "\x00" in text:
        raise ContractError("boot_recovery_transaction_rejected")
    section = ""
    seen_sections: set[str] = set()
    rows: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            if section not in {"Unit", "Service", "Install"} or section in seen_sections:
                raise ContractError("boot_recovery_transaction_rejected")
            seen_sections.add(section)
            continue
        if not section or "=" not in line:
            raise ContractError("boot_recovery_transaction_rejected")
        key, value = line.split("=", 1)
        if not key or not value:
            raise ContractError("boot_recovery_transaction_rejected")
        rows.append((section, key, value))
    if seen_sections != {"Unit", "Service", "Install"}:
        raise ContractError("boot_recovery_transaction_rejected")
    return rows


def parse_boot_recovery_transaction(
    recovery_unit_raw: bytes,
    gate_raw: bytes,
) -> dict[str, object]:
    rows = _parse_unit_directives(recovery_unit_raw)

    def exact(section: str, key: str, expected: str) -> None:
        values = [
            value
            for candidate_section, candidate_key, value in rows
            if candidate_section == section and candidate_key == key
        ]
        if values != [expected] or any(
            candidate_key == key and candidate_section != section
            for candidate_section, candidate_key, _value in rows
        ):
            raise ContractError("boot_recovery_transaction_rejected")

    version_identity = str(PRODUCTION_SYSTEMD["version_identity"])
    match = re.fullmatch(r"systemd-([0-9]+)", version_identity)
    if match is None or int(match.group(1)) < 254:
        raise ContractError("boot_recovery_transaction_rejected")
    recovery_name = str(PRODUCTION_PATHS["recovery_unit_name"])
    expected_gate = (
        "[Unit]\n"
        f"Requires={recovery_name}\n"
        f"After={recovery_name}\n"
    ).encode("ascii")
    if gate_raw != expected_gate:
        raise ContractError("boot_recovery_transaction_rejected")
    exact("Unit", "StartLimitBurst", "2")
    exact("Service", "Type", "oneshot")
    exact("Service", "Restart", "on-failure")
    exact("Service", "RestartMode", "direct")
    exact("Service", "RestartPreventExitStatus", "2")
    exact("Service", "RemainAfterExit", "yes")
    exact("Install", "WantedBy", "multi-user.target")
    return {
        "schema": BOOT_RECOVERY_TRANSACTION_SCHEMA,
        "systemd_version_identity": version_identity,
        "restart_mode_added_version": 254,
        "service_type": "oneshot",
        "restart": "on-failure",
        "restart_mode": "direct",
        "restart_prevent_exit_status": [2],
        "start_limit_burst": 2,
        "remain_after_exit": True,
        "dependent_relationship": ["Requires", "After"],
        "direct_reentry_preserves_dependent_job": True,
        "typed_blocked_fails_dependency": True,
        "second_unexpected_failure_fails_dependency": True,
    }


def _boot_recovery_artifacts() -> list[dict[str, object]]:
    fixed = PRODUCTION_PATHS
    authority = PRODUCTION_SYSTEMD
    runtime = str(fixed["recovery_runtime_root"])
    recovery_name = str(fixed["recovery_unit_name"])
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": runtime + "/scripts:" + runtime + "/src",
    }
    exec_start = " ".join(
        [
            str(authority["environment_scrubber"]["path"]),
            "-i",
            *[key + "=" + environment[key] for key in sorted(environment)],
            str(authority["credential_drop"]["path"]),
            "--reuid=0",
            "--regid=0",
            "--clear-groups",
            "--no-new-privs",
            str(PRODUCTION_INTERPRETER["invocation_path"]),
            "-B",
            "-P",
            "-S",
            "-m",
            "p08_activation_boot_recovery_v1",
            "--activation-contract",
            runtime + "/contracts/P08_ACTIVATION_CONTRACT.json",
            "--activation-root",
            "/",
        ]
    )
    recovery_unit = (
        "[Unit]\n"
        "Description=Myuna P08 activation boot recovery gate v1\n"
        "DefaultDependencies=no\n"
        "StartLimitIntervalSec=900s\n"
        "StartLimitBurst=2\n"
        "Requires=local-fs.target\n"
        "After=local-fs.target\n"
        f"Before={fixed['service_name']} {fixed['socket_name']} shutdown.target\n"
        "Conflicts=shutdown.target\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "User=0\n"
        "Group=0\n"
        "SetLoginEnvironment=no\n"
        f"WorkingDirectory={runtime}\n"
        f"ExecStart={exec_start}\n"
        "NoNewPrivileges=yes\n"
        "PrivateTmp=yes\n"
        "PrivateDevices=yes\n"
        "ProtectHome=yes\n"
        "ProtectKernelTunables=yes\n"
        "ProtectKernelModules=yes\n"
        "ProtectControlGroups=yes\n"
        "RestrictAddressFamilies=AF_UNIX\n"
        "UMask=0077\n"
        "TimeoutStartSec=900s\n"
        "RuntimeMaxSec=900s\n"
        "Restart=on-failure\n"
        "RestartMode=direct\n"
        "RestartPreventExitStatus=2\n"
        "RestartSec=1s\n"
        "RemainAfterExit=yes\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    ).encode("ascii")
    gate = (
        "[Unit]\n"
        f"Requires={recovery_name}\n"
        f"After={recovery_name}\n"
    ).encode("ascii")

    def regular(role: str, path: str, raw: bytes) -> dict[str, object]:
        return {
            "role": role,
            "path": path,
            "type": "file",
            "mode": 0o644,
            "uid": 0,
            "gid": 0,
            "nlink": 1,
            "size": len(raw),
            "sha256": sha256(raw).hexdigest(),
            "content": raw.decode("ascii"),
        }

    return [
        regular("recovery_unit", str(fixed["recovery_unit"]), recovery_unit),
        regular(
            "service_recovery_dropin",
            str(fixed["service_recovery_dropin"]),
            gate,
        ),
        regular(
            "socket_recovery_dropin",
            str(fixed["socket_recovery_dropin"]),
            gate,
        ),
        {
            "role": "recovery_enablement",
            "path": str(fixed["recovery_enablement"]),
            "type": "symlink",
            "mode": None,
            "uid": 0,
            "gid": 0,
            "nlink": 1,
            "size": len("../" + recovery_name),
            "sha256": sha256(("../" + recovery_name).encode("ascii")).hexdigest(),
            "target": "../" + recovery_name,
        },
    ]


def _retained_residue_normalization_contract(
    artifacts: list[dict[str, object]],
    source_inventory: list[dict[str, object]],
) -> dict[str, object]:
    """Bind the closed failure-21 residue without authorizing its mutation."""

    body = {
        "schema": RECOVERY_RESIDUE_NORMALIZATION_PLAN_SCHEMA,
        "mode": "verify_only",
        "source_authority": {
            "accepted_t0_handoff_sha256": (
                "51e5d093f9a453886fc694e749ab12156562257c1c0c4bc0db71c5009f19b24a"
            ),
            "architecture": ARCHITECTURE,
            "source_inventory_digest": digest_value(source_inventory),
            "recovery_artifacts_digest": digest_value(artifacts),
        },
        "terminal_handoff_sha256": (
            "2cddf0f2768bdc9a876d14e94c02a36a1b2eb83299412a4281d07e72ae1a38ca"
        ),
        "entry_identity": (
            "a78258620da75c530811fec517d652635fe219e94438cc183208109dac011693"
        ),
        "sequence_identity": (
            "63cd2dbf51dd4ac827f3712c036b65e87f585a436ca4e2a9e6a6f449570dc0d7"
        ),
        "plan_digest": (
            "469deea5d22e1818d6575c2392609f8503b49dc300ac486df341b7d9bee3d152"
        ),
        "launch_claim_digest": (
            "a2423d527d6dd80e673b51a4abe5c83aea3d30ca1233c967f578f4b62b516014"
        ),
        "prestate_identity": (
            "7ae707a2847bc64ae114bd7d8be369aeb70b6b281f01e9e2355225551f80e5d3"
        ),
        "predecessor_identity": (
            "1b589a474c56e138082f014724065dd57d38440b08c57b1497e5a4cb3cbe3e06"
        ),
        "failed_target_identity": (
            "b372c38b35608820a014cc1178931b808dd11ea42bad2239339b1e1c0851f735"
        ),
        "failed_contract_digest": (
            "be4b61562f2f64d346b40ae48ad5a6ea16188d0f03cd828142499b0abf6ec11a"
        ),
        "expected_residue": {
            "runtime": "exact",
            "artifacts_digest": digest_value(artifacts),
            "unit": {
                "load_state": "loaded",
                "active_state": "failed",
                "sub_state": "failed",
                "unit_file_state": "enabled",
                "result": "exit-code",
                "exec_main_code": 1,
                "exec_main_status": 2,
                "n_restarts": 0,
            },
            "closure_present": False,
            "arm_present": False,
            "disarm_present": False,
            "target_product_present": False,
            "predecessor_selected": True,
        },
        "allowed_future_operation": "infrastructure_convergence_only",
        "normalization_execution_authorized": False,
        "target_action_allowed": False,
        "forward_action_replay_allowed": False,
        "old_role_replay_allowed": False,
        "separately_sequenced_t2_required": True,
        "raw_content_included": False,
    }
    return {**body, "normalization_contract_digest": digest_value(body)}


def _boot_recovery_contract(
    source_inventory: list[dict[str, object]],
) -> dict[str, object]:
    matches = [row for row in source_inventory if row["path"] == BOOT_RECOVERY_PATH]
    if len(matches) != 1:
        raise ContractError("boot_recovery_source_rejected")
    fixed = PRODUCTION_PATHS
    artifacts = _boot_recovery_artifacts()
    recovery_units = [row for row in artifacts if row["role"] == "recovery_unit"]
    if len(recovery_units) != 1:
        raise ContractError("boot_recovery_artifact_rejected")
    recovery_gates = [
        row
        for row in artifacts
        if row["role"] in {"service_recovery_dropin", "socket_recovery_dropin"}
    ]
    if (
        len(recovery_gates) != 2
        or recovery_gates[0]["content"] != recovery_gates[1]["content"]
    ):
        raise ContractError("boot_recovery_artifact_rejected")
    transaction_liveness = parse_boot_recovery_transaction(
        str(recovery_units[0]["content"]).encode("ascii"),
        str(recovery_gates[0]["content"]).encode("ascii"),
    )
    effective_model = _recovery_systemd255_effective_model(
        str(recovery_units[0]["content"]).encode("ascii")
    )
    unit_lines = str(recovery_units[0]["content"]).splitlines()
    exec_lines = [line.removeprefix("ExecStart=") for line in unit_lines if line.startswith("ExecStart=")]
    if len(exec_lines) != 1:
        raise ContractError("boot_recovery_artifact_rejected")
    state_machine = {
        "schema": BOOT_RECOVERY_STATE_MACHINE_SCHEMA,
        "initial": "inspect_arm",
        "states": [
            "no_arm_noop",
            "disarmed_noop",
            "accepted_preserved",
            "predecessor_already_exact",
            "convergence_required",
            "converged_predecessor",
            "blocked_invalid_authority",
            "blocked_convergence_failed",
        ],
        "accepted_authority_requires": [
            "accepted_result",
            "accepted_terminal",
            "guardian_discharge",
            "strategy_launch_terminal",
        ],
        "no_forward_replay": True,
        "no_acceptance_replay": True,
        "postcommit_restores_old_history": False,
        "invalid_authority_keeps_product_blocked": True,
        "disarm_after": [
            "accepted_preserved",
            "predecessor_already_exact",
            "converged_predecessor",
        ],
    }

    infrastructure_prefixes = [
        "runtime_package",
        "recovery_unit",
        "recovery_enablement",
        "daemon_reload",
        "recovery_unit_start_no_arm",
        "closure_readback",
        "socket_recovery_dropin",
        "service_recovery_dropin",
        "arm",
        "product_gate_reload",
    ]
    artifact_roles = {str(row["role"]) for row in artifacts}
    prefix_operations: list[dict[str, object]] = []
    for prefix in infrastructure_prefixes:
        if prefix == "runtime_package":
            operation = {
                "prefix": prefix,
                "kind": "runtime_tree",
                "destination_authority": "recovery_runtime_root",
                "hidden_sibling_stage": True,
                "atomic_publish": "renameat2_noreplace",
            }
        elif prefix in artifact_roles:
            operation = {
                "prefix": prefix,
                "kind": "artifact",
                "destination_authority": prefix,
                "hidden_sibling_stage": True,
                "atomic_publish": "renameat2_noreplace",
            }
        elif prefix in {"closure_readback", "arm"}:
            operation = {
                "prefix": prefix,
                "kind": "canonical_file",
                "destination_authority": (
                    "incident_recovery_closure"
                    if prefix == "closure_readback"
                    else "boot_recovery_arm"
                ),
                "hidden_sibling_stage": True,
                "atomic_publish": "renameat2_noreplace",
            }
        else:
            operation = {
                "prefix": prefix,
                "kind": "manager_effect",
                "destination_authority": prefix,
                "hidden_sibling_stage": False,
                "atomic_publish": "not_applicable",
            }
        prefix_operations.append(operation)


    return {
        "schema": BOOT_RECOVERY_CONTRACT_SCHEMA,
        "entrypoint": BOOT_RECOVERY_PATH,
        "entrypoint_sha256": matches[0]["sha256"],
        "entry_schema": BOOT_RECOVERY_ENTRY_SCHEMA,
        "runtime_root": str(fixed["recovery_runtime_root"]),
        "runtime_identity": {
            "uid": 0,
            "gid": 0,
            "groups": [],
            "no_new_privileges": True,
        },
        "loaded_modules": [
            BOOT_RECOVERY_PATH,
            "scripts/p08_activation_contract_v1.py",
            SUPERVISOR_GUARDIAN_MANAGER_PATH,
            "scripts/p08_activation_launcher_v1.py",
            PRODUCTION_ADAPTER_PATH,
            "scripts/p08_activation_supervisor_v1.py",
        ],
        "unit_name": str(fixed["recovery_unit_name"]),
        "transaction_liveness": transaction_liveness,
        "unit_runtime": {
            "schema": BOOT_RECOVERY_UNIT_STATE_SCHEMA,
            "load_state": "loaded",
            "active_state": "active",
            "sub_state": "exited",
            "unit_file_state": "enabled",
            "result": "success",
            "exec_main_code": 1,
            "exec_main_status": 0,
            "main_pid": 0,
            "n_restarts": 0,
            "restart_mode": "direct",
            "control_group": "/system.slice/" + str(fixed["recovery_unit_name"]),
            "fragment_path": str(fixed["recovery_unit"]),
            "drop_in_paths": [],
            "exec_start_argv": exec_lines[0].split(" "),
            "dependencies": effective_model["priming_effective_dependencies"],
        },
        "armed_unit_runtime": {
            "schema": BOOT_RECOVERY_UNIT_STATE_SCHEMA,
            "load_state": "loaded",
            "active_state": "active",
            "sub_state": "exited",
            "unit_file_state": "enabled",
            "result": "success",
            "exec_main_code": 1,
            "exec_main_status": 0,
            "main_pid": 0,
            "n_restarts": 0,
            "restart_mode": "direct",
            "control_group": "/system.slice/" + str(fixed["recovery_unit_name"]),
            "fragment_path": str(fixed["recovery_unit"]),
            "drop_in_paths": [],
            "exec_start_argv": exec_lines[0].split(" "),
            "dependencies": effective_model["armed_effective_dependencies"],
        },
        "manager_entry_runtime": {
            "load_state": "loaded",
            "active_state": "activating",
            "sub_state": "start",
            "unit_file_state": "enabled",
            "result": "success",
            "exec_main_code": 0,
            "exec_main_status": 0,
            "n_restarts_allowed": [0, 1],
            "restart_mode": "direct",
            "control_group": "/system.slice/" + str(fixed["recovery_unit_name"]),
            "fragment_path": str(fixed["recovery_unit"]),
            "drop_in_paths": [],
            "exec_start_argv": exec_lines[0].split(" "),
            # The manager can legitimately reopen after a reboot at any exact
            # infrastructure prefix.  Product gate drop-ins are therefore
            # projected from the exact on-disk artifact set, while every
            # source/default/enablement edge remains fixed here.
            "base_dependencies": effective_model["priming_effective_dependencies"],
        },
        "gate_artifact_units": {
            "service_recovery_dropin": str(fixed["service_name"]),
            "socket_recovery_dropin": str(fixed["socket_name"]),
        },
        "effective_systemd_model": effective_model,
        "infrastructure_transaction": {
            "obligation_schema": RECOVERY_INFRASTRUCTURE_OBLIGATION_SCHEMA,
            "intent_schema": RECOVERY_INFRASTRUCTURE_INTENT_SCHEMA,
            "event_schema": RECOVERY_INFRASTRUCTURE_EVENT_SCHEMA,
            "convergence_schema": RECOVERY_INFRASTRUCTURE_CONVERGENCE_SCHEMA,
            "obligation_before_first_write": True,
            "intent_before_each_effect": True,
            "staging_location": "hidden_destination_sibling",
            "staging_owner_readback": "immutable_intent",
            "atomic_publish": "renameat2_noreplace",
            "event_binds_intent": True,
            "typed_failure_derives_mutation_from_transaction": True,
            "unexpected_failure_derives_mutation_from_transaction": True,
            "prestate": "absent",
            "obligation_binds_owner_boot": True,
            "same_boot_prime_before_arm": True,
            "product_gate_files_before_arm": True,
            "socket_gate_before_service_gate": True,
            "product_gate_reload_after_arm": True,
            "after_image_fields": [
                "runtime_inventory_digest",
                "runtime_directories_digest",
                "artifacts_digest",
            ],
            "artifacts_digest": digest_value(artifacts),
            "prefixes": infrastructure_prefixes,
            "prefix_operations": prefix_operations,
            "prefix_operations_digest": digest_value(prefix_operations),
            "reverse_order": list(reversed(infrastructure_prefixes)),
            "exact_partial_is_reconcilable": True,
            "mixed_or_substituted_fails_closed": True,
            "target_product_mutation_allowed": False,
            "no_arm_invocation_requires_same_boot_owned_prime_or_convergence": True,
            "boot_reentry_replays_forward_action": False,
            "manager_entry_dependencies_from_exact_gate_artifacts": True,
            "boot_self_convergence_never_stops_current_unit": True,
            "boot_self_convergence_removes_persistent_files_before_exit": True,
            "obligation_path": (
                "incident/RECOVERY.INFRASTRUCTURE/OBLIGATION.json"
            ),
            "intents_path": "incident/RECOVERY.INFRASTRUCTURE/intents",
            "events_path": "incident/RECOVERY.INFRASTRUCTURE/events",
            "convergence_path": (
                "incident/RECOVERY.INFRASTRUCTURE/CONVERGENCE.json"
            ),
        },
        "retained_residue_normalization": _retained_residue_normalization_contract(
            artifacts,
            source_inventory,
        ),
        "gate_units": [str(fixed["service_name"]), str(fixed["socket_name"])],
        "artifacts": artifacts,
        "install_order": [
            "runtime_package",
            "recovery_unit",
            "recovery_enablement",
            "daemon_reload",
            "recovery_unit_start_no_arm",
            "closure_readback",
            "socket_recovery_dropin",
            "service_recovery_dropin",
            "arm",
            "product_gate_reload",
        ],
        "hazardous_roles_after_arm": [
            "stop_socket",
            "stop_service",
            "install",
            "select",
            "continuity_assessment",
            "continuity_transition",
            "continuity_reconcile",
            "start_service",
            "start_socket",
            "accept_status",
            "converge",
            "recover",
            "postflight",
        ],
        "arm_path": str(fixed["boot_recovery_arm"]),
        "disarm_path": str(fixed["boot_recovery_disarm"]),
        "boot_receipt_root": str(fixed["boot_recovery_boots"]),
        "arm_requires_action_backup": True,
        "no_arm_is_exact_noop": False,
        "same_boot_owned_prime_is_exact_noop": True,
        "per_boot_owner_max_count": 1,
        "per_boot_manager_max_starts": 2,
        "fresh_boot_deadline_seconds": 900,
        "same_plan_convergence_only": True,
        "source_owned_launcher_required": True,
        "product_start_requires_recovery_success": True,
        "production_live_authorized": False,
        "state_machine": state_machine,
    }


def validate_retained_residue_normalization_contract(
    contract: Mapping[str, object], value: object | None = None
) -> dict[str, object]:
    """Validate the verify-only contract for failure-21's immutable residue.

    This helper grants no mutation authority.  It only proves that a future,
    separately sequenced normalization proposal is bound to the exact closed
    terminal, incident lineage and generated recovery artifact identities.
    """

    validated = validate_contract(contract)
    expected = validated["production_adapter"]["boot_recovery"][
        "retained_residue_normalization"
    ]
    candidate = expected if value is None else value
    if not isinstance(candidate, Mapping) or candidate != expected:
        raise ContractError("recovery_residue_normalization_rejected")
    if (
        candidate.get("schema")
        != RECOVERY_RESIDUE_NORMALIZATION_PLAN_SCHEMA
        or candidate.get("mode") != "verify_only"
        or candidate.get("normalization_execution_authorized") is not False
        or candidate.get("target_action_allowed") is not False
        or candidate.get("forward_action_replay_allowed") is not False
        or candidate.get("old_role_replay_allowed") is not False
        or candidate.get("separately_sequenced_t2_required") is not True
        or candidate.get("raw_content_included") is not False
        or candidate.get("source_authority")
        != {
            "accepted_t0_handoff_sha256": (
                "51e5d093f9a453886fc694e749ab12156562257c1c0c4bc0db71c5009f19b24a"
            ),
            "architecture": ARCHITECTURE,
            "source_inventory_digest": digest_value(
                contract["engine_source"]["source_inventory"]
            ),
            "recovery_artifacts_digest": digest_value(
                contract["production_adapter"]["boot_recovery"]["artifacts"]
            ),
        }
        or candidate.get("normalization_contract_digest")
        != digest_value(
            {
                key: item
                for key, item in candidate.items()
                if key != "normalization_contract_digest"
            }
        )
    ):
        raise ContractError("recovery_residue_normalization_rejected")
    return json.loads(canonical_bytes(candidate))


def _production_adapter_contract(
    source_inventory: list[dict[str, object]],
    unit_semantics: Mapping[str, object],
) -> dict[str, object]:
    matches = [row for row in source_inventory if row["path"] == PRODUCTION_ADAPTER_PATH]
    if len(matches) != 1:
        raise ContractError("production_adapter_source_rejected")
    semantics = {
        "service": _unit_semantics(
            unit_semantics.get("service")
            if isinstance(unit_semantics, Mapping)
            else None,
            expected_role="service",
        ),
        "socket": _unit_semantics(
            unit_semantics.get("socket")
            if isinstance(unit_semantics, Mapping)
            else None,
            expected_role="socket",
        ),
    }
    return {
        "schema": PRODUCTION_ADAPTER_SCHEMA,
        "entrypoint": PRODUCTION_ADAPTER_PATH,
        "entrypoint_sha256": matches[0]["sha256"],
        "backends": ["synthetic", "systemd"],
        "boot_recovery": _boot_recovery_contract(source_inventory),
        "acceptance_entrypoints": {
            "synthetic": "scripts/p08_activation_synthetic_acceptance_v1.py",
            "systemd": "scripts/p08_temporal_gateway_v1.py",
        },
        "accounts": json.loads(canonical_bytes(PRODUCTION_ACCOUNTS)),
        "fixed_paths": dict(PRODUCTION_PATHS),
        "public_roles": list(PUBLIC_ROLES),
        "public_identity_policy": {
            "environment": {"gid": 0, "mode": 0o600, "nlink": 1, "uid": 0},
            "selector": {"gid": 0, "mode": 0o600, "nlink": 1, "uid": 0},
            "service_unit": {"gid": 0, "mode": 0o644, "nlink": 1, "uid": 0},
            "socket_unit": {"gid": 0, "mode": 0o644, "nlink": 1, "uid": 0},
        },
        "roles": list(ROLE_ORDER),
        "single_plan_digest": True,
        "unit_runtime": build_unit_runtime(semantics),
        "unit_semantics": semantics,
        "unified_launcher_required": True,
        "live_execute_implemented": True,
    }


def compile_contract(
    *,
    core_root: str,
    deploy_root: str,
    core_commit: str,
    core_tree: str,
    deploy_commit: str,
    deploy_tree: str,
    source_inventory: list[dict[str, object]],
    core_inventory: list[dict[str, object]],
    unit_semantics: Mapping[str, object],
    compatibility: Mapping[str, object],
    interpreter: Mapping[str, object],
    runtime_identity: Mapping[str, object],
) -> dict[str, object]:
    _commit(core_commit, "core_commit_rejected")
    _commit(core_tree, "core_tree_rejected")
    _commit(deploy_commit, "deploy_commit_rejected")
    _commit(deploy_tree, "deploy_tree_rejected")
    if (
        not isinstance(core_root, str)
        or not core_root.startswith("/")
        or not isinstance(deploy_root, str)
        or not deploy_root.startswith("/")
    ):
        raise ContractError("source_root_rejected")
    for inventory in (source_inventory, core_inventory):
        if not inventory or any(
            not isinstance(row, dict)
            or set(row) != {"mode", "path", "sha256", "size"}
            or not isinstance(row["path"], str)
            or not row["path"]
            or row["path"].startswith("/")
            or ".." in row["path"].split("/")
            or not isinstance(row["mode"], int)
            or isinstance(row["mode"], bool)
            or row["mode"] < 0
            or row["mode"] > 0o7777
            or not isinstance(row["size"], int)
            or isinstance(row["size"], bool)
            or row["size"] < 1
            or not isinstance(row["sha256"], str)
            or not HEX64.fullmatch(row["sha256"])
            for row in inventory
        ):
            raise ContractError("source_inventory_rejected")
        paths = [str(row["path"]) for row in inventory]
        if paths != sorted(set(paths)):
            raise ContractError("source_inventory_rejected")
    if not set(REQUIRED_ENGINE_SOURCE_PATHS).issubset(
        {str(row["path"]) for row in source_inventory}
    ):
        raise ContractError("source_inventory_rejected")
    normalized_interpreter = _interpreter_authority(interpreter)
    _exact_keys(
        runtime_identity,
        {"uid", "gid", "groups"},
        "runtime_identity_rejected",
    )
    if (
        not isinstance(runtime_identity["uid"], int)
        or isinstance(runtime_identity["uid"], bool)
        or runtime_identity["uid"] < 0
        or not isinstance(runtime_identity["gid"], int)
        or isinstance(runtime_identity["gid"], bool)
        or runtime_identity["gid"] < 0
        or not isinstance(runtime_identity["groups"], list)
        or runtime_identity["groups"] != sorted(set(runtime_identity["groups"]))
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in runtime_identity["groups"]
        )
    ):
        raise ContractError("runtime_identity_rejected")
    legacy = legacy_lineage_index()
    body = {
        "schema": CONTRACT_SCHEMA,
        "architecture": ARCHITECTURE,
        "engine_source": {
            "schema": ENGINE_SOURCE_SCHEMA,
            "core_root": core_root,
            "deploy_root": deploy_root,
            "core_commit": core_commit,
            "core_tree": core_tree,
            "core_inventory": core_inventory,
            "core_inventory_digest": digest_value(core_inventory),
            "deploy_commit": deploy_commit,
            "deploy_tree": deploy_tree,
            "source_inventory": source_inventory,
            "source_inventory_digest": digest_value(source_inventory),
        },
        "interpreter": normalized_interpreter,
        "systemd_authority": {
            **json.loads(canonical_bytes(PRODUCTION_SYSTEMD)),
            "dependency_properties": list(SYSTEMD_DEPENDENCY_PROPERTIES),
        },
        "runtime_identity": dict(runtime_identity),
        "launcher": {
            "schema": CAPTURE_SCHEMA,
            "closed_stdin": True,
            "minimal_environment": [
                "LANG",
                "LC_ALL",
                "PATH",
                "PYTHONDONTWRITEBYTECODE",
                "PYTHONPATH",
            ],
            "raw_output_retained": False,
            "runtime_package": {
                "schema": RUNTIME_PACKAGE_SCHEMA,
                "root_binding": "execution.target_source_path",
                "python_paths": ["scripts", "src"],
                "full_inventory_exact": True,
                "bytecode_allowed": False,
                "untracked_imports_allowed": False,
                "non_overwriting_required": True,
            },
            "stderr_must_be_empty_on_success": True,
            "top_level_entry": _top_level_entry_contract(),
            "supervisor_bootstrap": {
                "schema": SUPERVISOR_BOOTSTRAP_SCHEMA,
                "capture_schema": SUPERVISOR_BOOTSTRAP_CAPTURE_SCHEMA,
                "intent_schema": SUPERVISOR_BOOTSTRAP_INTENT_SCHEMA,
                "entrypoint": SUPERVISOR_BOOTSTRAP_PATH,
                "child_entrypoint": "scripts/p08_activation_supervisor_v1.py",
                "guardian": _guardian_launcher_contract(),
                "loaded_modules": [
                    SUPERVISOR_BOOTSTRAP_PATH,
                    "scripts/p08_activation_contract_v1.py",
                    SUPERVISOR_GUARDIAN_MANAGER_PATH,
                    "scripts/p08_activation_launcher_v1.py",
                    PRODUCTION_ADAPTER_PATH,
                    "scripts/p08_activation_supervisor_v1.py",
                ],
                "hard_deadline_seconds": 3600,
                "kill_grace_seconds": 1,
                "evidence_mode": 0o600,
                "directory_mode": 0o700,
                "raw_output_retained": False,
            },
            "umask": 0o077,
        },
        "production_adapter": _production_adapter_contract(
            source_inventory, unit_semantics
        ),
        "phase_graph": {
            "edges": [list(edge) for edge in _PHASE_EDGES],
            "failure_to_converge": sorted(_FAILURE_TO_CONVERGE),
            "initial": "construct",
            "terminal": "postflight",
        },
        "roles": _role_contracts(),
        "schemas": {
            "account_projection": ACCOUNT_PROJECTION_SCHEMA,
            "boot_recovery_arm": BOOT_RECOVERY_ARM_SCHEMA,
            "boot_recovery_closure": BOOT_RECOVERY_CLOSURE_SCHEMA,
            "boot_recovery_contract": BOOT_RECOVERY_CONTRACT_SCHEMA,
            "boot_recovery_disarm": BOOT_RECOVERY_DISARM_SCHEMA,
            "boot_recovery_owner": BOOT_RECOVERY_OWNER_SCHEMA,
            "boot_recovery_reentry": BOOT_RECOVERY_REENTRY_SCHEMA,
            "boot_recovery_state_machine": BOOT_RECOVERY_STATE_MACHINE_SCHEMA,
            "boot_recovery_terminal": BOOT_RECOVERY_TERMINAL_SCHEMA,
            "boot_recovery_entry": BOOT_RECOVERY_ENTRY_SCHEMA,
            "boot_recovery_unit_state": BOOT_RECOVERY_UNIT_STATE_SCHEMA,
            "boot_recovery_transaction": BOOT_RECOVERY_TRANSACTION_SCHEMA,
            "recovery_infrastructure_model": RECOVERY_INFRASTRUCTURE_MODEL_SCHEMA,
            "recovery_infrastructure_obligation": RECOVERY_INFRASTRUCTURE_OBLIGATION_SCHEMA,
            "recovery_infrastructure_intent": RECOVERY_INFRASTRUCTURE_INTENT_SCHEMA,
            "recovery_infrastructure_event": RECOVERY_INFRASTRUCTURE_EVENT_SCHEMA,
            "recovery_infrastructure_convergence": RECOVERY_INFRASTRUCTURE_CONVERGENCE_SCHEMA,
            "recovery_residue_normalization_plan": RECOVERY_RESIDUE_NORMALIZATION_PLAN_SCHEMA,
            "capture": CAPTURE_SCHEMA,
            "contract": CONTRACT_SCHEMA,
            "evidence": EVIDENCE_SCHEMA,
            "invocation": INVOCATION_SCHEMA,
            "plan": PLAN_SCHEMA,
            "progress": PROGRESS_SCHEMA,
            "result": RESULT_SCHEMA,
            "shadow": SHADOW_SCHEMA,
            "state_machine": STATE_MACHINE_SCHEMA,
            "execution": EXECUTION_SCHEMA,
            "journal": JOURNAL_SCHEMA,
            "ledger": LEDGER_SCHEMA,
            "opaque_backup": OPAQUE_BACKUP_SCHEMA,
            "continuity_binding": CONTINUITY_BINDING_SCHEMA,
            "unit_receipt": UNIT_RECEIPT_SCHEMA,
            "acceptance_receipt": ACCEPTANCE_RECEIPT_SCHEMA,
            "supervisor_receipt": SUPERVISOR_RECEIPT_SCHEMA,
            "role_intent": ROLE_INTENT_SCHEMA,
            "supervisor_failure": SUPERVISOR_FAILURE_SCHEMA,
            "supervisor_entry": SUPERVISOR_ENTRY_SCHEMA,
            "supervisor_preclaim_result": SUPERVISOR_PRECLAIM_RESULT_SCHEMA,
            "supervisor_bootstrap": SUPERVISOR_BOOTSTRAP_SCHEMA,
            "supervisor_bootstrap_capture": SUPERVISOR_BOOTSTRAP_CAPTURE_SCHEMA,
            "supervisor_bootstrap_intent": SUPERVISOR_BOOTSTRAP_INTENT_SCHEMA,
            "top_level_entry": TOP_LEVEL_ENTRY_SCHEMA,
            "top_level_entry_intent": TOP_LEVEL_ENTRY_INTENT_SCHEMA,
            "top_level_entry_capture": TOP_LEVEL_ENTRY_CAPTURE_SCHEMA,
            "top_level_entry_result": TOP_LEVEL_ENTRY_RESULT_SCHEMA,
            "windows_wsl_transport": WINDOWS_WSL_TRANSPORT_SCHEMA,
            "windows_wsl_capture": WINDOWS_WSL_CAPTURE_SCHEMA,
            "windows_wsl_capture_persist_result": WINDOWS_WSL_CAPTURE_PERSIST_RESULT_SCHEMA,
            "windows_host_launcher": WINDOWS_HOST_LAUNCHER_SCHEMA,
            "supervisor_outer_terminal": SUPERVISOR_OUTER_TERMINAL_SCHEMA,
            "supervisor_guardian_obligation": SUPERVISOR_GUARDIAN_OBLIGATION_SCHEMA,
            "supervisor_guardian_manager_intent": SUPERVISOR_GUARDIAN_MANAGER_INTENT_SCHEMA,
            "supervisor_guardian_transient": SUPERVISOR_GUARDIAN_TRANSIENT_SCHEMA,
            "supervisor_guardian_transient_submission": SUPERVISOR_GUARDIAN_TRANSIENT_SUBMISSION_SCHEMA,
            "supervisor_guardian_generation": SUPERVISOR_GUARDIAN_GENERATION_SCHEMA,
            "supervisor_guardian_child": SUPERVISOR_GUARDIAN_CHILD_SCHEMA,
            "supervisor_guardian_terminal": SUPERVISOR_GUARDIAN_TERMINAL_SCHEMA,
            "supervisor_guardian_discharge": SUPERVISOR_GUARDIAN_DISCHARGE_SCHEMA,
            "supervisor_strategy_launch_claim": SUPERVISOR_STRATEGY_LAUNCH_CLAIM_SCHEMA,
            "supervisor_strategy_launch_terminal": SUPERVISOR_STRATEGY_LAUNCH_TERMINAL_SCHEMA,
            "supervisor_strategy_launch_premutation_terminal": (
                SUPERVISOR_STRATEGY_LAUNCH_PREMUTATION_TERMINAL_SCHEMA
            ),
            "selector": SELECTOR_SCHEMA,
            "unit_state": UNIT_STATE_SCHEMA,
            "unit_semantics": UNIT_SEMANTICS_SCHEMA,
            "unit_runtime": UNIT_RUNTIME_SCHEMA,
            "unit_enablement_policy": UNIT_ENABLEMENT_POLICY_SCHEMA,
            "unit_coupled_state": UNIT_COUPLED_STATE_SCHEMA,
            "execution_substrate": EXECUTION_SUBSTRATE_SCHEMA,
            "systemd_effective_unit_model": SYSTEMD_EFFECTIVE_UNIT_MODEL_SCHEMA,
            "process_identity": PROCESS_IDENTITY_SCHEMA,
            "numeric_credential_launch": NUMERIC_CREDENTIAL_LAUNCH_SCHEMA,
            "socket_inode": SOCKET_INODE_SCHEMA,
            "runtime_package": RUNTIME_PACKAGE_SCHEMA,
            "predecessor_release": PREDECESSOR_RELEASE_SCHEMA,
            "predecessor_client_roles": PREDECESSOR_CLIENT_ROLES_SCHEMA,
        },
        "result_classes": list(RESULT_CLASSES),
        "continuity": {
            "states": list(CONTINUITY_STATES),
            "no_transition_is_success": True,
            "ambiguous_requires_same_action_reconcile": True,
            "postcommit_restores_old_history": False,
            "reconciled_not_committed_replays_transition": False,
        },
        "state_access": {
            "readiness_metadata_only": True,
            "opaque_read_requires_action_ownership": True,
            "precommit_state_restore_allowed": True,
            "postcommit_state_restore_allowed": False,
        },
        "lineage": legacy,
        "compatibility": dict(compatibility),
        "max_actions": 1,
        "namespace_reset_allowed": False,
        "production_live_authorized": False,
    }
    contract_digest = digest_value(body)
    return {**body, "contract_digest": contract_digest}


def validate_contract(contract: Mapping[str, object]) -> dict[str, object]:
    expected_keys = {
        "architecture",
        "compatibility",
        "continuity",
        "contract_digest",
        "engine_source",
        "interpreter",
        "launcher",
        "lineage",
        "max_actions",
        "namespace_reset_allowed",
        "phase_graph",
        "production_live_authorized",
        "production_adapter",
        "result_classes",
        "roles",
        "runtime_identity",
        "schema",
        "schemas",
        "state_access",
        "systemd_authority",
    }
    _exact_keys(contract, expected_keys, "contract_keys_rejected")
    if contract["schema"] != CONTRACT_SCHEMA or contract["architecture"] != ARCHITECTURE:
        raise ContractError("contract_schema_rejected")
    supplied = _hex64(contract["contract_digest"], "contract_digest_rejected")
    unsigned = {key: value for key, value in contract.items() if key != "contract_digest"}
    if digest_value(unsigned) != supplied:
        raise ContractError("contract_digest_rejected")
    source = contract["engine_source"]
    _exact_keys(
        source,
        {
            "core_commit",
            "core_inventory",
            "core_inventory_digest",
            "core_root",
            "core_tree",
            "deploy_commit",
            "deploy_root",
            "deploy_tree",
            "schema",
            "source_inventory",
            "source_inventory_digest",
        },
        "contract_source_rejected",
    )
    if (
        source["schema"] != ENGINE_SOURCE_SCHEMA
        or not isinstance(source["core_root"], str)
        or not source["core_root"].startswith("/")
        or not isinstance(source["deploy_root"], str)
        or not source["deploy_root"].startswith("/")
    ):
        raise ContractError("contract_source_rejected")
    for key in ("core_commit", "core_tree", "deploy_commit", "deploy_tree"):
        _commit(source[key], "contract_source_rejected")
    inventory = source["source_inventory"]
    core_inventory = source["core_inventory"]
    for rows, digest_key in (
        (inventory, "source_inventory_digest"),
        (core_inventory, "core_inventory_digest"),
    ):
        if (
            not isinstance(rows, list)
            or not rows
            or any(
                not isinstance(row, dict)
                or not isinstance(row.get("path"), str)
                for row in rows
            )
            or [row["path"] for row in rows]
            != sorted(set(row["path"] for row in rows))
            or source[digest_key] != digest_value(rows)
        ):
            raise ContractError("contract_source_rejected")
        for row in rows:
            if (
                not isinstance(row, dict)
                or set(row) != {"mode", "path", "sha256", "size"}
                or not isinstance(row["path"], str)
                or not row["path"]
                or row["path"].startswith("/")
                or ".." in row["path"].split("/")
                or not isinstance(row["mode"], int)
                or isinstance(row["mode"], bool)
                or row["mode"] < 0
                or row["mode"] > 0o7777
                or not isinstance(row["size"], int)
                or isinstance(row["size"], bool)
                or row["size"] < 1
            ):
                raise ContractError("contract_source_rejected")
            _hex64(row["sha256"], "contract_source_rejected")
    _interpreter_authority(contract["interpreter"])
    _systemd_authority(contract["systemd_authority"])
    runtime = contract["runtime_identity"]
    _exact_keys(runtime, {"uid", "gid", "groups"}, "contract_runtime_rejected")
    if (
        not isinstance(runtime["uid"], int)
        or isinstance(runtime["uid"], bool)
        or runtime["uid"] < 0
        or not isinstance(runtime["gid"], int)
        or isinstance(runtime["gid"], bool)
        or runtime["gid"] < 0
        or not isinstance(runtime["groups"], list)
        or runtime["groups"] != sorted(set(runtime["groups"]))
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in runtime["groups"]
        )
    ):
        raise ContractError("contract_runtime_rejected")
    roles = contract["roles"]
    if not isinstance(roles, dict) or set(roles) != set(ROLE_ORDER):
        raise ContractError("contract_roles_rejected")
    generated_roles = _role_contracts()
    for role in ROLE_ORDER:
        row = roles[role]
        _exact_keys(
            row,
            {
                "call_budget",
                "hard_deadline_seconds",
                "metadata_only",
                "mutation_allowed",
                "no_progress_seconds",
                "payload_keys",
                "progress_phases",
                "role",
                "success_result_class",
            },
            "contract_roles_rejected",
        )
        if (
            row["role"] != role
            or row["call_budget"] != generated_roles[role]["call_budget"]
            or row["metadata_only"] != generated_roles[role]["metadata_only"]
            or row["mutation_allowed"] != generated_roles[role]["mutation_allowed"]
            or row["payload_keys"] != generated_roles[role]["payload_keys"]
            or row["progress_phases"] != generated_roles[role]["progress_phases"]
            or row["success_result_class"]
            != generated_roles[role]["success_result_class"]
            or not isinstance(row["hard_deadline_seconds"], int)
            or isinstance(row["hard_deadline_seconds"], bool)
            or not isinstance(row["no_progress_seconds"], int)
            or isinstance(row["no_progress_seconds"], bool)
            or row["no_progress_seconds"] < 1
            or row["hard_deadline_seconds"] <= row["no_progress_seconds"]
            or row["hard_deadline_seconds"] > 3600
        ):
            raise ContractError("contract_roles_rejected")
    expected_schemas = {
        "account_projection": ACCOUNT_PROJECTION_SCHEMA,
        "boot_recovery_arm": BOOT_RECOVERY_ARM_SCHEMA,
        "boot_recovery_closure": BOOT_RECOVERY_CLOSURE_SCHEMA,
        "boot_recovery_contract": BOOT_RECOVERY_CONTRACT_SCHEMA,
        "boot_recovery_disarm": BOOT_RECOVERY_DISARM_SCHEMA,
        "boot_recovery_owner": BOOT_RECOVERY_OWNER_SCHEMA,
        "boot_recovery_reentry": BOOT_RECOVERY_REENTRY_SCHEMA,
        "boot_recovery_state_machine": BOOT_RECOVERY_STATE_MACHINE_SCHEMA,
        "boot_recovery_terminal": BOOT_RECOVERY_TERMINAL_SCHEMA,
        "boot_recovery_entry": BOOT_RECOVERY_ENTRY_SCHEMA,
        "boot_recovery_unit_state": BOOT_RECOVERY_UNIT_STATE_SCHEMA,
        "boot_recovery_transaction": BOOT_RECOVERY_TRANSACTION_SCHEMA,
        "recovery_infrastructure_model": RECOVERY_INFRASTRUCTURE_MODEL_SCHEMA,
        "recovery_infrastructure_obligation": RECOVERY_INFRASTRUCTURE_OBLIGATION_SCHEMA,
        "recovery_infrastructure_intent": RECOVERY_INFRASTRUCTURE_INTENT_SCHEMA,
        "recovery_infrastructure_event": RECOVERY_INFRASTRUCTURE_EVENT_SCHEMA,
        "recovery_infrastructure_convergence": RECOVERY_INFRASTRUCTURE_CONVERGENCE_SCHEMA,
        "recovery_residue_normalization_plan": RECOVERY_RESIDUE_NORMALIZATION_PLAN_SCHEMA,
        "capture": CAPTURE_SCHEMA,
        "contract": CONTRACT_SCHEMA,
        "evidence": EVIDENCE_SCHEMA,
        "execution": EXECUTION_SCHEMA,
        "execution_substrate": EXECUTION_SUBSTRATE_SCHEMA,
        "systemd_effective_unit_model": SYSTEMD_EFFECTIVE_UNIT_MODEL_SCHEMA,
        "invocation": INVOCATION_SCHEMA,
        "journal": JOURNAL_SCHEMA,
        "ledger": LEDGER_SCHEMA,
        "opaque_backup": OPAQUE_BACKUP_SCHEMA,
        "plan": PLAN_SCHEMA,
        "progress": PROGRESS_SCHEMA,
        "result": RESULT_SCHEMA,
        "continuity_binding": CONTINUITY_BINDING_SCHEMA,
        "unit_receipt": UNIT_RECEIPT_SCHEMA,
        "acceptance_receipt": ACCEPTANCE_RECEIPT_SCHEMA,
        "supervisor_receipt": SUPERVISOR_RECEIPT_SCHEMA,
        "role_intent": ROLE_INTENT_SCHEMA,
        "supervisor_failure": SUPERVISOR_FAILURE_SCHEMA,
        "supervisor_entry": SUPERVISOR_ENTRY_SCHEMA,
        "supervisor_preclaim_result": SUPERVISOR_PRECLAIM_RESULT_SCHEMA,
        "supervisor_bootstrap": SUPERVISOR_BOOTSTRAP_SCHEMA,
        "supervisor_bootstrap_capture": SUPERVISOR_BOOTSTRAP_CAPTURE_SCHEMA,
        "supervisor_bootstrap_intent": SUPERVISOR_BOOTSTRAP_INTENT_SCHEMA,
        "top_level_entry": TOP_LEVEL_ENTRY_SCHEMA,
        "top_level_entry_intent": TOP_LEVEL_ENTRY_INTENT_SCHEMA,
        "top_level_entry_capture": TOP_LEVEL_ENTRY_CAPTURE_SCHEMA,
        "top_level_entry_result": TOP_LEVEL_ENTRY_RESULT_SCHEMA,
        "windows_wsl_transport": WINDOWS_WSL_TRANSPORT_SCHEMA,
        "windows_wsl_capture": WINDOWS_WSL_CAPTURE_SCHEMA,
        "windows_wsl_capture_persist_result": WINDOWS_WSL_CAPTURE_PERSIST_RESULT_SCHEMA,
        "windows_host_launcher": WINDOWS_HOST_LAUNCHER_SCHEMA,
        "supervisor_outer_terminal": SUPERVISOR_OUTER_TERMINAL_SCHEMA,
        "supervisor_guardian_obligation": SUPERVISOR_GUARDIAN_OBLIGATION_SCHEMA,
        "supervisor_guardian_manager_intent": SUPERVISOR_GUARDIAN_MANAGER_INTENT_SCHEMA,
        "supervisor_guardian_transient": SUPERVISOR_GUARDIAN_TRANSIENT_SCHEMA,
        "supervisor_guardian_transient_submission": SUPERVISOR_GUARDIAN_TRANSIENT_SUBMISSION_SCHEMA,
        "supervisor_guardian_generation": SUPERVISOR_GUARDIAN_GENERATION_SCHEMA,
        "supervisor_guardian_child": SUPERVISOR_GUARDIAN_CHILD_SCHEMA,
        "supervisor_guardian_terminal": SUPERVISOR_GUARDIAN_TERMINAL_SCHEMA,
        "supervisor_guardian_discharge": SUPERVISOR_GUARDIAN_DISCHARGE_SCHEMA,
        "supervisor_strategy_launch_claim": SUPERVISOR_STRATEGY_LAUNCH_CLAIM_SCHEMA,
        "supervisor_strategy_launch_terminal": SUPERVISOR_STRATEGY_LAUNCH_TERMINAL_SCHEMA,
        "supervisor_strategy_launch_premutation_terminal": (
            SUPERVISOR_STRATEGY_LAUNCH_PREMUTATION_TERMINAL_SCHEMA
        ),
        "selector": SELECTOR_SCHEMA,
        "shadow": SHADOW_SCHEMA,
        "state_machine": STATE_MACHINE_SCHEMA,
        "unit_state": UNIT_STATE_SCHEMA,
        "unit_semantics": UNIT_SEMANTICS_SCHEMA,
        "unit_runtime": UNIT_RUNTIME_SCHEMA,
        "unit_enablement_policy": UNIT_ENABLEMENT_POLICY_SCHEMA,
        "unit_coupled_state": UNIT_COUPLED_STATE_SCHEMA,
        "predecessor_release": PREDECESSOR_RELEASE_SCHEMA,
        "predecessor_client_roles": PREDECESSOR_CLIENT_ROLES_SCHEMA,
        "process_identity": PROCESS_IDENTITY_SCHEMA,
        "numeric_credential_launch": NUMERIC_CREDENTIAL_LAUNCH_SCHEMA,
        "socket_inode": SOCKET_INODE_SCHEMA,
        "runtime_package": RUNTIME_PACKAGE_SCHEMA,
    }
    if contract["schemas"] != expected_schemas:
        raise ContractError("contract_schemas_rejected")
    adapter_contract = contract["production_adapter"]
    if not isinstance(adapter_contract, Mapping):
        raise ContractError("contract_production_adapter_rejected")
    if contract["production_adapter"] != _production_adapter_contract(
        inventory,
        adapter_contract.get("unit_semantics"),
    ):
        raise ContractError("contract_production_adapter_rejected")
    if contract["phase_graph"] != {
        "edges": [list(edge) for edge in _PHASE_EDGES],
        "failure_to_converge": sorted(_FAILURE_TO_CONVERGE),
        "initial": "construct",
        "terminal": "postflight",
    }:
        raise ContractError("contract_phase_graph_rejected")
    if contract["launcher"] != {
        "schema": CAPTURE_SCHEMA,
        "closed_stdin": True,
        "minimal_environment": [
            "LANG",
            "LC_ALL",
            "PATH",
            "PYTHONDONTWRITEBYTECODE",
            "PYTHONPATH",
        ],
        "raw_output_retained": False,
        "runtime_package": {
            "schema": RUNTIME_PACKAGE_SCHEMA,
            "root_binding": "execution.target_source_path",
            "python_paths": ["scripts", "src"],
            "full_inventory_exact": True,
            "bytecode_allowed": False,
            "untracked_imports_allowed": False,
            "non_overwriting_required": True,
        },
        "stderr_must_be_empty_on_success": True,
        "top_level_entry": _top_level_entry_contract(),
        "supervisor_bootstrap": {
            "schema": SUPERVISOR_BOOTSTRAP_SCHEMA,
            "capture_schema": SUPERVISOR_BOOTSTRAP_CAPTURE_SCHEMA,
            "intent_schema": SUPERVISOR_BOOTSTRAP_INTENT_SCHEMA,
            "entrypoint": SUPERVISOR_BOOTSTRAP_PATH,
            "child_entrypoint": "scripts/p08_activation_supervisor_v1.py",
            "guardian": _guardian_launcher_contract(),
            "loaded_modules": [
                SUPERVISOR_BOOTSTRAP_PATH,
                "scripts/p08_activation_contract_v1.py",
                SUPERVISOR_GUARDIAN_MANAGER_PATH,
                "scripts/p08_activation_launcher_v1.py",
                PRODUCTION_ADAPTER_PATH,
                "scripts/p08_activation_supervisor_v1.py",
            ],
            "hard_deadline_seconds": 3600,
            "kill_grace_seconds": 1,
            "evidence_mode": 0o600,
            "directory_mode": 0o700,
            "raw_output_retained": False,
        },
        "umask": 0o077,
    }:
        raise ContractError("contract_launcher_rejected")
    if contract["result_classes"] != list(RESULT_CLASSES):
        raise ContractError("contract_result_classes_rejected")
    continuity = contract["continuity"]
    if continuity != {
        "states": list(CONTINUITY_STATES),
        "no_transition_is_success": True,
        "ambiguous_requires_same_action_reconcile": True,
        "postcommit_restores_old_history": False,
        "reconciled_not_committed_replays_transition": False,
    }:
        raise ContractError("contract_continuity_rejected")
    if contract["lineage"] != legacy_lineage_index():
        raise ContractError("contract_lineage_rejected")
    if (
        contract["state_access"]
        != {
            "readiness_metadata_only": True,
            "opaque_read_requires_action_ownership": True,
            "precommit_state_restore_allowed": True,
            "postcommit_state_restore_allowed": False,
        }
        or contract["max_actions"] != 1
        or contract["namespace_reset_allowed"] is not False
        or contract["production_live_authorized"] is not False
        or not isinstance(contract["compatibility"], dict)
        or set(contract["compatibility"])
        != {"legacy_release_contract_digest", "p07", "p10b", "predecessor"}
    ):
        raise ContractError("contract_policy_rejected")
    predecessor = _predecessor_release(contract["compatibility"]["predecessor"])
    if predecessor != contract["compatibility"]["predecessor"]:
        raise ContractError("contract_policy_rejected")
    _hex64(
        contract["compatibility"]["legacy_release_contract_digest"],
        "contract_policy_rejected",
    )
    for role in ("p07", "p10b"):
        if not isinstance(contract["compatibility"][role], Mapping):
            raise ContractError("contract_policy_rejected")
    return dict(contract)


def build_plan(
    contract: Mapping[str, object],
    *,
    sequence_identity: str,
    invocation_nonce: str,
    prestate_identity: str,
    predecessor_identity: str,
    target_identity: str,
    execution: Mapping[str, object],
) -> dict[str, object]:
    validated = validate_contract(contract)
    for value, error in (
        (sequence_identity, "sequence_identity_rejected"),
        (invocation_nonce, "invocation_nonce_rejected"),
        (prestate_identity, "prestate_identity_rejected"),
        (predecessor_identity, "predecessor_identity_rejected"),
        (target_identity, "target_identity_rejected"),
    ):
        _hex64(value, error)
    validated_execution = validate_execution(validated, execution)
    if not str(validated_execution["target_source_path"]).rstrip("/").endswith(
        "/" + target_identity
    ):
        raise ContractError("target_source_identity_rejected")
    if predecessor_identity != validated_execution["selected_release_identity"]:
        raise ContractError("predecessor_identity_rejected")
    expected_predecessor = validated["compatibility"].get("predecessor")
    if (
        not isinstance(expected_predecessor, Mapping)
        or expected_predecessor.get("release_identity") != predecessor_identity
    ):
        raise ContractError("predecessor_identity_rejected")
    prestate_projection = {
        "accounts": validated_execution["account_projection"],
        "opaque": validated_execution["opaque_prestate"],
        "predecessor_release": validated_execution["predecessor_release"],
        "public": validated_execution["public_prestate"],
        "units": validated_execution["unit_prestate"],
    }
    if digest_value(prestate_projection) != prestate_identity:
        raise ContractError("prestate_identity_rejected")
    body = {
        "schema": PLAN_SCHEMA,
        "architecture": ARCHITECTURE,
        "contract_digest": validated["contract_digest"],
        "sequence_identity": sequence_identity,
        "invocation_nonce": invocation_nonce,
        "prestate_identity": prestate_identity,
        "predecessor_identity": predecessor_identity,
        "target_identity": target_identity,
        "execution": validated_execution,
        "execution_digest": digest_value(validated_execution),
        "legacy_lineage_digest": validated["lineage"]["lineage_digest"],
        "phase_graph_digest": digest_value(validated["phase_graph"]),
        "role_contracts_digest": digest_value(validated["roles"]),
        "max_actions": 1,
    }
    return {**body, "plan_digest": digest_value(body)}


def validate_plan(
    contract: Mapping[str, object], plan: Mapping[str, object]
) -> dict[str, object]:
    validated_contract = validate_contract(contract)
    keys = {
        "architecture",
        "contract_digest",
        "execution",
        "execution_digest",
        "invocation_nonce",
        "legacy_lineage_digest",
        "max_actions",
        "phase_graph_digest",
        "plan_digest",
        "predecessor_identity",
        "prestate_identity",
        "role_contracts_digest",
        "schema",
        "sequence_identity",
        "target_identity",
    }
    _exact_keys(plan, keys, "plan_keys_rejected")
    if plan["schema"] != PLAN_SCHEMA or plan["architecture"] != ARCHITECTURE:
        raise ContractError("plan_schema_rejected")
    for key in (
        "contract_digest",
        "execution_digest",
        "invocation_nonce",
        "legacy_lineage_digest",
        "phase_graph_digest",
        "plan_digest",
        "predecessor_identity",
        "prestate_identity",
        "role_contracts_digest",
        "sequence_identity",
        "target_identity",
    ):
        _hex64(plan[key], "plan_identity_rejected")
    if (
        plan["contract_digest"] != validated_contract["contract_digest"]
        or plan["legacy_lineage_digest"]
        != validated_contract["lineage"]["lineage_digest"]
        or plan["phase_graph_digest"] != digest_value(validated_contract["phase_graph"])
        or plan["role_contracts_digest"] != digest_value(validated_contract["roles"])
        or plan["max_actions"] != 1
    ):
        raise ContractError("plan_binding_rejected")
    execution = validate_execution(validated_contract, plan["execution"])
    if (
        plan["execution_digest"] != digest_value(execution)
        or plan["predecessor_identity"] != execution["selected_release_identity"]
        or not isinstance(validated_contract["compatibility"].get("predecessor"), Mapping)
        or validated_contract["compatibility"]["predecessor"].get("release_identity")
        != plan["predecessor_identity"]
        or not str(execution["target_source_path"]).rstrip("/").endswith(
            "/" + str(plan["target_identity"])
        )
        or digest_value(
            {
                "accounts": execution["account_projection"],
                "opaque": execution["opaque_prestate"],
                "predecessor_release": execution["predecessor_release"],
                "public": execution["public_prestate"],
                "units": execution["unit_prestate"],
            }
        )
        != plan["prestate_identity"]
    ):
        raise ContractError("plan_execution_rejected")
    unsigned = {key: value for key, value in plan.items() if key != "plan_digest"}
    if digest_value(unsigned) != plan["plan_digest"]:
        raise ContractError("plan_digest_rejected")
    return dict(plan)


def build_result(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    *,
    role: str,
    role_call: int,
    status: str,
    result_class: str,
    payload: Mapping[str, object],
    persistent_mutation: bool,
    mutation_scope: str | None = None,
) -> dict[str, object]:
    validated_contract = validate_contract(contract)
    validated_plan = validate_plan(validated_contract, plan)
    if role not in validated_contract["roles"] or not ROLE_NAME.fullmatch(role):
        raise ContractError("result_role_rejected")
    if status not in {"ready", "success", "rejected", "indeterminate"}:
        raise ContractError("result_status_rejected")
    if result_class not in RESULT_CLASSES:
        raise ContractError("result_class_rejected")
    expected = set(validated_contract["roles"][role]["payload_keys"])
    _exact_keys(payload, expected, "result_payload_rejected")
    if not isinstance(role_call, int) or isinstance(role_call, bool) or role_call < 1:
        raise ContractError("result_call_rejected")
    if not isinstance(persistent_mutation, bool):
        raise ContractError("result_mutation_rejected")
    if mutation_scope is None:
        mutation_scope = "product" if persistent_mutation else "none"
    if (
        mutation_scope not in MUTATION_SCOPES
        or persistent_mutation is (mutation_scope == "none")
    ):
        raise ContractError("result_mutation_rejected")
    if status in {"ready", "success"}:
        _validate_success_payload(role, payload)
    result = {
        "schema": RESULT_SCHEMA,
        "contract_digest": validated_contract["contract_digest"],
        "plan_digest": validated_plan["plan_digest"],
        "sequence_identity": validated_plan["sequence_identity"],
        "invocation_nonce": validated_plan["invocation_nonce"],
        "role": role,
        "role_call": role_call,
        "status": status,
        "result_class": result_class,
        "persistent_mutation": persistent_mutation,
        "mutation_scope": mutation_scope,
        "raw_output_included": False,
        "payload": dict(payload),
    }
    return {**result, "result_digest": digest_value(result)}


def validate_result(
    contract: Mapping[str, object],
    plan: Mapping[str, object],
    result: Mapping[str, object],
    *,
    expected_role: str,
    expected_call: int,
) -> dict[str, object]:
    validated_contract = validate_contract(contract)
    validated_plan = validate_plan(validated_contract, plan)
    keys = {
        "contract_digest",
        "invocation_nonce",
        "payload",
        "persistent_mutation",
        "mutation_scope",
        "plan_digest",
        "raw_output_included",
        "result_class",
        "result_digest",
        "role",
        "role_call",
        "schema",
        "sequence_identity",
        "status",
    }
    _exact_keys(result, keys, "result_keys_rejected")
    if (
        result["schema"] != RESULT_SCHEMA
        or result["role"] != expected_role
        or result["role_call"] != expected_call
        or result["contract_digest"] != validated_contract["contract_digest"]
        or result["plan_digest"] != validated_plan["plan_digest"]
        or result["sequence_identity"] != validated_plan["sequence_identity"]
        or result["invocation_nonce"] != validated_plan["invocation_nonce"]
        or result["raw_output_included"] is not False
    ):
        raise ContractError("result_binding_rejected")
    payload = result["payload"]
    expected_payload = set(validated_contract["roles"][expected_role]["payload_keys"])
    _exact_keys(payload, expected_payload, "result_payload_rejected")
    if (
        not isinstance(result["persistent_mutation"], bool)
        or result["mutation_scope"] not in MUTATION_SCOPES
        or result["persistent_mutation"]
        is (result["mutation_scope"] == "none")
    ):
        raise ContractError("result_mutation_rejected")
    if result["status"] not in {"ready", "success", "rejected", "indeterminate"}:
        raise ContractError("result_status_rejected")
    if result["result_class"] not in RESULT_CLASSES:
        raise ContractError("result_class_rejected")
    if result["status"] in {"ready", "success"}:
        _validate_success_payload(expected_role, payload)
    unsigned = {key: value for key, value in result.items() if key != "result_digest"}
    if digest_value(unsigned) != result["result_digest"]:
        raise ContractError("result_digest_rejected")
    return dict(result)


def _validate_success_payload(role: str, payload: Mapping[str, object]) -> None:
    boolean_keys = {
        "action_owned",
        "action_backup_bound",
        "accepted",
        "arm_exact",
        "backed_up",
        "byte_identical",
        "code_public_predecessor",
        "contract_verified",
        "converged",
        "dependency_state_exact",
        "environment_exact",
        "enablement_exact",
        "exact",
        "forward_state_possible",
        "hazardous_mutation_started",
        "incident_owned",
        "installed_inventory_exact",
        "inventory_exact",
        "ordering_exact",
        "metadata_only",
        "non_overwriting",
        "nonce_echo_exact",
        "opaque_content_read",
        "opaque_exact",
        "persistent_mutation",
        "public_exact",
        "product_gate_exact",
        "runtime_exact",
        "selector_exact",
        "semantic_identical",
        "service_started",
        "service_cascade_stopped",
        "service_stopped",
        "socket_started",
        "socket_dependency_started",
        "socket_stopped",
        "source_bound",
        "stable",
        "state_preserved",
        "transition_required",
        "trusted_time_history_restored",
        "units_exact",
        "unit_exact",
    }
    integer_keys = {"formal_calls", "max_actions", "orphan_count"}
    for key, value in payload.items():
        if key in boolean_keys and not isinstance(value, bool):
            raise ContractError("result_payload_type_rejected")
        if key in integer_keys and (
            not isinstance(value, int) or isinstance(value, bool) or value < 0
        ):
            raise ContractError("result_payload_type_rejected")
    if "continuity_state" in payload and payload["continuity_state"] not in CONTINUITY_STATES:
        raise ContractError("result_payload_type_rejected")
    if "provider_state_effect" in payload and payload["provider_state_effect"] not in {
        "none",
        "committed",
        "ambiguous",
        "not_committed",
    }:
        raise ContractError("result_payload_type_rejected")
    if "state_restore_scope" in payload and payload["state_restore_scope"] not in {
        "p08_state_and_public",
        "code_public_only",
        "recovery_infrastructure_only",
        "recovery_infrastructure_and_product",
    }:
        raise ContractError("result_payload_type_rejected")
    if "selected_identity" in payload:
        _hex64(payload["selected_identity"], "result_payload_type_rejected")


def allowed_successors(contract: Mapping[str, object], role: str) -> frozenset[str]:
    validated = validate_contract(contract)
    if role not in validated["roles"]:
        raise ContractError("phase_role_rejected")
    return frozenset(
        right for left, right in validated["phase_graph"]["edges"] if left == role
    )


def failure_can_converge(contract: Mapping[str, object], role: str) -> bool:
    validated = validate_contract(contract)
    return role in validated["phase_graph"]["failure_to_converge"]
