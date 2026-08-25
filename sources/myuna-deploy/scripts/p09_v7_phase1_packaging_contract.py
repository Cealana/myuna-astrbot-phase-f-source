"""Content-free, exact-source contract for the P09 V7 Phase-1 runtime projection."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Mapping, Sequence


LEGACY_RUNTIME_PROFILE = "p09-v7-phase1-v1"
RUNTIME_PROFILE = "p09-v7-phase1-v2"
V7_1_RUNTIME_PROFILE = "p09-v7.1-authoring-v1"
SUPPORTED_RUNTIME_PROFILES = (
    LEGACY_RUNTIME_PROFILE,
    RUNTIME_PROFILE,
    V7_1_RUNTIME_PROFILE,
)
LEGACY_CONTRACT_SCHEMA = "myuna.p09-v7-phase1-runtime-projection.v1"
CONTRACT_SCHEMA = "myuna.p09-v7-phase1-runtime-projection.v2"
V7_1_CONTRACT_SCHEMA = "myuna.p09-v7.1-runtime-projection.v1"
LEGACY_CORE_COMMIT = "949759c3b6a560b9e10aeee5c01d420ed627bbef"
CORE_COMMIT = "000b5f1a8bb3c0fca9885b0ff5387087bceaa37c"
V7_1_CORE_COMMIT = "7ec92e64b11a77ef18638c1a37724a38b0d341a9"
CAPABILITY_BOUNDARY = "references/26-v7-phase1-capability-boundary.md"
V7_1_INTERACTION_CONTRACT = "references/26-v7.1-interaction-and-presentation.md"
V7_1_CAPABILITY_BOUNDARY = "references/27-v7.1-runtime-capability-boundary.md"
OWNER_INPUT_SCHEMA = "myuna.owner-input.v7.1"
ORDERED_REPLY_SCHEMA = "myuna.ordered-reply.v1"
AFFINITY_SCHEMA = "myuna.structured-affinity.v1"
AFFINITY_CAPABILITY_DIGEST = (
    "bc28be2f125bb7099859dd366d54d59f48053db670ad2d841482c15fa50d5096"
)

CORE_SOURCE_FILES = {
    "src/myuna_core/conversation.py": (
        "7e5aec8ce56021091decd8a333f8342b114bc3cd7137e201e3dc50cdd60f14b7"
    ),
    "src/myuna_core/definition_profile.py": (
        "e92384430ae702ba98d9fabbbc2a238a593e91aa82709ca2500361445bfc0118"
    ),
}

V7_1_CORE_SOURCE_FILES = {
    "src/myuna_core/conversation.py": (
        "3fe296161ecb2eb37c919b05b8a1df7119899fbdb637e7d6c7f6c0dc646a946f"
    ),
    "src/myuna_core/definition_profile.py": (
        "5c3d2978095a00798b15083809d63f22dc282b8784e43204cf1dcf747904b205"
    ),
    "src/myuna_core/interaction_contract_v7_1.py": (
        "692b112a03249629330952e12102a08f6614a60d0e1840d204fbfa3c2a781fea"
    ),
}

LEGACY_CORE_SOURCE_FILES = {
    "src/myuna_core/conversation.py": (
        "25379903b139173f588465d72b64b220141618187a47fd48323043dd5a1dc10a"
    ),
    "src/myuna_core/definition_profile.py": (
        "e92384430ae702ba98d9fabbbc2a238a593e91aa82709ca2500361445bfc0118"
    ),
}

LEGACY_CORE_ROOT_MODULES = (
    "myuna_core",
    "myuna_core.authenticated_conversation",
    "myuna_core.channel_gateway",
    "myuna_core.identity",
    "myuna_core.external_context.contracts",
    "myuna_core.external_context.lifecycle_v3",
    "myuna_core.external_context.release_set",
    "myuna_core.external_context.safety",
    "myuna_core.definition_profile",
)

CORE_ROOT_MODULES = (
    "myuna_core",
    "myuna_core.authenticated_conversation",
    "myuna_core.channel_gateway",
    "myuna_core.identity",
    "myuna_core.external_context.contracts",
    "myuna_core.external_context.lifecycle_v3",
    "myuna_core.external_context.policy_overlay",
    "myuna_core.external_context.release_set",
    "myuna_core.external_context.safety",
    "myuna_core.definition_profile",
)

V7_1_CORE_ROOT_MODULES = (
    *CORE_ROOT_MODULES,
    "myuna_core.interaction_contract_v7_1",
)

LEGACY_CORE_FILES = (
    "myuna_core/__init__.py",
    "myuna_core/authenticated_conversation.py",
    "myuna_core/channel_capability.py",
    "myuna_core/channel_gateway.py",
    "myuna_core/definition_profile.py",
    "myuna_core/external_context/__init__.py",
    "myuna_core/external_context/contracts.py",
    "myuna_core/external_context/lifecycle_v3.py",
    "myuna_core/external_context/projection.py",
    "myuna_core/external_context/release_set.py",
    "myuna_core/external_context/runtime.py",
    "myuna_core/external_context/safety.py",
    "myuna_core/identity.py",
    "myuna_core/owner_profile/__init__.py",
    "myuna_core/owner_profile/access.py",
    "myuna_core/owner_profile/approval.py",
    "myuna_core/owner_profile/contracts.py",
    "myuna_core/owner_profile/loader.py",
    "myuna_core/owner_profile/projection.py",
    "myuna_core/owner_profile/retrieval.py",
)

CORE_FILES = (
    "myuna_core/__init__.py",
    "myuna_core/authenticated_conversation.py",
    "myuna_core/channel_capability.py",
    "myuna_core/channel_gateway.py",
    "myuna_core/definition_profile.py",
    "myuna_core/external_context/__init__.py",
    "myuna_core/external_context/contracts.py",
    "myuna_core/external_context/lifecycle_v3.py",
    "myuna_core/external_context/policy_overlay.py",
    "myuna_core/external_context/projection.py",
    "myuna_core/external_context/release_set.py",
    "myuna_core/external_context/runtime.py",
    "myuna_core/external_context/safety.py",
    "myuna_core/identity.py",
    "myuna_core/owner_profile/__init__.py",
    "myuna_core/owner_profile/access.py",
    "myuna_core/owner_profile/approval.py",
    "myuna_core/owner_profile/contracts.py",
    "myuna_core/owner_profile/loader.py",
    "myuna_core/owner_profile/projection.py",
    "myuna_core/owner_profile/retrieval.py",
)

V7_1_CORE_FILES = (
    "myuna_core/__init__.py",
    "myuna_core/authenticated_conversation.py",
    "myuna_core/channel_capability.py",
    "myuna_core/channel_gateway.py",
    "myuna_core/definition_profile.py",
    "myuna_core/external_context/__init__.py",
    "myuna_core/external_context/contracts.py",
    "myuna_core/external_context/lifecycle_v3.py",
    "myuna_core/external_context/policy_overlay.py",
    "myuna_core/external_context/projection.py",
    "myuna_core/external_context/release_set.py",
    "myuna_core/external_context/runtime.py",
    "myuna_core/external_context/safety.py",
    "myuna_core/identity.py",
    "myuna_core/interaction_contract_v7_1.py",
    "myuna_core/owner_profile/__init__.py",
    "myuna_core/owner_profile/access.py",
    "myuna_core/owner_profile/approval.py",
    "myuna_core/owner_profile/contracts.py",
    "myuna_core/owner_profile/loader.py",
    "myuna_core/owner_profile/projection.py",
    "myuna_core/owner_profile/retrieval.py",
)

PROJECTION_FILES = (
    "p09_v7_phase1_projection/__init__.py",
    "p09_v7_phase1_projection/conversation.py",
    "p09_v7_phase1_projection/definition_profile.py",
)

PROJECTION_MODULES = (
    "p09_v7_phase1_projection",
    "p09_v7_phase1_projection.conversation",
    "p09_v7_phase1_projection.definition_profile",
)

V7_1_PROJECTION_FILES = (
    "p09_v7_1_projection/__init__.py",
    "p09_v7_1_projection/adapter.py",
    "p09_v7_1_projection/conversation.py",
    "p09_v7_1_projection/definition_profile.py",
)

V7_1_PROJECTION_MODULES = (
    "p09_v7_1_projection",
    "p09_v7_1_projection.adapter",
    "p09_v7_1_projection.conversation",
    "p09_v7_1_projection.definition_profile",
)

FORBIDDEN_ADDED_CORE_PREFIXES = (
    "myuna_core/active_temporal_context/",
    "myuna_core/affinity/",
    "myuna_core/capability_runtime/",
    "myuna_core/memory/",
    "myuna_core/owner_profile/write_",
    "myuna_core/providers/",
    "myuna_core/session_context/",
    "myuna_core/trusted_time/",
)


class V7PackagingContractRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise V7PackagingContractRejected(code)


def _digest_file(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def core_commit_for(runtime_profile: str) -> str:
    _require(
        runtime_profile in SUPPORTED_RUNTIME_PROFILES,
        "v7_runtime_profile_rejected",
    )
    if runtime_profile == LEGACY_RUNTIME_PROFILE:
        return LEGACY_CORE_COMMIT
    if runtime_profile == V7_1_RUNTIME_PROFILE:
        return V7_1_CORE_COMMIT
    return CORE_COMMIT


def core_source_files_for(runtime_profile: str) -> dict[str, str]:
    core_commit_for(runtime_profile)
    if runtime_profile == LEGACY_RUNTIME_PROFILE:
        return dict(LEGACY_CORE_SOURCE_FILES)
    if runtime_profile == V7_1_RUNTIME_PROFILE:
        return dict(V7_1_CORE_SOURCE_FILES)
    return dict(CORE_SOURCE_FILES)


def core_root_modules_for(runtime_profile: str) -> tuple[str, ...]:
    core_commit_for(runtime_profile)
    if runtime_profile == LEGACY_RUNTIME_PROFILE:
        return LEGACY_CORE_ROOT_MODULES
    if runtime_profile == V7_1_RUNTIME_PROFILE:
        return V7_1_CORE_ROOT_MODULES
    return CORE_ROOT_MODULES


def core_files_for(runtime_profile: str) -> tuple[str, ...]:
    core_commit_for(runtime_profile)
    if runtime_profile == LEGACY_RUNTIME_PROFILE:
        return LEGACY_CORE_FILES
    if runtime_profile == V7_1_RUNTIME_PROFILE:
        return V7_1_CORE_FILES
    return CORE_FILES


def projection_files_for(runtime_profile: str) -> tuple[str, ...]:
    core_commit_for(runtime_profile)
    if runtime_profile == V7_1_RUNTIME_PROFILE:
        return V7_1_PROJECTION_FILES
    return PROJECTION_FILES


def projection_modules_for(runtime_profile: str) -> tuple[str, ...]:
    core_commit_for(runtime_profile)
    if runtime_profile == V7_1_RUNTIME_PROFILE:
        return V7_1_PROJECTION_MODULES
    return PROJECTION_MODULES


def validate_core_source(
    core_source: Path,
    core_commit: str,
    runtime_profile: str = RUNTIME_PROFILE,
) -> None:
    _require(
        core_commit == core_commit_for(runtime_profile),
        "v7_core_commit_rejected",
    )
    for relative, expected in core_source_files_for(runtime_profile).items():
        path = core_source / relative
        _require(
            not path.is_symlink() and path.is_file(),
            "v7_core_source_module_rejected",
        )
        _require(_digest_file(path) == expected, "v7_core_source_digest_rejected")


def contract_payload(
    runtime_profile: str = RUNTIME_PROFILE,
) -> dict[str, object]:
    source_core_commit = core_commit_for(runtime_profile)
    if runtime_profile == V7_1_RUNTIME_PROFILE:
        return {
            "schema": V7_1_CONTRACT_SCHEMA,
            "runtime_profile": runtime_profile,
            "profile_version": "v7.1",
            "phase": "authoring-source-supersession",
            "source_core_commit": source_core_commit,
            "source_modules": core_source_files_for(runtime_profile),
            "definition_source": {
                "canonical_inventory_sha256": (
                    "6b0a6385e0d1cefd5889294cc08049ae95693dbfc9596a426aea5aa0396df0bf"
                ),
                "effective_tree_sha256": (
                    "d8055dafc07e09d73b791c1a1911926d0ff0261926d8c6e7e1011d6ed0801aa7"
                ),
                "version": "v7.1",
                "zip_sha256": (
                    "ebe4e33ed3301e7282d95158e8a5a1cac77f39f90ec6ecd5ecec27415161e9e7"
                ),
            },
            "interaction_contract": V7_1_INTERACTION_CONTRACT,
            "capability_boundary": V7_1_CAPABILITY_BOUNDARY,
            "owner_input_schema": OWNER_INPUT_SCHEMA,
            "ordered_reply_schema": ORDERED_REPLY_SCHEMA,
            "projection_modules": list(projection_modules_for(runtime_profile)),
            "ordered_multibeat_reply": True,
            "semantic_pause_preservation": True,
            "closure_consistent_actions": True,
            "observer_side_inquiry": {
                "external_context_allowed": False,
                "history_read_allowed": False,
                "history_write_allowed": False,
                "scene_advance_allowed": False,
                "state_write_allowed": False,
            },
            "adapter_contract": {
                "background_polling": False,
                "duplicate_history_write": False,
                "ordered_reply_single_delivery": True,
                "preserve_unicode_and_blank_lines": True,
            },
            "dynamic_affinity_state": False,
            "affinity_persistence": False,
            "profile_or_session_writes": False,
            "external_context_mutation": False,
            "legacy_trust_migration": False,
            "structured_affinity_foundation": {
                "active": False,
                "capability_digest": AFFINITY_CAPABILITY_DIGEST,
                "packaged": False,
                "schema": AFFINITY_SCHEMA,
            },
            "rollback": {
                "definition_version": "v6",
                "runtime_profile": "p07-hybrid-v2",
            },
        }
    payload: dict[str, object] = {
        "schema": (
            LEGACY_CONTRACT_SCHEMA
            if runtime_profile == LEGACY_RUNTIME_PROFILE
            else CONTRACT_SCHEMA
        ),
        "profile_version": "v7",
        "phase": 1,
        "source_core_commit": source_core_commit,
        "source_modules": core_source_files_for(runtime_profile),
        "capability_boundary": CAPABILITY_BOUNDARY,
        "projection_modules": list(PROJECTION_MODULES),
        "dynamic_affinity_state": False,
        "affinity_persistence": False,
        "profile_or_session_writes": False,
        "legacy_trust_migration": False,
    }
    if runtime_profile == RUNTIME_PROFILE:
        payload["runtime_profile"] = runtime_profile
        payload["structured_affinity_foundation"] = {
            "active": False,
            "capability_digest": AFFINITY_CAPABILITY_DIGEST,
            "packaged": False,
            "schema": AFFINITY_SCHEMA,
        }
    return payload


def validate_runtime_contract(
    payload: object,
    *,
    runtime_profile: str = RUNTIME_PROFILE,
    core_commit: str,
    roots: Sequence[str],
    core_files: Sequence[str],
    runtime_files: Sequence[str],
) -> None:
    _require(isinstance(payload, Mapping), "v7_runtime_contract_rejected")
    _require(
        dict(payload) == contract_payload(runtime_profile),
        "v7_runtime_contract_rejected",
    )
    _require(
        core_commit == core_commit_for(runtime_profile),
        "v7_runtime_core_commit_rejected",
    )
    _require(
        tuple(roots) == core_root_modules_for(runtime_profile),
        "v7_runtime_roots_rejected",
    )
    _require(
        tuple(core_files) == core_files_for(runtime_profile),
        "v7_runtime_core_inventory_rejected",
    )
    runtime_set = set(runtime_files)
    _require(
        {
            f"runtime/{relative}"
            for relative in projection_files_for(runtime_profile)
        }
        <= runtime_set,
        "v7_runtime_projection_inventory_rejected",
    )
    expected_projection_paths = {
        f"runtime/{relative}" for relative in projection_files_for(runtime_profile)
    }
    actual_projection_paths = {
        relative
        for relative in runtime_set
        if relative.startswith("runtime/p09_v7")
    }
    _require(
        actual_projection_paths == expected_projection_paths,
        "v7_runtime_projection_mixed_contract_rejected",
    )
    _require(
        not any(
            relative.startswith(prefix)
            for relative in core_files
            for prefix in FORBIDDEN_ADDED_CORE_PREFIXES
        ),
        "v7_runtime_forbidden_module_rejected",
    )
