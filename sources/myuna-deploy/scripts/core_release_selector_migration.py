"""Pure Core Release Selector v1 R4 migration planner.

This module has no filesystem, subprocess, network or service APIs.  Callers
must provide all bytes explicitly.  It validates the exact legacy drop-in
inventory, removes only release ownership directives, renders an
approval-bound runtime binding, and returns an immutable in-memory bundle.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import re
import shlex
from typing import Mapping

from core_release_selector import (
    SelectionBindingIntent,
    analyze_systemd_release_inventory,
    assert_environment_files_do_not_define_pythonpath,
    canonical_json_bytes,
    load_binding_intent,
    render_runtime_binding,
    validate_binding_intent_evidence,
)


SCHEMA = "myuna.core-release-selector.r4-migration-contract.v1"
STATUS = "repository_candidate_not_installed_or_active"
RUNTIME_BINDING_NAME = "qq.binding.json"
HEX_64 = re.compile(r"^[a-f0-9]{64}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]*$")
WORKING_DIRECTORY = re.compile(r"^(\s*)WorkingDirectory=(.*)$")
ENVIRONMENT = re.compile(r"^(\s*)Environment=(.*)$")


class MigrationContractError(RuntimeError):
    """A deterministic R4 migration contract rejection."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise MigrationContractError(code)


def digest(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def exact_object(
    value: object, fields: set[str], code: str
) -> dict[str, object]:
    require(isinstance(value, dict) and set(value) == fields, code)
    return value


def digest_field(value: object, code: str) -> str:
    require(isinstance(value, str) and HEX_64.fullmatch(value) is not None, code)
    return value


def string_field(value: object, code: str) -> str:
    require(isinstance(value, str) and value != "", code)
    return value


@dataclass(frozen=True)
class MigrationEntry:
    action: str
    source_sha256: str
    target_sha256: str | None
    removed_release_directive_count: int


@dataclass(frozen=True)
class MigrationContract:
    base_template_sha256: str
    prestate_dropin_file_count: int
    prestate_effective_owner: str
    prestate_effective_working_directory: str
    active_tree_sha256: str
    active_file_count: int
    target_release_path: str
    target_tree_sha256: str
    target_file_count: int
    selector_name: str
    selector_sha256: str
    guard_name: str
    guard_sha256: str
    runtime_binding_path: str
    verifier_path: str
    verifier_sha256: str
    binding_intent_sha256: str
    migration: Mapping[str, MigrationEntry]
    preserved_dropins: Mapping[str, str]
    environment_files: tuple[str, ...]


@dataclass(frozen=True)
class MigrationBundle:
    approval_plan_digest: str
    runtime_binding: bytes
    writes: Mapping[str, bytes]
    deletes: tuple[str, ...]
    rollback_dropins: Mapping[str, bytes]
    final_dropin_sha256: Mapping[str, str]
    effective_owner: str
    effective_working_directory: str

    def summary(self) -> dict[str, object]:
        return {
            "approval_plan_digest": self.approval_plan_digest,
            "runtime_binding_sha256": digest(self.runtime_binding),
            "writes": {
                name: digest(payload)
                for name, payload in sorted(self.writes.items())
            },
            "deletes": list(self.deletes),
            "rollback_dropins": {
                name: digest(payload)
                for name, payload in sorted(self.rollback_dropins.items())
            },
            "final_dropin_sha256": dict(sorted(self.final_dropin_sha256.items())),
            "effective_owner": self.effective_owner,
            "effective_working_directory": self.effective_working_directory,
        }


def load_migration_contract(payload: object) -> MigrationContract:
    root = exact_object(
        payload,
        {
            "schema",
            "status",
            "unit",
            "instance",
            "base_template",
            "prestate",
            "target",
            "r3b",
            "migration",
            "preserved_dropins",
            "environment_files",
            "gateway",
            "next_stage",
        },
        "migration contract rejected",
    )
    require(root["schema"] == SCHEMA and root["status"] == STATUS, "migration contract rejected")
    require(root["unit"] == "myuna-core@qq.service" and root["instance"] == "qq", "migration contract rejected")
    base = exact_object(root["base_template"], {"path", "sha256"}, "base template rejected")
    require(base["path"] == "/etc/systemd/system/myuna-core@.service", "base template rejected")
    prestate = exact_object(
        root["prestate"],
        {
            "dropin_file_count",
            "effective_owner",
            "effective_working_directory",
            "active_tree_sha256",
            "active_file_count",
        },
        "prestate rejected",
    )
    require(
        type(prestate["dropin_file_count"]) is int
        and prestate["dropin_file_count"] > 0
        and type(prestate["active_file_count"]) is int
        and prestate["active_file_count"] > 0,
        "prestate rejected",
    )
    target = exact_object(
        root["target"],
        {
            "release_path",
            "tree_sha256",
            "file_count",
            "source_commit",
            "selector_dropin",
            "selector_dropin_sha256",
            "guard_dropin",
            "guard_dropin_sha256",
            "runtime_binding",
        },
        "target rejected",
    )
    require(type(target["file_count"]) is int and target["file_count"] > 0, "target rejected")
    r3b = exact_object(
        root["r3b"],
        {
            "approved_plan_digest",
            "verifier_path",
            "verifier_sha256",
            "candidate_root",
            "binding_intent_sha256",
        },
        "r3b evidence rejected",
    )
    raw_migration = root["migration"]
    require(isinstance(raw_migration, dict) and raw_migration, "migration entries rejected")
    migration: dict[str, MigrationEntry] = {}
    for name, raw_entry in raw_migration.items():
        require(isinstance(name, str) and SAFE_NAME.fullmatch(name) is not None, "migration name rejected")
        require(isinstance(raw_entry, dict), "migration entry rejected")
        action = raw_entry.get("action")
        if action == "delete":
            entry = exact_object(
                raw_entry,
                {"action", "source_sha256", "removed_release_directive_count"},
                "migration delete rejected",
            )
            target_sha256 = None
        elif action == "replace":
            entry = exact_object(
                raw_entry,
                {
                    "action",
                    "source_sha256",
                    "target_sha256",
                    "removed_release_directive_count",
                },
                "migration replacement rejected",
            )
            target_sha256 = digest_field(entry["target_sha256"], "migration replacement rejected")
        else:
            raise MigrationContractError("migration action rejected")
        require(
            entry["removed_release_directive_count"] == 2,
            "migration directive count rejected",
        )
        migration[name] = MigrationEntry(
            action=action,
            source_sha256=digest_field(entry["source_sha256"], "migration source rejected"),
            target_sha256=target_sha256,
            removed_release_directive_count=2,
        )
    raw_preserved = root["preserved_dropins"]
    require(isinstance(raw_preserved, dict) and raw_preserved, "preserved drop-ins rejected")
    preserved: dict[str, str] = {}
    for name, expected_digest in raw_preserved.items():
        require(
            isinstance(name, str)
            and SAFE_NAME.fullmatch(name) is not None
            and name not in migration,
            "preserved drop-in name rejected",
        )
        preserved[name] = digest_field(expected_digest, "preserved drop-in rejected")
    environment_files = root["environment_files"]
    require(
        isinstance(environment_files, list)
        and environment_files
        and all(isinstance(path, str) and path.startswith("/etc/myuna/") for path in environment_files)
        and len(set(environment_files)) == len(environment_files),
        "environment file inventory rejected",
    )
    gateway = exact_object(
        root["gateway"],
        {
            "unit",
            "fragment_sha256",
            "dropins",
            "requires_core",
            "future_activation_sequence",
        },
        "gateway evidence rejected",
    )
    require(
        gateway["unit"] == "myuna-qq-owner-runtime-dev.service"
        and gateway["requires_core"] is True
        and isinstance(gateway["dropins"], dict)
        and gateway["dropins"],
        "gateway evidence rejected",
    )
    digest_field(gateway["fragment_sha256"], "gateway evidence rejected")
    for value in gateway["dropins"].values():
        digest_field(value, "gateway evidence rejected")
    exact_object(
        root["next_stage"],
        {
            "name",
            "requires_separate_plan_digest_and_owner_approval",
            "r4a_does_not_authorize_system_writes_or_activation",
        },
        "next stage rejected",
    )
    require(
        root["next_stage"]["requires_separate_plan_digest_and_owner_approval"] is True
        and root["next_stage"]["r4a_does_not_authorize_system_writes_or_activation"] is True,
        "next stage rejected",
    )
    contract = MigrationContract(
        base_template_sha256=digest_field(base["sha256"], "base template rejected"),
        prestate_dropin_file_count=prestate["dropin_file_count"],
        prestate_effective_owner=string_field(prestate["effective_owner"], "prestate rejected"),
        prestate_effective_working_directory=string_field(
            prestate["effective_working_directory"], "prestate rejected"
        ),
        active_tree_sha256=digest_field(prestate["active_tree_sha256"], "prestate rejected"),
        active_file_count=prestate["active_file_count"],
        target_release_path=string_field(target["release_path"], "target rejected"),
        target_tree_sha256=digest_field(target["tree_sha256"], "target rejected"),
        target_file_count=target["file_count"],
        selector_name=string_field(target["selector_dropin"], "target rejected"),
        selector_sha256=digest_field(target["selector_dropin_sha256"], "target rejected"),
        guard_name=string_field(target["guard_dropin"], "target rejected"),
        guard_sha256=digest_field(target["guard_dropin_sha256"], "target rejected"),
        runtime_binding_path=string_field(target["runtime_binding"], "target rejected"),
        verifier_path=string_field(r3b["verifier_path"], "r3b evidence rejected"),
        verifier_sha256=digest_field(r3b["verifier_sha256"], "r3b evidence rejected"),
        binding_intent_sha256=digest_field(
            r3b["binding_intent_sha256"], "r3b evidence rejected"
        ),
        migration=migration,
        preserved_dropins=preserved,
        environment_files=tuple(environment_files),
    )
    require(
        contract.active_tree_sha256 == contract.target_tree_sha256
        and contract.active_file_count == contract.target_file_count,
        "path-only migration evidence rejected",
    )
    return contract


def _has_directive(payload: bytes) -> bool:
    for raw_line in payload.decode("utf-8").splitlines():
        line = raw_line.strip()
        if line and not line.startswith(("#", ";", "[")) and "=" in line:
            return True
    return False


def strip_release_owner_directives(payload: bytes) -> tuple[bytes | None, int]:
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise MigrationContractError("drop-in encoding rejected") from exc
    output: list[str] = []
    removed = 0
    for raw_line in text.splitlines(keepends=True):
        line = raw_line.rstrip("\r\n")
        if WORKING_DIRECTORY.fullmatch(line) is not None:
            removed += 1
            continue
        environment_match = ENVIRONMENT.fullmatch(line)
        if environment_match is not None:
            try:
                assignments = shlex.split(environment_match.group(2).strip())
            except ValueError as exc:
                raise MigrationContractError("drop-in environment rejected") from exc
            pythonpath = [
                assignment
                for assignment in assignments
                if assignment.startswith("PYTHONPATH=")
            ]
            if pythonpath:
                require(
                    len(assignments) == 1 and len(pythonpath) == 1,
                    "mixed PYTHONPATH directive rejected",
                )
                removed += 1
                continue
        output.append(raw_line)
    sanitized = "".join(output).encode("utf-8")
    if not _has_directive(sanitized):
        return None, removed
    return sanitized, removed


def _validate_intent(
    contract: MigrationContract, binding_intent: bytes
) -> SelectionBindingIntent:
    require(digest(binding_intent) == contract.binding_intent_sha256, "binding intent drift rejected")
    try:
        from core_release_selector import parse_json_document

        intent = load_binding_intent(parse_json_document(binding_intent))
    except Exception as exc:
        raise MigrationContractError("binding intent rejected") from exc
    validate_binding_intent_evidence(intent)
    release = intent.selected_release
    require(
        release.release_path.as_posix() == contract.target_release_path
        and release.tree_sha256 == contract.target_tree_sha256
        and release.file_count == contract.target_file_count
        and intent.verifier_script_path == contract.verifier_path
        and intent.verifier_script_sha256 == contract.verifier_sha256,
        "binding intent target rejected",
    )
    return intent


def build_migration_bundle(
    contract: MigrationContract,
    *,
    base_template: bytes,
    live_dropins: Mapping[str, bytes],
    environment_files: Mapping[str, bytes],
    binding_intent: bytes,
    staged_guard: bytes,
    staged_selector: bytes,
    approval_plan_digest: str,
) -> MigrationBundle:
    require(isinstance(contract, MigrationContract), "contract type rejected")
    require(
        isinstance(base_template, bytes)
        and digest(base_template) == contract.base_template_sha256,
        "base template drift rejected",
    )
    expected_names = set(contract.migration) | set(contract.preserved_dropins)
    require(
        set(live_dropins) == expected_names
        and len(live_dropins) == contract.prestate_dropin_file_count
        and all(isinstance(value, bytes) for value in live_dropins.values()),
        "live drop-in inventory rejected",
    )
    for name, expected_digest in contract.preserved_dropins.items():
        require(
            digest(live_dropins[name]) == expected_digest,
            "preserved drop-in drift rejected",
        )
    inventory_before = analyze_systemd_release_inventory(
        base_template, live_dropins
    )
    require(
        inventory_before.effective_owner is not None
        and inventory_before.effective_owner.source_name
        == contract.prestate_effective_owner
        and inventory_before.effective_owner.working_directory
        == contract.prestate_effective_working_directory,
        "effective prestate rejected",
    )
    require(
        {owner.source_name for owner in inventory_before.dropin_owners}
        == set(contract.migration),
        "legacy release owner set rejected",
    )
    require(
        set(environment_files) == set(contract.environment_files)
        and all(isinstance(value, bytes) for value in environment_files.values()),
        "environment file set rejected",
    )
    assert_environment_files_do_not_define_pythonpath(environment_files)
    require(
        digest(staged_guard) == contract.guard_sha256
        and digest(staged_selector) == contract.selector_sha256,
        "staged selector evidence rejected",
    )
    staged = dict(live_dropins)
    writes: dict[str, bytes] = {
        contract.guard_name: staged_guard,
        contract.selector_name: staged_selector,
    }
    deletes: list[str] = []
    for name, entry in contract.migration.items():
        source = live_dropins[name]
        require(digest(source) == entry.source_sha256, "migration source drift rejected")
        sanitized, removed = strip_release_owner_directives(source)
        require(
            removed == entry.removed_release_directive_count,
            "release directive count rejected",
        )
        if entry.action == "delete":
            require(sanitized is None and entry.target_sha256 is None, "delete migration rejected")
            staged.pop(name)
            deletes.append(name)
        else:
            require(
                sanitized is not None
                and entry.target_sha256 is not None
                and digest(sanitized) == entry.target_sha256,
                "replacement migration rejected",
            )
            staged[name] = sanitized
            writes[name] = sanitized
    staged[contract.guard_name] = staged_guard
    staged[contract.selector_name] = staged_selector
    inventory_after = analyze_systemd_release_inventory(base_template, staged)
    require(
        [owner.source_name for owner in inventory_after.dropin_owners]
        == [contract.selector_name]
        and inventory_after.effective_owner is not None
        and inventory_after.effective_owner.source_name == contract.selector_name
        and inventory_after.effective_owner.working_directory
        == contract.target_release_path,
        "staged release ownership rejected",
    )
    intent = _validate_intent(contract, binding_intent)
    try:
        binding = render_runtime_binding(
            intent, approval_plan_digest=approval_plan_digest
        )
    except Exception as exc:
        raise MigrationContractError("runtime binding render rejected") from exc
    runtime_binding = canonical_json_bytes(binding.to_payload())
    writes[RUNTIME_BINDING_NAME] = runtime_binding
    final_hashes = {
        name: digest(payload) for name, payload in staged.items()
    }
    return MigrationBundle(
        approval_plan_digest=approval_plan_digest,
        runtime_binding=runtime_binding,
        writes=writes,
        deletes=tuple(sorted(deletes)),
        rollback_dropins=dict(live_dropins),
        final_dropin_sha256=final_hashes,
        effective_owner=inventory_after.effective_owner.source_name,
        effective_working_directory=(
            inventory_after.effective_owner.working_directory
        ),
    )

