from __future__ import annotations

from contextlib import redirect_stdout
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
from typing import Mapping
import unittest
from unittest.mock import patch
import sys

import activate_p07_owner_private_memory_dual_state_recovery_v2 as dual_state
import build_telegram_gateway_release_v1 as gateway_release
import p07_full_mutation_set_v1 as mutation
import p07_owner_private_memory_production_plan as production
import p07_owner_private_memory_runtime_artifact_v1 as runtime_artifact
import p07_owner_private_memory_transactional_controller as parent
import p07_owner_private_memory_transactional_runtime as runtime
import p07_transactional_plugin_artifact_v1 as plugin_artifact


CATEGORIES = (
    "archive_roots",
    "core_release",
    "diary_roots",
    "dropins",
    "index_roots",
    "plugin_release",
    "runtime_release",
    "selectors",
)


def lineages() -> dict[str, object]:
    semantic = {
        "full_mutation_bundle_id": parent.FULL_MUTATION_BUNDLE_ID,
        "full_mutation_handoff_sha256": parent.FULL_MUTATION_HANDOFF_SHA256,
        "full_mutation_manifest_sha256": parent.FULL_MUTATION_MANIFEST_SHA256,
        "predecessor": {
            "attempts": 2,
            "maximum_attempts": 2,
            "schema": dual_state.IMMUTABLE_PREDECESSOR_SCHEMA,
            "strategy_id": parent.PREDECESSOR_STRATEGY_ID,
        },
        "root_cause_handoff_sha256": parent.ROOT_CAUSE_HANDOFF_SHA256,
        "schema": parent.LINEAGE_SCHEMA,
        "source_boundary": {
            "core_commit": parent.LINEAGE_CORE_SOURCE_COMMIT,
            "core_tree": parent.LINEAGE_CORE_SOURCE_TREE,
            "deploy_parent_commit": parent.DEPLOY_PARENT_COMMIT,
            "deploy_parent_tree": parent.DEPLOY_PARENT_TREE,
        },
        "v2": {
            "attempts": 1,
            "backup_tree_digest": parent.V2_BACKUP_TREE_DIGEST,
            "journal_sha256": parent.V2_JOURNAL_SHA256,
            "ledger_sha256": parent.V2_LEDGER_SHA256,
            "maximum_attempts": 1,
            "plan_sha256": parent.V2_PLAN_SHA256,
            "prestate_sha256": parent.V2_PRESTATE_SHA256,
            "receipt_sha256": parent.V2_RECEIPT_SHA256,
            "schema": parent.LINEAGE_SCHEMA,
            "source_commit": parent.V2_SOURCE_COMMIT,
            "state_tree_digest": parent.V2_STATE_TREE_DIGEST,
            "strategy_id": parent.V2_STRATEGY_ID,
            "terminal_handoff_sha256": parent.TERMINAL_V2_HANDOFF_SHA256,
        },
    }
    return {
        **semantic,
        "evidence_digest": parent.digest("p07_transactional_lineage_evidence", semantic),
    }


def boundaries() -> dict[str, object]:
    return {
        name: {
            "identity_digest": f"{index + 1:064x}",
            "mutation_allowed": False,
            "state": "immutable",
        }
        for index, name in enumerate(sorted(parent._BOUNDARY_PROGRAMS))
    }


def policy() -> dict[str, object]:
    return {
        "calendar_zone_selector_digest": "1" * 64,
        "diary_egress_policy_digest": "2" * 64,
        "historical_recall_egress_digest": "3" * 64,
        "p15_prompt_owner_digest": "4" * 64,
        "profile_confirmation_gate_digest": "5" * 64,
        "selected_calendar_zone": "Asia/Shanghai",
    }


def synthetic_plugin_binding() -> dict[str, object]:
    source_rows: list[dict[str, object]] = []
    for order, (source_path, destination, mode) in enumerate(
        gateway_release.COMPONENTS
    ):
        payload = f"synthetic-runtime-plugin-{order}\n".encode("ascii")
        source_rows.append(
            {
                "destination": destination,
                "git_blob": f"{order + 1:040x}",
                "order": order,
                "path": source_path,
                "sha256": sha256(payload).hexdigest(),
                "size": len(payload),
                "source_mode": "100644",
                "target_mode": f"{mode:04o}",
            }
        )

    def support(path: str, marker: bytes, blob: str) -> dict[str, object]:
        return {
            "git_blob": blob,
            "path": path,
            "sha256": sha256(marker).hexdigest(),
            "size": len(marker),
            "source_mode": "100644",
        }

    return plugin_artifact._assemble_binding(
        deploy_commit="c" * 40,
        deploy_tree="d" * 40,
        source_files=source_rows,
        release_builder=support(
            plugin_artifact.RELEASE_BUILDER_PATH,
            b"synthetic-release-builder\n",
            "e" * 40,
        ),
        config_renderer=support(
            plugin_artifact.CONFIG_RENDERER_PATH,
            b"synthetic-config-renderer\n",
            "f" * 40,
        ),
    )


def synthetic_runtime_artifact(
    plugin_binding: dict[str, object],
) -> dict[str, object]:
    payload = b"synthetic-owner-private-memory-runtime\n"
    files = {
        "runtime/owner_memory.py": {
            "mode": runtime_artifact.FILE_MODE,
            "sha256": sha256(payload).hexdigest(),
            "size": len(payload),
        }
    }
    binding = runtime_artifact.build_binding(
        source_core_commit=runtime.CORE_SOURCE_COMMIT,
        source_core_tree=runtime.CORE_SOURCE_TREE,
        source_deploy_commit="c" * 40,
        source_deploy_tree="d" * 40,
        base_release_digest="1" * 64,
        file_inventory=files,
        plugin_binding=plugin_binding,
        memory_contract=runtime_artifact.MEMORY_CONTRACT,
        source_policy=production.source_policy(),
        program_boundaries=production.source_boundaries(),
    )
    unsigned = {
        "base_release_digest": "1" * 64,
        "core_import_closure": {"algorithm": "synthetic", "files": [], "roots": []},
        "files": files,
        "owner_private_memory_contract": runtime_artifact.MEMORY_CONTRACT,
        "owner_private_memory_runtime_binding": binding,
        "runtime_profile": runtime_artifact.RUNTIME_PROFILE,
        "schema": runtime_artifact.HYBRID_RUNTIME_SCHEMA,
        "source_core_commit": runtime.CORE_SOURCE_COMMIT,
        "source_core_tree": runtime.CORE_SOURCE_TREE,
        "source_deploy_commit": "c" * 40,
        "source_deploy_tree": "d" * 40,
    }
    manifest = {
        **unsigned,
        "release_digest": sha256(runtime_artifact.canonical(unsigned)).hexdigest(),
    }
    return runtime_artifact.projection_from_manifest(
        manifest, manifest_bytes=runtime_artifact.canonical(manifest)
    )


def public_prestate() -> dict[str, object]:
    result = {
        name: {"digest": f"{index + 1:064x}"}
        for index, name in enumerate(sorted(parent._PUBLIC_PRESTATE_FIELDS))
    }
    result["p08_status"] = {
        "schema": "myuna.synthetic-p08-content-free-status.v1",
        "source_identity": "synthetic-p08-content-free-status",
        "status_digest": "a" * 64,
    }
    return result


def parent_namespace() -> dict[str, object]:
    return {
        "backup_root_exists": False,
        "ledger_exists": False,
        "schema": parent.NAMESPACE_SCHEMA,
        "source_id": parent.SOURCE_ID,
        "state_root_exists": False,
    }


def service_projection() -> dict[str, object]:
    def unit(name: str, sub_state: str) -> dict[str, object]:
        return {
            "active_state": "active",
            "nrestarts": 0,
            "sub_state": sub_state,
            "unit": name,
        }

    return {
        "container": {
            "health": "healthy",
            "name": runtime.CONTAINER,
            "restart_count": 0,
            "state": "running",
        },
        "core": unit(runtime.CORE_UNIT, "running"),
        "telegram": unit(runtime.TELEGRAM_UNIT, "running"),
        "telegram_socket": unit(runtime.TELEGRAM_SOCKET, "listening"),
    }


def build_contract(root: Path) -> tuple[dict[str, object], dict[str, bytes]]:
    paths = [f"{index:02d}-{category}.conf" for index, category in enumerate(CATEGORIES)]
    root_contract = mutation.build_root(
        root_id="transaction_root",
        path=root,
        allowed_logical_paths=paths,
        allowed_owners=((os.getuid(), os.getgid()),),
        inventory_pattern="*.conf",
        recursive=False,
    )
    prestate: list[dict[str, object]] = []
    operations: list[dict[str, object]] = []
    after_payloads: dict[str, bytes] = {}
    for order, logical_path in enumerate(paths):
        before_payload = f"before-{logical_path}\n".encode("ascii")
        after_payload = f"after-{logical_path}\n".encode("ascii")
        if order == 0:
            kind = "add"
            before = mutation.absent_state()
        else:
            kind = "remove" if order == 1 else "replace"
            target = root / logical_path
            target.write_bytes(before_payload)
            os.chmod(target, 0o640)
            before = mutation.regular_state(
                before_payload,
                uid=os.getuid(),
                gid=os.getgid(),
                mode=0o640,
            )
            prestate.append(
                mutation.inventory_entry(
                    root_id="transaction_root", logical_path=logical_path, state=before
                )
            )
        after = (
            mutation.absent_state()
            if kind == "remove"
            else mutation.regular_state(
                after_payload,
                uid=os.getuid(),
                gid=os.getgid(),
                mode=0o640,
            )
        )
        operations.append(
            mutation.build_operation(
                root=root_contract,
                order=order,
                kind=kind,
                logical_path=logical_path,
                before=before,
                after=after,
                generator=mutation.build_generator(
                    generator_id=f"generator_{order}",
                    source_sha256=f"{order + 1:064x}",
                    input_digest=f"{order + 11:064x}",
                    output_state=after,
                ),
            )
        )
        if after["exists"]:
            after_payloads[mutation.path_key("transaction_root", logical_path)] = after_payload
    return (
        mutation.build_mutation_set(
            transaction_id="synthetic_transactional_runtime",
            roots=[root_contract],
            prestate_inventory=prestate,
            operations=operations,
        ),
        after_payloads,
    )


def coverage(contract: dict[str, object], root: Path) -> dict[str, object]:
    operation_keys = [
        "file:"
        + mutation.path_key(str(item["root_id"]), str(item["logical_path"]))
        for item in contract["operations"]
    ]
    archive_path = (root / "protected-archive").as_posix()
    return {
        "archive_roots": [
            "root:archive_root:"
            + parent.digest("p07_protected_root_path", archive_path)
        ],
        "core_release": [operation_keys[0]],
        "diary_roots": [operation_keys[1]],
        "dropins": [operation_keys[2], operation_keys[3]],
        "index_roots": [operation_keys[4]],
        "plugin_release": [operation_keys[5]],
        "runtime_release": [operation_keys[6]],
        "selectors": [operation_keys[7]],
    }


def root_transitions(root: Path) -> list[dict[str, object]]:
    path = (root / "protected-archive").as_posix()
    return [
        {
            "after_exists": True,
            "after_gid": os.getgid(),
            "after_mode": 0o700,
            "after_type": "directory",
            "after_uid": os.getuid(),
            "before_exists": False,
            "before_gid": 0,
            "before_mode": 0,
            "before_type": "absent",
            "before_uid": 0,
            "kind": "add",
            "path": path,
            "path_digest": parent.digest("p07_protected_root_path", path),
            "root_role": "archive_root",
        }
    ]


def runtime_manifest(source_path: Path) -> tuple[dict[str, object], str]:
    payload = source_path.read_bytes()
    plugin = synthetic_plugin_binding()
    semantic = {
        "capabilities": {
            "after_payload_package_source_present": True,
            "attempt_consumed": False,
            "backup_created": False,
            "context_bound_rejection_envelope_source_present": True,
            "failed_request_continuation_materialized": False,
            "failed_request_continuation_source_present": True,
            "immutable_continuation_reference_source_present": True,
            "installed": False,
            "ledger_created": False,
            "live_mutated": False,
            "p08_server_rejection_subprojection_source_present": True,
            "p08_status_stage_projection_source_present": True,
            "plan_created": False,
            "preflight_executed": False,
            "production_adapter_source_present": True,
            "provider_called": False,
            "selected": False,
            "source_derived_fresh_max1_strategy_present": True,
            "source_owned_artifact_root_contract_present": True,
            "source_owned_request_collection_closed": True,
            "source_owned_request_collection_present": True,
            "source_owned_request_constructor_present": True,
            "status_invocation_evidence_source_present": True,
            "state_created": False,
        },
        "failed_request_continuation_storage": (
            runtime.failed_request_continuation_storage_identity()
        ),
        "files": [
            {
                "mode": 0o755,
                "path": "scripts/p07_owner_private_memory_transactional_runtime.py",
                "sha256": sha256(payload).hexdigest(),
                "size": len(payload),
            }
        ],
        "parent": {
            "controller_bundle_id": runtime.PARENT_CONTROLLER_BUNDLE_ID,
            "controller_manifest_sha256": runtime.PARENT_CONTROLLER_MANIFEST_SHA256,
            "controller_source_id": parent.SOURCE_ID,
            "full_mutation_bundle_id": parent.FULL_MUTATION_BUNDLE_ID,
            "full_mutation_manifest_sha256": parent.FULL_MUTATION_MANIFEST_SHA256,
            "full_mutation_source_id": mutation.SOURCE_ID,
            "predecessor_runtime_bundle_id": runtime.PREDECESSOR_RUNTIME_BUNDLE_ID,
            "predecessor_runtime_manifest_sha256": (
                runtime.PREDECESSOR_RUNTIME_MANIFEST_SHA256
            ),
            "production_plan_source_id": production.SOURCE_ID,
        },
        "plugin": plugin,
        "runtime_artifact": synthetic_runtime_artifact(plugin),
        "schema": runtime.BUNDLE_SCHEMA,
        "source_owned_artifact_roots": runtime.source_owned_artifact_root_contract(),
        "source": {
            "core_commit": runtime.CORE_SOURCE_COMMIT,
            "core_tree": runtime.CORE_SOURCE_TREE,
            "deploy_commit": "c" * 40,
            "deploy_parent_commit": runtime.DEPLOY_PARENT_COMMIT,
            "deploy_parent_tree": runtime.DEPLOY_PARENT_TREE,
            "deploy_tree": "d" * 40,
            "runtime_source_id": runtime.SOURCE_ID,
        },
    }
    manifest = {
        **semantic,
        "bundle_id": runtime.digest(
            runtime.BUNDLE_ID_DOMAIN, semantic
        ),
    }
    return manifest, sha256(runtime.canonical(manifest)).hexdigest()


class FakeRunner:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.services = service_projection()
        self.fail_counts: dict[tuple[str, ...], int] = {}

    def run(self, arguments: tuple[str, ...], *, timeout: int) -> runtime.CommandResult:
        del timeout
        if arguments not in runtime.allowed_commands():
            raise AssertionError(arguments)
        self.commands.append(arguments)
        remaining = self.fail_counts.get(arguments, 0)
        if remaining:
            self.fail_counts[arguments] = remaining - 1
            return runtime.CommandResult(1, "", "f" * 64)
        if arguments == (
            runtime.SYSTEMCTL,
            "stop",
            runtime.TELEGRAM_SOCKET,
            runtime.TELEGRAM_UNIT,
            runtime.CORE_UNIT,
        ):
            for key in ("core", "telegram", "telegram_socket"):
                self.services[key]["active_state"] = "inactive"
                self.services[key]["sub_state"] = "dead"
        elif arguments == (runtime.SYSTEMCTL, "start", runtime.CORE_UNIT):
            self.services["core"]["active_state"] = "active"
            self.services["core"]["sub_state"] = "running"
        elif arguments == (runtime.PYTHON, "-B", runtime.TELEGRAM_RESUME_CONTROLLER):
            self.services["telegram"]["active_state"] = "active"
            self.services["telegram"]["sub_state"] = "running"
            self.services["telegram_socket"]["active_state"] = "active"
            self.services["telegram_socket"]["sub_state"] = "listening"
        elif arguments[:2] == (runtime.SYSTEMCTL, "show"):
            unit = arguments[2]
            key = {
                runtime.CORE_UNIT: "core",
                runtime.TELEGRAM_UNIT: "telegram",
                runtime.TELEGRAM_SOCKET: "telegram_socket",
            }[unit]
            state = self.services[key]
            output = (
                f"ActiveState={state['active_state']}\n"
                f"SubState={state['sub_state']}\n"
                f"NRestarts={state['nrestarts']}\n"
            )
            return runtime.CommandResult(0, output, "0" * 64)
        elif arguments[0] == runtime.DOCKER:
            container = self.services["container"]
            output = (
                f"{container['state']}|{container['health']}|"
                f"{container['restart_count']}\n"
            )
            return runtime.CommandResult(0, output, "0" * 64)
        return runtime.CommandResult(0, "", "0" * 64)


class TransactionalRuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.transaction_root = self.root / "target"
        self.transaction_root.mkdir()
        self.contract, self.after_payloads = build_contract(self.transaction_root)
        self.state_root = self.root / "state"
        self.backup_root = self.root / "backups"
        self.package_root = self.root / "packages"
        self.archive_root = self.root / "protected-archive"
        self.continuation_ancestor = self.root / "continuation-ancestor"
        self.continuation_ancestor.mkdir(mode=0o755)
        self.continuation_ancestor.chmod(0o755)
        self.continuation_parent = self.continuation_ancestor / "protected-parent"
        self.continuation_root = self.continuation_parent / "continuations"
        self.fresh_state_parent = self.root / "fresh-state-parent"
        self.fresh_backup_parent = self.root / "fresh-backup-parent"
        self.fresh_package_parent = self.root / "fresh-package-parent"
        self.fresh_status_ancestor = self.root / "fresh-status-ancestor"
        for path in (
            self.fresh_state_parent,
            self.fresh_backup_parent,
            self.fresh_package_parent,
            self.fresh_status_ancestor,
        ):
            path.mkdir(mode=0o700)
            path.chmod(0o700)
        self.fresh_status_parent = self.fresh_status_ancestor / "status-parent"
        path_roles = []
        for category, operation in zip(CATEGORIES, self.contract["operations"]):
            key = mutation.path_key(operation["root_id"], operation["logical_path"])
            path_roles.append(
                {
                    "identity": "file:" + key,
                    "kind": operation["kind"],
                    "path": (self.transaction_root / operation["logical_path"]).as_posix(),
                    "role": category,
                }
            )
        self.production_identity = {
            "archive": {
                "database_gid": os.getgid(),
                "database_mode": 0o600,
                "database_name": production.FACTUAL_DATABASE_NAME,
                "database_uid": os.getuid(),
                "delivery_journal_retired": True,
                "empty": True,
                "journal_mode": production.FACTUAL_JOURNAL_MODE,
                "journal_name": production.FACTUAL_JOURNAL_NAME,
                "post_start_factual_audit": False,
                "root": self.archive_root.as_posix(),
                "root_precreated": True,
                "synchronous": production.FACTUAL_SYNCHRONOUS_LEVEL,
            },
            "identity_digest": "f" * 64,
            "path_roles": {"files": path_roles},
            "schema": production.TARGET_SCHEMA,
        }
        self.patchers = (
            patch.object(runtime, "STATE_ROOT", self.state_root),
            patch.object(runtime, "BACKUP_ROOT", self.backup_root),
            patch.object(runtime, "PACKAGE_ROOT", self.package_root),
            patch.object(
                runtime,
                "SOURCE_OWNED_CONTINUATION_TRUSTED_ANCESTOR",
                self.continuation_ancestor,
            ),
            patch.object(
                runtime,
                "SOURCE_OWNED_CONTINUATION_PARENT",
                self.continuation_parent,
            ),
            patch.object(
                runtime,
                "SOURCE_OWNED_CONTINUATION_ROOT",
                self.continuation_root,
            ),
            patch.object(runtime, "SOURCE_OWNED_CONTINUATION_UID", os.getuid()),
            patch.object(runtime, "SOURCE_OWNED_CONTINUATION_GID", os.getgid()),
            patch.object(runtime, "FRESH_STATE_PARENT", self.fresh_state_parent),
            patch.object(runtime, "FRESH_BACKUP_PARENT", self.fresh_backup_parent),
            patch.object(runtime, "FRESH_PACKAGE_PARENT", self.fresh_package_parent),
            patch.object(
                runtime, "FRESH_STATUS_TRUSTED_ANCESTOR", self.fresh_status_ancestor
            ),
            patch.object(runtime, "FRESH_STATUS_PARENT", self.fresh_status_parent),
            patch.object(parent, "FUTURE_STATE_ROOT", self.root / "old-state"),
            patch.object(parent, "FUTURE_BACKUP_ROOT", self.root / "old-backups"),
            patch.object(
                production,
                "validate_production_identity",
                return_value=self.production_identity,
            ),
        )
        for patcher in self.patchers:
            patcher.start()
        self.addCleanup(self.temporary.cleanup)
        for patcher in reversed(self.patchers):
            self.addCleanup(patcher.stop)
        self.lineage = lineages()
        self.parent_namespace = parent_namespace()
        self.parent_plan = parent.build_plan(
            core_commit=runtime.CORE_SOURCE_COMMIT,
            deploy_commit="c" * 40,
            deploy_tree="d" * 40,
            artifact_identities={
                "controller_bundle_id": runtime.PARENT_CONTROLLER_BUNDLE_ID,
                "full_mutation_bundle_id": parent.FULL_MUTATION_BUNDLE_ID,
                "full_mutation_manifest_sha256": parent.FULL_MUTATION_MANIFEST_SHA256,
            },
            lineages=self.lineage,
            public_prestate=public_prestate(),
            boundaries=boundaries(),
            policy=policy(),
            mutation_set=self.contract,
            mutation_coverage=coverage(self.contract, self.root),
            root_transitions=root_transitions(self.root),
            namespace=self.parent_namespace,
            state_root=self.state_root,
            backup_root=self.backup_root,
        )
        source_path = Path(runtime.__file__)
        self.manifest, self.manifest_sha = runtime_manifest(source_path)
        self.production_identity["plugin"] = plugin_artifact.binding_projection(
            self.manifest["plugin"]
        )
        self.production_identity["runtime_artifact"] = self.manifest[
            "runtime_artifact"
        ]
        current_request = self.prepare_request()
        current_request["owner_uid"] = (
            runtime.TERMINAL_REQUEST_PAYLOAD_TARGET_OWNER_UID
        )
        current_request["owner_gid"] = (
            runtime.TERMINAL_REQUEST_PAYLOAD_TARGET_OWNER_GID
        )
        self.continuation = runtime._assemble_failed_request_continuation_payload(
            current_intent=runtime._failed_request_intent_projection(
                current_request, expected_terminal=None
            ),
            target_contract=runtime._target_contract_from_manifest(
                manifest=self.manifest,
                manifest_sha256=self.manifest_sha,
                client_sha256=runtime.P08_STATUS_CLIENT_SOURCE_SHA256,
                protocol_acceptance_source_sha256=(
                    production.P08_PROTOCOL_ACCEPTANCE_SOURCE_SHA256
                ),
                service_entrypoint_sha256=(
                    runtime.P08_STATUS_SERVICE_ENTRYPOINT_SHA256
                ),
                future_unit_sha256=runtime.P08_STATUS_FUTURE_UNIT_SHA256,
                future_socket_unit_sha256=(
                    runtime.P08_STATUS_FUTURE_SOCKET_UNIT_SHA256
                ),
            ),
            contract=runtime._production_failed_request_contract(),
        )
        runtime._materialize_failed_request_continuation(
            continuation=self.continuation,
            trusted_ancestor=self.continuation_ancestor,
            continuation_parent=self.continuation_parent,
            continuation_root=runtime.SOURCE_OWNED_CONTINUATION_ROOT,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
        )
        self.runtime_plan = runtime.build_runtime_plan(
            parent_plan=self.parent_plan,
            mutation_set=self.contract,
            production_identity=self.production_identity,
            lineages=self.lineage,
            parent_namespace=self.parent_namespace,
            runtime_namespace=runtime.absent_runtime_namespace(),
            runtime_manifest=self.manifest,
            runtime_manifest_sha256=self.manifest_sha,
            expected_runtime_bundle_id=self.manifest["bundle_id"],
            expected_runtime_manifest_sha256=self.manifest_sha,
            prestate_services=service_projection(),
        )
        self.material = runtime.ProductionRuntimeMaterial(
            runtime_plan=self.runtime_plan,
            mutation_set=self.contract,
            before_payloads={},
            after_payloads=self.after_payloads,
        )
        self.package_context = runtime._package_context(
            material=self.material,
            lineages=self.lineage,
            parent_namespace=self.parent_namespace,
            runtime_manifest=self.manifest,
            runtime_manifest_sha256=self.manifest_sha,
            expected_runtime_bundle_id=self.manifest["bundle_id"],
            expected_runtime_manifest_sha256=self.manifest_sha,
            failed_request_continuation=self.continuation,
        )
        self._package_receipt: dict[str, object] | None = None

    def context(self, mode: str, **extra: object) -> dict[str, object]:
        receipt = self.ensure_package()
        return {
            "mode": mode,
            "package_digest": receipt["package_digest"],
            "package_id": receipt["package_id"],
            "schema": runtime.REQUEST_SCHEMA,
            **extra,
        }

    def prepare_request(self) -> dict[str, object]:
        return {
            "core_candidate": "/inactive/core",
            "expected_runtime_bundle_id": self.manifest["bundle_id"],
            "expected_runtime_manifest_sha256": self.manifest_sha,
            "lineages": self.lineage,
            "mode": "prepare-package",
            "owner_gid": os.getgid(),
            "owner_uid": os.getuid(),
            "plugin_candidate": "/inactive/plugin",
            "runtime_candidate": "/inactive/runtime",
            "runtime_manifest": self.manifest,
            "runtime_manifest_sha256": self.manifest_sha,
            "schema": runtime.REQUEST_SCHEMA,
        }

    def ensure_package(self) -> dict[str, object]:
        if self._package_receipt is None:
            self._package_receipt = runtime.materialize_after_payload_package(
                context=self.package_context,
                after_payloads=self.after_payloads,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
                package_root=self.package_root,
            )
        return self._package_receipt

    def package_fixture(
        self, package_root: Path
    ) -> tuple[runtime.ProductionRuntimeMaterial, dict[str, object]]:
        with patch.object(runtime, "PACKAGE_ROOT", package_root):
            runtime_plan = runtime.build_runtime_plan(
                parent_plan=self.parent_plan,
                mutation_set=self.contract,
                production_identity=self.production_identity,
                lineages=self.lineage,
                parent_namespace=self.parent_namespace,
                runtime_namespace=runtime.absent_runtime_namespace(),
                runtime_manifest=self.manifest,
                runtime_manifest_sha256=self.manifest_sha,
                expected_runtime_bundle_id=self.manifest["bundle_id"],
                expected_runtime_manifest_sha256=self.manifest_sha,
                prestate_services=service_projection(),
            )
            material = runtime.ProductionRuntimeMaterial(
                runtime_plan=runtime_plan,
                mutation_set=self.contract,
                before_payloads={},
                after_payloads=self.after_payloads,
            )
            context = runtime._package_context(
                material=material,
                lineages=self.lineage,
                parent_namespace=self.parent_namespace,
                runtime_manifest=self.manifest,
                runtime_manifest_sha256=self.manifest_sha,
                expected_runtime_bundle_id=self.manifest["bundle_id"],
                expected_runtime_manifest_sha256=self.manifest_sha,
                failed_request_continuation=self.continuation,
            )
        return material, context

    def create_backup_and_ledger(self) -> None:
        runtime.dispatch_request(
            mode="backup-contract",
            request=self.context(
                "backup-contract", owner_uid=os.getuid(), owner_gid=os.getgid()
            ),
        )
        runtime.dispatch_request(
            mode="ledger-create",
            request=self.context("ledger-create", owner_uid=os.getuid(), owner_gid=os.getgid()),
        )

    def test_prepare_package_binds_exact_source_artifact_and_absent_namespace(self) -> None:
        request = self.prepare_request()

        def construct(**kwargs: object) -> runtime.ProductionRuntimeMaterial:
            runtime.validate_runtime_artifact_manifest(
                kwargs["runtime_manifest"],
                manifest_sha256=kwargs["runtime_manifest_sha256"],
                expected_bundle_id=kwargs["expected_runtime_bundle_id"],
                expected_manifest_sha256=kwargs["expected_runtime_manifest_sha256"],
            )
            runtime.observe_parent_failed_start_namespace()
            runtime.verify_namespace_absent(
                runtime.namespace_observation(
                    state_root=self.state_root,
                    backup_root=self.backup_root,
                )
            )
            return self.material

        with patch.object(
            runtime, "construct_production_runtime_material", side_effect=construct
        ) as constructor:
            receipt = runtime.dispatch_request(
                mode="prepare-package",
                request=request,
                package_root=self.package_root,
                failed_request_continuation=self.continuation,
            )
            self.assertEqual(receipt["status"], "complete")
            self.assertEqual(constructor.call_count, 1)
            self.assertEqual(receipt["flags"], runtime._ZERO_FLAGS)
            self.assertEqual(
                set(receipt),
                {
                    "flags",
                    "operation_count",
                    "package_digest",
                    "package_id",
                    "payload_bytes",
                    "payload_count",
                    "plan_id",
                    "receipt_id",
                    "schema",
                    "source_id",
                    "status",
                    "strategy_id",
                },
            )
        drifted = json.loads(json.dumps(request))
        drifted["runtime_manifest"]["source"]["deploy_tree"] = "e" * 40
        with patch.object(
            runtime, "construct_production_runtime_material", side_effect=construct
        ):
            with self.assertRaisesRegex(RuntimeError, "manifest_digest_drifted"):
                runtime.dispatch_request(
                    mode="prepare-package",
                    request=drifted,
                    package_root=self.root / "drifted-packages",
                    failed_request_continuation=self.continuation,
                )
        with patch.object(
            runtime, "construct_production_runtime_material", side_effect=construct
        ):
            with self.assertRaisesRegex(RuntimeError, "namespace_preexisting"):
                runtime.dispatch_request(
                    mode="prepare-package",
                    request=request,
                    package_root=self.package_root,
                    failed_request_continuation=self.continuation,
                )

    def test_source_owned_constructor_derives_every_identity_and_is_stable(self) -> None:
        core_identity = {
            "commit": runtime.CORE_SOURCE_COMMIT,
            "tree": runtime.CORE_SOURCE_TREE,
        }
        deploy_identity = {
            "commit": self.manifest["source"]["deploy_commit"],
            "tree": self.manifest["source"]["deploy_tree"],
        }
        candidates = (
            Path("/source-owned/core"),
            Path("/source-owned/runtime"),
            Path("/source-owned/plugin"),
        )
        owner = type(
            "Owner",
            (),
            {"pw_uid": os.getuid(), "pw_gid": os.getgid()},
        )()
        with (
            patch.object(
                runtime,
                "_source_git_identity",
                side_effect=[core_identity, deploy_identity, core_identity, deploy_identity],
            ),
            patch.object(
                runtime,
                "_source_owned_bundle_manifest",
                return_value=(self.manifest, self.manifest_sha),
            ),
            patch.object(
                runtime, "_source_owned_candidates", return_value=candidates
            ),
            patch.object(
                production, "resolve_reviewed_artifacts", return_value=object()
            ) as resolver,
            patch.object(runtime.pwd, "getpwnam", return_value=owner),
            patch.object(
                runtime,
                "IMMUTABLE_LINEAGE_EVIDENCE_DIGEST",
                self.lineage["evidence_digest"],
            ),
        ):
            first = runtime._construct_source_owned_prepare_request(
                core_source=Path("/fixed/core"),
                deploy_source=Path("/fixed/deploy"),
                runtime_build_root=Path("/fixed/runtime-build"),
                bundle_root=Path("/fixed/bundle"),
                evidence_root=Path("/fixed/evidence"),
                owner_account="myuna",
                lineage_loader=lambda _root: self.lineage,
            )
            second = runtime._construct_source_owned_prepare_request(
                core_source=Path("/fixed/core"),
                deploy_source=Path("/fixed/deploy"),
                runtime_build_root=Path("/fixed/runtime-build"),
                bundle_root=Path("/fixed/bundle"),
                evidence_root=Path("/fixed/evidence"),
                owner_account="myuna",
                lineage_loader=lambda _root: self.lineage,
            )
        self.assertEqual(first, second)
        self.assertEqual(runtime.canonical(first), runtime.canonical(second))
        self.assertEqual(first["core_candidate"], candidates[0].as_posix())
        self.assertEqual(first["runtime_candidate"], candidates[1].as_posix())
        self.assertEqual(first["plugin_candidate"], candidates[2].as_posix())
        self.assertEqual(resolver.call_count, 2)

    def test_source_owned_constructor_rejects_source_and_caller_substitution(self) -> None:
        with patch.object(
            runtime,
            "_source_git_identity",
            side_effect=[
                {"commit": runtime.CORE_SOURCE_COMMIT, "tree": "0" * 40},
                {"commit": "c" * 40, "tree": "d" * 40},
            ],
        ):
            with self.assertRaisesRegex(RuntimeError, "core_source_rejected"):
                runtime._construct_source_owned_prepare_request(
                    core_source=Path("/fixed/core"),
                    deploy_source=Path("/fixed/deploy"),
                    runtime_build_root=Path("/fixed/runtime-build"),
                    bundle_root=Path("/fixed/bundle"),
                    evidence_root=Path("/fixed/evidence"),
                    owner_account="myuna",
                    lineage_loader=lambda _root: self.lineage,
                )
        exact = self.prepare_request()
        substituted = json.loads(json.dumps(exact))
        substituted["runtime_candidate"] = "/alternate/runtime"
        with patch.object(
            runtime, "construct_source_owned_prepare_request", return_value=exact
        ):
            self.assertEqual(runtime.validate_source_owned_prepare_request(exact), exact)
            with self.assertRaisesRegex(RuntimeError, "source_owned_request_rejected"):
                runtime.validate_source_owned_prepare_request(substituted)

    def test_source_owned_artifact_roots_are_fixed_reviewed_and_manifest_bound(self) -> None:
        contract = runtime.source_owned_artifact_root_contract()
        self.assertEqual(
            contract["runtime_root"],
            {
                "path": (
                    "/srv/myuna/builds/"
                    "p07-p08-single-nonce-stage-integration-v1-final-runtime-a"
                ),
                "role": "production-runtime-artifact-root",
            },
        )
        self.assertEqual(
            contract["bundle_root"],
            {
                "path": (
                    "/srv/myuna/builds/"
                    "p07-p08-single-nonce-stage-integration-v1-final-bundle-a"
                ),
                "role": "production-transactional-bundle-root",
            },
        )
        self.assertTrue(all(value is False for value in contract["selection"].values()))
        self.assertEqual(
            runtime._validate_source_owned_artifact_root_contract(contract), contract
        )

        for field, value in (
            ("runtime_root", "/srv/myuna/builds/predecessor-runtime"),
            ("bundle_root", "/srv/myuna/builds/predecessor-bundle"),
        ):
            drifted = json.loads(json.dumps(self.manifest))
            drifted["source_owned_artifact_roots"][field]["path"] = value
            semantic = {key: drifted[key] for key in drifted if key != "bundle_id"}
            drifted["bundle_id"] = runtime.digest(runtime.BUNDLE_ID_DOMAIN, semantic)
            manifest_sha = sha256(runtime.canonical(drifted)).hexdigest()
            with self.subTest(field=field), self.assertRaisesRegex(
                RuntimeError, "artifact_root_contract_rejected"
            ):
                runtime.validate_runtime_artifact_manifest(
                    drifted,
                    manifest_sha256=manifest_sha,
                    expected_bundle_id=drifted["bundle_id"],
                    expected_manifest_sha256=manifest_sha,
                )

    def test_production_constructor_ignores_environment_and_has_no_root_locator(self) -> None:
        projection = {"source_owned": True}
        with (
            patch.dict(
                os.environ,
                {
                    "P07_RUNTIME_ARTIFACT_ROOT": "/srv/myuna/builds/predecessor-runtime",
                    "P07_TRANSACTIONAL_BUNDLE_ROOT": "/srv/myuna/builds/predecessor-bundle",
                },
            ),
            patch.object(
                runtime,
                "_construct_source_owned_prepare_request",
                return_value=projection,
            ) as constructor,
        ):
            self.assertEqual(runtime.construct_source_owned_prepare_request(), projection)
        constructor.assert_called_once_with(
            core_source=runtime.SOURCE_OWNED_CORE_ROOT,
            deploy_source=runtime.SOURCE_OWNED_DEPLOY_ROOT,
            runtime_build_root=runtime.SOURCE_OWNED_RUNTIME_ARTIFACT_ROOT,
            bundle_root=runtime.SOURCE_OWNED_TRANSACTIONAL_BUNDLE_ROOT,
            evidence_root=runtime.SOURCE_OWNED_EVIDENCE_ROOT,
            owner_account=runtime.SOURCE_OWNED_OWNER_ACCOUNT,
        )
        source = Path(runtime.__file__).read_text(encoding="utf-8")
        self.assertNotIn(
            "p07-immutable-continuation-fresh-strategy-v1-final-runtime-a", source
        )
        self.assertNotIn(
            "p07-immutable-continuation-fresh-strategy-v1-final-bundle-a", source
        )

    def test_terminal_prepare_request_replay_rejects_before_observer(self) -> None:
        request = self.prepare_request()
        with (
            patch.object(
                runtime, "construct_production_runtime_material"
            ) as constructor,
            patch.object(production, "SystemProtectedObserver") as observer,
        ):
            with self.assertRaisesRegex(RuntimeError, "terminal_request_replay_rejected"):
                runtime.dispatch_request(mode="prepare-package", request=request)
        constructor.assert_not_called()
        observer.assert_not_called()

    def test_source_owned_request_package_is_deterministic_non_overwriting_and_content_free(self) -> None:
        request = self.prepare_request()
        first_root = self.root / "source-requests-a"
        second_root = self.root / "source-requests-b"
        first = runtime._materialize_source_owned_request(
            request=request,
            request_root=first_root,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
        )
        second = runtime._materialize_source_owned_request(
            request=request,
            request_root=second_root,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
        )
        self.assertEqual(first["request_id"], second["request_id"])
        self.assertEqual(first["request_sha256"], second["request_sha256"])
        first_package = first_root / str(first["request_id"])
        second_package = second_root / str(second["request_id"])
        for name in ("completion.json", "receipt.json", "request.json"):
            self.assertEqual(
                (first_package / name).read_bytes(),
                (second_package / name).read_bytes(),
            )
            self.assertEqual(
                (first_package / name).stat().st_mode & 0o777,
                (second_package / name).stat().st_mode & 0o777,
            )
        receipt_text = (first_package / "receipt.json").read_text(encoding="ascii")
        for forbidden in ("payload", "profile", "message", "temporal_text"):
            self.assertNotIn(forbidden, receipt_text.lower())
        preserved = {
            name: (first_package / name).read_bytes()
            for name in ("completion.json", "receipt.json", "request.json")
        }
        sibling = json.loads(json.dumps(request))
        sibling["owner_uid"] = int(sibling["owner_uid"]) + 1
        third = json.loads(json.dumps(request))
        third["owner_uid"] = int(third["owner_uid"]) + 2
        second_receipt = runtime._materialize_source_owned_request(
            request=sibling,
            request_root=first_root,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
        )
        third_receipt = runtime._materialize_source_owned_request(
            request=third,
            request_root=first_root,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
        )
        self.assertEqual(second_receipt["collection_count_before"], 1)
        self.assertEqual(third_receipt["collection_count"], 3)
        self.assertEqual(len(set(first_root.iterdir())), 3)
        for name, payload in preserved.items():
            self.assertEqual((first_package / name).read_bytes(), payload)
        with self.assertRaisesRegex(RuntimeError, "replay_rejected"):
            runtime._materialize_source_owned_request(
                request=request,
                request_root=first_root,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )

    def test_source_owned_request_crash_residue_replay_and_tamper_fail_closed(self) -> None:
        request = self.prepare_request()
        for stage in (
            "root_created",
            "writer_locked",
            "temporary_created",
            "request_written",
            "receipt_written",
            "completion_written",
            "finalized",
        ):
            request_root = self.root / f"request-crash-{stage}"

            def crash(observed: str, *, expected: str = stage) -> None:
                if observed == expected:
                    raise RuntimeError("synthetic_request_crash")

            with self.assertRaisesRegex(RuntimeError, "synthetic_request_crash"):
                runtime._materialize_source_owned_request(
                    request=request,
                    request_root=request_root,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                    crash_hook=crash,
                )
            residue_before = sorted(path.name for path in request_root.iterdir())
            if stage in ("root_created", "writer_locked"):
                retried = runtime._materialize_source_owned_request(
                    request=request,
                    request_root=request_root,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
                self.assertEqual(retried["collection_count"], 1)
            elif stage == "finalized":
                with self.assertRaisesRegex(RuntimeError, "replay_rejected"):
                    runtime._materialize_source_owned_request(
                        request=request,
                        request_root=request_root,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )
                self.assertEqual(
                    runtime._verify_source_owned_request_collection(
                        request_root=request_root,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )["collection_count"],
                    1,
                )
            else:
                with self.assertRaisesRegex(RuntimeError, "collection_rejected"):
                    runtime._materialize_source_owned_request(
                        request=request,
                        request_root=request_root,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )
                self.assertEqual(
                    sorted(path.name for path in request_root.iterdir()), residue_before
                )

        request_root = self.root / "request-tamper"
        receipt = runtime._materialize_source_owned_request(
            request=request,
            request_root=request_root,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
        )
        request_path = request_root / str(receipt["request_id"]) / "request.json"
        os.link(request_path, self.root / "request-hardlink")
        with self.assertRaisesRegex(RuntimeError, "request_package_rejected"):
            runtime._verify_source_owned_request_package(
                request=request,
                request_root=request_root,
                request_id=str(receipt["request_id"]),
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )
        (self.root / "request-hardlink").unlink()
        request_path.chmod(0o640)
        with self.assertRaisesRegex(RuntimeError, "request_package_rejected"):
            runtime._verify_source_owned_request_package(
                request=request,
                request_root=request_root,
                request_id=str(receipt["request_id"]),
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )

    def test_source_owned_request_noncanonical_and_symlink_outputs_reject(self) -> None:
        request = self.prepare_request()
        noncanonical = self.root / "noncanonical.json"
        noncanonical.write_text(
            json.dumps(request, ensure_ascii=True, indent=2), encoding="ascii"
        )
        with self.assertRaisesRegex(RuntimeError, "source_owned_noncanonical"):
            runtime._canonical_read(
                noncanonical, "transactional_runtime_source_owned_noncanonical"
            )
        target = self.root / "symlink-target"
        target.mkdir()
        output = self.root / "request-symlink"
        output.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "collection_rejected"):
            runtime._materialize_source_owned_request(
                request=request,
                request_root=output,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )

    def test_source_owned_request_collection_rejects_inventory_and_root_drift(self) -> None:
        request = self.prepare_request()
        cases = ("unknown", "symlink", "partial", "mode")
        for case in cases:
            request_root = self.root / f"request-collection-{case}"
            runtime._materialize_source_owned_request(
                request=request,
                request_root=request_root,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )
            if case == "unknown":
                (request_root / "unexpected").write_bytes(b"")
            elif case == "symlink":
                (request_root / ("a" * 64)).symlink_to(
                    request_root / next(request_root.iterdir()).name,
                    target_is_directory=True,
                )
            elif case == "partial":
                partial = request_root / ("b" * 64)
                partial.mkdir(mode=0o700)
                (partial / "request.json").write_bytes(b"{}\n")
            else:
                request_root.chmod(0o750)
            with self.assertRaisesRegex(RuntimeError, "collection_rejected"):
                runtime._verify_source_owned_request_collection(
                    request_root=request_root,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )

    def test_source_owned_request_collection_serializes_two_writers(self) -> None:
        request = self.prepare_request()
        request_root = self.root / "request-concurrent"
        locked = threading.Event()
        release = threading.Event()
        outcome: list[object] = []

        def hold_lock(stage: str) -> None:
            if stage == "writer_locked":
                locked.set()
                if not release.wait(timeout=5):
                    raise RuntimeError("synthetic_writer_timeout")

        def first_writer() -> None:
            try:
                outcome.append(
                    runtime._materialize_source_owned_request(
                        request=request,
                        request_root=request_root,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                        crash_hook=hold_lock,
                    )
                )
            except Exception as exc:  # pragma: no cover - asserted below
                outcome.append(exc)

        thread = threading.Thread(target=first_writer)
        thread.start()
        self.assertTrue(locked.wait(timeout=5))
        sibling = json.loads(json.dumps(request))
        sibling["owner_uid"] = int(sibling["owner_uid"]) + 1
        try:
            with self.assertRaisesRegex(RuntimeError, "concurrent_writer"):
                runtime._materialize_source_owned_request(
                    request=sibling,
                    request_root=request_root,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
        finally:
            release.set()
            thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], dict)
        self.assertEqual(
            runtime._verify_source_owned_request_collection(
                request_root=request_root,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )["collection_count"],
            1,
        )

    def test_source_owned_request_collection_owner_and_no_replace_fail_closed(self) -> None:
        request = self.prepare_request()
        request_root = self.root / "request-owner"
        runtime._materialize_source_owned_request(
            request=request,
            request_root=request_root,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
        )
        with self.assertRaisesRegex(RuntimeError, "collection_rejected"):
            runtime._verify_source_owned_request_collection(
                request_root=request_root,
                owner_uid=os.getuid() + 1,
                owner_gid=os.getgid(),
            )

        source = self.root / "rename-source"
        target = self.root / "rename-target"
        source.mkdir()
        target.mkdir()
        (source / "source-marker").write_bytes(b"source")
        (target / "target-marker").write_bytes(b"target")
        with self.assertRaisesRegex(RuntimeError, "replay_rejected"):
            runtime._rename_no_replace(source, target)
        self.assertEqual((source / "source-marker").read_bytes(), b"source")
        self.assertEqual((target / "target-marker").read_bytes(), b"target")

    def test_source_owned_request_collection_has_zero_observer_reachability(self) -> None:
        request = self.prepare_request()
        with (
            patch.object(production, "SystemProtectedObserver") as observer,
            patch.object(
                runtime, "construct_production_runtime_material"
            ) as production_constructor,
        ):
            receipt = runtime._materialize_source_owned_request(
                request=request,
                request_root=self.root / "request-no-observer",
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )
        self.assertEqual(receipt["collection_count"], 1)
        observer.assert_not_called()
        production_constructor.assert_not_called()

    def test_request_collection_max_two_rejects_third_without_mutation(self) -> None:
        request_root = self.root / "request-max-two"
        requests = []
        for offset in range(3):
            request = self.prepare_request()
            request["owner_uid"] = offset
            requests.append(request)
        for request in requests[:2]:
            runtime._materialize_source_owned_request(
                request=request,
                request_root=request_root,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
                maximum_count=runtime.MAX_SOURCE_OWNED_REQUEST_COUNT,
            )
        before = {
            path.relative_to(request_root).as_posix(): sha256(path.read_bytes()).hexdigest()
            for path in request_root.rglob("*")
            if path.is_file()
        }
        with self.assertRaisesRegex(RuntimeError, "request_collection_closed"):
            runtime._materialize_source_owned_request(
                request=requests[2],
                request_root=request_root,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
                maximum_count=runtime.MAX_SOURCE_OWNED_REQUEST_COUNT,
            )
        after = {
            path.relative_to(request_root).as_posix(): sha256(path.read_bytes()).hexdigest()
            for path in request_root.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)
        self.assertEqual(
            runtime._verify_source_owned_request_collection(
                request_root=request_root,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )["collection_count"],
            2,
        )

    def test_failed_request_continuation_binds_exact_p08_accepted_handoff(self) -> None:
        self.assertEqual(
            runtime.P08_ACCEPTED_HANDOFF_SHA256,
            "1e287ae36ce93218ae36466a1876deb8b434e03b1d1e7ceb43aaaceee106baae",
        )
        self.assertEqual(len(runtime.P08_ACCEPTED_HANDOFF_SHA256), 64)

    def test_terminal_manifest_capability_profile_is_exact_and_not_current(self) -> None:
        manifest = json.loads(json.dumps(self.manifest))
        manifest.pop("failed_request_continuation_storage")
        manifest.pop("source_owned_artifact_roots")
        manifest["schema"] = runtime.TERMINAL_BUNDLE_SCHEMA
        manifest["capabilities"] = runtime._runtime_capability_identity(
            terminal_predecessor=True
        )
        semantic = {key: manifest[key] for key in manifest if key != "bundle_id"}
        manifest["bundle_id"] = runtime.digest(
            runtime.TERMINAL_BUNDLE_ID_DOMAIN, semantic
        )
        manifest_sha = sha256(runtime.canonical(manifest)).hexdigest()

        validated = runtime.validate_runtime_artifact_manifest(
            manifest,
            manifest_sha256=manifest_sha,
            expected_bundle_id=manifest["bundle_id"],
            expected_manifest_sha256=manifest_sha,
            terminal_predecessor=True,
        )
        self.assertEqual(validated["capabilities"], manifest["capabilities"])
        with self.assertRaisesRegex(RuntimeError, "manifest_rejected"):
            runtime.validate_runtime_artifact_manifest(
                manifest,
                manifest_sha256=manifest_sha,
                expected_bundle_id=manifest["bundle_id"],
                expected_manifest_sha256=manifest_sha,
            )

    def test_failed_request_continuation_is_deterministic_singleton_and_content_free(self) -> None:
        layouts = []
        for name in ("continuation-a", "continuation-b"):
            ancestor = self.root / f"{name}-ancestor"
            ancestor.mkdir(mode=0o755)
            ancestor.chmod(0o755)
            parent_path = ancestor / "protected-parent"
            layouts.append((ancestor, parent_path, parent_path / "continuations"))
        roots = [layout[2] for layout in layouts]
        receipts = [
            runtime._materialize_failed_request_continuation(
                continuation=self.continuation,
                trusted_ancestor=ancestor,
                continuation_parent=parent_path,
                continuation_root=root_path,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )
            for ancestor, parent_path, root_path in layouts
        ]
        self.assertEqual(receipts[0], receipts[1])
        continuation_id = str(receipts[0]["continuation_id"])
        for name in ("continuation.json", "receipt.json", "completion.json"):
            self.assertEqual(
                (roots[0] / continuation_id / name).read_bytes(),
                (roots[1] / continuation_id / name).read_bytes(),
            )
        receipt_text = (roots[0] / continuation_id / "receipt.json").read_text(
            encoding="ascii"
        )
        for forbidden in ("temporal_text", "profile", "payload", "message"):
            self.assertNotIn(forbidden, receipt_text.lower())
        with self.assertRaisesRegex(RuntimeError, "continuation_namespace_rejected"):
            runtime._materialize_failed_request_continuation(
                continuation=self.continuation,
                trusted_ancestor=layouts[0][0],
                continuation_parent=layouts[0][1],
                continuation_root=roots[0],
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )

    def test_failed_request_continuation_storage_is_independent_root_owned_layout(self) -> None:
        ancestor = Path("/var/lib")
        parent_path = Path(
            "/var/lib/myuna-p07-owner-private-memory-failed-request-continuations-v1"
        )
        root_path = parent_path / "continuations"
        with (
            patch.object(runtime, "SOURCE_OWNED_CONTINUATION_TRUSTED_ANCESTOR", ancestor),
            patch.object(runtime, "SOURCE_OWNED_CONTINUATION_PARENT", parent_path),
            patch.object(runtime, "SOURCE_OWNED_CONTINUATION_ROOT", root_path),
            patch.object(runtime, "SOURCE_OWNED_CONTINUATION_UID", 0),
            patch.object(runtime, "SOURCE_OWNED_CONTINUATION_GID", 0),
        ):
            storage = runtime.failed_request_continuation_storage_identity()
        self.assertEqual(
            storage,
            {
                "child": {"link_count": 2, "mode": 0o700, "role": "continuation-child"},
                "files": {"link_count": 1, "mode": 0o600, "role": "continuation-files"},
                "owner": {"gid": 0, "uid": 0},
                "parent": {
                    "initial_state": "absent",
                    "link_count_after_materialization": 3,
                    "mode": 0o700,
                    "path": "/var/lib/myuna-p07-owner-private-memory-failed-request-continuations-v1",
                    "role": "continuation-protected-parent",
                    "type": "directory",
                },
                "root": {
                    "initial_state": "absent",
                    "link_count_after_materialization": 3,
                    "mode": 0o700,
                    "path": "/var/lib/myuna-p07-owner-private-memory-failed-request-continuations-v1/continuations",
                    "role": "continuation-collection-root",
                    "type": "directory",
                },
                "schema": "myuna.p07-owner-private-memory-failed-request-continuation-storage.v1",
                "source_id": "p07-owner-private-memory-failed-request-continuation-root-owned-storage-v1",
                "trusted_ancestor": {
                    "mode": 0o755,
                    "path": "/var/lib",
                    "role": "continuation-trusted-ancestor",
                    "type": "directory",
                },
            },
        )
        self.assertNotIn(
            "/var/lib/myuna-telegram-gateway",
            runtime.canonical(storage).decode("ascii"),
        )

    def test_failed_request_continuation_namespace_identity_failures_are_content_free(self) -> None:
        def layout(name: str) -> tuple[Path, Path, Path]:
            ancestor = self.root / f"{name}-ancestor"
            ancestor.mkdir(mode=0o755)
            ancestor.chmod(0o755)
            parent_path = ancestor / "protected-parent"
            return ancestor, parent_path, parent_path / "continuations"

        wrong_mode = layout("wrong-mode")
        wrong_mode[0].chmod(0o750)
        wrong_owner = layout("wrong-owner")
        partial = layout("partial")
        partial[1].mkdir(mode=0o700)
        legacy = layout("legacy")
        wrong_role = layout("wrong-role")

        real_ancestor = self.root / "real-ancestor"
        real_ancestor.mkdir(mode=0o755)
        real_ancestor.chmod(0o755)
        symlink_ancestor = self.root / "symlink-ancestor"
        symlink_ancestor.symlink_to(real_ancestor, target_is_directory=True)
        symlink_parent = symlink_ancestor / "protected-parent"
        symlink_layout = (
            symlink_ancestor,
            symlink_parent,
            symlink_parent / "continuations",
        )

        cases = (
            (*wrong_mode, os.getuid(), os.getgid()),
            (*wrong_owner, os.getuid() + 1, os.getgid()),
            (*partial, os.getuid(), os.getgid()),
            (*symlink_layout, os.getuid(), os.getgid()),
            (
                wrong_role[0],
                wrong_role[1],
                wrong_role[0] / "other-parent" / "continuations",
                os.getuid(),
                os.getgid(),
            ),
        )
        for ancestor, parent_path, root_path, owner_uid, owner_gid in cases:
            with self.assertRaisesRegex(RuntimeError, "continuation_namespace_rejected"):
                runtime._materialize_failed_request_continuation(
                    continuation=self.continuation,
                    trusted_ancestor=ancestor,
                    continuation_parent=parent_path,
                    continuation_root=root_path,
                    owner_uid=owner_uid,
                    owner_gid=owner_gid,
                )

        with patch.object(runtime, "LEGACY_GATEWAY_CONTINUATION_ROOT", legacy[2]):
            with self.assertRaisesRegex(RuntimeError, "continuation_namespace_rejected"):
                runtime._materialize_failed_request_continuation(
                    continuation=self.continuation,
                    trusted_ancestor=legacy[0],
                    continuation_parent=legacy[1],
                    continuation_root=legacy[2],
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
        self.assertFalse(legacy[1].exists())

    def test_failed_request_continuation_crash_replay_concurrency_and_drift_fail_closed(self) -> None:
        for stage in (
            "parent_created",
            "root_created",
            "temporary_created",
            "continuation_written",
            "receipt_written",
            "completion_written",
            "finalized",
        ):
            ancestor = self.root / f"continuation-crash-{stage}-ancestor"
            ancestor.mkdir(mode=0o755)
            ancestor.chmod(0o755)
            parent_path = ancestor / "protected-parent"
            root = parent_path / "continuations"

            def crash(observed: str, *, expected: str = stage) -> None:
                if observed == expected:
                    raise RuntimeError("synthetic_continuation_crash")

            with self.assertRaisesRegex(RuntimeError, "synthetic_continuation_crash"):
                runtime._materialize_failed_request_continuation(
                    continuation=self.continuation,
                    trusted_ancestor=ancestor,
                    continuation_parent=parent_path,
                    continuation_root=root,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                    crash_hook=crash,
                )
            with self.assertRaisesRegex(RuntimeError, "continuation_namespace_rejected"):
                runtime._materialize_failed_request_continuation(
                    continuation=self.continuation,
                    trusted_ancestor=ancestor,
                    continuation_parent=parent_path,
                    continuation_root=root,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )

        race_ancestor = self.root / "continuation-race-ancestor"
        race_ancestor.mkdir(mode=0o755)
        race_ancestor.chmod(0o755)
        race_parent = race_ancestor / "protected-parent"
        race_root = race_parent / "continuations"
        started = threading.Barrier(2)
        results: list[object] = []

        def writer() -> None:
            started.wait(timeout=5)
            try:
                results.append(
                    runtime._materialize_failed_request_continuation(
                        continuation=self.continuation,
                        trusted_ancestor=race_ancestor,
                        continuation_parent=race_parent,
                        continuation_root=race_root,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )
                )
            except Exception as exc:  # pragma: no cover - asserted below
                results.append(exc)

        threads = [threading.Thread(target=writer) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        self.assertEqual(sum(isinstance(item, dict) for item in results), 1)
        self.assertEqual(sum(isinstance(item, Exception) for item in results), 1)

        for field, mutate in (
            ("p08", lambda item: item["p08_accepted"].update({"release_digest": "0" * 64})),
            ("terminal", lambda item: item["terminal_rejection"].update({"sha256": "0" * 64})),
            ("target", lambda item: item["target_contract"].update({"bundle_id": "0" * 64})),
            ("third_request", lambda item: item["request_collection"].update({"third_request_allowed": True})),
        ):
            del field
            drifted = json.loads(json.dumps(self.continuation))
            mutate(drifted)
            with self.assertRaisesRegex(RuntimeError, "continuation_binding_rejected"):
                runtime._validate_failed_request_continuation_payload(
                    drifted,
                    runtime_manifest=self.manifest,
                    runtime_manifest_sha256=self.manifest_sha,
                    lineages=self.lineage,
                )

    def test_failed_request_continuation_file_rename_collision_preserves_evidence(self) -> None:
        root = self.root / "continuation-file-race"
        root.mkdir(mode=0o700)
        target = root / "continuation.json"
        payload = runtime.canonical(self.continuation)
        original = runtime._rename_no_replace

        def collide(*args: object, **kwargs: object) -> None:
            target.write_bytes(b"synthetic-collision-evidence")
            target.chmod(0o600)
            original(*args, **kwargs)

        with patch.object(runtime, "_rename_no_replace", side_effect=collide):
            with self.assertRaisesRegex(
                RuntimeError, "continuation_file_write_rejected"
            ):
                runtime._write_continuation_file_no_replace(
                    target,
                    payload=payload,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
        self.assertEqual(target.read_bytes(), b"synthetic-collision-evidence")
        temporary = root / f".{target.name}.{sha256(payload).hexdigest()[:16]}.tmp"
        self.assertTrue(temporary.is_file())

    def test_continuation_prepare_uses_current_source_once_and_never_dispatches_terminal_request(self) -> None:
        observer = object()
        projection = {"status": "complete", "flags": dict(runtime._ZERO_FLAGS)}
        target = {
            "core_candidate": Path("/inactive/core"),
            "lineages": self.lineage,
            "manifest": self.manifest,
            "manifest_sha256": self.manifest_sha,
            "owner_gid": 0,
            "owner_uid": 0,
            "plugin_candidate": Path("/inactive/plugin"),
            "runtime_candidate": Path("/inactive/runtime"),
        }

        with (
            patch.object(
                runtime,
                "verify_source_owned_failed_request_continuation",
                return_value={"continuation": self.continuation},
            ) as verifier,
            patch.object(
                runtime,
                "_source_owned_target_material",
                return_value=target,
            ) as target_constructor,
            patch.object(production, "SystemProtectedObserver", return_value=observer),
            patch.object(
                runtime,
                "_prepare_package_from_target_material",
                return_value=projection,
            ) as preparer,
            patch.object(runtime, "construct_source_owned_prepare_request") as request_constructor,
            patch.object(runtime, "dispatch_request") as dispatcher,
        ):
            self.assertEqual(
                runtime.prepare_package_from_failed_request_continuation(), projection
            )
        verifier.assert_called_once_with()
        target_constructor.assert_called_once()
        preparer.assert_called_once_with(
            target=target,
            failed_request_continuation=self.continuation,
            production_observer=observer,
            package_root=runtime.PACKAGE_ROOT,
        )
        request_constructor.assert_not_called()
        dispatcher.assert_not_called()

    def test_continuation_constructor_binds_terminal_rejection_p08_repair_and_same_intent(self) -> None:
        request_root = self.root / "terminal-requests"
        first_request = self.prepare_request()
        first_request["owner_uid"] = 1
        runtime._materialize_source_owned_request(
            request=first_request,
            request_root=request_root,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
        )
        terminal_request = self.prepare_request()
        terminal_manifest = json.loads(json.dumps(self.manifest))
        terminal_manifest.pop("failed_request_continuation_storage")
        terminal_manifest.pop("source_owned_artifact_roots")
        terminal_manifest["schema"] = runtime.TERMINAL_BUNDLE_SCHEMA
        terminal_manifest["capabilities"] = runtime._runtime_capability_identity(
            terminal_predecessor=True
        )
        terminal_semantic = {
            key: terminal_manifest[key]
            for key in terminal_manifest
            if key != "bundle_id"
        }
        terminal_manifest["bundle_id"] = runtime.digest(
            runtime.TERMINAL_BUNDLE_ID_DOMAIN, terminal_semantic
        )
        terminal_manifest_sha = sha256(
            runtime.canonical(terminal_manifest)
        ).hexdigest()
        terminal_request["runtime_manifest"] = terminal_manifest
        terminal_request["runtime_manifest_sha256"] = terminal_manifest_sha
        terminal_request["expected_runtime_bundle_id"] = terminal_manifest["bundle_id"]
        terminal_request["expected_runtime_manifest_sha256"] = terminal_manifest_sha
        terminal_request["owner_uid"] = 0
        terminal_request["owner_gid"] = 0
        terminal_receipt = runtime._materialize_source_owned_request(
            request=terminal_request,
            request_root=request_root,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
        )
        collection = runtime._verify_source_owned_request_collection(
            request_root=request_root,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
        )
        evidence_root = self.root / "continuation-evidence"
        evidence_root.mkdir()
        terminal_handoff = b"synthetic terminal handoff\n"
        p08_handoff = b"synthetic p08 accepted handoff\n"
        (evidence_root / "terminal.md").write_bytes(terminal_handoff)
        (evidence_root / "p08.md").write_bytes(p08_handoff)
        rejection_sha = sha256(
            runtime.canonical(
                runtime._historical_terminal_content_free_rejection(
                    runtime.TERMINAL_REJECTION_REASON
                )
            )[:-1]
        ).hexdigest()
        contract = runtime._production_failed_request_contract()
        contract["terminal"] = {
            **contract["terminal"],
            "collection_count": 2,
            "collection_digest": collection["collection_digest"],
            "completion_sha256": terminal_receipt["completion_sha256"],
            "deploy_commit": self.manifest["source"]["deploy_commit"],
            "deploy_tree": self.manifest["source"]["deploy_tree"],
            "handoff_name": "terminal.md",
            "handoff_sha256": sha256(terminal_handoff).hexdigest(),
            "manifest_sha256": terminal_manifest_sha,
            "payload_target_owner_gid": 0,
            "payload_target_owner_uid": 0,
            "receipt_sha256": terminal_receipt["receipt_sha256"],
            "rejection_sha256": rejection_sha,
            "request_id": terminal_receipt["request_id"],
            "request_sha256": terminal_receipt["request_sha256"],
            "runtime_bundle_id": terminal_manifest["bundle_id"],
        }
        contract["p08_accepted"] = {
            **contract["p08_accepted"],
            "handoff_name": "p08.md",
            "handoff_sha256": sha256(p08_handoff).hexdigest(),
        }
        deploy_source = Path(runtime.__file__).resolve().parent.parent
        target_material = {
            "core_candidate": Path("/inactive/core"),
            "lineages": self.lineage,
            "manifest": self.manifest,
            "manifest_sha256": self.manifest_sha,
            "owner_gid": 0,
            "owner_uid": 0,
            "plugin_candidate": Path("/inactive/plugin"),
            "runtime_candidate": Path("/inactive/runtime"),
        }
        with patch.object(
            runtime, "_source_owned_target_material", return_value=target_material
        ):
            continuation = runtime._construct_failed_request_continuation(
                core_source=self.root / "core",
                deploy_source=deploy_source,
                runtime_build_root=self.root / "runtime",
                bundle_root=self.root / "bundle",
                evidence_root=evidence_root,
                request_root=request_root,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
                owner_account="root",
                contract=contract,
            )
        self.assertEqual(
            continuation["terminal_rejection"]["reason"],
            runtime.TERMINAL_REJECTION_REASON,
        )
        self.assertFalse(continuation["terminal_rejection"]["reinterpreted_as_ready"])
        self.assertTrue(continuation["fresh_p08_status_required"])
        self.assertEqual(continuation["p08_accepted"]["status"], runtime.P08_ACCEPTED_STATUS)
        self.assertEqual(continuation["request_collection"]["collection_count"], 2)
        self.assertFalse(continuation["request_collection"]["third_request_allowed"])
        status_client = continuation["target_contract"]["p08_status_client"]
        self.assertEqual(
            status_client["source_sha256"], runtime.P08_STATUS_CLIENT_SOURCE_SHA256
        )
        self.assertEqual(
            status_client["reviewed_inactive_release_digest"],
            runtime.P08_STATUS_STAGE_INACTIVE_RELEASE_DIGEST,
        )
        self.assertEqual(
            status_client["reviewed_inactive_manifest_sha256"],
            runtime.P08_STATUS_STAGE_INACTIVE_MANIFEST_SHA256,
        )
        self.assertEqual(
            status_client["reviewed_inactive_source_inventory_digest"],
            runtime.P08_STATUS_STAGE_INACTIVE_SOURCE_INVENTORY_DIGEST,
        )
        self.assertEqual(
            status_client["reviewed_future_installed_inventory_digest"],
            runtime.P08_STATUS_STAGE_FUTURE_INSTALLED_INVENTORY_DIGEST,
        )
        self.assertEqual(
            status_client["reviewed_full_inventory_digest"],
            runtime.P08_STATUS_STAGE_FULL_INVENTORY_DIGEST,
        )
        self.assertEqual(
            status_client["reviewed_inactive_controller_digest"],
            runtime.P08_STATUS_STAGE_CONTROLLER_DIGEST,
        )
        self.assertEqual(
            status_client["reviewed_inactive_strategy_digest"],
            runtime.P08_STATUS_STAGE_STRATEGY_DIGEST,
        )
        self.assertEqual(
            status_client["reviewed_inactive_deploy_commit"],
            runtime.P08_STATUS_STAGE_INACTIVE_DEPLOY_COMMIT,
        )
        self.assertEqual(
            status_client["reviewed_inactive_deploy_tree"],
            runtime.P08_STATUS_STAGE_INACTIVE_DEPLOY_TREE,
        )
        self.assertEqual(
            status_client["service_entrypoint_sha256"],
            runtime.P08_STATUS_SERVICE_ENTRYPOINT_SHA256,
        )
        self.assertEqual(
            status_client["future_unit_sha256"],
            runtime.P08_STATUS_FUTURE_UNIT_SHA256,
        )
        self.assertEqual(
            status_client["future_socket_unit_sha256"],
            runtime.P08_STATUS_FUTURE_SOCKET_UNIT_SHA256,
        )
        self.assertEqual(
            status_client["target_server_rejection_projection_sha256"],
            runtime.P08_TARGET_SERVER_REJECTION_PROJECTION_SHA256,
        )
        self.assertEqual(
            status_client["target_status_stage_projection_sha256"],
            runtime.P08_TARGET_STATUS_STAGE_PROJECTION_SHA256,
        )
        self.assertEqual(
            status_client["server_rejection_contract_identity"],
            runtime.P08_SERVER_REJECTION_CONTRACT_IDENTITY,
        )
        self.assertEqual(
            status_client["status_stage_contract_identity"],
            runtime.P08_STATUS_STAGE_CONTRACT_IDENTITY,
        )
        self.assertEqual(
            status_client["server_rejection_contract"],
            production.p08_server_rejection_contract(),
        )
        self.assertEqual(
            status_client["status_stage_contract"],
            production.p08_status_stage_contract(),
        )
        self.assertEqual(
            status_client["protocol_acceptance_contract"],
            production.p08_protocol_acceptance_contract(),
        )
        self.assertEqual(
            status_client["protocol_acceptance_contract_digest"],
            runtime.P08_PROTOCOL_ACCEPTANCE_CONTRACT_DIGEST,
        )

        drifted_contract = json.loads(json.dumps(contract))
        drifted_contract["terminal"]["request_sha256"] = "0" * 64
        with (
            patch.object(
                runtime,
                "_source_owned_target_material",
                return_value=target_material,
            ),
            self.assertRaisesRegex(RuntimeError, "terminal_identity_rejected"),
        ):
            runtime._construct_failed_request_continuation(
                core_source=self.root / "core",
                deploy_source=deploy_source,
                runtime_build_root=self.root / "runtime",
                bundle_root=self.root / "bundle",
                evidence_root=evidence_root,
                request_root=request_root,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
                owner_account="root",
                contract=drifted_contract,
            )

        current_drift = dict(target_material)
        current_drift["owner_uid"] = 1
        with (
            patch.object(
                runtime,
                "_source_owned_target_material",
                return_value=current_drift,
            ),
            self.assertRaisesRegex(RuntimeError, "intent_drifted"),
        ):
            runtime._construct_failed_request_continuation(
                core_source=self.root / "core",
                deploy_source=deploy_source,
                runtime_build_root=self.root / "runtime",
                bundle_root=self.root / "bundle",
                evidence_root=evidence_root,
                request_root=request_root,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
                owner_account="root",
                contract=contract,
            )

    def test_continuation_source_scope_is_exact_and_additive(self) -> None:
        self.assertEqual(
            runtime._allowed_continuation_source_paths(),
            {
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
            },
        )

    def test_p08_helper_service_unit_and_release_contract_are_exactly_bound(self) -> None:
        source_root = Path(runtime.__file__).resolve().parent.parent
        deploy_source = self.root / "p08-source-binding"
        paths = (
            runtime.P08_STATUS_CLIENT_SOURCE_PATH,
            production.P08_PROTOCOL_ACCEPTANCE_SOURCE_PATH,
            runtime.P08_STATUS_SERVICE_ENTRYPOINT_SOURCE_PATH,
            runtime.P08_STATUS_FUTURE_UNIT_SOURCE_PATH,
            runtime.P08_STATUS_FUTURE_SOCKET_UNIT_SOURCE_PATH,
        )
        for relative in paths:
            target = deploy_source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((source_root / relative).read_bytes())

        projection = runtime._target_contract_projection_from_manifest(
            self.manifest,
            manifest_sha256=self.manifest_sha,
            deploy_source=deploy_source,
        )["p08_status_client"]
        self.assertEqual(
            projection["source_sha256"], runtime.P08_STATUS_CLIENT_SOURCE_SHA256
        )
        self.assertEqual(
            projection["protocol_acceptance_source_sha256"],
            production.P08_PROTOCOL_ACCEPTANCE_SOURCE_SHA256,
        )
        self.assertEqual(
            projection["service_entrypoint_sha256"],
            runtime.P08_STATUS_SERVICE_ENTRYPOINT_SHA256,
        )
        self.assertEqual(
            projection["future_unit_sha256"],
            runtime.P08_STATUS_FUTURE_UNIT_SHA256,
        )
        self.assertEqual(
            projection["future_socket_unit_sha256"],
            runtime.P08_STATUS_FUTURE_SOCKET_UNIT_SHA256,
        )
        self.assertEqual(
            projection["target_server_rejection_projection_sha256"],
            runtime.P08_TARGET_SERVER_REJECTION_PROJECTION_SHA256,
        )
        self.assertEqual(
            projection["target_status_stage_projection_sha256"],
            runtime.P08_TARGET_STATUS_STAGE_PROJECTION_SHA256,
        )
        self.assertEqual(
            projection["reviewed_inactive_release_digest"],
            runtime.P08_STATUS_STAGE_INACTIVE_RELEASE_DIGEST,
        )
        self.assertEqual(
            projection["reviewed_inactive_manifest_sha256"],
            runtime.P08_STATUS_STAGE_INACTIVE_MANIFEST_SHA256,
        )
        self.assertEqual(
            projection["reviewed_full_inventory_digest"],
            runtime.P08_STATUS_STAGE_FULL_INVENTORY_DIGEST,
        )
        self.assertEqual(
            projection["reviewed_inactive_controller_digest"],
            runtime.P08_STATUS_STAGE_CONTROLLER_DIGEST,
        )
        self.assertEqual(
            projection["reviewed_inactive_strategy_digest"],
            runtime.P08_STATUS_STAGE_STRATEGY_DIGEST,
        )
        self.assertEqual(
            projection["protocol_acceptance_contract"],
            production.p08_protocol_acceptance_contract(),
        )
        self.assertEqual(
            projection["protocol_acceptance_contract_digest"],
            runtime.P08_PROTOCOL_ACCEPTANCE_CONTRACT_DIGEST,
        )

        drift_cases = (
            (
                runtime.P08_STATUS_CLIENT_SOURCE_PATH,
                "transactional_runtime_failed_request_p08_client_rejected",
            ),
            (
                production.P08_PROTOCOL_ACCEPTANCE_SOURCE_PATH,
                "transactional_runtime_failed_request_p08_protocol_source_rejected",
            ),
            (
                runtime.P08_STATUS_SERVICE_ENTRYPOINT_SOURCE_PATH,
                "transactional_runtime_failed_request_p08_service_rejected",
            ),
            (
                runtime.P08_STATUS_FUTURE_UNIT_SOURCE_PATH,
                "transactional_runtime_failed_request_p08_unit_rejected",
            ),
            (
                runtime.P08_STATUS_FUTURE_SOCKET_UNIT_SOURCE_PATH,
                "transactional_runtime_failed_request_p08_socket_unit_rejected",
            ),
        )
        for relative, code in drift_cases:
            target = deploy_source / relative
            original = target.read_bytes()
            target.write_bytes(original + b"\n")
            with self.subTest(relative=relative), self.assertRaisesRegex(
                RuntimeError, code
            ):
                runtime._target_contract_projection_from_manifest(
                    self.manifest,
                    manifest_sha256=self.manifest_sha,
                    deploy_source=deploy_source,
                )
            target.write_bytes(original)

    def test_runtime_manifest_rejects_plugin_binding_and_projection_substitution(self) -> None:
        old_runtime = json.loads(json.dumps(self.manifest))
        old_runtime.pop("runtime_artifact")
        old_semantic = {
            key: old_runtime[key] for key in old_runtime if key != "bundle_id"
        }
        old_runtime["bundle_id"] = runtime.digest(
            runtime.BUNDLE_ID_DOMAIN, old_semantic
        )
        old_digest = sha256(runtime.canonical(old_runtime)).hexdigest()
        with self.assertRaisesRegex(RuntimeError, "manifest_rejected"):
            runtime.validate_runtime_artifact_manifest(
                old_runtime,
                manifest_sha256=old_digest,
                expected_bundle_id=old_runtime["bundle_id"],
                expected_manifest_sha256=old_digest,
            )

        drifted = json.loads(json.dumps(self.manifest))
        drifted["plugin"]["target"]["release_digest"] = "0" * 64
        semantic = {key: drifted[key] for key in drifted if key != "bundle_id"}
        drifted["bundle_id"] = runtime.digest(
            runtime.BUNDLE_ID_DOMAIN, semantic
        )
        digest_value = sha256(runtime.canonical(drifted)).hexdigest()
        with self.assertRaisesRegex(RuntimeError, "plugin_binding_"):
            runtime.validate_runtime_artifact_manifest(
                drifted,
                manifest_sha256=digest_value,
                expected_bundle_id=drifted["bundle_id"],
                expected_manifest_sha256=digest_value,
            )

        source_drift = json.loads(json.dumps(self.manifest))
        source_drift["runtime_artifact"]["source"]["deploy_commit"] = "e" * 40
        runtime_semantic = {
            key: source_drift["runtime_artifact"][key]
            for key in source_drift["runtime_artifact"]
            if key != "projection_digest"
        }
        source_drift["runtime_artifact"]["projection_digest"] = (
            runtime_artifact.digest("p07_runtime_artifact_projection", runtime_semantic)
        )
        semantic = {
            key: source_drift[key] for key in source_drift if key != "bundle_id"
        }
        source_drift["bundle_id"] = runtime.digest(
            runtime.BUNDLE_ID_DOMAIN, semantic
        )
        source_digest = sha256(runtime.canonical(source_drift)).hexdigest()
        with self.assertRaisesRegex(RuntimeError, "artifact_binding_rejected"):
            runtime.validate_runtime_artifact_manifest(
                source_drift,
                manifest_sha256=source_digest,
                expected_bundle_id=source_drift["bundle_id"],
                expected_manifest_sha256=source_digest,
            )

        projection = dict(self.production_identity["plugin"])
        projection["release_digest"] = "1" * 64
        target_identity = {**self.production_identity, "plugin": projection}
        with patch.object(
            production,
            "validate_production_identity",
            return_value=target_identity,
        ), self.assertRaisesRegex(RuntimeError, "artifact_binding_rejected"):
            runtime.build_runtime_plan(
                parent_plan=self.parent_plan,
                mutation_set=self.contract,
                production_identity=target_identity,
                lineages=self.lineage,
                parent_namespace=self.parent_namespace,
                runtime_namespace=runtime.absent_runtime_namespace(),
                runtime_manifest=self.manifest,
                runtime_manifest_sha256=self.manifest_sha,
                expected_runtime_bundle_id=self.manifest["bundle_id"],
                expected_runtime_manifest_sha256=self.manifest_sha,
                prestate_services=service_projection(),
            )

        runtime_projection = json.loads(json.dumps(self.production_identity))
        runtime_projection["runtime_artifact"]["release_digest"] = "2" * 64
        semantic = {
            key: runtime_projection["runtime_artifact"][key]
            for key in runtime_projection["runtime_artifact"]
            if key != "projection_digest"
        }
        runtime_projection["runtime_artifact"]["projection_digest"] = (
            runtime_artifact.digest("p07_runtime_artifact_projection", semantic)
        )
        with patch.object(
            production,
            "validate_production_identity",
            return_value=runtime_projection,
        ), self.assertRaisesRegex(RuntimeError, "artifact_binding_rejected"):
            runtime.build_runtime_plan(
                parent_plan=self.parent_plan,
                mutation_set=self.contract,
                production_identity=runtime_projection,
                lineages=self.lineage,
                parent_namespace=self.parent_namespace,
                runtime_namespace=runtime.absent_runtime_namespace(),
                runtime_manifest=self.manifest,
                runtime_manifest_sha256=self.manifest_sha,
                expected_runtime_bundle_id=self.manifest["bundle_id"],
                expected_runtime_manifest_sha256=self.manifest_sha,
                prestate_services=service_projection(),
            )

    def test_package_is_deterministic_reopenable_and_has_exact_inventory(self) -> None:
        first_semantic = runtime._package_semantic(
            context=self.package_context, after_payloads=self.after_payloads
        )
        second_semantic = runtime._package_semantic(
            context=json.loads(runtime.canonical(self.package_context).decode("ascii")),
            after_payloads=dict(reversed(list(self.after_payloads.items()))),
        )
        self.assertEqual(runtime.canonical(first_semantic), runtime.canonical(second_semantic))
        receipt = self.ensure_package()
        verified = runtime.verify_after_payload_package(
            package_id=str(receipt["package_id"]),
            package_digest=str(receipt["package_digest"]),
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
        )
        self.assertEqual(verified.runtime_plan["plan_id"], self.runtime_plan["plan_id"])
        self.assertEqual(verified.after_payloads, self.after_payloads)
        self.assertEqual(
            sorted(path.name for path in verified.package_path.iterdir()),
            ["COMPLETE.json", "context.json", "manifest.json", "payloads", "receipt.json"],
        )
        self.assertTrue(
            all(
                (path.stat().st_mode & 0o777) == (0o700 if path.is_dir() else 0o600)
                for path in verified.package_path.rglob("*")
            )
        )

    def test_package_rejects_arbitrary_path_payload_substitution_and_extra_file(self) -> None:
        receipt = self.ensure_package()
        arbitrary = self.context(
            "backup-contract",
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
            after_payload_root="/tmp/caller-controlled",
        )
        with self.assertRaisesRegex(RuntimeError, "request_rejected"):
            runtime.dispatch_request(mode="backup-contract", request=arbitrary)
        package_path = self.package_root / str(receipt["package_id"])
        payload = next((package_path / "payloads").iterdir())
        original = payload.read_bytes()
        payload.write_bytes(b"x" * len(original))
        os.chmod(payload, 0o600)
        with self.assertRaisesRegex(RuntimeError, "payload_readback_rejected"):
            runtime.verify_after_payload_package(
                package_id=str(receipt["package_id"]),
                package_digest=str(receipt["package_digest"]),
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )

    def test_package_rejects_symlink_substitution_before_document_read(self) -> None:
        receipt = self.ensure_package()
        package_path = self.package_root / str(receipt["package_id"])
        receipt_path = package_path / "receipt.json"
        receipt_path.unlink()
        receipt_path.symlink_to(package_path / "manifest.json")
        with self.assertRaisesRegex(RuntimeError, "receipt_rejected"):
            runtime.verify_after_payload_package(
                package_id=str(receipt["package_id"]),
                package_digest=str(receipt["package_digest"]),
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )

    def test_package_rejects_hardlink_and_extra_inventory(self) -> None:
        receipt = self.ensure_package()
        package_path = self.package_root / str(receipt["package_id"])
        receipt_path = package_path / "receipt.json"
        receipt_path.unlink()
        os.link(package_path / "manifest.json", receipt_path)
        with self.assertRaisesRegex(RuntimeError, "manifest_rejected"):
            runtime.verify_after_payload_package(
                package_id=str(receipt["package_id"]),
                package_digest=str(receipt["package_digest"]),
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )

    def test_package_rejects_unmodelled_inventory(self) -> None:
        receipt = self.ensure_package()
        package_path = self.package_root / str(receipt["package_id"])
        extra = package_path / "unexpected.json"
        extra.write_text("{}", encoding="ascii")
        os.chmod(extra, 0o600)
        with self.assertRaisesRegex(RuntimeError, "package_inventory_rejected"):
            runtime.verify_after_payload_package(
                package_id=str(receipt["package_id"]),
                package_digest=str(receipt["package_digest"]),
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )

    @unittest.skipUnless(os.geteuid() == 0, "root is required for owner drift fixture")
    def test_package_rejects_uid_gid_drift(self) -> None:
        receipt = self.ensure_package()
        package_path = self.package_root / str(receipt["package_id"])
        payload = next((package_path / "payloads").iterdir())
        os.chown(payload, 1, 1)
        with self.assertRaisesRegex(RuntimeError, "payload_readback_rejected"):
            runtime.verify_after_payload_package(
                package_id=str(receipt["package_id"]),
                package_digest=str(receipt["package_digest"]),
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )

    def test_package_crash_residue_and_replay_fail_closed_at_every_stage(self) -> None:
        stages = [
            "namespace_created",
            "staging_created",
            "context_written",
            *[
                f"payload_written_{int(operation['order']):04d}"
                for operation in self.contract["operations"]
                if operation["after"]["exists"]
            ],
            "manifest_written",
            "receipt_written",
            "completion_written",
            "finalized",
        ]
        for index, stage in enumerate(stages):
            with self.subTest(stage=stage):
                package_root = self.root / f"crash-packages-{index}"
                material, context = self.package_fixture(package_root)

                def crash(current: str, *, target: str = stage) -> None:
                    if current == target:
                        raise RuntimeError("synthetic_package_crash")

                with patch.object(runtime, "PACKAGE_ROOT", package_root):
                    with self.assertRaisesRegex(RuntimeError, "synthetic_package_crash"):
                        runtime.materialize_after_payload_package(
                            context=context,
                            after_payloads=material.after_payloads,
                            owner_uid=os.getuid(),
                            owner_gid=os.getgid(),
                            stage_hook=crash,
                        )
                    with self.assertRaisesRegex(RuntimeError, "namespace_preexisting"):
                        runtime.materialize_after_payload_package(
                            context=context,
                            after_payloads=material.after_payloads,
                            owner_uid=os.getuid(),
                            owner_gid=os.getgid(),
                        )

    def test_package_bounds_role_and_metadata_drift_fail_closed(self) -> None:
        with patch.object(runtime, "MAX_PACKAGE_PAYLOAD_BYTES", 0):
            with self.assertRaisesRegex(RuntimeError, "payload_bound_rejected"):
                runtime._package_semantic(
                    context=self.package_context, after_payloads=self.after_payloads
                )
        missing = dict(self.after_payloads)
        missing.pop(next(iter(missing)))
        with self.assertRaisesRegex(RuntimeError, "payload_set_rejected"):
            runtime._package_semantic(
                context=self.package_context, after_payloads=missing
            )
        extra = {**self.after_payloads, "unmodelled:payload": b"synthetic"}
        with self.assertRaisesRegex(RuntimeError, "payload_bound_rejected"):
            runtime._package_semantic(
                context=self.package_context, after_payloads=extra
            )
        drifted_plan = json.loads(json.dumps(self.runtime_plan))
        drifted_plan["production_identity"]["path_roles"]["files"] = []
        with self.assertRaisesRegex(RuntimeError, "package_role_rejected"):
            runtime._package_operation_entries(
                runtime_plan=drifted_plan,
                mutation_set=self.contract,
                after_payloads=self.after_payloads,
            )
        receipt = self.ensure_package()
        package_path = self.package_root / str(receipt["package_id"])
        payload = next((package_path / "payloads").iterdir())
        with patch.object(runtime, "_has_extended_acl", return_value=True):
            with self.assertRaisesRegex(RuntimeError, "package_root_rejected"):
                runtime.verify_after_payload_package(
                    package_id=str(receipt["package_id"]),
                    package_digest=str(receipt["package_digest"]),
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
        os.chmod(payload, 0o640)
        with self.assertRaisesRegex(RuntimeError, "payload_readback_rejected"):
            runtime.verify_after_payload_package(
                package_id=str(receipt["package_id"]),
                package_digest=str(receipt["package_digest"]),
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )

    def test_old_failed_start_namespace_cannot_be_substituted_or_reused(self) -> None:
        parent.FUTURE_STATE_ROOT.mkdir()
        request = {
            "core_candidate": "/inactive/core",
            "expected_runtime_bundle_id": self.manifest["bundle_id"],
            "expected_runtime_manifest_sha256": self.manifest_sha,
            "lineages": self.lineage,
            "mode": "prepare-package",
            "owner_gid": os.getgid(),
            "owner_uid": os.getuid(),
            "plugin_candidate": "/inactive/plugin",
            "runtime_candidate": "/inactive/runtime",
            "runtime_manifest": self.manifest,
            "runtime_manifest_sha256": self.manifest_sha,
            "schema": runtime.REQUEST_SCHEMA,
        }
        def construct(**_kwargs: object) -> runtime.ProductionRuntimeMaterial:
            runtime.observe_parent_failed_start_namespace()
            raise AssertionError("unreachable")

        with patch.object(
            runtime, "construct_production_runtime_material", side_effect=construct
        ):
            with self.assertRaisesRegex(RuntimeError, "future_namespace_preexisting"):
                runtime.dispatch_request(
                    mode="prepare-package",
                    request=request,
                    package_root=self.package_root,
                    failed_request_continuation=self.continuation,
                )

    def test_backup_ledger_are_non_overwriting_and_max_one(self) -> None:
        self.create_backup_and_ledger()
        package = self.ensure_package()
        ledger = runtime.verify_ledger_root(
            plan=self.runtime_plan,
            state_root=self.state_root,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
            package_id=str(package["package_id"]),
            package_digest=str(package["package_digest"]),
            allow_runtime_files=False,
        )
        self.assertEqual((ledger["attempts"], ledger["maximum_attempts"]), (0, 1))
        with self.assertRaisesRegex(RuntimeError, "backup_or_state_preexisting"):
            runtime.dispatch_request(
                mode="backup-contract",
                request=self.context(
                    "backup-contract", owner_uid=os.getuid(), owner_gid=os.getgid()
                ),
            )
        (self.state_root / "ATTEMPT-9999.json").write_text("{}", encoding="ascii")
        with self.assertRaisesRegex(RuntimeError, "state_inventory_rejected"):
            runtime.verify_ledger_root(
                plan=self.runtime_plan,
                state_root=self.state_root,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
                package_id=str(package["package_id"]),
                package_digest=str(package["package_digest"]),
                allow_runtime_files=True,
            )

    def test_formal_preflight_is_deterministic_and_content_free(self) -> None:
        self.create_backup_and_ledger()
        runner = FakeRunner()
        request = self.context(
            "preflight-only", owner_uid=os.getuid(), owner_gid=os.getgid()
        )
        first = runtime.dispatch_request(mode="preflight-only", request=request, runner=runner)
        second = runtime.dispatch_request(mode="preflight-only", request=request, runner=runner)
        self.assertEqual(runtime.canonical(first), runtime.canonical(second))
        self.assertEqual(
            (first["status"], first["attempts"], first["next_attempt"], first["maximum_attempts"]),
            ("ready", 0, 1, 1),
        )
        self.assertEqual(first["flags"], runtime._ZERO_FLAGS)
        runner.services["core"]["nrestarts"] = 1
        with self.assertRaisesRegex(RuntimeError, "service_drifted"):
            runtime.dispatch_request(mode="preflight-only", request=request, runner=runner)

    def test_activation_orders_commands_and_consumes_exactly_once(self) -> None:
        self.create_backup_and_ledger()
        runner = FakeRunner()
        preflight_request = self.context(
            "preflight-only", owner_uid=os.getuid(), owner_gid=os.getgid()
        )
        first = runtime.dispatch_request(
            mode="preflight-only", request=preflight_request, runner=runner
        )
        second = runtime.dispatch_request(
            mode="preflight-only", request=preflight_request, runner=runner
        )
        runner.commands.clear()
        receipt = runtime.dispatch_request(
            mode="activate",
            request=self.context(
                "activate",
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
                preflight_one=first,
                preflight_two=second,
            ),
            runner=runner,
        )
        self.assertEqual(receipt["status"], "activated")
        stop = runner.commands.index(
            (
                runtime.SYSTEMCTL,
                "stop",
                runtime.TELEGRAM_SOCKET,
                runtime.TELEGRAM_UNIT,
                runtime.CORE_UNIT,
            )
        )
        reload = runner.commands.index((runtime.SYSTEMCTL, "daemon-reload"))
        core = runner.commands.index((runtime.SYSTEMCTL, "start", runtime.CORE_UNIT))
        telegram = runner.commands.index(
            (runtime.PYTHON, "-B", runtime.TELEGRAM_RESUME_CONTROLLER)
        )
        self.assertLess(stop, reload)
        self.assertLess(reload, core)
        self.assertLess(core, telegram)
        postflight = runtime.dispatch_request(
            mode="postflight",
            request=self.context("postflight", owner_uid=os.getuid(), owner_gid=os.getgid()),
            runner=runner,
        )
        self.assertEqual((postflight["status"], postflight["attempts"]), ("activated", 1))
        with self.assertRaisesRegex(RuntimeError, "attempt_exhausted"):
            runtime.dispatch_request(
                mode="activate",
                request=self.context(
                    "activate",
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                    preflight_one=first,
                    preflight_two=second,
                ),
                runner=runner,
            )

    def test_pre_attempt_failure_is_not_reported_as_rollback_verified(self) -> None:
        self.create_backup_and_ledger()
        runner = FakeRunner()
        preflight_request = self.context(
            "preflight-only", owner_uid=os.getuid(), owner_gid=os.getgid()
        )
        preflight = runtime.dispatch_request(
            mode="preflight-only", request=preflight_request, runner=runner
        )
        with patch.object(
            runtime.PreparedRuntimeBackend,
            "create_backup",
            side_effect=parent.TransactionalControllerRejected("synthetic_backup_failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "pre_attempt_failed"):
                runtime.dispatch_request(
                    mode="activate",
                    request=self.context(
                        "activate",
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                        preflight_one=preflight,
                        preflight_two=preflight,
                    ),
                    runner=runner,
                )
        receipt = json.loads(
            (
                self.state_root / f"RECEIPT-{self.runtime_plan['plan_id']}.json"
            ).read_text(encoding="ascii")
        )
        self.assertEqual(receipt["status"], "pre_attempt_failed")
        self.assertEqual(receipt["journal_projection"]["attempts"], 0)

    def test_post_attempt_failure_runs_one_exact_rollback(self) -> None:
        self.create_backup_and_ledger()
        runner = FakeRunner()
        preflight_request = self.context(
            "preflight-only", owner_uid=os.getuid(), owner_gid=os.getgid()
        )
        preflight = runtime.dispatch_request(
            mode="preflight-only", request=preflight_request, runner=runner
        )
        core_start = (runtime.SYSTEMCTL, "start", runtime.CORE_UNIT)
        runner.fail_counts[core_start] = 1
        with self.assertRaisesRegex(
            RuntimeError, "activation_failed_rollback_verified"
        ) as captured:
            runtime.dispatch_request(
                mode="activate",
                request=self.context(
                    "activate",
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                    preflight_one=preflight,
                    preflight_two=preflight,
                ),
                runner=runner,
            )
        legacy_envelope = runtime._runtime_rejection_projection(captured.exception)
        self.assertEqual(
            legacy_envelope["strategy_context_status"], "legacy_verified"
        )
        self.assertEqual(legacy_envelope["strategy_id"], runtime.STRATEGY_ID)
        self.assertEqual(
            legacy_envelope["strategy_digest"],
            runtime._verified_legacy_rejection_strategy_context(
                runtime._legacy_strategy_contract()
            ).strategy_digest,
        )
        receipt = json.loads(
            (
                self.state_root / f"RECEIPT-{self.runtime_plan['plan_id']}.json"
            ).read_text(encoding="ascii")
        )
        self.assertEqual(receipt["status"], "failed_rollback_verified")
        self.assertEqual(receipt["journal_projection"]["rollback_invocations"], 1)
        self.assertEqual(receipt["journal_projection"]["recovery_class"], "rolled_back")
        self.assertFalse((self.root / "protected-archive").exists())
        mutation.require_prestate(self.contract)
        postflight = runtime.dispatch_request(
            mode="postflight",
            request=self.context("postflight", owner_uid=os.getuid(), owner_gid=os.getgid()),
            runner=runner,
        )
        self.assertEqual(postflight["status"], "failed_rollback_verified")

    def test_rollback_failure_preserves_both_typed_causes(self) -> None:
        self.create_backup_and_ledger()
        runner = FakeRunner()
        preflight = runtime.dispatch_request(
            mode="preflight-only",
            request=self.context(
                "preflight-only", owner_uid=os.getuid(), owner_gid=os.getgid()
            ),
            runner=runner,
        )
        runner.fail_counts[(runtime.SYSTEMCTL, "start", runtime.CORE_UNIT)] = 2
        with self.assertRaises(runtime.TransactionalRuntimeRejected) as captured:
            runtime.dispatch_request(
                mode="activate",
                request=self.context(
                    "activate",
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                    preflight_one=preflight,
                    preflight_two=preflight,
                ),
                runner=runner,
            )
        self.assertEqual(captured.exception.code, "transactional_runtime_rollback_failed")
        self.assertIsNotNone(captured.exception.activation_failure_code)
        self.assertIsNotNone(captured.exception.rollback_failure_code)
        receipt = json.loads(
            (
                self.state_root / f"RECEIPT-{self.runtime_plan['plan_id']}.json"
            ).read_text(encoding="ascii")
        )
        self.assertEqual(receipt["status"], "rollback_failed")
        self.assertIsNotNone(receipt["activation_failure_code"])
        self.assertIsNotNone(receipt["rollback_failure_code"])

    def test_command_runner_rejects_legacy_or_unbound_commands(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "command_not_allowlisted"):
            runtime.SubprocessCommandRunner().run(
                (runtime.PYTHON, "-B", "activate_p07_owner_private_memory_v1.py"),
                timeout=1,
            )
        source = Path(runtime.__file__).read_text(encoding="utf-8")
        self.assertNotIn("subprocess.run([", source)
        self.assertNotIn("activate_p07_owner_private_memory_v1.py", source)
        self.assertNotIn("activate_p07_owner_private_memory_dual_state_recovery_v2.py", source)

    def test_cli_rejection_is_typed_and_content_free(self) -> None:
        output = io.StringIO()
        with (
            patch.object(
                sys,
                "argv",
                [
                    "p07_owner_private_memory_transactional_runtime.py",
                    "--mode",
                    "offline-self-test",
                    "--request",
                    "/not/allowed.json",
                ],
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(runtime.main(), 2)
        projection = json.loads(output.getvalue())
        self.assertEqual(projection["status"], "rejected")
        self.assertEqual(
            projection["reason_code"], "transactional_runtime_request_rejected"
        )
        self.assertEqual(projection["flags"], runtime._ZERO_FLAGS)
        self.assertEqual(projection["strategy_context_status"], "unavailable")
        self.assertNotIn("strategy_id", projection)
        self.assertNotIn("strategy_digest", projection)

    def test_cli_canonicalizes_production_plan_rejection_without_ready_fallback(self) -> None:
        output = io.StringIO()
        with (
            patch.object(
                sys,
                "argv",
                [
                    "p07_owner_private_memory_transactional_runtime.py",
                    "--mode",
                    "prepare-package",
                    "--request",
                    "/fixed/request.json",
                ],
            ),
            patch.object(runtime, "_canonical_read", return_value={}),
            patch.object(
                runtime,
                "dispatch_request",
                side_effect=production.ProductionPlanRejected(
                    "production_p08_content_free_status_unavailable"
                ),
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(runtime.main(), 2)
        projection = json.loads(output.getvalue())
        self.assertEqual(projection["status"], "rejected")
        self.assertEqual(
            projection["reason_code"],
            "production_p08_content_free_status_unavailable",
        )
        self.assertEqual(projection["flags"], runtime._ZERO_FLAGS)
        self.assertIsNone(projection["activation_failure_code"])
        self.assertIsNone(projection["rollback_failure_code"])
        self.assertEqual(projection["strategy_context_status"], "unavailable")
        self.assertNotIn("strategy_id", projection)
        self.assertNotIn("strategy_digest", projection)
        self.assertNotIn("p08_status_stage_projection", projection)
        self.assertNotIn("p08_status_stage_projection_digest", projection)

    def test_cli_binds_exact_content_free_p08_stage_without_changing_rejection(self) -> None:
        status_rejection = runtime.p08_gateway.ContentFreeStatusRejection.from_stage(
            "transport_timeout", invocation_nonce="a" * 64
        )
        gateway_error = runtime.p08_gateway.TemporalGatewayRejected(
            "temporal_status_unavailable",
            retryable=True,
            status_stage=status_rejection.stage,
            status_rejection=status_rejection,
        )
        stage_projection = production.p08_status_stage_projection(gateway_error)
        self.assertIsNotNone(stage_projection)
        rejected = production.ProductionPlanRejected(
            "production_p08_content_free_status_unavailable",
            p08_status_stage_projection=stage_projection,
        )
        expected_projection, expected_digest = runtime._p08_status_stage_evidence(
            rejected
        )
        output = io.StringIO()
        with (
            patch.object(
                sys,
                "argv",
                [
                    "p07_owner_private_memory_transactional_runtime.py",
                    "--mode",
                    "prepare-package",
                    "--request",
                    "/fixed/request.json",
                ],
            ),
            patch.object(runtime, "_canonical_read", return_value={}),
            patch.object(runtime, "dispatch_request", side_effect=rejected) as dispatch,
            redirect_stdout(output),
        ):
            self.assertEqual(runtime.main(), 2)
        projection = json.loads(output.getvalue())
        self.assertEqual(projection["status"], "rejected")
        self.assertEqual(
            projection["reason_code"],
            "production_p08_content_free_status_unavailable",
        )
        self.assertEqual(projection["flags"], runtime._ZERO_FLAGS)
        self.assertEqual(
            projection["p08_status_stage_projection"], expected_projection
        )
        self.assertEqual(
            projection["p08_status_stage_projection_digest"], expected_digest
        )
        self.assertFalse(projection["p08_status_stage_projection"]["persistent_mutation"])
        dispatch.assert_called_once_with(mode="prepare-package", request={})

    def test_p08_stage_evidence_drift_is_generic_and_never_claims_stage(self) -> None:
        status_rejection = runtime.p08_gateway.ContentFreeStatusRejection.from_stage(
            "parent_timeout", invocation_nonce="b" * 64
        )
        gateway_error = runtime.p08_gateway.TemporalGatewayRejected(
            "temporal_status_unavailable",
            retryable=True,
            status_stage=status_rejection.stage,
            status_rejection=status_rejection,
        )
        exact = production.p08_status_stage_projection(gateway_error)
        self.assertIsNotNone(exact)
        drifted = (
            {**exact, "unexpected": False},
            {**exact, "schema": "myuna.mixed.v1"},
            {**exact, "stage": "unsupported_stage"},
            {**exact, "invocation_nonce": "c" * 64},
            {**exact, "retryable": 1},
            {**exact, "projection_digest": "0" * 64},
        )
        for payload in drifted:
            with self.subTest(payload=payload):
                rejected = production.ProductionPlanRejected(
                    "production_p08_content_free_status_unavailable",
                    p08_status_stage_projection=payload,
                )
                self.assertEqual(
                    runtime._p08_status_stage_evidence(rejected), (None, None)
                )
                receipt = runtime._runtime_rejection_projection(rejected)
                self.assertEqual(
                    receipt["reason_code"],
                    "production_p08_content_free_status_unavailable",
                )
                self.assertNotIn("p08_status_stage_projection", receipt)
                self.assertNotIn("p08_status_stage_projection_digest", receipt)

        wrong_reason = production.ProductionPlanRejected(
            "production_source_identity_rejected",
            p08_status_stage_projection=exact,
        )
        self.assertEqual(
            runtime._p08_status_stage_evidence(wrong_reason), (None, None)
        )

    def test_rejection_envelope_requires_exact_verified_strategy_context(self) -> None:
        generic = runtime._content_free_rejection("production_source_identity_rejected")
        self.assertEqual(generic["strategy_context_status"], "unavailable")
        self.assertNotIn("strategy_id", generic)
        self.assertNotIn("strategy_digest", generic)

        legacy = runtime._verified_legacy_rejection_strategy_context(
            runtime._legacy_strategy_contract()
        )
        legacy_projection = runtime._content_free_rejection(
            "transactional_runtime_request_rejected", strategy_context=legacy
        )
        self.assertEqual(legacy_projection["strategy_context_status"], "legacy_verified")
        self.assertEqual(legacy_projection["strategy_id"], runtime.STRATEGY_ID)
        self.assertEqual(legacy_projection["strategy_digest"], legacy.strategy_digest)

        strategy = self.fresh_strategy()
        fresh = self.fresh_rejection_context(strategy)
        fresh_projection = runtime._content_free_rejection(
            "production_p08_content_free_status_unavailable",
            strategy_context=fresh,
        )
        self.assertEqual(fresh_projection["strategy_context_status"], "fresh_verified")
        self.assertEqual(fresh_projection["strategy_id"], strategy["strategy_id"])
        self.assertEqual(fresh_projection["strategy_digest"], strategy["strategy_digest"])

        malformed = runtime._VerifiedRejectionStrategyContext(
            context_digest="0" * 64,
            context_kind="fresh",
            source_id=runtime.SOURCE_ID,
            strategy_digest=strategy["strategy_digest"],
            strategy_id=strategy["strategy_id"],
            strategy_schema=runtime.FRESH_STRATEGY_SCHEMA,
        )
        for bad_context in (None, {}, malformed, object()):
            with self.subTest(context=type(bad_context).__name__):
                projection = runtime._content_free_rejection(
                    "transactional_runtime_request_rejected",
                    strategy_context=bad_context,
                )
                self.assertEqual(projection["strategy_context_status"], "unavailable")
                self.assertNotIn("strategy_id", projection)
                self.assertNotIn("strategy_digest", projection)

        for code in (
            "transactional_runtime_source_identity_rejected",
            "transactional_runtime_manifest_rejected",
            "transactional_runtime_status_invocation_parent_rejected",
            "transactional_runtime_status_invocation_permission_rejected",
        ):
            projection = runtime._runtime_rejection_projection(
                runtime.TransactionalRuntimeRejected(code)
            )
            self.assertEqual(projection["strategy_context_status"], "unavailable")

        substituted = runtime.TransactionalRuntimeRejected(
            "transactional_runtime_request_rejected"
        )
        setattr(
            substituted,
            runtime._REJECTION_STRATEGY_CONTEXT_ATTRIBUTE,
            {"strategy_id": strategy["strategy_id"]},
        )
        projection = runtime._runtime_rejection_projection(substituted)
        self.assertEqual(projection["strategy_context_status"], "unavailable")
        self.assertNotIn("strategy_id", projection)

        conflict = runtime.TransactionalRuntimeRejected(
            "transactional_runtime_request_rejected"
        )
        runtime._attach_rejection_strategy_context(conflict, fresh)
        runtime._attach_rejection_strategy_context(conflict, legacy)
        projection = runtime._runtime_rejection_projection(conflict)
        self.assertEqual(projection["strategy_context_status"], "unavailable")
        self.assertNotIn("strategy_id", projection)

    def test_rejection_strategy_context_rejects_fresh_and_legacy_substitution(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "rejection_strategy_context_rejected"):
            runtime._verified_legacy_rejection_strategy_context(
                {**runtime._legacy_strategy_contract(), "maximum_attempts": 2}
            )
        strategy = self.fresh_strategy()
        drifted = json.loads(json.dumps(strategy))
        drifted["strategy_digest"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "fresh_strategy_rejected"):
            self.fresh_rejection_context(drifted)
        with self.assertRaisesRegex(RuntimeError, "rejection_strategy_context_rejected"):
            runtime.SourceOwnedStatusEvidenceObserver(
                strategy=drifted,
                rejection_context=self.fresh_rejection_context(strategy),
                trusted_ancestor=self.fresh_status_ancestor,
                status_parent=self.fresh_status_parent,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
                helper=lambda _config: self.accepted_p08_status(),
                source_nonce="0" * 64,
            )

    def test_construct_request_cli_accepts_no_caller_identity_or_request(self) -> None:
        projection = {
            "constructor_source_id": runtime.REQUEST_CONSTRUCTOR_SOURCE_ID,
            "flags": dict(runtime._ZERO_FLAGS),
            "request_id": "1" * 64,
            "request_path": "/fixed/request.json",
            "request_sha256": "2" * 64,
            "schema": runtime.REQUEST_CONSTRUCTOR_RECEIPT_SCHEMA,
            "status": "verified",
        }
        output = io.StringIO()
        with (
            patch.object(
                sys,
                "argv",
                [
                    "p07_owner_private_memory_transactional_runtime.py",
                    "--mode",
                    "construct-request",
                ],
            ),
            patch.object(
                runtime, "materialize_source_owned_request", return_value=projection
            ) as constructor,
            redirect_stdout(output),
        ):
            self.assertEqual(runtime.main(), 0)
        self.assertEqual(json.loads(output.getvalue()), projection)
        constructor.assert_called_once_with()

        rejected = io.StringIO()
        with (
            patch.object(
                sys,
                "argv",
                [
                    "p07_owner_private_memory_transactional_runtime.py",
                    "--mode",
                    "construct-request",
                    "--request",
                    "/caller/substitution.json",
                ],
            ),
            patch.object(runtime, "materialize_source_owned_request") as constructor,
            redirect_stdout(rejected),
        ):
            self.assertEqual(runtime.main(), 2)
        self.assertEqual(
            json.loads(rejected.getvalue())["reason_code"],
            "transactional_runtime_request_rejected",
        )
        constructor.assert_not_called()

    def test_unknown_request_field_and_preflight_drift_fail_closed(self) -> None:
        request = self.context(
            "preflight-only",
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
            unexpected=True,
        )
        with self.assertRaisesRegex(RuntimeError, "request_rejected"):
            runtime.dispatch_request(mode="preflight-only", request=request, runner=FakeRunner())
        self.create_backup_and_ledger()
        runner = FakeRunner()
        valid = runtime.dispatch_request(
            mode="preflight-only",
            request=self.context(
                "preflight-only", owner_uid=os.getuid(), owner_gid=os.getgid()
            ),
            runner=runner,
        )
        drifted = json.loads(json.dumps(valid))
        drifted["next_attempt"] = 2
        with self.assertRaisesRegex(RuntimeError, "preflight_rejected"):
            runtime.execute_activation(
                runtime_plan=self.runtime_plan,
                mutation_set=self.contract,
                preflight_one=valid,
                preflight_two=drifted,
                after_payloads=self.after_payloads,
                package_id=str(self.ensure_package()["package_id"]),
                package_digest=str(self.ensure_package()["package_digest"]),
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
                runner=runner,
            )

    def accepted_p08_status(
        self,
    ) -> runtime.p08_gateway.ContentFreeTemporalGatewayStatus:
        return runtime.p08_gateway.ContentFreeTemporalGatewayStatus(
            active_fact_count=2,
            active_set_digest="1" * 64,
            lifecycle_digest="2" * 64,
            lifecycle_event_count=3,
            lifecycle_watermark=4,
            pending_proposal_count=0,
            request_nonce="3" * 64,
            response_digest="4" * 64,
            scope_binding_digest="5" * 64,
            source_identity="6" * 64,
            status_digest="7" * 64,
            total_fact_count=2,
            trusted_time_binding_digest="8" * 64,
        )

    def fresh_strategy(self) -> dict[str, object]:
        return runtime.build_fresh_strategy_contract(
            runtime_manifest=self.manifest,
            runtime_manifest_sha256=self.manifest_sha,
            lineages=self.lineage,
            continuation_reference=runtime.immutable_continuation_reference_contract(),
        )

    def fresh_rejection_context(
        self, strategy: Mapping[str, object] | None = None
    ) -> object:
        selected = self.fresh_strategy() if strategy is None else strategy
        return runtime._verified_fresh_rejection_strategy_context(
            selected,
            runtime_manifest=self.manifest,
            runtime_manifest_sha256=self.manifest_sha,
            lineages=self.lineage,
            continuation_reference=runtime.immutable_continuation_reference_contract(),
        )

    def synthetic_immutable_reference(
        self,
    ) -> tuple[dict[str, object], Path, Path]:
        request_root = self.root / "synthetic-request-collection"
        first = self.prepare_request()
        first["owner_uid"] = 4242
        first["owner_gid"] = 4343
        second = json.loads(json.dumps(first))
        second["core_candidate"] = "/inactive/core-sibling"
        runtime._materialize_source_owned_request(
            request=first,
            request_root=request_root,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
            maximum_count=2,
        )
        runtime._materialize_source_owned_request(
            request=second,
            request_root=request_root,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
            maximum_count=2,
        )
        collection = runtime._verify_source_owned_request_collection(
            request_root=request_root,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
        )
        evidence_root = self.root / "synthetic-evidence"
        evidence_root.mkdir(mode=0o700)
        handoff_name = "synthetic-terminal-handoff.md"
        handoff_bytes = b"synthetic content-free terminal handoff\n"
        (evidence_root / handoff_name).write_bytes(handoff_bytes)
        child = self.continuation_root / self.continuation["continuation_id"]

        def directory(path: Path) -> dict[str, object]:
            metadata = path.lstat()
            return {
                "gid": metadata.st_gid,
                "mode": metadata.st_mode & 0o7777,
                "nlink": metadata.st_nlink,
                "type": "directory",
                "uid": metadata.st_uid,
            }

        request_children = {}
        for request_id in sorted(path.name for path in request_root.iterdir()):
            request_child = request_root / request_id
            request_children[request_id] = {
                "directory": directory(request_child),
                "files": {
                    name: runtime._fixed_path_identity(request_child / name)
                    for name in (
                        "completion.json",
                        "receipt.json",
                        "request.json",
                    )
                },
            }
        request_collection = {
            "children": request_children,
            "closed": True,
            "collection_count": 2,
            "collection_digest": collection["collection_digest"],
            "payload_target_owner": {
                "gid": 4343,
                "role": "terminal_request_payload_target_runtime_owner",
                "uid": 4242,
            },
            "root": directory(request_root),
            "schema": runtime.HISTORICAL_REQUEST_EVIDENCE_STORAGE_SCHEMA,
            "source_id": runtime.HISTORICAL_REQUEST_EVIDENCE_STORAGE_SOURCE_ID,
            "storage_owner": {
                "gid": os.getgid(),
                "role": "immutable_historical_request_evidence_storage_owner",
                "uid": os.getuid(),
            },
            "storage_role": "immutable_historical_request_evidence_collection",
            "terminal_request_id": sorted(request_children)[1],
            "third_request_allowed": False,
        }
        semantic = {
            "continuation": {
                "child": directory(child),
                "continuation_id": self.continuation["continuation_id"],
                "files": {
                    name: runtime._fixed_path_identity(child / name)
                    for name in (
                        "completion.json",
                        "continuation.json",
                        "receipt.json",
                    )
                },
                "parent": directory(self.continuation_parent),
                "root": directory(self.continuation_root),
            },
            "historical_target": {"deploy_commit": "9" * 40},
            "lineages": {
                "combined_verifier_digest": runtime.IMMUTABLE_LINEAGE_EVIDENCE_DIGEST,
                "dual_state_v2": "1/1",
                "p07_policy_overlay_v1": "2/2",
            },
            "request_collection": request_collection,
            "schema": runtime.IMMUTABLE_CONTINUATION_REFERENCE_SCHEMA,
            "source_id": runtime.IMMUTABLE_CONTINUATION_REFERENCE_SOURCE_ID,
            "terminal_t2": {
                "handoff_name": handoff_name,
                "handoff_sha256": sha256(handoff_bytes).hexdigest(),
                "p08_rejection_payload_sha256": "a" * 64,
                "p08_rejection_stdout_sha256": "b" * 64,
                "reason": runtime.TERMINAL_REJECTION_REASON,
                "reinterpreted_as_ready": False,
                "status": "synthetic_terminal",
            },
        }
        reference = {
            **semantic,
            "reference_digest": runtime.digest(
                "p07_immutable_continuation_reference_v3", semantic
            ),
        }
        return reference, request_root, evidence_root

    def fresh_package_fixture(
        self,
    ) -> tuple[dict[str, object], dict[str, object], Path]:
        strategy = self.fresh_strategy()
        runtime.observe_fresh_strategy_namespace(strategy)
        status = self.accepted_p08_status()
        observer = runtime.SourceOwnedStatusEvidenceObserver(
            strategy=strategy,
            rejection_context=self.fresh_rejection_context(strategy),
            trusted_ancestor=self.fresh_status_ancestor,
            status_parent=self.fresh_status_parent,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
            helper=lambda _config: status,
            source_nonce="9" * 64,
        )
        self.assertEqual(observer._p08_status(object()), status)
        status_evidence = observer.completed_evidence()
        fresh_prestate = public_prestate()
        fresh_prestate["p08_status"] = status.projection()
        source = self.manifest["source"]
        fresh_parent_plan = parent.build_plan(
            core_commit=runtime.CORE_SOURCE_COMMIT,
            deploy_commit=source["deploy_commit"],
            deploy_tree=source["deploy_tree"],
            artifact_identities={
                "controller_bundle_id": runtime.PARENT_CONTROLLER_BUNDLE_ID,
                "full_mutation_bundle_id": parent.FULL_MUTATION_BUNDLE_ID,
                "full_mutation_manifest_sha256": parent.FULL_MUTATION_MANIFEST_SHA256,
            },
            lineages=self.lineage,
            public_prestate=fresh_prestate,
            boundaries=boundaries(),
            policy=policy(),
            mutation_set=self.contract,
            mutation_coverage=coverage(self.contract, self.root),
            root_transitions=root_transitions(self.root),
            namespace=self.parent_namespace,
            state_root=Path(strategy["storage"]["state_root"]),
            backup_root=Path(strategy["storage"]["backup_root"]),
        )
        runtime_plan = runtime.build_runtime_plan(
            parent_plan=fresh_parent_plan,
            mutation_set=self.contract,
            production_identity=self.production_identity,
            lineages=self.lineage,
            parent_namespace=self.parent_namespace,
            runtime_namespace=runtime.absent_runtime_namespace(),
            runtime_manifest=self.manifest,
            runtime_manifest_sha256=self.manifest_sha,
            expected_runtime_bundle_id=self.manifest["bundle_id"],
            expected_runtime_manifest_sha256=self.manifest_sha,
            prestate_services=service_projection(),
            fresh_strategy=strategy,
            continuation_reference=runtime.immutable_continuation_reference_contract(),
            status_invocation_evidence=status_evidence,
        )
        material = runtime.ProductionRuntimeMaterial(
            runtime_plan=runtime_plan,
            mutation_set=self.contract,
            before_payloads={},
            after_payloads=self.after_payloads,
        )
        context = runtime._package_context(
            material=material,
            lineages=self.lineage,
            parent_namespace=self.parent_namespace,
            runtime_manifest=self.manifest,
            runtime_manifest_sha256=self.manifest_sha,
            expected_runtime_bundle_id=self.manifest["bundle_id"],
            expected_runtime_manifest_sha256=self.manifest_sha,
            immutable_continuation_reference=(
                runtime.immutable_continuation_reference_contract()
            ),
            fresh_strategy=strategy,
        )
        package_root = Path(strategy["storage"]["package_root"])
        receipt = runtime.materialize_after_payload_package(
            context=context,
            after_payloads=self.after_payloads,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
            package_root=package_root,
        )
        return runtime_plan, receipt, package_root

    def test_immutable_continuation_reference_is_read_only_and_target_independent(self) -> None:
        reference, request_root, evidence_root = self.synthetic_immutable_reference()
        verified = runtime._verify_immutable_continuation_reference(
            reference=reference,
            continuation_parent=self.continuation_parent,
            continuation_root=self.continuation_root,
            request_root=request_root,
            evidence_root=evidence_root,
        )
        self.assertEqual(verified["status"], "verified_read_only")
        self.assertFalse(verified["reinterpreted_as_ready"])
        self.assertNotEqual(
            reference["historical_target"]["deploy_commit"],
            self.manifest["source"]["deploy_commit"],
        )
        self.assertEqual(
            runtime._verify_source_owned_request_collection(
                request_root=request_root,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )["collection_count"],
            2,
        )
        continuation_file = (
            self.continuation_root
            / self.continuation["continuation_id"]
            / "continuation.json"
        )
        continuation_file.chmod(0o640)
        with self.assertRaisesRegex(RuntimeError, "immutable_continuation_reference"):
            runtime._verify_immutable_continuation_reference(
                reference=reference,
                continuation_parent=self.continuation_parent,
                continuation_root=self.continuation_root,
                request_root=request_root,
                evidence_root=evidence_root,
            )

    def test_production_historical_request_evidence_contract_separates_owner_roles(self) -> None:
        storage = runtime.historical_request_evidence_storage_contract()
        self.assertEqual(
            storage["storage_owner"],
            {
                "gid": 0,
                "role": "immutable_historical_request_evidence_storage_owner",
                "uid": 0,
            },
        )
        self.assertEqual(
            storage["payload_target_owner"],
            {
                "gid": 989,
                "role": "terminal_request_payload_target_runtime_owner",
                "uid": 999,
            },
        )
        self.assertNotIn("owner_uid", storage)
        self.assertNotIn("owner_gid", storage)
        self.assertEqual(storage["root"]["mode"], 0o700)
        self.assertEqual(storage["root"]["nlink"], 4)
        self.assertEqual(
            set(storage["children"]),
            {
                runtime.HISTORICAL_REQUEST_EVIDENCE_FIRST_ID,
                runtime.TERMINAL_REQUEST_ID,
            },
        )
        expected = {
            runtime.HISTORICAL_REQUEST_EVIDENCE_FIRST_ID: {
                "completion.json": (
                    416,
                    "0b97bdbbd660e05e330c90fd1e80faf36aec3cc1ef543d51003b9d6d122d6b86",
                ),
                "receipt.json": (
                    668,
                    "1ae934520c820e8cac53019e14bd06310c3bf56727b375a049a9a69225dfd93d",
                ),
                "request.json": (
                    15523,
                    "e81bc41a62c24ebd8fd0da05d8b79d906dd259406ae0e5a3c618afd4d678a3ef",
                ),
            },
            runtime.TERMINAL_REQUEST_ID: {
                "completion.json": (416, runtime.TERMINAL_REQUEST_COMPLETION_SHA256),
                "receipt.json": (668, runtime.TERMINAL_REQUEST_RECEIPT_SHA256),
                "request.json": (15585, runtime.TERMINAL_REQUEST_SHA256),
            },
        }
        for request_id, files in expected.items():
            self.assertEqual(
                storage["children"][request_id]["directory"],
                {"gid": 0, "mode": 0o700, "nlink": 2, "type": "directory", "uid": 0},
            )
            for name, (size, digest_value) in files.items():
                self.assertEqual(
                    storage["children"][request_id]["files"][name],
                    {
                        "gid": 0,
                        "mode": 0o600,
                        "nlink": 1,
                        "sha256": digest_value,
                        "size": size,
                        "type": "regular",
                        "uid": 0,
                    },
                )
        self.assertEqual(storage["collection_count"], 2)
        self.assertEqual(
            storage["collection_digest"],
            runtime.TERMINAL_REQUEST_COLLECTION_DIGEST,
        )
        self.assertTrue(storage["closed"])
        self.assertFalse(storage["third_request_allowed"])
        self.assertEqual(
            runtime._validate_historical_request_evidence_storage_contract(
                storage, require_production_exact=True
            ),
            storage,
        )

    def test_production_historical_storage_owner_substitution_is_rejected(self) -> None:
        for uid, gid in ((999, 989), (1234, 5678)):
            storage = runtime.historical_request_evidence_storage_contract()
            storage["storage_owner"]["uid"] = uid
            storage["storage_owner"]["gid"] = gid
            storage["root"]["uid"] = uid
            storage["root"]["gid"] = gid
            for child in storage["children"].values():
                child["directory"]["uid"] = uid
                child["directory"]["gid"] = gid
                for file_identity in child["files"].values():
                    file_identity["uid"] = uid
                    file_identity["gid"] = gid
            with self.assertRaisesRegex(RuntimeError, "historical_request_evidence"):
                runtime._validate_historical_request_evidence_storage_contract(
                    storage, require_production_exact=True
                )

    def test_production_historical_inventory_drift_matrix_is_rejected(self) -> None:
        first_id = runtime.HISTORICAL_REQUEST_EVIDENCE_FIRST_ID
        drifts = {}

        changed = runtime.historical_request_evidence_storage_contract()
        changed["root"]["type"] = "symlink"
        drifts["root-type"] = changed

        changed = runtime.historical_request_evidence_storage_contract()
        changed["root"]["mode"] = 0o750
        drifts["root-mode"] = changed

        changed = runtime.historical_request_evidence_storage_contract()
        changed["children"][first_id]["directory"]["nlink"] = 3
        drifts["child-link"] = changed

        changed = runtime.historical_request_evidence_storage_contract()
        changed["children"][first_id]["files"]["request.json"]["size"] += 1
        drifts["file-size"] = changed

        changed = runtime.historical_request_evidence_storage_contract()
        changed["children"][first_id]["files"]["request.json"]["sha256"] = "0" * 64
        drifts["file-hash"] = changed

        changed = runtime.historical_request_evidence_storage_contract()
        changed["children"][first_id]["files"]["request.json"]["type"] = "symlink"
        drifts["file-type"] = changed

        changed = runtime.historical_request_evidence_storage_contract()
        changed["children"][first_id]["files"]["request.json"]["nlink"] = 2
        drifts["hardlink"] = changed

        changed = runtime.historical_request_evidence_storage_contract()
        child = changed["children"].pop(first_id)
        changed["children"]["f" * 64] = child
        drifts["child-name"] = changed

        changed = runtime.historical_request_evidence_storage_contract()
        changed["collection_count"] = 3
        drifts["count"] = changed

        changed = runtime.historical_request_evidence_storage_contract()
        changed["children"][".partial.tmp"] = json.loads(
            json.dumps(changed["children"][first_id])
        )
        drifts["temp-extra"] = changed

        for name, storage in drifts.items():
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    RuntimeError, "historical_request_evidence"
                ):
                    runtime._validate_historical_request_evidence_storage_contract(
                        storage, require_production_exact=True
                    )

    def test_payload_target_owner_cannot_be_reused_as_storage_owner(self) -> None:
        reference, request_root, evidence_root = self.synthetic_immutable_reference()
        drifted = json.loads(json.dumps(reference))
        drifted["request_collection"]["payload_target_owner"]["uid"] = os.getuid()
        drifted["request_collection"]["payload_target_owner"]["gid"] = os.getgid()
        semantic = {
            key: drifted[key] for key in drifted if key != "reference_digest"
        }
        drifted["reference_digest"] = runtime.digest(
            "p07_immutable_continuation_reference_v3", semantic
        )
        with self.assertRaisesRegex(RuntimeError, "immutable_continuation_reference"):
            runtime._verify_immutable_continuation_reference(
                reference=drifted,
                continuation_parent=self.continuation_parent,
                continuation_root=self.continuation_root,
                request_root=request_root,
                evidence_root=evidence_root,
            )

    def test_fresh_strategy_is_source_derived_nonresetting_max_one(self) -> None:
        first = self.fresh_strategy()
        second = self.fresh_strategy()
        self.assertEqual(runtime.canonical(first), runtime.canonical(second))
        self.assertEqual(first["maximum_attempts"], 1)
        self.assertEqual(first["predecessor_attempts"]["p07_policy_overlay_v1"], "2/2")
        self.assertEqual(first["predecessor_attempts"]["dual_state_v2"], "1/1")
        self.assertEqual(
            first["predecessor_attempts"]["terminal_continuation_t2"],
            "terminal_before_attempt",
        )
        self.assertNotEqual(first["strategy_id"], runtime.STRATEGY_ID)
        self.assertEqual(
            first["continuation_reference_digest"],
            runtime.immutable_continuation_reference_contract()["reference_digest"],
        )
        runtime.observe_fresh_strategy_namespace(first)
        drifted = json.loads(json.dumps(first))
        drifted["maximum_attempts"] = 2
        with self.assertRaisesRegex(RuntimeError, "fresh_strategy_rejected"):
            runtime.validate_fresh_strategy_contract(
                drifted,
                runtime_manifest=self.manifest,
                runtime_manifest_sha256=self.manifest_sha,
                lineages=self.lineage,
                continuation_reference=runtime.immutable_continuation_reference_contract(),
            )

    def test_status_invocation_is_append_only_single_call_and_content_free(self) -> None:
        strategy = self.fresh_strategy()
        status = self.accepted_p08_status()
        observer = runtime.SourceOwnedStatusEvidenceObserver(
            strategy=strategy,
            rejection_context=self.fresh_rejection_context(strategy),
            trusted_ancestor=self.fresh_status_ancestor,
            status_parent=self.fresh_status_parent,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
            helper=lambda _config: status,
            source_nonce="a" * 64,
        )
        self.assertEqual(observer._p08_status(object()), status)
        evidence = observer.completed_evidence()
        self.assertEqual(evidence["status"], "accepted")
        with self.assertRaisesRegex(RuntimeError, "replay_rejected"):
            observer._p08_status(object())
        child = Path(strategy["storage"]["status_invocation_root"]) / evidence[
            "invocation_id"
        ]
        intent = json.loads((child / "intent.json").read_text(encoding="ascii"))
        helper = intent["helper"]
        self.assertEqual(
            helper["helper_source_sha256"], runtime.P08_STATUS_CLIENT_SOURCE_SHA256
        )
        self.assertEqual(
            helper["protocol_acceptance_contract_digest"],
            runtime.P08_PROTOCOL_ACCEPTANCE_CONTRACT_DIGEST,
        )
        protocol_evidence = helper["protocol_acceptance_evidence"]
        self.assertEqual(protocol_evidence["helper_calls"], 1)
        self.assertFalse(protocol_evidence["raw_error_stream_retained"])
        self.assertFalse(protocol_evidence["retry_or_fallback"])
        self.assertEqual(
            protocol_evidence["source_sha256"],
            production.P08_PROTOCOL_ACCEPTANCE_SOURCE_SHA256,
        )
        self.assertEqual(
            helper["inactive_deploy_commit"],
            runtime.P08_STATUS_STAGE_INACTIVE_DEPLOY_COMMIT,
        )
        self.assertEqual(
            helper["inactive_strategy_digest"],
            runtime.P08_STATUS_STAGE_STRATEGY_DIGEST,
        )
        serialized = b"".join(
            (child / name).read_bytes()
            for name in ("intent.json", "result.json", "completion.json")
        ).decode("ascii")
        for forbidden in (
            "exception",
            "stderr",
            "stdout",
            "private_text",
            "temporal_text",
            "provider_payload",
            "channel_content",
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertIn('"credential_value_read":false', serialized)

    def test_all_p08_stages_are_allowlisted_and_malformed_rejection_stays_partial(self) -> None:
        strategy = self.fresh_strategy()
        rejection_context = self.fresh_rejection_context(strategy)
        intent = runtime._status_invocation_intent(
            strategy=strategy, source_nonce="b" * 64
        )
        for stage in production.p08_status_stage_contract()["stage_policy"]:
            projection = runtime.p08_gateway.ContentFreeStatusRejection.from_stage(
                stage, invocation_nonce="c" * 64
            ).projection()
            result = runtime._status_result_projection(
                intent=intent, status="rejected", rejected=projection
            )
            self.assertEqual(result["status"], "rejected")
            self.assertFalse(result["rejected_projection"]["persistent_mutation"])
            rejected = production.ProductionPlanRejected(
                "production_p08_content_free_status_unavailable",
                p08_status_stage_projection=projection,
            )
            runtime._attach_rejection_strategy_context(rejected, rejection_context)
            envelope = runtime._runtime_rejection_projection(rejected)
            self.assertEqual(envelope["strategy_context_status"], "fresh_verified")
            self.assertEqual(envelope["strategy_id"], strategy["strategy_id"])
            self.assertEqual(envelope["strategy_digest"], strategy["strategy_digest"])
            self.assertEqual(envelope["p08_status_stage_projection"]["stage"], stage)

        def malformed(_config: object) -> runtime.p08_gateway.ContentFreeTemporalGatewayStatus:
            raise production.ProductionPlanRejected(
                "production_p08_content_free_status_unavailable"
            )

        observer = runtime.SourceOwnedStatusEvidenceObserver(
            strategy=strategy,
            rejection_context=self.fresh_rejection_context(strategy),
            trusted_ancestor=self.fresh_status_ancestor,
            status_parent=self.fresh_status_parent,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
            helper=malformed,
            source_nonce="d" * 64,
        )
        with self.assertRaisesRegex(RuntimeError, "unclassified_rejected"):
            observer._p08_status(object())
        root = Path(strategy["storage"]["status_invocation_root"])
        child = next(root.iterdir())
        self.assertEqual(sorted(path.name for path in child.iterdir()), ["intent.json"])
        with self.assertRaisesRegex(RuntimeError, "namespace_rejected"):
            runtime._begin_status_invocation(
                strategy=strategy,
                trusted_ancestor=self.fresh_status_ancestor,
                status_parent=self.fresh_status_parent,
                status_root=root,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
                source_nonce="e" * 64,
            )

    def test_fresh_package_preflight_activation_and_rollback_bind_strategy(self) -> None:
        plan, receipt, package_root = self.fresh_package_fixture()

        def request(mode: str, **extra: object) -> dict[str, object]:
            return {
                "mode": mode,
                "owner_gid": os.getgid(),
                "owner_uid": os.getuid(),
                "package_digest": receipt["package_digest"],
                "package_id": receipt["package_id"],
                "schema": runtime.REQUEST_SCHEMA,
                **extra,
            }

        runtime.dispatch_request(
            mode="backup-contract",
            request=request("backup-contract"),
            package_root=package_root,
        )
        ledger = runtime.dispatch_request(
            mode="ledger-create",
            request=request("ledger-create"),
            package_root=package_root,
        )
        self.assertEqual(ledger["strategy_id"], plan["strategy"]["strategy_id"])
        runner = FakeRunner()
        first = runtime.dispatch_request(
            mode="preflight-only",
            request=request("preflight-only"),
            package_root=package_root,
            runner=runner,
        )
        second = runtime.dispatch_request(
            mode="preflight-only",
            request=request("preflight-only"),
            package_root=package_root,
            runner=runner,
        )
        self.assertEqual(runtime.canonical(first), runtime.canonical(second))
        runner.fail_counts[(runtime.SYSTEMCTL, "start", runtime.CORE_UNIT)] = 1
        with self.assertRaisesRegex(
            RuntimeError, "activation_failed_rollback_verified"
        ) as captured:
            runtime.dispatch_request(
                mode="activate",
                request=request(
                    "activate", preflight_one=first, preflight_two=second
                ),
                package_root=package_root,
                runner=runner,
            )
        fresh_envelope = runtime._runtime_rejection_projection(captured.exception)
        self.assertEqual(fresh_envelope["strategy_context_status"], "fresh_verified")
        self.assertEqual(fresh_envelope["strategy_id"], plan["strategy"]["strategy_id"])
        self.assertEqual(
            fresh_envelope["strategy_digest"], plan["strategy"]["strategy_digest"]
        )
        ledger_path = Path(plan["storage"]["state_root"]) / "ATTEMPT_LEDGER.json"
        consumed = json.loads(ledger_path.read_text(encoding="ascii"))
        self.assertEqual(consumed["attempts"], 1)
        self.assertEqual(consumed["maximum_attempts"], 1)
        self.assertEqual(consumed["strategy_id"], plan["strategy"]["strategy_id"])
        mutation.require_prestate(self.contract)

    def test_rejected_status_seals_only_allowlisted_stage_and_blocks_retry(self) -> None:
        strategy = self.fresh_strategy()
        rejection = runtime.p08_gateway.ContentFreeStatusRejection.from_stage(
            "transport_connect", invocation_nonce="e" * 64
        ).projection()

        def rejected(_config: object) -> runtime.p08_gateway.ContentFreeTemporalGatewayStatus:
            raise production.ProductionPlanRejected(
                "production_p08_content_free_status_unavailable",
                p08_status_stage_projection=rejection,
            )

        observer = runtime.SourceOwnedStatusEvidenceObserver(
            strategy=strategy,
            rejection_context=self.fresh_rejection_context(strategy),
            trusted_ancestor=self.fresh_status_ancestor,
            status_parent=self.fresh_status_parent,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
            helper=rejected,
            source_nonce="f" * 64,
        )
        with self.assertRaisesRegex(
            RuntimeError, "p08_content_free_status_unavailable"
        ) as captured:
            observer._p08_status(object())
        envelope = runtime._runtime_rejection_projection(captured.exception)
        self.assertEqual(envelope["strategy_context_status"], "fresh_verified")
        self.assertEqual(envelope["strategy_id"], strategy["strategy_id"])
        self.assertEqual(envelope["strategy_digest"], strategy["strategy_digest"])
        evidence = runtime._verify_status_invocation_evidence(
            strategy=strategy,
            status_parent=self.fresh_status_parent,
            status_root=Path(strategy["storage"]["status_invocation_root"]),
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
        )
        self.assertEqual(evidence["status"], "rejected")
        self.assertEqual(evidence["strategy_id"], envelope["strategy_id"])
        intent_path = (
            Path(strategy["storage"]["status_invocation_root"])
            / evidence["invocation_id"]
            / "intent.json"
        )
        durable_intent = json.loads(intent_path.read_text(encoding="ascii"))
        self.assertEqual(durable_intent["strategy_id"], envelope["strategy_id"])
        self.assertEqual(durable_intent["strategy_digest"], envelope["strategy_digest"])
        self.assertEqual(
            evidence["stage_projection_digest"],
            runtime.digest("p07_status_invocation_rejected_projection", rejection),
        )
        self.assertFalse(Path(strategy["storage"]["package_root"]).exists())
        self.assertFalse(Path(strategy["storage"]["state_root"]).exists())
        self.assertFalse(Path(strategy["storage"]["backup_root"]).exists())

    def test_status_invocation_crash_boundaries_and_concurrent_writer_fail_closed(self) -> None:
        for index, stage in enumerate(
            ("parent_created", "root_created", "child_created", "intent_written")
        ):
            ancestor = self.root / f"crash-ancestor-{index}"
            ancestor.mkdir(mode=0o700)
            parent_path = ancestor / "status-parent"
            with patch.object(runtime, "FRESH_STATUS_PARENT", parent_path):
                strategy = self.fresh_strategy()

                def crash(observed: str, *, expected: str = stage) -> None:
                    if observed == expected:
                        raise RuntimeError("synthetic_crash")

                with self.assertRaisesRegex(RuntimeError, "synthetic_crash"):
                    runtime._begin_status_invocation(
                        strategy=strategy,
                        trusted_ancestor=ancestor,
                        status_parent=parent_path,
                        status_root=Path(
                            strategy["storage"]["status_invocation_root"]
                        ),
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                        source_nonce=f"{index + 1:064x}",
                        crash_hook=crash,
                    )
                with self.assertRaisesRegex(RuntimeError, "namespace_rejected"):
                    runtime._begin_status_invocation(
                        strategy=strategy,
                        trusted_ancestor=ancestor,
                        status_parent=parent_path,
                        status_root=Path(
                            strategy["storage"]["status_invocation_root"]
                        ),
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                        source_nonce=f"{index + 20:064x}",
                    )

        ancestor = self.root / "race-ancestor"
        ancestor.mkdir(mode=0o700)
        parent_path = ancestor / "status-parent"
        with patch.object(runtime, "FRESH_STATUS_PARENT", parent_path):
            strategy = self.fresh_strategy()
            barrier = threading.Barrier(2)
            outcomes: list[str] = []

            def writer(nonce: str) -> None:
                barrier.wait()
                try:
                    runtime._begin_status_invocation(
                        strategy=strategy,
                        trusted_ancestor=ancestor,
                        status_parent=parent_path,
                        status_root=Path(
                            strategy["storage"]["status_invocation_root"]
                        ),
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                        source_nonce=nonce,
                    )
                except runtime.TransactionalRuntimeRejected:
                    outcomes.append("rejected")
                else:
                    outcomes.append("accepted")

            threads = [
                threading.Thread(target=writer, args=("a" * 64,)),
                threading.Thread(target=writer, args=("b" * 64,)),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(sorted(outcomes), ["accepted", "rejected"])

    def test_source_first_sqlite_platform_probe_is_bounded_and_closes(self) -> None:
        self.archive_root.mkdir(mode=0o700)
        self.archive_root.chmod(0o700)
        arguments = {
            "expected_uid": os.getuid(),
            "expected_gid": os.getgid(),
            "database_name": production.FACTUAL_DATABASE_NAME,
            "journal_name": production.FACTUAL_JOURNAL_NAME,
        }
        descriptors: list[int] = []
        original_descriptor = runtime._probe_connection_descriptor

        def capture_descriptor(before, after, identity):
            descriptor = original_descriptor(before, after, identity)
            descriptors.append(descriptor)
            return descriptor

        with patch.object(
            runtime,
            "_probe_connection_descriptor",
            side_effect=capture_descriptor,
        ):
            projection = runtime._verify_source_first_sqlite_platform(
                self.archive_root,
                **arguments,
            )
        self.assertEqual(len(descriptors), 1)
        with self.assertRaises(FileNotFoundError):
            os.stat(f"/proc/self/fd/{descriptors[0]}")
        self.assertEqual(
            projection,
            {
                "closed_before_return": True,
                "database_identity_verified": True,
                "journal_mode": "persist",
                "journal_namespace_verified": True,
                "residue_count": 0,
                "synchronous": 2,
            },
        )
        self.assertEqual(list(self.archive_root.iterdir()), [])
        for stage in (
            "before_commit",
            "after_commit_before_verification",
            "after_verification_before_cleanup",
        ):
            with self.assertRaises(runtime.TransactionalRuntimeRejected):
                runtime._verify_source_first_sqlite_platform(
                    self.archive_root,
                    fault_stage=stage,
                    **arguments,
                )
            self.assertEqual(list(self.archive_root.iterdir()), [])
        self.archive_root.chmod(0o750)
        with self.assertRaisesRegex(
            runtime.TransactionalRuntimeRejected,
            "sqlite_probe_root_rejected",
        ):
            runtime._verify_source_first_sqlite_platform(
                self.archive_root,
                **arguments,
            )

    def test_source_first_probe_descriptor_is_connection_specific(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = root / "expected.sqlite3"
            other = root / "other.sqlite3"
            expected_connection = sqlite3.connect(expected)
            expected_connection.close()
            other_connection = sqlite3.connect(other)
            other_connection.close()
            expected.chmod(0o600)
            other.chmod(0o600)
            held_expected = os.open(expected, os.O_RDONLY)
            try:
                before = runtime._probe_fd_inventory()
                connection = sqlite3.connect(other, isolation_level=None)
                try:
                    with self.assertRaisesRegex(
                        runtime.TransactionalRuntimeRejected,
                        "connection_identity_ambiguous",
                    ):
                        runtime._probe_connection_descriptor(
                            before,
                            runtime._probe_fd_inventory(),
                            runtime._probe_identity(expected),
                        )
                finally:
                    connection.close()
            finally:
                os.close(held_expected)

            before = runtime._probe_fd_inventory()
            connection = sqlite3.connect(expected, isolation_level=None)
            descriptor = runtime._probe_connection_descriptor(
                before,
                runtime._probe_fd_inventory(),
                runtime._probe_identity(expected),
            )
            self.assertEqual(
                runtime._probe_descriptor_identity(descriptor),
                runtime._probe_identity(expected),
            )
            connection.close()
            with self.assertRaises(FileNotFoundError):
                os.stat(f"/proc/self/fd/{descriptor}")

    def test_production_platform_hook_precedes_reload_and_is_not_postflight_audit(self) -> None:
        self.archive_root.mkdir(mode=0o700)
        self.archive_root.chmod(0o700)
        runner = FakeRunner()
        hooks = runtime.ContentSafeProductionHooks(
            runtime_plan=self.runtime_plan,
            mutation_set=self.contract,
            runner=runner,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
            preflight_sha256="a" * 64,
            package_id="b" * 64,
            package_digest="c" * 64,
        )
        with patch.object(runtime, "_verify_inventory"), patch.object(
            parent, "verify_root_transitions"
        ), patch.object(
            runtime,
            "_verify_source_first_sqlite_platform",
            wraps=runtime._verify_source_first_sqlite_platform,
        ) as platform:
            hooks.stop_target_services()
            hooks.verify_target_services_stopped()
            hooks.verify_target_semantics()
            self.assertNotIn(
                (runtime.SYSTEMCTL, "daemon-reload"),
                runner.commands,
            )
            hooks.daemon_reload()
            platform.assert_called_once_with(
                self.archive_root,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
                database_name=production.FACTUAL_DATABASE_NAME,
                journal_name=production.FACTUAL_JOURNAL_NAME,
            )
            with patch.object(hooks, "_verify_target_files"), patch.object(
                runtime,
                "observe_services",
                return_value=self.runtime_plan["services"]["target"],
            ):
                hooks.verify_target()
            self.assertEqual(platform.call_count, 1)
        self.assertEqual(list(self.archive_root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
