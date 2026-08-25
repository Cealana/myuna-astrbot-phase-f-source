from __future__ import annotations

import base64
from dataclasses import replace
import copy
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, SCRIPTS.as_posix())
MODULE_PATH = SCRIPTS / "activate_p07_owner_private_memory_v1.py"
SPEC = importlib.util.spec_from_file_location(
    "activate_p07_owner_private_memory_v1",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)
product = module.product


def authority(seed: int = 19001) -> dict[str, object]:
    files: dict[str, object] = {}
    for index, path in enumerate(sorted(product.FILE_ROLES)):
        if path == product.MEMORY_SELECTOR_PATH:
            memory_release_set_id = f"{seed:016x}" + "3" * 48
            archive_id = (
                "p07-owner-private-memory-transactional-"
                + memory_release_set_id[:16]
            )
            payload = product.canonical(
                {
                    "archive_id": archive_id,
                    "calendar_zone": "Asia/Shanghai",
                    "calendar_zone_config_digest": "1" * 64,
                    "channel_kind": "telegram",
                    "client_id": "telegram-owner-runtime",
                    "diary_coupled": False,
                    "egress_policy_digest": "2" * 64,
                    "egress_policy_mode": "historical_raw_recall_v1",
                    "expected_gid": product.MEMORY_RUNTIME_GID,
                    "expected_uid": product.MEMORY_RUNTIME_UID,
                    "memory_release_set_id": memory_release_set_id,
                    "no_old_data_migration": True,
                    "p15_handoff_schema": "myuna.p15-handoff.v1",
                    "p15_projection_active": False,
                    "p08_lifecycle_start_watermark": (
                        product.P08_LIFECYCLE_START_WATERMARK
                    ),
                    "parent_epoch_id": product.PARENT_EPOCH_ID,
                    "parent_epoch_revision": product.PARENT_EPOCH_REVISION,
                    "parent_manifest_digest": product.PARENT_MANIFEST_SHA256,
                    "parent_release_set_id": product.PARENT_RELEASE_SET_ID,
                    "parent_selector_digest": product.PARENT_SELECTOR_SHA256,
                    "policy_overlay_id": "4" * 64,
                    "prompt_owner": "telegram-owner-runtime",
                    "runtime_root": f"{product.MEMORY_RUNTIME_ROOT}/{archive_id}",
                    "schema": "myuna.p07-owner-private-memory-selector.v4",
                    "status": "active",
                    "summary_used": False,
                }
            )
        else:
            payload = f"target:{seed}:{index}:{path}\n".encode("ascii")
        role, mode = product.FILE_ROLES[path]
        files[path] = {
            "gid": 0,
            "mode": mode,
            "owner": product.FILE_OWNERS[path],
            "payload_b64": base64.b64encode(payload).decode("ascii"),
            "payload_sha256": sha256(payload).hexdigest(),
            "role": role,
            "uid": 0,
        }
    def release(key: str, digest: str, root: str) -> dict[str, object]:
        members = [{"path": "payload", "sha256": digest, "size": 1}]
        return {
            "bundle_prefix": f"staging/releases/{key}/{digest}",
            "digest": digest,
            "directory_mode": "0550",
            "file_mode": "0440",
            "members": members,
            "member_set_sha256": product.release_member_set_sha256(members),
            "receipt_sha256": sha256(f"receipt:{key}".encode()).hexdigest(),
            "root": root,
        }
    image_receipt = {
        "archive_sha256": "e" * 64,
        "archive_size": 1,
        "image_id": "sha256:" + "f" * 64,
        "image_reference": product.TARGET_IMAGE_PREFIX + "f" * 64,
        "layers": [{"diff_id": "sha256:" + "d" * 64}],
        "manifest_digest": "sha256:" + "f" * 64,
        "platform": {"architecture": "amd64", "os": "linux"},
    }
    return product.validate_source_authority({
        "builder": {
            "astrbot_commit": product.ACCEPTED_ASTRBOT_COMMIT,
            "astrbot_tree": "a" * 40,
            "base_image_digest": "sha256:7546bddf1040419a455dd1ca683a5e9cf84436bbd85de17c7ac626d3af7affe4",
            "gateway_builder_blob": product.GATEWAY_BUILDER_BLOB,
            "hybrid_builder_blob": product.HYBRID_BUILDER_BLOB,
            "runtime_base_digest": product.ACCEPTED_RUNTIME_BASE,
            "runtime_base_member_set_sha256": "b" * 64,
            "tool_set_sha256": "c" * 64,
        },
        "controller": {
            "config_sha256": files[
                "/etc/myuna-telegram-gateway/r5-resume-v1.json"
            ]["payload_sha256"],
            "member_set_sha256": "2" * 64,
            "source_receipt_sha256": "3" * 64,
        },
        "files": files,
        "image": {
            "archive_members": [{"path": "staging/image/" + "e" * 64 + ".part-000000", "sha256": "d" * 64, "size": 1}],
            "archive_sha256": "e" * 64,
            "archive_size": 1,
            "digest": "f" * 64,
            "member_set_sha256": product.image_member_set_sha256(image_receipt),
            "receipt": image_receipt,
            "receipt_sha256": sha256(product.canonical(image_receipt)).hexdigest(),
            "reference": product.TARGET_IMAGE_PREFIX + "f" * 64,
        },
        "parent": {
            "epoch_id": product.PARENT_EPOCH_ID,
            "epoch_revision": product.PARENT_EPOCH_REVISION,
            "lifecycle_start_watermark": product.P08_LIFECYCLE_START_WATERMARK,
            "manifest_sha256": product.PARENT_MANIFEST_SHA256,
            "release_set_id": product.PARENT_RELEASE_SET_ID,
            "selector_sha256": product.PARENT_SELECTOR_SHA256,
        },
        "releases": {
            "core": release("core", "6" * 64, product.CORE_RELEASE_ROOT),
            "plugin": release("plugin", "9" * 64, product.PLUGIN_RELEASE_ROOT),
            "runtime": release("runtime", "c" * 64, product.RUNTIME_RELEASE_ROOT),
        },
        "schema": product.SOURCE_SCHEMA,
        "source": {
            "core_commit": product.ACCEPTED_CORE_COMMIT,
            "core_tree": product.ACCEPTED_CORE_TREE,
            "deploy_commit": "f" * 40,
            "deploy_parent": product.ACCEPTED_DEPLOY_PARENT,
            "deploy_tree": "1" * 40,
        },
    })


def observation(
    selected: dict[str, object],
    *,
    files_old: bool = False,
    third_path: str | None = None,
    target_policy: str = "absent",
    target_active: bool = False,
    selected_present: bool = False,
) -> tuple[dict[str, object], dict[str, str | None], dict[str, bytes | None]]:
    files: dict[str, object] = {}
    old_hashes: dict[str, str | None] = {}
    old_payloads: dict[str, bytes | None] = {}
    absent = {
        "/etc/systemd/system/myuna-core@qq.service.d/90-p07-owner-private-memory-v1.conf",
        "/etc/myuna-telegram-gateway/p07-owner-private-memory-selector-v4.json",
    }
    for index, path in enumerate(sorted(product.FILE_ROLES)):
        target = selected["files"][path]
        if files_old and path in absent:
            files[path] = {
                "gid": None,
                "identity": None,
                "kind": "absent",
                "mode": None,
                "payload_b64": None,
                "sha256": None,
                "uid": None,
            }
            old_hashes[path] = None
            old_payloads[path] = None
            continue
        old_payload = f"old:{index}:{path}\n".encode("ascii")
        old_hashes[path] = sha256(old_payload).hexdigest()
        old_payloads[path] = old_payload
        if path == third_path:
            payload = b"third-state\n"
        elif files_old:
            payload = old_payload
        else:
            payload = base64.b64decode(target["payload_b64"])
        files[path] = {
            "gid": 0,
            "identity": sha256(path.encode()).hexdigest(),
            "kind": "regular",
            "mode": product.FILE_ROLES[path][1],
            "payload_b64": base64.b64encode(payload).decode("ascii"),
            "sha256": sha256(payload).hexdigest(),
            "uid": 0,
        }
    target_present = target_policy != "absent" or target_active
    selected_root = product.selected_memory_runtime(
        product.validate_source_authority(selected)
    )
    return (
        {
            "archive_name": {
                "identity": None,
                "name": product.ARCHIVE_PREFIX
                + product.validate_source_authority(selected)["authority_sha256"][:16],
                "projection_sha256": None,
                "state": "OLD",
            },
            "archive_root": {
                "handle_count": 0,
                "identity": "parent-root",
                "legacy_identity": "legacy-empty-root",
                "legacy_name": product.LEGACY_MEMORY_ARCHIVE_ID,
                "path": product.MEMORY_RUNTIME_ROOT,
                "selected_identity": (
                    "selected-empty-root" if selected_present else None
                ),
                "selected_name": selected_root["archive_id"],
                "selected_state": "TARGET" if selected_present else "OLD",
                "state": "TARGET",
            },
            "files": files,
            "network": {
                "identity": "network-object",
                "member_ids": ["old-object"],
                "name": product.NETWORK_NAME,
                "projection_sha256": "8" * 64,
                "state": "TARGET",
            },
            "old_container": {
                "active": True,
                "identity": "old-object",
                "name": product.CONTAINER_NAME,
                "policy": "on-failure:3",
                "state": "TARGET" if not target_present else "THIRD_STATE",
            },
            "parent": {
                "manifest_sha256": product.PARENT_MANIFEST_SHA256,
                "selector_sha256": product.PARENT_SELECTOR_SHA256,
                "state": "TARGET",
            },
            "releases": {
                key: {
                    "identity": (
                        selected["image"]["member_set_sha256"]
                        if key == "image"
                        else selected["releases"][key]["member_set_sha256"]
                    ),
                    "state": "TARGET",
                }
                for key in ("core", "image", "plugin", "runtime")
            },
            "schema": product.OBSERVATION_SCHEMA,
            "services": {
                key: {"active": True, "identity": unit + "-identity"}
                for key, unit in (
                    ("core", module.CORE_SERVICE),
                    ("runtime", module.RUNTIME_SERVICE),
                    ("socket", module.RUNTIME_SOCKET),
                )
            },
            "target_container": {
                "active": target_active,
                "identity": "target-object" if target_present else None,
                "name": product.CONTAINER_NAME,
                "policy": target_policy,
                "state": "TARGET" if target_present else "OLD",
            },
        },
        old_hashes,
        old_payloads,
    )


class FixedEffects:
    def __init__(
        self,
        selected: dict[str, object],
        old_payloads: dict[str, bytes | None],
        initial_observation: dict[str, object],
    ) -> None:
        self.selected = selected
        self.initial_observation = copy.deepcopy(initial_observation)
        self.files = dict(old_payloads)
        self.services = {
            module.CORE_SERVICE: True,
            module.RUNTIME_SOCKET: True,
            module.RUNTIME_SERVICE: True,
        }
        self.old_active = True
        self.old_archived = False
        self.target_exists = False
        self.target_active = False
        self.target_policy = "absent"
        self.selected_root_exists = (
            initial_observation["archive_root"]["selected_state"] == "TARGET"
        )
        self.selected_root_identity = "selected-empty-root"
        self.selected_entries = False
        self.private_handles = 0
        self.activate_runtime_on_socket_start = False
        product.ATTEMPT5_OLD_CONTAINER_ID = "old-object"
        product.ATTEMPT5_OLD_CONTAINER_NETWORKS_SHA256 = "old-networks-digest"
        product.ATTEMPT5_OLD_CONTAINER_CONFIGURATION_SHA256 = product.digest(
            "phase_f_attempt5_old_container_configuration",
            {
                "command_digest": "old-command-digest",
                "host_config_digest": "old-host-config-digest",
                "image": "old-image",
                "mounts_digest": "old-mounts-digest",
                "network_names": [product.NETWORK_NAME],
                "networks_digest": "old-networks-digest",
                "plan_digest": "",
                "policy": "on-failure:3",
                "project": "old-project",
                "service": "old-service",
                "target_config_digest": "",
                "user": "988:982",
            },
        )
        self.entry_on_socket_start = False
        self.handle_on_socket_start = False
        self.calls: list[str] = []
        self.fail_start = False
        self.fail_reload_once = False
        self.drift_service_identity = False
        self.fail_install_once = False
        self.fail_archive_once = False
        self.fail_create_once = False

    def file_observation(self, path: Path) -> dict[str, object]:
        payload = self.files[path.as_posix()]
        if payload is None:
            return {
                "gid": None,
                "identity": None,
                "kind": "absent",
                "mode": None,
                "payload_b64": None,
                "sha256": None,
                "uid": None,
            }
        return {
            "gid": 0,
            "identity": sha256(path.as_posix().encode()).hexdigest(),
            "kind": "regular",
            "mode": product.FILE_ROLES[path.as_posix()][1],
            "payload_b64": base64.b64encode(payload).decode("ascii"),
            "sha256": sha256(payload).hexdigest(),
            "uid": 0,
        }

    def install_file(self, path: str, row: dict[str, object]) -> None:
        self.calls.append("install:" + path)
        self.files[path] = base64.b64decode(row["payload_b64"])
        if self.fail_install_once:
            self.fail_install_once = False
            raise module.MemoryActivationRejected("injected_install_lost_return")

    def remove_file(self, path: str) -> None:
        self.calls.append("remove:" + path)
        self.files[path] = None

    def service_observation(self, unit: str) -> dict[str, object]:
        return {
            "active": self.services[unit],
            "identity": (
                "substituted-unit" if self.drift_service_identity
                else unit + "-identity"
            ),
        }

    def stop_service(self, unit: str) -> None:
        self.calls.append("stop:" + unit)
        self.services[unit] = False

    def start_service(self, unit: str) -> None:
        self.calls.append("start:" + unit)
        self.services[unit] = True
        if unit == module.RUNTIME_SOCKET and self.activate_runtime_on_socket_start:
            self.services[module.RUNTIME_SERVICE] = True
            self.selected_entries = True
        if unit == module.RUNTIME_SOCKET and self.entry_on_socket_start:
            self.selected_entries = True
        if unit == module.RUNTIME_SOCKET and self.handle_on_socket_start:
            self.private_handles = 1

    def archive_root_observation(
        self,
        _authority: dict[str, object],
    ) -> dict[str, object]:
        selected = product.selected_memory_runtime(
            product.validate_source_authority(self.selected)
        )
        safe = not self.selected_entries and self.private_handles == 0
        return {
            "handle_count": self.private_handles,
            "identity": "parent-root",
            "legacy_identity": "legacy-empty-root",
            "legacy_name": product.LEGACY_MEMORY_ARCHIVE_ID,
            "path": product.MEMORY_RUNTIME_ROOT,
            "selected_identity": (
                self.selected_root_identity if self.selected_root_exists else None
            ),
            "selected_name": selected["archive_id"],
            "selected_state": (
                "TARGET"
                if self.selected_root_exists and safe
                else "OLD"
                if not self.selected_root_exists
                else "THIRD_STATE"
            ),
            "state": "TARGET" if safe else "THIRD_STATE",
        }

    def create_root(
        self,
        _authority: dict[str, object],
        captured: dict[str, object],
    ) -> str | None:
        if captured["selected_state"] == "TARGET":
            return None
        self.calls.append("create-selected-root")
        self.selected_root_exists = True
        return self.selected_root_identity

    def remove_root(self, _authority: dict[str, object], identity: str) -> None:
        self.calls.append("remove-selected-root")
        if (
            identity != self.selected_root_identity
            or not self.selected_root_exists
            or self.selected_entries
            or self.private_handles
        ):
            raise module.MemoryActivationRejected("generated_root_drift")
        self.selected_root_exists = False

    def container(self, name: str) -> dict[str, object]:
        if name.startswith(product.ARCHIVE_PREFIX):
            if self.old_archived:
                return {
                    "active": self.old_active,
                    "command_digest": "old-command-digest",
                    "host_config_digest": "old-host-config-digest",
                    "identity": "old-object",
                    "image": "old-image",
                    "mounts_digest": "old-mounts-digest",
                    "name": name,
                    "network_names": [product.NETWORK_NAME],
                    "networks_digest": "old-networks-digest",
                    "plan_digest": "",
                    "policy": "on-failure:3",
                    "project": "old-project",
                    "service": "old-service",
                    "state": "TARGET",
                    "target_config_digest": "",
                    "user": "988:982",
                }
            return {
                "active": False,
                "identity": None,
                "name": name,
                "policy": "absent",
                "state": "OLD",
            }
        if self.target_exists:
            return {
                "active": self.target_active,
                "identity": "target-object",
                "name": name,
                "plan_digest": "f" * 64,
                "policy": self.target_policy,
                "state": "TARGET",
            }
        if not self.old_archived:
            return {
                "active": self.old_active,
                "command_digest": "old-command-digest",
                "host_config_digest": "old-host-config-digest",
                "identity": "old-object",
                "image": "old-image",
                "mounts_digest": "old-mounts-digest",
                "name": name,
                "network_names": [product.NETWORK_NAME],
                "networks_digest": "old-networks-digest",
                "plan_digest": "",
                "policy": "on-failure:3",
                "project": "old-project",
                "service": "old-service",
                "state": "TARGET",
                "target_config_digest": "",
                "user": "988:982",
            }
        return {
            "active": False,
            "identity": None,
            "name": name,
            "policy": "absent",
            "state": "OLD",
        }

    def stop_old(self, identity: str) -> None:
        self.calls.append("stop-old:" + identity)
        self.old_active = False

    def archive_old(self, identity: str, name: str) -> None:
        self.calls.append("archive-old:" + identity)
        self.old_archived = True
        if self.fail_archive_once:
            self.fail_archive_once = False
            raise module.MemoryActivationRejected("injected_archive_lost_return")

    def restore_old(self, identity: str, name: str) -> None:
        self.calls.append("restore-old:" + identity)
        self.old_archived = False

    def restore_old_running(self, identity: str) -> None:
        self.calls.append("restore-old-running:" + identity)
        self.old_active = True

    def reload(self) -> None:
        self.calls.append("daemon-reload")
        if self.fail_reload_once:
            self.fail_reload_once = False
            raise module.MemoryActivationRejected("injected_reload_failure")

    def readiness(self) -> dict[str, object]:
        return {
            key: {"active": value, "identity": key}
            for key, value in (
                ("core", self.services[module.CORE_SERVICE]),
                ("runtime", self.services[module.RUNTIME_SERVICE]),
                ("socket", self.services[module.RUNTIME_SOCKET]),
            )
        }

    def create_target(self, _plan: dict[str, object]) -> None:
        self.calls.append("create-target")
        self.target_exists = True
        self.target_active = False
        self.target_policy = module.PRE_DISPATCH_POLICY
        if self.fail_create_once:
            self.fail_create_once = False
            raise module.MemoryActivationRejected("injected_create_lost_return")

    def set_policy(self, _plan: object, identity: str, policy: str) -> None:
        self.calls.append("policy:" + policy)
        self.assert_target(identity)
        self.target_policy = policy

    def start_target(self, _plan: object, identity: str) -> None:
        self.calls.append("start-target")
        self.assert_target(identity)
        self.target_active = True
        if self.fail_start:
            raise module.MemoryActivationRejected("injected_lost_return")

    def remove_target(self, identity: str) -> None:
        self.calls.append("remove-target")
        self.assert_target(identity)
        self.target_exists = False
        self.target_active = False
        self.target_policy = "absent"

    def assert_target(self, identity: str) -> None:
        if identity != "target-object":
            raise AssertionError(identity)

    def network(self) -> dict[str, object]:
        return {
            "identity": "network-object",
            "member_ids": (
                ["old-object", "target-object"]
                if self.target_exists
                else []
                if self.old_archived or not self.old_active
                else ["old-object"]
            ),
            "name": product.NETWORK_NAME,
            "state": "TARGET",
        }


class OwnerPrivateMemoryActivationTests(unittest.TestCase):
    def test_inaccessible_handle_inventory_fails_closed(self) -> None:
        with mock.patch.object(module.Path, "iterdir", side_effect=PermissionError):
            with self.assertRaises(module.MemoryActivationRejected):
                module._private_root_handle_count(
                    Path(module.product.MEMORY_RUNTIME_ROOT)
                )

    def test_service_observation_uses_exact_named_properties(self) -> None:
        fragment = "/etc/systemd/system/" + module.RUNTIME_SERVICE
        valid = (
            "InvocationID=\n"
            f"FragmentPath={fragment}\n"
            "ActiveState=inactive\n"
        )
        with mock.patch.object(module, "_command", return_value=valid) as command:
            observed = module._service_observation(module.RUNTIME_SERVICE)
        self.assertFalse(observed["active"])
        self.assertEqual(
            observed["identity"],
            sha256(
                product.canonical([module.RUNTIME_SERVICE, fragment])
            ).hexdigest(),
        )
        self.assertNotIn("--value", command.call_args.args[0])

        hostile = (
            "ActiveState=active\n"
            f"FragmentPath={fragment}\n"
            "InvocationID=\n",
            "ActiveState=inactive\nFragmentPath=relative.service\nInvocationID=\n",
            f"ActiveState=absent\nFragmentPath={fragment}\nInvocationID=\n",
            f"ActiveState=inactive\nFragmentPath={fragment}\n",
            (
                f"ActiveState=inactive\nFragmentPath={fragment}\n"
                "InvocationID=\nInvocationID=duplicate\n"
            ),
            (
                f"ActiveState=inactive\nFragmentPath={fragment}\n"
                "InvocationID=\nUnknown=value\n"
            ),
            f"ActiveState=inactive\nFragmentPath={fragment}\nmalformed\n",
            f"inactive\n{fragment}\ninvocation\n",
        )
        for payload in hostile:
            with self.subTest(payload=payload), mock.patch.object(
                module,
                "_command",
                return_value=payload,
            ):
                with self.assertRaises(module.MemoryActivationRejected):
                    module._service_observation(module.RUNTIME_SERVICE)

    def test_named_inactive_service_and_socket_survive_full_reverse(self) -> None:
        plan, selected, old_payloads = self.make_plan()
        for key, unit in (
            ("core", module.CORE_SERVICE),
            ("runtime", module.RUNTIME_SERVICE),
            ("socket", module.RUNTIME_SOCKET),
        ):
            fragment = "/etc/systemd/system/" + unit
            plan["observation"]["services"][key]["identity"] = sha256(
                product.canonical([unit, fragment])
            ).hexdigest()
        plan = product.build_fixed_plan(selected, plan["observation"])
        effects = FixedEffects(selected, old_payloads, plan["observation"])
        effects.fail_reload_once = True
        service_observation = module._service_observation

        def named_service_observation(unit: str) -> dict[str, object]:
            active = effects.services[unit]
            payload = (
                f"FragmentPath=/etc/systemd/system/{unit}\n"
                f"InvocationID={'a' * 32 if active else ''}\n"
                f"ActiveState={'active' if active else 'inactive'}\n"
            )
            with mock.patch.object(module, "_command", return_value=payload):
                return service_observation(unit)

        with self.patches(effects), mock.patch.object(
            module,
            "_service_observation",
            side_effect=named_service_observation,
        ):
            with self.assertRaises(module.MemoryActivationRejected) as raised:
                module.run_fixed_product_activation(
                    plan,
                    supervised_start=False,
                )
        self.assertEqual(raised.exception.code, "injected_reload_failure")
        self.assertTrue(all(effects.services.values()))
        self.assertFalse(effects.target_exists)
        self.assertFalse(effects.selected_root_exists)

    def make_plan(
        self,
        *,
        files_old: bool = True,
        third_path: str | None = None,
        target_policy: str = "absent",
        target_active: bool = False,
        selected_present: bool = False,
    ) -> tuple[dict[str, object], dict[str, object], dict[str, bytes | None]]:
        selected = authority()
        current, old_hashes, old_payloads = observation(
            selected,
            files_old=files_old,
            third_path=third_path,
            target_policy=target_policy,
            target_active=target_active,
            selected_present=selected_present,
        )
        product.OLD_FILE_SHA256.clear()
        product.OLD_FILE_SHA256.update(old_hashes)
        plan = product.build_fixed_plan(selected, current)
        return plan, selected, old_payloads

    def patches(self, effects: FixedEffects) -> mock._patch_dict:
        return mock.patch.multiple(
            module,
            _archive_old_container=effects.archive_old,
            _archive_root_observation=effects.archive_root_observation,
            _container_or_absent=effects.container,
            _converge_immutable_artifacts=lambda _authority: 0,
            _create_selected_runtime_root=effects.create_root,
            _create_target_container=effects.create_target,
            _daemon_reload_and_verify=effects.reload,
            _file_observation=effects.file_observation,
            _install_target_file=effects.install_file,
            _network_observation=effects.network,
            _image_observation=lambda _image: {
                "identity": "image-member-set",
                "state": "TARGET",
            },
            _release_observation=lambda release: {
                "identity": release["member_set_sha256"],
                "state": "TARGET",
            },
            observe_fixed_product=lambda _authority: copy.deepcopy(
                effects.initial_observation
            ),
            _readiness_observation=effects.readiness,
            _remove_target=effects.remove_target,
            _remove_created_runtime_root=effects.remove_root,
            _remove_target_file=effects.remove_file,
            _restore_old_container=effects.restore_old,
            _restore_old_running=effects.restore_old_running,
            _service_observation=effects.service_observation,
            _set_target_policy=effects.set_policy,
            _start_service=effects.start_service,
            _start_target_once=effects.start_target,
            _stop_old_container=effects.stop_old,
            _stop_service=effects.stop_service,
        )

    def test_release_publication_is_absent_to_exact_target_and_collision_safe(self) -> None:
        payload = b"sealed-release-payload\n"
        digest = sha256(b"release-name").hexdigest()
        member = {
            "path": "nested/payload",
            "sha256": sha256(payload).hexdigest(),
            "size": len(payload),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            release = {
                "bundle_prefix": f"staging/releases/core/{digest}",
                "digest": digest,
                "directory_mode": "0550",
                "file_mode": "0440",
                "members": [member],
                "member_set_sha256": product.release_member_set_sha256([member]),
                "root": root.as_posix(),
            }
            with mock.patch.object(
                module,
                "_sealed_bundle_member",
                return_value=payload,
            ), mock.patch.object(
                module,
                "_release_owner",
                return_value=(os.getuid(), os.getgid()),
            ):
                module._publish_release("core", release)
                self.assertEqual(
                    (root / digest / "nested/payload").read_bytes(), payload
                )
                module._publish_release("core", release)
            with mock.patch.object(
                module,
                "_release_owner",
                return_value=(os.getuid(), os.getgid()),
            ):
                observed = module._release_observation(release)
            self.assertEqual(observed["state"], "TARGET")
            self.assertEqual(
                observed["identity"], release["member_set_sha256"]
            )

            collision_digest = sha256(b"collision").hexdigest()
            collision = dict(release)
            collision["digest"] = collision_digest
            collision["bundle_prefix"] = f"staging/releases/core/{collision_digest}"
            collision_root = root / collision_digest
            collision_root.mkdir()
            (collision_root / "partial").write_bytes(b"third-state")
            with mock.patch.object(module, "_sealed_bundle_member") as sealed:
                with self.assertRaises(module.MemoryActivationRejected):
                    module._publish_release("core", collision)
            sealed.assert_not_called()

    def test_release_content_identity_and_metadata_are_independent_gates(self) -> None:
        payload = b"immutable-release-member\n"
        digest = sha256(b"content-identity-release").hexdigest()
        member = {
            "path": "nested/payload",
            "sha256": sha256(payload).hexdigest(),
            "size": len(payload),
        }
        member_set = product.release_member_set_sha256([member])

        def materialize(parent: Path) -> tuple[dict[str, object], Path, Path]:
            parent.mkdir()
            selected = parent / digest
            nested = selected / "nested"
            nested.mkdir(parents=True)
            target = nested / "payload"
            target.write_bytes(payload)
            target.chmod(0o440)
            nested.chmod(0o550)
            selected.chmod(0o550)
            return (
                {
                    "bundle_prefix": f"staging/releases/core/{digest}",
                    "digest": digest,
                    "directory_mode": "0550",
                    "file_mode": "0440",
                    "members": [member],
                    "member_set_sha256": member_set,
                    "root": parent.as_posix(),
                },
                selected,
                target,
            )

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            module,
            "_release_owner",
            return_value=(os.getuid(), os.getgid()),
        ):
            root = Path(temporary)
            first, first_selected, first_file = materialize(root / "first")
            second, _second_selected, _second_file = materialize(root / "second")
            first_observation = module._release_observation(first)
            second_observation = module._release_observation(second)
            self.assertNotEqual(first_selected.stat().st_ino, _second_selected.stat().st_ino)
            self.assertEqual(first_observation, second_observation)
            self.assertEqual(
                first_observation,
                {"identity": member_set, "state": "TARGET"},
            )

            substituted, _selected, substituted_file = materialize(
                root / "substituted"
            )
            substituted_file.chmod(0o640)
            substituted_file.write_bytes(b"substituted-release-member\n")
            substituted_file.chmod(0o440)
            self.assertEqual(
                module._release_observation(substituted)["state"],
                "THIRD_STATE",
            )

            missing, _selected, missing_file = materialize(root / "missing")
            missing_file.parent.chmod(0o750)
            missing_file.unlink()
            missing_file.parent.chmod(0o550)
            self.assertEqual(
                module._release_observation(missing)["state"], "THIRD_STATE"
            )

            extra, extra_selected, _extra_file = materialize(root / "extra")
            extra_selected.chmod(0o750)
            added = extra_selected / "extra"
            added.write_bytes(b"extra\n")
            added.chmod(0o440)
            extra_selected.chmod(0o550)
            self.assertEqual(
                module._release_observation(extra)["state"], "THIRD_STATE"
            )

            linked, _selected, linked_file = materialize(root / "linked")
            os.link(linked_file, root / "outside-hardlink")
            with self.assertRaises(module.MemoryActivationRejected):
                module._release_observation(linked)

            symlinked, _selected, symlinked_file = materialize(root / "symlinked")
            symlinked_file.parent.chmod(0o750)
            symlinked_file.unlink()
            symlinked_file.symlink_to(root / "outside-hardlink")
            symlinked_file.parent.chmod(0o550)
            with self.assertRaises(module.MemoryActivationRejected):
                module._release_observation(symlinked)

            wrong_mode, _selected, wrong_mode_file = materialize(root / "mode")
            wrong_mode_file.chmod(0o600)
            with self.assertRaises(module.MemoryActivationRejected):
                module._release_observation(wrong_mode)

            wrong_owner, _selected, _owner_file = materialize(root / "owner")
            with mock.patch.object(
                module,
                "_release_owner",
                return_value=(os.getuid() + 1, os.getgid()),
            ), self.assertRaises(module.MemoryActivationRejected):
                module._release_observation(wrong_owner)

            wrong_type = dict(first)
            wrong_type["root"] = (root / "type").as_posix()
            Path(str(wrong_type["root"])).mkdir()
            (Path(str(wrong_type["root"])) / digest).write_bytes(b"not-directory")
            self.assertEqual(
                module._release_observation(wrong_type)["state"], "THIRD_STATE"
            )

            raced, raced_selected, _raced_file = materialize(root / "race")
            original_lstat = Path.lstat
            root_lstat_calls = 0

            def racing_lstat(selected: Path):
                nonlocal root_lstat_calls
                if selected == raced_selected:
                    root_lstat_calls += 1
                    observed = original_lstat(selected)
                    if root_lstat_calls == 3:
                        fields = list(observed)
                        fields[1] += 1
                        return os.stat_result(fields)
                return original_lstat(selected)

            with mock.patch.object(Path, "lstat", new=racing_lstat), self.assertRaises(
                module.MemoryActivationRejected
            ):
                module._release_observation(raced)

            first_file.chmod(0o440)

        selected = authority()
        current, old_hashes, _old_payloads = observation(selected)
        current["releases"]["runtime"] = {"identity": None, "state": "OLD"}
        with mock.patch.dict(module.product.OLD_FILE_SHA256, old_hashes, clear=True):
            plan = product.build_fixed_plan(selected, current)
        self.assertEqual(
            plan["observation"]["releases"]["runtime"],
            {"identity": None, "state": "OLD"},
        )
        substituted_identity = copy.deepcopy(current)
        substituted_identity["releases"]["core"]["identity"] = "0" * 64
        with self.assertRaises(product.ProductionPlanRejected) as rejected:
            product.build_fixed_plan(selected, substituted_identity)
        self.assertEqual(rejected.exception.code, "fixed_release_observation_rejected")

    def test_image_observation_uses_receipt_projection_not_command_digest(self) -> None:
        image = authority()["image"]
        receipt = image["receipt"]
        projection = {
            "Architecture": receipt["platform"]["architecture"],
            "Id": receipt["image_id"],
            "Os": receipt["platform"]["os"],
            "RepoDigests": [receipt["image_reference"]],
            "RootFS": {"Layers": [row["diff_id"] for row in receipt["layers"]]},
        }
        with mock.patch.object(
            module,
            "_command",
            side_effect=lambda _arguments: json.dumps(projection),
        ):
            self.assertEqual(module._image_observation(image)["state"], "TARGET")
            projection["RootFS"]["Layers"] = ["sha256:" + "0" * 64]
            self.assertEqual(module._image_observation(image)["state"], "THIRD_STATE")

    def test_no_start_without_explicit_supervised_decision(self) -> None:
        plan, selected, old_payloads = self.make_plan()
        effects = FixedEffects(selected, old_payloads, plan["observation"])
        with self.patches(effects):
            result = module.run_fixed_product_activation(
                plan,
                supervised_start=False,
            )
        self.assertEqual(result["status"], "SUPERVISED_START_REQUIRED")
        self.assertNotIn("start-target", effects.calls)
        self.assertNotIn("start:" + module.RUNTIME_SERVICE, effects.calls)
        self.assertIn("start:" + module.RUNTIME_SOCKET, effects.calls)
        self.assertFalse(effects.services[module.RUNTIME_SERVICE])
        self.assertTrue(effects.services[module.RUNTIME_SOCKET])
        self.assertFalse(result["writer_boundary"])

    def test_exactly_one_start_dispatch_then_manual_terminal(self) -> None:
        plan, selected, old_payloads = self.make_plan()
        effects = FixedEffects(selected, old_payloads, plan["observation"])
        with self.patches(effects):
            with mock.patch.object(
                module,
                "observe_fixed_product",
                return_value=copy.deepcopy(plan["observation"]),
            ):
                result = module.run_fixed_product_activation(
                    plan,
                    supervised_start=True,
                )
        self.assertEqual(effects.calls.count("start-target"), 1)
        self.assertEqual(
            effects.calls[-2:],
            ["policy:on-failure:3", "start-target"],
        )
        self.assertNotIn("start:" + module.RUNTIME_SERVICE, effects.calls)
        self.assertLess(
            effects.calls.index("create-target"),
            effects.calls.index("start:" + module.RUNTIME_SOCKET),
        )
        self.assertEqual(result["status"], "SUPERVISED_MANUAL_REQUIRED")
        self.assertTrue(result["writer_boundary"])

    def test_exact_preexisting_empty_selected_root_is_reused(self) -> None:
        plan, selected, old_payloads = self.make_plan(selected_present=True)
        effects = FixedEffects(selected, old_payloads, plan["observation"])
        with self.patches(effects):
            result = module.run_fixed_product_activation(
                plan,
                supervised_start=True,
            )
        self.assertEqual(result["status"], "SUPERVISED_MANUAL_REQUIRED")
        self.assertNotIn("create-selected-root", effects.calls)
        self.assertNotIn("remove-selected-root", effects.calls)
        self.assertTrue(effects.selected_root_exists)

    def test_early_socket_activation_is_manual_without_reverse(self) -> None:
        plan, selected, old_payloads = self.make_plan()
        effects = FixedEffects(selected, old_payloads, plan["observation"])
        effects.activate_runtime_on_socket_start = True
        with self.patches(effects):
            result = module.run_fixed_product_activation(
                plan,
                supervised_start=True,
            )
        self.assertEqual(
            result["reason"],
            "fixed_writer_boundary_crossed_or_ambiguous",
        )
        self.assertTrue(result["writer_boundary"])
        self.assertNotIn("start-target", effects.calls)
        self.assertNotIn("remove-selected-root", effects.calls)
        self.assertNotIn("restore-old:old-object", effects.calls)

    def test_selected_entry_or_handle_aba_is_manual_without_reverse(self) -> None:
        for field in ("entry_on_socket_start", "handle_on_socket_start"):
            plan, selected, old_payloads = self.make_plan()
            effects = FixedEffects(selected, old_payloads, plan["observation"])
            setattr(effects, field, True)
            with self.patches(effects):
                result = module.run_fixed_product_activation(
                    plan,
                    supervised_start=True,
                )
            self.assertEqual(
                result["reason"],
                "fixed_writer_boundary_crossed_or_ambiguous",
                field,
            )
            self.assertNotIn("start-target", effects.calls, field)
            self.assertNotIn("remove-selected-root", effects.calls, field)

    def test_lost_return_after_dispatch_never_reverses(self) -> None:
        plan, selected, old_payloads = self.make_plan()
        effects = FixedEffects(selected, old_payloads, plan["observation"])
        effects.fail_start = True
        with self.patches(effects):
            with mock.patch.object(
                module,
                "observe_fixed_product",
                return_value=copy.deepcopy(plan["observation"]),
            ):
                result = module.run_fixed_product_activation(
                    plan,
                    supervised_start=True,
                )
        self.assertEqual(result["reason"], "writer_dispatch_lost_or_failed")
        self.assertTrue(result["writer_boundary"])
        self.assertNotIn("restore-old:old-object", effects.calls)
        self.assertNotIn("remove-target", effects.calls)

    def test_fresh_fenced_or_running_target_is_zero_callback_manual_stop(self) -> None:
        for policy, active in (
            (module.DISPATCH_FENCE_POLICY, False),
            (module.DISPATCH_FENCE_POLICY, True),
        ):
            plan, _selected, _old = self.make_plan(
                files_old=False,
                target_policy=policy,
                target_active=active,
            )
            with mock.patch.object(
                module,
                "observe_fixed_product",
                return_value=copy.deepcopy(plan["observation"]),
            ):
                result = module.run_fixed_product_activation(
                    plan,
                    supervised_start=True,
                )
            self.assertEqual(result["callbacks"], 0)
            self.assertEqual(result["status"], "SUPERVISED_MANUAL_REQUIRED")
            self.assertTrue(result["writer_boundary"])

    def test_third_state_is_zero_callback_manual_stop(self) -> None:
        path = sorted(product.FILE_ROLES)[0]
        plan, _selected, _old = self.make_plan(
            files_old=False,
            third_path=path,
        )
        with mock.patch.object(
            module,
            "observe_fixed_product",
            return_value=copy.deepcopy(plan["observation"]),
        ):
            result = module.run_fixed_product_activation(
                plan,
                supervised_start=True,
            )
        self.assertEqual(result["callbacks"], 0)
        self.assertEqual(result["reason"], "file_third_state")

    def test_fresh_resource_identity_substitution_is_zero_callback_manual_stop(self) -> None:
        plan, selected, old_payloads = self.make_plan()
        effects = FixedEffects(selected, old_payloads, plan["observation"])
        effects.drift_service_identity = True
        with self.patches(effects):
            result = module.run_fixed_product_activation(
                plan,
                supervised_start=True,
            )
        self.assertEqual(result["callbacks"], 0)
        self.assertEqual(result["status"], "SUPERVISED_MANUAL_REQUIRED")
        self.assertEqual(result["reason"], "fixed_service_prestate_drifted")

    def test_fresh_observation_failure_is_zero_callback_manual_stop(self) -> None:
        plan, _selected, _old_payloads = self.make_plan()
        with mock.patch.object(
            module,
            "observe_fixed_product",
            side_effect=module.MemoryActivationRejected(
                "fixed_observation_unavailable"
            ),
        ):
            result = module.run_fixed_product_activation(
                plan,
                supervised_start=True,
            )
        self.assertEqual(result["callbacks"], 0)
        self.assertEqual(result["status"], "SUPERVISED_MANUAL_REQUIRED")
        self.assertEqual(result["reason"], "fixed_observation_unavailable")

    def test_concurrent_owner_is_manual_and_never_observes_or_mutates(self) -> None:
        def lock(_descriptor: int, operation: int) -> None:
            if operation & module.fcntl.LOCK_NB:
                raise BlockingIOError

        with mock.patch.object(module.os, "open", return_value=91), mock.patch.object(
            module.os, "close"
        ), mock.patch.object(module.fcntl, "flock", side_effect=lock), mock.patch.object(
            module, "load_installed_source_authority"
        ) as load:
            self.assertEqual(module.fixed_owner_entry(supervised_start=True), 75)
        load.assert_not_called()

    def test_lock_io_failure_is_manual_and_never_observes_or_mutates(self) -> None:
        def lock(_descriptor: int, operation: int) -> None:
            if operation & module.fcntl.LOCK_NB:
                raise OSError("generated lock failure")

        with mock.patch.object(module.os, "open", return_value=91), mock.patch.object(
            module.os, "close"
        ), mock.patch.object(module.fcntl, "flock", side_effect=lock), mock.patch.object(
            module, "load_installed_source_authority"
        ) as load:
            self.assertEqual(module.fixed_owner_entry(supervised_start=True), 75)
        load.assert_not_called()

    def test_pre_writer_failure_runs_exact_reverse_and_restores_absence(self) -> None:
        plan, selected, old_payloads = self.make_plan()
        effects = FixedEffects(selected, old_payloads, plan["observation"])
        effects.fail_reload_once = True
        with self.patches(effects):
            with self.assertRaises(module.MemoryActivationRejected) as raised:
                module.run_fixed_product_activation(
                    plan,
                    supervised_start=False,
                )
        self.assertEqual(raised.exception.code, "injected_reload_failure")
        self.assertIn("restore-old:old-object", effects.calls)
        absent = [path for path, payload in old_payloads.items() if payload is None]
        self.assertEqual(len(absent), 2)
        self.assertTrue(all(effects.files[path] is None for path in absent))
        self.assertFalse(effects.target_exists)
        self.assertFalse(effects.selected_root_exists)
        self.assertIn("remove-selected-root", effects.calls)

    def test_pre_writer_lost_returns_restore_exact_completed_prefix(self) -> None:
        for failure in ("fail_archive_once", "fail_install_once", "fail_create_once"):
            plan, selected, old_payloads = self.make_plan()
            effects = FixedEffects(selected, old_payloads, plan["observation"])
            setattr(effects, failure, True)
            with self.patches(effects):
                with self.assertRaises(module.MemoryActivationRejected):
                    module.run_fixed_product_activation(
                        plan,
                        supervised_start=False,
                    )
            self.assertFalse(effects.old_archived, failure)
            self.assertFalse(effects.target_exists, failure)
            self.assertEqual(effects.files, old_payloads, failure)
            self.assertTrue(effects.old_active, failure)

    def test_partial_or_competing_archive_root_blocks_all_callbacks(self) -> None:
        plan, _selected, _old = self.make_plan(files_old=False)
        for mutation in ("partial", "handle"):
            changed = copy.deepcopy(plan["observation"])
            changed["archive_root"].update(
                selected_identity="partial-private-store",
                selected_state="THIRD_STATE",
                state="THIRD_STATE",
            )
            if mutation == "handle":
                changed["archive_root"]["handle_count"] = 1
            changed_plan = product.build_fixed_plan(plan["authority"], changed)
            with mock.patch.object(
                module,
                "observe_fixed_product",
                return_value=copy.deepcopy(changed_plan["observation"]),
            ):
                result = module.run_fixed_product_activation(
                    changed_plan,
                    supervised_start=True,
                )
            self.assertEqual(result["callbacks"], 0, mutation)
            self.assertEqual(
                result["reason"],
                "private_writer_state_ambiguous",
                mutation,
            )

    def test_archive_name_collision_blocks_all_callbacks(self) -> None:
        plan, _selected, _old = self.make_plan(files_old=False)
        plan["observation"]["archive_name"]["identity"] = "other-object"
        plan["observation"]["archive_name"]["projection_sha256"] = "f" * 64
        plan["observation"]["archive_name"]["state"] = "THIRD_STATE"
        plan["target_effect"] = None
        body = {
            key: plan[key]
            for key in (
                "archive_name",
                "authority",
                "fixed_stages",
                "observation",
                "schema",
                "target_effect",
            )
        }
        plan["plan_sha256"] = product.digest("phase_f_fixed_product_plan", body)
        with mock.patch.object(
            module,
            "observe_fixed_product",
            return_value=copy.deepcopy(plan["observation"]),
        ):
            result = module.run_fixed_product_activation(
                plan,
                supervised_start=True,
            )
        self.assertEqual(result["callbacks"], 0)
        self.assertEqual(result["reason"], "archive_name_ambiguous")

    def test_installer_renders_existing_unit_and_never_starts_service(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ("a" * 64)
            root.mkdir()
            source = ROOT / "systemd/myuna-telegram-owner-r5-resume.service"
            (root / "myuna-telegram-owner-r5-resume.service.in").write_bytes(
                source.read_bytes()
            )
            fake_module = root / "activate_p07_owner_private_memory_v1.py"
            fake_module.write_text("# fixed owner\n", encoding="utf-8")
            unit = Path(temporary) / "installed.service"
            releases = Path(temporary) / "controller-releases"
            releases.mkdir()
            verified = authority()
            verified["authority_sha256"] = "f" * 64
            verified["release_sha256"] = root.name
            with mock.patch.object(module, "__file__", fake_module.as_posix()), mock.patch.object(
                module, "UNIT_PATH", unit
            ), mock.patch.object(
                module, "CONTROLLER_RELEASES_ROOT", releases
            ), mock.patch.object(
                module.resume,
                "verify_fixed_controller_release",
                return_value=verified,
            ), mock.patch.object(module, "_atomic_file") as write:
                def materialize(path: Path, payload: bytes, mode: int, uid: int, gid: int) -> None:
                    path.write_bytes(payload)
                    path.chmod(mode)
                write.side_effect = materialize
                real_observation = module._file_observation
                with mock.patch.object(module, "_file_observation") as observed:
                    def root_owned(path: Path) -> dict[str, object]:
                        row = real_observation(path)
                        if path == unit and row["kind"] == "absent":
                            row = {
                                "gid": 0,
                                "identity": "original-old-unit",
                                "kind": "regular",
                                "mode": "0644",
                                "payload_b64": base64.b64encode(
                                    b"original old unit\n"
                                ).decode("ascii"),
                                "sha256": module.ACCEPTED_OLD_UNIT_SHA256,
                                "uid": 0,
                            }
                        row["uid"] = 0
                        row["gid"] = 0
                        return row
                    observed.side_effect = root_owned
                    result = module.install_current_controller_unit()
                    repeated = module.install_current_controller_unit()
            self.assertEqual(result["status"], "INSTALLED_INACTIVE_NOT_STARTED")
            self.assertEqual(repeated, result)
            self.assertEqual(write.call_count, 1)
            text = unit.read_text("utf-8")
            self.assertIn(
                f"ExecStart=/usr/bin/python3 {releases / root.name}/telegram_r5_boot_resume.py",
                text,
            )
            self.assertNotIn("@CONTROLLER_", text)

    def test_transitional_first_parent_chain_rejects_ambiguity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "deploy"
            repository.mkdir()

            def git(*arguments: str) -> bytes:
                completed = module.subprocess.run(
                    ["/usr/bin/git", "-C", repository.as_posix(), *arguments],
                    check=True,
                    capture_output=True,
                )
                return completed.stdout

            git("init", "-q")
            git("config", "user.name", "Phase F Test")
            git("config", "user.email", "phase-f@example.invalid")
            commits: list[str] = []
            for index in range(5):
                (repository / "lineage.txt").write_text(
                    f"{index}\n", encoding="utf-8"
                )
                git("add", "lineage.txt")
                git("commit", "-q", "-m", f"lineage-{index}")
                commits.append(git("rev-parse", "HEAD").decode().strip())
            with mock.patch.object(
                product, "TRANSITIONAL_LINEAGE_LOWER", commits[0]
            ), mock.patch.object(
                product, "TRANSITIONAL_LINEAGE_UPPER", commits[-1]
            ), mock.patch.object(
                product, "ACCEPTED_DEPLOY_PARENT", commits[1]
            ):
                pairs = module._bounded_transitional_pairs(repository)
                self.assertEqual(
                    pairs,
                    tuple(
                        (commits[index], commits[index - 1])
                        for index in range(4, 0, -1)
                    ),
                )
                self.assertNotIn((commits[0], "0" * 40), pairs)

                git("replace", commits[-1], commits[-2])
                with self.assertRaises(module.MemoryActivationRejected):
                    module._bounded_transitional_pairs(repository)
                git("replace", "-d", commits[-1])

                graft = Path(
                    git("rev-parse", "--git-path", "info/grafts")
                    .decode()
                    .strip()
                )
                if not graft.is_absolute():
                    graft = repository / graft
                graft.parent.mkdir(parents=True, exist_ok=True)
                graft.write_text(f"{commits[-1]} {commits[0]}\n", encoding="ascii")
                with self.assertRaises(module.MemoryActivationRejected):
                    module._bounded_transitional_pairs(repository)
                graft.unlink()

                with mock.patch.object(
                    product, "TRANSITIONAL_LINEAGE_UPPER", "0" * 40
                ), mock.patch.object(
                    product, "ACCEPTED_DEPLOY_PARENT", "0" * 40
                ):
                    with self.assertRaises(module.MemoryActivationRejected):
                        module._bounded_transitional_pairs(repository)

            git("checkout", "-q", "-b", "side")
            (repository / "side.txt").write_text("side\n", encoding="utf-8")
            git("add", "side.txt")
            git("commit", "-q", "-m", "side")
            side = git("rev-parse", "HEAD").decode().strip()
            git("checkout", "-q", "master")
            git("merge", "-q", "--no-ff", "side", "-m", "merge")
            merge = git("rev-parse", "HEAD").decode().strip()
            with mock.patch.object(
                product, "TRANSITIONAL_LINEAGE_LOWER", commits[0]
            ), mock.patch.object(
                product, "TRANSITIONAL_LINEAGE_UPPER", merge
            ), mock.patch.object(product, "ACCEPTED_DEPLOY_PARENT", merge):
                with self.assertRaises(module.MemoryActivationRejected):
                    module._bounded_transitional_pairs(repository)
            self.assertNotEqual(side, merge)

    def test_logic_controller_and_attempt5_product_authorities_are_independent(
        self,
    ) -> None:
        selected = authority()
        frozen = copy.deepcopy(selected)
        frozen.pop("authority_sha256")
        frozen["source"]["deploy_commit"] = product.ATTEMPT5_PRODUCT_DEPLOY_COMMIT
        frozen["source"]["deploy_parent"] = product.ATTEMPT5_PRODUCT_DEPLOY_PARENT
        frozen_digest = product.digest("phase_f_fixed_source", frozen)
        frozen_envelope = {
            **frozen,
            "authority_sha256": "a" * 64,
            "release_sha256": product.ATTEMPT5_PRODUCT_CONTROLLER_RELEASE,
        }
        current_release = "c" * 64
        current_envelope = {
            "release_sha256": current_release,
            "source": {
                "deploy_parent": product.ACCEPTED_DEPLOY_PARENT,
            },
        }
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            module,
            "__file__",
            (Path(temporary) / current_release / "activate.py").as_posix(),
        ), mock.patch.object(
            module.resume,
            "verify_fixed_controller_release",
            return_value=current_envelope,
        ) as current_verify, mock.patch.object(
            module,
            "_historical_controller_authority",
            return_value=frozen_envelope,
        ) as frozen_verify, mock.patch.object(
            product,
            "ATTEMPT5_PRODUCT_AUTHORITY_SHA256",
            frozen_digest,
        ):
            loaded = module.load_installed_source_authority()
        self.assertEqual(loaded["authority_sha256"], frozen_digest)
        self.assertEqual(
            (
                loaded["source"]["deploy_commit"],
                loaded["source"]["deploy_parent"],
            ),
            (
                product.ATTEMPT5_PRODUCT_DEPLOY_COMMIT,
                product.ATTEMPT5_PRODUCT_DEPLOY_PARENT,
            ),
        )
        current_verify.assert_called_once()
        frozen_verify.assert_called_once_with(
            module.CONTROLLER_RELEASES_ROOT
            / product.ATTEMPT5_PRODUCT_CONTROLLER_RELEASE
        )
        varied_release = "d" * 64
        varied_current = {
            **current_envelope,
            "authority_sha256": "e" * 64,
            "release_sha256": varied_release,
        }
        with mock.patch.object(
            module,
            "__file__",
            (Path("/tmp") / varied_release / "activate.py").as_posix(),
        ), mock.patch.object(
            module.resume,
            "verify_fixed_controller_release",
            return_value=varied_current,
        ), mock.patch.object(
            module,
            "_historical_controller_authority",
            return_value=frozen_envelope,
        ), mock.patch.object(
            product,
            "ATTEMPT5_PRODUCT_AUTHORITY_SHA256",
            frozen_digest,
        ):
            varied_loaded = module.load_installed_source_authority()
        self.assertEqual(
            product.canonical(varied_loaded),
            product.canonical(loaded),
        )
        current_generated = copy.deepcopy(selected)
        with self.assertRaises(module.MemoryActivationRejected):
            module._fresh_checkpoint_plan(current_generated)
        with mock.patch.object(
            product,
            "ATTEMPT5_PRODUCT_AUTHORITY_SHA256",
            frozen_digest,
        ):
            current, old_hashes, _old_payloads = observation(
                loaded,
                files_old=False,
            )
        current["services"] = {
            key: {"active": False, "identity": row["identity"]}
            for key, row in current["services"].items()
        }
        current["old_container"] = {
            "active": False,
            "identity": None,
            "name": product.CONTAINER_NAME,
            "policy": "absent",
            "state": "THIRD_STATE",
        }
        current["archive_name"] = {
            "identity": "old-object",
            "name": product.ARCHIVE_PREFIX + frozen_digest[:16],
            "projection_sha256": "a" * 64,
            "state": "TARGET",
        }
        current["archive_root"]["selected_identity"] = "selected-empty-root"
        current["archive_root"]["selected_state"] = "TARGET"
        current["network"]["member_ids"] = []
        with mock.patch.object(
            product,
            "ATTEMPT5_PRODUCT_AUTHORITY_SHA256",
            frozen_digest,
        ), mock.patch.dict(
            product.OLD_FILE_SHA256,
            old_hashes,
            clear=True,
        ), mock.patch.object(
            module,
            "_old_container_role_observation",
            return_value={
                "active": False,
                "identity": "old-object",
                "state": "TARGET",
            },
        ), mock.patch.object(
            module,
            "_effective_units_state",
            return_value="TARGET",
        ):
            plan = product.build_fixed_plan(loaded, current)
            result = module.run_checkpointed_stage(
                plan,
                requested_stage=None,
                supervised_start=False,
            )
        self.assertEqual(result["prefix_before"], "FILES_AND_UNITS_TARGET")
        self.assertEqual(result["next_stage"], "RECOVER_ATTEMPT5_FAILED_TARGET_TO_CORRECTED_STOPPED")
        self.assertEqual(result["callbacks"], 0)

        substituted = copy.deepcopy(frozen_envelope)
        substituted["files"][sorted(product.FILE_ROLES)[0]][
            "payload_sha256"
        ] = "0" * 64
        with mock.patch.object(
            module,
            "__file__",
            (Path("/tmp") / current_release / "activate.py").as_posix(),
        ), mock.patch.object(
            module.resume,
            "verify_fixed_controller_release",
            return_value=current_envelope,
        ), mock.patch.object(
            module,
            "_historical_controller_authority",
            return_value=substituted,
        ), mock.patch.object(
            product,
            "ATTEMPT5_PRODUCT_AUTHORITY_SHA256",
            frozen_digest,
        ):
            with self.assertRaises(product.ProductionPlanRejected):
                module.load_installed_source_authority()
        self.assertFalse(hasattr(module, "_verify_file_generation_predecessor"))
        self.assertFalse(
            any(name.startswith("FILE_PREDECESSOR_") for name in vars(product))
        )

    def test_historical_controller_retains_verified_envelope(self) -> None:
        selected = authority()
        verified = {
            **selected,
            "authority_sha256": "a" * 64,
            "release_sha256": "b" * 64,
        }
        with tempfile.TemporaryDirectory() as temporary:
            release_root = Path(temporary)
            (release_root / "p07_owner_private_memory_production_plan.py").write_text(
                "# generated historical product authority\n",
                encoding="utf-8",
            )
            current_product = sys.modules[
                "p07_owner_private_memory_production_plan"
            ]

            def environment_bound_verifier(
                selected_root: Path,
                *,
                environment: dict[str, str] | None = None,
            ) -> dict[str, object]:
                self.assertEqual(selected_root, release_root)
                if environment is None:
                    raise module.resume.ResumeRejected(
                        "fixed_controller_environment_rejected"
                    )
                self.assertEqual(environment, {})
                return verified

            with mock.patch.object(
                module.resume,
                "verify_fixed_controller_release",
                side_effect=environment_bound_verifier,
            ) as verify:
                with mock.patch.dict(
                    os.environ,
                    {
                        module.resume.CONTROLLER_RELEASE_ENV: "c" * 64,
                        module.resume.CONTROLLER_CONFIG_ENV: "d" * 64,
                        module.resume.CONTROLLER_AUTHORITY_ENV: "e" * 64,
                    },
                ):
                    with self.assertRaises(module.resume.ResumeRejected):
                        module.resume.verify_fixed_controller_release(release_root)
                    verify.reset_mock()
                    self.assertEqual(
                        module._historical_controller_authority(release_root),
                        verified,
                    )
                self.assertIs(
                    sys.modules["p07_owner_private_memory_production_plan"],
                    current_product,
                )
                verify.assert_called_once_with(release_root, environment={})
                self.assertEqual(verified["authority_sha256"], "a" * 64)
                self.assertEqual(verified["release_sha256"], "b" * 64)

            for rejection_code in (
                "fixed_controller_member_rejected",
                "fixed_controller_config_rejected",
                "fixed_controller_source_rejected",
                "fixed_controller_authority_rejected",
                "fixed_controller_release_rejected",
            ):
                with mock.patch.object(
                    module.resume,
                    "verify_fixed_controller_release",
                    side_effect=module.resume.ResumeRejected(rejection_code),
                ) as failed_verify:
                    with self.assertRaises(
                        module.resume.ResumeRejected
                    ) as rejected:
                        module._historical_controller_authority(release_root)
                self.assertEqual(str(rejected.exception), rejection_code)
                failed_verify.assert_called_once_with(
                    release_root,
                    environment={},
                )
                self.assertIs(
                    sys.modules["p07_owner_private_memory_production_plan"],
                    current_product,
                )

    def test_transitional_admission_requires_pair_unit_and_attempt_gate(self) -> None:
        release_id = "a" * 64
        config_sha256 = "b" * 64
        authority_sha256 = "c" * 64
        commit = "1" * 40
        parent = "2" * 40
        tree = "3" * 40
        with tempfile.TemporaryDirectory() as temporary:
            releases = Path(temporary) / "releases"
            release_root = releases / release_id
            release_root.mkdir(parents=True)
            release_root.chmod(0o555)
            template = (
                "Environment=MYUNA_PHASE_F_CONTROLLER_RELEASE_SHA256="
                "@CONTROLLER_RELEASE_DIGEST@\n"
                "Environment=MYUNA_PHASE_F_CONTROLLER_CONFIG_SHA256="
                "@CONTROLLER_CONFIG_SHA256@\n"
                "Environment=MYUNA_PHASE_F_CONTROLLER_AUTHORITY_SHA256="
                "@CONTROLLER_AUTHORITY_SHA256@\n"
                "ExecStart=/usr/bin/python3 @CONTROLLER_RELEASE_ROOT@/"
                "telegram_r5_boot_resume.py\n"
            )
            unit_payload = (
                template.replace("@CONTROLLER_RELEASE_DIGEST@", release_id)
                .replace("@CONTROLLER_CONFIG_SHA256@", config_sha256)
                .replace("@CONTROLLER_AUTHORITY_SHA256@", authority_sha256)
                .replace("@CONTROLLER_RELEASE_ROOT@", release_root.as_posix())
            ).encode("utf-8")
            before = {
                "gid": 0,
                "kind": "regular",
                "mode": "0644",
                "payload_b64": base64.b64encode(unit_payload).decode("ascii"),
                "sha256": sha256(unit_payload).hexdigest(),
                "uid": 0,
            }
            document = {
                "deploy_commit": commit,
                "deploy_parent": parent,
                "deploy_tree": tree,
                "fixed_product_authority": {
                    "controller": {"config_sha256": config_sha256}
                },
            }
            verified = {
                "authority_sha256": authority_sha256,
                "controller": {"config_sha256": config_sha256},
                "source": {
                    "deploy_commit": commit,
                    "deploy_parent": parent,
                    "deploy_tree": tree,
                },
            }
            template_observation = {
                "payload_b64": base64.b64encode(template.encode()).decode("ascii")
            }
            with mock.patch.object(
                module, "CONTROLLER_RELEASES_ROOT", releases
            ), mock.patch.object(
                module, "_canonical_release_json", return_value=document
            ), mock.patch.object(
                module, "_bounded_transitional_pairs", return_value=((commit, parent),)
            ), mock.patch.object(
                module, "_verified_deploy_source_binding"
            ) as source_binding, mock.patch.object(
                module, "_historical_controller_authority", return_value=verified
            ), mock.patch.object(
                module, "_file_observation", return_value=template_observation
            ):
                self.assertTrue(module._admit_transitional_controller_unit(before))
                source_binding.assert_called_once()
                with mock.patch.object(
                    module, "_bounded_transitional_pairs", return_value=()
                ):
                    with self.assertRaises(module.MemoryActivationRejected):
                        module._admit_transitional_controller_unit(before)
                for field, value in (
                    ("TRANSITIONAL_ATTEMPT_UNCONSUMED", True),
                    ("TRANSITIONAL_WRITER_BOUNDARY", True),
                    ("TRANSITIONAL_STAGE_ENTRY", "IMMUTABLE_TARGET"),
                    ("TRANSITIONAL_INSTALL_ATTEMPT", 6),
                ):
                    with mock.patch.object(product, field, value):
                        with self.assertRaises(module.MemoryActivationRejected):
                            module._admit_transitional_controller_unit(before)
                changed = copy.deepcopy(before)
                changed_payload = unit_payload + b"x"
                changed["payload_b64"] = base64.b64encode(changed_payload).decode(
                    "ascii"
                )
                changed["sha256"] = sha256(changed_payload).hexdigest()
                with self.assertRaises(module.MemoryActivationRejected):
                    module._admit_transitional_controller_unit(changed)

    def test_prior_child_name_requires_sealed_creator_lineage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            releases = Path(temporary)
            release_root = releases / product.ATTEMPT5_PRIOR_CONTROLLER_RELEASE
            release_root.mkdir(mode=0o555)
            commit = "1" * 40
            parent = "2" * 40
            tree = "3" * 40
            prior_name = "p07-owner-private-memory-transactional-deadbeefdeadbeef"
            document = {
                "deploy_commit": commit,
                "deploy_parent": parent,
                "deploy_tree": tree,
            }
            verified = {
                "source": {
                    "deploy_commit": commit,
                    "deploy_parent": parent,
                    "deploy_tree": tree,
                }
            }
            with mock.patch.object(
                module, "CONTROLLER_RELEASES_ROOT", releases
            ), mock.patch.object(
                module, "_canonical_release_json", return_value=document
            ), mock.patch.object(
                module,
                "_bounded_transitional_pairs",
                return_value=((commit, parent),),
            ) as bounded, mock.patch.object(
                module, "_verified_deploy_source_binding"
            ) as source_binding, mock.patch.object(
                module, "_historical_controller_authority", return_value=verified
            ), mock.patch.object(
                product,
                "_source_generated_memory_runtime",
                return_value={"archive_id": prior_name},
            ), mock.patch.object(
                product,
                "ATTEMPT5_PRIOR_ARCHIVE_CHILD_NAME_SHA256",
                sha256(prior_name.encode("ascii")).hexdigest(),
            ):
                self.assertEqual(
                    module._prior_attempt_archive_child_name(Path(temporary)),
                    prior_name,
                )
                bounded.assert_called_once_with(
                    Path(temporary),
                    upper=product.ARCHIVE_CHILD_CREATOR_LINEAGE_UPPER,
                )
                source_binding.assert_called_once_with(
                    release_root,
                    document,
                    Path(temporary),
                )
            with mock.patch.object(
                module, "CONTROLLER_RELEASES_ROOT", releases
            ), mock.patch.object(
                module, "_canonical_release_json", return_value=document
            ), mock.patch.object(
                module,
                "_bounded_transitional_pairs",
                return_value=((commit, parent),),
            ), mock.patch.object(
                module, "_verified_deploy_source_binding"
            ), mock.patch.object(
                module, "_historical_controller_authority", return_value=verified
            ), mock.patch.object(
                product,
                "_source_generated_memory_runtime",
                return_value={"archive_id": prior_name},
            ):
                with self.assertRaises(module.MemoryActivationRejected):
                    module._prior_attempt_archive_child_name(Path(temporary))

    def test_deploy_source_binding_uses_real_git_blobs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "deploy"
            release_root = base / ("a" * 64)
            repository.mkdir()
            release_root.mkdir()

            def git(*arguments: str) -> bytes:
                return module.subprocess.run(
                    ["/usr/bin/git", "-C", repository.as_posix(), *arguments],
                    check=True,
                    capture_output=True,
                ).stdout

            git("init", "-q")
            git("config", "user.name", "Phase F Test")
            git("config", "user.email", "phase-f@example.invalid")
            sources = (
                "scripts/activate_p07_owner_private_memory_v1.py",
                "scripts/build_p07_hybrid_live_releases_v1.py",
                "scripts/build_telegram_r5_controller_release_v1.py",
                "scripts/p07_owner_private_memory_production_plan.py",
                "scripts/telegram_r5_boot_resume.py",
            )
            destinations = (
                "activate_p07_owner_private_memory_v1.py",
                "source-authority/build_p07_hybrid_live_releases_v1.py",
                "source-authority/build_telegram_r5_controller_release_v1.py",
                "p07_owner_private_memory_production_plan.py",
                "telegram_r5_boot_resume.py",
            )
            for index, source in enumerate(sources):
                selected = repository / source
                selected.parent.mkdir(parents=True, exist_ok=True)
                selected.write_text(f"source-{index}\n", encoding="utf-8")
            git("add", ".")
            git("commit", "-q", "-m", "source")
            commit = git("rev-parse", "HEAD").decode().strip()
            tree = git("rev-parse", "HEAD^{tree}").decode().strip()
            rows: list[dict[str, object]] = []
            for source, destination in zip(sources, destinations):
                payload = (repository / source).read_bytes()
                blob = git("rev-parse", f"HEAD:{source}").decode().strip()
                row = {
                    "blob": blob,
                    "bytes": len(payload),
                    "content_sha256": sha256(payload).hexdigest(),
                    "destination": destination,
                    "installed_mode": "0444",
                    "mode": "100644",
                    "source": source,
                }
                rows.append(row)
                target = release_root / destination
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
                target.chmod(0o444)
            receipt = {
                "core_commit": product.ACCEPTED_CORE_COMMIT,
                "core_members": [],
                "core_tree": product.ACCEPTED_CORE_TREE,
                "deploy_commit": commit,
                "deploy_members": rows,
                "deploy_tree": tree,
                "member_count": len(rows),
                "schema": "myuna.telegram.r5-controller-corresponding-source.v2",
            }
            receipt_payload = module.canonical(receipt)
            (release_root / "CORRESPONDING_SOURCE.json").write_bytes(receipt_payload)
            (release_root / "CORRESPONDING_SOURCE.json").chmod(0o444)
            document = {
                "controller_builder": rows[2],
                "controller_builder_sha256": rows[2]["content_sha256"],
                "deploy_commit": commit,
                "deploy_tree": tree,
                "files": rows,
                "paired_builder": rows[1],
                "paired_builder_sha256": rows[1]["content_sha256"],
                "paired_source_receipt_sha256": sha256(receipt_payload).hexdigest(),
                "source_receipt": receipt,
            }
            module._verified_deploy_source_binding(
                release_root, document, repository
            )
            selected = release_root / destinations[0]
            selected.chmod(0o644)
            selected.write_bytes(b"substituted\n")
            selected.chmod(0o444)
            with self.assertRaises(module.MemoryActivationRejected):
                module._verified_deploy_source_binding(
                    release_root, document, repository
                )
            selected.chmod(0o644)
            selected.write_bytes((repository / sources[0]).read_bytes())
            selected.chmod(0o444)
            changed = copy.deepcopy(document)
            changed["files"][0]["blob"] = "0" * 40
            with self.assertRaises(module.MemoryActivationRejected):
                module._verified_deploy_source_binding(
                    release_root, changed, repository
                )

    def test_installer_unit_shape_rejects_before_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            regular = root / "regular"
            regular.write_bytes(b"unit\n")
            symlink = root / "symlink"
            symlink.symlink_to(regular)
            with self.assertRaises(module.MemoryActivationRejected) as linked:
                module._file_observation(symlink)
            self.assertEqual(linked.exception.code, "fixed_file_observation_rejected")

            directory = root / "directory"
            directory.mkdir()
            with self.assertRaises(module.MemoryActivationRejected) as partial:
                module._file_observation(directory)
            self.assertEqual(partial.exception.code, "fixed_file_observation_rejected")

            hardlink = root / "hardlink"
            os.link(regular, hardlink)
            with self.assertRaises(module.MemoryActivationRejected) as collided:
                module._file_observation(regular)
            self.assertEqual(
                collided.exception.code, "fixed_file_observation_rejected"
            )

    def test_checkpoint_all_immutable_subsets_are_fresh_and_distinct(self) -> None:
        prefixes: set[str] = set()
        for checkpoint in ("running", "stopped", "archived"):
            for mask in range(16):
                plan, selected, old_payloads = self.make_plan(
                    selected_present=checkpoint != "running"
                )
                current = copy.deepcopy(plan["observation"])
                if checkpoint != "running":
                    current["services"] = {
                        key: {"active": False, "identity": row["identity"]}
                        for key, row in current["services"].items()
                    }
                    current["old_container"]["active"] = False
                    current["network"]["member_ids"] = []
                if checkpoint == "archived":
                    current["old_container"] = {
                        "active": False,
                        "identity": None,
                        "name": product.CONTAINER_NAME,
                        "policy": "absent",
                        "state": "THIRD_STATE",
                    }
                    current["archive_name"] = {
                        "identity": "old-object",
                        "name": current["archive_name"]["name"],
                        "projection_sha256": "a" * 64,
                        "state": "TARGET",
                    }
                states = tuple(
                    "TARGET" if mask & (1 << index) else "OLD"
                    for index in range(4)
                )
                for key, state in zip(product.IMMUTABLE_ARTIFACTS, states):
                    row = current["releases"][key]
                    row["state"] = state
                    row["identity"] = (
                        (
                            selected["image"]
                            if key == "image"
                            else selected["releases"][key]
                        )["member_set_sha256"]
                        if state == "TARGET"
                        else None
                    )
                plan = product.build_fixed_plan(selected, current)
                effects = FixedEffects(selected, old_payloads, plan["observation"])
                if checkpoint != "running":
                    effects.old_active = False
                    effects.services = {
                        module.CORE_SERVICE: False,
                        module.RUNTIME_SOCKET: False,
                        module.RUNTIME_SERVICE: False,
                    }
                    effects.selected_root_exists = True
                if checkpoint == "archived":
                    effects.old_archived = True
                with self.patches(effects):
                    result = module.run_checkpointed_stage(
                        plan,
                        requested_stage=None,
                        supervised_start=False,
                    )
                expected_prefix = (
                    product.immutable_subset_prefix(states)
                    if "OLD" in states
                    else {
                        "running": "IMMUTABLE_TARGET",
                        "stopped": "OLD_CONTAINER_STOPPED",
                        "archived": "OLD_CONTAINER_ARCHIVED",
                    }[checkpoint]
                )
                expected_next = (
                    product.immutable_subset_next_stage(states)
                    if "OLD" in states
                    else product.CHECKPOINT_NEXT_STAGE[expected_prefix]
                )
                self.assertEqual(
                    result["prefix_before"], expected_prefix, (checkpoint, states)
                )
                self.assertEqual(
                    result["prefix_after"], expected_prefix, (checkpoint, states)
                )
                self.assertEqual(
                    result["next_stage"], expected_next, (checkpoint, states)
                )
                self.assertEqual(result["callbacks"], 0, (checkpoint, states))
                self.assertEqual(effects.calls, [], (checkpoint, states))
                prefixes.add(product.immutable_subset_prefix(states))
        self.assertEqual(len(prefixes), 16)

    def test_checkpoint_observed_non_linear_subset_publishes_only_runtime(self) -> None:
        plan, selected, old_payloads = self.stopped_old_plan()
        before_states = ("TARGET", "TARGET", "OLD", "TARGET")
        for key, state in zip(product.IMMUTABLE_ARTIFACTS, before_states):
            plan["observation"]["releases"][key]["state"] = state
            if state == "OLD":
                plan["observation"]["releases"][key]["identity"] = None
        plan = product.build_fixed_plan(selected, plan["observation"])
        after_observation = copy.deepcopy(plan["observation"])
        after_observation["releases"]["runtime"]["state"] = "TARGET"
        after_observation["releases"]["runtime"]["identity"] = selected[
            "releases"
        ]["runtime"]["member_set_sha256"]
        after_plan = product.build_fixed_plan(selected, after_observation)
        effects = FixedEffects(selected, old_payloads, plan["observation"])
        effects.old_active = False
        effects.selected_root_exists = True
        effects.services = {
            module.CORE_SERVICE: False,
            module.RUNTIME_SOCKET: False,
            module.RUNTIME_SERVICE: False,
        }
        with self.patches(effects), mock.patch.object(
            module, "_publish_release"
        ) as publish_release, mock.patch.object(
            module, "_publish_image"
        ) as publish_image, mock.patch.object(
            module, "_fresh_checkpoint_plan", return_value=after_plan
        ):
            result = module.run_checkpointed_stage(
                plan,
                requested_stage="STAGE_RUNTIME_RELEASE",
                supervised_start=False,
            )
        publish_release.assert_called_once_with(
            "runtime", selected["releases"]["runtime"]
        )
        publish_image.assert_not_called()
        self.assertEqual(result["callbacks"], 1)
        self.assertEqual(
            result["prefix_before"],
            product.immutable_subset_prefix(before_states),
        )
        self.assertEqual(result["prefix_after"], "OLD_CONTAINER_STOPPED")
        self.assertEqual(result["next_stage"], "ARCHIVE_EXACT_OLD_CONTAINER")
        self.assertEqual(effects.calls, [])

    def test_stopped_old_immutable_lost_return_never_replays_stop(self) -> None:
        plan, selected, old_payloads = self.stopped_old_plan()
        before_states = ("TARGET", "TARGET", "OLD", "TARGET")
        for key, state in zip(product.IMMUTABLE_ARTIFACTS, before_states):
            plan["observation"]["releases"][key]["state"] = state
            if state == "OLD":
                plan["observation"]["releases"][key]["identity"] = None
        plan = product.build_fixed_plan(selected, plan["observation"])
        after = copy.deepcopy(plan["observation"])
        after["releases"]["runtime"] = {
            "identity": selected["releases"]["runtime"]["member_set_sha256"],
            "state": "TARGET",
        }
        after_plan = product.build_fixed_plan(selected, after)
        effects = FixedEffects(selected, old_payloads, plan["observation"])
        effects.old_active = False
        effects.selected_root_exists = True
        effects.services = {
            module.CORE_SERVICE: False,
            module.RUNTIME_SOCKET: False,
            module.RUNTIME_SERVICE: False,
        }
        with self.patches(effects), mock.patch.object(
            module,
            "_publish_release",
            side_effect=module.MemoryActivationRejected("injected_publish_lost_return"),
        ), mock.patch.object(
            module, "_fresh_checkpoint_plan", return_value=after_plan
        ), mock.patch.object(module, "_stop_old_container") as stopped, mock.patch.object(
            module, "_archive_old_container"
        ) as archived:
            result = module.run_checkpointed_stage(
                plan,
                requested_stage="STAGE_RUNTIME_RELEASE",
                supervised_start=False,
            )
        stopped.assert_not_called()
        archived.assert_not_called()
        self.assertEqual(result["status"], "STAGE_TARGET")
        self.assertEqual(result["reason"], "lost_return_reobserved_target")
        self.assertEqual(result["callbacks"], 1)
        self.assertEqual(result["prefix_after"], "OLD_CONTAINER_STOPPED")
        self.assertEqual(result["next_stage"], "ARCHIVE_EXACT_OLD_CONTAINER")

    def test_checkpoint_each_immutable_third_state_rejects_before_callback(self) -> None:
        for hostile_index in range(4):
            plan, selected, old_payloads = self.make_plan()
            for index, key in enumerate(product.IMMUTABLE_ARTIFACTS):
                plan["observation"]["releases"][key]["state"] = (
                    "THIRD_STATE" if index == hostile_index else "OLD"
                )
                if index != hostile_index:
                    plan["observation"]["releases"][key]["identity"] = None
            plan = product.build_fixed_plan(selected, plan["observation"])
            effects = FixedEffects(selected, old_payloads, plan["observation"])
            with self.patches(effects):
                with self.assertRaises(module.MemoryActivationRejected) as raised:
                    module.run_checkpointed_stage(
                        plan,
                        requested_stage=None,
                        supervised_start=False,
                    )
            self.assertEqual(
                raised.exception.code,
                "fixed_checkpoint_third_state_rejected",
            )
            self.assertEqual(effects.calls, [])

    def test_checkpoint_substituted_immutable_identity_rejects(self) -> None:
        plan, selected, _old_payloads = self.make_plan()
        plan["observation"]["releases"]["runtime"]["identity"] = "substituted"
        with self.assertRaises(product.ProductionPlanRejected):
            product.build_fixed_plan(selected, plan["observation"])

    def test_checkpoint_observe_only_and_receipt_non_authority(self) -> None:
        plan, selected, old_payloads = self.make_plan()
        effects = FixedEffects(selected, old_payloads, plan["observation"])
        with self.patches(effects):
            result = module.run_checkpointed_stage(
                plan,
                requested_stage=None,
                supervised_start=False,
            )
            with self.assertRaises(module.MemoryActivationRejected):
                module.run_checkpointed_stage(
                    plan,
                    requested_stage="QUIESCE_RUNTIME_SOCKET",
                    supervised_start=False,
                )
        self.assertEqual(result["prefix_before"], "IMMUTABLE_TARGET")
        self.assertEqual(result["prefix_after"], "IMMUTABLE_TARGET")
        self.assertEqual(result["next_stage"], "QUIESCE_RUNTIME_SERVICE")
        self.assertEqual(result["callbacks"], 0)
        self.assertEqual(result["stage"], "OBSERVE_ONLY")
        self.assertFalse(result["private_content_read"])
        self.assertEqual(effects.calls, [])

    def test_checkpoint_pre_callback_observation_failure_reports_zero(self) -> None:
        selected = authority()
        with mock.patch.object(
            module.os,
            "open",
            return_value=91,
        ), mock.patch.object(module.os, "close"), mock.patch.object(
            module.fcntl,
            "flock",
        ), mock.patch.object(
            module,
            "load_installed_source_authority",
            return_value=selected,
        ), mock.patch.object(
            module,
            "_fresh_checkpoint_plan",
            side_effect=module.MemoryActivationRejected(
                "fixed_observation_unavailable"
            ),
        ), mock.patch("builtins.print") as printed:
            code = module.fixed_owner_entry(supervised_start=False)
        payload = json.loads(printed.call_args.args[0])
        self.assertEqual(code, 1)
        self.assertEqual(payload["callbacks"], 0)
        self.assertEqual(payload["status"], "rejected")
        self.assertEqual(payload["reason"], "fixed_observation_unavailable")

    def test_checkpoint_invocation_performs_one_exact_stage(self) -> None:
        plan, selected, old_payloads = self.make_plan()
        effects = FixedEffects(selected, old_payloads, plan["observation"])

        def after_stop(_authority: dict[str, object]) -> dict[str, object]:
            current = copy.deepcopy(plan["observation"])
            current["services"]["runtime"] = effects.service_observation(
                module.RUNTIME_SERVICE
            )
            return product.build_fixed_plan(selected, current)

        with self.patches(effects), mock.patch.object(
            module,
            "_fresh_checkpoint_plan",
            side_effect=after_stop,
        ):
            result = module.run_checkpointed_stage(
                plan,
                requested_stage="QUIESCE_RUNTIME_SERVICE",
                supervised_start=False,
            )
        self.assertEqual(effects.calls, ["stop:" + module.RUNTIME_SERVICE])
        self.assertEqual(result["callbacks"], 1)
        self.assertEqual(result["prefix_before"], "IMMUTABLE_TARGET")
        self.assertEqual(result["prefix_after"], "RUNTIME_SERVICE_QUIESCED")
        self.assertEqual(result["next_stage"], "QUIESCE_RUNTIME_SOCKET")
        self.assertEqual(result["status"], "STAGE_TARGET")

    def test_checkpoint_service_effect_observation_failure_is_terminal(self) -> None:
        plan, selected, old_payloads = self.make_plan()
        effects = FixedEffects(selected, old_payloads, plan["observation"])
        with self.patches(effects), mock.patch.object(
            module,
            "_fresh_checkpoint_plan",
            side_effect=module.MemoryActivationRejected(
                "injected_post_effect_observation_failure"
            ),
        ):
            result = module.run_checkpointed_stage(
                plan,
                requested_stage="QUIESCE_RUNTIME_SERVICE",
                supervised_start=False,
            )
        self.assertEqual(effects.calls, ["stop:" + module.RUNTIME_SERVICE])
        self.assertEqual(result["status"], "SUPERVISED_MANUAL_REQUIRED")
        self.assertEqual(result["callbacks"], 1)
        self.assertEqual(result["stage"], "QUIESCE_RUNTIME_SERVICE")
        self.assertFalse(result["writer_boundary"])
        self.assertIsNone(result["next_stage"])
        self.assertEqual(
            result["reason"],
            "post_effect_observation_unestablished",
        )
        self.assertNotIn("prefix_after", result)
        self.assertNotIn("observation_after_sha256", result)

    def test_checkpoint_file_failure_restores_only_same_invocation(self) -> None:
        plan, selected, old_payloads = self.make_plan()
        current = copy.deepcopy(plan["observation"])
        current["services"] = {
            key: {"active": False, "identity": row["identity"]}
            for key, row in current["services"].items()
        }
        current["archive_root"]["selected_state"] = "TARGET"
        current["archive_root"]["selected_identity"] = "selected-empty-root"
        current["old_container"] = {
            "active": False,
            "identity": None,
            "name": product.CONTAINER_NAME,
            "policy": "absent",
            "state": "THIRD_STATE",
        }
        current["archive_name"] = {
            "identity": "old-object",
            "name": current["archive_name"]["name"],
            "projection_sha256": "a" * 64,
            "state": "TARGET",
        }
        current["network"]["member_ids"] = []
        plan = product.build_fixed_plan(selected, current)
        effects = FixedEffects(selected, old_payloads, plan["observation"])
        effects.services = {
            module.CORE_SERVICE: False,
            module.RUNTIME_SOCKET: False,
            module.RUNTIME_SERVICE: False,
        }
        effects.selected_root_exists = True
        effects.old_active = False
        effects.old_archived = True
        effects.fail_install_once = True
        with self.patches(effects), mock.patch.object(
            module,
            "_fresh_checkpoint_plan",
            return_value=plan,
        ):
            result = module.run_checkpointed_stage(
                plan,
                requested_stage="INSTALL_SEVEN_TARGET_FILES_AND_RELOAD",
                supervised_start=False,
            )
        self.assertEqual(result["status"], "STAGE_FAILED_CHECKPOINT_RESTORED")
        self.assertEqual(result["prefix_before"], "OLD_CONTAINER_ARCHIVED")
        self.assertEqual(result["prefix_after"], "OLD_CONTAINER_ARCHIVED")
        self.assertEqual(result["local_reverse"], "RESTORED_PRECEDING_CHECKPOINT")
        first_path = sorted(product.FILE_ROLES)[0]
        self.assertEqual(effects.files[first_path], old_payloads[first_path])
        self.assertNotIn("remove-selected-root", effects.calls)
        self.assertNotIn("restore-old:old-object", effects.calls)

    def test_checkpoint_file_reverse_failure_is_truthful_manual_stop(self) -> None:
        plan, selected, old_payloads = self.make_plan()
        current = copy.deepcopy(plan["observation"])
        current["services"] = {
            key: {"active": False, "identity": row["identity"]}
            for key, row in current["services"].items()
        }
        current["archive_root"]["selected_state"] = "TARGET"
        current["archive_root"]["selected_identity"] = "selected-empty-root"
        current["old_container"] = {
            "active": False,
            "identity": None,
            "name": product.CONTAINER_NAME,
            "policy": "absent",
            "state": "THIRD_STATE",
        }
        current["archive_name"] = {
            "identity": "old-object",
            "name": current["archive_name"]["name"],
            "projection_sha256": "a" * 64,
            "state": "TARGET",
        }
        current["network"]["member_ids"] = []
        plan = product.build_fixed_plan(selected, current)
        effects = FixedEffects(selected, old_payloads, plan["observation"])
        effects.services = {
            module.CORE_SERVICE: False,
            module.RUNTIME_SOCKET: False,
            module.RUNTIME_SERVICE: False,
        }
        effects.selected_root_exists = True
        effects.old_active = False
        effects.old_archived = True
        install_attempts = 0

        def fail_stage_and_reverse(path: str, row: dict[str, object]) -> None:
            nonlocal install_attempts
            install_attempts += 1
            effects.install_file(path, row)
            raise module.MemoryActivationRejected(
                "injected_stage_failure"
                if install_attempts == 1
                else "injected_reverse_failure"
            )

        def fail_reverse_remove(path: str) -> None:
            effects.remove_file(path)
            raise module.MemoryActivationRejected(
                "injected_reverse_failure"
            )

        with self.patches(effects), mock.patch.object(
            module,
            "_install_target_file",
            side_effect=fail_stage_and_reverse,
        ), mock.patch.object(
            module,
            "_remove_target_file",
            side_effect=fail_reverse_remove,
        ):
            result = module.run_checkpointed_stage(
                plan,
                requested_stage="INSTALL_SEVEN_TARGET_FILES_AND_RELOAD",
                supervised_start=False,
            )
        self.assertEqual(result["status"], "SUPERVISED_MANUAL_REQUIRED")
        self.assertEqual(result["callbacks"], 2)
        self.assertEqual(result["local_reverse"], "FAILED_OR_UNESTABLISHED")
        self.assertFalse(result["writer_boundary"])
        self.assertIsNone(result["next_stage"])
        self.assertNotIn("prefix_after", result)
        self.assertNotIn("observation_after_sha256", result)
        self.assertEqual(install_attempts, 1)
        self.assertEqual(len(effects.calls), 2)

    def test_checkpoint_selected_root_internal_failure_returns_predecessor(self) -> None:
        plan, selected, old_payloads = self.make_plan()
        current = copy.deepcopy(plan["observation"])
        current["services"] = {
            key: {"active": False, "identity": row["identity"]}
            for key, row in current["services"].items()
        }
        plan = product.build_fixed_plan(selected, current)
        effects = FixedEffects(selected, old_payloads, plan["observation"])
        effects.services = {
            module.CORE_SERVICE: False,
            module.RUNTIME_SOCKET: False,
            module.RUNTIME_SERVICE: False,
        }

        def create_then_restore(authority_value: object, captured: object) -> None:
            identity = effects.create_root(authority_value, captured)
            assert identity is not None
            effects.remove_root(authority_value, identity)
            raise module.MemoryActivationRejected("injected_root_failure")

        with self.patches(effects), mock.patch.object(
            module,
            "_create_selected_runtime_root",
            side_effect=create_then_restore,
        ), mock.patch.object(module, "_fresh_checkpoint_plan", return_value=plan):
            result = module.run_checkpointed_stage(
                plan,
                requested_stage="CREATE_SELECTED_RUNTIME_ROOT",
                supervised_start=False,
            )
        self.assertEqual(result["status"], "STAGE_FAILED_CHECKPOINT_RESTORED")
        self.assertFalse(effects.selected_root_exists)
        self.assertEqual(effects.calls, ["create-selected-root", "remove-selected-root"])

    def test_checkpoint_third_state_rejects_before_callback(self) -> None:
        path = sorted(product.FILE_ROLES)[0]
        plan, selected, old_payloads = self.make_plan(
            files_old=False,
            third_path=path,
        )
        effects = FixedEffects(selected, old_payloads, plan["observation"])
        with self.patches(effects):
            with self.assertRaises(module.MemoryActivationRejected):
                module.run_checkpointed_stage(
                    plan,
                    requested_stage=None,
                    supervised_start=False,
                )
        self.assertEqual(effects.calls, [])

    def test_checkpoint_writer_stage_is_one_dispatch_and_terminal(self) -> None:
        plan, selected, old_payloads = self.make_plan(
            files_old=False,
            selected_present=True,
        )
        ready = copy.deepcopy(plan["observation"])
        ready["services"] = {
            "core": {"active": True, "identity": ready["services"]["core"]["identity"]},
            "runtime": {"active": False, "identity": ready["services"]["runtime"]["identity"]},
            "socket": {"active": True, "identity": ready["services"]["socket"]["identity"]},
        }
        ready["archive_name"] = {
            "identity": "old-object",
            "name": ready["archive_name"]["name"],
            "projection_sha256": "a" * 64,
            "state": "TARGET",
        }
        ready["old_container"] = {
            "active": False,
            "identity": "target-object",
            "name": product.CONTAINER_NAME,
            "policy": module.PRE_DISPATCH_POLICY,
            "state": "THIRD_STATE",
        }
        ready["target_container"] = {
            "active": False,
            "identity": "target-object",
            "name": product.CONTAINER_NAME,
            "policy": module.PRE_DISPATCH_POLICY,
            "state": "TARGET",
        }
        ready["network"]["member_ids"] = []
        plan = product.build_fixed_plan(selected, ready)
        effects = FixedEffects(selected, old_payloads, plan["observation"])
        effects.old_active = False
        effects.old_archived = True
        effects.target_exists = True
        effects.target_policy = module.PRE_DISPATCH_POLICY
        effects.services = {
            module.CORE_SERVICE: True,
            module.RUNTIME_SOCKET: True,
            module.RUNTIME_SERVICE: False,
        }

        def after_start(_authority: dict[str, object]) -> dict[str, object]:
            current = copy.deepcopy(ready)
            current["old_container"]["policy"] = module.DISPATCH_FENCE_POLICY
            current["target_container"]["active"] = True
            current["target_container"]["policy"] = module.DISPATCH_FENCE_POLICY
            current["network"]["member_ids"] = ["target-object"]
            return product.build_fixed_plan(selected, current)

        with self.patches(effects), mock.patch.object(
            module,
            "_effective_units_state",
            return_value="TARGET",
        ), mock.patch.object(
            module,
            "_fresh_checkpoint_plan",
            side_effect=after_start,
        ):
            result = module.run_checkpointed_stage(
                plan,
                requested_stage="ARM_AND_START_TARGET_ONCE",
                supervised_start=True,
            )
        self.assertEqual(
            effects.calls,
            ["policy:on-failure:3", "start-target"],
        )
        self.assertEqual(result["prefix_after"], "POST_WRITER_MANUAL")
        self.assertEqual(result["callbacks"], 2)
        self.assertTrue(result["writer_boundary"])
        self.assertEqual(result["local_reverse"], "FORBIDDEN_POST_WRITER")

    def test_checkpoint_writer_observation_failure_has_no_fake_poststate(self) -> None:
        plan, selected, old_payloads = self.make_plan(
            files_old=False,
            selected_present=True,
        )
        ready = copy.deepcopy(plan["observation"])
        ready["services"] = {
            "core": {
                "active": True,
                "identity": ready["services"]["core"]["identity"],
            },
            "runtime": {
                "active": False,
                "identity": ready["services"]["runtime"]["identity"],
            },
            "socket": {
                "active": True,
                "identity": ready["services"]["socket"]["identity"],
            },
        }
        ready["archive_name"] = {
            "identity": "old-object",
            "name": ready["archive_name"]["name"],
            "projection_sha256": "a" * 64,
            "state": "TARGET",
        }
        ready["old_container"] = {
            "active": False,
            "identity": "target-object",
            "name": product.CONTAINER_NAME,
            "policy": module.PRE_DISPATCH_POLICY,
            "state": "THIRD_STATE",
        }
        ready["target_container"] = {
            "active": False,
            "identity": "target-object",
            "name": product.CONTAINER_NAME,
            "policy": module.PRE_DISPATCH_POLICY,
            "state": "TARGET",
        }
        ready["network"]["member_ids"] = []
        plan = product.build_fixed_plan(selected, ready)
        effects = FixedEffects(selected, old_payloads, plan["observation"])
        effects.old_active = False
        effects.old_archived = True
        effects.target_exists = True
        effects.target_policy = module.PRE_DISPATCH_POLICY
        effects.services = {
            module.CORE_SERVICE: True,
            module.RUNTIME_SOCKET: True,
            module.RUNTIME_SERVICE: False,
        }
        with self.patches(effects), mock.patch.object(
            module,
            "_effective_units_state",
            return_value="TARGET",
        ), mock.patch.object(
            module,
            "_fresh_checkpoint_plan",
            side_effect=module.MemoryActivationRejected(
                "injected_writer_terminal_observation_failure"
            ),
        ):
            result = module.run_checkpointed_stage(
                plan,
                requested_stage="ARM_AND_START_TARGET_ONCE",
                supervised_start=True,
            )
        self.assertEqual(effects.calls, ["policy:on-failure:3", "start-target"])
        self.assertEqual(result["status"], "SUPERVISED_MANUAL_REQUIRED")
        self.assertEqual(result["callbacks"], 2)
        self.assertTrue(result["writer_boundary"])
        self.assertEqual(result["local_reverse"], "FORBIDDEN_POST_WRITER")
        self.assertIsNone(result["next_stage"])
        self.assertNotIn("prefix_after", result)
        self.assertNotIn("observation_after_sha256", result)

    def stopped_old_plan(
        self,
    ) -> tuple[dict[str, object], dict[str, object], dict[str, bytes | None]]:
        plan, selected, old_payloads = self.make_plan(selected_present=True)
        current = copy.deepcopy(plan["observation"])
        current["services"] = {
            key: {"active": False, "identity": row["identity"]}
            for key, row in current["services"].items()
        }
        current["old_container"]["active"] = False
        current["network"]["member_ids"] = []
        return product.build_fixed_plan(selected, current), selected, old_payloads

    def test_prior_archive_child_converges_atomically_to_same_stable_inode(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            os.chown(root, product.MEMORY_RUNTIME_UID, product.MEMORY_RUNTIME_GID)
            root.chmod(0o700)
            legacy = root / product.LEGACY_MEMORY_ARCHIVE_ID
            prior_name = "p07-owner-private-memory-transactional-deadbeefdeadbeef"
            prior = root / prior_name
            for child in (legacy, prior):
                child.mkdir(mode=0o700)
                os.chown(
                    child,
                    product.MEMORY_RUNTIME_UID,
                    product.MEMORY_RUNTIME_GID,
                )
                child.chmod(0o700)
            parent_identity = module._directory_identity(root.stat())
            prior_identity = module._directory_identity(prior.stat())
            old = {
                "active": False,
                "identity": product.ATTEMPT5_OLD_CONTAINER_ID,
                "state": "TARGET",
            }
            absent = {
                "active": False,
                "identity": None,
                "name": product.CONTAINER_NAME,
                "policy": "absent",
                "state": "OLD",
            }
            with mock.patch.object(
                product, "MEMORY_RUNTIME_ROOT", root.as_posix()
            ), mock.patch.object(
                product, "ATTEMPT5_ARCHIVE_PARENT_IDENTITY", parent_identity
            ), mock.patch.object(
                product, "ATTEMPT5_PRIOR_ARCHIVE_CHILD_IDENTITY", prior_identity
            ), mock.patch.object(
                product,
                "ATTEMPT5_PRIOR_ARCHIVE_CHILD_NAME_SHA256",
                sha256(prior_name.encode("ascii")).hexdigest(),
            ), mock.patch.object(
                module, "_prior_attempt_archive_child_name", return_value=prior_name
            ), mock.patch.object(
                module, "_old_container_observation", return_value=old
            ), mock.patch.object(
                module, "_target_container_observation", return_value=absent
            ):
                selected = authority()
                before = module._archive_root_observation(selected)
                self.assertEqual(before["selected_state"], "OLD")
                self.assertEqual(before["selected_identity"], prior_identity)
                original = prior.stat()
                result = module._converge_archive_child_name(selected, before)
                stable = root / product.stable_attempt_archive_child_name()
                self.assertFalse(prior.exists())
                self.assertTrue(stable.is_dir())
                self.assertEqual(
                    (stable.stat().st_dev, stable.stat().st_ino),
                    (original.st_dev, original.st_ino),
                )
                self.assertEqual(result, prior_identity)
                after = module._archive_root_observation(selected)
                self.assertEqual(after["selected_state"], "TARGET")
                self.assertEqual(after["selected_identity"], prior_identity)
                stable.chmod(0o755)
                self.assertEqual(
                    module._archive_root_observation(selected)["state"],
                    "THIRD_STATE",
                )
                stable.chmod(0o700)
                generated = stable / "generated-hostile"
                generated.write_bytes(b"generated\n")
                self.assertEqual(
                    module._archive_root_observation(selected)["state"],
                    "THIRD_STATE",
                )
                generated.unlink()
                prior.mkdir(mode=0o700)
                os.chown(
                    prior,
                    product.MEMORY_RUNTIME_UID,
                    product.MEMORY_RUNTIME_GID,
                )
                self.assertEqual(
                    module._archive_root_observation(selected)["state"],
                    "THIRD_STATE",
                )

    def test_archive_child_convergence_is_sole_stage_and_stop_is_never_replayed(
        self,
    ) -> None:
        after, selected, _old_payloads = self.stopped_old_plan()
        before_observation = copy.deepcopy(after["observation"])
        before_observation["archive_root"]["selected_state"] = "OLD"
        before_observation["archive_root"]["selected_identity"] = (
            product.ATTEMPT5_PRIOR_ARCHIVE_CHILD_IDENTITY
        )
        before = product.build_fixed_plan(selected, before_observation)
        self.assertEqual(
            module._checkpoint_prefix(before),
            "ARCHIVE_CHILD_NAME_CONVERGENCE_REQUIRED",
        )
        calls: list[str] = []
        with mock.patch.object(
            module,
            "_converge_archive_child_name",
            side_effect=lambda *_args: calls.append("converge"),
        ), mock.patch.object(
            module, "_fresh_checkpoint_plan", return_value=after
        ), mock.patch.object(
            module, "_stop_old_container"
        ) as stopped, mock.patch.object(
            module, "_archive_old_container"
        ) as archived:
            result = module.run_checkpointed_stage(
                before,
                requested_stage="CONVERGE_ARCHIVE_CHILD_NAME",
                supervised_start=False,
            )
        self.assertEqual(calls, ["converge"])
        stopped.assert_not_called()
        archived.assert_not_called()
        self.assertEqual(result["callbacks"], 1)
        self.assertEqual(result["prefix_after"], "OLD_CONTAINER_STOPPED")
        self.assertEqual(result["next_stage"], "ARCHIVE_EXACT_OLD_CONTAINER")

    def test_archive_child_convergence_lost_return_and_collision_fail_closed(
        self,
    ) -> None:
        after, selected, _old_payloads = self.stopped_old_plan()
        before_observation = copy.deepcopy(after["observation"])
        before_observation["archive_root"]["selected_state"] = "OLD"
        before_observation["archive_root"]["selected_identity"] = (
            product.ATTEMPT5_PRIOR_ARCHIVE_CHILD_IDENTITY
        )
        before = product.build_fixed_plan(selected, before_observation)
        failure = module.MemoryActivationRejected("injected_after_rename")
        with mock.patch.object(
            module, "_converge_archive_child_name", side_effect=failure
        ), mock.patch.object(
            module, "_fresh_checkpoint_plan", return_value=after
        ), mock.patch.object(module, "_stop_old_container") as stopped:
            result = module.run_checkpointed_stage(
                before,
                requested_stage="CONVERGE_ARCHIVE_CHILD_NAME",
                supervised_start=False,
            )
        stopped.assert_not_called()
        self.assertEqual(result["status"], "STAGE_TARGET")
        self.assertEqual(result["reason"], "lost_return_reobserved_target")
        self.assertEqual(result["callbacks"], 1)

        collision = copy.deepcopy(before)
        collision["observation"]["archive_root"]["selected_state"] = "THIRD_STATE"
        collision["plan_sha256"] = product.digest(
            "phase_f_fixed_plan",
            {key: collision[key] for key in collision if key != "plan_sha256"},
        )
        with mock.patch.object(module, "_converge_archive_child_name") as converge:
            with self.assertRaises(
                (module.MemoryActivationRejected, product.ProductionPlanRejected)
            ):
                module.run_checkpointed_stage(
                    collision,
                    requested_stage="CONVERGE_ARCHIVE_CHILD_NAME",
                    supervised_start=False,
                )
        converge.assert_not_called()

    def test_old_container_projection_binds_every_fixed_configuration_field(
        self,
    ) -> None:
        plan, selected, old_payloads = self.make_plan(selected_present=True)
        effects = FixedEffects(selected, old_payloads, plan["observation"])
        exact = effects.container(product.CONTAINER_NAME)
        with mock.patch.object(module, "_container_or_absent", return_value=exact):
            self.assertEqual(module._old_container_observation()["state"], "TARGET")
        stopped = copy.deepcopy(exact)
        stopped["active"] = False
        with mock.patch.object(module, "_container_or_absent", return_value=stopped):
            observed = module._old_container_observation()
        self.assertEqual(observed["state"], "TARGET")
        self.assertFalse(observed["active"])
        substitutions = {
            "command_digest": "substituted",
            "host_config_digest": "substituted",
            "identity": "recreated-object",
            "image": "substituted",
            "mounts_digest": "substituted",
            "name": "renamed-container",
            "network_names": ["substituted-network"],
            "networks_digest": "substituted",
            "plan_digest": "f" * 64,
            "policy": "always",
            "project": "substituted",
            "service": "substituted",
            "target_config_digest": "f" * 64,
            "user": "0:0",
        }
        for field, value in substitutions.items():
            hostile = copy.deepcopy(stopped)
            hostile[field] = value
            with self.subTest(field=field), mock.patch.object(
                module, "_container_or_absent", return_value=hostile
            ):
                self.assertEqual(
                    module._old_container_observation()["state"],
                    "THIRD_STATE",
                )
        missing = copy.deepcopy(stopped)
        missing.pop("command_digest")
        with mock.patch.object(module, "_container_or_absent", return_value=missing):
            self.assertEqual(
                module._old_container_observation()["state"],
                "THIRD_STATE",
            )

    def test_target_role_inventory_is_independent_of_shared_name_vacancy(
        self,
    ) -> None:
        selected = product.validate_source_authority(authority())
        target_config = selected["files"][
            "/etc/myuna-telegram-gateway/r5-resume-v1.json"
        ]["payload_sha256"]
        exact = {
            "active": False,
            "identity": "target-object",
            "image": selected["image"]["reference"],
            "name": product.CONTAINER_NAME,
            "network_names": [product.NETWORK_NAME],
            "plan_digest": "f" * 64,
            "policy": module.PRE_DISPATCH_POLICY,
            "project": module.resume.COMPOSE_PROJECT,
            "service": module.resume.COMPOSE_SERVICE,
            "target_config_digest": target_config,
            "user": product.TARGET_USER,
        }
        with mock.patch.object(module, "_command", return_value=""), mock.patch.object(
            module, "_container_or_absent"
        ) as observed:
            absent = module._target_container_observation(selected)
        observed.assert_not_called()
        self.assertEqual(absent["state"], "OLD")
        self.assertIsNone(absent["identity"])

        with mock.patch.object(
            module, "_command", return_value=product.CONTAINER_NAME
        ), mock.patch.object(
            module, "_container_or_absent", return_value=exact
        ):
            current = module._target_container_observation(selected)
        self.assertEqual(current["state"], "TARGET")
        self.assertEqual(current["name"], product.CONTAINER_NAME)

        elsewhere = dict(exact, name="unexpected-target-role")
        with mock.patch.object(
            module, "_command", return_value="unexpected-target-role"
        ), mock.patch.object(
            module, "_container_or_absent", return_value=elsewhere
        ):
            displaced = module._target_container_observation(selected)
        self.assertEqual(displaced["state"], "TARGET")
        self.assertNotEqual(displaced["name"], product.CONTAINER_NAME)

        with mock.patch.object(
            module, "_command", return_value="target-a\ntarget-b"
        ):
            ambiguous = module._target_container_observation(selected)
        self.assertEqual(ambiguous["state"], "THIRD_STATE")
        self.assertIsNone(ambiguous["identity"])

    def test_running_and_stopped_old_network_membership_are_state_specific(
        self,
    ) -> None:
        stopped, selected, old_payloads = self.stopped_old_plan()
        self.assertEqual(module._checkpoint_prefix(stopped), "OLD_CONTAINER_STOPPED")
        self.assertEqual(
            product.CHECKPOINT_NEXT_STAGE["OLD_CONTAINER_STOPPED"],
            "ARCHIVE_EXACT_OLD_CONTAINER",
        )
        for members in (["old-object"], ["unexpected-object"]):
            hostile = copy.deepcopy(stopped)
            hostile["observation"]["network"]["member_ids"] = members
            hostile = product.build_fixed_plan(selected, hostile["observation"])
            with self.subTest(stopped_members=members), self.assertRaises(
                module.MemoryActivationRejected
            ):
                module._checkpoint_prefix(hostile)

        running = copy.deepcopy(stopped)
        running["observation"]["old_container"]["active"] = True
        running["observation"]["network"]["member_ids"] = ["old-object"]
        running = product.build_fixed_plan(selected, running["observation"])
        self.assertEqual(module._checkpoint_prefix(running), "SELECTED_ROOT_TARGET")
        self.assertEqual(
            product.CHECKPOINT_NEXT_STAGE["SELECTED_ROOT_TARGET"],
            "STOP_EXACT_OLD_CONTAINER",
        )
        running_empty = copy.deepcopy(running)
        running_empty["observation"]["network"]["member_ids"] = []
        running_empty = product.build_fixed_plan(
            selected, running_empty["observation"]
        )
        with self.assertRaises(module.MemoryActivationRejected):
            module._checkpoint_prefix(running_empty)

        target_present = copy.deepcopy(stopped)
        target_present["observation"]["old_container"]["state"] = "THIRD_STATE"
        target_present["observation"]["target_container"] = {
            "active": False,
            "identity": "target-object",
            "name": product.CONTAINER_NAME,
            "policy": module.PRE_DISPATCH_POLICY,
            "state": "TARGET",
        }
        target_present = product.build_fixed_plan(
            selected, target_present["observation"]
        )
        with self.assertRaises(module.MemoryActivationRejected):
            module._checkpoint_prefix(target_present)

    def test_stopped_old_recovery_archives_without_replaying_stop(self) -> None:
        stopped, selected, old_payloads = self.stopped_old_plan()
        effects = FixedEffects(selected, old_payloads, stopped["observation"])
        effects.old_active = False
        effects.selected_root_exists = True
        after = copy.deepcopy(stopped["observation"])
        after["archive_name"] = {
            "identity": "old-object",
            "name": after["archive_name"]["name"],
            "projection_sha256": "a" * 64,
            "state": "TARGET",
        }
        after["old_container"] = {
            "active": False,
            "identity": None,
            "name": product.CONTAINER_NAME,
            "policy": "absent",
            "state": "THIRD_STATE",
        }
        after["network"]["member_ids"] = []
        after_plan = product.build_fixed_plan(selected, after)
        with self.patches(effects), mock.patch.object(
            module, "_fresh_checkpoint_plan", return_value=after_plan
        ):
            result = module.run_checkpointed_stage(
                stopped,
                requested_stage="ARCHIVE_EXACT_OLD_CONTAINER",
                supervised_start=False,
            )
        self.assertEqual(effects.calls, ["archive-old:old-object"])
        self.assertNotIn("stop-old:old-object", effects.calls)
        self.assertEqual(result["prefix_before"], "OLD_CONTAINER_STOPPED")
        self.assertEqual(result["prefix_after"], "OLD_CONTAINER_ARCHIVED")
        self.assertEqual(result["callbacks"], 1)

    def test_target_create_seam_consumes_only_plan_owned_effect_projection(self) -> None:
        selected = authority(19001)
        current, _old_hashes, _old_payloads = observation(selected)
        network = module.resume.PhaseFNetworkProjection(
            network_id="network-object",
            name=product.NETWORK_NAME,
            driver="bridge",
            internal=False,
            attachable=False,
            ingress=False,
            enable_ipv6=False,
            options_digest="1" * 64,
            labels_digest="2" * 64,
            ipam_digest="3" * 64,
            member_container_ids=(),
        )
        archive = module.resume.PhaseFContainerProjection(
            container_id=product.ATTEMPT5_OLD_CONTAINER_ID,
            name=current["archive_name"]["name"],
            image="frozen-old-image",
            status="exited",
            health="",
            restart_policy="on-failure",
            restart_maximum_retry_count=3,
            project="frozen-old-project",
            service="frozen-old-service",
            plan_digest="",
            target_config_digest="",
            user="988:982",
            command_digest="4" * 64,
            host_config_digest="5" * 64,
            mounts_digest="6" * 64,
            networks_digest="7" * 64,
            network_names=(product.NETWORK_NAME,),
        )
        current["network"]["member_ids"] = []
        current["network"]["projection_sha256"] = (
            module.resume.phase_f_network_identity_sha256(network)
        )
        current["archive_name"] = {
            "identity": archive.container_id,
            "name": archive.name,
            "projection_sha256": module.resume.phase_f_container_identity_sha256(archive),
            "state": "TARGET",
        }
        current["old_container"] = {
            "active": False,
            "identity": None,
            "name": product.CONTAINER_NAME,
            "policy": "absent",
            "state": "THIRD_STATE",
        }
        plan = product.build_fixed_plan(selected, current)
        captured: list[module.resume.PhaseFTargetContainer] = []

        def create(
            target: module.resume.PhaseFTargetContainer,
            **_kwargs: object,
        ) -> None:
            captured.append(target)

        with mock.patch.object(
            module.resume, "phase_f_network_projection", return_value=network
        ), mock.patch.object(
            module.resume, "phase_f_container_projection", return_value=archive
        ), mock.patch.object(
            module.resume, "phase_f_create_target_stopped", side_effect=create
        ) as create_call:
            module._create_target_container(plan)
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0].effect, plan["target_effect"])
        self.assertEqual(captured[0].plan_digest, product.ATTEMPT5_PRODUCT_ENTRY_PLAN_SHA256)
        self.assertEqual(
            plan["target_effect"]["archive_container_id"],
            archive.container_id,
        )
        self.assertIsNone(plan["observation"]["old_container"]["identity"])
        create_call.assert_called_once()

    def attempt5_archived_plan(self) -> dict[str, object]:
        plan, selected, _old_payloads = self.make_plan(
            files_old=False,
            selected_present=True,
        )
        current = copy.deepcopy(plan["observation"])
        current["network"]["member_ids"] = []
        current["archive_name"] = {
            "identity": product.ATTEMPT5_OLD_CONTAINER_ID,
            "name": current["archive_name"]["name"],
            "projection_sha256": "a" * 64,
            "state": "TARGET",
        }
        current["old_container"] = {
            "active": False,
            "identity": None,
            "name": product.CONTAINER_NAME,
            "policy": "absent",
            "state": "THIRD_STATE",
        }
        return product.build_fixed_plan(selected, current)

    def failed_attempt5_target_projection(
        self,
        plan: dict[str, object],
    ) -> module.resume.PhaseFContainerProjection:
        target = module._target_container_from_plan(plan)
        effect = target.effect
        assert isinstance(effect, dict)
        host = dict(effect["host"])
        host["tmpfs"] = "/tmp:rw,nosuid,nodev,noexec,size=128m,uid=1000,gid=1000"
        host["restart"] = {
            "maximum_retry_count": 3,
            "name": "on-failure",
        }
        return module.resume.PhaseFContainerProjection(
            container_id="a94aa745b9946ae74e2ccd41bd5a72f7ec1354214f616e774ec635b8a38f4380",
            name=product.CONTAINER_NAME,
            image="myuna/astrbot-phase-f-deterministic@sha256:ef2d2f966745b6d2e05b3286698bf6601a9a2c478f762b6b0df9703eee48d214",
            status="exited",
            health="unhealthy",
            restart_policy="on-failure",
            restart_maximum_retry_count=3,
            project=str(effect["project"]),
            service=str(effect["service"]),
            plan_digest=target.plan_digest,
            target_config_digest="0710c79b11aa9bcdccb6c73c83b60ac05626d16e33344ce17225136d0fed281c",
            user=module.ATTEMPT5_FAILED_TARGET_USER_EVIDENCE,
            command_digest=str(effect["command_sha256"]),
            host_config_digest="1c72426859c6d4b60c267c79194d2df4d43b1975a4a9d3bb35012eb1e271b761",
            mounts_digest="92fc4d7d4fac55effa4526777c283dddc7f1f8c6ef4de34afb7c6f5c7b93d025",
            networks_digest="b61f48ad20624ec85b7183428c8ee4df7039c88b06daa29c7ec0ba842ff239fb",
            network_names=(product.NETWORK_NAME,),
            effect_digest=module.ATTEMPT5_FAILED_TARGET_EFFECT_SHA256,
            effect_environment_digest=str(effect["environment_sha256"]),
            effect_host_digest=module.resume._phase_f_digest(
                "phase_f_attempt5_target_host_v1", host
            ),
            effect_mounts_digest="8a5bad38ad5987ba0ccba498848b6d2fce1abda9c76a1ac7ce068ae442f4575b",
        )

    def test_failed_attempt5_recovery_admission_is_exact_and_content_free(
        self,
    ) -> None:
        plan = self.attempt5_archived_plan()
        exact = self.failed_attempt5_target_projection(plan)
        docker_facts = "\n".join(
            json.dumps(value) for value in (3, 1, False, "", [])
        )
        socket_facts = "NConnections=0\nNAccepted=0\nNRefused=0\n"

        def command(args: tuple[str, ...], **_kwargs: object) -> str:
            return docker_facts if args[0] == "/usr/bin/docker" else socket_facts

        no_access = {
            role: False
            for role in (
                "channel_data",
                "plugin_release",
                "signing_secret",
                "runtime_root",
                "media_runtime_root",
                "runtime_socket",
            )
        }
        self.assertEqual(
            module.resume.phase_f_container_identity_sha256(exact),
            module.ATTEMPT5_FAILED_TARGET_TERMINAL_IDENTITY_SHA256,
        )
        self.assertEqual(
            exact.effect_host_digest,
            "364f84421338726619cde8939fe9eef87aee41b1c513bf1c7318dffbe5cac5b8",
        )
        terminal_effect = copy.deepcopy(plan["target_effect"])
        terminal_effect["mounts_sha256"] = exact.effect_mounts_digest
        terminal_target = mock.Mock(effect=terminal_effect)
        patches = (
            mock.patch.object(
                module.resume,
                "_phase_f_runtime_access_projection",
                return_value=no_access,
            ),
            mock.patch.object(module, "_command", side_effect=command),
            mock.patch.object(
                module, "_target_container_from_plan", return_value=terminal_target
            ),
        )
        with patches[0], patches[1], patches[2], mock.patch.object(
            module.resume,
            "phase_f_container_projection",
            return_value=exact,
        ):
            self.assertEqual(
                module._attempt5_failed_target_recovery_projection(plan),
                exact,
            )

        substitutions = {
            "container_id": "b" * 64,
            "name": product.CONTAINER_NAME + "-substituted",
            "image": "substituted-image",
            "project": "substituted-project",
            "service": "substituted-service",
            "plan_digest": "1" * 64,
            "target_config_digest": "2" * 64,
            "user": product.TARGET_USER,
            "command_digest": "3" * 64,
            "host_config_digest": "4" * 64,
            "mounts_digest": "5" * 64,
            "networks_digest": "6" * 64,
            "network_names": (),
            "status": "running",
            "health": "",
            "restart_policy": "no",
            "restart_maximum_retry_count": 2,
            "effect_digest": "a" * 64,
            "effect_environment_digest": "b" * 64,
            "effect_host_digest": "c" * 64,
            "effect_mounts_digest": "d" * 64,
        }
        for field, value in substitutions.items():
            hostile = replace(exact, **{field: value})
            with self.subTest(field=field), patches[0], patches[1], patches[2], mock.patch.object(
                module.resume,
                "phase_f_container_projection",
                return_value=hostile,
            ):
                self.assertIsNone(
                    module._attempt5_failed_target_recovery_projection(plan)
                )

        old_can_access = dict(no_access)
        old_can_access["runtime_socket"] = True
        with mock.patch.object(
            module.resume,
            "_phase_f_runtime_access_projection",
            return_value=old_can_access,
        ), patches[1], patches[2], mock.patch.object(
            module.resume,
            "phase_f_container_projection",
            return_value=exact,
        ):
            self.assertIsNone(
                module._attempt5_failed_target_recovery_projection(plan)
            )

        self.assertNotIn(
            "_remove_target",
            module._attempt5_failed_target_recovery_projection.__code__.co_names,
        )
        self.assertNotIn(
            "_create_target_container",
            module._attempt5_failed_target_recovery_projection.__code__.co_names,
        )

        docker_substitutions = (
            (2, 1, False, "", []),
            (3, 0, False, "", []),
            (3, 1, True, "", []),
            (3, 1, False, "nonempty", []),
            (3, 1, False, "", ["1000"]),
        )
        for index, values in enumerate(docker_substitutions):
            hostile_docker = "\n".join(json.dumps(value) for value in values)

            def hostile_docker_command(
                args: tuple[str, ...],
                **_kwargs: object,
            ) -> str:
                return hostile_docker if args[0] == "/usr/bin/docker" else socket_facts

            with self.subTest(docker_fact=index), mock.patch.object(
                module.resume,
                "_phase_f_runtime_access_projection",
                return_value=no_access,
            ), mock.patch.object(
                module, "_command", side_effect=hostile_docker_command
            ), mock.patch.object(
                module, "_target_container_from_plan", return_value=terminal_target
            ), mock.patch.object(
                module.resume,
                "phase_f_container_projection",
                return_value=exact,
            ):
                self.assertIsNone(
                    module._attempt5_failed_target_recovery_projection(plan)
                )

        socket_substitutions = (
            "NConnections=1\nNAccepted=0\nNRefused=0\n",
            "NConnections=0\nNAccepted=1\nNRefused=0\n",
            "NConnections=0\nNAccepted=0\nNRefused=1\n",
        )
        for index, hostile_socket in enumerate(socket_substitutions):

            def hostile_socket_command(
                args: tuple[str, ...],
                **_kwargs: object,
            ) -> str:
                return docker_facts if args[0] == "/usr/bin/docker" else hostile_socket

            with self.subTest(socket_fact=index), mock.patch.object(
                module.resume,
                "_phase_f_runtime_access_projection",
                return_value=no_access,
            ), mock.patch.object(
                module, "_command", side_effect=hostile_socket_command
            ), mock.patch.object(
                module, "_target_container_from_plan", return_value=terminal_target
            ), mock.patch.object(
                module.resume,
                "phase_f_container_projection",
                return_value=exact,
            ):
                self.assertIsNone(
                    module._attempt5_failed_target_recovery_projection(plan)
                )

    def test_failed_attempt5_recovery_prefix_requires_complete_exact_suffix(
        self,
    ) -> None:
        base = self.attempt5_archived_plan()
        failed = self.failed_attempt5_target_projection(base)
        current = copy.deepcopy(base["observation"])
        current["services"]["runtime"]["active"] = False
        current["services"]["socket"]["active"] = True
        current["services"]["core"]["active"] = True
        current["target_container"] = {
            "active": False,
            "identity": failed.container_id,
            "name": product.CONTAINER_NAME,
            "policy": module.DISPATCH_FENCE_POLICY,
            "state": "THIRD_STATE",
        }
        current["old_container"] = {
            "active": False,
            "identity": failed.container_id,
            "name": product.CONTAINER_NAME,
            "policy": module.DISPATCH_FENCE_POLICY,
            "state": "THIRD_STATE",
        }
        exact_plan = product.build_fixed_plan(base["authority"], current)
        archived = {
            "active": False,
            "identity": current["archive_name"]["identity"],
            "name": exact_plan["archive_name"],
            "policy": "no",
            "state": "TARGET",
        }
        with mock.patch.object(
            module,
            "_attempt5_failed_target_recovery_projection",
            return_value=failed,
        ), mock.patch.object(
            module, "_old_container_role_observation", return_value=archived
        ), mock.patch.object(
            module, "_effective_units_state", return_value="TARGET"
        ), mock.patch.object(module, "_remove_target") as remove_target, mock.patch.object(
            module, "_create_target_container"
        ) as create_target:
            self.assertEqual(
                module._checkpoint_prefix(exact_plan),
                "POST_WRITER_RECOVERY_REQUIRED",
            )
        remove_target.assert_not_called()
        create_target.assert_not_called()

        def variant() -> dict[str, object]:
            return copy.deepcopy(current)

        hostile_observations: dict[str, dict[str, object]] = {}
        row = variant()
        row["parent"]["state"] = "THIRD_STATE"
        hostile_observations["parent"] = row
        row = variant()
        row["network"]["state"] = "THIRD_STATE"
        hostile_observations["network_state"] = row
        row = variant()
        row["network"]["member_ids"] = [failed.container_id]
        hostile_observations["network_member"] = row
        row = variant()
        row["archive_root"]["state"] = "THIRD_STATE"
        hostile_observations["root_state"] = row
        row = variant()
        row["archive_root"]["handle_count"] = 1
        hostile_observations["root_handle"] = row
        row = variant()
        row["archive_root"]["selected_state"] = "OLD"
        hostile_observations["selected_root"] = row
        row = variant()
        row["target_container"]["identity"] = "b" * 64
        hostile_observations["target_identity"] = row
        row = variant()
        row["target_container"]["name"] += "-substituted"
        hostile_observations["target_name"] = row
        row = variant()
        row["target_container"]["active"] = True
        hostile_observations["target_active"] = row
        row = variant()
        row["target_container"]["policy"] = "no"
        hostile_observations["target_policy"] = row
        row = variant()
        row["old_container"]["state"] = "OLD"
        hostile_observations["old_state"] = row
        row = variant()
        row["old_container"]["identity"] = "c" * 64
        hostile_observations["old_identity"] = row
        row = variant()
        row["archive_name"]["state"] = "THIRD_STATE"
        hostile_observations["archive_state"] = row
        row = variant()
        row["releases"]["core"] = {"identity": None, "state": "OLD"}
        hostile_observations["release_state"] = row
        row = variant()
        first_file = sorted(row["files"])[0]
        row["files"][first_file]["state"] = "THIRD_STATE"
        hostile_observations["file_state"] = row
        row = variant()
        row["services"]["runtime"]["active"] = True
        hostile_observations["runtime_active"] = row
        row = variant()
        row["services"]["socket"]["active"] = False
        hostile_observations["socket_inactive"] = row
        row = variant()
        row["services"]["core"]["active"] = False
        hostile_observations["core_inactive"] = row

        for name, observation in hostile_observations.items():
            with self.subTest(prefix_field=name), mock.patch.object(
                module,
                "_attempt5_failed_target_recovery_projection",
                return_value=failed,
            ), mock.patch.object(
                module, "_old_container_role_observation", return_value=archived
            ), mock.patch.object(
                module, "_effective_units_state", return_value="TARGET"
            ), mock.patch.object(module, "_remove_target") as remove_target, mock.patch.object(
                module, "_create_target_container"
            ) as create_target:
                with self.assertRaises(
                    (module.MemoryActivationRejected, product.ProductionPlanRejected)
                ):
                    hostile_plan = product.build_fixed_plan(
                        base["authority"], observation
                    )
                    module._checkpoint_prefix(hostile_plan)
            remove_target.assert_not_called()
            create_target.assert_not_called()

        for name, value in (
            ("archive_identity", {**archived, "identity": "d" * 64}),
            ("archive_state", {**archived, "state": "THIRD_STATE"}),
            ("archive_active", {**archived, "active": True}),
        ):
            with self.subTest(prefix_field=name), mock.patch.object(
                module,
                "_attempt5_failed_target_recovery_projection",
                return_value=failed,
            ), mock.patch.object(
                module, "_old_container_role_observation", return_value=value
            ), mock.patch.object(
                module, "_effective_units_state", return_value="TARGET"
            ), mock.patch.object(module, "_remove_target") as remove_target, mock.patch.object(
                module, "_create_target_container"
            ) as create_target:
                with self.assertRaises(module.MemoryActivationRejected):
                    module._checkpoint_prefix(exact_plan)
            remove_target.assert_not_called()
            create_target.assert_not_called()

    def test_failed_attempt5_recovery_is_remove_then_corrected_stopped_only(
        self,
    ) -> None:
        plan = self.attempt5_archived_plan()
        failed = self.failed_attempt5_target_projection(plan)
        removed = copy.deepcopy(plan)
        stopped = copy.deepcopy(plan)
        calls: list[str] = []
        with mock.patch.object(
            module,
            "_attempt5_failed_target_recovery_projection",
            return_value=failed,
        ), mock.patch.object(
            module,
            "_remove_target",
            side_effect=lambda identity: calls.append("remove:" + identity),
        ), mock.patch.object(
            module,
            "_create_target_container",
            side_effect=lambda _plan: calls.append("create-corrected-stopped"),
        ), mock.patch.object(
            module,
            "_fresh_checkpoint_plan",
            side_effect=(removed, stopped),
        ), mock.patch.object(
            module,
            "_checkpoint_prefix",
            side_effect=("FILES_AND_UNITS_TARGET", "TARGET_CONTAINER_STOPPED"),
        ):
            result = module._run_attempt5_stopped_recovery(
                plan,
                prefix_before="POST_WRITER_RECOVERY_REQUIRED",
            )
        self.assertEqual(
            calls,
            ["remove:a94aa745b9946ae74e2ccd41bd5a72f7ec1354214f616e774ec635b8a38f4380", "create-corrected-stopped"],
        )
        self.assertEqual(result["callbacks"], 2)
        self.assertEqual(result["prefix_after"], "TARGET_CONTAINER_STOPPED")
        self.assertIsNone(result["next_stage"])
        self.assertTrue(result["writer_boundary"])
        self.assertNotIn("start", " ".join(calls))

        with mock.patch.object(
            module,
            "_attempt5_failed_target_recovery_projection",
            return_value=failed,
        ), mock.patch.object(
            module,
            "_remove_target",
            side_effect=module.MemoryActivationRejected("remove_lost_return"),
        ) as remove, mock.patch.object(
            module, "_create_target_container"
        ) as create, mock.patch.object(
            module, "_fresh_checkpoint_plan", return_value=removed
        ), mock.patch.object(
            module, "_checkpoint_prefix", return_value="FILES_AND_UNITS_TARGET"
        ):
            lost = module._run_attempt5_stopped_recovery(
                plan,
                prefix_before="POST_WRITER_RECOVERY_REQUIRED",
            )
        remove.assert_called_once()
        create.assert_not_called()
        self.assertEqual(lost["callbacks"], 1)
        self.assertEqual(lost["prefix_after"], "FILES_AND_UNITS_TARGET")

        with mock.patch.object(
            module,
            "_create_target_container",
            side_effect=module.MemoryActivationRejected("create_lost_return"),
        ) as create_lost, mock.patch.object(
            module,
            "_fresh_checkpoint_plan",
            side_effect=(removed, stopped),
        ), mock.patch.object(
            module,
            "_checkpoint_prefix",
            side_effect=("FILES_AND_UNITS_TARGET", "TARGET_CONTAINER_STOPPED"),
        ), mock.patch.object(module, "_remove_target") as remove_again:
            create_lost_result = module._run_attempt5_stopped_recovery(
                removed,
                prefix_before="FILES_AND_UNITS_TARGET",
            )
        remove_again.assert_not_called()
        create_lost.assert_called_once_with(removed)
        self.assertEqual(create_lost_result["callbacks"], 1)
        self.assertEqual(
            create_lost_result["reason"],
            "recovery_lost_return_reobserved_corrected_stopped",
        )
        self.assertEqual(
            create_lost_result["prefix_after"],
            "TARGET_CONTAINER_STOPPED",
        )

        with mock.patch.object(
            module, "_checkpoint_prefix", return_value="TARGET_CONTAINER_STOPPED"
        ):
            terminal = module.run_checkpointed_stage(
                plan,
                requested_stage=None,
                supervised_start=False,
            )
        self.assertEqual(terminal["callbacks"], 0)
        self.assertIsNone(terminal["next_stage"])
        self.assertEqual(terminal["reason"], "corrected_stopped_recovery_terminal")

    def test_source_has_no_generic_owner_or_private_database_primitive(self) -> None:
        text = MODULE_PATH.read_text("utf-8")
        for forbidden in (
            "AtomicPolicyOverlayTransaction",
            "transactional_controller",
            "transactional_runtime",
            "activation_transaction_substrate",
            "sqlite3",
            "WAL",
            "SHM",
        ):
            self.assertNotIn(forbidden, text)
        self.assertEqual(text.count("run_fixed_product_activation("), 1)


if __name__ == "__main__":
    unittest.main()
