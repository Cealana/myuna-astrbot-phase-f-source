from __future__ import annotations

import base64
from hashlib import sha256
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "p07_owner_private_memory_production_plan.py"
SPEC = importlib.util.spec_from_file_location(
    "p07_owner_private_memory_production_plan",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def authority(seed: int) -> dict[str, object]:
    files: dict[str, object] = {}
    for index, path in enumerate(sorted(module.FILE_ROLES)):
        if path == module.MEMORY_SELECTOR_PATH:
            memory_release_set_id = f"{seed:016x}" + "3" * 48
            archive_id = (
                "p07-owner-private-memory-transactional-"
                + memory_release_set_id[:16]
            )
            payload = module.canonical(
                {
                    "archive_id": archive_id,
                    "calendar_zone": "Asia/Shanghai",
                    "calendar_zone_config_digest": "1" * 64,
                    "channel_kind": "telegram",
                    "client_id": "telegram-owner-runtime",
                    "diary_coupled": False,
                    "egress_policy_digest": "2" * 64,
                    "egress_policy_mode": "historical_raw_recall_v1",
                    "expected_gid": module.MEMORY_RUNTIME_GID,
                    "expected_uid": module.MEMORY_RUNTIME_UID,
                    "memory_release_set_id": memory_release_set_id,
                    "no_old_data_migration": True,
                    "p15_handoff_schema": "myuna.p15-handoff.v1",
                    "p15_projection_active": False,
                    "p08_lifecycle_start_watermark": (
                        module.P08_LIFECYCLE_START_WATERMARK
                    ),
                    "parent_epoch_id": module.PARENT_EPOCH_ID,
                    "parent_epoch_revision": module.PARENT_EPOCH_REVISION,
                    "parent_manifest_digest": module.PARENT_MANIFEST_SHA256,
                    "parent_release_set_id": module.PARENT_RELEASE_SET_ID,
                    "parent_selector_digest": module.PARENT_SELECTOR_SHA256,
                    "policy_overlay_id": "4" * 64,
                    "prompt_owner": "telegram-owner-runtime",
                    "runtime_root": f"{module.MEMORY_RUNTIME_ROOT}/{archive_id}",
                    "schema": "myuna.p07-owner-private-memory-selector.v4",
                    "status": "active",
                    "summary_used": False,
                }
            )
        else:
            payload = f"target:{seed}:{index}:{path}\n".encode("ascii")
        role, mode = module.FILE_ROLES[path]
        files[path] = {
            "gid": 0,
            "mode": mode,
            "owner": module.FILE_OWNERS[path],
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
            "member_set_sha256": module.release_member_set_sha256(members),
            "receipt_sha256": sha256(f"receipt:{key}".encode()).hexdigest(),
            "root": root,
        }
    image_receipt = {
        "archive_sha256": "e" * 64,
        "archive_size": 1,
        "image_id": "sha256:" + "f" * 64,
        "image_reference": module.TARGET_IMAGE_PREFIX + "f" * 64,
        "layers": [{"diff_id": "sha256:" + "d" * 64}],
        "manifest_digest": "sha256:" + "f" * 64,
        "platform": {"architecture": "amd64", "os": "linux"},
    }
    return module.validate_source_authority({
        "builder": {
            "astrbot_commit": module.ACCEPTED_ASTRBOT_COMMIT,
            "astrbot_tree": "a" * 40,
            "base_image_digest": "sha256:7546bddf1040419a455dd1ca683a5e9cf84436bbd85de17c7ac626d3af7affe4",
            "gateway_builder_blob": module.GATEWAY_BUILDER_BLOB,
            "hybrid_builder_blob": module.HYBRID_BUILDER_BLOB,
            "runtime_base_digest": module.ACCEPTED_RUNTIME_BASE,
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
            "member_set_sha256": module.image_member_set_sha256(image_receipt),
            "receipt": image_receipt,
            "receipt_sha256": sha256(module.canonical(image_receipt)).hexdigest(),
            "reference": module.TARGET_IMAGE_PREFIX + "f" * 64,
        },
        "parent": {
            "epoch_id": module.PARENT_EPOCH_ID,
            "epoch_revision": module.PARENT_EPOCH_REVISION,
            "lifecycle_start_watermark": module.P08_LIFECYCLE_START_WATERMARK,
            "manifest_sha256": module.PARENT_MANIFEST_SHA256,
            "release_set_id": module.PARENT_RELEASE_SET_ID,
            "selector_sha256": module.PARENT_SELECTOR_SHA256,
        },
        "releases": {
            "core": release("core", "6" * 64, module.CORE_RELEASE_ROOT),
            "plugin": release("plugin", "9" * 64, module.PLUGIN_RELEASE_ROOT),
            "runtime": release("runtime", "c" * 64, module.RUNTIME_RELEASE_ROOT),
        },
        "schema": module.SOURCE_SCHEMA,
        "source": {
            "core_commit": module.ACCEPTED_CORE_COMMIT,
            "core_tree": module.ACCEPTED_CORE_TREE,
            "deploy_commit": "f" * 40,
            "deploy_parent": module.ACCEPTED_DEPLOY_PARENT,
            "deploy_tree": "1" * 40,
        },
    })


def observation(
    selected: dict[str, object],
    *,
    file_state: str = "TARGET",
) -> tuple[dict[str, object], dict[str, str | None]]:
    old_hashes: dict[str, str | None] = {}
    files: dict[str, object] = {}
    for index, path in enumerate(sorted(module.FILE_ROLES)):
        target = selected["files"][path]
        if file_state == "TARGET":
            payload = base64.b64decode(target["payload_b64"])
        elif file_state == "OLD":
            payload = f"old:{index}:{path}\n".encode("ascii")
        else:
            payload = f"third:{index}:{path}\n".encode("ascii")
        old_hashes[path] = sha256(
            f"old:{index}:{path}\n".encode("ascii")
        ).hexdigest()
        files[path] = {
            "gid": 0,
            "identity": sha256(f"inode:{index}".encode()).hexdigest(),
            "kind": "regular",
            "mode": module.FILE_ROLES[path][1],
            "payload_b64": base64.b64encode(payload).decode("ascii"),
            "sha256": sha256(payload).hexdigest(),
            "uid": 0,
        }
    selected_root = module.selected_memory_runtime(
        module.validate_source_authority(selected)
    )
    return (
        {
            "archive_name": {
                "identity": None,
                "name": module.ARCHIVE_PREFIX
                + module.validate_source_authority(selected)["authority_sha256"][:16],
                "projection_sha256": None,
                "state": "OLD",
            },
            "archive_root": {
                "handle_count": 0,
                "identity": "parent-root",
                "legacy_identity": "legacy-empty-root",
                "legacy_name": module.LEGACY_MEMORY_ARCHIVE_ID,
                "path": module.MEMORY_RUNTIME_ROOT,
                "selected_identity": None,
                "selected_name": selected_root["archive_id"],
                "selected_state": "OLD",
                "state": "TARGET",
            },
            "files": files,
            "network": {
                "identity": "network-object",
                "member_ids": ["old-container"],
                "name": module.NETWORK_NAME,
                "projection_sha256": "8" * 64,
                "state": "TARGET",
            },
            "old_container": {
                "active": True,
                "identity": "old-container",
                "name": module.CONTAINER_NAME,
                "policy": "on-failure:3",
                "state": "TARGET",
            },
            "parent": {
                "manifest_sha256": module.PARENT_MANIFEST_SHA256,
                "selector_sha256": module.PARENT_SELECTOR_SHA256,
                "state": "TARGET",
            },
            "releases": {
                key: {
                    "identity": (
                        selected["image"]["member_set_sha256"]
                        if key == "image"
                        else selected["releases"][key][
                            "member_set_sha256"
                        ]
                    ),
                    "state": "TARGET",
                }
                for key in ("core", "image", "plugin", "runtime")
            },
            "schema": module.OBSERVATION_SCHEMA,
            "services": {
                key: {"active": True, "identity": key + "-unit"}
                for key in ("core", "runtime", "socket")
            },
            "target_container": {
                "active": False,
                "identity": None,
                "name": module.CONTAINER_NAME,
                "policy": "absent",
                "state": "OLD",
            },
        },
        old_hashes,
    )


class ProductionPlanTests(unittest.TestCase):
    def test_exact_finite_delta_and_stages_are_deterministic_for_dual_seeds(self) -> None:
        identities: list[str] = []
        for seed in (19001, 19002):
            selected = authority(seed)
            current, old_hashes = observation(selected)
            with mock.patch.dict(module.OLD_FILE_SHA256, old_hashes, clear=True):
                plan = module.build_fixed_plan(selected, current)
                self.assertEqual(module.validate_fixed_plan(plan), plan)
            self.assertEqual(set(plan["authority"]["files"]), set(module.FILE_ROLES))
            self.assertEqual(len(plan["authority"]["files"]), 7)
            self.assertEqual(plan["fixed_stages"], list(module.FIXED_STAGES))
            identities.append(plan["plan_sha256"])
        self.assertNotEqual(*identities)

    def test_checkpoint_prefix_table_is_exact_and_linear(self) -> None:
        self.assertEqual(set(module.CHECKPOINT_NEXT_STAGE), set(module.CHECKPOINT_PREFIXES))
        self.assertEqual(set(module.CHECKPOINT_STAGE_TARGET), set(module.FIXED_STAGES))
        self.assertIsNone(module.CHECKPOINT_NEXT_STAGE["POST_WRITER_MANUAL"])
        self.assertIsNone(module.CHECKPOINT_NEXT_STAGE["TARGET_CONTAINER_STOPPED"])
        self.assertEqual(
            module.CHECKPOINT_NEXT_STAGE["POST_WRITER_RECOVERY_REQUIRED"],
            "RECOVER_ATTEMPT5_FAILED_TARGET_TO_CORRECTED_STOPPED",
        )
        self.assertEqual(
            module.CHECKPOINT_NEXT_STAGE["FILES_AND_UNITS_TARGET"],
            "RECOVER_ATTEMPT5_FAILED_TARGET_TO_CORRECTED_STOPPED",
        )
        for stage, target in module.CHECKPOINT_STAGE_TARGET.items():
            self.assertIn(target, module.CHECKPOINT_PREFIXES)
            self.assertIn(stage, module.FIXED_STAGES)
        self.assertEqual(
            module.CHECKPOINT_NEXT_STAGE["READY_FOR_SUPERVISED_GATE"],
            "ARM_AND_START_TARGET_ONCE",
        )
        self.assertEqual(
            module.CHECKPOINT_NEXT_STAGE[
                "POST_WRITER_DURABILITY_SOCKET_REQUIRED"
            ],
            "START_RUNTIME_SOCKET",
        )
        self.assertEqual(
            module.CHECKPOINT_NEXT_STAGE[
                "POST_WRITER_DURABILITY_TARGET_START_REQUIRED"
            ],
            "START_REPLACEMENT_ATTEMPT6_TARGET_ONCE",
        )
        self.assertIsNone(
            module.CHECKPOINT_NEXT_STAGE["POST_WRITER_DURABILITY_TARGET"]
        )

    def test_attempt5_target_identity_has_one_source_owned_projection(self) -> None:
        selected = authority(19001)
        current, old_hashes = observation(selected)
        with mock.patch.dict(module.OLD_FILE_SHA256, old_hashes, clear=True):
            effect = module._attempt5_target_effect(selected, current)
        self.assertEqual(module.TARGET_USER, "988:982")
        self.assertEqual(
            effect["user"],
            f"{module.MEMORY_RUNTIME_UID}:{module.MEMORY_RUNTIME_GID}",
        )
        self.assertIn("uid=988,gid=982", effect["host"]["tmpfs"])

    def test_each_file_projects_old_target_and_third_state(self) -> None:
        selected = authority(19001)
        for state in ("OLD", "TARGET", "THIRD_STATE"):
            current, old_hashes = observation(selected, file_state=state)
            with mock.patch.dict(module.OLD_FILE_SHA256, old_hashes, clear=True):
                plan = module.build_fixed_plan(selected, current)
            self.assertEqual(
                {row["state"] for row in plan["observation"]["files"].values()},
                {state},
            )

    def test_arbitrary_predecessor_generation_is_third_state(self) -> None:
        selected = authority(19001)
        current, old_hashes = observation(selected, file_state="THIRD_STATE")
        with mock.patch.dict(module.OLD_FILE_SHA256, old_hashes, clear=True):
            plan = module.build_fixed_plan(selected, current)
            self.assertEqual(
                {row["state"] for row in plan["observation"]["files"].values()},
                {"THIRD_STATE"},
            )
            hostile = module.json.loads(module.canonical(current))
            path = sorted(module.FILE_ROLES)[0]
            payload = base64.b64decode(
                hostile["files"][path]["payload_b64"], validate=True
            ) + b"substituted"
            hostile["files"][path]["payload_b64"] = base64.b64encode(
                payload
            ).decode("ascii")
            hostile["files"][path]["sha256"] = sha256(payload).hexdigest()
            rejected = module.build_fixed_plan(selected, hostile)
            self.assertEqual(
                rejected["observation"]["files"][path]["state"],
                "THIRD_STATE",
            )
        self.assertFalse(
            any(name.startswith("FILE_PREDECESSOR_") for name in vars(module))
        )
        self.assertEqual(
            module.ATTEMPT5_PRODUCT_CONTROLLER_RELEASE,
            "b78ef052c838dc896f98cb9ef8d2a0c96ae55b2d1146ede39d8e8753a976aa69",
        )
        self.assertEqual(
            (
                module.ATTEMPT5_PRODUCT_DEPLOY_COMMIT,
                module.ATTEMPT5_PRODUCT_DEPLOY_PARENT,
            ),
            (
                "a4a16a4f14ec3c762427a7b21de97f5af9910464",
                "7341d9b60b4bf445bec56842df326edfd670e50d",
            ),
        )
        self.assertEqual(
            module.ATTEMPT5_PRODUCT_AUTHORITY_SHA256,
            "34a0e759e6fc7729e36d3355a2f617a06ac0bebee36bc445740db652c4dc23b0",
        )
        self.assertEqual(
            module.ATTEMPT5_PRODUCT_ENTRY_PLAN_SHA256,
            "bed60d0c4f567e389d0c5aa54b0300944f668c577b70d07ad268c9cec653d21a",
        )

    def test_two_source_owned_absent_paths_are_old(self) -> None:
        selected = authority(19001)
        current, old_hashes = observation(selected)
        absent = [
            path for path, value in module.OLD_FILE_SHA256.items() if value is None
        ]
        self.assertEqual(len(absent), 2)
        for path in absent:
            current["files"][path] = {
                "gid": None,
                "identity": None,
                "kind": "absent",
                "mode": None,
                "payload_b64": None,
                "sha256": None,
                "uid": None,
            }
            old_hashes[path] = None
        with mock.patch.dict(module.OLD_FILE_SHA256, old_hashes, clear=True):
            plan = module.build_fixed_plan(selected, current)
        self.assertTrue(
            all(plan["observation"]["files"][path]["state"] == "OLD" for path in absent)
        )

    def test_unresolved_or_substituted_authority_rejects(self) -> None:
        self.assertEqual(
            module.ACCEPTED_DEPLOY_PARENT,
            "ae634e82eba960cb4a3a8f9e3b848fb05331537f",
        )
        selected = authority(19001)
        for kind, parent in (
            ("reviewed-parent", "9985a3b414a752b3d93cedc491de7e4c912cc3cd"),
            ("prior-parent", "beb53ffe931fd81cf20435aa1f55ad19aaf5a9f6"),
            ("old-direct", "e7d624659b882280b5c874e3095dcc46662236b6"),
            ("prior-main", "5f6e32c4abc0f7e23c29cdda94cb675ebf0d077b"),
            ("old", "3ff4b54bec8d6b1522bcba5b76a572984227cc62"),
            ("intermediate", "b42c2f815c87699068f7f8eda7f5f06a6a8e467b"),
            ("self", selected["source"]["deploy_commit"]),
            ("sibling", "e" * 40),
            ("merge", "d" * 40),
            ("substituted", "0" * 40),
        ):
            with self.subTest(parent_kind=kind):
                changed = module.json.loads(module.canonical(selected))
                changed["source"]["deploy_parent"] = parent
                with self.assertRaises(module.ProductionPlanRejected):
                    module.validate_source_authority(changed)

    def test_current_and_frozen_source_tuples_never_mix(self) -> None:
        current = authority(19001)
        frozen_source = {
            "core_commit": module.ATTEMPT5_PRODUCT_CORE_COMMIT,
            "core_tree": module.ATTEMPT5_PRODUCT_CORE_TREE,
            "deploy_commit": module.ATTEMPT5_PRODUCT_DEPLOY_COMMIT,
            "deploy_parent": module.ATTEMPT5_PRODUCT_DEPLOY_PARENT,
            "deploy_tree": module.ATTEMPT5_PRODUCT_DEPLOY_TREE,
        }
        self.assertNotEqual(current["source"], frozen_source)
        for field, replacement in frozen_source.items():
            mixed = module.json.loads(module.canonical(current))
            mixed.pop("authority_sha256", None)
            mixed["source"][field] = replacement
            with self.subTest(field=field), self.assertRaises(
                module.ProductionPlanRejected
            ):
                module.validate_source_authority(mixed)

        self.assertEqual(
            module.ATTEMPT5_PRODUCT_CORE_COMMIT,
            "0d6885192307a75f6948e0085c3ca2c3c9f66676",
        )
        self.assertEqual(
            module.ATTEMPT5_PRODUCT_DEPLOY_TREE,
            "c7eba974fea43c18b3ee933833904a148f32ec20",
        )
        for mutation in (
            lambda value: value["releases"]["core"].update(digest="UNKNOWN"),
            lambda value: value["image"].update(reference="mutable:latest"),
            lambda value: value["controller"].update(
                member_set_sha256="short"
            ),
        ):
            changed = module.json.loads(module.canonical(current))
            mutation(changed)
            with self.assertRaises(module.ProductionPlanRejected):
                module.validate_source_authority(changed)
        changed = module.json.loads(module.canonical(current))
        selector = changed["files"][module.MEMORY_SELECTOR_PATH]
        payload = module.json.loads(
            base64.b64decode(selector["payload_b64"], validate=True)
        )
        payload["runtime_root"] = module.MEMORY_RUNTIME_ROOT + "/caller"
        encoded = module.canonical(payload)
        selector["payload_b64"] = base64.b64encode(encoded).decode("ascii")
        selector["payload_sha256"] = sha256(encoded).hexdigest()
        with self.assertRaises(module.ProductionPlanRejected):
            module.selected_memory_runtime(
                module.validate_source_authority(changed)
            )

    def test_all_immutable_subsets_are_distinct_and_choose_first_missing(self) -> None:
        observed: set[str] = set()
        for mask in range(16):
            states = tuple(
                "TARGET" if mask & (1 << index) else "OLD"
                for index in range(4)
            )
            prefix = module.immutable_subset_prefix(states)
            self.assertNotIn(prefix, observed, states)
            observed.add(prefix)
            missing = next(
                (index for index, state in enumerate(states) if state == "OLD"),
                None,
            )
            expected = (
                module.IMMUTABLE_STAGES[missing]
                if missing is not None
                else "QUIESCE_RUNTIME_SERVICE"
            )
            self.assertEqual(module.immutable_subset_next_stage(states), expected)
            self.assertEqual(module.CHECKPOINT_NEXT_STAGE[prefix], expected)
        self.assertEqual(len(observed), 16)
        self.assertEqual(
            module.immutable_subset_prefix(("TARGET",) * 4),
            "IMMUTABLE_TARGET",
        )
        for index in range(4):
            hostile = ["OLD"] * 4
            hostile[index] = "THIRD_STATE"
            with self.assertRaises(ValueError):
                module.immutable_subset_prefix(tuple(hostile))

    def test_transitional_lineage_bounds_and_attempt_gate_are_source_owned(self) -> None:
        self.assertEqual(
            module.TRANSITIONAL_LINEAGE_LOWER,
            "d445af03f668370b47a4672cdc9a7119d9cfc7d6",
        )
        self.assertEqual(
            module.TRANSITIONAL_LINEAGE_UPPER,
            "34efdf57bd9ee8a090bc40ebe10c90f5da534e42",
        )
        self.assertEqual(module.TRANSITIONAL_INSTALL_ATTEMPT, 5)
        self.assertIs(module.TRANSITIONAL_ATTEMPT_UNCONSUMED, False)
        self.assertIs(module.TRANSITIONAL_WRITER_BOUNDARY, False)
        self.assertEqual(
            module.TRANSITIONAL_STAGE_ENTRY, "ARCHIVE_CHILD_NAME_CONVERGENCE_REQUIRED"
        )
        self.assertFalse(
            any(name.startswith("PRIOR_INSTALL_") for name in vars(module))
        )

    def test_post_writer_selected_root_phase_authority_is_sealed(self) -> None:
        phase = module._selected_root_phase_authority()
        self.assertEqual(
            phase,
            {
                "archive_parent_identity": (
                    module.ATTEMPT5_ARCHIVE_PARENT_IDENTITY
                ),
                "attempt": 5,
                "attempt6_absent": True,
                "attempt_consumed": True,
                "domain": "phase-f.fixed-product-supervised-activation",
                "network_projection_sha256": (
                    "56605a22077783c6c780cb701b119b8a3375ac3804ba8d67d"
                    "a17b88087ef6eab"
                ),
                "phase": "POST_WRITER",
                "product_authority_sha256": (
                    module.ATTEMPT5_PRODUCT_AUTHORITY_SHA256
                ),
                "product_controller_release": (
                    module.ATTEMPT5_PRODUCT_CONTROLLER_RELEASE
                ),
                "product_plan_sha256": (
                    module.ATTEMPT5_PRODUCT_ENTRY_PLAN_SHA256
                ),
                "schema": (
                    "myuna.phase-f.post-writer-selected-root-authority.v1"
                ),
                "selected_root_identity": (
                    module.ATTEMPT5_PRIOR_ARCHIVE_CHILD_IDENTITY
                ),
                "version": 1,
                "writer_bound": True,
            },
        )
        contract = module.source_contract()
        self.assertNotIn("post_writer_selected_root_authority_sha256", contract)
        self.assertEqual(
            contract["replacement_attempt6_authority_sha256"],
            module.REPLACEMENT_ATTEMPT6_AUTHORITY_SHA256,
        )
        for field, value in (
            ("_SELECTED_ROOT_PHASE", "THIRD_STATE"),
            ("_SELECTED_ROOT_PHASE_DOMAIN", "substituted"),
            ("_SELECTED_ROOT_PHASE_VERSION", 2),
            ("_SELECTED_ROOT_NETWORK_PROJECTION_SHA256", "0" * 64),
            ("_SELECTED_ROOT_PHASE_AUTHORITY_SHA256", "1" * 64),
        ):
            with self.subTest(field=field), mock.patch.object(
                module,
                field,
                value,
            ):
                with self.assertRaises(module.ProductionPlanRejected):
                    module._selected_root_phase_authority()
        pre_writer_body = {**phase}
        pre_writer_body.update(
            attempt_consumed=False,
            phase="PRE_WRITER",
            writer_bound=False,
        )
        pre_writer_sha256 = module.digest(
            "phase_f_post_writer_selected_root_authority_v1",
            pre_writer_body,
        )
        with mock.patch.object(
            module,
            "_SELECTED_ROOT_PHASE",
            "PRE_WRITER",
        ), mock.patch.object(
            module,
            "_SELECTED_ROOT_PHASE_AUTHORITY_SHA256",
            pre_writer_sha256,
        ):
            self.assertEqual(
                module._selected_root_phase_authority(),
                pre_writer_body,
            )

    def test_selected_runtime_projection_and_root_states_are_exact(self) -> None:
        selected = authority(19001)
        validated = module.validate_source_authority(selected)
        runtime = module.selected_memory_runtime(validated)
        self.assertEqual(runtime["expected_uid"], module.MEMORY_RUNTIME_UID)
        self.assertEqual(runtime["expected_gid"], module.MEMORY_RUNTIME_GID)
        self.assertEqual(
            runtime["runtime_root"],
            f"{module.MEMORY_RUNTIME_ROOT}/{runtime['archive_id']}",
        )
        current, old_hashes = observation(selected)
        with mock.patch.dict(module.OLD_FILE_SHA256, old_hashes, clear=True):
            absent = module.build_fixed_plan(selected, current)
            current["archive_root"].update(
                selected_identity="selected-empty-root",
                selected_state="TARGET",
            )
            present = module.build_fixed_plan(selected, current)
            current["archive_root"].update(
                handle_count=1,
                selected_state="THIRD_STATE",
                state="THIRD_STATE",
            )
            rejected = module.build_fixed_plan(selected, current)
        self.assertEqual(
            absent["observation"]["archive_root"]["selected_state"],
            "OLD",
        )
        self.assertEqual(
            present["observation"]["archive_root"]["selected_state"],
            "TARGET",
        )
        self.assertEqual(rejected["observation"]["archive_root"]["state"], "THIRD_STATE")

    def test_payload_digest_mode_role_and_extra_path_reject(self) -> None:
        selected = authority(19001)
        path = sorted(module.FILE_ROLES)[0]
        for field, value in (
            ("payload_sha256", "0" * 64),
            ("mode", "0777"),
            ("role", "caller_selected"),
        ):
            changed = module.json.loads(module.canonical(selected))
            changed["files"][path][field] = value
            with self.assertRaises(module.ProductionPlanRejected):
                module.validate_source_authority(changed)
        changed = module.json.loads(module.canonical(selected))
        changed["files"]["/tmp/extra"] = changed["files"][path]
        with self.assertRaises(module.ProductionPlanRejected):
            module.validate_source_authority(changed)

    def test_observation_identity_shape_and_plan_tampering_reject(self) -> None:
        selected = authority(19001)
        current, old_hashes = observation(selected)
        changed = module.json.loads(module.canonical(current))
        changed["network"]["member_ids"] = ["z", "a"]
        with mock.patch.dict(module.OLD_FILE_SHA256, old_hashes, clear=True):
            with self.assertRaises(module.ProductionPlanRejected):
                module.build_fixed_plan(selected, changed)
            plan = module.build_fixed_plan(selected, current)
            plan["fixed_stages"] = list(reversed(plan["fixed_stages"]))
            with self.assertRaises(module.ProductionPlanRejected):
                module.validate_fixed_plan(plan)

    def test_attempt5_stopped_old_container_authority_is_frozen(self) -> None:
        self.assertEqual(
            module.ACCEPTED_DEPLOY_PARENT,
            "ae634e82eba960cb4a3a8f9e3b848fb05331537f",
        )
        self.assertEqual(
            module.ATTEMPT5_OLD_CONTAINER_ID,
            "42cca5e1e6c77aa3b1af30e326c8ef21875aa47a1ffca02ee68d718325dc1a82",
        )
        self.assertRegex(
            module.ATTEMPT5_OLD_CONTAINER_CONFIGURATION_SHA256,
            r"^[0-9a-f]{64}$",
        )
        self.assertRegex(
            module.ATTEMPT5_OLD_CONTAINER_NETWORKS_SHA256,
            r"^[0-9a-f]{64}$",
        )
        self.assertNotEqual(
            module.ATTEMPT5_OLD_CONTAINER_CONFIGURATION_SHA256,
            module.ATTEMPT5_OLD_CONTAINER_NETWORKS_SHA256,
        )
    def test_stable_archive_child_is_attempt_root_owned_and_selector_normalized(
        self,
    ) -> None:
        selected = authority(19001)
        name = module.stable_attempt_archive_child_name()
        self.assertEqual(name, "p07-owner-private-memory-attempt-v1-07ab938c868b266e")
        self.assertEqual(
            module.CHECKPOINT_NEXT_STAGE["ARCHIVE_CHILD_NAME_CONVERGENCE_REQUIRED"],
            "CONVERGE_ARCHIVE_CHILD_NAME",
        )
        self.assertEqual(
            module.CHECKPOINT_STAGE_TARGET["CONVERGE_ARCHIVE_CHILD_NAME"],
            "OLD_CONTAINER_STOPPED",
        )
        runtime = module.selected_memory_runtime(selected)
        self.assertEqual(runtime["archive_id"], name)
        row = selected["files"][module.MEMORY_SELECTOR_PATH]
        payload = module.json.loads(
            base64.b64decode(row["payload_b64"], validate=True).decode("ascii")
        )
        self.assertEqual(payload["archive_id"], name)
        self.assertEqual(
            payload["runtime_root"], f"{module.MEMORY_RUNTIME_ROOT}/{name}"
        )
        with mock.patch.object(module, "ACCEPTED_DEPLOY_PARENT", "1" * 40), \
             mock.patch.object(module, "TRANSITIONAL_LINEAGE_UPPER", "2" * 40), \
             mock.patch.object(module, "ARCHIVE_CHILD_CREATOR_LINEAGE_UPPER", "3" * 40):
            self.assertEqual(module.stable_attempt_archive_child_name(), name)
        for field, value in (
            ("STABLE_ARCHIVE_CHILD_CAPABILITY", "substituted"),
            ("STABLE_ARCHIVE_CHILD_ATTEMPT_ROOT", "substituted"),
            ("TRANSITIONAL_INSTALL_ATTEMPT", 6),
            ("STABLE_ARCHIVE_CHILD_OLD_CONTAINER_ID", "4" * 64),
            ("ATTEMPT5_ARCHIVE_PARENT_IDENTITY", "5" * 64),
        ):
            with self.subTest(field=field), mock.patch.object(module, field, value):
                self.assertNotEqual(module.stable_attempt_archive_child_name(), name)
        hostile = module.json.loads(module.canonical(selected))
        selector = hostile["files"][module.MEMORY_SELECTOR_PATH]
        projected = module.json.loads(
            base64.b64decode(selector["payload_b64"], validate=True).decode("ascii")
        )
        projected["archive_id"] = "p07-owner-private-memory-attempt-v1-" + "0" * 16
        projected["runtime_root"] = (
            module.MEMORY_RUNTIME_ROOT + "/" + projected["archive_id"]
        )
        encoded = module.canonical(projected)
        selector["payload_b64"] = base64.b64encode(encoded).decode("ascii")
        selector["payload_sha256"] = sha256(encoded).hexdigest()
        hostile.pop("authority_sha256")
        with self.assertRaises(module.ProductionPlanRejected):
            module.validate_source_authority(hostile)


    def test_attempt5_target_effect_is_one_frozen_canonical_projection(self) -> None:
        selected = authority(19001)
        observed, _old = observation(selected)
        observed["archive_name"] = {
            "identity": module.ATTEMPT5_OLD_CONTAINER_ID,
            "name": observed["archive_name"]["name"],
            "projection_sha256": "a" * 64,
            "state": "TARGET",
        }
        observed["old_container"] = {
            "active": False,
            "identity": None,
            "name": module.CONTAINER_NAME,
            "policy": "absent",
            "state": "THIRD_STATE",
        }
        observed["network"]["member_ids"] = []
        plan = module.build_fixed_plan(selected, observed)
        effect = plan["target_effect"]
        self.assertIsInstance(effect, dict)
        self.assertEqual(effect["archive_container_id"], module.ATTEMPT5_OLD_CONTAINER_ID)
        self.assertEqual(effect["archive_projection_sha256"], "a" * 64)
        self.assertEqual(effect["attempt"], 5)
        self.assertFalse(effect["writer"])
        self.assertEqual(effect["plan_digest"], module.ATTEMPT5_PRODUCT_ENTRY_PLAN_SHA256)
        self.assertEqual(module.validate_fixed_plan(plan)["target_effect"], effect)
        validated = module.validate_source_authority(selected)
        expected = module._attempt5_target_effect(validated, observed)
        with mock.patch.object(module, "ACCEPTED_DEPLOY_PARENT", "0" * 40), mock.patch.object(
            module, "TRANSITIONAL_LINEAGE_UPPER", "1" * 40
        ):
            self.assertEqual(module._attempt5_target_effect(validated, observed), expected)

        for field, value in (
            ("container_name", "substituted"),
            ("archive_container_id", "substituted"),
            ("command", {"command": ["substituted"], "entrypoint": None}),
            ("image", "substituted"),
            ("target_config_digest", "0" * 64),
            ("command_sha256", "0" * 64),
            ("user", "0:0"),
            ("network_name", "substituted"),
            ("archive_name", "substituted"),
            ("project", "substituted"),
            ("service", "substituted"),
            ("plan_digest", "0" * 64),
            ("attempt", 6),
            ("writer", True),
            ("effect_sha256", "0" * 64),
        ):
            hostile = module.json.loads(module.canonical(plan))
            hostile["target_effect"][field] = value
            body = {key: hostile[key] for key in hostile if key != "plan_sha256"}
            hostile["plan_sha256"] = module.digest("phase_f_fixed_product_plan", body)
            with self.subTest(field=field), self.assertRaisesRegex(
                module.ProductionPlanRejected, "fixed_target_effect_rejected"
            ):
                module.validate_fixed_plan(hostile)

        before_archive, _old = observation(selected)
        self.assertIsNone(module.build_fixed_plan(selected, before_archive)["target_effect"])

    def test_contract_contains_no_programmable_graph_or_private_authority(self) -> None:
        contract = module.source_contract()
        self.assertEqual(contract["file_paths"], sorted(module.FILE_ROLES))
        text = MODULE_PATH.read_text("utf-8")
        for forbidden in (
            "Driver",
            "Protocol",
            "transactional_controller",
            "transactional_runtime",
            "activation_transaction_substrate",
            "journal",
            "ledger",
        ):
            self.assertNotIn(forbidden, text)

    def test_r5_durability_projection_changes_only_plugin_and_config(self) -> None:
        baseline = authority(19001)
        baseline["source"] = {
            "core_commit": module.R5_DURABILITY_BASELINE_CORE_COMMIT,
            "core_tree": module.R5_DURABILITY_BASELINE_CORE_TREE,
            "deploy_commit": module.R5_DURABILITY_BASELINE_DEPLOY_COMMIT,
            "deploy_parent": module.R5_DURABILITY_BASELINE_DEPLOY_PARENT,
            "deploy_tree": module.R5_DURABILITY_BASELINE_DEPLOY_TREE,
        }
        baseline_plugin = baseline["releases"]["plugin"]
        baseline_plugin["digest"] = module.R5_DURABILITY_BASELINE_PLUGIN_RELEASE
        baseline_plugin["bundle_prefix"] = (
            "staging/releases/plugin/"
            + module.R5_DURABILITY_BASELINE_PLUGIN_RELEASE
        )
        baseline_config = baseline["files"][module.R5_CONFIG_PATH]
        baseline_config["payload_sha256"] = (
            module.R5_DURABILITY_BASELINE_CONFIG_SHA256
        )
        baseline["controller"]["config_sha256"] = (
            module.R5_DURABILITY_BASELINE_CONFIG_SHA256
        )

        target = module.json.loads(module.canonical(baseline))
        target.pop("authority_sha256", None)
        target["source"] = {
            "core_commit": module.ACCEPTED_CORE_COMMIT,
            "core_tree": module.ACCEPTED_CORE_TREE,
            "deploy_commit": "d" * 40,
            "deploy_parent": module.ACCEPTED_DEPLOY_PARENT,
            "deploy_tree": "e" * 40,
        }
        target_plugin = target["releases"]["plugin"]
        target_plugin["digest"] = module.R5_DURABILITY_TARGET_PLUGIN_RELEASE
        target_plugin["bundle_prefix"] = (
            "staging/releases/plugin/" + module.R5_DURABILITY_TARGET_PLUGIN_RELEASE
        )
        payload = module.r5_durability_target_config()
        target_config = target["files"][module.R5_CONFIG_PATH]
        target_config["payload_b64"] = base64.b64encode(payload).decode("ascii")
        target_config["payload_sha256"] = module.sha256(payload).hexdigest()
        target["controller"]["config_sha256"] = module.sha256(payload).hexdigest()

        validated = module.validate_r5_durability_authority(baseline, target)
        self.assertEqual(
            validated["releases"]["plugin"]["digest"],
            module.R5_DURABILITY_TARGET_PLUGIN_RELEASE,
        )
        self.assertEqual(
            validated["files"][module.R5_CONFIG_PATH]["payload_sha256"],
            module.R5_DURABILITY_TARGET_CONFIG_SHA256,
        )
        for field in ("builder", "image", "parent"):
            hostile = module.json.loads(module.canonical(target))
            hostile[field] = module.json.loads(module.canonical(target[field]))
            key = sorted(hostile[field])[0]
            hostile[field][key] = "substituted"
            with self.subTest(field=field), self.assertRaises(
                module.ProductionPlanRejected
            ):
                module.validate_r5_durability_authority(baseline, hostile)
        for release in ("core", "runtime"):
            hostile = module.json.loads(module.canonical(target))
            hostile["releases"][release]["digest"] = "0" * 64
            with self.subTest(release=release), self.assertRaises(
                module.ProductionPlanRejected
            ):
                module.validate_r5_durability_authority(baseline, hostile)
        protected_path = next(
            path for path in sorted(module.FILE_ROLES) if path != module.R5_CONFIG_PATH
        )
        hostile = module.json.loads(module.canonical(target))
        hostile["files"][protected_path]["payload_sha256"] = "0" * 64
        with self.assertRaises(module.ProductionPlanRejected):
            module.validate_r5_durability_authority(baseline, hostile)

    def test_r5_durability_source_constants_and_target_payload_are_frozen(self) -> None:
        self.assertEqual(
            module.R5_DURABILITY_TARGET_PLUGIN_RELEASE,
            "a85c745dd40b4c29e8e49072475fdbed6454bbacbbe5d373cf6144b265aff4af",
        )
        payload = module.r5_durability_target_config()
        self.assertEqual(
            module.sha256(payload).hexdigest(),
            "c1a20bd08ce3c56e1d273bed0e176c2f6a980d3c5373592c83a03db4d6412c63",
        )
        decoded = module.json.loads(payload.decode("ascii"))
        self.assertEqual(
            decoded["gateway_release"], module.R5_DURABILITY_TARGET_PLUGIN_RELEASE
        )
        self.assertNotIn(module.R5_DURABILITY_BASELINE_PLUGIN_RELEASE, payload.decode())

    def test_immutable_hybrid_builder_policy_and_boundaries_remain_finite(self) -> None:
        policy = module.source_policy()
        boundaries = module.source_boundaries()
        self.assertEqual(
            set(policy),
            {
                "automatic_private_writer_recovery",
                "fixed_product_contract_sha256",
                "private_content_required",
                "supervised_writer_boundary",
            },
        )
        self.assertEqual(set(boundaries), {"p01", "p08", "p09", "p10", "p15", "p16"})
        self.assertTrue(all(row["mutation_allowed"] is False for row in boundaries.values()))


    def test_replacement_attempt6_is_one_exact_prospective_whole_tuple(self) -> None:
        replacements: list[dict[str, object]] = []
        for seed in (11, 29):
            selected = authority(seed)
            current, old_hashes = observation(selected)
            with mock.patch.dict(module.OLD_FILE_SHA256, old_hashes, clear=True):
                plan = module.build_fixed_plan(selected, current)
                self.assertEqual(module.validate_fixed_plan(plan), plan)
            replacement = plan["replacement_attempt6"]
            self.assertEqual(
                replacement,
                module.source_contract()["replacement_attempt6"],
            )
            self.assertEqual(replacement["attempt"], 6)
            self.assertEqual(replacement["predecessor_attempt"], 5)
            self.assertTrue(replacement["attempt5_immutable"])
            self.assertFalse(replacement["attempt5_resume_allowed"])
            self.assertEqual(replacement["execution_owner"], "ATTEMPT6")
            self.assertEqual(
                replacement["target_start_stage"],
                "START_REPLACEMENT_ATTEMPT6_TARGET_ONCE",
            )
            self.assertFalse(replacement["consumed"])
            self.assertFalse(replacement["writer_bound"])
            self.assertEqual(replacement["creation_ordinal"], 1)
            self.assertEqual(replacement["callbacks"], 0)
            self.assertEqual(replacement["receipt_state"], "UNCREATED")
            self.assertIsNone(replacement["receipt_sha256"])
            self.assertEqual(
                replacement["current_tuple_sha256"],
                "a6a5d8adc79ef7085b050e8aee7f0adf1da7341ede441fa81dc066ac766caf17",
            )
            self.assertEqual(
                replacement["rollback_tuple_sha256"],
                replacement["current_tuple_sha256"],
            )
            self.assertEqual(
                replacement["target_tuple_sha256"],
                "96c4b4f8320b22c239f8a73f404d343bae4f14bdf41516ba123b31cdfca33ee4",
            )
            replacements.append(replacement)
        self.assertEqual(*replacements)
        self.assertNotIn(
            "post_writer_selected_root_authority_sha256",
            module.source_contract(),
        )
        self.assertNotIn("RESUME_ATTEMPT5_TARGET_ONCE", module.FIXED_STAGES)

    def test_replacement_attempt6_hostile_authorities_reject(self) -> None:
        selected = authority(11)
        current, old_hashes = observation(selected)
        with mock.patch.dict(module.OLD_FILE_SHA256, old_hashes, clear=True):
            plan = module.build_fixed_plan(selected, current)
        hostile_fields = (
            ("attempt", 7),
            ("predecessor_attempt", 6),
            ("attempt5_immutable", False),
            ("attempt5_resume_allowed", True),
            ("creation_ordinal", 2),
            ("execution_owner", "ATTEMPT5"),
            ("consumed", True),
            ("writer_bound", True),
            ("callbacks", 1),
            ("current_role", "THIRD_STATE"),
            ("target_role", "THIRD_STATE"),
            ("rollback_role", "EXACT_TARGET"),
            ("current_tuple_sha256", module.REPLACEMENT_ATTEMPT6_TARGET_TUPLE_SHA256),
            ("target_tuple_sha256", module.REPLACEMENT_ATTEMPT6_CURRENT_TUPLE_SHA256),
            ("rollback_tuple_sha256", module.REPLACEMENT_ATTEMPT6_TARGET_TUPLE_SHA256),
            ("receipt_state", "PRESENT"),
            ("receipt_sha256", "0" * 64),
            ("target_start_stage", "RESUME_ATTEMPT5_TARGET_ONCE"),
            ("authority_sha256", "0" * 64),
        )
        for field, value in hostile_fields:
            hostile = module.json.loads(module.canonical(plan))
            hostile["replacement_attempt6"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                module.ProductionPlanRejected,
                "fixed_replacement_attempt6_authority_rejected",
            ):
                module.validate_fixed_plan(hostile)
        for key in (
            "attempt5_resume_allowed",
            "current_tuple_sha256",
            "execution_owner",
            "receipt_state",
            "target_start_stage",
        ):
            partial = module.json.loads(module.canonical(plan))
            del partial["replacement_attempt6"][key]
            with self.subTest(missing=key), self.assertRaisesRegex(
                module.ProductionPlanRejected,
                "fixed_replacement_attempt6_authority_rejected",
            ):
                module.validate_fixed_plan(partial)

        for key, value in (
            ("attempt6_absent", True),
            ("attempt_consumed", True),
            ("resume_stage", "RESUME_ATTEMPT5_TARGET_ONCE"),
        ):
            mixed = module.json.loads(module.canonical(plan))
            mixed["replacement_attempt6"][key] = value
            with self.subTest(mixed=key), self.assertRaisesRegex(
                module.ProductionPlanRejected,
                "fixed_replacement_attempt6_authority_rejected",
            ):
                module.validate_fixed_plan(mixed)

if __name__ == "__main__":
    unittest.main()
