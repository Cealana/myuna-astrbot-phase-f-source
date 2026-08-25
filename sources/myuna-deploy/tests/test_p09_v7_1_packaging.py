from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from scripts import activate_p07_hybrid_external_generation_v1 as activation
from scripts import build_p07_hybrid_live_releases_v1 as builder
from scripts import p09_v7_phase1_packaging_contract as contract


REPO = Path(__file__).resolve().parents[1]


def load_protocol():
    path = REPO / "channels/astrbot-telegram/plugin/myuna_telegram_gateway/protocol.py"
    spec = importlib.util.spec_from_file_location("v7_1_telegram_protocol", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class P09V71ContractTests(unittest.TestCase):
    def test_contract_is_exact_inactive_and_content_free(self) -> None:
        self.assertEqual(contract.V7_1_RUNTIME_PROFILE, "p09-v7.1-authoring-v1")
        self.assertEqual(
            contract.V7_1_CORE_COMMIT,
            "7ec92e64b11a77ef18638c1a37724a38b0d341a9",
        )
        payload = contract.contract_payload(contract.V7_1_RUNTIME_PROFILE)
        self.assertEqual(payload["schema"], "myuna.p09-v7.1-runtime-projection.v1")
        self.assertEqual(payload["profile_version"], "v7.1")
        self.assertEqual(payload["owner_input_schema"], "myuna.owner-input.v7.1")
        self.assertEqual(payload["ordered_reply_schema"], "myuna.ordered-reply.v1")
        self.assertTrue(payload["ordered_multibeat_reply"])
        self.assertTrue(payload["semantic_pause_preservation"])
        self.assertTrue(payload["closure_consistent_actions"])
        self.assertFalse(payload["dynamic_affinity_state"])
        self.assertFalse(payload["affinity_persistence"])
        self.assertFalse(payload["profile_or_session_writes"])
        self.assertFalse(payload["external_context_mutation"])
        self.assertFalse(payload["legacy_trust_migration"])
        self.assertEqual(payload["rollback"]["definition_version"], "v6")
        self.assertEqual(payload["rollback"]["runtime_profile"], "p07-hybrid-v2")
        self.assertFalse(payload["structured_affinity_foundation"]["active"])
        self.assertFalse(payload["structured_affinity_foundation"]["packaged"])
        self.assertEqual(
            payload["definition_source"]["zip_sha256"],
            "ebe4e33ed3301e7282d95158e8a5a1cac77f39f90ec6ecd5ecec27415161e9e7",
        )
        serialized = json.dumps(payload, sort_keys=True)
        for forbidden in (
            "secret",
            "private_message",
            "database_row",
            "profile_content",
            "provider_payload",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_old_profiles_and_projection_inventories_are_immutable(self) -> None:
        self.assertEqual(
            contract.projection_files_for(contract.LEGACY_RUNTIME_PROFILE),
            contract.PROJECTION_FILES,
        )
        self.assertEqual(
            contract.projection_files_for(contract.RUNTIME_PROFILE),
            contract.PROJECTION_FILES,
        )
        self.assertEqual(
            contract.core_commit_for(contract.RUNTIME_PROFILE),
            "000b5f1a8bb3c0fca9885b0ff5387087bceaa37c",
        )
        self.assertEqual(builder._BASELINE_RUNTIME_PROFILE, "p07-hybrid-v2")

    def test_mixed_projection_inventory_and_stale_identity_fail_closed(self) -> None:
        profile = contract.V7_1_RUNTIME_PROFILE
        runtime_files = [
            f"runtime/{path}" for path in contract.projection_files_for(profile)
        ]
        runtime_files.append("runtime/p09_v7_phase1_projection/__init__.py")
        with self.assertRaises(contract.V7PackagingContractRejected) as mixed:
            contract.validate_runtime_contract(
                contract.contract_payload(profile),
                runtime_profile=profile,
                core_commit=contract.V7_1_CORE_COMMIT,
                roots=contract.V7_1_CORE_ROOT_MODULES,
                core_files=contract.V7_1_CORE_FILES,
                runtime_files=runtime_files,
            )
        self.assertEqual(mixed.exception.code, "v7_runtime_projection_mixed_contract_rejected")
        with self.assertRaises(contract.V7PackagingContractRejected):
            contract.validate_runtime_contract(
                contract.contract_payload(profile),
                runtime_profile=profile,
                core_commit=contract.CORE_COMMIT,
                roots=contract.V7_1_CORE_ROOT_MODULES,
                core_files=contract.V7_1_CORE_FILES,
                runtime_files=[
                    f"runtime/{path}"
                    for path in contract.projection_files_for(profile)
                ],
            )

    def test_telegram_protocol_preserves_unicode_order_and_semantic_blank_lines(self) -> None:
        protocol = load_protocol()
        rendered = "先等一下（抬手示意）\n\n好，现在继续\n（把视线转回来）"
        raw = json.dumps(
            {"code": "owner-runtime-reply", "reply": rendered, "status": "accepted"},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertEqual(protocol.decode_gateway_response(raw)["reply"], rendered)
        self.assertTrue(protocol.check_command_is_explicit(" /Check status "))

    def test_projection_sources_contain_no_wildcard_discovery_or_polling(self) -> None:
        projection_root = REPO / "scripts/p09_v7_1_projection"
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(projection_root.glob("*.py"))
        )
        for forbidden in ("rglob(", "glob(\"*", "poll(", "asyncio.sleep"):
            self.assertNotIn(forbidden, sources)


@unittest.skipUnless(os.environ.get("P09_V7_CORE_SOURCE"), "exact Core candidate required")
class P09V71ExactCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        core = Path(os.environ["P09_V7_CORE_SOURCE"])
        sys.path.insert(0, str(core / "src"))

    @classmethod
    def tearDownClass(cls) -> None:
        core = Path(os.environ["P09_V7_CORE_SOURCE"])
        candidate = str(core / "src")
        if candidate in sys.path:
            sys.path.remove(candidate)

    def test_exact_core_source_inventory_and_projection(self) -> None:
        core = Path(os.environ["P09_V7_CORE_SOURCE"])
        profile = contract.V7_1_RUNTIME_PROFILE
        contract.validate_core_source(core, contract.V7_1_CORE_COMMIT, profile)
        closure = builder.runtime_core_import_closure(
            core,
            root_modules=contract.core_root_modules_for(profile),
        )
        self.assertEqual(closure, contract.core_files_for(profile))
        self.assertEqual(
            set(closure) - set(contract.CORE_FILES),
            {"myuna_core/interaction_contract_v7_1.py"},
        )

        from scripts.p09_v7_1_projection import validate_projection
        from scripts.p09_v7_1_projection.adapter import (
            adapter_policy_for,
            preserve_rendered_reply,
        )

        validate_projection()
        observer = adapter_policy_for(
            "（她为什么停顿了一下？）",
            hybrid_external_generation=True,
        )
        self.assertEqual(observer.route, "observer_inquiry")
        self.assertFalse(observer.legacy_history_read)
        self.assertFalse(observer.legacy_history_write)
        self.assertFalse(observer.external_context_read)
        self.assertFalse(observer.external_epoch_write)
        self.assertFalse(observer.background_polling)
        command = adapter_policy_for("/Check status", hybrid_external_generation=True)
        self.assertEqual(command.route, "command_isolated")
        self.assertFalse(command.provider_call_allowed)
        hybrid = adapter_policy_for("普通消息", hybrid_external_generation=True)
        self.assertFalse(hybrid.legacy_history_write)
        self.assertTrue(hybrid.external_epoch_write)
        rendered = "第一拍\n\n第二拍\n（第三拍动作）"
        self.assertEqual(preserve_rendered_reply(rendered), rendered)


@unittest.skipUnless(
    os.geteuid() == 0
    and os.environ.get("P09_V7_CORE_SOURCE")
    and os.environ.get("P09_V7_DEPLOY_SOURCE")
    and os.environ.get("P09_V7_DEPLOY_COMMIT")
    and os.environ.get("P09_V7_RUNTIME_BASE"),
    "exact root service-identity build inputs required",
)
class P09V71DeterministicBuildTests(unittest.TestCase):
    def test_deterministic_build_validation_and_startup_import(self) -> None:
        core = Path(os.environ["P09_V7_CORE_SOURCE"])
        deploy = Path(os.environ["P09_V7_DEPLOY_SOURCE"])
        deploy_commit = os.environ["P09_V7_DEPLOY_COMMIT"]
        base = Path(os.environ["P09_V7_RUNTIME_BASE"])
        profile = contract.V7_1_RUNTIME_PROFILE
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = builder.build_runtime(
                deploy,
                deploy_commit,
                core,
                contract.V7_1_CORE_COMMIT,
                base,
                root / "first",
                profile,
            )
            second = builder.build_runtime(
                deploy,
                deploy_commit,
                core,
                contract.V7_1_CORE_COMMIT,
                base,
                root / "second",
                profile,
            )
            self.assertEqual(first, second)
            digest = first["release_digest"]
            candidate = root / "first" / digest
            self.assertEqual(
                activation.validate_runtime(
                    candidate,
                    contract.V7_1_CORE_COMMIT,
                    deploy_commit,
                ),
                digest,
            )
            activation.verify_runtime_startup_smoke(candidate)
            self.assertFalse(any(path.suffix == ".pyc" for path in candidate.rglob("*")))
            self.assertFalse(any(path.name == "__pycache__" for path in candidate.rglob("*")))

            mixed = root / "mixed" / digest
            shutil.copytree(candidate, mixed)
            extra = mixed / "runtime/p09_v7_phase1_projection/__init__.py"
            extra.parent.mkdir(parents=True)
            extra.write_text("# stale projection\n", encoding="utf-8")
            with self.assertRaises(activation.ActivationRejected):
                activation.validate_runtime(
                    mixed,
                    contract.V7_1_CORE_COMMIT,
                    deploy_commit,
                )


if __name__ == "__main__":
    unittest.main()
