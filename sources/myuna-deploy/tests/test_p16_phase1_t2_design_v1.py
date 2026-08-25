from __future__ import annotations

import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_p16_phase1_t2_releases_v1 as builder  # noqa: E402
from p16_phase1_t2_contract_v1 import (  # noqa: E402
    FORBIDDEN_FIELDS,
    build_design_plan,
    build_preflight,
    canonical,
    validate_bundle,
)


CHECKPOINT = json.loads(
    (ROOT / "tests/fixtures/p16_phase1_t2_generation13_checkpoint_v1.json").read_text(
        encoding="ascii"
    )
)


class P16Phase1T2DesignV1Tests(unittest.TestCase):
    def _source_tree(self, root: Path, mapping: dict[str, str]) -> None:
        for source in mapping.values():
            path = root / source
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"source:{source}\n", encoding="utf-8")

    def _base_tree(self, root: Path, mapping: dict[str, str] | None = None) -> None:
        root.mkdir(parents=True)
        (root / "sentinel.txt").write_text("base\n", encoding="ascii")
        for destination in (mapping or {}):
            path = root / destination
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"base:{destination}\n", encoding="utf-8")

    def _build(self, root: Path, name: str, deploy_commit: str = "8" * 40) -> dict[str, object]:
        core_source = root / "core-source"
        deploy_source = root / "deploy-source"
        core_base = root / "bases" / builder.GENERATION13_CORE
        runtime_base = root / "bases" / builder.GENERATION13_RUNTIME
        plugin_base = root / "bases" / builder.GENERATION13_PLUGIN
        if not core_source.exists():
            self._source_tree(core_source, builder.p16_builder._CORE_OVERLAYS)
            self._source_tree(
                deploy_source,
                {**builder.TELEGRAM_OVERLAYS, **builder.ADAPTER_OVERLAYS},
            )
            controller = deploy_source / builder.CONTROLLER_SOURCE
            controller.parent.mkdir(parents=True, exist_ok=True)
            controller.write_text("# synthetic controller\n", encoding="ascii")
            self._base_tree(core_base, builder.p16_builder._CORE_OVERLAYS)
            self._base_tree(runtime_base, builder.TELEGRAM_OVERLAYS)
            self._base_tree(plugin_base)
        return builder.build_phase1_t2_bundle(
            core_base=core_base,
            telegram_base=runtime_base,
            plugin_base=plugin_base,
            core_source_root=core_source,
            deploy_source_root=deploy_source,
            core_source_commit=builder.EXPECTED_CORE_SOURCE,
            deploy_source_commit=deploy_commit,
            output_root=root / name,
        )

    def test_a_b_builds_have_identical_artifacts_complete_inventories_and_no_links(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self._build(root, "run-a")
            second = self._build(root, "run-b")
            replay = self._build(root, "run-a")
            self.assertEqual(first, second)
            self.assertEqual(first, replay)
            self.assertEqual(validate_bundle(first), first)
            self.assertEqual(len(first["controller_source_sha256"]), 64)
            for name in sorted(first["artifacts"]):
                left = json.loads((root / "run-a/inventories" / f"{name}.json").read_text())
                right = json.loads((root / "run-b/inventories" / f"{name}.json").read_text())
                self.assertEqual(left, right)
                self.assertEqual(len(left["files"]), first["artifacts"][name]["file_count"])
                self.assertTrue(all(item["mode"] == "0440" for item in left["files"]))
            for run in (root / "run-a", root / "run-b"):
                for path in run.rglob("*"):
                    self.assertFalse(path.is_symlink())
                    if path.is_dir() and path.name not in {"inventories"}:
                        self.assertFalse(stat.S_IMODE(path.stat().st_mode) & 0o022)

    def test_plan_is_default_off_content_free_and_requires_fresh_live_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = self._build(Path(directory), "run-a")
            plan = build_design_plan(bundle, CHECKPOINT)
            self.assertFalse(plan["activation_ready"])
            self.assertTrue(plan["fresh_live_preflight_required"])
            self.assertEqual(plan["marker"]["install_state"], "absent")
            self.assertEqual(plan["selector"]["payload"]["channel"], "telegram")
            self.assertEqual(plan["receipt"]["public_reply_contract"], "unchanged")
            self.assertEqual(plan["rollback"]["history_action"], "preserve_no_delete_on_rollback_or_uninstall")
            self.assertEqual(plan["least_privilege"]["acl_policy"], "no_unlisted_entries")
            self.assertEqual(
                plan["rollback"]["desired_service_state"],
                {
                    "core": "active_running",
                    "telegram_runtime": "active_running",
                    "telegram_socket": "active_running",
                    "p08_service": "active_running",
                    "p08_socket": "active_running",
                },
            )
            self.assertIn("qq", plan["untouched_scope"])
            serialized = canonical(plan).decode("ascii")
            self.assertTrue(all(field not in plan["receipt"]["fields"] for field in FORBIDDEN_FIELDS))
            self.assertNotIn("private_message", serialized)
            first = build_preflight(bundle, CHECKPOINT)
            second = build_preflight(bundle, CHECKPOINT)
            self.assertEqual(first, second)
            self.assertFalse(first["activation_ready"])
            self.assertFalse(first["live_observation_performed"])
            self.assertFalse(first["mutation_performed"])

    def test_any_checkpoint_or_bundle_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = self._build(Path(directory), "run-a")
            for drift in (
                {"content_free": False},
                {"bundle_digest": "0" * 64},
                {"extra": "forbidden"},
            ):
                with self.subTest(bundle_drift=drift):
                    with self.assertRaises(ValueError):
                        build_preflight({**bundle, **drift}, CHECKPOINT)
            checkpoint = json.loads(json.dumps(CHECKPOINT))
            checkpoint["aggregate"]["pending"] = 1
            with self.assertRaises(ValueError):
                build_preflight(bundle, checkpoint)

    def test_service_overlay_is_additive_and_does_not_enable_or_restart(self) -> None:
        dropin = (
            ROOT
            / "systemd/myuna-telegram-owner-runtime-dev.service.d/40-p16-incident-history-v1.conf"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "ReadWritePaths=/var/lib/myuna-fault-diagnostics/incident-history-v1/telegram",
            dropin,
        )
        self.assertNotIn("ExecStart", dropin)
        self.assertNotIn("ConditionPathExists", dropin)
        self.assertNotIn("systemctl", dropin)
        service = (ROOT / "systemd/myuna-telegram-owner-runtime-dev.service").read_text(
            encoding="utf-8"
        )
        self.assertIn("User=myuna-gateway-telegram", service)
        self.assertIn("Group=myuna-gateway-telegram", service)
        self.assertIn("NoNewPrivileges=true", service)
        self.assertIn("CapabilityBoundingSet=", service)


if __name__ == "__main__":
    unittest.main()
