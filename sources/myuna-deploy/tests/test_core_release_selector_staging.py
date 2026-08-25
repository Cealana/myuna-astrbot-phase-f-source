from __future__ import annotations

import ast
from copy import deepcopy
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from install_core_release_selector_staging import (  # noqa: E402
    GUARD_DROPIN,
    STABLE_SELECTOR_DROPIN,
    STAGED_CANDIDATE,
    STAGED_INTENT,
    STAGED_MANIFEST,
    StagingInstallError,
    build_inactive_payloads,
    install_inactive_staging,
)
from core_release_selector import SelectorContractError  # noqa: E402


PLAN_DIGEST = "a" * 64
VERIFIER_SHA256 = "3fab13b7b533c3e93bf5759256ff5153d7bb17aea0fc8307f560e82985a7fcaf"


class InactivePayloadTests(unittest.TestCase):
    def test_payloads_are_exact_and_explicitly_inactive(self) -> None:
        verifier, tool, staged = build_inactive_payloads(
            ROOT, approved_plan_digest=PLAN_DIGEST
        )
        self.assertEqual(verifier, VERIFIER_SHA256)
        self.assertEqual(set(tool), {"core_release_selector.py"})
        self.assertEqual(
            set(staged),
            {
                STAGED_CANDIDATE,
                STAGED_INTENT,
                STAGED_MANIFEST,
                GUARD_DROPIN,
                STABLE_SELECTOR_DROPIN,
            },
        )
        manifest = json.loads(staged[STAGED_MANIFEST].decode("utf-8"))
        self.assertEqual(manifest["status"], "inactive_staging")
        self.assertEqual(
            manifest["approved_inactive_install_plan_digest"], PLAN_DIGEST
        )
        self.assertFalse(manifest["runtime_binding_present"])
        self.assertFalse(manifest["active_systemd_dropin_written"])
        self.assertFalse(manifest["daemon_reload_performed"])
        self.assertFalse(manifest["service_lifecycle_performed"])

    def test_invalid_approval_digest_is_rejected(self) -> None:
        for value in ("", "A" * 64, "a" * 63):
            with self.subTest(value=value):
                with self.assertRaises(StagingInstallError):
                    build_inactive_payloads(ROOT, approved_plan_digest=value)

    def test_source_binding_intent_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            (source / "scripts").mkdir(parents=True)
            (source / "config").mkdir()
            for relative in (
                "scripts/core_release_selector.py",
                "config/core-release-selector-v1.json",
                "config/core-release-selector-v1-binding-intent.json",
            ):
                target = source / relative
                target.write_bytes((ROOT / relative).read_bytes())
            intent_path = source / "config/core-release-selector-v1-binding-intent.json"
            payload = json.loads(intent_path.read_text(encoding="utf-8"))
            payload["guard_dropin_sha256"] = "b" * 64
            intent_path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(SelectorContractError):
                build_inactive_payloads(source, approved_plan_digest=PLAN_DIGEST)


class InactiveInstallTests(unittest.TestCase):
    def _roots(self, root: Path) -> tuple[Path, Path]:
        tool = root / "opt/myuna/core-release-selector/releases"
        candidate = root / "etc/myuna/core-release-selector/candidates"
        tool.parent.parent.mkdir(parents=True)
        candidate.parent.parent.mkdir(parents=True)
        return tool, candidate

    def test_install_is_content_addressed_inactive_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tool_root, candidate_root = self._roots(Path(temporary))
            uid, gid = os.getuid(), os.getgid()
            first = install_inactive_staging(
                PLAN_DIGEST,
                source_root=ROOT,
                tool_release_root=tool_root,
                candidate_root=candidate_root,
                uid=uid,
                gid=gid,
            )
            self.assertTrue(first["tool_created"])
            self.assertTrue(first["staging_created"])
            self.assertFalse(first["runtime_changed"])
            self.assertFalse(first["systemd_changed"])
            self.assertFalse(first["selected_or_activated"])
            tool_destination = tool_root / VERIFIER_SHA256
            staging_destination = candidate_root / PLAN_DIGEST
            self.assertTrue((tool_destination / "core_release_selector.py").is_file())
            self.assertTrue((staging_destination / STAGED_MANIFEST).is_file())
            self.assertEqual(stat.S_IMODE(tool_destination.stat().st_mode), 0o550)
            self.assertEqual(
                stat.S_IMODE((tool_destination / "core_release_selector.py").stat().st_mode),
                0o440,
            )
            second = install_inactive_staging(
                PLAN_DIGEST,
                source_root=ROOT,
                tool_release_root=tool_root,
                candidate_root=candidate_root,
                uid=uid,
                gid=gid,
            )
            self.assertFalse(second["tool_created"])
            self.assertFalse(second["staging_created"])

    def test_existing_staging_content_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tool_root, candidate_root = self._roots(Path(temporary))
            uid, gid = os.getuid(), os.getgid()
            install_inactive_staging(
                PLAN_DIGEST,
                source_root=ROOT,
                tool_release_root=tool_root,
                candidate_root=candidate_root,
                uid=uid,
                gid=gid,
            )
            target = candidate_root / PLAN_DIGEST / STAGED_MANIFEST
            target.chmod(0o640)
            target.write_bytes(target.read_bytes() + b"\n")
            target.chmod(0o440)
            with self.assertRaises(StagingInstallError):
                install_inactive_staging(
                    PLAN_DIGEST,
                    source_root=ROOT,
                    tool_release_root=tool_root,
                    candidate_root=candidate_root,
                    uid=uid,
                    gid=gid,
                )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_symlinked_staging_destination_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tool_root, candidate_root = self._roots(root)
            uid, gid = os.getuid(), os.getgid()
            candidate_root.parent.mkdir(mode=0o750)
            os.chown(candidate_root.parent, uid, gid)
            target = root / "elsewhere"
            target.mkdir()
            candidate_root.symlink_to(target, target_is_directory=True)
            with self.assertRaises(StagingInstallError):
                install_inactive_staging(
                    PLAN_DIGEST,
                    source_root=ROOT,
                    tool_release_root=tool_root,
                    candidate_root=candidate_root,
                    uid=uid,
                    gid=gid,
                )


class StagingStaticSafetyTests(unittest.TestCase):
    def test_installer_has_no_process_network_or_systemd_api(self) -> None:
        source_path = ROOT / "scripts/install_core_release_selector_staging.py"
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots: set[str] = set()
        called_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                called_names.add(node.func.id)
        self.assertTrue(
            {"subprocess", "socket", "requests", "urllib"}.isdisjoint(imported_roots)
        )
        self.assertNotIn("system", called_names)
        self.assertNotIn("popen", called_names)
        self.assertNotIn("systemctl", source)
        self.assertNotIn("daemon-reload", source)


if __name__ == "__main__":
    unittest.main()
