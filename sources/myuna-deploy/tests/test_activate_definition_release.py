from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import stat
import tempfile
import unittest

from scripts.activate_definition_release import ActivationError, activate


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


class ActivateDefinitionReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.definition = self.root / "definition"
        self.release = self.definition / "releases/v5/build"
        payload = self.release / "runtime-build/definition/SKILL.md"
        payload.parent.mkdir(parents=True)
        payload.write_text("test Definition\n", encoding="utf-8")
        digest = sha256(payload.read_bytes()).hexdigest().upper()
        manifest = self.release / "evidence/release-files.sha256"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(
            f"{digest}  runtime-build/definition/SKILL.md\n", encoding="utf-8"
        )
        self.summary = {
            "schema_version": 1,
            "status": "approved-release",
            "approved": True,
            "activation_allowed": True,
            "release_id": "v5-build",
            "version": "v5",
            "build_id": "build",
            "source_sha256": "A" * 64,
            "allowed_environments": ["dev"],
        }
        _write_json(self.release / "evidence/release-summary.json", self.summary)
        self.registry = self.definition / "registry.json"
        _write_json(
            self.registry,
            {
                "schema_version": 1,
                "active_version": None,
                "previous_version": None,
                "candidates": [{"version": "v5", "active": False}],
                "releases": [
                    {
                        "release_id": "v5-build",
                        "path": "releases/v5/build",
                        "active_environments": [],
                    }
                ],
            },
        )
        self.approval = self.definition / "approvals/v5.json"
        _write_json(
            self.approval,
            {
                "scope": "definition-v5-dev-release-only",
                "approved": True,
                "version": "v5",
                "build_id": "build",
                "source_sha256": "A" * 64,
                "allowed_environments": ["dev"],
                "authorizations": {
                    "create_release": True,
                    "activate_dev": True,
                    "loopback_core_test": True,
                    "real_memory": False,
                    "tools": False,
                    "external_listener": False,
                    "astrbot_qq": False,
                },
            },
        )
        for path in sorted(self.release.rglob("*"), reverse=True):
            path.chmod(0o550 if path.is_dir() else 0o440)
        self.release.chmod(0o550)

    def tearDown(self) -> None:
        for path in (self.release, *self.release.rglob("*")):
            try:
                path.chmod(0o700 if path.is_dir() else 0o600)
            except OSError:
                pass
        self.temporary.cleanup()

    def test_activation_is_atomic_and_updates_environment_registry(self) -> None:
        record = activate(
            environment="dev",
            release_root=self.release,
            registry_path=self.registry,
            approval_path=self.approval,
            environments_root=self.root / "environments",
            now=datetime(2026, 7, 16, tzinfo=timezone.utc),
        )
        current = self.root / "environments/dev/definition/current"
        self.assertTrue(current.is_symlink())
        self.assertEqual(current.resolve(), self.release.resolve())
        updated = json.loads(self.registry.read_text(encoding="utf-8"))
        self.assertEqual(updated["active_version"], "v5")
        self.assertEqual(updated["active_release_id"], "v5-build")
        self.assertEqual(updated["releases"][0]["active_environments"], ["dev"])
        self.assertEqual(record["scope"], "loopback-dev-conversation-only")
        self.assertEqual(stat.S_IMODE((current.parent / "activation.json").stat().st_mode), 0o640)

    def test_mismatched_approval_fails_before_creating_pointer(self) -> None:
        approval = json.loads(self.approval.read_text(encoding="utf-8"))
        approval["build_id"] = "wrong"
        _write_json(self.approval, approval)
        with self.assertRaises(ActivationError):
            activate(
                environment="dev",
                release_root=self.release,
                registry_path=self.registry,
                approval_path=self.approval,
                environments_root=self.root / "environments",
            )
        self.assertFalse((self.root / "environments/dev/definition/current").exists())

    def test_same_version_hotfix_tracks_previous_release_id(self) -> None:
        registry = json.loads(self.registry.read_text(encoding="utf-8"))
        registry["releases"].insert(
            0,
            {
                "release_id": "v5-old-build",
                "path": "releases/v5/old-build",
                "active_environments": ["dev"],
            },
        )
        registry["active_version"] = "v5"
        registry["active_release_id"] = "v5-old-build"
        _write_json(self.registry, registry)
        approval = json.loads(self.approval.read_text(encoding="utf-8"))
        approval.update(
            {
                "scope": "definition-v5-dev-qq-voice-hotfix-only",
                "activation_plan_digest": "d" * 64,
                "authorizations": {
                    "create_release": True,
                    "activate_dev": True,
                    "qq_owner_private_text": True,
                    "restart_qq_core": True,
                    "restart_channel_containers": False,
                    "real_memory": False,
                    "tools": False,
                    "external_listener": False,
                },
            }
        )
        _write_json(self.approval, approval)
        record = activate(
            environment="dev",
            release_root=self.release,
            registry_path=self.registry,
            approval_path=self.approval,
            environments_root=self.root / "environments",
        )
        updated = json.loads(self.registry.read_text(encoding="utf-8"))
        self.assertEqual(updated["active_release_id"], "v5-build")
        self.assertEqual(updated["previous_release_id"], "v5-old-build")
        self.assertEqual(
            record["scope"], "qq-owner-private-dev-voice-hotfix-only"
        )

    def test_writable_release_fails_closed(self) -> None:
        skill = self.release / "runtime-build/definition/SKILL.md"
        skill.chmod(0o640)
        with self.assertRaises(ActivationError):
            activate(
                environment="dev",
                release_root=self.release,
                registry_path=self.registry,
                approval_path=self.approval,
                environments_root=self.root / "environments",
            )


if __name__ == "__main__":
    unittest.main()
