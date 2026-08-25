from __future__ import annotations

from pathlib import Path
import pwd
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import activate_p07_policy_overlay_v1 as activation


def prepared() -> activation.PreparedPolicyOverlayActivation:
    parent = SimpleNamespace(release_set_id="a" * 64)
    overlay = SimpleNamespace(overlay_id="b" * 64)
    return activation.PreparedPolicyOverlayActivation(  # type: ignore[arg-type]
        core_candidate=Path("/synthetic/core"),
        runtime_candidate=Path("/synthetic/runtime"),
        plugin_candidate=Path("/synthetic/plugin"),
        bundle_root=Path("/synthetic/bundle"),
        core_commit="1" * 40,
        deploy_commit="2" * 40,
        parent=parent,
        parent_manifest_digest="3" * 64,
        parent_selector_digest="4" * 64,
        overlay=overlay,
        overlay_documents={},
        overlay_bundle_manifest={"bundle_id": "5" * 64},
        core_release="6" * 64,
        runtime_release="7" * 64,
        plugin_release="8" * 64,
        plugin_config_digest="9" * 64,
        target_core_binding=b"binding\n",
        target_core_selector=b"selector\n",
        target_telegram_dropin=b"dropin\n",
        prestate={},
        prestate_payloads={},
        plan_bytes=b'{"schema":"synthetic"}\n',
        expected_revision=63,
        expected_turns=51,
        expected_summaries=12,
    )


class PolicyOverlayActivationTests(unittest.TestCase):
    @unittest.skipUnless(__import__("os").geteuid() == 0, "root-only metadata fixture")
    def test_rollback_roots_require_same_filesystem_and_safe_parents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup_parent = root / "backups"
            overlay_parent = root / "overlay"
            state_parent = root / "state"
            for path in (backup_parent, overlay_parent, state_parent):
                path.mkdir(mode=0o700)
            __import__("os").chown(
                backup_parent,
                pwd.getpwnam("myuna").pw_uid,
                backup_parent.stat().st_gid,
            )
            __import__("os").chown(
                state_parent,
                pwd.getpwnam(activation.TELEGRAM_RUNTIME_USER).pw_uid,
                state_parent.stat().st_gid,
            )
            with (
                patch.object(activation, "BACKUP_ROOT", backup_parent / "series"),
                patch.object(
                    activation,
                    "POLICY_OVERLAY_MANIFEST_PATH",
                    overlay_parent / "overlay.json",
                ),
                patch.object(activation, "STATE_ROOT", state_parent / "series"),
            ):
                projection = activation._verify_rollback_roots()
                self.assertEqual(set(projection), {"backup_parent", "overlay_parent", "state_parent"})
                overlay_parent.chmod(0o702)
                with self.assertRaisesRegex(
                    activation.PolicyOverlayActivationRejected,
                    "rollback_parent_rejected",
                ):
                    activation._verify_rollback_roots()

    def test_preflight_is_content_free_and_has_no_mutation_flags(self) -> None:
        selected = prepared()
        projection = activation.activate(
            selected,
            expected_plan_sha256=selected.plan_digest,
            preflight_only=True,
        )
        self.assertEqual(projection["status"], "ready")
        self.assertEqual(projection["attempts"], 0)
        self.assertEqual(projection["next_attempt"], 1)
        self.assertEqual(projection["maximum_attempts"], 2)
        for field in (
            "channel_called",
            "health_called",
            "model_called",
            "mutation_performed",
            "private_content_read",
            "provider_called",
        ):
            self.assertIs(projection[field], False)

    def test_plan_mismatch_rejects_before_backend_construction(self) -> None:
        selected = prepared()
        with patch.object(activation, "LivePolicyOverlayBackend") as backend:
            with self.assertRaisesRegex(
                activation.PolicyOverlayActivationRejected,
                "policy_overlay_plan_drifted",
            ):
                activation.activate(
                    selected,
                    expected_plan_sha256="f" * 64,
                    preflight_only=False,
                )
        backend.assert_not_called()

    def test_attempt_ledger_missing_is_zero_and_malformed_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            with patch.object(activation, "ATTEMPT_LEDGER", ledger):
                self.assertEqual(activation._attempt_count(), 0)
                ledger.write_text("{}\n", encoding="ascii")
                ledger.chmod(0o600)
                with self.assertRaisesRegex(
                    activation.PolicyOverlayActivationRejected,
                    "attempt_ledger_rejected",
                ):
                    activation._attempt_count()

    def test_attempt_ledger_symlink_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_text(
                '{"attempts":0,"last_plan_sha256":"'
                + "0" * 64
                + '","schema":"myuna.p07-policy-overlay-attempt-ledger.v1"}\n',
                encoding="ascii",
            )
            link = root / "ledger.json"
            link.symlink_to(target)
            with patch.object(activation, "ATTEMPT_LEDGER", link):
                with self.assertRaisesRegex(
                    activation.PolicyOverlayActivationRejected,
                    "attempt_ledger_rejected",
                ):
                    activation._attempt_count()


if __name__ == "__main__":
    unittest.main()
