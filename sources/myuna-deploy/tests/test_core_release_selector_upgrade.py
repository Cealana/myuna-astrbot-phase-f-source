from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import sys
import unittest


FORMAL_SCRIPTS = Path("/srv/myuna/repos/deploy/scripts")
CANDIDATE_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(FORMAL_SCRIPTS))
sys.path.insert(0, str(CANDIDATE_SCRIPTS))

from core_release_selector import (  # noqa: E402
    ReleaseEvidence,
    SelectionCandidate,
    build_binding_intent,
    canonical_json_bytes,
    render_runtime_binding,
    render_selector_dropin,
)
import core_release_selector_upgrade as upgrade  # noqa: E402


def h(payload: bytes) -> str:
    return sha256(payload).hexdigest()


class UpgradeContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.current = ReleaseEvidence(
            tree_sha256="1" * 64,
            source_commit="2" * 40,
            file_count=149,
            artifact_manifest_sha256="3" * 64,
            installation_receipt_sha256="4" * 64,
        )
        self.target = ReleaseEvidence(
            tree_sha256="5" * 64,
            source_commit="6" * 40,
            file_count=153,
            artifact_manifest_sha256="7" * 64,
            installation_receipt_sha256="8" * 64,
        )
        self.verifier = "/opt/myuna/core-release-selector/releases/" + "9" * 64 + "/core_release_selector.py"
        current_intent = build_binding_intent(
            SelectionCandidate(self.current),
            verifier_script_path=self.verifier,
            verifier_script_sha256="9" * 64,
        )
        self.current_binding = render_runtime_binding(
            current_intent, approval_plan_digest="a" * 64
        )
        self.current_binding_payload = canonical_json_bytes(self.current_binding.to_payload())
        self.rollback_selector = render_selector_dropin(SelectionCandidate(self.current)).encode()
        self.target_selector = render_selector_dropin(SelectionCandidate(self.target)).encode()
        self.old_env = b"MYUNA_ENV=dev\nMYUNA_DEV_TOKEN_CREDENTIAL=qq_owner_core_token\n"
        self.new_env = (
            b"MYUNA_ENV=dev\nMYUNA_HTTP_CLIENT_CREDENTIALS="
            b"qq-owner-private:astrbot_qq:qq_owner_core_token,"
            b"telegram-owner-private:astrbot_telegram:telegram_owner_core_token\n"
        )
        self.credential = (
            b"[Service]\nLoadCredential=telegram_owner_core_token:"
            b"/etc/myuna-telegram-gateway/secrets/core-token-v1\n"
        )
        self.prestate_dropins = {
            "05-core-release-selector-guard-v1.conf": "b" * 64,
            upgrade.SELECTOR_DROPIN: h(self.rollback_selector),
            "credentials.conf": "c" * 64,
        }
        self.target_dropins = dict(self.prestate_dropins)
        self.target_dropins[upgrade.SELECTOR_DROPIN] = h(self.target_selector)
        self.target_dropins[upgrade.TELEGRAM_CREDENTIAL_DROPIN] = h(self.credential)
        self.states = {
            upgrade.UNIT: {"active_state": "inactive", "sub_state": "dead"},
            "myuna-qq-owner-runtime-dev.socket": {"active_state": "active", "sub_state": "listening"},
            "myuna-qq-owner-runtime-dev.service": {"active_state": "inactive", "sub_state": "dead"},
        }

    def plan(self) -> bytes:
        return upgrade.build_upgrade_plan(
            deploy_commit="d" * 40,
            core_commit="e" * 40,
            current_binding=self.current_binding,
            target_release=self.target,
            verifier_sha256="9" * 64,
            base_unit_sha256="f" * 64,
            prestate_dropin_sha256=self.prestate_dropins,
            target_dropin_sha256=self.target_dropins,
            prestate_qq_env_sha256=h(self.old_env),
            target_qq_env_sha256=h(self.new_env),
            target_selector_sha256=h(self.target_selector),
            target_credential_dropin_sha256=h(self.credential),
            service_states=self.states,
        )

    def bundle(self) -> dict[str, bytes]:
        plan = self.plan()
        target_intent = build_binding_intent(
            SelectionCandidate(self.target),
            verifier_script_path=self.verifier,
            verifier_script_sha256="9" * 64,
        )
        target_binding = render_runtime_binding(
            target_intent, approval_plan_digest=h(plan)
        )
        return upgrade.build_upgrade_bundle(
            plan=plan,
            target_binding=canonical_json_bytes(target_binding.to_payload()),
            target_selector=self.target_selector,
            target_qq_env=self.new_env,
            target_credential_dropin=self.credential,
            rollback_binding=self.current_binding_payload,
            rollback_selector=self.rollback_selector,
            rollback_qq_env=self.old_env,
        )

    def test_plan_is_canonical_and_round_trips(self) -> None:
        plan = self.plan()
        loaded = upgrade.load_upgrade_plan(plan)
        self.assertEqual(canonical_json_bytes(loaded), plan)
        self.assertEqual(loaded["target"]["selected_release"]["tree_sha256"], "5" * 64)

    def test_bundle_round_trips(self) -> None:
        bundle = self.bundle()
        manifest = upgrade.validate_upgrade_bundle(bundle)
        self.assertEqual(manifest["activation_plan_digest"], h(bundle[upgrade.PLAN_PATH]))
        self.assertFalse(manifest["activated"])

    def test_plan_rejects_same_release(self) -> None:
        with self.assertRaises(upgrade.UpgradeContractError):
            upgrade.build_upgrade_plan(
                deploy_commit="d" * 40,
                core_commit="e" * 40,
                current_binding=self.current_binding,
                target_release=self.current,
                verifier_sha256="9" * 64,
                base_unit_sha256="f" * 64,
                prestate_dropin_sha256=self.prestate_dropins,
                target_dropin_sha256=self.target_dropins,
                prestate_qq_env_sha256=h(self.old_env),
                target_qq_env_sha256=h(self.new_env),
                target_selector_sha256=h(self.target_selector),
                target_credential_dropin_sha256=h(self.credential),
                service_states=self.states,
            )

    def test_plan_rejects_missing_dedicated_credential_dropin(self) -> None:
        broken = dict(self.target_dropins)
        broken.pop(upgrade.TELEGRAM_CREDENTIAL_DROPIN)
        with self.assertRaises(upgrade.UpgradeContractError):
            upgrade.build_upgrade_plan(
                deploy_commit="d" * 40,
                core_commit="e" * 40,
                current_binding=self.current_binding,
                target_release=self.target,
                verifier_sha256="9" * 64,
                base_unit_sha256="f" * 64,
                prestate_dropin_sha256=self.prestate_dropins,
                target_dropin_sha256=broken,
                prestate_qq_env_sha256=h(self.old_env),
                target_qq_env_sha256=h(self.new_env),
                target_selector_sha256=h(self.target_selector),
                target_credential_dropin_sha256=h(self.credential),
                service_states=self.states,
            )

    def test_plan_rejects_unsafe_service_state(self) -> None:
        states = deepcopy(self.states)
        states[upgrade.UNIT] = {"active_state": "failed", "sub_state": "failed"}
        with self.assertRaises(upgrade.UpgradeContractError):
            upgrade.build_upgrade_plan(
                deploy_commit="d" * 40,
                core_commit="e" * 40,
                current_binding=self.current_binding,
                target_release=self.target,
                verifier_sha256="9" * 64,
                base_unit_sha256="f" * 64,
                prestate_dropin_sha256=self.prestate_dropins,
                target_dropin_sha256=self.target_dropins,
                prestate_qq_env_sha256=h(self.old_env),
                target_qq_env_sha256=h(self.new_env),
                target_selector_sha256=h(self.target_selector),
                target_credential_dropin_sha256=h(self.credential),
                service_states=states,
            )

    def test_bundle_rejects_wrong_target_binding_approval(self) -> None:
        bundle = self.bundle()
        raw = json.loads(bundle[upgrade.TARGET_BINDING_PATH])
        raw["approval_plan_digest"] = "0" * 64
        bundle[upgrade.TARGET_BINDING_PATH] = canonical_json_bytes(raw)
        manifest = json.loads(bundle[upgrade.MANIFEST_PATH])
        manifest["artifacts"][upgrade.TARGET_BINDING_PATH] = h(bundle[upgrade.TARGET_BINDING_PATH])
        bundle[upgrade.MANIFEST_PATH] = canonical_json_bytes(manifest)
        with self.assertRaises(upgrade.UpgradeContractError):
            upgrade.validate_upgrade_bundle(bundle)

    def test_bundle_rejects_environment_tamper(self) -> None:
        bundle = self.bundle()
        bundle[upgrade.TARGET_ENV_PATH] += b"UNAUTHORIZED=1\n"
        manifest = json.loads(bundle[upgrade.MANIFEST_PATH])
        manifest["artifacts"][upgrade.TARGET_ENV_PATH] = h(bundle[upgrade.TARGET_ENV_PATH])
        bundle[upgrade.MANIFEST_PATH] = canonical_json_bytes(manifest)
        with self.assertRaises(upgrade.UpgradeContractError):
            upgrade.validate_upgrade_bundle(bundle)

    def test_bundle_rejects_extra_path(self) -> None:
        bundle = self.bundle()
        bundle["target/extra.conf"] = b"x"
        with self.assertRaises(upgrade.UpgradeContractError):
            upgrade.validate_upgrade_bundle(bundle)


if __name__ == "__main__":
    unittest.main()

