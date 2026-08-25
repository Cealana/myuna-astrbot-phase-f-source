from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import telegram_r3_inactive_install_contract as contract


class TelegramR3InactiveInstallContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = contract.build_inactive_install_plan(
            core_commit="a" * 40,
            deploy_commit="b" * 40,
            core_release_digest="c" * 64,
            gateway_release_digest="d" * 64,
        )

    def test_plan_is_content_addressed_and_inactive(self) -> None:
        self.assertEqual(
            self.plan["status"],
            "candidate_not_installed_not_active",
        )
        self.assertTrue(
            self.plan["artifacts"]["core_release_target"].endswith("c" * 64)
        )
        self.assertTrue(
            self.plan["artifacts"]["gateway_release_target"].endswith("d" * 64)
        )
        self.assertEqual(len(contract.plan_digest(self.plan)), 64)

    def test_core_mutations_are_staged_outside_live_configuration(self) -> None:
        inactive = self.plan["inactive_runtime"]
        self.assertTrue(
            inactive["core_environment_candidate"].startswith(
                "/opt/myuna/telegram-gateway/staging/"
            )
        )
        self.assertTrue(
            inactive["core_systemd_dropin_candidate"].startswith(
                "/opt/myuna/telegram-gateway/staging/"
            )
        )
        serialized = contract.canonical_json(self.plan).decode("utf-8")
        self.assertNotIn("/etc/myuna/qq.env", serialized)
        self.assertNotIn(
            "/etc/systemd/system/myuna-core@qq.service.d/",
            serialized,
        )

    def test_systemd_units_are_bound_to_exact_content_addressed_releases(
        self,
    ) -> None:
        rendering = self.plan["inactive_runtime"][
            "content_addressed_systemd_units"
        ]
        self.assertEqual(
            rendering["core_release_root"],
            "/srv/myuna/releases/core/" + "c" * 64,
        )
        self.assertEqual(
            rendering["gateway_release_root"],
            "/opt/myuna/telegram-gateway/releases/" + "d" * 64,
        )
        self.assertEqual(len(rendering["units"]), 4)
        for filename, evidence in rendering["units"].items():
            self.assertEqual(
                evidence["inactive_install_target"],
                f"/etc/systemd/system/{filename}",
            )
            self.assertTrue(
                evidence["staging_target"].startswith(
                    "/opt/myuna/telegram-gateway/staging/" + "d" * 64
                )
            )
            self.assertEqual(len(evidence["template_sha256"]), 64)
            self.assertEqual(len(evidence["rendered_sha256"]), 64)
        self.assertIn(
            "render_content_addressed_telegram_service_and_socket_units",
            self.plan["operations"],
        )

    def test_core_release_access_is_narrow_acl_not_group_membership(self) -> None:
        identities = self.plan["created_identities"]
        access = self.plan["inactive_runtime"]["core_release_access"]
        self.assertEqual(identities["supplementary_groups"], [])
        self.assertFalse(access["wider_myuna_group_membership"])
        self.assertEqual(
            access["telegram_runtime_access"],
            "exact_release_user_acl_read_execute_only",
        )
        self.assertIn(
            "grant_exact_core_release_read_execute_acl_to_telegram_identity",
            self.plan["operations"],
        )
        self.assertIn(
            "add_telegram_identity_to_myuna_group",
            self.plan["forbidden_effects"],
        )

    def test_markers_secrets_and_units_remain_inactive(self) -> None:
        inactive = self.plan["inactive_runtime"]
        self.assertEqual(
            set(inactive["approval_markers"].values()),
            {"absent"},
        )
        self.assertTrue(inactive["secrets_directory"]["required_empty"])
        self.assertTrue(
            all(
                state in {"inactive", "disabled_inactive"}
                for state in inactive["service_states"].values()
            )
        )
        self.assertEqual(
            inactive["telegram_astrbot"],
            {
                "config_rendered": False,
                "container_state": "absent_or_stopped",
                "token_present": False,
            },
        )

    def test_one_no_login_identity_is_shared_with_the_container(self) -> None:
        identities = self.plan["created_identities"]
        self.assertEqual(
            identities["linux_user"],
            "myuna-gateway-telegram",
        )
        self.assertEqual(
            identities["astrbot_container_uid_gid_source"],
            "myuna-gateway-telegram",
        )
        self.assertTrue(identities["single_runtime_identity"])

    def test_plan_explicitly_forbids_activation_and_secret_use(self) -> None:
        forbidden = set(self.plan["forbidden_effects"])
        self.assertIn("read_or_write_secret_values", forbidden)
        self.assertIn("write_core_environment", forbidden)
        self.assertIn("write_core_systemd_dropin", forbidden)
        self.assertIn("select_or_activate_core_release", forbidden)
        self.assertIn("enable_start_or_restart_service", forbidden)
        self.assertIn("modify_database_schema_roles_grants_or_rows", forbidden)

    def test_invalid_digests_fail_closed(self) -> None:
        with self.assertRaises(contract.TelegramInactiveInstallRejected):
            contract.build_inactive_install_plan(
                core_commit="short",
                deploy_commit="b" * 64,
                core_release_digest="c" * 64,
                gateway_release_digest="d" * 64,
            )


if __name__ == "__main__":
    unittest.main()
