from __future__ import annotations

import ast
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import activate_p08_p07_generation13_v1 as activation


class FakeP07ReleaseSet:
    generation = 13
    release_set_id = "1" * 64
    core = {"release_digest": "2" * 64}
    telegram_runtime = {"release_digest": "3" * 64}
    credential = {"projection_digest": "4" * 64}
    runtime_config = {"digest": "5" * 64}
    selector = {"digest": "6" * 64}
    epoch = {
        "epoch_id": "telegram-owner-private-external-d-reset-v7",
        "database_path": (
            "/var/lib/myuna-telegram-gateway/external-context-epochs/"
            "telegram-owner-private-external-d-reset-v7/epoch.db"
        ),
    }
    rollback = {
        "core_release_digest": "7" * 64,
        "desired_service_states_digest": "8" * 64,
        "epoch_bundle_digest": "9" * 64,
        "runtime_release_digest": "a" * 64,
        "selector_digest": "b" * 64,
    }


class FakeP07Prepared:
    def __init__(self) -> None:
        self.release_set = FakeP07ReleaseSet()
        self.plan_digest = "c" * 64
        self.target_telegram_config_digest = None
        self.prestate = {
            "files": {"release_set": {"sha256": "d" * 64}},
            "previous_bundle": {
                "bundle_projection": {
                    "files": [
                        {
                            "gid": 100,
                            "mode": 0o600,
                            "name": "epoch.db",
                            "state": "present",
                            "uid": 100,
                        }
                    ],
                    "parent": {"gid": 100, "mode": 0o700, "uid": 100},
                }
            },
        }


class FakeP08Plan:
    def as_payload(self) -> dict[str, object]:
        return {
            "schema": "myuna.p08-active-temporal-activation-plan.v1",
            "plan_digest": "e" * 64,
            "release_digest": "f" * 64,
            "core_commit": "1" * 40,
            "deploy_commit": "2" * 40,
            "gateway_client_sha256": "3" * 64,
            "gateway_manifest_digest": "4" * 64,
            "gateway_runtime": "/candidate/runtime",
            "plugin": "/candidate/plugin",
            "plugin_digest": "5" * 64,
            "release_source": "/candidate/p08",
            "release_target": "/opt/myuna/active-temporal/releases/" + "f" * 64,
            "state_prestate": "absent",
            "files_prestate": {
                "/etc/p08/selector": {"state": "absent"},
                "/etc/p08/unit": {"state": "absent"},
            },
        }


class Generation13CombinedActivationTests(unittest.TestCase):
    def test_plan_binds_all_three_phases_and_accepts_continuity_reset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "telegram.json"
            config.write_text(
                json.dumps(
                    {
                        "schema": "myuna.telegram.r5-boot-resume-config.v1",
                        "gateway_release": "0" * 64,
                    }
                ),
                "ascii",
            )
            fake_p07 = FakeP07Prepared()
            with patch.object(activation, "TELEGRAM_CONFIG", config), patch.object(
                activation,
                "prepare_p07_activation",
                return_value=fake_p07,
            ), patch.object(
                activation,
                "activate_p07_component",
                return_value={
                    "status": "ready",
                    "release_set_id": FakeP07ReleaseSet.release_set_id,
                },
            ), patch.object(
                activation,
                "_plugin_evidence",
                return_value={
                    "candidate_path": "/candidate/plugin",
                    "main_sha256": "1" * 64,
                    "plugin_path": "/candidate/plugin/package",
                    "protocol_sha256": "2" * 64,
                    "release_digest": "3" * 64,
                },
            ), patch.object(
                activation.p08_activation,
                "prepare_plan",
                return_value=FakeP08Plan(),
            ), patch.object(
                activation,
                "_units_digest",
                return_value="4" * 64,
            ):
                prepared = activation.prepare_combined_activation(
                    core_candidate=Path("/candidate/core"),
                    runtime_candidate=Path("/candidate/runtime"),
                    p08_release=Path("/candidate/p08"),
                    plugin_release=Path("/candidate/plugin"),
                    core_commit="1" * 40,
                    deploy_commit="2" * 40,
                    expected_core_release="7" * 64,
                    expected_runtime_release="a" * 64,
                    expected_definition_release="v6-r3",
                    expected_previous_epoch_sha256="5" * 64,
                    expected_previous_release_set_id="6" * 64,
                    expected_revision=7,
                    expected_turns=7,
                    expected_summaries=0,
                    expected_pending=0,
                )
        self.assertEqual(
            prepared.plan_payload["boundaries"]["continuity"],
            "external-context-reset-accepted",
        )
        self.assertEqual(prepared.combined_release_set.p07["generation"], 13)
        self.assertEqual(prepared.combined_release_set.rollback["previous_generation"], 11)
        self.assertEqual(
            prepared.combined_release_set.rollback["reverse_order"],
            ("p08", "telegram_plugin", "p07"),
        )
        self.assertIsNotNone(fake_p07.target_telegram_config_digest)

    def test_p08_contract_digest_excludes_only_staging_paths(self) -> None:
        first = FakeP08Plan().as_payload()
        second = dict(first)
        second["gateway_runtime"] = "/other/runtime"
        second["plugin"] = "/other/plugin"
        second["release_source"] = "/other/p08"
        second["plan_digest"] = "9" * 64
        self.assertEqual(
            activation._p08_activation_contract_digest(first),
            activation._p08_activation_contract_digest(second),
        )
        second["release_digest"] = "8" * 64
        self.assertNotEqual(
            activation._p08_activation_contract_digest(first),
            activation._p08_activation_contract_digest(second),
        )

    def test_plugin_config_is_deterministic_and_changes_only_release_binding(self) -> None:
        first = activation._plugin_config("a" * 64)
        second = activation._plugin_config("a" * 64)
        self.assertEqual(first, second)
        payload = json.loads(first)
        self.assertEqual(payload["gateway_release"], "a" * 64)
        self.assertIn("/" + "a" * 64 + "/", payload["plugin_root"])

    def test_attempt_ledger_is_combined_scoped_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(activation, "STATE_ROOT", root), patch.object(
                activation, "ATTEMPT_LEDGER", root / "ATTEMPT_LEDGER.json"
            ):
                self.assertEqual(activation._consume_attempt("a" * 64), 1)
                self.assertEqual(activation._consume_attempt("b" * 64), 2)
                with self.assertRaisesRegex(
                    activation.CombinedActivationRejected,
                    "live_attempt_budget_exhausted",
                ):
                    activation._consume_attempt("c" * 64)

    def test_source_has_no_channel_model_provider_or_secret_clients(self) -> None:
        source = Path(activation.__file__).read_text("utf-8")
        ast.parse(source)
        for forbidden in ("requests", "httpx", "deepseek", "telegram.send"):
            self.assertNotIn(forbidden, source.lower())
        self.assertIn("plugin.parent.as_posix()", source)
        self.assertIn("p08_activation.ActivationRejected", source)
        self.assertIn("CombinedReleaseSetTransaction", source)
        self.assertIn("rollback_p08", source)
        self.assertIn("rollback_telegram_plugin", source)
        self.assertIn("rollback_p07", source)

    def test_adr_freezes_continuity_reset_and_reverse_rollback(self) -> None:
        text = (
            Path(__file__).parents[1]
            / "docs/ADR-065-p08-p07-generation13-successor-atomic-release-set-v1.md"
        ).read_text("utf-8")
        self.assertIn("external-context continuity resets", text)
        self.assertIn("P08, plugin,", text)
        self.assertIn("Effective V6 remains selected", text)
        self.assertIn("authorizes no mainline move", text)


if __name__ == "__main__":
    unittest.main()
