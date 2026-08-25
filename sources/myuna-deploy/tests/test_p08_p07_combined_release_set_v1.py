from __future__ import annotations

import json
import unittest

from p08_p07_combined_release_set_v1 import (
    CombinedReleaseSet,
    CombinedReleaseSetRejected,
    EPOCH_ID,
    EPOCH_PATH,
)


def fields() -> dict[str, object]:
    return {
        "p07": {
            "core_release_digest": "1" * 64,
            "credential_projection_digest": "2" * 64,
            "epoch_id": EPOCH_ID,
            "epoch_path": EPOCH_PATH,
            "generation": 12,
            "release_set_id": "3" * 64,
            "runtime_config_digest": "4" * 64,
            "runtime_release_digest": "5" * 64,
            "selector_digest": "6" * 64,
        },
        "telegram_plugin": {
            "main_sha256": "7" * 64,
            "protocol_sha256": "8" * 64,
            "release_digest": "9" * 64,
            "selected_config_path": "/etc/myuna-telegram-gateway/r5-resume-v1.json",
            "selected_config_prestate_digest": "a" * 64,
            "selected_config_target_digest": "b" * 64,
        },
        "p08": {
            "activation_contract_digest": "c" * 64,
            "release_digest": "d" * 64,
            "selector_path": "/etc/myuna-active-temporal-context-v1/selector.json",
            "selector_schema": "myuna.p08-active-temporal-selector.v1",
            "service": "myuna-active-temporal-context-v1.service",
            "socket": "myuna-active-temporal-context-v1.socket",
            "units_digest": "e" * 64,
        },
        "rollback": {
            "combined_prestate_digest": "f" * 64,
            "desired_service_states_digest": "0" * 64,
            "p08_prestate": "absent",
            "previous_core_release_digest": "1" * 64,
            "previous_epoch_bundle_digest": "2" * 64,
            "previous_epoch_permissions_digest": "3" * 64,
            "previous_generation": 11,
            "previous_plugin_config_digest": "4" * 64,
            "previous_plugin_release_digest": "5" * 64,
            "previous_release_set_digest": "6" * 64,
            "previous_release_set_id": "7" * 64,
            "previous_runtime_release_digest": "8" * 64,
            "previous_selector_digest": "9" * 64,
            "reverse_order": ["p08", "telegram_plugin", "p07"],
        },
    }


class CombinedReleaseSetTests(unittest.TestCase):
    def test_round_trip_and_digest_are_deterministic(self) -> None:
        first = CombinedReleaseSet.create(**fields())
        second = CombinedReleaseSet.create(**fields())
        self.assertEqual(first, second)
        self.assertEqual(len(first.release_set_id), 64)
        self.assertEqual(CombinedReleaseSet.from_payload(first.as_payload()), first)
        self.assertEqual(json.loads(json.dumps(first.as_payload())), first.as_payload())

    def test_release_set_binds_fresh_epoch_plugin_p08_and_exact_rollback(self) -> None:
        release = CombinedReleaseSet.create(**fields())
        self.assertEqual(release.p07["generation"], 12)
        self.assertEqual(release.p07["epoch_id"], EPOCH_ID)
        self.assertEqual(release.rollback["previous_generation"], 11)
        self.assertEqual(release.rollback["p08_prestate"], "absent")
        self.assertEqual(
            release.rollback["reverse_order"],
            ("p08", "telegram_plugin", "p07"),
        )

    def test_release_set_is_deeply_immutable(self) -> None:
        release = CombinedReleaseSet.create(**fields())
        with self.assertRaises(TypeError):
            release.p07["generation"] = 13  # type: ignore[index]
        with self.assertRaises(TypeError):
            release.rollback["previous_generation"] = 4  # type: ignore[index]

    def test_unknown_fields_wrong_order_or_failed_epoch_reuse_fail_closed(self) -> None:
        cases = []
        unknown = fields()
        unknown["p07"] = {**unknown["p07"], "unknown": "x"}
        cases.append(unknown)
        wrong_order = fields()
        wrong_order["rollback"] = {
            **wrong_order["rollback"],
            "reverse_order": ["p07", "telegram_plugin", "p08"],
        }
        cases.append(wrong_order)
        reused = fields()
        reused["p07"] = {
            **reused["p07"],
            "epoch_id": "telegram-owner-private-external-d-reset-v5",
        }
        cases.append(reused)
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(CombinedReleaseSetRejected):
                    CombinedReleaseSet.create(**case)


if __name__ == "__main__":
    unittest.main()
