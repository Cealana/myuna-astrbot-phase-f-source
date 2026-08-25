from __future__ import annotations

from copy import deepcopy
import unittest

from myuna_core.external_context.contracts import (
    EXTERNAL_PROJECTION_POLICY,
    EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY,
)

from myuna_core.external_context.release_set import (
    P07DReleaseSet,
    RELEASE_SET_EPOCH_ID,
    RELEASE_SET_EPOCH_ID_7,
    RELEASE_SET_EPOCH_ID_11,
    RELEASE_SET_EPOCH_ID_12,
    RELEASE_SET_EPOCH_PATH,
    RELEASE_SET_EPOCH_PATH_7,
    RELEASE_SET_EPOCH_PATH_11,
    RELEASE_SET_EPOCH_PATH_12,
    RELEASE_SET_GENERATION,
    RELEASE_SET_GENERATION_11,
    RELEASE_SET_GENERATION_12,
    RELEASE_SET_GENERATION_13,
    ReleaseSetRejected,
)


D = "a" * 64


def sample_fields() -> dict[str, object]:
    return {
        "core": {
            "entrypoint": "/srv/myuna/releases/core/" + D + "/src/myuna_core/server.py",
            "file_count": 300,
            "inventory_digest": "1" * 64,
            "release_digest": "2" * 64,
            "tree_digest": "3" * 64,
        },
        "telegram_runtime": {
            "entrypoint": "/srv/myuna/releases/telegram-owner-runtime/" + D + "/runtime/telegram_owner_runtime_gateway.py",
            "file_count": 42,
            "inventory_digest": "4" * 64,
            "release_digest": "5" * 64,
        },
        "selector": {
            "digest": "6" * 64,
            "generation": RELEASE_SET_GENERATION,
            "path": "/etc/myuna-telegram-gateway/external-epoch-selector-v2.json",
            "schema": "myuna.external-epoch-selector.v2",
        },
        "runtime_config": {
            "binding_digest": "7" * 64,
            "channel_kind": "astrbot_telegram",
            "digest": "8" * 64,
            "gid": 982,
            "mode": 0o640,
            "namespace_id": "telegram-owner-private",
            "path": "/etc/myuna-telegram-gateway/runtime-config-v1.json",
            "principal_id": "owner-synthetic",
            "uid": 0,
        },
        "credential": {
            "dropin_set_digest": "9" * 64,
            "effective_count": 1,
            "effective_source": "/etc/myuna/secrets/deepseek-api-key",
            "name": "deepseek_api_key",
            "projection_digest": "b" * 64,
            "source_category": "systemd_load_credential",
        },
        "epoch": {
            "database_path": RELEASE_SET_EPOCH_PATH,
            "directory_mode": 0o700,
            "epoch_id": RELEASE_SET_EPOCH_ID,
            "file_mode": 0o600,
            "gid": 982,
            "schema": "myuna.external-authorized-epoch.v3",
            "schema_version": 3,
            "uid": 988,
        },
        "services": [
            {
                "binding_digest": "2" * 64,
                "desired_state": "active",
                "gid": 982,
                "kind": "core",
                "stable_observation_seconds": 15,
                "uid": 988,
                "unit": "myuna-core@qq.service",
            },
            {
                "binding_digest": "3" * 64,
                "desired_state": "active",
                "gid": 982,
                "kind": "telegram",
                "stable_observation_seconds": 15,
                "uid": 988,
                "unit": "myuna-telegram-owner-runtime-dev.service",
            },
            {
                "binding_digest": "4" * 64,
                "desired_state": "active",
                "gid": 982,
                "kind": "telegram_socket",
                "stable_observation_seconds": 5,
                "uid": 988,
                "unit": "myuna-telegram-owner-runtime-dev.socket",
            },
        ],
        "rollback": {
            "core_release_digest": "c" * 64,
            "desired_service_states_digest": "d" * 64,
            "epoch_bundle_digest": "e" * 64,
            "manifest_digest": "f" * 64,
            "runtime_release_digest": "0" * 64,
            "selector_digest": "1" * 64,
        },
    }


class ReleaseSetTests(unittest.TestCase):
    def test_current_generation_uses_new_isolated_successor_epoch(self) -> None:
        self.assertEqual(RELEASE_SET_GENERATION, RELEASE_SET_GENERATION_13)
        fields = sample_fields()
        self.assertIn("external-d-reset-v7", fields["epoch"]["database_path"])
        self.assertNotIn("external-d-reset-v6/", fields["epoch"]["database_path"])

    def test_generation_twelve_manifest_remains_strictly_parseable(self) -> None:
        fields = sample_fields()
        fields["selector"]["generation"] = RELEASE_SET_GENERATION_12
        fields["epoch"]["epoch_id"] = RELEASE_SET_EPOCH_ID_12
        fields["epoch"]["database_path"] = RELEASE_SET_EPOCH_PATH_12
        selected = P07DReleaseSet.create(**fields, generation=RELEASE_SET_GENERATION_12)
        self.assertEqual(P07DReleaseSet.from_payload(selected.as_payload()), selected)
        self.assertNotEqual(selected.epoch["database_path"], RELEASE_SET_EPOCH_PATH)

    def test_generation_eleven_manifest_remains_strictly_parseable(self) -> None:
        fields = sample_fields()
        fields["selector"]["generation"] = RELEASE_SET_GENERATION_11
        fields["epoch"]["epoch_id"] = RELEASE_SET_EPOCH_ID_11
        fields["epoch"]["database_path"] = RELEASE_SET_EPOCH_PATH_11
        selected = P07DReleaseSet.create(**fields, generation=RELEASE_SET_GENERATION_11)
        self.assertEqual(P07DReleaseSet.from_payload(selected.as_payload()), selected)
        self.assertNotEqual(selected.epoch["database_path"], RELEASE_SET_EPOCH_PATH)

    def test_round_trip_and_digest_are_deterministic(self) -> None:
        first = P07DReleaseSet.create(**sample_fields())
        second = P07DReleaseSet.create(**deepcopy(sample_fields()))
        self.assertEqual(first.release_set_id, second.release_set_id)
        self.assertEqual(P07DReleaseSet.from_payload(first.as_payload()), first)
        self.assertRegex(first.epoch_identity_digest, r"^[0-9a-f]{64}$")
        self.assertEqual(
            first.projection_policy_version,
            EXTERNAL_PROJECTION_POLICY,
        )

    def test_projection_policy_is_optional_for_rollback_and_digest_bound_when_set(self) -> None:
        legacy = P07DReleaseSet.create(**sample_fields())
        fields = sample_fields()
        fields["epoch"]["projection_policy_version"] = (
            EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY
        )
        verbatim = P07DReleaseSet.create(**fields)

        self.assertEqual(
            legacy.projection_policy_version,
            EXTERNAL_PROJECTION_POLICY,
        )
        self.assertEqual(
            verbatim.projection_policy_version,
            EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY,
        )
        self.assertNotEqual(legacy.release_set_id, verbatim.release_set_id)
        self.assertEqual(P07DReleaseSet.from_payload(verbatim.as_payload()), verbatim)

        invalid = sample_fields()
        invalid["epoch"]["projection_policy_version"] = "future-policy"
        with self.assertRaisesRegex(ReleaseSetRejected, "release_set_epoch_rejected"):
            P07DReleaseSet.create(**invalid)

    def test_release_set_is_deeply_immutable_and_missing_fields_are_typed(self) -> None:
        fields = sample_fields()
        release_set = P07DReleaseSet.create(**fields)
        fields["core"]["release_digest"] = "f" * 64
        self.assertEqual(release_set.core["release_digest"], "2" * 64)
        with self.assertRaises(TypeError):
            release_set.core["release_digest"] = "f" * 64
        incomplete = sample_fields()
        incomplete.pop("rollback")
        with self.assertRaisesRegex(ReleaseSetRejected, "release_set_fields_rejected"):
            P07DReleaseSet.create(**incomplete)

    def test_mixed_artifact_or_digest_drift_is_rejected(self) -> None:
        release_set = P07DReleaseSet.create(**sample_fields())
        payload = release_set.as_payload()
        payload["core"]["release_digest"] = "f" * 64
        with self.assertRaisesRegex(ReleaseSetRejected, "release_set_digest_mismatch"):
            P07DReleaseSet.from_payload(payload)

    def test_generation_and_failed_epoch_reuse_are_rejected(self) -> None:
        fields = sample_fields()
        fields["selector"]["generation"] = 6
        with self.assertRaisesRegex(ReleaseSetRejected, "release_set_selector_rejected"):
            P07DReleaseSet.create(**fields)
        fields = sample_fields()
        fields["epoch"]["epoch_id"] = "telegram-owner-private-external-d-v2"
        with self.assertRaisesRegex(ReleaseSetRejected, "release_set_epoch_rejected"):
            P07DReleaseSet.create(**fields)

    def test_generation_seven_manifest_remains_strictly_parseable(self) -> None:
        fields = sample_fields()
        fields["selector"]["generation"] = 7
        fields["epoch"]["epoch_id"] = RELEASE_SET_EPOCH_ID_7
        fields["epoch"]["database_path"] = RELEASE_SET_EPOCH_PATH_7
        selected = P07DReleaseSet.create(**fields, generation=7)
        self.assertEqual(P07DReleaseSet.from_payload(selected.as_payload()), selected)
        self.assertNotEqual(selected.epoch["database_path"], RELEASE_SET_EPOCH_PATH)

    def test_runtime_config_and_credential_contract_are_exact(self) -> None:
        fields = sample_fields()
        fields["runtime_config"]["mode"] = 0o644
        with self.assertRaisesRegex(ReleaseSetRejected, "release_set_runtime_config_rejected"):
            P07DReleaseSet.create(**fields)
        fields = sample_fields()
        fields["credential"]["effective_count"] = 2
        with self.assertRaisesRegex(ReleaseSetRejected, "release_set_credential_rejected"):
            P07DReleaseSet.create(**fields)

    def test_service_identity_duplicates_and_unknown_fields_fail_closed(self) -> None:
        fields = sample_fields()
        fields["services"][1]["unit"] = fields["services"][0]["unit"]
        with self.assertRaisesRegex(ReleaseSetRejected, "release_set_services_rejected"):
            P07DReleaseSet.create(**fields)
        payload = P07DReleaseSet.create(**sample_fields()).as_payload()
        payload["unexpected"] = True
        with self.assertRaisesRegex(ReleaseSetRejected, "release_set_fields_rejected"):
            P07DReleaseSet.from_payload(payload)


if __name__ == "__main__":
    unittest.main()
