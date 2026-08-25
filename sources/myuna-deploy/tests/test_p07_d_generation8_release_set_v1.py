from __future__ import annotations

import os
import unittest

from telegram_owner_runtime_gateway import ExternalEpochSelection
from myuna_core.external_context.release_set import P07DReleaseSet, RELEASE_SET_EPOCH_PATH_8
from p07_d_generation8_release_set import (
    B_V4_EPOCH_ID,
    build_release_set,
    rollback_manifest_digest,
    selector_payload,
    service_binding_digest,
)


class Generation8ReleaseSetTests(unittest.TestCase):
    def test_selector_closes_generation_four_to_isolated_generation_eight(self) -> None:
        payload = selector_payload("a" * 64)
        self.assertEqual(payload["generation"], 8)
        self.assertEqual(payload["previous_epoch_id"], B_V4_EPOCH_ID)
        self.assertEqual(payload["database_path"], RELEASE_SET_EPOCH_PATH_8)
        self.assertIn("external-d-reset-v2", payload["database_path"])
        self.assertNotIn("external-d-reset-v1/", payload["database_path"])
        selection = ExternalEpochSelection.from_payload(payload)
        self.assertEqual(selection.generation, 8)
        self.assertEqual(selection.database_path.as_posix(), RELEASE_SET_EPOCH_PATH_8)

    def test_service_binding_includes_shared_acl_projection(self) -> None:
        common = {
            "kind": "core",
            "unit": "core.service",
            "uid": 999,
            "gid": 989,
            "binding_files": {"/etc/myuna/core.conf": "1" * 64},
        }
        first = service_binding_digest(**common, release_set_acl_digest="2" * 64)
        second = service_binding_digest(**common, release_set_acl_digest="3" * 64)
        self.assertNotEqual(first, second)

    def test_manifest_round_trip_binds_epoch_and_rollback(self) -> None:
        selector = selector_payload("a" * 64)
        selected = build_release_set(
            core={
                "entrypoint": "/release/core/src/myuna_core/__main__.py",
                "file_count": 3,
                "inventory_digest": "1" * 64,
                "release_digest": "2" * 64,
                "tree_digest": "3" * 64,
            },
            telegram_runtime={
                "entrypoint": "/release/runtime/telegram_owner_runtime_gateway.py",
                "file_count": 4,
                "inventory_digest": "4" * 64,
                "release_digest": "5" * 64,
            },
            selector={
                "digest": "6" * 64,
                "generation": 8,
                "path": "/etc/myuna/selector.json",
                "schema": selector["schema"],
            },
            runtime_config={
                "binding_digest": "7" * 64,
                "channel_kind": "astrbot_telegram",
                "digest": "8" * 64,
                "gid": os.getgid(),
                "mode": 0o640,
                "namespace_id": "namespace-synthetic",
                "path": "/etc/myuna/runtime.json",
                "principal_id": "principal-synthetic",
                "uid": os.getuid(),
            },
            credential={
                "dropin_set_digest": "9" * 64,
                "effective_count": 1,
                "effective_source": "/etc/myuna/secret",
                "name": "deepseek_api_key",
                "projection_digest": "b" * 64,
                "source_category": "systemd_load_credential",
            },
            epoch_uid=os.getuid(),
            epoch_gid=os.getgid(),
            services=(
                {"binding_digest": "c" * 64, "desired_state": "active", "gid": os.getgid(), "kind": "core", "stable_observation_seconds": 5, "uid": os.getuid(), "unit": "core.service"},
                {"binding_digest": "d" * 64, "desired_state": "active", "gid": os.getgid(), "kind": "telegram", "stable_observation_seconds": 5, "uid": os.getuid(), "unit": "telegram.service"},
                {"binding_digest": "e" * 64, "desired_state": "active", "gid": os.getgid(), "kind": "telegram_socket", "stable_observation_seconds": 5, "uid": os.getuid(), "unit": "telegram.socket"},
            ),
            rollback={
                "core_release_digest": "f" * 64,
                "desired_service_states_digest": "0" * 64,
                "epoch_bundle_digest": "a" * 64,
                "manifest_digest": rollback_manifest_digest({"synthetic": True}),
                "runtime_release_digest": "1" * 64,
                "selector_digest": "2" * 64,
            },
        )
        self.assertEqual(P07DReleaseSet.from_payload(selected.as_payload()), selected)
        self.assertEqual(selected.generation, 8)
        self.assertEqual(selected.epoch["schema_version"], 3)


if __name__ == "__main__":
    unittest.main()
