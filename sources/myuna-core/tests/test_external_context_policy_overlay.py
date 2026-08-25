from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import json
import os
import tempfile
import unittest

from myuna_core.external_context.contracts import (
    EXTERNAL_PROJECTION_POLICY,
    EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY,
)
from myuna_core.external_context.policy_overlay import (
    POLICY_OVERLAY_MAX_INPUT_CHARACTERS,
    POLICY_OVERLAY_MAX_PROJECTION_CHARACTERS,
    POLICY_OVERLAY_MAX_SERIALIZED_BYTES,
    PolicyOverlay,
    PolicyOverlayMarker,
    PolicyOverlayRejected,
    PolicyOverlaySelector,
    PolicyOverlayState,
    ZERO_DIGEST,
    canonical_document,
    load_selected_policy_overlay,
    projection_policy_contract,
    require_overlay_component_set,
    require_policy_overlay_transition,
)
from myuna_core.external_context.release_set import P07DReleaseSet
from tests.test_external_context_release_set import sample_fields


CORE = "c" * 64
RUNTIME = "d" * 64
PLUGIN = "e" * 64
PLUGIN_CONFIG = "f" * 64
PARENT_FILE = "a" * 64
CORE_COMMIT = "1" * 40
DEPLOY_COMMIT = "2" * 40


def parent() -> P07DReleaseSet:
    return P07DReleaseSet.create(**sample_fields())


def overlay(parent_release_set: P07DReleaseSet | None = None) -> PolicyOverlay:
    return PolicyOverlay.create(
        parent_release_set=parent_release_set or parent(),
        parent_manifest_file_digest=PARENT_FILE,
        core_release_digest=CORE,
        runtime_release_digest=RUNTIME,
        plugin_release_digest=PLUGIN,
        plugin_config_digest=PLUGIN_CONFIG,
        core_commit=CORE_COMMIT,
        deploy_commit=DEPLOY_COMMIT,
    )


class OverlayFiles:
    def __init__(self, root: Path, selected: PolicyOverlay) -> None:
        self.manifest = root / "manifest.json"
        self.selector = root / "selector.json"
        self.marker = root / "marker.json"
        self.state = root / "state.json"
        self.selected = selected
        self.active_state = PolicyOverlayState.create(
            sequence=1,
            status="active",
            overlay_id=selected.overlay_id,
            previous_state_digest=ZERO_DIGEST,
        )
        self.selected_selector = PolicyOverlaySelector.create(
            selected, self.active_state
        )
        self.selected_marker = PolicyOverlayMarker.create(
            self.selected_selector, self.active_state
        )

    def write(self) -> None:
        for path, payload in (
            (self.manifest, self.selected.as_payload()),
            (self.selector, self.selected_selector.as_payload()),
            (self.marker, self.selected_marker.as_payload()),
            (self.state, self.active_state.as_payload()),
        ):
            path.write_bytes(canonical_document(payload))
            path.chmod(0o640)

    def load(
        self,
        *,
        parent_release_set: P07DReleaseSet | None = None,
        component_kind: str = "core",
        current_component_release_digest: str = CORE,
    ) -> PolicyOverlay | None:
        return load_selected_policy_overlay(
            parent_release_set=parent_release_set or parent(),
            parent_manifest_file_digest=PARENT_FILE,
            component_kind=component_kind,
            current_component_release_digest=current_component_release_digest,
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
            manifest_path=self.manifest,
            selector_path=self.selector,
            marker_path=self.marker,
            state_path=self.state,
        )


class PolicyOverlayTests(unittest.TestCase):
    def test_absence_is_exact_compressed_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            files = OverlayFiles(Path(directory), overlay())
            self.assertIsNone(files.load())
        contract = projection_policy_contract()
        self.assertEqual(
            contract["compressed_fallback_policy"], EXTERNAL_PROJECTION_POLICY
        )
        self.assertEqual(
            contract["policy_version"],
            EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY,
        )
        self.assertEqual(POLICY_OVERLAY_MAX_INPUT_CHARACTERS, 200_000)
        self.assertEqual(POLICY_OVERLAY_MAX_PROJECTION_CHARACTERS, 199_000)
        self.assertEqual(POLICY_OVERLAY_MAX_SERIALIZED_BYTES, 1_198_096)

    def test_exact_active_snapshot_round_trips_for_core_and_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            files = OverlayFiles(Path(directory), overlay())
            files.write()
            selected = files.load()
            self.assertEqual(selected, files.selected)
            runtime = files.load(
                component_kind="runtime",
                current_component_release_digest=RUNTIME,
            )
            self.assertEqual(runtime, files.selected)
            require_overlay_component_set(
                files.selected,
                core_release_digest=CORE,
                runtime_release_digest=RUNTIME,
                plugin_release_digest=PLUGIN,
                plugin_config_digest=PLUGIN_CONFIG,
            )

    def test_partial_or_mixed_snapshot_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            files = OverlayFiles(Path(directory), overlay())
            files.write()
            files.marker.unlink()
            with self.assertRaisesRegex(
                PolicyOverlayRejected, "policy_overlay_partial_state_rejected"
            ):
                files.load()

        with tempfile.TemporaryDirectory() as directory:
            files = OverlayFiles(Path(directory), overlay())
            files.write()
            payload = json.loads(files.marker.read_text("ascii"))
            payload["selector_id"] = "9" * 64
            files.marker.write_bytes(canonical_document(payload))
            files.marker.chmod(0o640)
            with self.assertRaises(PolicyOverlayRejected):
                files.load()

    def test_wrong_parent_epoch_component_and_complete_set_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            files = OverlayFiles(Path(directory), overlay())
            files.write()
            mismatched_fields = sample_fields()
            mismatched_fields["selector"]["digest"] = "9" * 64
            with self.assertRaisesRegex(
                PolicyOverlayRejected, "policy_overlay_parent_mismatch"
            ):
                files.load(
                    parent_release_set=P07DReleaseSet.create(**mismatched_fields)
                )
            with self.assertRaisesRegex(
                PolicyOverlayRejected,
                "policy_overlay_component_identity_mismatch",
            ):
                files.load(current_component_release_digest="9" * 64)
            with self.assertRaisesRegex(
                PolicyOverlayRejected, "policy_overlay_component_set_mismatch"
            ):
                require_overlay_component_set(
                    files.selected,
                    core_release_digest=CORE,
                    runtime_release_digest=RUNTIME,
                    plugin_release_digest="9" * 64,
                    plugin_config_digest=PLUGIN_CONFIG,
                )

    def test_unknown_schema_duplicate_field_and_mode_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            files = OverlayFiles(Path(directory), overlay())
            files.write()
            payload = json.loads(files.manifest.read_text("ascii"))
            payload["schema"] = "myuna.p07-policy-overlay.future"
            files.manifest.write_bytes(canonical_document(payload))
            files.manifest.chmod(0o640)
            with self.assertRaises(PolicyOverlayRejected):
                files.load()

        with tempfile.TemporaryDirectory() as directory:
            files = OverlayFiles(Path(directory), overlay())
            files.write()
            raw = files.state.read_text("ascii").rstrip()
            files.state.write_text(raw[:-1] + ',"sequence":1}\n', "ascii")
            files.state.chmod(0o640)
            with self.assertRaisesRegex(
                PolicyOverlayRejected, "policy_overlay_duplicate_field"
            ):
                files.load()

        with tempfile.TemporaryDirectory() as directory:
            files = OverlayFiles(Path(directory), overlay())
            files.write()
            files.selector.chmod(0o600)
            with self.assertRaisesRegex(
                PolicyOverlayRejected, "policy_overlay_file_metadata_rejected"
            ):
                files.load()

    def test_transition_chain_rejects_replay_and_unauthorized_jump(self) -> None:
        selected = overlay()
        active = PolicyOverlayState.create(
            sequence=1,
            status="active",
            overlay_id=selected.overlay_id,
            previous_state_digest=ZERO_DIGEST,
        )
        require_policy_overlay_transition(None, active)
        compressed = PolicyOverlayState.create(
            sequence=2,
            status="compressed",
            overlay_id=None,
            previous_state_digest=active.state_digest,
        )
        require_policy_overlay_transition(active, compressed)
        with self.assertRaisesRegex(
            PolicyOverlayRejected, "policy_overlay_transition_rejected"
        ):
            require_policy_overlay_transition(compressed, active)

        with tempfile.TemporaryDirectory() as directory:
            files = OverlayFiles(Path(directory), selected)
            files.state.write_bytes(canonical_document(compressed.as_payload()))
            files.state.chmod(0o640)
            self.assertIsNone(files.load())
            files.write()
            files.state.write_bytes(canonical_document(compressed.as_payload()))
            files.state.chmod(0o640)
            with self.assertRaises(PolicyOverlayRejected):
                files.load()

    def test_overlay_parser_does_not_touch_epoch_or_history_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            immutable = root / "epoch.db.synthetic"
            immutable.write_bytes(b"synthetic epoch bytes remain exact")
            before = immutable.read_bytes()
            files = OverlayFiles(root, overlay())
            files.write()
            self.assertIsNotNone(files.load())
            self.assertEqual(immutable.read_bytes(), before)

    def test_digest_bound_fields_cannot_be_changed_coherently_by_parser(self) -> None:
        selected = overlay()
        payload = deepcopy(selected.as_payload())
        payload["policy"]["max_complete_turns"] = 63
        with self.assertRaisesRegex(
            PolicyOverlayRejected, "policy_overlay_policy_rejected"
        ):
            PolicyOverlay.from_payload(payload)
        payload = deepcopy(selected.as_payload())
        payload["components"]["plugin_release_digest"] = "9" * 64
        with self.assertRaisesRegex(
            PolicyOverlayRejected, "policy_overlay_digest_mismatch"
        ):
            PolicyOverlay.from_payload(payload)


if __name__ == "__main__":
    unittest.main()
