from __future__ import annotations

import ast
from contextlib import nullcontext, redirect_stdout
from hashlib import sha256
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, (ROOT / "scripts").as_posix())
MODULE_PATH = ROOT / "scripts/phase_f_owner_adjudicated_one_time_cutover_v1.py"
SPEC = importlib.util.spec_from_file_location(
    "phase_f_owner_adjudicated_one_time_cutover_v1", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def synthetic_state(seed: int = 11) -> module.Preflight:
    members = tuple(
        module.CheckpointMember(
            path=Path(f"/synthetic/file-{index}"),
            payload=f"old:{seed}:{index}\n".encode("ascii"),
            mode=0o640 if index < 3 else 0o644,
            uid=0,
            gid=index,
            role=f"role-{index}",
        )
        for index in range(7)
    )
    target = module.boot.PhaseFContainerProjection(**module._TARGET_CONTAINER)
    archive = module.boot.PhaseFContainerProjection(**module._ARCHIVE_CONTAINER)
    network = module.boot.PhaseFNetworkProjection(**module._NETWORK)
    return module.Preflight(
        release_root=Path("/synthetic/releases") / (f"{seed:064x}"[-64:]),
        new_unit=f"new-unit:{seed}\n".encode("ascii"),
        old_unit=f"old-unit:{seed}\n".encode("ascii"),
        authority={"seed": seed},
        checkpoint=members,
        target=target,
        archive=archive,
        network=network,
    )


class FakeEffects:
    def __init__(
        self,
        seed: int = 11,
        *,
        reject_preflight: str | None = None,
        fail_call: str | None = None,
    ) -> None:
        self.state = synthetic_state(seed)
        self.reject_preflight = reject_preflight
        self.fail_call = fail_call
        self.calls: list[str] = []

    def _call(self, name: str) -> None:
        self.calls.append(name)
        if self.fail_call == name:
            raise module.CutoverRejected(f"fault:{name}")

    def preflight(self, mode: str) -> module.Preflight:
        self._call(f"preflight:{mode}")
        if self.reject_preflight is not None:
            raise module.CutoverRejected(f"substitution:{self.reject_preflight}")
        return self.state

    def write_new_unit(self, _state: module.Preflight) -> None:
        self._call("write_new_unit")

    def daemon_reload(self) -> None:
        self._call("daemon_reload")

    def start_service(self, unit: str) -> None:
        self._call(f"start_service:{unit}")

    def start_target(self, _state: module.Preflight) -> None:
        self._call("start_target")

    def stop_service(self, unit: str) -> None:
        self._call(f"stop_service:{unit}")

    def stop_target(self, _state: module.Preflight) -> None:
        self._call("stop_target")

    def restore_member(self, member: module.CheckpointMember) -> None:
        self._call(f"restore_member:{member.role}")

    def restore_old_unit(self, _state: module.Preflight) -> None:
        self._call("restore_old_unit")

    def restore_old_container(self, _state: module.Preflight) -> None:
        self._call("restore_old_container")

    def verify_new_running(self, _state: module.Preflight) -> None:
        self._call("verify_new_running")

    def verify_old_stopped(self, _state: module.Preflight) -> None:
        self._call("verify_old_stopped")


class OwnerAdjudicatedCutoverTests(unittest.TestCase):
    @staticmethod
    def external_release(root: Path, marker: str = "a") -> tuple[Path, module.ReleaseSelection]:
        deploy_commit = marker * 40
        deploy_tree = ("b" if marker != "b" else "c") * 40
        public = {
            "deploy_commit": deploy_commit,
            "deploy_members": [],
            "deploy_tree": deploy_tree,
            "schema": "myuna.telegram.r5-controller-corresponding-source.v2",
        }
        public_payload = module._canonical(public)
        public_sha = sha256(public_payload).hexdigest()
        document = {
            "deploy_commit": deploy_commit,
            "deploy_tree": deploy_tree,
            "fixed_product_authority": {"source": {"deploy_commit": deploy_commit}},
            "paired_source_package_sha256": public_sha,
            "paired_source_receipt_sha256": public_sha,
            "source_receipt": public,
        }
        manifest = module._canonical(document)
        release_sha = sha256(manifest).hexdigest()
        release = root / release_sha
        release.mkdir()
        (release / "MANIFEST.json").write_bytes(manifest)
        (release / "CORRESPONDING_SOURCE.json").write_bytes(public_payload)
        os.chmod(release / "MANIFEST.json", 0o444)
        os.chmod(release / "CORRESPONDING_SOURCE.json", 0o444)
        return release, module.ReleaseSelection(
            deploy_commit=deploy_commit,
            deploy_tree=deploy_tree,
            public_package_sha256=public_sha,
            release_sha256=release_sha,
        )

    def test_external_selection_rejects_consistent_sibling_before_packaged_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            release, reviewed = self.external_release(root, "a")
            document = module._external_release_document(release, reviewed)
            self.assertEqual(document["deploy_commit"], reviewed.deploy_commit)

            sibling, sibling_selection = self.external_release(root, "b")
            self.assertNotEqual(sibling_selection.deploy_commit, reviewed.deploy_commit)
            with self.assertRaisesRegex(module.CutoverRejected, "release_selection_rejected"):
                module._external_release_document(sibling, reviewed)

            substituted = module.ReleaseSelection(
                deploy_commit=reviewed.deploy_commit,
                deploy_tree=reviewed.deploy_tree,
                public_package_sha256=sibling_selection.public_package_sha256,
                release_sha256=reviewed.release_sha256,
            )
            with self.assertRaisesRegex(module.CutoverRejected, "public_package_rejected"):
                module._external_release_document(release, substituted)

    def test_cli_preserves_typed_manual_required_without_raw_exception(self) -> None:
        selection = [
            "--reviewed-deploy-commit", "a" * 40,
            "--reviewed-deploy-tree", "b" * 40,
            "--public-package-sha256", "c" * 64,
            "--release-sha256", "d" * 64,
        ]
        for mode, kind in (
            ("cutover", "cutover_manual_required"),
            ("rollback", "rollback_manual_required"),
        ):
            with self.subTest(mode=mode):
                output = io.StringIO()
                error = module.ManualRequired(kind, "restore:old_container", "lost_return")
                with (
                    mock.patch.object(sys, "argv", [MODULE_PATH.as_posix(), mode, *selection]),
                    mock.patch.object(module.os, "geteuid", return_value=0),
                    mock.patch.object(module, "releases_lock", return_value=nullcontext()),
                    mock.patch.object(module, "HostEffects"),
                    mock.patch.object(module, "execute", side_effect=error),
                    redirect_stdout(output),
                ):
                    self.assertEqual(module.main(), 1)
                result = json.loads(output.getvalue())
                self.assertEqual(result["status"], kind)
                self.assertEqual(result["boundary"], "restore:old_container")
                self.assertNotIn("code", result)
                self.assertNotIn("lost_return", output.getvalue())
                self.assertNotIn("ManualRequired", output.getvalue())

    def test_host_effects_explicit_rollback_admits_remove_before_rename_partial(self) -> None:
        synthetic = synthetic_state()
        old_sha = sha256(synthetic.old_unit).hexdigest()
        files = {}
        observed = {}
        for member in synthetic.checkpoint:
            payload = b"new:" + member.payload
            files[member.path.as_posix()] = {
                "gid": member.gid,
                "mode": f"{member.mode:04o}",
                "payload_b64": module.base64.b64encode(payload).decode("ascii"),
                "payload_sha256": sha256(payload).hexdigest(),
                "role": member.role,
                "uid": member.uid,
            }
            observed[member.path] = {
                "gid": member.gid,
                "mode": f"{member.mode:04o}",
                "sha256": sha256(payload).hexdigest(),
                "size": len(payload),
                "uid": member.uid,
            }
        selection = module.ReleaseSelection("a" * 40, "b" * 40, "c" * 64, "d" * 64)
        effects = module.HostEffects(selection)
        projections = {
            module.boot.CONTAINER: None,
            module.ARCHIVE_NAME: synthetic.archive,
        }
        with (
            mock.patch.object(effects, "_load_release", return_value=(synthetic.release_root, {"files": files}, synthetic.new_unit, synthetic.old_unit)),
            mock.patch.object(effects, "_checkpoint", return_value=synthetic.checkpoint),
            mock.patch.object(module, "_file_projection", side_effect=lambda path: observed[path]),
            mock.patch.object(module, "_read_regular", return_value=synthetic.old_unit),
            mock.patch.object(module, "OLD_UNIT_SHA256", old_sha),
            mock.patch.object(module.boot, "phase_f_container_projection", side_effect=lambda name: projections[name]),
            mock.patch.object(module.boot, "phase_f_network_projection", return_value=synthetic.network),
            mock.patch.object(effects, "_service_state", return_value="inactive"),
        ):
            partial = effects.preflight("rollback")
            self.assertIsNone(partial.target)
            with self.assertRaisesRegex(module.CutoverRejected, "cutover_container_prestate_rejected"):
                effects.preflight("cutover")
        with (
            mock.patch.object(module.boot, "phase_f_container_projection", return_value=None),
            mock.patch.object(module.boot, "phase_f_remove_container_exact") as remove,
            mock.patch.object(module.boot, "phase_f_rename_container_exact") as rename,
        ):
            effects.restore_old_container(partial)
        remove.assert_not_called()
        rename.assert_called_once_with(
            partial.archive,
            source_name=module.ARCHIVE_NAME,
            target_name=module.boot.CONTAINER,
        )
        restored = module.boot.PhaseFContainerProjection(
            **{**module._ARCHIVE_CONTAINER, "name": module.boot.CONTAINER}
        )
        with (
            mock.patch.object(module, "_read_regular", return_value=synthetic.old_unit),
            mock.patch.object(module, "OLD_UNIT_SHA256", old_sha),
            mock.patch.object(effects, "_service_state", return_value="inactive"),
            mock.patch.object(module.boot, "phase_f_container_projection", return_value=restored),
        ):
            effects.verify_old_stopped(partial)

        with (
            mock.patch.object(effects, "preflight", return_value=partial),
            mock.patch.object(effects, "stop_service"),
            mock.patch.object(effects, "stop_target"),
            mock.patch.object(effects, "restore_member"),
            mock.patch.object(effects, "restore_old_unit"),
            mock.patch.object(effects, "daemon_reload"),
            mock.patch.object(
                effects,
                "restore_old_container",
                side_effect=module.CutoverRejected("lost_return"),
            ),
            mock.patch.object(effects, "verify_old_stopped"),
        ):
            with self.assertRaises(module.ManualRequired) as raised:
                module.execute("rollback", effects)
        self.assertEqual(raised.exception.kind, "rollback_manual_required")
        self.assertEqual(raised.exception.boundary, "restore:old_container")
        self.assertEqual(raised.exception.effect_code, "lost_return")

    def test_finite_modes_have_no_semantic_success_or_persistent_state(self) -> None:
        preflight = module.execute("preflight", FakeEffects())
        self.assertEqual(preflight["status"], "PREFLIGHT_ACCEPTED_ZERO_EFFECT")
        self.assertNotIn("semantic_success", preflight)

        cutover = module.execute("cutover", FakeEffects())
        self.assertEqual(cutover["status"], "OWNER_ADJUDICATION_REQUIRED")
        self.assertIs(cutover["semantic_success"], False)

        rollback = module.execute("rollback", FakeEffects())
        self.assertEqual(rollback["status"], "EXACT_OLD_STOPPED_ROLLBACK_CONVERGED")
        self.assertIs(rollback["semantic_success"], False)

        with self.assertRaisesRegex(module.CutoverRejected, "mode_rejected"):
            module.execute("retry", FakeEffects())

    def test_cutover_fault_matrix_stops_before_later_forward_effects(self) -> None:
        forward = (
            "write_new_unit",
            "daemon_reload",
            f"start_service:{module.CORE_SERVICE}",
            f"start_service:{module.RUNTIME_SOCKET}",
            "start_target",
            "verify_new_running",
        )
        for boundary in forward:
            with self.subTest(boundary=boundary):
                effects = FakeEffects(fail_call=boundary)
                with self.assertRaisesRegex(
                    module.CutoverRejected, "cutover_manual_required"
                ):
                    module.execute("cutover", effects)
                failed = effects.calls.index(boundary)
                for later in forward[forward.index(boundary) + 1 :]:
                    self.assertNotIn(later, effects.calls[failed + 1 :])
                self.assertNotIn("verify_new_running", effects.calls[failed + 1 :])

    def test_rollback_fault_matrix_is_typed_manual_required(self) -> None:
        effects = FakeEffects()
        module.execute("rollback", effects)
        boundaries = tuple(effects.calls[1:])
        self.assertEqual(
            [name for name in boundaries if name.startswith("restore_member:")],
            [f"restore_member:role-{index}" for index in range(7)],
        )
        for boundary in boundaries:
            with self.subTest(boundary=boundary):
                faulted = FakeEffects(fail_call=boundary)
                with self.assertRaisesRegex(
                    module.CutoverRejected, "rollback_manual_required"
                ):
                    module.execute("rollback", faulted)
                self.assertEqual(faulted.calls.count(boundary), 1)

    def test_all_substitutions_reject_before_effect(self) -> None:
        substitutions = [
            "source",
            "public_source",
            "release",
            "checkpoint",
            "selector",
            "unit",
            "config",
            "competing_owner",
            "network",
            "target_container",
            "rollback_container",
            *[f"file:{index}" for index in range(7)],
            *[f"service:{unit}" for unit in module.SERVICES],
        ]
        for name in substitutions:
            with self.subTest(name=name):
                effects = FakeEffects(reject_preflight=name)
                with self.assertRaisesRegex(module.CutoverRejected, "substitution"):
                    module.execute("cutover", effects)
                self.assertEqual(effects.calls, ["preflight:cutover"])

    def test_lost_return_and_partial_state_never_auto_advance(self) -> None:
        for prefix in (
            "unit_written",
            "daemon_reloaded",
            "core_started",
            "socket_started",
            "container_policy_changed",
            "container_started",
        ):
            with self.subTest(prefix=prefix):
                effects = FakeEffects(reject_preflight=f"partial:{prefix}")
                with self.assertRaisesRegex(module.CutoverRejected, "partial"):
                    module.execute("cutover", effects)
                self.assertEqual(effects.calls, ["preflight:cutover"])

    def test_dual_seed_action_order_and_results_are_deterministic(self) -> None:
        observations = []
        for seed in (11, 29):
            first = FakeEffects(seed)
            second = FakeEffects(seed)
            first_result = module.execute("cutover", first)
            second_result = module.execute("cutover", second)
            self.assertEqual(first_result, second_result)
            self.assertEqual(first.calls, second.calls)
            observations.append((first_result, first.calls))
        self.assertEqual(observations[0], observations[1])

    def test_exact_old_and_new_convergence_are_terminal_oracles_only(self) -> None:
        cutover = FakeEffects()
        result = module.execute("cutover", cutover)
        self.assertEqual(cutover.calls[-1], "verify_new_running")
        self.assertEqual(result["status"], "OWNER_ADJUDICATION_REQUIRED")
        self.assertNotIn("success", result["status"].lower())

        rollback = FakeEffects()
        result = module.execute("rollback", rollback)
        self.assertEqual(rollback.calls[-1], "verify_old_stopped")
        self.assertEqual(result["status"], "EXACT_OLD_STOPPED_ROLLBACK_CONVERGED")

    def test_source_graph_has_no_rejected_owner_or_persistent_authority_import(self) -> None:
        tree = ast.parse(MODULE_PATH.read_text("utf-8"))
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imports.add(node.module)
        self.assertIn("telegram_r5_boot_resume", imports)
        for forbidden in (
            "activate_p07_owner_private_memory_v1",
            "p07_owner_private_memory_production_plan",
            "p07_d_activation_transaction",
            "activation_transaction_substrate_v1",
        ):
            self.assertNotIn(forbidden, imports)
        text = MODULE_PATH.read_text("utf-8")
        for forbidden_call in (
            "fixed_owner_entry(",
            "run_checkpointed_stage(",
            "controller_entry(",
        ):
            self.assertNotIn(forbidden_call, text)

    def test_fixed_identity_constants_and_checkpoint_members_are_unique(self) -> None:
        self.assertEqual(
            module.EXPECTED_DEPLOY_PARENT,
            "c172aad62030bdd8f319ae394afe9665c936eb7d",
        )
        self.assertEqual(len(module._TARGET_CONTAINER["container_id"]), 64)
        self.assertNotEqual(
            module._TARGET_CONTAINER["container_id"],
            module._ARCHIVE_CONTAINER["container_id"],
        )
        for seed in (11, 29):
            state = synthetic_state(seed)
            self.assertEqual(len(state.checkpoint), 7)
            self.assertEqual(len({member.path for member in state.checkpoint}), 7)
            self.assertEqual(len({member.role for member in state.checkpoint}), 7)
            self.assertEqual(
                len({sha256(member.payload).hexdigest() for member in state.checkpoint}),
                7,
            )


if __name__ == "__main__":
    unittest.main()
