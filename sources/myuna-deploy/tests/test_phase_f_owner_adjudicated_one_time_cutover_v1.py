from __future__ import annotations

import ast
from contextlib import ExitStack, nullcontext, redirect_stdout
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
    current = tuple(
        module.SealedMember(
            path=Path(f"/synthetic/file-{index}"),
            payload=f"current:{seed}:{index}\n".encode("ascii"),
            mode=0o640 if index < 3 else 0o644,
            uid=0,
            gid=index,
            role=f"role-{index}",
        )
        for index in range(7)
    )
    target_members = tuple(
        module.SealedMember(
            path=member.path,
            payload=f"target:{seed}:{index}\n".encode("ascii"),
            mode=member.mode,
            uid=member.uid,
            gid=member.gid,
            role=member.role,
        )
        for index, member in enumerate(current)
    )
    old = module.boot.PhaseFContainerProjection(**module._OLD_CONTAINER)
    archive = module.replace(old, name=module.boot.ARCHIVE_PREFIX + "f" * 16)
    network = module.boot.PhaseFNetworkProjection(**module._NETWORK)
    return module.Preflight(
        release_root=Path("/synthetic/releases") / (f"{seed:064x}"[-64:]),
        new_unit=f"new-unit:{seed}\n".encode("ascii"),
        old_unit=f"old-unit:{seed}\n".encode("ascii"),
        authority={"authority_sha256": "f" * 64, "seed": seed},
        current=current,
        target_members=target_members,
        old=old,
        target_authority=mock.Mock(archive_name=archive.name),
        target=old,
        archive=None,
        network=network,
        topology="old_only",
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

    def archive_old(self, state: module.Preflight) -> module.Preflight:
        self._call("archive_old")
        return module.replace(
            state,
            target=None,
            topology="archive_only",
        )

    def create_target(self, state: module.Preflight) -> module.Preflight:
        self._call("create_target")
        return module.replace(
            state,
            target=self.state.target,
            topology="archive_target",
        )

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

    def write_member(self, member: module.SealedMember) -> None:
        kind = "target" if member.payload.startswith(b"target:") else "current"
        self._call(f"write_member:{kind}:{member.role}")

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

    def test_source_authority_accepts_exact_eight_field_projection_in_ten_field_envelope(self) -> None:
        release_sha256 = "d" * 64
        static_authority_sha256 = "e" * 64
        source = {
            "deploy_commit": "a" * 40,
            "deploy_parent": module.EXPECTED_DEPLOY_PARENT,
            "deploy_tree": "b" * 40,
        }
        fixed = {
            "builder": {},
            "controller": {},
            "files": {},
            "image": {},
            "parent": {},
            "releases": {},
            "schema": "synthetic.fixed-product-authority.v1",
            "source": source,
        }
        verified = {
            **fixed,
            "authority_sha256": static_authority_sha256,
            "release_sha256": release_sha256,
        }
        expected = {
            "controller_config_sha256": "c" * 64,
            "controller_release_sha256": release_sha256,
            "controller_static_authority_sha256": static_authority_sha256,
        }
        builder = mock.Mock()
        builder.verified_controller_authority.return_value = verified
        builder.expected_controller_authority.return_value = expected
        builder.verify_release.return_value = True
        builder._fixed_historical_authority.side_effect = [({}, {}), ({}, {})]
        builder._expected.return_value = {}
        effects = module.HostEffects(
            module.ReleaseSelection("a" * 40, "b" * 40, "c" * 64, release_sha256)
        )
        old_unit = b"synthetic-old-unit\n"
        with (
            mock.patch.object(
                module,
                "__file__",
                f"/opt/myuna/telegram-r5/releases/{release_sha256}/"
                "phase_f_owner_adjudicated_one_time_cutover_v1.py",
            ),
            mock.patch.object(
                module,
                "_external_release_document",
                return_value={"fixed_product_authority": fixed},
            ),
            mock.patch.object(module, "_load_module", return_value=builder),
            mock.patch.object(module, "_sealed_members", side_effect=[(), ()]),
            mock.patch.object(
                module, "_render_unit", side_effect=[b"synthetic-new-unit\n", old_unit]
            ),
            mock.patch.object(module, "OLD_UNIT_SHA256", sha256(old_unit).hexdigest()),
        ):
            loaded = effects._load_release()
        self.assertIs(loaded[1], verified)
        builder.verify_release.assert_called_once_with(
            module.RELEASES_ROOT, release_sha256, expected
        )

    def test_source_authority_rejects_hostile_projection_envelopes_before_release_use(self) -> None:
        release_sha256 = "d" * 64
        static_authority_sha256 = "e" * 64
        source = {
            "deploy_commit": "a" * 40,
            "deploy_parent": module.EXPECTED_DEPLOY_PARENT,
            "deploy_tree": "b" * 40,
        }
        fixed = {
            "builder": {},
            "controller": {},
            "files": {},
            "image": {},
            "parent": {},
            "releases": {},
            "schema": "synthetic.fixed-product-authority.v1",
            "source": source,
        }
        verified = {
            **fixed,
            "authority_sha256": static_authority_sha256,
            "release_sha256": release_sha256,
        }
        expected = {
            "controller_config_sha256": "c" * 64,
            "controller_release_sha256": release_sha256,
            "controller_static_authority_sha256": static_authority_sha256,
        }
        missing_manifest = dict(fixed)
        missing_manifest.pop("builder")
        extra_manifest = {**fixed, "unknown": {}}
        missing_base = dict(verified)
        missing_base.pop("controller")
        missing_release = dict(verified)
        missing_release.pop("release_sha256")
        missing_static = dict(verified)
        missing_static.pop("authority_sha256")
        sibling_source = {
            **source,
            "deploy_parent": "f" * 40,
        }
        cases = {
            "missing_manifest_base": (missing_manifest, verified, expected),
            "extra_manifest_base": (extra_manifest, verified, expected),
            "wrong_manifest_type": ([], verified, expected),
            "missing_verified_base": (fixed, missing_base, expected),
            "wrong_verified_base_type": (
                {**fixed, "builder": []},
                {**verified, "builder": []},
                expected,
            ),
            "wrong_verified_schema_type": (
                {**fixed, "schema": {}},
                {**verified, "schema": {}},
                expected,
            ),
            "missing_release_binding": (fixed, missing_release, expected),
            "missing_static_binding": (fixed, missing_static, expected),
            "extra_verified_field": (fixed, {**verified, "unknown": None}, expected),
            "wrong_release_type": (fixed, {**verified, "release_sha256": b"d" * 64}, expected),
            "wrong_static_type": (fixed, {**verified, "authority_sha256": 7}, expected),
            "substituted_release": (fixed, {**verified, "release_sha256": "f" * 64}, expected),
            "substituted_static": (fixed, {**verified, "authority_sha256": "f" * 64}, expected),
            "copied_release_as_static": (
                fixed,
                {**verified, "authority_sha256": release_sha256},
                expected,
            ),
            "substituted_base": (
                fixed,
                {**verified, "controller": {"substituted": True}},
                expected,
            ),
            "caller_consistent_sibling_source": (
                {**fixed, "source": sibling_source},
                {**verified, "source": sibling_source},
                expected,
            ),
            "wrong_expected_envelope": (
                fixed,
                verified,
                {**expected, "unknown": None},
            ),
            "wrong_expected_config_type": (
                fixed,
                verified,
                {**expected, "controller_config_sha256": b"c" * 64},
            ),
            "substituted_expected_static": (
                fixed,
                verified,
                {**expected, "controller_static_authority_sha256": "f" * 64},
            ),
        }
        for name, (manifest_authority, selected_authority, selected_expected) in cases.items():
            with self.subTest(name=name):
                builder = mock.Mock()
                builder.verified_controller_authority.return_value = selected_authority
                builder.expected_controller_authority.return_value = selected_expected
                builder.verify_release.return_value = True
                effects = module.HostEffects(
                    module.ReleaseSelection(
                        "a" * 40,
                        "b" * 40,
                        "c" * 64,
                        release_sha256,
                    )
                )
                with (
                    mock.patch.object(
                        module,
                        "__file__",
                        f"/opt/myuna/telegram-r5/releases/{release_sha256}/"
                        "phase_f_owner_adjudicated_one_time_cutover_v1.py",
                    ),
                    mock.patch.object(
                        module,
                        "_external_release_document",
                        return_value={"fixed_product_authority": manifest_authority},
                    ),
                    mock.patch.object(module, "_load_module", return_value=builder),
                ):
                    with self.assertRaisesRegex(
                        module.CutoverRejected, "source_authority_rejected"
                    ):
                        effects._load_release()
                builder.verify_release.assert_not_called()

    def test_cli_preserves_typed_manual_required_without_raw_exception(self) -> None:
        selection = [
            "--reviewed-deploy-commit", "a" * 40,
            "--reviewed-deploy-tree", "b" * 40,
            "--public-package-sha256", "c" * 64,
            "--release-sha256", "d" * 64,
        ]
        for mode, kind, boundary, raw_cause, expected_cause in (
            (
                "cutover",
                "cutover_manual_required",
                "target_container",
                "target_start_command_rejected",
                "target_start_command_rejected",
            ),
            (
                "rollback",
                "rollback_manual_required",
                "restore:old_container",
                "lost_return:synthetic-raw-value",
                "manual_effect_unclassified_rejected",
            ),
            (
                "cutover",
                "cutover_manual_required",
                "runtime_socket",
                "runtime_signing_stage_rejected",
                "runtime_signing_stage_rejected",
            ),
        ):
            with self.subTest(mode=mode):
                output = io.StringIO()
                error = module.ManualRequired(kind, boundary, raw_cause)
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
                self.assertEqual(result["boundary"], boundary)
                self.assertEqual(result["cause"], expected_cause)
                self.assertNotIn("code", result)
                if raw_cause != expected_cause:
                    self.assertNotIn(raw_cause, output.getvalue())
                self.assertNotIn("ManualRequired", output.getvalue())

    def test_target_container_lower_rejections_have_finite_cli_causes(self) -> None:
        selection = [
            "--reviewed-deploy-commit", "a" * 40,
            "--reviewed-deploy-tree", "b" * 40,
            "--public-package-sha256", "c" * 64,
            "--release-sha256", "d" * 64,
        ]
        cases = (
            (
                "policy",
                module.boot.ResumeRejected("phase_f_policy_identity_rejected"),
                "target_policy_identity_rejected",
            ),
            (
                "policy",
                module.boot.ResumeRejected("phase_f_policy_state_ambiguous"),
                "target_policy_state_rejected",
            ),
            (
                "policy",
                module.boot.ResumeRejected("fixed_command_failed:docker:23"),
                "target_policy_command_rejected",
            ),
            (
                "policy",
                module.boot.ResumeRejected("phase_f_policy_poststate_rejected"),
                "target_policy_poststate_rejected",
            ),
            (
                "start",
                module.boot.ResumeRejected("phase_f_start_identity_rejected"),
                "target_start_identity_rejected",
            ),
            (
                "start",
                module.boot.ResumeRejected("phase_f_start_state_ambiguous"),
                "target_start_state_rejected",
            ),
            (
                "start",
                module.boot.ResumeRejected("fixed_command_failed:docker:29"),
                "target_start_command_rejected",
            ),
            (
                "start",
                module.boot.ResumeRejected("phase_f_start_poststate_rejected"),
                "target_start_poststate_rejected",
            ),
            (
                "start",
                module.boot.ResumeRejected("phase_f_start_health_timeout"),
                "target_start_health_timeout",
            ),
            (
                "policy",
                module.boot.ResumeRejected("future-lower-secret"),
                "target_container_unclassified_rejected",
            ),
            (
                "policy",
                RuntimeError("unexpected-policy-secret"),
                "target_container_unclassified_rejected",
            ),
            (
                "start",
                RuntimeError("unexpected-start-secret"),
                "target_container_unclassified_rejected",
            ),
        )
        for operation, lower_error, expected_cause in cases:
            with self.subTest(
                operation=operation,
                lower=type(lower_error).__name__,
                expected=expected_cause,
            ):
                state = synthetic_state()
                effects = module.HostEffects(
                    module.ReleaseSelection("a" * 40, "b" * 40, "c" * 64, "d" * 64)
                )
                policy = mock.Mock(return_value=state.target)
                start = mock.Mock(return_value=state.target)
                if operation == "policy":
                    policy.side_effect = lower_error
                else:
                    start.side_effect = lower_error
                with (
                    mock.patch.object(
                        module.boot, "phase_f_set_restart_policy_exact", policy
                    ),
                    mock.patch.object(module.boot, "phase_f_start_container_exact", start),
                ):
                    with self.assertRaises(module.CutoverRejected) as caught:
                        effects.start_target(state)
                self.assertEqual(caught.exception.code, expected_cause)
                self.assertEqual(policy.call_count, 1)
                self.assertEqual(start.call_count, 0 if operation == "policy" else 1)
                self.assertNotIn(str(lower_error), str(caught.exception))

                fake = FakeEffects()
                with mock.patch.object(
                    fake,
                    "start_target",
                    side_effect=module.CutoverRejected(expected_cause),
                ):
                    with self.assertRaises(module.ManualRequired) as manual:
                        module.execute("cutover", fake)
                self.assertEqual(manual.exception.effect_code, expected_cause)
                self.assertNotIn("verify_new_running", fake.calls)
                self.assertEqual(fake.calls.count("stop_target"), 1)

                output = io.StringIO()
                with (
                    mock.patch.object(sys, "argv", [MODULE_PATH.as_posix(), "cutover", *selection]),
                    mock.patch.object(module.os, "geteuid", return_value=0),
                    mock.patch.object(module, "releases_lock", return_value=nullcontext()),
                    mock.patch.object(module, "HostEffects"),
                    mock.patch.object(module, "execute", side_effect=manual.exception),
                    redirect_stdout(output),
                ):
                    self.assertEqual(module.main(), 1)
                receipt = json.loads(output.getvalue())
                self.assertEqual(
                    receipt,
                    {
                        "boundary": "target_container",
                        "cause": expected_cause,
                        "mode": "cutover",
                        "schema": module.SCHEMA,
                        "status": "cutover_manual_required",
                    },
                )
                self.assertNotIn(str(lower_error), output.getvalue())
                self.assertNotIn("traceback", output.getvalue().lower())
                self.assertNotIn("stderr", output.getvalue().lower())

    def test_host_effects_explicit_rollback_admits_remove_before_rename_partial(self) -> None:
        synthetic = synthetic_state()
        old_sha = sha256(synthetic.old_unit).hexdigest()
        observed = {}
        for member in synthetic.target_members:
            observed[member.path] = {
                "gid": member.gid,
                "mode": f"{member.mode:04o}",
                "sha256": sha256(member.payload).hexdigest(),
                "size": len(member.payload),
                "uid": member.uid,
            }
        selection = module.ReleaseSelection("a" * 40, "b" * 40, "c" * 64, "d" * 64)
        effects = module.HostEffects(selection)
        projections = {
            module.boot.CONTAINER: None,
            synthetic.target_authority.archive_name: module.replace(
                synthetic.old,
                name=synthetic.target_authority.archive_name,
            ),
        }
        effects._builder = mock.Mock()
        effects._builder.verified_target_container_authority.return_value = (
            synthetic.target_authority
        )
        with (
            mock.patch.object(
                effects,
                "_load_release",
                return_value=(
                    synthetic.release_root,
                    synthetic.authority,
                    synthetic.current,
                    synthetic.target_members,
                    synthetic.new_unit,
                    synthetic.old_unit,
                ),
            ),
            mock.patch.object(module, "_file_projection", side_effect=lambda path: observed[path]),
            mock.patch.object(module, "_read_regular", return_value=synthetic.old_unit),
            mock.patch.object(module, "OLD_UNIT_SHA256", old_sha),
            mock.patch.object(module.boot, "phase_f_container_projection", side_effect=lambda name: projections[name]),
            mock.patch.object(module.boot, "phase_f_network_projection", return_value=synthetic.network),
            mock.patch.object(effects, "_service_state", return_value="inactive"),
            mock.patch.object(effects, "_staged_signing_state", return_value="absent"),
            mock.patch.object(
                effects,
                "_governed_container_names",
                return_value=(synthetic.target_authority.archive_name,),
            ),
        ):
            partial = effects.preflight("rollback")
            self.assertIsNone(partial.target)
            with self.assertRaisesRegex(module.CutoverRejected, "cutover_file_prestate_rejected"):
                effects.preflight("cutover")
        with (
            mock.patch.object(
                module.boot,
                "phase_f_container_projection",
                side_effect=lambda name: (
                    None if name == module.boot.CONTAINER else partial.archive
                ),
            ),
            mock.patch.object(module.boot, "phase_f_remove_container_exact") as remove,
            mock.patch.object(module.boot, "phase_f_rename_container_exact") as rename,
        ):
            effects.restore_old_container(partial)
        remove.assert_not_called()
        rename.assert_called_once_with(
            partial.archive,
            source_name=partial.target_authority.archive_name,
            target_name=module.boot.CONTAINER,
        )
        restored = synthetic.old
        with (
            mock.patch.object(module, "_read_regular", return_value=synthetic.old_unit),
            mock.patch.object(module, "OLD_UNIT_SHA256", old_sha),
            mock.patch.object(effects, "_service_state", return_value="inactive"),
            mock.patch.object(effects, "_staged_signing_state", return_value="absent"),
            mock.patch.object(
                module.boot,
                "phase_f_container_projection",
                side_effect=lambda name: (
                    restored if name == module.boot.CONTAINER else None
                ),
            ),
            mock.patch.object(module.boot, "phase_f_network_projection", return_value=synthetic.network),
            mock.patch.object(
                effects,
                "_governed_container_names",
                return_value=(module.boot.CONTAINER,),
            ),
        ):
            effects.verify_old_stopped(partial)

        with (
            mock.patch.object(effects, "preflight", return_value=partial),
            mock.patch.object(effects, "stop_service"),
            mock.patch.object(effects, "stop_target"),
            mock.patch.object(effects, "write_member"),
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

    def test_dynamic_target_identity_is_bound_by_source_projection_not_old_id(self) -> None:
        synthetic = synthetic_state()
        authority = mock.Mock(
            image="myuna/astrbot-phase-f-deterministic@sha256:" + "1" * 64,
            plan_digest="2" * 64,
            target_config_digest="3" * 64,
            user="988:982",
            effect={
                "command_sha256": "4" * 64,
                "effect_sha256": "5" * 64,
                "environment_sha256": "6" * 64,
                "host_sha256": "7" * 64,
                "mounts_sha256": "8" * 64,
            },
        )
        base = {
            **module._OLD_CONTAINER,
            "command_digest": "4" * 64,
            "effect_digest": "5" * 64,
            "effect_environment_digest": "6" * 64,
            "effect_host_digest": "7" * 64,
            "effect_mounts_digest": "8" * 64,
            "image": authority.image,
            "plan_digest": authority.plan_digest,
            "target_config_digest": authority.target_config_digest,
        }
        first = module.boot.PhaseFContainerProjection(
            **{**base, "container_id": "9" * 64}
        )
        second = module.boot.PhaseFContainerProjection(
            **{**base, "container_id": "a" * 64}
        )
        self.assertTrue(module._target_matches_authority(authority, first))
        self.assertTrue(module._target_matches_authority(authority, second))
        self.assertNotEqual(first.container_id, second.container_id)
        self.assertNotEqual(first.container_id, synthetic.old.container_id)
        self.assertFalse(
            module._target_matches_authority(
                authority,
                module.replace(second, effect_digest="b" * 64),
            )
        )

    def test_archive_create_effects_are_at_most_once_and_typed(self) -> None:
        synthetic = synthetic_state()
        archived = module.replace(
            synthetic.old,
            name=synthetic.target_authority.archive_name,
        )
        effects = module.HostEffects(
            module.ReleaseSelection("a" * 40, "b" * 40, "c" * 64, "d" * 64)
        )
        with mock.patch.object(
            module.boot,
            "phase_f_rename_container_exact",
            return_value=archived,
        ) as rename:
            archive_state = effects.archive_old(synthetic)
        self.assertEqual(archive_state.topology, "archive_only")
        rename.assert_called_once_with(
            synthetic.old,
            source_name=module.boot.CONTAINER,
            target_name=synthetic.target_authority.archive_name,
        )

        created = module.replace(synthetic.old, container_id="a" * 64)
        with (
            mock.patch.object(
                module.boot,
                "phase_f_create_target_stopped",
                return_value=created,
            ) as create,
            mock.patch.object(module, "_target_matches_authority", return_value=True),
        ):
            created_state = effects.create_target(archive_state)
        self.assertEqual(created_state.topology, "archive_target")
        self.assertEqual(created_state.target.container_id, "a" * 64)
        create.assert_called_once_with(
            synthetic.target_authority,
            expected_network=synthetic.network,
            archived_old=archived,
        )

        for operation, state, lower, expected in (
            (
                "archive",
                synthetic,
                module.boot.ResumeRejected("phase_f_rename_poststate_rejected"),
                "archive_old_poststate_rejected",
            ),
            (
                "create",
                archive_state,
                module.boot.ResumeRejected("phase_f_create_poststate_rejected"),
                "target_create_poststate_rejected",
            ),
        ):
            with self.subTest(operation=operation):
                patched = (
                    "phase_f_rename_container_exact"
                    if operation == "archive"
                    else "phase_f_create_target_stopped"
                )
                with mock.patch.object(module.boot, patched, side_effect=lower) as call:
                    with self.assertRaises(module.CutoverRejected) as raised:
                        (
                            effects.archive_old(state)
                            if operation == "archive"
                            else effects.create_target(state)
                        )
                self.assertEqual(raised.exception.code, expected)
                self.assertEqual(call.call_count, 1)

        for boundary in ("archive_old", "create_target"):
            fake = FakeEffects(fail_call=boundary)
            with self.assertRaises(module.ManualRequired) as raised:
                module.execute("cutover", fake)
            self.assertEqual(fake.calls.count(boundary), 1)
            self.assertEqual(raised.exception.boundary, boundary)
            if boundary == "archive_old":
                self.assertNotIn("write_member:target:role-0", fake.calls)
            else:
                self.assertIn("write_member:target:role-6", fake.calls)

    def test_runtime_signing_socket_prestate_is_finite_typed_and_single_dispatch(self) -> None:
        selection = module.ReleaseSelection("a" * 40, "b" * 40, "c" * 64, "d" * 64)
        effects = module.HostEffects(selection)
        order: list[str] = []

        def stage(uid: int, gid: int) -> None:
            order.append(f"stage:{uid}:{gid}")

        def run(command: list[str], **_kwargs: object) -> str:
            order.append(":".join(command[-2:]))
            return ""

        with (
            mock.patch.object(
                effects,
                "_staged_signing_state",
                side_effect=("absent", "exact"),
            ),
            mock.patch.object(
                effects,
                "_service_state",
                side_effect=("inactive", "active"),
            ),
            mock.patch.object(module.boot, "stage_ephemeral_signing", side_effect=stage) as stage_call,
            mock.patch.object(module.boot, "run", side_effect=run) as run_call,
        ):
            effects.start_service(module.RUNTIME_SOCKET)
        self.assertEqual(
            order,
            [
                "stage:988:982",
                f"start:{module.RUNTIME_SOCKET}",
            ],
        )
        self.assertEqual(stage_call.call_count, 1)
        self.assertEqual(run_call.call_count, 1)

        cases = (
            (
                "runtime_signing_stage_rejected",
                ("absent",),
                OSError("synthetic-stage-lost-return"),
                None,
                ("inactive",),
                0,
            ),
            (
                "runtime_signing_poststate_rejected",
                ("absent", "third"),
                None,
                None,
                (),
                0,
            ),
            (
                "runtime_socket_start_rejected",
                ("absent", "exact"),
                None,
                OSError("synthetic-socket-lost-return"),
                ("inactive",),
                1,
            ),
            (
                "runtime_socket_poststate_rejected",
                ("absent", "exact"),
                None,
                None,
                ("inactive", "inactive"),
                1,
            ),
        )
        for expected, signing, stage_error, run_error, service, expected_run in cases:
            with self.subTest(expected=expected):
                stage_effect = mock.Mock(side_effect=stage_error)
                run_effect = mock.Mock(side_effect=run_error)
                with (
                    mock.patch.object(
                        effects,
                        "_staged_signing_state",
                        side_effect=signing,
                    ),
                    mock.patch.object(
                        effects,
                        "_service_state",
                        side_effect=service,
                    ),
                    mock.patch.object(
                        module.boot,
                        "stage_ephemeral_signing",
                        stage_effect,
                    ),
                    mock.patch.object(module.boot, "run", run_effect),
                ):
                    with self.assertRaises(module.CutoverRejected) as caught:
                        effects.start_service(module.RUNTIME_SOCKET)
                self.assertEqual(caught.exception.code, expected)
                self.assertEqual(stage_effect.call_count, 1)
                self.assertEqual(run_effect.call_count, expected_run)
                self.assertNotIn("synthetic", str(caught.exception))

    def test_runtime_signing_cleanup_is_exact_only_and_no_redispatch(self) -> None:
        effects = module.HostEffects(
            module.ReleaseSelection("a" * 40, "b" * 40, "c" * 64, "d" * 64)
        )
        with (
            mock.patch.object(effects, "_service_state", return_value="inactive"),
            mock.patch.object(
                effects,
                "_staged_signing_state",
                side_effect=("exact", "absent"),
            ),
            mock.patch.object(Path, "unlink") as unlink,
        ):
            effects.stop_service(module.RUNTIME_SOCKET)
        unlink.assert_called_once_with()

        with (
            mock.patch.object(effects, "_service_state", return_value="inactive"),
            mock.patch.object(effects, "_staged_signing_state", return_value="third"),
            mock.patch.object(Path, "unlink") as unlink,
        ):
            with self.assertRaisesRegex(
                module.CutoverRejected,
                "runtime_signing_cleanup_rejected",
            ):
                effects.stop_service(module.RUNTIME_SOCKET)
        unlink.assert_not_called()

    def test_bounded_signing_digest_is_nofollow_metadata_and_acl_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "synthetic-signing"
            payload = b"synthetic-signing-authority-value\n"
            path.write_bytes(payload)
            path.chmod(0o600)
            metadata = path.stat()
            self.assertEqual(
                module._bounded_regular_digest(
                    path,
                    mode=0o600,
                    uid=metadata.st_uid,
                    gid=metadata.st_gid,
                    code="synthetic_rejected",
                ),
                (sha256(payload).hexdigest(), len(payload)),
            )
            path.chmod(0o644)
            with self.assertRaisesRegex(module.CutoverRejected, "synthetic_rejected"):
                module._bounded_regular_digest(
                    path,
                    mode=0o600,
                    uid=metadata.st_uid,
                    gid=metadata.st_gid,
                    code="synthetic_rejected",
                )

    def test_rollback_hazard_preflight_is_typed_manual_required(self) -> None:
        for code in (
            "rollback_container_prestate_rejected",
            "rollback_signing_prestate_rejected",
        ):
            with self.subTest(code=code):
                effects = FakeEffects()
                with mock.patch.object(
                    effects,
                    "preflight",
                    side_effect=module.CutoverRejected(code),
                ):
                    with self.assertRaises(module.ManualRequired) as caught:
                        module.execute("rollback", effects)
                self.assertEqual(caught.exception.kind, "rollback_manual_required")
                self.assertEqual(caught.exception.boundary, "preflight")
                self.assertEqual(caught.exception.effect_code, code)

    def test_container_census_excludes_inactive_historical_names_only(self) -> None:
        source_archive = module.boot.ARCHIVE_PREFIX + "a" * 16
        output = "\n".join(
            (
                module.boot.CONTAINER,
                module.boot.ARCHIVE_PREFIX + "durable-20260730T100006Z",
                module.boot.ARCHIVE_PREFIX + "recovery-20260730T164327",
                source_archive,
            )
        )
        with mock.patch.object(module.boot, "run", return_value=output):
            self.assertEqual(
                module.HostEffects._governed_container_names(),
                (module.boot.CONTAINER, source_archive),
            )

    def test_forward_requires_seven_current_and_rollback_admits_all_128_mixtures(self) -> None:
        synthetic = synthetic_state()
        old_sha = sha256(synthetic.old_unit).hexdigest()
        selection = module.ReleaseSelection("a" * 40, "b" * 40, "c" * 64, "d" * 64)
        effects = module.HostEffects(selection)
        projections = {
            module.boot.CONTAINER: synthetic.old,
            synthetic.target_authority.archive_name: None,
        }
        effects._builder = mock.Mock()
        effects._builder.verified_target_container_authority.return_value = (
            synthetic.target_authority
        )

        def projection(member: module.SealedMember) -> dict[str, object]:
            return {
                "gid": member.gid,
                "mode": f"{member.mode:04o}",
                "sha256": sha256(member.payload).hexdigest(),
                "size": len(member.payload),
                "uid": member.uid,
            }

        def preflight(
            observed: dict[Path, dict[str, object]],
            mode: str,
            *,
            containers: dict[str, module.boot.PhaseFContainerProjection | None] = projections,
            network: module.boot.PhaseFNetworkProjection = synthetic.network,
            governed: tuple[str, ...] = (module.boot.CONTAINER,),
            target_matches: bool = False,
            signing_state: str = "absent",
        ) -> module.Preflight:
            with ExitStack() as stack:
                stack.enter_context(
                    mock.patch.object(
                        effects,
                        "_load_release",
                        return_value=(
                            synthetic.release_root,
                            synthetic.authority,
                            synthetic.current,
                            synthetic.target_members,
                            synthetic.new_unit,
                            synthetic.old_unit,
                        ),
                    )
                )
                stack.enter_context(mock.patch.object(module, "_read_regular", return_value=synthetic.old_unit))
                stack.enter_context(mock.patch.object(module, "OLD_UNIT_SHA256", old_sha))
                stack.enter_context(
                    mock.patch.object(
                        module.boot,
                        "phase_f_container_projection",
                        side_effect=lambda name: containers.get(name),
                    )
                )
                stack.enter_context(mock.patch.object(module.boot, "phase_f_network_projection", return_value=network))
                stack.enter_context(mock.patch.object(effects, "_service_state", return_value="inactive"))
                stack.enter_context(
                    mock.patch.object(
                        effects,
                        "_staged_signing_state",
                        return_value=signing_state,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        effects,
                        "_governed_container_names",
                        return_value=governed,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        module,
                        "_target_matches_authority",
                        return_value=target_matches,
                    )
                )
                stack.enter_context(mock.patch.object(module, "_file_projection", side_effect=lambda path: observed[path]))
                return effects.preflight(mode)

        all_current = {
            member.path: projection(member) for member in synthetic.current
        }
        for signing_state in ("absent", "exact"):
            for mask in range(128):
                observed = {
                    current.path: projection(
                        target if mask & (1 << index) else current
                    )
                    for index, (current, target) in enumerate(
                        zip(synthetic.current, synthetic.target_members, strict=True)
                    )
                }
                with self.subTest(mask=mask, signing_state=signing_state):
                    self.assertEqual(
                        len(
                            preflight(
                                observed,
                                "rollback",
                                signing_state=signing_state,
                            ).current
                        ),
                        7,
                    )
                    if mask == 0 and signing_state == "absent":
                        self.assertEqual(
                            len(preflight(observed, "cutover").target_members),
                            7,
                        )
                    elif mask != 0:
                        with self.assertRaisesRegex(
                            module.CutoverRejected, "cutover_file_prestate_rejected"
                        ):
                            preflight(observed, "cutover")
            if signing_state == "exact":
                with self.assertRaisesRegex(
                    module.CutoverRejected, "cutover_signing_prestate_rejected"
                ):
                    preflight(all_current, "cutover", signing_state=signing_state)

        with self.assertRaisesRegex(
            module.CutoverRejected, "rollback_signing_prestate_rejected"
        ):
            preflight(all_current, "rollback", signing_state="third")

        third = {member.path: projection(member) for member in synthetic.current}
        third[synthetic.current[3].path] = {**third[synthetic.current[3].path], "sha256": "f" * 64}
        with self.assertRaisesRegex(
            module.CutoverRejected, "rollback_file_prestate_rejected"
        ):
            preflight(third, "rollback")

        with self.assertRaisesRegex(
            module.CutoverRejected, "rollback_container_prestate_rejected"
        ):
            preflight(
                all_current,
                "rollback",
                governed=(
                    module.boot.CONTAINER,
                    module.boot.ARCHIVE_PREFIX + "0" * 16,
                ),
            )
        wrong_network = module.replace(synthetic.network, network_id="f" * 64)
        with self.assertRaisesRegex(
            module.CutoverRejected, "rollback_container_prestate_rejected"
        ):
            preflight(all_current, "rollback", network=wrong_network)

        dynamic_target = module.replace(
            synthetic.old,
            container_id="a" * 64,
            target_config_digest="b" * 64,
        )
        archive = module.replace(
            synthetic.old,
            name=synthetic.target_authority.archive_name,
        )
        archive_target = {
            module.boot.CONTAINER: dynamic_target,
            synthetic.target_authority.archive_name: archive,
        }
        admitted = preflight(
            all_current,
            "rollback",
            containers=archive_target,
            governed=tuple(
                sorted(
                    (
                        module.boot.CONTAINER,
                        synthetic.target_authority.archive_name,
                    )
                )
            ),
            target_matches=True,
        )
        self.assertEqual(admitted.topology, "archive_target")
        self.assertEqual(admitted.target.container_id, "a" * 64)

    def test_per_role_atomic_fault_and_lost_return_matrix_is_single_dispatch(self) -> None:
        stages = (
            "before",
            "write",
            "chmod",
            "chown",
            "file_fsync",
            "rename",
            "rename_lost_return",
            "dir_fsync_lost_return",
        )
        real_write = module.os.write
        real_fsync = module.os.fsync
        real_replace = module.os.replace
        for role_index, (_path, role) in enumerate(module.ROLE_ORDER):
            for stage in stages:
                with self.subTest(role=role, stage=stage), tempfile.TemporaryDirectory() as temporary:
                    path = Path(temporary) / f"member-{role_index}"
                    old = f"current:{role_index}\n".encode("ascii")
                    new = f"target:{role_index}\n".encode("ascii")
                    path.write_bytes(old)
                    path.chmod(0o640)
                    member = module.SealedMember(path, new, 0o640, 0, 0, role)
                    calls = {"write": 0, "replace": 0, "fsync": 0}

                    def partial_write(descriptor: int, payload: memoryview) -> int:
                        calls["write"] += 1
                        if calls["write"] == 1:
                            return real_write(descriptor, payload[: max(1, len(payload) // 2)])
                        raise OSError("synthetic-write")

                    def replace_then_raise(source: Path, destination: Path) -> None:
                        calls["replace"] += 1
                        real_replace(source, destination)
                        raise OSError("synthetic-lost-rename-return")

                    def dir_fsync_then_raise(descriptor: int) -> None:
                        calls["fsync"] += 1
                        real_fsync(descriptor)
                        if calls["fsync"] == 2:
                            raise OSError("synthetic-lost-dir-fsync-return")

                    with ExitStack() as stack:
                        if stage == "before":
                            stack.enter_context(mock.patch.object(module.tempfile, "mkstemp", side_effect=OSError("synthetic-before")))
                        elif stage == "write":
                            stack.enter_context(mock.patch.object(module.os, "write", side_effect=partial_write))
                        elif stage == "chmod":
                            stack.enter_context(mock.patch.object(module.os, "fchmod", side_effect=OSError("synthetic-chmod")))
                        elif stage == "chown":
                            stack.enter_context(mock.patch.object(module.os, "fchown", side_effect=OSError("synthetic-chown")))
                        else:
                            stack.enter_context(mock.patch.object(module.os, "fchown", return_value=None))
                            if stage == "file_fsync":
                                stack.enter_context(mock.patch.object(module.os, "fsync", side_effect=OSError("synthetic-file-fsync")))
                            elif stage == "rename":
                                stack.enter_context(mock.patch.object(module.os, "replace", side_effect=OSError("synthetic-rename")))
                            elif stage == "rename_lost_return":
                                stack.enter_context(mock.patch.object(module.os, "replace", side_effect=replace_then_raise))
                            elif stage == "dir_fsync_lost_return":
                                stack.enter_context(mock.patch.object(module.os, "fsync", side_effect=dir_fsync_then_raise))
                        with self.assertRaises(OSError):
                            module._atomic_file(path, member.payload, mode=member.mode, uid=member.uid, gid=member.gid)

                    self.assertLessEqual(calls["replace"], 1)
                    expected = new if stage in {"rename_lost_return", "dir_fsync_lost_return"} else old
                    self.assertEqual(path.read_bytes(), expected)
                    self.assertEqual(list(path.parent.glob(".phase-f-cutover-*")), [])

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
            "archive_old",
            *[f"write_member:target:role-{index}" for index in range(7)],
            "write_new_unit",
            "daemon_reload",
            f"start_service:{module.CORE_SERVICE}",
            f"start_service:{module.RUNTIME_SOCKET}",
            "create_target",
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
            [name for name in boundaries if name.startswith("write_member:current:")],
            [f"write_member:current:role-{index}" for index in range(7)],
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
            "current_authority",
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
        calls = observations[0][1]
        self.assertEqual(
            calls[2:9],
            [f"write_member:target:role-{index}" for index in range(7)],
        )
        self.assertEqual(calls[1], "archive_old")
        self.assertLess(calls.index("write_member:target:role-6"), calls.index("write_new_unit"))
        self.assertLess(calls.index("write_new_unit"), calls.index("daemon_reload"))
        self.assertLess(
            calls.index(f"start_service:{module.RUNTIME_SOCKET}"),
            calls.index("create_target"),
        )
        self.assertEqual(calls.count("daemon_reload"), 1)

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
        for retired_authority in (
            "CHECKPOINT_ROOT",
            "CHECKPOINT_MANIFEST_SHA256",
            "CHECKPOINT_SCHEMA",
            "_checkpoint(",
        ):
            self.assertNotIn(retired_authority, text)
        for forbidden_call in (
            "fixed_owner_entry(",
            "run_checkpointed_stage(",
            "controller_entry(",
        ):
            self.assertNotIn(forbidden_call, text)

    def test_fixed_identity_constants_and_sealed_members_are_unique(self) -> None:
        self.assertEqual(
            module.EXPECTED_DEPLOY_PARENT,
            "00b39126ce8b742869cf1c6f2868d705e4bc8315",
        )
        self.assertEqual(len(module._OLD_CONTAINER["container_id"]), 64)
        self.assertEqual(
            module.CURRENT_CONTROLLER_RELEASE,
            "b78ef052c838dc896f98cb9ef8d2a0c96ae55b2d1146ede39d8e8753a976aa69",
        )
        self.assertEqual(len(module.ROLE_ORDER), 7)
        self.assertEqual(len({path for path, _role in module.ROLE_ORDER}), 7)
        self.assertEqual(len({role for _path, role in module.ROLE_ORDER}), 7)
        for seed in (11, 29):
            state = synthetic_state(seed)
            self.assertEqual(len(state.current), 7)
            self.assertEqual(len(state.target_members), 7)
            self.assertEqual(len({member.path for member in state.current}), 7)
            self.assertEqual(len({member.role for member in state.current}), 7)
            self.assertEqual(
                len({sha256(member.payload).hexdigest() for member in state.current}),
                7,
            )


if __name__ == "__main__":
    unittest.main()
