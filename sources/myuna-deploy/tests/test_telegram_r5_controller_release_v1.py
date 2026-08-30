#!/usr/bin/env python3
from __future__ import annotations

import base64
from dataclasses import replace
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CORE = Path("/srv/myuna/repos/core")
sys.path.insert(0, (ROOT / "scripts").as_posix())
ACCEPTED_PARENT = "d891a6ed0d213c60f284cb9258057c4dc5f08978"
CORE_COMMIT = "4c13c0b20552b5d8a8720f180d0569405fed00b0"
CONFIG_SHA256 = "e" * 64
MODULE_PATH = ROOT / "scripts/build_telegram_r5_controller_release_v1.py"
SPEC = importlib.util.spec_from_file_location(
    "build_telegram_r5_controller_release_v1",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)
product = module.product


def run(arguments: list[str], *, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        arguments,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def fixed_build_output(seed: int = 19001) -> tuple[dict[str, object], dict[str, bytes]]:
    files: dict[str, object] = {}
    for index, path in enumerate(sorted(product.FILE_ROLES)):
        if path == product.MEMORY_SELECTOR_PATH:
            release_set = f"{seed:016x}" + "3" * 48
            archive = "p07-owner-private-memory-transactional-" + release_set[:16]
            payload = product.canonical(
                {
                    "archive_id": archive,
                    "calendar_zone": "Asia/Shanghai",
                    "calendar_zone_config_digest": "1" * 64,
                    "channel_kind": "telegram",
                    "client_id": "telegram-owner-runtime",
                    "diary_coupled": False,
                    "egress_policy_digest": "2" * 64,
                    "egress_policy_mode": "historical_raw_recall_v1",
                    "expected_gid": product.MEMORY_RUNTIME_GID,
                    "expected_uid": product.MEMORY_RUNTIME_UID,
                    "memory_release_set_id": release_set,
                    "no_old_data_migration": True,
                    "p15_handoff_schema": "myuna.p15-handoff.v1",
                    "p15_projection_active": False,
                    "p08_lifecycle_start_watermark": product.P08_LIFECYCLE_START_WATERMARK,
                    "parent_epoch_id": product.PARENT_EPOCH_ID,
                    "parent_epoch_revision": product.PARENT_EPOCH_REVISION,
                    "parent_manifest_digest": product.PARENT_MANIFEST_SHA256,
                    "parent_release_set_id": product.PARENT_RELEASE_SET_ID,
                    "parent_selector_digest": product.PARENT_SELECTOR_SHA256,
                    "policy_overlay_id": "4" * 64,
                    "prompt_owner": "telegram-owner-runtime",
                    "runtime_root": f"{product.MEMORY_RUNTIME_ROOT}/{archive}",
                    "schema": "myuna.p07-owner-private-memory-selector.v4",
                    "status": "active",
                    "summary_used": False,
                }
            )
        else:
            payload = f"fixed-target:{seed}:{index}:{path}\n".encode("ascii")
        role, mode = product.FILE_ROLES[path]
        files[path] = {
            "gid": 0,
            "mode": mode,
            "owner": product.FILE_OWNERS[path],
            "payload_b64": base64.b64encode(payload).decode("ascii"),
            "payload_sha256": sha256(payload).hexdigest(),
            "role": role,
            "uid": 0,
        }
    payloads: dict[str, bytes] = {}

    def release(key: str, marker: str, root: str) -> dict[str, object]:
        payload = f"release:{seed}:{key}\n".encode("ascii")
        digest = sha256(f"digest:{seed}:{key}".encode()).hexdigest()
        rows = [{"path": "payload", "sha256": sha256(payload).hexdigest(), "size": len(payload)}]
        prefix = f"staging/releases/{key}/{digest}"
        payloads[f"{prefix}/payload"] = payload
        return {
            "bundle_prefix": prefix,
            "digest": digest,
            "directory_mode": "0550",
            "file_mode": "0440",
            "members": rows,
            "member_set_sha256": product.release_member_set_sha256(rows),
            "receipt_sha256": sha256(marker.encode()).hexdigest(),
            "root": root,
        }

    image_payload = f"image:{seed}\n".encode("ascii")
    archive_sha = sha256(image_payload).hexdigest()
    image_digest = sha256(f"image-digest:{seed}".encode()).hexdigest()
    image_path = f"staging/image/{archive_sha}.part-000000"
    payloads[image_path] = image_payload
    image_receipt = {
        "archive_sha256": archive_sha,
        "archive_size": len(image_payload),
        "image_id": "sha256:" + image_digest,
        "image_reference": product.TARGET_IMAGE_PREFIX + image_digest,
        "layers": [{"diff_id": "sha256:" + "d" * 64}],
        "manifest_digest": "sha256:" + image_digest,
        "platform": {"architecture": "amd64", "os": "linux"},
    }
    authority = {
        "builder": {
            "astrbot_commit": product.ACCEPTED_ASTRBOT_COMMIT,
            "astrbot_tree": "a" * 40,
            "base_image_digest": "sha256:7546bddf1040419a455dd1ca683a5e9cf84436bbd85de17c7ac626d3af7affe4",
            "gateway_builder_blob": product.GATEWAY_BUILDER_BLOB,
            "hybrid_builder_blob": product.HYBRID_BUILDER_BLOB,
            "runtime_base_digest": product.ACCEPTED_RUNTIME_BASE,
            "runtime_base_member_set_sha256": "b" * 64,
            "tool_set_sha256": "c" * 64,
        },
        "controller": {
            "config_sha256": files[
                "/etc/myuna-telegram-gateway/r5-resume-v1.json"
            ]["payload_sha256"],
            "member_set_sha256": "1" * 64,
            "source_receipt_sha256": "2" * 64,
        },
        "files": files,
        "image": {
            "archive_members": [{"path": image_path, "sha256": sha256(image_payload).hexdigest(), "size": len(image_payload)}],
            "archive_sha256": archive_sha,
            "archive_size": len(image_payload),
            "digest": image_digest,
            "member_set_sha256": product.image_member_set_sha256(image_receipt),
            "receipt": image_receipt,
            "receipt_sha256": sha256(product.canonical(image_receipt)).hexdigest(),
            "reference": product.TARGET_IMAGE_PREFIX + image_digest,
        },
        "parent": {
            "epoch_id": product.PARENT_EPOCH_ID,
            "epoch_revision": product.PARENT_EPOCH_REVISION,
            "lifecycle_start_watermark": product.P08_LIFECYCLE_START_WATERMARK,
            "manifest_sha256": product.PARENT_MANIFEST_SHA256,
            "release_set_id": product.PARENT_RELEASE_SET_ID,
            "selector_sha256": product.PARENT_SELECTOR_SHA256,
        },
        "releases": {
            "core": release("core", "core-receipt", product.CORE_RELEASE_ROOT),
            "plugin": release("plugin", "plugin-receipt", product.PLUGIN_RELEASE_ROOT),
            "runtime": release("runtime", "runtime-receipt", product.RUNTIME_RELEASE_ROOT),
        },
        "schema": product.SOURCE_SCHEMA,
        "source": {
            "core_commit": product.ACCEPTED_CORE_COMMIT,
            "core_tree": product.ACCEPTED_CORE_TREE,
            "deploy_commit": "0" * 40,
            "deploy_parent": module.CUTOVER_ACCEPTED_DEPLOY_PARENT,
            "deploy_tree": "1" * 40,
        },
    }
    return authority, payloads


def maintenance_build_output(
    seed: int = 19001,
) -> tuple[dict[str, object], dict[str, object], dict[str, bytes]]:
    baseline, payloads = fixed_build_output(seed)

    def rekey_plugin(authority: dict[str, object], digest: str) -> None:
        release = authority["releases"]["plugin"]
        old_prefix = str(release["bundle_prefix"])
        new_prefix = f"staging/releases/plugin/{digest}"
        for path in list(payloads):
            if path.startswith(old_prefix + "/"):
                payloads[new_prefix + path[len(old_prefix):]] = payloads.pop(path)
        release["bundle_prefix"] = new_prefix
        release["digest"] = digest

    baseline["source"] = {
        "core_commit": product.R5_DURABILITY_BASELINE_CORE_COMMIT,
        "core_tree": product.R5_DURABILITY_BASELINE_CORE_TREE,
        "deploy_commit": product.R5_DURABILITY_BASELINE_DEPLOY_COMMIT,
        "deploy_parent": product.R5_DURABILITY_BASELINE_DEPLOY_PARENT,
        "deploy_tree": product.R5_DURABILITY_BASELINE_DEPLOY_TREE,
    }
    rekey_plugin(baseline, product.R5_DURABILITY_BASELINE_PLUGIN_RELEASE)
    baseline_config = baseline["files"][product.R5_CONFIG_PATH]
    baseline_config["payload_sha256"] = product.R5_DURABILITY_BASELINE_CONFIG_SHA256
    baseline["controller"]["config_sha256"] = (
        product.R5_DURABILITY_BASELINE_CONFIG_SHA256
    )

    target = json.loads(module._canonical(baseline))
    rekey_plugin(target, product.R5_DURABILITY_TARGET_PLUGIN_RELEASE)
    target_payload = product.r5_durability_target_config()
    target_config = target["files"][product.R5_CONFIG_PATH]
    target_config["payload_b64"] = base64.b64encode(target_payload).decode("ascii")
    target_config["payload_sha256"] = sha256(target_payload).hexdigest()
    target["controller"]["config_sha256"] = sha256(target_payload).hexdigest()
    target["source"] = {
        "core_commit": product.ACCEPTED_CORE_COMMIT,
        "core_tree": product.ACCEPTED_CORE_TREE,
        "deploy_commit": "d" * 40,
        "deploy_parent": module.CUTOVER_ACCEPTED_DEPLOY_PARENT,
        "deploy_tree": "e" * 40,
    }
    return baseline, target, payloads


class TelegramR5ControllerReleaseTests(unittest.TestCase):
    def candidate_repositories(self, root: Path) -> tuple[Path, Path, str, str]:
        deploy = root / "deploy"
        core = root / "core"
        deploy_commit = run(["git", "-C", ROOT.as_posix(), "rev-parse", "HEAD"])
        run([
            "git", "-c", f"safe.directory={ROOT.as_posix()}", "clone", "--quiet", "--no-checkout",
            ROOT.as_posix(), deploy.as_posix(),
        ])
        run([
            "git", "-c", f"safe.directory={CORE.as_posix()}", "clone", "--quiet",
            CORE.as_posix(), core.as_posix(),
        ])
        run(["git", "checkout", "--quiet", "--detach", deploy_commit], cwd=deploy)
        self.assertEqual(run(["git", "status", "--porcelain=v1"], cwd=deploy), "")
        self.assertEqual(run(["git", "rev-parse", "HEAD^"], cwd=deploy), ACCEPTED_PARENT)
        self.assertEqual(run(["git", "rev-parse", "HEAD"], cwd=core), CORE_COMMIT)
        return deploy, core, deploy_commit, CORE_COMMIT

    def build(self, root: Path, seed: int = 19001) -> tuple[Path, str, dict[str, object]]:
        deploy, core, deploy_commit, core_commit = self.candidate_repositories(root)
        output = root / "controller-releases"
        authority, payloads = fixed_build_output(seed)
        authority["source"]["deploy_commit"] = deploy_commit
        authority["source"]["deploy_tree"] = run(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=deploy
        )
        with mock.patch.object(
            module,
            "_orchestrate_product",
            return_value=(authority, payloads),
        ):
            digest = module.build_release(
                deploy,
                core,
                root / "astrbot",
                root / product.ACCEPTED_RUNTIME_BASE,
                root / "base.oci.tar",
                output,
                deploy_commit,
                core_commit,
            )
        expected = module.expected_controller_authority(output, digest)
        return output, digest, expected

    def maintenance_build(
        self, root: Path, seed: int = 19001
    ) -> tuple[Path, str, dict[str, object]]:
        deploy, core, deploy_commit, core_commit = self.candidate_repositories(root)
        output = root / "controller-releases"
        baseline, target, payloads = maintenance_build_output(seed)
        target["source"]["deploy_commit"] = deploy_commit
        target["source"]["deploy_tree"] = run(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=deploy
        )
        with mock.patch.object(
            module,
            "_orchestrate_r5_durability",
            return_value=(target, payloads, baseline),
        ):
            digest = module.build_release(
                deploy,
                core,
                root / "astrbot",
                root / product.ACCEPTED_RUNTIME_BASE,
                root / "base.oci.tar",
                output,
                deploy_commit,
                core_commit,
                baseline_controller_root=root / product.R5_DURABILITY_BASELINE_CONTROLLER_RELEASE,
            )
        return output, digest, module.expected_controller_authority(output, digest)

    def test_sealed_fixed_closure_and_isolated_target_route_for_dual_seeds(self) -> None:
        for seed in (19001, 19002):
            with tempfile.TemporaryDirectory() as temporary:
                output, digest, expected = self.build(Path(temporary), seed)
                self.assertTrue(module.verify_release(output, digest, expected))
                release = output / digest
                manifest = json.loads((release / "MANIFEST.json").read_bytes())
                destinations = {row["destination"] for row in manifest["files"]}
                self.assertTrue({
                    "activate_p07_owner_private_memory_v1.py",
                    "p07_owner_private_memory_production_plan.py",
                    "phase_f_owner_adjudicated_one_time_cutover_v1.py",
                    "telegram_r5_boot_resume.py",
                }.issubset(destinations))
                command = next(
                    row
                    for row in manifest["files"]
                    if row["destination"]
                    == "phase_f_owner_adjudicated_one_time_cutover_v1.py"
                )
                self.assertEqual(
                    command["source"],
                    "scripts/phase_f_owner_adjudicated_one_time_cutover_v1.py",
                )
                self.assertEqual(command["mode"], "100755")
                self.assertEqual(command["installed_mode"], "0555")
                self.assertIn(
                    command,
                    manifest["source_receipt"]["deploy_members"],
                )
                for forbidden in (
                    "activate_p07_d_generation13_v1.py",
                    "p07_d_activation_transaction.py",
                    "p07_owner_private_memory_transactional_controller.py",
                    "p07_owner_private_memory_transactional_runtime.py",
                    "activation_transaction_substrate_v1.py",
                ):
                    self.assertNotIn(forbidden, destinations)
                self.assertEqual(manifest["owner_chain"], list(module.boot.FIXED_OWNER_CHAIN))
                self.assertEqual(manifest["core_import_closure"]["files"], [])
                self.assertEqual(
                    manifest["fixed_product_authority"]["source"]["deploy_parent"],
                    ACCEPTED_PARENT,
                )
                self.assertIn(
                    "activate_p07_owner_private_memory_v1.run_checkpointed_stage",
                    manifest["owner_chain"],
                )
                self.assertNotIn(
                    "activate_p07_owner_private_memory_v1.run_fixed_product_activation",
                    manifest["owner_chain"],
                )
                program = textwrap.dedent(
                    f"""
                    import importlib.util, pathlib, sys
                    release = pathlib.Path({release.as_posix()!r})
                    sys.path.insert(0, release.as_posix())
                    spec = importlib.util.spec_from_file_location('sealed_builder', release / 'source-authority/build_telegram_r5_controller_release_v1.py')
                    selected = importlib.util.module_from_spec(spec)
                    sys.modules[spec.name] = selected
                    spec.loader.exec_module(selected)
                    verified = selected.verified_controller_authority(release.parent, release.name)
                    activation_spec = importlib.util.spec_from_file_location('sealed_activation', release / 'activate_p07_owner_private_memory_v1.py')
                    activation = importlib.util.module_from_spec(activation_spec)
                    sys.modules[activation_spec.name] = activation
                    activation_spec.loader.exec_module(activation)
                    installer_verified = activation._verified_controller_authority(release)
                    expected = selected.expected_controller_authority(release.parent, release.name)
                    valid = (
                        selected.verify_release(release.parent, release.name, expected)
                        and installer_verified == verified
                        and verified['source']['deploy_parent'] == {ACCEPTED_PARENT!r}
                        and (release / 'phase_f_owner_adjudicated_one_time_cutover_v1.py').is_file()
                    )
                    raise SystemExit(0 if valid else 1)
                    """
                )
                completed = subprocess.run(
                    [sys.executable, "-I", "-B", "-c", program],
                    check=False,
                    capture_output=True,
                    text=True,
                    env={"PYTHONDONTWRITEBYTECODE": "1"},
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_r5_durability_release_is_deterministic_and_cold_resume_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_output, first_digest, first_expected = self.maintenance_build(
                Path(first)
            )
            second_output, second_digest, second_expected = self.maintenance_build(
                Path(second)
            )
            self.assertEqual(first_digest, second_digest)
            self.assertEqual(first_expected, second_expected)
            release = first_output / first_digest
            manifest = json.loads((release / "MANIFEST.json").read_bytes())
            authority = manifest["fixed_product_authority"]
            self.assertEqual(
                authority["releases"]["plugin"]["digest"],
                product.R5_DURABILITY_TARGET_PLUGIN_RELEASE,
            )
            config = authority["files"][product.R5_CONFIG_PATH]
            self.assertEqual(
                base64.b64decode(config["payload_b64"], validate=True),
                product.r5_durability_target_config(),
            )
            program = textwrap.dedent(
                f"""
                import importlib.util, pathlib, sys
                release = pathlib.Path({release.as_posix()!r})
                sys.path[:] = [release.as_posix(), *[p for p in sys.path if 'site-packages' not in p and 'myuna' not in p]]
                spec = importlib.util.spec_from_file_location('sealed_builder', release / 'source-authority/build_telegram_r5_controller_release_v1.py')
                selected = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = selected
                spec.loader.exec_module(selected)
                verified = selected.verified_controller_authority(release.parent, release.name)
                expected = selected.expected_controller_authority(release.parent, release.name)
                valid = (
                    selected.verify_release(release.parent, release.name, expected)
                    and verified['releases']['plugin']['digest'] == {product.R5_DURABILITY_TARGET_PLUGIN_RELEASE!r}
                    and verified['source']['deploy_parent'] == {ACCEPTED_PARENT!r}
                )
                raise SystemExit(0 if valid else 1)
                """
            )
            completed = subprocess.run(
                [sys.executable, "-I", "-B", "-c", program],
                check=False,
                capture_output=True,
                text=True,
                env={"PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(any(release.rglob("*.pyc")))
            self.assertFalse(any(path.name == "__pycache__" for path in release.rglob("*")))

    def test_real_r5_durability_orchestrator_reopens_accepted_builders(self) -> None:
        self.assertEqual(
            module._R5_DURABILITY_HYBRID_BUILDER_BLOB,
            "b2075d024ad98ab5bec93ebfec29187fa183d14d",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            deploy, core, deploy_commit, core_commit = self.candidate_repositories(root)
            baseline_root = (
                Path("/opt/myuna/telegram-r5/releases")
                / product.R5_DURABILITY_BASELINE_CONTROLLER_RELEASE
            )
            authority, payloads, baseline = module._orchestrate_r5_durability(
                deploy,
                core,
                baseline_root,
                deploy_commit,
                core_commit,
                root / "scratch",
            )
            self.assertEqual(
                authority["releases"]["plugin"]["digest"],
                product.R5_DURABILITY_TARGET_PLUGIN_RELEASE,
            )
            self.assertEqual(
                base64.b64decode(
                    authority["files"][product.R5_CONFIG_PATH]["payload_b64"],
                    validate=True,
                ),
                product.r5_durability_target_config(),
            )
            self.assertEqual(
                baseline["releases"]["plugin"]["digest"],
                product.R5_DURABILITY_BASELINE_PLUGIN_RELEASE,
            )
            self.assertTrue(
                any(
                    path.startswith(
                        authority["releases"]["plugin"]["bundle_prefix"] + "/"
                    )
                    for path in payloads
                )
            )

    def test_exact_installed_old_and_current_reopen_through_one_finite_seam(self) -> None:
        releases = Path("/opt/myuna/telegram-r5/releases")
        cases = (
            (
                product.R5_DURABILITY_BASELINE_CONTROLLER_RELEASE,
                product.R5_DURABILITY_BASELINE_DEPLOY_COMMIT,
                product.R5_DURABILITY_BASELINE_DEPLOY_PARENT,
                product.R5_DURABILITY_BASELINE_DEPLOY_TREE,
            ),
            (
                product.ATTEMPT5_PRODUCT_CONTROLLER_RELEASE,
                product.ATTEMPT5_PRODUCT_DEPLOY_COMMIT,
                product.ATTEMPT5_PRODUCT_DEPLOY_PARENT,
                product.ATTEMPT5_PRODUCT_DEPLOY_TREE,
            ),
        )
        for digest, commit, parent, tree in cases:
            with self.subTest(digest=digest):
                document, authority = module._fixed_historical_authority(releases / digest)
                self.assertEqual(document["deploy_commit"], commit)
                self.assertEqual(document["deploy_parent"], parent)
                self.assertEqual(document["deploy_tree"], tree)
                self.assertEqual(authority, document["fixed_product_authority"])
                self.assertEqual(authority["source"]["deploy_commit"], commit)
                self.assertEqual(authority["source"]["deploy_parent"], parent)
                self.assertEqual(authority["source"]["deploy_tree"], tree)
        old_document, old_authority = module._fixed_historical_authority(
            releases / product.R5_DURABILITY_BASELINE_CONTROLLER_RELEASE
        )
        self.assertEqual(
            old_authority["controller"]["config_sha256"],
            product.R5_DURABILITY_BASELINE_CONFIG_SHA256,
        )
        self.assertEqual(
            old_authority["releases"]["plugin"]["digest"],
            product.R5_DURABILITY_BASELINE_PLUGIN_RELEASE,
        )
        self.assertEqual(old_document["fixed_product_authority"], old_authority)
        with tempfile.TemporaryDirectory() as temporary:
            substituted = Path(temporary) / product.R5_DURABILITY_BASELINE_CONTROLLER_RELEASE
            substituted.mkdir(mode=0o555)
            with self.assertRaises(module.TelegramR5ControllerReleaseRejected):
                module._fixed_historical_authority(substituted)
        with self.assertRaises(module.TelegramR5ControllerReleaseRejected):
            module._fixed_historical_authority(releases / ("f" * 64))

    def test_finite_historical_seam_rejects_source_authority_and_environment_substitutions(self) -> None:
        release = (
            Path("/opt/myuna/telegram-r5/releases")
            / product.ATTEMPT5_PRODUCT_CONTROLLER_RELEASE
        )
        document, authority = module._fixed_historical_authority(release)
        wrong_source = json.loads(module._canonical(document))
        wrong_source["deploy_parent"] = "f" * 40
        with mock.patch.object(
            module.boot, "_controller_manifest", return_value=(wrong_source, b"")
        ):
            with self.assertRaisesRegex(
                module.TelegramR5ControllerReleaseRejected,
                "fixed_historical_source_rejected",
            ):
                module._fixed_historical_authority(release)

        for field in ("files", "source", "controller"):
            substituted = json.loads(module._canonical(authority))
            substituted[field] = {}
            with self.subTest(field=field), mock.patch.object(
                module.boot,
                "verify_fixed_controller_release",
                return_value={"release_sha256": release.name, **substituted},
            ):
                with self.assertRaisesRegex(
                    module.TelegramR5ControllerReleaseRejected,
                    "fixed_historical_authority_rejected",
                ):
                    module._fixed_historical_authority(release)

        with mock.patch.object(
            module.boot,
            "verify_fixed_controller_release",
            side_effect=module.boot.ResumeRejected("environment_rejected"),
        ):
            with self.assertRaisesRegex(
                module.TelegramR5ControllerReleaseRejected,
                "fixed_historical_release_rejected",
            ):
                module._fixed_historical_authority(release)

    def test_member_environment_and_complete_set_hostility_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output, digest, expected = self.build(Path(temporary))
            wrong = dict(expected)
            wrong["controller_config_sha256"] = "f" * 64
            self.assertFalse(module.verify_release(output, digest, wrong))
            release = output / digest
            member = release / "telegram_r5_boot_resume.py"
            original = member.read_bytes()
            os.chmod(member, 0o755)
            member.write_bytes(original + b"# substituted\n")
            os.chmod(member, 0o555)
            self.assertFalse(module.verify_release(output, digest, expected))
            os.chmod(member, 0o755)
            member.write_bytes(original)
            os.chmod(member, 0o555)
            os.chmod(release, 0o755)
            extra = release / "unexpected-member"
            extra.write_bytes(b"unexpected\n")
            os.chmod(extra, 0o444)
            os.chmod(release, 0o555)
            self.assertFalse(module.verify_release(output, digest, expected))

    def test_builder_to_stateless_cutover_guard_unit_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, digest, expected = self.build(root)
            release = output / digest
            selection = module.controller_selection_tuple(output, digest)
            program = textwrap.dedent(
                f"""
                import importlib.util, pathlib, sys
                release = pathlib.Path({release.as_posix()!r})
                sys.path.insert(0, release.as_posix())
                spec = importlib.util.spec_from_file_location('sealed_cutover', release / 'phase_f_owner_adjudicated_one_time_cutover_v1.py')
                selected = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = selected
                spec.loader.exec_module(selected)
                expected = {expected!r}
                selection = selected.ReleaseSelection(**{selection!r})
                text = selected._render_unit(release, expected, guard=True, selection=selection).decode('utf-8')
                valid = (
                    f'ExecStart=/usr/bin/python3 {{release}}/phase_f_owner_adjudicated_one_time_cutover_v1.py preflight' in text
                    and f'--release-sha256 {{release.name}}' in text
                    and '--reviewed-deploy-commit' in text
                    and '--public-package-sha256' in text
                    and f'ExecStart=/usr/bin/python3 {{release}}/telegram_r5_boot_resume.py' not in text
                    and '@CONTROLLER_' not in text
                )
                raise SystemExit(0 if valid else 1)
                """
            )
            completed = subprocess.run(
                [sys.executable, "-I", "-B", "-c", program],
                check=False,
                capture_output=True,
                text=True,
                env={"PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_selection_tuple_is_exact_and_public_package_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output, digest, _expected = self.build(Path(temporary))
            selection = module.controller_selection_tuple(output, digest)
            release = output / digest
            manifest = json.loads((release / "MANIFEST.json").read_bytes())
            self.assertEqual(selection["release_sha256"], digest)
            self.assertEqual(selection["deploy_commit"], manifest["deploy_commit"])
            self.assertEqual(selection["deploy_tree"], manifest["deploy_tree"])
            self.assertEqual(
                selection["public_package_sha256"],
                sha256((release / "CORRESPONDING_SOURCE.json").read_bytes()).hexdigest(),
            )
            self.assertEqual(
                selection["public_package_sha256"],
                manifest["paired_source_package_sha256"],
            )

    def test_builder_projects_one_dynamic_target_from_verified_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output, digest, _expected = self.build(Path(temporary), 19003)
            authority = module.verified_controller_authority(output, digest)
            old = module.boot.PhaseFContainerProjection(
                container_id="1" * 64,
                name=module.boot.CONTAINER,
                image="myuna/astrbot-phase-f-deterministic@sha256:" + "2" * 64,
                status="exited",
                health="unhealthy",
                restart_policy="no",
                restart_maximum_retry_count=0,
                project=module.boot.COMPOSE_PROJECT,
                service=module.boot.COMPOSE_SERVICE,
                plan_digest=product.ATTEMPT5_PRODUCT_ENTRY_PLAN_SHA256,
                target_config_digest="3" * 64,
                user=product.TARGET_USER,
                command_digest="4" * 64,
                host_config_digest="5" * 64,
                mounts_digest="6" * 64,
                networks_digest="7" * 64,
                network_names=(module.boot.NETWORK,),
            )
            network = module.boot.PhaseFNetworkProjection(
                network_id="8" * 64,
                name=module.boot.NETWORK,
                driver="bridge",
                internal=False,
                attachable=False,
                ingress=False,
                enable_ipv6=False,
                options_digest="9" * 64,
                labels_digest="a" * 64,
                ipam_digest="b" * 64,
                member_container_ids=(),
            )
            target = module.verified_target_container_authority(
                authority,
                old,
                network,
            )
            archived = replace(old, name=target.archive_name)
            self.assertTrue(target.archive_name.startswith(module.boot.ARCHIVE_PREFIX))
            self.assertEqual(target.effect["archive_container_id"], old.container_id)
            self.assertEqual(
                target.effect["archive_projection_sha256"],
                module.boot.phase_f_container_identity_sha256(archived),
            )
            self.assertEqual(
                target.effect["network_projection_sha256"],
                module.boot.phase_f_network_identity_sha256(network),
            )
            self.assertNotIn("container_id", target.__dataclass_fields__)

            with self.assertRaises(module.TelegramR5ControllerReleaseRejected):
                module.verified_target_container_authority(
                    authority,
                    replace(
                        old,
                        name=module.boot.ARCHIVE_PREFIX + "c" * 16,
                    ),
                    network,
                )
            with self.assertRaises(module.TelegramR5ControllerReleaseRejected):
                module.verified_target_container_authority(
                    authority,
                    old,
                    replace(
                        network,
                        member_container_ids=(old.container_id,),
                    ),
                )

    def test_only_exact_direct_child_source_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            deploy, _core, deploy_commit, _core_commit = self.candidate_repositories(root)
            self.assertEqual(
                module._validate_repository(
                    deploy,
                    deploy_commit,
                    parent=ACCEPTED_PARENT,
                ),
                run(["git", "rev-parse", "HEAD^{tree}"], cwd=deploy),
            )
            environment = {
                **os.environ,
                "GIT_AUTHOR_NAME": "Generated Synthetic",
                "GIT_AUTHOR_EMAIL": "generated@example.invalid",
                "GIT_COMMITTER_NAME": "Generated Synthetic",
                "GIT_COMMITTER_EMAIL": "generated@example.invalid",
            }
            subprocess.run(
                ["git", "commit", "--allow-empty", "--quiet", "-m", "grandchild"],
                cwd=deploy,
                check=True,
                env=environment,
            )
            with self.assertRaises(module.TelegramR5ControllerReleaseRejected):
                module._validate_repository(
                    deploy,
                    run(["git", "rev-parse", "HEAD"], cwd=deploy),
                    parent=ACCEPTED_PARENT,
                )
            self.assertEqual(run(["git", "rev-parse", "HEAD^^"], cwd=deploy), ACCEPTED_PARENT)

            run(["git", "checkout", "--quiet", "--detach", ACCEPTED_PARENT], cwd=deploy)
            subprocess.run(
                ["git", "commit", "--allow-empty", "--quiet", "-m", "sibling"],
                cwd=deploy,
                check=True,
                env=environment,
            )
            with self.assertRaises(module.TelegramR5ControllerReleaseRejected):
                module._validate_repository(
                    deploy,
                    deploy_commit,
                    parent=ACCEPTED_PARENT,
                )

            run(["git", "checkout", "--quiet", "--detach", deploy_commit], cwd=deploy)
            with self.assertRaises(module.TelegramR5ControllerReleaseRejected):
                module._validate_repository(
                    deploy,
                    deploy_commit,
                    parent="f" * 40,
                )

    def test_builder_source_has_no_retired_target_owner_import(self) -> None:
        text = MODULE_PATH.read_text("utf-8")
        self.assertNotIn("from p07_d_generation13_release_set", text)
        self.assertNotIn("import activation_transaction_substrate", text)
        self.assertNotIn("fixed_product_authority", str(module.build_release.__signature__) if hasattr(module.build_release, "__signature__") else "")
        self.assertNotIn("controller_config_sha256", module.build_release.__annotations__)
        for required in (
            "paired.build_core",
            "paired.build_runtime",
            "runtime_artifact.verify_candidate",
            "gateway.verify_release",
            "gateway.verify_deterministic_astrbot_archive",
        ):
            self.assertIn(required, text)

    def test_cutover_parent_override_is_exact_and_always_restored(self) -> None:
        original = product.ACCEPTED_DEPLOY_PARENT
        self.assertEqual(module.CUTOVER_ACCEPTED_DEPLOY_PARENT, ACCEPTED_PARENT)
        with module._source_parent_contract(ACCEPTED_PARENT):
            self.assertEqual(product.ACCEPTED_DEPLOY_PARENT, ACCEPTED_PARENT)
        self.assertEqual(product.ACCEPTED_DEPLOY_PARENT, original)
        with self.assertRaises(module.TelegramR5ControllerReleaseRejected):
            with module._source_parent_contract("f" * 40):
                self.fail("unreachable")
        self.assertEqual(product.ACCEPTED_DEPLOY_PARENT, original)

    def test_runtime_base_projection_excludes_only_validated_bytecode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime-base"
            root.mkdir(mode=0o755)
            ordinary = root / "runtime.py"
            ordinary.write_bytes(b"ordinary-v1\n")
            ordinary.chmod(0o644)
            cache = root / "pkg" / "__pycache__"
            cache.mkdir(parents=True, mode=0o755)
            (cache / "runtime.cpython-311.pyc").write_bytes(b"bytecode-v1")
            top_level_bytecode = root / "generated.pyo"
            top_level_bytecode.write_bytes(b"optimized-v1")
            baseline = module._input_tree_member_set(root)

            (cache / "runtime.cpython-311.pyc").write_bytes(b"bytecode-v2")
            (cache / "nested").mkdir()
            (cache / "nested" / "ordinary-name").write_bytes(b"generated")
            top_level_bytecode.unlink()
            (root / "replacement.pyc").write_bytes(b"replacement")
            self.assertEqual(module._input_tree_member_set(root), baseline)

            ordinary.write_bytes(b"ordinary-v2\n")
            self.assertNotEqual(module._input_tree_member_set(root), baseline)
            ordinary.write_bytes(b"ordinary-v1\n")
            ordinary.chmod(0o600)
            self.assertNotEqual(module._input_tree_member_set(root), baseline)
            ordinary.chmod(0o644)
            renamed = root / "runtime-renamed.py"
            ordinary.rename(renamed)
            self.assertNotEqual(module._input_tree_member_set(root), baseline)
            renamed.rename(ordinary)
            ordinary.unlink()
            self.assertNotEqual(module._input_tree_member_set(root), baseline)
            ordinary.write_bytes(b"ordinary-v1\n")
            ordinary.chmod(0o644)
            (root / "pkg").chmod(0o700)
            self.assertNotEqual(module._input_tree_member_set(root), baseline)
            (root / "pkg").chmod(0o755)
            binding = root / "cache.pyc.txt"
            binding.write_bytes(b"binding")
            self.assertNotEqual(module._input_tree_member_set(root), baseline)
            binding.unlink()
            binding = root / "__pycache__-ordinary"
            binding.write_bytes(b"binding")
            self.assertNotEqual(module._input_tree_member_set(root), baseline)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime-base"
            comparison = Path(temporary) / "comparison"
            root.mkdir(mode=0o755)
            comparison.mkdir(mode=0o755)
            (root / "__pycache__").write_bytes(b"ordinary-file")
            self.assertNotEqual(
                module._input_tree_member_set(root),
                module._input_tree_member_set(comparison),
            )

    def test_runtime_base_projection_rejects_invalid_members_before_exclusion(self) -> None:
        constructors = {
            "symlink": lambda root: (root / "__pycache__" / "bad.pyc").symlink_to(root / "target"),
            "fifo": lambda root: os.mkfifo(root / "bad.pyc"),
            "hardlink": lambda root: os.link(root / "source", root / "hardlinked.pyc"),
        }
        for label, construct in constructors.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "runtime-base"
                root.mkdir()
                (root / "__pycache__").mkdir()
                (root / "target").write_bytes(b"target")
                (root / "source").write_bytes(b"source")
                construct(root)
                with self.assertRaises(module.TelegramR5ControllerReleaseRejected):
                    module._input_tree_member_set(root)


if __name__ == "__main__":
    unittest.main()
