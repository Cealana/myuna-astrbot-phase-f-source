#!/usr/bin/env python3
from __future__ import annotations

import base64
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CORE = Path("/srv/myuna/repos/core")
sys.path.insert(0, (ROOT / "scripts").as_posix())
ACCEPTED_PARENT = "ea2ae1e3e3f913fc1f227fdba61bc90cf5a8bd5b"
CORE_COMMIT = "0d6885192307a75f6948e0085c3ca2c3c9f66676"
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
            "deploy_parent": product.ACCEPTED_DEPLOY_PARENT,
            "deploy_tree": "1" * 40,
        },
    }
    return authority, payloads


class TelegramR5ControllerReleaseTests(unittest.TestCase):
    def candidate_repositories(self, root: Path) -> tuple[Path, Path, str, str]:
        deploy = root / "deploy"
        core = root / "core"
        run([
            "git", "-c", f"safe.directory={ROOT.as_posix()}", "clone", "--quiet",
            ROOT.as_posix(), deploy.as_posix(),
        ])
        run([
            "git", "-c", f"safe.directory={CORE.as_posix()}", "clone", "--quiet",
            CORE.as_posix(), core.as_posix(),
        ])
        changed = run(["git", "-C", ROOT.as_posix(), "diff", "--name-only"]).splitlines()
        self.assertEqual(
            set(changed),
            {
                "scripts/activate_p07_owner_private_memory_v1.py",
                "scripts/p07_owner_private_memory_production_plan.py",
                "scripts/telegram_r5_boot_resume.py",
                "tests/test_p07_owner_private_memory_activation_v1.py",
                "tests/test_p07_owner_private_memory_production_plan.py",
                "tests/test_telegram_r5_boot_resume.py",
                "tests/test_telegram_r5_controller_release_v1.py",
            },
        )
        for relative in changed:
            target = deploy / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
            os.chmod(target, stat.S_IMODE((ROOT / relative).stat().st_mode))
        run(["git", "add", "--", *changed], cwd=deploy)
        environment = {
            **os.environ,
            "GIT_AUTHOR_NAME": "Generated Synthetic",
            "GIT_AUTHOR_EMAIL": "generated@example.invalid",
            "GIT_COMMITTER_NAME": "Generated Synthetic",
            "GIT_COMMITTER_EMAIL": "generated@example.invalid",
        }
        subprocess.run(
            ["git", "commit", "--quiet", "-m", "generated fixed product source"],
            cwd=deploy,
            check=True,
            env=environment,
        )
        deploy_commit = run(["git", "rev-parse", "HEAD"], cwd=deploy)
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
                    "telegram_r5_boot_resume.py",
                }.issubset(destinations))
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
                    import importlib.util, os, pathlib, sys, types
                    release = pathlib.Path({release.as_posix()!r})
                    sys.path.insert(0, release.as_posix())
                    owner = types.ModuleType('activate_p07_owner_private_memory_v1')
                    owner.fixed_owner_entry = lambda: 75
                    sys.modules[owner.__name__] = owner
                    spec = importlib.util.spec_from_file_location('sealed_boot', release / 'telegram_r5_boot_resume.py')
                    selected = importlib.util.module_from_spec(spec)
                    sys.modules[spec.name] = selected
                    spec.loader.exec_module(selected)
                    os.environ[selected.CONTROLLER_RELEASE_ENV] = {digest!r}
                    os.environ[selected.CONTROLLER_CONFIG_ENV] = {str(expected['controller_config_sha256'])!r}
                    os.environ[selected.CONTROLLER_AUTHORITY_ENV] = {str(expected['controller_static_authority_sha256'])!r}
                    raise SystemExit(0 if selected.main() == 75 else 1)
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

    def test_builder_to_existing_installer_unit_execstart_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, digest, _expected = self.build(root)
            release = output / digest
            installed_root = root / "installed-releases"
            installed_root.mkdir()
            unit = root / "installed-unit.service"
            program = textwrap.dedent(
                f"""
                import pathlib, sys
                release = pathlib.Path({release.as_posix()!r})
                sys.path.insert(0, release.as_posix())
                import activate_p07_owner_private_memory_v1 as owner
                owner.CONTROLLER_RELEASES_ROOT = pathlib.Path({installed_root.as_posix()!r})
                owner.UNIT_PATH = pathlib.Path({unit.as_posix()!r})
                def write(path, payload, mode, uid, gid):
                    path.write_bytes(payload)
                    path.chmod(mode)
                owner._atomic_file = write
                original_observation = owner._file_observation
                def observe(path):
                    row = original_observation(path)
                    row['uid'] = 0
                    row['gid'] = 0
                    return row
                owner._file_observation = observe
                result = owner.install_current_controller_unit()
                installed = owner.CONTROLLER_RELEASES_ROOT / release.name
                text = owner.UNIT_PATH.read_text('utf-8')
                valid = (
                    result['status'] == 'INSTALLED_INACTIVE_NOT_STARTED'
                    and installed.is_dir()
                    and f'ExecStart=/usr/bin/python3 {{installed}}/telegram_r5_boot_resume.py' in text
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

    def test_only_exact_direct_child_source_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            deploy, core, _deploy_commit, core_commit = self.candidate_repositories(root)
            environment = {
                **os.environ,
                "GIT_AUTHOR_NAME": "Generated Synthetic",
                "GIT_AUTHOR_EMAIL": "generated@example.invalid",
                "GIT_COMMITTER_NAME": "Generated Synthetic",
                "GIT_COMMITTER_EMAIL": "generated@example.invalid",
            }
            subprocess.run(
                ["git", "commit", "--allow-empty", "--quiet", "-m", "second child"],
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
