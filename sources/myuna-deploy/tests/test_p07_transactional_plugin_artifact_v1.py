from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

import build_telegram_gateway_release_v1 as gateway_release
import p07_transactional_plugin_artifact_v1 as plugin


HISTORICAL_PLUGIN_RELEASES = (
    "8e3bb318f27db7ebe57a44c6cd88054596ca08cfdfa328493e4c99cdaf3a13b3",
    "0aa958c2575814e3e2abbfe219a6d651f0bb156c45812f9cd39e51d4da512012",
)


class PluginArtifactSourceBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        upstream = Path(__file__).resolve().parents[1]
        paths = {
            source_path
            for source_path, _destination, _mode in gateway_release.COMPONENTS
        } | {plugin.RELEASE_BUILDER_PATH, plugin.CONFIG_RENDERER_PATH}
        for relative in sorted(paths):
            target = self.source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(upstream / relative, target)
            os.chmod(target, 0o644)
        (self.source / ".gitignore").write_text("__pycache__/\n", encoding="ascii")
        self.git("init", "-q")
        self.git("config", "user.name", "Synthetic P07")
        self.git("config", "user.email", "synthetic-p07@example.invalid")
        self.git("add", ".")
        self.git("commit", "-qm", "synthetic plugin source")

    def git(self, *arguments: str) -> str:
        completed = subprocess.run(
            ["/usr/bin/git", "-C", str(self.source), *arguments],
            capture_output=True,
            check=True,
            env={
                "HOME": str(self.root / "home"),
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/usr/sbin",
            },
            text=True,
        )
        return completed.stdout.strip()

    def identities(self) -> tuple[str, str]:
        return self.git("rev-parse", "HEAD"), self.git("rev-parse", "HEAD^{tree}")

    def binding(self) -> dict[str, object]:
        commit, tree = self.identities()
        return plugin.derive_binding(
            self.source, expected_commit=commit, expected_tree=tree
        )

    def candidate(self, output: Path, binding: dict[str, object]) -> Path:
        return output / str(binding["target"]["release_digest"])

    def test_source_derivation_and_a_b_materialization_are_deterministic(self) -> None:
        binding = self.binding()
        first_root = self.root / "a"
        second_root = self.root / "b"
        first = plugin.materialize_source_bound_release(
            source=self.source, output_root=first_root, binding=binding
        )
        second = plugin.materialize_source_bound_release(
            source=self.source, output_root=second_root, binding=binding
        )
        self.assertEqual(first.binding, second.binding)
        self.assertEqual(first.release_digest, second.release_digest)
        for relative in sorted(first.files):
            left = self.candidate(first_root, binding) / relative
            right = self.candidate(second_root, binding) / relative
            self.assertEqual(left.read_bytes(), right.read_bytes())
            self.assertEqual(
                stat.S_IMODE(left.stat().st_mode), stat.S_IMODE(right.stat().st_mode)
            )
        self.assertEqual(
            plugin.binding_projection(binding)["release_digest"],
            first.release_digest,
        )
        with self.assertRaisesRegex(RuntimeError, "output_rejected"):
            plugin.materialize_source_bound_release(
                source=self.source, output_root=first_root, binding=binding
            )

    def test_ignored_residue_does_not_change_tracked_source_identity(self) -> None:
        before = self.binding()
        residue = self.source / plugin.PLUGIN_SOURCE_ROOT / "__pycache__"
        residue.mkdir()
        (residue / "ignored.pyc").write_bytes(b"ignored")
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.assertEqual(self.binding(), before)

    def test_tracked_extra_missing_path_and_source_mode_fail_closed(self) -> None:
        extra = self.source / plugin.PLUGIN_SOURCE_ROOT / "extra.py"
        extra.write_text("x = 1\n", encoding="ascii")
        self.git("add", str(extra.relative_to(self.source)))
        self.git("commit", "-qm", "tracked extra")
        with self.assertRaisesRegex(RuntimeError, "source_inventory_rejected"):
            self.binding()

        self.git("rm", "-q", str(extra.relative_to(self.source)))
        self.git("commit", "-qm", "remove tracked extra")
        selected = self.binding()
        for mutate, gate in (
            (
                lambda value: value["source"]["files"][0].__setitem__(
                    "path", "channels/astrbot-telegram/plugin/myuna_telegram_gateway/other.py"
                ),
                "binding_source_rejected",
            ),
            (
                lambda value: value["source"]["files"][0].__setitem__(
                    "source_mode", "100600"
                ),
                "binding_source_rejected",
            ),
        ):
            drifted = deepcopy(selected)
            mutate(drifted)
            with self.subTest(gate=gate), self.assertRaisesRegex(RuntimeError, gate):
                plugin.validate_binding(drifted)

    def test_structurally_valid_substitute_and_old_releases_are_rejected(self) -> None:
        binding = self.binding()
        exact_root = self.root / "exact"
        plugin.materialize_source_bound_release(
            source=self.source, output_root=exact_root, binding=binding
        )
        exact = self.candidate(exact_root, binding)

        main_path = self.source / plugin.PLUGIN_SOURCE_ROOT / "main.py"
        main_path.write_bytes(main_path.read_bytes() + b"\n")
        self.git("add", str(main_path.relative_to(self.source)))
        self.git("commit", "-qm", "different valid plugin")
        substitute_binding = self.binding()
        substitute_root = self.root / "substitute"
        plugin.materialize_source_bound_release(
            source=self.source,
            output_root=substitute_root,
            binding=substitute_binding,
        )
        substitute = self.candidate(substitute_root, substitute_binding)
        with self.assertRaisesRegex(RuntimeError, "source_binding_rejected"):
            plugin.verify_candidate(substitute, binding)

        for release in HISTORICAL_PLUGIN_RELEASES:
            historical = self.root / release
            historical.mkdir()
            os.chmod(historical, 0o555)
            with self.subTest(release=release), self.assertRaisesRegex(
                RuntimeError, "source_binding_rejected"
            ):
                plugin.verify_candidate(historical.resolve(), binding)
        self.assertEqual(plugin.verify_candidate(exact.resolve(), binding).binding, binding)

    def test_candidate_bytes_mode_manifest_inventory_and_links_fail_closed(self) -> None:
        cases = (
            "bytes",
            "mode",
            "manifest",
            "extra",
            "fifo",
            "symlink",
            "hardlink",
        )
        for case in cases:
            with self.subTest(case=case):
                binding = self.binding()
                output = self.root / f"case-{case}"
                plugin.materialize_source_bound_release(
                    source=self.source, output_root=output, binding=binding
                )
                candidate = self.candidate(output, binding)
                first = candidate / str(binding["source"]["files"][0]["destination"])
                if case == "bytes":
                    os.chmod(first, 0o644)
                    first.write_bytes(b"x" * first.stat().st_size)
                    os.chmod(first, 0o444)
                elif case == "mode":
                    os.chmod(first, 0o640)
                elif case == "manifest":
                    manifest = output / f"{candidate.name}{plugin.MANIFEST_SUFFIX}"
                    os.chmod(manifest, 0o644)
                    manifest.write_bytes(manifest.read_bytes() + b" ")
                    os.chmod(manifest, 0o444)
                elif case == "extra":
                    os.chmod(candidate, 0o755)
                    extra = candidate / "extra.txt"
                    extra.write_text("extra", encoding="ascii")
                    os.chmod(extra, 0o444)
                elif case == "fifo":
                    os.chmod(candidate, 0o755)
                    os.mkfifo(candidate / "unexpected.fifo", mode=0o444)
                elif case == "symlink":
                    os.chmod(first.parent, 0o755)
                    first.unlink()
                    first.symlink_to(candidate / str(binding["source"]["files"][1]["destination"]))
                else:
                    second = candidate / str(binding["source"]["files"][1]["destination"])
                    os.chmod(first.parent, 0o755)
                    first.unlink()
                    os.link(second, first)
                with self.assertRaisesRegex(RuntimeError, "artifact_"):
                    plugin.verify_candidate(candidate.resolve(), binding)

    def test_binding_rejects_renderer_manifest_rollback_commit_tree_and_digest_drift(self) -> None:
        binding = self.binding()
        mutations = {
            "renderer": lambda value: value["config_rendering"]["renderer"].__setitem__(
                "git_blob", "0" * 40
            ),
            "manifest": lambda value: value["target"].__setitem__(
                "manifest_sha256", "0" * 64
            ),
            "rollback": lambda value: value["rollback"].__setitem__(
                "release_digest", "1" * 64
            ),
            "commit": lambda value: value["source"].__setitem__(
                "deploy_commit", "2" * 40
            ),
            "tree": lambda value: value["source"].__setitem__(
                "deploy_tree", "3" * 40
            ),
            "binding": lambda value: value.__setitem__("binding_digest", "4" * 64),
        }
        for name, mutate in mutations.items():
            drifted = deepcopy(binding)
            mutate(drifted)
            with self.subTest(name=name), self.assertRaisesRegex(
                RuntimeError, "plugin_binding_"
            ):
                plugin.validate_binding(drifted)

    def test_binding_is_ascii_canonical_and_content_free(self) -> None:
        binding = self.binding()
        encoded = plugin.canonical(binding)
        self.assertEqual(json.loads(encoded.decode("ascii")), binding)
        self.assertNotIn(b"provider", encoded.lower())
        self.assertNotIn(b"credential", encoded.lower())
        self.assertNotIn(b"private", encoded.lower())


if __name__ == "__main__":
    unittest.main()
