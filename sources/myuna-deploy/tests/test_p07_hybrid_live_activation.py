from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import tempfile
import unittest


from scripts import activate_p07_hybrid_external_generation_v1 as activation
from scripts import build_p07_hybrid_live_releases_v1 as builder


class P07HybridLiveActivationTests(unittest.TestCase):
    def test_runtime_builder_strips_predecessor_python_bytecode_from_staging(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "runtime/__pycache__"
            cache.mkdir(parents=True)
            (cache / "cached.cpython-312.pyc").write_bytes(b"synthetic-bytecode")
            (root / "runtime/legacy.pyc").write_bytes(b"synthetic-bytecode")
            (root / "runtime/legacy.pyo").write_bytes(b"synthetic-bytecode")
            source = root / "runtime/keep.py"
            source.write_text("VALUE = 1\n", encoding="utf-8")

            builder._strip_python_bytecode_from_staging(root)

            self.assertTrue(source.is_file())
            self.assertFalse(cache.exists())
            self.assertFalse(
                any(path.suffix in {".pyc", ".pyo"} for path in root.rglob("*"))
            )

    def test_core_gate_enables_only_p07_feature(self) -> None:
        self.assertEqual(
            activation.render_core_gate(),
            (
                b"[Service]\n"
                b"Environment=MYUNA_P07_HYBRID_EXTERNAL_ENABLED=true\n"
            ),
        )
        self.assertNotIn(b"MYUNA_DEEPSEEK_MODEL", activation.render_core_gate())

    def test_telegram_dropin_pins_current_only_hybrid_and_bounded_pacing(self) -> None:
        runtime = "a" * 64
        rendered = activation.render_telegram_dropin(runtime).decode("ascii")
        self.assertIn(f"/{runtime}/runtime/telegram_owner_runtime_gateway.py", rendered)
        self.assertNotIn("/srv/myuna/releases/core/", rendered)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", rendered)
        self.assertIn("MYUNA_P07_HYBRID_EXTERNAL_ENABLED=true", rendered)
        self.assertIn("MYUNA_P07_HYBRID_PACING_SECONDS=2", rendered)
        self.assertNotIn("MYUNA_DEEPSEEK_MODEL", rendered)

    def test_runtime_manifest_digest_is_content_addressed(self) -> None:
        unsigned = {
            "schema": builder.RUNTIME_SCHEMA,
            "base_release_digest": "c" * 64,
            "source_deploy_commit": "d" * 40,
            "files": {"runtime/synthetic.py": {"sha256": "e" * 64, "size": 7}},
        }
        first = builder.digest(builder.canonical(unsigned))
        second = builder.digest(builder.canonical(dict(reversed(list(unsigned.items())))))
        self.assertEqual(first, second)

    def test_runtime_manifest_requires_exact_full_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / ("a" * 64)
            core_file = candidate / "runtime/myuna_core/__init__.py"
            entrypoint = candidate / "runtime/telegram_owner_runtime_gateway.py"
            core_file.parent.mkdir(parents=True)
            core_file.write_text("", encoding="utf-8")
            entrypoint.write_text("VALUE = 1\n", encoding="utf-8")
            inventory = builder._tree_file_inventory(candidate)
            manifest = {
                "schema": activation.RUNTIME_SCHEMA,
                "release_digest": candidate.name,
                "source_core_commit": "b" * 40,
                "source_deploy_commit": "c" * 40,
                "files": inventory,
                "core_import_closure": {
                    "algorithm": activation._IMPORT_CLOSURE_ALGORITHM,
                    "roots": ["myuna_core"],
                    "files": ["myuna_core/__init__.py"],
                },
            }
            (candidate / "P07_HYBRID_MANIFEST.json").write_bytes(
                activation.canonical(manifest)
            )
            for path in (candidate, *candidate.rglob("*")):
                path.chmod(0o550 if path.is_dir() else 0o440)
            self.assertEqual(
                activation.validate_runtime(candidate, "b" * 40, "c" * 40),
                candidate.name,
            )

            candidate.chmod(0o750)
            extra = candidate / "runtime/unmanifested.py"
            extra.write_text("VALUE = 2\n", encoding="utf-8")
            extra.chmod(0o440)
            candidate.chmod(0o550)
            with self.assertRaises(activation.ActivationRejected) as captured:
                activation.validate_runtime(candidate, "b" * 40, "c" * 40)
            self.assertEqual(
                captured.exception.code,
                "runtime_import_inventory_rejected",
            )

    def test_owner_private_memory_runtime_profile_is_closed_non_v7(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / ("a" * 64)
            core_file = candidate / "runtime/myuna_core/__init__.py"
            entrypoint = candidate / "runtime/telegram_owner_runtime_gateway.py"
            core_file.parent.mkdir(parents=True)
            core_file.write_text("", encoding="utf-8")
            entrypoint.write_text("VALUE = 1\n", encoding="utf-8")
            manifest = {
                "schema": activation.RUNTIME_SCHEMA,
                "release_digest": candidate.name,
                "source_core_commit": "b" * 40,
                "source_deploy_commit": "c" * 40,
                "files": builder._tree_file_inventory(candidate),
                "core_import_closure": {
                    "algorithm": activation._IMPORT_CLOSURE_ALGORITHM,
                    "roots": ["myuna_core"],
                    "files": ["myuna_core/__init__.py"],
                },
                "runtime_profile": "p07-owner-private-memory-v1",
                "v7_phase1_contract": None,
            }
            manifest_path = candidate / "P07_HYBRID_MANIFEST.json"
            manifest_path.write_bytes(activation.canonical(manifest))
            for path in (candidate, *candidate.rglob("*")):
                path.chmod(0o550 if path.is_dir() else 0o440)
            self.assertEqual(
                activation.validate_runtime(candidate, "b" * 40, "c" * 40),
                candidate.name,
            )

            candidate.chmod(0o750)
            manifest["v7_phase1_contract"] = {}
            manifest_path.chmod(0o640)
            manifest_path.write_bytes(activation.canonical(manifest))
            manifest_path.chmod(0o440)
            candidate.chmod(0o550)
            with self.assertRaises(activation.ActivationRejected) as captured:
                activation.validate_runtime(candidate, "b" * 40, "c" * 40)
            self.assertEqual(captured.exception.code, "runtime_profile_rejected")

    def test_runtime_core_closure_covers_package_and_conditional_imports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            core = Path(temporary)
            package = core / "src/myuna_core"
            external = package / "external_context"
            external.mkdir(parents=True)
            sources = {
                package / "__init__.py": "",
                package / "authenticated_conversation.py": "",
                package / "identity.py": "",
                package / "channel_gateway.py": (
                    "if False:\n"
                    "    import myuna_core.conditional_local\n"
                    "try:\n"
                    "    from myuna_core import optional_local\n"
                    "except ImportError:\n"
                    "    pass\n"
                    "def load():\n"
                    "    import myuna_core.function_local\n"
                ),
                package / "conditional_local.py": "",
                package / "optional_local.py": "",
                package / "function_local.py": "",
                external / "__init__.py": (
                    "from .projection import Projection\n"
                    "from .runtime import Runtime\n"
                    "from .summary import Summary\n"
                ),
                external / "contracts.py": "",
                external / "lifecycle_v3.py": "",
                external / "policy_overlay.py": "",
                external / "release_set.py": "",
                external / "safety.py": "",
                external / "projection.py": "class Projection: pass\n",
                external / "runtime.py": "class Runtime: pass\n",
                external / "summary.py": "class Summary: pass\n",
            }
            for path, payload in sources.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(payload, encoding="utf-8")
            closure = builder.runtime_core_import_closure(core)
            for expected in (
                "myuna_core/conditional_local.py",
                "myuna_core/optional_local.py",
                "myuna_core/function_local.py",
                "myuna_core/external_context/projection.py",
                "myuna_core/external_context/runtime.py",
                "myuna_core/external_context/summary.py",
            ):
                self.assertIn(expected, closure)

            legacy = (
                "myuna_core/__init__.py",
                "myuna_core/authenticated_conversation.py",
                "myuna_core/channel_gateway.py",
                "myuna_core/identity.py",
                "myuna_core/external_context/__init__.py",
                "myuna_core/external_context/contracts.py",
                "myuna_core/external_context/safety.py",
            )
            with self.assertRaises(builder.BuildRejected) as captured:
                builder.validate_declared_runtime_core_files(core, legacy)
            self.assertEqual(captured.exception.code, "runtime_import_closure_rejected")

            (package / "channel_gateway.py").write_text(
                "if False:\n"
                "    import myuna_core.providers.credentials\n",
                encoding="utf-8",
            )
            provider = package / "providers"
            provider.mkdir()
            (provider / "__init__.py").write_text("", encoding="utf-8")
            (provider / "credentials.py").write_text("", encoding="utf-8")
            with self.assertRaises(builder.BuildRejected) as forbidden:
                builder.runtime_core_import_closure(core)
            self.assertEqual(forbidden.exception.code, "runtime_import_scope_rejected")

    def _runtime_smoke_fixture(
        self,
        root: Path,
        *,
        include_projection: bool,
        entrypoint: str = "VALUE = 1\n",
    ) -> Path:
        runtime = root / "runtime"
        external = runtime / "myuna_core/external_context"
        external.mkdir(parents=True)
        (runtime / "myuna_core/__init__.py").write_text("", encoding="utf-8")
        (external / "__init__.py").write_text(
            "from .projection import Projection\n",
            encoding="utf-8",
        )
        if include_projection:
            (external / "projection.py").write_text(
                "class Projection: pass\n",
                encoding="utf-8",
            )
        (runtime / "telegram_owner_runtime_gateway.py").write_text(
            entrypoint,
            encoding="utf-8",
        )
        (root / "P07_HYBRID_MANIFEST.json").write_text(
            '{"schema":"synthetic-legacy"}\n',
            encoding="ascii",
        )
        for path in (root, *root.rglob("*")):
            path.chmod(0o550 if path.is_dir() else 0o440)
        return root

    @unittest.skipUnless(os.geteuid() == 0, "exact service-identity smoke requires root")
    def test_runtime_startup_smoke_reproduces_old_failure_and_accepts_closure(self) -> None:
        pwd.getpwnam(activation.TELEGRAM_RUNTIME_USER)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old = self._runtime_smoke_fixture(
                root / "old",
                include_projection=False,
            )
            with self.assertRaises(activation.ActivationRejected) as captured:
                activation.verify_runtime_startup_smoke(old)
            self.assertEqual(captured.exception.code, "runtime_startup_import_rejected")
            self.assertEqual(
                activation.failure_gate_code(captured.exception),
                "import_closure",
            )

            new = self._runtime_smoke_fixture(
                root / "new",
                include_projection=True,
            )
            self.assertEqual(
                activation._runtime_smoke_modules(new)[0],
                "telegram_owner_runtime_gateway",
            )
            activation.verify_runtime_startup_smoke(new)
            self.assertFalse(any(path.suffix == ".pyc" for path in new.rglob("*")))
            self.assertFalse(any(path.name == "__pycache__" for path in new.rglob("*")))

    @unittest.skipUnless(os.geteuid() == 0, "exact service-identity smoke requires root")
    def test_runtime_startup_smoke_classifies_read_only_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidate = self._runtime_smoke_fixture(
                Path(temporary) / "candidate",
                include_projection=True,
                entrypoint="raise OSError(30, 'synthetic')\n",
            )
            with self.assertRaises(activation.ActivationRejected) as captured:
                activation.verify_runtime_startup_smoke(candidate)
            self.assertEqual(captured.exception.code, "runtime_startup_permission_rejected")
            self.assertEqual(
                activation.failure_gate_code(captured.exception),
                "permission_read_only_bytecode",
            )

    def test_failure_projection_is_content_free_and_categorized(self) -> None:
        cases = {
            "runtime_import_closure_rejected": "import_closure",
            "runtime_startup_permission_rejected": "permission_read_only_bytecode",
            "credential_category_rejected": "credential_category",
            "runtime_startup_other_rejected": "other_startup",
        }
        for code, expected in cases.items():
            projection = activation.failure_projection(activation.ActivationRejected(code))
            self.assertEqual(projection["failure_gate"], expected)
            self.assertEqual(set(projection), {"schema", "failure_gate"})

    def test_tree_inventory_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "regular").write_text("synthetic", encoding="utf-8")
            (root / "link").symlink_to(root / "regular")
            with self.assertRaises(activation.ActivationRejected):
                activation.tree_inventory(root)

    def test_telegram_config_contains_only_selected_release_paths(self) -> None:
        plugin = "f" * 64
        payload = json.loads(activation.render_telegram_config(plugin))
        self.assertEqual(payload["gateway_release"], plugin)
        self.assertEqual(payload["schema"], "myuna.telegram.r5-boot-resume-config.v1")


if __name__ == "__main__":
    unittest.main()
