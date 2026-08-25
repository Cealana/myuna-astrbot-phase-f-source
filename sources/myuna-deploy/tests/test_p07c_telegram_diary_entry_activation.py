from __future__ import annotations

import ast
from hashlib import sha256
import importlib.util
import inspect
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
PLUGIN_PROTOCOL = (
    ROOT
    / "channels/astrbot-telegram/plugin/myuna_telegram_gateway/protocol.py"
)


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


activation = load(
    "p07c_diary_entry_activation_test",
    SCRIPTS / "activate_p07c_telegram_diary_entry_v1.py",
)
builder = load(
    "p07c_diary_runtime_builder_test",
    SCRIPTS / "build_p07c_telegram_diary_runtime_v1.py",
)
protocol = load("p07c_diary_plugin_protocol_test", PLUGIN_PROTOCOL)
consent_activation = load(
    "p07c_diary_consent_activation_test",
    SCRIPTS / "activate_p07c_telegram_diary_consent_layer_v1.py",
)


class P07CTelegramDiaryEntryActivationTests(unittest.TestCase):
    def test_new_scripts_parse_and_keep_fixed_boundaries(self) -> None:
        for path in (
            SCRIPTS / "activate_p07c_telegram_diary_entry_v1.py",
            SCRIPTS / "build_p07c_telegram_diary_runtime_v1.py",
            SCRIPTS / "activate_p07c_telegram_diary_consent_layer_v1.py",
        ):
            ast.parse(path.read_text("utf-8"), filename=str(path))
        source = inspect.getsource(activation)
        self.assertIn("restore_prestate", source)
        self.assertIn("verify_rollback", source)
        self.assertIn("model_called", source)
        self.assertIn("raw_message_recorded", source)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("rm -", source)
        consent_source = inspect.getsource(consent_activation)
        self.assertIn("restore(config_bytes)", consent_source)
        self.assertIn("verify_selection(PREVIOUS_PLUGIN_RELEASE)", consent_source)
        self.assertNotIn("systemctl(\"restart\", entry.RUNTIME_SERVICE)", consent_source)

    def test_plugin_timeout_exceeds_gateway_timeout(self) -> None:
        default = inspect.signature(protocol.send_envelope).parameters["timeout"].default
        runtime_source = (SCRIPTS / "telegram_owner_runtime_gateway.py").read_text(
            "utf-8"
        )
        self.assertEqual(default, 175.0)
        self.assertIn("CORE_REQUEST_TIMEOUT_SECONDS = 165", runtime_source)
        self.assertGreater(default, 165)

    def test_rendered_selection_contains_only_content_free_paths(self) -> None:
        runtime_digest = "a" * 64
        plugin_digest = "b" * 64
        config = json.loads(activation.render_config(plugin_digest))
        self.assertEqual(config["gateway_release"], plugin_digest)
        self.assertNotIn("message", repr(config).lower())
        dropin = activation.render_dropin(runtime_digest).decode("ascii")
        self.assertIn(runtime_digest, dropin)
        self.assertIn("MYUNA_SESSION_CONTEXT_STORE=sqlite-v1", dropin)

    def test_runtime_candidate_validator_checks_commit_and_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            commit = "c" * 40
            candidate = root / ("d" * 64)
            source = candidate / "runtime/example.py"
            source.parent.mkdir(parents=True)
            source.write_text("VALUE = 1\n", "utf-8")
            manifest = {
                "files": {"runtime/example.py": sha256(source.read_bytes()).hexdigest()},
                "release_digest": candidate.name,
                "schema": activation.RUNTIME_SCHEMA,
                "source_deploy_commit": commit,
            }
            (candidate / "MANIFEST.json").write_text(
                json.dumps(manifest),
                "ascii",
            )
            self.assertEqual(
                activation.validate_runtime_candidate(candidate, commit),
                candidate.name,
            )
            source.write_text("VALUE = 2\n", "utf-8")
            with self.assertRaises(activation.ActivationRejected):
                activation.validate_runtime_candidate(candidate, commit)

    def test_plugin_candidate_validator_checks_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate = root / ("e" * 64)
            source = candidate / "channels/plugin/protocol.py"
            source.parent.mkdir(parents=True)
            source.write_text("VALUE = 1\n", "utf-8")
            manifest = {
                "files": [
                    {
                        "destination": "channels/plugin/protocol.py",
                        "mode": "0444",
                        "sha256": sha256(source.read_bytes()).hexdigest(),
                        "size": source.stat().st_size,
                    }
                ],
                "release_digest": candidate.name,
                "schema": activation.PLUGIN_SCHEMA,
            }
            (root / f"{candidate.name}.manifest.json").write_text(
                json.dumps(manifest),
                "ascii",
            )
            self.assertEqual(
                activation.validate_plugin_candidate(candidate),
                candidate.name,
            )
            (candidate / "unexpected").write_text("drift", "utf-8")
            with self.assertRaises(activation.ActivationRejected):
                activation.validate_plugin_candidate(candidate)

    def test_builder_manifest_is_content_free(self) -> None:
        identity = {
            "base_release_digest": builder.BASE_RELEASE_DIGEST,
            "files": {"runtime/example.py": "f" * 64},
            "policy": {
                "raw_content_in_manifest": False,
                "scope": "telegram-owner-private-only",
            },
            "schema": builder.SCHEMA,
            "source_deploy_commit": "a" * 40,
        }
        encoded = builder.canonical_bytes(identity)
        self.assertNotIn(b"query", encoded)
        self.assertNotIn(b"message_text", encoded)
        self.assertIn(b'"raw_content_in_manifest":false', encoded)


if __name__ == "__main__":
    unittest.main()
