from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import activate_p16_diagnostics_v1 as activation  # noqa: E402
import core_release_selector as selector_contract  # noqa: E402


class ActivateP16DiagnosticsV1Tests(unittest.TestCase):
    def _core_candidate(self, root: Path) -> tuple[Path, dict[str, object]]:
        payloads = {
            relative: f"core:{relative}".encode("ascii")
            for relative in activation._EXPECTED_RELEASE_FILES["core"]
        }
        unsigned = {
            "schema": activation.RELEASE_SCHEMA,
            "kind": "core",
            "base_release_digest": "a" * 64,
            "source_commit": "b" * 40,
            "files": {
                relative: {
                    "sha256": activation._digest_bytes(payload),
                    "size": len(payload),
                }
                for relative, payload in payloads.items()
            },
        }
        manifest_digest = activation._digest_bytes(activation._canonical(unsigned))
        manifest = {**unsigned, "release_digest": manifest_digest}
        temporary = root / "core-candidate"
        temporary.mkdir()
        for relative, payload in payloads.items():
            target = temporary / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        manifest_bytes = activation._canonical(manifest) + b"\n"
        (temporary / "P16_MANIFEST.json").write_bytes(manifest_bytes)
        receipt = {
            "schema": "myuna.p16-core-installation-receipt.v1",
            "base_release_digest": "a" * 64,
            "source_commit": "b" * 40,
            "overlay_manifest_sha256": activation._digest_bytes(manifest_bytes),
            "content_free": True,
            "private_content_read": False,
        }
        (temporary / "P16_INSTALLATION_RECEIPT.json").write_bytes(
            activation._canonical(receipt) + b"\n"
        )
        for path in [temporary, *temporary.rglob("*")]:
            path.chmod(0o550 if path.is_dir() else 0o440)
        tree_digest, _ = activation.compute_tree_digest(temporary)
        release = root / tree_digest
        temporary.rename(release)
        return release, manifest

    def test_selector_rendering_is_exact_and_preserves_sqlite_mode(self) -> None:
        release = Path("/opt/myuna/context24-gateway/qq/releases/" + "a" * 64)
        rendered = activation._gateway_selector(
            release,
            "qq_owner_runtime_gateway.py",
        ).decode("ascii")
        self.assertEqual(rendered.count("ExecStart="), 2)
        self.assertIn(f"ExecStart=/usr/bin/python3 {release}/runtime/", rendered)
        self.assertIn("Environment=MYUNA_SESSION_CONTEXT_STORE=sqlite-v1", rendered)
        for forbidden in ("EnvironmentFile", "token", "credential", "restart"):
            self.assertNotIn(forbidden, rendered)

    def test_resolves_only_exact_content_addressed_gateway_exec(self) -> None:
        release = "/opt/myuna/context24-gateway/telegram/releases/" + "b" * 64
        value = (
            "{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 "
            + release
            + "/runtime/telegram_owner_runtime_gateway.py ; status=0/0 }"
        )
        self.assertEqual(
            activation._selected_gateway_release(value, channel="telegram"),
            Path(release),
        )
        with self.assertRaisesRegex(RuntimeError, "cannot be resolved"):
            activation._selected_gateway_release(
                "/tmp/unapproved/telegram_owner_runtime_gateway.py",
                channel="telegram",
            )

    def test_resolves_only_exact_content_addressed_core_workdir(self) -> None:
        release = "/srv/myuna/releases/core/" + "a" * 64
        self.assertEqual(activation._selected_core_release(release), Path(release))
        for invalid in (release + "/src", "/tmp/" + "a" * 64, "relative/path"):
            with self.assertRaisesRegex(RuntimeError, "cannot be resolved"):
                activation._selected_core_release(invalid)

    def test_preflight_is_content_free_and_does_not_activate(self) -> None:
        manifests = {
            key: {"release_digest": character * 64}
            for key, character in zip(
                ("core", "qq", "telegram", "diagnostics"),
                "abcd",
            )
        }
        selected = {
            key: Path("/fixed") / manifests[key]["release_digest"]
            for key in ("core", "qq", "telegram")
        }
        with mock.patch.object(
            activation,
            "_preflight_context",
            return_value={"manifests": manifests, "selected": selected},
        ), mock.patch.object(activation, "_copy_release") as copy_release:
            result = activation.preflight(
                core_candidate=Path("core"),
                qq_candidate=Path("qq"),
                telegram_candidate=Path("telegram"),
                diagnostics_candidate=Path("diagnostics"),
            )
        copy_release.assert_not_called()
        self.assertEqual(result["schema"], activation.PREFLIGHT_SCHEMA)
        self.assertEqual(result["result"], "ready")
        self.assertTrue(result["content_free"])
        self.assertFalse(result["private_content_read"])
        self.assertFalse(result["channel_called"])

    def test_session_acl_preserves_group_mask_and_grants_only_traverse(self) -> None:
        with mock.patch.object(activation, "_run") as run, mock.patch.object(
            activation,
            "_verify_session_acl",
        ) as verify:
            activation._apply_session_acl()
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(commands), 4)
        self.assertIn("g:sudo:--x,m::r-x", commands[0])
        self.assertIn("g:sudo:--x,m::--x", commands[1])
        self.assertIn("g:sudo:--x,m::r-x", commands[2])
        self.assertIn("g:sudo:--x,m::--x", commands[3])
        verify.assert_called_once_with()

    def test_release_manifest_is_strict_and_bound_to_directory_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            payloads = {
                relative: f"payload:{relative}".encode("ascii")
                for relative in activation._EXPECTED_RELEASE_FILES["diagnostics"]
            }
            unsigned = {
                "schema": activation.RELEASE_SCHEMA,
                "kind": "diagnostics",
                "base_release_digest": None,
                "source_commit": "d" * 40,
                "files": {
                    relative: {
                        "sha256": activation._digest_bytes(payload),
                        "size": len(payload),
                    }
                    for relative, payload in payloads.items()
                },
            }
            digest = activation._digest_bytes(activation._canonical(unsigned))
            release = Path(directory) / digest
            release.mkdir()
            for relative, payload in payloads.items():
                target = release / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
            manifest = {**unsigned, "release_digest": digest}
            (release / "P16_MANIFEST.json").write_text(json.dumps(manifest))
            self.assertEqual(
                activation._release(release, "diagnostics")["release_digest"],
                release.name,
            )
            manifest["raw_private_content"] = "forbidden"
            (release / "P16_MANIFEST.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(RuntimeError, "manifest is invalid"):
                activation._release(release, "diagnostics")

    def test_release_rejects_overlay_digest_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            payloads = {
                relative: b"safe"
                for relative in activation._EXPECTED_RELEASE_FILES["diagnostics"]
            }
            unsigned = {
                "schema": activation.RELEASE_SCHEMA,
                "kind": "diagnostics",
                "base_release_digest": None,
                "source_commit": "e" * 40,
                "files": {
                    relative: {
                        "sha256": activation._digest_bytes(payload),
                        "size": len(payload),
                    }
                    for relative, payload in payloads.items()
                },
            }
            digest = activation._digest_bytes(activation._canonical(unsigned))
            release = Path(directory) / digest
            release.mkdir()
            for relative, payload in payloads.items():
                target = release / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
            (release / "P16_MANIFEST.json").write_text(
                json.dumps({**unsigned, "release_digest": digest})
            )
            (release / "myuna_diagnose.py").write_bytes(b"drift")
            with self.assertRaisesRegex(RuntimeError, "file digest is invalid"):
                activation._release(release, "diagnostics")

    def test_core_release_is_tree_addressed_and_builds_guard_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            release, manifest = self._core_candidate(Path(directory))
            self.assertEqual(activation._release(release, "core"), manifest)
            verifier_digest = "c" * 64
            current_binding = SimpleNamespace(
                verifier_script_path=(
                    "/opt/myuna/core-release-selector/releases/"
                    f"{verifier_digest}/core_release_selector.py"
                ),
                verifier_script_sha256=verifier_digest,
            )
            with mock.patch.object(
                selector_contract,
                "RELEASE_ROOT",
                str(release.parent),
            ):
                payload = activation._core_runtime_binding(
                    release,
                    manifest=manifest,
                    current_binding=current_binding,
                    approval_plan_digest="d" * 64,
                    validate_tree=lambda _release, _evidence: None,
                    guard_payload=(
                        "[Unit]\n"
                        "ConditionPathExists=/etc/myuna/core-release-selector/"
                        "qq.binding.json\n\n"
                        "[Service]\n"
                        f"ExecStartPre=/usr/bin/python3 "
                        f"{current_binding.verifier_script_path} verify-active\n"
                    ).encode("ascii"),
                )
                binding = activation.load_runtime_binding(
                    activation.parse_json_document(payload)
                )
            self.assertEqual(binding.selected_release.tree_sha256, release.name)
            self.assertEqual(binding.selected_release.source_commit, "b" * 40)
            self.assertEqual(binding.approval_plan_digest, "d" * 64)

    def test_activation_and_rollback_commands_are_target_scoped(self) -> None:
        source = (ROOT / "scripts/activate_p16_diagnostics_v1.py").read_text()
        for required in (
            "myuna-core@qq.service",
            "myuna-qq-owner-runtime-dev.service",
            "myuna-telegram-owner-runtime-dev.service",
            "--restore=",
            "content_free",
            "private_content_read",
            "rollback_preflight",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "/healthz",
            "/readyz",
            "/v1/status",
            "/v1/chat",
            "journalctl",
            "docker",
            "shutdown",
            "terminate",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
