from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CORE = Path("/srv/myuna/repos/core")
PREDECESSOR_RELEASE = Path(
    "/opt/myuna/active-temporal/releases/"
    "9a767797c9e4ee9ac3e417e2e00fdcabb68b6fcafeddcec090b05eb3ef9b103f"
)

import sys

sys.path.insert(0, str(ROOT / "scripts"))

import activate_p08_active_temporal_context_v1 as activation
import build_p08_active_temporal_release_v2 as builder
import build_p07_hybrid_live_releases_v1 as p07_builder
import p08_current_selected_upgrade_v1 as current_selected_upgrade
import p08_existing_state_upgrade_v1 as upgrade
import p08_temporal_gateway_v1 as temporal


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _git_head(root: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
        timeout=10,
    ).stdout.strip()


def _fake_gateway_runtime(
    root: Path,
    client: Path,
    *,
    core_commit: str,
    deploy_commit: str,
) -> Path:
    stage = root / "stage"
    runtime = stage / "runtime"
    runtime.mkdir(parents=True)
    shutil.copyfile(client, runtime / "p08_temporal_gateway_v1.py")
    shutil.copyfile(
        ROOT / "scripts/telegram_owner_runtime_gateway.py",
        runtime / "telegram_owner_runtime_gateway.py",
    )
    files = {}
    for path in sorted(runtime.iterdir()):
        files[f"runtime/{path.name}"] = {
            "size": path.stat().st_size,
            "sha256": _digest(path),
        }
    unsigned = {
        "schema": activation.GATEWAY_RELEASE_SCHEMA,
        "base_release_digest": "0" * 64,
        "source_core_commit": core_commit,
        "source_deploy_commit": deploy_commit,
        "files": files,
    }
    release_digest = sha256(
        json.dumps(unsigned, separators=(",", ":"), sort_keys=True).encode("ascii")
        + b"\n"
    ).hexdigest()
    release = root / release_digest
    stage.rename(release)
    (release / "P07_HYBRID_MANIFEST.json").write_text(
        json.dumps(
            {**unsigned, "release_digest": release_digest},
            separators=(",", ":"),
            sort_keys=True,
        ),
        "utf-8",
    )
    return release


def _fake_plugin(root: Path) -> Path:
    package = root / "myuna_telegram_gateway"
    package.mkdir(parents=True)
    for name in ("main.py", "protocol.py"):
        shutil.copyfile(
            ROOT
            / "channels/astrbot-telegram/plugin/myuna_telegram_gateway"
            / name,
            package / name,
        )
    return root


class P08PackagingTests(unittest.TestCase):
    def test_p07_runtime_projection_includes_temporal_client(self) -> None:
        self.assertIn("p08_temporal_gateway_v1.py", p07_builder._RUNTIME_OVERLAYS)
        gateway = (ROOT / "scripts/telegram_owner_runtime_gateway.py").read_text(
            "utf-8"
        )
        self.assertIn("from p08_temporal_gateway_v1 import", gateway)

    def test_builds_are_deterministic_and_bind_gateway_client(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            core_commit = _git_head(CORE)
            deploy_commit = _git_head(ROOT)
            outputs = []
            for name in ("a", "b"):
                output = root / name
                manifest = builder.build_release(
                    core_root=CORE,
                    deploy_root=ROOT,
                    output_root=output,
                    predecessor_release=PREDECESSOR_RELEASE,
                    core_commit=core_commit,
                    deploy_commit=deploy_commit,
                )
                self.assertEqual(manifest["schema"], builder.SCHEMA)
                self.assertEqual(manifest["core_commit"], core_commit)
                self.assertEqual(manifest["deploy_commit"], deploy_commit)
                self.assertIn(
                    "status_content_free",
                    manifest["protocol_contract"]["operations"],
                )
                self.assertEqual(
                    manifest["gateway_client"]["sha256"],
                    _digest(ROOT / "scripts/p08_temporal_gateway_v1.py"),
                )
                self.assertEqual(
                    manifest["upgrade_compatibility"]["active_gateway_client"][
                        "sha256"
                    ],
                    "798f834102af16efd47d7ddc3fa72904a6ca86d01fd02b354aadf65607594894",
                )
                self.assertEqual(
                    manifest["upgrade_compatibility"]["legacy_operation_subset"],
                    ["confirm", "propose", "retrieve"],
                )
                self.assertEqual(
                    manifest["upgrade_compatibility"]["status_helper_client"][
                        "sha256"
                    ],
                    manifest["gateway_client"]["sha256"],
                )
                self.assertEqual(
                    [
                        row["path"]
                        for row in manifest["gateway_status_runtime"]["files"]
                    ],
                    ["scripts/p08_temporal_gateway_v1.py"],
                )
                self.assertEqual(
                    manifest["gateway_status_runtime"]["stage_projection"][
                        "source_identity"
                    ],
                    temporal.STATUS_STAGE_SOURCE_IDENTITY,
                )
                self.assertEqual(
                    manifest["entrypoint"],
                    "p08_temporal_service_v1",
                )
                capability = manifest["trusted_time_capability_contract"]
                self.assertEqual(
                    capability["schema"],
                    upgrade.TRUSTED_TIME_CAPABILITY_CLOSURE_SCHEMA,
                )
                self.assertTrue(
                    upgrade.TRUSTED_TIME_CAPABILITY_REQUIRED_PATHS.issubset(
                        {Path(row["path"]) for row in capability["closure_files"]}
                    )
                )
                self.assertFalse(
                    capability["composition"]["direct_provider_injection"]
                )
                self.assertTrue(capability["composition"]["require_ready"])
                self.assertEqual(
                    manifest["service_contract"]["rejection_subprojection"][
                        "source_identity"
                    ],
                    temporal.SERVER_REJECTION_SOURCE_IDENTITY,
                )
                self.assertEqual(
                    manifest["gateway_status_runtime"][
                        "server_rejection_binding"
                    ]["source_identity"],
                    temporal.SERVER_REJECTION_SOURCE_IDENTITY,
                )
                self.assertFalse(
                    manifest["gateway_status_runtime"]["stage_projection"][
                        "persistent_mutation"
                    ]
                )
                self.assertFalse(
                    manifest["gateway_status_runtime"]["stage_projection"][
                        "raw_output_included"
                    ]
                )
                self.assertTrue(
                    manifest["post_target_action_contract"][
                        "live_execute_implemented"
                    ]
                )
                self.assertEqual(
                    manifest["post_target_action_contract"][
                        "incident_max_actions"
                    ],
                    1,
                )
                self.assertEqual(
                    manifest["post_target_action_contract"]["repair_plan_schema"],
                    "myuna.p08-post-target-repair-plan.v3",
                )
                self.assertEqual(
                    manifest["post_target_action_contract"]["rollback_plan_schema"],
                    "myuna.p08-post-target-rollback-plan.v3",
                )
                self.assertEqual(
                    manifest["post_target_action_contract"]["readiness_schema"],
                    "myuna.p08-post-target-action-readiness.v1",
                )
                self.assertEqual(
                    manifest["post_target_action_contract"][
                        "action_state_binding_schema"
                    ],
                    "myuna.p08-post-target-action-state-binding.v1",
                )
                acceptance_contract = manifest["post_target_action_contract"][
                    "protocol_acceptance"
                ]
                self.assertEqual(
                    acceptance_contract["schema"],
                    "myuna.p08-protocol-acceptance-contract.v1",
                )
                self.assertEqual(acceptance_contract["helper_calls"], 1)
                self.assertFalse(acceptance_contract["retry_or_fallback"])
                self.assertFalse(acceptance_contract["raw_stderr_retained"])
                self.assertEqual(
                    acceptance_contract["child_stage_contract_identity"],
                    temporal.STATUS_STAGE_SOURCE_IDENTITY,
                )
                self.assertEqual(
                    manifest["current_selected_upgrade_contract"],
                    current_selected_upgrade.release_contract(output),
                )
                self.assertEqual(
                    manifest["current_selected_upgrade_contract"]["max_attempts"],
                    1,
                )
                self.assertEqual(
                    manifest["current_selected_upgrade_contract"][
                        "failed_incident_digest"
                    ],
                    current_selected_upgrade.FAILED_INCIDENT_DIGEST,
                )
                self.assertFalse(
                    manifest["current_selected_upgrade_contract"][
                        "failed_restore_authority"
                    ]
                )
                self.assertEqual(
                    manifest["current_selected_upgrade_contract"][
                        "terminal_incident_digest"
                    ],
                    current_selected_upgrade.TERMINAL_INCIDENT_DIGEST,
                )
                self.assertFalse(
                    manifest["current_selected_upgrade_contract"][
                        "terminal_restore_authority"
                    ]
                )
                self.assertEqual(
                    manifest["current_selected_upgrade_contract"]["plan_schema"],
                    current_selected_upgrade.PLAN_SCHEMA,
                )
                self.assertEqual(
                    manifest["current_selected_upgrade_contract"]["strategy"][
                        "incident_namespace"
                    ],
                    str(current_selected_upgrade.EVIDENCE_ROOT / "incidents"),
                )
                launcher_binding = manifest["formal_preflight_launcher_contract"]
                self.assertEqual(
                    launcher_binding["launcher"],
                    manifest["current_selected_upgrade_contract"]["formal_launcher"],
                )
                self.assertEqual(
                    launcher_binding["source_binding"]["core"]["commit"],
                    core_commit,
                )
                self.assertEqual(
                    launcher_binding["source_binding"]["deploy"]["commit"],
                    deploy_commit,
                )
                self.assertEqual(
                    launcher_binding["launcher"]["artifact"]["launcher"][
                        "source_mode"
                    ],
                    0o755,
                )
                self.assertFalse(
                    launcher_binding["launcher"]["evidence_raw_stderr_retained"]
                )
                self.assertEqual(
                    manifest["p07_single_nonce_integration"],
                    current_selected_upgrade.p07_single_nonce_integration_contract(),
                )
                self.assertEqual(
                    manifest["current_selected_upgrade_contract"][
                        "p07_single_nonce_integration"
                    ],
                    current_selected_upgrade.p07_single_nonce_integration_contract(),
                )
                self.assertEqual(
                    manifest["current_selected_upgrade_contract"][
                        "prestate_rejection"
                    ]["handoff_sha256"],
                    current_selected_upgrade.PRESTATE_REJECTION_HANDOFF_SHA256,
                )
                self.assertEqual(
                    manifest["current_selected_upgrade_contract"]["strategy"][
                        "prestate_rejection"
                    ],
                    current_selected_upgrade.prestate_rejection_contract(),
                )
                self.assertEqual(
                    manifest["current_selected_upgrade_contract"][
                        "predecessor_release_digest"
                    ],
                    current_selected_upgrade.PREDECESSOR_RELEASE_DIGEST,
                )
                self.assertEqual(
                    manifest["current_selected_upgrade_contract"][
                        "v2_terminal_incident_digest"
                    ],
                    current_selected_upgrade.V2_TERMINAL_INCIDENT_DIGEST,
                )
                self.assertFalse(
                    manifest["current_selected_upgrade_contract"][
                        "v2_terminal_restore_authority"
                    ]
                )
                self.assertEqual(
                    [
                        row["operation"]
                        for row in manifest["upgrade_compatibility"][
                            "synthetic_protocol_fixtures"
                        ]["cases"]
                    ],
                    [
                        "confirm",
                        "propose",
                        "retrieve",
                        "snapshot_active",
                        "status_content_free",
                    ],
                )
                self.assertIn(
                    "scripts/p08_existing_state_upgrade_v1.py",
                    {row["path"] for row in manifest["files"]},
                )
                self.assertIn(
                    "scripts/p08_current_selected_upgrade_v1.py",
                    {row["path"] for row in manifest["files"]},
                )
                self.assertIn(
                    "scripts/p08_formal_preflight_launcher_v1.py",
                    {row["path"] for row in manifest["files"]},
                )
                self.assertIn(
                    "scripts/build_p08_active_temporal_release_v2.py",
                    {row["path"] for row in manifest["files"]},
                )
                self.assertIn(
                    "src/p08_temporal_service_v1.py",
                    {row["path"] for row in manifest["files"]},
                )
                outputs.append(
                    {
                        path.relative_to(output).as_posix(): (
                            path.read_bytes(),
                            stat.S_IMODE(path.stat().st_mode),
                        )
                        for path in sorted(output.rglob("*"))
                        if path.is_file()
                    }
                )
            self.assertEqual(outputs[0], outputs[1])

    def test_builder_rejects_source_commit_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(
                RuntimeError, "core_source_identity_rejected"
            ):
                builder.build_release(
                    core_root=CORE,
                    deploy_root=ROOT,
                    output_root=root / "wrong-core",
                    predecessor_release=PREDECESSOR_RELEASE,
                    core_commit="0" * 40,
                    deploy_commit=_git_head(ROOT),
                )
            with self.assertRaisesRegex(
                RuntimeError, "deploy_source_identity_rejected"
            ):
                builder.build_release(
                    core_root=CORE,
                    deploy_root=ROOT,
                    output_root=root / "wrong-deploy",
                    predecessor_release=PREDECESSOR_RELEASE,
                    core_commit=_git_head(CORE),
                    deploy_commit="0" * 40,
                )

    def test_builder_rejects_p07_integration_source_substitution(self) -> None:
        tracked = set(builder.P07_INTEGRATION_FILES)
        with mock.patch.object(builder, "_git", side_effect=["", ""]):
            builder._validate_p07_integration_source_identity(
                root=ROOT,
                deploy_commit=current_selected_upgrade.P07_INTEGRATION_DEPLOY_COMMIT,
                tracked=tracked,
            )
        with mock.patch.object(
            builder,
            "_git",
            side_effect=["", builder.P07_INTEGRATION_FILES[0] + "\n"],
        ):
            with self.assertRaisesRegex(
                RuntimeError, "p07_integration_source_identity_rejected"
            ):
                builder._validate_p07_integration_source_identity(
                    root=ROOT,
                    deploy_commit=current_selected_upgrade.P07_INTEGRATION_DEPLOY_COMMIT,
                    tracked=tracked,
                )
        with self.assertRaisesRegex(
            RuntimeError, "p07_integration_source_identity_rejected"
        ):
            builder._validate_p07_integration_source_identity(
                root=ROOT,
                deploy_commit=current_selected_upgrade.P07_INTEGRATION_DEPLOY_COMMIT,
                tracked=tracked - {builder.P07_INTEGRATION_FILES[0]},
            )

    def test_builder_rejects_unknown_or_incomplete_protocol_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unknown = root / "unknown.py"
            unknown.write_text(
                'SCHEMA = "myuna.active-temporal-context-protocol.v999"\n'
                'CONTENT_FREE_STATUS_SCHEMA = "myuna.active-temporal-content-free-status.v1"\n'
                '_OPERATIONS = frozenset({"status_content_free"})\n',
                "utf-8",
            )
            with self.assertRaisesRegex(
                RuntimeError, "protocol_contract_rejected"
            ):
                builder._protocol_contract(unknown)

            incomplete = root / "incomplete.py"
            incomplete.write_text(
                'SCHEMA = "myuna.active-temporal-context-protocol.v1"\n'
                'CONTENT_FREE_STATUS_SCHEMA = "myuna.active-temporal-content-free-status.v1"\n'
                '_OPERATIONS = frozenset({"retrieve", "propose", "confirm"})\n',
                "utf-8",
            )
            with self.assertRaisesRegex(
                RuntimeError, "protocol_contract_rejected"
            ):
                builder._protocol_contract(incomplete)

            oversized = root / "oversized.py"
            oversized.write_bytes(b"#" * (builder.MAX_PROTOCOL_BYTES + 1))
            with self.assertRaisesRegex(
                RuntimeError, "protocol_contract_rejected"
            ):
                builder._protocol_contract(oversized)

    def test_preflight_binds_release_gateway_plugin_and_empty_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            core_commit = _git_head(CORE)
            deploy_commit = _git_head(ROOT)
            manifest = builder.build_release(
                core_root=CORE,
                deploy_root=ROOT,
                output_root=release,
                predecessor_release=PREDECESSOR_RELEASE,
                core_commit=core_commit,
                deploy_commit=deploy_commit,
            )
            gateway = _fake_gateway_runtime(
                root / "gateway",
                release / manifest["gateway_client"]["source_path"],
                core_commit=core_commit,
                deploy_commit=deploy_commit,
            )
            plugin = _fake_plugin(root / "plugin")
            synthetic = root / "host"
            synthetic.mkdir()
            plan = activation.prepare_plan(
                release=release,
                gateway_runtime=gateway,
                plugin=plugin,
                root=synthetic,
            )
            payload = plan.as_payload()
            self.assertEqual(payload["schema"], activation.PLAN_SCHEMA)
            self.assertEqual(payload["plan_digest"], plan.digest)
            self.assertEqual(
                payload["gateway_client_sha256"],
                manifest["gateway_client"]["sha256"],
            )
            self.assertEqual(payload["state_prestate"], "absent")

            state = synthetic / str(activation.STATE_ROOT).lstrip("/")
            state.mkdir(parents=True)
            with self.assertRaisesRegex(
                activation.ActivationRejected, "state_preexisting"
            ):
                activation.prepare_plan(
                    release=release,
                    gateway_runtime=gateway,
                    plugin=plugin,
                    root=synthetic,
                )

    def test_wrong_gateway_client_or_plugin_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            core_commit = _git_head(CORE)
            deploy_commit = _git_head(ROOT)
            manifest = builder.build_release(
                core_root=CORE,
                deploy_root=ROOT,
                output_root=release,
                predecessor_release=PREDECESSOR_RELEASE,
                core_commit=core_commit,
                deploy_commit=deploy_commit,
            )
            gateway = _fake_gateway_runtime(
                root / "gateway",
                release / manifest["gateway_client"]["source_path"],
                core_commit=core_commit,
                deploy_commit=deploy_commit,
            )
            plugin = _fake_plugin(root / "plugin")
            (gateway / "runtime/p08_temporal_gateway_v1.py").write_text("drift", "utf-8")
            with self.assertRaises(activation.ActivationRejected):
                activation.prepare_plan(
                    release=release,
                    gateway_runtime=gateway,
                    plugin=plugin,
                    root=root / "host",
                )

    def test_activator_has_bounded_rollback_and_no_other_program_paths(self) -> None:
        source = (ROOT / "scripts/activate_p08_active_temporal_context_v1.py").read_text(
            "utf-8"
        )
        self.assertIn("state-preserved", source)
        self.assertIn("rollback_failed", source)
        self.assertIn("gateway_client_mismatch", source)
        self.assertIn('"is-active", "--quiet", SOCKET', source)
        self.assertIn('"is-active", "--quiet", SERVICE', source)
        self.assertIn("build_runtime_from_environment", source)
        for forbidden in (
            "/var/lib/myuna-telegram-gateway/external-context-epochs",
            "/var/lib/myuna-gateway/session-context",
            "/var/lib/myuna-owner-profile",
            "myuna-qq-owner-runtime",
        ):
            self.assertNotIn(forbidden, source)

    def test_post_start_state_acceptance_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            for name in ("temporal-context.sqlite3", "trusted-time.sqlite3"):
                path = root / name
                path.write_bytes(b"synthetic")
                path.chmod(0o600)
            activation._validate_state_files(root, service_uid=os.geteuid())
            extra = root / "unexpected"
            extra.write_bytes(b"synthetic")
            extra.chmod(0o600)
            with self.assertRaisesRegex(
                activation.ActivationRejected, "state_inventory_rejected"
            ):
                activation._validate_state_files(root, service_uid=os.geteuid())


if __name__ == "__main__":
    unittest.main()
