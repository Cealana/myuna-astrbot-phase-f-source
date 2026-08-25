from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CORE = Path("/srv/myuna/repos/core")
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import build_p08_active_temporal_release_v2 as builder
import p08_existing_state_upgrade_v1 as upgrade
import p08_temporal_gateway_v1 as temporal


PREDECESSOR = Path(
    "/opt/myuna/active-temporal/releases/"
    "9a767797c9e4ee9ac3e417e2e00fdcabb68b6fcafeddcec090b05eb3ef9b103f"
)
ACTIVE_GATEWAY = Path(
    "/opt/myuna/context24-gateway/telegram/releases/"
    "7baf48da3715ee2e1446ebf04a40ba8183c990fcf7f9505d9df465dc04e3d421"
)
UNIT_STATE = {
    "service_active": "active",
    "socket_active": "active",
    "socket_enabled": "enabled",
}

# The closed existing-state controller remains bound to its historical target
# units even though the replacement activation engine builds a numeric
# credential launch target.  Keeping these bytes local to the legacy fixture
# prevents current source units from relabelling old rollback authority.
LEGACY_TARGET_SERVICE_UNIT = b"""[Unit]
Description=Myuna active temporal context private worker v1
Requires=myuna-active-temporal-context-v1.socket
After=myuna-active-temporal-context-v1.socket

[Service]
Type=exec
User=myuna_active_temporal
Group=myuna_active_temporal
SetLoginEnvironment=no
EnvironmentFile=/etc/myuna-active-temporal-context-v1/selector.env
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/usr/bin/python3 -B -P -S -m p08_temporal_service_v1
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX
ReadWritePaths=/var/lib/myuna-active-temporal-context-v1
UMask=0077
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
"""
LEGACY_TARGET_SOCKET_UNIT = b"""[Unit]
Description=Myuna active temporal context private socket v1

[Socket]
ListenStream=/run/myuna-active-temporal-context-v1/temporal.sock
SocketUser=myuna_active_temporal
SocketGroup=myuna-gateway-telegram
SocketMode=0660
RemoveOnStop=yes
Service=myuna-active-temporal-context-v1.service

[Install]
WantedBy=sockets.target
"""


class SyntheticCrash(BaseException):
    pass


class RecordingRunner:
    def __init__(self, *, fail_once: tuple[str, ...] | None = None) -> None:
        self.events: list[tuple[str, ...]] = []
        self.fail_once = fail_once
        self.failed = False

    def __call__(self, command: list[str]) -> None:
        event = tuple(command)
        self.events.append(event)
        if self.fail_once == event and not self.failed:
            self.failed = True
            raise upgrade.UpgradeRejected("synthetic_command_failure")


def _copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def _target_stage(root: Path) -> Path:
    stage = root / "target-stage"
    for relative in builder.CORE_FILES:
        _copy(CORE / relative, stage / relative)
    for relative in builder.CORE_DIRECTORIES:
        source = CORE / relative
        for path in sorted(source.rglob("*.py")):
            _copy(path, stage / path.relative_to(CORE))
    for relative in builder.DEPLOY_FILES:
        _copy(ROOT / relative, stage / relative)
    (stage / upgrade.SERVICE_UNIT_PATH).write_bytes(LEGACY_TARGET_SERVICE_UNIT)
    (stage / upgrade.SOCKET_UNIT_PATH).write_bytes(LEGACY_TARGET_SOCKET_UNIT)
    _copy(
        ROOT / upgrade.SERVICE_SOURCE_PATH,
        stage / upgrade.SERVICE_ENTRYPOINT_PATH,
    )
    return stage


def _target_release(root: Path) -> Path:
    stage = _target_stage(root)
    compatibility = upgrade.derive_compatibility_closure(
        predecessor_release=PREDECESSOR,
        target_root=stage,
    )
    client = stage / upgrade.CLIENT_PATH
    protocol = stage / upgrade.PROTOCOL_PATH
    manifest = {
        "core_commit": upgrade.TARGET_CORE_COMMIT,
        "deploy_commit": "d" * 40,
        "entrypoint": "p08_temporal_service_v1",
        "files": builder._inventory(stage),
        "forward_continuity_contract": builder.forward_continuity.contract(),
        "gateway_client": {
            "runtime_path": "runtime/p08_temporal_gateway_v1.py",
            "sha256": upgrade.digest_file(client),
            "source_path": upgrade.CLIENT_PATH.as_posix(),
        },
        "gateway_status_runtime": upgrade.status_runtime_contract(stage),
        "protocol_contract": builder._protocol_contract(protocol),
        "protocol_schema": upgrade.PROTOCOL_SCHEMA,
        "runtime_profile": "p08-active-temporal-private-v2",
        "schema": upgrade.RELEASE_SCHEMA,
        "service_contract": upgrade.server_rejection_contract(stage),
        "state_schema": "myuna.active-temporal-context.v1",
        "trusted_time_capability_contract": (
            upgrade.trusted_time_capability_contract(stage)
        ),
        "trusted_time_schema": "myuna.trusted-time-provider.v1",
        "upgrade_compatibility": compatibility,
    }
    (stage / "manifest.json").write_bytes(upgrade.canonical(manifest) + b"\n")
    digest = sha256(upgrade.canonical(manifest)).hexdigest()
    release = root / digest
    stage.rename(release)
    return release


def _selector_bytes() -> bytes:
    return (
        upgrade.canonical(
            {
                "core_commit": upgrade.PREDECESSOR_CORE_COMMIT,
                "deploy_commit": upgrade.PREDECESSOR_DEPLOY_COMMIT,
                "gateway_client_sha256": upgrade.PREDECESSOR_CLIENT_SHA256,
                "gateway_manifest_digest": upgrade.ACTIVE_GATEWAY_MANIFEST_DIGEST,
                "plan_digest": upgrade.PREDECESSOR_PLAN_DIGEST,
                "plugin_digest": upgrade.ACTIVE_PLUGIN_DIGEST,
                "release_digest": upgrade.PREDECESSOR_RELEASE_DIGEST,
                "release_path": str(
                    upgrade.RELEASE_ROOT / upgrade.PREDECESSOR_RELEASE_DIGEST
                ),
                "schema": upgrade.SELECTOR_SCHEMA,
            }
        )
        + b"\n"
    )


def _selector_env_bytes() -> bytes:
    return (
        "PYTHONPATH=/opt/myuna/active-temporal/releases/"
        "9a767797c9e4ee9ac3e417e2e00fdcabb68b6fcafeddcec090b05eb3ef9b103f/src\n"
        "MYUNA_P08_STATE_ROOT=/var/lib/myuna-active-temporal-context-v1\n"
        "MYUNA_P08_SERVICE_UID=976\n"
        "MYUNA_P08_TELEGRAM_UID=988\n"
    ).encode("ascii")


def _write(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(mode)


def _synthetic_host(root: Path) -> tuple[Path, tuple[int, int, int]]:
    host = root / "host"
    _write(
        host / str(upgrade.SELECTOR_JSON).lstrip("/"),
        _selector_bytes(),
        0o600,
    )
    _write(
        host / str(upgrade.SELECTOR_ENV).lstrip("/"),
        _selector_env_bytes(),
        0o600,
    )
    _write(
        host / str(upgrade.UNIT_ROOT / upgrade.SERVICE).lstrip("/"),
        (PREDECESSOR / upgrade.SERVICE_UNIT_PATH).read_bytes(),
        0o644,
    )
    _write(
        host / str(upgrade.UNIT_ROOT / upgrade.SOCKET).lstrip("/"),
        (PREDECESSOR / upgrade.SOCKET_UNIT_PATH).read_bytes(),
        0o644,
    )
    state = host / str(upgrade.STATE_ROOT).lstrip("/")
    state.mkdir(parents=True)
    state.chmod(0o700)
    for index, name in enumerate(upgrade.STATE_FILES):
        _write(
            state / name,
            b"opaque-synthetic-state-v1\0" + bytes([index]) * 31,
            0o600,
        )
    return host, (os.geteuid(), os.getegid(), os.geteuid())


def _plan(root: Path) -> tuple[Path, Path, tuple[int, int, int], dict[str, object]]:
    target = _target_release(root)
    host, identity = _synthetic_host(root)
    plan = upgrade.prepare_plan(
        predecessor_release=PREDECESSOR,
        target_release=target,
        active_gateway_runtime=ACTIVE_GATEWAY,
        root=host,
        synthetic_identity=identity,
        unit_state=UNIT_STATE,
    ).as_payload()
    return target, host, identity, plan


def _rebind_plan(payload: dict[str, object]) -> dict[str, object]:
    selected = json.loads(json.dumps(payload))
    selected.pop("plan_digest", None)
    selected.pop("schema", None)
    return {
        "plan_digest": upgrade.digest_bytes(upgrade.canonical(selected)),
        "schema": upgrade.PLAN_SCHEMA,
        **selected,
    }


@unittest.skipUnless(
    PREDECESSOR.is_dir() and ACTIVE_GATEWAY.is_dir() and CORE.is_dir(),
    "exact P08 predecessor, active gateway, and Core source are required",
)
class ExistingStateUpgradeContractTests(unittest.TestCase):
    def test_status_helper_release_import_closure_is_network_denied_and_complete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = _target_release(Path(directory))
            environment = {
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": os.pathsep.join(
                    [str(target / "src"), str(target / "scripts")]
                ),
            }
            command = [
                sys.executable,
                "-B",
                "-c",
                (
                    "import p08_temporal_gateway_v1; "
                    "import p08_temporal_service_v1; "
                    "from myuna_core.trusted_time.runtime import TrustedTimeCapability; "
                    "assert p08_temporal_service_v1.TrustedTimeCapability "
                    "is TrustedTimeCapability"
                ),
            ]
            if os.geteuid() == 0 and Path("/usr/bin/unshare").is_file():
                command = ["/usr/bin/unshare", "--net", "--", *command]
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                timeout=10,
                check=False,
            )
            self.assertEqual(
                completed.returncode,
                0,
                sha256(completed.stderr).hexdigest(),
            )
            self.assertEqual(completed.stdout, b"")
            closure = upgrade.status_runtime_contract(target)
            self.assertEqual(
                [row["path"] for row in closure["files"]],
                [path.as_posix() for path in upgrade.STATUS_RUNTIME_PATHS],
            )
            self.assertEqual(closure["schema"], upgrade.STATUS_RUNTIME_SCHEMA)
            projection = closure["stage_projection"]
            self.assertEqual(projection["schema"], upgrade.STATUS_STAGE_SCHEMA)
            self.assertEqual(
                projection["source_identity"],
                temporal.STATUS_STAGE_SOURCE_IDENTITY,
            )
            self.assertFalse(projection["persistent_mutation"])
            self.assertFalse(projection["raw_output_included"])
            self.assertEqual(
                {row["stage"] for row in projection["rejections"]},
                set(temporal._STATUS_STAGE_POLICY),
            )
            self.assertEqual(
                closure["server_rejection_binding"]["source_identity"],
                temporal.SERVER_REJECTION_SOURCE_IDENTITY,
            )
            capability = upgrade.trusted_time_capability_contract(target)
            closure_paths = {
                Path(row["path"]) for row in capability["closure_files"]
            }
            self.assertTrue(
                upgrade.TRUSTED_TIME_CAPABILITY_REQUIRED_PATHS.issubset(
                    closure_paths
                )
            )
            self.assertEqual(
                capability["composition"],
                {
                    "direct_provider_injection": False,
                    "require_ready": True,
                    "shutdown_on_failure": True,
                    "shutdown_on_service_exit": True,
                    "startup_once": True,
                },
            )
            removed = target / "src/myuna_core/capability_runtime/lifecycle.py"
            saved = removed.read_bytes()
            removed.unlink()
            try:
                with self.assertRaisesRegex(
                    upgrade.UpgradeRejected,
                    "trusted_time_capability_closure_rejected",
                ):
                    upgrade.trusted_time_capability_contract(target)
            finally:
                removed.write_bytes(saved)

    def test_server_rejection_service_and_client_contract_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stage = _target_stage(Path(directory))
            contract = upgrade.server_rejection_contract(stage)
            self.assertEqual(contract["entrypoint"], "p08_temporal_service_v1")
            self.assertEqual(
                contract["rejection_subprojection"]["source_identity"],
                temporal.SERVER_REJECTION_SOURCE_IDENTITY,
            )
            self.assertEqual(
                {row["stage"] for row in contract["rejection_subprojection"]["rejections"]},
                set(temporal._SERVER_REJECTION_POLICY),
            )
            self.assertFalse(
                contract["rejection_subprojection"]["raw_cause_included"]
            )

            service = stage / upgrade.SERVICE_ENTRYPOINT_PATH
            client = stage / upgrade.CLIENT_PATH
            original_service = service.read_text("utf-8")
            original_client = client.read_text("utf-8")
            mutations = {
                "runtime_substitution": (
                    service,
                    original_service + "\n# substitution\n",
                ),
                "mixed_client_policy": (
                    client,
                    original_client.replace(
                        '"peer_rejected",',
                        '"peer_substituted",',
                        1,
                    ),
                ),
                "unknown_server_stage": (
                    service,
                    original_service.replace(
                        '"service_peer_boundary": (',
                        '"service_peer_substituted": (',
                        1,
                    ),
                ),
            }
            for name, (path, mutated) in mutations.items():
                with self.subTest(name=name):
                    path.write_text(mutated, "utf-8")
                    with self.assertRaises(upgrade.UpgradeRejected):
                        upgrade.server_rejection_contract(stage)
                    service.write_text(original_service, "utf-8")
                    client.write_text(original_client, "utf-8")

    def test_status_stage_contract_drift_or_substitution_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = _target_stage(root)
            helper = stage / upgrade.CLIENT_PATH
            source = helper.read_text("utf-8")
            cases = {
                "missing_required_stage": source.replace(
                    '"parent_malformed": ("parent_malformed", False),',
                    '"parent_substituted": ("parent_malformed", False),',
                    1,
                ),
                "schema_drift": source.replace(
                    temporal.STATUS_STAGE_SCHEMA,
                    "myuna.p08-content-free-status-stage.v999",
                    1,
                ),
                "nonliteral_policy": source.replace(
                    '_STATUS_STAGE_POLICY: dict[str, tuple[str, bool]] = {',
                    '_STATUS_STAGE_POLICY: dict[str, tuple[str, bool]] = dict({',
                    1,
                ).replace(
                    '\n}\nSTATUS_STAGE_SOURCE_IDENTITY',
                    '\n})\nSTATUS_STAGE_SOURCE_IDENTITY',
                    1,
                ),
            }
            for name, mutated in cases.items():
                with self.subTest(name=name):
                    helper.write_text(mutated, encoding="utf-8")
                    with self.assertRaises(upgrade.UpgradeRejected):
                        upgrade.status_runtime_contract(stage)
                    helper.write_text(source, encoding="utf-8")

    def test_exact_source_compatibility_closure_and_synthetic_fixtures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stage = _target_stage(Path(directory))
            closure = upgrade.derive_compatibility_closure(
                predecessor_release=PREDECESSOR,
                target_root=stage,
            )
            self.assertEqual(closure["schema"], upgrade.CONTRACT_SCHEMA)
            self.assertEqual(
                closure["active_gateway_client"]["sha256"],
                upgrade.PREDECESSOR_CLIENT_SHA256,
            )
            self.assertEqual(
                closure["active_gateway_client"]["operations"],
                list(upgrade.LEGACY_OPERATIONS),
            )
            self.assertEqual(
                closure["target_server"]["operations"],
                list(upgrade.TARGET_OPERATIONS),
            )
            self.assertEqual(
                closure["status_helper_client"]["sha256"],
                upgrade.TARGET_CLIENT_SHA256,
            )
            self.assertEqual(
                [
                    row["operation"]
                    for row in closure["synthetic_protocol_fixtures"]["cases"]
                ],
                list(upgrade.TARGET_OPERATIONS),
            )
            self.assertFalse(closure["service_semantics"]["state_schema_migration"])

            with self.assertRaises(upgrade.UpgradeRejected):
                upgrade.derive_compatibility_closure(
                    predecessor_release=PREDECESSOR,
                    target_root=stage,
                    target_service_unit_sha256="0" * 63,
                )
            with self.assertRaises(upgrade.UpgradeRejected):
                upgrade.derive_compatibility_closure(
                    predecessor_release=PREDECESSOR,
                    target_root=stage,
                    target_socket_unit_sha256="0" * 64,
                )

    def test_missing_mixed_stale_or_substituted_clients_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = _target_stage(root)
            (stage / upgrade.CLIENT_PATH).write_bytes(b"SCHEMA='unknown'\n")
            with self.assertRaises(upgrade.UpgradeRejected):
                upgrade.derive_compatibility_closure(
                    predecessor_release=PREDECESSOR,
                    target_root=stage,
                )

            substituted = root / upgrade.PREDECESSOR_RELEASE_DIGEST
            shutil.copytree(PREDECESSOR, substituted)
            with (substituted / upgrade.CLIENT_PATH).open("ab") as stream:
                stream.write(b"\n# substitution\n")
            with self.assertRaises(upgrade.UpgradeRejected):
                upgrade.validate_predecessor_release(substituted)

    def test_active_gateway_is_exact_and_caller_allowlists_are_not_accepted(self) -> None:
        runtime = upgrade.validate_active_gateway_runtime(ACTIVE_GATEWAY)
        self.assertEqual(
            runtime["client_contract"]["operations"],
            list(upgrade.LEGACY_OPERATIONS),
        )
        self.assertNotIn("allowed_clients", upgrade.prepare_plan.__annotations__)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / ACTIVE_GATEWAY.name
            shutil.copytree(ACTIVE_GATEWAY, fake)
            (fake / "runtime/p08_temporal_gateway_v1.py").write_text(
                "# mixed client", "utf-8"
            )
            with self.assertRaises(upgrade.UpgradeRejected):
                upgrade.validate_active_gateway_runtime(fake)

    def test_opaque_backup_restore_is_non_overwriting_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            host, identity = _synthetic_host(root)
            state = host / str(upgrade.STATE_ROOT).lstrip("/")
            descriptor = upgrade.describe_opaque_state(
                state, expected_uid=identity[0], expected_gid=identity[1]
            )
            backup = root / "backup"
            upgrade.backup_opaque_state(
                source=state,
                backup=backup,
                expected=descriptor,
                expected_uid=identity[0],
                expected_gid=identity[1],
            )
            upgrade.validate_opaque_backup(
                backup=backup,
                expected=descriptor,
                expected_uid=identity[0],
                expected_gid=identity[1],
            )
            with self.assertRaisesRegex(
                upgrade.UpgradeRejected, "state_backup_preexisting"
            ):
                upgrade.backup_opaque_state(
                    source=state,
                    backup=backup,
                    expected=descriptor,
                    expected_uid=identity[0],
                    expected_gid=identity[1],
                )
            changed = state / upgrade.STATE_FILES[0]
            changed.write_bytes(b"different-opaque-state")
            changed.chmod(0o600)
            upgrade.restore_opaque_state(
                target=state,
                backup=backup,
                expected=descriptor,
                expected_uid=identity[0],
                expected_gid=identity[1],
                plan_digest="a" * 64,
            )
            self.assertEqual(
                upgrade.describe_opaque_state(
                    state, expected_uid=identity[0], expected_gid=identity[1]
                ),
                descriptor,
            )
            self.assertTrue((backup / "displaced-state-tree").is_dir())
            self.assertTrue((backup / "displaced-copy/STATE.json").is_file())

    def test_state_type_permission_size_inventory_and_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            host, identity = _synthetic_host(root)
            state = host / str(upgrade.STATE_ROOT).lstrip("/")
            descriptor = upgrade.describe_opaque_state(
                state, expected_uid=identity[0], expected_gid=identity[1]
            )

            target = state / upgrade.STATE_FILES[0]
            target.chmod(0o644)
            with self.assertRaisesRegex(
                upgrade.UpgradeRejected, "state_file_permission_rejected"
            ):
                upgrade.describe_opaque_state(
                    state, expected_uid=identity[0], expected_gid=identity[1]
                )
            target.chmod(0o600)

            extra = state / "unknown.sqlite3"
            _write(extra, b"synthetic", 0o600)
            with self.assertRaisesRegex(
                upgrade.UpgradeRejected, "state_inventory_rejected"
            ):
                upgrade.describe_opaque_state(
                    state, expected_uid=identity[0], expected_gid=identity[1]
                )
            extra.unlink()

            target.write_bytes(b"changed")
            target.chmod(0o600)
            with self.assertRaisesRegex(
                upgrade.UpgradeRejected, "state_preflight_drifted"
            ):
                upgrade.backup_opaque_state(
                    source=state,
                    backup=root / "drift-backup",
                    expected=descriptor,
                    expected_uid=identity[0],
                    expected_gid=identity[1],
                )

            with target.open("r+b") as stream:
                stream.truncate(upgrade.MAX_STATE_FILE_BYTES + 1)
            with self.assertRaisesRegex(
                upgrade.UpgradeRejected, "state_file_size_rejected"
            ):
                upgrade.describe_opaque_state(
                    state, expected_uid=identity[0], expected_gid=identity[1]
                )

    def test_plan_binds_exact_predecessor_target_public_state_and_p08_only_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target, host, identity, plan = _plan(Path(directory))
            self.assertEqual(plan["schema"], upgrade.PLAN_SCHEMA)
            self.assertEqual(
                plan["predecessor"]["release_digest"],
                upgrade.PREDECESSOR_RELEASE_DIGEST,
            )
            self.assertEqual(
                plan["active_gateway_runtime"]["client_contract"]["sha256"],
                upgrade.PREDECESSOR_CLIENT_SHA256,
            )
            self.assertEqual(
                plan["target"]["release_digest"], target.name
            )
            self.assertEqual(plan["unit_prestate"], UNIT_STATE)
            self.assertEqual(
                plan["state_prestate"],
                upgrade.describe_opaque_state(
                    host / str(upgrade.STATE_ROOT).lstrip("/"),
                    expected_uid=identity[0],
                    expected_gid=identity[1],
                ),
            )
            allowed = "\n".join(plan["allowed_mutation_paths"])
            for forbidden in ("p07", "generation13", "owner-profile", "session"):
                self.assertNotIn(forbidden, allowed.casefold())

    def test_public_schema_permission_and_substitution_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = _target_release(root)
            host, identity = _synthetic_host(root)
            selector = host / str(upgrade.SELECTOR_JSON).lstrip("/")
            selector.write_text('{"schema":"unknown"}\n', "utf-8")
            selector.chmod(0o600)
            with self.assertRaises(upgrade.UpgradeRejected):
                upgrade.prepare_plan(
                    predecessor_release=PREDECESSOR,
                    target_release=target,
                    active_gateway_runtime=ACTIVE_GATEWAY,
                    root=host,
                    synthetic_identity=identity,
                    unit_state=UNIT_STATE,
                )

    def test_success_preserves_state_and_rejects_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, host, identity, plan = _plan(root)
            state = host / str(upgrade.STATE_ROOT).lstrip("/")
            before = upgrade.describe_opaque_state(
                state, expected_uid=identity[0], expected_gid=identity[1]
            )
            runner = RecordingRunner()
            receipt = upgrade.execute_plan(
                plan,
                root=host,
                synthetic_identity=identity,
                unit_state=UNIT_STATE,
                runner=runner,
            )
            self.assertEqual(receipt["status"], "target_verified")
            self.assertTrue(receipt["state_bytes_preserved"])
            self.assertEqual(
                upgrade.describe_opaque_state(
                    state, expected_uid=identity[0], expected_gid=identity[1]
                ),
                before,
            )
            self.assertEqual(
                json.loads(
                    (
                        host
                        / str(upgrade.EVIDENCE_ROOT).lstrip("/")
                        / plan["plan_digest"]
                        / "JOURNAL.json"
                    ).read_text("utf-8")
                )["stage"],
                "target_verified",
            )
            self.assertTrue(
                (
                    host
                    / str(upgrade.RELEASE_ROOT).lstrip("/")
                    / target.name
                ).is_dir()
            )
            with self.assertRaisesRegex(upgrade.UpgradeRejected, "activation_replayed"):
                upgrade.execute_plan(
                    plan,
                    root=host,
                    synthetic_identity=identity,
                    unit_state=UNIT_STATE,
                    runner=runner,
                )
            self.assertTrue(
                all(
                    upgrade.SERVICE in event or upgrade.SOCKET in event or "daemon-reload" in event
                    for event in runner.events
                )
            )

    def test_partial_failure_restores_exact_predecessor_without_p07_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, host, identity, plan = _plan(root)
            state = host / str(upgrade.STATE_ROOT).lstrip("/")
            before = upgrade.describe_opaque_state(
                state, expected_uid=identity[0], expected_gid=identity[1]
            )
            failing = (
                "/usr/bin/systemctl",
                "start",
                upgrade.SERVICE,
            )
            runner = RecordingRunner(fail_once=failing)
            with self.assertRaisesRegex(
                upgrade.UpgradeRejected, "activation_failed_rollback_verified"
            ):
                upgrade.execute_plan(
                    plan,
                    root=host,
                    synthetic_identity=identity,
                    unit_state=UNIT_STATE,
                    runner=runner,
                )
            self.assertEqual(
                upgrade.digest_file(host / str(upgrade.SELECTOR_JSON).lstrip("/")),
                upgrade.PREDECESSOR_SELECTOR_SHA256,
            )
            self.assertEqual(
                upgrade.describe_opaque_state(
                    state, expected_uid=identity[0], expected_gid=identity[1]
                ),
                before,
            )
            evidence = (
                host
                / str(upgrade.EVIDENCE_ROOT).lstrip("/")
                / plan["plan_digest"]
            )
            self.assertEqual(
                json.loads((evidence / "JOURNAL.json").read_text("utf-8"))["stage"],
                "rolled_back",
            )
            self.assertTrue(
                (
                    host
                    / str(upgrade.RELEASE_ROOT).lstrip("/")
                    / target.name
                ).is_dir()
            )

    def test_socket_stop_is_first_and_second_stop_failure_restores_predecessor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, host, identity, plan = _plan(root)
            state = host / str(upgrade.STATE_ROOT).lstrip("/")
            before = upgrade.describe_opaque_state(
                state, expected_uid=identity[0], expected_gid=identity[1]
            )
            failing = ("/usr/bin/systemctl", "stop", upgrade.SERVICE)
            runner = RecordingRunner(fail_once=failing)
            with self.assertRaisesRegex(
                upgrade.UpgradeRejected,
                "pre_target_failure_predecessor_restored",
            ):
                upgrade.execute_plan(
                    plan,
                    root=host,
                    synthetic_identity=identity,
                    unit_state=UNIT_STATE,
                    runner=runner,
                )
            self.assertEqual(
                runner.events[:2],
                [
                    ("/usr/bin/systemctl", "stop", upgrade.SOCKET),
                    ("/usr/bin/systemctl", "stop", upgrade.SERVICE),
                ],
            )
            evidence = (
                host
                / str(upgrade.EVIDENCE_ROOT).lstrip("/")
                / plan["plan_digest"]
            )
            journal = json.loads((evidence / "JOURNAL.json").read_text("utf-8"))
            self.assertLess(
                journal["events"].index("stop_started"),
                journal["events"].index("pre_target_state_preserved"),
            )
            self.assertEqual(journal["stage"], "rolled_back")
            self.assertEqual(
                upgrade.describe_opaque_state(
                    state, expected_uid=identity[0], expected_gid=identity[1]
                ),
                before,
            )
            self.assertEqual(
                upgrade.digest_file(host / str(upgrade.SELECTOR_JSON).lstrip("/")),
                upgrade.PREDECESSOR_SELECTOR_SHA256,
            )
            self.assertFalse(
                (
                    host
                    / str(upgrade.RELEASE_ROOT).lstrip("/")
                    / target.name
                ).exists()
            )

    def test_crash_after_socket_stop_before_service_stop_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, host, identity, plan = _plan(root)
            state = host / str(upgrade.STATE_ROOT).lstrip("/")
            before = upgrade.describe_opaque_state(
                state, expected_uid=identity[0], expected_gid=identity[1]
            )

            class CrashBetweenStops(RecordingRunner):
                def __call__(self, command: list[str]) -> None:
                    event = tuple(command)
                    self.events.append(event)
                    if event == ("/usr/bin/systemctl", "stop", upgrade.SERVICE):
                        raise SyntheticCrash()

            crashing = CrashBetweenStops()
            with self.assertRaises(SyntheticCrash):
                upgrade.execute_plan(
                    plan,
                    root=host,
                    synthetic_identity=identity,
                    unit_state=UNIT_STATE,
                    runner=crashing,
                )
            self.assertEqual(
                crashing.events,
                [
                    ("/usr/bin/systemctl", "stop", upgrade.SOCKET),
                    ("/usr/bin/systemctl", "stop", upgrade.SERVICE),
                ],
            )
            recovered = upgrade.recover_plan(
                plan, root=host, runner=RecordingRunner()
            )
            self.assertEqual(recovered["stage"], "rolled_back")
            self.assertEqual(
                upgrade.describe_opaque_state(
                    state, expected_uid=identity[0], expected_gid=identity[1]
                ),
                before,
            )
            self.assertEqual(
                upgrade.digest_file(host / str(upgrade.SELECTOR_JSON).lstrip("/")),
                upgrade.PREDECESSOR_SELECTOR_SHA256,
            )
            self.assertFalse(
                (
                    host
                    / str(upgrade.RELEASE_ROOT).lstrip("/")
                    / target.name
                ).exists()
            )

    def test_failure_before_stop_started_does_not_run_rollback_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, host, identity, plan = _plan(root)
            runner = RecordingRunner()

            def hook(stage: str) -> None:
                if stage == "public_backup_verified":
                    raise upgrade.UpgradeRejected("synthetic_pre_mutation_failure")

            with self.assertRaisesRegex(upgrade.UpgradeRejected, "pre_attempt_failed"):
                upgrade.execute_plan(
                    plan,
                    root=host,
                    synthetic_identity=identity,
                    unit_state=UNIT_STATE,
                    runner=runner,
                    stage_hook=hook,
                )
            self.assertEqual(runner.events, [])
            self.assertEqual(
                upgrade.digest_file(host / str(upgrade.SELECTOR_JSON).lstrip("/")),
                upgrade.PREDECESSOR_SELECTOR_SHA256,
            )
            self.assertFalse(
                (
                    host
                    / str(upgrade.RELEASE_ROOT).lstrip("/")
                    / target.name
                ).exists()
            )

    def test_public_backup_readback_rejects_extra_missing_mode_and_source_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, host, _, plan = _plan(root)
            backup = root / "public-backup"
            upgrade._copy_public_backup(host, backup, plan)
            upgrade._validate_public_backup(backup, plan)

            extra = backup / "extra"
            extra.write_bytes(b"synthetic")
            with self.assertRaisesRegex(upgrade.UpgradeRejected, "public_backup_rejected"):
                upgrade._validate_public_backup(backup, plan)
            extra.unlink()

            selected = next(
                path for path in backup.iterdir() if path.name != "PUBLIC.json"
            )
            original = selected.read_bytes()
            selected.write_bytes(original + b"drift")
            with self.assertRaisesRegex(upgrade.UpgradeRejected, "public_backup_rejected"):
                upgrade._validate_public_backup(backup, plan)
            selected.write_bytes(original)
            selected.chmod(0o600 if stat.S_IMODE(selected.stat().st_mode) != 0o600 else 0o644)
            with self.assertRaisesRegex(upgrade.UpgradeRejected, "public_backup_rejected"):
                upgrade._validate_public_backup(backup, plan)
            selected.unlink()
            with self.assertRaisesRegex(upgrade.UpgradeRejected, "public_backup_rejected"):
                upgrade._validate_public_backup(backup, plan)

        if os.geteuid() == 0:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _, host, _, plan = _plan(root)
                backup = root / "public-backup"
                upgrade._copy_public_backup(host, backup, plan)
                selected = next(
                    path for path in backup.iterdir() if path.name != "PUBLIC.json"
                )
                os.chown(selected, 1, 1)
                with self.assertRaisesRegex(
                    upgrade.UpgradeRejected, "public_backup_rejected"
                ):
                    upgrade._validate_public_backup(backup, plan)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, host, _, plan = _plan(root)
            backup = root / "public-backup"
            original_write = upgrade._exclusive_write
            mutated = False

            def drifting_write(
                path: Path,
                payload: bytes,
                *,
                mode: int,
                uid: int | None = None,
                gid: int | None = None,
            ) -> None:
                nonlocal mutated
                original_write(path, payload, mode=mode, uid=uid, gid=gid)
                if path.name != "PUBLIC.json" and not mutated:
                    mutated = True
                    source = host / str(upgrade.SELECTOR_JSON).lstrip("/")
                    source.write_bytes(source.read_bytes() + b" ")
                    source.chmod(0o600)

            with mock.patch.object(upgrade, "_exclusive_write", drifting_write):
                with self.assertRaisesRegex(
                    upgrade.UpgradeRejected, "public_prestate_drifted"
                ):
                    upgrade._copy_public_backup(host, backup, plan)

    def test_public_backup_modes_ignore_caller_umask_and_read_back_exactly(self) -> None:
        for mask in (0o022, 0o077):
            with self.subTest(umask=oct(mask)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _, host, _, plan = _plan(root)
                backup = root / "public-backup"
                previous = os.umask(mask)
                try:
                    upgrade._copy_public_backup(host, backup, plan)
                finally:
                    os.umask(previous)
                upgrade._validate_public_backup(backup, plan)
                expected = plan["public_prestate"]
                observed_modes: dict[str, int] = {}
                for text, projection in expected.items():
                    name = upgrade.digest_bytes(text.encode("ascii"))
                    path = backup / name
                    metadata = path.lstat()
                    observed_modes[text] = stat.S_IMODE(metadata.st_mode)
                    self.assertEqual(observed_modes[text], projection["mode"])
                    self.assertEqual(metadata.st_uid, projection["uid"])
                    self.assertEqual(metadata.st_gid, projection["gid"])
                    self.assertEqual(metadata.st_nlink, 1)
                    self.assertEqual(metadata.st_size, projection["size"])
                    self.assertEqual(upgrade.digest_file(path), projection["sha256"])
                self.assertEqual(
                    sorted(observed_modes.values()),
                    [0o600, 0o600, 0o644, 0o644],
                )
                self.assertEqual(list(backup.glob(".*.stage")), [])

    def test_exclusive_write_is_no_replace_and_rejects_residue_and_concurrency(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "exact"
            previous = os.umask(0o077)
            try:
                upgrade._exclusive_write(target, b"exact-bytes", mode=0o644)
            finally:
                os.umask(previous)
            metadata = target.lstat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o644)
            self.assertEqual(metadata.st_nlink, 1)
            self.assertEqual(target.read_bytes(), b"exact-bytes")
            with self.assertRaisesRegex(upgrade.UpgradeRejected, "exclusive_write_target_exists"):
                upgrade._exclusive_write(target, b"replacement", mode=0o600)

            residue_target = root / "residue"
            (root / ".residue.synthetic.stage").write_bytes(b"partial")
            with self.assertRaisesRegex(
                upgrade.UpgradeRejected, "exclusive_write_residue_rejected"
            ):
                upgrade._exclusive_write(residue_target, b"new", mode=0o600)
            self.assertFalse(residue_target.exists())

            concurrent = root / "concurrent"
            barrier = threading.Barrier(2)
            outcomes: list[str] = []

            def write(payload: bytes) -> None:
                barrier.wait()
                try:
                    upgrade._exclusive_write(concurrent, payload, mode=0o600)
                    outcomes.append("written")
                except upgrade.UpgradeRejected as exc:
                    outcomes.append(exc.code)

            workers = [
                threading.Thread(target=write, args=(b"first",)),
                threading.Thread(target=write, args=(b"second",)),
            ]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=10)
            self.assertEqual(outcomes.count("written"), 1)
            self.assertEqual(len(outcomes), 2)
            self.assertTrue(
                any(
                    code
                    in {
                        "exclusive_write_target_exists",
                        "exclusive_write_residue_rejected",
                    }
                    for code in outcomes
                    if code != "written"
                )
            )
            self.assertIn(concurrent.read_bytes(), {b"first", b"second"})
            self.assertEqual(stat.S_IMODE(concurrent.stat().st_mode), 0o600)
            self.assertEqual(concurrent.stat().st_nlink, 1)
            self.assertEqual(list(root.glob(".concurrent.*.stage")), [])

    def test_state_advance_before_backup_is_preserved_and_target_not_selected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, host, identity, plan = _plan(root)
            state = host / str(upgrade.STATE_ROOT).lstrip("/")
            advanced = b"opaque-owner-progress-after-plan"
            injected = False

            def hook(stage: str) -> None:
                nonlocal injected
                if stage == "services_stopped" and not injected:
                    injected = True
                    evidence = (
                        host
                        / str(upgrade.EVIDENCE_ROOT).lstrip("/")
                        / plan["plan_digest"]
                    )
                    upgrade.backup_opaque_state(
                        source=state,
                        backup=evidence / "state",
                        expected=plan["state_prestate"],
                        expected_uid=identity[0],
                        expected_gid=identity[1],
                    )
                    selected = state / upgrade.STATE_FILES[0]
                    selected.write_bytes(advanced)
                    selected.chmod(0o600)

            with self.assertRaisesRegex(
                upgrade.UpgradeRejected, "pre_target_state_drift_preserved"
            ):
                upgrade.execute_plan(
                    plan,
                    root=host,
                    synthetic_identity=identity,
                    unit_state=UNIT_STATE,
                    runner=RecordingRunner(),
                    stage_hook=hook,
                )
            self.assertEqual((state / upgrade.STATE_FILES[0]).read_bytes(), advanced)
            self.assertEqual(
                upgrade.digest_file(host / str(upgrade.SELECTOR_JSON).lstrip("/")),
                upgrade.PREDECESSOR_SELECTOR_SHA256,
            )
            self.assertFalse(
                (
                    host
                    / str(upgrade.RELEASE_ROOT).lstrip("/")
                    / target.name
                ).exists()
            )
            evidence = (
                host
                / str(upgrade.EVIDENCE_ROOT).lstrip("/")
                / plan["plan_digest"]
            )
            self.assertFalse((evidence / "state/displaced-state-tree").exists())
            journal = json.loads((evidence / "JOURNAL.json").read_text("utf-8"))
            self.assertIn("pre_target_state_preserved", journal["events"])
            self.assertEqual(journal["stage"], "rolled_back")

    def test_semantically_reconstructed_plans_and_evidence_plan_drift_are_rejected(self) -> None:
        mutations = (
            lambda plan: plan["allowed_mutation_paths"].append("/tmp/not-p08"),
            lambda plan: plan["public_prestate"].pop(str(upgrade.SELECTOR_ENV)),
            lambda plan: plan["predecessor"].__setitem__("release_path", "/tmp/predecessor"),
            lambda plan: plan["target"].__setitem__("release_target", "/tmp/target"),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                _, _, _, plan = _plan(Path(directory))
                selected = json.loads(json.dumps(plan))
                mutate(selected)
                rebound = _rebind_plan(selected)
                with self.assertRaises(upgrade.UpgradeRejected):
                    upgrade.validate_plan(rebound)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, host, identity, plan = _plan(root)

            def hook(stage: str) -> None:
                if stage == "prepared":
                    raise SyntheticCrash()

            with self.assertRaises(SyntheticCrash):
                upgrade.execute_plan(
                    plan,
                    root=host,
                    synthetic_identity=identity,
                    unit_state=UNIT_STATE,
                    runner=RecordingRunner(),
                    stage_hook=hook,
                )
            evidence = (
                host
                / str(upgrade.EVIDENCE_ROOT).lstrip("/")
                / plan["plan_digest"]
            )
            (evidence / "PLAN.json").write_bytes(b"{}")
            with self.assertRaisesRegex(upgrade.UpgradeRejected, "evidence_plan_rejected"):
                upgrade.recover_plan(plan, root=host, runner=RecordingRunner())

    def test_crash_journal_recovers_and_rollback_replay_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, host, identity, plan = _plan(root)
            crashed = False

            def hook(stage: str) -> None:
                nonlocal crashed
                if stage == "selector_applied" and not crashed:
                    crashed = True
                    raise SyntheticCrash()

            with self.assertRaises(SyntheticCrash):
                upgrade.execute_plan(
                    plan,
                    root=host,
                    synthetic_identity=identity,
                    unit_state=UNIT_STATE,
                    runner=RecordingRunner(),
                    stage_hook=hook,
                )
            recovered = upgrade.recover_plan(
                plan,
                root=host,
                runner=RecordingRunner(),
            )
            self.assertEqual(recovered["stage"], "rolled_back")
            self.assertEqual(
                upgrade.digest_file(host / str(upgrade.SELECTOR_JSON).lstrip("/")),
                upgrade.PREDECESSOR_SELECTOR_SHA256,
            )
            with self.assertRaisesRegex(upgrade.UpgradeRejected, "rollback_replayed"):
                upgrade.recover_plan(
                    plan,
                    root=host,
                    runner=RecordingRunner(),
                )

    def test_crash_before_state_backup_recovers_without_reading_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, host, identity, plan = _plan(root)

            def hook(stage: str) -> None:
                if stage == "services_stopped":
                    raise SyntheticCrash()

            with self.assertRaises(SyntheticCrash):
                upgrade.execute_plan(
                    plan,
                    root=host,
                    synthetic_identity=identity,
                    unit_state=UNIT_STATE,
                    runner=RecordingRunner(),
                    stage_hook=hook,
                )
            recovered = upgrade.recover_plan(
                plan,
                root=host,
                runner=RecordingRunner(),
            )
            self.assertEqual(recovered["stage"], "rolled_back")
            self.assertFalse(
                (
                    host
                    / str(upgrade.EVIDENCE_ROOT).lstrip("/")
                    / plan["plan_digest"]
                    / "state"
                ).exists()
            )

    def test_target_state_drift_is_preserved_then_exactly_restored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, host, identity, plan = _plan(root)
            state = host / str(upgrade.STATE_ROOT).lstrip("/")
            before = plan["state_prestate"]
            injected = False

            def hook(stage: str) -> None:
                nonlocal injected
                if stage == "target_started" and not injected:
                    injected = True
                    target = state / upgrade.STATE_FILES[0]
                    target.write_bytes(b"synthetic-target-drift")
                    target.chmod(0o600)
                    raise upgrade.UpgradeRejected("synthetic_target_state_drift")

            with self.assertRaisesRegex(
                upgrade.UpgradeRejected, "activation_failed_rollback_verified"
            ):
                upgrade.execute_plan(
                    plan,
                    root=host,
                    synthetic_identity=identity,
                    unit_state=UNIT_STATE,
                    runner=RecordingRunner(),
                    stage_hook=hook,
                )
            self.assertEqual(
                upgrade.describe_opaque_state(
                    state, expected_uid=identity[0], expected_gid=identity[1]
                ),
                before,
            )
            evidence = (
                host
                / str(upgrade.EVIDENCE_ROOT).lstrip("/")
                / plan["plan_digest"]
            )
            self.assertTrue((evidence / "state/displaced-state-tree").is_dir())
            self.assertTrue((evidence / "state/displaced-copy/STATE.json").is_file())

    def test_corrupt_journal_and_unknown_plan_schema_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, host, identity, plan = _plan(root)
            bad = dict(plan)
            bad["schema"] = "unknown"
            with self.assertRaisesRegex(upgrade.UpgradeRejected, "plan_schema_rejected"):
                upgrade.validate_plan(bad)

            def hook(stage: str) -> None:
                if stage == "prepared":
                    raise SyntheticCrash()

            with self.assertRaises(SyntheticCrash):
                upgrade.execute_plan(
                    plan,
                    root=host,
                    synthetic_identity=identity,
                    unit_state=UNIT_STATE,
                    runner=RecordingRunner(),
                    stage_hook=hook,
                )
            journal = (
                host
                / str(upgrade.EVIDENCE_ROOT).lstrip("/")
                / plan["plan_digest"]
                / "JOURNAL.json"
            )
            journal.write_bytes(b"{malformed")
            with self.assertRaisesRegex(upgrade.UpgradeRejected, "journal_rejected"):
                upgrade.recover_plan(plan, root=host, runner=RecordingRunner())

    def test_source_contains_no_private_parser_or_other_program_mutator(self) -> None:
        source = (SCRIPTS / "p08_existing_state_upgrade_v1.py").read_text("utf-8")
        self.assertNotIn("import sqlite3", source)
        for forbidden in (
            "telegram_owner_runtime_gateway.py",
            "activate_p08_p07_generation13_v1",
            "owner_profile.sqlite",
            "session-context.sqlite",
            "myuna-qq-owner-runtime",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
