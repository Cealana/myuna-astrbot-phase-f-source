from __future__ import annotations

from dataclasses import replace
import ast
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, (ROOT / "scripts").as_posix())
MODULE_PATH = ROOT / "scripts" / "telegram_r5_boot_resume.py"
SPEC = importlib.util.spec_from_file_location("telegram_r5_boot_resume", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


GATEWAY = "8de31f75e2dae6f9d65512660c86ea7d60c1ba6add45006b7bcccb0db68510ab"


def payload() -> dict[str, str]:
    root = f"/opt/myuna/telegram-gateway/releases/{GATEWAY}"
    return {
        "channel_root": "/srv/myuna/channels/astrbot-telegram/dev",
        "compose_file": f"{root}/channels/astrbot-telegram/compose.dev.yml",
        "gateway_release": GATEWAY,
        "plugin_root": (
            f"{root}/channels/astrbot-telegram/plugin/myuna_telegram_gateway"
        ),
        "schema": module.SCHEMA,
    }


class TelegramR5ResumeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compatibility_gate = mock.patch.object(
            module, "_phase_f_require_runtime_compatibility"
        )
        self.compatibility_gate.start()
        self.addCleanup(self.compatibility_gate.stop)

    @staticmethod
    def network(*members: str) -> module.PhaseFNetworkProjection:
        return module.PhaseFNetworkProjection(
            network_id="network-object-1",
            name=module.NETWORK,
            driver="bridge",
            internal=False,
            attachable=False,
            ingress=False,
            enable_ipv6=False,
            options_digest="1" * 64,
            labels_digest="2" * 64,
            ipam_digest="3" * 64,
            member_container_ids=tuple(sorted(members)),
        )

    @staticmethod
    def container(
        *,
        container_id: str = "old-object-1",
        name: str = module.CONTAINER,
        status: str = "running",
        health: str = "healthy",
        policy: str = "on-failure",
        policy_maximum: int = 3,
        plan_digest: str = "",
        target_config_digest: str = "",
        image: str = module.EXPECTED_IMAGE,
    ) -> module.PhaseFContainerProjection:
        return module.PhaseFContainerProjection(
            container_id=container_id, name=name, image=image,
            status=status, health=health, restart_policy=policy,
            restart_maximum_retry_count=policy_maximum,
            project=module.COMPOSE_PROJECT, service=module.COMPOSE_SERVICE,
            plan_digest=plan_digest, target_config_digest=target_config_digest,
            user="988:982", command_digest="4" * 64,
            host_config_digest="5" * 64, mounts_digest="6" * 64,
            networks_digest="7" * 64, network_names=(module.NETWORK,),
        )

    @staticmethod
    def target() -> module.PhaseFTargetContainer:
        plan = "bed60d0c4f567e389d0c5aa54b0300944f668c577b70d07ad268c9cec653d21a"
        return module.PhaseFTargetContainer(
            plan_digest=plan, target_config_digest="9" * 64,
            image=module.EXPECTED_IMAGE_PREFIX + "f" * 64, user="988:982",
            channel_root=Path("/srv/myuna/channels/astrbot-telegram/dev"),
            plugin_root=Path("/opt/myuna/release/plugin"),
            signing_secret=Path("/run/secrets/signing"),
            runtime_root=Path("/run/myuna-telegram-gateway"),
            media_auth_runtime_root=Path("/run/myuna-telegram-media-auth"),
            archive_name=f"{module.ARCHIVE_PREFIX}34a0e759e6fc7729",
        )

    @staticmethod
    def target_effect(
        target: module.PhaseFTargetContainer,
        network: module.PhaseFNetworkProjection,
        archive: module.PhaseFContainerProjection,
    ) -> dict[str, object]:
        body: dict[str, object] = {
            "archive_container_id": archive.container_id,
            "archive_name": target.archive_name,
            "archive_projection_sha256": module.phase_f_container_identity_sha256(archive),
            "attempt": 5,
            "command": {"command": ["python", "main.py"], "entrypoint": None},
            "container_name": module.CONTAINER,
            "environment": module._phase_f_effect_environment(),
            "host": module._phase_f_effect_host(target.user),
            "image": target.image,
            "mounts": module._phase_f_effect_mounts(target),
            "network_name": module.NETWORK,
            "network_projection_sha256": module.phase_f_network_identity_sha256(network),
            "plan_digest": module.ATTEMPT5_ENTRY_PLAN_SHA256,
            "project": module.COMPOSE_PROJECT,
            "service": module.COMPOSE_SERVICE,
            "target_config_digest": target.target_config_digest,
            "user": target.user,
            "writer": False,
        }
        body["command_sha256"] = module._phase_f_digest(
            "myuna.phase-f.container-command.v1", body["command"]
        )
        body["environment_sha256"] = module._phase_f_digest(
            "phase_f_attempt5_target_environment_v1",
            sorted(body["environment"]["explicit"]),
        )
        body["host_sha256"] = module._phase_f_digest(
            "phase_f_attempt5_target_host_v1", body["host"]
        )
        body["mounts_sha256"] = module._phase_f_digest(
            "phase_f_attempt5_target_mounts_v1", body["mounts"]
        )
        body["network_sha256"] = module._phase_f_digest(
            "phase_f_attempt5_target_network_v1",
            {"name": body["network_name"], "projection_sha256": body["network_projection_sha256"]},
        )
        body["create_arguments_sha256"] = module._phase_f_digest(
            "phase_f_attempt5_target_create_arguments_v1",
            module._phase_f_base_create_arguments(target),
        )
        return {**body, "effect_sha256": module._phase_f_digest("phase_f_attempt5_target_effect_v1", body)}

    def test_runtime_compatibility_admission_uses_exact_numeric_platform_semantics(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            channel = root / "channel"
            data = channel / "astrbot-data"
            plugin = root / "plugin"
            secret = root / "signing"
            runtime = root / "runtime"
            media = root / "media"
            channel.mkdir(mode=0o755)
            data.mkdir(mode=0o700)
            plugin.mkdir(mode=0o550)
            secret.write_bytes(b"generated-synthetic\n")
            secret.chmod(0o400)
            runtime.mkdir(mode=0o750)
            media.mkdir(mode=0o750)
            socket_path = runtime / "owner.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(socket_path.as_posix())
            socket_path.chmod(0o660)
            for path, uid, gid in (
                (data, 988, 982),
                (plugin, 0, 982),
                (secret, 988, 982),
                (runtime, 0, 982),
                (media, 988, 982),
                (socket_path, 0, 982),
            ):
                os.chown(path, uid, gid, follow_symlinks=False)
            target = module.PhaseFTargetContainer(
                plan_digest=module.ATTEMPT5_ENTRY_PLAN_SHA256,
                target_config_digest="9" * 64,
                image=module.EXPECTED_IMAGE_PREFIX + "f" * 64,
                user="988:982",
                channel_root=channel,
                plugin_root=plugin,
                signing_secret=secret,
                runtime_root=runtime,
                media_auth_runtime_root=media,
                archive_name=f"{module.ARCHIVE_PREFIX}{'a' * 16}",
            )
            network = self.network()
            archived = replace(
                self.container(status="exited", health=""),
                name=target.archive_name,
            )
            target = replace(
                target,
                effect=self.target_effect(target, network, archived),
            )
            calls: list[list[str]] = []

            def runner(arguments: list[str], **_kwargs: object) -> str:
                calls.append(arguments)
                return json.dumps(["name=seccomp,profile=default"])

            try:
                exact = module._phase_f_runtime_access_projection(
                    target,
                    runner=runner,
                )
                old = module._phase_f_runtime_access_projection(
                    target,
                    runner=runner,
                    probe_uid=1000,
                    probe_gid=1000,
                )
                self.assertTrue(all(exact.values()))
                self.assertFalse(any(old.values()))
                self.assertTrue(all(call[:2] == ["/usr/bin/docker", "info"] for call in calls))

                for path, uid, gid, mode in (
                    (data, 988, 982, 0o700),
                    (plugin, 0, 982, 0o550),
                    (secret, 988, 982, 0o400),
                    (runtime, 0, 982, 0o750),
                    (media, 988, 982, 0o750),
                    (socket_path, 0, 982, 0o660),
                ):
                    with self.subTest(role=path.name, hostile="mode"):
                        path.chmod(mode ^ 0o001)
                        with self.assertRaisesRegex(
                            module.ResumeRejected,
                            "phase_f_runtime_resource_metadata_rejected",
                        ):
                            module._phase_f_runtime_access_projection(target, runner=runner)
                        path.chmod(mode)
                    with self.subTest(role=path.name, hostile="identity"):
                        os.chown(path, uid + 1, gid, follow_symlinks=False)
                        with self.assertRaisesRegex(
                            module.ResumeRejected,
                            "phase_f_runtime_resource_metadata_rejected",
                        ):
                            module._phase_f_runtime_access_projection(target, runner=runner)
                        os.chown(path, uid, gid, follow_symlinks=False)
                with mock.patch.object(
                    module.os,
                    "getxattr",
                    return_value=b"named-acl",
                ), self.assertRaisesRegex(
                    module.ResumeRejected,
                    "phase_f_runtime_resource_acl_rejected",
                ):
                    module._phase_f_runtime_access_projection(target, runner=runner)
                with self.assertRaisesRegex(
                    module.ResumeRejected,
                    "phase_f_runtime_identity_model_rejected",
                ):
                    module._phase_f_runtime_access_projection(
                        target,
                        runner=lambda _args, **_kw: json.dumps(["name=userns"]),
                    )
            finally:
                listener.close()

    @staticmethod
    def container_inspect_output(
        mounts: object, *, status: str = "running", health: str | None = "healthy"
    ) -> str:
        state: dict[str, object] = {"Status": status}
        if health is not None:
            state["Health"] = {"Status": health}
        values = (
            "container-object-1",
            f"/{module.CONTAINER}",
            module.EXPECTED_IMAGE,
            status,
            state,
            module.EXPECTED_RESTART_POLICY,
            module.EXPECTED_RESTART_MAXIMUM_RETRY_COUNT,
            module.COMPOSE_PROJECT,
            module.COMPOSE_SERVICE,
            None,
            None,
            None,
            "988:982",
            ["entrypoint"],
            ["command"],
            [
                "HOME=/AstrBot/data/home",
                "MYUNA_GATEWAY_CHANNEL_INSTANCE=telegram-owner-dev",
                "MYUNA_GATEWAY_SIGNING_SECRET=/run/secrets/myuna-telegram-channel-signing-v1",
                "MYUNA_GATEWAY_SOCKET=/run/myuna-telegram-gateway/owner.sock",
                "MYUNA_MEDIA_SHADOW_SOCKET=/run/myuna-telegram-media-auth/shadow.sock",
                "PYTHONDONTWRITEBYTECODE=1",
                "TZ=Asia/Shanghai",
            ],
            {
                "Test": ["CMD-SHELL", "python -c \"import socket; s=socket.create_connection(('127.0.0.1',6185),3); s.close()\""],
                "Interval": 15_000_000_000,
                "Retries": 12,
                "StartPeriod": 45_000_000_000,
                "Timeout": 5_000_000_000,
            },
            30,
            {
                "ReadonlyRootfs": True,
                "RestartPolicy": {
                    "MaximumRetryCount": module.EXPECTED_RESTART_MAXIMUM_RETRY_COUNT,
                    "Name": module.EXPECTED_RESTART_POLICY,
                },
            },
            mounts,
            {module.NETWORK: {"IPAddress": "172.18.0.2"}},
        )
        return "\n".join(
            json.dumps(value, sort_keys=True, separators=(",", ":"))
            for value in values
        )

    def test_exact_target_enters_fixed_owner_before_direct_effects(self) -> None:
        selected = {
            module.CONTROLLER_RELEASE_ENV: "1" * 64,
            module.CONTROLLER_CONFIG_ENV: "2" * 64,
            module.CONTROLLER_AUTHORITY_ENV: "3" * 64,
        }
        with mock.patch.dict(module.os.environ, selected, clear=True), mock.patch.object(
            module, "verify_fixed_controller_release", return_value={}
        ) as verify, mock.patch(
            "activate_p07_owner_private_memory_v1.fixed_owner_entry",
            return_value=75,
        ) as owner, mock.patch.object(module, "read_config") as read_config, mock.patch.object(
            module, "run"
        ) as run:
            self.assertEqual(module.main(), 75)
        verify.assert_called_once_with(MODULE_PATH.parent)
        owner.assert_called_once_with()
        read_config.assert_not_called()
        run.assert_not_called()
        self.assertIn(
            "activate_p07_owner_private_memory_v1.run_checkpointed_stage",
            module.FIXED_OWNER_CHAIN,
        )
        self.assertNotIn(
            "activate_p07_owner_private_memory_v1.run_fixed_product_activation",
            module.FIXED_OWNER_CHAIN,
        )

    def test_generic_non_target_preserves_generation13_owner(self) -> None:
        with mock.patch.dict(module.os.environ, {}, clear=True), mock.patch(
            "activate_p07_d_generation13_v1.controller_entry",
            return_value=75,
        ) as owner, mock.patch.object(
            module, "verify_fixed_controller_release"
        ) as verify:
            self.assertEqual(module.main(), 75)
        owner.assert_called_once_with()
        verify.assert_not_called()

    def test_exact_config_is_accepted(self) -> None:
        config = module.ResumeConfig.from_payload(payload())
        self.assertEqual(config.gateway_release, GATEWAY)
        self.assertEqual(config.channel_root.as_posix(), payload()["channel_root"])

    def test_unknown_key_and_mutable_paths_fail_closed(self) -> None:
        extra = payload()
        extra["extra"] = "rejected"
        with self.assertRaises(module.ResumeRejected):
            module.ResumeConfig.from_payload(extra)
        for key, value in (
            ("compose_file", "/opt/myuna/telegram-gateway/current/compose.dev.yml"),
            ("plugin_root", "/srv/myuna/repos/deploy/plugin"),
            ("channel_root", "/srv/myuna/channels/other"),
            ("gateway_release", "short"),
        ):
            changed = payload()
            changed[key] = value
            with self.assertRaises(module.ResumeRejected):
                module.ResumeConfig.from_payload(changed)

    def test_canonical_receipt_is_stable(self) -> None:
        first = module.canonical({"status": "ok", "schema": "test"})
        second = module.canonical({"schema": "test", "status": "ok"})
        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))

    def test_compose_environment_is_complete_and_project_pinned(self) -> None:
        config = module.ResumeConfig.from_payload(payload())
        environment = module.compose_environment(config, 1001, 1002)
        self.assertEqual(
            environment["CHANNEL_MEDIA_AUTH_RUNTIME_ROOT"],
            "/run/myuna-telegram-media-auth",
        )
        self.assertEqual(environment["COMPOSE_PROJECT_NAME"], module.COMPOSE_PROJECT)

    def test_core_readiness_is_tcp_only(self) -> None:
        with mock.patch.object(module.socket, "create_connection") as connection:
            connection.return_value.__enter__.return_value = object()
            self.assertTrue(module.core_transport_ready())
            connection.assert_called_once_with(("127.0.0.1", 18081), timeout=3)
        text = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("/healthz", text)
        self.assertNotIn("/readyz", text)
        self.assertNotIn("http.client", text)

    def test_managed_and_archived_container_contracts(self) -> None:
        managed = module.ContainerRecord(
            name=module.CONTAINER,
            status="exited",
            project=module.COMPOSE_PROJECT,
            service=module.COMPOSE_SERVICE,
            restart_policy=module.EXPECTED_RESTART_POLICY,
            restart_maximum_retry_count=3,
        )
        archived = module.ContainerRecord(
            name=f"{module.ARCHIVE_PREFIX}20260730T000000",
            status="exited",
            project="historical-project",
            service=module.COMPOSE_SERVICE,
            restart_policy="no",
            restart_maximum_retry_count=0,
        )
        module.validate_container_inventory((managed, archived))
        with self.assertRaises(module.ResumeRejected):
            module.validate_container_inventory(
                (
                    archived.__class__(
                        **{
                            **archived.__dict__,
                            "restart_policy": "unless-stopped",
                        }
                    ),
                )
            )
        with self.assertRaises(module.ResumeRejected):
            module.validate_container_inventory(
                (
                    managed.__class__(
                        **{
                            **managed.__dict__,
                            "project": "unexpected-project",
                        }
                    ),
                )
            )

    def test_exact_empty_docker_placeholder_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "container-channel-signing-v1"
            path.mkdir(mode=0o755)
            module.clear_docker_created_placeholder(path)
            self.assertFalse(path.exists())

    def test_nonempty_or_symlink_placeholder_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nonempty = root / "nonempty"
            nonempty.mkdir(mode=0o755)
            (nonempty / "unexpected").write_text("x", encoding="utf-8")
            with self.assertRaises(module.ResumeRejected):
                module.clear_docker_created_placeholder(nonempty)
            target = root / "target"
            target.mkdir()
            symlink = root / "symlink"
            symlink.symlink_to(target, target_is_directory=True)
            with self.assertRaises(module.ResumeRejected):
                module.clear_docker_created_placeholder(symlink)

    def test_read_config_requires_root_owned_0600_metadata_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.json"
            path.write_text(json.dumps(payload()), encoding="utf-8")
            path.chmod(0o644)
            with self.assertRaises(module.ResumeRejected):
                module.read_config(path)

    def test_protected_directory_requires_exact_owner_mode_and_real_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "runtime"
            path.mkdir(mode=0o750)
            path.chmod(0o750)
            metadata = path.stat()
            self.assertTrue(
                module.protected_directory(
                    path,
                    0o750,
                    uid=metadata.st_uid,
                    gid=metadata.st_gid,
                )
            )
            self.assertFalse(
                module.protected_directory(
                    path,
                    0o700,
                    uid=metadata.st_uid,
                    gid=metadata.st_gid,
                )
            )
            symlink = root / "runtime-link"
            symlink.symlink_to(path, target_is_directory=True)
            self.assertFalse(
                module.protected_directory(
                    symlink,
                    0o750,
                    uid=metadata.st_uid,
                    gid=metadata.st_gid,
                )
            )

    def test_stage_one_entry_does_not_mutate_media_runtime_root(self) -> None:
        text = MODULE_PATH.read_text(encoding="utf-8")
        tree = ast.parse(text)
        entry_source = "\n".join(
            ast.get_source_segment(text, node) or ""
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name in {"main", "_retired_direct_resume"}
        )
        self.assertNotIn("MEDIA_AUTH_RUNTIME_ROOT", entry_source)
        self.assertNotIn("mkdir", entry_source)
        self.assertNotIn("systemctl", entry_source)

    def test_unit_is_bounded_and_has_no_shell(self) -> None:
        text = (
            ROOT
            / "systemd"
            / "myuna-telegram-owner-r5-resume.service"
        ).read_text(encoding="utf-8")
        self.assertIn("StartLimitBurst=3", text)
        self.assertIn("Restart=on-failure", text)
        self.assertIn("RestartSec=60s", text)
        self.assertIn("RemainAfterExit=yes", text)
        self.assertIn("WantedBy=multi-user.target", text)
        self.assertIn("myuna-core@qq.service", text)
        self.assertIn("Environment=PYTHONDONTWRITEBYTECODE=1", text)
        self.assertEqual(text.count("ExecStart="), 1)
        self.assertNotIn("/bin/sh", text)
        self.assertNotIn("/bin/bash", text)
        self.assertNotIn("ExecStartPre=", text)

    def test_script_has_no_arbitrary_cli_or_message_model_path(self) -> None:
        text = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("argparse", text)
        self.assertNotIn("shell=True", text)
        self.assertNotIn("sendMessage", text)
        self.assertNotIn("chat/completions", text)
        self.assertNotIn("OPENAI_API_KEY", text)
        self.assertNotIn("DEEPSEEK_API_KEY", text)
        tree = ast.parse(text)
        retired = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "_retired_direct_resume"
        )
        self.assertEqual(len(retired.body), 2)
        self.assertIsInstance(retired.body[-1], ast.Raise)
        self.assertIn("phase_f_direct_resume_retired", text)
        self.assertIn("return controller_entry()", text)
        self.assertNotIn('run(["/usr/bin/systemctl", "start", RUNTIME_SERVICE])', text)

    def test_compose_restart_policy_defers_cold_boot_to_r5(self) -> None:
        text = (
            ROOT / "channels" / "astrbot-telegram" / "compose.dev.yml"
        ).read_text(encoding="utf-8")
        self.assertIn('restart: "on-failure:3"', text)
        self.assertNotIn("restart: unless-stopped", text)
        self.assertIn("external: true", text)
        self.assertIn("name: myuna-astrbot-telegram-dev", text)
        self.assertNotIn("driver: bridge", text)

    def test_container_mount_projection_is_complete_and_order_independent(self) -> None:
        first = {
            "Destination": "/target/a",
            "Mode": "ro",
            "Opaque": {"nested": [1, True, None]},
            "Propagation": "rprivate",
            "RW": False,
            "Source": "/source/a",
            "Type": "bind",
        }
        second = {
            "Destination": "/target/b",
            "Mode": "rw",
            "Propagation": "rprivate",
            "RW": True,
            "Source": "/source/b",
            "Type": "bind",
        }
        mounts = [first, second, second]
        reordered = [second, first, second]
        projections = []
        for value in (mounts, reordered):
            output = self.container_inspect_output(value)
            projected = module.phase_f_container_projection(
                module.CONTAINER,
                runner=lambda _args, **_kwargs: output,
            )
            self.assertIsNotNone(projected)
            projections.append(projected)
        self.assertEqual(projections[0].mounts_digest, projections[1].mounts_digest)

    def test_container_projection_uses_only_canonical_stdout(self) -> None:
        mounts = [
            {
                "Destination": "/target/a",
                "Mode": "ro",
                "Propagation": "rprivate",
                "RW": False,
                "Source": "/source/a",
                "Type": "bind",
            }
        ]
        output = self.container_inspect_output(mounts)

        def project(stderr: str) -> module.PhaseFContainerProjection | None:
            completed = mock.Mock(returncode=0, stdout=output, stderr=stderr)
            with mock.patch.object(module.subprocess, "run", return_value=completed) as invoke:
                result = module.phase_f_container_projection(module.CONTAINER)
            self.assertEqual(invoke.call_args.kwargs["stdout"], module.subprocess.PIPE)
            self.assertEqual(invoke.call_args.kwargs["stderr"], module.subprocess.PIPE)
            return result

        self.assertEqual(project(""), project("benign docker diagnostic\n"))

    def test_created_health_absence_and_zero_secret_projection_are_state_bound(self) -> None:
        output = self.container_inspect_output([], status="created", health=None)
        projected = module.phase_f_container_projection(
            module.CONTAINER,
            runner=lambda _args, **_kwargs: output,
        )
        self.assertIsNotNone(projected)
        assert projected is not None
        self.assertEqual(projected.health, "")

        running_without_health = self.container_inspect_output([], health=None)
        with self.assertRaisesRegex(
            module.ResumeRejected, "phase_f_container_health_rejected"
        ):
            module.phase_f_container_projection(
                module.CONTAINER,
                runner=lambda _args, **_kwargs: running_without_health,
            )

        secret = "UNRELATED_SECRET=must-not-escape"
        rows = self.container_inspect_output([]).splitlines()
        environment = json.loads(rows[15])
        environment.append(secret)
        rows[15] = json.dumps(environment, sort_keys=True, separators=(",", ":"))
        projected = module.phase_f_container_projection(
            module.CONTAINER,
            runner=lambda _args, **_kwargs: "\n".join(rows),
        )
        self.assertNotIn(secret, repr(projected))

        rows[4] = json.dumps({"Health": {"Status": 1}, "Status": "running"})
        with self.assertRaisesRegex(
            module.ResumeRejected, "phase_f_container_health_rejected"
        ):
            module.phase_f_container_projection(
                module.CONTAINER,
                runner=lambda _args, **_kwargs: "\n".join(rows),
            )


    def test_docker_stdout_protocol_and_nonzero_remain_fail_closed(self) -> None:
        output = self.container_inspect_output([])
        hostile_stdout = (
            "\n".join(output.splitlines()[:-1]),
            output + "\n" + json.dumps("extra"),
            output.replace(json.dumps("container-object-1"), "not-json", 1),
        )
        for value in hostile_stdout:
            with self.assertRaisesRegex(
                module.ResumeRejected,
                "phase_f_docker_projection_(shape|decode)_rejected",
            ):
                module.phase_f_container_projection(
                    module.CONTAINER,
                    runner=lambda _args, **_kwargs: value,
                )

        completed = mock.Mock(
            returncode=23,
            stdout=output,
            stderr="private diagnostic must not escape",
        )
        with mock.patch.object(module.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(
                module.ResumeRejected,
                r"^fixed_command_failed:docker:23$",
            ) as raised:
                module.run(["/usr/bin/docker", "version"])
        self.assertNotIn("private diagnostic", str(raised.exception))

    def test_container_mount_projection_binds_every_mapping_and_duplicate(self) -> None:
        first = {
            "Destination": "/target/a",
            "Mode": "ro",
            "Opaque": {"nested": [1, True, None]},
            "Propagation": "rprivate",
            "RW": False,
            "Source": "/source/a",
            "Type": "bind",
        }
        second = {
            "Destination": "/target/b",
            "Mode": "rw",
            "Propagation": "rprivate",
            "RW": True,
            "Source": "/source/b",
            "Type": "bind",
        }
        base = [first, second, second]

        changed_value = json.loads(json.dumps(base))
        changed_value[0]["Opaque"]["nested"][0] = 2
        added_member = json.loads(json.dumps(base))
        added_member[0]["Added"] = {"complete": "member"}
        removed_member = json.loads(json.dumps(base))
        del removed_member[0]["Propagation"]
        variants = (
            changed_value,
            added_member,
            removed_member,
            base[:-1],
            [*base, second],
            [*base, {"Destination": "/target/c", "Type": "tmpfs"}],
        )

        def digest(value: object) -> str:
            output = self.container_inspect_output(value)
            projected = module.phase_f_container_projection(
                module.CONTAINER,
                runner=lambda _args, **_kwargs: output,
            )
            self.assertIsNotNone(projected)
            return projected.mounts_digest

        expected = digest(base)
        for variant in variants:
            self.assertNotEqual(digest(variant), expected)

    def test_effect_mount_projection_uses_frozen_destination_order(self) -> None:
        target = self.target()
        frozen = module._phase_f_effect_mounts(target)
        expected = module._phase_f_digest(
            "phase_f_attempt5_target_mounts_v1", frozen
        )
        observed = [
            {
                "Destination": row["destination"],
                "RW": not row["readonly"],
                "Source": row["source"],
            }
            for row in frozen
        ]
        for rows in (observed, list(reversed(observed))):
            self.assertEqual(
                module._phase_f_digest(
                    "phase_f_attempt5_target_mounts_v1",
                    module._phase_f_observed_effect_mounts(rows),
                ),
                expected,
            )

        variants = []
        for field, value in (
            ("Source", "/substituted"),
            ("Destination", "/unexpected"),
            ("RW", False),
        ):
            changed = json.loads(json.dumps(observed))
            changed[0][field] = value
            variants.append(changed)
        variants.extend(
            (
                observed[:-1],
                [*observed, dict(observed[0])],
                [dict(observed[0]), *observed[1:]],
            )
        )
        variants[-1][0]["Destination"] = observed[1]["Destination"]
        for rows in variants:
            self.assertNotEqual(
                module._phase_f_digest(
                    "phase_f_attempt5_target_mounts_v1",
                    module._phase_f_observed_effect_mounts(rows),
                ),
                expected,
            )

    def test_container_mount_projection_rejects_non_mapping_shapes(self) -> None:
        malformed = (
            {"not": "a-list"},
            [{"Type": "bind"}, "not-a-mapping"],
        )
        for value in malformed:
            output = self.container_inspect_output(value)
            with self.assertRaisesRegex(
                module.ResumeRejected,
                "container_mounts_rejected",
            ):
                module.phase_f_container_projection(
                    module.CONTAINER,
                    runner=lambda _args, **_kwargs: output,
                )

    def test_external_network_is_double_observed_and_never_mutated(self) -> None:
        expected = self.network("old-object-1")
        runner = mock.Mock()
        with mock.patch.object(module, "phase_f_network_projection", side_effect=(expected, expected)):
            self.assertEqual(module.phase_f_require_external_network(expected, runner=runner), expected)
        runner.assert_not_called()
        drift = replace(expected, ipam_digest="a" * 64)
        with mock.patch.object(module, "phase_f_network_projection", side_effect=(expected, drift)), self.assertRaisesRegex(module.ResumeRejected, "network_not_ready"):
            module.phase_f_require_external_network(expected, runner=runner)

    def test_stop_and_rename_preserve_exact_old_container_id(self) -> None:
        old = self.container()
        stopped = replace(old, status="exited", health="")
        archived = replace(stopped, name=f"{module.ARCHIVE_PREFIX}{'8' * 16}")
        calls: list[list[str]] = []
        invoke = lambda args, **_kw: calls.append(args) or ""
        with mock.patch.object(module, "phase_f_container_projection", side_effect=(old, stopped)):
            self.assertEqual(module.phase_f_stop_container_exact(old, name=module.CONTAINER, runner=invoke), stopped)
        self.assertEqual(calls[0][-1], old.container_id)
        calls.clear()
        with mock.patch.object(module, "phase_f_container_projection", side_effect=(stopped, None, None, archived)):
            result = module.phase_f_rename_container_exact(old, source_name=module.CONTAINER, target_name=archived.name, runner=invoke)
        self.assertEqual(result.container_id, old.container_id)
        self.assertEqual(calls[0][-2:], [old.container_id, archived.name])

    def test_rename_collision_and_identity_substitution_are_ambiguous(self) -> None:
        old = replace(self.container(), status="exited", health="")
        collision = replace(old, container_id="third-object", name="archive")
        with mock.patch.object(module, "phase_f_container_projection", side_effect=(old, collision)), self.assertRaisesRegex(module.ResumeRejected, "collision_ambiguous"):
            module.phase_f_rename_container_exact(old, source_name=module.CONTAINER, target_name="archive", runner=mock.Mock())
        substituted = replace(old, image="sha256:" + "f" * 64)
        with mock.patch.object(module, "phase_f_container_projection", return_value=substituted), self.assertRaisesRegex(module.ResumeRejected, "stop_identity_rejected"):
            module.phase_f_stop_container_exact(old, name=module.CONTAINER, runner=mock.Mock())

    def test_create_policy_start_and_remove_are_separate_exact_effects(self) -> None:
        target = self.target()
        archived = replace(self.container(status="exited", health=""), name=target.archive_name)
        created = self.container(
            container_id="target-object-1", status="created", health="",
            policy="no", policy_maximum=0, plan_digest=target.plan_digest,
            target_config_digest=target.target_config_digest, image=target.image,
        )
        policy = replace(created, restart_policy=module.EXPECTED_RESTART_POLICY, restart_maximum_retry_count=module.EXPECTED_RESTART_MAXIMUM_RETRY_COUNT)
        running = replace(policy, status="running", health="healthy")
        network_before = self.network()
        network_during = self.network()
        calls: list[list[str]] = []
        invoke = lambda args, **_kw: calls.append(args) or ""
        with mock.patch.object(module, "phase_f_require_external_network"), mock.patch.object(module, "phase_f_container_projection", side_effect=(None, archived, created)), mock.patch.object(module, "phase_f_network_projection", return_value=network_during):
            self.assertEqual(module.phase_f_create_target_stopped(target, expected_network=network_before, archived_old=archived, runner=invoke), created)
        self.assertEqual(calls[0][:3], ["/usr/bin/docker", "container", "create"])
        calls.clear()
        with mock.patch.object(module, "phase_f_container_projection", side_effect=(created, policy)):
            self.assertEqual(module.phase_f_set_restart_policy_exact(created, runner=invoke), policy)
        self.assertEqual(calls[0][2], "update")
        calls.clear()
        with mock.patch.object(module, "phase_f_container_projection", side_effect=(policy, running)):
            self.assertEqual(module.phase_f_start_container_exact(policy, runner=invoke, sleeper=lambda _seconds: None), running)
        self.assertEqual(calls[0][2], "start")
        stopped = replace(running, status="exited", health="")
        calls.clear()
        with mock.patch.object(module, "phase_f_container_projection", side_effect=(stopped, None)), mock.patch.object(module, "phase_f_network_projection", return_value=network_before):
            module.phase_f_remove_container_exact(stopped, expected_network=network_before, runner=invoke)
        self.assertEqual(calls[0][2], "rm")

    def test_archive_name_shape_and_exact_archived_object_gate_create(self) -> None:
        target = self.target()
        runner = mock.Mock()
        for archive_name in (
            f"{module.ARCHIVE_PREFIX}{'a' * 15}",
            f"{module.ARCHIVE_PREFIX}{'g' * 16}",
            f"{module.ARCHIVE_PREFIX}{'a' * 17}",
        ):
            with self.assertRaisesRegex(module.ResumeRejected, "phase_f_archive_name_rejected"):
                replace(target, archive_name=archive_name)
        with self.assertRaisesRegex(module.ResumeRejected, "phase_f_target_digest_rejected"):
            replace(target, plan_digest="not-a-digest")
        runner.assert_not_called()

        network = self.network()
        archived = replace(self.container(status="exited", health=""), name=target.archive_name)
        substituted_name = replace(target, archive_name=f"{module.ARCHIVE_PREFIX}{'0' * 16}")
        with mock.patch.object(module, "phase_f_require_external_network"), mock.patch.object(
            module, "phase_f_container_projection", side_effect=(None, None)
        ), self.assertRaisesRegex(module.ResumeRejected, "phase_f_create_archive_drift"):
            module.phase_f_create_target_stopped(
                substituted_name, expected_network=network, archived_old=archived, runner=runner
            )
        runner.assert_not_called()

        substituted_object = replace(archived, container_id="substituted-object")
        with mock.patch.object(module, "phase_f_require_external_network"), mock.patch.object(
            module, "phase_f_container_projection", side_effect=(None, substituted_object)
        ), self.assertRaisesRegex(module.ResumeRejected, "phase_f_create_archive_drift"):
            module.phase_f_create_target_stopped(
                target, expected_network=network, archived_old=archived, runner=runner
            )
        runner.assert_not_called()

    def test_attempt5_effect_is_single_pre_and_post_create_authority(self) -> None:
        target = self.target()
        network = self.network()
        archive = self.container(
            container_id="archived-old-object",
            name=target.archive_name,
            status="exited",
            health="",
        )
        effect = self.target_effect(target, network, archive)
        target = replace(target, effect=effect)
        created = replace(
            self.container(
                container_id="target-object",
                name=module.CONTAINER,
                status="created",
                health="",
                policy="no",
                policy_maximum=0,
                plan_digest=target.plan_digest,
                target_config_digest=target.target_config_digest,
                image=target.image,
            ),
            command_digest=effect["command_sha256"],
            effect_digest=effect["effect_sha256"],
            effect_environment_digest=effect["environment_sha256"],
            effect_host_digest=effect["host_sha256"],
            effect_mounts_digest=effect["mounts_sha256"],
        )
        after_network = network
        mutations: list[list[str]] = []

        def runner(command: list[str], **_kwargs: object) -> str:
            mutations.append(command)
            return created.container_id

        with mock.patch.object(
            module, "phase_f_require_external_network", return_value=network
        ), mock.patch.object(
            module,
            "phase_f_container_projection",
            side_effect=(None, archive, created),
        ), mock.patch.object(
            module, "phase_f_network_projection", return_value=after_network
        ):
            observed = module.phase_f_create_target_stopped(
                target,
                expected_network=network,
                archived_old=archive,
                runner=runner,
            )
        self.assertEqual(observed, created)
        self.assertEqual(len(mutations), 1)
        self.assertEqual(mutations[0][:4], ["/usr/bin/docker", "container", "create", "--name"])
        self.assertIn("myuna.phase-f.target-effect-digest=" + effect["effect_sha256"], mutations[0])

        unexpected = self.network("foreign-endpoint")
        no_runner = mock.Mock()
        with mock.patch.object(
            module, "phase_f_require_external_network", return_value=unexpected
        ), self.assertRaisesRegex(
            module.ResumeRejected, "phase_f_create_network_prestate_rejected"
        ):
            module.phase_f_create_target_stopped(
                target,
                expected_network=unexpected,
                archived_old=archive,
                runner=no_runner,
            )
        no_runner.assert_not_called()

        post_runner = mock.Mock(return_value=created.container_id)
        with mock.patch.object(
            module, "phase_f_require_external_network", return_value=network
        ), mock.patch.object(
            module,
            "phase_f_container_projection",
            side_effect=(None, archive, created),
        ), mock.patch.object(
            module, "phase_f_network_projection", return_value=unexpected
        ), self.assertRaisesRegex(
            module.ResumeRejected, "phase_f_create_network_poststate_rejected"
        ):
            module.phase_f_create_target_stopped(
                target,
                expected_network=network,
                archived_old=archive,
                runner=post_runner,
            )
        post_runner.assert_called_once()

        substitutions: list[tuple[str, object]] = [
            ("container_name", "substituted"),
            ("archive_container_id", "substituted"),
            ("archive_name", target.archive_name + "-substituted"),
            ("image", module.EXPECTED_IMAGE_PREFIX + "0" * 64),
            ("target_config_digest", "0" * 64),
            ("command_sha256", "0" * 64),
            ("user", "0:0"),
            ("network_name", "substituted"),
            ("project", "substituted"),
            ("service", "substituted"),
            ("plan_digest", "0" * 64),
            ("attempt", 6),
            ("writer", True),
            ("archive_projection_sha256", "0" * 64),
            ("network_projection_sha256", "0" * 64),
            ("effect_sha256", "0" * 64),
        ]
        for field, value in substitutions:
            hostile = dict(effect)
            hostile[field] = value
            with self.subTest(field=field), self.assertRaises(module.ResumeRejected):
                replace(self.target(), effect=hostile)
        for field in ("command", "environment", "host", "mounts"):
            hostile = dict(effect)
            nested = json.loads(json.dumps(hostile[field]))
            if field == "command":
                nested["command"][0] = "substituted"
            elif field == "environment":
                nested["explicit"][0] = "HOME=/substituted"
            elif field == "host":
                nested["memory"] = "2048m"
            else:
                nested.append(dict(nested[0]))
            hostile[field] = nested
            with self.subTest(field=field), self.assertRaises(module.ResumeRejected):
                replace(self.target(), effect=hostile)

    def test_complete_target_authority_accepts_only_two_restart_host_pairs(self) -> None:
        target = self.target()
        network = self.network()
        archive = replace(
            self.container(status="exited", health=""),
            name=target.archive_name,
        )
        effect = self.target_effect(target, network, archive)
        authority = replace(target, effect=effect)
        pre_policy = replace(
            self.container(
                container_id="attempt-8-target",
                status="created",
                health="",
                policy="no",
                policy_maximum=0,
                plan_digest=authority.plan_digest,
                target_config_digest=authority.target_config_digest,
                image=authority.image,
            ),
            command_digest=effect["command_sha256"],
            effect_digest=effect["effect_sha256"],
            effect_environment_digest=effect["environment_sha256"],
            effect_host_digest=effect["host_sha256"],
            effect_mounts_digest=effect["mounts_sha256"],
        )
        post_digest = module._phase_f_effect_host_digest_with_restart(
            effect,
            module.EXPECTED_RESTART_POLICY,
            module.EXPECTED_RESTART_MAXIMUM_RETRY_COUNT,
        )
        post_policy = replace(
            pre_policy,
            status="running",
            health="healthy",
            restart_policy=module.EXPECTED_RESTART_POLICY,
            restart_maximum_retry_count=(
                module.EXPECTED_RESTART_MAXIMUM_RETRY_COUNT
            ),
            effect_host_digest=post_digest,
        )
        running_network = replace(
            network,
            member_container_ids=(post_policy.container_id,),
        )

        self.assertTrue(
            module.phase_f_target_matches_authority(
                authority,
                pre_policy,
                network=network,
                expected_container_id=pre_policy.container_id,
            )
        )
        self.assertTrue(
            module.phase_f_target_matches_authority(
                authority,
                post_policy,
                network=running_network,
                expected_container_id=post_policy.container_id,
            )
        )
        self.assertNotEqual(effect["host_sha256"], post_digest)

        hostile = (
            replace(pre_policy, effect_host_digest=post_digest),
            replace(post_policy, effect_host_digest=effect["host_sha256"]),
            replace(post_policy, restart_policy="always"),
            replace(post_policy, restart_maximum_retry_count=4),
            replace(post_policy, effect_host_digest="0" * 64),
            replace(post_policy, command_digest="0" * 64),
            replace(post_policy, effect_digest="0" * 64),
            replace(post_policy, effect_environment_digest="0" * 64),
            replace(post_policy, effect_mounts_digest="0" * 64),
            replace(post_policy, image=module.EXPECTED_IMAGE_PREFIX + "0" * 64),
            replace(post_policy, plan_digest="0" * 64),
            replace(post_policy, target_config_digest="0" * 64),
            replace(post_policy, user="0:0"),
            replace(post_policy, name="sibling"),
            replace(post_policy, project="sibling"),
            replace(post_policy, service="sibling"),
            replace(post_policy, network_names=("sibling",)),
        )
        for observed in hostile:
            with self.subTest(observed=observed):
                self.assertFalse(
                    module.phase_f_target_matches_authority(
                        authority,
                        observed,
                        network=running_network,
                        expected_container_id=post_policy.container_id,
                    )
                )

        for hostile_network in (
            replace(running_network, network_id="sibling-network"),
            replace(running_network, member_container_ids=()),
            replace(
                running_network,
                member_container_ids=tuple(
                    sorted(("second-target", post_policy.container_id))
                ),
            ),
        ):
            expected = hostile_network.member_container_ids == ()
            self.assertEqual(
                module.phase_f_target_matches_authority(
                    authority,
                    post_policy,
                    network=hostile_network,
                    expected_container_id=post_policy.container_id,
                ),
                expected,
            )
        self.assertFalse(
            module.phase_f_target_matches_authority(
                authority,
                post_policy,
                network=running_network,
                expected_container_id="sibling-target",
            )
        )

        hostile_effect = dict(effect)
        hostile_effect["host_sha256"] = "0" * 64
        hostile_authority = mock.Mock(
            archive_name=authority.archive_name,
            channel_root=authority.channel_root,
            effect=hostile_effect,
            image=authority.image,
            media_auth_runtime_root=authority.media_auth_runtime_root,
            plan_digest=authority.plan_digest,
            plugin_root=authority.plugin_root,
            runtime_root=authority.runtime_root,
            signing_secret=authority.signing_secret,
            target_config_digest=authority.target_config_digest,
            user=authority.user,
        )
        self.assertFalse(
            module.phase_f_target_matches_authority(
                hostile_authority,
                post_policy,
                network=running_network,
                expected_container_id=post_policy.container_id,
            )
        )

    def test_start_poststate_uses_finite_sanitized_categories(self) -> None:
        selected = self.container(
            container_id="target-object",
            status="created",
            health="",
        )
        cases = (
            (None, "phase_f_start_poststate_missing"),
            (
                replace(selected, container_id="sibling-object"),
                "phase_f_start_poststate_identity_rejected",
            ),
            (
                replace(selected, status="dead"),
                "phase_f_start_poststate_state_rejected",
            ),
        )
        for observed, code in cases:
            runner = mock.Mock(return_value="")
            with self.subTest(code=code), mock.patch.object(
                module,
                "phase_f_container_projection",
                side_effect=(selected, observed),
            ), self.assertRaisesRegex(module.ResumeRejected, code):
                module.phase_f_start_container_exact(
                    selected,
                    runner=runner,
                    sleeper=lambda _seconds: None,
                )
            runner.assert_called_once()

    def test_lost_return_reobservation_accepts_only_exact_poststate(self) -> None:
        old = self.container()
        substituted = replace(old, status="exited", health="", mounts_digest="f" * 64)
        with mock.patch.object(module, "phase_f_container_projection", side_effect=(old, substituted)), self.assertRaisesRegex(module.ResumeRejected, "stop_poststate_rejected"):
            module.phase_f_stop_container_exact(old, name=module.CONTAINER, runner=lambda _args, **_kw: "")


if __name__ == "__main__":
    unittest.main()
