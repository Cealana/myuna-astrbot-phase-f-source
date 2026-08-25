from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT / "scripts"))

import activate_p16_phase1_t2_v1 as activation  # noqa: E402


class ActivateP16Phase1T2V1Tests(unittest.TestCase):
    def _bundle_context(self) -> dict[str, object]:
        return {
            "bundle": {
                "bundle_digest": "a" * 64,
                "artifacts": {
                    "core": {"release_digest": "b" * 64},
                    "telegram_runtime": {"release_digest": "c" * 64},
                    "telegram_plugin": {"release_digest": "d" * 64},
                    "p16_adapter": {"release_digest": "e" * 64},
                },
            }
        }

    def _service(self, name: str) -> dict[str, object]:
        return {
            "active_state": "active",
            "sub_state": "running",
            "result": "success",
            "nrestarts": 0,
            "pid": 100,
            "invocation_id": (name[0] * 32),
            "binding_digest": (name[-1] * 64),
        }

    def _live(self) -> dict[str, object]:
        return {
            "source": {
                "core": {"commit": "1" * 40, "clean_tracked": True},
                "deploy": {"commit": "2" * 40, "clean_tracked": True},
                "controller_source_sha256": "3" * 64,
            },
            "services": {
                "core": self._service("core"),
                "telegram": self._service("telegram"),
                "telegram_socket": self._service("telegram_socket"),
                "p08": self._service("p08"),
                "p08_socket": self._service("p08_socket"),
            },
            "selected": {
                "core": "4" * 64,
                "telegram_runtime": "5" * 64,
                "telegram_plugin": "6" * 64,
                "p08": "7" * 64,
            },
            "compatibility": {
                "combined_release_set_id": "8" * 64,
                "p07_release_set_id": "9" * 64,
                "effective_definition_id": "effective-v6-safe-id",
                "generation": 13,
                "epoch_schema": "myuna.external-authorized-epoch.v3",
            },
            "readiness": {
                "schema": "myuna.p07-d-runtime-readiness.v1",
                "generation": 13,
                "release_set_id": "9" * 64,
                "selector_digest": "a" * 64,
                "runtime_config_digest": "b" * 64,
                "epoch_metadata_digest": "c" * 64,
                "process_binding_digest": "d" * 64,
            },
            "files": {
                name: {
                    "sha256": character * 64,
                    "size": 10,
                    "uid": 0,
                    "gid": 0,
                    "mode": "0640",
                    "type": "regular_no_symlink",
                }
                for name, character in zip(
                    (
                        "core_binding",
                        "core_selector",
                        "core_guard",
                        "generation13_telegram_dropin",
                        "p07_selector",
                        "p07_release_set",
                        "runtime_config",
                        "plugin_config",
                        "effective_v6",
                        "incident_selector",
                        "incident_marker",
                        "p16_telegram_dropin",
                    ),
                    "abcdefghijkl",
                )
            },
            "history": {"root": {"state": "absent"}, "channel": {"state": "absent"}},
            "artifact_targets": {
                "core": {"state": "absent"},
                "telegram_runtime": {"state": "absent"},
                "p16_adapter": {"state": "absent"},
            },
            "attempts": 0,
        }

    def test_live_plan_is_deterministic_default_off_and_content_free(self) -> None:
        first = activation._build_live_plan(self._bundle_context(), self._live())
        second = activation._build_live_plan(self._bundle_context(), self._live())
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "ready_default_off")
        self.assertTrue(
            all(
                service["binding_projection"] == activation.SERVICE_BINDING_PROJECTION
                for service in first["prestate"]["services"].values()
            )
        )
        self.assertEqual(
            first["prestate"]["incident_marker"],
            self._live()["files"]["incident_marker"],
        )
        self.assertTrue(first["activation"]["marker_created_last"])
        self.assertTrue(first["rollback"]["marker_removed_first"])
        self.assertFalse(first["mutation_performed"])
        serialized = activation.canonical(first).decode("ascii")
        for forbidden in (
            "raw_message",
            "caption",
            "model_response",
            "provider_payload",
            "db_row",
            "profile_content",
            "raw_log",
            "credential_value",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_service_state_gate_rejects_restart_or_wrong_substate(self) -> None:
        healthy = self._service("core")
        activation._require_active(healthy)
        activation._require_active({**healthy, "sub_state": "listening"}, socket=True)
        for drift in (
            {"nrestarts": 1},
            {"active_state": "inactive"},
            {"sub_state": "failed"},
            {"result": "exit-code"},
        ):
            with self.subTest(drift=drift):
                with self.assertRaises(activation.P16Phase1T2Rejected):
                    activation._require_active({**healthy, **drift})

    def test_socket_projection_uses_only_properties_systemd_exposes(self) -> None:
        observed = {
            "ActiveState": "active",
            "SubState": "running",
            "Result": "success",
            "InvocationID": "a" * 32,
            "WorkingDirectory": "",
        }
        with mock.patch.object(activation, "_show", return_value=observed) as show:
            projection = activation._service_projection("synthetic.socket", socket=True)
        requested = show.call_args.args[1]
        self.assertNotIn("NRestarts", requested)
        self.assertNotIn("MainPID", requested)
        self.assertNotIn("ExecStart", requested)
        self.assertEqual(projection["nrestarts"], 0)
        self.assertEqual(projection["pid"], 0)
        self.assertEqual(projection["exec_start"], "")

    def test_protected_file_accepts_explicit_service_group_and_rejects_drift(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("exact owner/group projection requires root")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "selector.json"
            path.write_bytes(b"{}\n")
            service_gid = activation.pwd.getpwnam(activation.TELEGRAM_RUNTIME_USER).pw_gid
            os.chown(path, 0, service_gid)
            os.chmod(path, 0o440)
            self.assertEqual(
                activation._require_protected_file(
                    path,
                    uid=0,
                    gid=service_gid,
                    mode=0o440,
                    code="selector_rejected",
                ),
                b"{}\n",
            )
            os.chmod(path, 0o444)
            with self.assertRaisesRegex(
                activation.P16Phase1T2Rejected, "selector_rejected"
            ):
                activation._require_protected_file(
                    path,
                    uid=0,
                    gid=service_gid,
                    mode=0o440,
                    code="selector_rejected",
                )

    def test_service_binding_ignores_only_systemd_invocation_fields(self) -> None:
        static = (
            "{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /safe/runtime.py ; "
            "ignore_errors=no"
        )

        def observed(*, pid: int, started: str, runtime: str = "/safe/runtime.py") -> dict[str, str]:
            return {
                "ActiveState": "active",
                "SubState": "running",
                "Result": "success",
                "NRestarts": "0",
                "MainPID": str(pid),
                "InvocationID": f"{pid:032x}",
                "ExecStart": (
                    static.replace("/safe/runtime.py", runtime)
                    + f" ; start_time=[{started}] ; stop_time=[n/a] ; pid={pid} ; "
                    "code=(null) ; status=0/0 }"
                ),
                "WorkingDirectory": "/safe",
            }

        with mock.patch.object(activation, "_show", return_value=observed(pid=101, started="first")):
            first = activation._service_projection("synthetic.service")
        with mock.patch.object(activation, "_show", return_value=observed(pid=202, started="second")):
            restarted = activation._service_projection("synthetic.service")
        with mock.patch.object(
            activation,
            "_show",
            return_value=observed(pid=202, started="second", runtime="/safe/other.py"),
        ):
            changed = activation._service_projection("synthetic.service")

        self.assertNotEqual(first["exec_start"], restarted["exec_start"])
        self.assertEqual(first["binding_digest"], restarted["binding_digest"])
        self.assertNotEqual(first["binding_digest"], changed["binding_digest"])

    def test_stable_exec_start_projection_rejects_unparsed_runtime_field(self) -> None:
        with self.assertRaisesRegex(
            activation.P16Phase1T2Rejected,
            "service_exec_start_projection_rejected",
        ):
            activation._stable_exec_start_projection(
                "status=0/0 { path=/safe ; argv[]=/safe ; unknown=ok }"
            )

    def test_readiness_waits_for_new_process_receipt_then_requires_stability(self) -> None:
        class Clock:
            def __init__(self) -> None:
                self.now = 0.0
                self.sleeps: list[float] = []

            def monotonic(self) -> float:
                return self.now

            def sleep(self, seconds: float) -> None:
                self.sleeps.append(seconds)
                self.now += seconds

        clock = Clock()
        process = {
            **self._service("telegram"),
            "exec_start": "/safe/runtime.py",
            "working_directory": "",
        }
        release_set = SimpleNamespace(
            release_set_id="a" * 64,
            epoch={"epoch_id": "epoch-synthetic"},
            selector={"digest": "b" * 64},
            runtime_config={"digest": "c" * 64},
        )

        def receipt(pid: int, invocation: str) -> SimpleNamespace:
            return SimpleNamespace(
                generation=13,
                release_set_id=release_set.release_set_id,
                selector_digest=release_set.selector["digest"],
                runtime_config_digest=release_set.runtime_config["digest"],
                epoch_metadata_digest="d" * 64,
                pid=pid,
                invocation_id=invocation,
            )

        stale = receipt(99, "e" * 32)
        current = receipt(int(process["pid"]), str(process["invocation_id"]))
        with mock.patch.object(
            activation.pwd,
            "getpwnam",
            return_value=SimpleNamespace(pw_uid=1000, pw_gid=1000),
        ), mock.patch.object(
            activation,
            "_service_projection",
            return_value=process,
        ) as service, mock.patch.object(
            activation,
            "inspect_runtime_readiness",
            side_effect=(stale, current),
        ):
            projected = activation._readiness_projection(
                release_set,
                process,
                wait_for_process=True,
                timeout_seconds=1.0,
                poll_seconds=0.1,
                stable_seconds=0.2,
                monotonic=clock.monotonic,
                sleep=clock.sleep,
            )

        self.assertEqual(projected["process_binding_digest"], activation.digest(
            "myuna-p16-phase1-t2-readiness-process-v1",
            {"invocation_id": process["invocation_id"], "pid": process["pid"]},
        ))
        self.assertEqual(clock.sleeps, [0.1, 0.2])
        self.assertEqual(service.call_count, 3)

    def test_readiness_wait_times_out_on_persistently_stale_process(self) -> None:
        class Clock:
            def __init__(self) -> None:
                self.now = 0.0

            def monotonic(self) -> float:
                return self.now

            def sleep(self, seconds: float) -> None:
                self.now += seconds

        clock = Clock()
        process = {
            **self._service("telegram"),
            "exec_start": "/safe/runtime.py",
            "working_directory": "",
        }
        release_set = SimpleNamespace(
            release_set_id="a" * 64,
            epoch={"epoch_id": "epoch-synthetic"},
            selector={"digest": "b" * 64},
            runtime_config={"digest": "c" * 64},
        )
        stale = SimpleNamespace(pid=99, invocation_id="e" * 32)
        with mock.patch.object(
            activation.pwd,
            "getpwnam",
            return_value=SimpleNamespace(pw_uid=1000, pw_gid=1000),
        ), mock.patch.object(
            activation,
            "_service_projection",
            return_value=process,
        ), mock.patch.object(
            activation,
            "inspect_runtime_readiness",
            return_value=stale,
        ):
            with self.assertRaisesRegex(
                activation.P16Phase1T2Rejected,
                "runtime_readiness_process_timeout",
            ):
                activation._readiness_projection(
                    release_set,
                    process,
                    wait_for_process=True,
                    timeout_seconds=0.3,
                    poll_seconds=0.1,
                    stable_seconds=0.0,
                    monotonic=clock.monotonic,
                    sleep=clock.sleep,
                )

    def test_readiness_wait_does_not_retry_binding_rejection(self) -> None:
        process = {
            **self._service("telegram"),
            "exec_start": "/safe/runtime.py",
            "working_directory": "",
        }
        release_set = SimpleNamespace(
            release_set_id="a" * 64,
            epoch={"epoch_id": "epoch-synthetic"},
            selector={"digest": "b" * 64},
            runtime_config={"digest": "c" * 64},
        )
        with mock.patch.object(
            activation.pwd,
            "getpwnam",
            return_value=SimpleNamespace(pw_uid=1000, pw_gid=1000),
        ), mock.patch.object(
            activation,
            "_service_projection",
            return_value=process,
        ), mock.patch.object(
            activation,
            "inspect_runtime_readiness",
            side_effect=activation.RuntimeReadinessRejected(
                "runtime_readiness_binding_rejected"
            ),
        ), mock.patch.object(activation.time, "sleep") as sleep:
            with self.assertRaisesRegex(
                activation.RuntimeReadinessRejected,
                "runtime_readiness_binding_rejected",
            ):
                activation._readiness_projection(
                    release_set,
                    process,
                    wait_for_process=True,
                    sleep=sleep,
                )
        sleep.assert_not_called()

    def test_p08_selection_uses_protected_selector_not_service_environment(self) -> None:
        release = "a" * 64
        plan = "b" * 64
        selector = {
            "schema": activation.p08_activation.SELECTOR_SCHEMA,
            "plan_digest": plan,
            "release_digest": release,
            "release_path": f"/opt/myuna/active-temporal-context-v1/releases/{release}",
            "core_commit": "c" * 40,
            "deploy_commit": "d" * 40,
            "gateway_manifest_digest": "e" * 64,
            "gateway_client_sha256": "f" * 64,
            "plugin_digest": "1" * 64,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "selector.json"
            path.write_bytes(activation.canonical(selector) + b"\n")
            with mock.patch.object(activation.p08_activation, "SELECTOR_JSON", path):
                observed = activation._p08_selection(release, plan)
                self.assertEqual(observed["release_digest"], release)
                with self.assertRaises(activation.P16Phase1T2Rejected):
                    activation._p08_selection("2" * 64, plan)

    def test_acl_projection_accepts_only_exact_basic_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "history"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            with mock.patch.object(
                activation,
                "_basic_acl",
                return_value=("user::rwx", "group::---", "other::---"),
            ):
                projection = activation._directory_projection(
                    root,
                    uid=os.getuid(),
                    gid=os.getgid(),
                    mode=0o700,
                    allow_absent=False,
                )
                self.assertEqual(projection["state"], "present_exact")
                os.chmod(root, 0o750)
                with self.assertRaises(activation.P16Phase1T2Rejected):
                    activation._directory_projection(
                        root,
                        uid=os.getuid(),
                        gid=os.getgid(),
                        mode=0o700,
                        allow_absent=False,
                    )
            link = Path(directory) / "link"
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(activation.P16Phase1T2Rejected):
                activation._directory_projection(
                    link,
                    uid=os.getuid(),
                    gid=os.getgid(),
                    mode=0o700,
                    allow_absent=True,
                )

    def test_successor_uses_independent_append_only_series_and_never_rewrites_terminal_ledger(self) -> None:
        source = (ROOT / "scripts/activate_p16_phase1_t2_v1.py").read_text("utf-8")
        self.assertIn("SUCCESSOR_STATE_ROOT", source)
        self.assertIn("new_append_only_series_no_rewrite", (
            ROOT / "scripts/p16_phase1_t2_contract_v1.py"
        ).read_text("utf-8"))
        self.assertNotIn("_atomic_write(ATTEMPT_LEDGER", source)

    def test_rollback_removes_marker_first_and_restores_before_restart(self) -> None:
        events: list[str] = []
        plan = {"live_plan_digest": "a" * 64}
        backup = {
            "files": {
                "core_binding": {"source": {}},
                "core_selector": {"source": {}},
                "incident_selector": {"source": {}},
                "incident_marker": {"source": {}},
                "p16_telegram_dropin": {"source": {}},
            }
        }

        def systemctl(*arguments: str, **_kwargs: object) -> None:
            events.append("systemctl:" + ":".join(arguments))

        with mock.patch.object(
            activation, "_disable_marker", side_effect=lambda: events.append("disable-marker")
        ), mock.patch.object(
            activation, "_systemctl", side_effect=systemctl
        ), mock.patch.object(
            activation,
            "_verify_targets_stopped",
            side_effect=lambda: events.append("verify-stopped"),
        ), mock.patch.object(
            activation, "_load_backup", return_value=backup
        ), mock.patch.object(
            activation,
            "_restore_exact",
            side_effect=lambda path, *_args, **_kwargs: events.append(
                "restore:" + str(path)
            ),
        ), mock.patch.object(
            activation,
            "_remove_default_off_targets",
            side_effect=lambda: events.append("remove-selector-dropin"),
        ), mock.patch.object(
            activation,
            "_verify_prestate",
            side_effect=lambda _plan: events.append("verify-prestate") or {"status": "restored"},
        ):
            result = activation._restore_prestate(Path("/backup") / ("a" * 64), plan)

        self.assertEqual(result["status"], "restored")
        self.assertEqual(events[0], "disable-marker")
        self.assertLess(events.index("disable-marker"), events.index("systemctl:stop:" + ":".join((activation.TELEGRAM_SOCKET, activation.TELEGRAM_SERVICE, activation.CORE_SERVICE))))
        self.assertLess(
            events.index("restore:" + str(activation.CORE_BINDING)),
            events.index("remove-selector-dropin"),
        )
        self.assertLess(events.index("systemctl:daemon-reload"), events.index("systemctl:start:" + activation.CORE_SERVICE))
        self.assertGreater(
            events.index("restore:" + str(activation.INCIDENT_HISTORY_MARKER)),
            events.index(
                "systemctl:start:"
                + ":".join((activation.TELEGRAM_SOCKET, activation.TELEGRAM_SERVICE))
            ),
        )
        self.assertEqual(events[-1], "verify-prestate")

    def test_backup_manifest_preserves_active_predecessor_overlay_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "backups"
            projection = {
                "sha256": "a" * 64,
                "size": 10,
                "uid": 0,
                "gid": 0,
                "mode": "0440",
                "type": "regular_no_symlink",
            }
            plan = {
                "live_plan_digest": "b" * 64,
                "prestate": {
                    "incident_selector": {**projection, "sha256": "c" * 64},
                    "incident_marker": {**projection, "sha256": "d" * 64},
                    "p16_telegram_dropin": {
                        **projection,
                        "sha256": "e" * 64,
                        "mode": "0644",
                    },
                },
            }

            def backup_file(_root: Path, name: str, _source: Path) -> dict[str, object]:
                return {"backup_name": name, "source": projection}

            with mock.patch.object(activation, "BACKUP_ROOT", root), mock.patch.object(
                activation, "_backup_file", side_effect=backup_file
            ):
                created = activation._create_backup(plan)
            manifest = json.loads((created / "BACKUP.json").read_text("ascii"))
            self.assertEqual(manifest["target_prestate"], {
                "incident_selector": plan["prestate"]["incident_selector"],
                "incident_marker": plan["prestate"]["incident_marker"],
                "p16_telegram_dropin": plan["prestate"]["p16_telegram_dropin"],
            })
            self.assertTrue(
                {"incident_selector", "incident_marker", "p16_telegram_dropin"}.issubset(
                    manifest["files"]
                )
            )

    def test_dropin_sorts_after_generation13_and_preserves_only_p16_write_path(self) -> None:
        self.assertGreater(
            activation.P16_TELEGRAM_DROPIN.name,
            activation.GENERATION13_TELEGRAM_DROPIN.name,
        )
        rendered = activation._render_telegram_dropin(
            Path("/srv/myuna/releases/core/" + "a" * 64),
            Path("/opt/myuna/context24-gateway/telegram/releases/" + "b" * 64),
        ).decode("ascii")
        self.assertIn("ReadWritePaths=/var/lib/myuna-fault-diagnostics/incident-history-v1/telegram", rendered)
        self.assertEqual(rendered.count("ExecStart="), 2)
        for forbidden in ("/healthz", "/readyz", "journalctl", "profile", "qq"):
            self.assertNotIn(forbidden, rendered.lower())

    def test_source_contains_no_forbidden_live_probe_or_channel_call(self) -> None:
        source = (ROOT / "scripts/activate_p16_phase1_t2_v1.py").read_text("utf-8")
        for forbidden in (
            "/healthz",
            "/readyz",
            "journalctl",
            "curl ",
            "requests.",
            "httpx.",
            "send_message",
            "provider.call",
            "sqlite3",
        ):
            self.assertNotIn(forbidden, source)
        self.assertLess(source.index("stage = \"verify_default_off_target\""), source.index("stage = \"enable_marker_last\""))
        self.assertEqual(source.count("wait_for_process=True"), 2)


if __name__ == "__main__":
    unittest.main()
