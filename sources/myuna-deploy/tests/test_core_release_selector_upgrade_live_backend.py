from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


CANDIDATE_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
FORMAL_SCRIPTS = Path("/srv/myuna/repos/deploy/scripts")
sys.path[:0] = [str(CANDIDATE_SCRIPTS), str(FORMAL_SCRIPTS)]

from core_release_selector_upgrade_live_backend import (  # noqa: E402
    CORE_UNIT,
    GATEWAY_SOCKET,
    CommandRunner,
    FixedSystemdSelectedUpgradeBackend,
    SelectedUpgradeLiveBackendError,
    running_state,
    socket_ready_state,
)


class StatePredicateTests(unittest.TestCase):
    def test_regular_service_requires_active_running(self) -> None:
        self.assertTrue(running_state({"ActiveState": "active", "SubState": "running"}))
        self.assertFalse(running_state({"ActiveState": "active", "SubState": "listening"}))
        self.assertFalse(running_state({}))

    def test_socket_accepts_only_listening_or_running(self) -> None:
        for substate in ("listening", "running"):
            self.assertTrue(
                socket_ready_state({"ActiveState": "active", "SubState": substate})
            )
        self.assertFalse(
            socket_ready_state({"ActiveState": "inactive", "SubState": "dead"})
        )


class FixedCommandBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = object.__new__(FixedSystemdSelectedUpgradeBackend)
        self.backend.wait_timeout_seconds = 1
        self.backend.runner = mock.Mock()

    def test_systemctl_allows_only_fixed_actions_and_units(self) -> None:
        self.backend._systemctl("start", CORE_UNIT)
        self.backend.runner.run.assert_called_once_with(
            ["/usr/bin/systemctl", "start", CORE_UNIT],
            timeout_seconds=1,
        )
        with self.assertRaises(SelectedUpgradeLiveBackendError):
            self.backend._systemctl("restart", CORE_UNIT)
        with self.assertRaises(SelectedUpgradeLiveBackendError):
            self.backend._systemctl("start", "arbitrary.service")

    def test_daemon_reload_rejects_unit(self) -> None:
        self.backend._systemctl("daemon-reload")
        with self.assertRaises(SelectedUpgradeLiveBackendError):
            self.backend._systemctl("daemon-reload", CORE_UNIT)

    def test_show_rejects_unknown_unit(self) -> None:
        with self.assertRaises(SelectedUpgradeLiveBackendError):
            self.backend._show("arbitrary.service", ("ActiveState",))

    def test_socket_wait_accepts_active_running(self) -> None:
        self.backend._state = mock.Mock(return_value=("active", "running"))
        with mock.patch(
            "core_release_selector_upgrade_live_backend.time.monotonic",
            side_effect=(0.0, 0.1),
        ):
            self.backend._wait_state(GATEWAY_SOCKET, ("active", "listening"))

    @staticmethod
    def healthy_connection() -> mock.Mock:
        connection = mock.Mock()
        response = mock.Mock(status=200)
        response.read.return_value = b"ok"
        connection.getresponse.return_value = response
        return connection

    def test_loopback_health_retries_connection_refused_then_passes(self) -> None:
        refused = mock.Mock()
        refused.request.side_effect = ConnectionRefusedError()
        with (
            mock.patch(
                "core_release_selector_upgrade_live_backend.http.client.HTTPConnection",
                side_effect=[refused, self.healthy_connection(), self.healthy_connection()],
            ),
            mock.patch(
                "core_release_selector_upgrade_live_backend.time.monotonic",
                side_effect=[0.0, 0.1],
            ),
            mock.patch("core_release_selector_upgrade_live_backend.time.sleep") as sleep,
        ):
            self.backend._loopback_health()
        sleep.assert_called_once_with(0.1)

    def test_loopback_health_retries_non_200_then_passes(self) -> None:
        not_ready = mock.Mock()
        response = mock.Mock(status=503)
        response.read.return_value = b"not ready"
        not_ready.getresponse.return_value = response
        with (
            mock.patch(
                "core_release_selector_upgrade_live_backend.http.client.HTTPConnection",
                side_effect=[not_ready, self.healthy_connection(), self.healthy_connection()],
            ),
            mock.patch(
                "core_release_selector_upgrade_live_backend.time.monotonic",
                side_effect=[0.0, 0.1],
            ),
            mock.patch("core_release_selector_upgrade_live_backend.time.sleep"),
        ):
            self.backend._loopback_health()

    def test_loopback_health_timeout_is_fail_closed(self) -> None:
        refused = mock.Mock()
        refused.request.side_effect = ConnectionRefusedError()
        with (
            mock.patch(
                "core_release_selector_upgrade_live_backend.http.client.HTTPConnection",
                return_value=refused,
            ),
            mock.patch(
                "core_release_selector_upgrade_live_backend.time.monotonic",
                side_effect=[0.0, 2.0],
            ),
            self.assertRaisesRegex(
                SelectedUpgradeLiveBackendError,
                "target_loopback_health_timeout",
            ),
        ):
            self.backend._loopback_health()


class CommandRunnerTests(unittest.TestCase):
    @mock.patch("core_release_selector_upgrade_live_backend.subprocess.run")
    def test_runner_never_uses_shell(self, run: mock.Mock) -> None:
        run.return_value = subprocess.CompletedProcess(["/bin/true"], 0, "", "")
        CommandRunner().run(["/bin/true"])
        self.assertIs(run.call_args.kwargs["shell"], False)
        self.assertIs(run.call_args.kwargs["check"], False)

    @mock.patch("core_release_selector_upgrade_live_backend.subprocess.run")
    def test_runner_redacts_failure_to_basename_and_code(self, run: mock.Mock) -> None:
        run.return_value = subprocess.CompletedProcess(["/bin/false"], 7, "secret", "secret")
        with self.assertRaisesRegex(
            SelectedUpgradeLiveBackendError,
            "command_failed:false:7",
        ):
            CommandRunner().run(["/bin/false"])


if __name__ == "__main__":
    unittest.main()
