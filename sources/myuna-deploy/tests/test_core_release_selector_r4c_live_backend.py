from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from core_release_selector_r4c_live_backend import (  # noqa: E402
    GATEWAY_SOCKET_UNIT,
    LiveBackendError,
    SystemdFilesystemBackend,
    _gateway_socket_ready_state,
    _running_state,
)


class UnitStatePredicateTests(unittest.TestCase):
    def test_regular_unit_requires_active_running(self) -> None:
        self.assertTrue(
            _running_state(
                {"ActiveState": "active", "SubState": "running"}
            )
        )
        self.assertFalse(
            _running_state(
                {"ActiveState": "active", "SubState": "listening"}
            )
        )
        self.assertFalse(
            _running_state(
                {"ActiveState": "inactive", "SubState": "dead"}
            )
        )

    def test_gateway_socket_accepts_only_ready_substates(self) -> None:
        for substate in ("listening", "running"):
            with self.subTest(substate=substate):
                self.assertTrue(
                    _gateway_socket_ready_state(
                        {"ActiveState": "active", "SubState": substate}
                    )
                )

        for active_state, substate in (
            ("inactive", "dead"),
            ("activating", "start"),
            ("active", "start-chown"),
            ("active", "failed"),
        ):
            with self.subTest(
                active_state=active_state,
                substate=substate,
            ):
                self.assertFalse(
                    _gateway_socket_ready_state(
                        {
                            "ActiveState": active_state,
                            "SubState": substate,
                        }
                    )
                )

    def test_missing_state_fields_fail_closed(self) -> None:
        self.assertFalse(_running_state({}))
        self.assertFalse(_gateway_socket_ready_state({}))
        self.assertFalse(
            _gateway_socket_ready_state({"ActiveState": "active"})
        )


class GatewaySocketWaitTests(unittest.TestCase):
    @staticmethod
    def _backend() -> SystemdFilesystemBackend:
        backend = object.__new__(SystemdFilesystemBackend)
        backend.wait_timeout_seconds = 1
        return backend

    def test_listening_socket_satisfies_ready_wait(self) -> None:
        backend = self._backend()
        backend._show = mock.Mock(
            return_value={
                "ActiveState": "active",
                "SubState": "listening",
            }
        )
        with mock.patch(
            "core_release_selector_r4c_live_backend.time.monotonic",
            side_effect=(0.0, 0.1),
        ):
            backend._wait_gateway_socket_ready(True)
        backend._show.assert_called_once_with(
            GATEWAY_SOCKET_UNIT,
            ("ActiveState", "SubState"),
        )

    def test_listening_socket_does_not_satisfy_inactive_wait(self) -> None:
        backend = self._backend()
        backend._show = mock.Mock(
            return_value={
                "ActiveState": "active",
                "SubState": "listening",
            }
        )
        with (
            mock.patch(
                "core_release_selector_r4c_live_backend.time.monotonic",
                side_effect=(0.0, 0.1, 1.1),
            ),
            mock.patch(
                "core_release_selector_r4c_live_backend.time.sleep"
            ),
            self.assertRaisesRegex(
                LiveBackendError,
                "gateway_socket_state_timeout",
            ),
        ):
            backend._wait_gateway_socket_ready(False)

    def test_inactive_socket_satisfies_inactive_wait(self) -> None:
        backend = self._backend()
        backend._show = mock.Mock(
            return_value={
                "ActiveState": "inactive",
                "SubState": "dead",
            }
        )
        with mock.patch(
            "core_release_selector_r4c_live_backend.time.monotonic",
            side_effect=(0.0, 0.1),
        ):
            backend._wait_gateway_socket_ready(False)


if __name__ == "__main__":
    unittest.main()
