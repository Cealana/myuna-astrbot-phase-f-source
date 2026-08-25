#!/usr/bin/env python3
from __future__ import annotations

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError
from urllib.request import urlopen


def choose_port() -> int:
    with closing(socket.socket()) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def fetch(url: str) -> tuple[int, dict[str, object]]:
    try:
        with urlopen(url, timeout=1.0) as response:
            return response.status, json.load(response)
    except HTTPError as exc:
        return exc.code, json.load(exc)


def wait_for_health(base_url: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"server exited early with code {process.returncode}")
        try:
            status, payload = fetch(base_url + "/healthz")
            if status == 200 and payload.get("status") == "alive":
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise RuntimeError("health endpoint did not become ready")


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke-test the inactive Myuna bootstrap surface")
    parser.add_argument("--core", type=Path, required=True)
    args = parser.parse_args()

    core = args.core.resolve()
    port = choose_port()
    with tempfile.TemporaryDirectory(prefix="myuna-smoke-") as temporary:
        root = Path(temporary)
        environment = os.environ.copy()
        environment.update(
            {
                "PYTHONPATH": str(core / "src"),
                "MYUNA_ENV": "dev",
                "MYUNA_BIND_HOST": "127.0.0.1",
                "MYUNA_PORT": str(port),
                "MYUNA_DATA_DIR": str(root / "data"),
                "MYUNA_LOG_DIR": str(root / "logs"),
                "MYUNA_DEFINITION_RELEASE": "",
                "MYUNA_PROVIDERS_ENABLED": "",
            }
        )
        process = subprocess.Popen(
            [sys.executable, "-m", "myuna_core"],
            cwd=core,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        base_url = f"http://127.0.0.1:{port}"
        try:
            wait_for_health(base_url, process)
            health_status, health = fetch(base_url + "/healthz")
            ready_status, ready = fetch(base_url + "/readyz")
            status_code, status = fetch(base_url + "/v1/status")
            post_request = __import__("urllib.request", fromlist=["Request"]).Request(
                base_url + "/v1/chat", data=b"{}", method="POST"
            )
            try:
                urlopen(post_request, timeout=1.0)
                raise AssertionError("POST unexpectedly succeeded")
            except HTTPError as exc:
                post_status = exc.code
                post_payload = json.load(exc)

            assert health_status == 200 and health["status"] == "alive"
            assert ready_status == 503 and ready["status"] == "not_ready"
            assert status_code == 200 and status["ready"] is False
            assert sorted(status["reasons"]) == ["no_approved_definition", "no_enabled_provider"]
            assert post_status == 503 and post_payload["error"] == "runtime_not_activated"

            print(
                json.dumps(
                    {
                        "health": health,
                        "readiness": ready,
                        "status": status,
                        "post_guard": post_payload,
                        "result": "pass",
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
        finally:
            process.terminate()
            try:
                process.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3.0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
