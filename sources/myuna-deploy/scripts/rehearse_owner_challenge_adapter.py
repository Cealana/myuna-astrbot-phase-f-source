#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time


CONFIG_PATH = Path("/etc/myuna-gateway/owner-challenge-v1.json")
ACTIVATION_PATH = Path("/etc/myuna-gateway/activation-approved")
EVIDENCE_PATH = Path("/var/lib/myuna-gateway/owner-challenge-v1-evidence.json")
SOCKET_PATH = Path("/run/myuna-gateway/challenge.sock")
SIGNING_PATH = Path("/etc/myuna-gateway/secrets/channel-signing-v1")
PEPPER_PATH = Path("/etc/myuna-gateway/secrets/identity-pepper-v1")
PLUGIN_PROTOCOL = Path(
    "/srv/myuna/channel-adapters/astrbot_plugin_myuna_gateway/v1/protocol.py"
)
CORE_PATH = Path("/usr/local/lib/myuna-gateway/core-v1")


class RehearsalError(RuntimeError):
    pass


def _run(
    command: list[str],
    *,
    check: bool = True,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if check and result.returncode != 0:
        raise RehearsalError("owner challenge rehearsal command failed")
    return result


def _load_protocol():
    spec = importlib.util.spec_from_file_location("myuna_gateway_protocol_rehearsal", PLUGIN_PROTOCOL)
    if spec is None or spec.loader is None:
        raise RehearsalError("installed plugin protocol is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_protected(path: Path, payload: bytes, mode: int, gid: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
        os.fchown(descriptor, 0, gid)
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


def _identity_counts() -> str:
    result = _run(
        [
            "runuser",
            "-u",
            "postgres",
            "--",
            "psql",
            "--dbname=myuna_dev",
            "--no-psqlrc",
            "--no-align",
            "--tuples-only",
            "--command",
            "SELECT count(*) - 1, (SELECT count(*) - 1 FROM memory.memory_namespace), "
            "(SELECT count(*) FROM myuna_identity.account_binding) "
            "FROM myuna_identity.principal;",
        ]
    )
    return result.stdout.strip()


def _delete_synthetic_event(event_id: str) -> None:
    _run(
        [
            "runuser",
            "-u",
            "postgres",
            "--",
            "psql",
            "--dbname=myuna_dev",
            "--no-psqlrc",
            "--set=ON_ERROR_STOP=1",
            f"--set=event_id={event_id}",
        ],
        check=False,
        input_text=(
            "DELETE FROM gateway_runtime.inbound_event "
            "WHERE channel_kind = 'astrbot_qq' "
            "AND channel_instance = 'napcat-rehearsal' "
            "AND event_id = :'event_id';\n"
        ),
    )


def main() -> int:
    if os.geteuid() != 0:
        raise RehearsalError("run as root")
    if _identity_counts() != "0|0|0":
        raise RehearsalError("rehearsal requires zero real identity rows")
    for path in (CONFIG_PATH, ACTIVATION_PATH, EVIDENCE_PATH, SOCKET_PATH):
        if path.exists():
            raise RehearsalError("rehearsal gate is not clean")

    sys.path.insert(0, str(CORE_PATH))
    from myuna_core.identity import account_fingerprint

    protocol = _load_protocol()
    signing_secret = SIGNING_PATH.read_bytes().strip()
    identity_pepper = PEPPER_PATH.read_bytes().strip()
    synthetic_sender = "9876543210"
    synthetic_challenge = "rehearsal-" + secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    gateway_gid = int(_run(["id", "-g", "myuna-gateway"]).stdout.strip())
    config = {
        "account_fingerprint": account_fingerprint(
            "astrbot_qq", synthetic_sender, identity_pepper
        ),
        "binding_id": "binding-synthetic-owner-rehearsal",
        "challenge_sha256": sha256(synthetic_challenge.encode("utf-8")).hexdigest(),
        "expires_at": (now + timedelta(minutes=10)).isoformat(timespec="seconds"),
        "namespace_id": "ns-synthetic-owner-rehearsal",
        "plan_digest": sha256(b"synthetic-owner-challenge-rehearsal-v1").hexdigest(),
        "principal_id": "principal-synthetic-owner-rehearsal",
    }
    envelope = protocol.build_signed_envelope(
        sender_id=synthetic_sender,
        message_text=synthetic_challenge,
        message_id="synthetic-owner-challenge-rehearsal",
        raw_timestamp=now.timestamp(),
        signing_secret=signing_secret,
        channel_instance="napcat-rehearsal",
        now=now,
        nonce_factory=lambda: "r" * 32,
    )
    event_id = envelope["event"]["event_id"]

    try:
        _write_protected(
            CONFIG_PATH,
            (json.dumps(config, sort_keys=True, indent=2) + "\n").encode("utf-8"),
            0o640,
            gateway_gid,
        )
        _write_protected(ACTIVATION_PATH, b"synthetic-rehearsal-only\n", 0o644, 0)
        _run(["systemctl", "start", "myuna-channel-gateway-dev.socket"])
        for _ in range(50):
            if SOCKET_PATH.is_socket():
                break
            time.sleep(0.1)
        if not SOCKET_PATH.is_socket():
            raise RehearsalError("challenge socket did not start")
        result = protocol.send_envelope(SOCKET_PATH, envelope, timeout=5)
        if result != {"status": "accepted", "code": "owner-challenge-accepted"}:
            raise RehearsalError("synthetic challenge was not accepted")
        evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        if evidence.get("result") != "qq-private-challenge-matched":
            raise RehearsalError("synthetic evidence is invalid")
        if _identity_counts() != "0|0|0":
            raise RehearsalError("rehearsal changed real identity rows")
    finally:
        _run(
            [
                "systemctl",
                "stop",
                "myuna-channel-gateway-dev.socket",
                "myuna-channel-gateway-dev.service",
            ],
            check=False,
        )
        for path in (EVIDENCE_PATH, ACTIVATION_PATH, CONFIG_PATH):
            path.unlink(missing_ok=True)
        _delete_synthetic_event(event_id)

    if _identity_counts() != "0|0|0" or SOCKET_PATH.exists():
        raise RehearsalError("rehearsal cleanup failed")
    print("Synthetic owner challenge rehearsal passed; real identity rows remain zero.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RehearsalError, subprocess.SubprocessError) as exc:
        print(f"owner challenge rehearsal failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
