#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re

import activate_p07c_telegram_diary_entry_v1 as entry
from p07_d_generation13_release_set import phase_f_selected_target


PREVIOUS_PLUGIN_RELEASE = (
    "dd5f3cc36344b920b9984929d0e88aa18b46879d3292e5209facb3f07084f13f"
)
RUNTIME_RELEASE = (
    "01b9b766bf0fc46dc8c33055b578dda3888159dd8857aab38e19406e5523d22a"
)
BACKUP_ROOT = Path("/var/backups/myuna/p07c-telegram-diary-consent-layer-v1")
STATE_ROOT = Path("/var/lib/myuna-telegram-gateway/p07c-diary-consent-layer-v1")
SCHEMA = "myuna.p07c-telegram-diary-consent-layer-activation.v1"
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


class ActivationRejected(RuntimeError):
    """The narrow Telegram Diary consent-layer repair was rejected."""


def expected_plugin_path(digest: str) -> str:
    return (
        entry.PLUGIN_ROOT
        / digest
        / "channels/astrbot-telegram/plugin/myuna_telegram_gateway"
    ).as_posix()


def verify_selection(plugin_digest: str) -> None:
    if not all(entry.active(unit) for unit in (entry.RUNTIME_SOCKET, entry.RUNTIME_SERVICE)):
        raise ActivationRejected("Telegram runtime units rejected")
    if (
        f"/{RUNTIME_RELEASE}/runtime/telegram_owner_runtime_gateway.py"
        not in entry.effective_runtime()
    ):
        raise ActivationRejected("Telegram runtime selection rejected")
    if (
        entry.DROPIN.is_symlink()
        or entry.DROPIN.read_bytes() != entry.render_dropin(RUNTIME_RELEASE)
    ):
        raise ActivationRejected("Telegram runtime drop-in rejected")
    if (
        entry.CONFIG.is_symlink()
        or entry.CONFIG.read_bytes() != entry.render_config(plugin_digest)
    ):
        raise ActivationRejected("Telegram plugin config rejected")
    if (
        expected_plugin_path(plugin_digest) not in entry.container_mounts()
        or not entry.container_healthy()
    ):
        raise ActivationRejected("Telegram plugin container rejected")


def backup_prestate(activation_id: str) -> tuple[Path, bytes]:
    backup = BACKUP_ROOT / activation_id
    backup.mkdir(parents=True, mode=0o700)
    os.chmod(BACKUP_ROOT, 0o700)
    config_bytes = entry.CONFIG.read_bytes()
    entry.atomic_write(backup / "r5-resume-v1.json", config_bytes, mode=0o600)
    entry.atomic_write(
        backup / "PRESTATE.json",
        entry.canonical_bytes(
            {
                "config_sha256": sha256(config_bytes).hexdigest(),
                "plugin_release": PREVIOUS_PLUGIN_RELEASE,
                "runtime_release": RUNTIME_RELEASE,
                "schema": SCHEMA,
            }
        ),
        mode=0o600,
    )
    return backup, config_bytes


def restore(config_bytes: bytes) -> None:
    entry.atomic_write(entry.CONFIG, config_bytes, mode=0o600)
    entry.run_resume_controller()
    verify_selection(PREVIOUS_PLUGIN_RELEASE)


def activate(
    plugin_candidate: Path,
    *,
    source_commit: str,
    preflight_only: bool,
) -> dict[str, object]:
    if os.geteuid() != 0:
        raise ActivationRejected("root identity required")
    if _COMMIT.fullmatch(source_commit) is None:
        raise ActivationRejected("source commit rejected")
    try:
        plugin_digest = entry.validate_plugin_candidate(plugin_candidate)
        verify_selection(PREVIOUS_PLUGIN_RELEASE)
    except entry.ActivationRejected as exc:
        raise ActivationRejected(str(exc)) from exc
    if preflight_only:
        return {
            "plugin_release": plugin_digest,
            "runtime_release": RUNTIME_RELEASE,
            "status": "ready",
        }
    if phase_f_selected_target(Path(__file__).resolve().parent):
        raise ActivationRejected("phase_f_canonical_owner_required")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    activation_id = f"{stamp}-{plugin_digest[:16]}"
    backup, config_bytes = backup_prestate(activation_id)
    STATE_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STATE_ROOT, 0o700)
    journal = STATE_ROOT / f"JOURNAL-{activation_id}.json"
    receipt = STATE_ROOT / f"RECEIPT-{activation_id}.json"
    entry.atomic_write(
        journal,
        entry.canonical_bytes(
            {
                "activation_id": activation_id,
                "model_called": False,
                "raw_message_recorded": False,
                "schema": SCHEMA,
                "status": "activating",
            }
        ),
        mode=0o600,
    )
    try:
        entry.install_plugin(plugin_candidate, plugin_digest)
        entry.atomic_write(
            entry.CONFIG,
            entry.render_config(plugin_digest),
            mode=0o600,
        )
        entry.run_resume_controller()
        verify_selection(plugin_digest)
        payload = {
            "activation_id": activation_id,
            "backup": backup.name,
            "model_called": False,
            "plugin_release": plugin_digest,
            "profile_content_recorded": False,
            "raw_identity_recorded": False,
            "raw_message_recorded": False,
            "runtime_release": RUNTIME_RELEASE,
            "schema": SCHEMA,
            "source_commit": source_commit,
            "status": "ACTIVE_WAITING_OWNER_DIARY_E2E",
        }
        entry.atomic_write(receipt, entry.canonical_bytes(payload), mode=0o600)
        entry.atomic_write(journal, entry.canonical_bytes(payload), mode=0o600)
        return payload
    except Exception:
        restore(config_bytes)
        entry.atomic_write(
            journal,
            entry.canonical_bytes(
                {
                    "activation_id": activation_id,
                    "model_called": False,
                    "rollback": "verified",
                    "schema": SCHEMA,
                    "status": "rolled_back",
                }
            ),
            mode=0o600,
        )
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plugin-candidate", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    try:
        result = activate(
            args.plugin_candidate.resolve(),
            source_commit=args.source_commit,
            preflight_only=args.preflight_only,
        )
    except (ActivationRejected, entry.ActivationRejected) as exc:
        print(
            json.dumps(
                {"error": str(exc), "status": "rejected"},
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
