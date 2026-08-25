#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import pwd
import stat
import sys
import tempfile
from typing import Mapping

from telegram_bot_token_intake import TOKEN_PATH, TokenIntakeRejected, validate_token


BASELINE_PATH = Path(
    "/srv/myuna/channels/astrbot-telegram/dev/astrbot-data/cmd_config.json"
)
TELEGRAM_USER = "myuna-gateway-telegram"


class ConfigRenderRejected(RuntimeError):
    """Content-free rejection; never include config or token values."""


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ConfigRenderRejected("Telegram config render rejected")
    return {str(key): copy.deepcopy(child) for key, child in value.items()}


def render_config(baseline: object, token: str) -> dict[str, object]:
    if not isinstance(token, str):
        raise ConfigRenderRejected("Telegram config render rejected")
    try:
        validate_token(token.encode("ascii"))
    except (UnicodeEncodeError, TokenIntakeRejected):
        raise ConfigRenderRejected("Telegram config render rejected") from None

    rendered = _object(baseline)
    if not isinstance(rendered.get("platform", []), list):
        raise ConfigRenderRejected("Telegram config render rejected")
    provider_settings = _object(rendered.get("provider_settings", {}))
    proactive = _object(provider_settings.get("proactive_capability", {}))

    rendered["admins_id"] = []
    rendered["disable_builtin_commands"] = True
    rendered["provider"] = []
    rendered["provider_sources"] = []
    provider_settings["enable"] = False
    provider_settings["web_search"] = False
    proactive["add_cron_tools"] = False
    provider_settings["proactive_capability"] = proactive
    rendered["provider_settings"] = provider_settings
    rendered["platform"] = [
        {
            "enable": True,
            "id": "telegram-owner-private",
            "start_message": (
                "Myuna Telegram 安全入口已启动；请按 Owner 绑定流程继续"
            ),
            "telegram_api_base_url": "https://api.telegram.org/bot",
            "telegram_command_auto_refresh": False,
            "telegram_command_register": False,
            "telegram_file_base_url": "https://api.telegram.org/file/bot",
            "telegram_polling_restart_delay": 5.0,
            "telegram_token": token,
            "type": "telegram",
        }
    ]
    return rendered


def validate_rendered_config(payload: object) -> None:
    rendered = _object(payload)
    platforms = rendered.get("platform")
    if not isinstance(platforms, list) or len(platforms) != 1:
        raise ConfigRenderRejected("Telegram config render rejected")
    platform = _object(platforms[0])
    if (
        platform.get("type") != "telegram"
        or platform.get("enable") is not True
        or platform.get("telegram_command_register") is not False
        or platform.get("telegram_command_auto_refresh") is not False
    ):
        raise ConfigRenderRejected("Telegram config render rejected")
    token = platform.get("telegram_token")
    if not isinstance(token, str):
        raise ConfigRenderRejected("Telegram config render rejected")
    try:
        validate_token(token.encode("ascii"))
    except (UnicodeEncodeError, TokenIntakeRejected):
        raise ConfigRenderRejected("Telegram config render rejected") from None
    if rendered.get("provider") != [] or rendered.get("provider_sources") != []:
        raise ConfigRenderRejected("Telegram config render rejected")
    if rendered.get("admins_id") != []:
        raise ConfigRenderRejected("Telegram config render rejected")
    provider_settings = _object(rendered.get("provider_settings"))
    if (
        provider_settings.get("enable") is not False
        or provider_settings.get("web_search") is not False
    ):
        raise ConfigRenderRejected("Telegram config render rejected")


def _load_regular_json(path: Path, *, require_root_owner: bool) -> object:
    if path.is_symlink() or not path.is_file():
        raise ConfigRenderRejected("Telegram config render rejected")
    metadata = path.stat()
    if require_root_owner and metadata.st_uid != 0:
        raise ConfigRenderRejected("Telegram config render rejected")
    if metadata.st_mode & 0o077:
        raise ConfigRenderRejected("Telegram config render rejected")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise ConfigRenderRejected("Telegram config render rejected") from None


def _write_atomic(path: Path, payload: bytes, *, uid: int, gid: int) -> None:
    descriptor: int | None = None
    temporary_name: str | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".cmd-config-",
            dir=path.parent,
        )
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def main() -> int:
    if os.geteuid() != 0:
        raise ConfigRenderRejected("local root authority is required")
    try:
        service_user = pwd.getpwnam(TELEGRAM_USER)
    except KeyError:
        raise ConfigRenderRejected("Telegram service account is unavailable") from None
    baseline = _load_regular_json(BASELINE_PATH, require_root_owner=False)
    token_bytes = bytearray(TOKEN_PATH.read_bytes())
    try:
        token = validate_token(bytes(token_bytes)).decode("ascii")
        rendered = render_config(baseline, token)
        validate_rendered_config(rendered)
        serialized = (
            json.dumps(rendered, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        _write_atomic(
            BASELINE_PATH,
            serialized,
            uid=service_user.pw_uid,
            gid=service_user.pw_gid,
        )
    except (OSError, TokenIntakeRejected, UnicodeDecodeError):
        raise ConfigRenderRejected("Telegram config render rejected") from None
    finally:
        for index in range(len(token_bytes)):
            token_bytes[index] = 0
        token = ""

    metadata = BASELINE_PATH.stat()
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ConfigRenderRejected("Telegram config render rejected")
    print(
        json.dumps(
            {
                "astrbot_provider_enabled": False,
                "bot_token_echoed": False,
                "config_mode": "0600",
                "result": "telegram-astrbot-config-rendered",
                "telegram_platform_count": 1,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ConfigRenderRejected):
        print("Telegram config render rejected", file=sys.stderr)
        raise SystemExit(1) from None
