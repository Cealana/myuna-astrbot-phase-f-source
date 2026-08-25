from __future__ import annotations

from pathlib import Path
from typing import Mapping
import os
import stat


class CredentialError(RuntimeError):
    pass


def load_systemd_credential(
    name: str = "deepseek_api_key",
    *,
    environ: Mapping[str, str] | None = None,
) -> str:
    source = os.environ if environ is None else environ
    if source.get("DEEPSEEK_API_KEY"):
        raise CredentialError("environment-variable API keys are forbidden")
    directory_raw = source.get("CREDENTIALS_DIRECTORY", "")
    if not directory_raw:
        raise CredentialError("systemd credential directory is unavailable")
    directory = Path(directory_raw)
    if not directory.is_absolute():
        raise CredentialError("systemd credential directory must be absolute")
    path = directory / name
    if path.is_symlink() or not path.is_file():
        raise CredentialError("systemd credential is missing or unsafe")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o007:
        raise CredentialError("systemd credential must not be world-readable")
    value = path.read_text(encoding="utf-8")
    if value.endswith("\n"):
        value = value[:-1]
    if not 8 <= len(value) <= 4096 or "\n" in value or "\r" in value:
        raise CredentialError("systemd credential has an invalid format")
    return value
