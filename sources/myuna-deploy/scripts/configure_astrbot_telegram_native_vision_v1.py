from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import stat
import tempfile


UTF8_BOM = b"\xef\xbb\xbf"
PROVIDER_ID = "myuna_telegram_native_vision_gemini"
PROVIDER_SOURCE_ID = f"{PROVIDER_ID}_source"
ENV_REFERENCE = "$MYUNA_TELEGRAM_GEMINI_API_KEY"


class NativeVisionConfigRejected(RuntimeError):
    """Configuration mutation was rejected without exposing configuration."""


def provider_entry() -> dict[str, object]:
    return {
        "id": PROVIDER_ID,
        "provider_source_id": PROVIDER_SOURCE_ID,
        "model": "gemini-3.6-flash",
        "modalities": [],
        "custom_extra_body": {},
        "enable": True,
    }


def provider_source_entry() -> dict[str, object]:
    return {
        "id": PROVIDER_SOURCE_ID,
        "provider": "google",
        "type": "googlegenai_chat_completion",
        "provider_type": "chat_completion",
        "key": [ENV_REFERENCE],
        "api_base": "https://generativelanguage.googleapis.com/",
        "timeout": 90,
        "gm_resp_image_modal": False,
        "gm_native_search": False,
        "gm_native_coderunner": False,
        "gm_url_context": False,
        "gm_safety_settings": {
            "harassment": "BLOCK_MEDIUM_AND_ABOVE",
            "hate_speech": "BLOCK_MEDIUM_AND_ABOVE",
            "sexually_explicit": "BLOCK_MEDIUM_AND_ABOVE",
            "dangerous_content": "BLOCK_MEDIUM_AND_ABOVE",
        },
        "gm_thinking_config": {"budget": 0, "level": "MINIMAL"},
        "proxy": "",
    }


def legacy_provider_entry() -> dict[str, object]:
    result = provider_entry()
    result["model"] = "gemini-2.5-flash"
    return result


def legacy_provider_source_entry() -> dict[str, object]:
    result = provider_source_entry()
    result["gm_thinking_config"]["level"] = "HIGH"
    return result


def decode_config(raw: bytes) -> dict[str, object]:
    if not raw.startswith(UTF8_BOM):
        raise NativeVisionConfigRejected("configuration rejected")
    try:
        decoded = raw.decode("utf-8-sig")
        document = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NativeVisionConfigRejected("configuration rejected") from exc
    if not isinstance(document, dict):
        raise NativeVisionConfigRejected("configuration rejected")
    return document


def mutate_document(document: dict[str, object]) -> dict[str, object]:
    providers = document.get("provider")
    provider_sources = document.get("provider_sources")
    platforms = document.get("platform")
    if (
        not isinstance(providers, list)
        or not isinstance(provider_sources, list)
        or not isinstance(platforms, list)
    ):
        raise NativeVisionConfigRejected("configuration rejected")
    provider_indices = [
        index
        for index, item in enumerate(providers)
        if isinstance(item, dict) and item.get("id") == PROVIDER_ID
    ]
    source_indices = [
        index
        for index, item in enumerate(provider_sources)
        if isinstance(item, dict) and item.get("id") == PROVIDER_SOURCE_ID
    ]
    if len(provider_indices) != len(source_indices) or len(provider_indices) > 1:
        raise NativeVisionConfigRejected("configuration rejected")
    if sum(
        isinstance(item, dict) and item.get("type") == "telegram"
        for item in platforms
    ) != 1:
        raise NativeVisionConfigRejected("configuration rejected")
    unrelated = copy.deepcopy(document)
    if provider_indices:
        existing_provider = providers[provider_indices[0]]
        existing_source = provider_sources[source_indices[0]]
        allowed_pairs = (
            (legacy_provider_entry(), legacy_provider_source_entry()),
            (provider_entry(), provider_source_entry()),
        )
        if (existing_provider, existing_source) not in allowed_pairs:
            raise NativeVisionConfigRejected("configuration rejected")
        del unrelated["provider"][provider_indices[0]]
        del unrelated["provider_sources"][source_indices[0]]
    encoded_unrelated = json.dumps(
        unrelated,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    if ENV_REFERENCE in encoded_unrelated:
        raise NativeVisionConfigRejected("configuration rejected")

    result = copy.deepcopy(document)
    if provider_indices:
        result["provider"][provider_indices[0]] = provider_entry()
        result["provider_sources"][source_indices[0]] = provider_source_entry()
    else:
        result["provider"].append(provider_entry())
        result["provider_sources"].append(provider_source_entry())
    return result


def mutate_bytes(raw: bytes) -> bytes:
    document = decode_config(raw)
    mutated = mutate_document(document)
    encoded = json.dumps(
        mutated,
        ensure_ascii=False,
        indent=2,
        separators=(",", ": "),
    ).encode("utf-8")
    return UTF8_BOM + encoded + b"\n"


def configure(path: Path) -> dict[str, bool]:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise NativeVisionConfigRejected("configuration rejected") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise NativeVisionConfigRejected("configuration rejected")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise NativeVisionConfigRejected("configuration rejected") from exc
    mutated = mutate_bytes(raw)

    descriptor, temporary = tempfile.mkstemp(prefix=".cmd-config.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, metadata.st_uid, metadata.st_gid)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(mutated)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as exc:
        raise NativeVisionConfigRejected("configuration rejected") from exc
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass

    after = os.lstat(path)
    verified = decode_config(path.read_bytes())
    target = [
        item
        for item in verified["provider"]
        if isinstance(item, dict) and item.get("id") == PROVIDER_ID
    ]
    target_source = [
        item
        for item in verified["provider_sources"]
        if isinstance(item, dict) and item.get("id") == PROVIDER_SOURCE_ID
    ]
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISREG(after.st_mode)
        or stat.S_IMODE(after.st_mode) != 0o600
        or after.st_uid != metadata.st_uid
        or after.st_gid != metadata.st_gid
        or target != [provider_entry()]
        or target_source != [provider_source_entry()]
    ):
        raise NativeVisionConfigRejected("configuration rejected")
    return {
        "bom_preserved": True,
        "provider_added": True,
        "provider_source_added": True,
        "semantic_diff_provider_and_source_only": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    try:
        result = configure(args.config)
    except NativeVisionConfigRejected:
        print(json.dumps({"status": "rejected"}, separators=(",", ":")))
        return 1
    print(
        json.dumps(
            {"status": "configured", **result},
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
