#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


BASE_RELEASE_DIGEST = (
    "ea55dd9dd75c9e644c45449290e99959333b1a9a3f8b4b4479b8da21f27d7044"
)
BASE_RELEASE = Path("/opt/myuna/context24-gateway/telegram/releases") / BASE_RELEASE_DIGEST
REPLACEMENT = Path("runtime/telegram_owner_runtime_gateway.py")
SOURCE = Path("scripts/telegram_owner_runtime_gateway.py")
READINESS_REPLACEMENT = Path("runtime/p07_d_runtime_readiness.py")
READINESS_SOURCE = Path("scripts/p07_d_runtime_readiness.py")
SCHEMA = "myuna.p07c-telegram-diary-runtime-repair.v1"


class BuildRejected(RuntimeError):
    """The bounded P07-C Telegram runtime build was rejected."""


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def digest_file(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def git_head(repo: Path) -> str:
    try:
        return subprocess.check_output(
            [
                "git",
                "-c",
                f"safe.directory={repo}",
                "-C",
                str(repo),
                "rev-parse",
                "HEAD",
            ],
            text=True,
        ).strip()
    except subprocess.SubprocessError as exc:
        raise BuildRejected("source commit rejected") from exc


def validate_base(base_release: Path = BASE_RELEASE) -> None:
    try:
        manifest = json.loads((base_release / "MANIFEST.json").read_text("utf-8"))
        if manifest.get("release_digest") != BASE_RELEASE_DIGEST:
            raise BuildRejected("base release digest rejected")
        files = manifest.get("files")
        if not isinstance(files, dict) or not files:
            raise BuildRejected("base release manifest rejected")
        for relative, expected in files.items():
            path = base_release / relative
            if (
                not isinstance(relative, str)
                or not isinstance(expected, str)
                or path.is_symlink()
                or not path.is_file()
                or digest_file(path) != expected
            ):
                raise BuildRejected("base release bytes rejected")
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BuildRejected("base release rejected") from exc


def validate_runtime(runtime: Path) -> None:
    for path in sorted(runtime.rglob("*.py")):
        ast.parse(path.read_text("utf-8"), filename=str(path))
    probe = """
import importlib.util
from pathlib import Path
import sys
runtime = Path(sys.argv[1])
sys.path.insert(0, str(runtime))
source = runtime / "telegram_owner_runtime_gateway.py"
spec = importlib.util.spec_from_file_location("p07c_diary_runtime_candidate", source)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
assert module.CORE_REQUEST_TIMEOUT_SECONDS == 165
assert module.diary_command_is_explicit("/Diary synthetic archive control")
assert module.diary_command_is_explicit("/Diary")
assert module.benchmark_intent_grants_profile_consent("/Benchmark synthetic stable preference")
assert module.benchmark_intent_grants_profile_consent("/Benchmark confirm ABCDEF123456")
assert not module.benchmark_intent_grants_profile_consent("/Diary archive")
assert not module.benchmark_intent_grants_profile_consent("ordinary chat")
assert not module.benchmark_intent_grants_profile_consent("/status")
"""
    subprocess.run(
        ["python3", "-B", "-c", probe, str(runtime)],
        check=True,
        capture_output=True,
        text=True,
    )


def build(repo: Path, output_root: Path) -> tuple[str, Path, dict[str, object]]:
    validate_base()
    source = repo / SOURCE
    readiness_source = repo / READINESS_SOURCE
    if (
        source.is_symlink()
        or not source.is_file()
        or readiness_source.is_symlink()
        or not readiness_source.is_file()
    ):
        raise BuildRejected("runtime source rejected")
    output_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".p07c-diary-runtime-", dir=output_root) as tmp:
        stage = Path(tmp) / "release"
        shutil.copytree(BASE_RELEASE, stage)
        for path in (stage, *stage.rglob("*")):
            path.chmod(0o750 if path.is_dir() else 0o640)
        shutil.copyfile(source, stage / REPLACEMENT)
        shutil.copyfile(readiness_source, stage / READINESS_REPLACEMENT)
        validate_runtime(stage / "runtime")
        files = {
            path.relative_to(stage).as_posix(): digest_file(path)
            for path in sorted((stage / "runtime").rglob("*.py"))
        }
        identity = {
            "base_release_digest": BASE_RELEASE_DIGEST,
            "files": files,
            "policy": {
                "core_timeout_seconds": 165,
                "diary_context": "single-turn-not-session-persisted",
                "intent": "explicit-diary-only",
                "raw_content_in_manifest": False,
                "scope": "telegram-owner-private-only",
            },
            "schema": SCHEMA,
            "source_deploy_commit": git_head(repo),
        }
        digest = sha256(canonical_bytes(identity)).hexdigest()
        destination = output_root / digest
        if destination.exists() or destination.is_symlink():
            raise BuildRejected("runtime output rejected")
        manifest = {
            **identity,
            "destination": f"/opt/myuna/context24-gateway/telegram/releases/{digest}",
            "release_digest": digest,
        }
        (stage / "MANIFEST.json").write_bytes(canonical_bytes(manifest) + b"\n")
        stage.rename(destination)
    return digest, destination, manifest


def verify(candidate: Path, manifest: dict[str, object]) -> bool:
    try:
        if json.loads((candidate / "MANIFEST.json").read_text("utf-8")) != manifest:
            return False
        files = manifest["files"]
        return isinstance(files, dict) and all(
            (candidate / relative).is_file()
            and not (candidate / relative).is_symlink()
            and digest_file(candidate / relative) == expected
            for relative, expected in files.items()
        )
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("build/p07c-telegram-diary-runtime-v1"),
    )
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    try:
        digest, candidate, manifest = build(repo, args.output_root.resolve())
        if not verify(candidate, manifest):
            raise BuildRejected("runtime verification rejected")
    except BuildRejected:
        print(json.dumps({"status": "rejected"}, separators=(",", ":")))
        return 1
    print(
        json.dumps(
            {
                "candidate": str(candidate),
                "release_digest": digest,
                "status": "built",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
