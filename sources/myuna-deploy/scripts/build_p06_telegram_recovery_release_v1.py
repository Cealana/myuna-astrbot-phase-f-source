#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


BASE_RELEASE_DIGEST = (
    "a75ebd22247755b19556f11c07807bb08beb76783d40510af647afdde0d552f5"
)
BASE_RELEASE = (
    Path("/opt/myuna/context24-gateway/telegram/releases")
    / BASE_RELEASE_DIGEST
)
REPLACEMENTS = {
    "runtime/gateway_recovery_episode.py": "scripts/gateway_recovery_episode.py",
    "runtime/p07_d_runtime_readiness.py": "scripts/p07_d_runtime_readiness.py",
    "runtime/telegram_owner_runtime_gateway.py": (
        "scripts/telegram_owner_runtime_gateway.py"
    ),
}
SCHEMA = "myuna.telegram-owner-recovery-release.v1"


class RecoveryReleaseRejected(RuntimeError):
    """The content-addressed recovery runtime candidate was rejected."""


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_base_release(base_release: Path = BASE_RELEASE) -> None:
    try:
        manifest = json.loads(
            (base_release / "MANIFEST.json").read_text(encoding="utf-8")
        )
        if manifest.get("release_digest") != BASE_RELEASE_DIGEST:
            raise RecoveryReleaseRejected("base release digest rejected")
        files = manifest.get("files")
        if not isinstance(files, dict) or not files:
            raise RecoveryReleaseRejected("base release manifest rejected")
        for relative, expected in files.items():
            path = base_release / relative
            if (
                not isinstance(relative, str)
                or not isinstance(expected, str)
                or path.is_symlink()
                or not path.is_file()
                or digest_file(path) != expected
            ):
                raise RecoveryReleaseRejected("base release bytes rejected")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryReleaseRejected("base release rejected") from exc


def _git_head(repo: Path) -> str:
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
        raise RecoveryReleaseRejected("source commit rejected") from exc


def _validate_runtime(runtime: Path) -> None:
    for path in sorted(runtime.rglob("*.py")):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    probe = """
import importlib.util
import os
from pathlib import Path
import sys

runtime = Path(sys.argv[1])
sys.path.insert(0, str(runtime))
os.environ["MYUNA_SESSION_CONTEXT_STORE"] = "memory"
path = runtime / "telegram_owner_runtime_gateway.py"
spec = importlib.util.spec_from_file_location("candidate_telegram_runtime", path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
assert type(module._build_context_store()).__name__ == "InMemoryContextStore"
assert module.RECOVERY_NOTICE_TEXT
"""
    subprocess.run(
        ["python3", "-B", "-c", probe, str(runtime)],
        check=True,
        capture_output=True,
        text=True,
    )


def build(
    repo: Path,
    output_root: Path,
    *,
    base_release: Path = BASE_RELEASE,
) -> tuple[str, Path, dict[str, object]]:
    _validate_base_release(base_release)
    for relative in REPLACEMENTS.values():
        source = repo / relative
        if source.is_symlink() or not source.is_file():
            raise RecoveryReleaseRejected("candidate source rejected")

    output_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".p06-telegram-recovery-v1-",
        dir=output_root,
    ) as temporary:
        stage = Path(temporary) / "release"
        shutil.copytree(base_release, stage)
        for path in (stage, *stage.rglob("*")):
            path.chmod(0o750 if path.is_dir() else 0o640)
        for destination, source in REPLACEMENTS.items():
            target = stage / destination
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(repo / source, target)
        _validate_runtime(stage / "runtime")

        files = {
            path.relative_to(stage).as_posix(): digest_file(path)
            for path in sorted((stage / "runtime").rglob("*.py"))
        }
        identity = {
            "schema": SCHEMA,
            "base_release_digest": BASE_RELEASE_DIGEST,
            "source_deploy_base_commit": _git_head(repo),
            "files": files,
            "policy": {
                "scope": "telegram-owner-private-only",
                "duplicate_semantics": "durable-event-replay-silent",
                "distinct_same_text": "process",
                "episode_store": "content-free-sqlite-v1",
                "recovery_notice": "fixed-at-most-once",
                "startup_notice": False,
                "typed_user_visible_degradation": False,
            },
        }
        digest = hashlib.sha256(canonical_bytes(identity)).hexdigest()
        destination = output_root / digest
        if destination.exists() or destination.is_symlink():
            raise RecoveryReleaseRejected("candidate output rejected")
        manifest = {
            **identity,
            "release_digest": digest,
            "destination": (
                "/opt/myuna/context24-gateway/telegram/releases/" + digest
            ),
        }
        (stage / "MANIFEST.json").write_bytes(canonical_bytes(manifest) + b"\n")
        stage.rename(destination)
    return digest, destination, manifest


def verify(candidate: Path, manifest: dict[str, object]) -> bool:
    try:
        if json.loads(
            (candidate / "MANIFEST.json").read_text(encoding="utf-8")
        ) != manifest:
            return False
        files = manifest["files"]
        if not isinstance(files, dict):
            return False
        return all(
            (candidate / relative).is_file()
            and not (candidate / relative).is_symlink()
            and digest_file(candidate / relative) == expected
            for relative, expected in files.items()
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("build/p06-telegram-recovery-v1"),
    )
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    try:
        digest, destination, manifest = build(
            repo,
            args.output_root.resolve(),
        )
        if not verify(destination, manifest):
            raise RecoveryReleaseRejected("candidate verification rejected")
    except RecoveryReleaseRejected:
        print(json.dumps({"status": "rejected"}, separators=(",", ":")))
        return 1
    print(
        json.dumps(
            {
                "candidate": str(destination),
                "release_digest": digest,
                "status": "built",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
