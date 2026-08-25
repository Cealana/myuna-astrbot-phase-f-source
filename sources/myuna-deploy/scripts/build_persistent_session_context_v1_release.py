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
    "cf3f941a13c94bdac2fd94c4159618354fb82899cad36117b92d0c88981dbde5"
)
BASE_RELEASE = Path("/opt/myuna/context24-gateway/qq/releases") / BASE_RELEASE_DIGEST
REPLACEMENTS = {
    "runtime/context_window_policy.py": "scripts/context_window_policy.py",
    "runtime/degradation_shadow_enqueue.py": "scripts/degradation_shadow_enqueue.py",
    "runtime/fault_incident_v1.py": "scripts/fault_incident_v1.py",
    "runtime/gateway_degradation_protocol.py": (
        "scripts/gateway_degradation_protocol.py"
    ),
    "runtime/gateway_enqueue.py": "scripts/gateway_enqueue.py",
    "runtime/gateway_post_reply.py": "scripts/gateway_post_reply.py",
    "runtime/incident_history_runtime_adapter_v1.py": (
        "scripts/incident_history_runtime_adapter_v1.py"
    ),
    "runtime/incident_history_v1.py": "scripts/incident_history_v1.py",
    "runtime/qq_owner_runtime_gateway.py": "scripts/qq_owner_runtime_gateway.py",
    "runtime/p07_d_runtime_readiness.py": "scripts/p07_d_runtime_readiness.py",
    "runtime/telegram_owner_runtime_gateway.py": (
        "scripts/telegram_owner_runtime_gateway.py"
    ),
    "runtime/session_context_admin.py": "scripts/session_context_admin.py",
    "runtime/user_visible_fault_v1.py": "scripts/user_visible_fault_v1.py",
}


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_file(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def _validate_base_release() -> dict[str, object]:
    manifest_path = BASE_RELEASE / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("release_digest") != BASE_RELEASE_DIGEST:
        raise RuntimeError("base release digest mismatch")
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise RuntimeError("base release manifest files are invalid")
    for relative, expected in files.items():
        path = BASE_RELEASE / relative
        if not path.is_file() or digest_file(path) != expected:
            raise RuntimeError(f"base release file mismatch: {relative}")
    return manifest


def _git_head(repo: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        text=True,
    ).strip()


def _validate_python(runtime: Path) -> None:
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
for filename in (
    "qq_owner_runtime_gateway.py",
    "telegram_owner_runtime_gateway.py",
):
    name = "candidate_" + filename.removesuffix(".py")
    spec = importlib.util.spec_from_file_location(name, runtime / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    assert type(module._build_context_store()).__name__ == "InMemoryContextStore"
"""
    subprocess.run(
        ["python3", "-B", "-c", probe, str(runtime)],
        check=True,
        capture_output=True,
        text=True,
    )


def build(repo: Path, output_root: Path) -> tuple[str, Path]:
    base_manifest = _validate_base_release()
    for relative in REPLACEMENTS.values():
        if not (repo / relative).is_file():
            raise RuntimeError(f"candidate source is missing: {relative}")

    output_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".persistent-session-context-v1-",
        dir=output_root,
    ) as temporary:
        stage = Path(temporary) / "release"
        shutil.copytree(BASE_RELEASE, stage)
        for staged_path in [stage, *stage.rglob("*")]:
            if staged_path.is_dir():
                staged_path.chmod(0o750)
            else:
                staged_path.chmod(0o640)
        for destination, source in REPLACEMENTS.items():
            target = stage / destination
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(repo / source, target)
        _validate_python(stage / "runtime")

        files = {
            str(path.relative_to(stage)).replace("\\", "/"): digest_file(path)
            for path in sorted((stage / "runtime").rglob("*.py"))
        }
        identity = {
            "schema": "myuna-persistent-session-context-release-v1",
            "base_release_digest": BASE_RELEASE_DIGEST,
            "source_deploy_base_commit": _git_head(repo),
            "files": files,
            "policy": {
                "max_history_messages": 128,
                "max_history_characters": 131072,
                "storage": "rolling-plaintext-sqlite-v1",
                "database_mode": "0600",
                "commit": "after-successful-reply",
                "retention": "until-explicit-clear",
                "channel_isolation": "separate-database-and-namespace",
                "duplicate_cooldown_seconds": 300,
                "core_request_timeout_seconds": 70,
                "provider_timeout_seconds": 60,
                "provider_max_attempts": 1,
            },
        }
        release_digest = digest_bytes(canonical_bytes(identity))
        destinations = {
            "qq": (
                "/opt/myuna/context24-gateway/qq/releases/"
                f"{release_digest}"
            ),
            "telegram": (
                "/opt/myuna/context24-gateway/telegram/releases/"
                f"{release_digest}"
            ),
        }
        manifest = {
            **identity,
            "release_digest": release_digest,
            "destinations": destinations,
        }
        (stage / "MANIFEST.json").write_bytes(canonical_bytes(manifest) + b"\n")

        destination = output_root / release_digest
        if destination.exists():
            raise RuntimeError("content-addressed candidate already exists")
        stage.rename(destination)
    return release_digest, destination


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("build/persistent-session-context-v1"),
    )
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    digest, destination = build(repo, args.output_root.resolve())
    print(json.dumps({
        "status": "built",
        "release_digest": digest,
        "candidate": str(destination),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
