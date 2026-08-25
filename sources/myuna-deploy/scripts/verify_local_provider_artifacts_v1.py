#!/usr/bin/env python3
"""Verify the exact P07 local-provider runtime and model artifacts."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import tempfile
from typing import Sequence


RUNTIME_TAG = "b10217"
RUNTIME_COMMIT = "ddd4ec1428a6201e18975ea52b07c71e0f9aef26"
RUNTIME_FILENAME = "llama-b10217-bin-ubuntu-x64.tar.gz"
RUNTIME_BYTES = 16_433_859
RUNTIME_SHA256 = "b79145bfa48f4fef83e76e1cef7ef4fbdf966e497a2fd774f1107fc2a24500af"
MODEL_REPOSITORY = "Qwen/Qwen3-4B-GGUF"
MODEL_COMMIT = "bc640142c66e1fdd12af0bd68f40445458f3869b"
MODEL_FILENAME = "Qwen3-4B-Q4_K_M.gguf"
MODEL_BYTES = 2_497_280_256
MODEL_SHA256 = "7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5"
MODEL_LICENSE = "Apache-2.0"
RECEIPT_SCHEMA = "myuna.local-provider-artifacts.v1"
MAX_RUNTIME_MEMBERS = 128
MAX_RUNTIME_UNCOMPRESSED_BYTES = 128 * 1024 * 1024


class LocalProviderArtifactError(RuntimeError):
    """A deterministic content-free artifact rejection."""


@dataclass(frozen=True, slots=True)
class ArtifactSpec:
    filename: str
    byte_count: int
    sha256_hex: str


RUNTIME_SPEC = ArtifactSpec(RUNTIME_FILENAME, RUNTIME_BYTES, RUNTIME_SHA256)
MODEL_SPEC = ArtifactSpec(MODEL_FILENAME, MODEL_BYTES, MODEL_SHA256)


def _reject(code: str) -> LocalProviderArtifactError:
    return LocalProviderArtifactError(code)


def _digest(path: Path) -> str:
    value = sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                value.update(chunk)
    except OSError as exc:
        raise _reject("artifact_unavailable") from exc
    return value.hexdigest()


def verify_regular_artifact(path: Path, spec: ArtifactSpec) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise _reject("artifact_unavailable") from exc
    if (
        path.name != spec.filename
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size != spec.byte_count
    ):
        raise _reject("artifact_metadata_rejected")
    if _digest(path) != spec.sha256_hex:
        raise _reject("artifact_digest_rejected")


def _safe_runtime_member(member: tarfile.TarInfo) -> None:
    name = PurePosixPath(member.name)
    if (
        name.is_absolute()
        or not name.parts
        or name.parts[0] != f"llama-{RUNTIME_TAG}"
        or any(part in {"", ".", ".."} for part in name.parts)
        or not (member.isdir() or member.isfile() or member.issym())
        or member.islnk()
        or member.isdev()
        or member.size < 0
    ):
        raise _reject("runtime_archive_rejected")
    if member.issym():
        target = PurePosixPath(member.linkname)
        resolved = name.parent / target
        if (
            target.is_absolute()
            or any(part in {"", ".", ".."} for part in target.parts)
            or not resolved.parts
            or resolved.parts[0] != f"llama-{RUNTIME_TAG}"
        ):
            raise _reject("runtime_archive_rejected")


def verify_runtime_archive(path: Path) -> dict[str, object]:
    verify_regular_artifact(path, RUNTIME_SPEC)
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
    except (OSError, tarfile.TarError) as exc:
        raise _reject("runtime_archive_rejected") from exc
    if not 1 <= len(members) <= MAX_RUNTIME_MEMBERS:
        raise _reject("runtime_archive_rejected")
    total = 0
    names: set[str] = set()
    for member in members:
        _safe_runtime_member(member)
        if member.name in names:
            raise _reject("runtime_archive_rejected")
        names.add(member.name)
        total += member.size
    required = {
        f"llama-{RUNTIME_TAG}/llama-server",
        f"llama-{RUNTIME_TAG}/LICENSE",
        f"llama-{RUNTIME_TAG}/libllama-server-impl.so",
    }
    if not required <= names or total > MAX_RUNTIME_UNCOMPRESSED_BYTES:
        raise _reject("runtime_archive_rejected")
    return {
        "archive_bytes": RUNTIME_BYTES,
        "archive_sha256": RUNTIME_SHA256,
        "commit": RUNTIME_COMMIT,
        "filename": RUNTIME_FILENAME,
        "member_count": len(members),
        "tag": RUNTIME_TAG,
        "uncompressed_bytes": total,
    }


def verify_model(path: Path) -> dict[str, object]:
    verify_regular_artifact(path, MODEL_SPEC)
    try:
        with path.open("rb") as stream:
            magic = stream.read(4)
    except OSError as exc:
        raise _reject("artifact_unavailable") from exc
    if magic != b"GGUF":
        raise _reject("model_format_rejected")
    return {
        "bytes": MODEL_BYTES,
        "commit": MODEL_COMMIT,
        "filename": MODEL_FILENAME,
        "license": MODEL_LICENSE,
        "repository": MODEL_REPOSITORY,
        "sha256": MODEL_SHA256,
    }


def canonical_receipt(runtime: dict[str, object], model: dict[str, object]) -> bytes:
    return (
        json.dumps(
            {
                "model": model,
                "private_content_present": False,
                "runtime": runtime,
                "schema": RECEIPT_SCHEMA,
            },
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def write_receipt(path: Path, payload: bytes) -> None:
    if not path.is_absolute() or path.name != "ARTIFACTS.json":
        raise _reject("receipt_path_rejected")
    try:
        parent = path.parent.lstat()
    except OSError as exc:
        raise _reject("receipt_parent_rejected") from exc
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or stat.S_IMODE(parent.st_mode) != 0o700
        or parent.st_uid != os.geteuid()
    ):
        raise _reject("receipt_parent_rejected")
    descriptor, temporary = tempfile.mkstemp(prefix=".ARTIFACTS.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            if path.read_bytes() != payload:
                raise _reject("receipt_conflict")
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except LocalProviderArtifactError:
        raise
    except OSError as exc:
        raise _reject("receipt_write_failed") from exc
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        runtime = verify_runtime_archive(arguments.runtime)
        model = verify_model(arguments.model)
        payload = canonical_receipt(runtime, model)
        write_receipt(arguments.receipt, payload)
    except LocalProviderArtifactError as exc:
        print(json.dumps({"status": "rejected", "error": str(exc)}, sort_keys=True))
        return 1
    print(
        json.dumps(
            {
                "status": "verified",
                "private_content_present": False,
                "receipt_sha256": sha256(payload).hexdigest(),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
