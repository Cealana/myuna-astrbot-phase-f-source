from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
from typing import Mapping, Sequence

from external_epoch_bundle import BUNDLE_SCHEMA
from myuna_core.external_context.release_set import (
    P07DReleaseSet,
    RELEASE_SET_EPOCH_ID_11,
    RELEASE_SET_EPOCH_ID_13,
    RELEASE_SET_EPOCH_PATH_13,
    RELEASE_SET_EPOCH_SCHEMA,
    RELEASE_SET_EPOCH_VERSION,
    RELEASE_SET_GENERATION_13,
    RELEASE_SET_GENERATION_11,
)
from p07_d_generation8_release_set import (
    canonical,
    digest,
    rollback_manifest_digest,
    service_binding_digest,
)


GENERATION = RELEASE_SET_GENERATION_13
RELEASE_SET_EPOCH_ID = RELEASE_SET_EPOCH_ID_13
RELEASE_SET_EPOCH_PATH = RELEASE_SET_EPOCH_PATH_13
SELECTOR_SCHEMA = "myuna.external-epoch-selector.v2"
PREVIOUS_GENERATION = RELEASE_SET_GENERATION_11
PREVIOUS_EPOCH_ID = RELEASE_SET_EPOCH_ID_11
CONTROLLER_RELEASE_SCHEMA = "myuna.telegram.r5-controller-release.v3"
CONTROLLER_SOURCE_SCHEMA = "myuna.telegram.r5-controller-corresponding-source.v2"
CONTROLLER_OWNER_CHAIN = (
    "telegram_r5_boot_resume.main",
    "activate_p07_d_generation13_v1.controller_entry",
    "p07_d_activation_transaction.AtomicReleaseSetTransaction.enter_canonical_owner",
    "activate_p07_d_generation13_v1.Generation13LiveBackend",
)
ATTEMPT_AUTHORITY_SHA256 = "9dde7192c7bc7e9759581a310576af7e31afc64ff3568f953bed371eacf828cf"
CONTROLLER_EXPECTED_AUTHORITY_SCHEMA = "myuna.phase-f.controller-expected-authority.v1"
CONTROLLER_STATIC_AUTHORITY_DOMAIN = b"myuna.phase-f.controller-static-authority.v1\0"
CONTROLLER_RELEASE_ENV = "MYUNA_PHASE_F_CONTROLLER_RELEASE_SHA256"
CONTROLLER_CONFIG_ENV = "MYUNA_PHASE_F_CONTROLLER_CONFIG_SHA256"
CONTROLLER_AUTHORITY_ENV = "MYUNA_PHASE_F_CONTROLLER_AUTHORITY_SHA256"
_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_MODE = re.compile(r"^100(?:644|755)$")
_INSTALLED_MODE = re.compile(r"^0(?:444|555)$")
_FORBIDDEN_CONTROLLER_MODULES = frozenset(
    {
        "activate_p07_external_epoch_rollover_v1",
        "activate_p07_hybrid_external_generation_v1",
        "p09_v7_phase1_packaging_contract",
    }
)


def _controller_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate controller release key")
        value[key] = item
    return value


def _controller_canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _controller_json(payload: bytes, *, maximum: int) -> dict[str, object]:
    _require(
        0 < len(payload) <= maximum
        and payload.endswith(b"\n")
        and not payload.endswith(b"\n\n")
        and b"\r" not in payload
        and b"\x00" not in payload,
        "controller_release_noncanonical",
    )
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_controller_object,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        raise Generation13ReleaseSetRejected("controller_release_parse_rejected") from exc
    _require(
        type(value) is dict and _controller_canonical(value) == payload,
        "controller_release_noncanonical",
    )
    assert isinstance(value, dict)
    return value


def _controller_read(parent: int, name: str, *, maximum: int) -> tuple[bytes, os.stat_result]:
    _require("/" not in name and name not in {".", ".."}, "controller_release_name_rejected")
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
    except OSError as exc:
        raise Generation13ReleaseSetRejected("controller_release_member_rejected") from exc
    try:
        before = os.fstat(descriptor)
        _require(
            stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            "controller_release_member_type_rejected",
        )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            total += len(chunk)
            _require(total <= maximum, "controller_release_member_size_rejected")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        _require(
            stat.S_ISREG(after.st_mode) and after.st_nlink == 1,
            "controller_release_member_type_rejected",
        )
        _require(
            (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_size,
                before.st_uid,
                before.st_gid,
                before.st_ctime_ns,
                before.st_mtime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_size,
                after.st_uid,
                after.st_gid,
                after.st_ctime_ns,
                after.st_mtime_ns,
            ),
            "controller_release_member_changed_during_read",
        )
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        _require(
            (
                named.st_dev,
                named.st_ino,
                named.st_mode,
                named.st_nlink,
                named.st_size,
                named.st_uid,
                named.st_gid,
                named.st_ctime_ns,
                named.st_mtime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_size,
                after.st_uid,
                after.st_gid,
                after.st_ctime_ns,
                after.st_mtime_ns,
            ),
            "controller_release_member_identity_rejected",
        )
        return b"".join(chunks), after
    finally:
        os.close(descriptor)


def _controller_named_identity(parent: int, name: str, descriptor: int, code: str) -> None:
    metadata = os.fstat(descriptor)
    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    _require(
        (named.st_dev, named.st_ino, named.st_mode, named.st_nlink, named.st_size)
        == (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink, metadata.st_size),
        code,
    )


def _controller_open_directory(parent: int, name: str) -> int:
    _require("/" not in name and name not in {".", ".."}, "controller_release_name_rejected")
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
    except OSError as exc:
        raise Generation13ReleaseSetRejected("controller_release_tree_type_rejected") from exc
    try:
        metadata = os.fstat(descriptor)
        _require(
            stat.S_ISDIR(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o555,
            "controller_release_tree_type_rejected",
        )
        _controller_named_identity(parent, name, descriptor, "controller_release_tree_identity_rejected")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _controller_read_path(root: int, relative: str, *, maximum: int) -> tuple[bytes, os.stat_result]:
    parts = Path(relative).parts
    _require(bool(parts) and Path(relative).as_posix() == relative, "controller_release_member_path_rejected")
    current = root
    held: list[tuple[int, str, int]] = []
    try:
        for part in parts[:-1]:
            child = _controller_open_directory(current, part)
            held.append((current, part, child))
            current = child
        return _controller_read(current, parts[-1], maximum=maximum)
    finally:
        for parent, name, descriptor in reversed(held):
            try:
                _controller_named_identity(
                    parent,
                    name,
                    descriptor,
                    "controller_release_tree_identity_rejected",
                )
            finally:
                os.close(descriptor)


def _controller_inventory(parent: int, prefix: tuple[str, ...] = ()) -> set[str]:
    names: set[str] = set()
    try:
        entries = os.listdir(parent)
    except OSError as exc:
        raise Generation13ReleaseSetRejected("controller_release_tree_rejected") from exc
    for name in entries:
        _require(type(name) is str and "/" not in name and name not in {".", ".."}, "controller_release_name_rejected")
        try:
            metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except OSError as exc:
            raise Generation13ReleaseSetRejected("controller_release_tree_rejected") from exc
        relative = "/".join((*prefix, name))
        if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
            child = _controller_open_directory(parent, name)
            try:
                names.update(_controller_inventory(child, (*prefix, name)))
                _controller_named_identity(parent, name, child, "controller_release_tree_identity_rejected")
            finally:
                os.close(child)
        elif stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
            names.add(relative)
        else:
            raise Generation13ReleaseSetRejected("controller_release_tree_type_rejected")
    return names


def _controller_member(row: object) -> dict[str, object]:
    _require(type(row) is dict, "controller_release_member_schema_rejected")
    assert isinstance(row, dict)
    required = {
        "blob",
        "bytes",
        "content_sha256",
        "destination",
        "installed_mode",
        "mode",
        "source",
    }
    _require(set(row) == required, "controller_release_member_schema_rejected")
    _require(
        type(row["bytes"]) is int and int(row["bytes"]) >= 0,
        "controller_release_member_schema_rejected",
    )
    for key in ("blob", "content_sha256", "destination", "installed_mode", "mode", "source"):
        _require(type(row[key]) is str and bool(row[key]), "controller_release_member_schema_rejected")
    _require(_HEX_40.fullmatch(str(row["blob"])) is not None, "controller_release_member_schema_rejected")
    _require(_HEX_64.fullmatch(str(row["content_sha256"])) is not None, "controller_release_member_schema_rejected")
    _require(_MODE.fullmatch(str(row["mode"])) is not None, "controller_release_member_schema_rejected")
    _require(_INSTALLED_MODE.fullmatch(str(row["installed_mode"])) is not None, "controller_release_member_schema_rejected")
    for key in ("destination", "source"):
        path = Path(str(row[key]))
        _require(
            not path.is_absolute()
            and ".." not in path.parts
            and path.as_posix() == str(row[key]),
            "controller_release_member_path_rejected",
        )
    return row


def controller_static_authority_sha256(
    document: Mapping[str, object],
    release_digest: str,
    controller_config_sha256: str,
) -> str:
    _require(_HEX_64.fullmatch(release_digest) is not None, "controller_expected_authority_rejected")
    _require(_HEX_64.fullmatch(controller_config_sha256) is not None, "controller_expected_authority_rejected")
    files = document.get("files")
    _require(type(files) is list and bool(files), "controller_expected_authority_rejected")
    members = [_controller_member(row) for row in files]
    body = {
        "attempt_authority_sha256": ATTEMPT_AUTHORITY_SHA256,
        "controller_builder_sha256": document.get("controller_builder_sha256"),
        "controller_config_sha256": controller_config_sha256,
        "controller_release_sha256": release_digest,
        "core_commit": document.get("core_commit"),
        "core_tree": document.get("core_tree"),
        "deploy_commit": document.get("deploy_commit"),
        "deploy_tree": document.get("deploy_tree"),
        "member_set_sha256": sha256(_controller_canonical(members)).hexdigest(),
        "owner_chain": list(CONTROLLER_OWNER_CHAIN),
        "paired_builder_sha256": document.get("paired_builder_sha256"),
        "paired_source_receipt_sha256": document.get("paired_source_receipt_sha256"),
        "schema": "myuna.phase-f.controller-static-authority.v1",
    }
    for key in (
        "controller_builder_sha256",
        "member_set_sha256",
        "paired_builder_sha256",
        "paired_source_receipt_sha256",
    ):
        _require(type(body[key]) is str and _HEX_64.fullmatch(str(body[key])) is not None, "controller_expected_authority_rejected")
    for key in ("core_commit", "core_tree", "deploy_commit", "deploy_tree"):
        _require(type(body[key]) is str and _HEX_40.fullmatch(str(body[key])) is not None, "controller_expected_authority_rejected")
    return sha256(CONTROLLER_STATIC_AUTHORITY_DOMAIN + _controller_canonical(body)).hexdigest()


def controller_expected_authority(
    *,
    release_digest: str,
    controller_config_sha256: str,
    static_authority_sha256: str,
    t2_receipts: tuple[dict[str, object], dict[str, object]] | None,
) -> dict[str, object]:
    for value in (release_digest, controller_config_sha256, static_authority_sha256):
        _require(type(value) is str and _HEX_64.fullmatch(value) is not None, "controller_expected_authority_rejected")
    receipt_digests: list[str] | None = None
    if t2_receipts is not None:
        _require(type(t2_receipts) is tuple and len(t2_receipts) == 2, "controller_expected_authority_rejected")
        _require(all(type(receipt) is dict for receipt in t2_receipts), "controller_expected_authority_rejected")
        receipt_digests = [sha256(_controller_canonical(receipt)).hexdigest() for receipt in t2_receipts]
        _require(receipt_digests[0] != receipt_digests[1], "controller_expected_authority_rejected")
    return {
        "attempt_authority_sha256": ATTEMPT_AUTHORITY_SHA256,
        "controller_config_sha256": controller_config_sha256,
        "controller_release_sha256": release_digest,
        "controller_static_authority_sha256": static_authority_sha256,
        "schema": CONTROLLER_EXPECTED_AUTHORITY_SCHEMA,
        "t2_receipt_sha256": receipt_digests,
    }


def _controller_expected_authority(value: object) -> dict[str, object]:
    _require(type(value) is dict, "controller_expected_authority_rejected")
    assert isinstance(value, dict)
    _require(
        set(value)
        == {
            "attempt_authority_sha256",
            "controller_config_sha256",
            "controller_release_sha256",
            "controller_static_authority_sha256",
            "schema",
            "t2_receipt_sha256",
        },
        "controller_expected_authority_rejected",
    )
    _require(value["schema"] == CONTROLLER_EXPECTED_AUTHORITY_SCHEMA, "controller_expected_authority_rejected")
    _require(value["attempt_authority_sha256"] == ATTEMPT_AUTHORITY_SHA256, "controller_expected_authority_rejected")
    for key in ("controller_config_sha256", "controller_release_sha256", "controller_static_authority_sha256"):
        _require(type(value[key]) is str and _HEX_64.fullmatch(str(value[key])) is not None, "controller_expected_authority_rejected")
    receipts = value["t2_receipt_sha256"]
    _require(
        receipts is None
        or (
            type(receipts) is list
            and len(receipts) == 2
            and receipts[0] != receipts[1]
            and all(type(item) is str and _HEX_64.fullmatch(item) is not None for item in receipts)
        ),
        "controller_expected_authority_rejected",
    )
    return value

def phase_f_selected_target(
    release_root: Path,
    *,
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Reconstruct the exact sealed Phase-F target; absence means generic input."""

    source = os.environ if environment is None else environment
    values = (
        source.get(CONTROLLER_RELEASE_ENV),
        source.get(CONTROLLER_CONFIG_ENV),
        source.get(CONTROLLER_AUTHORITY_ENV),
    )
    if values == (None, None, None):
        return False
    _require(all(type(value) is str for value in values), "phase_f_target_selection_rejected")
    release_digest, config_digest, authority_digest = values
    assert isinstance(release_digest, str)
    assert isinstance(config_digest, str)
    assert isinstance(authority_digest, str)
    expected = controller_expected_authority(
        release_digest=release_digest,
        controller_config_sha256=config_digest,
        static_authority_sha256=authority_digest,
        t2_receipts=None,
    )
    verified = verify_controller_release_authority(release_root, expected)
    _require(
        verified["schema"] == CONTROLLER_RELEASE_SCHEMA
        and verified["owner_chain"] == list(CONTROLLER_OWNER_CHAIN),
        "phase_f_target_fingerprint_rejected",
    )
    return True


def verify_controller_release_authority(
    release_root: Path,
    expected_authority: Mapping[str, object],
) -> dict[str, object]:
    """Verify one manifest-bound sealed controller release without source fallbacks."""

    authority = _controller_expected_authority(expected_authority)
    expected_release_digest = str(authority["controller_release_sha256"])
    _require(
        _HEX_64.fullmatch(expected_release_digest) is not None
        and release_root.name == expected_release_digest,
        "controller_release_digest_rejected",
    )
    parent = -1
    root = -1
    try:
        parent = os.open(
            release_root.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        root = os.open(
            release_root.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
        root_metadata = os.fstat(root)
        _require(
            stat.S_ISDIR(root_metadata.st_mode)
            and stat.S_IMODE(root_metadata.st_mode) == 0o555,
            "controller_release_root_rejected",
        )
        _controller_named_identity(parent, release_root.name, root, "controller_release_root_identity_rejected")
    except Exception as exc:
        if root >= 0:
            os.close(root)
        if parent >= 0:
            os.close(parent)
        if isinstance(exc, OSError):
            raise Generation13ReleaseSetRejected("controller_release_root_rejected") from exc
        raise
    try:
        manifest_bytes, manifest_metadata = _controller_read(
            root,
            "MANIFEST.json",
            maximum=1024 * 1024,
        )
        _require(
            stat.S_IMODE(manifest_metadata.st_mode) == 0o444
            and sha256(manifest_bytes).hexdigest() == expected_release_digest,
            "controller_release_manifest_rejected",
        )
        document = _controller_json(manifest_bytes, maximum=1024 * 1024)
        required = {
            "controller_builder",
            "controller_builder_sha256",
            "core_commit",
            "core_import_closure",
            "core_tree",
            "deploy_commit",
            "deploy_tree",
            "files",
            "forbidden_modules",
            "owner_chain",
            "paired_builder",
            "paired_builder_sha256",
            "paired_source_package_sha256",
            "paired_source_receipt_sha256",
            "schema",
            "source_receipt",
        }
        _require(set(document) == required, "controller_release_schema_rejected")
        _require(document["schema"] == CONTROLLER_RELEASE_SCHEMA, "controller_release_schema_rejected")
        for key in ("core_commit", "core_tree", "deploy_commit", "deploy_tree"):
            _require(type(document[key]) is str and _HEX_40.fullmatch(str(document[key])) is not None, "controller_release_source_rejected")
        _require(document["owner_chain"] == list(CONTROLLER_OWNER_CHAIN), "controller_release_owner_chain_rejected")
        _require(
            document["forbidden_modules"] == sorted(_FORBIDDEN_CONTROLLER_MODULES),
            "controller_release_legacy_edge_rejected",
        )
        files = document["files"]
        _require(type(files) is list and bool(files), "controller_release_files_rejected")
        members = [_controller_member(row) for row in files]
        destinations = [str(row["destination"]) for row in members]
        _require(destinations == sorted(destinations) and len(destinations) == len(set(destinations)), "controller_release_file_order_rejected")
        sources = [str(row["source"]) for row in members]
        _require(len(sources) == len(set(sources)), "controller_release_source_member_rejected")
        forbidden_files = {f"{name}.py" for name in _FORBIDDEN_CONTROLLER_MODULES}
        _require(not forbidden_files.intersection(destinations), "controller_release_legacy_edge_rejected")
        expected_names = {"MANIFEST.json", "CORRESPONDING_SOURCE.json", *destinations}
        actual_names = _controller_inventory(root)
        _require(actual_names == expected_names, "controller_release_file_set_rejected")
        for row in members:
            destination = str(row["destination"])
            payload, metadata = _controller_read_path(
                root,
                destination,
                maximum=int(row["bytes"]),
            )
            _require(
                stat.S_IMODE(metadata.st_mode) == int(str(row["installed_mode"]), 8)
                and len(payload) == row["bytes"]
                and sha256(payload).hexdigest() == row["content_sha256"],
                "controller_release_member_drifted",
            )
        receipt_bytes, receipt_metadata = _controller_read(root, "CORRESPONDING_SOURCE.json", maximum=1024 * 1024)
        _require(stat.S_IMODE(receipt_metadata.st_mode) == 0o444, "controller_release_receipt_rejected")
        receipt = _controller_json(receipt_bytes, maximum=1024 * 1024)
        _require(receipt == document["source_receipt"], "controller_release_receipt_rejected")
        receipt_digest = sha256(receipt_bytes).hexdigest()
        _require(
            receipt_digest == document["paired_source_receipt_sha256"]
            and receipt_digest == document["paired_source_package_sha256"],
            "controller_release_receipt_rejected",
        )
        paired = _controller_member(document["paired_builder"])
        controller = _controller_member(document["controller_builder"])
        _require(
            paired in members
            and controller in members
            and paired["content_sha256"] == document["paired_builder_sha256"]
            and controller["content_sha256"] == document["controller_builder_sha256"],
            "controller_release_builder_rejected",
        )
        closure = document["core_import_closure"]
        _require(type(closure) is dict and set(closure) == {"files", "roots", "sha256"}, "controller_release_core_closure_rejected")
        _require(type(closure["files"]) is list and closure["files"] == sorted(closure["files"]), "controller_release_core_closure_rejected")
        _require(type(closure["roots"]) is list and closure["roots"] == sorted(closure["roots"]), "controller_release_core_closure_rejected")
        closure_body = {"files": closure["files"], "roots": closure["roots"]}
        _require(
            type(closure["sha256"]) is str
            and closure["sha256"] == sha256(_controller_canonical(closure_body)).hexdigest(),
            "controller_release_core_closure_rejected",
        )
        _require(
            controller_static_authority_sha256(
                document,
                expected_release_digest,
                str(authority["controller_config_sha256"]),
            )
            == authority["controller_static_authority_sha256"],
            "controller_static_authority_rejected",
        )
        _require(_controller_inventory(root) == expected_names, "controller_release_file_set_rejected")
        _controller_named_identity(parent, release_root.name, root, "controller_release_root_identity_rejected")
        return document
    finally:
        os.close(root)
        os.close(parent)


class Generation13ReleaseSetRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise Generation13ReleaseSetRejected(code)


def selector_payload(previous_bundle_digest: str) -> dict[str, object]:
    _require(
        isinstance(previous_bundle_digest, str)
        and len(previous_bundle_digest) == 64
        and all(character in "0123456789abcdef" for character in previous_bundle_digest),
        "generation13_bundle_digest_rejected",
    )
    return {
        "channel_kind": "astrbot_telegram",
        "client_id": "telegram-owner-private",
        "database_path": RELEASE_SET_EPOCH_PATH,
        "epoch_id": RELEASE_SET_EPOCH_ID,
        "generation": GENERATION,
        "previous_epoch_bundle_digest": previous_bundle_digest,
        "previous_epoch_bundle_schema": BUNDLE_SCHEMA,
        "previous_epoch_id": PREVIOUS_EPOCH_ID,
        "schema": SELECTOR_SCHEMA,
        "status": "active",
    }


def build_release_set(
    *,
    core: Mapping[str, object],
    telegram_runtime: Mapping[str, object],
    selector: Mapping[str, object],
    runtime_config: Mapping[str, object],
    credential: Mapping[str, object],
    epoch_uid: int,
    epoch_gid: int,
    services: Sequence[Mapping[str, object]],
    rollback: Mapping[str, object],
) -> P07DReleaseSet:
    return P07DReleaseSet.create(
        core=dict(core),
        telegram_runtime=dict(telegram_runtime),
        selector=dict(selector),
        runtime_config=dict(runtime_config),
        credential=dict(credential),
        epoch={
            "database_path": RELEASE_SET_EPOCH_PATH,
            "directory_mode": 0o700,
            "epoch_id": RELEASE_SET_EPOCH_ID,
            "file_mode": 0o600,
            "gid": epoch_gid,
            "schema": RELEASE_SET_EPOCH_SCHEMA,
            "schema_version": RELEASE_SET_EPOCH_VERSION,
            "uid": epoch_uid,
        },
        services=tuple(dict(item) for item in services),
        rollback=dict(rollback),
        generation=GENERATION,
    )


def protected_manifest_path() -> Path:
    return Path("/etc/myuna-telegram-gateway/p07-d-release-set-v1.json")
