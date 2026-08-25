"""Deterministic, fail-closed Core Release Selector v1 contracts.

This repository-only module parses and renders selection documents, audits
provided systemd fragments, and verifies an already-installed immutable
release.  It never chooses a release, writes system state, calls systemctl, or
performs service lifecycle operations.
"""

from __future__ import annotations

from dataclasses import dataclass
import argparse
import grp
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
from typing import Mapping, Sequence


CANDIDATE_SCHEMA = "myuna.core-release-selection-candidate.v1"
BINDING_INTENT_SCHEMA = "myuna.core-release-selection-binding-intent.v1"
BINDING_SCHEMA = "myuna.core-release-selection-binding.v1"
DOCUMENT_KIND = "candidate"
CANDIDATE_STATUS = "repository_only_inactive"
BINDING_INTENT_STATUS = "inactive_staging"
BINDING_STATUS = "selected_for_instance"
UNIT = "myuna-core@qq.service"
INSTANCE = "qq"
RELEASE_ROOT = "/srv/myuna/releases/core"
STABLE_SELECTOR_DROPIN = "10-core-release-selector-v1.conf"
GUARD_DROPIN = "05-core-release-selector-guard-v1.conf"
CANONICAL_JSON_ALGORITHM = "myuna-canonical-json-v1"
TREE_DIGEST_ALGORITHM = "myuna-path-content-tree-sha256-v1"

RUNTIME_BINDING_PATH = Path("/etc/myuna/core-release-selector/qq.binding.json")
RUNTIME_SELECTOR_PATH = Path(
    "/etc/systemd/system/myuna-core@qq.service.d/10-core-release-selector-v1.conf"
)
RUNTIME_GUARD_PATH = Path(
    "/etc/systemd/system/myuna-core@qq.service.d/05-core-release-selector-guard-v1.conf"
)

LEGACY_REPOSITORY_OWNER = "myuna-core-qq-voice-hotfix-1.conf"
LEGACY_REPOSITORY_OWNER_SHA256 = (
    "bf86829a4362fe3dc395e799d554b254434b4de7a20646ac5ff45dbaeee15a8d"
)

_HEX_64 = re.compile(r"^[a-f0-9]{64}$")
_HEX_40 = re.compile(r"^[a-f0-9]{40}$")
_VERIFIER_PATH = re.compile(
    r"^/opt/myuna/core-release-selector/releases/[a-f0-9]{64}/"
    r"core_release_selector\.py$"
)
_CANDIDATE_FIELDS = frozenset(
    {
        "schema",
        "document_kind",
        "status",
        "unit",
        "instance",
        "release_root",
        "stable_selector_dropin",
        "canonical_json_algorithm",
        "selected_release",
    }
)
_RELEASE_FIELDS = frozenset(
    {
        "tree_digest_algorithm",
        "tree_sha256",
        "source_commit",
        "file_count",
        "artifact_manifest_sha256",
        "installation_receipt_sha256",
    }
)
_BINDING_INTENT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "unit",
        "instance",
        "release_root",
        "selector_dropin",
        "guard_dropin",
        "candidate_canonical_sha256",
        "selector_dropin_sha256",
        "guard_dropin_sha256",
        "verifier_script_path",
        "verifier_script_sha256",
        "selected_release",
    }
)
_BINDING_FIELDS = frozenset(
    {
        "schema",
        "status",
        "unit",
        "instance",
        "release_root",
        "selector_dropin",
        "guard_dropin",
        "candidate_canonical_sha256",
        "approval_plan_digest",
        "selector_dropin_sha256",
        "guard_dropin_sha256",
        "verifier_script_path",
        "verifier_script_sha256",
        "selected_release",
    }
)
_PYTHONPATH_IN_ENVIRONMENT_FILE = re.compile(
    r"^[ \t]*(?:export[ \t]+)?PYTHONPATH[ \t]*=", re.MULTILINE
)
_WORKING_DIRECTORY_DIRECTIVE = re.compile(r"^WorkingDirectory[ \t]*=(.*)$")
_ENVIRONMENT_DIRECTIVE = re.compile(r"^Environment[ \t]*=(.*)$")


class SelectorContractError(ValueError):
    """A deterministic, content-free rejection safe to expose in audit data."""


@dataclass(frozen=True, slots=True)
class ReleaseEvidence:
    tree_sha256: str
    source_commit: str
    file_count: int
    artifact_manifest_sha256: str
    installation_receipt_sha256: str

    @property
    def release_path(self) -> PurePosixPath:
        return PurePosixPath(RELEASE_ROOT) / self.tree_sha256

    @property
    def pythonpath(self) -> PurePosixPath:
        return self.release_path / "src"

    def to_payload(self) -> dict[str, object]:
        return {
            "tree_digest_algorithm": TREE_DIGEST_ALGORITHM,
            "tree_sha256": self.tree_sha256,
            "source_commit": self.source_commit,
            "file_count": self.file_count,
            "artifact_manifest_sha256": self.artifact_manifest_sha256,
            "installation_receipt_sha256": self.installation_receipt_sha256,
        }


@dataclass(frozen=True, slots=True)
class SelectionCandidate:
    selected_release: ReleaseEvidence

    def to_payload(self) -> dict[str, object]:
        return {
            "schema": CANDIDATE_SCHEMA,
            "document_kind": DOCUMENT_KIND,
            "status": CANDIDATE_STATUS,
            "unit": UNIT,
            "instance": INSTANCE,
            "release_root": RELEASE_ROOT,
            "stable_selector_dropin": STABLE_SELECTOR_DROPIN,
            "canonical_json_algorithm": CANONICAL_JSON_ALGORITHM,
            "selected_release": self.selected_release.to_payload(),
        }


@dataclass(frozen=True, slots=True)
class SelectionBindingIntent:
    candidate_canonical_sha256: str
    selector_dropin_sha256: str
    guard_dropin_sha256: str
    verifier_script_path: str
    verifier_script_sha256: str
    selected_release: ReleaseEvidence

    def to_payload(self) -> dict[str, object]:
        return {
            "schema": BINDING_INTENT_SCHEMA,
            "status": BINDING_INTENT_STATUS,
            "unit": UNIT,
            "instance": INSTANCE,
            "release_root": RELEASE_ROOT,
            "selector_dropin": STABLE_SELECTOR_DROPIN,
            "guard_dropin": GUARD_DROPIN,
            "candidate_canonical_sha256": self.candidate_canonical_sha256,
            "selector_dropin_sha256": self.selector_dropin_sha256,
            "guard_dropin_sha256": self.guard_dropin_sha256,
            "verifier_script_path": self.verifier_script_path,
            "verifier_script_sha256": self.verifier_script_sha256,
            "selected_release": self.selected_release.to_payload(),
        }


@dataclass(frozen=True, slots=True)
class RuntimeBinding:
    candidate_canonical_sha256: str
    approval_plan_digest: str
    selector_dropin_sha256: str
    guard_dropin_sha256: str
    verifier_script_path: str
    verifier_script_sha256: str
    selected_release: ReleaseEvidence

    def to_payload(self) -> dict[str, object]:
        return {
            "schema": BINDING_SCHEMA,
            "status": BINDING_STATUS,
            "unit": UNIT,
            "instance": INSTANCE,
            "release_root": RELEASE_ROOT,
            "selector_dropin": STABLE_SELECTOR_DROPIN,
            "guard_dropin": GUARD_DROPIN,
            "candidate_canonical_sha256": self.candidate_canonical_sha256,
            "approval_plan_digest": self.approval_plan_digest,
            "selector_dropin_sha256": self.selector_dropin_sha256,
            "guard_dropin_sha256": self.guard_dropin_sha256,
            "verifier_script_path": self.verifier_script_path,
            "verifier_script_sha256": self.verifier_script_sha256,
            "selected_release": self.selected_release.to_payload(),
        }


@dataclass(frozen=True, slots=True)
class ReleaseOwner:
    source_name: str
    source_sha256: str
    working_directory: str
    pythonpath: str
    is_base_template: bool


@dataclass(frozen=True, slots=True)
class SystemdReleaseInventory:
    base_template_sha256: str
    fragment_sha256: tuple[tuple[str, str], ...]
    base_owner: ReleaseOwner | None
    dropin_owners: tuple[ReleaseOwner, ...]
    effective_owner: ReleaseOwner | None


def _mapping(value: object, fields: frozenset[str], error: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise SelectorContractError(error)
    if any(not isinstance(key, str) for key in value):
        raise SelectorContractError(error)
    return value


def _strict_string(value: object, expected: str, error: str) -> None:
    if not isinstance(value, str) or value != expected:
        raise SelectorContractError(error)


def _digest(value: object, pattern: re.Pattern[str], error: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise SelectorContractError(error)
    return value


def _load_release(payload: object) -> ReleaseEvidence:
    release = _mapping(payload, _RELEASE_FIELDS, "release evidence rejected")
    _strict_string(
        release["tree_digest_algorithm"],
        TREE_DIGEST_ALGORITHM,
        "release evidence rejected",
    )
    tree_sha256 = _digest(
        release["tree_sha256"], _HEX_64, "release evidence rejected"
    )
    source_commit = _digest(
        release["source_commit"], _HEX_40, "release evidence rejected"
    )
    file_count = release["file_count"]
    if type(file_count) is not int or file_count <= 0:
        raise SelectorContractError("release evidence rejected")
    artifact_manifest_sha256 = _digest(
        release["artifact_manifest_sha256"],
        _HEX_64,
        "release evidence rejected",
    )
    installation_receipt_sha256 = _digest(
        release["installation_receipt_sha256"],
        _HEX_64,
        "release evidence rejected",
    )
    return ReleaseEvidence(
        tree_sha256=tree_sha256,
        source_commit=source_commit,
        file_count=file_count,
        artifact_manifest_sha256=artifact_manifest_sha256,
        installation_receipt_sha256=installation_receipt_sha256,
    )


def load_selection_candidate(payload: object) -> SelectionCandidate:
    candidate = _mapping(payload, _CANDIDATE_FIELDS, "selection candidate rejected")
    fixed = {
        "schema": CANDIDATE_SCHEMA,
        "document_kind": DOCUMENT_KIND,
        "status": CANDIDATE_STATUS,
        "unit": UNIT,
        "instance": INSTANCE,
        "release_root": RELEASE_ROOT,
        "stable_selector_dropin": STABLE_SELECTOR_DROPIN,
        "canonical_json_algorithm": CANONICAL_JSON_ALGORITHM,
    }
    for field, expected in fixed.items():
        _strict_string(candidate[field], expected, "selection candidate rejected")
    return SelectionCandidate(selected_release=_load_release(candidate["selected_release"]))


def _load_verifier_identity(
    payload: Mapping[str, object], *, error: str
) -> tuple[str, str]:
    verifier_script_path = payload["verifier_script_path"]
    verifier_script_sha256 = _digest(
        payload["verifier_script_sha256"], _HEX_64, error
    )
    if (
        not isinstance(verifier_script_path, str)
        or _VERIFIER_PATH.fullmatch(verifier_script_path) is None
        or PurePosixPath(verifier_script_path).parent.name
        != verifier_script_sha256
    ):
        raise SelectorContractError(error)
    return verifier_script_path, verifier_script_sha256


def load_binding_intent(payload: object) -> SelectionBindingIntent:
    intent = _mapping(
        payload, _BINDING_INTENT_FIELDS, "binding intent rejected"
    )
    fixed = {
        "schema": BINDING_INTENT_SCHEMA,
        "status": BINDING_INTENT_STATUS,
        "unit": UNIT,
        "instance": INSTANCE,
        "release_root": RELEASE_ROOT,
        "selector_dropin": STABLE_SELECTOR_DROPIN,
        "guard_dropin": GUARD_DROPIN,
    }
    for field, expected in fixed.items():
        _strict_string(intent[field], expected, "binding intent rejected")
    verifier_script_path, verifier_script_sha256 = _load_verifier_identity(
        intent, error="binding intent rejected"
    )
    loaded = SelectionBindingIntent(
        candidate_canonical_sha256=_digest(
            intent["candidate_canonical_sha256"],
            _HEX_64,
            "binding intent rejected",
        ),
        selector_dropin_sha256=_digest(
            intent["selector_dropin_sha256"],
            _HEX_64,
            "binding intent rejected",
        ),
        guard_dropin_sha256=_digest(
            intent["guard_dropin_sha256"],
            _HEX_64,
            "binding intent rejected",
        ),
        verifier_script_path=verifier_script_path,
        verifier_script_sha256=verifier_script_sha256,
        selected_release=_load_release(intent["selected_release"]),
    )
    validate_binding_intent_evidence(loaded)
    return loaded


def load_runtime_binding(payload: object) -> RuntimeBinding:
    binding = _mapping(payload, _BINDING_FIELDS, "runtime binding rejected")
    fixed = {
        "schema": BINDING_SCHEMA,
        "status": BINDING_STATUS,
        "unit": UNIT,
        "instance": INSTANCE,
        "release_root": RELEASE_ROOT,
        "selector_dropin": STABLE_SELECTOR_DROPIN,
        "guard_dropin": GUARD_DROPIN,
    }
    for field, expected in fixed.items():
        _strict_string(binding[field], expected, "runtime binding rejected")
    verifier_script_path, verifier_script_sha256 = _load_verifier_identity(
        binding, error="runtime binding rejected"
    )
    loaded = RuntimeBinding(
        candidate_canonical_sha256=_digest(
            binding["candidate_canonical_sha256"],
            _HEX_64,
            "runtime binding rejected",
        ),
        approval_plan_digest=_digest(
            binding["approval_plan_digest"], _HEX_64, "runtime binding rejected"
        ),
        selector_dropin_sha256=_digest(
            binding["selector_dropin_sha256"],
            _HEX_64,
            "runtime binding rejected",
        ),
        guard_dropin_sha256=_digest(
            binding["guard_dropin_sha256"],
            _HEX_64,
            "runtime binding rejected",
        ),
        verifier_script_path=verifier_script_path,
        verifier_script_sha256=verifier_script_sha256,
        selected_release=_load_release(binding["selected_release"]),
    )
    validate_runtime_binding_evidence(loaded)
    return loaded


def _validate_json_value(value: object) -> None:
    if value is None or type(value) in (str, int, bool):
        return
    if type(value) is list:
        for item in value:
            _validate_json_value(item)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise SelectorContractError("canonical JSON rejected")
            _validate_json_value(item)
        return
    raise SelectorContractError("canonical JSON rejected")


def canonical_json_bytes(value: object) -> bytes:
    _validate_json_value(value)
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return rendered.encode("utf-8")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise SelectorContractError("canonical JSON rejected") from exc


def canonical_json_sha256(value: object) -> str:
    return sha256(canonical_json_bytes(value)).hexdigest()


def parse_json_document(data: bytes) -> object:
    def no_duplicates(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
        output: dict[str, object] = {}
        for key, value in pairs:
            if key in output:
                raise SelectorContractError("JSON document rejected")
            output[key] = value
        return output

    try:
        text = data.decode("utf-8")
        return json.loads(text, object_pairs_hook=no_duplicates)
    except (UnicodeError, json.JSONDecodeError, SelectorContractError) as exc:
        raise SelectorContractError("JSON document rejected") from exc


def _selector_text(release: ReleaseEvidence) -> str:
    release_path = release.release_path.as_posix()
    return (
        "[Service]\n"
        f"WorkingDirectory={release_path}\n"
        f"Environment=PYTHONPATH={release_path}/src\n"
    )


def render_selector_dropin(candidate: SelectionCandidate) -> str:
    if not isinstance(candidate, SelectionCandidate):
        raise TypeError("candidate must be SelectionCandidate")
    return _selector_text(candidate.selected_release)


def render_guard_dropin(verifier_script_path: str) -> str:
    if (
        not isinstance(verifier_script_path, str)
        or _VERIFIER_PATH.fullmatch(verifier_script_path) is None
    ):
        raise SelectorContractError("verifier path rejected")
    return (
        "[Unit]\n"
        f"ConditionPathExists={RUNTIME_BINDING_PATH.as_posix()}\n"
        "\n[Service]\n"
        f"ExecStartPre=/usr/bin/python3 {verifier_script_path} verify-active\n"
    )


def build_binding_intent(
    candidate: SelectionCandidate,
    *,
    verifier_script_path: str,
    verifier_script_sha256: str,
) -> SelectionBindingIntent:
    if not isinstance(candidate, SelectionCandidate):
        raise TypeError("candidate must be SelectionCandidate")
    verifier = {
        "verifier_script_path": verifier_script_path,
        "verifier_script_sha256": verifier_script_sha256,
    }
    loaded_path, loaded_sha256 = _load_verifier_identity(
        verifier, error="binding intent rejected"
    )
    selector = render_selector_dropin(candidate).encode("utf-8")
    guard = render_guard_dropin(loaded_path).encode("utf-8")
    intent = SelectionBindingIntent(
        candidate_canonical_sha256=canonical_json_sha256(candidate.to_payload()),
        selector_dropin_sha256=sha256(selector).hexdigest(),
        guard_dropin_sha256=sha256(guard).hexdigest(),
        verifier_script_path=loaded_path,
        verifier_script_sha256=loaded_sha256,
        selected_release=candidate.selected_release,
    )
    validate_binding_intent_evidence(intent)
    return intent


def validate_binding_intent_evidence(intent: SelectionBindingIntent) -> None:
    if not isinstance(intent, SelectionBindingIntent):
        raise TypeError("intent must be SelectionBindingIntent")
    candidate = SelectionCandidate(selected_release=intent.selected_release)
    if (
        canonical_json_sha256(candidate.to_payload())
        != intent.candidate_canonical_sha256
    ):
        raise SelectorContractError("binding intent evidence rejected")
    selector = render_selector_dropin(candidate).encode("utf-8")
    if sha256(selector).hexdigest() != intent.selector_dropin_sha256:
        raise SelectorContractError("binding intent evidence rejected")
    guard = render_guard_dropin(intent.verifier_script_path).encode("utf-8")
    if sha256(guard).hexdigest() != intent.guard_dropin_sha256:
        raise SelectorContractError("binding intent evidence rejected")
    _load_verifier_identity(
        intent.to_payload(), error="binding intent evidence rejected"
    )


def render_runtime_binding(
    intent: SelectionBindingIntent, *, approval_plan_digest: str
) -> RuntimeBinding:
    if not isinstance(intent, SelectionBindingIntent):
        raise TypeError("intent must be SelectionBindingIntent")
    validate_binding_intent_evidence(intent)
    approval = _digest(
        approval_plan_digest, _HEX_64, "runtime binding rejected"
    )
    binding = RuntimeBinding(
        candidate_canonical_sha256=intent.candidate_canonical_sha256,
        approval_plan_digest=approval,
        selector_dropin_sha256=intent.selector_dropin_sha256,
        guard_dropin_sha256=intent.guard_dropin_sha256,
        verifier_script_path=intent.verifier_script_path,
        verifier_script_sha256=intent.verifier_script_sha256,
        selected_release=intent.selected_release,
    )
    validate_runtime_binding_evidence(binding)
    return binding


def validate_runtime_binding_evidence(binding: RuntimeBinding) -> None:
    if not isinstance(binding, RuntimeBinding):
        raise TypeError("binding must be RuntimeBinding")
    intent = SelectionBindingIntent(
        candidate_canonical_sha256=binding.candidate_canonical_sha256,
        selector_dropin_sha256=binding.selector_dropin_sha256,
        guard_dropin_sha256=binding.guard_dropin_sha256,
        verifier_script_path=binding.verifier_script_path,
        verifier_script_sha256=binding.verifier_script_sha256,
        selected_release=binding.selected_release,
    )
    validate_binding_intent_evidence(intent)


def compute_tree_digest(root: Path) -> tuple[str, int]:
    if not isinstance(root, Path) or root.is_symlink() or not root.is_dir():
        raise SelectorContractError("release tree rejected")
    entries = sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())
    files: list[Path] = []
    for entry in entries:
        if entry.is_symlink():
            raise SelectorContractError("release tree rejected")
        if entry.is_dir():
            continue
        if not entry.is_file():
            raise SelectorContractError("release tree rejected")
        files.append(entry)
    combined = sha256()
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        payload = path.read_bytes()
        combined.update(len(relative).to_bytes(4, "big"))
        combined.update(relative)
        combined.update(len(payload).to_bytes(8, "big"))
        combined.update(payload)
    return combined.hexdigest(), len(files)


def validate_immutable_release_tree(
    root: Path,
    release: ReleaseEvidence,
    *,
    expected_uid: int = 0,
    expected_gid: int | None = None,
) -> None:
    if expected_gid is None:
        try:
            expected_gid = grp.getgrnam("myuna").gr_gid
        except KeyError as exc:
            raise SelectorContractError("release ownership rejected") from exc
    if root.as_posix() != release.release_path.as_posix():
        raise SelectorContractError("release path rejected")
    digest, count = compute_tree_digest(root)
    if digest != release.tree_sha256 or count != release.file_count:
        raise SelectorContractError("release tree evidence rejected")
    for entry in (root, *root.rglob("*")):
        if entry.is_symlink():
            raise SelectorContractError("release permissions rejected")
        metadata = entry.stat()
        if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
            raise SelectorContractError("release permissions rejected")
        expected_mode = 0o550 if entry.is_dir() else 0o440
        if stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise SelectorContractError("release permissions rejected")


def validate_verifier_file(
    path: Path,
    binding: RuntimeBinding,
    *,
    expected_uid: int = 0,
    expected_gid: int | None = None,
) -> None:
    if not isinstance(path, Path) or not isinstance(binding, RuntimeBinding):
        raise TypeError("path and binding types rejected")
    validate_runtime_binding_evidence(binding)
    if expected_gid is None:
        try:
            expected_gid = grp.getgrnam("myuna").gr_gid
        except KeyError as exc:
            raise SelectorContractError("verifier ownership rejected") from exc
    if (
        path.as_posix() != binding.verifier_script_path
        or path.is_symlink()
        or not path.is_file()
        or path.parent.is_symlink()
        or not path.parent.is_dir()
    ):
        raise SelectorContractError("verifier path rejected")
    if sha256(path.read_bytes()).hexdigest() != binding.verifier_script_sha256:
        raise SelectorContractError("verifier content rejected")
    for entry, expected_mode in ((path.parent, 0o550), (path, 0o440)):
        metadata = entry.stat()
        if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
            raise SelectorContractError("verifier ownership rejected")
        if stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise SelectorContractError("verifier permissions rejected")


def validate_runtime_observation(
    binding: RuntimeBinding,
    *,
    observed_cwd: str,
    observed_pythonpath: str,
    selector_dropin: bytes,
    guard_dropin: bytes,
    observed_verifier_path: str,
    observed_verifier_sha256: str,
    observed_tree_sha256: str,
    observed_file_count: int,
) -> None:
    if not isinstance(binding, RuntimeBinding):
        raise TypeError("binding must be RuntimeBinding")
    validate_runtime_binding_evidence(binding)
    expected_selector = _selector_text(binding.selected_release).encode("utf-8")
    if selector_dropin != expected_selector:
        raise SelectorContractError("selector content rejected")
    if sha256(selector_dropin).hexdigest() != binding.selector_dropin_sha256:
        raise SelectorContractError("selector digest rejected")
    expected_guard = render_guard_dropin(binding.verifier_script_path).encode("utf-8")
    if guard_dropin != expected_guard:
        raise SelectorContractError("guard content rejected")
    if sha256(guard_dropin).hexdigest() != binding.guard_dropin_sha256:
        raise SelectorContractError("guard digest rejected")
    if (
        observed_verifier_path != binding.verifier_script_path
        or observed_verifier_sha256 != binding.verifier_script_sha256
    ):
        raise SelectorContractError("verifier identity rejected")
    expected_cwd = binding.selected_release.release_path.as_posix()
    if observed_cwd != expected_cwd:
        raise SelectorContractError("runtime working directory rejected")
    if observed_pythonpath != f"{expected_cwd}/src":
        raise SelectorContractError("runtime PYTHONPATH rejected")
    if (
        observed_tree_sha256 != binding.selected_release.tree_sha256
        or observed_file_count != binding.selected_release.file_count
    ):
        raise SelectorContractError("runtime release evidence rejected")


def assert_environment_files_do_not_define_pythonpath(
    environment_files: Mapping[str, bytes],
) -> None:
    for name, payload in environment_files.items():
        if not isinstance(name, str) or not isinstance(payload, bytes):
            raise SelectorContractError("EnvironmentFile inventory rejected")
        try:
            text = payload.decode("utf-8")
        except UnicodeError as exc:
            raise SelectorContractError("EnvironmentFile inventory rejected") from exc
        if _PYTHONPATH_IN_ENVIRONMENT_FILE.search(text) is not None:
            raise SelectorContractError("EnvironmentFile PYTHONPATH rejected")


def _release_owner(name: str, payload: bytes, *, is_base: bool) -> ReleaseOwner | None:
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise SelectorContractError("systemd fragment rejected") from exc
    working_directories: list[str] = []
    pythonpaths: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        working_directory_match = _WORKING_DIRECTORY_DIRECTIVE.fullmatch(line)
        if working_directory_match is not None:
            working_directories.append(working_directory_match.group(1).strip())
            continue
        environment_match = _ENVIRONMENT_DIRECTIVE.fullmatch(line)
        if environment_match is not None:
            try:
                assignments = shlex.split(environment_match.group(1).strip())
            except ValueError as exc:
                raise SelectorContractError("systemd fragment rejected") from exc
            for assignment in assignments:
                if assignment.startswith("PYTHONPATH="):
                    pythonpaths.append(assignment.split("=", 1)[1])
    if not working_directories and not pythonpaths:
        return None
    if len(working_directories) != 1 or len(pythonpaths) != 1:
        raise SelectorContractError("partial or duplicate release ownership")
    working_directory = working_directories[0]
    pythonpath = pythonpaths[0]
    if pythonpath != f"{working_directory}/src":
        raise SelectorContractError("split release ownership rejected")
    return ReleaseOwner(
        source_name=name,
        source_sha256=sha256(payload).hexdigest(),
        working_directory=working_directory,
        pythonpath=pythonpath,
        is_base_template=is_base,
    )


def analyze_systemd_release_inventory(
    base_template: bytes,
    dropins: Mapping[str, bytes],
) -> SystemdReleaseInventory:
    if not isinstance(base_template, bytes):
        raise SelectorContractError("systemd inventory rejected")
    if any(not isinstance(name, str) or not isinstance(data, bytes) for name, data in dropins.items()):
        raise SelectorContractError("systemd inventory rejected")
    base_owner = _release_owner("myuna-core@.service", base_template, is_base=True)
    owners: list[ReleaseOwner] = []
    fragments: list[tuple[str, str]] = []
    for name in sorted(dropins):
        payload = dropins[name]
        fragments.append((name, sha256(payload).hexdigest()))
        owner = _release_owner(name, payload, is_base=False)
        if owner is not None:
            owners.append(owner)
    effective = owners[-1] if owners else base_owner
    return SystemdReleaseInventory(
        base_template_sha256=sha256(base_template).hexdigest(),
        fragment_sha256=tuple(fragments),
        base_owner=base_owner,
        dropin_owners=tuple(owners),
        effective_owner=effective,
    )


def validate_inventory_prestate(
    inventory: SystemdReleaseInventory,
    *,
    expected_base_sha256: str,
    expected_dropin_sha256: Mapping[str, str],
    expected_effective_owner: str,
    expected_effective_working_directory: str,
) -> None:
    if inventory.base_template_sha256 != expected_base_sha256:
        raise SelectorContractError("systemd prestate rejected")
    if dict(inventory.fragment_sha256) != dict(expected_dropin_sha256):
        raise SelectorContractError("systemd prestate rejected")
    effective = inventory.effective_owner
    if (
        effective is None
        or effective.source_name != expected_effective_owner
        or effective.working_directory != expected_effective_working_directory
    ):
        raise SelectorContractError("systemd prestate rejected")


def validate_r1_repository_release_owners(systemd_files: Mapping[str, bytes]) -> None:
    owners: dict[str, str] = {}
    for name, payload in systemd_files.items():
        owner = _release_owner(name, payload, is_base=False)
        if owner is not None:
            owners[name] = owner.source_sha256
    expected = {LEGACY_REPOSITORY_OWNER: LEGACY_REPOSITORY_OWNER_SHA256}
    if owners != expected:
        raise SelectorContractError("repository release ownership rejected")


def verify_active_runtime() -> None:
    try:
        binding_payload = parse_json_document(RUNTIME_BINDING_PATH.read_bytes())
        binding = load_runtime_binding(binding_payload)
        selector_dropin = RUNTIME_SELECTOR_PATH.read_bytes()
        guard_dropin = RUNTIME_GUARD_PATH.read_bytes()
        verifier_path = Path(__file__)
        validate_verifier_file(verifier_path, binding)
        release_root = Path(binding.selected_release.release_path.as_posix())
        validate_immutable_release_tree(release_root, binding.selected_release)
        digest, count = compute_tree_digest(release_root)
        validate_runtime_observation(
            binding,
            observed_cwd=Path.cwd().as_posix(),
            observed_pythonpath=os.environ.get("PYTHONPATH", ""),
            selector_dropin=selector_dropin,
            guard_dropin=guard_dropin,
            observed_verifier_path=verifier_path.as_posix(),
            observed_verifier_sha256=sha256(verifier_path.read_bytes()).hexdigest(),
            observed_tree_sha256=digest,
            observed_file_count=count,
        )
    except (OSError, SelectorContractError) as exc:
        raise SelectorContractError("active runtime verification failed") from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Myuna Core Release Selector v1")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("verify-active")
    arguments = parser.parse_args(argv)
    if arguments.command == "verify-active":
        try:
            verify_active_runtime()
        except SelectorContractError:
            return 1
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
