#!/usr/bin/env python3
"""Typed, content-free filesystem mutation-set contract for P07.

The module is deliberately independent from any live strategy or attempt
namespace.  It models the complete byte and metadata transition for an
allowlisted set of non-secret configuration files, proves an off-live staged
bundle, verifies per-path read-back and the complete observed inventory, and
supports one crash-resumable exact reverse rollback.
"""

from __future__ import annotations

from hashlib import sha256
import fnmatch
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Callable, Mapping, Sequence


SCHEMA = "myuna.p07-full-filesystem-mutation-set.v1"
ROOT_SCHEMA = "myuna.p07-filesystem-mutation-root.v1"
STATE_SCHEMA = "myuna.p07-filesystem-path-state.v1"
GENERATOR_SCHEMA = "myuna.p07-filesystem-generator-identity.v1"
OPERATION_SCHEMA = "myuna.p07-filesystem-mutation-operation.v1"
STAGING_SCHEMA = "myuna.p07-filesystem-mutation-staging.v1"
JOURNAL_SCHEMA = "myuna.p07-filesystem-mutation-journal.v1"
EVIDENCE_SCHEMA = "myuna.p07-filesystem-mutation-evidence.v1"
SOURCE_ID = "p07-full-filesystem-mutation-set-v1"
CONTENT_CLASS = "nonsecret_configuration"

_SHA = re.compile(r"^[0-9a-f]{64}$")
_TYPED = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
_PATTERN = re.compile(r"^\*\.[A-Za-z0-9][A-Za-z0-9_.-]*$")
_STATE_FIELDS = {
    "exists",
    "file_type",
    "gid",
    "mode",
    "schema",
    "sha256",
    "size",
    "uid",
}
_ROOT_FIELDS = {
    "allowed_logical_paths",
    "allowed_owners",
    "content_class",
    "inventory_pattern",
    "path",
    "recursive",
    "root_id",
    "schema",
}
_GENERATOR_FIELDS = {
    "generator_id",
    "input_digest",
    "output_state_digest",
    "schema",
    "source_sha256",
}
_OPERATION_FIELDS = {
    "after",
    "before",
    "content_class",
    "generator",
    "kind",
    "logical_path",
    "order",
    "root_id",
    "schema",
}


class MutationSetRejected(RuntimeError):
    def __init__(self, code: str, *, cause_code: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.cause_code = cause_code


def typed_exception_code(exc: BaseException, *, fallback: str) -> str:
    candidate = getattr(exc, "code", None)
    if isinstance(candidate, str) and _TYPED.fullmatch(candidate) is not None:
        return candidate
    return fallback


def require(condition: bool, code: str) -> None:
    if not condition:
        raise MutationSetRejected(code)


def canonical(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"


def digest(domain: str, payload: object) -> str:
    return sha256(
        domain.encode("ascii") + b"\0" + canonical(payload).rstrip(b"\n")
    ).hexdigest()


def digest_bytes(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        require(key not in result, "mutation_set_duplicate_field_rejected")
        result[key] = value
    return result


def _normalized_absolute(value: str, code: str) -> str:
    require(isinstance(value, str) and value.startswith("/"), code)
    path = PurePosixPath(value)
    require(
        path.is_absolute()
        and "." not in path.parts
        and ".." not in path.parts
        and path.as_posix() == value
        and value != "/",
        code,
    )
    return value


def _normalized_logical(value: str, code: str) -> str:
    require(isinstance(value, str) and bool(value), code)
    path = PurePosixPath(value)
    require(
        not path.is_absolute()
        and "." not in path.parts
        and ".." not in path.parts
        and path.as_posix() == value
        and value not in {"", "."},
        code,
    )
    return value


def absent_state() -> dict[str, object]:
    return {
        "exists": False,
        "file_type": "absent",
        "gid": None,
        "mode": None,
        "schema": STATE_SCHEMA,
        "sha256": None,
        "size": 0,
        "uid": None,
    }


def regular_state(
    payload: bytes,
    *,
    uid: int,
    gid: int,
    mode: int,
) -> dict[str, object]:
    state = {
        "exists": True,
        "file_type": "regular",
        "gid": gid,
        "mode": mode,
        "schema": STATE_SCHEMA,
        "sha256": digest_bytes(payload),
        "size": len(payload),
        "uid": uid,
    }
    return validate_state(state)


def validate_state(payload: Mapping[str, object]) -> dict[str, object]:
    state = dict(payload)
    require(
        set(state) == _STATE_FIELDS and state.get("schema") == STATE_SCHEMA,
        "mutation_set_path_state_rejected",
    )
    if state["exists"] is False:
        require(
            state
            == absent_state(),
            "mutation_set_absent_state_rejected",
        )
    else:
        require(
            state["exists"] is True
            and state["file_type"] == "regular"
            and isinstance(state["sha256"], str)
            and _SHA.fullmatch(state["sha256"]) is not None
            and isinstance(state["size"], int)
            and state["size"] >= 0
            and isinstance(state["uid"], int)
            and state["uid"] >= 0
            and isinstance(state["gid"], int)
            and state["gid"] >= 0
            and isinstance(state["mode"], int)
            and 0 <= state["mode"] <= 0o7777,
            "mutation_set_regular_state_rejected",
        )
    return state


def inspect_path(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return absent_state()
    except OSError as exc:
        raise MutationSetRejected("mutation_set_path_unavailable") from exc
    require(not stat.S_ISLNK(metadata.st_mode), "mutation_set_symlink_rejected")
    require(stat.S_ISREG(metadata.st_mode), "mutation_set_path_type_rejected")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise MutationSetRejected("mutation_set_path_unavailable") from exc
    return regular_state(
        payload,
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        mode=stat.S_IMODE(metadata.st_mode),
    )


def build_root(
    *,
    root_id: str,
    path: Path,
    allowed_logical_paths: Sequence[str],
    allowed_owners: Sequence[tuple[int, int]],
    inventory_pattern: str = "*.conf",
    recursive: bool = False,
) -> dict[str, object]:
    normalized_path = _normalized_absolute(path.as_posix(), "mutation_set_root_path_rejected")
    require(_TYPED.fullmatch(root_id) is not None, "mutation_set_root_id_rejected")
    require(
        isinstance(recursive, bool)
        and isinstance(inventory_pattern, str)
        and (
            inventory_pattern == "*"
            or _PATTERN.fullmatch(inventory_pattern) is not None
        ),
        "mutation_set_inventory_pattern_rejected",
    )
    logical_paths = sorted(
        {
            _normalized_logical(item, "mutation_set_allowed_path_rejected")
            for item in allowed_logical_paths
        }
    )
    require(
        logical_paths
        and len(logical_paths) == len(allowed_logical_paths)
        and (recursive or all("/" not in item for item in logical_paths)),
        "mutation_set_allowed_path_rejected",
    )
    owners = sorted({(uid, gid) for uid, gid in allowed_owners})
    require(
        owners
        and len(owners) == len(allowed_owners)
        and all(
            isinstance(uid, int)
            and uid >= 0
            and isinstance(gid, int)
            and gid >= 0
            for uid, gid in owners
        ),
        "mutation_set_allowed_owner_rejected",
    )
    return {
        "allowed_logical_paths": logical_paths,
        "allowed_owners": [
            {"gid": gid, "uid": uid} for uid, gid in owners
        ],
        "content_class": CONTENT_CLASS,
        "inventory_pattern": inventory_pattern,
        "path": normalized_path,
        "recursive": recursive,
        "root_id": root_id,
        "schema": ROOT_SCHEMA,
    }


def validate_root(payload: Mapping[str, object]) -> dict[str, object]:
    root = dict(payload)
    require(set(root) == _ROOT_FIELDS, "mutation_set_root_contract_rejected")
    rebuilt = build_root(
        root_id=str(root.get("root_id", "")),
        path=Path(str(root.get("path", ""))),
        allowed_logical_paths=list(root.get("allowed_logical_paths", [])),
        allowed_owners=[
            (int(item["uid"]), int(item["gid"]))
            for item in root.get("allowed_owners", [])
            if isinstance(item, Mapping)
            and set(item) == {"gid", "uid"}
            and isinstance(item.get("uid"), int)
            and isinstance(item.get("gid"), int)
        ],
        inventory_pattern=str(root.get("inventory_pattern", "")),
        recursive=root.get("recursive", False),
    )
    require(root == rebuilt, "mutation_set_root_contract_rejected")
    return rebuilt


def build_generator(
    *,
    generator_id: str,
    source_sha256: str,
    input_digest: str,
    output_state: Mapping[str, object],
) -> dict[str, object]:
    state = validate_state(output_state)
    require(
        _TYPED.fullmatch(generator_id) is not None
        and _SHA.fullmatch(source_sha256) is not None
        and _SHA.fullmatch(input_digest) is not None,
        "mutation_set_generator_identity_rejected",
    )
    return {
        "generator_id": generator_id,
        "input_digest": input_digest,
        "output_state_digest": digest("myuna-p07-path-state-v1", state),
        "schema": GENERATOR_SCHEMA,
        "source_sha256": source_sha256,
    }


def validate_generator(
    payload: Mapping[str, object], *, output_state: Mapping[str, object]
) -> dict[str, object]:
    generator = dict(payload)
    require(
        set(generator) == _GENERATOR_FIELDS
        and generator.get("schema") == GENERATOR_SCHEMA,
        "mutation_set_generator_identity_rejected",
    )
    rebuilt = build_generator(
        generator_id=str(generator.get("generator_id", "")),
        source_sha256=str(generator.get("source_sha256", "")),
        input_digest=str(generator.get("input_digest", "")),
        output_state=output_state,
    )
    require(generator == rebuilt, "mutation_set_generator_identity_rejected")
    return rebuilt


def build_operation(
    *,
    root: Mapping[str, object],
    order: int,
    kind: str,
    logical_path: str,
    before: Mapping[str, object],
    after: Mapping[str, object],
    generator: Mapping[str, object],
) -> dict[str, object]:
    normalized_root = validate_root(root)
    before_state = validate_state(before)
    after_state = validate_state(after)
    logical = _normalized_logical(logical_path, "mutation_set_logical_path_rejected")
    require(
        isinstance(order, int)
        and order >= 0
        and kind in {"add", "replace", "remove"}
        and logical in normalized_root["allowed_logical_paths"]
        and (normalized_root["recursive"] or "/" not in logical),
        "mutation_set_operation_rejected",
    )
    if kind == "add":
        require(
            before_state["exists"] is False and after_state["exists"] is True,
            "mutation_set_add_precondition_rejected",
        )
    elif kind == "replace":
        require(
            before_state["exists"] is True
            and after_state["exists"] is True
            and before_state != after_state,
            "mutation_set_replace_precondition_rejected",
        )
    else:
        require(
            before_state["exists"] is True and after_state["exists"] is False,
            "mutation_set_remove_precondition_rejected",
        )
    allowed_owners = {
        (item["uid"], item["gid"])
        for item in normalized_root["allowed_owners"]
    }
    for state_payload in (before_state, after_state):
        if state_payload["exists"]:
            require(
                (state_payload["uid"], state_payload["gid"]) in allowed_owners,
                "mutation_set_operation_owner_rejected",
            )
    normalized_generator = validate_generator(generator, output_state=after_state)
    return {
        "after": after_state,
        "before": before_state,
        "content_class": CONTENT_CLASS,
        "generator": normalized_generator,
        "kind": kind,
        "logical_path": logical,
        "order": order,
        "root_id": normalized_root["root_id"],
        "schema": OPERATION_SCHEMA,
    }


def validate_operation(
    payload: Mapping[str, object], *, roots: Mapping[str, Mapping[str, object]]
) -> dict[str, object]:
    operation = dict(payload)
    require(
        set(operation) == _OPERATION_FIELDS
        and operation.get("schema") == OPERATION_SCHEMA
        and operation.get("content_class") == CONTENT_CLASS
        and operation.get("root_id") in roots
        and isinstance(operation.get("before"), Mapping)
        and isinstance(operation.get("after"), Mapping)
        and isinstance(operation.get("generator"), Mapping),
        "mutation_set_operation_contract_rejected",
    )
    rebuilt = build_operation(
        root=roots[str(operation["root_id"])],
        order=operation.get("order", -1),
        kind=str(operation.get("kind", "")),
        logical_path=str(operation.get("logical_path", "")),
        before=operation["before"],
        after=operation["after"],
        generator=operation["generator"],
    )
    require(operation == rebuilt, "mutation_set_operation_contract_rejected")
    return rebuilt


def inventory_entry(
    *, root_id: str, logical_path: str, state: Mapping[str, object]
) -> dict[str, object]:
    normalized = validate_state(state)
    require(
        normalized["exists"] is True
        and _TYPED.fullmatch(root_id) is not None,
        "mutation_set_inventory_entry_rejected",
    )
    return {
        "logical_path": _normalized_logical(
            logical_path, "mutation_set_inventory_path_rejected"
        ),
        "root_id": root_id,
        "state": normalized,
    }


def _normalize_inventory(
    entries: Sequence[Mapping[str, object]],
    *,
    roots: Mapping[str, Mapping[str, object]],
) -> list[dict[str, object]]:
    normalized: list[dict[str, object]] = []
    for payload in entries:
        require(
            isinstance(payload, Mapping)
            and set(payload) == {"logical_path", "root_id", "state"}
            and payload.get("root_id") in roots
            and isinstance(payload.get("state"), Mapping),
            "mutation_set_inventory_entry_rejected",
        )
        entry = inventory_entry(
            root_id=str(payload["root_id"]),
            logical_path=str(payload["logical_path"]),
            state=payload["state"],
        )
        root = roots[entry["root_id"]]
        require(
            fnmatch.fnmatch(entry["logical_path"], root["inventory_pattern"])
            and (root["recursive"] or "/" not in entry["logical_path"]),
            "mutation_set_inventory_path_rejected",
        )
        normalized.append(entry)
    normalized.sort(key=lambda item: (item["root_id"], item["logical_path"]))
    require(
        len({(item["root_id"], item["logical_path"]) for item in normalized})
        == len(normalized),
        "mutation_set_inventory_duplicate_rejected",
    )
    return normalized


def inventory_from_absolute(
    *,
    root: Mapping[str, object],
    inventory: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    normalized_root = validate_root(root)
    root_path = PurePosixPath(str(normalized_root["path"]))
    entries: list[dict[str, object]] = []
    required = {"file_type", "gid", "mode", "path", "sha256", "size", "uid"}
    for payload in inventory:
        item = dict(payload)
        require(
            set(item) == required
            and item.get("file_type") == "regular"
            and isinstance(item.get("path"), str),
            "mutation_set_absolute_inventory_rejected",
        )
        absolute = PurePosixPath(str(item["path"]))
        try:
            logical = absolute.relative_to(root_path).as_posix()
        except ValueError:
            raise MutationSetRejected("mutation_set_inventory_escape_rejected") from None
        entries.append(
            inventory_entry(
                root_id=str(normalized_root["root_id"]),
                logical_path=logical,
                state={
                    "exists": True,
                    "file_type": "regular",
                    "gid": item["gid"],
                    "mode": item["mode"],
                    "schema": STATE_SCHEMA,
                    "sha256": item["sha256"],
                    "size": item["size"],
                    "uid": item["uid"],
                },
            )
        )
    return _normalize_inventory(
        entries, roots={str(normalized_root["root_id"]): normalized_root}
    )


def inventory_to_absolute(
    *, root: Mapping[str, object], inventory: Sequence[Mapping[str, object]]
) -> list[dict[str, object]]:
    normalized_root = validate_root(root)
    roots = {str(normalized_root["root_id"]): normalized_root}
    normalized = _normalize_inventory(inventory, roots=roots)
    base = PurePosixPath(str(normalized_root["path"]))
    result: list[dict[str, object]] = []
    for item in normalized:
        state = item["state"]
        result.append(
            {
                "file_type": "regular",
                "gid": state["gid"],
                "mode": state["mode"],
                "path": (base / str(item["logical_path"])).as_posix(),
                "sha256": state["sha256"],
                "size": state["size"],
                "uid": state["uid"],
            }
        )
    return result


def _apply_operations(
    prestate: Sequence[Mapping[str, object]],
    operations: Sequence[Mapping[str, object]],
    *,
    roots: Mapping[str, Mapping[str, object]],
) -> list[dict[str, object]]:
    current = {
        (item["root_id"], item["logical_path"]): dict(item)
        for item in _normalize_inventory(prestate, roots=roots)
    }
    for operation_payload in operations:
        operation = validate_operation(operation_payload, roots=roots)
        key = (operation["root_id"], operation["logical_path"])
        actual = current.get(key)
        expected_before = operation["before"]
        if expected_before["exists"]:
            require(
                actual is not None and actual["state"] == expected_before,
                "mutation_set_operation_prestate_drifted",
            )
        else:
            require(actual is None, "mutation_set_add_path_preexisting")
        if operation["after"]["exists"]:
            current[key] = inventory_entry(
                root_id=str(operation["root_id"]),
                logical_path=str(operation["logical_path"]),
                state=operation["after"],
            )
        else:
            del current[key]
    return _normalize_inventory(list(current.values()), roots=roots)


def build_mutation_set(
    *,
    transaction_id: str,
    roots: Sequence[Mapping[str, object]],
    prestate_inventory: Sequence[Mapping[str, object]],
    operations: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    require(_TYPED.fullmatch(transaction_id) is not None, "mutation_set_transaction_id_rejected")
    normalized_roots = [validate_root(item) for item in roots]
    normalized_roots.sort(key=lambda item: item["root_id"])
    roots_by_id = {str(item["root_id"]): item for item in normalized_roots}
    require(
        len(roots_by_id) == len(normalized_roots) and bool(normalized_roots),
        "mutation_set_root_duplicate_rejected",
    )
    normalized_operations = [
        validate_operation(item, roots=roots_by_id) for item in operations
    ]
    normalized_operations.sort(key=lambda item: item["order"])
    require(
        [item["order"] for item in normalized_operations]
        == list(range(len(normalized_operations)))
        and bool(normalized_operations),
        "mutation_set_operation_order_rejected",
    )
    operation_keys = [
        (item["root_id"], item["logical_path"])
        for item in normalized_operations
    ]
    require(
        len(set(operation_keys)) == len(operation_keys),
        "mutation_set_duplicate_path_rejected",
    )
    for index, left in enumerate(operation_keys):
        for right in operation_keys[index + 1 :]:
            if left[0] != right[0]:
                continue
            left_parts = PurePosixPath(str(left[1])).parts
            right_parts = PurePosixPath(str(right[1])).parts
            require(
                left_parts != right_parts[: len(left_parts)]
                and right_parts != left_parts[: len(right_parts)],
                "mutation_set_overlapping_path_rejected",
            )
    normalized_prestate = _normalize_inventory(
        prestate_inventory, roots=roots_by_id
    )
    target = _apply_operations(
        normalized_prestate, normalized_operations, roots=roots_by_id
    )
    semantic = {
        "content_class": CONTENT_CLASS,
        "operations": normalized_operations,
        "prestate_inventory": normalized_prestate,
        "prestate_inventory_digest": digest(
            "myuna-p07-filesystem-prestate-inventory-v1", normalized_prestate
        ),
        "roots": normalized_roots,
        "schema": SCHEMA,
        "source_id": SOURCE_ID,
        "target_inventory": target,
        "target_inventory_digest": digest(
            "myuna-p07-filesystem-target-inventory-v1", target
        ),
        "transaction_id": transaction_id,
    }
    return {
        **semantic,
        "mutation_set_id": digest(
            "myuna-p07-full-filesystem-mutation-set-v1", semantic
        ),
    }


def validate_mutation_set(payload: Mapping[str, object]) -> dict[str, object]:
    contract = dict(payload)
    required = {
        "content_class",
        "mutation_set_id",
        "operations",
        "prestate_inventory",
        "prestate_inventory_digest",
        "roots",
        "schema",
        "source_id",
        "target_inventory",
        "target_inventory_digest",
        "transaction_id",
    }
    require(
        set(contract) == required
        and contract.get("schema") == SCHEMA
        and contract.get("source_id") == SOURCE_ID
        and contract.get("content_class") == CONTENT_CLASS
        and isinstance(contract.get("roots"), list)
        and isinstance(contract.get("operations"), list)
        and isinstance(contract.get("prestate_inventory"), list),
        "mutation_set_contract_rejected",
    )
    rebuilt = build_mutation_set(
        transaction_id=str(contract.get("transaction_id", "")),
        roots=contract["roots"],
        prestate_inventory=contract["prestate_inventory"],
        operations=contract["operations"],
    )
    require(contract == rebuilt, "mutation_set_contract_rejected")
    return rebuilt


def roots_by_id(contract: Mapping[str, object]) -> dict[str, dict[str, object]]:
    normalized = validate_mutation_set(contract)
    return {str(item["root_id"]): dict(item) for item in normalized["roots"]}


def target_inventory_for_root(
    contract: Mapping[str, object], root_id: str
) -> list[dict[str, object]]:
    normalized = validate_mutation_set(contract)
    require(root_id in roots_by_id(normalized), "mutation_set_root_id_rejected")
    return [
        dict(item)
        for item in normalized["target_inventory"]
        if item["root_id"] == root_id
    ]


def _root_path(root: Mapping[str, object], logical_path: str) -> Path:
    normalized_root = validate_root(root)
    logical = _normalized_logical(logical_path, "mutation_set_logical_path_rejected")
    require(
        normalized_root["recursive"] or "/" not in logical,
        "mutation_set_logical_path_rejected",
    )
    return Path(str(normalized_root["path"])) / logical


def scan_root(root: Mapping[str, object]) -> list[dict[str, object]]:
    normalized = validate_root(root)
    root_path = Path(str(normalized["path"]))
    try:
        root_metadata = root_path.lstat()
    except OSError as exc:
        raise MutationSetRejected("mutation_set_inventory_root_unavailable") from exc
    require(
        not stat.S_ISLNK(root_metadata.st_mode)
        and stat.S_ISDIR(root_metadata.st_mode),
        "mutation_set_inventory_root_type_rejected",
    )
    candidates = (
        root_path.rglob(str(normalized["inventory_pattern"]))
        if normalized["recursive"]
        else root_path.glob(str(normalized["inventory_pattern"]))
    )
    result = []
    for path in sorted(candidates, key=lambda item: item.relative_to(root_path).as_posix()):
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise MutationSetRejected("mutation_set_inventory_path_unavailable") from exc
        require(not stat.S_ISLNK(metadata.st_mode), "mutation_set_symlink_rejected")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        require(
            stat.S_ISREG(metadata.st_mode),
            "mutation_set_inventory_path_type_rejected",
        )
        logical = path.relative_to(root_path).as_posix()
        result.append(
            inventory_entry(
                root_id=str(normalized["root_id"]),
                logical_path=logical,
                state=inspect_path(path),
            )
        )
    return _normalize_inventory(
        result, roots={str(normalized["root_id"]): normalized}
    )


def scan_contract_roots(contract: Mapping[str, object]) -> list[dict[str, object]]:
    normalized = validate_mutation_set(contract)
    result: list[dict[str, object]] = []
    for root in normalized["roots"]:
        result.extend(scan_root(root))
    return _normalize_inventory(result, roots=roots_by_id(normalized))


def path_key(root_id: str, logical_path: str) -> str:
    require(
        _TYPED.fullmatch(root_id) is not None,
        "mutation_set_root_id_rejected",
    )
    return f"{root_id}:{_normalized_logical(logical_path, 'mutation_set_logical_path_rejected')}"


def comparison_evidence(
    *,
    expected: Sequence[Mapping[str, object]],
    observed: Sequence[Mapping[str, object]],
    contract: Mapping[str, object],
    phase: str,
) -> dict[str, object]:
    require(_TYPED.fullmatch(phase) is not None, "mutation_set_evidence_phase_rejected")
    roots = roots_by_id(contract)
    normalized_expected = _normalize_inventory(expected, roots=roots)
    normalized_observed = _normalize_inventory(observed, roots=roots)
    expected_map = {
        (item["root_id"], item["logical_path"]): item["state"]
        for item in normalized_expected
    }
    observed_map = {
        (item["root_id"], item["logical_path"]): item["state"]
        for item in normalized_observed
    }
    mismatches: list[dict[str, object]] = []
    state_fields = ("exists", "file_type", "sha256", "size", "uid", "gid", "mode")
    for root_id, logical_path in sorted(set(expected_map) | set(observed_map)):
        expected_state = expected_map.get((root_id, logical_path), absent_state())
        observed_state = observed_map.get((root_id, logical_path), absent_state())
        fields = [
            field
            for field in state_fields
            if expected_state[field] != observed_state[field]
        ]
        if fields:
            mismatches.append(
                {
                    "expected": expected_state,
                    "logical_path": logical_path,
                    "mismatch_fields": fields,
                    "observed": observed_state,
                    "path_digest": digest(
                        "myuna-p07-mutation-logical-path-v1",
                        {"logical_path": logical_path, "root_id": root_id},
                    ),
                    "root_id": root_id,
                }
            )
    return {
        "content_retained": False,
        "credential_value_read": False,
        "mismatches": mismatches,
        "mutation_set_id": validate_mutation_set(contract)["mutation_set_id"],
        "phase": phase,
        "schema": EVIDENCE_SCHEMA,
        "status": "match" if not mismatches else "mismatch",
    }


def require_prestate(contract: Mapping[str, object]) -> list[dict[str, object]]:
    normalized = validate_mutation_set(contract)
    observed = scan_contract_roots(normalized)
    observed_digest = digest(
        "myuna-p07-filesystem-prestate-inventory-v1", observed
    )
    if observed == normalized["target_inventory"]:
        raise MutationSetRejected("mutation_set_replayed")
    require(
        observed_digest == normalized["prestate_inventory_digest"]
        and observed == normalized["prestate_inventory"],
        "mutation_set_prestate_drifted",
    )
    return observed


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(path: Path, payload: bytes, *, mode: int, uid: int, gid: int) -> None:
    require(path.is_absolute(), "mutation_set_write_path_rejected")
    parent = path.parent
    metadata = parent.lstat()
    require(
        not stat.S_ISLNK(metadata.st_mode) and stat.S_ISDIR(metadata.st_mode),
        "mutation_set_write_parent_rejected",
    )
    temporary = parent / f".{path.name}.p07-{digest_bytes(payload)[:16]}.tmp"
    require(not temporary.exists() and not temporary.is_symlink(), "mutation_set_stale_temp_rejected")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, uid, gid)
        observed = inspect_path(temporary)
        require(
            observed
            == regular_state(payload, uid=uid, gid=gid, mode=mode),
            "mutation_set_staged_write_readback_rejected",
        )
        os.replace(temporary, path)
        _fsync_directory(parent)
    except BaseException:
        try:
            if temporary.exists() and not temporary.is_symlink():
                temporary.unlink()
        except OSError:
            pass
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _ensure_write_parents(
    *, root: Mapping[str, object], target: Path, uid: int, gid: int
) -> None:
    """Create only deterministic release-subdirectories below one bound root."""

    normalized_root = validate_root(root)
    root_path = Path(str(normalized_root["path"]))
    try:
        relative_parent = target.parent.relative_to(root_path)
    except ValueError:
        raise MutationSetRejected("mutation_set_write_parent_escape_rejected") from None
    current = root_path
    for part in relative_parent.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o550)
            os.chown(current, uid, gid)
            os.chmod(current, 0o550)
            _fsync_directory(current.parent)
            metadata = current.lstat()
        except OSError as exc:
            raise MutationSetRejected("mutation_set_write_parent_unavailable") from exc
        require(
            not stat.S_ISLNK(metadata.st_mode)
            and stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == uid
            and metadata.st_gid == gid
            and stat.S_IMODE(metadata.st_mode) == 0o550,
            "mutation_set_write_parent_rejected",
        )


def _prune_empty_write_parents(
    *, root: Mapping[str, object], target: Path, uid: int, gid: int
) -> None:
    normalized_root = validate_root(root)
    root_path = Path(str(normalized_root["path"]))
    current = target.parent
    try:
        current.relative_to(root_path)
    except ValueError:
        raise MutationSetRejected("mutation_set_write_parent_escape_rejected") from None
    while current != root_path:
        metadata = current.lstat()
        require(
            not stat.S_ISLNK(metadata.st_mode)
            and stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == uid
            and metadata.st_gid == gid
            and stat.S_IMODE(metadata.st_mode) == 0o550,
            "mutation_set_rollback_parent_rejected",
        )
        try:
            current.rmdir()
        except OSError:
            break
        _fsync_directory(current.parent)
        current = current.parent


def _stage_blob_name(operation: Mapping[str, object], phase: str) -> str:
    logical_digest = digest(
        "myuna-p07-staged-logical-path-v1",
        {
            "logical_path": operation["logical_path"],
            "root_id": operation["root_id"],
        },
    )
    return f"{phase}/{operation['order']:04d}-{logical_digest[:20]}.blob"


def _validate_payload(payload: bytes, state: Mapping[str, object], code: str) -> None:
    normalized = validate_state(state)
    require(
        normalized["exists"] is True
        and normalized["sha256"] == digest_bytes(payload)
        and normalized["size"] == len(payload),
        code,
    )


def stage_mutation_set(
    *,
    contract: Mapping[str, object],
    staging_root: Path,
    before_payloads: Mapping[str, bytes],
    after_payloads: Mapping[str, bytes],
) -> dict[str, object]:
    normalized = validate_mutation_set(contract)
    require(
        staging_root.is_absolute()
        and not staging_root.exists()
        and not staging_root.is_symlink(),
        "mutation_set_staging_root_rejected",
    )
    staging_posix = PurePosixPath(staging_root.as_posix())
    for root in normalized["roots"]:
        target = PurePosixPath(str(root["path"]))
        require(
            staging_posix != target
            and target not in staging_posix.parents
            and staging_posix not in target.parents,
            "mutation_set_staging_overlaps_target",
        )
    expected_before = {
        path_key(str(item["root_id"]), str(item["logical_path"]))
        for item in normalized["operations"]
        if item["before"]["exists"]
    }
    expected_after = {
        path_key(str(item["root_id"]), str(item["logical_path"]))
        for item in normalized["operations"]
        if item["after"]["exists"]
    }
    require(
        set(before_payloads) == expected_before
        and set(after_payloads) == expected_after,
        "mutation_set_staging_payload_set_rejected",
    )
    staging_root.mkdir(parents=True, mode=0o700)
    os.chmod(staging_root, 0o700)
    staged_files: list[dict[str, object]] = []
    try:
        for operation in normalized["operations"]:
            key = path_key(str(operation["root_id"]), str(operation["logical_path"]))
            for phase, payloads, state in (
                ("before", before_payloads, operation["before"]),
                ("after", after_payloads, operation["after"]),
            ):
                if not state["exists"]:
                    continue
                payload = payloads[key]
                _validate_payload(payload, state, "mutation_set_staging_payload_rejected")
                relative = _stage_blob_name(operation, phase)
                target = staging_root / relative
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.chmod(target.parent, 0o700)
                _atomic_write(
                    target,
                    payload,
                    mode=int(state["mode"]),
                    uid=os.getuid(),
                    gid=os.getgid(),
                )
                staged_files.append(
                    {
                        "logical_path": operation["logical_path"],
                        "mode": state["mode"],
                        "phase": phase,
                        "root_id": operation["root_id"],
                        "sha256": state["sha256"],
                        "size": state["size"],
                        "staged_path": relative,
                        "target_gid": state["gid"],
                        "target_uid": state["uid"],
                    }
                )
        semantic = {
            "content_class": CONTENT_CLASS,
            "files": staged_files,
            "mutation_set_id": normalized["mutation_set_id"],
            "schema": STAGING_SCHEMA,
            "target_inventory_digest": normalized["target_inventory_digest"],
            "transaction_id": normalized["transaction_id"],
        }
        manifest = {
            **semantic,
            "staging_digest": digest(
                "myuna-p07-filesystem-mutation-staging-v1", semantic
            ),
        }
        _atomic_write(
            staging_root / "manifest.json",
            canonical(manifest),
            mode=0o600,
            uid=os.getuid(),
            gid=os.getgid(),
        )
        _fsync_directory(staging_root)
        verify_staging(contract=normalized, staging_root=staging_root)
        return manifest
    except BaseException:
        raise


def verify_staging(
    *, contract: Mapping[str, object], staging_root: Path
) -> dict[str, object]:
    normalized = validate_mutation_set(contract)
    try:
        root_metadata = staging_root.lstat()
        manifest_bytes = (staging_root / "manifest.json").read_bytes()
        manifest = json.loads(
            manifest_bytes.decode("ascii"), object_pairs_hook=_strict_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MutationSetRejected("mutation_set_staging_manifest_rejected") from exc
    require(
        not stat.S_ISLNK(root_metadata.st_mode)
        and stat.S_ISDIR(root_metadata.st_mode)
        and stat.S_IMODE(root_metadata.st_mode) == 0o700
        and isinstance(manifest, dict),
        "mutation_set_staging_root_rejected",
    )
    required = {
        "content_class",
        "files",
        "mutation_set_id",
        "schema",
        "staging_digest",
        "target_inventory_digest",
        "transaction_id",
    }
    semantic = {key: manifest.get(key) for key in required - {"staging_digest"}}
    require(
        set(manifest) == required
        and manifest.get("schema") == STAGING_SCHEMA
        and manifest.get("content_class") == CONTENT_CLASS
        and manifest.get("mutation_set_id") == normalized["mutation_set_id"]
        and manifest.get("transaction_id") == normalized["transaction_id"]
        and manifest.get("target_inventory_digest")
        == normalized["target_inventory_digest"]
        and manifest.get("staging_digest")
        == digest("myuna-p07-filesystem-mutation-staging-v1", semantic)
        and canonical(manifest) == manifest_bytes,
        "mutation_set_staging_manifest_rejected",
    )
    files = manifest.get("files")
    require(isinstance(files, list), "mutation_set_staging_manifest_rejected")
    expected_names = {"manifest.json"}
    for item in files:
        require(
            isinstance(item, dict)
            and set(item)
            == {
                "logical_path",
                "mode",
                "phase",
                "root_id",
                "sha256",
                "size",
                "staged_path",
                "target_gid",
                "target_uid",
            }
            and item["phase"] in {"before", "after"}
            and isinstance(item["staged_path"], str),
            "mutation_set_staging_manifest_rejected",
        )
        path = staging_root / item["staged_path"]
        state = inspect_path(path)
        require(
            state["sha256"] == item["sha256"]
            and state["size"] == item["size"]
            and state["mode"] == item["mode"],
            "mutation_set_staging_readback_rejected",
        )
        expected_names.add(item["staged_path"])
    actual_names = {
        path.relative_to(staging_root).as_posix()
        for path in staging_root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    require(actual_names == expected_names, "mutation_set_staging_inventory_rejected")
    return manifest


def _staged_payload(
    staging_root: Path,
    manifest: Mapping[str, object],
    operation: Mapping[str, object],
    phase: str,
) -> bytes:
    matches = [
        item
        for item in manifest["files"]
        if item["root_id"] == operation["root_id"]
        and item["logical_path"] == operation["logical_path"]
        and item["phase"] == phase
    ]
    require(len(matches) == 1, "mutation_set_staging_payload_missing")
    return (staging_root / matches[0]["staged_path"]).read_bytes()


def _write_journal(path: Path, payload: Mapping[str, object]) -> None:
    require(
        path.is_absolute()
        and path.name.endswith(".json")
        and path.parent.is_dir()
        and not path.parent.is_symlink(),
        "mutation_set_journal_path_rejected",
    )
    _atomic_write(
        path,
        canonical(payload),
        mode=0o600,
        uid=os.getuid(),
        gid=os.getgid(),
    )


def _load_journal(path: Path, contract: Mapping[str, object]) -> dict[str, object]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("ascii"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MutationSetRejected("mutation_set_journal_rejected") from exc
    required = {
        "content_retained",
        "contract_id",
        "credential_value_read",
        "current_order",
        "events",
        "forward_completed_orders",
        "rollback_completed_orders",
        "rollback_failed",
        "rollback_started",
        "schema",
        "stage",
        "transaction_id",
    }
    normalized = validate_mutation_set(contract)
    require(
        isinstance(payload, dict)
        and set(payload) == required
        and payload.get("schema") == JOURNAL_SCHEMA
        and payload.get("contract_id") == normalized["mutation_set_id"]
        and payload.get("transaction_id") == normalized["transaction_id"]
        and payload.get("content_retained") is False
        and payload.get("credential_value_read") is False
        and isinstance(payload.get("events"), list)
        and isinstance(payload.get("forward_completed_orders"), list)
        and isinstance(payload.get("rollback_completed_orders"), list)
        and canonical(payload) == raw,
        "mutation_set_journal_rejected",
    )
    return payload


def _initial_journal(contract: Mapping[str, object]) -> dict[str, object]:
    normalized = validate_mutation_set(contract)
    return {
        "content_retained": False,
        "contract_id": normalized["mutation_set_id"],
        "credential_value_read": False,
        "current_order": None,
        "events": [],
        "forward_completed_orders": [],
        "rollback_completed_orders": [],
        "rollback_failed": False,
        "rollback_started": False,
        "schema": JOURNAL_SCHEMA,
        "stage": "prepared",
        "transaction_id": normalized["transaction_id"],
    }


def _event(
    *, operation: Mapping[str, object], phase: str, observed: Mapping[str, object]
) -> dict[str, object]:
    return {
        "atomic_rename_complete": True,
        "content_retained": False,
        "expected_state_digest": digest(
            "myuna-p07-path-state-v1",
            operation["after"] if phase == "forward" else operation["before"],
        ),
        "fsync_complete": True,
        "logical_path": operation["logical_path"],
        "observed_state_digest": digest("myuna-p07-path-state-v1", observed),
        "operation": operation["kind"],
        "order": operation["order"],
        "path_digest": digest(
            "myuna-p07-mutation-logical-path-v1",
            {
                "logical_path": operation["logical_path"],
                "root_id": operation["root_id"],
            },
        ),
        "phase": phase,
        "root_id": operation["root_id"],
    }


def _tombstone_path(
    contract: Mapping[str, object], operation: Mapping[str, object], root: Mapping[str, object]
) -> Path:
    return Path(str(root["path"])) / (
        f".p07-{validate_mutation_set(contract)['mutation_set_id'][:16]}-"
        f"{int(operation['order']):04d}.removed"
    )


def _apply_operation(
    *,
    contract: Mapping[str, object],
    operation: Mapping[str, object],
    root: Mapping[str, object],
    staging_root: Path,
    manifest: Mapping[str, object],
) -> dict[str, object]:
    target = _root_path(root, str(operation["logical_path"]))
    require(
        inspect_path(target) == operation["before"],
        "mutation_set_path_precondition_drifted",
    )
    if operation["kind"] == "remove":
        tombstone = _tombstone_path(contract, operation, root)
        require(
            not tombstone.exists() and not tombstone.is_symlink(),
            "mutation_set_remove_tombstone_preexisting",
        )
        os.replace(target, tombstone)
        _fsync_directory(target.parent)
    else:
        payload = _staged_payload(staging_root, manifest, operation, "after")
        after = operation["after"]
        _ensure_write_parents(
            root=root,
            target=target,
            uid=int(after["uid"]),
            gid=int(after["gid"]),
        )
        _atomic_write(
            target,
            payload,
            mode=int(after["mode"]),
            uid=int(after["uid"]),
            gid=int(after["gid"]),
        )
    observed = inspect_path(target)
    require(observed == operation["after"], "mutation_set_path_readback_mismatch")
    return observed


def _restore_operation(
    *,
    contract: Mapping[str, object],
    operation: Mapping[str, object],
    root: Mapping[str, object],
    staging_root: Path,
    manifest: Mapping[str, object],
) -> dict[str, object]:
    target = _root_path(root, str(operation["logical_path"]))
    current = inspect_path(target)
    if current != operation["before"]:
        require(
            current == operation["after"],
            "mutation_set_rollback_path_drifted",
        )
        if operation["before"]["exists"]:
            payload = _staged_payload(staging_root, manifest, operation, "before")
            before = operation["before"]
            _atomic_write(
                target,
                payload,
                mode=int(before["mode"]),
                uid=int(before["uid"]),
                gid=int(before["gid"]),
            )
        else:
            target.unlink()
            _fsync_directory(target.parent)
            _prune_empty_write_parents(
                root=root,
                target=target,
                uid=int(operation["after"]["uid"]),
                gid=int(operation["after"]["gid"]),
            )
    tombstone = _tombstone_path(contract, operation, root)
    if tombstone.exists() or tombstone.is_symlink():
        require(
            not tombstone.is_symlink(),
            "mutation_set_rollback_tombstone_rejected",
        )
        tombstone.unlink()
        _fsync_directory(tombstone.parent)
    observed = inspect_path(target)
    require(observed == operation["before"], "mutation_set_rollback_readback_mismatch")
    return observed


Checkpoint = Callable[[str, int | None], None]


def _rollback(
    *,
    contract: Mapping[str, object],
    staging_root: Path,
    journal_path: Path,
    checkpoint: Checkpoint | None = None,
) -> dict[str, object]:
    normalized = validate_mutation_set(contract)
    manifest = verify_staging(contract=normalized, staging_root=staging_root)
    journal = _load_journal(journal_path, normalized)
    require(not journal["rollback_failed"], "mutation_set_rollback_previous_failed")
    if not journal["rollback_started"]:
        journal["rollback_started"] = True
        journal["stage"] = "rollback"
        journal["current_order"] = None
        _write_journal(journal_path, journal)
        if checkpoint is not None:
            checkpoint("rollback_started", None)
    roots = roots_by_id(normalized)
    completed = set(journal["rollback_completed_orders"])
    try:
        for operation in reversed(normalized["operations"]):
            order = int(operation["order"])
            if order in completed:
                target = _root_path(roots[str(operation["root_id"])], str(operation["logical_path"]))
                require(
                    inspect_path(target) == operation["before"],
                    "mutation_set_rollback_replay_drifted",
                )
                continue
            journal["current_order"] = order
            _write_journal(journal_path, journal)
            if checkpoint is not None:
                checkpoint("before_rollback_operation", order)
            observed = _restore_operation(
                contract=normalized,
                operation=operation,
                root=roots[str(operation["root_id"])],
                staging_root=staging_root,
                manifest=manifest,
            )
            journal["events"].append(
                _event(operation=operation, phase="rollback", observed=observed)
            )
            journal["rollback_completed_orders"].append(order)
            journal["current_order"] = None
            _write_journal(journal_path, journal)
            if checkpoint is not None:
                checkpoint("after_rollback_operation", order)
        observed_inventory = scan_contract_roots(normalized)
        evidence = comparison_evidence(
            expected=normalized["prestate_inventory"],
            observed=observed_inventory,
            contract=normalized,
            phase="rollback_inventory",
        )
        require(evidence["status"] == "match", "mutation_set_rollback_inventory_mismatch")
        journal["events"].append(evidence)
        journal["stage"] = "rolled_back"
        journal["current_order"] = None
        _write_journal(journal_path, journal)
        if checkpoint is not None:
            checkpoint("rolled_back", None)
        return journal
    except Exception as exc:
        journal["rollback_failed"] = True
        journal["stage"] = "rollback_failed"
        journal["current_order"] = None
        _write_journal(journal_path, journal)
        code = typed_exception_code(exc, fallback="failed")
        raise MutationSetRejected(
            "mutation_set_rollback_failed", cause_code=code
        ) from exc


def execute_mutation_set(
    *,
    contract: Mapping[str, object],
    staging_root: Path,
    journal_path: Path,
    after_verified: Callable[[], None] | None = None,
    checkpoint: Checkpoint | None = None,
) -> dict[str, object]:
    normalized = validate_mutation_set(contract)
    manifest = verify_staging(contract=normalized, staging_root=staging_root)
    require(not journal_path.exists() and not journal_path.is_symlink(), "mutation_set_journal_preexisting")
    require_prestate(normalized)
    journal = _initial_journal(normalized)
    _write_journal(journal_path, journal)
    if checkpoint is not None:
        checkpoint("prepared", None)
    roots = roots_by_id(normalized)
    try:
        for operation in normalized["operations"]:
            order = int(operation["order"])
            journal["stage"] = "applying"
            journal["current_order"] = order
            _write_journal(journal_path, journal)
            if checkpoint is not None:
                checkpoint("before_forward_operation", order)
            observed = _apply_operation(
                contract=normalized,
                operation=operation,
                root=roots[str(operation["root_id"])],
                staging_root=staging_root,
                manifest=manifest,
            )
            journal["events"].append(
                _event(operation=operation, phase="forward", observed=observed)
            )
            journal["forward_completed_orders"].append(order)
            journal["current_order"] = None
            _write_journal(journal_path, journal)
            if checkpoint is not None:
                checkpoint("after_forward_operation", order)
        observed_inventory = scan_contract_roots(normalized)
        evidence = comparison_evidence(
            expected=normalized["target_inventory"],
            observed=observed_inventory,
            contract=normalized,
            phase="target_inventory",
        )
        require(evidence["status"] == "match", "mutation_set_target_inventory_mismatch")
        journal["events"].append(evidence)
        journal["stage"] = "target_verified"
        _write_journal(journal_path, journal)
        if checkpoint is not None:
            checkpoint("target_verified", None)
        if after_verified is not None:
            after_verified()
        for operation in normalized["operations"]:
            tombstone = _tombstone_path(
                normalized,
                operation,
                roots[str(operation["root_id"])],
            )
            if tombstone.exists() or tombstone.is_symlink():
                require(not tombstone.is_symlink(), "mutation_set_tombstone_rejected")
                tombstone.unlink()
                _fsync_directory(tombstone.parent)
        journal["stage"] = "complete"
        _write_journal(journal_path, journal)
        if checkpoint is not None:
            checkpoint("complete", None)
        return journal
    except Exception as exc:
        cause_code = typed_exception_code(exc, fallback="failed")
        _rollback(
            contract=normalized,
            staging_root=staging_root,
            journal_path=journal_path,
            checkpoint=checkpoint,
        )
        raise MutationSetRejected(
            "mutation_set_apply_failed_rolled_back",
            cause_code=cause_code,
        ) from exc


def recover_mutation_set(
    *,
    contract: Mapping[str, object],
    staging_root: Path,
    journal_path: Path,
    checkpoint: Checkpoint | None = None,
) -> str:
    normalized = validate_mutation_set(contract)
    verify_staging(contract=normalized, staging_root=staging_root)
    journal = _load_journal(journal_path, normalized)
    if journal["stage"] == "complete":
        evidence = comparison_evidence(
            expected=normalized["target_inventory"],
            observed=scan_contract_roots(normalized),
            contract=normalized,
            phase="recovery_complete",
        )
        require(evidence["status"] == "match", "mutation_set_completed_state_drifted")
        return "complete"
    if journal["stage"] == "rolled_back":
        evidence = comparison_evidence(
            expected=normalized["prestate_inventory"],
            observed=scan_contract_roots(normalized),
            contract=normalized,
            phase="recovery_rolled_back",
        )
        require(evidence["status"] == "match", "mutation_set_rolled_back_state_drifted")
        return "rolled_back"
    _rollback(
        contract=normalized,
        staging_root=staging_root,
        journal_path=journal_path,
        checkpoint=checkpoint,
    )
    return "rolled_back"


def rollback_mutation_set(
    *,
    contract: Mapping[str, object],
    staging_root: Path,
    journal_path: Path,
    checkpoint: Checkpoint | None = None,
) -> dict[str, object]:
    """Perform the transaction's single exact reverse transition.

    This public entry point is intentionally distinct from crash recovery.  A
    higher-level controller uses it when every filesystem byte reached the
    exact target but a later semantic, daemon-reload, service-start, or
    functional-acceptance stage failed.  It accepts only an exact target or an
    already-started rollback bound to the same mutation set.  Completed
    rollback, a prior rollback failure, and third-state drift remain terminal.
    """

    normalized = validate_mutation_set(contract)
    verify_staging(contract=normalized, staging_root=staging_root)
    journal = _load_journal(journal_path, normalized)
    require(
        journal["stage"] not in {"rolled_back", "rollback_failed"}
        and not journal["rollback_failed"],
        "mutation_set_rollback_state_rejected",
    )
    if not journal["rollback_started"]:
        observed = scan_contract_roots(normalized)
        require(
            observed == normalized["target_inventory"],
            "mutation_set_rollback_target_drifted",
        )
    return _rollback(
        contract=normalized,
        staging_root=staging_root,
        journal_path=journal_path,
        checkpoint=checkpoint,
    )


def journal_projection(path: Path, contract: Mapping[str, object]) -> dict[str, object]:
    journal = _load_journal(path, contract)
    return {
        "content_retained": False,
        "contract_id": journal["contract_id"],
        "credential_value_read": False,
        "event_count": len(journal["events"]),
        "forward_completed_count": len(journal["forward_completed_orders"]),
        "rollback_completed_count": len(journal["rollback_completed_orders"]),
        "rollback_failed": journal["rollback_failed"],
        "rollback_started": journal["rollback_started"],
        "schema": JOURNAL_SCHEMA,
        "stage": journal["stage"],
        "transaction_id": journal["transaction_id"],
    }
