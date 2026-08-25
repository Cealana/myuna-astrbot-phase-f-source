from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Callable

from p07_d_release_set import ProtectedReleaseSetSnapshot, require_same_release_set_snapshot
from p07_d_generation13_release_set import (
    CONTROLLER_OWNER_CHAIN,
    Generation13ReleaseSetRejected,
    controller_expected_authority,
    verify_controller_release_authority,
)


_TYPED_FAILURE_CODE = re.compile(r"^[a-z][a-z0-9_]{2,127}$")


class ReleaseSetActivationRejected(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        activation_failure_code: str | None = None,
        rollback_failure_code: str | None = None,
    ) -> None:
        if _TYPED_FAILURE_CODE.fullmatch(code) is None:
            raise ValueError("typed failure code rejected")
        for optional_code in (activation_failure_code, rollback_failure_code):
            if optional_code is not None and _TYPED_FAILURE_CODE.fullmatch(optional_code) is None:
                raise ValueError("typed failure code rejected")
        super().__init__(code)
        self.code = code
        self.activation_failure_code = activation_failure_code
        self.rollback_failure_code = rollback_failure_code


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ReleaseSetActivationRejected(code)


@dataclass(frozen=True, slots=True)
class ServiceObservation:
    unit: str
    active_state: str
    sub_state: str
    result: str
    nrestarts: int

    def __post_init__(self) -> None:
        _require(bool(self.unit), "service_observation_rejected")
        _require(self.active_state in {"active", "inactive", "failed"}, "service_observation_rejected")
        _require(bool(self.sub_state) and bool(self.result), "service_observation_rejected")
        _require(type(self.nrestarts) is int and self.nrestarts >= 0, "service_observation_rejected")


@dataclass(frozen=True, slots=True)
class FunctionalObservation:
    services: tuple[ServiceObservation, ...]
    service_binding_digests: tuple[tuple[str, str], ...]
    selected_release_set_id: str | None
    core_release_digest: str
    runtime_release_digest: str
    selector_digest: str
    runtime_config_digest: str
    credential_projection_digest: str
    epoch_identity_digest: str
    selected_failed_epoch: bool


@dataclass(frozen=True, slots=True)
class ActivationPrestate:
    state_digest: str
    desired_service_units: tuple[str, ...]
    rollback_release_set_id: str | None

    def __post_init__(self) -> None:
        _require(len(self.state_digest) == 64, "activation_prestate_rejected")
        _require(len(self.desired_service_units) == 3, "activation_prestate_rejected")
        _require(len(set(self.desired_service_units)) == 3, "activation_prestate_rejected")


@dataclass(frozen=True, slots=True)
class TargetPreflightObservation:
    core_file_count: int
    core_inventory_digest: str
    core_release_digest: str
    core_tree_digest: str
    runtime_file_count: int
    runtime_inventory_digest: str
    runtime_release_digest: str
    selector_digest: str
    selector_generation: int
    selector_schema: str
    runtime_config_path: str
    runtime_config_digest: str
    runtime_binding_digest: str
    credential_name: str
    credential_effective_count: int
    credential_effective_source: str
    credential_dropin_set_digest: str
    credential_projection_digest: str
    credential_source_category: str
    target_epoch_path: str
    target_epoch_exists: bool
    failed_epoch_selected: bool
    service_binding_digests: tuple[tuple[str, str], ...]


def verify_target_preflight(
    snapshot: ProtectedReleaseSetSnapshot,
    observed: TargetPreflightObservation,
) -> None:
    release_set = snapshot.release_set
    expected = TargetPreflightObservation(
        core_file_count=release_set.core["file_count"],
        core_inventory_digest=release_set.core["inventory_digest"],
        core_release_digest=release_set.core["release_digest"],
        core_tree_digest=release_set.core["tree_digest"],
        runtime_file_count=release_set.telegram_runtime["file_count"],
        runtime_inventory_digest=release_set.telegram_runtime["inventory_digest"],
        runtime_release_digest=release_set.telegram_runtime["release_digest"],
        selector_digest=release_set.selector["digest"],
        selector_generation=release_set.selector["generation"],
        selector_schema=release_set.selector["schema"],
        runtime_config_path=release_set.runtime_config["path"],
        runtime_config_digest=release_set.runtime_config["digest"],
        runtime_binding_digest=release_set.runtime_config["binding_digest"],
        credential_name=release_set.credential["name"],
        credential_effective_count=release_set.credential["effective_count"],
        credential_effective_source=release_set.credential["effective_source"],
        credential_dropin_set_digest=release_set.credential["dropin_set_digest"],
        credential_projection_digest=release_set.credential["projection_digest"],
        credential_source_category=release_set.credential["source_category"],
        target_epoch_path=release_set.epoch["database_path"],
        target_epoch_exists=False,
        failed_epoch_selected=False,
        service_binding_digests=tuple(
            sorted((item["unit"], item["binding_digest"]) for item in release_set.services)
        ),
    )
    _require(observed == expected, "target_preflight_release_set_mismatch")


def verify_stable_functional_target(
    snapshot: ProtectedReleaseSetSnapshot,
    first: FunctionalObservation,
    second: FunctionalObservation,
) -> None:
    release_set = snapshot.release_set
    _require(first == second, "target_functional_state_drifted")
    _require(first.selected_release_set_id == release_set.release_set_id, "target_release_set_not_selected")
    _require(first.core_release_digest == release_set.core["release_digest"], "target_core_release_mismatch")
    _require(first.runtime_release_digest == release_set.telegram_runtime["release_digest"], "target_runtime_release_mismatch")
    _require(first.selector_digest == release_set.selector["digest"], "target_selector_mismatch")
    _require(first.runtime_config_digest == release_set.runtime_config["digest"], "target_runtime_config_mismatch")
    _require(first.credential_projection_digest == release_set.credential["projection_digest"], "target_credential_mismatch")
    _require(first.epoch_identity_digest == release_set.epoch_identity_digest, "target_epoch_identity_mismatch")
    _require(not first.selected_failed_epoch, "target_failed_epoch_selected")
    expected_units = {item["unit"] for item in release_set.services}
    _require({item.unit for item in first.services} == expected_units, "target_service_set_mismatch")
    expected_bindings = tuple(
        sorted((item["unit"], item["binding_digest"]) for item in release_set.services)
    )
    _require(first.service_binding_digests == expected_bindings, "target_service_binding_mismatch")
    for service in first.services:
        _require(service.active_state == "active", "target_service_inactive")
        _require(service.result == "success", "target_service_result_rejected")
        _require(service.sub_state in {"running", "listening"}, "target_service_substate_rejected")


def verify_stable_functional_rollback(
    expected: FunctionalObservation,
    first: FunctionalObservation,
    second: FunctionalObservation,
) -> None:
    def functional_projection(
        observation: FunctionalObservation,
    ) -> tuple[object, ...]:
        services = tuple(
            (item.unit, item.active_state, item.sub_state, item.result)
            for item in observation.services
        )
        return (
            services,
            observation.service_binding_digests,
            observation.selected_release_set_id,
            observation.core_release_digest,
            observation.runtime_release_digest,
            observation.selector_digest,
            observation.runtime_config_digest,
            observation.credential_projection_digest,
            observation.epoch_identity_digest,
            observation.selected_failed_epoch,
        )

    def restart_counters(
        observation: FunctionalObservation,
    ) -> dict[str, int]:
        projected = {item.unit: item.nrestarts for item in observation.services}
        _require(
            len(projected) == len(observation.services),
            "rollback_service_set_rejected",
        )
        return projected

    _require(
        functional_projection(first) == functional_projection(expected),
        "rollback_functional_state_rejected",
    )
    _require(
        functional_projection(second) == functional_projection(first),
        "rollback_functional_state_drifted",
    )
    expected_restarts = restart_counters(expected)
    first_restarts = restart_counters(first)
    second_restarts = restart_counters(second)
    _require(
        expected_restarts.keys() == first_restarts.keys() == second_restarts.keys(),
        "rollback_service_set_rejected",
    )
    _require(
        all(first_restarts[unit] <= expected_restarts[unit] for unit in expected_restarts),
        "rollback_restart_counter_increased_from_prestate",
    )
    _require(
        all(second_restarts[unit] <= first_restarts[unit] for unit in first_restarts),
        "rollback_restart_counter_increased_during_observation",
    )
    _require(not first.selected_failed_epoch, "rollback_failed_epoch_selected")
    for service in second.services:
        _require(service.active_state == "active", "rollback_service_inactive")
        _require(service.result == "success", "rollback_service_result_rejected")
        _require(service.sub_state in {"running", "listening"}, "rollback_service_substate_rejected")


def _typed_exception_code(exc: Exception, *, fallback: str) -> str:
    candidate = getattr(exc, "code", None)
    if isinstance(candidate, str) and _TYPED_FAILURE_CODE.fullmatch(candidate) is not None:
        return candidate
    return fallback


@dataclass(frozen=True, slots=True)
class TransactionResult:
    status: str
    release_set_id: str
    journal: tuple[str, ...]


_S2_SOURCE = "7ff8f35a3e141674d7111a45dd247069d09d445a"
_S2_ATTEMPT = "A0003"
_S2_GEN0 = "J000000-GEN0.json"
_S2_SCHEMA = "myuna.phase-f-durable-journal.v1"
_S2_HEX = re.compile(r"^[0-9a-f]{64}$")
_S2_NAME = re.compile(r"^J(?P<seq>[0-9]{6})-(?P<kind>[A-Z][A-Z0-9_]*)\.json$")
_S2_KINDS = frozenset({
    "GEN0", "OP_INTENT", "OP_DISPATCHED", "OP_OBSERVED_OLD",
    "OP_OBSERVED_DESIRED", "OP_OBSERVED_AMBIGUOUS",
    "ROLLBACK_STARTED", "COMP_INTENT", "COMP_DISPATCHED",
    "COMP_OBSERVED_OLD", "COMP_OBSERVED_DESIRED", "COMP_OBSERVED_AMBIGUOUS",
    "FORWARD_STARTED", "FORWARD_INTENT", "FORWARD_DISPATCHED",
    "FORWARD_OBSERVED_OLD", "FORWARD_OBSERVED_DESIRED", "FORWARD_OBSERVED_AMBIGUOUS",
    "WRITER_INTENT", "WRITER_DISPATCHED", "WRITER_RETURNED",
    "TERMINAL_OLD", "TERMINAL_TARGET", "TERMINAL_AMBIGUOUS",
})
_S2_OBSERVATIONS = frozenset({"OLD", "DESIRED", "ALTERNATE", "UNKNOWN", "IN_FLIGHT", "ABA", "THIRD_STATE"})
_S2_PROGRAM = (
    ("O01_STOP_RUNTIME_SERVICE", "IDEMPOTENT"),
    ("O02_STOP_RUNTIME_SOCKET", "IDEMPOTENT"),
    ("O03_STOP_CORE_SERVICE", "IDEMPOTENT"),
    ("O04_STOP_OLD_CONTAINER", "IDEMPOTENT"),
    ("O05_ARCHIVE_OLD_CONTAINER", "EXACT_PRESTATE_ONCE"),
    ("O06_PUBLISH_RELEASE_SET", "EXACT_PRESTATE_ONCE"),
    ("O07_PUBLISH_EPOCH_SELECTOR", "EXACT_PRESTATE_ONCE"),
    ("O08_PUBLISH_CORE_BINDING", "EXACT_PRESTATE_ONCE"),
    ("O09_PUBLISH_CORE_SELECTOR", "EXACT_PRESTATE_ONCE"),
    ("O10_PUBLISH_CORE_GATE", "EXACT_PRESTATE_ONCE"),
    ("O11_PUBLISH_RUNTIME_DROPIN", "EXACT_PRESTATE_ONCE"),
    ("O12_DAEMON_RELOAD", "IDEMPOTENT"),
    ("O13_START_CORE_SERVICE", "IDEMPOTENT"),
    ("O14_START_RUNTIME_SOCKET", "IDEMPOTENT"),
    ("O15_START_RUNTIME_SERVICE", "IDEMPOTENT"),
    ("O16_CREATE_TARGET_STOPPED", "EXACT_PRESTATE_ONCE"),
    ("O17_SET_TARGET_RESTART_POLICY", "IDEMPOTENT"),
    ("O18_START_TARGET_CONTAINER", "IDEMPOTENT"),
)
_S2_REVERSE = (
    "O18_START_TARGET_CONTAINER", "O17_SET_TARGET_RESTART_POLICY",
    "O16_CREATE_TARGET_STOPPED", "O05_ARCHIVE_OLD_CONTAINER",
    "O11_PUBLISH_RUNTIME_DROPIN", "O10_PUBLISH_CORE_GATE",
    "O09_PUBLISH_CORE_SELECTOR", "O08_PUBLISH_CORE_BINDING",
    "O07_PUBLISH_EPOCH_SELECTOR", "O06_PUBLISH_RELEASE_SET",
    "O12_DAEMON_RELOAD", "O15_START_RUNTIME_SERVICE",
    "O14_START_RUNTIME_SOCKET", "O13_START_CORE_SERVICE",
    "O03_STOP_CORE_SERVICE", "O02_STOP_RUNTIME_SOCKET", "O01_STOP_RUNTIME_SERVICE",
    "O04_STOP_OLD_CONTAINER",
)
_S3_FORWARD_OLD = (
    "F01_STOP_TARGET_CONTAINER", "F02_REMOVE_TARGET_CONTAINER",
    "F03_RESTORE_OLD_CONTAINER_NAME", "F04_RESTORE_RELEASE_SET",
    "F05_RESTORE_EPOCH_SELECTOR", "F06_RESTORE_CORE_BINDING",
    "F07_RESTORE_CORE_SELECTOR", "F08_RESTORE_CORE_GATE",
    "F09_RESTORE_RUNTIME_DROPIN", "F10_DAEMON_RELOAD_OLD",
    "F11_RESTORE_OLD_CORE_SERVICE", "F12_RESTORE_OLD_RUNTIME_SOCKET",
    "F13_RESTORE_OLD_RUNTIME_SERVICE", "F14_VERIFY_OLD_RESTART_POLICY",
    "F15_RESTORE_OLD_RUNNING_STATE", "F16_ORDINARY_STARTUP_RECOVER",
    "F17_READINESS_OBSERVATION_ONE", "F18_READINESS_OBSERVATION_TWO",
    "F19_INGRESS_OBSERVATION_ONE", "F20_INGRESS_OBSERVATION_TWO",
    "F21_FULL_OLD_OBSERVATION_ONE", "F22_FULL_OLD_OBSERVATION_TWO",
)
_S2_OPERATION_IDS = frozenset(item[0] for item in _S2_PROGRAM)
_S3_FORWARD_IDS = frozenset(_S3_FORWARD_OLD)


class _DuplicateJsonKey(ValueError):
    pass


def _s2_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJsonKey(key)
        value[key] = item
    return value


def _s2_bytes(value: object) -> bytes:
    try:
        return json.dumps(value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
    except (TypeError, ValueError) as exc:
        raise ReleaseSetActivationRejected("journal_noncanonical") from exc


def _s2_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _s2_program_body() -> list[dict[str, object]]:
    return [
        {
            "compensator_id": operation_id,
            "index": index,
            "operation_id": operation_id,
            "retry_class": retry,
            "writer_side": "PRE_WRITER",
        }
        for index, (operation_id, retry) in enumerate(_S2_PROGRAM, 1)
    ]


def _s2_plan_id() -> str:
    body = {"attempt": 3, "program": _s2_program_body(), "source_commit": _S2_SOURCE}
    return _s2_digest(b"myuna.phase-f.stage2.plan.v1\0" + _s2_bytes(body))


def _s2_record(kind: str, sequence: int, predecessor: str | None, operation_id: str | None = None, observation: str | None = None) -> dict[str, object]:
    value: dict[str, object] = {
        "attempt": 3, "kind": kind, "operation_id": operation_id,
        "plan_id": _s2_plan_id(), "predecessor_sha256": predecessor,
        "schema": _S2_SCHEMA, "sequence": sequence,
        "source_commit": _S2_SOURCE, "stage_observation": observation,
    }
    if kind == "GEN0":
        value["program"] = _s2_program_body()
    return value


def _s2_string(value: object, choices: frozenset[str] | None = None) -> str:
    _require(type(value) is str and bool(value), "journal_type_rejected")
    assert isinstance(value, str)
    if choices is not None:
        _require(value in choices, "journal_value_rejected")
    return value


def _s2_int(value: object) -> int:
    _require(type(value) is int and value >= 0, "journal_type_rejected")
    assert isinstance(value, int) and not isinstance(value, bool)
    return value


def _s2_parse(data: bytes) -> dict[str, object]:
    _require(len(data) <= 65536 and data.endswith(b"\n") and not data.endswith(b"\n\n"), "journal_noncanonical")
    _require(b"\r" not in data and b"\x00" not in data, "journal_noncanonical")
    try:
        value = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=_s2_object)
    except (_DuplicateJsonKey, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseSetActivationRejected("journal_parse_rejected") from exc
    _require(type(value) is dict and _s2_bytes(value) == data, "journal_noncanonical")
    assert isinstance(value, dict)
    kind = _s2_string(value.get("kind"), _S2_KINDS)
    _require(
        kind != "TERMINAL_TARGET",
        "phase_f_t2_terminal_not_implemented",
    )
    keys = {"attempt", "kind", "operation_id", "plan_id", "predecessor_sha256", "schema", "sequence", "source_commit", "stage_observation"}
    if kind == "GEN0":
        keys.add("program")
    _require(set(value) == keys, "journal_schema_rejected")
    _require(_s2_int(value["attempt"]) == 3, "journal_attempt_rejected")
    sequence = _s2_int(value["sequence"])
    _require(value["schema"] == _S2_SCHEMA and value["source_commit"] == _S2_SOURCE, "journal_source_rejected")
    plan_id = _s2_string(value["plan_id"])
    _require(_S2_HEX.fullmatch(plan_id) is not None and plan_id == _s2_plan_id(), "journal_plan_rejected")
    if kind == "GEN0":
        _require(sequence == 0 and value["predecessor_sha256"] is None, "journal_predecessor_rejected")
        _require(value["operation_id"] is None and value["stage_observation"] is None, "journal_schema_rejected")
        _require(value["program"] == _s2_program_body(), "journal_program_rejected")
    else:
        _require(sequence > 0, "journal_sequence_rejected")
        predecessor = _s2_string(value["predecessor_sha256"])
        _require(_S2_HEX.fullmatch(predecessor) is not None, "journal_predecessor_rejected")
        if kind.startswith("OP_"):
            operation = _s2_string(value["operation_id"])
            _require(operation in _S2_OPERATION_IDS, "journal_operation_rejected")
        elif kind.startswith("COMP_"):
            operation = _s2_string(value["operation_id"])
            _require(operation in _S2_OPERATION_IDS, "journal_operation_rejected")
        elif kind.startswith("FORWARD_") and kind != "FORWARD_STARTED":
            operation = _s2_string(value["operation_id"])
            _require(operation in _S3_FORWARD_IDS, "journal_operation_rejected")
        else:
            operation = None
            _require(value["operation_id"] is None, "journal_schema_rejected")
        if kind.startswith(("OP_OBSERVED_", "COMP_OBSERVED_", "FORWARD_OBSERVED_")):
            _s2_string(value["stage_observation"], frozenset({kind.rsplit("_", 1)[1]}))
        else:
            _require(value["stage_observation"] is None, "journal_schema_rejected")
    return value


def _s2_filename(sequence: int, kind: str) -> str:
    return _S2_GEN0 if sequence == 0 else f"J{sequence:06d}-{kind}.json"


def _s2_parent(path: Path) -> int:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise ReleaseSetActivationRejected("journal_parent_rejected") from exc
    metadata = os.fstat(descriptor)
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        os.close(descriptor)
        raise ReleaseSetActivationRejected("journal_parent_identity_rejected")
    return descriptor


def _s2_named_identity(directory: int, name: str, metadata: os.stat_result, *, regular: bool) -> None:
    try:
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except OSError as exc:
        raise ReleaseSetActivationRejected("journal_name_identity_rejected") from exc
    _require((named.st_dev, named.st_ino) == (metadata.st_dev, metadata.st_ino), "journal_name_identity_rejected")
    if regular:
        _require(named.st_nlink == metadata.st_nlink == 1, "journal_member_link_rejected")


def _s2_attempt(parent: int) -> int:
    try:
        descriptor = os.open(_S2_ATTEMPT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
    except OSError as exc:
        raise ReleaseSetActivationRejected("journal_attempt_rejected") from exc
    metadata = os.fstat(descriptor)
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        os.close(descriptor)
        raise ReleaseSetActivationRejected("journal_attempt_identity_rejected")
    _s2_named_identity(parent, _S2_ATTEMPT, metadata, regular=False)
    return descriptor


def _s2_read(directory: int, name: str) -> bytes:
    _require("/" not in name and name not in {".", ".."}, "journal_name_rejected")
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
    except OSError as exc:
        raise ReleaseSetActivationRejected("journal_member_rejected") from exc
    try:
        metadata = os.fstat(descriptor)
        _require(stat.S_ISREG(metadata.st_mode), "journal_member_type_rejected")
        _require(metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o600, "journal_member_identity_rejected")
        _s2_named_identity(directory, name, metadata, regular=True)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 16384)
            if not chunk:
                break
            chunks.append(chunk)
            _require(sum(map(len, chunks)) <= 65536, "journal_size_rejected")
        data = b"".join(chunks)
        _s2_named_identity(directory, name, metadata, regular=True)
        return data
    finally:
        os.close(descriptor)


def _s2_write(directory: int, entry: dict[str, object]) -> bytes:
    data = _s2_bytes(entry)
    _s2_parse(data)
    name = _s2_filename(int(entry["sequence"]), str(entry["kind"]))
    try:
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    except FileExistsError as exc:
        raise ReleaseSetActivationRejected("journal_collision_ambiguous") from exc
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory)
    _require(_s2_read(directory, name) == data, "journal_reopen_rejected")
    return data


def _s2_index(operation_id: str) -> int:
    for index, (candidate, _retry) in enumerate(_S2_PROGRAM):
        if candidate == operation_id:
            return index
    raise ReleaseSetActivationRejected("journal_operation_rejected")


def _s2_validate_transitions(entries: list[dict[str, object]]) -> None:
    _require(bool(entries) and entries[0]["kind"] == "GEN0", "journal_gen0_rejected")
    activation_index = 0
    completed: list[str] = []
    expected = "OP_INTENT"
    mode = "ACTIVATION"
    rollback_program: tuple[str, ...] = ()
    rollback_index = 0
    forward_index = 0
    for entry in entries[1:]:
        kind, operation = str(entry["kind"]), entry["operation_id"]
        _require(expected != "CLOSED", "journal_transition_rejected")
        if expected == "TERMINAL_AMBIGUOUS":
            _require(kind == "TERMINAL_AMBIGUOUS", "journal_transition_rejected")
            expected = "CLOSED"
            continue
        if mode == "ACTIVATION" and kind == "ROLLBACK_STARTED":
            _require(expected in {"OP_INTENT", "OP_DISPATCHED", "WRITER_INTENT", "WRITER_DISPATCHED"} and bool(completed), "journal_rollback_start_rejected")
            rollback_program = tuple(item for item in _S2_REVERSE if item in completed)
            rollback_index = 0
            mode, expected = "ROLLBACK", "COMP_INTENT"
            continue
        if mode == "ACTIVATION" and kind == "FORWARD_STARTED":
            _require(expected in {"WRITER_RETURNED_OR_FORWARD", "POST_WRITER"}, "journal_forward_start_rejected")
            mode, expected = "FORWARD", "FORWARD_INTENT"
            continue
        if mode == "ACTIVATION":
            if activation_index < len(_S2_PROGRAM):
                _require(operation == _S2_PROGRAM[activation_index][0], "journal_operation_order_rejected")
                _require(kind == expected or (expected == "OP_OBSERVE" and kind.startswith("OP_OBSERVED_")), "journal_transition_rejected")
                if kind == "OP_INTENT":
                    expected = "OP_DISPATCHED"
                elif kind == "OP_DISPATCHED":
                    expected = "OP_OBSERVE"
                elif kind == "OP_OBSERVED_DESIRED":
                    completed.append(str(operation))
                    activation_index += 1
                    expected = "OP_INTENT" if activation_index < len(_S2_PROGRAM) else "WRITER_INTENT"
                else:
                    expected = "TERMINAL_AMBIGUOUS"
                continue
            if expected == "WRITER_INTENT":
                _require(kind == "WRITER_INTENT", "journal_transition_rejected")
                expected = "WRITER_DISPATCHED"
            elif expected == "WRITER_DISPATCHED":
                _require(kind == "WRITER_DISPATCHED", "journal_transition_rejected")
                expected = "WRITER_RETURNED_OR_FORWARD"
            elif expected == "WRITER_RETURNED_OR_FORWARD":
                _require(kind == "WRITER_RETURNED", "journal_transition_rejected")
                expected = "POST_WRITER"
            elif expected == "POST_WRITER":
                _require(kind == "TERMINAL_TARGET", "journal_transition_rejected")
                expected = "CLOSED"
            else:
                _require(False, "journal_transition_rejected")
            continue
        if mode == "ROLLBACK":
            if rollback_index == len(rollback_program):
                _require(kind == "TERMINAL_OLD", "journal_transition_rejected")
                expected = "CLOSED"
                continue
            _require(operation == rollback_program[rollback_index], "journal_compensation_order_rejected")
            _require(kind == expected or (expected == "COMP_OBSERVE" and kind.startswith("COMP_OBSERVED_")), "journal_transition_rejected")
            if kind == "COMP_INTENT":
                expected = "COMP_DISPATCHED"
            elif kind == "COMP_DISPATCHED":
                expected = "COMP_OBSERVE"
            elif kind == "COMP_OBSERVED_OLD":
                rollback_index += 1
                expected = "COMP_INTENT" if rollback_index < len(rollback_program) else "TERMINAL_OLD"
            else:
                expected = "TERMINAL_AMBIGUOUS"
            continue
        if mode == "FORWARD":
            if forward_index == len(_S3_FORWARD_OLD):
                _require(kind == "TERMINAL_OLD", "journal_transition_rejected")
                expected = "CLOSED"
                continue
            _require(operation == _S3_FORWARD_OLD[forward_index], "journal_forward_order_rejected")
            _require(kind == expected or (expected == "FORWARD_OBSERVE" and kind.startswith("FORWARD_OBSERVED_")), "journal_transition_rejected")
            if kind == "FORWARD_INTENT":
                expected = "FORWARD_DISPATCHED"
            elif kind == "FORWARD_DISPATCHED":
                expected = "FORWARD_OBSERVE"
            elif kind == "FORWARD_OBSERVED_DESIRED":
                forward_index += 1
                expected = "FORWARD_INTENT" if forward_index < len(_S3_FORWARD_OLD) else "TERMINAL_OLD"
            else:
                expected = "TERMINAL_AMBIGUOUS"
            continue
        _require(False, "journal_transition_rejected")


def _s2_chain(directory: int) -> list[tuple[dict[str, object], bytes]]:
    names = sorted(os.listdir(directory))
    _require(bool(names), "journal_gen0_missing")
    chain: list[tuple[dict[str, object], bytes]] = []
    predecessor: str | None = None
    for sequence, name in enumerate(names):
        matched = _S2_NAME.fullmatch(name)
        _require(matched is not None and int(matched.group("seq")) == sequence, "journal_gap_rejected")
        data = _s2_read(directory, name)
        entry = _s2_parse(data)
        _require(entry["sequence"] == sequence and entry["kind"] == matched.group("kind"), "journal_name_rejected")
        _require(name == _s2_filename(sequence, str(entry["kind"])), "journal_name_rejected")
        if sequence: _require(entry["predecessor_sha256"] == predecessor, "journal_predecessor_rejected")
        else: _require(name == _S2_GEN0, "journal_gen0_name_rejected")
        predecessor = _s2_digest(data)
        chain.append((entry, data))
    _s2_validate_transitions([entry for entry, _data in chain])
    return chain


def _s2_initialize(parent_path: Path) -> bool:
    parent = _s2_parent(parent_path)
    try:
        fcntl.flock(parent, fcntl.LOCK_EX)
        try:
            os.mkdir(_S2_ATTEMPT, mode=0o700, dir_fd=parent); os.fsync(parent); created = True
        except FileExistsError:
            created = False
        attempt = _s2_attempt(parent)
        try:
            if created:
                _s2_write(attempt, _s2_record("GEN0", 0, None)); return True
            chain = _s2_chain(attempt)
            _require(chain[0][1] == _s2_bytes(_s2_record("GEN0", 0, None)), "journal_gen0_collision_ambiguous")
            return False
        finally: os.close(attempt)
    finally:
        fcntl.flock(parent, fcntl.LOCK_UN); os.close(parent)


def _s2_recover_once(parent_path: Path, *, observe: Callable[[str], str], apply: Callable[[str], None], invoke_writer: Callable[[], None]) -> str:
    parent = _s2_parent(parent_path)
    try:
        fcntl.flock(parent, fcntl.LOCK_EX)
        attempt = _s2_attempt(parent)
        try:
            chain = _s2_chain(attempt); last, last_bytes = chain[-1]; sequence = len(chain); predecessor = _s2_digest(last_bytes); kind = str(last["kind"])
            def publish(entry_kind: str, operation: str | None = None, observation: str | None = None) -> bytes:
                return _s2_write(attempt, _s2_record(entry_kind, sequence, predecessor, operation, observation))
            if kind in {"TERMINAL_AMBIGUOUS", "TERMINAL_OLD", "TERMINAL_TARGET"}:
                return str(kind)
            if kind.startswith("COMP_") or kind == "ROLLBACK_STARTED":
                return "PRE_WRITER_ROLLBACK_IN_PROGRESS"
            if kind.startswith("FORWARD_") or kind == "FORWARD_STARTED":
                return "POST_WRITER_FORWARD_IN_PROGRESS"
            if kind in {"WRITER_DISPATCHED", "WRITER_RETURNED"}: return "POST_WRITER_RECOVERY_REQUIRED"
            if kind in {"GEN0", "OP_OBSERVED_DESIRED"}:
                index = 0 if kind == "GEN0" else _s2_index(str(last["operation_id"])) + 1
                if index == len(_S2_PROGRAM): publish("WRITER_INTENT"); return "WRITER_INTENT_DURABLE"
                publish("OP_INTENT", _S2_PROGRAM[index][0]); return "INTENT_DURABLE"
            if kind == "OP_INTENT":
                publish("OP_DISPATCHED", str(last["operation_id"])); return "DISPATCHED_DURABLE_NO_CALL"
            if kind == "OP_DISPATCHED":
                operation = str(last["operation_id"]); observed = _s2_string(observe(operation), _S2_OBSERVATIONS)
                if observed == "DESIRED": result = "OP_OBSERVED_DESIRED"
                elif observed == "OLD" and _S2_PROGRAM[_s2_index(operation)][1] in {
                    "IDEMPOTENT",
                    "EXACT_PRESTATE_ONCE",
                }:
                    try: apply(operation)
                    except Exception: return "LOST_RETURN_REOBSERVE_REQUIRED"
                    after = _s2_string(observe(operation), _S2_OBSERVATIONS)
                    result = "OP_OBSERVED_DESIRED" if after == "DESIRED" else ("OP_OBSERVED_OLD" if after == "OLD" else "OP_OBSERVED_AMBIGUOUS")
                else: result = "OP_OBSERVED_AMBIGUOUS"
                observed_bytes = publish(result, operation, result.removeprefix("OP_OBSERVED_"))
                if result != "OP_OBSERVED_DESIRED":
                    _s2_write(attempt, _s2_record("TERMINAL_AMBIGUOUS", sequence + 1, _s2_digest(observed_bytes)))
                    return "AMBIGUOUS_ADMISSION_CLOSED"
                return "DESIRED_DURABLE"
            if kind == "WRITER_INTENT":
                dispatched = publish("WRITER_DISPATCHED")
                try: invoke_writer()
                except Exception: return "WRITER_LOST_RETURN_POST_BOUNDARY"
                _s2_write(attempt, _s2_record("WRITER_RETURNED", sequence + 1, _s2_digest(dispatched)))
                return "WRITER_RETURNED_POST_BOUNDARY"
            raise ReleaseSetActivationRejected("journal_transition_rejected")
        finally: os.close(attempt)
    finally:
        fcntl.flock(parent, fcntl.LOCK_UN); os.close(parent)


def _s3_completed_activation(chain: list[tuple[dict[str, object], bytes]]) -> tuple[str, ...]:
    completed = tuple(
        str(entry["operation_id"])
        for entry, _data in chain
        if entry["kind"] == "OP_OBSERVED_DESIRED"
    )
    _require(completed == tuple(item[0] for item in _S2_PROGRAM[: len(completed)]), "journal_completed_prefix_rejected")
    return completed


def _s3_rollback_once(parent_path: Path, *, backend) -> str:
    parent = _s2_parent(parent_path)
    try:
        fcntl.flock(parent, fcntl.LOCK_EX)
        attempt = _s2_attempt(parent)
        try:
            chain = _s2_chain(attempt)
            _require(not any(entry["kind"] == "WRITER_DISPATCHED" for entry, _data in chain), "post_writer_rollback_forbidden")
            last, last_bytes = chain[-1]
            kind = str(last["kind"])
            sequence = len(chain)
            predecessor = _s2_digest(last_bytes)

            def publish(entry_kind: str, operation: str | None = None, observation: str | None = None) -> bytes:
                return _s2_write(attempt, _s2_record(entry_kind, sequence, predecessor, operation, observation))

            if kind in {"TERMINAL_OLD", "TERMINAL_AMBIGUOUS"}:
                return kind
            completed = _s3_completed_activation(chain)
            _require(bool(completed), "rollback_no_mutation")
            rollback_program = tuple(item for item in _S2_REVERSE if item in completed)
            if not any(entry["kind"] == "ROLLBACK_STARTED" for entry, _data in chain):
                _require(kind in {"OP_INTENT", "OP_OBSERVED_DESIRED", "WRITER_INTENT"}, "rollback_inflight_ambiguous")
                publish("ROLLBACK_STARTED")
                return "ROLLBACK_STARTED_DURABLE"
            compensated = tuple(
                str(entry["operation_id"])
                for entry, _data in chain
                if entry["kind"] == "COMP_OBSERVED_OLD"
            )
            _require(compensated == rollback_program[: len(compensated)], "journal_compensation_order_rejected")
            if kind in {"ROLLBACK_STARTED", "COMP_OBSERVED_OLD"}:
                if len(compensated) == len(rollback_program):
                    first = backend.observe_full_old()
                    second = backend.observe_full_old()
                    if first != "OLD" or second != "OLD":
                        ambiguous = publish("TERMINAL_AMBIGUOUS")
                        _require(bool(ambiguous), "journal_write_rejected")
                        return "AMBIGUOUS_ADMISSION_CLOSED"
                    publish("TERMINAL_OLD")
                    return "TERMINAL_OLD"
                publish("COMP_INTENT", rollback_program[len(compensated)])
                return "COMP_INTENT_DURABLE"
            operation = str(last["operation_id"])
            if kind == "COMP_INTENT":
                publish("COMP_DISPATCHED", operation)
                return "COMP_DISPATCHED_DURABLE_NO_CALL"
            if kind == "COMP_DISPATCHED":
                observed = _s2_string(backend.observe_compensation(operation), _S2_OBSERVATIONS)
                if observed == "OLD":
                    publish("COMP_OBSERVED_OLD", operation, "OLD")
                    return "COMPENSATED_OLD_DURABLE"
                if observed == "DESIRED":
                    try:
                        backend.compensate_operation(operation)
                    except Exception:
                        return "COMPENSATION_LOST_RETURN_REOBSERVE_REQUIRED"
                    after = _s2_string(backend.observe_compensation(operation), _S2_OBSERVATIONS)
                    if after == "OLD":
                        publish("COMP_OBSERVED_OLD", operation, "OLD")
                        return "COMPENSATED_OLD_DURABLE"
                ambiguous = publish("COMP_OBSERVED_AMBIGUOUS", operation, "AMBIGUOUS")
                _s2_write(attempt, _s2_record("TERMINAL_AMBIGUOUS", sequence + 1, _s2_digest(ambiguous)))
                return "AMBIGUOUS_ADMISSION_CLOSED"
            raise ReleaseSetActivationRejected("journal_compensation_transition_rejected")
        finally:
            os.close(attempt)
    finally:
        fcntl.flock(parent, fcntl.LOCK_UN)
        os.close(parent)


def _s3_forward_old_once(parent_path: Path, *, backend) -> str:
    parent = _s2_parent(parent_path)
    try:
        fcntl.flock(parent, fcntl.LOCK_EX)
        attempt = _s2_attempt(parent)
        try:
            chain = _s2_chain(attempt)
            _require(any(entry["kind"] == "WRITER_DISPATCHED" for entry, _data in chain), "forward_before_writer_rejected")
            last, last_bytes = chain[-1]
            kind = str(last["kind"])
            sequence = len(chain)
            predecessor = _s2_digest(last_bytes)

            def publish(entry_kind: str, operation: str | None = None, observation: str | None = None) -> bytes:
                return _s2_write(attempt, _s2_record(entry_kind, sequence, predecessor, operation, observation))

            if kind in {"TERMINAL_OLD", "TERMINAL_AMBIGUOUS"}:
                return kind
            if not any(entry["kind"] == "FORWARD_STARTED" for entry, _data in chain):
                _require(kind in {"WRITER_DISPATCHED", "WRITER_RETURNED"}, "forward_start_rejected")
                publish("FORWARD_STARTED")
                return "FORWARD_STARTED_DURABLE"
            completed = tuple(
                str(entry["operation_id"])
                for entry, _data in chain
                if entry["kind"] == "FORWARD_OBSERVED_DESIRED"
            )
            _require(completed == _S3_FORWARD_OLD[: len(completed)], "journal_forward_order_rejected")
            if kind in {"FORWARD_STARTED", "FORWARD_OBSERVED_DESIRED"}:
                if len(completed) == len(_S3_FORWARD_OLD):
                    publish("TERMINAL_OLD")
                    return "TERMINAL_OLD"
                publish("FORWARD_INTENT", _S3_FORWARD_OLD[len(completed)])
                return "FORWARD_INTENT_DURABLE"
            operation = str(last["operation_id"])
            if kind == "FORWARD_INTENT":
                publish("FORWARD_DISPATCHED", operation)
                return "FORWARD_DISPATCHED_DURABLE_NO_CALL"
            if kind == "FORWARD_DISPATCHED":
                observed = _s2_string(backend.observe_forward_old(operation), _S2_OBSERVATIONS)
                if observed == "DESIRED":
                    publish("FORWARD_OBSERVED_DESIRED", operation, "DESIRED")
                    return "FORWARD_DESIRED_DURABLE"
                if observed == "OLD":
                    try:
                        backend.apply_forward_old(operation)
                    except Exception:
                        return "FORWARD_LOST_RETURN_REOBSERVE_REQUIRED"
                    after = _s2_string(backend.observe_forward_old(operation), _S2_OBSERVATIONS)
                    if after == "DESIRED":
                        publish("FORWARD_OBSERVED_DESIRED", operation, "DESIRED")
                        return "FORWARD_DESIRED_DURABLE"
                ambiguous = publish("FORWARD_OBSERVED_AMBIGUOUS", operation, "AMBIGUOUS")
                _s2_write(attempt, _s2_record("TERMINAL_AMBIGUOUS", sequence + 1, _s2_digest(ambiguous)))
                return "AMBIGUOUS_ADMISSION_CLOSED"
            raise ReleaseSetActivationRejected("journal_forward_transition_rejected")
        finally:
            os.close(attempt)
    finally:
        fcntl.flock(parent, fcntl.LOCK_UN)
        os.close(parent)


def _s2_recovery_side(parent_path: Path) -> str:
    parent = _s2_parent(parent_path)
    try:
        fcntl.flock(parent, fcntl.LOCK_SH); attempt = _s2_attempt(parent)
        try:
            chain = _s2_chain(attempt)
            return "POST_WRITER_FORWARD_ONLY" if any(entry["kind"] == "WRITER_DISPATCHED" for entry, _data in chain) else "PRE_WRITER_ROLLBACK_ALLOWED"
        finally: os.close(attempt)
    finally:
        fcntl.flock(parent, fcntl.LOCK_UN); os.close(parent)



class AtomicReleaseSetTransaction:
    """All-or-functional-rollback coordinator; the backend owns privileged effects."""

    def __init__(self, backend: object) -> None:
        self.backend = backend

    @classmethod
    def enter_canonical_owner(
        cls,
        *,
        release_root: Path | None = None,
        selected_release_sha256: str | None = None,
        selected_config_sha256: str | None = None,
        selected_authority_sha256: str | None = None,
        t2_receipts: tuple[dict[str, object], dict[str, object]] | None = None,
    ) -> None:
        """Validate the sole sealed-artifact/T2 admission boundary without effects.

        T1 deliberately has no T2 collector implementation.  The installed
        controller can therefore establish TARGET_ARTIFACT_VERIFIED, but no
        caller value can create GEN0 or dispatch an operation.
        """

        _require(isinstance(release_root, Path), "phase_f_target_artifact_required")
        assert isinstance(release_root, Path)
        try:
            expected_authority = controller_expected_authority(
                release_digest=selected_release_sha256,
                controller_config_sha256=selected_config_sha256,
                static_authority_sha256=selected_authority_sha256,
                t2_receipts=t2_receipts,
            )
            target_artifact = verify_controller_release_authority(
                release_root,
                expected_authority,
            )
        except (Generation13ReleaseSetRejected, OSError) as exc:
            raise ReleaseSetActivationRejected(
                "phase_f_target_artifact_not_verified"
            ) from exc
        _require(
            tuple(target_artifact["owner_chain"]) == CONTROLLER_OWNER_CHAIN,
            "phase_f_owner_chain_rejected",
        )
        if t2_receipts is None:
            raise ReleaseSetActivationRejected("phase_f_t2_pair_required")
        _require(type(t2_receipts) is tuple and len(t2_receipts) == 2, "phase_f_t2_pair_rejected")
        raise ReleaseSetActivationRejected("phase_f_t2_observation_stage_required")

    def resume_once(self, journal_parent: Path) -> str:
        backend = self.backend
        return _s2_recover_once(
            journal_parent,
            observe=backend.observe_operation,
            apply=backend.apply_operation,
            invoke_writer=backend.invoke_writer,
        )

    def rollback_once(self, journal_parent: Path) -> str:
        return _s3_rollback_once(journal_parent, backend=self.backend)

    def forward_old_once(self, journal_parent: Path) -> str:
        return _s3_forward_old_once(journal_parent, backend=self.backend)
