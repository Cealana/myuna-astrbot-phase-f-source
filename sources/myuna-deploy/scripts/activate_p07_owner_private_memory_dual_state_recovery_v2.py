#!/usr/bin/env python3
"""One-attempt P07 dual-state recovery controller.

This controller creates a distinct attempt namespace while binding the
exhausted two-attempt predecessor as immutable evidence.  It never resets,
renames, or substitutes the predecessor lineage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

import activate_p07_owner_private_memory_v1 as memory


SCHEMA = memory.DUAL_STATE_RECOVERY_V2_STRATEGY.activation_schema
IMMUTABLE_PREDECESSOR_SCHEMA = (
    "myuna.p07-owner-private-memory-immutable-predecessor.v2"
)
LEGACY_STATE_ROOT = Path("/var/lib/myuna-telegram-gateway/p07-policy-overlay-v1")
LEGACY_BACKUP_ROOT = Path("/var/backups/myuna/p07-policy-overlay-v1")
LEGACY_ARCHIVE_ROOT = Path(
    "/var/lib/myuna-telegram-gateway/owner-private-memory-v1"
)
LEGACY_ARCHIVE_ID = "p07-owner-private-memory-v1-4cfdb84d81bb7c81"
LEGACY_ARCHIVE_UID = 988
LEGACY_ARCHIVE_GID = 982
LEGACY_ARCHIVE_EVIDENCE_DIGEST = (
    "97ff4ba69ef476d7615c69e4d636d1a3dd8b4df083768459cec35c99778ab253"
)
LEGACY_STATE_TREE_DIGEST = (
    "618308401f10003c5b4785217f6a8258653b52cc9d827fa5dd68a5b5101a03d9"
)
LEGACY_BACKUP_TREE_DIGEST = (
    "db5b96c4084f5ec8385a90003261bb083ef27136d5d1308c770b0148fe1f9174"
)
LEGACY_ARCHIVE_TREE_DIGEST = (
    "3dcd1d04b9e5955868508bc0a4c6de820f40007144c29f434ae96bc6e7aced52"
)
LEGACY_LEDGER_SHA256 = (
    "be14ed700e7be4c964ffccceb6c6c6bfacd25b257700b3d9ae38af869a134565"
)
LEGACY_ATTEMPT1_RECEIPT_SHA256 = (
    "8958b60300b087b6973537ba0859b4fcd4546fca4d8afc317660b42266b59e64"
)
LEGACY_ATTEMPT2_RECEIPT_SHA256 = (
    "d027790d243c6064f52d34a365adb07fd084199b256876f193cc601ffd0103c4"
)
LEGACY_LAST_PLAN_SHA256 = (
    "8e884a4ddde1f28f2772dabb67f2c394bfa7ab27c2b54933c83a41e5f2e79384"
)
LEGACY_FORMAL_PREFLIGHT_SHA256 = (
    "bf01d112679ab889997be673cf4d53d0a24fd537b3eb4d78ef2ebea34b8d2513"
)
HARD_STOP_HANDOFF_SHA256 = (
    "3a73a9fc36da092cc6ac256aa2fd82ef7f6a1a742004537c8889616dda0b3ecb"
)
DIAGNOSIS_HANDOFF_SHA256 = (
    "5245f36a60fa9b1dde0cd1544df1a9ae8a4475ca6804547ab2ab776b4e23a8b7"
)
DUAL_STATE_T1_HANDOFF_SHA256 = (
    "395b5fc0ea2a465ab6ee44e2b813276dbc3adbfa3bfdc0fedbb8a25ac48a5035"
)
_STATE_FILES = {
    "ATTEMPT_LEDGER.json": LEGACY_LEDGER_SHA256,
    "JOURNAL-20260807T225958Z-dce5d7584a1b.json": (
        LEGACY_ATTEMPT1_RECEIPT_SHA256
    ),
    "JOURNAL-20260808T003412Z-8e884a4ddde1.json": (
        LEGACY_ATTEMPT2_RECEIPT_SHA256
    ),
    "RECEIPT-20260807T225958Z-dce5d7584a1b.json": (
        LEGACY_ATTEMPT1_RECEIPT_SHA256
    ),
    "RECEIPT-20260808T003412Z-8e884a4ddde1.json": (
        LEGACY_ATTEMPT2_RECEIPT_SHA256
    ),
}
_BACKUP_PLANS = {
    "dce5d7584a1b7b5d7e4567938f35a4875b3cb6d0b1841c0902df72e7acef5cfe",
    LEGACY_LAST_PLAN_SHA256,
}


def _protected_tree_digest(root: Path, *, code: str) -> str:
    try:
        root_metadata = root.lstat()
    except OSError as exc:
        raise memory.MemoryActivationRejected(code) from exc
    memory.require(
        not root.is_symlink() and stat.S_ISDIR(root_metadata.st_mode), code
    )
    rows: list[dict[str, object]] = []
    try:
        paths = sorted(root.rglob("*"))
    except OSError as exc:
        raise memory.MemoryActivationRejected(code) from exc
    for path in paths:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise memory.MemoryActivationRejected(code) from exc
        memory.require(not path.is_symlink(), code)
        if stat.S_ISDIR(metadata.st_mode):
            kind = "directory"
            sha256: str | None = None
            size: int | None = None
        elif stat.S_ISREG(metadata.st_mode):
            kind = "file"
            sha256 = memory.digest_file(path)
            size = metadata.st_size
        else:
            raise memory.MemoryActivationRejected(code)
        rows.append(
            {
                "gid": metadata.st_gid,
                "kind": kind,
                "mode": stat.S_IMODE(metadata.st_mode),
                "path": path.relative_to(root).as_posix(),
                "sha256": sha256,
                "size": size,
                "uid": metadata.st_uid,
            }
        )
    payload = memory.canonical(
        {
            "entries": rows,
            "root": {
                "gid": root_metadata.st_gid,
                "mode": stat.S_IMODE(root_metadata.st_mode),
                "uid": root_metadata.st_uid,
            },
        }
    )[:-1]
    return hashlib.sha256(
        b"myuna-p07-dual-state-recovery-v2-protected-tree\0" + payload
    ).hexdigest()


def _verify_handoff(path: Path, expected_sha256: str, code: str) -> None:
    memory.require(
        path.is_file()
        and not path.is_symlink()
        and memory.digest_file(path) == expected_sha256,
        code,
    )


def verify_immutable_predecessor(
    *,
    hard_stop_handoff: Path,
    diagnosis_handoff: Path,
    dual_state_t1_handoff: Path,
    formal_preflight_one: Path,
    formal_preflight_two: Path,
    state_root: Path = LEGACY_STATE_ROOT,
    backup_root: Path = LEGACY_BACKUP_ROOT,
    archive_root: Path = LEGACY_ARCHIVE_ROOT,
) -> dict[str, object]:
    _verify_handoff(
        hard_stop_handoff,
        HARD_STOP_HANDOFF_SHA256,
        "p07_v2_hard_stop_handoff_drifted",
    )
    _verify_handoff(
        diagnosis_handoff,
        DIAGNOSIS_HANDOFF_SHA256,
        "p07_v2_diagnosis_handoff_drifted",
    )
    _verify_handoff(
        dual_state_t1_handoff,
        DUAL_STATE_T1_HANDOFF_SHA256,
        "p07_v2_dual_state_handoff_drifted",
    )
    memory.require(
        formal_preflight_one.resolve() != formal_preflight_two.resolve(),
        "p07_v2_predecessor_preflight_identity_rejected",
    )
    for path in (formal_preflight_one, formal_preflight_two):
        _verify_handoff(
            path,
            LEGACY_FORMAL_PREFLIGHT_SHA256,
            "p07_v2_predecessor_preflight_drifted",
        )
    memory.require(
        state_root == LEGACY_STATE_ROOT
        and backup_root == LEGACY_BACKUP_ROOT
        and archive_root == LEGACY_ARCHIVE_ROOT,
        "p07_v2_predecessor_root_rejected",
    )
    state_digest = _protected_tree_digest(
        state_root, code="p07_v2_predecessor_state_drifted"
    )
    backup_digest = _protected_tree_digest(
        backup_root, code="p07_v2_predecessor_backup_drifted"
    )
    archive_tree_digest = _protected_tree_digest(
        archive_root, code="p07_v2_predecessor_archive_drifted"
    )
    memory.require(
        state_digest == LEGACY_STATE_TREE_DIGEST
        and backup_digest == LEGACY_BACKUP_TREE_DIGEST
        and archive_tree_digest == LEGACY_ARCHIVE_TREE_DIGEST,
        "p07_v2_immutable_predecessor_drifted",
    )
    memory.require(
        {path.name for path in state_root.iterdir()} == set(_STATE_FILES)
        and all(
            memory.digest_file(state_root / name) == expected
            for name, expected in _STATE_FILES.items()
        )
        and {path.name for path in backup_root.iterdir()} == _BACKUP_PLANS,
        "p07_v2_immutable_predecessor_drifted",
    )
    try:
        ledger = json.loads((state_root / "ATTEMPT_LEDGER.json").read_text("ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise memory.MemoryActivationRejected(
            "p07_v2_predecessor_ledger_rejected"
        ) from exc
    memory.require(
        ledger
        == {
            "attempts": 2,
            "last_plan_sha256": LEGACY_LAST_PLAN_SHA256,
            "schema": memory.lineage.ATTEMPT_SCHEMA,
        },
        "p07_v2_predecessor_ledger_rejected",
    )
    observed_archive_evidence = memory._memory_runtime_root_evidence(
        archive_ids={LEGACY_ARCHIVE_ID},
        expected_uid=LEGACY_ARCHIVE_UID,
        expected_gid=LEGACY_ARCHIVE_GID,
        empty_archive_ids={LEGACY_ARCHIVE_ID},
        code="p07_v2_predecessor_archive_drifted",
    )
    memory.require(
        observed_archive_evidence == LEGACY_ARCHIVE_EVIDENCE_DIGEST,
        "p07_v2_predecessor_archive_drifted",
    )
    return {
        "archive_evidence_digest": observed_archive_evidence,
        "archive_gid": LEGACY_ARCHIVE_GID,
        "archive_id": LEGACY_ARCHIVE_ID,
        "archive_uid": LEGACY_ARCHIVE_UID,
        "attempt1_receipt_sha256": LEGACY_ATTEMPT1_RECEIPT_SHA256,
        "attempt2_receipt_sha256": LEGACY_ATTEMPT2_RECEIPT_SHA256,
        "attempts": 2,
        "backup_evidence_digest": backup_digest,
        "backup_root": backup_root.as_posix(),
        "diagnosis_handoff_sha256": DIAGNOSIS_HANDOFF_SHA256,
        "dual_state_t1_handoff_sha256": DUAL_STATE_T1_HANDOFF_SHA256,
        "hard_stop_handoff_sha256": HARD_STOP_HANDOFF_SHA256,
        "last_plan_sha256": LEGACY_LAST_PLAN_SHA256,
        "ledger_sha256": LEGACY_LEDGER_SHA256,
        "maximum_attempts": 2,
        "preflight_sha256": LEGACY_FORMAL_PREFLIGHT_SHA256,
        "schema": IMMUTABLE_PREDECESSOR_SCHEMA,
        "state_evidence_digest": state_digest,
        "state_root": state_root.as_posix(),
        "strategy_id": "p07-policy-overlay-v1",
    }


def parser() -> argparse.ArgumentParser:
    selected = memory.parser()
    selected.add_argument("--predecessor-hard-stop-handoff", type=Path, required=True)
    selected.add_argument("--predecessor-diagnosis-handoff", type=Path, required=True)
    selected.add_argument("--predecessor-dual-state-t1-handoff", type=Path, required=True)
    selected.add_argument("--predecessor-formal-preflight-one", type=Path, required=True)
    selected.add_argument("--predecessor-formal-preflight-two", type=Path, required=True)
    return selected


def _legacy_continuation_arguments_absent(values: argparse.Namespace) -> bool:
    return all(
        getattr(values, field) is None
        for field in (
            "prior_attempt_handoff",
            "expected_prior_attempt_handoff_sha256",
            "attempt2_lineage_handoff",
            "expected_attempt2_lineage_handoff_sha256",
            "attempt2_lineage_erratum",
            "expected_attempt2_lineage_erratum_sha256",
            "prior_preflight_one",
            "prior_preflight_two",
            "expected_prior_preflight_sha256",
            "expected_prior_plan_sha256",
            "expected_prior_backup_sha256",
            "expected_prior_backup_evidence_digest",
            "expected_prior_state_evidence_digest",
            "expected_prior_ledger_sha256",
            "expected_prior_receipt_sha256",
        )
    )


def main() -> int:
    values = parser().parse_args()
    try:
        memory.require(
            os.geteuid() == 0
            and values.expected_attempts == 0
            and _legacy_continuation_arguments_absent(values),
            "p07_v2_strategy_arguments_rejected",
        )
        predecessor = verify_immutable_predecessor(
            hard_stop_handoff=values.predecessor_hard_stop_handoff.resolve(),
            diagnosis_handoff=values.predecessor_diagnosis_handoff.resolve(),
            dual_state_t1_handoff=(
                values.predecessor_dual_state_t1_handoff.resolve()
            ),
            formal_preflight_one=values.predecessor_formal_preflight_one.resolve(),
            formal_preflight_two=values.predecessor_formal_preflight_two.resolve(),
        )
        prepared = memory.prepare_from_namespace(
            values,
            attempt_strategy=memory.DUAL_STATE_RECOVERY_V2_STRATEGY,
            immutable_predecessor=predecessor,
            executor_path=Path(__file__),
        )
        result = memory.execute_namespace(values, prepared)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "failure_gate": memory._failure_projection(exc)["failure_gate"],
                    "schema": SCHEMA,
                    "status": "rejected",
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
