from __future__ import annotations

import json
import os
import pwd
import re
import subprocess
from typing import Any, Callable


EXPECTED_OS_USER = "myuna_memory_runtime"
EXPECTED_DATABASE_ROLE = "myuna_memory_runtime"
DATABASE_NAME = "myuna_owner_memory"
SAFE_VIEW = "memory.owner_memory_runtime_nonrestricted_v1"
EXPECTED_NAMESPACE = "ns-owner-cealana-private"
PSQL_PATH = "/usr/bin/psql"
MAX_DATABASE_OUTPUT_BYTES = 4 * 1024 * 1024
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class RecordSourceError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def current_os_user() -> str:
    return pwd.getpwuid(os.geteuid()).pw_name


def verify_runtime_identity(*, user_name: str | None = None) -> None:
    if (user_name or current_os_user()) != EXPECTED_OS_USER:
        raise RecordSourceError("runtime_identity_mismatch", retryable=False)


def _validate_record(record: object) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise RecordSourceError("safe_view_record_invalid", retryable=False)
    candidate_id = record.get("candidate_id")
    if not isinstance(candidate_id, str) or _SAFE_IDENTIFIER.fullmatch(candidate_id) is None:
        raise RecordSourceError("safe_view_record_invalid", retryable=False)
    if record.get("namespace_id") != EXPECTED_NAMESPACE:
        raise RecordSourceError("safe_view_boundary_violation", retryable=False)
    if record.get("sensitivity") != "normal":
        raise RecordSourceError("safe_view_boundary_violation", retryable=False)
    if record.get("confirmation_level") != "user_confirmed":
        raise RecordSourceError("safe_view_boundary_violation", retryable=False)
    return record


def _database_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PGAPPNAME": "myuna-owner-memory-readonly-v2",
        "PGOPTIONS": (
            "-c default_transaction_read_only=on "
            "-c statement_timeout=800 "
            "-c lock_timeout=250 "
            "-c idle_in_transaction_session_timeout=1000"
        ),
    }


def load_safe_records(
    *,
    user_name: str | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[dict[str, Any]]:
    verify_runtime_identity(user_name=user_name)
    sql = (
        "COPY ("
        "SELECT row_to_json(runtime_row)::text "
        f"FROM {SAFE_VIEW} AS runtime_row "
        "ORDER BY candidate_id"
        ") TO STDOUT;"
    )
    try:
        completed = runner(
            [
                PSQL_PATH,
                f"--dbname={DATABASE_NAME}",
                f"--username={EXPECTED_DATABASE_ROLE}",
                "--no-psqlrc",
                "--set=ON_ERROR_STOP=1",
                "--command",
                sql,
            ],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=_database_environment(),
            timeout=1.0,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RecordSourceError("safe_view_unavailable", retryable=True) from exc

    if not isinstance(completed.stdout, str):
        raise RecordSourceError("safe_view_output_invalid", retryable=True)
    if len(completed.stdout.encode("utf-8")) > MAX_DATABASE_OUTPUT_BYTES:
        raise RecordSourceError("safe_view_output_budget_exceeded", retryable=True)

    records: list[dict[str, Any]] = []
    try:
        for line in completed.stdout.splitlines():
            if line.strip():
                records.append(_validate_record(json.loads(line)))
    except (json.JSONDecodeError, UnicodeError, TypeError, ValueError) as exc:
        raise RecordSourceError("safe_view_output_invalid", retryable=True) from exc
    return records
