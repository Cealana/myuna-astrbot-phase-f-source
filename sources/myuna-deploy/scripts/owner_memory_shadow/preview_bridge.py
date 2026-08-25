"""Restricted-safe bridge to the audited preview ranking implementation."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import pwd
import subprocess
from types import ModuleType
from typing import Any


DEFAULT_PREVIEW = Path("/opt/myuna/owner-memory-retrieval-preview-v1/preview.py")
EXPECTED_NAMESPACE = "ns-owner-cealana-private"
EXPECTED_OS_USER = "myuna_memory_preview"


def _load_preview_module() -> ModuleType:
    """Load only the existing preview file, never an import-path lookalike."""

    configured = os.environ.get("MYUNA_OWNER_MEMORY_PREVIEW_MODULE")
    path = Path(configured) if configured else DEFAULT_PREVIEW
    path = path.resolve(strict=True)
    if path.name != "preview.py" or not path.is_file():
        raise RuntimeError("preview_module_invalid")
    spec = importlib.util.spec_from_file_location("myuna_owner_memory_preview_v1", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("preview_module_unloadable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for required in ("retrieve", "EXPECTED_NAMESPACE"):
        if not hasattr(module, required):
            raise RuntimeError("preview_contract_missing")
    if module.EXPECTED_NAMESPACE != EXPECTED_NAMESPACE:
        raise RuntimeError("preview_namespace_mismatch")
    return module


def _load_nonrestricted_records() -> list[dict[str, Any]]:
    """Read only the fixed namespace/non-restricted projection in PostgreSQL."""

    current_user = pwd.getpwuid(os.geteuid()).pw_name
    if current_user != EXPECTED_OS_USER:
        raise RuntimeError("preview_os_user_mismatch")
    # The predicates are static source text, not derived from the datagram.
    sql = (
        "COPY ("
        "SELECT row_to_json(preview_row)::text "
        "FROM memory.owner_memory_retrieval_preview_v1 AS preview_row "
        "WHERE namespace_id = 'ns-owner-cealana-private' "
        "AND sensitivity <> 'restricted' "
        "ORDER BY candidate_id"
        ") TO STDOUT;"
    )
    environment = os.environ.copy()
    environment.update(
        {
            "PGAPPNAME": "myuna-owner-memory-shadow-v1",
            "PGOPTIONS": (
                "-c default_transaction_read_only=on "
                "-c statement_timeout=5000 "
                "-c lock_timeout=1000 "
                "-c idle_in_transaction_session_timeout=5000"
            ),
        }
    )
    completed = subprocess.run(
        [
            "psql", "--dbname=myuna_owner_memory", "--no-psqlrc",
            "--set=ON_ERROR_STOP=1", "--command", sql,
        ],
        check=True, capture_output=True, text=True, encoding="utf-8",
        env=environment, timeout=8,
    )
    records = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
    if any(record.get("namespace_id") != EXPECTED_NAMESPACE for record in records):
        raise RuntimeError("safe_view_namespace_violation")
    if any(record.get("sensitivity") == "restricted" for record in records):
        raise RuntimeError("safe_view_restricted_violation")
    return records


class SafePreviewBridge:
    """Expose ranking with a single, non-configurable safe read operation."""

    def __init__(self, module: ModuleType):
        self._module = module

    def load_safe_records(self) -> list[dict[str, Any]]:
        return _load_nonrestricted_records()

    def retrieve_safe(self, records: list[dict[str, Any]], **kwargs: Any) -> dict[str, Any]:
        # There is intentionally no include_restricted argument in this API.
        return self._module.retrieve(records, include_restricted=False, **kwargs)

    def parse_datetime(self, value: str):
        return self._module._parse_datetime(value)


def load_preview_bridge() -> SafePreviewBridge:
    return SafePreviewBridge(_load_preview_module())

