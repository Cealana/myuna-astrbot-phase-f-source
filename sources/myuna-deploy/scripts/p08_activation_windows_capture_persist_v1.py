#!/usr/bin/env python3
"""Root-owned persistence boundary for the raw-free Windows transport capture."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from typing import Mapping, Sequence

import p08_activation_contract_v1 as contract_v1
import p08_activation_launcher_v1 as launcher_v1
import p08_activation_production_adapter_v1 as adapter_v1


class CapturePersistError(RuntimeError):
    pass


class CanonicalArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - fixed argparse seam
        raise CapturePersistError("capture_persist_arguments_rejected")


def _load_contract(path: Path) -> dict[str, object]:
    try:
        return contract_v1.validate_contract(adapter_v1._read_json(path))
    except (adapter_v1.AdapterError, contract_v1.ContractError):
        raise CapturePersistError("capture_persist_contract_rejected") from None


def _target_closure(
    contract: Mapping[str, object], target_source: Path
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    try:
        inventory = adapter_v1.target_inventory(target_source)
        directories = adapter_v1.target_directory_inventory(
            target_source, file_inventory=inventory
        )
        adapter_v1._target_manifest(contract, target_source, inventory)
    except adapter_v1.AdapterError:
        raise CapturePersistError("capture_persist_target_rejected") from None
    return inventory, directories


def _read_stdin_bounded(limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = os.read(0, min(65_536, limit + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > limit:
            raise CapturePersistError("capture_persist_input_rejected")
    return b"".join(chunks)


def _fallback() -> dict[str, object]:
    return {
        "schema": contract_v1.SUPERVISOR_ENTRY_SCHEMA,
        "status": "indeterminate",
        "stage": "source_owned_windows_capture_persist",
        "product_state": "unknown",
        "raw_output_included": False,
        "retry_authorized": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = CanonicalArgumentParser(allow_abbrev=False)
    parser.add_argument("--activation-contract", type=Path, required=True)
    parser.add_argument("--activation-root", type=Path, required=True)
    parser.add_argument(
        "--activation-backend", choices=("synthetic", "systemd"), required=True
    )
    parser.add_argument("--activation-target-source", type=Path, required=True)
    parser.add_argument("--acceptance-scope-digest", required=True)
    parser.add_argument("--entry-identity", required=True)
    try:
        values = parser.parse_args(argv)
        contract = _load_contract(values.activation_contract)
        if (
            contract_v1.HEX64.fullmatch(values.acceptance_scope_digest) is None
            or contract_v1.HEX64.fullmatch(values.entry_identity) is None
        ):
            raise CapturePersistError("capture_persist_arguments_rejected")
        inventory, directories = _target_closure(
            contract, values.activation_target_source
        )
        launcher_v1.verify_loaded_runtime_inventory(
            contract,
            values.activation_target_source,
            inventory,
            directories,
            {
                contract_v1.WINDOWS_CAPTURE_PERSIST_PATH: sys.modules[__name__],
                "scripts/p08_activation_contract_v1.py": contract_v1,
                "scripts/p08_activation_launcher_v1.py": launcher_v1,
                contract_v1.PRODUCTION_ADAPTER_PATH: adapter_v1,
            },
        )
        launcher_v1.verify_current_windows_capture_persister(
            contract,
            contract_path=values.activation_contract,
            root=values.activation_root,
            backend=values.activation_backend,
            target_source=values.activation_target_source,
            acceptance_scope_digest=values.acceptance_scope_digest,
            entry_identity=values.entry_identity,
        )
        top = contract["launcher"]["top_level_entry"]
        raw = _read_stdin_bounded(int(top["host_launcher"]["stdout_limit"]))
        try:
            parsed = json.loads(raw.decode("utf-8", "strict"))
        except (UnicodeError, json.JSONDecodeError):
            raise CapturePersistError("capture_persist_input_rejected") from None
        if contract_v1.canonical_bytes(parsed) != raw:
            raise CapturePersistError("capture_persist_input_rejected")
        capture = launcher_v1.validate_windows_wsl_capture(contract, parsed)
        expected_identity = launcher_v1.windows_host_entry_identity(
            contract,
            acceptance_scope_digest=values.acceptance_scope_digest,
            backend=values.activation_backend,
            root=values.activation_root,
            target_source=values.activation_target_source,
        )
        if (
            capture["entry_identity"] != values.entry_identity
            or values.entry_identity != expected_identity
            or capture["acceptance_scope_digest"] != values.acceptance_scope_digest
        ):
            raise CapturePersistError("capture_persist_identity_rejected")
        entry_root = (
            values.activation_root
            / str(top["evidence_root"]).lstrip("/")
            / values.entry_identity
        )
        if capture["canonical_status"] == "complete":
            child_result_path = entry_root / "RESULT.json"
            child_result = launcher_v1.validate_top_level_entry_result(
                contract, adapter_v1._read_json(child_result_path)
            )
            child_bytes = contract_v1.canonical_bytes(child_result)
            if (
                sha256(child_bytes).hexdigest() != capture["stdout_sha256"]
                or len(child_bytes) != capture["stdout_size"]
                or child_result["result_digest"]
                != capture["canonical_result_digest"]
            ):
                raise CapturePersistError("capture_persist_result_binding_rejected")
        host_capture_path = entry_root / "HOST.CAPTURE.json"
        launcher_v1.persist_capture_o_excl(host_capture_path, capture)
        persisted = launcher_v1.validate_windows_wsl_capture(
            contract, adapter_v1._read_json(host_capture_path)
        )
        result = launcher_v1.build_windows_capture_persist_result(
            contract, persisted
        )
        persist_result_path = entry_root / "HOST.PERSIST.RESULT.json"
        launcher_v1.persist_capture_o_excl(persist_result_path, result)
        result = launcher_v1.validate_windows_capture_persist_result(
            contract, adapter_v1._read_json(persist_result_path)
        )
    except Exception:
        result = _fallback()
    sys.stdout.buffer.write(contract_v1.canonical_bytes(result))
    return 0 if result.get("status") == "persisted" else 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
