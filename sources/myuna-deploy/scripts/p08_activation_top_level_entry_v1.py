#!/usr/bin/env python3
"""Source-owned direct-WSL transport, closed-stdin, and capture boundary.

The Windows host is transport only.  This exact materialized module verifies
that substrate and its own process/source identities, closes the untrusted
outer descriptor, then creates the reviewed bootstrap with verified
``/dev/null`` stdin and one nonce-bound parent relationship.  It never builds
a plan or performs a product role itself.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import sys
from typing import Mapping, Sequence

import p08_activation_contract_v1 as contract_v1
import p08_activation_launcher_v1 as launcher_v1
import p08_activation_production_adapter_v1 as adapter_v1


class TopLevelEntryError(RuntimeError):
    pass


class CanonicalArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - fixed argparse seam
        raise TopLevelEntryError("top_level_entry_arguments_rejected")


def _load_contract(path: Path) -> dict[str, object]:
    try:
        return contract_v1.validate_contract(adapter_v1._read_json(path))
    except (adapter_v1.AdapterError, contract_v1.ContractError):
        raise TopLevelEntryError("top_level_entry_contract_rejected") from None


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
        raise TopLevelEntryError("top_level_entry_target_rejected") from None
    return inventory, directories


def _fallback_result(
    contract: Mapping[str, object] | None,
    *,
    acceptance_scope_digest: str | None,
    target_source: Path | None,
    intent: Mapping[str, object] | None,
    indeterminate: bool,
    failure_category: str,
) -> dict[str, object]:
    if contract is None or not isinstance(acceptance_scope_digest, str):
        return {
            "schema": contract_v1.SUPERVISOR_ENTRY_SCHEMA,
            "status": "indeterminate",
            "stage": "source_owned_entry",
            "product_state": "unknown",
            "raw_output_included": False,
            "retry_authorized": False,
        }
    if contract_v1.HEX64.fullmatch(acceptance_scope_digest) is None:
        acceptance_scope_digest = sha256(
            acceptance_scope_digest.encode("utf-8", "surrogatepass")
        ).hexdigest()
    if intent is None:
        entry_identity = contract_v1.digest_value(
            {
                "architecture": contract_v1.ARCHITECTURE,
                "contract_digest": contract["contract_digest"],
                "acceptance_scope_digest": acceptance_scope_digest,
                "target_source": str(target_source) if target_source is not None else None,
                "stage": "top_level_pre_intent",
            }
        )
        intent = {
            "entry_identity": entry_identity,
            "acceptance_scope_digest": acceptance_scope_digest,
            "intent_digest": None,
        }
    return launcher_v1.build_top_level_entry_result(
        contract,
        intent,
        None,
        prelaunch_status="indeterminate" if indeterminate else "rejected",
        failure_category=failure_category,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = CanonicalArgumentParser(allow_abbrev=False)
    parser.add_argument("--activation-contract", type=Path, required=True)
    parser.add_argument("--activation-root", type=Path, required=True)
    parser.add_argument(
        "--activation-backend", choices=("synthetic", "systemd"), required=True
    )
    parser.add_argument("--activation-target-source", type=Path, required=True)
    parser.add_argument("--acceptance-scope-digest", required=True)
    contract: dict[str, object] | None = None
    intent: dict[str, object] | None = None
    capture: dict[str, object] | None = None
    target_source: Path | None = None
    acceptance_scope_digest: str | None = None
    child_entered = [False]
    failure_category = "arguments_rejected"
    read_fd = -1
    write_fd = -1
    try:
        values = parser.parse_args(argv)
        failure_category = "contract_rejected"
        contract = _load_contract(values.activation_contract)
        target_source = values.activation_target_source
        acceptance_scope_digest = values.acceptance_scope_digest
        failure_category = "target_rejected"
        inventory, directories = _target_closure(contract, target_source)
        failure_category = "loaded_runtime_rejected"
        launcher_v1.verify_loaded_runtime_inventory(
            contract,
            target_source,
            inventory,
            directories,
            {
                contract_v1.TOP_LEVEL_ENTRY_PATH: sys.modules[__name__],
                "scripts/p08_activation_contract_v1.py": contract_v1,
                "scripts/p08_activation_launcher_v1.py": launcher_v1,
                contract_v1.PRODUCTION_ADAPTER_PATH: adapter_v1,
            },
        )
        read_fd, write_fd = os.pipe()
        os.set_inheritable(read_fd, True)
        parent_nonce = secrets.token_bytes(32)
        failure_category = "intent_rejected"
        intent = launcher_v1.build_top_level_entry_intent(
            contract,
            contract_path=values.activation_contract,
            root=values.activation_root,
            backend=values.activation_backend,
            target_source=target_source,
            target_inventory=inventory,
            target_directories=directories,
            acceptance_scope_digest=acceptance_scope_digest,
            parent_pipe_fd=read_fd,
            parent_nonce_sha256=sha256(parent_nonce).hexdigest(),
        )
        failure_category = "process_identity_rejected"
        launcher_v1.verify_current_top_level_entry(contract, intent)
        # The source-owned boundary establishes the exact value before any
        # evidence write; inherited host state never becomes authority.
        os.umask(int(intent["umask"]))
        failure_category = "intent_persistence_rejected"
        launcher_v1.persist_capture_o_excl(Path(str(intent["intent_path"])), intent)
        persisted_intent = launcher_v1.validate_top_level_entry_intent(
            contract, adapter_v1._read_json(Path(str(intent["intent_path"])))
        )
        # The Windows transport pipe is never consumed and cannot reach the
        # product entry.  Child stdin is opened and independently verified by
        # the unified launcher below.
        os.close(0)
        failure_category = "capture_rejected"
        capture = launcher_v1.run_top_level_entry_capture(
            contract,
            persisted_intent,
            parent_pipe_fds=(read_fd, write_fd),
            parent_nonce=parent_nonce,
            child_started=lambda _child: child_entered.__setitem__(0, True),
        )
        read_fd = -1
        write_fd = -1
        failure_category = "capture_persistence_rejected"
        launcher_v1.persist_capture_o_excl(
            Path(str(intent["capture_path"])), capture
        )
        capture = launcher_v1.validate_top_level_entry_capture(
            contract,
            persisted_intent,
            adapter_v1._read_json(Path(str(intent["capture_path"]))),
        )
        result = launcher_v1.build_top_level_entry_result(
            contract, persisted_intent, capture
        )
        failure_category = "result_persistence_rejected"
        launcher_v1.persist_capture_o_excl(Path(str(intent["result_path"])), result)
        failure_category = "result_readback_rejected"
        result = launcher_v1.validate_top_level_entry_result(
            contract, adapter_v1._read_json(Path(str(intent["result_path"])))
        )
    except Exception:
        for descriptor in (read_fd, write_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        result = _fallback_result(
            contract,
            acceptance_scope_digest=acceptance_scope_digest,
            target_source=target_source,
            intent=intent,
            indeterminate=child_entered[0] or capture is not None,
            failure_category=failure_category,
        )
        if contract is not None and intent is not None:
            try:
                result_path = Path(str(intent["result_path"]))
                if not result_path.exists():
                    launcher_v1.persist_capture_o_excl(result_path, result)
                    result = launcher_v1.validate_top_level_entry_result(
                        contract, adapter_v1._read_json(result_path)
                    )
            except Exception:
                pass
    sys.stdout.buffer.write(contract_v1.canonical_bytes(result))
    if result.get("status") == "accepted":
        return 0
    if result.get("status") in {"hard_stop", "rejected"}:
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
