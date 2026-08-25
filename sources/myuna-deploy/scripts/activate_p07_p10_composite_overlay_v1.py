#!/usr/bin/env python3
"""Non-resetting P07/P10 composite controller over the generation-13 parent.

The controller deliberately reuses the existing P07 policy-overlay state,
backup and attempt-ledger namespace.  It adds current P10/P09/P16/P01 source
and lineage bindings around the proven v1 transaction; it does not create a
new strategy series or a fresh epoch.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path

import activate_p07_policy_overlay_v1 as legacy
from build_p07_p10_composite_overlay_v1 import verify_bundle
from p07_p10_composite_overlay_contract_v1 import (
    PLAN_SCHEMA,
    PREFLIGHT_SCHEMA,
    P01_CONSUMED_ATTEMPTS,
    P01_HANDOFF_SHA256,
    P01_MAXIMUM_ATTEMPTS,
    FUTURE_ACTIVATION_ORDER,
    FUTURE_ROLLBACK_ORDER,
    P07_CONSUMED_ATTEMPTS,
    P07_MAXIMUM_ATTEMPTS,
    P07_REJECTED_CALL_HANDOFF_SHA256,
    P07_REJECTED_FORMAL_CALLS,
    P09_HANDOFF_SHA256,
    P10_HANDOFF_SHA256,
    P16_ATTEMPT_FILE_SHA256,
    P16_CONSUMED_ATTEMPTS,
    P16_HANDOFF_SHA256,
    P16_MARKER_SHA256,
    P16_MAXIMUM_ATTEMPTS,
    P16_SELECTOR_SHA256,
    CompositeContractRejected,
    canonical,
    contract_digest,
    require,
    require_regular_digest,
)


SCHEMA = "myuna.p07-p10-composite-overlay-activation.v1"
P16_MARKER = Path("/etc/myuna-gateway/incident-history-v1-enabled")
P16_SELECTOR = Path("/etc/myuna-gateway/incident-history-v1.selector.json")
P16_ATTEMPT = Path(
    "/var/lib/myuna-fault-diagnostics/"
    "p16-projection-budget-attempt-series-v1/attempt-0001.json"
)


@dataclass(frozen=True)
class EvidencePaths:
    p07_rejected_call: Path
    p10_handoff: Path
    p09_handoff: Path
    p16_handoff: Path
    p01_handoff: Path


@dataclass(frozen=True)
class PreparedCompositeActivation:
    legacy_activation: legacy.PreparedPolicyOverlayActivation
    composite_bundle: Path
    composite_manifest: dict[str, object]
    plan_bytes: bytes
    evidence_paths: EvidencePaths

    @property
    def plan_digest(self) -> str:
        return legacy.digest_bytes(self.plan_bytes)


def _verify_evidence(paths: EvidencePaths) -> None:
    require_regular_digest(
        paths.p07_rejected_call,
        P07_REJECTED_CALL_HANDOFF_SHA256,
        "p07_rejected_call_evidence_drifted",
    )
    require_regular_digest(paths.p10_handoff, P10_HANDOFF_SHA256, "p10_handoff_drifted")
    require_regular_digest(paths.p09_handoff, P09_HANDOFF_SHA256, "p09_handoff_drifted")
    require_regular_digest(paths.p16_handoff, P16_HANDOFF_SHA256, "p16_handoff_drifted")
    require_regular_digest(paths.p01_handoff, P01_HANDOFF_SHA256, "p01_handoff_drifted")


def _verify_live_lineages() -> None:
    require(
        legacy.STATE_ROOT
        == Path("/var/lib/myuna-telegram-gateway/p07-policy-overlay-v1")
        and legacy.BACKUP_ROOT
        == Path("/var/backups/myuna/p07-policy-overlay-v1")
        and legacy.ATTEMPT_LEDGER == legacy.STATE_ROOT / "ATTEMPT_LEDGER.json"
        and legacy.MAX_ATTEMPTS == P07_MAXIMUM_ATTEMPTS,
        "p07_attempt_namespace_drifted",
    )
    require(legacy._attempt_count() == P07_CONSUMED_ATTEMPTS, "p07_attempt_lineage_drifted")
    require_regular_digest(P16_MARKER, P16_MARKER_SHA256, "p16_marker_drifted")
    require_regular_digest(P16_SELECTOR, P16_SELECTOR_SHA256, "p16_selector_drifted")
    require_regular_digest(P16_ATTEMPT, P16_ATTEMPT_FILE_SHA256, "p16_attempt_lineage_drifted")
    try:
        names = {path.name for path in P16_ATTEMPT.parent.iterdir()}
    except OSError:
        raise CompositeContractRejected("p16_attempt_lineage_drifted") from None
    require(names == {"attempt-0001.json"}, "p16_attempt_lineage_drifted")


def prepare_activation(
    *,
    composite_bundle: Path,
    evidence_paths: EvidencePaths,
    **legacy_arguments: object,
) -> PreparedCompositeActivation:
    _verify_evidence(evidence_paths)
    _verify_live_lineages()
    core_source = Path(str(legacy_arguments["core_source"]))
    deploy_source = Path(str(legacy_arguments["deploy_source"]))
    manifest = verify_bundle(
        composite_bundle,
        core_source=core_source,
        deploy_source=deploy_source,
        parent_manifest=legacy.RELEASE_SET_PATH,
        core_candidate=Path(str(legacy_arguments["core_candidate"])),
        runtime_candidate=Path(str(legacy_arguments["runtime_candidate"])),
        plugin_candidate=Path(str(legacy_arguments["plugin_candidate"])),
        core_commit=str(legacy_arguments["core_commit"]),
        deploy_commit=str(legacy_arguments["deploy_commit"]),
    )
    expected_overlay_root = (
        composite_bundle
        / "policy-overlay"
        / str(manifest["overlay_bundle"]["bundle_id"])
    )
    require(
        Path(str(legacy_arguments["overlay_bundle"])) == expected_overlay_root,
        "composite_underlying_overlay_path_rejected",
    )
    selected = legacy.prepare_activation(**legacy_arguments)  # type: ignore[arg-type]
    require(
        expected_overlay_root == selected.bundle_root
        and manifest["overlay_bundle"]["bundle_id"]
        == selected.overlay_bundle_manifest["bundle_id"],
        "composite_underlying_overlay_drifted",
    )
    underlying = json.loads(selected.plan_bytes.decode("ascii"))
    plan = {
        "attempt_lineages": {
            "p01": {"consumed": P01_CONSUMED_ATTEMPTS, "maximum": P01_MAXIMUM_ATTEMPTS},
            "p07": {
                "consumed": P07_CONSUMED_ATTEMPTS,
                "maximum": P07_MAXIMUM_ATTEMPTS,
                "rejected_formal_calls_preserved": P07_REJECTED_FORMAL_CALLS,
                "shared_state_namespace": str(legacy.STATE_ROOT),
            },
            "p16": {"consumed": P16_CONSUMED_ATTEMPTS, "maximum": P16_MAXIMUM_ATTEMPTS},
        },
        "boundaries": {
            "channel_called": False,
            "database_rows_read": False,
            "epoch_rewritten": False,
            "health_called": False,
            "model_called": False,
            "p09_v7_selected": False,
            "private_content_read": False,
            "provider_called": False,
        },
        "composite_id": manifest["composite_id"],
        "contract_digest": contract_digest(),
        "executor_sha256": legacy.digest_file(Path(__file__).resolve()),
        "future_activation_order": list(FUTURE_ACTIVATION_ORDER),
        "future_rollback_order": list(FUTURE_ROLLBACK_ORDER),
        "p10": {
            "external_message": False,
            "hybrid_epoch_access": False,
            "source_files": manifest["p10_ingress"]["files"],
        },
        "prestate_digest": underlying["prestate_digest"],
        "schema": PLAN_SCHEMA,
        "source": manifest["source"],
        "target": manifest["artifacts"],
        "underlying_policy_overlay_plan_sha256": selected.plan_digest,
    }
    return PreparedCompositeActivation(
        legacy_activation=selected,
        composite_bundle=composite_bundle,
        composite_manifest=manifest,
        plan_bytes=canonical(plan),
        evidence_paths=evidence_paths,
    )


def preflight_projection(prepared: PreparedCompositeActivation) -> dict[str, object]:
    return {
        "attempts": P07_CONSUMED_ATTEMPTS,
        "channel_called": False,
        "composite_id": prepared.composite_manifest["composite_id"],
        "health_called": False,
        "maximum_attempts": P07_MAXIMUM_ATTEMPTS,
        "model_called": False,
        "mutation_performed": False,
        "new_sequence_required_calls": 2,
        "next_attempt": 1,
        "plan_sha256": prepared.plan_digest,
        "prior_rejected_formal_calls_preserved": P07_REJECTED_FORMAL_CALLS,
        "private_content_read": False,
        "provider_called": False,
        "schema": PREFLIGHT_SCHEMA,
        "status": "ready",
    }


class CompositeBackend(legacy.LivePolicyOverlayBackend):
    def __init__(self, prepared: PreparedCompositeActivation) -> None:
        super().__init__(prepared.legacy_activation)
        self.composite = prepared
        self.backup_root = legacy.BACKUP_ROOT / prepared.plan_digest

    def create_plan_bound_backup(self) -> None:
        legacy.require(legacy._absent(legacy.BACKUP_ROOT), "policy_overlay_backup_root_preexisting")
        legacy.BACKUP_ROOT.mkdir(parents=True, mode=0o700)
        os.chown(legacy.BACKUP_ROOT, 0, 0)
        os.chmod(legacy.BACKUP_ROOT, 0o700)
        legacy.require(
            legacy.BACKUP_ROOT.stat().st_dev
            == legacy.POLICY_OVERLAY_MANIFEST_PATH.parent.stat().st_dev,
            "policy_overlay_backup_filesystem_rejected",
        )
        self.backup_root.mkdir(mode=0o700)
        os.chown(self.backup_root, 0, 0)
        legacy.atomic_write(self.backup_root / "PLAN.json", self.composite.plan_bytes, mode=0o600)
        legacy.atomic_write(
            self.backup_root / "UNDERLYING-POLICY-OVERLAY-PLAN.json",
            self.prepared.plan_bytes,
            mode=0o600,
        )
        legacy.atomic_write(
            self.backup_root / "PRESTATE.json",
            legacy.canonical(self.prepared.prestate),
            mode=0o600,
        )
        for name, payload in self.prepared.prestate_payloads.items():
            legacy.atomic_write(self.backup_root / name, payload, mode=0o600)

    def consume_attempt(self) -> int:
        legacy.require(legacy._attempt_count() == 0, "policy_overlay_attempt_lineage_drifted")
        legacy.STATE_ROOT.mkdir(parents=True, mode=0o700)
        os.chown(legacy.STATE_ROOT, 0, 0)
        os.chmod(legacy.STATE_ROOT, 0o700)
        legacy.atomic_write(
            legacy.ATTEMPT_LEDGER,
            legacy.canonical(
                {
                    "attempts": 1,
                    "last_plan_sha256": self.composite.plan_digest,
                    "schema": legacy.ATTEMPT_SCHEMA,
                }
            ),
            mode=0o600,
        )
        return 1


def activate(
    prepared: PreparedCompositeActivation,
    *,
    expected_plan_sha256: str | None,
    preflight_only: bool,
) -> dict[str, object]:
    _verify_evidence(prepared.evidence_paths)
    _verify_live_lineages()
    if expected_plan_sha256 is not None:
        require(prepared.plan_digest == expected_plan_sha256, "composite_plan_drifted")
    if preflight_only:
        return preflight_projection(prepared)
    require(expected_plan_sha256 is not None, "composite_expected_plan_required")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backend = CompositeBackend(prepared)
    journal = legacy.STATE_ROOT / f"JOURNAL-{stamp}-{prepared.plan_digest[:12]}.json"
    try:
        result = legacy.AtomicPolicyOverlayTransaction(backend).run()
        receipt = {
            "attempt": result.attempt,
            "channel_called": False,
            "composite_id": prepared.composite_manifest["composite_id"],
            "health_called": False,
            "model_called": False,
            "plan_sha256": prepared.plan_digest,
            "private_content_read": False,
            "provider_called": False,
            "schema": SCHEMA,
            "status": "ACTIVE_WAITING_OWNER_ORGANIC_TELEGRAM_E2E",
        }
        legacy.atomic_write(journal, canonical(receipt), mode=0o600)
        legacy.atomic_write(
            legacy.STATE_ROOT / f"RECEIPT-{stamp}-{prepared.plan_digest[:12]}.json",
            canonical(receipt),
            mode=0o600,
        )
        return receipt
    except legacy.PolicyOverlayTransactionRejected as exc:
        failure = {
            "attempt": 1,
            **legacy._failure_projection(exc),
            "plan_sha256": prepared.plan_digest,
            "schema": SCHEMA,
            "status": (
                "hard_stop_rollback_failed"
                if exc.rollback_failure_code is not None
                else "activation_failed_rollback_verified"
            ),
        }
        if legacy.STATE_ROOT.exists():
            legacy.atomic_write(journal, canonical(failure), mode=0o600)
            legacy.atomic_write(
                legacy.STATE_ROOT / f"RECEIPT-{stamp}-{prepared.plan_digest[:12]}.json",
                canonical(failure),
                mode=0o600,
            )
        raise


def parser() -> object:
    selected = legacy.parser()
    selected.add_argument("--composite-bundle", type=Path, required=True)
    selected.add_argument("--p07-rejected-call-evidence", type=Path, required=True)
    selected.add_argument("--p10-handoff", type=Path, required=True)
    selected.add_argument("--p09-handoff", type=Path, required=True)
    selected.add_argument("--p16-handoff", type=Path, required=True)
    selected.add_argument("--p01-handoff", type=Path, required=True)
    return selected


def main() -> int:
    arguments = parser().parse_args()  # type: ignore[union-attr]
    evidence = EvidencePaths(
        p07_rejected_call=arguments.p07_rejected_call_evidence.resolve(),
        p10_handoff=arguments.p10_handoff.resolve(),
        p09_handoff=arguments.p09_handoff.resolve(),
        p16_handoff=arguments.p16_handoff.resolve(),
        p01_handoff=arguments.p01_handoff.resolve(),
    )
    try:
        prepared = prepare_activation(
            composite_bundle=arguments.composite_bundle.resolve(),
            evidence_paths=evidence,
            core_source=arguments.core_source.resolve(),
            deploy_source=arguments.deploy_source.resolve(),
            core_candidate=arguments.core_candidate.resolve(),
            runtime_candidate=arguments.runtime_candidate.resolve(),
            plugin_candidate=arguments.plugin_candidate.resolve(),
            overlay_bundle=arguments.overlay_bundle.resolve(),
            core_commit=arguments.core_commit,
            deploy_commit=arguments.deploy_commit,
            expected_parent_release_set_id=arguments.expected_parent_release_set_id,
            expected_parent_manifest_digest=arguments.expected_parent_manifest_digest,
            expected_parent_selector_digest=arguments.expected_parent_selector_digest,
            expected_live_core_release=arguments.expected_live_core_release,
            expected_live_runtime_release=arguments.expected_live_runtime_release,
            expected_plugin_release=arguments.expected_plugin_release,
            expected_plugin_config_digest=arguments.expected_plugin_config_digest,
            expected_effective_v6_digest=arguments.expected_effective_v6_digest,
            expected_revision=arguments.expected_revision,
            expected_turns=arguments.expected_turns,
            expected_summaries=arguments.expected_summaries,
            expected_attempts=arguments.expected_attempts,
        )
        result = activate(
            prepared,
            expected_plan_sha256=arguments.expected_plan_sha256,
            preflight_only=arguments.preflight_only,
        )
    except Exception as exc:
        failure = getattr(exc, "code", None) or legacy._failure_projection(exc)["failure_gate"]
        print(json.dumps({"failure_gate": failure, "schema": SCHEMA, "status": "rejected"}, separators=(",", ":"), sort_keys=True))
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
