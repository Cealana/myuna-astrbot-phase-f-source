#!/usr/bin/env python3
"""Build the deterministic inactive P01-B/P16 incident-recovery bundle."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import activate_p07_hybrid_external_generation_v1 as p07
import build_p16_phase1_t2_releases_v1 as p16_builder
from p01b_p16_successor_contract_v1 import (
    BUNDLE_SCHEMA,
    build_bundle,
    canonical,
    digest,
    validate_epoch_anchor_binding,
)
from p16_phase1_t2_contract_v1 import validate_bundle as validate_p16_bundle


CONTROLLER_SOURCE = "scripts/activate_p01b_p16_successor_v1.py"
P16_RECEIPT_DIGEST = (
    "1d708c6ed927a96cba200cc430af5bfc7137db1316b47f2765f12df9fd5a181b"
)
LEGACY_ATTEMPT_FILE_SHA256 = (
    "a97d3f741665f77c1b92ea15e0153c3005980eb5679f7d9c9e461a14c54183b5"
)
LEGACY_FAILURE_RECEIPT_FILE_SHA256 = (
    "4a29d9fed140fd83393e3bbd810dd87430532c3ccf8652c07001669751017725"
)
RECOVERY_ATTEMPT_SERIES_ID = (
    "10b60c58c577688dcb3f2c63e53b904f8e9f6938fbf28509255f41b85d61106b"
)
RECOVERY_STRATEGY_ID = (
    "5d3e593692eb9430f07e122310fe9d77a6c6d45cb03887ccb739e2c6cbe742b3"
)
RECOVERY_LINEAGE_DIGEST = (
    "614510f5885ec02fe21d35ff69f9082ed47ae23613d2339cec3f0db227e18ab9"
)
RECOVERY_BUNDLE_DIGEST = (
    "9b9b63d865918ae504a1098905d8918853fd5ce83575329894b8ab053b15eb29"
)
RECOVERY_BUNDLE_MANIFEST_SHA256 = (
    "39f69c9bcfd003dfcb6122f2a7beaa602c35068c4f291aa07774f6a1bf5e742d"
)
RECOVERY_LIVE_PLAN_DIGEST = (
    "454e4de5a9cb085cfe789ac1b8fb31ca4a98ef77a3b97676173799de36a8fd0f"
)
RECOVERY_ATTEMPT_FILE_SHA256 = (
    "63087bf636f149a95a99e27b11c0929dbf70db77a83e76f4fde446154b475ca6"
)
RECOVERY_ATTEMPT_DIGEST = (
    "2af038facfb1e9779a300e7a057d0289c3ac9178004935c3ec7ab9102c97666c"
)
RECOVERY_FAILURE_RECEIPT_FILE_SHA256 = (
    "718a3756d864023a66edaaa9e702d6ea37320d0314259aafe67e933636050277"
)
RECOVERY_FAILURE_RECEIPT_DIGEST = (
    "c1c3687159e73b0d119e8950da3e1504a0614f9725bf5a0c7ba2b4b6821c0192"
)
OWNER_EPOCH_ANCHOR_FILE_SHA256 = (
    "4cf767768f4d4b8e7f31d6a7b9a5a31e6b1464f6dda26bee7f115053a698ec48"
)
OWNER_EPOCH_ANCHOR_DIGEST = (
    "34a162367729238c525fc93de9326899f15cc31cef3bd175718eba931b87f2ca"
)
OWNER_EPOCH_ANCHOR_SOURCE_HANDOFF_SHA256 = (
    "ed258711ceb958beba48a0f96a6af944cab5bf3771e7d35b5302b301e22d6588"
)
OWNER_EPOCH_ANCHOR_CHECKPOINT = {
    "abandoned_delivery_count": 0,
    "blocked_summary_count": 0,
    "delivered_intent_count": 51,
    "delivery_in_progress_count": 0,
    "max_revision": 63,
    "metadata_digest": (
        "4ad4f5f4de7219ee2661ee60d5448c1f53b11334515d353a4fd296914c99eadf"
    ),
    "pending_count": 0,
    "queued_summary_count": 0,
    "selected_revision": 63,
    "summary_count": 12,
    "turn_count": 51,
}


def _git_head(root: Path) -> str:
    completed = subprocess.run(
        ["/usr/sbin/runuser", "-u", "myuna", "--", "git", "-C", str(root), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if completed.returncode != 0:
        raise ValueError("source identity unavailable")
    head = completed.stdout.strip()
    status = subprocess.run(
        [
            "/usr/sbin/runuser",
            "-u",
            "myuna",
            "--",
            "git",
            "-C",
            str(root),
            "status",
            "--porcelain",
            "--untracked-files=no",
        ],
        check=False,
        capture_output=True,
        timeout=10,
    )
    if status.returncode != 0 or status.stdout != b"":
        raise ValueError("source is not clean")
    return head


def _manifest(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("manifest unavailable")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("manifest rejected")
    return value


def _owner_epoch_anchor(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Owner epoch anchor unavailable")
    raw = path.read_bytes()
    value = json.loads(raw)
    if raw != canonical(value) + b"\n":
        raise ValueError("Owner epoch anchor is not canonical")
    binding = validate_epoch_anchor_binding(
        {**value, "anchor_file_sha256": sha256(raw).hexdigest()}
    )
    if (
        binding["anchor_file_sha256"] != OWNER_EPOCH_ANCHOR_FILE_SHA256
        or binding["anchor_digest"] != OWNER_EPOCH_ANCHOR_DIGEST
        or binding["source_handoff_sha256"]
        != OWNER_EPOCH_ANCHOR_SOURCE_HANDOFF_SHA256
        or binding["accepted_checkpoint"] != OWNER_EPOCH_ANCHOR_CHECKPOINT
    ):
        raise ValueError("Owner epoch anchor drifted")
    return binding


def _copy_tree(source: Path, component: Path) -> Path:
    if source.is_symlink() or not source.is_dir() or len(source.name) != 64:
        raise ValueError("artifact source rejected")
    destination = component / source.name
    component.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        current, _ = p16_builder._inventory(destination)
        expected, _ = p16_builder._inventory(source)
        if current != expected:
            raise ValueError("existing artifact drifted")
        return destination
    temporary = Path(tempfile.mkdtemp(prefix=".p01b-successor-", dir=component))
    try:
        p16_builder.p16_builder._remove_temporary_tree(temporary)
        shutil.copytree(source, temporary, symlinks=True)
        p16_builder._freeze(temporary)
        os.replace(temporary, destination)
    except BaseException:
        if temporary.exists():
            p16_builder.p16_builder._remove_temporary_tree(temporary)
        raise
    return destination


def _record(root: Path) -> tuple[dict[str, object], dict[str, object]]:
    return p16_builder._artifact_record(root)


def build_successor(
    *,
    core_source_root: Path,
    deploy_source_root: Path,
    predecessor_bundle_root: Path,
    runtime_candidate: Path,
    plugin_candidate: Path,
    accepted_epoch_anchor: Path,
    output_root: Path,
) -> dict[str, object]:
    core_commit = _git_head(core_source_root)
    deploy_commit = _git_head(deploy_source_root)
    controller = deploy_source_root / CONTROLLER_SOURCE
    if controller.is_symlink() or not controller.is_file():
        raise ValueError("controller source unavailable")
    p16_manifest_path = predecessor_bundle_root / "P16_PHASE1_T2_BUNDLE.json"
    predecessor = validate_p16_bundle(_manifest(p16_manifest_path))
    p16_manifest_raw = p16_manifest_path.read_bytes()
    epoch_anchor = _owner_epoch_anchor(accepted_epoch_anchor)

    runtime_digest = p07.validate_runtime(runtime_candidate, core_commit, deploy_commit)
    p07.verify_runtime_startup_smoke(runtime_candidate)
    plugin_digest = p07.validate_plugin(plugin_candidate)
    if runtime_candidate.name != runtime_digest or plugin_candidate.name != plugin_digest:
        raise ValueError("candidate directory identity rejected")

    predecessor_artifacts = predecessor["artifacts"]
    sources = {
        "core": predecessor_bundle_root
        / "core"
        / predecessor_artifacts["core"]["release_digest"],
        "telegram_runtime": runtime_candidate,
        "telegram_plugin": plugin_candidate,
        "p16_adapter": predecessor_bundle_root
        / "p16_adapter"
        / predecessor_artifacts["p16_adapter"]["release_digest"],
    }
    output_root.mkdir(parents=True, exist_ok=True)
    built = {name: _copy_tree(source, output_root / name) for name, source in sources.items()}
    inventory_root = output_root / "inventories"
    inventory_root.mkdir(exist_ok=True)
    records: dict[str, object] = {}
    for name, root in built.items():
        record, inventory = _record(root)
        records[name] = record
        payload = canonical(inventory) + b"\n"
        path = inventory_root / f"{name}.json"
        if path.exists():
            if path.is_symlink() or path.read_bytes() != payload:
                raise ValueError("inventory drifted")
        else:
            path.write_bytes(payload)
            path.chmod(0o440)

    if records["core"] != predecessor_artifacts["core"]:
        raise ValueError("predecessor Core was not preserved")
    if records["p16_adapter"] != predecessor_artifacts["p16_adapter"]:
        raise ValueError("predecessor P16 adapter was not preserved")

    lineage = predecessor["attempt_lineage"]
    identity = {
        "schema": BUNDLE_SCHEMA,
        "status": "built_inactive",
        "core_source_commit": core_commit,
        "deploy_source_commit": deploy_commit,
        "controller_source_sha256": sha256(controller.read_bytes()).hexdigest(),
        "predecessor": {
            "bundle_digest": predecessor["bundle_digest"],
            "bundle_manifest_sha256": sha256(p16_manifest_raw).hexdigest(),
            "attempt_series_id": lineage["attempt_series_id"],
            "strategy_digest": digest(
                "myuna-p01b-predecessor-p16-strategy-v1",
                lineage["strategy_id"],
            ),
            "attempts": 1,
            "maximum_attempts": 2,
            "activation_receipt_digest": P16_RECEIPT_DIGEST,
            "artifacts": predecessor_artifacts,
            "content_free": True,
        },
        "incident_predecessor": {
            "legacy_attempt": 1,
            "legacy_maximum_attempts": 2,
            "legacy_attempt2_prohibited": True,
            "legacy_attempt_file_sha256": LEGACY_ATTEMPT_FILE_SHA256,
            "legacy_failure_receipt_file_sha256": LEGACY_FAILURE_RECEIPT_FILE_SHA256,
            "legacy_failure_status": "hard_stop_rollback_failed",
            "legacy_failure_stage": "verify_target_before_marker",
            "legacy_failure_gate": "target_service_inactive",
            "legacy_rollback": "failed",
            "legacy_rollback_gate": "rollback_prestate_rejected",
            "content_free": True,
        },
        "recovery_predecessor": {
            "attempt": 1,
            "maximum_attempts": 2,
            "attempt2_authorized": False,
            "attempt_file_sha256": RECOVERY_ATTEMPT_FILE_SHA256,
            "attempt_digest": RECOVERY_ATTEMPT_DIGEST,
            "attempt_series_id": RECOVERY_ATTEMPT_SERIES_ID,
            "bundle_digest": RECOVERY_BUNDLE_DIGEST,
            "bundle_manifest_sha256": RECOVERY_BUNDLE_MANIFEST_SHA256,
            "strategy_id": RECOVERY_STRATEGY_ID,
            "lineage_digest": RECOVERY_LINEAGE_DIGEST,
            "live_plan_digest": RECOVERY_LIVE_PLAN_DIGEST,
            "failure_receipt_file_sha256": RECOVERY_FAILURE_RECEIPT_FILE_SHA256,
            "failure_receipt_digest": RECOVERY_FAILURE_RECEIPT_DIGEST,
            "failure_status": "hard_stop_rollback_failed",
            "failure_stage": "verify_target_before_marker",
            "failure_gate": (
                "target_telegram_telegram_readiness_stability_convergence_timeout"
            ),
            "failure_service_alias": "telegram",
            "failure_phase": "telegram_readiness_stability",
            "rollback": "failed",
            "rollback_gate": "rollback_prestate_rejected",
            "content_free": True,
        },
        "epoch_anchor": epoch_anchor,
        "artifacts": records,
        "content_free": True,
    }
    bundle = build_bundle(identity)
    manifest = output_root / "P01B_P16_INCIDENT_RECOVERY_BUNDLE.json"
    expected = canonical(bundle) + b"\n"
    if manifest.exists():
        if manifest.is_symlink() or manifest.read_bytes() != expected:
            raise ValueError("successor manifest drifted")
    else:
        manifest.write_bytes(expected)
        manifest.chmod(0o440)
    return bundle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core-source-root", type=Path, required=True)
    parser.add_argument("--deploy-source-root", type=Path, required=True)
    parser.add_argument("--predecessor-bundle-root", type=Path, required=True)
    parser.add_argument("--runtime-candidate", type=Path, required=True)
    parser.add_argument("--plugin-candidate", type=Path, required=True)
    parser.add_argument("--accepted-epoch-anchor", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = build_successor(**vars(args))
    except (OSError, ValueError, json.JSONDecodeError):
        print(json.dumps({"status": "rejected"}, separators=(",", ":")))
        return 1
    print(
        json.dumps(
            {"bundle_digest": value["bundle_digest"], "status": "built_inactive"},
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
