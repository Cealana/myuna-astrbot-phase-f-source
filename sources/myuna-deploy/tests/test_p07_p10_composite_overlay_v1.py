from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import activate_p07_p10_composite_overlay_v1 as activation
import activate_p07_policy_overlay_v1 as legacy
import build_p07_p10_composite_overlay_v1 as builder
import p07_p10_composite_overlay_contract_v1 as contract


def legacy_prepared() -> legacy.PreparedPolicyOverlayActivation:
    parent = SimpleNamespace(release_set_id=contract.PARENT_RELEASE_SET_ID)
    overlay = SimpleNamespace(overlay_id="b" * 64)
    return legacy.PreparedPolicyOverlayActivation(  # type: ignore[arg-type]
        core_candidate=Path("/synthetic/core"),
        runtime_candidate=Path("/synthetic/runtime"),
        plugin_candidate=Path("/synthetic/plugin"),
        bundle_root=Path("/synthetic/composite/policy-overlay") / ("5" * 64),
        core_commit="1" * 40,
        deploy_commit="2" * 40,
        parent=parent,
        parent_manifest_digest=contract.PARENT_MANIFEST_SHA256,
        parent_selector_digest=contract.PARENT_SELECTOR_SHA256,
        overlay=overlay,
        overlay_documents={},
        overlay_bundle_manifest={"bundle_id": "5" * 64},
        core_release="6" * 64,
        runtime_release="7" * 64,
        plugin_release="8" * 64,
        plugin_config_digest="9" * 64,
        target_core_binding=b"binding\n",
        target_core_selector=b"selector\n",
        target_telegram_dropin=b"dropin\n",
        prestate={"files": {}, "live": {}},
        prestate_payloads={
            "CORE_BINDING": b"old-binding\n",
            "CORE_SELECTOR": b"old-selector\n",
            "TELEGRAM_DROPIN": b"old-dropin\n",
        },
        plan_bytes=(
            b'{"prestate_digest":"'
            + b"a" * 64
            + b'","schema":"synthetic"}\n'
        ),
        expected_revision=63,
        expected_turns=51,
        expected_summaries=12,
    )


def composite_prepared() -> activation.PreparedCompositeActivation:
    return activation.PreparedCompositeActivation(
        legacy_activation=legacy_prepared(),
        composite_bundle=Path("/synthetic/composite"),
        composite_manifest={
            "composite_id": "c" * 64,
            "p10_ingress": {"files": {}},
        },
        plan_bytes=b'{"schema":"synthetic-composite"}\n',
        evidence_paths=activation.EvidencePaths(
            p07_rejected_call=Path("/evidence/p07"),
            p10_handoff=Path("/evidence/p10"),
            p09_handoff=Path("/evidence/p09"),
            p16_handoff=Path("/evidence/p16"),
            p01_handoff=Path("/evidence/p01"),
        ),
    )


class CompositeContractTests(unittest.TestCase):
    def test_contract_is_closed_and_preserves_all_attempt_lineages(self) -> None:
        selected = contract.contract_payload()
        contract.require_exact_contract(selected)
        attempts = selected["attempt_lineages"]
        self.assertEqual(attempts["p07"]["consumed"], 0)
        self.assertEqual(attempts["p07"]["maximum"], 2)
        self.assertEqual(attempts["p07"]["rejected_formal_calls"], 1)
        self.assertEqual(attempts["p16"]["consumed"], 1)
        self.assertEqual(attempts["p16"]["maximum"], 2)
        self.assertEqual(attempts["p01"]["consumed"], 2)
        self.assertEqual(attempts["p01"]["maximum"], 2)

    def test_contract_keeps_effective_v6_and_p09_v7_inactive(self) -> None:
        selected = contract.contract_payload()
        self.assertEqual(selected["profile"]["runtime_profile"], "p07-hybrid-v2")
        self.assertIs(selected["profile"]["v7_selected"], False)
        self.assertIs(selected["profile"]["p09_affinity_active"], False)
        self.assertEqual(selected["parent"]["epoch_id"], contract.PARENT_EPOCH_ID)
        self.assertIs(selected["boundaries"]["fresh_epoch"], False)

    def test_policy_oracles_and_compressed_rollback_are_exact(self) -> None:
        selected = contract.contract_payload()["policy"]
        self.assertEqual(selected["request_max_characters"], 200_000)
        self.assertEqual(selected["projection_max_characters"], 199_000)
        self.assertEqual(selected["maximum_complete_turns"], 64)
        self.assertEqual(selected["compressed_rollback"], "overlay_absent_parent_exact")

    def test_p10_source_identity_rejects_missing_or_drifted_blob(self) -> None:
        exact = {
            path: {"git_blob": values[0], "sha256": values[1]}
            for path, values in contract.P10_SOURCE_IDENTITIES.items()
        }
        contract.require_source_identity(
            core_commit="1" * 40,
            deploy_commit="2" * 40,
            p10_files=exact,
        )
        missing = dict(exact)
        missing.pop(next(iter(missing)))
        with self.assertRaisesRegex(
            contract.CompositeContractRejected, "p10_source_inventory_rejected"
        ):
            contract.require_source_identity(
                core_commit="1" * 40,
                deploy_commit="2" * 40,
                p10_files=missing,
            )
        drifted = json.loads(json.dumps(exact))
        drifted[next(iter(drifted))]["sha256"] = "f" * 64
        with self.assertRaisesRegex(
            contract.CompositeContractRejected, "p10_source_identity_drifted"
        ):
            contract.require_source_identity(
                core_commit="1" * 40,
                deploy_commit="2" * 40,
                p10_files=drifted,
            )

    def test_historical_p10_ingress_blobs_remain_recoverable(self) -> None:
        root = Path(__file__).resolve().parents[1]
        for _relative, (blob, content_sha256) in contract.P10_SOURCE_IDENTITIES.items():
            completed = subprocess.run(
                [
                    "/usr/bin/git",
                    "-c",
                    f"safe.directory={root}",
                    "-C",
                    str(root),
                    "cat-file",
                    "blob",
                    blob,
                ],
                check=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(
                __import__("hashlib").sha256(completed.stdout).hexdigest(),
                content_sha256,
            )

    def test_regular_evidence_rejects_symlink_and_digest_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "evidence.md"
            target.write_bytes(b"evidence\n")
            expected = __import__("hashlib").sha256(target.read_bytes()).hexdigest()
            contract.require_regular_digest(target, expected, "evidence_rejected")
            link = root / "link.md"
            link.symlink_to(target)
            with self.assertRaisesRegex(
                contract.CompositeContractRejected, "evidence_rejected"
            ):
                contract.require_regular_digest(link, expected, "evidence_rejected")


class CompositeBuildTests(unittest.TestCase):
    def test_synthetic_bundle_is_deterministic_and_mixed_manifest_rejects(self) -> None:
        core_commit = "1" * 40
        deploy_commit = "2" * 40
        core_release = "6" * 64
        runtime_release = "7" * 64
        plugin_release = "8" * 64
        plugin_config = "9" * 64
        overlay_manifest = {
            "bundle_id": "5" * 64,
            "components": {
                "core_release_digest": core_release,
                "plugin_config_digest": plugin_config,
                "plugin_release_digest": plugin_release,
                "runtime_release_digest": runtime_release,
            },
            "parent_release_set_id": contract.PARENT_RELEASE_SET_ID,
            "source": {"core_commit": core_commit, "deploy_commit": deploy_commit},
        }
        p10 = {
            path: {"git_blob": values[0], "sha256": values[1]}
            for path, values in contract.P10_SOURCE_IDENTITIES.items()
        }
        p09 = {
            path: {"git_blob": "a" * 40, "sha256": "b" * 64}
            for path in builder.P09_COMPATIBILITY_PATHS
        }

        def projection(_source: Path, paths: object) -> dict[str, dict[str, str]]:
            return p10 if isinstance(paths, dict) else p09

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            core_source = root / "core-source"
            deploy_source = root / "deploy-source"
            core_candidate = root / core_release
            runtime_candidate = root / runtime_release
            plugin_candidate = root / plugin_release
            overlay_bundle = root / "overlay"
            for path in (
                core_source,
                deploy_source,
                core_candidate,
                runtime_candidate,
                plugin_candidate,
                overlay_bundle,
            ):
                path.mkdir()
            (runtime_candidate / "P16_MANIFEST.json").write_text("{}\n", "ascii")
            for name in (
                "bundle-manifest.json",
                "overlay-manifest.json",
                "overlay-marker.json",
                "overlay-selector.json",
                "overlay-state.json",
            ):
                (overlay_bundle / name).write_text(name + "\n", "ascii")
            parent = SimpleNamespace(release_set_id=contract.PARENT_RELEASE_SET_ID)
            core = SimpleNamespace(source_commit=core_commit, tree_sha256=core_release)
            with (
                patch.object(builder, "validate_source"),
                patch.object(
                    builder,
                    "load_parent_manifest",
                    return_value=(parent, contract.PARENT_MANIFEST_SHA256),
                ),
                patch.object(
                    builder,
                    "verify_overlay_bundle",
                    return_value=overlay_manifest,
                ),
                patch.object(builder, "core_evidence", return_value=(core, {}, {})),
                patch.object(builder, "validate_runtime", return_value=runtime_release),
                patch.object(builder, "validate_plugin", return_value=plugin_release),
                patch.object(builder, "_source_projection", side_effect=projection),
            ):
                first = builder.build_bundle(
                    output_root=root / "a",
                    core_source=core_source,
                    deploy_source=deploy_source,
                    parent_manifest=root / "parent.json",
                    core_candidate=core_candidate,
                    runtime_candidate=runtime_candidate,
                    plugin_candidate=plugin_candidate,
                    overlay_bundle=overlay_bundle,
                    core_commit=core_commit,
                    deploy_commit=deploy_commit,
                )
                second = builder.build_bundle(
                    output_root=root / "b",
                    core_source=core_source,
                    deploy_source=deploy_source,
                    parent_manifest=root / "parent.json",
                    core_candidate=core_candidate,
                    runtime_candidate=runtime_candidate,
                    plugin_candidate=plugin_candidate,
                    overlay_bundle=overlay_bundle,
                    core_commit=core_commit,
                    deploy_commit=deploy_commit,
                )
                self.assertEqual(first, second)
                first_root = root / "a" / first["composite_id"]
                second_root = root / "b" / second["composite_id"]
                self.assertEqual(
                    {
                        path.relative_to(first_root).as_posix(): path.read_bytes()
                        for path in first_root.rglob("*")
                        if path.is_file()
                    },
                    {
                        path.relative_to(second_root).as_posix(): path.read_bytes()
                        for path in second_root.rglob("*")
                        if path.is_file()
                    },
                )
                manifest_path = first_root / "composite-manifest.json"
                mixed = json.loads(manifest_path.read_text("ascii"))
                mixed["p09_source_compatibility"]["v7_selected"] = True
                manifest_path.write_bytes(contract.canonical(mixed))
                with self.assertRaises(contract.CompositeContractRejected):
                    builder.verify_bundle(
                        first_root,
                        core_source=core_source,
                        deploy_source=deploy_source,
                        parent_manifest=root / "parent.json",
                        core_candidate=core_candidate,
                        runtime_candidate=runtime_candidate,
                        plugin_candidate=plugin_candidate,
                        core_commit=core_commit,
                        deploy_commit=deploy_commit,
                    )


class CompositeActivationTests(unittest.TestCase):
    def test_preflight_projection_is_deterministic_and_content_free(self) -> None:
        prepared = composite_prepared()
        first = activation.preflight_projection(prepared)
        second = activation.preflight_projection(prepared)
        self.assertEqual(first, second)
        self.assertEqual(first["new_sequence_required_calls"], 2)
        self.assertEqual(first["prior_rejected_formal_calls_preserved"], 1)
        self.assertEqual(first["attempts"], 0)
        for field in (
            "channel_called",
            "health_called",
            "model_called",
            "mutation_performed",
            "private_content_read",
            "provider_called",
        ):
            self.assertIs(first[field], False)

    def test_plan_mismatch_rejects_before_backend_or_transaction(self) -> None:
        prepared = composite_prepared()
        with (
            patch.object(activation, "_verify_evidence"),
            patch.object(activation, "_verify_live_lineages"),
            patch.object(activation, "CompositeBackend") as backend,
        ):
            with self.assertRaisesRegex(
                contract.CompositeContractRejected, "composite_plan_drifted"
            ):
                activation.activate(
                    prepared,
                    expected_plan_sha256="f" * 64,
                    preflight_only=False,
                )
        backend.assert_not_called()

    def test_prepare_wraps_underlying_plan_and_preserves_rejected_call(self) -> None:
        selected = legacy_prepared()
        manifest = {
            "artifacts": {
                "core_release": selected.core_release,
                "plugin_release": selected.plugin_release,
                "runtime_release": selected.runtime_release,
            },
            "composite_id": "c" * 64,
            "overlay_bundle": {"bundle_id": selected.overlay_bundle_manifest["bundle_id"]},
            "p10_ingress": {"files": {"synthetic": {"git_blob": "a", "sha256": "b"}}},
            "source": {"core_commit": selected.core_commit, "deploy_commit": selected.deploy_commit},
        }
        evidence = composite_prepared().evidence_paths
        with (
            patch.object(activation, "_verify_evidence"),
            patch.object(activation, "_verify_live_lineages"),
            patch.object(activation.legacy, "prepare_activation", return_value=selected),
            patch.object(activation, "verify_bundle", return_value=manifest),
        ):
            prepared = activation.prepare_activation(
                composite_bundle=Path("/synthetic/composite"),
                evidence_paths=evidence,
                core_source=Path("/synthetic/core-source"),
                deploy_source=Path("/synthetic/deploy-source"),
                core_candidate=Path("/synthetic/core"),
                runtime_candidate=Path("/synthetic/runtime"),
                plugin_candidate=Path("/synthetic/plugin"),
                core_commit=selected.core_commit,
                deploy_commit=selected.deploy_commit,
                overlay_bundle=Path("/synthetic/composite/policy-overlay")
                / ("5" * 64),
            )
        plan = json.loads(prepared.plan_bytes.decode("ascii"))
        self.assertEqual(plan["underlying_policy_overlay_plan_sha256"], selected.plan_digest)
        self.assertEqual(plan["attempt_lineages"]["p07"]["consumed"], 0)
        self.assertEqual(
            plan["attempt_lineages"]["p07"]["rejected_formal_calls_preserved"],
            1,
        )
        self.assertEqual(plan["future_rollback_order"][0], "remove_overlay_marker")

    def test_controller_reuses_existing_p07_attempt_namespace(self) -> None:
        self.assertEqual(
            legacy.STATE_ROOT,
            Path("/var/lib/myuna-telegram-gateway/p07-policy-overlay-v1"),
        )
        self.assertEqual(
            legacy.BACKUP_ROOT,
            Path("/var/backups/myuna/p07-policy-overlay-v1"),
        )
        self.assertEqual(legacy.ATTEMPT_LEDGER, legacy.STATE_ROOT / "ATTEMPT_LEDGER.json")
        self.assertEqual(legacy.MAX_ATTEMPTS, 2)

    @unittest.skipUnless(__import__("os").geteuid() == 0, "root-only metadata fixture")
    def test_composite_backup_is_durable_before_shared_attempt_consumption(self) -> None:
        prepared = composite_prepared()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup_root = root / "backups" / "series"
            state_root = root / "state" / "series"
            overlay_parent = root / "overlay"
            for path in (backup_root.parent, state_root.parent, overlay_parent):
                path.mkdir(parents=True, mode=0o700)
            backend = activation.CompositeBackend(prepared)
            with (
                patch.object(legacy, "BACKUP_ROOT", backup_root),
                patch.object(legacy, "STATE_ROOT", state_root),
                patch.object(legacy, "ATTEMPT_LEDGER", state_root / "ATTEMPT_LEDGER.json"),
                patch.object(
                    legacy,
                    "POLICY_OVERLAY_MANIFEST_PATH",
                    overlay_parent / "overlay.json",
                ),
                patch.object(backend, "backup_root", backup_root / prepared.plan_digest),
            ):
                backend.create_plan_bound_backup()
                self.assertTrue((backend.backup_root / "PLAN.json").is_file())
                self.assertFalse((state_root / "ATTEMPT_LEDGER.json").exists())
                self.assertEqual(backend.consume_attempt(), 1)
                ledger = json.loads(
                    (state_root / "ATTEMPT_LEDGER.json").read_text("ascii")
                )
                self.assertEqual(ledger["attempts"], 1)
                self.assertEqual(ledger["last_plan_sha256"], prepared.plan_digest)

    def test_composite_plan_declares_marker_first_rollback(self) -> None:
        selected = list(contract.FUTURE_ROLLBACK_ORDER)
        self.assertEqual(selected[0], "remove_overlay_marker")
        self.assertLess(selected.index("remove_overlay_marker"), selected.index("restore_core_runtime_bindings"))
        self.assertLess(
            contract.FUTURE_ACTIVATION_ORDER.index("plan_bound_backup"),
            contract.FUTURE_ACTIVATION_ORDER.index("consume_shared_p07_attempt"),
        )


if __name__ == "__main__":
    unittest.main()
