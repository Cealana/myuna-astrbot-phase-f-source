from __future__ import annotations

from pathlib import Path
from hashlib import sha256
import json
import stat
import tempfile
import unittest

import build_p07_owner_private_memory_transactional_runtime as builder
import p07_owner_private_memory_runtime_artifact_v1 as runtime_artifact
import p07_owner_private_memory_transactional_runtime as runtime


class TransactionalRuntimeBuildTest(unittest.TestCase):
    def setUp(self) -> None:
        self.source = Path(__file__).resolve().parents[1]
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def build(self, name: str) -> tuple[Path, dict[str, object]]:
        output = self.root / name
        deploy_commit = builder.git(self.source, "rev-parse", "HEAD")
        deploy_tree = builder.git(self.source, "rev-parse", "HEAD^{tree}")

        def exact_runtime(
            _candidate: Path, **kwargs: object
        ) -> tuple[str, dict[str, object]]:
            plugin_binding = kwargs["plugin_binding"]
            payload = b"synthetic-runtime-bundle-artifact\n"
            files = {
                "runtime/bundle.py": {
                    "mode": runtime_artifact.FILE_MODE,
                    "sha256": sha256(payload).hexdigest(),
                    "size": len(payload),
                }
            }
            binding = runtime_artifact.build_binding(
                source_core_commit=runtime.CORE_SOURCE_COMMIT,
                source_core_tree=runtime.CORE_SOURCE_TREE,
                source_deploy_commit=deploy_commit,
                source_deploy_tree=deploy_tree,
                base_release_digest="1" * 64,
                file_inventory=files,
                plugin_binding=plugin_binding,
                memory_contract=runtime_artifact.MEMORY_CONTRACT,
                source_policy=builder.production.source_policy(),
                program_boundaries=builder.production.source_boundaries(),
            )
            unsigned = {
                "base_release_digest": "1" * 64,
                "core_import_closure": {
                    "algorithm": "synthetic",
                    "files": [],
                    "roots": [],
                },
                "files": files,
                "owner_private_memory_contract": runtime_artifact.MEMORY_CONTRACT,
                "owner_private_memory_runtime_binding": binding,
                "runtime_profile": runtime_artifact.RUNTIME_PROFILE,
                "schema": runtime_artifact.HYBRID_RUNTIME_SCHEMA,
                "source_core_commit": runtime.CORE_SOURCE_COMMIT,
                "source_core_tree": runtime.CORE_SOURCE_TREE,
                "source_deploy_commit": deploy_commit,
                "source_deploy_tree": deploy_tree,
            }
            payload_manifest = {
                **unsigned,
                "release_digest": sha256(runtime_artifact.canonical(unsigned)).hexdigest(),
            }
            projection = runtime_artifact.projection_from_manifest(
                payload_manifest,
                manifest_bytes=runtime_artifact.canonical(payload_manifest),
            )
            return str(projection["release_digest"]), projection

        from unittest.mock import patch

        with patch.object(
            builder.production,
            "verify_runtime_artifact_candidate",
            side_effect=exact_runtime,
        ):
            manifest = builder.build_bundle(
                deploy_source=self.source,
                output_root=output,
                core_commit=runtime.CORE_SOURCE_COMMIT,
                deploy_commit=deploy_commit,
                runtime_candidate=self.root / "synthetic-runtime-locator",
            )
        return output, manifest

    def test_a_b_builds_are_byte_and_mode_identical_and_inactive(self) -> None:
        output_a, manifest_a = self.build("a")
        output_b, manifest_b = self.build("b")
        self.assertEqual(manifest_a, manifest_b)
        self.assertEqual(
            (output_a / "manifest.json").read_bytes(),
            (output_b / "manifest.json").read_bytes(),
        )
        self.assertEqual(manifest_a["source"]["core_commit"], runtime.CORE_SOURCE_COMMIT)
        self.assertEqual(manifest_a["source"]["deploy_parent_commit"], runtime.DEPLOY_PARENT_COMMIT)
        self.assertTrue(manifest_a["capabilities"]["production_adapter_source_present"])
        self.assertTrue(manifest_a["capabilities"]["after_payload_package_source_present"])
        self.assertTrue(
            manifest_a["capabilities"]["source_owned_request_constructor_present"]
        )
        self.assertTrue(
            manifest_a["capabilities"]["source_owned_request_collection_present"]
        )
        self.assertTrue(
            manifest_a["capabilities"]["source_owned_request_collection_closed"]
        )
        self.assertTrue(
            manifest_a["capabilities"]["failed_request_continuation_source_present"]
        )
        self.assertTrue(
            manifest_a["capabilities"]["p08_status_stage_projection_source_present"]
        )
        self.assertTrue(
            manifest_a["capabilities"][
                "p08_server_rejection_subprojection_source_present"
            ]
        )
        self.assertTrue(
            manifest_a["capabilities"][
                "context_bound_rejection_envelope_source_present"
            ]
        )
        self.assertFalse(
            manifest_a["capabilities"]["failed_request_continuation_materialized"]
        )
        self.assertEqual(
            manifest_a["failed_request_continuation_storage"],
            runtime.failed_request_continuation_storage_identity(),
        )
        self.assertEqual(
            manifest_a["plugin"]["source"]["deploy_commit"],
            manifest_a["source"]["deploy_commit"],
        )
        self.assertEqual(
            manifest_a["runtime_artifact"]["source"],
            {
                "core_commit": manifest_a["source"]["core_commit"],
                "core_tree": manifest_a["source"]["core_tree"],
                "deploy_commit": manifest_a["source"]["deploy_commit"],
                "deploy_tree": manifest_a["source"]["deploy_tree"],
            },
        )
        self.assertEqual(
            manifest_a["source_owned_artifact_roots"],
            runtime.source_owned_artifact_root_contract(),
        )
        self.assertIn(
            "docs/ADR-082-p07-source-owned-artifact-root-binding.md",
            builder.SOURCE_FILES,
        )
        self.assertIn(
            "docs/ADR-083-p07-context-bound-rejection-envelope.md",
            builder.SOURCE_FILES,
        )
        self.assertIn(
            "docs/ADR-084-p07-p08-server-rejection-integration.md",
            builder.SOURCE_FILES,
        )
        self.assertIn(
            "docs/ADR-085-p07-p08-current-selected-reconciliation.md",
            builder.SOURCE_FILES,
        )
        self.assertIn(
            "docs/ADR-087-p07-p08-single-nonce-stage-integration.md",
            builder.SOURCE_FILES,
        )
        self.assertIn("scripts/p08_temporal_service_v1.py", builder.SOURCE_FILES)
        self.assertIn(
            "systemd/myuna-active-temporal-context-v1.service",
            builder.SOURCE_FILES,
        )
        self.assertIn(
            "systemd/myuna-active-temporal-context-v1.socket",
            builder.SOURCE_FILES,
        )
        plugin_release = manifest_a["plugin"]["target"]["release_digest"]
        self.assertTrue((output_a / "telegram-plugin" / plugin_release).is_dir())
        self.assertTrue(
            all(
                value is False
                for key, value in manifest_a["capabilities"].items()
                if key
                not in {
                    "production_adapter_source_present",
                    "after_payload_package_source_present",
                    "context_bound_rejection_envelope_source_present",
                    "failed_request_continuation_source_present",
                    "immutable_continuation_reference_source_present",
                    "p08_server_rejection_subprojection_source_present",
                    "p08_status_stage_projection_source_present",
                    "source_derived_fresh_max1_strategy_present",
                    "source_owned_artifact_root_contract_present",
                    "source_owned_request_collection_closed",
                    "source_owned_request_collection_present",
                    "source_owned_request_constructor_present",
                    "status_invocation_evidence_source_present",
                }
            )
        )
        for relative in builder.SOURCE_FILES:
            first = output_a / relative
            second = output_b / relative
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(
                stat.S_IMODE(first.stat().st_mode), stat.S_IMODE(second.stat().st_mode)
            )
        self.assertFalse(
            any(
                "__pycache__" in path.as_posix()
                or path.suffix in {".pyc", ".pyo"}
                for path in output_a.rglob("*")
            )
        )

    def test_manifest_or_inventory_tamper_is_rejected(self) -> None:
        output, _ = self.build("tamper")
        target = output / "scripts/p07_owner_private_memory_transactional_runtime.py"
        target.write_bytes(target.read_bytes() + b"\n")
        with self.assertRaisesRegex(RuntimeError, "bundle_inventory_rejected"):
            builder.verify_bundle(output)

    def test_continuation_storage_path_role_substitution_is_rejected(self) -> None:
        _, manifest = self.build("storage-binding")
        drifted = json.loads(json.dumps(manifest))
        drifted["failed_request_continuation_storage"]["root"]["path"] = (
            "/var/lib/myuna-telegram-gateway/"
            "p07-owner-private-memory-failed-request-continuations-v1"
        )
        semantic = {key: drifted[key] for key in drifted if key != "bundle_id"}
        drifted["bundle_id"] = runtime.digest(
            runtime.BUNDLE_ID_DOMAIN, semantic
        )
        manifest_sha = sha256(runtime.canonical(drifted)).hexdigest()
        with self.assertRaisesRegex(RuntimeError, "storage_identity_rejected"):
            runtime.validate_runtime_artifact_manifest(
                drifted,
                manifest_sha256=manifest_sha,
                expected_bundle_id=drifted["bundle_id"],
                expected_manifest_sha256=manifest_sha,
            )

    def test_artifact_root_substitution_is_rejected_even_with_recomputed_digests(self) -> None:
        _, manifest = self.build("artifact-root-binding")
        drifted = json.loads(json.dumps(manifest))
        drifted["source_owned_artifact_roots"]["bundle_root"]["path"] = (
            "/srv/myuna/builds/p07-immutable-continuation-fresh-strategy-v1-final-bundle-a"
        )
        semantic = {key: drifted[key] for key in drifted if key != "bundle_id"}
        drifted["bundle_id"] = runtime.digest(runtime.BUNDLE_ID_DOMAIN, semantic)
        manifest_sha = sha256(runtime.canonical(drifted)).hexdigest()
        with self.assertRaisesRegex(RuntimeError, "artifact_root_contract_rejected"):
            runtime.validate_runtime_artifact_manifest(
                drifted,
                manifest_sha256=manifest_sha,
                expected_bundle_id=drifted["bundle_id"],
                expected_manifest_sha256=manifest_sha,
            )

    def test_source_validation_requires_clean_exact_descendant(self) -> None:
        responses = {
            ("rev-parse", "HEAD"): "c" * 40,
            ("status", "--porcelain"): " M source.py",
        }

        def fake_git(_source: Path, *arguments: str) -> str:
            return responses.get(arguments, "")

        from unittest.mock import patch

        with patch.object(builder, "git", side_effect=fake_git):
            with self.assertRaisesRegex(RuntimeError, "source_dirty"):
                builder.validate_source(self.source, "c" * 40)


if __name__ == "__main__":
    unittest.main()
