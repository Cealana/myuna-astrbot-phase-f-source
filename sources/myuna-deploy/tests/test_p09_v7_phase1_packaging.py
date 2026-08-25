from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from scripts import activate_p07_hybrid_external_generation_v1 as activation
from scripts import build_p07_hybrid_live_releases_v1 as builder
from scripts import p09_v7_phase1_packaging_contract as contract


class P09V7Phase1PackagingTests(unittest.TestCase):
    def test_contract_is_exact_narrow_and_content_free(self) -> None:
        self.assertEqual(contract.RUNTIME_PROFILE, "p09-v7-phase1-v2")
        self.assertEqual(
            contract.CORE_COMMIT,
            "000b5f1a8bb3c0fca9885b0ff5387087bceaa37c",
        )
        self.assertEqual(
            set(contract.CORE_SOURCE_FILES),
            {
                "src/myuna_core/conversation.py",
                "src/myuna_core/definition_profile.py",
            },
        )
        self.assertIn("myuna_core/definition_profile.py", contract.CORE_FILES)
        payload = contract.contract_payload()
        self.assertFalse(payload["dynamic_affinity_state"])
        self.assertFalse(payload["affinity_persistence"])
        self.assertFalse(payload["profile_or_session_writes"])
        self.assertFalse(payload["legacy_trust_migration"])
        self.assertEqual(payload["runtime_profile"], contract.RUNTIME_PROFILE)
        affinity = payload["structured_affinity_foundation"]
        self.assertEqual(affinity["schema"], "myuna.structured-affinity.v1")
        self.assertEqual(
            affinity["capability_digest"],
            "bc28be2f125bb7099859dd366d54d59f48053db670ad2d841482c15fa50d5096",
        )
        self.assertFalse(affinity["active"])
        self.assertFalse(affinity["packaged"])
        serialized = json.dumps(payload, sort_keys=True)
        for forbidden in ("secret", "token", "database_row", "private_message"):
            self.assertNotIn(forbidden, serialized)

    def test_baseline_profile_and_v6_projection_remain_unchanged(self) -> None:
        from scripts.p09_v7_phase1_projection.conversation import local_core_sections_paths

        self.assertEqual(builder._BASELINE_RUNTIME_PROFILE, "p07-hybrid-v2")
        self.assertEqual(local_core_sections_paths("v5"), ("SKILL.md",))
        self.assertEqual(local_core_sections_paths("v6"), ("SKILL.md",))
        self.assertEqual(
            local_core_sections_paths("v7"),
            ("SKILL.md", contract.CAPABILITY_BOUNDARY),
        )

    def test_contract_mismatch_fails_closed(self) -> None:
        payload = contract.contract_payload()
        payload["dynamic_affinity_state"] = True
        with self.assertRaises(contract.V7PackagingContractRejected):
            contract.validate_runtime_contract(
                payload,
                core_commit=contract.CORE_COMMIT,
                roots=contract.CORE_ROOT_MODULES,
                core_files=contract.CORE_FILES,
                runtime_files=[f"runtime/{path}" for path in contract.PROJECTION_FILES],
            )

    def test_legacy_profile_is_immutable_and_mixed_contract_fails_closed(self) -> None:
        legacy = contract.contract_payload(contract.LEGACY_RUNTIME_PROFILE)
        self.assertEqual(
            contract.core_commit_for(contract.LEGACY_RUNTIME_PROFILE),
            "949759c3b6a560b9e10aeee5c01d420ed627bbef",
        )
        self.assertEqual(
            legacy["schema"],
            "myuna.p09-v7-phase1-runtime-projection.v1",
        )
        self.assertNotIn("runtime_profile", legacy)
        self.assertNotIn("structured_affinity_foundation", legacy)
        self.assertNotIn(
            "myuna_core.external_context.policy_overlay",
            contract.core_root_modules_for(contract.LEGACY_RUNTIME_PROFILE),
        )
        self.assertNotIn(
            "myuna_core/external_context/policy_overlay.py",
            contract.core_files_for(contract.LEGACY_RUNTIME_PROFILE),
        )
        self.assertIn(
            "myuna_core.external_context.policy_overlay",
            contract.core_root_modules_for(contract.RUNTIME_PROFILE),
        )
        self.assertIn(
            "myuna_core/external_context/policy_overlay.py",
            contract.core_files_for(contract.RUNTIME_PROFILE),
        )
        with self.assertRaises(contract.V7PackagingContractRejected):
            contract.validate_runtime_contract(
                legacy,
                runtime_profile=contract.RUNTIME_PROFILE,
                core_commit=contract.CORE_COMMIT,
                roots=contract.CORE_ROOT_MODULES,
                core_files=contract.CORE_FILES,
                runtime_files=[f"runtime/{path}" for path in contract.PROJECTION_FILES],
            )
        with self.assertRaises(contract.V7PackagingContractRejected):
            contract.validate_runtime_contract(
                contract.contract_payload(),
                core_commit="0" * 40,
                roots=contract.CORE_ROOT_MODULES,
                core_files=contract.CORE_FILES,
                runtime_files=[f"runtime/{path}" for path in contract.PROJECTION_FILES],
            )

    @unittest.skipUnless(os.environ.get("P09_V7_CORE_SOURCE"), "exact Core candidate path required")
    def test_exact_core_candidate_source_and_inventory(self) -> None:
        core = Path(os.environ["P09_V7_CORE_SOURCE"])
        contract.validate_core_source(core, contract.CORE_COMMIT)
        baseline = builder.runtime_core_import_closure(core)
        v7 = builder.runtime_core_import_closure(
            core,
            root_modules=contract.CORE_ROOT_MODULES,
        )
        self.assertEqual(v7, contract.CORE_FILES)
        self.assertEqual(set(v7) - set(baseline), {"myuna_core/definition_profile.py"})
        self.assertEqual(set(baseline) - set(v7), set())
        self.assertFalse(
            any(
                path.startswith(prefix)
                for path in contract.CORE_FILES
                for prefix in contract.FORBIDDEN_ADDED_CORE_PREFIXES
            )
        )

    @unittest.skipUnless(
        os.geteuid() == 0
        and os.environ.get("P09_V7_CORE_SOURCE")
        and os.environ.get("P09_V7_DEPLOY_SOURCE")
        and os.environ.get("P09_V7_DEPLOY_COMMIT")
        and os.environ.get("P09_V7_RUNTIME_BASE"),
        "exact root service-identity build inputs required",
    )
    def test_deterministic_build_validate_and_service_identity_import(self) -> None:
        core = Path(os.environ["P09_V7_CORE_SOURCE"])
        deploy = Path(os.environ["P09_V7_DEPLOY_SOURCE"])
        deploy_commit = os.environ["P09_V7_DEPLOY_COMMIT"]
        base = Path(os.environ["P09_V7_RUNTIME_BASE"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = builder.build_runtime(
                deploy,
                deploy_commit,
                core,
                contract.CORE_COMMIT,
                base,
                root / "first",
                contract.RUNTIME_PROFILE,
            )
            second = builder.build_runtime(
                deploy,
                deploy_commit,
                core,
                contract.CORE_COMMIT,
                base,
                root / "second",
                contract.RUNTIME_PROFILE,
            )
            self.assertEqual(first, second)
            digest = first["release_digest"]
            candidate = root / "first" / digest
            self.assertEqual(
                activation.validate_runtime(candidate, contract.CORE_COMMIT, deploy_commit),
                digest,
            )
            activation.verify_runtime_startup_smoke(candidate)
            self.assertFalse(any(path.suffix == ".pyc" for path in candidate.rglob("*")))
            self.assertFalse(any(path.name == "__pycache__" for path in candidate.rglob("*")))

            with self.assertRaises(activation.ActivationRejected) as wrong_core:
                activation.validate_runtime(candidate, "0" * 40, deploy_commit)
            self.assertEqual(wrong_core.exception.code, "runtime_core_commit_rejected")

            missing = root / "missing" / digest
            shutil.copytree(candidate, missing)
            projection = missing / "runtime/p09_v7_phase1_projection/conversation.py"
            projection.parent.chmod(0o750)
            projection.unlink()
            projection.parent.chmod(0o550)
            with self.assertRaises(activation.ActivationRejected):
                activation.validate_runtime(missing, contract.CORE_COMMIT, deploy_commit)

            mismatched = root / "mismatched" / digest
            shutil.copytree(candidate, mismatched)
            manifest_path = mismatched / "P07_HYBRID_MANIFEST.json"
            manifest_path.chmod(0o640)
            manifest = json.loads(manifest_path.read_text("ascii"))
            manifest["runtime_profile"] = "p09-v7-phase1-v3"
            manifest_path.write_text(
                json.dumps(manifest, separators=(",", ":"), sort_keys=True) + "\n",
                encoding="ascii",
            )
            manifest_path.chmod(0o440)
            with self.assertRaises(activation.ActivationRejected) as wrong_version:
                activation.validate_runtime(mismatched, contract.CORE_COMMIT, deploy_commit)
            self.assertEqual(wrong_version.exception.code, "runtime_profile_rejected")


if __name__ == "__main__":
    unittest.main()
