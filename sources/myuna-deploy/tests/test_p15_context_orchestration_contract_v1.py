from __future__ import annotations

from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import unittest


SCRIPT = Path(__file__).parents[1] / "scripts" / "p15_context_orchestration_contract_v1.py"
SPEC = importlib.util.spec_from_file_location("p15_context_orchestration_contract_v1", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class P15DeployContractTests(unittest.TestCase):
    def test_contract_is_deterministic_and_inactive(self) -> None:
        payload = MODULE.contract_payload()
        first = MODULE.contract_digest()
        second = MODULE.contract_digest()
        self.assertEqual(first, second)
        self.assertEqual(
            first,
            sha256(
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest(),
        )
        self.assertTrue(payload["source_only"])
        self.assertFalse(payload["activation_authorized"])
        self.assertFalse(payload["runtime_builder_present"])
        self.assertFalse(payload["p09"]["prompt_projection_active"])

    def test_exact_dependency_identity_verifies(self) -> None:
        result = MODULE.verify_dependency_identity(
            core_commit=MODULE.GENERATION12_CORE_COMMIT,
            deploy_commit=MODULE.GENERATION12_DEPLOY_COMMIT,
            p09_source_main_commit=MODULE.P09_SOURCE_MAIN_COMMIT,
            p09_source_main_tree=MODULE.P09_SOURCE_MAIN_TREE,
            p09_capability_digest=MODULE.P09_CAPABILITY_DIGEST,
        )
        self.assertEqual(result["dependency_identity"], "verified")
        self.assertFalse(result["activation_authorized"])

    def test_dependency_drift_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            MODULE.P15DeployContractError,
            "p15_dependency_identity_mismatch",
        ):
            MODULE.verify_dependency_identity(
                core_commit=MODULE.GENERATION12_CORE_COMMIT,
                deploy_commit=MODULE.GENERATION12_DEPLOY_COMMIT,
                p09_source_main_commit="0" * 40,
                p09_source_main_tree=MODULE.P09_SOURCE_MAIN_TREE,
                p09_capability_digest=MODULE.P09_CAPABILITY_DIGEST,
            )


if __name__ == "__main__":
    unittest.main()
