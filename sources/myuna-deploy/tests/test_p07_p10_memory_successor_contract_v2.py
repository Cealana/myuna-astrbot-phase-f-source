from __future__ import annotations

import unittest

from scripts import p07_p10_memory_successor_contract_v2 as contract


class MemorySuccessorContractV2Tests(unittest.TestCase):
    def test_boundary_is_closed_and_predecessor_is_bound(self) -> None:
        selected = contract.payload()
        self.assertEqual(selected["profile_mutation_command"], "/Benchmark")
        self.assertFalse(selected["diary_profile_consent"])
        self.assertFalse(selected["p15_projection_active"])
        self.assertFalse(selected["p10_check_external_message"])
        self.assertEqual(selected["p07_attempts"], {"consumed": 0, "maximum": 2})
        self.assertEqual(len(contract.digest()), 64)

    def test_historical_source_identity_snapshot_remains_closed(self) -> None:
        files = {
            path: {"git_blob": blob, "sha256": digest}
            for path, (blob, digest) in contract.SOURCE_IDENTITIES.items()
        }
        contract.require_source_identity(
            core_commit="1" * 40,
            deploy_commit="2" * 40,
            files=files,
        )

    def test_mixed_identity_fails_closed(self) -> None:
        files = {
            path: {"git_blob": blob, "sha256": digest}
            for path, (blob, digest) in contract.SOURCE_IDENTITIES.items()
        }
        first = next(iter(files))
        files[first] = {**files[first], "sha256": "0" * 64}
        with self.assertRaisesRegex(
            contract.MemorySuccessorContractRejected, "source_identity_drifted"
        ):
            contract.require_source_identity(
                core_commit="1" * 40,
                deploy_commit="2" * 40,
                files=files,
            )


if __name__ == "__main__":
    unittest.main()
