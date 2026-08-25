from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import subprocess
import unittest

from scripts import p07_p10_memory_successor_contract_v3 as contract


class MemorySuccessorContractV3Tests(unittest.TestCase):
    def test_boundary_is_closed_and_predecessor_is_bound(self) -> None:
        selected = contract.payload()
        self.assertEqual(selected["profile_mutation_command"], "/Benchmark")
        self.assertFalse(selected["diary_profile_consent"])
        self.assertFalse(selected["p15_projection_active"])
        self.assertFalse(selected["partial_day_provider_call"])
        self.assertFalse(selected["existing_history_migration"])
        self.assertEqual(selected["rollback"], "local-only-disabled")
        self.assertEqual(selected["p07_attempts"], {"consumed": 0, "maximum": 2})
        self.assertEqual(len(selected["predecessor_contract_digest"]), 64)
        self.assertEqual(len(contract.digest()), 64)

    def test_current_candidate_files_match_exact_identity(self) -> None:
        root = Path(__file__).resolve().parents[1]
        files: dict[str, dict[str, str]] = {}
        for relative in contract.SOURCE_IDENTITIES:
            path = root / relative
            blob = subprocess.run(
                ["/usr/bin/git", "-C", str(root), "hash-object", str(path)],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            ).stdout.strip()
            files[relative] = {
                "git_blob": blob,
                "sha256": sha256(path.read_bytes()).hexdigest(),
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
            contract.MemorySuccessorContractRejected,
            "source_identity_drifted",
        ):
            contract.require_source_identity(
                core_commit="1" * 40,
                deploy_commit="2" * 40,
                files=files,
            )


if __name__ == "__main__":
    unittest.main()
