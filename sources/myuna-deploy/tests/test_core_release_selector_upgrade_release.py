from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


CANDIDATE_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(CANDIDATE_SCRIPTS))

from core_release_selector_upgrade_release import (  # noqa: E402
    EXECUTOR_FILES,
    MANIFEST_NAME,
    UpgradeReleaseError,
    build_manifest,
    canonical_bytes,
    validate_installed_release,
)


SOURCE = "a" * 40
ACTIVATION = "b" * 64
TRANSACTION = "c" * 64
INACTIVE = "d" * 64


def artifacts():
    return {name: f"payload:{name}".encode() for name in EXECUTOR_FILES}


class ReleaseContractTests(unittest.TestCase):
    def manifest(self, payloads=None):
        return build_manifest(
            payloads or artifacts(),
            source_deploy_commit=SOURCE,
            activation_plan_digest=ACTIVATION,
            transaction_tree_sha256=TRANSACTION,
            inactive_transaction_install_plan_digest=INACTIVE,
        )

    def test_manifest_is_deterministic_and_content_addressed(self) -> None:
        first = self.manifest()
        second = self.manifest(dict(reversed(list(artifacts().items()))))
        self.assertEqual(first, second)
        self.assertEqual(len(first["release_digest"]), 64)

    def test_missing_or_extra_artifact_rejected(self) -> None:
        payloads = artifacts()
        payloads.pop(next(iter(payloads)))
        with self.assertRaisesRegex(UpgradeReleaseError, "artifact_paths"):
            self.manifest(payloads)

    def test_installed_release_validates_exact_files_and_payloads(self) -> None:
        payloads = artifacts()
        manifest = self.manifest(payloads)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / manifest["release_digest"]
            root.mkdir()
            for name, payload in payloads.items():
                (root / name).write_bytes(payload)
            (root / MANIFEST_NAME).write_bytes(canonical_bytes(manifest))
            evidence = validate_installed_release(
                root,
                expected_release_digest=manifest["release_digest"],
                expected_source_deploy_commit=SOURCE,
                expected_activation_plan_digest=ACTIVATION,
                expected_transaction_tree_sha256=TRANSACTION,
                expected_inactive_install_plan_digest=INACTIVE,
                require_installed_metadata=False,
            )
            self.assertEqual(evidence, manifest)

    def test_payload_tamper_rejected(self) -> None:
        payloads = artifacts()
        manifest = self.manifest(payloads)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / manifest["release_digest"]
            root.mkdir()
            for name, payload in payloads.items():
                (root / name).write_bytes(payload)
            (root / MANIFEST_NAME).write_bytes(canonical_bytes(manifest))
            (root / next(iter(EXECUTOR_FILES))).write_bytes(b"tampered")
            with self.assertRaisesRegex(UpgradeReleaseError, "manifest_rejected"):
                validate_installed_release(
                    root,
                    expected_release_digest=manifest["release_digest"],
                    expected_source_deploy_commit=SOURCE,
                    expected_activation_plan_digest=ACTIVATION,
                    expected_transaction_tree_sha256=TRANSACTION,
                    expected_inactive_install_plan_digest=INACTIVE,
                    require_installed_metadata=False,
                )


if __name__ == "__main__":
    unittest.main()

