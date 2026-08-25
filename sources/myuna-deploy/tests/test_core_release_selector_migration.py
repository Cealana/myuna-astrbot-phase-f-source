from __future__ import annotations

import ast
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
FORMAL_DEPLOY = Path(
    os.environ.get("MYUNA_FORMAL_DEPLOY_ROOT", "/srv/myuna/repos/deploy")
)
sys.path.insert(0, str(ROOT / "scripts"))
if not (ROOT / "scripts/core_release_selector.py").is_file():
    sys.path.insert(1, str(FORMAL_DEPLOY / "scripts"))

from core_release_selector import (  # noqa: E402
    ReleaseEvidence,
    SelectionCandidate,
    build_binding_intent,
    canonical_json_bytes,
    parse_json_document,
    render_guard_dropin,
    render_selector_dropin,
)
from core_release_selector_migration import (  # noqa: E402
    MigrationContractError,
    build_migration_bundle,
    load_migration_contract,
    strip_release_owner_directives,
)


TARGET_TREE = "a" * 64
SOURCE_COMMIT = "b" * 40
ARTIFACT_MANIFEST = "c" * 64
INSTALL_RECEIPT = "d" * 64
VERIFIER_SHA = "e" * 64
OLD_PATH = f"/srv/myuna/releases/core/{'f' * 64}"
TARGET_PATH = f"/srv/myuna/releases/core/{TARGET_TREE}"
APPROVAL = "9" * 64


def digest(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def fixture() -> dict[str, object]:
    release = ReleaseEvidence(
        tree_sha256=TARGET_TREE,
        source_commit=SOURCE_COMMIT,
        file_count=3,
        artifact_manifest_sha256=ARTIFACT_MANIFEST,
        installation_receipt_sha256=INSTALL_RECEIPT,
    )
    candidate = SelectionCandidate(selected_release=release)
    verifier_path = (
        "/opt/myuna/core-release-selector/releases/"
        f"{VERIFIER_SHA}/core_release_selector.py"
    )
    intent = build_binding_intent(
        candidate,
        verifier_script_path=verifier_path,
        verifier_script_sha256=VERIFIER_SHA,
    )
    binding_intent = canonical_json_bytes(intent.to_payload())
    selector = render_selector_dropin(candidate).encode("utf-8")
    guard = render_guard_dropin(verifier_path).encode("utf-8")
    base = (
        "[Service]\n"
        "WorkingDirectory=/srv/myuna/repos/core\n"
        "Environment=PYTHONPATH=/srv/myuna/repos/core/src\n"
    ).encode("utf-8")
    pure = (
        "[Service]\n"
        f"WorkingDirectory={OLD_PATH}\n"
        f"Environment=PYTHONPATH={OLD_PATH}/src\n"
    ).encode("utf-8")
    hybrid = (
        "[Service]\n"
        f"WorkingDirectory={OLD_PATH}\n"
        f"Environment=PYTHONPATH={OLD_PATH}/src\n"
        "Environment=MYUNA_FEATURE_ENABLED=1\n"
    ).encode("utf-8")
    preserved = b"[Service]\nLoadCredential=example:/run/secret\n"
    sanitized_hybrid, removed = strip_release_owner_directives(hybrid)
    assert sanitized_hybrid is not None and removed == 2
    payload = {
        "schema": "myuna.core-release-selector.r4-migration-contract.v1",
        "status": "repository_candidate_not_installed_or_active",
        "unit": "myuna-core@qq.service",
        "instance": "qq",
        "base_template": {
            "path": "/etc/systemd/system/myuna-core@.service",
            "sha256": digest(base),
        },
        "prestate": {
            "dropin_file_count": 3,
            "effective_owner": "99-hybrid.conf",
            "effective_working_directory": OLD_PATH,
            "active_tree_sha256": TARGET_TREE,
            "active_file_count": 3,
        },
        "target": {
            "release_path": TARGET_PATH,
            "tree_sha256": TARGET_TREE,
            "file_count": 3,
            "source_commit": SOURCE_COMMIT,
            "selector_dropin": "10-core-release-selector-v1.conf",
            "selector_dropin_sha256": digest(selector),
            "guard_dropin": "05-core-release-selector-guard-v1.conf",
            "guard_dropin_sha256": digest(guard),
            "runtime_binding": "/etc/myuna/core-release-selector/qq.binding.json",
        },
        "r3b": {
            "approved_plan_digest": "8" * 64,
            "verifier_path": verifier_path,
            "verifier_sha256": VERIFIER_SHA,
            "candidate_root": f"/etc/myuna/core-release-selector/candidates/{'8' * 64}",
            "binding_intent_sha256": digest(binding_intent),
        },
        "migration": {
            "90-pure.conf": {
                "action": "delete",
                "source_sha256": digest(pure),
                "removed_release_directive_count": 2,
            },
            "99-hybrid.conf": {
                "action": "replace",
                "source_sha256": digest(hybrid),
                "target_sha256": digest(sanitized_hybrid),
                "removed_release_directive_count": 2,
            },
        },
        "preserved_dropins": {
            "credentials.conf": digest(preserved),
        },
        "environment_files": ["/etc/myuna/qq.env"],
        "gateway": {
            "unit": "myuna-qq-owner-runtime-dev.service",
            "fragment_sha256": "1" * 64,
            "dropins": {"gateway.conf": "2" * 64},
            "requires_core": True,
            "future_activation_sequence": "stop then start",
        },
        "next_stage": {
            "name": "R4B inactive transaction bundle staging",
            "requires_separate_plan_digest_and_owner_approval": True,
            "r4a_does_not_authorize_system_writes_or_activation": True,
        },
    }
    return {
        "payload": payload,
        "base": base,
        "dropins": {
            "90-pure.conf": pure,
            "99-hybrid.conf": hybrid,
            "credentials.conf": preserved,
        },
        "environment_files": {"/etc/myuna/qq.env": b"MYUNA_PORT=8000\n"},
        "binding_intent": binding_intent,
        "guard": guard,
        "selector": selector,
        "sanitized_hybrid": sanitized_hybrid,
    }


class ContractTests(unittest.TestCase):
    def test_contract_loads_exact_fixture(self) -> None:
        data = fixture()
        contract = load_migration_contract(data["payload"])
        self.assertEqual(contract.target_release_path, TARGET_PATH)
        self.assertEqual(set(contract.migration), {"90-pure.conf", "99-hybrid.conf"})

    def test_contract_rejects_extra_root_field(self) -> None:
        payload = deepcopy(fixture()["payload"])
        payload["unexpected"] = True
        with self.assertRaises(MigrationContractError):
            load_migration_contract(payload)

    def test_contract_rejects_non_path_only_migration(self) -> None:
        payload = deepcopy(fixture()["payload"])
        payload["prestate"]["active_tree_sha256"] = "3" * 64
        with self.assertRaises(MigrationContractError):
            load_migration_contract(payload)

    def test_contract_rejects_overlapping_preserved_name(self) -> None:
        payload = deepcopy(fixture()["payload"])
        payload["preserved_dropins"]["90-pure.conf"] = "4" * 64
        with self.assertRaises(MigrationContractError):
            load_migration_contract(payload)

    def test_contract_rejects_activation_authority(self) -> None:
        payload = deepcopy(fixture()["payload"])
        payload["next_stage"]["r4a_does_not_authorize_system_writes_or_activation"] = False
        with self.assertRaises(MigrationContractError):
            load_migration_contract(payload)


class SanitizerTests(unittest.TestCase):
    def test_pure_owner_becomes_delete(self) -> None:
        pure = fixture()["dropins"]["90-pure.conf"]
        sanitized, removed = strip_release_owner_directives(pure)
        self.assertIsNone(sanitized)
        self.assertEqual(removed, 2)

    def test_hybrid_preserves_non_release_directive_byte_for_byte(self) -> None:
        data = fixture()
        sanitized, removed = strip_release_owner_directives(
            data["dropins"]["99-hybrid.conf"]
        )
        self.assertEqual(sanitized, data["sanitized_hybrid"])
        self.assertEqual(removed, 2)
        self.assertIn(b"MYUNA_FEATURE_ENABLED=1", sanitized)

    def test_mixed_pythonpath_environment_fails_closed(self) -> None:
        payload = (
            f"[Service]\nEnvironment=PYTHONPATH={OLD_PATH}/src OTHER=1\n"
        ).encode("utf-8")
        with self.assertRaises(MigrationContractError):
            strip_release_owner_directives(payload)

    def test_invalid_utf8_fails_closed(self) -> None:
        with self.assertRaises(MigrationContractError):
            strip_release_owner_directives(b"\xff")


class BundleTests(unittest.TestCase):
    def build(self, **overrides):
        data = fixture()
        arguments = {
            "base_template": data["base"],
            "live_dropins": data["dropins"],
            "environment_files": data["environment_files"],
            "binding_intent": data["binding_intent"],
            "staged_guard": data["guard"],
            "staged_selector": data["selector"],
            "approval_plan_digest": APPROVAL,
        }
        arguments.update(overrides)
        return build_migration_bundle(
            load_migration_contract(data["payload"]), **arguments
        )

    def test_bundle_has_single_effective_selector_owner(self) -> None:
        bundle = self.build()
        self.assertEqual(bundle.effective_owner, "10-core-release-selector-v1.conf")
        self.assertEqual(bundle.effective_working_directory, TARGET_PATH)
        self.assertEqual(bundle.deletes, ("90-pure.conf",))
        self.assertIn("99-hybrid.conf", bundle.writes)
        self.assertIn("qq.binding.json", bundle.writes)
        self.assertEqual(len(bundle.final_dropin_sha256), 4)

    def test_runtime_binding_is_approval_bound(self) -> None:
        bundle = self.build()
        payload = parse_json_document(bundle.runtime_binding)
        self.assertEqual(payload["approval_plan_digest"], APPROVAL)
        self.assertEqual(payload["selected_release"]["tree_sha256"], TARGET_TREE)

    def test_live_dropin_drift_fails_closed(self) -> None:
        data = fixture()
        drifted = dict(data["dropins"])
        drifted["credentials.conf"] += b"\n"
        with self.assertRaises(MigrationContractError):
            self.build(live_dropins=drifted)

    def test_missing_live_dropin_fails_closed(self) -> None:
        data = fixture()
        missing = dict(data["dropins"])
        missing.pop("credentials.conf")
        with self.assertRaises(MigrationContractError):
            self.build(live_dropins=missing)

    def test_environment_file_pythonpath_fails_closed(self) -> None:
        with self.assertRaises(Exception):
            self.build(
                environment_files={
                    "/etc/myuna/qq.env": b"PYTHONPATH=/tmp/escape\n"
                }
            )

    def test_guard_drift_fails_closed(self) -> None:
        with self.assertRaises(MigrationContractError):
            self.build(staged_guard=b"[Service]\n")

    def test_binding_intent_drift_fails_closed(self) -> None:
        data = fixture()
        payload = bytearray(data["binding_intent"])
        payload[-2] = ord(" ")
        with self.assertRaises(MigrationContractError):
            self.build(binding_intent=bytes(payload))

    def test_summary_contains_hashes_not_payloads(self) -> None:
        summary = self.build().summary()
        serialized = json.dumps(summary, sort_keys=True)
        self.assertNotIn("MYUNA_FEATURE_ENABLED=1", serialized)
        self.assertIn("runtime_binding_sha256", summary)


class StaticSafetyTests(unittest.TestCase):
    def test_module_has_no_filesystem_process_network_or_service_api(self) -> None:
        source = (ROOT / "scripts/core_release_selector_migration.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        imported_roots: set[str] = set()
        called_attributes: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(
                    alias.name.split(".", 1)[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                called_attributes.add(node.func.attr)
        self.assertTrue(
            {
                "os",
                "pathlib",
                "shutil",
                "socket",
                "subprocess",
                "tempfile",
                "urllib",
            }.isdisjoint(imported_roots)
        )
        self.assertTrue(
            {"open", "read_bytes", "write_bytes", "unlink", "replace", "rename"}.isdisjoint(
                called_attributes
            )
        )
        self.assertNotIn("systemctl", source)
        self.assertNotIn("daemon-reload", source)


if __name__ == "__main__":
    unittest.main()

