from __future__ import annotations

import ast
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from core_release_selector import (  # noqa: E402
    BINDING_INTENT_SCHEMA,
    BINDING_INTENT_STATUS,
    BINDING_SCHEMA,
    BINDING_STATUS,
    CANONICAL_JSON_ALGORITHM,
    CANDIDATE_SCHEMA,
    CANDIDATE_STATUS,
    DOCUMENT_KIND,
    INSTANCE,
    RELEASE_ROOT,
    STABLE_SELECTOR_DROPIN,
    TREE_DIGEST_ALGORITHM,
    UNIT,
    SelectorContractError,
    analyze_systemd_release_inventory,
    assert_environment_files_do_not_define_pythonpath,
    build_binding_intent,
    canonical_json_bytes,
    canonical_json_sha256,
    compute_tree_digest,
    load_binding_intent,
    load_runtime_binding,
    load_selection_candidate,
    parse_json_document,
    render_guard_dropin,
    render_runtime_binding,
    render_selector_dropin,
    validate_binding_intent_evidence,
    validate_immutable_release_tree,
    validate_inventory_prestate,
    validate_r1_repository_release_owners,
    validate_runtime_binding_evidence,
    validate_runtime_observation,
)


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
COMMIT_A = "d" * 40
CURRENT_TREE = "430be06ece061b16b3bc2d67e9e2d17764c81073ffc8593403470063935f68a8"
CURRENT_COMMIT = "1d968d9bf361cc50a4a9b709a566c698424f3287"
CURRENT_ARTIFACT_MANIFEST = (
    "7909359616a3b089f9b6fe5c6b90e6900c7edd9c849e33b012c4b909bc5ac938"
)
CURRENT_INSTALL_RECEIPT = (
    "b296bcc04909a459e39d3f60724e7987f431187d05958bc74df99eaf60069777"
)
CURRENT_CANDIDATE_CANONICAL = (
    "b55d45bca0e0f9361de4db5cfe943c357c1267145d0ad37394901631d273f699"
)
CURRENT_VERIFIER_SHA256 = (
    "3fab13b7b533c3e93bf5759256ff5153d7bb17aea0fc8307f560e82985a7fcaf"
)
CURRENT_VERIFIER_PATH = (
    "/opt/myuna/core-release-selector/releases/"
    f"{CURRENT_VERIFIER_SHA256}/core_release_selector.py"
)
CURRENT_GUARD_SHA256 = (
    "30c69f98d8a27c5d3cd04c6ae9b9ad7513e00685e0003ee71399a3d2fae180c4"
)
CURRENT_INTENT_CANONICAL = (
    "0ee3c54dbcb3575d6b471595341df076658ca5b6cdf676bf30ec4b5a53ce3068"
)


def release_payload(
    *, tree: str = CURRENT_TREE, file_count: object = 149
) -> dict[str, object]:
    return {
        "tree_digest_algorithm": TREE_DIGEST_ALGORITHM,
        "tree_sha256": tree,
        "source_commit": CURRENT_COMMIT,
        "file_count": file_count,
        "artifact_manifest_sha256": CURRENT_ARTIFACT_MANIFEST,
        "installation_receipt_sha256": CURRENT_INSTALL_RECEIPT,
    }


def candidate_payload() -> dict[str, object]:
    return {
        "schema": CANDIDATE_SCHEMA,
        "document_kind": DOCUMENT_KIND,
        "status": CANDIDATE_STATUS,
        "unit": UNIT,
        "instance": INSTANCE,
        "release_root": RELEASE_ROOT,
        "stable_selector_dropin": STABLE_SELECTOR_DROPIN,
        "canonical_json_algorithm": CANONICAL_JSON_ALGORITHM,
        "selected_release": release_payload(),
    }


def binding_intent_payload() -> dict[str, object]:
    candidate = load_selection_candidate(candidate_payload())
    return build_binding_intent(
        candidate,
        verifier_script_path=CURRENT_VERIFIER_PATH,
        verifier_script_sha256=CURRENT_VERIFIER_SHA256,
    ).to_payload()


def binding_payload() -> dict[str, object]:
    intent = load_binding_intent(binding_intent_payload())
    return render_runtime_binding(
        intent, approval_plan_digest=DIGEST_B
    ).to_payload()


def release_fragment(tree: str) -> bytes:
    root = f"/srv/myuna/releases/core/{tree}"
    return (
        "[Service]\n"
        f"WorkingDirectory={root}\n"
        f"Environment=PYTHONPATH={root}/src\n"
    ).encode("utf-8")


class CandidateContractTests(unittest.TestCase):
    def test_repository_candidate_parses_and_round_trips_exactly(self) -> None:
        payload = candidate_payload()
        candidate = load_selection_candidate(payload)
        self.assertEqual(candidate.to_payload(), payload)
        self.assertEqual(candidate.selected_release.tree_sha256, CURRENT_TREE)
        self.assertEqual(
            candidate.selected_release.release_path.as_posix(),
            f"{RELEASE_ROOT}/{CURRENT_TREE}",
        )

    def test_formal_candidate_config_matches_sealed_contract(self) -> None:
        payload = parse_json_document(
            (ROOT / "config/core-release-selector-v1.json").read_bytes()
        )
        candidate = load_selection_candidate(payload)
        self.assertEqual(candidate.to_payload(), candidate_payload())
        self.assertEqual(canonical_json_sha256(payload), CURRENT_CANDIDATE_CANONICAL)

    def test_candidate_rejects_missing_or_extra_top_level_fields(self) -> None:
        missing = candidate_payload()
        del missing["instance"]
        with self.assertRaises(SelectorContractError):
            load_selection_candidate(missing)
        extra = candidate_payload()
        extra["automatic_activation"] = True
        with self.assertRaises(SelectorContractError):
            load_selection_candidate(extra)

    def test_candidate_rejects_every_fixed_identity_drift(self) -> None:
        replacements = {
            "schema": "myuna.core-release-selection-candidate.v2",
            "document_kind": "active",
            "status": "active",
            "unit": "myuna-core@dev.service",
            "instance": "dev",
            "release_root": "/tmp/releases",
            "stable_selector_dropin": "zzzzzzz-selector.conf",
            "canonical_json_algorithm": "other-json-v1",
        }
        for field, replacement in replacements.items():
            with self.subTest(field=field):
                payload = candidate_payload()
                payload[field] = replacement
                with self.assertRaises(SelectorContractError):
                    load_selection_candidate(payload)

    def test_release_rejects_missing_extra_or_custom_path(self) -> None:
        missing = candidate_payload()
        del missing["selected_release"]["artifact_manifest_sha256"]
        with self.assertRaises(SelectorContractError):
            load_selection_candidate(missing)
        extra = candidate_payload()
        extra["selected_release"]["release_path"] = "/tmp/escape"
        with self.assertRaises(SelectorContractError):
            load_selection_candidate(extra)

    def test_release_rejects_bad_digest_commit_and_provenance(self) -> None:
        for field, value in (
            ("tree_sha256", "A" * 64),
            ("tree_sha256", "a" * 63),
            ("source_commit", "d" * 39),
            ("artifact_manifest_sha256", "missing"),
            ("installation_receipt_sha256", "0" * 65),
        ):
            with self.subTest(field=field, value=value):
                payload = candidate_payload()
                payload["selected_release"][field] = value
                with self.assertRaises(SelectorContractError):
                    load_selection_candidate(payload)

    def test_release_file_count_requires_positive_non_boolean_integer(self) -> None:
        for value in (0, -1, True, 1.5, "149"):
            with self.subTest(value=value):
                payload = candidate_payload()
                payload["selected_release"]["file_count"] = value
                with self.assertRaises(SelectorContractError):
                    load_selection_candidate(payload)

    def test_release_rejects_tree_digest_algorithm_drift(self) -> None:
        payload = candidate_payload()
        payload["selected_release"]["tree_digest_algorithm"] = "git-tree-sha1"
        with self.assertRaises(SelectorContractError):
            load_selection_candidate(payload)


class CanonicalJsonTests(unittest.TestCase):
    def test_canonical_json_golden_vector(self) -> None:
        value = {
            "schema": "example.v1",
            "count": 2,
            "enabled": True,
            "names": ["a", "myuna"],
        }
        expected = (
            b'{"count":2,"enabled":true,"names":["a","myuna"],'
            b'"schema":"example.v1"}'
        )
        self.assertEqual(canonical_json_bytes(value), expected)
        self.assertEqual(
            canonical_json_sha256(value),
            "337de83fb0bf73a9d4d86370978c15ab9282a015630794a4620941515b9e0957",
        )

    def test_canonical_json_is_order_independent_without_newline(self) -> None:
        first = {"z": 1, "a": [True, None, "x"]}
        second = {"a": [True, None, "x"], "z": 1}
        self.assertEqual(canonical_json_bytes(first), canonical_json_bytes(second))
        self.assertFalse(canonical_json_bytes(first).endswith(b"\n"))

    def test_canonical_json_rejects_floats_tuples_and_non_string_keys(self) -> None:
        for value in ({"value": 1.0}, ("not", "a", "list"), {1: "bad"}):
            with self.subTest(value=value):
                with self.assertRaises(SelectorContractError):
                    canonical_json_bytes(value)

    def test_json_parser_rejects_duplicate_keys_and_invalid_utf8(self) -> None:
        with self.assertRaises(SelectorContractError):
            parse_json_document(b'{"a":1,"a":2}')
        with self.assertRaises(SelectorContractError):
            parse_json_document(b"\xff")


class RendererTests(unittest.TestCase):
    def test_selector_render_is_exact_and_deterministic(self) -> None:
        candidate = load_selection_candidate(candidate_payload())
        root = f"{RELEASE_ROOT}/{CURRENT_TREE}"
        expected = (
            "[Service]\n"
            f"WorkingDirectory={root}\n"
            f"Environment=PYTHONPATH={root}/src\n"
        )
        self.assertEqual(render_selector_dropin(candidate), expected)
        self.assertEqual(render_selector_dropin(candidate), expected)

    def test_selector_render_has_only_atomic_release_pair(self) -> None:
        rendered = render_selector_dropin(load_selection_candidate(candidate_payload()))
        self.assertEqual(len(rendered.splitlines()), 3)
        for forbidden in (
            "EnvironmentFile",
            "LoadCredential",
            "HTTP_PROXY",
            "CAPABILITY",
            "MEMORY",
            "Wants=",
            "After=",
            "ExecStart=",
        ):
            self.assertNotIn(forbidden, rendered)

    def test_guard_render_is_content_addressed_and_has_no_release_pair(self) -> None:
        verifier = (
            "/opt/myuna/core-release-selector/releases/"
            f"{DIGEST_A}/core_release_selector.py"
        )
        rendered = render_guard_dropin(verifier)
        self.assertIn(
            "ConditionPathExists=/etc/myuna/core-release-selector/qq.binding.json",
            rendered,
        )
        self.assertIn(f"ExecStartPre=/usr/bin/python3 {verifier} verify-active", rendered)
        self.assertNotIn("WorkingDirectory=", rendered)
        self.assertNotIn("PYTHONPATH=", rendered)

    def test_guard_rejects_mutable_or_arbitrary_verifier_paths(self) -> None:
        for path in (
            "/tmp/core_release_selector.py",
            "/opt/myuna/core-release-selector/current/core_release_selector.py",
            f"/opt/myuna/core-release-selector/releases/{'A' * 64}/core_release_selector.py",
            f"/opt/myuna/core-release-selector/releases/{DIGEST_A}/../tool.py",
        ):
            with self.subTest(path=path):
                with self.assertRaises(SelectorContractError):
                    render_guard_dropin(path)


class TreeDigestTests(unittest.TestCase):
    def test_tree_digest_golden_vector(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "dir").mkdir()
            (root / "a.txt").write_bytes(b"A")
            (root / "dir/b.bin").write_bytes(bytes((0, 255)))
            digest, count = compute_tree_digest(root)
        self.assertEqual(
            digest,
            "3c9e00eee57c43dbb603eed3a4a36f62f759db7f6e288fd24db05dd68333cb63",
        )
        self.assertEqual(count, 2)

    def test_tree_digest_ignores_empty_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "empty").mkdir()
            digest, count = compute_tree_digest(root)
        self.assertEqual(digest, sha256(b"").hexdigest())
        self.assertEqual(count, 0)

    def test_tree_digest_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "source").write_text("x", encoding="utf-8")
            (root / "link").symlink_to(root / "source")
            with self.assertRaises(SelectorContractError):
                compute_tree_digest(root)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO requires POSIX")
    def test_tree_digest_rejects_special_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.mkfifo(root / "pipe")
            with self.assertRaises(SelectorContractError):
                compute_tree_digest(root)

    def test_immutable_tree_rejects_non_derived_path_before_permissions(self) -> None:
        candidate = load_selection_candidate(candidate_payload())
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(SelectorContractError):
                validate_immutable_release_tree(
                    Path(temporary), candidate.selected_release, expected_gid=0
                )


class BindingIntentTests(unittest.TestCase):
    def test_formal_inactive_intent_matches_deterministic_render(self) -> None:
        payload = parse_json_document(
            (ROOT / "config/core-release-selector-v1-binding-intent.json").read_bytes()
        )
        intent = load_binding_intent(payload)
        self.assertEqual(intent.to_payload(), binding_intent_payload())
        self.assertEqual(canonical_json_sha256(payload), CURRENT_INTENT_CANONICAL)
        self.assertEqual(intent.guard_dropin_sha256, CURRENT_GUARD_SHA256)

    def test_binding_intent_is_deliberately_not_a_runtime_binding(self) -> None:
        with self.assertRaises(SelectorContractError):
            load_runtime_binding(binding_intent_payload())
        with self.assertRaises(SelectorContractError):
            load_binding_intent(binding_payload())

    def test_binding_intent_rejects_identity_and_evidence_drift(self) -> None:
        replacements = {
            "status": "selected_for_instance",
            "candidate_canonical_sha256": DIGEST_A,
            "selector_dropin_sha256": DIGEST_A,
            "guard_dropin_sha256": DIGEST_A,
            "verifier_script_sha256": DIGEST_A,
            "verifier_script_path": (
                "/opt/myuna/core-release-selector/releases/"
                f"{DIGEST_A}/core_release_selector.py"
            ),
        }
        for field, value in replacements.items():
            with self.subTest(field=field):
                payload = binding_intent_payload()
                payload[field] = value
                with self.assertRaises(SelectorContractError):
                    load_binding_intent(payload)

    def test_binding_intent_rejects_extra_field(self) -> None:
        payload = binding_intent_payload()
        payload["approval_plan_digest"] = DIGEST_B
        with self.assertRaises(SelectorContractError):
            load_binding_intent(payload)

    def test_runtime_binding_is_derived_only_after_approval_digest(self) -> None:
        intent = load_binding_intent(binding_intent_payload())
        binding = render_runtime_binding(intent, approval_plan_digest=DIGEST_B)
        self.assertEqual(binding.approval_plan_digest, DIGEST_B)
        self.assertEqual(binding.candidate_canonical_sha256, CURRENT_CANDIDATE_CANONICAL)
        self.assertEqual(binding.verifier_script_path, CURRENT_VERIFIER_PATH)
        validate_runtime_binding_evidence(binding)
        for invalid in ("", "A" * 64, "a" * 63):
            with self.subTest(invalid=invalid):
                with self.assertRaises(SelectorContractError):
                    render_runtime_binding(intent, approval_plan_digest=invalid)

    def test_binding_intent_evidence_validator_rejects_manual_object_drift(self) -> None:
        intent = load_binding_intent(binding_intent_payload())
        drifted = type(intent)(
            candidate_canonical_sha256=DIGEST_A,
            selector_dropin_sha256=intent.selector_dropin_sha256,
            guard_dropin_sha256=intent.guard_dropin_sha256,
            verifier_script_path=intent.verifier_script_path,
            verifier_script_sha256=intent.verifier_script_sha256,
            selected_release=intent.selected_release,
        )
        with self.assertRaises(SelectorContractError):
            validate_binding_intent_evidence(drifted)


class RuntimeBindingTests(unittest.TestCase):
    def test_runtime_binding_parses(self) -> None:
        binding = load_runtime_binding(binding_payload())
        self.assertEqual(binding.selected_release.tree_sha256, CURRENT_TREE)
        self.assertEqual(binding.approval_plan_digest, DIGEST_B)
        self.assertEqual(binding.verifier_script_sha256, CURRENT_VERIFIER_SHA256)
        self.assertEqual(binding.guard_dropin_sha256, CURRENT_GUARD_SHA256)

    def test_runtime_binding_rejects_extra_fields_and_identity_drift(self) -> None:
        extra = binding_payload()
        extra["fallback_release"] = DIGEST_C
        with self.assertRaises(SelectorContractError):
            load_runtime_binding(extra)
        drift = binding_payload()
        drift["status"] = "active"
        with self.assertRaises(SelectorContractError):
            load_runtime_binding(drift)

    def test_runtime_observation_accepts_exact_atomic_selection(self) -> None:
        binding = load_runtime_binding(binding_payload())
        selector = (
            "[Service]\n"
            f"WorkingDirectory={RELEASE_ROOT}/{CURRENT_TREE}\n"
            f"Environment=PYTHONPATH={RELEASE_ROOT}/{CURRENT_TREE}/src\n"
        ).encode("utf-8")
        guard = render_guard_dropin(CURRENT_VERIFIER_PATH).encode("utf-8")
        validate_runtime_observation(
            binding,
            observed_cwd=f"{RELEASE_ROOT}/{CURRENT_TREE}",
            observed_pythonpath=f"{RELEASE_ROOT}/{CURRENT_TREE}/src",
            selector_dropin=selector,
            guard_dropin=guard,
            observed_verifier_path=CURRENT_VERIFIER_PATH,
            observed_verifier_sha256=CURRENT_VERIFIER_SHA256,
            observed_tree_sha256=CURRENT_TREE,
            observed_file_count=149,
        )

    def test_runtime_observation_rejects_each_drift_dimension(self) -> None:
        binding = load_runtime_binding(binding_payload())
        selector = render_selector_dropin(
            load_selection_candidate(candidate_payload())
        ).encode("utf-8")
        guard = render_guard_dropin(CURRENT_VERIFIER_PATH).encode("utf-8")
        valid = {
            "observed_cwd": f"{RELEASE_ROOT}/{CURRENT_TREE}",
            "observed_pythonpath": f"{RELEASE_ROOT}/{CURRENT_TREE}/src",
            "selector_dropin": selector,
            "guard_dropin": guard,
            "observed_verifier_path": CURRENT_VERIFIER_PATH,
            "observed_verifier_sha256": CURRENT_VERIFIER_SHA256,
            "observed_tree_sha256": CURRENT_TREE,
            "observed_file_count": 149,
        }
        replacements = {
            "observed_cwd": "/srv/myuna/repos/core",
            "observed_pythonpath": "/srv/myuna/repos/core/src",
            "selector_dropin": selector + b"# drift\n",
            "guard_dropin": guard + b"# drift\n",
            "observed_verifier_path": (
                "/opt/myuna/core-release-selector/releases/"
                f"{DIGEST_A}/core_release_selector.py"
            ),
            "observed_verifier_sha256": DIGEST_A,
            "observed_tree_sha256": DIGEST_A,
            "observed_file_count": 150,
        }
        for field, replacement in replacements.items():
            with self.subTest(field=field):
                observed = dict(valid)
                observed[field] = replacement
                with self.assertRaises(SelectorContractError):
                    validate_runtime_observation(binding, **observed)


class InventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = (
            b"[Service]\nWorkingDirectory=/srv/myuna/repos/core\n"
            b"Environment=PYTHONPATH=/srv/myuna/repos/core/src\n"
        )
        self.dropins = {
            "25-proxy.conf": b"[Service]\nEnvironment=HTTP_PROXY=http://127.0.0.1\n",
            "90-old.conf": release_fragment("1" * 64),
            "zz-new.conf": release_fragment(CURRENT_TREE),
        }

    def test_inventory_reports_base_owners_and_lexical_winner_without_authorizing_it(self) -> None:
        inventory = analyze_systemd_release_inventory(self.base, self.dropins)
        self.assertIsNotNone(inventory.base_owner)
        self.assertEqual(len(inventory.dropin_owners), 2)
        self.assertEqual(inventory.effective_owner.source_name, "zz-new.conf")
        self.assertEqual(
            inventory.effective_owner.working_directory,
            f"{RELEASE_ROOT}/{CURRENT_TREE}",
        )

    def test_inventory_rejects_partial_or_split_release_ownership(self) -> None:
        for fragment in (
            b"[Service]\nWorkingDirectory=/srv/myuna/releases/core/x\n",
            b"[Service]\nEnvironment=PYTHONPATH=/srv/myuna/releases/core/x/src\n",
            (
                b"[Service]\nWorkingDirectory=/srv/myuna/releases/core/a\n"
                b"Environment=PYTHONPATH=/srv/myuna/releases/core/b/src\n"
            ),
        ):
            with self.subTest(fragment=fragment):
                with self.assertRaises(SelectorContractError):
                    analyze_systemd_release_inventory(self.base, {"bad.conf": fragment})

    def test_inventory_recognizes_systemd_whitespace_around_assignment(self) -> None:
        fragment = (
            b"[Service]\nWorkingDirectory = /srv/myuna/releases/core/x\n"
            b"Environment = \"PYTHONPATH=/srv/myuna/releases/core/x/src\"\n"
        )
        inventory = analyze_systemd_release_inventory(self.base, {"spaced.conf": fragment})
        self.assertEqual(inventory.effective_owner.source_name, "spaced.conf")

    def test_inventory_prestate_requires_exact_names_hashes_and_winner(self) -> None:
        inventory = analyze_systemd_release_inventory(self.base, self.dropins)
        expected = {
            name: sha256(payload).hexdigest() for name, payload in self.dropins.items()
        }
        validate_inventory_prestate(
            inventory,
            expected_base_sha256=sha256(self.base).hexdigest(),
            expected_dropin_sha256=expected,
            expected_effective_owner="zz-new.conf",
            expected_effective_working_directory=f"{RELEASE_ROOT}/{CURRENT_TREE}",
        )
        expected["unknown.conf"] = DIGEST_A
        with self.assertRaises(SelectorContractError):
            validate_inventory_prestate(
                inventory,
                expected_base_sha256=sha256(self.base).hexdigest(),
                expected_dropin_sha256=expected,
                expected_effective_owner="zz-new.conf",
                expected_effective_working_directory=f"{RELEASE_ROOT}/{CURRENT_TREE}",
            )

    def test_environment_files_reject_pythonpath_injection(self) -> None:
        assert_environment_files_do_not_define_pythonpath(
            {"safe.env": b"MODEL=deepseek\n# PYTHONPATH=comment\n"}
        )
        for payload in (
            b"PYTHONPATH=/tmp\n",
            b"  PYTHONPATH = /tmp\n",
            b"export PYTHONPATH=/tmp\n",
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(SelectorContractError):
                    assert_environment_files_do_not_define_pythonpath(
                        {"unsafe.env": payload}
                    )

    def test_formal_repository_has_only_exact_known_legacy_owner(self) -> None:
        systemd = ROOT / "systemd"
        files = {path.name: path.read_bytes() for path in systemd.glob("*.conf")}
        validate_r1_repository_release_owners(files)

    def test_repository_owner_guard_rejects_second_or_drifted_owner(self) -> None:
        systemd = ROOT / "systemd"
        files = {path.name: path.read_bytes() for path in systemd.glob("*.conf")}
        second = dict(files)
        second["new-feature.conf"] = release_fragment(CURRENT_TREE)
        with self.assertRaises(SelectorContractError):
            validate_r1_repository_release_owners(second)
        drifted = dict(files)
        drifted["myuna-core-qq-voice-hotfix-1.conf"] += b"# drift\n"
        with self.assertRaises(SelectorContractError):
            validate_r1_repository_release_owners(drifted)


class StaticSafetyTests(unittest.TestCase):
    def test_selector_module_has_no_process_network_or_write_side_effect_api(self) -> None:
        source_path = ROOT / "scripts/core_release_selector.py"
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported_roots: set[str] = set()
        called_attributes: set[str] = set()
        called_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    called_attributes.add(node.func.attr)
                elif isinstance(node.func, ast.Name):
                    called_names.add(node.func.id)
        self.assertTrue(
            {"subprocess", "socket", "requests", "urllib", "shutil"}.isdisjoint(
                imported_roots
            )
        )
        self.assertTrue(
            {
                "write_text",
                "write_bytes",
                "replace",
                "rename",
                "unlink",
                "mkdir",
                "makedirs",
                "system",
                "popen",
            }.isdisjoint(called_attributes)
        )
        self.assertNotIn("open", called_names)

    def test_repository_candidate_files_are_present(self) -> None:
        expected = (
            "scripts/core_release_selector.py",
            "scripts/install_core_release_selector_staging.py",
            "config/core-release-selector-v1.json",
            "config/core-release-selector-v1-binding-intent.json",
            "tests/test_core_release_selector.py",
            "tests/test_core_release_selector_staging.py",
            "docs/ADR-031-core-release-selector-v1.md",
            "docs/core-release-selector-v1-r2c-canonical-evidence.md",
            "docs/core-release-selector-v1-r3-inactive-staging.md",
        )
        for relative in expected:
            with self.subTest(relative=relative):
                self.assertTrue((ROOT / relative).is_file())


if __name__ == "__main__":
    unittest.main()
