from __future__ import annotations

import ast
from copy import deepcopy
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from core_release_selector import (  # noqa: E402
    canonical_json_bytes,
    load_binding_intent,
    parse_json_document,
    render_guard_dropin,
    render_runtime_binding,
    render_selector_dropin,
    SelectionCandidate,
)
import core_release_selector_transaction as v1  # noqa: E402
from core_release_selector_transaction_v2 import (  # noqa: E402
    ACTIVATION_PLAN_SCHEMA,
    ACTIVATION_SEQUENCE,
    GATEWAY_SOCKET_UNIT,
    TRANSACTION_MANIFEST_SCHEMA,
    TransactionContractError,
    build_activation_plan,
    build_transaction_payloads,
    digest,
    load_activation_plan,
    transaction_tree_digest,
    validate_transaction_payloads,
)
from install_core_release_selector_transaction_v2 import (  # noqa: E402
    TransactionInstallError,
    install_inactive_transaction,
)


R4B_PLAN_DIGEST = "f" * 64


def fixture() -> dict[str, object]:
    intent = load_binding_intent(
        parse_json_document(
            (
                ROOT / "config/core-release-selector-v1-binding-intent.json"
            ).read_bytes()
        )
    )
    candidate = SelectionCandidate(selected_release=intent.selected_release)
    selector = render_selector_dropin(candidate).encode("utf-8")
    guard = render_guard_dropin(intent.verifier_script_path).encode("utf-8")
    base = (
        b"[Service]\n"
        b"WorkingDirectory=/srv/myuna/repos/core\n"
        b"Environment=PYTHONPATH=/srv/myuna/repos/core/src\n"
    )
    legacy = (
        b"[Service]\n"
        b"WorkingDirectory=/srv/myuna/releases/core/legacy\n"
        b"Environment=PYTHONPATH=/srv/myuna/releases/core/legacy/src\n"
    )
    feature = b"[Service]\nEnvironment=MYUNA_FEATURE=1\n"
    rollback = {"90-legacy.conf": legacy, "feature.conf": feature}
    final = {
        v1.GUARD_NAME: guard,
        v1.SELECTOR_NAME: selector,
        "feature.conf": feature,
    }
    writes = {v1.GUARD_NAME: guard, v1.SELECTOR_NAME: selector}
    plan = build_activation_plan(
        deploy_commit="a" * 40,
        core_commit="b" * 40,
        migration_contract_sha256="c" * 64,
        r3b_plan_digest="d" * 64,
        binding_intent_sha256="e" * 64,
        verifier_sha256=intent.verifier_script_sha256,
        base_template_sha256=digest(base),
        prestate_dropin_sha256={
            name: digest(payload) for name, payload in rollback.items()
        },
        prestate_effective_owner="90-legacy.conf",
        prestate_working_directory="/srv/myuna/releases/core/legacy",
        target_release_path=intent.selected_release.release_path.as_posix(),
        target_tree_sha256=intent.selected_release.tree_sha256,
        target_file_count=intent.selected_release.file_count,
        final_dropin_sha256={
            name: digest(payload) for name, payload in final.items()
        },
        write_dropin_sha256={
            name: digest(payload) for name, payload in writes.items()
        },
        deletes=("90-legacy.conf",),
        gateway_fragment_sha256="1" * 64,
        gateway_dropin_sha256={"gateway.conf": "2" * 64},
        gateway_socket_fragment_sha256="3" * 64,
        gateway_socket_dropin_sha256={},
        gateway_socket_listen_stream="/run/myuna-gateway/qq-owner.sock",
        gateway_socket_unit_file_state="enabled",
        gateway_socket_substate="running",
    )
    binding = canonical_json_bytes(
        render_runtime_binding(
            intent, approval_plan_digest=digest(plan)
        ).to_payload()
    )
    payloads = build_transaction_payloads(
        activation_plan=plan,
        runtime_binding=binding,
        base_template=base,
        rollback_dropins=rollback,
        final_dropins=final,
        write_dropins=writes,
        deletes=("90-legacy.conf",),
    )
    return {
        "intent": intent,
        "plan": plan,
        "binding": binding,
        "base": base,
        "rollback": rollback,
        "final": final,
        "writes": writes,
        "payloads": payloads,
    }


class SocketAwareActivationPlanTests(unittest.TestCase):
    def test_plan_is_canonical_and_socket_aware(self) -> None:
        plan = fixture()["plan"]
        loaded = load_activation_plan(plan)
        self.assertEqual(canonical_json_bytes(loaded), plan)
        self.assertEqual(loaded["schema"], ACTIVATION_PLAN_SCHEMA)
        self.assertEqual(
            loaded["gateway"]["socket"]["unit"], GATEWAY_SOCKET_UNIT
        )
        self.assertTrue(loaded["gateway"]["service_triggered_by_socket"])
        self.assertEqual(
            loaded["activation"]["sequence"], list(ACTIVATION_SEQUENCE)
        )
        self.assertTrue(
            loaded["rollback"]["restore_gateway_socket_running_state"]
        )

    def test_socket_stop_precedes_service_and_start_precedes_service(self) -> None:
        sequence = load_activation_plan(fixture()["plan"])["activation"][
            "sequence"
        ]
        self.assertLess(
            sequence.index("stop Gateway socket explicitly"),
            sequence.index("stop Gateway service explicitly"),
        )
        self.assertLess(
            sequence.index("start Gateway socket explicitly"),
            sequence.index("start Gateway service explicitly"),
        )

    def test_plan_rejects_missing_socket(self) -> None:
        payload = parse_json_document(fixture()["plan"])
        payload["gateway"].pop("socket")
        with self.assertRaises(TransactionContractError):
            load_activation_plan(canonical_json_bytes(payload))

    def test_plan_rejects_socket_hash_drift(self) -> None:
        payload = parse_json_document(fixture()["plan"])
        payload["gateway"]["socket"]["fragment_sha256"] = "x" * 64
        with self.assertRaises(TransactionContractError):
            load_activation_plan(canonical_json_bytes(payload))

    def test_plan_rejects_reversed_stop_order(self) -> None:
        payload = parse_json_document(fixture()["plan"])
        sequence = payload["activation"]["sequence"]
        left = sequence.index("stop Gateway socket explicitly")
        right = sequence.index("stop Gateway service explicitly")
        sequence[left], sequence[right] = sequence[right], sequence[left]
        with self.assertRaises(TransactionContractError):
            load_activation_plan(canonical_json_bytes(payload))


class SocketAwareTransactionTests(unittest.TestCase):
    def test_v2_transaction_round_trip_is_plan_bound(self) -> None:
        item = fixture()
        evidence = validate_transaction_payloads(item["payloads"])
        binding = parse_json_document(item["binding"])
        manifest = parse_json_document(item["payloads"][v1.MANIFEST_PATH])
        self.assertEqual(
            binding["approval_plan_digest"], digest(item["plan"])
        )
        self.assertEqual(evidence.activation_plan_digest, digest(item["plan"]))
        self.assertEqual(manifest["schema"], TRANSACTION_MANIFEST_SCHEMA)
        self.assertEqual(
            evidence.transaction_tree_sha256,
            transaction_tree_digest(item["payloads"]),
        )

    def test_v1_transaction_is_rejected_by_v2_validator(self) -> None:
        item = fixture()
        plan = load_activation_plan(item["plan"])
        legacy_plan = deepcopy(plan)
        legacy_plan["schema"] = v1.ACTIVATION_PLAN_SCHEMA
        legacy_plan["gateway"].pop("socket")
        legacy_plan["gateway"].pop("service_triggered_by_socket")
        legacy_plan["activation"]["sequence"] = list(v1.ACTIVATION_SEQUENCE)
        legacy_plan["activation"]["health_checks"] = list(v1.HEALTH_CHECKS)
        legacy_plan["rollback"].pop(
            "restore_gateway_socket_running_state"
        )
        legacy_plan["scope"] = {
            "allowed": list(v1.ALLOWED_SCOPE),
            "forbidden": list(v1.FORBIDDEN_SCOPE),
        }
        legacy_plan_bytes = canonical_json_bytes(legacy_plan)
        legacy_binding = canonical_json_bytes(
            render_runtime_binding(
                item["intent"], approval_plan_digest=digest(legacy_plan_bytes)
            ).to_payload()
        )
        legacy_payloads = v1.build_transaction_payloads(
            activation_plan=legacy_plan_bytes,
            runtime_binding=legacy_binding,
            base_template=item["base"],
            rollback_dropins=item["rollback"],
            final_dropins=item["final"],
            write_dropins=item["writes"],
            deletes=("90-legacy.conf",),
        )
        with self.assertRaises(TransactionContractError):
            validate_transaction_payloads(legacy_payloads)

    def test_modified_socket_plan_fails_even_with_rehashed_manifest(self) -> None:
        payloads = dict(fixture()["payloads"])
        plan = parse_json_document(payloads[v1.ACTIVATION_PLAN_PATH])
        plan["gateway"]["socket"]["unit_file_state"] = "disabled"
        payloads[v1.ACTIVATION_PLAN_PATH] = canonical_json_bytes(plan)
        manifest = parse_json_document(payloads[v1.MANIFEST_PATH])
        manifest["activation_plan_digest"] = digest(
            payloads[v1.ACTIVATION_PLAN_PATH]
        )
        manifest["artifacts"][v1.ACTIVATION_PLAN_PATH] = digest(
            payloads[v1.ACTIVATION_PLAN_PATH]
        )
        payloads[v1.MANIFEST_PATH] = canonical_json_bytes(manifest)
        with self.assertRaises(TransactionContractError):
            validate_transaction_payloads(payloads)

    def test_wrong_binding_digest_fails_closed(self) -> None:
        item = fixture()
        binding = parse_json_document(item["binding"])
        binding["approval_plan_digest"] = "0" * 64
        with self.assertRaises(TransactionContractError):
            build_transaction_payloads(
                activation_plan=item["plan"],
                runtime_binding=canonical_json_bytes(binding),
                base_template=item["base"],
                rollback_dropins=item["rollback"],
                final_dropins=item["final"],
                write_dropins=item["writes"],
                deletes=("90-legacy.conf",),
            )

    def test_extra_artifact_fails_closed(self) -> None:
        payloads = dict(fixture()["payloads"])
        payloads["unexpected.txt"] = b"x"
        with self.assertRaises(TransactionContractError):
            validate_transaction_payloads(payloads)


class SocketAwareInactiveInstallTests(unittest.TestCase):
    def _write_source(
        self, root: Path, payloads: dict[str, bytes]
    ) -> Path:
        source = root / "source"
        source.mkdir()
        for relative, payload in payloads.items():
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        return source

    def _roots(self, root: Path) -> tuple[Path, Path]:
        managed = root / "opt/myuna/core-release-selector"
        managed.mkdir(parents=True, mode=0o750)
        os.chown(managed, os.getuid(), os.getgid())
        managed.chmod(0o750)
        return managed / "transactions", managed / "receipts"

    def test_install_is_inactive_socket_aware_and_idempotent(self) -> None:
        item = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self._write_source(root, item["payloads"])
            transaction_root, receipt_root = self._roots(root)
            expected = transaction_tree_digest(item["payloads"])
            arguments = dict(
                source_root=source,
                expected_transaction_digest=expected,
                transaction_root=transaction_root,
                receipt_root=receipt_root,
                uid=os.getuid(),
                gid=os.getgid(),
            )
            first = install_inactive_transaction(
                R4B_PLAN_DIGEST, **arguments
            )
            second = install_inactive_transaction(
                R4B_PLAN_DIGEST, **arguments
            )
            self.assertTrue(first["gateway_socket_in_contract"])
            self.assertTrue(first["transaction_created"])
            self.assertTrue(first["receipt_created"])
            self.assertFalse(first["runtime_changed"])
            self.assertFalse(second["transaction_created"])
            self.assertFalse(second["receipt_created"])
            destination = transaction_root / expected
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o550)

    def test_v1_source_cannot_be_installed_by_v2_installer(self) -> None:
        item = fixture()
        payloads = dict(item["payloads"])
        manifest = parse_json_document(payloads[v1.MANIFEST_PATH])
        manifest["schema"] = v1.TRANSACTION_MANIFEST_SCHEMA
        payloads[v1.MANIFEST_PATH] = canonical_json_bytes(manifest)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self._write_source(root, payloads)
            transaction_root, receipt_root = self._roots(root)
            with self.assertRaises(TransactionInstallError):
                install_inactive_transaction(
                    R4B_PLAN_DIGEST,
                    source_root=source,
                    expected_transaction_digest=transaction_tree_digest(
                        payloads
                    ),
                    transaction_root=transaction_root,
                    receipt_root=receipt_root,
                    uid=os.getuid(),
                    gid=os.getgid(),
                )


class SocketAwareStaticSafetyTests(unittest.TestCase):
    def test_contract_has_no_side_effect_api(self) -> None:
        path = ROOT / "scripts/core_release_selector_transaction_v2.py"
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported: set[str] = set()
        calls: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(
                    alias.name.split(".", 1)[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
            elif isinstance(node, ast.Call) and isinstance(
                node.func, ast.Name
            ):
                calls.add(node.func.id)
        self.assertTrue(
            {
                "os",
                "subprocess",
                "socket",
                "requests",
                "urllib",
                "shutil",
            }.isdisjoint(imported)
        )
        self.assertTrue({"open", "system", "popen"}.isdisjoint(calls))

    def test_installer_cannot_touch_active_runtime(self) -> None:
        path = (
            ROOT
            / "scripts/install_core_release_selector_transaction_v2.py"
        )
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(
                    alias.name.split(".", 1)[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        self.assertTrue(
            {
                "subprocess",
                "socket",
                "requests",
                "urllib",
            }.isdisjoint(imported)
        )
        self.assertNotIn("/etc/systemd/", source)
        self.assertNotIn(
            "/etc/myuna/core-release-selector/qq.binding.json", source
        )
        self.assertNotIn("daemon-reload", source)


if __name__ == "__main__":
    unittest.main()
