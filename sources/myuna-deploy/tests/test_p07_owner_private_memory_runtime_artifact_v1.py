from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import os
from pathlib import Path
import tempfile
import unittest

import build_telegram_gateway_release_v1 as gateway_release
import p07_owner_private_memory_runtime_artifact_v1 as artifact
import p07_transactional_plugin_artifact_v1 as plugin_artifact


def plugin_binding() -> dict[str, object]:
    rows: list[dict[str, object]] = []
    for order, (source_path, destination, mode) in enumerate(gateway_release.COMPONENTS):
        payload = f"runtime-artifact-plugin-{order}\n".encode("ascii")
        rows.append(
            {
                "destination": destination,
                "git_blob": f"{order + 1:040x}",
                "order": order,
                "path": source_path,
                "sha256": sha256(payload).hexdigest(),
                "size": len(payload),
                "source_mode": "100644",
                "target_mode": f"{mode:04o}",
            }
        )

    def support(path: str, payload: bytes, blob: str) -> dict[str, object]:
        return {
            "git_blob": blob,
            "path": path,
            "sha256": sha256(payload).hexdigest(),
            "size": len(payload),
            "source_mode": "100644",
        }

    return plugin_artifact._assemble_binding(
        deploy_commit="c" * 40,
        deploy_tree="d" * 40,
        source_files=rows,
        release_builder=support(
            plugin_artifact.RELEASE_BUILDER_PATH,
            b"runtime-artifact-release-builder\n",
            "e" * 40,
        ),
        config_renderer=support(
            plugin_artifact.CONFIG_RENDERER_PATH,
            b"runtime-artifact-config-renderer\n",
            "f" * 40,
        ),
    )


def boundaries() -> dict[str, object]:
    return {
        program: {
            "identity_digest": f"{index + 1:064x}",
            "mutation_allowed": False,
            "state": "immutable_no_mutation",
        }
        for index, program in enumerate(sorted(artifact.PROGRAMS))
    }


def manifest() -> tuple[dict[str, object], bytes]:
    files = {
        "runtime/owner_memory.py": {
            "mode": artifact.FILE_MODE,
            "sha256": sha256(b"owner-memory-runtime\n").hexdigest(),
            "size": len(b"owner-memory-runtime\n"),
        }
    }
    binding = artifact.build_binding(
        source_core_commit="a" * 40,
        source_core_tree="b" * 40,
        source_deploy_commit="c" * 40,
        source_deploy_tree="d" * 40,
        base_release_digest="1" * 64,
        file_inventory=files,
        plugin_binding=plugin_binding(),
        memory_contract=artifact.MEMORY_CONTRACT,
        source_policy={"diary_mode": "disabled-memory-only"},
        program_boundaries=boundaries(),
    )
    unsigned = {
        "base_release_digest": "1" * 64,
        "core_import_closure": {"algorithm": "synthetic", "files": [], "roots": []},
        "files": files,
        "owner_private_memory_contract": artifact.MEMORY_CONTRACT,
        "owner_private_memory_runtime_binding": binding,
        "runtime_profile": artifact.RUNTIME_PROFILE,
        "schema": artifact.HYBRID_RUNTIME_SCHEMA,
        "source_core_commit": "a" * 40,
        "source_core_tree": "b" * 40,
        "source_deploy_commit": "c" * 40,
        "source_deploy_tree": "d" * 40,
    }
    payload = {**unsigned, "release_digest": sha256(artifact.canonical(unsigned)).hexdigest()}
    return payload, artifact.canonical(payload)


class RuntimeArtifactContractTest(unittest.TestCase):
    def test_projection_is_stable_and_binds_source_inventory_plugin_and_policy(self) -> None:
        payload, raw = manifest()
        first = artifact.projection_from_manifest(payload, manifest_bytes=raw)
        second = artifact.projection_from_manifest(
            deepcopy(payload), manifest_bytes=artifact.canonical(deepcopy(payload))
        )
        self.assertEqual(first, second)
        self.assertEqual(first["source"]["deploy_commit"], "c" * 40)
        self.assertEqual(first["artifact"]["file_count"], 1)
        self.assertEqual(
            first["plugin"]["release_digest"],
            plugin_binding()["target"]["release_digest"],
        )

    def test_source_inventory_plugin_and_manifest_substitution_fail_closed(self) -> None:
        payload, raw = manifest()
        cases: list[tuple[dict[str, object], str]] = []
        source = deepcopy(payload)
        source["source_deploy_tree"] = "9" * 40
        cases.append((source, "manifest_binding_rejected"))
        inventory = deepcopy(payload)
        inventory["files"]["runtime/owner_memory.py"]["mode"] = "0644"
        cases.append((inventory, "inventory_rejected"))
        plugin = deepcopy(payload)
        plugin["owner_private_memory_runtime_binding"]["plugin"]["release_digest"] = "8" * 64
        cases.append((plugin, "binding_digest_rejected"))
        for drifted, code in cases:
            with self.subTest(code=code), self.assertRaisesRegex(RuntimeError, code):
                artifact.projection_from_manifest(
                    drifted, manifest_bytes=artifact.canonical(drifted)
                )
        with self.assertRaisesRegex(RuntimeError, "manifest_rejected"):
            artifact.projection_from_manifest(payload, manifest_bytes=raw + b" ")

    def test_projection_rejects_extra_fields_and_service_substitution(self) -> None:
        payload, raw = manifest()
        projection = artifact.projection_from_manifest(payload, manifest_bytes=raw)
        extra = deepcopy(projection)
        extra["source"]["extra"] = "not-allowed"
        semantic = {key: extra[key] for key in extra if key != "projection_digest"}
        extra["projection_digest"] = artifact.digest(
            "p07_runtime_artifact_projection", semantic
        )
        with self.assertRaisesRegex(RuntimeError, "projection_rejected"):
            artifact.validate_projection(extra)
        service = deepcopy(projection)
        service["service_identity_digest"] = "7" * 64
        semantic = {key: service[key] for key in service if key != "projection_digest"}
        service["projection_digest"] = artifact.digest(
            "p07_runtime_artifact_projection", semantic
        )
        with self.assertRaisesRegex(RuntimeError, "projection_rejected"):
            artifact.validate_projection(service)

    def test_candidate_reopen_requires_exact_bytes_modes_inventory_and_no_links(self) -> None:
        payload, raw = manifest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "runtime"
            target = root / "runtime/owner_memory.py"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"owner-memory-runtime\n")
            (root / "P07_HYBRID_MANIFEST.json").write_bytes(raw)
            for path in (root, root / "runtime"):
                os.chmod(path, 0o550)
            for path in (target, root / "P07_HYBRID_MANIFEST.json"):
                os.chmod(path, 0o440)
            selected, projection = artifact.verify_candidate(root)
            self.assertEqual(selected, payload)
            self.assertEqual(projection["release_digest"], payload["release_digest"])
            os.chmod(target, 0o640)
            with self.assertRaisesRegex(RuntimeError, "mode_rejected"):
                artifact.verify_candidate(root)
            os.chmod(target, 0o440)
            os.chmod(root / "runtime", 0o750)
            extra = root / "runtime/extra.py"
            extra.write_bytes(b"extra\n")
            os.chmod(extra, 0o440)
            os.chmod(root / "runtime", 0o550)
            with self.assertRaisesRegex(RuntimeError, "inventory_rejected"):
                artifact.verify_candidate(root)


if __name__ == "__main__":
    unittest.main()
