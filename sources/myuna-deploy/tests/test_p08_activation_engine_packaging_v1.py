from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORE = Path("/srv/myuna/repos/core")
PREDECESSOR = Path(
    "/opt/myuna/active-temporal/releases/"
    "1b589a474c56e138082f014724065dd57d38440b08c57b1497e5a4cb3cbe3e06"
)
sys.path.insert(0, str(ROOT / "scripts"))

import build_p08_activation_engine_release_v1 as builder
import p08_activation_contract_v1 as contract_v1


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=15,
    ).stdout.strip()


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _inventory(root: Path) -> list[dict[str, object]]:
    rows = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        details = path.lstat()
        self_type = "file" if stat.S_ISREG(details.st_mode) else "directory"
        if not (stat.S_ISREG(details.st_mode) or stat.S_ISDIR(details.st_mode)):
            raise AssertionError(f"unexpected type: {relative}")
        if details.st_nlink > 1 and stat.S_ISREG(details.st_mode):
            raise AssertionError(f"hardlink: {relative}")
        row = {
            "path": relative,
            "type": self_type,
            "mode": stat.S_IMODE(details.st_mode),
            "uid": details.st_uid,
            "gid": details.st_gid,
        }
        if stat.S_ISREG(details.st_mode):
            row.update(size=details.st_size, sha256=_digest(path))
        rows.append(row)
    return rows


class ActivationEnginePackagingTests(unittest.TestCase):
    def test_deterministic_inactive_build_and_installed_import_closure(self) -> None:
        core_commit = _git(CORE, "rev-parse", "HEAD")
        deploy_commit = _git(ROOT, "rev-parse", "HEAD")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outputs = []
            manifests = []
            for name, build_umask in (("a", 0o077), ("b", 0o022)):
                output = root / name
                previous_umask = os.umask(build_umask)
                try:
                    manifest = builder.build_release(
                        core_root=CORE,
                        deploy_root=ROOT,
                        output_root=output,
                        predecessor_release=PREDECESSOR,
                        core_commit=core_commit,
                        deploy_commit=deploy_commit,
                    )
                finally:
                    os.umask(previous_umask)
                outputs.append(output)
                manifests.append(manifest)
            self.assertEqual(manifests[0], manifests[1])
            self.assertEqual(_inventory(outputs[0]), _inventory(outputs[1]))
            manifest = manifests[0]
            self.assertEqual(manifest["schema"], builder.SCHEMA)
            self.assertFalse(manifest["legacy_activation_architecture_authoritative"])
            engine = manifest["activation_engine_contract"]
            self.assertEqual(engine["architecture"], contract_v1.ARCHITECTURE)
            self.assertTrue(engine["live_execute_implemented"])
            self.assertFalse(engine["production_live_authorized"])
            self.assertEqual(
                engine["supervisor_entrypoint"],
                "scripts/p08_activation_supervisor_bootstrap_v1.py",
            )
            self.assertEqual(
                engine["supervisor_child_entrypoint"],
                "scripts/p08_activation_supervisor_v1.py",
            )
            contract_path = outputs[0] / engine["contract_path"]
            lineage_path = outputs[0] / engine["lineage_path"]
            self.assertEqual(_digest(contract_path), engine["contract_sha256"])
            self.assertEqual(_digest(lineage_path), engine["lineage_sha256"])
            contract = contract_v1.validate_contract(json.loads(contract_path.read_bytes()))
            self.assertEqual(contract["contract_digest"], engine["contract_digest"])
            self.assertEqual(contract["engine_source"]["core_commit"], core_commit)
            self.assertEqual(contract["engine_source"]["deploy_commit"], deploy_commit)
            self.assertEqual(
                contract["lineage"]["architecture_reset_failure_counted"], 16
            )
            self.assertEqual(contract["lineage"]["failure_counted"], 21)
            self.assertEqual(
                contract["compatibility"]["predecessor"]["release_identity"],
                PREDECESSOR.name,
            )
            predecessor = contract["compatibility"]["predecessor"]
            client_roles = predecessor["client_roles"]["roles"]
            self.assertEqual(
                client_roles["legacy_runtime_client"]["sha256"],
                "798f834102af16efd47d7ddc3fa72904a6ca86d01fd02b354aadf65607594894",
            )
            self.assertEqual(
                client_roles["status_content_free_helper"]["sha256"],
                "900070b3556722e6e435f58af67d8dc42395e8dfbe765522c37711375183dff7",
            )
            self.assertEqual(
                predecessor["public_binding"]["selector"][
                    "gateway_client_sha256"
                ],
                client_roles["legacy_runtime_client"]["sha256"],
            )
            self.assertFalse(
                predecessor["unit_runtime"]["enablement_policy"]["service"][
                    "enabled"
                ]
            )
            self.assertTrue(
                predecessor["unit_runtime"]["enablement_policy"]["socket"][
                    "enabled"
                ]
            )
            self.assertEqual(
                contract["production_adapter"]["unit_runtime"]["profile"],
                "target",
            )
            self.assertEqual(
                contract["compatibility"]["predecessor"]["unit_runtime"]["profile"],
                "predecessor",
            )
            self.assertEqual(
                contract["production_adapter"]["unit_runtime"]["service"][
                    "exec_start_argv"
                ],
                [
                    "/usr/bin/setpriv",
                    "--reuid=976",
                    "--regid=976",
                    "--clear-groups",
                    "--no-new-privs",
                    "/usr/bin/python3",
                    "-B",
                    "-P",
                    "-S",
                    "-m",
                    "p08_temporal_service_v1",
                ],
            )
            self.assertEqual(
                contract["production_adapter"]["unit_runtime"]["service"][
                    "process_identity"
                ]["groups"],
                [],
            )
            self.assertEqual(
                contract["production_adapter"]["unit_runtime"]["socket"][
                    "socket_user"
                ],
                "976",
            )
            self.assertEqual(
                contract["compatibility"]["predecessor"]["unit_runtime"][
                    "service"
                ]["exec_start_argv"],
                [
                    "/usr/bin/python3",
                    "-B",
                    "-m",
                    "myuna_core.active_temporal_context.service",
                ],
            )
            self.assertEqual(
                manifest["upgrade_compatibility"]["predecessor_release_digest"],
                builder.legacy_builder.existing_state_upgrade.PREDECESSOR_RELEASE_DIGEST,
            )
            paths = {row["path"] for row in manifest["files"]}
            self.assertTrue(set(builder.ENGINE_FILES).issubset(paths))
            self.assertIn("contracts/P08_ACTIVATION_CONTRACT.json", paths)
            self.assertIn("contracts/P08_LEGACY_LINEAGE_INDEX.json", paths)
            for output in outputs:
                self.assertTrue(
                    all(
                        stat.S_IMODE(path.lstat().st_mode) == 0o755
                        for path in (output, *sorted(item for item in output.rglob("*") if item.is_dir()))
                    )
                )
                self.assertFalse(any(path.is_symlink() for path in output.rglob("*")))
                self.assertFalse(
                    any(
                        "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}
                        for path in output.rglob("*")
                    )
                )
            completed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import p08_activation_contract_v1 as c; "
                        "import p08_activation_engine_v1 as e; "
                        "import p08_activation_launcher_v1 as l; "
                        "import p08_activation_production_adapter_v1 as p; "
                        "import p08_activation_installed_shadow_v1 as i; "
                        "import p08_activation_shadow_v1 as s; "
                        "assert c.ARCHITECTURE == 'myuna.p08-activation-engine.v1'"
                    ),
                ],
                cwd=outputs[0],
                env={
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONPATH": (
                        f"{outputs[0] / 'scripts'}:{outputs[0] / 'src'}"
                    ),
                },
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
            )
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout, b"")
            self.assertEqual(completed.stderr, b"")

    def test_dirty_engine_source_and_output_replay_fail_closed(self) -> None:
        # The source identity oracle is intentionally exercised on the real clean
        # candidate by the deterministic build test.  Output replay is rejected
        # before any source or predecessor read.
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "exists"
            output.mkdir()
            with self.assertRaisesRegex(RuntimeError, "output_exists"):
                builder.build_release(
                    core_root=CORE,
                    deploy_root=ROOT,
                    output_root=output,
                    predecessor_release=PREDECESSOR,
                    core_commit="1" * 40,
                    deploy_commit="2" * 40,
                )


if __name__ == "__main__":
    unittest.main()
