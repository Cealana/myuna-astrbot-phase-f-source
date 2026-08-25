from __future__ import annotations

from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORE_ROOT = Path(os.environ.get("MYUNA_P08_CORE_SOURCE", ""))
SCRIPT = ROOT / "scripts" / "build_p08_active_temporal_release_v1.py"
CONTRACT = ROOT / "docs" / "p08-private-service-source-v1.md"


def _load_builder():
    spec = importlib.util.spec_from_file_location("p08_builder", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tree_digest(root: Path) -> str:
    digest = sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


@unittest.skipUnless(CORE_ROOT.is_dir(), "MYUNA_P08_CORE_SOURCE is required")
class P08PrivateServicePackagingTests(unittest.TestCase):
    def test_contract_keeps_source_and_live_boundaries_explicit(self) -> None:
        text = " ".join(CONTRACT.read_text(encoding="utf-8").split())
        for required in (
            "LinuxAdjtimexSynchronizationProbe",
            "does not call a network client or subprocess",
            "exact Telegram runtime peer UID",
            "creates only two new empty databases",
            "does not install",
            "QQ remains excluded",
        ):
            self.assertIn(required, text)

    def test_units_freeze_private_identity_socket_and_no_network(self) -> None:
        service = (ROOT / "systemd/myuna-active-temporal-context-v1.service").read_text()
        socket = (ROOT / "systemd/myuna-active-temporal-context-v1.socket").read_text()
        tmpfiles = (ROOT / "systemd/myuna-active-temporal-context-v1.tmpfiles.conf").read_text()
        self.assertNotIn("User=", service)
        self.assertNotIn("Group=", service)
        self.assertNotIn("SupplementaryGroups=", service)
        self.assertIn(
            "ExecStart=/usr/bin/setpriv --reuid=976 --regid=976 "
            "--clear-groups --no-new-privs /usr/bin/python3 -B -P -S "
            "-m p08_temporal_service_v1",
            service,
        )
        self.assertIn("NoNewPrivileges=yes", service)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", service)
        self.assertIn("SocketUser=976", socket)
        self.assertIn("SocketGroup=982", socket)
        self.assertIn("SocketMode=0660", socket)
        self.assertIn(" 0700 myuna_active_temporal myuna_active_temporal ", tmpfiles)

    def test_build_is_deterministic_and_contains_only_bounded_runtime(self) -> None:
        builder = _load_builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outputs = (root / "a", root / "b")
            for output in outputs:
                builder.build_release(
                    core_root=CORE_ROOT,
                    deploy_root=ROOT,
                    output_root=output,
                    core_commit="a" * 40,
                    deploy_commit="b" * 40,
                )
            self.assertEqual(_tree_digest(outputs[0]), _tree_digest(outputs[1]))
            manifest = json.loads((outputs[0] / "manifest.json").read_text())
            paths = {item["path"] for item in manifest["files"]}
            self.assertIn("src/myuna_core/active_temporal_context/service.py", paths)
            self.assertIn("src/myuna_core/trusted_time/linux.py", paths)
            self.assertFalse(any("owner_profile" in path for path in paths))
            self.assertFalse(any("session" in path for path in paths))
            self.assertFalse(any("__pycache__" in path or path.endswith(".pyc") for path in paths))

    def test_runtime_only_import_smoke(self) -> None:
        builder = _load_builder()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "release"
            builder.build_release(
                core_root=CORE_ROOT,
                deploy_root=ROOT,
                output_root=output,
                core_commit="a" * 40,
                deploy_commit="b" * 40,
            )
            completed = subprocess.run(
                [
                    "python3",
                    "-B",
                    "-c",
                    "from myuna_core.active_temporal_context.service import CLIENT_ID; assert CLIENT_ID == 'telegram-owner-runtime-v1'",
                ],
                env={"PYTHONPATH": str(output / "src"), "PYTHONDONTWRITEBYTECODE": "1"},
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
