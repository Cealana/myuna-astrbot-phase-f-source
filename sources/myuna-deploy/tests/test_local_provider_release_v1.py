from __future__ import annotations

from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys
import tarfile
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_local_provider_artifacts_v1.py"
SPEC = importlib.util.spec_from_file_location("verify_local_provider_artifacts_v1", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)


class LocalProviderReleaseV1Tests(unittest.TestCase):
    def test_regular_artifact_check_is_size_name_and_digest_bound(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            payload = b"synthetic-public-artifact"
            path = root / "synthetic.bin"
            path.write_bytes(payload)
            spec = verifier.ArtifactSpec(
                "synthetic.bin", len(payload), sha256(payload).hexdigest()
            )
            verifier.verify_regular_artifact(path, spec)
            with self.assertRaises(verifier.LocalProviderArtifactError):
                verifier.verify_regular_artifact(
                    path,
                    verifier.ArtifactSpec("synthetic.bin", len(payload), "0" * 64),
                )

    def test_runtime_member_rejects_escape_absolute_hardlink_and_device(self) -> None:
        safe = tarfile.TarInfo("llama-b10217/llama-server")
        safe.type = tarfile.REGTYPE
        verifier._safe_runtime_member(safe)
        unsafe = []
        for name in (
            "../escape",
            "/absolute",
            "llama-b10217/../escape",
            "wrong-root/llama-server",
        ):
            member = tarfile.TarInfo(name)
            member.type = tarfile.REGTYPE
            unsafe.append(member)
        hardlink = tarfile.TarInfo("llama-b10217/hard")
        hardlink.type = tarfile.LNKTYPE
        hardlink.linkname = "llama-b10217/llama-server"
        unsafe.append(hardlink)
        device = tarfile.TarInfo("llama-b10217/device")
        device.type = tarfile.CHRTYPE
        unsafe.append(device)
        escaping_link = tarfile.TarInfo("llama-b10217/link")
        escaping_link.type = tarfile.SYMTYPE
        escaping_link.linkname = "../outside"
        unsafe.append(escaping_link)
        for member in unsafe:
            with self.subTest(name=member.name), self.assertRaises(
                verifier.LocalProviderArtifactError
            ):
                verifier._safe_runtime_member(member)

    def test_receipt_is_canonical_public_metadata_only(self) -> None:
        runtime = {"tag": "synthetic", "archive_sha256": "a" * 64}
        model = {"repository": "synthetic/model", "sha256": "b" * 64}
        payload = verifier.canonical_receipt(runtime, model)
        document = json.loads(payload)
        self.assertFalse(document["private_content_present"])
        self.assertEqual(payload, verifier.canonical_receipt(runtime, model))
        serialized = payload.decode("ascii")
        for forbidden in ("profile.toml", "raw_query", "message_text", "identity"):
            self.assertNotIn(forbidden, serialized)

    def test_service_is_privileged_loopback_offline_and_resource_bounded(self) -> None:
        unit = (ROOT / "systemd" / "myuna-local-provider-v1.service").read_text(
            encoding="utf-8"
        )
        required = (
            "User=myuna_local_provider",
            "--host 127.0.0.1 --port 879",
            "--alias myuna-local-owner-v1",
            "--ctx-size 8192",
            "--parallel 1",
            "--reasoning off",
            "--no-webui",
            "--no-slots",
            "--offline",
            "--no-cache-prompt",
            "--log-disable",
            "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
            "AmbientCapabilities=CAP_NET_BIND_SERVICE",
            "IPAddressDeny=any",
            "IPAddressAllow=localhost",
            "MemoryMax=8G",
        )
        for value in required:
            self.assertIn(value, unit)
        self.assertNotIn("Authorization", unit)
        self.assertNotIn("--log-prompts-dir", unit)
        self.assertNotIn("0.0.0.0", unit)

    def test_core_overlay_replaces_legacy_read_and_allows_only_local_profile(self) -> None:
        overlay = {}
        for line in (ROOT / "config" / "qq-owner-p07-local-profile-v1.env").read_text(
            encoding="utf-8"
        ).splitlines():
            key, value = line.split("=", 1)
            overlay[key] = value
        self.assertEqual(overlay["MYUNA_PROVIDERS_ENABLED"], "local")
        self.assertEqual(overlay["MYUNA_OWNER_MEMORY_READ_ENABLED"], "false")
        self.assertEqual(overlay["MYUNA_OWNER_PROFILE_READ_ENABLED"], "true")
        self.assertEqual(overlay["MYUNA_OWNER_PROFILE_PROVIDER_ALLOWLIST"], "local")
        self.assertEqual(
            overlay["MYUNA_LOCAL_PROVIDER_BASE_URL"],
            "http://127.0.0.1:879/v1",
        )

    def test_capability_manifest_is_read_only_profile_and_local_model(self) -> None:
        document = json.loads(
            (
                ROOT
                / "config"
                / "capabilities"
                / "qq-owner-v6-p07-local-profile-v1.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            document["service"]["response_scope"],
            "owner_private_dev_profile_read_v1",
        )
        self.assertTrue(document["capabilities"]["long_term_memory_read"]["enabled"])
        self.assertFalse(document["capabilities"]["long_term_memory_write"]["enabled"])
        for route in ("default", "persona_escalation"):
            self.assertEqual(document["models"][route]["provider"], "local")
            self.assertEqual(
                document["models"][route]["model"], "myuna-local-owner-v1"
            )
            self.assertEqual(document["models"][route]["thinking"], "disabled")


if __name__ == "__main__":
    unittest.main()
