from __future__ import annotations

import importlib.util
import inspect
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
SCRIPT = SCRIPTS / "activate_owner_profile_local_provider_v1.py"
SPEC = importlib.util.spec_from_file_location(
    "activate_owner_profile_local_provider_v1", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
activation = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = activation
SPEC.loader.exec_module(activation)


class ActivateOwnerProfileLocalProviderV1Tests(unittest.TestCase):
    def test_target_binding_selects_exact_content_addressed_core_release(self) -> None:
        binding, selector = activation._target_binding("a" * 64)
        document = json.loads(binding)
        selected = document["selected_release"]
        self.assertEqual(selected["tree_sha256"], activation.CORE_TARGET_RELEASE)
        self.assertEqual(selected["source_commit"], activation.CORE_TARGET_COMMIT)
        self.assertEqual(selected["file_count"], activation.CORE_TARGET_FILE_COUNT)
        self.assertIn(activation.CORE_TARGET_RELEASE.encode("ascii"), selector)

    def test_artifact_and_install_receipts_are_content_free_and_canonical(self) -> None:
        artifact = activation._artifact_manifest_bytes()
        receipt = activation._installation_receipt_bytes()
        self.assertEqual(artifact, activation.canonical_json_bytes(json.loads(artifact)))
        self.assertEqual(receipt, activation.canonical_json_bytes(json.loads(receipt)))
        serialized = (artifact + receipt).decode("ascii")
        for forbidden in ("message_text", "raw_query", "profile.toml", "identity"):
            self.assertNotIn(forbidden, serialized)
        with TemporaryDirectory() as temp:
            fixture = Path(temp) / "fixture.bin"
            fixture.write_bytes(b"streamed-digest-fixture" * 100_000)
            self.assertEqual(
                activation._digest_file(fixture),
                activation._digest(fixture.read_bytes()),
            )

    def test_core_dropin_rebinds_deepseek_after_credential_list_reset(self) -> None:
        text = activation.CORE_DROPIN_BYTES.decode("ascii")
        self.assertIn("Wants=myuna-local-provider-v1.service", text)
        self.assertIn("myuna-owner-profile-read-v1.socket", text)
        self.assertIn("EnvironmentFile=/etc/myuna/p07-local-profile-v1.env", text)
        self.assertIn("LoadCredential=\n", text)
        self.assertIn(
            "LoadCredential=deepseek_api_key:/etc/myuna/secrets/deepseek-api-key",
            text,
        )
        self.assertIn("telegram_owner_core_token", text)
        self.assertIn("qq_owner_core_token", text)
        self.assertLess(
            text.index("LoadCredential=\n"),
            text.index("LoadCredential=deepseek_api_key:"),
        )
        self.assertNotIn("owner-memory", text.casefold())

    def test_confirmation_is_exact_and_names_only_bounded_units(self) -> None:
        self.assertEqual(
            activation.CONFIRMATION,
            "I_UNDERSTAND_P07_WILL_RESTART_MYUNA_CORE_AND_QQ_GATEWAY",
        )
        self.assertEqual(activation.CORE_SERVICE, "myuna-core@qq.service")
        self.assertEqual(
            activation.GATEWAY_SOCKET, "myuna-qq-owner-runtime-dev.socket"
        )
        self.assertEqual(
            activation.GATEWAY_SERVICE, "myuna-qq-owner-runtime-dev.service"
        )

    def test_synthetic_probe_source_has_no_profile_or_credential_input(self) -> None:
        source = inspect.getsource(activation._wait_local_service) + inspect.getsource(
            activation._synthetic_probe
        )
        self.assertTrue(activation._local_health_ready(200, b'{"status":"ok"}'))
        self.assertFalse(activation._local_health_ready(503, b'{"status":"ok"}'))
        self.assertFalse(activation._local_health_ready(200, b'{"status":"loading"}'))
        self.assertFalse(activation._local_health_ready(200, b"not-json"))
        self.assertIn("http://127.0.0.1:879/health", source)
        self.assertIn("Synthetic protocol probe", source)
        self.assertIn("ProxyHandler({})", source)
        self.assertNotIn("Authorization", source)
        self.assertNotIn("profile.toml", source)
        self.assertNotIn("deepseek_api_key", source)


if __name__ == "__main__":
    unittest.main()
