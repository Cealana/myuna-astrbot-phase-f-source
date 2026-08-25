from __future__ import annotations

import json
import inspect
from pathlib import Path
import unittest

from scripts.activate_v5_voice_hotfix import (
    BUILD_ID,
    OPERATION,
    TARGET_CORE_COMMIT,
    activation_digest,
    ensure_definition_candidate,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/activate_v5_voice_hotfix.py"


class VoiceHotfixActivationTests(unittest.TestCase):
    def test_digest_is_canonical_and_change_sensitive(self) -> None:
        plan = {
            "operation": OPERATION,
            "target": {"build_id": BUILD_ID, "core": TARGET_CORE_COMMIT},
        }
        encoded = json.loads(json.dumps(plan))
        self.assertEqual(activation_digest(plan), activation_digest(encoded))
        changed = {**plan, "operation": "different"}
        self.assertNotEqual(activation_digest(plan), activation_digest(changed))

    def test_runtime_configs_bind_exact_release_and_keep_capabilities_closed(self) -> None:
        environment = (ROOT / "config/qq-owner-v5-voice-hotfix-1.env").read_text(
            encoding="utf-8"
        )
        capability = json.loads(
            (ROOT / "config/capabilities/dev-v5-voice-hotfix-1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIn(f"MYUNA_DEFINITION_RELEASE=v5-{BUILD_ID}", environment)
        self.assertIn("MYUNA_MEMORY_WORKER_ENABLED=false", environment)
        self.assertEqual(capability["definition"]["build_id"], BUILD_ID)
        self.assertFalse(capability["capabilities"]["long_term_memory_read"]["enabled"])
        self.assertFalse(capability["capabilities"]["long_term_memory_write"]["enabled"])
        self.assertFalse(capability["capabilities"]["tools"]["enabled"])
        self.assertFalse(capability["capabilities"]["vision"]["enabled"])

    def test_script_has_narrow_restart_and_verified_rollback_contract(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"qq_core_restart": True', source)
        self.assertIn('"napcat_restart": False', source)
        self.assertIn('"astrbot_restart": False', source)
        self.assertIn('"database_writes": False', source)
        self.assertIn("create_backups(stamp, plan)", source)
        self.assertIn("rollback(backup)", source)
        self.assertIn("allowed_heads", source)
        self.assertIn("_target_deploy_commit()", source)
        self.assertNotIn('restart", "myuna-napcat-dev', source)
        self.assertNotIn('restart", "myuna-astrbot-dev', source)

    def test_candidate_install_reuses_the_hash_verified_evaluated_artifact(self) -> None:
        source = inspect.getsource(ensure_definition_candidate)
        self.assertIn("shutil.copytree(EXTERNAL_CANDIDATE", source)
        self.assertIn("CANDIDATE_SUMMARY_SHA256", source)
        self.assertIn("CANDIDATE_MANIFEST_SHA256", source)
        self.assertNotIn("build_runtime_hotfix.py", source)


if __name__ == "__main__":
    unittest.main()
