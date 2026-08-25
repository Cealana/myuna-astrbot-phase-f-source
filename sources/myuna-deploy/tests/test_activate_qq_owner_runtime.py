from __future__ import annotations

from pathlib import Path
import unittest

from scripts.activate_qq_owner_runtime import (
    BINDING_ID,
    EVIDENCE_SHA256,
    FINALIZATION_DIGEST,
    NAMESPACE_ID,
    OPERATION,
    PRINCIPAL_ID,
    activation_digest,
    public_receipt,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "activate_qq_owner_runtime.py"


class QQOwnerRuntimeActivationTests(unittest.TestCase):
    def test_digest_is_stable_and_plan_bound(self) -> None:
        plan = {
            "operation": OPERATION,
            "identity": {
                "binding_id": BINDING_ID,
                "evidence_sha256": EVIDENCE_SHA256,
                "finalization_digest": FINALIZATION_DIGEST,
                "namespace_id": NAMESPACE_ID,
                "principal_id": PRINCIPAL_ID,
            },
        }
        self.assertEqual(activation_digest(plan), activation_digest(plan))
        changed = {**plan, "operation": "different"}
        self.assertNotEqual(activation_digest(plan), activation_digest(changed))

    def test_receipt_contains_no_secret_and_claims_no_extra_capability(self) -> None:
        receipt = public_receipt(
            digest="a" * 64,
            plan={"source": {"bundle_sha256": "b" * 64}},
            backups=[
                {
                    "filename": "safe.dump",
                    "label": "pre",
                    "sha256": "c" * 64,
                    "linux_path": "/safe/safe.dump",
                }
            ],
        )
        rendered = repr(receipt)
        self.assertNotIn("token", rendered.casefold())
        self.assertFalse(receipt["auto_start_enabled"])
        self.assertFalse(receipt["group_chat"])
        self.assertFalse(receipt["memory_read"])
        self.assertFalse(receipt["memory_write"])
        self.assertFalse(receipt["tools"])

    def test_script_requires_digest_backups_and_clean_rollback(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--approved-plan-digest")', source)
        self.assertIn('create_verified_backup("pre"', source)
        self.assertIn('create_verified_backup("post"', source)
        self.assertIn("copy_backup_to_windows", source)
        self.assertIn("DROP FUNCTION gateway_runtime.resolve_verified_binding", source)
        self.assertIn('"systemctl", "disable"', source)
        self.assertNotIn('"systemctl", "enable"', source)
        self.assertIn("MYUNA_MEMORY_WORKER_ENABLED=false", (
            ROOT / "config" / "qq-owner-v5.env"
        ).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
