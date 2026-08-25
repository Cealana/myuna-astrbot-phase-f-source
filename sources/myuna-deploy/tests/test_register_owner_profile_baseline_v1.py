from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import unittest

from install_owner_profile_data_v1 import (
    install_profile_release,
    load_intake_bundle,
)
from myuna_core.owner_profile.approval import (
    APPROVAL_DECISION,
    APPROVAL_SCOPE,
    APPROVAL_TYPE,
)
from myuna_core.owner_profile.loader import build_receipt
from register_owner_profile_baseline_v1 import (
    OwnerProfileBaselineRegisterError,
    register_baseline,
)


PROFILE_BYTES = """schema_version = 1
document_type = "owner_profile_baseline"
profile_id = "synthetic-registered-baseline"
profile_revision = 2

[[sections]]
section_id = "synthetic-section"
topic_key = "synthetic-topic"
category = "long_term_preference"
title = "Synthetic 中文"
body = "Synthetic stable registered baseline."
keywords = ["synthetic", "中文"]
""".encode("utf-8")


def canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


class RegisterOwnerProfileBaselineV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.uid = os.geteuid()
        self.gid = os.getegid()
        self.digest = sha256(PROFILE_BYTES).hexdigest()
        self.intake_root = self.root / "intake"
        self.intake_root.mkdir(mode=0o700)
        self.intake = self.intake_root / f"r2-{self.digest}"
        self.intake.mkdir(mode=0o700)
        approval = {
            "schema_version": 1,
            "approval_type": APPROVAL_TYPE,
            "approval_scope": APPROVAL_SCOPE,
            "decision": APPROVAL_DECISION,
            "profile_schema_version": 1,
            "profile_id": "synthetic-registered-baseline",
            "profile_revision": 2,
            "profile_sha256": self.digest,
        }
        payloads = {
            "profile.toml": PROFILE_BYTES,
            "receipt.json": canonical(build_receipt(PROFILE_BYTES)),
            "approval.json": canonical(approval),
        }
        for name, payload in payloads.items():
            path = self.intake / name
            path.write_bytes(payload)
            path.chmod(0o600)
        destination_parent = self.root / "destination"
        destination_parent.mkdir(mode=0o755)
        self.runtime_root = destination_parent / "profile-root"
        bundle = load_intake_bundle(
            self.intake,
            intake_uid=self.uid,
            allowed_roots=(self.intake_root,),
        )
        self.installed, _ = install_profile_release(
            bundle,
            destination_root=self.runtime_root,
            root_uid=self.uid,
            service_uid=self.uid,
            service_gid=self.gid,
        )
        ledger_parent = self.root / "ledger-parent"
        ledger_parent.mkdir(mode=0o755)
        self.ledger_root = ledger_parent / "write-v1"
        self.ledger = self.ledger_root / "ledger"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def register(self):
        return register_baseline(
            self.intake,
            self.installed,
            intake_uid=self.uid,
            service_uid=self.uid, intake_root=self.intake_root,
            ledger_root=self.ledger_root,
            ledger_directory=self.ledger,
            ledger_uid=self.uid, ledger_gid=self.gid,
        )

    def test_exact_baseline_registration_is_private_and_idempotent(self) -> None:
        state, created = self.register()
        self.assertTrue(created)
        self.assertEqual(state.active_revision, 2)
        self.assertEqual(state.last_sequence, 1)
        events = list(self.ledger.iterdir())
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].stat().st_mode & 0o777, 0o600)

        repeated, repeated_created = self.register()
        self.assertEqual(repeated, state)
        self.assertFalse(repeated_created)

    def test_installed_release_or_approval_drift_rejects(self) -> None:
        profile = self.installed / "profile.toml"
        profile.chmod(0o640)
        with self.assertRaisesRegex(
            OwnerProfileBaselineRegisterError,
            "profile_permission_drift",
        ):
            self.register()
        profile.chmod(0o600)

        approval = self.intake / "approval.json"
        approval.write_bytes(b"synthetic-conflict\n")
        with self.assertRaisesRegex(
            OwnerProfileBaselineRegisterError,
            "malformed_approval",
        ):
            self.register()

    def test_conflicting_existing_ledger_is_preserved(self) -> None:
        self.register()
        event = next(self.ledger.iterdir())
        event.chmod(0o640)
        with self.assertRaisesRegex(
            OwnerProfileBaselineRegisterError,
            "lifecycle_permission_drift",
        ):
            self.register()
        self.assertEqual(event.stat().st_mode & 0o777, 0o640)

    def test_confirmation_digest_is_private_not_status_output(self) -> None:
        state, _ = self.register()
        approval_bytes = (self.intake / "approval.json").read_bytes()
        confirmation_digest = sha256(approval_bytes).hexdigest()
        record = state.revisions[2]
        self.assertEqual(record.confirmation_sha256, confirmation_digest)
        status = json.dumps(
            {
                "revision": state.active_revision,
                "raw_content_recorded": False,
            }
        )
        self.assertNotIn(self.digest, status)
        self.assertNotIn(confirmation_digest, status)


if __name__ == "__main__":
    unittest.main()
