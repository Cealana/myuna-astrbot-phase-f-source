from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import p07_credential_binding as binding
from scripts import reconcile_p07_core_credential_binding_v1 as reconciliation


class CredentialBindingContractTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, Path, Path]:
        dropins = root / "dropins"
        dropins.mkdir()
        source = root / "secret-source"
        source.write_bytes(b"synthetic-not-a-secret")
        source.chmod(0o600)
        (dropins / "credentials.conf").write_text(
            f"[Service]\n{binding.DIRECTIVE_PREFIX}{source.as_posix()}\n",
            encoding="ascii",
        )
        redundant = dropins / "zzzzzzzzz-p07-hybrid-external-v1.conf"
        redundant.write_bytes(binding.legacy_duplicate_hybrid_gate(source))
        for path in dropins.glob("*.conf"):
            path.chmod(0o644)
        effective = root / "effective"
        effective.write_bytes(b"synthetic-effective")
        effective.chmod(0o440)
        return dropins, source, effective

    def _duplicate(self, dropins: Path, source: Path) -> dict[str, object]:
        return binding.verify_reconcilable_duplicate(
            dropins,
            canonical_dropin="credentials.conf",
            redundant_dropin="zzzzzzzzz-p07-hybrid-external-v1.conf",
            expected_source=source,
            expected_uid=os.geteuid(),
        )

    def test_duplicate_same_source_is_reconcilable_but_never_strict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dropins, source, _effective = self._fixture(Path(temporary))
            evidence = self._duplicate(dropins, source)
            self.assertEqual(evidence["declaration_count"], 2)
            with self.assertRaises(binding.CredentialBindingRejected) as captured:
                binding.verify_strict_binding(
                    dropins,
                    canonical_dropin="credentials.conf",
                    expected_source=source,
                    expected_uid=os.geteuid(),
                )
            self.assertEqual(captured.exception.code, "credential_category_rejected")
            (dropins / "zzzzzzzzz-p07-hybrid-external-v1.conf").write_bytes(
                binding.canonical_hybrid_gate()
            )
            strict = binding.verify_strict_binding(
                dropins,
                canonical_dropin="credentials.conf",
                expected_source=source,
                expected_uid=os.geteuid(),
            )
            self.assertEqual(strict["declaration_count"], 1)
            self.assertEqual(strict["effective_declaration_count"], 1)

    def test_ordered_reset_requires_same_source_rebind(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dropins, source, _effective = self._fixture(Path(temporary))
            (dropins / "zzzzzzzzz-p07-hybrid-external-v1.conf").write_bytes(
                binding.canonical_hybrid_gate()
            )
            local_profile = dropins / "zzzzzzz-p07-local-profile-v1.conf"
            local_profile.write_text(
                "[Service]\nLoadCredential=\n"
                f"{binding.DIRECTIVE_PREFIX}{source.as_posix()}\n"
                "LoadCredential=telegram_owner_core_token:/synthetic\n",
                encoding="ascii",
            )
            local_profile.chmod(0o644)
            strict = binding.verify_strict_binding(
                dropins,
                canonical_dropin="credentials.conf",
                expected_source=source,
                expected_uid=os.geteuid(),
            )
            self.assertEqual(strict["declaration_count"], 2)
            self.assertEqual(strict["effective_declaration_count"], 1)
            self.assertEqual(
                strict["effective_dropin"],
                "zzzzzzz-p07-local-profile-v1.conf",
            )

            extra = dropins / "00-shadowed-duplicate.conf"
            extra.write_text(
                f"[Service]\n{binding.DIRECTIVE_PREFIX}{source.as_posix()}\n",
                encoding="ascii",
            )
            extra.chmod(0o644)
            with self.assertRaises(binding.CredentialBindingRejected) as duplicate:
                binding.verify_strict_binding(
                    dropins,
                    canonical_dropin="credentials.conf",
                    expected_source=source,
                    expected_uid=os.geteuid(),
                )
            self.assertEqual(duplicate.exception.code, "credential_category_rejected")
            extra.unlink()

            local_profile.write_text(
                "[Service]\nLoadCredential=\n"
                "LoadCredential=telegram_owner_core_token:/synthetic\n",
                encoding="ascii",
            )
            with self.assertRaises(binding.CredentialBindingRejected) as missing:
                binding.verify_strict_binding(
                    dropins,
                    canonical_dropin="credentials.conf",
                    expected_source=source,
                    expected_uid=os.geteuid(),
                )
            self.assertEqual(missing.exception.code, "credential_category_rejected")

            other = Path(temporary) / "other-source"
            other.write_bytes(b"synthetic")
            other.chmod(0o600)
            local_profile.write_text(
                "[Service]\nLoadCredential=\n"
                f"{binding.DIRECTIVE_PREFIX}{other.as_posix()}\n",
                encoding="ascii",
            )
            with self.assertRaises(binding.CredentialBindingRejected) as drift:
                binding.verify_strict_binding(
                    dropins,
                    canonical_dropin="credentials.conf",
                    expected_source=source,
                    expected_uid=os.geteuid(),
                )
            self.assertEqual(drift.exception.code, "credential_source_drifted")

    def test_duplicate_different_source_and_missing_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dropins, source, _effective = self._fixture(Path(temporary))
            other = Path(temporary) / "other-source"
            other.write_bytes(b"synthetic")
            other.chmod(0o600)
            (dropins / "zzzzzzzzz-p07-hybrid-external-v1.conf").write_bytes(
                binding.legacy_duplicate_hybrid_gate(other)
            )
            with self.assertRaises(binding.CredentialBindingRejected) as different:
                self._duplicate(dropins, source)
            self.assertEqual(
                different.exception.code,
                "credential_duplicate_source_rejected",
            )
            (dropins / "zzzzzzzzz-p07-hybrid-external-v1.conf").unlink()
            with self.assertRaises(binding.CredentialBindingRejected) as missing:
                self._duplicate(dropins, source)
            self.assertEqual(
                missing.exception.code,
                "credential_duplicate_count_rejected",
            )

    def test_symlink_type_owner_mode_and_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dropins, source, _effective = self._fixture(root)
            redundant = dropins / "zzzzzzzzz-p07-hybrid-external-v1.conf"
            redundant.chmod(0o666)
            with self.assertRaises(binding.CredentialBindingRejected) as mode:
                self._duplicate(dropins, source)
            self.assertEqual(mode.exception.code, "credential_dropin_mode_rejected")
            redundant.chmod(0o644)
            redundant.write_bytes(
                binding.legacy_duplicate_hybrid_gate(source) + b"# drift\n"
            )
            with self.assertRaises(binding.CredentialBindingRejected) as drift:
                self._duplicate(dropins, source)
            self.assertEqual(
                drift.exception.code,
                "credential_redundant_dropin_drifted",
            )
            redundant.unlink()
            redundant.symlink_to(dropins / "credentials.conf")
            with self.assertRaises(binding.CredentialBindingRejected) as symlink:
                self._duplicate(dropins, source)
            self.assertEqual(symlink.exception.code, "credential_dropin_type_rejected")

            redundant.unlink()
            redundant.mkdir()
            with self.assertRaises(binding.CredentialBindingRejected) as file_type:
                self._duplicate(dropins, source)
            self.assertEqual(file_type.exception.code, "credential_dropin_type_rejected")

    @unittest.skipUnless(os.geteuid() == 0, "owner drift requires root")
    def test_owner_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dropins, source, _effective = self._fixture(Path(temporary))
            redundant = dropins / "zzzzzzzzz-p07-hybrid-external-v1.conf"
            os.chown(redundant, 65534, 65534)
            with self.assertRaises(binding.CredentialBindingRejected) as captured:
                self._duplicate(dropins, source)
            self.assertEqual(
                captured.exception.code,
                "credential_dropin_owner_rejected",
            )

    def test_ordering_is_explicit_and_unrelated_dropins_do_not_decide_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dropins, source, _effective = self._fixture(Path(temporary))
            unrelated = dropins / "000-unrelated.conf"
            unrelated.write_text(
                "[Service]\nLoadCredential=telegram_owner_core_token:/synthetic\n",
                encoding="ascii",
            )
            unrelated.chmod(0o644)
            first = self._duplicate(dropins, source)
            unrelated.rename(dropins / "zzz-unrelated.conf")
            second = self._duplicate(dropins, source)
            self.assertEqual(
                first["redundant_dropin_sha256"],
                second["redundant_dropin_sha256"],
            )

    def test_source_and_effective_type_and_mode_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dropins, source, effective = self._fixture(root)
            source.chmod(0o607)
            with self.assertRaises(binding.CredentialBindingRejected) as source_mode:
                self._duplicate(dropins, source)
            self.assertEqual(
                source_mode.exception.code,
                "credential_source_mode_rejected",
            )
            source.chmod(0o600)
            binding.verify_effective_credential(
                effective,
                expected_uid=os.geteuid(),
            )
            effective.chmod(0o447)
            with self.assertRaises(binding.CredentialBindingRejected) as effective_mode:
                binding.verify_effective_credential(
                    effective,
                    expected_uid=os.geteuid(),
                )
            self.assertEqual(
                effective_mode.exception.code,
                "effective_credential_mode_rejected",
            )
            effective.chmod(0o440)
            source.unlink()
            target = root / "target"
            target.write_bytes(b"synthetic")
            source.symlink_to(target)
            with self.assertRaises(binding.CredentialBindingRejected) as source_type:
                self._duplicate(dropins, source)
            self.assertEqual(
                source_type.exception.code,
                "credential_source_type_rejected",
            )

    @unittest.skipUnless(os.geteuid() == 0, "source owner drift requires root")
    def test_source_owner_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dropins, source, _effective = self._fixture(Path(temporary))
            os.chown(source, 65534, 65534)
            with self.assertRaises(binding.CredentialBindingRejected) as captured:
                self._duplicate(dropins, source)
            self.assertEqual(
                captured.exception.code,
                "credential_source_owner_rejected",
            )


@unittest.skipUnless(os.geteuid() == 0, "reconciliation activator requires root")
class CredentialBindingReconciliationTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, Path, Path]:
        return CredentialBindingContractTests()._fixture(root)

    def _patch_runtime(
        self,
        root: Path,
        dropins: Path,
        source: Path,
        effective: Path,
    ) -> list[mock._patch]:
        return [
            mock.patch.object(reconciliation, "DROPIN_ROOT", dropins),
            mock.patch.object(
                reconciliation,
                "REDUNDANT_PATH",
                dropins / "zzzzzzzzz-p07-hybrid-external-v1.conf",
            ),
            mock.patch.object(reconciliation, "EXPECTED_SOURCE", source),
            mock.patch.object(reconciliation, "EFFECTIVE_CREDENTIAL", effective),
            mock.patch.object(reconciliation, "BACKUP_ROOT", root / "backups"),
            mock.patch.object(reconciliation, "STATE_ROOT", root / "state"),
            mock.patch.object(reconciliation, "systemctl", return_value=""),
        ]

    def test_preflight_apply_and_exact_duplicate_replay_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dropins, source, effective = self._fixture(root)
            patches = self._patch_runtime(root, dropins, source, effective)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                ready = reconciliation.reconcile(
                    expected_plan_sha256=None,
                    preflight_only=True,
                )
                result = reconciliation.reconcile(
                    expected_plan_sha256=str(ready["plan_sha256"]),
                    preflight_only=False,
                )
                self.assertEqual(result["declaration_count"], 1)
                self.assertEqual(
                    result["status"],
                    "CREDENTIAL_BINDING_RECONCILED_B_PREFLIGHT_REQUIRED",
                )
                with self.assertRaises(
                    reconciliation.CredentialBindingRejected
                ) as replay:
                    reconciliation.reconcile(
                        expected_plan_sha256=str(ready["plan_sha256"]),
                        preflight_only=False,
                    )
                self.assertEqual(
                    replay.exception.code,
                    "credential_duplicate_count_rejected",
                )

    def test_failure_after_write_restores_exact_duplicate_prestate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dropins, source, effective = self._fixture(root)
            redundant = dropins / "zzzzzzzzz-p07-hybrid-external-v1.conf"
            original = redundant.read_bytes()
            patches = self._patch_runtime(root, dropins, source, effective)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                ready = reconciliation.reconcile(
                    expected_plan_sha256=None,
                    preflight_only=True,
                )
                with mock.patch.object(
                    reconciliation,
                    "verify_target",
                    side_effect=reconciliation.ReconciliationRejected(
                        "synthetic_target_failure"
                    ),
                ):
                    with self.assertRaises(reconciliation.ReconciliationRejected):
                        reconciliation.reconcile(
                            expected_plan_sha256=str(ready["plan_sha256"]),
                            preflight_only=False,
                        )
                self.assertEqual(redundant.read_bytes(), original)
                restored = reconciliation.inspect_prestate()
                self.assertEqual(
                    restored["binding"]["status"],
                    "reconcilable_duplicate",
                )

    def test_daemon_reload_failure_restores_exact_duplicate_prestate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dropins, source, effective = self._fixture(root)
            redundant = dropins / "zzzzzzzzz-p07-hybrid-external-v1.conf"
            original = redundant.read_bytes()
            patches = self._patch_runtime(root, dropins, source, effective)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
                ready = reconciliation.reconcile(
                    expected_plan_sha256=None,
                    preflight_only=True,
                )
                with mock.patch.object(
                    reconciliation,
                    "systemctl",
                    side_effect=[OSError("synthetic reload failure"), ""],
                ):
                    with self.assertRaises(OSError):
                        reconciliation.reconcile(
                            expected_plan_sha256=str(ready["plan_sha256"]),
                            preflight_only=False,
                        )
                self.assertEqual(redundant.read_bytes(), original)
                self.assertEqual(
                    reconciliation.inspect_prestate()["binding"]["status"],
                    "reconcilable_duplicate",
                )

    def test_rollback_failure_records_content_free_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dropins, source, effective = self._fixture(root)
            patches = self._patch_runtime(root, dropins, source, effective)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                ready = reconciliation.reconcile(
                    expected_plan_sha256=None,
                    preflight_only=True,
                )
                with mock.patch.object(
                    reconciliation,
                    "verify_target",
                    side_effect=OSError("synthetic target failure"),
                ), mock.patch.object(
                    reconciliation,
                    "restore",
                    side_effect=OSError("synthetic rollback failure"),
                ):
                    with self.assertRaises(
                        reconciliation.ReconciliationRejected
                    ) as captured:
                        reconciliation.reconcile(
                            expected_plan_sha256=str(ready["plan_sha256"]),
                            preflight_only=False,
                        )
                self.assertEqual(
                    captured.exception.code,
                    "credential_rollback_rejected",
                )
                journals = list((root / "state").glob("JOURNAL-*.json"))
                self.assertEqual(len(journals), 1)
                projection = json.loads(journals[0].read_text(encoding="utf-8"))
                self.assertEqual(projection["rollback"], "failed")
                self.assertEqual(projection["status"], "rollback_failed")
                self.assertNotIn("synthetic", journals[0].read_text(encoding="utf-8"))

    def test_plan_is_content_free_and_digest_drift_fails_before_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dropins, source, effective = self._fixture(root)
            patches = self._patch_runtime(root, dropins, source, effective)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                prestate = reconciliation.inspect_prestate()
                plan = reconciliation.build_plan(prestate)
                self.assertNotIn(b"synthetic-not-a-secret", plan)
                self.assertNotIn(source.as_posix().encode("utf-8"), plan)
                with self.assertRaises(
                    reconciliation.ReconciliationRejected
                ) as drift:
                    reconciliation.reconcile(
                        expected_plan_sha256="0" * 64,
                        preflight_only=False,
                    )
                self.assertEqual(drift.exception.code, "plan_digest_drifted")
                self.assertFalse((root / "backups").exists())


if __name__ == "__main__":
    unittest.main()
