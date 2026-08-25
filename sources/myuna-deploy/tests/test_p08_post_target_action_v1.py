from __future__ import annotations

from contextlib import contextmanager, redirect_stdout
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from unittest import mock

import p08_existing_state_upgrade_v1 as upgrade
import p08_post_target_action_v1 as post
import p08_temporal_gateway_v1 as temporal
from test_p08_existing_state_upgrade_v1 import (
    ACTIVE_GATEWAY,
    CORE,
    PREDECESSOR,
    RecordingRunner,
    UNIT_STATE,
    _plan,
    _target_release,
)


def _subprocess_release(root: Path, source: str) -> Path:
    release = root / "releases/candidate"
    helper = release / upgrade.CLIENT_PATH
    helper.parent.mkdir(parents=True)
    helper.write_text(source, encoding="utf-8")
    return release


def _retag_release(root: Path) -> Path:
    release = _target_release(root)
    manifest_path = release / "manifest.json"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    manifest["deploy_commit"] = "e" * 40
    manifest["post_target_action_contract"] = {
        "action_state_binding_schema": post.ACTION_STATE_BINDING_SCHEMA,
        "incident_max_actions": 1,
        "live_execute_implemented": True,
        "max_attempts_per_action_plan": 1,
        "readiness_schema": post.READINESS_SCHEMA,
        "repair_plan_schema": post.REPAIR_PLAN_SCHEMA,
        "rollback_plan_schema": post.ROLLBACK_PLAN_SCHEMA,
        "sha256": upgrade.digest_file(
            release / "scripts/p08_post_target_action_v1.py"
        ),
        "source_path": "scripts/p08_post_target_action_v1.py",
    }
    raw = upgrade.canonical(manifest)
    manifest_path.write_bytes(raw + b"\n")
    target = release.parent / sha256(raw).hexdigest()
    release.rename(target)
    return target


@contextmanager
def _completed_target_fixture(root: Path):
    _, host, identity, completed_plan = _plan(root)
    upgrade.execute_plan(
        completed_plan,
        root=host,
        synthetic_identity=identity,
        unit_state=UNIT_STATE,
        runner=RecordingRunner(),
    )
    target = completed_plan["target"]
    assert isinstance(target, dict)
    evidence = (
        host
        / str(upgrade.EVIDENCE_ROOT).lstrip("/")
        / str(completed_plan["plan_digest"])
    )
    installed = host / str(target["release_target"]).lstrip("/")
    predecessor_mirror = (
        host
        / str(upgrade.RELEASE_ROOT / upgrade.PREDECESSOR_RELEASE_DIGEST).lstrip("/")
    )
    shutil.copytree(PREDECESSOR, predecessor_mirror)
    failure_relative = (
        upgrade.EVIDENCE_ROOT
        / "synthetic-post-target-sequence"
        / "POST_ACTIVATION_FAILURE.json"
    )
    failure_path = host / str(failure_relative).lstrip("/")
    failure_path.parent.mkdir(parents=True, mode=0o700)
    failure = {
        "activation_calls": 1,
        "controller_receipt_sha256": upgrade.digest_file(evidence / "RECEIPT.json"),
        "controller_status": "target_verified",
        "live_release_digest": target["release_digest"],
        "opaque_state_exact": True,
        "protocol_acceptance_calls": 1,
        "protocol_process_created": True,
        "protocol_retry": False,
        "rollback_executed": False,
        "schema": "myuna.p08-superseding-post-activation-acceptance-failure.v1",
        "sequence_id": post.FAILED_ACCEPTANCE_SEQUENCE_ID,
        "status": post.FAILED_ACCEPTANCE_STATUS,
    }
    failure_path.write_bytes(post.canonical(failure))
    failure_path.chmod(0o600)
    values = {
        "COMPLETED_PLAN_DIGEST": completed_plan["plan_digest"],
        "COMPLETED_PLAN_SHA256": upgrade.digest_file(evidence / "PLAN.json"),
        "COMPLETED_JOURNAL_SHA256": upgrade.digest_file(
            evidence / "JOURNAL.json"
        ),
        "COMPLETED_RECEIPT_SHA256": upgrade.digest_file(
            evidence / "RECEIPT.json"
        ),
        "COMPLETED_TARGET_RELEASE_DIGEST": target["release_digest"],
        "COMPLETED_TARGET_MANIFEST_SHA256": upgrade.digest_file(
            installed / "manifest.json"
        ),
        "COMPLETED_TARGET_CLIENT_SHA256": upgrade.digest_file(
            installed / upgrade.CLIENT_PATH
        ),
        "COMPLETED_TARGET_SERVICE_UNIT_SHA256": upgrade.digest_file(
            installed / upgrade.SERVICE_UNIT_PATH
        ),
        "COMPLETED_TARGET_SOCKET_UNIT_SHA256": upgrade.digest_file(
            installed / upgrade.SOCKET_UNIT_PATH
        ),
        "COMPLETED_TARGET_DEPLOY_COMMIT": target["deploy_commit"],
        "COMPLETED_TARGET_SELECTOR_SHA256": upgrade.digest_file(
            host / str(upgrade.SELECTOR_JSON).lstrip("/")
        ),
        "COMPLETED_TARGET_SELECTOR_ENV_SHA256": upgrade.digest_file(
            host / str(upgrade.SELECTOR_ENV).lstrip("/")
        ),
        "COMPLETED_EVIDENCE_ROOT": upgrade.EVIDENCE_ROOT
        / str(completed_plan["plan_digest"]),
        "FAILED_ACCEPTANCE_RECEIPT_PATH": failure_relative,
        "FAILED_ACCEPTANCE_RECEIPT_SHA256": upgrade.digest_file(failure_path),
    }
    with mock.patch.multiple(post, **values):
        yield host, identity, completed_plan


@unittest.skipUnless(
    PREDECESSOR.is_dir() and ACTIVE_GATEWAY.is_dir() and CORE.is_dir(),
    "exact P08 predecessor, active gateway, and Core source are required",
)
class PostTargetActionContractTests(unittest.TestCase):
    def test_content_free_acceptance_binds_exact_nonce_before_helper_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            release_root = Path(directory) / "releases"
            release = release_root / "candidate"
            helper = release / upgrade.CLIENT_PATH
            helper.parent.mkdir(parents=True)
            helper.write_text("# synthetic helper\n", encoding="utf-8")
            nonce = "a" * 64
            payload = dict(post._synthetic_content_free_acceptance(release))
            payload["request_nonce"] = nonce
            completed = mock.Mock(
                returncode=0,
                stdout=post.canonical(payload) + b"\n",
            )
            with (
                mock.patch.object(post.upgrade, "RELEASE_ROOT", release_root),
                mock.patch.object(post.secrets, "token_hex", return_value=nonce),
                mock.patch.object(post.subprocess, "run", return_value=completed) as run,
            ):
                observed = post._run_content_free_acceptance(release)
            self.assertEqual(observed, payload)
            invocation = run.call_args
            self.assertEqual(
                invocation.kwargs["env"][post.CONTENT_FREE_STATUS_INVOCATION_NONCE_ENV],
                nonce,
            )
            self.assertEqual(invocation.kwargs["stderr"], post.subprocess.DEVNULL)
            self.assertEqual(invocation.kwargs["timeout"], 15)

            mismatched = {**payload, "request_nonce": "b" * 64}
            completed.stdout = post.canonical(mismatched) + b"\n"
            with (
                mock.patch.object(post.upgrade, "RELEASE_ROOT", release_root),
                mock.patch.object(post.secrets, "token_hex", return_value=nonce),
                mock.patch.object(post.subprocess, "run", return_value=completed),
                self.assertRaisesRegex(
                    post.PostTargetRejected, "protocol_acceptance_rejected"
                ),
            ):
                post._run_content_free_acceptance(release)

            duplicate_nonce = (
                post.canonical(payload)[:-1]
                + b',"request_nonce":"'
                + nonce.encode("ascii")
                + b'"}'
            )
            completed.stdout = duplicate_nonce
            with (
                mock.patch.object(post.upgrade, "RELEASE_ROOT", release_root),
                mock.patch.object(post.secrets, "token_hex", return_value=nonce),
                mock.patch.object(post.subprocess, "run", return_value=completed),
                self.assertRaisesRegex(
                    post.PostTargetRejected, "protocol_acceptance_rejected"
                ),
            ):
                post._run_content_free_acceptance(release)

            with (
                mock.patch.object(post.upgrade, "RELEASE_ROOT", release_root),
                mock.patch.object(post.secrets, "token_hex", return_value="invalid"),
                mock.patch.object(post.subprocess, "run") as rejected_run,
                self.assertRaisesRegex(
                    post.PostTargetRejected,
                    "protocol_acceptance_invocation_rejected",
                ),
            ):
                post._run_content_free_acceptance(release)
            rejected_run.assert_not_called()

    def test_real_subprocess_success_closes_one_nonce_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            nonce = "a" * 64
            payload = post._synthetic_content_free_acceptance(Path("/unused"))
            source = (
                "import json,os\n"
                f"p={payload!r}\n"
                f"p['request_nonce']=os.environ[{post.CONTENT_FREE_STATUS_INVOCATION_NONCE_ENV!r}]\n"
                "print(json.dumps(p,sort_keys=True,separators=(',',':')))\n"
            )
            release = _subprocess_release(Path(directory), source)
            with (
                mock.patch.object(post.upgrade, "RELEASE_ROOT", release.parent),
                mock.patch.object(post.secrets, "token_hex", return_value=nonce),
            ):
                observed = post._run_content_free_acceptance(release)
            self.assertEqual(observed["request_nonce"], nonce)

    def test_real_subprocess_nonzero_preserves_only_valid_stage_projection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            nonce = "b" * 64
            runtime_rejection = temporal.ContentFreeRuntimeRejection.from_stage(
                "trusted_time_boundary",
                request_nonce=nonce,
                error_category="trusted_time_unavailable",
            )
            projection = temporal.ContentFreeStatusRejection.from_stage(
                "server_status_runtime_rejection",
                invocation_nonce=nonce,
                runtime_rejection=runtime_rejection,
            ).projection()
            source = (
                "import json,sys\n"
                f"print(json.dumps({projection!r},sort_keys=True,separators=(',',':')))\n"
                "sys.exit(1)\n"
            )
            release = _subprocess_release(Path(directory), source)
            with (
                mock.patch.object(post.upgrade, "RELEASE_ROOT", release.parent),
                mock.patch.object(post.secrets, "token_hex", return_value=nonce),
                self.assertRaises(post.PostTargetRejected) as raised,
            ):
                post._run_content_free_acceptance(release)
            self.assertEqual(raised.exception.code, "protocol_acceptance_failed")
            self.assertEqual(
                raised.exception.content_free_failure_projection, projection
            )
            self.assertEqual(
                projection["runtime_rejection"]["stage"],
                "trusted_time_boundary",
            )

    def test_real_subprocess_invalid_nonzero_envelopes_remain_generic(self) -> None:
        nonce = "c" * 64
        valid = temporal.ContentFreeStatusRejection.from_stage(
            "transport_connect", invocation_nonce=nonce
        ).projection()
        variants = {
            "empty": b"",
            "malformed": b"not-json\n",
            "unknown": post.canonical({**valid, "stage": "unknown"}) + b"\n",
            "oversize": b"x" * (temporal.MAX_STATUS_HELPER_OUTPUT_BYTES + 1),
            "raw-tainted": post.canonical(valid) + b"\nraw-cause\n",
            "wrong-nonce": post.canonical(
                {**valid, "invocation_nonce": "d" * 64}
            )
            + b"\n",
            "second-nonce": post.canonical(valid)
            + post.canonical({**valid, "invocation_nonce": "e" * 64}),
        }
        for name, output in variants.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                source = (
                    "import sys\n"
                    f"sys.stdout.buffer.write({output!r})\n"
                    "sys.exit(1)\n"
                )
                release = _subprocess_release(Path(directory), source)
                with (
                    mock.patch.object(post.upgrade, "RELEASE_ROOT", release.parent),
                    mock.patch.object(post.secrets, "token_hex", return_value=nonce),
                    self.assertRaises(post.PostTargetRejected) as raised,
                ):
                    post._run_content_free_acceptance(release)
                self.assertEqual(raised.exception.code, "protocol_acceptance_failed")
                self.assertIsNone(
                    raised.exception.content_free_failure_projection
                )

    def test_cli_routes_explicit_action_identity_without_raw_failure(self) -> None:
        output = io.StringIO()
        with mock.patch.object(
            post, "prepare_action", return_value={"status": "synthetic-ready"}
        ) as prepare, redirect_stdout(output):
            self.assertEqual(post.main(["prepare-rollback"]), 0)
        prepare.assert_called_once_with(action="rollback")
        self.assertEqual(
            json.loads(output.getvalue()), {"status": "synthetic-ready"}
        )

        output = io.StringIO()
        with mock.patch.object(
            post,
            "_load_json",
            return_value={"schema": "synthetic-plan"},
        ), mock.patch.object(
            post,
            "execute_live_action",
            side_effect=post.PostTargetRejected("synthetic_rejected"),
        ) as execute, redirect_stdout(output):
            self.assertEqual(
                post.main(["execute-repair", "--plan", "synthetic-plan.json"]),
                2,
            )
        execute.assert_called_once_with(
            {"schema": "synthetic-plan"}, expected_action="repair"
        )
        self.assertEqual(
            json.loads(output.getvalue()),
            {
                "code": "synthetic_rejected",
                "schema": "myuna.p08-post-target-action-cli-result.v1",
                "status": "rejected",
            },
        )

    def test_metadata_only_preflight_cli_is_identical_and_reads_no_state_bytes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with _completed_target_fixture(root) as (host, _, _):
                repair_release = _retag_release(root / "repair")
                current_state = host / str(upgrade.STATE_ROOT).lstrip("/")
                completed_state = (
                    host
                    / str(post.COMPLETED_EVIDENCE_ROOT).lstrip("/")
                    / "state/data"
                )
                forbidden = {
                    (current_state / name).resolve() for name in upgrade.STATE_FILES
                } | {
                    (completed_state / name).resolve() for name in upgrade.STATE_FILES
                }
                original_open = Path.open

                def guarded_open(selected: Path, *args, **kwargs):
                    if selected.resolve() in forbidden:
                        raise AssertionError("opaque state bytes read during readiness")
                    return original_open(selected, *args, **kwargs)

                outputs: list[bytes] = []
                with mock.patch.object(Path, "open", new=guarded_open):
                    for _ in range(2):
                        output = io.StringIO()
                        with redirect_stdout(output):
                            self.assertEqual(
                                post.main(
                                    [
                                        "preflight-repair",
                                        "--repair-release",
                                        str(repair_release),
                                        "--synthetic-root",
                                        str(host),
                                    ]
                                ),
                                0,
                            )
                        outputs.append(output.getvalue().encode("ascii"))
                self.assertEqual(outputs[0], outputs[1])
                readiness = json.loads(outputs[0])
                self.assertEqual(readiness["status"], "ready")
                self.assertFalse(readiness["opaque_content_read"])
                self.assertFalse(readiness["persistent_mutation"])
                self.assertTrue(
                    readiness["opaque_content_read_deferred_to_action_owned_backup"]
                )
                self.assertFalse(
                    (
                        host
                        / str(post.POST_ACTION_EVIDENCE_ROOT).lstrip("/")
                    ).exists()
                )

    def test_prepare_metadata_drift_and_path_substitution_fail_closed(self) -> None:
        for substitution in ("same-size", "hardlink", "symlink"):
            with (
                self.subTest(substitution=substitution),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                with _completed_target_fixture(root) as (host, _, _):
                    plan = post.prepare_action(
                        action="rollback", root=host, unit_state=UNIT_STATE
                    )
                    state_root = host / str(upgrade.STATE_ROOT).lstrip("/")
                    target = state_root / upgrade.STATE_FILES[0]
                    original = target.read_bytes()
                    replacement = target.with_name(f".{target.name}.{substitution}")
                    if substitution == "same-size":
                        changed = bytes([original[0] ^ 1]) + original[1:]
                        replacement.write_bytes(changed)
                        replacement.chmod(0o600)
                        metadata = target.stat()
                        os.utime(
                            replacement,
                            ns=(metadata.st_atime_ns, metadata.st_mtime_ns),
                        )
                    elif substitution == "hardlink":
                        os.link(target, replacement)
                    else:
                        replacement.symlink_to(target.name)
                    os.replace(replacement, target)
                    if substitution == "same-size":
                        expected_error = post.PostTargetRejected
                        expected_code = "action_current_target_drifted"
                    else:
                        expected_error = upgrade.UpgradeRejected
                        expected_code = (
                            "state_inventory_rejected|state_file_type_rejected"
                        )
                    with self.assertRaisesRegex(expected_error, expected_code):
                        post.verify_action_plan(
                            plan,
                            expected_action="rollback",
                            root=host,
                            unit_state=UNIT_STATE,
                        )

    def test_action_owned_backup_precedes_stop_and_detects_content_spoof(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with _completed_target_fixture(root) as (host, _, _):
                plan = post.prepare_action(
                    action="rollback", root=host, unit_state=UNIT_STATE
                )
                evidence = post.stage_synthetic_action_plan(
                    plan,
                    expected_action="rollback",
                    root=host,
                    unit_state=UNIT_STATE,
                )
                binding = evidence / "STATE_BINDING.json"
                backup = evidence / "current-state/STATE.json"
                self.assertTrue(binding.is_file())
                self.assertTrue(backup.is_file())
                journal = json.loads((evidence / "JOURNAL.json").read_text("ascii"))
                self.assertEqual(journal["stage"], "attempt_owned")

                state_root = host / str(upgrade.STATE_ROOT).lstrip("/")
                target = state_root / upgrade.STATE_FILES[0]
                original = target.read_bytes()
                metadata = target.stat()
                target.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                target.chmod(0o600)
                os.utime(target, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
                expected_metadata = plan["current_target"]["state"]
                original_describe = upgrade.describe_opaque_state_metadata

                def spoof_metadata(
                    selected: Path, *, expected_uid: int, expected_gid: int
                ):
                    if selected.resolve() == state_root.resolve():
                        return json.loads(json.dumps(expected_metadata))
                    return original_describe(
                        selected, expected_uid=expected_uid, expected_gid=expected_gid
                    )

                with mock.patch.object(
                    upgrade,
                    "describe_opaque_state_metadata",
                    side_effect=spoof_metadata,
                ):
                    runner = RecordingRunner()
                    with self.assertRaisesRegex(
                        post.PostTargetRejected, "action_owned_state_drifted"
                    ):
                        post.simulate_staged_action(
                            plan,
                            expected_action="rollback",
                            root=host,
                            unit_state=UNIT_STATE,
                            runner=runner,
                        )
                    self.assertEqual(runner.events, [])
                    with self.assertRaisesRegex(
                        post.PostTargetRejected, "incident_action_already_consumed"
                    ):
                        post.stage_synthetic_action_plan(
                            plan,
                            expected_action="rollback",
                            root=host,
                            unit_state=UNIT_STATE,
                        )

    def test_partial_action_state_backup_consumes_incident_before_any_stop(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with _completed_target_fixture(root) as (host, _, _):
                plan = post.prepare_action(
                    action="rollback", root=host, unit_state=UNIT_STATE
                )
                evidence = (
                    host
                    / str(post.POST_ACTION_EVIDENCE_ROOT).lstrip("/")
                    / "incidents"
                    / str(plan["incident"]["incident_digest"])
                )
                original_copy = upgrade._copy_exact_file
                calls = 0

                def fail_after_first(source: Path, destination: Path, row) -> None:
                    nonlocal calls
                    original_copy(source, destination, row)
                    calls += 1
                    if calls == 1:
                        raise upgrade.UpgradeRejected("synthetic_partial_backup")

                with mock.patch.object(
                    upgrade, "_copy_exact_file", side_effect=fail_after_first
                ):
                    with self.assertRaisesRegex(
                        upgrade.UpgradeRejected, "synthetic_partial_backup"
                    ):
                        post.stage_synthetic_action_plan(
                            plan,
                            expected_action="rollback",
                            root=host,
                            unit_state=UNIT_STATE,
                        )
                self.assertTrue((evidence / "PLAN.json").is_file())
                self.assertTrue((evidence / "LEDGER.json").is_file())
                journal = json.loads((evidence / "JOURNAL.json").read_text("ascii"))
                self.assertEqual(journal["stage"], "current_public_backed_up")
                with self.assertRaisesRegex(
                    post.PostTargetRejected, "incident_action_already_consumed"
                ):
                    post.stage_synthetic_action_plan(
                        plan,
                        expected_action="rollback",
                        root=host,
                        unit_state=UNIT_STATE,
                    )

    def test_production_completed_target_release_identity_is_exact(self) -> None:
        target = upgrade.RELEASE_ROOT / post.COMPLETED_TARGET_RELEASE_DIGEST
        if not target.is_dir():
            self.skipTest("exact completed target release is not available")
        manifest = post.validate_completed_target_release(target)
        self.assertEqual(
            manifest["deploy_commit"], post.COMPLETED_TARGET_DEPLOY_COMMIT
        )

    def test_repair_and_rollback_plans_are_identity_separated_and_max_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with _completed_target_fixture(root) as (host, _, _):
                repair_release = _retag_release(root / "repair")
                repair = post.prepare_action(
                    action="repair",
                    repair_release=repair_release,
                    root=host,
                    unit_state=UNIT_STATE,
                )
                rollback = post.prepare_action(
                    action="rollback",
                    root=host,
                    unit_state=UNIT_STATE,
                )
                self.assertEqual(repair["schema"], post.REPAIR_PLAN_SCHEMA)
                self.assertEqual(rollback["schema"], post.ROLLBACK_PLAN_SCHEMA)
                self.assertNotEqual(repair["plan_digest"], rollback["plan_digest"])
                self.assertNotIn(str(upgrade.STATE_ROOT), repair["allowed_mutation_paths"])
                self.assertNotIn(str(upgrade.STATE_ROOT), rollback["allowed_mutation_paths"])

                evidence = post.stage_synthetic_action_plan(
                    repair,
                    expected_action="repair",
                    root=host,
                    unit_state=UNIT_STATE,
                )
                ledger = json.loads((evidence / "LEDGER.json").read_text("ascii"))
                self.assertEqual(ledger["attempts"], 1)
                self.assertTrue(ledger["consumed"])
                self.assertEqual(
                    repair["incident"]["incident_digest"],
                    rollback["incident"]["incident_digest"],
                )
                with self.assertRaises(post.PostTargetRejected):
                    post.stage_synthetic_action_plan(
                        repair,
                        expected_action="repair",
                        root=host,
                        unit_state=UNIT_STATE,
                    )
                with self.assertRaisesRegex(
                    post.PostTargetRejected, "incident_action_already_consumed"
                ):
                    post.stage_synthetic_action_plan(
                        rollback,
                        expected_action="rollback",
                        root=host,
                        unit_state=UNIT_STATE,
                    )
                with self.assertRaisesRegex(
                    post.PostTargetRejected, "synthetic_root_rejected"
                ):
                    post.stage_synthetic_action_plan(
                        repair,
                        expected_action="repair",
                        root=Path("/"),
                        unit_state=UNIT_STATE,
                    )

    def test_synthetic_repair_and_rollback_preserve_opaque_state(self) -> None:
        for action in ("repair", "rollback"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with _completed_target_fixture(root) as (host, identity, _):
                    before = upgrade.describe_opaque_state(
                        host / str(upgrade.STATE_ROOT).lstrip("/"),
                        expected_uid=identity[0],
                        expected_gid=identity[1],
                    )
                    repair_release = (
                        _retag_release(root / "repair")
                        if action == "repair"
                        else None
                    )
                    plan = post.prepare_action(
                        action=action,
                        repair_release=repair_release,
                        root=host,
                        unit_state=UNIT_STATE,
                    )
                    post.stage_synthetic_action_plan(
                        plan,
                        expected_action=action,
                        root=host,
                        unit_state=UNIT_STATE,
                    )
                    runner = RecordingRunner()
                    acceptance_calls: list[Path] = []

                    def acceptance(release: Path):
                        acceptance_calls.append(release)
                        return post._synthetic_content_free_acceptance(release)

                    receipt = post.simulate_staged_action(
                        plan,
                        expected_action=action,
                        root=host,
                        unit_state=UNIT_STATE,
                        runner=runner,
                        acceptance_runner=acceptance,
                    )
                    after = upgrade.describe_opaque_state(
                        host / str(upgrade.STATE_ROOT).lstrip("/"),
                        expected_uid=identity[0],
                        expected_gid=identity[1],
                    )
                    self.assertEqual(after, before)
                    self.assertTrue(receipt["state_bytes_preserved"])
                    self.assertEqual(len(acceptance_calls), 1 if action == "repair" else 0)
                    self.assertEqual(
                        receipt["acceptance_projection_sha256"] is not None,
                        action == "repair",
                    )
                    self.assertEqual(
                        runner.events[:2],
                        [
                            ("/usr/bin/systemctl", "stop", upgrade.SOCKET),
                            ("/usr/bin/systemctl", "stop", upgrade.SERVICE),
                        ],
                    )
                    selector = json.loads(
                        (
                            host / str(upgrade.SELECTOR_JSON).lstrip("/")
                        ).read_text("ascii")
                    )
                    expected_release = (
                        plan["repair_target"]["release_digest"]
                        if action == "repair"
                        else upgrade.PREDECESSOR_RELEASE_DIGEST
                    )
                    self.assertEqual(selector["release_digest"], expected_release)
                    start_service = runner.events.index(
                        ("/usr/bin/systemctl", "start", upgrade.SERVICE)
                    )
                    start_socket = runner.events.index(
                        ("/usr/bin/systemctl", "start", upgrade.SOCKET)
                    )
                    self.assertLess(start_service, start_socket)

    def test_synthetic_failure_converges_in_reverse_to_current_target_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with _completed_target_fixture(root) as (host, identity, _):
                plan = post.prepare_action(
                    action="rollback", root=host, unit_state=UNIT_STATE
                )
                current_selector = upgrade.digest_file(
                    host / str(upgrade.SELECTOR_JSON).lstrip("/")
                )
                state_before = upgrade.describe_opaque_state(
                    host / str(upgrade.STATE_ROOT).lstrip("/"),
                    expected_uid=identity[0],
                    expected_gid=identity[1],
                )
                evidence = post.stage_synthetic_action_plan(
                    plan,
                    expected_action="rollback",
                    root=host,
                    unit_state=UNIT_STATE,
                )
                runner = RecordingRunner(
                    fail_once=("/usr/bin/systemctl", "start", upgrade.SERVICE)
                )
                with self.assertRaisesRegex(
                    post.PostTargetRejected,
                    "action_failed_current_target_restored",
                ):
                    post.simulate_staged_action(
                        plan,
                        expected_action="rollback",
                        root=host,
                        unit_state=UNIT_STATE,
                        runner=runner,
                    )
                self.assertEqual(
                    upgrade.digest_file(host / str(upgrade.SELECTOR_JSON).lstrip("/")),
                    current_selector,
                )
                self.assertEqual(
                    upgrade.describe_opaque_state(
                        host / str(upgrade.STATE_ROOT).lstrip("/"),
                        expected_uid=identity[0],
                        expected_gid=identity[1],
                    ),
                    state_before,
                )
                journal = json.loads(
                    (evidence / "JOURNAL.json").read_text("ascii")
                )
                self.assertEqual(journal["stage"], "recovered_current_target")
                self.assertEqual(journal["events"].count("convergence_owned"), 1)
                self.assertGreaterEqual(
                    runner.events.count(
                        ("/usr/bin/systemctl", "stop", upgrade.SOCKET)
                    ),
                    2,
                )

    def test_pre_stop_ownership_is_durable_and_second_stop_failure_converges(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with _completed_target_fixture(root) as (host, _, _):
                plan = post.prepare_action(
                    action="rollback", root=host, unit_state=UNIT_STATE
                )
                evidence = post.stage_synthetic_action_plan(
                    plan,
                    expected_action="rollback",
                    root=host,
                    unit_state=UNIT_STATE,
                )
                observed: list[dict[str, object]] = []
                delegate = RecordingRunner(
                    fail_once=("/usr/bin/systemctl", "stop", upgrade.SERVICE)
                )

                def runner(command):
                    if not observed:
                        journal = json.loads(
                            (evidence / "JOURNAL.json").read_text("ascii")
                        )
                        observed.append(
                            {
                                "backup": (evidence / "current-public/PUBLIC.json").is_file(),
                                "journal_stage": journal["stage"],
                                "ledger": (evidence / "LEDGER.json").is_file(),
                                "plan": (evidence / "PLAN.json").is_file(),
                            }
                        )
                    delegate(command)

                with self.assertRaisesRegex(
                    post.PostTargetRejected,
                    "action_failed_current_target_restored",
                ):
                    post.simulate_staged_action(
                        plan,
                        expected_action="rollback",
                        root=host,
                        unit_state=UNIT_STATE,
                        runner=runner,
                    )
                self.assertEqual(
                    observed,
                    [
                        {
                            "backup": True,
                            "journal_stage": "attempt_owned",
                            "ledger": True,
                            "plan": True,
                        }
                    ],
                )
                self.assertEqual(
                    delegate.events[:2],
                    [
                        ("/usr/bin/systemctl", "stop", upgrade.SOCKET),
                        ("/usr/bin/systemctl", "stop", upgrade.SERVICE),
                    ],
                )

    def test_crash_after_public_apply_recovers_once_without_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with _completed_target_fixture(root) as (host, identity, _):
                repair_release = _retag_release(root / "repair")
                plan = post.prepare_action(
                    action="repair",
                    repair_release=repair_release,
                    root=host,
                    unit_state=UNIT_STATE,
                )
                evidence = post.stage_synthetic_action_plan(
                    plan,
                    expected_action="repair",
                    root=host,
                    unit_state=UNIT_STATE,
                )
                state_before = upgrade.describe_opaque_state(
                    host / str(upgrade.STATE_ROOT).lstrip("/"),
                    expected_uid=identity[0],
                    expected_gid=identity[1],
                )
                acceptance_calls: list[Path] = []

                def acceptance(release: Path):
                    acceptance_calls.append(release)
                    return post._synthetic_content_free_acceptance(release)

                def crash(stage: str) -> None:
                    if stage == "public_applied":
                        raise SystemExit("synthetic-crash")

                with self.assertRaises(SystemExit):
                    post.simulate_staged_action(
                        plan,
                        expected_action="repair",
                        root=host,
                        unit_state=UNIT_STATE,
                        runner=RecordingRunner(),
                        acceptance_runner=acceptance,
                        stage_hook=crash,
                    )
                self.assertEqual(acceptance_calls, [])
                state_file = (
                    host
                    / str(upgrade.STATE_ROOT).lstrip("/")
                    / upgrade.STATE_FILES[0]
                )
                state_file.write_bytes(b"synthetic-crash-window-state-drift")
                state_file.chmod(0o600)
                receipt = post.recover_interrupted_action(
                    plan,
                    expected_action="repair",
                    root=host,
                    unit_state=UNIT_STATE,
                    runner=RecordingRunner(),
                )
                self.assertEqual(
                    receipt["status"], "interrupted_action_current_target_restored"
                )
                self.assertEqual(
                    upgrade.describe_opaque_state(
                        host / str(upgrade.STATE_ROOT).lstrip("/"),
                        expected_uid=identity[0],
                        expected_gid=identity[1],
                    ),
                    state_before,
                )
                journal = json.loads(
                    (evidence / "JOURNAL.json").read_text("ascii")
                )
                self.assertEqual(journal["events"].count("convergence_owned"), 1)
                self.assertEqual(journal["stage"], "recovered_current_target")
                with self.assertRaisesRegex(
                    post.PostTargetRejected, "interrupted_action_replay_rejected"
                ):
                    post.recover_interrupted_action(
                        plan,
                        expected_action="repair",
                        root=host,
                        unit_state=UNIT_STATE,
                        runner=RecordingRunner(),
                    )

    def test_concurrent_repair_and_rollback_share_one_incident_allocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with _completed_target_fixture(root) as (host, _, _):
                repair = post.prepare_action(
                    action="repair",
                    repair_release=_retag_release(root / "repair"),
                    root=host,
                    unit_state=UNIT_STATE,
                )
                rollback = post.prepare_action(
                    action="rollback", root=host, unit_state=UNIT_STATE
                )
                barrier = threading.Barrier(2)
                results: list[tuple[str, str]] = []

                def stage(action: str, plan: dict[str, object]) -> None:
                    barrier.wait()
                    try:
                        post.stage_action_plan(
                            plan,
                            expected_action=action,
                            root=host,
                            unit_state=UNIT_STATE,
                        )
                        results.append((action, "staged"))
                    except post.PostTargetRejected as exc:
                        results.append((action, exc.code))

                threads = [
                    threading.Thread(target=stage, args=("repair", repair)),
                    threading.Thread(target=stage, args=("rollback", rollback)),
                ]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
                self.assertEqual(len(results), 2)
                self.assertEqual(sum(value == "staged" for _, value in results), 1)
                self.assertEqual(
                    sum(
                        value == "incident_action_already_consumed"
                        for _, value in results
                    ),
                    1,
                )

    def test_repair_source_and_staged_ledger_metadata_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with _completed_target_fixture(root) as (host, _, _):
                repair_release = _retag_release(root / "repair")
                repair = post.prepare_action(
                    action="repair",
                    repair_release=repair_release,
                    root=host,
                    unit_state=UNIT_STATE,
                )
                manifest = repair_release / "manifest.json"
                manifest.chmod(0o600)
                with self.assertRaisesRegex(
                    post.PostTargetRejected, "repair_target_drifted"
                ):
                    post.verify_action_plan(
                        repair,
                        expected_action="repair",
                        root=host,
                        unit_state=UNIT_STATE,
                    )
                manifest.chmod(0o644)
                evidence = post.stage_synthetic_action_plan(
                    repair,
                    expected_action="repair",
                    root=host,
                    unit_state=UNIT_STATE,
                )
                (evidence / "LEDGER.json").chmod(0o644)
                with self.assertRaisesRegex(
                    post.PostTargetRejected, "action_ledger_rejected"
                ):
                    post.verify_staged_synthetic_action(
                        repair,
                        expected_action="repair",
                        root=host,
                        unit_state=UNIT_STATE,
                    )

    def test_repair_acceptance_failure_calls_once_and_converges_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with _completed_target_fixture(root) as (host, identity, _):
                repair = post.prepare_action(
                    action="repair",
                    repair_release=_retag_release(root / "repair"),
                    root=host,
                    unit_state=UNIT_STATE,
                )
                current_selector = upgrade.digest_file(
                    host / str(upgrade.SELECTOR_JSON).lstrip("/")
                )
                state_before = upgrade.describe_opaque_state(
                    host / str(upgrade.STATE_ROOT).lstrip("/"),
                    expected_uid=identity[0],
                    expected_gid=identity[1],
                )
                evidence = post.stage_synthetic_action_plan(
                    repair,
                    expected_action="repair",
                    root=host,
                    unit_state=UNIT_STATE,
                )
                acceptance_calls: list[Path] = []

                def acceptance(release: Path):
                    acceptance_calls.append(release)
                    raise post.PostTargetRejected("synthetic_acceptance_failed")

                with self.assertRaisesRegex(
                    post.PostTargetRejected,
                    "action_failed_current_target_restored",
                ):
                    post.simulate_staged_action(
                        repair,
                        expected_action="repair",
                        root=host,
                        unit_state=UNIT_STATE,
                        runner=RecordingRunner(),
                        acceptance_runner=acceptance,
                    )
                self.assertEqual(len(acceptance_calls), 1)
                self.assertEqual(
                    upgrade.digest_file(host / str(upgrade.SELECTOR_JSON).lstrip("/")),
                    current_selector,
                )
                self.assertEqual(
                    upgrade.describe_opaque_state(
                        host / str(upgrade.STATE_ROOT).lstrip("/"),
                        expected_uid=identity[0],
                        expected_gid=identity[1],
                    ),
                    state_before,
                )
                journal = json.loads((evidence / "JOURNAL.json").read_text("ascii"))
                self.assertEqual(
                    journal["events"].count("protocol_acceptance_called"), 1
                )
                self.assertEqual(journal["events"].count("convergence_owned"), 1)
                self.assertEqual(journal["stage"], "recovered_current_target")

    def test_mixed_origin_current_state_and_action_identity_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with _completed_target_fixture(root) as (host, _, _):
                rollback = post.prepare_action(
                    action="rollback", root=host, unit_state=UNIT_STATE
                )
                mixed = json.loads(json.dumps(rollback))
                mixed["schema"] = post.REPAIR_PLAN_SCHEMA
                with self.assertRaises(post.PostTargetRejected):
                    post.validate_action_plan(mixed, expected_action="rollback")
                mixed = json.loads(json.dumps(rollback))
                mixed["failure_receipt"]["sha256"] = "0" * 64
                with self.assertRaises(post.PostTargetRejected):
                    post.validate_action_plan(mixed, expected_action="rollback")
                selector = host / str(upgrade.SELECTOR_JSON).lstrip("/")
                selector.chmod(0o644)
                with self.assertRaisesRegex(
                    post.PostTargetRejected, "current_public_rejected"
                ):
                    post.verify_action_plan(
                        rollback,
                        expected_action="rollback",
                        root=host,
                        unit_state=UNIT_STATE,
                    )
                selector.chmod(0o600)
                state_file = (
                    host
                    / str(upgrade.STATE_ROOT).lstrip("/")
                    / upgrade.STATE_FILES[0]
                )
                state_file.write_bytes(b"synthetic-authoritative-drift")
                state_file.chmod(0o600)
                with self.assertRaisesRegex(
                    post.PostTargetRejected, "action_current_target_drifted"
                ):
                    post.verify_action_plan(
                        rollback,
                        expected_action="rollback",
                        root=host,
                        unit_state=UNIT_STATE,
                    )


if __name__ == "__main__":
    unittest.main()
