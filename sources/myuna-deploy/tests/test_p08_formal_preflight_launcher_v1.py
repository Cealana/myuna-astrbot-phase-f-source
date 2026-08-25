from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import p08_formal_preflight_launcher_v1 as launcher


def _invocation(
    cwd: Path, *, role: str = launcher.ROLE_FORMAL
) -> dict[str, object]:
    body = {
        "argv_identity_sha256": "1" * 64,
        "controller_sha256": "2" * 64,
        "cwd": str(cwd),
        "environment_identity_sha256": "3" * 64,
        "hard_timeout_seconds": launcher.ROLE_TIMEOUT_SECONDS[role],
        "host_contract_digest": "4" * 64,
        "launcher_contract_digest": "5" * 64,
        "no_progress_timeout_seconds": launcher.ROLE_NO_PROGRESS_TIMEOUT_SECONDS[role],
        "phase_liveness_contract_digest": "8" * 64,
        "role": role,
        "schema": launcher.LAUNCHER_SCHEMA,
        "source_binding_digest": "6" * 64,
        "target_release_digest": "7" * 64,
    }
    if role == launcher.ROLE_DRIFT:
        plan_bytes = _prepare_ready_bytes()
        plan = json.loads(plan_bytes.decode("ascii"))
        fixture_root = cwd
        plan_path = (
            fixture_root
            / "evidence"
            / "prepare-captures"
            / ("a" * 64)
            / "PLAN.INPUT.json"
        )
        formal = _invocation(cwd, role=launcher.ROLE_FORMAL)
        formal_sequence = launcher.sequence_contract(formal)
        formal_result_path = (
            cwd
            / "evidence"
            / "formal-sequences"
            / str(formal_sequence["sequence_identity"])
            / "RESULT.json"
        )
        body.update(
            {
                "drift_exactly_once": True,
                "formal_invocation_identity_sha256": formal[
                    "invocation_identity_sha256"
                ],
                "formal_sequence_identity": formal_sequence["sequence_identity"],
                "formal_result_sha256": (
                    launcher.digest_file(formal_result_path)
                    if formal_result_path.is_file()
                    else "e" * 64
                ),
                "plan_digest": plan["plan_digest"],
                "plan_sha256": launcher.digest_bytes(plan_bytes),
                "prepare_identity": "a" * 64,
            }
        )
        argv = [
            str(launcher.INTERPRETER),
            str(launcher.DEPLOY_ROOT / launcher.CONTROLLER_RELATIVE),
            "verify",
            "--plan",
            str(plan_path),
        ]
        environment = dict(launcher.FIXED_ENVIRONMENT)
        body["argv_identity_sha256"] = launcher.digest_bytes(
            launcher.canonical(argv)
        )
        body["cwd"] = str(launcher.DEPLOY_ROOT)
        body["environment_identity_sha256"] = launcher.digest_bytes(
            launcher.canonical(environment)
        )
    else:
        argv = [
            "/usr/bin/python3",
            "/synthetic/controller.py",
            "prepare" if role == launcher.ROLE_PREPARE else "preflight",
        ]
        environment = {"PYTHONDONTWRITEBYTECODE": "1"}
    return {
        **body,
        "invocation_identity_sha256": launcher.digest_bytes(
            launcher.canonical(body)
        ),
        "_argv": argv,
        "_environment": environment,
    }


def _ready_payload() -> dict[str, object]:
    forward_contract = launcher.expected_forward_continuity_contract()
    strategy_body = {
        "forward_continuity": forward_contract,
        "schema": launcher.CONTROLLER_STRATEGY_SCHEMA,
        "synthetic_source_binding": "b" * 64,
    }
    strategy = {
        **strategy_body,
        "strategy_digest": launcher.digest_bytes(launcher.canonical(strategy_body)),
    }
    plan_body = {
        "strategy": strategy,
        "synthetic_plan_binding": "c" * 64,
    }
    plan_digest = launcher.digest_bytes(launcher.canonical(plan_body))
    plan = {
        **plan_body,
        "plan_digest": plan_digest,
        "schema": launcher.CONTROLLER_PLAN_SCHEMA,
    }
    readiness_body = {
        "contract_digest": forward_contract["contract_digest"],
        "opaque_content_read": False,
        "persistent_mutation": False,
        "plan_digest": plan_digest,
        "schema": launcher.FORWARD_CONTINUITY_READINESS_SCHEMA,
        "status": "ready",
        "strategy_digest": strategy["strategy_digest"],
        "transition_deferred_to_action_ownership": True,
    }
    readiness = {
        **readiness_body,
        "readiness_digest": launcher.digest_bytes(
            launcher.canonical(readiness_body)
        ),
    }
    payload = {
        "forward_continuity": readiness,
        "opaque_content_read": False,
        "opaque_content_read_deferred_to_action_owned_backup": True,
        "persistent_mutation": False,
        "plan": plan,
        "plan_digest": plan_digest,
        "schema": launcher.CONTROLLER_READINESS_SCHEMA,
        "status": "ready",
    }
    return payload


def _ready_bytes() -> bytes:
    payload = _ready_payload()
    return launcher.canonical(payload) + b"\n"


def _rejected_bytes(code: str = "synthetic_rejected") -> bytes:
    return launcher.canonical(
        {
            "category": "typed_rejection",
            "code": code,
            "opaque_content_read": False,
            "persistent_mutation": False,
            "retryable": False,
            "schema": launcher.CONTROLLER_CLI_RESULT_SCHEMA,
            "status": "rejected",
        }
    ) + b"\n"


def _prepare_ready_bytes() -> bytes:
    raw_plan = {"action": "upgrade", "synthetic": True}
    plan_digest = launcher.digest_bytes(launcher.canonical(raw_plan))
    return launcher.canonical(
        {
            **raw_plan,
            "plan_digest": plan_digest,
            "schema": launcher.CONTROLLER_PLAN_SCHEMA,
        }
    ) + b"\n"


def _observation(
    *,
    returncode: int | None = 0,
    stdout: bytes | None = None,
    stderr: bytes = b"",
    created: bool = True,
    timed_out: bool = False,
    role: str = launcher.ROLE_FORMAL,
    progress_valid: bool = True,
    progress_complete: bool = True,
    progress_error: str | None = None,
) -> launcher.ProcessObservation:
    phases = launcher.ROLE_PHASES[role] if progress_complete else ()
    events = tuple(
        {
            "monotonic_ns": index,
            "nonce": "9" * 64,
            "phase": phase,
            "role": role,
            "schema": launcher.PHASE_LIVENESS_SCHEMA,
            "sequence": index,
        }
        for index, phase in enumerate(phases, 1)
    )
    return launcher.ProcessObservation(
        process_created=created,
        pid=222 if created else None,
        started_ns=100,
        ended_ns=200,
        returncode=returncode,
        timed_out=timed_out,
        stdout=_ready_bytes() if stdout is None else stdout,
        stderr=stderr,
        progress_valid=progress_valid,
        progress_complete=progress_complete,
        progress_events=events,
        progress_error=progress_error,
    )


def _seed_exact_two(root: Path, evidence: Path) -> None:
    plan = evidence / "prepare-captures" / ("a" * 64) / "PLAN.INPUT.json"
    plan.parent.mkdir(parents=True, mode=0o700)
    plan.write_bytes(_prepare_ready_bytes())
    plan.chmod(0o600)
    invocation = _invocation(root, role=launcher.ROLE_FORMAL)
    for call_index in (1, 2):
        launcher.capture_formal_call(
            invocation=invocation,
            evidence_root=evidence,
            call_index=call_index,
            runner=lambda *unused: _observation(),
        )
    launcher.verify_exact_two(invocation=invocation, evidence_root=evidence)


class FormalLauncherContractTests(unittest.TestCase):
    def _root(self, root: Path) -> Path:
        evidence = root / "evidence"
        evidence.mkdir(mode=0o700)
        return evidence

    def test_controller_mode_0644_requires_explicit_interpreter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            controller = root / "controller.py"
            controller.write_text("#!/usr/bin/python3\nprint('entered')\n", "utf-8")
            controller.chmod(0o644)
            try:
                direct = subprocess.run(
                    [str(controller)],
                    check=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                direct_entered = direct.returncode == 0
            except PermissionError:
                direct_entered = False
            explicit = subprocess.run(
                [str(launcher.INTERPRETER), str(controller)],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertFalse(direct_entered)
            self.assertEqual(explicit.returncode, 0)
            self.assertEqual(explicit.stdout, b"entered\n")

    def test_missing_pythonpath_fails_import_and_exact_path_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "synthetic_core.py").write_text("VALUE = 'bound'\n", "utf-8")
            controller = root / "controller.py"
            controller.write_text(
                "import synthetic_core\nprint(synthetic_core.VALUE)\n", "utf-8"
            )
            missing = subprocess.run(
                [str(launcher.INTERPRETER), str(controller)],
                check=False,
                env={"PYTHONDONTWRITEBYTECODE": "1"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            exact = subprocess.run(
                [str(launcher.INTERPRETER), str(controller)],
                check=False,
                env={
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONPATH": str(source),
                },
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(missing.returncode, 0)
            self.assertEqual(missing.stdout, b"")
            self.assertEqual(exact.returncode, 0)
            self.assertEqual(exact.stdout, b"bound\n")
            self.assertFalse(any(root.rglob("*.pyc")))

    def test_process_runner_closes_stdin_separates_pipes_and_uses_umask(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child = root / "child.py"
            output = root / "created"
            child.write_text(
                "import os,sys\n"
                "import p08_formal_preflight_launcher_v1 as launcher\n"
                "for phase in launcher.ROLE_PHASES[launcher.ROLE_PREPARE]: launcher.emit_phase(phase)\n"
                f"fd=os.open({str(output)!r},os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o666)\n"
                "os.close(fd)\n"
                "stdin_empty=(sys.stdin.buffer.read()==b'')\n"
                "sys.stdout.write('out:'+str(stdin_empty))\n"
                "sys.stderr.write('err')\n",
                "utf-8",
            )
            observed = launcher._run_process(
                [str(launcher.INTERPRETER), str(child)],
                {
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONPATH": str(SCRIPTS),
                },
                root,
                launcher.ROLE_TIMEOUT_SECONDS[launcher.ROLE_PREPARE],
                launcher.ROLE_PREPARE,
                "a" * 64,
            )
            self.assertTrue(observed.process_created)
            self.assertEqual(observed.returncode, 0)
            self.assertEqual(observed.stdout, b"out:True")
            self.assertEqual(observed.stderr, b"err")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_ready_exact_two_is_source_verified_and_raw_output_is_not_retained(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = self._root(root)
            invocation = _invocation(root)
            runner = mock.Mock(return_value=_observation())
            first = launcher.capture_formal_call(
                invocation=invocation,
                evidence_root=evidence,
                call_index=1,
                runner=runner,
            )
            second = launcher.capture_formal_call(
                invocation=invocation,
                evidence_root=evidence,
                call_index=2,
                runner=runner,
            )
            result = launcher.verify_exact_two(
                invocation=invocation, evidence_root=evidence
            )
            self.assertEqual(first["status"], "ready")
            self.assertEqual(second["status"], "ready")
            self.assertNotEqual(first["call_nonce"], second["call_nonce"])
            self.assertEqual(result["status"], "ready")
            self.assertEqual(result["calls"], 2)
            self.assertEqual(runner.call_count, 2)
            for call in runner.call_args_list:
                self.assertEqual(call.args[0], invocation["_argv"])
                self.assertEqual(call.args[1], invocation["_environment"])
                self.assertEqual(call.args[2], root)
                self.assertEqual(
                    call.args[3],
                    launcher.ROLE_TIMEOUT_SECONDS[launcher.ROLE_FORMAL],
                )
                self.assertEqual(call.args[4], launcher.ROLE_FORMAL)
                self.assertRegex(call.args[5], r"^[0-9a-f]{64}$")
            durable = b"".join(path.read_bytes() for path in evidence.rglob("*.json"))
            self.assertNotIn(_ready_bytes(), durable)
            self.assertNotIn(b"synthetic-plan", durable)
            self.assertNotIn(b"private-cause-must-not-persist", durable)

    def test_absent_evidence_root_is_created_source_owned_and_durable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            capture = launcher.capture_formal_call(
                invocation=_invocation(root),
                evidence_root=evidence,
                call_index=1,
                runner=lambda *unused: _observation(),
            )
            self.assertEqual(capture["status"], "ready")
            self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
            durable_files = list(evidence.rglob("*.json"))
            self.assertEqual(len(durable_files), 3)
            for path in durable_files:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_canonical_exit_two_is_rejected_not_indeterminate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = launcher.capture_formal_call(
                invocation=_invocation(root),
                evidence_root=self._root(root),
                call_index=1,
                runner=lambda *unused: _observation(
                    returncode=2, stdout=_rejected_bytes("public_state_drifted")
                ),
            )
            self.assertEqual(capture["status"], "rejected")
            self.assertEqual(
                capture["result_detail"], "typed_rejection:public_state_drifted"
            )
            self.assertTrue(capture["canonical_result"])

    def test_unknown_malformed_empty_oversize_raw_tainted_and_stderr_fail_closed(self) -> None:
        ready = json.loads(_ready_bytes().decode("ascii"))
        ready["raw"] = "forbidden"
        variants = {
            "empty": _observation(stdout=b""),
            "malformed": _observation(stdout=b"{bad\n"),
            "unknown": _observation(
                stdout=launcher.canonical({"schema": "unknown", "status": "ready"})
                + b"\n"
            ),
            "oversize": _observation(stdout=b"x" * (launcher.MAX_STDOUT_BYTES + 1)),
            "raw_tainted": _observation(stdout=launcher.canonical(ready) + b"\n"),
            "stderr": _observation(stderr=b"private-cause-must-not-persist"),
            "unexpected_exit": _observation(returncode=1, stdout=b""),
            "signal": _observation(returncode=-9, stdout=b""),
            "timeout": _observation(returncode=-9, stdout=b"", timed_out=True),
            "preinvoke": _observation(returncode=None, stdout=b"", created=False),
        }
        for name, observed in variants.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                evidence = self._root(root)
                capture = launcher.capture_formal_call(
                    invocation=_invocation(root),
                    evidence_root=evidence,
                    call_index=1,
                    runner=lambda *unused, value=observed: value,
                )
                self.assertEqual(capture["status"], "indeterminate")
                self.assertFalse(capture["canonical_result"])
                durable = b"".join(
                    path.read_bytes() for path in evidence.rglob("*.json")
                )
                self.assertNotIn(b"private-cause-must-not-persist", durable)

    def test_forward_continuity_nested_contract_is_exact_and_fail_closed(self) -> None:
        mutations = {
            "missing": lambda value: value.pop("readiness_digest"),
            "extra": lambda value: value.__setitem__("raw", "forbidden"),
            "schema": lambda value: value.__setitem__("schema", "unknown.v1"),
            "boolean": lambda value: value.__setitem__("opaque_content_read", True),
            "plan": lambda value: value.__setitem__("plan_digest", "0" * 64),
            "strategy": lambda value: value.__setitem__("strategy_digest", "1" * 64),
            "contract": lambda value: value.__setitem__("contract_digest", "2" * 64),
            "digest": lambda value: value.__setitem__("readiness_digest", "3" * 64),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                payload = _ready_payload()
                nested = payload["forward_continuity"]
                self.assertIsInstance(nested, dict)
                mutate(nested)
                parsed = launcher._parse_child(
                    _observation(stdout=launcher.canonical(payload) + b"\n")
                )
                self.assertEqual(parsed, ("indeterminate", None, None, False))

        for name, mutate in {
            "plan_schema": lambda payload: payload["plan"].__setitem__(
                "schema", "stale.v11"
            ),
            "strategy_schema": lambda payload: payload["plan"]["strategy"].__setitem__(
                "schema", "stale.v11"
            ),
            "contract_substitution": lambda payload: payload["plan"]["strategy"][
                "forward_continuity"
            ].__setitem__("core_commit", "0" * 40),
        }.items():
            with self.subTest(name=name):
                payload = _ready_payload()
                mutate(payload)
                parsed = launcher._parse_child(
                    _observation(stdout=launcher.canonical(payload) + b"\n")
                )
                self.assertEqual(parsed, ("indeterminate", None, None, False))

    def test_wrong_nonce_one_field_drift_and_mixed_capture_fail_closed(self) -> None:
        for selected in ("nonce", "stdout", "source"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                evidence = self._root(root)
                invocation = _invocation(root)
                for index in (1, 2):
                    launcher.capture_formal_call(
                        invocation=invocation,
                        evidence_root=evidence,
                        call_index=index,
                        runner=lambda *unused: _observation(),
                    )
                sequence = launcher.sequence_contract(invocation)
                path = (
                    evidence
                    / "formal-sequences"
                    / str(sequence["sequence_identity"])
                    / "CALL-2.CAPTURE.json"
                )
                payload = json.loads(path.read_text("ascii"))
                if selected == "nonce":
                    payload["call_nonce"] = "0" * 64
                elif selected == "stdout":
                    payload["stdout_sha256"] = "0" * 64
                else:
                    payload["invocation_identity_sha256"] = "0" * 64
                path.write_bytes(launcher.canonical(payload) + b"\n")
                with self.assertRaisesRegex(
                    launcher.LauncherRejected, "exact_two_sequence_rejected"
                ):
                    launcher.verify_exact_two(
                        invocation=invocation, evidence_root=evidence
                    )

    def test_crash_residue_replay_and_concurrent_writer_are_consumed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = self._root(root)
            invocation = _invocation(root)
            first = launcher.capture_formal_call(
                invocation=invocation,
                evidence_root=evidence,
                call_index=1,
                runner=lambda *unused: (_ for _ in ()).throw(RuntimeError("crash")),
            )
            self.assertEqual(first["status"], "indeterminate")
            with self.assertRaisesRegex(
                launcher.LauncherRejected, "capture_replay_rejected"
            ):
                launcher.capture_formal_call(
                    invocation=invocation,
                    evidence_root=evidence,
                    call_index=1,
                    runner=lambda *unused: _observation(),
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = self._root(root)
            invocation = _invocation(root)

            def compete() -> str:
                try:
                    launcher.capture_formal_call(
                        invocation=invocation,
                        evidence_root=evidence,
                        call_index=1,
                        runner=lambda *unused: _observation(),
                    )
                    return "captured"
                except launcher.LauncherRejected as exc:
                    return exc.code

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = sorted(pool.map(lambda unused: compete(), range(2)))
            self.assertEqual(results.count("captured"), 1)
            self.assertEqual(len(results), 2)
            self.assertTrue(
                set(results) <= {
                    "captured",
                    "capture_replay_rejected",
                    "capture_persist_rejected",
                    "sequence_identity_rejected",
                    "sequence_contract_rejected",
                },
                results,
            )

    def test_call_order_and_third_call_reject_without_runner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = self._root(root)
            invoked = mock.Mock(return_value=_observation())
            with self.assertRaisesRegex(launcher.LauncherRejected, "call_order_rejected"):
                launcher.capture_formal_call(
                    invocation=_invocation(root),
                    evidence_root=evidence,
                    call_index=2,
                    runner=invoked,
                )
            with self.assertRaisesRegex(launcher.LauncherRejected, "call_index_rejected"):
                launcher.capture_formal_call(
                    invocation=_invocation(root),
                    evidence_root=evidence,
                    call_index=3,
                    runner=invoked,
                )
            invoked.assert_not_called()

    def test_artifact_contract_binds_controller_and_launcher_modes(self) -> None:
        contract = launcher.artifact_contract(ROOT)
        self.assertEqual(contract["controller"]["source_mode"], 0o644)
        self.assertEqual(contract["launcher"]["source_mode"], 0o755)
        self.assertEqual(contract["controller"]["allowed_installed_modes"], [0o444, 0o644])
        self.assertEqual(contract["launcher"]["allowed_installed_modes"], [0o444, 0o644])
        self.assertEqual(contract["controller_path"], launcher.CONTROLLER_RELATIVE.as_posix())
        self.assertEqual(contract["launcher_path"], launcher.LAUNCHER_RELATIVE.as_posix())
        body = {key: value for key, value in contract.items() if key != "contract_digest"}
        self.assertEqual(
            contract["contract_digest"], launcher.digest_bytes(launcher.canonical(body))
        )

    def test_runtime_identity_rejects_uid_cwd_interpreter_or_groups_drift(self) -> None:
        checks = (
            {"geteuid": 1, "getegid": 0, "getgroups": [0]},
            {"geteuid": 0, "getegid": 1, "getgroups": [0]},
            {"geteuid": 0, "getegid": 0, "getgroups": [1]},
        )
        for values in checks:
            with self.subTest(values=values), mock.patch.object(
                launcher.os, "geteuid", return_value=values["geteuid"]
            ), mock.patch.object(
                launcher.os, "getegid", return_value=values["getegid"]
            ), mock.patch.object(
                launcher.os, "getgroups", return_value=values["getgroups"]
            ):
                with self.assertRaisesRegex(
                    launcher.LauncherRejected, "privilege_identity_rejected"
                ):
                    launcher._validate_runtime_identity()

    def test_v6_through_v12_history_are_bound_and_never_reopened(self) -> None:
        import p08_current_selected_upgrade_v1 as controller

        strategy = controller.strategy_contract()
        self.assertEqual(strategy["v6_incident_digest"], controller.V6_INCIDENT_DIGEST)
        self.assertEqual(strategy["v6_plan_digest"], controller.V6_PLAN_DIGEST)
        self.assertEqual(strategy["v6_formal_sequence"]["calls_consumed"], 2)
        self.assertEqual(strategy["v6_formal_sequence"]["calls_maximum"], 2)
        self.assertFalse(strategy["v6_formal_sequence"]["reopen_authority"])
        self.assertEqual(
            strategy["v6_capture_t0_handoff_sha256"],
            controller.V6_CAPTURE_T0_HANDOFF_SHA256,
        )
        self.assertEqual(
            strategy["v7_prepare_residue"]["prepare_call"]["prepare_calls"], 1
        )
        self.assertFalse(strategy["v7_prepare_residue"]["content_opened"])
        self.assertFalse(strategy["v7_prepare_residue"]["restore_authority"])
        self.assertEqual(
            strategy["v8_closed_sequence"]["sequence_identity"],
            controller.V8_FORMAL_SEQUENCE_IDENTITY,
        )
        self.assertFalse(strategy["v8_closed_sequence"]["reopen_authority"])
        self.assertEqual(
            strategy["v8_t0_handoff_sha256"],
            controller.V8_TIMEOUT_T0_HANDOFF_SHA256,
        )
        self.assertEqual(
            strategy["v9_closed_sequence"]["formal"]["sequence_identity"],
            controller.V9_FORMAL_SEQUENCE_IDENTITY,
        )
        self.assertEqual(strategy["v9_closed_sequence"]["drift_calls_consumed"], 1)
        self.assertFalse(strategy["v9_closed_sequence"]["reopen_authority"])
        self.assertIn(
            "forward-continuity-lineage-sha-repair-v13",
            strategy["incident_namespace"],
        )
        self.assertEqual(
            strategy["v10_terminal"]["status"],
            "trusted_time_drift_exceeded_predecessor_restored",
        )
        self.assertFalse(strategy["v10_terminal"]["reopen_authority"])
        self.assertEqual(
            strategy["v11_closed_sequence"]["formal"]["calls_consumed"], 1
        )
        self.assertFalse(strategy["v11_closed_sequence"]["reopen_authority"])
        self.assertEqual(strategy["v12_rejected_prepare"]["prepare"]["status"], "rejected")
        self.assertEqual(strategy["v12_rejected_prepare"]["formal_calls_consumed"], 0)
        self.assertFalse(strategy["v12_rejected_prepare"]["reopen_authority"])

    def test_prepare_success_persists_only_validated_plan_and_projection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = self._root(root)
            invocation = _invocation(root, role=launcher.ROLE_PREPARE)
            observation = _observation(
                stdout=_prepare_ready_bytes(), role=launcher.ROLE_PREPARE
            )
            result = launcher.capture_prepare_call(
                invocation=invocation,
                evidence_root=evidence,
                runner=lambda *unused: observation,
            )
            self.assertEqual(result["status"], "ready")
            self.assertFalse(result["raw_output_retained"])
            prepare = launcher.prepare_contract(invocation)
            selected = (
                evidence
                / "prepare-captures"
                / str(prepare["prepare_identity"])
            )
            plan = json.loads((selected / "PLAN.INPUT.json").read_text("ascii"))
            self.assertEqual(plan["schema"], launcher.CONTROLLER_PLAN_SCHEMA)
            self.assertEqual(result["plan_digest"], plan["plan_digest"])
            durable = b"".join(path.read_bytes() for path in selected.glob("*.json"))
            self.assertNotIn(b"private-cause-must-not-persist", durable)
            self.assertEqual(
                sorted(path.name for path in selected.glob("*.json")),
                [
                    "CAPTURE.json",
                    "CLAIM.json",
                    "PLAN.INPUT.json",
                    "PREPARE.json",
                    "RESULT.json",
                ],
            )

    def test_prepare_rejection_indeterminate_replay_and_role_mixing_fail_closed(self) -> None:
        cases = {
            "typed": _observation(
                returncode=2,
                stdout=_rejected_bytes(),
                role=launcher.ROLE_PREPARE,
            ),
            "invalid_plan": _observation(
                stdout=_ready_bytes(), role=launcher.ROLE_PREPARE
            ),
            "stderr": _observation(
                stdout=_prepare_ready_bytes(),
                stderr=b"private-raw-cause",
                role=launcher.ROLE_PREPARE,
            ),
            "empty": _observation(
                returncode=1, stdout=b"", role=launcher.ROLE_PREPARE
            ),
            "oversize": _observation(
                stdout=b"x" * (launcher.MAX_STDOUT_BYTES + 1),
                role=launcher.ROLE_PREPARE,
            ),
        }
        for name, observation in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                evidence = self._root(root)
                invocation = _invocation(root, role=launcher.ROLE_PREPARE)
                result = launcher.capture_prepare_call(
                    invocation=invocation,
                    evidence_root=evidence,
                    runner=lambda *unused, value=observation: value,
                )
                expected = "rejected" if name == "typed" else "indeterminate"
                self.assertEqual(result["status"], expected)
                self.assertFalse(any(evidence.rglob("PLAN.INPUT.json")))
                durable = b"".join(
                    path.read_bytes() for path in evidence.rglob("*.json")
                )
                self.assertNotIn(b"private-raw-cause", durable)
                with self.assertRaisesRegex(
                    launcher.LauncherRejected, "prepare_replay_rejected"
                ):
                    launcher.capture_prepare_call(
                        invocation=invocation,
                        evidence_root=evidence,
                        runner=lambda *unused: _observation(
                            stdout=_prepare_ready_bytes(),
                            role=launcher.ROLE_PREPARE,
                        ),
                    )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = self._root(root)
            with self.assertRaisesRegex(
                launcher.LauncherRejected, "invocation_role_rejected"
            ):
                launcher.capture_prepare_call(
                    invocation=_invocation(root),
                    evidence_root=evidence,
                )
            with self.assertRaisesRegex(
                launcher.LauncherRejected, "invocation_role_rejected"
            ):
                launcher.capture_formal_call(
                    invocation=_invocation(root, role=launcher.ROLE_PREPARE),
                    evidence_root=evidence,
                    call_index=1,
                )

    def test_prepare_crash_residue_and_concurrent_claim_are_consumed_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = self._root(root)
            invocation = _invocation(root, role=launcher.ROLE_PREPARE)
            result = launcher.capture_prepare_call(
                invocation=invocation,
                evidence_root=evidence,
                runner=lambda *unused: (_ for _ in ()).throw(
                    RuntimeError("synthetic crash")
                ),
            )
            self.assertEqual(result["status"], "indeterminate")
            with self.assertRaisesRegex(
                launcher.LauncherRejected, "prepare_replay_rejected"
            ):
                launcher.capture_prepare_call(
                    invocation=invocation,
                    evidence_root=evidence,
                    runner=lambda *unused: _observation(
                        stdout=_prepare_ready_bytes(),
                        role=launcher.ROLE_PREPARE,
                    ),
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = self._root(root)
            invocation = _invocation(root, role=launcher.ROLE_PREPARE)

            def compete() -> str:
                try:
                    launcher.capture_prepare_call(
                        invocation=invocation,
                        evidence_root=evidence,
                        runner=lambda *unused: _observation(
                            stdout=_prepare_ready_bytes(),
                            role=launcher.ROLE_PREPARE,
                        ),
                    )
                    return "captured"
                except launcher.LauncherRejected as exc:
                    return exc.code

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda unused: compete(), range(2)))
            self.assertEqual(results.count("captured"), 1)
            self.assertEqual(len(results), 2)
            self.assertIn(
                next(result for result in results if result != "captured"),
                {
                    "capture_persist_rejected",
                    "prepare_identity_rejected",
                    "prepare_replay_rejected",
                },
            )

    def test_drift_capture_is_single_source_owned_ready_and_raw_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = self._root(root)
            _seed_exact_two(root, evidence)
            invocation = _invocation(root, role=launcher.ROLE_DRIFT)
            result = launcher.capture_drift_call(
                invocation=invocation,
                evidence_root=evidence,
                runner=lambda *unused: _observation(
                    stdout=_prepare_ready_bytes(), role=launcher.ROLE_DRIFT
                ),
            )
            self.assertEqual(result["status"], "ready")
            self.assertEqual(result["call_count"], 1)
            self.assertFalse(result["persistent_product_mutation"])
            self.assertFalse(result["raw_output_retained"])
            drift = launcher.drift_contract(invocation)
            selected = (
                evidence / "drift-captures" / str(drift["drift_identity"])
            )
            self.assertEqual(
                sorted(path.name for path in selected.glob("*.json")),
                ["CAPTURE.json", "CLAIM.json", "DRIFT.json", "RESULT.json"],
            )
            durable = b"".join(path.read_bytes() for path in selected.glob("*.json"))
            self.assertNotIn(_prepare_ready_bytes(), durable)
            with self.assertRaisesRegex(
                launcher.LauncherRejected, "drift_replay_rejected"
            ):
                launcher.capture_drift_call(
                    invocation=invocation,
                    evidence_root=evidence,
                    runner=lambda *unused: _observation(
                        stdout=_prepare_ready_bytes(), role=launcher.ROLE_DRIFT
                    ),
                )

    def test_drift_malformed_substituted_and_role_mixed_fail_closed(self) -> None:
        ready = json.loads(_prepare_ready_bytes().decode("ascii"))
        wrong_digest = dict(ready)
        wrong_digest["plan_digest"] = "0" * 64
        variants = {
            "empty": _observation(
                returncode=1, stdout=b"", role=launcher.ROLE_DRIFT
            ),
            "malformed": _observation(stdout=b"{bad\n", role=launcher.ROLE_DRIFT),
            "oversize": _observation(
                stdout=b"x" * (launcher.MAX_STDOUT_BYTES + 1),
                role=launcher.ROLE_DRIFT,
            ),
            "wrong_plan": _observation(
                stdout=launcher.canonical(wrong_digest) + b"\n",
                role=launcher.ROLE_DRIFT,
            ),
            "stderr": _observation(
                stdout=_prepare_ready_bytes(),
                stderr=b"private-cause",
                role=launcher.ROLE_DRIFT,
            ),
        }
        for name, observation in variants.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                evidence = self._root(root)
                _seed_exact_two(root, evidence)
                result = launcher.capture_drift_call(
                    invocation=_invocation(root, role=launcher.ROLE_DRIFT),
                    evidence_root=evidence,
                    runner=lambda *unused, value=observation: value,
                )
                self.assertEqual(result["status"], "indeterminate")
                durable = b"".join(
                    path.read_bytes() for path in evidence.rglob("*.json")
                )
                self.assertNotIn(b"private-cause", durable)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(
                launcher.LauncherRejected, "drift_invocation_contract_rejected"
            ):
                launcher.capture_drift_call(
                    invocation=_invocation(root, role=launcher.ROLE_FORMAL),
                    evidence_root=self._root(root),
                )

    def test_drift_requires_persisted_exact_two_before_claim_or_runner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = self._root(root)
            runner = mock.Mock()
            with self.assertRaisesRegex(
                launcher.LauncherRejected, "sequence_identity_rejected"
            ):
                launcher.capture_drift_call(
                    invocation=_invocation(root, role=launcher.ROLE_DRIFT),
                    evidence_root=evidence,
                    runner=runner,
                )
            runner.assert_not_called()
            self.assertFalse((evidence / "drift-captures").exists())

    def test_drift_private_argv_or_environment_substitution_consumes_claim(self) -> None:
        for field, replacement in (
            ("_argv", ["/usr/bin/python3", "/substituted/controller.py"]),
            ("_environment", {"PYTHONDONTWRITEBYTECODE": "1"}),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                evidence = self._root(root)
                _seed_exact_two(root, evidence)
                invocation = _invocation(root, role=launcher.ROLE_DRIFT)
                invocation[field] = replacement
                runner = mock.Mock()
                with self.assertRaisesRegex(
                    launcher.LauncherRejected,
                    "drift_invocation_contract_rejected",
                ):
                    launcher.capture_drift_call(
                        invocation=invocation,
                        evidence_root=evidence,
                        runner=runner,
                    )
                runner.assert_not_called()
                selected = evidence / "drift-captures"
                claims = list(selected.rglob("CLAIM.json"))
                self.assertEqual(len(claims), 1)
                self.assertFalse(list(selected.rglob("CAPTURE.json")))

    def test_drift_formal_evidence_mutation_after_runner_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = self._root(root)
            _seed_exact_two(root, evidence)
            invocation = _invocation(root, role=launcher.ROLE_DRIFT)
            result_path = (
                evidence
                / "formal-sequences"
                / str(invocation["formal_sequence_identity"])
                / "RESULT.json"
            )
            runner_calls = 0

            def mutate_after_entry(*unused: object) -> launcher.ProcessObservation:
                nonlocal runner_calls
                runner_calls += 1
                result_path.chmod(0o644)
                return _observation(
                    stdout=_prepare_ready_bytes(), role=launcher.ROLE_DRIFT
                )

            with self.assertRaisesRegex(
                launcher.LauncherRejected, "capture_evidence_rejected"
            ):
                launcher.capture_drift_call(
                    invocation=invocation,
                    evidence_root=evidence,
                    runner=mutate_after_entry,
                )
            self.assertEqual(runner_calls, 1)
            selected = evidence / "drift-captures"
            self.assertEqual(len(list(selected.rglob("CLAIM.json"))), 1)
            self.assertFalse(list(selected.rglob("CAPTURE.json")))

    def test_drift_plan_mutation_after_runner_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = self._root(root)
            _seed_exact_two(root, evidence)
            invocation = _invocation(root, role=launcher.ROLE_DRIFT)
            plan_path = Path(str(invocation["_argv"][4]))
            runner_calls = 0

            def mutate_after_entry(*unused: object) -> launcher.ProcessObservation:
                nonlocal runner_calls
                runner_calls += 1
                plan_path.chmod(0o644)
                return _observation(
                    stdout=_prepare_ready_bytes(), role=launcher.ROLE_DRIFT
                )

            with self.assertRaisesRegex(
                launcher.LauncherRejected, "drift_plan_identity_rejected"
            ):
                launcher.capture_drift_call(
                    invocation=invocation,
                    evidence_root=evidence,
                    runner=mutate_after_entry,
                )
            self.assertEqual(runner_calls, 1)
            selected = evidence / "drift-captures"
            self.assertEqual(len(list(selected.rglob("CLAIM.json"))), 1)
            self.assertFalse(list(selected.rglob("CAPTURE.json")))

    def test_drift_plan_path_substitution_consumes_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = self._root(root)
            _seed_exact_two(root, evidence)
            invocation = _invocation(root, role=launcher.ROLE_DRIFT)
            substituted = root / "substituted" / "PLAN.INPUT.json"
            substituted.parent.mkdir()
            substituted.write_bytes(_prepare_ready_bytes())
            substituted.chmod(0o600)
            invocation["_argv"] = [*invocation["_argv"][:4], str(substituted)]
            runner = mock.Mock()
            with self.assertRaisesRegex(
                launcher.LauncherRejected, "drift_plan_identity_rejected"
            ):
                launcher.capture_drift_call(
                    invocation=invocation,
                    evidence_root=evidence,
                    runner=runner,
                )
            runner.assert_not_called()
            selected = evidence / "drift-captures"
            self.assertEqual(len(list(selected.rglob("CLAIM.json"))), 1)
            self.assertFalse(list(selected.rglob("CAPTURE.json")))

    def test_role_budgets_and_phase_contract_are_source_bound(self) -> None:
        self.assertEqual(
            launcher.ROLE_TIMEOUT_SECONDS,
            {
                launcher.ROLE_PREPARE: 60,
                launcher.ROLE_FORMAL: 180,
                launcher.ROLE_DRIFT: 120,
            },
        )
        self.assertEqual(
            launcher.ROLE_NO_PROGRESS_TIMEOUT_SECONDS,
            {
                launcher.ROLE_PREPARE: 75,
                launcher.ROLE_FORMAL: 75,
                launcher.ROLE_DRIFT: 75,
            },
        )
        self.assertEqual(launcher.NO_PROGRESS_TIMEOUT_SECONDS, 75)
        measured_double_seconds = (
            launcher.MEASURED_SINGLE_VALIDATION_MILLISECONDS
            * launcher.FORMAL_VALIDATION_PASSES
            / 1000
        )
        self.assertGreater(
            launcher.ROLE_TIMEOUT_SECONDS[launcher.ROLE_FORMAL],
            measured_double_seconds + launcher.NO_PROGRESS_TIMEOUT_SECONDS,
        )
        self.assertGreater(
            launcher.ROLE_TIMEOUT_SECONDS[launcher.ROLE_PREPARE],
            launcher.MEASURED_SINGLE_VALIDATION_MILLISECONDS / 1000,
        )
        self.assertLess(
            launcher.NO_PROGRESS_TIMEOUT_SECONDS,
            launcher.ROLE_TIMEOUT_SECONDS[launcher.ROLE_FORMAL],
        )
        contract = launcher.host_contract()
        self.assertFalse(
            contract["phase_liveness"]["hard_deadline_extensible"]
        )
        self.assertEqual(
            contract["phase_liveness"]["phases"][launcher.ROLE_FORMAL],
            list(launcher.ROLE_PHASES[launcher.ROLE_FORMAL]),
        )
        self.assertEqual(
            contract["phase_liveness"]["phases"][launcher.ROLE_DRIFT],
            list(launcher.ROLE_PHASES[launcher.ROLE_DRIFT]),
        )

    def test_phase_parser_rejects_nonce_role_order_replay_and_malformed(self) -> None:
        nonce = "a" * 64
        valid = {
            "monotonic_ns": 10,
            "nonce": nonce,
            "phase": launcher.PHASE_STARTUP,
            "role": launcher.ROLE_FORMAL,
            "schema": launcher.PHASE_LIVENESS_SCHEMA,
            "sequence": 1,
        }
        self.assertEqual(
            launcher._validate_phase_line(
                launcher.canonical(valid),
                role=launcher.ROLE_FORMAL,
                nonce=nonce,
                expected_sequence=1,
                prior_timestamp=-1,
            ),
            valid,
        )
        cases = (
            {**valid, "nonce": "b" * 64},
            {**valid, "role": launcher.ROLE_PREPARE},
            {**valid, "phase": launcher.PHASE_SOURCE_LINEAGE},
            {**valid, "sequence": 2},
            {**valid, "monotonic_ns": 9},
            {**valid, "raw": "forbidden"},
        )
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(
                launcher.LauncherRejected
            ):
                launcher._validate_phase_line(
                    launcher.canonical(payload),
                    role=launcher.ROLE_FORMAL,
                    nonce=nonce,
                    expected_sequence=1,
                    prior_timestamp=9,
                )
        with self.assertRaisesRegex(
            launcher.LauncherRejected, "phase_liveness_malformed"
        ):
            launcher._validate_phase_line(
                b"not-json",
                role=launcher.ROLE_FORMAL,
                nonce=nonce,
                expected_sequence=1,
                prior_timestamp=-1,
            )

    def test_deadline_boundaries_use_fake_clock_values_and_hard_deadline_wins(self) -> None:
        self.assertIsNone(
            launcher._deadline_class(
                9.999, hard_deadline=10.0, progress_deadline=20.0
            )
        )
        self.assertEqual(
            launcher._deadline_class(
                10.0, hard_deadline=10.0, progress_deadline=20.0
            ),
            "hard_total",
        )
        self.assertEqual(
            launcher._deadline_class(
                20.0, hard_deadline=30.0, progress_deadline=20.0
            ),
            "no_progress",
        )
        self.assertEqual(
            launcher._deadline_class(
                30.0, hard_deadline=30.0, progress_deadline=20.0
            ),
            "hard_total",
        )

    def test_real_subprocess_phase_pipe_completes_formal_trace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child = root / "child.py"
            ready = repr(_ready_bytes())
            child.write_text(
                "import p08_formal_preflight_launcher_v1 as l\n"
                "for phase in l.ROLE_PHASES[l.ROLE_FORMAL]: l.emit_phase(phase)\n"
                f"payload={ready}\n"
                "print(payload.decode('ascii'),end='')\n",
                "utf-8",
            )
            observation = launcher._run_process(
                [str(launcher.INTERPRETER), str(child)],
                {
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONPATH": str(SCRIPTS),
                },
                root,
                launcher.ROLE_TIMEOUT_SECONDS[launcher.ROLE_FORMAL],
                launcher.ROLE_FORMAL,
                "b" * 64,
            )
            self.assertEqual(observation.returncode, 0)
            self.assertTrue(observation.progress_valid)
            self.assertTrue(observation.progress_complete)
            self.assertEqual(
                [event["phase"] for event in observation.progress_events],
                list(launcher.ROLE_PHASES[launcher.ROLE_FORMAL]),
            )
            self.assertEqual(observation.stderr, b"")

    def test_real_subprocess_scaled_double_validation_stays_within_formal_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child = root / "scaled.py"
            ready = repr(_ready_bytes())
            child.write_text(
                "import time\n"
                "import p08_formal_preflight_launcher_v1 as l\n"
                "for phase in l.ROLE_PHASES[l.ROLE_FORMAL]:\n"
                " l.emit_phase(phase)\n"
                " if phase in (l.PHASE_TARGET_VALIDATION_PASS1,l.PHASE_TARGET_VALIDATION_PASS2): time.sleep(0.15)\n"
                f"payload={ready}\n"
                "print(payload.decode('ascii'),end='')\n",
                "utf-8",
            )
            with mock.patch.dict(
                launcher.ROLE_TIMEOUT_SECONDS,
                {launcher.ROLE_PREPARE: 2, launcher.ROLE_FORMAL: 3},
                clear=True,
            ), mock.patch.dict(
                launcher.ROLE_NO_PROGRESS_TIMEOUT_SECONDS,
                {launcher.ROLE_FORMAL: 1},
                clear=True,
            ):
                observation = launcher._run_process(
                    [str(launcher.INTERPRETER), str(child)],
                    {
                        "PYTHONDONTWRITEBYTECODE": "1",
                        "PYTHONPATH": str(SCRIPTS),
                    },
                    root,
                    3,
                    launcher.ROLE_FORMAL,
                    "f" * 64,
                )
            self.assertEqual(observation.returncode, 0)
            self.assertFalse(observation.timed_out)
            self.assertTrue(observation.progress_complete)
            self.assertGreaterEqual(
                observation.ended_ns - observation.started_ns, 250_000_000
            )
            self.assertEqual(observation.stderr, b"")

    def test_no_progress_and_hard_deadlines_are_independent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child = root / "stall.py"
            child.write_text(
                "import time\n"
                "import p08_formal_preflight_launcher_v1 as l\n"
                "l.emit_phase(l.PHASE_STARTUP)\n"
                "time.sleep(5)\n",
                "utf-8",
            )
            with mock.patch.dict(
                launcher.ROLE_TIMEOUT_SECONDS,
                {launcher.ROLE_PREPARE: 60, launcher.ROLE_FORMAL: 3},
                clear=True,
            ), mock.patch.dict(
                launcher.ROLE_NO_PROGRESS_TIMEOUT_SECONDS,
                {launcher.ROLE_FORMAL: 1},
                clear=True,
            ):
                no_progress = launcher._run_process(
                    [str(launcher.INTERPRETER), str(child)],
                    {
                        "PYTHONDONTWRITEBYTECODE": "1",
                        "PYTHONPATH": str(SCRIPTS),
                    },
                    root,
                    3,
                    launcher.ROLE_FORMAL,
                    "c" * 64,
                )
            self.assertTrue(no_progress.timed_out)
            self.assertEqual(no_progress.timeout_class, "no_progress")
            self.assertTrue(no_progress.drain_completed)

            child.write_text(
                "import time\n"
                "import p08_formal_preflight_launcher_v1 as l\n"
                "for phase in l.ROLE_PHASES[l.ROLE_FORMAL]:\n"
                " l.emit_phase(phase); time.sleep(0.05)\n"
                "time.sleep(5)\n",
                "utf-8",
            )
            with mock.patch.dict(
                launcher.ROLE_TIMEOUT_SECONDS,
                {launcher.ROLE_PREPARE: 60, launcher.ROLE_FORMAL: 1},
                clear=True,
            ), mock.patch.dict(
                launcher.ROLE_NO_PROGRESS_TIMEOUT_SECONDS,
                {launcher.ROLE_FORMAL: 5},
                clear=True,
            ):
                hard = launcher._run_process(
                    [str(launcher.INTERPRETER), str(child)],
                    {
                        "PYTHONDWRITEBYTECODE": "1",
                        "PYTHONPATH": str(SCRIPTS),
                    },
                    root,
                    1,
                    launcher.ROLE_FORMAL,
                    "d" * 64,
                )
            self.assertTrue(hard.timed_out)
            self.assertEqual(hard.timeout_class, "hard_total")
            self.assertTrue(hard.progress_complete)
            self.assertTrue(hard.drain_completed)

    def test_pipe_close_and_progress_substitution_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child = root / "close.py"
            child.write_text(
                "import os,time\n"
                "import p08_formal_preflight_launcher_v1 as l\n"
                "os.close(int(os.environ[l.PHASE_FD_ENV]))\n"
                "time.sleep(5)\n",
                "utf-8",
            )
            observation = launcher._run_process(
                [str(launcher.INTERPRETER), str(child)],
                {
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONPATH": str(SCRIPTS),
                },
                root,
                launcher.ROLE_TIMEOUT_SECONDS[launcher.ROLE_PREPARE],
                launcher.ROLE_PREPARE,
                "e" * 64,
            )
            self.assertFalse(observation.progress_valid)
            self.assertEqual(
                observation.progress_error, "phase_liveness_pipe_closed"
            )
            self.assertTrue(observation.drain_completed)

            wrong = _observation(
                progress_valid=False,
                progress_complete=False,
                progress_error="phase_liveness_mismatch",
            )
            status, detail, identity, canonical_result = launcher._parse_child(wrong)
            self.assertEqual(status, "indeterminate")
            self.assertIsNone(detail)
            self.assertIsNone(identity)
            self.assertFalse(canonical_result)

    def test_progress_pipe_oversize_and_term_kill_wait_leave_no_orphan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child = root / "oversize.py"
            child.write_text(
                "import os,time\n"
                "import p08_formal_preflight_launcher_v1 as l\n"
                "os.write(int(os.environ[l.PHASE_FD_ENV]),b'x'*(l.MAX_PHASE_STREAM_BYTES+1))\n"
                "time.sleep(5)\n",
                "utf-8",
            )
            with mock.patch.dict(
                launcher.ROLE_TIMEOUT_SECONDS,
                {launcher.ROLE_PREPARE: 2, launcher.ROLE_FORMAL: 3},
                clear=True,
            ):
                oversized = launcher._run_process(
                    [str(launcher.INTERPRETER), str(child)],
                    {
                        "PYTHONDONTWRITEBYTECODE": "1",
                        "PYTHONPATH": str(SCRIPTS),
                    },
                    root,
                    2,
                    launcher.ROLE_PREPARE,
                    "1" * 64,
                )
            self.assertFalse(oversized.progress_valid)
            self.assertEqual(oversized.progress_error, "phase_liveness_oversize")
            self.assertTrue(oversized.drain_completed)

            child.write_text(
                "import signal,time\n"
                "import p08_formal_preflight_launcher_v1 as l\n"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                "l.emit_phase(l.PHASE_STARTUP)\n"
                "time.sleep(5)\n",
                "utf-8",
            )
            with mock.patch.dict(
                launcher.ROLE_TIMEOUT_SECONDS,
                {launcher.ROLE_PREPARE: 2, launcher.ROLE_FORMAL: 3},
                clear=True,
            ), mock.patch.dict(
                launcher.ROLE_NO_PROGRESS_TIMEOUT_SECONDS,
                {launcher.ROLE_PREPARE: 0.2},
                clear=True,
            ), mock.patch.object(
                launcher, "TERMINATION_GRACE_SECONDS", 0.2
            ):
                terminated = launcher._run_process(
                    [str(launcher.INTERPRETER), str(child)],
                    {
                        "PYTHONDONTWRITEBYTECODE": "1",
                        "PYTHONPATH": str(SCRIPTS),
                    },
                    root,
                    2,
                    launcher.ROLE_PREPARE,
                    "2" * 64,
                )
            self.assertEqual(terminated.timeout_class, "no_progress")
            self.assertTrue(terminated.termination_escalated)
            self.assertEqual(terminated.returncode, -signal.SIGKILL)
            self.assertTrue(terminated.drain_completed)
            self.assertIsNotNone(terminated.pid)
            self.assertFalse(Path(f"/proc/{terminated.pid}").exists())


if __name__ == "__main__":
    unittest.main()
