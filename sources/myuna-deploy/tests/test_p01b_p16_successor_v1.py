from __future__ import annotations

import ast
import copy
from hashlib import sha256
import json
import multiprocessing
from pathlib import Path
import tempfile
from types import SimpleNamespace
from typing import Mapping
import unittest
from unittest import mock

import activate_p01b_p16_successor_v1 as activation
import build_p01b_p16_successor_v1 as builder
from p01b_p16_successor_contract_v1 import (
    BUNDLE_SCHEMA,
    MAX_ATTEMPTS,
    P01BSuccessorContractRejected,
    attempt_payload,
    build_bundle,
    build_selector,
    canonical,
    digest,
    marker_payload,
    validate_bundle,
    validate_epoch_anchor_binding,
)


def _hex(character: str, size: int = 64) -> str:
    return character * size


def _artifact(character: str) -> dict[str, object]:
    return {
        "file_count": 1,
        "inventory_digest": _hex(character),
        "release_digest": _hex(character),
    }


def _recovery_evidence() -> tuple[
    dict[str, object], dict[str, object], dict[str, object]
]:
    attempt_unsigned = {
        "schema": activation.ATTEMPT_SCHEMA,
        "attempt": 1,
        "maximum_attempts": 2,
        "bundle_digest": _hex("9"),
        "attempt_series_id": _hex("a"),
        "strategy_id": _hex("b"),
        "lineage_digest": _hex("c"),
        "live_plan_digest": _hex("d"),
        "previous_attempt_digest": None,
        "recorded_at": "2026-08-07T00:00:00Z",
        "content_free": True,
    }
    attempt = {
        **attempt_unsigned,
        "attempt_digest": digest(
            "myuna-p01b-p16-incident-recovery-attempt-v1", attempt_unsigned
        ),
    }
    attempt_bytes = canonical(attempt) + b"\n"
    failure_unsigned = {
        "schema": activation.ACTIVATION_RECEIPT_SCHEMA,
        "status": "hard_stop_rollback_failed",
        "attempt": 1,
        "bundle_digest": attempt["bundle_digest"],
        "live_plan_digest": attempt["live_plan_digest"],
        "failure_stage": "verify_target_before_marker",
        "failure_gate": (
            "target_telegram_telegram_readiness_stability_convergence_timeout"
        ),
        "failure_service_alias": "telegram",
        "failure_phase": "telegram_readiness_stability",
        "rollback": "failed",
        "rollback_gate": "rollback_prestate_rejected",
        "p16_attempt2_consumed": False,
        "legacy_p01b_attempt2_consumed": False,
        "legacy_p01b_attempt2_relabelled": False,
        "p16_lineage_rewritten": False,
        "private_content_read": False,
        "channel_called": False,
        "model_called": False,
        "provider_called": False,
        "health_called": False,
    }
    failure = {
        **failure_unsigned,
        "receipt_digest": digest(
            "myuna-p01b-p16-incident-recovery-receipt-v1", failure_unsigned
        ),
    }
    failure_bytes = canonical(failure) + b"\n"
    recovery = {
        "attempt": 1,
        "maximum_attempts": 2,
        "attempt2_authorized": False,
        "attempt_file_sha256": sha256(attempt_bytes).hexdigest(),
        "attempt_digest": attempt["attempt_digest"],
        "attempt_series_id": attempt["attempt_series_id"],
        "bundle_digest": attempt["bundle_digest"],
        "bundle_manifest_sha256": _hex("e"),
        "strategy_id": attempt["strategy_id"],
        "lineage_digest": attempt["lineage_digest"],
        "live_plan_digest": attempt["live_plan_digest"],
        "failure_receipt_file_sha256": sha256(failure_bytes).hexdigest(),
        "failure_receipt_digest": failure["receipt_digest"],
        "failure_status": failure["status"],
        "failure_stage": failure["failure_stage"],
        "failure_gate": failure["failure_gate"],
        "failure_service_alias": failure["failure_service_alias"],
        "failure_phase": failure["failure_phase"],
        "rollback": failure["rollback"],
        "rollback_gate": failure["rollback_gate"],
        "content_free": True,
    }
    return attempt, failure, recovery


def _bundle() -> dict[str, object]:
    _attempt, _failure, recovery = _recovery_evidence()
    predecessor = {
        "bundle_digest": _hex("a"),
        "bundle_manifest_sha256": _hex("b"),
        "attempt_series_id": _hex("c"),
        "strategy_digest": _hex("d"),
        "attempts": 1,
        "maximum_attempts": 2,
        "activation_receipt_digest": _hex("e"),
        "artifacts": {
            "core": _artifact("1"),
            "p16_adapter": _artifact("2"),
            "telegram_runtime": _artifact("3"),
            "telegram_plugin": _artifact("4"),
        },
        "content_free": True,
    }
    identity = {
        "schema": BUNDLE_SCHEMA,
        "status": "built_inactive",
        "core_source_commit": _hex("1", 40),
        "deploy_source_commit": _hex("2", 40),
        "controller_source_sha256": _hex("f"),
        "predecessor": predecessor,
        "incident_predecessor": {
            "legacy_attempt": 1,
            "legacy_maximum_attempts": 2,
            "legacy_attempt2_prohibited": True,
            "legacy_attempt_file_sha256": _hex("7"),
            "legacy_failure_receipt_file_sha256": _hex("8"),
            "legacy_failure_status": "hard_stop_rollback_failed",
            "legacy_failure_stage": "verify_target_before_marker",
            "legacy_failure_gate": "target_service_inactive",
            "legacy_rollback": "failed",
            "legacy_rollback_gate": "rollback_prestate_rejected",
            "content_free": True,
        },
        "recovery_predecessor": recovery,
        "epoch_anchor": _anchor_binding(),
        "artifacts": {
            "core": _artifact("1"),
            "p16_adapter": _artifact("2"),
            "telegram_runtime": _artifact("5"),
            "telegram_plugin": _artifact("6"),
        },
        "content_free": True,
    }
    return build_bundle(identity)


def _attempt_worker(state_root: str, bundle: dict[str, object], queue) -> None:
    root = Path(state_root)
    with (
        mock.patch.object(activation, "STATE_ROOT", root),
        mock.patch.object(activation, "ATTEMPT_ROOT", root / "attempts"),
        mock.patch.object(activation, "RECEIPT_ROOT", root / "receipts"),
        mock.patch.object(activation, "LOCK_PATH", root / "ATTEMPTS.lock"),
        mock.patch.object(activation, "SELECTOR_PATH", root / "SELECTOR.json"),
        mock.patch.object(activation, "MARKER_PATH", root / "ENABLED.json"),
    ):
        try:
            value = activation._consume_attempt(bundle, _hex("9"))
            queue.put(("ok", value["attempt"]))
        except BaseException as exc:
            queue.put(("error", getattr(exc, "code", type(exc).__name__)))


class _Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


def _service(
    *,
    pid: int = 101,
    invocation: str = "a" * 32,
    active: bool = True,
    restarts: int = 0,
    binding: str = "b" * 64,
) -> dict[str, object]:
    return {
        "active_state": "active" if active else "inactive",
        "sub_state": "running" if active else "dead",
        "result": "success",
        "nrestarts": restarts,
        "pid": pid if active else 0,
        "invocation_id": invocation if active else "",
        "binding_digest": binding,
        "exec_start": "/release/runtime/telegram_owner_runtime_gateway.py",
        "working_directory": "/srv/myuna",
    }


def _readiness(_release_set, observed: Mapping[str, object]) -> dict[str, object]:
    return {
        "schema": "myuna.p07-d-runtime-readiness.v1",
        "generation": 13,
        "release_set_id": _hex("5"),
        "selector_digest": _hex("2"),
        "runtime_config_digest": _hex("3"),
        "epoch_metadata_digest": _hex("4"),
        "pid": observed["pid"],
        "invocation_id": observed["invocation_id"],
        "service_pid": observed["pid"],
        "service_invocation_id": observed["invocation_id"],
    }


def _epoch(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "abandoned_delivery_count": 0,
        "blocked_summary_count": 0,
        "delivered_intent_count": 4,
        "epoch_id": "epoch-v1",
        "max_revision": 5,
        "pending_count": 0,
        "queued_summary_count": 0,
        "release_set_id": _hex("5"),
        "schema": "myuna.external-authorized-epoch.v3",
        "selected_revision": 5,
        "summary_count": 1,
        "turn_count": 4,
    }
    value.update(overrides)
    return value


def _release_set():
    return SimpleNamespace(
        release_set_id=_hex("5"),
        epoch={"epoch_id": "epoch-v1"},
        selector={"digest": _hex("2")},
        runtime_config={"digest": _hex("3")},
    )


def _project_epoch(value: Mapping[str, object] | None = None) -> dict[str, object]:
    return activation._typed_epoch_projection(
        _epoch() if value is None else value,
        expected_epoch_id="epoch-v1",
        expected_release_set_id=_hex("5"),
    )


def _anchor(value: Mapping[str, object] | None = None) -> dict[str, object]:
    checkpoint = activation._epoch_checkpoint(_project_epoch(value))
    unsigned = {
        "accepted_checkpoint": checkpoint,
        "content_free": True,
        "owner_decision_scope": activation.EPOCH_ANCHOR_SCOPE,
        "private_content_included": False,
        "schema": activation.EPOCH_ANCHOR_SCHEMA,
        "source_handoff_sha256": _hex("a"),
        "status": "owner_accepted",
    }
    return {
        **unsigned,
        "anchor_digest": activation.digest(
            "myuna.p01b-p16-incident-recovery-epoch-anchor.v1", unsigned
        ),
    }


def _anchor_binding(value: Mapping[str, object] | None = None) -> dict[str, object]:
    anchor = _anchor(value)
    return validate_epoch_anchor_binding(
        {
            **anchor,
            "anchor_file_sha256": sha256(canonical(anchor) + b"\n").hexdigest(),
        }
    )


def _approved_anchor_document() -> dict[str, object]:
    unsigned = {
        "accepted_checkpoint": dict(builder.OWNER_EPOCH_ANCHOR_CHECKPOINT),
        "content_free": True,
        "owner_decision_scope": activation.EPOCH_ANCHOR_SCOPE,
        "private_content_included": False,
        "schema": activation.EPOCH_ANCHOR_SCHEMA,
        "source_handoff_sha256": builder.OWNER_EPOCH_ANCHOR_SOURCE_HANDOFF_SHA256,
        "status": "owner_accepted",
    }
    return {
        **unsigned,
        "anchor_digest": digest(
            "myuna.p01b-p16-incident-recovery-epoch-anchor.v1", unsigned
        ),
    }


def _generation13_fixture(*, startup_digest: str) -> dict[str, object]:
    release_set = _release_set()
    readiness = _readiness(release_set, _service())
    readiness["epoch_metadata_digest"] = startup_digest
    return {
        "accepted_epoch_anchor": _anchor(),
        "epoch": _project_epoch(),
        "generation13_dropin": {"sha256": _hex("1")},
        "p07_release_set": {"sha256": _hex("2")},
        "p07_selector": {"sha256": _hex("3")},
        "p08": {"release_digest": _hex("4")},
        "readiness": activation._readiness_identity_projection(
            readiness, release_set
        ),
        "runtime_config": {"sha256": _hex("5")},
    }


def _recovery_prestate(generation13: Mapping[str, object]) -> dict[str, object]:
    return {
        "accepted_epoch_anchor": _anchor(),
        "channel_called": False,
        "dynamic_invariants": {
            "container": {"semantic_digest": _hex("1")},
            "generation13": dict(generation13),
            "services": {"telegram": {"active_state": "active"}},
        },
        "health_called": False,
        "legacy_incident": {"attempt": 1},
        "model_called": False,
        "p01b_attempts": 1,
        "p16": {"attempts": 1},
        "private_content_read": False,
        "provider_called": False,
        "recovery_incident": {
            "attempt": 1,
            "attempt_digest": _hex("8"),
            "attempt2_authorized": False,
        },
        "restorable_state": {
            "components": {"core": _hex("6")},
            "files": {"telegram_config": {"sha256": _hex("7")}},
        },
    }


class ContractTests(unittest.TestCase):
    def test_bundle_round_trip_and_determinism(self) -> None:
        first = _bundle()
        second = _bundle()
        self.assertEqual(first, second)
        self.assertEqual(validate_bundle(first), first)
        self.assertEqual(len(first["bundle_digest"]), 64)
        self.assertEqual(first["lineage"]["maximum_attempts"], 2)
        self.assertTrue(first["lineage"]["predecessor_p16_unused_attempt_preserved"])
        self.assertEqual(first["lineage"]["consumed_legacy_p01b_attempt"], 1)
        self.assertEqual(first["lineage"]["consumed_incident_attempts"], 1)
        self.assertEqual(first["lineage"]["remaining_incident_attempts"], 1)
        self.assertFalse(first["lineage"]["attempt_budget_reset"])
        self.assertFalse(first["lineage"]["incident_attempt2_authorized"])
        self.assertEqual(
            first["lineage"]["attempt_series_id"],
            first["recovery_predecessor"]["attempt_series_id"],
        )
        self.assertTrue(first["lineage"]["legacy_p01b_attempt2_prohibited"])
        self.assertEqual(first["epoch_anchor"], _anchor_binding())

    def test_builder_binds_only_exact_owner_approved_anchor(self) -> None:
        exact = _approved_anchor_document()
        self.assertEqual(
            exact["accepted_checkpoint"],
            {
                "abandoned_delivery_count": 0,
                "blocked_summary_count": 0,
                "delivered_intent_count": 51,
                "delivery_in_progress_count": 0,
                "max_revision": 63,
                "metadata_digest": (
                    "4ad4f5f4de7219ee2661ee60d5448c1f53b11334515d353a4fd296914c99eadf"
                ),
                "pending_count": 0,
                "queued_summary_count": 0,
                "selected_revision": 63,
                "summary_count": 12,
                "turn_count": 51,
            },
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "anchor.json"
            path.write_bytes(canonical(exact) + b"\n")
            binding = builder._owner_epoch_anchor(path)
            self.assertEqual(
                binding["anchor_file_sha256"],
                builder.OWNER_EPOCH_ANCHOR_FILE_SHA256,
            )
            self.assertEqual(
                binding["anchor_digest"], builder.OWNER_EPOCH_ANCHOR_DIGEST
            )
            for mutate in (
                lambda value: value["accepted_checkpoint"].update(
                    {
                        "turn_count": 50,
                        "delivered_intent_count": 50,
                        "selected_revision": 62,
                        "max_revision": 62,
                        "metadata_digest": (
                            "180ff7e6283bee6e8bab8bc7c83aacb5bc094910eb3c7290b2551eb7371071e3"
                        ),
                    }
                ),
                lambda value: value["accepted_checkpoint"].update(
                    {
                        "turn_count": 52,
                        "delivered_intent_count": 52,
                        "selected_revision": 64,
                        "max_revision": 64,
                        "metadata_digest": _hex("b"),
                    }
                ),
                lambda value: value["accepted_checkpoint"].update(
                    {"pending_count": 1}
                ),
                lambda value: value.update({"unknown": False}),
            ):
                changed = copy.deepcopy(exact)
                mutate(changed)
                if "unknown" not in changed:
                    unsigned = {
                        key: changed[key]
                        for key in changed
                        if key != "anchor_digest"
                    }
                    changed["anchor_digest"] = digest(
                        "myuna.p01b-p16-incident-recovery-epoch-anchor.v1",
                        unsigned,
                    )
                path.write_bytes(canonical(changed) + b"\n")
                with self.subTest(changed=changed):
                    with self.assertRaises(
                        (P01BSuccessorContractRejected, ValueError)
                    ):
                        builder._owner_epoch_anchor(path)

    def test_bundle_rejects_digest_tamper(self) -> None:
        value = _bundle()
        value["bundle_digest"] = _hex("0")
        with self.assertRaises(P01BSuccessorContractRejected):
            validate_bundle(value)

    def test_bundle_requires_exact_predecessor_core_and_adapter(self) -> None:
        value = _bundle()
        identity = {
            key: item
            for key, item in value.items()
            if key not in {"bundle_digest", "lineage"}
        }
        identity["artifacts"] = dict(identity["artifacts"])
        identity["artifacts"]["core"] = _artifact("7")
        with self.assertRaises(P01BSuccessorContractRejected):
            build_bundle(identity)

    def test_bundle_requires_new_runtime_and_plugin(self) -> None:
        value = _bundle()
        identity = {
            key: item
            for key, item in value.items()
            if key not in {"bundle_digest", "lineage"}
        }
        identity["artifacts"] = dict(identity["predecessor"]["artifacts"])
        with self.assertRaises(P01BSuccessorContractRejected):
            build_bundle(identity)

    def test_selector_explicitly_layers_over_immutable_p16(self) -> None:
        selector = build_selector(_bundle())
        self.assertEqual(selector["predecessor_p16_selector_semantics"], "preserved_immutable_base")
        self.assertTrue(selector["predecessor_p16_unused_attempt_preserved"])
        self.assertEqual(selector["consumed_p01b_attempt"], 1)
        self.assertEqual(selector["remaining_p01b_attempts"], 1)
        self.assertFalse(selector["attempt_budget_reset"])
        self.assertFalse(selector["p01b_attempt2_authorized"])
        self.assertTrue(selector["legacy_p01b_attempt2_prohibited"])
        self.assertEqual(
            selector["epoch_anchor_file_sha256"],
            _anchor_binding()["anchor_file_sha256"],
        )
        self.assertEqual(
            selector["epoch_anchor_digest"], _anchor()["anchor_digest"]
        )
        self.assertTrue(selector["trusted_visual_instruction_separate"])
        self.assertTrue(selector["authenticated_caption_separate"])
        self.assertTrue(selector["untrusted_observation_separate"])
        self.assertFalse(selector["caption_sent_to_gemini_by_default"])
        self.assertEqual(marker_payload(_bundle())["bundle_digest"], _bundle()["bundle_digest"])

    def test_attempt_chain_is_non_resetting(self) -> None:
        bundle = _bundle()
        first, _failure, _recovery = _recovery_evidence()
        second = attempt_payload(
            bundle,
            attempt=2,
            live_plan_digest=_hex("8"),
            previous_attempt_digest=first["attempt_digest"],
            recorded_at="2026-08-07T00:01:00Z",
        )
        self.assertEqual(second["previous_attempt_digest"], first["attempt_digest"])
        self.assertNotEqual(first["attempt_digest"], second["attempt_digest"])
        with self.assertRaises(P01BSuccessorContractRejected):
            attempt_payload(
                bundle,
                attempt=1,
                live_plan_digest=_hex("7"),
                previous_attempt_digest=None,
                recorded_at="2026-08-07T00:02:00Z",
            )

    def test_source_repair_never_resets_incident_series(self) -> None:
        first = _bundle()
        identity = {
            key: copy.deepcopy(value)
            for key, value in first.items()
            if key not in {"bundle_digest", "lineage"}
        }
        identity["deploy_source_commit"] = _hex("3", 40)
        identity["controller_source_sha256"] = _hex("4")
        identity["artifacts"]["telegram_runtime"] = _artifact("7")
        identity["artifacts"]["telegram_plugin"] = _artifact("8")
        repaired = build_bundle(identity)
        self.assertNotEqual(repaired["bundle_digest"], first["bundle_digest"])
        self.assertNotEqual(repaired["lineage"]["strategy_id"], first["lineage"]["strategy_id"])
        self.assertEqual(
            repaired["lineage"]["attempt_series_id"],
            first["recovery_predecessor"]["attempt_series_id"],
        )
        self.assertEqual(repaired["lineage"]["consumed_incident_attempts"], 1)
        self.assertEqual(repaired["lineage"]["remaining_incident_attempts"], 1)

    def test_recovery_predecessor_tamper_fails_closed(self) -> None:
        value = _bundle()
        identity = {
            key: copy.deepcopy(item)
            for key, item in value.items()
            if key not in {"bundle_digest", "lineage"}
        }
        identity["recovery_predecessor"]["attempt2_authorized"] = True
        with self.assertRaises(P01BSuccessorContractRejected):
            build_bundle(identity)

    def test_bundle_epoch_anchor_digest_and_shape_tamper_fail_closed(self) -> None:
        value = _bundle()
        for mutate in (
            lambda anchor: anchor.update({"anchor_digest": _hex("0")}),
            lambda anchor: anchor.update({"unknown": False}),
            lambda anchor: anchor["accepted_checkpoint"].update(
                {"turn_count": True}
            ),
            lambda anchor: anchor["accepted_checkpoint"].update(
                {"pending_count": 1}
            ),
        ):
            identity = {
                key: copy.deepcopy(item)
                for key, item in value.items()
                if key not in {"bundle_digest", "lineage"}
            }
            mutate(identity["epoch_anchor"])
            with self.subTest(anchor=identity["epoch_anchor"]):
                with self.assertRaises(P01BSuccessorContractRejected):
                    build_bundle(identity)

    def test_bundle_anchor_change_never_resets_incident_series(self) -> None:
        first = _bundle()
        later = _epoch(
            delivered_intent_count=5,
            turn_count=5,
            max_revision=6,
            selected_revision=6,
        )
        identity = {
            key: copy.deepcopy(item)
            for key, item in first.items()
            if key not in {"bundle_digest", "lineage"}
        }
        identity["epoch_anchor"] = _anchor_binding(later)
        successor = build_bundle(identity)
        self.assertNotEqual(successor["bundle_digest"], first["bundle_digest"])
        self.assertEqual(
            successor["lineage"]["attempt_series_id"],
            first["lineage"]["attempt_series_id"],
        )
        self.assertEqual(successor["lineage"]["consumed_incident_attempts"], 1)
        self.assertEqual(successor["lineage"]["remaining_incident_attempts"], 1)
        self.assertFalse(successor["lineage"]["attempt_budget_reset"])
        self.assertFalse(successor["lineage"]["incident_attempt2_authorized"])


class AttemptStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "state"
        self.bundle = _bundle()
        self.patches = (
            mock.patch.object(activation, "STATE_ROOT", self.root),
            mock.patch.object(activation, "ATTEMPT_ROOT", self.root / "attempts"),
            mock.patch.object(activation, "RECEIPT_ROOT", self.root / "receipts"),
            mock.patch.object(activation, "LOCK_PATH", self.root / "ATTEMPTS.lock"),
            mock.patch.object(activation, "SELECTOR_PATH", self.root / "SELECTOR.json"),
            mock.patch.object(activation, "MARKER_PATH", self.root / "ENABLED.json"),
        )
        for patch in self.patches:
            patch.start()
        self.recovery_attempt, self.recovery_failure, _recovery = _recovery_evidence()
        self._seed_recovery_state()

    def _seed_recovery_state(self) -> None:
        self.root.mkdir(mode=0o700)
        attempt_root = self.root / "attempts"
        receipt_root = self.root / "receipts"
        attempt_root.mkdir(mode=0o700)
        receipt_root.mkdir(mode=0o700)
        attempt_path = attempt_root / "attempt-0001.json"
        receipt_path = receipt_root / "failure-attempt-0001.json"
        attempt_path.write_bytes(canonical(self.recovery_attempt) + b"\n")
        receipt_path.write_bytes(canonical(self.recovery_failure) + b"\n")
        attempt_path.chmod(0o600)
        receipt_path.chmod(0o600)

    def tearDown(self) -> None:
        for patch in reversed(self.patches):
            patch.stop()
        self.temporary.cleanup()

    def test_preserved_attempt1_then_attempt2_budget_exhausted(self) -> None:
        second = activation._consume_attempt(self.bundle, _hex("8"))
        self.assertEqual(second["attempt"], 2)
        self.assertEqual(
            second["previous_attempt_digest"], self.recovery_attempt["attempt_digest"]
        )
        with self.assertRaisesRegex(activation.P01BActivationRejected, "attempt_budget_exhausted"):
            activation._consume_attempt(self.bundle, _hex("7"))

    def test_replay_does_not_overwrite_either_attempt(self) -> None:
        first_bytes = (self.root / "attempts" / "attempt-0001.json").read_bytes()
        activation._consume_attempt(self.bundle, _hex("9"))
        second_bytes = (self.root / "attempts" / "attempt-0002.json").read_bytes()
        with self.assertRaisesRegex(
            activation.P01BActivationRejected, "attempt_budget_exhausted"
        ):
            activation._consume_attempt(self.bundle, _hex("9"))
        self.assertEqual((self.root / "attempts" / "attempt-0001.json").read_bytes(), first_bytes)
        self.assertEqual((self.root / "attempts" / "attempt-0002.json").read_bytes(), second_bytes)
        self.assertEqual(
            json.loads(first_bytes)["attempt_digest"],
            self.recovery_attempt["attempt_digest"],
        )

    def test_partial_or_unknown_state_fails_closed(self) -> None:
        (self.root / "attempts" / "unexpected.json").write_text("{}", encoding="ascii")
        with self.assertRaisesRegex(activation.P01BActivationRejected, "attempt_state_partial"):
            activation._attempt_rows(self.bundle)

    def test_digest_tamper_fails_closed(self) -> None:
        path = self.root / "attempts" / "attempt-0001.json"
        value = json.loads(path.read_bytes())
        value["live_plan_digest"] = _hex("0")
        path.write_bytes(canonical(value) + b"\n")
        with self.assertRaisesRegex(activation.P01BActivationRejected, "recovery_attempt_rejected"):
            activation._attempt_rows(self.bundle)

    def test_acl_drift_fails_closed(self) -> None:
        path = self.root / "attempts" / "attempt-0001.json"
        path.chmod(0o644)
        with self.assertRaisesRegex(Exception, "attempt_state_rejected"):
            activation._attempt_rows(self.bundle)

    @unittest.skipUnless(hasattr(multiprocessing, "get_context"), "multiprocessing unavailable")
    def test_concurrent_consumers_serialize(self) -> None:
        for patch in reversed(self.patches):
            patch.stop()
        self.patches = ()
        context = multiprocessing.get_context("fork")
        queue = context.Queue()
        processes = [
            context.Process(target=_attempt_worker, args=(str(self.root), self.bundle, queue))
            for _ in range(2)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(10)
            self.assertEqual(process.exitcode, 0)
        results = sorted(queue.get(timeout=2) for _ in processes)
        self.assertEqual(results, [("error", "attempt_budget_exhausted"), ("ok", 2)])

    def test_recovery_failure_receipt_is_exactly_bound(self) -> None:
        rows = activation._attempt_rows(self.bundle)
        projection = activation._verify_recovery_incident(self.bundle, rows[0])
        self.assertEqual(projection["attempt"], 1)
        self.assertFalse(projection["attempt2_authorized"])
        path = self.root / "receipts" / "failure-attempt-0001.json"
        tampered = json.loads(path.read_bytes())
        tampered["failure_phase"] = "other"
        path.write_bytes(canonical(tampered) + b"\n")
        with self.assertRaisesRegex(
            activation.P01BActivationRejected,
            "recovery_failure_receipt_rejected",
        ):
            activation._verify_recovery_incident(self.bundle, rows[0])

    def test_missing_predecessor_attempt_never_resets_series(self) -> None:
        path = self.root / "attempts" / "attempt-0001.json"
        path.unlink()
        with self.assertRaisesRegex(
            activation.P01BActivationRejected,
            "recovery_attempt_lineage_rejected",
        ):
            activation._consume_attempt(self.bundle, _hex("9"))
        self.assertFalse(path.exists())
        self.assertFalse((self.root / "attempts" / "attempt-0002.json").exists())


class PhaseAwareAttemptLineageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.bundle = _bundle()
        self.first, _failure, _recovery = _recovery_evidence()
        executor = Path(self.temporary.name) / "executor.py"
        executor.write_text("# synthetic\n", encoding="ascii")
        self.prestate = _recovery_prestate(
            _generation13_fixture(startup_digest=_hex("4"))
        )
        self.plan = activation._plan(self.bundle, self.prestate, executor)
        self.second = attempt_payload(
            self.bundle,
            attempt=2,
            live_plan_digest=self.plan["live_plan_digest"],
            previous_attempt_digest=self.first["attempt_digest"],
            recorded_at="2026-08-07T01:00:00Z",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _resign_plan(self, value: Mapping[str, object]) -> dict[str, object]:
        unsigned = {key: copy.deepcopy(item) for key, item in value.items() if key != "live_plan_digest"}
        return {
            **unsigned,
            "live_plan_digest": activation.digest(
                "myuna-p01b-p16-incident-recovery-live-plan-v1", unsigned
            ),
        }

    def _second_for_plan(self, plan: Mapping[str, object]) -> dict[str, object]:
        return attempt_payload(
            self.bundle,
            attempt=2,
            live_plan_digest=str(plan["live_plan_digest"]),
            previous_attempt_digest=str(self.first["attempt_digest"]),
            recorded_at="2026-08-07T01:00:00Z",
        )

    def test_pre_attempt_phase_accepts_only_exact_one(self) -> None:
        accepted = activation._require_attempt_phase_lineage(
            self.bundle,
            [self.first],
            phase=activation.PRE_ATTEMPT_CAPTURE_PHASE,
        )
        self.assertEqual(accepted["attempts"], 1)
        for attempts in (
            [],
            [self.first, self.second],
            [self.first, self.second, self.second],
        ):
            with self.subTest(count=len(attempts)):
                with self.assertRaisesRegex(
                    activation.P01BActivationRejected,
                    "recovery_attempt_lineage_rejected",
                ):
                    activation._require_attempt_phase_lineage(
                        self.bundle,
                        list(attempts),
                        phase=activation.PRE_ATTEMPT_CAPTURE_PHASE,
                    )

    def test_post_attempt_phase_accepts_only_exact_bound_second(self) -> None:
        accepted = activation._require_attempt_phase_lineage(
            self.bundle,
            [self.first, self.second],
            phase=activation.POST_ATTEMPT_ROLLBACK_PHASE,
            rollback_plan=self.plan,
        )
        self.assertEqual(accepted["attempts"], 2)
        self.assertEqual(accepted["live_plan_digest"], self.plan["live_plan_digest"])

    def test_post_attempt_rejects_missing_third_and_attempt_field_drift(self) -> None:
        for attempts in (
            [self.first],
            [self.first, self.second, self.second],
        ):
            with self.subTest(count=len(attempts)):
                with self.assertRaises(activation.P01BActivationRejected):
                    activation._require_attempt_phase_lineage(
                        self.bundle,
                        list(attempts),
                        phase=activation.POST_ATTEMPT_ROLLBACK_PHASE,
                        rollback_plan=self.plan,
                    )
        for field, replacement in (
            ("attempt", 3),
            ("attempt_series_id", _hex("0")),
            ("previous_attempt_digest", _hex("0")),
            ("live_plan_digest", _hex("0")),
            ("maximum_attempts", 3),
        ):
            changed = {**self.second, field: replacement}
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    activation.P01BActivationRejected,
                    "recovery_attempt_lineage_rejected",
                ):
                    activation._require_attempt_phase_lineage(
                        self.bundle,
                        [self.first, changed],
                        phase=activation.POST_ATTEMPT_ROLLBACK_PHASE,
                        rollback_plan=self.plan,
                    )

    def test_post_attempt_rejects_plan_and_prestate_drift_against_bound_attempt(self) -> None:
        for mutate in (
            lambda value: value.update({"next_attempt": 3}),
            lambda value: value["prestate"].update({"p01b_attempts": 0}),
            lambda value: value["prestate"]["restorable_state"]["files"].update(
                {"telegram_config": {"sha256": _hex("0")}}
            ),
        ):
            changed = copy.deepcopy(self.plan)
            mutate(changed)
            with self.assertRaises(activation.P01BActivationRejected):
                activation._require_attempt_phase_lineage(
                    self.bundle,
                    [self.first, self.second],
                    phase=activation.POST_ATTEMPT_ROLLBACK_PHASE,
                    rollback_plan=changed,
                )

    def test_reset_new_series_p16_and_legacy_consumption_reject(self) -> None:
        for field, replacement in (
            ("attempt_budget_reset", True),
            ("attempt_series_id", _hex("0")),
            ("predecessor_p16_attempts", 2),
            ("predecessor_p16_unused_attempt_preserved", False),
            ("legacy_p01b_attempt2_prohibited", False),
            ("incident_attempt2_authorized", True),
        ):
            changed = copy.deepcopy(self.bundle)
            changed["lineage"] = {**changed["lineage"], field: replacement}
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    activation.P01BActivationRejected,
                    "recovery_attempt_lineage_rejected",
                ):
                    activation._require_attempt_phase_lineage(
                        changed,
                        [self.first, self.second],
                        phase=activation.POST_ATTEMPT_ROLLBACK_PHASE,
                        rollback_plan=self.plan,
                    )

    def test_plan_boundaries_cannot_relabel_p16_or_legacy_attempt2(self) -> None:
        for field in (
            "p16_lineage_consumed_or_rewritten",
            "legacy_p01b_attempt2_consumed_or_relabelled",
            "incident_attempt_budget_reset",
        ):
            changed = copy.deepcopy(self.plan)
            changed["boundaries"] = {**changed["boundaries"], field: True}
            changed = self._resign_plan(changed)
            second = self._second_for_plan(changed)
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    activation.P01BActivationRejected,
                    "rollback_attempt_plan_rejected",
                ):
                    activation._require_attempt_phase_lineage(
                        self.bundle,
                        [self.first, second],
                        phase=activation.POST_ATTEMPT_ROLLBACK_PHASE,
                        rollback_plan=changed,
                    )

    def test_phase_or_plan_bypass_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            activation.P01BActivationRejected, "attempt_phase_rejected"
        ):
            activation._require_attempt_phase_lineage(
                self.bundle,
                [self.first, self.second],
                phase="optional",
                rollback_plan=self.plan,
            )
        with self.assertRaisesRegex(
            activation.P01BActivationRejected,
            "recovery_attempt_lineage_rejected",
        ):
            activation._require_attempt_phase_lineage(
                self.bundle,
                [self.first],
                phase=activation.PRE_ATTEMPT_CAPTURE_PHASE,
                rollback_plan=self.plan,
            )

    def test_historical_attempt_and_failure_receipt_bytes_are_not_rewritten(self) -> None:
        attempt_path = Path(self.temporary.name) / "attempt-0002.json"
        receipt_path = Path(self.temporary.name) / "failure-attempt-0002.json"
        attempt_path.write_bytes(canonical(self.second) + b"\n")
        receipt = {
            "status": "hard_stop_rollback_failed",
            "rollback_gate": "recovery_attempt_lineage_rejected",
        }
        receipt_path.write_bytes(canonical(receipt) + b"\n")
        before = (attempt_path.read_bytes(), receipt_path.read_bytes())
        activation._require_attempt_phase_lineage(
            self.bundle,
            [self.first, self.second],
            phase=activation.POST_ATTEMPT_ROLLBACK_PHASE,
            rollback_plan=self.plan,
        )
        self.assertEqual(
            (attempt_path.read_bytes(), receipt_path.read_bytes()), before
        )


class RecoveryOracleTests(unittest.TestCase):
    def test_service_alias_and_phase_survive_p16_exception_translation(self) -> None:
        with mock.patch.object(
            activation.p16,
            "_service_projection",
            side_effect=activation.p16.P16Phase1T2Rejected("target_service_inactive"),
        ):
            with self.assertRaises(activation.P01BActivationRejected) as raised:
                activation._stable_service("telegram", phase="initial_service_snapshot")
        self.assertEqual(raised.exception.service_alias, "telegram")
        self.assertEqual(raised.exception.phase, "initial_service_snapshot")
        self.assertIn("target_service_inactive", raised.exception.code)

    def test_socket_active_never_masks_inactive_telegram_service(self) -> None:
        def projection(unit: str, *, socket: bool = False) -> dict[str, object]:
            if unit == activation.p16.TELEGRAM_SERVICE:
                return _service(active=False)
            return _service()

        with mock.patch.object(activation.p16, "_service_projection", side_effect=projection):
            with self.assertRaises(activation.P01BActivationRejected) as raised:
                activation._stable_service("telegram", phase="initial_service_snapshot")
        self.assertEqual(raised.exception.service_alias, "telegram")

    def test_restart_delay_then_new_stable_identity_converges(self) -> None:
        clock = _Clock()

        def observe() -> dict[str, object]:
            if clock.value < 1:
                return _service(pid=101, invocation="a" * 32)
            if clock.value < 6:
                return _service(active=False)
            return _service(pid=202, invocation="c" * 32)

        result = activation._wait_telegram_convergence(
            _release_set(),
            expected_binding_digest="b" * 64,
            observe=observe,
            readiness_probe=_readiness,
            timeout_seconds=20,
            poll_seconds=0.5,
            stable_seconds=10,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )
        self.assertEqual(result["pid"], 202)
        self.assertEqual(result["nrestarts"], 0)
        self.assertGreaterEqual(result["stable_seconds"], 10)

    def test_pid_swap_after_readiness_fails_closed(self) -> None:
        clock = _Clock()

        def observe() -> dict[str, object]:
            if clock.value < 6:
                return _service(pid=101, invocation="a" * 32)
            return _service(pid=202, invocation="c" * 32)

        with self.assertRaisesRegex(
            activation.P01BActivationRejected,
            "identity_drifted_after_readiness",
        ):
            activation._wait_telegram_convergence(
                _release_set(),
                expected_binding_digest="b" * 64,
                observe=observe,
                readiness_probe=_readiness,
                timeout_seconds=20,
                poll_seconds=0.5,
                stable_seconds=10,
                monotonic=clock.monotonic,
                sleep=clock.sleep,
            )

    def test_restart_counter_never_passes_zero_restart_oracle(self) -> None:
        clock = _Clock()
        with self.assertRaises(activation.P01BActivationRejected) as raised:
            activation._wait_telegram_convergence(
                object(),
                expected_binding_digest="b" * 64,
                observe=lambda: _service(restarts=1),
                readiness_probe=_readiness,
                timeout_seconds=10,
                poll_seconds=1,
                stable_seconds=10,
                monotonic=clock.monotonic,
                sleep=clock.sleep,
            )
        self.assertEqual(raised.exception.service_alias, "telegram")
        self.assertEqual(raised.exception.phase, "telegram_readiness_stability")

    def test_binding_drift_fails_without_convergence(self) -> None:
        clock = _Clock()
        with self.assertRaisesRegex(activation.P01BActivationRejected, "binding_drifted"):
            activation._wait_telegram_convergence(
                object(),
                expected_binding_digest="b" * 64,
                observe=lambda: _service(binding="c" * 64),
                readiness_probe=_readiness,
                timeout_seconds=10,
                poll_seconds=1,
                stable_seconds=10,
                monotonic=clock.monotonic,
                sleep=clock.sleep,
            )

    def test_persistent_stale_readiness_has_typed_timeout(self) -> None:
        clock = _Clock()

        def stale(_release_set, observed: Mapping[str, object]) -> dict[str, object]:
            value = _readiness(_release_set, observed)
            value["pid"] = 999
            value["invocation_id"] = "f" * 32
            return value

        with self.assertRaisesRegex(
            activation.P01BActivationRejected,
            "convergence_timeout_readiness_process_mismatch",
        ):
            activation._wait_telegram_convergence(
                _release_set(),
                expected_binding_digest="b" * 64,
                observe=_service,
                readiness_probe=stale,
                timeout_seconds=10,
                poll_seconds=1,
                stable_seconds=10,
                monotonic=clock.monotonic,
                sleep=clock.sleep,
            )

    def test_readiness_unknown_field_and_wrong_type_fail_closed(self) -> None:
        for mutate, expected in (
            (lambda value: value.update({"unknown": "x"}), "shape_rejected"),
            (lambda value: value.update({"pid": True}), "type_rejected"),
        ):
            clock = _Clock()

            def probe(
                release_set, observed: Mapping[str, object], *, selected=mutate
            ) -> dict[str, object]:
                value = _readiness(release_set, observed)
                selected(value)
                return value

            with self.subTest(expected=expected):
                with self.assertRaisesRegex(
                    activation.P01BActivationRejected, expected
                ):
                    activation._wait_telegram_convergence(
                        _release_set(),
                        expected_binding_digest="b" * 64,
                        observe=_service,
                        readiness_probe=probe,
                        timeout_seconds=10,
                        poll_seconds=1,
                        stable_seconds=10,
                        monotonic=clock.monotonic,
                        sleep=clock.sleep,
                    )

    def test_inactive_service_remains_bounded_by_overall_timeout(self) -> None:
        clock = _Clock()
        with self.assertRaisesRegex(
            activation.P01BActivationRejected,
            "convergence_timeout_service_not_active",
        ):
            activation._wait_telegram_convergence(
                _release_set(),
                expected_binding_digest="b" * 64,
                observe=lambda: _service(active=False),
                readiness_probe=_readiness,
                timeout_seconds=10,
                poll_seconds=1,
                stable_seconds=10,
                monotonic=clock.monotonic,
                sleep=clock.sleep,
            )
        self.assertGreaterEqual(clock.value, 10)

    def test_service_observation_unknown_field_fails_closed(self) -> None:
        clock = _Clock()

        def observe() -> dict[str, object]:
            return {**_service(), "unknown": "x"}

        with self.assertRaisesRegex(
            activation.P01BActivationRejected,
            "service_observation_shape_rejected",
        ):
            activation._wait_telegram_convergence(
                _release_set(),
                expected_binding_digest="b" * 64,
                observe=observe,
                readiness_probe=_readiness,
                timeout_seconds=10,
                poll_seconds=1,
                stable_seconds=10,
                monotonic=clock.monotonic,
                sleep=clock.sleep,
            )

    def test_epoch_metadata_requires_typed_quiescence(self) -> None:
        projected = _project_epoch()
        self.assertTrue(projected["quiescent"])
        with self.assertRaisesRegex(activation.P01BActivationRejected, "epoch_not_quiescent"):
            _project_epoch(_epoch(pending_count=1))
        with self.assertRaisesRegex(activation.P01BActivationRejected, "epoch_metadata_rejected"):
            _project_epoch(_epoch(turn_count=True))

    def test_epoch_identity_and_unknown_fields_fail_closed(self) -> None:
        with self.assertRaisesRegex(activation.P01BActivationRejected, "epoch_identity_rejected"):
            activation._typed_epoch_projection(
                _epoch(epoch_id="wrong"),
                expected_epoch_id="epoch-v1",
                expected_release_set_id=_hex("5"),
            )
        unknown = {**_epoch(), "unexpected": 0}
        with self.assertRaisesRegex(activation.P01BActivationRejected, "epoch_metadata_rejected"):
            _project_epoch(unknown)

    def test_revision_delivery_and_all_unresolved_states_fail_closed(self) -> None:
        invalid = (
            _epoch(selected_revision=4),
            _epoch(delivered_intent_count=3),
            _epoch(abandoned_delivery_count=1),
            _epoch(queued_summary_count=1),
            _epoch(blocked_summary_count=1),
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    activation.P01BActivationRejected, "epoch_not_quiescent"
                ):
                    _project_epoch(value)

    def test_two_epoch_observations_must_be_identical(self) -> None:
        values = iter(
            (
                _epoch(),
                _epoch(
                    delivered_intent_count=5,
                    turn_count=5,
                    max_revision=6,
                    selected_revision=6,
                ),
            )
        )
        with self.assertRaisesRegex(activation.P01BActivationRejected, "epoch_not_quiescent"):
            activation._quiescent_epoch_projection(
                _release_set(),
                reader=lambda _release: next(values),
                sleep=lambda _seconds: None,
            )

    def test_stale_startup_epoch_digest_is_identity_evidence_only(self) -> None:
        release_set = _release_set()
        readiness = _readiness(release_set, _service())
        projected = activation._readiness_identity_projection(readiness, release_set)
        self.assertEqual(projected["startup_epoch_metadata_digest"], _hex("4"))
        self.assertEqual(
            projected["epoch_digest_semantics"],
            "startup_observation_only_not_current_epoch_gate",
        )
        self.assertNotIn("current_epoch_metadata_digest", projected)

    def test_generation13_accepts_stale_startup_digest_only_with_exact_anchor(self) -> None:
        predecessor = {
            "compatibility": {
                "p07_release_set_id": _hex("5"),
                "p08_plan_digest": _hex("7"),
            },
            "generation13_base": {
                "p08_release_digest": _hex("6"),
            },
        }
        release_set = _release_set()
        current = _project_epoch()
        readiness = _readiness(release_set, _service())
        with (
            mock.patch.object(activation.p16, "_p07_snapshot", return_value=release_set),
            mock.patch.object(activation.p16, "_p08_selection", return_value={"p08": True}),
            mock.patch.object(activation.p16, "_file_projection", return_value={"file": True}),
            mock.patch.object(
                activation, "_quiescent_epoch_projection", return_value=current
            ),
        ):
            result = activation._generation13_projection(
                predecessor,
                accepted_epoch_anchor=_anchor(),
                readiness_override=readiness,
            )
            self.assertEqual(
                result["readiness"]["startup_epoch_metadata_digest"], _hex("4")
            )
            earlier = _epoch(
                delivered_intent_count=3,
                turn_count=3,
                summary_count=1,
                selected_revision=4,
                max_revision=4,
            )
            with self.assertRaisesRegex(
                activation.P01BActivationRejected, "epoch_anchor_mismatch"
            ):
                activation._generation13_projection(
                    predecessor,
                    accepted_epoch_anchor=_anchor(earlier),
                    readiness_override=readiness,
                )

    def test_exact_anchor_passes_and_earlier_anchor_rejects(self) -> None:
        current = _project_epoch()
        activation._require_epoch_anchor(current, _anchor())
        earlier = _epoch(
            delivered_intent_count=3,
            turn_count=3,
            summary_count=1,
            selected_revision=4,
            max_revision=4,
        )
        with self.assertRaisesRegex(
            activation.P01BActivationRejected, "epoch_anchor_mismatch"
        ):
            activation._require_epoch_anchor(current, _anchor(earlier))

    def test_post_restart_generation_accepts_only_startup_refresh(self) -> None:
        expected = _generation13_fixture(startup_digest=_hex("4"))
        current = _generation13_fixture(
            startup_digest=str(expected["epoch"]["metadata_digest"])
        )
        activation._require_post_restart_generation13_convergence(
            current, expected, code="generation13_changed"
        )
        drifted = dict(current)
        drifted["readiness"] = dict(current["readiness"])
        drifted["readiness"]["runtime_config_digest"] = _hex("9")
        with self.assertRaisesRegex(
            activation.P01BActivationRejected, "generation13_changed"
        ):
            activation._require_post_restart_generation13_convergence(
                drifted, expected, code="generation13_changed"
            )

    def test_post_restart_startup_digest_must_equal_current_epoch(self) -> None:
        expected = _generation13_fixture(startup_digest=_hex("4"))
        current = _generation13_fixture(startup_digest=_hex("8"))
        with self.assertRaisesRegex(
            activation.P01BActivationRejected,
            "post_restart_startup_epoch_drifted",
        ):
            activation._require_post_restart_generation13_convergence(
                current, expected, code="generation13_changed"
            )

    def test_generation13_unknown_readiness_field_fails_closed(self) -> None:
        expected = _generation13_fixture(startup_digest=_hex("4"))
        current = _generation13_fixture(
            startup_digest=str(expected["epoch"]["metadata_digest"])
        )
        current["readiness"] = {**current["readiness"], "unknown": "x"}
        with self.assertRaisesRegex(
            activation.P01BActivationRejected,
            "generation13_readiness_shape_rejected",
        ):
            activation._require_post_restart_generation13_convergence(
                current, expected, code="generation13_changed"
            )

    def test_generation13_unknown_epoch_field_and_digest_tamper_fail_closed(self) -> None:
        expected = _generation13_fixture(startup_digest=_hex("4"))
        current = _generation13_fixture(
            startup_digest=str(expected["epoch"]["metadata_digest"])
        )
        for mutate, expected_code in (
            (
                lambda value: value["epoch"].update({"unknown": False}),
                "generation13_readiness_shape_rejected",
            ),
            (
                lambda value: value["epoch"].update(
                    {"metadata_digest": _hex("9")}
                ),
                "generation13_epoch_projection_rejected",
            ),
        ):
            changed = copy.deepcopy(current)
            mutate(changed)
            with self.subTest(expected_code=expected_code):
                with self.assertRaisesRegex(
                    activation.P01BActivationRejected, expected_code
                ):
                    activation._require_post_restart_generation13_convergence(
                        changed, expected, code="generation13_changed"
                    )

    def test_rollback_normalization_preserves_bytes_and_stable_semantics(self) -> None:
        expected_generation = _generation13_fixture(startup_digest=_hex("4"))
        current_generation = _generation13_fixture(
            startup_digest=str(expected_generation["epoch"]["metadata_digest"])
        )
        expected = _recovery_prestate(expected_generation)
        current = _recovery_prestate(current_generation)
        self.assertEqual(
            activation._normalized_recovery_prestate(
                current, require_fresh_startup_epoch=True
            ),
            activation._normalized_recovery_prestate(
                expected, require_fresh_startup_epoch=False
            ),
        )
        current["restorable_state"] = {
            **current["restorable_state"],
            "files": {"telegram_config": {"sha256": _hex("0")}},
        }
        self.assertNotEqual(
            activation._normalized_recovery_prestate(
                current, require_fresh_startup_epoch=True
            ),
            activation._normalized_recovery_prestate(
                expected, require_fresh_startup_epoch=False
            ),
        )

    def test_rollback_convergence_rejects_each_stable_or_byte_lane_drift(self) -> None:
        expected_generation = _generation13_fixture(startup_digest=_hex("4"))
        current_generation = _generation13_fixture(
            startup_digest=str(expected_generation["epoch"]["metadata_digest"])
        )
        expected = _recovery_prestate(expected_generation)
        current = _recovery_prestate(current_generation)
        expected["p01b_attempts"] = current["p01b_attempts"] = 2
        activation._require_rollback_prestate_convergence(current, expected)

        mutations = (
            lambda value: value["restorable_state"]["files"].update(
                {"telegram_config": {"sha256": _hex("0")}}
            ),
            lambda value: value["dynamic_invariants"]["services"]["telegram"].update(
                {"active_state": "inactive"}
            ),
            lambda value: value["dynamic_invariants"]["container"].update(
                {"semantic_digest": _hex("0")}
            ),
            lambda value: value["dynamic_invariants"]["generation13"]["readiness"].update(
                {"runtime_config_digest": _hex("0")}
            ),
            lambda value: value["dynamic_invariants"]["generation13"].update(
                {
                    "epoch": _project_epoch(
                        _epoch(
                            delivered_intent_count=5,
                            turn_count=5,
                            max_revision=6,
                            selected_revision=6,
                        )
                    )
                }
            ),
        )
        for mutate in mutations:
            changed = copy.deepcopy(current)
            mutate(changed)
            with self.assertRaises(activation.P01BActivationRejected):
                activation._require_rollback_prestate_convergence(
                    changed, expected
                )

    def test_rollback_unknown_prestate_field_fails_closed(self) -> None:
        generation = _generation13_fixture(startup_digest=_hex("4"))
        value = {**_recovery_prestate(generation), "unknown": False}
        with self.assertRaisesRegex(
            activation.P01BActivationRejected,
            "rollback_prestate_shape_rejected",
        ):
            activation._normalized_recovery_prestate(
                value, require_fresh_startup_epoch=False
            )

    def test_anchor_unknown_type_and_digest_tamper_fail_closed(self) -> None:
        unknown = {**_anchor(), "unexpected": False}
        with self.assertRaisesRegex(
            activation.P01BActivationRejected, "epoch_anchor_rejected"
        ):
            activation._validate_epoch_anchor(unknown)
        wrong_type = _anchor()
        wrong_type["accepted_checkpoint"] = {
            **wrong_type["accepted_checkpoint"],
            "turn_count": True,
        }
        with self.assertRaisesRegex(
            activation.P01BActivationRejected, "epoch_anchor_rejected"
        ):
            activation._validate_epoch_anchor(wrong_type)
        tampered = {**_anchor(), "anchor_digest": _hex("0")}
        with self.assertRaisesRegex(
            activation.P01BActivationRejected, "epoch_anchor_digest_rejected"
        ):
            activation._validate_epoch_anchor(tampered)

    def test_bundle_accepts_only_its_exact_owner_anchor(self) -> None:
        bundle = _bundle()
        self.assertEqual(
            activation._require_bundle_epoch_anchor(bundle, _anchor()),
            _anchor(),
        )
        later = _epoch(
            delivered_intent_count=5,
            turn_count=5,
            max_revision=6,
            selected_revision=6,
        )
        with self.assertRaisesRegex(
            activation.P01BActivationRejected, "bundle_epoch_anchor_rejected"
        ):
            activation._require_bundle_epoch_anchor(bundle, _anchor(later))

    def test_bundle_anchor_file_hash_is_exact(self) -> None:
        bundle = _bundle()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "anchor.json"
            path.write_bytes(canonical(_anchor()) + b"\n")
            activation._require_bundle_epoch_anchor(
                bundle, _anchor(), source_path=path
            )
            path.write_bytes(canonical(_anchor()) + b"\n\n")
            with self.assertRaisesRegex(
                activation.P01BActivationRejected,
                "bundle_epoch_anchor_rejected",
            ):
                activation._require_bundle_epoch_anchor(
                    bundle, _anchor(), source_path=path
                )

    def test_anchor_is_explicitly_plan_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executor = Path(temporary) / "executor.py"
            executor.write_text("# synthetic\n", encoding="ascii")
            prestate = {"accepted_epoch_anchor": _anchor(), "p01b_attempts": 0}
            plan = activation._plan(_bundle(), prestate, executor)
        self.assertEqual(plan["accepted_epoch_anchor"], prestate["accepted_epoch_anchor"])
        self.assertEqual(
            plan["prestate"]["accepted_epoch_anchor"], prestate["accepted_epoch_anchor"]
        )


class CrashRollbackMatrixTests(unittest.TestCase):
    def _run_crash(self, point: str) -> tuple[bool, str]:
        bundle = _bundle()
        plan = {
            "live_plan_digest": _hex("9"),
            "prestate": {},
        }
        context = {
            "bundle": bundle,
            "artifacts": {
                "core": Path("/candidate/core"),
                "telegram_runtime": Path("/candidate/runtime"),
            },
        }
        captured: dict[str, object] = {}
        rollback_called = False
        atomic_calls = 0
        target_calls = 0

        def crash(code: str = "synthetic_crash") -> None:
            raise activation.P01BActivationRejected(code)

        def systemctl(*arguments: str, **_kwargs: object) -> None:
            if point == "stop_telegram" and arguments[0] == "stop":
                crash()

        def atomic_write(*_args: object, **_kwargs: object) -> None:
            nonlocal atomic_calls
            atomic_calls += 1
            if point == "select_runtime_plugin_overlay" and atomic_calls == 1:
                crash()
            if point == "enable_marker_last" and atomic_calls == 3:
                crash()

        def target(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal target_calls
            target_calls += 1
            if point == "verify_target_before_marker" and target_calls == 1:
                crash()
            if point == "verify_enabled_target" and target_calls == 2:
                crash()
            return {"target": True}

        def restore(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal rollback_called
            rollback_called = True
            return {"rollback": "verified"}

        def receipt(_root: Path, _name: str, payload: Mapping[str, object]) -> Path:
            captured.update(payload)
            return Path("receipt.json")

        patches = (
            mock.patch.object(activation, "prepare_live", return_value=(context, plan)),
            mock.patch.object(activation, "_create_backup", return_value=Path("/backup")),
            mock.patch.object(activation, "_consume_attempt", return_value={"attempt": 1, "attempt_digest": _hex("8")}),
            mock.patch.object(activation, "_install_targets", side_effect=(lambda *_: crash()) if point == "install_artifacts" else None),
            mock.patch.object(activation, "_write_selector", side_effect=(lambda *_: crash()) if point == "write_selector" else None),
            mock.patch.object(activation.p16, "_systemctl", side_effect=systemctl),
            mock.patch.object(activation.p16, "_atomic_write", side_effect=atomic_write),
            mock.patch.object(activation.p07, "run_resume_controller", side_effect=(lambda: crash()) if point == "resume_controller" else None),
            mock.patch.object(activation, "_restore_service_states", side_effect=(lambda *_: crash()) if point == "restore_service_states" else None),
            mock.patch.object(activation, "_target_projection", side_effect=target),
            mock.patch.object(activation, "_restore_prestate", side_effect=restore),
            mock.patch.object(activation, "_write_receipt", side_effect=receipt),
            mock.patch.object(activation.time, "monotonic", side_effect=(iter((0.0, 121.0)) if point == "verify_target_before_marker" else activation.time.monotonic)),
            mock.patch.object(activation.time, "sleep", return_value=None),
        )
        for patch in patches:
            patch.start()
        try:
            with self.assertRaises(activation.P01BActivationRejected):
                activation.activate(
                    bundle_root=Path("/bundle"),
                    predecessor_bundle_root=Path("/predecessor"),
                    core_source_root=Path("/core-source"),
                    deploy_source_root=Path("/deploy-source"),
                    accepted_epoch_anchor_path=Path("/accepted-anchor"),
                    expected_live_plan_digest=_hex("9"),
                    confirmation=f"ACTIVATE:{_hex('9')}",
                )
        finally:
            for patch in reversed(patches):
                patch.stop()
        return rollback_called, str(captured.get("failure_stage", ""))

    def test_every_live_mutation_crash_is_rollback_bound(self) -> None:
        points = {
            "write_selector": "write_selector",
            "stop_telegram": "stop_telegram",
            "select_runtime_plugin_overlay": "select_runtime_plugin_overlay",
            "resume_controller": "resume_controller",
            "restore_service_states": "restore_service_states",
            "verify_target_before_marker": "verify_target_before_marker",
            "enable_marker_last": "enable_marker_last",
            "verify_enabled_target": "verify_enabled_target",
        }
        for point, stage in points.items():
            with self.subTest(point=point):
                rollback, observed_stage = self._run_crash(point)
                self.assertTrue(rollback)
                self.assertEqual(observed_stage, stage)

    def test_immutable_install_crash_needs_no_rollback(self) -> None:
        rollback, stage = self._run_crash("install_artifacts")
        self.assertFalse(rollback)
        self.assertEqual(stage, "install_artifacts")


class PrivacyAndRollbackStructureTests(unittest.TestCase):
    def test_controller_has_no_forbidden_active_probe_or_private_reader(self) -> None:
        source = Path(activation.__file__).read_text("utf-8")
        tree = ast.parse(source)
        self.assertNotIn("/healthz", source)
        self.assertNotIn("/readyz", source)
        self.assertNotIn("sqlite3", source)
        self.assertNotIn("requests.", source)
        self.assertNotIn("httpx.", source)
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        self.assertNotIn("message_text", names)
        self.assertNotIn("provider_payload", names)
        self.assertNotIn("profile_row", names)

    def test_preflight_public_projection_is_fixed_and_content_free(self) -> None:
        source = Path(activation.__file__).read_text("utf-8")
        for field in (
            '"mutation_performed": False',
            '"private_content_read": False',
            '"channel_called": False',
            '"model_called": False',
            '"provider_called": False',
            '"health_called": False',
            '"p16_attempt2_consumed": False',
        ):
            self.assertIn(field, source)
        self.assertIn('parser.add_argument("--accepted-epoch-anchor", type=Path)', source)
        self.assertNotIn('"epoch_readiness_digest_mismatch"', source)

    def test_anchor_contract_contains_no_private_payload_fields(self) -> None:
        anchor = _anchor()
        serialized = canonical(anchor).decode("ascii")
        for forbidden in (
            "message",
            "caption",
            "profile",
            "provider_payload",
            "raw_media",
            "secret",
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertTrue(anchor["content_free"])
        self.assertFalse(anchor["private_content_included"])

    def test_container_mount_projection_is_order_independent_but_set_bound(self) -> None:
        first = [
            {"Type": "bind", "Source": "/release/plugin-a", "Destination": "/app/a", "RW": False, "Propagation": "rprivate"},
            {"Type": "volume", "Source": "/volume/data", "Destination": "/app/b", "RW": True, "Propagation": "", "Name": "data"},
        ]
        reordered = list(reversed(first))
        changed = [dict(first[0]), {**first[1], "Destination": "/app/c"}]
        projection_a = activation._mount_projection(first, expected_plugin_digest="plugin-a")
        projection_b = activation._mount_projection(reordered, expected_plugin_digest="plugin-a")
        projection_c = activation._mount_projection(changed, expected_plugin_digest="plugin-a")
        self.assertEqual(projection_a, projection_b)
        self.assertNotEqual(projection_a["semantic_digest"], projection_c["semantic_digest"])

    def test_mount_semantic_and_identity_lanes_are_separate(self) -> None:
        first = [{"Type": "bind", "Source": "/one/plugin-a", "Destination": "/app/plugin", "RW": False, "Propagation": "rprivate"}]
        second = [{**first[0], "Source": "/two/plugin-a"}]
        left = activation._mount_projection(first, expected_plugin_digest="plugin-a")
        right = activation._mount_projection(second, expected_plugin_digest="plugin-a")
        self.assertEqual(left["semantic_digest"], right["semantic_digest"])
        self.assertNotEqual(left["identity_digest"], right["identity_digest"])

    def test_backup_detects_byte_or_acl_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_bytes(b"safe\n")
            source.chmod(0o640)
            backup_root = root / "backup"
            backup_root.mkdir(mode=0o700)
            record = activation._backup_file(backup_root, "SOURCE", source)
            plan = {"live_plan_digest": _hex("9")}
            document = {
                "schema": "myuna.p01b-p16-incident-recovery-backup.v1",
                "plan": plan,
                "files": {"source": record},
            }
            (backup_root / "BACKUP.json").write_bytes(canonical(document) + b"\n")
            (backup_root / "BACKUP.json").chmod(0o600)
            activation._verify_backup(backup_root, plan)
            (backup_root / "SOURCE").write_bytes(b"tampered\n")
            with self.assertRaisesRegex(activation.P01BActivationRejected, "backup_file_rejected"):
                activation._verify_backup(backup_root, plan)


if __name__ == "__main__":
    unittest.main()
