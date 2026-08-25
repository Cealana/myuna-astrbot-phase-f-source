#!/usr/bin/env python3
"""Source-owned P08 orchestration for one explicit trusted-time transition.

Readiness is metadata-only.  Assessment, the protected reconciliation binding,
and the max-one forward transition are action-owned and never run at service
startup.  Public results contain only versioned content-free projections.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Callable, Mapping, Protocol

from myuna_core.active_temporal_context import service as core_service
from myuna_core.active_temporal_context.store import TemporalContextStore
from myuna_core.trusted_time import (
    ContinuityAssessment,
    DurableTrustedTimeProvider,
    ForwardContinuityAuthorization,
    LinuxAdjtimexSynchronizationProbe,
    SynchronizationEvidence,
    SystemUtcObservationSource,
    TrustedTimeError,
    TrustedTimeTransitionAmbiguousError,
    TrustedTimeWatermark,
    UtcObservation,
)
from myuna_core.trusted_time.continuity import ContinuityAnchor


CONTRACT_SCHEMA = "myuna.p08-forward-continuity-orchestration.v1"
READINESS_SCHEMA = "myuna.p08-forward-continuity-readiness.v1"
PROTECTED_BINDING_SCHEMA = "myuna.p08-forward-continuity-protected-binding.v1"
RESULT_SCHEMA = "myuna.p08-forward-continuity-result.v1"
RECONCILIATION_SCHEMA = "myuna.p08-forward-continuity-reconcile-result.v1"
CORE_COMMIT = "97be9ef1f6182810575f62f79fd8b08680d1568c"
P08_ARCHITECTURE_HANDOFF_SHA256 = (
    "367dbfdbb1a2d872bd5f4c19f1daba6e398a788051107b866cb60b16f1c109f7"
)
P10B_T1_HANDOFF_SHA256 = (
    "129c409236049eb74bf1400dd4c2c1c5fad4106a10ed29217bc23f6f8a03cd7f"
)
PREDECESSOR_RELEASE_DIGEST = (
    "1b589a474c56e138082f014724065dd57d38440b08c57b1497e5a4cb3cbe3e06"
)
PREDECESSOR_CORE_COMMIT = "065ef4b647f63925ae20bb564007c127433c0b81"
HEX64 = re.compile(r"[0-9a-f]{64}")
SAFE_CODE = re.compile(r"[a-z][a-z0-9_]{0,95}")


class ProviderPort(Protocol):
    def assess_continuity(self) -> ContinuityAssessment: ...
    def transition_forward(
        self,
        assessment: ContinuityAssessment,
        authorization: ForwardContinuityAuthorization,
    ) -> object: ...
    def reconcile_forward_transition(
        self,
        assessment: ContinuityAssessment,
        authorization: ForwardContinuityAuthorization,
    ) -> object: ...
    def validate_state(self) -> None: ...


PersistProtected = Callable[[bytes], None]


class ForwardContinuityRejected(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        state_effect: str = "none",
        projection: Mapping[str, object] | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code if SAFE_CODE.fullmatch(code) is not None else "transition_rejected"
        self.state_effect = state_effect
        self.projection = None if projection is None else dict(projection)


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ForwardContinuityRejected(code)


def canonical(payload: object) -> bytes:
    return json.dumps(
        payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def digest(payload: object) -> str:
    return sha256(canonical(payload)).hexdigest()


def require_digest(value: object, code: str = "digest_rejected") -> str:
    require(isinstance(value, str) and HEX64.fullmatch(value) is not None, code)
    return value


def contract() -> dict[str, object]:
    body = {
        "assessment_action_owned": True,
        "assessment_persistent_mutation": False,
        "automatic_startup_transition": False,
        "core_commit": CORE_COMMIT,
        "max_attempts": 1,
        "no_fallback": True,
        "no_retry": True,
        "p08_architecture_handoff_sha256": P08_ARCHITECTURE_HANDOFF_SHA256,
        "p10b_t1_handoff_sha256": P10B_T1_HANDOFF_SHA256,
        "postcommit_ambiguity_action": "reconcile_only",
        "predecessor_core_commit": PREDECESSOR_CORE_COMMIT,
        "predecessor_forward_state_compatible": True,
        "predecessor_release_digest": PREDECESSOR_RELEASE_DIGEST,
        "readiness_opaque_content_read": False,
        "readiness_persistent_mutation": False,
        "rollback_code_public_only_after_commit": True,
        "schema": CONTRACT_SCHEMA,
        "state_backup_restore_after_forward_commit": False,
        "transition_direction": "forward_only",
        "transition_explicit": True,
    }
    return {**body, "contract_digest": digest(body)}


def readiness(*, plan_digest: str, strategy_digest: str) -> dict[str, object]:
    require_digest(plan_digest, "plan_digest_rejected")
    require_digest(strategy_digest, "strategy_digest_rejected")
    body = {
        "contract_digest": contract()["contract_digest"],
        "opaque_content_read": False,
        "persistent_mutation": False,
        "plan_digest": plan_digest,
        "schema": READINESS_SCHEMA,
        "status": "ready",
        "strategy_digest": strategy_digest,
        "transition_deferred_to_action_ownership": True,
    }
    return {**body, "readiness_digest": digest(body)}


def provider_for_state(root: Path, *, expected_uid: int) -> DurableTrustedTimeProvider:
    """Construct the same provider/watermark closure used by the P08 service."""

    store = TemporalContextStore(
        root / core_service.TEMPORAL_DATABASE_NAME,
        expected_uid=expected_uid,
    )
    watermark = store.trusted_time_watermark()
    provider_watermark = (
        None
        if watermark is None
        else TrustedTimeWatermark(
            source=watermark[0], sequence=watermark[1], instant=watermark[2]
        )
    )
    return DurableTrustedTimeProvider(
        root / core_service.TRUSTED_TIME_DATABASE_NAME,
        SystemUtcObservationSource(LinuxAdjtimexSynchronizationProbe()),
        consumer_watermark=provider_watermark,
        expected_uid=expected_uid,
    )


def _anchor_payload(value: ContinuityAnchor | None) -> object:
    return None if value is None else value.payload()


def _observation_payload(value: UtcObservation) -> dict[str, object]:
    return {
        "authority": value.evidence.authority,
        "boot_id": value.boot_id,
        "instant": value.instant.isoformat(timespec="microseconds"),
        "monotonic_ns": value.monotonic_ns,
        "synchronized": value.evidence.synchronized,
        "uncertainty_microseconds": int(
            value.evidence.uncertainty.total_seconds() * 1_000_000
        ),
    }


def _protected_binding(
    assessment: ContinuityAssessment,
    authorization: ForwardContinuityAuthorization,
    *,
    plan_digest: str,
    strategy_digest: str,
) -> dict[str, object]:
    require(assessment._candidate is not None, "assessment_candidate_rejected")
    require(assessment._observation is not None, "assessment_observation_rejected")
    body = {
        "assessment": assessment.public_payload(),
        "assessment_private": {
            "assessed_monotonic_ns": assessment._assessed_monotonic_ns,
            "candidate": _anchor_payload(assessment._candidate),
            "observation": _observation_payload(assessment._observation),
            "prior_anchor": _anchor_payload(assessment._prior_anchor),
            "signed_residual_microseconds": assessment._signed_residual_microseconds,
        },
        "authorization": authorization.public_payload(),
        "authorization_private": {
            "residual_lower_microseconds": authorization._residual_lower_microseconds,
            "residual_upper_microseconds": authorization._residual_upper_microseconds,
        },
        "content_free_export_allowed": False,
        "plan_digest": require_digest(plan_digest, "plan_digest_rejected"),
        "schema": PROTECTED_BINDING_SCHEMA,
        "strategy_digest": require_digest(
            strategy_digest, "strategy_digest_rejected"
        ),
    }
    return {**body, "binding_digest": digest(body)}


def _parse_anchor(value: object) -> ContinuityAnchor | None:
    if value is None:
        return None
    try:
        return ContinuityAnchor.from_payload(value)
    except Exception as exc:
        raise ForwardContinuityRejected("protected_binding_rejected") from exc


def _parse_observation(value: object) -> UtcObservation:
    expected = {
        "authority",
        "boot_id",
        "instant",
        "monotonic_ns",
        "synchronized",
        "uncertainty_microseconds",
    }
    require(isinstance(value, Mapping) and set(value) == expected, "protected_binding_rejected")
    try:
        instant = datetime.fromisoformat(value["instant"])  # type: ignore[arg-type]
        uncertainty = timedelta(microseconds=value["uncertainty_microseconds"])  # type: ignore[arg-type]
        return UtcObservation(
            instant=instant,
            monotonic_ns=value["monotonic_ns"],  # type: ignore[arg-type]
            boot_id=value["boot_id"],  # type: ignore[arg-type]
            evidence=SynchronizationEvidence(
                synchronized=value["synchronized"],  # type: ignore[arg-type]
                uncertainty=uncertainty,
                authority=value["authority"],  # type: ignore[arg-type]
            ),
        )
    except Exception as exc:
        raise ForwardContinuityRejected("protected_binding_rejected") from exc


def restore_protected_binding(
    payload: Mapping[str, object],
    *,
    plan_digest: str,
    strategy_digest: str,
) -> tuple[ContinuityAssessment, ForwardContinuityAuthorization]:
    expected = {
        "assessment",
        "assessment_private",
        "authorization",
        "authorization_private",
        "binding_digest",
        "content_free_export_allowed",
        "plan_digest",
        "schema",
        "strategy_digest",
    }
    require(set(payload) == expected, "protected_binding_rejected")
    body = {key: payload[key] for key in expected - {"binding_digest"}}
    require(
        payload.get("schema") == PROTECTED_BINDING_SCHEMA
        and payload.get("content_free_export_allowed") is False
        and payload.get("plan_digest") == require_digest(plan_digest)
        and payload.get("strategy_digest") == require_digest(strategy_digest)
        and payload.get("binding_digest") == digest(body),
        "protected_binding_rejected",
    )
    public = payload.get("assessment")
    private = payload.get("assessment_private")
    auth_public = payload.get("authorization")
    auth_private = payload.get("authorization_private")
    require(
        isinstance(public, Mapping)
        and isinstance(private, Mapping)
        and isinstance(auth_public, Mapping)
        and isinstance(auth_private, Mapping),
        "protected_binding_rejected",
    )
    require(
        set(public)
        == {
            "assessment_clock_digest",
            "assessment_digest",
            "candidate_digest",
            "consumer_watermark_digest",
            "continuity",
            "direction",
            "drift_bucket",
            "eligibility",
            "evidence_digest",
            "persistent_mutation",
            "policy_digest",
            "prior_anchor_digest",
            "schema",
            "source_binding_digest",
            "status",
            "uncertainty_bucket",
        }
        and set(private)
        == {
            "assessed_monotonic_ns",
            "candidate",
            "observation",
            "prior_anchor",
            "signed_residual_microseconds",
        },
        "protected_binding_rejected",
    )
    try:
        assessment = ContinuityAssessment(
            **public,  # type: ignore[arg-type]
            _prior_anchor=_parse_anchor(private["prior_anchor"]),
            _candidate=_parse_anchor(private["candidate"]),
            _observation=_parse_observation(private["observation"]),
            _signed_residual_microseconds=private["signed_residual_microseconds"],  # type: ignore[arg-type]
            _assessed_monotonic_ns=private["assessed_monotonic_ns"],  # type: ignore[arg-type]
        )
        require(
            set(auth_public)
            == {
                "assessment_digest",
                "assessment_evidence_digest",
                "authorization_digest",
                "authorization_identity_digest",
                "candidate_digest",
                "consumer_watermark_digest",
                "direction",
                "lineage_digest",
                "max_age_seconds",
                "max_attempts",
                "policy_digest",
                "prior_anchor_digest",
                "residual_window_digest",
                "schema",
                "source_binding_digest",
                "source_contract_digest",
                "source_evidence_digest",
                "transition_id",
            }
            and set(auth_private)
            == {"residual_lower_microseconds", "residual_upper_microseconds"},
            "protected_binding_rejected",
        )
        authorization = ForwardContinuityAuthorization(
            **auth_public,  # type: ignore[arg-type]
            _residual_lower_microseconds=auth_private["residual_lower_microseconds"],  # type: ignore[arg-type]
            _residual_upper_microseconds=auth_private["residual_upper_microseconds"],  # type: ignore[arg-type]
        )
    except ForwardContinuityRejected:
        raise
    except Exception as exc:
        raise ForwardContinuityRejected("protected_binding_rejected") from exc
    return assessment, authorization


def _result(
    *,
    status: str,
    assessment: ContinuityAssessment,
    authorization: ForwardContinuityAuthorization,
    state_effect: str,
    transition_digest: str | None,
    error_category: str | None,
    retryable: bool,
) -> dict[str, object]:
    body = {
        "assessment_digest": assessment.assessment_digest,
        "authorization_digest": authorization.authorization_digest,
        "error_category": error_category,
        "persistent_mutation": state_effect == "committed",
        "private_content_included": False,
        "raw_cause_included": False,
        "retryable": retryable,
        "schema": RESULT_SCHEMA,
        "state_effect": state_effect,
        "status": status,
        "transition_digest": transition_digest,
        "transition_id": authorization.transition_id,
    }
    return {**body, "result_digest": digest(body)}


def assess(
    provider: ProviderPort,
    *,
    action_owned: bool,
    plan_digest: str,
    strategy_digest: str,
) -> dict[str, object]:
    require(action_owned, "action_ownership_required")
    require_digest(plan_digest, "plan_digest_rejected")
    require_digest(strategy_digest, "strategy_digest_rejected")
    value = provider.assess_continuity()
    require(
        isinstance(value, ContinuityAssessment)
        and value.persistent_mutation is False,
        "assessment_rejected",
    )
    return value.public_payload()


def transition(
    provider: ProviderPort,
    *,
    action_owned: bool,
    plan_digest: str,
    strategy_digest: str,
    incident_digest: str,
    persist_protected: PersistProtected,
) -> dict[str, object]:
    require(action_owned, "action_ownership_required")
    require_digest(plan_digest, "plan_digest_rejected")
    require_digest(strategy_digest, "strategy_digest_rejected")
    require_digest(incident_digest, "incident_digest_rejected")
    assessment = provider.assess_continuity()
    require(
        isinstance(assessment, ContinuityAssessment)
        and assessment.status == "forward_transition_required"
        and assessment.eligibility == "explicit_forward_transition"
        and assessment.direction == "forward"
        and assessment.persistent_mutation is False,
        "forward_transition_not_required",
    )
    source_contract_digest = require_digest(
        contract()["contract_digest"], "contract_digest_rejected"
    )
    authorization = ForwardContinuityAuthorization.bind(
        assessment,
        transition_id=incident_digest,
        source_contract_digest=source_contract_digest,
        source_evidence_digest=plan_digest,
        lineage_digest=strategy_digest,
        authorization_identity_digest=digest(
            {
                "incident_digest": incident_digest,
                "plan_digest": plan_digest,
                "strategy_digest": strategy_digest,
            }
        ),
        residual_tolerance_microseconds=0,
        max_age_seconds=60,
    )
    protected = _protected_binding(
        assessment,
        authorization,
        plan_digest=plan_digest,
        strategy_digest=strategy_digest,
    )
    persist_protected(canonical(protected))
    try:
        receipt = provider.transition_forward(assessment, authorization)
        transition_digest = require_digest(
            getattr(receipt, "transition_digest", None),
            "transition_receipt_rejected",
        )
        require(getattr(receipt, "status", None) == "committed", "transition_receipt_rejected")
        return _result(
            status="committed",
            assessment=assessment,
            authorization=authorization,
            state_effect="committed",
            transition_digest=transition_digest,
            error_category=None,
            retryable=False,
        )
    except TrustedTimeTransitionAmbiguousError:
        try:
            reconciled = provider.reconcile_forward_transition(
                assessment, authorization
            )
        except Exception as exc:
            raise ForwardContinuityRejected(
                "transition_reconcile_rejected", state_effect="ambiguous"
            ) from exc
        status = getattr(reconciled, "status", None)
        require(status in {"committed", "not_committed"}, "transition_reconcile_rejected")
        if status == "committed":
            return _result(
                status="committed_reconciled",
                assessment=assessment,
                authorization=authorization,
                state_effect="committed",
                transition_digest=require_digest(
                    getattr(reconciled, "transition_digest", None),
                    "transition_reconcile_rejected",
                ),
                error_category="trusted_time_transition_ambiguous",
                retryable=False,
            )
        raise ForwardContinuityRejected(
            "transition_not_committed_reconciled",
            state_effect="none",
            projection=_result(
                status="not_committed_reconciled",
                assessment=assessment,
                authorization=authorization,
                state_effect="none",
                transition_digest=None,
                error_category="trusted_time_transition_ambiguous",
                retryable=False,
            ),
        )
    except TrustedTimeError as exc:
        code = str(getattr(exc, "code", "trusted_time_rejected"))
        raise ForwardContinuityRejected(
            "transition_precommit_rejected",
            state_effect="none",
            projection=_result(
                status="precommit_rejected",
                assessment=assessment,
                authorization=authorization,
                state_effect="none",
                transition_digest=None,
                error_category=code if SAFE_CODE.fullmatch(code) is not None else "trusted_time_rejected",
                retryable=False,
            ),
        ) from None
    except ForwardContinuityRejected:
        raise
    except Exception as exc:
        raise ForwardContinuityRejected(
            "transition_outcome_ambiguous", state_effect="ambiguous"
        ) from exc


def reconcile(
    provider: ProviderPort,
    protected: Mapping[str, object],
    *,
    action_owned: bool,
    plan_digest: str,
    strategy_digest: str,
) -> dict[str, object]:
    require(action_owned, "action_ownership_required")
    assessment, authorization = restore_protected_binding(
        protected, plan_digest=plan_digest, strategy_digest=strategy_digest
    )
    try:
        value = provider.reconcile_forward_transition(assessment, authorization)
    except TrustedTimeError as exc:
        code = str(getattr(exc, "code", "trusted_time_reconcile_rejected"))
        raise ForwardContinuityRejected(
            code if SAFE_CODE.fullmatch(code) is not None else "transition_reconcile_rejected",
            state_effect="ambiguous",
        ) from None
    except Exception as exc:
        raise ForwardContinuityRejected(
            "transition_reconcile_rejected", state_effect="ambiguous"
        ) from exc
    status = getattr(value, "status", None)
    require(status in {"committed", "not_committed"}, "transition_reconcile_rejected")
    body = {
        "authorization_digest": authorization.authorization_digest,
        "persistent_mutation": False,
        "private_content_included": False,
        "raw_cause_included": False,
        "schema": RECONCILIATION_SCHEMA,
        "state_effect": "committed" if status == "committed" else "none",
        "status": status,
        "transition_digest": getattr(value, "transition_digest", None),
        "transition_id": authorization.transition_id,
    }
    if status == "committed":
        require_digest(body["transition_digest"], "transition_reconcile_rejected")
    else:
        require(body["transition_digest"] is None, "transition_reconcile_rejected")
    return {**body, "reconciliation_digest": digest(body)}


def validate_forward_state(provider: ProviderPort) -> dict[str, object]:
    provider.validate_state()
    body = {
        "predecessor_core_commit": PREDECESSOR_CORE_COMMIT,
        "predecessor_forward_state_compatible": True,
        "predecessor_release_digest": PREDECESSOR_RELEASE_DIGEST,
        "schema": "myuna.p08-predecessor-forward-state-validation.v1",
        "state_bytes_restored": False,
        "status": "valid",
    }
    return {**body, "validation_digest": digest(body)}
