from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Mapping

from myuna_core.authenticated_conversation import AuthenticatedConversationContext

from .contracts import (
    ExternalContextEnvelope,
    ExternalSummary,
    ExternalSummaryJob,
    ExternalTurn,
    ExternalTurnProvenance,
)


RELEASE_BOUND_CONTEXT_SCHEMA = "myuna.external-context-release-bound.v1"
RELEASE_BOUND_CONTEXT_OVERLAY_SCHEMA = "myuna.external-context-release-bound.v2"
RELEASE_BOUND_PROVENANCE_SCHEMA = "myuna.external-turn-provenance.v2"
RELEASE_BOUND_PROVENANCE_OVERLAY_SCHEMA = "myuna.external-turn-provenance.v3"
RELEASE_BOUND_SUMMARY_JOB_SCHEMA = "myuna.external-summary-job.v2"
RELEASE_BOUND_SUMMARY_CANDIDATE_SCHEMA = "myuna.external-summary-candidate.v2"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ReleaseBoundLifecycleRejected(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ReleaseBoundLifecycleRejected(code)


def _sha(value: object, code: str) -> str:
    _require(isinstance(value, str) and _SHA256.fullmatch(value) is not None, code)
    return value


def _canonical(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _digest(domain: bytes, payload: Mapping[str, object]) -> str:
    return sha256(domain + b"\0" + _canonical(payload)).hexdigest()


@dataclass(frozen=True, slots=True)
class ReleaseBoundExternalContext:
    release_set_id: str
    envelope: ExternalContextEnvelope
    policy_overlay_id: str | None = None
    schema: str | None = None

    def __post_init__(self) -> None:
        expected_schema = (
            RELEASE_BOUND_CONTEXT_SCHEMA
            if self.policy_overlay_id is None
            else RELEASE_BOUND_CONTEXT_OVERLAY_SCHEMA
        )
        if self.schema is None:
            object.__setattr__(self, "schema", expected_schema)
        _require(self.schema == expected_schema, "release_bound_context_schema_unknown")
        _sha(self.release_set_id, "release_bound_context_release_set_rejected")
        if self.policy_overlay_id is not None:
            _sha(
                self.policy_overlay_id,
                "release_bound_context_policy_overlay_rejected",
            )

    @classmethod
    def from_payload(
        cls,
        payload: object,
        *,
        context: AuthenticatedConversationContext,
    ) -> "ReleaseBoundExternalContext":
        _require(isinstance(payload, Mapping), "release_bound_context_fields_rejected")
        schema = payload.get("schema")
        if schema == RELEASE_BOUND_CONTEXT_SCHEMA:
            required = {"external_context", "release_set_id", "schema"}
            policy_overlay_id = None
        elif schema == RELEASE_BOUND_CONTEXT_OVERLAY_SCHEMA:
            required = {
                "external_context",
                "policy_overlay_id",
                "release_set_id",
                "schema",
            }
            policy_overlay_id = payload.get("policy_overlay_id")
        else:
            raise ReleaseBoundLifecycleRejected(
                "release_bound_context_schema_unknown"
            )
        _require(isinstance(payload, Mapping) and set(payload) == required, "release_bound_context_fields_rejected")
        return cls(
            release_set_id=payload["release_set_id"],  # type: ignore[arg-type]
            envelope=ExternalContextEnvelope.from_payload(
                payload["external_context"],  # type: ignore[arg-type]
                context=context,
            ),
            policy_overlay_id=policy_overlay_id,  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )

    def as_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "external_context": self.envelope.as_payload(),
            "release_set_id": self.release_set_id,
            "schema": self.schema,
        }
        if self.policy_overlay_id is not None:
            payload["policy_overlay_id"] = self.policy_overlay_id
        return payload


@dataclass(frozen=True, slots=True)
class ReleaseBoundTurnProvenance:
    release_set_id: str
    provenance: ExternalTurnProvenance
    policy_overlay_id: str | None = None
    schema: str | None = None

    def __post_init__(self) -> None:
        expected_schema = (
            RELEASE_BOUND_PROVENANCE_SCHEMA
            if self.policy_overlay_id is None
            else RELEASE_BOUND_PROVENANCE_OVERLAY_SCHEMA
        )
        if self.schema is None:
            object.__setattr__(self, "schema", expected_schema)
        _require(self.schema == expected_schema, "release_bound_provenance_schema_unknown")
        _sha(self.release_set_id, "release_bound_provenance_release_set_rejected")
        if self.policy_overlay_id is not None:
            _sha(
                self.policy_overlay_id,
                "release_bound_provenance_policy_overlay_rejected",
            )

    @classmethod
    def from_payload(cls, payload: object) -> "ReleaseBoundTurnProvenance":
        _require(isinstance(payload, Mapping), "release_bound_provenance_fields_rejected")
        schema = payload.get("schema")
        if schema == RELEASE_BOUND_PROVENANCE_SCHEMA:
            required = {"provenance", "release_set_id", "schema"}
            policy_overlay_id = None
        elif schema == RELEASE_BOUND_PROVENANCE_OVERLAY_SCHEMA:
            required = {
                "policy_overlay_id",
                "provenance",
                "release_set_id",
                "schema",
            }
            policy_overlay_id = payload.get("policy_overlay_id")
        else:
            raise ReleaseBoundLifecycleRejected(
                "release_bound_provenance_schema_unknown"
            )
        _require(set(payload) == required, "release_bound_provenance_fields_rejected")
        return cls(
            release_set_id=payload["release_set_id"],  # type: ignore[arg-type]
            provenance=ExternalTurnProvenance.from_payload(payload["provenance"]),
            policy_overlay_id=policy_overlay_id,  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )

    def as_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "provenance": self.provenance.as_payload(),
            "release_set_id": self.release_set_id,
            "schema": self.schema,
        }
        if self.policy_overlay_id is not None:
            payload["policy_overlay_id"] = self.policy_overlay_id
        return payload


@dataclass(frozen=True, slots=True)
class ReleaseBoundSummaryJob:
    release_set_id: str
    job: ExternalSummaryJob
    digest: str
    schema: str = RELEASE_BOUND_SUMMARY_JOB_SCHEMA

    def __post_init__(self) -> None:
        _require(self.schema == RELEASE_BOUND_SUMMARY_JOB_SCHEMA, "release_bound_summary_job_schema_unknown")
        _sha(self.release_set_id, "release_bound_summary_job_release_set_rejected")
        _sha(self.digest, "release_bound_summary_job_digest_rejected")
        _require(self.digest == _digest(b"myuna-external-summary-job-v2", self.digest_payload()), "release_bound_summary_job_digest_mismatch")

    def digest_payload(self) -> dict[str, object]:
        return {
            "job": self.job.as_payload(),
            "release_set_id": self.release_set_id,
            "schema": self.schema,
        }

    @classmethod
    def create(
        cls,
        *,
        release_set_id: str,
        epoch_id: str,
        base_revision: int,
        summary_version: int,
        covered_end: int,
        covered_terminal_digest: str,
        profile_revisions: tuple[int, ...],
        prior_summary: ExternalSummary | None,
        turns: tuple[ExternalTurn, ...],
    ) -> "ReleaseBoundSummaryJob":
        job = ExternalSummaryJob.create(
            epoch_id=epoch_id,
            base_revision=base_revision,
            summary_version=summary_version,
            covered_end=covered_end,
            covered_terminal_digest=covered_terminal_digest,
            profile_revisions=profile_revisions,
            prior_summary=prior_summary,
            turns=turns,
        )
        payload = {
            "job": job.as_payload(),
            "release_set_id": release_set_id,
            "schema": RELEASE_BOUND_SUMMARY_JOB_SCHEMA,
        }
        return cls(
            release_set_id=release_set_id,
            job=job,
            digest=_digest(b"myuna-external-summary-job-v2", payload),
        )

    @classmethod
    def from_payload(cls, payload: object) -> "ReleaseBoundSummaryJob":
        required = {"digest", "job", "release_set_id", "schema"}
        _require(isinstance(payload, Mapping) and set(payload) == required, "release_bound_summary_job_fields_rejected")
        return cls(
            release_set_id=payload["release_set_id"],  # type: ignore[arg-type]
            job=ExternalSummaryJob.from_payload(payload["job"]),
            digest=payload["digest"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )

    def as_payload(self) -> dict[str, object]:
        return {**self.digest_payload(), "digest": self.digest}


@dataclass(frozen=True, slots=True)
class ReleaseBoundSummaryCandidate:
    release_set_id: str
    job_digest: str
    summary: ExternalSummary
    schema: str = RELEASE_BOUND_SUMMARY_CANDIDATE_SCHEMA

    def __post_init__(self) -> None:
        _require(self.schema == RELEASE_BOUND_SUMMARY_CANDIDATE_SCHEMA, "release_bound_summary_candidate_schema_unknown")
        _sha(self.release_set_id, "release_bound_summary_candidate_release_set_rejected")
        _sha(self.job_digest, "release_bound_summary_candidate_job_rejected")

    @classmethod
    def from_payload(cls, payload: object) -> "ReleaseBoundSummaryCandidate":
        required = {"job_digest", "release_set_id", "schema", "summary"}
        _require(isinstance(payload, Mapping) and set(payload) == required, "release_bound_summary_candidate_fields_rejected")
        return cls(
            release_set_id=payload["release_set_id"],  # type: ignore[arg-type]
            job_digest=payload["job_digest"],  # type: ignore[arg-type]
            summary=ExternalSummary.from_payload(payload["summary"]),
            schema=payload["schema"],  # type: ignore[arg-type]
        )

    def as_payload(self) -> dict[str, object]:
        return {
            "job_digest": self.job_digest,
            "release_set_id": self.release_set_id,
            "schema": self.schema,
            "summary": self.summary.as_payload(),
        }

    def validate_for(self, job: ReleaseBoundSummaryJob) -> None:
        summary = self.summary
        _require(self.release_set_id == job.release_set_id, "release_bound_summary_candidate_release_set_mismatch")
        _require(self.job_digest == job.digest, "release_bound_summary_candidate_job_mismatch")
        _require(summary.summary_version == job.job.summary_version, "release_bound_summary_candidate_range_mismatch")
        _require(summary.covered_start == job.job.covered_start, "release_bound_summary_candidate_range_mismatch")
        _require(summary.covered_end == job.job.covered_end, "release_bound_summary_candidate_range_mismatch")
        _require(summary.covered_terminal_digest == job.job.covered_terminal_digest, "release_bound_summary_candidate_range_mismatch")
        _require(summary.profile_revisions == job.job.profile_revisions, "release_bound_summary_candidate_profiles_mismatch")
