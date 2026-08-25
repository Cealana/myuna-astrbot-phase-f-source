from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Mapping

from myuna_core.authenticated_conversation import AuthenticatedConversationContext


EXTERNAL_CONTEXT_SCHEMA = "myuna.external-context-envelope.v1"
EXTERNAL_VISUAL_CONTEXT_SCHEMA = "myuna.external-context-envelope.v2"
EXTERNAL_PROJECTION_POLICY = "p07-hybrid-external-generation-v1"
EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY = "p07-hybrid-verbatim-first-v1"
EXTERNAL_VISUAL_PROJECTION_POLICY = "p01b-contextual-visual-interpretation-v1"
VISUAL_EVIDENCE_SCHEMA = "myuna.visual-evidence.v1"
VISUAL_EVIDENCE_SOURCE = "gemini_visual_extraction"
TURN_PROVENANCE_SCHEMA = "myuna.external-turn-provenance.v1"
SUMMARY_JOB_SCHEMA = "myuna.external-summary-job.v1"
SUMMARY_CANDIDATE_SCHEMA = "myuna.external-summary-candidate.v1"
PROJECTION_SOURCE_CATEGORIES = frozenset(
    {
        "owner_current_message",
        "owner_profile_selected",
        "profile_derived_summary",
        "ordinary_external_turn",
        "unknown",
    }
)
ZERO_DIGEST = "0" * 64
MAX_CURRENT_MESSAGE_CHARACTERS = 4_000
MAX_VISUAL_OBSERVATION_CHARACTERS = 240
MAX_SUMMARY_CHARACTERS = 4_000
MAX_SUMMARY_PROFILE_REVISIONS = 32
MAX_SUMMARY_JOB_TURNS = 5
MAX_SUMMARY_SOURCE_CHARACTERS = 20_000
MAX_RECENT_TURNS = 6
MAX_RECENT_CHARACTERS = 12_000
MAX_VERBATIM_RECENT_TURNS = 64
MAX_VERBATIM_RECENT_CHARACTERS = 199_000
MAX_REPLY_CHARACTERS = 4_000

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ExternalContextError(ValueError):
    """Content-free fail-closed error for external context contracts."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _digest(domain: bytes, payload: Mapping[str, object]) -> str:
    return sha256(domain + b"\0" + _canonical(payload)).hexdigest()


def _safe_id(value: object, *, code: str) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise ExternalContextError(code)
    return value


def _sha(value: object, *, code: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ExternalContextError(code)
    return value


def _bounded_text(value: object, *, maximum: int, code: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or "\x00" in value
        or len(value) > maximum
    ):
        raise ExternalContextError(code)
    return value


def current_message_digest(
    context: AuthenticatedConversationContext,
    message: str,
) -> str:
    message = _bounded_text(
        message,
        maximum=MAX_CURRENT_MESSAGE_CHARACTERS,
        code="current_message_out_of_contract",
    )
    return _digest(
        b"myuna-owner-current-message-v1",
        {
            "event_id": context.event_id,
            "message": message,
            "request_id": context.request_id,
        },
    )


def visual_evidence_digest(
    context: AuthenticatedConversationContext,
    *,
    current_message: str,
    observation: str,
    caption_present: bool,
) -> str:
    return _digest(
        b"myuna-visual-evidence-v1",
        {
            "caption_present": caption_present,
            "current_message_digest": current_message_digest(context, current_message),
            "observation": observation,
            "schema": VISUAL_EVIDENCE_SCHEMA,
            "source": VISUAL_EVIDENCE_SOURCE,
        },
    )


@dataclass(frozen=True, slots=True)
class VisualEvidence:
    observation: str
    caption_present: bool
    evidence_digest: str
    source: str = VISUAL_EVIDENCE_SOURCE
    schema: str = VISUAL_EVIDENCE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != VISUAL_EVIDENCE_SCHEMA:
            raise ExternalContextError("visual_evidence_schema_unknown")
        if self.source != VISUAL_EVIDENCE_SOURCE:
            raise ExternalContextError("visual_evidence_source_unknown")
        _bounded_text(
            self.observation,
            maximum=MAX_VISUAL_OBSERVATION_CHARACTERS,
            code="visual_observation_out_of_contract",
        )
        if not isinstance(self.caption_present, bool):
            raise ExternalContextError("visual_caption_presence_out_of_contract")
        _sha(self.evidence_digest, code="visual_evidence_digest_out_of_contract")

    @classmethod
    def create(
        cls,
        *,
        context: AuthenticatedConversationContext,
        current_message: str,
        observation: str,
        caption_present: bool,
    ) -> VisualEvidence:
        return cls(
            observation=observation,
            caption_present=caption_present,
            evidence_digest=visual_evidence_digest(
                context,
                current_message=current_message,
                observation=observation,
                caption_present=caption_present,
            ),
        )

    @classmethod
    def from_payload(
        cls,
        payload: object,
        *,
        context: AuthenticatedConversationContext,
        current_message: str,
    ) -> VisualEvidence:
        required = {
            "caption_present",
            "evidence_digest",
            "observation",
            "schema",
            "source",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise ExternalContextError("visual_evidence_fields_out_of_contract")
        evidence = cls(
            observation=payload["observation"],  # type: ignore[arg-type]
            caption_present=payload["caption_present"],  # type: ignore[arg-type]
            evidence_digest=payload["evidence_digest"],  # type: ignore[arg-type]
            source=payload["source"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )
        expected = visual_evidence_digest(
            context,
            current_message=current_message,
            observation=evidence.observation,
            caption_present=evidence.caption_present,
        )
        if evidence.evidence_digest != expected:
            raise ExternalContextError("visual_evidence_digest_mismatch")
        return evidence

    def as_payload(self) -> dict[str, object]:
        return {
            "caption_present": self.caption_present,
            "evidence_digest": self.evidence_digest,
            "observation": self.observation,
            "schema": self.schema,
            "source": self.source,
        }


def turn_digest(
    *,
    sequence: int,
    parent_digest: str,
    user_message: str,
    assistant_reply: str,
) -> str:
    return _digest(
        b"myuna-external-authorized-turn-v1",
        {
            "assistant_reply": assistant_reply,
            "parent_digest": parent_digest,
            "sequence": sequence,
            "user_message": user_message,
        },
    )


def summary_digest(
    *,
    content: str,
    covered_start: int,
    covered_end: int,
    covered_terminal_digest: str,
    profile_revisions: tuple[int, ...],
    summary_version: int,
) -> str:
    return _digest(
        b"myuna-external-authorized-summary-v1",
        {
            "content": content,
            "covered_end": covered_end,
            "covered_start": covered_start,
            "covered_terminal_digest": covered_terminal_digest,
            "profile_revisions": list(profile_revisions),
            "summary_version": summary_version,
        },
    )


@dataclass(frozen=True, slots=True)
class EgressSafetySignals:
    classifier_available: bool = False
    credential_material: bool = False
    forwarded_private: bool = False
    third_party_private: bool = False

    @classmethod
    def from_payload(cls, payload: object) -> EgressSafetySignals:
        if (
            not isinstance(payload, Mapping)
            or set(payload)
            != {
                "classifier_available",
                "credential_material",
                "forwarded_private",
                "third_party_private",
            }
            or any(not isinstance(value, bool) for value in payload.values())
        ):
            raise ExternalContextError("safety_signals_out_of_contract")
        return cls(
            classifier_available=payload["classifier_available"],
            credential_material=payload["credential_material"],
            forwarded_private=payload["forwarded_private"],
            third_party_private=payload["third_party_private"],
        )

    def as_payload(self) -> dict[str, bool]:
        return {
            "classifier_available": self.classifier_available,
            "credential_material": self.credential_material,
            "forwarded_private": self.forwarded_private,
            "third_party_private": self.third_party_private,
        }


@dataclass(frozen=True, slots=True)
class ExternalTurn:
    sequence: int
    parent_digest: str
    digest: str
    user_message: str
    assistant_reply: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.sequence, int)
            or isinstance(self.sequence, bool)
            or self.sequence < 1
        ):
            raise ExternalContextError("turn_sequence_out_of_contract")
        _sha(self.parent_digest, code="turn_parent_digest_out_of_contract")
        _sha(self.digest, code="turn_digest_out_of_contract")
        _bounded_text(
            self.user_message,
            maximum=MAX_CURRENT_MESSAGE_CHARACTERS,
            code="turn_user_message_out_of_contract",
        )
        _bounded_text(
            self.assistant_reply,
            maximum=MAX_REPLY_CHARACTERS,
            code="turn_assistant_reply_out_of_contract",
        )
        expected = turn_digest(
            sequence=self.sequence,
            parent_digest=self.parent_digest,
            user_message=self.user_message,
            assistant_reply=self.assistant_reply,
        )
        if self.digest != expected:
            raise ExternalContextError("turn_digest_mismatch")

    @classmethod
    def create(
        cls,
        *,
        sequence: int,
        parent_digest: str,
        user_message: str,
        assistant_reply: str,
    ) -> ExternalTurn:
        return cls(
            sequence=sequence,
            parent_digest=parent_digest,
            digest=turn_digest(
                sequence=sequence,
                parent_digest=parent_digest,
                user_message=user_message,
                assistant_reply=assistant_reply,
            ),
            user_message=user_message,
            assistant_reply=assistant_reply,
        )

    @classmethod
    def from_payload(cls, payload: object) -> ExternalTurn:
        required = {
            "assistant_reply",
            "digest",
            "parent_digest",
            "sequence",
            "user_message",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise ExternalContextError("turn_fields_out_of_contract")
        return cls(
            sequence=payload["sequence"],  # type: ignore[arg-type]
            parent_digest=payload["parent_digest"],  # type: ignore[arg-type]
            digest=payload["digest"],  # type: ignore[arg-type]
            user_message=payload["user_message"],  # type: ignore[arg-type]
            assistant_reply=payload["assistant_reply"],  # type: ignore[arg-type]
        )

    def as_payload(self) -> dict[str, object]:
        return {
            "assistant_reply": self.assistant_reply,
            "digest": self.digest,
            "parent_digest": self.parent_digest,
            "sequence": self.sequence,
            "user_message": self.user_message,
        }


@dataclass(frozen=True, slots=True)
class ExternalSummary:
    summary_version: int
    covered_start: int
    covered_end: int
    covered_terminal_digest: str
    profile_revisions: tuple[int, ...]
    content: str
    digest: str

    def __post_init__(self) -> None:
        for value, code in (
            (self.summary_version, "summary_version_out_of_contract"),
            (self.covered_start, "summary_range_out_of_contract"),
            (self.covered_end, "summary_range_out_of_contract"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ExternalContextError(code)
        if self.covered_start != 1 or self.covered_end < self.covered_start:
            raise ExternalContextError("summary_range_out_of_contract")
        _sha(
            self.covered_terminal_digest,
            code="summary_terminal_digest_out_of_contract",
        )
        _sha(self.digest, code="summary_digest_out_of_contract")
        _bounded_text(
            self.content,
            maximum=MAX_SUMMARY_CHARACTERS,
            code="summary_content_out_of_contract",
        )
        invalid_profile_revisions = any(
            not isinstance(item, int) or isinstance(item, bool) or item < 1
            for item in self.profile_revisions
        )
        if (
            len(self.profile_revisions) > MAX_SUMMARY_PROFILE_REVISIONS
            or invalid_profile_revisions
            or len(set(self.profile_revisions)) != len(self.profile_revisions)
            or tuple(sorted(self.profile_revisions)) != self.profile_revisions
        ):
            raise ExternalContextError("summary_profile_revisions_out_of_contract")
        expected = summary_digest(
            content=self.content,
            covered_start=self.covered_start,
            covered_end=self.covered_end,
            covered_terminal_digest=self.covered_terminal_digest,
            profile_revisions=self.profile_revisions,
            summary_version=self.summary_version,
        )
        if self.digest != expected:
            raise ExternalContextError("summary_digest_mismatch")

    @classmethod
    def create(
        cls,
        *,
        summary_version: int,
        covered_start: int,
        covered_end: int,
        covered_terminal_digest: str,
        profile_revisions: tuple[int, ...],
        content: str,
    ) -> ExternalSummary:
        return cls(
            summary_version=summary_version,
            covered_start=covered_start,
            covered_end=covered_end,
            covered_terminal_digest=covered_terminal_digest,
            profile_revisions=profile_revisions,
            content=content,
            digest=summary_digest(
                content=content,
                covered_start=covered_start,
                covered_end=covered_end,
                covered_terminal_digest=covered_terminal_digest,
                profile_revisions=profile_revisions,
                summary_version=summary_version,
            ),
        )

    @classmethod
    def from_payload(cls, payload: object) -> ExternalSummary:
        required = {
            "content",
            "covered_end",
            "covered_start",
            "covered_terminal_digest",
            "digest",
            "profile_revisions",
            "summary_version",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise ExternalContextError("summary_fields_out_of_contract")
        revisions = payload["profile_revisions"]
        if not isinstance(revisions, list):
            raise ExternalContextError("summary_profile_revisions_out_of_contract")
        return cls(
            summary_version=payload["summary_version"],  # type: ignore[arg-type]
            covered_start=payload["covered_start"],  # type: ignore[arg-type]
            covered_end=payload["covered_end"],  # type: ignore[arg-type]
            covered_terminal_digest=payload["covered_terminal_digest"],  # type: ignore[arg-type]
            profile_revisions=tuple(revisions),
            content=payload["content"],  # type: ignore[arg-type]
            digest=payload["digest"],  # type: ignore[arg-type]
        )

    def as_payload(self) -> dict[str, object]:
        return {
            "content": self.content,
            "covered_end": self.covered_end,
            "covered_start": self.covered_start,
            "covered_terminal_digest": self.covered_terminal_digest,
            "digest": self.digest,
            "profile_revisions": list(self.profile_revisions),
            "summary_version": self.summary_version,
        }


def projection_digest(messages: tuple[Mapping[str, str], ...]) -> str:
    return _digest(
        b"myuna-external-projection-v1",
        {"messages": [dict(item) for item in messages]},
    )


@dataclass(frozen=True, slots=True)
class ExternalTurnProvenance:
    epoch_id: str
    epoch_revision: int
    projection_digest: str
    sources: tuple[str, ...]
    profile_revisions: tuple[int, ...]
    summary_version: int | None
    recent_turn_start: int | None
    recent_turn_end: int | None
    schema: str = TURN_PROVENANCE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != TURN_PROVENANCE_SCHEMA:
            raise ExternalContextError("turn_provenance_schema_unknown")
        _safe_id(self.epoch_id, code="turn_provenance_epoch_out_of_contract")
        if (
            not isinstance(self.epoch_revision, int)
            or isinstance(self.epoch_revision, bool)
            or self.epoch_revision < 0
        ):
            raise ExternalContextError("turn_provenance_revision_out_of_contract")
        _sha(self.projection_digest, code="turn_provenance_digest_out_of_contract")
        if (
            not self.sources
            or len(set(self.sources)) != len(self.sources)
            or any(item not in PROJECTION_SOURCE_CATEGORIES for item in self.sources)
            or (
                "unknown" not in self.sources
                and "owner_current_message" not in self.sources
            )
            or ("unknown" in self.sources and len(self.sources) != 1)
        ):
            raise ExternalContextError("turn_provenance_sources_out_of_contract")
        if (
            len(self.profile_revisions) > MAX_SUMMARY_PROFILE_REVISIONS
            or tuple(sorted(set(self.profile_revisions))) != self.profile_revisions
            or any(
                not isinstance(item, int) or isinstance(item, bool) or item < 1
                for item in self.profile_revisions
            )
        ):
            raise ExternalContextError("turn_provenance_profiles_out_of_contract")
        if self.summary_version is not None and (
            not isinstance(self.summary_version, int)
            or isinstance(self.summary_version, bool)
            or self.summary_version < 1
        ):
            raise ExternalContextError("turn_provenance_summary_out_of_contract")
        if (self.recent_turn_start is None) != (self.recent_turn_end is None):
            raise ExternalContextError("turn_provenance_recent_range_out_of_contract")
        if self.recent_turn_start is not None and (
            not isinstance(self.recent_turn_start, int)
            or isinstance(self.recent_turn_start, bool)
            or not isinstance(self.recent_turn_end, int)
            or isinstance(self.recent_turn_end, bool)
            or self.recent_turn_start < 1
            or self.recent_turn_end < self.recent_turn_start
        ):
            raise ExternalContextError("turn_provenance_recent_range_out_of_contract")
        if ("owner_profile_selected" in self.sources) != bool(self.profile_revisions):
            raise ExternalContextError("turn_provenance_profiles_out_of_contract")
        if ("profile_derived_summary" in self.sources) != (self.summary_version is not None):
            raise ExternalContextError("turn_provenance_summary_out_of_contract")
        if ("ordinary_external_turn" in self.sources) != (self.recent_turn_start is not None):
            raise ExternalContextError("turn_provenance_recent_range_out_of_contract")

    @classmethod
    def from_payload(cls, payload: object) -> "ExternalTurnProvenance":
        required = {
            "epoch_id",
            "epoch_revision",
            "profile_revisions",
            "projection_digest",
            "recent_turn_end",
            "recent_turn_start",
            "schema",
            "sources",
            "summary_version",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise ExternalContextError("turn_provenance_fields_out_of_contract")
        if not isinstance(payload["sources"], list) or not isinstance(
            payload["profile_revisions"], list
        ):
            raise ExternalContextError("turn_provenance_fields_out_of_contract")
        return cls(
            epoch_id=payload["epoch_id"],
            epoch_revision=payload["epoch_revision"],
            projection_digest=payload["projection_digest"],
            sources=tuple(payload["sources"]),
            profile_revisions=tuple(payload["profile_revisions"]),
            summary_version=payload["summary_version"],
            recent_turn_start=payload["recent_turn_start"],
            recent_turn_end=payload["recent_turn_end"],
            schema=payload["schema"],
        )

    def as_payload(self) -> dict[str, object]:
        return {
            "epoch_id": self.epoch_id,
            "epoch_revision": self.epoch_revision,
            "profile_revisions": list(self.profile_revisions),
            "projection_digest": self.projection_digest,
            "recent_turn_end": self.recent_turn_end,
            "recent_turn_start": self.recent_turn_start,
            "schema": self.schema,
            "sources": list(self.sources),
            "summary_version": self.summary_version,
        }


def summary_job_digest(payload: Mapping[str, object]) -> str:
    return _digest(b"myuna-external-summary-job-v1", payload)


@dataclass(frozen=True, slots=True)
class ExternalSummaryJob:
    epoch_id: str
    base_revision: int
    summary_version: int
    covered_start: int
    covered_end: int
    covered_terminal_digest: str
    profile_revisions: tuple[int, ...]
    prior_summary: ExternalSummary | None
    turns: tuple[ExternalTurn, ...]
    digest: str
    schema: str = SUMMARY_JOB_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SUMMARY_JOB_SCHEMA:
            raise ExternalContextError("summary_job_schema_unknown")
        _safe_id(self.epoch_id, code="summary_job_epoch_out_of_contract")
        for value in (
            self.base_revision,
            self.summary_version,
            self.covered_start,
            self.covered_end,
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ExternalContextError("summary_job_range_out_of_contract")
        if (
            self.covered_start != 1
            or self.covered_end < self.covered_start
            or not self.turns
        ):
            raise ExternalContextError("summary_job_range_out_of_contract")
        _sha(self.covered_terminal_digest, code="summary_job_terminal_out_of_contract")
        _sha(self.digest, code="summary_job_digest_out_of_contract")
        expected_first = (
            1 if self.prior_summary is None else self.prior_summary.covered_end + 1
        )
        expected_version = (
            1
            if self.prior_summary is None
            else self.prior_summary.summary_version + 1
        )
        if self.summary_version != expected_version:
            raise ExternalContextError("summary_job_version_out_of_contract")
        if (
            self.turns[0].sequence != expected_first
            or self.turns[-1].sequence != self.covered_end
        ):
            raise ExternalContextError("summary_job_range_out_of_contract")
        previous = (
            ZERO_DIGEST
            if self.prior_summary is None
            else self.prior_summary.covered_terminal_digest
        )
        for turn in self.turns:
            if turn.parent_digest != previous:
                raise ExternalContextError("summary_job_turn_chain_mismatch")
            previous = turn.digest
        if previous != self.covered_terminal_digest:
            raise ExternalContextError("summary_job_terminal_mismatch")
        if (
            len(self.turns) > MAX_SUMMARY_JOB_TURNS
            or sum(
                len(turn.user_message) + len(turn.assistant_reply)
                for turn in self.turns
            )
            > MAX_SUMMARY_SOURCE_CHARACTERS
        ):
            raise ExternalContextError("summary_job_capacity_exceeded")
        if (
            tuple(sorted(set(self.profile_revisions))) != self.profile_revisions
            or any(
                not isinstance(item, int) or isinstance(item, bool) or item < 1
                for item in self.profile_revisions
            )
        ):
            raise ExternalContextError("summary_job_profiles_out_of_contract")
        expected = summary_job_digest(self.digest_payload())
        if self.digest != expected:
            raise ExternalContextError("summary_job_digest_mismatch")

    def digest_payload(self) -> dict[str, object]:
        return {
            "base_revision": self.base_revision,
            "covered_end": self.covered_end,
            "covered_start": self.covered_start,
            "covered_terminal_digest": self.covered_terminal_digest,
            "epoch_id": self.epoch_id,
            "prior_summary": (
                None if self.prior_summary is None else self.prior_summary.as_payload()
            ),
            "profile_revisions": list(self.profile_revisions),
            "schema": self.schema,
            "summary_version": self.summary_version,
            "turns": [turn.as_payload() for turn in self.turns],
        }

    @classmethod
    def create(
        cls,
        *,
        epoch_id: str,
        base_revision: int,
        summary_version: int,
        covered_end: int,
        covered_terminal_digest: str,
        profile_revisions: tuple[int, ...],
        prior_summary: ExternalSummary | None,
        turns: tuple[ExternalTurn, ...],
    ) -> "ExternalSummaryJob":
        payload = {
            "base_revision": base_revision,
            "covered_end": covered_end,
            "covered_start": 1,
            "covered_terminal_digest": covered_terminal_digest,
            "epoch_id": epoch_id,
            "prior_summary": (
                None if prior_summary is None else prior_summary.as_payload()
            ),
            "profile_revisions": list(profile_revisions),
            "schema": SUMMARY_JOB_SCHEMA,
            "summary_version": summary_version,
            "turns": [turn.as_payload() for turn in turns],
        }
        return cls(
            epoch_id=epoch_id,
            base_revision=base_revision,
            summary_version=summary_version,
            covered_start=1,
            covered_end=covered_end,
            covered_terminal_digest=covered_terminal_digest,
            profile_revisions=profile_revisions,
            prior_summary=prior_summary,
            turns=turns,
            digest=summary_job_digest(payload),
        )

    @classmethod
    def from_payload(cls, payload: object) -> "ExternalSummaryJob":
        required = {
            "base_revision",
            "covered_end",
            "covered_start",
            "covered_terminal_digest",
            "digest",
            "epoch_id",
            "prior_summary",
            "profile_revisions",
            "schema",
            "summary_version",
            "turns",
        }
        if (
            not isinstance(payload, Mapping)
            or set(payload) != required
            or not isinstance(payload["turns"], list)
            or not isinstance(payload["profile_revisions"], list)
        ):
            raise ExternalContextError("summary_job_fields_out_of_contract")
        prior = (
            None
            if payload["prior_summary"] is None
            else ExternalSummary.from_payload(payload["prior_summary"])
        )
        return cls(
            epoch_id=payload["epoch_id"],
            base_revision=payload["base_revision"],
            summary_version=payload["summary_version"],
            covered_start=payload["covered_start"],
            covered_end=payload["covered_end"],
            covered_terminal_digest=payload["covered_terminal_digest"],
            profile_revisions=tuple(payload["profile_revisions"]),
            prior_summary=prior,
            turns=tuple(ExternalTurn.from_payload(item) for item in payload["turns"]),
            digest=payload["digest"],
            schema=payload["schema"],
        )

    def as_payload(self) -> dict[str, object]:
        return {**self.digest_payload(), "digest": self.digest}


@dataclass(frozen=True, slots=True)
class ExternalSummaryCandidate:
    job_digest: str
    summary: ExternalSummary
    schema: str = SUMMARY_CANDIDATE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SUMMARY_CANDIDATE_SCHEMA:
            raise ExternalContextError("summary_candidate_schema_unknown")
        _sha(self.job_digest, code="summary_candidate_job_out_of_contract")

    @classmethod
    def from_payload(cls, payload: object) -> "ExternalSummaryCandidate":
        if not isinstance(payload, Mapping) or set(payload) != {
            "job_digest",
            "schema",
            "summary",
        }:
            raise ExternalContextError("summary_candidate_fields_out_of_contract")
        return cls(
            job_digest=payload["job_digest"],
            summary=ExternalSummary.from_payload(payload["summary"]),
            schema=payload["schema"],
        )

    def as_payload(self) -> dict[str, object]:
        return {
            "job_digest": self.job_digest,
            "schema": self.schema,
            "summary": self.summary.as_payload(),
        }


@dataclass(frozen=True, slots=True)
class ExternalContextEnvelope:
    epoch_id: str
    epoch_revision: int
    turn_sequence: int
    parent_digest: str
    channel_kind: str
    principal_id: str
    namespace_id: str
    current_message: str
    current_message_digest: str
    summary: ExternalSummary | None
    recent_turns: tuple[ExternalTurn, ...]
    safety: EgressSafetySignals
    visual_evidence: VisualEvidence | None = None
    projection_policy_version: str = EXTERNAL_PROJECTION_POLICY
    schema: str = EXTERNAL_CONTEXT_SCHEMA

    def __post_init__(self) -> None:
        if self.visual_evidence is None:
            if self.schema != EXTERNAL_CONTEXT_SCHEMA:
                raise ExternalContextError("external_context_schema_unknown")
            if self.projection_policy_version not in {
                EXTERNAL_PROJECTION_POLICY,
                EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY,
            }:
                raise ExternalContextError("projection_policy_unknown")
        else:
            if self.schema != EXTERNAL_VISUAL_CONTEXT_SCHEMA:
                raise ExternalContextError("external_context_schema_unknown")
            if self.projection_policy_version != EXTERNAL_VISUAL_PROJECTION_POLICY:
                raise ExternalContextError("projection_policy_unknown")
        _safe_id(self.epoch_id, code="epoch_id_out_of_contract")
        for value, code in (
            (self.epoch_revision, "epoch_revision_out_of_contract"),
            (self.turn_sequence, "turn_sequence_out_of_contract"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ExternalContextError(code)
        _sha(self.parent_digest, code="epoch_parent_digest_out_of_contract")
        for value, code in (
            (self.principal_id, "principal_binding_out_of_contract"),
            (self.namespace_id, "namespace_binding_out_of_contract"),
        ):
            _safe_id(value, code=code)
        if self.channel_kind != "astrbot_telegram":
            raise ExternalContextError("external_channel_not_authorized")
        _bounded_text(
            self.current_message,
            maximum=MAX_CURRENT_MESSAGE_CHARACTERS,
            code="current_message_out_of_contract",
        )
        _sha(self.current_message_digest, code="current_message_digest_out_of_contract")
        recent_turn_limit, recent_character_limit = self._recent_limits()
        if len(self.recent_turns) > recent_turn_limit:
            raise ExternalContextError("recent_turn_count_exceeded")
        if (
            sum(
                len(item.user_message) + len(item.assistant_reply)
                for item in self.recent_turns
            )
            > recent_character_limit
        ):
            raise ExternalContextError("recent_turn_characters_exceeded")
        self._validate_chain()

    def _recent_limits(self) -> tuple[int, int]:
        if (
            self.visual_evidence is None
            and self.projection_policy_version
            == EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY
        ):
            return MAX_VERBATIM_RECENT_TURNS, MAX_VERBATIM_RECENT_CHARACTERS
        return MAX_RECENT_TURNS, MAX_RECENT_CHARACTERS

    def _validate_chain(self) -> None:
        if self.recent_turns:
            first = self.recent_turns[0]
            verbatim_chain = (
                self.projection_policy_version
                == EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY
                and first.sequence == 1
                and first.parent_digest == ZERO_DIGEST
            )
            expected_sequence = (
                1
                if verbatim_chain or self.summary is None
                else self.summary.covered_end + 1
            )
            expected_parent = (
                ZERO_DIGEST
                if verbatim_chain or self.summary is None
                else self.summary.covered_terminal_digest
            )
            if first.sequence != expected_sequence or first.parent_digest != expected_parent:
                raise ExternalContextError("recent_turn_chain_gap")
            previous = first
            for item in self.recent_turns[1:]:
                if item.sequence != previous.sequence + 1 or item.parent_digest != previous.digest:
                    raise ExternalContextError("recent_turn_chain_gap")
                previous = item
            if previous.sequence != self.turn_sequence or previous.digest != self.parent_digest:
                raise ExternalContextError("epoch_head_mismatch")
            if verbatim_chain and self.summary is not None:
                if self.summary.covered_end > self.turn_sequence:
                    raise ExternalContextError("verbatim_summary_chain_mismatch")
                covered = self.recent_turns[self.summary.covered_end - 1]
                if covered.digest != self.summary.covered_terminal_digest:
                    raise ExternalContextError("verbatim_summary_chain_mismatch")
            return
        if self.summary is not None:
            if (
                self.summary.covered_end != self.turn_sequence
                or self.summary.covered_terminal_digest != self.parent_digest
            ):
                raise ExternalContextError("summary_epoch_head_mismatch")
            return
        if self.turn_sequence != 0 or self.parent_digest != ZERO_DIGEST:
            raise ExternalContextError("empty_epoch_head_mismatch")

    @classmethod
    def from_payload(
        cls,
        payload: object,
        *,
        context: AuthenticatedConversationContext,
    ) -> ExternalContextEnvelope:
        if not isinstance(payload, Mapping):
            raise ExternalContextError("external_context_fields_out_of_contract")
        required = {
            "channel_kind",
            "current_message",
            "current_message_digest",
            "epoch_id",
            "epoch_revision",
            "namespace_id",
            "parent_digest",
            "principal_id",
            "projection_policy_version",
            "recent_turns",
            "safety",
            "schema",
            "summary",
            "turn_sequence",
        }
        schema = payload.get("schema")
        if schema == EXTERNAL_VISUAL_CONTEXT_SCHEMA:
            required.add("visual_evidence")
        elif schema != EXTERNAL_CONTEXT_SCHEMA:
            raise ExternalContextError("external_context_schema_unknown")
        if set(payload) != required:
            raise ExternalContextError("external_context_fields_out_of_contract")
        current_message = payload["current_message"]
        visual_payload = payload.get("visual_evidence")
        turns_payload = payload["recent_turns"]
        if not isinstance(turns_payload, list):
            raise ExternalContextError("recent_turns_out_of_contract")
        policy = payload["projection_policy_version"]
        recent_turn_limit = (
            MAX_VERBATIM_RECENT_TURNS
            if schema == EXTERNAL_CONTEXT_SCHEMA
            and policy == EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY
            else MAX_RECENT_TURNS
        )
        if len(turns_payload) > recent_turn_limit:
            raise ExternalContextError("recent_turn_count_exceeded")
        summary_payload = payload["summary"]
        visual_evidence = (
            None
            if visual_payload is None
            else VisualEvidence.from_payload(
                visual_payload,
                context=context,
                current_message=current_message,  # type: ignore[arg-type]
            )
        )
        envelope = cls(
            epoch_id=payload["epoch_id"],  # type: ignore[arg-type]
            epoch_revision=payload["epoch_revision"],  # type: ignore[arg-type]
            turn_sequence=payload["turn_sequence"],  # type: ignore[arg-type]
            parent_digest=payload["parent_digest"],  # type: ignore[arg-type]
            channel_kind=payload["channel_kind"],  # type: ignore[arg-type]
            principal_id=payload["principal_id"],  # type: ignore[arg-type]
            namespace_id=payload["namespace_id"],  # type: ignore[arg-type]
            current_message=current_message,  # type: ignore[arg-type]
            current_message_digest=payload["current_message_digest"],  # type: ignore[arg-type]
            summary=(
                None
                if summary_payload is None
                else ExternalSummary.from_payload(summary_payload)
            ),
            recent_turns=tuple(ExternalTurn.from_payload(item) for item in turns_payload),
            safety=EgressSafetySignals.from_payload(payload["safety"]),
            visual_evidence=visual_evidence,
            projection_policy_version=(
                payload["projection_policy_version"]  # type: ignore[arg-type]
            ),
            schema=payload["schema"],  # type: ignore[arg-type]
        )
        if (
            envelope.channel_kind != context.channel_kind
            or envelope.principal_id != context.principal_id
            or envelope.namespace_id != context.namespace_id
        ):
            raise ExternalContextError("external_context_binding_mismatch")
        expected_message_digest = current_message_digest(context, envelope.current_message)
        if envelope.current_message_digest != expected_message_digest:
            raise ExternalContextError("current_message_digest_mismatch")
        return envelope

    def as_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "channel_kind": self.channel_kind,
            "current_message": self.current_message,
            "current_message_digest": self.current_message_digest,
            "epoch_id": self.epoch_id,
            "epoch_revision": self.epoch_revision,
            "namespace_id": self.namespace_id,
            "parent_digest": self.parent_digest,
            "principal_id": self.principal_id,
            "projection_policy_version": self.projection_policy_version,
            "recent_turns": [item.as_payload() for item in self.recent_turns],
            "safety": self.safety.as_payload(),
            "schema": self.schema,
            "summary": None if self.summary is None else self.summary.as_payload(),
            "turn_sequence": self.turn_sequence,
        }
        if self.visual_evidence is not None:
            payload["visual_evidence"] = self.visual_evidence.as_payload()
        return payload
