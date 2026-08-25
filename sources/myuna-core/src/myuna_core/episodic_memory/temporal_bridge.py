from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import shlex
from typing import Mapping, Sequence

from myuna_core.active_temporal_context.protocol import ActiveSnapshotReceipt

from .contracts import CompleteTurn, EpisodicMemoryError, require_digest
from .temporal_validity import (
    TemporalEndpoint,
    TemporalIntervalEpisode,
    TemporalIntervalRevision,
)


TEMPORAL_INTERVAL_INDEX_SCHEMA = "myuna.p07-temporal-interval-index.v2"
MAX_LIFECYCLE_PAGE = 4


def _digest(label: str, payload: object) -> str:
    return sha256(
        label.encode("ascii")
        + b"\0"
        + json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _safe_transition(value: Mapping[str, object]) -> None:
    expected = {
        "category",
        "event_kind",
        "event_sequence",
        "expires_at",
        "fact_id",
        "occurred_at",
        "reason",
        "revision",
        "slot_key",
        "source_kind",
        "source_ref",
        "state",
        "supersedes_fact_id",
        "transition",
        "trusted_time_source_class",
        "valid_from",
        "valid_to",
    }
    if set(value) != expected:
        raise EpisodicMemoryError("temporal_transition_fields_rejected")


def _parse_time(value: object, code: str) -> datetime:
    if not isinstance(value, str):
        raise EpisodicMemoryError(code)
    try:
        selected = datetime.fromisoformat(value)
    except ValueError:
        raise EpisodicMemoryError(code) from None
    if selected.tzinfo is None or selected.utcoffset() is None:
        raise EpisodicMemoryError(code)
    return selected.astimezone(timezone.utc)


def _statement_from_source(turn: CompleteTurn) -> str:
    try:
        parts = shlex.split(turn.draft.owner.text, posix=True)
    except ValueError:
        raise EpisodicMemoryError("temporal_source_command_unparseable") from None
    if not parts or parts[0].casefold() != "/temporal" or len(parts) < 2:
        raise EpisodicMemoryError("temporal_source_command_unparseable")
    action = parts[1].casefold()
    if action == "add" and len(parts) >= 6:
        statement = " ".join(parts[5:])
    elif action in {"supersede", "refresh", "restore"} and len(parts) >= 7:
        statement = " ".join(parts[6:])
    else:
        raise EpisodicMemoryError("temporal_source_command_unparseable")
    if not statement or len(statement) > 4_000:
        raise EpisodicMemoryError("temporal_source_statement_rejected")
    return statement


def _state(transition: Mapping[str, object]) -> str | None:
    movement = transition["transition"]
    category = transition["category"]
    source_kind = transition["source_kind"]
    event_kind = transition["event_kind"]
    reason = transition["reason"]
    if movement == "active->expired":
        return "ended"
    if movement == "active->revoked":
        return "cancelled"
    if movement == "active->superseded+active" or source_kind in {
        "owner_refresh",
        "owner_restore",
    }:
        return "changed"
    if movement in {"proposed->active", "revoked->active(new_revision)"}:
        if source_kind == "owner_confirmation" or (
            event_kind in {"activate", "confirm", "restore"}
            and reason == "owner_confirmed"
        ):
            return "confirmed_started"
        if category == "temporary_plan":
            return "planned"
        return "observed"
    return None


@dataclass(frozen=True, slots=True)
class TemporalIntervalIndexSnapshot:
    after_event_sequence: int
    observed_watermark: int
    archive_head_digest: str
    episodes: tuple[TemporalIntervalEpisode, ...]
    unresolved_event_sequences: tuple[int, ...]
    blocked_interval_ids: tuple[str, ...]
    snapshot_digest: str
    schema: str = TEMPORAL_INTERVAL_INDEX_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != TEMPORAL_INTERVAL_INDEX_SCHEMA:
            raise EpisodicMemoryError("temporal_interval_index_schema_unknown")
        if (
            isinstance(self.after_event_sequence, bool)
            or not isinstance(self.after_event_sequence, int)
            or self.after_event_sequence < 0
            or isinstance(self.observed_watermark, bool)
            or not isinstance(self.observed_watermark, int)
            or self.observed_watermark < self.after_event_sequence
        ):
            raise EpisodicMemoryError("temporal_interval_cursor_invalid")
        require_digest(self.archive_head_digest, "temporal_interval_archive_head")
        if tuple(sorted(set(self.unresolved_event_sequences))) != (
            self.unresolved_event_sequences
        ):
            raise EpisodicMemoryError("temporal_interval_unresolved_invalid")
        if tuple(sorted(set(self.blocked_interval_ids))) != self.blocked_interval_ids:
            raise EpisodicMemoryError("temporal_interval_blocked_invalid")
        payload = self.semantic_payload()
        if self.snapshot_digest != _digest("myuna-p07-temporal-index-v2", payload):
            raise EpisodicMemoryError("temporal_interval_index_digest_mismatch")

    def semantic_payload(self) -> dict[str, object]:
        return {
            "after_event_sequence": self.after_event_sequence,
            "archive_head_digest": self.archive_head_digest,
            "blocked_interval_ids": list(self.blocked_interval_ids),
            "episodes": [item.payload() for item in self.episodes],
            "observed_watermark": self.observed_watermark,
            "schema": self.schema,
            "unresolved_event_sequences": list(self.unresolved_event_sequences),
        }

    def payload(self) -> dict[str, object]:
        return self.semantic_payload() | {"snapshot_digest": self.snapshot_digest}

    @classmethod
    def empty(
        cls,
        archive_head_digest: str,
        *,
        initial_event_sequence: int = 0,
    ) -> TemporalIntervalIndexSnapshot:
        if (
            isinstance(initial_event_sequence, bool)
            or not isinstance(initial_event_sequence, int)
            or initial_event_sequence < 0
        ):
            raise EpisodicMemoryError("temporal_interval_cursor_invalid")
        semantic = {
            "after_event_sequence": initial_event_sequence,
            "archive_head_digest": archive_head_digest,
            "blocked_interval_ids": [],
            "episodes": [],
            "observed_watermark": initial_event_sequence,
            "schema": TEMPORAL_INTERVAL_INDEX_SCHEMA,
            "unresolved_event_sequences": [],
        }
        return cls(
            initial_event_sequence,
            initial_event_sequence,
            archive_head_digest,
            (),
            (),
            (),
            _digest("myuna-p07-temporal-index-v2", semantic),
        )

    @classmethod
    def from_payload(cls, payload: object) -> TemporalIntervalIndexSnapshot:
        expected = {
            "after_event_sequence",
            "archive_head_digest",
            "blocked_interval_ids",
            "episodes",
            "observed_watermark",
            "schema",
            "snapshot_digest",
            "unresolved_event_sequences",
        }
        if (
            not isinstance(payload, Mapping)
            or set(payload) != expected
            or not isinstance(payload["episodes"], list)
            or not isinstance(payload["unresolved_event_sequences"], list)
            or not isinstance(payload["blocked_interval_ids"], list)
        ):
            raise EpisodicMemoryError("temporal_interval_index_payload_rejected")
        return cls(
            after_event_sequence=payload["after_event_sequence"],  # type: ignore[arg-type]
            observed_watermark=payload["observed_watermark"],  # type: ignore[arg-type]
            archive_head_digest=payload["archive_head_digest"],  # type: ignore[arg-type]
            episodes=tuple(
                TemporalIntervalEpisode.from_payload(item)
                for item in payload["episodes"]
            ),
            unresolved_event_sequences=tuple(
                payload["unresolved_event_sequences"]  # type: ignore[arg-type]
            ),
            blocked_interval_ids=tuple(
                payload["blocked_interval_ids"]  # type: ignore[arg-type]
            ),
            snapshot_digest=payload["snapshot_digest"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )

    def audit_projection(self) -> dict[str, object]:
        return {
            "after_event_sequence": self.after_event_sequence,
            "blocked_interval_count": len(self.blocked_interval_ids),
            "episode_count": len(self.episodes),
            "observed_watermark": self.observed_watermark,
            "snapshot_digest": self.snapshot_digest,
            "unresolved_event_count": len(self.unresolved_event_sequences),
        }


def advance_temporal_interval_index(
    prior: TemporalIntervalIndexSnapshot,
    transitions: Sequence[Mapping[str, object]],
    *,
    observed_watermark: int,
    has_more: bool,
    archive_turns: Sequence[CompleteTurn],
    archive_head_digest: str,
    active_snapshot_receipt: ActiveSnapshotReceipt,
) -> TemporalIntervalIndexSnapshot:
    if not isinstance(active_snapshot_receipt, ActiveSnapshotReceipt) or not (
        active_snapshot_receipt.matches_lifecycle_page(
            after_event_sequence=prior.after_event_sequence,
            transitions=transitions,
            lifecycle_watermark=observed_watermark,
            lifecycle_has_more=has_more,
        )
    ):
        raise EpisodicMemoryError("temporal_active_snapshot_receipt_rejected")
    if len(transitions) > MAX_LIFECYCLE_PAGE:
        raise EpisodicMemoryError("temporal_transition_page_oversize")
    if observed_watermark < prior.after_event_sequence:
        raise EpisodicMemoryError("temporal_transition_watermark_regressed")
    archive_prefixes = {"0" * 64, *(turn.turn_digest for turn in archive_turns)}
    if prior.archive_head_digest not in archive_prefixes:
        raise EpisodicMemoryError("temporal_interval_archive_drifted")
    by_source_ref = {
        turn.draft.turn_id.removeprefix("turn-"): turn
        for turn in archive_turns
        if "control_temporal_isolated" in turn.draft.provenance_categories
    }
    episodes = {item.interval_id: item for item in prior.episodes}
    unresolved = set(prior.unresolved_event_sequences)
    blocked = set(prior.blocked_interval_ids)
    expected_sequence = prior.after_event_sequence + 1
    for transition in transitions:
        _safe_transition(transition)
        sequence = transition["event_sequence"]
        if sequence != expected_sequence:
            raise EpisodicMemoryError("temporal_transition_sequence_drifted")
        expected_sequence += 1
        slot_key = transition["slot_key"]
        source_ref = transition["source_ref"]
        if not isinstance(slot_key, str) or not isinstance(source_ref, str):
            raise EpisodicMemoryError("temporal_transition_identity_rejected")
        interval_id = "ti_" + _digest(
            "myuna-p07-p08-slot-v1",
            {"slot_key": slot_key},
        )[:32]
        selected_state = _state(transition)
        source_turn = by_source_ref.get(source_ref)
        if selected_state is None or source_turn is None or interval_id in blocked:
            unresolved.add(sequence)
            blocked.add(interval_id)
            continue
        try:
            statement = _statement_from_source(source_turn)
        except EpisodicMemoryError:
            unresolved.add(sequence)
            blocked.add(interval_id)
            continue
        prior_episode = episodes.get(interval_id)
        prior_revisions = () if prior_episode is None else prior_episode.revisions
        previous_digest = (
            "0" * 64 if not prior_revisions else prior_revisions[-1].revision_digest
        )
        binding = source_turn.draft.time_binding
        if binding.status != "exact":
            unresolved.add(sequence)
            blocked.add(interval_id)
            continue
        start = TemporalEndpoint(
            kind="exact",
            calendar_zone=binding.calendar_zone,
            trusted_time_binding_digest=binding.binding_digest,
            uncertainty_microseconds=binding.uncertainty_microseconds or 0,
            instant_utc=_parse_time(transition["valid_from"], "temporal_valid_from_invalid"),
        )
        if selected_state == "cancelled":
            end = TemporalEndpoint(
                kind="unknown",
                calendar_zone=binding.calendar_zone,
                trusted_time_binding_digest=binding.binding_digest,
                uncertainty_microseconds=binding.uncertainty_microseconds or 0,
            )
        else:
            endpoint_value = transition["valid_to"] or transition["expires_at"]
            end = TemporalEndpoint(
                kind="exact",
                calendar_zone=binding.calendar_zone,
                trusted_time_binding_digest=binding.binding_digest,
                uncertainty_microseconds=binding.uncertainty_microseconds or 0,
                instant_utc=_parse_time(endpoint_value, "temporal_valid_to_invalid"),
            )
        revision = TemporalIntervalRevision(
            interval_id=interval_id,
            revision=len(prior_revisions) + 1,
            state=selected_state,
            statement=statement,
            conflict_key=slot_key,
            start=start,
            end=end,
            source_turn_sequences=(source_turn.draft.sequence,),
            source_turn_digests=(source_turn.turn_digest,),
            p08_revision=transition["revision"],  # type: ignore[arg-type]
            p08_event_sequence=sequence,  # type: ignore[arg-type]
            p08_event_kind=transition["event_kind"],  # type: ignore[arg-type]
            previous_revision_digest=previous_digest,
        )
        episodes[interval_id] = TemporalIntervalEpisode.create(
            (*prior_revisions, revision)
        )
    next_after = prior.after_event_sequence
    if transitions:
        next_after = transitions[-1]["event_sequence"]  # type: ignore[assignment]
    if not has_more and next_after != observed_watermark:
        raise EpisodicMemoryError("temporal_transition_terminal_gap")
    semantic = {
        "after_event_sequence": next_after,
        "archive_head_digest": archive_head_digest,
        "blocked_interval_ids": sorted(blocked),
        "episodes": [episodes[key].payload() for key in sorted(episodes)],
        "observed_watermark": observed_watermark,
        "schema": TEMPORAL_INTERVAL_INDEX_SCHEMA,
        "unresolved_event_sequences": sorted(unresolved),
    }
    return TemporalIntervalIndexSnapshot(
        after_event_sequence=next_after,
        observed_watermark=observed_watermark,
        archive_head_digest=archive_head_digest,
        episodes=tuple(episodes[key] for key in sorted(episodes)),
        unresolved_event_sequences=tuple(sorted(unresolved)),
        blocked_interval_ids=tuple(sorted(blocked)),
        snapshot_digest=_digest("myuna-p07-temporal-index-v2", semantic),
    )


def rebind_temporal_interval_archive_head(
    prior: TemporalIntervalIndexSnapshot,
    *,
    archive_turns: Sequence[CompleteTurn],
    archive_head_digest: str,
) -> TemporalIntervalIndexSnapshot:
    """Rebind only the raw archive head; no P08 lifecycle page is admitted."""

    archive_prefixes = {"0" * 64, *(turn.turn_digest for turn in archive_turns)}
    if prior.archive_head_digest not in archive_prefixes:
        raise EpisodicMemoryError("temporal_interval_archive_drifted")
    require_digest(archive_head_digest, "temporal_interval_archive_head")
    semantic = prior.semantic_payload() | {
        "archive_head_digest": archive_head_digest,
    }
    return TemporalIntervalIndexSnapshot(
        after_event_sequence=prior.after_event_sequence,
        observed_watermark=prior.observed_watermark,
        archive_head_digest=archive_head_digest,
        episodes=prior.episodes,
        unresolved_event_sequences=prior.unresolved_event_sequences,
        blocked_interval_ids=prior.blocked_interval_ids,
        snapshot_digest=_digest("myuna-p07-temporal-index-v2", semantic),
    )


class TemporalIntervalIndexStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def read(
        self,
        *,
        archive_head_digest: str,
        initial_event_sequence: int = 0,
    ) -> TemporalIntervalIndexSnapshot:
        if not self.path.exists():
            return TemporalIntervalIndexSnapshot.empty(
                archive_head_digest,
                initial_event_sequence=initial_event_sequence,
            )
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise EpisodicMemoryError("temporal_interval_index_unreadable") from None
        return TemporalIntervalIndexSnapshot.from_payload(payload)

    def write(self, snapshot: TemporalIntervalIndexSnapshot) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = self.path.with_name(self.path.name + ".tmp")
        data = json.dumps(
            snapshot.payload(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        descriptor = os.open(
            temporary,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except BaseException:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise
