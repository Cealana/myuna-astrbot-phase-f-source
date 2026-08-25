from __future__ import annotations


class TrustedTimeError(RuntimeError):
    """A fixed, content-free trusted-time failure."""

    code = "trusted_time_error"
    retryable = False

    def __init__(self) -> None:
        super().__init__(self.code)

    def public_payload(self) -> dict[str, object]:
        return {"code": self.code, "retryable": self.retryable}


class TrustedTimePermissionError(TrustedTimeError):
    code = "trusted_time_permission_denied"


class TrustedTimeUnavailableError(TrustedTimeError):
    code = "trusted_time_unavailable"
    retryable = True


class TrustedTimeTimeoutError(TrustedTimeError):
    code = "trusted_time_timeout"
    retryable = True


class TrustedTimeUnsynchronizedError(TrustedTimeError):
    code = "trusted_time_unsynchronized"
    retryable = True


class TrustedTimeUncertainError(TrustedTimeError):
    code = "trusted_time_uncertainty_exceeded"
    retryable = True


class TrustedTimeRegressionError(TrustedTimeError):
    code = "trusted_time_regression"


class TrustedTimeDriftError(TrustedTimeError):
    code = "trusted_time_drift_exceeded"
    retryable = True


class TrustedTimeSourceDriftError(TrustedTimeError):
    code = "trusted_time_source_drift"


class TrustedTimeStateCorruptError(TrustedTimeError):
    code = "trusted_time_state_corrupt"


class TrustedTimeStatePermissionError(TrustedTimeError):
    code = "trusted_time_state_permission_drift"


class TrustedTimePersistenceAmbiguousError(TrustedTimeError):
    code = "trusted_time_persistence_ambiguous"
    retryable = True


class TrustedTimeAuditUnavailableError(TrustedTimeError):
    code = "trusted_time_audit_unavailable"
    retryable = True


class TrustedTimeSequenceExhaustedError(TrustedTimeError):
    code = "trusted_time_sequence_exhausted"


class TrustedTimeContinuityIneligibleError(TrustedTimeError):
    code = "trusted_time_continuity_ineligible"


class TrustedTimeTransitionRejectedError(TrustedTimeError):
    code = "trusted_time_transition_rejected"


class TrustedTimeTransitionReplayError(TrustedTimeError):
    code = "trusted_time_transition_replay"


class TrustedTimeTransitionExpiredError(TrustedTimeError):
    code = "trusted_time_transition_expired"


class TrustedTimeTransitionAmbiguousError(TrustedTimePersistenceAmbiguousError):
    code = "trusted_time_transition_persistence_ambiguous"
    retryable = False
