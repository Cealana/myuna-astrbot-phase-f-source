from .audit import TrustedTimeAuditEvent, TrustedTimeAuditSink
from .contracts import (
    P08_CONSUMER_ID,
    SynchronizationEvidence,
    TrustedTimePolicy,
    TrustedTimeWatermark,
    UtcObservation,
    UtcObservationPort,
)
from .continuity import (
    ASSESSMENT_SCHEMA,
    AUTHORIZATION_SCHEMA,
    CONTINUITY_EXTENSION_SCHEMA,
    RECEIPT_SCHEMA,
    RECONCILIATION_SCHEMA,
    ContinuityAssessment,
    ForwardContinuityAuthorization,
    ForwardContinuityReconciliation,
    ForwardContinuityTransitionReceipt,
)
from .errors import (
    TrustedTimeAuditUnavailableError,
    TrustedTimeContinuityIneligibleError,
    TrustedTimeDriftError,
    TrustedTimeError,
    TrustedTimePersistenceAmbiguousError,
    TrustedTimePermissionError,
    TrustedTimeRegressionError,
    TrustedTimeSequenceExhaustedError,
    TrustedTimeSourceDriftError,
    TrustedTimeStateCorruptError,
    TrustedTimeStatePermissionError,
    TrustedTimeTimeoutError,
    TrustedTimeTransitionAmbiguousError,
    TrustedTimeTransitionExpiredError,
    TrustedTimeTransitionRejectedError,
    TrustedTimeTransitionReplayError,
    TrustedTimeUnavailableError,
    TrustedTimeUncertainError,
    TrustedTimeUnsynchronizedError,
)
from .provider import DurableTrustedTimeProvider
from .source import SystemUtcObservationSource
from .linux import LinuxAdjtimexSynchronizationProbe


def __getattr__(name: str):
    if name == "TrustedTimeCapability":
        from .runtime import TrustedTimeCapability

        return TrustedTimeCapability
    raise AttributeError(name)


__all__ = [
    "ASSESSMENT_SCHEMA",
    "AUTHORIZATION_SCHEMA",
    "CONTINUITY_EXTENSION_SCHEMA",
    "ContinuityAssessment",
    "DurableTrustedTimeProvider",
    "ForwardContinuityAuthorization",
    "ForwardContinuityReconciliation",
    "ForwardContinuityTransitionReceipt",
    "RECEIPT_SCHEMA",
    "RECONCILIATION_SCHEMA",
    "P08_CONSUMER_ID",
    "LinuxAdjtimexSynchronizationProbe",
    "SynchronizationEvidence",
    "SystemUtcObservationSource",
    "TrustedTimeAuditEvent",
    "TrustedTimeAuditSink",
    "TrustedTimeAuditUnavailableError",
    "TrustedTimeCapability",
    "TrustedTimeContinuityIneligibleError",
    "TrustedTimeDriftError",
    "TrustedTimeError",
    "TrustedTimePersistenceAmbiguousError",
    "TrustedTimePermissionError",
    "TrustedTimePolicy",
    "TrustedTimeRegressionError",
    "TrustedTimeSequenceExhaustedError",
    "TrustedTimeSourceDriftError",
    "TrustedTimeStateCorruptError",
    "TrustedTimeStatePermissionError",
    "TrustedTimeTimeoutError",
    "TrustedTimeTransitionAmbiguousError",
    "TrustedTimeTransitionExpiredError",
    "TrustedTimeTransitionRejectedError",
    "TrustedTimeTransitionReplayError",
    "TrustedTimeUnavailableError",
    "TrustedTimeUncertainError",
    "TrustedTimeUnsynchronizedError",
    "TrustedTimeWatermark",
    "UtcObservation",
    "UtcObservationPort",
]
