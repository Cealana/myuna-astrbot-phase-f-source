from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Protocol


_TYPED = re.compile(r"^[a-z][a-z0-9_]{2,127}$")


class PolicyOverlayTransactionRejected(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        activation_failure_code: str | None = None,
        rollback_failure_code: str | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.activation_failure_code = activation_failure_code
        self.rollback_failure_code = rollback_failure_code


def typed_exception_code(exc: BaseException, *, fallback: str) -> str:
    candidate = getattr(exc, "code", None)
    if isinstance(candidate, str) and _TYPED.fullmatch(candidate) is not None:
        return candidate
    return fallback


@dataclass(frozen=True, slots=True)
class PolicyOverlayObservation:
    state_digest: str
    service_restart_total: int
    services_stable: bool


@dataclass(frozen=True, slots=True)
class PolicyOverlayTransactionResult:
    attempt: int
    observation: PolicyOverlayObservation


class PolicyOverlayTransactionBackend(Protocol):
    def create_plan_bound_backup(self) -> None: ...

    def consume_attempt(self) -> int: ...

    def install_inactive_releases(self) -> None: ...

    def stop_target_services(self) -> None: ...

    def verify_target_services_stopped(self) -> None: ...

    def apply_target(self) -> None: ...

    def daemon_reload(self) -> None: ...

    def start_target_services(self) -> None: ...

    def observe_target(self) -> PolicyOverlayObservation: ...

    def restore_prestate(self) -> None: ...

    def observe_prestate(self) -> PolicyOverlayObservation: ...

    def expected_prestate(self) -> PolicyOverlayObservation: ...


def _verify_pair(
    first: PolicyOverlayObservation,
    second: PolicyOverlayObservation,
    *,
    expected_digest: str | None,
    failure_code: str,
) -> None:
    if (
        not first.services_stable
        or not second.services_stable
        or first.state_digest != second.state_digest
        or first.service_restart_total != second.service_restart_total
        or (expected_digest is not None and first.state_digest != expected_digest)
    ):
        raise PolicyOverlayTransactionRejected(failure_code)


class AtomicPolicyOverlayTransaction:
    """Backup-first activation with one bounded functional rollback."""

    def __init__(self, backend: PolicyOverlayTransactionBackend) -> None:
        self.backend = backend

    def run(self) -> PolicyOverlayTransactionResult:
        self.backend.create_plan_bound_backup()
        attempt = self.backend.consume_attempt()
        try:
            self.backend.install_inactive_releases()
            self.backend.stop_target_services()
            self.backend.verify_target_services_stopped()
            self.backend.apply_target()
            self.backend.daemon_reload()
            self.backend.start_target_services()
            first = self.backend.observe_target()
            second = self.backend.observe_target()
            _verify_pair(
                first,
                second,
                expected_digest=None,
                failure_code="policy_overlay_target_unstable",
            )
            return PolicyOverlayTransactionResult(
                attempt=attempt,
                observation=second,
            )
        except Exception as activation_exc:
            activation_code = typed_exception_code(
                activation_exc,
                fallback="policy_overlay_activation_failed",
            )
            try:
                self.backend.stop_target_services()
                self.backend.verify_target_services_stopped()
                self.backend.restore_prestate()
                self.backend.daemon_reload()
                self.backend.start_target_services()
                expected = self.backend.expected_prestate()
                first = self.backend.observe_prestate()
                second = self.backend.observe_prestate()
                _verify_pair(
                    first,
                    second,
                    expected_digest=expected.state_digest,
                    failure_code="policy_overlay_rollback_unstable",
                )
            except Exception as rollback_exc:
                raise PolicyOverlayTransactionRejected(
                    "policy_overlay_rollback_failed",
                    activation_failure_code=activation_code,
                    rollback_failure_code=typed_exception_code(
                        rollback_exc,
                        fallback="policy_overlay_rollback_failed",
                    ),
                ) from rollback_exc
            raise PolicyOverlayTransactionRejected(
                "policy_overlay_activation_failed_rollback_verified",
                activation_failure_code=activation_code,
            ) from activation_exc
