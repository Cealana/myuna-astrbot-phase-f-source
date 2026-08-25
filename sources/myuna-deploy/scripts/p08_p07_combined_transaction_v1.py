from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Callable, Protocol


_TYPED = re.compile(r"^[a-z][a-z0-9_]{2,127}$")
APPLY_ORDER = ("p07", "telegram_plugin", "p08")
ROLLBACK_ORDER = tuple(reversed(APPLY_ORDER))


class CombinedTransactionRejected(RuntimeError):
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


def _typed(exc: BaseException, fallback: str) -> str:
    value = getattr(exc, "code", None)
    return value if isinstance(value, str) and _TYPED.fullmatch(value) else fallback


class CombinedBackend(Protocol):
    def capture_prestate(self) -> str: ...

    def verify_preflight(self, prestate_digest: str) -> None: ...

    def apply_p07(self) -> None: ...

    def apply_telegram_plugin(self) -> None: ...

    def apply_p08(self) -> None: ...

    def observe_target(self) -> str: ...

    def rollback_p08(self) -> None: ...

    def rollback_telegram_plugin(self) -> None: ...

    def rollback_p07(self) -> None: ...

    def observe_prestate(self, expected_digest: str) -> str: ...


Journal = Callable[[str, str], None]


@dataclass(frozen=True, slots=True)
class CombinedTransactionResult:
    apply_order: tuple[str, ...]
    combined_release_set_id: str
    rollback_order: tuple[str, ...]
    target_observation_digest: str


class CombinedReleaseSetTransaction:
    def __init__(
        self,
        backend: CombinedBackend,
        *,
        combined_release_set_id: str,
        journal: Journal | None = None,
    ) -> None:
        self.backend = backend
        self.combined_release_set_id = combined_release_set_id
        self.journal = journal or (lambda _phase, _status: None)

    def run(self) -> CombinedTransactionResult:
        prestate_digest = self.backend.capture_prestate()
        self.backend.verify_preflight(prestate_digest)
        attempted: list[str] = []
        try:
            for phase, action in (
                ("p07", self.backend.apply_p07),
                ("telegram_plugin", self.backend.apply_telegram_plugin),
                ("p08", self.backend.apply_p08),
            ):
                attempted.append(phase)
                self.journal(phase, "applying")
                action()
                self.journal(phase, "applied")
            observation = self.backend.observe_target()
            self.journal("combined", "accepted")
            return CombinedTransactionResult(
                apply_order=APPLY_ORDER,
                combined_release_set_id=self.combined_release_set_id,
                rollback_order=ROLLBACK_ORDER,
                target_observation_digest=observation,
            )
        except BaseException as activation_error:
            activation_code = _typed(
                activation_error,
                f"{attempted[-1] if attempted else 'preflight'}_activation_rejected",
            )
            rollback_failure: str | None = None
            for phase, rollback in (
                ("p08", self.backend.rollback_p08),
                ("telegram_plugin", self.backend.rollback_telegram_plugin),
                ("p07", self.backend.rollback_p07),
            ):
                if phase not in attempted:
                    continue
                try:
                    self.journal(phase, "rolling_back")
                    rollback()
                    self.journal(phase, "rolled_back")
                except BaseException as rollback_error:
                    if rollback_failure is None:
                        rollback_failure = _typed(
                            rollback_error,
                            f"{phase}_rollback_rejected",
                        )
                    self.journal(phase, "rollback_failed")
            try:
                observed = self.backend.observe_prestate(prestate_digest)
                if observed != prestate_digest and rollback_failure is None:
                    rollback_failure = "functional_prestate_mismatch"
            except BaseException as rollback_observation_error:
                if rollback_failure is None:
                    rollback_failure = _typed(
                        rollback_observation_error,
                        "functional_rollback_observation_rejected",
                    )
            if rollback_failure is not None:
                raise CombinedTransactionRejected(
                    "combined_functional_rollback_failed",
                    activation_failure_code=activation_code,
                    rollback_failure_code=rollback_failure,
                ) from activation_error
            raise CombinedTransactionRejected(
                "combined_activation_rolled_back",
                activation_failure_code=activation_code,
            ) from activation_error
