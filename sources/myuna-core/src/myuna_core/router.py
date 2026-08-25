from __future__ import annotations

from dataclasses import dataclass

from .config import Settings


@dataclass(frozen=True, slots=True)
class RouterStatus:
    ready: bool
    definition_release: str | None
    enabled_providers: tuple[str, ...]
    reasons: tuple[str, ...]


class ModelRouter:
    """Status-only router boundary; provider calls are intentionally not implemented yet."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def status(self) -> RouterStatus:
        return RouterStatus(
            ready=self._settings.ready,
            definition_release=self._settings.definition_release,
            enabled_providers=self._settings.enabled_providers,
            reasons=self._settings.readiness_reasons,
        )

