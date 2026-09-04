"""One absolute, monotonic deadline shared by an analyzer request."""

from __future__ import annotations

import time
from dataclasses import dataclass


class AnalysisDeadlineExceeded(TimeoutError):
    """The request-wide analysis deadline was exhausted."""


@dataclass(frozen=True)
class AnalysisDeadline:
    """A non-renewable deadline created once at request entry."""

    expires_at: float

    @classmethod
    def start(cls, timeout_seconds: int) -> AnalysisDeadline:
        if not isinstance(timeout_seconds, int) or timeout_seconds < 1:
            raise ValueError("analysis timeout must be a positive integer")
        return cls(time.monotonic() + timeout_seconds)

    def remaining(self) -> float:
        return self.expires_at - time.monotonic()

    def check(self, stage: str = "analysis") -> None:
        if self.remaining() <= 0:
            raise AnalysisDeadlineExceeded(f"{stage} exceeded the request deadline")

    def step_timeout(self, maximum: int) -> int:
        if not isinstance(maximum, int) or maximum < 1:
            raise ValueError("step timeout must be a positive integer")
        remaining = int(self.remaining())
        return min(maximum, remaining) if remaining > 0 else 0
