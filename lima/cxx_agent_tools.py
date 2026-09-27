"""Shared C/C++ agent budget accounting (retirement Task 2 trim).

Kept from the original module's security boundary: budgets are atomic.
Every deduction goes through ``consume``, a single-lock transaction that
either charges the whole request or nothing; the per-call cap and the
cumulative cap share one pool bounded by ``max_output_bytes``. ``files``
charges deduplicate per snapshot path.

The review/evidence tool registries, the snapshot reader protocol and the
symbol-index plumbing that used to live here served the retired seven-role
chain; the platform chain carries its own tools and only this budget
accounting remains shared.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass


class AgentBudgetExceeded(RuntimeError):
    """The task-level agent tool budget cannot cover one more response."""


@dataclass(frozen=True)
class RemainingBudget:
    """Read-only snapshot of the budget remaining; never mutates the pool."""

    calls: int
    files: int
    lines: int
    bytes_remaining: int


class _Usage:
    """Mutable per-task usage guarded by the owning budget's lock."""

    __slots__ = ("files_read", "used_bytes", "used_calls", "used_files", "used_lines")

    def __init__(self) -> None:
        self.used_calls = 0
        self.used_files = 0
        self.used_lines = 0
        self.used_bytes = 0
        self.files_read: set[str] = set()


@dataclass(frozen=True)
class CxxAgentBudget:
    """Task-level tool budget: immutable caps, lock-guarded mutable usage.

    All deductions go through :meth:`consume`, a single-lock atomic
    transaction: the four remaining amounts are checked together and either
    every one of them fits or nothing is charged and
    :class:`AgentBudgetExceeded` is raised.

    Equality and repr cover only the four caps: instances with equal caps
    are deliberately the same configuration even while their mutable usage
    differs.
    """

    max_calls: int = 40
    max_context_files: int = 12
    max_context_lines: int = 1200
    max_output_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        for name in (
            "max_calls",
            "max_context_files",
            "max_context_lines",
            "max_output_bytes",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer, got {value!r}")
        object.__setattr__(self, "_lock", threading.Lock())
        object.__setattr__(self, "_usage", _Usage())

    def consume(
        self,
        *,
        calls: int = 0,
        files: int = 0,
        lines: int = 0,
        bytes: int = 0,
        file_path: str | None = None,
    ) -> None:
        """Atomically deduct one combined demand or charge nothing at all.

        ``file_path`` deduplicates the ``files`` charge: the first charge for
        a snapshot path costs ``files``; later charges for the same path cost
        zero files because the file already sits in the pool.
        """
        amounts = (("calls", calls), ("files", files), ("lines", lines), ("bytes", bytes))
        for name, value in amounts:
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(
                    f"budget amount {name} must be a non-negative integer, got {value!r}"
                )
        with self._lock:
            usage = self._usage
            charge_files = files
            if files and file_path is not None and file_path in usage.files_read:
                charge_files = 0
            checks = (
                ("calls", usage.used_calls, calls, self.max_calls),
                ("files", usage.used_files, charge_files, self.max_context_files),
                ("lines", usage.used_lines, lines, self.max_context_lines),
                ("bytes", usage.used_bytes, bytes, self.max_output_bytes),
            )
            for name, used, request, cap in checks:
                if used + request > cap:
                    raise AgentBudgetExceeded(
                        f"agent tool budget exhausted for {name}: "
                        f"needs {request} more, only {cap - used} remaining"
                    )
            usage.used_calls += calls
            usage.used_files += charge_files
            usage.used_lines += lines
            usage.used_bytes += bytes
            if charge_files and file_path is not None:
                usage.files_read.add(file_path)

    def consume_call(self) -> None:
        """Charge one tool invocation."""
        self.consume(calls=1)

    def consume_files(self, count: int = 1) -> None:
        """Charge snapshot files against the context-file pool."""
        self.consume(files=count)

    def consume_lines(self, count: int = 1) -> None:
        """Charge code lines against the context-line pool."""
        self.consume(lines=count)

    def consume_bytes(self, count: int = 1) -> None:
        """Charge UTF-8 output bytes against the output pool."""
        self.consume(bytes=count)

    def remaining(self) -> RemainingBudget:
        """Return a frozen read-only snapshot of what is left."""
        with self._lock:
            usage = self._usage
            return RemainingBudget(
                calls=self.max_calls - usage.used_calls,
                files=self.max_context_files - usage.used_files,
                lines=self.max_context_lines - usage.used_lines,
                bytes_remaining=self.max_output_bytes - usage.used_bytes,
            )


__all__ = [
    "AgentBudgetExceeded",
    "CxxAgentBudget",
    "RemainingBudget",
]
