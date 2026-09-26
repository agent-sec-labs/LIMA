"""Agent tool wrapper around the ASan reproduction workbench (design §5.1).

Exposes the Task 1 versioned ``/v1/repro`` endpoint to agents as the tool
``compile_and_run_asan``: one sandboxed ``clang++ -fsanitize=address``
compile-and-run per call, with the model-generated PoC driver entering the
same five-layer sandbox jail as the repository code (design invariant 5).

Security and budget discipline:

* Zero network here: the strictly validating Task 1 client
  (:class:`lima.cxx_memory.CxxMemoryAnalyzerClient` or a test fake) is
  injected; this module never opens a socket and never spawns a process.
* Argument validation reuses the Task 1 rules verbatim
  (``_validate_repro_driver_code`` / ``_validate_repro_requested_sources`` /
  ``_require_safe_relative_unit``), surfaced as ``ValueError`` argument
  errors.  A rejected request never reaches the client and never charges
  the budget.
* Budget order mirrors ``lima.cxx_llm``: ``calls=1`` plus the exact UTF-8
  request bytes (the driver) are charged before the wire round trip and
  are never refunded when the transport fails; the response text bytes
  (:func:`observation_payload_bytes`, an exact proxy for the escaped
  variable text the observation adds to the model context) are charged
  when the response arrives, and an over-budget observation is dropped
  unreturned via ``AgentBudgetExceeded``.  A degraded transport-failure
  observation bills no response bytes because no response arrived.
* Escaping: everything that originates from the wire (compiler/stream
  diagnostics, ASan error type) is rendered repr-style with ``ascii()``
  and truncated after escaping, so no raw control character, newline or
  non-ASCII text can reach the model context.  ``raw_tail`` keeps at most
  ``MAX_RAW_TAIL_CHARS`` escaped characters of the diagnostic stream (the
  server includes the bounded driver stderr/stdout there).
* Failure semantics: ``CxxAnalyzerUnavailable`` and
  ``CxxAnalyzerProtocolError`` degrade to a bounded
  ``transport-failed`` observation instead of raising through the agent
  loop.  ``stage`` vocabulary: ``compile``, ``run``, ``transport-failed``.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Any, Protocol

from .cxx_agent_tools import CxxAgentBudget
from .cxx_memory import (
    CxxAnalyzerProtocolError,
    CxxAnalyzerUnavailable,
    ReproResponse,
    _validate_repro_driver_code,
    _validate_repro_requested_sources,
)
from .runtime import AgentTool

TRANSPORT_FAILED_STAGE = "transport-failed"
MAX_RAW_TAIL_CHARS = 800
MAX_DIAGNOSTIC_CHARS = 500
MAX_ERROR_TYPE_CHARS = 120
MAX_DEGRADED_DIAGNOSTIC_CHARS = 500
MAX_FRAME_TEXT_CHARS = 400

_HEX64 = frozenset("0123456789abcdef")


class ReproAnalyzerClient(Protocol):
    """The one Task 1 client method the workbench needs (injected).

    Clients MAY accept a keyword-only ``timeout`` (the deadline-bounded
    per-call wire timeout); the workbench detects the capability once, by
    signature inspection before any call, so every experiment executes
    exactly one client invocation.
    """

    def repro_compile_run(
        self,
        repository_key: str,
        snapshot_sha256: str,
        source_files: tuple[str, ...],
        driver_code: str,
    ) -> ReproResponse: ...


def _accepts_timeout_keyword(method: Any) -> bool:
    """True when ``method``'s signature binds a ``timeout`` keyword.

    Pure signature inspection -- the method body never runs -- so a
    ``TypeError`` raised *inside* a timeout-aware client surfaces as a real
    program error instead of being mistaken for a legacy signature (which
    would re-run the experiment without a timeout).  Unintrospectable
    callables are treated as legacy: one call, client-owned wire timeout.
    """

    try:
        inspect.signature(method).bind(
            "repository", "snapshot", (), "driver", timeout=1,
        )
    except (TypeError, ValueError):
        return False
    return True


@dataclass(frozen=True)
class ExperimentObservation:
    """Distilled, escaped and bounded view of one repro experiment.

    Not a JSON dump: the agent gets the verdict fields it needs to revise a
    hypothesis.  ``error_type``/``faulting_line``/``freed_line``/
    ``allocated_line`` come from the structured ASan report (``None`` when
    the experiment failed to compile or ran clean); ``diagnostics`` are the
    escaped protocol diagnostics; ``raw_tail`` is the escaped tail of the
    diagnostic stream (driver stderr proxy), at most ``MAX_RAW_TAIL_CHARS``
    characters.

    ``ok`` keeps its wire meaning -- "the tested binary exited cleanly with
    no ASan report" -- so a real sanitizer hit always arrives as
    ``ok=False``.  The frame-identity fields (``faulting_file``/
    ``faulting_function``/``freed_file``/``allocated_file``, ``None``
    without a symbolized frame) carry where the crash landed so consumers
    can bind the evidence to the audited target instead of the PoC driver.
    """

    ok: bool
    stage: str
    exit_code: int | None
    error_type: str | None
    faulting_line: int | None
    freed_line: int | None
    allocated_line: int | None
    diagnostics: tuple[str, ...]
    raw_tail: str
    faulting_file: str | None = None
    faulting_function: str | None = None
    freed_file: str | None = None
    allocated_file: str | None = None


def _escape_text(text: str | None, limit: int) -> str | None:
    """Render untrusted text repr-style, then bound it.

    ``ascii()`` escapes control characters, newlines and everything
    non-ASCII into visible literals; truncating afterwards keeps the bound
    without ever re-introducing a raw control character.
    """

    if text is None:
        return None
    return ascii(text)[:limit]


def _frame_line(frame: Any) -> int | None:
    """Defensively extract a 1-based line from one validated ASan frame."""

    if isinstance(frame, dict):
        line = frame.get("line")
        if isinstance(line, int) and not isinstance(line, bool) and line >= 1:
            return line
    return None


def _frame_text(frame: Any, key: str) -> str | None:
    """Defensively extract escaped text (file/function) from one frame."""

    if isinstance(frame, dict):
        value = frame.get(key)
        if isinstance(value, str) and value:
            return _escape_text(value, MAX_FRAME_TEXT_CHARS)
    return None


def _observation_from_response(response: ReproResponse) -> ExperimentObservation:
    """Distill one strictly validated ``ReproResponse`` for the agent."""

    report = response.asan_report or {}
    error_type = _escape_text(report.get("error_type"), MAX_ERROR_TYPE_CHARS)
    diagnostics = tuple(
        _escape_text(item, MAX_DIAGNOSTIC_CHARS) for item in response.diagnostics
    )
    raw_tail = _escape_text("\n".join(response.diagnostics), MAX_RAW_TAIL_CHARS) or ""
    faulting_frame = report.get("faulting_frame")
    freed_frame = report.get("freed_by_frame")
    allocated_frame = report.get("allocated_by_frame")
    return ExperimentObservation(
        ok=response.ok,
        stage=response.stage,
        exit_code=response.exit_code,
        error_type=error_type,
        faulting_line=_frame_line(faulting_frame),
        freed_line=_frame_line(freed_frame),
        allocated_line=_frame_line(allocated_frame),
        diagnostics=diagnostics,
        raw_tail=raw_tail,
        faulting_file=_frame_text(faulting_frame, "file"),
        faulting_function=_frame_text(faulting_frame, "function"),
        freed_file=_frame_text(freed_frame, "file"),
        allocated_file=_frame_text(allocated_frame, "file"),
    )


def _degraded_observation(exc: Exception) -> ExperimentObservation:
    """Bounded, escaped stand-in for an experiment that never returned."""

    detail = _escape_text(str(exc), MAX_DEGRADED_DIAGNOSTIC_CHARS) or ""
    return ExperimentObservation(
        ok=False,
        stage=TRANSPORT_FAILED_STAGE,
        exit_code=None,
        error_type=None,
        faulting_line=None,
        freed_line=None,
        allocated_line=None,
        diagnostics=(f"transport-failed: {detail}",),
        raw_tail="",
    )


def observation_payload_bytes(observation: ExperimentObservation) -> int:
    """UTF-8 byte size of the variable observation text charged to the budget.

    Exact billing proxy: the escaped variable strings an observation adds
    to the model context (error type, the faulting frame's file -- it
    travels on through the experiment ledger -- diagnostics, raw tail)
    joined by newlines.  Fixed-structure fields (flags, stage, line
    numbers) and the frame texts no consumer renders (function,
    freed/allocated files) form the envelope and are not billed, mirroring
    the ``cxx_agent_tools`` rule.
    """

    parts = [
        observation.error_type or "",
        observation.faulting_file or "",
        *observation.diagnostics,
        observation.raw_tail,
    ]
    return len("\n".join(parts).encode("utf-8"))


def _require_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be non-empty text")
    return value


def _require_snapshot_hash(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX64 for character in value)
    ):
        raise ValueError("snapshot_hash must be a 64-character lowercase hex digest")
    return value


def _require_source_files(source_files: Any) -> tuple[str, ...]:
    """Normalize and validate the source set with the Task 1 rules."""

    if isinstance(source_files, str) or not isinstance(source_files, list | tuple):
        raise ValueError("source_files must be a list or tuple of relative POSIX paths")
    try:
        return _validate_repro_requested_sources(tuple(source_files))
    except CxxAnalyzerProtocolError as exc:
        raise ValueError(f"invalid source_files ({exc})") from exc


def _require_driver_code(driver_code: Any) -> str:
    """Validate the driver with the Task 1 size and content rules."""

    try:
        return _validate_repro_driver_code(driver_code)
    except CxxAnalyzerProtocolError as exc:
        raise ValueError(f"invalid driver_code ({exc})") from exc


class ReproWorkbench:
    """Budgeted, degrading agent wrapper over ``repro_compile_run``."""

    def __init__(
        self,
        analyzer_client: ReproAnalyzerClient,
        budget: CxxAgentBudget,
        default_timeout: int = 60,
    ) -> None:
        if not isinstance(budget, CxxAgentBudget):
            raise ValueError("budget must be a CxxAgentBudget")
        if (
            isinstance(default_timeout, bool)
            or not isinstance(default_timeout, int)
            or default_timeout <= 0
        ):
            raise ValueError("default_timeout must be a positive integer")
        self._client = analyzer_client
        self._budget = budget
        # Capability decided once by signature inspection, before any call:
        # every experiment then executes exactly one client invocation.
        self._client_accepts_timeout = _accepts_timeout_keyword(
            analyzer_client.repro_compile_run
        )
        # Requested per-experiment wall-clock ceiling for orchestration;
        # the wire timeout stays owned by the injected Task 1 client.
        self.default_timeout = default_timeout

    def run_experiment(
        self,
        repository_key: str,
        snapshot_hash: str,
        source_files,
        driver_code: str,
        *,
        timeout: int | None = None,
    ) -> ExperimentObservation:
        """Run one sandboxed ASan compile-and-run as a budgeted agent step.

        Deduction order: validate arguments (free on failure) -> charge
        ``calls=1`` plus the exact driver bytes -> send -> on response,
        charge the observation text bytes and return.  Transport and
        protocol failures degrade to a ``transport-failed`` observation
        while the pre-send charge stays (nothing is refunded).  A locally
        rejected request never reaches the client.

        ``timeout`` is the caller's orchestration ceiling for this one
        experiment (the deadline-bounded step timeout; ``None`` keeps
        :attr:`default_timeout`).  It is forwarded to the client as a
        per-call wire timeout when the client's signature accepts one
        (decided once at construction by pure signature inspection), so
        the real transport is bounded by the same deadline that bounds
        orchestration -- and a client call failure is never retried.
        """

        repo = _require_text(repository_key, "repository_key")
        snapshot = _require_snapshot_hash(snapshot_hash)
        sources = _require_source_files(source_files)
        driver = _require_driver_code(driver_code)
        if (
            timeout is not None
            and (
                isinstance(timeout, bool)
                or not isinstance(timeout, int)
                or timeout <= 0
            )
        ):
            raise ValueError("timeout must be a positive integer or None")
        effective_timeout = timeout if timeout is not None else self.default_timeout
        self._budget.consume(calls=1, bytes=len(driver.encode("utf-8")))
        try:
            if self._client_accepts_timeout:
                response = self._client.repro_compile_run(
                    repo, snapshot, sources, driver, timeout=effective_timeout
                )
            else:
                # Legacy 4-argument client: the wire timeout stays owned by
                # the client itself.
                response = self._client.repro_compile_run(
                    repo, snapshot, sources, driver
                )
        except (CxxAnalyzerUnavailable, CxxAnalyzerProtocolError) as exc:
            return _degraded_observation(exc)
        observation = _observation_from_response(response)
        self._budget.consume(bytes=observation_payload_bytes(observation))
        return observation


_REPRO_TOOL_SCHEMA = {
    "type": "object",
    "properties": {
        "repository_key": {"type": "string"},
        "snapshot_hash": {"type": "string"},
        "source_files": {"type": "array", "items": {"type": "string"}},
        "driver_code": {"type": "string"},
    },
    "required": ["repository_key", "snapshot_hash", "source_files", "driver_code"],
    "additionalProperties": False,
}


def as_agent_tool(workbench: ReproWorkbench) -> AgentTool:
    """Wrap the workbench as the ``compile_and_run_asan`` agent tool."""

    def compile_and_run_asan(
        repository_key: str,
        snapshot_hash: str,
        source_files: list[str] | tuple[str, ...],
        driver_code: str,
    ) -> ExperimentObservation:
        """Compile driver plus snapshot sources under ASan and run them.

        Templates from ``lima.repro_templates`` are convenient skeletons
        for ``driver_code``; fully custom drivers are equally welcome --
        both run in the same sandbox under the same budget.
        """

        return workbench.run_experiment(
            repository_key, snapshot_hash, source_files, driver_code
        )

    return AgentTool(
        "compile_and_run_asan",
        "Compile the given snapshot sources together with a PoC driver under "
        "AddressSanitizer inside the sandbox, run the binary, and return the "
        "distilled experiment observation (ok, stage, exit code, ASan error "
        "type, faulting/freed/allocated lines, escaped diagnostics and the "
        "raw output tail).",
        _REPRO_TOOL_SCHEMA,
        compile_and_run_asan,
    )


__all__ = [
    "MAX_DIAGNOSTIC_CHARS",
    "MAX_DEGRADED_DIAGNOSTIC_CHARS",
    "MAX_ERROR_TYPE_CHARS",
    "MAX_RAW_TAIL_CHARS",
    "ExperimentObservation",
    "ReproAnalyzerClient",
    "ReproWorkbench",
    "TRANSPORT_FAILED_STAGE",
    "as_agent_tool",
    "observation_payload_bytes",
]
