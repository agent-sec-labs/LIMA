"""Bounded PoC reproduction workbench: compile and run inside the sandbox.

Platform plan Task 1 (design ``docs/superpowers/specs/2026-09-12-agent-vuln-
platform-design.md`` section 5).  The workbench lets an agent-provided,
therefore untrusted, PoC driver be compiled together with verified snapshot
sources under AddressSanitizer and executed, returning a structured report.

Red lines implemented here:

- Both steps go through :func:`cxx_analyzer.execution.run_step`, the
  fail-closed Landlock launcher; no direct ``subprocess`` use.  The driver
  and the binary live in the snapshot's writable build root, the compiler
  and the binary read the verified source tree, and the environment is the
  analyzer-owned :data:`SANITIZER_ENVIRONMENT` (which also strips secrets
  via ``clean_environment`` inside the executor).
- The driver is staged under a content-hash name inside the per-request
  snapshot, so experiments are reproducible and cannot collide.
- :func:`parse_asan_report` never guesses: without a complete,
  self-consistent ASan report (ERROR line plus matching SUMMARY line) it
  returns ``None``.
- A SIGSEGV death with an empty ASan stream is treated as sanitizer
  runtime noise (a known clang-14 renderer crash class under restricted,
  non-root containers), not as a verdict: the run is retried in place
  within the same budget before being reported as ``ok=False``.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from .deadline import AnalysisDeadline, AnalysisDeadlineExceeded
from .execution import SANITIZER_ENVIRONMENT, ToolExecution, run_step
from .snapshot import PreparedSnapshot

REPRO_SCHEMA_VERSION: Final = 1
COMPILE_DRIVER: Final = "clang++-14"
COMPILE_FLAGS: Final = ("-fsanitize=address", "-g", "-O1")
MAX_REPRO_SOURCES: Final = 16
MAX_REPRO_DRIVER_BYTES: Final = 256 * 1024
MAX_REPRO_PATH_CHARS: Final = 1024
REPRO_STEP_OUTPUT_BYTES: Final = 1024 * 1024

_BINARY_HASH_BUDGET_BYTES: Final = 64 * 1024 * 1024
_DIAGNOSTIC_ENTRY_BYTES: Final = 2_048
_MAX_DIAGNOSTICS: Final = 8
# A SIGSEGV death with an empty ASan stream is renderer noise (the ASan
# runtime crashing while rendering its own report under the restricted,
# non-root container), never a "no vulnerability" verdict: the first run
# plus two retries are spent before the experiment is reported honestly.
_MAX_RUN_ATTEMPTS: Final = 3
_ASAN_SEGV_RETRIED: Final = "asan-runtime-segv-retried"
_DRIVER_DIRECTORY: Final = "build"
_DRIVER_PREFIX: Final = "repro_driver_"
_DRIVER_SUFFIX: Final = ".cpp"
_BINARY_PREFIX: Final = "repro_bin_"

_ANSI: Final = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ERROR_LINE: Final = re.compile(
    r"^==\d+==ERROR: AddressSanitizer: (?P<error_type>[^\r\n]+?)"
    r"(?: on address | on |$)",
    re.MULTILINE,
)
_SUMMARY_LINE: Final = re.compile(
    r"^SUMMARY: AddressSanitizer: (?P<summary_type>\S+)", re.MULTILINE
)
_ACCESS_LINE: Final = re.compile(
    r"^(?P<access>READ|WRITE) of size (?P<size>\d+) at", re.MULTILINE
)
_FREED_HEADER: Final = re.compile(r"^freed by thread", re.MULTILINE)
_ALLOCATED_HEADER: Final = re.compile(
    r"^(?:previously )?allocated by thread", re.MULTILINE
)
_FRAME_LINE: Final = re.compile(r"#\d+\s+(?:0x[0-9a-fA-F]+\s+in\s+)?(.+)")
_FRAME_LOCATION: Final = re.compile(
    r"(?P<function>.+?)\s+(?P<file>[^:\s]+):(?P<line>[1-9]\d*)(?::(?P<column>[1-9]\d*))?"
)


@dataclass(frozen=True)
class ReproExecution:
    """One bounded compile-and-run experiment inside one live snapshot.

    ``stage`` names the step that decided the outcome (``compile`` or
    ``run``); ``ok`` is True only for a completed run that exited zero
    without a parseable ASan report and without truncated output.
    ``exit_code`` is the deciding step's return code (``None`` when the
    step timed out or never launched).  ``artifacts`` carries the
    snapshot-relative driver/binary paths plus both SHA-256 digests (the
    binary digest is empty when no binary was produced).
    """

    stage: str
    ok: bool
    exit_code: int | None
    asan_report: dict[str, object] | None
    diagnostics: tuple[str, ...]
    artifacts: dict[str, str]
    elapsed_seconds: float


def _safe_relative_path(value: object) -> str:
    """Accept only a bounded, safe, snapshot-relative POSIX path."""

    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_REPRO_PATH_CHARS
        or PurePosixPath(value).is_absolute()
        or "\\" in value
        or "\x00" in value
        or any(segment in {"", ".", ".."} for segment in value.split("/"))
    ):
        raise ValueError("repro path must be a safe snapshot-relative POSIX path")
    return value


def build_compile_argv(
    source_files: list[str], driver_path: str, output_path: str
) -> list[str]:
    """Return the pinned, deterministic ASan compile argv for one experiment.

    Pure validation and assembly only: sources first, then the driver, so
    the driver's ``main`` links last; the binary lands in the snapshot's
    writable build root.  Every path must be a safe relative POSIX path.
    """

    if isinstance(source_files, (str, bytes)) or not isinstance(
        source_files, (list, tuple)
    ):
        raise ValueError("repro source files must be a sequence of relative paths")
    if not source_files or len(source_files) > MAX_REPRO_SOURCES:
        raise ValueError("repro source files must be between 1 and 16 entries")
    sources = tuple(_safe_relative_path(source) for source in source_files)
    if len(set(sources)) != len(sources):
        raise ValueError("repro source files must be unique")
    driver = _safe_relative_path(driver_path)
    output = _safe_relative_path(output_path)
    return [COMPILE_DRIVER, *COMPILE_FLAGS, *sources, driver, "-o", output]


def build_run_argv(binary_path: str) -> list[str]:
    """Return the pinned run argv; ASan options come from the environment."""

    return [_safe_relative_path(binary_path)]


def _frame(line: str) -> dict[str, object] | None:
    """Parse one stack frame line into ``function/file/line/column``.

    Both ``file:line:col`` and ``file:line`` spellings are accepted; a
    frame without a parseable source location (interceptors without debug
    info, module-only frames) yields ``None`` so the caller can move on to
    the next frame instead of guessing.
    """

    match = _FRAME_LINE.fullmatch(line.strip())
    if match is None:
        return None
    location = _FRAME_LOCATION.fullmatch(match.group(1).strip())
    if location is None:
        return None
    function = location.group("function").strip()
    if not function:
        return None
    return {
        "function": function,
        "file": location.group("file"),
        "line": int(location.group("line")),
        "column": (
            int(location.group("column")) if location.group("column") else None
        ),
    }


def _first_frame(section: str) -> dict[str, object] | None:
    for line in section.splitlines():
        frame = _frame(line)
        if frame is not None:
            return frame
    return None


def _normalized_error_type(error_type: str) -> str:
    return "double-free" if error_type == "attempting double-free" else error_type


def parse_asan_report(text: str) -> dict[str, object] | None:
    """Parse the first ASan report in one output stream, or return ``None``.

    The report is only accepted when it is structurally complete: an
    ``==pid==ERROR: AddressSanitizer: <type>`` line plus a ``SUMMARY``
    line whose type matches (``attempting double-free`` normalizes to
    ``double-free``).  Anything else -- clean output, truncated or
    corrupted reports -- yields ``None`` instead of a guessed answer.
    ``raw_report_sha256`` covers the exact ``ERROR``..``SUMMARY`` block so
    experiments stay auditable.
    """

    if not isinstance(text, str) or not text:
        return None
    clean = _ANSI.sub("", text)
    error = _ERROR_LINE.search(clean)
    if error is None:
        return None
    summary = _SUMMARY_LINE.search(clean, error.end())
    if summary is None:
        return None
    if _ERROR_LINE.search(clean, error.end(), summary.start()) is not None:
        # A second report starts before this one's summary: corrupted mix.
        return None
    error_type = error.group("error_type").strip()
    if _normalized_error_type(error_type) != summary.group("summary_type"):
        return None
    newline = clean.find("\n", summary.start())
    summary_line_end = len(clean) if newline == -1 else newline
    block = clean[error.start() : summary_line_end]
    summary_offset = summary.start() - error.start()
    freed = _FREED_HEADER.search(block)
    allocated = _ALLOCATED_HEADER.search(block)
    primary_end = min(
        summary_offset,
        freed.start() if freed else len(block),
        allocated.start() if allocated else len(block),
    )
    primary = block[:primary_end]
    access = _ACCESS_LINE.search(primary)
    freed_section = (
        block[freed.start() : min(
            allocated.start() if allocated else summary_offset, summary_offset
        )]
        if freed
        else ""
    )
    allocated_section = (
        block[allocated.start() : summary_offset] if allocated else ""
    )
    return {
        "error_type": error_type,
        "access": access.group("access") if access else None,
        "access_size": int(access.group("size")) if access else None,
        "faulting_frame": _first_frame(primary),
        "freed_by_frame": _first_frame(freed_section),
        "allocated_by_frame": _first_frame(allocated_section),
        "raw_report_sha256": hashlib.sha256(block.encode("utf-8")).hexdigest(),
    }


def _validate_driver_code(driver_code: object) -> str:
    if not isinstance(driver_code, str) or not driver_code:
        raise ValueError("repro driver code must be non-empty text")
    if len(driver_code.encode("utf-8")) > MAX_REPRO_DRIVER_BYTES:
        raise ValueError("repro driver code exceeds the 256 KiB budget")
    if "\x00" in driver_code:
        raise ValueError("repro driver code must not contain NUL")
    return driver_code


def _validate_sources(source_files: object, snapshot: PreparedSnapshot) -> tuple[str, ...]:
    if isinstance(source_files, (str, bytes)) or not isinstance(
        source_files, (list, tuple)
    ):
        raise ValueError("repro source files must be a sequence of relative paths")
    if not source_files or len(source_files) > MAX_REPRO_SOURCES:
        raise ValueError("repro source files must be between 1 and 16 entries")
    sources = tuple(_safe_relative_path(source) for source in source_files)
    if len(set(sources)) != len(sources):
        raise ValueError("repro source files must be unique")
    inventory = set(snapshot.files)
    if any(source not in inventory for source in sources):
        raise ValueError("repro source file is outside the verified snapshot inventory")
    return sources


def _bounded_diagnostic(text: str) -> tuple[str, bool]:
    encoded = text.encode("utf-8")
    if len(encoded) <= _DIAGNOSTIC_ENTRY_BYTES:
        return text, False
    bounded = encoded[:_DIAGNOSTIC_ENTRY_BYTES]
    while bounded:
        try:
            return bounded.decode("utf-8"), True
        except UnicodeDecodeError:
            bounded = bounded[:-1]
    return "", True


def _step_diagnostics(execution: ToolExecution, *streams: str) -> list[str]:
    """Bound one step's outcome into stable, wire-safe diagnostic entries."""

    diagnostics: list[str] = []
    if execution.status == "timed-out":
        diagnostics.append("repro-step-timed-out")
    elif execution.status in {"sandbox-unavailable", "sandbox-failed"}:
        diagnostics.append(execution.status)
    if execution.output_truncated:
        diagnostics.append("repro-output-truncated")
    if execution.diagnostic and execution.diagnostic not in diagnostics:
        diagnostics.append(execution.diagnostic)
    for stream in streams:
        if not stream or not stream.strip():
            continue
        bounded, truncated = _bounded_diagnostic(stream)
        if bounded:
            diagnostics.append(bounded)
        if truncated and "repro-diagnostics-truncated" not in diagnostics:
            diagnostics.append("repro-diagnostics-truncated")
    return diagnostics[:_MAX_DIAGNOSTICS]


def _hash_file(path: Path) -> tuple[str, str]:
    """Stream-hash one file under a hard byte budget; never raise."""

    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > _BINARY_HASH_BUDGET_BYTES:
                    return "", "repro-binary-hash-skipped"
                digest.update(chunk)
    except OSError:
        return "", "repro-binary-hash-unavailable"
    return digest.hexdigest(), ""


def _is_instrument_segv(execution: ToolExecution) -> bool:
    """True for a SIGSEGV death with no ASan report: renderer noise.

    On POSIX a signal death surfaces as the negative signal number, so the
    tested process dying with SIGSEGV and an empty ASan stream is the
    sanitizer runtime's own crash while rendering its report under the
    restricted container -- not evidence about the PoC.  A real bare
    SIGSEGV of the tested program (no report) is possible but rare, and a
    UAF-class PoC is built to trigger an ASan report rather than a silent
    segfault, so the noise reading is the honest default.
    """

    return execution.status == "failed" and execution.returncode == -11


def _step_budget(deadline: AnalysisDeadline, timeout_seconds: int) -> int:
    budget = deadline.step_timeout(timeout_seconds)
    if budget < 1:
        raise AnalysisDeadlineExceeded("repro step exceeded the request deadline")
    return budget


def run_repro(
    snapshot: PreparedSnapshot,
    source_files: list[str],
    driver_code: str,
    *,
    deadline: AnalysisDeadline,
    timeout_seconds: int = 60,
) -> ReproExecution:
    """Compile verified sources plus one untrusted driver and run it.

    The driver is staged in the request-private build root under a
    content-hash name, compiled with the pinned ASan argv and executed;
    both steps run through the sandbox executor under the shared request
    deadline.  Every input is validated fail-closed before anything is
    staged or executed.

    Run-stage instrument noise: the ASan runtime itself crashes
    (SIGSEGV, empty stream) with measurable probability while rendering
    its report under the restricted, non-root container.  A run that dies
    with ``exit_code == -11`` and no parseable report is therefore not a
    "no vulnerability" verdict -- it is retried in place, at most two
    retries (three attempts total), each with its own step budget, until
    either a report is parsed or a non-noise outcome arrives.  When all
    attempts are SIGSEGV-without-report the experiment reports ``ok=False``
    with stage ``run``, the last exit code, and the
    ``asan-runtime-segv-retried`` diagnostic.  Every other exit code keeps
    its single-shot behavior.
    """

    started = time.monotonic()
    if not isinstance(deadline, AnalysisDeadline):
        raise ValueError("repro requires an AnalysisDeadline")
    if type(timeout_seconds) is not int or timeout_seconds < 1:
        raise ValueError("repro timeout must be a positive integer")
    sources = _validate_sources(source_files, snapshot)
    driver_text = _validate_driver_code(driver_code)

    tag = hashlib.sha256(driver_text.encode("utf-8")).hexdigest()[:8]
    driver_relative = f"{_DRIVER_DIRECTORY}/{_DRIVER_PREFIX}{tag}{_DRIVER_SUFFIX}"
    binary_relative = f"{_DRIVER_DIRECTORY}/{_BINARY_PREFIX}{tag}"
    driver_target = snapshot.build_root / f"{_DRIVER_PREFIX}{tag}{_DRIVER_SUFFIX}"
    binary_target = snapshot.build_root / f"{_BINARY_PREFIX}{tag}"
    artifacts = {
        "driver_path": driver_relative,
        "binary_path": binary_relative,
        "driver_sha256": hashlib.sha256(driver_text.encode("utf-8")).hexdigest(),
        "binary_sha256": "",
    }
    try:
        with driver_target.open("xb") as handle:
            handle.write(driver_text.encode("utf-8"))
    except FileExistsError as exc:
        raise ValueError("repro driver is already staged in this snapshot") from exc

    deadline.check("repro compile")
    compile_execution = run_step(
        build_compile_argv(sources, driver_relative, binary_relative),
        snapshot,
        ".",
        _step_budget(deadline, timeout_seconds),
        REPRO_STEP_OUTPUT_BYTES,
        SANITIZER_ENVIRONMENT,
        deadline=deadline,
    )
    if compile_execution.status != "completed" or not binary_target.is_file():
        diagnostics = _step_diagnostics(compile_execution, compile_execution.stderr)
        if compile_execution.status == "completed":
            diagnostics.append("repro-binary-missing")
        return ReproExecution(
            stage="compile",
            ok=False,
            exit_code=compile_execution.returncode,
            asan_report=None,
            diagnostics=tuple(diagnostics),
            artifacts=artifacts,
            elapsed_seconds=round(time.monotonic() - started, 6),
        )

    binary_sha256, hash_diagnostic = _hash_file(binary_target)
    artifacts["binary_sha256"] = binary_sha256

    deadline.check("repro run")
    run_execution: ToolExecution | None = None
    report: dict[str, object] | None = None
    segv_retried = False
    for attempt in range(_MAX_RUN_ATTEMPTS):
        if attempt:
            deadline.check("repro run retry")
        run_execution = run_step(
            build_run_argv(binary_relative),
            snapshot,
            ".",
            _step_budget(deadline, timeout_seconds),
            REPRO_STEP_OUTPUT_BYTES,
            SANITIZER_ENVIRONMENT,
            deadline=deadline,
        )
        report = parse_asan_report(run_execution.stderr) or parse_asan_report(
            run_execution.stdout
        )
        if report is not None or not _is_instrument_segv(run_execution):
            break
        segv_retried = True
    assert run_execution is not None  # the loop always executes at least once
    clean_exit = (
        run_execution.status == "completed" and run_execution.returncode == 0
    )
    ok = report is None and clean_exit and not run_execution.output_truncated
    diagnostics = _step_diagnostics(
        run_execution,
        *(
            (run_execution.stderr, run_execution.stdout)
            if report is None and not clean_exit
            else ()
        ),
    )
    if segv_retried:
        diagnostics.insert(0, _ASAN_SEGV_RETRIED)
    if hash_diagnostic and hash_diagnostic not in diagnostics:
        diagnostics.append(hash_diagnostic)
    return ReproExecution(
        stage="run",
        ok=ok,
        exit_code=run_execution.returncode,
        asan_report=report,
        diagnostics=tuple(diagnostics[:_MAX_DIAGNOSTICS]),
        artifacts=artifacts,
        elapsed_seconds=round(time.monotonic() - started, 6),
    )
