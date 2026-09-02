"""Fail-closed AddressSanitizer confirmation for an already-built snapshot."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Final

from .build_scan import BuildContext
from .config import AnalyzerSettings
from .deadline import AnalysisDeadline
from .execution import SANITIZER_ENVIRONMENT, ToolExecution, run_step
from .languages import language_for_path
from .normalizers import NormalizedFinding
from .protocol import tool_run_from_execution
from .snapshot import PreparedSnapshot
from .source_scan import LayerResult

MAX_FINDINGS: Final = 64
MAX_DIAGNOSTICS: Final = 64
MAX_TOOL_RUNS: Final = 64
_ANSI: Final = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ERROR: Final = re.compile(
    r"^==\d+==ERROR: AddressSanitizer: "
    r"(heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow|"
    r"heap-use-after-free|attempting double-free)\b",
    re.MULTILINE,
)
_SUMMARY: Final = re.compile(
    r"^SUMMARY: AddressSanitizer: (heap-buffer-overflow|stack-buffer-overflow|"
    r"global-buffer-overflow|heap-use-after-free|double-free)\b",
    re.MULTILINE,
)
_ACCESS: Final = re.compile(r"^(READ|WRITE) of size \d+ at\b", re.MULTILINE)
_AUXILIARY_STACK: Final = re.compile(
    r"^(?:freed by thread|previously allocated by thread|allocated by thread)\b",
    re.MULTILINE,
)
_FRAME: Final = re.compile(
    r"^\s*#\d+\s+(?:0x[0-9a-fA-F]+\s+in\s+)?"
    r"(?P<symbol>[^\r\n]*?)\s+(?P<path>(?:[A-Za-z]:)?/[^\r\n:]+):(?P<line>[1-9]\d*)(?::\d+)?\s*$",
    re.MULTILINE,
)
_CWE_SLUG: Final = {
    "CWE-787": "oob-write", "CWE-125": "oob-read",
    "CWE-416": "use-after-free", "CWE-415": "double-free",
}


def _review() -> tuple[list[NormalizedFinding], list[str]]:
    return [], ["needs-human-review"]


def _map(error_type: str, access: str | None) -> str | None:
    if error_type in {"heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow"}:
        return {"READ": "CWE-125", "WRITE": "CWE-787"}.get(access)
    if error_type == "heap-use-after-free":
        return "CWE-416" if access in {"READ", "WRITE"} else None
    if error_type == "attempting double-free":
        return "CWE-415"
    return None


def _safe_frame(block: str, snapshot: PreparedSnapshot) -> tuple[str, int, str] | None:
    root = Path(snapshot.root).resolve()
    files = set(snapshot.files)
    for frame in _FRAME.finditer(block):
        try:
            path = Path(frame.group("path")).resolve().relative_to(root).as_posix()
        except (ValueError, OSError):
            continue
        if path not in files:
            continue
        symbol = frame.group("symbol").strip()
        if not symbol or "/" in symbol or "\\" in symbol or "\x00" in symbol:
            continue
        return path, int(frame.group("line")), symbol
    return None


def parse_asan_log(
    text: str, snapshot: PreparedSnapshot | None = None
) -> tuple[list[NormalizedFinding], list[str]]:
    """Accept only complete ASan reports with a structured in-snapshot frame.

    A snapshot is intentionally required for a finding: text-only callers get a
    review diagnostic because an absolute tool path cannot prove repository
    containment.
    """

    if not isinstance(text, str) or snapshot is None:
        return _review()
    clean = _ANSI.sub("", text)
    findings: list[NormalizedFinding] = []
    for match in _ERROR.finditer(clean):
        if len(findings) >= MAX_FINDINGS:
            return _review()
        next_error = _ERROR.search(clean, match.end())
        block = clean[match.start(): next_error.start() if next_error else len(clean)]
        error_type = match.group(1)
        summary = _SUMMARY.search(block)
        summary_type = "double-free" if error_type == "attempting double-free" else error_type
        if summary is None or summary.group(1) != summary_type:
            return _review()
        auxiliary = _AUXILIARY_STACK.search(block)
        primary_end = min(
            summary.start(), auxiliary.start() if auxiliary is not None else len(block)
        )
        primary = block[:primary_end]
        access_match = _ACCESS.search(primary)
        access = access_match.group(1) if access_match else None
        cwe = _map(error_type, access)
        frame = _safe_frame(primary, snapshot)
        if cwe is None or frame is None:
            return _review()
        path, line, symbol = frame
        language = language_for_path(path)
        access_text = access if access is not None else "FREE"
        trace = json.dumps(
            [{"kind": "asan-frame", "path": path, "line": line}],
            separators=(",", ":"), sort_keys=True,
        )
        findings.append(NormalizedFinding.create(
            rule_id=f"cxx.asan.{_CWE_SLUG[cwe]}", severity="high",
            title=f"AddressSanitizer {error_type}",
            explanation="AddressSanitizer produced a complete structured runtime report.",
            path=path, line=line,
            evidence=f"AddressSanitizer reported {error_type} ({access_text}).",
            fix="", test="Reproduce under AddressSanitizer.", confidence=1.0,
            cwe=cwe, tool="asan", evidence_kind="sanitizer",
            verification_state="confirmed", language=language, symbol=symbol,
            analysis_mode="sanitizer-confirmed", trace=trace, diagnostics=[],
        ))
    return (findings, []) if findings else _review()


def _tool_run(execution: ToolExecution) -> dict[str, object]:
    return tool_run_from_execution("asan-test", execution)


def _valid_context(
    snapshot: PreparedSnapshot,
    context: object,
    deadline: AnalysisDeadline | None,
) -> bool:
    return (
        isinstance(context, BuildContext)
        and context.sanitizer_enabled
        and context.snapshot_root == Path(snapshot.root).resolve()
        and context.snapshot_files == tuple(snapshot.files)
        and isinstance(context.deadline, AnalysisDeadline)
        and (deadline is None or context.deadline is deadline)
    )


def run_sanitizer_scan(
    snapshot: PreparedSnapshot,
    settings: AnalyzerSettings,
    build_context: object,
    *,
    deadline: AnalysisDeadline | None = None,
) -> LayerResult:
    """Run administrator test argv only after a matching successful build."""

    if not settings.test_steps:
        return LayerResult((), ("sanitizer-not-configured",), ())
    if not _valid_context(snapshot, build_context, deadline):
        return LayerResult((), ("sanitizer-build-context-unavailable",), ())
    active_deadline = build_context.deadline
    snapshot.resolve_cwd(".")
    findings: list[NormalizedFinding] = []
    diagnostics: list[str] = []
    tool_runs: list[dict[str, object]] = []
    for step in settings.test_steps:
        if len(tool_runs) >= MAX_TOOL_RUNS:
            diagnostics.append("analysis-budget-exhausted")
            break
        remaining = active_deadline.step_timeout(settings.step_timeout_seconds)
        if remaining < 1:
            diagnostics.append("timed-out")
            break
        execution = run_step(
            step, snapshot, ".", remaining, settings.max_output_bytes,
            env=SANITIZER_ENVIRONMENT, deadline=active_deadline,
        )
        tool_runs.append(_tool_run(execution))
        if (
            execution.status == "timed-out"
            or execution.output_truncated
            or not execution.digests_complete
        ):
            diagnostics.append("needs-human-review")
            continue
        combined_output = execution.stdout + "\n" + execution.stderr
        parsed, parsed_diagnostics = parse_asan_log(combined_output, snapshot)
        if parsed:
            findings.extend(parsed[: MAX_FINDINGS - len(findings)])
        elif execution.status == "failed":
            no_sanitizer_evidence = (
                parsed_diagnostics == ["needs-human-review"]
                and "AddressSanitizer" not in combined_output
            )
            diagnostics.append(
                "test-failed-without-sanitizer-evidence"
                if no_sanitizer_evidence
                else "needs-human-review"
            )
        else:
            diagnostics.extend(parsed_diagnostics)
        if len(findings) >= MAX_FINDINGS or len(diagnostics) >= MAX_DIAGNOSTICS:
            diagnostics = diagnostics[:MAX_DIAGNOSTICS]
            if "analysis-budget-exhausted" not in diagnostics:
                diagnostics[-1:] = ["analysis-budget-exhausted"]
            break
    return LayerResult(tuple(findings), tuple(diagnostics), tuple(tool_runs))
