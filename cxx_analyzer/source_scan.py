"""Narrow Semgrep-backed source-only scanning inside a prepared snapshot."""

from __future__ import annotations

import json
import sys
import tempfile
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path, PurePosixPath

from .config import AnalyzerSettings
from .deadline import AnalysisDeadline
from .execution import ToolExecution, run_step
from .languages import language_for_path
from .normalizers import SUPPORTED_CWES, NormalizedFinding
from .protocol import timed_out_tool_run, tool_run_from_execution
from .snapshot import PreparedSnapshot

_RULE_PREFIXES = {
    "cxx.source.oob-write": "CWE-787",
    "cxx.source.oob-read": "CWE-125",
    "cxx.source.use-after-free": "CWE-416",
    "cxx.source.double-free": "CWE-415",
}
_RULE_FILE_NAME = ".lima-semgrep-rules.yml"
RULES_TEMP_ROOT: Path | None = None
MAX_SEMGREP_ERRORS = 64
MAX_SEMGREP_ERROR_BYTES = 4_096


@dataclass(frozen=True)
class LayerResult:
    findings: tuple[NormalizedFinding, ...]
    diagnostics: tuple[str, ...]
    tool_runs: tuple[dict[str, object], ...]
    build_context: object | None = None


def _safe_result_path(path: object, snapshot_files: set[str]) -> str:
    if not isinstance(path, str) or not path:
        raise ValueError("Semgrep result path is invalid")
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or "\\" in path or "\0" in path or any(
        part in {"", ".", ".."} for part in path.split("/")
    ):
        raise ValueError("Semgrep result path escapes the snapshot")
    if path not in snapshot_files:
        raise ValueError("Semgrep result path was not scanned from the snapshot")
    return path


def _rule_cwe(check_id: object, metadata: object) -> str:
    if not isinstance(check_id, str) or not isinstance(metadata, dict):
        raise ValueError("Semgrep rule metadata is invalid")
    cwe = metadata.get("cwe")
    if cwe not in SUPPORTED_CWES or metadata.get("candidate") is not True:
        raise ValueError("Semgrep rule metadata is incomplete")
    for prefix, expected_cwe in _RULE_PREFIXES.items():
        if check_id == prefix or check_id.startswith(prefix + "."):
            if cwe != expected_cwe:
                raise ValueError("Semgrep rule CWE does not match its fixed prefix")
            return cwe
    raise ValueError("Semgrep rule id is outside the narrow source rule set")


def _symbol(metavars: object) -> str:
    if not isinstance(metavars, dict):
        return "unknown"
    candidate = metavars.get("$FUNC")
    if isinstance(candidate, dict) and isinstance(candidate.get("abstract_content"), str):
        value = candidate["abstract_content"].strip()
        if value:
            return value
    return "unknown"


def parse_semgrep_json(
    raw: str, snapshot_files: set[str]
) -> tuple[tuple[NormalizedFinding, ...], list[str]]:
    """Parse only trusted Semgrep fields, rejecting malformed tool output entirely."""

    try:
        document = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Semgrep did not return valid JSON") from exc
    if (
        not isinstance(document, dict)
        or not isinstance(document.get("results"), list)
        or not isinstance(document.get("errors"), list)
    ):
        raise ValueError("Semgrep JSON lacks a results list")

    errors = document["errors"]
    if len(errors) > MAX_SEMGREP_ERRORS:
        raise ValueError("Semgrep JSON contains too many errors")
    for error in errors:
        if not isinstance(error, dict):
            raise ValueError("Semgrep error is invalid")
        error_type = error.get("type")
        message = error.get("message")
        if (
            not isinstance(error_type, str)
            or not error_type
            or not isinstance(message, str)
            or not message
            or len(error_type.encode("utf-8")) > MAX_SEMGREP_ERROR_BYTES
            or len(message.encode("utf-8")) > MAX_SEMGREP_ERROR_BYTES
        ):
            raise ValueError("Semgrep error is invalid")
    if errors:
        return (), ["semgrep-reported-errors"]

    diagnostics: list[str] = []
    findings: list[NormalizedFinding] = []
    for result in document["results"]:
        if not isinstance(result, dict):
            raise ValueError("Semgrep result is invalid")
        extra = result.get("extra")
        if not isinstance(extra, dict):
            raise ValueError("Semgrep result lacks extra metadata")
        cwe = _rule_cwe(result.get("check_id"), extra.get("metadata"))
        path = _safe_result_path(result.get("path"), snapshot_files)
        start = result.get("start")
        if not isinstance(start, dict) or type(start.get("line")) is not int or start["line"] < 1:
            raise ValueError("Semgrep result line is invalid")
        try:
            language = language_for_path(path)
        except ValueError:
            raise ValueError("Semgrep result does not identify C or C++ source") from None
        evidence = extra.get("lines", "")
        if not isinstance(evidence, str) or not evidence:
            raise ValueError("Semgrep result lacks bounded source evidence")
        check_id = result["check_id"]
        title = extra.get("message", check_id)
        if not isinstance(title, str) or not title:
            title = check_id
        findings.append(NormalizedFinding.create(
            rule_id=check_id,
            severity="high",
            title=title,
            explanation=(
                "A narrow Semgrep source pattern matched; runtime confirmation is required."
            ),
            path=path,
            line=start["line"],
            evidence=evidence,
            fix="",
            test="Exercise the affected path under AddressSanitizer.",
            confidence=0.5,
            cwe=cwe,
            tool="semgrep",
            evidence_kind="line",
            verification_state="candidate",
            language=language,
            symbol=_symbol(extra.get("metavars")),
            analysis_mode="source-only",
            trace=json.dumps({"check_id": check_id, "metadata": extra["metadata"]}, sort_keys=True),
            diagnostics=diagnostics,
        ))
    return tuple(findings), diagnostics


def _tool_run(execution: ToolExecution) -> dict[str, object]:
    return tool_run_from_execution("semgrep", execution)


def run_source_scan(
    snapshot: PreparedSnapshot,
    settings: AnalyzerSettings,
    *,
    deadline: AnalysisDeadline | None = None,
) -> LayerResult:
    """Run packaged narrow rules without admitting any unbounded tool output."""

    active_deadline = deadline or AnalysisDeadline.start(settings.total_timeout_seconds)
    timeout = active_deadline.step_timeout(settings.step_timeout_seconds)
    if timeout < 1:
        return LayerResult((), ("timed-out",), (timed_out_tool_run("semgrep"),))
    snapshot.resolve_cwd(".")
    rule_text = files("cxx_analyzer.rules").joinpath("cxx-memory.yml").read_text(encoding="utf-8")
    stage_root = RULES_TEMP_ROOT or snapshot.scratch_root
    try:
        with tempfile.TemporaryDirectory(
            prefix="lima-semgrep-", dir=stage_root
        ) as rule_directory:
            rule_path = Path(rule_directory) / _RULE_FILE_NAME
            rule_path.write_text(rule_text, encoding="utf-8")
            execution = run_step(
                (
                    "semgrep", "--json", "--quiet", "--no-rewrite-rule-ids",
                    "--config", str(rule_path),
                    "--include", "*.c", "--include", "*.cc", "--include", "*.cpp",
                    "--include", "*.cxx", "--include", "*.h", "--include", "*.hh",
                    "--include", "*.hpp", "--include", "*.hxx", ".",
                ),
                snapshot,
                ".",
                timeout_seconds=timeout,
                max_output_bytes=settings.max_output_bytes,
                env={},
                deadline=active_deadline,
            )
    except OSError:
        return LayerResult((), ("Semgrep rule staging was unavailable",), ())
    tool_runs = (_tool_run(execution),)
    if execution.status != "completed":
        return LayerResult((), ("Semgrep source scan did not complete",), tool_runs)
    if not execution.digests_complete or execution.output_truncated:
        return LayerResult((), ("Semgrep output was incomplete or truncated",), tool_runs)
    try:
        findings, diagnostics = parse_semgrep_json(execution.stdout, set(snapshot.files))
    except ValueError:
        return LayerResult((), ("Semgrep JSON was rejected",), tool_runs)
    if diagnostics:
        return LayerResult(
            (),
            tuple(diagnostics),
            (tool_run_from_execution("semgrep", execution, semantic_failure=True),),
        )
    return LayerResult(findings, tuple(diagnostics), tool_runs)


def recognized_host_semgrep_unavailability(
    returncode: int, stderr: str, *, platform_name: str | None = None
) -> bool:
    """Recognize only the documented Windows trust-store startup failure."""

    platform_value = platform_name or sys.platform
    return (
        platform_value == "win32"
        and returncode == 2
        and "Failed to create system store X509 authenticator" in stderr
    )
