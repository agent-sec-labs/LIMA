"""Narrow Semgrep-backed source-only scanning inside a prepared snapshot."""

from __future__ import annotations

import json
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path, PurePosixPath

from .config import MAX_ARGUMENTS_PER_STEP, AnalyzerSettings
from .deadline import AnalysisDeadline
from .execution import ToolExecution, run_step
from .languages import language_for_path
from .normalizers import SUPPORTED_CWES, NormalizedFinding
from .protocol import new_run_id, timed_out_tool_run, tool_run_from_execution
from .snapshot import PreparedSnapshot, _read_regular_file

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
    if (
        parsed.is_absolute()
        or "\\" in path
        or "\0" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
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


def _snapshot_evidence(
    snapshot: PreparedSnapshot,
    settings: AnalyzerSettings,
    deadline: AnalysisDeadline,
    path: str,
    line: int,
) -> str:
    data = _read_regular_file(
        snapshot.root, snapshot.root / path, settings.repository_scan_max_file_bytes, deadline
    )
    lines = data.decode("utf8").splitlines()
    if line > len(lines) or not lines[line - 1].strip():
        raise ValueError("Semgrep result line lacks snapshot source evidence")
    return lines[line - 1]


def parse_semgrep_json(
    raw: str,
    snapshot_files: set[str],
    *,
    source_reader: Callable[[str, int], str] | None = None,
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
        # A valid tool document can contain many unsupported-source errors on
        # a large repository. Keep the rejection bounded and explicit instead
        # of misclassifying the entire JSON document as malformed. No findings
        # from an incomplete scan are admitted, including this overflow path.
        return (), ["semgrep-reported-errors", f"semgrep-error-limit-exceeded:{len(errors)}"]
    for error in errors:
        if not isinstance(error, dict):
            raise ValueError("Semgrep error is invalid")
        # Real Semgrep emits structured types (for example a
        # ["PartialParsing", [...]] pair); only their boundedness matters
        # because the error path never yields findings.
        raw_type = error.get("type")
        if isinstance(raw_type, str):
            error_type = raw_type
        elif isinstance(raw_type, list) and raw_type and isinstance(raw_type[0], str):
            error_type = raw_type[0]
        else:
            error_type = json.dumps(raw_type, sort_keys=True, default=str)
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
        if source_reader is not None:
            evidence = source_reader(path, start["line"])
        if (
            not isinstance(evidence, str)
            or not evidence
            or (source_reader is None and evidence.strip().lower() == "requires login")
        ):
            raise ValueError("Semgrep result lacks bounded source evidence")
        check_id = result["check_id"]
        title = extra.get("message", check_id)
        if not isinstance(title, str) or not title:
            title = check_id
        findings.append(
            NormalizedFinding.create(
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
                trace=json.dumps(
                    {"check_id": check_id, "metadata": extra["metadata"]}, sort_keys=True
                ),
                diagnostics=diagnostics,
            )
        )
    return tuple(findings), diagnostics


def _tool_run(execution: ToolExecution, run_id: str) -> dict[str, object]:
    return tool_run_from_execution("semgrep", execution, run_id=run_id)


def _recovery_targets(raw: str, snapshot_files: set[str]) -> tuple[list[str], int, int] | None:
    """Only tool-identified source gaps may narrow one fresh, independent scan."""
    try:
        document = json.loads(raw)
        errors = document.get("errors")
        if not isinstance(errors, list) or not errors or len(errors) > 4096:
            return None
        excluded: set[str] = set()
        for error in errors:
            if not isinstance(error, dict):
                return None
            raw_kind = error.get("type")
            kind = raw_kind[0] if isinstance(raw_kind, list) and raw_kind else raw_kind
            if kind not in {
                "PartialParsing",
                "Parse error",
                "Syntax error",
                "Other syntax error",
                "Lexical error",
                "Timeout",
            }:
                return None
            paths = [error["path"]] if error.get("path") is not None else []
            if (
                not paths
                and kind == "PartialParsing"
                and isinstance(raw_kind, list)
                and len(raw_kind) == 2
                and isinstance(raw_kind[1], list)
            ):
                paths = [
                    location.get("path") if isinstance(location, dict) else None
                    for location in raw_kind[1]
                ]
            if not paths:
                return None
            for raw_path in paths:
                path = _safe_result_path(raw_path, snapshot_files)
                language_for_path(path)
                excluded.add(path)
        sources = set()
        for path in snapshot_files:
            try:
                language_for_path(path)
            except ValueError:
                continue
            sources.add(path)
        targets = sorted(sources - excluded)
        # Bound argv independently of source/output byte budgets. Each path is
        # a separate argument after --, never a shell string or exclude glob.
        if (
            not targets
            or len(targets) > 20_000
            or any(len(path.encode("utf8")) > 4096 for path in targets)
            or sum(len(path.encode("utf-8")) + 1 for path in targets) > 1024 * 1024
        ):
            return None
        return targets, len(excluded), len(errors)
    except (TypeError, ValueError, AttributeError):
        return None


def _recover_source_scan(
    snapshot: PreparedSnapshot,
    settings: AnalyzerSettings,
    deadline: AnalysisDeadline,
    raw: str,
    rule_text: str,
    stage_root: Path,
    first_run: dict[str, object],
) -> LayerResult | None:
    selection = _recovery_targets(raw, set(snapshot.files))
    if selection is None:
        return None
    targets, excluded_count, error_count = selection
    timeout = deadline.step_timeout(settings.step_timeout_seconds)
    if timeout < 1:
        return None
    try:
        with tempfile.TemporaryDirectory(prefix="lima-semgrep-retry-", dir=stage_root) as directory:
            rule_path = Path(directory) / _RULE_FILE_NAME
            rule_path.write_text(rule_text, encoding="utf8")
            command = (
                "semgrep",
                "scan",
                "--experimental",
                "--json",
                "--quiet",
                "--no-rewrite-rule-ids",
                "--jobs",
                "2",
                "--max-target-bytes",
                str(settings.repository_scan_max_file_bytes),
                "--config",
                str(rule_path),
                "--metrics=off",
                "--disable-version-check",
                "--",
                *targets,
            )
            if len(command) > MAX_ARGUMENTS_PER_STEP:
                manifest = Path(directory) / "targets.json"
                manifest.write_text(json.dumps(targets, ensure_ascii=False), encoding="utf8")
                command = (
                    sys.executable,
                    "-I",
                    str(Path(sys.prefix) / "lib/lima-semgrep-targets.py"),
                    str(rule_path),
                    str(manifest),
                    str(settings.repository_scan_max_file_bytes),
                )
            execution = run_step(
                command,
                snapshot,
                ".",
                timeout_seconds=timeout,
                max_output_bytes=settings.max_output_bytes,
                env={},
                deadline=deadline,
            )
    except (OSError, ValueError):
        return LayerResult(
            (), ("semgrep-reported-errors", "semgrep-recovery-unavailable"), (first_run,)
        )
    run_id = new_run_id()
    try:
        if (
            execution.status != "completed"
            or execution.output_truncated
            or not execution.digests_complete
        ):
            raise ValueError("recovery execution was incomplete")
        findings, diagnostics = parse_semgrep_json(
            execution.stdout,
            set(targets),
            source_reader=lambda path, line: _snapshot_evidence(
                snapshot, settings, deadline, path, line
            ),
        )
        if diagnostics:
            raise ValueError("recovery scan remained incomplete")
    except ValueError as exc:
        return LayerResult(
            (),
            (
                "semgrep-reported-errors",
                "semgrep-recovery-failed",
                f"semgrep-recovery-tool-status:{execution.status}",
                f"semgrep-recovery-returncode:{execution.returncode}",
                f"semgrep-recovery-reason:{str(exc)[:100]}",
                f"semgrep-initial-error-count:{error_count}",
                f"semgrep-excluded-source-files:{excluded_count}",
                f"semgrep-recovery-attempted-source-files:{len(targets)}",
            ),
            (
                first_run,
                tool_run_from_execution("semgrep", execution, run_id=run_id, semantic_failure=True),
            ),
        )
    return LayerResult(
        tuple(finding.bind_producer(run_id) for finding in findings),
        (
            f"semgrep-initial-error-count:{error_count}",
            f"semgrep-excluded-source-files:{excluded_count}",
            f"semgrep-accepted-source-files:{len(targets)}",
        ),
        (first_run, _tool_run(execution, run_id)),
    )


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
        with tempfile.TemporaryDirectory(prefix="lima-semgrep-", dir=stage_root) as rule_directory:
            rule_path = Path(rule_directory) / _RULE_FILE_NAME
            rule_path.write_text(rule_text, encoding="utf-8")
            execution = run_step(
                (
                    "semgrep",
                    "scan",
                    "--experimental",
                    "--json",
                    "--quiet",
                    "--no-rewrite-rule-ids",
                    "--jobs",
                    "2",
                    "--max-target-bytes",
                    str(settings.repository_scan_max_file_bytes),
                    "--config",
                    str(rule_path),
                    "--include",
                    "*.c",
                    "--include",
                    "*.cc",
                    "--include",
                    "*.cpp",
                    "--include",
                    "*.cxx",
                    "--include",
                    "*.h",
                    "--include",
                    "*.hh",
                    "--include",
                    "*.hpp",
                    "--include",
                    "*.hxx",
                    "--metrics=off",
                    "--disable-version-check",
                    ".",
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
    run_id = new_run_id()
    tool_runs = (_tool_run(execution, run_id),)
    if execution.status != "completed":
        return LayerResult((), ("Semgrep source scan did not complete",), tool_runs)
    if not execution.digests_complete or execution.output_truncated:
        return LayerResult(
            (),
            ("Semgrep output was incomplete or truncated",),
            (tool_run_from_execution("semgrep", execution, run_id=run_id, semantic_failure=True),),
        )
    try:
        findings, diagnostics = parse_semgrep_json(
            execution.stdout,
            set(snapshot.files),
            source_reader=lambda path, line: _snapshot_evidence(
                snapshot, settings, active_deadline, path, line
            ),
        )
    except ValueError:
        return LayerResult(
            (),
            ("Semgrep JSON was rejected",),
            (tool_run_from_execution("semgrep", execution, run_id=run_id, semantic_failure=True),),
        )
    if diagnostics:
        failed_run = tool_run_from_execution(
            "semgrep", execution, run_id=run_id, semantic_failure=True
        )
        recovered = _recover_source_scan(
            snapshot,
            settings,
            active_deadline,
            execution.stdout,
            rule_text,
            stage_root,
            failed_run,
        )
        if recovered is not None:
            return recovered
        return LayerResult(
            (),
            tuple(diagnostics),
            (failed_run,),
        )
    return LayerResult(
        tuple(item.bind_producer(run_id) for item in findings),
        tuple(diagnostics),
        tool_runs,
    )


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
