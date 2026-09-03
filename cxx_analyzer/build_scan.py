"""CMake and Clang Static Analyzer orchestration inside a verified snapshot."""

from __future__ import annotations

import json
import plistlib
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from .config import MAX_ARGUMENT_BYTES, MAX_ARGUMENTS_PER_STEP, AnalyzerSettings
from .deadline import AnalysisDeadline
from .execution import SANITIZER_ENVIRONMENT, ToolExecution, run_step
from .languages import language_for_path
from .normalizers import NormalizedFinding
from .protocol import new_run_id, timed_out_tool_run, tool_run_from_execution
from .snapshot import PreparedSnapshot
from .source_scan import LayerResult

_CMAKE_STEPS: Final = (
    (
        "cmake",
        "-S",
        ".",
        "-B",
        "build",
        "-DCMAKE_BUILD_TYPE=Debug",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
    ),
    ("cmake", "--build", "build", "--parallel", "2"),
)
_CHECKER_CWE: Final = {
    ("alpha.security.ArrayBoundV2", "Out-of-bound write"): "CWE-787",
    ("alpha.security.ArrayBoundV2", "Out-of-bound read"): "CWE-125",
    ("unix.Malloc", "Use-after-free"): "CWE-416",
    ("unix.Malloc", "Double free"): "CWE-415",
}
_CWE_SLUG: Final = {
    "CWE-787": "oob-write",
    "CWE-125": "oob-read",
    "CWE-416": "use-after-free",
    "CWE-415": "double-free",
}
_MAX_DATABASE_BYTES: Final = 4 * 1024 * 1024
_MAX_DATABASE_ENTRIES: Final = 2048
_MAX_PLIST_BYTES: Final = 4 * 1024 * 1024
_ANALYZER_TEMP_ROOT: Path | None = None
MAX_COMPILATION_UNITS: Final = 256
MAX_FINDINGS: Final = 256
MAX_DIAGNOSTICS: Final = 256
MAX_TOOL_RUNS: Final = 320
MAX_AGGREGATE_PLIST_BYTES: Final = 8 * 1024 * 1024
_BUDGET_DIAGNOSTIC: Final = "analysis-budget-exhausted"
_SUPPORTED_PATH_OPTIONS: Final = frozenset(
    {
        "-I",
        "-F",
        "-B",
        "-include",
        "-include-pch",
        "-include-pth",
        "-imacros",
        "-isystem",
        "-isysroot",
        "-iquote",
        "-idirafter",
        "-iframework",
        "-iframeworkwithsysroot",
        "-iprefix",
        "-iwithprefix",
        "-iwithprefixbefore",
        "-ivfsoverlay",
        "-resource-dir",
        "-stdlib++-isystem",
        "--sysroot",
        "--gcc-toolchain",
        "-gcc-toolchain",
        "-fmodule-file",
        "-fmodule-map-file",
        "-fprofile-use",
        "-fprofile-instr-use",
        "-fprofile-sample-use",
        "-fprofile-list",
        "-fmodules-cache-path",
    }
)
_CONCATENATED_PATH_OPTIONS: Final = ("-I", "-F", "-B")
_FORBIDDEN_PASSTHROUGH_OPTIONS: Final = frozenset(
    {
        "-cc1",
        "-fplugin",
        "-load",
        "-mllvm",
        "-plugin",
        "-Xanalyzer",
        "-Xassembler",
        "-Xclang",
        "-Xlinker",
        "-Xpreprocessor",
        "--config",
    }
)
_FORBIDDEN_PASSTHROUGH_PREFIXES: Final = ("-Wa,", "-Wl,", "-Wp,")
_FORBIDDEN_JOINED_PASSTHROUGH_PREFIXES: Final = (
    "--config=",
    "-fplugin=",
    "-load=",
    "-mllvm=",
    "-plugin=",
    "-Xanalyzer=",
    "-Xassembler=",
    "-Xclang=",
    "-Xlinker=",
    "-Xpreprocessor=",
)


@dataclass(frozen=True)
class CompilationUnit:
    """One validated argv-array compilation database entry."""

    directory: str
    file: str
    arguments: tuple[str, ...]


@dataclass(frozen=True)
class BuildContext:
    """A narrow proof that this live snapshot completed its trusted build steps."""

    snapshot_root: Path
    snapshot_files: tuple[str, ...]
    sanitizer_enabled: bool = False
    deadline: AnalysisDeadline | None = None


class AnalysisBudgetExceeded(ValueError):
    """A stable internal signal that analysis must stop without more tool launches."""


def select_build_steps(
    snapshot: PreparedSnapshot, settings: AnalyzerSettings
) -> tuple[tuple[str, ...], ...]:
    """Select only fixed CMake argv or administrator-provided argv arrays."""

    if settings.auto_cmake and "CMakeLists.txt" in snapshot.files:
        return _CMAKE_STEPS
    return settings.build_steps


def _inside_snapshot(root: Path, value: Path) -> tuple[Path, str]:
    resolved_root = root.resolve()
    resolved = value.resolve()
    try:
        relative = resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError("build path escapes the snapshot") from exc
    relative_text = relative.as_posix()
    if relative_text in {"", "."}:
        return resolved, "."
    parsed = PurePosixPath(relative_text)
    if any(part in {"", ".", ".."} for part in parsed.parts):
        raise ValueError("build path is not a safe snapshot-relative path")
    return resolved, relative_text


def _bounded_bytes(path: Path, maximum: int, label: str) -> bytes:
    try:
        with path.open("rb") as stream:
            raw = stream.read(maximum + 1)
    except OSError as exc:
        raise ValueError(f"{label} is unreadable") from exc
    if len(raw) > maximum:
        raise ValueError(f"{label} exceeds the byte limit")
    return raw


def _bounded_json(path: Path) -> object:
    try:
        return json.loads(_bounded_bytes(path, _MAX_DATABASE_BYTES, "compilation database"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("compilation database is unreadable") from exc


def _validate_argument_paths(root: Path, working_directory: Path, arguments: list[str]) -> None:
    if not arguments[0]:
        raise ValueError("compilation database executable is empty")
    expected_path_option: str | None = None
    for argument in arguments[1:]:
        if argument.startswith("@"):
            raise ValueError("compilation database response files are forbidden")
        if expected_path_option is not None:
            if expected_path_option == "-fmodule-file" and "=" in argument:
                argument = argument.rsplit("=", 1)[1]
            if not argument:
                raise ValueError("compilation database path option is empty")
            _inside_snapshot(
                root,
                Path(argument) if Path(argument).is_absolute() else working_directory / argument,
            )
            expected_path_option = None
            continue
        if argument in _FORBIDDEN_PASSTHROUGH_OPTIONS or argument.startswith(
            (*_FORBIDDEN_PASSTHROUGH_PREFIXES, *_FORBIDDEN_JOINED_PASSTHROUGH_PREFIXES)
        ):
            raise ValueError("compilation database passthrough options are forbidden")
        if argument in _SUPPORTED_PATH_OPTIONS:
            expected_path_option = argument
            continue
        option, separator, option_value = argument.partition("=")
        if separator and option in _SUPPORTED_PATH_OPTIONS:
            if option == "-fmodule-file" and "=" in option_value:
                option_value = option_value.rsplit("=", 1)[1]
            if not option_value:
                raise ValueError("compilation database path option is empty")
            _inside_snapshot(
                root,
                Path(option_value)
                if Path(option_value).is_absolute()
                else working_directory / option_value,
            )
            continue
        concatenated_path = next(
            (
                argument[len(prefix) :]
                for prefix in _CONCATENATED_PATH_OPTIONS
                if argument.startswith(prefix) and len(argument) > len(prefix)
            ),
            None,
        )
        if concatenated_path is not None:
            _inside_snapshot(
                root,
                Path(concatenated_path)
                if Path(concatenated_path).is_absolute()
                else working_directory / concatenated_path,
            )
            continue
        if (
            argument.startswith("-")
            and not argument.startswith(("-D", "-U"))
            and ("/" in argument or "\\" in argument)
        ):
            raise ValueError("unknown joined path-bearing option is forbidden")
        if (
            separator
            and not option.startswith(("-D", "-U"))
            and (
                Path(option_value).is_absolute()
                or "/" in option_value
                or "\\" in option_value
                or option_value.startswith(".")
            )
        ):
            raise ValueError("unknown path-bearing compiler option is forbidden")
        if not argument.startswith("-"):
            _inside_snapshot(
                root,
                Path(argument) if Path(argument).is_absolute() else working_directory / argument,
            )
    if expected_path_option is not None:
        raise ValueError("compilation database path option lacks a value")


def load_compilation_database(
    snapshot: PreparedSnapshot, database_path: Path
) -> tuple[CompilationUnit, ...]:
    """Load a bounded compdb, rejecting shell command strings and escaping files."""

    root = Path(snapshot.root).resolve()
    database, _ = _inside_snapshot(root, Path(database_path))
    document = _bounded_json(database)
    if not isinstance(document, list) or len(document) > _MAX_DATABASE_ENTRIES:
        raise ValueError("compilation database must be a bounded array")
    if len(document) > MAX_COMPILATION_UNITS:
        raise AnalysisBudgetExceeded("compilation unit budget exhausted")

    snapshot_files = set(snapshot.files)
    units: list[CompilationUnit] = []
    for entry in document:
        if not isinstance(entry, dict) or "command" in entry:
            raise ValueError("compilation database command strings are forbidden")
        arguments = entry.get("arguments")
        directory = entry.get("directory")
        file = entry.get("file")
        if (
            not isinstance(arguments, list)
            or not arguments
            or len(arguments) > MAX_ARGUMENTS_PER_STEP
            or not isinstance(directory, str)
            or not directory
            or not isinstance(file, str)
            or not file
        ):
            raise ValueError("compilation database entry is invalid")
        if any(
            not isinstance(argument, str)
            or "\0" in argument
            or len(argument.encode("utf-8")) > MAX_ARGUMENT_BYTES
            for argument in arguments
        ):
            raise ValueError("compilation database arguments are invalid")
        working_directory, relative_directory = _inside_snapshot(
            root, Path(directory) if Path(directory).is_absolute() else root / directory
        )
        _validate_argument_paths(root, working_directory, arguments)
        source_path = Path(file)
        if not source_path.is_absolute():
            source_path = working_directory / source_path
        _, relative_file = _inside_snapshot(root, source_path)
        if relative_file not in snapshot_files:
            raise ValueError("compilation database source is outside the snapshot inventory")
        units.append(CompilationUnit(relative_directory, relative_file, tuple(arguments)))
    return tuple(units)


def _safe_plist_path(value: object, snapshot: PreparedSnapshot, relative_cwd: str) -> str | None:
    if not isinstance(value, str) or not value or "\0" in value or "\\" in value:
        raise ValueError("Clang plist file path is invalid")
    root = Path(snapshot.root).resolve()
    working_directory, _ = _inside_snapshot(root, root / relative_cwd)
    candidate = Path(value)
    if candidate.is_absolute():
        _, relative = _inside_snapshot(root, candidate)
    else:
        _, relative = _inside_snapshot(root, working_directory / value)
    return relative if relative in set(snapshot.files) else None


def _structured_location(location: object, files: tuple[str | None, ...]) -> tuple[str, int, int]:
    if not isinstance(location, dict):
        raise ValueError("Clang plist location is missing")
    file_index = location.get("file")
    line = location.get("line")
    column = location.get("col", 1)
    if (
        type(file_index) is not int
        or not 0 <= file_index < len(files)
        or type(line) is not int
        or line < 1
        or type(column) is not int
        or column < 1
    ):
        raise ValueError("Clang plist location is invalid")
    path = files[file_index]
    if path is None:
        raise LookupError("Clang diagnostic refers to a non-inventory file")
    return path, line, column


def parse_clang_plist(
    raw: bytes,
    snapshot: PreparedSnapshot,
    *,
    relative_cwd: str = ".",
) -> tuple[tuple[NormalizedFinding, ...], list[str]]:
    """Normalize only structured plist locations; never scrape human diagnostics."""

    if not isinstance(raw, bytes) or len(raw) > _MAX_PLIST_BYTES:
        raise ValueError("Clang plist exceeds the byte limit")
    try:
        document = plistlib.loads(raw)
    except (ValueError, TypeError, plistlib.InvalidFileException) as exc:
        raise ValueError("Clang output is not a valid plist") from exc
    if not isinstance(document, dict):
        raise ValueError("Clang plist root is invalid")
    raw_files = document.get("files")
    raw_diagnostics = document.get("diagnostics")
    if not isinstance(raw_files, list) or not isinstance(raw_diagnostics, list):
        raise ValueError("Clang plist lacks files or diagnostics")
    files = tuple(_safe_plist_path(path, snapshot, relative_cwd) for path in raw_files)

    findings: list[NormalizedFinding] = []
    diagnostics: list[str] = []
    for diagnostic in raw_diagnostics:
        if not isinstance(diagnostic, dict):
            raise ValueError("Clang plist diagnostic is invalid")
        checker = diagnostic.get("check_name")
        diagnostic_type = diagnostic.get("type")
        if not isinstance(checker, str) or not isinstance(diagnostic_type, str):
            raise ValueError("Clang plist checker metadata is invalid")
        cwe = _CHECKER_CWE.get((checker, diagnostic_type))
        if cwe is None:
            diagnostics.append("unsupported Clang checker result")
            continue
        try:
            path, line, _ = _structured_location(diagnostic.get("location"), files)
        except LookupError:
            diagnostics.append("Clang diagnostic outside snapshot inventory")
            continue
        description = diagnostic.get("description")
        symbol = diagnostic.get("issue_context")
        if not isinstance(description, str) or not description.strip():
            raise ValueError("Clang plist description is invalid")
        if not isinstance(symbol, str) or not symbol.strip():
            symbol = "unknown"

        raw_trace = diagnostic.get("path")
        if not isinstance(raw_trace, list):
            raise ValueError("Clang plist trace is invalid")
        trace: list[dict[str, object]] = []
        try:
            for frame in raw_trace:
                if not isinstance(frame, dict):
                    raise ValueError("Clang plist trace frame is invalid")
                kind = frame.get("kind")
                if kind == "event":
                    frame_path, frame_line, frame_column = _structured_location(
                        frame.get("location"), files
                    )
                    trace.append(
                        {
                            "kind": "event",
                            "path": frame_path,
                            "line": frame_line,
                            "column": frame_column,
                        }
                    )
                    continue
                if kind != "control" or not isinstance(frame.get("edges"), list):
                    raise ValueError("Clang plist trace kind is unsupported")
                for edge in frame["edges"]:
                    if not isinstance(edge, dict):
                        raise ValueError("Clang plist control edge is invalid")
                    for endpoint, trace_kind in (
                        ("start", "control-start"),
                        ("end", "control-end"),
                    ):
                        frame_path, frame_line, frame_column = _structured_location(
                            edge.get(endpoint), files
                        )
                        trace.append(
                            {
                                "kind": trace_kind,
                                "path": frame_path,
                                "line": frame_line,
                                "column": frame_column,
                            }
                        )
        except LookupError:
            diagnostics.append("Clang trace outside snapshot inventory")
            continue
        if not trace:
            trace.append({"kind": "event", "path": path, "line": line, "column": 1})
        language = language_for_path(path)
        findings.append(
            NormalizedFinding.create(
                rule_id=f"cxx.clang.{_CWE_SLUG[cwe]}",
                severity="high",
                title=diagnostic_type,
                explanation=description.strip(),
                path=path,
                line=line,
                evidence=description.strip(),
                fix="",
                test="Exercise the affected path under AddressSanitizer.",
                confidence=0.85,
                cwe=cwe,
                tool="clang",
                evidence_kind="path",
                verification_state="build-verified",
                language=language,
                symbol=symbol.strip(),
                analysis_mode="build-backed",
                trace=json.dumps(trace, separators=(",", ":"), sort_keys=True),
                diagnostics=diagnostics,
            )
        )
    return tuple(findings), diagnostics


def _tool_run(
    tool: str,
    execution: ToolExecution,
    run_id: str | None = None,
    *,
    build_step: bool = False,
) -> dict[str, object]:
    return tool_run_from_execution(
        tool, execution, run_id=run_id, build_step=build_step
    )


def _deadline_run(tool: str) -> dict[str, object]:
    return timed_out_tool_run(tool)


def _mark_budget_exhausted(diagnostics: list[str]) -> None:
    if _BUDGET_DIAGNOSTIC in diagnostics:
        return
    if len(diagnostics) >= MAX_DIAGNOSTICS:
        diagnostics[-1] = _BUDGET_DIAGNOSTIC
    else:
        diagnostics.append(_BUDGET_DIAGNOSTIC)


def _extend_parsed_results(
    findings: list[NormalizedFinding],
    diagnostics: list[str],
    parsed_findings: tuple[NormalizedFinding, ...],
    parsed_diagnostics: list[str],
) -> bool:
    for finding in parsed_findings:
        if len(findings) >= MAX_FINDINGS:
            _mark_budget_exhausted(diagnostics)
            return False
        findings.append(finding)
    for diagnostic in parsed_diagnostics:
        if len(diagnostics) >= MAX_DIAGNOSTICS:
            _mark_budget_exhausted(diagnostics)
            return False
        diagnostics.append(diagnostic)
    return True


def _find_database(snapshot: PreparedSnapshot) -> Path | None:
    root = Path(snapshot.root)
    preferred = (root / "build" / "compile_commands.json", root / "compile_commands.json")
    for candidate in preferred:
        if candidate.is_file():
            return candidate
    candidates = sorted(root.glob("*/compile_commands.json"))
    return candidates[0] if len(candidates) == 1 else None


def _analyzer_argv(unit: CompilationUnit, output: Path) -> tuple[str, ...]:
    compiler = (
        "clang++-14" if language_for_path(unit.file) == "c++" else "clang-14"
    )
    original = list(unit.arguments[1:])
    filtered: list[str] = []
    skip_next = False
    for argument in original:
        if skip_next:
            skip_next = False
            continue
        if argument in {"-o", "-MF", "-MT", "-MQ"}:
            skip_next = True
            continue
        if argument in {"-c", "-MMD", "-MD", "-MP"}:
            continue
        if argument.startswith("@"):
            raise ValueError("compilation database response files are forbidden")
        if re.match(r"^-(?:o|MF|MT|MQ).+", argument):
            continue
        filtered.append(argument)
    return (
        compiler,
        "--analyze",
        "-Xanalyzer",
        "-analyzer-output=plist",
        "-Xanalyzer",
        "-analyzer-checker=core,unix,alpha.security.ArrayBoundV2",
        *filtered,
        "-o",
        str(output),
    )


def run_build_scan(
    snapshot: PreparedSnapshot,
    settings: AnalyzerSettings,
    *,
    sanitizer_enabled: bool = False,
    deadline: AnalysisDeadline | None = None,
) -> LayerResult:
    """Build a trusted context and run Clang without turning target failures into HTTP errors."""

    steps = select_build_steps(snapshot, settings)
    if not steps:
        return LayerResult((), ("build-not-configured",), ())

    active_deadline = deadline or AnalysisDeadline.start(settings.total_timeout_seconds)
    tool_runs: list[dict[str, object]] = []
    for step in steps:
        if len(tool_runs) >= MAX_TOOL_RUNS:
            return LayerResult((), (_BUDGET_DIAGNOSTIC,), tuple(tool_runs))
        remaining = active_deadline.step_timeout(settings.step_timeout_seconds)
        if remaining <= 0:
            tool_runs.append(_deadline_run("build-step"))
            return LayerResult((), ("timed-out",), tuple(tool_runs))
        execution = run_step(
            step,
            snapshot,
            ".",
            timeout_seconds=remaining,
            max_output_bytes=settings.max_output_bytes,
            env=SANITIZER_ENVIRONMENT if sanitizer_enabled else {},
            deadline=active_deadline,
        )
        run = _tool_run("build-step", execution, build_step=True)
        tool_runs.append(run)
        if execution.status != "completed":
            diagnostic = "timed-out" if execution.status == "timed-out" else "build_failed"
            return LayerResult((), (diagnostic,), tuple(tool_runs))

    database = _find_database(snapshot)
    if database is None:
        return LayerResult((), ("compile-commands-missing",), tuple(tool_runs))
    try:
        units = load_compilation_database(snapshot, database)
    except AnalysisBudgetExceeded:
        return LayerResult((), (_BUDGET_DIAGNOSTIC,), tuple(tool_runs))
    except ValueError:
        return LayerResult((), ("compile-commands-rejected",), tuple(tool_runs))
    if not units:
        return LayerResult((), ("compile-commands-empty",), tuple(tool_runs))

    findings: list[NormalizedFinding] = []
    diagnostics: list[str] = []
    aggregate_plist_bytes = 0
    try:
        with tempfile.TemporaryDirectory(
            prefix="lima-clang-", dir=_ANALYZER_TEMP_ROOT or snapshot.scratch_root
        ) as temporary:
            output_root = Path(temporary)
            for index, unit in enumerate(units):
                if len(tool_runs) >= MAX_TOOL_RUNS:
                    _mark_budget_exhausted(diagnostics)
                    break
                if (
                    len(findings) >= MAX_FINDINGS
                    or len(diagnostics) >= MAX_DIAGNOSTICS
                    or aggregate_plist_bytes >= MAX_AGGREGATE_PLIST_BYTES
                ):
                    _mark_budget_exhausted(diagnostics)
                    break
                output = output_root / f"{index}.plist"
                try:
                    argv = _analyzer_argv(unit, output)
                except ValueError:
                    diagnostics.append("compile-commands-rejected")
                    continue
                remaining = active_deadline.step_timeout(settings.step_timeout_seconds)
                if remaining <= 0:
                    tool_runs.append(_deadline_run("clang"))
                    diagnostics.append("timed-out")
                    break
                execution = run_step(
                    argv,
                    snapshot,
                    unit.directory,
                    timeout_seconds=remaining,
                    max_output_bytes=settings.max_output_bytes,
                    env={},
                    deadline=active_deadline,
                )
                clang_run_id = new_run_id()
                tool_runs.append(_tool_run("clang", execution, clang_run_id))
                if execution.status != "completed":
                    diagnostics.append(
                        "timed-out" if execution.status == "timed-out" else "clang_failed"
                    )
                    continue
                remaining_bytes = MAX_AGGREGATE_PLIST_BYTES - aggregate_plist_bytes
                if remaining_bytes <= 0:
                    _mark_budget_exhausted(diagnostics)
                    break
                try:
                    output_size = output.stat().st_size
                    if output_size > remaining_bytes:
                        _mark_budget_exhausted(diagnostics)
                        break
                    aggregate_plist_bytes += output_size
                    raw = _bounded_bytes(
                        output,
                        min(_MAX_PLIST_BYTES, remaining_bytes),
                        "Clang plist",
                    )
                    parsed, parser_diagnostics = parse_clang_plist(
                        raw, snapshot, relative_cwd=unit.directory
                    )
                except (OSError, ValueError):
                    if aggregate_plist_bytes >= MAX_AGGREGATE_PLIST_BYTES:
                        _mark_budget_exhausted(diagnostics)
                        break
                    diagnostics.append("clang-output-rejected")
                    continue
                if not _extend_parsed_results(
                    findings,
                    diagnostics,
                    tuple(item.bind_producer(clang_run_id) for item in parsed),
                    parser_diagnostics,
                ):
                    break
    except OSError:
        return LayerResult((), ("clang-output-unavailable",), tuple(tool_runs))
    return LayerResult(
        tuple(findings),
        tuple(diagnostics),
        tuple(tool_runs),
        BuildContext(
            Path(snapshot.root).resolve(),
            tuple(snapshot.files),
            sanitizer_enabled,
            active_deadline,
        ),
    )
