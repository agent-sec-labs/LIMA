"""Build Context Resolver: pin compile semantics for one translation unit.

Task 3 of the UAF v2 plan (design ``docs/superpowers/specs/2026-09-10-cxx-uaf-v2-design.md``
section 6).  The resolver answers exactly one question -- *is the compiler
semantics of this translation unit pinned by a trusted build context?* -- and
never claims Clang parse success or AST/CFG generation; that is the
extraction stage's ``ExtractionCoverage`` answer.

Red lines implemented here:

- The default path never generates a compilation database: CMake, Make,
  Ninja, Meson, Bazel, Autotools, repository scripts and tests are never
  executed.  A snapshot's ``CMakeLists.txt`` is untrusted data
  (``execute_process()`` and friends), so only an existing
  ``compile_commands.json`` is consumed, followed by the minimal
  heuristic fallback.
- Trusted generation (admin gate ``trusted_build_context_generation``
  plus every probed isolation capability, see
  :mod:`cxx_analyzer.trust`) is configure-only
  (``GENERATION_CONFIGURE_ONLY``) and never implies ``--build``.  This
  task does not implement generation at all: the tier answers
  ``unavailable`` with an explicit diagnostic (fail closed).
- A ``heuristic`` context is always ``incomplete``.
- A repository compilation database's compiler argv is never trusted:
  ``command`` strings are only split with :func:`compiler_command_to_argv`
  and every argv item passes :func:`validate_compiler_argv`.  Response
  files, compiler plugins, ``-Xclang -load``, passthrough options and
  path escapes produce rejections; any rejection, duplicate/ambiguous
  entry or missing referenced path degrades the context to
  ``incomplete``.
- ``context_hash`` exists only for ``resolved`` contexts and hashes the
  semantic argument projection (:data:`SEMANTIC_ARG_OPTIONS`) together
  with the translation unit, source kind and working directory, so
  non-semantic output flags never drift the identity.

The shared compdb search and argv validation were extracted from
:cmod:`cxx_analyzer.build_scan`, which now calls this module; both layers
stay behaviorally identical.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from . import trust
from .config import MAX_ARGUMENT_BYTES, MAX_ARGUMENTS_PER_STEP, AnalyzerSettings
from .languages import language_for_path

__all__ = [
    "FORBIDDEN_ARGV",
    "GENERATION_CONFIGURE_ONLY",
    "MAX_DATABASE_BYTES",
    "MAX_DATABASE_ENTRIES",
    "RESPONSE_FILE_PATTERN",
    "SEMANTIC_ARG_OPTIONS",
    "WIRE_RESOLUTION_STATUSES",
    "WIRE_SOURCE_KINDS",
    "UnitBuildContext",
    "compiler_command_to_argv",
    "compute_context_hash",
    "find_compile_databases",
    "heuristic_compiler_argv",
    "inside_snapshot",
    "read_compilation_database",
    "resolve_build_context",
    "resolve_build_context_execution",
    "resolve_build_context_wire",
    "validate_argument_paths",
    "validate_compiler_argv",
]

GENERATION_CONFIGURE_ONLY: Final = True
GENERATION_NOT_IMPLEMENTED: Final = "generation-not-implemented-in-this-task"
HEURISTIC_DIAGNOSTIC: Final = "heuristic-context"

MAX_DATABASE_BYTES: Final = 4 * 1024 * 1024
MAX_DATABASE_ENTRIES: Final = 2048

RESPONSE_FILE_PATTERN: Final = re.compile(r"^@")
FORBIDDEN_ARGV: Final = frozenset(
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
FORBIDDEN_ARGV_PREFIXES: Final = ("-Wa,", "-Wl,", "-Wp,")
FORBIDDEN_ARGV_JOINED_PREFIXES: Final = (
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

# Arguments that can change the AST semantics of the translation unit.
# Everything else (output artifacts, dependency files, warning or
# optimization flags) is deliberately excluded from ``context_hash``.
SEMANTIC_ARG_OPTIONS: Final = frozenset(
    {"-I", "-D", "-U", "-std", "-target", "--target", "--sysroot", "-isystem"}
)
_SEMANTIC_JOINED_PREFIXES: Final = ("-I", "-D", "-U", "-isystem")

# Options whose value position must never be mistaken for a compile input
# while checking referenced paths for existence.
_VALUE_CONSUMING_OPTIONS: Final = frozenset(
    {"-D", "-U", "-x", "-std", "-target", "--target", "-arch"}
)
_OUTPUT_VALUE_OPTIONS: Final = frozenset({"-o", "-MF", "-MT", "-MQ"})
_OUTPUT_FLAGS: Final = frozenset({"-c", "-MMD", "-MD", "-MP"})
_OUTPUT_JOINED_PATTERN: Final = re.compile(r"^-(?:o|MF|MT|MQ).+")

_ADAPTER_MARKERS: Final = frozenset(
    {
        "Makefile",
        "makefile",
        "GNUmakefile",
        "configure",
        "meson.build",
        "BUILD.bazel",
        "build.ninja",
    }
)

_REJECTION_MESSAGES: Final = {
    "empty-compiler": "compilation database executable is empty",
    "response-file-forbidden": "compilation database response files are forbidden",
    "forbidden-passthrough-option": "compilation database passthrough options are forbidden",
    "path-option-empty": "compilation database path option is empty",
    "path-escapes-snapshot": "build path escapes the snapshot",
    "unsafe-relative-path": "build path is not a safe snapshot-relative path",
    "unknown-joined-path-option": "unknown joined path-bearing option is forbidden",
    "unknown-path-option": "unknown path-bearing compiler option is forbidden",
    "path-option-without-value": "compilation database path option lacks a value",
    "too-many-arguments": "compilation database arguments are invalid",
    "argument-invalid": "compilation database arguments are invalid",
}

# Frozen wire vocabulary of the ``/v1/uaf-facts`` build-context block.  It
# mirrors ``lima.uaf_models`` (RESOLUTION_STATUSES / RESOLUTION_SOURCE_KINDS)
# so the sidecar can project resolutions onto plain dicts without importing
# the main-process package; a parity test keeps the two in lockstep.
WIRE_RESOLUTION_STATUSES: Final = frozenset({"resolved", "incomplete", "unavailable"})
WIRE_SOURCE_KINDS: Final = frozenset(
    {"repository-compdb", "cmake-export", "build-adapter", "heuristic"}
)
_WIRE_MAX_DIAGNOSTIC_BYTES: Final = 2_048


def _dedupe(items: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(items))


# ------------------------------------------------------------------- paths


def _snapshot_relative(root: Path, value: Path) -> tuple[Path | None, str, str]:
    """Bind one path inside the snapshot root without raising.

    Returns ``(resolved, relative_text, "")`` on success and
    ``(None, "", rejection)`` where the rejection is either
    ``path-escapes-snapshot`` or ``unsafe-relative-path``.  This is the
    non-raising form of :func:`inside_snapshot`.
    """

    resolved_root = root.resolve()
    resolved = value.resolve()
    try:
        relative = resolved.relative_to(resolved_root)
    except ValueError:
        return None, "", "path-escapes-snapshot"
    relative_text = relative.as_posix()
    if relative_text in {"", "."}:
        return resolved, ".", ""
    parsed = PurePosixPath(relative_text)
    if any(part in {"", ".", ".."} for part in parsed.parts):
        return None, "", "unsafe-relative-path"
    return resolved, relative_text, ""


def inside_snapshot(root: Path, value: Path) -> tuple[Path, str]:
    """Return ``(resolved_path, snapshot_relative_posix)`` or raise."""

    resolved, relative_text, rejection = _snapshot_relative(root, value)
    if rejection == "path-escapes-snapshot":
        raise ValueError(_REJECTION_MESSAGES[rejection])
    if rejection == "unsafe-relative-path":
        raise ValueError(_REJECTION_MESSAGES[rejection])
    return resolved, relative_text


# ------------------------------------------------------ compilation databases


def find_compile_databases(snapshot_root: Path) -> list[Path]:
    """List existing compilation databases in priority order.

    ``build/compile_commands.json`` first, then the snapshot root, then a
    single unique ``*/compile_commands.json`` subdirectory match.  This is
    the extracted form of the build scan layer's database search; the
    first list element is exactly what the build scan previously selected.
    """

    root = Path(snapshot_root)
    databases = [
        candidate
        for candidate in (
            root / "build" / "compile_commands.json",
            root / "compile_commands.json",
        )
        if candidate.is_file()
    ]
    subdirectories = sorted(
        path for path in root.glob("*/compile_commands.json") if path not in databases
    )
    if len(subdirectories) == 1:
        databases.append(subdirectories[0])
    return databases


def read_compilation_database(database_path: Path) -> list:
    """Load a bounded compilation database document (a JSON array)."""

    try:
        with Path(database_path).open("rb") as stream:
            raw = stream.read(MAX_DATABASE_BYTES + 1)
    except OSError as exc:
        raise ValueError("compilation database is unreadable") from exc
    if len(raw) > MAX_DATABASE_BYTES:
        raise ValueError("compilation database exceeds the byte limit")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("compilation database is unreadable") from exc
    if not isinstance(document, list) or len(document) > MAX_DATABASE_ENTRIES:
        raise ValueError("compilation database must be a bounded array")
    return document


def compiler_command_to_argv(command: object) -> list[str]:
    """Split a CMake ``command`` shell string into argv without executing it.

    Posix shell quoting rules only: the string is never run as a shell
    command.  A mangled string raises ``ValueError`` so the caller can
    reject the entry instead of analyzing the wrong file.
    """

    if not isinstance(command, str) or not command:
        raise ValueError("compilation database command is invalid")
    try:
        return shlex.split(command, posix=True)
    except ValueError as exc:
        raise ValueError("compilation database command is invalid") from exc


# ------------------------------------------------------------ argv validation


def validate_compiler_argv(
    argv: Sequence[str],
    *,
    root: Path | None = None,
    working_directory: Path | None = None,
    referenced_paths: list[tuple[Path, str]] | None = None,
) -> tuple[list[str], list[str]]:
    """Validate one compiler argv and return ``(normalized, rejections)``.

    This is the shared, non-raising form of the build scan layer's argv
    validation chain.  ``normalized`` is the full argv exactly when no
    rejection was recorded; with any rejection it is empty, because a
    half-filtered argv could silently change AST semantics (fail closed).

    With ``root`` (and ``working_directory``, defaulting to ``root``)
    every referenced path must stay inside the snapshot; without ``root``
    only the lexical option screening runs.  ``referenced_paths``, when
    given, collects ``(resolved_path, kind)`` pairs with kind ``option``
    or ``input`` for successfully bound paths.
    """

    if not argv or not argv[0]:
        return [], ["empty-compiler"]
    if len(argv) > MAX_ARGUMENTS_PER_STEP:
        return [], ["too-many-arguments"]
    for argument in argv:
        if (
            not isinstance(argument, str)
            or "\0" in argument
            or len(argument.encode("utf-8")) > MAX_ARGUMENT_BYTES
        ):
            return [], ["argument-invalid"]

    rejections: list[str] = []
    if root is None:
        working_directory = None
    elif working_directory is None:
        working_directory = root

    def bind(value: str, kind: str) -> None:
        bound, _, rejection = _snapshot_relative(
            root,
            Path(value) if Path(value).is_absolute() else working_directory / value,
        )
        if rejection:
            rejections.append(rejection)
        elif referenced_paths is not None:
            referenced_paths.append((bound, kind))

    expected_path_option: str | None = None
    for argument in argv[1:]:
        if RESPONSE_FILE_PATTERN.match(argument):
            rejections.append("response-file-forbidden")
            continue
        if expected_path_option is not None:
            value = argument
            if expected_path_option == "-fmodule-file" and "=" in argument:
                value = argument.rsplit("=", 1)[1]
            if not value:
                rejections.append("path-option-empty")
            elif root is not None:
                bind(value, "option")
            expected_path_option = None
            continue
        if argument in FORBIDDEN_ARGV or argument.startswith(
            (*FORBIDDEN_ARGV_PREFIXES, *FORBIDDEN_ARGV_JOINED_PREFIXES)
        ):
            rejections.append("forbidden-passthrough-option")
            continue
        if argument in _SUPPORTED_PATH_OPTIONS:
            expected_path_option = argument
            continue
        option, separator, option_value = argument.partition("=")
        if separator and option in _SUPPORTED_PATH_OPTIONS:
            if option == "-fmodule-file" and "=" in option_value:
                option_value = option_value.rsplit("=", 1)[1]
            if not option_value:
                rejections.append("path-option-empty")
            elif root is not None:
                bind(option_value, "option")
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
            if root is not None:
                bind(concatenated_path, "option")
            continue
        if (
            argument.startswith("-")
            and not argument.startswith(("-D", "-U"))
            and ("/" in argument or "\\" in argument)
        ):
            rejections.append("unknown-joined-path-option")
            continue
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
            rejections.append("unknown-path-option")
            continue
        if not argument.startswith("-") and root is not None:
            bind(argument, "input")
    if expected_path_option is not None:
        rejections.append("path-option-without-value")

    unique = _dedupe(rejections)
    return (list(argv), []) if not unique else ([], list(unique))


def validate_argument_paths(root: Path, working_directory: Path, arguments: list[str]) -> None:
    """Raising argv validation, preserved verbatim for the build scan layer.

    Raises ``ValueError`` with the historical message of the first
    rejection produced by :func:`validate_compiler_argv`; behavior is
    unchanged from the pre-extraction implementation.
    """

    _, rejections = validate_compiler_argv(
        arguments, root=root, working_directory=working_directory
    )
    if rejections:
        raise ValueError(_REJECTION_MESSAGES[rejections[0]])


# --------------------------------------------------------------- hashing


def semantic_arguments(argv: Sequence[str]) -> tuple[str, ...]:
    """Project the semantic arguments (``SEMANTIC_ARG_OPTIONS``) of an argv."""

    selected: list[str] = []
    expect_value = False
    for argument in argv[1:]:
        if expect_value:
            selected.append(argument)
            expect_value = False
            continue
        if argument in SEMANTIC_ARG_OPTIONS:
            selected.append(argument)
            expect_value = True
            continue
        option, separator, _ = argument.partition("=")
        if separator and option in SEMANTIC_ARG_OPTIONS:
            selected.append(argument)
            continue
        if any(
            argument.startswith(prefix) and len(argument) > len(prefix)
            for prefix in _SEMANTIC_JOINED_PREFIXES
        ):
            selected.append(argument)
    return tuple(selected)


def compute_context_hash(
    translation_unit: str,
    source_kind: str,
    arguments: Sequence[str],
    working_directory: str,
) -> str:
    """Hash the semantic context material (canonical JSON, SHA-256)."""

    material = {
        "tu": translation_unit,
        "source_kind": source_kind,
        "args": list(semantic_arguments(arguments)),
        "workdir": working_directory,
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


# ------------------------------------------------------------- resolver


def heuristic_compiler_argv(translation_unit: str) -> tuple[str, ...]:
    """The minimal fallback argv: fixed compiler, ``-fsyntax-only``, no flags.

    The language standard is intentionally left at the compiler default.
    This argv is never executed by the resolver; it only documents the
    heuristic context for the extraction stage.
    """

    compiler = "clang++-14" if language_for_path(translation_unit) == "c++" else "clang-14"
    return (compiler, "-fsyntax-only", translation_unit)


@dataclass(frozen=True)
class _CompdbEntry:
    """One compilation database entry bound to the snapshot."""

    relative_directory: str
    relative_file: str
    working_directory: Path
    arguments: tuple[str, ...]
    rejections: tuple[str, ...]


def _parse_entry(root: Path, entry: object) -> tuple[_CompdbEntry | None, str]:
    """Parse one database entry; ``(None, candidate_file)`` when invalid."""

    candidate_file = ""
    if isinstance(entry, dict) and isinstance(entry.get("file"), str):
        candidate_file = entry["file"]
    if not isinstance(entry, dict):
        return None, candidate_file
    arguments = entry.get("arguments")
    if arguments is None and "command" in entry:
        try:
            arguments = compiler_command_to_argv(entry["command"])
        except ValueError:
            return None, candidate_file
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
        return None, candidate_file
    if any(
        not isinstance(argument, str)
        or "\0" in argument
        or len(argument.encode("utf-8")) > MAX_ARGUMENT_BYTES
        for argument in arguments
    ):
        return None, candidate_file
    try:
        working_directory, relative_directory = inside_snapshot(
            root, Path(directory) if Path(directory).is_absolute() else root / directory
        )
    except ValueError:
        return None, candidate_file
    _, rejections = validate_compiler_argv(
        arguments, root=root, working_directory=working_directory
    )
    try:
        source_path = Path(file)
        if not source_path.is_absolute():
            source_path = working_directory / source_path
        _, relative_file = inside_snapshot(root, source_path)
    except ValueError:
        return None, candidate_file
    parsed = _CompdbEntry(
        relative_directory, relative_file, working_directory, tuple(arguments), tuple(rejections)
    )
    return parsed, relative_file


def _missing_referenced_paths(
    working_directory: Path, arguments: Sequence[str]
) -> list[str]:
    """Report referenced snapshot paths that do not exist (lost generated headers)."""

    def bind(value: str) -> Path:
        return Path(value) if Path(value).is_absolute() else working_directory / value

    def exists(path: Path, kind: str) -> bool:
        try:
            return path.exists() if kind == "option" else path.is_file()
        except OSError:
            return False

    missing: list[str] = []
    expected_path_option: str | None = None
    skip_value = False
    for argument in arguments[1:]:
        if skip_value:
            skip_value = False
            continue
        if expected_path_option is not None:
            value = argument
            if expected_path_option == "-fmodule-file" and "=" in argument:
                value = argument.rsplit("=", 1)[1]
            if value and not exists(bind(value), "option"):
                missing.append(value)
            expected_path_option = None
            continue
        if argument in _VALUE_CONSUMING_OPTIONS:
            skip_value = True
            continue
        if argument in _OUTPUT_VALUE_OPTIONS:
            skip_value = True
            continue
        if argument in _OUTPUT_FLAGS or _OUTPUT_JOINED_PATTERN.match(argument):
            continue
        if argument in _SUPPORTED_PATH_OPTIONS:
            expected_path_option = argument
            continue
        option, separator, option_value = argument.partition("=")
        if separator and option in _SUPPORTED_PATH_OPTIONS:
            if option == "-fmodule-file" and "=" in option_value:
                option_value = option_value.rsplit("=", 1)[1]
            if option_value and not exists(bind(option_value), "option"):
                missing.append(option_value)
            continue
        concatenated_path = next(
            (
                argument[len(prefix) :]
                for prefix in _CONCATENATED_PATH_OPTIONS
                if argument.startswith(prefix) and len(argument) > len(prefix)
            ),
            None,
        )
        if concatenated_path is not None and not exists(bind(concatenated_path), "option"):
            missing.append(concatenated_path)
            continue
        if not argument.startswith("-") and not exists(bind(argument), "input"):
            missing.append(argument)
    return missing


def _resolve_from_database(
    root: Path, translation_unit: str, database: Path
) -> tuple[UnitBuildContext | None, tuple[str, ...]]:
    """Resolve against one database; ``None`` means "no entry for this TU"."""

    try:
        document = read_compilation_database(database)
    except (OSError, ValueError):
        return None, ("compdb-unreadable",)
    matched: list[_CompdbEntry] = []
    invalid_match = False
    for entry in document:
        parsed, candidate_file = _parse_entry(root, entry)
        if candidate_file != translation_unit:
            continue
        if parsed is None:
            invalid_match = True
        else:
            matched.append(parsed)
    incomplete = _resolve_incomplete
    if not matched and not invalid_match:
        return None, ()
    if len(matched) > 1 or (matched and invalid_match):
        return incomplete("repository-compdb", ("ambiguous-tu-entry",)), ()
    if invalid_match:
        return incomplete("repository-compdb", ("compdb-entry-invalid",)), ()
    entry = matched[0]
    if entry.rejections:
        return incomplete("repository-compdb", _dedupe(entry.rejections)), ()
    if _missing_referenced_paths(entry.working_directory, entry.arguments):
        return incomplete("repository-compdb", ("missing-referenced-path",)), ()
    context_hash = compute_context_hash(
        translation_unit, "repository-compdb", entry.arguments, entry.relative_directory
    )
    return (
        UnitBuildContext(
            status="resolved",
            source_kind="repository-compdb",
            context_hash=context_hash,
            diagnostics=(),
            arguments=entry.arguments,
            relative_directory=entry.relative_directory,
        ),
        (),
    )


def _resolve_incomplete(source_kind: str, diagnostics: Sequence[str]) -> UnitBuildContext:
    return UnitBuildContext(
        status="incomplete",
        source_kind=source_kind,
        context_hash="",
        diagnostics=tuple(diagnostics),
    )


@dataclass(frozen=True)
class UnitBuildContext:
    """Internal per-unit resolution shared by every public projection.

    ``status``/``source_kind``/``context_hash``/``diagnostics`` carry the
    frozen resolution answer; ``arguments`` and ``relative_directory``
    expose the pinned compiler argv and working directory to the extraction
    stage only for ``resolved`` contexts (empty otherwise, so a non-resolved
    context can never reach Clang).  This type is lima-free; the typed
    contract object is built by :func:`resolve_build_context` and the plain
    wire dict by :attr:`wire`.
    """

    status: str
    source_kind: str = ""
    context_hash: str = ""
    diagnostics: tuple[str, ...] = ()
    arguments: tuple[str, ...] = ()
    relative_directory: str = ""

    @property
    def wire(self) -> dict[str, object]:
        """Project the closed four-field ``/v1/uaf-facts`` wire dict."""

        if self.status not in WIRE_RESOLUTION_STATUSES:
            raise ValueError("resolution status is outside the closed domain")
        if self.source_kind != "" and self.source_kind not in WIRE_SOURCE_KINDS:
            raise ValueError("resolution source kind is outside the closed domain")
        if self.context_hash != "" and (
            not isinstance(self.context_hash, str)
            or len(self.context_hash) != 64
            or any(character not in "0123456789abcdef" for character in self.context_hash)
        ):
            raise ValueError("context hash is not a lowercase SHA-256 digest")
        bounded: list[str] = []
        for diagnostic in self.diagnostics:
            if (
                not isinstance(diagnostic, str)
                or not diagnostic
                or len(diagnostic.encode("utf-8")) > _WIRE_MAX_DIAGNOSTIC_BYTES
            ):
                raise ValueError("resolution diagnostic is outside the closed domain")
            bounded.append(diagnostic)
        return {
            "status": self.status,
            "source_kind": self.source_kind,
            "context_hash": self.context_hash,
            "diagnostics": bounded,
        }


def _resolution(
    status: str, source_kind: str = "", context_hash: str = "", diagnostics: Sequence[str] = ()
) -> object:
    """Build the frozen ``BuildContextResolution`` contract object.

    ``lima.uaf_models`` is imported lazily so that the analyzer sidecar
    package (which ships without the ``lima`` package) can still import
    this module for the shared search and validation helpers.
    """

    from lima.uaf_models import (  # noqa: PLC0415 -- deliberate lazy import
        RESOLUTION_SOURCE_KINDS,
        RESOLUTION_STATUSES,
        BuildContextResolution,
    )

    if status not in RESOLUTION_STATUSES:
        raise ValueError("resolution status is outside the closed domain")
    if source_kind != "" and source_kind not in RESOLUTION_SOURCE_KINDS:
        raise ValueError("resolution source kind is outside the closed domain")
    return BuildContextResolution(
        status=status,
        source_kind=source_kind,
        context_hash=context_hash,
        diagnostics=tuple(diagnostics),
    )


def _canonical_unit(root: Path, translation_unit: object) -> str | None:
    """Return the canonical snapshot-relative posix TU path, or ``None``."""

    if not isinstance(translation_unit, str) or not translation_unit:
        return None
    _, relative_text, rejection = _snapshot_relative(root, root / translation_unit)
    if rejection or relative_text != translation_unit:
        return None
    return relative_text


def _resolve(
    snapshot_root: Path,
    translation_unit: str,
    settings: AnalyzerSettings,
    capabilities: Mapping[str, bool] | None,
) -> UnitBuildContext:
    """Shared decision core behind every public resolver projection."""

    root = Path(snapshot_root).resolve()
    unit = _canonical_unit(root, translation_unit)
    if unit is None:
        return UnitBuildContext(
            status="unavailable",
            diagnostics=("translation-unit-not-in-snapshot",),
        )
    try:
        language_for_path(unit)
    except ValueError:
        return UnitBuildContext(
            status="unavailable",
            diagnostics=("unsupported-translation-unit",),
        )

    generation_enabled = False
    if settings.trusted_build_context_generation:
        probes = (
            dict(capabilities)
            if capabilities is not None
            else trust.build_generation_capabilities()
        )
        generation_enabled = bool(probes) and all(probes.values())

    pending: list[str] = []
    for database in find_compile_databases(root):
        outcome, diagnostics = _resolve_from_database(root, unit, database)
        pending.extend(diagnostics)
        if outcome is not None:
            return outcome
    pending = list(_dedupe(pending))

    if generation_enabled:
        source_kind = ""
        if (root / "CMakeLists.txt").is_file():
            # Adapter selection is not authorization: auto_cmake selects the
            # CMake adapter inside the already-gated generation tier only.
            if settings.auto_cmake:
                source_kind = "cmake-export"
        elif any((root / marker).is_file() for marker in _ADAPTER_MARKERS):
            source_kind = "build-adapter"
        if source_kind:
            return UnitBuildContext(
                status="unavailable",
                source_kind=source_kind,
                diagnostics=(*pending, GENERATION_NOT_IMPLEMENTED),
            )

    return UnitBuildContext(
        status="incomplete",
        source_kind="heuristic",
        diagnostics=(*pending, HEURISTIC_DIAGNOSTIC),
    )


def resolve_build_context_execution(
    snapshot_root: Path,
    translation_unit: str,
    settings: AnalyzerSettings,
    capabilities: Mapping[str, bool] | None = None,
) -> UnitBuildContext:
    """Resolve one translation unit and keep the extraction-stage details.

    This is the raw shared resolution: the closed wire dict (``.wire``),
    the typed contract (via :func:`resolve_build_context`) and the plain
    wire projection (via :func:`resolve_build_context_wire`) are all
    projections of this one decision, so they can never disagree.
    ``arguments`` and ``relative_directory`` are populated exactly when the
    status is ``resolved``; every other status leaves them empty, so a
    non-resolved context can never reach the compiler.
    """

    return _resolve(snapshot_root, translation_unit, settings, capabilities)


def resolve_build_context_wire(
    snapshot_root: Path,
    translation_unit: str,
    settings: AnalyzerSettings,
    capabilities: Mapping[str, bool] | None = None,
) -> dict[str, object]:
    """Resolve one translation unit and project the closed wire dict.

    The sidecar's ``/v1/uaf-facts`` endpoint serves this projection.  It is
    a plain dict with exactly the frozen wire vocabulary and never imports
    the main-process ``lima`` package; a parity test keeps the vocabulary
    identical to ``lima.uaf_models``.
    """

    return _resolve(snapshot_root, translation_unit, settings, capabilities).wire


def resolve_build_context(
    snapshot_root: Path,
    translation_unit: str,
    settings: AnalyzerSettings,
    capabilities: Mapping[str, bool] | None = None,
) -> object:
    """Resolve the pinned build context for one translation unit.

    Priority (design section 6.2):

    1. an existing ``compile_commands.json`` in the verified snapshot
       (``build/`` first, then the root, then one unique subdirectory);
    2. trusted generation tiers, reachable only while the admin gate
       ``trusted_build_context_generation`` holds and every probed
       isolation capability is true.  This task deliberately implements
       no generation: the tier answers ``unavailable`` with the
       ``generation-not-implemented-in-this-task`` diagnostic and never
       executes CMake, Make, Ninja, Meson, Bazel, Autotools or repository
       scripts.  The CMake adapter tier is configure-only
       (``GENERATION_CONFIGURE_ONLY``): it never implies ``--build``;
    3. the extension-based minimal heuristic, which is always
       ``incomplete`` (``heuristic-context``) and can therefore never
       contribute to a ``fact-verified`` outcome.

    Every candidate compiler argv passes
    :func:`validate_compiler_argv`; rejections, duplicate/ambiguous
    entries and missing referenced paths all degrade to ``incomplete``.
    ``context_hash`` is only produced for ``resolved`` contexts and never
    claims Clang parse success -- that is the extraction stage's answer.
    """

    resolution = _resolve(snapshot_root, translation_unit, settings, capabilities)
    return _resolution(
        status=resolution.status,
        source_kind=resolution.source_kind,
        context_hash=resolution.context_hash,
        diagnostics=resolution.diagnostics,
    )
