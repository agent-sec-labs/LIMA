"""Deterministic repository inventory adapter for repository profiles (IP-0016).

Layer 1 of the repository profile stack: read a bounded, read-only
:class:`lima.workspace.RepositoryWorkspace` snapshot plus a small set of
manifest files, and derive a fully provenanced
:class:`lima.contracts.profile.RepositoryProfile` bound to an
:class:`lima.contracts.common.ArtifactEnvelope`.

Frozen behaviour (Packet ``IP-0016-PACKET/v1.1``):

- stdlib-only on top of ``lima.contracts`` and ``lima.workspace``;
- target code is never run and never imported: ``setup.py`` is only parsed
  into an AST, never evaluated;
- nothing is written to disk and no network facility is used anywhere in
  this module;
- every iteration is path-sorted and no clock, randomness, or environment
  input is read, so two builds of one snapshot produce byte-identical
  payloads and content digests;
- failures are fail-closed: invalid arguments raise
  :class:`lima.contracts.errors.ContractError` or ``ValueError`` and are
  never silently corrected, while workspace skip reasons and manifest
  failures become typed coverage gaps instead of guessed defaults.
"""

from __future__ import annotations

import ast
import configparser
import fnmatch
import json
import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Final

from lima.contracts.codec import compute_content_digest
from lima.contracts.common import (
    ArtifactClassification,
    ArtifactEnvelope,
    ArtifactReference,
    RetentionClass,
    SchemaVersion,
)
from lima.contracts.errors import ContractError, ContractErrorCode
from lima.contracts.profile import (
    REPOSITORY_PROFILE_SCHEMA_NAME,
    AttackSurfaceEntry,
    CodeRole,
    CodeRoleAssignment,
    DetectionMethod,
    ExecutionCapability,
    ProfileCoverageGap,
    RepositoryKind,
    RepositoryProfile,
    SupportLevel,
    TechnologyDeclaration,
    encode_profile_envelope,
)
from lima.workspace import RepositoryWorkspace

__all__ = [
    "GAP_BUDGET_EXHAUSTED",
    "GAP_INVENTORY_SKIPPED",
    "GAP_MANIFEST_PARSE_ERROR",
    "GAP_NO_LANGUAGES_DETECTED",
    "GAP_UNSUPPORTED_LANGUAGE",
    "PROFILE_PROVENANCE_ANCHOR",
    "SKIP_REASON_TO_GAP_DETAIL",
    "ProfileBudgets",
    "ProfileBuildResult",
    "ProfileInventoryOptions",
    "build_repository_profile",
]

PROFILE_PROVENANCE_ANCHOR: Final[str] = "inventory"

GAP_UNSUPPORTED_LANGUAGE: Final[str] = "UNSUPPORTED_LANGUAGE"
GAP_BUDGET_EXHAUSTED: Final[str] = "BUDGET_EXHAUSTED"
GAP_MANIFEST_PARSE_ERROR: Final[str] = "MANIFEST_PARSE_ERROR"
GAP_NO_LANGUAGES_DETECTED: Final[str] = "NO_LANGUAGES_DETECTED"
GAP_INVENTORY_SKIPPED: Final[str] = "INVENTORY_SKIPPED"

#: sha256(b"") -- "no policy / no toolchain digest" sentinel (Packet v1.1).
_SENTINEL_EMPTY_DIGEST: Final[str] = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)
_DEFAULT_PRODUCER: Final[str] = "lima.audit.inventory"

#: Frozen detail copy shared by every workspace skip-reason gap (Packet D6).
_SKIP_DETAIL_TEMPLATE: Final[str] = "reason={reason}; count={count}"

_SKIP_REASONS: Final[tuple[str, ...]] = (
    "binary",
    "file-limit",
    "file-size-limit",
    "ignored-directory",
    "non-utf8",
    "sensitive-config",
    "symlink",
    "total-size-limit",
    "unreadable",
    "unsupported-extension",
)

SKIP_REASON_TO_GAP_DETAIL: Final[Mapping[str, str]] = MappingProxyType(
    {reason: _SKIP_DETAIL_TEMPLATE for reason in _SKIP_REASONS}
)

_BUDGET_SKIP_REASONS: Final[frozenset[str]] = frozenset(
    {"file-limit", "file-size-limit", "total-size-limit"}
)

_EXTENSION_TO_LANGUAGE: Final[Mapping[str, str]] = MappingProxyType(
    {
        ".go": "Go",
        ".java": "Java",
        ".js": "JavaScript",
        ".jsx": "JavaScript",
        ".py": "Python",
        ".rs": "Rust",
        ".ts": "TypeScript",
        ".tsx": "TypeScript",
    }
)

_FRAMEWORK_KEYWORDS: Final[tuple[str, ...]] = (
    "fastapi",
    "flask",
    "django",
    "pytest",
    "react",
)

_BUILD_SYSTEM_NAMES: Final[tuple[str, ...]] = (
    "setuptools",
    "hatchling",
    "poetry-core",
)

_MANIFEST_EXACT_NAMES: Final[frozenset[str]] = frozenset(
    {
        "Cargo.toml",
        "environment.yml",
        "go.mod",
        "package.json",
        "pom.xml",
        "pyproject.toml",
        "setup.cfg",
        "setup.py",
    }
)
_REQUIREMENTS_MANIFEST_PATTERN: Final[str] = "requirements*.txt"
_TEST_CONFIG_TOOL_NAMES: Final[tuple[str, ...]] = ("pytest", "tox", "nox")

_TEST_DIR_NAMES: Final[frozenset[str]] = frozenset({"tests", "testing"})
_DOCS_DIR_NAMES: Final[frozenset[str]] = frozenset({"doc", "docs"})
_EXAMPLE_DIR_NAMES: Final[frozenset[str]] = frozenset({"example", "examples"})
_BUILD_OUTPUT_DIR_NAMES: Final[frozenset[str]] = frozenset({"build", "dist"})
_GENERATED_NAME_PATTERNS: Final[tuple[str, ...]] = (
    "*.min.js",
    "*.pb.py",
    "*_generated.py",
    "*_pb2.py",
)
_DOCS_CONTENT_SUFFIXES: Final[frozenset[str]] = frozenset({".md", ".rst"})

_ROOT_ENTRY_CANDIDATES: Final[frozenset[str]] = frozenset(
    {"__main__.py", "cli.py", "main.py"}
)

_PATH_CLASS_REASONS: Final[frozenset[str]] = frozenset(
    {
        "PATH_DOCS_DIR",
        "PATH_EXAMPLE_DIR",
        "PATH_PATTERN_GENERATED",
        "PATH_TEST_DIR",
    }
)
_NON_PATH_REASONS: Final[frozenset[str]] = frozenset(
    {
        "ENTRY_SCRIPT_DECLARED",
        "MANIFEST_BUILD_TARGET",
        "MANIFEST_PACKAGES_EXCLUDED",
        "MANIFEST_TEST_CONFIG",
        "NOT_IMPORTED_BY_PROD",
    }
)
_ROLE_PATH_EVIDENCE: Final[tuple[tuple[str, CodeRole], ...]] = (
    ("PATH_PATTERN_GENERATED", CodeRole.GENERATED),
    ("PATH_TEST_DIR", CodeRole.TEST),
    ("PATH_DOCS_DIR", CodeRole.DOCUMENTATION),
    ("PATH_EXAMPLE_DIR", CodeRole.EXAMPLE),
)

_MAX_BASIS_POINTS: Final[int] = 10_000
_MAX_COVERAGE_GAPS: Final[int] = 256
_MAX_CODE_ROLE_ASSIGNMENTS: Final[int] = 2048

#: Deterministic envelope facts (Packet D3): no clock input is allowed.
_DETERMINISTIC_CREATED_AT: Final[str] = "1970-01-01T00:00:00.000000Z"
_INVENTORY_SCHEMA_NAME: Final[str] = "lima.repository-inventory"


@dataclass(frozen=True)
class ProfileBudgets:
    """Read budgets for the manifest layer; both values must be positive."""

    manifest_max_bytes: int = 262_144
    max_manifest_files: int = 64

    def __post_init__(self) -> None:
        for name in ("manifest_max_bytes", "max_manifest_files"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class ProfileInventoryOptions:
    """Deterministic build options for the repository profile inventory."""

    budgets: ProfileBudgets = ProfileBudgets()
    schema_version: SchemaVersion = SchemaVersion(4, 0)


@dataclass(frozen=True)
class ProfileBuildResult:
    """One deterministic profile build: payload, binding envelope, anchors."""

    profile: RepositoryProfile
    envelope: ArtifactEnvelope
    provenance_anchor_ids: tuple[str, ...]


@dataclass
class _ManifestSummary:
    """Mutable accumulator for facts extracted from manifest files."""

    declared_languages: set[str] = field(default_factory=set)
    frameworks: set[str] = field(default_factory=set)
    package_managers: set[str] = field(default_factory=set)
    build_systems: set[str] = field(default_factory=set)
    scripts: dict[str, str] = field(default_factory=dict)
    exclude_patterns: list[str] = field(default_factory=list)
    has_build_system: bool = False
    has_test_config: bool = False
    has_python_manifest: bool = False
    buildable: bool = False


def _suffix_of(relative_path: str) -> str:
    return PurePosixPath(relative_path).suffix.lower()


def _ratio_bp(numerator: int, denominator: int) -> int:
    """Integer basis-point ratio, rounded up and capped at 10000."""
    if numerator <= 0 or denominator <= 0:
        return 0
    return min(_MAX_BASIS_POINTS, (numerator * 10_000 + denominator - 1) // denominator)


def _manifest_candidates(workspace: RepositoryWorkspace) -> list[str]:
    """Return sorted repo-relative manifest paths from root and level-1 dirs."""
    root = workspace.root
    top_names = sorted(os.listdir(root))
    level_one_dirs = []
    for name in top_names:
        candidate = root / name
        if candidate.is_dir() and not candidate.is_symlink():
            level_one_dirs.append(name)
    directory_names = frozenset(level_one_dirs)

    def _is_manifest(name: str) -> bool:
        if name in directory_names:
            return False
        if name in _MANIFEST_EXACT_NAMES:
            return True
        return fnmatch.fnmatchcase(name, _REQUIREMENTS_MANIFEST_PATTERN)

    candidates = [name for name in top_names if _is_manifest(name)]
    for directory in sorted(level_one_dirs):
        for name in sorted(os.listdir(root / directory)):
            if fnmatch.fnmatchcase(name, _REQUIREMENTS_MANIFEST_PATTERN) or (
                name in _MANIFEST_EXACT_NAMES
            ):
                candidates.append(f"{directory}/{name}")
    return sorted(candidates)


def _record_manifest_error(
    gaps: list[tuple[str, str]], relative_path: str, error: Exception
) -> None:
    """Record one manifest failure without embedding the exception text."""
    gaps.append(
        (
            GAP_MANIFEST_PARSE_ERROR,
            f"manifest={relative_path}; error={type(error).__name__}",
        )
    )


def _keywords_in_lines(text: str) -> set[str]:
    found: set[str] = set()
    for line in text.splitlines():
        for keyword in _FRAMEWORK_KEYWORDS:
            if keyword in line:
                found.add(keyword)
    return found


def _keywords_in_import_lines(text: str) -> set[str]:
    found: set[str] = set()
    for line in text.splitlines():
        if "import" not in line and "require" not in line:
            continue
        for keyword in _FRAMEWORK_KEYWORDS:
            if keyword in line:
                found.add(keyword)
    return found


def _import_stems(text: str) -> set[str]:
    """Return imported module/name stems of one Python source text."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return set()
    stems: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                stems.update(alias.name.split("."))
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                stems.update(node.module.split("."))
            stems.update(alias.name for alias in node.names if alias.name != "*")
    return stems


def _parse_pyproject(
    relative_path: str,
    text: str,
    summary: _ManifestSummary,
    gaps: list[tuple[str, str]],
) -> None:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        _record_manifest_error(gaps, relative_path, error)
        return
    summary.has_python_manifest = True
    project = data.get("project")
    if isinstance(project, dict):
        requires_python = project.get("requires-python")
        if isinstance(requires_python, str) and requires_python.strip():
            summary.declared_languages.add("Python")
        scripts = project.get("scripts")
        if isinstance(scripts, dict):
            for key in sorted(scripts):
                value = scripts[key]
                if isinstance(key, str) and isinstance(value, str):
                    summary.scripts[key] = value
    build_system = data.get("build-system")
    if isinstance(build_system, dict):
        summary.has_build_system = True
        summary.buildable = True
        requires = build_system.get("requires")
        if isinstance(requires, list):
            for entry in requires:
                if not isinstance(entry, str):
                    continue
                match = next(
                    (name for name in _BUILD_SYSTEM_NAMES if name in entry), None
                )
                if match is not None:
                    summary.build_systems.add(match)
                    break
    tool = data.get("tool")
    if isinstance(tool, dict):
        if any(section in tool for section in _TEST_CONFIG_TOOL_NAMES):
            summary.has_test_config = True
        setuptools_config = tool.get("setuptools")
        if isinstance(setuptools_config, dict):
            packages = setuptools_config.get("packages")
            if isinstance(packages, dict):
                find = packages.get("find")
                if isinstance(find, dict):
                    exclude = find.get("exclude")
                    if isinstance(exclude, list):
                        summary.exclude_patterns.extend(
                            pattern
                            for pattern in exclude
                            if isinstance(pattern, str)
                        )


def _parse_setup_py(
    relative_path: str,
    text: str,
    summary: _ManifestSummary,
    gaps: list[tuple[str, str]],
) -> None:
    """Parse ``setup.py`` into an AST only; it is never evaluated or imported."""
    try:
        ast.parse(text)
    except (SyntaxError, ValueError) as error:
        _record_manifest_error(gaps, relative_path, error)
        return
    # Layer-1 metadata is limited to parse success: no keyword arguments are
    # trusted from untrusted setup code and nothing beyond parsing happens.
    summary.has_python_manifest = True
    summary.buildable = True


def _parse_setup_cfg(
    relative_path: str,
    text: str,
    summary: _ManifestSummary,
    gaps: list[tuple[str, str]],
) -> None:
    parser = configparser.RawConfigParser()
    try:
        parser.read_string(text)
    except configparser.Error as error:
        _record_manifest_error(gaps, relative_path, error)
        return
    summary.has_python_manifest = True


def _parse_package_json(
    relative_path: str,
    text: str,
    summary: _ManifestSummary,
    gaps: list[tuple[str, str]],
) -> None:
    try:
        data = json.loads(text)
    except ValueError as error:
        _record_manifest_error(gaps, relative_path, error)
        return
    if isinstance(data, dict):
        summary.package_managers.add("npm")
        summary.buildable = True


def _parse_cargo_toml(
    relative_path: str,
    text: str,
    summary: _ManifestSummary,
    gaps: list[tuple[str, str]],
) -> None:
    try:
        tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        _record_manifest_error(gaps, relative_path, error)
        return
    summary.declared_languages.add("Rust")
    summary.package_managers.add("cargo")
    summary.buildable = True


def _parse_manifest(
    relative_path: str,
    text: str,
    summary: _ManifestSummary,
    gaps: list[tuple[str, str]],
) -> None:
    name = relative_path.rsplit("/", 1)[-1]
    if name == "pyproject.toml":
        _parse_pyproject(relative_path, text, summary, gaps)
    elif name == "setup.py":
        _parse_setup_py(relative_path, text, summary, gaps)
    elif name == "setup.cfg":
        _parse_setup_cfg(relative_path, text, summary, gaps)
    elif name == "package.json":
        _parse_package_json(relative_path, text, summary, gaps)
    elif name == "Cargo.toml":
        _parse_cargo_toml(relative_path, text, summary, gaps)
    elif name == "go.mod":
        summary.declared_languages.add("Go")
        summary.package_managers.add("go-modules")
        summary.buildable = True
    elif fnmatch.fnmatchcase(name, _REQUIREMENTS_MANIFEST_PATTERN):
        summary.package_managers.add("pip")
    summary.frameworks.update(_keywords_in_lines(text))


def _load_one_manifest(
    workspace: RepositoryWorkspace,
    relative_path: str,
    budgets: ProfileBudgets,
    summary: _ManifestSummary,
    gaps: list[tuple[str, str]],
) -> None:
    try:
        path = workspace.absolute_file(relative_path)
        size = path.stat().st_size
    except OSError as error:
        _record_manifest_error(gaps, relative_path, error)
        return
    if size > budgets.manifest_max_bytes:
        gaps.append(
            (
                GAP_BUDGET_EXHAUSTED,
                f"manifest={relative_path}; bytes={size}; "
                f"limit={budgets.manifest_max_bytes}",
            )
        )
        return
    try:
        text = workspace.read_text(relative_path)
    except (OSError, ValueError) as error:
        _record_manifest_error(gaps, relative_path, error)
        return
    _parse_manifest(relative_path, text, summary, gaps)


def _load_manifests(
    workspace: RepositoryWorkspace,
    candidates: list[str],
    budgets: ProfileBudgets,
) -> tuple[_ManifestSummary, list[tuple[str, str]]]:
    summary = _ManifestSummary()
    gaps: list[tuple[str, str]] = []
    ordered = sorted(candidates)
    if len(ordered) > budgets.max_manifest_files:
        overflow = len(ordered) - budgets.max_manifest_files
        gaps.append(
            (GAP_BUDGET_EXHAUSTED, f"reason=manifest-file-limit; count={overflow}")
        )
        ordered = ordered[: budgets.max_manifest_files]
    for relative_path in ordered:
        _load_one_manifest(workspace, relative_path, budgets, summary, gaps)
    return summary, gaps


def _read_source_text(workspace: RepositoryWorkspace, relative_path: str) -> str | None:
    try:
        return workspace.read_text(relative_path)
    except (OSError, ValueError):
        return None


def _path_evidence(
    inventory_files: list, summary: _ManifestSummary
) -> dict[str, set[str]]:
    evidence: dict[str, set[str]] = {}
    for item in inventory_files:
        parts = item.path.split("/")
        directories = parts[:-1]
        name = parts[-1]
        reasons: set[str] = set()
        if any(part in _TEST_DIR_NAMES for part in directories):
            reasons.add("PATH_TEST_DIR")
        if any(part in _DOCS_DIR_NAMES for part in directories):
            reasons.add("PATH_DOCS_DIR")
        if any(part in _EXAMPLE_DIR_NAMES for part in directories):
            reasons.add("PATH_EXAMPLE_DIR")
        if any(fnmatch.fnmatchcase(name, pattern) for pattern in _GENERATED_NAME_PATTERNS):
            reasons.add("PATH_PATTERN_GENERATED")
        if any(part in _BUILD_OUTPUT_DIR_NAMES for part in directories):
            reasons.add("MANIFEST_BUILD_TARGET")
        if any(
            fnmatch.fnmatchcase(item.path, pattern)
            for pattern in summary.exclude_patterns
        ):
            reasons.add("MANIFEST_PACKAGES_EXCLUDED")
        if summary.has_test_config and "PATH_TEST_DIR" in reasons:
            reasons.add("MANIFEST_TEST_CONFIG")
        evidence[item.path] = reasons
    return evidence


def _source_evidence(
    workspace: RepositoryWorkspace,
    inventory_files: list,
    evidence: dict[str, set[str]],
) -> tuple[set[str], set[str]]:
    """Collect import stems of production files plus framework keyword hits.

    Source files whose imports cannot be parsed contribute no references;
    this only lowers the (low-confidence) ``NOT_IMPORTED_BY_PROD`` evidence
    and never produces a coverage gap.
    """
    references: set[str] = set()
    keywords: set[str] = set()
    for item in inventory_files:
        suffix = _suffix_of(item.path)
        if suffix not in _EXTENSION_TO_LANGUAGE:
            continue
        text = _read_source_text(workspace, item.path)
        if text is None:
            continue
        keywords.update(_keywords_in_import_lines(text))
        if suffix == ".py" and not (evidence[item.path] & _PATH_CLASS_REASONS):
            references.update(_import_stems(text))
    return references, keywords


def _resolve_script_target(target: str, inventoried: frozenset[str]) -> str | None:
    module = target.split(":", 1)[0]
    parts = [part for part in module.split(".") if part]
    if not parts:
        return None
    for size in range(len(parts), 0, -1):
        candidate = "/".join(parts[:size]) + "/__init__.py"
        if candidate in inventoried:
            return candidate
    module_file = "/".join(parts) + ".py"
    if module_file in inventoried:
        return module_file
    return None


def _build_entrypoints(
    summary: _ManifestSummary, inventoried: frozenset[str]
) -> tuple[list[AttackSurfaceEntry], frozenset[str]]:
    entries: list[AttackSurfaceEntry] = []
    targets: set[str] = set()
    if summary.scripts:
        for name in sorted(summary.scripts):
            resolved = _resolve_script_target(summary.scripts[name], inventoried)
            if resolved is None:
                continue
            targets.add(resolved)
            entries.append(
                AttackSurfaceEntry(
                    path=resolved,
                    symbol=name,
                    reason_codes=("ENTRY_SCRIPT_DECLARED",),
                    source_artifact_ids=(PROFILE_PROVENANCE_ANCHOR,),
                )
            )
    else:
        for relative_path in sorted(_ROOT_ENTRY_CANDIDATES):
            if relative_path in inventoried:
                entries.append(
                    AttackSurfaceEntry(
                        path=relative_path,
                        symbol=None,
                        reason_codes=("ENTRY_ROOT_CONVENTION",),
                        source_artifact_ids=(PROFILE_PROVENANCE_ANCHOR,),
                    )
                )
    entries.sort(key=lambda entry: (entry.path, entry.symbol or ""))
    return entries, frozenset(targets)


def _repository_kinds(
    inventory_files: list,
    summary: _ManifestSummary,
    language_names: frozenset[str],
    manifest_rels: list[str],
) -> tuple[RepositoryKind, ...]:
    kinds: set[RepositoryKind] = set()
    paths = [item.path for item in inventory_files]
    root_files = {path for path in paths if "/" not in path}
    has_languages = bool(language_names)
    has_scripts = bool(summary.scripts)
    if has_languages and (
        has_scripts or "cli.py" in root_files or "__main__.py" in root_files
    ):
        kinds.add(RepositoryKind.CLI)
    has_src_root = any(path.split("/", 1)[0] == "src" for path in paths)
    if (
        has_languages
        and not has_scripts
        and has_src_root
        and "pyproject.toml" in manifest_rels
    ):
        kinds.add(RepositoryKind.LIBRARY)
    has_app_root = any(path.split("/", 1)[0] == "app" for path in paths)
    has_server_module = any(
        path.rsplit("/", 1)[-1] in {"asgi.py", "wsgi.py"} for path in paths
    )
    if has_languages and (
        has_app_root or "main.py" in root_files or has_server_module
    ):
        kinds.add(RepositoryKind.APPLICATION)
    docs_like = [
        path for path in paths if _suffix_of(path) in _DOCS_CONTENT_SUFFIXES
    ]
    if not language_names and docs_like and len(docs_like) * 2 > len(paths):
        kinds.add(RepositoryKind.DOCS_CONTENT)
    manifest_subdirs = {rel.split("/", 1)[0] for rel in manifest_rels if "/" in rel}
    if has_languages and len(manifest_subdirs) >= 2:
        kinds.add(RepositoryKind.MONOREPO)
    if not kinds:
        kinds.add(RepositoryKind.UNKNOWN)
    return tuple(sorted(kinds, key=lambda kind: kind.value))


def _support_level_and_gaps(
    language_names: frozenset[str],
    summary: _ManifestSummary,
    gaps: list[tuple[str, str]],
) -> SupportLevel:
    if "Python" in language_names:
        if summary.has_python_manifest:
            return SupportLevel.SUPPORTED
        return SupportLevel.PARTIAL
    if language_names:
        gaps.append(
            (
                GAP_UNSUPPORTED_LANGUAGE,
                "reason=unsupported-language; languages="
                + ",".join(sorted(language_names)),
            )
        )
        return SupportLevel.PARTIAL
    gaps.append((GAP_NO_LANGUAGES_DETECTED, "reason=no-languages-detected"))
    return SupportLevel.UNSUPPORTED


def _skip_reason_gaps(
    inventory, has_languages: bool
) -> list[tuple[str, str]]:
    gaps: list[tuple[str, str]] = []
    for reason in sorted(inventory.skipped):
        count = inventory.skipped[reason]
        detail = SKIP_REASON_TO_GAP_DETAIL[reason].format(reason=reason, count=count)
        if reason in _BUDGET_SKIP_REASONS:
            gaps.append((GAP_BUDGET_EXHAUSTED, detail))
        elif reason == "unsupported-extension" and not has_languages:
            gaps.append((GAP_UNSUPPORTED_LANGUAGE, detail))
        elif reason != "unsupported-extension":
            gaps.append((GAP_INVENTORY_SKIPPED, detail))
    return gaps


def _technology_declarations(
    names: set[str] | frozenset[str], detection: DetectionMethod
) -> tuple[TechnologyDeclaration, ...]:
    declarations = [
        TechnologyDeclaration(
            name=name,
            detection=detection,
            source_artifact_ids=(PROFILE_PROVENANCE_ANCHOR,),
        )
        for name in sorted(names)
    ]
    return tuple(declarations)


def _language_declarations(
    inventory_files: list, summary: _ManifestSummary
) -> tuple[TechnologyDeclaration, ...]:
    inferred: set[str] = set()
    for item in inventory_files:
        name = _EXTENSION_TO_LANGUAGE.get(_suffix_of(item.path))
        if name is not None:
            inferred.add(name)
    names = inferred | summary.declared_languages
    declarations = [
        TechnologyDeclaration(
            name=name,
            detection=(
                DetectionMethod.DECLARED
                if name in summary.declared_languages
                else DetectionMethod.INFERRED
            ),
            source_artifact_ids=(PROFILE_PROVENANCE_ANCHOR,),
        )
        for name in sorted(names)
    ]
    return tuple(declarations)


def _code_role_assignments(
    evidence: dict[str, set[str]],
    entry_targets: frozenset[str],
    gaps: list[tuple[str, str]],
) -> tuple[CodeRoleAssignment, ...]:
    assignments: list[CodeRoleAssignment] = []
    for relative_path in sorted(evidence):
        reasons = evidence[relative_path]
        if relative_path in entry_targets:
            reasons.add("ENTRY_SCRIPT_DECLARED")
        for path_reason, role in _ROLE_PATH_EVIDENCE:
            if path_reason in reasons and reasons & _NON_PATH_REASONS:
                assignments.append(
                    CodeRoleAssignment(
                        role=role,
                        path=relative_path,
                        reason_codes=tuple(sorted(reasons)),
                        source_artifact_ids=(PROFILE_PROVENANCE_ANCHOR,),
                    )
                )
    assignments.sort(key=lambda assignment: (assignment.role.value, assignment.path))
    if len(assignments) > _MAX_CODE_ROLE_ASSIGNMENTS:
        overflow = len(assignments) - _MAX_CODE_ROLE_ASSIGNMENTS
        assignments = assignments[:_MAX_CODE_ROLE_ASSIGNMENTS]
        gaps.append((GAP_BUDGET_EXHAUSTED, f"reason=code-role-limit; count={overflow}"))
    return tuple(assignments)


def _coverage_gaps(gaps: list[tuple[str, str]]) -> tuple[ProfileCoverageGap, ...]:
    ordered = sorted(gaps, key=lambda pair: (pair[0], pair[1].encode("utf-8")))
    if len(ordered) > _MAX_COVERAGE_GAPS:
        return (
            ProfileCoverageGap(
                gap_code=GAP_BUDGET_EXHAUSTED,
                detail=f"reason=coverage-gap-limit; count={len(ordered)}",
            ),
        )
    return tuple(
        ProfileCoverageGap(gap_code=code, detail=detail) for code, detail in ordered
    )


def _execution_capability(
    inventory_files: list, summary: _ManifestSummary
) -> ExecutionCapability:
    has_test_directory = any(
        part in _TEST_DIR_NAMES
        for item in inventory_files
        for part in item.path.split("/")[:-1]
    )
    return ExecutionCapability(
        buildable=bool(summary.buildable),
        testable=bool(has_test_directory or summary.has_test_config),
        requires_network=False,
        requires_services=False,
        requires_gpu=False,
        requires_external_credentials=False,
    )


def _build_profile_envelope(
    *,
    profile: RepositoryProfile,
    inventory,
    schema_version: SchemaVersion,
    tenant_id: str,
    task_id: str,
    workflow_id: str,
    stage_attempt_id: str,
    artifact_id: str,
    repository_snapshot_digest: str,
    producer: str,
    policy_digest: str,
    toolchain_digest: str,
) -> ArtifactEnvelope:
    payload = profile.to_dict()
    lineage = (
        ArtifactReference(
            schema_name=_INVENTORY_SCHEMA_NAME,
            schema_version=schema_version,
            artifact_id=PROFILE_PROVENANCE_ANCHOR,
            tenant_id=tenant_id,
            repository_snapshot_digest=repository_snapshot_digest,
            content_digest=inventory.fingerprint(),
        ),
    )
    envelope = ArtifactEnvelope(
        schema_name=REPOSITORY_PROFILE_SCHEMA_NAME,
        schema_version=schema_version,
        artifact_id=artifact_id,
        tenant_id=tenant_id,
        task_id=task_id,
        workflow_id=workflow_id,
        stage_attempt_id=stage_attempt_id,
        repository_snapshot_digest=repository_snapshot_digest,
        producer=producer,
        created_at=_DETERMINISTIC_CREATED_AT,
        policy_digest=policy_digest,
        toolchain_digest=toolchain_digest,
        content_digest=compute_content_digest(payload),
        classification=ArtifactClassification.INTERNAL,
        retention_class=RetentionClass.STANDARD,
        payload=payload,
        lineage=lineage,
    )
    # Full binding validation (payload identity, digest, protected
    # classification, source lineage); the encoded bytes are not kept.
    encode_profile_envelope(envelope, profile)
    return envelope


def build_repository_profile(
    workspace: RepositoryWorkspace,
    *,
    tenant_id: str,
    task_id: str,
    workflow_id: str,
    stage_attempt_id: str,
    artifact_id: str,
    repository_snapshot_digest: str,
    producer: str = _DEFAULT_PRODUCER,
    policy_digest: str = _SENTINEL_EMPTY_DIGEST,
    toolchain_digest: str = _SENTINEL_EMPTY_DIGEST,
    options: ProfileInventoryOptions | None = None,
) -> ProfileBuildResult:
    """Build a deterministic repository profile from a read-only workspace."""
    if not isinstance(workspace, RepositoryWorkspace):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    for identifier in (
        tenant_id,
        task_id,
        workflow_id,
        stage_attempt_id,
        artifact_id,
        producer,
    ):
        if not isinstance(identifier, str):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if not isinstance(repository_snapshot_digest, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    for digest in (policy_digest, toolchain_digest):
        if not isinstance(digest, str):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
        if not digest:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE)
    if options is not None and not isinstance(options, ProfileInventoryOptions):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    budgets = options.budgets if options is not None else ProfileBudgets()
    schema_version = (
        options.schema_version if options is not None else SchemaVersion(4, 0)
    )

    inventory = workspace.inventory()
    gaps: list[tuple[str, str]] = []
    manifest_rels = _manifest_candidates(workspace)
    summary, manifest_gaps = _load_manifests(workspace, manifest_rels, budgets)
    gaps.extend(manifest_gaps)

    evidence = _path_evidence(inventory.files, summary)
    references, source_keywords = _source_evidence(workspace, inventory.files, evidence)
    summary.frameworks.update(source_keywords)
    for relative_path, reasons in evidence.items():
        stem = relative_path.rsplit("/", 1)[-1].split(".", 1)[0]
        if stem not in references:
            reasons.add("NOT_IMPORTED_BY_PROD")

    inventoried = frozenset(item.path for item in inventory.files)
    entrypoints, entry_targets = _build_entrypoints(summary, inventoried)

    languages = _language_declarations(inventory.files, summary)
    language_names = frozenset(declaration.name for declaration in languages)
    frameworks = _technology_declarations(
        summary.frameworks, DetectionMethod.INFERRED
    )
    package_managers = _technology_declarations(
        summary.package_managers, DetectionMethod.DECLARED
    )
    build_systems = _technology_declarations(
        summary.build_systems, DetectionMethod.DECLARED
    )

    kinds = _repository_kinds(inventory.files, summary, language_names, manifest_rels)
    support_level = _support_level_and_gaps(language_names, summary, gaps)
    gaps.extend(_skip_reason_gaps(inventory, bool(language_names)))
    code_roles = _code_role_assignments(evidence, entry_targets, gaps)

    file_count = len(inventory.files)
    total_bytes = inventory.total_bytes
    max_file_bytes = max((item.size for item in inventory.files), default=0)
    code_bytes = sum(
        item.size
        for item in inventory.files
        if _suffix_of(item.path) in _EXTENSION_TO_LANGUAGE
    )
    binary_skips = inventory.skipped.get("binary", 0) + inventory.skipped.get(
        "non-utf8", 0
    )
    generated_count = sum(
        1 for assignment in code_roles if assignment.role is CodeRole.GENERATED
    )

    profile = RepositoryProfile(
        schema_version=schema_version,
        repository_kinds=kinds,
        execution_capability=_execution_capability(inventory.files, summary),
        support_level=support_level,
        component_path=None,
        file_count=file_count,
        total_bytes=total_bytes,
        max_file_bytes=max_file_bytes,
        code_density_bp=_ratio_bp(code_bytes, total_bytes),
        binary_ratio_bp=_ratio_bp(binary_skips, inventory.discovered_files),
        generated_ratio_bp=_ratio_bp(generated_count, file_count),
        languages=languages,
        frameworks=frameworks,
        package_managers=package_managers,
        build_systems=build_systems,
        code_roles=code_roles,
        entrypoints=tuple(entrypoints),
        coverage_gaps=_coverage_gaps(gaps),
    )
    envelope = _build_profile_envelope(
        profile=profile,
        inventory=inventory,
        schema_version=schema_version,
        tenant_id=tenant_id,
        task_id=task_id,
        workflow_id=workflow_id,
        stage_attempt_id=stage_attempt_id,
        artifact_id=artifact_id,
        repository_snapshot_digest=repository_snapshot_digest,
        producer=producer,
        policy_digest=policy_digest,
        toolchain_digest=toolchain_digest,
    )
    return ProfileBuildResult(
        profile=profile,
        envelope=envelope,
        provenance_anchor_ids=(PROFILE_PROVENANCE_ANCHOR,),
    )
