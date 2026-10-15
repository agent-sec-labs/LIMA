"""Monorepo component graph and per-component Profile/RAM/semantic chain.

IP-0023 (Packet v5.1, sections 5.1-5.9): a deterministic, read-only,
stdlib-only monorepo component layer on top of the frozen three-layer public
interfaces (``lima.audit.inventory`` / ``lima.audit.ram`` /
``lima.audit.semantic_prioritizer``), ``lima.audit.ram_schema`` (read-only
reuse of its public wire functions) and ``lima.workspace``.

Frozen behaviour highlights (Packet v5.1):

- component discovery from two separated input sets -- (S1) the caller's
  admitted main inventory and (S2) the controlled manifest metadata channel
  (nine-name closed set, two policies, count+byte budgets, split skip
  counting);
- single precise file ownership by deepest admitted anchor, enforced through
  the W-1 double-list restricted view (``admitted_files``/``metadata_files``)
  and the W-2 candidate-union filter;
- per-component Profile/RAM/semantic builds through the frozen public
  entries with full five-parameter policy inheritance and keyed artifact
  digest references (``ComponentInfo.artifact_digests``);
- module-root resolution, three-state edges, typed unknown-import carriage
  and the shared edge/unknown mixed cap (one-pass truncation, builder and
  validator same semantics);
- the closed completeness trigger set T1-T8 plus the priority-unique
  three-state decision table inputs;
- an independently versioned component-graph wire payload with a canonical
  digest and a fail-closed ten-dimension validator (V1-V10).

Determinism: no clock, no randomness, no environment reads, no network, no
filesystem writes; every enumeration is sorted. Fail-closed: contract
violations raise ``ContractError``/``ValueError``, budget exhaustion yields
partial facts plus typed gaps, never silent truncation.
"""

from __future__ import annotations

import ast
import json
import os
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Final

from lima.audit.inventory import (
    ProfileBudgets,
    ProfileBuildResult,
    ProfileInventoryOptions,
    build_repository_profile,
    is_secret_shaped_path,
)
from lima.audit.ram import (
    RamBudgets,
    RamFactsBuildResult,
    build_python_ram_facts,
    ram_facts_digest,
)
from lima.audit.ram_schema import ram_wire_payload
from lima.audit.semantic_prioritizer import (
    SemanticModelClient,
    SemanticOptions,
    SemanticTopNResult,
    build_semantic_top_n,
    semantic_result_digest,
)
from lima.contracts.codec import compute_content_digest
from lima.contracts.errors import ContractError, ContractErrorCode
from lima.contracts.profile import ProfileCoverageGap
from lima.workspace import RepositoryWorkspace, WorkspaceInventory

COMPONENT_GRAPH_SCHEMA_VERSION: Final[str] = "2.0"
COMPONENT_GRAPH_SCHEMA_NAME: Final[str] = "lima.component-graph"
COMPONENT_GRAPH_SCHEMA_FILE: Final[Path] = (
    Path("schemas") / "v4" / "lima.component-graph.json"
)
COMPONENT_GRAPH_PROVENANCE_ANCHOR: Final[str] = "component-graph"

COMPONENT_EDGE_STATUS_RESOLVED: Final[str] = "resolved"
COMPONENT_EDGE_STATUS_AMBIGUOUS: Final[str] = "ambiguous"
COMPONENT_EDGE_STATUS_UNRESOLVED: Final[str] = "unresolved"
COMPONENT_EDGE_STATUSES: Final[frozenset[str]] = frozenset(
    {COMPONENT_EDGE_STATUS_RESOLVED, COMPONENT_EDGE_STATUS_AMBIGUOUS,
     COMPONENT_EDGE_STATUS_UNRESOLVED}
)

COMPONENT_MANIFEST_KIND_PYPROJECT: Final[str] = "pyproject"
COMPONENT_MANIFEST_KIND_SETUP_PY: Final[str] = "setup_py"
COMPONENT_MANIFEST_KIND_SETUP_CFG: Final[str] = "setup_cfg"
COMPONENT_MANIFEST_KIND_REQUIREMENTS: Final[str] = "requirements"
COMPONENT_MANIFEST_KIND_ENVIRONMENT_YML: Final[str] = "environment_yml"
COMPONENT_MANIFEST_KIND_PACKAGE_JSON: Final[str] = "package_json"
COMPONENT_MANIFEST_KIND_GO_MOD: Final[str] = "go_mod"
COMPONENT_MANIFEST_KIND_CARGO_TOML: Final[str] = "cargo_toml"
COMPONENT_MANIFEST_KIND_POM_XML: Final[str] = "pom_xml"

UNBUILT_REASON_CAP_DIVERGENCE: Final[str] = "cap-divergence"
UNBUILT_REASON_VIEW_UNFORMABLE: Final[str] = "view-unformable"
UNBUILT_REASON_ADMISSION_REFUSED: Final[str] = "admission-refused"
UNBUILT_REASONS: Final[frozenset[str]] = frozenset(
    {UNBUILT_REASON_CAP_DIVERGENCE, UNBUILT_REASON_VIEW_UNFORMABLE,
     UNBUILT_REASON_ADMISSION_REFUSED}
)

COMPONENT_MANIFEST_SOURCE_INVENTORY: Final[str] = "source-inventory"
COMPONENT_MANIFEST_SOURCE_METADATA_CHANNEL: Final[str] = "metadata-channel"
COMPONENT_MANIFEST_SOURCES: Final[frozenset[str]] = frozenset(
    {COMPONENT_MANIFEST_SOURCE_INVENTORY,
     COMPONENT_MANIFEST_SOURCE_METADATA_CHANNEL}
)

MANIFEST_POLICY_METADATA_CHANNEL: Final[str] = "metadata-channel"
MANIFEST_POLICY_ADMITTED_ONLY: Final[str] = "admitted-only"
MANIFEST_POLICIES: Final[frozenset[str]] = frozenset(
    {MANIFEST_POLICY_METADATA_CHANNEL, MANIFEST_POLICY_ADMITTED_ONLY}
)

# --- module-private frozen vocabulary and helpers ---------------------------

#: Manifest exact-name map, value-restating the frozen inventory layer
#: (Packet v5.1 section 5.1.7: closed nine-name set; no private import).
_MANIFEST_EXACT_KINDS: Final[Mapping[str, str]] = {
    "Cargo.toml": COMPONENT_MANIFEST_KIND_CARGO_TOML,
    "environment.yml": COMPONENT_MANIFEST_KIND_ENVIRONMENT_YML,
    "go.mod": COMPONENT_MANIFEST_KIND_GO_MOD,
    "package.json": COMPONENT_MANIFEST_KIND_PACKAGE_JSON,
    "pom.xml": COMPONENT_MANIFEST_KIND_POM_XML,
    "pyproject.toml": COMPONENT_MANIFEST_KIND_PYPROJECT,
    "setup.cfg": COMPONENT_MANIFEST_KIND_SETUP_CFG,
    "setup.py": COMPONENT_MANIFEST_KIND_SETUP_PY,
}
_REQUIREMENTS_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^requirements[^/]*\.txt$")
_DEPENDENCY_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.\-]+")
_SENTINEL_EMPTY_DIGEST: Final[str] = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)
_COMPONENT_PRODUCER: Final[str] = "lima.audit.component_graph"

#: T6 loss keys over the main inventory skip vocabulary (section 5.2.4).
_T6_LOSS_KEYS: Final[tuple[str, ...]] = (
    "file-limit",
    "total-size-limit",
    "file-size-limit",
    "binary",
    "non-utf8",
    "unreadable",
)
#: T8 evidence-loss keys over the channel skip vocabulary (section 5.1.7).
_T8_LOSS_KEYS: Final[tuple[str, ...]] = (
    "metadata-manifest-limit",
    "metadata-byte-limit",
    "unreadable",
    "non-utf8",
)
#: Channel skip vocabulary (seven keys; sections 5.1.7/5.2.4).
_CHANNEL_SKIP_VOCABULARY: Final[frozenset[str]] = frozenset(
    {"ignored-directory", "sensitive-filename", "symlink", *_T8_LOSS_KEYS}
)
#: Source-inventory gap-reason vocabulary: main skip keys plus the anchor
#: rejection key (section 5.4.8 V7 structural check domain).
_SOURCE_GAP_VOCABULARY: Final[frozenset[str]] = frozenset(
    {
        *_T6_LOSS_KEYS,
        "ignored-directory",
        "symlink",
        "sensitive-config",
        "unsupported-extension",
        "sensitive-filename",
    }
)
#: Graph-level budget-family gap reasons (no channel segment; section 5.1.7).
_GRAPH_BUDGET_REASONS: Final[frozenset[str]] = frozenset(
    {
        "component-limit",
        "edge-limit",
        "edge-evidence-limit",
        "unknown-import-limit",
        "unassigned-file-limit",
        "aggregate-model-call-limit",
        "aggregate-token-pool-limit",
    }
)
_CHANNEL_METADATA_BUDGET_REASONS: Final[frozenset[str]] = frozenset(
    {"metadata-manifest-limit", "metadata-byte-limit"}
)

_PER_CANDIDATE_OUTPUT_TOKENS: Final[int] = 128
_DESCRIPTOR_KEY: Final[str] = '"candidate_id":'

#: Frozen stdlib top-level snapshot (Packet v5.1 section 5.3.3 P4a):
#: cross-interpreter stability is preferred over exhaustiveness.
_STDLIB_TOP_LEVEL_NAMES: Final[frozenset[str]] = frozenset(
    """
    abc argparse array ast asyncio atexit base64 binascii bisect builtins
    calendar cmath codecs collections concurrent configparser contextlib
    contextvars copy copyreg csv ctypes dataclasses datetime decimal difflib
    dis doctest email enum errno faulthandler fileinput fnmatch fractions
    ftplib functools gc getpass gettext glob gzip hashlib heapq hmac html
    http importlib inspect io ipaddress itertools json keyword linecache
    locale logging lzma marshal math mimetypes mmap multiprocessing numbers
    operator os pathlib pdb pickle platform plistlib poplib posixpath pprint
    profile pstats pty pwd py_compile pyclbr pydoc queue quopri random re
    readline reprlib resource runpy sched secrets select selectors shelve
    shlex shutil signal site smtplib socket sqlite3 ssl stat statistics
    string stringprep struct subprocess symtable sys sysconfig tarfile
    tempfile termios textwrap threading time timeit token tokenize traceback
    tracemalloc tty types typing unicodedata unittest urllib uuid venv
    warnings wave weakref webbrowser wsgiref xml xmlrpc zipfile zlib
    """.split()
)


def _manifest_kind_of(name: str) -> str | None:
    if name in _MANIFEST_EXACT_KINDS:
        return _MANIFEST_EXACT_KINDS[name]
    if _REQUIREMENTS_NAME_RE.match(name) is not None:
        return COMPONENT_MANIFEST_KIND_REQUIREMENTS
    return None


def _anchor_of(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else ""


def _component_id_of(anchor: str) -> str:
    return "component:." if anchor == "" else f"component:{anchor}"


def _internal_path(anchor: str, repo_path: str) -> str:
    if anchor == "":
        return repo_path
    prefix = anchor + "/"
    return repo_path[len(prefix):] if repo_path.startswith(prefix) else repo_path


def _in_subtree(path: str, anchor: str) -> bool:
    if anchor == "":
        return True
    return path == anchor or path.startswith(anchor + "/")


def _owner_anchor(path: str, anchors: list[str]) -> str | None:
    best: str | None = None
    best_depth = -1
    for anchor in anchors:
        if anchor == "":
            depth = 0
        elif path.startswith(anchor + "/"):
            depth = anchor.count("/") + 1
        else:
            continue
        if depth > best_depth:
            best, best_depth = anchor, depth
    return best


def _make_gap(code: str, detail: str) -> ProfileCoverageGap:
    return ProfileCoverageGap(gap_code=code, detail=detail)


def _channel_gap_detail(reason: str, count: int, channel: str) -> str:
    return f"channel={channel}; reason={reason}; count={count}"


def _budget_gap_detail(reason: str, count: int) -> str:
    return f"reason={reason}; count={count}"


# ---------------------------------------------------------------------------
# Frozen dataclasses (Packet v5.1 sections 5.4.1-5.4.3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ComponentManifestRef:
    """One discovered manifest file (repo-relative POSIX path)."""

    path: str
    manifest_kind: str
    source: str


@dataclass(frozen=True)
class EdgeEvidence:
    """One import-site evidence anchor for an edge."""

    path: str
    line: int
    imported_name: str


@dataclass(frozen=True)
class ComponentArtifactDigests:
    """Public per-component artifact digest references (R3 binding)."""

    profile_content_digest: str
    ram_facts_digest: str
    semantic_result_digest: str


@dataclass(frozen=True)
class ComponentInfo:
    """One component's discovery facts plus optional artifact references."""

    component_id: str
    root_dir: str
    manifests: tuple[ComponentManifestRef, ...]
    python_file_count: int
    is_empty: bool
    artifact_digests: ComponentArtifactDigests | None = None


@dataclass(frozen=True)
class ComponentScanSummary:
    """Graph-level per-component scan counters (counts only, no paths)."""

    component_id: str
    parse_error_file_count: int
    read_failure_file_count: int
    dynamic_import_site_count: int
    unknown_truncated_count: int
    manifest_parse_failure_count: int


@dataclass(frozen=True)
class UnknownImportRecord:
    """One unresolved import name carried typed (never faked as external)."""

    source_component_id: str
    imported_name: str
    count: int


@dataclass(frozen=True)
class UnbuiltComponentRecord:
    """One component that could not be built (three distinguishable reasons)."""

    component_id: str
    reason: str


@dataclass(frozen=True)
class ComponentEdge:
    """One inter-component dependency edge with capped evidence."""

    source_component_id: str
    target_component_id: str | None
    status: str
    imported_name: str
    evidence: tuple[EdgeEvidence, ...]


@dataclass(frozen=True)
class ResourceMetering:
    """Read-attempt and successful-byte metering over the nine IO stages."""

    main_inventory_read_attempts: int = 0
    component_rescan_read_attempts: int = 0
    profile_manifest_read_attempts: int = 0
    ast_read_attempts: int = 0
    metadata_channel_read_attempts: int = 0
    read_success_bytes: int = 0


@dataclass(frozen=True)
class ComponentGraph:
    """The independently versioned component graph carrier."""

    components: tuple[ComponentInfo, ...]
    edges: tuple[ComponentEdge, ...]
    unassigned_files: tuple[str, ...]
    unassigned_file_count: int
    unknown_imports: tuple[UnknownImportRecord, ...]
    scan_summaries: tuple[ComponentScanSummary, ...]
    unbuilt_components: tuple[UnbuiltComponentRecord, ...]
    dependencies_complete: bool
    coverage_gaps: tuple[ProfileCoverageGap, ...]
    manifests_discovered_count: int
    metadata_manifest_count: int
    collaboration_manifest_count: int
    overflow_manifest_count: int
    provenance_anchor_ids: tuple[str, ...] = (COMPONENT_GRAPH_PROVENANCE_ANCHOR,)


#: Budget legal domains (single source of truth): construction-time
#: validation (MonorepoBudgets.__post_init__) and the public validator's V8
#: budget cross-check both read this table; the schema hard caps are the
#: domain upper bounds (Packet v5.1 sections 5.4.3/5.4.8 V8). Defaults are
#: NOT hard caps -- any in-domain value is legal.
_BUDGET_DOMAINS: Final[Mapping[str, tuple[int, int]]] = {
    "max_components": (1, 64),
    "max_edges": (1, 16_384),
    "max_edge_evidence": (1, 1_024),
    "max_unassigned_files": (1, 4_096),
    "max_total_model_calls": (1, 512),
    "aggregate_max_prompt_tokens": (1, 1_000_000),
    "aggregate_max_output_tokens": (1, 1_000_000),
    "aggregate_max_total_tokens": (1, 1_000_000),
    "max_metadata_manifests": (1, 1_024),
    "max_metadata_total_bytes": (1, 10**12),
}


@dataclass(frozen=True)
class MonorepoBudgets:
    """Aggregate budgets with default / legal-domain / schema-cap separation.

    Construction validates the legal domain (exact ``int`` type and range);
    the wire schema carries the independent hard caps (domain upper bounds);
    the builder truncates against the effective values.
    """

    max_components: int = 16
    max_edges: int = 4_096
    max_edge_evidence: int = 64
    max_unassigned_files: int = 256
    max_total_model_calls: int = 8
    aggregate_max_prompt_tokens: int = 24_000
    aggregate_max_output_tokens: int = 4_096
    aggregate_max_total_tokens: int = 28_096
    max_metadata_manifests: int = 64
    max_metadata_total_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        for name, (low, high) in _BUDGET_DOMAINS.items():
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"{name} must be an integer in [{low}, {high}]")
        if (
            self.aggregate_max_total_tokens
            < self.aggregate_max_prompt_tokens + self.aggregate_max_output_tokens
        ):
            raise ValueError(
                "aggregate_max_total_tokens must be >= "
                "aggregate_max_prompt_tokens + aggregate_max_output_tokens"
            )


@dataclass(frozen=True)
class ComponentDiscoveryResult:
    """Component discovery over the two separated input sets."""

    components: tuple[ComponentInfo, ...]
    unassigned_files: tuple[str, ...]
    unassigned_file_count: int
    metadata_manifest_count: int
    metadata_channel_skipped: Mapping[str, int]
    manifests_discovered_count: int
    collaboration_manifest_count: int
    overflow_manifest_count: int
    coverage_gaps: tuple[ProfileCoverageGap, ...]
    truncated: bool
    provenance_anchor_ids: tuple[str, ...] = (COMPONENT_GRAPH_PROVENANCE_ANCHOR,)


@dataclass(frozen=True)
class ComponentBuildResult:
    """One built component with its three-stage public results and wire."""

    component: ComponentInfo
    profile_result: ProfileBuildResult
    ram_result: RamFactsBuildResult
    semantic_result: SemanticTopNResult
    ram_wire: Mapping[str, object]
    effective_profile_budgets: ProfileBudgets
    effective_ram_budgets: RamBudgets
    effective_semantic_options: SemanticOptions


@dataclass(frozen=True)
class MonorepoProfileBuildResult:
    """Whole-monorepo build result: discovery, per-component chain and graph."""

    discovery: ComponentDiscoveryResult
    per_component: tuple[ComponentBuildResult, ...]
    graph: ComponentGraph
    metering: ResourceMetering
    provenance_anchor_ids: tuple[str, ...] = (COMPONENT_GRAPH_PROVENANCE_ANCHOR,)


__all__ = [
    "COMPONENT_EDGE_STATUSES",
    "COMPONENT_EDGE_STATUS_AMBIGUOUS",
    "COMPONENT_EDGE_STATUS_RESOLVED",
    "COMPONENT_EDGE_STATUS_UNRESOLVED",
    "COMPONENT_GRAPH_PROVENANCE_ANCHOR",
    "COMPONENT_GRAPH_SCHEMA_FILE",
    "COMPONENT_GRAPH_SCHEMA_NAME",
    "COMPONENT_GRAPH_SCHEMA_VERSION",
    "COMPONENT_MANIFEST_KIND_CARGO_TOML",
    "COMPONENT_MANIFEST_KIND_ENVIRONMENT_YML",
    "COMPONENT_MANIFEST_KIND_GO_MOD",
    "COMPONENT_MANIFEST_KIND_PACKAGE_JSON",
    "COMPONENT_MANIFEST_KIND_POM_XML",
    "COMPONENT_MANIFEST_KIND_PYPROJECT",
    "COMPONENT_MANIFEST_KIND_REQUIREMENTS",
    "COMPONENT_MANIFEST_KIND_SETUP_CFG",
    "COMPONENT_MANIFEST_KIND_SETUP_PY",
    "COMPONENT_MANIFEST_SOURCES",
    "COMPONENT_MANIFEST_SOURCE_INVENTORY",
    "COMPONENT_MANIFEST_SOURCE_METADATA_CHANNEL",
    "MANIFEST_POLICIES",
    "MANIFEST_POLICY_ADMITTED_ONLY",
    "MANIFEST_POLICY_METADATA_CHANNEL",
    "UNBUILT_REASONS",
    "UNBUILT_REASON_ADMISSION_REFUSED",
    "UNBUILT_REASON_CAP_DIVERGENCE",
    "UNBUILT_REASON_VIEW_UNFORMABLE",
    "ComponentArtifactDigests",
    "ComponentBuildResult",
    "ComponentDiscoveryResult",
    "ComponentEdge",
    "ComponentGraph",
    "ComponentInfo",
    "ComponentManifestRef",
    "ComponentScanSummary",
    "EdgeEvidence",
    "MonorepoBudgets",
    "MonorepoProfileBuildResult",
    "ResourceMetering",
    "UnbuiltComponentRecord",
    "UnknownImportRecord",
    "build_monorepo_profile",
    "component_graph_digest",
    "component_graph_payload",
    "detect_components",
    "load_component_graph_schema",
    "validate_component_graph_payload",
]


# ---------------------------------------------------------------------------
# S2 channel: controlled manifest metadata discovery (section 5.1.7)
# ---------------------------------------------------------------------------


def _channel_walk(
    workspace: RepositoryWorkspace,
) -> tuple[list[str], dict[str, int]]:
    """One deterministic channel walk: manifest candidates + prune counts."""

    candidates: list[str] = []
    prunes: dict[str, int] = {
        "ignored-directory": 0,
        "sensitive-filename": 0,
        "symlink": 0,
    }
    root = workspace.root
    for current_root, directory_names, file_names in os.walk(
        root, topdown=True, followlinks=False
    ):
        current = Path(current_root)
        kept: list[str] = []
        for name in sorted(directory_names):
            child = current / name
            if name in workspace.ignored_directories:
                prunes["ignored-directory"] += 1
            elif child.is_symlink():
                prunes["symlink"] += 1
            elif is_secret_shaped_path(child.relative_to(root).as_posix()) or (
                is_secret_shaped_path(name)
            ):
                prunes["sensitive-filename"] += 1
            else:
                kept.append(name)
        directory_names[:] = kept
        for name in sorted(file_names):
            if _manifest_kind_of(name) is None:
                continue
            candidate = current / name
            if candidate.is_symlink():
                prunes["symlink"] += 1
                continue
            relative = candidate.relative_to(root).as_posix()
            if is_secret_shaped_path(relative):
                prunes["sensitive-filename"] += 1
                continue
            candidates.append(relative)
    return sorted(candidates), prunes


def _run_channel(
    workspace: RepositoryWorkspace, budgets: MonorepoBudgets
) -> tuple[dict[str, str], set[str], dict[str, int], int]:
    """Enumerate and read the S2 channel under its count/byte budgets.

    Returns (texts, discovered paths, skip counts incl. prunes, read attempts).
    Failures keep the manifest discovered (enumeration hit anchors it); the
    text stays absent and the loss is carried by the channel skip dictionary.
    """

    candidates, prunes = _channel_walk(workspace)
    texts: dict[str, str] = {}
    failures: set[str] = set()
    skipped: dict[str, int] = {}
    attempts = 0
    consumed = 0
    for path in candidates:
        discovered = len(texts) + len(failures)
        if discovered >= budgets.max_metadata_manifests:
            skipped["metadata-manifest-limit"] = (
                len(candidates) - discovered
            )
            break
        attempts += 1
        try:
            text = workspace.read_text(path)
        except UnicodeDecodeError:
            failures.add(path)
            skipped["non-utf8"] = skipped.get("non-utf8", 0) + 1
            continue
        except (OSError, ValueError):
            failures.add(path)
            skipped["unreadable"] = skipped.get("unreadable", 0) + 1
            continue
        size = len(text.encode("utf-8"))
        if consumed + size > budgets.max_metadata_total_bytes:
            skipped["metadata-byte-limit"] = consumed + size - (
                budgets.max_metadata_total_bytes
            )
            break
        consumed += size
        texts[path] = text
    for key, count in prunes.items():
        if count:
            skipped[key] = count
    return texts, set(texts) | failures, skipped, attempts


def _is_collaboration_manifest(name: str, text: str) -> bool:
    """Closed workspace-collaboration semantics (section 5.1.1); unrecognized
    shapes fall back to a component manifest (conservative default)."""

    if name == "pyproject.toml":
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return False
        tool = data.get("tool")
        if not isinstance(tool, dict):
            return False
        uv = tool.get("uv")
        if isinstance(uv, dict):
            workspace = uv.get("workspace")
            if isinstance(workspace, dict) and workspace.get("members"):
                return True
        pdm = tool.get("pdm")
        if isinstance(pdm, dict) and pdm.get("workspace"):
            return True
        return False
    if name == "package.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return False
        return isinstance(data, dict) and bool(data.get("workspaces"))
    if name == "Cargo.toml":
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return False
        return "workspace" in data and "package" not in data
    return False


def _declared_dependency_names(name: str, text: str) -> set[str]:
    """Closed dependency-declaration parse (P4b): pyproject [project]
    dependencies plus requirements*.txt line-leading names."""

    names: set[str] = set()
    if name == "pyproject.toml":
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return names
        project = data.get("project")
        if not isinstance(project, dict):
            return names
        dependencies = project.get("dependencies")
        if not isinstance(dependencies, list):
            return names
        for item in dependencies:
            match = _DEPENDENCY_NAME_RE.match(str(item))
            if match is not None:
                names.add(match.group(0))
    elif _REQUIREMENTS_NAME_RE.match(name) is not None:
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "-")):
                continue
            match = _DEPENDENCY_NAME_RE.match(stripped)
            if match is not None:
                names.add(match.group(0))
    return names


# ---------------------------------------------------------------------------
# Discovery (sections 5.1.1-5.1.8)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _DiscoveryOutcome:
    """Internal shared discovery state for both public entry points."""

    components: tuple[ComponentInfo, ...]
    unassigned_files: tuple[str, ...]
    unassigned_file_count: int
    metadata_manifest_count: int
    metadata_channel_skipped: dict[str, int]
    manifests_discovered_count: int
    collaboration_manifest_count: int
    overflow_manifest_count: int
    gaps: tuple[tuple[str, str], ...]
    truncated: bool
    manifest_texts: dict[str, str]
    channel_paths: set[str]
    channel_read_attempts: int
    main_inventory: WorkspaceInventory
    owned_files: dict[str, list[str]]
    owned_py: dict[str, list[str]]


def _discover(
    workspace: RepositoryWorkspace,
    budgets: MonorepoBudgets,
    manifest_policy: str,
    meter: _ReadPhaseMeter | None = None,
) -> _DiscoveryOutcome:
    main = workspace.inventory()
    admitted = {item.path for item in main.files}

    s1_manifests = {
        path
        for path in admitted
        if _manifest_kind_of(path.rsplit("/", 1)[-1]) is not None
    }

    channel_texts: dict[str, str] = {}
    channel_skipped: dict[str, int] = {}
    channel_paths: set[str] = set()
    channel_attempts = 0
    if manifest_policy == MANIFEST_POLICY_METADATA_CHANNEL:
        if meter is not None:
            meter.phase = "channel"
        try:
            channel_texts, channel_paths, channel_skipped, channel_attempts = (
                _run_channel(workspace, budgets)
            )
        finally:
            if meter is not None:
                meter.phase = ""

    manifest_texts: dict[str, str] = dict(channel_texts)
    for path in channel_paths:
        if path not in manifest_texts:
            manifest_texts[path] = ""
    # S1-manifest read-back: reads the channel did not already perform.
    # Metering bucket (IR-03 opening-summary choice, constant within one
    # build): S8 metadata_channel_read_attempts -- the read-back is the
    # channel's complement (each discovered manifest is read exactly once by
    # channel-or-read-back), so the stage keeps its Packet meaning while S3
    # stays exactly the per-component Profile manifest reads.
    if meter is not None:
        meter.phase = "channel"
    try:
        for path in sorted(s1_manifests):
            if path in manifest_texts:
                continue
            try:
                manifest_texts[path] = workspace.read_text(path)
            except (OSError, ValueError, UnicodeDecodeError):
                manifest_texts[path] = ""
                channel_attempts += 1
    finally:
        if meter is not None:
            meter.phase = ""

    collaboration = 0
    rejected_anchors = 0
    per_anchor: dict[str, list[str]] = {}
    rejected_anchor_set: set[str] = set()
    anchor_probe_seen: set[str] = set()
    all_manifests = sorted(s1_manifests | channel_paths)
    for path in all_manifests:
        anchor = _anchor_of(path)
        if anchor not in anchor_probe_seen:
            anchor_probe_seen.add(anchor)
            basename = path.rsplit("/", 1)[-1]
            probe = f"{anchor}/{basename}" if anchor else basename
            if is_secret_shaped_path(probe):
                rejected_anchor_set.add(anchor)
                rejected_anchors += 1
        if anchor in rejected_anchor_set:
            continue
        if _is_collaboration_manifest(
            path.rsplit("/", 1)[-1], manifest_texts.get(path, "")
        ):
            collaboration += 1
            continue
        if anchor not in per_anchor:
            per_anchor[anchor] = []
        per_anchor[anchor].append(path)

    anchors_by_id = sorted(per_anchor, key=_component_id_of)
    truncated = len(anchors_by_id) > budgets.max_components
    overflow_paths: list[str] = []
    kept_anchors = anchors_by_id
    if truncated:
        for anchor in anchors_by_id[budgets.max_components:]:
            overflow_paths.extend(per_anchor[anchor])
        kept_anchors = anchors_by_id[: budgets.max_components]

    components: list[ComponentInfo] = []
    for anchor in kept_anchors:
        refs = tuple(
            ComponentManifestRef(
                path=path,
                manifest_kind=str(_manifest_kind_of(path.rsplit("/", 1)[-1])),
                source=(
                    COMPONENT_MANIFEST_SOURCE_INVENTORY
                    if path in s1_manifests
                    else COMPONENT_MANIFEST_SOURCE_METADATA_CHANNEL
                ),
            )
            for path in sorted(per_anchor[anchor])
        )
        components.append(
            ComponentInfo(
                component_id=_component_id_of(anchor),
                root_dir=anchor,
                manifests=refs,
                python_file_count=0,
                is_empty=True,
            )
        )

    kept_anchor_list = [component.root_dir for component in components]
    owned_files: dict[str, list[str]] = {anchor: [] for anchor in kept_anchor_list}
    owned_py: dict[str, list[str]] = {anchor: [] for anchor in kept_anchor_list}
    unassigned: list[str] = []
    for path in sorted(admitted):
        owner = _owner_anchor(path, kept_anchor_list)
        if owner is None:
            if path.endswith(".py"):
                unassigned.append(path)
            continue
        owned_files[owner].append(path)
        if path.endswith(".py"):
            owned_py[owner].append(path)

    for component in components:
        count = len(owned_py[component.root_dir])
        object.__setattr__(component, "python_file_count", count)
        object.__setattr__(component, "is_empty", count == 0)

    published = sum(len(refs) for component in components for refs in (component.manifests,))
    manifests_discovered = published + collaboration + len(overflow_paths)

    unassigned_public = [
        path for path in unassigned if not is_secret_shaped_path(path)
    ]

    gaps: list[tuple[str, str]] = []
    if rejected_anchors:
        gaps.append(
            (
                "INVENTORY_SKIPPED",
                _channel_gap_detail("sensitive-filename", rejected_anchors,
                                    COMPONENT_MANIFEST_SOURCE_INVENTORY),
            )
        )
    for key in _T6_LOSS_KEYS:
        count = main.skipped.get(key, 0)
        if count:
            gaps.append(
                ("INVENTORY_SKIPPED",
                 _channel_gap_detail(key, count,
                                     COMPONENT_MANIFEST_SOURCE_INVENTORY))
            )
    for key in _T8_LOSS_KEYS:
        count = channel_skipped.get(key, 0)
        if count:
            code = (
                "BUDGET_EXHAUSTED"
                if key in _CHANNEL_METADATA_BUDGET_REASONS
                else "INVENTORY_SKIPPED"
            )
            gaps.append(
                (code, _channel_gap_detail(key, count,
                                           COMPONENT_MANIFEST_SOURCE_METADATA_CHANNEL))
            )
    if truncated:
        gaps.append(
            (
                "BUDGET_EXHAUSTED",
                _budget_gap_detail(
                    "component-limit", len(anchors_by_id) - budgets.max_components
                ),
            )
        )

    return _DiscoveryOutcome(
        components=tuple(components),
        unassigned_files=tuple(unassigned_public),
        unassigned_file_count=len(unassigned),
        metadata_manifest_count=len(channel_paths),
        metadata_channel_skipped=dict(sorted(channel_skipped.items())),
        manifests_discovered_count=manifests_discovered,
        collaboration_manifest_count=collaboration,
        overflow_manifest_count=len(overflow_paths),
        gaps=tuple(sorted(set(gaps))),
        truncated=truncated,
        manifest_texts=manifest_texts,
        channel_paths=channel_paths,
        channel_read_attempts=channel_attempts,
        main_inventory=main,
        owned_files=owned_files,
        owned_py=owned_py,
    )


def detect_components(
    workspace: RepositoryWorkspace,
    *,
    budgets: MonorepoBudgets | None = None,
    manifest_policy: str = MANIFEST_POLICY_METADATA_CHANNEL,
) -> ComponentDiscoveryResult:
    """Discover monorepo components over the two separated input sets."""

    if not isinstance(workspace, RepositoryWorkspace):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if budgets is not None and not isinstance(budgets, MonorepoBudgets):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if manifest_policy not in MANIFEST_POLICIES:
        raise ValueError(f"unknown manifest policy: {manifest_policy}")
    outcome = _discover(
        workspace,
        budgets if budgets is not None else MonorepoBudgets(),
        manifest_policy,
    )
    return ComponentDiscoveryResult(
        components=outcome.components,
        unassigned_files=outcome.unassigned_files,
        unassigned_file_count=outcome.unassigned_file_count,
        metadata_manifest_count=outcome.metadata_manifest_count,
        metadata_channel_skipped=outcome.metadata_channel_skipped,
        manifests_discovered_count=outcome.manifests_discovered_count,
        collaboration_manifest_count=outcome.collaboration_manifest_count,
        overflow_manifest_count=outcome.overflow_manifest_count,
        coverage_gaps=tuple(_make_gap(*pair) for pair in outcome.gaps),
        truncated=outcome.truncated,
    )


# ---------------------------------------------------------------------------
# Module roots, name table, import resolution (sections 5.3.1-5.3.5)
# ---------------------------------------------------------------------------


def _hatch_common_parent(anchor: str, packages: object) -> str | None:
    if not isinstance(packages, list) or not packages:
        return None
    directories: list[list[str]] = []
    for item in packages:
        if not isinstance(item, str) or not item:
            continue
        parts = [part for part in item.strip("/").split("/") if part]
        if not parts:
            continue
        directories.append(parts[:-1] if len(parts) > 1 else [])
    if not directories:
        return None
    common: list[str] = []
    for index in range(min(len(parts) for parts in directories)):
        segment = directories[0][index]
        if all(parts[index] == segment for parts in directories):
            common.append(segment)
        else:
            break
    internal = "/".join(common)
    if not internal:
        return None
    return f"{anchor}/{internal}" if anchor else internal


def _module_roots(
    component: ComponentInfo,
    all_repo_files: set[str],
    manifest_texts: Mapping[str, str],
) -> list[str]:
    """Module-root set R(C) (section 5.3.2): component root, build-config
    declared directories (closed key set) and content-evidenced ``src``."""

    anchor = component.root_dir
    roots = [anchor]
    for ref in component.manifests:
        if not ref.path.endswith("pyproject.toml"):
            continue
        try:
            data = tomllib.loads(manifest_texts.get(ref.path, ""))
        except tomllib.TOMLDecodeError:
            continue
        tool = data.get("tool")
        if not isinstance(tool, dict):
            continue
        values: list[str] = []
        setuptools = tool.get("setuptools")
        if isinstance(setuptools, dict):
            packages = setuptools.get("packages")
            if isinstance(packages, dict):
                find = packages.get("find")
                if isinstance(find, dict):
                    where = find.get("where", [])
                    values.extend([where] if isinstance(where, str) else where)
            package_dir = setuptools.get("package-dir")
            if isinstance(package_dir, dict):
                for value in package_dir.values():
                    values.extend([value] if isinstance(value, str) else value)
        hatch_root: str | None = None
        hatch = tool.get("hatch")
        if isinstance(hatch, dict):
            build = hatch.get("build")
            if isinstance(build, dict):
                targets = build.get("targets")
                if isinstance(targets, dict):
                    wheel = targets.get("wheel")
                    if isinstance(wheel, dict):
                        hatch_root = _hatch_common_parent(
                            anchor, wheel.get("packages")
                        )
        for value in values:
            if not isinstance(value, str):
                continue
            internal = value.strip("/")
            candidate = f"{anchor}/{internal}" if anchor else internal
            if candidate and candidate not in roots:
                roots.append(candidate)
        if hatch_root is not None and hatch_root not in roots:
            roots.append(hatch_root)
    src = f"{anchor}/src" if anchor else "src"
    depth = src.count("/") + 1
    direct_py = any(
        path.startswith(src + "/")
        and path.endswith(".py")
        and path.count("/") == depth
        for path in all_repo_files
    )
    direct_pkg = any(
        path.startswith(src + "/")
        and path.endswith("__init__.py")
        and path.count("/") == depth + 1
        for path in all_repo_files
    )
    if (direct_py or direct_pkg) and src not in roots:
        roots.append(src)
    return roots


def _build_name_table(
    components: tuple[ComponentInfo, ...],
    all_repo_files: set[str],
    manifest_texts: Mapping[str, str],
) -> dict[str, set[str]]:
    """Top-level name table per component (regular + namespace packages)."""

    directories: set[str] = set()
    for path in all_repo_files:
        parts = path.split("/")
        for index in range(1, len(parts)):
            directories.add("/".join(parts[:index]))
    table: dict[str, set[str]] = {}
    for component in components:
        names: set[str] = set()
        for root in _module_roots(component, all_repo_files, manifest_texts):
            prefix = root + "/" if root else ""
            for path in all_repo_files:
                if not path.startswith(prefix):
                    continue
                rest = path[len(prefix):]
                if "/" in rest:
                    continue
                if path.endswith(".py") and not path.endswith("__init__.py"):
                    names.add(rest[: -len(".py")])
            for directory in directories:
                if not directory.startswith(prefix):
                    continue
                rest = directory[len(prefix):]
                if rest and "/" not in rest:
                    names.add(rest)
        table[component.component_id] = names
    return table


@dataclass
class _EdgeDraft:
    source_component_id: str
    target_component_id: str | None
    status: str
    imported_name: str
    evidence: list[tuple[str, int, str]]


def _resolve_absolute_import(
    component_id: str,
    top_level: str,
    line: int,
    path: str,
    own_names: set[str],
    name_table: Mapping[str, set[str]],
    declared: set[str],
    edges: dict[tuple[str, str, str, str], _EdgeDraft],
    unknowns: dict[tuple[str, str], int],
) -> None:
    """Closed edge-derivation rules P1-P5 (section 5.3.3), self first."""

    if top_level in own_names:
        return
    definers = {
        component_id_
        for component_id_, names in name_table.items()
        if top_level in names
    }
    if len(definers) == 1:
        target = next(iter(definers))
        key = (component_id, COMPONENT_EDGE_STATUS_RESOLVED, target, top_level)
        draft = edges.setdefault(
            key,
            _EdgeDraft(component_id, target, COMPONENT_EDGE_STATUS_RESOLVED,
                       top_level, []),
        )
        draft.evidence.append((path, line, top_level))
        return
    if len(definers) >= 2:
        key = (component_id, COMPONENT_EDGE_STATUS_AMBIGUOUS, "", top_level)
        draft = edges.setdefault(
            key,
            _EdgeDraft(component_id, None, COMPONENT_EDGE_STATUS_AMBIGUOUS,
                       top_level, []),
        )
        draft.evidence.append((path, line, top_level))
        return
    if top_level in _STDLIB_TOP_LEVEL_NAMES or top_level in declared:
        return
    unknowns[(component_id, top_level)] = (
        unknowns.get((component_id, top_level), 0) + 1
    )


def _resolve_relative_import(
    component_id: str,
    anchor: str,
    path: str,
    node: ast.ImportFrom,
    dotted: str,
    all_repo_files: set[str],
    components: tuple[ComponentInfo, ...],
    edges: dict[tuple[str, str, str, str], _EdgeDraft],
) -> None:
    """Relative import resolution with package/file context (section 5.3.3)."""

    def emit(target: str | None, status: str) -> None:
        key = (component_id, status, target or "", dotted)
        draft = edges.setdefault(
            key, _EdgeDraft(component_id, target, status, dotted, [])
        )
        draft.evidence.append((path, node.lineno, dotted))

    file_dir = path.rsplit("/", 1)[0] if "/" in path else ""
    base_parts = file_dir.split("/") if file_dir else []
    up = node.level - 1
    if up > len(base_parts):
        emit(None, COMPONENT_EDGE_STATUS_UNRESOLVED)
        return
    module_parts = node.module.split(".") if node.module else []
    target = "/".join(base_parts[: len(base_parts) - up] + module_parts)
    exists = (
        f"{target}.py" in all_repo_files or f"{target}/__init__.py" in all_repo_files
    )
    if not exists:
        emit(None, COMPONENT_EDGE_STATUS_UNRESOLVED)
        return
    if _in_subtree(target, anchor):
        return
    best: str | None = None
    for component in components:
        other = component.root_dir
        if other == anchor:
            continue
        if _in_subtree(target, other) and (
            best is None or other.count("/") > best.count("/")
        ):
            best = other
    if best is not None:
        emit(_component_id_of(best), COMPONENT_EDGE_STATUS_RESOLVED)
        return
    if any(component.root_dir == "" for component in components):
        return
    emit(None, COMPONENT_EDGE_STATUS_UNRESOLVED)


def _scan_imports(
    workspace: RepositoryWorkspace,
    owned_py: Mapping[str, list[str]],
    components: tuple[ComponentInfo, ...],
    name_table: Mapping[str, set[str]],
    manifest_texts: Mapping[str, str],
    all_repo_files: set[str],
) -> tuple[
    list[tuple[tuple[str, str, str, str], _EdgeDraft]],
    list[tuple[tuple[str, str], int]],
    dict[str, dict[str, int]],
]:
    """Graph-level AST scan over every owned ``.py`` (repo-level coordinates)."""

    edges: dict[tuple[str, str, str, str], _EdgeDraft] = {}
    unknowns: dict[tuple[str, str], int] = {}
    summaries: dict[str, dict[str, int]] = {
        component.component_id: {
            "parse_error_file_count": 0,
            "read_failure_file_count": 0,
            "dynamic_import_site_count": 0,
            "unknown_truncated_count": 0,
            "manifest_parse_failure_count": 0,
        }
        for component in components
    }
    for component in sorted(components, key=lambda item: item.component_id):
        component_id = component.component_id
        declared: set[str] = set()
        for ref in component.manifests:
            text = manifest_texts.get(ref.path, "")
            declared |= _declared_dependency_names(
                ref.path.rsplit("/", 1)[-1], text
            )
            if ref.path.endswith(".toml") and text:
                try:
                    tomllib.loads(text)
                except tomllib.TOMLDecodeError:
                    summaries[component_id]["manifest_parse_failure_count"] += 1
        own_names = name_table.get(component_id, set())
        for path in sorted(owned_py.get(component.root_dir, [])):
            try:
                text = workspace.read_text(path)
            except (OSError, ValueError, UnicodeDecodeError):
                summaries[component_id]["read_failure_file_count"] += 1
                continue
            try:
                tree = ast.parse(text)
            except SyntaxError:
                summaries[component_id]["parse_error_file_count"] += 1
                continue
            if is_secret_shaped_path(path):
                # Admission-filtered path: counters may grow, but no import
                # evidence from this file ever reaches a public surface.
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    callee = (
                        func.id
                        if isinstance(func, ast.Name)
                        else func.attr
                        if isinstance(func, ast.Attribute)
                        else ""
                    )
                    if callee in ("import_module", "__import__"):
                        summaries[component_id]["dynamic_import_site_count"] += 1
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        _resolve_absolute_import(
                            component_id,
                            alias.name.split(".")[0],
                            node.lineno,
                            path,
                            own_names,
                            name_table,
                            declared,
                            edges,
                            unknowns,
                        )
                elif isinstance(node, ast.ImportFrom):
                    dotted = "." * node.level + (node.module or "")
                    if node.level == 0 and node.module:
                        _resolve_absolute_import(
                            component_id,
                            node.module.split(".")[0],
                            node.lineno,
                            path,
                            own_names,
                            name_table,
                            declared,
                            edges,
                            unknowns,
                        )
                    else:
                        _resolve_relative_import(
                            component_id,
                            component.root_dir,
                            path,
                            node,
                            dotted,
                            all_repo_files,
                            components,
                            edges,
                        )
    edge_items = [(key, edges[key]) for key in sorted(edges)]
    unknown_items = [(key, unknowns[key]) for key in sorted(unknowns)]
    return edge_items, unknown_items, summaries


# ---------------------------------------------------------------------------
# Real-read metering (CL-04 / IR-03): main-workspace phase meter and the
# per-component metered view
# ---------------------------------------------------------------------------


class _ReadPhaseMeter:
    """Build-local real-read meter for the caller's main workspace (IR-03).

    Fires at the workspace's actual read points: inventory reads always
    attribute to S0; text reads attribute to the current phase (S8 channel
    or read-back, S7 graph AST). The meter is created per build, attached
    for the discovery + AST phases only, and detached with the previously
    saved probes restored (no residue on the caller's instance, no state
    shared between adjacent or nested builds).
    """

    __slots__ = (
        "phase",
        "s0_attempts",
        "s0_bytes",
        "s7_attempts",
        "s7_bytes",
        "s8_attempts",
        "s8_bytes",
        "_workspace",
        "_saved",
    )

    def __init__(self) -> None:
        self.phase = ""
        self.s0_attempts = 0
        self.s0_bytes = 0
        self.s7_attempts = 0
        self.s7_bytes = 0
        self.s8_attempts = 0
        self.s8_bytes = 0
        self._workspace: RepositoryWorkspace | None = None
        self._saved: tuple[Any, Any] = (None, None)

    def inventory_read(self, size: int) -> None:
        self.s0_attempts += 1
        self.s0_bytes += size

    def text_read(self, size: int) -> None:
        if self.phase == "channel":
            self.s8_attempts += 1
            self.s8_bytes += size
        elif self.phase == "ast":
            self.s7_attempts += 1
            self.s7_bytes += size
        else:
            raise RuntimeError(
                "main-workspace text read outside an attributed IO stage"
            )

    def attach(self, workspace: RepositoryWorkspace) -> None:
        """Enable observation on ``workspace`` for the duration of one build."""

        self._workspace = workspace
        self._saved = (
            workspace._inventory_read_probe,
            workspace._text_read_probe,
        )
        workspace._inventory_read_probe = self.inventory_read
        workspace._text_read_probe = self.text_read

    def detach(self) -> None:
        """Restore the caller's workspace exactly as it was attached."""

        workspace = self._workspace
        if workspace is None:
            return
        workspace._inventory_read_probe, workspace._text_read_probe = self._saved
        self._workspace = None
        self._saved = (None, None)


class _MeteredWorkspace(RepositoryWorkspace):
    """Component workspace metering real read attempts and successful bytes.

    The restricted view itself is the real W-1 behaviour (base-class keyword
    parameters); this subclass only observes the reads the frozen layers
    perform at the real read points (inventory ``read_bytes`` and
    ``read_text``): pre-read rejections never count as attempts, post-read
    failures (byte-cap rejection, decode failure) still meter their bytes,
    and every counter lives on this throwaway instance.
    """

    def __init__(
        self,
        root: Any,
        *,
        max_files: int,
        max_file_bytes: int,
        max_total_bytes: int,
        extensions: Any,
        ignored_directories: Any,
        admitted_files: Any,
        metadata_files: Any,
        manifest_set: frozenset[str],
    ) -> None:
        super().__init__(
            root,
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
            extensions=extensions,
            ignored_directories=ignored_directories,
            admitted_files=admitted_files,
            metadata_files=metadata_files,
        )
        self._manifest_set = manifest_set
        self.rescan_attempts = 0
        self.manifest_read_attempts = 0
        self.success_bytes = 0
        self._inventory_reads = 0
        self._text_reads = 0
        self._read_bytes_seen = 0
        self._inventory_read_probe = self._observe_inventory_read
        self._text_read_probe = self._observe_text_read

    def _observe_inventory_read(self, size: int) -> None:
        self._inventory_reads += 1
        self._read_bytes_seen += size

    def _observe_text_read(self, size: int) -> None:
        self._text_reads += 1
        self._read_bytes_seen += size

    @staticmethod
    def _posix(relative_path: object) -> str:
        return str(relative_path).replace("\\", "/")

    def inventory(self) -> WorkspaceInventory:
        reads_before = self._inventory_reads + self._text_reads
        bytes_before = self._read_bytes_seen
        result = super().inventory()
        self.rescan_attempts += (
            self._inventory_reads + self._text_reads
        ) - reads_before
        self.success_bytes += self._read_bytes_seen - bytes_before
        return result

    def read_text(self, relative_path: object) -> str:
        posix = self._posix(relative_path)
        manifest_read = posix in self._manifest_set
        reads_before = self._inventory_reads + self._text_reads
        bytes_before = self._read_bytes_seen
        try:
            text = super().read_text(relative_path)
        finally:
            real_reads = (
                self._inventory_reads + self._text_reads
            ) - reads_before
            if manifest_read:
                self.manifest_read_attempts += real_reads
            else:
                self.rescan_attempts += real_reads
            self.success_bytes += self._read_bytes_seen - bytes_before
        return text


class _PoolExhausted(Exception):
    """Internal signal: the aggregate pool cannot fund this attempt."""


class _AggregatePoolGuard:
    """Client-side guard enforcing the effective aggregate token pools.

    Estimates follow the frozen calibre (ceil(chars/4) prompts, per-candidate
    constant output tokens); scheduled attempts pre-deduct and are never
    refunded; insufficient attempts are not scheduled (the component falls
    back to its deterministic no-client form).
    """

    def __init__(self, inner: SemanticModelClient, pools: list[int]) -> None:
        self._inner = inner
        self._pools = pools
        self.scheduled_calls = 0
        self.blocked_attempts = 0

    def complete(self, prompt: str, *, timeout_seconds: int) -> str:
        batch = max(1, prompt.count(_DESCRIPTOR_KEY))
        prompt_estimate = max(1, (len(prompt) + 3) // 4)
        output_estimate = _PER_CANDIDATE_OUTPUT_TOKENS * batch
        if (
            self._pools[0] < prompt_estimate
            or self._pools[1] < output_estimate
            or self._pools[2] < prompt_estimate + output_estimate
        ):
            self.blocked_attempts += 1
            raise _PoolExhausted(
                "aggregate token pool exhausted before scheduling"
            )
        self._pools[0] -= prompt_estimate
        self._pools[1] -= output_estimate
        self._pools[2] -= prompt_estimate + output_estimate
        self.scheduled_calls += 1
        return self._inner.complete(prompt, timeout_seconds=timeout_seconds)


# ---------------------------------------------------------------------------
# build_monorepo_profile (sections 5.2/5.4.4)
# ---------------------------------------------------------------------------


def _effective_pools(
    budgets: MonorepoBudgets, caller: SemanticOptions
) -> tuple[int, int, int]:
    requested = (
        budgets.aggregate_max_prompt_tokens,
        budgets.aggregate_max_output_tokens,
        budgets.aggregate_max_total_tokens,
    )
    caller_values = (
        caller.budgets.max_prompt_tokens_estimate,
        caller.budgets.max_output_tokens_estimate,
        caller.budgets.max_total_tokens_estimate,
    )
    return tuple(  # type: ignore[return-value]
        min(pair) for pair in zip(requested, caller_values, strict=True)
    )


def _effective_budgets_dict(
    budgets: MonorepoBudgets, pools: tuple[int, int, int]
) -> dict[str, int]:
    return {
        "max_components": budgets.max_components,
        "max_edges": budgets.max_edges,
        "max_edge_evidence": budgets.max_edge_evidence,
        "max_unassigned_files": budgets.max_unassigned_files,
        "max_total_model_calls": budgets.max_total_model_calls,
        "aggregate_max_prompt_tokens": pools[0],
        "aggregate_max_output_tokens": pools[1],
        "aggregate_max_total_tokens": pools[2],
        "max_metadata_manifests": budgets.max_metadata_manifests,
        "max_metadata_total_bytes": budgets.max_metadata_total_bytes,
    }


def build_monorepo_profile(
    workspace: RepositoryWorkspace,
    *,
    tenant_id: str,
    task_id: str,
    workflow_id: str,
    stage_attempt_id: str,
    artifact_id: str,
    repository_snapshot_digest: str,
    policy_digest: str = _SENTINEL_EMPTY_DIGEST,
    toolchain_digest: str = _SENTINEL_EMPTY_DIGEST,
    profile_options: ProfileInventoryOptions | None = None,
    ram_budgets: RamBudgets | None = None,
    semantic_options: SemanticOptions | None = None,
    monorepo_budgets: MonorepoBudgets | None = None,
    manifest_policy: str = MANIFEST_POLICY_METADATA_CHANNEL,
    model_client: SemanticModelClient | None = None,
) -> MonorepoProfileBuildResult:
    """Build the whole monorepo: discovery, per-component chain, graph."""

    if not isinstance(workspace, RepositoryWorkspace):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    for identifier in (
        tenant_id,
        task_id,
        workflow_id,
        stage_attempt_id,
        artifact_id,
    ):
        if not isinstance(identifier, str):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if (
        not isinstance(repository_snapshot_digest, str)
        or not repository_snapshot_digest
    ):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE)
    if policy_digest is not None and not isinstance(policy_digest, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if toolchain_digest is not None and not isinstance(toolchain_digest, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if profile_options is not None and not isinstance(
        profile_options, ProfileInventoryOptions
    ):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if ram_budgets is not None and not isinstance(ram_budgets, RamBudgets):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if semantic_options is not None and not isinstance(
        semantic_options, SemanticOptions
    ):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if monorepo_budgets is not None and not isinstance(
        monorepo_budgets, MonorepoBudgets
    ):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if manifest_policy not in MANIFEST_POLICIES:
        raise ValueError(f"unknown manifest policy: {manifest_policy}")

    budgets = monorepo_budgets if monorepo_budgets is not None else MonorepoBudgets()
    meter = _ReadPhaseMeter()
    meter.attach(workspace)
    try:
        outcome = _discover(workspace, budgets, manifest_policy, meter)
        admitted = {item.path for item in outcome.main_inventory.files}
        all_repo_files = admitted | outcome.channel_paths
        name_table = _build_name_table(
            outcome.components, all_repo_files, outcome.manifest_texts
        )
        meter.phase = "ast"
        edge_items, unknown_items, summaries = _scan_imports(
            workspace,
            outcome.owned_py,
            outcome.components,
            name_table,
            outcome.manifest_texts,
            all_repo_files,
        )
        meter.phase = ""
    finally:
        meter.detach()

    gaps: list[tuple[str, str]] = list(outcome.gaps)

    for _key, draft in edge_items:
        evidence = sorted(set(draft.evidence))
        if len(evidence) > budgets.max_edge_evidence:
            gaps.append(
                (
                    "BUDGET_EXHAUSTED",
                    _budget_gap_detail(
                        "edge-evidence-limit", len(evidence) - budgets.max_edge_evidence
                    ),
                )
            )
            evidence = evidence[: budgets.max_edge_evidence]
        draft.evidence = evidence

    unknown_by_component: dict[str, int] = {}
    if len(edge_items) + len(unknown_items) > budgets.max_edges:
        kept_edges = edge_items[: budgets.max_edges]
        kept_unknowns_full = edge_items + unknown_items
        kept_unknowns = kept_unknowns_full[budgets.max_edges:]
        kept_unknowns = [
            item for item in kept_unknowns if item in unknown_items
        ]
        dropped_edges = len(edge_items) - len(kept_edges)
        if dropped_edges:
            gaps.append(
                ("BUDGET_EXHAUSTED",
                 _budget_gap_detail("edge-limit", dropped_edges))
            )
        if kept_unknowns:
            # IR-02 (Packet v5.1 section 5.3.4): count DROPPED RECORDS per
            # component, not import sites -- sum over scan summaries must
            # equal the unknown-import-limit gap count (V7 balance); the
            # kept records' UnknownImportRecord.count keeps its site
            # semantics.
            for (_source, _name), _count in kept_unknowns:
                unknown_by_component[_source] = (
                    unknown_by_component.get(_source, 0) + 1
                )
            gaps.append(
                (
                    "BUDGET_EXHAUSTED",
                    _budget_gap_detail("unknown-import-limit", len(kept_unknowns)),
                )
            )
            for source, count in unknown_by_component.items():
                summaries[source]["unknown_truncated_count"] += count
        unknown_items = [
            item
            for item in unknown_items
            if item not in set(kept_unknowns)
        ]
        edge_items = kept_edges

    unassigned_files = list(outcome.unassigned_files)
    unassigned_count = outcome.unassigned_file_count
    if len(unassigned_files) > budgets.max_unassigned_files:
        gaps.append(
            (
                "BUDGET_EXHAUSTED",
                _budget_gap_detail(
                    "unassigned-file-limit",
                    len(unassigned_files) - budgets.max_unassigned_files,
                ),
            )
        )
        unassigned_files = unassigned_files[: budgets.max_unassigned_files]

    base_options = (
        semantic_options if semantic_options is not None else SemanticOptions()
    )
    pools = _effective_pools(budgets, base_options)
    model_active = model_client is not None and base_options.model_id != "unset"
    remaining_calls = budgets.max_total_model_calls
    # IR-01 (Packet v5.1 section 5.4.4 single scheduling rule): ONE guard
    # for the whole build -- the effective min(requested, caller) pools are
    # shared across every component; per-attempt estimates are checked
    # against all three remainders, pre-deducted and never refunded
    # (failures and timeouts consume), unfunded attempts are not scheduled.
    shared_guard = (
        _AggregatePoolGuard(model_client, list(pools)) if model_active else None
    )
    call_degraded_components = 0
    blocked_attempts_total = 0

    effective_profile = (
        profile_options.budgets if profile_options is not None else ProfileBudgets()
    )
    effective_ram = ram_budgets if ram_budgets is not None else RamBudgets()

    builds: list[ComponentBuildResult] = []
    unbuilt: list[UnbuiltComponentRecord] = []
    component_infos: list[ComponentInfo] = []
    rescan_attempts = 0
    manifest_attempts = 0
    success_bytes = 0

    for component in outcome.components:
        anchor = component.root_dir
        slice_internal = sorted(
            _internal_path(anchor, path) for path in outcome.owned_files[anchor]
        )
        metadata_internal = sorted(
            {_internal_path(anchor, ref.path) for ref in component.manifests}
        )
        try:
            component_ws = _MeteredWorkspace(
                workspace.root if anchor == "" else workspace.root / anchor,
                max_files=workspace.max_files,
                max_file_bytes=workspace.max_file_bytes,
                max_total_bytes=workspace.max_total_bytes,
                extensions=workspace.extensions,
                ignored_directories=workspace.ignored_directories,
                admitted_files=slice_internal,
                metadata_files=metadata_internal,
                manifest_set=frozenset(metadata_internal),
            )
            precheck = component_ws.inventory()
            mapped = {
                f"{anchor}/{item.path}" if anchor else item.path
                for item in precheck.files
            }
            if mapped != set(outcome.owned_files[anchor]):
                unbuilt.append(
                    UnbuiltComponentRecord(
                        component_id=component.component_id,
                        reason=UNBUILT_REASON_CAP_DIVERGENCE,
                    )
                )
                component_infos.append(component)
                rescan_attempts += component_ws.rescan_attempts
                manifest_attempts += component_ws.manifest_read_attempts
                success_bytes += component_ws.success_bytes
                continue
        except (OSError, ValueError):
            unbuilt.append(
                UnbuiltComponentRecord(
                    component_id=component.component_id,
                    reason=UNBUILT_REASON_VIEW_UNFORMABLE,
                )
            )
            component_infos.append(component)
            continue

        profile_result = build_repository_profile(
            component_ws,
            tenant_id=tenant_id,
            task_id=task_id,
            workflow_id=workflow_id,
            stage_attempt_id=stage_attempt_id,
            artifact_id=artifact_id,
            repository_snapshot_digest=repository_snapshot_digest,
            producer=_COMPONENT_PRODUCER,
            policy_digest=policy_digest,
            toolchain_digest=toolchain_digest,
            options=profile_options,
        )
        ram_result = build_python_ram_facts(component_ws, budgets=effective_ram)

        effective_options = base_options
        if model_active and remaining_calls > 0:
            allowed = min(base_options.budgets.max_llm_calls, remaining_calls)
            stage_options = replace(
                base_options,
                budgets=replace(base_options.budgets, max_llm_calls=allowed),
            )
            scheduled_before = shared_guard.scheduled_calls
            blocked_before = shared_guard.blocked_attempts
            semantic_result = build_semantic_top_n(
                ram_result.facts, options=stage_options,
                model_client=shared_guard,
            )
            remaining_calls -= (
                shared_guard.scheduled_calls - scheduled_before
            )
            blocked_attempts_total += (
                shared_guard.blocked_attempts - blocked_before
            )
            effective_options = stage_options
        elif model_active:
            semantic_result = build_semantic_top_n(
                ram_result.facts, options=base_options
            )
            call_degraded_components += 1
        else:
            semantic_result = build_semantic_top_n(
                ram_result.facts, options=base_options
            )

        ram_wire = ram_wire_payload(
            ram_result,
            semantic_result,
            profile_budgets=effective_profile,
            ram_budgets=effective_ram,
            semantic_options=effective_options,
        )
        digests = ComponentArtifactDigests(
            profile_content_digest=profile_result.envelope.content_digest,
            ram_facts_digest=ram_facts_digest(ram_result.facts),
            semantic_result_digest=semantic_result_digest(
                semantic_result,
                input_facts_digest=ram_facts_digest(ram_result.facts),
            ),
        )
        built_info = replace(component, artifact_digests=digests)
        component_infos.append(built_info)
        builds.append(
            ComponentBuildResult(
                component=built_info,
                profile_result=profile_result,
                ram_result=ram_result,
                semantic_result=semantic_result,
                ram_wire=ram_wire,
                effective_profile_budgets=effective_profile,
                effective_ram_budgets=effective_ram,
                effective_semantic_options=effective_options,
            )
        )
        rescan_attempts += component_ws.rescan_attempts
        manifest_attempts += component_ws.manifest_read_attempts
        success_bytes += component_ws.success_bytes

    if call_degraded_components:
        gaps.append(
            (
                "BUDGET_EXHAUSTED",
                _budget_gap_detail(
                    "aggregate-model-call-limit", call_degraded_components
                ),
            )
        )
    if blocked_attempts_total:
        gaps.append(
            (
                "BUDGET_EXHAUSTED",
                _budget_gap_detail(
                    "aggregate-token-pool-limit", blocked_attempts_total
                ),
            )
        )

    t2 = any(
        gap.gap_code == "BUDGET_EXHAUSTED"
        and gap.detail.startswith("reason=python-file-limit")
        for build in builds
        for gap in build.ram_result.facts.coverage_gaps
    )
    t3 = any(
        code == "BUDGET_EXHAUSTED"
        and detail.startswith(("reason=edge-limit", "reason=unknown-import-limit"))
        for code, detail in gaps
    )
    t4 = any(
        summary["parse_error_file_count"] > 0
        or summary["manifest_parse_failure_count"] > 0
        for summary in summaries.values()
    )
    t5 = any(
        summary["read_failure_file_count"] > 0 for summary in summaries.values()
    )
    t6 = outcome.main_inventory.truncated or any(
        outcome.main_inventory.skipped.get(key, 0) > 0 for key in _T6_LOSS_KEYS
    )
    t7 = bool(unbuilt)
    t8 = any(
        outcome.metadata_channel_skipped.get(key, 0) > 0 for key in _T8_LOSS_KEYS
    )
    dependencies_complete = not (
        outcome.truncated or t2 or t3 or t4 or t5 or t6 or t7 or t8
    )

    ordered_infos = sorted(component_infos, key=lambda item: item.component_id)
    scan_summaries = tuple(
        ComponentScanSummary(
            component_id=component.component_id,
            **summaries[component.component_id],
        )
        for component in ordered_infos
    )
    graph = ComponentGraph(
        components=tuple(ordered_infos),
        edges=tuple(
            ComponentEdge(
                source_component_id=draft.source_component_id,
                target_component_id=draft.target_component_id,
                status=draft.status,
                imported_name=draft.imported_name,
                evidence=tuple(
                    EdgeEvidence(path=item[0], line=item[1], imported_name=item[2])
                    for item in draft.evidence
                ),
            )
            for _key, draft in edge_items
        ),
        unassigned_files=tuple(unassigned_files),
        unassigned_file_count=unassigned_count,
        unknown_imports=tuple(
            UnknownImportRecord(
                source_component_id=key[0], imported_name=key[1], count=count
            )
            for key, count in unknown_items
        ),
        scan_summaries=scan_summaries,
        unbuilt_components=tuple(unbuilt),
        dependencies_complete=dependencies_complete,
        coverage_gaps=tuple(
            _make_gap(code, detail) for code, detail in sorted(set(gaps))
        ),
        manifests_discovered_count=outcome.manifests_discovered_count,
        metadata_manifest_count=outcome.metadata_manifest_count,
        collaboration_manifest_count=outcome.collaboration_manifest_count,
        overflow_manifest_count=outcome.overflow_manifest_count,
    )

    metering = ResourceMetering(
        # IR-03 (Packet v5.1 section 5.4.4-IO): real read attempts and
        # successful bytes over the nine IO stages, observed at the actual
        # read points (never discovered/candidate/kept-set sizes), including
        # work that later caps reject; failed attempts count 0 bytes.
        main_inventory_read_attempts=meter.s0_attempts,
        component_rescan_read_attempts=rescan_attempts,
        profile_manifest_read_attempts=manifest_attempts,
        ast_read_attempts=meter.s7_attempts,
        metadata_channel_read_attempts=meter.s8_attempts,
        read_success_bytes=(
            success_bytes + meter.s0_bytes + meter.s7_bytes + meter.s8_bytes
        ),
    )

    discovery = ComponentDiscoveryResult(
        components=outcome.components,
        unassigned_files=tuple(unassigned_files),
        unassigned_file_count=unassigned_count,
        metadata_manifest_count=outcome.metadata_manifest_count,
        metadata_channel_skipped=outcome.metadata_channel_skipped,
        manifests_discovered_count=outcome.manifests_discovered_count,
        collaboration_manifest_count=outcome.collaboration_manifest_count,
        overflow_manifest_count=outcome.overflow_manifest_count,
        coverage_gaps=tuple(_make_gap(*pair) for pair in outcome.gaps),
        truncated=outcome.truncated,
    )

    result = MonorepoProfileBuildResult(
        discovery=discovery,
        per_component=tuple(builds),
        graph=graph,
        metering=metering,
    )
    object.__setattr__(
        result, "_effective_monorepo_budgets", _effective_budgets_dict(budgets, pools)
    )
    return result


# ---------------------------------------------------------------------------
# canonical projection, digest, payload, schema (sections 5.4.5-5.4.7)
# ---------------------------------------------------------------------------

_SCAN_COUNT_FIELDS: Final[tuple[str, ...]] = (
    "parse_error_file_count",
    "read_failure_file_count",
    "dynamic_import_site_count",
    "unknown_truncated_count",
    "manifest_parse_failure_count",
)


def canonical_dict_from_graph(graph: ComponentGraph) -> dict[str, Any]:
    """Project a graph onto the frozen canonical dictionary (section 5.4.5)."""

    return {
        "components": [
            {
                "component_id": item.component_id,
                "root_dir": item.root_dir,
                "manifests": [
                    {
                        "path": ref.path,
                        "kind": ref.manifest_kind,
                        "source": ref.source,
                    }
                    for ref in item.manifests
                ],
                "python_file_count": item.python_file_count,
                "is_empty": item.is_empty,
                "artifact_digests": (
                    None
                    if item.artifact_digests is None
                    else {
                        "profile_content_digest": (
                            item.artifact_digests.profile_content_digest
                        ),
                        "ram_facts_digest": item.artifact_digests.ram_facts_digest,
                        "semantic_result_digest": (
                            item.artifact_digests.semantic_result_digest
                        ),
                    }
                ),
            }
            for item in graph.components
        ],
        "edges": [
            {
                "source_component_id": edge.source_component_id,
                "target_component_id": edge.target_component_id,
                "status": edge.status,
                "imported_name": edge.imported_name,
                "evidence": [
                    {
                        "path": item.path,
                        "line": item.line,
                        "imported_name": item.imported_name,
                    }
                    for item in edge.evidence
                ],
            }
            for edge in graph.edges
        ],
        "unknown_imports": [
            {
                "source_component_id": item.source_component_id,
                "imported_name": item.imported_name,
                "count": item.count,
            }
            for item in graph.unknown_imports
        ],
        "scan_summaries": [
            {
                "component_id": item.component_id,
                **{field: getattr(item, field) for field in _SCAN_COUNT_FIELDS},
            }
            for item in graph.scan_summaries
        ],
        "unbuilt_components": [
            {"component_id": item.component_id, "reason": item.reason}
            for item in graph.unbuilt_components
        ],
        "unassigned_files": list(graph.unassigned_files),
        "unassigned_file_count": graph.unassigned_file_count,
        "dependencies_complete": graph.dependencies_complete,
        "coverage_gaps": [
            {"gap_code": gap.gap_code, "detail": gap.detail}
            for gap in graph.coverage_gaps
        ],
        "manifests_discovered_count": graph.manifests_discovered_count,
        "metadata_manifest_count": graph.metadata_manifest_count,
        "collaboration_manifest_count": graph.collaboration_manifest_count,
        "overflow_manifest_count": graph.overflow_manifest_count,
    }


def component_graph_digest(graph: ComponentGraph) -> str:
    """Return the 64-hex canonical digest of one component graph."""

    return compute_content_digest(canonical_dict_from_graph(graph))


def component_graph_payload(result: MonorepoProfileBuildResult) -> dict[str, Any]:
    """Project one build result onto the public wire payload."""

    budgets = getattr(result, "_effective_monorepo_budgets", None)
    if not isinstance(budgets, Mapping):
        raise ContractError(
            ContractErrorCode.INVALID_FIELD_VALUE,
            "result is missing its effective budget carrier",
        )
    graph = result.graph
    builds_by_id = {
        build.component.component_id: build for build in result.per_component
    }
    summaries_by_id = {
        item.component_id: item for item in graph.scan_summaries
    }
    components: list[dict[str, Any]] = []
    for info in graph.components:
        build = builds_by_id.get(info.component_id)
        summary = summaries_by_id[info.component_id]
        components.append(
            {
                "component_id": info.component_id,
                "root_dir": info.root_dir,
                "manifests": [
                    {
                        "path": ref.path,
                        "manifest_kind": ref.manifest_kind,
                        "source": ref.source,
                    }
                    for ref in info.manifests
                ],
                "python_file_count": info.python_file_count,
                "is_empty": info.is_empty,
                "built": build is not None,
                "digests": (
                    None
                    if info.artifact_digests is None
                    else {
                        "profile_content_digest": (
                            info.artifact_digests.profile_content_digest
                        ),
                        "ram_facts_digest": info.artifact_digests.ram_facts_digest,
                        "semantic_result_digest": (
                            info.artifact_digests.semantic_result_digest
                        ),
                    }
                ),
                "scan_summary": {
                    field: getattr(summary, field) for field in _SCAN_COUNT_FIELDS
                },
                "semantic_topn": (
                    None
                    if build is None
                    else {
                        "model_id": build.effective_semantic_options.model_id,
                        "top_n": build.effective_semantic_options.top_n,
                        "ranked_candidate_ids": [
                            item.candidate_id
                            for item in build.semantic_result.ranked
                        ],
                    }
                ),
            }
        )
    return {
        "schema_version": COMPONENT_GRAPH_SCHEMA_VERSION,
        "model_kind": COMPONENT_GRAPH_SCHEMA_NAME,
        "components": components,
        "edges": [
            {
                "source_component_id": edge.source_component_id,
                "target_component_id": edge.target_component_id,
                "status": edge.status,
                "imported_name": edge.imported_name,
                "evidence": [
                    {
                        "path": item.path,
                        "line": item.line,
                        "imported_name": item.imported_name,
                    }
                    for item in edge.evidence
                ],
            }
            for edge in graph.edges
        ],
        "unknown_imports": [
            {
                "source_component_id": item.source_component_id,
                "imported_name": item.imported_name,
                "count": item.count,
            }
            for item in graph.unknown_imports
        ],
        "unassigned_files": list(graph.unassigned_files),
        "unassigned_file_count": graph.unassigned_file_count,
        "scan_summaries": [
            {
                "component_id": item.component_id,
                **{field: getattr(item, field) for field in _SCAN_COUNT_FIELDS},
            }
            for item in graph.scan_summaries
        ],
        "unbuilt_components": [
            {"component_id": item.component_id, "reason": item.reason}
            for item in graph.unbuilt_components
        ],
        "dependencies_complete": graph.dependencies_complete,
        "coverage_gaps": [
            {"gap_code": gap.gap_code, "detail": gap.detail}
            for gap in graph.coverage_gaps
        ],
        "metadata_manifest_count": graph.metadata_manifest_count,
        "metadata_channel_skipped": dict(result.discovery.metadata_channel_skipped),
        "manifests_discovered_count": graph.manifests_discovered_count,
        "collaboration_manifest_count": graph.collaboration_manifest_count,
        "overflow_manifest_count": graph.overflow_manifest_count,
        "build": {"monorepo_budgets": dict(budgets)},
        "identity": {"component_graph_digest": component_graph_digest(graph)},
        "provenance": {
            "provenance_anchor_ids": [COMPONENT_GRAPH_PROVENANCE_ANCHOR]
        },
    }


def load_component_graph_schema() -> dict[str, Any]:
    """Read-only load of the wire schema file (zero network)."""

    schema_path = Path(__file__).resolve().parents[2] / COMPONENT_GRAPH_SCHEMA_FILE
    return json.loads(schema_path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# validator V1-V10 (section 5.4.8)
# ---------------------------------------------------------------------------

_PAYLOAD_TOP_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "model_kind",
        "components",
        "edges",
        "unknown_imports",
        "unassigned_files",
        "unassigned_file_count",
        "scan_summaries",
        "unbuilt_components",
        "dependencies_complete",
        "coverage_gaps",
        "metadata_manifest_count",
        "metadata_channel_skipped",
        "manifests_discovered_count",
        "collaboration_manifest_count",
        "overflow_manifest_count",
        "build",
        "identity",
        "provenance",
    }
)
_COMPONENT_ENTRY_KEYS: Final[frozenset[str]] = frozenset(
    {
        "component_id",
        "root_dir",
        "manifests",
        "python_file_count",
        "is_empty",
        "built",
        "digests",
        "scan_summary",
        "semantic_topn",
    }
)
_MANIFEST_REF_KEYS: Final[frozenset[str]] = frozenset(
    {"path", "manifest_kind", "source"}
)
_DIGEST_KEYS: Final[frozenset[str]] = frozenset(
    {"profile_content_digest", "ram_facts_digest", "semantic_result_digest"}
)
_EDGE_KEYS: Final[frozenset[str]] = frozenset(
    {"source_component_id", "target_component_id", "status", "imported_name",
     "evidence"}
)
_EVIDENCE_KEYS: Final[frozenset[str]] = frozenset(
    {"path", "line", "imported_name"}
)
_UNKNOWN_KEYS: Final[frozenset[str]] = frozenset(
    {"source_component_id", "imported_name", "count"}
)
_UNBUILT_KEYS: Final[frozenset[str]] = frozenset({"component_id", "reason"})
_GAP_KEYS: Final[frozenset[str]] = frozenset({"gap_code", "detail"})
_SCAN_SUMMARY_KEYS: Final[frozenset[str]] = frozenset(
    {"component_id", *_SCAN_COUNT_FIELDS}
)
_TOPN_KEYS: Final[frozenset[str]] = frozenset(
    {"model_id", "top_n", "ranked_candidate_ids"}
)
_BUDGET_KEYS: Final[frozenset[str]] = frozenset(
    {
        "max_components",
        "max_edges",
        "max_edge_evidence",
        "max_unassigned_files",
        "max_total_model_calls",
        "aggregate_max_prompt_tokens",
        "aggregate_max_output_tokens",
        "aggregate_max_total_tokens",
        "max_metadata_manifests",
        "max_metadata_total_bytes",
    }
)
_KIND_VALUES: Final[frozenset[str]] = frozenset(set(_MANIFEST_EXACT_KINDS.values())) | {
    COMPONENT_MANIFEST_KIND_REQUIREMENTS
}
_HEX64_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_SEGMENT_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9._\-]+$")
_DRIVE_PREFIX_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z]:")
_GAP_CODE_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


def _invalid(message: str) -> None:
    raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, message)


def _unknown(message: str) -> None:
    raise ContractError(ContractErrorCode.UNKNOWN_FIELD, message)


def _check_path(value: object, *, charset: bool = False) -> None:
    if not isinstance(value, str) or not value:
        _invalid("path fields must be non-empty strings")
    if value == ".":
        return
    # V5 (Packet v5.1 section 5.4.8): repo-relative POSIX only -- reject
    # Windows drive prefixes ("C:/...", "C:x"), any backslash (also the
    # UNC share form), NUL, absolute and trailing-slash shapes. Legal
    # Unicode segments stay allowed outside the charset-checked families.
    if (
        "\x00" in value
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or _DRIVE_PREFIX_RE.match(value) is not None
    ):
        _invalid(f"invalid path shape: {value!r}")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        _invalid(f"path is not valid UTF-8: {value!r}")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        _invalid(f"invalid path segment: {value!r}")
    if charset and not all(_SEGMENT_RE.fullmatch(part) for part in parts):
        _invalid(f"path charset violation: {value!r}")
    if is_secret_shaped_path(value):
        _invalid(f"secret-shaped path on a public surface: {value!r}")


def _parse_channel_detail(detail: str) -> tuple[str, str, int]:
    parts = detail.split("; ")
    if len(parts) != 3 or not parts[0].startswith("channel="):
        _invalid(f"channel-carrier detail format: {detail!r}")
    channel = parts[0][len("channel="):]
    if channel not in COMPONENT_MANIFEST_SOURCES:
        _invalid(f"channel domain: {channel!r}")
    if not parts[1].startswith("reason=") or not parts[2].startswith("count="):
        _invalid(f"channel-carrier detail order: {detail!r}")
    reason = parts[1][len("reason="):]
    digits = parts[2][len("count="):]
    if not digits.isdigit() or int(digits) < 1:
        _invalid(f"channel-carrier count: {detail!r}")
    return channel, reason, int(digits)


def _parse_budget_detail(detail: str) -> tuple[str, int]:
    parts = detail.split("; ")
    if len(parts) != 2 or not parts[0].startswith("reason="):
        _invalid(f"budget-family detail format: {detail!r}")
    if not parts[1].startswith("count="):
        _invalid(f"budget-family detail order: {detail!r}")
    reason = parts[0][len("reason="):]
    digits = parts[1][len("count="):]
    if not digits.isdigit() or int(digits) < 1:
        _invalid(f"budget-family count: {detail!r}")
    if reason not in _GRAPH_BUDGET_REASONS:
        _invalid(f"budget-family reason vocabulary: {reason!r}")
    return reason, int(digits)


def validate_component_graph_payload(payload: Mapping[str, object]) -> None:
    """Validate one component-graph wire payload fail-closed (V1-V10)."""

    if not isinstance(payload, Mapping):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$")
    extra = set(payload) - _PAYLOAD_TOP_KEYS
    if extra:
        _unknown(f"$.{sorted(extra)[0]}")
    if payload.get("schema_version") != COMPONENT_GRAPH_SCHEMA_VERSION:
        _invalid("schema_version")
    if payload.get("model_kind") != COMPONENT_GRAPH_SCHEMA_NAME:
        _invalid("model_kind")
    if payload.get("provenance") != {
        "provenance_anchor_ids": [COMPONENT_GRAPH_PROVENANCE_ANCHOR]
    }:
        _invalid("provenance")

    components = payload.get("components")
    if not isinstance(components, list):
        _invalid("components")
    ids: list[str] = []
    published_manifests = 0
    published_meta = 0
    for entry in components:
        if not isinstance(entry, Mapping):
            _invalid("component entry")
        entry_extra = set(entry) - _COMPONENT_ENTRY_KEYS
        if entry_extra:
            _unknown(f"$.components.{sorted(entry_extra)[0]}")
        component_id = entry.get("component_id")
        if not isinstance(component_id, str) or not component_id.startswith(
            "component:"
        ):
            _invalid("component_id")
        segment = component_id[len("component:"):]
        _check_path(segment, charset=True)
        root_dir = entry.get("root_dir")
        if not isinstance(root_dir, str):
            _invalid("root_dir")
        if root_dir:
            _check_path(root_dir, charset=True)
        ids.append(component_id)

        count = entry.get("python_file_count")
        if type(count) is not int or count < 0:
            _invalid("python_file_count")
        if entry.get("is_empty") is not (count == 0):
            _invalid("is_empty must equal python_file_count == 0")

        manifests = entry.get("manifests")
        if not isinstance(manifests, list):
            _invalid("manifests")
        manifest_paths: list[str] = []
        for ref in manifests:
            if not isinstance(ref, Mapping) or set(ref) != _MANIFEST_REF_KEYS:
                _unknown("manifest ref keys")
            _check_path(ref["path"])
            if ref["manifest_kind"] not in _KIND_VALUES:
                _invalid("manifest_kind")
            if ref["source"] not in COMPONENT_MANIFEST_SOURCES:
                _invalid("manifest source")
            manifest_paths.append(ref["path"])
            published_manifests += 1
            if ref["source"] == COMPONENT_MANIFEST_SOURCE_METADATA_CHANNEL:
                published_meta += 1
        if manifest_paths != sorted(manifest_paths) or len(
            set(manifest_paths)
        ) != len(manifest_paths):
            _invalid("manifests must be path-sorted and unique")
        if len(manifests) > 1_024:
            _invalid("manifests exceed the schema hard cap")

        built = entry.get("built")
        digests = entry.get("digests")
        if not isinstance(built, bool):
            _invalid("built")
        if (digests is not None) is not built:
            _invalid("digests non-null iff built")
        if digests is not None:
            if not isinstance(digests, Mapping) or set(digests) != _DIGEST_KEYS:
                _invalid("digest keys")
            for value in digests.values():
                if not isinstance(value, str) or _HEX64_RE.fullmatch(value) is None:
                    _invalid("digest format")

        scan = entry.get("scan_summary")
        if not isinstance(scan, Mapping) or set(scan) != {
            *_SCAN_COUNT_FIELDS
        }:
            _unknown("scan_summary keys")
        for field in _SCAN_COUNT_FIELDS:
            value = scan[field]
            if type(value) is not int or value < 0:
                _invalid(f"scan_summary.{field}")

        topn = entry.get("semantic_topn")
        if topn is None:
            if built:
                _invalid("built components must carry semantic_topn")
        else:
            if not isinstance(topn, Mapping) or set(topn) != _TOPN_KEYS:
                _unknown("semantic_topn keys")
            top_n = topn.get("top_n")
            if type(top_n) is not int or not 1 <= top_n <= 100:
                _invalid("top_n")
            ranked = topn.get("ranked_candidate_ids")
            if not isinstance(ranked, list) or len(ranked) > top_n or len(
                ranked
            ) > 100:
                _invalid("ranked_candidate_ids")
            for item in ranked:
                if not isinstance(item, str):
                    _invalid("candidate_id")

    if len(set(ids)) != len(ids):
        _invalid("duplicate component_id")
    if ids != sorted(ids):
        _invalid("components must be component_id-sorted")
    if len(components) > 64:
        _invalid("components exceed the schema hard cap")

    edges = payload.get("edges")
    if not isinstance(edges, list):
        _invalid("edges")
    if len(edges) > 16_384:
        _invalid("edges exceed the schema hard cap")
    edge_keys: list[tuple[str, str, str, str]] = []
    for edge in edges:
        if not isinstance(edge, Mapping) or set(edge) != _EDGE_KEYS:
            _unknown("edge keys")
        source = edge["source_component_id"]
        target = edge["target_component_id"]
        status = edge["status"]
        if status not in COMPONENT_EDGE_STATUSES:
            _invalid("edge status")
        if source not in ids:
            _invalid("edge source must exist")
        if status == COMPONENT_EDGE_STATUS_RESOLVED:
            if target not in ids or target == source:
                _invalid("resolved edge target")
        elif target is not None:
            _invalid("ambiguous/unresolved edge target must be null")
        evidence = edge["evidence"]
        if not isinstance(evidence, list):
            _invalid("evidence")
        if len(evidence) > 1_024:
            _invalid("evidence exceeds the schema hard cap")
        evidence_tuples: list[tuple[str, int, str]] = []
        for item in evidence:
            if not isinstance(item, Mapping) or set(item) != _EVIDENCE_KEYS:
                _unknown("evidence keys")
            _check_path(item["path"])
            line = item["line"]
            if type(line) is not int or line < 1:
                _invalid("evidence line")
            evidence_tuples.append((item["path"], line, item["imported_name"]))
        if evidence_tuples != sorted(evidence_tuples) or len(
            set(evidence_tuples)
        ) != len(evidence_tuples):
            _invalid("evidence must be (path, line, imported_name)-sorted and unique")
        edge_keys.append((source, status, target or "", edge["imported_name"]))
    if len(set(edge_keys)) != len(edge_keys) or edge_keys != sorted(edge_keys):
        _invalid("edges must be key-sorted and unique")

    unknowns = payload.get("unknown_imports")
    if not isinstance(unknowns, list):
        _invalid("unknown_imports")
    if len(unknowns) > 16_384:
        _invalid("unknown_imports exceed the schema hard cap")
    unknown_keys: list[tuple[str, str]] = []
    for item in unknowns:
        if not isinstance(item, Mapping) or set(item) != _UNKNOWN_KEYS:
            _unknown("unknown_import keys")
        if item["source_component_id"] not in ids:
            _invalid("unknown_import source must exist")
        if type(item["count"]) is not int or item["count"] < 1:
            _invalid("unknown_import count")
        unknown_keys.append(
            (item["source_component_id"], item["imported_name"])
        )
    if len(set(unknown_keys)) != len(unknown_keys) or unknown_keys != sorted(
        unknown_keys
    ):
        _invalid("unknown_imports must be sorted and unique")

    unassigned = payload.get("unassigned_files")
    if not isinstance(unassigned, list):
        _invalid("unassigned_files")
    if len(unassigned) > 4_096:
        _invalid("unassigned_files exceed the schema hard cap")
    for item in unassigned:
        _check_path(item)
    if unassigned != sorted(unassigned) or len(set(unassigned)) != len(
        unassigned
    ):
        _invalid("unassigned_files must be sorted and unique")
    unassigned_count = payload.get("unassigned_file_count")
    if type(unassigned_count) is not int or unassigned_count < len(unassigned):
        _invalid("unassigned_file_count")

    summaries = payload.get("scan_summaries")
    if not isinstance(summaries, list):
        _invalid("scan_summaries")
    summaries_by_id: dict[str, Mapping[str, object]] = {}
    for item in summaries:
        if not isinstance(item, Mapping) or set(item) != _SCAN_SUMMARY_KEYS:
            _unknown("scan_summary keys")
        summary_id = item["component_id"]
        if summary_id not in ids:
            _invalid("scan_summary component_id must exist")
        for field in _SCAN_COUNT_FIELDS:
            value = item[field]
            if type(value) is not int or value < 0:
                _invalid(f"scan_summary.{field}")
        summaries_by_id[summary_id] = item
    if sorted(summaries_by_id) != sorted(ids) or len(summaries) != len(ids):
        _invalid("scan_summaries must cover each component exactly once")
    summaries_order = [item["component_id"] for item in summaries]  # type: ignore[index]
    if summaries_order != sorted(summaries_order):
        _invalid("scan_summaries must be component_id-sorted")
    for entry in components:
        summary = summaries_by_id[entry["component_id"]]  # type: ignore[index]
        for field in _SCAN_COUNT_FIELDS:
            if summary[field] != entry["scan_summary"][field]:  # type: ignore[index]
                _invalid("scan_summary must equal the component entry counts")

    unbuilt = payload.get("unbuilt_components")
    if not isinstance(unbuilt, list):
        _invalid("unbuilt_components")
    unbuilt_ids: list[str] = []
    for item in unbuilt:
        if not isinstance(item, Mapping) or set(item) != _UNBUILT_KEYS:
            _unknown("unbuilt keys")
        if item["component_id"] not in ids:
            _invalid("unbuilt component_id must exist")
        if item["reason"] not in UNBUILT_REASONS:
            _invalid("unbuilt reason")
        unbuilt_ids.append(item["component_id"])
    if unbuilt_ids != sorted(unbuilt_ids) or len(set(unbuilt_ids)) != len(
        unbuilt_ids
    ):
        _invalid("unbuilt_components must be sorted and unique")
    built_ids = {entry["component_id"] for entry in components if entry["built"]}
    if set(unbuilt_ids) != set(ids) - built_ids:
        _invalid("unbuilt/built correspondence")
    complete = payload.get("dependencies_complete")
    if not isinstance(complete, bool):
        _invalid("dependencies_complete")
    if unbuilt and complete is not False:
        _invalid("unbuilt components require dependencies_complete == false")

    gaps = payload.get("coverage_gaps")
    if not isinstance(gaps, list):
        _invalid("coverage_gaps")
    gap_pairs: list[tuple[str, str]] = []
    for gap in gaps:
        if not isinstance(gap, Mapping) or set(gap) != _GAP_KEYS:
            _unknown("gap keys")
        code = gap["gap_code"]
        detail = gap["detail"]
        if not isinstance(code, str) or _GAP_CODE_RE.fullmatch(code) is None:
            _invalid("gap_code")
        if not isinstance(detail, str) or not detail:
            _invalid("gap detail")
        gap_pairs.append((code, detail))
    if gap_pairs != sorted(gap_pairs):
        _invalid("coverage_gaps must be (gap_code, detail)-sorted")

    channel_meta: dict[str, int] = {}
    seen_triples: set[tuple[str, str, str]] = set()
    unknown_limit_count = 0
    for code, detail in gap_pairs:
        if code == "INVENTORY_SKIPPED" or detail.startswith("channel="):
            channel, reason, count = _parse_channel_detail(detail)
            triple = (code, channel, reason)
            if triple in seen_triples:
                _invalid(f"duplicate (gap_code, channel, reason) triple: {triple!r}")
            seen_triples.add(triple)
            if code == "INVENTORY_SKIPPED":
                vocabulary = (
                    _CHANNEL_SKIP_VOCABULARY
                    if channel == COMPONENT_MANIFEST_SOURCE_METADATA_CHANNEL
                    else _SOURCE_GAP_VOCABULARY
                )
                if reason not in vocabulary:
                    _invalid(f"channel-carrier reason vocabulary: {reason!r}")
            else:
                if channel != COMPONENT_MANIFEST_SOURCE_METADATA_CHANNEL:
                    _invalid("metadata budget reasons must stay in the channel domain")
                if reason not in _CHANNEL_METADATA_BUDGET_REASONS:
                    _invalid("budget-family reasons must not carry a channel")
            if channel == COMPONENT_MANIFEST_SOURCE_METADATA_CHANNEL:
                channel_meta[reason] = count
            if reason == "unknown-import-limit":
                unknown_limit_count = count
        else:
            reason, count = _parse_budget_detail(detail)
            if reason == "unknown-import-limit":
                unknown_limit_count = count

    skipped = payload.get("metadata_channel_skipped")
    if not isinstance(skipped, Mapping):
        _invalid("metadata_channel_skipped")
    for key, value in skipped.items():
        if key not in _CHANNEL_SKIP_VOCABULARY:
            _invalid(f"metadata_channel_skipped vocabulary: {key!r}")
        if type(value) is not int or value < 0:
            _invalid("metadata_channel_skipped counts")
    for reason, count in channel_meta.items():
        if skipped.get(reason) != count:
            _invalid("metadata-domain gap records must match the channel dictionary")
    for key in _T8_LOSS_KEYS:
        if skipped.get(key, 0) > 0 and key not in channel_meta:
            _invalid("missing metadata-domain gap record for a loss key")

    truncated_total = sum(
        item["unknown_truncated_count"] for item in summaries  # type: ignore[index]
    )
    if truncated_total != unknown_limit_count:
        _invalid("unknown-truncation accounting must match the gap count")

    discovered = payload.get("manifests_discovered_count")
    collaboration = payload.get("collaboration_manifest_count")
    overflow = payload.get("overflow_manifest_count")
    metadata_manifest = payload.get("metadata_manifest_count")
    for name, value in (
        ("manifests_discovered_count", discovered),
        ("collaboration_manifest_count", collaboration),
        ("overflow_manifest_count", overflow),
        ("metadata_manifest_count", metadata_manifest),
    ):
        if type(value) is not int or value < 0:
            _invalid(name)
    if discovered != published_manifests + collaboration + overflow:
        _invalid("manifest conservation (INV-OWN-3(a))")
    if metadata_manifest > discovered:
        _invalid("metadata_manifest_count exceeds manifests_discovered_count")
    if published_meta > metadata_manifest:
        _invalid("published metadata-channel manifests exceed the channel count")

    build_section = payload.get("build")
    if not isinstance(build_section, Mapping) or set(build_section) != {
        "monorepo_budgets"
    }:
        _unknown("build keys")
    budgets = build_section["monorepo_budgets"]
    if not isinstance(budgets, Mapping) or set(budgets) != _BUDGET_KEYS:
        _unknown("monorepo_budgets keys")
    # V8 (Packet v5.1 sections 5.4.3/5.4.8): the effective budgets carry
    # exact-int legal domains (the schema hard caps are the domain upper
    # bounds; defaults are NOT hard caps) plus the frozen cross-field
    # invariant total >= prompt + output. Same table as construction-time
    # validation -- a consistently digest-bound payload cannot smuggle an
    # out-of-domain budget through the unbound build section.
    for name, (low, high) in _BUDGET_DOMAINS.items():
        value = budgets[name]  # type: ignore[index]
        if type(value) is not int or not low <= value <= high:
            _invalid(f"monorepo_budgets.{name} domain")
    if (
        budgets["aggregate_max_total_tokens"]  # type: ignore[index]
        < budgets["aggregate_max_prompt_tokens"]  # type: ignore[index]
        + budgets["aggregate_max_output_tokens"]  # type: ignore[index]
    ):
        _invalid("aggregate_max_total_tokens must be >= prompt + output")
    if len(components) > budgets["max_components"]:
        _invalid("components exceed the effective max_components")
    if len(edges) + len(unknowns) > budgets["max_edges"]:
        _invalid("edges+unknown_imports exceed the effective max_edges")
    for edge in edges:
        if len(edge["evidence"]) > budgets["max_edge_evidence"]:  # type: ignore[arg-type]
            _invalid("evidence exceeds the effective max_edge_evidence")
    if len(unassigned) > budgets["max_unassigned_files"]:
        _invalid("unassigned_files exceed the effective max_unassigned_files")
    if metadata_manifest > budgets["max_metadata_manifests"]:
        _invalid("metadata_manifest_count exceeds the effective channel budget")

    identity = payload.get("identity")
    if not isinstance(identity, Mapping) or set(identity) != {
        "component_graph_digest"
    }:
        _unknown("identity keys")
    digest_value = identity["component_graph_digest"]
    if not isinstance(digest_value, str) or _HEX64_RE.fullmatch(digest_value) is None:
        _invalid("identity digest format")

    canonical = {
        "components": [
            {
                "component_id": entry["component_id"],  # type: ignore[index]
                "root_dir": entry["root_dir"],  # type: ignore[index]
                "manifests": [
                    {
                        "path": ref["path"],  # type: ignore[index]
                        "kind": ref["manifest_kind"],  # type: ignore[index]
                        "source": ref["source"],  # type: ignore[index]
                    }
                    for ref in entry["manifests"]  # type: ignore[index]
                ],
                "python_file_count": entry["python_file_count"],  # type: ignore[index]
                "is_empty": entry["is_empty"],  # type: ignore[index]
                "artifact_digests": (
                    None
                    if entry["digests"] is None  # type: ignore[index]
                    else dict(entry["digests"])  # type: ignore[index]
                ),
            }
            for entry in components
        ],
        "edges": [dict(edge) for edge in edges],
        "unknown_imports": [dict(item) for item in unknowns],
        "scan_summaries": [dict(item) for item in summaries],
        "unbuilt_components": [dict(item) for item in unbuilt],
        "unassigned_files": list(unassigned),
        "unassigned_file_count": unassigned_count,
        "dependencies_complete": complete,
        "coverage_gaps": [dict(gap) for gap in gaps],
        "manifests_discovered_count": discovered,
        "metadata_manifest_count": metadata_manifest,
        "collaboration_manifest_count": collaboration,
        "overflow_manifest_count": overflow,
    }
    if compute_content_digest(canonical) != digest_value:
        raise ContractError(
            ContractErrorCode.DIGEST_MISMATCH, "$.identity.component_graph_digest"
        )
