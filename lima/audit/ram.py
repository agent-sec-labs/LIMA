"""Deterministic Python RAM facts layer for repository profiles (IP-0018).

Layer 2 of the repository profile stack: derive the FR-02 static facts
(entrypoints, external sources, sensitive sinks, trust boundaries, key flows,
unresolved call edges) plus the FR-05 ``DYNAMIC_IMPORT`` and
``AMBIGUOUS_DISPATCH`` typed coverage gaps from a bounded, read-only
:class:`lima.workspace.RepositoryWorkspace` snapshot and the frozen facts of
:class:`lima.python_dataflow.PythonDataflowAnalyzer`.

Frozen behaviour (Packet ``IP-0018-PACKET/v1``):

- stdlib-only on top of ``lima.contracts``, ``lima.workspace`` and
  ``lima.python_dataflow``; no third-party dependency is introduced;
- target code is never executed or imported; nothing is written to disk, no
  network facility is used and no environment variable is read;
- every output path is a repo-relative POSIX path taken from the workspace
  inventory; source text, snippets and secrets never enter the output, and
  key flows carry ``path:line`` anchors only;
- every derivation is deterministic: path-sorted iteration, no clock, no
  randomness, no environment input, so two builds of one snapshot with one
  budget set produce equal facts and equal digests;
- failures are fail-closed: invalid arguments raise
  :class:`lima.contracts.errors.ContractError` or ``ValueError`` and are
  never silently corrected, while read failures and budget truncations
  become typed coverage gaps instead of guessed defaults.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from lima.contracts.codec import compute_content_digest
from lima.contracts.errors import ContractError, ContractErrorCode
from lima.contracts.profile import AttackSurfaceEntry, ProfileCoverageGap
from lima.python_dataflow import (
    DIRECT_SOURCE_CALLS,
    ENDPOINT_DECORATORS,
    REQUEST_SOURCE_ATTRIBUTES,
    REQUEST_SOURCE_SUFFIXES,
    ModuleInfo,
    PythonDataflowAnalyzer,
    PythonDataflowResult,
)
from lima.workspace import RepositoryWorkspace

__all__ = [
    "GAP_AMBIGUOUS_DISPATCH",
    "GAP_DYNAMIC_IMPORT",
    "RAM_PROVENANCE_ANCHOR",
    "PythonRamFacts",
    "RamBudgets",
    "RamFactsBuildResult",
    "RamKeyFlow",
    "build_python_ram_facts",
    "ram_facts_digest",
]

RAM_PROVENANCE_ANCHOR: Final[str] = "ram-facts"

GAP_DYNAMIC_IMPORT: Final[str] = "DYNAMIC_IMPORT"
GAP_AMBIGUOUS_DISPATCH: Final[str] = "AMBIGUOUS_DISPATCH"

#: Frozen IP-0016 gap semantics reused by value (Packet §5.0/§5.2): the RAM
#: layer must not import :mod:`lima.audit.inventory` (Packet §4 dependency
#: direction), so the identical frozen gap-code strings are restated here.
_GAP_BUDGET_EXHAUSTED: Final[str] = "BUDGET_EXHAUSTED"
_GAP_INVENTORY_SKIPPED: Final[str] = "INVENTORY_SKIPPED"

_REASON_ENDPOINT: Final[str] = "RAM_ENDPOINT_DECORATED"
_REASON_EXTERNAL_SOURCE: Final[str] = "RAM_EXTERNAL_SOURCE"
_REASON_SENSITIVE_SINK: Final[str] = "RAM_SENSITIVE_SINK"
_REASON_TRUST_BOUNDARY: Final[str] = "RAM_TRUST_BOUNDARY"
_REASON_UNRESOLVED_CALL: Final[str] = "RAM_UNRESOLVED_CALL"

#: TaintTrace step bound transcribed from Packet §3.1 and reused by §5.1.5.
_MAX_TRACE_STEPS: Final[int] = 12


@dataclass(frozen=True)
class RamBudgets:
    """Read budgets for the RAM facts layer; every value must be positive."""

    max_python_files: int = 512
    max_key_flows: int = 256
    max_unresolved_edges: int = 1024

    def __post_init__(self) -> None:
        for name in ("max_python_files", "max_key_flows", "max_unresolved_edges"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class RamKeyFlow:
    """One source-to-sink flow reduced to ordered ``path:line`` anchors."""

    sink_rule_id: str
    steps: tuple[str, ...]


@dataclass(frozen=True)
class PythonRamFacts:
    """The frozen FR-02/FR-05 static fact set of one Python snapshot."""

    entrypoints: tuple[AttackSurfaceEntry, ...]
    external_sources: tuple[AttackSurfaceEntry, ...]
    source_labels: tuple[str, ...]
    sensitive_sinks: tuple[AttackSurfaceEntry, ...]
    sink_rule_ids: tuple[str, ...]
    sink_cwes: tuple[str, ...]
    trust_boundaries: tuple[AttackSurfaceEntry, ...]
    key_flows: tuple[RamKeyFlow, ...]
    unresolved_edges: tuple[AttackSurfaceEntry, ...]
    coverage_gaps: tuple[ProfileCoverageGap, ...]
    counters: Mapping[str, int]


@dataclass(frozen=True)
class RamFactsBuildResult:
    """One deterministic RAM facts build with its provenance anchor."""

    facts: PythonRamFacts
    provenance_anchor_ids: tuple[str, ...]


def _dotted_name(node: ast.AST) -> str:
    """Join an Attribute chain plus Name into one dotted name.

    Same semantics as ``lima.python_dataflow._call_name`` (Attribute chain
    joined in reverse), reimplemented here because that helper is private.
    """
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _entry(path: str, symbol: str | None, reason_code: str) -> AttackSurfaceEntry:
    return AttackSurfaceEntry(
        path=path,
        symbol=symbol,
        reason_codes=(reason_code,),
        source_artifact_ids=(RAM_PROVENANCE_ANCHOR,),
    )


def _parent_map(tree: ast.Module) -> dict[int, ast.AST]:
    parents: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    return parents


def _enclosing_function_name(
    node: ast.AST, parents: dict[int, ast.AST]
) -> str | None:
    current = parents.get(id(node))
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current.name
        current = parents.get(id(current))
    return None


def _source_label(node: ast.AST) -> str | None:
    """Return the frozen external-source label of one site, if any."""
    if isinstance(node, ast.Call):
        name = _dotted_name(node.func)
        direct = DIRECT_SOURCE_CALLS.get(name)
        if direct is not None:
            return direct
        if isinstance(node.func, ast.Attribute):
            for suffix, label in REQUEST_SOURCE_SUFFIXES.items():
                if name.endswith(suffix):
                    return label
        return None
    if isinstance(node, ast.Attribute):
        last = _dotted_name(node).rsplit(".", 1)[-1]
        return REQUEST_SOURCE_ATTRIBUTES.get(last)
    return None


def _collect_entrypoints(
    modules: Mapping[str, ModuleInfo],
) -> list[AttackSurfaceEntry]:
    entries: list[AttackSurfaceEntry] = []
    for info in sorted(modules.values(), key=lambda item: item.path):
        for node in ast.walk(info.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                value = decorator.func if isinstance(decorator, ast.Call) else decorator
                if _dotted_name(value).rsplit(".", 1)[-1] in ENDPOINT_DECORATORS:
                    entries.append(_entry(info.path, node.name, _REASON_ENDPOINT))
                    break
    entries.sort(key=lambda entry: (entry.path, entry.symbol or ""))
    return entries


def _collect_external_sources(
    modules: Mapping[str, ModuleInfo],
) -> tuple[list[AttackSurfaceEntry], list[str]]:
    pairs: list[tuple[AttackSurfaceEntry, str]] = []
    for info in sorted(modules.values(), key=lambda item: item.path):
        parents = _parent_map(info.tree)
        for node in ast.walk(info.tree):
            label = _source_label(node)
            if label is None:
                continue
            pairs.append(
                (
                    _entry(
                        info.path,
                        _enclosing_function_name(node, parents),
                        _REASON_EXTERNAL_SOURCE,
                    ),
                    label,
                )
            )
    pairs.sort(key=lambda pair: (pair[0].path, pair[0].symbol or ""))
    entries = [pair[0] for pair in pairs]
    labels = [pair[1] for pair in pairs]
    return entries, labels


def _collect_trust_boundaries(
    entrypoints: list[AttackSurfaceEntry],
    external_sources: list[AttackSurfaceEntry],
) -> list[AttackSurfaceEntry]:
    paths = {entry.path for entry in entrypoints}
    paths.update(entry.path for entry in external_sources)
    return [_entry(path, None, _REASON_TRUST_BOUNDARY) for path in sorted(paths)]


def _collect_sink_facts(
    result: PythonDataflowResult,
    limits: RamBudgets,
    gaps: list[tuple[str, str]],
) -> tuple[list[AttackSurfaceEntry], list[str], list[str], list[RamKeyFlow]]:
    findings = sorted(
        result.findings, key=lambda item: (item.path, item.line, item.rule_id)
    )
    entries = [_entry(item.path, None, _REASON_SENSITIVE_SINK) for item in findings]
    rule_ids = [item.rule_id for item in findings]
    cwes = [item.cwe for item in findings]
    flows: list[RamKeyFlow] = []
    for item in findings:
        steps = tuple(
            f"{record.path}:{record.line}" for record in item.evidence_records
        )[-_MAX_TRACE_STEPS:]
        flows.append(RamKeyFlow(sink_rule_id=item.rule_id, steps=steps))
    flows.sort(key=lambda flow: (flow.sink_rule_id, flow.steps))
    if len(flows) > limits.max_key_flows:
        overflow = len(flows) - limits.max_key_flows
        gaps.append(
            (_GAP_BUDGET_EXHAUSTED, f"reason=key-flow-limit; count={overflow}")
        )
        flows = flows[: limits.max_key_flows]
    return entries, rule_ids, cwes, flows


def _collect_unresolved_edges(
    analyzer: PythonDataflowAnalyzer,
    limits: RamBudgets,
    gaps: list[tuple[str, str]],
) -> list[AttackSurfaceEntry]:
    edges = [
        _entry(path, callee, _REASON_UNRESOLVED_CALL)
        for path, _line, callee in analyzer.unresolved_call_sites
    ]
    edges.sort(key=lambda entry: (entry.path, entry.symbol or ""))
    if len(edges) > limits.max_unresolved_edges:
        overflow = len(edges) - limits.max_unresolved_edges
        gaps.append(
            (_GAP_BUDGET_EXHAUSTED, f"reason=unresolved-edge-limit; count={overflow}")
        )
        edges = edges[: limits.max_unresolved_edges]
    return edges


def _read_python_text(
    workspace: RepositoryWorkspace,
    relative_path: str,
    gaps: list[tuple[str, str]],
) -> str | None:
    try:
        return workspace.read_text(relative_path)
    except (OSError, ValueError):
        gaps.append(
            (_GAP_INVENTORY_SKIPPED, f"reason=read-failed; file={relative_path}")
        )
        return None


def _coverage_gaps(
    gaps: list[tuple[str, str]],
) -> tuple[ProfileCoverageGap, ...]:
    ordered = sorted(gaps, key=lambda pair: (pair[0], pair[1].encode("utf-8")))
    return tuple(
        ProfileCoverageGap(gap_code=code, detail=detail) for code, detail in ordered
    )


def _counters(result: PythonDataflowResult) -> Mapping[str, int]:
    return MappingProxyType(
        {
            "ambiguous_modules": result.ambiguous_modules,
            "cross_file_edges": result.cross_file_edges,
            "dynamic_import_sites": result.dynamic_import_sites,
            "functions_indexed": result.functions_indexed,
            "interprocedural_edges": result.interprocedural_edges,
            "modules_indexed": result.modules_indexed,
            "parse_error_files": len(result.parse_errors),
            "unresolved_calls": result.unresolved_calls,
        }
    )


def _call_graph_gaps(
    analyzer: PythonDataflowAnalyzer, result: PythonDataflowResult
) -> list[tuple[str, str]]:
    gaps: list[tuple[str, str]] = []
    if analyzer.dynamic_import_sites:
        gaps.append(
            (
                GAP_DYNAMIC_IMPORT,
                f"reason=dynamic-import; count={len(analyzer.dynamic_import_sites)}",
            )
        )
    if result.ambiguous_modules:
        gaps.append(
            (
                GAP_AMBIGUOUS_DISPATCH,
                f"reason=ambiguous-module; count={result.ambiguous_modules}",
            )
        )
    return gaps


def build_python_ram_facts(
    workspace: RepositoryWorkspace,
    *,
    budgets: RamBudgets | None = None,
) -> RamFactsBuildResult:
    """Derive the deterministic Python RAM fact set from one read-only workspace."""
    if not isinstance(workspace, RepositoryWorkspace):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if budgets is not None and not isinstance(budgets, RamBudgets):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    limits = budgets if budgets is not None else RamBudgets()

    inventory = workspace.inventory()
    candidates = sorted(
        item.path for item in inventory.files if item.path.endswith(".py")
    )
    gaps: list[tuple[str, str]] = []
    if len(candidates) > limits.max_python_files:
        overflow = len(candidates) - limits.max_python_files
        gaps.append(
            (_GAP_BUDGET_EXHAUSTED, f"reason=python-file-limit; count={overflow}")
        )
        candidates = candidates[: limits.max_python_files]

    files: dict[str, str] = {}
    for relative_path in candidates:
        text = _read_python_text(workspace, relative_path, gaps)
        if text is not None:
            files[relative_path] = text

    analyzer = PythonDataflowAnalyzer(max_call_depth=4)
    result = analyzer.analyze_project(files)

    entrypoints = _collect_entrypoints(analyzer.modules)
    external_sources, source_labels = _collect_external_sources(analyzer.modules)
    sensitive_sinks, sink_rule_ids, sink_cwes, key_flows = _collect_sink_facts(
        result, limits, gaps
    )
    trust_boundaries = _collect_trust_boundaries(entrypoints, external_sources)
    unresolved_edges = _collect_unresolved_edges(analyzer, limits, gaps)
    gaps.extend(_call_graph_gaps(analyzer, result))

    facts = PythonRamFacts(
        entrypoints=tuple(entrypoints),
        external_sources=tuple(external_sources),
        source_labels=tuple(source_labels),
        sensitive_sinks=tuple(sensitive_sinks),
        sink_rule_ids=tuple(sink_rule_ids),
        sink_cwes=tuple(sink_cwes),
        trust_boundaries=tuple(trust_boundaries),
        key_flows=tuple(key_flows),
        unresolved_edges=tuple(unresolved_edges),
        coverage_gaps=_coverage_gaps(gaps),
        counters=_counters(result),
    )
    return RamFactsBuildResult(
        facts=facts,
        provenance_anchor_ids=(RAM_PROVENANCE_ANCHOR,),
    )


def ram_facts_digest(facts: PythonRamFacts) -> str:
    """Return the lowercase 64-hex canonical content digest of one fact set."""
    if not isinstance(facts, PythonRamFacts):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    payload = {
        "coverage_gaps": [gap.to_dict() for gap in facts.coverage_gaps],
        "counters": {name: facts.counters[name] for name in sorted(facts.counters)},
        "entrypoints": [entry.to_dict() for entry in facts.entrypoints],
        "external_sources": [entry.to_dict() for entry in facts.external_sources],
        "key_flows": [
            {"sink_rule_id": flow.sink_rule_id, "steps": list(flow.steps)}
            for flow in facts.key_flows
        ],
        "sensitive_sinks": [entry.to_dict() for entry in facts.sensitive_sinks],
        "sink_cwes": list(facts.sink_cwes),
        "sink_rule_ids": list(facts.sink_rule_ids),
        "source_labels": list(facts.source_labels),
        "trust_boundaries": [entry.to_dict() for entry in facts.trust_boundaries],
        "unresolved_edges": [entry.to_dict() for entry in facts.unresolved_edges],
    }
    return compute_content_digest(payload)
