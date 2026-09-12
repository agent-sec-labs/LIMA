"""Scratch implementation of the IP-0018 Python RAM facts layer.

PI-DR2 scratch skeleton: proves the frozen Packet IP-0018-PACKET/v1 §5
design contracts are GREEN-reachable. NOT part of any commit on the
integration branch; the Implementation Agent writes the product file.

The TEMP copy branch (PI-DR6) uses a byte-identical copy of this file.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass, field
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
    PythonDataflowAnalyzer,
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

_BUDGET_FILE_LIMIT: Final[str] = "reason=python-file-limit; count={count}"
_BUDGET_KEY_FLOW_LIMIT: Final[str] = "reason=key-flow-limit; count={count}"
_BUDGET_EDGE_LIMIT: Final[str] = "reason=unresolved-edge-limit; count={count}"
_GAP_DYNAMIC_IMPORT_DETAIL: Final[str] = "reason=dynamic-import; count={count}"
_GAP_AMBIGUOUS_DETAIL: Final[str] = "reason=ambiguous-module; count={count}"
_GAP_READ_FAILED: Final[str] = "reason=read-failed; file={path}"

_ENTRYPOINT_REASON: Final[str] = "RAM_ENDPOINT_DECORATED"
_SOURCE_REASON: Final[str] = "RAM_EXTERNAL_SOURCE"
_SINK_REASON: Final[str] = "RAM_SENSITIVE_SINK"
_BOUNDARY_REASON: Final[str] = "RAM_TRUST_BOUNDARY"
_EDGE_REASON: Final[str] = "RAM_UNRESOLVED_CALL"

_SOURCE_SUFFIX_KEYS: Final[tuple[str, ...]] = tuple(sorted(REQUEST_SOURCE_SUFFIXES))


@dataclass(frozen=True)
class RamBudgets:
    """Positive read budgets for the RAM facts layer (Packet §5.1.7)."""

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
    """One taint-proven source-to-sink flow as ordered repo-relative anchors."""

    sink_rule_id: str
    steps: tuple[str, ...]


@dataclass(frozen=True)
class PythonRamFacts:
    """Deterministic Python RAM facts: FR-02 six elements plus typed gaps."""

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
    counters: Mapping[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class RamFactsBuildResult:
    """One deterministic RAM facts build: payload plus provenance anchors."""

    facts: PythonRamFacts
    provenance_anchor_ids: tuple[str, ...]


def _call_name(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _decorator_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    names: list[str] = []
    for decorator in node.decorator_list:
        value = decorator.func if isinstance(decorator, ast.Call) else decorator
        names.append(_call_name(value))
    return names


def _entry(path: str, symbol: str | None, reason: str) -> AttackSurfaceEntry:
    return AttackSurfaceEntry(
        path=path,
        symbol=symbol,
        reason_codes=(reason,),
        source_artifact_ids=(RAM_PROVENANCE_ANCHOR,),
    )


def _collect_entrypoints(analyzer: PythonDataflowAnalyzer) -> list[AttackSurfaceEntry]:
    entries: list[AttackSurfaceEntry] = []
    for info in analyzer.modules.values():
        for node in ast.walk(info.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if any(
                name.split(".")[-1] in ENDPOINT_DECORATORS
                for name in _decorator_names(node)
            ):
                entries.append(_entry(info.path, node.name, _ENTRYPOINT_REASON))
    return entries


def _collect_sources(
    analyzer: PythonDataflowAnalyzer,
) -> list[tuple[AttackSurfaceEntry, str]]:
    hits: dict[tuple[str, int, str | None], tuple[str, str]] = {}
    for info in analyzer.modules.values():
        for node in ast.walk(info.tree):
            if isinstance(node, ast.Call):
                name = _call_name(node.func)
                if name in DIRECT_SOURCE_CALLS:
                    key = (info.path, node.lineno, None)
                    hits.setdefault(key, (name, DIRECT_SOURCE_CALLS[name]))
                    continue
                if isinstance(node.func, ast.Attribute):
                    for suffix in _SOURCE_SUFFIX_KEYS:
                        if name.endswith(suffix):
                            key = (info.path, node.lineno, None)
                            hits.setdefault(
                                key, (name, REQUEST_SOURCE_SUFFIXES[suffix])
                            )
                            break
            elif isinstance(node, ast.Attribute):
                name = _call_name(node)
                last = name.split(".")[-1]
                if last in REQUEST_SOURCE_ATTRIBUTES:
                    key = (info.path, node.lineno, None)
                    hits.setdefault(
                        key, (name, REQUEST_SOURCE_ATTRIBUTES[last])
                    )
    result: list[tuple[AttackSurfaceEntry, str]] = []
    for (path, line, _), (_name, label) in hits.items():
        result.append((_entry(path, None, _SOURCE_REASON), label))
    return result


def build_python_ram_facts(
    workspace: RepositoryWorkspace,
    *,
    budgets: RamBudgets | None = None,
) -> RamFactsBuildResult:
    """Build deterministic Python RAM facts from a read-only workspace."""
    if not isinstance(workspace, RepositoryWorkspace):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    effective_budgets = RamBudgets() if budgets is None else budgets

    inventory = workspace.inventory()
    python_paths = sorted(
        item.path for item in inventory.files if item.path.endswith(".py")
    )
    gaps: list[tuple[str, str]] = []
    if len(python_paths) > effective_budgets.max_python_files:
        overflow = len(python_paths) - effective_budgets.max_python_files
        gaps.append(("BUDGET_EXHAUSTED", _BUDGET_FILE_LIMIT.format(count=overflow)))
        python_paths = python_paths[: effective_budgets.max_python_files]

    files: dict[str, str] = {}
    for relative_path in python_paths:
        try:
            files[relative_path] = workspace.read_text(relative_path)
        except Exception:
            gaps.append(
                ("INVENTORY_SKIPPED", _GAP_READ_FAILED.format(path=relative_path))
            )

    analyzer = PythonDataflowAnalyzer(max_call_depth=4)
    result = analyzer.analyze_project(files)

    entrypoints = _collect_entrypoints(analyzer)
    sources = _collect_sources(analyzer)

    sinks = [
        _entry(finding.path, None, _SINK_REASON) for finding in result.findings
    ]
    sink_rule_ids = tuple(finding.rule_id for finding in result.findings)
    sink_cwes = tuple(finding.cwe for finding in result.findings)

    boundary_paths = {entry.path for entry in entrypoints}
    boundary_paths.update(entry.path for entry, _label in sources)
    trust_boundaries = [
        _entry(path, None, _BOUNDARY_REASON) for path in sorted(boundary_paths)
    ]

    key_flows: list[RamKeyFlow] = [
        RamKeyFlow(
            sink_rule_id=finding.rule_id,
            steps=tuple(
                f"{record.path}:{record.line}"
                for record in finding.evidence_records
            ),
        )
        for finding in result.findings
    ]
    key_flows.sort(key=lambda flow: (flow.sink_rule_id, flow.steps))
    if len(key_flows) > effective_budgets.max_key_flows:
        overflow = len(key_flows) - effective_budgets.max_key_flows
        gaps.append(("BUDGET_EXHAUSTED", _BUDGET_KEY_FLOW_LIMIT.format(count=overflow)))
        key_flows = key_flows[: effective_budgets.max_key_flows]

    edge_sites = sorted(analyzer.unresolved_call_sites)
    unresolved_edges = [
        _entry(path, name, _EDGE_REASON) for path, _line, name in edge_sites
    ]
    if len(unresolved_edges) > effective_budgets.max_unresolved_edges:
        overflow = len(unresolved_edges) - effective_budgets.max_unresolved_edges
        gaps.append(("BUDGET_EXHAUSTED", _BUDGET_EDGE_LIMIT.format(count=overflow)))
        unresolved_edges = unresolved_edges[: effective_budgets.max_unresolved_edges]

    if analyzer.dynamic_import_sites:
        gaps.append(
            (
                GAP_DYNAMIC_IMPORT,
                _GAP_DYNAMIC_IMPORT_DETAIL.format(
                    count=len(analyzer.dynamic_import_sites)
                ),
            )
        )
    if result.ambiguous_modules:
        gaps.append(
            (
                GAP_AMBIGUOUS_DISPATCH,
                _GAP_AMBIGUOUS_DETAIL.format(count=result.ambiguous_modules),
            )
        )

    gaps.sort(key=lambda pair: (pair[0], pair[1].encode("utf-8")))
    facts = PythonRamFacts(
        entrypoints=tuple(sorted(entrypoints, key=lambda e: (e.path, e.symbol or ""))),
        external_sources=tuple(
            sorted((entry for entry, _ in sources), key=lambda e: (e.path, e.symbol or ""))
        ),
        source_labels=tuple(
            label for _entry_item, label in sorted(
                sources, key=lambda pair: (pair[0].path, pair[0].symbol or "")
            )
        ),
        sensitive_sinks=tuple(sorted(sinks, key=lambda e: (e.path, e.symbol or ""))),
        sink_rule_ids=sink_rule_ids,
        sink_cwes=sink_cwes,
        trust_boundaries=tuple(sorted(trust_boundaries, key=lambda e: (e.path, e.symbol or ""))),
        key_flows=tuple(key_flows),
        unresolved_edges=tuple(
            sorted(unresolved_edges, key=lambda e: (e.path, e.symbol or ""))
        ),
        coverage_gaps=tuple(
            ProfileCoverageGap(gap_code=code, detail=detail) for code, detail in gaps
        ),
        counters=MappingProxyType(
            {
                "dynamic_import_sites": len(analyzer.dynamic_import_sites),
                "ambiguous_modules": result.ambiguous_modules,
                "unresolved_calls": result.unresolved_calls,
                "modules_indexed": result.modules_indexed,
                "functions_indexed": result.functions_indexed,
                "interprocedural_edges": result.interprocedural_edges,
                "cross_file_edges": result.cross_file_edges,
                "parse_error_files": len(result.parse_errors),
            }
        ),
    )
    return RamFactsBuildResult(facts=facts, provenance_anchor_ids=(RAM_PROVENANCE_ANCHOR,))


def ram_facts_digest(facts: PythonRamFacts) -> str:
    """Return the 64-hex deterministic digest of one facts payload."""
    payload = {
        "entrypoints": [entry.to_dict() for entry in facts.entrypoints],
        "external_sources": [entry.to_dict() for entry in facts.external_sources],
        "source_labels": list(facts.source_labels),
        "sensitive_sinks": [entry.to_dict() for entry in facts.sensitive_sinks],
        "sink_rule_ids": list(facts.sink_rule_ids),
        "sink_cwes": list(facts.sink_cwes),
        "trust_boundaries": [entry.to_dict() for entry in facts.trust_boundaries],
        "key_flows": [
            {"sink_rule_id": flow.sink_rule_id, "steps": list(flow.steps)}
            for flow in facts.key_flows
        ],
        "unresolved_edges": [entry.to_dict() for entry in facts.unresolved_edges],
        "coverage_gaps": [gap.to_dict() for gap in facts.coverage_gaps],
        "counters": {key: facts.counters[key] for key in sorted(facts.counters)},
    }
    return compute_content_digest(payload)
