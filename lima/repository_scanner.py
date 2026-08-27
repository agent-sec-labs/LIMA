"""Deterministic full-repository scanning baseline for LIMA."""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Iterable, Optional

from .cxx_memory import (
    REQUESTED_LAYERS,
    CxxAnalyzerProtocolError,
    CxxAnalyzerUnavailable,
    CxxMemoryAdapter,
)
from .diff_parser import parse_unified_diff
from .models import Finding, ReviewReport, Severity
from .python_analyzer import PythonAstSecurityAnalyzer
from .python_dataflow import PythonDataflowAnalyzer
from .reviewer import Reviewer, SecurityRuleReviewer
from .sast import BanditAdapter, SastAdapter
from .workspace import CXX_SOURCE_EXTENSIONS, RepositoryWorkspace, WorkspaceInventory

SEVERITY_RANK = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
VERIFICATION_RANK = {
    "candidate": 0,
    "syntax-verified": 1,
    "corroborated": 2,
    "dataflow-verified": 3,
    "build-verified": 3,
    "confirmed": 4,
}


@dataclass
class RepositoryScanResult:
    report: ReviewReport
    inventory: WorkspaceInventory

    def to_dict(self) -> dict:
        value = self.report.to_dict()
        value["workspace"] = self.inventory.to_dict()
        return value


def _full_file_diff(path: str, content: str) -> str:
    """Represent a repository file as added lines for existing diff reviewers."""
    return "\n".join(
        difflib.unified_diff(
            [], content.splitlines(), fromfile="/dev/null", tofile="b/" + path,
            lineterm="",
        )
    )


class RepositoryScanner:
    """Run bounded local reviewers across a read-only repository snapshot."""

    def __init__(
        self,
        reviewers: Optional[Iterable[Reviewer]] = None,
        *,
        sast_mode: str = "auto",
        sast_adapters: Optional[Iterable[SastAdapter]] = None,
        dataflow_enabled: bool = True,
        cxx_memory_mode: str = "off",
        cxx_memory_adapter: Optional[CxxMemoryAdapter] = None,
        cxx_requested_layers: tuple[str, ...] = REQUESTED_LAYERS,
    ) -> None:
        self.reviewers = list(
            reviewers or [SecurityRuleReviewer()]
        )
        if not self.reviewers:
            raise ValueError("at least one repository reviewer is required")
        if sast_mode not in {"auto", "off", "required"}:
            raise ValueError("sast_mode must be auto, off or required")
        if cxx_memory_mode not in {"auto", "off", "required"}:
            raise ValueError("cxx_memory_mode must be auto, off or required")
        self.python_analyzer = PythonAstSecurityAnalyzer()
        self.python_dataflow = PythonDataflowAnalyzer()
        self.dataflow_enabled = bool(dataflow_enabled)
        self.sast_mode = sast_mode
        self.sast_adapters = list(sast_adapters) if sast_adapters is not None else [BanditAdapter()]
        self.cxx_memory_mode = cxx_memory_mode
        self.cxx_memory_adapter = cxx_memory_adapter
        self.cxx_requested_layers = cxx_requested_layers

    @staticmethod
    def _semantic_key(finding: Finding) -> tuple[str, int, str]:
        return (finding.path, finding.line, finding.cwe or finding.rule_id)

    @classmethod
    def _merge_finding(
        cls, findings: list[Finding], index: dict[tuple[str, int, str], Finding],
        candidate: Finding,
    ) -> bool:
        key = cls._semantic_key(candidate)
        existing = index.get(key)
        if existing is None:
            index[key] = candidate
            findings.append(candidate)
            return False
        sources = sorted(set(existing.source.split("+")) | set(candidate.source.split("+")))
        corroborated = len(sources) > len(set(existing.source.split("+")))
        existing.source = "+".join(sources)
        if corroborated:
            existing.confidence = min(0.99, max(existing.confidence, candidate.confidence) + 0.03)
            known_evidence = {
                (item.source, item.kind, item.rule_id, item.path, item.line, item.snippet)
                for item in existing.evidence_records
            }
            for evidence in candidate.evidence_records:
                identity = (
                    evidence.source, evidence.kind, evidence.rule_id,
                    evidence.path, evidence.line, evidence.snippet,
                )
                if identity not in known_evidence:
                    existing.evidence_records.append(evidence)
                    known_evidence.add(identity)
        candidate_state = candidate.verification_state
        suggested_state = "corroborated" if corroborated else existing.verification_state
        existing.verification_state = max(
            (existing.verification_state, candidate_state, suggested_state),
            key=lambda item: VERIFICATION_RANK.get(item, 0),
        )
        if existing.verification_state == "dataflow-verified":
            existing.evidence_kind = "source-to-sink"
        elif existing.verification_state == "corroborated":
            existing.evidence_kind = "corroborated"
        if SEVERITY_RANK[candidate.severity] > SEVERITY_RANK[existing.severity]:
            existing.severity = candidate.severity
        return corroborated

    @staticmethod
    def _cxx_semantic_key(finding: Finding) -> tuple[str, str, str, int]:
        return (
            finding.cwe,
            PurePosixPath(finding.path).as_posix(),
            finding.symbol,
            finding.line,
        )

    @classmethod
    def _merge_cxx_finding(
        cls,
        findings: list[Finding],
        index: dict[tuple[str, str, str, int], Finding],
        candidate: Finding,
    ) -> None:
        candidate.automatic_repair = False
        key = cls._cxx_semantic_key(candidate)
        existing = index.get(key)
        if existing is None:
            index[key] = candidate
            findings.append(candidate)
            return

        existing.source = "+".join(sorted(
            set(existing.source.split("+")) | set(candidate.source.split("+"))
        ))
        known_evidence = {
            (item.source, item.kind, item.rule_id, item.path, item.line, item.snippet)
            for item in existing.evidence_records
        }
        for evidence in candidate.evidence_records:
            identity = (
                evidence.source, evidence.kind, evidence.rule_id,
                evidence.path, evidence.line, evidence.snippet,
            )
            if identity not in known_evidence:
                existing.evidence_records.append(evidence)
                known_evidence.add(identity)

        if (
            VERIFICATION_RANK.get(candidate.verification_state, 0)
            > VERIFICATION_RANK.get(existing.verification_state, 0)
        ):
            existing.verification_state = candidate.verification_state
            existing.analysis_mode = candidate.analysis_mode
            existing.evidence_kind = candidate.evidence_kind
        existing.confidence = max(existing.confidence, candidate.confidence)
        if SEVERITY_RANK[candidate.severity] > SEVERITY_RANK[existing.severity]:
            existing.severity = candidate.severity

    def scan(
        self, workspace: RepositoryWorkspace, *, repository_key: str = ""
    ) -> RepositoryScanResult:
        inventory = workspace.inventory()
        findings: list[Finding] = []
        finding_index: dict[tuple[str, int, str], Finding] = {}
        cxx_finding_index: dict[tuple[str, str, str, int], Finding] = {}
        python_parse_errors = 0
        dataflow_parse_errors = 0
        dataflow_functions_indexed = 0
        interprocedural_call_edges = 0
        interprocedural_truncated_calls = 0
        unresolved_dataflow_calls = 0
        dataflow_modules_indexed = 0
        cross_file_call_edges = 0
        dynamic_import_sites = 0
        ambiguous_python_modules = 0

        repository_files = list(workspace.iter_text(inventory))
        project_dataflow = None
        if self.dataflow_enabled:
            project_dataflow = self.python_dataflow.analyze_project({
                path: content for path, content in repository_files
                if path.endswith(".py")
            })
            dataflow_parse_errors = len(project_dataflow.parse_errors)
            dataflow_functions_indexed = project_dataflow.functions_indexed
            interprocedural_call_edges = project_dataflow.interprocedural_edges
            interprocedural_truncated_calls = project_dataflow.truncated_calls
            unresolved_dataflow_calls = project_dataflow.unresolved_calls
            dataflow_modules_indexed = project_dataflow.modules_indexed
            cross_file_call_edges = project_dataflow.cross_file_edges
            dynamic_import_sites = project_dataflow.dynamic_import_sites
            ambiguous_python_modules = project_dataflow.ambiguous_modules

        for path, content in repository_files:
            diff = _full_file_diff(path, content)
            if not diff:
                continue
            parsed = parse_unified_diff(diff)
            file_findings: list[Finding] = []
            reviewers = self.reviewers
            if path.endswith(".py"):
                analysis = self.python_analyzer.analyze(path, content)
                file_findings.extend(analysis.findings)
                if analysis.parse_error:
                    python_parse_errors += 1
                reviewers = [
                    item for item in reviewers
                    if not isinstance(item, SecurityRuleReviewer)
                ]
            for reviewer in reviewers:
                file_findings.extend(reviewer.review(diff, parsed))
            for finding in file_findings:
                self._merge_finding(findings, finding_index, finding)

        if project_dataflow:
            for finding in project_dataflow.findings:
                self._merge_finding(findings, finding_index, finding)

        sast_summary: dict[str, dict] = {}
        completed_sast = []
        if self.sast_mode != "off":
            for adapter in self.sast_adapters:
                result = adapter.scan(workspace, inventory)
                sast_summary[result.engine] = result.summary()
                if result.status == "completed":
                    completed_sast.append(result.engine)
                elif self.sast_mode == "required":
                    raise RuntimeError(
                        "required SAST engine %s is %s: %s"
                        % (result.engine, result.status, result.diagnostic)
                    )
                for finding in result.findings:
                    self._merge_finding(findings, finding_index, finding)

        cxx_summary = {
            "status": "disabled" if self.cxx_memory_mode == "off" else "not-applicable",
            "mode": self.cxx_memory_mode,
            "requested_layers": list(self.cxx_requested_layers),
            "tool_runs": [],
            "coverage": {},
            "diagnostics": [],
        }
        has_cxx_source = any(
            PurePosixPath(item.path).suffix.lower() in CXX_SOURCE_EXTENSIONS
            for item in inventory.files
        )
        if self.cxx_memory_mode != "off" and has_cxx_source:
            try:
                if self.cxx_memory_adapter is None:
                    raise CxxAnalyzerUnavailable("C/C++ analyzer is not configured")
                cxx_result = self.cxx_memory_adapter.analyze(
                    repository_key,
                    inventory.fingerprint(),
                    self.cxx_requested_layers,
                )
            except CxxAnalyzerUnavailable as exc:
                if self.cxx_memory_mode == "required":
                    raise RuntimeError(
                        "required C/C++ memory analyzer is unavailable"
                    ) from exc
                cxx_summary.update({
                    "status": "unavailable",
                    "diagnostics": ["C/C++ memory analyzer is unavailable"],
                })
            except CxxAnalyzerProtocolError as exc:
                if self.cxx_memory_mode == "required":
                    raise RuntimeError(
                        "required C/C++ memory analyzer returned an invalid response"
                    ) from exc
                cxx_summary.update({
                    "status": "invalid-response",
                    "diagnostics": ["C/C++ memory analyzer response was rejected"],
                })
            else:
                cxx_summary.update({
                    "status": cxx_result.status,
                    "tool_runs": cxx_result.tool_runs,
                    "coverage": cxx_result.coverage,
                    "diagnostics": cxx_result.diagnostics,
                })
                for finding in cxx_result.findings:
                    self._merge_cxx_finding(findings, cxx_finding_index, finding)

        findings.sort(
            key=lambda item: (
                -SEVERITY_RANK[item.severity], item.path, item.line, item.rule_id
            )
        )
        highest = max((SEVERITY_RANK[item.severity] for item in findings), default=0)
        risk = {0: "low", 1: "low", 2: "medium", 3: "high", 4: "critical"}[highest]
        summary = (
            "Scanned %d UTF-8 source files (%d bytes) with AST%s%s and found "
            "%d actionable candidate%s."
            % (
                len(inventory.files), inventory.total_bytes,
                " + repository dataflow" if self.dataflow_enabled else "",
                (" + " + "+".join(completed_sast)) if completed_sast else "",
                len(findings),
                "" if len(findings) == 1 else "s",
            )
        )
        corroborated_findings = sum(
            len(set(item.source.split("+"))) > 1 for item in findings
        )
        dataflow_verified_findings = sum(
            item.verification_state == "dataflow-verified" for item in findings
        )
        report = ReviewReport(
            repository=str(workspace.root),
            pull_request=None,
            summary=summary,
            risk=risk,
            findings=findings,
            files_reviewed=[item.path for item in inventory.files],
            reviewer="repository-hybrid:python-ast"
            + ("+python-dataflow" if self.dataflow_enabled else "")
            + (("+" + "+".join(completed_sast)) if completed_sast else ""),
            collaboration={
                "mode": "hybrid-repository-scan",
                "scanned_files": len(inventory.files),
                "scanned_bytes": inventory.total_bytes,
                "workspace_truncated": inventory.truncated,
                "python_parse_errors": python_parse_errors,
                "dataflow_parse_errors": dataflow_parse_errors,
                "dataflow_enabled": self.dataflow_enabled,
                "dataflow_scope": "repository-static-imports",
                "dataflow_modules_indexed": dataflow_modules_indexed,
                "dataflow_functions_indexed": dataflow_functions_indexed,
                "interprocedural_call_edges": interprocedural_call_edges,
                "cross_file_call_edges": cross_file_call_edges,
                "interprocedural_truncated_calls": interprocedural_truncated_calls,
                "unresolved_dataflow_calls": unresolved_dataflow_calls,
                "dynamic_import_sites": dynamic_import_sites,
                "ambiguous_python_modules": ambiguous_python_modules,
                "dataflow_verified_findings": dataflow_verified_findings,
                "corroborated_findings": corroborated_findings,
                "candidate_findings": sum(
                    item.verification_state == "candidate" for item in findings
                ),
                "sast": sast_summary,
                "cxx_memory": cxx_summary,
                "skipped": dict(sorted(inventory.skipped.items())),
            },
        )
        return RepositoryScanResult(report=report, inventory=inventory)
