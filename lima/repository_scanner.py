"""Deterministic full-repository scanning baseline for LIMA."""

from __future__ import annotations

import difflib
import json
import time
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
from typing import Callable, Final, Iterable, Optional

from .adjudication import adjudicate_findings
from .agent_orchestrator import (
    PLATFORM_SOURCE_NAME,
    platform_rule_id,
    run_platform_review,
)
from .agent_repro_tools import ReproWorkbench
from .contracts.codec import compute_content_digest
from .cxx_agent_tools import CxxAgentBudget
from .cxx_memory import (
    MAX_UAF_TRANSLATION_UNITS,
    REQUESTED_LAYERS,
    CxxAnalysisResult,
    CxxAnalyzerProtocolError,
    CxxAnalyzerUnavailable,
    CxxMemoryAdapter,
)
from .diff_parser import parse_unified_diff
from .metrics import metrics
from .models import Finding, ReviewReport, Severity
from .platform_contracts import privacy_text, seal_platform_review
from .python_analyzer import PythonAstSecurityAnalyzer
from .python_dataflow import PythonDataflowAnalyzer
from .reviewer import Reviewer, SecurityRuleReviewer
from .sast import BanditAdapter, SastAdapter
from .task_progress import (
    AST_ANALYSIS,
    DATAFLOW_ANALYSIS,
    INVENTORY,
    SAST_ANALYSIS,
)
from .uaf_orchestrator import UAF_STATE_CONFIDENCE
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
    "tool-corroborated": 2,
    "dataflow-verified": 3,
    "build-verified": 3,
    # UAF v2 states (design section 5).  No legacy path emits them, so the
    # ranks only decide UAF-involving merges: D2 static proof ranks with
    # the other build/dataflow-verified tiers, D3 runtime with "confirmed".
    "fact-verified": 3,
    "runtime-confirmed": 4,
    "confirmed": 4,
}

# Diff-only/降级语义沿用 legacy：needs-human-review 与 semantic-supported
# 不是 verified 状态（rank 0），永不越过上面的离散门禁。

# 冻结决策（Epic #33）：任何 coverage-affecting skip ≥ 1 即标记
# completed_with_warnings，不做可配置阈值。ignored-directory 与
# unsupported-extension 属于既定扫描范围（node_modules、图片等），不算覆盖损失。
COVERAGE_AFFECTING_SKIPS = frozenset({
    "symlink",
    "unreadable",
    "file-size-limit",
    "file-limit",
    "total-size-limit",
    "binary",
    "non-utf8",
})

# AST 逐文件进度的双门限节流（文件数或时间先到即发）。
AST_PROGRESS_FILE_INTERVAL = 25
AST_PROGRESS_TIME_INTERVAL_SECONDS = 0.5

ProgressCallback = Callable[..., None]


def coverage_warning_counts(inventory: WorkspaceInventory) -> dict[str, int]:
    """Skip counts that reduced actually-scanned coverage, keyed by reason."""

    return {
        reason: count
        for reason, count in sorted(inventory.skipped.items())
        if reason in COVERAGE_AFFECTING_SKIPS and count > 0
    }


def _report(
    callback: ProgressCallback | None, stage: str, message: str, **detail: object
) -> None:
    if callback is not None:
        callback(stage, message, **detail)


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
        cxx_agent_mode: str = "off",
        cxx_agent_budget_factory: Callable[[], CxxAgentBudget] | None = None,
        should_cancel: Callable[[], bool] | None = None,
        cxx_uaf_llm_factory: Callable[[], dict] | None = None,
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
        if cxx_agent_mode not in {"auto", "off", "required"}:
            raise ValueError("cxx_agent_mode must be auto, off or required")
        self.python_analyzer = PythonAstSecurityAnalyzer()
        self.python_dataflow = PythonDataflowAnalyzer()
        self.dataflow_enabled = bool(dataflow_enabled)
        self.sast_mode = sast_mode
        self.sast_adapters = list(sast_adapters) if sast_adapters is not None else [BanditAdapter()]
        self.cxx_memory_mode = cxx_memory_mode
        self.cxx_memory_adapter = cxx_memory_adapter
        self.cxx_requested_layers = cxx_requested_layers
        self.cxx_agent_mode = cxx_agent_mode
        self.cxx_agent_budget_factory = cxx_agent_budget_factory
        self.should_cancel = should_cancel
        self.cxx_uaf_llm_factory = cxx_uaf_llm_factory

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

    _PLATFORM_TITLES = {
        "CWE-416": "Use-after-free: pointer dereferenced after release",
        "CWE-415": "Double free: object released twice",
        "CWE-787": "Out-of-bounds write past the allocated region",
        "CWE-125": "Out-of-bounds read past the allocated region",
    }

    def _platform_finding(self, item) -> Finding:
        """Project one platform outcome target onto the Finding shape.

        ``state`` 即 Arbiter 终态（冻结状态机复用）；C++ Finding 永不自动
        修复（设计不变量）；candidate_id 与实验台账提供可审计身份。
        """

        title = self._PLATFORM_TITLES.get(
            item.cwe, f"{item.cwe} suspected by agent analysis",
        )
        # Review feedback round 3: free LLM text is privacy-redacted (#94
        # reuse) before it becomes report-bound Finding.explanation.
        explanation = privacy_text(item.hypothesis_reason)
        if item.experiment_log:
            hits = sum(
                1 for entry in item.experiment_log if entry.get("hit")
            )
            explanation += (
                f"; reproduction experiments: {len(item.experiment_log)} "
                f"run, {hits} hit"
            )
        if item.proof_verdict:
            explanation += f"; deterministic proof verdict {item.proof_verdict}"
        finding = Finding(
            rule_id=platform_rule_id(item.cwe),
            severity=Severity.HIGH,
            title=title,
            explanation=explanation[:2000],
            path=item.path,
            line=item.line,
            evidence=(
                f"agent hypothesis at {item.path}:{item.line}; "
                f"experiments {len(item.experiment_log)}; state {item.state}"
            ),
            fix="",
            test="Run the recorded PoC driver under AddressSanitizer.",
            confidence=UAF_STATE_CONFIDENCE.get(item.state, 0.5),
            cwe=item.cwe,
            source=PLATFORM_SOURCE_NAME,
            evidence_kind=(
                "runtime-asan"
                if item.state == "runtime-confirmed"
                else "proof"
                if item.state == "fact-verified"
                else "hypothesis"
            ),
            verification_state=item.state,
            # Review round 5: ASan raw tails ride in EvidenceRecord.snippet;
            # mask them before the record copies reach the report.
            evidence_records=[
                replace(record, snippet=privacy_text(record.snippet))
                for record in item.evidence_records
            ],
            language="c++",
            symbol=item.symbol,
            analysis_mode=PLATFORM_SOURCE_NAME,
            automatic_repair=False,
            candidate_id=(
                item.identity.candidate_id
                if item.identity is not None
                else ""
            ),
            trigger_path=[f"{item.path}:{item.line}"],
        )
        return finding

    def _platform_collaboration(
        self, mode: str, status: str, outcome, v4: dict | None = None,
    ) -> dict:
        """The collaboration.platform audit payload (platform design §6)."""

        states: dict[str, int] = {}
        for item in outcome.targets:
            states[item.state] = states.get(item.state, 0) + 1
        broker_counts: dict[str, int] = {}
        for item in outcome.targets:
            for verdict in item.broker_verdicts:
                broker_counts[verdict.verdict] = (
                    broker_counts.get(verdict.verdict, 0) + 1
                )
        stats = outcome.stats
        audit = []
        for item in outcome.targets[:32]:
            audit.append({
                "target_id": item.target_id,
                "path": item.path,
                "line": item.line,
                "state": item.state,
                "cwe": item.cwe,
                "proof": item.proof_verdict,
                "experiments": len(item.experiment_log),
                # Review round 4: every free-text report exit (including
                # rejection reasons) passes the #94 privacy mask.
                "rejected_reason": privacy_text(item.rejected_reason),
            })
        payload = {
            "mode": mode,
            "status": status,
            "translation_units": list(outcome.translation_units),
            "stats": {
                "leads": stats.lead_count,
                "targets": stats.target_count,
                "findings": stats.finding_count,
                "experiments": stats.experiment_count,
                "specialist_calls": stats.specialist_calls,
                "critic_calls": stats.critic_calls,
                "scout_calls": stats.scout_calls,
            },
            "states": states,
            "broker": broker_counts,
            # Review round 4: diagnostics are free text too -- mask them.
            "diagnostics": [privacy_text(item) for item in outcome.diagnostics],
            "targets": audit,
        }
        if v4 is not None:
            payload["v4"] = v4
        return payload

    _V4_PAYLOAD_BUDGET_BYTES: Final = 512 * 1024

    @staticmethod
    def _platform_required_error(prefix: str, exc: Exception) -> RuntimeError:
        """Review round 5: required failures carry masked free text only.

        The raised error reaches the task failure payload, dead-letter
        queue and alerts verbatim, so the exception text passes the #94
        mask before the raise (mask first, then bound -- truncating first
        would cut secrets below the detection threshold); the cause chain
        keeps the original for local debugging without persisting it.
        """

        return RuntimeError(f"{prefix}: {privacy_text(str(exc))[:300]}")

    @staticmethod
    def _seal_platform_v4(outcome, repository_key: str, inventory) -> dict:
        """Seal the platform review into a report-embedded V4 preview.

        Review-feedback semantics (PR #183 round 2):

        - **Report-embedded preview, not an artifact store.** The whole
          projection lives inside the task report
          (``collaboration.platform.v4``): there is no independent
          artifact persistence, the repair-verification converter
          (``patch_outcome_to_rvr``) has no runtime caller yet, the
          oracle reference is a payload-level digest pin over the PoC
          driver bytes, and the workflow/security-outcome/profile links
          remain stand-ins.  Downstream stages must not treat this as
          the independently consumable V4 artifact chain.
        - **No unretrievable references under a full seal.** ``status``
          is ``sealed`` only when every referenced id (the AEP plus
          every listed VEP) carries a retrievable, digest-verifiable
          payload.  Byte-budget omissions downgrade the status to
          ``partial`` and every id without a payload is listed
          explicitly in ``omitted_payload_ids``.
        - **Optional projection.** Sealing never blocks task completion
          and never alters detection results; ``seal-failed`` records
          the bounded reason instead.  Consumers may only consume
          payloads from ``sealed``/``partial`` states and must verify
          each payload against its recorded digest.
        """

        budget = RepositoryScanner._V4_PAYLOAD_BUDGET_BYTES
        try:
            bundle = seal_platform_review(
                outcome,
                snapshot_sha256=inventory.fingerprint(),
                repository=repository_key,
            )
        except Exception as exc:  # noqa: BLE001 - bounded honest degradation
            metrics.inc("repository_scan_platform_v4_seal_failed_total")
            return {
                "status": "seal-failed",
                "availability": "report-embedded",
                "diagnostics": [privacy_text(str(exc))[:300]],
            }
        veps = []
        payloads: dict[str, dict] = {}
        omitted: list[str] = []
        payload_bytes = 0
        aep_payload = bundle.aep.to_dict()
        aep_bytes = len(json.dumps(aep_payload, sort_keys=True))
        if aep_bytes > budget:
            omitted.append(bundle.aep_artifact_id)
        else:
            payloads[bundle.aep_artifact_id] = aep_payload
            payload_bytes += aep_bytes
        for vep in bundle.veps:
            payload_dict = vep.to_dict()
            veps.append({
                "artifact_id": vep.hypothesis_id,
                "content_digest": compute_content_digest(payload_dict),
                "verification_verdict": vep.verification_verdict.value,
            })
            encoded = len(json.dumps(payload_dict, sort_keys=True))
            if payload_bytes + encoded > budget:
                omitted.append(vep.hypothesis_id)
                continue
            payloads[vep.hypothesis_id] = payload_dict
            payload_bytes += encoded
        result = {
            "status": "sealed" if not omitted else "partial",
            "availability": "report-embedded",
            "aep": {
                "artifact_id": bundle.aep_artifact_id,
                "content_digest": bundle.aep_content_digest,
                "audit_outcome": bundle.aep.audit_outcome.value,
            },
            "workflow_summary": {
                "execution_status": (
                    bundle.workflow_summary.execution_status.value
                ),
                "content_digest": compute_content_digest(
                    bundle.workflow_summary.to_dict()
                ),
            },
            "veps": veps,
            "payloads": payloads,
        }
        if omitted:
            result["omitted_payload_ids"] = omitted
        return result

    def _run_platform_branch(
        self,
        workspace: RepositoryWorkspace,
        inventory: WorkspaceInventory,
        findings: list[Finding],
        tool_analysis: CxxAnalysisResult | None,
        cxx_finding_index: dict[tuple[str, str, str, int], Finding],
        repository_key: str,
        cancel_probe: Callable[[], bool] | None,
    ) -> dict:
        """Run the single agent platform chain for the facts domain.

        设计（agent-vuln-platform §6/§10）：智能体是检测主体。线索由
        analyzer facts 的 release 事件生成（platform 编排内部完成），Scout
        升级目标，Specialist 假设 → 沙箱 ASan 实验 → Critic 修正循环，
        事实/证明作为可咨询仪器进入冻结 Arbiter。legacy 分支域
        （CWE-787/125/415）不受影响；analyzer client 缺失时如实跳过。
        """

        mode = self.cxx_agent_mode
        if mode == "off":
            return {"mode": "off", "status": "disabled"}
        adapter = self.cxx_memory_adapter
        if not callable(getattr(adapter, "analyze_uaf_facts", None)):
            return {"mode": mode, "status": "analyzer-not-configured"}
        translation_units = tuple(sorted({
            PurePosixPath(item.path).as_posix()
            for item in inventory.files
            if PurePosixPath(item.path).suffix.lower() in CXX_SOURCE_EXTENSIONS
        }))[:MAX_UAF_TRANSLATION_UNITS]
        if not translation_units:
            return {"mode": mode, "status": "no-cxx-sources"}
        budget = (
            self.cxx_agent_budget_factory()
            if self.cxx_agent_budget_factory is not None
            else CxxAgentBudget()
        )
        llm_config = (
            dict(self.cxx_uaf_llm_factory())
            if self.cxx_uaf_llm_factory is not None
            else {}
        )
        if not llm_config:
            if mode == "required":
                raise RuntimeError(
                    "required platform review has no configured LLM provider"
                )
            return {"mode": mode, "status": "llm-not-configured"}
        workbench = (
            ReproWorkbench(adapter, budget)
            if callable(getattr(adapter, "repro_compile_run", None))
            else None
        )
        try:
            outcome = run_platform_review(
                adapter,
                workspace,
                repository_key=repository_key,
                snapshot_hash=inventory.fingerprint(),
                translation_units=translation_units,
                mode=mode,
                budget=budget,
                llm_config=llm_config,
                repro_workbench=workbench,
                tool_analysis=tool_analysis,
                should_cancel=cancel_probe,
            )
        except (CxxAnalyzerUnavailable, CxxAnalyzerProtocolError) as exc:
            if mode == "required":
                raise self._platform_required_error(
                    "required platform review failed on the C/C++ analyzer",
                    exc,
                ) from exc
            metrics.inc("repository_scan_platform_unavailable_total")
            return {
                "mode": mode,
                "status": "analyzer-unavailable",
                "diagnostics": [privacy_text(str(exc))[:500]],
            }
        except (RuntimeError, ValueError) as exc:
            if mode == "required":
                raise self._platform_required_error(
                    "required platform review failed", exc
                ) from exc
            metrics.inc("repository_scan_platform_failed_total")
            return {
                "mode": mode,
                "status": "review-failed",
                "diagnostics": [privacy_text(str(exc))[:500]],
            }
        # rejected/abstain 保留在 outcome 审计记录里，不投影为 Finding；
        # 正向状态按冻结状态机输出。合并键是不可变 finding 身份
        # (cwe, path, symbol, line)。
        for item in outcome.findings:
            candidate_finding = self._platform_finding(item)
            candidate_finding.automatic_repair = False
            self._merge_cxx_finding(
                findings, cxx_finding_index, candidate_finding
            )
        v4 = self._seal_platform_v4(outcome, repository_key, inventory)
        return self._platform_collaboration(
            mode, "completed", outcome, v4=v4
        )

    def scan(
        self,
        workspace: RepositoryWorkspace,
        *,
        repository_key: str = "",
        progress_callback: ProgressCallback | None = None,
        task_id: str = "",
        should_cancel: Callable[[], bool] | None = None,
    ) -> RepositoryScanResult:
        _report(progress_callback, INVENTORY, "正在盘点工作区文件")
        inventory = workspace.inventory()
        _report(
            progress_callback, INVENTORY, "工作区盘点完成",
            current=len(inventory.files), total=len(inventory.files), unit="files",
        )
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
            _report(progress_callback, DATAFLOW_ANALYSIS, "正在建立跨文件数据流索引")
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
            _report(
                progress_callback, DATAFLOW_ANALYSIS, "数据流索引建立完成",
                modules=dataflow_modules_indexed,
                functions=dataflow_functions_indexed,
            )

        total_files = len(repository_files)
        last_emit = time.monotonic()
        _report(
            progress_callback, AST_ANALYSIS, "正在逐文件执行 AST 与规则分析",
            current=0, total=total_files, unit="files",
        )
        for index, (path, content) in enumerate(repository_files, start=1):
            diff = _full_file_diff(path, content)
            if diff:
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
            now = time.monotonic()
            if (
                index % AST_PROGRESS_FILE_INTERVAL == 0
                or index == total_files
                or now - last_emit >= AST_PROGRESS_TIME_INTERVAL_SECONDS
            ):
                _report(
                    progress_callback, AST_ANALYSIS,
                    "已分析 %d/%d 个文件" % (index, total_files),
                    current=index, total=total_files, unit="files",
                )
                last_emit = now

        if project_dataflow:
            for finding in project_dataflow.findings:
                self._merge_finding(findings, finding_index, finding)

        sast_summary: dict[str, dict] = {}
        completed_sast = []
        if self.sast_mode != "off":
            for adapter in self.sast_adapters:
                _report(progress_callback, SAST_ANALYSIS, "SAST 引擎运行中")
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
                _report(
                    progress_callback, SAST_ANALYSIS,
                    "SAST 引擎 %s 完成（%s）" % (result.engine, result.status),
                    engine=result.engine,
                )

        cxx_summary = {
            "status": "disabled" if self.cxx_memory_mode == "off" else "not-applicable",
            "mode": self.cxx_memory_mode,
            "requested_layers": list(self.cxx_requested_layers),
            "tool_runs": [],
            "coverage": {},
            "diagnostics": [],
        }
        cxx_result: CxxAnalysisResult | None = None
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
                    inventory=inventory,
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
                    # Review round 6: sidecar diagnostics are free text too.
                "diagnostics": [privacy_text(item) for item in cxx_result.diagnostics],
                })
                for finding in cxx_result.findings:
                    self._merge_cxx_finding(findings, cxx_finding_index, finding)

        # 平台分支是唯一的智能体检测链（设计 §10 单链；retirement Task 1
        # 移除了 legacy 七角色分支）：Scout→假设→实验→修正循环，按
        # (cwe, path, symbol, line) 不可变身份合并进同一份报告。
        cancel_probe = should_cancel if should_cancel is not None else self.should_cancel
        platform_summary = self._run_platform_branch(
            workspace,
            inventory,
            findings,
            cxx_result,
            cxx_finding_index,
            repository_key,
            cancel_probe,
        )

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
                "platform": platform_summary,
                "skipped": dict(sorted(inventory.skipped.items())),
            },
            adjudication=adjudicate_findings(findings),
        )
        return RepositoryScanResult(report=report, inventory=inventory)
