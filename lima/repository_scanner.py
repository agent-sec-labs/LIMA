"""Deterministic full-repository scanning baseline for LIMA."""

from __future__ import annotations

import difflib
import json
import time
from dataclasses import dataclass
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
from .cxx_agent_models import LEGACY_AGENT_CWES, to_agent_finding_payload
from .cxx_agent_tools import CxxAgentBudget
from .cxx_agents import (
    LLM_ROLES,
    SPECIALIST_ROLES,
    CxxAgentCoordinator,
)
from .cxx_context import CxxContextIndex
from .cxx_memory import (
    MAX_UAF_TRANSLATION_UNITS,
    REQUESTED_LAYERS,
    CxxAnalysisResult,
    CxxAnalyzerProtocolError,
    CxxAnalyzerUnavailable,
    CxxMemoryAdapter,
)
from .cxx_retrieval import RetrievalBudget, retrieve_repository
from .diff_parser import parse_unified_diff
from .metrics import metrics
from .models import Finding, ReviewReport, Severity
from .platform_contracts import seal_platform_review
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


class _AgentClientProbe:
    """Recording proxy around one scan's agent client.

    ``step`` 透传给真实 client（预算、门禁、验证都在 client/coordinator 内），
    只记录成功返回的轮数：这是“LLM 是否真正可用”的权威信号——角色状态无法
    区分“空分配跳过（ok）”与“真实分析成功（ok）”，而零成功轮次 + 任一角色
    failed-replaced 即设计规定的 auto 降级/required 失败判据。
    """

    def __init__(self, client: object) -> None:
        self._client = client
        self.succeeded_turns = 0

    @property
    def model(self) -> str:
        return str(getattr(self._client, "model", ""))

    def step(self, role, managed_context, tools, budget, read_paths=None):
        step = self._client.step(
            role, managed_context, tools, budget, read_paths=read_paths,
        )
        self.succeeded_turns += 1
        return step


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
        cxx_agent_client_factory: Callable[[], object] | None = None,
        cxx_agent_budget_factory: Callable[[], CxxAgentBudget] | None = None,
        cxx_agent_max_candidates: int = 100,
        should_cancel: Callable[[], bool] | None = None,
        cxx_agent_store: object = None,
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
        if (
            isinstance(cxx_agent_max_candidates, bool)
            or not isinstance(cxx_agent_max_candidates, int)
            or cxx_agent_max_candidates <= 0
        ):
            raise ValueError("cxx_agent_max_candidates must be a positive integer")
        self.cxx_agent_max_candidates = cxx_agent_max_candidates
        self.python_analyzer = PythonAstSecurityAnalyzer()
        self.python_dataflow = PythonDataflowAnalyzer()
        self.dataflow_enabled = bool(dataflow_enabled)
        self.sast_mode = sast_mode
        self.sast_adapters = list(sast_adapters) if sast_adapters is not None else [BanditAdapter()]
        self.cxx_memory_mode = cxx_memory_mode
        self.cxx_memory_adapter = cxx_memory_adapter
        self.cxx_requested_layers = cxx_requested_layers
        self.cxx_agent_mode = cxx_agent_mode
        self.cxx_agent_client_factory = cxx_agent_client_factory
        self.cxx_agent_budget_factory = cxx_agent_budget_factory
        self.should_cancel = should_cancel
        self.cxx_agent_store = cxx_agent_store
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

    def _agent_finding(
        self, candidate, specialist_roles: dict[str, list[str]],
    ) -> Finding:
        payload = to_agent_finding_payload(candidate)
        # 两来源并存红线：agent finding 不与 Sidecar merge，candidate_id 是
        # 唯一身份键；报告以 source 区分来源。
        payload["source"] = "cxx-agent"
        payload["candidate_id"] = candidate.candidate_id
        payload["agent_role"] = "+".join(
            sorted(set(specialist_roles.get(candidate.candidate_id, ())))
        )
        payload["trigger_path"] = list(candidate.trigger_path)
        return Finding(**payload)

    def _cxx_agent_collaboration(
        self,
        mode: str,
        status: str,
        client: object,
        review: object,
        retrieval: object,
        budget: CxxAgentBudget,
    ) -> dict:
        remaining = budget.remaining()
        summary: dict = {
            "mode": mode,
            "model": getattr(client, "model", ""),
            "status": status,
            "budget": {
                "max_calls": budget.max_calls,
                "max_context_files": budget.max_context_files,
                "max_context_lines": budget.max_context_lines,
                "max_output_bytes": budget.max_output_bytes,
                "remaining": {
                    "calls": remaining.calls,
                    "files": remaining.files,
                    "lines": remaining.lines,
                    "bytes_remaining": remaining.bytes_remaining,
                },
            },
        }
        if review is not None:
            verification: dict[str, int] = {}
            for candidate in review.candidates:
                verification[candidate.verification_state] = (
                    verification.get(candidate.verification_state, 0) + 1
                )
            verification["verified_only"] = len(review.verified_only)
            summary.update({
                "snapshot_sha256": review.snapshot_sha256,
                "retrieval": {
                    "candidates": len(retrieval.candidates),
                    "context_files": len(retrieval.context_files),
                    "context_lines": retrieval.context_lines,
                    "uncovered_candidates": retrieval.uncovered_candidates,
                },
                "verification": verification,
                "roles": [
                    {
                        "role": outcome.role,
                        "status": outcome.status,
                        **({"error": outcome.error[:300]}
                           if outcome.error else {}),
                    }
                    for outcome in review.role_outcomes
                ],
                "arbiter_rejections": list(review.arbiter_rejections),
                "message_count": review.message_count,
                "tool_evidence_bound": any(
                    candidate.verification_state in {
                        "tool-corroborated", "runtime-confirmed",
                    }
                    for candidate in review.candidates
                ),
            })
        return summary

    def _run_cxx_agent_branch(
        self,
        workspace: RepositoryWorkspace,
        inventory: WorkspaceInventory,
        findings: list[Finding],
        tool_analysis: CxxAnalysisResult | None,
        task_id: str,
        cancel_probe: Callable[[], bool] | None,
    ) -> dict:
        """Run the LLM agent pipeline over one indexed snapshot.

        共享红线：inventory 来自本次 scan 的唯一一次 ``workspace.inventory()``，
        索引在分支内只构建一次，传统扫描与 LLM 分支共享同一快照。
        ``mode=off``（或未配置 client）时零 LLM 行为，等价既有管线。
        """

        mode = self.cxx_agent_mode
        if mode == "off":
            return {"mode": "off", "status": "disabled"}
        if self.cxx_agent_client_factory is None:
            if mode == "required":
                raise RuntimeError(
                    "required C++ agent pipeline has no configured LLM provider"
                )
            return {"mode": mode, "status": "llm-not-configured"}
        has_cxx_source = any(
            PurePosixPath(item.path).suffix.lower() in CXX_SOURCE_EXTENSIONS
            for item in inventory.files
        )
        if not has_cxx_source:
            return {"mode": mode, "status": "no-cxx-sources"}
        budget = (
            self.cxx_agent_budget_factory()
            if self.cxx_agent_budget_factory is not None
            else CxxAgentBudget()
        )
        retrieval_budget = RetrievalBudget(
            max_candidates=self.cxx_agent_max_candidates,
            max_context_files=budget.max_context_files,
            max_context_lines=budget.max_context_lines,
        )
        try:
            index = CxxContextIndex.build(workspace, inventory)
            if not index.coverage.indexed:
                return {"mode": mode, "status": "no-cxx-sources"}
            retrieval = retrieve_repository(index, retrieval_budget)
            probe = _AgentClientProbe(self.cxx_agent_client_factory())
            coordinator = CxxAgentCoordinator(
                client=probe,
                index=index,
                # SnapshotReader 协议要求 .read_text(path)；workspace 本身即实现。
                reader=workspace,
                store=self.cxx_agent_store,
                task_id=task_id,
                budget=budget,
                tool_analysis=tool_analysis,
                source_mode="repository",
                should_cancel=cancel_probe,
            )
            review = coordinator.review_repository(retrieval)
        except (RuntimeError, ValueError) as exc:
            if mode == "required":
                raise RuntimeError(
                    f"C++ agent pipeline failed in required mode: {exc}"
                ) from exc
            metrics.inc("repository_scan_cxx_agent_unavailable_total")
            return {
                "mode": mode,
                "model": "",
                "status": "llm-unavailable",
                "diagnostics": [str(exc)[:500]],
            }
        cancelled = bool(cancel_probe is not None and cancel_probe())
        llm_failed = any(
            outcome.role in LLM_ROLES and outcome.status == "failed-replaced"
            for outcome in review.role_outcomes
        )
        if cancelled:
            status = "cancelled"
        elif probe.succeeded_turns == 0 and llm_failed:
            # 零成功模型轮次且存在角色降级：设计规定的 auto 降级/required
            # 失败判据（LLM 不可用导致验证无法完成）。
            if mode == "required":
                raise RuntimeError(
                    "C++ agent pipeline failed in required mode: all agent "
                    "roles failed: "
                    + "; ".join(
                        outcome.error[:120]
                        for outcome in review.role_outcomes
                        if outcome.error
                    )[:500]
                )
            metrics.inc("repository_scan_cxx_agent_unavailable_total")
            status = "llm-unavailable"
        else:
            status = "completed"
        specialist_roles: dict[str, list[str]] = {}
        for outcome in review.role_outcomes:
            if outcome.role in SPECIALIST_ROLES:
                for candidate in outcome.candidates:
                    specialist_roles.setdefault(
                        candidate.candidate_id, []
                    ).append(outcome.role)
        # 降级 passthrough（cwe=unreviewed 的种子壳）不是 LLM 断言，永不转成
        # Finding；只有 legacy CWE 域（787/125/415）的候选进入报告，验证状态
        # 保持终态。CWE-416 属于 UAF v2 管线：合同层（from_untrusted_json）
        # 已物理拒绝 legacy 候选携带 CWE-416，此处投影层再做一道防御纵深。
        for candidate in review.candidates:
            if candidate.cwe not in LEGACY_AGENT_CWES:
                continue
            findings.append(self._agent_finding(candidate, specialist_roles))
        return self._cxx_agent_collaboration(
            mode, status, probe, review, retrieval, budget,
        )

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
        explanation = item.hypothesis_reason
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
            evidence_records=list(item.evidence_records),
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
                "rejected_reason": item.rejected_reason,
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
            "diagnostics": list(outcome.diagnostics),
            "targets": audit,
        }
        if v4 is not None:
            payload["v4"] = v4
        return payload

    _V4_PAYLOAD_BUDGET_BYTES: Final = 512 * 1024
    _V4_MAX_PAYLOAD_ARTIFACTS: Final = 64

    @staticmethod
    def _seal_platform_v4(outcome, repository_key: str, inventory) -> dict:
        """Seal the platform review into V4 artifacts (review feedback #183).

        The production path mints and validates the AEP, per-finding VEPs
        (each pinned to the real AEP reference and a driver-digest oracle
        reference) and the workflow summary; content-addressed ids and
        digests ride the collaboration payload, and full artifact payloads
        travel along under a byte budget so independent stages can consume
        the sealed chain from one report.  Sealing failures degrade to an
        honest diagnostic and never alter detection results.
        """

        budget = RepositoryScanner._V4_PAYLOAD_BUDGET_BYTES
        max_artifacts = RepositoryScanner._V4_MAX_PAYLOAD_ARTIFACTS
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
                "diagnostics": [str(exc)[:300]],
            }
        veps = []
        payloads: dict[str, dict] = {}
        payload_bytes = 0
        truncated = False
        aep_payload = bundle.aep.to_dict()
        aep_bytes = len(json.dumps(aep_payload, sort_keys=True))
        if aep_bytes > budget:
            truncated = True
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
            if (
                truncated
                or len(payloads) >= max_artifacts
                or payload_bytes + encoded > budget
            ):
                truncated = True
                continue
            payloads[vep.hypothesis_id] = payload_dict
            payload_bytes += encoded
        return {
            "status": "sealed",
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
            "payloads_truncated": truncated,
        }

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
                raise RuntimeError(
                    f"required platform review failed on the C/C++ analyzer: "
                    f"{exc}"
                ) from exc
            metrics.inc("repository_scan_platform_unavailable_total")
            return {
                "mode": mode,
                "status": "analyzer-unavailable",
                "diagnostics": [str(exc)[:500]],
            }
        except (RuntimeError, ValueError) as exc:
            if mode == "required":
                raise RuntimeError(
                    f"required platform review failed: {exc}"
                ) from exc
            metrics.inc("repository_scan_platform_failed_total")
            return {
                "mode": mode,
                "status": "review-failed",
                "diagnostics": [str(exc)[:500]],
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
                    "diagnostics": cxx_result.diagnostics,
                })
                for finding in cxx_result.findings:
                    self._merge_cxx_finding(findings, cxx_finding_index, finding)

        # LLM 分支在既有管线完成后、报告组装前运行：agent finding 与工具
        # finding 融入同一份报告，audit 信息保存在 collaboration.cxx_agent。
        cancel_probe = should_cancel if should_cancel is not None else self.should_cancel
        cxx_agent_summary = self._run_cxx_agent_branch(
            workspace,
            inventory,
            findings,
            cxx_result,
            task_id,
            cancel_probe,
        )
        # 平台分支是唯一的智能体检测链（设计 §10 单链）：legacy 分支域
        # （CWE-787/125/415）不变，CWE-416 域由 Scout→假设→实验→修正循环
        # 处理，按 (cwe, path, symbol, line) 不可变身份合并进同一份报告。
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
                "cxx_agent": cxx_agent_summary,
                "platform": platform_summary,
                "skipped": dict(sorted(inventory.skipped.items())),
            },
            adjudication=adjudicate_findings(findings),
        )
        return RepositoryScanResult(report=report, inventory=inventory)
