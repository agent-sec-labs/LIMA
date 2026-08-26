"""Bounded semantic and LLM adjudication for production repository scans."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from .adjudication import adjudicate_candidate_response, finalize_adjudication
from .models import Finding, Severity
from .semantic_retrieval import (
    SecuritySemanticRetriever,
    SemanticCandidate,
)


class CandidateTriageClient(Protocol):
    provider: str
    model: str

    def triage_candidate_batch(self, candidates: list[SemanticCandidate]) -> dict:
        ...


class RepositorySemanticTriageError(RuntimeError):
    """A sanitized failure for required production semantic triage."""


@dataclass(frozen=True)
class RepositoryTriageOutcome:
    adjudication: dict
    diagnostics: dict
    findings: tuple[Finding, ...] = ()


class RepositorySemanticTriage:
    """Retrieve bounded evidence, call one model batch, and fail closed."""

    def __init__(
        self,
        client: CandidateTriageClient,
        *,
        mode: str = "auto",
        max_candidates: int = 6,
        retriever: SecuritySemanticRetriever | None = None,
    ) -> None:
        if mode not in {"auto", "required"}:
            raise ValueError("repository semantic triage mode must be auto or required")
        if max_candidates < 1:
            raise ValueError("repository semantic triage candidate limit must be positive")
        self.client = client
        self.mode = mode
        self.max_candidates = max_candidates
        self.retriever = retriever or SecuritySemanticRetriever()

    @staticmethod
    def _review_decision(reason: str) -> dict:
        return {
            "subject_type": "repository-semantic-triage",
            "path": "",
            "symbol": "",
            "disposition": "needs_review",
            "reason": reason,
        }

    @staticmethod
    def _combine(base: Mapping[str, Any], semantic: Mapping[str, Any]) -> dict:
        semantic_decisions = [
            {**item, "decision_source": "semantic-llm"}
            for item in semantic.get("decisions", [])
        ]
        semantic_fingerprints = {
            item.get("fingerprint") for item in semantic_decisions
            if item.get("fingerprint")
        }
        base_decisions = [
            {**item, "decision_source": item.get("decision_source", "scanner")}
            for item in base.get("decisions", [])
            if not item.get("fingerprint")
            or item.get("fingerprint") not in semantic_fingerprints
        ]
        return finalize_adjudication([*base_decisions, *semantic_decisions])

    @staticmethod
    def _candidate_for(
        decision: Mapping[str, Any], candidates: Sequence[SemanticCandidate],
    ) -> SemanticCandidate | None:
        return next((
            candidate for candidate in candidates
            if candidate.path == decision.get("path")
            and candidate.qualname == decision.get("symbol")
        ), None)

    @staticmethod
    def _existing_finding(
        candidate: SemanticCandidate, decision: Mapping[str, Any],
        findings: Sequence[Finding],
    ) -> Finding | None:
        cwe = str(decision.get("llm_cwe", ""))
        return next((
            finding for finding in findings
            if finding.path == candidate.path
            and finding.cwe == cwe
            and candidate.start_line <= finding.line <= candidate.end_line
        ), None)

    @staticmethod
    def _finding_from_alert(
        candidate: SemanticCandidate, decision: Mapping[str, Any], provider: str,
    ) -> Finding:
        cwe = str(decision.get("llm_cwe", ""))
        labels = {
            "CWE-22": "Path traversal evidence",
            "CWE-78": "Command injection evidence",
            "CWE-89": "SQL injection evidence",
        }
        fixes = {
            "CWE-22": "Resolve the candidate path and enforce containment under a trusted root.",
            "CWE-78": "Avoid shell interpolation; use a fixed executable and structured argv.",
            "CWE-89": "Bind values and allowlist every dynamic SQL structure token.",
        }
        tests = {
            "CWE-22": "Add traversal, absolute-path and symlink-escape regression cases.",
            "CWE-78": "Add shell-metacharacter and executable-boundary regression cases.",
            "CWE-89": "Add malicious identifier and ORDER BY direction regression cases.",
        }
        evidence_parts = [
            str(decision.get(key, "")).strip()
            for key in (
                "llm_root_cause", "llm_source_evidence", "llm_sink_evidence",
                "llm_mitigation_evidence",
            )
            if str(decision.get(key, "")).strip()
        ]
        verification_state = (
            "corroborated"
            if decision.get("reason") == "risk-invariant-and-llm-agree"
            else "candidate"
        )
        return Finding(
            rule_id="HYBRID-%s" % cwe,
            severity=Severity.HIGH if cwe in {"CWE-78", "CWE-89"} else Severity.MEDIUM,
            title=labels.get(cwe, "Hybrid semantic security evidence"),
            explanation=str(decision.get("llm_root_cause", ""))
            or "Semantic security evidence requires investigation.",
            path=candidate.path,
            line=candidate.start_line,
            evidence=" | ".join(evidence_parts)[:2000]
            or "Risk invariant and model verdict indicate a security boundary failure.",
            fix=fixes.get(cwe, "Apply a minimal fix at the identified trust boundary."),
            test=tests.get(cwe, "Add a regression test for the identified security boundary."),
            confidence=float(decision.get("llm_confidence", 0.0) or 0.0),
            cwe=cwe,
            source="semantic-invariant+llm:%s" % (provider or "unknown"),
            evidence_kind="semantic-root-cause",
            verification_state=verification_state,
        )

    def _attach_alert_findings(
        self,
        semantic: dict,
        candidates: Sequence[SemanticCandidate],
        existing_findings: Sequence[Finding],
        provider: str,
    ) -> tuple[Finding, ...]:
        created = []
        for decision in semantic.get("decisions", []):
            if decision.get("disposition") != "alert":
                continue
            candidate = self._candidate_for(decision, candidates)
            if candidate is None:
                continue
            finding = self._existing_finding(candidate, decision, existing_findings)
            if finding is None:
                finding = self._finding_from_alert(candidate, decision, provider)
                created.append(finding)
            decision["fingerprint"] = finding.fingerprint
            decision["rule_id"] = finding.rule_id
            decision["line"] = finding.line
        return tuple(created)

    def _failure(
        self, base: Mapping[str, Any], exc: Exception, stage: str, started: float,
        retrieval_summary: Mapping[str, Any] | None = None,
    ) -> RepositoryTriageOutcome:
        if self.mode == "required":
            raise RepositorySemanticTriageError(
                "required repository semantic triage failed closed"
            ) from exc
        semantic = finalize_adjudication([
            self._review_decision("semantic-triage-provider-failure")
        ])
        usage = getattr(exc, "usage", {})
        safe_usage = {
            key: int((usage or {}).get(key, 0) or 0)
            for key in ("prompt_tokens", "completion_tokens", "total_tokens")
        }
        diagnostics = {
            "mode": self.mode,
            "status": "failed-closed",
            "failure_stage": stage,
            "failure_type": exc.__class__.__name__,
            "provider": str(getattr(self.client, "provider", "unknown")),
            "model": str(getattr(self.client, "model", "unknown")),
            "usage": safe_usage,
            "latency_ms": getattr(exc, "latency_ms", None),
            "duration_ms": round((time.perf_counter() - started) * 1000, 3),
            "secret_persisted": False,
        }
        if retrieval_summary:
            diagnostics["retrieval"] = dict(retrieval_summary)
        return RepositoryTriageOutcome(
            adjudication=self._combine(base, semantic),
            diagnostics=diagnostics,
        )

    def run(
        self,
        root: str | Path,
        baseline_adjudication: Mapping[str, Any],
        existing_findings: Sequence[Finding] = (),
    ) -> RepositoryTriageOutcome:
        started = time.perf_counter()
        try:
            retrieval = self.retriever.retrieve_run(root)
            candidates = self.retriever.evidence_packet(
                list(retrieval.candidates), self.max_candidates
            )
        except Exception as exc:
            return self._failure(baseline_adjudication, exc, "retrieval", started)

        retrieval_summary = {
            "inventory": dict(retrieval.diagnostics.get("inventory") or {}),
            "parsed_files": retrieval.diagnostics.get("parsed_files", 0),
            "parse_errors": retrieval.diagnostics.get("parse_errors", 0),
            "functions_seen": retrieval.diagnostics.get("functions_seen", 0),
            "selected_candidates": retrieval.diagnostics.get("selected_candidates", 0),
            "evidence_candidates": len(candidates),
        }
        if not candidates:
            semantic = finalize_adjudication([
                self._review_decision("no-semantic-candidates-for-safety-proof")
            ])
            return RepositoryTriageOutcome(
                adjudication=self._combine(baseline_adjudication, semantic),
                diagnostics={
                    "mode": self.mode,
                    "status": "no-candidates",
                    "retrieval": retrieval_summary,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                    "secret_persisted": False,
                },
            )

        try:
            response = self.client.triage_candidate_batch(list(candidates))
        except Exception as exc:
            return self._failure(
                baseline_adjudication, exc, "provider", started, retrieval_summary
            )

        semantic = adjudicate_candidate_response(response, candidates)
        contract_valid = response.get("contract_valid") is True
        if self.mode == "required" and not contract_valid:
            raise RepositorySemanticTriageError(
                "required repository semantic triage returned an invalid contract"
            )
        provider = str(response.get("provider") or getattr(self.client, "provider", "unknown"))
        created_findings = self._attach_alert_findings(
            semantic, candidates, existing_findings, provider
        )
        diagnostics = {
            "mode": self.mode,
            "status": "completed" if contract_valid else "invalid-contract",
            "provider": provider,
            "model": str(response.get("model") or getattr(self.client, "model", "unknown")),
            "contract_valid": contract_valid,
            "contract_errors": list(response.get("contract_errors") or []),
            "usage": dict(response.get("usage") or {}),
            "latency_ms": response.get("latency_ms"),
            "prompt_sha256": str(response.get("prompt_sha256", "")),
            "context_chars": int(response.get("context_chars", 0) or 0),
            "retrieval": retrieval_summary,
            "duration_ms": round((time.perf_counter() - started) * 1000, 3),
            "secret_persisted": False,
        }
        return RepositoryTriageOutcome(
            adjudication=self._combine(baseline_adjudication, semantic),
            diagnostics=diagnostics,
            findings=created_findings,
        )
