"""Shared, fail-closed evidence disposition for evaluation and production reports."""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from .models import Finding


POLICY_NAME = "agreement-required-for-auto-clear-v1"
DISPOSITIONS = ("alert", "needs_review", "clear")
CWE_CATEGORIES = {"CWE-22": "path", "CWE-78": "command", "CWE-89": "sql"}
VERIFIED_RISK_STATES = frozenset({
    "syntax-verified", "corroborated", "dataflow-verified", "confirmed",
})


def finalize_adjudication(
    decisions: Iterable[Mapping[str, Any]], *, policy: str = POLICY_NAME,
) -> Dict[str, Any]:
    """Validate decisions and derive one stable report-level disposition."""
    normalized: List[Dict[str, Any]] = []
    for raw in decisions:
        decision = dict(raw)
        disposition = str(decision.get("disposition", "")).strip().lower()
        if disposition not in DISPOSITIONS:
            raise ValueError("invalid evidence disposition: %s" % disposition)
        if disposition == "clear" and not (
            decision.get("reason") == "mitigation-invariant-and-llm-agree"
            and "mitigation" in set(decision.get("invariant_statuses") or [])
            and decision.get("llm_is_vulnerable") is False
        ):
            decision["requested_disposition"] = "clear"
            disposition = "needs_review"
            decision["reason"] = "clear-rejected-without-agreeing-safety-evidence"
        decision["disposition"] = disposition
        normalized.append(decision)

    observed = Counter(item["disposition"] for item in normalized)
    counts = {name: observed.get(name, 0) for name in DISPOSITIONS}
    auto_clear = bool(normalized) and counts["clear"] == len(normalized)
    if counts["alert"]:
        overall = "alert"
        reason = "one-or-more-actionable-alerts"
    elif counts["needs_review"]:
        overall = "needs_review"
        reason = "one-or-more-items-require-human-review"
    elif auto_clear:
        overall = "clear"
        reason = "all-items-have-agreeing-safety-evidence"
    else:
        overall = "needs_review"
        reason = "no-positive-safety-evidence"
    return {
        "policy": policy,
        "overall_disposition": overall,
        "overall_reason": reason,
        "decisions": normalized,
        "counts": counts,
        "auto_clear": auto_clear,
    }


def adjudicate_findings(
    findings: Sequence[Finding], *, multi_agent_verified: bool = False,
) -> Dict[str, Any]:
    """Map production findings to the shared disposition contract.

    A finding is a positive risk claim, so this path never emits ``clear``.
    Empty or unverified results remain ``needs_review`` until an explicit safety
    candidate has both deterministic mitigation evidence and a clean model verdict.
    """
    decisions = []
    for finding in findings:
        state = finding.verification_state.strip().lower()
        if multi_agent_verified:
            disposition = "alert"
            reason = "multi-agent-verification-approved-risk"
        elif state in VERIFIED_RISK_STATES:
            disposition = "alert"
            reason = {
                "syntax-verified": "deterministic-syntax-risk-evidence",
                "corroborated": "independent-evidence-corroborated-risk",
                "dataflow-verified": "source-to-sink-risk-evidence",
                "confirmed": "confirmed-risk-evidence",
            }[state]
        else:
            disposition = "needs_review"
            reason = "unverified-finding-requires-human-review"
        decisions.append({
            "fingerprint": finding.fingerprint,
            "path": finding.path,
            "line": finding.line,
            "rule_id": finding.rule_id,
            "cwe": finding.cwe,
            "disposition": disposition,
            "reason": reason,
            "verification_state": state,
            "evidence_sources": sorted({
                record.source for record in finding.evidence_records if record.source
            }),
        })
    return finalize_adjudication(decisions)


def adjudicate_candidate_response(
    response: Mapping[str, Any], candidates: Sequence[Any],
) -> Dict[str, Any]:
    """Combine semantic invariants with a contract-validated model response."""
    verdicts = {
        (str(item.get("path", "")), str(item.get("symbol", ""))): item
        for item in response.get("verdicts", [])
        if isinstance(item, dict)
    }
    contract_valid = (
        response.get("status") == "completed"
        and response.get("contract_valid") is True
    )
    decisions = []
    for candidate in candidates:
        identity = (candidate.path, candidate.qualname)
        verdict = verdicts.get(identity)
        statuses = {item.status for item in candidate.invariants}
        categories = {item.category for item in candidate.invariants}
        if not contract_valid or verdict is None:
            disposition = "needs_review"
            reason = "invalid-or-missing-llm-verdict"
        elif "risk" in statuses:
            verdict_category = CWE_CATEGORIES.get(str(verdict.get("cwe", "")))
            if verdict.get("is_vulnerable") is True and verdict_category in categories:
                disposition = "alert"
                reason = "risk-invariant-and-llm-agree"
            else:
                disposition = "needs_review"
                reason = "risk-invariant-conflicts-with-llm"
        elif "mitigation" in statuses:
            if verdict.get("is_vulnerable") is False:
                disposition = "clear"
                reason = "mitigation-invariant-and-llm-agree"
            else:
                disposition = "needs_review"
                reason = "mitigation-invariant-conflicts-with-llm"
        elif verdict.get("is_vulnerable") is True:
            disposition = "alert"
            reason = "llm-alert-without-deterministic-invariant"
        else:
            disposition = "needs_review"
            reason = "llm-clean-without-deterministic-safety-evidence"
        try:
            llm_confidence = (
                max(0.0, min(1.0, float(verdict.get("confidence", 0.0))))
                if verdict is not None else 0.0
            )
        except (TypeError, ValueError):
            llm_confidence = 0.0
        decisions.append({
            "path": candidate.path,
            "symbol": candidate.qualname,
            "start_line": candidate.start_line,
            "end_line": candidate.end_line,
            "category": candidate.category,
            "disposition": disposition,
            "reason": reason,
            "invariant_statuses": sorted(statuses),
            "llm_is_vulnerable": (
                verdict.get("is_vulnerable") if verdict is not None else None
            ),
            "llm_cwe": str(verdict.get("cwe", "")) if verdict is not None else "",
            "llm_confidence": llm_confidence,
            "llm_root_cause": (
                str(verdict.get("root_cause", "")) if verdict is not None else ""
            ),
            "llm_trust_boundary": (
                str(verdict.get("trust_boundary", "")) if verdict is not None else ""
            ),
            "llm_source_evidence": (
                str(verdict.get("source_evidence", "")) if verdict is not None else ""
            ),
            "llm_sink_evidence": (
                str(verdict.get("sink_evidence", "")) if verdict is not None else ""
            ),
            "llm_mitigation_evidence": (
                str(verdict.get("mitigation_evidence", "")) if verdict is not None else ""
            ),
            "locally_template_repairable": (
                bool(verdict.get("locally_template_repairable", False))
                if verdict is not None else False
            ),
        })
    return finalize_adjudication(decisions)
