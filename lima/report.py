from typing import Any, Dict


DISPOSITION_LABELS = {
    "alert": "Actionable alert",
    "needs_review": "Human review required",
    "clear": "Cleared by agreeing evidence",
}


def _finding_decision(item: Dict[str, Any], adjudication: Dict[str, Any]) -> Dict[str, Any]:
    decisions = adjudication.get("decisions") or []
    fingerprint = item.get("fingerprint")
    if fingerprint:
        matched = next(
            (value for value in decisions if value.get("fingerprint") == fingerprint),
            None,
        )
        if matched:
            return matched
    return next((
        value for value in decisions
        if value.get("path") == item.get("path")
        and value.get("line") == item.get("line")
        and value.get("rule_id") == item.get("rule_id")
    ), {})


def to_markdown(report: Dict[str, Any]) -> str:
    if report.get("pull_request") is None:
        title = "# LIMA Repository Audit"
    else:
        title = "# LIMA PR Review — #%s" % report["pull_request"]
    lines = [
        title,
        "",
        "**Repository:** `%s`  " % report.get("repository", ""),
        "**Risk:** `%s`  " % report.get("risk", "unknown"),
        "**Reviewer:** `%s`" % report.get("reviewer", "unknown"),
        "",
        report.get("summary", ""),
        "",
    ]
    collaboration = report.get("collaboration") or {}
    if collaboration.get("mode") in {
        "deterministic-repository-baseline", "hybrid-repository-scan"
    }:
        lines.extend([
            "## Workspace coverage",
            "",
            "- Scanned files: `%s`; bytes: `%s`; truncated: `%s`" % (
                collaboration.get("scanned_files", 0),
                collaboration.get("scanned_bytes", 0),
                collaboration.get("workspace_truncated", False),
            ),
            "- Python parse errors: `%s`" % collaboration.get("python_parse_errors", 0),
            "- Dataflow-verified findings: `%s`" % collaboration.get(
                "dataflow_verified_findings", 0
            ),
            "- Dataflow scope: `%s`; indexed modules: `%s`; functions: `%s`" % (
                collaboration.get("dataflow_scope", "disabled"),
                collaboration.get("dataflow_modules_indexed", 0),
                collaboration.get("dataflow_functions_indexed", 0),
            ),
            "- Call edges: `%s`; cross-file: `%s`; bounded truncations: `%s`" % (
                collaboration.get("interprocedural_call_edges", 0),
                collaboration.get("cross_file_call_edges", 0),
                collaboration.get("interprocedural_truncated_calls", 0),
            ),
            "- Unresolved calls: `%s`; dynamic imports: `%s`; ambiguous modules: `%s`" % (
                collaboration.get("unresolved_dataflow_calls", 0),
                collaboration.get("dynamic_import_sites", 0),
                collaboration.get("ambiguous_python_modules", 0),
            ),
            "- Corroborated findings: `%s`" % collaboration.get("corroborated_findings", 0),
            "- Unverified candidates: `%s`" % collaboration.get("candidate_findings", 0),
            "- SAST engines: `%s`" % (collaboration.get("sast") or {}),
            "- Skipped: `%s`" % (collaboration.get("skipped") or {}),
            "",
        ])
    elif collaboration:
        lines.extend([
            "## Multi-agent collaboration",
            "",
            "- Protocol: `%s`" % collaboration.get("protocol", "unknown"),
            "- Assignments: `%s`; dialogue rounds: `%s`; messages: `%s`" % (
                collaboration.get("planned_assignments", 0),
                collaboration.get("dialogue_rounds", 0),
                collaboration.get("messages", 0),
            ),
            "- Retries: `%s`; handoffs: `%s`; rejected by verification: `%s`" % (
                collaboration.get("retries", 0), collaboration.get("handoffs", 0),
                collaboration.get("rejected_findings", 0),
            ),
            "",
        ])
    semantic = collaboration.get("semantic_triage") or {}
    if semantic:
        retrieval = semantic.get("retrieval") or {}
        usage = semantic.get("usage") or {}
        lines.extend([
            "## Production semantic triage",
            "",
            "- Mode: `%s`; status: **%s**" % (
                semantic.get("mode", "off"), semantic.get("status", "disabled"),
            ),
            "- Provider/model: `%s` / `%s`" % (
                semantic.get("provider", "local"), semantic.get("model", "none"),
            ),
            "- Evidence candidates: `%s`; context characters: `%s`" % (
                retrieval.get("evidence_candidates", 0),
                semantic.get("context_chars", 0),
            ),
            "- Tokens: `%s`; model latency: `%s ms`; secret persisted: `%s`" % (
                usage.get("total_tokens", 0), semantic.get("latency_ms", 0),
                semantic.get("secret_persisted", False),
            ),
            "",
        ])
    adjudication = report.get("adjudication") or {}
    if adjudication:
        counts = adjudication.get("counts") or {}
        overall = str(adjudication.get("overall_disposition", "needs_review"))
        lines.extend([
            "## Evidence disposition",
            "",
            "- Overall: **%s**" % DISPOSITION_LABELS.get(overall, overall),
            "- Actionable alerts: `%s`; human review: `%s`; cleared: `%s`" % (
                counts.get("alert", 0), counts.get("needs_review", 0),
                counts.get("clear", 0),
            ),
            "- Policy: `%s`; automatic clear allowed: `%s`" % (
                adjudication.get("policy", "unknown"),
                bool(adjudication.get("auto_clear", False)),
            ),
            "",
        ])
    findings = report.get("findings", [])
    if not findings:
        lines.append(
            "No actionable finding reached the current evidence threshold. "
            "This is not proof that the reviewed code is secure."
        )
        return "\n".join(lines) + "\n"
    lines.extend(["## Findings", ""])
    icons = {"critical": "🚨", "high": "🔴", "medium": "🟠", "low": "🟡"}
    for index, item in enumerate(findings, 1):
        severity = item.get("severity", "medium")
        decision = _finding_decision(item, adjudication)
        disposition = str(decision.get("disposition", "needs_review"))
        lines.extend(
            [
                "### %d. %s %s" % (index, icons.get(severity, "•"), item.get("title", "Finding")),
                "",
                "`%s:%s` · **%s** · `%s` · `%s` · `%s`" % (
                    item.get("path", ""), item.get("line", 0), severity.upper(),
                    item.get("rule_id", ""), item.get("cwe", "unmapped") or "unmapped",
                    item.get("verification_state", "candidate")),
                "",
                item.get("explanation", ""),
                "",
                "**Disposition:** %s — `%s`" % (
                    DISPOSITION_LABELS.get(disposition, disposition),
                    decision.get("reason", "missing-disposition-evidence"),
                ),
                "",
                "**Evidence**",
                "",
                "```text",
                item.get("evidence", ""),
                "```",
                "",
                "**Suggested fix:** %s" % item.get("fix", ""),
                "",
                "**Suggested test:** %s" % item.get("test", ""),
                "",
                "**Evidence sources:** `%s`" % item.get("source", "unknown"),
                "",
            ]
        )
        if item.get("verification_state") == "dataflow-verified":
            lines.extend(["**Source-to-sink path**", ""])
            for step in item.get("evidence_records") or []:
                if step.get("source") != "python-dataflow":
                    continue
                lines.append(
                    "- `%s` at `%s:%s`: %s"
                    % (
                        step.get("kind", "step"), step.get("path", ""),
                        step.get("line", 0), step.get("snippet", ""),
                    )
                )
            lines.append("")
    return "\n".join(lines) + "\n"
