import html
import re
from collections.abc import Mapping
from typing import Any, Dict, Iterable


_MAX_CXX_DIAGNOSTICS = 8
_MAX_CXX_RENDER_TEXT = 480
_ANALYSIS_MODE_LABELS = {
    "source-only": "纯源码候选",
    "build-backed": "构建支持的静态验证",
    "sanitizer-confirmed": "Sanitizer 动态确认",
}
_VERIFICATION_STATE_LABELS = {
    "candidate": "候选 · 需复核",
    "build-verified": "构建支持的静态验证",
    "confirmed": "Sanitizer 动态确认",
    "syntax-verified": "语法约束已验证",
    "dataflow-verified": "数据流已验证",
    # C/C++ agent 管线的六种验证状态（设计第 9 节）。
    "llm-candidate": "LLM 候选 · 需复核",
    "agent-corroborated": "双 Agent 共识候选 · 需复核",
    "tool-corroborated": "工具证据已绑定",
    "runtime-confirmed": "运行时证据已确认",
    "human-confirmed": "人工已确认",
    "needs-human-review": "证据不足或冲突 · 需人工复核",
}
_DIAGNOSTIC_LABELS = {
    "BUILD_FAILED": "构建支持的静态验证未完成",
    "TIMED_OUT": "分析层超时，未完成验证",
    "SANITIZER_NOT_CONFIGURED": "Sanitizer 动态确认未配置",
    "SANITIZER_BUILD_CONTEXT_UNAVAILABLE": "Sanitizer 动态确认缺少构建上下文",
    "TEST_FAILED_WITHOUT_SANITIZER_EVIDENCE": "测试失败，未获得 Sanitizer 证据",
    "NEEDS_HUMAN_REVIEW": "工具输出需要人工复核",
    "ANALYSIS_BUDGET_EXHAUSTED": "分析预算已达到上限，结果可能不完整",
}


def _is_cxx_finding(item: Dict[str, Any]) -> bool:
    language = str(item.get("language", "")).lower().strip()
    return language in {"c", "c++", "cpp", "cxx"} or str(
        item.get("rule_id", "")
    ).lower().startswith("cxx.")


def _analysis_mode_label(value: Any) -> str:
    return _ANALYSIS_MODE_LABELS.get(
        str(value or "").lower(), "未知分析模式（需人工复核）"
    )


def _verification_state_label(value: Any) -> str:
    return _VERIFICATION_STATE_LABELS.get(
        str(value or "").lower(), "未知验证状态（需人工复核）"
    )


def _diagnostic_code(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("code") or value.get("status") or "analysis-limitation"
    code = re.sub(r"[^A-Z0-9]+", "_", str(value or "analysis-limitation").upper())
    code = code.strip("_") or "ANALYSIS_LIMITATION"
    return code[:64]


def _safe_cxx_text(value: Any, maximum: int = _MAX_CXX_RENDER_TEXT) -> str:
    """Render bounded C/C++ tool text without runtime addresses or credentials."""
    if not isinstance(value, str):
        return ""
    message = value.strip()
    message = re.sub(r"(?:https?://|www\.)[^\s`]+", "[内部地址已隐藏]", message, flags=re.I)
    message = re.sub(r"(?:\"[A-Za-z]:[\\/][^\"]*\"|'[A-Za-z]:[\\/][^']*')", "[运行路径已隐藏]", message)
    message = re.sub(r"(?:\"/[^\"]*\"|'/[^']*')", "[运行路径已隐藏]", message)
    message = re.sub(r"[A-Za-z]:[\\/][^\s`]+", "[运行路径已隐藏]", message)
    message = re.sub(r"(?<![.\w])/(?:[^\s`/]+/)+[^\s`/]+", "[运行路径已隐藏]", message)
    message = re.sub(
        r"(?i)(?:--|(?<![A-Z0-9_-]))(?:api[_-]?key|key|token|secret|password)(?:\s*=\s*|\s+)(?:\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|[^\s`]+)",
        "[敏感参数已隐藏]",
        message,
    )
    return message[:maximum]


def _safe_diagnostic_message(value: Any) -> str:
    return _safe_cxx_text(value, 240)


def _cxx_markdown_prose(value: Any, maximum: int = _MAX_CXX_RENDER_TEXT) -> str:
    """Encode bounded tool text for a single Markdown prose or heading line.

    One pass only: HTML entities, link syntax and every structural prefix
    (headings, lists, blockquotes, code fences, thematic breaks) are broken
    so untrusted text can never introduce document structure. Decorative
    emphasis from word-boundary underscores or GFM strikethrough tildes is
    accepted on purpose; it cannot change document structure.
    """

    text = " ".join(_safe_cxx_text(value, maximum).splitlines())
    text = html.escape(text, quote=False)
    text = text.replace("[", "&#91;").replace("]", "&#93;")
    text = text.replace("*", "&#42;")
    if re.match(
        r"^(?:#{1,6}(?:\s|$)|[-+*]\s|\d+[.)]\s|`{3,}|~{3,}|[-*_ =]{3,})",
        text,
    ):
        text = "&#8203;" + text
    return text


def _cxx_inline_code(value: Any) -> str:
    """Return one safe CommonMark code span for untrusted tool text.

    Code-span content is a literal context: entities would display as
    text, so the span keeps the redacted source verbatim and only the
    adaptive delimiter stops hostile backticks from closing it early.
    """

    text = " ".join(_safe_cxx_text(value).splitlines())
    runs = [len(match.group(0)) for match in re.finditer(r"`+", text)]
    if not runs:
        return f"`{text}`"
    delimiter = "`" * (max(runs) + 1)
    return f"{delimiter} {text} {delimiter}"


def _cxx_evidence_block(value: Any) -> tuple[str, str, str]:
    """Return an adaptive fenced block that untrusted evidence cannot close."""

    text = html.escape(_safe_cxx_text(value), quote=False)
    runs = [len(match.group(0)) for match in re.finditer(r"`+", text)]
    fence = "`" * max(3, (max(runs) + 1) if runs else 3)
    protected_lines = []
    for line in text.splitlines() or [""]:
        if re.match(r"^(?:```|#{1,6}(?:\s|$))", line):
            line = " " + line
        protected_lines.append(line)
    return f"{fence}text", "\n".join(protected_lines), fence


def _cxx_diagnostics(collaboration: Dict[str, Any]) -> Iterable[str]:
    cxx_memory = collaboration.get("cxx_memory")
    if not isinstance(cxx_memory, dict):
        return ()
    diagnostics = cxx_memory.get("diagnostics")
    if not isinstance(diagnostics, list):
        return ()
    lines = []
    for item in diagnostics[:_MAX_CXX_DIAGNOSTICS]:
        code = _diagnostic_code(item)
        message = _cxx_markdown_prose(
            item.get("message") if isinstance(item, dict) else "", 240
        )
        label = _DIAGNOSTIC_LABELS.get(code, "分析层未完成，结果需要人工复核")
        if message:
            label = "%s：%s" % (label, message)
        lines.append("- `%s` %s" % (code, label))
    return lines


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


def _cxx_trigger_path_text(value: Any) -> str:
    """Join model-supplied trigger-path steps for prose-context encoding."""

    if not isinstance(value, list | tuple):
        return ""
    return " → ".join(
        str(step) for step in value if isinstance(step, str) and step
    )


def _cxx_agent_degradation_line(agent: dict, status: str) -> str:
    """One honest degradation line: reason, bounded diagnostics, failed roles."""

    parts = [f"`{status}`"]
    reason = str(agent.get("reason") or "")
    if reason:
        parts.append(_cxx_markdown_prose(reason, 200))
    diagnostics = agent.get("diagnostics")
    if isinstance(diagnostics, list):
        for item in diagnostics[:_MAX_CXX_DIAGNOSTICS]:
            parts.append(_cxx_markdown_prose(item, 200))
    roles = agent.get("roles")
    if isinstance(roles, list):
        failed = [
            f"{item.get('role', '?')}={item.get('status', '?')}"
            for item in roles
            if isinstance(item, dict) and item.get("status") not in {None, "ok"}
        ]
        if failed:
            parts.append(f"failed roles: {', '.join(failed)}")
    return f"- Degradation: {' · '.join(parts)}"


def _cxx_agent_section(agent: dict) -> Iterable[str]:
    """Render the ``collaboration.cxx_agent`` audit payload (design §12).

    覆盖：是否真正调用 LLM、provider/model、提示词模板标识与角色清单、
    上下文统计、快照/manifest/head 哈希、用量（bytes-proxy）、coverage
    （验证计数 + 角色状态）、降级链与 ``automatic_repair=false`` 红线。
    哈希/模式/角色状态都是服务端可信值，走内联码；diagnostics/reason
    可能携带 provider 返回文本，一律经 ``_cxx_markdown_prose`` 编码。
    """

    status = str(agent.get("status", "unknown"))
    invoked = "yes" if status == "completed" else "no"
    lines = [
        "## C/C++ LLM agent",
        "",
        "- Status: `{status}` · mode `{mode}` · scope `{scope}`".format(
            status=status,
            mode=agent.get("mode", "off"),
            scope=agent.get("scope", "repository"),
        ),
        f"- LLM really invoked: **{invoked}** · "
        f"provider `{agent.get('provider', '')}` · "
        f"model `{agent.get('model', '')}`",
    ]
    prompt = agent.get("prompt")
    if isinstance(prompt, dict):
        roles = ", ".join(str(item) for item in (prompt.get("roles") or ()))
        template = prompt.get("template", "unknown")
        lines.append(f"- Prompt template: `{template}` · roles: `{roles or 'none'}`")
    retrieval = agent.get("retrieval")
    if isinstance(retrieval, dict):
        lines.append(
            "- Context sent: candidates `{candidates}` · files `{files}`"
            " · lines `{lines}` · uncovered `{uncovered}`".format(
                candidates=retrieval.get("candidates", 0),
                files=retrieval.get("context_files", 0),
                lines=retrieval.get("context_lines", 0),
                uncovered=retrieval.get("uncovered_candidates", 0),
            )
        )
    if agent.get("snapshot_sha256"):
        lines.append(f"- Snapshot sha256: `{agent['snapshot_sha256']}`")
    if agent.get("source_manifest_sha256"):
        lines.append(f"- Source manifest sha256: `{agent['source_manifest_sha256']}`")
    head_sha = str(agent.get("head_sha") or "")
    if head_sha:
        lines.append(f"- Head/base SHA: `{head_sha}` / `{agent.get('base_sha', '')}`")
    usage = agent.get("usage")
    if isinstance(usage, dict):
        lines.append(
            "- Usage: calls `{calls}` · context files `{files}`"
            " · context lines `{lines}` · output bytes `{bytes}`"
            " (bytes-proxy; provider token counts unavailable in v1)".format(
                calls=usage.get("calls", 0),
                files=usage.get("context_files", 0),
                lines=usage.get("context_lines", 0),
                bytes=usage.get("output_bytes", 0),
            )
        )
    verification = agent.get("verification")
    if isinstance(verification, dict):
        states = sorted(
            (str(key), value) for key, value in verification.items()
            if key != "verified_only"
        )
        rendered = " · ".join(f"`{key}` `{value}`" for key, value in states)
        if "verified_only" in verification:
            suffix = f"verified-only `{verification['verified_only']}`"
            rendered = f"{rendered} · {suffix}" if rendered else suffix
        if rendered:
            lines.append(f"- Verification: {rendered}")
    role_outcomes = agent.get("roles")
    if isinstance(role_outcomes, list) and role_outcomes:
        rendered_roles = " · ".join(
            f"`{item.get('role', '?')}` `{item.get('status', '?')}`"
            for item in role_outcomes if isinstance(item, dict)
        )
        lines.append(f"- Roles: {rendered_roles}")
    if "tool_evidence_bound" in agent:
        bound = bool(agent["tool_evidence_bound"])
        lines.append(f"- Tool evidence bound: `{bound}`")
    lines.append("- Automatic repair: **false**")
    if status != "completed":
        lines.append(_cxx_agent_degradation_line(agent, status))
    lines.append("")
    return lines


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
    cxx_agent = collaboration.get("cxx_agent")
    if isinstance(cxx_agent, dict):
        lines.extend(_cxx_agent_section(cxx_agent))
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
    cxx_diagnostics = tuple(_cxx_diagnostics(collaboration))
    if cxx_diagnostics:
        lines.extend([
            "## C/C++ 内存分析限制",
            "",
            "以下层级未完成或被降级；这不表示目标项目不存在漏洞。",
            "",
            *cxx_diagnostics,
            "",
        ])
    if not findings:
        if cxx_diagnostics:
            lines.append("ℹ️ 当前没有可报告的 C/C++ finding；受限分析结果不能作为“无漏洞”结论。")
        else:
            lines.append(
                "No actionable finding reached the current evidence threshold. "
                "This is not proof that the reviewed code is secure."
            )
        return "\n".join(lines) + "\n"
    lines.extend(["## Findings", ""])
    icons = {"critical": "🚨", "high": "🔴", "medium": "🟠", "low": "🟡"}
    for index, item in enumerate(findings, 1):
        severity = item.get("severity", "medium")
        is_cxx = _is_cxx_finding(item)
        display = _cxx_markdown_prose if is_cxx else str
        inline_code = (
            _cxx_inline_code if is_cxx else lambda value: "`%s`" % str(value)
        )
        # Raw values are kept for inline spans: they encode exactly once at
        # the output point instead of being pre-escaped into a second pass.
        raw_path = str(item.get("path") or "")
        evidence = display(item.get("evidence", ""))
        evidence_block = (
            _cxx_evidence_block(item.get("evidence", ""))
            if is_cxx
            else ("```text", evidence, "```")
        )
        decision = _finding_decision(item, adjudication)
        disposition = str(decision.get("disposition", "needs_review"))
        lines.extend(
            [
                "### %d. %s %s" % (index, icons.get(severity, "•"), display(item.get("title", "Finding"))),
                "",
                "%s · **%s** · %s · %s · %s" % (
                    inline_code(f"{raw_path}:{item.get('line', 0)}"),
                    severity.upper(),
                    inline_code(item.get("rule_id", "")),
                    inline_code(item.get("cwe", "unmapped") or "unmapped"),
                    inline_code(item.get("verification_state", "candidate")),
                ),
                "",
                display(item.get("explanation", "")),
                "",
                "**Disposition:** %s — `%s`" % (
                    DISPOSITION_LABELS.get(disposition, disposition),
                    decision.get("reason", "missing-disposition-evidence"),
                ),
                "",
                "**Evidence**",
                "",
                *evidence_block,
                "",
                "**Suggested fix:** %s" % display(item.get("fix", "")),
                "",
                "**Suggested test:** %s" % display(item.get("test", "")),
                "",
                "**Evidence sources:** %s" % inline_code(item.get("source", "unknown")),
                "",
            ]
        )
        if is_cxx:
            analysis_mode = str(item.get("analysis_mode", "")).lower()
            lines.extend([
                "**C/C++ memory-analysis details**",
                "",
                "- Language: %s" % inline_code(item.get("language", "unknown")),
                "- Symbol: %s" % inline_code(item.get("symbol", "unknown")),
                "- Location: %s" % inline_code(f"{raw_path}:{item.get('line', 0)}"),
                "- CWE: %s" % inline_code(item.get("cwe", "unmapped") or "unmapped"),
                "- Analysis mode: %s · **%s**" % (
                    inline_code(item.get("analysis_mode", "unknown")),
                    _analysis_mode_label(analysis_mode),
                ),
                "- Verification state: %s · %s" % (
                    inline_code(item.get("verification_state", "candidate")),
                    _verification_state_label(item.get("verification_state")),
                ),
                "- Tool: %s" % inline_code(item.get("source", "unknown")),
                f"- Candidate: {inline_code(item.get('candidate_id', '') or 'unbound')}",
                f"- Agent roles: {inline_code(item.get('agent_role', '') or 'unassigned')}",
                f"- Trigger path: {display(_cxx_trigger_path_text(item.get('trigger_path')))}",
                "",
                "**工具证据 / trace**",
                "",
            ])
            raw_evidence_records = item.get("evidence_records")
            evidence_records = [
                record for record in raw_evidence_records
                if isinstance(record, Mapping) and record
            ] if isinstance(raw_evidence_records, (list, tuple)) else []
            for record in evidence_records:
                lines.append("- %s · %s · %s" % (
                    inline_code(record.get("source", "unknown")),
                    inline_code(f"{record.get('path', '')}:{record.get('line', 0)}"),
                    display(record.get("snippet", "")),
                ))
            if not evidence_records:
                lines.append("- %s · %s · %s" % (
                    inline_code(item.get("source", "unknown")),
                    inline_code(f"{raw_path}:{item.get('line', 0)}"),
                    evidence,
                ))
            lines.append("")
            if analysis_mode == "source-only":
                lines.extend([
                    "> ⚠️ **纯源码分析，尚未经过目标项目构建验证**",
                    "",
                ])
            lines.extend(["**不支持自动修复**", ""])
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
