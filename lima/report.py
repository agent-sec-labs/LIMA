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
    message = re.sub(r"https?://[^\s`]+", "[内部地址已隐藏]", message, flags=re.I)
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
    """Encode bounded tool text for a single Markdown prose or heading line."""

    text = " ".join(_safe_cxx_text(value, maximum).splitlines())
    text = html.escape(text, quote=False)
    if re.match(r"^(?:#{1,6}(?:\s|$)|[-+*]\s|\d+[.)]\s|`{3,}|~{3,})", text):
        text = "&#8203;" + text
    return text


def _cxx_inline_code(value: Any) -> str:
    """Return one safe CommonMark code span for untrusted tool text."""

    text = _cxx_markdown_prose(value)
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
            lines.append("✅ No actionable issue detected in the added lines.")
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
        path = display(item.get("path", ""))
        evidence = display(item.get("evidence", ""))
        source = display(item.get("source", "unknown"))
        evidence_block = (
            _cxx_evidence_block(item.get("evidence", ""))
            if is_cxx
            else ("```text", evidence, "```")
        )
        lines.extend(
            [
                "### %d. %s %s" % (index, icons.get(severity, "•"), display(item.get("title", "Finding"))),
                "",
                "%s · **%s** · %s · %s · %s" % (
                    inline_code(f"{path}:{item.get('line', 0)}"),
                    severity.upper(),
                    inline_code(item.get("rule_id", "")),
                    inline_code(item.get("cwe", "unmapped") or "unmapped"),
                    inline_code(item.get("verification_state", "candidate")),
                ),
                "",
                display(item.get("explanation", "")),
                "",
                "**Evidence**",
                "",
                *evidence_block,
                "",
                "**Suggested fix:** %s" % display(item.get("fix", "")),
                "",
                "**Suggested test:** %s" % display(item.get("test", "")),
                "",
                "**Evidence sources:** %s" % inline_code(source),
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
                "- Location: %s" % inline_code(f"{path}:{item.get('line', 0)}"),
                "- CWE: %s" % inline_code(item.get("cwe", "unmapped") or "unmapped"),
                "- Analysis mode: %s · **%s**" % (
                    inline_code(item.get("analysis_mode", "unknown")),
                    _analysis_mode_label(analysis_mode),
                ),
                "- Verification state: %s · %s" % (
                    inline_code(item.get("verification_state", "candidate")),
                    _verification_state_label(item.get("verification_state")),
                ),
                "- Tool: %s" % inline_code(source),
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
                record_path = display(record.get("path", ""))
                lines.append("- %s · %s · %s" % (
                    inline_code(record.get("source", "unknown")),
                    inline_code(f"{record_path}:{record.get('line', 0)}"),
                    display(record.get("snippet", "")),
                ))
            if not evidence_records:
                lines.append("- %s · %s · %s" % (
                    inline_code(source),
                    inline_code(f"{path}:{item.get('line', 0)}"),
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
