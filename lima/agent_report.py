"""Report agent with offline CVE matching (plan Task 6, design section 7).

Renders one eRST-style vulnerability research dossier (Chinese Markdown)
per :class:`~lima.agent_orchestrator.PlatformFinding`, following the
user's disclosure template (0 metadata / 1 profile / 2 target context /
3 technical analysis / 4 reproduction / 5 impact / 6 remediation and
disclosure), plus an offline CVE index matcher.

Honesty invariants implemented here (design section 9):

- the "已通过 ASAN 物理验证" wording is reachable only when the finding's
  own experiment ledger contains an executed, hit ASan experiment; a
  bare ``runtime-confirmed`` label without that ledger is downgraded to
  待复核 at the report boundary (无实证不写"已验证");
- evidence-proportional severity: ``runtime-confirmed``/``fact-verified``
  map to 高危, tool-corroborated to 中危, everything else (including
  ``semantic-supported``) to 低危 -- unproven findings never parade as
  high severity;
- CVE matching is a strict three-key offline match against a local index
  (component prefix, ``fnmatch`` path glob, commit-window overlap when a
  commit window is provided); no match yields no CVE claim, rendered as
  暂无对应公开 CVE（待评审）.  The index is data supplied by the operator
  (NVD/CVE downloads); this module never queries the network.

Untrusted text (hypothesis, snippets, ledger entries) is rendered inside
fenced code blocks with the fence length chosen above the longest
backtick run in the content, so data cannot break out of its block; the
report is Markdown for humans, so no HTML escaping is applied.
"""

from __future__ import annotations

import datetime
import fnmatch
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Final

from .agent_orchestrator import PlatformFinding

__all__ = [
    "CWE_DISPLAY_NAMES",
    "CVE_ENTRY_FIELDS",
    "DossierContext",
    "STATE_SEVERITY",
    "STATE_STATUS",
    "generate_all_dossiers",
    "generate_dossier",
    "load_cve_index",
    "match_cve",
    "severity_for_state",
    "status_for_state",
]


# ------------------------------------------------------------------ states


STATE_STATUS: Final[dict[str, str]] = {
    "runtime-confirmed": "已通过 ASAN 物理验证",
    "fact-verified": "已通过确定性静态证明",
    "semantic-supported": "语义支持，待复核",
}

STATE_SEVERITY: Final[dict[str, str]] = {
    "runtime-confirmed": "高危",
    "fact-verified": "高危",
    "tool-corroborated": "中危",
    "semantic-supported": "低危",
}

_STATUS_PENDING: Final = "待复核"
_SEVERITY_PENDING: Final = "低危"
_SEVERITY_RANK: Final[dict[str, int]] = {"高危": 0, "中危": 1, "低危": 2}


def status_for_state(state: str) -> str:
    """The eRST status wording for one finding state (pure mapping)."""

    return STATE_STATUS.get(state, _STATUS_PENDING)


def severity_for_state(state: str) -> str:
    """The evidence-proportional severity for one finding state."""

    return STATE_SEVERITY.get(state, _SEVERITY_PENDING)


CWE_DISPLAY_NAMES: Final[dict[str, tuple[str, str]]] = {
    "CWE-416": ("Use After Free", "释放后使用"),
    "CWE-415": ("Double Free", "重复释放"),
    "CWE-787": ("Out-of-bounds Write", "越界写入"),
    "CWE-125": ("Out-of-bounds Read", "越界读取"),
    "CWE-476": ("NULL Pointer Dereference", "空指针解引用"),
    "CWE-190": ("Integer Overflow or Wraparound", "整数溢出"),
}


# --------------------------------------------------------------- cve index


CVE_ENTRY_FIELDS: Final = frozenset({
    "cve_id",
    "component",
    "affected_paths",
    "introduced_commit",
    "fixed_commit",
    "summary",
})

_CVE_ID_RE: Final = re.compile(r"CVE-\d{4}-\d{4,}\Z")
_INTERNAL_ID_RE: Final = re.compile(r"LIMA-FIND-\d{4}-\d{3}\Z")


def _validate_entry(entry: Any, origin: str) -> dict:
    """Validate one offline index entry; any deviation raises ValueError."""

    label = f"{origin}: CVE index entry"
    if not isinstance(entry, dict):
        raise ValueError(f"{label} must be a JSON object")
    if set(entry) != CVE_ENTRY_FIELDS:
        raise ValueError(f"{label} fields do not match the frozen schema")
    cve_id = entry["cve_id"]
    if not isinstance(cve_id, str) or not _CVE_ID_RE.match(cve_id):
        raise ValueError(f"{label} cve_id must match CVE-YYYY-NNNN+")
    component = entry["component"]
    if not isinstance(component, str) or not component:
        raise ValueError(f"{label} component must be non-empty text")
    paths = entry["affected_paths"]
    if not isinstance(paths, list) or not paths:
        raise ValueError(f"{label} affected_paths must be a non-empty list")
    if any(not isinstance(item, str) or not item for item in paths):
        raise ValueError(f"{label} affected_paths entries must be non-empty text")
    for field in ("introduced_commit", "fixed_commit"):
        if not isinstance(entry[field], str):
            raise ValueError(f"{label} {field} must be text")
    summary = entry["summary"]
    if not isinstance(summary, str) or not summary:
        raise ValueError(f"{label} summary must be non-empty text")
    return {
        "cve_id": cve_id,
        "component": component,
        "affected_paths": list(paths),
        "introduced_commit": entry["introduced_commit"],
        "fixed_commit": entry["fixed_commit"],
        "summary": summary,
    }


def _load_index_file(path: Path) -> list[dict]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read CVE index file {path.name}: {exc}") from exc
    if not isinstance(payload, list):
        raise ValueError(f"CVE index file {path.name} must hold a JSON list")
    return [
        _validate_entry(entry, path.name) for entry in payload
    ]


def load_cve_index(dir_or_file: str | Path) -> list[dict]:
    """Load and validate an offline CVE index from one file or a directory.

    In directory mode every ``*.json`` file is loaded in sorted name order,
    except ``*.schema.json`` files (schemas document the format, they are
    not data).  Missing fields, wrong types, unknown fields, malformed CVE
    ids and duplicate ids raise ``ValueError`` -- a corrupt index never
    silently shrinks to its valid subset.
    """

    root = Path(dir_or_file)
    if root.is_dir():
        files = sorted(
            item for item in root.glob("*.json")
            if not item.name.endswith(".schema.json")
        )
    elif root.is_file():
        files = [root]
    else:
        raise ValueError(f"CVE index path not found: {root}")
    entries: list[dict] = []
    seen: set[str] = set()
    for path in files:
        for entry in _load_index_file(path):
            if entry["cve_id"] in seen:
                raise ValueError(
                    f"duplicate cve_id {entry['cve_id']} in the offline index"
                )
            seen.add(entry["cve_id"])
            entries.append(entry)
    return entries


def _component_match(left: str, right: str) -> bool:
    """Component key: either side is a prefix of the other (case exact)."""

    return bool(left) and bool(right) and (
        left.startswith(right) or right.startswith(left)
    )


def match_cve(
    component: str,
    path: str,
    introduced_range: Sequence[str] | None,
    cve_index: Sequence[Mapping[str, Any]],
) -> tuple[str, ...]:
    """Three-key offline CVE match; no match yields an empty tuple.

    Keys, all of which must hold:

    1. component: the entry component and ``component`` are mutual
       non-empty prefixes of each other;
    2. path: ``path`` matches at least one ``affected_paths`` glob
       (``fnmatch.fnmatchcase`` -- case exact on every platform);
    3. commits: skipped entirely when ``introduced_range`` is ``None``;
       otherwise ``introduced_range`` is the sequence of commit hashes in
       the finding's vulnerable window and an entry overlaps when either
       of its ``introduced_commit``/``fixed_commit`` hashes appears in
       that window.  An entry without commit data cannot be excluded by
       this key (unknown timeline), but a window that excludes the
       indexed commits rules the entry out.

    The result is the deduplicated CVE ids in sorted order -- offline
    data in, offline answers out; nothing is ever guessed.
    """

    window = (
        frozenset(introduced_range)
        if introduced_range is not None
        else None
    )
    matched: set[str] = set()
    for entry in cve_index:
        if not _component_match(component, entry.get("component", "")):
            continue
        globs = entry.get("affected_paths", ())
        if not any(_path_matches(path, glob) for glob in globs):
            continue
        if window is not None:
            commits = {
                entry.get("introduced_commit", ""),
                entry.get("fixed_commit", ""),
            }
            commits.discard("")
            if commits and not commits & window:
                continue
        matched.add(entry["cve_id"])
    return tuple(sorted(matched))


def _path_matches(path: str, glob: str) -> bool:
    return fnmatch.fnmatchcase(path, glob)


# ----------------------------------------------------------------- dossier


@dataclass(frozen=True)
class DossierContext:
    """Scan-level context shared by every dossier of one review run.

    ``openharmony_versions`` carries the affected OpenHarmony version
    list, or (for oil-and-gas repositories) the branch/version tags the
    scan ran against.  ``known_commits`` optionally supplies the commit
    window used by the offline CVE matcher.  ``internal_id`` is assigned
    by :func:`generate_all_dossiers`; single-dossier callers must set it.
    """

    repository: str
    component: str
    openharmony_versions: tuple[str, ...] = ()
    commit_range: str = ""
    poc_driver_code: str = ""
    experiment_log: tuple[dict, ...] = ()
    cve_ids: tuple[str, ...] = ()
    patch_suggestion: str = ""
    internal_id: str = ""
    known_commits: tuple[str, ...] = ()


_REPORT_TITLE: Final = "# 漏洞研究报告 (Vulnerability Research Dossier)"
_TOOLCHAIN: Final = (
    "Debian bookworm 容器（复现工作台），clang++-14 + AddressSanitizer"
    "（`-fsanitize=address -g -O1`，快照内编译运行，沙箱五层锁）"
)
_NO_CVE_TEXT: Final = "暂无对应公开 CVE（待评审）"
_PATCH_PLACEHOLDER: Final = (
    "（占位）智能体补丁生成与 PoC 回归验证尚未接入（平台计划后续任务）；"
    "在补丁通过\"应用后重跑 PoC 不再触发\"的回归验证前，不提供修复承诺。"
)
_DISCLOSURE_NEW: Final = (
    "LIMA 智能体平台新发现，暂无对应公开 CVE：拟提交 OpenHarmony 安全奖励"
    "计划评审（当前标注：待评审）。"
)


def _fence(content: str, language: str) -> str:
    """Fence ``content`` with a run of backticks longer than any inside."""

    longest = max((len(run) for run in re.findall(r"`+", content)), default=2)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{content.rstrip(chr(10))}\n{fence}"


def _has_runtime_hit(experiment_log: Sequence[Any]) -> bool:
    return any(
        isinstance(entry, Mapping)
        and bool(entry.get("ok"))
        and bool(entry.get("hit"))
        for entry in experiment_log
    )


def _effective_status(finding: PlatformFinding) -> str:
    """Status wording, capped by the finding's own experiment ledger.

    ``runtime-confirmed`` claims physical verification only when the
    ledger holds an executed ASan experiment that hit; otherwise the
    report boundary downgrades to 待复核 (无实证不写"已验证").
    """

    if finding.state == "runtime-confirmed" and not _has_runtime_hit(
        finding.experiment_log,
    ):
        return _STATUS_PENDING + "（runtime-confirmed 标注缺少命中的实验记录）"
    return status_for_state(finding.state)


def _effective_severity(finding: PlatformFinding) -> str:
    if finding.state == "runtime-confirmed" and not _has_runtime_hit(
        finding.experiment_log,
    ):
        return _SEVERITY_PENDING
    return severity_for_state(finding.state)


def _cwe_label(cwe: str) -> tuple[str, str]:
    return CWE_DISPLAY_NAMES.get(cwe, (cwe or "未知类型", cwe or "未知类型"))


def _display(entry: Any) -> str:
    return str(entry) if entry not in (None, "") else "（未提供）"


def _section_metadata(finding: PlatformFinding, context: DossierContext) -> str:
    cwe_en, cwe_cn = _cwe_label(finding.cwe)
    subject = finding.symbol or finding.path.rsplit("/", 1)[-1]
    return "\n".join([
        "## 0. 基本信息 (Metadata)",
        "",
        f"- **内部编号**: {context.internal_id}",
        f"- **漏洞名称**: `{subject}` {cwe_cn}漏洞 ({cwe_en})",
        "- **发现方式**: LIMA C/C++ 智能体平台自动发现"
        "（假设-实验-修正闭环 + 确定性仪器咨询）",
        f"- **发现日期**: {datetime.date.today().isoformat()}",
        f"- **当前状态**: {_effective_status(finding)}",
        "- **CVE 编号**: "
        + ("、".join(context.cve_ids) if context.cve_ids else _NO_CVE_TEXT),
    ])


def _section_profile(finding: PlatformFinding, context: DossierContext) -> str:
    cwe_en, cwe_cn = _cwe_label(finding.cwe)
    return "\n".join([
        "## 1. 漏洞概览 (Vulnerability Profile)",
        "",
        f"- **漏洞类型**: {finding.cwe or '未知'}: {cwe_en} ({cwe_cn})",
        f"- **风险等级**: {_effective_severity(finding)}"
        "（按证据等级映射，未实证发现按低等级汇报）",
        f"- **影响组件**: {context.component}（`{finding.path}:"
        f"{finding.line}`，符号 `{finding.symbol or '未知'}`）",
        f"- **一句话总结**: {_display(finding.hypothesis_reason)}",
    ])


def _section_target(context: DossierContext) -> str:
    versions = (
        "、".join(context.openharmony_versions)
        if context.openharmony_versions
        else "（未提供）"
    )
    return "\n".join([
        "## 2. 目标环境 (Target Context)",
        "",
        f"- **源码仓库**: {context.repository}",
        f"- **影响组件**: {context.component}",
        f"- **版本/分支**: {versions}",
        f"- **提交范围**: {_display(context.commit_range)}",
        f"- **编译验证环境**: {_TOOLCHAIN}",
    ])


def _section_analysis(finding: PlatformFinding) -> str:
    lines = [
        "## 3. 技术分析 (Technical Deep Dive)",
        "",
        "### 3.1 缺陷位置与触发路径",
        "",
        f"- **缺陷位置**: `{finding.path}` 第 {finding.line} 行，"
        f"符号 `{finding.symbol or '未知'}`",
        f"- **智能体假设（Specialist 原文）**: {_display(finding.hypothesis_reason)}",
        "",
        "### 3.2 证据记录",
        "",
    ]
    records = tuple(finding.evidence_records)
    if not records:
        lines.append("（暂无证据记录——该发现未经工具或实验佐证，按低等级汇报）")
        return "\n".join(lines)
    for index, record in enumerate(records, start=1):
        source = getattr(record, "source", "?")
        kind = getattr(record, "kind", "?")
        path = getattr(record, "path", "?")
        line = getattr(record, "line", 0)
        rule = getattr(record, "rule_id", "") or "-"
        run_id = getattr(record, "tool_run_id", "") or "-"
        lines.append(
            f"- 证据 {index}: [{source}/{kind}] `{path}:{line}`"
            f"（rule `{rule}`，run `{run_id}`）"
        )
        snippet = getattr(record, "snippet", "")
        if snippet:
            lines.append("")
            lines.append(_fence(str(snippet), "text"))
    return "\n".join(lines)


def _compile_commands(finding: PlatformFinding) -> str:
    return "\n".join([
        "clang++-14 -fsanitize=address -g -O1 "
        f"{finding.path} poc_driver.cpp -o poc_driver",
        "./poc_driver",
    ])


def _section_reproduction(finding: PlatformFinding, context: DossierContext) -> str:
    driver = finding.poc_driver_code or context.poc_driver_code
    lines = [
        "## 4. 复现指南 (Reproduction)",
        "",
        "### 4.1 PoC 触发驱动（`poc_driver.cpp`，Specialist/Critic 生成，实验台账留痕）",
        "",
    ]
    if driver:
        lines.append(_fence(driver, "cpp"))
    else:
        lines.append("（暂无 PoC 驱动——该发现未生成可执行触发程序）")
    lines.extend([
        "",
        "### 4.2 编译与运行（复现工作台同款命令：clang++-14 + ASan）",
        "",
    ])
    if driver:
        lines.append(_fence(_compile_commands(finding), "bash"))
    else:
        lines.append("（无驱动则无编译运行命令——不虚构验证步骤）")
    lines.extend(["", "### 4.3 实验台账摘要", ""])
    ledger = finding.experiment_log or context.experiment_log
    if ledger:
        rendered = []
        for entry in ledger:
            if isinstance(entry, Mapping):
                flattened = " ".join(
                    f"{key}={entry[key]}" for key in sorted(entry)
                )
            else:
                flattened = repr(entry)
            rendered.append(flattened[:400])
        lines.append(_fence("\n".join(rendered), "text"))
    else:
        lines.append("（暂无已执行实验记录——不得据此宣称物理验证）")
    return "\n".join(lines)


def _section_impact(finding: PlatformFinding, context: DossierContext) -> str:
    module = (
        finding.path.rsplit("/", 1)[0] if "/" in finding.path else "."
    )
    versions = (
        "、".join(context.openharmony_versions)
        if context.openharmony_versions
        else "（未提供）"
    )
    cves = (
        "、".join(context.cve_ids)
        if context.cve_ids
        else _NO_CVE_TEXT + "——离线索引三键（组件/路径/提交窗）无匹配，不臆测"
    )
    return "\n".join([
        "## 5. 影响分析 (Impact Analysis)",
        "",
        f"- **影响模块**: `{module}`（由缺陷路径推断）",
        f"- **影响版本**: {versions}"
        + (f"，提交范围 `{context.commit_range}`" if context.commit_range else ""),
        f"- **CVE 匹配**: {cves}",
    ])


def _section_remediation(context: DossierContext) -> str:
    suggestion = context.patch_suggestion or _PATCH_PLACEHOLDER
    disclosure = (
        f"已匹配已知公开 CVE（{'、'.join(context.cve_ids)}）；"
        "披露前请核对受影响范围与官方通告。"
        if context.cve_ids
        else _DISCLOSURE_NEW
    )
    return "\n".join([
        "## 6. 修复建议与披露 (Remediation & Disclosure)",
        "",
        f"- **修复建议**: {suggestion}",
        f"- **披露计划**: {disclosure}",
    ])


def generate_dossier(finding: PlatformFinding, context: DossierContext) -> str:
    """Render one eRST-style Chinese Markdown dossier for ``finding``.

    The report states exactly what its evidence supports: the status
    wording comes from the finding state with the physical-verification
    claim gated on the finding's own hit experiments, and CVE claims come
    only from ``context.cve_ids`` (batch callers fill them via
    :func:`match_cve`).
    """

    if not isinstance(finding, PlatformFinding):
        raise ValueError("finding must be a PlatformFinding")
    if not isinstance(context, DossierContext):
        raise ValueError("context must be a DossierContext")
    if not _INTERNAL_ID_RE.match(context.internal_id):
        raise ValueError(
            "context.internal_id must match LIMA-FIND-YYYY-NNN "
            "(use generate_all_dossiers for automatic assignment)"
        )
    if not context.repository or not context.component:
        raise ValueError("context.repository/component must be non-empty text")
    sections = [
        _REPORT_TITLE,
        _section_metadata(finding, context),
        _section_profile(finding, context),
        _section_target(context),
        _section_analysis(finding),
        _section_reproduction(finding, context),
        _section_impact(finding, context),
        _section_remediation(context),
    ]
    return "\n\n".join(sections) + "\n"


def generate_all_dossiers(
    findings: Sequence[PlatformFinding],
    context: DossierContext,
    cve_index: Sequence[Mapping[str, Any]],
) -> list[tuple[PlatformFinding, str]]:
    """Render dossiers for every finding, highest severity first.

    Findings are ordered by effective severity (高危→中危→低危), then
    path, line and target id, and receive deterministic internal ids
    ``LIMA-FIND-<year>-NNN`` in that order.  When ``context.cve_ids`` is
    empty, each finding's CVE list is filled by the offline three-key
    :func:`match_cve` against ``cve_index`` (no match stays no match).
    """

    if not isinstance(context, DossierContext):
        raise ValueError("context must be a DossierContext")
    ordered = sorted(
        findings,
        key=lambda item: (
            _SEVERITY_RANK[_effective_severity(item)],
            item.path,
            item.line,
            item.target_id,
        ),
    )
    year = datetime.date.today().year
    results: list[tuple[PlatformFinding, str]] = []
    for index, finding in enumerate(ordered, start=1):
        matched = match_cve(
            context.component,
            finding.path,
            context.known_commits or None,
            cve_index,
        )
        item_context = replace(
            context,
            internal_id=f"LIMA-FIND-{year}-{index:03d}",
            cve_ids=context.cve_ids or matched,
            poc_driver_code=context.poc_driver_code or finding.poc_driver_code,
            experiment_log=context.experiment_log or finding.experiment_log,
        )
        results.append((finding, generate_dossier(finding, item_context)))
    return results
