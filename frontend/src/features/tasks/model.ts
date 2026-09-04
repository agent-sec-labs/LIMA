import {
  TASK_STAGES,
  type AdjudicationDecision,
  type FindingItem,
  type ScanAdjudication,
  type ScanReport,
  type TaskDetail,
  type TaskListItem,
  type TaskLifecycleState,
  type TaskStage,
} from "@/shared/api/types";

/**
 * Task Center 领域模型：阶段/状态标签、终态判定与动态轮询间隔。
 * 轮询策略（issue #40）：活跃任务前 30s 每 2s 刷新、之后每 4s；
 * 终态即停；页面隐藏时由 TanStack 默认行为暂停，回焦即刷新。
 */

export const STAGE_LABELS: Record<TaskStage, string> = {
  QUEUED: "排队中",
  RESOLVING_REVISION: "解析版本",
  CHECKING_CACHE: "检查缓存",
  DOWNLOADING_ARCHIVE: "下载快照",
  VALIDATING_ARCHIVE: "校验归档",
  PREPARING_WORKSPACE: "准备工作区",
  INVENTORY: "文件盘点",
  DATAFLOW_ANALYSIS: "数据流分析",
  AST_ANALYSIS: "AST 分析",
  SAST_ANALYSIS: "SAST 分析",
  SEMANTIC_TRIAGE: "语义复核",
  FINALIZING: "生成报告",
  COMPLETED: "完成",
};

export const STATE_LABELS: Record<TaskLifecycleState, string> = {
  PENDING: "等待中",
  PLANNING: "规划中",
  EXECUTING: "分析中",
  REVIEWING: "证据复核中",
  SUCCESS: "已完成",
  FAILED: "失败",
  CANCELLED: "已取消",
};

export const TERMINAL_STATES: readonly TaskLifecycleState[] = ["SUCCESS", "FAILED", "CANCELLED"];

export function isTerminalState(state: TaskLifecycleState | string | undefined | null): boolean {
  return TERMINAL_STATES.includes(String(state ?? "").toUpperCase() as TaskLifecycleState);
}

export function stateColor(state: TaskLifecycleState | string): string {
  const value = String(state).toUpperCase();
  if (value === "SUCCESS") return "green";
  if (value === "FAILED") return "red";
  if (value === "CANCELLED") return "default";
  return "blue";
}

export function stageLabel(stage: string | undefined | null): string {
  return STAGE_LABELS[String(stage ?? "") as TaskStage] ?? String(stage ?? "—");
}

/** 详情轮询：任务创建后 30s 内 2s 一刷，之后 4s；终态停。 */
export function detailRefetchInterval(task: TaskDetail | null | undefined): number | false {
  if (!task || isTerminalState(task.state)) return false;
  const created = Date.parse(task.created_at ?? "");
  if (!Number.isNaN(created) && Date.now() - created > 30_000) return 4000;
  return 2000;
}

/** 列表轮询：存在非终态任务时 4s 一刷。 */
export function listRefetchInterval(tasks: TaskListItem[] | undefined): number | false {
  if (!tasks || tasks.length === 0) return false;
  return tasks.some((item) => !isTerminalState(item.state)) ? 4000 : false;
}

export function formatElapsed(fromIso?: string, toIso?: string): string {
  const from = Date.parse(fromIso ?? "");
  if (Number.isNaN(from)) return "—";
  const to = Date.parse(toIso ?? "");
  const end = Number.isNaN(to) ? Date.now() : to;
  const seconds = Math.max(0, Math.round((end - from) / 1000));
  if (seconds < 60) return `${seconds} 秒`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} 分 ${seconds % 60} 秒`;
  return `${Math.floor(minutes / 60)} 时 ${minutes % 60} 分`;
}

export function formatTime(iso?: string | null): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return String(iso);
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

const SEVERITY_META: Record<string, { label: string; color: string }> = {
  critical: { label: "严重", color: "red" },
  high: { label: "高危", color: "red" },
  medium: { label: "中危", color: "orange" },
  low: { label: "低危", color: "green" },
  info: { label: "提示", color: "default" },
  clean: { label: "未发现风险", color: "green" },
};

export function severityMeta(severity: string | undefined): { label: string; color: string } {
  return SEVERITY_META[String(severity ?? "").toLowerCase()] ?? SEVERITY_META.info;
}

export function severityCounts(findings: FindingItem[]): Record<string, number> {
  return findings.reduce(
    (counts, finding) => {
      const severity = String(finding.severity || "info").toLowerCase();
      counts[severity] = (counts[severity] || 0) + 1;
      return counts;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<string, number>,
  );
}

/** 报告风险：显式 risk 合法则用之，否则按发现严重度推导（含 clean）。 */
export function reportRisk(report: ScanReport | null | undefined, findings: FindingItem[]): string {
  const explicit = String(report?.risk || "").toLowerCase();
  if (SEVERITY_META[explicit]) return explicit;
  const counts = severityCounts(findings);
  if (counts.critical) return "critical";
  if (counts.high) return "high";
  if (counts.medium) return "medium";
  if (counts.low || counts.info) return "low";
  return "clean";
}

/** 置信度：>1 视为已是百分数（legacy 语义），未提供显示 —。 */
export function confidenceLabel(value: number | undefined): string {
  const number = Number(value);
  if (!Number.isFinite(number)) return "未提供";
  return `${Math.round((number <= 1 ? number : number / 100) * 100)}%`;
}

/** 证据状态：子串匹配（legacy 语义），未知态一律「候选 · 需复核」fail-closed。 */
export function verificationLabel(value: string | undefined): string {
  const state = String(value || "candidate").toLowerCase();
  if (state.includes("dataflow")) return "数据流已验证";
  if (state.includes("syntax")) return "语法约束已验证";
  if (state.includes("verified")) return "已验证";
  return "候选 · 需复核";
}

/** 已验证判定（子串 + corroborated/confirmed），推导处置时使用。 */
export function isVerifiedState(value: string | undefined): boolean {
  const state = String(value || "candidate").toLowerCase();
  return state.includes("verified") || state === "corroborated" || state === "confirmed";
}

export const DISPOSITION_LABELS: Record<string, string> = {
  alert: "确认告警",
  needs_review: "需要复核",
  clear: "证据通过",
};

export const DISPOSITION_REASONS: Record<string, string> = {
  "multi-agent-verification-approved-risk": "多 Agent 证据复核与仲裁已通过",
  "deterministic-syntax-risk-evidence": "确定性语法约束确认风险",
  "independent-evidence-corroborated-risk": "两个独立证据源相互印证",
  "source-to-sink-risk-evidence": "已确认不可信输入到危险调用的数据流",
  "confirmed-risk-evidence": "风险证据已经确认",
  "unverified-finding-requires-human-review": "当前只有候选证据，需要人工结合业务上下文判断",
  "risk-invariant-and-llm-agree": "风险不变量与模型结论一致",
  "risk-invariant-conflicts-with-llm": "风险不变量与模型结论冲突，禁止自动放行",
  "mitigation-invariant-and-llm-agree": "缓解不变量与模型 clean 结论一致",
  "mitigation-invariant-conflicts-with-llm": "缓解不变量与模型结论冲突",
  "invalid-or-missing-llm-verdict": "模型结论缺失或不符合输出契约",
  "llm-alert-without-deterministic-invariant": "模型报告风险，但尚缺少确定性不变量",
  "llm-clean-without-deterministic-safety-evidence": "模型认为安全，但没有确定性缓解证据",
  "clear-rejected-without-agreeing-safety-evidence": "放行请求缺少确定性缓解证据与有效模型 clean 结论",
  "semantic-triage-provider-failure": "远程模型调用失败，系统已禁止自动放行",
  "no-semantic-candidates-for-safety-proof": "没有足够的语义候选可以形成正向安全证明",
};

export function dispositionReason(reason: string | undefined): string {
  return DISPOSITION_REASONS[String(reason ?? "")] || String(reason ?? "") || "缺少处置依据";
}

const DISPOSITIONS: readonly string[] = ["alert", "needs_review", "clear"];

/** 仲裁视图：后端缺 adjudication 时按 verification_state fail-closed 推导。 */
export interface ReportAdjudication {
  policy: string;
  overall_disposition: "alert" | "needs_review" | "clear";
  auto_clear: boolean;
  counts: { alert: number; needs_review: number; clear: number };
  decisions: AdjudicationDecision[];
}

export function reportAdjudication(
  report: ScanReport | null | undefined,
  findings: FindingItem[],
): ReportAdjudication {
  const raw: ScanAdjudication =
    report?.adjudication && typeof report.adjudication === "object" ? report.adjudication : {};
  let decisions: AdjudicationDecision[] = Array.isArray(raw.decisions) ? raw.decisions : [];
  if (!Object.keys(raw).length) {
    decisions = findings.map((finding) => ({
      fingerprint: finding.fingerprint || "",
      path: finding.path || "",
      line: finding.line || 0,
      rule_id: finding.rule_id || "",
      disposition: isVerifiedState(finding.verification_state) ? "alert" : "needs_review",
      reason: isVerifiedState(finding.verification_state)
        ? "confirmed-risk-evidence"
        : "unverified-finding-requires-human-review",
    }));
  }
  const derivedCounts = decisions.reduce(
    (counts, decision) => {
      const disposition = DISPOSITIONS.includes(decision.disposition)
        ? decision.disposition
        : "needs_review";
      counts[disposition] += 1;
      return counts;
    },
    { alert: 0, needs_review: 0, clear: 0 } as Record<string, number>,
  );
  const counts = {
    alert: Number(raw.counts?.alert ?? derivedCounts.alert) || 0,
    needs_review: Number(raw.counts?.needs_review ?? derivedCounts.needs_review) || 0,
    clear: Number(raw.counts?.clear ?? derivedCounts.clear) || 0,
  };
  const explicit = String(raw.overall_disposition || "").toLowerCase();
  const overall: ReportAdjudication["overall_disposition"] = DISPOSITIONS.includes(explicit)
    ? (explicit as ReportAdjudication["overall_disposition"])
    : counts.alert
      ? "alert"
      : counts.needs_review
        ? "needs_review"
        : counts.clear
          ? "clear"
          : "needs_review";
  return {
    policy: raw.policy || "legacy-fail-closed",
    overall_disposition: overall,
    auto_clear: raw.auto_clear === true && overall === "clear",
    counts,
    decisions,
  };
}

/** 单条发现的处置决策：先 fingerprint 精确匹配，再 (path, line, rule_id)。 */
export function decisionForFinding(
  finding: FindingItem,
  adjudication: ReportAdjudication,
): AdjudicationDecision {
  if (finding.fingerprint) {
    const exact = adjudication.decisions.find(
      (decision) => decision.fingerprint === finding.fingerprint,
    );
    if (exact) return exact;
  }
  return (
    adjudication.decisions.find(
      (decision) =>
        decision.path === finding.path &&
        Number(decision.line || 0) === Number(finding.line || 0) &&
        decision.rule_id === finding.rule_id,
    ) || {
      disposition: "needs_review",
      reason: "unverified-finding-requires-human-review",
    }
  );
}

export const FEEDBACK_LABELS: Record<string, string> = {
  false_positive: "误报",
  missed_issue: "漏报",
  bad_fix: "坏修复",
  accepted: "已接受",
};

export const SEMANTIC_STATUS_LABELS: Record<string, string> = {
  completed: "模型复核完成",
  "invalid-contract": "输出契约无效",
  "failed-closed": "调用失败 · 已关闭放行",
  "no-candidates": "没有可复核候选",
  disabled: "未启用",
  "llm-not-configured": "模型未配置",
};

/** 运行中任务的来源摘要（github 显示 canonical_name@ref，本地显示仓库键）。 */
export function sourceSummary(task: TaskDetail): string {
  const input = (task.input ?? {}) as {
    repository_key?: string;
    scan_source?: { canonical_name?: string; requested_ref?: string; repository_key?: string };
  };
  const scan = input.scan_source;
  if (scan?.canonical_name) {
    return scan.requested_ref
      ? `${scan.canonical_name} @ ${scan.requested_ref}`
      : String(scan.canonical_name);
  }
  return input.repository_key || task.repository || "—";
}

export function resolvedRevision(task: TaskDetail): string {
  const fromPolicy = task.report?.collaboration?.import_policy?.resolved_revision;
  const fromProgress = (task.progress?.detail ?? {}) as { resolved_revision?: string };
  return fromPolicy || fromProgress.resolved_revision || "";
}

export const ALL_STAGES: readonly TaskStage[] = TASK_STAGES;
