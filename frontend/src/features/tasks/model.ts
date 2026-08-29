import {
  TASK_STAGES,
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
  low: { label: "低危", color: "blue" },
  info: { label: "提示", color: "default" },
};

export function severityMeta(severity: string | undefined): { label: string; color: string } {
  return SEVERITY_META[String(severity ?? "").toLowerCase()] ?? SEVERITY_META.info;
}

const VERIFICATION_LABELS: Record<string, string> = {
  candidate: "候选",
  "syntax-verified": "语法验证",
  corroborated: "多源佐证",
  "dataflow-verified": "数据流验证",
  confirmed: "已确认",
};

export function verificationLabel(state: string | undefined): string {
  return VERIFICATION_LABELS[String(state ?? "")] ?? String(state ?? "—");
}

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
