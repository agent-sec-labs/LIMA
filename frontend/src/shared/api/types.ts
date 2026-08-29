/**
 * 与后端 T1/T2 契约对齐的运行时类型（lima/task_progress.py、lima/task_failure.py）。
 * 后续 feature 目录复用这些类型，不重复手写。
 */

export const TASK_STAGES = [
  "QUEUED",
  "RESOLVING_REVISION",
  "CHECKING_CACHE",
  "DOWNLOADING_ARCHIVE",
  "VALIDATING_ARCHIVE",
  "PREPARING_WORKSPACE",
  "INVENTORY",
  "DATAFLOW_ANALYSIS",
  "AST_ANALYSIS",
  "SAST_ANALYSIS",
  "SEMANTIC_TRIAGE",
  "FINALIZING",
  "COMPLETED",
] as const;

export type TaskStage = (typeof TASK_STAGES)[number];

export interface TaskProgress {
  stage: TaskStage;
  stage_index: number;
  stage_total: number;
  message: string;
  started_at: string;
  stage_started_at: string;
  updated_at: string;
  attempt: number;
  max_attempts: number;
  current: number | null;
  total: number | null;
  unit: string;
  detail: Record<string, unknown>;
}

/** 任务列表使用的轻量投影（无时间戳与 detail）。 */
export interface TaskProgressSummary {
  stage: TaskStage;
  stage_index: number;
  stage_total: number;
  message: string;
  attempt: number;
  max_attempts: number;
  current: number | null;
  total: number | null;
  unit: string;
}

export interface TaskFailure {
  code: string;
  category: string;
  stage: string;
  title: string;
  message: string;
  retryable: boolean;
  suggestion: string;
  technical_detail: string;
  detail: Record<string, unknown>;
}

export interface TaskWarning {
  code: string;
  category: string;
  path?: string;
  message: string;
}

export type TaskLifecycleState =
  | "PENDING"
  | "PLANNING"
  | "EXECUTING"
  | "REVIEWING"
  | "SUCCESS"
  | "FAILED"
  | "CANCELLED";

export interface TaskListItem {
  id: string;
  state: TaskLifecycleState;
  repository: string;
  task_type: string;
  pull_request?: number | null;
  created_at: string;
  updated_at: string;
  error: string | null;
  progress: TaskProgressSummary | null;
}

/** T4 完成载荷：progress.detail.completion（skip≥1 即 warnings）。 */
export interface TaskCompletion {
  status: "completed" | "completed_with_warnings";
  warning_count: number;
  warnings?: Record<string, number>;
}

export interface FindingItem {
  severity?: string;
  rule_id?: string;
  cwe?: string;
  path?: string;
  line?: number;
  title?: string;
  verification_state?: string;
  source?: string;
  confidence?: number;
  evidence?: string;
  explanation?: string;
  fix?: string;
}

export interface ScanReport {
  repository?: string;
  risk?: string;
  reviewer?: string;
  summary?: string;
  findings?: FindingItem[];
  files_reviewed?: string[] | number;
  adjudication?: { policy?: string; overall_disposition?: string };
  collaboration?: {
    scanned_files?: number;
    scanned_bytes?: number;
    workspace_truncated?: boolean;
    skipped?: Record<string, number>;
    import_policy?: {
      resolved_revision?: string;
      cache_hit?: boolean;
      repository_key?: string;
      archive_sha256?: string;
      source?: Record<string, unknown>;
    };
    [key: string]: unknown;
  };
}

/** GET /v1/tasks/:id 的完整任务详情（store 水合后形态）。 */
export interface TaskDetail {
  id: string;
  state: TaskLifecycleState;
  repository: string;
  pull_request?: number | null;
  created_at?: string;
  updated_at?: string;
  error?: string | null;
  input?: Record<string, unknown>;
  report?: ScanReport | null;
  progress?: TaskProgress | null;
  failure?: TaskFailure | null;
}

export interface HealthPayload {
  status: string;
  version: string;
  reviewer: string;
  runtime: string;
  queue: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  tenant_id: string;
  role: string;
}
