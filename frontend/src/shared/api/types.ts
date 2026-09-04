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
  fingerprint?: string;
}

/** 仲裁决策：后端给出或由客户端按 verification_state 推导（与 legacy 语义一致）。 */
export interface AdjudicationDecision {
  fingerprint?: string;
  path?: string;
  line?: number;
  start_line?: number;
  symbol?: string;
  rule_id?: string;
  disposition: "alert" | "needs_review" | "clear";
  reason: string;
  decision_source?: string;
  llm_root_cause?: string;
  llm_mitigation_evidence?: string;
  llm_sink_evidence?: string;
}

export interface ScanAdjudication {
  policy?: string;
  overall_disposition?: string;
  overall_reason?: string;
  auto_clear?: boolean;
  counts?: { alert?: number; needs_review?: number; clear?: number };
  decisions?: AdjudicationDecision[];
}

/** 语义复核状态（report.collaboration.semantic_triage）。 */
export interface SemanticTriage {
  status?: string;
  mode?: string;
  provider?: string;
  model?: string;
  retrieval?: { evidence_candidates?: number };
  usage?: { total_tokens?: number };
  latency_ms?: number;
}

export interface ScanReport {
  repository?: string;
  risk?: string;
  reviewer?: string;
  summary?: string;
  findings?: FindingItem[];
  files_reviewed?: string[] | number;
  file_count?: number;
  adjudication?: ScanAdjudication;
  collaboration?: {
    scanned_files?: number;
    scanned_bytes?: number;
    workspace_truncated?: boolean;
    skipped?: Record<string, number>;
    semantic_triage?: SemanticTriage;
    import_policy?: {
      resolved_revision?: string;
      cache_hit?: boolean;
      repository_key?: string;
      archive_sha256?: string;
      source?: { requested_ref?: string; [key: string]: unknown };
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

/** POST /v1/tasks/:id/repair-preview（repair_preview.py 契约）。 */
export interface RepairPreviewResult {
  task_id?: string;
  repository?: string;
  status: "verified-preview" | "blocked" | "no-repair" | string;
  snapshot_sha256?: string;
  files_changed?: number;
  changed_lines?: number;
  rules?: string[];
  strategies?: string[];
  patches?: { path: string; diff: string }[];
  blocked_findings?: unknown[];
  verification?: { passed?: boolean; checks?: string[] };
  publication_ready?: boolean;
  note?: string;
  duration_seconds?: number;
  [key: string]: unknown;
}

/** POST /v1/tasks/:id/fix（fixer.create_fix_commits 契约）。 */
export interface FixResult {
  branch: string | null;
  source_sha?: string;
  commits?: unknown[];
  note?: string;
  [key: string]: unknown;
}

export type FeedbackCategory = "false_positive" | "missed_issue" | "bad_fix";

export interface FeedbackPayload {
  category: FeedbackCategory;
  finding: FindingItem | null;
  note: string;
}

/** GET /v1/tasks/:id/feedback → cases（store.list_task_failure_cases 行）。 */
export interface FeedbackCase {
  id?: number;
  task_id?: string;
  category: string;
  payload?: { finding?: FindingItem | null; note?: string };
  resolved?: boolean | number;
  created_at?: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  tenant_id: string;
  role: string;
}
