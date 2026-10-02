import type { FieldErrors, Resolver } from "react-hook-form";
import type { CxxAgentCapabilities, RepositoryScanRequest } from "@/shared/api/types";
import { z } from "zod";

/**
 * audit-create 领域模型：Zod 契约、草稿保持与提交载荷。
 *
 * A/B/C 三态边界（Epic #33）：A=editing（草稿可编辑，导航往返不丢）、
 * B=submitting（收到 202 前的瞬态）、C=任务中心（/tasks/:id 独占异步状态）。
 */

export const AUDIT_MODES = ["repository", "diff"] as const;
export const SOURCE_MODES = ["local", "github"] as const;
export type AuditMode = (typeof AUDIT_MODES)[number];
export type SourceMode = (typeof SOURCE_MODES)[number];

/**
 * agentDetection 三态：null = 用户尚未选择（等 capabilities 初始化开关）；
 * 一旦落为 true/false 即为用户可见的明确选择，异步响应不得再覆盖
 * （方案 §4.2；null 随草稿缓存持久，导航往返不丢）。
 */
export interface AuditDraft {
  mode: AuditMode;
  sourceMode: SourceMode;
  repository: string;
  githubRef: string;
  diff: string;
  pullRequest: string;
  agentDetection: boolean | null;
}

export const EMPTY_DRAFT: AuditDraft = {
  mode: "repository",
  sourceMode: "local",
  repository: "",
  githubRef: "",
  diff: "",
  pullRequest: "",
  agentDetection: null,
};

// SPA 内模块级草稿缓存：路由卸载/返回不丢数据；202 后显式清空。
let draftStore: AuditDraft = { ...EMPTY_DRAFT };

export function loadDraft(): AuditDraft {
  return { ...draftStore };
}

export function saveDraft(draft: AuditDraft): void {
  draftStore = { ...draft };
}

export function clearDraft(): void {
  draftStore = { ...EMPTY_DRAFT };
}

const SLUG = /^[A-Za-z0-9_.-]+$/;
const GITHUB_HOSTS = new Set(["github.com", "www.github.com"]);
const SHA_PATTERN = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/i;

export function isMovingRef(ref: string): boolean {
  const value = ref.trim();
  return value !== "" && !SHA_PATTERN.test(value);
}

/** 与 legacy `normalizeRepositoryTarget` 同语义的目标归一化（仅校验，不改写载荷）。 */
export function normalizeRepositoryTarget(raw: string): string {
  const value = String(raw ?? "")
    .trim()
    .replace(/\.git$/i, "");
  if (!value) throw new Error("请输入 GitHub 仓库链接或 owner/project 仓库键。");
  let candidate = value;
  if (/^https?:\/\//i.test(value)) {
    let parsed: URL;
    try {
      parsed = new URL(value);
    } catch {
      throw new Error("仓库链接格式无效。");
    }
    if (!GITHUB_HOSTS.has(parsed.hostname.toLowerCase())) {
      throw new Error("当前只接受 github.com 链接；其他来源请先安全导入 repositories 目录。");
    }
    candidate = parsed.pathname.replace(/^\/+|\/+$/g, "").replace(/\.git$/i, "");
  }
  const parts = candidate.split("/");
  if (
    parts.length !== 2 ||
    !parts.every((part) => SLUG.test(part)) ||
    parts.some((part) => part === "." || part === "..")
  ) {
    throw new Error("仓库目标应为 owner/project，不能包含绝对路径、目录穿越或额外层级。");
  }
  return parts.join("/");
}

export const auditDraftSchema = z
  .object({
    mode: z.enum(AUDIT_MODES),
    sourceMode: z.enum(SOURCE_MODES),
    repository: z.string(),
    githubRef: z.string(),
    diff: z.string(),
    pullRequest: z.string(),
    agentDetection: z.boolean().nullable(),
  })
  .superRefine((value, ctx) => {
    try {
      normalizeRepositoryTarget(value.repository);
    } catch (error) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["repository"],
        message: (error as Error).message,
      });
    }
    if (value.mode === "repository" && value.sourceMode === "github") {
      const ref = value.githubRef.trim();
      if (ref !== "" && (!/^[A-Za-z0-9_./-]{1,240}$/.test(ref) || ref.includes(".."))) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["githubRef"],
          message: "ref 只能包含字母、数字、/、_、.、-，且不能包含 “..” 目录段。",
        });
      }
    }
    if (value.mode === "diff") {
      const diff = value.diff.trim();
      const hasAddedLine = diff
        .split(/\r?\n/)
        .some((line) => line.startsWith("+") && !line.startsWith("+++"));
      if (!diff.includes("@@") || !hasAddedLine) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["diff"],
          message: "请粘贴包含 @@ 区块和新增行的 Unified Diff。",
        });
      }
      const pr = value.pullRequest.trim();
      if (pr !== "") {
        const number = Number(pr);
        if (!Number.isInteger(number) || number < 1) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["pullRequest"],
            message: "PR 编号必须是正整数。",
          });
        }
      }
    }
  });

export type AuditDraftForm = z.infer<typeof auditDraftSchema>;

/**
 * 轻量 Zod resolver：项目未引入 @hookform/resolvers，手写映射保持零新依赖。
 */
export function auditResolver(): Resolver<AuditDraft> {
  return async (values) => {
    const result = auditDraftSchema.safeParse(values);
    if (result.success) {
      return { values, errors: {} };
    }
    const errors: FieldErrors<AuditDraft> = {};
    for (const issue of result.error.issues) {
      const key = issue.path[0] as keyof AuditDraft | undefined;
      if (key !== undefined && errors[key] === undefined) {
        errors[key] = { type: String(issue.code), message: issue.message };
      }
    }
    return { values: {}, errors };
  };
}

export interface ScanCreatedResponse {
  task_id: string;
  state: string;
}

export interface ScanCapabilitiesPayload {
  enabled?: boolean;
  scan_sources?: {
    configured?: string;
    local_import?: boolean;
    github?: boolean;
  };
  /** #243 新增：按任务开启智能体检测的门禁字段（方案 §4.6）。 */
  cxx_agent?: CxxAgentCapabilities;
}

/** 智能体检测开关门禁（方案 §4.2 三态矩阵的前端只读投影）。 */
export interface AgentDetectionGate {
  /** #243 新字段齐备：可初始化开关并按状态提交。 */
  ready: boolean;
  /** 服务端策略锁定开启（required / per_request_switch=false）。 */
  lockedOn: boolean;
  /** 配置完整（模型 + 分析器），允许从关闭切到开启。 */
  canEnable: boolean;
  /** 服务端默认开启但配置不完整：必须暂停提交并提示管理员修复。 */
  defaultOnBlocked: boolean;
  /** 本次提交的有效开关值。 */
  effective: boolean;
  /** 模型调用次数上限（不是货币费用）。 */
  maxAgentCalls: number;
}

/**
 * 从 capabilities 推导开关门禁。旧服务端缺少 #243 新字段时 ready=false，
 * 不得按旧 configured 值猜测可用性（方案 §4.6）。
 */
export function agentDetectionGate(
  caps: CxxAgentCapabilities | null | undefined,
  agentDetection: boolean | null,
): AgentDetectionGate {
  const ready = Boolean(
    caps &&
      (caps.mode === "off" || caps.mode === "auto" || caps.mode === "required") &&
      typeof caps.per_request_switch === "boolean" &&
      typeof caps.llm_configured === "boolean" &&
      typeof caps.analyzer_configured === "boolean" &&
      typeof caps.max_agent_calls === "number",
  );
  if (!ready || !caps) {
    return {
      ready: false,
      lockedOn: false,
      canEnable: false,
      defaultOnBlocked: false,
      effective: agentDetection === true,
      maxAgentCalls: 0,
    };
  }
  const configured = caps.llm_configured === true && caps.analyzer_configured === true;
  const defaultOn = caps.mode !== "off";
  const lockedOn = caps.mode === "required" || caps.per_request_switch === false;
  return {
    ready: true,
    lockedOn,
    canEnable: configured,
    defaultOnBlocked: defaultOn && !configured,
    effective: lockedOn || (agentDetection ?? defaultOn),
    maxAgentCalls: Math.max(0, Math.floor(caps.max_agent_calls ?? 0)),
  };
}

/** 载荷与 legacy 行为一致：目标原样透传（服务端归一化），浏览器零 api.github.com。
 * 仓库模式两种来源都显式提交 agent_detection（新前端不依赖服务端默认）；
 * PR/diff 分支不带该字段（方案 §4.1）。
 * `agentDetection` 是有效策略值（required 锁定开启时为 true，见
 * agentDetectionGate）；缺省回退草稿值仅供纯模型层单测使用，页面提交
 * 必须显式传入 gate.effective（审计问题 3）。 */
export function buildSubmitPayload(
  draft: AuditDraft,
  agentDetection: boolean = draft.agentDetection === true,
): { path: string; body: RepositoryScanRequest | Record<string, unknown> } {
  const repository = draft.repository.trim();
  if (draft.mode === "diff") {
    const pr = Number(draft.pullRequest.trim());
    return {
      path: "/v1/reviews?async=true",
      body: {
        repository,
        diff: draft.diff,
        ...(Number.isInteger(pr) && pr > 0 ? { pull_request: pr } : {}),
      },
    };
  }
  if (draft.sourceMode === "github") {
    const ref = draft.githubRef.trim();
    return {
      path: "/v1/repository-scans",
      body: {
        source: {
          type: "github",
          url: repository,
          ...(ref !== "" ? { ref } : {}),
        },
        agent_detection: agentDetection,
      },
    };
  }
  return {
    path: "/v1/repository-scans",
    body: { repository_key: repository, agent_detection: agentDetection },
  };
}
