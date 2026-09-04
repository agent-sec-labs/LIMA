import type { FieldErrors, Resolver } from "react-hook-form";
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

export interface AuditDraft {
  mode: AuditMode;
  sourceMode: SourceMode;
  repository: string;
  githubRef: string;
  diff: string;
  pullRequest: string;
}

export const EMPTY_DRAFT: AuditDraft = {
  mode: "repository",
  sourceMode: "local",
  repository: "",
  githubRef: "",
  diff: "",
  pullRequest: "",
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
}

/** 载荷与 legacy 行为一致：目标原样透传（服务端归一化），浏览器零 api.github.com。 */
export function buildSubmitPayload(
  draft: AuditDraft,
): { path: string; body: Record<string, unknown> } {
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
      },
    };
  }
  return {
    path: "/v1/repository-scans",
    body: { repository_key: repository },
  };
}
