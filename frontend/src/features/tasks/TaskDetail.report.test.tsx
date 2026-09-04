import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { App as AntApp, ConfigProvider } from "antd";
import { RouterProvider } from "react-router-dom";
import { createAppRouter, type AppRouterInstance } from "@/router";
import type { TaskDetail } from "@/shared/api/types";
import { confidenceLabel, reportAdjudication, reportRisk, verificationLabel } from "./model";

/**
 * T10 对等规格（issue #43）：证据处置推导（fail-closed）、修复预览 / 修复分支、
 * 误报反馈（含历史）。文案与处置语义与已删除的 web/app.js 逐字对齐。
 */

interface FetchRoute {
  url: string;
  method?: string;
  body: unknown | (() => unknown);
}

function stubFetch(routes: FetchRoute[]): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      const route = routes.find(
        (item) => item.url === url && (item.method ?? "GET") === method,
      );
      if (!route) {
        return new Response(JSON.stringify({ error: `unstubbed ${method} ${url}` }), {
          status: 500,
          headers: { "content-type": "application/json" },
        });
      }
      const body = typeof route.body === "function" ? (route.body as () => unknown)() : route.body;
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }),
  );
}

function renderAt(path: string): AppRouterInstance {
  const router = createAppRouter("memory", path);
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <ConfigProvider>
      <AntApp>
        <QueryClientProvider client={client}>
          <RouterProvider router={router} />
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  );
  return router;
}

const NOW = new Date().toISOString();

function successTask(overrides: Partial<TaskDetail> = {}): TaskDetail {
  return {
    id: "task-report",
    state: "SUCCESS",
    repository: "org/report",
    created_at: NOW,
    updated_at: NOW,
    input: { task_type: "repository_scan", repository_key: "team/report" },
    progress: {
      stage: "COMPLETED",
      stage_index: 13,
      stage_total: 13,
      message: "任务完成",
      started_at: NOW,
      stage_started_at: NOW,
      updated_at: NOW,
      attempt: 1,
      max_attempts: 3,
      current: null,
      total: null,
      unit: "",
      detail: { completion: { status: "completed", warning_count: 0 } },
    },
    failure: null,
    report: null,
    ...overrides,
  };
}

/** 无 adjudication 键的报告：处置必须按 verification_state fail-closed 推导。 */
const DERIVED_REPORT: TaskDetail["report"] = {
  repository: "org/report",
  reviewer: "repository-hybrid",
  summary: "两个候选问题。",
  files_reviewed: ["app.py", "executor.py"],
  findings: [
    {
      severity: "critical",
      rule_id: "SEC-EVAL",
      cwe: "CWE-95",
      path: "executor.py",
      line: 3,
      title: "用户输入直接进入 eval",
      verification_state: "dataflow-verified",
      confidence: 0.98,
    },
    {
      severity: "medium",
      rule_id: "SEC-ASSERT",
      cwe: "CWE-703",
      path: "app.py",
      line: 9,
      title: "使用 assert 做权限判断",
      verification_state: "candidate",
      confidence: 0.41,
    },
  ],
};

describe("report domain derivation (model)", () => {
  it("derives fail-closed dispositions when adjudication is absent", () => {
    const findings = DERIVED_REPORT!.findings!;
    const { adjudication: _absent, ...withoutAdjudication } = DERIVED_REPORT!;
    const adjudication = reportAdjudication(withoutAdjudication, findings);
    expect(adjudication.overall_disposition).toBe("alert");
    expect(adjudication.counts).toEqual({ alert: 1, needs_review: 1, clear: 0 });
    expect(adjudication.policy).toBe("legacy-fail-closed");
    expect(adjudication.decisions[0].reason).toBe("confirmed-risk-evidence");
    expect(adjudication.decisions[1].reason).toBe("unverified-finding-requires-human-review");
  });

  it("keeps explicit adjudication counts and overall disposition", () => {
    const adjudication = reportAdjudication(
      {
        adjudication: {
          policy: "evidence-first",
          overall_disposition: "clear",
          counts: { alert: 0, needs_review: 0, clear: 2 },
          decisions: [],
        },
      },
      [],
    );
    expect(adjudication.overall_disposition).toBe("clear");
    expect(adjudication.auto_clear).toBe(false);
    expect(adjudication.counts.clear).toBe(2);
  });

  it("derives risk including clean, and labels confidence and verification", () => {
    expect(reportRisk({}, [])).toBe("clean");
    expect(reportRisk({}, [{ severity: "high" }])).toBe("high");
    expect(reportRisk({ risk: "LOW" }, [{ severity: "critical" }])).toBe("low");
    expect(confidenceLabel(0.42)).toBe("42%");
    expect(confidenceLabel(42)).toBe("42%");
    expect(confidenceLabel(undefined)).toBe("未提供");
    expect(verificationLabel("dataflow-verified")).toBe("数据流已验证");
    expect(verificationLabel("syntax-verified")).toBe("语法约束已验证");
    expect(verificationLabel("corroborated")).toBe("候选 · 需复核");
    expect(verificationLabel(undefined)).toBe("候选 · 需复核");
  });
});

describe("task detail report surface", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("shows the derived disposition banner and per-finding dispositions", async () => {
    stubFetch([
      { url: "/v1/tasks/task-report", body: successTask({ report: DERIVED_REPORT }) },
      { url: "/v1/tasks/task-report/feedback", body: { cases: [] } },
    ]);
    renderAt("/tasks/task-report");
    expect(await screen.findByText("证据处置：确认告警")).toBeVisible();
    expect(screen.getByText("至少一项风险已有足够证据，请进入修复与安全回归流程。")).toBeVisible();
    expect(screen.getByText("当前只有候选证据，需要人工结合业务上下文判断")).toBeVisible();
    expect(screen.getByText("候选 · 需复核")).toBeVisible();
    expect(screen.getByText("数据流已验证")).toBeVisible();
    expect(screen.getByText("98%")).toBeVisible();
    expect(screen.getByText("41%")).toBeVisible();
  });

  it("runs a repair preview and renders the operation result panel", async () => {
    const calls: string[] = [];
    stubFetch([
      { url: "/v1/tasks/task-report", body: successTask({ report: DERIVED_REPORT }) },
      { url: "/v1/tasks/task-report/feedback", body: { cases: [] } },
      {
        url: "/v1/tasks/task-report/repair-preview",
        method: "POST",
        body: () => {
          calls.push("repair-preview");
          return {
            status: "verified-preview",
            files_changed: 2,
            changed_lines: 6,
            note: "预览通过全部安全门禁",
          };
        },
      },
    ]);
    renderAt("/tasks/task-report");
    fireEvent.click(await screen.findByRole("button", { name: "生成修复预览" }));
    expect(await screen.findByText("自动修复预览")).toBeVisible();
    expect(screen.getByText("预览通过全部安全门禁")).toBeVisible();
    expect(screen.getByText("verified-preview")).toBeVisible();
    await waitFor(() => expect(calls).toEqual(["repair-preview"]));
  });

  it("gates the fix branch button to PR tasks and requires confirmation", async () => {
    const calls: string[] = [];
    stubFetch([
      {
        url: "/v1/tasks/task-pr",
        body: successTask({
          id: "task-pr",
          pull_request: 7,
          report: DERIVED_REPORT,
        }),
      },
      { url: "/v1/tasks/task-pr/feedback", body: { cases: [] } },
      {
        url: "/v1/tasks/task-pr/fix",
        method: "POST",
        body: () => {
          calls.push("fix");
          return { branch: "lima/fix-7", source_sha: "a".repeat(40), commits: [], note: "ok" };
        },
      },
    ]);
    renderAt("/tasks/task-pr");
    fireEvent.click(await screen.findByRole("button", { name: "创建修复分支" }));
    // 破坏性操作必须先过确认弹窗，未确认前不得发请求。
    expect(calls).toEqual([]);
    expect((await screen.findAllByText("确认创建修复分支？")).length).toBeGreaterThan(0);
    // 触发按钮与弹窗确定按钮同名：点击后出现的那个（弹窗内确定项）。
    const modalOk = await waitFor(
      () => {
        const buttons = screen.getAllByRole("button", { name: "创建修复分支" });
        expect(buttons.length).toBeGreaterThanOrEqual(2);
        return buttons[buttons.length - 1];
      },
      { timeout: 5000 },
    );
    fireEvent.click(modalOk);
    await waitFor(() => expect(calls).toEqual(["fix"]), { timeout: 5000 });
    expect(await screen.findByText("修复分支结果")).toBeVisible();
    expect(screen.getByText("lima/fix-7")).toBeVisible();
  });

  it("submits feedback and renders the recorded case history", async () => {
    const posts: unknown[] = [];
    // 反馈历史按调用序返回不同载荷：首次空，提交后含一条已记录案例。
    let feedbackLoaded = false;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? "GET";
        if (url === "/v1/tasks/task-report") {
          return new Response(JSON.stringify(successTask({ report: DERIVED_REPORT })), {
            headers: { "content-type": "application/json" },
          });
        }
        if (url === "/v1/tasks/task-report/feedback" && method === "POST") {
          posts.push(JSON.parse(String(init?.body ?? "{}")));
          return new Response(JSON.stringify({ recorded: true, category: "false_positive" }), {
            headers: { "content-type": "application/json" },
          });
        }
        if (url === "/v1/tasks/task-report/feedback") {
          const cases = feedbackLoaded
            ? [
                {
                  id: 1,
                  category: "false_positive",
                  payload: { finding: DERIVED_REPORT!.findings![1], note: "业务上白名单" },
                  resolved: 0,
                },
              ]
            : [];
          feedbackLoaded = true;
          return new Response(JSON.stringify({ cases }), {
            headers: { "content-type": "application/json" },
          });
        }
        return new Response(JSON.stringify({ error: "unstubbed" }), { status: 500 });
      }),
    );
    renderAt("/tasks/task-report");
    const note = await screen.findByPlaceholderText("说明判断依据或预期行为");
    fireEvent.change(note, { target: { value: "业务上白名单" } });
    fireEvent.click(await screen.findByRole("button", { name: "提交反馈" }));
    await waitFor(() => expect(posts.length).toBeGreaterThan(0));
    const payload = posts.at(-1) as { category: string; finding: unknown; note: string };
    expect(payload.category).toBe("false_positive");
    expect(payload.finding).toBeNull();
    expect(payload.note).toBe("业务上白名单");
    expect(await screen.findByText("误报已记录，将进入后续回放评测。")).toBeVisible();
    expect(await screen.findByText("待评测")).toBeVisible();
    expect(screen.getByText("SEC-ASSERT · app.py:9")).toBeVisible();
  });

  it("renders semantic triage status and semantic evidence rows", async () => {
    const report: TaskDetail["report"] = {
      ...DERIVED_REPORT,
      adjudication: {
        policy: "evidence-first",
        decisions: [
          {
            decision_source: "semantic-llm",
            symbol: "evaluate_expression",
            path: "executor.py",
            start_line: 2,
            disposition: "alert",
            reason: "risk-invariant-and-llm-agree",
            llm_root_cause: "用户输入未过滤直达 eval。",
          },
        ],
      },
      collaboration: {
        semantic_triage: {
          status: "completed",
          mode: "auto",
          provider: "deepseek",
          model: "security-triage",
          retrieval: { evidence_candidates: 3 },
          usage: { total_tokens: 1200 },
          latency_ms: 800,
        },
      },
    };
    stubFetch([
      { url: "/v1/tasks/task-report", body: successTask({ report }) },
      { url: "/v1/tasks/task-report/feedback", body: { cases: [] } },
    ]);
    renderAt("/tasks/task-report");
    expect(await screen.findByText("模型复核完成")).toBeVisible();
    expect(screen.getByText("AUTO")).toBeVisible();
    expect(screen.getByText("语义证据处置")).toBeVisible();
    expect(screen.getByText("evaluate_expression")).toBeVisible();
    expect(screen.getByText("风险不变量与模型结论一致")).toBeVisible();
    expect(screen.getByText(/模型证据：用户输入未过滤直达 eval。/)).toBeVisible();
  });

  it("shows the clean risk label when nothing crosses the threshold", async () => {
    stubFetch([
      {
        url: "/v1/tasks/task-clean",
        body: successTask({
          id: "task-clean",
          report: { repository: "org/clean", findings: [], files_reviewed: 3, summary: "" },
        }),
      },
      { url: "/v1/tasks/task-clean/feedback", body: { cases: [] } },
    ]);
    renderAt("/tasks/task-clean");
    expect(await screen.findByText("未发现风险")).toBeVisible();
    expect(
      screen.getByText(/本次审计没有发现满足当前规则和证据阈值的安全问题/),
    ).toBeVisible();
  });
});
