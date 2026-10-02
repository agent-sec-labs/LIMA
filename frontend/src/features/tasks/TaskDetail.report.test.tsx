import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { App as AntApp, ConfigProvider } from "antd";
import { RouterProvider } from "react-router-dom";
import { createAppRouter, type AppRouterInstance } from "@/router";
import type { TaskDetail } from "@/shared/api/types";
import {
  confidenceLabel,
  reportAdjudication,
  reportRisk,
  stageLabel,
  verificationLabel,
} from "./model";

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

/** UAF v2 审计摘要载荷（report.collaboration.uaf_v2，设计 §14）。 */
const UAF_V2_PAYLOAD = {
  mode: "auto",
  status: "completed",
  translation_units: ["src/a.cpp"],
  stats: {
    tu_count: 1,
    candidate_count: 1,
    pass: 1,
    refuted: 0,
    unknown: 0,
    llm_invoked: 0,
    llm_calls: 0,
  },
  states: { "fact-verified": 1 },
  broker: { support: 1, contradict: 0, "no-evidence": 0 },
  diagnostics: [],
};

/** 带 UAF finding 的报告：徽标走前端精确匹配 map。 */
const UAF_REPORT: TaskDetail["report"] = {
  repository: "org/report",
  reviewer: "repository-hybrid",
  summary: "一个 UAF 候选。",
  files_reviewed: ["src/a.cpp"],
  findings: [
    {
      severity: "high",
      rule_id: "cxx.uaf-v2.cwe-416",
      cwe: "CWE-416",
      path: "src/a.cpp",
      line: 30,
      title: "Use-after-free: pointer dereferenced after release",
      verification_state: "fact-verified",
      confidence: 0.97,
      source: "cxx-uaf-v2",
    },
  ],
  collaboration: { uaf_v2: UAF_V2_PAYLOAD },
};

/** 混合报告（§4.7）：一个可预览的 Python finding + 一个 C++ finding
 *（automatic_repair=false，永不进入修复预览）。 */
const MIXED_REPORT: TaskDetail["report"] = {
  repository: "org/report",
  reviewer: "repository-hybrid",
  summary: "混合发现。",
  files_reviewed: ["app.py", "src/a.cpp"],
  findings: [
    {
      severity: "high",
      rule_id: "SEC-SQLI",
      cwe: "CWE-89",
      path: "app.py",
      line: 12,
      title: "SQL 拼接进入执行",
      verification_state: "dataflow-verified",
      confidence: 0.9,
    },
    {
      severity: "high",
      rule_id: "cxx.platform.cwe-416",
      cwe: "CWE-416",
      path: "src/a.cpp",
      line: 30,
      title: "Use-after-free suspected by agent analysis",
      verification_state: "runtime-confirmed",
      confidence: 0.95,
      automatic_repair: false,
    },
  ],
};

/** 只有 C++ finding 的报告：修复预览入口必须隐藏（§4.7 回归）。 */
const CXX_ONLY_REPORT: TaskDetail["report"] = {
  repository: "org/report",
  reviewer: "repository-hybrid",
  summary: "只有 C++ 候选。",
  files_reviewed: ["src/a.cpp"],
  findings: [MIXED_REPORT!.findings![1]],
};

/** 平台链载荷（方案 §3.4 扩展后的形态：可选详情 + 省略原因）。 */
const PLATFORM_PAYLOAD = {
  mode: "auto",
  status: "completed",
  translation_units: ["src/a.cpp"],
  stats: {
    leads: 5,
    targets: 2,
    findings: 1,
    experiments: 3,
    scout_calls: 2,
    specialist_calls: 4,
    critic_calls: 1,
  },
  states: { "runtime-confirmed": 1, rejected: 1 },
  broker: { support: 1, contradict: 0 },
  diagnostics: [],
  targets: [
    {
      target_id: "target-1",
      path: "src/a.cpp",
      line: 42,
      state: "runtime-confirmed",
      cwe: "CWE-416",
      proof: "PASS",
      experiments: 1,
      rejected_reason: "",
      hypothesis_reason: "释放后再次使用对象",
      poc_driver_code: "int main() { int *p = new int(1); delete p; return *p; }",
      experiment_log: [
        {
          round: 1,
          stage: "run",
          exit_code: 1,
          error_type: "heap-use-after-free",
          faulting_line: 42,
          hit: true,
        },
      ],
      detail_omissions: [],
    },
    {
      target_id: "target-2",
      path: "src/b.cpp",
      line: 7,
      state: "rejected",
      cwe: "CWE-416",
      proof: "REFUTED",
      experiments: 2,
      rejected_reason: "实验未命中",
      detail_omissions: [
        "poc_driver_code:too-large",
        "experiment_log:older-rounds-omitted",
      ],
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

  it("labels UAF v2 arbiter states with exact-match badges", () => {
    expect(verificationLabel("fact-verified")).toBe("事实已验证");
    expect(verificationLabel("semantic-supported")).toBe("语义支持 · 需复核");
    // 子串匹配与 fail-closed fallback 保持 legacy 语义。
    expect(verificationLabel("dataflow-verified")).toBe("数据流已验证");
    expect(verificationLabel("corroborated")).toBe("候选 · 需复核");
    expect(verificationLabel(undefined)).toBe("候选 · 需复核");
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
      { url: "/v1/tasks/task-report", body: successTask({ report: MIXED_REPORT }) },
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

  it("renders the UAF v2 audit details for zero-call deterministic proofs", async () => {
    stubFetch([
      { url: "/v1/tasks/task-uaf", body: successTask({ id: "task-uaf", report: UAF_REPORT }) },
      { url: "/v1/tasks/task-uaf/feedback", body: { cases: [] } },
    ]);
    renderAt("/tasks/task-uaf");
    // fact-verified 徽标走前端精确匹配 map（证据状态列）。
    expect(await screen.findByText("事实已验证")).toBeVisible();
    const summary = screen.getByText("C/C++ UAF v2（确定性证明）");
    expect(summary).toBeVisible();
    const details = summary.closest("details");
    expect(details).not.toBeNull();
    // 状态行 / stats 行 / broker 三态行。
    expect(details!.textContent).toContain("模式 auto");
    expect(details!.textContent).toContain("候选 1");
    expect(details!.textContent).toContain("PASS 1");
    expect(details!.textContent).toContain("REFUTED 0");
    expect(details!.textContent).toContain("UNKNOWN 0");
    expect(details!.textContent).toContain("证据仲裁：支持 1");
    expect(details!.textContent).toContain("反驳 0");
    expect(details!.textContent).toContain("无证据 0");
    // 零调用红线：PASS 全覆盖必须显示确定性证明注记，不得显示已调用。
    // toBeVisible is unreliable here: jsdom cannot fully resolve antd's
    // dev-only :where() styles, and getComputedStyle reports the element
    // hidden. Presence in the document carries the intended meaning.
    expect(screen.getByText("确定性证明 · 未调用 LLM")).toBeInTheDocument();
    expect(details!.textContent).not.toContain("LLM 调用：");
    // 审计区不含任何修复入口（任务级修复按钮不变）。
    expect(within(details as HTMLElement).queryAllByRole("button")).toEqual([]);
    expect(screen.queryByRole("button", { name: "创建修复分支" })).toBeNull();
  });

  it("shows the actual LLM call count when the semantic branch ran", async () => {
    stubFetch([
      {
        url: "/v1/tasks/task-uaf-llm",
        body: successTask({
          id: "task-uaf-llm",
          report: {
            ...UAF_REPORT,
            collaboration: {
              uaf_v2: {
                ...UAF_V2_PAYLOAD,
                stats: {
                  ...UAF_V2_PAYLOAD.stats,
                  pass: 0,
                  unknown: 1,
                  llm_invoked: 1,
                  llm_calls: 4,
                },
              },
            },
          },
        }),
      },
      { url: "/v1/tasks/task-uaf-llm/feedback", body: { cases: [] } },
    ]);
    renderAt("/tasks/task-uaf-llm");
    const details = (await screen.findByText("C/C++ UAF v2（确定性证明）")).closest("details");
    expect(details!.textContent).toContain("LLM 调用：4");
    expect(screen.queryByText("确定性证明 · 未调用 LLM")).toBeNull();
  });

  it("renders legacy reports without the uaf_v2 key unchanged", async () => {
    stubFetch([
      {
        url: "/v1/tasks/task-legacy",
        body: successTask({
          id: "task-legacy",
          report: { ...DERIVED_REPORT, collaboration: { scanned_files: 2 } },
        }),
      },
      { url: "/v1/tasks/task-legacy/feedback", body: { cases: [] } },
    ]);
    renderAt("/tasks/task-legacy");
    expect(await screen.findByText("证据处置：确认告警")).toBeVisible();
    expect(screen.queryByText(/C\/C\+\+ UAF v2/)).toBeNull();
  });

  it("hides the repair preview button when no previewable Python finding exists", async () => {
    stubFetch([
      {
        url: "/v1/tasks/task-cxx",
        body: successTask({ id: "task-cxx", report: CXX_ONLY_REPORT }),
      },
      { url: "/v1/tasks/task-cxx/feedback", body: { cases: [] } },
    ]);
    renderAt("/tasks/task-cxx");
    // runtime-confirmed 未命中前端已验证子串规则 → fail-closed 需要复核横幅。
    expect(await screen.findByText("证据处置：需要复核")).toBeVisible();
    // 只有 automatic_repair=false 的 C++ finding：不显示修复预览入口。
    expect(screen.queryByRole("button", { name: "生成修复预览" })).toBeNull();
  });

  it("shows the platform audit card with stats and per-target drill-down details", async () => {
    const report: TaskDetail["report"] = {
      ...MIXED_REPORT,
      collaboration: { platform: PLATFORM_PAYLOAD },
    };
    stubFetch([
      { url: "/v1/tasks/task-platform", body: successTask({ id: "task-platform", report }) },
      { url: "/v1/tasks/task-platform/feedback", body: { cases: [] } },
    ]);
    renderAt("/tasks/task-platform");
    const title = await screen.findByText("C++ 智能体检测（平台链）");
    expect(title).toBeVisible();
    const card = title.closest(".ant-card") as HTMLElement;

    // 基本统计与状态标签（§4.3）。
    expect(within(card).getByText("检测完成")).toBeVisible();
    expect(within(card).getByText("运行时确认 × 1")).toBeVisible();
    expect(within(card).getByText("已否决 × 1")).toBeVisible();
    const stats = within(card).getByLabelText("平台链统计");
    expect(stats.textContent).toContain("线索 5");
    expect(stats.textContent).toContain("目标 2");
    expect(stats.textContent).toContain("模型调用 7");

    // 目标摘要行（前 32 个）：target_id、位置、状态、证明结论。
    expect(within(card).getByText("target-1")).toBeVisible();
    expect(within(card).getByText("src/a.cpp:42")).toBeVisible();
    expect(within(card).getByText("运行时确认")).toBeVisible();

    // 下钻（§4.4）：假设 / PoC 展示副本 / 实验日志 / 证明结论。
    const expandButtons = card.querySelectorAll(".ant-table-row-expand-icon");
    expect(expandButtons.length).toBeGreaterThanOrEqual(2);
    fireEvent.click(expandButtons[0]);
    expect(await within(card).findByText("释放后再次使用对象")).toBeVisible();
    const poc = within(card).getByLabelText("poc-driver-code");
    expect(poc.textContent).toContain("delete p");
    expect(await within(card).findByText("heap-use-after-free")).toBeVisible();

    // 省略原因如实展示，不把缺失误读成“无实验”。
    fireEvent.click(expandButtons[1]);
    expect(await within(card).findByText(/PoC driver 超出单条预算/)).toBeVisible();
    expect(within(card).getByText(/较早轮次已省略/)).toBeVisible();
    expect(within(card).getByText(/实验未命中/)).toBeVisible();
  });

  it("does not render the platform card for disabled runs or legacy reports", async () => {
    const disabledReport: TaskDetail["report"] = {
      ...MIXED_REPORT,
      collaboration: { platform: { mode: "off", status: "disabled" } },
    };
    stubFetch([
      {
        url: "/v1/tasks/task-off",
        body: successTask({ id: "task-off", report: disabledReport }),
      },
      { url: "/v1/tasks/task-off/feedback", body: { cases: [] } },
      {
        url: "/v1/tasks/task-old",
        body: successTask({
          id: "task-old",
          report: { ...MIXED_REPORT, collaboration: { scanned_files: 2 } },
        }),
      },
      { url: "/v1/tasks/task-old/feedback", body: { cases: [] } },
    ]);
    renderAt("/tasks/task-off");
    await screen.findByText("证据处置：确认告警");
    expect(screen.queryByText("C++ 智能体检测（平台链）")).toBeNull();

    renderAt("/tasks/task-old");
    await screen.findAllByText("证据处置：确认告警");
    expect(screen.queryByText("C++ 智能体检测（平台链）")).toBeNull();
  });

  it("shows the real platform status instead of a fake zero-finding conclusion", async () => {
    const report: TaskDetail["report"] = {
      ...MIXED_REPORT,
      collaboration: { platform: { mode: "auto", status: "no-cxx-sources" } },
    };
    stubFetch([
      { url: "/v1/tasks/task-nocxx", body: successTask({ id: "task-nocxx", report }) },
      { url: "/v1/tasks/task-nocxx/feedback", body: { cases: [] } },
    ]);
    renderAt("/tasks/task-nocxx");
    const title = await screen.findByText("C++ 智能体检测（平台链）");
    const card = title.closest(".ant-card") as HTMLElement;
    expect(within(card).getByText("仓库没有 C++ 来源")).toBeVisible();
    expect(
      within(card).getByText(/这是运行状态，不代表仓库没有 C\+\+ 风险/),
    ).toBeVisible();
  });

  it("labels PLATFORM_ANALYSIS in the running stage timeline", async () => {
    expect(stageLabel("PLATFORM_ANALYSIS")).toBe("C++ 智能体检测");
    const now = new Date().toISOString();
    const running: TaskDetail = {
      id: "task-run",
      state: "EXECUTING",
      repository: "org/run",
      created_at: now,
      updated_at: now,
      input: { task_type: "repository_scan", repository_key: "team/run" },
      progress: {
        stage: "PLATFORM_ANALYSIS",
        stage_index: 11,
        stage_total: 14,
        message: "正在进行 C++ 智能体检测",
        started_at: now,
        stage_started_at: now,
        updated_at: now,
        attempt: 1,
        max_attempts: 3,
        current: null,
        total: null,
        unit: "",
        detail: {},
      },
      failure: null,
      report: null,
      error: null,
    };
    stubFetch([
      { url: "/v1/tasks/task-run", body: running },
    ]);
    renderAt("/tasks/task-run");
    expect(await screen.findByText("C++ 智能体检测")).toBeVisible();
    expect(screen.getByText("正在进行 C++ 智能体检测")).toBeVisible();
  });

  it("locates the running stage by name when old task indexes shift after the new stage", async () => {
    // 审计问题 4 复现：旧任务的编号（SEMANTIC_TRIAGE=10/13）比前端列表
    // （插入 PLATFORM_ANALYSIS 后 14 阶段）少一格；按名称定位才不会把
    // 语义复核错标成"C++ 智能体检测"、把完成错标成"生成报告"。
    const now = new Date().toISOString();
    const running: TaskDetail = {
      id: "task-old-run",
      state: "EXECUTING",
      repository: "org/old",
      created_at: now,
      updated_at: now,
      input: { task_type: "repository_scan", repository_key: "team/old" },
      progress: {
        stage: "SEMANTIC_TRIAGE",
        stage_index: 10,
        stage_total: 13,
        message: "正在语义复核候选发现",
        started_at: now,
        stage_started_at: now,
        updated_at: now,
        attempt: 1,
        max_attempts: 3,
        current: null,
        total: null,
        unit: "",
        detail: {},
      },
      failure: null,
      report: null,
      error: null,
    };
    stubFetch([
      { url: "/v1/tasks/task-old-run", body: running },
    ]);
    renderAt("/tasks/task-old-run");
    await screen.findByText("正在语义复核候选发现");
    const processStep = document.querySelector(".ant-steps-item-process");
    expect(processStep).not.toBeNull();
    expect(processStep!.textContent).toContain("语义复核");
    expect(processStep!.textContent).not.toContain("C++ 智能体检测");
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
