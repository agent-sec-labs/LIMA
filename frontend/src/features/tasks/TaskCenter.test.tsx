import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { App as AntApp, ConfigProvider } from "antd";
import { RouterProvider } from "react-router-dom";
import { createAppRouter, type AppRouterInstance } from "@/router";
import type { TaskDetail, TaskListItem } from "@/shared/api/types";
import { detailRefetchInterval, listRefetchInterval } from "./model";

/**
 * T7 行为规格：URL 即选中态、动态轮询到终态、结构化失败、警告可区分。
 * 轮询测试用可变 stub（首次 RUNNING、其后 SUCCESS）离线验证真实刷新。
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
const OLD = new Date(Date.now() - 120_000).toISOString();

function progress(overrides: Partial<TaskDetail["progress"]>): NonNullable<TaskDetail["progress"]> {
  return {
    stage: "AST_ANALYSIS",
    stage_index: 9,
    stage_total: 13,
    message: "正在逐文件执行 AST 与规则分析",
    started_at: NOW,
    stage_started_at: NOW,
    updated_at: NOW,
    attempt: 1,
    max_attempts: 3,
    current: 5,
    total: 40,
    unit: "files",
    detail: {},
    ...overrides,
  };
}

const RUNNING_TASK: TaskDetail = {
  id: "task-running",
  state: "EXECUTING",
  repository: "org/alpha",
  created_at: NOW,
  updated_at: NOW,
  input: {
    task_type: "repository_scan",
    scan_source: { type: "github", canonical_name: "org/alpha", requested_ref: "main" },
  },
  progress: progress({
    stage: "DATAFLOW_ANALYSIS",
    stage_index: 8,
    message: "正在建立跨文件数据流索引",
    attempt: 2,
    current: 12,
  }),
  failure: null,
  report: null,
};

const FAILED_TASK: TaskDetail = {
  id: "task-failed",
  state: "FAILED",
  repository: "org/beta",
  created_at: NOW,
  updated_at: NOW,
  input: { task_type: "repository_scan", repository_key: "team/beta" },
  progress: progress({
    stage: "RESOLVING_REVISION",
    stage_index: 2,
    message: "正在解析 GitHub 仓库版本",
    attempt: 3,
    current: null,
    total: null,
    unit: "",
  }),
  failure: {
    code: "GITHUB_RATE_LIMITED",
    category: "github",
    stage: "RESOLVING_REVISION",
    title: "GitHub 请求频率受限",
    message: "API 配额暂时耗尽。",
    retryable: true,
    suggestion: "系统会自动重试；持续出现请在服务端配置凭据以提高配额。",
    technical_detail: "HTTP 429 from api.github.com",
    detail: {},
  },
  report: null,
};

const CLEAN_TASK: TaskDetail = {
  id: "task-clean",
  state: "SUCCESS",
  repository: "org/clean",
  created_at: NOW,
  updated_at: NOW,
  input: { task_type: "repository_scan", repository_key: "team/clean" },
  progress: progress({
    stage: "COMPLETED",
    stage_index: 13,
    message: "任务完成",
    current: null,
    total: null,
    unit: "",
    detail: { completion: { status: "completed", warning_count: 0 } },
  }),
  report: {
    repository: "org/clean",
    risk: "high",
    reviewer: "repository-hybrid",
    summary: "发现 1 个候选安全问题。",
    files_reviewed: ["app.py"],
    findings: [
      {
        severity: "high",
        rule_id: "SEC-EVAL",
        cwe: "CWE-78",
        path: "app.py",
        line: 42,
        title: "用户输入进入 shell 命令",
        verification_state: "dataflow-verified",
        confidence: 0.97,
        evidence: "request.args['target'] 传入 subprocess.run(..., shell=True)。",
        explanation: "攻击者可以构造 shell 元字符执行额外命令。",
        fix: "移除 shell=True，改用参数化 argv。",
      },
    ],
    adjudication: { policy: "evidence-first" },
    collaboration: { import_policy: { repository_key: "team/clean" } },
  },
};

const WARN_TASK: TaskDetail = {
  ...CLEAN_TASK,
  id: "task-warn",
  repository: "org/warn",
  progress: progress({
    stage: "COMPLETED",
    stage_index: 13,
    message: "任务完成",
    current: null,
    total: null,
    unit: "",
    detail: {
      completion: {
        status: "completed_with_warnings",
        warning_count: 2,
        warnings: { SYMLINK_SKIPPED: 1, "non-utf8": 1 },
      },
    },
  }),
};

const TASK_LIST: { tasks: TaskListItem[] } = {
  tasks: [
    {
      id: "task-running",
      state: "EXECUTING",
      repository: "org/alpha",
      task_type: "repository_scan",
      created_at: NOW,
      updated_at: NOW,
      error: null,
      progress: {
        stage: "DATAFLOW_ANALYSIS",
        stage_index: 8,
        stage_total: 13,
        message: "正在建立跨文件数据流索引",
        attempt: 2,
        max_attempts: 3,
        current: 12,
        total: 40,
        unit: "files",
      },
    },
    {
      id: "task-clean",
      state: "SUCCESS",
      repository: "org/clean",
      task_type: "repository_scan",
      created_at: NOW,
      updated_at: NOW,
      error: null,
      progress: null,
    },
  ],
};

function taskRoute(task: TaskDetail): FetchRoute {
  return { url: `/v1/tasks/${task.id}`, body: task };
}

beforeEach(() => {
  vi.unstubAllGlobals();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("polling policy (model)", () => {
  it("stops on terminal states and slows with task age", () => {
    expect(detailRefetchInterval({ ...RUNNING_TASK, state: "SUCCESS" })).toBe(false);
    expect(detailRefetchInterval({ ...RUNNING_TASK, state: "FAILED" })).toBe(false);
    expect(detailRefetchInterval(null)).toBe(false);
    expect(detailRefetchInterval(RUNNING_TASK)).toBe(2000);
    expect(detailRefetchInterval({ ...RUNNING_TASK, created_at: OLD })).toBe(4000);
  });

  it("polls the list only while tasks are active", () => {
    expect(listRefetchInterval(undefined)).toBe(false);
    expect(listRefetchInterval([])).toBe(false);
    expect(listRefetchInterval(TASK_LIST.tasks)).toBe(4000);
    expect(listRefetchInterval(TASK_LIST.tasks.map((item) => ({ ...item, state: "SUCCESS" as const })))).toBe(false);
  });
});

describe("task list", () => {
  it("shows repositories with lifecycle state and current stage", async () => {
    stubFetch([{ url: "/api/tasks", body: TASK_LIST }]);
    renderAt("/tasks");
    expect(await screen.findByText("org/alpha")).toBeInTheDocument();
    expect(screen.getByText("数据流分析（8/13）")).toBeInTheDocument();
    expect(screen.getByText("分析中")).toBeInTheDocument();
    expect(screen.getAllByText("已完成").length).toBeGreaterThanOrEqual(2);
  });

  it("navigates to the task detail by URL on click", async () => {
    stubFetch([
      { url: "/api/tasks", body: TASK_LIST },
      taskRoute(RUNNING_TASK),
    ]);
    renderAt("/tasks");
    fireEvent.click(await screen.findByText("org/alpha"));
    expect(await screen.findByText("执行进度")).toBeInTheDocument();
    expect(screen.getByText("数据流分析")).toBeInTheDocument();
    expect(screen.getByText(/12\/40 files/)).toBeInTheDocument();
    expect(screen.getByText("队列重试：第 2 次 / 上限 3")).toBeInTheDocument();
  });
});

describe("task detail", () => {
  it("restores the selected task from a direct URL and renders structured failure", async () => {
    stubFetch([taskRoute(FAILED_TASK)]);
    renderAt("/tasks/task-failed");
    expect(await screen.findByText("org/beta")).toBeInTheDocument();
    expect(screen.getByText("GitHub 请求频率受限")).toBeInTheDocument();
    expect(screen.getByText("阶段：解析版本")).toBeInTheDocument();
    expect(screen.getByText("可自动重试")).toBeInTheDocument();
    expect(screen.getByText(/系统会自动重试/)).toBeInTheDocument();
    // 技术细节默认折叠：原始异常不是主 UI
    expect(screen.queryByText(/HTTP 429/)).not.toBeInTheDocument();
  });

  it("updates a running task through polling without manual refresh", async () => {
    let calls = 0;
    stubFetch([
      {
        url: "/v1/tasks/task-poll",
        body: () => {
          calls += 1;
          if (calls <= 1) {
            return { ...RUNNING_TASK, id: "task-poll", repository: "org/poll" };
          }
          return { ...CLEAN_TASK, id: "task-poll", repository: "org/poll" };
        },
      },
    ]);
    renderAt("/tasks/task-poll");
    expect(await screen.findByText("执行进度")).toBeInTheDocument();
    // 不做任何交互，等待轮询把任务推进到终态并渲染完成横幅与报告
    expect(await screen.findByText("审计完成", undefined, { timeout: 6000 })).toBeInTheDocument();
    expect(screen.getByText("用户输入进入 shell 命令")).toBeInTheDocument();
    expect(calls).toBeGreaterThanOrEqual(2);
  });

  it("distinguishes completed-with-warnings from a clean completion", async () => {
    stubFetch([taskRoute(WARN_TASK), taskRoute(CLEAN_TASK)]);
    renderAt("/tasks/task-warn");
    expect(await screen.findByText(/完成但有警告/)).toBeInTheDocument();
    expect(screen.getByText("SYMLINK_SKIPPED（1 个）")).toBeInTheDocument();
    expect(screen.getByText("non-utf8（1 个）")).toBeInTheDocument();

    const router = createAppRouter("memory", "/tasks/task-clean");
    render(
      <ConfigProvider>
        <AntApp>
          <QueryClientProvider client={new QueryClient()}>
            <RouterProvider router={router} />
          </QueryClientProvider>
        </AntApp>
      </ConfigProvider>,
    );
    expect(await screen.findByText("审计完成")).toBeInTheDocument();
    expect(screen.getByText("本次执行没有影响覆盖范围的跳过。")).toBeInTheDocument();
  });

  it("switching task URLs abandons the previous task view", async () => {
    stubFetch([taskRoute(RUNNING_TASK), taskRoute(FAILED_TASK)]);
    const router = renderAt("/tasks/task-running");
    expect(await screen.findByText("org/alpha")).toBeInTheDocument();

    await router.navigate("/tasks/task-failed");
    expect(await screen.findByText("org/beta")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.queryByText("正在建立跨文件数据流索引")).not.toBeInTheDocument();
    });
  });
});
