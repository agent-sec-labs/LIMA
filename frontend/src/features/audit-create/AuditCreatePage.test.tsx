import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { App as AntApp, ConfigProvider } from "antd";
import { RouterProvider } from "react-router-dom";
import { createAppRouter, type AppRouterInstance } from "@/router";
import { buildSubmitPayload, clearDraft, saveDraft, type AuditDraft } from "./model";

/**
 * T6 行为规格：三态边界 + 导航恢复 + 草稿保持 + 202 移交任务中心。
 * 全部通过 memory 路由与 fetch stub 离线运行。
 * 智能体检测（#245）：开关三态初始化、capabilities 门禁、提交确认与具名 400。
 */

interface FetchRoute {
  url: string;
  method?: string;
  status?: number;
  body: unknown;
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
      return new Response(JSON.stringify(route.body), {
        status: route.status ?? 200,
        headers: { "content-type": "application/json" },
      });
    }),
  );
}

/** #243 新字段齐备的 cxx_agent 能力节点（默认 mode=off，可从 off 开启）。 */
function cxxAgentCaps(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    mode: "off",
    repository_scan: false,
    pull_request_scan: false,
    per_request_switch: true,
    llm_configured: true,
    analyzer_configured: true,
    max_agent_calls: 40,
    configured: false,
    automatic_repair: false,
    ...overrides,
  };
}

const CAPABILITIES = {
  url: "/api/repository-scans/capabilities",
  body: {
    enabled: true,
    scan_sources: { configured: "both", local_import: true, github: true },
    cxx_agent: cxxAgentCaps(),
  },
};

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

async function fillTarget(value: string): Promise<void> {
  fireEvent.change(await screen.findByLabelText("仓库目标"), {
    target: { value },
  });
}

function clickNext(): void {
  fireEvent.click(screen.getByRole("button", { name: /下一步/ }));
}

beforeEach(() => {
  clearDraft();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** 带请求记录的 fetch stub：断言提交体与调用次数。 */
function stubTrackedFetch(routes: FetchRoute[]): {
  requests: { url: string; method: string; body: unknown }[];
} {
  const requests: { url: string; method: string; body: unknown }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      requests.push({
        url,
        method,
        body: init?.body !== undefined ? JSON.parse(String(init.body)) : undefined,
      });
      const route = routes.find(
        (item) => item.url === url && (item.method ?? "GET") === method,
      );
      if (!route) {
        return new Response(JSON.stringify({ error: `unstubbed ${method} ${url}` }), {
          status: 500,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify(route.body), {
        status: route.status ?? 200,
        headers: { "content-type": "application/json" },
      });
    }),
  );
  return { requests };
}

function pendingTask(id: string): unknown {
  const now = new Date().toISOString();
  return {
    id,
    state: "PENDING",
    repository: "team/project",
    created_at: now,
    updated_at: now,
    input: {},
    progress: null,
    failure: null,
    error: null,
  };
}

async function agentSwitch(): Promise<HTMLElement> {
  return await screen.findByRole("switch", { name: "智能体检测" });
}

describe("buildSubmitPayload agent_detection placement (§4.1)", () => {
  const base: AuditDraft = {
    mode: "repository",
    sourceMode: "local",
    repository: "team/project ",
    githubRef: "",
    diff: "",
    pullRequest: "",
    agentDetection: false,
  };

  it("sends an explicit agent_detection on both repository sources", () => {
    const local = buildSubmitPayload(base);
    expect(local.body).toEqual({ repository_key: "team/project", agent_detection: false });

    const github = buildSubmitPayload({
      ...base,
      sourceMode: "github",
      repository: "https://github.com/team/project",
      githubRef: "main ",
      agentDetection: true,
    });
    expect(github.body).toEqual({
      source: { type: "github", url: "https://github.com/team/project", ref: "main" },
      agent_detection: true,
    });
  });

  it("never adds agent_detection to PR/diff reviews", () => {
    const diff = buildSubmitPayload({
      ...base,
      mode: "diff",
      diff: "@@\n+x",
      pullRequest: "7",
      agentDetection: true,
    });
    expect(diff.path).toBe("/v1/reviews?async=true");
    expect(diff.body).not.toHaveProperty("agent_detection");
  });
});

describe("AuditCreatePage navigation recovery", () => {
  it("restores the draft when navigating away and back without refresh", async () => {
    stubFetch([CAPABILITIES]);
    const router = renderAt("/audit/new");
    await fillTarget("agent-sec-labs/LIMA");

    await router.navigate("/tasks");
    await waitFor(() => {
      expect(screen.queryByLabelText("仓库目标")).not.toBeInTheDocument();
    });

    await router.navigate("/audit/new");
    const restored = (await screen.findByLabelText("仓库目标")) as HTMLInputElement;
    expect(restored.value).toBe("agent-sec-labs/LIMA");
    expect(screen.getByText("选择目标")).toBeInTheDocument();
  });
});

describe("AuditCreatePage submission boundary", () => {
  it("returns to editing with the draft intact when the API rejects the request", async () => {
    stubFetch([
      CAPABILITIES,
      {
        url: "/v1/repository-scans",
        method: "POST",
        status: 400,
        body: { error: "仓库键不在导入根目录内" },
      },
    ]);
    renderAt("/audit/new");
    await fillTarget("team/project");
    clickNext();
    fireEvent.click(await screen.findByRole("button", { name: /开始安全审计/ }));

    const input = (await screen.findByLabelText("仓库目标")) as HTMLInputElement;
    expect(input.value).toBe("team/project");
    expect(await screen.findByText("仓库键不在导入根目录内")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /下一步/ })).toBeInTheDocument();
  });

  it("hands off to the task route on 202 and clears the draft", async () => {
    stubFetch([
      CAPABILITIES,
      {
        url: "/v1/repository-scans",
        method: "POST",
        status: 202,
        body: { task_id: "task-123", state: "PENDING" },
      },
      {
        url: "/v1/tasks/task-123",
        body: {
          id: "task-123",
          state: "PENDING",
          repository: "team/project",
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          input: {},
          progress: null,
          failure: null,
          error: null,
        },
      },
    ]);
    const router = renderAt("/audit/new");
    await fillTarget("team/project");
    clickNext();
    fireEvent.click(await screen.findByRole("button", { name: /开始安全审计/ }));

    // 202 后责任移交任务中心：详情页渲染该任务（T7 TaskDetailPage）
    expect(await screen.findByText("等待中")).toBeInTheDocument();
    expect(screen.getAllByText("team/project").length).toBeGreaterThanOrEqual(1);
    await router.navigate("/audit/new");
    const input = (await screen.findByLabelText("仓库目标")) as HTMLInputElement;
    expect(input.value).toBe("");
  });
});

describe("AuditCreatePage Zod validation", () => {
  it("rejects an empty target with a readable message", async () => {
    stubFetch([CAPABILITIES]);
    renderAt("/audit/new");
    await screen.findByText("发起安全审计");
    clickNext();
    expect(
      await screen.findByText("请输入 GitHub 仓库链接或 owner/project 仓库键。"),
    ).toBeInTheDocument();
  });

  it("rejects non-github hosts and malformed refs", async () => {
    stubFetch([CAPABILITIES]);
    renderAt("/audit/new");
    await fillTarget("https://gitlab.com/owner/project");
    clickNext();
    expect(await screen.findByText(/只接受 github.com 链接/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("radio", { name: /GitHub 仓库/ }));
    const refInput = (await screen.findByLabelText(/ref（可选/)) as HTMLInputElement;
    fireEvent.change(refInput, { target: { value: "release/../main" } });
    await fillTarget("owner/project");
    clickNext();
    expect(await screen.findByText(/ref 只能包含字母、数字/)).toBeInTheDocument();
  });

  it("requires a unified diff with added lines in diff mode", async () => {
    stubFetch([CAPABILITIES]);
    renderAt("/audit/new");
    fireEvent.click(await screen.findByRole("radio", { name: /PR \/ Diff 审查/ }));
    await fillTarget("owner/project");
    const diffArea = (await screen.findByLabelText(/Unified Diff/)) as HTMLTextAreaElement;
    fireEvent.change(diffArea, { target: { value: "not a diff" } });
    clickNext();
    expect(await screen.findByText(/请粘贴包含 @@ 区块和新增行/)).toBeInTheDocument();
  });
});

describe("AuditCreatePage capabilities gating", () => {
  it(
    "disables the GitHub source when the server reports it as off",
    async () => {
      stubFetch([
        {
          url: "/api/repository-scans/capabilities",
          body: {
            enabled: true,
            scan_sources: { configured: "local-import", github: false },
          },
        },
      ]);
      renderAt("/audit/new");
      // 用例预算由 vitest.config 的全局 testTimeout 统一放宽（CI 慢机）。
      await waitFor(
        () => {
          expect(screen.getByRole("radio", { name: /GitHub 仓库/ })).toBeDisabled();
        },
        { timeout: 9000 },
      );
      expect(screen.getByText(/GitHub 来源未启用/)).toBeInTheDocument();
    },
  );
});

describe("AuditCreatePage agent detection switch (#245)", () => {
  it("initializes on for default auto, requires confirmation, and sends agent_detection:true", async () => {
    const { requests } = stubTrackedFetch([
      {
        url: "/api/repository-scans/capabilities",
        body: { ...CAPABILITIES.body, cxx_agent: cxxAgentCaps({ mode: "auto" }) },
      },
      {
        url: "/v1/repository-scans",
        method: "POST",
        status: 202,
        body: { task_id: "task-agent", state: "PENDING" },
      },
      { url: "/v1/tasks/task-agent", body: pendingTask("task-agent") },
    ]);
    renderAt("/audit/new");
    await fillTarget("team/project");
    const sw = await agentSwitch();
    await waitFor(() => expect(sw.getAttribute("aria-checked")).toBe("true"));
    clickNext();
    fireEvent.click(await screen.findByRole("button", { name: /开始安全审计/ }));

    // 开启状态（含管理员默认值）必须先确认；取消不发送任何请求。
    expect(
      (await screen.findAllByText("确认启用智能体检测？")).length,
    ).toBeGreaterThan(0);
    expect(screen.getByText(/最多 40 次模型调用/)).toBeInTheDocument();
    expect(requests.filter((r) => r.url === "/v1/repository-scans")).toHaveLength(0);
    fireEvent.click(screen.getByRole("button", { name: /取\s*消/ }));
    await waitFor(() =>
      expect(screen.queryAllByText("确认启用智能体检测？")).toHaveLength(0),
    );

    // 再次提交并确认 → 载荷显式带 agent_detection:true。
    fireEvent.click(screen.getByRole("button", { name: /开始安全审计/ }));
    fireEvent.click(await screen.findByRole("button", { name: "确认开启并提交" }));
    await waitFor(() => {
      const post = requests.find((r) => r.url === "/v1/repository-scans");
      expect(post?.body).toMatchObject({
        repository_key: "team/project",
        agent_detection: true,
      });
    });
  });

  it("sends agent_detection:false without confirmation when the user turns off default auto", async () => {
    const { requests } = stubTrackedFetch([
      {
        url: "/api/repository-scans/capabilities",
        body: { ...CAPABILITIES.body, cxx_agent: cxxAgentCaps({ mode: "auto" }) },
      },
      {
        url: "/v1/repository-scans",
        method: "POST",
        status: 202,
        body: { task_id: "task-off", state: "PENDING" },
      },
      { url: "/v1/tasks/task-off", body: pendingTask("task-off") },
    ]);
    renderAt("/audit/new");
    await fillTarget("team/project");
    const sw = await agentSwitch();
    await waitFor(() => expect(sw.getAttribute("aria-checked")).toBe("true"));
    // 用户显式关闭：异步 capabilities 不得再覆盖该选择。
    fireEvent.click(sw);
    await waitFor(() => expect(sw.getAttribute("aria-checked")).toBe("false"));
    clickNext();
    fireEvent.click(await screen.findByRole("button", { name: /开始安全审计/ }));
    // 关闭时不弹调用确认，直接提交。
    await waitFor(() => {
      expect(screen.queryByText("确认启用智能体检测？")).not.toBeInTheDocument();
    });
    await waitFor(() => {
      const post = requests.find((r) => r.url === "/v1/repository-scans");
      expect(post?.body).toMatchObject({ agent_detection: false });
    });
  });

  it("locks the switch on for required mode and explains the server policy", async () => {
    stubFetch([
      {
        url: "/api/repository-scans/capabilities",
        body: {
          ...CAPABILITIES.body,
          cxx_agent: cxxAgentCaps({
            mode: "required",
            per_request_switch: false,
            repository_scan: true,
            configured: true,
          }),
        },
      },
    ]);
    renderAt("/audit/new");
    const sw = await agentSwitch();
    await waitFor(() => expect(sw.getAttribute("aria-checked")).toBe("true"));
    expect(sw).toBeDisabled();
    expect(
      await screen.findByText("服务端策略要求开启智能体检测，本次任务无法关闭。"),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /下一步/ })).toBeEnabled();
  });

  it("keeps the switch off and disabled when the model or analyzer is not configured", async () => {
    stubFetch([
      {
        url: "/api/repository-scans/capabilities",
        body: {
          ...CAPABILITIES.body,
          cxx_agent: cxxAgentCaps({ llm_configured: false }),
        },
      },
    ]);
    renderAt("/audit/new");
    const sw = await agentSwitch();
    await waitFor(() => expect(sw).toBeDisabled());
    expect(sw.getAttribute("aria-checked")).toBe("false");
    expect(
      await screen.findByText("服务端模型或事实分析器未配置，暂不能开启智能体检测。"),
    ).toBeInTheDocument();
  });

  it("pauses repository submission when default-on lacks configuration", async () => {
    stubFetch([
      {
        url: "/api/repository-scans/capabilities",
        body: {
          ...CAPABILITIES.body,
          cxx_agent: cxxAgentCaps({ mode: "auto", analyzer_configured: false }),
        },
      },
    ]);
    renderAt("/audit/new");
    // 提示同时出现在开关区与提交按钮区：两处都可见。
    expect(
      (await screen.findAllByText(
        "管理员默认开启了智能体检测，但服务端模型或事实分析器未配置；请联系管理员修复后再提交。",
      )).length,
    ).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: /下一步/ })).toBeDisabled();
  });

  it("pauses repository submission on an old server without the new capability fields", async () => {
    stubFetch([
      {
        url: "/api/repository-scans/capabilities",
        body: {
          enabled: true,
          scan_sources: { configured: "both", local_import: true, github: true },
        },
      },
    ]);
    renderAt("/audit/new");
    expect(
      (await screen.findAllByText(/服务端版本较旧，暂不支持按任务开启智能体检测/)).length,
    ).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: /下一步/ })).toBeDisabled();
    // PR / Diff 审查不受 capabilities 门禁影响。
    fireEvent.click(screen.getByRole("radio", { name: /PR \/ Diff 审查/ }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /下一步/ })).toBeEnabled(),
    );
  });

  it("pauses repository submission with a retry when capabilities fail to load", async () => {
    stubFetch([
      {
        url: "/api/repository-scans/capabilities",
        status: 500,
        body: { error: "boom" },
      },
    ]);
    renderAt("/audit/new");
    // antd 对两字按钮自动加字间距（“重 试”），用正则匹配。
    expect(await screen.findByRole("button", { name: /重\s*试/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /下一步/ })).toBeDisabled();
    // PR / Diff 审查不受影响。
    fireEvent.click(screen.getByRole("radio", { name: /PR \/ Diff 审查/ }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /下一步/ })).toBeEnabled(),
    );
  });

  it("pauses repository submission while capabilities are still loading", async () => {
    // 审计问题 2 复现：能力请求一直不返回时，用户仍能走完向导，但
    // 提交入口必须禁用且不得发送 agent_detection（绕过策略检查与确认）。
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        calls.push(String(input));
        return new Promise(() => {});
      }),
    );
    renderAt("/audit/new");
    await fillTarget("team/project");
    // editing 阶段允许继续填表前进；真正的提交入口在 loading 下必须禁用。
    clickNext();
    const start = await screen.findByRole("button", { name: /开始安全审计/ });
    expect(start).toBeDisabled();
    expect(
      (await screen.findAllByText(/正在读取服务端智能体检测配置/)).length,
    ).toBeGreaterThan(0);
    expect(calls.filter((url) => url === "/v1/repository-scans")).toHaveLength(0);
  });

  it("submits the effective policy value when required locks a stale off draft", async () => {
    // 审计问题 3 复现：草稿残留 false（上个会话关闭过），服务端切到
    // required 后 UI 锁定开启，请求必须带 true 而不是草稿值。
    saveDraft({
      mode: "repository",
      sourceMode: "local",
      repository: "",
      githubRef: "",
      diff: "",
      pullRequest: "",
      agentDetection: false,
    });
    const { requests } = stubTrackedFetch([
      {
        url: "/api/repository-scans/capabilities",
        body: {
          ...CAPABILITIES.body,
          cxx_agent: cxxAgentCaps({
            mode: "required",
            per_request_switch: false,
            repository_scan: true,
            configured: true,
          }),
        },
      },
      {
        url: "/v1/repository-scans",
        method: "POST",
        status: 202,
        body: { task_id: "task-locked", state: "PENDING" },
      },
      { url: "/v1/tasks/task-locked", body: pendingTask("task-locked") },
    ]);
    renderAt("/audit/new");
    await fillTarget("team/project");
    const sw = await agentSwitch();
    await waitFor(() => expect(sw.getAttribute("aria-checked")).toBe("true"));
    expect(sw).toBeDisabled();
    clickNext();
    fireEvent.click(await screen.findByRole("button", { name: /开始安全审计/ }));
    fireEvent.click(await screen.findByRole("button", { name: "确认开启并提交" }));
    await waitFor(() => {
      const post = requests.find((r) => r.url === "/v1/repository-scans");
      expect(post?.body).toMatchObject({
        repository_key: "team/project",
        agent_detection: true,
      });
    });
  });

  it("keeps the draft and refreshes capabilities on a named agent-detection 400", async () => {
    const { requests } = stubTrackedFetch([
      { url: "/api/repository-scans/capabilities", body: CAPABILITIES.body },
      {
        url: "/v1/repository-scans",
        method: "POST",
        status: 400,
        body: {
          error: "agent detection model is not configured",
          code: "agent-detection-unavailable",
        },
      },
    ]);
    renderAt("/audit/new");
    await fillTarget("team/project");
    clickNext();
    fireEvent.click(await screen.findByRole("button", { name: /开始安全审计/ }));

    // 具名 400：可读提示 + 草稿保留 + capabilities 刷新。
    expect(
      await screen.findByText("服务端未配置智能体检测模型，暂时无法开启；请联系管理员配置后重试。"),
    ).toBeInTheDocument();
    const input = (await screen.findByLabelText("仓库目标")) as HTMLInputElement;
    expect(input.value).toBe("team/project");
    await waitFor(() => {
      expect(
        requests.filter((r) => r.url === "/api/repository-scans/capabilities").length,
      ).toBeGreaterThanOrEqual(2);
    });
  });
});
