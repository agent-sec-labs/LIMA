import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "react-router-dom";
import { createAppRouter, type AppRouterInstance } from "@/router";
import { clearDraft } from "./model";

/**
 * T6 行为规格：三态边界 + 导航恢复 + 草稿保持 + 202 移交任务中心。
 * 全部通过 memory 路由与 fetch stub 离线运行。
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

const CAPABILITIES = {
  url: "/api/repository-scans/capabilities",
  body: {
    enabled: true,
    scan_sources: { configured: "both", local_import: true, github: true },
  },
};

function renderAt(path: string): AppRouterInstance {
  const router = createAppRouter("memory", path);
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
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
      await waitFor(
        () => {
          expect(screen.getByRole("radio", { name: /GitHub 仓库/ })).toBeDisabled();
        },
        { timeout: 9000 },
      );
      expect(screen.getByText(/GitHub 来源未启用/)).toBeInTheDocument();
    },
    // 本机冷启动/负载下该用例在默认 5s 边缘，显式放宽用例与等待超时。
    20000,
  );
});
