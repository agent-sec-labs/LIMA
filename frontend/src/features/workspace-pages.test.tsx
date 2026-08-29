import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { App as AntApp, ConfigProvider } from "antd";
import { RouterProvider } from "react-router-dom";
import { AuthProvider } from "@/shared/auth/AuthContext";
import { createAppRouter, type AppRouterInstance } from "@/router";

/** T8 页面冒烟：skills / settings / evolution / experiments 的离线渲染契约。 */

interface FetchRoute {
  url: string;
  body: unknown;
}

function stubFetch(routes: FetchRoute[]): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      const route = routes.find((item) => item.url === url);
      if (!route) {
        return new Response(JSON.stringify({ error: `unstubbed ${url}` }), {
          status: 500,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify(route.body), {
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
          <AuthProvider>
            <RouterProvider router={router} />
          </AuthProvider>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  );
  return router;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("workspace pages", () => {
  it("skills page lists sandboxed capabilities and the local-rules fallback", async () => {
    stubFetch([
      {
        url: "/api/skills",
        body: {
          llm: { enabled: false, provider: "local", model: "" },
          skills: [
            {
              name: "repository-scan",
              version: "2.0",
              source: "built-in",
              sandboxed: true,
              description: "受控读取 Python 仓库，融合 AST、跨文件数据流和 SAST 证据。",
            },
            { name: "llm-review", version: "1.0", sandboxed: false, description: "内部组件，不应展示。" },
          ],
        },
      },
    ]);
    renderAt("/skills");
    expect(await screen.findByText("repository-scan")).toBeInTheDocument();
    expect(screen.getByText("确定性本地规则")).toBeInTheDocument();
    expect(screen.getByText("隔离运行")).toBeInTheDocument();
    expect(screen.queryByText("llm-review")).not.toBeInTheDocument();
  });

  it("settings page keeps key guidance server-side without any client input", async () => {
    stubFetch([
      { url: "/api/skills", body: { llm: { enabled: true, provider: "deepseek", model: "deepseek-v4-flash" } } },
    ]);
    renderAt("/settings");
    expect(await screen.findByText("规则 + LLM 证据融合")).toBeInTheDocument();
    expect(screen.getByText("LIMA_DEEPSEEK_API_KEY")).toBeInTheDocument();
    expect(screen.getByText(/网页不可读取/)).toBeInTheDocument();
  });

  it("evolution page renders gate stats and unresolved case count", async () => {
    stubFetch([
      {
        url: "/v1/evolution/status",
        body: { validation_cases: 42, holdout_cases: 18, unresolved_cases: 2, active_version: "1.5.0", ready: true },
      },
      {
        url: "/v1/evolution/runs",
        body: { runs: [{ candidate_version: "1.5.0", decision: "通过门禁", candidate_score: 0.842, baseline_score: 0.811 }] },
      },
      { url: "/api/failures", body: { cases: [] } },
    ]);
    renderAt("/evolution");
    expect(await screen.findByText("42")).toBeInTheDocument();
    expect(screen.getByText("通过门禁")).toBeInTheDocument();
    expect(screen.getByText("门禁就绪")).toBeInTheDocument();
  });

  it("experiments page renders the record list, live state and metric labels", async () => {
    stubFetch([
      {
        url: "/v1/experiments/catalog",
        body: {
          llm_available: true,
          datasets: [{ path: "demo/repository-disjoint.json", name: "热门仓库外部评测示例", case_count: 5, modes: ["retrieval"] }],
        },
      },
      {
        url: "/v1/experiments",
        body: {
          experiments: [
            {
              id: "00000000-0000-4000-8000-000000000001",
              state: "SUCCEEDED",
              mode: "llm-retrieval",
              dataset_path: "demo/repository-disjoint.json",
              manifest: { dataset_name: "热门仓库外部评测示例" },
              progress: { total_cases: 5, completed_cases: 5, llm_calls: 10, total_tokens: 18420 },
              result: { metrics: { cases: 5, retrieval_target_symbol_recall: 0.8, llm_paired_discrimination_rate: 0.6 } },
            },
          ],
        },
      },
    ]);
    renderAt("/experiments");
    expect(await screen.findByText("热门仓库外部评测示例")).toBeInTheDocument();
    expect(screen.getAllByText("已完成").length).toBeGreaterThan(0);
    expect(screen.getByText("风险不变量召回率")).toBeInTheDocument();
    expect(screen.getByText("目标人工复核率")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /创建后台实验/ })).toBeInTheDocument();
  });
});
