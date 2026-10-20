import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { clearStoredToken, storeToken } from "@/shared/api/client";
import { TaskActions } from "./TaskActions";

afterEach(() => { vi.unstubAllGlobals(); clearStoredToken(); });
function show(state: "EXECUTING" | "CANCELLED" | "SUCCESS", report = false) {
  render(<QueryClientProvider client={new QueryClient()}><TaskActions task={{ id: "task-1", repository: "ResInsight", state, report: report ? {} : null }} /></QueryClientProvider>);
}

describe("task controls", () => {
  it("sends an authenticated cancellation request", async () => {
    storeToken("session");
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ cancel_requested: true }), { status: 202, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetch);
    show("EXECUTING");
    fireEvent.click(screen.getByRole("button", { name: "请求取消" }));
    expect(await screen.findByText(/取消请求已提交/)).toBeInTheDocument();
    expect(fetch).toHaveBeenCalledWith("/v1/tasks/task-1/cancel", expect.objectContaining({ method: "POST", headers: expect.objectContaining({ Authorization: "Bearer session" }) }));
  });

  it("can resume a cancelled task", async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ resumed: true }), { status: 202, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetch);
    show("CANCELLED");
    fireEvent.click(screen.getByRole("button", { name: "恢复任务" }));
    expect(await screen.findByText(/任务已重新入队/)).toBeInTheDocument();
    expect(fetch).toHaveBeenCalledWith("/v1/tasks/task-1/resume", expect.objectContaining({ method: "POST" }));
    expect(screen.queryByRole("button", { name: "请求取消" })).not.toBeInTheDocument();
  });

  it("offers report download only when a completed report exists", () => {
    show("SUCCESS", true);
    expect(screen.getByRole("button", { name: "下载报告" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "恢复任务" })).not.toBeInTheDocument();
  });
});
