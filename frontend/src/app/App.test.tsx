import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { App } from "@/app/App";
import { createAppRouter } from "@/router";

// 地基冒烟：Provider 组合 + 路由渲染。业务页面由 T6/T7/T8 各自覆盖。
describe("App foundation", () => {
  it("renders the audit-create route inside the shell", async () => {
    render(<App router={createAppRouter("memory", "/audit/new")} />);
    expect(await screen.findByText("发起审计（T6）")).toBeInTheDocument();
  });

  it("keeps brand identity in the shell", async () => {
    render(<App router={createAppRouter("memory", "/tasks")} />);
    expect(await screen.findByText("审计结果（T7）")).toBeInTheDocument();
    expect(screen.getByText("砺码 · LIMA")).toBeInTheDocument();
  });
});
