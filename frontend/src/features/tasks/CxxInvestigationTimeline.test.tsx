import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { CxxInvestigationTimeline } from "./CxxInvestigationTimeline";

describe("CxxInvestigationTimeline", () => {
  it("renders old targets without an investigation", () => {
    const { container } = render(<CxxInvestigationTimeline />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows observed actions, stop reason, and delegated tasks", () => {
    render(<CxxInvestigationTimeline investigation={{
      strategy: "team", stop_reason: "budget-exhausted", action_count: 1, child_count: 1,
      actions: [{ tool: "read_source", purpose: "检查释放后的所有权" }],
      children: [{ role: "ownership", stop_reason: "final" }],
    }} />);
    expect(screen.getByText("检查释放后的所有权")).toBeInTheDocument();
    expect(screen.getByText("read_source")).toBeInTheDocument();
    expect(screen.getByText(/预算耗尽/)).toBeInTheDocument();
    expect(screen.getByText("ownership")).toBeInTheDocument();
  });

  it("reports omitted details", () => {
    render(<CxxInvestigationTimeline investigation={{
      stop_reason: "final", action_count: 12, child_count: 0,
      detail_omissions: ["investigation:byte-budget"],
    }} />);
    expect(screen.getByText(/详情因报告字节预算省略/)).toBeInTheDocument();
  });
});
