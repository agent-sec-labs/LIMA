import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { CxxMemoryCard } from "./CxxMemoryCard";

describe("C++ analysis evidence status", () => {
  it("does not call a legacy rejected parser result successful", () => {
    render(<CxxMemoryCard summary={{ status: "completed", diagnostics: ["Semgrep JSON was rejected"], tool_runs: [{ tool: "semgrep", status: "completed" }] }} />);
    expect(screen.getByText("C/C++ 分析失败")).toBeInTheDocument();
    expect(screen.getByText("Semgrep JSON was rejected")).toBeInTheDocument();
  });

  it("shows unavailable build and sanitizer layers as incomplete coverage", () => {
    render(<CxxMemoryCard summary={{ status: "partial", diagnostics: ["build-not-configured", "sanitizer-not-configured"], coverage: { source_files: 3002 } }} />);
    expect(screen.getByText("C/C++ 分析部分完成")).toBeInTheDocument();
    expect(screen.getByText("build-not-configured")).toBeInTheDocument();
  });

  it("shows accepted source evidence separately from vulnerability confirmation", () => {
    render(<CxxMemoryCard summary={{ status: "completed", tool_runs: [{ tool: "semgrep", status: "completed" }] }} />);
    expect(screen.getByText("C/C++ 分析完成")).toBeInTheDocument();
    expect(screen.getByText(/不代表已证明仓库安全/)).toBeInTheDocument();
  });

  it("hides the card for disabled analysis", () => {
    const { container } = render(<CxxMemoryCard summary={{ status: "disabled" }} />);
    expect(container).toBeEmptyDOMElement();
  });
});
