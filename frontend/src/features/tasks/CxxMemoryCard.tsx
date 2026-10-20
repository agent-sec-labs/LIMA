import React from "react";
import { Alert, Card, Space, Tag, Typography } from "antd";
import type { CxxMemorySummary } from "@/shared/api/types";

/** Process exit is not evidence acceptance; also interpret legacy diagnostics. */
export function CxxMemoryCard({ summary }: { summary?: CxxMemorySummary | undefined }): React.JSX.Element | null {
  if (!summary?.status || ["disabled", "not-applicable"].includes(summary.status)) return null;
  const diagnostics = Array.isArray(summary.diagnostics) ? summary.diagnostics.filter((item) => typeof item === "string") : [];
  const runs = Array.isArray(summary.tool_runs) ? summary.tool_runs : [];
  const failed = ["failed", "unavailable", "invalid-response"].includes(summary.status)
    || (summary.status !== "partial" && runs.some((run) => ["failed", "timed-out", "build_failed"].includes(run.status ?? "")))
    || diagnostics.some((item) => /rejected|did not complete|incomplete or truncated|semgrep-reported-errors/i.test(item));
  const partial = !failed && (summary.status === "partial" || diagnostics.length > 0);
  return (
    <Card size="small" title="C/C++ 分析状态">
      <Space direction="vertical" style={{ width: "100%" }}>
        <Alert type={failed ? "error" : partial ? "warning" : "success"} showIcon
          message={failed ? "C/C++ 分析失败" : partial ? "C/C++ 分析部分完成" : "C/C++ 分析完成"}
          description="工具完成不等于漏洞已确认；覆盖缺口或没有发现均不代表已证明仓库安全。" />
        {summary.coverage?.source_files !== undefined && <Typography.Text>静态快照 C/C++ 文件：{summary.coverage.source_files}</Typography.Text>}
        <Space wrap>{runs.map((run, index) => <Tag key={index}>{run.tool || "工具"}：{run.status || "未知"}</Tag>)}</Space>
        {diagnostics.map((item, index) => <Typography.Text key={index}>{item}</Typography.Text>)}
      </Space>
    </Card>
  );
}
