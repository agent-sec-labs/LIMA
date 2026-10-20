import React, { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button, Space, Typography } from "antd";
import { api } from "@/shared/api/client";
import type { TaskDetail } from "@/shared/api/types";
import { isTerminalState } from "./model";

export function TaskActions({ task }: { task: TaskDetail }): React.JSX.Element {
  const client = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState("");
  const [failed, setFailed] = useState(false);
  const act = async (action: "cancel" | "resume" | "download"): Promise<void> => {
    setBusy(true);
    setFailed(false);
    try {
      if (action === "download") {
        const markdown = await api.taskReport(task.id);
        const url = URL.createObjectURL(new Blob([markdown], { type: "text/markdown;charset=utf-8" }));
        const link = document.createElement("a");
        link.href = url;
        link.download = `lima-${task.id}.md`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
        setResult("报告已下载。");
      } else {
        if (action === "cancel") {
          await api.cancelTask(task.id);
          setResult("取消请求已提交，将在当前工作单元结束后停止。");
        } else {
          await api.resumeTask(task.id);
          setResult("任务已重新入队。");
        }
        await client.invalidateQueries({ queryKey: ["task", task.id] });
        await client.invalidateQueries({ queryKey: ["tasks"] });
      }
    } catch (error) {
      setFailed(true);
      setResult(`操作失败：${(error as Error).message}`);
    } finally {
      setBusy(false);
    }
  };
  return <Space wrap>
    {!isTerminalState(task.state) && <Button loading={busy} onClick={() => void act("cancel")}>请求取消</Button>}
    {["FAILED", "CANCELLED"].includes(task.state) && <Button loading={busy} onClick={() => void act("resume")}>恢复任务</Button>}
    {task.state === "SUCCESS" && task.report && <Button loading={busy} onClick={() => void act("download")}>下载报告</Button>}
    {result && <Typography.Text type={failed ? "danger" : "secondary"}>{result}</Typography.Text>}
  </Space>;
}
