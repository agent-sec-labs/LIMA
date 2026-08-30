import React, { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Empty,
  Input,
  List,
  Radio,
  Space,
  Tag,
  Typography,
} from "antd";
import { api } from "@/shared/api/client";
import type { TaskListItem } from "@/shared/api/types";
import {
  STATE_LABELS,
  formatTime,
  isTerminalState,
  listRefetchInterval,
  stateColor,
  stageLabel,
} from "./model";

type FilterKey = "all" | "running" | "SUCCESS" | "FAILED";

/** 任务列表：每项展示生命周期状态 + 当前执行阶段；点击进入 /tasks/:id 详情。 */

export function TaskListPage(): React.JSX.Element {
  const navigate = useNavigate();
  const [filter, setFilter] = useState<FilterKey>("all");
  const [search, setSearch] = useState("");

  const query = useQuery({
    queryKey: ["tasks"],
    queryFn: () => api.get<{ tasks: TaskListItem[] }>("/api/tasks"),
    refetchInterval: (ctx) => listRefetchInterval(ctx.state.data?.tasks),
    refetchOnWindowFocus: true,
  });

  const tasks = useMemo(() => {
    const all = query.data?.tasks ?? [];
    const keyword = search.trim().toLowerCase();
    return all.filter((task) => {
      const stateOk =
        filter === "all"
          ? true
          : filter === "running"
            ? !isTerminalState(task.state)
            : task.state === filter;
      const textOk =
        keyword === ""
          ? true
          : `${task.id} ${task.repository}`.toLowerCase().includes(keyword);
      return stateOk && textOk;
    });
  }, [query.data, filter, search]);

  return (
    <div style={{ padding: 24 }}>
      <Typography.Title level={3}>审计结果</Typography.Title>
      <Space direction="vertical" size="middle" style={{ width: "100%" }}>
        <Space wrap>
          <Radio.Group
            value={filter}
            onChange={(event) => setFilter(event.target.value as FilterKey)}
            optionType="button"
            buttonStyle="solid"
          >
            <Radio.Button value="all">全部</Radio.Button>
            <Radio.Button value="running">进行中</Radio.Button>
            <Radio.Button value="SUCCESS">已完成</Radio.Button>
            <Radio.Button value="FAILED">失败</Radio.Button>
          </Radio.Group>
          <Input.Search
            placeholder="搜索仓库或任务 ID"
            allowClear
            style={{ width: 260 }}
            onSearch={setSearch}
            onChange={(event) => setSearch(event.target.value)}
          />
          <Typography.Text type="secondary">
            {tasks.length} / {query.data?.tasks?.length ?? 0} 项
          </Typography.Text>
          {query.isError && (
            <Typography.Text type="danger">
              任务列表加载失败：{(query.error as Error)?.message}
            </Typography.Text>
          )}
        </Space>
        <List
          size="small"
          loading={query.isLoading}
          dataSource={tasks}
          locale={{ emptyText: <Empty description="没有匹配的审计任务" /> }}
          renderItem={(task) => {
            const progress = task.progress;
            return (
              <List.Item
                style={{ cursor: "pointer", padding: "10px 12px" }}
                onClick={() => navigate(`/tasks/${encodeURIComponent(task.id)}`)}
              >
                <List.Item.Meta
                  title={
                    <Space>
                      <Typography.Text strong>{task.repository || "未命名审计"}</Typography.Text>
                      <Tag color={stateColor(task.state)}>
                        {STATE_LABELS[task.state] ?? task.state}
                      </Tag>
                      <Typography.Text type="secondary">
                        {task.task_type === "repository_scan" ? "完整仓库" : "Diff 审查"}
                      </Typography.Text>
                    </Space>
                  }
                  description={
                    <Space size="middle" wrap>
                      <span>
                        {progress
                          ? `${stageLabel(progress.stage)}（${progress.stage_index}/${progress.stage_total}）`
                          : "暂无执行进度"}
                      </span>
                      {progress?.message ? (
                        <Typography.Text type="secondary">{progress.message}</Typography.Text>
                      ) : null}
                      {progress && progress.attempt > 1 ? (
                        <Tag color="orange">重试 {progress.attempt}/{progress.max_attempts}</Tag>
                      ) : null}
                    </Space>
                  }
                />
                <Typography.Text type="secondary">{formatTime(task.created_at)}</Typography.Text>
              </List.Item>
            );
          }}
        />
      </Space>
    </div>
  );
}
