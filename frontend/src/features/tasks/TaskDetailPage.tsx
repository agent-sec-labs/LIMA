import React from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Card,
  Collapse,
  Descriptions,
  Progress,
  Space,
  Steps,
  Table,
  Tag,
  Typography,
} from "antd";
import { api } from "@/shared/api/client";
import type { FindingItem, TaskCompletion, TaskDetail, TaskProgress } from "@/shared/api/types";
import {
  ALL_STAGES,
  STATE_LABELS,
  detailRefetchInterval,
  formatElapsed,
  formatTime,
  isTerminalState,
  resolvedRevision,
  severityMeta,
  sourceSummary,
  stageLabel,
  stateColor,
  verificationLabel,
} from "./model";

/**
 * 任务详情：URL 即选中态（/tasks/:taskId）。
 * 轮询由 detailRefetchInterval 决定（活跃 2s→4s，终态停，隐藏暂停，回焦即刷）。
 */

function StageTimeline({ progress }: { progress: TaskProgress }): React.JSX.Element {
  const currentIndex = Math.max(0, progress.stage_index - 1);
  return (
    <Card size="small" title="执行进度" extra={<Typography.Text type="secondary">{progress.stage_index}/{progress.stage_total} 阶段</Typography.Text>}>
      <Steps
        direction="vertical"
        size="small"
        current={currentIndex}
        items={ALL_STAGES.map((stage, index) => ({
          title: stageLabel(stage),
          description:
            index === currentIndex && stage !== "COMPLETED"
              ? [
                  progress.message,
                  progress.current !== null && progress.total !== null && progress.total > 0
                    ? `${progress.current}/${progress.total} ${progress.unit || ""}`
                    : null,
                ]
                  .filter(Boolean)
                  .join(" · ")
              : undefined,
        }))}
      />
      <Space wrap style={{ marginTop: 12 }}>
        {progress.current !== null && progress.total !== null && progress.total > 0 && (
          <Progress
            percent={Math.round((Number(progress.current) / Number(progress.total)) * 100)}
            size="small"
            style={{ maxWidth: 240 }}
          />
        )}
        {progress.attempt > 1 && (
          <Tag color="orange">
            队列重试：第 {progress.attempt} 次 / 上限 {progress.max_attempts}
          </Tag>
        )}
        <Typography.Text type="secondary">
          阶段开始于 {formatTime(progress.stage_started_at)} · 更新于 {formatTime(progress.updated_at)}
        </Typography.Text>
      </Space>
    </Card>
  );
}

function FailureCard({ task }: { task: TaskDetail }): React.JSX.Element {
  const failure = task.failure;
  if (!failure) {
    return (
      <Alert
        type="error"
        showIcon
        message="任务失败（无结构化诊断）"
        description={task.error || "请检查服务端任务日志后重试。"}
      />
    );
  }
  return (
    <Card size="small" title="失败诊断">
      <Space direction="vertical" size="small" style={{ width: "100%" }}>
        <Typography.Title level={5} style={{ margin: 0 }}>{failure.title}</Typography.Title>
        <Space wrap>
          <Tag color="red">{failure.code}</Tag>
          {failure.stage ? <Tag>阶段：{stageLabel(failure.stage)}</Tag> : null}
          <Tag color={failure.retryable ? "orange" : "default"}>
            {failure.retryable ? "可自动重试" : "不可自动重试"}
          </Tag>
          {task.progress && task.progress.attempt > 1 ? (
            <Tag color="orange">已重试 {task.progress.attempt - 1} 次</Tag>
          ) : null}
        </Space>
        <Typography.Paragraph style={{ marginBottom: 0 }}>{failure.message}</Typography.Paragraph>
        <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
          建议处理：{failure.suggestion}
        </Typography.Paragraph>
        {failure.technical_detail ? (
          <Collapse
            size="small"
            items={[{
              key: "tech",
              label: "技术细节（默认折叠，面向管理员）",
              children: (
                <Typography.Text code style={{ whiteSpace: "pre-wrap" }}>
                  {failure.technical_detail}
                </Typography.Text>
              ),
            }]}
          />
        ) : null}
      </Space>
    </Card>
  );
}

function CompletionBanner({ completion }: { completion: TaskCompletion }): React.JSX.Element {
  if (completion.status === "completed_with_warnings") {
    return (
      <Alert
        type="warning"
        showIcon
        message={`完成但有警告：${completion.warning_count} 项影响覆盖的跳过`}
        description={
          completion.warnings ? (
            <Space direction="vertical" size={0}>
              {Object.entries(completion.warnings).map(([reason, count]) => (
                <span key={reason}>
                  {reason}（{count} 个）
                </span>
              ))}
            </Space>
          ) : null
        }
      />
    );
  }
  return <Alert type="success" showIcon message="审计完成" description="本次执行没有影响覆盖范围的跳过。" />;
}

const FINDING_COLUMNS = [
  {
    title: "严重性",
    dataIndex: "severity",
    key: "severity",
    width: 90,
    render: (value: string) => {
      const meta = severityMeta(value);
      return <Tag color={meta.color}>{meta.label}</Tag>;
    },
  },
  {
    title: "问题与依据",
    dataIndex: "title",
    key: "title",
    render: (value: string, record: FindingItem) => (
      <Space direction="vertical" size={0}>
        <Typography.Text strong>{value || record.rule_id || "未命名问题"}</Typography.Text>
        <Typography.Text type="secondary">
          {record.cwe || "CWE 未分类"} · {record.rule_id || "未命名规则"}
        </Typography.Text>
      </Space>
    ),
  },
  {
    title: "位置",
    key: "location",
    width: 220,
    render: (_: unknown, record: FindingItem) => (
      <Typography.Text code>{`${record.path || "未知文件"}:${record.line ?? "?"}`}</Typography.Text>
    ),
  },
  {
    title: "证据状态",
    dataIndex: "verification_state",
    key: "verification_state",
    width: 110,
    render: (value: string) => verificationLabel(value),
  },
  {
    title: "置信度",
    dataIndex: "confidence",
    key: "confidence",
    width: 90,
    render: (value: number | undefined) =>
      value === undefined || value === null ? "—" : `${Math.round(Number(value) * 100)}%`,
  },
];

function ReportCard({ task }: { task: TaskDetail }): React.JSX.Element | null {
  const report = task.report;
  if (!report) return null;
  const findings = report.findings ?? [];
  const files = Array.isArray(report.files_reviewed)
    ? report.files_reviewed.length
    : Number(report.files_reviewed || 0);
  const revision = resolvedRevision(task);
  return (
    <Card size="small" title="审计报告" style={{ marginTop: 16 }}>
      <Space direction="vertical" size="small" style={{ width: "100%" }}>
        <Descriptions size="small" column={2} bordered>
          <Descriptions.Item label="风险评级">
            <Tag color={severityMeta(report.risk).color}>{severityMeta(report.risk).label}</Tag>
          </Descriptions.Item>
          <Descriptions.Item label="发现数量">{findings.length}</Descriptions.Item>
          <Descriptions.Item label="扫描文件数">{files}</Descriptions.Item>
          <Descriptions.Item label="分析引擎">{report.reviewer || "—"}</Descriptions.Item>
          {revision ? (
            <Descriptions.Item label="已扫描固定提交" span={2}>
              <Typography.Text code>{revision}</Typography.Text>
            </Descriptions.Item>
          ) : null}
        </Descriptions>
        {report.summary ? <Typography.Paragraph>{report.summary}</Typography.Paragraph> : null}
        <Table
          size="small"
          columns={FINDING_COLUMNS}
          dataSource={findings}
          rowKey={(_record, index) => String(index)}
          pagination={findings.length > 10 ? { pageSize: 10 } : false}
          expandable={{
            expandedRowRender: (record: FindingItem) => (
              <Space direction="vertical" size={4} style={{ width: "100%" }}>
                <span><strong>为什么是问题：</strong>{record.explanation || "当前报告没有提供进一步解释。"}</span>
                <span><strong>关键证据：</strong>{record.evidence || "当前报告没有提供证据摘要。"}</span>
                <span><strong>建议修复：</strong>{record.fix || "建议由开发者结合业务上下文制定最小修复。"}</span>
              </Space>
            ),
          }}
        />
        <Typography.Text type="secondary">
          “没有发现”不等于“已经证明安全”；置信度不能替代可利用性分析。
          {report.adjudication?.policy ? ` 仲裁策略：${report.adjudication.policy}。` : ""}
        </Typography.Text>
      </Space>
    </Card>
  );
}

export function TaskDetailPage(): React.JSX.Element {
  const { taskId = "" } = useParams();
  const navigate = useNavigate();
  const query = useQuery({
    queryKey: ["task", taskId],
    queryFn: () => api.get<TaskDetail>(`/v1/tasks/${encodeURIComponent(taskId)}`),
    refetchInterval: (ctx) => detailRefetchInterval(ctx.state.data),
    refetchOnWindowFocus: true,
    enabled: taskId !== "",
  });

  if (query.isLoading) {
    return (
      <div style={{ padding: 24 }}>
        <Typography.Title level={3}>任务详情</Typography.Title>
        <Card size="small" loading />
      </div>
    );
  }
  if (query.isError || !query.data) {
    return (
      <div style={{ padding: 24 }}>
        <Typography.Title level={3}>任务详情</Typography.Title>
        <Alert
          type="error"
          showIcon
          message="任务详情加载失败"
          description={(query.error as Error)?.message ?? "请检查服务连接后重试。"}
          action={<Button onClick={() => query.refetch()}>重试</Button>}
        />
      </div>
    );
  }

  const task = query.data;
  const running = !isTerminalState(task.state);
  const completion = running
    ? undefined
    : (task.progress?.detail as { completion?: TaskCompletion } | undefined)?.completion;

  return (
    <div style={{ padding: 24 }}>
      <Space direction="vertical" size="middle" style={{ width: "100%" }}>
        <Space wrap>
          <Button onClick={() => navigate("/tasks")}>返回列表</Button>
          <Typography.Title level={4} style={{ margin: 0 }}>
            {task.repository || "未命名审计"}
          </Typography.Title>
          <Tag color={stateColor(task.state)}>{STATE_LABELS[task.state] ?? task.state}</Tag>
          {task.pull_request ? <Tag>PR #{task.pull_request}</Tag> : null}
        </Space>
        <Descriptions size="small" column={3} bordered>
          <Descriptions.Item label="来源">{sourceSummary(task)}</Descriptions.Item>
          <Descriptions.Item label="创建时间">{formatTime(task.created_at)}</Descriptions.Item>
          <Descriptions.Item label="耗时">
            {formatElapsed(task.created_at, isTerminalState(task.state) ? task.updated_at : undefined)}
          </Descriptions.Item>
        </Descriptions>

        {running && task.progress && <StageTimeline progress={task.progress} />}
        {running && !task.progress && (
          <Alert type="info" showIcon message="任务排队或执行中，暂无阶段进度。" />
        )}

        {task.state === "FAILED" && <FailureCard task={task} />}
        {task.state === "CANCELLED" && (
          <Alert type="info" showIcon message="任务已取消" description={task.error || "—"} />
        )}

        {task.state === "SUCCESS" && completion && <CompletionBanner completion={completion} />}
        {task.state === "SUCCESS" && <ReportCard task={task} />}
      </Space>
    </div>
  );
}
