import React, { useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  App as AntApp,
  Button,
  Card,
  Collapse,
  Descriptions,
  Empty,
  Form,
  Input,
  InputNumber,
  Progress,
  Select,
  Space,
  Steps,
  Table,
  Tag,
  Typography,
} from "antd";
import { api } from "@/shared/api/client";
import type {
  FeedbackCategory,
  FeedbackPayload,
  FindingItem,
  FixResult,
  RepairPreviewResult,
  TaskCompletion,
  TaskDetail,
  TaskProgress,
} from "@/shared/api/types";
import {
  ALL_STAGES,
  DISPOSITION_LABELS,
  FEEDBACK_LABELS,
  SEMANTIC_STATUS_LABELS,
  STATE_LABELS,
  confidenceLabel,
  decisionForFinding,
  detailRefetchInterval,
  dispositionReason,
  formatElapsed,
  formatTime,
  isTerminalState,
  isVerifiedState,
  reportAdjudication,
  reportRisk,
  resolvedRevision,
  severityCounts,
  severityMeta,
  sourceSummary,
  stageLabel,
  stateColor,
  verificationLabel,
} from "./model";

/**
 * 任务详情：URL 即选中态（/tasks/:taskId）。
 * 轮询由 detailRefetchInterval 决定（活跃 2s→4s，终态停，隐藏暂停，回焦即刷）。
 * 报告视图含 T10 补齐的 legacy 对等功能：证据处置横幅、语义复核状态、
 * 修复预览 / 修复分支、误报反馈（含历史）。处置推导与文案与 web/app.js 逐字对齐。
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

/** 证据处置横幅（legacy disposition-banner 对等，fail-closed 文案逐字对齐）。 */
function DispositionBanner({
  adjudication,
}: {
  adjudication: ReturnType<typeof reportAdjudication>;
}): React.JSX.Element {
  const disposition = adjudication.overall_disposition;
  const label = DISPOSITION_LABELS[disposition] ?? "需要复核";
  const type = disposition === "alert" ? "error" : disposition === "clear" ? "success" : "warning";
  const explanation =
    disposition === "alert"
      ? "至少一项风险已有足够证据，请进入修复与安全回归流程。"
      : disposition === "clear"
        ? "全部评估对象同时具备确定性缓解证据与一致的模型 clean 结论。"
        : "证据缺失或相互冲突，系统已禁止自动放行，请安排人工复核。";
  return (
    <Alert
      type={type}
      showIcon
      aria-label="证据处置结论"
      message={`证据处置：${label}`}
      description={
        <Space direction="vertical" size={2}>
          <span>{explanation}</span>
          <Space size="large">
            <span><strong>{adjudication.counts.alert}</strong> 告警</span>
            <span><strong>{adjudication.counts.needs_review}</strong> 复核</span>
            <span><strong>{adjudication.counts.clear}</strong> 通过</span>
          </Space>
        </Space>
      }
    />
  );
}

/** 语义复核状态卡（legacy semantic-status-card 对等）。 */
function SemanticTriageCard({ report }: { report: NonNullable<TaskDetail["report"]> }): React.JSX.Element | null {
  const semantic = report.collaboration?.semantic_triage;
  if (!semantic || typeof semantic !== "object") return null;
  const status = String(semantic.status || "disabled");
  const healthy = status === "completed";
  const neutral = status === "disabled" || status === "llm-not-configured";
  const candidates = Number(semantic.retrieval?.evidence_candidates || 0);
  const tokens = Number(semantic.usage?.total_tokens || 0);
  const latency = Number(semantic.latency_ms || 0);
  const explanation = healthy
    ? "系统已对有界语义证据包执行一次批量模型复核，并与确定性安全不变量共同仲裁。"
    : status === "failed-closed" || status === "invalid-contract"
      ? "模型不可用或输出不符合契约；相关对象已进入人工复核，不会自动标记安全。"
      : status === "no-candidates"
        ? "当前检索器没有形成可验证的安全证据包，因此系统不会仅凭零发现给出安全结论。"
        : "生产语义复核当前未执行，报告仅使用本地 AST、数据流和 SAST 证据。";
  return (
    <Card size="small" title="生产语义复核状态" aria-label="生产语义复核状态">
      <Space direction="vertical" size="small" style={{ width: "100%" }}>
        <Space wrap>
          <Tag color={healthy ? "green" : neutral ? "default" : "orange"}>
            {String(semantic.mode || "off").toUpperCase()}
          </Tag>
          <Typography.Text strong>
            {SEMANTIC_STATUS_LABELS[status] || status}
          </Typography.Text>
        </Space>
        <Typography.Text type="secondary">{explanation}</Typography.Text>
        <Descriptions size="small" column={4} bordered>
          <Descriptions.Item label="供应商 / 模型" span={2}>
            {[semantic.provider, semantic.model].filter(Boolean).join(" / ") || "本地模式"}
          </Descriptions.Item>
          <Descriptions.Item label="证据候选">{candidates || "—"}</Descriptions.Item>
          <Descriptions.Item label="Token">{tokens || "—"}</Descriptions.Item>
          <Descriptions.Item label="模型时延">{latency ? `${Math.round(latency)} ms` : "—"}</Descriptions.Item>
        </Descriptions>
      </Space>
    </Card>
  );
}

/** 语义证据处置明细（decision_source === "semantic-llm" 且有 symbol）。 */
function SemanticEvidence({
  adjudication,
}: {
  adjudication: ReturnType<typeof reportAdjudication>;
}): React.JSX.Element | null {
  const rows = adjudication.decisions.filter(
    (decision) => decision.decision_source === "semantic-llm" && decision.symbol,
  );
  if (!rows.length) return null;
  return (
    <Card size="small" title="语义证据处置" extra={<Tag>{adjudication.policy}</Tag>}>
      <Typography.Paragraph type="secondary" style={{ marginBottom: 12 }}>
        模型结论必须与确定性不变量共同解读；冲突不会自动放行。
      </Typography.Paragraph>
      <Space direction="vertical" size="small" style={{ width: "100%" }}>
        {rows.map((decision, index) => {
          const color =
            decision.disposition === "alert" ? "red" : decision.disposition === "clear" ? "green" : "orange";
          const modelEvidence =
            decision.disposition === "clear"
              ? decision.llm_mitigation_evidence
              : decision.llm_root_cause || decision.llm_sink_evidence;
          return (
            <Card size="small" type="inner" key={`${decision.symbol}-${index}`}>
              <Space direction="vertical" size={2} style={{ width: "100%" }}>
                <Space wrap>
                  <Tag color={color}>{DISPOSITION_LABELS[decision.disposition] ?? "需要复核"}</Tag>
                  <Typography.Text strong>{decision.symbol}</Typography.Text>
                  <Typography.Text code>
                    {`${decision.path || "未知文件"}:${decision.start_line ?? "?"}`}
                  </Typography.Text>
                </Space>
                <span>{dispositionReason(decision.reason)}</span>
                <Typography.Text type="secondary">
                  模型证据：{modelEvidence || "模型没有提供可展示的证据摘要。"}
                </Typography.Text>
              </Space>
            </Card>
          );
        })}
      </Space>
    </Card>
  );
}

/** 严重度分布（按最大类别归一化的条形图，legacy chart-card 对等）。 */
function SeverityChart({ findings }: { findings: FindingItem[] }): React.JSX.Element {
  const counts = severityCounts(findings);
  const maxCount = Math.max(1, counts.critical, counts.high, counts.medium, counts.low, counts.info);
  const rows: Array<{ key: string; color: string }> = [
    { key: "critical", color: "#cf1322" },
    { key: "high", color: "#d4380d" },
    { key: "medium", color: "#d46b08" },
    { key: "low", color: "#389e0d" },
  ];
  return (
    <Card size="small" title="严重度分布" aria-label="严重度分布图">
      <Space direction="vertical" size={6} style={{ width: "100%" }}>
        {rows.map(({ key, color }) => (
          <Space key={key} style={{ width: "100%", justifyContent: "space-between" }} size="middle">
            <Typography.Text style={{ width: 36 }}>{severityMeta(key).label}</Typography.Text>
            <div style={{ flex: 1, height: 8, background: "#f0f0f0", borderRadius: 4, overflow: "hidden" }}>
              <div
                style={{
                  width: `${Math.round((counts[key] / maxCount) * 100)}%`,
                  height: "100%",
                  background: color,
                }}
                aria-label={`${severityMeta(key).label} ${counts[key]} 个`}
              />
            </div>
            <Typography.Text strong style={{ width: 28, textAlign: "right" }}>{counts[key]}</Typography.Text>
          </Space>
        ))}
      </Space>
    </Card>
  );
}

const OPERATION_LABELS: Record<string, string> = {
  status: "状态",
  branch: "修复分支",
  changed_files: "修改文件数",
  changed_lines: "修改行数",
  oracle: "安全 Oracle",
  cwe: "漏洞类型",
  note: "说明",
  snapshot_sha256: "快照 SHA256",
  files_changed: "修改文件数",
  duration_seconds: "耗时（秒）",
  publication_ready: "是否可发布",
  repository: "仓库",
  source_sha: "源提交",
  task_id: "任务",
};

function operationLabel(key: string): string {
  return OPERATION_LABELS[key] || key.replaceAll("_", " ");
}

function operationValue(value: unknown): string {
  if (typeof value === "boolean") return value ? "是" : "否";
  if (value == null || value === "") return "—";
  if (typeof value === "number") return Number.isInteger(value) ? String(value) : value.toFixed(3);
  if (Array.isArray(value)) return value.map(String).join("、") || "—";
  return String(value);
}

/** 修复预览 / 修复分支结果面板（legacy renderOperationResult 对等：仅标量与数组）。 */
function OperationResultPanel({
  title,
  data,
}: {
  title: string;
  data: RepairPreviewResult | FixResult;
}): React.JSX.Element {
  const entries = Object.entries(data ?? {}).filter(
    ([, value]) => typeof value !== "object" || Array.isArray(value),
  );
  return (
    <Card size="small" type="inner" title={title}>
      <Descriptions size="small" column={2} bordered>
        {entries.map(([key, value]) => (
          <Descriptions.Item key={key} label={operationLabel(key)}>
            {operationValue(value)}
          </Descriptions.Item>
        ))}
      </Descriptions>
    </Card>
  );
}

function findingsColumns(adjudication: ReturnType<typeof reportAdjudication>) {
  return [
    {
      title: "严重性",
      dataIndex: "severity",
      key: "severity",
      width: 84,
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
      width: 200,
      render: (_: unknown, record: FindingItem) => (
        <Typography.Text code>{`${record.path || "未知文件"}:${record.line ?? "?"}`}</Typography.Text>
      ),
    },
    {
      title: "处置结论",
      key: "disposition",
      width: 168,
      render: (_: unknown, record: FindingItem) => {
        const decision = decisionForFinding(record, adjudication);
        const color =
          decision.disposition === "alert" ? "red" : decision.disposition === "clear" ? "green" : "orange";
        return (
          <Space direction="vertical" size={0}>
            <Tag color={color}>{DISPOSITION_LABELS[decision.disposition] ?? "需要复核"}</Tag>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {dispositionReason(decision.reason)}
            </Typography.Text>
          </Space>
        );
      },
    },
    {
      title: "证据状态",
      dataIndex: "verification_state",
      key: "verification_state",
      width: 132,
      render: (value: string) => verificationLabel(value),
    },
    {
      title: "置信度",
      dataIndex: "confidence",
      key: "confidence",
      width: 90,
      render: (value: number | undefined) => confidenceLabel(value),
    },
  ];
}

interface FeedbackFormValues {
  category: FeedbackCategory;
  findingIndex: string;
  ruleId: string;
  path: string;
  line: number | null;
  note: string;
}

/** 反馈面板（legacy #feedback-panel 对等）：误报/漏报/坏修复 + 本任务历史。 */
function FeedbackPanel({ task }: { task: TaskDetail }): React.JSX.Element {
  const { message } = AntApp.useApp();
  const queryClient = useQueryClient();
  const taskId = task.id;
  const findings = useMemo(() => task.report?.findings ?? [], [task.report]);
  const [form] = Form.useForm<FeedbackFormValues>();
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState("");
  const category = Form.useWatch("category", form) ?? "false_positive";

  const history = useQuery({
    queryKey: ["task-feedback", taskId],
    queryFn: () => api.taskFeedback(taskId),
  });

  const submit = async (values: FeedbackFormValues): Promise<void> => {
    const finding =
      values.findingIndex === ""
        ? null
        : { ...(findings[Number(values.findingIndex)] || {}) };
    if (values.category === "missed_issue" && finding) {
      if (values.ruleId.trim()) finding.rule_id = values.ruleId.trim();
      if (values.path.trim()) finding.path = values.path.trim();
      if (Number.isInteger(values.line) && (values.line ?? 0) > 0) finding.line = values.line ?? 0;
    }
    setSubmitting(true);
    setResult("正在保存反馈…");
    try {
      const payload: FeedbackPayload = {
        category: values.category,
        finding: finding && Object.keys(finding).length ? finding : null,
        note: values.note.trim(),
      };
      const data = await api.submitTaskFeedback(taskId, payload);
      setResult(`${FEEDBACK_LABELS[data.category] || data.category}已记录，将进入后续回放评测。`);
      form.resetFields();
      await queryClient.invalidateQueries({ queryKey: ["task-feedback", taskId] });
      void message.success("反馈已记录：感谢你帮助系统区分真实漏洞与噪声。");
    } catch (error) {
      setResult(`提交失败：${(error as Error).message}`);
      void message.error(`反馈提交失败：${(error as Error).message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const cases = history.data?.cases ?? [];
  return (
    <Card
      size="small"
      title="这个判断准确吗？"
      extra={<Tag>仅本任务</Tag>}
      style={{ marginTop: 16 }}
    >
      <Typography.Paragraph type="secondary" style={{ marginBottom: 12 }}>
        标记误报、漏报或坏修复，帮助后续评测改进。
      </Typography.Paragraph>
      <Form
        form={form}
        layout="vertical"
        initialValues={{ category: "false_positive", findingIndex: "" }}
        onFinish={(values) => void submit(values)}
      >
        <Space wrap size="middle" style={{ display: "flex" }}>
          <Form.Item name="category" label="反馈类型" style={{ minWidth: 160, marginBottom: 12 }}>
            <Select
              options={[
                { value: "false_positive", label: "误报" },
                { value: "missed_issue", label: "漏报" },
                { value: "bad_fix", label: "坏修复" },
              ]}
            />
          </Form.Item>
          <Form.Item name="findingIndex" label="关联问题（可选）" style={{ minWidth: 280, marginBottom: 12 }}>
            <Select
              allowClear
              placeholder="不关联已有问题"
              options={findings.map((finding, index) => ({
                value: String(index),
                label: `${finding.rule_id || "未命名规则"} · ${finding.path || "未知文件"}:${finding.line ?? "?"}`,
              }))}
            />
          </Form.Item>
        </Space>
        {category === "missed_issue" && (
          <Space wrap size="middle" style={{ display: "flex" }}>
            <Form.Item name="ruleId" label="规则 ID" style={{ minWidth: 160, marginBottom: 12 }}>
              <Input placeholder="SEC-RULE" />
            </Form.Item>
            <Form.Item name="path" label="文件路径" style={{ minWidth: 220, marginBottom: 12 }}>
              <Input placeholder="app/api.py" />
            </Form.Item>
            <Form.Item name="line" label="行号" style={{ marginBottom: 12 }}>
              <InputNumber min={1} placeholder="42" />
            </Form.Item>
          </Space>
        )}
        <Form.Item
          name="note"
          label="说明"
          rules={[{ required: true, message: "请说明判断依据或预期行为" }]}
          style={{ marginBottom: 12 }}
        >
          <Input.TextArea rows={3} maxLength={2000} placeholder="说明判断依据或预期行为" />
        </Form.Item>
        <Space style={{ width: "100%", justifyContent: "space-between" }}>
          <Typography.Text type="secondary">
            {category === "missed_issue"
              ? "补充规则、路径和行号可让后续回放评测更准确。"
              : "提交后可在本任务和高级实验中查看状态。"}
          </Typography.Text>
          <Button type="primary" htmlType="submit" loading={submitting}>
            提交反馈
          </Button>
        </Space>
      </Form>
      {result ? <Typography.Paragraph aria-live="polite">{result}</Typography.Paragraph> : null}
      <Typography.Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 4 }}>
        本任务反馈
      </Typography.Paragraph>
      {history.isLoading ? (
        <Typography.Text type="secondary">正在读取反馈…</Typography.Text>
      ) : history.isError ? (
        <Typography.Text type="danger">
          无法读取反馈：{(history.error as Error)?.message}
        </Typography.Text>
      ) : cases.length === 0 ? (
        <Typography.Text type="secondary">
          尚无反馈。提交后，它会进入失败案例集和后续回放评测。
        </Typography.Text>
      ) : (
        <Space direction="vertical" size="small" style={{ width: "100%" }}>
          {cases.map((item) => {
            const finding = item.payload?.finding;
            const reference = finding?.rule_id
              ? `${finding.rule_id} · ${finding.path || "未知文件"}:${finding.line ?? "?"}`
              : "未关联已有问题";
            return (
              <Card size="small" type="inner" key={item.id ?? `${item.category}-${reference}`}>
                <Space wrap style={{ width: "100%", justifyContent: "space-between" }}>
                  <Space wrap>
                    <Tag>{FEEDBACK_LABELS[item.category] || item.category}</Tag>
                    <Space direction="vertical" size={0}>
                      <Typography.Text strong>{reference}</Typography.Text>
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        {item.payload?.note || "未填写说明"}
                      </Typography.Text>
                    </Space>
                  </Space>
                  <Tag color={item.resolved ? "green" : "processing"}>
                    {item.resolved ? "已解决" : "待评测"}
                  </Tag>
                </Space>
              </Card>
            );
          })}
        </Space>
      )}
    </Card>
  );
}

function ReportCard({ task }: { task: TaskDetail }): React.JSX.Element | null {
  const { message, modal } = AntApp.useApp();
  const report = task.report;
  if (!report) return null;
  const findings = report.findings ?? [];
  const files = Array.isArray(report.files_reviewed)
    ? report.files_reviewed.length
    : Number(report.files_reviewed || report.file_count || 0);
  const revision = resolvedRevision(task);
  const requestedRef = report.collaboration?.import_policy?.source?.requested_ref;
  const cacheHit = report.collaboration?.import_policy?.cache_hit;
  const adjudication = reportAdjudication(report, findings);
  const risk = reportRisk(report, findings);
  const verified = findings.filter((finding) => isVerifiedState(finding.verification_state)).length;
  const counts = severityCounts(findings);
  const highPriority = counts.critical + counts.high;
  const summary =
    report.summary ||
    (findings.length
      ? `发现 ${findings.length} 个候选安全问题。请优先处理高风险和证据已验证的结论。`
      : "本次审计没有发现满足当前规则和证据阈值的安全问题。仍建议结合业务威胁模型进行人工复核。");
  const repositoryScan = String(
    (task.input as { task_type?: string } | undefined)?.task_type ?? "",
  ) === "repository_scan";
  const [previewBusy, setPreviewBusy] = useState(false);
  const [fixBusy, setFixBusy] = useState(false);
  const [operation, setOperation] = useState<
    { title: string; data: RepairPreviewResult | FixResult } | null
  >(null);

  const runPreview = async (): Promise<void> => {
    setPreviewBusy(true);
    try {
      const data = await api.createRepairPreview(task.id);
      setOperation({ title: "自动修复预览", data });
      if (data.status === "verified-preview") {
        void message.success(`修复预览已通过门禁${data.note ? `：${data.note}` : ""}`);
      } else {
        void message.warning(`未生成自动修复${data.note ? `：${data.note}` : ""}`);
      }
    } catch (error) {
      void message.error(`修复预览失败：${(error as Error).message}`);
    } finally {
      setPreviewBusy(false);
    }
  };

  const runFix = (): void => {
    modal.confirm({
      title: "确认创建修复分支？",
      content:
        "该操作会在目标仓库创建新分支并写入修复提交。不会覆盖当前分支，但可能触发仓库 CI。请确认你有权修改该仓库。",
      okText: "创建修复分支",
      cancelText: "取消",
      onOk: async () => {
        setFixBusy(true);
        try {
          const data = await api.createFix(task.id);
          setOperation({ title: "修复分支结果", data });
          void message.success(`修复分支已创建：${data.branch || "请在仓库中检查变更。"}`);
        } catch (error) {
          void message.error(`创建修复分支失败：${(error as Error).message}`);
        } finally {
          setFixBusy(false);
        }
      },
    });
  };

  const showPreview = repositoryScan && findings.length > 0;
  const showFix = Boolean(task.pull_request);

  return (
    <Card
      size="small"
      title="审计报告"
      style={{ marginTop: 16 }}
      extra={
        <Space>
          {showPreview && (
            <Button size="small" loading={previewBusy} onClick={() => void runPreview()}>
              生成修复预览
            </Button>
          )}
          {showFix && (
            <Button size="small" danger loading={fixBusy} onClick={runFix}>
              创建修复分支
            </Button>
          )}
        </Space>
      }
    >
      <Space direction="vertical" size="small" style={{ width: "100%" }}>
        {operation && <OperationResultPanel title={operation.title} data={operation.data} />}
        <Descriptions size="small" column={2} bordered>
          <Descriptions.Item label="风险评级">
            <Tag color={severityMeta(risk).color}>{severityMeta(risk).label}</Tag>
          </Descriptions.Item>
          <Descriptions.Item label="发现数量">{findings.length}</Descriptions.Item>
          <Descriptions.Item label="扫描文件数">{files}</Descriptions.Item>
          <Descriptions.Item label="分析引擎">{report.reviewer || "—"}</Descriptions.Item>
          {revision ? (
            <Descriptions.Item label="已扫描固定提交" span={2}>
              <Typography.Text code>{revision}</Typography.Text>
              {requestedRef && !/^[0-9a-f]{40}([0-9a-f]{24})?$/i.test(requestedRef) ? (
                <Typography.Text type="secondary">（由 {requestedRef} 在扫描时解析钉死）</Typography.Text>
              ) : null}
              {cacheHit === true ? (
                <Typography.Text type="secondary"> · 命中快照缓存，未重新下载</Typography.Text>
              ) : null}
            </Descriptions.Item>
          ) : null}
        </Descriptions>
        <Typography.Paragraph style={{ marginBottom: 0 }}>{summary}</Typography.Paragraph>
        <DispositionBanner adjudication={adjudication} />
        <SemanticTriageCard report={report} />
        <Space size="large" wrap aria-label="报告摘要">
          <span>问题总数 <strong>{findings.length}</strong></span>
          <span>严重 / 高危 <strong>{highPriority}</strong></span>
          <span>证据已验证 <strong>{verified}</strong></span>
          <span>审计文件 <strong>{files || "—"}</strong></span>
        </Space>
        <SeverityChart findings={findings} />
        <SemanticEvidence adjudication={adjudication} />
        <Table
          size="small"
          columns={findingsColumns(adjudication)}
          dataSource={findings}
          rowKey={(_record, index) => String(index)}
          pagination={findings.length > 10 ? { pageSize: 10 } : false}
          locale={{
            emptyText: (
              <Empty
                description={
                  <span style={{ maxWidth: 460, whiteSpace: "normal", display: "inline-block" }}>
                    未发现达到阈值的问题。这不等于绝对安全。请结合依赖风险、部署配置和业务权限继续复核。
                  </span>
                }
              />
            ),
          }}
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
          如何解读：系统只有在确定性缓解证据与模型 clean 结论一致时才自动放行；冲突或缺失证据统一进入人工复核。“没有发现”不等于“已经证明安全”，置信度也不能替代漏洞可利用性分析。策略：{adjudication.policy}。
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
    queryFn: ({ signal }) => api.task(taskId, signal),
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
  const reportReady = task.state === "SUCCESS" && task.report;

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
        {reportReady && <FeedbackPanel task={task} />}
      </Space>
    </div>
  );
}
