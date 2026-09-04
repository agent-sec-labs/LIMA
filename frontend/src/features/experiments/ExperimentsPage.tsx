import React, { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  App as AntApp,
  Button,
  Card,
  Col,
  Descriptions,
  Form,
  InputNumber,
  List,
  Progress,
  Row,
  Select,
  Space,
  Tag,
  Typography,
} from "antd";
import { api } from "@/shared/api/client";

/**
 * 外部评测：冻结数据集上的有界实验。
 * 轮询用 TanStack refetchInterval（存在活跃实验时每 5s 刷新，页面隐藏时暂停）。
 */

interface CatalogDataset {
  path: string;
  name?: string;
  evaluation_role?: string;
  case_count?: number;
  modes?: string[];
}

interface ExperimentRecord {
  id: string;
  state: string;
  mode: string;
  dataset_path: string;
  created_at?: string;
  updated_at?: string;
  manifest?: { dataset_name?: string; budgets?: { max_llm_calls?: number; max_total_tokens?: number } };
  progress?: {
    total_cases?: number;
    completed_cases?: number;
    current_case?: string;
    llm_calls?: number;
    total_tokens?: number;
    warnings?: number;
  };
  result?: {
    metrics?: Record<string, number>;
  };
}

const STATE_LABELS: Record<string, string> = {
  QUEUED: "等待执行",
  RUNNING: "正在运行",
  AGGREGATING: "正在汇总",
  SUCCEEDED: "已完成",
  SUCCEEDED_WITH_WARNINGS: "完成但有警告",
  FAILED: "运行失败",
  NEEDS_ATTENTION: "需要管理员处理",
  BUDGET_EXHAUSTED: "预算已耗尽",
  CANCELLED: "已取消",
};

const ACTIVE_STATES = new Set(["QUEUED", "RUNNING", "AGGREGATING"]);

function stateColor(state: string): string {
  if (state === "SUCCEEDED") return "green";
  if (["FAILED", "BUDGET_EXHAUSTED"].includes(state)) return "red";
  if (["NEEDS_ATTENTION", "SUCCEEDED_WITH_WARNINGS"].includes(state)) return "orange";
  if (ACTIVE_STATES.has(state)) return "blue";
  return "default";
}

interface CreateFields {
  dataset: string;
  mode: string;
  max_llm_calls?: number;
  max_total_tokens: number;
}

const METRIC_LABELS: Record<string, string> = {
  cases: "案例数",
  retrieval_target_symbol_recall: "风险不变量召回率",
  llm_vulnerable_recall: "漏洞召回率",
  llm_fixed_specificity: "修复具体性",
  llm_paired_discrimination_rate: "目标人工复核率",
};

export function ExperimentsPage(): React.JSX.Element {
  const queryClient = useQueryClient();
  const { message, modal } = AntApp.useApp();
  const [selected, setSelected] = useState<string>("");
  const [form] = Form.useForm<CreateFields>();
  const mode = Form.useWatch("mode", form);

  const catalog = useQuery({
    queryKey: ["experiment-catalog"],
    queryFn: () => api.get<{ llm_available?: boolean; datasets: CatalogDataset[] }>("/v1/experiments/catalog"),
  });
  const experiments = useQuery({
    queryKey: ["experiments"],
    queryFn: () => api.get<{ experiments: ExperimentRecord[] }>("/v1/experiments"),
    refetchInterval: (query) => {
      const records = query.state.data?.experiments ?? [];
      return records.some((item) => ACTIVE_STATES.has(item.state)) ? 5000 : false;
    },
  });

  const datasets = catalog.data?.datasets ?? [];
  const records = experiments.data?.experiments ?? [];
  const current = useMemo(
    () => records.find((item) => item.id === selected) ?? records[0],
    [records, selected],
  );

  const create = useMutation({
    mutationFn: (values: CreateFields) =>
      api.post<{ run_id: string }>("/v1/experiments", {
        dataset: values.dataset,
        mode: values.mode,
        max_llm_calls: values.mode === "llm-retrieval" ? (values.max_llm_calls ?? 0) : 0,
        max_total_tokens: values.max_total_tokens,
      }),
    onSuccess: (created) => {
      setSelected(created.run_id);
      void queryClient.invalidateQueries({ queryKey: ["experiments"] });
      void message.success("后台实验已创建，现在可以关闭浏览器；LIMA 会持续保存中间结果。");
    },
    onError: (error) => {
      void message.error(`实验创建失败：${(error as Error).message}`);
    },
  });

  const act = useMutation({
    mutationFn: ({ id, action }: { id: string; action: "cancel" | "resume" | "retry-ambiguous" }) => {
      if (action === "cancel") {
        return api.post(`/v1/experiments/${encodeURIComponent(id)}/cancel`, {});
      }
      return api.post(`/v1/experiments/${encodeURIComponent(id)}/resume`, {
        allow_ambiguous_retry: action === "retry-ambiguous",
      });
    },
    onSuccess: (_data, variables) => {
      void queryClient.invalidateQueries({ queryKey: ["experiments"] });
      void message.success(variables.action === "cancel" ? "取消请求已提交" : "实验已重新入队");
    },
    onError: (error) => {
      void message.error(`实验操作失败：${(error as Error).message}`);
    },
  });

  const confirmAct = (action: "cancel" | "resume" | "retry-ambiguous"): void => {
    if (!current) return;
    const content =
      action === "cancel"
        ? "实验会在当前案例边界停止，已完成的案例和 artifact 会保留。"
        : action === "retry-ambiguous"
          ? "上一次请求可能已经被供应商计费。继续会重新执行该案例，并按保守策略累计调用次数。"
          : "已完成案例不会重新扫描；实验会从最近一个完整边界继续。";
    modal.confirm({
      title:
        action === "cancel" ? "确认请求取消实验？" : action === "retry-ambiguous" ? "确认承担可能的重复调用？" : "确认从断点恢复？",
      content,
      okText: action === "cancel" ? "请求取消" : "继续",
      onOk: () => act.mutateAsync({ id: current.id, action }),
    });
  };

  const progress = current?.progress ?? {};
  const totalCases = Number(progress.total_cases || 0);
  const completed = Math.min(totalCases, Number(progress.completed_cases || 0));
  const percent = totalCases ? Math.round((completed / totalCases) * 100) : 0;

  return (
    <div style={{ padding: 24 }}>
      <Typography.Title level={3}>外部评测</Typography.Title>
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={10}>
          <Card size="small" title="发起评测">
            <Form
              form={form}
              layout="vertical"
              requiredMark={false}
              onFinish={(values) => create.mutate(values)}
              initialValues={{ mode: "retrieval", max_llm_calls: 20, max_total_tokens: 100000 }}
            >
              <Form.Item
                name="dataset"
                label="冻结数据集"
                rules={[{ required: true, message: "请选择数据集" }]}
                extra="数据集固定案例与 SHA-256 指纹，评测不执行目标仓库代码。"
              >
                <Select
                  placeholder="选择评测数据集"
                  loading={catalog.isLoading}
                  options={datasets.map((item) => ({
                    value: item.path,
                    label: `${item.name ?? item.path} · ${item.case_count ?? 0} 案例 · ${item.evaluation_role ?? "development"}`,
                  }))}
                />
              </Form.Item>
              <Form.Item name="mode" label="模式" rules={[{ required: true }]}>
                <Select
                  options={[
                    { value: "deterministic", label: "确定性扫描" },
                    { value: "retrieval", label: "检索基线" },
                    { value: "llm-retrieval", label: "检索 + 真实 LLM" },
                  ]}
                />
              </Form.Item>
              {mode === "llm-retrieval" && (
                <Form.Item name="max_llm_calls" label="最大模型调用次数">
                  <InputNumber min={1} style={{ width: "100%" }} />
                </Form.Item>
              )}
              <Form.Item name="max_total_tokens" label="Token 预算">
                <InputNumber min={1000} style={{ width: "100%" }} />
              </Form.Item>
              <Button type="primary" htmlType="submit" loading={create.isPending}>
                创建后台实验
              </Button>
            </Form>
          </Card>
        </Col>
        <Col xs={24} lg={14}>
          <Card size="small" title="实验记录" extra={<Typography.Text type="secondary">活跃实验每 5 秒自动刷新</Typography.Text>}>
            <List
              size="small"
              dataSource={records}
              locale={{ emptyText: "还没有实验记录" }}
              renderItem={(item) => (
                <List.Item
                  onClick={() => setSelected(item.id)}
                  style={{ cursor: "pointer", background: current?.id === item.id ? "#e6f0ff" : undefined, padding: "8px 12px" }}
                >
                  <List.Item.Meta
                    title={
                      <Space>
                        <Typography.Text strong>{item.manifest?.dataset_name ?? item.dataset_path}</Typography.Text>
                        <Tag color={stateColor(item.state)}>{STATE_LABELS[item.state] ?? item.state}</Tag>
                        <Typography.Text type="secondary">{item.mode}</Typography.Text>
                      </Space>
                    }
                    description={`${item.progress?.completed_cases ?? 0}/${item.progress?.total_cases ?? 0} 案例 · ${item.progress?.llm_calls ?? 0} 次调用 · ${item.progress?.total_tokens ?? 0} tokens`}
                  />
                </List.Item>
              )}
            />
          </Card>
        </Col>
      </Row>
      {current && (
        <Card
          size="small"
          title={`实验详情 · ${current.id.slice(0, 8)}`}
          style={{ marginTop: 16 }}
          extra={
            <Space>
              {ACTIVE_STATES.has(current.state) && (
                <Button size="small" onClick={() => confirmAct("cancel")}>
                  请求取消
                </Button>
              )}
              {(current.state === "NEEDS_ATTENTION" || current.state === "FAILED") && (
                <Button size="small" onClick={() => confirmAct("resume")}>
                  从断点恢复
                </Button>
              )}
              {current.state === "NEEDS_ATTENTION" && (
                <Button size="small" danger onClick={() => confirmAct("retry-ambiguous")}>
                  重试模糊调用
                </Button>
              )}
            </Space>
          }
        >
          <Row gutter={[16, 16]}>
            <Col xs={24} md={8}>
              <Progress
                percent={percent}
                status={current.state === "FAILED" ? "exception" : ACTIVE_STATES.has(current.state) ? "active" : "normal"}
              />
              <Typography.Text type="secondary">
                {completed}/{totalCases} 案例
                {progress.current_case ? ` · 当前：${progress.current_case}` : ""}
                {Number(progress.warnings || 0) > 0 ? ` · ${progress.warnings} 个警告` : ""}
              </Typography.Text>
            </Col>
            <Col xs={24} md={16}>
              <Descriptions size="small" column={2}>
                <Descriptions.Item label="模式">{current.mode}</Descriptions.Item>
                <Descriptions.Item label="状态">{STATE_LABELS[current.state] ?? current.state}</Descriptions.Item>
                <Descriptions.Item label="创建时间">{current.created_at ?? "—"}</Descriptions.Item>
                <Descriptions.Item label="Token 消耗">{current.progress?.total_tokens ?? 0}</Descriptions.Item>
              </Descriptions>
            </Col>
          </Row>
          {current.result?.metrics && (
            <Descriptions size="small" column={2} bordered style={{ marginTop: 12 }} title="评测指标">
              {Object.entries(current.result.metrics).map(([key, value]) => (
                <Descriptions.Item key={key} label={METRIC_LABELS[key] ?? key}>
                  {value}
                </Descriptions.Item>
              ))}
            </Descriptions>
          )}
        </Card>
      )}
    </div>
  );
}
